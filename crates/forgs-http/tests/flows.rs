//! End-to-end flows over the real router, an in-memory store, a stub
//! identity provider and a stub workload issuer.

#![allow(clippy::too_many_lines, clippy::similar_names)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use forgs::schema::{KindSpec, Schema};
use forgs::store::AppRecord;
use forgs::{AppKind, RoleLadder, SubjectKey, TokenFormat, TokenHash, TokenKind, TokenUse};
use forgs_http::{
    AllowedKinds, AnyConnection, ApiCookie, ApiError, ApiKeyPurposes, AppTokenLookup, AuditEvent,
    AuditSink, AuthContext, Authenticated, FixedClock, HeaderOnly, KeyMint, PurposeKind,
    SessionOnly, StaticPurposes,
};
use forgs_idp::oidc::OidcError;
use forgs_idp::workload::{WorkloadClaims, WorkloadIdentity};
use forgs_idp::{
    AuthRequest, ExternalIdentity, IdentityProvider, IdpError, ProviderTokens, WorkloadIssuer,
};
use forgs_store::{NewApiKey, NewGrant, Store};
use http_body_util::BodyExt as _;
use serde_json::{json, Value};
use tower::ServiceExt as _;

const PUBLIC: &str = "https://forge.example";
const NOW: u64 = 1_800_000_000;

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

/// `(subject, email, suggested username)`.
type StubIdentity = (String, String, Option<String>);

/// Identities keyed by authorization code.
struct StubIdp {
    name: &'static str,
    ids: Mutex<HashMap<String, StubIdentity>>,
    redirect_uris: Mutex<Vec<String>>,
}

impl StubIdp {
    fn new(name: &'static str) -> Arc<Self> {
        Arc::new(Self {
            name,
            ids: Mutex::new(HashMap::new()),
            redirect_uris: Mutex::new(Vec::new()),
        })
    }
    fn add(&self, code: &str, subject: &str, email: &str, suggest: Option<&str>) {
        self.ids.lock().unwrap().insert(
            code.to_owned(),
            (
                subject.to_owned(),
                email.to_owned(),
                suggest.map(str::to_owned),
            ),
        );
    }
}

#[async_trait]
impl IdentityProvider for StubIdp {
    fn name(&self) -> &str {
        self.name
    }
    fn authorization_url(&self, redirect_uri: &str, req: &AuthRequest) -> Result<String, IdpError> {
        Ok(forgs_idp::url::append_query(
            "https://idp.example/authorize",
            &[
                ("state", &req.state),
                ("redirect_uri", redirect_uri),
                ("code_challenge", &req.pkce_challenge()),
            ],
        ))
    }
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        pkce_verifier: &str,
    ) -> Result<ProviderTokens, IdpError> {
        assert_ne!(pkce_verifier, "");
        self.redirect_uris
            .lock()
            .unwrap()
            .push(redirect_uri.to_owned());
        Ok(ProviderTokens::new(code.to_owned(), None))
    }
    async fn fetch_identity(
        &self,
        tokens: ProviderTokens,
        _nonce: &str,
        _now: u64,
    ) -> Result<ExternalIdentity, IdpError> {
        let (code, _) = tokens.into_parts();
        let ids = self.ids.lock().unwrap();
        let (sub, email, suggest) = ids.get(&code).cloned().ok_or_else(|| IdpError::Oauth {
            code: "bad_verification_code".into(),
            description: None,
        })?;
        ExternalIdentity::verified(self.name, sub, Some(email), true, suggest)
    }
}

/// Accepts `good:<owner>/<repo>`.
struct StubIssuer;

#[async_trait]
impl WorkloadIssuer for StubIssuer {
    fn name(&self) -> &'static str {
        "github-actions"
    }
    async fn verify(&self, jwt: &str, _now: u64) -> Result<WorkloadIdentity, OidcError> {
        let repo = jwt.strip_prefix("good:").ok_or(OidcError::BadSignature)?;
        let owner = repo.split('/').next().unwrap().to_owned();
        Ok(WorkloadIdentity {
            subject: forgs::subject::workload_subject_key(repo),
            claims: WorkloadClaims {
                repository: repo.to_owned(),
                repository_owner: owner,
                git_ref: None,
                workflow: None,
                job_workflow_ref: None,
                run_id: None,
                sub: "repo:x".into(),
                exp: NOW + 300,
            },
        })
    }
}

#[derive(Default)]
struct Collect(Mutex<Vec<AuditEvent>>);

#[async_trait]
impl AuditSink for Collect {
    async fn record(&self, e: AuditEvent) {
        self.0.lock().unwrap().push(e);
    }
}

impl Collect {
    fn has(&self, action: &str) -> bool {
        self.0.lock().unwrap().iter().any(|e| e.action == action)
    }
}

/// The app's node tokens, keyed by hash; counts lookups.
#[derive(Default)]
struct NodeTokens {
    rows: Mutex<HashMap<String, AppRecord>>,
    lookups: AtomicUsize,
    broken: AtomicBool,
}

#[async_trait]
impl AppTokenLookup for NodeTokens {
    async fn lookup_app(
        &self,
        kind: AppKind,
        hash: &TokenHash,
    ) -> Result<Option<AppRecord>, String> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        assert_eq!(kind.label(), "node", "only connection kinds are looked up");
        if self.broken.load(Ordering::SeqCst) {
            return Err("disk on fire".into());
        }
        Ok(self.rows.lock().unwrap().get(hash.as_str()).cloned())
    }
}

/// `ci`/`node` purposes; `node` keys carry `{"tags": [..]}`, stored sorted,
/// and only the highest role may mint tags.
struct TestPurposes(StaticPurposes);

#[async_trait]
impl ApiKeyPurposes for TestPurposes {
    fn kind(&self, purpose: &str) -> Option<PurposeKind> {
        self.0.kind(purpose)
    }

    async fn check_payload(
        &self,
        ctx: &AuthContext,
        mint: &KeyMint<'_>,
    ) -> Result<Option<String>, ApiError> {
        match (mint.purpose, mint.payload) {
            (_, None | Some(Value::Null)) => Ok(None),
            ("node", Some(p)) => {
                // Authority cap: tags confer access only an admin holds.
                if !mint.role.satisfies(ctx.store().roles().highest()) {
                    return Err(ApiError::Forbidden);
                }
                let mut tags: Vec<String> = p
                    .get("tags")
                    .and_then(Value::as_array)
                    .ok_or(ApiError::BadRequest)?
                    .iter()
                    .map(|t| t.as_str().map(str::to_owned).ok_or(ApiError::BadRequest))
                    .collect::<Result<_, _>>()?;
                tags.sort();
                tags.dedup();
                Ok(Some(json!({ "tags": tags }).to_string()))
            }
            _ => Err(ApiError::BadRequest),
        }
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct H {
    app: Router,
    ctx: AuthContext,
    clock: Arc<FixedClock>,
    idp: Arc<StubIdp>,
    idp2: Arc<StubIdp>,
    audit: Arc<Collect>,
    nodes: Arc<NodeTokens>,
    node: AppKind,
    node_device: AppKind,
}

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("not json: {}", String::from_utf8_lossy(&self.body)))
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn location(&self) -> String {
        self.headers[header::LOCATION].to_str().unwrap().to_owned()
    }
    fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }
    #[track_caller]
    fn expect(&self, status: StatusCode) -> &Self {
        assert_eq!(self.status, status, "body: {}", self.text());
        self
    }
    fn error(&self) -> String {
        self.json()["error"].as_str().unwrap().to_owned()
    }
}

#[derive(Default, Clone)]
struct Jar(HashMap<String, String>);

impl Jar {
    fn absorb(&mut self, r: &Resp) {
        for c in r.set_cookies() {
            let first = c.split(';').next().unwrap();
            let (k, v) = first.split_once('=').unwrap();
            if c.contains("Max-Age=0") || v.is_empty() {
                self.0.remove(k);
            } else {
                self.0.insert(k.to_owned(), v.to_owned());
            }
        }
    }
    fn header(&self) -> String {
        self.0
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
    fn get(&self, k: &str) -> String {
        self.0.get(k).cloned().unwrap_or_default()
    }
}

fn schema() -> Schema {
    Schema::builder()
        .kind("org", KindSpec::root().leaf().personal_for_users())
        .reserved(&["api", "admin", "login", "settings"])
        .build()
        .unwrap()
}

/// An app route under the cookie prefix, and one outside it, both marked
/// `ApiCookie`.
async fn app_me(auth: Authenticated<SessionOnly, ApiCookie>) -> String {
    auth.subject.key().to_string()
}

/// Brand `frg` (cookie names unchanged) plus fleet-like app kinds.
fn test_format() -> (TokenFormat, AppKind, AppKind) {
    let mut b = TokenFormat::builder("frg");
    let node = b.app_kind("node", "n", TokenUse::Connection);
    let node_device = b.app_kind("node_device", "nd", TokenUse::RedeemOnly);
    (b.build().unwrap(), node, node_device)
}

struct NodeOnly;

impl AllowedKinds for NodeOnly {
    fn allowed(ctx: &AuthContext) -> Vec<TokenKind> {
        vec![TokenKind::App(ctx.format().app_kind("node").unwrap())]
    }
}

/// An app route only a node token reaches.
async fn app_node(auth: Authenticated<NodeOnly, HeaderOnly>) -> String {
    auth.subject.key().to_string()
}

/// An app route any connection credential reaches.
async fn app_any(auth: Authenticated<AnyConnection, HeaderOnly>) -> String {
    auth.subject.key().to_string()
}

async fn harness_with(issuer: bool) -> H {
    harness_at(issuer, &format!("{PUBLIC}/")).await
}

async fn harness_at(issuer: bool, public_url: &str) -> H {
    let store = Store::connect_in_memory(schema(), RoleLadder::new(&["member", "admin"]).unwrap())
        .await
        .unwrap();
    let clock = Arc::new(FixedClock::new(NOW));
    let idp = StubIdp::new("stub");
    let idp2 = StubIdp::new("stub2");
    let audit = Arc::new(Collect::default());
    let nodes = Arc::new(NodeTokens::default());
    let (format, node, node_device) = test_format();
    let mut b = AuthContext::builder(store, public_url, &[42; 32])
        .app_label("test")
        .format(format)
        .app_tokens(nodes.clone())
        .clock(clock.clone())
        .provider(idp.clone())
        .provider(idp2.clone())
        .audit(audit.clone())
        .api_key_purposes(Arc::new(TestPurposes(
            StaticPurposes::new()
                .with("ci", PurposeKind::Workload)
                .with("node", PurposeKind::App),
        )));
    if issuer {
        b = b.workload_issuer(Arc::new(StubIssuer));
    }
    let ctx = b.build().unwrap();
    let app = forgs_http::router::<AuthContext>()
        .route("/api/me", get(app_me).post(app_me))
        .route("/other/me", post(app_me))
        .route("/api/node", get(app_node))
        .route("/api/any", get(app_any))
        .with_state(ctx.clone());
    H {
        app,
        ctx,
        clock,
        idp,
        idp2,
        audit,
        nodes,
        node,
        node_device,
    }
}

async fn harness() -> H {
    harness_with(true).await
}

impl H {
    async fn send(&self, req: Request<Body>) -> Resp {
        let r = self.app.clone().oneshot(req).await.unwrap();
        let status = r.status();
        let headers = r.headers().clone();
        let body = r.into_body().collect().await.unwrap().to_bytes().to_vec();
        Resp {
            status,
            headers,
            body,
        }
    }

    async fn get(&self, uri: &str, jar: Option<&Jar>, extra: &[(&str, &str)]) -> Resp {
        let mut b = Request::builder().method(Method::GET).uri(uri);
        if let Some(j) = jar {
            b = b.header(header::COOKIE, j.header());
        }
        for (k, v) in extra {
            b = b.header(*k, *v);
        }
        self.send(b.body(Body::empty()).unwrap()).await
    }

    async fn post_json(
        &self,
        uri: &str,
        bearer: Option<&str>,
        jar: Option<&Jar>,
        extra: &[(&str, &str)],
        body: &Value,
    ) -> Resp {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(t) = bearer {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if let Some(j) = jar {
            b = b.header(header::COOKIE, j.header());
        }
        for (k, v) in extra {
            b = b.header(*k, *v);
        }
        self.send(b.body(Body::from(body.to_string())).unwrap())
            .await
    }

    async fn post_form(&self, uri: &str, jar: &Jar, form: &[(&str, &str)]) -> Resp {
        self.post_form_with(uri, jar, &[], form).await
    }

    async fn post_form_with(
        &self,
        uri: &str,
        jar: &Jar,
        extra: &[(&str, &str)],
        form: &[(&str, &str)],
    ) -> Resp {
        let body = serde_urlencoded::to_string(form).unwrap();
        let mut b = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, jar.header());
        for (k, v) in extra {
            b = b.header(*k, *v);
        }
        self.send(b.body(Body::from(body)).unwrap()).await
    }

    /// Start + callback with `code`; returns the callback response.
    async fn browser_login(&self, jar: &mut Jar, provider: &str, code: &str) -> Resp {
        let start = self
            .get(&format!("/auth/{provider}/start"), Some(jar), &[])
            .await;
        start.expect(StatusCode::FOUND);
        jar.absorb(&start);
        let state = query_param(&start.location(), "state");
        let cb = self
            .get(
                &format!("/auth/{provider}/callback?code={code}&state={state}"),
                Some(jar),
                &[],
            )
            .await;
        jar.absorb(&cb);
        cb
    }

    /// A brand-new user through first login + signup. Returns the browser jar.
    async fn signup(&self, code: &str, sub: &str, email: &str, username: &str) -> Jar {
        self.idp.add(code, sub, email, Some(username));
        let mut jar = Jar::default();
        let cb = self.browser_login(&mut jar, "stub", code).await;
        cb.expect(StatusCode::FOUND);
        assert_eq!(cb.location(), "/auth/signup");
        let r = self
            .post_form("/auth/signup", &jar, &[("username", username)])
            .await;
        r.expect(StatusCode::SEE_OTHER);
        jar.absorb(&r);
        jar
    }

    fn session(jar: &Jar) -> String {
        jar.get("frg_session")
    }

    async fn whoami(&self, token: &str) -> Resp {
        self.get(
            "/auth/session",
            None,
            &[("authorization", &format!("Bearer {token}"))],
        )
        .await
    }
}

fn query_param(url: &str, key: &str) -> String {
    let q = url.split_once('?').unwrap().1;
    let m: HashMap<String, String> = serde_urlencoded::from_str(q).unwrap();
    m[key].clone()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn signup_origin_checks() {
    // Each case: (extra headers, expected status).
    let cases: &[(&[(&str, &str)], StatusCode)] = &[
        (&[("origin", PUBLIC)], StatusCode::SEE_OTHER),
        (
            &[("origin", PUBLIC), ("sec-fetch-site", "same-origin")],
            StatusCode::SEE_OTHER,
        ),
        (
            &[("origin", "null"), ("sec-fetch-site", "same-origin")],
            StatusCode::SEE_OTHER,
        ),
        (&[("origin", "null")], StatusCode::FORBIDDEN),
        (
            &[("origin", "null"), ("sec-fetch-site", "same-site")],
            StatusCode::FORBIDDEN,
        ),
        (
            &[("origin", "null"), ("sec-fetch-site", "cross-site")],
            StatusCode::FORBIDDEN,
        ),
        (&[("origin", "https://evil.example")], StatusCode::FORBIDDEN),
        (
            &[
                ("origin", "https://evil.example"),
                ("sec-fetch-site", "same-origin"),
            ],
            StatusCode::FORBIDDEN,
        ),
        (&[("sec-fetch-site", "cross-site")], StatusCode::FORBIDDEN),
        (
            &[("origin", PUBLIC), ("sec-fetch-site", "cross-site")],
            StatusCode::FORBIDDEN,
        ),
    ];
    // A trailing slash or a path in public_url still yields the bare origin.
    for public_url in [format!("{PUBLIC}/"), format!("{PUBLIC}/app/")] {
        let h = harness_at(true, &public_url).await;
        for (i, (extra, want)) in cases.iter().enumerate() {
            let name = format!("user{i}");
            h.idp.add(
                &format!("code{i}"),
                &format!("sub{i}"),
                &format!("{name}@example.com"),
                Some(&name),
            );
            let mut jar = Jar::default();
            let cb = h.browser_login(&mut jar, "stub", &format!("code{i}")).await;
            cb.expect(StatusCode::FOUND);
            assert_eq!(cb.location(), "/auth/signup");
            let r = h
                .post_form_with("/auth/signup", &jar, extra, &[("username", &name)])
                .await;
            assert_eq!(r.status, *want, "{public_url} {extra:?}");
            if *want == StatusCode::FORBIDDEN {
                // The ticket is unspent: a proper same-origin retry succeeds.
                let r = h
                    .post_form_with(
                        "/auth/signup",
                        &jar,
                        &[("origin", PUBLIC)],
                        &[("username", &name)],
                    )
                    .await;
                r.expect(StatusCode::SEE_OTHER);
            }
        }
    }
}

#[tokio::test]
async fn first_login_signup_then_second_login() {
    let h = harness().await;
    h.idp.add("c1", "100", "alice@example.com", Some("Alice"));

    let mut jar = Jar::default();
    let cb = h.browser_login(&mut jar, "stub", "c1").await;
    cb.expect(StatusCode::FOUND);
    assert_eq!(cb.location(), "/auth/signup");
    assert!(jar.0.contains_key("frg_signup"));
    assert!(
        !jar.0.contains_key("frg_session"),
        "no session before signup"
    );
    assert!(!jar.0.contains_key("frg_oauth"), "flow cookie is spent");

    // The form pre-fills the (validated) suggestion and is locked down.
    let page = h.get("/auth/signup", Some(&jar), &[]).await;
    page.expect(StatusCode::OK);
    assert!(page.text().contains("value=\"alice\""), "{}", page.text());
    assert!(page.headers[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .starts_with("default-src 'none'"));
    assert_eq!(page.headers[header::REFERRER_POLICY], "same-origin");

    let r = h
        .post_form("/auth/signup", &jar, &[("username", "alice")])
        .await;
    r.expect(StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/");
    jar.absorb(&r);
    assert!(!jar.0.contains_key("frg_signup"));
    let cookies = r.set_cookies().join("\n");
    assert!(cookies.contains("frg_session=frgs1_"));
    assert!(cookies.contains("HttpOnly"));

    // The cookie works on the whoami route; personal ns + admin membership.
    let me = h.get("/auth/session", Some(&jar), &[]).await;
    me.expect(StatusCode::OK);
    let me = me.json();
    assert_eq!(me["username"], "alice");
    assert_eq!(me["memberships"].as_array().unwrap().len(), 1);
    assert_eq!(me["memberships"][0]["role"], "admin");
    let personal = h
        .ctx
        .store()
        .node_by_path(&["alice"])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(me["memberships"][0]["namespace"], personal.id.to_string());
    assert!(h.audit.has("user.signup"));

    // Second login: straight to a session, no signup.
    h.idp
        .add("c2", "100", "alice@example.com", Some("whatever"));
    let mut jar2 = Jar::default();
    let cb = h.browser_login(&mut jar2, "stub", "c2").await;
    cb.expect(StatusCode::FOUND);
    assert_eq!(cb.location(), "/");
    assert!(!jar2.0.contains_key("frg_signup"));
    let me = h.whoami(&H::session(&jar2)).await;
    assert_eq!(me.json()["username"], "alice");

    // The redirect_uri the provider saw came from public_url.
    for uri in h.idp.redirect_uris.lock().unwrap().iter() {
        assert_eq!(uri, &format!("{PUBLIC}/auth/stub/callback"));
    }
}

#[tokio::test]
async fn json_signup_and_ticket_survives_a_failed_name() {
    let h = harness().await;
    h.signup("a", "1", "a@x.example", "alice").await;
    h.idp.add("b", "2", "b@x.example", None);
    let mut jar = Jar::default();
    h.browser_login(&mut jar, "stub", "b").await;
    let ticket = jar.get("frg_signup");

    let taken = h
        .post_json(
            "/auth/signup",
            None,
            None,
            &[],
            &json!({"ticket": ticket, "username": "Alice"}),
        )
        .await;
    taken.expect(StatusCode::CONFLICT);
    assert_eq!(taken.error(), "username_taken");
    // Same ticket, another name.
    let ok = h
        .post_json(
            "/auth/signup",
            None,
            None,
            &[],
            &json!({"ticket": ticket, "username": "bob"}),
        )
        .await;
    ok.expect(StatusCode::OK);
    assert_eq!(ok.json()["username"], "bob");
    // One-shot.
    let again = h
        .post_json(
            "/auth/signup",
            None,
            None,
            &[],
            &json!({"ticket": ticket, "username": "bob2"}),
        )
        .await;
    again.expect(StatusCode::GONE);
    assert_eq!(again.error(), "ticket_expired");
    // A forged ticket is the same answer; a cross-origin form is refused.
    let forged = h
        .post_json(
            "/auth/signup",
            None,
            None,
            &[],
            &json!({"ticket": "abc.def", "username": "x"}),
        )
        .await;
    assert_eq!(forged.error(), "ticket_expired");
    let cross = h
        .post_json(
            "/auth/signup",
            None,
            None,
            &[("origin", "https://evil.example")],
            &json!({"ticket": ticket, "username": "x"}),
        )
        .await;
    cross.expect(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cli_device_flow_end_to_end() {
    let h = harness().await;
    let mut browser = h.signup("a", "1", "a@x.example", "alice").await;

    let start = h
        .post_json("/auth/device/start", None, None, &[], &json!({}))
        .await;
    start.expect(StatusCode::OK);
    let start = start.json();
    let secret = start["device_secret"].as_str().unwrap().to_owned();
    let code = start["user_code"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("frgd1_"));
    assert_eq!(start["verification_uri"], format!("{PUBLIC}/auth/device"));
    assert_eq!(
        start["verification_uri_complete"],
        format!("{PUBLIC}/auth/device?code={code}")
    );

    let poll = |s: String| {
        let h = &h;
        async move {
            h.post_json(
                "/auth/device/poll",
                None,
                None,
                &[],
                &json!({"device_secret": s}),
            )
            .await
        }
    };
    assert_eq!(poll(secret.clone()).await.json()["status"], "pending");
    assert_eq!(poll(secret.clone()).await.json()["status"], "slow_down");
    h.clock.advance(5);
    assert_eq!(poll(secret.clone()).await.json()["status"], "pending");

    // Logged out: the page offers logins that come back here.
    let anon = h.get(&format!("/auth/device?code={code}"), None, &[]).await;
    anon.expect(StatusCode::OK);
    assert!(anon.text().contains("/auth/stub/start?return_to="));
    assert!(!anon.text().contains("<form"));

    // Logged in: a form with the code pre-filled and a CSRF field.
    let page = h
        .get(&format!("/auth/device?code={code}"), Some(&browser), &[])
        .await;
    page.expect(StatusCode::OK);
    let csrf = browser.get("frg_csrf");
    assert!(page.text().contains(&csrf));
    assert!(page.text().contains(&code));

    // Without CSRF: refused, and nothing approved.
    h.post_form(
        "/auth/device",
        &browser,
        &[("code", &code), ("action", "approve")],
    )
    .await
    .expect(StatusCode::FORBIDDEN);
    assert_eq!(poll(secret.clone()).await.json()["status"], "slow_down");

    h.post_form(
        "/auth/device",
        &browser,
        &[("code", &code), ("action", "approve"), ("csrf", &csrf)],
    )
    .await
    .expect(StatusCode::OK);
    // A second approval of the same code is a conflict.
    h.post_form(
        "/auth/device",
        &browser,
        &[("code", &code), ("action", "approve"), ("csrf", &csrf)],
    )
    .await
    .expect(StatusCode::CONFLICT);

    let granted = poll(secret.clone()).await;
    granted.expect(StatusCode::OK);
    let g = granted.json();
    assert_eq!(g["status"], "granted");
    assert_eq!(g["username"], "alice");
    let session = g["token"].as_str().unwrap().to_owned();
    let refresh = g["refresh_token"].as_str().unwrap().to_owned();
    assert!(refresh.starts_with("frgr1_"));
    h.whoami(&session).await.expect(StatusCode::OK);

    // Single mint.
    let again = poll(secret.clone()).await;
    again.expect(StatusCode::UNAUTHORIZED);
    assert_eq!(again.error(), "invalid_grant");

    // Non-rotating refresh: twice, both work, refresh never echoed.
    let mut minted = Vec::new();
    for _ in 0..2 {
        let r = h
            .post_json(
                "/auth/token",
                None,
                None,
                &[],
                &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
            )
            .await;
        r.expect(StatusCode::OK);
        assert!(r.json().get("refresh_token").is_none());
        minted.push(r.json()["token"].as_str().unwrap().to_owned());
    }
    for t in &minted {
        h.whoami(t).await.expect(StatusCode::OK);
    }

    // Replacing refresh of a session.
    let replaced = h
        .post_json(
            "/auth/token",
            None,
            None,
            &[],
            &json!({"grant_type": "refresh", "session_token": minted[0]}),
        )
        .await;
    replaced.expect(StatusCode::OK);
    h.whoami(&minted[0]).await.expect(StatusCode::UNAUTHORIZED);

    // logout --all kills every session and the refresh token.
    h.post_json(
        "/auth/logout",
        Some(&session),
        None,
        &[],
        &json!({"all": true}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    for t in minted.iter().chain([&session]) {
        h.whoami(t).await.expect(StatusCode::UNAUTHORIZED);
    }
    h.get("/auth/session", Some(&browser), &[])
        .await
        .expect(StatusCode::UNAUTHORIZED);
    h.post_json(
        "/auth/token",
        None,
        None,
        &[],
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    )
    .await
    .expect(StatusCode::UNAUTHORIZED);
    browser.0.clear();
}

#[tokio::test]
async fn device_denial_and_expiry() {
    let h = harness().await;
    let browser = h.signup("a", "1", "a@x.example", "alice").await;
    let start = h
        .post_json("/auth/device/start", None, None, &[], &json!({}))
        .await
        .json();
    let secret = start["device_secret"].as_str().unwrap().to_owned();
    let code = start["user_code"].as_str().unwrap().to_owned();
    h.post_form(
        "/auth/device",
        &browser,
        &[
            ("code", &code.to_lowercase()),
            ("action", "deny"),
            ("csrf", &browser.get("frg_csrf")),
        ],
    )
    .await
    .expect(StatusCode::OK);
    let p = h
        .post_json(
            "/auth/device/poll",
            None,
            None,
            &[],
            &json!({"device_secret": secret}),
        )
        .await;
    assert_eq!(p.json()["status"], "denied");

    let start = h
        .post_json("/auth/device/start", None, None, &[], &json!({}))
        .await
        .json();
    h.clock.advance(h.ctx.ttl().device_flow + 1);
    let p = h
        .post_json(
            "/auth/device/poll",
            None,
            None,
            &[],
            &json!({"device_secret": start["device_secret"]}),
        )
        .await;
    assert_eq!(p.json()["status"], "expired");
    // Not a device secret at all.
    h.post_json(
        "/auth/device/poll",
        None,
        None,
        &[],
        &json!({"device_secret": "nope"}),
    )
    .await
    .expect(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn csrf_and_cookie_confinement() {
    let h = harness().await;
    let jar = h.signup("a", "1", "a@x.example", "alice").await;
    let token = H::session(&jar);
    let csrf = jar.get("frg_csrf");

    // Cookie under the API prefix: GET needs no CSRF, POST does.
    h.get("/api/me", Some(&jar), &[])
        .await
        .expect(StatusCode::OK);
    h.post_json("/api/me", None, Some(&jar), &[], &json!({}))
        .await
        .expect(StatusCode::FORBIDDEN);
    h.post_json(
        "/api/me",
        None,
        Some(&jar),
        &[("x-frg-csrf", "0".repeat(64).as_str())],
        &json!({}),
    )
    .await
    .expect(StatusCode::FORBIDDEN);
    h.post_json(
        "/api/me",
        None,
        Some(&jar),
        &[("x-frg-csrf", &csrf)],
        &json!({}),
    )
    .await
    .expect(StatusCode::OK);
    assert!(h.audit.has("auth.reject.csrf"));
    // A bearer needs no CSRF header.
    h.post_json("/api/me", Some(&token), None, &[], &json!({}))
        .await
        .expect(StatusCode::OK);
    // The same carrier outside the prefix ignores the cookie.
    h.post_json(
        "/other/me",
        None,
        Some(&jar),
        &[("x-frg-csrf", &csrf)],
        &json!({}),
    )
    .await
    .expect(StatusCode::UNAUTHORIZED);

    // forgs' own JSON routes refuse a cookie-only request.
    for (uri, body) in [
        (
            "/auth/keys",
            json!({"action": "list", "namespace": "alice"}),
        ),
        ("/auth/logout", json!({})),
        (
            "/auth/members",
            json!({"action": "list", "namespace": "alice"}),
        ),
        (
            "/auth/rename",
            json!({"action": "user", "new_username": "zed"}),
        ),
    ] {
        h.post_json(uri, None, Some(&jar), &[("x-frg-csrf", &csrf)], &body)
            .await
            .expect(StatusCode::UNAUTHORIZED);
    }
    let t = h
        .post_json(
            "/auth/token",
            None,
            Some(&jar),
            &[("x-frg-csrf", &csrf)],
            &json!({"grant_type": "refresh", "session_token": ""}),
        )
        .await;
    t.expect(StatusCode::UNAUTHORIZED);

    // Browser logout: CSRF enforced for the cookie, clears cookies.
    h.post_json("/auth/session/logout", None, Some(&jar), &[], &json!({}))
        .await
        .expect(StatusCode::FORBIDDEN);
    let out = h
        .post_json(
            "/auth/session/logout",
            None,
            Some(&jar),
            &[("x-frg-csrf", &csrf)],
            &json!({}),
        )
        .await;
    out.expect(StatusCode::NO_CONTENT);
    assert!(out
        .set_cookies()
        .iter()
        .any(|c| c.starts_with("frg_session=;")));
    h.whoami(&token).await.expect(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_kind_is_403_and_every_401_is_identical() {
    let h = harness().await;
    let jar = h.signup("a", "1", "a@x.example", "alice").await;
    let session = H::session(&jar);
    let alice = h
        .ctx
        .store()
        .user_by_username("alice")
        .await
        .unwrap()
        .unwrap();
    let refresh = forgs_http::session::mint_refresh(&h.ctx, alice.id)
        .await
        .unwrap();
    let key = h
        .post_json(
            "/auth/keys",
            Some(&session),
            None,
            &[],
            &json!({"action": "create", "namespace": "alice", "ttl_secs": 600, "purpose": "node"}),
        )
        .await
        .json()["key"]
        .as_str()
        .unwrap()
        .to_owned();
    let device = h
        .post_json("/auth/device/start", None, None, &[], &json!({}))
        .await
        .json()["device_secret"]
        .as_str()
        .unwrap()
        .to_owned();

    for t in [&refresh, &key, &device] {
        let r = h.whoami(t).await;
        r.expect(StatusCode::FORBIDDEN);
        assert_eq!(r.error(), "forbidden");
    }

    let unknown = h
        .ctx
        .format()
        .mint(forgs::TokenKind::Session)
        .to_secret_string();
    let mut bodies = Vec::new();
    for t in [unknown.as_str(), "garbage", "frgs1_short", ""] {
        let r = h.whoami(t).await;
        r.expect(StatusCode::UNAUTHORIZED);
        bodies.push(r.body.clone());
    }
    let none = h.get("/auth/session", None, &[]).await;
    bodies.push(none.body.clone());
    h.clock.advance(h.ctx.ttl().session + 1);
    let expired = h.whoami(&session).await;
    expired.expect(StatusCode::UNAUTHORIZED);
    bodies.push(expired.body.clone());
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
    assert_eq!(bodies[0], br#"{"error":"unauthorized"}"#);
    assert!(h.audit.has("auth.reject.expired"));
    assert!(h.audit.has("auth.wrong_kind"));
}

#[tokio::test]
async fn tombstoned_reserved_and_invalid_usernames() {
    let h = harness().await;
    let jar = h.signup("a", "1", "a@x.example", "alice").await;
    h.post_json(
        "/auth/rename",
        Some(&H::session(&jar)),
        None,
        &[],
        &json!({"action": "user", "new_username": "alice2"}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    // Session survives the rename; the name changed.
    assert_eq!(
        h.whoami(&H::session(&jar)).await.json()["username"],
        "alice2"
    );

    h.idp.add("b", "2", "b@x.example", None);
    let mut jar2 = Jar::default();
    h.browser_login(&mut jar2, "stub", "b").await;
    let ticket = jar2.get("frg_signup");
    let try_name = |name: &'static str| {
        let h = &h;
        let ticket = ticket.clone();
        async move {
            h.post_json(
                "/auth/signup",
                None,
                None,
                &[],
                &json!({"ticket": ticket, "username": name}),
            )
            .await
        }
    };
    let r = try_name("alice").await;
    r.expect(StatusCode::CONFLICT);
    assert_eq!(r.error(), "username_taken");
    assert!(h.audit.has("signup.reject.name_taken"));
    for bad in ["admin", "-x", "a b", ""] {
        let r = try_name(bad).await;
        r.expect(StatusCode::BAD_REQUEST);
        assert_eq!(r.error(), "username_invalid", "{bad}");
    }
    // The HTML form re-renders with the error and the escaped input.
    let form = h
        .post_form("/auth/signup", &jar2, &[("username", "<b>admin")])
        .await;
    form.expect(StatusCode::BAD_REQUEST);
    assert!(form.text().contains("&lt;b&gt;admin"));
    assert!(!form.text().contains("<b>admin"));
    try_name("carol").await.expect(StatusCode::OK);
}

#[tokio::test]
async fn email_match_does_not_auto_link() {
    let h = harness().await;
    let bob = h.signup("b", "2", "bob@x.example", "bob").await;

    // A different provider asserting bob's verified email: signup, not a
    // session for bob.
    h.idp2.add("z", "900", "BOB@x.example", Some("bob"));
    let mut jar = Jar::default();
    let cb = h.browser_login(&mut jar, "stub2", "z").await;
    assert_eq!(cb.location(), "/auth/signup");
    assert!(!jar.0.contains_key("frg_session"));
    let r = h
        .post_form("/auth/signup", &jar, &[("username", "bobby")])
        .await;
    r.expect(StatusCode::CONFLICT);
    assert!(r.text().contains("add this login method"));
    let r = h
        .post_json(
            "/auth/signup",
            None,
            Some(&jar),
            &[],
            &json!({"ticket": "", "username": "bobby"}),
        )
        .await;
    assert_eq!(r.error(), "email_in_use");
    assert!(h
        .ctx
        .store()
        .user_by_username("bobby")
        .await
        .unwrap()
        .is_none());

    // Link from bob's authenticated session (CSRF-checked).
    let mut bob = bob;
    h.post_form("/auth/identities/link/stub2", &bob, &[])
        .await
        .expect(StatusCode::FORBIDDEN);
    let start = h
        .post_form(
            "/auth/identities/link/stub2",
            &bob,
            &[("csrf", &bob.get("frg_csrf"))],
        )
        .await;
    start.expect(StatusCode::SEE_OTHER);
    bob.absorb(&start);
    let state = query_param(&start.location(), "state");
    // The link intent is bound to bob's session: without it, refused.
    let mut stranger = Jar::default();
    stranger.0.insert("frg_oauth".into(), bob.get("frg_oauth"));
    h.get(
        &format!("/auth/stub2/callback?code=z&state={state}"),
        Some(&stranger),
        &[],
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
    let cb = h
        .get(
            &format!("/auth/stub2/callback?code=z&state={state}"),
            Some(&bob),
            &[],
        )
        .await;
    cb.expect(StatusCode::FOUND);
    assert!(h.audit.has("identity.link"));

    // Now stub2 logs bob in.
    let mut jar3 = Jar::default();
    let cb = h.browser_login(&mut jar3, "stub2", "z").await;
    assert_eq!(cb.location(), "/");
    assert_eq!(h.whoami(&H::session(&jar3)).await.json()["username"], "bob");
}

#[tokio::test]
async fn oauth_state_is_bound_and_redirect_uri_ignores_host() {
    let h = harness().await;
    h.idp.add("c", "1", "a@x.example", None);

    let start = h
        .get(
            "/auth/stub/start?return_to=//evil.example",
            None,
            &[
                ("host", "evil.example"),
                ("x-forwarded-host", "evil.example"),
            ],
        )
        .await;
    start.expect(StatusCode::FOUND);
    assert_eq!(
        query_param(&start.location(), "redirect_uri"),
        format!("{PUBLIC}/auth/stub/callback")
    );
    let mut jar = Jar::default();
    jar.absorb(&start);
    let state = query_param(&start.location(), "state");

    // Wrong state, no cookie, forged cookie, wrong provider: 400, nothing minted.
    h.get(
        &format!("/auth/stub/callback?code=c&state=x{state}"),
        Some(&jar),
        &[],
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
    h.get(
        &format!("/auth/stub/callback?code=c&state={state}"),
        None,
        &[],
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
    let mut forged = jar.clone();
    let v = forged.get("frg_oauth");
    forged
        .0
        .insert("frg_oauth".into(), format!("{}0", &v[..v.len() - 1]));
    h.get(
        &format!("/auth/stub/callback?code=c&state={state}"),
        Some(&forged),
        &[],
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
    h.get(
        &format!("/auth/stub2/callback?code=c&state={state}"),
        Some(&jar),
        &[],
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
    assert!(
        h.idp.redirect_uris.lock().unwrap().is_empty(),
        "no code spent"
    );

    // The real one works, and the hostile return_to was dropped.
    let cb = h
        .get(
            &format!("/auth/stub/callback?code=c&state={state}"),
            Some(&jar),
            &[],
        )
        .await;
    cb.expect(StatusCode::FOUND);
    jar.absorb(&cb);
    // Replay: the flow cookie is gone.
    h.get(
        &format!("/auth/stub/callback?code=c&state={state}"),
        Some(&jar),
        &[],
    )
    .await
    .expect(StatusCode::BAD_REQUEST);

    // Expired flow cookie.
    let mut jar = Jar::default();
    let start = h.get("/auth/stub/start", None, &[]).await;
    jar.absorb(&start);
    h.clock.advance(h.ctx.ttl().login_flow + 1);
    h.get(
        &format!(
            "/auth/stub/callback?code=c&state={}",
            query_param(&start.location(), "state")
        ),
        Some(&jar),
        &[],
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
    assert!(h.audit.has("auth.login.bad_state"));

    // Unknown provider.
    h.get("/auth/nope/start", None, &[])
        .await
        .expect(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_keys() {
    let h = harness().await;
    let alice = H::session(&h.signup("a", "1", "a@x.example", "alice").await);
    let bob = H::session(&h.signup("b", "2", "b@x.example", "bob").await);
    let keys = |t: &str, body: Value| {
        let h = &h;
        let t = t.to_owned();
        async move { h.post_json("/auth/keys", Some(&t), None, &[], &body).await }
    };
    let create = |ttl: u64, purpose: &str| json!({"action": "create", "namespace": "alice", "ttl_secs": ttl, "purpose": purpose});

    keys(&alice, create(0, "ci"))
        .await
        .expect(StatusCode::BAD_REQUEST);
    keys(&alice, create(31 * 24 * 3600, "ci"))
        .await
        .expect(StatusCode::BAD_REQUEST);
    keys(&alice, create(60, "cii"))
        .await
        .expect(StatusCode::BAD_REQUEST);
    keys(
        &alice,
        json!({"action": "create", "namespace": "alice", "ttl_secs": 60, "purpose": "node",
               "subject_name": "x"}),
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
    let r = keys(&bob, create(60, "ci")).await;
    r.expect(StatusCode::FORBIDDEN);
    assert!(h.audit.has("api_key.denied"));
    // Unknown namespace: the same 403.
    keys(
        &alice,
        json!({"action": "create", "namespace": "nope", "ttl_secs": 60, "purpose": "ci"}),
    )
    .await
    .expect(StatusCode::FORBIDDEN);

    let created = keys(&alice, create(3600, "ci")).await;
    created.expect(StatusCode::OK);
    let created = created.json();
    assert_eq!(created["single_use"], true);
    assert_eq!(created["expires"], NOW + 3600);
    let hash = created["key_hash"].as_str().unwrap().to_owned();

    let list = keys(&alice, json!({"action": "list", "namespace": "alice"}))
        .await
        .json();
    assert_eq!(list["keys"][0]["key_hash"], hash);
    assert!(!list.to_string().contains("frgk1_"));

    let revoke = |t: &str, prefix: &str| {
        keys(
            t,
            json!({"action": "revoke", "namespace": "alice", "prefix": prefix}),
        )
    };
    revoke(&alice, &hash[..7])
        .await
        .expect(StatusCode::BAD_REQUEST);
    revoke(&alice, "zzzzzzzz")
        .await
        .expect(StatusCode::BAD_REQUEST);
    revoke(&alice, "00000000ff")
        .await
        .expect(StatusCode::NOT_FOUND);

    // Two keys sharing a prefix: ambiguous.
    let ns = h
        .ctx
        .store()
        .node_by_path(&["alice"])
        .await
        .unwrap()
        .unwrap()
        .id;
    let alice_id = h
        .ctx
        .store()
        .user_by_username("alice")
        .await
        .unwrap()
        .unwrap()
        .id;
    for suffix in ["a", "b"] {
        h.ctx
            .store()
            .scoped(ns)
            .insert_api_key(
                &NewApiKey {
                    hash: TokenHash::from_hex(format!("deadbeef{}", suffix.repeat(56))),
                    purpose: "ci".into(),
                    subject_name: None,
                    payload: None,
                    single_use: true,
                    expires: Some(NOW + 60),
                    created_by: Some(alice_id),
                },
                NOW,
            )
            .await
            .unwrap();
    }
    let r = revoke(&alice, "deadbeef").await;
    r.expect(StatusCode::CONFLICT);
    assert_eq!(r.error(), "ambiguous_prefix");

    // Bob joins as a plain member: may mint, may not revoke alice's key.
    h.post_json(
        "/auth/members",
        Some(&alice),
        None,
        &[],
        &json!({"action": "set", "namespace": "alice", "username": "bob", "role": "member"}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    let bobs = keys(&bob, create(60, "ci")).await.json();
    let bobs_hash = bobs["key_hash"].as_str().unwrap().to_owned();
    revoke(&bob, &hash).await.expect(StatusCode::FORBIDDEN);
    assert!(h.audit.has("api_key.revoke.denied"));
    // Admin may revoke anyone's; creator their own.
    let r = revoke(&alice, &bobs_hash).await;
    r.expect(StatusCode::OK);
    assert_eq!(r.json()["revoked"][0], bobs_hash);
    let mine = keys(&bob, create(60, "ci")).await.json();
    revoke(&bob, mine["key_hash"].as_str().unwrap())
        .await
        .expect(StatusCode::OK);
    revoke(&alice, &hash).await.expect(StatusCode::OK);
}

#[tokio::test]
async fn workload_exchange() {
    let h = harness().await;
    let alice = H::session(&h.signup("a", "1", "a@x.example", "alice").await);
    let token = |body: Value| {
        let h = &h;
        async move { h.post_json("/auth/token", None, None, &[], &body).await }
    };

    // Named workload key → workload token speaking as the named identity.
    let key = h
        .post_json(
            "/auth/keys",
            Some(&alice),
            None,
            &[],
            &json!({"action": "create", "namespace": "alice", "ttl_secs": 600,
                    "purpose": "ci", "subject_name": "Builder"}),
        )
        .await
        .json();
    assert_eq!(key["subject_name"], "builder");
    let key = key["key"].as_str().unwrap().to_owned();
    let r = token(json!({"grant_type": "api_key", "api_key": key})).await;
    r.expect(StatusCode::OK);
    let wt = r.json();
    assert!(wt["expires"].as_u64().unwrap() <= NOW + 600);
    let me = h.whoami(wt["token"].as_str().unwrap()).await.json();
    assert!(me["subject"]
        .as_str()
        .unwrap()
        .ends_with("/workload:agent:builder"));
    // Single use.
    token(json!({"grant_type": "api_key", "api_key": key}))
        .await
        .expect(StatusCode::UNAUTHORIZED);
    // A workload token is not a session: 403 on session-only routes.
    h.post_json(
        "/auth/keys",
        wt["token"].as_str(),
        None,
        &[],
        &json!({"action": "list", "namespace": "alice"}),
    )
    .await
    .expect(StatusCode::FORBIDDEN);

    // An app-purpose key is refused without being burned.
    let node = h
        .post_json(
            "/auth/keys",
            Some(&alice),
            None,
            &[],
            &json!({"action": "create", "namespace": "alice", "ttl_secs": 600, "purpose": "node"}),
        )
        .await
        .json()["key"]
        .as_str()
        .unwrap()
        .to_owned();
    token(json!({"grant_type": "api_key", "api_key": node}))
        .await
        .expect(StatusCode::FORBIDDEN);
    let hash = h.ctx.format().parse(&node).unwrap().hash();
    assert!(h
        .ctx
        .store()
        .api_key_by_hash(&hash)
        .await
        .unwrap()
        .is_some());

    // OIDC: no grant → flat 401; with a grant → a workload token.
    let jwt = "good:octo/widgets";
    let r = token(json!({"grant_type": "github_oidc", "oidc_token": jwt})).await;
    r.expect(StatusCode::UNAUTHORIZED);
    assert_eq!(r.error(), "invalid_grant");
    token(json!({"grant_type": "github_oidc", "oidc_token": "bad"}))
        .await
        .expect(StatusCode::UNAUTHORIZED);
    let ns = h
        .ctx
        .store()
        .node_by_path(&["alice"])
        .await
        .unwrap()
        .unwrap()
        .id;
    h.ctx
        .store()
        .scoped(ns)
        .insert_grant(
            &NewGrant {
                subject: forgs::subject::workload_subject_key("octo/widgets"),
                selector: "*".into(),
                ops: "read".into(),
                expires: None,
                created_by: None,
            },
            NOW,
        )
        .await
        .unwrap();
    let r = token(json!({"grant_type": "github_oidc", "oidc_token": jwt})).await;
    r.expect(StatusCode::OK);
    assert_eq!(r.json()["expires"], NOW + 3600);
    let me = h.whoami(r.json()["token"].as_str().unwrap()).await.json();
    assert_eq!(
        me["subject"],
        SubjectKey::parse("gha/workload:octo/widgets")
            .unwrap()
            .to_string()
    );

    // Unconfigured server: 503.
    let h2 = harness_with(false).await;
    let r = h2
        .post_json(
            "/auth/token",
            None,
            None,
            &[],
            &json!({"grant_type": "github_oidc", "oidc_token": jwt}),
        )
        .await;
    r.expect(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.error(), "workload_unconfigured");
}

#[tokio::test]
async fn members_are_admin_gated_and_keep_an_admin() {
    let h = harness().await;
    let alice = H::session(&h.signup("a", "1", "a@x.example", "alice").await);
    let bob = H::session(&h.signup("b", "2", "b@x.example", "bob").await);
    let m = |t: &str, body: Value| {
        let h = &h;
        let t = t.to_owned();
        async move {
            h.post_json("/auth/members", Some(&t), None, &[], &body)
                .await
        }
    };

    m(&bob, json!({"action": "list", "namespace": "alice"}))
        .await
        .expect(StatusCode::FORBIDDEN);
    m(
        &alice,
        json!({"action": "set", "namespace": "alice", "username": "bob", "role": "member"}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    let list = m(&bob, json!({"action": "list", "namespace": "alice"})).await;
    list.expect(StatusCode::OK);
    assert_eq!(list.json()["members"].as_array().unwrap().len(), 2);
    // A member cannot manage members.
    m(
        &bob,
        json!({"action": "set", "namespace": "alice", "username": "bob", "role": "admin"}),
    )
    .await
    .expect(StatusCode::FORBIDDEN);
    // Unknown role, unknown user.
    m(
        &alice,
        json!({"action": "set", "namespace": "alice", "username": "bob", "role": "owner"}),
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
    m(
        &alice,
        json!({"action": "set", "namespace": "alice", "username": "zed", "role": "member"}),
    )
    .await
    .expect(StatusCode::NOT_FOUND);
    // The last admin cannot demote or remove themselves.
    let r = m(
        &alice,
        json!({"action": "set", "namespace": "alice", "username": "alice", "role": "member"}),
    )
    .await;
    r.expect(StatusCode::CONFLICT);
    assert_eq!(r.error(), "last_admin");
    m(
        &alice,
        json!({"action": "remove", "namespace": "alice", "username": "alice"}),
    )
    .await
    .expect(StatusCode::CONFLICT);
    // With a second admin, it is fine.
    m(
        &alice,
        json!({"action": "set", "namespace": "alice", "username": "bob", "role": "admin"}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    m(
        &bob,
        json!({"action": "remove", "namespace": "alice", "username": "alice"}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    m(&alice, json!({"action": "list", "namespace": "alice"}))
        .await
        .expect(StatusCode::FORBIDDEN);
    // A personal namespace is renamed with its user, not directly.
    h.post_json(
        "/auth/rename",
        Some(&bob),
        None,
        &[],
        &json!({"action": "namespace", "namespace": "alice", "new_name": "x"}),
    )
    .await
    .expect(StatusCode::CONFLICT);
    assert!(h.audit.has("member.set"));
    assert!(h.audit.has("member.remove"));
}

#[tokio::test]
async fn logout_ignores_someone_elses_refresh_token() {
    let h = harness().await;
    let alice = H::session(&h.signup("a", "1", "a@x.example", "alice").await);
    let bob_id = {
        h.signup("b", "2", "b@x.example", "bob").await;
        h.ctx
            .store()
            .user_by_username("bob")
            .await
            .unwrap()
            .unwrap()
            .id
    };
    let bobs_refresh = forgs_http::session::mint_refresh(&h.ctx, bob_id)
        .await
        .unwrap();
    h.post_json(
        "/auth/logout",
        Some(&alice),
        None,
        &[],
        &json!({"refresh_token": bobs_refresh}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    h.whoami(&alice).await.expect(StatusCode::UNAUTHORIZED);
    h.post_json(
        "/auth/token",
        None,
        None,
        &[],
        &json!({"grant_type": "refresh_token", "refresh_token": bobs_refresh}),
    )
    .await
    .expect(StatusCode::OK);
}

#[tokio::test]
async fn disabled_users_are_locked_out_uniformly() {
    let h = harness().await;
    let jar = h.signup("a", "1", "a@x.example", "alice").await;
    let id = h
        .ctx
        .store()
        .user_by_username("alice")
        .await
        .unwrap()
        .unwrap()
        .id;
    h.ctx
        .store()
        .set_user_state(id, forgs_store::UserState::Disabled)
        .await
        .unwrap();
    let r = h.whoami(&H::session(&jar)).await;
    r.expect(StatusCode::UNAUTHORIZED);
    assert_eq!(r.body, br#"{"error":"unauthorized"}"#);
    let mut j = Jar::default();
    h.idp.add("again", "1", "a@x.example", None);
    h.browser_login(&mut j, "stub", "again")
        .await
        .expect(StatusCode::FORBIDDEN);
    assert!(!j.0.contains_key("frg_session"));
}

#[tokio::test]
async fn config_is_validated() {
    let store = Store::connect_in_memory(schema(), RoleLadder::default())
        .await
        .unwrap();
    let b = |url: &str, secret: &[u8]| AuthContext::builder(store.clone(), url, secret);
    assert!(b("forge.example", &[1; 32]).build().is_err());
    assert!(b("https://x/?q=1", &[1; 32]).build().is_err());
    assert!(b(PUBLIC, &[1; 16]).build().is_err());
    assert!(b(PUBLIC, &[1; 32]).mount("x/").build().is_err());
    assert!(b(PUBLIC, &[1; 32])
        .provider(StubIdp::new("login"))
        .build()
        .is_err());
    assert!(b(PUBLIC, &[1; 32])
        .provider(StubIdp::new("a"))
        .provider(StubIdp::new("a"))
        .build()
        .is_err());
    let ctx = b(PUBLIC, &[1; 32]).mount("/sso").build().unwrap();
    assert_eq!(
        ctx.redirect_uri("github"),
        format!("{PUBLIC}/sso/auth/github/callback")
    );
}

#[tokio::test]
async fn app_connection_kinds_authenticate_through_the_hook() {
    let h = harness().await;
    let session = H::session(&h.signup("a", "1", "a@x.example", "alice").await);
    let get = |uri: &'static str, t: String| {
        let h = &h;
        async move {
            h.get(uri, None, &[("authorization", &format!("Bearer {t}"))])
                .await
        }
    };
    let subject = SubjectKey::new(Some("ns1"), forgs::SubjectKind::App("node"), "n1").unwrap();
    let token = h.ctx.format().mint(TokenKind::App(h.node));
    h.nodes.rows.lock().unwrap().insert(
        token.hash().as_str().to_owned(),
        AppRecord {
            subject: subject.clone(),
            expires: None,
            issued_at: Some(NOW),
        },
    );
    let node = token.to_secret_string();

    // Known node token: the app route and an AnyConnection route accept it,
    // speaking as the record's subject.
    let r = get("/api/node", node.clone()).await;
    r.expect(StatusCode::OK);
    assert_eq!(r.text(), subject.to_string());
    get("/api/any", node.clone()).await.expect(StatusCode::OK);
    // Fenced per route: SessionOnly routes refuse it with 403.
    get("/api/me", node.clone())
        .await
        .expect(StatusCode::FORBIDDEN);
    // `/auth/session` answers any connection kind with its subject.
    assert_eq!(h.whoami(&node).await.json()["subject"], subject.to_string());
    h.post_json(
        "/auth/keys",
        Some(&node),
        None,
        &[],
        &json!({"action": "list", "namespace": "alice"}),
    )
    .await
    .expect(StatusCode::FORBIDDEN);
    // And a session is not a node.
    get("/api/node", session.clone())
        .await
        .expect(StatusCode::FORBIDDEN);
    get("/api/any", session.clone())
        .await
        .expect(StatusCode::OK);
    // A node token cannot refresh a session.
    let r = h
        .post_json(
            "/auth/token",
            None,
            None,
            &[],
            &json!({"grant_type": "refresh", "session_token": node}),
        )
        .await;
    r.expect(StatusCode::UNAUTHORIZED);
    assert_eq!(r.error(), "invalid_grant");

    // Unknown, expired, revoked and a failing lookup: the uniform 401.
    let mut bodies = Vec::new();
    let unknown = h
        .ctx
        .format()
        .mint(TokenKind::App(h.node))
        .to_secret_string();
    let r = get("/api/node", unknown).await;
    r.expect(StatusCode::UNAUTHORIZED);
    bodies.push(r.body.clone());

    let expired = h.ctx.format().mint(TokenKind::App(h.node));
    h.nodes.rows.lock().unwrap().insert(
        expired.hash().as_str().to_owned(),
        AppRecord {
            subject: subject.clone(),
            expires: Some(NOW),
            issued_at: None,
        },
    );
    let r = get("/api/node", expired.to_secret_string()).await;
    r.expect(StatusCode::UNAUTHORIZED);
    bodies.push(r.body.clone());
    assert!(h.audit.has("auth.reject.expired"));

    h.nodes.broken.store(true, Ordering::SeqCst);
    let r = get("/api/node", node.clone()).await;
    r.expect(StatusCode::UNAUTHORIZED);
    bodies.push(r.body.clone());
    h.nodes.broken.store(false, Ordering::SeqCst);

    h.nodes.rows.lock().unwrap().remove(token.hash().as_str());
    let r = get("/api/node", node.clone()).await;
    r.expect(StatusCode::UNAUTHORIZED);
    bodies.push(r.body.clone());
    let r = get("/api/node", "garbage".to_owned()).await;
    bodies.push(r.body.clone());
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
    assert_eq!(bodies[0], br#"{"error":"unauthorized"}"#);

    // A redeem-only app kind is refused from its prefix: no lookup at all.
    let before = h.nodes.lookups.load(Ordering::SeqCst);
    let device = h
        .ctx
        .format()
        .mint(TokenKind::App(h.node_device))
        .to_secret_string();
    get("/api/node", device.clone())
        .await
        .expect(StatusCode::FORBIDDEN);
    get("/api/any", device).await.expect(StatusCode::FORBIDDEN);
    assert_eq!(h.nodes.lookups.load(Ordering::SeqCst), before);
}

#[tokio::test]
async fn app_tokens_are_unknown_without_a_hook() {
    let store = Store::connect_in_memory(schema(), RoleLadder::new(&["member", "admin"]).unwrap())
        .await
        .unwrap();
    let (format, node, _) = test_format();
    let ctx = AuthContext::builder(store, PUBLIC, &[42; 32])
        .format(format)
        .clock(Arc::new(FixedClock::new(NOW)))
        .build()
        .unwrap();
    let t = ctx.format().mint(TokenKind::App(node)).to_secret_string();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {t}").parse().unwrap(),
    );
    let allowed = [TokenKind::App(node)];
    let r = forgs_http::authenticate_request(
        &ctx,
        &headers,
        "/api/node",
        &allowed,
        forgs_http::Carrier::Header,
    )
    .await
    .unwrap_err();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_key_payloads_are_validated_canonicalised_and_listed() {
    let h = harness().await;
    let alice = H::session(&h.signup("a", "1", "a@x.example", "alice").await);
    let keys = |body: Value| {
        let h = &h;
        let t = alice.clone();
        async move { h.post_json("/auth/keys", Some(&t), None, &[], &body).await }
    };
    let create = |purpose: &str, payload: Value| {
        json!({"action": "create", "namespace": "alice", "ttl_secs": 60,
               "purpose": purpose, "payload": payload})
    };
    // `ci` knows no payload; `null` is the same as absent.
    keys(create("ci", json!({"ops": ["x"]})))
        .await
        .expect(StatusCode::BAD_REQUEST);
    let plain = keys(create("ci", Value::Null)).await;
    plain.expect(StatusCode::OK);
    assert!(plain.json().get("payload").is_none());
    // The hook refuses a bad shape.
    keys(create("node", json!({"tags": [1]})))
        .await
        .expect(StatusCode::BAD_REQUEST);
    // And canonicalises a good one.
    let r = keys(create("node", json!({"tags": ["b", "a", "b"]}))).await;
    r.expect(StatusCode::OK);
    let created = r.json();
    assert_eq!(created["payload"], json!({"tags": ["a", "b"]}));
    let hash = created["key_hash"].as_str().unwrap().to_owned();

    let list = keys(json!({"action": "list", "namespace": "alice"}))
        .await
        .json();
    let row = list["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key_hash"] == hash)
        .unwrap();
    assert_eq!(row["payload"], json!({"tags": ["a", "b"]}));

    let ns = h
        .ctx
        .store()
        .node_by_path(&["alice"])
        .await
        .unwrap()
        .unwrap()
        .id;
    let stored = h
        .ctx
        .store()
        .scoped(ns)
        .list_api_keys()
        .await
        .unwrap()
        .into_iter()
        .find(|k| k.key_hash.as_str() == hash)
        .unwrap();
    assert_eq!(stored.payload.as_deref(), Some(r#"{"tags":["a","b"]}"#));

    // A shell-minted key with a non-JSON payload is listed without one.
    h.ctx
        .store()
        .scoped(ns)
        .insert_api_key(
            &NewApiKey {
                hash: TokenHash::from_hex("ab".repeat(32)),
                purpose: "node".into(),
                subject_name: None,
                payload: Some("not json".into()),
                single_use: true,
                expires: None,
                created_by: None,
            },
            NOW,
        )
        .await
        .unwrap();
    let list = keys(json!({"action": "list", "namespace": "alice"}))
        .await
        .json();
    let odd = list["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key_hash"] == "ab".repeat(32))
        .unwrap();
    assert!(odd.get("payload").is_none());
}

#[tokio::test]
async fn named_identity_and_payload_authority_require_highest_role() {
    let h = harness().await;
    let alice = H::session(&h.signup("a", "1", "a@x.example", "alice").await);
    let bob = H::session(&h.signup("b", "2", "b@x.example", "bob").await);
    let keys = |t: &str, body: Value| {
        let h = &h;
        let t = t.to_owned();
        async move { h.post_json("/auth/keys", Some(&t), None, &[], &body).await }
    };
    let named = |name: Option<&str>| {
        let mut b = json!({"action": "create", "namespace": "alice", "ttl_secs": 600,
                           "purpose": "ci"});
        if let Some(n) = name {
            b["subject_name"] = json!(n);
        }
        b
    };
    let set_role = |role: &str| {
        let h = &h;
        let alice = alice.clone();
        let body = json!({"action": "set", "namespace": "alice", "username": "bob", "role": role});
        async move {
            h.post_json("/auth/members", Some(&alice), None, &[], &body)
                .await
                .expect(StatusCode::NO_CONTENT);
        }
    };
    let redeem_subject = |key: Value| {
        let h = &h;
        async move {
            let r = h
                .post_json(
                    "/auth/token",
                    None,
                    None,
                    &[],
                    &json!({"grant_type": "api_key", "api_key": key["key"]}),
                )
                .await;
            r.expect(StatusCode::OK);
            h.whoami(r.json()["token"].as_str().unwrap()).await.json()["subject"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };

    // The admin names an identity.
    keys(&alice, named(Some("deployer")))
        .await
        .expect(StatusCode::OK);
    set_role("member").await;
    // A plain member may not reuse it, nor name a fresh one.
    keys(&bob, named(Some("deployer")))
        .await
        .expect(StatusCode::FORBIDDEN);
    assert!(h.audit.has("api_key.denied"));
    keys(&bob, named(Some("other")))
        .await
        .expect(StatusCode::FORBIDDEN);
    // An unnamed key is fine, and speaks as its own immutable id.
    let r = keys(&bob, named(None)).await;
    r.expect(StatusCode::OK);
    let unnamed = r.json();
    let subject = redeem_subject(unnamed.clone()).await;
    assert!(
        subject.ends_with(&format!(
            "/workload:key:{}",
            unnamed["id"].as_str().unwrap()
        )),
        "{subject}"
    );
    assert!(!subject.contains(&unnamed["key_hash"].as_str().unwrap()[..8]));
    // The payload hook sees the role: a member may not mint tags.
    let node = json!({"action": "create", "namespace": "alice", "ttl_secs": 60,
                      "purpose": "node", "payload": {"tags": ["a"]}});
    keys(&bob, node.clone()).await.expect(StatusCode::FORBIDDEN);
    keys(&alice, node).await.expect(StatusCode::OK);

    // The admin can still rotate the identity.
    let r = keys(&alice, named(Some("deployer"))).await;
    r.expect(StatusCode::OK);
    assert!(redeem_subject(r.json())
        .await
        .ends_with("/workload:agent:deployer"));
    // A promoted bob may.
    set_role("admin").await;
    keys(&bob, named(Some("deployer")))
        .await
        .expect(StatusCode::OK);
}

#[tokio::test]
async fn create_and_delete_namespace() {
    use forgs_http::members::{create_namespace, delete_namespace};

    let h = harness().await;
    h.signup("a", "1", "a@x.example", "alice").await;
    h.signup("b", "2", "b@x.example", "bob").await;
    let id = |name: &'static str| {
        let h = &h;
        async move {
            h.ctx
                .store()
                .user_by_username(name)
                .await
                .unwrap()
                .unwrap()
                .id
        }
    };
    let alice = id("alice").await;
    let bob = id("bob").await;

    let team = create_namespace(&h.ctx, alice, None, "org", "team", Some(1))
        .await
        .unwrap();
    assert_eq!(
        h.ctx
            .store()
            .effective_role(team, &SubjectKey::user(alice))
            .await
            .unwrap(),
        Some(h.ctx.store().roles().highest())
    );
    assert!(h.audit.has("namespace.create"));

    let e = create_namespace(&h.ctx, alice, None, "org", "team2", Some(1))
        .await
        .unwrap_err();
    assert_eq!(e, ApiError::NAMESPACE_LIMIT);
    assert_eq!(e.status(), StatusCode::FORBIDDEN);
    let e = create_namespace(&h.ctx, bob, None, "org", "TEAM", None)
        .await
        .unwrap_err();
    assert_eq!(e.code(), "username_taken");
    let e = create_namespace(&h.ctx, bob, None, "nope", "x", None)
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::BAD_REQUEST);
    // The schema's org kind is a leaf: nothing can go under it, and only an
    // admin of the parent gets that far.
    let e = create_namespace(&h.ctx, bob, Some("team"), "org", "x", None)
        .await
        .unwrap_err();
    assert_eq!(e, ApiError::Forbidden);
    let e = create_namespace(&h.ctx, alice, Some("team"), "org", "x", None)
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::BAD_REQUEST);

    let e = delete_namespace(&h.ctx, bob, "team").await.unwrap_err();
    assert_eq!(e, ApiError::Forbidden);
    // A plain member is refused too, and that refusal is audited.
    forgs_http::members::set(&h.ctx, alice, "team", "bob", "member")
        .await
        .unwrap();
    let e = delete_namespace(&h.ctx, bob, "team").await.unwrap_err();
    assert_eq!(e, ApiError::Forbidden);
    assert!(h.audit.has("namespace.delete.denied"));
    let e = delete_namespace(&h.ctx, alice, "alice").await.unwrap_err();
    assert_eq!(e, ApiError::CONFLICT);
    delete_namespace(&h.ctx, alice, "team").await.unwrap();
    assert!(h.audit.has("namespace.delete"));
    assert!(h.ctx.store().node(team).await.unwrap().is_none());
    // The name is released forever; the cap no longer counts the old node.
    let e = create_namespace(&h.ctx, alice, None, "org", "team", Some(1))
        .await
        .unwrap_err();
    assert_eq!(e.code(), "username_taken");
    create_namespace(&h.ctx, alice, None, "org", "team2", Some(1))
        .await
        .unwrap();
}
