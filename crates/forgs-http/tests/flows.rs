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
    AuditSink, AuthContext, Authenticated, ConfigError, FixedClock, HeaderOnly, KeyMint,
    PurposeKind, SessionOnly, StaticPurposes,
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

/// Accepts `<prefix>:<owner_id>/<repo_id>/<owner>/<repo>` (prefix `good` for
/// the default issuer), keyed under `ns`. The `jti` is everything after the
/// prefix, so the same string is the same token, and two issuers can share a
/// `jti`.
struct StubIssuer {
    name: &'static str,
    ns: &'static str,
    prefix: &'static str,
}

const STUB_ISSUER: StubIssuer = StubIssuer {
    name: "github-actions",
    ns: "gha",
    prefix: "good",
};

#[async_trait]
impl WorkloadIssuer for StubIssuer {
    fn name(&self) -> &str {
        self.name
    }
    fn subject_ns(&self) -> &str {
        self.ns
    }
    async fn verify(&self, jwt: &str, _now: u64) -> Result<WorkloadIdentity, OidcError> {
        let rest = jwt
            .strip_prefix(self.prefix)
            .and_then(|r| r.strip_prefix(':'))
            .ok_or(OidcError::BadSignature)?;
        let mut parts = rest.splitn(4, '/');
        let (Some(oid), Some(rid), Some(owner), Some(name)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(OidcError::Malformed);
        };
        Ok(WorkloadIdentity {
            subject: forgs::subject::workload_subject_key(self.ns, oid, rid)
                .ok_or(OidcError::Malformed)?,
            claims: WorkloadClaims {
                repository_id: rid.to_owned(),
                repository_owner_id: oid.to_owned(),
                repository: format!("{owner}/{name}"),
                repository_owner: owner.to_owned(),
                git_ref: Some("refs/heads/main".into()),
                ref_type: None,
                ref_protected: None,
                environment: None,
                event_name: Some("push".into()),
                workflow: None,
                job_workflow_ref: None,
                runner_environment: None,
                run_id: None,
                sub: "repo:x".into(),
                exp: NOW + 300,
                jti: rest.to_owned(),
                accept_until: NOW + 360,
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

/// App approvals: anyone may approve; `redeem` is counted.
#[derive(Default)]
struct CountingApprovals(AtomicUsize);

#[async_trait]
impl forgs_http::PendingApprovalHook for CountingApprovals {
    async fn authorize(
        &self,
        _ctx: &AuthContext,
        _row: &forgs_store::PendingDevice,
        _approver: forgs::UserId,
        _ns: Option<forgs::NsNodeId>,
    ) -> Result<(), ApiError> {
        Ok(())
    }

    async fn redeem(
        &self,
        _ctx: &AuthContext,
        _approved_by: forgs::UserId,
        _ns: Option<forgs::NsNodeId>,
        _payload: &str,
    ) -> Result<Value, ApiError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"ok": true}))
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
    approvals: Arc<CountingApprovals>,
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

/// Brand `frg` (cookies `__Host-frg_*`) plus fleet-like app kinds.
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
    harness_cfg(issuer, public_url, |b| b).await
}

async fn harness_cfg(
    issuer: bool,
    public_url: &str,
    cfg: impl FnOnce(forgs_http::AuthContextBuilder) -> forgs_http::AuthContextBuilder,
) -> H {
    let store = Store::connect_in_memory(schema(), RoleLadder::new(&["member", "admin"]).unwrap())
        .await
        .unwrap();
    let clock = Arc::new(FixedClock::new(NOW));
    let idp = StubIdp::new("stub");
    let idp2 = StubIdp::new("stub2");
    let audit = Arc::new(Collect::default());
    let nodes = Arc::new(NodeTokens::default());
    let approvals = Arc::new(CountingApprovals::default());
    let (format, node, node_device) = test_format();
    let mut b = AuthContext::builder(store, public_url, &[42; 32])
        .app_label("test")
        .format(format)
        .app_tokens(nodes.clone())
        .clock(clock.clone())
        .provider(idp.clone())
        .provider(idp2.clone())
        .audit(audit.clone())
        .pending_approvals(approvals.clone())
        .api_key_purposes(Arc::new(TestPurposes(
            StaticPurposes::new()
                .with("ci", PurposeKind::Workload)
                .with("node", PurposeKind::App),
        )));
    if issuer {
        b = b
            .workload_issuer(Arc::new(STUB_ISSUER))
            .workload_issuer(Arc::new(StubIssuer {
                name: "ghes",
                ns: "ghes-corp",
                prefix: "ghes",
            }));
    }
    let ctx = cfg(b).build().unwrap();
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
        approvals,
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

    /// A browser form POST: `Origin: PUBLIC` unless `extra` sets one.
    async fn post_form_with(
        &self,
        uri: &str,
        jar: &Jar,
        extra: &[(&str, &str)],
        form: &[(&str, &str)],
    ) -> Resp {
        if extra.iter().any(|(k, _)| k.eq_ignore_ascii_case("origin")) {
            return self.post_form_raw(uri, jar, extra, form).await;
        }
        let mut with_origin = vec![("origin", PUBLIC)];
        with_origin.extend_from_slice(extra);
        self.post_form_raw(uri, jar, &with_origin, form).await
    }

    /// A form POST carrying exactly `extra` (no default `Origin`).
    async fn post_form_raw(
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
        jar.get("__Host-frg_session")
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
        // No Origin: the cookie ticket is an ambient credential, so only the
        // browser's own fetch metadata can vouch for the request.
        (&[], StatusCode::FORBIDDEN),
        (&[("sec-fetch-site", "same-origin")], StatusCode::SEE_OTHER),
        (&[("sec-fetch-site", "same-site")], StatusCode::FORBIDDEN),
        (&[("sec-fetch-site", "none")], StatusCode::FORBIDDEN),
    ];
    // A trailing slash, a path or an explicit default port in public_url
    // still yields the bare origin.
    for public_url in [
        format!("{PUBLIC}/"),
        format!("{PUBLIC}/app/"),
        format!("{PUBLIC}:443/"),
    ] {
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
                .post_form_raw("/auth/signup", &jar, extra, &[("username", &name)])
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
    assert!(jar.0.contains_key("__Host-frg_signup"));
    assert!(
        !jar.0.contains_key("__Host-frg_session"),
        "no session before signup"
    );
    assert!(
        !jar.0.contains_key("__Host-frg_oauth"),
        "flow cookie is spent"
    );

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
    assert!(!jar.0.contains_key("__Host-frg_signup"));
    let cookies = r.set_cookies().join("\n");
    assert!(cookies.contains("__Host-frg_session=frgs1_"));
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
    assert!(!jar2.0.contains_key("__Host-frg_signup"));
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
    let ticket = jar.get("__Host-frg_signup");

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
async fn a_new_login_ends_the_browsers_previous_session() {
    let h = harness().await;
    let mut jar = h.signup("a", "1", "a@x.example", "alice").await;
    h.signup("b", "2", "b@x.example", "bob").await;
    let old = H::session(&jar);
    h.whoami(&old).await.expect(StatusCode::OK);

    // Same browser, logging in again (here as bob): alice's session ends.
    h.idp.add("b2", "2", "b@x.example", None);
    let cb = h.browser_login(&mut jar, "stub", "b2").await;
    cb.expect(StatusCode::FOUND);
    let new = H::session(&jar);
    assert_ne!(new, old);
    h.whoami(&old).await.expect(StatusCode::UNAUTHORIZED);
    let me = h.whoami(&new).await;
    me.expect(StatusCode::OK);
    assert_eq!(me.json()["username"], "bob");
}

#[tokio::test]
async fn json_signup_from_the_cookie_needs_an_origin() {
    let h = harness().await;
    h.idp.add("b", "2", "b@x.example", None);
    let mut jar = Jar::default();
    h.browser_login(&mut jar, "stub", "b").await;
    // The ticket rides in the cookie (empty body ticket): with no Origin and
    // no fetch metadata that is an unvouched ambient credential.
    let bare = h
        .post_json(
            "/auth/signup",
            None,
            Some(&jar),
            &[],
            &json!({"ticket": "", "username": "bob"}),
        )
        .await;
    bare.expect(StatusCode::FORBIDDEN);
    let ok = h
        .post_json(
            "/auth/signup",
            None,
            Some(&jar),
            &[("origin", PUBLIC)],
            &json!({"ticket": "", "username": "bob"}),
        )
        .await;
    ok.expect(StatusCode::OK);
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
    // No link that carries the code: the user must type it.
    assert!(start.get("verification_uri_complete").is_none());

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
    // Too fast: slow_down, and the interval grows by 5s each time.
    assert_eq!(poll(secret.clone()).await.json()["status"], "slow_down");
    h.clock.advance(5);
    assert_eq!(poll(secret.clone()).await.json()["status"], "slow_down");
    h.clock.advance(15);
    assert_eq!(poll(secret.clone()).await.json()["status"], "pending");

    // Logged out: the page offers logins that come back here.
    let anon = h.get(&format!("/auth/device?code={code}"), None, &[]).await;
    anon.expect(StatusCode::OK);
    assert!(anon.text().contains("/auth/stub/start?return_to="));
    assert!(!anon.text().contains("<form"));

    // Logged in: a form with a CSRF field, never pre-filled from the link.
    let page = h
        .get(&format!("/auth/device?code={code}"), Some(&browser), &[])
        .await;
    page.expect(StatusCode::OK);
    let csrf = browser.get("__Host-frg_csrf");
    assert!(page.text().contains(&csrf));
    assert!(!page.text().contains(&code));
    assert!(page.text().contains("value=\"review\""));

    // The review step shows when the device asked; nothing is decided.
    let review = h
        .post_form(
            "/auth/device",
            &browser,
            &[("code", &code), ("action", "review"), ("csrf", &csrf)],
        )
        .await;
    review.expect(StatusCode::OK);
    assert!(
        review.text().contains("2027-01-15 08:00:00 UTC"),
        "{}",
        review.text()
    );
    assert!(review.text().contains("an unknown address"));
    assert!(review.text().contains("value=\"approve\""));

    // Without CSRF: refused, and nothing approved.
    h.post_form(
        "/auth/device",
        &browser,
        &[("code", &code), ("action", "approve")],
    )
    .await
    .expect(StatusCode::FORBIDDEN);
    h.clock.advance(60);
    assert_eq!(poll(secret.clone()).await.json()["status"], "pending");

    h.post_form(
        "/auth/device",
        &browser,
        &[("code", &code), ("action", "approve"), ("csrf", &csrf)],
    )
    .await
    .expect(StatusCode::OK);
    // A second approval of the same code looks like an unknown code.
    h.post_form(
        "/auth/device",
        &browser,
        &[("code", &code), ("action", "approve"), ("csrf", &csrf)],
    )
    .await
    .expect(StatusCode::NOT_FOUND);
    assert!(h.audit.has("device.decide.unknown"));

    h.clock.advance(15);
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
            ("csrf", &browser.get("__Host-frg_csrf")),
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
    let csrf = jar.get("__Host-frg_csrf");

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
        .any(|c| c.starts_with("__Host-frg_session=;")));
    // The flow cookies go too: no half-finished login or signup outlives it.
    for name in ["__Host-frg_oauth", "__Host-frg_signup"] {
        assert!(
            out.set_cookies()
                .iter()
                .any(|c| c.starts_with(&format!("{name}=;")) && c.contains("Max-Age=0")),
            "{name}"
        );
    }
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
async fn concurrent_session_refresh_yields_exactly_one_success() {
    let h = harness().await;
    let jar = h.signup("a", "1", "a@x.example", "alice").await;
    let session = H::session(&jar);
    let (a, b) = tokio::join!(
        forgs_http::session::refresh_session(&h.ctx, &session),
        forgs_http::session::refresh_session(&h.ctx, &session)
    );
    let (ok, err): (Vec<_>, Vec<_>) = [a, b].into_iter().partition(Result::is_ok);
    assert_eq!(ok.len(), 1, "exactly one refresh wins");
    assert!(matches!(err[0], Err(forgs_http::ApiError::InvalidGrant)));
    h.whoami(&session).await.expect(StatusCode::UNAUTHORIZED);
    let fresh = ok.into_iter().next().unwrap().unwrap().token;
    h.whoami(&fresh).await.expect(StatusCode::OK);
    assert!(h.audit.has("session.refresh_refused"));
}

#[tokio::test]
async fn session_refresh_chain_has_an_absolute_lifetime() {
    let h = harness().await;
    let jar = h.signup("a", "1", "a@x.example", "alice").await;
    let ttl = *h.ctx.ttl();
    let start = h.ctx.now();
    let end = start + ttl.session_max_life;
    let refresh = |tok: String| {
        let h = &h;
        async move {
            h.post_json(
                "/auth/token",
                None,
                None,
                &[],
                &json!({"grant_type": "refresh", "session_token": tok}),
            )
            .await
        }
    };
    let mut tok = H::session(&jar);
    let mut refused = false;
    for _ in 0..1000 {
        h.clock.advance(ttl.session - 60);
        let r = refresh(tok.clone()).await;
        if r.status == StatusCode::UNAUTHORIZED {
            assert_eq!(r.error(), "invalid_grant");
            refused = true;
            break;
        }
        r.expect(StatusCode::OK);
        let expires = r.json()["expires"].as_u64().unwrap();
        assert!(expires <= end, "refreshed session outlives the chain");
        tok = r.json()["token"].as_str().unwrap().to_owned();
    }
    assert!(refused, "the chain was refreshable forever");
    assert!(h.ctx.now() >= end);

    // A refresh-token redemption starts a fresh, refreshable chain.
    let alice = h
        .ctx
        .store()
        .user_by_username("alice")
        .await
        .unwrap()
        .unwrap();
    let rt = forgs_http::session::mint_refresh(&h.ctx, alice.id)
        .await
        .unwrap();
    let r = h
        .post_json(
            "/auth/token",
            None,
            None,
            &[],
            &json!({"grant_type": "refresh_token", "refresh_token": rt}),
        )
        .await;
    r.expect(StatusCode::OK);
    let new = r.json()["token"].as_str().unwrap().to_owned();
    let r = refresh(new).await;
    r.expect(StatusCode::OK);
    assert_eq!(
        r.json()["expires"].as_u64().unwrap(),
        h.ctx.now() + ttl.session
    );
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
    let ticket = jar2.get("__Host-frg_signup");
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
async fn rename_loops_are_rate_limited() {
    let h = harness().await;
    let jar = h.signup("a", "1", "a@x.example", "alice").await;
    let rename = |name: String| {
        let h = &h;
        let jar = &jar;
        async move {
            h.post_json(
                "/auth/rename",
                Some(&H::session(jar)),
                None,
                &[],
                &json!({"action": "user", "new_username": name}),
            )
            .await
        }
    };
    let max = forgs_store::DEFAULT_RELEASE_LIMIT.max;
    for i in 0..max {
        rename(format!("alice{i}"))
            .await
            .expect(StatusCode::NO_CONTENT);
    }
    let r = rename("google".into()).await;
    r.expect(StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.error(), "rate_limited");
    assert!(h.audit.has("user.rename.limited"));
    // The refused name was not burned.
    assert!(h
        .ctx
        .store()
        .tombstone(None, "google")
        .await
        .unwrap()
        .is_none());
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
    assert!(!jar.0.contains_key("__Host-frg_session"));
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
            &[("origin", PUBLIC)],
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

    // Link from bob's authenticated session (CSRF-checked), after step-up
    // through the provider he already has (stub, code "b").
    let mut bob = bob;
    h.post_form("/auth/identities/link/stub2", &bob, &[])
        .await
        .expect(StatusCode::FORBIDDEN);
    let start = h
        .post_form(
            "/auth/identities/link/stub2",
            &bob,
            &[("csrf", &bob.get("__Host-frg_csrf"))],
        )
        .await;
    start.expect(StatusCode::SEE_OTHER);
    bob.absorb(&start);
    // The first leg goes to the *already linked* provider.
    assert!(query_param(&start.location(), "redirect_uri").ends_with("/auth/stub/callback"));
    let state = query_param(&start.location(), "state");
    // The intent is bound to bob's session: without it, refused.
    let mut stranger = Jar::default();
    stranger
        .0
        .insert("__Host-frg_oauth".into(), bob.get("__Host-frg_oauth"));
    h.get(
        &format!("/auth/stub/callback?code=b&state={state}"),
        Some(&stranger),
        &[],
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
    // A reauth-leg cookie cannot be used at the target provider directly.
    h.get(
        &format!("/auth/stub2/callback?code=z&state={state}"),
        Some(&bob),
        &[],
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
    let reauth = h
        .get(
            &format!("/auth/stub/callback?code=b&state={state}"),
            Some(&bob),
            &[],
        )
        .await;
    reauth.expect(StatusCode::FOUND);
    assert!(h.audit.has("identity.link.reauth"));
    assert!(query_param(&reauth.location(), "redirect_uri").ends_with("/auth/stub2/callback"));
    assert_eq!(
        reauth
            .set_cookies()
            .iter()
            .filter(|c| c.starts_with("__Host-frg_oauth="))
            .count(),
        1
    );
    bob.absorb(&reauth);
    let state = query_param(&reauth.location(), "state");
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

impl H {
    async fn user_id(&self, username: &str) -> forgs::UserId {
        self.ctx
            .store()
            .user_by_username(username)
            .await
            .unwrap()
            .unwrap()
            .id
    }

    /// Start linking `target` from `jar`'s session; returns the 303.
    async fn link_start(&self, jar: &mut Jar, target: &str) -> Resp {
        let r = self
            .post_form(
                &format!("/auth/identities/link/{target}"),
                jar,
                &[("csrf", &jar.get("__Host-frg_csrf"))],
            )
            .await;
        jar.absorb(&r);
        r
    }

    /// The full two-leg link: reauth via `reauth`/`reauth_code`, then link
    /// `target`/`code`. Returns the final callback.
    async fn link(
        &self,
        jar: &mut Jar,
        reauth: &str,
        reauth_code: &str,
        target: &str,
        code: &str,
    ) -> Resp {
        let start = self.link_start(jar, target).await;
        start.expect(StatusCode::SEE_OTHER);
        let state = query_param(&start.location(), "state");
        let r = self
            .get(
                &format!("/auth/{reauth}/callback?code={reauth_code}&state={state}"),
                Some(jar),
                &[],
            )
            .await;
        r.expect(StatusCode::FOUND);
        jar.absorb(&r);
        let state = query_param(&r.location(), "state");
        let cb = self
            .get(
                &format!("/auth/{target}/callback?code={code}&state={state}"),
                Some(jar),
                &[],
            )
            .await;
        jar.absorb(&cb);
        cb
    }
}

#[tokio::test]
async fn link_start_refuses_a_bearer_and_a_user_without_identities() {
    let h = harness().await;
    let bob = h.signup("b", "2", "bob@x.example", "bob").await;
    let r = h
        .post_form_with(
            "/auth/identities/link/stub2",
            &Jar::default(),
            &[("authorization", &format!("Bearer {}", H::session(&bob)))],
            &[],
        )
        .await;
    r.expect(StatusCode::FORBIDDEN);
    assert!(r
        .set_cookies()
        .iter()
        .all(|c| !c.starts_with("__Host-frg_oauth=")));
    assert!(h.audit.has("identity.link.refused"));

    // A local user (no identity) cannot step up, so cannot link.
    let (local, _) = h
        .ctx
        .store()
        .create_local_user("root", None, NOW)
        .await
        .unwrap();
    let s = forgs_http::session::mint_session(&h.ctx, local, "test")
        .await
        .unwrap();
    let mut jar = Jar::default();
    jar.0.insert("__Host-frg_session".into(), s.token.clone());
    jar.0.insert(
        "__Host-frg_csrf".into(),
        forgs_http::cookies::csrf_token(
            &h.ctx,
            h.ctx.format().parse(&s.token).unwrap().hash().as_str(),
        ),
    );
    let r = h.link_start(&mut jar, "stub2").await;
    assert_eq!(r.error(), "reauth_required");
}

#[tokio::test]
async fn reauth_with_someone_elses_identity_links_nothing() {
    let h = harness().await;
    let mut bob = h.signup("b", "2", "bob@x.example", "bob").await;
    h.signup("a", "1", "a@x.example", "alice").await;
    h.idp2.add("z", "900", "z@x.example", None);
    let start = h.link_start(&mut bob, "stub2").await;
    start.expect(StatusCode::SEE_OTHER);
    let state = query_param(&start.location(), "state");
    // The IdP hands back alice's identity (code "a"), not bob's.
    let r = h
        .get(
            &format!("/auth/stub/callback?code=a&state={state}"),
            Some(&bob),
            &[],
        )
        .await;
    r.expect(StatusCode::FORBIDDEN);
    assert!(r.text().contains("confirm it"));
    assert!(h.audit.has("identity.link.reauth_failed"));
    // And an identity unknown to everyone is refused the same way.
    h.idp.add("n", "777", "n@x.example", None);
    let start = h.link_start(&mut bob, "stub2").await;
    let state = query_param(&start.location(), "state");
    h.get(
        &format!("/auth/stub/callback?code=n&state={state}"),
        Some(&bob),
        &[],
    )
    .await
    .expect(StatusCode::FORBIDDEN);
    let bob_id = h.user_id("bob").await;
    assert_eq!(
        h.ctx
            .store()
            .identities_for_user(bob_id)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn identities_are_listed_and_unlinked_but_never_the_last() {
    let h = harness().await;
    let mut bob = h.signup("b", "2", "bob@x.example", "bob").await;
    let alice = h.signup("a", "1", "a@x.example", "alice").await;
    h.idp2.add("z", "900", "z@x.example", None);
    h.clock.advance(10);
    h.link(&mut bob, "stub", "b", "stub2", "z")
        .await
        .expect(StatusCode::FOUND);

    // Listed via cookie and via bearer.
    let by_cookie = h.get("/auth/identities", Some(&bob), &[]).await;
    by_cookie.expect(StatusCode::OK);
    let list = h
        .get(
            "/auth/identities",
            None,
            &[("authorization", &format!("Bearer {}", H::session(&bob)))],
        )
        .await
        .json();
    assert_eq!(by_cookie.json(), list);
    let ids = list["identities"].as_array().unwrap();
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0]["provider"], "stub");
    assert_eq!(ids[1]["provider"], "stub2");
    assert_eq!(ids[1]["subject"], "900");
    let stub_id = ids[0]["id"].as_str().unwrap().to_owned();
    let stub2_id = ids[1]["id"].as_str().unwrap().to_owned();

    // A cookie unlink without CSRF is refused.
    h.post_json(
        "/auth/identities/unlink",
        None,
        Some(&bob),
        &[],
        &json!({"id": stub2_id}),
    )
    .await
    .expect(StatusCode::FORBIDDEN);
    // Someone else's id, or garbage: 404 alike.
    let alice_ids = h
        .get(
            "/auth/identities",
            None,
            &[("authorization", &format!("Bearer {}", H::session(&alice)))],
        )
        .await
        .json();
    let alice_id = alice_ids["identities"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for id in [alice_id.as_str(), "nope"] {
        let r = h
            .post_json(
                "/auth/identities/unlink",
                Some(&H::session(&bob)),
                None,
                &[],
                &json!({ "id": id }),
            )
            .await;
        r.expect(StatusCode::NOT_FOUND);
    }
    let csrf = bob.get("__Host-frg_csrf");
    h.post_json(
        "/auth/identities/unlink",
        None,
        Some(&bob),
        &[("x-frg-csrf", &csrf)],
        &json!({ "id": stub2_id }),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    assert!(h.audit.has("identity.unlink"));
    // The last one stays.
    let r = h
        .post_json(
            "/auth/identities/unlink",
            Some(&H::session(&bob)),
            None,
            &[],
            &json!({ "id": stub_id }),
        )
        .await;
    r.expect(StatusCode::CONFLICT);
    assert_eq!(r.error(), "last_identity");
    // stub2 no longer logs bob in.
    let mut jar = Jar::default();
    let cb = h.browser_login(&mut jar, "stub2", "z").await;
    assert_eq!(cb.location(), "/auth/signup");
}

#[tokio::test]
async fn logout_all_can_unlink_late_identities() {
    let h = harness().await;
    let mut bob = h.signup("b", "2", "bob@x.example", "bob").await;
    h.idp2.add("z", "900", "z@x.example", None);
    h.clock.advance(100);
    h.link(&mut bob, "stub", "b", "stub2", "z")
        .await
        .expect(StatusCode::FOUND);
    let token = H::session(&bob);
    h.post_json(
        "/auth/logout",
        Some(&token),
        None,
        &[],
        &json!({"all": true, "identities_linked_after": NOW + 50}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    h.whoami(&token).await.expect(StatusCode::UNAUTHORIZED);
    let bob_id = h.user_id("bob").await;
    let left = h.ctx.store().identities_for_user(bob_id).await.unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].provider, "stub");
    // Even a cut-off before everything keeps the oldest.
    let mut jar = Jar::default();
    h.browser_login(&mut jar, "stub", "b").await;
    h.post_json(
        "/auth/logout",
        Some(&H::session(&jar)),
        None,
        &[],
        &json!({"all": true, "identities_linked_after": 0}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    assert_eq!(
        h.ctx
            .store()
            .identities_for_user(bob_id)
            .await
            .unwrap()
            .len(),
        1
    );
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
    let v = forged.get("__Host-frg_oauth");
    forged.0.insert("__Host-frg_oauth".into(), {
        // Always a different last character (a fixed `0` would be a
        // no-op whenever the cookie already ends in `0`).
        let last = if v.ends_with('0') { '1' } else { '0' };
        format!("{}{last}", &v[..v.len() - 1])
    });
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
    // A short prefix only: never the full hash.
    assert_eq!(list["keys"][0]["hash_prefix"], hash[..16]);
    assert!(!list.to_string().contains(&hash));
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
    // ... decided from the prefix alone: a forged (unknown) workload token
    // gets the same 403, so the status is no liveness oracle.
    let forged = h
        .ctx
        .format()
        .mint(forgs::TokenKind::Workload)
        .to_secret_string();
    h.post_json(
        "/auth/keys",
        Some(&forged),
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
    let jwt = "good:1/2/octo/widgets";
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
                subject: forgs::subject::workload_subject_key("gha", "1", "2").unwrap(),
                selector: "*".into(),
                ops: "read".into(),
                expires: None,
                created_by: None,
            },
            NOW,
        )
        .await
        .unwrap();
    // The no-grant refusal above did not burn the jti: this first success
    // is the same JWT.
    let r = token(json!({"grant_type": "github_oidc", "oidc_token": jwt})).await;
    r.expect(StatusCode::OK);
    assert_eq!(r.json()["expires"], NOW + 3600);
    // Single use: a replay of the same JWT is refused, flat, and audited.
    assert!(!h.audit.has("workload.reject.replay"));
    let replay = token(json!({"grant_type": "github_oidc", "oidc_token": jwt})).await;
    replay.expect(StatusCode::UNAUTHORIZED);
    assert_eq!(replay.error(), "invalid_grant");
    assert!(h.audit.has("workload.reject.replay"));
    let me = h.whoami(r.json()["token"].as_str().unwrap()).await.json();
    assert_eq!(
        me["subject"],
        SubjectKey::parse("gha/workload:id:1/2")
            .unwrap()
            .to_string()
    );
    let mint = h
        .audit
        .0
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|e| e.action == "workload.token.mint")
        .cloned()
        .unwrap();
    let detail = mint.detail.unwrap();
    assert!(detail.contains("repository_id=2"), "{detail}");
    assert!(detail.contains("owner_id=1"), "{detail}");
    assert!(
        detail.contains("ref=refs/heads/main event=push"),
        "{detail}"
    );

    // The same ids from another issuer are another subject: the grant to
    // `gha/…` does not reach it.
    let ghes = "ghes:1/2/octo/widgets";
    token(json!({"grant_type": "github_oidc", "oidc_token": ghes}))
        .await
        .expect(StatusCode::UNAUTHORIZED);
    // A repo recreated under the same name (new ids) is not the granted one.
    token(json!({"grant_type": "github_oidc", "oidc_token": "good:1/3/octo/widgets"}))
        .await
        .expect(StatusCode::UNAUTHORIZED);
    // A legacy name-keyed grant authorizes nothing.
    h.ctx
        .store()
        .scoped(ns)
        .insert_grant(
            &NewGrant {
                subject: SubjectKey::parse("gha/workload:octo/widgets").unwrap(),
                selector: "*".into(),
                ops: "read".into(),
                expires: None,
                created_by: None,
            },
            NOW,
        )
        .await
        .unwrap();
    token(json!({"grant_type": "github_oidc", "oidc_token": "good:1/3/octo/widgets"}))
        .await
        .expect(StatusCode::UNAUTHORIZED);
    h.ctx
        .store()
        .scoped(ns)
        .insert_grant(
            &NewGrant {
                subject: forgs::subject::workload_subject_key("ghes-corp", "1", "2").unwrap(),
                selector: "*".into(),
                ops: "read".into(),
                expires: None,
                created_by: None,
            },
            NOW,
        )
        .await
        .unwrap();
    // Same jti as the replayed `gha` JWT, but another issuer: independent.
    let r = token(json!({"grant_type": "github_oidc", "oidc_token": ghes})).await;
    r.expect(StatusCode::OK);
    let me = h.whoami(r.json()["token"].as_str().unwrap()).await.json();
    assert_eq!(me["subject"], "ghes-corp/workload:id:1/2");

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
    // A co-admin cannot evict or demote a personal namespace's owner.
    m(
        &alice,
        json!({"action": "set", "namespace": "alice", "username": "bob", "role": "admin"}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    let r = m(
        &bob,
        json!({"action": "remove", "namespace": "alice", "username": "alice"}),
    )
    .await;
    r.expect(StatusCode::CONFLICT);
    assert_eq!(r.error(), "conflict");
    m(
        &bob,
        json!({"action": "set", "namespace": "alice", "username": "alice", "role": "member"}),
    )
    .await
    .expect(StatusCode::CONFLICT);
    // The owner can remove the co-admin; then bob is out.
    m(
        &alice,
        json!({"action": "remove", "namespace": "alice", "username": "bob"}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    m(&bob, json!({"action": "list", "namespace": "alice"}))
        .await
        .expect(StatusCode::FORBIDDEN);
    // In a shared namespace, a disabled co-admin does not count.
    let alice_id = h
        .ctx
        .store()
        .user_by_username("alice")
        .await
        .unwrap()
        .unwrap()
        .id;
    let bob_id = h
        .ctx
        .store()
        .user_by_username("bob")
        .await
        .unwrap()
        .unwrap()
        .id;
    forgs_http::members::create_namespace(&h.ctx, alice_id, None, "org", "team", None)
        .await
        .unwrap();
    m(
        &alice,
        json!({"action": "set", "namespace": "team", "username": "bob", "role": "admin"}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    h.ctx
        .store()
        .set_user_state(bob_id, forgs_store::UserState::Disabled)
        .await
        .unwrap();
    let r = m(
        &alice,
        json!({"action": "remove", "namespace": "team", "username": "alice"}),
    )
    .await;
    r.expect(StatusCode::CONFLICT);
    assert_eq!(r.error(), "last_admin");
    h.ctx
        .store()
        .set_user_state(bob_id, forgs_store::UserState::Active)
        .await
        .unwrap();
    m(
        &alice,
        json!({"action": "remove", "namespace": "team", "username": "alice"}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    // A personal namespace is renamed with its user, not directly.
    h.post_json(
        "/auth/rename",
        Some(&alice),
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
    assert!(!j.0.contains_key("__Host-frg_session"));
}

/// Audit HTTP-03 / HTTP-10: a key and the workload tokens it minted are only
/// as alive as the key itself and its creator's active membership.
#[tokio::test]
async fn keys_and_their_tokens_die_with_creator_standing_and_revocation() {
    let h = harness().await;
    let alice = H::session(&h.signup("a", "1", "a@x.example", "alice").await);
    let bob = H::session(&h.signup("b", "2", "b@x.example", "bob").await);
    let member = |action: &str| {
        let h = &h;
        let alice = alice.clone();
        let body =
            json!({"action": action, "namespace": "alice", "username": "bob", "role": "member"});
        async move {
            h.post_json("/auth/members", Some(&alice), None, &[], &body)
                .await
                .expect(StatusCode::NO_CONTENT);
        }
    };
    let mint = || {
        let h = &h;
        let bob = bob.clone();
        async move {
            h.post_json(
                "/auth/keys",
                Some(&bob),
                None,
                &[],
                &json!({"action": "create", "namespace": "alice", "ttl_secs": 3600,
                        "purpose": "ci", "multi_use": true}),
            )
            .await
            .json()
        }
    };
    let redeem = |key: String| {
        let h = &h;
        async move {
            h.post_json(
                "/auth/token",
                None,
                None,
                &[],
                &json!({"grant_type": "api_key", "api_key": key}),
            )
            .await
        }
    };
    let bob_id = h
        .ctx
        .store()
        .user_by_username("bob")
        .await
        .unwrap()
        .unwrap()
        .id;

    member("set").await;
    let created = mint().await;
    assert_eq!(created["single_use"], false);
    let key = created["key"].as_str().unwrap().to_owned();
    let r = redeem(key.clone()).await;
    r.expect(StatusCode::OK);
    let wt = r.json()["token"].as_str().unwrap().to_owned();
    h.whoami(&wt).await.expect(StatusCode::OK);

    // Removed: the token dies, the key stops redeeming (audited).
    h.post_json(
        "/auth/members",
        Some(&alice),
        None,
        &[],
        &json!({"action": "remove", "namespace": "alice", "username": "bob"}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    h.whoami(&wt).await.expect(StatusCode::UNAUTHORIZED);
    let r = redeem(key.clone()).await;
    r.expect(StatusCode::UNAUTHORIZED);
    assert_eq!(r.error(), "invalid_grant");
    assert!(h.audit.has("api_key.redeem.creator_inactive"));

    // Re-added: redeemable again.
    member("set").await;
    let r = redeem(key.clone()).await;
    r.expect(StatusCode::OK);
    let wt = r.json()["token"].as_str().unwrap().to_owned();
    h.whoami(&wt).await.expect(StatusCode::OK);

    // Disabled: same.
    h.ctx
        .store()
        .set_user_state(bob_id, forgs_store::UserState::Disabled)
        .await
        .unwrap();
    h.whoami(&wt).await.expect(StatusCode::UNAUTHORIZED);
    redeem(key.clone()).await.expect(StatusCode::UNAUTHORIZED);
    h.ctx
        .store()
        .set_user_state(bob_id, forgs_store::UserState::Active)
        .await
        .unwrap();

    // Revoked: the token minted from it dies with it.
    let r = redeem(key.clone()).await;
    r.expect(StatusCode::OK);
    let wt = r.json()["token"].as_str().unwrap().to_owned();
    h.post_json(
        "/auth/keys",
        Some(&alice),
        None,
        &[],
        &json!({"action": "revoke", "namespace": "alice",
                "prefix": created["key_hash"].as_str().unwrap()}),
    )
    .await
    .expect(StatusCode::OK);
    h.whoami(&wt).await.expect(StatusCode::UNAUTHORIZED);
    redeem(key).await.expect(StatusCode::UNAUTHORIZED);
}

/// Audit TC-4: an app approval is not redeemed once its approver is disabled.
#[tokio::test]
async fn app_approvals_of_a_disabled_approver_are_not_redeemed() {
    let h = harness().await;
    h.signup("a", "1", "a@x.example", "alice").await;
    let alice = h
        .ctx
        .store()
        .user_by_username("alice")
        .await
        .unwrap()
        .unwrap()
        .id;
    let started = forgs_http::device::start_pending_approval(&h.ctx, r#"{"node":"n1"}"#, None)
        .await
        .unwrap();
    forgs_http::device::decide(&h.ctx, alice, &started.user_code, None, true)
        .await
        .unwrap();
    h.ctx
        .store()
        .set_user_state(alice, forgs_store::UserState::Disabled)
        .await
        .unwrap();
    let r = forgs_http::device::poll(&h.ctx, &started.device_secret).await;
    assert!(matches!(r, Err(ApiError::InvalidGrant)), "{r:?}");
    assert_eq!(h.approvals.0.load(Ordering::SeqCst), 0);

    // An active approver's approval is redeemed.
    h.ctx
        .store()
        .set_user_state(alice, forgs_store::UserState::Active)
        .await
        .unwrap();
    let started = forgs_http::device::start_pending_approval(&h.ctx, r#"{"node":"n2"}"#, None)
        .await
        .unwrap();
    forgs_http::device::decide(&h.ctx, alice, &started.user_code, None, true)
        .await
        .unwrap();
    assert!(matches!(
        forgs_http::device::poll(&h.ctx, &started.device_secret).await,
        Ok(forgs_http::device::PollOutcome::App(_))
    ));
    assert_eq!(h.approvals.0.load(Ordering::SeqCst), 1);
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
    let issuer = |name: &'static str, ns: &'static str| -> Arc<dyn WorkloadIssuer> {
        Arc::new(StubIssuer {
            name,
            ns,
            prefix: "good",
        })
    };
    for (a, b2) in [
        // Duplicate name.
        (("gh", "gha"), ("gh", "ghes")),
        // Duplicate subject label.
        (("gh", "gha"), ("ghes", "gha")),
        // Invalid label / name.
        (("gh", "gha"), ("ghes", "GHES")),
        (("gh", "gha"), ("ghes", "a/b")),
        (("gh", "gha"), ("Bad Name", "ghes")),
    ] {
        let err = b(PUBLIC, &[1; 32])
            .workload_issuer(issuer(a.0, a.1))
            .workload_issuer(issuer(b2.0, b2.1))
            .build()
            .err();
        assert!(
            matches!(
                err,
                Some(ConfigError::WorkloadIssuerName(_) | ConfigError::WorkloadSubjectNs(_))
            ),
            "{a:?} {b2:?}: {err:?}"
        );
    }
    assert!(b(PUBLIC, &[1; 32])
        .workload_issuer(issuer("gh", "gha"))
        .workload_issuer(issuer("ghes", "ghes-corp"))
        .build()
        .is_ok());
    // `cookie_api_prefix` must end with `/`: `/api` would also match
    // `/apix` and `/api-admin`.
    for bad in ["/api", "api/", "/a pi/"] {
        assert!(
            matches!(
                b(PUBLIC, &[1; 32])
                    .cookie_api_prefix(Some(bad))
                    .build()
                    .err(),
                Some(ConfigError::Path(_))
            ),
            "{bad}"
        );
    }
    assert!(b(PUBLIC, &[1; 32])
        .cookie_api_prefix(Some("/app/api/"))
        .build()
        .is_ok());
    assert!(b(PUBLIC, &[1; 32]).cookie_api_prefix(None).build().is_ok());
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
        .find(|k| k["hash_prefix"] == hash[..16])
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
        .find(|k| k["hash_prefix"] == "ab".repeat(8))
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
    // AN-5: a root name that parses as an id is refused, so a
    // single-segment `namespace` reference is never both an id and a name.
    let id_shaped = team.to_string().to_ascii_lowercase();
    let e = create_namespace(&h.ctx, bob, None, "org", &id_shaped, None)
        .await
        .unwrap_err();
    assert_eq!(e, ApiError::USERNAME_INVALID);
    // An id-shaped reference resolves as an id only: the node's id (any
    // case) finds it, an unknown id is the flat 403, never a path lookup.
    assert_eq!(
        forgs_http::auth::resolve_ns(&h.ctx, &id_shaped)
            .await
            .unwrap(),
        team
    );
    assert_eq!(
        forgs_http::auth::resolve_ns(&h.ctx, &forgs::NsNodeId::from_parts(1, 1).to_string())
            .await
            .unwrap_err(),
        ApiError::Forbidden
    );
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

// ---------------------------------------------------------------------------
// Unauthenticated audit noise is not persisted (audit HTTP-05)

#[tokio::test]
async fn store_audit_sink_drops_unauthenticated_noise() {
    let store = Store::connect_in_memory(schema(), RoleLadder::default())
        .await
        .unwrap();
    // Default sink: StoreAuditSink over the store.
    let ctx = AuthContext::builder(store.clone(), PUBLIC, &[42; 32])
        .clock(Arc::new(FixedClock::new(NOW)))
        .build()
        .unwrap();
    let app = forgs_http::router::<AuthContext>()
        .route("/api/any", get(app_any))
        .with_state(ctx.clone());
    let count = || async {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM forgs_audit")
            .fetch_one(store.pool())
            .await
            .unwrap();
        n
    };
    let send = |auth: Option<String>| {
        let app = app.clone();
        async move {
            let mut b = Request::builder().uri("/api/any");
            if let Some(a) = auth {
                b = b.header(header::AUTHORIZATION, a);
            }
            app.oneshot(b.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status()
        }
    };
    for auth in [
        None,
        Some("Bearer garbage".to_owned()),
        Some("Bearer ".to_owned()),
    ] {
        assert_eq!(send(auth).await, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(count().await, 0, "missing/malformed must not write rows");

    // A well-formed but unknown credential is still recorded.
    let unknown = ctx.format().mint(TokenKind::Session).to_secret_string();
    assert_eq!(
        send(Some(format!("Bearer {unknown}"))).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(count().await, 1);
}

#[tokio::test]
async fn store_audit_sink_can_opt_into_noise() {
    let store = Store::connect_in_memory(schema(), RoleLadder::default())
        .await
        .unwrap();
    let noise = AuditEvent::new(NOW, "auth.reject.missing");
    assert!(noise.is_unauthenticated_noise());
    assert!(!AuditEvent::new(NOW, "auth.reject.unknown").is_unauthenticated_noise());
    assert!(!noise
        .clone()
        .subject(&SubjectKey::user(forgs::UserId::generate(NOW * 1000)))
        .is_unauthenticated_noise());

    forgs_http::StoreAuditSink::new(store.clone())
        .record(noise.clone())
        .await;
    forgs_http::StoreAuditSink::new(store.clone())
        .persist_unauthenticated_noise(true)
        .record(noise)
        .await;
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM forgs_audit")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(n, 1);
}

// ---------------------------------------------------------------------------
// Device flow abuse controls
// ---------------------------------------------------------------------------

async fn device_start_from(h: &H, ip: Option<&str>) -> Resp {
    let extra: Vec<(&str, &str)> = ip.map(|i| ("x-forwarded-for", i)).into_iter().collect();
    h.post_json("/auth/device/start", None, None, &extra, &json!({}))
        .await
}

async fn device_poll_status(h: &H, secret: &str) -> Value {
    h.post_json(
        "/auth/device/poll",
        None,
        None,
        &[],
        &json!({"device_secret": secret}),
    )
    .await
    .json()["status"]
        .clone()
}

#[tokio::test]
async fn device_caps_are_per_kind() {
    let h = harness_cfg(true, &format!("{PUBLIC}/"), |b| {
        b.max_pending_devices(2).max_pending_approvals(1)
    })
    .await;
    for _ in 0..2 {
        device_start_from(&h, None).await.expect(StatusCode::OK);
    }
    device_start_from(&h, None)
        .await
        .expect(StatusCode::SERVICE_UNAVAILABLE);
    // A login flood does not block app approvals, and vice versa.
    forgs_http::device::start_pending_approval(&h.ctx, "{}", None)
        .await
        .unwrap();
    assert_eq!(
        forgs_http::device::start_pending_approval(&h.ctx, "{}", None).await,
        Err(forgs_http::ApiError::UNAVAILABLE)
    );
    // Rows age out.
    h.clock.advance(h.ctx.ttl().device_flow);
    device_start_from(&h, None).await.expect(StatusCode::OK);
}

#[tokio::test]
async fn device_starts_are_capped_per_source() {
    let h = harness_cfg(true, &format!("{PUBLIC}/"), |b| {
        b.client_ip(forgs_http::ForwardedFor {
            header: axum::http::HeaderName::from_static("x-forwarded-for"),
            trusted_hops: 0,
        })
        .max_pending_devices_per_source(2)
    })
    .await;
    let browser = h.signup("a", "1", "a@x.example", "alice").await;
    let mut first = None;
    for _ in 0..2 {
        let r = device_start_from(&h, Some("spoofed, 203.0.113.7")).await;
        r.expect(StatusCode::OK);
        first.get_or_insert(r.json());
    }
    device_start_from(&h, Some("203.0.113.7"))
        .await
        .expect(StatusCode::SERVICE_UNAVAILABLE);
    // Another source has its own allowance; an IPv6 /64 is one source.
    device_start_from(&h, Some("198.51.100.1"))
        .await
        .expect(StatusCode::OK);
    device_start_from(&h, Some("2001:db8:1:2::1"))
        .await
        .expect(StatusCode::OK);
    device_start_from(&h, Some("2001:db8:1:2::ffff"))
        .await
        .expect(StatusCode::OK);
    device_start_from(&h, Some("2001:db8:1:2:dead::"))
        .await
        .expect(StatusCode::SERVICE_UNAVAILABLE);
    // An unknown source only meets the global ceiling.
    device_start_from(&h, None).await.expect(StatusCode::OK);

    // The review page shows where the device asked from.
    let code = first.unwrap()["user_code"].as_str().unwrap().to_owned();
    let review = h
        .post_form(
            "/auth/device",
            &browser,
            &[
                ("code", &code),
                ("action", "review"),
                ("csrf", &browser.get("__Host-frg_csrf")),
            ],
        )
        .await;
    review.expect(StatusCode::OK);
    assert!(review.text().contains("203.0.113.7"), "{}", review.text());
    assert!(!review.text().contains("spoofed"));
}

#[tokio::test]
async fn device_slow_down_skips_the_store_and_is_capped() {
    let h = harness().await;
    let start = device_start_from(&h, None).await.json();
    let secret = start["device_secret"].as_str().unwrap().to_owned();
    assert_eq!(device_poll_status(&h, &secret).await, "pending");
    // Each too-fast poll adds 5s, up to 60s.
    for _ in 0..20 {
        assert_eq!(device_poll_status(&h, &secret).await, "slow_down");
    }
    h.clock.advance(59);
    assert_eq!(device_poll_status(&h, &secret).await, "slow_down");
    h.clock.advance(60);
    assert_eq!(device_poll_status(&h, &secret).await, "pending");
    // Unknown secrets get no pacing state: they are simply expired.
    let other = h
        .ctx
        .format()
        .mint(TokenKind::DeviceSecret)
        .to_secret_string();
    assert_eq!(device_poll_status(&h, &other).await, "expired");
    assert_eq!(device_poll_status(&h, &other).await, "expired");
}

#[tokio::test]
async fn device_code_guessing_is_uniform_audited_and_locked_out() {
    let h = harness().await;
    let browser = h.signup("a", "1", "a@x.example", "alice").await;
    let csrf = browser.get("__Host-frg_csrf");
    let submit = |code: String, action: &'static str| {
        let (h, browser, csrf) = (&h, &browser, &csrf);
        async move {
            h.post_form(
                "/auth/device",
                browser,
                &[("code", &code), ("action", action), ("csrf", csrf)],
            )
            .await
        }
    };
    let real = device_start_from(&h, None).await.json()["user_code"]
        .as_str()
        .unwrap()
        .to_owned();
    // A decided code is the same 404 as an unknown one.
    let decided = device_start_from(&h, None).await.json()["user_code"]
        .as_str()
        .unwrap()
        .to_owned();
    submit(decided.clone(), "deny").await.expect(StatusCode::OK);
    let a = submit(decided, "approve").await;
    a.expect(StatusCode::NOT_FOUND);
    let b = submit("ZZZZ-ZZZZ".into(), "approve").await;
    b.expect(StatusCode::NOT_FOUND);
    assert_eq!(a.text(), b.text());
    assert!(h.audit.has("device.decide.unknown"));
    // Malformed codes do not count.
    for _ in 0..20 {
        submit("!".into(), "approve")
            .await
            .expect(StatusCode::BAD_REQUEST);
    }
    // 10 misses in all (2 so far), then even a valid code is refused.
    for i in 0..8 {
        submit(format!("ZZZZ-ZZZ{i}"), "review")
            .await
            .expect(StatusCode::NOT_FOUND);
    }
    let locked = submit(real.clone(), "approve").await;
    locked.expect(StatusCode::TOO_MANY_REQUESTS);
    assert!(locked.text().contains("Too many wrong codes"));
    submit(real.clone(), "review")
        .await
        .expect(StatusCode::TOO_MANY_REQUESTS);
    assert!(h.audit.has("device.decide.locked"));
    // Another user is unaffected.
    let bob = h.signup("b", "2", "b@x.example", "bob").await;
    h.post_form(
        "/auth/device",
        &bob,
        &[
            ("code", &real),
            ("action", "review"),
            ("csrf", &bob.get("__Host-frg_csrf")),
        ],
    )
    .await
    .expect(StatusCode::OK);
    // The window passes.
    h.clock.advance(h.ctx.ttl().device_flow);
    let fresh = device_start_from(&h, None).await.json()["user_code"]
        .as_str()
        .unwrap()
        .to_owned();
    submit(fresh, "approve").await.expect(StatusCode::OK);
}

#[tokio::test]
async fn device_approval_can_be_cancelled_by_its_approver() {
    let h = harness().await;
    let alice = h.signup("a", "1", "a@x.example", "alice").await;
    let bob = h.signup("b", "2", "b@x.example", "bob").await;
    let form = |jar: &Jar, code: &str, action: &str| {
        vec![
            ("code".to_owned(), code.to_owned()),
            ("action".to_owned(), action.to_owned()),
            ("csrf".to_owned(), jar.get("__Host-frg_csrf")),
        ]
    };
    let post = |jar: &Jar, f: Vec<(String, String)>| {
        let (h, jar) = (&h, jar.clone());
        async move {
            let f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            h.post_form("/auth/device", &jar, &f).await
        }
    };
    let start = device_start_from(&h, None).await.json();
    let secret = start["device_secret"].as_str().unwrap().to_owned();
    let code = start["user_code"].as_str().unwrap().to_owned();
    let ok = post(&alice, form(&alice, &code, "approve")).await;
    ok.expect(StatusCode::OK);
    assert!(ok.text().contains("Cancel this approval"));
    // Someone else cannot retract it.
    post(&bob, form(&bob, &code, "deny"))
        .await
        .expect(StatusCode::NOT_FOUND);
    post(&alice, form(&alice, &code, "deny"))
        .await
        .expect(StatusCode::OK);
    assert!(h
        .audit
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|e| e.action == "device.deny" && e.detail.as_deref() == Some("cancelled approval")));
    assert_eq!(device_poll_status(&h, &secret).await, "denied");

    // Once redeemed it can no longer be cancelled.
    let start = device_start_from(&h, None).await.json();
    let secret = start["device_secret"].as_str().unwrap().to_owned();
    let code = start["user_code"].as_str().unwrap().to_owned();
    post(&alice, form(&alice, &code, "approve"))
        .await
        .expect(StatusCode::OK);
    assert_eq!(device_poll_status(&h, &secret).await, "granted");
    post(&alice, form(&alice, &code, "deny"))
        .await
        .expect(StatusCode::NOT_FOUND);
}

impl Collect {
    fn count(&self, action: &str, detail_has: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| {
                e.action == action && e.detail.as_deref().unwrap_or("").contains(detail_has)
            })
            .count()
    }
}

#[tokio::test]
async fn api_keys_are_capped_paginated_redacted_and_refusals_audited() {
    let h = harness_cfg(true, &format!("{PUBLIC}/"), |b| {
        b.max_api_keys_per_namespace(5).max_api_keys_per_user(3)
    })
    .await;
    let alice = H::session(&h.signup("a", "1", "a@x.example", "alice").await);
    let bob = H::session(&h.signup("b", "2", "b@x.example", "bob").await);
    h.signup("c", "3", "c@x.example", "carol").await;
    let post = |path: &'static str, t: &str, body: Value| {
        let h = &h;
        let t = t.to_owned();
        async move { h.post_json(path, Some(&t), None, &[], &body).await }
    };
    // Alice's keys carry a payload; bob (a plain member) mints plain CI keys.
    let mint = |t: &str| {
        let body = if t == alice {
            json!({"action": "create", "namespace": "alice", "ttl_secs": 60, "purpose": "node",
                   "payload": {"tags": ["x"]}})
        } else {
            json!({"action": "create", "namespace": "alice", "ttl_secs": 60, "purpose": "ci"})
        };
        post("/auth/keys", t, body)
    };

    // Refused mints are audited.
    post(
        "/auth/keys",
        &alice,
        json!({"action": "create", "namespace": "alice", "ttl_secs": 0, "purpose": "ci"}),
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
    assert_eq!(h.audit.count("api_key.denied", "bad ttl"), 1);
    post(
        "/auth/keys",
        &alice,
        json!({"action": "create", "namespace": "alice", "ttl_secs": 60, "purpose": "nope"}),
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
    assert_eq!(h.audit.count("api_key.denied", "unknown purpose"), 1);

    // Per-user cap: alice may hold 3 live keys.
    for _ in 0..3 {
        mint(&alice).await.expect(StatusCode::OK);
    }
    let r = mint(&alice).await;
    r.expect(StatusCode::FORBIDDEN);
    assert_eq!(r.error(), "key_limit");
    assert_eq!(h.audit.count("api_key.denied", "live key limit"), 1);

    // Per-namespace cap: bob joins and fills the namespace to 5.
    post(
        "/auth/members",
        &alice,
        json!({"action": "set", "namespace": "alice", "username": "bob", "role": "member"}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    mint(&bob).await.expect(StatusCode::OK);
    let bobs = mint(&bob).await;
    bobs.expect(StatusCode::OK);
    let bobs_hash = bobs.json()["key_hash"].as_str().unwrap().to_owned();
    let r = mint(&bob).await;
    r.expect(StatusCode::FORBIDDEN);
    assert_eq!(r.error(), "key_limit");

    // A plain member sees prefixes only, and detail only for their own keys.
    let list = post(
        "/auth/keys",
        &bob,
        json!({"action": "list", "namespace": "alice"}),
    )
    .await
    .json();
    let rows = list["keys"].as_array().unwrap();
    assert_eq!(rows.len(), 5);
    assert!(list.get("next").is_none());
    for k in rows {
        assert_eq!(k["hash_prefix"].as_str().unwrap().len(), 16);
        assert!(k.get("key_hash").is_none());
        // Alice's keys: neither payload nor creator shown to bob.
        if k["purpose"] == "node" {
            assert!(
                k.get("payload").is_none() && k.get("created_by").is_none(),
                "{k}"
            );
        } else {
            assert!(k.get("created_by").is_some(), "{k}");
        }
    }
    assert!(rows
        .iter()
        .any(|k| bobs_hash.starts_with(k["hash_prefix"].as_str().unwrap())));
    assert_eq!(
        rows.iter()
            .filter(|k| k.get("created_by").is_some())
            .count(),
        2
    );
    // The admin sees every key's detail.
    let list = post(
        "/auth/keys",
        &alice,
        json!({"action": "list", "namespace": "alice"}),
    )
    .await
    .json();
    assert!(list["keys"]
        .as_array()
        .unwrap()
        .iter()
        .all(|k| k.get("created_by").is_some()
            && (k["purpose"] != "node" || k.get("payload").is_some())));

    // Pagination: pages of 2 cover all 5, newest first, without repeats.
    let mut seen = Vec::new();
    let mut before: Option<String> = None;
    loop {
        let mut body = json!({"action": "list", "namespace": "alice", "limit": 2});
        if let Some(b) = &before {
            body["before"] = json!(b);
        }
        let page = post("/auth/keys", &alice, body).await.json();
        for k in page["keys"].as_array().unwrap() {
            seen.push(k["id"].as_str().unwrap().to_owned());
        }
        match page.get("next") {
            Some(n) => before = Some(n.as_str().unwrap().to_owned()),
            None => break,
        }
    }
    assert_eq!(seen.len(), 5);
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.reverse();
    sorted.dedup();
    assert_eq!(seen, sorted);
    post(
        "/auth/keys",
        &alice,
        json!({"action": "list", "namespace": "alice", "limit": 0}),
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
    post(
        "/auth/keys",
        &alice,
        json!({"action": "list", "namespace": "alice", "before": "not-an-id"}),
    )
    .await
    .expect(StatusCode::BAD_REQUEST);

    // Expired keys stop counting: alice can mint again after they lapse.
    h.clock.advance(61);
    mint(&alice).await.expect(StatusCode::OK);

    // Members pagination.
    post(
        "/auth/members",
        &alice,
        json!({"action": "set", "namespace": "alice", "username": "carol", "role": "member"}),
    )
    .await
    .expect(StatusCode::NO_CONTENT);
    let p1 = post(
        "/auth/members",
        &bob,
        json!({"action": "list", "namespace": "alice", "limit": 2}),
    )
    .await
    .json();
    assert_eq!(p1["members"].as_array().unwrap().len(), 2);
    let after = p1["next"].as_str().unwrap().to_owned();
    let p2 = post(
        "/auth/members",
        &bob,
        json!({"action": "list", "namespace": "alice", "limit": 2, "after": after}),
    )
    .await
    .json();
    assert_eq!(p2["members"].as_array().unwrap().len(), 1);
    assert!(p2.get("next").is_none());

    // A non-member's (or unknown namespace's) member writes are audited.
    let dave = H::session(&h.signup("d", "4", "d@x.example", "dave").await);
    for (action, body) in [
        (
            "member.set.denied",
            json!({"action": "set", "namespace": "alice", "username": "dave", "role": "admin"}),
        ),
        (
            "member.remove.denied",
            json!({"action": "remove", "namespace": "alice", "username": "bob"}),
        ),
        (
            "member.set.denied",
            json!({"action": "set", "namespace": "nope", "username": "dave", "role": "admin"}),
        ),
    ] {
        let before = h.audit.count(action, "not a member");
        post("/auth/members", &dave, body)
            .await
            .expect(StatusCode::FORBIDDEN);
        assert_eq!(
            h.audit.count(action, "not a member"),
            before + 1,
            "{action}"
        );
    }
    let before = h.audit.count("namespace.rename.denied", "not a member");
    post(
        "/auth/rename",
        &dave,
        json!({"action": "namespace", "namespace": "alice", "new_name": "x"}),
    )
    .await
    .expect(StatusCode::FORBIDDEN);
    assert_eq!(
        h.audit.count("namespace.rename.denied", "not a member"),
        before + 1
    );
}
