//! [`AuthContext`]: everything the auth surface needs, injected once.
//!
//! Nothing here reads ambient state. The clock, the TTLs, the public URL, the
//! cookie names and the CSRF secret are all supplied by the app, which is
//! what makes every flow a deterministic integration test.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use forgs::store::{
    ApiKeyRecord, AppRecord, DeviceSecretRecord, RefreshRecord, SessionRecord, WorkloadRecord,
};
use forgs::{AppKind, TokenFormat, TokenHash, TokenStore};
use forgs_idp::{IdentityProvider, WorkloadIssuer};
use forgs_store::Store;
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

use crate::audit::{AuditSink, StoreAuditSink};
use crate::hooks::{
    ApiKeyPurposes, AppTokenLookup, NoPendingApprovals, PendingApprovalHook, StaticPurposes,
};

/// A source of "now", in epoch seconds.
pub trait Clock: Send + Sync {
    /// The current time, epoch seconds.
    fn now(&self) -> u64;
}

/// The wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// A settable clock, for tests (the app's as well as ours).
#[derive(Debug, Default)]
pub struct FixedClock(AtomicU64);

impl FixedClock {
    /// A clock stopped at `now`.
    #[must_use]
    pub fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }

    /// Set the time.
    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }

    /// Move the time forward by `secs`.
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Credential and flow lifetimes, in seconds (docs/design.md §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ttls {
    /// A user session (bearer or cookie). 12h.
    pub session: u64,
    /// A CLI refresh token. 30d, non-rotating.
    pub refresh: u64,
    /// Absolute lifetime of a session refresh chain (`grant_type: refresh`),
    /// counted from the original authentication. No refreshed session
    /// outlives it. 30d.
    pub session_max_life: u64,
    /// A workload token's default lifetime. 1h.
    pub workload: u64,
    /// The ceiling on any workload token. 12h.
    pub workload_cap: u64,
    /// A first login awaiting its username choice. 15m.
    pub pending_signup: u64,
    /// A device-flow approval. 10m.
    pub device_flow: u64,
    /// Minimum seconds between device polls. 5s.
    pub device_interval: u64,
    /// An in-flight authorization-code login (the `oauth` cookie). 10m.
    pub login_flow: u64,
    /// The longest API key the API will mint. 30d; zero is refused.
    pub api_key_max: u64,
}

impl Default for Ttls {
    fn default() -> Self {
        Self {
            session: 12 * 3600,
            refresh: 30 * 24 * 3600,
            session_max_life: 30 * 24 * 3600,
            workload: 3600,
            workload_cap: 12 * 3600,
            pending_signup: 15 * 60,
            device_flow: 10 * 60,
            device_interval: 5,
            login_flow: 10 * 60,
            api_key_max: 30 * 24 * 3600,
        }
    }
}

/// The cookie names, all derived from one brand so two forgs apps on one
/// host (or one app with two brands) never read each other's cookies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieNames {
    /// The session token. `HttpOnly`.
    pub session: String,
    /// The double-submit CSRF token. Deliberately **not** `HttpOnly`.
    pub csrf: String,
    /// The in-flight authorization-code login. `HttpOnly`, sealed.
    pub oauth: String,
    /// The pending-signup ticket. `HttpOnly`, sealed.
    pub signup: String,
}

impl CookieNames {
    /// `{brand}_session`, `{brand}_csrf`, `{brand}_oauth`, `{brand}_signup`.
    #[must_use]
    pub fn for_brand(brand: &str) -> Self {
        Self {
            session: format!("{brand}_session"),
            csrf: format!("{brand}_csrf"),
            oauth: format!("{brand}_oauth"),
            signup: format!("{brand}_signup"),
        }
    }
}

/// The keys the browser surface MACs with.
///
/// Derived from a secret **the app injects for this purpose** — not from any
/// signing key the app has for something else. forgs cannot see an app's
/// keys and should not, and reusing a signing key across purposes couples
/// their compromise and rotation, so the app persists a dedicated secret (≥ 32 random bytes) and hands
/// it in. Rotating it logs every open tab out, which is correct.
///
/// Two keys come out of it, domain-separated by label and by the app label:
///
/// * `csrf = HMAC-SHA256(secret, "forgs/csrf/v1\0" ‖ app_label)` — the
///   double-submit token is `hex(HMAC(csrf, session_token_hash))`;
/// * `flow = HMAC-SHA256(secret, "forgs/flow/v1\0" ‖ app_label)` — seals the
///   `oauth` and `signup` cookies, so a cookie planted by a sibling origin
///   cannot inject a login state, a link intent or a ticket.
///
/// Versioned labels: a future derivation is a new label, never a silent
/// reinterpretation of the same bytes.
#[derive(Clone)]
pub struct CsrfKey {
    csrf: [u8; 32],
    flow: [u8; 32],
}

/// `HMAC-SHA256(key, parts…)`.
pub(crate) fn hmac256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts a key of any length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

impl CsrfKey {
    /// Derive the keys from an app-injected `secret`, separated by
    /// `app_label` (so two apps sharing a secret by accident still do not
    /// share tokens).
    #[must_use]
    pub fn derive(secret: &[u8], app_label: &str) -> Self {
        Self {
            csrf: hmac256(secret, &[b"forgs/csrf/v1\0", app_label.as_bytes()]),
            flow: hmac256(secret, &[b"forgs/flow/v1\0", app_label.as_bytes()]),
        }
    }

    pub(crate) fn csrf(&self) -> &[u8; 32] {
        &self.csrf
    }

    pub(crate) fn flow(&self) -> &[u8; 32] {
        &self.flow
    }
}

impl fmt::Debug for CsrfKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CsrfKey(<redacted>)")
    }
}

/// Why an [`AuthContext`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// `public_url` is not an absolute `http(s)` URL without query/fragment.
    #[error("public_url must be an absolute http(s) URL without query or fragment: {0}")]
    PublicUrl(String),
    /// The injected secret is too short.
    #[error("the CSRF/cookie secret must be at least 32 bytes")]
    ShortSecret,
    /// A provider name is unusable in a URL path, reserved, or duplicated.
    #[error("invalid or duplicate provider name {0:?}")]
    ProviderName(String),
    /// A workload issuer name is invalid (same rule as provider names) or
    /// duplicated.
    #[error("invalid or duplicate workload issuer name {0:?}")]
    WorkloadIssuerName(String),
    /// A workload issuer's subject label fails
    /// [`forgs::subject::valid_workload_ns`] or is shared with another issuer
    /// — two issuers on one label would map their repos onto the same
    /// subjects.
    #[error("invalid or duplicate workload subject label {0:?}")]
    WorkloadSubjectNs(String),
    /// The mount prefix must be empty or start with `/` and not end with one.
    #[error("invalid mount prefix {0:?}")]
    Mount(String),
    /// A path setting (`post_login_redirect`, `cookie_api_prefix`) must be an
    /// absolute same-origin path.
    #[error("invalid path setting {0:?}")]
    Path(String),
}

/// Path segments under `/auth/` that a provider name would shadow.
const RESERVED_PROVIDER_NAMES: &[&str] = &[
    "providers",
    "login",
    "signup",
    "token",
    "logout",
    "session",
    "device",
    "keys",
    "identities",
    "members",
    "rename",
];

pub(crate) struct Inner {
    pub(crate) store: Store,
    pub(crate) format: TokenFormat,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) ttl: Ttls,
    pub(crate) public_url: String,
    pub(crate) public_origin: String,
    pub(crate) mount: String,
    pub(crate) cookies: CookieNames,
    pub(crate) csrf_header: String,
    pub(crate) cookie_api_prefix: Option<String>,
    pub(crate) keys: CsrfKey,
    pub(crate) providers: Vec<Arc<dyn IdentityProvider>>,
    pub(crate) workload_issuers: Vec<Arc<dyn WorkloadIssuer>>,
    pub(crate) audit: Arc<dyn AuditSink>,
    pub(crate) purposes: Arc<dyn ApiKeyPurposes>,
    pub(crate) approvals: Arc<dyn PendingApprovalHook>,
    pub(crate) app_tokens: Option<Arc<dyn AppTokenLookup>>,
    pub(crate) post_login_redirect: String,
    pub(crate) max_pending_devices: u64,
    /// Last poll time per device-secret hash, for `slow_down`.
    pub(crate) poll_log: Mutex<HashMap<String, u64>>,
}

/// The auth surface's configuration and collaborators. Cheap to clone.
///
/// Apps put it in their router state and implement
/// `axum::extract::FromRef<AppState> for AuthContext`; [`crate::router`] and
/// the [`crate::Authenticated`] extractor take it from there.
#[derive(Clone)]
pub struct AuthContext {
    pub(crate) inner: Arc<Inner>,
}

impl fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthContext")
            .field("public_url", &self.inner.public_url)
            .field("mount", &self.inner.mount)
            .field("cookies", &self.inner.cookies)
            .finish_non_exhaustive()
    }
}

impl AuthContext {
    /// Start building a context over `store`.
    ///
    /// `public_url` is the app's browser-reachable base URL; every absolute
    /// URL forgs emits — above all the OAuth `redirect_uri` — is derived from
    /// it and **never** from `Host` / `X-Forwarded-Host`. `secret` is the
    /// dedicated cookie/CSRF secret (see [`CsrfKey`]).
    #[must_use]
    pub fn builder(store: Store, public_url: &str, secret: &[u8]) -> AuthContextBuilder {
        AuthContextBuilder {
            store,
            public_url: public_url.to_owned(),
            secret: secret.to_vec(),
            app_label: String::new(),
            format: TokenFormat::default(),
            clock: Arc::new(SystemClock),
            ttl: Ttls::default(),
            cookie_brand: None,
            csrf_header: None,
            cookie_api_prefix: Some("/api/".to_owned()),
            mount: String::new(),
            providers: Vec::new(),
            workload_issuers: Vec::new(),
            audit: None,
            purposes: Arc::new(StaticPurposes::default()),
            approvals: Arc::new(NoPendingApprovals),
            app_tokens: None,
            post_login_redirect: "/".to_owned(),
            max_pending_devices: 1024,
        }
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    /// The token format (brand and kinds).
    #[must_use]
    pub fn format(&self) -> &TokenFormat {
        &self.inner.format
    }

    /// Now, from the injected clock.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.inner.clock.now()
    }

    /// The TTLs.
    #[must_use]
    pub fn ttl(&self) -> &Ttls {
        &self.inner.ttl
    }

    /// The configured public URL (no trailing `/`).
    #[must_use]
    pub fn public_url(&self) -> &str {
        &self.inner.public_url
    }

    /// Where the forgs router is nested in the app (`""` or `/x`).
    #[must_use]
    pub fn mount(&self) -> &str {
        &self.inner.mount
    }

    /// The cookie names.
    #[must_use]
    pub fn cookies(&self) -> &CookieNames {
        &self.inner.cookies
    }

    /// The header a cookie-authenticated mutating call echoes the CSRF token
    /// in.
    #[must_use]
    pub fn csrf_header(&self) -> &str {
        &self.inner.csrf_header
    }

    /// The path prefix under which [`crate::Carrier::ApiCookie`] accepts a
    /// cookie, if any.
    #[must_use]
    pub fn cookie_api_prefix(&self) -> Option<&str> {
        self.inner.cookie_api_prefix.as_deref()
    }

    /// The configured providers.
    #[must_use]
    pub fn providers(&self) -> &[Arc<dyn IdentityProvider>] {
        &self.inner.providers
    }

    /// A provider by configured name.
    #[must_use]
    pub fn provider(&self, name: &str) -> Option<&Arc<dyn IdentityProvider>> {
        self.inner.providers.iter().find(|p| p.name() == name)
    }

    /// The configured workload issuers.
    #[must_use]
    pub fn workload_issuers(&self) -> &[Arc<dyn WorkloadIssuer>] {
        &self.inner.workload_issuers
    }

    /// The audit sink.
    #[must_use]
    pub fn audit(&self) -> &Arc<dyn AuditSink> {
        &self.inner.audit
    }

    /// The API-key purpose policy.
    #[must_use]
    pub fn purposes(&self) -> &Arc<dyn ApiKeyPurposes> {
        &self.inner.purposes
    }

    /// The pending-approval hook.
    #[must_use]
    pub fn approvals(&self) -> &Arc<dyn PendingApprovalHook> {
        &self.inner.approvals
    }

    /// Where a browser lands after login when no `return_to` was given.
    #[must_use]
    pub fn post_login_redirect(&self) -> &str {
        &self.inner.post_login_redirect
    }

    /// The credential lookup every authentication goes through: the store for
    /// core kinds, the [`AppTokenLookup`] hook (if any) for app kinds.
    pub(crate) fn token_store(&self) -> CtxTokenStore<'_> {
        CtxTokenStore {
            store: &self.inner.store,
            apps: self.inner.app_tokens.as_deref(),
        }
    }

    pub(crate) fn keys(&self) -> &CsrfKey {
        &self.inner.keys
    }

    /// `scheme://host[:port]` of the public URL, for `Origin` checks.
    pub(crate) fn public_origin(&self) -> &str {
        &self.inner.public_origin
    }

    /// An absolute URL for a path under the mount: `{public_url}{mount}{path}`.
    #[must_use]
    pub fn absolute(&self, path: &str) -> String {
        format!("{}{}{path}", self.inner.public_url, self.inner.mount)
    }

    /// A same-origin path under the mount: `{mount}{path}`.
    #[must_use]
    pub fn path(&self, path: &str) -> String {
        format!("{}{path}", self.inner.mount)
    }

    /// The OAuth `redirect_uri` for `provider`.
    ///
    /// **From `public_url`, never from the request.** Behind a reverse proxy
    /// the server does not see its own public name, and a `Host`-derived
    /// callback is a host-header-injection route to an attacker-controlled
    /// OAuth redirect — an account takeover.
    #[must_use]
    pub fn redirect_uri(&self, provider: &str) -> String {
        self.absolute(&format!("/auth/{provider}/callback"))
    }
}

/// Builder for [`AuthContext`].
pub struct AuthContextBuilder {
    store: Store,
    public_url: String,
    secret: Vec<u8>,
    app_label: String,
    format: TokenFormat,
    clock: Arc<dyn Clock>,
    ttl: Ttls,
    cookie_brand: Option<String>,
    csrf_header: Option<String>,
    cookie_api_prefix: Option<String>,
    mount: String,
    providers: Vec<Arc<dyn IdentityProvider>>,
    workload_issuers: Vec<Arc<dyn WorkloadIssuer>>,
    audit: Option<Arc<dyn AuditSink>>,
    purposes: Arc<dyn ApiKeyPurposes>,
    approvals: Arc<dyn PendingApprovalHook>,
    app_tokens: Option<Arc<dyn AppTokenLookup>>,
    post_login_redirect: String,
    max_pending_devices: u64,
}

impl fmt::Debug for AuthContextBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthContextBuilder")
            .field("public_url", &self.public_url)
            .finish_non_exhaustive()
    }
}

impl AuthContextBuilder {
    /// Separates this app's CSRF / cookie keys from any other app's (default
    /// empty).
    #[must_use]
    pub fn app_label(mut self, label: &str) -> Self {
        label.clone_into(&mut self.app_label);
        self
    }

    /// The token format (default: brand `frg`, core kinds only).
    #[must_use]
    pub fn format(mut self, format: TokenFormat) -> Self {
        self.format = format;
        self
    }

    /// The clock (default: the wall clock).
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The TTLs.
    #[must_use]
    pub fn ttls(mut self, ttl: Ttls) -> Self {
        self.ttl = ttl;
        self
    }

    /// The cookie brand (default: the token format's brand).
    #[must_use]
    pub fn cookie_brand(mut self, brand: &str) -> Self {
        self.cookie_brand = Some(brand.to_owned());
        self
    }

    /// The CSRF header name (default `x-{brand}-csrf`).
    #[must_use]
    pub fn csrf_header(mut self, name: &str) -> Self {
        self.csrf_header = Some(name.to_ascii_lowercase());
        self
    }

    /// The path prefix under which an app route marked
    /// [`crate::ApiCookie`] accepts the session cookie (default `/api/`), or
    /// `None` for nowhere.
    #[must_use]
    pub fn cookie_api_prefix(mut self, prefix: Option<&str>) -> Self {
        self.cookie_api_prefix = prefix.map(str::to_owned);
        self
    }

    /// Where the app nests [`crate::router`] (`""`, the default, or `/x`).
    #[must_use]
    pub fn mount(mut self, mount: &str) -> Self {
        mount.clone_into(&mut self.mount);
        self
    }

    /// Add a login provider.
    #[must_use]
    pub fn provider(mut self, provider: Arc<dyn IdentityProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    /// Add a workload issuer (e.g. GitHub Actions). Each issuer's
    /// [`WorkloadIssuer::name`] and [`WorkloadIssuer::subject_ns`] must be
    /// unique among the configured issuers; [`Self::build`] refuses
    /// duplicates.
    #[must_use]
    pub fn workload_issuer(mut self, issuer: Arc<dyn WorkloadIssuer>) -> Self {
        self.workload_issuers.push(issuer);
        self
    }

    /// The audit sink (default: [`StoreAuditSink`]).
    #[must_use]
    pub fn audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(sink);
        self
    }

    /// The API-key purpose policy (default: no purposes; minting refuses).
    #[must_use]
    pub fn api_key_purposes(mut self, purposes: Arc<dyn ApiKeyPurposes>) -> Self {
        self.purposes = purposes;
        self
    }

    /// The pending-approval hook for app device approvals (default: none).
    #[must_use]
    pub fn pending_approvals(mut self, hook: Arc<dyn PendingApprovalHook>) -> Self {
        self.approvals = hook;
        self
    }

    /// The lookup for the app's own connection token kinds (default: none,
    /// so every app token is an unknown credential).
    #[must_use]
    pub fn app_tokens(mut self, lookup: Arc<dyn AppTokenLookup>) -> Self {
        self.app_tokens = Some(lookup);
        self
    }

    /// Where a browser lands after login by default (`/`).
    #[must_use]
    pub fn post_login_redirect(mut self, path: &str) -> Self {
        path.clone_into(&mut self.post_login_redirect);
        self
    }

    /// Ceiling on live device approvals an unauthenticated caller can create
    /// (default 1024).
    #[must_use]
    pub fn max_pending_devices(mut self, n: u64) -> Self {
        self.max_pending_devices = n;
        self
    }

    /// Validate and build.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for an unusable public URL, a short secret, a bad
    /// provider name, mount or path, or an invalid or duplicate workload
    /// issuer name or subject label.
    pub fn build(self) -> Result<AuthContext, ConfigError> {
        let public_url = self.public_url.trim().trim_end_matches('/').to_owned();
        let public_origin = origin_of(&public_url)
            .ok_or_else(|| ConfigError::PublicUrl(self.public_url.clone()))?;
        if self.secret.len() < 32 {
            return Err(ConfigError::ShortSecret);
        }
        if !(self.mount.is_empty()
            || (self.mount.starts_with('/')
                && !self.mount.ends_with('/')
                && safe_path(&self.mount)))
        {
            return Err(ConfigError::Mount(self.mount));
        }
        if crate::login::safe_return_to(&self.post_login_redirect).is_none() {
            return Err(ConfigError::Path(self.post_login_redirect));
        }
        if let Some(p) = &self.cookie_api_prefix {
            if !p.starts_with('/') || !safe_path(p) {
                return Err(ConfigError::Path(p.clone()));
            }
        }
        let mut seen = Vec::new();
        for p in &self.providers {
            let name = p.name();
            let ok = valid_name(name)
                && !RESERVED_PROVIDER_NAMES.contains(&name)
                && !seen.contains(&name);
            if !ok {
                return Err(ConfigError::ProviderName(name.to_owned()));
            }
            seen.push(name);
        }
        let mut names = Vec::new();
        let mut labels = Vec::new();
        for issuer in &self.workload_issuers {
            let name = issuer.name();
            if !valid_name(name) || names.contains(&name) {
                return Err(ConfigError::WorkloadIssuerName(name.to_owned()));
            }
            names.push(name);
            let ns = issuer.subject_ns();
            if !forgs::subject::valid_workload_ns(ns) || labels.contains(&ns) {
                return Err(ConfigError::WorkloadSubjectNs(ns.to_owned()));
            }
            labels.push(ns);
        }
        let brand = self
            .cookie_brand
            .unwrap_or_else(|| self.format.brand().to_owned());
        let csrf_header = self
            .csrf_header
            .unwrap_or_else(|| format!("x-{brand}-csrf"));
        let audit = self
            .audit
            .unwrap_or_else(|| Arc::new(StoreAuditSink::new(self.store.clone())));
        Ok(AuthContext {
            inner: Arc::new(Inner {
                keys: CsrfKey::derive(&self.secret, &self.app_label),
                store: self.store,
                format: self.format,
                clock: self.clock,
                ttl: self.ttl,
                public_url,
                public_origin,
                mount: self.mount,
                cookies: CookieNames::for_brand(&brand),
                csrf_header,
                cookie_api_prefix: self.cookie_api_prefix,
                providers: self.providers,
                workload_issuers: self.workload_issuers,
                audit,
                purposes: self.purposes,
                approvals: self.approvals,
                app_tokens: self.app_tokens,
                post_login_redirect: self.post_login_redirect,
                max_pending_devices: self.max_pending_devices,
                poll_log: Mutex::new(HashMap::new()),
            }),
        })
    }
}

/// [`TokenStore`] over the context: every core lookup delegates to the
/// [`Store`], app kinds go to the [`AppTokenLookup`] hook (or are unknown).
pub(crate) struct CtxTokenStore<'a> {
    store: &'a Store,
    apps: Option<&'a dyn AppTokenLookup>,
}

#[async_trait]
impl TokenStore for CtxTokenStore<'_> {
    async fn lookup_session(&self, hash: &TokenHash) -> Result<Option<SessionRecord>, String> {
        self.store.lookup_session(hash).await
    }

    async fn lookup_refresh_token(
        &self,
        hash: &TokenHash,
    ) -> Result<Option<RefreshRecord>, String> {
        self.store.lookup_refresh_token(hash).await
    }

    async fn lookup_api_key(&self, hash: &TokenHash) -> Result<Option<ApiKeyRecord>, String> {
        self.store.lookup_api_key(hash).await
    }

    async fn lookup_workload(&self, hash: &TokenHash) -> Result<Option<WorkloadRecord>, String> {
        self.store.lookup_workload(hash).await
    }

    async fn lookup_device_secret(
        &self,
        hash: &TokenHash,
    ) -> Result<Option<DeviceSecretRecord>, String> {
        self.store.lookup_device_secret(hash).await
    }

    async fn lookup_app(
        &self,
        kind: AppKind,
        hash: &TokenHash,
    ) -> Result<Option<AppRecord>, String> {
        match self.apps {
            Some(apps) => apps.lookup_app(kind, hash).await,
            None => Ok(None),
        }
    }
}

/// Printable ASCII path characters with nothing that could end a header or
/// an HTML attribute.
fn safe_path(p: &str) -> bool {
    p.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/-_.~".contains(&b))
}

/// `scheme://authority` of an absolute http(s) URL with no query/fragment.
fn origin_of(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .map(|r| ("https", r))
        .or_else(|| url.strip_prefix("http://").map(|r| ("http", r)))?;
    let (scheme, rest) = rest;
    if url.contains(['?', '#']) || url.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return None;
    }
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some(format!("{scheme}://{}", authority.to_ascii_lowercase()))
}

/// A provider or workload issuer name: 1–64 chars over `[a-z0-9_-]`.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins() {
        assert_eq!(
            origin_of("https://Forge.example/app").as_deref(),
            Some("https://forge.example")
        );
        assert_eq!(
            origin_of("http://127.0.0.1:7000").as_deref(),
            Some("http://127.0.0.1:7000")
        );
        for bad in [
            "ftp://x",
            "https://",
            "https://x/?q",
            "https://x/#f",
            "https://u@x",
            "x",
        ] {
            assert_eq!(origin_of(bad), None, "{bad}");
        }
    }

    #[test]
    fn keys_are_domain_separated() {
        let a = CsrfKey::derive(&[7; 32], "fleet");
        let b = CsrfKey::derive(&[7; 32], "forge");
        let c = CsrfKey::derive(&[8; 32], "fleet");
        assert_ne!(a.csrf, b.csrf);
        assert_ne!(a.csrf, c.csrf);
        assert_ne!(a.csrf, a.flow);
        assert_eq!(a.csrf, CsrfKey::derive(&[7; 32], "fleet").csrf);
        assert!(!format!("{a:?}").contains('7'));
    }

    #[test]
    fn fixed_clock_moves() {
        let c = FixedClock::new(10);
        c.advance(5);
        assert_eq!(c.now(), 15);
        c.set(3);
        assert_eq!(c.now(), 3);
    }
}
