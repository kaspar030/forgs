//! [`AuthContext`]: everything the auth surface needs, injected once.
//!
//! Nothing here reads ambient state. The clock, the TTLs, the public URL, the
//! cookie names and the CSRF secret are all supplied by the app, which is
//! what makes every flow a deterministic integration test.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::http::{Extensions, HeaderMap, HeaderName};
use forgs::store::{
    ApiKeyRecord, AppRecord, DeviceSecretRecord, RefreshRecord, SessionRecord, WorkloadRecord,
};
use forgs::{AppKind, TokenFormat, TokenHash, TokenStore, UserId};
use forgs_idp::{IdentityProvider, WorkloadIssuer};
use forgs_store::Store;
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

use crate::audit::{AuditSink, StoreAuditSink};
use crate::hooks::{
    ApiKeyPurposes, AppTokenLookup, NoPendingApprovals, NoSignupApprovals, PendingApprovalHook,
    SignupApprovalHook, StaticPurposes,
};

/// Who may create an account through first-login signup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignupPolicy {
    /// Anyone who logs in with a configured provider may sign up and use
    /// the account at once.
    #[default]
    Open,
    /// Signup creates the account as [`forgs_store::UserState::Pending`]:
    /// the user sees a "waiting for approval" page and cannot log in until
    /// an approver ([`SignupApprovalHook::can_approve`]) approves them.
    Approval,
    /// Signup is refused (`403 signup_closed`): accounts are created by the
    /// app (invites, an admin) only.
    Closed,
}

/// A source of "now", in epoch seconds.
pub trait Clock: Send + Sync {
    /// The current time, epoch seconds.
    fn now(&self) -> u64;
}

/// The wall clock.
///
/// # Panics
///
/// [`Clock::now`] panics if the system clock reads before the Unix epoch.
/// Returning any fixed value instead would fail open (with `0`, every expiry
/// check passes), so a clock that broken stops the request instead.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before the Unix epoch; refusing to check expiries")
            .as_secs()
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
///
/// Every name carries the `__Host-` prefix. A browser only accepts a
/// `__Host-` cookie that is `Secure`, `Path=/` and has no `Domain` — exactly
/// what [`crate::cookies::set_cookie`] emits — so no sibling or parent domain
/// can write (or shadow, via a longer `Path`) these cookies, and neither can
/// an on-path attacker over plain http (cookie tossing).
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
    /// `__Host-{brand}_session`, `__Host-{brand}_csrf`,
    /// `__Host-{brand}_oauth`, `__Host-{brand}_signup`.
    #[must_use]
    pub fn for_brand(brand: &str) -> Self {
        Self {
            session: format!("__Host-{brand}_session"),
            csrf: format!("__Host-{brand}_csrf"),
            oauth: format!("__Host-{brand}_oauth"),
            signup: format!("__Host-{brand}_signup"),
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
///   `oauth` and `signup` cookies, so a *forged* value is refused. The seal
///   binds name and expiry, not the browser: it does not stop a valid value
///   minted in an attacker's own browser being planted — the `__Host-`
///   cookie prefix ([`CookieNames`]) is what stops that.
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
    /// absolute same-origin path; `cookie_api_prefix` must also end with `/`.
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
    "signups",
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
    pub(crate) signup_policy: SignupPolicy,
    pub(crate) signup_approvals: Arc<dyn SignupApprovalHook>,
    pub(crate) app_tokens: Option<Arc<dyn AppTokenLookup>>,
    pub(crate) post_login_redirect: String,
    pub(crate) max_pending_devices: u64,
    pub(crate) max_pending_approvals: u64,
    pub(crate) max_pending_devices_per_source: u64,
    pub(crate) max_api_keys_per_namespace: u64,
    pub(crate) max_api_keys_per_user: u64,
    pub(crate) max_ssh_keys_per_user: u64,
    pub(crate) client_ip: Arc<dyn ClientIp>,
    /// Poll state per device-secret hash, for `slow_down`.
    pub(crate) poll_log: Mutex<HashMap<String, PollState>>,
    /// Wrong user codes per user, for the guessing lockout.
    pub(crate) decide_misses: Mutex<HashMap<UserId, MissWindow>>,
}

/// A live device flow's poll pacing (see [`crate::device`]).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PollState {
    /// Last accepted-or-refused poll, epoch seconds.
    pub(crate) last: u64,
    /// The interval the poller must now keep.
    pub(crate) interval: u64,
}

/// A user's wrong-code count in the current window.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MissWindow {
    pub(crate) count: u32,
    pub(crate) start: u64,
}

/// How the unauthenticated device-start route learns who is calling, for the
/// per-source cap and the source shown on the confirm page.
///
/// forgs never trusts a forwarding header by default ([`NoClientIp`]
/// ignores headers). An app behind a reverse proxy configures
/// [`ForwardedFor`] with the number of proxies it trusts; an app that owns
/// its listener inserts [`PeerIp`] into the request extensions (e.g. a
/// one-line middleware over axum's `ConnectInfo<SocketAddr>`), which every
/// built-in resolver prefers to read.
pub trait ClientIp: Send + Sync + 'static {
    /// The caller's address, or `None` if unknown.
    fn client_ip(&self, headers: &HeaderMap, ext: &Extensions) -> Option<IpAddr>;
}

/// The peer address of the connection, inserted into the request
/// extensions by the app (forgs-http cannot name `ConnectInfo` itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIp(pub IpAddr);

/// The default: the [`PeerIp`] extension if the app inserted one, else
/// unknown. Never reads a header.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoClientIp;

impl ClientIp for NoClientIp {
    fn client_ip(&self, _headers: &HeaderMap, ext: &Extensions) -> Option<IpAddr> {
        ext.get::<PeerIp>().map(|p| p.0)
    }
}

/// Behind `trusted_hops` + 1 reverse proxies that each append to a
/// comma-separated header such as `X-Forwarded-For`: the entry
/// `trusted_hops` places from the right is the one the outermost trusted
/// proxy saw. `trusted_hops: 0` means one proxy, which wrote the last entry.
/// Anything further left is client-supplied and never read. A missing or
/// unparseable entry is unknown, not the [`PeerIp`] (which would be the
/// proxy).
#[derive(Debug, Clone)]
pub struct ForwardedFor {
    /// The header (e.g. `x-forwarded-for`).
    pub header: HeaderName,
    /// Proxies in front of the outermost one that appends.
    pub trusted_hops: usize,
}

impl ClientIp for ForwardedFor {
    fn client_ip(&self, headers: &HeaderMap, _ext: &Extensions) -> Option<IpAddr> {
        // Several header lines are one list, in order.
        let joined = headers
            .get_all(&self.header)
            .iter()
            .map(|v| v.to_str().ok())
            .collect::<Option<Vec<_>>>()?
            .join(",");
        let entry = joined.rsplit(',').nth(self.trusted_hops)?.trim();
        entry
            .parse::<IpAddr>()
            .ok()
            .or_else(|| entry.parse::<std::net::SocketAddr>().ok().map(|a| a.ip()))
    }
}

/// The bucket a source address counts against: an IPv4 address itself
/// (also when IPv4-mapped), an IPv6 address's `/64` (one host commonly owns
/// a whole /64, so per-address limits there mean nothing).
#[must_use]
pub fn source_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.to_string();
            }
            let s = v6.segments();
            let net = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
            format!("{net}/64")
        }
    }
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
            signup_policy: SignupPolicy::Open,
            signup_approvals: Arc::new(NoSignupApprovals),
            app_tokens: None,
            post_login_redirect: "/".to_owned(),
            max_pending_devices: 1024,
            max_pending_approvals: 1024,
            max_pending_devices_per_source: 32,
            max_api_keys_per_namespace: 1000,
            max_api_keys_per_user: 100,
            max_ssh_keys_per_user: 100,
            client_ip: Arc::new(NoClientIp),
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

    /// The signup policy.
    #[must_use]
    pub fn signup_policy(&self) -> SignupPolicy {
        self.inner.signup_policy
    }

    /// The signup-approval hook.
    #[must_use]
    pub fn signup_approvals(&self) -> &Arc<dyn SignupApprovalHook> {
        &self.inner.signup_approvals
    }

    /// The caller's address per the configured [`ClientIp`] resolver, for an
    /// app's own unauthenticated start route.
    #[must_use]
    pub fn client_ip(&self, headers: &HeaderMap, ext: &Extensions) -> Option<IpAddr> {
        self.inner.client_ip.client_ip(headers, ext)
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
    signup_policy: SignupPolicy,
    signup_approvals: Arc<dyn SignupApprovalHook>,
    app_tokens: Option<Arc<dyn AppTokenLookup>>,
    post_login_redirect: String,
    max_pending_devices: u64,
    max_pending_approvals: u64,
    max_pending_devices_per_source: u64,
    max_api_keys_per_namespace: u64,
    max_api_keys_per_user: u64,
    max_ssh_keys_per_user: u64,
    client_ip: Arc<dyn ClientIp>,
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
    ///
    /// The prefix must end with `/` ([`Self::build`] refuses `/api`, which
    /// would also match `/apix` and `/api-admin`).
    ///
    /// **`GET`/`HEAD` handlers under this prefix must be side-effect free**:
    /// the session cookie is `SameSite=Lax`, so it rides cross-site top-level
    /// `GET` navigations, and the CSRF check is skipped for safe methods.
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

    /// Who may sign up (default [`SignupPolicy::Open`]).
    #[must_use]
    pub fn signup_policy(mut self, policy: SignupPolicy) -> Self {
        self.signup_policy = policy;
        self
    }

    /// Who may approve pending signups (default [`NoSignupApprovals`]:
    /// nobody).
    #[must_use]
    pub fn signup_approvals(mut self, hook: Arc<dyn SignupApprovalHook>) -> Self {
        self.signup_approvals = hook;
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

    /// Ceiling on live CLI device logins an unauthenticated caller can
    /// create (default 1024). App approvals have their own ceiling
    /// ([`Self::max_pending_approvals`]), so flooding one kind does not
    /// lock out the other.
    #[must_use]
    pub fn max_pending_devices(mut self, n: u64) -> Self {
        self.max_pending_devices = n;
        self
    }

    /// Ceiling on live app pending approvals
    /// ([`crate::device::start_pending_approval`]; default 1024).
    #[must_use]
    pub fn max_pending_approvals(mut self, n: u64) -> Self {
        self.max_pending_approvals = n;
        self
    }

    /// Ceiling on live device flows (both kinds) from one source (default
    /// 32; `u64::MAX` disables). Only enforced when the source is known: see
    /// [`Self::client_ip`].
    #[must_use]
    pub fn max_pending_devices_per_source(mut self, n: u64) -> Self {
        self.max_pending_devices_per_source = n;
        self
    }

    /// Ceiling on **live** (unexpired, unconsumed) API keys a namespace may
    /// hold when minting over the API (default 1000; `u64::MAX` disables).
    /// Past it a mint is `403 key_limit`. Shell-minted keys count toward it
    /// but are never refused by it.
    #[must_use]
    pub fn max_api_keys_per_namespace(mut self, n: u64) -> Self {
        self.max_api_keys_per_namespace = n;
        self
    }

    /// Ceiling on live API keys one user may hold in one namespace when
    /// minting over the API (default 100; `u64::MAX` disables), so one member
    /// cannot exhaust [`Self::max_api_keys_per_namespace`] alone.
    #[must_use]
    pub fn max_api_keys_per_user(mut self, n: u64) -> Self {
        self.max_api_keys_per_user = n;
        self
    }

    /// Ceiling on **live** (unexpired) SSH public keys one user may register
    /// (default 100; `u64::MAX` disables). Past it an add is `403 key_limit`.
    #[must_use]
    pub fn max_ssh_keys_per_user(mut self, n: u64) -> Self {
        self.max_ssh_keys_per_user = n;
        self
    }

    /// How the device-start route learns the caller's address (default
    /// [`NoClientIp`]: the [`PeerIp`] extension if present, never a header).
    #[must_use]
    pub fn client_ip(mut self, resolver: impl ClientIp) -> Self {
        self.client_ip = Arc::new(resolver);
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
            if !p.starts_with('/') || !p.ends_with('/') || !safe_path(p) {
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
                signup_policy: self.signup_policy,
                signup_approvals: self.signup_approvals,
                app_tokens: self.app_tokens,
                post_login_redirect: self.post_login_redirect,
                max_pending_devices: self.max_pending_devices,
                max_pending_approvals: self.max_pending_approvals,
                max_pending_devices_per_source: self.max_pending_devices_per_source,
                max_api_keys_per_namespace: self.max_api_keys_per_namespace,
                max_api_keys_per_user: self.max_api_keys_per_user,
                max_ssh_keys_per_user: self.max_ssh_keys_per_user,
                client_ip: self.client_ip,
                poll_log: Mutex::new(HashMap::new()),
                decide_misses: Mutex::new(HashMap::new()),
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
    let mut authority = authority.to_ascii_lowercase();
    // An explicit default port is the same origin as none: browsers never
    // send it in `Origin`, so keeping it would make every check fail closed.
    let default_port = if scheme == "https" { ":443" } else { ":80" };
    if let Some(host) = authority.strip_suffix(default_port) {
        if !host.is_empty() && !host.ends_with(':') {
            authority = host.to_owned();
        }
    }
    Some(format!("{scheme}://{authority}"))
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
        assert_eq!(
            origin_of("https://X.example:443/app").as_deref(),
            Some("https://x.example")
        );
        assert_eq!(
            origin_of("http://x.example:80").as_deref(),
            Some("http://x.example")
        );
        assert_eq!(
            origin_of("http://x.example:443").as_deref(),
            Some("http://x.example:443")
        );
        assert_eq!(
            origin_of("https://x.example:8443").as_deref(),
            Some("https://x.example:8443")
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
    fn cookie_names_are_host_prefixed() {
        let n = CookieNames::for_brand("frg");
        assert_eq!(n.session, "__Host-frg_session");
        assert_eq!(n.csrf, "__Host-frg_csrf");
        assert_eq!(n.oauth, "__Host-frg_oauth");
        assert_eq!(n.signup, "__Host-frg_signup");
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

    #[test]
    fn source_keys_bucket_v6_by_64() {
        let k = |s: &str| source_key(s.parse().unwrap());
        assert_eq!(k("10.1.2.3"), "10.1.2.3");
        assert_eq!(k("::ffff:10.1.2.3"), "10.1.2.3");
        assert_eq!(k("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64");
        assert_eq!(k("2001:db8:1:2:bbbb::9"), "2001:db8:1:2::/64");
        assert_ne!(k("2001:db8:1:3::1"), k("2001:db8:1:2::1"));
    }

    #[test]
    fn forwarded_for_reads_only_trusted_entries() {
        let mut h = HeaderMap::new();
        let ext = Extensions::new();
        h.append("x-forwarded-for", "6.6.6.6, 1.1.1.1".parse().unwrap());
        h.append("x-forwarded-for", "2.2.2.2".parse().unwrap());
        let ff = |hops| ForwardedFor {
            header: HeaderName::from_static("x-forwarded-for"),
            trusted_hops: hops,
        };
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        assert_eq!(ff(0).client_ip(&h, &ext), ip("2.2.2.2"));
        assert_eq!(ff(1).client_ip(&h, &ext), ip("1.1.1.1"));
        assert_eq!(ff(5).client_ip(&h, &ext), None);
        assert_eq!(ff(0).client_ip(&HeaderMap::new(), &ext), None);
        let mut ext = Extensions::new();
        ext.insert(PeerIp(ip("9.9.9.9").unwrap()));
        assert_eq!(NoClientIp.client_ip(&h, &ext), ip("9.9.9.9"));
        assert_eq!(NoClientIp.client_ip(&h, &Extensions::new()), None);
    }
}
