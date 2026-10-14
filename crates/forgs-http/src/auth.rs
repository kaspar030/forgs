//! The single `Subject` seam.
//!
//! [`authenticate_request`] is **the only place a [`Subject`] is constructed
//! from wire input.** Everything downstream consumes the [`Caller`] it
//! returns and is unchanged by how the caller proved itself. The
//! [`Authenticated`] extractor is a thin wrapper over it, and apps that do
//! not use the extractor call the same function.
//!
//! `forgs::verify` deliberately stops at [`forgs::Authenticated`] and never
//! mints a `Subject`: it knows nothing about membership, and a second minting
//! site in a crate with no membership knowledge is exactly how tenancy holes
//! appear. `acting_in` is never set here — it is a claim a handler attaches
//! only after checking membership in the named namespace.
//!
//! # One extra carrier, not a second credential
//!
//! A browser cannot hold an `Authorization` header the way the CLI does, so
//! the same session token may also arrive in the `HttpOnly` session cookie.
//! [`Carrier`] says where a route accepts it:
//!
//! * [`Carrier::Header`] — `Authorization: Bearer` only. Every JSON route
//!   forgs owns (`/auth/token`, `/auth/keys`, `/auth/logout`, …): a cookie
//!   alone is a flat 401 there.
//! * [`Carrier::ApiCookie`] — header, or the cookie **only when the request
//!   path is under the configured `cookie_api_prefix`** (default `/api/`).
//!   That allowlist is the blast radius of the cookie design.
//! * [`Carrier::Cookie`] — header or cookie, for forgs' own explicitly marked
//!   browser routes (the device-verification form, session logout, link
//!   start, whoami).
//!
//! The header wins when both are present: an explicit credential is a
//! deliberate act, a cookie is attached by the browser, so a page that opts
//! into a bearer never has an ambient credential substituted for it.
//!
//! A credential that arrived by cookie is ambient, so a mutating call
//! carrying one must also carry the CSRF token; the extractor enforces that
//! for every non-`GET`/`HEAD` request, so no handler can forget it.
//!
//! # No oracle
//!
//! Every rejection before a credential resolves — missing, malformed,
//! unknown, expired, store failure, disabled user — is one byte-identical
//! `401 unauthorized` body. A valid credential of the wrong kind for the
//! route (including a redeem-only kind, decided from the prefix alone) is
//! `403 forbidden`: that distinction is a function of the prefix the caller
//! supplied and leaks nothing. The reason goes to the audit sink.
//!
//! # App token kinds
//!
//! An app's own connection kinds (fleet: a node token) authenticate through
//! this same function: the lookup goes to the app's
//! [`crate::AppTokenLookup`] hook, the route fences kinds with
//! [`AllowedKinds`] as for core kinds (so an app token is `403` on
//! [`SessionOnly`] routes), and an unknown, revoked, expired or
//! failed-lookup app token is the same uniform `401`. There is no second
//! `Subject`-minting site for apps.

use std::marker::PhantomData;

use axum::extract::{FromRef, FromRequestParts, OriginalUri};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse as _, Response};
use forgs::{AuthError, Subject, SubjectKind, TokenKind, UserId};
use forgs_store::UserState;

use crate::audit::AuditEvent;
use crate::context::AuthContext;
use crate::cookies::{cookie_value, csrf_ok};
use crate::error::{reject, ApiError};

/// Extract the bearer credential from an `Authorization` header.
#[must_use]
pub fn bearer_of(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, credential) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(credential.trim())
}

/// Where a route accepts the credential. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// `Authorization: Bearer` only.
    Header,
    /// Header, or the session cookie under `cookie_api_prefix` only.
    ApiCookie,
    /// Header or session cookie (forgs' own marked browser routes).
    Cookie,
}

/// How the credential actually arrived. The CSRF check keys off this rather
/// than off [`Carrier`]: a page that sends an explicit header needs no CSRF
/// token, because that credential is not ambient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    /// In an `Authorization: Bearer` header.
    Header,
    /// In the session cookie.
    Cookie,
}

/// An authenticated caller.
#[derive(Debug, Clone)]
pub struct Caller {
    /// The verified credential.
    pub auth: forgs::Authenticated,
    /// Who it speaks as. `acting_in` is unset.
    pub subject: Subject,
    /// How the credential arrived.
    pub arrival: Arrival,
}

impl Caller {
    /// The user id, for a user session.
    #[must_use]
    pub fn user_id(&self) -> Option<UserId> {
        self.subject.key().user_id()
    }

    /// The user id, or `403` for a non-user caller.
    ///
    /// # Errors
    ///
    /// [`ApiError::Forbidden`] for a workload or app subject.
    pub fn require_user(&self) -> Result<UserId, ApiError> {
        self.user_id().ok_or(ApiError::Forbidden)
    }
}

/// The uniform 401.
fn unauthorized() -> Response {
    reject(
        StatusCode::UNAUTHORIZED,
        forgs::api::error_code::UNAUTHORIZED,
    )
}

/// The uniform 403.
fn forbidden() -> Response {
    reject(StatusCode::FORBIDDEN, forgs::api::error_code::FORBIDDEN)
}

/// Authenticate a request and build the caller's [`Subject`]. **The only
/// place a `Subject` is constructed from wire input.**
///
/// `path` is the full request path (after any nesting; see
/// [`request_path`]), consulted only for [`Carrier::ApiCookie`]. `allowed`
/// is the set of credential kinds the route accepts.
///
/// # Errors
///
/// The response to return: the uniform `401`, or `403` for a wrong kind.
// `Response` is axum's native rejection type (see `FromRequestParts::Rejection`);
// boxing it would only add unboxing at every call site on the error path.
#[allow(clippy::result_large_err)]
pub async fn authenticate_request(
    ctx: &AuthContext,
    headers: &HeaderMap,
    path: &str,
    allowed: &[TokenKind],
    carrier: Carrier,
) -> Result<Caller, Response> {
    let now = ctx.now();
    let cookie_ok = match carrier {
        Carrier::Header => false,
        Carrier::Cookie => true,
        Carrier::ApiCookie => ctx.cookie_api_prefix().is_some_and(|p| path.starts_with(p)),
    };
    let (bearer, arrival) = match bearer_of(headers) {
        Some(b) => (b, Arrival::Header),
        None if cookie_ok => (
            cookie_value(headers, &ctx.cookies().session).unwrap_or(""),
            Arrival::Cookie,
        ),
        None => ("", Arrival::Header),
    };

    let auth = match forgs::authenticate(ctx.format(), &ctx.token_store(), bearer, now).await {
        Ok(a) => a,
        Err(e) => return Err(reject_authentication(ctx, &e).await),
    };
    if !allowed.contains(&auth.kind) {
        let e = AuthError::WrongKind { got: auth.kind };
        ctx.audit()
            .record(
                AuditEvent::new(now, e.label())
                    .subject(&auth.subject)
                    .target(auth.hash.short())
                    .detail(e.to_string()),
            )
            .await;
        return Err(forbidden());
    }
    // A disabled (or deleted) user's sessions stop working at once, with the
    // same body as an unknown token.
    if auth.subject.kind() == SubjectKind::User {
        let Some(user) = auth.subject.user_id() else {
            return Err(unauthorized());
        };
        match ctx.store().user_by_id(user).await {
            Ok(Some(u)) if u.state == UserState::Active => {}
            Ok(_) => {
                ctx.audit()
                    .record(
                        AuditEvent::new(now, "auth.reject.disabled")
                            .subject(&auth.subject)
                            .target(auth.hash.short()),
                    )
                    .await;
                return Err(unauthorized());
            }
            Err(e) => {
                tracing::warn!(error = %e, "user lookup failed during authentication");
                return Err(unauthorized());
            }
        }
    }
    let subject = Subject::new(auth.subject.clone());
    Ok(Caller {
        auth,
        subject,
        arrival,
    })
}

/// Audit a failed authentication and produce the uniform rejection.
async fn reject_authentication(ctx: &AuthContext, e: &AuthError) -> Response {
    if let AuthError::Store(detail) = e {
        // Our fault, not the caller's; still the uniform 401 (no oracle), but
        // it must be visible as an operational problem.
        tracing::warn!(%detail, "credential store failed during authentication");
    }
    let mut ev = AuditEvent::new(ctx.now(), e.label()).detail(e.to_string());
    if let Some(k) = e.kind() {
        ev = ev.target(k.to_string());
    }
    ctx.audit().record(ev).await;
    if matches!(e, AuthError::WrongKind { .. }) {
        return forbidden();
    }
    unauthorized()
}

/// Require the CSRF header on a mutating, cookie-authenticated request.
///
/// # Errors
///
/// `403 forbidden` when it is missing or wrong.
// `Response` is axum's native rejection type (see `FromRequestParts::Rejection`);
// boxing it would only add unboxing at every call site on the error path.
#[allow(clippy::result_large_err)]
pub async fn require_csrf(
    ctx: &AuthContext,
    method: &Method,
    headers: &HeaderMap,
    caller: &Caller,
) -> Result<(), Response> {
    if matches!(*method, Method::GET | Method::HEAD) {
        return Ok(());
    }
    if csrf_ok(
        ctx,
        headers,
        caller.auth.hash.as_str(),
        caller.arrival == Arrival::Cookie,
    ) {
        return Ok(());
    }
    ctx.audit()
        .record(
            AuditEvent::new(ctx.now(), "auth.reject.csrf")
                .subject(&caller.auth.subject)
                .target(caller.auth.hash.short()),
        )
        .await;
    Err(forbidden())
}

/// The request's full path, including any prefix a parent router stripped
/// when nesting.
#[must_use]
pub fn request_path(parts: &Parts) -> String {
    parts
        .extensions
        .get::<OriginalUri>()
        .map_or_else(|| parts.uri.path().to_owned(), |u| u.0.path().to_owned())
}

/// Which credential kinds a route accepts.
pub trait AllowedKinds: Send + Sync + 'static {
    /// The kinds, given the app's token format (for app kinds).
    fn allowed(ctx: &AuthContext) -> Vec<TokenKind>;
}

/// A user session only.
#[derive(Debug, Clone, Copy)]
pub struct SessionOnly;
impl AllowedKinds for SessionOnly {
    fn allowed(_: &AuthContext) -> Vec<TokenKind> {
        vec![TokenKind::Session]
    }
}

/// A user session or a workload token.
#[derive(Debug, Clone, Copy)]
pub struct SessionOrWorkload;
impl AllowedKinds for SessionOrWorkload {
    fn allowed(_: &AuthContext) -> Vec<TokenKind> {
        vec![TokenKind::Session, TokenKind::Workload]
    }
}

/// Any connection credential of the app's format (sessions, workloads, and
/// app connection kinds).
#[derive(Debug, Clone, Copy)]
pub struct AnyConnection;
impl AllowedKinds for AnyConnection {
    fn allowed(ctx: &AuthContext) -> Vec<TokenKind> {
        ctx.format()
            .kinds()
            .filter(|k| ctx.format().token_use(*k) == forgs::TokenUse::Connection)
            .collect()
    }
}

/// Which [`Carrier`] a route uses, as a type.
pub trait CarrierSpec: Send + Sync + 'static {
    /// The carrier.
    const CARRIER: Carrier;
}

/// [`Carrier::Header`].
#[derive(Debug, Clone, Copy)]
pub struct HeaderOnly;
impl CarrierSpec for HeaderOnly {
    const CARRIER: Carrier = Carrier::Header;
}

/// [`Carrier::ApiCookie`]: the app's cookie-capable API routes.
#[derive(Debug, Clone, Copy)]
pub struct ApiCookie;
impl CarrierSpec for ApiCookie {
    const CARRIER: Carrier = Carrier::ApiCookie;
}

/// [`Carrier::Cookie`]: explicitly marked browser routes.
#[derive(Debug, Clone, Copy)]
pub struct CookieOk;
impl CarrierSpec for CookieOk {
    const CARRIER: Carrier = Carrier::Cookie;
}

/// An authenticated caller, as an axum extractor.
///
/// `K` is the allowed kinds, `C` the carrier. For a cookie arrival on any
/// method but `GET`/`HEAD` the CSRF header is checked here, so the extractor
/// *is* the mutating-auth check and no handler can forget it.
pub struct Authenticated<K: AllowedKinds, C: CarrierSpec = HeaderOnly> {
    /// The caller.
    pub caller: Caller,
    _k: PhantomData<fn() -> (K, C)>,
}

impl<K: AllowedKinds, C: CarrierSpec> std::fmt::Debug for Authenticated<K, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticated")
            .field("caller", &self.caller)
            .finish()
    }
}

impl<K: AllowedKinds, C: CarrierSpec> std::ops::Deref for Authenticated<K, C> {
    type Target = Caller;
    fn deref(&self) -> &Caller {
        &self.caller
    }
}

impl<S, K, C> FromRequestParts<S> for Authenticated<K, C>
where
    AuthContext: FromRef<S>,
    S: Send + Sync,
    K: AllowedKinds,
    C: CarrierSpec,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ctx = AuthContext::from_ref(state);
        let path = request_path(parts);
        let caller =
            authenticate_request(&ctx, &parts.headers, &path, &K::allowed(&ctx), C::CARRIER)
                .await?;
        require_csrf(&ctx, &parts.method, &parts.headers, &caller).await?;
        Ok(Self {
            caller,
            _k: PhantomData,
        })
    }
}

/// Resolve a `namespace` field (an id, or a `/`-separated path) to a node id.
///
/// # Errors
///
/// [`ApiError::Forbidden`] if nothing matches — the same answer as "not a
/// member", so the endpoint is not a namespace-existence oracle.
pub async fn resolve_ns(ctx: &AuthContext, raw: &str) -> Result<forgs::NsNodeId, ApiError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(ApiError::BadRequest);
    }
    if let Ok(id) = forgs::NsNodeId::parse(raw) {
        if ctx
            .store()
            .node(id)
            .await
            .map_err(crate::error::store_err("node"))?
            .is_some()
        {
            return Ok(id);
        }
    }
    let segs: Vec<&str> = raw.trim_matches('/').split('/').collect();
    match ctx.store().node_by_path(&segs).await {
        Ok(Some(n)) => Ok(n.id),
        Ok(None) | Err(forgs_store::StoreError::Name(_)) => Err(ApiError::Forbidden),
        Err(e) => Err(e.into()),
    }
}

/// Convenience: turn an [`ApiError`] into its response.
#[must_use]
pub fn error_response(e: &ApiError) -> Response {
    e.clone().into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn bearer_parsing() {
        let mut h = HeaderMap::new();
        assert_eq!(bearer_of(&h), None);
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer  abc "),
        );
        assert_eq!(bearer_of(&h), Some("abc"));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("bearer x"));
        assert_eq!(bearer_of(&h), Some("x"));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic x"));
        assert_eq!(bearer_of(&h), None);
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer"));
        assert_eq!(bearer_of(&h), None);
    }
}
