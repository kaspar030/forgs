//! The axum [`router`]: thin adapters from HTTP to the framework-agnostic
//! service functions.
//!
//! | route | carrier | what |
//! |---|---|---|
//! | `GET /auth/providers` | — | configured provider names (JSON) |
//! | `GET /auth/login` | — | provider list (HTML) |
//! | `GET /auth/{provider}/start` | — | 302 to the provider, sets the flow cookie |
//! | `GET /auth/{provider}/callback` | cookie (flow) | session, or pending signup |
//! | `GET`/`POST /auth/signup` | cookie (ticket) | choose a username (HTML form or JSON) |
//! | `POST /auth/token` | body | `refresh`, `refresh_token`, `github_oidc`, `api_key` |
//! | `POST /auth/logout` | **header** | revoke session (+refresh, or `all`) |
//! | `POST /auth/session/logout` | cookie + CSRF | browser logout |
//! | `GET /auth/session` | header or cookie | whoami |
//! | `POST /auth/device/start`, `/poll` | body | the CLI's device flow |
//! | `GET`/`POST /auth/device` | cookie + CSRF | the browser verification page |
//! | `POST /auth/keys` | **header** | API keys |
//! | `POST /auth/identities/link/{provider}` | cookie + CSRF only (no bearer) | add a login method, after step-up re-auth |
//! | `GET /auth/identities` | header or cookie | the caller's login methods |
//! | `POST /auth/identities/unlink` | header, or cookie + CSRF | remove one (never the last) |
//! | `GET /auth/keys/ssh` | header or cookie | the caller's SSH public keys |
//! | `POST /auth/keys/ssh`, `/auth/keys/ssh/delete` | header, or cookie + CSRF | add / remove one |
//! | `POST /auth/members`, `/auth/rename` | **header** | membership, renames |
//! | `GET /auth/signups` | header or cookie | pending signups (JSON, approvers only) |
//! | `POST /auth/signups/approve`, `/reject` | header, or cookie + CSRF | decide one |
//! | `GET`/`POST /auth/signups/review` | cookie + CSRF | the browser review page |
//!
//! The JSON surface the CLI uses (`/auth/token`, `/auth/keys`,
//! `/auth/logout`, `/auth/members`, `/auth/rename`) refuses a cookie-only
//! request; only the explicitly marked browser routes read the session
//! cookie. No route emits CORS headers.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{FromRef, FromRequest, Path, RawQuery, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use forgs::api::{
    ApiKeyRequest, DevicePollRequest, DeviceStartRequest, LogoutRequest, MembersRequest,
    RenameRequest, SessionInfo, SignupDecisionRequest, SignupPendingResponse, SignupRequest,
    SshKeyAddRequest, SshKeyDeleteRequest, TokenRequest, UnlinkIdentityRequest,
};
use forgs::TokenKind;
use serde::de::DeserializeOwned;

use crate::auth::{
    authenticate_request, bearer_of, AnyConnection, Arrival, Authenticated, Caller, Carrier,
    CookieOk, SessionOnly,
};
use crate::context::AuthContext;
use crate::cookies::{
    clear_cookie, cleared_session_cookies, cookie_value, csrf_matches, csrf_token, redirect,
    session_cookies, set_cookie, with_cookies,
};
use crate::error::{reject, ApiError};
use crate::login::{safe_return_to, FlowIntent, LoginOutcome};
use crate::signup::SignupOutcome;
use crate::{
    device, html, identities, keys, login, members, session, signup, signups, ssh_keys, workload,
};

/// The auth routes, to be merged or nested into the app's router. Tell the
/// context where it is nested with [`crate::AuthContextBuilder::mount`].
pub fn router<S>() -> Router<S>
where
    AuthContext: FromRef<S>,
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/auth/providers", get(providers))
        .route("/auth/login", get(login_page))
        .route("/auth/signup", get(signup_page).post(signup_submit))
        .route("/auth/token", post(token))
        .route("/auth/logout", post(logout))
        .route("/auth/session", get(whoami))
        .route("/auth/session/logout", post(session_logout))
        .route("/auth/device/start", post(device_start))
        .route("/auth/device/poll", post(device_poll))
        .route("/auth/device", get(device_page).post(device_submit))
        .route("/auth/keys", post(api_keys))
        .route("/auth/keys/ssh", get(ssh_keys_list).post(ssh_keys_add))
        .route("/auth/keys/ssh/delete", post(ssh_keys_delete))
        .route("/auth/identities", get(identities_list))
        .route("/auth/identities/unlink", post(identities_unlink))
        .route("/auth/identities/link/{provider}", post(link_start))
        .route("/auth/members", post(members_route))
        .route("/auth/rename", post(rename))
        .route("/auth/signups", get(signups_list))
        .route("/auth/signups/approve", post(signups_approve))
        .route("/auth/signups/reject", post(signups_reject))
        .route(
            "/auth/signups/review",
            get(signups_review_page).post(signups_review_submit),
        )
        .route("/auth/{provider}/start", get(login_start))
        .route("/auth/{provider}/callback", get(login_callback))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A JSON body whose rejection is the uniform error shape rather than axum's
/// plain-text one.
pub struct JsonBody<T>(pub T);

impl<S, T> FromRequest<S> for JsonBody<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Self(v)),
            Err(e) => Err(reject(
                if e.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE {
                    StatusCode::UNSUPPORTED_MEDIA_TYPE
                } else {
                    StatusCode::BAD_REQUEST
                },
                forgs::api::error_code::INVALID_REQUEST,
            )),
        }
    }
}

fn query_map(q: Option<String>) -> HashMap<String, String> {
    q.and_then(|q| serde_urlencoded::from_str(&q).ok())
        .unwrap_or_default()
}

fn form_map(body: &[u8]) -> HashMap<String, String> {
    serde_urlencoded::from_bytes(body).unwrap_or_default()
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim_start().starts_with("application/json"))
}

/// For a browser POST that is not otherwise CSRF-protected (no session yet):
/// refuse a cross-origin `Origin` or `Sec-Fetch-Site: cross-site`.
///
/// `Origin: null` (an opaque origin, e.g. from a document with a
/// `no-referrer` policy or a privacy setting) is accepted only when the
/// browser's own fetch metadata says `Sec-Fetch-Site: same-origin`; pages
/// cannot forge that header. A missing `Origin` is held to the same rule
/// unless `allow_missing` — for a request that carries no ambient
/// credential (its secret is in the body, not a cookie), where a missing
/// `Origin` is just a non-browser client.
fn same_origin(ctx: &AuthContext, headers: &HeaderMap, allow_missing: bool) -> bool {
    let site = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok());
    if site.is_some_and(|v| v.eq_ignore_ascii_case("cross-site")) {
        return false;
    }
    let same_origin_site = site.is_some_and(|s| s.eq_ignore_ascii_case("same-origin"));
    match headers.get(header::ORIGIN) {
        None => allow_missing || same_origin_site,
        Some(v) => match v.to_str() {
            Ok("null") => same_origin_site,
            Ok(o) => o == ctx.public_origin(),
            Err(_) => false,
        },
    }
}

/// The browser's session, if it presents one that resolves. Silent when it
/// presents none (an anonymous page view is not a rejection worth auditing).
async fn optional_caller(ctx: &AuthContext, headers: &HeaderMap) -> Option<Caller> {
    if bearer_of(headers).is_none() && cookie_value(headers, &ctx.cookies().session).is_none() {
        return None;
    }
    authenticate_request(ctx, headers, "", &[TokenKind::Session], Carrier::Cookie)
        .await
        .ok()
}

/// Authenticate a no-JS form POST: session by header or cookie, and for a
/// cookie arrival the CSRF token from the header **or** the `csrf` field.
// `Response` is axum's native rejection type (see `FromRequestParts::Rejection`);
// boxing it would only add unboxing at every call site on the error path.
#[allow(clippy::result_large_err)]
async fn form_caller(
    ctx: &AuthContext,
    headers: &HeaderMap,
    form_csrf: Option<&str>,
) -> Result<Caller, Response> {
    let caller =
        authenticate_request(ctx, headers, "", &[TokenKind::Session], Carrier::Cookie).await?;
    if caller.arrival == Arrival::Cookie {
        let offered = headers
            .get(ctx.csrf_header())
            .and_then(|v| v.to_str().ok())
            .or(form_csrf)
            .unwrap_or("");
        if !csrf_matches(ctx, caller.auth.hash.as_str(), offered) {
            ctx.audit()
                .record(
                    crate::audit::AuditEvent::new(ctx.now(), "auth.reject.csrf")
                        .subject(&caller.auth.subject)
                        .target(caller.auth.hash.short()),
                )
                .await;
            return Err(reject(
                StatusCode::FORBIDDEN,
                forgs::api::error_code::FORBIDDEN,
            ));
        }
    }
    Ok(caller)
}

fn landing(ctx: &AuthContext, return_to: Option<&str>) -> String {
    return_to
        .and_then(safe_return_to)
        .unwrap_or(ctx.post_login_redirect())
        .to_owned()
}

fn error_page(e: &ApiError) -> Response {
    let text = match e {
        ApiError::BadRequest => "This login link is invalid or has expired. Please start again.",
        ApiError::Forbidden => "This account cannot log in.",
        e if *e == ApiError::NO_VERIFIED_EMAIL => {
            "The provider did not confirm a verified email address. Verify an email address \
             with the provider (and make it your primary one), then try again."
        }
        e if *e == ApiError::IDENTITY_TAKEN => "That login is already linked to an account.",
        e if *e == ApiError::UNKNOWN_PROVIDER => "Unknown login provider.",
        e if *e == ApiError::UPSTREAM => "The login provider could not complete the login.",
        e if *e == ApiError::SIGNUP_CLOSED => {
            "This server does not accept new signups. Ask an administrator for an account."
        }
        e if *e == ApiError::REAUTH_REQUIRED => {
            "To add a login method, confirm it's you by logging in with a method already linked \
             to this account."
        }
        _ => "Something went wrong. Please try again.",
    };
    html::message(e.status(), "Login failed", text)
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

async fn providers(State(ctx): State<AuthContext>) -> Response {
    let names: Vec<&str> = ctx.providers().iter().map(|p| p.name()).collect();
    Json(serde_json::json!({ "providers": names })).into_response()
}

fn login_links(ctx: &AuthContext, return_to: Option<&str>, lead: &str) -> Response {
    let names: Vec<&str> = ctx.providers().iter().map(|p| p.name()).collect();
    let rt = return_to.and_then(safe_return_to);
    html::login(
        &names,
        |n| {
            let base = ctx.path(&format!("/auth/{n}/start"));
            match rt {
                Some(rt) => format!("{base}?return_to={}", forgs_idp::url::percent_encode(rt)),
                None => base,
            }
        },
        lead,
    )
}

async fn login_page(State(ctx): State<AuthContext>, RawQuery(q): RawQuery) -> Response {
    let q = query_map(q);
    login_links(
        &ctx,
        q.get("return_to").map(String::as_str),
        "Choose how to log in.",
    )
}

/// `GET /auth/{provider}/start`. The request's `Host` is never consulted:
/// the `redirect_uri` comes from `public_url` alone.
async fn login_start(
    State(ctx): State<AuthContext>,
    Path(provider): Path<String>,
    RawQuery(q): RawQuery,
) -> Response {
    let q = query_map(q);
    match login::start_login(
        &ctx,
        &provider,
        q.get("return_to").map(String::as_str),
        &FlowIntent::Login,
    ) {
        Ok(started) => redirect(
            &started.authorize_url,
            &[set_cookie(
                &ctx.cookies().oauth,
                &started.cookie,
                ctx.ttl().login_flow,
                true,
            )],
            false,
        ),
        Err(e) => error_page(&e),
    }
}

/// `GET /auth/{provider}/callback?code&state`.
async fn login_callback(
    State(ctx): State<AuthContext>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> Response {
    let q = query_map(q);
    // Cleared first, whatever happens: a `state` is single-use, and a
    // replayed callback finds no cookie.
    let spent = clear_cookie(&ctx.cookies().oauth, true);
    let previous = optional_caller(&ctx, &headers).await;
    let outcome = login::complete_login(
        &ctx,
        &provider,
        q.get("code").map_or("", String::as_str),
        q.get("state").map_or("", String::as_str),
        cookie_value(&headers, &ctx.cookies().oauth),
        // Only the browser's own session cookie counts as "logged in here": a
        // bearer header never continues a reauth or link leg.
        previous
            .as_ref()
            .filter(|c| c.arrival == Arrival::Cookie)
            .and_then(Caller::user_id),
    )
    .await;
    match outcome {
        Ok(LoginOutcome::Session {
            session, return_to, ..
        }) => {
            // The browser's previous session is replaced by this one: end it
            // rather than leave a live credential nobody holds any more.
            // Best effort — the new login stands either way.
            if let Some(prev) = previous.filter(|c| c.arrival == Arrival::Cookie) {
                let _ = ctx.store().delete_session(&prev.auth.hash).await;
            }
            let mut cookies = vec![spent];
            cookies.extend(session_cookies(&ctx, &session.token, session.expires));
            redirect(&landing(&ctx, return_to.as_deref()), &cookies, false)
        }
        Ok(LoginOutcome::NeedsSignup { ticket_cookie, .. }) => redirect(
            &ctx.path("/auth/signup"),
            &[
                spent,
                set_cookie(
                    &ctx.cookies().signup,
                    &ticket_cookie,
                    ctx.ttl().pending_signup,
                    true,
                ),
            ],
            false,
        ),
        // Waiting for approval: no session; the browser's previous one (if
        // any) is left alone.
        Ok(LoginOutcome::Pending { .. }) => with_cookies(html::pending_approval(), &[spent]),
        Ok(LoginOutcome::Linked { return_to, .. }) => {
            redirect(&landing(&ctx, return_to.as_deref()), &[spent], false)
        }
        // Step-up done: on to the provider being linked. The new flow cookie
        // replaces the spent one (one Set-Cookie per name, never both).
        Ok(LoginOutcome::Reauthenticated { started }) => redirect(
            &started.authorize_url,
            &[set_cookie(
                &ctx.cookies().oauth,
                &started.cookie,
                ctx.ttl().login_flow,
                true,
            )],
            false,
        ),
        Err(e) => with_cookies(error_page(&e), &[spent]),
    }
}

/// `POST /auth/identities/link/{provider}` — "add a login method": only from
/// an authenticated **browser** session (cookie + CSRF; a bearer token is
/// refused), and only after step-up re-authentication with an identity
/// already linked to the user (see [`crate::login`]). The form field `via`
/// may name which linked provider to re-authenticate with; by default it is
/// the one used most recently.
async fn link_start(
    State(ctx): State<AuthContext>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = form_map(&body);
    let caller = match form_caller(&ctx, &headers, form.get("csrf").map(String::as_str)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if caller.arrival != Arrival::Cookie {
        ctx.audit()
            .record(
                crate::audit::AuditEvent::new(ctx.now(), "identity.link.refused")
                    .subject(&caller.auth.subject)
                    .target(provider.clone())
                    .detail("bearer"),
            )
            .await;
        return ApiError::Forbidden.into_response();
    }
    let Some(user) = caller.user_id() else {
        return ApiError::Forbidden.into_response();
    };
    if ctx.provider(&provider).is_none() {
        return ApiError::UNKNOWN_PROVIDER.into_response();
    }
    let linked = match ctx.store().identities_for_user(user).await {
        Ok(l) => l,
        Err(e) => return crate::error::store_err("identities_for_user")(e).into_response(),
    };
    let usable = |p: &str| linked.iter().any(|i| i.provider == p) && ctx.provider(p).is_some();
    let via = match form.get("via").map(String::as_str) {
        Some(v) if usable(v) => Some(v.to_owned()),
        _ => linked
            .iter()
            .filter(|i| ctx.provider(&i.provider).is_some())
            .max_by_key(|i| (i.last_login_at.unwrap_or(i.linked_at), i.linked_at))
            .map(|i| i.provider.clone()),
    };
    let Some(via) = via else {
        return ApiError::REAUTH_REQUIRED.into_response();
    };
    match login::start_login(
        &ctx,
        &via,
        form.get("return_to").map(String::as_str),
        &FlowIntent::Reauth {
            user,
            link_provider: provider,
        },
    ) {
        Ok(started) => redirect(
            &started.authorize_url,
            &[set_cookie(
                &ctx.cookies().oauth,
                &started.cookie,
                ctx.ttl().login_flow,
                true,
            )],
            true,
        ),
        Err(e) => e.into_response(),
    }
}

/// `GET /auth/identities` — the caller's linked login methods.
async fn identities_list(
    State(ctx): State<AuthContext>,
    auth: Authenticated<SessionOnly, CookieOk>,
) -> Response {
    match identities::list(&ctx, &auth).await {
        Ok(l) => Json(l).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /auth/identities/unlink` — remove one (CSRF-checked for a cookie).
async fn identities_unlink(
    State(ctx): State<AuthContext>,
    auth: Authenticated<SessionOnly, CookieOk>,
    JsonBody(req): JsonBody<UnlinkIdentityRequest>,
) -> Response {
    match identities::unlink(&ctx, &auth, &req).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /auth/keys/ssh` — the caller's SSH public keys.
async fn ssh_keys_list(
    State(ctx): State<AuthContext>,
    auth: Authenticated<SessionOnly, CookieOk>,
) -> Response {
    match ssh_keys::list(&ctx, &auth).await {
        Ok(l) => Json(l).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /auth/keys/ssh` — register one (CSRF-checked for a cookie).
async fn ssh_keys_add(
    State(ctx): State<AuthContext>,
    auth: Authenticated<SessionOnly, CookieOk>,
    JsonBody(req): JsonBody<SshKeyAddRequest>,
) -> Response {
    match ssh_keys::add(&ctx, &auth, &req).await {
        Ok(k) => (StatusCode::CREATED, Json(k)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /auth/keys/ssh/delete` — remove one (CSRF-checked for a cookie).
async fn ssh_keys_delete(
    State(ctx): State<AuthContext>,
    auth: Authenticated<SessionOnly, CookieOk>,
    JsonBody(req): JsonBody<SshKeyDeleteRequest>,
) -> Response {
    match ssh_keys::delete(&ctx, &auth, &req).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Signup
// ---------------------------------------------------------------------------

async fn signup_page(State(ctx): State<AuthContext>, headers: HeaderMap) -> Response {
    let expired = || {
        html::page(
            StatusCode::GONE,
            "Login expired",
            &format!(
                "<p>This signup has expired. <a href=\"{}\">Log in again</a>.</p>",
                html::escape(&ctx.path("/auth/login"))
            ),
        )
    };
    let Some(ticket) =
        cookie_value(&headers, &ctx.cookies().signup).and_then(|c| signup::open_ticket(&ctx, c))
    else {
        return expired();
    };
    let Ok(p) = signup::pending(&ctx, ticket.id).await else {
        return expired();
    };
    let suggestion = p
        .suggested_username
        .as_deref()
        .and_then(|s| ctx.store().schema().validate_username(s).ok())
        .unwrap_or_default();
    html::signup(&ctx.path("/auth/signup"), &suggestion, None, StatusCode::OK)
}

fn signup_error_text(e: &ApiError) -> &'static str {
    if *e == ApiError::USERNAME_TAKEN {
        "That username is taken. Choose another."
    } else if *e == ApiError::USERNAME_INVALID {
        "That username is not allowed. Use letters, digits and single hyphens."
    } else if *e == ApiError::EMAIL_IN_USE {
        "An account already uses this email address. Log in with that account's existing \
         method, then add this login method from there."
    } else {
        "Something went wrong. Please try again."
    }
}

/// `POST /auth/signup`: a JSON [`SignupRequest`] (ticket = the signup
/// cookie's value, or empty to use the cookie) or the HTML form.
async fn signup_submit(
    State(ctx): State<AuthContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // No session exists yet, so there is no CSRF token to check; the ticket
    // cookie is `SameSite=Lax` (not sent on a cross-site POST) and the origin
    // is checked on top. A foreign origin is refused outright; a missing one
    // only when the ticket comes from the cookie (an ambient credential).
    if !same_origin(&ctx, &headers, true) {
        return ApiError::Forbidden.into_response();
    }
    let json = is_json(&headers);
    let (sealed, username, from_cookie) = if json {
        let Ok(req) = serde_json::from_slice::<SignupRequest>(&body) else {
            return ApiError::BadRequest.into_response();
        };
        if req.ticket.is_empty() {
            let sealed = cookie_value(&headers, &ctx.cookies().signup).map(str::to_owned);
            (sealed, req.username, true)
        } else {
            (Some(req.ticket), req.username, false)
        }
    } else {
        let form = form_map(&body);
        (
            cookie_value(&headers, &ctx.cookies().signup).map(str::to_owned),
            form.get("username").cloned().unwrap_or_default(),
            true,
        )
    };
    if from_cookie && !same_origin(&ctx, &headers, false) {
        return ApiError::Forbidden.into_response();
    }
    let Some(ticket) = sealed.and_then(|s| signup::open_ticket(&ctx, &s)) else {
        return if json {
            ApiError::TICKET_EXPIRED.into_response()
        } else {
            html::message(
                StatusCode::GONE,
                "Login expired",
                "This signup has expired. Please log in again.",
            )
        };
    };
    match signup::signup(&ctx, ticket.id, &username).await {
        Ok(SignupOutcome::Pending(user)) => {
            let cookies = [clear_cookie(&ctx.cookies().signup, true)];
            if json {
                let body = SignupPendingResponse {
                    status: "pending".to_owned(),
                    user_id: user.to_string(),
                    username: session::username_of(&ctx, user).await.unwrap_or_default(),
                };
                with_cookies((StatusCode::ACCEPTED, Json(body)).into_response(), &cookies)
            } else {
                with_cookies(html::pending_approval(), &cookies)
            }
        }
        Ok(SignupOutcome::Session(user, s)) => {
            let mut cookies = vec![clear_cookie(&ctx.cookies().signup, true)];
            cookies.extend(session_cookies(&ctx, &s.token, s.expires));
            if json {
                let info = SessionInfo {
                    subject: forgs::SubjectKey::user(user).to_string(),
                    user_id: Some(user.to_string()),
                    username: session::username_of(&ctx, user).await,
                    expires: Some(s.expires),
                    memberships: Vec::new(),
                };
                with_cookies(Json(info).into_response(), &cookies)
            } else {
                redirect(&landing(&ctx, ticket.return_to.as_deref()), &cookies, true)
            }
        }
        Err(e) if json => e.into_response(),
        Err(e) if e == ApiError::SIGNUP_CLOSED => html::message(
            e.status(),
            "Signups are closed",
            "This server does not accept new signups. Ask an administrator for an account.",
        ),
        Err(e) if e == ApiError::TICKET_EXPIRED => html::message(
            StatusCode::GONE,
            "Login expired",
            "This signup has expired. Please log in again.",
        ),
        Err(e) => html::signup(
            &ctx.path("/auth/signup"),
            &username,
            Some(signup_error_text(&e)),
            e.status(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Tokens and sessions
// ---------------------------------------------------------------------------

async fn token(State(ctx): State<AuthContext>, JsonBody(req): JsonBody<TokenRequest>) -> Response {
    let res = match req {
        TokenRequest::Refresh { session_token } => {
            session::refresh_session(&ctx, &session_token).await
        }
        TokenRequest::RefreshToken { refresh_token } => {
            session::redeem_refresh_token(&ctx, &refresh_token).await
        }
        TokenRequest::GithubOidc { oidc_token } => workload::exchange_oidc(&ctx, &oidc_token).await,
        TokenRequest::ApiKey { api_key } => workload::exchange_api_key(&ctx, &api_key).await,
    };
    match res {
        Ok(r) => Json(r).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn logout(
    State(ctx): State<AuthContext>,
    auth: Authenticated<SessionOnly>,
    JsonBody(req): JsonBody<LogoutRequest>,
) -> Response {
    match session::logout(&ctx, &auth, &req).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

async fn whoami(
    State(ctx): State<AuthContext>,
    auth: Authenticated<AnyConnection, CookieOk>,
) -> Response {
    match members::whoami(&ctx, &auth).await {
        Ok(i) => Json(i).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /auth/session/logout` — browser logout (never holds a refresh
/// token). Clears the cookies and redirects a form; `204` for a script.
async fn session_logout(
    State(ctx): State<AuthContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = if is_json(&headers) {
        HashMap::new()
    } else {
        form_map(&body)
    };
    let caller = match form_caller(&ctx, &headers, form.get("csrf").map(String::as_str)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(e) = session::logout(&ctx, &caller, &LogoutRequest::default()).await {
        return e.into_response();
    }
    // Also any half-finished login or signup: an abandoned signup ticket
    // must not stay usable on a shared machine after its user logs out.
    let mut cookies = cleared_session_cookies(&ctx);
    cookies.push(clear_cookie(&ctx.cookies().oauth, true));
    cookies.push(clear_cookie(&ctx.cookies().signup, true));
    if form.contains_key("csrf") {
        redirect(ctx.post_login_redirect(), &cookies, true)
    } else {
        with_cookies(StatusCode::NO_CONTENT.into_response(), &cookies)
    }
}

// ---------------------------------------------------------------------------
// Device flow
// ---------------------------------------------------------------------------

async fn device_start(
    State(ctx): State<AuthContext>,
    headers: HeaderMap,
    ext: axum::http::Extensions,
    JsonBody(_req): JsonBody<DeviceStartRequest>,
) -> Response {
    let source = ctx.client_ip(&headers, &ext);
    match device::start(&ctx, None, source).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn device_poll(
    State(ctx): State<AuthContext>,
    JsonBody(req): JsonBody<DevicePollRequest>,
) -> Response {
    match device::poll(&ctx, &req.device_secret).await {
        Ok(device::PollOutcome::Login(r)) => Json(r).into_response(),
        Ok(device::PollOutcome::App(v)) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /auth/device`. Any `?code=` is ignored: the page never pre-fills a
/// code, so a phished link cannot reduce approval to one click. The user
/// types the code their device shows, reviews when and where it asked, and
/// only then approves, each step a CSRF-checked POST.
async fn device_page(State(ctx): State<AuthContext>, headers: HeaderMap) -> Response {
    let Some(caller) = optional_caller(&ctx, &headers).await else {
        return login_links(
            &ctx,
            Some(&ctx.path("/auth/device")),
            "Log in to confirm the device. You will come back here afterwards.",
        );
    };
    let username = match caller.user_id() {
        Some(u) => session::username_of(&ctx, u).await.unwrap_or_default(),
        None => String::new(),
    };
    html::device_form(
        &ctx.path("/auth/device"),
        &username,
        &csrf_token(&ctx, caller.auth.hash.as_str()),
    )
}

fn device_error(e: &ApiError) -> Response {
    let text = match e {
        ApiError::BadRequest => "That is not a valid code.",
        ApiError::NotFound => {
            "No pending device login has that code. It may have expired or already been used."
        }
        _ if *e == ApiError::RATE_LIMITED => "Too many wrong codes. Try again later.",
        _ => "Something went wrong. Please try again.",
    };
    html::message(e.status(), "Device login", text)
}

/// `POST /auth/device`: `action=review` shows the device's details,
/// `approve` / `deny` decide (a deny also cancels the user's own
/// not-yet-redeemed approval).
async fn device_submit(
    State(ctx): State<AuthContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = form_map(&body);
    let csrf = form.get("csrf").map(String::as_str);
    let caller = match form_caller(&ctx, &headers, csrf).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(user) = caller.user_id() else {
        return ApiError::Forbidden.into_response();
    };
    let code = form.get("code").map_or("", String::as_str);
    let csrf = csrf.unwrap_or_default();
    let action = ctx.path("/auth/device");
    let approve = match form.get("action").map(String::as_str) {
        Some("review") => {
            return match device::review(&ctx, user, code).await {
                Ok(info) => {
                    let username = session::username_of(&ctx, user).await.unwrap_or_default();
                    html::device_confirm(&action, &username, &info, csrf)
                }
                Err(e) => device_error(&e),
            };
        }
        Some("approve") => true,
        Some("deny") => false,
        _ => {
            return html::message(
                StatusCode::BAD_REQUEST,
                "Device login",
                "Choose approve or deny.",
            )
        }
    };
    match device::decide(&ctx, user, code, None, approve).await {
        Ok(()) if approve => html::device_approved(&action, code, csrf),
        Ok(()) => html::message(
            StatusCode::OK,
            "Device denied",
            "The device login was denied.",
        ),
        Err(e) => device_error(&e),
    }
}

// ---------------------------------------------------------------------------
// Keys, members, renames
// ---------------------------------------------------------------------------

async fn api_keys(
    State(ctx): State<AuthContext>,
    auth: Authenticated<SessionOnly>,
    JsonBody(req): JsonBody<ApiKeyRequest>,
) -> Response {
    let user = match auth.require_user() {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let res = match req {
        ApiKeyRequest::Create {
            namespace,
            ttl_secs,
            multi_use,
            purpose,
            subject_name,
            payload,
        } => keys::create(
            &ctx,
            user,
            &namespace,
            ttl_secs,
            multi_use,
            &purpose,
            subject_name.as_deref(),
            payload.as_ref(),
        )
        .await
        .map(|v| Json(v).into_response()),
        ApiKeyRequest::List {
            namespace,
            before,
            limit,
        } => keys::list(&ctx, user, &namespace, before.as_deref(), limit)
            .await
            .map(|v| Json(v).into_response()),
        ApiKeyRequest::Revoke { namespace, prefix } => {
            keys::revoke(&ctx, user, &namespace, &prefix)
                .await
                .map(|v| Json(v).into_response())
        }
    };
    res.unwrap_or_else(IntoResponse::into_response)
}

async fn members_route(
    State(ctx): State<AuthContext>,
    auth: Authenticated<SessionOnly>,
    JsonBody(req): JsonBody<MembersRequest>,
) -> Response {
    let user = match auth.require_user() {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let res = match req {
        MembersRequest::List {
            namespace,
            after,
            limit,
        } => members::list(&ctx, user, &namespace, after.as_deref(), limit)
            .await
            .map(|v| Json(v).into_response()),
        MembersRequest::Set {
            namespace,
            username,
            role,
        } => members::set(&ctx, user, &namespace, &username, &role)
            .await
            .map(|()| StatusCode::NO_CONTENT.into_response()),
        MembersRequest::Remove {
            namespace,
            username,
        } => members::remove(&ctx, user, &namespace, &username)
            .await
            .map(|()| StatusCode::NO_CONTENT.into_response()),
    };
    res.unwrap_or_else(IntoResponse::into_response)
}

async fn rename(
    State(ctx): State<AuthContext>,
    auth: Authenticated<SessionOnly>,
    JsonBody(req): JsonBody<RenameRequest>,
) -> Response {
    let user = match auth.require_user() {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let res = match req {
        RenameRequest::User { new_username } => {
            members::rename_user(&ctx, user, &new_username).await
        }
        RenameRequest::Namespace {
            namespace,
            new_name,
        } => members::rename_namespace(&ctx, user, &namespace, &new_name).await,
    };
    match res {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Signup approval
// ---------------------------------------------------------------------------

/// `GET /auth/signups?limit&after` — pending signups (approvers only).
async fn signups_list(
    State(ctx): State<AuthContext>,
    auth: Authenticated<SessionOnly, CookieOk>,
    RawQuery(q): RawQuery,
) -> Response {
    let user = match auth.require_user() {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let q = query_map(q);
    let Ok(limit) = q.get("limit").map(|l| l.parse::<u32>()).transpose() else {
        return ApiError::BadRequest.into_response();
    };
    match signups::list(&ctx, user, q.get("after").map(String::as_str), limit).await {
        Ok(l) => Json(l).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /auth/signups/approve` (CSRF-checked for a cookie).
async fn signups_approve(
    State(ctx): State<AuthContext>,
    auth: Authenticated<SessionOnly, CookieOk>,
    JsonBody(req): JsonBody<SignupDecisionRequest>,
) -> Response {
    let res = match auth.require_user() {
        Ok(u) => signups::approve(&ctx, u, &req.user_id).await,
        Err(e) => Err(e),
    };
    match res {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /auth/signups/reject` (CSRF-checked for a cookie).
async fn signups_reject(
    State(ctx): State<AuthContext>,
    auth: Authenticated<SessionOnly, CookieOk>,
    JsonBody(req): JsonBody<SignupDecisionRequest>,
) -> Response {
    let res = match auth.require_user() {
        Ok(u) => signups::reject(&ctx, u, &req.user_id).await,
        Err(e) => Err(e),
    };
    match res {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

fn signups_error(e: &ApiError) -> Response {
    let text = match e {
        ApiError::Forbidden => "You are not allowed to review signups.",
        ApiError::NotFound => "That signup is no longer waiting for approval.",
        e if *e == ApiError::CONFLICT => {
            "That account cannot be rejected: something was already created in its namespace."
        }
        _ => "Something went wrong. Please try again.",
    };
    html::message(e.status(), "Pending signups", text)
}

async fn render_review(ctx: &AuthContext, caller: &Caller, notice: Option<&str>) -> Response {
    let Some(user) = caller.user_id() else {
        return signups_error(&ApiError::Forbidden);
    };
    match signups::list(ctx, user, None, None).await {
        Ok(l) => html::signup_review(
            &ctx.path("/auth/signups/review"),
            &csrf_token(ctx, caller.auth.hash.as_str()),
            &l.users,
            notice,
        ),
        Err(e) => signups_error(&e),
    }
}

/// `GET /auth/signups/review` — the browser page listing pending signups.
async fn signups_review_page(State(ctx): State<AuthContext>, headers: HeaderMap) -> Response {
    let Some(caller) = optional_caller(&ctx, &headers).await else {
        return login_links(
            &ctx,
            Some(&ctx.path("/auth/signups/review")),
            "Log in to review pending signups. You will come back here afterwards.",
        );
    };
    render_review(&ctx, &caller, None).await
}

/// `POST /auth/signups/review`: `user_id` and `action=approve|reject`.
async fn signups_review_submit(
    State(ctx): State<AuthContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let form = form_map(&body);
    let caller = match form_caller(&ctx, &headers, form.get("csrf").map(String::as_str)).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(user) = caller.user_id() else {
        return signups_error(&ApiError::Forbidden);
    };
    let target = form.get("user_id").map_or("", String::as_str);
    let (res, done) = match form.get("action").map(String::as_str) {
        Some("approve") => (signups::approve(&ctx, user, target).await, "Approved."),
        Some("reject") => (signups::reject(&ctx, user, target).await, "Rejected."),
        _ => {
            return html::message(
                StatusCode::BAD_REQUEST,
                "Pending signups",
                "Choose approve or reject.",
            )
        }
    };
    match res {
        Ok(()) => render_review(&ctx, &caller, Some(done)).await,
        Err(e) => signups_error(&e),
    }
}
