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
//! | `POST /auth/identities/link/{provider}` | cookie + CSRF | add a login method |
//! | `POST /auth/members`, `/auth/rename` | **header** | membership, renames |
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
    RenameRequest, SessionInfo, SignupRequest, TokenRequest,
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
use crate::login::{safe_return_to, LoginOutcome};
use crate::{device, html, keys, login, members, session, signup, workload};

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
        .route("/auth/identities/link/{provider}", post(link_start))
        .route("/auth/members", post(members_route))
        .route("/auth/rename", post(rename))
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
fn same_origin(ctx: &AuthContext, headers: &HeaderMap) -> bool {
    if headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("cross-site"))
    {
        return false;
    }
    match headers.get(header::ORIGIN) {
        None => true,
        Some(v) => v.to_str().ok() == Some(ctx.public_origin()),
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
        None,
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
    let current = optional_caller(&ctx, &headers)
        .await
        .and_then(|c| c.user_id());
    let outcome = login::complete_login(
        &ctx,
        &provider,
        q.get("code").map_or("", String::as_str),
        q.get("state").map_or("", String::as_str),
        cookie_value(&headers, &ctx.cookies().oauth),
        current,
    )
    .await;
    match outcome {
        Ok(LoginOutcome::Session {
            session, return_to, ..
        }) => {
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
        Ok(LoginOutcome::Linked { return_to, .. }) => {
            redirect(&landing(&ctx, return_to.as_deref()), &[spent], false)
        }
        Err(e) => with_cookies(error_page(&e), &[spent]),
    }
}

/// `POST /auth/identities/link/{provider}` — "add a login method", only
/// from an authenticated session (CSRF-checked).
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
    let Some(user) = caller.user_id() else {
        return ApiError::Forbidden.into_response();
    };
    match login::start_login(
        &ctx,
        &provider,
        form.get("return_to").map(String::as_str),
        Some(user),
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
    // is checked on top.
    if !same_origin(&ctx, &headers) {
        return ApiError::Forbidden.into_response();
    }
    let json = is_json(&headers);
    let (sealed, username) = if json {
        let Ok(req) = serde_json::from_slice::<SignupRequest>(&body) else {
            return ApiError::BadRequest.into_response();
        };
        let sealed = if req.ticket.is_empty() {
            cookie_value(&headers, &ctx.cookies().signup).map(str::to_owned)
        } else {
            Some(req.ticket)
        };
        (sealed, req.username)
    } else {
        let form = form_map(&body);
        (
            cookie_value(&headers, &ctx.cookies().signup).map(str::to_owned),
            form.get("username").cloned().unwrap_or_default(),
        )
    };
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
        Ok((user, s)) => {
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
    let cookies = cleared_session_cookies(&ctx);
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
    JsonBody(_req): JsonBody<DeviceStartRequest>,
) -> Response {
    match device::start(&ctx, None, None).await {
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

/// `GET /auth/device[?code=…]`. The code is only reflected after
/// normalisation (so only the code alphabet can appear), and only pre-fills
/// the form: approval always takes an explicit, CSRF-checked POST.
async fn device_page(
    State(ctx): State<AuthContext>,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> Response {
    let q = query_map(q);
    let code = q
        .get("code")
        .and_then(|c| forgs::user_code::normalise(c))
        .map(|c| forgs::user_code::display(&c))
        .unwrap_or_default();
    let Some(caller) = optional_caller(&ctx, &headers).await else {
        let here = if code.is_empty() {
            ctx.path("/auth/device")
        } else {
            ctx.path(&format!("/auth/device?code={code}"))
        };
        return login_links(
            &ctx,
            Some(&here),
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
        &code,
        &csrf_token(&ctx, caller.auth.hash.as_str()),
    )
}

async fn device_submit(
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
        return ApiError::Forbidden.into_response();
    };
    let approve = match form.get("action").map(String::as_str) {
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
    let code = form.get("code").map_or("", String::as_str);
    match device::decide(&ctx, user, code, None, approve).await {
        Ok(()) if approve => html::message(
            StatusCode::OK,
            "Device approved",
            "The device is now logged in. You can return to your terminal.",
        ),
        Ok(()) => html::message(
            StatusCode::OK,
            "Device denied",
            "The device login was denied.",
        ),
        Err(e) => {
            let text = match e {
                ApiError::BadRequest => "That is not a valid code.",
                ApiError::NotFound => "No pending device login has that code. It may have expired.",
                _ if e == ApiError::CONFLICT => "That code was already used.",
                _ => "Something went wrong. Please try again.",
            };
            html::message(e.status(), "Device login", text)
        }
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
        ApiKeyRequest::List { namespace } => keys::list(&ctx, user, &namespace)
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
        MembersRequest::List { namespace } => members::list(&ctx, user, &namespace)
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
