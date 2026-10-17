//! forgs as its own device authorization server (docs/design.md §4), and the
//! generic pending-approval machine apps reuse (framework-agnostic).
//!
//! ```text
//! CLI  POST /auth/device/start → { device_secret, user_code, verification_uri }
//! user opens verification_uri → logs in with ANY provider (incl. first-login
//!      username choice) → confirms the user code
//! CLI  POST /auth/device/poll { device_secret } → pending | session + refresh
//! ```
//!
//! This makes CLI login provider-agnostic. The poll is keyed by the device
//! secret (a redeem-only token, stored as a hash), the human side by the
//! short user code. The single atomic consume in the store is the guard that
//! a credential is minted at most once however many polls race; every check
//! before it is a courtesy that lets the poll report *why*.
//!
//! # Accepted risks, recorded rather than fixed
//!
//! * **Remote phishing** (RFC 8628 §5.4): an attacker starts a flow and
//!   talks a victim into confirming the code. Inherent to every device
//!   flow. The verification page makes the user type or confirm the code
//!   after logging in, and never approves from a link alone.
//! * **Unauthenticated growth**: `start` writes a row. The live set is
//!   capped (`max_pending_devices`) and rows expire; a full table denies new
//!   logins until rows age out.

use forgs::api::{DevicePollResponse, DeviceStartResponse, TokenResponse};
use forgs::{NsNodeId, TokenKind, UserId};

use crate::audit::AuditEvent;
use crate::context::AuthContext;
use crate::error::{store_err, ApiError};
use crate::session::{mint_refresh, mint_session, username_of};

/// Begin a device flow. `payload` is `None` for a CLI login; an app passes
/// its own JSON to start a generic pending approval (see
/// [`crate::PendingApprovalHook`]). `source_ip` is advisory (behind a proxy
/// it is the proxy's).
///
/// # Errors
///
/// [`ApiError::UNAVAILABLE`] when the live set is full, `500` on storage
/// failure.
pub async fn start(
    ctx: &AuthContext,
    payload: Option<&str>,
    source_ip: Option<&str>,
) -> Result<DeviceStartResponse, ApiError> {
    let now = ctx.now();
    let live = ctx
        .store()
        .live_pending_device_count(now)
        .await
        .map_err(store_err("live_pending_device_count"))?;
    if live >= ctx.inner.max_pending_devices {
        tracing::warn!(live, "device flow refused: too many live approvals");
        return Err(ApiError::UNAVAILABLE);
    }
    let secret = ctx.format().mint(TokenKind::DeviceSecret);
    let ttl = ctx.ttl().device_flow;
    let (_id, code) = ctx
        .store()
        .insert_pending_device(
            forgs::user_code::generate,
            &secret.hash(),
            payload,
            source_ip,
            now,
            now.saturating_add(ttl),
        )
        .await
        .map_err(store_err("insert_pending_device"))?;
    let display = forgs::user_code::display(&code);
    ctx.audit()
        .record(
            AuditEvent::new(now, "device.start")
                .target(secret.hash().short())
                .detail(if payload.is_some() {
                    "app approval"
                } else {
                    "login"
                }),
        )
        .await;
    let verification_uri = ctx.absolute("/auth/device");
    Ok(DeviceStartResponse {
        device_secret: secret.to_secret_string(),
        verification_uri_complete: Some(format!("{verification_uri}?code={display}")),
        verification_uri,
        user_code: display,
        interval: ctx.ttl().device_interval,
        expires_in: ttl,
    })
}

/// Start a generic pending approval (an app's "headless machine asks, a
/// human approves"). Same as [`start`] with a payload.
///
/// # Errors
///
/// As [`start`].
pub async fn start_pending_approval(
    ctx: &AuthContext,
    payload: &str,
    source_ip: Option<&str>,
) -> Result<DeviceStartResponse, ApiError> {
    start(ctx, Some(payload), source_ip).await
}

/// Approve or deny the flow with user code `raw_code`, as `user`.
///
/// For a login row (no payload) `ns` must be `None`: approval binds the row
/// to `user`, whose session the poll then mints. For an app row the
/// [`crate::PendingApprovalHook::authorize`] hook decides first.
///
/// # Errors
///
/// `400` for a malformed code, `404` for an unknown/expired one, `409` when
/// already decided, the hook's error, `500` on storage failure.
pub async fn decide(
    ctx: &AuthContext,
    user: UserId,
    raw_code: &str,
    ns: Option<NsNodeId>,
    approve: bool,
) -> Result<(), ApiError> {
    let now = ctx.now();
    let code = forgs::user_code::normalise(raw_code).ok_or(ApiError::BadRequest)?;
    let row = ctx
        .store()
        .pending_device_by_code(&code, now)
        .await
        .map_err(store_err("pending_device_by_code"))?
        .ok_or(ApiError::NotFound)?;
    if !row.is_pending() {
        return Err(ApiError::CONFLICT);
    }
    let subject = forgs::SubjectKey::user(user);
    if approve {
        if row.payload.is_some() {
            ctx.approvals().authorize(ctx, &row, user, ns).await?;
        } else if ns.is_some() {
            return Err(ApiError::BadRequest);
        }
        let ok = ctx
            .store()
            .approve_pending_device(&code, ns, user, now)
            .await
            .map_err(store_err("approve_pending_device"))?;
        if !ok {
            return Err(ApiError::CONFLICT);
        }
    } else {
        let ok = ctx
            .store()
            .deny_pending_device(&code, now)
            .await
            .map_err(store_err("deny_pending_device"))?;
        if !ok {
            return Err(ApiError::CONFLICT);
        }
    }
    let mut ev = AuditEvent::new(
        now,
        if approve {
            "device.approve"
        } else {
            "device.deny"
        },
    )
    .subject(&subject)
    .target(forgs::user_code::display(&code));
    if let Some(ns) = ns {
        ev = ev.ns(ns);
    }
    ctx.audit().record(ev).await;
    Ok(())
}

/// What a poll produced.
#[derive(Debug)]
pub enum PollOutcome {
    /// A login flow's status (possibly `Granted`).
    Login(DevicePollResponse),
    /// An approved app row, redeemed by the app's hook.
    App(serde_json::Value),
}

/// How many poll timestamps to keep before pruning.
const POLL_LOG_PRUNE_AT: usize = 4096;

/// Record a poll of `hash` and say whether it came too soon.
fn too_fast(ctx: &AuthContext, hash: &str) -> bool {
    let now = ctx.now();
    let interval = ctx.ttl().device_interval;
    let horizon = ctx.ttl().device_flow;
    let mut log = ctx
        .inner
        .poll_log
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if log.len() >= POLL_LOG_PRUNE_AT {
        log.retain(|_, t| now.saturating_sub(*t) < horizon);
    }
    let fast = log
        .get(hash)
        .is_some_and(|last| now.saturating_sub(*last) < interval);
    log.insert(hash.to_owned(), now);
    fast
}

/// Poll a device flow with its device secret.
///
/// Pending / slow-down / denied / expired describe the caller's *own* flow
/// and are reported as such; a secret that is not a device secret of ours
/// at all is a flat `401 invalid_grant`.
///
/// # Errors
///
/// [`ApiError::InvalidGrant`], the hook's error, `500` on storage failure.
pub async fn poll(ctx: &AuthContext, device_secret: &str) -> Result<PollOutcome, ApiError> {
    let now = ctx.now();
    let token = match ctx.format().parse(device_secret) {
        Ok(t) if t.kind() == TokenKind::DeviceSecret => t,
        _ => return Err(ApiError::InvalidGrant),
    };
    let hash = token.hash();
    let Some(row) = ctx
        .store()
        .pending_device_by_hash(&hash, now)
        .await
        .map_err(store_err("pending_device_by_hash"))?
    else {
        // Unknown and expired look alike: both are "this flow is over".
        return Ok(PollOutcome::Login(DevicePollResponse::Expired));
    };
    if row.is_denied() {
        return Ok(PollOutcome::Login(DevicePollResponse::Denied));
    }
    if row.is_pending() {
        let r = if too_fast(ctx, hash.as_str()) {
            DevicePollResponse::SlowDown
        } else {
            DevicePollResponse::Pending
        };
        return Ok(PollOutcome::Login(r));
    }
    if !row.is_approved() {
        // Already redeemed: single mint.
        return Err(ApiError::InvalidGrant);
    }
    let Some(approved) = ctx
        .store()
        .consume_pending_device(&hash, now)
        .await
        .map_err(store_err("consume_pending_device"))?
    else {
        return Err(ApiError::InvalidGrant);
    };
    if let Ok(mut log) = ctx.inner.poll_log.lock() {
        log.remove(hash.as_str());
    }
    // The approver must still be active for both outcomes: a login mints
    // their session, and an app payload is redeemed on their authority.
    let user = approved.approved_by;
    if !crate::session::user_is_active(ctx, user).await? {
        return Err(ApiError::InvalidGrant);
    }
    if let Some(payload) = approved.payload.as_deref() {
        let v = ctx
            .approvals()
            .redeem(ctx, user, approved.ns, payload)
            .await?;
        return Ok(PollOutcome::App(v));
    }
    let session = mint_session(ctx, user, "device flow").await?;
    // A failed refresh mint must not fail the login: the session is usable
    // and the client handles a missing refresh token.
    let refresh_token = if let Ok(t) = mint_refresh(ctx, user).await {
        Some(t)
    } else {
        tracing::warn!("minted a device-flow session but not its refresh token");
        None
    };
    ctx.audit()
        .record(
            AuditEvent::new(now, "auth.login")
                .subject(&forgs::SubjectKey::user(user))
                .target("device"),
        )
        .await;
    Ok(PollOutcome::Login(DevicePollResponse::Granted(
        TokenResponse {
            token: session.token,
            expires: session.expires,
            username: username_of(ctx, user).await,
            user_id: Some(user.to_string()),
            refresh_token,
        },
    )))
}
