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
//! Poll outcomes: `pending`, `slow_down`, `denied`, `expired` (also for a
//! well-formed device secret that is unknown — "this flow is over"), or the
//! granted session. Only a token that is not a device secret at all, or an
//! already-redeemed one, is a flat `401 invalid_grant`.
//!
//! # Abuse controls
//!
//! * **Unauthenticated growth**: `start` writes a row. Live CLI logins
//!   ([`crate::AuthContextBuilder::max_pending_devices`]) and live app
//!   approvals ([`crate::AuthContextBuilder::max_pending_approvals`]) have
//!   separate ceilings, so flooding one kind does not lock out the other,
//!   and one source may hold at most
//!   [`crate::AuthContextBuilder::max_pending_devices_per_source`] live
//!   flows. The source comes from the configured [`crate::ClientIp`]
//!   resolver, keyed by [`crate::source_key`] (IPv6 per /64), and is stored
//!   in the row's `source_ip`. With the default [`crate::NoClientIp`] and no
//!   [`crate::PeerIp`] extension the source is unknown and **only** the
//!   global ceilings apply; behind a proxy configure [`crate::ForwardedFor`]
//!   with the right number of trusted hops, never more.
//! * **Polling too fast** (RFC 8628 §3.5): a poll sooner than the flow's
//!   interval is answered `slow_down` without touching the database, and
//!   the interval grows by 5s (to at most 60s).
//! * **User-code guessing**: an unknown, expired or already-decided code is
//!   one indistinguishable `404`, audited as `device.decide.unknown`; after
//!   10 misses within the device-flow TTL a user is refused (`429
//!   rate_limited`, audited `device.decide.locked`) for the rest of that
//!   window, even for a valid code.
//! * **Remote phishing** (RFC 8628 §5.4): an attacker starts a flow and
//!   talks a victim into confirming the code. Inherent to every device
//!   flow, so made laborious: there is no `verification_uri_complete` and
//!   the page never pre-fills a code, the user must type it, and a review
//!   step shows when and from where the device asked before Approve/Deny.
//!   A mistaken approval can be cancelled until the device redeems it.
//!
//! The poll pacing and the miss counter live **in memory, per process**:
//! they are load and nuisance controls, not security boundaries (a restart
//! or a second replica resets them). The code space (~40 bits) behind a
//! 10-minute TTL is what makes guessing infeasible.

use std::net::IpAddr;

use forgs::api::{DevicePollResponse, DeviceStartResponse, TokenResponse};
use forgs::{NsNodeId, TokenKind, UserId};

use crate::audit::AuditEvent;
use crate::context::{source_key, AuthContext, MissWindow, PollState};
use crate::error::{store_err, ApiError};
use crate::session::{mint_refresh, mint_session, username_of};

/// Begin a device flow. `payload` is `None` for a CLI login; an app passes
/// its own JSON to start a generic pending approval (see
/// [`crate::PendingApprovalHook`]). `source_ip` is the caller as the
/// app's [`crate::ClientIp`] resolver sees it
/// ([`AuthContext::client_ip`]); `None` skips the per-source ceiling.
///
/// # Errors
///
/// [`ApiError::UNAVAILABLE`] when this kind's live set, or the source's
/// share of it, is full; `500` on storage failure.
pub async fn start(
    ctx: &AuthContext,
    payload: Option<&str>,
    source_ip: Option<IpAddr>,
) -> Result<DeviceStartResponse, ApiError> {
    let now = ctx.now();
    let source = source_ip.map(source_key);
    let live = ctx
        .store()
        .live_pending_device_counts(now, source.as_deref())
        .await
        .map_err(store_err("live_pending_device_counts"))?;
    let (count, cap) = if payload.is_some() {
        (live.approvals, ctx.inner.max_pending_approvals)
    } else {
        (live.logins, ctx.inner.max_pending_devices)
    };
    // Refusals are logged, not audited: an unauthenticated flood must not
    // turn into a flood of audit rows.
    if count >= cap {
        tracing::warn!(
            live = count,
            app = payload.is_some(),
            "device flow refused: cap"
        );
        return Err(ApiError::UNAVAILABLE);
    }
    if source.is_some() && live.from_source >= ctx.inner.max_pending_devices_per_source {
        tracing::warn!(
            source = source.as_deref(),
            live = live.from_source,
            "device flow refused: source cap"
        );
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
            source.as_deref(),
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
                .detail(format!(
                    "{} from {}",
                    if payload.is_some() {
                        "app approval"
                    } else {
                        "login"
                    },
                    source.as_deref().unwrap_or("unknown")
                )),
        )
        .await;
    let verification_uri = ctx.absolute("/auth/device");
    Ok(DeviceStartResponse {
        device_secret: secret.to_secret_string(),
        // Deliberately none: a link that carries the code makes approval
        // one click for a phished victim.
        verification_uri_complete: None,
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
    source_ip: Option<IpAddr>,
) -> Result<DeviceStartResponse, ApiError> {
    start(ctx, Some(payload), source_ip).await
}

/// Wrong codes a user may submit per device-flow TTL window.
pub const DECIDE_MISS_LIMIT: u32 = 10;

/// How many users' miss windows to keep before pruning.
const DECIDE_MISSES_PRUNE_AT: usize = 4096;

/// Whether `user` has used up their wrong-code allowance.
fn locked_out(ctx: &AuthContext, user: UserId, now: u64) -> bool {
    let window = ctx.ttl().device_flow;
    let misses = ctx
        .inner
        .decide_misses
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    misses
        .get(&user)
        .is_some_and(|m| now.saturating_sub(m.start) < window && m.count >= DECIDE_MISS_LIMIT)
}

/// Refuse a locked-out user, audited.
async fn lockout(ctx: &AuthContext, user: UserId, now: u64) -> ApiError {
    ctx.audit()
        .record(
            AuditEvent::new(now, "device.decide.locked").subject(&forgs::SubjectKey::user(user)),
        )
        .await;
    ApiError::RATE_LIMITED
}

/// Count and audit a miss: the code is unknown, expired or not decidable
/// by this user. Every such case is the same `404`, so the response is no
/// oracle for "exists but decided".
async fn miss(ctx: &AuthContext, user: UserId, code: &str, what: &str, now: u64) -> ApiError {
    let window = ctx.ttl().device_flow;
    {
        let mut misses = ctx
            .inner
            .decide_misses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if misses.len() >= DECIDE_MISSES_PRUNE_AT {
            misses.retain(|_, m| now.saturating_sub(m.start) < window);
        }
        let m = misses.entry(user).or_insert(MissWindow {
            count: 0,
            start: now,
        });
        if now.saturating_sub(m.start) >= window {
            *m = MissWindow {
                count: 0,
                start: now,
            };
        }
        m.count = m.count.saturating_add(1);
    }
    ctx.audit()
        .record(
            AuditEvent::new(now, "device.decide.unknown")
                .subject(&forgs::SubjectKey::user(user))
                .target(forgs::user_code::display(code))
                .detail(what),
        )
        .await;
    ApiError::NotFound
}

/// What the confirm page shows about a pending flow before Approve/Deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The code, as displayed.
    pub display_code: String,
    /// When the device asked, epoch seconds.
    pub created_at: u64,
    /// The source bucket it asked from ([`crate::source_key`]), if known.
    pub source_ip: Option<String>,
    /// An app approval rather than a CLI login.
    pub is_app: bool,
}

/// Look up a pending flow by user code for the review step, as `user`.
/// Same lockout, miss counting and single `404` as [`decide`].
///
/// # Errors
///
/// `400` for a malformed code, `404` for one that is unknown, expired or
/// already decided, [`ApiError::RATE_LIMITED`] when locked out, `500` on
/// storage failure.
pub async fn review(
    ctx: &AuthContext,
    user: UserId,
    raw_code: &str,
) -> Result<DeviceInfo, ApiError> {
    let now = ctx.now();
    let code = forgs::user_code::normalise(raw_code).ok_or(ApiError::BadRequest)?;
    if locked_out(ctx, user, now) {
        return Err(lockout(ctx, user, now).await);
    }
    let row = ctx
        .store()
        .pending_device_by_code(&code, now)
        .await
        .map_err(store_err("pending_device_by_code"))?;
    match row {
        Some(row) if row.is_pending() => Ok(DeviceInfo {
            display_code: forgs::user_code::display(&code),
            created_at: row.created_at,
            source_ip: row.source_ip,
            is_app: row.payload.is_some(),
        }),
        _ => Err(miss(ctx, user, &code, "review", now).await),
    }
}

/// Approve or deny the flow with user code `raw_code`, as `user`.
///
/// For a login row (no payload) `ns` must be `None`: approval binds the row
/// to `user`, whose session the poll then mints. For an app row the
/// [`crate::PendingApprovalHook::authorize`] hook decides first.
///
/// A deny also cancels `user`'s own approval that the device has not
/// redeemed yet (audited `device.deny`, detail `cancelled approval`).
///
/// # Errors
///
/// `400` for a malformed code; one `404` for a code that is unknown,
/// expired, already decided (or lost a race to be decided), so the status
/// is no oracle; [`ApiError::RATE_LIMITED`] after too many such misses;
/// the hook's error; `500` on storage failure.
pub async fn decide(
    ctx: &AuthContext,
    user: UserId,
    raw_code: &str,
    ns: Option<NsNodeId>,
    approve: bool,
) -> Result<(), ApiError> {
    let now = ctx.now();
    let code = forgs::user_code::normalise(raw_code).ok_or(ApiError::BadRequest)?;
    if locked_out(ctx, user, now) {
        return Err(lockout(ctx, user, now).await);
    }
    let what = if approve { "approve" } else { "deny" };
    let Some(row) = ctx
        .store()
        .pending_device_by_code(&code, now)
        .await
        .map_err(store_err("pending_device_by_code"))?
    else {
        return Err(miss(ctx, user, &code, what, now).await);
    };
    let subject = forgs::SubjectKey::user(user);
    let mut cancelled = false;
    if approve {
        if !row.is_pending() {
            return Err(miss(ctx, user, &code, what, now).await);
        }
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
            return Err(miss(ctx, user, &code, what, now).await);
        }
    } else {
        cancelled = row.is_approved() && row.approved_by == Some(user);
        if !(row.is_pending() || cancelled) {
            return Err(miss(ctx, user, &code, what, now).await);
        }
        let ok = ctx
            .store()
            .deny_pending_device(&code, user, now)
            .await
            .map_err(store_err("deny_pending_device"))?;
        if !ok {
            return Err(miss(ctx, user, &code, what, now).await);
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
    if cancelled {
        ev = ev.detail("cancelled approval");
    }
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

/// How many poll states to keep before pruning.
const POLL_LOG_PRUNE_AT: usize = 4096;

/// How much a `slow_down` adds to a flow's interval (RFC 8628 §3.5).
pub const SLOW_DOWN_STEP: u64 = 5;

/// The interval a `slow_down` never pushes past.
pub const MAX_INTERVAL: u64 = 60;

fn poll_log(
    ctx: &AuthContext,
) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, PollState>> {
    ctx.inner
        .poll_log
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Before any database read: is this poll of `hash` sooner than its flow's
/// interval? If so, grow the interval and count this poll as the last one.
/// Only flows seen pending have an entry, so unknown secrets cost nothing.
fn too_fast(ctx: &AuthContext, hash: &str, now: u64) -> bool {
    let mut log = poll_log(ctx);
    let Some(st) = log.get_mut(hash) else {
        return false;
    };
    if now.saturating_sub(st.last) >= st.interval {
        return false;
    }
    st.interval = st.interval.saturating_add(SLOW_DOWN_STEP).min(MAX_INTERVAL);
    st.last = now;
    true
}

/// Record a poll of a pending flow.
fn record_poll(ctx: &AuthContext, hash: &str, now: u64) {
    let horizon = ctx.ttl().device_flow;
    let mut log = poll_log(ctx);
    if log.len() >= POLL_LOG_PRUNE_AT {
        log.retain(|_, st| now.saturating_sub(st.last) < horizon);
    }
    let interval = ctx.ttl().device_interval;
    log.entry(hash.to_owned())
        .and_modify(|st| st.last = now)
        .or_insert(PollState {
            last: now,
            interval,
        });
}

fn forget_poll(ctx: &AuthContext, hash: &str) {
    poll_log(ctx).remove(hash);
}

/// Poll a device flow with its device secret.
///
/// Pending / slow-down / denied / expired describe the caller's *own* flow
/// and are reported as such: a well-formed device secret that is unknown or
/// expired is `expired` ("this flow is over"). A token that is not a device
/// secret at all, or one already redeemed, is a flat `401 invalid_grant`.
///
/// A poll sooner than the flow's current interval is `slow_down` without a
/// database read, and grows the interval (see the module docs).
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
    if too_fast(ctx, hash.as_str(), now) {
        return Ok(PollOutcome::Login(DevicePollResponse::SlowDown));
    }
    let Some(row) = ctx
        .store()
        .pending_device_by_hash(&hash, now)
        .await
        .map_err(store_err("pending_device_by_hash"))?
    else {
        // Unknown and expired look alike: both are "this flow is over".
        forget_poll(ctx, hash.as_str());
        return Ok(PollOutcome::Login(DevicePollResponse::Expired));
    };
    if row.is_denied() {
        forget_poll(ctx, hash.as_str());
        return Ok(PollOutcome::Login(DevicePollResponse::Denied));
    }
    if row.is_pending() {
        record_poll(ctx, hash.as_str(), now);
        return Ok(PollOutcome::Login(DevicePollResponse::Pending));
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
    forget_poll(ctx, hash.as_str());
    // The approver must still be active for both outcomes: a login mints
    // their session, and an app payload is redeemed on their authority.
    let user = approved.approved_by;
    if !crate::session::user_is_active(ctx, user, "device flow").await? {
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
