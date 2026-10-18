//! First-login username choice (framework-agnostic).
//!
//! An unknown identity comes back from the provider as a pending signup: a
//! one-shot, short-lived ticket held in a sealed `HttpOnly` cookie. The user
//! picks a username, and [`signup`] creates — in **one** transaction — the
//! user, the identity, its verified email, the personal namespace and the
//! admin membership there. A failure (name taken, tombstoned, reserved,
//! email already held by another user) rolls everything back and leaves the
//! ticket usable, so the user can pick another name.
//!
//! The [`SignupPolicy`] decides what a signup yields: an active account and
//! a session ([`SignupPolicy::Open`]), a pending account waiting for an
//! approver ([`SignupPolicy::Approval`], see [`crate::signups`]), or a
//! refusal ([`SignupPolicy::Closed`]).

use forgs::{PendingId, UserId};
use forgs_store::{PendingSignup, StoreError, UserState};

use crate::audit::AuditEvent;
use crate::context::{AuthContext, SignupPolicy};
use crate::cookies::unseal;
use crate::error::{store_err, ApiError};
use crate::session::{mint_session, MintedSession};

/// An opened signup cookie.
#[derive(Debug, Clone)]
pub struct SignupTicket {
    /// The pending-signup id.
    pub id: PendingId,
    /// Where to go after signing up.
    pub return_to: Option<String>,
}

/// Open a sealed signup cookie value.
#[must_use]
pub fn open_ticket(ctx: &AuthContext, sealed: &str) -> Option<SignupTicket> {
    let fields = unseal(ctx, &ctx.cookies().signup, sealed, 2)?;
    let id = PendingId::parse(&fields[0]).ok()?;
    let return_to = Some(fields[1].clone()).filter(|r| crate::login::safe_return_to(r).is_some());
    Some(SignupTicket { id, return_to })
}

/// The live pending signup behind a ticket (for the form's suggestion).
///
/// # Errors
///
/// [`ApiError::TICKET_EXPIRED`] when unknown or expired.
pub async fn pending(ctx: &AuthContext, ticket: PendingId) -> Result<PendingSignup, ApiError> {
    ctx.store()
        .pending_signup(ticket, ctx.now())
        .await
        .map_err(store_err("pending_signup"))?
        .ok_or(ApiError::TICKET_EXPIRED)
}

/// How a signup ended.
#[derive(Debug)]
pub enum SignupOutcome {
    /// [`SignupPolicy::Open`]: the account is active and a browser session
    /// was minted.
    Session(UserId, MintedSession),
    /// [`SignupPolicy::Approval`]: the account was created
    /// [`UserState::Pending`]; no session exists until it is approved.
    Pending(UserId),
}

/// Complete a signup: under [`SignupPolicy::Open`] mint a browser session;
/// under [`SignupPolicy::Approval`] create the user pending, call
/// [`crate::SignupApprovalHook::on_pending`] and mint nothing.
///
/// # Errors
///
/// [`ApiError::SIGNUP_CLOSED`] under [`SignupPolicy::Closed`] (the ticket is
/// left alone), [`ApiError::USERNAME_INVALID`] (policy, reserved),
/// [`ApiError::USERNAME_TAKEN`] (taken by a user or a root namespace, or
/// tombstoned — deliberately the same), [`ApiError::EMAIL_IN_USE`] (log in
/// with the existing method and link), [`ApiError::IDENTITY_TAKEN`],
/// [`ApiError::TICKET_EXPIRED`].
pub async fn signup(
    ctx: &AuthContext,
    ticket: PendingId,
    username: &str,
) -> Result<SignupOutcome, ApiError> {
    let now = ctx.now();
    let policy = ctx.signup_policy();
    if policy == SignupPolicy::Closed {
        ctx.audit()
            .record(
                AuditEvent::new(now, "signup.reject.closed")
                    .target(username.trim().chars().take(128).collect::<String>()),
            )
            .await;
        return Err(ApiError::SIGNUP_CLOSED);
    }
    // Pre-check for a precise error before opening a write transaction; the
    // store validates again inside it.
    if ctx.store().schema().validate_username(username).is_err() {
        return Err(ApiError::USERNAME_INVALID);
    }
    let state = if policy == SignupPolicy::Approval {
        UserState::Pending
    } else {
        UserState::Active
    };
    let created = match ctx
        .store()
        .signup_pending(ticket, username, None, state, now)
        .await
    {
        Ok(Some((user, _personal))) => user,
        Ok(None) => return Err(ApiError::TICKET_EXPIRED),
        Err(e) => {
            let label = match &e {
                StoreError::NameTaken | StoreError::NameTombstoned => "signup.reject.name_taken",
                StoreError::EmailTaken => "signup.reject.email_in_use",
                StoreError::IdentityTaken => "signup.reject.identity_taken",
                _ => "signup.reject",
            };
            ctx.audit()
                .record(AuditEvent::new(now, label).target(username.trim().to_owned()))
                .await;
            return Err(e.into());
        }
    };
    let action = if state == UserState::Pending {
        "user.signup.pending"
    } else {
        "user.signup"
    };
    ctx.audit()
        .record(
            AuditEvent::new(now, action)
                .subject(&forgs::SubjectKey::user(created))
                .target(username.trim().to_ascii_lowercase()),
        )
        .await;
    if state == UserState::Pending {
        match ctx.store().user_by_id(created).await {
            Ok(Some(user)) => ctx.signup_approvals().on_pending(ctx, &user).await,
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "could not load a pending user for on_pending"),
        }
        return Ok(SignupOutcome::Pending(created));
    }
    let session = mint_session(ctx, created, "signup").await?;
    Ok(SignupOutcome::Session(created, session))
}
