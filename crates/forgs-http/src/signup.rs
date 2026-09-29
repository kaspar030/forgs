//! First-login username choice (framework-agnostic).
//!
//! An unknown identity comes back from the provider as a pending signup: a
//! one-shot, short-lived ticket held in a sealed `HttpOnly` cookie. The user
//! picks a username, and [`signup`] creates — in **one** transaction — the
//! user, the identity, its verified email, the personal namespace and the
//! admin membership there. A failure (name taken, tombstoned, reserved,
//! email already held by another user) rolls everything back and leaves the
//! ticket usable, so the user can pick another name.

use forgs::{PendingId, UserId};
use forgs_store::{PendingSignup, StoreError};

use crate::audit::AuditEvent;
use crate::context::AuthContext;
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

/// Complete a signup and mint a browser session.
///
/// # Errors
///
/// [`ApiError::USERNAME_INVALID`] (policy, reserved), [`ApiError::USERNAME_TAKEN`]
/// (taken by a user or a root namespace, or tombstoned — deliberately the
/// same), [`ApiError::EMAIL_IN_USE`] (log in with the existing method and
/// link), [`ApiError::IDENTITY_TAKEN`], [`ApiError::TICKET_EXPIRED`].
pub async fn signup(
    ctx: &AuthContext,
    ticket: PendingId,
    username: &str,
) -> Result<(UserId, MintedSession), ApiError> {
    let now = ctx.now();
    // Pre-check for a precise error before opening a write transaction; the
    // store validates again inside it.
    if ctx.store().schema().validate_username(username).is_err() {
        return Err(ApiError::USERNAME_INVALID);
    }
    let created = match ctx
        .store()
        .signup_pending(ticket, username, None, now)
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
    ctx.audit()
        .record(
            AuditEvent::new(now, "user.signup")
                .subject(&forgs::SubjectKey::user(created))
                .target(username.trim().to_ascii_lowercase()),
        )
        .await;
    let session = mint_session(ctx, created, "signup").await?;
    Ok((created, session))
}
