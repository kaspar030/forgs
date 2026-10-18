//! Signup approval (framework-agnostic): list, approve and reject users
//! waiting under [`crate::SignupPolicy::Approval`].
//!
//! Who may decide is the app's call ([`crate::SignupApprovalHook`]); the
//! default denies everyone. Approving makes the account active. Rejecting
//! **deletes** the pending user, their personal namespace and their
//! identity rows, with no tombstone: the name, identity and email are free
//! to sign up again ([`forgs_store::Store::reject_user`]).

use forgs::api::{PendingUserInfo, PendingUserList};
use forgs::{SubjectKey, UserId};

use crate::audit::AuditEvent;
use crate::context::AuthContext;
use crate::error::{store_err, ApiError};

/// `403` (audited `signup.denied`) unless the hook lets `caller` decide.
async fn require_approver(ctx: &AuthContext, caller: UserId, what: &str) -> Result<(), ApiError> {
    if ctx.signup_approvals().can_approve(ctx, caller).await {
        return Ok(());
    }
    ctx.audit()
        .record(
            AuditEvent::new(ctx.now(), "signup.denied")
                .subject(&SubjectKey::user(caller))
                .detail(what.to_owned()),
        )
        .await;
    Err(ApiError::Forbidden)
}

/// One page of pending users, oldest first. `after` is the previous page's
/// [`PendingUserList::next`]; `limit` is capped at [`forgs::api::MAX_PAGE`].
///
/// # Errors
///
/// `403` for a caller the hook does not allow, `400` for a zero `limit` or
/// a malformed `after`, `500` on storage failure.
pub async fn list(
    ctx: &AuthContext,
    caller: UserId,
    after: Option<&str>,
    limit: Option<u32>,
) -> Result<PendingUserList, ApiError> {
    require_approver(ctx, caller, "list").await?;
    let limit = crate::keys::page_size(limit)?;
    let after = after
        .map(|a| UserId::parse(a).map_err(|_| ApiError::BadRequest))
        .transpose()?;
    let mut rows = ctx
        .store()
        .pending_users_page(after, limit.saturating_add(1))
        .await
        .map_err(store_err("pending_users_page"))?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = more
        .then(|| rows.last().map(|u| u.id.to_string()))
        .flatten();
    let mut users = Vec::with_capacity(rows.len());
    for u in rows {
        let emails = ctx
            .store()
            .emails_of_user(u.id)
            .await
            .map_err(store_err("emails_of_user"))?;
        users.push(PendingUserInfo {
            user_id: u.id.to_string(),
            username: u.username,
            display_name: u.display_name,
            created_at: u.created_at,
            emails,
        });
    }
    Ok(PendingUserList { users, next })
}

/// Parse a wire user id; malformed is `404` like unknown (not pending).
fn parse_user(user: &str) -> Result<UserId, ApiError> {
    UserId::parse(user.trim()).map_err(|_| ApiError::NotFound)
}

/// Approve a pending user: they can log in from now on.
///
/// # Errors
///
/// `403` for a caller the hook does not allow, `404` if `user` is not a
/// pending user, `500` on storage failure.
pub async fn approve(ctx: &AuthContext, caller: UserId, user: &str) -> Result<(), ApiError> {
    require_approver(ctx, caller, "approve").await?;
    let user = parse_user(user)?;
    let username = crate::session::username_of(ctx, user).await;
    ctx.store()
        .approve_user(user)
        .await
        .map_err(store_err("approve_user"))?;
    ctx.audit()
        .record(
            AuditEvent::new(ctx.now(), "user.signup.approved")
                .subject(&SubjectKey::user(caller))
                .target(SubjectKey::user(user).to_string())
                .detail(format!("username={}", username.unwrap_or_default())),
        )
        .await;
    Ok(())
}

/// Reject a pending user: delete the account and its personal namespace,
/// freeing the name (no tombstone).
///
/// # Errors
///
/// `403` for a caller the hook does not allow, `404` if `user` is not a
/// pending user, `409 conflict` if the app created nodes under the pending
/// user's personal namespace, `500` on storage failure.
pub async fn reject(ctx: &AuthContext, caller: UserId, user: &str) -> Result<(), ApiError> {
    require_approver(ctx, caller, "reject").await?;
    let user = parse_user(user)?;
    let username = crate::session::username_of(ctx, user).await;
    ctx.store()
        .reject_user(user)
        .await
        .map_err(store_err("reject_user"))?;
    ctx.audit()
        .record(
            AuditEvent::new(ctx.now(), "user.signup.rejected")
                .subject(&SubjectKey::user(caller))
                .target(SubjectKey::user(user).to_string())
                .detail(format!("username={}", username.unwrap_or_default())),
        )
        .await;
    Ok(())
}
