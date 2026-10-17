//! The caller's linked login methods: list and unlink (docs/design.md §4).
//!
//! Linking itself is a browser flow with step-up (see [`crate::login`]).
//! Unlinking never removes a user's **last** identity.

use forgs::api::{IdentityInfo, IdentityList, UnlinkIdentityRequest};
use forgs::IdentityId;
use forgs_store::StoreError;

use crate::audit::AuditEvent;
use crate::auth::Caller;
use crate::context::AuthContext;
use crate::error::{store_err, ApiError};

/// `GET /auth/identities` — the caller's identities, oldest first.
///
/// # Errors
///
/// [`ApiError::Forbidden`] for a non-user caller, `500` on storage failure.
pub async fn list(ctx: &AuthContext, caller: &Caller) -> Result<IdentityList, ApiError> {
    let user = caller.require_user()?;
    let rows = ctx
        .store()
        .identities_for_user(user)
        .await
        .map_err(store_err("identities_for_user"))?;
    Ok(IdentityList {
        identities: rows
            .into_iter()
            .map(|i| IdentityInfo {
                id: i.id.to_string(),
                provider: i.provider,
                subject: i.subject,
                email: i.email,
                email_verified: i.email_verified,
                linked_at: i.linked_at,
                last_login_at: i.last_login_at,
            })
            .collect(),
    })
}

/// `POST /auth/identities/unlink` — remove one of the caller's identities.
///
/// # Errors
///
/// [`ApiError::NotFound`] for an unknown id or one of another user's (alike:
/// no oracle), [`ApiError::LAST_IDENTITY`] for the only remaining one,
/// [`ApiError::Forbidden`] for a non-user caller, `500` on storage failure.
pub async fn unlink(
    ctx: &AuthContext,
    caller: &Caller,
    req: &UnlinkIdentityRequest,
) -> Result<(), ApiError> {
    let user = caller.require_user()?;
    let id = IdentityId::parse(req.id.trim()).map_err(|_| ApiError::NotFound)?;
    let provider = ctx
        .store()
        .identities_for_user(user)
        .await
        .map_err(store_err("identities_for_user"))?
        .into_iter()
        .find(|i| i.id == id)
        .map(|i| i.provider);
    match ctx.store().unlink_identity(user, id).await {
        Ok(()) => {}
        Err(StoreError::NotFound) => return Err(ApiError::NotFound),
        Err(e) => return Err(store_err("unlink_identity")(e)),
    }
    ctx.audit()
        .record(
            AuditEvent::new(ctx.now(), "identity.unlink")
                .subject(&caller.auth.subject)
                .target(provider.unwrap_or_default())
                .detail(format!("identity {id}")),
        )
        .await;
    Ok(())
}
