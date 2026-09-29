//! Sessions, refresh tokens and logout (framework-agnostic).

use forgs::api::{LogoutRequest, TokenResponse};
use forgs::{TokenKind, UserId};

use crate::audit::AuditEvent;
use crate::auth::Caller;
use crate::context::AuthContext;
use crate::error::{store_err, ApiError};

/// A freshly minted session.
#[derive(Clone, PartialEq, Eq)]
pub struct MintedSession {
    /// The session token.
    pub token: String,
    /// Its expiry, epoch seconds.
    pub expires: u64,
}

impl std::fmt::Debug for MintedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedSession")
            .field("token", &"<redacted>")
            .field("expires", &self.expires)
            .finish()
    }
}

/// Mint a session for an existing user. `how` goes into the audit detail.
///
/// # Errors
///
/// [`ApiError::Internal`] if the insert fails.
pub async fn mint_session(
    ctx: &AuthContext,
    user: UserId,
    how: &str,
) -> Result<MintedSession, ApiError> {
    let now = ctx.now();
    let expires = now.saturating_add(ctx.ttl().session);
    let token = ctx.format().mint(TokenKind::Session);
    ctx.store()
        .insert_session(&token.hash(), user, now, expires)
        .await
        .map_err(store_err("insert_session"))?;
    ctx.audit()
        .record(
            AuditEvent::new(now, "session.mint")
                .subject(&forgs::SubjectKey::user(user))
                .target(token.hash().short())
                .detail(how),
        )
        .await;
    Ok(MintedSession {
        token: token.to_secret_string(),
        expires,
    })
}

/// Mint a refresh token for an existing user (CLI logins only; the browser
/// never receives one).
///
/// # Errors
///
/// [`ApiError::Internal`] if the insert fails.
pub async fn mint_refresh(ctx: &AuthContext, user: UserId) -> Result<String, ApiError> {
    let now = ctx.now();
    let expires = now.saturating_add(ctx.ttl().refresh);
    let token = ctx.format().mint(TokenKind::Refresh);
    ctx.store()
        .insert_refresh_token(&token.hash(), user, now, expires)
        .await
        .map_err(store_err("insert_refresh_token"))?;
    ctx.audit()
        .record(
            AuditEvent::new(now, "refresh_token.mint")
                .subject(&forgs::SubjectKey::user(user))
                .target(token.hash().short()),
        )
        .await;
    Ok(token.to_secret_string())
}

/// The username of `user`, for a response's display field.
pub(crate) async fn username_of(ctx: &AuthContext, user: UserId) -> Option<String> {
    ctx.store()
        .user_by_id(user)
        .await
        .ok()
        .flatten()
        .map(|u| u.username)
}

/// Whether `user` exists and is active.
pub(crate) async fn user_is_active(ctx: &AuthContext, user: UserId) -> Result<bool, ApiError> {
    Ok(ctx
        .store()
        .user_by_id(user)
        .await
        .map_err(store_err("user_by_id"))?
        .is_some_and(|u| u.state == forgs_store::UserState::Active))
}

/// `grant_type: refresh` — exchange a live session token for a fresh one.
///
/// **Replacing**: the old session stops working immediately, so a stolen one
/// has a strictly bounded life even if the theft is not noticed.
///
/// # Errors
///
/// `401 invalid_grant` for anything but a live session of an active user
/// (uniformly), `500` on a storage failure.
pub async fn refresh_session(
    ctx: &AuthContext,
    session_token: &str,
) -> Result<TokenResponse, ApiError> {
    let now = ctx.now();
    let auth = match forgs::authenticate(ctx.format(), &ctx.token_store(), session_token, now).await
    {
        Ok(a) if a.kind == TokenKind::Session => a,
        Ok(a) => {
            ctx.audit()
                .record(
                    AuditEvent::new(now, "auth.wrong_kind")
                        .subject(&a.subject)
                        .detail("session refresh with a non-session token"),
                )
                .await;
            return Err(ApiError::InvalidGrant);
        }
        Err(e) => {
            ctx.audit()
                .record(AuditEvent::new(now, e.label()).detail("session refresh"))
                .await;
            return Err(ApiError::InvalidGrant);
        }
    };
    let user = auth.subject.user_id().ok_or(ApiError::InvalidGrant)?;
    if !user_is_active(ctx, user).await? {
        return Err(ApiError::InvalidGrant);
    }
    let fresh = mint_session(ctx, user, "session refresh").await?;
    let _ = ctx.store().delete_session(&auth.hash).await;
    Ok(TokenResponse {
        token: fresh.token,
        expires: fresh.expires,
        username: username_of(ctx, user).await,
        user_id: Some(user.to_string()),
        refresh_token: None,
    })
}

/// `grant_type: refresh_token` — redeem a refresh token for a session.
///
/// # Why this does not delete the refresh token
///
/// [`refresh_session`] replaces; **this path is deliberately the opposite.**
/// A replacing refresh cannot sit on a path two concurrent clients use (a
/// sidecar in a parallel build): the loser would hold a token the winner's
/// redemption deleted. Non-rotating redemption means N concurrent
/// redemptions all succeed and every minted session is independently valid.
/// The cost — a leaked refresh token is usable for its TTL — is bounded by
/// `logout --all` and expiry. **If you are here to "fix" the missing
/// delete: it is not missing.** The response does not echo the refresh
/// token: the caller already holds it.
///
/// # Errors
///
/// `401 invalid_grant` uniformly, `500` on a storage failure.
pub async fn redeem_refresh_token(
    ctx: &AuthContext,
    refresh_token: &str,
) -> Result<TokenResponse, ApiError> {
    let now = ctx.now();
    let record =
        match forgs::verify::verify_refresh_token(ctx.format(), ctx.store(), refresh_token, now)
            .await
        {
            Ok((_hash, record)) => record,
            Err(e) => {
                ctx.audit()
                    .record(AuditEvent::new(now, e.label()).detail("refresh token redemption"))
                    .await;
                return Err(ApiError::InvalidGrant);
            }
        };
    if !user_is_active(ctx, record.user_id).await? {
        return Err(ApiError::InvalidGrant);
    }
    let s = mint_session(ctx, record.user_id, "refresh token redemption").await?;
    // Nothing is deleted here. See the doc comment above.
    Ok(TokenResponse {
        token: s.token,
        expires: s.expires,
        username: username_of(ctx, record.user_id).await,
        user_id: Some(record.user_id.to_string()),
        refresh_token: None,
    })
}

/// `POST /auth/logout` — revoke the caller's credentials.
///
/// * default — delete the session the caller **authenticated with** (never
///   one named in the request) and, if a `refresh_token` is supplied whose
///   row belongs to this same user, that too. Someone else's refresh token
///   is ignored silently: never an oracle, never a cross-user delete.
/// * `all` — delete every session and refresh token of the calling user;
///   the lost-machine answer.
///
/// Success is uniform whether or not rows existed. **A storage failure is an
/// error, not a success**: "revoked" and "already gone" must be
/// indistinguishable, but a failed write means the credential is still live,
/// and telling someone whose laptop was stolen otherwise is the exact
/// failure this route exists to prevent.
///
/// # Errors
///
/// [`ApiError::Forbidden`] for a non-user caller, [`ApiError::Internal`] on a
/// storage failure.
pub async fn logout(
    ctx: &AuthContext,
    caller: &Caller,
    req: &LogoutRequest,
) -> Result<(), ApiError> {
    let user = caller.require_user()?;
    let now = ctx.now();
    let detail = if req.all {
        let s = ctx
            .store()
            .delete_sessions_for_user(user)
            .await
            .map_err(|e| internal("logout --all sessions", &e))?;
        let r = ctx
            .store()
            .delete_refresh_tokens_for_user(user)
            .await
            .map_err(|e| internal("logout --all refresh tokens", &e))?;
        format!("logout --all: {s} sessions, {r} refresh tokens")
    } else {
        ctx.store()
            .delete_session(&caller.auth.hash)
            .await
            .map_err(|e| internal("logout session", &e))?;
        let mut revoked_refresh = false;
        if let Some(presented) = req.refresh_token.as_deref() {
            // An unparseable or wrong-kind value is simply not a refresh
            // token of ours and is dropped without a lookup.
            if let Ok(t) = ctx.format().parse(presented) {
                if t.kind() == TokenKind::Refresh {
                    let hash = t.hash();
                    // Ownership before the delete; a lookup failure is fatal
                    // for the same reason the deletes are.
                    let row = forgs::TokenStore::lookup_refresh_token(ctx.store(), &hash)
                        .await
                        .map_err(|e| {
                            tracing::warn!(error = %e, "refresh lookup failed on logout");
                            ApiError::Internal
                        })?;
                    if row.is_some_and(|r| r.user_id == user) {
                        ctx.store()
                            .delete_refresh_token(&hash)
                            .await
                            .map_err(|e| internal("logout refresh token", &e))?;
                        revoked_refresh = true;
                    }
                }
            }
        }
        if revoked_refresh {
            "logout: session and refresh token".to_owned()
        } else {
            "logout: session".to_owned()
        }
    };
    ctx.audit()
        .record(
            AuditEvent::new(now, "session.logout")
                .subject(&caller.auth.subject)
                .detail(detail),
        )
        .await;
    Ok(())
}

fn internal(what: &str, e: &forgs_store::StoreError) -> ApiError {
    tracing::warn!(error = %e, %what, "failed to revoke credentials");
    ApiError::Internal
}
