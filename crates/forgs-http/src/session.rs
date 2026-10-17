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

/// Mint a session for an existing user, starting a new refresh chain (its
/// absolute lifetime counts from now). `how` goes into the audit detail.
///
/// # Errors
///
/// [`ApiError::Internal`] if the insert fails.
pub async fn mint_session(
    ctx: &AuthContext,
    user: UserId,
    how: &str,
) -> Result<MintedSession, ApiError> {
    mint_session_in_chain(ctx, user, how, ctx.now()).await
}

/// Mint a session belonging to the refresh chain authenticated at
/// `auth_time`. Its expiry is capped at the chain's absolute end,
/// `auth_time + session_max_life`.
async fn mint_session_in_chain(
    ctx: &AuthContext,
    user: UserId,
    how: &str,
    auth_time: u64,
) -> Result<MintedSession, ApiError> {
    let now = ctx.now();
    let ttl = ctx.ttl();
    let expires = now
        .saturating_add(ttl.session)
        .min(auth_time.saturating_add(ttl.session_max_life));
    let token = ctx.format().mint(TokenKind::Session);
    ctx.store()
        .insert_session(&token.hash(), user, now, auth_time, expires)
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
/// **Replacing, atomically**: the old session is consumed by one
/// `DELETE … RETURNING` *before* the new one is minted, so concurrent
/// refreshes of one token yield exactly one success — a stolen session
/// cannot be forked. If the mint then fails the caller has lost its session:
/// that fails closed.
///
/// **Bounded**: the replacement inherits the chain's original
/// authentication time, and a chain older than
/// [`Ttls::session_max_life`](crate::context::Ttls::session_max_life) cannot
/// be refreshed (nor can any session in it expire past that age). A stolen
/// session refreshed forever therefore still dies; getting a new chain
/// needs a fresh login or a refresh-token redemption.
///
/// # Errors
///
/// `401 invalid_grant` for anything but a live, in-lifetime session of an
/// active user (uniformly), `500` on a storage failure.
pub async fn refresh_session(
    ctx: &AuthContext,
    session_token: &str,
) -> Result<TokenResponse, ApiError> {
    let now = ctx.now();
    let auth = match forgs::authenticate(
        ctx.format(),
        &ctx.token_store(),
        session_token,
        &[TokenKind::Session],
        now,
    )
    .await
    {
        // A non-session token is `WrongKind` from its prefix, below.
        Ok(a) => a,
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
    let min_auth_time = now.saturating_sub(ctx.ttl().session_max_life);
    let consumed = ctx
        .store()
        .consume_session(&auth.hash, now, min_auth_time)
        .await
        .map_err(store_err("consume_session"))?;
    let Some(consumed) = consumed.filter(|c| c.user_id == user) else {
        ctx.audit()
            .record(
                AuditEvent::new(now, "session.refresh_refused")
                    .subject(&auth.subject)
                    .target(auth.hash.short())
                    .detail("session already consumed or past absolute lifetime"),
            )
            .await;
        return Err(ApiError::InvalidGrant);
    };
    let fresh = mint_session_in_chain(ctx, user, "session refresh", consumed.auth_time).await?;
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
///   the lost-machine answer. With `identities_linked_after`, also unlink
///   every identity linked after that time (never the user's oldest one).
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
        let i = match req.identities_linked_after {
            Some(t) => ctx
                .store()
                .unlink_identities_linked_after(user, t)
                .await
                .map_err(|e| internal("logout --all identities", &e))?,
            None => 0,
        };
        format!("logout --all: {s} sessions, {r} refresh tokens, {i} identities")
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
