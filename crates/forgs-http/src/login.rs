//! Browser login through any configured [`forgs_idp::IdentityProvider`]:
//! authorization code + PKCE + a sealed `state` cookie (framework-agnostic).
//!
//! # What actually protects the callback
//!
//! The `state` value, bound to a short-lived, sealed, `HttpOnly`,
//! `SameSite=Lax` cookie. PKCE is sent (and some providers — GitHub OAuth
//! apps — ignore it); it is correct and harmless, but writing "PKCE protects
//! this" would be false for those providers. The cookie is cleared by the
//! callback before anything else can fail, so a `state` is single-use.
//!
//! `redirect_uri` comes from [`AuthContext::redirect_uri`], i.e. from the
//! configured `public_url` — never from `Host` or `X-Forwarded-Host`.
//!
//! # No auto-linking on email
//!
//! An unknown `(provider, subject)` always becomes a pending signup, **even
//! if its verified email matches an existing user**: this path never looks
//! email up at all. Auto-linking on email turns "attacker controls a
//! provider that asserts your email" into account takeover. A second login
//! method is linked only from an authenticated browser session, and only
//! after step-up (below).
//!
//! # Linking requires step-up
//!
//! A session token alone — stolen, redeemed from a refresh token, or a CLI
//! token — must not be able to add a permanent login method to an account.
//! So linking is two legs, each with its own sealed flow cookie:
//!
//! 1. [`FlowIntent::Reauth`]: the browser logs in again with a provider
//!    **already linked** to the user. The callback checks that the asserted
//!    identity belongs to the logged-in user (`reauth_required` otherwise)
//!    and starts leg 2.
//! 2. [`FlowIntent::Link`]: the browser logs in with the target provider and
//!    the callback links that identity.
//!
//! A `Link` cookie is minted only by a successful reauth leg (the cookie is
//! sealed). Both legs re-check that the same user is still logged in. A user
//! with no linked identity (a local bootstrap user) cannot link at all.
//!
//! Re-authenticating and linking through the *same* provider (a second
//! GitHub account) usually ends in `identity_taken`: the provider tends to
//! hand back the account the browser is already logged in to. Log out of
//! the provider between the legs.

use forgs::UserId;
use forgs_idp::{AuthRequest, IdpError};
use forgs_store::{NewIdentity, UserState};

use crate::audit::AuditEvent;
use crate::context::AuthContext;
use crate::cookies::{constant_time_eq, seal, unseal};
use crate::error::{store_err, ApiError};
use crate::session::{mint_session, MintedSession};

/// A same-origin relative path safe to redirect to, or `None`.
///
/// Must start with a single `/` (not `//`, which is protocol-relative, nor
/// `/\`, which some browsers normalise to `//`), and contain only characters
/// that can end neither a header nor an HTML attribute.
#[must_use]
pub fn safe_return_to(s: &str) -> Option<&str> {
    let ok = s.starts_with('/')
        && !s.starts_with("//")
        && s.len() <= 512
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.~?=&%+".contains(&b));
    ok.then_some(s)
}

/// A started login: where to send the browser, and the flow cookie value.
#[derive(Debug, Clone)]
pub struct StartedLogin {
    /// The provider's authorize URL.
    pub authorize_url: String,
    /// The sealed value for the `oauth` cookie.
    pub cookie: String,
}

/// What a login flow is for, sealed into its flow cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowIntent {
    /// An ordinary login (or first-login signup).
    Login,
    /// Step-up: prove, with an identity already linked to `user`, that the
    /// person holding the session is the account's owner; then link
    /// `link_provider`.
    Reauth {
        /// The logged-in user.
        user: UserId,
        /// The provider to link once re-authenticated.
        link_provider: String,
    },
    /// Link the identity to `user`. Minted only by a successful
    /// [`FlowIntent::Reauth`] leg.
    Link {
        /// The logged-in user.
        user: UserId,
    },
}

impl FlowIntent {
    fn encode(&self) -> String {
        match self {
            FlowIntent::Login => String::new(),
            FlowIntent::Reauth {
                user,
                link_provider,
            } => format!("reauth:{user}:{link_provider}"),
            FlowIntent::Link { user } => format!("link:{user}"),
        }
    }

    fn decode(s: &str) -> Option<Self> {
        if s.is_empty() {
            return Some(FlowIntent::Login);
        }
        if let Some(u) = s.strip_prefix("link:") {
            return UserId::parse(u).ok().map(|user| FlowIntent::Link { user });
        }
        let rest = s.strip_prefix("reauth:")?;
        let (u, p) = rest.split_once(':')?;
        if p.is_empty() {
            return None;
        }
        Some(FlowIntent::Reauth {
            user: UserId::parse(u).ok()?,
            link_provider: p.to_owned(),
        })
    }
}

/// Begin an authorization-code login with `provider`.
///
/// `return_to` (a same-origin path; anything else is dropped) is where the
/// browser lands afterwards. `intent` is [`FlowIntent::Login`] except for
/// the authenticated "add login method" route, which starts a
/// [`FlowIntent::Reauth`] leg (see the module docs).
///
/// # Errors
///
/// [`ApiError::UNKNOWN_PROVIDER`] (for `provider`, or a reauth leg's
/// `link_provider`), or [`ApiError::UPSTREAM`] if the provider cannot build
/// its URL.
pub fn start_login(
    ctx: &AuthContext,
    provider: &str,
    return_to: Option<&str>,
    intent: &FlowIntent,
) -> Result<StartedLogin, ApiError> {
    let p = ctx.provider(provider).ok_or(ApiError::UNKNOWN_PROVIDER)?;
    if let FlowIntent::Reauth { link_provider, .. } = intent {
        ctx.provider(link_provider)
            .ok_or(ApiError::UNKNOWN_PROVIDER)?;
    }
    let req = AuthRequest::generate();
    let authorize_url = p
        .authorization_url(&ctx.redirect_uri(provider), &req)
        .map_err(|e| {
            tracing::warn!(error = %e, provider, "could not build an authorize URL");
            ApiError::UPSTREAM
        })?;
    let return_to = return_to.and_then(safe_return_to).unwrap_or("");
    let intent = intent.encode();
    let cookie = seal(
        ctx,
        &ctx.cookies().oauth,
        ctx.now().saturating_add(ctx.ttl().login_flow),
        &[
            provider,
            &req.state,
            &req.nonce,
            &req.pkce_verifier,
            return_to,
            &intent,
        ],
    );
    Ok(StartedLogin {
        authorize_url,
        cookie,
    })
}

/// How a callback ended.
#[derive(Debug)]
pub enum LoginOutcome {
    /// A known identity: a browser session was minted.
    Session {
        /// The session.
        session: MintedSession,
        /// Who.
        user: UserId,
        /// Where to go next.
        return_to: Option<String>,
    },
    /// An unknown identity: it must choose a username first.
    NeedsSignup {
        /// The sealed value for the `signup` cookie.
        ticket_cookie: String,
        /// Where to go after signup.
        return_to: Option<String>,
    },
    /// The identity was linked to the logged-in user.
    Linked {
        /// Who.
        user: UserId,
        /// Where to go next.
        return_to: Option<String>,
    },
    /// The step-up leg succeeded: the browser goes on to the target
    /// provider with this new flow cookie.
    Reauthenticated {
        /// The link leg.
        started: StartedLogin,
    },
}

/// Finish a login. `oauth_cookie` is the flow cookie's value (the caller
/// clears the cookie whatever happens); `current_user` is whoever the
/// browser's session cookie authenticates as right now, if anyone.
///
/// # Errors
///
/// `400 invalid_request` for a missing/forged/expired/mismatched state (all
/// alike, and nothing minted), [`ApiError::NO_VERIFIED_EMAIL`],
/// [`ApiError::UPSTREAM`] for other provider failures, `403` for a disabled
/// user, [`ApiError::IDENTITY_TAKEN`] when linking an identity already
/// linked, [`ApiError::REAUTH_REQUIRED`] when a step-up leg asserted an
/// identity that is not the logged-in user's, `500` on storage failure.
#[allow(clippy::too_many_lines)]
pub async fn complete_login(
    ctx: &AuthContext,
    provider: &str,
    code: &str,
    state: &str,
    oauth_cookie: Option<&str>,
    current_user: Option<UserId>,
) -> Result<LoginOutcome, ApiError> {
    let now = ctx.now();
    let bad_state = |why: &'static str| {
        let ctx = ctx.clone();
        let provider = provider.to_owned();
        async move {
            ctx.audit()
                .record(
                    AuditEvent::new(ctx.now(), "auth.login.bad_state")
                        .target(provider)
                        .detail(why),
                )
                .await;
            ApiError::BadRequest
        }
    };
    let Some(fields) = oauth_cookie.and_then(|c| unseal(ctx, &ctx.cookies().oauth, c, 6)) else {
        return Err(bad_state("missing, forged or expired flow cookie").await);
    };
    let [cookie_provider, cookie_state, nonce, verifier, return_to, intent] = &fields[..] else {
        return Err(bad_state("malformed flow cookie").await);
    };
    if cookie_provider != provider
        || code.is_empty()
        || !constant_time_eq(state.as_bytes(), cookie_state.as_bytes())
    {
        return Err(bad_state("state or provider mismatch").await);
    }
    let return_to = Some(return_to.clone()).filter(|r| safe_return_to(r).is_some());
    let p = ctx.provider(provider).ok_or(ApiError::UNKNOWN_PROVIDER)?;
    let req = AuthRequest {
        state: cookie_state.clone(),
        nonce: nonce.clone(),
        pkce_verifier: verifier.clone(),
    };
    let identity = match p
        .complete(code, &ctx.redirect_uri(provider), &req, now)
        .await
    {
        Ok(i) => i,
        Err(e) => {
            ctx.audit()
                .record(
                    AuditEvent::new(now, e.label())
                        .target(provider)
                        .detail(e.to_string()),
                )
                .await;
            return Err(match e {
                IdpError::NoVerifiedEmail { .. } => ApiError::NO_VERIFIED_EMAIL,
                _ => ApiError::UPSTREAM,
            });
        }
    };
    let new_identity = NewIdentity {
        provider: identity.provider().to_owned(),
        subject: identity.subject().to_owned(),
        email: Some(identity.email().to_owned()),
        email_verified: identity.email_verified(),
    };

    let Some(intent) = FlowIntent::decode(intent) else {
        return Err(bad_state("malformed flow intent").await);
    };
    match intent {
        FlowIntent::Login => {}
        FlowIntent::Reauth {
            user,
            link_provider,
        } => {
            // Started from an authenticated browser session; the same user
            // must still be the one logged in when it comes back.
            if current_user != Some(user) {
                return Err(bad_state("reauth flow finished without the starting session").await);
            }
            let owner = ctx
                .store()
                .user_by_identity(identity.provider(), identity.subject())
                .await
                .map_err(store_err("user_by_identity"))?;
            if owner.as_ref().map(|u| u.id) != Some(user) {
                ctx.audit()
                    .record(
                        AuditEvent::new(now, "identity.link.reauth_failed")
                            .subject(&forgs::SubjectKey::user(user))
                            .target(link_provider)
                            .detail(format!("reauth via {provider} asserted another identity")),
                    )
                    .await;
                return Err(ApiError::REAUTH_REQUIRED);
            }
            ctx.store()
                .touch_identity_login(
                    identity.provider(),
                    identity.subject(),
                    Some(identity.email()),
                    identity.email_verified(),
                    now,
                )
                .await
                .map_err(store_err("touch_identity_login"))?;
            ctx.audit()
                .record(
                    AuditEvent::new(now, "identity.link.reauth")
                        .subject(&forgs::SubjectKey::user(user))
                        .target(link_provider.clone())
                        .detail(format!("via {provider}")),
                )
                .await;
            let started = start_login(
                ctx,
                &link_provider,
                return_to.as_deref(),
                &FlowIntent::Link { user },
            )?;
            return Ok(LoginOutcome::Reauthenticated { started });
        }
        FlowIntent::Link { user } => {
            if current_user != Some(user) {
                return Err(bad_state("link flow finished without the starting session").await);
            }
            let id = ctx
                .store()
                .link_identity(user, &new_identity, now)
                .await
                .map_err(store_err("link_identity"))?;
            ctx.audit()
                .record(
                    AuditEvent::new(now, "identity.link")
                        .subject(&forgs::SubjectKey::user(user))
                        .target(provider)
                        .detail(format!("identity {id}")),
                )
                .await;
            return Ok(LoginOutcome::Linked { user, return_to });
        }
    }

    let known = ctx
        .store()
        .user_by_identity(identity.provider(), identity.subject())
        .await
        .map_err(store_err("user_by_identity"))?;
    if let Some(user) = known {
        if user.state != UserState::Active {
            ctx.audit()
                .record(
                    AuditEvent::new(now, "auth.login.disabled")
                        .subject(&forgs::SubjectKey::user(user.id))
                        .target(provider),
                )
                .await;
            return Err(ApiError::Forbidden);
        }
        ctx.store()
            .touch_identity_login(
                identity.provider(),
                identity.subject(),
                Some(identity.email()),
                identity.email_verified(),
                now,
            )
            .await
            .map_err(store_err("touch_identity_login"))?;
        let session = mint_session(ctx, user.id, &format!("browser login via {provider}")).await?;
        ctx.audit()
            .record(
                AuditEvent::new(now, "auth.login")
                    .subject(&forgs::SubjectKey::user(user.id))
                    .target(provider),
            )
            .await;
        return Ok(LoginOutcome::Session {
            session,
            user: user.id,
            return_to,
        });
    }

    // Unknown identity. Deliberately no email lookup: see the module docs.
    let expires = now.saturating_add(ctx.ttl().pending_signup);
    let ticket = ctx
        .store()
        .insert_pending_signup(&new_identity, identity.suggested_username(), now, expires)
        .await
        .map_err(store_err("insert_pending_signup"))?;
    ctx.audit()
        .record(
            AuditEvent::new(now, "auth.login.pending_signup")
                .target(provider)
                .detail(format!("ticket {ticket}")),
        )
        .await;
    let rt = return_to.clone().unwrap_or_default();
    Ok(LoginOutcome::NeedsSignup {
        ticket_cookie: seal(
            ctx,
            &ctx.cookies().signup,
            expires,
            &[&ticket.to_string(), &rt],
        ),
        return_to,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_to_is_same_origin_only() {
        for ok in ["/", "/ui", "/auth/device?code=ABCD1234", "/a/b-c_d.e~f"] {
            assert_eq!(safe_return_to(ok), Some(ok));
        }
        for bad in [
            "",
            "//evil.example",
            "/\\evil.example",
            "https://evil.example",
            "javascript:alert(1)",
            "/a\"b",
            "/a<b",
            "/a b",
            "/a\nb",
        ] {
            assert_eq!(safe_return_to(bad), None, "{bad:?}");
        }
    }
}
