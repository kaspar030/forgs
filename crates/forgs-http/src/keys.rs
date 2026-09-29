//! Namespace-scoped API keys (framework-agnostic).
//!
//! Two properties make it safe to let a plain member mint:
//!
//! * the namespace is a *target* checked for membership (effective role,
//!   inheritance included) — a minted key can never exceed the caller's own
//!   access, and "not a member" and "no such namespace" are the same `403`;
//! * keys minted over the API **must expire**, capped at
//!   [`crate::Ttls::api_key_max`]. A forever-key is refused rather than
//!   silently capped: quietly giving a 30-day key would be discovered a
//!   month later.
//!
//! Revocation is by hash prefix (≥ 8 hex), by the key's **creator or an
//! admin** of the namespace; an ambiguous prefix is a `409` and names no
//! candidates.

use forgs::api::{ApiKeyCreated, ApiKeyInfo, ApiKeyList, ApiKeyRevoked};
use forgs::{NsNodeId, TokenKind, UserId};
use forgs_store::NewApiKey;

use crate::audit::AuditEvent;
use crate::auth::resolve_ns;
use crate::context::AuthContext;
use crate::error::{store_err, ApiError};
use crate::hooks::PurposeKind;

/// The shortest revocation prefix, in hex characters.
pub const MIN_PREFIX_LEN: usize = 8;

/// Resolve `namespace` and require `user` to be a member (any role) there.
/// Refusals are audited and indistinguishable from "no such namespace".
async fn require_member(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
    action: &str,
) -> Result<(NsNodeId, forgs::Role), ApiError> {
    let subject = forgs::SubjectKey::user(user);
    let ns = match resolve_ns(ctx, namespace).await {
        Ok(ns) => ns,
        Err(ApiError::Forbidden) => {
            ctx.audit()
                .record(
                    AuditEvent::new(ctx.now(), &format!("{action}.denied"))
                        .subject(&subject)
                        .detail("unknown namespace"),
                )
                .await;
            return Err(ApiError::Forbidden);
        }
        Err(e) => return Err(e),
    };
    if let Some(role) = ctx
        .store()
        .effective_role(ns, &subject)
        .await
        .map_err(store_err("effective_role"))?
    {
        Ok((ns, role))
    } else {
        {
            ctx.audit()
                .record(
                    AuditEvent::new(ctx.now(), &format!("{action}.denied"))
                        .ns(ns)
                        .subject(&subject)
                        .detail("not a member"),
                )
                .await;
            Err(ApiError::Forbidden)
        }
    }
}

/// Mint a key in `namespace` for `user`.
///
/// # Errors
///
/// `403` for a non-member; `400` for a zero or over-cap TTL, an unknown
/// purpose, or a `subject_name` that is invalid or on a non-workload
/// purpose; `500` on storage failure.
pub async fn create(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
    ttl_secs: u64,
    multi_use: bool,
    purpose: &str,
    subject_name: Option<&str>,
) -> Result<ApiKeyCreated, ApiError> {
    let now = ctx.now();
    let (ns, _role) = require_member(ctx, user, namespace, "api_key").await?;
    if ttl_secs == 0 || ttl_secs > ctx.ttl().api_key_max {
        return Err(ApiError::BadRequest);
    }
    let kind = ctx.purposes().kind(purpose).ok_or(ApiError::BadRequest)?;
    // A name on a purpose that confers no subject would be a stored no-op
    // that looks effective; an invalid name is refused rather than repaired
    // (a repaired name is a different identity).
    let subject_name = match subject_name {
        None => None,
        Some(_) if kind != PurposeKind::Workload => return Err(ApiError::BadRequest),
        Some(raw) => Some(forgs::subject::normalise_service_name(raw).ok_or(ApiError::BadRequest)?),
    };
    let expires = now.saturating_add(ttl_secs);
    let token = ctx.format().mint(TokenKind::ApiKey);
    let id = ctx
        .store()
        .scoped(ns)
        .insert_api_key(
            &NewApiKey {
                hash: token.hash(),
                purpose: purpose.to_owned(),
                subject_name: subject_name.clone(),
                payload: None,
                single_use: !multi_use,
                expires: Some(expires),
                created_by: Some(user),
            },
            now,
        )
        .await
        .map_err(store_err("insert_api_key"))?;
    ctx.audit()
        .record(
            AuditEvent::new(now, "api_key.mint")
                .ns(ns)
                .subject(&forgs::SubjectKey::user(user))
                .target(token.hash().short())
                .detail(format!(
                    "purpose={purpose} as={} single_use={} ttl={ttl_secs}",
                    subject_name.as_deref().unwrap_or("-"),
                    !multi_use
                )),
        )
        .await;
    Ok(ApiKeyCreated {
        key: token.to_secret_string(),
        key_hash: token.hash().as_str().to_owned(),
        id: id.to_string(),
        namespace: ns.to_string(),
        single_use: !multi_use,
        purpose: purpose.to_owned(),
        subject_name,
        expires,
    })
}

/// List `namespace`'s keys (hashes only). Membership required.
///
/// # Errors
///
/// `403` for a non-member, `500` on storage failure.
pub async fn list(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
) -> Result<ApiKeyList, ApiError> {
    let (ns, _) = require_member(ctx, user, namespace, "api_key").await?;
    let keys = ctx
        .store()
        .scoped(ns)
        .list_api_keys()
        .await
        .map_err(store_err("list_api_keys"))?;
    Ok(ApiKeyList {
        namespace: ns.to_string(),
        keys: keys
            .into_iter()
            .map(|k| ApiKeyInfo {
                id: k.id.to_string(),
                key_hash: k.key_hash.as_str().to_owned(),
                single_use: k.single_use,
                purpose: k.purpose,
                subject_name: k.subject_name,
                expires: k.expires,
                consumed_at: k.consumed_at,
                created_at: k.created_at,
                created_by: k.created_by.map(|u| u.to_string()),
            })
            .collect(),
    })
}

/// Revoke the key in `namespace` whose hash starts with `prefix`.
///
/// # Errors
///
/// `403` for a non-member or a caller who is neither the creator nor an
/// admin (audited), `400` for a short or non-hex prefix, `404` for no match,
/// `409 ambiguous_prefix`, `500` on storage failure.
pub async fn revoke(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
    prefix: &str,
) -> Result<ApiKeyRevoked, ApiError> {
    let now = ctx.now();
    let (ns, role) = require_member(ctx, user, namespace, "api_key.revoke").await?;
    let prefix = prefix.trim().to_ascii_lowercase();
    // Load-bearing: a short prefix cannot address a key on purpose.
    if prefix.len() < MIN_PREFIX_LEN || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest);
    }
    let scope = ctx.store().scoped(ns);
    let keys = scope
        .list_api_keys()
        .await
        .map_err(store_err("list_api_keys"))?;
    let matches: Vec<_> = keys
        .iter()
        .filter(|k| k.key_hash.as_str().starts_with(&prefix))
        .collect();
    let target = match matches.as_slice() {
        [] => return Err(ApiError::NotFound),
        [one] => *one,
        _ => return Err(ApiError::AMBIGUOUS_PREFIX),
    };
    let subject = forgs::SubjectKey::user(user);
    let owned = target.created_by == Some(user);
    let admin = role.satisfies(ctx.store().roles().highest());
    if !owned && !admin {
        ctx.audit()
            .record(
                AuditEvent::new(now, "api_key.revoke.denied")
                    .ns(ns)
                    .subject(&subject)
                    .target(target.key_hash.short())
                    .detail("neither the key's creator nor an admin"),
            )
            .await;
        return Err(ApiError::Forbidden);
    }
    let revoked: Vec<String> = scope
        .delete_api_keys_by_prefix(&prefix)
        .await
        .map_err(store_err("delete_api_keys_by_prefix"))?
        .into_iter()
        .map(|h| h.as_str().to_owned())
        .collect();
    ctx.purposes()
        .on_revoked(ctx, ns, &revoked, target.subject_name.as_deref())
        .await;
    ctx.audit()
        .record(
            AuditEvent::new(now, "api_key.revoke")
                .ns(ns)
                .subject(&subject)
                .detail(revoked.join(",")),
        )
        .await;
    Ok(ApiKeyRevoked {
        namespace: ns.to_string(),
        revoked,
    })
}
