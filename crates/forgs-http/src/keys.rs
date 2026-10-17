//! Namespace-scoped API keys (framework-agnostic).
//!
//! Two properties make it safe to let a plain member mint:
//!
//! * the namespace is a *target* checked for membership (effective role,
//!   inheritance included), and "not a member" and "no such namespace" are
//!   the same `403`. A minted key can never exceed the caller's own access:
//!   naming a workload identity (`subject_name`) requires the namespace's
//!   **highest role** (a key for an existing name speaks as that identity
//!   and inherits its grants), and the payload hook receives the caller's
//!   role to cap the payload's authority ([`crate::KeyMint`]);
//! * keys minted over the API **must expire**, capped at
//!   [`crate::Ttls::api_key_max`]. A forever-key is refused rather than
//!   silently capped: quietly giving a 30-day key would be discovered a
//!   month later.
//!
//! Minting is capped by live keys per namespace and per minting user
//! ([`crate::AuthContextBuilder::max_api_keys_per_namespace`],
//! [`crate::AuthContextBuilder::max_api_keys_per_user`]; `403 key_limit`).
//! Every refused mint is audited as `api_key.denied`.
//!
//! Listings are paginated and show a 16-hex hash prefix, never the full
//! hash; a key's payload and creator are shown only to the namespace's
//! admins and to the key's creator.
//!
//! Revocation is by hash prefix (≥ 8 hex), by the key's **creator or an
//! admin** of the namespace; an ambiguous prefix is a `409` and names no
//! candidates.

use forgs::api::{ApiKeyCreated, ApiKeyInfo, ApiKeyList, ApiKeyRevoked, MAX_PAGE};
use forgs::{ApiKeyId, NsNodeId, TokenKind, UserId};
use forgs_store::{ApiKeyCap, NewApiKey, StoreError};

use crate::audit::AuditEvent;
use crate::auth::resolve_ns;
use crate::context::AuthContext;
use crate::error::{store_err, ApiError};
use crate::hooks::{KeyMint, PurposeKind};

/// The shortest revocation prefix, in hex characters.
pub const MIN_PREFIX_LEN: usize = 8;

/// How much of a key's hash a listing shows, in hex characters.
pub const LISTED_PREFIX_LEN: usize = 16;

/// A requested page size, capped at [`MAX_PAGE`]; zero is a `400`.
pub(crate) fn page_size(limit: Option<u32>) -> Result<u32, ApiError> {
    match limit {
        None => Ok(MAX_PAGE),
        Some(0) => Err(ApiError::BadRequest),
        Some(n) => Ok(n.min(MAX_PAGE)),
    }
}

/// Record a refused mint (the caller is an authenticated member: no
/// unauthenticated amplification).
async fn deny_mint(ctx: &AuthContext, ns: NsNodeId, user: UserId, why: &str) {
    ctx.audit()
        .record(
            AuditEvent::new(ctx.now(), "api_key.denied")
                .ns(ns)
                .subject(&forgs::SubjectKey::user(user))
                .detail(why),
        )
        .await;
}

/// Check a mint request's TTL, purpose and `subject_name`, returning the
/// normalised name or why it is refused (for the audit log; never echoes
/// raw caller input).
fn mint_shape(
    ctx: &AuthContext,
    ttl_secs: u64,
    purpose: &str,
    subject_name: Option<&str>,
) -> Result<Option<String>, String> {
    if ttl_secs == 0 || ttl_secs > ctx.ttl().api_key_max {
        return Err(format!("bad ttl={ttl_secs}"));
    }
    let kind = ctx
        .purposes()
        .kind(purpose)
        .ok_or_else(|| "unknown purpose".to_owned())?;
    // A name on a purpose that confers no subject would be a stored no-op
    // that looks effective; an invalid name is refused rather than repaired
    // (a repaired name is a different identity).
    match subject_name {
        None => Ok(None),
        Some(_) if kind != PurposeKind::Workload => {
            Err(format!("purpose={purpose} takes no subject_name"))
        }
        Some(raw) => forgs::subject::normalise_service_name(raw)
            .map(Some)
            .ok_or_else(|| "invalid subject_name".to_owned()),
    }
}

/// The stored payload as JSON for the response. A hook that returned
/// non-JSON is the app's bug, not the caller's: mint nothing.
fn echo_payload(
    stored: Option<&str>,
    purpose: &str,
) -> Result<Option<serde_json::Value>, ApiError> {
    stored
        .map(|p| {
            serde_json::from_str(p).map_err(|e| {
                tracing::warn!(error = %e, purpose, "check_payload returned non-JSON");
                ApiError::Internal
            })
        })
        .transpose()
}

/// The configured live-key ceilings (`u64::MAX` disables one).
fn key_caps(ctx: &AuthContext) -> ApiKeyCap {
    let cap = |n: u64| (n != u64::MAX).then_some(n);
    ApiKeyCap {
        per_namespace: cap(ctx.inner.max_api_keys_per_namespace),
        per_creator: cap(ctx.inner.max_api_keys_per_user),
    }
}

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
/// `403` for a non-member, or for a caller below the namespace's highest
/// role passing a `subject_name` (audited); `400` for a zero or over-cap TTL, an unknown
/// purpose, a `subject_name` that is invalid or on a non-workload
/// purpose, or a payload the purpose policy refuses
/// ([`crate::ApiKeyPurposes::check_payload`]); `403 key_limit` at a live-key
/// ceiling; `500` on storage failure. Every refusal past the membership
/// check is audited as `api_key.denied`.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
    ttl_secs: u64,
    multi_use: bool,
    purpose: &str,
    subject_name: Option<&str>,
    payload: Option<&serde_json::Value>,
) -> Result<ApiKeyCreated, ApiError> {
    let now = ctx.now();
    let (ns, role) = require_member(ctx, user, namespace, "api_key").await?;
    let subject_name = match mint_shape(ctx, ttl_secs, purpose, subject_name) {
        Ok(n) => n,
        Err(why) => {
            deny_mint(ctx, ns, user, &why).await;
            return Err(ApiError::BadRequest);
        }
    };

    // A named identity is derived from (ns, name) alone: a key for an
    // existing name inherits that identity's grants. Only the highest role
    // may name (or rotate) one.
    if subject_name.is_some() && !role.satisfies(ctx.store().roles().highest()) {
        deny_mint(
            ctx,
            ns,
            user,
            "naming an identity requires the highest role",
        )
        .await;
        return Err(ApiError::Forbidden);
    }
    let stored = match ctx
        .purposes()
        .check_payload(
            ctx,
            &KeyMint {
                caller: user,
                ns,
                role,
                purpose,
                subject_name: subject_name.as_deref(),
                payload,
            },
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            deny_mint(ctx, ns, user, &format!("purpose={purpose} payload refused")).await;
            return Err(e);
        }
    };
    let echoed = echo_payload(stored.as_deref(), purpose)?;
    let expires = now.saturating_add(ttl_secs);
    let token = ctx.format().mint(TokenKind::ApiKey);
    let id = match ctx
        .store()
        .scoped(ns)
        .insert_api_key_capped(
            &NewApiKey {
                hash: token.hash(),
                purpose: purpose.to_owned(),
                subject_name: subject_name.clone(),
                payload: stored,
                single_use: !multi_use,
                expires: Some(expires),
                created_by: Some(user),
            },
            now,
            key_caps(ctx),
        )
        .await
    {
        Ok(id) => id,
        Err(StoreError::KeyLimit) => {
            deny_mint(ctx, ns, user, "live key limit").await;
            return Err(ApiError::KEY_LIMIT);
        }
        Err(e) => return Err(store_err("insert_api_key")(e)),
    };
    ctx.audit()
        .record(
            AuditEvent::new(now, "api_key.mint")
                .ns(ns)
                .subject(&forgs::SubjectKey::user(user))
                .target(token.hash().short())
                .detail(format!(
                    "purpose={purpose} as={} single_use={} ttl={ttl_secs} payload={}",
                    subject_name.as_deref().unwrap_or("-"),
                    !multi_use,
                    if echoed.is_some() { "yes" } else { "-" },
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
        payload: echoed,
        expires,
    })
}

/// List one page of `namespace`'s keys, newest first. Membership required.
///
/// `before` is the previous page's [`ApiKeyList::next`]; `limit` is capped at
/// [`MAX_PAGE`]. Hashes are cut to [`LISTED_PREFIX_LEN`]; a key's payload and
/// creator are listed only for the namespace's admins and the key's creator.
///
/// # Errors
///
/// `403` for a non-member, `400` for a malformed `before` or a zero `limit`,
/// `500` on storage failure.
pub async fn list(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
    before: Option<&str>,
    limit: Option<u32>,
) -> Result<ApiKeyList, ApiError> {
    let (ns, role) = require_member(ctx, user, namespace, "api_key").await?;
    let limit = page_size(limit)?;
    let before = before
        .map(|b| ApiKeyId::parse(b.trim()).map_err(|_| ApiError::BadRequest))
        .transpose()?;
    let mut keys = ctx
        .store()
        .scoped(ns)
        .list_api_keys_page(before, limit.saturating_add(1))
        .await
        .map_err(store_err("list_api_keys_page"))?;
    let more = keys.len() > limit as usize;
    keys.truncate(limit as usize);
    let next = more
        .then(|| keys.last().map(|k| k.id.to_string()))
        .flatten();
    let admin = role.satisfies(ctx.store().roles().highest());
    Ok(ApiKeyList {
        namespace: ns.to_string(),
        keys: keys
            .into_iter()
            .map(|k| {
                let detail = admin || k.created_by == Some(user);
                ApiKeyInfo {
                    id: k.id.to_string(),
                    hash_prefix: k.key_hash.as_str()
                        [..LISTED_PREFIX_LEN.min(k.key_hash.as_str().len())]
                        .to_owned(),
                    single_use: k.single_use,
                    purpose: k.purpose,
                    subject_name: k.subject_name,
                    payload: k.payload.as_deref().filter(|_| detail).and_then(|p| {
                        serde_json::from_str(p)
                            .inspect_err(|e| {
                                // A shell-minted key may carry a non-JSON payload.
                                tracing::warn!(error = %e, key = %k.key_hash.short(),
                                    "API key payload is not JSON; not listed");
                            })
                            .ok()
                    }),
                    expires: k.expires,
                    consumed_at: k.consumed_at,
                    created_at: k.created_at,
                    created_by: k.created_by.filter(|_| detail).map(|u| u.to_string()),
                }
            })
            .collect(),
        next,
    })
}

/// Revoke the key in `namespace` whose hash starts with `prefix`.
///
/// The workload tokens already minted from the key die with it.
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
    // Two rows are enough to tell "one" from "ambiguous".
    let matches = scope
        .api_keys_by_prefix(&prefix, 2)
        .await
        .map_err(store_err("api_keys_by_prefix"))?;
    let target = match matches.as_slice() {
        [] => return Err(ApiError::NotFound),
        [one] => one,
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
