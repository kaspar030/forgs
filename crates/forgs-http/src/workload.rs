//! Workload token exchange at `POST /auth/token` (framework-agnostic).
//!
//! * `github_oidc` — a CI job's OIDC JWT, verified by a configured
//!   [`forgs_idp::WorkloadIssuer`]. The subject is
//!   `<issuer label>/workload:id:<owner_id>/<repo_id>` — immutable ids, never
//!   the reassignable `owner/repo` name, and namespaced by the issuer that
//!   verified it — and it must hold at least one live grant: a workload
//!   belongs to no tenant and reaches anything only through grants, so a
//!   token for a grantless repo would be useless and is not minted. A grant
//!   covers **every workflow on every branch** of the repo unless the
//!   issuer's [`forgs_idp::ClaimConstraints`] (ref, environment,
//!   `job_workflow_ref`, event, `ref_protected`) narrow it; a refused job is
//!   `oidc.reject.claim_not_allowed` in the audit. Each JWT is **single
//!   use**: its `(issuer, jti)` is recorded (until the JWT's `exp` + leeway)
//!   just before the mint, and a second exchange is
//!   `workload.reject.replay`. A token refused earlier (e.g. no grant yet)
//!   is not burnt.
//! * `api_key` — the weak path for a runner with no workload identity: a
//!   long-lived bearer secret in somebody's CI config. Bounded by being
//!   namespace-scoped, expiring and revocable; the workload token it mints
//!   never outlives the key. The purpose must be a
//!   [`crate::PurposeKind::Workload`] purpose, checked **before** the consume
//!   so a mis-aimed redemption does not burn a single-use key. A key is only
//!   as alive as its creator's active membership: a disabled creator, or one
//!   with no membership left on the key namespace's chain, makes the key
//!   unredeemable (shell-minted keys have no creator and are exempt), and the
//!   workload tokens it minted are linked to it, so revoking the key or
//!   disabling/removing its creator ends them immediately.
//!
//! Every verification failure is a flat `401 invalid_grant`; the reason is
//! audited, never returned.

use forgs::api::TokenResponse;
use forgs::{ApiKeyId, SubjectKey, SubjectKind, TokenKind};

use crate::audit::AuditEvent;
use crate::context::AuthContext;
use crate::error::{store_err, ApiError};
use crate::hooks::PurposeKind;

async fn mint_workload(
    ctx: &AuthContext,
    subject: &SubjectKey,
    issuer: &str,
    claims: Option<&str>,
    not_after: Option<u64>,
    source_key: Option<ApiKeyId>,
    detail: Option<&str>,
) -> Result<TokenResponse, ApiError> {
    let now = ctx.now();
    let ttl = ctx.ttl().workload.min(ctx.ttl().workload_cap);
    let mut expires = now.saturating_add(ttl);
    if let Some(cap) = not_after {
        expires = expires.min(cap);
    }
    let token = ctx.format().mint(TokenKind::Workload);
    match source_key {
        Some(key) => ctx
            .store()
            .insert_key_workload_token(&token.hash(), subject, issuer, key, now, expires)
            .await
            .map_err(store_err("insert_key_workload_token"))?,
        None => ctx
            .store()
            .insert_workload_token(&token.hash(), subject, issuer, claims, now, expires)
            .await
            .map_err(store_err("insert_workload_token"))?,
    }
    ctx.audit()
        .record(
            AuditEvent::new(now, "workload.token.mint")
                .subject(subject)
                .target(token.hash().short())
                .detail(detail.map_or_else(|| format!("issuer={issuer}"), str::to_owned)),
        )
        .await;
    Ok(TokenResponse {
        token: token.to_secret_string(),
        expires,
        username: None,
        user_id: None,
        refresh_token: None,
    })
}

/// Record the JWT's `(issuer, jti)`; a replay is `401 invalid_grant`,
/// audited as `workload.reject.replay`. Fails closed: if the mint after it
/// fails, the jti stays used and the job fetches a fresh id token.
async fn claim_jti(
    ctx: &AuthContext,
    issuer: &str,
    identity: &forgs_idp::WorkloadIdentity,
) -> Result<(), ApiError> {
    let now = ctx.now();
    let c = &identity.claims;
    if ctx
        .store()
        .record_workload_jti(
            issuer,
            &c.jti,
            &identity.subject,
            now,
            c.accept_until.max(now),
        )
        .await
        .map_err(store_err("record_workload_jti"))?
    {
        return Ok(());
    }
    ctx.audit()
        .record(
            AuditEvent::new(now, "workload.reject.replay")
                .subject(&identity.subject)
                .detail(format!(
                    "issuer={issuer} repository_id={} run_id={}",
                    c.repository_id,
                    c.run_id.as_deref().unwrap_or("-")
                )),
        )
        .await;
    Err(ApiError::InvalidGrant)
}

/// Exchange a workload OIDC JWT.
///
/// # Errors
///
/// [`ApiError::WORKLOAD_UNCONFIGURED`] with no issuer, `401 invalid_grant`
/// for any verification failure or a grantless subject, `500` on storage
/// failure.
pub async fn exchange_oidc(ctx: &AuthContext, jwt: &str) -> Result<TokenResponse, ApiError> {
    let now = ctx.now();
    if ctx.workload_issuers().is_empty() {
        return Err(ApiError::WORKLOAD_UNCONFIGURED);
    }
    let mut identity = None;
    let mut last = None;
    for issuer in ctx.workload_issuers() {
        match issuer.verify(jwt, now).await {
            Ok(id) => {
                identity = Some((issuer.name().to_owned(), issuer.subject_ns().to_owned(), id));
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let Some((issuer, subject_ns, identity)) = identity else {
        let label = last.as_ref().map_or("oidc.reject", |e| e.label());
        ctx.audit()
            .record(AuditEvent::new(now, label).detail("workload OIDC exchange"))
            .await;
        return Err(ApiError::InvalidGrant);
    };
    // Defence in depth: an issuer may only speak for subjects under its own
    // label, so a buggy or hostile issuer cannot claim another's repos.
    if identity.subject.ns() != Some(subject_ns.as_str())
        || identity.subject.kind() != SubjectKind::Workload
    {
        ctx.audit()
            .record(
                AuditEvent::new(now, "workload.reject.ns_mismatch")
                    .subject(&identity.subject)
                    .detail(format!("issuer={issuer} expected_ns={subject_ns}")),
            )
            .await;
        return Err(ApiError::InvalidGrant);
    }
    let grants = ctx
        .store()
        .grants_for_subject(&identity.subject, now)
        .await
        .map_err(store_err("grants_for_subject"))?;
    if grants.is_empty() {
        // Named in the audit with the repo and its ids: the operator's next
        // action is to grant exactly that subject. The owner is not
        // sufficient.
        ctx.audit()
            .record(
                AuditEvent::new(now, "workload.reject.no_grant")
                    .subject(&identity.subject)
                    .detail(format!(
                        "issuer={issuer} repository={} owner={} repository_id={} owner_id={}",
                        identity.claims.repository,
                        identity.claims.repository_owner,
                        identity.claims.repository_id,
                        identity.claims.repository_owner_id
                    )),
            )
            .await;
        return Err(ApiError::InvalidGrant);
    }
    let c = &identity.claims;
    // Single use, recorded last so an earlier refusal (no grant) does not
    // burn the JWT.
    claim_jti(ctx, &issuer, &identity).await?;
    let claims = serde_json::json!({
        "repository": c.repository,
        "repository_id": c.repository_id,
        "repository_owner_id": c.repository_owner_id,
        "repository_owner": c.repository_owner,
        "ref": c.git_ref,
        "ref_type": c.ref_type,
        "ref_protected": c.ref_protected,
        "environment": c.environment,
        "event_name": c.event_name,
        "workflow": c.workflow,
        "job_workflow_ref": c.job_workflow_ref,
        "runner_environment": c.runner_environment,
        "run_id": c.run_id,
        "sub": c.sub,
        "jti": c.jti,
    })
    .to_string();
    // Deliberately not capped by the JWT's `exp` (minutes): the job outlives
    // its id token. The extension is bounded by the jti's single use above
    // and by `Ttls::workload`.
    let detail = format!(
        "issuer={issuer} repository={} repository_id={} owner_id={} ref={} event={} environment={}",
        c.repository,
        c.repository_id,
        c.repository_owner_id,
        c.git_ref.as_deref().unwrap_or("-"),
        c.event_name.as_deref().unwrap_or("-"),
        c.environment.as_deref().unwrap_or("-"),
    );
    mint_workload(
        ctx,
        &identity.subject,
        &issuer,
        Some(&claims),
        None,
        None,
        Some(&detail),
    )
    .await
}

/// Redeem a workload-purpose API key.
///
/// # Errors
///
/// `401 invalid_grant` for an unknown/expired/consumed/malformed key or one
/// whose creator is disabled or no longer a member, `403`
/// for a key whose purpose is not a workload purpose, the purpose hook's
/// error, `500` on storage failure.
pub async fn exchange_api_key(ctx: &AuthContext, key: &str) -> Result<TokenResponse, ApiError> {
    let now = ctx.now();
    let hash = match forgs::verify::verify_api_key(ctx.format(), ctx.store(), key, now).await {
        Ok((hash, _)) => hash,
        Err(e) => {
            ctx.audit()
                .record(AuditEvent::new(now, e.label()).detail("api key redemption"))
                .await;
            return Err(ApiError::InvalidGrant);
        }
    };
    let meta = ctx
        .store()
        .api_key_by_hash(&hash)
        .await
        .map_err(store_err("api_key_by_hash"))?
        .ok_or(ApiError::InvalidGrant)?;
    if ctx.purposes().kind(&meta.purpose) != Some(PurposeKind::Workload) {
        ctx.audit()
            .record(
                AuditEvent::new(now, "api_key.redeem.wrong_purpose")
                    .ns(meta.ns)
                    .target(hash.short())
                    .detail(format!("purpose={}", meta.purpose)),
            )
            .await;
        return Err(ApiError::Forbidden);
    }
    // Audited pre-check of the creator's standing; the consume below
    // enforces the same rule atomically, closing the race.
    if !ctx
        .store()
        .api_key_creator_live(&meta)
        .await
        .map_err(store_err("api_key_creator_live"))?
    {
        ctx.audit()
            .record(
                AuditEvent::new(now, "api_key.redeem.creator_inactive")
                    .ns(meta.ns)
                    .target(hash.short())
                    .detail(format!(
                        "created_by={}",
                        meta.created_by
                            .map_or_else(|| "-".to_owned(), |u| u.to_string())
                    )),
            )
            .await;
        return Err(ApiError::InvalidGrant);
    }
    // The single atomic consume.
    let consumed = ctx
        .store()
        .consume_api_key(&hash, now)
        .await
        .map_err(store_err("consume_api_key"))?
        .ok_or(ApiError::InvalidGrant)?;
    // Named: an identity that survives rotation. Unnamed: derived from the
    // key's immutable id (a ULID), so every runner redeeming it is one
    // subject and no two keys can collide (a hash prefix could). The hash
    // prefix stays in logs only. The name is
    // re-validated on read: constructing a subject id from unvalidated text
    // is precisely what the charset rule exists to prevent.
    let subject = match consumed.subject_name.as_deref() {
        Some(raw) => {
            let name = forgs::subject::normalise_service_name(raw).ok_or(ApiError::Forbidden)?;
            forgs::subject::agent_subject_key(&consumed.ns, &name)
        }
        None => SubjectKey::new(
            Some(&consumed.ns.to_string()),
            SubjectKind::Workload,
            &format!("key:{}", consumed.id),
        )
        .ok_or(ApiError::Internal)?,
    };
    ctx.purposes()
        .on_workload_redeemed(ctx, &consumed, &subject)
        .await?;
    ctx.audit()
        .record(
            AuditEvent::new(now, "api_key.redeem")
                .ns(consumed.ns)
                .subject(&subject)
                .target(hash.short()),
        )
        .await;
    mint_workload(
        ctx,
        &subject,
        "api_key",
        None,
        consumed.expires,
        Some(consumed.id),
        None,
    )
    .await
}
