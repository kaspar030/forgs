//! Membership management and renames (framework-agnostic).
//!
//! Listing a namespace's members needs membership there; changing them needs
//! the ladder's highest role (inherited roles count). A change that would
//! leave a namespace with no direct admin is refused (`409 last_admin`) —
//! otherwise one click orphans a tenant. Renames tombstone the old name
//! forever.

use forgs::api::{MemberInfo, MemberList, SessionInfo, SessionMembership};
use forgs::schema::NameOrigin;
use forgs::{NsNodeId, SubjectKey, UserId};

use crate::audit::AuditEvent;
use crate::auth::{resolve_ns, Caller};
use crate::context::AuthContext;
use crate::error::{store_err, ApiError};

/// The caller's effective role in `namespace`, or `403` (no oracle).
async fn role_in(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
) -> Result<(NsNodeId, forgs::Role), ApiError> {
    let ns = resolve_ns(ctx, namespace).await?;
    let role = ctx
        .store()
        .effective_role(ns, &SubjectKey::user(user))
        .await
        .map_err(store_err("effective_role"))?
        .ok_or(ApiError::Forbidden)?;
    Ok((ns, role))
}

async fn require_admin(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
    action: &str,
) -> Result<NsNodeId, ApiError> {
    let highest = ctx.store().roles().highest();
    match role_in(ctx, user, namespace).await {
        Ok((ns, role)) if role.satisfies(highest) => Ok(ns),
        Ok((ns, _)) => {
            ctx.audit()
                .record(
                    AuditEvent::new(ctx.now(), &format!("{action}.denied"))
                        .ns(ns)
                        .subject(&SubjectKey::user(user))
                        .detail("not an admin"),
                )
                .await;
            Err(ApiError::Forbidden)
        }
        Err(e) => Err(e),
    }
}

/// List `namespace`'s direct members.
///
/// # Errors
///
/// `403` for a non-member, `500` on storage failure.
pub async fn list(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
) -> Result<MemberList, ApiError> {
    let (ns, _) = role_in(ctx, user, namespace).await?;
    let rows = ctx
        .store()
        .scoped(ns)
        .list_members()
        .await
        .map_err(store_err("list_members"))?;
    let roles = ctx.store().roles();
    Ok(MemberList {
        namespace: ns.to_string(),
        members: rows
            .into_iter()
            .map(|m| MemberInfo {
                subject: m.subject.to_string(),
                user_id: m.user_id.map(|u| u.to_string()),
                username: m.username,
                role: roles.label(m.role).unwrap_or_default().to_owned(),
            })
            .collect(),
    })
}

/// Would removing/demoting `target` leave `ns` with no direct admin?
async fn is_last_admin(
    ctx: &AuthContext,
    ns: NsNodeId,
    target: &SubjectKey,
) -> Result<bool, ApiError> {
    let highest = ctx.store().roles().highest();
    let members = ctx
        .store()
        .scoped(ns)
        .list_members()
        .await
        .map_err(store_err("list_members"))?;
    let admins: Vec<_> = members.iter().filter(|m| m.role == highest).collect();
    Ok(admins.len() == 1 && &admins[0].subject == target)
}

async fn target_user(ctx: &AuthContext, username: &str) -> Result<UserId, ApiError> {
    // An unknown username is a 404: usernames are public handles.
    Ok(ctx
        .store()
        .user_by_username(username)
        .await
        .map_err(store_err("user_by_username"))?
        .ok_or(ApiError::NotFound)?
        .id)
}

/// Add `username` to `namespace` with `role`, or change their role.
///
/// # Errors
///
/// `403` for a non-admin, `400` for an unknown role, `404` for an unknown
/// user, `409 last_admin`, `500` on storage failure.
pub async fn set(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
    username: &str,
    role: &str,
) -> Result<(), ApiError> {
    let ns = require_admin(ctx, user, namespace, "member.set").await?;
    let role = ctx
        .store()
        .roles()
        .parse(role)
        .ok_or(ApiError::BadRequest)?;
    let target = SubjectKey::user(target_user(ctx, username).await?);
    if role != ctx.store().roles().highest() && is_last_admin(ctx, ns, &target).await? {
        return Err(ApiError::LAST_ADMIN);
    }
    let now = ctx.now();
    ctx.store()
        .scoped(ns)
        .set_member(&target, role, now)
        .await
        .map_err(store_err("set_member"))?;
    ctx.audit()
        .record(
            AuditEvent::new(now, "member.set")
                .ns(ns)
                .subject(&SubjectKey::user(user))
                .target(target.to_string())
                .detail(format!("role={}", ctx.store().roles().display(role))),
        )
        .await;
    Ok(())
}

/// Remove `username`'s direct membership in `namespace`.
///
/// # Errors
///
/// As [`set`]; `404` when they were not a direct member.
pub async fn remove(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
    username: &str,
) -> Result<(), ApiError> {
    let ns = require_admin(ctx, user, namespace, "member.remove").await?;
    let target = SubjectKey::user(target_user(ctx, username).await?);
    if is_last_admin(ctx, ns, &target).await? {
        return Err(ApiError::LAST_ADMIN);
    }
    let existed = ctx
        .store()
        .scoped(ns)
        .remove_member(&target)
        .await
        .map_err(store_err("remove_member"))?;
    if !existed {
        return Err(ApiError::NotFound);
    }
    ctx.audit()
        .record(
            AuditEvent::new(ctx.now(), "member.remove")
                .ns(ns)
                .subject(&SubjectKey::user(user))
                .target(target.to_string()),
        )
        .await;
    Ok(())
}

/// Rename the calling user (their personal namespace follows). Sessions
/// stay valid: they are keyed by the immutable user id.
///
/// # Errors
///
/// `400 username_invalid`, `409 username_taken` (incl. tombstoned),
/// `500` on storage failure.
pub async fn rename_user(
    ctx: &AuthContext,
    user: UserId,
    new_username: &str,
) -> Result<(), ApiError> {
    let now = ctx.now();
    let old = crate::session::username_of(ctx, user)
        .await
        .unwrap_or_default();
    ctx.store()
        .rename_user(user, new_username, now)
        .await
        .map_err(store_err("rename_user"))?;
    ctx.audit()
        .record(
            AuditEvent::new(now, "user.rename")
                .subject(&SubjectKey::user(user))
                .target(new_username.trim().to_ascii_lowercase())
                .detail(format!("from {old}")),
        )
        .await;
    Ok(())
}

/// Rename a non-personal namespace node the caller administers.
///
/// # Errors
///
/// `403` for a non-admin, `409 conflict` for a personal node (rename the
/// user instead), the name errors of [`rename_user`].
pub async fn rename_namespace(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
    new_name: &str,
) -> Result<(), ApiError> {
    let ns = require_admin(ctx, user, namespace, "namespace.rename").await?;
    let now = ctx.now();
    ctx.store()
        .rename_node(ns, new_name, NameOrigin::User, now)
        .await
        .map_err(store_err("rename_node"))?;
    ctx.audit()
        .record(
            AuditEvent::new(now, "namespace.rename")
                .ns(ns)
                .subject(&SubjectKey::user(user))
                .target(new_name.trim().to_owned()),
        )
        .await;
    Ok(())
}

/// Who the caller is.
///
/// # Errors
///
/// `500` on storage failure.
pub async fn whoami(ctx: &AuthContext, caller: &Caller) -> Result<SessionInfo, ApiError> {
    let mut info = SessionInfo {
        subject: caller.subject.key().to_string(),
        user_id: None,
        username: None,
        expires: caller.auth.expires,
        memberships: Vec::new(),
    };
    if let Some(user) = caller.user_id() {
        info.user_id = Some(user.to_string());
        info.username = crate::session::username_of(ctx, user).await;
        let roles = ctx.store().roles();
        info.memberships = ctx
            .store()
            .memberships_of_user(user)
            .await
            .map_err(store_err("memberships_of_user"))?
            .into_iter()
            .map(|m| SessionMembership {
                namespace: m.ns.to_string(),
                role: roles.label(m.role).unwrap_or_default().to_owned(),
            })
            .collect();
    }
    Ok(info)
}
