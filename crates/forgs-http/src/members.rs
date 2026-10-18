//! Membership management and renames (framework-agnostic).
//!
//! Listing a namespace's members needs membership there; changing them needs
//! the ladder's highest role (inherited roles count). A change that would
//! leave a namespace with no direct admin who is an active user is refused
//! (`409 last_admin`) — otherwise one click orphans a tenant — and a personal
//! namespace's own user cannot be removed or demoted there (`409 conflict`).
//! Both checks and the caller's role are re-read in the write's transaction,
//! so concurrent changes cannot race past them. Renames tombstone the old name
//! forever, so releasing root names is rate-limited per user and per renamed
//! user / node (`429 rate_limited`; `forgs_store::Store::with_release_limit`).
//!
//! [`create_namespace`] creates a node and makes its creator the admin in one
//! store transaction, optionally capped by how many such nodes the creator
//! already owns; [`delete_namespace`] deletes an empty, non-personal node.

use forgs::api::{MemberInfo, MemberList, SessionInfo, SessionMembership};
use forgs::schema::NameOrigin;
use forgs::{NsNodeId, SubjectKey, UserId};
use forgs_store::StoreError;

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
        // A non-member or an unknown namespace: the same 403, audited too
        // (the caller is authenticated, so this is not free amplification).
        // The namespace is not resolvable here, so the raw name is the
        // target, truncated.
        Err(ApiError::Forbidden) => {
            ctx.audit()
                .record(
                    AuditEvent::new(ctx.now(), &format!("{action}.denied"))
                        .subject(&SubjectKey::user(user))
                        .target(namespace.trim().chars().take(128).collect::<String>())
                        .detail("not a member or no such namespace"),
                )
                .await;
            Err(ApiError::Forbidden)
        }
        Err(e) => Err(e),
    }
}

/// List one page of `namespace`'s direct members, by subject.
///
/// `after` is the previous page's [`MemberList::next`]; `limit` is capped at
/// [`forgs::api::MAX_PAGE`].
///
/// # Errors
///
/// `403` for a non-member, `400` for a zero `limit`, `500` on storage
/// failure.
pub async fn list(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
    after: Option<&str>,
    limit: Option<u32>,
) -> Result<MemberList, ApiError> {
    let (ns, _) = role_in(ctx, user, namespace).await?;
    let limit = crate::keys::page_size(limit)?;
    let mut rows = ctx
        .store()
        .scoped(ns)
        .list_members_page(after, limit.saturating_add(1))
        .await
        .map_err(store_err("list_members_page"))?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = more
        .then(|| rows.last().map(|m| m.subject.to_string()))
        .flatten();
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
        next,
    })
}

/// How a refused guarded membership write is reported. `NotAdmin` means the
/// caller lost the admin role between the pre-check and the write.
fn member_err(what: &'static str) -> impl Fn(StoreError) -> ApiError {
    move |e| match e {
        StoreError::NotAdmin => ApiError::Forbidden,
        StoreError::LastAdmin => ApiError::LAST_ADMIN,
        StoreError::PersonalOwner => ApiError::CONFLICT,
        other => store_err(what)(other),
    }
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

/// As [`target_user`], but a user still waiting for signup approval is
/// reported exactly like an unknown one: they cannot be added anywhere
/// before approval.
async fn addable_user(ctx: &AuthContext, username: &str) -> Result<UserId, ApiError> {
    let u = ctx
        .store()
        .user_by_username(username)
        .await
        .map_err(store_err("user_by_username"))?
        .ok_or(ApiError::NotFound)?;
    if u.state == forgs_store::UserState::Pending {
        return Err(ApiError::NotFound);
    }
    Ok(u.id)
}

/// Add `username` to `namespace` with `role`, or change their role.
///
/// # Errors
///
/// `403` for a non-admin, `400` for an unknown role, `404` for an unknown
/// user, `409 last_admin` when no other active user would remain a direct
/// admin, `409 conflict` for demoting a personal namespace's own user,
/// `500` on storage failure.
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
    let target = SubjectKey::user(addable_user(ctx, username).await?);
    let now = ctx.now();
    // The store re-checks the caller's role and the last-admin guard inside
    // the write's transaction: the pre-check above only orders the errors.
    ctx.store()
        .scoped(ns)
        .set_member_guarded(&SubjectKey::user(user), &target, role, now)
        .await
        .map_err(member_err("set_member_guarded"))?;
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
/// If that leaves them no membership on a namespace chain where they minted
/// API keys, those keys stop redeeming and the workload tokens minted from
/// them are deleted (the store does this in the same transaction).
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
    let existed = ctx
        .store()
        .scoped(ns)
        .remove_member_guarded(&SubjectKey::user(user), &target)
        .await
        .map_err(member_err("remove_member_guarded"))?;
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
/// `429 rate_limited` past the store's release limit (the old name would be
/// tombstoned; see `forgs_store::Store::with_release_limit`), `500` on
/// storage failure.
pub async fn rename_user(
    ctx: &AuthContext,
    user: UserId,
    new_username: &str,
) -> Result<(), ApiError> {
    let now = ctx.now();
    let old = crate::session::username_of(ctx, user)
        .await
        .unwrap_or_default();
    let r = ctx
        .store()
        .rename_user(user, new_username, Some(user), now)
        .await;
    if matches!(r, Err(StoreError::ReleaseLimited)) {
        ctx.audit()
            .record(
                AuditEvent::new(now, "user.rename.limited")
                    .subject(&SubjectKey::user(user))
                    .target(new_username.trim().to_ascii_lowercase())
                    .detail(format!("from {old}")),
            )
            .await;
    }
    r.map_err(store_err("rename_user"))?;
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

/// Create a namespace node of `kind` named `name` under `parent` (`None`:
/// the root), owned by `user`, with `user` as a member holding the ladder's
/// highest role — atomically.
///
/// Under a parent the caller needs the highest role there (inherited roles
/// count); at the root any authenticated user may create. With
/// `max_owned = Some(cap)` the creation is refused once `user` owns `cap`
/// non-personal nodes of `kind` under `parent` (a hard cap).
///
/// # Errors
///
/// `403` for an unknown parent or a non-admin there, `403 namespace_limit`
/// at the cap, `400` for an unknown kind or a kind not allowed under the
/// parent, `400 username_invalid` for a bad name, `409 username_taken` for a
/// taken or released name.
pub async fn create_namespace(
    ctx: &AuthContext,
    user: UserId,
    parent: Option<&str>,
    kind: &str,
    name: &str,
    max_owned: Option<u64>,
) -> Result<NsNodeId, ApiError> {
    let parent_id = match parent {
        Some(p) => Some(require_admin(ctx, user, p, "namespace.create").await?),
        None => None,
    };
    let now = ctx.now();
    let ns = ctx
        .store()
        .create_node_with_admin(
            parent_id,
            kind,
            name,
            NameOrigin::User,
            user,
            max_owned,
            now,
        )
        .await
        .map_err(|e| match e {
            StoreError::UnknownKind(_) | StoreError::BadPlacement { .. } => {
                tracing::debug!(error = %e, "create_node_with_admin: bad kind");
                ApiError::BadRequest
            }
            other => store_err("create_node_with_admin")(other),
        })?;
    ctx.audit()
        .record(
            AuditEvent::new(now, "namespace.create")
                .ns(ns)
                .subject(&SubjectKey::user(user))
                .target(name.trim().to_owned())
                .detail(format!("kind={kind}")),
        )
        .await;
    Ok(ns)
}

/// How a failed node deletion is reported.
fn delete_err(e: StoreError) -> ApiError {
    match e {
        StoreError::HasChildren | StoreError::Dangling => ApiError::NOT_EMPTY,
        StoreError::PersonalNode => ApiError::CONFLICT,
        other => store_err("delete_node")(other),
    }
}

/// Delete a non-personal namespace node the caller administers. Its name is
/// tombstoned; memberships, keys and grants bound to it go with it.
///
/// # Errors
///
/// `403` for an unknown namespace or a non-admin, `409 conflict` for a
/// personal node (delete the user instead), `409 not_empty` while the node
/// has children or app data still references it, `429 rate_limited` for a
/// root node past the caller's release limit.
pub async fn delete_namespace(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
) -> Result<(), ApiError> {
    let ns = require_admin(ctx, user, namespace, "namespace.delete").await?;
    let name = ctx
        .store()
        .node(ns)
        .await
        .map_err(store_err("node"))?
        .map_or_else(|| namespace.to_owned(), |n| n.name);
    let now = ctx.now();
    ctx.store()
        .delete_node(ns, Some(user), now)
        .await
        .map_err(delete_err)?;
    ctx.audit()
        .record(
            AuditEvent::new(now, "namespace.delete")
                .ns(ns)
                .subject(&SubjectKey::user(user))
                .target(name),
        )
        .await;
    Ok(())
}

/// Rename a non-personal namespace node the caller administers.
///
/// # Errors
///
/// `403` for a non-admin, `409 conflict` for a personal node (rename the
/// user instead), the name errors of [`rename_user`] (including
/// `429 rate_limited` for a root node).
pub async fn rename_namespace(
    ctx: &AuthContext,
    user: UserId,
    namespace: &str,
    new_name: &str,
) -> Result<(), ApiError> {
    let ns = require_admin(ctx, user, namespace, "namespace.rename").await?;
    let now = ctx.now();
    let r = ctx
        .store()
        .rename_node(ns, new_name, NameOrigin::User, Some(user), now)
        .await;
    if matches!(r, Err(StoreError::ReleaseLimited)) {
        ctx.audit()
            .record(
                AuditEvent::new(now, "namespace.rename.limited")
                    .ns(ns)
                    .subject(&SubjectKey::user(user))
                    .target(new_name.trim().to_owned()),
            )
            .await;
    }
    r.map_err(store_err("rename_node"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_errors_map_to_conflicts() {
        assert_eq!(delete_err(StoreError::HasChildren), ApiError::NOT_EMPTY);
        assert_eq!(delete_err(StoreError::Dangling), ApiError::NOT_EMPTY);
        assert_eq!(delete_err(StoreError::PersonalNode), ApiError::CONFLICT);
        assert_eq!(delete_err(StoreError::NotFound), ApiError::NotFound);
    }
}
