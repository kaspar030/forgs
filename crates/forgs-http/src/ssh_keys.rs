//! The caller's SSH public keys: list, add, delete (docs/design.md §3).
//!
//! Users only: a workload or app caller is `403`. Keys are identity data like
//! linked logins, so they are managed with a session (bearer, or cookie +
//! CSRF from a browser). The consumer's SSH server maps an authenticated key
//! back to the user with [`forgs::authenticate_ssh_key`] over the store.

use forgs::api::{SshKeyAddRequest, SshKeyDeleteRequest, SshKeyInfo, SshKeyList};
use forgs::{SshKeyId, SshPublicKey, SubjectKey, UserId};
use forgs_store::{SshKey, StoreError};

use crate::audit::AuditEvent;
use crate::auth::Caller;
use crate::context::AuthContext;
use crate::error::{store_err, ApiError};

/// The longest title accepted, in characters.
pub const MAX_TITLE_CHARS: usize = 256;

fn info(k: SshKey) -> SshKeyInfo {
    SshKeyInfo {
        id: k.id.to_string(),
        key_type: k.key_type.as_str().to_owned(),
        fingerprint: k.fingerprint.to_string(),
        public_key: k.public_key,
        title: k.title,
        created_at: k.created_at,
        last_used_at: k.last_used_at,
        expires_at: k.expires,
    }
}

async fn deny(ctx: &AuthContext, user: UserId, target: &str, why: &str) {
    ctx.audit()
        .record(
            AuditEvent::new(ctx.now(), "ssh_key.denied")
                .subject(&SubjectKey::user(user))
                .target(target)
                .detail(why),
        )
        .await;
}

/// `GET /auth/keys/ssh` — the caller's SSH keys, oldest first.
///
/// # Errors
///
/// [`ApiError::Forbidden`] for a non-user caller, `500` on storage failure.
pub async fn list(ctx: &AuthContext, caller: &Caller) -> Result<SshKeyList, ApiError> {
    let user = caller.require_user()?;
    let rows = ctx
        .store()
        .ssh_keys_for_user(user)
        .await
        .map_err(store_err("ssh_keys_for_user"))?;
    Ok(SshKeyList {
        keys: rows.into_iter().map(info).collect(),
    })
}

/// Validate a title: trimmed, no control characters, at most
/// [`MAX_TITLE_CHARS`].
fn clean_title(raw: &str) -> Option<String> {
    let t = raw.trim();
    (!t.is_empty() && t.chars().count() <= MAX_TITLE_CHARS && !t.chars().any(char::is_control))
        .then(|| t.to_owned())
}

/// `POST /auth/keys/ssh` — register an SSH public key for the caller.
///
/// The title defaults to the key's comment, else `<type> <fingerprint
/// prefix>`.
///
/// # Errors
///
/// `400 invalid_request` for a refused or malformed key, a bad title or a
/// past expiry; `409 ssh_key_taken` if the key is registered already (to
/// anyone); `403 key_limit` at the per-user cap; [`ApiError::Forbidden`] for
/// a non-user caller; `500` on storage failure.
pub async fn add(
    ctx: &AuthContext,
    caller: &Caller,
    req: &SshKeyAddRequest,
) -> Result<SshKeyInfo, ApiError> {
    let user = caller.require_user()?;
    let now = ctx.now();
    let key = match SshPublicKey::parse_openssh(&req.public_key) {
        Ok(k) => k,
        Err(e) => {
            deny(ctx, user, "", &e.to_string()).await;
            return Err(ApiError::BadRequest);
        }
    };
    let fingerprint = key.fingerprint();
    let title = match req.title.as_deref() {
        Some(t) => clean_title(t).ok_or(ApiError::BadRequest)?,
        None => key.comment().and_then(clean_title).unwrap_or_else(|| {
            let fp = fingerprint.as_str();
            format!("{} {}", key.key_type(), &fp[..fp.len().min(19)])
        }),
    };
    if req.expires_at.is_some_and(|e| e <= now) {
        return Err(ApiError::BadRequest);
    }
    let id = match ctx
        .store()
        .add_ssh_key(
            user,
            &key,
            &title,
            req.expires_at,
            ctx.inner.max_ssh_keys_per_user,
            now,
        )
        .await
    {
        Ok(id) => id,
        Err(StoreError::SshKeyTaken) => {
            deny(ctx, user, fingerprint.as_str(), "key already registered").await;
            return Err(ApiError::SSH_KEY_TAKEN);
        }
        Err(StoreError::KeyLimit) => {
            deny(ctx, user, fingerprint.as_str(), "per-user ssh key limit").await;
            return Err(ApiError::KEY_LIMIT);
        }
        Err(e) => return Err(store_err("add_ssh_key")(e)),
    };
    ctx.audit()
        .record(
            AuditEvent::new(now, "ssh_key.add")
                .subject(&SubjectKey::user(user))
                .target(fingerprint.as_str())
                .detail(format!("ssh key {id} {}", key.key_type())),
        )
        .await;
    let row = ctx
        .store()
        .ssh_key_of_user(user, id)
        .await
        .map_err(store_err("ssh_key_of_user"))?
        .ok_or(ApiError::Internal)?;
    Ok(info(row))
}

/// `POST /auth/keys/ssh/delete` — remove one of the caller's SSH keys.
///
/// # Errors
///
/// [`ApiError::NotFound`] for an unknown id or another user's (alike: no
/// oracle), [`ApiError::Forbidden`] for a non-user caller, `500` on storage
/// failure.
pub async fn delete(
    ctx: &AuthContext,
    caller: &Caller,
    req: &SshKeyDeleteRequest,
) -> Result<(), ApiError> {
    let user = caller.require_user()?;
    let id = SshKeyId::parse(req.id.trim()).map_err(|_| ApiError::NotFound)?;
    let key = ctx
        .store()
        .ssh_key_of_user(user, id)
        .await
        .map_err(store_err("ssh_key_of_user"))?
        .ok_or(ApiError::NotFound)?;
    match ctx.store().delete_ssh_key(user, id).await {
        Ok(()) => {}
        Err(StoreError::NotFound) => return Err(ApiError::NotFound),
        Err(e) => return Err(store_err("delete_ssh_key")(e)),
    }
    ctx.audit()
        .record(
            AuditEvent::new(ctx.now(), "ssh_key.delete")
                .subject(&SubjectKey::user(user))
                .target(key.fingerprint.as_str())
                .detail(format!("ssh key {id} {}", key.key_type)),
        )
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles() {
        assert_eq!(clean_title("  laptop "), Some("laptop".into()));
        assert_eq!(clean_title(""), None);
        assert_eq!(clean_title("a\nb"), None);
        assert_eq!(clean_title(&"x".repeat(257)), None);
        assert!(clean_title(&"x".repeat(256)).is_some());
    }
}
