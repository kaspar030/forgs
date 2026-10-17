//! Users' SSH public keys (docs/design.md §3), and the
//! [`forgs::SshKeyStore`] lookup over them.
//!
//! Per-user queries, keyed by the authenticated user, plus the lookup by
//! fingerprint: a fingerprint is public, but finding a row by it yields only
//! "whose key is this", which the SSH server asks *after* the client proved
//! possession of the private key with a signature.

use async_trait::async_trait;
use forgs::store::{SshKeyRecord, SshKeyStore};
use forgs::{SshFingerprint, SshKeyId, SshKeyType, SshPublicKey, UserId};

use crate::error::{from_ts, parse_id, ts, ts_opt, Result, StoreError};
use crate::users::UserState;
use crate::{now_ms, Store};

/// How often `last_used_at` is written at most, in seconds: every git fetch
/// authenticates, and each one should not be a write.
const TOUCH_INTERVAL_SECS: u64 = 60;

/// A registered SSH public key, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKey {
    /// Immutable id (what deleting names).
    pub id: SshKeyId,
    /// The key's algorithm.
    pub key_type: SshKeyType,
    /// `type base64`, without a comment.
    pub public_key: String,
    /// The canonical fingerprint.
    pub fingerprint: SshFingerprint,
    /// The label.
    pub title: String,
    /// When it was added, epoch seconds.
    pub created_at: u64,
    /// When it last authenticated (throttled to once a minute), epoch seconds.
    pub last_used_at: Option<u64>,
    /// Expiry, epoch seconds.
    pub expires: Option<u64>,
}

type SshKeyRow = (
    String,
    String,
    String,
    String,
    String,
    i64,
    Option<i64>,
    Option<i64>,
);

/// `user_id` followed by an [`SshKeyRow`].
type OwnedSshKeyRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    Option<i64>,
    Option<i64>,
);

const COLS: &str =
    "id, key_type, public_key, fingerprint, title, created_at, last_used_at, expires";

fn key_from_row(r: SshKeyRow) -> Result<SshKey> {
    let (id, key_type, public_key, fingerprint, title, created_at, last_used_at, expires) = r;
    Ok(SshKey {
        id: parse_id!(SshKeyId, id)?,
        key_type: SshKeyType::from_name(&key_type)
            .ok_or_else(|| crate::error::corrupt("ssh key type", &key_type))?,
        public_key,
        fingerprint: SshFingerprint::parse(&fingerprint)
            .map_err(|_| crate::error::corrupt("ssh fingerprint", &fingerprint))?,
        title,
        created_at: from_ts(created_at),
        last_used_at: last_used_at.map(from_ts),
        expires: expires.map(from_ts),
    })
}

impl Store {
    /// Register `key` for `user`, unless the user already holds
    /// `max_per_user` live (unexpired) keys. The count, the uniqueness check
    /// and the insert share one `BEGIN IMMEDIATE` transaction.
    ///
    /// A fingerprint maps to exactly one user: a key already registered —
    /// to anyone, `user` included — is [`StoreError::SshKeyTaken`].
    ///
    /// # Errors
    ///
    /// [`StoreError::SshKeyTaken`], [`StoreError::KeyLimit`],
    /// [`StoreError::Dangling`] (no such user), a CHECK failure (empty
    /// title) as [`StoreError::Db`], or a database error.
    pub async fn add_ssh_key(
        &self,
        user: UserId,
        key: &SshPublicKey,
        title: &str,
        expires: Option<u64>,
        max_per_user: u64,
        now: u64,
    ) -> Result<SshKeyId> {
        let id = SshKeyId::generate(now_ms(now));
        let user_s = user.to_string();
        let fingerprint = key.fingerprint();
        let now_s = ts(now)?;
        let mut tx = self.begin().await?;
        let (taken, live): (bool, i64) = sqlx::query_as(
            "SELECT EXISTS (SELECT 1 FROM forgs_ssh_key WHERE fingerprint = ?2),
                    (SELECT COUNT(*) FROM forgs_ssh_key
                      WHERE user_id = ?1 AND (expires IS NULL OR expires > ?3))",
        )
        .bind(&user_s)
        .bind(fingerprint.as_str())
        .bind(now_s)
        .fetch_one(&mut *tx)
        .await?;
        if taken {
            return Err(StoreError::SshKeyTaken);
        }
        if u64::try_from(live).unwrap_or(0) >= max_per_user {
            return Err(StoreError::KeyLimit);
        }
        sqlx::query(
            "INSERT INTO forgs_ssh_key
                 (id, user_id, key_type, public_key, fingerprint, title, created_at, expires)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(id.to_string())
        .bind(&user_s)
        .bind(key.key_type().as_str())
        .bind(key.to_openssh())
        .bind(fingerprint.as_str())
        .bind(title)
        .bind(now_s)
        .bind(ts_opt(expires)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// `user`'s SSH keys, oldest first, expired ones included (until swept).
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::CorruptRow`].
    pub async fn ssh_keys_for_user(&self, user: UserId) -> Result<Vec<SshKey>> {
        let rows: Vec<SshKeyRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {COLS} FROM forgs_ssh_key WHERE user_id = ?1 ORDER BY created_at, id"
        )))
        .bind(user.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(key_from_row).collect()
    }

    /// One of `user`'s SSH keys by id.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::CorruptRow`].
    pub async fn ssh_key_of_user(&self, user: UserId, id: SshKeyId) -> Result<Option<SshKey>> {
        let row: Option<SshKeyRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {COLS} FROM forgs_ssh_key WHERE id = ?2 AND user_id = ?1"
        )))
        .bind(user.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(key_from_row).transpose()
    }

    /// Delete one of `user`'s SSH keys.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `id` is not a key of `user` (another
    /// user's id is indistinguishable from an unknown one), or a database
    /// error.
    pub async fn delete_ssh_key(&self, user: UserId, id: SshKeyId) -> Result<()> {
        let n = sqlx::query("DELETE FROM forgs_ssh_key WHERE id = ?2 AND user_id = ?1")
            .bind(user.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Delete every SSH key of `user` added strictly after `after` (epoch
    /// seconds) — the `logout --all` answer to "someone added an SSH key to
    /// my account". Returns how many were removed.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::TimeOverflow`].
    pub async fn delete_ssh_keys_added_after(&self, user: UserId, after: u64) -> Result<u64> {
        Ok(
            sqlx::query("DELETE FROM forgs_ssh_key WHERE user_id = ?1 AND created_at > ?2")
                .bind(user.to_string())
                .bind(ts(after)?)
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }

    /// The SSH key with this fingerprint, whoever holds it and whatever the
    /// user's state (administrative view; authentication goes through
    /// [`SshKeyStore::lookup_ssh_key`], which skips disabled users).
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::CorruptRow`].
    pub async fn ssh_key_by_fingerprint(
        &self,
        fingerprint: &SshFingerprint,
    ) -> Result<Option<(UserId, SshKey)>> {
        let row: Option<OwnedSshKeyRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT user_id, {COLS} FROM forgs_ssh_key WHERE fingerprint = ?1"
        )))
        .bind(fingerprint.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(user, a, b, c, d, e, f, g, h)| {
            Ok((
                parse_id!(UserId, user)?,
                key_from_row((a, b, c, d, e, f, g, h))?,
            ))
        })
        .transpose()
    }

    /// Record a use of key `id` at `now`. Throttled: written only when the
    /// stored `last_used_at` is absent or more than a minute older.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::TimeOverflow`].
    pub async fn touch_ssh_key(&self, id: SshKeyId, now: u64) -> Result<()> {
        sqlx::query(
            "UPDATE forgs_ssh_key SET last_used_at = ?2
              WHERE id = ?1 AND (last_used_at IS NULL OR last_used_at < ?3)",
        )
        .bind(id.to_string())
        .bind(ts(now)?)
        .bind(ts(now.saturating_sub(TOUCH_INTERVAL_SECS))?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn err(e: impl Into<StoreError>) -> String {
    e.into().to_string()
}

#[async_trait]
impl SshKeyStore for Store {
    /// The key with this fingerprint, **only if its user is active**: a
    /// disabled user's keys are kept but inert, and work again once the user
    /// is re-enabled — the same standing rule as for the API keys a user
    /// minted. Expiry is not filtered: [`forgs::authenticate_ssh_key`]
    /// reports it as `Expired`.
    async fn lookup_ssh_key(
        &self,
        fingerprint: &SshFingerprint,
    ) -> Result<Option<SshKeyRecord>, String> {
        let row: Option<(String, String, Option<i64>)> = sqlx::query_as(
            "SELECT k.id, k.user_id, k.expires FROM forgs_ssh_key k
               JOIN forgs_user u ON u.id = k.user_id
              WHERE k.fingerprint = ?1 AND u.state = ?2",
        )
        .bind(fingerprint.as_str())
        .bind(UserState::Active.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(err)?;
        row.map(|(id, user, expires)| {
            Ok(SshKeyRecord {
                id: parse_id!(SshKeyId, id).map_err(err)?,
                user_id: parse_id!(UserId, user).map_err(err)?,
                expires: expires.map(from_ts),
            })
        })
        .transpose()
    }

    async fn touch_ssh_key(&self, id: SshKeyId, now: u64) -> Result<(), String> {
        Store::touch_ssh_key(self, id, now).await.map_err(err)
    }
}
