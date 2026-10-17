//! Credentials looked up or revoked by token hash, and the one deliberately
//! cross-namespace read, [`Store::grants_for_subject`].
//!
//! Every hash-keyed query here is unscoped by design: the hash *is* the
//! capability, so a caller can only reach a row whose secret it holds.

use forgs::{ApiKeyId, GrantId, NsNodeId, SubjectKey, TokenHash, UserId};

use crate::error::{from_ts, parse_id, ts, Result};
use crate::Store;

/// One stored grant.
///
/// Deliberately **unvalidated**: `subject`, `selector` and `ops` are the raw
/// stored strings, because a row whose selector no longer parses must be
/// visible (and revocable) rather than poisoning the whole query. Turning a
/// row into something that grants access is the app's job and must fail
/// closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRow {
    /// Grant id.
    pub id: GrantId,
    /// The granting namespace (the fence: the grant covers its subtree).
    pub ns: NsNodeId,
    /// The rendered subject key the grant was issued to.
    pub subject: String,
    /// Canonical selector text.
    pub selector: String,
    /// Canonical ops text.
    pub ops: String,
    /// Expiry, epoch seconds.
    pub expires: Option<u64>,
    /// The granting user.
    pub created_by: Option<UserId>,
    /// Creation time, epoch seconds.
    pub created_at: u64,
}

pub(crate) type GrantDbRow = (
    String,
    String,
    String,
    String,
    String,
    Option<i64>,
    Option<String>,
    i64,
);

pub(crate) const GRANT_COLS: &str =
    "id, ns_node_id, subject, selector, ops, expires, created_by, created_at";

pub(crate) fn grant_from_row(r: GrantDbRow) -> Result<GrantRow> {
    let (id, ns, subject, selector, ops, expires, created_by, created_at) = r;
    Ok(GrantRow {
        id: parse_id!(GrantId, id)?,
        ns: parse_id!(NsNodeId, ns)?,
        subject,
        selector,
        ops,
        expires: expires.map(from_ts),
        created_by: created_by.map(|u| parse_id!(UserId, u)).transpose()?,
        created_at: from_ts(created_at),
    })
}

/// An API key that was just redeemed by [`Store::consume_api_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedApiKey {
    /// The key id.
    pub id: ApiKeyId,
    /// The namespace it is scoped to.
    pub ns: NsNodeId,
    /// What it is for; the app's redemption dispatches on it.
    pub purpose: String,
    /// The identity name, if any.
    pub subject_name: Option<String>,
    /// App payload.
    pub payload: Option<String>,
    /// Whether it was single-use (and is now consumed).
    pub single_use: bool,
    /// Expiry, which e.g. a synthesised grant inherits.
    pub expires: Option<u64>,
    /// Who minted it.
    pub created_by: Option<UserId>,
}

/// A session consumed by [`Store::consume_session`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumedSession {
    /// The session's user.
    pub user_id: UserId,
    /// When the session's refresh chain was originally authenticated.
    pub auth_time: u64,
}

type ApiKeyRecordRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    bool,
    Option<i64>,
    Option<String>,
);

fn consumed_from_row(r: ApiKeyRecordRow) -> Result<ConsumedApiKey> {
    let (id, ns, purpose, subject_name, payload, single_use, expires, created_by) = r;
    Ok(ConsumedApiKey {
        id: parse_id!(ApiKeyId, id)?,
        ns: parse_id!(NsNodeId, ns)?,
        purpose,
        subject_name,
        payload,
        single_use,
        // A negative stored expiry becomes 0: expired, never unbounded.
        expires: expires.map(from_ts),
        created_by: created_by.map(|u| parse_id!(UserId, u)).transpose()?,
    })
}

const API_KEY_COLS: &str =
    "id, ns_node_id, purpose, subject_name, payload, single_use, expires, created_by";

impl Store {
    /// Insert a user session (by token hash).
    ///
    /// `auth_time` is when the session's refresh chain was originally
    /// authenticated: `issued_at` for a fresh login, the predecessor's
    /// `auth_time` for a session refresh.
    ///
    /// The user must exist: the foreign key makes a session for a
    /// nonexistent user fail loudly here rather than become a valid token
    /// belonging to nobody.
    ///
    /// # Errors
    ///
    /// [`crate::StoreError::Dangling`] or a database error.
    pub async fn insert_session(
        &self,
        hash: &TokenHash,
        user: UserId,
        issued_at: u64,
        auth_time: u64,
        expires: u64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO forgs_session (token_hash, user_id, issued_at, auth_time, expires)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(hash.as_str())
        .bind(user.to_string())
        .bind(ts(issued_at)?)
        .bind(ts(auth_time)?)
        .bind(ts(expires)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically consume a live session for a refresh, in **one statement**.
    ///
    /// Deletes the session if it is unexpired (`expires > now`; expiry is
    /// exclusive) and its chain is younger than the absolute limit
    /// (`auth_time > min_auth_time`), returning its user and `auth_time`.
    /// Concurrent refreshers race on the `DELETE`, so exactly one of them
    /// gets the row: one stolen session cannot be forked into several.
    ///
    /// Returns `None` when the session is unknown, already consumed,
    /// expired, or past its chain's absolute lifetime (an expired or
    /// over-age row is left alone).
    ///
    /// # Errors
    ///
    /// [`crate::StoreError::CorruptRow`] or a database error.
    pub async fn consume_session(
        &self,
        hash: &TokenHash,
        now: u64,
        min_auth_time: u64,
    ) -> Result<Option<ConsumedSession>> {
        let row: Option<(String, i64)> = sqlx::query_as(
            "DELETE FROM forgs_session
             WHERE token_hash = ?1 AND expires > ?2 AND auth_time > ?3
             RETURNING user_id, auth_time",
        )
        .bind(hash.as_str())
        .bind(ts(now)?)
        .bind(ts(min_auth_time)?)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(user, auth_time)| {
            Ok(ConsumedSession {
                user_id: parse_id!(UserId, user)?,
                auth_time: from_ts(auth_time),
            })
        })
        .transpose()
    }

    /// Delete a session (logout). Returns whether it existed.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn delete_session(&self, hash: &TokenHash) -> Result<bool> {
        let n = sqlx::query("DELETE FROM forgs_session WHERE token_hash = ?1")
            .bind(hash.as_str())
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n > 0)
    }

    /// Delete every session of `user` (`logout --all`, the revocation
    /// answer for a lost machine: "revoke all of mine"). Returns the count.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn delete_sessions_for_user(&self, user: UserId) -> Result<u64> {
        Ok(sqlx::query("DELETE FROM forgs_session WHERE user_id = ?1")
            .bind(user.to_string())
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    /// Insert a refresh token (by hash). Same foreign-key discipline as
    /// [`Store::insert_session`].
    ///
    /// # Errors
    ///
    /// [`crate::StoreError::Dangling`] or a database error.
    pub async fn insert_refresh_token(
        &self,
        hash: &TokenHash,
        user: UserId,
        issued_at: u64,
        expires: u64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO forgs_refresh_token (token_hash, user_id, issued_at, expires, created_at)
             VALUES (?1, ?2, ?3, ?4, ?3)",
        )
        .bind(hash.as_str())
        .bind(user.to_string())
        .bind(ts(issued_at)?)
        .bind(ts(expires)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete one refresh token (logout).
    ///
    /// Note what is absent: no redemption path calls this. Redemption is
    /// non-rotating by design, which is what lets concurrent clients each
    /// redeem and each keep a working session.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn delete_refresh_token(&self, hash: &TokenHash) -> Result<bool> {
        let n = sqlx::query("DELETE FROM forgs_refresh_token WHERE token_hash = ?1")
            .bind(hash.as_str())
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n > 0)
    }

    /// Delete every refresh token of `user` (the other half of
    /// `logout --all`).
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn delete_refresh_tokens_for_user(&self, user: UserId) -> Result<u64> {
        Ok(
            sqlx::query("DELETE FROM forgs_refresh_token WHERE user_id = ?1")
                .bind(user.to_string())
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }

    /// Record a minted workload token.
    ///
    /// Not namespace-scoped: **a workload belongs to no tenant** (see the
    /// migration). `issuer` names what minted it (`github_oidc`, `api_key`,
    /// an app label); `claims` is JSON recorded for audit and never read by
    /// an authorization decision.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn insert_workload_token(
        &self,
        hash: &TokenHash,
        subject: &SubjectKey,
        issuer: &str,
        claims: Option<&str>,
        issued_at: u64,
        expires: u64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO forgs_workload_token (token_hash, subject, issuer, claims, issued_at, expires)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(hash.as_str())
        .bind(subject.to_string())
        .bind(issuer)
        .bind(claims)
        .bind(ts(issued_at)?)
        .bind(ts(expires)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// An unconsumed API key by hash, **without** consuming it, and without
    /// checking expiry (so the app can read `purpose` before the consume and
    /// refuse a wrong-purpose key without burning it).
    ///
    /// # Errors
    ///
    /// [`crate::StoreError::CorruptRow`] or a database error.
    pub async fn api_key_by_hash(&self, hash: &TokenHash) -> Result<Option<ConsumedApiKey>> {
        let row: Option<ApiKeyRecordRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {API_KEY_COLS} FROM forgs_api_key WHERE key_hash = ?1 AND consumed_at IS NULL"
        )))
        .bind(hash.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(consumed_from_row).transpose()
    }

    /// Atomically redeem an API key: existence, single use and expiry, in
    /// **one statement**.
    ///
    /// A single-use key is marked consumed; a multi-use key is left
    /// redeemable. Doing this as one `UPDATE … RETURNING` is what makes
    /// "single use" mean single use under concurrent redemption, rather than
    /// a check followed by a racy write. Expiry is exclusive: `now ==
    /// expires` is expired.
    ///
    /// Returns `None` when the key is unknown, already consumed, or expired.
    ///
    /// # Errors
    ///
    /// [`crate::StoreError::CorruptRow`] or a database error.
    pub async fn consume_api_key(
        &self,
        hash: &TokenHash,
        now: u64,
    ) -> Result<Option<ConsumedApiKey>> {
        let row: Option<ApiKeyRecordRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "UPDATE forgs_api_key
                SET consumed_at = CASE WHEN single_use != 0 THEN ?2 ELSE consumed_at END
              WHERE key_hash = ?1
                AND consumed_at IS NULL
                AND (expires IS NULL OR expires > ?2)
             RETURNING {API_KEY_COLS}"
        )))
        .bind(hash.as_str())
        .bind(ts(now)?)
        .fetch_optional(&self.pool)
        .await?;
        row.map(consumed_from_row).transpose()
    }

    /// Every live grant issued **to** `subject`, across all namespaces.
    ///
    /// # Why this is not on [`crate::NsScope`]
    ///
    /// This is the single query that deliberately reads outside the
    /// namespace-scoping type, and it needs to read as a decision rather than
    /// an oversight: **a grant's entire purpose is to cross a namespace
    /// boundary.** Scoping it to the caller's namespace would return exactly
    /// the rows that do not matter. The scoping key here is the *subject*
    /// instead, and that is not weaker: a `SubjectKey` is derived from the
    /// authenticated `Subject`, and there is no wire field a caller can use to
    /// name a different one — the same structural property that makes
    /// `NsScope` safe, applied to a different column. The namespace fence
    /// (the resource must lie in the granting node's subtree) is then applied
    /// by `forgs::authz`.
    ///
    /// Expired rows are filtered here (exclusive: `expires == now` is
    /// expired), so a stale grant cannot widen access even if a caller
    /// forgets the `now` check downstream; `forgs::authz` checks again anyway.
    ///
    /// # Errors
    ///
    /// [`crate::StoreError::CorruptRow`] or a database error.
    pub async fn grants_for_subject(
        &self,
        subject: &SubjectKey,
        now: u64,
    ) -> Result<Vec<GrantRow>> {
        let rows: Vec<GrantDbRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {GRANT_COLS} FROM forgs_grant
              WHERE subject = ?1 AND (expires IS NULL OR expires > ?2)
              ORDER BY created_at DESC, id DESC"
        )))
        .bind(subject.to_string())
        .bind(ts(now)?)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(grant_from_row).collect()
    }
}
