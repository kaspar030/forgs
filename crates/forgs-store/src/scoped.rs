//! [`NsScope`]: the namespace-scoped handle. Every statement here binds the
//! handle's namespace id, so a query spanning namespaces is not expressible
//! through it.

use forgs::{ApiKeyId, GrantId, NsNodeId, Role, SubjectKey, SubjectKind, TokenHash, UserId};

use crate::credentials::{grant_from_row, GrantDbRow, GrantRow, GRANT_COLS};
use crate::error::{from_ts, parse_id, ts, ts_opt, Result, StoreError};
use crate::{now_ms, Store};

/// A [`Store`] handle scoped to exactly one namespace node.
///
/// Tenant isolation is a property of the type, not of reviewer vigilance:
/// every method binds `self.ns` into its statement.
#[derive(Debug, Clone)]
pub struct NsScope<'a> {
    store: &'a Store,
    ns: NsNodeId,
}

/// One member of a namespace (direct membership only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRow {
    /// The member.
    pub subject: SubjectKey,
    /// The member's user id, for user subjects.
    pub user_id: Option<UserId>,
    /// The member's username, for user subjects (display only).
    pub username: Option<String>,
    /// The direct role.
    pub role: Role,
    /// When the membership was created, epoch seconds.
    pub created_at: u64,
}

/// An API key to mint. The secret itself is never passed in: only its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApiKey {
    /// The key's hash.
    pub hash: TokenHash,
    /// What the key is for (app-defined, non-empty).
    pub purpose: String,
    /// A stable identity name that survives rotation. `None` is the only
    /// spelling of "no name"; `Some("")` is refused by the schema.
    pub subject_name: Option<String>,
    /// App-defined JSON payload, opaque to forgs.
    pub payload: Option<String>,
    /// Whether redeeming the key consumes it.
    pub single_use: bool,
    /// Expiry, epoch seconds. Keys minted over an API must expire; that
    /// policy is the route's.
    pub expires: Option<u64>,
    /// The minting user, `None` for a shell-minted key.
    pub created_by: Option<UserId>,
}

/// An API key as an operator sees it. Hash-only: the secret was never
/// stored, so a listing is safe to print, pipe and log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyRow {
    /// The key id.
    pub id: ApiKeyId,
    /// The key's hash; a prefix of it is the revocation handle.
    pub key_hash: TokenHash,
    /// What the key is for.
    pub purpose: String,
    /// The identity name, if any.
    pub subject_name: Option<String>,
    /// App payload.
    pub payload: Option<String>,
    /// Whether redeeming consumes it.
    pub single_use: bool,
    /// Expiry, epoch seconds.
    pub expires: Option<u64>,
    /// Who minted it. Load-bearing for creator-or-admin revocation.
    pub created_by: Option<UserId>,
    /// When it was minted.
    pub created_at: u64,
    /// When a single-use key was consumed.
    pub consumed_at: Option<u64>,
}

/// A grant to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGrant {
    /// Who receives it.
    pub subject: SubjectKey,
    /// Canonical rendering of the app's selector (evaluation re-parses it, so
    /// storing whatever the user typed would make its meaning depend on
    /// which client wrote it).
    pub selector: String,
    /// Canonical rendering of the app's ops.
    pub ops: String,
    /// Expiry, epoch seconds.
    pub expires: Option<u64>,
    /// The granting user. Load-bearing for creator-or-admin revocation.
    pub created_by: Option<UserId>,
}

/// An audit entry to append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEntry<'a> {
    /// When, epoch seconds.
    pub ts: u64,
    /// Who acted.
    pub subject: Option<&'a SubjectKey>,
    /// A stable action label (`auth.login`, `member.add`).
    pub action: &'a str,
    /// What was acted on.
    pub target: Option<&'a str>,
    /// App JSON detail.
    pub detail: Option<&'a str>,
}

/// An audit row read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    /// Row id (monotonic).
    pub id: i64,
    /// When, epoch seconds.
    pub ts: u64,
    /// The namespace, `None` for events outside any.
    pub ns: Option<NsNodeId>,
    /// Rendered subject key (raw: kept even if it no longer parses).
    pub subject: Option<String>,
    /// Action label.
    pub action: String,
    /// Target.
    pub target: Option<String>,
    /// Detail.
    pub detail: Option<String>,
}

/// Minimum length of a revocation prefix: short enough to type, long enough
/// that a typo does not revoke a neighbour.
pub(crate) const MIN_PREFIX: usize = 8;

type ApiKeyDbRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    bool,
    Option<i64>,
    Option<String>,
    i64,
    Option<i64>,
);

type MemberDbRow = (String, Option<String>, Option<String>, String, i64);

type AuditDbRow = (
    i64,
    i64,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
);

pub(crate) async fn append_audit(
    store: &Store,
    ns: Option<&str>,
    e: &AuditEntry<'_>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO forgs_audit (ts, ns_node_id, subject, action, target, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(ts(e.ts)?)
    .bind(ns)
    .bind(e.subject.map(ToString::to_string))
    .bind(e.action)
    .bind(e.target)
    .bind(e.detail)
    .execute(store.pool())
    .await?;
    Ok(())
}

impl<'a> NsScope<'a> {
    pub(crate) fn new(store: &'a Store, ns: NsNodeId) -> Self {
        Self { store, ns }
    }

    /// The namespace this handle is scoped to.
    #[must_use]
    pub fn ns(&self) -> NsNodeId {
        self.ns
    }

    fn ns_s(&self) -> String {
        self.ns.to_string()
    }

    fn role_label(&self, role: Role) -> Result<&str> {
        self.store.roles().label(role).ok_or(StoreError::BadRole)
    }

    fn parse_role(&self, label: &str) -> Result<Role> {
        self.store
            .roles()
            .parse(label)
            .ok_or_else(|| crate::error::corrupt("role", label))
    }

    // -----------------------------------------------------------------------
    // Membership
    // -----------------------------------------------------------------------

    /// Add `subject` with `role`, or change its role (direct membership on
    /// this node only).
    ///
    /// A user subject must be `user:<valid id>` of an existing user (the
    /// foreign key gives cascade on user deletion).
    ///
    /// # Errors
    ///
    /// [`StoreError::BadRole`], [`StoreError::BadSubject`],
    /// [`StoreError::Dangling`] (no such node or user), or a database error.
    pub async fn set_member(&self, subject: &SubjectKey, role: Role, now: u64) -> Result<()> {
        let label = self.role_label(role)?;
        let user = match subject.kind() {
            SubjectKind::User => Some(subject.user_id().ok_or(StoreError::BadSubject)?),
            _ => None,
        };
        sqlx::query(
            "INSERT INTO forgs_membership (ns_node_id, subject, user_id, role, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (ns_node_id, subject) DO UPDATE SET role = excluded.role",
        )
        .bind(self.ns_s())
        .bind(subject.to_string())
        .bind(user.map(|u| u.to_string()))
        .bind(label)
        .bind(ts(now)?)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    /// Remove `subject`'s direct membership. Returns whether a row existed.
    ///
    /// For a user subject, in the same transaction, the workload tokens
    /// minted from that user's API keys that are no longer live (the user
    /// has no remaining membership on the key namespace's chain) are
    /// deleted. The keys themselves stay, inert, and work again if the user
    /// is re-added (see [`Store::consume_api_key`]).
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn remove_member(&self, subject: &SubjectKey) -> Result<bool> {
        let mut tx = self.store.begin().await?;
        let n = sqlx::query("DELETE FROM forgs_membership WHERE ns_node_id = ?1 AND subject = ?2")
            .bind(self.ns_s())
            .bind(subject.to_string())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n > 0 && subject.kind() == SubjectKind::User {
            if let Some(user) = subject.user_id() {
                crate::credentials::purge_dead_key_tokens_for_user_tx(&mut tx, &user.to_string())
                    .await?;
            }
        }
        tx.commit().await?;
        Ok(n > 0)
    }

    /// `subject`'s **direct** role on this node (no inheritance; for that see
    /// [`Store::effective_role`]).
    ///
    /// # Errors
    ///
    /// [`StoreError::CorruptRow`] for an unknown stored label (fails closed),
    /// or a database error.
    pub async fn member_role(&self, subject: &SubjectKey) -> Result<Option<Role>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT role FROM forgs_membership WHERE ns_node_id = ?1 AND subject = ?2",
        )
        .bind(self.ns_s())
        .bind(subject.to_string())
        .fetch_optional(self.store.pool())
        .await?;
        row.map(|(r,)| self.parse_role(&r)).transpose()
    }

    /// Every direct member of this node, by subject.
    ///
    /// # Errors
    ///
    /// [`StoreError::CorruptRow`] if a stored subject or role no longer
    /// parses, or a database error.
    pub async fn list_members(&self) -> Result<Vec<MemberRow>> {
        let rows: Vec<MemberDbRow> = sqlx::query_as(
            "SELECT m.subject, m.user_id, u.username, m.role, m.created_at
               FROM forgs_membership m LEFT JOIN forgs_user u ON u.id = m.user_id
              WHERE m.ns_node_id = ?1 ORDER BY m.subject",
        )
        .bind(self.ns_s())
        .fetch_all(self.store.pool())
        .await?;
        rows.into_iter()
            .map(|(subject, user, username, role, created_at)| {
                Ok(MemberRow {
                    subject: SubjectKey::parse_with(&subject, self.store.app_subject_kinds())
                        .ok_or_else(|| crate::error::corrupt("subject", &subject))?,
                    user_id: user.map(|u| parse_id!(UserId, u)).transpose()?,
                    username,
                    role: self.parse_role(&role)?,
                    created_at: from_ts(created_at),
                })
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // API keys
    // -----------------------------------------------------------------------

    /// Mint an API key in this namespace.
    ///
    /// # Errors
    ///
    /// [`StoreError::Dangling`] (no such node or creator), a CHECK failure
    /// (empty purpose or `subject_name`) as [`StoreError::Db`], or a database
    /// error.
    pub async fn insert_api_key(&self, key: &NewApiKey, now: u64) -> Result<ApiKeyId> {
        let id = ApiKeyId::generate(now_ms(now));
        sqlx::query(
            "INSERT INTO forgs_api_key
                 (id, key_hash, ns_node_id, purpose, subject_name, payload, single_use, expires,
                  created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(id.to_string())
        .bind(key.hash.as_str())
        .bind(self.ns_s())
        .bind(&key.purpose)
        .bind(key.subject_name.as_deref())
        .bind(key.payload.as_deref())
        .bind(key.single_use)
        .bind(ts_opt(key.expires)?)
        .bind(key.created_by.map(|u| u.to_string()))
        .bind(ts(now)?)
        .execute(self.store.pool())
        .await?;
        Ok(id)
    }

    /// Every API key of this namespace, newest first.
    ///
    /// # Errors
    ///
    /// [`StoreError::CorruptRow`] or a database error.
    pub async fn list_api_keys(&self) -> Result<Vec<ApiKeyRow>> {
        let rows: Vec<ApiKeyDbRow> = sqlx::query_as(
            "SELECT id, key_hash, purpose, subject_name, payload, single_use, expires, created_by,
                    created_at, consumed_at
               FROM forgs_api_key WHERE ns_node_id = ?1 ORDER BY created_at DESC, id DESC",
        )
        .bind(self.ns_s())
        .fetch_all(self.store.pool())
        .await?;
        rows.into_iter()
            .map(
                |(
                    id,
                    hash,
                    purpose,
                    subject_name,
                    payload,
                    single_use,
                    expires,
                    created_by,
                    created_at,
                    consumed_at,
                )| {
                    Ok(ApiKeyRow {
                        id: parse_id!(ApiKeyId, id)?,
                        key_hash: TokenHash::from_hex(hash),
                        purpose,
                        subject_name,
                        payload,
                        single_use,
                        expires: expires.map(from_ts),
                        created_by: created_by.map(|u| parse_id!(UserId, u)).transpose()?,
                        created_at: from_ts(created_at),
                        consumed_at: consumed_at.map(from_ts),
                    })
                },
            )
            .collect()
    }

    /// Revoke this namespace's keys whose hash starts with `prefix`
    /// (at least 8 lowercase hex characters), returning the hashes deleted.
    ///
    /// The caller should refuse an ambiguous prefix (more than one match)
    /// *before* revoking; [`NsScope::list_api_keys`] gives it what it needs.
    /// Revocation is a `DELETE`: trivially auditable, and there is no
    /// tombstone to forget to check. The workload tokens minted from the
    /// deleted keys are deleted with them, in the same transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::BadPrefix`] or a database error.
    pub async fn delete_api_keys_by_prefix(&self, prefix: &str) -> Result<Vec<TokenHash>> {
        if prefix.len() < MIN_PREFIX
            || !prefix
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(StoreError::BadPrefix);
        }
        let mut tx = self.store.begin().await?;
        sqlx::query(
            "DELETE FROM forgs_workload_token WHERE api_key_id IN (
                 SELECT id FROM forgs_api_key
                  WHERE ns_node_id = ?1 AND substr(key_hash, 1, length(?2)) = ?2)",
        )
        .bind(self.ns_s())
        .bind(prefix)
        .execute(&mut *tx)
        .await?;
        let rows: Vec<(String,)> = sqlx::query_as(
            "DELETE FROM forgs_api_key WHERE ns_node_id = ?1 AND substr(key_hash, 1, length(?2)) = ?2
             RETURNING key_hash",
        )
        .bind(self.ns_s())
        .bind(prefix)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(|(h,)| TokenHash::from_hex(h))
            .collect())
    }

    /// Revoke one of this namespace's keys by id. Returns whether it existed
    /// here. The workload tokens minted from it are deleted with it.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn delete_api_key(&self, id: ApiKeyId) -> Result<bool> {
        let mut tx = self.store.begin().await?;
        let n = sqlx::query("DELETE FROM forgs_api_key WHERE ns_node_id = ?1 AND id = ?2")
            .bind(self.ns_s())
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n > 0 {
            sqlx::query("DELETE FROM forgs_workload_token WHERE api_key_id = ?1")
                .bind(id.to_string())
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(n > 0)
    }

    // -----------------------------------------------------------------------
    // Grants
    //
    // Creation, listing and revocation are namespace-scoped as usual: it is
    // *this* namespace's resources being shared, so its admins own the
    // lifecycle. Only `Store::grants_for_subject` — the read on the receiving
    // side — leaves the scope, for the reason documented there.
    // -----------------------------------------------------------------------

    /// Grant `g` from this namespace.
    ///
    /// # Errors
    ///
    /// [`StoreError::Dangling`] or a database error.
    pub async fn insert_grant(&self, g: &NewGrant, now: u64) -> Result<GrantId> {
        let id = GrantId::generate(now_ms(now));
        self.write_grant(id, g, now, false).await?;
        Ok(id)
    }

    /// Insert grant `id`, or update its selector, ops and expiry if it
    /// exists.
    ///
    /// For credential redemptions that must converge on **one** row however
    /// often they run (a multi-use key redeemed by many runners, with an id
    /// derived deterministically from the key). Separate from
    /// [`NsScope::insert_grant`] on purpose: a human-created grant colliding
    /// on id is a bug worth failing on.
    ///
    /// The update only applies to a row of **this** namespace and the same
    /// subject: an id owned by another namespace or subject is
    /// [`StoreError::GrantConflict`], never taken over.
    ///
    /// # Errors
    ///
    /// [`StoreError::GrantConflict`], [`StoreError::Dangling`], or a
    /// database error.
    pub async fn upsert_grant(&self, id: GrantId, g: &NewGrant, now: u64) -> Result<()> {
        self.write_grant(id, g, now, true).await
    }

    async fn write_grant(&self, id: GrantId, g: &NewGrant, now: u64, upsert: bool) -> Result<()> {
        let sql = if upsert {
            "INSERT INTO forgs_grant (id, ns_node_id, subject, selector, ops, expires, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT (id) DO UPDATE SET
                 selector = excluded.selector, ops = excluded.ops, expires = excluded.expires
               WHERE forgs_grant.ns_node_id = excluded.ns_node_id
                 AND forgs_grant.subject = excluded.subject"
        } else {
            "INSERT INTO forgs_grant (id, ns_node_id, subject, selector, ops, expires, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
        };
        let n = sqlx::query(sql)
            .bind(id.to_string())
            .bind(self.ns_s())
            .bind(g.subject.to_string())
            .bind(&g.selector)
            .bind(&g.ops)
            .bind(ts_opt(g.expires)?)
            .bind(g.created_by.map(|u| u.to_string()))
            .bind(ts(now)?)
            .execute(self.store.pool())
            .await?
            .rows_affected();
        if n == 0 {
            return Err(StoreError::GrantConflict);
        }
        Ok(())
    }

    /// Every grant this namespace issued, newest first (expired included, so
    /// they can be seen and revoked).
    ///
    /// # Errors
    ///
    /// [`StoreError::CorruptRow`] or a database error.
    pub async fn list_grants(&self) -> Result<Vec<GrantRow>> {
        let rows: Vec<GrantDbRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {GRANT_COLS} FROM forgs_grant WHERE ns_node_id = ?1 ORDER BY created_at DESC, id DESC"
        )))
        .bind(self.ns_s())
        .fetch_all(self.store.pool())
        .await?;
        rows.into_iter().map(grant_from_row).collect()
    }

    /// Revoke one of this namespace's grants, returning it if it existed
    /// here (the caller needs the subject and selector to tear down what the
    /// grantee still holds).
    ///
    /// # Errors
    ///
    /// [`StoreError::CorruptRow`] or a database error.
    pub async fn delete_grant(&self, id: GrantId) -> Result<Option<GrantRow>> {
        let row: Option<GrantDbRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "DELETE FROM forgs_grant WHERE ns_node_id = ?1 AND id = ?2 RETURNING {GRANT_COLS}"
        )))
        .bind(self.ns_s())
        .bind(id.to_string())
        .fetch_optional(self.store.pool())
        .await?;
        row.map(grant_from_row).transpose()
    }

    /// Revoke this namespace's grants whose id starts with `prefix` (at
    /// least 8 Crockford base32 characters, case-insensitive), returning the
    /// rows deleted. As for keys, refuse an ambiguous prefix first.
    ///
    /// # Errors
    ///
    /// [`StoreError::BadPrefix`], [`StoreError::CorruptRow`], or a database
    /// error.
    pub async fn delete_grants_by_prefix(&self, prefix: &str) -> Result<Vec<GrantRow>> {
        let prefix = prefix.to_ascii_uppercase();
        if prefix.len() < MIN_PREFIX
            || !prefix.bytes().all(|b| {
                b.is_ascii_digit()
                    || (b.is_ascii_uppercase() && !matches!(b, b'I' | b'L' | b'O' | b'U'))
            })
        {
            return Err(StoreError::BadPrefix);
        }
        let rows: Vec<GrantDbRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "DELETE FROM forgs_grant WHERE ns_node_id = ?1 AND substr(id, 1, length(?2)) = ?2
             RETURNING {GRANT_COLS}"
        )))
        .bind(self.ns_s())
        .bind(&prefix)
        .fetch_all(self.store.pool())
        .await?;
        rows.into_iter().map(grant_from_row).collect()
    }

    // -----------------------------------------------------------------------
    // Audit
    // -----------------------------------------------------------------------

    /// Append an audit entry in this namespace.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn append_audit(&self, entry: &AuditEntry<'_>) -> Result<()> {
        append_audit(self.store, Some(&self.ns_s()), entry).await
    }

    /// This namespace's most recent audit rows, newest first.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn recent_audit(&self, limit: u32) -> Result<Vec<AuditRow>> {
        let rows: Vec<AuditDbRow> = sqlx::query_as(
            "SELECT id, ts, ns_node_id, subject, action, target, detail FROM forgs_audit
                  WHERE ns_node_id = ?1 ORDER BY id DESC LIMIT ?2",
        )
        .bind(self.ns_s())
        .bind(i64::from(limit))
        .fetch_all(self.store.pool())
        .await?;
        rows.into_iter()
            .map(|(id, t, ns, subject, action, target, detail)| {
                Ok(AuditRow {
                    id,
                    ts: from_ts(t),
                    ns: ns.map(|n| parse_id!(NsNodeId, n)).transpose()?,
                    subject,
                    action,
                    target,
                    detail,
                })
            })
            .collect()
    }
}

impl Store {
    /// Append an audit entry **outside any namespace** (a login, a signup).
    /// Deliberately unscoped: these events precede any namespace choice.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn append_audit(&self, entry: &AuditEntry<'_>) -> Result<()> {
        append_audit(self, None, entry).await
    }
}
