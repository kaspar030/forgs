//! Pre-tenancy state: pending signups (a first login choosing a username)
//! and pending device approvals (forgs' own device flow, and the generic
//! "headless machine asks, human approves" machine apps reuse).
//!
//! These rows have no user or namespace yet — binding one is exactly what
//! completing them does — so they live on [`Store`], reached by one-shot
//! ticket id, user code or device hash. Every state transition is a single
//! conditional statement, so no race can bind or redeem twice.

use forgs::{NsNodeId, PendingId, TokenHash, UserId};
use sqlx::SqliteConnection;

use crate::error::{from_ts, is_unique_on, parse_id, ts, Result};
use crate::{now_ms, Store};

/// A pending signup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSignup {
    /// The ticket id.
    pub id: PendingId,
    /// The provider instance.
    pub provider: String,
    /// The provider's immutable subject id.
    pub provider_subject: String,
    /// Asserted email.
    pub email: Option<String>,
    /// Whether the email was asserted verified.
    pub email_verified: bool,
    /// The provider's login, offered only as a suggestion.
    pub suggested_username: Option<String>,
    /// Creation time.
    pub created_at: u64,
    /// Expiry.
    pub expires: u64,
}

/// A pending device approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDevice {
    /// Row id.
    pub id: PendingId,
    /// The normalised user code.
    pub user_code: String,
    /// App payload. Arrived from an unauthenticated request:
    /// attacker-controlled.
    pub payload: Option<String>,
    /// Advisory source address.
    pub source_ip: Option<String>,
    /// Creation time.
    pub created_at: u64,
    /// Expiry.
    pub expires: u64,
    /// The namespace bound at approval, if the app binds one.
    pub ns: Option<NsNodeId>,
    /// The approving user.
    pub approved_by: Option<UserId>,
    /// Approval time.
    pub approved_at: Option<u64>,
    /// Redemption **or denial** time; there is deliberately no `denied_at`.
    pub consumed_at: Option<u64>,
}

impl PendingDevice {
    /// Still awaiting a decision.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.approved_at.is_none() && self.consumed_at.is_none()
    }

    /// Denied: consumed without ever being approved.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        self.approved_at.is_none() && self.consumed_at.is_some()
    }

    /// Approved and not yet redeemed.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        self.approved_at.is_some() && self.consumed_at.is_none()
    }
}

/// Live device approvals, as [`Store::live_pending_device_counts`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LiveCounts {
    /// CLI logins (no payload).
    pub logins: u64,
    /// App approvals (with a payload).
    pub approvals: u64,
    /// Either kind, from the asked-for source.
    pub from_source: u64,
}

/// An approved device approval, just redeemed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedDevice {
    /// Row id.
    pub id: PendingId,
    /// The namespace bound at approval, if any.
    pub ns: Option<NsNodeId>,
    /// The approving user: whom the redemption mints for.
    pub approved_by: UserId,
    /// App payload.
    pub payload: Option<String>,
}

type SignupRow = (
    String,
    String,
    String,
    Option<String>,
    bool,
    Option<String>,
    i64,
    i64,
);

const SIGNUP_COLS: &str =
    "id, provider, provider_subject, email, email_verified, suggested_username, created_at, expires";

fn signup_from_row(r: SignupRow) -> Result<PendingSignup> {
    let (
        id,
        provider,
        provider_subject,
        email,
        email_verified,
        suggested_username,
        created_at,
        expires,
    ) = r;
    Ok(PendingSignup {
        id: parse_id!(PendingId, id)?,
        provider,
        provider_subject,
        email,
        email_verified,
        suggested_username,
        created_at: from_ts(created_at),
        expires: from_ts(expires),
    })
}

type DeviceRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    i64,
    i64,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
);

const DEVICE_COLS: &str =
    "id, user_code, payload, source_ip, created_at, expires, ns_node_id, approved_by,
     approved_at, consumed_at";

fn device_from_row(r: DeviceRow) -> Result<PendingDevice> {
    let (
        id,
        user_code,
        payload,
        source_ip,
        created_at,
        expires,
        ns,
        approved_by,
        approved_at,
        consumed_at,
    ) = r;
    Ok(PendingDevice {
        id: parse_id!(PendingId, id)?,
        user_code,
        payload,
        source_ip,
        created_at: from_ts(created_at),
        expires: from_ts(expires),
        ns: ns.map(|n| parse_id!(NsNodeId, n)).transpose()?,
        approved_by: approved_by.map(|u| parse_id!(UserId, u)).transpose()?,
        approved_at: approved_at.map(from_ts),
        consumed_at: consumed_at.map(from_ts),
    })
}

pub(crate) async fn take_pending_signup_tx(
    conn: &mut SqliteConnection,
    id: PendingId,
    now: u64,
) -> Result<Option<PendingSignup>> {
    let row: Option<SignupRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "DELETE FROM forgs_pending_signup WHERE id = ?1 AND expires > ?2 RETURNING {SIGNUP_COLS}"
    )))
    .bind(id.to_string())
    .bind(ts(now)?)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(signup_from_row).transpose()
}

impl Store {
    /// Record a first login awaiting a username choice. Returns the ticket.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn insert_pending_signup(
        &self,
        identity: &crate::NewIdentity,
        suggested_username: Option<&str>,
        now: u64,
        expires: u64,
    ) -> Result<PendingId> {
        let id = PendingId::generate(now_ms(now));
        sqlx::query(
            "INSERT INTO forgs_pending_signup
                 (id, provider, provider_subject, email, email_verified, suggested_username, created_at, expires)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(id.to_string())
        .bind(&identity.provider)
        .bind(&identity.subject)
        .bind(identity.email.as_deref())
        .bind(identity.email_verified)
        .bind(suggested_username)
        .bind(ts(now)?)
        .bind(ts(expires)?)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Read a live pending signup without consuming it (to show the
    /// suggestion).
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn pending_signup(&self, id: PendingId, now: u64) -> Result<Option<PendingSignup>> {
        let row: Option<SignupRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {SIGNUP_COLS} FROM forgs_pending_signup WHERE id = ?1 AND expires > ?2"
        )))
        .bind(id.to_string())
        .bind(ts(now)?)
        .fetch_optional(&self.pool)
        .await?;
        row.map(signup_from_row).transpose()
    }

    /// Take a pending signup: one `DELETE … RETURNING`, so a ticket is usable
    /// exactly once. `None` if unknown, already taken, or expired.
    ///
    /// [`Store::signup_pending`] does this and the signup in one transaction.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn take_pending_signup(
        &self,
        id: PendingId,
        now: u64,
    ) -> Result<Option<PendingSignup>> {
        let mut conn = self.pool.acquire().await?;
        take_pending_signup_tx(&mut conn, id, now).await
    }

    /// Insert a pending device approval, retrying on a `user_code` collision.
    ///
    /// The caller supplies fresh codes through `next_code` rather than one
    /// value: at ~40 bits behind a short TTL a collision is astronomically
    /// unlikely, but an unauthenticated route must not have an unhandled error
    /// path for it. Three attempts; a collision on the third, or any other
    /// error, surfaces. Returns the row id and the code used.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn insert_pending_device(
        &self,
        mut next_code: impl FnMut() -> String,
        device_hash: &TokenHash,
        payload: Option<&str>,
        source_ip: Option<&str>,
        now: u64,
        expires: u64,
    ) -> Result<(PendingId, String)> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let code = next_code();
            let id = PendingId::generate(now_ms(now));
            let res = sqlx::query(
                "INSERT INTO forgs_pending_device
                     (id, user_code, device_hash, payload, source_ip, created_at, expires)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .bind(id.to_string())
            .bind(&code)
            .bind(device_hash.as_str())
            .bind(payload)
            .bind(source_ip)
            .bind(ts(now)?)
            .bind(ts(expires)?)
            .execute(&self.pool)
            .await;
            match res {
                Ok(_) => return Ok((id, code)),
                Err(e) if attempt < 3 && is_unique_on(&e, "forgs_pending_device.user_code") => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// How many device approvals are live (neither consumed nor expired):
    /// the ceiling an unauthenticated start route enforces.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn live_pending_device_count(&self, now: u64) -> Result<u64> {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM forgs_pending_device WHERE consumed_at IS NULL AND expires > ?1",
        )
        .bind(ts(now)?)
        .fetch_one(&self.pool)
        .await?;
        Ok(from_ts(n))
    }

    /// Live device approvals split by kind, plus how many came from `source`
    /// (the per-source bucket key stored in `source_ip`): the ceilings an
    /// unauthenticated start route enforces, in one read.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn live_pending_device_counts(
        &self,
        now: u64,
        source: Option<&str>,
    ) -> Result<LiveCounts> {
        let (logins, approvals, from_source): (i64, i64, i64) = sqlx::query_as(
            "SELECT COALESCE(SUM(payload IS NULL), 0),
                    COALESCE(SUM(payload IS NOT NULL), 0),
                    COALESCE(SUM(source_ip IS NOT NULL AND source_ip = ?2), 0)
               FROM forgs_pending_device WHERE consumed_at IS NULL AND expires > ?1",
        )
        .bind(ts(now)?)
        .bind(source)
        .fetch_one(&self.pool)
        .await?;
        Ok(LiveCounts {
            logins: from_ts(logins),
            approvals: from_ts(approvals),
            from_source: from_ts(from_source),
        })
    }

    /// A live (unexpired) device approval by normalised user code. Decided
    /// rows are returned so the caller can report their state; expired and
    /// unknown are both `None`.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn pending_device_by_code(
        &self,
        code: &str,
        now: u64,
    ) -> Result<Option<PendingDevice>> {
        let row: Option<DeviceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {DEVICE_COLS} FROM forgs_pending_device WHERE user_code = ?1 AND expires > ?2"
        )))
        .bind(code)
        .bind(ts(now)?)
        .fetch_optional(&self.pool)
        .await?;
        row.map(device_from_row).transpose()
    }

    /// A live device approval by device-secret hash (the poll route's
    /// reporting; redemption is [`Store::consume_pending_device`]).
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn pending_device_by_hash(
        &self,
        device_hash: &TokenHash,
        now: u64,
    ) -> Result<Option<PendingDevice>> {
        let row: Option<DeviceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {DEVICE_COLS} FROM forgs_pending_device WHERE device_hash = ?1 AND expires > ?2"
        )))
        .bind(device_hash.as_str())
        .bind(ts(now)?)
        .fetch_optional(&self.pool)
        .await?;
        row.map(device_from_row).transpose()
    }

    /// Approve: bind the row to `approver` (and optionally `ns`).
    ///
    /// **One conditional UPDATE**, so two concurrent approvals cannot bind
    /// twice: the second matches no row. Returns `true` when this call
    /// approved it.
    ///
    /// # Errors
    ///
    /// [`crate::StoreError::Dangling`] or a database error.
    pub async fn approve_pending_device(
        &self,
        code: &str,
        ns: Option<NsNodeId>,
        approver: UserId,
        now: u64,
    ) -> Result<bool> {
        let n = sqlx::query(
            "UPDATE forgs_pending_device
                SET ns_node_id = ?2, approved_by = ?3, approved_at = ?4
              WHERE user_code = ?1 AND approved_at IS NULL AND consumed_at IS NULL AND expires > ?4",
        )
        .bind(code)
        .bind(ns.map(|n| n.to_string()))
        .bind(approver.to_string())
        .bind(ts(now)?)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Deny, permanently: "consumed without ever being approved". Same
    /// conditional shape as approval.
    ///
    /// A row `by` approved but that has not been redeemed yet can also be
    /// denied (a retracted mistake): the approval is cleared, so the row
    /// reads as denied and the poll reports `denied`. Nobody else can
    /// retract someone's approval.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn deny_pending_device(&self, code: &str, by: UserId, now: u64) -> Result<bool> {
        let n = sqlx::query(
            "UPDATE forgs_pending_device
                SET consumed_at = ?2, approved_at = NULL, approved_by = NULL, ns_node_id = NULL
              WHERE user_code = ?1 AND consumed_at IS NULL AND expires > ?2
                AND (approved_at IS NULL OR approved_by = ?3)",
        )
        .bind(code)
        .bind(ts(now)?)
        .bind(by.to_string())
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Atomically redeem an approved device approval.
    ///
    /// **The single atomic consume**: one conditional `UPDATE … RETURNING`, so
    /// a credential is minted at most once however many polls race. Every
    /// check a route makes before calling this is a courtesy that lets it
    /// report *why*, not the guard.
    ///
    /// `None` when unknown, unapproved, already redeemed, denied or expired.
    ///
    /// # Errors
    ///
    /// [`crate::StoreError::CorruptRow`] or a database error.
    pub async fn consume_pending_device(
        &self,
        device_hash: &TokenHash,
        now: u64,
    ) -> Result<Option<ApprovedDevice>> {
        let row: Option<(String, Option<String>, String, Option<String>)> = sqlx::query_as(
            "UPDATE forgs_pending_device SET consumed_at = ?2
              WHERE device_hash = ?1 AND approved_at IS NOT NULL AND consumed_at IS NULL AND expires > ?2
             RETURNING id, ns_node_id, approved_by, payload",
        )
        .bind(device_hash.as_str())
        .bind(ts(now)?)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(id, ns, approved_by, payload)| {
            Ok(ApprovedDevice {
                id: parse_id!(PendingId, id)?,
                ns: ns.map(|n| parse_id!(NsNodeId, n)).transpose()?,
                approved_by: parse_id!(UserId, approved_by)?,
                payload,
            })
        })
        .transpose()
    }
}
