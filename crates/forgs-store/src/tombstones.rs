//! Released names (tombstones): who released them, the per-actor and
//! per-name release limit, and the operator API to undo abuse
//! (docs/design.md §2 "Renames and handles"; security audit 2026-10,
//! HTTP-07).
//!
//! A released name is blocked forever. Without a limit, one account could
//! rename through any number of free root names (`google`, `rust-lang`, …)
//! and deny every one of them to everyone. So:
//!
//! * **Release limit** ([`Store::with_release_limit`], default
//!   [`DEFAULT_RELEASE_LIMIT`]): releasing a **root** name on a user's behalf
//!   — renaming oneself, renaming or deleting a root node — is refused with
//!   [`StoreError::ReleaseLimited`] once that user has released
//!   `max` root names inside the window, or once the renamed user / root node
//!   has been renamed `max` times inside it. Names below the root are not
//!   limited: only admins of the parent can create, rename or delete there,
//!   so burning them harms nobody but that namespace.
//! * **Attribution**: every tombstone records the acting user
//!   (`released_by`, `None` for the app / an operator) and the cause.
//! * **Undo**: [`Store::tombstones_released_by`] lists one actor's
//!   tombstones and [`Store::release_tombstones_by`] /
//!   [`Store::release_tombstone`] delete them, making the names claimable
//!   again.
//! * **Cool-down** ([`Store::with_tombstone_cooldown`], default off): when
//!   set, [`Store::sweep`] deletes tombstones older than the cool-down.

use forgs::{NsNodeId, UserId};
use sqlx::SqliteConnection;

use crate::error::{from_ts, parse_id, ts, Result, StoreError};
use crate::users::tomb_name;
use crate::Store;

/// How many root names one user may release, and how often one user or root
/// node may be renamed, inside a sliding window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseLimit {
    /// Releases allowed inside the window.
    pub max: u32,
    /// The window, in seconds.
    pub window_secs: u64,
}

/// The default [`ReleaseLimit`]: 5 root-name releases per 30 days.
pub const DEFAULT_RELEASE_LIMIT: ReleaseLimit = ReleaseLimit {
    max: 5,
    window_secs: 30 * 24 * 60 * 60,
};

/// Why a name was released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseCause {
    /// The holder was renamed.
    Rename,
    /// The holder was deleted.
    Delete,
}

impl ReleaseCause {
    fn as_str(self) -> &'static str {
        match self {
            ReleaseCause::Rename => "rename",
            ReleaseCause::Delete => "delete",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "rename" => Ok(ReleaseCause::Rename),
            "delete" => Ok(ReleaseCause::Delete),
            other => Err(crate::error::corrupt("release cause", other)),
        }
    }
}

/// A tombstone: a released name, blocked for new claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tombstone {
    /// The parent the name was released under; `None` at the root.
    pub parent: Option<NsNodeId>,
    /// The released canonical name (lower-cased at the root).
    pub name: String,
    /// The node that held it, if any.
    pub node: Option<NsNodeId>,
    /// The user that held it, if any.
    pub user: Option<UserId>,
    /// When it was released, epoch seconds.
    pub released_at: u64,
    /// The acting user; `None` for the app / an operator, and for names
    /// released before attribution was recorded.
    pub released_by: Option<UserId>,
    /// Why; `None` for names released before causes were recorded.
    pub cause: Option<ReleaseCause>,
}

type TombRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    i64,
    Option<String>,
    Option<String>,
);

const TOMB_COLS: &str =
    "parent_key, name_canonical, node_id, user_id, released_at, released_by, cause";

fn tomb_from_row(r: TombRow) -> Result<Tombstone> {
    let (parent, name, node, user, released_at, released_by, cause) = r;
    Ok(Tombstone {
        parent: if parent.is_empty() {
            None
        } else {
            Some(parse_id!(NsNodeId, parent)?)
        },
        name,
        node: node.map(|n| parse_id!(NsNodeId, n)).transpose()?,
        user: user.map(|u| parse_id!(UserId, u)).transpose()?,
        released_at: from_ts(released_at),
        released_by: released_by.map(|u| parse_id!(UserId, u)).transpose()?,
        cause: cause.as_deref().map(ReleaseCause::parse).transpose()?,
    })
}

/// A tombstone to insert.
pub(crate) struct NewTomb<'a> {
    pub parent: Option<&'a str>,
    pub canonical: &'a str,
    pub node: Option<&'a str>,
    pub user: Option<&'a str>,
    pub released_by: Option<&'a str>,
    pub cause: ReleaseCause,
}

pub(crate) async fn insert_tombstone(
    conn: &mut SqliteConnection,
    t: &NewTomb<'_>,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO forgs_ns_tombstone
             (parent_key, name_canonical, node_id, user_id, released_at, released_by, cause)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(t.parent.unwrap_or(""))
    .bind(tomb_name(t.parent, t.canonical))
    .bind(t.node)
    .bind(t.user)
    .bind(now)
    .bind(t.released_by)
    .bind(t.cause.as_str())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

impl Store {
    /// Limit root-name releases on a user's behalf (see the module docs);
    /// `None` disables the limit. Default: [`DEFAULT_RELEASE_LIMIT`].
    #[must_use]
    pub fn with_release_limit(mut self, limit: Option<ReleaseLimit>) -> Self {
        self.release_limit = limit;
        self
    }

    /// The release limit in force (`None`: unlimited).
    #[must_use]
    pub fn release_limit(&self) -> Option<ReleaseLimit> {
        self.release_limit
    }

    /// Relax "blocked forever" to a cool-down: [`Store::sweep`] deletes
    /// tombstones released more than `cooldown_secs` ago, making those names
    /// claimable again. `None` (the default) keeps them forever.
    ///
    /// A cool-down re-opens the squatting risk tombstones exist for: after
    /// it, anyone may claim an old name and receive traffic meant for its
    /// previous holder. Pick one longer than links to the old name live.
    #[must_use]
    pub fn with_tombstone_cooldown(mut self, cooldown_secs: Option<u64>) -> Self {
        self.tombstone_cooldown = cooldown_secs;
        self
    }

    /// The tombstone cool-down in force (`None`: forever).
    #[must_use]
    pub fn tombstone_cooldown(&self) -> Option<u64> {
        self.tombstone_cooldown
    }

    /// Refuse inserting tombstone `t` if that would exceed the
    /// [`ReleaseLimit`]: only root names are limited, and a `None` actor
    /// (the app, an operator) never is.
    pub(crate) async fn check_release_limit(
        &self,
        conn: &mut SqliteConnection,
        t: &NewTomb<'_>,
        now: u64,
    ) -> Result<()> {
        let (Some(limit), Some(actor), None) = (self.release_limit, t.released_by, t.parent) else {
            return Ok(());
        };
        let since = ts(now.saturating_sub(limit.window_secs))?;
        let max = i64::from(limit.max);
        let (by_actor,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM forgs_ns_tombstone
              WHERE released_by = ?1 AND parent_key = '' AND released_at > ?2",
        )
        .bind(actor)
        .bind(since)
        .fetch_one(&mut *conn)
        .await?;
        if by_actor >= max {
            return Err(StoreError::ReleaseLimited);
        }
        if t.cause == ReleaseCause::Rename {
            // One holder renamed over and over, by however many admins.
            let (renames,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM forgs_ns_tombstone
                  WHERE parent_key = '' AND cause = 'rename' AND released_at > ?3
                    AND ((?1 IS NOT NULL AND user_id = ?1)
                      OR (?1 IS NULL AND ?2 IS NOT NULL AND node_id = ?2))",
            )
            .bind(t.user)
            .bind(t.node)
            .bind(since)
            .fetch_one(&mut *conn)
            .await?;
            if renames >= max {
                return Err(StoreError::ReleaseLimited);
            }
        }
        Ok(())
    }

    /// Every tombstone `actor` created, oldest first — to review a suspected
    /// name-burning account before [`Store::release_tombstones_by`].
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::CorruptRow`].
    pub async fn tombstones_released_by(&self, actor: UserId) -> Result<Vec<Tombstone>> {
        let rows: Vec<TombRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {TOMB_COLS} FROM forgs_ns_tombstone
              WHERE released_by = ?1 ORDER BY released_at, parent_key, name_canonical"
        )))
        .bind(actor.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(tomb_from_row).collect()
    }

    /// The tombstone of `name` under `parent` (`None`: the root), if any.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::CorruptRow`].
    pub async fn tombstone(
        &self,
        parent: Option<NsNodeId>,
        name: &str,
    ) -> Result<Option<Tombstone>> {
        let parent = parent.map(|p| p.to_string());
        let row: Option<TombRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {TOMB_COLS} FROM forgs_ns_tombstone
              WHERE parent_key = ?1 AND name_canonical = ?2"
        )))
        .bind(parent.as_deref().unwrap_or(""))
        .bind(tomb_name(parent.as_deref(), name.trim()))
        .fetch_optional(&self.pool)
        .await?;
        row.map(tomb_from_row).transpose()
    }

    /// Operator action: delete the tombstones `actor` created at or after
    /// `since` (`None`: all of them), making those names claimable again.
    /// Returns how many were released.
    ///
    /// Intended for undoing name burning. It re-opens the squatting risk for
    /// each released name (see [`Store::with_tombstone_cooldown`]); review
    /// the list with [`Store::tombstones_released_by`] first.
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn release_tombstones_by(&self, actor: UserId, since: Option<u64>) -> Result<u64> {
        let since = ts(since.unwrap_or(0))?;
        Ok(sqlx::query(
            "DELETE FROM forgs_ns_tombstone WHERE released_by = ?1 AND released_at >= ?2",
        )
        .bind(actor.to_string())
        .bind(since)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    /// Operator action: delete the tombstone of `name` under `parent`
    /// (`None`: the root), making it claimable again. Returns whether there
    /// was one. Same caveat as [`Store::release_tombstones_by`].
    ///
    /// # Errors
    ///
    /// A database error.
    pub async fn release_tombstone(&self, parent: Option<NsNodeId>, name: &str) -> Result<bool> {
        let parent = parent.map(|p| p.to_string());
        Ok(sqlx::query(
            "DELETE FROM forgs_ns_tombstone WHERE parent_key = ?1 AND name_canonical = ?2",
        )
        .bind(parent.as_deref().unwrap_or(""))
        .bind(tomb_name(parent.as_deref(), name.trim()))
        .execute(&self.pool)
        .await?
        .rows_affected()
            > 0)
    }
}
