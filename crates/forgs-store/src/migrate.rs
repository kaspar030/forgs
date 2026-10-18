//! forgs' own migrator.
//!
//! forgs tables live in the app's database so apps can hold foreign keys into
//! them (docs/design.md §5). forgs therefore keeps its **own** version table,
//! `forgs_schema_version`, and never touches sqlx's `_sqlx_migrations`: an app
//! calls [`migrate`] first, then runs its own migrator on the same pool, and
//! neither side sees the other's history.

use sqlx::SqlitePool;

use crate::error::{Result, StoreError};

/// Every forgs migration, in order. Versions are never renumbered or edited
/// once released; a change is a new entry.
const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../migrations/0001_init.sql")),
    (2, include_str!("../migrations/0002_session_auth_time.sql")),
    (
        3,
        include_str!("../migrations/0003_workload_token_source_key.sql"),
    ),
    (4, include_str!("../migrations/0004_audit_ts_index.sql")),
    (5, include_str!("../migrations/0005_tombstone_actor.sql")),
    (6, include_str!("../migrations/0006_workload_jti.sql")),
    (7, include_str!("../migrations/0007_child_names_nocase.sql")),
    (8, include_str!("../migrations/0008_token_hash_checks.sql")),
    (9, include_str!("../migrations/0009_ssh_keys.sql")),
    (10, include_str!("../migrations/0010_user_pending.sql")),
];

/// The newest schema version this build knows.
pub const SCHEMA_VERSION: i64 = MIGRATIONS[MIGRATIONS.len() - 1].0;

/// Apply every forgs migration the database does not have yet.
///
/// Idempotent. Each migration runs in its own `BEGIN IMMEDIATE` transaction
/// together with its version row, so a failing migration leaves nothing
/// behind and two processes migrating at once serialise rather than both
/// applying. Foreign keys are verified on the connection running each
/// migration, and `PRAGMA foreign_key_check` must report no violation in a
/// `forgs_` table before that migration commits.
///
/// # Errors
///
/// * [`StoreError::ForeignKeysOff`] if the pool's connections do not enforce
///   foreign keys: the schema's cascades and `REFERENCES` would silently be
///   comments, so this is refused loudly rather than discovered later.
/// * [`StoreError::ForeignKeyViolations`] if a migration leaves (or finds) a
///   `forgs_` row whose foreign key points nowhere — e.g. rows written while
///   foreign keys were off. Nothing of that migration is applied.
/// * [`StoreError::SchemaTooNew`] if the database was migrated by a newer
///   forgs.
/// * [`StoreError::Db`] if a statement fails.
pub async fn migrate(pool: &SqlitePool) -> Result<()> {
    {
        let mut conn = pool.acquire().await?;
        ensure_foreign_keys(&mut conn).await?;
    }
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS forgs_schema_version (
             version    INTEGER NOT NULL PRIMARY KEY,
             applied_at INTEGER NOT NULL
         ) STRICT",
    )
    .execute(pool)
    .await?;

    for (version, sql) in MIGRATIONS {
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        ensure_foreign_keys(&mut tx).await?;
        let (current,): (Option<i64>,) =
            sqlx::query_as("SELECT MAX(version) FROM forgs_schema_version")
                .fetch_one(&mut *tx)
                .await?;
        let current = current.unwrap_or(0);
        if current > SCHEMA_VERSION {
            return Err(StoreError::SchemaTooNew {
                found: current,
                known: SCHEMA_VERSION,
            });
        }
        if current >= *version {
            continue;
        }
        sqlx::raw_sql(*sql).execute(&mut *tx).await?;
        foreign_key_check(&mut tx, *version).await?;
        sqlx::query(
            "INSERT INTO forgs_schema_version (version, applied_at) VALUES (?1, unixepoch())",
        )
        .bind(version)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

/// Refuse a connection whose `PRAGMA foreign_keys` is off.
///
/// Reading the pragma works inside a transaction (only *setting* it is a
/// no-op there), so this is also how [`Store`](crate::Store) checks the
/// connection each write transaction landed on: a pool is a set of
/// connections, and one configured differently (or re-configured by the app)
/// would otherwise run its writes with every `ON DELETE CASCADE` silently
/// skipped.
pub(crate) async fn ensure_foreign_keys(conn: &mut sqlx::SqliteConnection) -> Result<()> {
    let (fk,): (i64,) = sqlx::query_as("PRAGMA foreign_keys")
        .fetch_one(&mut *conn)
        .await?;
    if fk == 0 {
        return Err(StoreError::ForeignKeysOff);
    }
    Ok(())
}

/// Fail migration `version` if any `forgs_` table holds a row whose foreign
/// key points nowhere. App tables are not judged: their integrity is the
/// app's, and a pre-existing violation there must not block a forgs upgrade.
async fn foreign_key_check(conn: &mut sqlx::SqliteConnection, version: i64) -> Result<()> {
    let tables: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT \"table\" FROM pragma_foreign_key_check
          WHERE \"table\" LIKE 'forgs\\_%' ESCAPE '\\' ORDER BY 1",
    )
    .fetch_all(&mut *conn)
    .await?;
    if tables.is_empty() {
        return Ok(());
    }
    Err(StoreError::ForeignKeyViolations {
        version,
        tables: tables.into_iter().map(|(t,)| t).collect(),
    })
}
