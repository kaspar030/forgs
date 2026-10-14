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
const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("../migrations/0001_init.sql"))];

/// The newest schema version this build knows.
pub const SCHEMA_VERSION: i64 = MIGRATIONS[MIGRATIONS.len() - 1].0;

/// Apply every forgs migration the database does not have yet.
///
/// Idempotent. Each migration runs in its own `BEGIN IMMEDIATE` transaction
/// together with its version row, so a failing migration leaves nothing
/// behind and two processes migrating at once serialise rather than both
/// applying.
///
/// # Errors
///
/// * [`StoreError::ForeignKeysOff`] if the pool's connections do not enforce
///   foreign keys: the schema's cascades and `REFERENCES` would silently be
///   comments, so this is refused loudly rather than discovered later.
/// * [`StoreError::SchemaTooNew`] if the database was migrated by a newer
///   forgs.
/// * [`StoreError::Db`] if a statement fails.
pub async fn migrate(pool: &SqlitePool) -> Result<()> {
    {
        let mut conn = pool.acquire().await?;
        let (fk,): (i64,) = sqlx::query_as("PRAGMA foreign_keys")
            .fetch_one(&mut *conn)
            .await?;
        if fk == 0 {
            return Err(StoreError::ForeignKeysOff);
        }
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
