//! forgs storage: the `SQLite` schema, forgs' own migrator, and the [`Store`]
//! over `sqlx` (docs/design.md §2–§5).
//!
//! forgs tables live **in the app's database file**, all prefixed `forgs_`,
//! so apps can hold foreign keys into `forgs_user` and `forgs_ns_node`. An app
//! connects its pool with foreign keys on ([`connect_options`]), calls
//! [`migrate`] (or builds a [`Store`], which does), then runs its own
//! migrator; forgs never touches `_sqlx_migrations`.
//!
//! Queries use the runtime `query` API rather than the compile-time `query!`
//! macro, so the crate builds without a live database.
//!
//! # Tenancy
//!
//! A namespace is a security boundary between tenants, so tenancy is
//! **structural, not advisory**. Rather
//! than an `ns` parameter on each method — which a caller can pass the wrong
//! value to as easily as it can forget a `WHERE` clause — every
//! namespace-owned row (memberships, API key listing and revocation, grant
//! lifecycle, the namespace's audit log) is reachable only through
//! [`NsScope`], obtained from [`Store::scoped`], which binds its one
//! namespace id into every statement.
//!
//! The queries on [`Store`] itself that are **deliberately not** namespace
//! scoped, and why each is safe:
//!
//! * **Lookups by token hash** — [`TokenStore`](forgs::TokenStore),
//!   [`Store::consume_api_key`], [`Store::api_key_by_hash`],
//!   [`Store::consume_pending_device`], the session / refresh / workload
//!   deletes. The hash *is* the capability: a caller can only name a row whose
//!   secret it holds, and no hash can be enumerated.
//! * **[`Store::grants_for_subject`]** — the single read that crosses
//!   namespaces on purpose, because a grant's whole purpose is to cross a
//!   namespace boundary. It is scoped by the authenticated subject instead;
//!   see its docs.
//! * **Per-user queries** — sessions and refresh tokens (not namespace-bound,
//!   design §3), [`Store::memberships_of_user`] ("my namespaces"): keyed by
//!   the authenticated user, which the caller cannot choose.
//! * **Users, identities and the namespace tree** — global by nature: names
//!   share one root name space, and ancestor / role chains are how authz
//!   decides *which* namespace a request may touch. These return structure,
//!   never another tenant's credentials or grants.
//! * **Pending signups and device approvals** — pre-tenancy state: which user
//!   and namespace a device joins is exactly what its approval decides.
//!   Reached by one-shot ticket id, user code or device hash.
//! * **Audit rows outside any namespace** ([`Store::append_audit`]) — logins
//!   and signups, which happen before any namespace is chosen.
//! * **[`Store::sweep`]** — system-initiated hygiene with no caller.
//!
//! [`Store::pool`] is public because apps share the database and need the pool
//! for their own tables; writing to `forgs_` tables through it bypasses these
//! checks (the schema's triggers and constraints still hold).

#![allow(clippy::module_name_repetitions)]

mod credentials;
mod error;
mod migrate;
mod ns;
mod pending;
mod scoped;
mod sweep;
mod tokens;
mod users;

use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use forgs::{RoleLadder, Schema};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;

pub use credentials::{ConsumedApiKey, ConsumedSession, GrantRow};
pub use error::StoreError;
pub use migrate::{migrate, SCHEMA_VERSION};
pub use ns::{Membership, NsNode};
pub use pending::{ApprovedDevice, PendingDevice, PendingSignup};
pub use scoped::{ApiKeyRow, AuditEntry, AuditRow, MemberRow, NewApiKey, NewGrant, NsScope};
pub use sweep::SweepCounts;
pub use users::{Identity, NewIdentity, NewSignup, User, UserState};

/// Connect options for a forgs database at `url` (`sqlite://path`,
/// `sqlite::memory:`): foreign keys **on**, and the file created if missing.
///
/// Foreign keys are enabled explicitly because `SQLite` defaults them off,
/// which would silently reduce every `REFERENCES` in the schema to a comment;
/// [`migrate`] refuses a pool without them.
///
/// # Errors
///
/// Returns [`StoreError::Db`] if `url` does not parse.
pub fn connect_options(url: &str) -> Result<SqliteConnectOptions, StoreError> {
    Ok(SqliteConnectOptions::from_str(url)?
        .foreign_keys(true)
        .create_if_missing(true))
}

/// The forgs store: a pool plus the app's namespace schema and role ladder.
///
/// Cheap to clone.
#[derive(Debug, Clone)]
pub struct Store {
    pool: SqlitePool,
    schema: Arc<Schema>,
    roles: Arc<RoleLadder>,
    app_subject_kinds: Vec<&'static str>,
}

impl Store {
    /// Wrap an existing pool, running [`migrate`] first.
    ///
    /// # Errors
    ///
    /// Whatever [`migrate`] returns.
    pub async fn new(
        pool: SqlitePool,
        schema: Schema,
        roles: RoleLadder,
    ) -> Result<Self, StoreError> {
        migrate(&pool).await?;
        Ok(Self {
            pool,
            schema: Arc::new(schema),
            roles: Arc::new(roles),
            app_subject_kinds: Vec::new(),
        })
    }

    /// Open (creating if absent) the database file at `path` in WAL mode, and
    /// migrate it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the file cannot be opened or migrated.
    pub async fn connect(
        path: &str,
        schema: Schema,
        roles: RoleLadder,
    ) -> Result<Self, StoreError> {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;
        Self::new(pool, schema, roles).await
    }

    /// An in-memory database (tests), migrated.
    ///
    /// One connection that is never recycled: every connection to
    /// `sqlite::memory:` is a separate, empty database.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if migration fails.
    pub async fn connect_in_memory(schema: Schema, roles: RoleLadder) -> Result<Self, StoreError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None::<Duration>)
            .max_lifetime(None::<Duration>)
            .connect_with(connect_options("sqlite::memory:")?)
            .await?;
        Self::new(pool, schema, roles).await
    }

    /// Recognise these app subject kinds (fleet: `node`) when reading stored
    /// subject keys back. Unknown kinds fail closed.
    #[must_use]
    pub fn with_app_subject_kinds(mut self, kinds: &[&'static str]) -> Self {
        self.app_subject_kinds = kinds.to_vec();
        self
    }

    /// The underlying pool, for the app's own tables. See the crate docs on
    /// what writing `forgs_` tables through it bypasses.
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// The namespace schema.
    #[must_use]
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// The role ladder.
    #[must_use]
    pub fn roles(&self) -> &RoleLadder {
        &self.roles
    }

    /// The app subject kinds recognised when parsing stored subjects.
    #[must_use]
    pub fn app_subject_kinds(&self) -> &[&'static str] {
        &self.app_subject_kinds
    }

    /// A handle scoped to namespace node `ns`. Every query on it binds `ns`.
    ///
    /// Scoping does not check that `ns` exists: queries on a missing node
    /// return nothing and writes fail their foreign key.
    #[must_use]
    pub fn scoped(&self, ns: forgs::NsNodeId) -> NsScope<'_> {
        NsScope::new(self, ns)
    }

    /// Begin a write transaction that takes the write lock up front, so the
    /// check-then-write sequences in this crate cannot interleave.
    async fn begin(&self) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>, StoreError> {
        Ok(self.pool.begin_with("BEGIN IMMEDIATE").await?)
    }
}

/// Epoch seconds to the milliseconds a ULID embeds.
fn now_ms(now: u64) -> u64 {
    now.saturating_mul(1000)
}
