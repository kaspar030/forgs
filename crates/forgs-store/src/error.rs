//! [`StoreError`] and the mapping from `SQLite` constraint failures to typed
//! variants.

use forgs::NameError;

/// Why a store operation failed.
///
/// Constraint violations the caller can act on (a taken name, a linked
/// identity) come back as their own variants, whether the store's own
/// pre-check caught them or the database constraint / trigger did. The second
/// path is the backstop for a race between two transactions.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Any other database failure.
    #[error("database error: {0}")]
    Db(#[source] sqlx::Error),
    /// The name violates the kind's or the username policy's rules.
    #[error("invalid name: {0}")]
    Name(NameError),
    /// The name is held by a sibling node or, at the root, by a user.
    #[error("name is taken")]
    NameTaken,
    /// The name was released earlier and is blocked (forever, unless a
    /// cool-down is configured).
    #[error("name was released and cannot be claimed again")]
    NameTombstoned,
    /// Releasing this name would exceed the store's release limit: the
    /// acting user released too many root names recently, or this user /
    /// root node was renamed too often (see [`crate::Store::with_release_limit`]).
    #[error("too many names released recently; try again later")]
    ReleaseLimited,
    /// The schema does not allow this kind under this parent.
    #[error("a {kind:?} node cannot be placed under {parent_kind:?}")]
    BadPlacement {
        /// The kind being placed.
        kind: String,
        /// The parent's kind, or `None` for the root.
        parent_kind: Option<String>,
    },
    /// No such kind in the schema.
    #[error("unknown namespace kind {0:?}")]
    UnknownKind(String),
    /// The kind's names are chosen by the app or mirrored, not by users.
    #[error("names of this kind cannot be chosen by users")]
    NotUserNameable,
    /// The `(provider, subject)` pair is already linked to a user.
    #[error("identity is already linked")]
    IdentityTaken,
    /// The email address belongs to another user.
    #[error("email address is already in use")]
    EmailTaken,
    /// The user's only remaining login method cannot be unlinked.
    #[error("cannot unlink the last identity")]
    LastIdentity,
    /// The referenced row does not exist.
    #[error("not found")]
    NotFound,
    /// A foreign key failed: a referenced row is missing, or a restricted
    /// row is still referenced.
    #[error("referential integrity violation")]
    Dangling,
    /// A node with children cannot be deleted.
    #[error("namespace node has children")]
    HasChildren,
    /// The owner already holds the maximum number of such nodes (see
    /// [`crate::Store::create_node_with_admin`]).
    #[error("the owner already holds the maximum number of such nodes")]
    OwnedLimit,
    /// The namespace (or the minting user there) already holds the maximum
    /// number of live API keys (see [`crate::NsScope::insert_api_key_capped`]).
    #[error("too many live API keys")]
    KeyLimit,
    /// A personal node is renamed and deleted only together with its user.
    #[error("a personal namespace node follows its user")]
    PersonalNode,
    /// The change would leave the namespace with no direct admin that is an
    /// active user (see [`crate::NsScope::set_member_guarded`]).
    #[error("the namespace would be left without an active admin")]
    LastAdmin,
    /// The user is the only active direct admin of a (non-personal)
    /// namespace; add another admin there first (see
    /// [`crate::Store::sole_admin_of`]).
    #[error("the user is the sole active admin of a namespace")]
    SoleAdmin(Vec<forgs::NsNodeId>),
    /// The acting subject lacks the ladder's highest effective role on the
    /// node (re-checked inside the write's transaction).
    #[error("the actor is not an admin of this namespace")]
    NotAdmin,
    /// A personal node's own user cannot be removed from it or demoted there.
    #[error("a personal namespace's owner keeps the highest role there")]
    PersonalOwner,
    /// A role not on the store's ladder.
    #[error("role is not on this ladder")]
    BadRole,
    /// A subject key that cannot be stored (e.g. `user:` with a non-id).
    #[error("subject cannot be stored")]
    BadSubject,
    /// A revocation prefix that is too short or not in the id alphabet.
    #[error("prefix is too short or malformed")]
    BadPrefix,
    /// An upsert would have taken over a grant id owned elsewhere.
    #[error("grant id belongs to another namespace or subject")]
    GrantConflict,
    /// A stored value no longer parses (id, role, subject, visibility).
    /// Fails closed: the row grants nothing.
    #[error("corrupt row: {0}")]
    CorruptRow(String),
    /// The pool's connections have `PRAGMA foreign_keys` off.
    #[error("foreign keys are off; connect with foreign_keys(true)")]
    ForeignKeysOff,
    /// The database was migrated by a newer forgs.
    #[error("database schema version {found} is newer than this build knows ({known})")]
    SchemaTooNew {
        /// The version recorded in the database.
        found: i64,
        /// The newest version this build knows.
        known: i64,
    },
    /// An epoch value does not fit `SQLite`'s signed 64-bit integer.
    #[error("timestamp out of range")]
    TimeOverflow,
}

impl From<NameError> for StoreError {
    fn from(e: NameError) -> Self {
        match e {
            NameError::UnknownKind(k) => StoreError::UnknownKind(k),
            NameError::NotUserNameable => StoreError::NotUserNameable,
            other => StoreError::Name(other),
        }
    }
}

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        let Some(db) = e.as_database_error() else {
            return StoreError::Db(e);
        };
        let msg = db.message();
        // Trigger aborts (see migrations/0001_init.sql).
        if msg.contains("forgs: name is tombstoned") {
            return StoreError::NameTombstoned;
        }
        if msg.contains("forgs: name is taken") {
            return StoreError::NameTaken;
        }
        // `ON DELETE RESTRICT` reports as SQLITE_CONSTRAINT_TRIGGER (1811),
        // which sqlx does not classify as a foreign-key violation.
        if msg.contains("FOREIGN KEY constraint failed") {
            return StoreError::Dangling;
        }
        match db.kind() {
            sqlx::error::ErrorKind::UniqueViolation => {
                if msg.contains("forgs_identity.") {
                    StoreError::IdentityTaken
                } else if msg.contains("forgs_user_email.email") {
                    StoreError::EmailTaken
                } else if msg.contains("forgs_user.username")
                    || msg.contains("forgs_ns_node_root_name")
                    || msg.contains("forgs_ns_node_child_name")
                    || msg.contains("forgs_ns_tombstone.")
                {
                    StoreError::NameTaken
                } else {
                    StoreError::Db(e)
                }
            }
            sqlx::error::ErrorKind::ForeignKeyViolation => StoreError::Dangling,
            _ => StoreError::Db(e),
        }
    }
}

/// Whether `e` is a UNIQUE violation mentioning `column` (`table.column`).
pub(crate) fn is_unique_on(e: &sqlx::Error, column: &str) -> bool {
    e.as_database_error().is_some_and(|db| {
        db.kind() == sqlx::error::ErrorKind::UniqueViolation && db.message().contains(column)
    })
}

/// Shorthand.
pub(crate) type Result<T, E = StoreError> = std::result::Result<T, E>;

/// An epoch value (`u64`) as `SQLite` stores it.
pub(crate) fn ts(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| StoreError::TimeOverflow)
}

/// An optional epoch value as `SQLite` stores it.
pub(crate) fn ts_opt(v: Option<u64>) -> Result<Option<i64>> {
    v.map(ts).transpose()
}

/// A stored epoch value back as `u64`. A negative value cannot come from
/// the clock; clamping it to 0 keeps expiry arithmetic in unsigned space and
/// makes such a credential *expired*, never unbounded.
pub(crate) fn from_ts(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

pub(crate) fn corrupt(what: &str, value: &str) -> StoreError {
    StoreError::CorruptRow(format!("{what} {value:?}"))
}

macro_rules! parse_id {
    ($ty:ty, $s:expr) => {{
        let s: &str = &$s;
        <$ty>::parse(s).map_err(|_| $crate::error::corrupt(stringify!($ty), s))
    }};
}
pub(crate) use parse_id;
