//! Users, external identities, signup, and renames of usernames.

use forgs::{IdentityId, NsNodeId, PendingId, SubjectKey, UserId};
use sqlx::SqliteConnection;

use crate::error::{from_ts, parse_id, ts, Result, StoreError};
use crate::tombstones::{insert_tombstone, NewTomb, ReleaseCause};
use crate::{now_ms, Store};

/// An external identity to link: `(provider, immutable subject)` plus what
/// the provider asserted about email.
///
/// The key is the pair `(provider, subject)`. It is never the email and never
/// the login: providers reassign both, and keying on either turns that into
/// account takeover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIdentity {
    /// The configured provider instance name (`github`, `gitlab-work`).
    pub provider: String,
    /// The provider's immutable subject id (GitHub's numeric id, OIDC `sub`).
    pub subject: String,
    /// The email the provider asserted, if any.
    pub email: Option<String>,
    /// Whether the provider asserted the email as verified. Only verified
    /// addresses are recorded as the user's email addresses.
    pub email_verified: bool,
}

/// A linked external identity, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Immutable id (what unlinking names).
    pub id: IdentityId,
    /// The configured provider instance name.
    pub provider: String,
    /// The provider's immutable subject id.
    pub subject: String,
    /// The email the provider last asserted, if any.
    pub email: Option<String>,
    /// Whether that email was asserted as verified.
    pub email_verified: bool,
    /// When it was linked, epoch seconds.
    pub linked_at: u64,
    /// The last login through it, epoch seconds.
    pub last_login_at: Option<u64>,
}

type IdentityRow = (
    String,
    String,
    String,
    Option<String>,
    bool,
    i64,
    Option<i64>,
);

fn identity_from_row(r: IdentityRow) -> Result<Identity> {
    let (id, provider, subject, email, email_verified, linked_at, last_login_at) = r;
    Ok(Identity {
        id: parse_id!(IdentityId, id)?,
        provider,
        subject,
        email,
        email_verified,
        linked_at: from_ts(linked_at),
        last_login_at: last_login_at.map(from_ts),
    })
}

/// A signup: the chosen username and the identity it links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSignup {
    /// The username as typed; validated and canonicalised by the schema.
    pub username: String,
    /// Free-form display name.
    pub display_name: Option<String>,
    /// The identity that proved who is signing up.
    pub identity: NewIdentity,
}

/// A user's account state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserState {
    /// May log in.
    Active,
    /// May not log in. Existing rows (memberships, keys) are kept.
    Disabled,
}

impl UserState {
    /// The stored label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            UserState::Active => "active",
            UserState::Disabled => "disabled",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "active" => Ok(UserState::Active),
            "disabled" => Ok(UserState::Disabled),
            other => Err(crate::error::corrupt("user state", other)),
        }
    }
}

/// A user row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Immutable id.
    pub id: UserId,
    /// Canonical username (also the personal node's name).
    pub username: String,
    /// Display name.
    pub display_name: Option<String>,
    /// Account state.
    pub state: UserState,
    /// Creation time, epoch seconds.
    pub created_at: u64,
    /// The user's personal namespace node, if the schema has a personal kind.
    pub personal_ns: Option<NsNodeId>,
}

type UserRow = (String, String, Option<String>, String, i64, Option<String>);

const USER_COLS: &str = "u.id, u.username, u.display_name, u.state, u.created_at,
     (SELECT n.id FROM forgs_ns_node n WHERE n.personal_of_user_id = u.id)";

fn user_from_row(r: UserRow) -> Result<User> {
    let (id, username, display_name, state, created_at, personal) = r;
    Ok(User {
        id: parse_id!(UserId, id)?,
        username,
        display_name,
        state: UserState::parse(&state)?,
        created_at: from_ts(created_at),
        personal_ns: personal.map(|p| parse_id!(NsNodeId, p)).transpose()?,
    })
}

/// The tombstone key of a name: names compare case-insensitively, at the
/// root and below it (security audit 2026-10, AN-6), whether or not the
/// kind's rules fold case. `parent` is unused but kept so every caller says
/// which name space it means.
pub(crate) fn tomb_name(_parent: Option<&str>, canonical: &str) -> String {
    canonical.to_ascii_lowercase()
}

/// Refuse `canonical` under `parent` if it is tombstoned or held.
///
/// Names compare case-insensitively everywhere, so siblings cannot differ
/// by case alone even under a kind whose rules keep case (AN-6). At the
/// root, users and root nodes share one name space: a root name collides with a username, and a username
/// with a root node's name. `except_user` excludes that user and their
/// personal node (a user renaming themselves); `except_node` excludes one node
/// (a node renaming itself).
pub(crate) async fn check_name_free(
    conn: &mut SqliteConnection,
    parent: Option<&str>,
    canonical: &str,
    except_user: Option<&str>,
    except_node: Option<&str>,
) -> Result<()> {
    let key = parent.unwrap_or("");
    let tomb = tomb_name(parent, canonical);
    let (tombstoned,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM forgs_ns_tombstone WHERE parent_key = ?1 AND name_canonical = ?2)",
    )
    .bind(key)
    .bind(&tomb)
    .fetch_one(&mut *conn)
    .await?;
    if tombstoned {
        return Err(StoreError::NameTombstoned);
    }
    let (taken,): (bool,) = if parent.is_none() {
        sqlx::query_as(
            "SELECT EXISTS (SELECT 1 FROM forgs_user WHERE username = ?1 AND id IS NOT ?2)
                 OR EXISTS (SELECT 1 FROM forgs_ns_node
                             WHERE parent_id IS NULL AND lower(name_canonical) = ?1
                               AND (?2 IS NULL OR personal_of_user_id IS NOT ?2)
                               AND id IS NOT ?3)",
        )
        .bind(&tomb)
        .bind(except_user)
        .bind(except_node)
        .fetch_one(&mut *conn)
        .await?
    } else {
        sqlx::query_as(
            "SELECT EXISTS (SELECT 1 FROM forgs_ns_node
                             WHERE parent_id = ?1 AND lower(name_canonical) = ?2 AND id IS NOT ?3)",
        )
        .bind(key)
        .bind(&tomb)
        .bind(except_node)
        .fetch_one(&mut *conn)
        .await?
    };
    if taken {
        return Err(StoreError::NameTaken);
    }
    Ok(())
}

async fn insert_identity(
    conn: &mut SqliteConnection,
    user: &str,
    identity: &NewIdentity,
    now: u64,
) -> Result<IdentityId> {
    let id = IdentityId::generate(now_ms(now));
    let now = ts(now)?;
    sqlx::query(
        "INSERT INTO forgs_identity
             (id, user_id, provider, provider_subject, email, email_verified, linked_at, last_login_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
    )
    .bind(id.to_string())
    .bind(user)
    .bind(&identity.provider)
    .bind(&identity.subject)
    .bind(identity.email.as_deref())
    .bind(identity.email_verified)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    if let (Some(email), true) = (&identity.email, identity.email_verified) {
        let email = email.trim().to_ascii_lowercase();
        if !email.is_empty() {
            // The first address becomes primary. An address another user
            // holds is refused (`EmailTaken`); one this user already holds is
            // left as it is.
            let done = sqlx::query(
                "INSERT INTO forgs_user_email (user_id, email, verified_at, is_primary)
                 VALUES (?1, ?2, ?3, NOT EXISTS (SELECT 1 FROM forgs_user_email
                                                  WHERE user_id = ?1 AND is_primary = 1))
                 ON CONFLICT (email) DO NOTHING",
            )
            .bind(user)
            .bind(&email)
            .bind(now)
            .execute(&mut *conn)
            .await?
            .rows_affected();
            if done == 0 {
                let (owner,): (String,) =
                    sqlx::query_as("SELECT user_id FROM forgs_user_email WHERE email = ?1")
                        .bind(&email)
                        .fetch_one(&mut *conn)
                        .await?;
                if owner != user {
                    return Err(StoreError::EmailTaken);
                }
            }
        }
    }
    Ok(id)
}

impl Store {
    /// Create a user (and, when the schema has a personal kind, their
    /// personal node with an admin membership) inside `conn`'s transaction.
    async fn create_user_tx(
        &self,
        conn: &mut SqliteConnection,
        raw_username: &str,
        display_name: Option<&str>,
        identity: Option<&NewIdentity>,
        now: u64,
    ) -> Result<(UserId, Option<NsNodeId>)> {
        let username = self.schema.validate_username(raw_username)?;
        check_name_free(conn, None, &username, None, None).await?;
        let user = UserId::generate(now_ms(now));
        let user_s = user.to_string();
        let now_i = ts(now)?;
        sqlx::query(
            "INSERT INTO forgs_user (id, username, display_name, state, created_at)
             VALUES (?1, ?2, ?3, 'active', ?4)",
        )
        .bind(&user_s)
        .bind(&username)
        .bind(display_name)
        .bind(now_i)
        .execute(&mut *conn)
        .await?;
        if let Some(identity) = identity {
            insert_identity(conn, &user_s, identity, now).await?;
        }
        let Some(kind) = self.schema.personal_kind() else {
            return Ok((user, None));
        };
        let node = NsNodeId::generate(now_ms(now));
        let node_s = node.to_string();
        sqlx::query(
            "INSERT INTO forgs_ns_node
                 (id, parent_id, kind, name, name_canonical, owner_user_id, personal_of_user_id, created_at)
             VALUES (?1, NULL, ?2, ?3, ?3, ?4, ?4, ?5)",
        )
        .bind(&node_s)
        .bind(kind)
        .bind(&username)
        .bind(&user_s)
        .bind(now_i)
        .execute(&mut *conn)
        .await?;
        let admin = self
            .roles
            .label(self.roles.highest())
            .ok_or(StoreError::BadRole)?;
        sqlx::query(
            "INSERT INTO forgs_membership (ns_node_id, subject, user_id, role, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&node_s)
        .bind(SubjectKey::user(user).to_string())
        .bind(&user_s)
        .bind(admin)
        .bind(now_i)
        .execute(&mut *conn)
        .await?;
        Ok((user, Some(node)))
    }

    /// Sign up: in **one** transaction, create the user, link the identity,
    /// record its verified email, and create the personal namespace node
    /// (named as the username) with the highest role for the user.
    ///
    /// The username is validated by the schema (policy, reserved list, the
    /// personal kind's rules) and checked against the root name space (users,
    /// root nodes of every kind, tombstones). Any failure — including a
    /// linked identity or an email another user holds — rolls everything back.
    ///
    /// # Errors
    ///
    /// [`StoreError::Name`], [`StoreError::NameTaken`],
    /// [`StoreError::NameTombstoned`], [`StoreError::IdentityTaken`],
    /// [`StoreError::EmailTaken`], or a database error.
    pub async fn signup(&self, signup: &NewSignup, now: u64) -> Result<(UserId, Option<NsNodeId>)> {
        let mut tx = self.begin().await?;
        let out = self
            .create_user_tx(
                &mut tx,
                &signup.username,
                signup.display_name.as_deref(),
                Some(&signup.identity),
                now,
            )
            .await?;
        tx.commit().await?;
        Ok(out)
    }

    /// Complete a pending signup: take the one-shot ticket and sign up with
    /// its identity, in one transaction.
    ///
    /// Returns `Ok(None)` for an unknown or expired ticket. If the signup
    /// fails (say the username is taken) the ticket is **not** consumed, so
    /// the user can pick another name.
    ///
    /// # Errors
    ///
    /// As [`Store::signup`].
    pub async fn signup_pending(
        &self,
        ticket: PendingId,
        username: &str,
        display_name: Option<&str>,
        now: u64,
    ) -> Result<Option<(UserId, Option<NsNodeId>)>> {
        let mut tx = self.begin().await?;
        let Some(pending) = crate::pending::take_pending_signup_tx(&mut tx, ticket, now).await?
        else {
            return Ok(None);
        };
        let identity = NewIdentity {
            provider: pending.provider,
            subject: pending.provider_subject,
            email: pending.email,
            email_verified: pending.email_verified,
        };
        let out = self
            .create_user_tx(&mut tx, username, display_name, Some(&identity), now)
            .await?;
        tx.commit().await?;
        Ok(Some(out))
    }

    /// Create a local user with no identity (bootstrap and tests only: login
    /// is external-only). Same path as [`Store::signup`] otherwise.
    ///
    /// # Errors
    ///
    /// As [`Store::signup`].
    pub async fn create_local_user(
        &self,
        username: &str,
        display_name: Option<&str>,
        now: u64,
    ) -> Result<(UserId, Option<NsNodeId>)> {
        let mut tx = self.begin().await?;
        let out = self
            .create_user_tx(&mut tx, username, display_name, None, now)
            .await?;
        tx.commit().await?;
        Ok(out)
    }

    /// The user linked to `(provider, subject)`.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::CorruptRow`].
    pub async fn user_by_identity(&self, provider: &str, subject: &str) -> Result<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {USER_COLS} FROM forgs_user u
               JOIN forgs_identity i ON i.user_id = u.id
              WHERE i.provider = ?1 AND i.provider_subject = ?2"
        )))
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await?;
        row.map(user_from_row).transpose()
    }

    /// Record a login through `(provider, subject)`, refreshing the asserted
    /// email. Returns `false` if the identity is not linked.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::TimeOverflow`].
    pub async fn touch_identity_login(
        &self,
        provider: &str,
        subject: &str,
        email: Option<&str>,
        email_verified: bool,
        now: u64,
    ) -> Result<bool> {
        let n = sqlx::query(
            "UPDATE forgs_identity SET last_login_at = ?3, email = ?4, email_verified = ?5
              WHERE provider = ?1 AND provider_subject = ?2",
        )
        .bind(provider)
        .bind(subject)
        .bind(ts(now)?)
        .bind(email)
        .bind(email_verified)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Link another identity to an existing (authenticated) user.
    ///
    /// Only ever called from an authenticated session: forgs never
    /// auto-links on a matching email (design §4).
    ///
    /// # Errors
    ///
    /// [`StoreError::IdentityTaken`], [`StoreError::EmailTaken`],
    /// [`StoreError::Dangling`] for an unknown user, or a database error.
    pub async fn link_identity(
        &self,
        user: UserId,
        identity: &NewIdentity,
        now: u64,
    ) -> Result<IdentityId> {
        let mut tx = self.begin().await?;
        let id = insert_identity(&mut tx, &user.to_string(), identity, now).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// The identities linked to `user`, oldest first.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::CorruptRow`].
    pub async fn identities_for_user(&self, user: UserId) -> Result<Vec<Identity>> {
        let rows: Vec<IdentityRow> = sqlx::query_as(
            "SELECT id, provider, provider_subject, email, email_verified, linked_at, last_login_at
               FROM forgs_identity WHERE user_id = ?1 ORDER BY linked_at, id",
        )
        .bind(user.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(identity_from_row).collect()
    }

    /// Unlink one of `user`'s identities, in one (immediate) transaction.
    ///
    /// Never removes the user's **last** identity: that would leave an
    /// account nobody can log in to. The user's recorded email addresses
    /// (`forgs_user_email`) are left as they are.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if `id` is not an identity of `user` (another
    /// user's id is indistinguishable from an unknown one),
    /// [`StoreError::LastIdentity`], or a database error.
    pub async fn unlink_identity(&self, user: UserId, id: IdentityId) -> Result<()> {
        let user_s = user.to_string();
        let mut tx = self.begin().await?;
        let (mine, total): (bool, i64) = sqlx::query_as(
            "SELECT EXISTS (SELECT 1 FROM forgs_identity WHERE id = ?2 AND user_id = ?1),
                    (SELECT COUNT(*) FROM forgs_identity WHERE user_id = ?1)",
        )
        .bind(&user_s)
        .bind(id.to_string())
        .fetch_one(&mut *tx)
        .await?;
        if !mine {
            return Err(StoreError::NotFound);
        }
        if total <= 1 {
            return Err(StoreError::LastIdentity);
        }
        sqlx::query("DELETE FROM forgs_identity WHERE id = ?2 AND user_id = ?1")
            .bind(&user_s)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Unlink every identity of `user` linked strictly after `after` (epoch
    /// seconds) — the `logout --all` answer to "someone linked a login method
    /// to my account". The user's oldest identity is always kept, so this
    /// never leaves the account without a login method. Returns how many
    /// were removed.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::TimeOverflow`].
    pub async fn unlink_identities_linked_after(&self, user: UserId, after: u64) -> Result<u64> {
        let mut tx = self.begin().await?;
        let n = sqlx::query(
            "DELETE FROM forgs_identity
              WHERE user_id = ?1 AND linked_at > ?2
                AND id <> (SELECT id FROM forgs_identity WHERE user_id = ?1
                            ORDER BY linked_at, id LIMIT 1)",
        )
        .bind(user.to_string())
        .bind(ts(after)?)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(n)
    }

    /// A user by id.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::CorruptRow`].
    pub async fn user_by_id(&self, user: UserId) -> Result<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {USER_COLS} FROM forgs_user u WHERE u.id = ?1"
        )))
        .bind(user.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(user_from_row).transpose()
    }

    /// A user by username (trimmed and lower-cased before lookup).
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::CorruptRow`].
    pub async fn user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {USER_COLS} FROM forgs_user u WHERE u.username = ?1"
        )))
        .bind(username.trim().to_ascii_lowercase())
        .fetch_optional(&self.pool)
        .await?;
        row.map(user_from_row).transpose()
    }

    /// Rename a user, in one transaction: the username, the personal node's
    /// name with it, and a tombstone for the old name so it can never be
    /// claimed again — by anyone, the renamer included.
    ///
    /// `actor` is the user acting (usually `user` themselves), recorded on
    /// the tombstone and subject to the release limit
    /// ([`Store::with_release_limit`]); `None` is the app or an operator,
    /// recorded as such and never limited.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`], the name errors of [`Store::signup`],
    /// [`StoreError::ReleaseLimited`], or a database error.
    pub async fn rename_user(
        &self,
        user: UserId,
        new_username: &str,
        actor: Option<UserId>,
        now: u64,
    ) -> Result<()> {
        let new = self.schema.validate_username(new_username)?;
        let user_s = user.to_string();
        let actor_s = actor.map(|a| a.to_string());
        let mut tx = self.begin().await?;
        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT u.username, (SELECT n.id FROM forgs_ns_node n WHERE n.personal_of_user_id = u.id)
               FROM forgs_user u WHERE u.id = ?1",
        )
        .bind(&user_s)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((old, personal)) = row else {
            return Err(StoreError::NotFound);
        };
        if old == new {
            return Ok(());
        }
        check_name_free(&mut tx, None, &new, Some(&user_s), None).await?;
        let tomb = NewTomb {
            parent: None,
            canonical: &old,
            node: personal.as_deref(),
            user: Some(&user_s),
            released_by: actor_s.as_deref(),
            cause: ReleaseCause::Rename,
        };
        self.check_release_limit(&mut tx, &tomb, now).await?;
        sqlx::query("UPDATE forgs_user SET username = ?2 WHERE id = ?1")
            .bind(&user_s)
            .bind(&new)
            .execute(&mut *tx)
            .await?;
        if let Some(node) = &personal {
            sqlx::query("UPDATE forgs_ns_node SET name = ?2, name_canonical = ?2 WHERE id = ?1")
                .bind(node)
                .bind(&new)
                .execute(&mut *tx)
                .await?;
        }
        insert_tombstone(&mut tx, &tomb, ts(now)?).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Set a user's state.
    ///
    /// Disabling also deletes, in the same transaction, every workload token
    /// minted from the user's API keys. The keys themselves are kept: they
    /// are inert while the user is disabled (see [`Store::consume_api_key`])
    /// and redeemable again after re-enabling. The user's SSH keys likewise
    /// stay registered but stop authenticating until re-enabled.
    ///
    /// Disabling is never refused (an operator must be able to lock out an
    /// account), but it can leave namespaces with no active admin: those
    /// (other than the user's personal node) are returned so the caller can
    /// report them. Re-enabling, or adding another admin, recovers them.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] or a database error.
    pub async fn set_user_state(&self, user: UserId, state: UserState) -> Result<Vec<NsNodeId>> {
        let user_s = user.to_string();
        let mut tx = self.begin().await?;
        let orphaned = if state == UserState::Disabled {
            self.sole_admin_of_tx(&mut tx, &user_s).await?
        } else {
            Vec::new()
        };
        let n = sqlx::query("UPDATE forgs_user SET state = ?2 WHERE id = ?1")
            .bind(&user_s)
            .bind(state.as_str())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        if state == UserState::Disabled {
            crate::credentials::purge_dead_key_tokens_for_user_tx(&mut tx, &user_s).await?;
        }
        tx.commit().await?;
        Ok(orphaned)
    }

    /// The non-personal namespaces where `user` is the only direct admin
    /// that is an active user: disabling or deleting `user` would leave them
    /// administrable by nobody (short of an inherited admin).
    ///
    /// # Errors
    ///
    /// [`StoreError::BadRole`] or a database error.
    pub async fn sole_admin_of(&self, user: UserId) -> Result<Vec<NsNodeId>> {
        let mut conn = self.pool.acquire().await?;
        self.sole_admin_of_tx(&mut conn, &user.to_string()).await
    }

    pub(crate) async fn sole_admin_of_tx(
        &self,
        conn: &mut SqliteConnection,
        user: &str,
    ) -> Result<Vec<NsNodeId>> {
        let highest = self
            .roles
            .label(self.roles.highest())
            .ok_or(StoreError::BadRole)?;
        let active = UserState::Active.as_str();
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT m.ns_node_id FROM forgs_membership m
               JOIN forgs_user u ON u.id = m.user_id
               JOIN forgs_ns_node n ON n.id = m.ns_node_id
              WHERE m.user_id = ?1 AND m.role = ?2 AND u.state = ?3
                AND n.personal_of_user_id IS NOT ?1
                AND NOT EXISTS (
                    SELECT 1 FROM forgs_membership o
                      JOIN forgs_user ou ON ou.id = o.user_id
                     WHERE o.ns_node_id = m.ns_node_id AND o.role = ?2
                       AND ou.state = ?3 AND o.user_id <> ?1)
              ORDER BY m.ns_node_id",
        )
        .bind(user)
        .bind(highest)
        .bind(active)
        .fetch_all(&mut *conn)
        .await?;
        rows.into_iter()
            .map(|(id,)| parse_id!(NsNodeId, id))
            .collect()
    }

    /// Delete a user, in one transaction: tombstone the username, delete the
    /// personal node (which must be a leaf), then the user row, which cascades
    /// identities, emails, sessions, refresh tokens, SSH keys and
    /// memberships, and
    /// clears `created_by` on grants. The user's API keys and the workload
    /// tokens minted from them are deleted first, so a NULL `created_by` on
    /// a key keeps meaning "shell-minted" rather than "orphaned but live".
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`], [`StoreError::SoleAdmin`] if the user is the
    /// only active direct admin of a non-personal namespace (add another
    /// admin there first), [`StoreError::HasChildren`] if the personal
    /// node has children, [`StoreError::Dangling`] if the user still owns
    /// other (non-personal) nodes (`owner_user_id` is `ON DELETE RESTRICT`:
    /// transfer or delete them first) or an app table still references the
    /// user or the personal node, or a database error. Nothing is changed on
    /// error.
    ///
    /// `actor` is recorded on the tombstone (`None`: the app or an
    /// operator). Deleting is not release-limited: an account can be deleted
    /// only once.
    pub async fn delete_user(&self, user: UserId, actor: Option<UserId>, now: u64) -> Result<()> {
        let user_s = user.to_string();
        let actor_s = actor.map(|a| a.to_string());
        let mut tx = self.begin().await?;
        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT u.username, (SELECT n.id FROM forgs_ns_node n WHERE n.personal_of_user_id = u.id)
               FROM forgs_user u WHERE u.id = ?1",
        )
        .bind(&user_s)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((username, personal)) = row else {
            return Err(StoreError::NotFound);
        };
        let sole = self.sole_admin_of_tx(&mut tx, &user_s).await?;
        if !sole.is_empty() {
            return Err(StoreError::SoleAdmin(sole));
        }
        sqlx::query(
            "DELETE FROM forgs_workload_token WHERE api_key_id IN (
                 SELECT id FROM forgs_api_key WHERE created_by = ?1)",
        )
        .bind(&user_s)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM forgs_api_key WHERE created_by = ?1")
            .bind(&user_s)
            .execute(&mut *tx)
            .await?;
        if let Some(node) = &personal {
            crate::ns::delete_leaf_tx(&mut tx, node).await?;
        }
        sqlx::query("DELETE FROM forgs_user WHERE id = ?1")
            .bind(&user_s)
            .execute(&mut *tx)
            .await?;
        insert_tombstone(
            &mut tx,
            &NewTomb {
                parent: None,
                canonical: &username,
                node: personal.as_deref(),
                user: Some(&user_s),
                released_by: actor_s.as_deref(),
                cause: ReleaseCause::Delete,
            },
            ts(now)?,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
