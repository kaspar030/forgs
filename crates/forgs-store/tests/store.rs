//! Invariant tests for forgs-store, against in-memory `SQLite`.

// Fixture-heavy tests: short names (`s`, `a`, `b`) read better than long ones.
#![allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_lines
)]

use forgs::schema::{KindSpec, NameOrigin, NameRules, Schema};
use forgs::{
    authenticate, AuthError, NameError, NsNodeId, RoleLadder, SubjectKey, TokenFormat, TokenHash,
    TokenKind, TokenStore, UserId,
};
use forgs_store::{
    AuditEntry, NewApiKey, NewGrant, NewIdentity, NewSignup, Store, StoreError, SweepCounts,
    UserState,
};
use sqlx::sqlite::SqlitePoolOptions;

const RESERVED: &[&str] = &["api", "admin", "login", "settings"];
const NOW: u64 = 1_700_000_000;

fn fleet() -> Schema {
    Schema::builder()
        .kind("org", KindSpec::root().leaf().personal_for_users())
        .reserved(RESERVED)
        .build()
        .unwrap()
}

fn forge() -> Schema {
    Schema::builder()
        .kind(
            "org",
            KindSpec::root().children(&["project"]).personal_for_users(),
        )
        .kind("project", KindSpec::child().leaf())
        .reserved(RESERVED)
        .build()
        .unwrap()
}

fn forgefront() -> Schema {
    Schema::builder()
        .kind(
            "forge",
            KindSpec::root().app_created().children(&["remote_owner"]),
        )
        .kind(
            "remote_owner",
            KindSpec::child()
                .under(&["forge"])
                .externally_named(NameRules::github()),
        )
        .kind(
            "repo",
            KindSpec::child()
                .under(&["remote_owner"])
                .externally_named(NameRules::github())
                .leaf(),
        )
        .kind("user", KindSpec::root().leaf().personal_for_users())
        .reserved(RESERVED)
        .build()
        .unwrap()
}

/// No personal kind: users have no namespace of their own.
fn no_personal() -> Schema {
    Schema::builder()
        .kind("team", KindSpec::root().leaf())
        .build()
        .unwrap()
}

async fn store(schema: Schema) -> Store {
    Store::connect_in_memory(schema, RoleLadder::default())
        .await
        .unwrap()
}

fn ident(provider: &str, subject: &str, email: Option<&str>) -> NewIdentity {
    NewIdentity {
        provider: provider.into(),
        subject: subject.into(),
        email: email.map(Into::into),
        email_verified: true,
    }
}

fn signup(username: &str, subject: &str, email: Option<&str>) -> NewSignup {
    NewSignup {
        username: username.into(),
        display_name: None,
        identity: ident("github", subject, email),
    }
}

async fn count(s: &Store, table: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
        .fetch_one(s.pool())
        .await
        .unwrap();
    n
}

fn hash(n: u8) -> TokenHash {
    TokenHash::from_hex(format!("{n:02x}").repeat(32))
}

fn key(h: TokenHash, single_use: bool, expires: Option<u64>) -> NewApiKey {
    NewApiKey {
        hash: h,
        purpose: "node".into(),
        subject_name: None,
        payload: Some(r#"{"tags":["a"]}"#.into()),
        single_use,
        expires,
        created_by: None,
    }
}

// ---------------------------------------------------------------------------
// Migrations and foreign keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migrate_is_idempotent_and_records_versions() {
    let s = store(fleet()).await;
    forgs_store::migrate(s.pool()).await.unwrap();
    forgs_store::migrate(s.pool()).await.unwrap();
    let rows: Vec<(i64,)> = sqlx::query_as("SELECT version FROM forgs_schema_version")
        .fetch_all(s.pool())
        .await
        .unwrap();
    assert_eq!(rows, vec![(forgs_store::SCHEMA_VERSION,)]);
    // forgs never touches sqlx's migration table.
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM sqlite_master WHERE name = '_sqlx_migrations'")
            .fetch_one(s.pool())
            .await
            .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn an_app_migration_can_reference_forgs_tables() {
    let s = store(forge()).await;
    sqlx::raw_sql(
        "CREATE TABLE app_board (
             id TEXT PRIMARY KEY,
             ns TEXT NOT NULL REFERENCES forgs_ns_node (id),
             owner TEXT REFERENCES forgs_user (id)
         )",
    )
    .execute(s.pool())
    .await
    .unwrap();
    let (user, ns) = s.create_local_user("alice", None, NOW).await.unwrap();
    let ns = ns.unwrap();
    sqlx::query("INSERT INTO app_board VALUES ('b1', ?1, ?2)")
        .bind(ns.to_string())
        .bind(user.to_string())
        .execute(s.pool())
        .await
        .unwrap();
    // The FK is enforced for the app's table too.
    assert!(
        sqlx::query("INSERT INTO app_board VALUES ('b2', 'nope', NULL)")
            .execute(s.pool())
            .await
            .is_err()
    );
    // And a node the app still references cannot be deleted.
    let proj = s
        .create_node(Some(ns), "project", "p", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    sqlx::query("INSERT INTO app_board VALUES ('b3', ?1, NULL)")
        .bind(proj.to_string())
        .execute(s.pool())
        .await
        .unwrap();
    assert!(matches!(
        s.delete_node(proj, NOW).await,
        Err(StoreError::Dangling)
    ));
    // Migrating again after the app's tables exist is still a no-op.
    forgs_store::migrate(s.pool()).await.unwrap();
}

#[tokio::test]
async fn a_pool_without_foreign_keys_is_refused() {
    let opts = forgs_store::connect_options("sqlite::memory:")
        .unwrap()
        .foreign_keys(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    assert!(matches!(
        forgs_store::migrate(&pool).await,
        Err(StoreError::ForeignKeysOff)
    ));
    assert!(matches!(
        Store::new(pool, fleet(), RoleLadder::default()).await,
        Err(StoreError::ForeignKeysOff)
    ));
}

#[tokio::test]
async fn a_newer_schema_is_refused() {
    let s = store(fleet()).await;
    sqlx::query("INSERT INTO forgs_schema_version VALUES (999, 0)")
        .execute(s.pool())
        .await
        .unwrap();
    assert!(matches!(
        forgs_store::migrate(s.pool()).await,
        Err(StoreError::SchemaTooNew { found: 999, .. })
    ));
}

#[tokio::test]
async fn foreign_keys_are_enforced() {
    let s = store(fleet()).await;
    let ghost = UserId::generate(NOW * 1000);
    assert!(matches!(
        s.insert_session(&hash(1), ghost, NOW, NOW + 10).await,
        Err(StoreError::Dangling)
    ));
    assert!(matches!(
        s.insert_refresh_token(&hash(1), ghost, NOW, NOW + 10).await,
        Err(StoreError::Dangling)
    ));
    let ghost_ns = NsNodeId::generate(NOW * 1000);
    assert!(matches!(
        s.scoped(ghost_ns)
            .insert_api_key(&key(hash(2), true, None), NOW)
            .await,
        Err(StoreError::Dangling)
    ));
}

// ---------------------------------------------------------------------------
// Signup and local users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn signup_creates_everything_atomically() {
    let s = store(fleet()).await;
    let (user, ns) = s
        .signup(&signup(" Alice ", "42", Some("Alice@Example.org")), NOW)
        .await
        .unwrap();
    let ns = ns.unwrap();
    let u = s.user_by_identity("github", "42").await.unwrap().unwrap();
    assert_eq!(u.id, user);
    assert_eq!(u.username, "alice");
    assert_eq!(u.state, UserState::Active);
    assert_eq!(u.personal_ns, Some(ns));
    assert_eq!(s.user_by_username("ALICE").await.unwrap().unwrap().id, user);
    let node = s.node(ns).await.unwrap().unwrap();
    assert_eq!(node.kind, "org");
    assert_eq!(node.name_canonical, "alice");
    assert_eq!(node.personal_of, Some(user));
    assert_eq!(node.owner, Some(user));
    let key = SubjectKey::user(user);
    assert_eq!(
        s.scoped(ns).member_role(&key).await.unwrap(),
        Some(s.roles().highest())
    );
    let (email,): (String,) = sqlx::query_as("SELECT email FROM forgs_user_email")
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert_eq!(email, "alice@example.org");
    assert_eq!(s.memberships_of_user(user).await.unwrap()[0].ns, ns);
}

async fn assert_only_one_user(s: &Store) {
    assert_eq!(count(s, "forgs_user").await, 1);
    assert_eq!(count(s, "forgs_identity").await, 1);
    assert_eq!(count(s, "forgs_ns_node").await, 1);
    assert_eq!(count(s, "forgs_membership").await, 1);
    assert_eq!(count(s, "forgs_user_email").await, 1);
}

#[tokio::test]
async fn failed_signups_roll_back_completely() {
    let s = store(fleet()).await;
    s.signup(&signup("alice", "1", Some("a@x.org")), NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.signup(&signup("bob", "1", Some("b@x.org")), NOW).await,
        Err(StoreError::IdentityTaken)
    ));
    assert_only_one_user(&s).await;
    assert!(matches!(
        s.signup(&signup("bob", "2", Some("A@X.org")), NOW).await,
        Err(StoreError::EmailTaken)
    ));
    assert_only_one_user(&s).await;
    assert!(matches!(
        s.signup(&signup("Alice", "3", None), NOW).await,
        Err(StoreError::NameTaken)
    ));
    assert_only_one_user(&s).await;
    assert!(matches!(
        s.signup(&signup("admin", "4", None), NOW).await,
        Err(StoreError::Name(NameError::Reserved))
    ));
    assert_only_one_user(&s).await;
    // An unverified email is not recorded, so it cannot squat an address.
    let mut su = signup("carol", "5", Some("a@x.org"));
    su.identity.email_verified = false;
    s.signup(&su, NOW).await.unwrap();
    assert_eq!(count(&s, "forgs_user_email").await, 1);
}

#[tokio::test]
async fn local_users_get_a_personal_node_and_no_identity() {
    let s = store(fleet()).await;
    let (user, ns) = s
        .create_local_user("root", Some("Root"), NOW)
        .await
        .unwrap();
    assert!(ns.is_some());
    assert_eq!(count(&s, "forgs_identity").await, 0);
    let u = s.user_by_id(user).await.unwrap().unwrap();
    assert_eq!(u.display_name.as_deref(), Some("Root"));
    // Linking later works, and a second link of the same identity fails.
    s.link_identity(user, &ident("github", "9", None), NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.link_identity(user, &ident("github", "9", None), NOW)
            .await,
        Err(StoreError::IdentityTaken)
    ));
    assert!(s
        .touch_identity_login("github", "9", Some("r@x.org"), true, NOW + 1)
        .await
        .unwrap());
    assert!(!s
        .touch_identity_login("github", "nope", None, false, NOW)
        .await
        .unwrap());
    s.set_user_state(user, UserState::Disabled).await.unwrap();
    assert_eq!(
        s.user_by_id(user).await.unwrap().unwrap().state,
        UserState::Disabled
    );
}

#[tokio::test]
async fn schemas_without_a_personal_kind_create_no_node() {
    let s = store(no_personal()).await;
    let (_, ns) = s.create_local_user("alice", None, NOW).await.unwrap();
    assert_eq!(ns, None);
    assert_eq!(count(&s, "forgs_ns_node").await, 0);
}

// ---------------------------------------------------------------------------
// The root name space
// ---------------------------------------------------------------------------

#[tokio::test]
async fn usernames_and_root_nodes_share_one_name_space() {
    let s = store(forge()).await;
    s.create_node(None, "org", "Ariel-OS", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    // Username vs existing org, case-folded.
    assert!(matches!(
        s.create_local_user("ARIEL-os", None, NOW).await,
        Err(StoreError::NameTaken)
    ));
    // Org vs existing username.
    s.create_local_user("alice", None, NOW).await.unwrap();
    assert!(matches!(
        s.create_node(None, "org", "Alice", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::NameTaken)
    ));
    // Children do not share it.
    let alice = s.node_by_path(&["alice"]).await.unwrap().unwrap();
    s.create_node(
        Some(alice.id),
        "project",
        "ariel-os",
        NameOrigin::User,
        None,
        NOW,
    )
    .await
    .unwrap();
}

/// The store's own pre-check (not the triggers or the unique index) must
/// see non-personal root nodes: drop the backstops and check it still refuses.
#[tokio::test]
async fn the_root_pre_check_sees_non_personal_nodes_without_backstops() {
    let s = store(forgefront()).await;
    sqlx::raw_sql(
        "DROP TRIGGER forgs_user_root_insert;
         DROP TRIGGER forgs_user_root_update;
         DROP TRIGGER forgs_ns_node_root_user_insert;
         DROP TRIGGER forgs_ns_node_root_user_update;
         DROP INDEX forgs_ns_node_root_name;",
    )
    .execute(s.pool())
    .await
    .unwrap();
    s.create_node(None, "forge", "acme", NameOrigin::App, None, NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.create_local_user("Acme", None, NOW).await,
        Err(StoreError::NameTaken)
    ));
    assert!(matches!(
        s.signup(&signup("acme", "1", None), NOW).await,
        Err(StoreError::NameTaken)
    ));
    assert!(matches!(
        s.create_node(None, "forge", "ACME", NameOrigin::App, None, NOW)
            .await,
        Err(StoreError::NameTaken)
    ));
    let (bob, _) = s.create_local_user("bob", None, NOW).await.unwrap();
    assert!(matches!(
        s.rename_user(bob, "acme", NOW).await,
        Err(StoreError::NameTaken)
    ));
    let other = s
        .create_node(None, "forge", "other", NameOrigin::App, None, NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.rename_node(other, "acme", NameOrigin::App, NOW).await,
        Err(StoreError::NameTaken)
    ));
    assert_eq!(count(&s, "forgs_user").await, 1);
    assert_eq!(count(&s, "forgs_ns_node").await, 3); // acme, bob, other
}

#[tokio::test]
async fn delete_user_refuses_while_they_own_other_nodes() {
    let s = store(fleet()).await;
    let (alice, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    s.create_node(None, "org", "team", NameOrigin::User, Some(alice), NOW)
        .await
        .unwrap();
    let r = s.delete_user(alice, NOW).await;
    assert!(matches!(r, Err(StoreError::Dangling)), "{r:?}");
    assert!(s.user_by_id(alice).await.unwrap().is_some());
    assert_eq!(count(&s, "forgs_ns_tombstone").await, 0);
}

#[tokio::test]
async fn app_created_root_nodes_block_usernames() {
    let s = store(forgefront()).await;
    let gh = s
        .create_node(None, "forge", "github", NameOrigin::App, None, NOW)
        .await
        .unwrap();
    let cb = s
        .create_node(None, "forge", "gitea", NameOrigin::App, None, NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.create_local_user("Gitea", None, NOW).await,
        Err(StoreError::NameTaken)
    ));
    assert!(matches!(
        s.create_local_user("github", None, NOW).await,
        Err(StoreError::NameTaken)
    ));
    // Users cannot create forge nodes, nor name mirrored kinds.
    assert!(matches!(
        s.create_node(None, "forge", "codeberg", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::NotUserNameable)
    ));
    assert!(matches!(
        s.create_node(Some(gh), "remote_owner", "x", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::NotUserNameable)
    ));
    // Mirrored names follow their own rules and ignore reservations.
    let owner = s
        .create_node(
            Some(gh),
            "remote_owner",
            "Admin",
            NameOrigin::App,
            None,
            NOW,
        )
        .await
        .unwrap();
    s.create_node(Some(owner), "repo", ".github", NameOrigin::App, None, NOW)
        .await
        .unwrap();
    let found = s
        .node_by_path(&["github", "ADMIN", ".github"])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.kind, "repo");
    assert!(s.node_by_path(&["gitea", "admin"]).await.unwrap().is_none());
    let _ = cb;
}

#[tokio::test]
async fn no_personal_kind_still_blocks_root_collisions_both_ways() {
    let s = store(no_personal()).await;
    s.create_local_user("alice", None, NOW).await.unwrap();
    assert!(matches!(
        s.create_node(None, "team", "alice", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::NameTaken)
    ));
    s.create_node(None, "team", "core", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.create_local_user("Core", None, NOW).await,
        Err(StoreError::NameTaken)
    ));
}

#[tokio::test]
async fn null_parents_do_not_defeat_root_uniqueness() {
    let s = store(forge()).await;
    let a = s
        .create_node(None, "org", "a-org", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    let b = s
        .create_node(None, "org", "b-org", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    // Bypass the store's check: the partial index still refuses a second root.
    let res = sqlx::query(
        "INSERT INTO forgs_ns_node (id, parent_id, kind, name, name_canonical, created_at)
         VALUES (?1, NULL, 'org', 'a-org', 'A-ORG', 0)",
    )
    .bind(NsNodeId::generate(1).to_string())
    .execute(s.pool())
    .await;
    assert!(res.is_err());
    // Same child name under different parents is fine; twice under one is not.
    s.create_node(Some(a), "project", "p", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    s.create_node(Some(b), "project", "p", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.create_node(Some(a), "project", "P", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::NameTaken)
    ));
}

// ---------------------------------------------------------------------------
// Tombstones
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_renamed_username_is_blocked_forever() {
    let s = store(fleet()).await;
    let (alice, ns) = s.create_local_user("alice", None, NOW).await.unwrap();
    let ns = ns.unwrap();
    s.rename_user(alice, "alicia", NOW).await.unwrap();
    assert_eq!(
        s.user_by_id(alice).await.unwrap().unwrap().username,
        "alicia"
    );
    assert_eq!(s.node(ns).await.unwrap().unwrap().name_canonical, "alicia");
    assert_eq!(s.node_by_path(&["alicia"]).await.unwrap().unwrap().id, ns);
    assert!(s.node_by_path(&["alice"]).await.unwrap().is_none());
    // Nobody may take `alice` again: not a new user, not an org, not the
    // renamer.
    assert!(matches!(
        s.create_local_user("Alice", None, NOW).await,
        Err(StoreError::NameTombstoned)
    ));
    assert!(matches!(
        s.create_node(None, "org", "alice", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::NameTombstoned)
    ));
    assert!(matches!(
        s.rename_user(alice, "alice", NOW).await,
        Err(StoreError::NameTombstoned)
    ));
    // Renaming into another user's name is refused.
    s.create_local_user("bob", None, NOW).await.unwrap();
    assert!(matches!(
        s.rename_user(alice, "bob", NOW).await,
        Err(StoreError::NameTaken)
    ));
    // Personal nodes are renamed only through the user.
    assert!(matches!(
        s.rename_node(ns, "x", NameOrigin::User, NOW).await,
        Err(StoreError::PersonalNode)
    ));
    assert!(matches!(
        s.delete_node(ns, NOW).await,
        Err(StoreError::PersonalNode)
    ));
}

#[tokio::test]
async fn renamed_and_deleted_node_names_are_blocked_under_their_parent_only() {
    let s = store(forge()).await;
    let a = s
        .create_node(None, "org", "a-org", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    let b = s
        .create_node(None, "org", "b-org", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    let p = s
        .create_node(Some(a), "project", "old", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    s.rename_node(p, "New", NameOrigin::User, NOW)
        .await
        .unwrap();
    let n = s.node(p).await.unwrap().unwrap();
    assert_eq!((n.name.as_str(), n.name_canonical.as_str()), ("New", "new"));
    // Display-only change releases nothing.
    s.rename_node(p, "NEW", NameOrigin::User, NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.create_node(Some(a), "project", "old", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::NameTombstoned)
    ));
    s.create_node(Some(b), "project", "old", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    s.delete_node(p, NOW).await.unwrap();
    assert!(matches!(
        s.create_node(Some(a), "project", "new", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::NameTombstoned)
    ));
    // A deleted root org's name is blocked for usernames too.
    s.delete_node(b, NOW).await.unwrap_err(); // has a child
    let c = s
        .create_node(None, "org", "c-org", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    s.delete_node(c, NOW).await.unwrap();
    assert!(matches!(
        s.create_local_user("c-org", None, NOW).await,
        Err(StoreError::NameTombstoned)
    ));
    assert_eq!(count(&s, "forgs_ns_tombstone").await, 3);
}

#[tokio::test]
async fn triggers_block_raw_sql_writes_of_tombstoned_names() {
    let s = store(forge()).await;
    let (alice, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    s.rename_user(alice, "alicia", NOW).await.unwrap();
    let res = sqlx::query(
        "INSERT INTO forgs_ns_node (id, parent_id, kind, name, name_canonical, created_at)
         VALUES (?1, NULL, 'org', 'alice', 'alice', 0)",
    )
    .bind(NsNodeId::generate(1).to_string())
    .execute(s.pool())
    .await
    .map_err(StoreError::from);
    assert!(matches!(res, Err(StoreError::NameTombstoned)));
    let res =
        sqlx::query("INSERT INTO forgs_user (id, username, created_at) VALUES (?1, 'alice', 0)")
            .bind(UserId::generate(1).to_string())
            .execute(s.pool())
            .await
            .map_err(StoreError::from);
    assert!(matches!(res, Err(StoreError::NameTombstoned)));
    let res = sqlx::query("UPDATE forgs_user SET username = 'alice' WHERE id = ?1")
        .bind(alice.to_string())
        .execute(s.pool())
        .await
        .map_err(StoreError::from);
    assert!(matches!(res, Err(StoreError::NameTombstoned)));
    // And the user/root-node collision triggers.
    let res = sqlx::query(
        "INSERT INTO forgs_ns_node (id, parent_id, kind, name, name_canonical, created_at)
         VALUES (?1, NULL, 'org', 'alicia', 'alicia', 0)",
    )
    .bind(NsNodeId::generate(2).to_string())
    .execute(s.pool())
    .await
    .map_err(StoreError::from);
    assert!(matches!(res, Err(StoreError::NameTaken)));
}

// ---------------------------------------------------------------------------
// Placement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn placement_and_naming_are_checked_against_the_schema() {
    let s = store(forge()).await;
    let org = s
        .create_node(None, "org", "org1", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    let p = s
        .create_node(Some(org), "project", "p", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.create_node(None, "project", "x", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::BadPlacement { .. })
    ));
    assert!(matches!(
        s.create_node(Some(p), "project", "x", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::BadPlacement { .. })
    ));
    assert!(matches!(
        s.create_node(Some(org), "org", "x", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::BadPlacement { .. })
    ));
    assert!(matches!(
        s.create_node(None, "nope", "x", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::UnknownKind(_))
    ));
    assert!(matches!(
        s.create_node(
            Some(org),
            "project",
            "settings",
            NameOrigin::User,
            None,
            NOW
        )
        .await,
        Err(StoreError::Name(NameError::Reserved))
    ));
    assert!(matches!(
        s.create_node(None, "org", "api", NameOrigin::App, None, NOW)
            .await,
        Err(StoreError::Name(NameError::Reserved))
    ));
    assert!(matches!(
        s.create_node(
            Some(NsNodeId::generate(1)),
            "project",
            "x",
            NameOrigin::User,
            None,
            NOW
        )
        .await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(s.children(Some(org)).await.unwrap().len(), 1);
    assert_eq!(s.children(None).await.unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Ancestors and roles
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ancestor_chains_and_role_inheritance() {
    let s = store(forgefront()).await;
    let gh = s
        .create_node(None, "forge", "github", NameOrigin::App, None, NOW)
        .await
        .unwrap();
    let owner = s
        .create_node(
            Some(gh),
            "remote_owner",
            "probe-rs",
            NameOrigin::App,
            None,
            NOW,
        )
        .await
        .unwrap();
    let repo = s
        .create_node(Some(owner), "repo", "probe-rs", NameOrigin::App, None, NOW)
        .await
        .unwrap();
    let chain: Vec<NsNodeId> = s
        .ancestors(repo)
        .await
        .unwrap()
        .iter()
        .map(|n| n.id)
        .collect();
    assert_eq!(chain, vec![gh, owner, repo]);
    assert!(s.ancestors(NsNodeId::generate(1)).await.unwrap().is_empty());

    let (alice, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    let key = SubjectKey::user(alice);
    let l = s.roles().clone();
    let write = l.parse("write").unwrap();
    let read = l.parse("read").unwrap();
    s.scoped(owner).set_member(&key, write, NOW).await.unwrap();
    s.scoped(repo).set_member(&key, read, NOW).await.unwrap();
    let rc = s.role_chain(repo, &key).await.unwrap();
    assert_eq!(
        rc,
        vec![(gh, None), (owner, Some(write)), (repo, Some(read))]
    );
    // Inherited, never lowered.
    assert_eq!(s.effective_role(repo, &key).await.unwrap(), Some(write));
    assert_eq!(s.effective_role(gh, &key).await.unwrap(), None);

    s.set_visibility(owner, Some(forgs::Visibility::Internal))
        .await
        .unwrap();
    assert_eq!(
        s.visibility_chain(repo).await.unwrap(),
        vec![None, Some(forgs::Visibility::Internal), None]
    );

    // An unknown stored role fails closed.
    sqlx::query("UPDATE forgs_membership SET role = 'overlord' WHERE ns_node_id = ?1")
        .bind(repo.to_string())
        .execute(s.pool())
        .await
        .unwrap();
    assert!(matches!(
        s.role_chain(repo, &key).await,
        Err(StoreError::CorruptRow(_))
    ));
    assert!(matches!(
        s.scoped(repo).member_role(&key).await,
        Err(StoreError::CorruptRow(_))
    ));
}

// ---------------------------------------------------------------------------
// Scoping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn membership_is_scoped() {
    let s = store(fleet()).await;
    let (alice, a) = s.create_local_user("alice", None, NOW).await.unwrap();
    let (bob, b) = s.create_local_user("bob", None, NOW).await.unwrap();
    let (a, b) = (a.unwrap(), b.unwrap());
    let ka = SubjectKey::user(alice);
    let kb = SubjectKey::user(bob);
    let member = s.roles().lowest();
    s.scoped(a).set_member(&kb, member, NOW).await.unwrap();
    // B's scope sees none of A's rows and cannot delete them.
    assert_eq!(s.scoped(b).member_role(&ka).await.unwrap(), None);
    assert!(!s.scoped(b).remove_member(&ka).await.unwrap());
    let in_a = s.scoped(a).list_members().await.unwrap();
    assert_eq!(in_a.len(), 2);
    assert_eq!(
        in_a.iter()
            .find(|m| m.subject == kb)
            .unwrap()
            .username
            .as_deref(),
        Some("bob")
    );
    assert_eq!(s.scoped(b).list_members().await.unwrap().len(), 1);
    // Upsert changes the role.
    s.scoped(a)
        .set_member(&kb, s.roles().highest(), NOW)
        .await
        .unwrap();
    assert_eq!(
        s.scoped(a).member_role(&kb).await.unwrap(),
        Some(s.roles().highest())
    );
    assert!(s.scoped(a).remove_member(&kb).await.unwrap());
    assert_eq!(s.scoped(a).member_role(&kb).await.unwrap(), None);
    // A bad user subject is refused.
    let bad = SubjectKey::new(None, forgs::SubjectKind::User, "not-a-ulid").unwrap();
    assert!(matches!(
        s.scoped(a).set_member(&bad, member, NOW).await,
        Err(StoreError::BadSubject)
    ));
    // Non-user subjects can be members (workloads via agent keys, later teams).
    let agent = forgs::subject::agent_subject_key(&a, "builder");
    s.scoped(a).set_member(&agent, member, NOW).await.unwrap();
    assert_eq!(s.scoped(a).member_role(&agent).await.unwrap(), Some(member));
}

#[tokio::test]
async fn api_key_listing_and_revocation_are_scoped() {
    let s = store(fleet()).await;
    let (_, a) = s.create_local_user("alice", None, NOW).await.unwrap();
    let (_, b) = s.create_local_user("bob", None, NOW).await.unwrap();
    let (a, b) = (a.unwrap(), b.unwrap());
    let id_a = s
        .scoped(a)
        .insert_api_key(&key(hash(0xaa), true, None), NOW)
        .await
        .unwrap();
    s.scoped(b)
        .insert_api_key(&key(hash(0xab), true, None), NOW)
        .await
        .unwrap();
    let list = s.scoped(a).list_api_keys().await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, id_a);
    assert_eq!(list[0].payload.as_deref(), Some(r#"{"tags":["a"]}"#));
    // B cannot revoke A's key by prefix or id.
    assert!(s
        .scoped(b)
        .delete_api_keys_by_prefix("aaaaaaaa")
        .await
        .unwrap()
        .is_empty());
    assert!(!s.scoped(b).delete_api_key(id_a).await.unwrap());
    assert!(matches!(
        s.scoped(a).delete_api_keys_by_prefix("aaaa").await,
        Err(StoreError::BadPrefix)
    ));
    assert!(matches!(
        s.scoped(a).delete_api_keys_by_prefix("%%%%%%%%").await,
        Err(StoreError::BadPrefix)
    ));
    assert_eq!(
        s.scoped(a)
            .delete_api_keys_by_prefix("aaaaaaaa")
            .await
            .unwrap(),
        vec![hash(0xaa)]
    );
    assert_eq!(s.scoped(b).list_api_keys().await.unwrap().len(), 1);
    // An empty subject name is not a second spelling of "none".
    let mut k = key(hash(3), true, None);
    k.subject_name = Some(String::new());
    assert!(s.scoped(a).insert_api_key(&k, NOW).await.is_err());
}

#[tokio::test]
async fn audit_is_scoped() {
    let s = store(fleet()).await;
    let (alice, a) = s.create_local_user("alice", None, NOW).await.unwrap();
    let (_, b) = s.create_local_user("bob", None, NOW).await.unwrap();
    let k = SubjectKey::user(alice);
    let e = |action| AuditEntry {
        ts: NOW,
        subject: Some(&k),
        action,
        target: None,
        detail: Some("{}"),
    };
    s.scoped(a.unwrap())
        .append_audit(&e("member.add"))
        .await
        .unwrap();
    s.scoped(a.unwrap())
        .append_audit(&e("key.mint"))
        .await
        .unwrap();
    s.append_audit(&e("auth.login")).await.unwrap();
    let rows = s.scoped(a.unwrap()).recent_audit(10).await.unwrap();
    assert_eq!(
        rows.iter().map(|r| r.action.as_str()).collect::<Vec<_>>(),
        ["key.mint", "member.add"]
    );
    assert!(s
        .scoped(b.unwrap())
        .recent_audit(10)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(s.scoped(a.unwrap()).recent_audit(1).await.unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// API key consumption
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_key_consumption() {
    let s = store(fleet()).await;
    let (_, ns) = s.create_local_user("alice", None, NOW).await.unwrap();
    let scope = s.scoped(ns.unwrap());
    scope
        .insert_api_key(&key(hash(1), true, Some(NOW + 10)), NOW)
        .await
        .unwrap();
    scope
        .insert_api_key(&key(hash(2), false, None), NOW)
        .await
        .unwrap();
    scope
        .insert_api_key(&key(hash(3), true, Some(NOW)), NOW)
        .await
        .unwrap();

    // Single use: exactly once.
    let got = s.consume_api_key(&hash(1), NOW).await.unwrap().unwrap();
    assert_eq!(got.ns, ns.unwrap());
    assert!(got.single_use);
    assert!(s.consume_api_key(&hash(1), NOW).await.unwrap().is_none());
    assert!(s.lookup_api_key(&hash(1)).await.unwrap().is_none());
    assert!(s.api_key_by_hash(&hash(1)).await.unwrap().is_none());
    // Multi use survives.
    for _ in 0..3 {
        assert!(s.consume_api_key(&hash(2), NOW).await.unwrap().is_some());
    }
    // now == expires is expired, and an expired key is not consumed.
    assert!(s.consume_api_key(&hash(3), NOW).await.unwrap().is_none());
    assert!(s.api_key_by_hash(&hash(3)).await.unwrap().is_some());
    let listed = scope.list_api_keys().await.unwrap();
    let k3 = listed.iter().find(|k| k.key_hash == hash(3)).unwrap();
    assert_eq!(k3.consumed_at, None);
    // Unknown.
    assert!(s.consume_api_key(&hash(9), NOW).await.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// TokenStore
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_store_lookups_round_trip() {
    let s = store(fleet()).await;
    let f = TokenFormat::default();
    let (alice, ns) = s.create_local_user("alice", None, NOW).await.unwrap();
    let ns = ns.unwrap();

    let session = f.mint(TokenKind::Session);
    s.insert_session(&session.hash(), alice, NOW, NOW + 100)
        .await
        .unwrap();
    let r = s.lookup_session(&session.hash()).await.unwrap().unwrap();
    assert_eq!((r.user_id, r.expires), (alice, NOW + 100));
    let auth = authenticate(&f, &s, &session.to_secret_string(), NOW + 1)
        .await
        .unwrap();
    assert_eq!(auth.subject, SubjectKey::user(alice));
    assert_eq!(
        authenticate(&f, &s, &session.to_secret_string(), NOW + 100).await,
        Err(AuthError::Expired(TokenKind::Session))
    );

    let refresh = f.mint(TokenKind::Refresh);
    s.insert_refresh_token(&refresh.hash(), alice, NOW, NOW + 1000)
        .await
        .unwrap();
    for _ in 0..2 {
        // Lookups never consume.
        let (_, r) = forgs::verify::verify_refresh_token(&f, &s, &refresh.to_secret_string(), NOW)
            .await
            .unwrap();
        assert_eq!(r.user_id, alice);
    }

    let api = f.mint(TokenKind::ApiKey);
    let mut k = key(api.hash(), true, Some(NOW + 5));
    k.subject_name = Some("builder".into());
    k.created_by = Some(alice);
    let id = s.scoped(ns).insert_api_key(&k, NOW).await.unwrap();
    let r = s.lookup_api_key(&api.hash()).await.unwrap().unwrap();
    assert_eq!(r.id, id);
    assert_eq!(r.ns, ns);
    assert_eq!(r.purpose, "node");
    assert_eq!(r.subject_name.as_deref(), Some("builder"));
    assert_eq!(r.created_by, Some(alice));
    assert_eq!(r.expires, Some(NOW + 5));
    assert_eq!(
        forgs::verify::verify_api_key(&f, &s, &api.to_secret_string(), NOW + 5).await,
        Err(AuthError::Expired(TokenKind::ApiKey))
    );
    s.consume_api_key(&api.hash(), NOW).await.unwrap().unwrap();
    assert_eq!(
        forgs::verify::verify_api_key(&f, &s, &api.to_secret_string(), NOW).await,
        Err(AuthError::Unknown(TokenKind::ApiKey))
    );

    let wl = f.mint(TokenKind::Workload);
    let subject = forgs::subject::workload_subject_key("probe-rs/probe-rs");
    s.insert_workload_token(
        &wl.hash(),
        &subject,
        "github_oidc",
        Some("{}"),
        NOW,
        NOW + 60,
    )
    .await
    .unwrap();
    let auth = authenticate(&f, &s, &wl.to_secret_string(), NOW)
        .await
        .unwrap();
    assert_eq!(auth.subject, subject);

    // An unparseable stored subject fails closed.
    let bad = f.mint(TokenKind::Workload);
    sqlx::query(
        "INSERT INTO forgs_workload_token (token_hash, subject, issuer, issued_at, expires)
         VALUES (?1, 'node:x', 'app', 0, 99999999999)",
    )
    .bind(bad.hash().as_str())
    .execute(s.pool())
    .await
    .unwrap();
    assert!(s.lookup_workload(&bad.hash()).await.unwrap().is_none());
    // ... unless the app registered that kind.
    let s2 = s.clone().with_app_subject_kinds(&["node"]);
    assert!(s2.lookup_workload(&bad.hash()).await.unwrap().is_some());

    // A negative stored expiry clamps to "expired", never unbounded.
    let neg = f.mint(TokenKind::Session);
    s.insert_session(&neg.hash(), alice, NOW, NOW)
        .await
        .unwrap();
    sqlx::query("UPDATE forgs_session SET expires = -5 WHERE token_hash = ?1")
        .bind(neg.hash().as_str())
        .execute(s.pool())
        .await
        .unwrap();
    assert_eq!(
        s.lookup_session(&neg.hash())
            .await
            .unwrap()
            .unwrap()
            .expires,
        0
    );

    // Device secrets: pending and approved resolve; decided ones do not.
    let dev = f.mint(TokenKind::DeviceSecret);
    let (pid, code) = s
        .insert_pending_device(
            forgs::user_code::generate,
            &dev.hash(),
            None,
            None,
            NOW,
            NOW + 900,
        )
        .await
        .unwrap();
    assert_eq!(
        s.lookup_device_secret(&dev.hash())
            .await
            .unwrap()
            .unwrap()
            .id,
        pid
    );
    s.deny_pending_device(&code, NOW).await.unwrap();
    assert!(s.lookup_device_secret(&dev.hash()).await.unwrap().is_none());

    // Deletions.
    assert!(s.delete_session(&session.hash()).await.unwrap());
    assert!(s.lookup_session(&session.hash()).await.unwrap().is_none());
    assert!(s.delete_refresh_token(&refresh.hash()).await.unwrap());
    assert!(!s.delete_refresh_token(&refresh.hash()).await.unwrap());
}

#[tokio::test]
async fn logout_all_is_per_user() {
    let s = store(fleet()).await;
    let (alice, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    let (bob, _) = s.create_local_user("bob", None, NOW).await.unwrap();
    s.insert_session(&hash(1), alice, NOW, NOW + 9)
        .await
        .unwrap();
    s.insert_session(&hash(2), alice, NOW, NOW + 9)
        .await
        .unwrap();
    s.insert_session(&hash(3), bob, NOW, NOW + 9).await.unwrap();
    s.insert_refresh_token(&hash(4), alice, NOW, NOW + 9)
        .await
        .unwrap();
    s.insert_refresh_token(&hash(5), bob, NOW, NOW + 9)
        .await
        .unwrap();
    assert_eq!(s.delete_sessions_for_user(alice).await.unwrap(), 2);
    assert_eq!(s.delete_refresh_tokens_for_user(alice).await.unwrap(), 1);
    assert!(s.lookup_session(&hash(3)).await.unwrap().is_some());
    assert!(s.lookup_refresh_token(&hash(5)).await.unwrap().is_some());
}

// ---------------------------------------------------------------------------
// Cascades
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deleting_a_user_cascades_their_rows() {
    let s = store(fleet()).await;
    let (alice, a) = s
        .signup(&signup("alice", "1", Some("a@x.org")), NOW)
        .await
        .unwrap();
    let (bob, b) = s.create_local_user("bob", None, NOW).await.unwrap();
    let b = b.unwrap();
    s.insert_session(&hash(1), alice, NOW, NOW + 9)
        .await
        .unwrap();
    s.insert_refresh_token(&hash(2), alice, NOW, NOW + 9)
        .await
        .unwrap();
    s.scoped(b)
        .set_member(&SubjectKey::user(alice), s.roles().lowest(), NOW)
        .await
        .unwrap();
    let mut k = key(hash(3), false, None);
    k.created_by = Some(alice);
    s.scoped(b).insert_api_key(&k, NOW).await.unwrap();
    let gid = s
        .scoped(b)
        .insert_grant(
            &NewGrant {
                subject: SubjectKey::user(bob),
                selector: "*".into(),
                ops: "read".into(),
                expires: None,
                created_by: Some(alice),
            },
            NOW,
        )
        .await
        .unwrap();

    s.delete_user(alice, NOW).await.unwrap();
    for t in [
        "forgs_identity",
        "forgs_user_email",
        "forgs_session",
        "forgs_refresh_token",
    ] {
        assert_eq!(count(&s, t).await, 0, "{t}");
    }
    assert!(s.node(a.unwrap()).await.unwrap().is_none());
    assert_eq!(s.scoped(b).list_members().await.unwrap().len(), 1);
    assert_eq!(
        s.scoped(b).list_api_keys().await.unwrap()[0].created_by,
        None
    );
    let g = s.scoped(b).list_grants().await.unwrap();
    assert_eq!((g[0].id, g[0].created_by), (gid, None));
    // Their name is released forever.
    assert!(matches!(
        s.create_local_user("alice", None, NOW).await,
        Err(StoreError::NameTombstoned)
    ));
}

#[tokio::test]
async fn deleting_a_node_cascades_and_needs_a_leaf() {
    let s = store(forge()).await;
    let (alice, a) = s.create_local_user("alice", None, NOW).await.unwrap();
    let a = a.unwrap();
    let p = s
        .create_node(Some(a), "project", "p", NameOrigin::User, Some(alice), NOW)
        .await
        .unwrap();
    let scope = s.scoped(p);
    scope
        .set_member(&SubjectKey::user(alice), s.roles().lowest(), NOW)
        .await
        .unwrap();
    scope
        .insert_api_key(&key(hash(1), true, None), NOW)
        .await
        .unwrap();
    scope
        .insert_grant(
            &NewGrant {
                subject: SubjectKey::user(alice),
                selector: "*".into(),
                ops: "x".into(),
                expires: None,
                created_by: None,
            },
            NOW,
        )
        .await
        .unwrap();
    // The personal node has a child: deleting the user is refused.
    assert!(matches!(
        s.delete_user(alice, NOW).await,
        Err(StoreError::HasChildren)
    ));
    let o = s
        .create_node(None, "org", "o", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    s.create_node(Some(o), "project", "q", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.delete_node(o, NOW).await,
        Err(StoreError::HasChildren)
    ));
    s.delete_node(p, NOW).await.unwrap();
    assert_eq!(count(&s, "forgs_api_key").await, 0);
    assert_eq!(count(&s, "forgs_grant").await, 0);
    assert_eq!(count(&s, "forgs_membership").await, 1); // alice on her own node
    s.delete_user(alice, NOW).await.unwrap();
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn grants_cross_namespaces_not_subjects() {
    let s = store(fleet()).await;
    let (alice, a) = s.create_local_user("alice", None, NOW).await.unwrap();
    let (bob, b) = s.create_local_user("bob", None, NOW).await.unwrap();
    let (_, c) = s.create_local_user("carol", None, NOW).await.unwrap();
    let (a, b, c) = (a.unwrap(), b.unwrap(), c.unwrap());
    let to = |subject: &SubjectKey, expires| NewGrant {
        subject: subject.clone(),
        selector: "tag=nrf52".into(),
        ops: "flash\nattach".into(),
        expires,
        created_by: None,
    };
    let kb = SubjectKey::user(bob);
    let ka = SubjectKey::user(alice);
    s.scoped(a).insert_grant(&to(&kb, None), NOW).await.unwrap();
    s.scoped(c)
        .insert_grant(&to(&kb, Some(NOW + 10)), NOW)
        .await
        .unwrap();
    s.scoped(c)
        .insert_grant(&to(&kb, Some(NOW)), NOW)
        .await
        .unwrap();
    s.scoped(b).insert_grant(&to(&ka, None), NOW).await.unwrap();
    let got = s.grants_for_subject(&kb, NOW).await.unwrap();
    let mut nss: Vec<_> = got.iter().map(|g| g.ns).collect();
    nss.sort();
    let mut want = vec![a, c];
    want.sort();
    assert_eq!(nss, want);
    assert!(got.iter().all(|g| g.subject == kb.to_string()));
    assert_eq!(s.grants_for_subject(&kb, NOW + 10).await.unwrap().len(), 1);
    // Listing is scoped and includes expired rows.
    assert_eq!(s.scoped(c).list_grants().await.unwrap().len(), 2);
    assert!(s
        .scoped(b)
        .list_grants()
        .await
        .unwrap()
        .iter()
        .all(|g| g.ns == b));
}

#[tokio::test]
async fn grant_upsert_and_revocation() {
    let s = store(fleet()).await;
    let (alice, a) = s.create_local_user("alice", None, NOW).await.unwrap();
    let (bob, b) = s.create_local_user("bob", None, NOW).await.unwrap();
    let (a, b) = (a.unwrap(), b.unwrap());
    let g = |ops: &str, who| NewGrant {
        subject: SubjectKey::user(who),
        selector: "*".into(),
        ops: ops.into(),
        expires: Some(NOW + 100),
        created_by: None,
    };
    let id = forgs::GrantId::generate(NOW * 1000);
    s.scoped(a)
        .upsert_grant(id, &g("x", bob), NOW)
        .await
        .unwrap();
    s.scoped(a)
        .upsert_grant(id, &g("y", bob), NOW)
        .await
        .unwrap();
    let rows = s.scoped(a).list_grants().await.unwrap();
    assert_eq!((rows.len(), rows[0].ops.as_str()), (1, "y"));
    // Another namespace, or another subject, cannot take the id over.
    assert!(matches!(
        s.scoped(b).upsert_grant(id, &g("z", bob), NOW).await,
        Err(StoreError::GrantConflict)
    ));
    assert!(matches!(
        s.scoped(a).upsert_grant(id, &g("z", alice), NOW).await,
        Err(StoreError::GrantConflict)
    ));
    assert!(s.scoped(a).insert_grant(&g("z", bob), NOW).await.is_ok());
    // Revocation is scoped by namespace.
    assert!(s.scoped(b).delete_grant(id).await.unwrap().is_none());
    let prefix = id.to_string()[..10].to_ascii_lowercase();
    assert!(s
        .scoped(b)
        .delete_grants_by_prefix(&prefix)
        .await
        .unwrap()
        .is_empty());
    assert!(matches!(
        s.scoped(a).delete_grants_by_prefix("01").await,
        Err(StoreError::BadPrefix)
    ));
    let del = s
        .scoped(a)
        .delete_grants_by_prefix(&id.to_string())
        .await
        .unwrap();
    assert_eq!(del.len(), 1);
    assert_eq!(del[0].id, id);
    assert_eq!(s.scoped(a).list_grants().await.unwrap().len(), 1);
    let rest = s.scoped(a).list_grants().await.unwrap()[0].id;
    assert!(s.scoped(a).delete_grant(rest).await.unwrap().is_some());
}

// ---------------------------------------------------------------------------
// Pending flows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pending_signups_are_one_shot_and_expire() {
    let s = store(fleet()).await;
    let id = ident("github", "7", Some("x@y.org"));
    let t = s
        .insert_pending_signup(&id, Some("kasp"), NOW, NOW + 900)
        .await
        .unwrap();
    assert_eq!(
        s.pending_signup(t, NOW)
            .await
            .unwrap()
            .unwrap()
            .suggested_username
            .as_deref(),
        Some("kasp")
    );
    let got = s.take_pending_signup(t, NOW).await.unwrap().unwrap();
    assert_eq!(got.provider_subject, "7");
    assert!(s.take_pending_signup(t, NOW).await.unwrap().is_none());

    let t = s
        .insert_pending_signup(&id, None, NOW, NOW + 900)
        .await
        .unwrap();
    assert!(s.take_pending_signup(t, NOW + 900).await.unwrap().is_none());

    // signup_pending: a failed name choice keeps the ticket.
    s.create_local_user("taken", None, NOW).await.unwrap();
    let t = s
        .insert_pending_signup(&id, None, NOW, NOW + 900)
        .await
        .unwrap();
    assert!(matches!(
        s.signup_pending(t, "taken", None, NOW).await,
        Err(StoreError::NameTaken)
    ));
    let (user, _) = s
        .signup_pending(t, "kaspar", None, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        s.user_by_identity("github", "7").await.unwrap().unwrap().id,
        user
    );
    assert!(s
        .signup_pending(t, "other", None, NOW)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn device_approval_state_machine() {
    let s = store(fleet()).await;
    let (alice, ns) = s.create_local_user("alice", None, NOW).await.unwrap();
    let exp = NOW + 900;
    let (_, code) = s
        .insert_pending_device(
            || "AAAAAAAA".into(),
            &hash(1),
            Some("{}"),
            Some("10.0.0.1"),
            NOW,
            exp,
        )
        .await
        .unwrap();
    assert_eq!(s.live_pending_device_count(NOW).await.unwrap(), 1);
    // Not approved: nothing to consume.
    assert!(s
        .consume_pending_device(&hash(1), NOW)
        .await
        .unwrap()
        .is_none());
    assert!(s
        .approve_pending_device(&code, ns, alice, NOW)
        .await
        .unwrap());
    // Approval is exactly once, and cannot then be denied.
    assert!(!s
        .approve_pending_device(&code, None, alice, NOW)
        .await
        .unwrap());
    assert!(!s.deny_pending_device(&code, NOW).await.unwrap());
    let row = s.pending_device_by_code(&code, NOW).await.unwrap().unwrap();
    assert!(row.is_approved());
    let got = s
        .consume_pending_device(&hash(1), NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (got.ns, got.approved_by, got.payload.as_deref()),
        (ns, alice, Some("{}"))
    );
    assert!(s
        .consume_pending_device(&hash(1), NOW)
        .await
        .unwrap()
        .is_none());
    assert_eq!(s.live_pending_device_count(NOW).await.unwrap(), 0);

    // Denial is final.
    let (_, code2) = s
        .insert_pending_device(|| "BBBBBBBB".into(), &hash(2), None, None, NOW, exp)
        .await
        .unwrap();
    assert!(s.deny_pending_device(&code2, NOW).await.unwrap());
    assert!(s
        .pending_device_by_hash(&hash(2), NOW)
        .await
        .unwrap()
        .unwrap()
        .is_denied());
    assert!(!s
        .approve_pending_device(&code2, None, alice, NOW)
        .await
        .unwrap());
    assert!(s
        .consume_pending_device(&hash(2), NOW)
        .await
        .unwrap()
        .is_none());

    // Expiry at every transition (exclusive).
    let (_, code3) = s
        .insert_pending_device(|| "CCCCCCCC".into(), &hash(3), None, None, NOW, exp)
        .await
        .unwrap();
    assert!(s
        .pending_device_by_code(&code3, exp)
        .await
        .unwrap()
        .is_none());
    assert!(!s
        .approve_pending_device(&code3, None, alice, exp)
        .await
        .unwrap());
    assert!(!s.deny_pending_device(&code3, exp).await.unwrap());
    assert!(s
        .approve_pending_device(&code3, None, alice, exp - 1)
        .await
        .unwrap());
    assert!(s
        .consume_pending_device(&hash(3), exp)
        .await
        .unwrap()
        .is_none());

    // Code collisions are retried; three in a row surface.
    let mut codes = ["AAAAAAAA", "BBBBBBBB", "DDDDDDDD"].into_iter();
    let (_, code4) = s
        .insert_pending_device(
            || codes.next().unwrap().into(),
            &hash(4),
            None,
            None,
            NOW,
            exp,
        )
        .await
        .unwrap();
    assert_eq!(code4, "DDDDDDDD");
    assert!(s
        .insert_pending_device(|| "AAAAAAAA".into(), &hash(5), None, None, NOW, exp)
        .await
        .is_err());
    // A device-hash collision is not retried.
    let mut n = 0;
    assert!(s
        .insert_pending_device(
            || {
                n += 1;
                format!("EEEEEEE{n}")
            },
            &hash(4),
            None,
            None,
            NOW,
            exp
        )
        .await
        .is_err());
    assert_eq!(n, 1);
}

// ---------------------------------------------------------------------------
// Sweep
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sweep_removes_exactly_the_dead_rows() {
    let s = store(fleet()).await;
    let (alice, ns) = s.create_local_user("alice", None, NOW).await.unwrap();
    let scope = s.scoped(ns.unwrap());
    let t = NOW + 100;
    s.insert_session(&hash(1), alice, NOW, t).await.unwrap(); // dead (== now)
    s.insert_session(&hash(2), alice, NOW, t + 1).await.unwrap();
    s.insert_refresh_token(&hash(3), alice, NOW, t - 1)
        .await
        .unwrap(); // dead
    s.insert_refresh_token(&hash(4), alice, NOW, t + 1)
        .await
        .unwrap();
    let w = forgs::subject::workload_subject_key("a/b");
    s.insert_workload_token(&hash(5), &w, "github_oidc", None, NOW, t)
        .await
        .unwrap(); // dead
    s.insert_workload_token(&hash(6), &w, "github_oidc", None, NOW, t + 1)
        .await
        .unwrap();
    scope
        .insert_api_key(&key(hash(7), true, Some(t)), NOW)
        .await
        .unwrap(); // dead
    scope
        .insert_api_key(&key(hash(8), true, None), NOW)
        .await
        .unwrap();
    scope
        .insert_api_key(&key(hash(9), true, None), NOW)
        .await
        .unwrap();
    s.consume_api_key(&hash(9), NOW).await.unwrap().unwrap(); // dead (consumed)
    scope
        .insert_api_key(&key(hash(10), false, None), NOW)
        .await
        .unwrap();
    s.consume_api_key(&hash(10), NOW).await.unwrap().unwrap(); // multi-use: live
    let id = ident("github", "1", None);
    s.insert_pending_signup(&id, None, NOW, t).await.unwrap(); // dead
    s.insert_pending_signup(&id, None, NOW, t + 1)
        .await
        .unwrap();
    s.insert_pending_device(|| "AAAAAAAA".into(), &hash(11), None, None, NOW, t)
        .await
        .unwrap(); // dead
    s.insert_pending_device(|| "BBBBBBBB".into(), &hash(12), None, None, NOW, t + 9)
        .await
        .unwrap();
    s.deny_pending_device("BBBBBBBB", NOW).await.unwrap(); // dead (decided)
    s.insert_pending_device(|| "CCCCCCCC".into(), &hash(13), None, None, NOW, t + 9)
        .await
        .unwrap();

    let got = s.sweep(t).await.unwrap();
    assert_eq!(
        got,
        SweepCounts {
            sessions: 1,
            refresh_tokens: 1,
            workload_tokens: 1,
            api_keys: 2,
            pending_signups: 1,
            pending_devices: 2,
        }
    );
    assert_eq!(s.sweep(t).await.unwrap(), SweepCounts::default());
    assert!(s.lookup_session(&hash(2)).await.unwrap().is_some());
    assert!(s.lookup_refresh_token(&hash(4)).await.unwrap().is_some());
    assert!(s.lookup_workload(&hash(6)).await.unwrap().is_some());
    assert_eq!(scope.list_api_keys().await.unwrap().len(), 2);
    assert!(s.lookup_device_secret(&hash(13)).await.unwrap().is_some());
}

#[tokio::test]
async fn a_file_database_round_trips() {
    let dir = std::env::temp_dir().join(format!("forgs-store-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("db.sqlite");
    let path = path.to_str().unwrap();
    {
        let s = Store::connect(path, fleet(), RoleLadder::default())
            .await
            .unwrap();
        s.create_local_user("alice", None, NOW).await.unwrap();
        s.pool().close().await;
    }
    let s = Store::connect(path, fleet(), RoleLadder::default())
        .await
        .unwrap();
    assert!(s.user_by_username("alice").await.unwrap().is_some());
    s.pool().close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn create_node_with_admin_is_atomic_and_capped() {
    let s = store(forge()).await;
    let (alice, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    let (bob, _) = s.create_local_user("bob", None, NOW).await.unwrap();
    let alice_key = SubjectKey::user(alice);

    // Alice's personal org does not count towards the cap.
    let team = s
        .create_node_with_admin(None, "org", "Team", NameOrigin::User, alice, Some(1), NOW)
        .await
        .unwrap();
    let node = s.node(team).await.unwrap().unwrap();
    assert_eq!(node.owner, Some(alice));
    assert_eq!(node.personal_of, None);
    assert_eq!(node.name, "Team");
    assert_eq!(
        s.effective_role(team, &alice_key).await.unwrap(),
        Some(s.roles().highest())
    );

    let nodes = count(&s, "forgs_ns_node").await;
    let members = count(&s, "forgs_membership").await;
    // At the cap: refused, nothing left behind.
    let r = s
        .create_node_with_admin(None, "org", "team2", NameOrigin::User, alice, Some(1), NOW)
        .await;
    assert!(matches!(r, Err(StoreError::OwnedLimit)), "{r:?}");
    let r = s
        .create_node_with_admin(None, "org", "zero", NameOrigin::User, bob, Some(0), NOW)
        .await;
    assert!(matches!(r, Err(StoreError::OwnedLimit)), "{r:?}");
    // A name failure leaves no membership behind.
    let r = s
        .create_node_with_admin(None, "org", "team", NameOrigin::User, bob, None, NOW)
        .await;
    assert!(matches!(r, Err(StoreError::NameTaken)), "{r:?}");
    let r = s
        .create_node_with_admin(None, "nope", "x", NameOrigin::User, bob, None, NOW)
        .await;
    assert!(matches!(r, Err(StoreError::UnknownKind(_))), "{r:?}");
    assert_eq!(count(&s, "forgs_ns_node").await, nodes);
    assert_eq!(count(&s, "forgs_membership").await, members);

    // Another user's nodes do not count; nor do Alice's under another parent.
    s.create_node_with_admin(None, "org", "bobs", NameOrigin::User, bob, Some(1), NOW)
        .await
        .unwrap();
    s.create_node_with_admin(
        Some(team),
        "project",
        "p1",
        NameOrigin::User,
        alice,
        Some(1),
        NOW,
    )
    .await
    .unwrap();
    let r = s
        .create_node_with_admin(
            Some(team),
            "project",
            "p2",
            NameOrigin::User,
            alice,
            Some(1),
            NOW,
        )
        .await;
    assert!(matches!(r, Err(StoreError::OwnedLimit)), "{r:?}");
    s.create_node_with_admin(
        Some(team),
        "project",
        "p2",
        NameOrigin::User,
        bob,
        Some(1),
        NOW,
    )
    .await
    .unwrap();

    // A parent with children cannot be deleted.
    let r = s.delete_node(team, NOW).await;
    assert!(matches!(r, Err(StoreError::HasChildren)), "{r:?}");
}
