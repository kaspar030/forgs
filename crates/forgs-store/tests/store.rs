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
    ApiKeyCap, AuditEntry, AuditRow, GrantRow, NewApiKey, NewGrant, NewIdentity, NewSignup, NsNode,
    ReleaseCause, ReleaseLimit, Store, StoreError, SweepCounts, UserState, DEFAULT_RELEASE_LIMIT,
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
    let want: Vec<(i64,)> = (1..=forgs_store::SCHEMA_VERSION).map(|v| (v,)).collect();
    assert_eq!(rows, want);
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
        s.delete_node(proj, None, NOW).await,
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
        s.insert_session(&hash(1), ghost, NOW, NOW, NOW + 10).await,
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

/// SC-6: a pooled connection with foreign keys turned off after migration is
/// refused at the next write transaction, rather than deleting a user without
/// cascading their sessions.
#[tokio::test]
async fn a_write_on_a_connection_without_foreign_keys_is_refused() {
    let s = store(fleet()).await;
    let (user, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    s.insert_session(&hash(1), user, NOW, NOW, NOW + 10)
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(s.pool())
        .await
        .unwrap();
    assert!(matches!(
        s.delete_user(user, None, NOW).await,
        Err(StoreError::ForeignKeysOff)
    ));
    assert_eq!(count(&s, "forgs_session").await, 1);
    assert_eq!(count(&s, "forgs_user").await, 1);
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(s.pool())
        .await
        .unwrap();
    s.delete_user(user, None, NOW).await.unwrap();
    assert_eq!(count(&s, "forgs_session").await, 0);
}

/// SC-6: a migration that finds dangling `forgs_` rows (written with foreign
/// keys off) is rolled back.
#[tokio::test]
async fn a_migration_refuses_dangling_forgs_rows() {
    let opts = forgs_store::connect_options("sqlite::memory:").unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE TABLE forgs_schema_version (
             version INTEGER NOT NULL PRIMARY KEY, applied_at INTEGER NOT NULL) STRICT",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!("../migrations/0001_init.sql"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO forgs_schema_version VALUES (1, 0)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(
        "PRAGMA foreign_keys = OFF;
         INSERT INTO forgs_session (token_hash, user_id, issued_at, expires)
              VALUES ('00', 'ghost', 0, 1);
         PRAGMA foreign_keys = ON;",
    )
    .execute(&pool)
    .await
    .unwrap();
    match forgs_store::migrate(&pool).await {
        Err(StoreError::ForeignKeyViolations { version, tables }) => {
            assert_eq!(version, 2);
            assert_eq!(tables, ["forgs_session"]);
        }
        other => panic!("expected ForeignKeyViolations, got {other:?}"),
    }
    let (v,): (i64,) = sqlx::query_as("SELECT MAX(version) FROM forgs_schema_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(v, 1);
}

/// SC-7: every credential-hash column refuses anything but 64 lowercase hex.
#[tokio::test]
async fn malformed_token_hashes_are_refused() {
    let s = store(fleet()).await;
    let (user, ns) = s.create_local_user("alice", None, NOW).await.unwrap();
    let ns = ns.unwrap();
    for bad in [
        "ab".repeat(31),
        "ab".repeat(33),
        "AB".repeat(32),
        format!("{}g", "a".repeat(63)),
        "secret_token_plaintext".to_owned(),
    ] {
        let bad = TokenHash::from_hex(bad);
        assert!(matches!(
            s.insert_session(&bad, user, NOW, NOW, NOW + 10).await,
            Err(StoreError::MalformedHash)
        ));
        assert!(matches!(
            s.insert_refresh_token(&bad, user, NOW, NOW + 10).await,
            Err(StoreError::MalformedHash)
        ));
        assert!(matches!(
            s.scoped(ns)
                .insert_api_key(&key(bad.clone(), true, None), NOW)
                .await,
            Err(StoreError::MalformedHash)
        ));
        for (table, col) in [
            ("forgs_workload_token", "token_hash"),
            ("forgs_pending_device", "device_hash"),
        ] {
            let sql = if table == "forgs_workload_token" {
                "INSERT INTO forgs_workload_token (token_hash, subject, issuer, issued_at, expires)
                 VALUES (?1, 'user:x', 'app', 0, 1)"
            } else {
                "INSERT INTO forgs_pending_device (id, user_code, device_hash, created_at, expires)
                 VALUES ('d', 'CODE', ?1, 0, 1)"
            };
            let e = sqlx::query(sql)
                .bind(bad.as_str())
                .execute(s.pool())
                .await
                .unwrap_err();
            assert!(
                e.to_string().contains("malformed token hash"),
                "{table}.{col}: {e}"
            );
        }
    }
    // Updating a stored hash to a malformed one is refused too.
    s.insert_session(&hash(1), user, NOW, NOW, NOW + 10)
        .await
        .unwrap();
    let e = sqlx::query("UPDATE forgs_session SET token_hash = 'x'")
        .execute(s.pool())
        .await
        .unwrap_err();
    assert!(e.to_string().contains("malformed token hash"));
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
async fn identities_are_listed_and_unlinked_but_never_the_last() {
    let s = store(fleet()).await;
    let (alice, _) = s.signup(&signup("alice", "1", None), NOW).await.unwrap();
    let (bob, _) = s.signup(&signup("bob", "2", None), NOW).await.unwrap();
    let late = s
        .link_identity(alice, &ident("gitlab", "9", None), NOW + 10)
        .await
        .unwrap();
    s.link_identity(alice, &ident("forgejo", "8", None), NOW + 20)
        .await
        .unwrap();
    let ids = s.identities_for_user(alice).await.unwrap();
    assert_eq!(
        ids.iter().map(|i| i.provider.as_str()).collect::<Vec<_>>(),
        ["github", "gitlab", "forgejo"]
    );
    assert_eq!(ids[1].id, late);
    assert_eq!(ids[1].linked_at, NOW + 10);

    // Another user's id is NotFound, not an unlink.
    let bobs = s.identities_for_user(bob).await.unwrap()[0].id;
    assert!(matches!(
        s.unlink_identity(alice, bobs).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        s.unlink_identity(bob, bobs).await,
        Err(StoreError::LastIdentity)
    ));
    s.unlink_identity(alice, late).await.unwrap();
    assert!(matches!(
        s.unlink_identity(alice, late).await,
        Err(StoreError::NotFound)
    ));

    // Linked-after keeps everything up to the cut-off ...
    assert_eq!(
        s.unlink_identities_linked_after(alice, NOW + 15)
            .await
            .unwrap(),
        1
    );
    assert_eq!(s.identities_for_user(alice).await.unwrap().len(), 1);
    // ... and never the oldest, even with a cut-off before it.
    assert_eq!(s.unlink_identities_linked_after(alice, 0).await.unwrap(), 0);
    assert_eq!(s.identities_for_user(alice).await.unwrap().len(), 1);
    assert_eq!(s.identities_for_user(bob).await.unwrap().len(), 1);
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
        s.rename_user(bob, "acme", Some(bob), NOW).await,
        Err(StoreError::NameTaken)
    ));
    let other = s
        .create_node(None, "forge", "other", NameOrigin::App, None, NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.rename_node(other, "acme", NameOrigin::App, None, NOW)
            .await,
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
    let r = s.delete_user(alice, None, NOW).await;
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
    s.rename_user(alice, "alicia", Some(alice), NOW)
        .await
        .unwrap();
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
        s.rename_user(alice, "alice", Some(alice), NOW).await,
        Err(StoreError::NameTombstoned)
    ));
    // Renaming into another user's name is refused.
    s.create_local_user("bob", None, NOW).await.unwrap();
    assert!(matches!(
        s.rename_user(alice, "bob", Some(alice), NOW).await,
        Err(StoreError::NameTaken)
    ));
    // Personal nodes are renamed only through the user.
    assert!(matches!(
        s.rename_node(ns, "x", NameOrigin::User, None, NOW).await,
        Err(StoreError::PersonalNode)
    ));
    assert!(matches!(
        s.delete_node(ns, None, NOW).await,
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
    s.rename_node(p, "New", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    let n = s.node(p).await.unwrap().unwrap();
    assert_eq!((n.name.as_str(), n.name_canonical.as_str()), ("New", "new"));
    // Display-only change releases nothing.
    s.rename_node(p, "NEW", NameOrigin::User, None, NOW)
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
    s.delete_node(p, None, NOW).await.unwrap();
    assert!(matches!(
        s.create_node(Some(a), "project", "new", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::NameTombstoned)
    ));
    // A deleted root org's name is blocked for usernames too.
    s.delete_node(b, None, NOW).await.unwrap_err(); // has a child
    let c = s
        .create_node(None, "org", "c-org", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    s.delete_node(c, None, NOW).await.unwrap();
    assert!(matches!(
        s.create_local_user("c-org", None, NOW).await,
        Err(StoreError::NameTombstoned)
    ));
    assert_eq!(count(&s, "forgs_ns_tombstone").await, 3);
}

/// A child kind whose rules keep case.
fn case_keeping() -> Schema {
    Schema::builder()
        .kind("org", KindSpec::root().children(&["project"]))
        .kind(
            "project",
            KindSpec::child().leaf().name_rules(NameRules {
                fold_case: false,
                ..NameRules::default()
            }),
        )
        .build()
        .unwrap()
}

/// AN-6: child names compare case-insensitively for uniqueness, tombstones
/// and lookups, even when the kind keeps case; the display case is kept.
#[tokio::test]
async fn child_names_compare_case_insensitively_even_when_case_is_kept() {
    let s = store(case_keeping()).await;
    let a = s
        .create_node(None, "org", "a-org", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    let p = s
        .create_node(Some(a), "project", "Foo", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    assert_eq!(s.node(p).await.unwrap().unwrap().name_canonical, "Foo");
    assert!(matches!(
        s.create_node(Some(a), "project", "foo", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::NameTaken)
    ));
    // Lookups ignore case.
    for seg in ["Foo", "foo", "FOO"] {
        assert_eq!(
            s.node_by_path(&["a-org", seg]).await.unwrap().map(|n| n.id),
            Some(p),
            "{seg}"
        );
    }
    // A case-only rename releases nothing and changes the stored case.
    s.rename_node(p, "FOO", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    assert_eq!(s.node(p).await.unwrap().unwrap().name_canonical, "FOO");
    assert_eq!(count(&s, "forgs_ns_tombstone").await, 0);
    // A real rename tombstones the old name in every case.
    s.rename_node(p, "Bar", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    for name in ["foo", "Foo", "FOO"] {
        assert!(matches!(
            s.create_node(Some(a), "project", name, NameOrigin::User, None, NOW)
                .await,
            Err(StoreError::NameTombstoned)
        ));
    }
    // So does a delete.
    s.delete_node(p, None, NOW).await.unwrap();
    assert!(matches!(
        s.create_node(Some(a), "project", "bAR", NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::NameTombstoned)
    ));
    // The triggers and index hold for raw SQL writers too.
    let q = s
        .create_node(Some(a), "project", "Baz", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    for name in ["baz", "foo", "bar"] {
        let raw = sqlx::query(
            "INSERT INTO forgs_ns_node (id, parent_id, kind, name, name_canonical, created_at)
             VALUES (?1, ?2, 'project', ?3, ?3, 0)",
        )
        .bind(NsNodeId::generate(1).to_string())
        .bind(a.to_string())
        .bind(name)
        .execute(s.pool())
        .await;
        assert!(raw.is_err(), "{name}");
    }
    let raw = sqlx::query("UPDATE forgs_ns_node SET name_canonical = 'FOO' WHERE id = ?1")
        .bind(q.to_string())
        .execute(s.pool())
        .await;
    assert!(raw.is_err());
}

/// Migration 7 lower-cases existing child tombstones, collapsing case-only
/// duplicates, and refuses to run while case-only siblings exist.
#[tokio::test]
async fn migration_7_folds_child_tombstones() {
    async fn at_v6() -> sqlx::SqlitePool {
        let opts = forgs_store::connect_options("sqlite::memory:").unwrap();
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TABLE forgs_schema_version (
                 version INTEGER NOT NULL PRIMARY KEY, applied_at INTEGER NOT NULL) STRICT",
        )
        .execute(&pool)
        .await
        .unwrap();
        for (v, sql) in [
            (1, include_str!("../migrations/0001_init.sql")),
            (2, include_str!("../migrations/0002_session_auth_time.sql")),
            (
                3,
                include_str!("../migrations/0003_workload_token_source_key.sql"),
            ),
            (4, include_str!("../migrations/0004_audit_ts_index.sql")),
            (5, include_str!("../migrations/0005_tombstone_actor.sql")),
            (6, include_str!("../migrations/0006_workload_jti.sql")),
        ] {
            sqlx::raw_sql(sql).execute(&pool).await.unwrap();
            sqlx::query("INSERT INTO forgs_schema_version VALUES (?1, 0)")
                .bind(v)
                .execute(&pool)
                .await
                .unwrap();
        }
        let a = NsNodeId::from_parts(1, 1).to_string();
        sqlx::query(
            "INSERT INTO forgs_ns_node (id, parent_id, kind, name, name_canonical, created_at)
             VALUES (?1, NULL, 'org', 'a', 'a', 0)",
        )
        .bind(&a)
        .execute(&pool)
        .await
        .unwrap();
        for (name, at) in [("Foo", 1), ("foo", 2), ("Bar", 3)] {
            sqlx::query(
                "INSERT INTO forgs_ns_tombstone (parent_key, name_canonical, released_at)
                 VALUES (?1, ?2, ?3)",
            )
            .bind(&a)
            .bind(name)
            .bind(at)
            .execute(&pool)
            .await
            .unwrap();
        }
        pool
    }
    let pool = at_v6().await;
    forgs_store::migrate(&pool).await.unwrap();
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT name_canonical FROM forgs_ns_tombstone ORDER BY 1")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(rows, [("bar".to_owned(),), ("foo".to_owned(),)]);

    // Case-only siblings block the migration, leaving version 6 in place.
    let pool = at_v6().await;
    for (i, name) in ["Qux", "qux"].into_iter().enumerate() {
        sqlx::query(
            "INSERT INTO forgs_ns_node (id, parent_id, kind, name, name_canonical, created_at)
             VALUES (?1, ?2, 'project', ?3, ?3, 0)",
        )
        .bind(NsNodeId::from_parts(2, i as u128).to_string())
        .bind(NsNodeId::from_parts(1, 1).to_string())
        .bind(name)
        .execute(&pool)
        .await
        .unwrap();
    }
    assert!(forgs_store::migrate(&pool).await.is_err());
    let (v,): (i64,) = sqlx::query_as("SELECT MAX(version) FROM forgs_schema_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(v, 6);
}

/// AN-5: root names may not be id-shaped, so a single-segment reference
/// never means both a node id and a name.
#[tokio::test]
async fn root_names_and_usernames_may_not_be_id_shaped() {
    let s = store(forge()).await;
    let id = NsNodeId::from_parts(9, 9).to_string().to_ascii_lowercase();
    assert!(matches!(
        s.create_node(None, "org", &id, NameOrigin::User, None, NOW)
            .await,
        Err(StoreError::Name(NameError::IdShaped))
    ));
    assert!(matches!(
        s.create_local_user(&id, None, NOW).await,
        Err(StoreError::Name(NameError::IdShaped))
    ));
    let a = s
        .create_node(None, "org", "a-org", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    // A child may be id-shaped: its path has a `/`.
    s.create_node(Some(a), "project", &id, NameOrigin::User, None, NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn root_name_releases_are_rate_limited_per_actor_and_per_holder() {
    const DAY: u64 = 24 * 60 * 60;
    let s = store(forge()).await.with_release_limit(Some(ReleaseLimit {
        max: 2,
        window_secs: 10 * DAY,
    }));
    let (alice, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    s.rename_user(alice, "a1", Some(alice), NOW).await.unwrap();
    s.rename_user(alice, "a2", Some(alice), NOW + 1)
        .await
        .unwrap();
    // The third rename inside the window would burn a third name.
    assert!(matches!(
        s.rename_user(alice, "google", Some(alice), NOW + 2).await,
        Err(StoreError::ReleaseLimited)
    ));
    // Nothing changed: the name is still free for anyone else.
    assert_eq!(s.user_by_id(alice).await.unwrap().unwrap().username, "a2");
    s.create_local_user("google", None, NOW + 3).await.unwrap();
    // Deleting a root node the user created counts too (create-then-delete
    // burns names as well).
    let org = s
        .create_node(None, "org", "rust-lang", NameOrigin::User, Some(alice), NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.delete_node(org, Some(alice), NOW + 4).await,
        Err(StoreError::ReleaseLimited)
    ));
    assert!(matches!(
        s.rename_node(org, "other", NameOrigin::User, Some(alice), NOW + 4)
            .await,
        Err(StoreError::ReleaseLimited)
    ));
    // Names below the root are not limited.
    let p = s
        .create_node(Some(org), "project", "p1", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    for (i, n) in ["p2", "p3", "p4"].into_iter().enumerate() {
        s.rename_node(p, n, NameOrigin::User, Some(alice), NOW + 5 + i as u64)
            .await
            .unwrap();
    }
    // The app / an operator is never limited.
    s.rename_user(alice, "a3", None, NOW + 9).await.unwrap();
    // After the window the user may release again.
    s.rename_user(alice, "a4", Some(alice), NOW + 10 * DAY + 2)
        .await
        .unwrap();

    // Per holder: one root node renamed by different admins.
    let (bob, _) = s.create_local_user("bob", None, NOW).await.unwrap();
    let (carol, _) = s.create_local_user("carol", None, NOW).await.unwrap();
    let (dave, _) = s.create_local_user("dave", None, NOW).await.unwrap();
    let team = s
        .create_node(None, "org", "team", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    s.rename_node(team, "team1", NameOrigin::User, Some(bob), NOW)
        .await
        .unwrap();
    s.rename_node(team, "team2", NameOrigin::User, Some(carol), NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.rename_node(team, "team3", NameOrigin::User, Some(dave), NOW)
            .await,
        Err(StoreError::ReleaseLimited)
    ));
    // A display-only change releases nothing and is never limited.
    s.rename_node(team, "TEAM2", NameOrigin::User, Some(dave), NOW)
        .await
        .unwrap();

    // Unlimited store.
    let s = store(forge()).await.with_release_limit(None);
    let (eve, _) = s.create_local_user("eve", None, NOW).await.unwrap();
    for i in 0..10 {
        s.rename_user(eve, &format!("eve{i}"), Some(eve), NOW)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn tombstones_record_their_actor_and_can_be_released_by_an_operator() {
    let s = store(forge()).await;
    assert_eq!(s.release_limit(), Some(DEFAULT_RELEASE_LIMIT));
    let (mallory, _) = s.create_local_user("mallory", None, NOW).await.unwrap();
    let (alice, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    s.rename_user(mallory, "google", Some(mallory), NOW)
        .await
        .unwrap();
    s.rename_user(mallory, "rust-lang", Some(mallory), NOW + 10)
        .await
        .unwrap();
    s.rename_user(alice, "alicia", Some(alice), NOW)
        .await
        .unwrap();
    let org = s
        .create_node(None, "org", "acme", NameOrigin::User, Some(alice), NOW)
        .await
        .unwrap();
    s.delete_node(org, None, NOW + 20).await.unwrap();

    let burned = s.tombstones_released_by(mallory).await.unwrap();
    assert_eq!(
        burned.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["mallory", "google"]
    );
    assert_eq!(burned[0].released_by, Some(mallory));
    assert_eq!(burned[0].user, Some(mallory));
    assert_eq!(burned[0].cause, Some(ReleaseCause::Rename));
    assert_eq!(burned[0].released_at, NOW);
    assert_eq!(burned[0].parent, None);
    let acme = s.tombstone(None, "ACME").await.unwrap().unwrap();
    assert_eq!(acme.released_by, None);
    assert_eq!(acme.node, Some(org));
    assert_eq!(acme.cause, Some(ReleaseCause::Delete));

    // Release only what came after a point in time...
    assert_eq!(
        s.release_tombstones_by(mallory, Some(NOW + 5))
            .await
            .unwrap(),
        1
    );
    assert!(s.tombstone(None, "google").await.unwrap().is_none());
    // ... and the freed name is claimable again.
    s.create_local_user("google", None, NOW + 30).await.unwrap();
    assert_eq!(s.release_tombstones_by(mallory, None).await.unwrap(), 1);
    // Every name mallory burned is free again (mallory now holds "rust-lang").
    s.create_local_user("mallory", None, NOW + 30)
        .await
        .unwrap();
    // One name at a time.
    assert!(s.release_tombstone(None, "Alice").await.unwrap());
    assert!(!s.release_tombstone(None, "alice").await.unwrap());
    s.create_local_user("alice", None, NOW + 30).await.unwrap();
    assert!(s.tombstones_released_by(alice).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_tombstone_cooldown_releases_old_names_on_sweep() {
    const DAY: u64 = 24 * 60 * 60;
    let s = store(forge()).await;
    let (alice, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    s.rename_user(alice, "alicia", Some(alice), NOW)
        .await
        .unwrap();
    // Forever by default.
    assert_eq!(s.tombstone_cooldown(), None);
    assert_eq!(s.sweep(NOW + 1000 * DAY).await.unwrap().tombstones, 0);
    let s = s.with_tombstone_cooldown(Some(30 * DAY));
    assert_eq!(s.sweep(NOW + 30 * DAY).await.unwrap().tombstones, 0);
    assert!(matches!(
        s.create_local_user("alice", None, NOW + 30 * DAY).await,
        Err(StoreError::NameTombstoned)
    ));
    assert_eq!(s.sweep(NOW + 30 * DAY + 1).await.unwrap().tombstones, 1);
    s.create_local_user("alice", None, NOW + 31 * DAY)
        .await
        .unwrap();
}

#[tokio::test]
async fn triggers_block_raw_sql_writes_of_tombstoned_names() {
    let s = store(forge()).await;
    let (alice, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    s.rename_user(alice, "alicia", Some(alice), NOW)
        .await
        .unwrap();
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
    assert_eq!(
        s.ancestors(NsNodeId::generate(1)).await.unwrap(),
        Vec::<NsNode>::new()
    );

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
async fn api_key_caps_count_live_keys_only() {
    let s = store(fleet()).await;
    let (alice, a) = s.create_local_user("alice", None, NOW).await.unwrap();
    let (bob, _) = s.create_local_user("bob", None, NOW).await.unwrap();
    let a = a.unwrap();
    let scope = s.scoped(a);
    let by = |n: u8, u: UserId, exp: Option<u64>| NewApiKey {
        created_by: Some(u),
        ..key(hash(n), true, exp)
    };
    let cap = ApiKeyCap {
        per_namespace: Some(3),
        per_creator: Some(2),
    };
    scope
        .insert_api_key_capped(&by(1, alice, Some(NOW + 10)), NOW, cap)
        .await
        .unwrap();
    scope
        .insert_api_key_capped(&by(2, alice, Some(NOW + 10)), NOW, cap)
        .await
        .unwrap();
    assert!(matches!(
        scope
            .insert_api_key_capped(&by(3, alice, Some(NOW + 10)), NOW, cap)
            .await,
        Err(StoreError::KeyLimit)
    ));
    scope
        .insert_api_key_capped(&by(4, bob, Some(NOW + 10)), NOW, cap)
        .await
        .unwrap();
    // The namespace is full for everyone, including a shell-minted key.
    assert!(matches!(
        scope
            .insert_api_key_capped(&by(5, bob, Some(NOW + 10)), NOW, cap)
            .await,
        Err(StoreError::KeyLimit)
    ));
    assert!(matches!(
        scope
            .insert_api_key_capped(&key(hash(6), true, None), NOW, cap)
            .await,
        Err(StoreError::KeyLimit)
    ));
    // The uncapped insert (operator path) is never refused.
    scope
        .insert_api_key(&key(hash(7), true, None), NOW)
        .await
        .unwrap();
    // Once expired, keys stop counting.
    scope
        .delete_api_keys_by_prefix(&hash(7).as_str()[..8])
        .await
        .unwrap();
    scope
        .insert_api_key_capped(&by(8, alice, Some(NOW + 100)), NOW + 11, cap)
        .await
        .unwrap();
}

#[tokio::test]
async fn api_keys_and_members_page() {
    let s = store(fleet()).await;
    let (_, a) = s.create_local_user("alice", None, NOW).await.unwrap();
    let a = a.unwrap();
    let scope = s.scoped(a);
    for n in 1..=5u8 {
        scope
            .insert_api_key(&key(hash(n), true, None), NOW + u64::from(n))
            .await
            .unwrap();
    }
    let p1 = scope.list_api_keys_page(None, 2).await.unwrap();
    assert_eq!(
        p1.iter().map(|k| k.key_hash.clone()).collect::<Vec<_>>(),
        vec![hash(5), hash(4)]
    );
    let p2 = scope.list_api_keys_page(Some(p1[1].id), 2).await.unwrap();
    assert_eq!(
        p2.iter().map(|k| k.key_hash.clone()).collect::<Vec<_>>(),
        vec![hash(3), hash(2)]
    );
    let p3 = scope.list_api_keys_page(Some(p2[1].id), 2).await.unwrap();
    assert_eq!(p3.len(), 1);
    // Prefix lookups are bounded and validated.
    assert_eq!(
        scope
            .api_keys_by_prefix(&hash(3).as_str()[..8], 2)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(scope
        .api_keys_by_prefix("ffffffff", 2)
        .await
        .unwrap()
        .is_empty());
    assert!(matches!(
        scope.api_keys_by_prefix("abc", 2).await,
        Err(StoreError::BadPrefix)
    ));

    let member = s.roles().lowest();
    for name in ["b", "c", "d"] {
        let agent = forgs::subject::agent_subject_key(&a, name);
        scope.set_member(&agent, member, NOW).await.unwrap();
    }
    let all = scope.list_members().await.unwrap();
    assert_eq!(all.len(), 4);
    let m1 = scope.list_members_page(None, 3).await.unwrap();
    assert_eq!(m1, all[..3]);
    let after = m1[2].subject.to_string();
    let m2 = scope.list_members_page(Some(&after), 3).await.unwrap();
    assert_eq!(m2, all[3..]);
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
    assert_eq!(
        s.scoped(b)
            .delete_api_keys_by_prefix("aaaaaaaa")
            .await
            .unwrap(),
        Vec::<TokenHash>::new()
    );
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
    assert_eq!(
        s.scoped(b.unwrap()).recent_audit(10).await.unwrap(),
        Vec::<AuditRow>::new()
    );
    assert_eq!(s.scoped(a.unwrap()).recent_audit(1).await.unwrap().len(), 1);
}

async fn audit_actions(s: &Store) -> Vec<String> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT action FROM forgs_audit ORDER BY id")
        .fetch_all(s.pool())
        .await
        .unwrap();
    rows.into_iter().map(|(a,)| a).collect()
}

#[tokio::test]
async fn the_sweep_prunes_audit_rows_past_retention() {
    let s = store(fleet()).await.with_audit_retention(Some(100));
    let (_, a) = s.create_local_user("alice", None, NOW).await.unwrap();
    let e = |ts, action| AuditEntry {
        ts,
        subject: None,
        action,
        target: None,
        detail: None,
    };
    s.append_audit(&e(NOW, "old")).await.unwrap();
    s.scoped(a.unwrap())
        .append_audit(&e(NOW, "old.scoped"))
        .await
        .unwrap();
    s.append_audit(&e(NOW + 1, "boundary")).await.unwrap();
    s.append_audit(&e(NOW + 50, "new")).await.unwrap();

    // Cutoff is now - retention = NOW + 1; rows strictly older go.
    let got = s.sweep(NOW + 101).await.unwrap();
    assert_eq!(got.audit, 2);
    assert_eq!(audit_actions(&s).await, ["boundary", "new"]);
    assert_eq!(s.sweep(NOW + 101).await.unwrap().audit, 0);

    // `None` keeps everything.
    let s = s.with_audit_retention(None);
    assert_eq!(s.sweep(u64::MAX >> 2).await.unwrap().audit, 0);
    assert_eq!(audit_actions(&s).await.len(), 2);
}

#[tokio::test]
async fn audit_retention_defaults_to_ninety_days_and_saturates() {
    let s = store(fleet()).await;
    assert_eq!(
        s.audit_retention(),
        Some(forgs_store::DEFAULT_AUDIT_RETENTION_SECS)
    );
    assert_eq!(forgs_store::DEFAULT_AUDIT_RETENTION_SECS, 90 * 86_400);
    let e = AuditEntry {
        ts: 0,
        subject: None,
        action: "ancient",
        target: None,
        detail: None,
    };
    s.append_audit(&e).await.unwrap();
    // now < retention: the cutoff saturates at 0 and nothing goes.
    assert_eq!(s.sweep(10).await.unwrap().audit, 0);
    let got = s
        .sweep(forgs_store::DEFAULT_AUDIT_RETENTION_SECS + 1)
        .await
        .unwrap();
    assert_eq!(got.audit, 1);
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
// API keys die with their creator's standing (audit HTTP-03 / HTTP-10)
// ---------------------------------------------------------------------------

/// alice's personal `org` (forge schema) with a `project` child; bob is a
/// member of the org (inherited at the project) and mints `n` multi-use keys
/// in the project.
async fn creator_fixture() -> (Store, UserId, NsNodeId, NsNodeId) {
    let s = store(forge()).await;
    let (_, org) = s.create_local_user("alice", None, NOW).await.unwrap();
    let org = org.unwrap();
    let (bob, _) = s.create_local_user("bob", None, NOW).await.unwrap();
    let project = s
        .create_node(Some(org), "project", "p", NameOrigin::User, None, NOW)
        .await
        .unwrap();
    s.scoped(org)
        .set_member(&SubjectKey::user(bob), s.roles().lowest(), NOW)
        .await
        .unwrap();
    (s, bob, org, project)
}

fn bobs_key(h: TokenHash, bob: UserId, single_use: bool) -> NewApiKey {
    let mut k = key(h, single_use, None);
    k.created_by = Some(bob);
    k
}

async fn mint_from(
    s: &Store,
    key_hash: &TokenHash,
    token: &TokenHash,
) -> forgs_store::ConsumedApiKey {
    let k = s.consume_api_key(key_hash, NOW).await.unwrap().unwrap();
    let w = forgs::subject::workload_subject_key("gha", "1", "2").unwrap();
    s.insert_key_workload_token(token, &w, "api_key", k.id, NOW, NOW + 100)
        .await
        .unwrap();
    k
}

#[tokio::test]
async fn a_disabled_creators_keys_stop_redeeming_and_their_tokens_die() {
    let (s, bob, _, project) = creator_fixture().await;
    s.scoped(project)
        .insert_api_key(&bobs_key(hash(1), bob, false), NOW)
        .await
        .unwrap();
    // Membership inherited from the org is enough.
    let k = mint_from(&s, &hash(1), &hash(0x51)).await;
    assert!(s.api_key_creator_live(&k).await.unwrap());
    // An unrelated OIDC token is untouched by everything below.
    let w = forgs::subject::workload_subject_key("gha", "3", "4").unwrap();
    s.insert_workload_token(&hash(0x52), &w, "github_oidc", None, NOW, NOW + 100)
        .await
        .unwrap();

    s.set_user_state(bob, UserState::Disabled).await.unwrap();
    assert!(s.lookup_workload(&hash(0x51)).await.unwrap().is_none());
    assert!(s.lookup_workload(&hash(0x52)).await.unwrap().is_some());
    assert!(!s.api_key_creator_live(&k).await.unwrap());
    assert!(s.consume_api_key(&hash(1), NOW).await.unwrap().is_none());
    // The key is kept, inert, and works again after re-enabling.
    assert!(s.api_key_by_hash(&hash(1)).await.unwrap().is_some());
    s.set_user_state(bob, UserState::Active).await.unwrap();
    assert!(s.consume_api_key(&hash(1), NOW).await.unwrap().is_some());
}

#[tokio::test]
async fn a_removed_creators_keys_stop_redeeming_and_their_tokens_die() {
    let (s, bob, org, project) = creator_fixture().await;
    let kb = SubjectKey::user(bob);
    s.scoped(project)
        .insert_api_key(&bobs_key(hash(1), bob, false), NOW)
        .await
        .unwrap();
    // A direct membership at the project as well as the inherited one.
    s.scoped(project)
        .set_member(&kb, s.roles().lowest(), NOW)
        .await
        .unwrap();
    mint_from(&s, &hash(1), &hash(0x51)).await;

    // Removing one of two memberships leaves the key (and token) live.
    assert!(s.scoped(org).remove_member(&kb).await.unwrap());
    assert!(s.lookup_workload(&hash(0x51)).await.unwrap().is_some());
    mint_from(&s, &hash(1), &hash(0x52)).await;

    // Removing the last one kills both tokens and the key.
    assert!(s.scoped(project).remove_member(&kb).await.unwrap());
    assert!(s.lookup_workload(&hash(0x51)).await.unwrap().is_none());
    assert!(s.lookup_workload(&hash(0x52)).await.unwrap().is_none());
    assert!(s.consume_api_key(&hash(1), NOW).await.unwrap().is_none());

    // Re-added: redeemable again.
    s.scoped(org)
        .set_member(&kb, s.roles().lowest(), NOW)
        .await
        .unwrap();
    assert!(s.consume_api_key(&hash(1), NOW).await.unwrap().is_some());
}

#[tokio::test]
async fn shell_minted_keys_have_no_creator_to_lose() {
    let (s, _, _, project) = creator_fixture().await;
    s.scoped(project)
        .insert_api_key(&key(hash(1), false, None), NOW)
        .await
        .unwrap();
    let k = s.consume_api_key(&hash(1), NOW).await.unwrap().unwrap();
    assert_eq!(k.created_by, None);
    assert!(s.api_key_creator_live(&k).await.unwrap());
}

#[tokio::test]
async fn deleting_a_user_deletes_their_keys_and_tokens() {
    let (s, bob, _, project) = creator_fixture().await;
    s.scoped(project)
        .insert_api_key(&bobs_key(hash(1), bob, false), NOW)
        .await
        .unwrap();
    s.scoped(project)
        .insert_api_key(&key(hash(2), false, None), NOW)
        .await
        .unwrap();
    mint_from(&s, &hash(1), &hash(0x51)).await;
    s.delete_user(bob, None, NOW).await.unwrap();
    assert!(s.lookup_workload(&hash(0x51)).await.unwrap().is_none());
    assert!(s.api_key_by_hash(&hash(1)).await.unwrap().is_none());
    // Not an orphaned live key: only the shell-minted one remains.
    let left = s.scoped(project).list_api_keys().await.unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].key_hash, hash(2));
}

#[tokio::test]
async fn deleting_a_user_ends_tokens_from_keys_in_their_personal_node() {
    let s = store(fleet()).await;
    let (bob, personal) = s.create_local_user("bob", None, NOW).await.unwrap();
    let personal = personal.unwrap();
    s.scoped(personal)
        .insert_api_key(&bobs_key(hash(1), bob, false), NOW)
        .await
        .unwrap();
    // A shell-minted key in the same node: its tokens die with the node too.
    s.scoped(personal)
        .insert_api_key(&key(hash(2), false, None), NOW)
        .await
        .unwrap();
    mint_from(&s, &hash(1), &hash(0x51)).await;
    mint_from(&s, &hash(2), &hash(0x52)).await;
    s.delete_user(bob, None, NOW).await.unwrap();
    assert!(s.lookup_workload(&hash(0x51)).await.unwrap().is_none());
    assert!(s.lookup_workload(&hash(0x52)).await.unwrap().is_none());
    assert_eq!(count(&s, "forgs_workload_token").await, 0);
}

#[tokio::test]
async fn deleting_a_node_ends_tokens_from_its_keys() {
    let (s, bob, _, project) = creator_fixture().await;
    s.scoped(project)
        .insert_api_key(&bobs_key(hash(1), bob, false), NOW)
        .await
        .unwrap();
    mint_from(&s, &hash(1), &hash(0x51)).await;
    s.delete_node(project, None, NOW).await.unwrap();
    assert!(s.lookup_workload(&hash(0x51)).await.unwrap().is_none());
}

#[tokio::test]
async fn revoking_a_key_deletes_its_workload_tokens() {
    let (s, bob, _, project) = creator_fixture().await;
    let scope = s.scoped(project);
    scope
        .insert_api_key(&bobs_key(hash(0xaa), bob, false), NOW)
        .await
        .unwrap();
    let id_b = scope
        .insert_api_key(&bobs_key(hash(0xbb), bob, false), NOW)
        .await
        .unwrap();
    scope
        .insert_api_key(&bobs_key(hash(0xcc), bob, false), NOW)
        .await
        .unwrap();
    mint_from(&s, &hash(0xaa), &hash(0x51)).await;
    mint_from(&s, &hash(0xbb), &hash(0x52)).await;
    mint_from(&s, &hash(0xcc), &hash(0x53)).await;
    let w = forgs::subject::workload_subject_key("gha", "3", "4").unwrap();
    s.insert_workload_token(&hash(0x54), &w, "github_oidc", None, NOW, NOW + 100)
        .await
        .unwrap();

    assert_eq!(
        scope.delete_api_keys_by_prefix("aaaaaaaa").await.unwrap(),
        vec![hash(0xaa)]
    );
    assert!(s.lookup_workload(&hash(0x51)).await.unwrap().is_none());
    assert!(s.lookup_workload(&hash(0x52)).await.unwrap().is_some());
    assert!(scope.delete_api_key(id_b).await.unwrap());
    assert!(s.lookup_workload(&hash(0x52)).await.unwrap().is_none());
    // Other keys' tokens and OIDC tokens survive.
    assert!(s.lookup_workload(&hash(0x53)).await.unwrap().is_some());
    assert!(s.lookup_workload(&hash(0x54)).await.unwrap().is_some());
}

#[tokio::test]
async fn the_sweep_keeps_a_consumed_key_while_its_token_lives() {
    let (s, bob, _, project) = creator_fixture().await;
    s.scoped(project)
        .insert_api_key(&bobs_key(hash(1), bob, true), NOW)
        .await
        .unwrap();
    mint_from(&s, &hash(1), &hash(0x51)).await; // token expires NOW + 100
    assert_eq!(s.sweep(NOW + 1).await.unwrap().api_keys, 0);
    // Still reachable through its creator.
    s.set_user_state(bob, UserState::Disabled).await.unwrap();
    assert!(s.lookup_workload(&hash(0x51)).await.unwrap().is_none());
    let got = s.sweep(NOW + 1).await.unwrap();
    assert_eq!(got.api_keys, 1);

    // And with the token expiring instead, both go in one pass.
    s.set_user_state(bob, UserState::Active).await.unwrap();
    s.scoped(project)
        .insert_api_key(&bobs_key(hash(2), bob, true), NOW)
        .await
        .unwrap();
    mint_from(&s, &hash(2), &hash(0x52)).await;
    let got = s.sweep(NOW + 100).await.unwrap();
    assert_eq!((got.workload_tokens, got.api_keys), (1, 1));
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
    s.insert_session(&session.hash(), alice, NOW, NOW, NOW + 100)
        .await
        .unwrap();
    let r = s.lookup_session(&session.hash()).await.unwrap().unwrap();
    assert_eq!((r.user_id, r.expires), (alice, NOW + 100));
    let auth = authenticate(
        &f,
        &s,
        &session.to_secret_string(),
        &[TokenKind::Session],
        NOW + 1,
    )
    .await
    .unwrap();
    assert_eq!(auth.subject, SubjectKey::user(alice));
    assert_eq!(
        authenticate(
            &f,
            &s,
            &session.to_secret_string(),
            &[TokenKind::Session],
            NOW + 100
        )
        .await,
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
    let subject = forgs::subject::workload_subject_key("gha", "1", "2").unwrap();
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
    let auth = authenticate(&f, &s, &wl.to_secret_string(), &[TokenKind::Workload], NOW)
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
    s.insert_session(&neg.hash(), alice, NOW, NOW, NOW)
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
    s.deny_pending_device(&code, alice, NOW).await.unwrap();
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
    s.insert_session(&hash(1), alice, NOW, NOW, NOW + 9)
        .await
        .unwrap();
    s.insert_session(&hash(2), alice, NOW, NOW, NOW + 9)
        .await
        .unwrap();
    s.insert_session(&hash(3), bob, NOW, NOW, NOW + 9)
        .await
        .unwrap();
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

#[tokio::test]
async fn consume_session_is_single_shot_and_bounded() {
    let s = store(fleet()).await;
    let (alice, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    // Live, chain started 50s before its issue.
    s.insert_session(&hash(1), alice, NOW, NOW - 50, NOW + 100)
        .await
        .unwrap();
    let got = s.consume_session(&hash(1), NOW, 0).await.unwrap().unwrap();
    assert_eq!(got.user_id, alice);
    assert_eq!(got.auth_time, NOW - 50);
    // Gone: a second consume (a racing refresher) gets nothing.
    assert!(s.consume_session(&hash(1), NOW, 0).await.unwrap().is_none());
    assert!(s.lookup_session(&hash(1)).await.unwrap().is_none());

    // Expired (expiry is exclusive): refused and left alone.
    s.insert_session(&hash(2), alice, NOW, NOW, NOW + 10)
        .await
        .unwrap();
    assert!(s
        .consume_session(&hash(2), NOW + 10, 0)
        .await
        .unwrap()
        .is_none());
    assert!(s.lookup_session(&hash(2)).await.unwrap().is_some());

    // Chain too old (auth_time <= min_auth_time): refused and left alone.
    s.insert_session(&hash(3), alice, NOW, NOW - 5, NOW + 10)
        .await
        .unwrap();
    assert!(s
        .consume_session(&hash(3), NOW, NOW - 5)
        .await
        .unwrap()
        .is_none());
    assert!(s.lookup_session(&hash(3)).await.unwrap().is_some());
    assert!(s
        .consume_session(&hash(3), NOW, NOW - 6)
        .await
        .unwrap()
        .is_some());

    // Unknown.
    assert!(s.consume_session(&hash(9), NOW, 0).await.unwrap().is_none());
}

#[tokio::test]
async fn concurrent_consume_session_yields_one_winner() {
    let s = store(fleet()).await;
    let (alice, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    s.insert_session(&hash(1), alice, NOW, NOW, NOW + 100)
        .await
        .unwrap();
    let h1 = hash(1);
    let (a, b) = tokio::join!(
        s.consume_session(&h1, NOW, 0),
        s.consume_session(&h1, NOW, 0)
    );
    let wins = [a.unwrap(), b.unwrap()]
        .iter()
        .filter(|r| r.is_some())
        .count();
    assert_eq!(wins, 1);
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
    s.insert_session(&hash(1), alice, NOW, NOW, NOW + 9)
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

    s.delete_user(alice, None, NOW).await.unwrap();
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
    // Their keys are deleted, not orphaned with a NULL creator (which would
    // make them indistinguishable from shell-minted keys, and live).
    assert!(s.scoped(b).list_api_keys().await.unwrap().is_empty());

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
        s.delete_user(alice, None, NOW).await,
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
        s.delete_node(o, None, NOW).await,
        Err(StoreError::HasChildren)
    ));
    s.delete_node(p, None, NOW).await.unwrap();
    assert_eq!(count(&s, "forgs_api_key").await, 0);
    assert_eq!(count(&s, "forgs_grant").await, 0);
    assert_eq!(count(&s, "forgs_membership").await, 1); // alice on her own node
    s.delete_user(alice, None, NOW).await.unwrap();
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
    assert_eq!(
        s.scoped(b).delete_grants_by_prefix(&prefix).await.unwrap(),
        Vec::<GrantRow>::new()
    );
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
    // Approval is exactly once, and cannot then be denied by anyone but
    // the approver.
    assert!(!s
        .approve_pending_device(&code, None, alice, NOW)
        .await
        .unwrap());
    let (bob, _) = s.create_local_user("bob", None, NOW).await.unwrap();
    assert!(!s.deny_pending_device(&code, bob, NOW).await.unwrap());
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
    // A redeemed row cannot be retracted, even by its approver.
    assert!(!s.deny_pending_device(&code, alice, NOW).await.unwrap());

    // The approver can retract an unredeemed approval: it reads as denied
    // and can no longer be redeemed.
    let (_, code_r) = s
        .insert_pending_device(|| "RRRRRRRR".into(), &hash(9), None, None, NOW, exp)
        .await
        .unwrap();
    assert!(s
        .approve_pending_device(&code_r, None, alice, NOW)
        .await
        .unwrap());
    assert!(s.deny_pending_device(&code_r, alice, NOW).await.unwrap());
    let row = s
        .pending_device_by_hash(&hash(9), NOW)
        .await
        .unwrap()
        .unwrap();
    assert!(row.is_denied());
    assert_eq!(
        (row.approved_by, row.approved_at, row.ns),
        (None, None, None)
    );
    assert!(s
        .consume_pending_device(&hash(9), NOW)
        .await
        .unwrap()
        .is_none());

    // Denial is final.
    let (_, code2) = s
        .insert_pending_device(|| "BBBBBBBB".into(), &hash(2), None, None, NOW, exp)
        .await
        .unwrap();
    assert!(s.deny_pending_device(&code2, alice, NOW).await.unwrap());
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
    assert!(!s.deny_pending_device(&code3, alice, exp).await.unwrap());
    assert!(s
        .approve_pending_device(&code3, None, alice, exp - 1)
        .await
        .unwrap());
    assert!(s
        .consume_pending_device(&hash(3), exp)
        .await
        .unwrap()
        .is_none());

    // Live counts split by kind and by source.
    let c = s
        .live_pending_device_counts(NOW, Some("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(
        c,
        forgs_store::LiveCounts {
            logins: 1,
            approvals: 0,
            from_source: 0
        }
    );
    s.insert_pending_device(
        || "SSSSSSS1".into(),
        &hash(21),
        Some("{}"),
        Some("10.0.0.1"),
        NOW,
        exp,
    )
    .await
    .unwrap();
    s.insert_pending_device(
        || "SSSSSSS2".into(),
        &hash(22),
        None,
        Some("10.0.0.1"),
        NOW,
        exp,
    )
    .await
    .unwrap();
    s.insert_pending_device(
        || "SSSSSSS3".into(),
        &hash(23),
        None,
        Some("10.0.0.2"),
        NOW,
        exp,
    )
    .await
    .unwrap();
    let c = s
        .live_pending_device_counts(NOW, Some("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(
        c,
        forgs_store::LiveCounts {
            logins: 3,
            approvals: 1,
            from_source: 2
        }
    );
    let c = s.live_pending_device_counts(NOW, None).await.unwrap();
    assert_eq!((c.logins, c.approvals, c.from_source), (3, 1, 0));
    let c = s
        .live_pending_device_counts(exp, Some("10.0.0.1"))
        .await
        .unwrap();
    assert_eq!(c, forgs_store::LiveCounts::default());
    for code in ["SSSSSSS1", "SSSSSSS2", "SSSSSSS3"] {
        s.deny_pending_device(code, alice, NOW).await.unwrap();
    }

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

#[tokio::test]
async fn workload_jti_is_single_use_per_issuer() {
    let s = store(fleet()).await;
    let w = forgs::subject::workload_subject_key("gha", "1", "2").unwrap();
    assert!(s
        .record_workload_jti("github-actions", "j1", &w, NOW, NOW + 60)
        .await
        .unwrap());
    assert!(!s
        .record_workload_jti("github-actions", "j1", &w, NOW + 1, NOW + 60)
        .await
        .unwrap());
    // jti is only unique within one issuer.
    let g = forgs::subject::workload_subject_key("ghes", "1", "2").unwrap();
    assert!(s
        .record_workload_jti("ghes", "j1", &g, NOW, NOW + 60)
        .await
        .unwrap());
    assert!(s
        .record_workload_jti("github-actions", "j2", &w, NOW, NOW + 60)
        .await
        .unwrap());
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
    s.insert_session(&hash(1), alice, NOW, NOW, t)
        .await
        .unwrap(); // dead (== now)
    s.insert_session(&hash(2), alice, NOW, NOW, t + 1)
        .await
        .unwrap();
    s.insert_refresh_token(&hash(3), alice, NOW, t - 1)
        .await
        .unwrap(); // dead
    s.insert_refresh_token(&hash(4), alice, NOW, t + 1)
        .await
        .unwrap();
    let w = forgs::subject::workload_subject_key("gha", "3", "4").unwrap();
    s.insert_workload_token(&hash(5), &w, "github_oidc", None, NOW, t)
        .await
        .unwrap(); // dead
    s.insert_workload_token(&hash(6), &w, "github_oidc", None, NOW, t + 1)
        .await
        .unwrap();
    assert!(s
        .record_workload_jti("github-actions", "j-dead", &w, NOW, t)
        .await
        .unwrap()); // dead
    assert!(s
        .record_workload_jti("github-actions", "j-live", &w, NOW, t + 1)
        .await
        .unwrap());
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
    s.deny_pending_device("BBBBBBBB", alice, NOW).await.unwrap(); // dead (decided)
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
            workload_jtis: 1,
            api_keys: 2,
            pending_signups: 1,
            pending_devices: 2,
            audit: 0,
            tombstones: 0,
        }
    );
    assert_eq!(s.sweep(t).await.unwrap(), SweepCounts::default());
    assert!(s.lookup_session(&hash(2)).await.unwrap().is_some());
    assert!(s.lookup_refresh_token(&hash(4)).await.unwrap().is_some());
    assert!(s.lookup_workload(&hash(6)).await.unwrap().is_some());
    // The live replay record survives: re-recording it is still a replay,
    // while the swept one may be recorded afresh.
    assert!(!s
        .record_workload_jti("github-actions", "j-live", &w, t, t + 1)
        .await
        .unwrap());
    assert!(s
        .record_workload_jti("github-actions", "j-dead", &w, t, t + 1)
        .await
        .unwrap());
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
    let r = s.delete_node(team, None, NOW).await;
    assert!(matches!(r, Err(StoreError::HasChildren)), "{r:?}");
}

/// A team node `t` with alice and bob as direct admins (fleet schema).
async fn two_admin_team(s: &Store) -> (UserId, UserId, NsNodeId) {
    let (alice, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    let (bob, _) = s.create_local_user("bob", None, NOW).await.unwrap();
    let t = s
        .create_node_with_admin(None, "org", "team", NameOrigin::User, alice, None, NOW)
        .await
        .unwrap();
    s.scoped(t)
        .set_member_guarded(
            &SubjectKey::user(alice),
            &SubjectKey::user(bob),
            s.roles().highest(),
            NOW,
        )
        .await
        .unwrap();
    (alice, bob, t)
}

#[tokio::test]
async fn guarded_membership_writes_keep_an_active_admin() {
    let s = store(fleet()).await;
    let (alice, bob, t) = two_admin_team(&s).await;
    let (ka, kb) = (SubjectKey::user(alice), SubjectKey::user(bob));
    let (low, high) = (s.roles().lowest(), s.roles().highest());
    let (carol, _) = s.create_local_user("carol", None, NOW).await.unwrap();
    let kc = SubjectKey::user(carol);
    // A non-admin actor is refused, even for a harmless change.
    s.scoped(t).set_member(&kc, low, NOW).await.unwrap();
    assert!(matches!(
        s.scoped(t).set_member_guarded(&kc, &kc, low, NOW).await,
        Err(StoreError::NotAdmin)
    ));
    assert!(matches!(
        s.scoped(t).remove_member_guarded(&kc, &kb).await,
        Err(StoreError::NotAdmin)
    ));
    // Bob demotes alice; then bob is the last admin and cannot leave.
    s.scoped(t)
        .set_member_guarded(&kb, &ka, low, NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.scoped(t).set_member_guarded(&kb, &kb, low, NOW).await,
        Err(StoreError::LastAdmin)
    ));
    assert!(matches!(
        s.scoped(t).remove_member_guarded(&kb, &kb).await,
        Err(StoreError::LastAdmin)
    ));
    // Demoted alice lost the actor check.
    assert!(matches!(
        s.scoped(t).remove_member_guarded(&ka, &kb).await,
        Err(StoreError::NotAdmin)
    ));
    // Re-promote alice and disable her: a disabled admin does not count.
    s.scoped(t)
        .set_member_guarded(&kb, &ka, high, NOW)
        .await
        .unwrap();
    let orphaned = s.set_user_state(alice, UserState::Disabled).await.unwrap();
    assert!(orphaned.is_empty(), "bob is still active");
    assert!(matches!(
        s.scoped(t).remove_member_guarded(&kb, &kb).await,
        Err(StoreError::LastAdmin)
    ));
    // ...but she can be removed (she is not an active admin).
    assert!(s.scoped(t).remove_member_guarded(&kb, &ka).await.unwrap());
    // Removing a non-member is a no-op, not an error.
    assert!(!s.scoped(t).remove_member_guarded(&kb, &ka).await.unwrap());
    // Non-admin targets are unaffected by the count.
    assert!(s.scoped(t).remove_member_guarded(&kb, &kc).await.unwrap());
}

#[tokio::test]
async fn a_personal_nodes_owner_cannot_be_evicted_or_demoted() {
    let s = store(fleet()).await;
    let (alice, a) = s.create_local_user("alice", None, NOW).await.unwrap();
    let (bob, _) = s.create_local_user("bob", None, NOW).await.unwrap();
    let a = a.unwrap();
    let (ka, kb) = (SubjectKey::user(alice), SubjectKey::user(bob));
    let high = s.roles().highest();
    s.scoped(a)
        .set_member_guarded(&ka, &kb, high, NOW)
        .await
        .unwrap();
    assert!(matches!(
        s.scoped(a).remove_member_guarded(&kb, &ka).await,
        Err(StoreError::PersonalOwner)
    ));
    assert!(matches!(
        s.scoped(a)
            .set_member_guarded(&kb, &ka, s.roles().lowest(), NOW)
            .await,
        Err(StoreError::PersonalOwner)
    ));
    // Alice can still remove her co-admin.
    assert!(s.scoped(a).remove_member_guarded(&ka, &kb).await.unwrap());
}

#[tokio::test]
async fn deleting_or_disabling_a_sole_admin_is_refused_or_reported() {
    let s = store(fleet()).await;
    let (alice, _) = s.create_local_user("alice", None, NOW).await.unwrap();
    let (bob, _) = s.create_local_user("bob", None, NOW).await.unwrap();
    let t = s
        .create_node_with_admin(None, "org", "team", NameOrigin::User, bob, None, NOW)
        .await
        .unwrap();
    // Alice is sole admin of nothing but her personal node: deletable.
    assert!(s.sole_admin_of(alice).await.unwrap().is_empty());
    // Alice becomes sole admin of t (bob demoted).
    let high = s.roles().highest();
    let (ka, kb) = (SubjectKey::user(alice), SubjectKey::user(bob));
    s.scoped(t)
        .set_member_guarded(&kb, &ka, high, NOW)
        .await
        .unwrap();
    s.scoped(t)
        .set_member_guarded(&ka, &kb, s.roles().lowest(), NOW)
        .await
        .unwrap();
    assert_eq!(s.sole_admin_of(alice).await.unwrap(), vec![t]);
    let r = s.delete_user(alice, None, NOW).await;
    assert!(
        matches!(&r, Err(StoreError::SoleAdmin(v)) if v == &vec![t]),
        "{r:?}"
    );
    assert!(s.user_by_id(alice).await.unwrap().is_some());
    // Disabling is allowed but reports the namespace.
    assert_eq!(
        s.set_user_state(alice, UserState::Disabled).await.unwrap(),
        vec![t]
    );
    // A disabled user is not counted, so it is no longer "sole admin of t".
    assert!(s.sole_admin_of(alice).await.unwrap().is_empty());
    s.set_user_state(alice, UserState::Active).await.unwrap();
    // With a second active admin, deleting works.
    s.scoped(t)
        .set_member_guarded(&ka, &kb, high, NOW)
        .await
        .unwrap();
    s.delete_user(alice, None, NOW).await.unwrap();
}

#[tokio::test]
async fn concurrent_mutual_demotions_leave_an_admin() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("forgs-last-admin");
    std::fs::create_dir_all(&dir).unwrap();
    for round in 0..20 {
        let path = dir.join(format!("r{round}.db"));
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
        let s = Store::connect(path.to_str().unwrap(), fleet(), RoleLadder::default())
            .await
            .unwrap();
        let (alice, bob, t) = two_admin_team(&s).await;
        let (ka, kb) = (SubjectKey::user(alice), SubjectKey::user(bob));
        let low = s.roles().lowest();
        let (s1, s2) = (s.clone(), s.clone());
        let (ka1, kb1, ka2, kb2) = (ka.clone(), kb.clone(), ka.clone(), kb.clone());
        let (r1, r2) = tokio::join!(
            async move { s1.scoped(t).set_member_guarded(&ka1, &kb1, low, NOW).await },
            async move {
                s2.scoped(t)
                    .remove_member_guarded(&kb2, &ka2)
                    .await
                    .map(|_| ())
            },
        );
        assert!(r1.is_ok() != r2.is_ok(), "exactly one wins: {r1:?} {r2:?}");
        let admins = s
            .scoped(t)
            .list_members()
            .await
            .unwrap()
            .into_iter()
            .filter(|m| m.role == s.roles().highest())
            .count();
        assert_eq!(admins, 1);
    }
}
