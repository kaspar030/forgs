-- forgs schema, version 1 (docs/design.md §2–§5).
--
-- These tables live in the **app's** SQLite file, next to its own tables, so
-- that apps can hold foreign keys into `forgs_user` and `forgs_ns_node`. Every
-- table is prefixed `forgs_`, and versions are tracked in `forgs_schema_version`
-- (created by the Rust migrator, `forgs_store::migrate`), never in sqlx's
-- `_sqlx_migrations`, so an app runs its own migrator afterwards on the same
-- pool without either side seeing the other's history.
--
-- Conventions:
--   * ids are TEXT ULIDs (`forgs::ids`), immutable. Names are handles that
--     resolve to ids; every stored reference is an id.
--   * times are INTEGER epoch seconds.
--   * token secrets are never stored: `*_hash` columns hold the lowercase-hex
--     SHA-256 (`forgs::TokenHash`).
--   * `PRAGMA foreign_keys = ON` is required, and the migrator refuses to run
--     without it, so the REFERENCES below are enforced rather than decorative.
--   * STRICT tables: a type mismatch is an error instead of a silent
--     coercion.

-- ---------------------------------------------------------------------------
-- Users and external identities (§4)
-- ---------------------------------------------------------------------------

-- A human. `username` is canonical (trimmed, lower-cased, validated by the
-- schema's username policy) and chosen in forgs, never derived from an
-- identity provider's login. It is also the name of the user's personal
-- namespace node, if the app's schema has a personal kind; the two are renamed
-- together, while the user id and the node id stay separate.
CREATE TABLE forgs_user (
    id           TEXT    NOT NULL PRIMARY KEY,
    username     TEXT    NOT NULL UNIQUE,
    display_name TEXT,
    state        TEXT    NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    created_at   INTEGER NOT NULL
) STRICT;

-- A link between a user and an external identity provider's subject.
--
-- The key is `(provider, immutable provider_subject)` — GitHub's numeric id,
-- an OIDC `sub` — and **never** the email or the login: both get reassigned
-- by providers, and keying on them turns reassignment into account takeover.
-- `provider` is the configured instance name (`github`, `gitlab-work`), so two
-- Forgejo instances are two providers whose subjects never mix. `email` is
-- what the provider last asserted, recorded for display and linking decisions.
CREATE TABLE forgs_identity (
    id               TEXT    NOT NULL PRIMARY KEY,
    user_id          TEXT    NOT NULL REFERENCES forgs_user (id) ON DELETE CASCADE,
    provider         TEXT    NOT NULL CHECK (provider <> ''),
    provider_subject TEXT    NOT NULL CHECK (provider_subject <> ''),
    email            TEXT,
    email_verified   INTEGER NOT NULL CHECK (email_verified IN (0, 1)),
    linked_at        INTEGER NOT NULL,
    last_login_at    INTEGER,
    UNIQUE (provider, provider_subject)
) STRICT;

CREATE INDEX forgs_identity_by_user ON forgs_identity (user_id);

-- Verified email addresses, lower-cased. An address belongs to at most one
-- user. Only addresses a provider asserted as *verified* are recorded here:
-- an unverified claim would let anyone squat somebody else's address.
CREATE TABLE forgs_user_email (
    user_id     TEXT    NOT NULL REFERENCES forgs_user (id) ON DELETE CASCADE,
    email       TEXT    NOT NULL UNIQUE CHECK (email <> '' AND email = lower(email)),
    verified_at INTEGER,
    is_primary  INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1))
) STRICT;

CREATE INDEX forgs_user_email_by_user ON forgs_user_email (user_id);
CREATE UNIQUE INDEX forgs_user_email_one_primary ON forgs_user_email (user_id) WHERE is_primary = 1;

-- ---------------------------------------------------------------------------
-- The namespace tree (§2)
-- ---------------------------------------------------------------------------

-- A node of the app-defined namespace tree. `kind` is checked against the
-- app's `forgs::Schema` by the store (SQLite cannot see it). `name` is the
-- display spelling, `name_canonical` the one uniqueness and lookup use.
--
-- `parent_id` is ON DELETE RESTRICT: only leaves can be deleted, so deleting a
-- node never silently takes a subtree (and whatever apps hang off it) along.
--
-- `personal_of_user_id` marks the one personal node of a user (created by
-- signup, renamed with the username). The personal *kind* is also usable for
-- ordinary nodes (fleet's team orgs are the same kind as personal orgs), so the
-- marker has to be per node, not per kind.
--
-- `visibility` NULL means "inherit" (`forgs::authz::effective_visibility`).
CREATE TABLE forgs_ns_node (
    id                  TEXT    NOT NULL PRIMARY KEY,
    parent_id           TEXT    REFERENCES forgs_ns_node (id) ON DELETE RESTRICT,
    kind                TEXT    NOT NULL CHECK (kind <> ''),
    name                TEXT    NOT NULL CHECK (name <> ''),
    name_canonical      TEXT    NOT NULL CHECK (name_canonical <> ''),
    visibility          TEXT    CHECK (visibility IS NULL OR visibility IN ('public', 'internal', 'private')),
    owner_user_id       TEXT    REFERENCES forgs_user (id) ON DELETE RESTRICT,
    personal_of_user_id TEXT    UNIQUE REFERENCES forgs_user (id) ON DELETE RESTRICT,
    external_ref        TEXT,
    created_at          INTEGER NOT NULL,
    CHECK (personal_of_user_id IS NULL
           OR (parent_id IS NULL AND owner_user_id = personal_of_user_id))
) STRICT;

-- Sibling uniqueness, per parent.
--
-- SQLite treats NULLs as distinct in a UNIQUE constraint, so the obvious
-- `UNIQUE (parent_id, name_canonical)` would happily admit two *root* nodes
-- with the same name. Hence two partial indexes: one for children, and one for
-- roots, which share one name space (GitHub's "users and orgs cannot share a
-- name", forgefront's `github` forge node blocking the username `github`).
-- The root index is on `lower(...)` so a root kind whose rules do not fold case
-- still cannot shadow another root by case alone.
CREATE UNIQUE INDEX forgs_ns_node_child_name
    ON forgs_ns_node (parent_id, name_canonical) WHERE parent_id IS NOT NULL;
CREATE UNIQUE INDEX forgs_ns_node_root_name
    ON forgs_ns_node (lower(name_canonical)) WHERE parent_id IS NULL;
CREATE INDEX forgs_ns_node_by_owner ON forgs_ns_node (owner_user_id);

-- Released names, blocked forever (§2 "Renames and handles").
--
-- A released name — from a rename or a deletion, of a node or a username —
-- can never be claimed again, by anyone, including its previous holder;
-- otherwise renaming lets someone squat the old path and receive its traffic.
-- `parent_key` is the parent node id, or '' for the root name space (which
-- usernames share); root names are stored lower-cased, as the root index
-- compares them.
--
-- `node_id` / `user_id` deliberately carry **no** foreign key: a tombstone must
-- outlive the node it came from, and keeps its id so a redirect from the old
-- path can be added later without a schema change.
CREATE TABLE forgs_ns_tombstone (
    parent_key     TEXT    NOT NULL,
    name_canonical TEXT    NOT NULL,
    node_id        TEXT,
    user_id        TEXT,
    released_at    INTEGER NOT NULL,
    PRIMARY KEY (parent_key, name_canonical)
) STRICT, WITHOUT ROWID;

-- Defence in depth. The store checks tombstones and root collisions itself
-- (inside a `BEGIN IMMEDIATE` transaction, so it can return a typed error),
-- but these triggers make the invariants hold for *every* writer, including an
-- app's own SQL or a future code path that forgets to check.

CREATE TRIGGER forgs_ns_node_tombstone_insert
BEFORE INSERT ON forgs_ns_node
WHEN EXISTS (
    SELECT 1 FROM forgs_ns_tombstone t
     WHERE t.parent_key = COALESCE(NEW.parent_id, '')
       AND t.name_canonical = CASE WHEN NEW.parent_id IS NULL
                                   THEN lower(NEW.name_canonical)
                                   ELSE NEW.name_canonical END)
BEGIN
    SELECT RAISE(ABORT, 'forgs: name is tombstoned');
END;

CREATE TRIGGER forgs_ns_node_tombstone_update
BEFORE UPDATE OF name_canonical, parent_id ON forgs_ns_node
WHEN (NEW.name_canonical IS NOT OLD.name_canonical OR NEW.parent_id IS NOT OLD.parent_id)
 AND EXISTS (
    SELECT 1 FROM forgs_ns_tombstone t
     WHERE t.parent_key = COALESCE(NEW.parent_id, '')
       AND t.name_canonical = CASE WHEN NEW.parent_id IS NULL
                                   THEN lower(NEW.name_canonical)
                                   ELSE NEW.name_canonical END)
BEGIN
    SELECT RAISE(ABORT, 'forgs: name is tombstoned');
END;

-- A root node may not take a name a user holds, except the user's own
-- personal node.
CREATE TRIGGER forgs_ns_node_root_user_insert
BEFORE INSERT ON forgs_ns_node
WHEN NEW.parent_id IS NULL AND EXISTS (
    SELECT 1 FROM forgs_user u
     WHERE u.username = lower(NEW.name_canonical)
       AND u.id IS NOT NEW.personal_of_user_id)
BEGIN
    SELECT RAISE(ABORT, 'forgs: name is taken');
END;

CREATE TRIGGER forgs_ns_node_root_user_update
BEFORE UPDATE OF name_canonical, parent_id ON forgs_ns_node
WHEN NEW.parent_id IS NULL AND EXISTS (
    SELECT 1 FROM forgs_user u
     WHERE u.username = lower(NEW.name_canonical)
       AND u.id IS NOT NEW.personal_of_user_id)
BEGIN
    SELECT RAISE(ABORT, 'forgs: name is taken');
END;

CREATE TRIGGER forgs_user_tombstone_insert
BEFORE INSERT ON forgs_user
WHEN EXISTS (
    SELECT 1 FROM forgs_ns_tombstone t
     WHERE t.parent_key = '' AND t.name_canonical = NEW.username)
BEGIN
    SELECT RAISE(ABORT, 'forgs: name is tombstoned');
END;

CREATE TRIGGER forgs_user_tombstone_update
BEFORE UPDATE OF username ON forgs_user
WHEN NEW.username IS NOT OLD.username AND EXISTS (
    SELECT 1 FROM forgs_ns_tombstone t
     WHERE t.parent_key = '' AND t.name_canonical = NEW.username)
BEGIN
    SELECT RAISE(ABORT, 'forgs: name is tombstoned');
END;

-- A username may not take a root node's name, except its own personal node's.
CREATE TRIGGER forgs_user_root_insert
BEFORE INSERT ON forgs_user
WHEN EXISTS (
    SELECT 1 FROM forgs_ns_node n
     WHERE n.parent_id IS NULL
       AND lower(n.name_canonical) = NEW.username
       AND n.personal_of_user_id IS NOT NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'forgs: name is taken');
END;

CREATE TRIGGER forgs_user_root_update
BEFORE UPDATE OF username ON forgs_user
WHEN NEW.username IS NOT OLD.username AND EXISTS (
    SELECT 1 FROM forgs_ns_node n
     WHERE n.parent_id IS NULL
       AND lower(n.name_canonical) = NEW.username
       AND n.personal_of_user_id IS NOT NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'forgs: name is taken');
END;

-- ---------------------------------------------------------------------------
-- Membership (§2)
-- ---------------------------------------------------------------------------

-- A subject's direct role on a node. Roles inherit down the tree
-- (`forgs::authz::effective_role`); there are deliberately no deny entries.
--
-- `subject` is a rendered `forgs::SubjectKey`. For a user subject (`user:<id>`)
-- `user_id` is set as well, and must agree with it, which is what gives user
-- memberships a foreign key and cascade. Team subjects, later, are additive.
-- `role` is a label of the app's role ladder; an unknown label read back fails
-- closed.
CREATE TABLE forgs_membership (
    ns_node_id TEXT    NOT NULL REFERENCES forgs_ns_node (id) ON DELETE CASCADE,
    subject    TEXT    NOT NULL,
    user_id    TEXT    REFERENCES forgs_user (id) ON DELETE CASCADE,
    role       TEXT    NOT NULL CHECK (role <> ''),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (ns_node_id, subject),
    CHECK ((substr(subject, 1, 5) = 'user:') = (user_id IS NOT NULL)),
    CHECK (user_id IS NULL OR subject = 'user:' || user_id)
) STRICT;

CREATE INDEX forgs_membership_by_user ON forgs_membership (user_id);

-- ---------------------------------------------------------------------------
-- Credentials (§3)
-- ---------------------------------------------------------------------------

-- A user's bearer session. Short-lived: a session token is a pure bearer
-- credential, so a short TTL is what bounds the value of a leak.
--
-- Not bound to any namespace: the request names the namespace it acts in and
-- authz checks membership there (§3). `user_id` carries its foreign key so a
-- session for a nonexistent user fails loudly at insert rather than becoming
-- a valid token belonging to nobody.
CREATE TABLE forgs_session (
    token_hash TEXT    NOT NULL PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES forgs_user (id) ON DELETE CASCADE,
    issued_at  INTEGER NOT NULL,
    expires    INTEGER NOT NULL
) STRICT;

CREATE INDEX forgs_session_by_user ON forgs_session (user_id);
CREATE INDEX forgs_session_by_expires ON forgs_session (expires);

-- A CLI refresh token: mints sessions for one user at the token route and
-- nowhere else (it is refused as a connection credential from its prefix
-- alone). Redemption does **not** rotate, so N concurrent redemptions all
-- succeed; the cost, stated plainly, is that a leaked refresh token is usable
-- for its whole TTL, bounded by that TTL and by `logout --all`.
--
-- `issued_at` and `created_at` coincide today; `created_at` is kept as a
-- creation anchor that stays meaningful if issuance is ever backdated.
CREATE TABLE forgs_refresh_token (
    token_hash TEXT    NOT NULL PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES forgs_user (id) ON DELETE CASCADE,
    issued_at  INTEGER NOT NULL,
    expires    INTEGER NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX forgs_refresh_token_by_user ON forgs_refresh_token (user_id);
CREATE INDEX forgs_refresh_token_by_expires ON forgs_refresh_token (expires);

-- A namespace-scoped, revocable API key (fleet's auth key), redeemed at an
-- app route for whatever `purpose` means to the app.
--
-- * `subject_name`: an operator-chosen identity that survives key rotation.
--   NULL is the **only** spelling of "no name"; `''` is refused, because a
--   query that checks `IS NOT NULL` but not `<> ''` would otherwise build a
--   real, shared, nameless identity. Not unique: two live keys sharing a name
--   is what makes a rotation overlap possible.
-- * `payload`: app-defined JSON (fleet: tags / ops), opaque to forgs.
-- * `created_by`: load-bearing — the creator may revoke their own key and an
--   admin any key, including shell-minted ones where this is NULL.
-- * `consumed_at`: set by the atomic consume of a single-use key.
CREATE TABLE forgs_api_key (
    id           TEXT    NOT NULL PRIMARY KEY,
    key_hash     TEXT    NOT NULL UNIQUE,
    ns_node_id   TEXT    NOT NULL REFERENCES forgs_ns_node (id) ON DELETE CASCADE,
    purpose      TEXT    NOT NULL CHECK (purpose <> ''),
    subject_name TEXT    CHECK (subject_name IS NULL OR subject_name <> ''),
    payload      TEXT,
    single_use   INTEGER NOT NULL CHECK (single_use IN (0, 1)),
    expires      INTEGER,
    created_by   TEXT    REFERENCES forgs_user (id) ON DELETE SET NULL,
    created_at   INTEGER NOT NULL,
    consumed_at  INTEGER
) STRICT;

CREATE INDEX forgs_api_key_by_ns ON forgs_api_key (ns_node_id);
CREATE INDEX forgs_api_key_by_expires ON forgs_api_key (expires);

-- A minted CI workload token.
--
-- Deliberately **no namespace and no foreign key: a workload belongs to no
-- tenant.** A workload token proves "a job in repo owner/name"; several
-- namespaces may each grant that repo access, and it is a member of none of
-- them. Stamping one namespace onto the row would pick an arbitrary winner or
-- invent a membership. So the row records the credential and its claims, and
-- every authorization decision goes through `forgs_grant`. The only query is a
-- lookup by token hash — the hash IS the capability — so there is no
-- cross-tenant read to prevent.
--
-- `claims` (JSON) is recorded for audit and metering and never authorizes.
CREATE TABLE forgs_workload_token (
    token_hash TEXT    NOT NULL PRIMARY KEY,
    subject    TEXT    NOT NULL,
    issuer     TEXT    NOT NULL CHECK (issuer <> ''),
    claims     TEXT,
    issued_at  INTEGER NOT NULL,
    expires    INTEGER NOT NULL
) STRICT;

-- Workload tokens are per job, the highest-churn credential here.
CREATE INDEX forgs_workload_token_by_expires ON forgs_workload_token (expires);

-- "Node N's admin grants subject S ops O over selector X within N's subtree,
-- until E." `selector` and `ops` are app-defined canonical text, opaque here.
--
-- `forgs_grant_by_subject` backs the one deliberately unscoped read
-- (`Store::grants_for_subject`): a grant's purpose is to cross a namespace
-- boundary, so it is scoped by the authenticated subject instead.
-- `created_by` is load-bearing for creator-or-admin revocation.
CREATE TABLE forgs_grant (
    id         TEXT    NOT NULL PRIMARY KEY,
    ns_node_id TEXT    NOT NULL REFERENCES forgs_ns_node (id) ON DELETE CASCADE,
    subject    TEXT    NOT NULL,
    selector   TEXT    NOT NULL,
    ops        TEXT    NOT NULL,
    expires    INTEGER,
    created_by TEXT    REFERENCES forgs_user (id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX forgs_grant_by_subject ON forgs_grant (subject);
CREATE INDEX forgs_grant_by_ns ON forgs_grant (ns_node_id);

-- ---------------------------------------------------------------------------
-- Pre-tenancy state
-- ---------------------------------------------------------------------------

-- A first login whose identity is not linked yet: the user still has to
-- choose a username (§4). One-shot and short-lived. No user exists, so
-- nothing here can carry a user foreign key.
CREATE TABLE forgs_pending_signup (
    id                 TEXT    NOT NULL PRIMARY KEY,
    provider           TEXT    NOT NULL,
    provider_subject   TEXT    NOT NULL,
    email              TEXT,
    email_verified     INTEGER NOT NULL CHECK (email_verified IN (0, 1)),
    suggested_username TEXT,
    created_at         INTEGER NOT NULL,
    expires            INTEGER NOT NULL
) STRICT;

CREATE INDEX forgs_pending_signup_by_expires ON forgs_pending_signup (expires);

-- A pending device approval: forgs' own device flow for CLI login, and the
-- generic "headless machine asks, human approves" machine apps reuse (fleet's
-- node enrollment). Which user (and optionally which namespace) it binds to is
-- precisely what the approval decides, so these columns are NULL until then;
-- this is pre-tenancy state, not a hole in the tenancy model.
--
-- The state machine, in two columns:
--
--   pending   approved_at IS NULL     AND consumed_at IS NULL
--   approved  approved_at IS NOT NULL AND consumed_at IS NULL
--   denied    approved_at IS NULL     AND consumed_at IS NOT NULL
--   redeemed  approved_at IS NOT NULL AND consumed_at IS NOT NULL
--
-- There is deliberately no `denied_at`: denial is "consumed without ever
-- having been approved", which makes "this code can never be used again" the
-- single predicate `consumed_at IS NOT NULL`. Every transition is one
-- conditional UPDATE, so a double approval cannot bind twice and a double
-- redemption cannot mint twice.
--
-- `device_hash` is the hash of the polling side's device secret. `payload` is
-- app JSON and, like `source_ip`, arrives from an unauthenticated request:
-- attacker-controlled, and advisory at best (behind a proxy the address is the
-- proxy's; `X-Forwarded-For` is deliberately not consulted).
CREATE TABLE forgs_pending_device (
    id          TEXT    NOT NULL PRIMARY KEY,
    user_code   TEXT    NOT NULL UNIQUE,
    device_hash TEXT    NOT NULL UNIQUE,
    payload     TEXT,
    source_ip   TEXT,
    created_at  INTEGER NOT NULL,
    expires     INTEGER NOT NULL,
    ns_node_id  TEXT    REFERENCES forgs_ns_node (id) ON DELETE CASCADE,
    approved_by TEXT    REFERENCES forgs_user (id) ON DELETE CASCADE,
    approved_at INTEGER,
    consumed_at INTEGER,
    CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    CHECK (ns_node_id IS NULL OR approved_at IS NOT NULL)
) STRICT;

CREATE INDEX forgs_pending_device_by_expires ON forgs_pending_device (expires);

-- ---------------------------------------------------------------------------
-- Audit
-- ---------------------------------------------------------------------------

-- Append-only log of security-relevant actions. `ns_node_id` has **no**
-- foreign key: the audit trail must outlive the nodes it talks about. NULL is
-- an event outside any namespace (a login, a signup). `subject` is a rendered
-- SubjectKey; `detail` is app JSON.
CREATE TABLE forgs_audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    ns_node_id TEXT,
    subject    TEXT,
    action     TEXT    NOT NULL,
    target     TEXT,
    detail     TEXT
) STRICT;

CREATE INDEX forgs_audit_by_ns_ts ON forgs_audit (ns_node_id, ts);
