# forgs — design sketch

Status: sketch. Nothing is implemented. Source material: `docs/fleet-survey.md`
(what probe-rs-fleet has today, with file:line refs).

**One line:** reusable identity, namespace, membership and authentication for
forge-shaped applications — extracted from probe-rs-fleet, generalised so that
probe-rs-fleet, forgefront and future projects can share it.

---

## 0. Decisions so far

- **Extract, don't rewrite.** The fleet code is reviewed and has a documented
  threat model (survey §5.4). forgs starts as a move of that code with the
  fleet-specific parts cut out behind seams, then generalises. Security
  properties carry over verbatim unless this doc says otherwise.
- **An external identity provider (IdP) proves who you are; it does not name you.**
  GitHub, and later others, become OAuth login providers that supply
  `(provider, immutable subject id, verified email)`. The **username is chosen
  by the user in forgs**, and it is unrelated to the GitHub login. (Today, fleet
  uses `gh-<id>` as the id and the GitHub login as the display name and lookup
  key. That goes away; see §4.)
- **Namespaces are an app-defined tree, not a fixed `org/project` shape.**
  (§2) This lets fleet's "orgs only", a forge's `owner/project`, and
  forgefront's `github/some-org/some-project` share one mechanism.
- **Immutable ids and mutable paths.** Every user, namespace node and
  credential has an opaque, immutable id. Paths and usernames are handles,
  resolved to ids *once*, at the point where a reference is stored (a grant, a
  membership). This is fleet's "rename-safe" rule, generalised.
- **SQLite via sqlx, async, pure-Rust deps** (the fleet agent cross-compiles to
  armv7-musl; forgefront is SQLite too). The storage trait boundary keeps
  Postgres possible, but it is not a goal.

## 1. What moves out of probe-rs-fleet

See survey §5.1/§5.2 for the full table. In short:

| Moves to forgs | Stays in fleet |
|---|---|
| opaque token mint/parse/hash (`fleet-auth/token.rs`), verification + `AuthError` (`verify.rs`), `TokenStore` shape (`store.rs`), `user_code.rs`, `rotation.rs` | node tokens, node-device secrets, over-WS rotation protocol |
| GitHub OAuth device + auth-code flow (`github.rs`), OIDC/JWKS verifier (`oidc.rs`), GHA workload-token fetch | `ci` auth-key → board grant synthesis |
| org / user / member / role, `Subject` / `SubjectKey` (`fleet-proto/ids.rs`), username/name validators | `NodeId`, `BoardRef`, `Constraint` selector, `AllowedOp`, capability tokens, `Ed25519Signer` |
| schema + queries for org, user, member, session, refresh_token, auth_key (core columns), workload_token, grant (opaque selector/ops), identity audit | node, board, lease, pending_node payload, audit board/node/lease columns |
| session/refresh/logout, sweep of expired credentials, device-flow broker, browser login + cookies + CSRF (`browser_auth.rs`), the single `Subject` construction seam (`http.rs:319-458`) | `/agent` `/client` `/delegate` websocket usage |
| generic authz: `require_role`, creator-or-admin revoke, deny-by-default, no-oracle errors, grant liveness + the namespace fence | `Access`'s board methods, `require_lease_control` |
| the pending-approval state machine (user code, then approve into an org, then poll with a device secret) | what the approval mints (a node token) |
| client helpers for login/refresh/logout/keys, CLI login-flow pieces | `node_*` client calls |

Warts to fix during the move (survey §5.5): two user-id schemes, `user.login`
used as a non-unique lookup key, the `UserId` newtype being unused, personal
org id == user id, no org switching at login, the unused `Group`, and the CSRF
key derived from fleet's capability-signing seed.

### Seams (traits and extension points)

1. `IdentityProvider`: device flow, auth-code + PKCE,
   `fetch_identity -> ExternalIdentity`. §4.
2. `WorkloadIssuer`: OIDC policy + claims → a workload subject. GHA is the
   first implementation.
3. **Token kinds**: forgs owns Session, Refresh, ApiKey, Workload and
   DeviceSecret. Apps register extra kinds (fleet: Node, NodeDevice), each with
   a prefix and a flag for "connection credential or redeem-only". **The token
   prefix brand is configurable** (fleet keeps `prf…1_`, so deployed tokens
   stay valid).
4. `SubjectKind`: User and Workload are built in; apps can add kinds (fleet: Node).
5. **Redemption hooks**: auth-key purposes and pending-approval completion call
   into the app, which mints its own credential.
6. `AuthContext`: clock (injected, as fleet's tests rely on it), TTL config,
   `public_url`, cookie names, a CSRF secret (injected, with domain separation),
   and an `AuditSink`.
7. **Grant payload**: forgs stores and evaluates liveness, the subject and the
   namespace fence. The selector and ops are app-defined via traits and stored
   as canonical text.

## 2. Namespaces

### Requirements

- **fleet**: flat orgs. Every user gets a personal org (an "org of one"), and
  team orgs sit alongside. There are no projects; boards and nodes are app
  tables that hang off an org.
- **a forge / "projects" user**: `owner/project`, where the owner is a user or
  an org sharing one top-level name space (GitHub/Gitea style). Roles on the
  owner are inherited by its projects, and projects can have extra direct
  collaborators.
- **forgefront**: several upstream forges at once:
  `github/some-org/some-project`, `codeberg/another-org/another-project`. The
  top segment is a forge, not a user. The middle segment is an *upstream*
  name, mirrored from the upstream and not chosen by anyone locally. Local users
  still need their own handles, and those must not collide with `github`.

### Model: a tree of typed nodes

```
ns_node { id (ulid, immutable), parent_id NULL, kind, name, created_at,
          owner_user_id NULL, external_ref NULL }
          UNIQUE(parent_id, name_canonical)
```

- A node's **path** is the `/`-joined names from the root down. Paths are for
  display and lookup. References are always stored by `id`.
- `kind` is an **app-defined string**, checked against a schema the app
  supplies at startup:

  ```rust
  Schema::builder()
      .kind("org",     KindSpec::root().children(&["project"]).personal_for_users())
      .kind("project", KindSpec::child().leaf())
      .reserved(&["api", "admin", "login", "settings"])
      .build()
  ```

  A `KindSpec` says where the kind may appear (at the root or under which
  parents), its name rules (charset, length, case folding), and whether it is
  **user-named** (checked against the username policy and reserved list) or
  **externally named** (mirrored upstream names, which may be looser, e.g.
  GitHub's charset, and are never checked against local reservations).
- **Personal namespaces**: at most one kind may be marked
  `personal_for_users()`. Signup then creates a node of that kind whose name is
  the chosen username, in the same transaction. Username and personal-namespace
  name are the same string (one rename renames both), while the user id and the
  node id stay separate (this fixes fleet's "personal org id == user id").
- **Sibling uniqueness is per parent**. Root-level kinds share the root name
  space. That gives GitHub's "users and orgs cannot share a name" rule for free,
  and forgefront's forge nodes (`github`, `codeberg`) automatically block those
  usernames.

The three consumers, expressed in this model:

| App | Schema | Example paths |
|---|---|---|
| fleet | `org` (root, personal) | `alice`, `ariel-os` |
| forge | `org` (root, personal), `project` (under org) | `alice/dotfiles`, `ariel-os/ariel-os` |
| forgefront | `forge` (root, app-created, not user-nameable); `remote_owner` (under forge, externally named); `repo` (under remote_owner, externally named); optionally `user` (root, personal) | `github/some-org/some-project`, `codeberg/another-org/another-project`, `kaspar` |

For forgefront, the GitHub names under `github/` are **mirrored data**, not
identity. That doesn't contradict "GitHub doesn't name you": your forgs user
`kaspar` may hold a GitHub *credential* whose login is `kaspar-gh`. That's a
separate concept from the IdP link (§4) and belongs to forgefront.

### Membership and roles

```
membership { ns_node_id, subject (user | team), role }
```

- **Roles are an app-defined ordered ladder**, stored as labels. The default
  ladder is `read < triage < write < maintain < admin`, and fleet configures
  `member < admin`. Apps compare them with `satisfies(min)`, the same
  semantics as today's `Role`.
- **Inheritance down the tree**: the effective role on a node is the max over
  its ancestors' memberships. Membership in `ariel-os` grants access to
  `ariel-os/*`, and a direct collaborator entry on `ariel-os/foo` can raise it
  for one project but never lower it. (Deny entries are deliberately absent;
  they make "who can see this" unanswerable.)
- **Teams** (optional, later): a team is a named set of users owned by a
  root-level node, and it can be a membership subject. This is what fleet's
  unused `Group` wanted to be.
- **Visibility** per node: `public | internal | private`, inherited unless
  overridden more restrictively. fleet sets everything private; forgefront
  largely ignores it.
- **Grants** (fleet's cross-org mechanism) are kept, and they generalise to:
  "node N's admin grants subject S ops O over selector X within N's subtree,
  expiring". The namespace fence ("the resource lies within the granting
  node's subtree") replaces today's `board.org == grant.org` conjunct.

### Renames and handles

- Renaming a node or username changes its path. Every stored reference is an id,
  so grants and memberships survive.
- **Name reuse cool-down** (configurable, default 90 days): a released name
  stays in a `ns_tombstone` table before anyone else may claim it. Otherwise,
  renaming lets someone squat the old path and receive traffic (the same class
  of issue as GitHub login reuse). Optional redirects from tombstones.

## 3. Principals and credentials

These are unchanged in substance from fleet (survey §2); they are renamed and
generalised:

- `Subject { kind, id, acting_in: Option<NsNodeId> }`. The session is no longer
  bound to one org at mint time (fleet always bound it to the personal org, so
  org switching was impossible). The request names its target namespace, and
  authz checks membership there. `SubjectKey` renders as `<kind>:<id>`, and
  workload keys keep their namespace prefix (`gha/workload:<owner>/<repo>`).
- Tokens: prefix-typed opaque secrets, stored only as SHA-256 hashes, and
  redeem-only kinds are rejected by prefix before any DB access. Sessions last
  12h. CLI refresh tokens last 30d and don't rotate. Workload tokens last 1h,
  capped at 12h. `logout --all` is kept.
- API keys (fleet's auth keys) are org/namespace-scoped. Minting requires
  membership, keys minted over the API must expire, they are revocable by the
  creator or an admin, and named identities survive rotation. The purpose is
  app-defined, with a redemption hook.
- Browser: an HttpOnly session cookie that is the same credential as the bearer
  token, a double-submit HMAC CSRF token, a cookie accepted only under a
  configurable API prefix, and `redirect_uri` derived only from `public_url`.

## 4. External identity (the GitHub change)

### Today (fleet)

`upsert_github_user` sets `user.id = personal_org.id = "gh-<github numeric id>"`.
It caches the GitHub `login` as `user.login` and sanitises it into the org slug.
`resolve_grantee` looks users up by that login. Email is the public profile
email, often null, and never verified or used. The survey (§3) has the full
details.

### Proposed

```
user      { id (ulid), username UNIQUE (canonical), display_name, created_at,
            state: active | disabled }
identity  { user_id, provider, provider_subject, email, email_verified,
            linked_at, last_login_at }  UNIQUE(provider, provider_subject)
user_email{ user_id, email UNIQUE (canonical), verified_at, primary }
```

- **The key is `(provider, immutable provider_subject)`**, which for GitHub is
  the numeric id. It is never the email, and never the login. This preserves
  fleet's takeover defence: emails and logins both get reassigned.
- The GitHub IdP requests the `read:user user:email` scopes and reads
  `GET /user/emails`, then takes the `primary && verified` address. With no
  verified email, login is refused and the error says so. The GitHub login is
  offered only as a **suggestion** for the username field, never as an
  identifier.
- The GitHub access token is still spent once and never stored (unchanged).
  Apps that need a long-lived GitHub credential, as forgefront does, manage it
  themselves, separately from login.

### First login: choosing a username

Today, both flows mint a session immediately. The new flow looks like this:

```
IdP callback / device poll  →  identity known?
   yes → mint session (as today)
   no  → create `pending_signup { id, identity fields, suggested_username,
                                  expires (15 min) }`
         browser: redirect to /signup?ticket=…  (ticket in HttpOnly cookie)
         CLI:     DevicePoll::NeedsUsername { ticket, suggestion }
                  → CLI prompts → POST /auth/signup { ticket, username }
   signup  → validate username (policy + reserved + ns-root collision + tombstones)
           → one transaction: user, identity, user_email, personal ns node,
             admin membership → mint session (+ refresh for CLI)
```

- **Account linking**: a second provider, or a second GitHub account, is linked
  only from an *authenticated* session ("add login method"). If a new identity
  arrives whose verified email matches an existing user, forgs does **not**
  auto-link. It tells the user to log in with their existing method and link
  from there. Auto-linking on email turns "attacker controls a provider that
  asserts your email" into account takeover.
- `coordinator user-token` (fleet's second id scheme) becomes "create a local
  user with username X" through the same code path, without an identity row.

### Migrating fleet

Existing `gh-<n>` users keep their user id. Ulid is the scheme for new rows,
and the id is opaque either way, so nothing needs rewriting. The migration:

- backfills `identity(github, n)`;
- sets `username` to the old sanitised slug;
- marks users `username_confirmed = false` so that the next login offers a rename;
- **moves the personal org to a new id** (or keeps `gh-<n>` as the node id: opaque
  is opaque). Keeping it is cheaper, since node ids like `gh-1/rpi-1` are baked
  into board refs. Recommendation: keep the ids and change only the displayed
  names.

## 5. Crate layout (proposal)

```
forgs            core: ids, namespace schema + tree ops, roles, Subject, tokens,
                 user_code, username policy, authz evaluation. Pure, no IO.
forgs-store      sqlx/SQLite: migrations, Store trait + impl, scoped handles.
forgs-idp        IdentityProvider trait; `github` feature (device + auth-code +
                 /user/emails); `oidc` feature (JWKS, GHA workload issuer).
forgs-http       axum: routes (/auth/*, signup, keys, members), Authenticated
                 extractor with per-route allowed kinds, cookies + CSRF.
forgs-client     HTTP client for login/refresh/logout/keys + CLI flow helpers
                 (hyper + rustls/ring, no server deps: the fleet Pi build).
```

These carry over fleet's pure-Rust / `ring` / `default-features = false`
discipline. `forgs-client` must not pull axum or sqlx.

**Migrations in a shared DB**: apps need foreign keys into `user` and
`ns_node`, so forgs tables live in the app's SQLite file. They are prefixed
`forgs_` to avoid collisions. forgs ships `forgs_store::migrate(&pool)` with
its own migration list, and apps run it before their own. Open detail: sqlx 0.8
has one `_sqlx_migrations` table, so either the two migrators use disjoint
version ranges with `ignore_missing`, or forgs keeps its own
`forgs_schema_version` table.

## 6. Open questions

1. **Table naming vs fleet compatibility**: rename fleet's `org`, `user`,
   `member` and related tables to `forgs_*` in a fleet migration, or let forgs
   use unprefixed names? Recommendation: prefix, with a one-off fleet migration.
2. **Other IdPs soon?** (Codeberg/Forgejo OAuth, generic OIDC login.) This
   affects whether `IdentityProvider` is generic OIDC-first or GitHub-first.
3. **Should password or email-magic-link login exist at all**, or only
   external IdPs? The sketch assumes IdP-only, plus admin-created local users.
4. **Teams in v1 or later?**
5. **Rename policy**: allowed at all? Cool-down length? Redirects?
6. **One repo or several crates published separately?** The layout above is a
   workspace in this repo, and fleet consumes it via git/path deps at first.
7. **Where does the fleet cut happen**: fleet switches to depending on forgs
   crate by crate (tokens → verify → store → http), each step green. Or one
   big switch?
