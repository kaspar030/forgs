# forgs — design

This is the design of the forgs crates as implemented. Background:
`docs/fleet-survey.md`, a snapshot of probe-rs-fleet's auth code (with
file:line refs) that forgs was extracted from.

**One line:** reusable identity, namespace, membership and authentication for
forge-shaped applications, shared by probe-rs-fleet, forgefront and future
projects.

---

## 0. Principles

- **Security properties come from a reviewed threat model.** forgs' token,
  verification, browser and authz rules are those of probe-rs-fleet's reviewed
  code and documented threat model (survey §5.4), with the fleet-specific
  parts behind seams. Deviations are stated in this doc.
- **An external identity provider (IdP) proves who you are; it does not name you.**
  GitHub and OIDC providers are login providers that supply
  `(provider, immutable subject id, verified email)`. The **username is chosen
  by the user in forgs**, and it is unrelated to the provider login (§4).
- **Namespaces are an app-defined tree, not a fixed `org/project` shape.**
  (§2) This lets fleet's "orgs only", a forge's `owner/project`, and
  forgefront's `github/some-org/some-project` share one mechanism.
- **Immutable ids and mutable paths.** Every user, namespace node and
  credential has an opaque, immutable id. Paths and usernames are handles,
  resolved to ids *once*, at the point where a reference is stored (a grant, a
  membership), so renames are safe.
- **SQLite via sqlx, async, pure-Rust deps** (the fleet agent cross-compiles to
  armv7-musl; forgefront is SQLite too). The storage boundary keeps Postgres
  possible, but it is not a goal.

## 1. What forgs provides, and what apps keep

fleet is the example consumer. survey §5.1/§5.2 maps each row to the fleet
code it came from.

| forgs | the app (fleet as example) |
|---|---|
| opaque token mint/parse/hash, verification + `AuthError`, the `TokenStore` shape, user codes, rotation policy | node tokens, node-device secrets, over-WS rotation protocol |
| GitHub OAuth2 auth-code flow, OIDC/JWKS verifier, GitHub Actions workload issuer + runner-side token fetch | `ci` auth-key → board grant synthesis |
| users, namespaces, memberships, role ladders, `Subject` / `SubjectKey`, username/name validators | `NodeId`, `BoardRef`, `Constraint` selector, `AllowedOp`, capability tokens, `Ed25519Signer` |
| schema + queries for users, identities, namespaces, memberships, sessions, refresh tokens, API keys (core columns), workload tokens, grants (opaque selector/ops), pending signups/devices, audit | node, board, lease, pending node payload, audit board/node/lease columns |
| session/refresh/logout, sweep of expired credentials, the CLI device flow, browser login + cookies + CSRF, the single `Subject` construction seam | `/agent` `/client` `/delegate` websocket usage |
| generic authz: role checks, creator-or-admin revoke, deny-by-default, no-oracle errors, grant liveness + the namespace fence | board-level access methods, lease control |
| the pending-approval state machine (user code, then approve into a namespace, then poll with a device secret) | what the approval mints (a node token) |
| client for device login/refresh/logout/keys/workload exchange, CLI helpers | node client calls |

Properties that follow from the model:

- a user id and the id of its personal namespace node are distinct;
- usernames are unique and canonical, and are the only user lookup handle;
- the target namespace (`acting_in`) is chosen per request, not at login;
- there are no group subjects;
- the CSRF secret is injected by the app and never derived from another key.

### Seams (traits and extension points)

1. `IdentityProvider` (forgs-idp): auth-code + PKCE,
   `fetch_identity -> ExternalIdentity`. §4.
2. `WorkloadIssuer` (forgs-idp): OIDC policy + claims → a workload subject.
   `GithubActionsIssuer` implements it. Each issuer has a configurable
   `name()` and a `subject_ns()` label, both unique across the configured
   issuers (`AuthContextBuilder::build` refuses duplicates).
3. **Token kinds** (`TokenFormat`): forgs owns Session, Refresh, ApiKey,
   Workload and DeviceSecret. Apps register extra kinds with
   `TokenFormatBuilder::app_kind` (fleet: node, node-device), each with a tag
   and a `TokenUse` (connection credential or redeem-only). **The token prefix
   brand is configurable.** forgs-http resolves app-kind tokens through
   `AppTokenLookup`.
4. `SubjectKind`: User and Workload are built in; apps add kinds with
   `SubjectKind::App` (fleet: node).
5. **Redemption hooks** (forgs-http): `ApiKeyPurposes` decides what an API key
   purpose redeems to, and `PendingApprovalHook` completes a pending approval;
   both call into the app, which mints its own credential.
6. `AuthContext` (forgs-http): injected clock, `Ttls`, `public_url`, cookie
   names (derived from the brand), a CSRF secret (injected, with domain
   separation), and an `AuditSink`. The default `StoreAuditSink` does not
   persist unauthenticated noise (missing / malformed credentials, which cost
   nothing to send); `Store::sweep` prunes audit rows past a retention window
   (default 90 days). forgs does not rate-limit: apps must put a rate limiter
   in front of `/auth/*`.
7. **Grant payload** (`forgs::authz`): forgs stores and evaluates liveness, the
   subject and the namespace fence. The selector and ops are app-defined via
   the `Selector`/`Resource`/`Op` traits and stored as canonical text.

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
forgs_ns_node { id (ulid, immutable), parent_id NULL, kind, name,
                name_canonical, visibility NULL, owner_user_id NULL,
                personal_of_user_id NULL, external_ref NULL, created_at }
                UNIQUE(parent_id, name_canonical); root names unique
```

- A node's **path** is the `/`-joined names from the root down. Paths are for
  display and lookup. References are always stored by `id`.
- `kind` is an **app-defined string**, checked against a schema the app
  supplies at startup:

  ```rust
  Schema::builder()
      .kind("org",     KindSpec::root().children(&["project"]).personal_for_users())
      .kind("project", KindSpec::child().under(&["org"]).leaf())
      .reserved(&["api", "admin", "login", "settings"])
      .build()
  ```

  A `KindSpec` says where the kind may appear (`root()`, or `child()` with
  `under(...)`), which kinds may sit beneath it (`children(...)`, `leaf()`),
  its `NameRules` (charset, length, case folding), and how it is named:
  **user-named** (the default; checked against the username policy and
  reserved list), **externally named** (`externally_named(rules)`: mirrored
  upstream names, which may be looser, e.g. `NameRules::github()`, and are
  never checked against local reservations), or **app-created**
  (`app_created()`: only the app creates them).
- **Personal namespaces**: at most one kind may be marked
  `personal_for_users()`; it must be a root, user-named kind. Signup creates a
  node of that kind whose name is the chosen username, in the same
  transaction. Username and personal-namespace name are the same string (one
  rename renames both), while the user id and the node id stay separate.
- **Sibling uniqueness is per parent**. Root-level kinds share the root name
  space. That gives GitHub's "users and orgs cannot share a name" rule for free,
  and forgefront's forge nodes (`github`, `codeberg`) automatically block those
  usernames.

The three consumers, expressed in this model:

| App | Schema | Example paths |
|---|---|---|
| fleet | `org` (root, personal) | `alice`, `ariel-os` |
| forge | `org` (root, personal), `project` (under org) | `alice/dotfiles`, `ariel-os/ariel-os` |
| forgefront | `forge` (root, `app_created`); `remote_owner` (under forge, `externally_named`); `repo` (under remote_owner, `externally_named`); optionally `user` (root, personal) | `github/some-org/some-project`, `codeberg/another-org/another-project`, `kaspar` |

For forgefront, the GitHub names under `github/` are **mirrored data**, not
identity. That doesn't contradict "GitHub doesn't name you": your forgs user
`kaspar` may hold a GitHub *credential* whose login is `kaspar-gh`. That's a
separate concept from the IdP link (§4) and belongs to forgefront.

### Membership and roles

```
forgs_membership { ns_node_id, subject (SubjectKey), user_id NULL, role }
```

- **Roles are an app-defined ordered ladder** (`RoleLadder`), stored as
  labels. The default ladder is `read < triage < write < maintain < admin`, and
  fleet configures `member < admin`. `Role::satisfies(min)` holds when the role
  ranks at or above `min`: a higher role implies every lower one. An unknown
  label read back fails closed.
- **Inheritance down the tree**: the effective role on a node is the max over
  its ancestors' memberships. Membership in `ariel-os` grants access to
  `ariel-os/*`, and a direct collaborator entry on `ariel-os/foo` can raise it
  for one project but never lower it. (Deny entries are deliberately absent;
  they make "who can see this" unanswerable.)
- **Teams** are not implemented. `membership.subject` is a rendered
  `SubjectKey` rather than a user id, so team subjects can be added without
  changing the existing rows.
- **Visibility** per node: `public | internal | private`, inherited unless
  overridden more restrictively (a less restrictive override is ignored).
  fleet sets everything private; forgefront largely ignores it.
- **Grants** are cross-namespace delegations: "node N's admin grants subject S
  ops O over selector X within N's subtree, expiring". The namespace fence
  requires the resource to lie within the granting node's subtree; a grant
  never reaches outside it.

### Renames and handles

- Renaming a node or username changes its path. Every stored reference is an id,
  so grants and memberships survive.
- **Released names are blocked forever**: a released name goes into
  `forgs_ns_tombstone` and can never be claimed again, by anyone, including its
  previous holder. Otherwise renaming lets someone squat the old path and
  receive traffic (the same class of issue as GitHub login reuse). The
  tombstone keeps the old node id, so a redirect from the old path can be
  added without a schema change.
- **Releasing root names is rate-limited** (security audit 2026-10,
  HTTP-07). Because tombstones are permanent, an unlimited rename loop would
  let one account burn every free root name (`google`, `rust-lang`, …) for
  everyone. `Store::with_release_limit` (default 5 per 30 days) refuses a
  root-name release — renaming oneself, renaming or deleting a root node —
  once the acting user released that many root names inside the window, or
  once the renamed user / root node was renamed that many times (whoever
  acted). The HTTP layer answers `429 rate_limited` and audits
  `user.rename.limited` / `namespace.rename.limited`. Names below the root
  are not limited: only the parent's admins can touch them, so burning them
  harms only that namespace. The app / an operator (`actor = None`) is never
  limited.
- **Every tombstone records its actor and cause** (`released_by`, `cause`:
  `rename` / `delete`). Operators undo abuse with
  `Store::tombstones_released_by` (review), `Store::release_tombstones_by`
  (bulk, optionally since a time) and `Store::release_tombstone` (one name).
- **Cool-down variant**: `Store::with_tombstone_cooldown(Some(secs))` makes
  `Store::sweep` delete tombstones older than `secs`, relaxing "forever" to a
  cool-down. Off by default; it re-opens squatting after the cool-down.

## 3. Principals and credentials

- `Subject { kind, id, acting_in: Option<NsNodeId> }`. A session is not bound
  to a namespace: the request names its target namespace, and authz checks
  membership there. `acting_in` is a claim to be checked, never a grant.
  `SubjectKey` renders as `<kind>:<id>`, and workload keys carry their
  namespace prefix (`gha/workload:id:<owner_id>/<repo_id>`).
- Workload identity (GitHub Actions OIDC) is keyed on the immutable
  `repository_owner_id` and `repository_id` claims, never on the
  `owner/repo` name, for the same reason as user identities (§4): names are
  reassignable, and whoever registers a freed name must not inherit the old
  repo's grants. A rename keeps the subject; a repo recreated under the same
  name is a new subject. The name is recorded for display and audit only.
  The namespace slot is a per-issuer label (`gha` for github.com, a distinct
  one such as `ghes-corp` for a GHES or enterprise issuer), so two issuers
  never share a subject. To grant a repo, resolve the typed `owner/repo` to
  its ids with `forgs_idp::github::resolve_repo_ids` and build the subject
  with `forgs::subject::workload_subject_key(ns, owner_id, repo_id)`.
  **Breaking (2026-10):** the earlier name-keyed subjects
  (`gha/workload:<owner>/<repo>`) no longer match any token. Existing grants
  on them are inert and are not migrated; recreate them against the id-keyed
  subject.
- Tokens: prefix-typed opaque secrets, stored only as SHA-256 hashes, and
  redeem-only kinds are rejected by prefix before any DB access.
- Lifetimes (`forgs_http::Ttls` defaults): sessions 12h; CLI refresh tokens
  30d, non-rotating; workload tokens 1h, capped at 12h; pending signups 15m;
  device approvals 10m; API keys minted over the API at most 30d.
  Session refresh (`grant_type: refresh`) consumes the old session in one
  atomic `DELETE … RETURNING` before minting, so concurrent refreshes of one
  token yield exactly one success; the replacement inherits the chain's
  original authentication time, and a chain is capped at 30d
  (`session_max_life`) from it. Login and refresh-token redemption start a
  new chain.
  `logout --all` revokes every session and refresh token of the user.
- API keys are namespace-scoped. Minting requires membership, keys minted over
  the API must expire, they are revocable by the creator or an admin, and named
  identities survive rotation. Naming a workload identity (`subject_name`)
  requires the namespace's highest role, because a key for an existing name
  speaks as that identity and inherits its grants. An unnamed key speaks as
  `<ns>/workload:key:<ApiKeyId>`. The purpose is app-defined, with a mint hook
  (`check_payload`, which receives the caller's role and must cap the
  payload's authority by it) and a redemption hook.
  A key is only as alive as its creator: redemption (`Store::consume_api_key`,
  so every path, HTTP or app) requires the creator to be an `active` user with
  a membership somewhere on the key namespace's ancestor chain. A disabled or
  removed creator's keys are inert and live again on re-enable or re-add. A
  NULL creator means shell-minted (operator CLI) and is exempt; deleting a
  user deletes their keys, so NULL never means "orphaned" (keys orphaned
  before schema version 3 cannot be told apart; review them with `keys list`).
  Workload tokens minted from a key record its id, and revoking the key,
  disabling its creator, removing the creator's last membership on the chain
  or deleting the creator deletes them immediately rather than at expiry.

- Browser: an HttpOnly session cookie that is the same credential as the bearer
  token, a double-submit HMAC CSRF token, a cookie accepted only on the
  explicitly marked browser routes and under a configurable API prefix, and
  `redirect_uri` derived only from `public_url`. Every cookie is named
  `__Host-{brand}_*` (`Secure`, `Path=/`, no `Domain`), so a sibling
  subdomain or an on-path attacker cannot toss or shadow one; forgs does not
  emit HSTS — deploy with it (ideally preloaded) and without untrusted
  sibling subdomains.

## 4. External identity

```
forgs_user       { id (ulid), username UNIQUE (canonical), display_name,
                   state: active | disabled, created_at }
forgs_identity   { id, user_id, provider, provider_subject, email,
                   email_verified, linked_at, last_login_at }
                   UNIQUE(provider, provider_subject)
forgs_user_email { user_id, email UNIQUE (canonical), verified_at, is_primary }
```

- **The key is `(provider, immutable provider_subject)`**, which for GitHub is
  the numeric id. It is never the email, and never the login: emails and
  logins both get reassigned, so keying on them enables account takeover.
- **Providers: GitHub, Codeberg/Forgejo, GitLab, and generic OIDC.** Only
  external login exists: no passwords, no magic links. Local users without an
  identity row exist only for bootstrapping and tests.
- The provider layer is **OAuth2 + OIDC-first**, with GitHub as the
  adapter. Forgejo/Codeberg and GitLab are OIDC providers (discovery,
  `id_token`, `email_verified` claim). GitHub is OAuth2-only: it requests
  `read:user user:email`, reads `GET /user/emails` and takes the
  `primary && verified` address. Each provider maps to one `ExternalIdentity
  { provider, subject, email, email_verified, suggested_username }`. With no
  verified email, login is refused and the error says so. The provider login
  is offered only as a **suggestion** for the username field, never as an
  identifier.
- A provider instance is **configured**, not hardcoded: `provider` is the
  configured instance name (`github`, `codeberg`, `gitlab-work`), so two
  Forgejo instances are two providers and their subject ids never mix.
- The provider access token is spent once and never stored. Apps that need a
  long-lived GitHub credential, as forgefront does, manage it themselves,
  separately from login.

### First login: choosing a username

```
IdP callback  →  identity known?
   yes → mint session
   no  → create `pending_signup { id, identity fields, suggested_username,
                                  expires (15 min) }`
         redirect to /auth/signup  (ticket in HttpOnly cookie)
   signup  → validate username (policy + reserved + ns-root collision + tombstones)
           → one transaction: user, identity, user_email, personal ns node,
             admin membership → mint session
```

- **Account linking**: a second provider, or a second GitHub account, is linked
  only from an *authenticated browser* session (`POST
  /auth/identities/link/{provider}`, "add login method"; cookie + CSRF, a
  bearer token is refused), and only after **step-up**: the browser first
  logs in again with a provider already linked to the account, and only an
  identity that belongs to the logged-in user lets the flow continue to the
  target provider. A stolen session, refresh or CLI token is therefore not
  enough to plant a permanent login method. A user with no linked identity
  cannot link. If a new identity arrives whose verified email matches
  an existing user, forgs does **not** auto-link. It tells the user to log in
  with their existing method and link from there. Auto-linking on email turns
  "attacker controls a provider that asserts your email" into account takeover.
  Linked identities are listed with `GET /auth/identities` and removed with
  `POST /auth/identities/unlink` (never the last one: `409 last_identity`).
  `POST /auth/logout {all, identities_linked_after}` also unlinks every
  identity linked after that time, always keeping the oldest.

### CLI login is forgs' own device flow

Not every provider has an RFC 8628 device flow (GitHub and GitLab do; Forgejo
does not), so **forgs is itself the device authorization server**, reusing the
pending-approval machine:

```
CLI  POST /auth/device/start → { device_secret, user_code, verification_uri }
user opens verification_uri (/auth/device) in a browser → logs in with ANY
     provider (auth-code flow, incl. first-login username choice) → confirms
     the user code
CLI  POST /auth/device/poll { device_secret } → pending | slow_down | denied |
     expired | session + refresh
```

This makes CLI login provider-agnostic, and the username choice happens in
the browser only. forgs therefore needs a browser-reachable `public_url`.

The start route is unauthenticated, so it is bounded. Live CLI logins and live
app approvals have separate ceilings (`max_pending_devices`,
`max_pending_approvals`), and one source may hold at most
`max_pending_devices_per_source` live flows. The source comes from the app's
`ClientIp` hook: `NoClientIp` by default, which reads only a `PeerIp`
extension the app inserts, or `ForwardedFor` with an explicit number of
trusted proxy hops. IPv6 counts per /64. The source is stored in the row's
`source_ip` column (the migration's "advisory" comment predates this). When
the source is unknown, only the global ceilings apply.

A poll sooner than the interval is answered `slow_down` without a database
read, and the interval grows by 5s, up to 60s (RFC 8628 §3.5). A well-formed
but unknown device secret polls as `expired`. Only a non-device-secret or an
already-redeemed one is `401 invalid_grant`.

On the browser side, the page never pre-fills the code and the start response
has no `verification_uri_complete`. The user types the code, reviews when and
from where the device asked, then approves or denies. An unknown, expired or
already-decided code is one `404`, audited `device.decide.unknown`. Ten misses
within the flow TTL lock the user out (`429 rate_limited`). The approver can
cancel an approval until the device redeems it. Poll pacing and the miss
counter are in-memory and per-process: they are load and nuisance controls,
not security boundaries.

## 5. Crate layout

```
forgs            core: ids, namespace schema, roles, Subject, tokens + verify,
                 user codes, rotation, username policy, authz evaluation,
                 /auth/* wire types (`forgs::api`). Pure: no IO, no clock.
forgs-store      sqlx/SQLite: schema + migrator, Store, NsScope handles,
                 expiry + audit-retention sweep.
forgs-idp        IdentityProvider and WorkloadIssuer traits, ExternalIdentity.
                 `client` feature: HTTPS egress (GitHub provider, GHA runner
                 token fetch). `oidc` feature: JWT/JWKS verification; with
                 `client`, OidcProvider, JwksCache and GithubActionsIssuer.
forgs-http       axum: /auth/* routes (providers, login, {provider}/start +
                 callback, signup, token, logout, session + session/logout,
                 device start/poll + page, keys, identities (list, unlink,
                 link with step-up), members,
                 rename), Authenticated extractor with per-route allowed
                 kinds, AuthContext, cookies + CSRF, app hooks, audit.
forgs-client     HTTP client for device login/refresh/logout/keys/workload
                 exchange + CLI helpers (hyper + rustls/ring, no server deps:
                 the fleet armv7-musl build).
```

All crates follow the pure-Rust / `ring` / `default-features = false`
discipline. `forgs-client` must not pull axum, sqlx or forgs-store.

**Migrations in a shared DB**: apps need foreign keys into `forgs_user` and
`forgs_ns_node`, so forgs tables live in the app's SQLite file, **all prefixed
`forgs_`**. forgs keeps its own `forgs_schema_version` table and applies its
own migrations in `forgs_store::migrate(&pool)`, independently of sqlx's
`_sqlx_migrations`. Apps call it (or build a `Store`, which does) before
running their own migrator.

## 6. Key constraints

1. All tables are prefixed `forgs_` and live in the app's database.
2. Login is external only: GitHub, Codeberg/Forgejo, GitLab, generic OIDC.
3. Identities are keyed by `(provider, provider_subject)`; usernames are
   chosen locally.
4. Renames are allowed; released names are blocked forever (unless a
   cool-down is configured), and root-name releases are rate-limited.
5. Teams are not implemented.
6. One workspace in this repo; apps consume it via a path/git dependency.
