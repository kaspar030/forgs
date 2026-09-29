# probe-rs-fleet → "forgs" extraction survey

Read-only survey of `/home/kaspar/src/ai/probe-rs-fleet` (paths below are relative to it).
Goal: identify everything identity/org/user/auth/authz-related that could move to a
reusable forge-style crate ("forgs"), and pin down exactly how GitHub names become identity.

---

## 0. TL;DR

* Identity lives in 3 places: `fleet-auth` (token format/verification/GitHub+OIDC clients,
  already DB-agnostic via a `TokenStore` trait), `fleet-proto::ids` (Subject/SubjectKey/OrgId/
  Role newtypes), and `fleet-coordinator` (SQLite schema + `Db` methods, `authz.rs`,
  `browser_auth.rs`, `http.rs` auth routes, `tokens.rs` TokenStore impl).
* **GitHub numeric id IS the identity key today**: `user.id = org.id = "gh-<github_user_id>"`
  (`state.rs:1701-1794`, `upsert_github_user`). GitHub `login` is cached as `user.login`
  and sanitised into the personal-org `org.slug`; it is *also* used as a lookup key when
  granting (`Db::user_by_login`, `core.rs:1669 resolve_grantee`). GitHub **org membership is
  never fetched** — fleet orgs are entirely local; there is no `/user/orgs` call anywhere.
* Email is fetched (`GithubUser.email`, public email only, often `None`) and stored but
  unused; no `user:email` scope, no `/user/emails` call → no *verified* email today.
* Coupling to fleet concepts: `TokenKind::{Node, NodeDevice}`, `auth_key.purpose/tags`
  (node enrollment), `pending_node`, `Access`/`GrantScope` (boards, selectors,
  `AllowedOp`), workload `gha` namespace, capability tokens (ed25519, lease/board-bound).

---

## 1. Domain model

### 1.1 Rust types

| Type | Location | Notes |
|---|---|---|
| `OrgId(String)` | `crates/fleet-proto/src/ids.rs:22` | every object belongs to one org; personal org = org of one |
| `UserId(String)` | `ids.rs:27` | "stable across GitHub login renames"; barely used — user ids flow as bare `String` |
| `NodeId(String)` | `ids.rs:34` | org-namespaced `"<org>/<name>"` via `state.rs::node_id_for` (`state.rs:2826`) — fleet-specific principal |
| `Group(String)` | `ids.rs:40` | carried on `Subject`, excluded from key; unused ("future grant evaluation") |
| `SubjectKind {User, Node, Workload}` | `ids.rs:135` | which auth path produced the subject |
| `Role {Member, Admin}` | `ids.rs:160-205` | ordered, `satisfies()` = `>=`; labels `member`/`admin` |
| `Subject {org, kind, id, groups}` | `ids.rs:211` | the authenticated caller; no `Default`/`From<String>`, built only at one seam |
| `SubjectKey {org, kind, id}` | `ids.rs:260` | stable identity; renders/parses `<org>/<kind>:<id>` (`parse` at `ids.rs:277`, splits at first `/` and first `:`) |
| `WORKLOAD_NS_GHA = "gha"` | `ids.rs:~380` | reserved namespace in the org slot for GHA OIDC subjects |
| `normalise_repo`, `workload_subject_key` | `ids.rs:390, 422` | `gha/workload:<owner>/<repo>` (lowercased, charset `[A-Za-z0-9._-]`) |
| `normalise_agent_name`, `agent_subject_key` | `ids.rs:467, 496` | `<org>/workload:agent:<name>`; `[a-z0-9._-]`, ≤64, leading alnum |
| `TokenKind {Node, Session, AuthKey, NodeDevice, Workload, Refresh}` | `crates/fleet-auth/src/token.rs` | prefix-typed opaque tokens (see §2.1) |
| `Authenticated {kind, org_id, id, expires, hash, token_issued_at}` | `fleet-auth/src/verify.rs` | verified credential, deliberately *not* a Subject |
| `NodeRecord/SessionRecord/AuthKeyRecord/WorkloadRecord/RefreshRecord` | `fleet-auth/src/store.rs` | what verification needs from storage |
| `TokenStore` trait | `fleet-auth/src/store.rs` | `lookup_{node,session,auth_key,workload,refresh_token}(hash)` → `Result<Option<_>, String>` |
| `GithubApp`, `GithubEndpoints`, `GithubUser {id: u64, login, email: Option}` | `fleet-auth/src/github.rs:~100-245` | |
| `OidcPolicy`, `WorkloadClaims` | `fleet-auth/src/oidc.rs:54, 72` | GHA OIDC |
| `GrantScope {id, org, selector: Constraint, ops: Vec<AllowedOp>, expires}` | `crates/fleet-core/src/access.rs` | evaluator view of a grant (board-specific) |
| `Access {own_org: Option<OrgId>, grants}` | `fleet-core/src/access.rs` | resolved per-request permission set |
| `AuthzError {Denied, NotFound}` | `crates/fleet-coordinator/src/authz.rs` | coarse, no-oracle |
| `GrantRow`, `CiAuthKeyMeta`, `AuthKeyListing`, `PendingNode`, `MemberRow` | `fleet-coordinator/src/state.rs:80,132,245,327,2696` | DB row types |
| `AllowedOp`, `CapabilityToken`, `SignedToken`, `TokenSigner/Verifier` | `crates/fleet-proto/src/token.rs` | lease capability model — fleet-specific |
| `Ed25519Signer`, `serve_token` | `fleet-coordinator/src/auth.rs` | signs capability tokens; seed also keys CSRF |
| wire types (`TokenRequest`, `TokenResponse`, `LogoutRequest`, `Device*`, `AuthKey*`, `NodeRegister*`, `NodeApproval*`, `ErrorResponse`) | `fleet-auth/src/lib.rs` `mod api` | JSON for `/auth/*` |
| `GrantSummary` etc. | `fleet-proto/src/admin.rs` | admin/listing wire types |

### 1.2 SQLite schema (`crates/fleet-coordinator/migrations/`)

Identity (0001):
```sql
CREATE TABLE org   (id TEXT PK, slug TEXT NOT NULL UNIQUE, kind TEXT NOT NULL /*personal|team|system*/, created_at INT);
CREATE TABLE user  (id TEXT PK, personal_org_id TEXT NOT NULL REFERENCES org(id),
                    github_user_id INTEGER, login TEXT, email TEXT, created_at INT);
CREATE TABLE member(org_id REFERENCES org, user_id REFERENCES user, role TEXT /*admin|member*/, PK(org_id,user_id));
CREATE TABLE session(token_hash TEXT PK, org_id REFERENCES org, user_id REFERENCES user, issued_at, expires);
```
* 0003: `CREATE UNIQUE INDEX user_by_github_id ON user(github_user_id) WHERE github_user_id IS NOT NULL`.
* 0007: reserved row `INSERT INTO org VALUES ('gha','system:gha','system',…)`.
* 0011: `refresh_token(token_hash PK, org_id FK, user_id FK, issued_at, expires, created_at)`.

Credentials / authz:
* `grant(id PK, org_id FK, subject TEXT /*rendered SubjectKey*/, selector TEXT, ops TEXT /*newline*/, expires INT NULL)`
  + 0006 `created_at`, `created_by`, `idx_grant_subject`, `idx_grant_org`.
* `auth_key(key_hash PK, org_id FK, tags, single_use, expires, created_by, created_at, consumed_at)`
  + 0007 `purpose TEXT DEFAULT 'node'` (`node|ci`, CLI also mentions `agent`), `ops`; + 0009 `subject_name TEXT NULL`.
* `workload_token(token_hash PK, subject, kind 'github_oidc'|'auth_key', repository, repository_owner, git_ref, workflow, job_workflow_ref, run_id, issued_at, expires)` — **no org_id** by design (0007).
* `pending_node(user_code PK, device_hash UNIQUE, node_name, tags, adopt_policy, source_ip, created_at, expires, org_id NULL, approved_by NULL REFERENCES user, approved_at, consumed_at)` (0005) — 4-state machine in two nullable timestamps.
* `node(…, org_id, owner_user_id REFERENCES user, token_hash, token_issued_at, …)` — node-as-principal.
* `audit_log(id, ts, org_id FK, subject, action, node_id, board, lease, detail)`.

Tenancy enforcement: `Db` vs `OrgDb<'a>` (`state.rs:235, 1907`); `Db::scoped(org)` returns a
handle that binds `org_id` into every query. Deliberate non-org-scoped queries:
`Db::grants_for_subject` (`state.rs:1882`), `pending_node` methods, `workload_token`.

### 1.3 Principals summary

| Principal | Credential | Org binding |
|---|---|---|
| User | session `prfs1_` (+ refresh `prfr1_`, CLI only) | session row's org_id (personal org at login) |
| Node | node token `prfn1_`, rotating | node row's org_id |
| Workload (GHA OIDC) | `prfw1_` | reserved `gha` namespace, no membership |
| Workload (ci/agent auth key) | `prfw1_` | key's org; `workload:key:<hash8>` or `workload:agent:<name>` |
| Pending node | device secret `prfnd1_` + user code | none until approved |
| Enrollment key | auth key `prffk1_` | org_id of key |

---

## 2. Authentication mechanisms

### 2.1 Opaque bearer tokens — `fleet-auth/src/token.rs` (generic, strong candidate)
* Format `<prefix><base64url-nopad(32 random bytes)>`; prefixes `prfn1_ prfs1_ prffk1_ prfnd1_ prfw1_ prfr1_`.
* Prefix is load-bearing: selects table *before* DB access; wrong kind → 403 not 401.
* Stored only as lowercase-hex SHA-256 (`TokenHash`, `short()` = 8 hex for logs; `Debug` redacts).
* `OpaqueToken::{mint, parse, kind, hash, to_secret_string}`; `Debug` never prints secret.
* Deps: `base64`, `sha2`, `rand_core`, `thiserror`. No fleet coupling except the kind enum
  (Node/NodeDevice are fleet concepts; prefix `prf` is fleet branding).
* No signing on these: ed25519 is only for **capability tokens** (`fleet-proto/src/token.rs`,
  `fleet-coordinator/src/auth.rs::Ed25519Signer`) — lease/board-bound, fleet-specific.

### 2.2 Verification — `fleet-auth/src/verify.rs`
* `authenticate(store, bearer, now) -> Authenticated` — Node/Session/Workload accepted;
  AuthKey/NodeDevice/Refresh → `WrongKind` from prefix alone (never connection credentials).
* `verify_auth_key`, `verify_refresh_token` — pre-checks (kind, existence, expiry); auth-key
  consumption is a separate atomic DB op (`Db::consume_auth_key`, `state.rs:1249`).
* `AuthError::{Missing, Malformed, Unknown(kind), Expired(kind), WrongKind, Store}` with stable
  audit labels (`auth.reject.*`); all map to one generic body (no oracle).
* `TokenStore` impl: `fleet-coordinator/src/tokens.rs` (`impl TokenStore for Db`); workload row's
  stored subject is re-parsed with `SubjectKey::parse` and dropped closed if unparseable.
* Single Subject construction seam: `http.rs:403 authenticate_request_with` (maps
  `TokenKind` → `SubjectKind`, checks per-route `allowed: &[TokenKind]`, `Carrier`
  Header vs HeaderOrCookie, audits wrong-kind rejects).

### 2.3 Sessions & refresh
* Session: `http.rs:2274 mint_session_for_user(coord, org, user_id, ttl, audit_detail)` →
  `Db::insert_session`; TTL `session_ttl_secs` (default 12h).
* `grant_type=refresh` (`http.rs:1452 refresh_session`) — **replacing** rotation of a live session.
* Refresh token `prfr1_` (`http.rs:1585 mint_refresh_token`, redeem `http.rs:1523`) —
  **non-rotating** by design (concurrent sidecars), TTL `refresh_token_ttl_secs` default 30d,
  only mints sessions for one user in one org; CLI-only (device flow + `coordinator user-token`).
* Logout: `http.rs:1649 auth_logout` (`POST /auth/logout`, `LogoutRequest{refresh_token, all}`);
  `--all` deletes all sessions+refresh tokens for the user (`delete_sessions_for_user`,
  `delete_refresh_tokens_for_user`, `state.rs:827, 915`). Foreign refresh token silently ignored.
* Sweep: `sweep.rs:45 sweep_once` deletes expired sessions/refresh/workload/pending.

### 2.4 GitHub OAuth (user login) — `fleet-auth/src/github.rs` (feature `client`)
* **Device flow** (RFC 8628): `start_device_flow`, `poll_device_flow` → `DevicePoll::{Pending,
  SlowDown, Denied, Expired, Granted{access_token}}`. Coordinator **brokers** it statelessly:
  `POST /auth/device/start` (`http.rs:2341`), `POST /auth/device/poll` (`http.rs:2370`); CLI never
  talks to GitHub; `device_code` round-trips through the client.
* **Authorization-code flow** (browser): `authorization_url`, `pkce_challenge`, `exchange_code`;
  routes `GET /auth/github/start` / `/auth/github/callback` in `browser_auth.rs`
  (`github_start` ~l.443, `github_callback`, `complete_github_login` ~l.569). Enabled only if
  `github.callback_registered` (`login_method`, l.169); else in-page brokered device fallback
  (`browser_auth::device_start/device_poll`, `prfs_device` cookie).
* Identity: `fetch_user` → `GET {api_base}/user` → `GithubUser{id, login, email}`
  (`github.rs:826`, parse `github.rs:496` rejects string ids). GitHub access token is used
  once and discarded; never stored/logged.
* Pure parse functions for testability; `GithubEndpoints` overridable (GHES / stub).
* Config: `fleet-coordinator/src/config.rs:56 GithubConfig` (client_id, client_secret, scope,
  4 URLs, callback_registered); `validate` requires secret when browser login enabled.
* HTTP: own `hyper` + `hyper-rustls` client (`https_client`, `send`, `post_form`, `get_json`),
  30s timeout, User-Agent required by GitHub.

### 2.5 GitHub Actions OIDC (workload identity) — `fleet-auth/src/oidc.rs` (feature `oidc`)
* `verify(jwt, jwks, policy, now) -> WorkloadClaims` — pure; RS256 only, `kid` mandatory, rejects
  `use=enc` keys, `iss`/`aud` required (audience has no default; = coordinator `public_url`),
  own clock + leeway, required `exp/iss/aud/sub/repository/repository_owner`.
* `JwksCache` (refresh_after, min_refetch, `refresh_for_unknown_kid`).
* `fetch_workload_id_token` (runner side) in `github.rs:863`.
* Exchange: `http.rs:804 exchange_github_oidc` → subject `gha/workload:<repo>`, row in
  `workload_token`, TTL `workload_token_ttl_secs` (1h, cap 12h). Authorization is **only** via a
  per-repo grant; `repository_owner` recorded, never authorizing.
* Deps: `jsonwebtoken` (rust_crypto) — heavy, hence feature-gated.
* Mostly generic (a JWT workload-identity verifier), but `WorkloadClaims` is GHA-shaped and calls
  `fleet_proto::ids::normalise_repo`.

### 2.6 Auth keys — pre-minted org-scoped bearer secrets
* Mint: API `POST /auth/keys` (`http.rs:1781 auth_keys`, `1895 create_auth_key`,
  `2053 list_auth_keys`, `2092 revoke_auth_key`), browser `/api/v1/auth-keys`, shell
  `fleet-bin/src/roles/admin.rs::auth_key` (can mint non-expiring). CLI `fleet-bin/src/roles/auth_key.rs`.
* Rules: membership suffices to mint/list; org taken from session (no org on wire); API keys must
  expire, cap 30d (`MAX_API_AUTH_KEY_TTL_SECS`); revoke by creator or org admin; prefix ≥8 hex,
  ambiguous → 409.
* Purposes: `node` → `redeem_auth_key` (`http.rs:694`) mints node token (fleet-specific).
  `ci` → `exchange_workload_key` (`http.rs:982`) synthesises/upserts a grant (id `ci-<hash29>` or
  `named_ci_grant_id(org,name)` `http.rs:1247`) and a workload token; `subject_name` = stable
  identity across rotation (`agent login`, `fleet-bin/src/roles/agent_login.rs`).
* Generic idea: "service account / API key with a stable name and rotatable secret".

### 2.7 User codes & pending-device approval
* `fleet-auth/src/user_code.rs`: 8-char Crockford base32 (~40 bits), `generate`, `normalise`
  (case/separator/confusable folding), `display` (`ABCD-1234`). Fully generic.
* Used by interactive node approval: `/node/register/{start,poll,approve}` (`http.rs:2565, 2670,
  2765`, `decide_pending_node` `2849`), `pending_node` table. The *pattern* (unauthenticated
  device asks; logged-in member approves into their org; device polls with a secret) is generic;
  the payload (node_name, tags, adopt policy, node token) is fleet-specific.

### 2.8 Browser cookies / CSRF — `fleet-coordinator/src/browser_auth.rs`
* Cookies: `prfs_session` (HttpOnly, Secure, SameSite=Lax, Path=/, Max-Age = session expiry),
  `prfs_csrf` (non-HttpOnly), `prfs_oauth` (`state.verifier`, 600s), `prfs_device`.
* CSRF: `csrf_key = HMAC-SHA256(signing_seed, "probe-rs-fleet/csrf/v1")`;
  `csrf_token = HMAC(k, session_token_hash)`; `csrf_ok` constant-time compare of `X-Fleet-Csrf`
  header, only for cookie-arrived credentials. No CSRF table.
* Cookie accepted only under `/api/v1/*` (`Carrier::HeaderOrCookie`, `api.rs:181 api_auth`,
  `206 mutating_auth`). `redirect_uri` from `public_url` only (never Host/X-Forwarded-Host).
* Coupling: needs `Coordinator` (config, clock, db, signing seed) — easily abstracted.

### 2.9 Node token rotation — `fleet-auth/src/rotation.rs`
`RotationPolicy{max_age_secs=7d, ack_timeout_secs=60}`, `should_rotate(issued_at, now, policy)`.
Generic as "credential max-age" helper; the over-WS rotation protocol is fleet-specific.

### 2.10 Interim admin verb
`coordinator user-token` (`fleet-bin/src/roles/admin.rs:434` → `http.rs:2245 mint_session`):
creates user with `user.id = <login string>` via `ensure_user_member` — a second identity scheme
(no GitHub). Known wart: two subjects for one human.

### 2.11 Client helpers — `fleet-auth/src/http_client.rs`
`exchange`, `refresh_session`, `redeem_refresh_token`, `logout`, `device_start/poll`,
`create/list/revoke_auth_key`, `node_register_*`, `node_approval`, `self_register`, … with optional
cert pin (`pin: Option<[u8;32]>`). Mix of generic (login/refresh/logout/keys) and fleet (node_*).

---

## 3. How GitHub names are used (critical)

### 3.1 User id and personal org id derive from the GitHub numeric id
`crates/fleet-coordinator/src/state.rs:1701 Db::upsert_github_user(gh_id, login, email, now)`:
```rust
let user_id = format!("gh-{gh_id}");
let org = OrgId(user_id.clone());
...
// existing user (found by github_user_id): only refresh display columns
sqlx::query("UPDATE user SET login = ?2, email = ?3 WHERE id = ?1")
...
let slug = unique_personal_slug(&mut tx, login, gh_id, &user_id).await?;
INSERT INTO org (id, slug, kind, created_at) VALUES (?1 /*gh-<id>*/, ?2 /*slug*/, 'personal', ?3) ON CONFLICT(id) DO NOTHING
INSERT INTO user (id, personal_org_id, github_user_id, login, email, created_at) VALUES (gh-<id>, gh-<id>, gh_id, login, email, now)
   ON CONFLICT(id) DO UPDATE SET github_user_id=…, login=…, email=…
INSERT INTO member (org_id, user_id, role) VALUES (gh-<id>, gh-<id>, 'admin') ON CONFLICT DO NOTHING
```
So: **user id = personal org id = `gh-<github numeric id>`**, user is admin of it. Called from
`http.rs:~2418` (device poll) and `browser_auth.rs::complete_github_login` (both then
`mint_session_for_user(org=gh-<id>, user=gh-<id>)`). Lookup: `Db::user_by_github_id`
(`state.rs:1667`, `SELECT id, personal_org_id FROM user WHERE github_user_id = ?1`).

Consequently `gh-<n>` leaks everywhere: node ids `gh-1/rpi-1` (`node_id_for`), board refs
`gh-1/gh-1/rpi-1/dk-3` (`BoardRef::answers_to`, `ids.rs:113`), subject keys `gh-2/user:gh-2`,
tests and docs. The login-time session is always scoped to the **personal** org — there is no
org switching / team-org selection path (team orgs only exist via `ensure_org(.., "team")` in
tests/shell/`default_org`).

### 3.2 GitHub login → org slug (display) — `state.rs:2770 unique_personal_slug`
```rust
sanitised = login.chars().map(|c| if alnum||'-'||'_' { lower } else { '-' }).trim_matches('-')
candidates = [sanitised, format!("{sanitised}-{gh_id}"), org_id /*gh-<id>*/]  // first not taken
```
`org.slug` is `UNIQUE`, display-only ("nothing resolves an org by it", 0007). Race on slug →
INSERT fails → 503 (accepted, 0003). Reserved `system:gha` slug can't collide (`:` impossible).

### 3.3 GitHub login as cached display + lookup key
* `user.login` refreshed on every login; `Db::user_login` (`state.rs:1831`) for display
  (`/api/v1/session`, `api.rs:682`; members list `list_members` joins `user.login`, `api.rs:791`).
* `TokenResponse.login` returned to CLI (`http.rs` device poll: `login: Some(user.login)`).
* **Grantee resolution uses the login**: `Db::user_by_login` (`state.rs:1852`,
  `SELECT id, personal_org_id FROM user WHERE login = ?1`) from `core.rs:1669 resolve_grantee`:
  ```rust
  if let Some(repo) = spec.strip_prefix("repo:") { … workload_subject_key }
  if let Some(key) = SubjectKey::parse(spec) { return key }          // e.g. gh-2/user:gh-2
  if let Some((user, org)) = self.db.user_by_login(spec).await? { SubjectKey{org, User, user} }
  if spec.starts_with("gh-") { SubjectKey{org: spec, User, id: spec} }  // user id == personal org id
  ```
  Resolved once to the immutable id at grant creation (rename-safe). Error text:
  "no such user `{grantee}`; ask them to run `probe-rs-fleet login` first". Note `login` has no
  unique index → ambiguous if two rows ever share a cached login (after a rename+reclaim before
  the old user re-logs in).
* The grant subject key for a user is `<personal org>/user:<user id>` = `gh-N/user:gh-N`; so a
  user granted access is always addressed **in their personal org**.

### 3.4 GitHub org membership / teams
**Not used at all.** No `read:org` scope, no `/user/orgs`, `/orgs/*/members`, or team calls. Fleet
orgs/membership are local tables. The only GitHub "owner" notion is `repository_owner` in the OIDC
path, explicitly never authorizing; repo grants are `gha/workload:owner/repo`.

### 3.5 Email
`GithubUser.email` = public profile email from `GET /user` (often null); stored in `user.email`,
never read for any decision, no verification, no `/user/emails`. Default `scope` is empty.

### 3.6 Implications for "GitHub = OAuth provider giving a verified email; user picks username"
* Replace `user.id = gh-<id>` with an opaque generated id (e.g. ULID) and add
  `identity(provider, provider_subject, email, email_verified, …)` link table; keep the
  `(provider, subject)` uniqueness (0003's invariant) — keying on the immutable provider id, not
  email, is still the takeover defence (emails can change/be reassigned too).
* Request `user:email` scope and call `GET /user/emails` to get `verified && primary`.
* Add `user.username` (unique, user-chosen, validated like `normalise_agent_name`) — becomes
  display handle and grantee lookup key (replacing `user_by_login`); personal-org slug = username.
  First-login flow needs an extra "choose username" step (both device flow and browser flow
  currently mint the session immediately → needs a pending-signup state or default-then-rename).
* Personal org id must stop equaling user id (`resolve_grantee`'s `gh-` branch, docs, fixtures).
* Rename safety: if usernames are renameable, keep the "resolve to immutable id at grant time" rule
  and consider a username-reuse cool-down.
* `coordinator user-token` (login-string ids) should become "create local user with username".

---

## 4. Authorization

### 4.1 Model (architecture §6.5)
* Deny by default; every request → `Subject` → org check first.
* Two org roles `member < admin`. Member: add node, use org boards, mint auth keys, list grants,
  approve pending nodes, `share`. Admin: act on others' leases, read audit log, create grants,
  revoke any grant/auth key.
* Ownership: lease holder, or admin of holder's org, or admin of board's org
  (`authz.rs::require_lease_control`). Creator-or-admin for revoking grants and auth keys.
* Grants: `{subject(SubjectKey), selector(Constraint), ops[AllowedOp], expires}` issued by an org
  over *its* boards to any subject (users in other orgs, nodes, workloads). API grants must expire
  (≤365d, `core.rs:1508 MAX_GRANT_TTL_SECS`).
* Membership only for `SubjectKind::User`; nodes/workloads reach resources only via grants.

### 4.2 Check functions
* `fleet-coordinator/src/authz.rs`: `same_org`, `require_role(db, subject, org, min)` (user-only,
  fail-closed on DB error), `is_org_admin`, `board_access(db, subject, now) -> Access`
  (membership leg + `grants_for_subject` leg; unparseable rows dropped closed),
  `require_lease_control`. Errors collapse to "not found"/"no such lease" to avoid enumeration.
* `fleet-core/src/access.rs` (pure): `GrantScope::{is_live_at, covers}` (org fence: `board.id.org
  == grant.org` && selector), `Access::{none, own_org, owns, may_use, matching_grant,
  effective_ops, allows}`, `selector_matches`.
* Call sites: `core.rs` (grant CRUD `1529/1791`, lease ops), `http.rs` (auth keys, approvals via
  `require_membership_for_auth_keys` `1845`, `require_membership_to_approve` `2810`), `api.rs`.
* Capability tokens attenuate: lease → `CapabilityToken{lease, board, allowed_ops, expires}`
  ed25519-signed, verified offline by node.

### 4.3 Generic vs fleet-specific
Generic: org/member/role model; `require_role`; creator-or-admin revocation; "grant to subject,
scoped by issuing org, expiring, audited"; subject-key rendering; fail-closed/no-oracle discipline;
`grants_for_subject` cross-org lookup pattern.
Fleet-specific: `Board`/`Constraint` selector language, `AllowedOp`, leases, capability tokens,
`Access` struct as written (board-typed). A generic crate could offer
`Grant<Sel, Op>` + a `Resource`/`Selector` trait (`fn org(&self)`, `fn matches(&Sel)`) and let fleet
plug in Board/Constraint/AllowedOp.

---

## 5. Proposed extraction boundary

### 5.1 Move to forgs (generic)
| Item | From | Notes |
|---|---|---|
| Opaque token mint/parse/hash, `TokenHash`, redacting Debug | `fleet-auth/src/token.rs` | make prefix set configurable: `TokenKind` → registry/trait (`trait TokenKindSpec { prefix, connection_credential: bool }`) or generic core kinds (Session, Refresh, ApiKey, Workload, DeviceSecret) + app-defined extras |
| `authenticate`/`verify_*`, `AuthError` + labels | `fleet-auth/src/verify.rs` | parameterise over kinds; keep "redeem-only kinds rejected by prefix" |
| `TokenStore`-style trait + records | `fleet-auth/src/store.rs` | drop `NodeRecord` from the core trait (app extension) |
| `should_rotate`/`RotationPolicy` | `rotation.rs` | tiny, generic |
| `user_code` | `user_code.rs` | as is |
| GitHub OAuth (device + auth-code + PKCE + fetch_user) | `github.rs` | generalise to `trait IdentityProvider` returning `{provider, subject, email, email_verified, suggested_username}`; add `/user/emails`; UA string configurable |
| OIDC JWT verifier + `JwksCache` | `oidc.rs` | generic workload-identity verifier; GHA claim mapping as a provider module; remove `fleet_proto::normalise_repo` dependency (move normaliser too) |
| Workload-id token fetch (runner) | `github.rs:863` | GHA client helper |
| Org/User/Member/Role, Subject/SubjectKey/SubjectKind/Group, reserved-namespace rule | `fleet-proto/src/ids.rs` | SubjectKind needs extensibility (Node is app-specific: `Other(&'static str)` or generic param) |
| `normalise_agent_name` (→ username/service-account name validator), `normalise_repo`, `workload_subject_key`, `agent_subject_key` | `ids.rs` | |
| Schema + queries: org, user, member, session, refresh_token, auth_key (minus tags/purpose-node), workload_token, grant (opaque selector/ops TEXT), audit_log core cols | migrations 0001/0003/0006/0007/0009/0011; `state.rs` `ensure_org`, `ensure_user_member`, `role_of`, `upsert_github_user`→`upsert_external_identity`, `unique_personal_slug`, session/refresh/workload/auth-key CRUD, `grants_for_subject`, `list_members`, `org_slug*`, `user_login`, `user_by_login` | need a way to share one sqlx pool/migration sequence with the app (forgs migrations namespace or `forgs::migrate(&pool)` run before app migrations; FK from app tables to `org`/`user`) |
| `OrgDb` tenancy-handle pattern | `state.rs:1907` | provide `ScopedDb` for forgs tables; apps extend |
| Session/refresh minting, refresh rotation, logout(+all), sweep of expired creds | `http.rs:1452,1523,1585,1649,2274`; `sweep.rs` | framework-agnostic service fns + optional axum router |
| Device-flow broker handlers | `http.rs:2341,2370` | |
| Browser login: cookies, CSRF HMAC, OAuth state cookie, callback, device fallback | `browser_auth.rs` | abstract `Coordinator` into `trait AuthContext { now, config, db, csrf_key }`; key derivation from app-supplied secret |
| Single Subject construction seam, `Carrier`/`Arrival`, `bearer_of`, `reject` no-oracle body | `http.rs:319-458` | axum extractor `Authenticated<Subject>` with `allowed kinds` |
| `authz` generic part: `same_org`, `require_role`, `is_org_admin`, creator-or-admin revoke helper, `AuthzError` | `authz.rs` | |
| Generic grant storage + evaluation skeleton (`GrantScope<S,O>`, live/expiry, org fence) | `fleet-core/src/access.rs` | selector/op/resource via traits |
| Auth-key API (create/list/revoke, TTL caps, prefix rules, named identity) | `http.rs:1781-2200`, `lib.rs api::AuthKey*` | purpose becomes app-defined; redemption hook trait |
| Pending-device approval state machine (generic parts) | `state.rs:1283-1580`, 0005 | payload as JSON/app columns; approve binds org+user |
| Wire types for login/refresh/logout/device/keys/errors | `fleet-auth/src/lib.rs api` | split fleet variants (AuthKey→node, SelfRegister, NodeRegister*) out |
| Client helpers (login/refresh/logout/keys) + CLI login flow pieces | `http_client.rs`, `fleet-bin/src/roles/login.rs`, `auth_key.rs`, `agent_login.rs` | |
| Audit entry for identity events (`user.create`, `session.mint`, `auth_key.*`, `grant.*`, `auth.reject.*`) | various | provide an `AuditSink` trait |

### 5.2 Stays in fleet
Nodes (`node` table, node tokens, rotation over WS, `node_id_for`, self-register/share,
`redeem_auth_key` node purpose, adopt policy), boards/`BoardRef`/`BoardName`, `Constraint`
selector language, `AllowedOp`, leases, scheduler, `Access` board methods, capability tokens &
`Ed25519Signer`/`serve_token`, `require_lease_control`, `audit_log` board/node/lease columns,
pending-node payload (node_name/tags/adopt), `/agent` `/client` `/delegate` WS auth usage,
`ci` auth-key grant synthesis (selector/ops for boards), web UI assets.

### 5.3 Seams / traits needed
1. **`IdentityProvider`** (GitHub first): `start_device`, `poll_device`, `authorize_url`,
   `exchange_code`, `fetch_identity -> ExternalIdentity{provider, subject_id, email, email_verified,
   display_login}`.
2. **`WorkloadIssuer`** (GHA OIDC): policy + claims → `(namespace, subject_id, claim columns)`.
3. **Token kinds**: core kinds + app-registered kinds (with prefix & "connection credential?" flag);
   app `TokenStore` extension for its own kinds (fleet: Node, NodeDevice).
4. **`SubjectKind`** extensible (User, Workload core; app kinds like Node).
5. **Storage**: forgs owns its tables/migrations in a shared SQLite pool; exposes `ForgsDb` and
   org-scoped handle; app tables FK into `org`/`user`.
6. **Grant evaluation**: `trait Resource { fn org(&self)->&OrgId }`, `trait Selector<R> { fn
   matches(&self, &R) -> bool; parse/display }`, `trait Op: Ord + label`. Stored as text.
7. **Auth-key redemption hook** per purpose (`node` → fleet, `ci/agent` → workload + grant).
8. **Pending-approval hook**: on redeem, app mints its credential (node token).
9. **Context** for HTTP handlers: clock (`now` injected — heavily relied on for tests), config
   (TTLs, public_url, cookie names/prefix), secret for CSRF derivation, audit sink.
10. **Username policy**: validator + reservation list (e.g. `gha`, `system:*`), choose-username
    step in signup.

### 5.4 Design decisions / security properties to carry over (from docs + code comments)
* Key identity on the **immutable provider id**, never a mutable handle (GitHub login
  rename/reuse = account takeover; `state.rs:1701` doc, arch §6.4). Store provider id with
  partial unique index. Resolve handles to immutable ids **once** at grant creation.
* Everyone is always in an org; personal org of one, user admin of it; no user-owned/org-owned
  branch (arch §6.1).
* Tenancy by type (`OrgDb`), FK enforcement on, provisioning order org→user→member→session in one
  transaction; the few deliberately unscoped queries documented as such (grants by subject,
  pre-tenancy pending rows, tenant-less workload tokens).
* Only SHA-256 hashes of secrets stored; secrets shown once; Debug redaction; 8-hex hash prefix for
  logs; revocation = row delete.
* Prefix-typed tokens; redeem-only kinds rejected before DB access; per-route allowed kinds;
  wrong kind → 403.
* No oracle: one generic error body; detail only in audit log; cross-org == not found.
* Fail closed on DB errors and unparseable rows (grants, workload subjects, roles).
* Provider access token spent once, never stored/logged; fleet issues its own refresh token
  (revocable, provider-independent) rather than storing GitHub's.
* Refresh tokens non-rotating (concurrency), bounded by TTL + `logout --all`; CLI-only, never
  issued to browsers.
* Short session TTL (12h); workload tokens per job (1h, cap 12h, no refresh).
* Browser: HttpOnly+Secure(unconditional)+SameSite=Lax cookie carrying the *same* session token;
  cookie accepted only on `/api/v1/*`; double-submit CSRF HMAC(derived key, token hash) + mandatory
  custom header + no CORS; header wins over cookie; no bearer-in-JS; strict CSP.
* OAuth callback: `redirect_uri` from configured `public_url` only; `state` bound to HttpOnly
  cookie; PKCE sent but GitHub ignores it → client_secret required for auth-code flow (don't call it
  PKCE-protected).
* Device flow brokered and stateless; accepted risks: quota exhaustion, RFC 8628 §5.4 phishing;
  no rate limiting yet.
* OIDC: pinned alg (RS256), mandatory `kid`, explicit audience (no default), injected clock,
  required claims not defaulted; trust per exact repo, never owner; lowercase normalisation in one
  function shared by grant and claim paths.
* Auth keys: org from session (never wire), membership to mint, API keys must expire (≤30d),
  creator-or-admin revoke, prefix ≥8 hex, ambiguous prefix 409; named identity survives rotation;
  NULL (not '') = "no name".
* Reserved namespaces enforced at *every* creation path (`ensure_org` + config validate) and
  structurally unreachable slugs.
* Attacker-controlled strings (names, tags, codes) charset-validated server-side and rendered as
  text; approval inspects first, shows approver-relative org, refuses takeover without `replace`.
* Grants: admin-gated creation, must expire via API (≤365d), org fence conjunct in every check,
  canonicalised selector stored, audit which grant allowed a request.
* Test fixtures build ids via production constructors (arch §6.1 note).

### 5.5 Known warts to fix during extraction
* Two user-id schemes (`gh-<id>` vs `coordinator user-token <login>`).
* `user.login` not unique but used as lookup key.
* `UserId` newtype unused; user ids are bare `String`.
* Personal org id == user id (baked into `resolve_grantee` `gh-` branch and docs).
* No org switching at login; session always in personal org; team orgs have no creation/invite API
  (members list read-only in web UI v1).
* `Group` carried but unused.
* CSRF key derived from the capability-token signing seed (ties forgs to fleet's key; make it an
  injected secret with domain separation).
