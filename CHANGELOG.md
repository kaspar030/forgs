# Changelog

## 0.3.0 — unreleased

### Added

- Signup approval. `forgs_http::SignupPolicy::{Open, Approval, Closed}`
  (`AuthContextBuilder::signup_policy`, default `Open`, so nothing changes
  for existing apps).
  - `Approval`: signup creates the user `UserState::Pending` and shows a
    "waiting for approval" page instead of logging in; a JSON
    `POST /auth/signup` answers `202 Accepted` with
    `forgs::api::SignupPendingResponse` (`{"status":"pending", user_id,
    username}`) and sets no session cookie. Logging in again shows the same
    page until approved.
  - `Closed`: an unknown identity is refused at the login callback and a
    signup submit is refused, both `403 signup_closed`.
- `SignupApprovalHook` (`can_approve`, `on_pending`;
  `AuthContextBuilder::signup_approvals`), default `NoSignupApprovals`
  denies everyone. Routes `GET /auth/signups` (JSON `PendingUserList`,
  `limit`/`after`), `POST /auth/signups/approve` and `/auth/signups/reject`
  (`SignupDecisionRequest`, `204`), and the browser page
  `GET`/`POST /auth/signups/review`; framework-agnostic `forgs_http::signups`.
  `forgs-client` gains `list_pending_signups` (+ `_page`), `approve_signup`,
  `reject_signup`.
- Store: `approve_user`, `reject_user` (deletes the pending user and personal
  node with **no tombstone**: the name, identity and email are free again),
  `pending_users_page`, `emails_of_user`.
- Error codes `signup_closed`, `account_pending` (`ApiError::SIGNUP_CLOSED`,
  `ACCOUNT_PENDING`).
- Audit events `user.signup.pending`, `user.signup.approved`,
  `user.signup.rejected`, `signup.denied`, `signup.reject.closed`,
  `auth.login.pending`, `auth.reject.pending`; session refresh,
  refresh-token redemption and device-flow polls now audit
  `auth.reject.disabled` / `auth.reject.pending` for an inactive user.

### Breaking

- `forgs_store::UserState` gains `Pending` (stored label `pending`);
  migration 0010 widens the `forgs_user.state` CHECK. A pending user cannot
  log in, none of their sessions, refresh tokens, API keys (and workload
  tokens minted from them), or SSH keys authenticate, and they are not an
  active member for last-admin checks. Pending users cannot be added as
  members (`404`, like an unknown user).
- `Store::signup` and `Store::signup_pending` take a `state: UserState`.
- `forgs_http::signup::signup` returns `SignupOutcome::{Session, Pending}`.
- `LoginOutcome` gains `Pending`.
- `Store::set_user_state` to any non-active state (now including `Pending`)
  purges workload tokens minted from the user's keys and reports orphaned
  namespaces, as disabling did.
- `signups` is a reserved provider name.

## 0.2.0 — 2026-10-16

### Security

- `PRAGMA foreign_keys` is verified on the connection of every `Store` write
  transaction (`StoreError::ForeignKeysOff`), not just one connection at
  migration, and each migration runs `PRAGMA foreign_key_check` on the
  `forgs_` tables before committing (`StoreError::ForeignKeyViolations`).
  Migration 8 refuses credential hashes that are not 64 lowercase hex
  (`StoreError::MalformedHash`) in sessions, refresh / workload tokens, API
  keys and pending devices. Subject lifecycle limits are documented in
  docs/design.md §2.
- API keys minted over `/auth/keys` are capped by live keys per namespace
  (`AuthContextBuilder::max_api_keys_per_namespace`, default 1000) and per
  user in a namespace (`max_api_keys_per_user`, default 100); past a cap a
  mint is `403 key_limit` (`StoreError::KeyLimit`,
  `NsScope::insert_api_key_capped`). Key and member listings are paginated
  (`limit`, capped at `forgs::api::MAX_PAGE`; `before` / `after` cursors and
  `next` in the response; `NsScope::list_api_keys_page`,
  `list_members_page`), and revocation no longer loads every key.
  **API change:** `ApiKeyInfo.key_hash` is replaced by `hash_prefix` (16 hex);
  `payload` and `created_by` are listed only for admins and the key's
  creator. `ForgsClient::list_api_keys` / `list_members` follow pages; the
  `_page` variants fetch one.
- Refused API-key mints (bad TTL, unknown purpose, bad `subject_name`,
  refused payload, key limit) are audited as `api_key.denied`, and member
  set/remove and namespace rename/delete/create attempts by a non-member (or
  on an unknown namespace) as `<action>.denied`.
- A connection token of a kind the route does not accept is refused from
  its prefix alone, before any store lookup: a live and a forged workload or
  app token now both get `403` on a session-only route (previously a live one
  got `403` and an unknown one `401`, a liveness oracle). **API change:**
  `forgs::authenticate` takes the route's `allowed: &[TokenKind]`.
- `SystemClock` panics if the system clock reads before the Unix epoch
  instead of returning `0` (which made every expiry check pass).
- `AuthContextBuilder::cookie_api_prefix` must end with `/` (`/api` would
  also have matched `/apix…`); `build` returns `ConfigError::Path`
  otherwise. App `ApiCookie` `GET`/`HEAD` handlers must be side-effect free
  (`SameSite=Lax` cookies ride cross-site top-level `GET`s, and CSRF is not
  checked for safe methods).
- A GitHub Actions id token can be exchanged for a workload token only once
  (per issuer and `jti`, remembered until the JWT's `exp` + leeway). A leaked
  id token can no longer be replayed for fresh workload tokens until it
  expires; a replay is a flat `401 invalid_grant` audited as
  `workload.reject.replay`. Keep `Ttls::workload` short (close to the job
  duration).
- GitHub Actions workload exchange can be restricted to specific jobs of a
  granted repo: `forgs_idp::ClaimConstraints` on the issuer policy
  (`GithubActionsIssuer::with_constraints`) allows-lists `ref`,
  `environment`, `job_workflow_ref` and `event_name`, deny-lists events, and
  can require `ref_protected`. Unconstrained, a grant still covers every
  workflow on every branch. **Behaviour change:** `pull_request_target` jobs
  (and tokens without `event_name`) are now refused by default; set
  `constraints` to `ClaimConstraints::default()` to restore the old
  behaviour. `WorkloadClaims` gains `ref_type`, `ref_protected`,
  `environment`, `event_name` and `runner_environment` (recorded in the
  token's claims and the mint audit).
- Browser cookies carry the `__Host-` prefix, so a sibling subdomain or an
  on-path attacker can no longer toss (plant or shadow) a session, CSRF,
  login-state or signup-ticket cookie. Deploy with HSTS.
- `POST /auth/signup` with the ticket in the cookie now requires an `Origin`
  header (or `Sec-Fetch-Site: same-origin`); a missing `Origin` is no longer
  waved through. A JSON request with the ticket in the body is unaffected.
- A completed browser login revokes the session the browser carried before.
- Logout also clears the in-flight login and pending-signup cookies.
- JSON error responses carry `X-Content-Type-Options: nosniff`.
- A `public_url` with an explicit default port (`https://x:443`) is
  normalised, instead of making every origin check fail closed.
- Minting an API key with a `subject_name` (a named workload identity) now
  requires the namespace's highest role. Previously any member could mint a
  key for an existing name and speak as that identity, inheriting its grants.
  A refusal is a `403` with an `api_key.denied` audit event.
- GitHub Actions workload subjects are keyed on the immutable
  `repository_owner_id`/`repository_id` claims instead of the reassignable
  `owner/repo` name, so a repo or owner name re-registered after a rename,
  transfer or deletion no longer inherits the old repo's grants. Both ids are
  now required in the token. Subjects are also namespaced per issuer, so a
  github.com repo and a GHES repo can never share a subject.

### Added

- SSH public keys as a user credential, for git-over-SSH consumers.
  `forgs::ssh` parses and strictly validates OpenSSH keys (`ssh-ed25519`,
  `ecdsa-sha2-nistp256`/`384`, `ssh-rsa` of 3072 to 16384 bits; DSA,
  `nistp521`, certificates and FIDO `sk-*` keys are refused) from an
  `authorized_keys` line or the raw wire blob, and computes the canonical
  `SHA256:` fingerprint. `authenticate_ssh_key` maps a key to its user's
  `user:<id>` subject through the new `SshKeyStore` seam (implemented by
  `Store`); a disabled user's keys are inert. The SSH server must accept only
  `rsa-sha2-*` RSA signatures (`SshKeyType::accepted_signature_algorithms`).
- Migration 0009 adds `forgs_ssh_key`; a fingerprint maps to exactly one user
  (`StoreError::SshKeyTaken`). `Store::add_ssh_key` (capped per user),
  `ssh_keys_for_user`, `ssh_key_of_user`, `delete_ssh_key`,
  `delete_ssh_keys_added_after`, `ssh_key_by_fingerprint`, `touch_ssh_key`
  (throttled to once a minute). The sweep deletes expired keys.
- Routes `GET`/`POST /auth/keys/ssh` and `POST /auth/keys/ssh/delete`
  (session bearer, or cookie + CSRF; users only), `409 ssh_key_taken`,
  `AuthContextBuilder::max_ssh_keys_per_user` (default 100, `403 key_limit`),
  audit events `ssh_key.add` / `.delete` / `.denied`. `forgs-client` gains
  `list_ssh_keys`, `add_ssh_key`, `delete_ssh_key`.

### Breaking

- `SweepCounts` gains `ssh_keys`; `LogoutRequest` gains
  `ssh_keys_added_after` (with `all`, deletes SSH keys added after that time);
  `StoreError` gains `SshKeyTaken`.

- Root namespace names (usernames included) that parse as a node id are
  refused (`NameError::IdShaped`), so a single-segment reference is never both
  an id and a name. Child names are unaffected.
- Child names now compare case-insensitively for sibling uniqueness,
  tombstones and path lookup, as root names already did (migration 0007). The
  migration refuses to run if two siblings differ only by case; rename one
  first. Display case is kept.
- `SubjectKey::parse` returns the canonical key (ids upper-cased, agent names
  lowercased) and refuses non-canonical workload ids instead of accepting
  spellings that would never match a grant.

- Workload JWTs must carry a non-empty `jti` (GitHub Actions and GHES tokens
  do). `WorkloadClaims` gains `jti` and `accept_until`; `SweepCounts` gains
  `workload_jtis`. Migration 0006 adds `forgs_workload_jti`. A client
  retrying an exchange must fetch a fresh id token.
- Cookies are renamed from `{brand}_session`/`_csrf`/`_oauth`/`_signup` to
  `__Host-{brand}_session` etc. Existing browser sessions are logged out
  once, and app JavaScript reading `{brand}_csrf` must read
  `__Host-{brand}_csrf`.
- The workload subject format is now
  `<issuer label>/workload:id:<owner_id>/<repo_id>` (e.g.
  `gha/workload:id:12345/67890`) instead of `gha/workload:<owner>/<repo>`.
  Existing GitHub Actions grants are not migrated and must be recreated;
  resolve a typed `owner/repo` to its ids with the new
  `forgs_idp::github::resolve_repo_ids`.
- `forgs::subject::workload_subject_key(ns, owner_id, repo_id)` replaces
  `workload_subject_key(repo)` and returns `Option<SubjectKey>`. New helpers
  `valid_workload_ns` and `normalise_github_id`.
- `WorkloadIssuer` gains a required `subject_ns()`. `GithubActionsIssuer`
  gains `with_name`; `OidcPolicy` gains `subject_ns` (and `OidcPolicy::custom`);
  `WorkloadClaims` gains `repository_id` and `repository_owner_id`.
- `AuthContextBuilder::build` refuses workload issuers with an invalid or
  duplicate name (`ConfigError::WorkloadIssuerName`) or subject label
  (`ConfigError::WorkloadSubjectNs`).

- `ApiKeyPurposes::check_payload` is now `async` and takes
  `(ctx: &AuthContext, mint: &KeyMint<'_>)`. `KeyMint` carries the caller,
  namespace, the caller's effective role, purpose, normalised `subject_name`
  and payload. Apps **must** cap the payload's authority (ops, tags) by
  `mint.role`; forgs cannot interpret app payloads.
- The subject of a redeemed unnamed workload key is now
  `<ns>/workload:key:<ApiKeyId>` (the key's immutable ULID) instead of
  `<ns>/workload:key:<first 8 hex of the hash>`, which could collide between
  keys. Existing grants on the old subjects are not migrated and must be
  re-issued.
