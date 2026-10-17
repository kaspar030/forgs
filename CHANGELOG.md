# Changelog

## Unreleased

### Security

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

### Breaking

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
