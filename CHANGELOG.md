# Changelog

## Unreleased

### Security

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
