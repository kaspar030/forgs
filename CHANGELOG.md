# Changelog

## Unreleased

### Security

- Minting an API key with a `subject_name` (a named workload identity) now
  requires the namespace's highest role. Previously any member could mint a
  key for an existing name and speak as that identity, inheriting its grants.
  A refusal is a `403` with an `api_key.denied` audit event.

### Breaking

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
