# forgs

Reusable identity, namespace, membership and authentication for forge-shaped
applications, shared by [probe-rs-fleet], forgefront and future projects.

forgs provides external login (GitHub, generic OIDC with Codeberg/Forgejo and
GitLab presets) with a locally chosen username, an app-defined namespace tree
with inherited roles, opaque bearer credentials (sessions, CLI refresh tokens,
API keys, workload tokens), its own CLI device flow, and the axum routes and
client that tie these together.

- Design: [`docs/design.md`](docs/design.md)
- Background: [`docs/fleet-survey.md`](docs/fleet-survey.md), a snapshot of
  probe-rs-fleet's auth code that forgs was extracted from.

## Crates

| Crate | Contents |
|---|---|
| `forgs` | ids, opaque tokens + verification, user codes, rotation policy, namespace schema, username policy, role ladders, `Subject`, authz evaluation, `/auth/*` wire types. **Pure: no IO, no clock.** |
| `forgs-store` | sqlx/SQLite: `forgs_`-prefixed tables, forgs' own migrator (`forgs_schema_version`, never `_sqlx_migrations`), `Store`, and namespace-scoped `NsScope` handles. |
| `forgs-idp` | `IdentityProvider` trait; GitHub (OAuth2), generic OIDC with Codeberg/Forgejo and GitLab presets, GitHub Actions workload issuer + runner-side token fetch. Features `client` (HTTPS egress) and `oidc` (JWT verification). |
| `forgs-http` | axum `/auth/*` routes (login/callback, signup, token, session/logout, device start/poll and approval page, keys, identity linking, members, rename, providers), the `Authenticated` extractor, `AuthContext`, cookies + CSRF, server-rendered pages, and app hooks (`AppTokenLookup`, `ApiKeyPurposes`, `PendingApprovalHook`). |
| `forgs-client` | hyper + rustls/`ring` client for device login, refresh, logout, API keys and workload exchange; GitHub Actions token fetch; CLI helpers; TLS pinning. No server dependencies (enforced by `tests/no_http_server_dep.rs`). |

## Dependency discipline

fleet's agent cross-compiles to armv7-musl and consumes `forgs-client`, so:

- pure Rust only — nothing that needs a C toolchain. The one exception is
  `sqlx`'s bundled SQLite, allowed only in the server-side crates
  (`forgs-store`, `forgs-http`);
- crypto via `ring` (rustls' `ring` provider), never `aws-lc-rs`;
- `default-features = false` wherever defaults pull in more than is used;
- `forgs` has no async runtime (tokio is a dev-dependency) and one RNG stack
  (`rand_core` 0.6; `ulid` is used without its `std`/`rand` feature).

Workspace lints: `unsafe_code = "forbid"`, `clippy::pedantic` warn.

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[probe-rs-fleet]: https://github.com/ariel-os/probe-rs-fleet
