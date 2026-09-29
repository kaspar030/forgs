# forgs

Reusable identity, namespace, membership and authentication for forge-shaped
applications — extracted from [probe-rs-fleet] and generalised so that fleet,
forgefront and future projects can share it.

Status: early. The pure core crate and the identity-provider crate exist so far.

- Design: [`docs/design.md`](docs/design.md)
- What fleet has today, and what moves: [`docs/fleet-survey.md`](docs/fleet-survey.md)

## Crates

| Crate | Contents | Status |
|---|---|---|
| `forgs` | ids, opaque tokens + verification, user codes, rotation policy, namespace schema, username policy, role ladders, `Subject`, authz evaluation, `/auth/*` wire types. **Pure: no IO, no clock.** | ✅ |
| `forgs-store` | sqlx/SQLite: `forgs_`-prefixed tables, migrations, `Store` trait + impl | planned |
| `forgs-idp` | `IdentityProvider` trait; GitHub (OAuth2), generic OIDC with Codeberg/Forgejo and GitLab presets, GitHub Actions workload issuer + runner-side token fetch. Features `client` (HTTPS egress) and `oidc` (JWT verification). | ✅ |
| `forgs-http` | axum routes, `Authenticated` extractor, cookies + CSRF | planned |
| `forgs-client` | HTTP client for login/refresh/logout/keys (no server deps) | planned |

## Dependency discipline

Carried over from probe-rs-fleet, whose agent cross-compiles to armv7-musl:

- pure Rust only — nothing that needs a C toolchain;
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

MIT OR Apache-2.0.

[probe-rs-fleet]: https://github.com/ariel-os/probe-rs-fleet
