//! The forgs HTTP client: CLI device login, session refresh, logout, API keys
//! and workload-token exchange against a forgs server's `/auth/*` JSON
//! surface (docs/design.md §4–§5).
//!
//! Wire types come from [`forgs::api`], so the contract cannot drift from
//! `forgs-http`.
//!
//! # Why hyper rather than reqwest
//!
//! This crate runs on the fleet agent, which cross-compiles to a static
//! armv7-musl binary: pure Rust, TLS through the rustls **`ring`** provider
//! (never `aws-lc-rs`), `default-features = false` everywhere. `reqwest` pulls
//! ~37 crates nothing else needs, including `url` → `idna` → the `icu_*`
//! unicode stack; `hyper` + `hyper-rustls` reuses what an app already links.
//! No server framework and no storage (no database) may enter the graph —
//! `tests/no_http_server_dep.rs` enforces it. [`credfile`] is plain std file
//! I/O, not storage in that sense.
//!
//! # One trust path
//!
//! Every connection is built from [`tls::client_trust_config`]: `WebPKI` roots
//! compiled into the binary, or a pinned server-leaf SHA-256 for a self-hosted
//! server with no public certificate. **Keep that single path.** If a second
//! one appears, a pin silently stops covering some route while appearing to
//! work. [`gha`] follows the same rule, so a pinned client cannot fetch a
//! GitHub Actions token: use a separate unpinned client for that.
//!
//! # Secrets
//!
//! No `Debug` output of anything here prints a credential: the wire types
//! redact by hand (in `forgs::api`), client-side holders use [`Secret`], and a
//! [`ClientError`] never carries a request or response body — only the
//! server's machine-readable error code.
//!
//! [`Secret`] wipes its buffer on drop, and so do the copies this crate makes
//! itself (the `Authorization` header text, the token fields of request
//! structs once sent). That is best-effort memory hygiene, not a guarantee:
//! the serialized body, hyper's buffers and `http::HeaderValue` keep copies
//! out of reach. The public API takes `&str` because the value has to be
//! copied into the plain-`String` wire types anyway; callers should still
//! hold tokens in a [`Secret`] rather than a bare `String`.
//!
//! # Modules
//!
//! * [`client`] — [`ForgsClient`], one method per route.
//! * [`device`] — the CLI device-login driver (start → show code → poll).
//! * [`refresh`] — "renew my session" policy on top of the two grants.
//! * [`gha`] — fetch a GitHub Actions OIDC token for workload exchange.
//! * [`cli`] — std-only helpers for a CLI: browser launch, TTL parsing,
//!   remediation text.
//! * [`tls`] — the trust configuration and certificate pinning.
//! * [`credfile`] (Unix only) — keep a refresh token in a private file:
//!   `0700` directory, `0600` file, atomic replace.

#![allow(clippy::module_name_repetitions)]

pub mod cli;
pub mod client;
#[cfg(unix)]
pub mod credfile;
pub mod device;
pub mod error;
pub mod gha;
pub mod refresh;
pub mod secret;
pub mod tls;
mod transport;

pub use client::{normalise_base, ApiKeySpec, ForgsClient};
pub use device::{DeviceLogin, DeviceLoginError, LoginSession, PollPolicy};
pub use error::ClientError;
pub use secret::Secret;

/// The wire types this client speaks, re-exported for convenience.
pub use forgs::api;
