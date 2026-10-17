//! forgs identity providers (docs/design.md §4).
//!
//! An identity provider proves **who you are**; it never names you. Every
//! provider maps a login to one [`ExternalIdentity`] keyed by `(provider
//! instance name, immutable subject)` — GitHub's numeric id, an OIDC `sub` —
//! never by email or login, both of which providers reassign. The provider's
//! login is only a *suggestion* for the forgs username, and an identity
//! without a verified email is refused.
//!
//! * [`github`] — GitHub (`OAuth2` only: `GET /user` + `GET /user/emails`),
//!   plus the `owner/repo` → immutable-id resolver workload grants need.
//! * [`oidc`] — generic `OpenID` Connect with Codeberg/Forgejo and GitLab
//!   presets, plus the JWT/JWKS machinery.
//! * [`workload`] — GitHub Actions workload identity (`WorkloadIssuer`).
//! * [`runner`] — the runner-side helper that fetches a GHA id token.
//!
//! There is no device-flow brokering to providers: forgs is its own device
//! authorization server, and every provider is reached through the browser
//! authorization-code flow.
//!
//! # Features
//!
//! * none — pure types and parsers only;
//! * `client` — HTTPS egress (`hyper` + `rustls`/`ring`, `webpki-roots`):
//!   [`github::GithubProvider`] and [`runner`];
//! * `oidc` — JWT verification (`jsonwebtoken` with `rust_crypto`); with
//!   `client` also `OidcProvider`, `JwksCache` and `GithubActionsIssuer`.
//!
//! Pure Rust only, `ring` for crypto, never `aws-lc-rs` or OpenSSL.

#![allow(clippy::module_name_repetitions)]

pub mod github;
pub mod identity;
pub mod url;

#[cfg(feature = "client")]
pub mod https;
#[cfg(feature = "client")]
pub mod runner;

#[cfg(feature = "oidc")]
pub mod oidc;
#[cfg(feature = "oidc")]
pub mod workload;

#[cfg(test)]
mod test_support;

pub use identity::{
    pkce_challenge, AuthRequest, ExternalIdentity, IdentityProvider, IdpError, ProviderTokens,
};

#[cfg(feature = "client")]
pub use github::resolve_repo_ids;
#[cfg(feature = "client")]
pub use github::GithubProvider;
pub use github::GithubRepoIds;
#[cfg(all(feature = "client", feature = "oidc"))]
pub use oidc::OidcProvider;
#[cfg(all(feature = "client", feature = "oidc"))]
pub use workload::GithubActionsIssuer;
#[cfg(feature = "oidc")]
pub use workload::{WorkloadIdentity, WorkloadIssuer};
