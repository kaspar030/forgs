//! `OpenID` Connect: JWT verification, discovery, a JWKS cache and the
//! generic OIDC login provider with Codeberg/Forgejo and GitLab presets.
//! Feature `oidc`; the fetching halves additionally need `client`.
//!
//! # What is verified, and never by inheriting a library default
//!
//! * the **signature**, against a JWKS key selected by the token's `kid`
//!   (mandatory: "try every key" turns a rotation window into an attacker's
//!   second chance);
//! * the **algorithm**, against an explicit allowlist ([`AlgPolicy`]) that
//!   cannot contain `HS*`: that is the fence against `alg: none` and the
//!   HMAC-with-the-public-key confusion family;
//! * the **issuer** and **audience**, exact-match against configured values;
//! * **expiry** and **not-before**, against an injected `now`.
//!
//! # One clock
//!
//! `jsonwebtoken` reads the wall clock itself for `exp`/`nbf`. This module
//! turns that off and does the only time comparison against the `now`
//! parameter, keeping `exp` required so a token without one is still refused.
//! A second, invisible clock inside the JWT library would disagree with the
//! caller's clock seam and produce tests that pass for the wrong reason.

mod discovery;
mod jwt;
pub mod presets;

#[cfg(feature = "client")]
mod jwks;
#[cfg(feature = "client")]
mod provider;

pub use discovery::{parse_discovery, parse_token_response, ProviderMetadata};
pub use jwt::{
    decode_verified, parse_jwks, verify_id_token, AlgPolicy, IdTokenClaims, IdTokenPolicy,
    OidcError, VerifyParams,
};
pub use presets::OidcConfig;

#[cfg(feature = "client")]
pub use jwks::JwksCache;
#[cfg(feature = "client")]
pub use provider::OidcProvider;

/// Re-exported so callers can name the JWKS type without depending on
/// `jsonwebtoken` directly.
pub use jsonwebtoken::jwk::JwkSet;
pub use jsonwebtoken::Algorithm;
