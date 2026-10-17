//! The pure core of forgs: reusable identity, namespace, membership and
//! authentication primitives for forge-shaped applications, extracted from
//! probe-rs-fleet (see `docs/design.md`).
//!
//! This crate is **pure**: no database, no HTTP, no async runtime, and no
//! clock — `now` is always a parameter, so every rule here is a table-driven
//! unit test. Storage lives in `forgs-store`, HTTP in `forgs-http`.
//!
//! * [`ids`] — opaque, immutable ULID ids.
//! * [`token`] — prefix-typed opaque bearer tokens, stored only as hashes.
//! * [`store`] / [`verify`] — the lookup seam and bearer verification.
//! * [`user_code`], [`rotation`] — device-flow codes and credential max-age.
//! * [`schema`], [`username`] — the app-defined namespace tree and naming
//!   rules.
//! * [`role`] — app-defined ordered role ladders.
//! * [`subject`] — the authenticated caller and its stable key.
//! * [`authz`] — role inheritance, visibility, grants and the namespace fence.
//! * [`ssh`] — SSH public keys: parsing, fingerprints, key → subject.
//! * [`api`] — JSON wire types shared by server and client.
//!
//! # What this crate deliberately does not do
//!
//! It never mints a [`subject::Subject`] from anything but a verified
//! credential at the server's seam, and never talks to storage itself:
//! [`store::TokenStore`] is implemented elsewhere. Minting identities in a
//! crate with no membership knowledge is exactly how tenancy holes appear.

#![allow(clippy::module_name_repetitions)]

pub mod api;
pub mod authz;
pub mod ids;
pub mod role;
pub mod rotation;
pub mod schema;
pub mod ssh;
pub mod store;
pub mod subject;
pub mod token;
pub mod user_code;
pub mod username;
pub mod verify;

pub use authz::{Access, AuthzError, GrantScope, Visibility};
pub use ids::{ApiKeyId, GrantId, IdError, IdentityId, NsNodeId, PendingId, SshKeyId, UserId};
pub use role::{Role, RoleLadder};
pub use rotation::{should_rotate, RotationPolicy};
pub use schema::{KindSpec, NameRules, Schema};
pub use ssh::{
    authenticate_ssh_key, SshAuthError, SshAuthenticated, SshFingerprint, SshKeyError, SshKeyType,
    SshPublicKey,
};
pub use store::{SshKeyStore, TokenStore};
pub use subject::{Subject, SubjectKey, SubjectKind};
pub use token::{AppKind, OpaqueToken, TokenError, TokenFormat, TokenHash, TokenKind, TokenUse};
pub use username::{NameError, UsernamePolicy};
pub use verify::{authenticate, AuthError, Authenticated};
