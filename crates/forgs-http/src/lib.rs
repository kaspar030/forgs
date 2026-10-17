//! forgs' HTTP surface (docs/design.md §3–§4): axum auth routes, first-login
//! signup, forgs as its own device authorization server, browser cookies and
//! CSRF.
//!
//! The app owns the server. It builds an [`AuthContext`] (store, token
//! format, clock, TTLs, `public_url`, cookie brand, a dedicated CSRF secret,
//! identity providers, workload issuers, an [`AuditSink`] and its hooks) and
//! merges [`router`] into its own axum `Router`. Every route is a thin
//! adapter over a framework-agnostic service function ([`session`],
//! [`login`], [`signup`], [`device`], [`keys`], [`workload`], [`members`],
//! [`identities`]),
//! so an app can drive the same logic from elsewhere.
//!
//! # Threat model, in brief
//!
//! * **One `Subject` seam.** [`authenticate_request`] (and the
//!   [`Authenticated`] extractor over it) is the only place a
//!   [`forgs::Subject`] is built from wire input.
//! * **No oracle.** Every credential rejection is one byte-identical `401`;
//!   a valid credential of the wrong kind for a route is `403`. Detail goes
//!   to the audit sink.
//! * **Cookie confinement.** The session cookie is accepted only on routes
//!   explicitly marked for it ([`Carrier`]); the CLI's JSON routes refuse a
//!   cookie-only request. Cookie-authenticated mutations need the CSRF token
//!   ([`cookies`]); no CORS headers are emitted.
//! * **`redirect_uri` from `public_url` only**, never `Host`.
//! * **No auto-linking on email.** An unknown identity always goes through
//!   signup; a second login method is linked only from an authenticated
//!   browser session (cookie + CSRF, never a bearer token), and only after
//!   step-up: a fresh login with a method already linked to the account.
//!   Identities can be listed and unlinked (never the last one).
//! * **Server-rendered pages** carry a strict CSP and escape every value
//!   ([`html`]).

#![allow(clippy::module_name_repetitions)]

pub mod audit;
pub mod auth;
pub mod context;
pub mod cookies;
pub mod device;
pub mod error;
pub mod hooks;
pub mod html;
pub mod identities;
pub mod keys;
pub mod login;
pub mod members;
mod routes;
pub mod session;
pub mod signup;
pub mod workload;

pub use audit::{AuditEvent, AuditSink, StoreAuditSink, TracingAuditSink};
pub use auth::{
    authenticate_request, AllowedKinds, AnyConnection, ApiCookie, Arrival, Authenticated, Caller,
    Carrier, CarrierSpec, CookieOk, HeaderOnly, SessionOnly, SessionOrWorkload,
};
pub use context::{
    AuthContext, AuthContextBuilder, Clock, ConfigError, CookieNames, CsrfKey, FixedClock,
    SystemClock, Ttls,
};
pub use error::{reject, ApiError};
pub use hooks::{
    ApiKeyPurposes, AppTokenLookup, KeyMint, NoPendingApprovals, PendingApprovalHook, PurposeKind,
    StaticPurposes,
};
pub use routes::{router, JsonBody};
