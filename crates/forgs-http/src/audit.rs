//! The audit seam.
//!
//! Every security-relevant decision in this crate — logins, signups, mints,
//! revocations, refusals with a resolvable subject — is reported as an
//! [`AuditEvent`] to the app's [`AuditSink`]. Rejections of *unauthenticated*
//! requests carry no namespace and no subject; they are reported too (with
//! `ns: None`) so a sink that wants them can have them, but the default
//! [`StoreAuditSink`] writes them to the no-namespace audit rows only.
//!
//! # Unauthenticated noise is not persisted by default
//!
//! A request with *no* credential, or one that does not even parse
//! (`auth.reject.missing`, `auth.reject.malformed`, `oidc.reject.malformed`;
//! see [`AuditEvent::is_unauthenticated_noise`]), costs an attacker nothing
//! to send. Writing a row for each would let an unauthenticated flood grow
//! the database without bound and compete for `SQLite`'s single writer lock
//! with real logins (security audit 2026-10, HTTP-05). [`StoreAuditSink`]
//! therefore only traces these at `debug` unless
//! [`StoreAuditSink::persist_unauthenticated_noise`] opts back in. Every
//! other rejection (unknown / expired tokens, bad grants) is still written:
//! those carry a well-formed credential and are what an operator looks for.
//!
//! The remaining rows are bounded by the store's audit retention
//! ([`forgs_store::Store::with_audit_retention`], applied by
//! [`forgs_store::Store::sweep`]), not by rate: **apps must put a rate
//! limiter in front of `/auth/*`** (and of their own authenticated routes),
//! since forgs does not rate-limit.
//!
//! Detail is for the operator, never for the response body (no oracle).

use async_trait::async_trait;
use forgs::{NsNodeId, SubjectKey};
use forgs_store::{AuditEntry, Store};

/// One audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// When, epoch seconds.
    pub ts: u64,
    /// The namespace it happened in, if any.
    pub ns: Option<NsNodeId>,
    /// Who acted, if known.
    pub subject: Option<SubjectKey>,
    /// A stable action label (`auth.login`, `api_key.mint`, `auth.reject.unknown`).
    pub action: String,
    /// What was acted on (a token hash prefix, a username, a provider).
    pub target: Option<String>,
    /// Free-form detail for the operator. Never a secret.
    pub detail: Option<String>,
}

impl AuditEvent {
    /// A bare event.
    #[must_use]
    pub fn new(ts: u64, action: &str) -> Self {
        Self {
            ts,
            ns: None,
            subject: None,
            action: action.to_owned(),
            target: None,
            detail: None,
        }
    }

    /// In namespace `ns`.
    #[must_use]
    pub fn ns(mut self, ns: NsNodeId) -> Self {
        self.ns = Some(ns);
        self
    }

    /// By `subject`.
    #[must_use]
    pub fn subject(mut self, subject: &SubjectKey) -> Self {
        self.subject = Some(subject.clone());
        self
    }

    /// About `target`.
    #[must_use]
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// With `detail`.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Whether this is a rejection of a request that carried no credential,
    /// or one that did not parse, with no resolvable subject: free for
    /// anyone to produce, so [`StoreAuditSink`] does not persist it by
    /// default (see the module docs).
    #[must_use]
    pub fn is_unauthenticated_noise(&self) -> bool {
        self.subject.is_none()
            && self.ns.is_none()
            && UNAUTHENTICATED_NOISE.contains(&self.action.as_str())
    }
}

/// Actions [`AuditEvent::is_unauthenticated_noise`] recognises.
const UNAUTHENTICATED_NOISE: &[&str] = &[
    "auth.reject.missing",
    "auth.reject.malformed",
    "oidc.reject.malformed",
];

/// Where audit events go.
///
/// Recording must not fail the request it describes: a sink logs its own
/// failures. (The one exception to "best effort" — revocation — is handled
/// by the caller, which reports a storage failure as a 500 on the *revoking*
/// write, not on the audit write.)
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Record `event`.
    async fn record(&self, event: AuditEvent);
}

/// Writes to `forgs_audit` through the store (namespace-scoped when the event
/// has a namespace).
///
/// Unauthenticated noise ([`AuditEvent::is_unauthenticated_noise`]) is only
/// traced at `debug`, not written, unless
/// [`StoreAuditSink::persist_unauthenticated_noise`] is set.
#[derive(Debug, Clone)]
pub struct StoreAuditSink {
    store: Store,
    persist_noise: bool,
}

impl StoreAuditSink {
    /// Over `store`.
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self {
            store,
            persist_noise: false,
        }
    }

    /// Also write unauthenticated noise (missing / malformed credentials) to
    /// `forgs_audit`. Off by default: only enable it behind a rate limiter.
    #[must_use]
    pub fn persist_unauthenticated_noise(mut self, yes: bool) -> Self {
        self.persist_noise = yes;
        self
    }
}

#[async_trait]
impl AuditSink for StoreAuditSink {
    async fn record(&self, e: AuditEvent) {
        if !self.persist_noise && e.is_unauthenticated_noise() {
            tracing::debug!(action = %e.action, detail = ?e.detail, "audit (not persisted)");
            return;
        }
        let entry = AuditEntry {
            ts: e.ts,
            subject: e.subject.as_ref(),
            action: &e.action,
            target: e.target.as_deref(),
            detail: e.detail.as_deref(),
        };
        let res = match e.ns {
            Some(ns) => self.store.scoped(ns).append_audit(&entry).await,
            None => self.store.append_audit(&entry).await,
        };
        if let Err(err) = res {
            tracing::warn!(error = %err, action = %e.action, "failed to write an audit row");
        }
    }
}

/// Logs every event through `tracing` at `info`.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingAuditSink;

#[async_trait]
impl AuditSink for TracingAuditSink {
    async fn record(&self, e: AuditEvent) {
        tracing::info!(
            action = %e.action,
            ns = ?e.ns.map(|n| n.to_string()),
            subject = ?e.subject.map(|s| s.to_string()),
            target = ?e.target,
            detail = ?e.detail,
            "audit"
        );
    }
}
