//! App extension points: API-key purposes and generic pending approvals.

use async_trait::async_trait;
use forgs::{NsNodeId, SubjectKey, UserId};
use forgs_store::{ConsumedApiKey, PendingDevice};

use crate::context::AuthContext;
use crate::error::ApiError;

/// What an API-key purpose redeems to at `POST /auth/token`
/// (`grant_type: api_key`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurposeKind {
    /// Redeemable for a workload token (a runner with no workload identity).
    /// Such keys may carry a `subject_name`: a stable identity that survives
    /// rotation (`<ns>/workload:agent:<name>`).
    Workload,
    /// Redeemed by the app at its own route (fleet: node enrollment). Refused
    /// at `/auth/token` with `403`. No `subject_name`.
    App,
}

/// The app's API-key purposes.
///
/// A purpose is an app-defined string; an unrecognised one is a `400` at
/// mint time, never a silent default (a typo'd purpose would mint the wrong
/// credential and fail far from the mistake).
#[async_trait]
pub trait ApiKeyPurposes: Send + Sync {
    /// How `purpose` redeems, or `None` if the app does not know it.
    fn kind(&self, purpose: &str) -> Option<PurposeKind>;

    /// Called after a [`PurposeKind::Workload`] key was consumed and before
    /// the workload token is minted, with the subject the token will speak
    /// as. The app typically upserts a grant here (fleet: the CI grant keyed
    /// by `(ns, name)`). An error refuses the redemption.
    ///
    /// # Errors
    ///
    /// Any [`ApiError`]; it becomes the response.
    async fn on_workload_redeemed(
        &self,
        _ctx: &AuthContext,
        _key: &ConsumedApiKey,
        _subject: &SubjectKey,
    ) -> Result<(), ApiError> {
        Ok(())
    }

    /// Called after keys were revoked from `ns`, with the revoked rows'
    /// hashes and the (single, since ambiguous prefixes are refused)
    /// `subject_name` — fleet's grant cascade. Failures are the app's to log:
    /// the keys are gone either way.
    async fn on_revoked(
        &self,
        _ctx: &AuthContext,
        _ns: NsNodeId,
        _revoked: &[String],
        _subject_name: Option<&str>,
    ) {
    }
}

/// A fixed purpose table.
#[derive(Debug, Clone, Default)]
pub struct StaticPurposes {
    purposes: Vec<(String, PurposeKind)>,
}

impl StaticPurposes {
    /// No purposes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a purpose.
    #[must_use]
    pub fn with(mut self, purpose: &str, kind: PurposeKind) -> Self {
        self.purposes.push((purpose.to_owned(), kind));
        self
    }
}

#[async_trait]
impl ApiKeyPurposes for StaticPurposes {
    fn kind(&self, purpose: &str) -> Option<PurposeKind> {
        self.purposes
            .iter()
            .find(|(p, _)| p == purpose)
            .map(|(_, k)| *k)
    }
}

/// The generic pending-approval machine, app side.
///
/// forgs' device flow and an app's "headless machine asks, a human approves"
/// flow (fleet's node enrollment) share one table. A row **without** a
/// payload is a CLI login and forgs handles it end to end. A row **with** a
/// payload belongs to the app: [`crate::device::start_pending_approval`]
/// creates it, the human decides with [`crate::device::decide`], and the
/// poll route calls [`PendingApprovalHook::redeem`] after the atomic consume
/// to let the app mint whatever the approval grants.
#[async_trait]
pub trait PendingApprovalHook: Send + Sync {
    /// Whether `approver` may approve `row` into `ns` (e.g. requires a role
    /// there). Called before the conditional approve.
    ///
    /// # Errors
    ///
    /// An [`ApiError`] refusing the approval.
    async fn authorize(
        &self,
        _ctx: &AuthContext,
        _row: &PendingDevice,
        _approver: UserId,
        _ns: Option<NsNodeId>,
    ) -> Result<(), ApiError> {
        Err(ApiError::Forbidden)
    }

    /// Mint what an approved app row grants. Returns the JSON body of the
    /// poll response.
    ///
    /// # Errors
    ///
    /// An [`ApiError`]; the row is already consumed.
    async fn redeem(
        &self,
        ctx: &AuthContext,
        approved_by: UserId,
        ns: Option<NsNodeId>,
        payload: &str,
    ) -> Result<serde_json::Value, ApiError>;
}

/// The default: no app approvals exist.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPendingApprovals;

#[async_trait]
impl PendingApprovalHook for NoPendingApprovals {
    async fn redeem(
        &self,
        _ctx: &AuthContext,
        _approved_by: UserId,
        _ns: Option<NsNodeId>,
        _payload: &str,
    ) -> Result<serde_json::Value, ApiError> {
        Err(ApiError::Forbidden)
    }
}
