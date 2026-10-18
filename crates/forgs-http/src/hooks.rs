//! App extension points: app token kinds, API-key purposes, generic
//! pending approvals and signup approvals.

use async_trait::async_trait;
use forgs::store::AppRecord;
use forgs::{AppKind, NsNodeId, Role, SubjectKey, TokenHash, UserId};
use forgs_store::{ConsumedApiKey, PendingDevice};

use crate::context::AuthContext;
use crate::error::ApiError;

/// Lookup for the app's own connection token kinds (fleet: a node).
///
/// [`crate::authenticate_request`] authenticates every credential through
/// one path; for a [`forgs::TokenKind::App`] kind it asks this hook (set
/// with [`crate::AuthContextBuilder::app_tokens`]). Without one, every app
/// token is unknown — the uniform `401`.
///
/// It is consulted only for app kinds registered as
/// [`forgs::TokenUse::Connection`]: a redeem-only kind is refused from its
/// prefix (`403`) before any lookup. Expiry is compared by forgs against the
/// injected clock, so return expired rows as they are (they become a `401`
/// with an `auth.reject.expired` audit event rather than an indistinguishable
/// unknown). The route still fences kinds with [`crate::AllowedKinds`].
#[async_trait]
pub trait AppTokenLookup: Send + Sync {
    /// The row for `hash` of app kind `kind`, or `None` if unknown/revoked.
    ///
    /// # Errors
    ///
    /// A storage error description; it fails closed (uniform `401`, logged).
    async fn lookup_app(
        &self,
        kind: AppKind,
        hash: &TokenHash,
    ) -> Result<Option<AppRecord>, String>;
}

/// What an API-key purpose redeems to at `POST /auth/token`
/// (`grant_type: api_key`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurposeKind {
    /// Redeemable for a workload token (a runner with no workload identity).
    /// Such keys may carry a `subject_name`: a stable identity that survives
    /// rotation (`<ns>/workload:agent:<name>`). Naming an identity requires
    /// the namespace's **highest role**: the subject is derived from the
    /// namespace and name alone, so a key for an existing name speaks as that
    /// identity and inherits its grants. An unnamed key speaks as
    /// `<ns>/workload:key:<ApiKeyId>`.
    Workload,
    /// Redeemed by the app at its own route (fleet: node enrollment). Refused
    /// at `/auth/token` with `403`. No `subject_name`.
    App,
}

/// Who is minting what: the context handed to
/// [`ApiKeyPurposes::check_payload`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct KeyMint<'a> {
    /// The minting user.
    pub caller: UserId,
    /// The namespace the key is minted in.
    pub ns: NsNodeId,
    /// The caller's effective role in `ns` (inheritance included). Interpret
    /// it against `ctx.store().roles()`.
    pub role: Role,
    /// The (known) purpose.
    pub purpose: &'a str,
    /// The normalised `subject_name`, if any (workload purposes only; the
    /// caller holds the highest role).
    pub subject_name: Option<&'a str>,
    /// The payload as sent.
    pub payload: Option<&'a serde_json::Value>,
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

    /// Validate, authorise and canonicalise the app payload a key is minted
    /// with (fleet: a node key's tags, a CI key's ops). Called at mint time,
    /// after the purpose is known, the caller's membership was checked and
    /// (for a `subject_name`) the highest role was required.
    ///
    /// **The app must cap the payload's authority by [`KeyMint::role`]**:
    /// forgs cannot interpret app ops or tags, so a payload delegating
    /// authority the caller does not hold is the app's to refuse (typically
    /// [`ApiError::Forbidden`]). Otherwise a low-role member could mint a key
    /// that exceeds their own access.
    ///
    /// The returned string is stored **verbatim** in `forgs_api_key.payload`,
    /// echoed (parsed) in the mint response and listing, and handed back in
    /// [`ConsumedApiKey::payload`] at redemption. It must be JSON; `None`
    /// stores no payload.
    ///
    /// The default knows no payloads: `None` or JSON `null` is fine, anything
    /// else is refused with `400` (never silently dropped).
    ///
    /// # Errors
    ///
    /// Any [`ApiError`] (typically [`ApiError::BadRequest`] for a bad shape,
    /// [`ApiError::Forbidden`] for authority the caller lacks); it becomes
    /// the response and nothing is minted.
    async fn check_payload(
        &self,
        _ctx: &AuthContext,
        mint: &KeyMint<'_>,
    ) -> Result<Option<String>, ApiError> {
        match mint.payload {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(_) => Err(ApiError::BadRequest),
        }
    }

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

/// Who may approve signups, and what to do when one waits
/// ([`crate::SignupPolicy::Approval`]).
///
/// forgs has no notion of a global administrator: the app decides. The
/// default ([`NoSignupApprovals`]) denies everyone, so a server configured
/// for approval without a hook simply accumulates pending users that only
/// the store API ([`forgs_store::Store::approve_user`]) can approve.
#[async_trait]
pub trait SignupApprovalHook: Send + Sync {
    /// Whether `approver` (an authenticated, active user) may list, approve
    /// and reject pending signups. Default: no one.
    async fn can_approve(&self, _ctx: &AuthContext, _approver: UserId) -> bool {
        false
    }

    /// Called after a pending signup committed (e.g. to notify the
    /// administrators). Failures are the app's to log: the signup stands.
    async fn on_pending(&self, _ctx: &AuthContext, _user: &forgs_store::User) {}
}

/// The default signup-approval hook: nobody may approve.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSignupApprovals;

#[async_trait]
impl SignupApprovalHook for NoSignupApprovals {}

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
