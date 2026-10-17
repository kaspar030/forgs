//! Wire types for the `/auth/*` JSON surface.
//!
//! Defined once and shared by `forgs-http` and `forgs-client`, so the contract
//! cannot drift between the two ends. JSON because this surface must be
//! curl-able and proxy-friendly.
//!
//! Namespaces and users travel as opaque ids or canonical paths (strings);
//! nothing on this surface is ever a *grant* of the thing it names — the server
//! checks membership for every namespace a request mentions.

use serde::{Deserialize, Serialize};

/// Stable machine-readable codes for [`ErrorResponse::error`].
pub mod error_code {
    /// A credential in the body was rejected (unknown, expired, wrong kind —
    /// deliberately not distinguished).
    pub const INVALID_GRANT: &str = "invalid_grant";
    /// The request was malformed or violated a rule.
    pub const INVALID_REQUEST: &str = "invalid_request";
    /// The bearer credential was rejected.
    pub const UNAUTHORIZED: &str = "unauthorized";
    /// Authenticated, but not allowed (or the target does not exist — no
    /// oracle).
    pub const FORBIDDEN: &str = "forbidden";
    /// The target does not exist or is not visible to the caller.
    pub const NOT_FOUND: &str = "not_found";
    /// A revocation prefix matched more than one key.
    pub const AMBIGUOUS_PREFIX: &str = "ambiguous_prefix";
    /// The chosen username is taken (or tombstoned).
    pub const USERNAME_TAKEN: &str = "username_taken";
    /// The chosen username violates the policy or is reserved.
    pub const USERNAME_INVALID: &str = "username_invalid";
    /// The signup ticket is unknown or expired.
    pub const TICKET_EXPIRED: &str = "ticket_expired";
    /// A new identity asserted an email another user already holds. forgs
    /// never auto-links on email: log in with the existing method and link
    /// this one from there.
    pub const EMAIL_IN_USE: &str = "email_in_use";
    /// The identity is already linked (to this or another user).
    pub const IDENTITY_TAKEN: &str = "identity_taken";
    /// The request conflicts with the current state.
    pub const CONFLICT: &str = "conflict";
    /// The server failed; nothing about the request is implied.
    pub const SERVER_ERROR: &str = "server_error";
    /// No workload issuer is configured for this grant.
    pub const WORKLOAD_UNCONFIGURED: &str = "workload_unconfigured";
    /// The change would leave a namespace without an admin.
    pub const LAST_ADMIN: &str = "last_admin";
    /// The caller already owns the maximum number of such namespaces.
    pub const NAMESPACE_LIMIT: &str = "namespace_limit";
    /// The namespace still has children or app data referencing it.
    pub const NOT_EMPTY: &str = "not_empty";
    /// The login provider is unknown or not configured.
    pub const UNKNOWN_PROVIDER: &str = "unknown_provider";
    /// The identity provider could not complete the login.
    pub const UPSTREAM_ERROR: &str = "upstream_error";
    /// The provider asserted no verified email, so the login is refused.
    pub const NO_VERIFIED_EMAIL: &str = "no_verified_email";
    /// The server is at capacity for this flow; retry later.
    pub const TEMPORARILY_UNAVAILABLE: &str = "temporarily_unavailable";
    /// The identity is the user's only login method and cannot be unlinked.
    pub const LAST_IDENTITY: &str = "last_identity";
    /// Adding a login method needs a fresh login with one already linked to
    /// the account (and the account has none usable).
    pub const REAUTH_REQUIRED: &str = "reauth_required";
}

/// A token-exchange request to `POST /auth/token`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum TokenRequest {
    /// Exchange a still-valid session token for a fresh one.
    ///
    /// **Replacing**: the old session stops working immediately. See
    /// [`TokenRequest::RefreshToken`] for the non-rotating variant, which is
    /// what a caller that may race a peer (a sidecar) wants.
    Refresh {
        /// The current session token.
        session_token: String,
    },
    /// Redeem a long-lived **refresh token** for a fresh session token.
    ///
    /// Deliberately **not** [`TokenRequest::Refresh`], which exchanges a
    /// still-valid session and replaces it. Two differences make this a
    /// separate grant rather than an overload:
    ///
    /// * it works when the session has already lapsed — that is the whole
    ///   point, since `Refresh` requires a live session and so cannot help
    ///   after the 12h cliff; and
    /// * **it is non-rotating**: redemption leaves the refresh token usable,
    ///   so N concurrent redemptions all succeed and every minted session is
    ///   independently valid.
    RefreshToken {
        /// The refresh token, written by `login`.
        refresh_token: String,
    },
    /// Exchange a **GitHub Actions OIDC JWT** for a short-lived workload
    /// token (wire `grant_type: "github_oidc"`).
    ///
    /// The runner holds no secret: `permissions: id-token: write` lets it ask
    /// GitHub for the JWT, and this exchanges it. New contract: `forgs-http`
    /// must implement it (a server without a workload issuer configured
    /// answers `503`; a verification failure is a flat `401 invalid_grant`).
    GithubOidc {
        /// The JWT from the runner's token service.
        oidc_token: String,
    },
    /// Redeem an **API key** for a workload token (wire
    /// `grant_type: "api_key"`) — the fallback for a runner with no workload
    /// identity. New contract: `forgs-http` must implement it (an expired or
    /// consumed key is a `401 invalid_grant`; a key whose purpose does not
    /// redeem to a workload token a `403 forbidden`).
    ApiKey {
        /// The API key, as minted by [`ApiKeyRequest::Create`].
        api_key: String,
    },
}

/// A successful token exchange (and the `Granted` device-poll outcome).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The minted session token.
    pub token: String,
    /// Expiry (epoch seconds).
    pub expires: u64,
    /// The username, for the CLI's summary line. Display only — identity is
    /// the immutable [`TokenResponse::user_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The user's immutable id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// A freshly minted **refresh token**, on the login paths that mint one
    /// (the device flow).
    ///
    /// Absent everywhere else, including from a redemption response: the
    /// caller already holds the refresh token it redeemed, and echoing it back
    /// would put a durable credential on the wire for nothing and invite a
    /// client to overwrite a good credential with a copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// A request to `POST /auth/logout` — revoke the caller's credentials.
///
/// Authenticated with `Authorization: Bearer <session token>`: an ordinary
/// authenticated call about the caller's *own* identity.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutRequest {
    /// The caller's refresh token, so it can be revoked alongside the
    /// session. A refresh token belonging to **another** user is ignored
    /// silently: never an oracle, never a cross-user delete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Revoke *every* session and refresh token of the calling user, not just
    /// the presented ones. This is the lost-machine answer.
    #[serde(default)]
    pub all: bool,
    /// With [`LogoutRequest::all`] only (ignored otherwise): also unlink every
    /// login method linked **after** this epoch (seconds) — for "someone may
    /// have added a login method to my account". The account's oldest
    /// identity is always kept.
    ///
    /// To remove one specific identity instead: list them
    /// (`GET /auth/identities`), unlink it (`POST /auth/identities/unlink`),
    /// then `logout --all`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identities_linked_after: Option<u64>,
}

/// One linked login method, in an [`IdentityList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityInfo {
    /// The identity id (what [`UnlinkIdentityRequest::id`] names).
    pub id: String,
    /// The configured provider instance name.
    pub provider: String,
    /// The provider's immutable subject id.
    pub subject: String,
    /// The email the provider last asserted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether that email was asserted as verified.
    #[serde(default)]
    pub email_verified: bool,
    /// When it was linked (epoch seconds).
    pub linked_at: u64,
    /// The last login through it (epoch seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<u64>,
}

/// `GET /auth/identities`: the caller's linked login methods, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityList {
    /// The identities.
    pub identities: Vec<IdentityInfo>,
}

/// A request to `POST /auth/identities/unlink`. The last identity cannot be
/// unlinked (`409 last_identity`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlinkIdentityRequest {
    /// The identity id from [`IdentityInfo::id`].
    pub id: String,
}

/// A request to begin forgs' own device flow (`POST /auth/device/start`).
///
/// Empty today; the struct exists so a future field is an additive change
/// rather than a shape change.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStartRequest {}

/// A started device flow.
///
/// forgs is itself the device authorization server (docs/design.md §4): the
/// user opens `verification_uri` in a browser, logs in with any provider
/// (choosing a username on first login), and confirms `user_code`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStartResponse {
    /// This client's poll credential. Never a connection credential; it is
    /// redeemed only at `/auth/device/poll`.
    pub device_secret: String,
    /// The short code the human confirms, hyphenated for display
    /// (`ABCD-1234`).
    pub user_code: String,
    /// Where the human goes. Carries **no code**, so the page reflects
    /// nothing and cannot become an injection surface.
    pub verification_uri: String,
    /// `verification_uri` with the code pre-filled, for clients that can open
    /// a browser themselves. The user must still confirm the code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    /// Minimum seconds between polls.
    pub interval: u64,
    /// Seconds until the flow expires.
    pub expires_in: u64,
}

/// A poll for the outcome of a device flow.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePollRequest {
    /// The device secret from [`DeviceStartResponse`].
    pub device_secret: String,
}

/// The outcome of a device-flow poll.
///
/// There is no "needs username" state: the username is chosen in the browser.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DevicePollResponse {
    /// Not yet approved; poll again after `interval`.
    Pending,
    /// Polling too fast; increase the interval.
    SlowDown,
    /// The user refused.
    Denied,
    /// The flow expired.
    Expired,
    /// Approved: a session plus a refresh token.
    Granted(TokenResponse),
}

/// Complete a first login by choosing a username (`POST /auth/signup`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignupRequest {
    /// The pending-signup ticket.
    pub ticket: String,
    /// The chosen username (canonicalised server-side).
    pub username: String,
}

/// A request to `POST /auth/keys`, the authenticated API-key surface.
///
/// One route with an `action` tag rather than REST verbs: one handler, one
/// client helper, and no key handle in a URL path (which proxies log).
///
/// **The caller authenticates with `Authorization: Bearer <session token>`.**
/// The namespace named here is a *target*, checked for membership; a minted
/// key can never exceed the caller's access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ApiKeyRequest {
    /// Mint a namespace-scoped key.
    Create {
        /// The namespace (id or path) the key is scoped to.
        namespace: String,
        /// Time-to-live in seconds. Zero (never expires) is refused over the
        /// API, and the value is capped by the server.
        ttl_secs: u64,
        /// Allow more than one redemption.
        #[serde(default)]
        multi_use: bool,
        /// What the key is for. App-defined; an unrecognised value is a
        /// `400`, never a silent default.
        purpose: String,
        /// A stable **identity** name that survives rotation: re-minting with
        /// the same name rotates only the secret. Absent means an identity
        /// derived from the key itself.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject_name: Option<String>,
        /// App data the key carries (fleet: the tags stamped onto an
        /// enrolled node, a CI key's ops). Validated and canonicalised by the
        /// app's purpose policy; a server that knows no payload for the
        /// purpose refuses a non-null one with `400`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        payload: Option<serde_json::Value>,
    },
    /// List a namespace's keys (hashes only).
    List {
        /// The namespace (id or path).
        namespace: String,
    },
    /// Revoke keys whose hash starts with `prefix`.
    Revoke {
        /// The namespace (id or path).
        namespace: String,
        /// Hash prefix, from an [`ApiKeyList`]. At least 8 hex characters;
        /// ambiguous is a `409` ([`error_code::AMBIGUOUS_PREFIX`]).
        prefix: String,
    },
}

/// A freshly minted API key. **The only time the secret exists.**
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyCreated {
    /// The key itself. Stored nowhere, only its hash.
    pub key: String,
    /// Lowercase-hex SHA-256 of the key — the handle for revocation.
    pub key_hash: String,
    /// The key's id.
    pub id: String,
    /// The namespace id the key is scoped to.
    pub namespace: String,
    /// Whether redeeming the key consumes it.
    pub single_use: bool,
    /// What the key is for, echoed so the CLI can print it.
    pub purpose: String,
    /// The identity the key speaks as, echoed so the CLI can tell a server
    /// that **ignored** the field from one that honoured it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_name: Option<String>,
    /// The payload as stored (the app's canonical form), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    /// Expiry (epoch seconds). Always set on this path.
    pub expires: u64,
}

/// One API key as a listing shows it. Hash-only, never a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    /// The key's id.
    pub id: String,
    /// Lowercase-hex SHA-256 of the key.
    pub key_hash: String,
    /// Whether redeeming the key consumes it.
    pub single_use: bool,
    /// What the key is for.
    pub purpose: String,
    /// The identity the key speaks as. Keys sharing a name are **one
    /// identity**, so revoking any of them affects that identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_name: Option<String>,
    /// The payload the key carries, if any. Not a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    /// Expiry (epoch seconds), or `None` for a key that never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
    /// When the key was consumed (epoch seconds), if it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<u64>,
    /// When the key was minted (epoch seconds).
    pub created_at: u64,
    /// The user who minted it, or `None` for a shell-minted key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
}

/// A namespace's API keys, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyList {
    /// The namespace id listed.
    pub namespace: String,
    /// The keys, newest first.
    pub keys: Vec<ApiKeyInfo>,
}

/// The outcome of a revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyRevoked {
    /// The namespace id the keys were revoked from.
    pub namespace: String,
    /// The hashes deleted.
    pub revoked: Vec<String>,
}

/// A request to `POST /auth/members`: manage a namespace's direct members.
///
/// Listing needs membership; changing needs the highest role on the ladder
/// (inherited roles count). Users travel as usernames and are resolved once,
/// server-side, to their immutable id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum MembersRequest {
    /// List the direct members.
    List {
        /// The namespace (id or path).
        namespace: String,
    },
    /// Add a user, or change their role.
    Set {
        /// The namespace (id or path).
        namespace: String,
        /// The user's current username.
        username: String,
        /// A role label from the app's ladder.
        role: String,
    },
    /// Remove a user's direct membership.
    Remove {
        /// The namespace (id or path).
        namespace: String,
        /// The user's current username.
        username: String,
    },
}

/// One direct member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberInfo {
    /// The rendered subject key (`user:<id>`, a workload, an app subject).
    pub subject: String,
    /// The user id, for user members.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// The username, for user members. Display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The role label.
    pub role: String,
}

/// A namespace's direct members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberList {
    /// The namespace id listed.
    pub namespace: String,
    /// The members, by subject.
    pub members: Vec<MemberInfo>,
}

/// A request to `POST /auth/rename`.
///
/// The old name is tombstoned forever (docs/design.md §6, decision 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RenameRequest {
    /// Rename the calling user (and their personal namespace with them).
    User {
        /// The new username.
        new_username: String,
    },
    /// Rename a (non-personal) namespace node the caller administers.
    Namespace {
        /// The namespace (id or path).
        namespace: String,
        /// Its new name (one path segment).
        new_name: String,
    },
}

/// One membership in a [`SessionInfo`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMembership {
    /// The namespace id.
    pub namespace: String,
    /// The direct role label.
    pub role: String,
}

/// `GET /auth/session`: who the caller is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    /// The rendered subject key.
    pub subject: String,
    /// The user id, for a user session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// The username, for a user session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The credential's expiry (epoch seconds), if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
    /// The user's direct memberships.
    #[serde(default)]
    pub memberships: Vec<SessionMembership>,
}

/// A rejected request.
///
/// Deliberately coarse: the body never distinguishes "unknown" from "expired"
/// (no oracle). Detail lives in the server's audit log. Candidate hashes for
/// an ambiguous prefix are *not* on the wire either; the CLI turns the code
/// into "list the keys and use a longer prefix".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// A short machine-readable code from [`error_code`].
    pub error: String,
}

/// What every hand-written `Debug` below prints in place of a secret.
const REDACTED: &str = "<redacted>";

/// `Some(<redacted>)` / `None`, so a `Debug` still shows *whether* an optional
/// secret is present.
fn redact_opt(v: Option<&String>) -> Option<&'static str> {
    v.map(|_| REDACTED)
}

impl std::fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, field) = match self {
            Self::Refresh { .. } => ("Refresh", "session_token"),
            Self::RefreshToken { .. } => ("RefreshToken", "refresh_token"),
            Self::GithubOidc { .. } => ("GithubOidc", "oidc_token"),
            Self::ApiKey { .. } => ("ApiKey", "api_key"),
        };
        f.debug_struct(name).field(field, &REDACTED).finish()
    }
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("token", &REDACTED)
            .field("expires", &self.expires)
            .field("username", &self.username)
            .field("user_id", &self.user_id)
            .field("refresh_token", &redact_opt(self.refresh_token.as_ref()))
            .finish()
    }
}

impl std::fmt::Debug for LogoutRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogoutRequest")
            .field("refresh_token", &redact_opt(self.refresh_token.as_ref()))
            .field("all", &self.all)
            .field("identities_linked_after", &self.identities_linked_after)
            .finish()
    }
}

impl std::fmt::Debug for DeviceStartResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceStartResponse")
            .field("device_secret", &REDACTED)
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("verification_uri_complete", &self.verification_uri_complete)
            .field("interval", &self.interval)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl std::fmt::Debug for DevicePollRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevicePollRequest")
            .field("device_secret", &REDACTED)
            .finish()
    }
}

impl std::fmt::Debug for DevicePollResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => f.write_str("Pending"),
            Self::SlowDown => f.write_str("SlowDown"),
            Self::Denied => f.write_str("Denied"),
            Self::Expired => f.write_str("Expired"),
            Self::Granted(t) => f.debug_tuple("Granted").field(t).finish(),
        }
    }
}

impl std::fmt::Debug for SignupRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupRequest")
            .field("ticket", &REDACTED)
            .field("username", &self.username)
            .finish()
    }
}

impl std::fmt::Debug for ApiKeyCreated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyCreated")
            .field("key", &REDACTED)
            .field("key_hash", &self.key_hash)
            .field("id", &self.id)
            .field("namespace", &self.namespace)
            .field("single_use", &self.single_use)
            .field("purpose", &self.purpose)
            .field("subject_name", &self.subject_name)
            .field("payload", &self.payload)
            .field("expires", &self.expires)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, to_value, Value};

    fn round_trip<T>(v: &T, expected: &Value)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        assert_eq!(&to_value(v).unwrap(), expected);
        let back: T = serde_json::from_value(expected.clone()).unwrap();
        assert_eq!(&back, v);
    }

    #[test]
    fn token_request_shapes() {
        round_trip(
            &TokenRequest::Refresh {
                session_token: "s".into(),
            },
            &json!({"grant_type": "refresh", "session_token": "s"}),
        );
        round_trip(
            &TokenRequest::RefreshToken {
                refresh_token: "r".into(),
            },
            &json!({"grant_type": "refresh_token", "refresh_token": "r"}),
        );
        round_trip(
            &TokenRequest::GithubOidc {
                oidc_token: "j".into(),
            },
            &json!({"grant_type": "github_oidc", "oidc_token": "j"}),
        );
        round_trip(
            &TokenRequest::ApiKey {
                api_key: "k".into(),
            },
            &json!({"grant_type": "api_key", "api_key": "k"}),
        );
        assert!(serde_json::from_value::<TokenRequest>(
            json!({"grant_type": "auth_key", "auth_key": "k"})
        )
        .is_err());
    }

    #[test]
    fn token_response_omits_absent_fields() {
        let r = TokenResponse {
            token: "t".into(),
            expires: 5,
            username: None,
            user_id: None,
            refresh_token: None,
        };
        round_trip(&r, &json!({"token": "t", "expires": 5}));
    }

    #[test]
    fn logout_defaults() {
        let r: LogoutRequest = serde_json::from_value(json!({})).unwrap();
        assert_eq!(r, LogoutRequest::default());
        round_trip(
            &LogoutRequest {
                refresh_token: Some("r".into()),
                all: true,
                identities_linked_after: None,
            },
            &json!({"refresh_token": "r", "all": true}),
        );
        round_trip(
            &LogoutRequest {
                refresh_token: None,
                all: true,
                identities_linked_after: Some(7),
            },
            &json!({"all": true, "identities_linked_after": 7}),
        );
    }

    #[test]
    fn device_poll_shapes() {
        round_trip(&DevicePollResponse::Pending, &json!({"status": "pending"}));
        round_trip(
            &DevicePollResponse::SlowDown,
            &json!({"status": "slow_down"}),
        );
        round_trip(&DevicePollResponse::Denied, &json!({"status": "denied"}));
        round_trip(&DevicePollResponse::Expired, &json!({"status": "expired"}));
        round_trip(
            &DevicePollResponse::Granted(TokenResponse {
                token: "t".into(),
                expires: 1,
                username: Some("alice".into()),
                user_id: Some("01J".into()),
                refresh_token: Some("r".into()),
            }),
            &json!({"status": "granted", "token": "t", "expires": 1,
                    "username": "alice", "user_id": "01J", "refresh_token": "r"}),
        );
        assert!(
            serde_json::from_value::<DevicePollResponse>(json!({"status": "needs_username"}))
                .is_err()
        );
        round_trip(&DeviceStartRequest {}, &json!({}));
        round_trip(
            &DevicePollRequest {
                device_secret: "d".into(),
            },
            &json!({"device_secret": "d"}),
        );
        round_trip(
            &DeviceStartResponse {
                device_secret: "d".into(),
                user_code: "ABCD-1234".into(),
                verification_uri: "https://x/device".into(),
                verification_uri_complete: None,
                interval: 5,
                expires_in: 900,
            },
            &json!({"device_secret": "d", "user_code": "ABCD-1234",
                    "verification_uri": "https://x/device", "interval": 5,
                    "expires_in": 900}),
        );
    }

    #[test]
    fn signup_shape() {
        round_trip(
            &SignupRequest {
                ticket: "t".into(),
                username: "alice".into(),
            },
            &json!({"ticket": "t", "username": "alice"}),
        );
    }

    #[test]
    fn api_key_request_shapes() {
        round_trip(
            &ApiKeyRequest::Create {
                namespace: "acme".into(),
                ttl_secs: 60,
                multi_use: false,
                purpose: "ci".into(),
                subject_name: Some("builder".into()),
                payload: None,
            },
            &json!({"action": "create", "namespace": "acme", "ttl_secs": 60,
                    "multi_use": false, "purpose": "ci", "subject_name": "builder"}),
        );
        round_trip(
            &ApiKeyRequest::Create {
                namespace: "acme".into(),
                ttl_secs: 60,
                multi_use: true,
                purpose: "node".into(),
                subject_name: None,
                payload: Some(json!({"tags": ["a", "b"]})),
            },
            &json!({"action": "create", "namespace": "acme", "ttl_secs": 60,
                    "multi_use": true, "purpose": "node",
                    "payload": {"tags": ["a", "b"]}}),
        );
        let c: ApiKeyRequest = serde_json::from_value(
            json!({"action": "create", "namespace": "a", "ttl_secs": 1, "purpose": "ci"}),
        )
        .unwrap();
        assert!(matches!(
            c,
            ApiKeyRequest::Create {
                multi_use: false,
                subject_name: None,
                payload: None,
                ..
            }
        ));
        round_trip(
            &ApiKeyRequest::List {
                namespace: "acme".into(),
            },
            &json!({"action": "list", "namespace": "acme"}),
        );
        round_trip(
            &ApiKeyRequest::Revoke {
                namespace: "acme".into(),
                prefix: "deadbeef".into(),
            },
            &json!({"action": "revoke", "namespace": "acme", "prefix": "deadbeef"}),
        );
    }

    #[test]
    fn api_key_responses_round_trip() {
        let info = ApiKeyInfo {
            id: "01J".into(),
            key_hash: "ab".into(),
            single_use: true,
            purpose: "ci".into(),
            subject_name: None,
            payload: None,
            expires: Some(9),
            consumed_at: None,
            created_at: 1,
            created_by: None,
        };
        let with_payload = ApiKeyInfo {
            payload: Some(json!(["x"])),
            ..info.clone()
        };
        round_trip(
            &ApiKeyList {
                namespace: "n".into(),
                keys: vec![info, with_payload],
            },
            &json!({"namespace": "n", "keys": [
                {"id": "01J", "key_hash": "ab",
                    "single_use": true, "purpose": "ci", "expires": 9, "created_at": 1},
                {"id": "01J", "key_hash": "ab", "payload": ["x"],
                    "single_use": true, "purpose": "ci", "expires": 9, "created_at": 1}]}),
        );
        round_trip(
            &ApiKeyCreated {
                key: "k".into(),
                key_hash: "h".into(),
                id: "i".into(),
                namespace: "n".into(),
                single_use: false,
                purpose: "ci".into(),
                subject_name: None,
                payload: None,
                expires: 3,
            },
            &json!({"key": "k", "key_hash": "h", "id": "i", "namespace": "n",
                    "single_use": false, "purpose": "ci", "expires": 3}),
        );
        round_trip(
            &ApiKeyCreated {
                key: "k".into(),
                key_hash: "h".into(),
                id: "i".into(),
                namespace: "n".into(),
                single_use: false,
                purpose: "node".into(),
                subject_name: None,
                payload: Some(json!({"tags": ["a"]})),
                expires: 3,
            },
            &json!({"key": "k", "key_hash": "h", "id": "i", "namespace": "n",
                    "single_use": false, "purpose": "node",
                    "payload": {"tags": ["a"]}, "expires": 3}),
        );
        round_trip(
            &ApiKeyRevoked {
                namespace: "n".into(),
                revoked: vec!["h".into()],
            },
            &json!({"namespace": "n", "revoked": ["h"]}),
        );
        round_trip(
            &ErrorResponse {
                error: error_code::INVALID_GRANT.into(),
            },
            &json!({"error": "invalid_grant"}),
        );
    }

    #[test]
    fn members_and_rename_shapes() {
        round_trip(
            &MembersRequest::List {
                namespace: "acme".into(),
            },
            &json!({"action": "list", "namespace": "acme"}),
        );
        round_trip(
            &MembersRequest::Set {
                namespace: "acme".into(),
                username: "bob".into(),
                role: "write".into(),
            },
            &json!({"action": "set", "namespace": "acme", "username": "bob", "role": "write"}),
        );
        round_trip(
            &MembersRequest::Remove {
                namespace: "acme".into(),
                username: "bob".into(),
            },
            &json!({"action": "remove", "namespace": "acme", "username": "bob"}),
        );
        round_trip(
            &MemberList {
                namespace: "n".into(),
                members: vec![MemberInfo {
                    subject: "user:01J".into(),
                    user_id: Some("01J".into()),
                    username: Some("bob".into()),
                    role: "admin".into(),
                }],
            },
            &json!({"namespace": "n", "members": [{"subject": "user:01J", "user_id": "01J",
                    "username": "bob", "role": "admin"}]}),
        );
        round_trip(
            &RenameRequest::User {
                new_username: "al".into(),
            },
            &json!({"action": "user", "new_username": "al"}),
        );
        round_trip(
            &RenameRequest::Namespace {
                namespace: "acme".into(),
                new_name: "acme2".into(),
            },
            &json!({"action": "namespace", "namespace": "acme", "new_name": "acme2"}),
        );
        round_trip(
            &SessionInfo {
                subject: "user:01J".into(),
                user_id: Some("01J".into()),
                username: Some("al".into()),
                expires: Some(5),
                memberships: vec![SessionMembership {
                    namespace: "n".into(),
                    role: "admin".into(),
                }],
            },
            &json!({"subject": "user:01J", "user_id": "01J", "username": "al", "expires": 5,
                    "memberships": [{"namespace": "n", "role": "admin"}]}),
        );
    }

    #[test]
    fn debug_never_prints_secrets() {
        const S: &str = "SEKRIT";
        let tr = TokenResponse {
            token: format!("{S}-t"),
            expires: 1,
            username: Some("alice".into()),
            user_id: None,
            refresh_token: Some(format!("{S}-r")),
        };
        let shown = [
            format!(
                "{:?}",
                TokenRequest::Refresh {
                    session_token: S.into()
                }
            ),
            format!(
                "{:?}",
                TokenRequest::RefreshToken {
                    refresh_token: S.into()
                }
            ),
            format!(
                "{:?}",
                TokenRequest::GithubOidc {
                    oidc_token: S.into()
                }
            ),
            format!("{:?}", TokenRequest::ApiKey { api_key: S.into() }),
            format!("{tr:?}"),
            format!("{:?}", DevicePollResponse::Granted(tr.clone())),
            format!(
                "{:?}",
                LogoutRequest {
                    refresh_token: Some(S.into()),
                    all: true,
                    identities_linked_after: None,
                }
            ),
            format!(
                "{:?}",
                DevicePollRequest {
                    device_secret: S.into()
                }
            ),
            format!(
                "{:?}",
                DeviceStartResponse {
                    device_secret: S.into(),
                    user_code: "ABCD-1234".into(),
                    verification_uri: "https://x/device".into(),
                    verification_uri_complete: None,
                    interval: 5,
                    expires_in: 900,
                }
            ),
            format!(
                "{:?}",
                SignupRequest {
                    ticket: S.into(),
                    username: "alice".into()
                }
            ),
            format!(
                "{:?}",
                ApiKeyCreated {
                    key: S.into(),
                    key_hash: "h".into(),
                    id: "i".into(),
                    namespace: "n".into(),
                    single_use: true,
                    purpose: "ci".into(),
                    subject_name: None,
                    payload: None,
                    expires: 3,
                }
            ),
        ];
        for s in &shown {
            assert!(!s.contains(S), "secret leaked: {s}");
            assert!(s.contains(REDACTED), "{s}");
        }
        // Non-secret fields stay visible.
        assert!(shown[4].contains("alice"));
        assert!(shown[8].contains("ABCD-1234"));
    }
}
