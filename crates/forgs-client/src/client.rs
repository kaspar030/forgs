//! [`ForgsClient`]: one method per `/auth/*` route, plus
//! [`ForgsClient::post_json`] / [`ForgsClient::post`] for the app's own routes
//! over the same trust path.

use std::time::Duration;

use hyper::body::Bytes;
use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::Zeroize;

use forgs::api::{
    ApiKeyCreated, ApiKeyList, ApiKeyRequest, ApiKeyRevoked, DevicePollRequest, DevicePollResponse,
    DeviceStartRequest, DeviceStartResponse, LogoutRequest, MemberList, MembersRequest,
    RenameRequest, TokenRequest, TokenResponse,
};

use crate::error::ClientError;
use crate::secret::Secret;
use crate::transport::{self, HttpClient};

/// A client for one forgs server.
///
/// Cheap to clone (the connection pool is shared). Build it once per server
/// and reuse it: the TLS configuration — including any pin — is fixed at
/// construction, so every route goes through the same trust path.
#[derive(Clone)]
pub struct ForgsClient {
    base: String,
    http: HttpClient,
    timeout: Duration,
    /// The origin of `base`, for checking where a device flow sends the
    /// human.
    origin: Origin,
    /// An extra origin the device verification URL may live on (a split
    /// internal/public deployment), set with
    /// [`ForgsClientBuilder::verification_origin`].
    verification_origin: Option<Origin>,
}

/// Builder for a [`ForgsClient`] with non-default policy. Start with
/// [`ForgsClient::builder`].
#[derive(Clone)]
pub struct ForgsClientBuilder {
    base: String,
    pin: Option<[u8; 32]>,
    timeout: Duration,
    allow_insecure_http: bool,
    verification_origin: Option<String>,
}

impl std::fmt::Debug for ForgsClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgsClientBuilder")
            .field("base", &self.base)
            .field("pinned", &self.pin.is_some())
            .field("timeout", &self.timeout)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .field("verification_origin", &self.verification_origin)
            .finish()
    }
}

impl ForgsClientBuilder {
    /// Pin the server's leaf certificate by SHA-256 (see [`crate::tls`]).
    /// A pinned client only ever speaks `https`.
    #[must_use]
    pub fn pin(mut self, pin: [u8; 32]) -> Self {
        self.pin = Some(pin);
        self
    }

    /// The per-request timeout (default 30s).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Accept a plain `http://` base on a non-loopback host. Off by default:
    /// credentials would cross the network in cleartext. Loopback
    /// (`localhost`, `127.0.0.0/8`, `::1`) is always allowed.
    #[must_use]
    pub fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// An extra origin (`https://login.example`, no path) the device flow's
    /// verification URL may point at, besides the base URL's own origin —
    /// for a deployment the client reaches internally while humans use a
    /// public name. A verification URL on any other origin is refused.
    #[must_use]
    pub fn verification_origin(mut self, origin: &str) -> Self {
        self.verification_origin = Some(origin.to_owned());
        self
    }

    /// Build the client.
    ///
    /// # Errors
    ///
    /// [`ClientError::Url`] if the base is not a usable `http(s)` URL, is
    /// `http` with a pin, is `http` on a non-loopback host without
    /// [`ForgsClientBuilder::allow_insecure_http`], or the verification
    /// origin is not a bare `http(s)` origin.
    pub fn build(self) -> Result<ForgsClient, ClientError> {
        let base = normalise_base(&self.base)?;
        let uri: http::Uri = base
            .parse()
            .map_err(|e: http::uri::InvalidUri| ClientError::Url(e.to_string()))?;
        let origin =
            Origin::of(&uri).ok_or_else(|| ClientError::Url("URL has no origin".to_owned()))?;
        if origin.scheme == "http" {
            if self.pin.is_some() {
                return Err(ClientError::Url(
                    "a certificate pin requires an https:// URL".to_owned(),
                ));
            }
            if !self.allow_insecure_http && !is_loopback_host(&origin.host) {
                return Err(ClientError::Url(
                    "plain http:// is only allowed for a loopback host; use https:// \
                     (or opt in with allow_insecure_http)"
                        .to_owned(),
                ));
            }
        }
        let verification_origin = self
            .verification_origin
            .as_deref()
            .map(parse_bare_origin)
            .transpose()?;
        Ok(ForgsClient {
            base,
            http: transport::build(self.pin),
            timeout: self.timeout,
            origin,
            verification_origin,
        })
    }
}

/// A URL origin: scheme, lowercased host, explicit port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Origin {
    pub(crate) scheme: String,
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl Origin {
    /// The origin of an absolute `http(s)` URI; `None` for anything else.
    pub(crate) fn of(uri: &http::Uri) -> Option<Self> {
        let scheme = uri.scheme_str()?.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "https" => 443,
            "http" => 80,
            _ => return None,
        };
        let authority = uri.authority()?;
        if authority.as_str().contains('@') || authority.host().is_empty() {
            return None;
        }
        Some(Self {
            scheme,
            host: authority.host().to_ascii_lowercase(),
            port: authority.port_u16().unwrap_or(default_port),
        })
    }
}

/// Parse `https://host[:port]` with nothing after the authority (a single
/// trailing `/` is tolerated).
fn parse_bare_origin(raw: &str) -> Result<Origin, ClientError> {
    let bad = || ClientError::Url("verification origin must be a bare http(s) origin".to_owned());
    let uri: http::Uri = raw.trim().parse().map_err(|_| bad())?;
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return Err(bad());
    }
    Origin::of(&uri).ok_or_else(bad)
}

/// `localhost` or a loopback IP literal (`127.0.0.0/8`, `::1`).
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

impl std::fmt::Debug for ForgsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgsClient")
            .field("base", &self.base)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// What to mint in [`ForgsClient::create_api_key`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApiKeySpec {
    /// The namespace (id or path) the key is scoped to.
    pub namespace: String,
    /// Time-to-live in seconds. Must be non-zero; the server caps it.
    pub ttl_secs: u64,
    /// Allow more than one redemption.
    pub multi_use: bool,
    /// What the key is for (app-defined).
    pub purpose: String,
    /// A stable identity name that survives rotation.
    pub subject_name: Option<String>,
    /// App data the key carries (fleet: a node key's tags). The server's
    /// purpose policy validates and canonicalises it; a purpose that takes
    /// none refuses a non-null payload with `400`.
    pub payload: Option<serde_json::Value>,
}

impl ForgsClient {
    /// A client for the server at `base_url`.
    ///
    /// `base_url` may be a full origin (`https://auth.example`), carry a path
    /// prefix (`https://example/forgs`), or be a bare `host:port` (defaults to
    /// `https`). `pin` is an optional server-leaf SHA-256 (see
    /// [`crate::tls`]).
    ///
    /// # Errors
    ///
    /// A plain `http://` base is accepted only for a loopback host and
    /// never with a pin; [`ForgsClient::builder`] can opt in to insecure
    /// http elsewhere.
    ///
    /// # Errors
    ///
    /// [`ClientError::Url`] if `base_url` is not a usable `http(s)` origin,
    /// or breaks the http policy above.
    pub fn new(base_url: &str, pin: Option<[u8; 32]>) -> Result<Self, ClientError> {
        let builder = Self::builder(base_url);
        match pin {
            Some(pin) => builder.pin(pin),
            None => builder,
        }
        .build()
    }

    /// A [`ForgsClientBuilder`] for the server at `base_url` (same forms as
    /// [`ForgsClient::new`]).
    #[must_use]
    pub fn builder(base_url: &str) -> ForgsClientBuilder {
        ForgsClientBuilder {
            base: base_url.to_owned(),
            pin: None,
            timeout: transport::DEFAULT_TIMEOUT,
            allow_insecure_http: false,
            verification_origin: None,
        }
    }

    /// Whether `uri` is on an origin the device flow may send the human to:
    /// the base URL's own, or the configured verification origin.
    pub(crate) fn verification_origin_allowed(&self, uri: &http::Uri) -> bool {
        Origin::of(uri)
            .is_some_and(|o| o == self.origin || self.verification_origin.as_ref() == Some(&o))
    }

    /// Whether the base URL is plain `http`.
    pub(crate) fn is_plain_http(&self) -> bool {
        self.origin.scheme == "http"
    }

    /// Replace the per-request timeout (default 30s).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The normalised base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// `{base}{route}`. `route` must be an absolute path (`/...`): anything
    /// else could splice into the authority (`"@evil/x"`, `"evil.example/x"`)
    /// and send the request — and its bearer — to a host the pin was never
    /// meant for.
    fn route(&self, route: &str) -> Result<http::Uri, ClientError> {
        if !route.starts_with('/')
            || route.contains("://")
            || route.contains('#')
            || route.bytes().any(|b| b.is_ascii_control() || b == b' ')
        {
            return Err(ClientError::Url(format!(
                "route must be an absolute path: {route:?}"
            )));
        }
        format!("{}{route}", self.base)
            .parse()
            .map_err(|e: http::uri::InvalidUri| ClientError::Url(e.to_string()))
    }

    /// `POST` JSON to `route` (relative to the base URL, starting with `/`)
    /// and return the raw response body — for an app route answering `204`
    /// or a non-JSON body.
    ///
    /// This is the same path every `/auth/*` call takes: the same connector
    /// and TLS configuration (so a pin covers app routes too), the same
    /// timeout and response-size cap. `bearer`, if any, is sent **only** as
    /// an `Authorization: Bearer` header, never in the URL or body.
    ///
    /// # Errors
    ///
    /// [`ClientError::Url`] for a route that is not an absolute path (nothing
    /// is sent); otherwise as [`ForgsClient::exchange`].
    pub async fn post<Q: Serialize>(
        &self,
        route: &str,
        bearer: Option<&Secret>,
        request: &Q,
    ) -> Result<Bytes, ClientError> {
        // Serialising our own wire types cannot fail; the message would not
        // quote a value either way.
        let body = serde_json::to_vec(request)
            .map_err(|e| ClientError::Malformed(format!("encoding the request: {e}")))?;
        transport::send(
            &self.http,
            self.timeout,
            http::Method::POST,
            self.route(route)?,
            bearer,
            Some(body),
        )
        .await
    }

    /// `POST` JSON to `route` and decode a JSON response. See
    /// [`ForgsClient::post`] for the trust path and the `route` rules; this is
    /// how an app calls its own JSON routes (fleet: node enrollment).
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::post`], plus [`ClientError::Malformed`] for a body
    /// that does not decode as `R`.
    pub async fn post_json<Q: Serialize, R: DeserializeOwned>(
        &self,
        route: &str,
        bearer: Option<&Secret>,
        request: &Q,
    ) -> Result<R, ClientError> {
        let bytes = self.post(route, bearer, request).await?;
        serde_json::from_slice(&bytes).map_err(|e| ClientError::malformed(route, &e))
    }

    /// `GET` `route` (relative to the base URL, starting with `/`) and return
    /// the raw response body. A query string in `route` is allowed
    /// (`/api/x?y=1`).
    ///
    /// Same trust path as [`ForgsClient::post`]: the same connector and TLS
    /// configuration (so a pin covers it), the same timeout and response-size
    /// cap. `bearer`, if any, is sent **only** as an `Authorization: Bearer`
    /// header, never in the URL.
    ///
    /// # Errors
    ///
    /// [`ClientError::Url`] for a route that is not an absolute path (nothing
    /// is sent); otherwise as [`ForgsClient::exchange`].
    pub async fn get(&self, route: &str, bearer: Option<&Secret>) -> Result<Bytes, ClientError> {
        self.get_absolute(self.route(route)?, bearer).await
    }

    /// `GET` `route` and decode a JSON response. See [`ForgsClient::get`] for
    /// the trust path and the `route` rules.
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::get`], plus [`ClientError::Malformed`] for a body
    /// that does not decode as `R`.
    pub async fn get_json<R: DeserializeOwned>(
        &self,
        route: &str,
        bearer: Option<&Secret>,
    ) -> Result<R, ClientError> {
        let bytes = self.get(route, bearer).await?;
        serde_json::from_slice(&bytes).map_err(|e| ClientError::malformed(route, &e))
    }

    /// `GET` an absolute URL through the same connector and trust config.
    pub(crate) async fn get_absolute(
        &self,
        uri: http::Uri,
        bearer: Option<&Secret>,
    ) -> Result<Bytes, ClientError> {
        transport::send(
            &self.http,
            self.timeout,
            http::Method::GET,
            uri,
            bearer,
            None,
        )
        .await
    }

    /// `POST /auth/token` with any grant.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] if the server was not reached,
    /// [`ClientError::Rejected`] for a non-2xx (a bad credential is a flat
    /// `401 invalid_grant`), [`ClientError::Malformed`] for an unreadable
    /// body. The other methods fail the same way.
    pub async fn exchange(&self, request: &TokenRequest) -> Result<TokenResponse, ClientError> {
        self.post_json("/auth/token", None, request).await
    }

    /// [`ForgsClient::exchange`], then wipe the credential copy held in
    /// `request` (the wire structs in `forgs::api` are plain `String`s).
    async fn exchange_scrubbed(
        &self,
        mut request: TokenRequest,
    ) -> Result<TokenResponse, ClientError> {
        let result = self.exchange(&request).await;
        match &mut request {
            TokenRequest::Refresh { session_token: s }
            | TokenRequest::RefreshToken { refresh_token: s }
            | TokenRequest::GithubOidc { oidc_token: s }
            | TokenRequest::ApiKey { api_key: s } => s.zeroize(),
        }
        result
    }

    /// Exchange a still-valid session token for a fresh one.
    ///
    /// **Replacing**: the server deletes the presented session on success, so
    /// two callers racing near expiry leave one holding a dead token, and a
    /// lapsed session cannot be refreshed at all.
    /// [`ForgsClient::redeem_refresh_token`] has neither property and is what
    /// a concurrent caller should reach for first.
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::exchange`].
    pub async fn refresh_session(&self, session_token: &str) -> Result<TokenResponse, ClientError> {
        self.exchange_scrubbed(TokenRequest::Refresh {
            session_token: session_token.to_owned(),
        })
        .await
    }

    /// Redeem a long-lived refresh token for a fresh session token.
    ///
    /// Works after the session has expired, and is **non-rotating**: the
    /// refresh token stays usable, so concurrent redemptions all succeed. The
    /// response carries no refresh token — keep the one you have.
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::exchange`]; an unknown or expired refresh token is a
    /// `401 invalid_grant` (log in again).
    pub async fn redeem_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, ClientError> {
        self.exchange_scrubbed(TokenRequest::RefreshToken {
            refresh_token: refresh_token.to_owned(),
        })
        .await
    }

    /// Exchange a GitHub Actions OIDC JWT for a short-lived workload token.
    /// Fetch the JWT with [`crate::gha::fetch_id_token`].
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::exchange`]. Every verification failure is a flat
    /// `401 invalid_grant`.
    pub async fn exchange_github_oidc(
        &self,
        oidc_token: &str,
    ) -> Result<TokenResponse, ClientError> {
        self.exchange_scrubbed(TokenRequest::GithubOidc {
            oidc_token: oidc_token.to_owned(),
        })
        .await
    }

    /// Redeem an API key for a workload token — the fallback for a runner
    /// with no workload identity.
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::exchange`]: an expired or consumed key is a
    /// `401 invalid_grant`, a key whose purpose does not redeem this way a
    /// `403 forbidden`.
    pub async fn exchange_api_key(&self, api_key: &str) -> Result<TokenResponse, ClientError> {
        self.exchange_scrubbed(TokenRequest::ApiKey {
            api_key: api_key.to_owned(),
        })
        .await
    }

    /// Revoke credentials at `POST /auth/logout`.
    ///
    /// The session authenticates as a **bearer header**: this is an ordinary
    /// authenticated call about the caller's own identity. With `all = false`
    /// the presented session and, if given, the caller's refresh token are
    /// revoked; with `all = true` every session and refresh token of the user
    /// goes — the lost-machine answer.
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::exchange`]. The success response (`204`) has no
    /// body.
    pub async fn logout(
        &self,
        session_token: &str,
        refresh_token: Option<&str>,
        all: bool,
    ) -> Result<(), ClientError> {
        let mut request = LogoutRequest {
            refresh_token: refresh_token.map(ToOwned::to_owned),
            all,
        };
        let result = self
            .post("/auth/logout", Some(&Secret::from(session_token)), &request)
            .await
            .map(drop);
        request.refresh_token.zeroize();
        result
    }

    /// Begin forgs' own device flow (`POST /auth/device/start`).
    /// [`crate::device::DeviceLogin`] drives the whole ceremony.
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::exchange`].
    pub async fn device_start(&self) -> Result<DeviceStartResponse, ClientError> {
        self.post_json("/auth/device/start", None, &DeviceStartRequest::default())
            .await
    }

    /// Poll a device flow (`POST /auth/device/poll`). Pending, slow-down,
    /// denial and expiry are `200` outcomes, not errors.
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::exchange`]; an unknown device secret is a
    /// [`ClientError::Rejected`].
    pub async fn device_poll(
        &self,
        device_secret: &str,
    ) -> Result<DevicePollResponse, ClientError> {
        let mut request = DevicePollRequest {
            device_secret: device_secret.to_owned(),
        };
        let result = self.post_json("/auth/device/poll", None, &request).await;
        request.device_secret.zeroize();
        result
    }

    /// Mint a namespace-scoped API key (`POST /auth/keys`, `create`).
    ///
    /// **Check the echo.** A server that does not know `subject_name` ignores
    /// it and mints an unnamed key while answering `200`;
    /// [`ApiKeyCreated::subject_name`] echoes what was stored, so a caller
    /// that asked for a name must compare the two before believing it has a
    /// stable identity.
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::exchange`]: a non-member is `403 forbidden`, a zero
    /// or over-cap TTL, unknown purpose or refused payload
    /// `400 invalid_request`.
    pub async fn create_api_key(
        &self,
        session_token: &str,
        spec: &ApiKeySpec,
    ) -> Result<ApiKeyCreated, ClientError> {
        self.keys(
            session_token,
            &ApiKeyRequest::Create {
                namespace: spec.namespace.clone(),
                ttl_secs: spec.ttl_secs,
                multi_use: spec.multi_use,
                purpose: spec.purpose.clone(),
                subject_name: spec.subject_name.clone(),
                payload: spec.payload.clone(),
            },
        )
        .await
    }

    /// List a namespace's API keys (hashes only, never a secret).
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::exchange`].
    pub async fn list_api_keys(
        &self,
        session_token: &str,
        namespace: &str,
    ) -> Result<ApiKeyList, ClientError> {
        self.keys(
            session_token,
            &ApiKeyRequest::List {
                namespace: namespace.to_owned(),
            },
        )
        .await
    }

    /// Revoke a namespace's API keys by hash prefix (at least 8 hex chars).
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::exchange`]: an ambiguous prefix is
    /// `409 ambiguous_prefix` and revokes nothing, an unknown one
    /// `404 not_found`, a caller who neither minted the key nor administers
    /// the namespace `403 forbidden`.
    pub async fn revoke_api_key(
        &self,
        session_token: &str,
        namespace: &str,
        prefix: &str,
    ) -> Result<ApiKeyRevoked, ClientError> {
        self.keys(
            session_token,
            &ApiKeyRequest::Revoke {
                namespace: namespace.to_owned(),
                prefix: prefix.to_owned(),
            },
        )
        .await
    }

    /// List a namespace's direct members (`POST /auth/members`, `list`).
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::exchange`]: a caller who may not see the namespace
    /// is `403 forbidden`.
    pub async fn list_members(
        &self,
        session_token: &str,
        namespace: &str,
    ) -> Result<MemberList, ClientError> {
        self.post_json(
            "/auth/members",
            Some(&Secret::from(session_token)),
            &MembersRequest::List {
                namespace: namespace.to_owned(),
            },
        )
        .await
    }

    /// Add a user to a namespace or change their role
    /// (`POST /auth/members`, `set`). Admin only.
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::exchange`]: a non-admin is `403 forbidden`, demoting
    /// the last admin `409 last_admin`.
    pub async fn set_member(
        &self,
        session_token: &str,
        namespace: &str,
        username: &str,
        role: &str,
    ) -> Result<(), ClientError> {
        self.members(
            session_token,
            &MembersRequest::Set {
                namespace: namespace.to_owned(),
                username: username.to_owned(),
                role: role.to_owned(),
            },
        )
        .await
    }

    /// Remove a user's direct membership (`POST /auth/members`, `remove`).
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::set_member`].
    pub async fn remove_member(
        &self,
        session_token: &str,
        namespace: &str,
        username: &str,
    ) -> Result<(), ClientError> {
        self.members(
            session_token,
            &MembersRequest::Remove {
                namespace: namespace.to_owned(),
                username: username.to_owned(),
            },
        )
        .await
    }

    /// Rename the calling user or a namespace (`POST /auth/rename`). The old
    /// name is tombstoned forever.
    ///
    /// # Errors
    ///
    /// As [`ForgsClient::exchange`]: a taken or tombstoned name is
    /// `409 username_taken`, an invalid one `400`.
    pub async fn rename(
        &self,
        session_token: &str,
        request: &RenameRequest,
    ) -> Result<(), ClientError> {
        self.post("/auth/rename", Some(&Secret::from(session_token)), request)
            .await
            .map(drop)
    }

    async fn members(
        &self,
        session_token: &str,
        request: &MembersRequest,
    ) -> Result<(), ClientError> {
        self.post("/auth/members", Some(&Secret::from(session_token)), request)
            .await
            .map(drop)
    }

    async fn keys<R: DeserializeOwned>(
        &self,
        session_token: &str,
        request: &ApiKeyRequest,
    ) -> Result<R, ClientError> {
        self.post_json("/auth/keys", Some(&Secret::from(session_token)), request)
            .await
    }
}

/// Normalise a user-supplied server address into `http(s)://host[:port][/path]`
/// with no trailing slash.
///
/// A bare `host:port` defaults to `https`. A path prefix is kept, for a
/// server mounted below the origin.
///
/// # Errors
///
/// [`ClientError::Url`] if the string is empty, unparseable, has no host, or
/// uses a scheme other than `http`/`https`.
pub fn normalise_base(base_url: &str) -> Result<String, ClientError> {
    let s = base_url.trim();
    if s.is_empty() {
        return Err(ClientError::Url("empty URL".to_owned()));
    }
    let with_scheme = if s.contains("://") {
        s.to_owned()
    } else {
        format!("https://{s}")
    };
    let uri: http::Uri = with_scheme
        .parse()
        .map_err(|e: http::uri::InvalidUri| ClientError::Url(e.to_string()))?;
    let scheme = uri.scheme_str().unwrap_or("https");
    if scheme != "http" && scheme != "https" {
        return Err(ClientError::Url(format!("unsupported scheme `{scheme}`")));
    }
    let authority = uri
        .authority()
        .filter(|a| !a.host().is_empty())
        .ok_or_else(|| ClientError::Url("URL has no host".to_owned()))?;
    if authority.as_str().contains('@') {
        return Err(ClientError::Url("URL must not carry userinfo".to_owned()));
    }
    if uri.query().is_some() {
        return Err(ClientError::Url("URL must not carry a query".to_owned()));
    }
    let path = uri.path().trim_end_matches('/');
    Ok(format!("{scheme}://{authority}{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_host_port_defaults_to_https() {
        assert_eq!(
            normalise_base("auth.example:7000").unwrap(),
            "https://auth.example:7000"
        );
    }

    #[test]
    fn scheme_kept_trailing_slash_trimmed_path_kept() {
        assert_eq!(
            normalise_base("http://127.0.0.1:7000/").unwrap(),
            "http://127.0.0.1:7000"
        );
        assert_eq!(
            normalise_base(" https://auth.example ").unwrap(),
            "https://auth.example"
        );
        assert_eq!(
            normalise_base("https://example.com/forgs/").unwrap(),
            "https://example.com/forgs"
        );
    }

    #[test]
    fn routes_append_to_the_base() {
        let c = ForgsClient::new("auth.example:7000/", None).unwrap();
        for route in [
            "/auth/token",
            "/auth/logout",
            "/auth/keys",
            "/auth/device/start",
            "/auth/device/poll",
            "/auth/members",
            "/auth/rename",
            "/api/nodes/enroll",
            "/api/x?y=1",
        ] {
            assert_eq!(
                c.route(route).unwrap().to_string(),
                format!("https://auth.example:7000{route}")
            );
        }
        let c = ForgsClient::new("https://example.com/forgs", None).unwrap();
        assert_eq!(
            c.route("/auth/token").unwrap().to_string(),
            "https://example.com/forgs/auth/token"
        );
    }

    #[test]
    fn routes_must_be_absolute_paths() {
        let c = ForgsClient::new("https://auth.example", None).unwrap();
        for bad in [
            "",
            "api/x",
            "@evil.example/x",
            ".evil.example/x",
            ":8443/x",
            "/x://y",
            "https://evil.example/x",
            "/a b",
            "/a\nb",
            "/a#f",
        ] {
            assert!(matches!(c.route(bad), Err(ClientError::Url(_))), "{bad:?}");
        }
    }

    #[test]
    fn unusable_urls_are_rejected() {
        for bad in [
            "",
            "  ",
            "ftp://auth.example",
            "https://",
            "https://user:pw@auth.example",
            "https://auth.example/?x=1",
        ] {
            assert!(
                matches!(normalise_base(bad), Err(ClientError::Url(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn http_policy() {
        // Non-loopback http needs the opt-in.
        assert!(matches!(
            ForgsClient::new("http://10.0.0.5:7000", None),
            Err(ClientError::Url(_))
        ));
        assert!(ForgsClient::builder("http://10.0.0.5")
            .allow_insecure_http(true)
            .build()
            .is_ok());
        for ok in [
            "http://127.0.0.1:1",
            "http://127.9.9.9",
            "http://localhost",
            "http://LocalHost:8",
            "http://[::1]:7",
        ] {
            assert!(ForgsClient::new(ok, None).is_ok(), "{ok}");
        }
        assert!(matches!(
            ForgsClient::new("http://localhost.evil.example", None),
            Err(ClientError::Url(_))
        ));
        // A pin always requires https.
        assert!(matches!(
            ForgsClient::new("http://127.0.0.1", Some([0; 32])),
            Err(ClientError::Url(_))
        ));
        assert!(matches!(
            ForgsClient::builder("http://10.0.0.5")
                .allow_insecure_http(true)
                .pin([0; 32])
                .build(),
            Err(ClientError::Url(_))
        ));
        assert!(ForgsClient::new("https://auth.example", Some([0; 32])).is_ok());
        assert!(ForgsClient::new("auth.example", Some([0; 32])).is_ok());
    }

    #[test]
    fn origins() {
        let o = |s: &str| s.parse().ok().and_then(|u| Origin::of(&u));
        assert_eq!(o("https://A.example/x"), o("https://a.example:443/y?z"));
        assert_eq!(o("http://a.example"), o("http://a.example:80"));
        assert_ne!(o("http://a.example"), o("https://a.example"));
        assert_ne!(o("https://a.example:8443"), o("https://a.example"));
        assert_eq!(o("file:///etc/passwd"), None);
        assert_eq!(o("ftp://a.example/"), None);
        assert_eq!(o("https://u@a.example/"), None);

        let c = ForgsClient::builder("https://internal.example:8443/forgs")
            .verification_origin("https://login.example/")
            .build()
            .unwrap();
        for (url, ok) in [
            ("https://internal.example:8443/forgs/auth/device", true),
            ("https://login.example/forgs/auth/device", true),
            ("https://internal.example/auth/device", false),
            ("http://login.example/auth/device", false),
            ("https://evil.example/auth/device", false),
        ] {
            assert_eq!(
                c.verification_origin_allowed(&url.parse().unwrap()),
                ok,
                "{url}"
            );
        }
        for bad in [
            "login.example",
            "https://login.example/x",
            "ftp://x",
            "https://x/?a",
        ] {
            assert!(
                matches!(
                    ForgsClient::builder("https://a.example")
                        .verification_origin(bad)
                        .build(),
                    Err(ClientError::Url(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn debug_shows_the_base_only() {
        let c = ForgsClient::new("auth.example", None).unwrap();
        let s = format!("{c:?}");
        assert!(s.contains("https://auth.example"), "{s}");
    }
}
