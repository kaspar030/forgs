//! [`ForgsClient`]: one method per `/auth/*` route.

use std::time::Duration;

use hyper::body::Bytes;
use serde::de::DeserializeOwned;
use serde::Serialize;

use forgs::api::{
    ApiKeyCreated, ApiKeyList, ApiKeyRequest, ApiKeyRevoked, DevicePollRequest, DevicePollResponse,
    DeviceStartRequest, DeviceStartResponse, LogoutRequest, TokenRequest, TokenResponse,
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// [`ClientError::Url`] if `base_url` is not a usable `http(s)` origin.
    pub fn new(base_url: &str, pin: Option<[u8; 32]>) -> Result<Self, ClientError> {
        Ok(Self {
            base: normalise_base(base_url)?,
            http: transport::build(pin),
            timeout: transport::DEFAULT_TIMEOUT,
        })
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

    fn route(&self, route: &str) -> Result<http::Uri, ClientError> {
        format!("{}{route}", self.base)
            .parse()
            .map_err(|e: http::uri::InvalidUri| ClientError::Url(e.to_string()))
    }

    async fn post_raw<Q: Serialize>(
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

    async fn post_json<Q: Serialize, R: DeserializeOwned>(
        &self,
        route: &str,
        bearer: Option<&Secret>,
        request: &Q,
    ) -> Result<R, ClientError> {
        let bytes = self.post_raw(route, bearer, request).await?;
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
        self.exchange(&TokenRequest::Refresh {
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
        self.exchange(&TokenRequest::RefreshToken {
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
        self.exchange(&TokenRequest::GithubOidc {
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
        self.exchange(&TokenRequest::ApiKey {
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
        self.post_raw(
            "/auth/logout",
            Some(&Secret::from(session_token)),
            &LogoutRequest {
                refresh_token: refresh_token.map(ToOwned::to_owned),
                all,
            },
        )
        .await
        .map(drop)
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
        self.post_json(
            "/auth/device/poll",
            None,
            &DevicePollRequest {
                device_secret: device_secret.to_owned(),
            },
        )
        .await
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
    /// or over-cap TTL or unknown purpose `400 invalid_request`.
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
    fn debug_shows_the_base_only() {
        let c = ForgsClient::new("auth.example", None).unwrap();
        let s = format!("{c:?}");
        assert!(s.contains("https://auth.example"), "{s}");
    }
}
