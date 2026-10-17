//! Fetch a **GitHub Actions OIDC token** from the runner's token service, for
//! [`ForgsClient::exchange_github_oidc`].
//!
//! `ACTIONS_ID_TOKEN_REQUEST_URL` / `ACTIONS_ID_TOKEN_REQUEST_TOKEN` exist
//! only in a job with `permissions: id-token: write`. Both are per-job; nothing
//! is stored. The request goes through the client's own connector (and so its
//! trust config), keeping one trust path.
//!
//! **A pinned client cannot reach GitHub.** The pin is the client's whole
//! trust config, so the TLS handshake with the token service fails (a
//! [`ClientError::Transport`]) and the request token is never sent: it fails
//! closed. If the forgs server is pinned, build a second, unpinned client for
//! this fetch — see [`fetch_id_token`].

use serde::Deserialize;

use crate::client::ForgsClient;
use crate::error::ClientError;
use crate::secret::Secret;

/// Environment variable holding the token-service URL.
pub const ENV_REQUEST_URL: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
/// Environment variable holding the token-service bearer token.
pub const ENV_REQUEST_TOKEN: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

/// Why [`fetch_id_token_from_env`] failed.
#[derive(Debug, thiserror::Error)]
pub enum GhaError {
    /// A variable is missing: not a GitHub Actions job, or no
    /// `permissions: id-token: write`.
    #[error(
        "`{0}` is not set: not a GitHub Actions job, or the job lacks \
         `permissions: id-token: write`"
    )]
    NotInJob(&'static str),
    /// The fetch itself failed.
    #[error(transparent)]
    Client(#[from] ClientError),
}

/// Fetch an OIDC token for `audience` (usually the forgs server's public URL)
/// from the runner's token service at `request_url`.
///
/// # Errors
///
/// [`ClientError::Url`] for an empty `audience` or one containing `&`/`#`
/// (refused rather than escaped: such an audience is a configuration
/// mistake), or an unparseable `request_url`; [`ClientError::Rejected`] for a
/// non-2xx (usually a job without `id-token: write`);
/// [`ClientError::Malformed`] for a body without a non-empty `value`.
///
/// # Pinned clients
///
/// `client`'s trust config applies here too, so a client built with a pin
/// fails against GitHub with [`ClientError::Transport`] before the request
/// token leaves the process. Use a separate `WebPKI` client for the fetch and
/// the pinned one for the exchange:
///
/// ```no_run
/// # async fn run(pin: [u8; 32], url: &str, token: &forgs_client::Secret)
/// #     -> Result<(), forgs_client::ClientError> {
/// use forgs_client::{gha, ForgsClient};
/// // The base URL is not used for the fetch (the full `request_url` is), but
/// // must be a valid base: `request_url` itself carries a query.
/// let github = ForgsClient::new("https://token.actions.githubusercontent.com", None)?;
/// let forgs = ForgsClient::new("https://forgs.internal:8443", Some(pin))?;
/// let jwt = gha::fetch_id_token(&github, url, token, "https://forgs.internal:8443").await?;
/// let session = forgs.exchange_github_oidc(jwt.expose()).await?;
/// # drop(session); Ok(()) }
/// ```
pub async fn fetch_id_token(
    client: &ForgsClient,
    request_url: &str,
    request_token: &Secret,
    audience: &str,
) -> Result<Secret, ClientError> {
    #[derive(Deserialize)]
    struct IdTokenResponse {
        value: String,
    }

    if audience.trim().is_empty() || audience.contains(['&', '#']) {
        return Err(ClientError::Url(
            "audience must be non-empty and free of `&` and `#`".to_owned(),
        ));
    }
    let separator = if request_url.contains('?') { '&' } else { '?' };
    let uri: http::Uri = format!(
        "{request_url}{separator}audience={}",
        percent_encode(audience)
    )
    .parse()
    .map_err(|e: http::uri::InvalidUri| ClientError::Url(e.to_string()))?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.host().is_none() {
        return Err(ClientError::Url(
            "the token-service URL must be an absolute http(s) URL".to_owned(),
        ));
    }
    let body = client.get_absolute(uri, Some(request_token)).await?;
    let parsed: IdTokenResponse = serde_json::from_slice(&body)
        .map_err(|e| ClientError::malformed("OIDC token response", &e))?;
    if parsed.value.trim().is_empty() {
        return Err(ClientError::Malformed(
            "OIDC token response carried an empty `value`".to_owned(),
        ));
    }
    Ok(Secret::from(parsed.value))
}

/// [`fetch_id_token`] with the URL and token read from the environment.
///
/// # Errors
///
/// [`GhaError::NotInJob`] if either variable is absent or empty, else as
/// [`fetch_id_token`].
///
/// # Pinned clients
///
/// As [`fetch_id_token`]: pass an unpinned client, or the fetch fails closed.
pub async fn fetch_id_token_from_env(
    client: &ForgsClient,
    audience: &str,
) -> Result<Secret, GhaError> {
    let read = |name: &'static str| {
        std::env::var(name)
            .ok()
            .filter(|v| !v.is_empty())
            .ok_or(GhaError::NotInJob(name))
    };
    let url = read(ENV_REQUEST_URL)?;
    let token = Secret::from(read(ENV_REQUEST_TOKEN)?);
    Ok(fetch_id_token(client, &url, &token, audience).await?)
}

/// Percent-encode a query value: everything outside RFC 3986's unreserved
/// set is escaped.
fn percent_encode(value: &str) -> String {
    use std::fmt::Write as _;
    value.bytes().fold(String::new(), |mut out, b| {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_query_values() {
        assert_eq!(
            percent_encode("https://forgs.example:8443/x y"),
            "https%3A%2F%2Fforgs.example%3A8443%2Fx%20y"
        );
        assert_eq!(percent_encode("aZ0-._~"), "aZ0-._~");
    }
}
