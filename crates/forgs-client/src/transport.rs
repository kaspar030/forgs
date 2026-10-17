//! The one place requests are sent: connector, timeout, body cap and error
//! mapping.

use std::time::Duration;

use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Bytes;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::error::ClientError;
use crate::secret::Secret;

/// Default end-to-end budget for one request.
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest response body read. Every `/auth/*` response is well under a KiB
/// (a key listing a few KiB); the cap stops a hostile endpoint streaming an
/// unbounded body into memory.
pub(crate) const MAX_BODY: usize = 1024 * 1024;

/// `User-Agent` on every request.
pub(crate) const USER_AGENT: &str = concat!("forgs-client/", env!("CARGO_PKG_VERSION"));

pub(crate) type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Build the pooled client over [`crate::tls::client_trust_config`].
///
/// A pinned client is `https`-only: a pin that a plain `http://` request
/// would silently skip is no pin at all.
pub(crate) fn build(pin: Option<[u8; 32]>) -> HttpClient {
    let builder = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(crate::tls::client_trust_config(pin));
    let builder = if pin.is_some() {
        builder.https_only()
    } else {
        builder.https_or_http()
    };
    let https = builder.enable_http1().build();
    Client::builder(TokioExecutor::new()).build(https)
}

/// Send `req`, returning the success body or mapping a non-2xx to
/// [`ClientError::Rejected`].
pub(crate) async fn send(
    http: &HttpClient,
    timeout: Duration,
    method: http::Method,
    uri: http::Uri,
    bearer: Option<&Secret>,
    json_body: Option<Vec<u8>>,
) -> Result<Bytes, ClientError> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::ACCEPT, "application/json")
        .header(http::header::USER_AGENT, USER_AGENT);
    if json_body.is_some() {
        builder = builder.header(http::header::CONTENT_TYPE, "application/json");
    }
    if let Some(bearer) = bearer {
        let mut value = http::HeaderValue::from_str(&format!("Bearer {}", bearer.expose()))
            // The error text would not name the value, but say why plainly.
            .map_err(|_| ClientError::Url("credential is not a valid header value".to_owned()))?;
        value.set_sensitive(true);
        builder = builder.header(http::header::AUTHORIZATION, value);
    }
    let req = builder
        .body(Full::new(Bytes::from(json_body.unwrap_or_default())))
        .map_err(|e| ClientError::Transport(e.to_string()))?;

    // One deadline for the whole exchange, headers and body alike.
    let exchange = async {
        let resp = http
            .request(req)
            .await
            .map_err(|e| ClientError::Transport(describe_hyper(&e)))?;
        let status = resp.status();
        let body = Limited::new(resp.into_body(), MAX_BODY)
            .collect()
            .await
            .map_err(|e| ClientError::Transport(format!("reading the response: {e}")))?
            .to_bytes();
        Ok::<_, ClientError>((status, body))
    };
    let (status, body) = tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| ClientError::Transport("request timed out".to_owned()))??;

    if !status.is_success() {
        let code = serde_json::from_slice::<forgs::api::ErrorResponse>(&body)
            .ok()
            .map(|e| e.error)
            .filter(|c| sane_code(c))
            .unwrap_or_else(|| "unknown".to_owned());
        return Err(ClientError::Rejected {
            status: status.as_u16(),
            code,
        });
    }
    Ok(body)
}

/// Whether a server-supplied error code is safe to carry and print:
/// `[a-z0-9_]{1,64}`. Anything else (terminal escapes, prose) becomes
/// `unknown`.
pub(crate) fn sane_code(code: &str) -> bool {
    (1..=64).contains(&code.len())
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// hyper-util's top-level error says only "client error (Connect)"; the cause
/// chain holds the useful part (connection refused, certificate mismatch).
fn describe_hyper(e: &hyper_util::client::legacy::Error) -> String {
    let mut out = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_sanitised() {
        for ok in ["invalid_grant", "x", "a1_b2", &"a".repeat(64)] {
            assert!(sane_code(ok), "{ok}");
        }
        for bad in [
            "",
            "Invalid",
            "a-b",
            "a b",
            "\u{1b}[31mx",
            "é",
            &"a".repeat(65),
        ] {
            assert!(!sane_code(bad), "{bad:?}");
        }
    }
}
