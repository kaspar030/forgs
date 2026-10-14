//! The HTTPS egress every provider call goes through (feature `client`).
//!
//! `hyper` + `hyper-rustls` with an explicitly built [`rustls::ClientConfig`]
//! over the `webpki-roots` bundle and the `ring` provider. `reqwest` is not
//! used: it pulls ~37 crates nothing else needs, including the `icu_*`
//! unicode stack.
//!
//! No certificate pinning: providers are public Web PKI hosts whose leaves
//! rotate. Every endpoint has passed [`crate::url::check_endpoint_url`] before
//! it gets here (https, or http on loopback only).

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::{ClientConfig, RootCertStore};

use crate::identity::IdpError;

/// How long one request may take, end to end.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest response body read. Discovery documents, JWKS, token responses and
/// `/user` payloads are all a few KiB; the cap stops a hostile endpoint from
/// streaming an unbounded body into memory.
pub(crate) const MAX_BODY: usize = 1024 * 1024;

/// `User-Agent` sent on every request. GitHub's API answers **403** without one.
pub(crate) const USER_AGENT: &str = concat!("forgs/", env!("CARGO_PKG_VERSION"));

/// Install the `ring` crypto provider as rustls's process default, exactly
/// once. Idempotent; an already-installed provider (someone else's) is fine.
pub fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// The client TLS config: webpki roots compiled into the binary (not the
/// platform store, which would differ between a Pi and a laptop and pull a
/// native dependency on musl), no client certificate.
fn tls_config() -> ClientConfig {
    install_crypto_provider();
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

fn client() -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config())
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

/// A response: status plus the (capped) body.
pub(crate) struct Response {
    pub status: u16,
    pub body: Bytes,
}

impl Response {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The non-2xx case as an [`IdpError::Http`].
    pub fn http_error(&self) -> IdpError {
        IdpError::Http {
            status: self.status,
            body: crate::identity::body_text(&self.body),
        }
    }
}

fn parse_uri(url: &str) -> Result<http::Uri, IdpError> {
    url.parse()
        .map_err(|e: http::uri::InvalidUri| IdpError::Url(e.to_string()))
}

async fn send(req: http::Request<Full<Bytes>>) -> Result<Response, IdpError> {
    let resp = tokio::time::timeout(REQUEST_TIMEOUT, client().request(req))
        .await
        .map_err(|_| IdpError::Transport("request timed out".to_owned()))?
        .map_err(|e| IdpError::Transport(e.to_string()))?;
    let status = resp.status().as_u16();
    let body = tokio::time::timeout(
        REQUEST_TIMEOUT,
        Limited::new(resp.into_body(), MAX_BODY).collect(),
    )
    .await
    .map_err(|_| IdpError::Transport("reading the response timed out".to_owned()))?
    .map_err(|e| IdpError::Transport(format!("reading the response: {e}")))?
    .to_bytes();
    Ok(Response { status, body })
}

/// `GET url`, with an optional bearer token.
pub(crate) async fn get(
    url: &str,
    bearer: Option<&str>,
    accept: &str,
) -> Result<Response, IdpError> {
    let mut builder = http::Request::builder()
        .method(http::Method::GET)
        .uri(parse_uri(url)?)
        .header(http::header::ACCEPT, accept)
        .header(http::header::USER_AGENT, USER_AGENT);
    if let Some(bearer) = bearer {
        builder = builder.header(http::header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    let req = builder
        .body(Full::new(Bytes::new()))
        .map_err(|e| IdpError::Transport(e.to_string()))?;
    send(req).await
}

/// `POST url` with a form body, `Accept: application/json`.
///
/// `Accept` is **mandatory** for GitHub: without it the token endpoint answers
/// `application/x-www-form-urlencoded`.
pub(crate) async fn post_form(url: &str, form: String) -> Result<Response, IdpError> {
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(parse_uri(url)?)
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(http::header::ACCEPT, "application/json")
        .header(http::header::USER_AGENT, USER_AGENT)
        .body(Full::new(Bytes::from(form)))
        .map_err(|e| IdpError::Transport(e.to_string()))?;
    send(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Reply, StubServer};

    #[tokio::test]
    async fn oversized_bodies_are_refused() {
        let big = "x".repeat(MAX_BODY + 1);
        let stub = StubServer::start(vec![("/big".into(), Reply::ok("text/plain", big))]).await;
        let Err(err) = get(&stub.url("/big"), None, "*/*").await else {
            panic!("expected an error");
        };
        assert!(matches!(err, IdpError::Transport(_)), "{err:?}");
    }

    #[tokio::test]
    async fn get_sends_ua_accept_and_bearer() {
        let stub =
            StubServer::start(vec![("/x".into(), Reply::ok("application/json", "{}"))]).await;
        let resp = get(&stub.url("/x"), Some("tok"), "application/json")
            .await
            .unwrap();
        assert!(resp.is_success());
        let reqs = stub.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].header("user-agent").unwrap(), USER_AGENT);
        assert_eq!(reqs[0].header("authorization").unwrap(), "Bearer tok");
        assert_eq!(reqs[0].header("accept").unwrap(), "application/json");
    }
}
