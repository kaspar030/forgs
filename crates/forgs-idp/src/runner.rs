//! Runner-side helper: fetch a **GitHub Actions workload identity token**
//! from the runner's own token service (feature `client`).
//!
//! `url` and `request_token` come from `ACTIONS_ID_TOKEN_REQUEST_URL` /
//! `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, which the runner injects **only** for a
//! job carrying `permissions: id-token: write`. Both are per-job credentials;
//! nothing is stored and nothing outlives the job. Needs only `client`, so a
//! runner or Pi build does not pull the JWT/RSA stack.

use serde::Deserialize;

use crate::https;
use crate::identity::IdpError;
use crate::url::append_query;

/// Environment variable holding the token-service URL.
pub const ENV_REQUEST_URL: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
/// Environment variable holding the token-service bearer token.
pub const ENV_REQUEST_TOKEN: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

/// Fetch an id token for `audience` from the runner's token service.
///
/// # Errors
///
/// [`IdpError::Url`] for an empty `audience` or one with `&`/`#` (refused
/// rather than escaped: a forgs URL containing them is a configuration
/// mistake); transport / HTTP errors (the usual cause of a 4xx being a job
/// without `id-token: write`); [`IdpError::Malformed`] for a body with no
/// non-empty `value`.
pub async fn fetch_gha_id_token(
    url: &str,
    request_token: &str,
    audience: &str,
) -> Result<String, IdpError> {
    #[derive(Deserialize)]
    struct IdTokenResponse {
        value: String,
    }

    if audience.trim().is_empty() || audience.contains(['&', '#']) {
        return Err(IdpError::Url(
            "audience must be non-empty and free of `&` and `#`".to_owned(),
        ));
    }
    crate::url::check_endpoint_url(url)?;
    let full = append_query(url, &[("audience", audience)]);
    let resp = https::get(&full, Some(request_token), "application/json").await?;
    if !resp.is_success() {
        return Err(resp.http_error());
    }
    let parsed: IdTokenResponse = serde_json::from_slice(&resp.body)
        .map_err(|e| IdpError::Malformed(format!("OIDC token response: {e}")))?;
    if parsed.value.trim().is_empty() {
        return Err(IdpError::Malformed(
            "OIDC token response carried an empty `value`".to_owned(),
        ));
    }
    Ok(parsed.value)
}

/// [`fetch_gha_id_token`] with the URL and token read from the environment.
///
/// # Errors
///
/// [`IdpError::Config`] when either variable is absent (the job lacks
/// `permissions: id-token: write`, or this is not a GitHub Actions job), else
/// as [`fetch_gha_id_token`].
pub async fn fetch_gha_id_token_from_env(audience: &str) -> Result<String, IdpError> {
    let read = |name: &str| {
        std::env::var(name)
            .ok()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                IdpError::Config(format!(
                    "`{name}` is not set: not a GitHub Actions job, or the job lacks \
                     `permissions: id-token: write`"
                ))
            })
    };
    let url = read(ENV_REQUEST_URL)?;
    let token = read(ENV_REQUEST_TOKEN)?;
    fetch_gha_id_token(&url, &token, audience).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Reply, StubServer};
    use serde_json::json;

    #[tokio::test]
    async fn fetches_with_audience_and_bearer() {
        let stub = StubServer::start(vec![(
            "/idtoken".into(),
            Reply::json(&json!({"count": 1, "value": "eyJ.x.y"})),
        )])
        .await;
        let url = format!("{}?api-version=2.0", stub.url("/idtoken"));
        let jwt = fetch_gha_id_token(&url, "req-tok", "https://forgs.example")
            .await
            .unwrap();
        assert_eq!(jwt, "eyJ.x.y");
        let reqs = stub.requests();
        assert_eq!(reqs[0].header("authorization"), Some("Bearer req-tok"));
        let q = reqs[0].query();
        assert_eq!(q["audience"], "https://forgs.example");
        assert_eq!(q["api-version"], "2.0");
    }

    #[tokio::test]
    async fn refuses_bad_audiences_and_bodies() {
        let stub = StubServer::start(vec![("/t".into(), Reply::json(&json!({"value": ""})))]).await;
        for aud in ["", "  ", "a&b", "a#b"] {
            assert!(matches!(
                fetch_gha_id_token(&stub.url("/t"), "t", aud).await,
                Err(IdpError::Url(_))
            ));
        }
        assert!(matches!(
            fetch_gha_id_token(&stub.url("/t"), "t", "aud").await,
            Err(IdpError::Malformed(_))
        ));
        stub.set("/t", Reply::status(403, "application/json", "{}"));
        assert!(matches!(
            fetch_gha_id_token(&stub.url("/t"), "t", "aud").await,
            Err(IdpError::Http { status: 403, .. })
        ));
        assert!(matches!(
            fetch_gha_id_token("http://evil.example/t", "t", "aud").await,
            Err(IdpError::Url(_))
        ));
    }
}
