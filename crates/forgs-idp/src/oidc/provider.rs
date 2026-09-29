//! The generic OIDC [`IdentityProvider`] (features `oidc` + `client`).

use std::time::Duration;

use super::discovery::{parse_discovery, parse_token_response, ProviderMetadata};
use super::jwks::JwksCache;
use super::jwt::verify_id_token;
use super::presets::OidcConfig;
use crate::https;
use crate::identity::{
    pkce_challenge, AuthRequest, ExternalIdentity, IdentityProvider, IdpError, ProviderTokens,
};
use crate::url::{append_query, form_body};

/// A discovered OIDC provider: Codeberg/Forgejo, GitLab, or any compliant
/// issuer.
///
/// Built once with [`OidcProvider::discover`] (one fetch of the discovery
/// document); the JWKS is cached and refreshed per [`JwksCache`]. No
/// userinfo call in v1: identity comes from the verified `id_token` alone.
#[derive(Debug)]
pub struct OidcProvider {
    config: OidcConfig,
    metadata: ProviderMetadata,
    jwks: JwksCache,
}

impl OidcProvider {
    /// Validate `config`, fetch its discovery document and build a provider.
    ///
    /// # Errors
    ///
    /// [`IdpError::Config`] / [`IdpError::Url`] for bad configuration,
    /// transport / HTTP errors fetching the document, [`IdpError::Discovery`]
    /// for an unusable document, or [`IdpError::Config`] when none of the
    /// configured algorithms is advertised.
    pub async fn discover(config: OidcConfig) -> Result<Self, IdpError> {
        config.validate()?;
        let resp = https::get(&config.discovery_url(), None, "application/json").await?;
        if !resp.is_success() {
            return Err(resp.http_error());
        }
        let metadata = parse_discovery(&resp.body, &config.issuer)?;
        Self::from_metadata(config, metadata)
    }

    /// Build a provider from an already-fetched document (tests, or a
    /// deployment that pins the metadata in configuration).
    ///
    /// # Errors
    ///
    /// As [`Self::discover`], minus the fetch.
    pub fn from_metadata(config: OidcConfig, metadata: ProviderMetadata) -> Result<Self, IdpError> {
        config.validate()?;
        if metadata.issuer != config.issuer {
            return Err(IdpError::Discovery("issuer mismatch".to_owned()));
        }
        // An absent list means the spec default, RS256.
        let advertised: Vec<&str> = if metadata.id_token_signing_alg_values_supported.is_empty() {
            vec!["RS256"]
        } else {
            metadata
                .id_token_signing_alg_values_supported
                .iter()
                .map(String::as_str)
                .collect()
        };
        if !config
            .algs
            .algorithms()
            .iter()
            .any(|a| advertised.contains(&format!("{a:?}").as_str()))
        {
            return Err(IdpError::Config(format!(
                "{}: none of the configured algorithms {:?} is advertised ({advertised:?})",
                config.name,
                config.algs.algorithms()
            )));
        }
        let jwks = JwksCache::new(
            metadata.jwks_uri.clone(),
            JwksCache::DEFAULT_REFRESH_AFTER,
            JwksCache::DEFAULT_MIN_REFETCH,
        );
        Ok(Self {
            config,
            metadata,
            jwks,
        })
    }

    /// Replace the JWKS cache timings (tests; operators with unusual issuers).
    #[must_use]
    pub fn with_jwks_timing(mut self, refresh_after: Duration, min_refetch: Duration) -> Self {
        self.jwks = JwksCache::new(self.metadata.jwks_uri.clone(), refresh_after, min_refetch);
        self
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// The discovered metadata.
    #[must_use]
    pub fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
    }
}

#[async_trait::async_trait]
impl IdentityProvider for OidcProvider {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn authorization_url(&self, redirect_uri: &str, req: &AuthRequest) -> Result<String, IdpError> {
        let challenge = pkce_challenge(&req.pkce_verifier);
        Ok(append_query(
            &self.metadata.authorization_endpoint,
            &[
                ("response_type", "code"),
                ("client_id", self.config.client_id.as_str()),
                ("redirect_uri", redirect_uri),
                ("scope", self.config.scopes.as_str()),
                ("state", req.state.as_str()),
                ("nonce", req.nonce.as_str()),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
            ],
        ))
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        pkce_verifier: &str,
    ) -> Result<ProviderTokens, IdpError> {
        let form = form_body(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", pkce_verifier),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ]);
        let resp = https::post_form(&self.metadata.token_endpoint, form).await?;
        // Parse before looking at the status: an OAuth error object (usually
        // with a 400) is more useful than the bare status.
        match (resp.is_success(), parse_token_response(&resp.body)) {
            (_, Err(e @ IdpError::Oauth { .. })) | (true, Err(e)) => Err(e),
            (false, _) => Err(resp.http_error()),
            (true, Ok((access, id))) => Ok(ProviderTokens::new(access, Some(id))),
        }
    }

    async fn fetch_identity(
        &self,
        tokens: ProviderTokens,
        expected_nonce: &str,
        now: u64,
    ) -> Result<ExternalIdentity, IdpError> {
        // The access token is not needed at all (no userinfo call): drop it
        // straight away.
        let (access_token, id_token) = tokens.into_parts();
        drop(access_token);
        let id_token = id_token
            .ok_or_else(|| IdpError::Malformed("token response lacked an `id_token`".to_owned()))?;
        let policy = self.config.id_token_policy();
        let claims = self
            .jwks
            .verify_with(|keys| verify_id_token(&id_token, keys, &policy, expected_nonce, now))
            .await?;
        self.config.identity_from_claims(&claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::presets::forgejo;
    use crate::oidc::OidcError;
    use crate::test_support::{
        jwks_json, sign, Reply, StubServer, KEY_A_DER_B64, KEY_A_N, KEY_B_DER_B64, KEY_B_N,
    };
    use serde_json::json;

    const CLIENT: &str = "forgs-client";
    const ACCESS: &str = "at_SPENDONCE_xyz";

    struct Fixture {
        stub: StubServer,
        idp: OidcProvider,
        req: AuthRequest,
    }

    fn claims(issuer: &str, nonce: &str) -> serde_json::Value {
        json!({
            "iss": issuer, "aud": CLIENT, "sub": "4242",
            "exp": 2_000u64, "iat": 900u64, "nonce": nonce,
            "email": "alice@example.com", "email_verified": true,
            "preferred_username": "alice",
        })
    }

    async fn fixture(min_refetch: Duration) -> Fixture {
        let stub = StubServer::start(vec![]).await;
        let issuer = stub.base();
        stub.set(
            "/.well-known/openid-configuration",
            Reply::json(&json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/login/oauth/authorize"),
                "token_endpoint": format!("{issuer}/login/oauth/access_token"),
                "jwks_uri": format!("{issuer}/login/oauth/keys"),
                "id_token_signing_alg_values_supported": ["RS256"],
            })),
        );
        stub.set(
            "/login/oauth/keys",
            Reply::json(&jwks_json(&[("a", KEY_A_N)])),
        );
        let idp = OidcProvider::discover(forgejo("forgejo-test", issuer, CLIENT, "s3cret"))
            .await
            .unwrap()
            .with_jwks_timing(Duration::from_secs(3600), min_refetch);
        let req = AuthRequest::generate();
        Fixture { stub, idp, req }
    }

    fn serve_token(f: &Fixture, id_token: &str) {
        f.stub.set(
            "/login/oauth/access_token",
            Reply::json(
                &json!({"access_token": ACCESS, "token_type": "bearer", "id_token": id_token}),
            ),
        );
    }

    #[tokio::test]
    async fn happy_path() {
        let f = fixture(Duration::ZERO).await;
        let url = f
            .idp
            .authorization_url("https://forgs.example/cb", &f.req)
            .unwrap();
        let q = crate::test_support::parse_form(url.split_once('?').unwrap().1);
        assert!(url.starts_with(&f.stub.url("/login/oauth/authorize?")));
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], CLIENT);
        assert_eq!(q["scope"], "openid email profile");
        assert_eq!(q["state"], f.req.state);
        assert_eq!(q["nonce"], f.req.nonce);
        assert_eq!(q["code_challenge"], f.req.pkce_challenge());
        assert_eq!(q["code_challenge_method"], "S256");

        serve_token(
            &f,
            &sign("a", KEY_A_DER_B64, &claims(&f.stub.base(), &f.req.nonce)),
        );
        let id = f
            .idp
            .complete("c0de", "https://forgs.example/cb", &f.req, 1_000)
            .await
            .unwrap();
        assert_eq!(id.provider(), "forgejo-test");
        assert_eq!(id.subject(), "4242");
        assert_eq!(id.email(), "alice@example.com");
        assert_eq!(id.suggested_username(), Some("alice"));

        let token_req = f
            .stub
            .requests()
            .into_iter()
            .find(|r| r.path() == "/login/oauth/access_token")
            .unwrap();
        let form = token_req.form();
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "c0de");
        assert_eq!(form["code_verifier"], f.req.pkce_verifier);
        assert_eq!(form["client_secret"], "s3cret");
        // The access token is never presented anywhere (no userinfo call).
        assert!(f
            .stub
            .requests()
            .iter()
            .all(|r| r.header("authorization").is_none()));
    }

    #[tokio::test]
    async fn wrong_nonce_wrong_aud_and_unverified_email_are_refused() {
        let f = fixture(Duration::ZERO).await;
        let base = f.stub.base();

        serve_token(
            &f,
            &sign("a", KEY_A_DER_B64, &claims(&base, "someone-elses")),
        );
        let err = f
            .idp
            .complete("c", "https://x/cb", &f.req, 1_000)
            .await
            .unwrap_err();
        assert!(
            matches!(err, IdpError::IdToken(OidcError::NonceMismatch)),
            "{err:?}"
        );

        let mut c = claims(&base, &f.req.nonce);
        c["aud"] = json!("another-client");
        serve_token(&f, &sign("a", KEY_A_DER_B64, &c));
        let err = f
            .idp
            .complete("c", "https://x/cb", &f.req, 1_000)
            .await
            .unwrap_err();
        assert!(
            matches!(err, IdpError::IdToken(OidcError::WrongAudience)),
            "{err:?}"
        );

        let mut c = claims(&base, &f.req.nonce);
        c["email_verified"] = json!(false);
        serve_token(&f, &sign("a", KEY_A_DER_B64, &c));
        let err = f
            .idp
            .complete("c", "https://x/cb", &f.req, 1_000)
            .await
            .unwrap_err();
        assert!(
            matches!(err, IdpError::NoVerifiedEmail { ref provider } if provider == "forgejo-test")
        );

        let mut c = claims(&base, &f.req.nonce);
        c.as_object_mut().unwrap().remove("email");
        serve_token(&f, &sign("a", KEY_A_DER_B64, &c));
        let err = f
            .idp
            .complete("c", "https://x/cb", &f.req, 1_000)
            .await
            .unwrap_err();
        assert!(matches!(err, IdpError::NoVerifiedEmail { .. }));
        assert!(!format!("{err:?} {err}").contains(ACCESS));
    }

    #[tokio::test]
    async fn key_rotation_is_picked_up_by_one_refetch() {
        let f = fixture(Duration::ZERO).await;
        let base = f.stub.base();
        serve_token(&f, &sign("a", KEY_A_DER_B64, &claims(&base, &f.req.nonce)));
        f.idp
            .complete("c", "https://x/cb", &f.req, 1_000)
            .await
            .unwrap();
        assert_eq!(f.stub.count("/login/oauth/keys"), 1);

        f.stub.set(
            "/login/oauth/keys",
            Reply::json(&jwks_json(&[("a", KEY_A_N), ("b", KEY_B_N)])),
        );
        serve_token(&f, &sign("b", KEY_B_DER_B64, &claims(&base, &f.req.nonce)));
        f.idp
            .complete("c", "https://x/cb", &f.req, 1_000)
            .await
            .unwrap();
        assert_eq!(f.stub.count("/login/oauth/keys"), 2);
    }

    #[tokio::test]
    async fn rotation_refetch_is_rate_limited() {
        let f = fixture(Duration::from_secs(3600)).await;
        serve_token(
            &f,
            &sign("zz", KEY_B_DER_B64, &claims(&f.stub.base(), &f.req.nonce)),
        );
        for _ in 0..3 {
            let err = f
                .idp
                .complete("c", "https://x/cb", &f.req, 1_000)
                .await
                .unwrap_err();
            assert!(
                matches!(err, IdpError::IdToken(OidcError::UnknownKid(_))),
                "{err:?}"
            );
        }
        assert_eq!(f.stub.count("/login/oauth/keys"), 1);
    }

    #[tokio::test]
    async fn token_endpoint_errors() {
        let f = fixture(Duration::ZERO).await;
        f.stub.set(
            "/login/oauth/access_token",
            Reply::status(400, "application/json", r#"{"error":"invalid_grant"}"#),
        );
        let err = f
            .idp
            .exchange_code("c", "https://x/cb", "v")
            .await
            .unwrap_err();
        assert!(matches!(err, IdpError::Oauth { ref code, .. } if code == "invalid_grant"));
        f.stub.set(
            "/login/oauth/access_token",
            Reply::status(502, "text/html", "<h1>bad gateway</h1>"),
        );
        let err = f
            .idp
            .exchange_code("c", "https://x/cb", "v")
            .await
            .unwrap_err();
        assert!(matches!(err, IdpError::Http { status: 502, .. }), "{err:?}");
        f.stub.set(
            "/login/oauth/access_token",
            Reply::json(&json!({"access_token": ACCESS})),
        );
        let err = f
            .idp
            .exchange_code("c", "https://x/cb", "v")
            .await
            .unwrap_err();
        assert!(matches!(err, IdpError::Malformed(_)));
        assert!(!format!("{err:?} {err}").contains(ACCESS));
    }

    #[tokio::test]
    async fn discovery_failures() {
        let stub = StubServer::start(vec![(
            "/.well-known/openid-configuration".into(),
            Reply::json(&json!({
                "issuer": "https://elsewhere.example",
                "authorization_endpoint": "https://elsewhere.example/a",
                "token_endpoint": "https://elsewhere.example/t",
                "jwks_uri": "https://elsewhere.example/k",
            })),
        )])
        .await;
        let err = OidcProvider::discover(forgejo("x", stub.base(), CLIENT, "s"))
            .await
            .unwrap_err();
        assert!(matches!(err, IdpError::Discovery(_)), "{err:?}");

        let issuer = stub.base();
        let md = ProviderMetadata {
            issuer: issuer.clone(),
            authorization_endpoint: format!("{issuer}/a"),
            token_endpoint: format!("{issuer}/t"),
            jwks_uri: format!("{issuer}/k"),
            userinfo_endpoint: None,
            id_token_signing_alg_values_supported: vec!["ES256".into()],
        };
        let err =
            OidcProvider::from_metadata(forgejo("x", issuer.clone(), CLIENT, "s"), md.clone())
                .unwrap_err();
        assert!(matches!(err, IdpError::Config(_)), "{err:?}");
        let md = ProviderMetadata {
            id_token_signing_alg_values_supported: vec![],
            ..md
        };
        assert!(OidcProvider::from_metadata(forgejo("x", issuer, CLIENT, "s"), md).is_ok());

        let err = OidcProvider::discover(forgejo("x", stub.url("/nothing"), CLIENT, "s"))
            .await
            .unwrap_err();
        assert!(matches!(err, IdpError::Http { status: 404, .. }), "{err:?}");
    }
}
