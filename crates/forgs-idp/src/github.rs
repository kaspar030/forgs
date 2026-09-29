//! GitHub login: the OAuth 2.0 **authorization-code** flow, then `GET /user`
//! and `GET /user/emails`.
//!
//! # Why this is not an OIDC client
//!
//! GitHub's user-facing login is plain OAuth 2.0 authorization, not `OpenID`
//! Connect: there is no `.well-known/openid-configuration`, no ID token, no
//! JWKS, and therefore nothing to verify a signature against. The token
//! endpoint hands back an *access token* and nothing else; the only way to
//! learn *who* authorised it is to spend it on `GET /user`. (GitHub Actions
//! workload tokens *are* OIDC; see [`crate::workload`].)
//!
//! # Identity
//!
//! The subject is the **numeric account id**, never the login: logins can be
//! renamed, and a freed login can be re-registered by someone else. The login
//! is offered only as a username *suggestion*. The email is the address that
//! is **both primary and verified** in `GET /user/emails` (scope
//! `user:email`); the public profile email is ignored — it is optional,
//! unverified, and user-editable. A verified but non-primary address is not
//! picked either: the primary is the one the user has chosen to be reached at,
//! and "some verified address" would let a stale secondary decide the account.
//! No primary-and-verified address → login refused
//! ([`IdpError::NoVerifiedEmail`]).
//!
//! # PKCE is not what protects the callback
//!
//! **GitHub does not implement PKCE** for OAuth Apps: it ignores
//! `code_challenge` and `code_verifier`. They are sent anyway (free, and
//! correct for GHES or a stricter endpoint later), but what actually protects
//! the callback is (a) the `state` value bound to an `HttpOnly` cookie, and
//! (b) the **client secret**, which makes an intercepted code unspendable.
//! That is why [`GithubConfig::client_secret`] is required, not optional.
//!
//! # Token handling
//!
//! The access token is a credential for the user's GitHub account, not for
//! forgs. It is spent on the two identity calls and dropped; never stored,
//! never logged. Apps that need a long-lived GitHub credential manage it
//! themselves (design §4).

use serde::Deserialize;

use crate::identity::{ExternalIdentity, IdpError};
use crate::url::append_query;

/// The default space-separated scope: profile (for the id and login) plus
/// `user:email` (for `GET /user/emails`).
pub const DEFAULT_SCOPE: &str = "read:user user:email";

/// The GitHub URLs the login flow touches.
///
/// Overridable as a unit for GitHub Enterprise Server or a loopback stub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubEndpoints {
    /// Browser-facing authorize endpoint.
    pub authorize_url: String,
    /// `POST` target that exchanges a code for an access token.
    pub access_token_url: String,
    /// REST API origin without a trailing slash; `/user` is appended.
    pub api_base: String,
}

impl Default for GithubEndpoints {
    /// github.com. Note the split origins: the OAuth endpoints live on
    /// `github.com`, the REST API on `api.github.com`.
    fn default() -> Self {
        Self {
            authorize_url: "https://github.com/login/oauth/authorize".to_owned(),
            access_token_url: "https://github.com/login/oauth/access_token".to_owned(),
            api_base: "https://api.github.com".to_owned(),
        }
    }
}

impl GithubEndpoints {
    /// Endpoints of a GitHub Enterprise Server at `origin`
    /// (`https://ghes.example`): OAuth on the origin, the API under `/api/v3`.
    #[must_use]
    pub fn enterprise(origin: &str) -> Self {
        let origin = origin.trim_end_matches('/');
        Self {
            authorize_url: format!("{origin}/login/oauth/authorize"),
            access_token_url: format!("{origin}/login/oauth/access_token"),
            api_base: format!("{origin}/api/v3"),
        }
    }
}

/// One configured GitHub provider instance.
#[derive(Clone)]
pub struct GithubConfig {
    /// Configured instance name (`github`, `ghes-work`).
    pub name: String,
    /// The OAuth App client id. Public.
    pub client_id: String,
    /// The client secret. **Required**: GitHub refuses a code exchange without
    /// it, and since it ignores PKCE the secret is the only thing stopping
    /// someone else from spending an intercepted code.
    pub client_secret: String,
    /// Space-separated scopes; [`DEFAULT_SCOPE`] unless overridden.
    pub scope: String,
    /// Where to send the requests.
    pub endpoints: GithubEndpoints,
}

impl GithubConfig {
    /// A github.com configuration named `github` with the default scope.
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            name: "github".to_owned(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scope: DEFAULT_SCOPE.to_owned(),
            endpoints: GithubEndpoints::default(),
        }
    }

    /// Check the configuration: non-empty name, id and secret; every endpoint
    /// passes [`crate::url::check_endpoint_url`].
    ///
    /// # Errors
    ///
    /// [`IdpError::Config`] or [`IdpError::Url`].
    pub fn validate(&self) -> Result<(), IdpError> {
        for (field, value) in [
            ("name", &self.name),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ] {
            if value.trim().is_empty() {
                return Err(IdpError::Config(format!("github: `{field}` is empty")));
            }
        }
        for url in [
            &self.endpoints.authorize_url,
            &self.endpoints.access_token_url,
            &self.endpoints.api_base,
        ] {
            crate::url::check_endpoint_url(url)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for GithubConfig {
    /// Redacts the client secret: configuration gets logged on startup.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubConfig")
            .field("name", &self.name)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("scope", &self.scope)
            .field("endpoints", &self.endpoints)
            .finish()
    }
}

/// The subset of `/user` that identifies a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubUser {
    /// The immutable numeric account id — the identity key.
    pub id: u64,
    /// The current login. A username suggestion only; may change.
    pub login: String,
}

/// One entry of `GET /user/emails`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GithubEmail {
    /// The address.
    pub email: String,
    /// Whether it is the account's primary address.
    #[serde(default)]
    pub primary: bool,
    /// Whether GitHub has verified it.
    #[serde(default)]
    pub verified: bool,
}

/// Build the browser redirect URL.
///
/// `allow_signup=false`: forgs' login page is not a GitHub signup funnel. No
/// `nonce`: GitHub is not OIDC.
#[must_use]
pub fn authorization_url(
    config: &GithubConfig,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> String {
    let mut pairs = vec![
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("state", state),
    ];
    if !config.scope.is_empty() {
        pairs.push(("scope", config.scope.as_str()));
    }
    pairs.push(("code_challenge", code_challenge));
    pairs.push(("code_challenge_method", "S256"));
    pairs.push(("allow_signup", "false"));
    append_query(&config.endpoints.authorize_url, &pairs)
}

#[derive(Deserialize)]
struct TokenBody {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Parse the token endpoint's response to a code exchange.
///
/// GitHub answers a failed exchange with **HTTP 200** and an `error` field, so
/// the error branch is checked first.
///
/// # Errors
///
/// [`IdpError::Oauth`] for an error object, [`IdpError::Malformed`] for
/// non-JSON, neither field, or an empty token.
pub fn parse_access_token_response(body: &[u8]) -> Result<String, IdpError> {
    let parsed: TokenBody =
        serde_json::from_slice(body).map_err(|e| IdpError::Malformed(e.to_string()))?;
    if let Some(code) = parsed.error {
        return Err(IdpError::Oauth {
            code,
            description: parsed.error_description,
        });
    }
    match parsed.access_token {
        Some(t) if !t.is_empty() => Ok(t),
        Some(_) => Err(IdpError::Malformed(
            "response carried an empty `access_token`".to_owned(),
        )),
        None => Err(IdpError::Malformed(
            "response has neither `access_token` nor `error`".to_owned(),
        )),
    }
}

#[derive(Deserialize)]
struct UserBody {
    /// A JSON **number**: a string id is a parse error, not a different
    /// identity.
    id: u64,
    login: String,
}

/// Parse `GET /user`.
///
/// # Errors
///
/// [`IdpError::Malformed`] unless the body has a numeric `id` and a string
/// `login`.
pub fn parse_user_response(body: &[u8]) -> Result<GithubUser, IdpError> {
    let parsed: UserBody =
        serde_json::from_slice(body).map_err(|e| IdpError::Malformed(e.to_string()))?;
    Ok(GithubUser {
        id: parsed.id,
        login: parsed.login,
    })
}

/// Parse `GET /user/emails`.
///
/// # Errors
///
/// [`IdpError::Malformed`] unless the body is a JSON array of email objects.
pub fn parse_emails_response(body: &[u8]) -> Result<Vec<GithubEmail>, IdpError> {
    serde_json::from_slice(body).map_err(|e| IdpError::Malformed(e.to_string()))
}

/// The address that is **both primary and verified**, if any. A verified
/// non-primary address is deliberately not picked (module docs).
#[must_use]
pub fn pick_primary_verified(emails: &[GithubEmail]) -> Option<&str> {
    emails
        .iter()
        .find(|e| e.primary && e.verified)
        .map(|e| e.email.as_str())
}

/// Map a GitHub user and email list to an [`ExternalIdentity`].
///
/// # Errors
///
/// [`IdpError::NoVerifiedEmail`] when no address is primary and verified.
pub fn github_identity(
    provider: &str,
    user: &GithubUser,
    emails: &[GithubEmail],
) -> Result<ExternalIdentity, IdpError> {
    ExternalIdentity::verified(
        provider,
        user.id.to_string(),
        pick_primary_verified(emails).map(str::to_owned),
        pick_primary_verified(emails).is_some(),
        Some(user.login.clone()),
    )
}

#[cfg(feature = "client")]
pub use provider::GithubProvider;

#[cfg(feature = "client")]
mod provider {
    use super::{
        authorization_url, github_identity, parse_access_token_response, parse_emails_response,
        parse_user_response, GithubConfig,
    };
    use crate::https;
    use crate::identity::{
        pkce_challenge, AuthRequest, ExternalIdentity, IdentityProvider, IdpError, ProviderTokens,
    };
    use crate::url::form_body;

    const API_ACCEPT: &str = "application/vnd.github+json";

    /// A GitHub [`IdentityProvider`].
    #[derive(Debug, Clone)]
    pub struct GithubProvider {
        config: GithubConfig,
    }

    impl GithubProvider {
        /// Build a provider, validating the configuration.
        ///
        /// # Errors
        ///
        /// As [`GithubConfig::validate`].
        pub fn new(config: GithubConfig) -> Result<Self, IdpError> {
            config.validate()?;
            Ok(Self { config })
        }

        /// The configuration.
        #[must_use]
        pub fn config(&self) -> &GithubConfig {
            &self.config
        }

        fn api(&self, path: &str) -> String {
            format!(
                "{}{path}",
                self.config.endpoints.api_base.trim_end_matches('/')
            )
        }
    }

    #[async_trait::async_trait]
    impl IdentityProvider for GithubProvider {
        fn name(&self) -> &str {
            &self.config.name
        }

        fn authorization_url(
            &self,
            redirect_uri: &str,
            req: &AuthRequest,
        ) -> Result<String, IdpError> {
            Ok(authorization_url(
                &self.config,
                redirect_uri,
                &req.state,
                &pkce_challenge(&req.pkce_verifier),
            ))
        }

        async fn exchange_code(
            &self,
            code: &str,
            redirect_uri: &str,
            pkce_verifier: &str,
        ) -> Result<ProviderTokens, IdpError> {
            let form = form_body(&[
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", pkce_verifier),
            ]);
            let resp = https::post_form(&self.config.endpoints.access_token_url, form).await?;
            if !resp.is_success() {
                return Err(resp.http_error());
            }
            let access_token = parse_access_token_response(&resp.body)?;
            Ok(ProviderTokens::new(access_token, None))
        }

        async fn fetch_identity(
            &self,
            tokens: ProviderTokens,
            _expected_nonce: &str,
            _now: u64,
        ) -> Result<ExternalIdentity, IdpError> {
            let (access_token, _) = tokens.into_parts();
            let user = https::get(&self.api("/user"), Some(&access_token), API_ACCEPT).await?;
            if !user.is_success() {
                return Err(user.http_error());
            }
            let emails =
                https::get(&self.api("/user/emails"), Some(&access_token), API_ACCEPT).await?;
            drop(access_token);
            if !emails.is_success() {
                return Err(emails.http_error());
            }
            let user = parse_user_response(&user.body)?;
            let emails = parse_emails_response(&emails.body)?;
            github_identity(&self.config.name, &user, &emails)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> GithubConfig {
        GithubConfig {
            scope: String::new(),
            ..GithubConfig::new("Iv1.abc", "s3cret")
        }
    }

    #[test]
    fn authorization_url_is_built_from_the_configured_endpoint() {
        let url = authorization_url(
            &cfg(),
            "https://forgs.example/auth/github/callback",
            "st4te",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        );
        assert_eq!(
            url,
            "https://github.com/login/oauth/authorize\
             ?client_id=Iv1.abc\
             &redirect_uri=https%3A%2F%2Fforgs.example%2Fauth%2Fgithub%2Fcallback\
             &state=st4te\
             &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
             &code_challenge_method=S256\
             &allow_signup=false"
        );
        assert!(!url.contains("scope"));
        assert!(!url.contains("nonce"));
    }

    #[test]
    fn default_scope_is_carried_and_opaque_values_escaped() {
        let c = GithubConfig::new("Iv1.abc", "s");
        let url = authorization_url(&c, "https://forgs.example/cb", "a&b=c", "chal");
        assert!(url.contains("&scope=read%3Auser%20user%3Aemail&"), "{url}");
        assert!(url.contains("&state=a%26b%3Dc&"), "{url}");
    }

    #[test]
    fn authorization_url_appends_to_an_existing_query() {
        let c = GithubConfig {
            endpoints: GithubEndpoints {
                authorize_url: "https://ghes.example/login/oauth/authorize?tenant=eng".to_owned(),
                ..GithubEndpoints::default()
            },
            ..cfg()
        };
        let url = authorization_url(&c, "https://forgs.example/cb", "s", "c");
        assert!(url.starts_with("https://ghes.example/login/oauth/authorize?tenant=eng&client_id="));
    }

    #[test]
    fn enterprise_endpoints() {
        let e = GithubEndpoints::enterprise("https://ghes.example/");
        assert_eq!(e.api_base, "https://ghes.example/api/v3");
        assert_eq!(
            e.authorize_url,
            "https://ghes.example/login/oauth/authorize"
        );
    }

    #[test]
    fn config_validation_and_redaction() {
        assert!(GithubConfig::new("id", "secret").validate().is_ok());
        assert!(matches!(
            GithubConfig::new("id", " ").validate(),
            Err(IdpError::Config(_))
        ));
        let mut c = GithubConfig::new("id", "secret");
        c.endpoints.api_base = "http://api.example".to_owned();
        assert!(matches!(c.validate(), Err(IdpError::Url(_))));
        let dbg = format!("{:?}", GithubConfig::new("id", "hunter2"));
        assert!(!dbg.contains("hunter2"), "{dbg}");
    }

    #[test]
    fn access_token_responses() {
        assert_eq!(
            parse_access_token_response(
                br#"{"access_token":"gho_16C7e42F292c6912E7710c838347Ae178B4a","token_type":"bearer","scope":""}"#
            )
            .unwrap(),
            "gho_16C7e42F292c6912E7710c838347Ae178B4a"
        );
        match parse_access_token_response(
            br#"{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired."}"#,
        )
        .unwrap_err()
        {
            IdpError::Oauth { code, description } => {
                assert_eq!(code, "bad_verification_code");
                assert_eq!(
                    description.as_deref(),
                    Some("The code passed is incorrect or expired.")
                );
            }
            other => panic!("{other:?}"),
        }
        for bad in [
            &br#"{"token_type":"bearer"}"#[..],
            br#"{"access_token":""}"#,
            b"nope",
        ] {
            assert!(matches!(
                parse_access_token_response(bad),
                Err(IdpError::Malformed(_))
            ));
        }
    }

    #[test]
    fn user_response_parses_numeric_id_only() {
        let user = parse_user_response(
            br#"{"login":"octocat","id":583231,"node_id":"MDQ6VXNlcjU4MzIzMQ==","email":"x@y","type":"User"}"#,
        )
        .unwrap();
        assert_eq!(
            user,
            GithubUser {
                id: 583_231,
                login: "octocat".to_owned()
            }
        );
        assert!(matches!(
            parse_user_response(br#"{"login":"octocat","id":"583231"}"#),
            Err(IdpError::Malformed(_))
        ));
    }

    fn emails(list: &[(&str, bool, bool)]) -> Vec<GithubEmail> {
        list.iter()
            .map(|(e, p, v)| GithubEmail {
                email: (*e).to_owned(),
                primary: *p,
                verified: *v,
            })
            .collect()
    }

    #[test]
    fn emails_parse_from_the_captured_shape() {
        let body = br#"[
            {"email":"octocat@github.com","verified":true,"primary":true,"visibility":"public"},
            {"email":"583231+octocat@users.noreply.github.com","verified":true,"primary":false,"visibility":null}
        ]"#;
        let list = parse_emails_response(body).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(pick_primary_verified(&list), Some("octocat@github.com"));
        assert!(matches!(
            parse_emails_response(b"{}"),
            Err(IdpError::Malformed(_))
        ));
    }

    #[test]
    fn only_a_primary_and_verified_email_is_picked() {
        let user = GithubUser {
            id: 42,
            login: "Octo".to_owned(),
        };
        for (list, expect) in [
            (emails(&[("a@x", true, true)]), Some("a@x")),
            (
                emails(&[("b@x", false, true), ("a@x", true, true)]),
                Some("a@x"),
            ),
            (emails(&[]), None),
            (emails(&[("a@x", false, false)]), None),
            (emails(&[("a@x", true, false)]), None),
            // A verified secondary does not stand in for an unverified primary.
            (emails(&[("a@x", true, false), ("b@x", false, true)]), None),
            (emails(&[("b@x", false, true)]), None),
        ] {
            assert_eq!(pick_primary_verified(&list), expect, "{list:?}");
            match (github_identity("github", &user, &list), expect) {
                (Ok(id), Some(e)) => {
                    assert_eq!(id.email(), e);
                    assert_eq!(id.subject(), "42");
                    assert_eq!(id.provider(), "github");
                    assert_eq!(id.suggested_username(), Some("Octo"));
                }
                (Err(IdpError::NoVerifiedEmail { provider }), None) => {
                    assert_eq!(provider, "github");
                }
                (other, _) => panic!("{list:?}: {other:?}"),
            }
        }
    }

    #[cfg(feature = "client")]
    mod flow {
        use super::super::*;
        use crate::identity::{AuthRequest, IdentityProvider};
        use crate::test_support::{Reply, StubServer};
        use serde_json::json;

        const TOKEN: &str = "gho_SPENDONCE_abcdef";

        async fn stub(emails: serde_json::Value) -> (StubServer, GithubProvider) {
            let stub = StubServer::start(vec![
                (
                    "/login/oauth/access_token".into(),
                    Reply::json(&json!({"access_token": TOKEN, "token_type": "bearer"})),
                ),
                (
                    "/api/v3/user".into(),
                    Reply::json(&json!({"id": 583_231, "login": "octocat"})),
                ),
                ("/api/v3/user/emails".into(), Reply::json(&emails)),
            ])
            .await;
            let config = GithubConfig {
                endpoints: GithubEndpoints::enterprise(&stub.base()),
                ..GithubConfig::new("Iv1.abc", "s3cret")
            };
            (stub, GithubProvider::new(config).unwrap())
        }

        #[tokio::test]
        async fn full_login_against_a_stub() {
            let (stub, gh) =
                stub(json!([{"email": "octo@example.com", "primary": true, "verified": true}]))
                    .await;
            let req = AuthRequest::generate();
            let url = gh
                .authorization_url("https://forgs.example/cb", &req)
                .unwrap();
            assert!(url.starts_with(&stub.url("/login/oauth/authorize?")));

            let id = gh
                .complete("the-code", "https://forgs.example/cb", &req, 1_000)
                .await
                .unwrap();
            assert_eq!(id.provider(), "github");
            assert_eq!(id.subject(), "583231");
            assert_eq!(id.email(), "octo@example.com");
            assert_eq!(id.suggested_username(), Some("octocat"));
            assert!(!format!("{id:?}").contains(TOKEN));

            let reqs = stub.requests();
            assert_eq!(reqs.len(), 3);
            let token_req = &reqs[0];
            assert_eq!(token_req.method, "POST");
            assert_eq!(token_req.header("accept"), Some("application/json"));
            let form = token_req.form();
            assert_eq!(form["client_id"], "Iv1.abc");
            assert_eq!(form["client_secret"], "s3cret");
            assert_eq!(form["code"], "the-code");
            assert_eq!(form["redirect_uri"], "https://forgs.example/cb");
            assert_eq!(form["code_verifier"], req.pkce_verifier);
            for r in &reqs[1..] {
                assert_eq!(r.method, "GET");
                assert_eq!(
                    r.header("authorization"),
                    Some(format!("Bearer {TOKEN}").as_str())
                );
                assert_eq!(r.header("accept"), Some("application/vnd.github+json"));
            }
            assert_eq!(reqs[1].path(), "/api/v3/user");
            assert_eq!(reqs[2].path(), "/api/v3/user/emails");
            for r in &reqs {
                assert!(r.header("user-agent").unwrap().starts_with("forgs/"));
            }
        }

        #[tokio::test]
        async fn no_verified_primary_email_refuses_login() {
            let (_stub, gh) =
                stub(json!([{"email": "octo@example.com", "primary": true, "verified": false}]))
                    .await;
            let req = AuthRequest::generate();
            let err = gh
                .complete("c", "https://forgs.example/cb", &req, 0)
                .await
                .unwrap_err();
            assert!(matches!(err, IdpError::NoVerifiedEmail { .. }), "{err:?}");
            assert!(!err.to_string().contains(TOKEN));
        }

        #[tokio::test]
        async fn oauth_errors_in_a_200_and_http_errors_surface() {
            let (stub, gh) = stub(json!([])).await;
            stub.set(
                "/login/oauth/access_token",
                Reply::json(&json!({"error": "bad_verification_code"})),
            );
            let err = gh
                .exchange_code("c", "https://x/cb", "v")
                .await
                .unwrap_err();
            assert!(
                matches!(err, IdpError::Oauth { ref code, .. } if code == "bad_verification_code")
            );

            stub.set(
                "/api/v3/user",
                Reply::status(401, "application/json", r#"{"message":"Bad credentials"}"#),
            );
            let err = gh
                .fetch_identity(ProviderTokens::new(TOKEN.to_owned(), None), "", 0)
                .await
                .unwrap_err();
            assert!(matches!(err, IdpError::Http { status: 401, .. }), "{err:?}");
            assert!(!format!("{err:?} {err}").contains(TOKEN));
        }

        use crate::identity::ProviderTokens;
    }
}
