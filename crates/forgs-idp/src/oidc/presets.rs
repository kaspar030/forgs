//! [`OidcConfig`] and the Codeberg/Forgejo and GitLab presets: thin builders
//! over the generic OIDC provider, differing only in issuer and the claim a
//! username suggestion is read from.

use super::jwt::{AlgPolicy, IdTokenClaims, IdTokenPolicy};
use crate::identity::{ExternalIdentity, IdpError};

/// Default scopes: `openid` for the `id_token`, `email` for the `email` /
/// `email_verified` claims, `profile` for the username claim.
pub const DEFAULT_SCOPES: &str = "openid email profile";

/// The Codeberg issuer.
pub const CODEBERG_ISSUER: &str = "https://codeberg.org";
/// The GitLab.com issuer.
pub const GITLAB_COM_ISSUER: &str = "https://gitlab.com";

/// One configured generic-OIDC provider instance.
#[derive(Clone, PartialEq, Eq)]
pub struct OidcConfig {
    /// Configured instance name (`codeberg`, `gitlab-work`). Two instances of
    /// the same software are two providers; their subjects never mix.
    pub name: String,
    /// The issuer, exactly as it writes itself in `iss` (see
    /// [`super::parse_discovery`]).
    pub issuer: String,
    /// Client id; also the expected `aud`.
    pub client_id: String,
    /// Client secret, sent as `client_secret_post`.
    pub client_secret: String,
    /// Space-separated scopes; [`DEFAULT_SCOPES`] unless overridden.
    pub scopes: String,
    /// The `id_token` claim offered as a username suggestion, if any.
    pub username_claim: Option<String>,
    /// Allowed `id_token` signature algorithms.
    pub algs: AlgPolicy,
    /// Clock-skew margin for `exp`/`nbf`/`iat`, seconds; at most
    /// [`MAX_LEEWAY_SECS`](super::MAX_LEEWAY_SECS).
    pub leeway_secs: u64,
}

impl OidcConfig {
    /// A generic configuration with default scopes, `[RS256]`, 60 s leeway
    /// and no username claim.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            issuer: issuer.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scopes: DEFAULT_SCOPES.to_owned(),
            username_claim: None,
            algs: AlgPolicy::rs256(),
            leeway_secs: 60,
        }
    }

    /// Set the username claim.
    #[must_use]
    pub fn with_username_claim(mut self, claim: impl Into<String>) -> Self {
        self.username_claim = Some(claim.into());
        self
    }

    /// Check the configuration.
    ///
    /// # Errors
    ///
    /// [`IdpError::Config`] for an empty field or scopes without `openid`;
    /// [`IdpError::Url`] for an unusable issuer.
    pub fn validate(&self) -> Result<(), IdpError> {
        for (field, value) in [
            ("name", &self.name),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ] {
            if value.trim().is_empty() {
                return Err(IdpError::Config(format!(
                    "{}: `{field}` is empty",
                    self.name
                )));
            }
        }
        if !self.scopes.split(' ').any(|s| s == "openid") {
            return Err(IdpError::Config(format!(
                "{}: scopes must include `openid`",
                self.name
            )));
        }
        if self.leeway_secs > super::jwt::MAX_LEEWAY_SECS {
            return Err(IdpError::Config(format!(
                "{}: `leeway_secs` {} exceeds the maximum {}",
                self.name,
                self.leeway_secs,
                super::jwt::MAX_LEEWAY_SECS
            )));
        }
        crate::url::check_endpoint_url(&self.issuer)
    }

    /// The policy an `id_token` from this provider is verified against.
    #[must_use]
    pub fn id_token_policy(&self) -> IdTokenPolicy {
        IdTokenPolicy {
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            algs: self.algs.clone(),
            leeway_secs: self.leeway_secs,
        }
    }

    /// Map verified `id_token` claims to an [`ExternalIdentity`]: `sub` is
    /// the subject, `email` + `email_verified` the email, and the configured
    /// [`Self::username_claim`] (string claims only) the suggestion.
    ///
    /// # Errors
    ///
    /// [`IdpError::NoVerifiedEmail`] without a verified email.
    pub fn identity_from_claims(
        &self,
        claims: &IdTokenClaims,
    ) -> Result<ExternalIdentity, IdpError> {
        let suggestion = self
            .username_claim
            .as_deref()
            .and_then(|c| claims.string_claim(c))
            .map(str::to_owned);
        ExternalIdentity::verified(
            self.name.clone(),
            claims.sub.clone(),
            claims.email.clone(),
            claims.email_verified,
            suggestion,
        )
    }

    /// `{issuer}/.well-known/openid-configuration` (OIDC Discovery §4: an
    /// issuer's trailing slash is not doubled).
    #[must_use]
    pub fn discovery_url(&self) -> String {
        format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        )
    }
}

impl std::fmt::Debug for OidcConfig {
    /// Redacts the client secret: configuration gets logged on startup.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("name", &self.name)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("scopes", &self.scopes)
            .field("username_claim", &self.username_claim)
            .field("algs", &self.algs)
            .field("leeway_secs", &self.leeway_secs)
            .finish()
    }
}

/// Any Forgejo (or Gitea) instance at `issuer`: username suggestion from
/// `preferred_username`.
#[must_use]
pub fn forgejo(
    name: impl Into<String>,
    issuer: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcConfig {
    OidcConfig::new(name, issuer, client_id, client_secret)
        .with_username_claim("preferred_username")
}

/// Codeberg: [`forgejo`] at [`CODEBERG_ISSUER`].
#[must_use]
pub fn codeberg(
    name: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcConfig {
    forgejo(name, CODEBERG_ISSUER, client_id, client_secret)
}

/// A GitLab instance at `issuer`: username suggestion from `nickname` (the
/// GitLab username).
#[must_use]
pub fn gitlab(
    name: impl Into<String>,
    issuer: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcConfig {
    OidcConfig::new(name, issuer, client_id, client_secret).with_username_claim("nickname")
}

/// GitLab.com: [`gitlab`] at [`GITLAB_COM_ISSUER`].
#[must_use]
pub fn gitlab_com(
    name: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcConfig {
    gitlab(name, GITLAB_COM_ISSUER, client_id, client_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_fill_issuer_and_claim() {
        let cb = codeberg("codeberg", "id", "sec");
        assert_eq!(cb.issuer, "https://codeberg.org");
        assert_eq!(cb.username_claim.as_deref(), Some("preferred_username"));
        assert_eq!(cb.scopes, "openid email profile");
        assert_eq!(cb.algs, AlgPolicy::rs256());
        assert!(cb.validate().is_ok());
        let mut lax = cb.clone();
        lax.leeway_secs = crate::oidc::MAX_LEEWAY_SECS;
        assert!(lax.validate().is_ok());
        lax.leeway_secs += 1;
        assert!(matches!(lax.validate(), Err(IdpError::Config(_))));
        assert_eq!(
            cb.discovery_url(),
            "https://codeberg.org/.well-known/openid-configuration"
        );

        let fj = forgejo("fj-work", "https://git.example.com/", "id", "sec");
        assert_eq!(fj.name, "fj-work");
        assert_eq!(fj.username_claim.as_deref(), Some("preferred_username"));
        assert_eq!(
            fj.discovery_url(),
            "https://git.example.com/.well-known/openid-configuration"
        );

        let gl = gitlab_com("gitlab", "id", "sec");
        assert_eq!(gl.issuer, "https://gitlab.com");
        assert_eq!(gl.username_claim.as_deref(), Some("nickname"));
        let glw = gitlab("gitlab-work", "https://gitlab.example", "id", "sec");
        assert_eq!(glw.issuer, "https://gitlab.example");
        assert_eq!(glw.name, "gitlab-work");
    }

    #[test]
    fn claims_map_to_an_identity() {
        let mut map = serde_json::Map::new();
        map.insert("nickname".into(), serde_json::json!("gl-user"));
        map.insert("preferred_username".into(), serde_json::json!(7));
        let claims = IdTokenClaims {
            sub: "99".into(),
            email: Some("u@example.com".into()),
            email_verified: true,
            claims: map,
        };
        let id = gitlab_com("gitlab", "i", "s")
            .identity_from_claims(&claims)
            .unwrap();
        assert_eq!(id.provider(), "gitlab");
        assert_eq!(id.subject(), "99");
        assert_eq!(id.email(), "u@example.com");
        assert_eq!(id.suggested_username(), Some("gl-user"));
        // Non-string claim → no suggestion.
        let id = codeberg("cb", "i", "s")
            .identity_from_claims(&claims)
            .unwrap();
        assert_eq!(id.suggested_username(), None);
        let unverified = IdTokenClaims {
            email_verified: false,
            ..claims.clone()
        };
        assert!(matches!(
            codeberg("cb", "i", "s").identity_from_claims(&unverified),
            Err(IdpError::NoVerifiedEmail { .. })
        ));
        let no_email = IdTokenClaims {
            email: None,
            ..claims
        };
        assert!(matches!(
            codeberg("cb", "i", "s").identity_from_claims(&no_email),
            Err(IdpError::NoVerifiedEmail { .. })
        ));
        let p = codeberg("cb", "i", "s").id_token_policy();
        assert_eq!(
            (p.issuer.as_str(), p.client_id.as_str()),
            ("https://codeberg.org", "i")
        );
    }

    #[test]
    fn validation_and_redaction() {
        let mut c = codeberg("codeberg", "id", "hunter2");
        assert!(!format!("{c:?}").contains("hunter2"));
        c.scopes = "email profile".to_owned();
        assert!(matches!(c.validate(), Err(IdpError::Config(_))));
        let c = OidcConfig::new("x", "http://idp.example", "id", "s");
        assert!(matches!(c.validate(), Err(IdpError::Url(_))));
        let c = OidcConfig::new("x", "https://idp.example", "id", "");
        assert!(matches!(c.validate(), Err(IdpError::Config(_))));
    }
}
