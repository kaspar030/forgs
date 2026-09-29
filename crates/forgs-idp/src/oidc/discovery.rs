//! OIDC Discovery (pure parsing).

use serde::Deserialize;

use crate::identity::IdpError;
use crate::url::check_endpoint_url;

/// The parts of a discovery document forgs uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMetadata {
    /// The issuer, byte-identical to the configured one.
    pub issuer: String,
    /// Browser-facing authorize endpoint.
    pub authorization_endpoint: String,
    /// Code-exchange endpoint.
    pub token_endpoint: String,
    /// JWKS endpoint.
    pub jwks_uri: String,
    /// Userinfo endpoint, if advertised. Unused in v1: the presets carry the
    /// email claims in the `id_token` when the `email` scope is requested. A
    /// userinfo fallback for issuers that do not is a follow-up.
    pub userinfo_endpoint: Option<String>,
    /// Advertised `id_token` signing algorithms, as strings.
    pub id_token_signing_alg_values_supported: Vec<String>,
}

#[derive(Deserialize)]
struct Raw {
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    jwks_uri: Option<String>,
    userinfo_endpoint: Option<String>,
    #[serde(default)]
    id_token_signing_alg_values_supported: Vec<String>,
}

/// Parse `/.well-known/openid-configuration`.
///
/// `issuer` must equal `expected_issuer` **exactly** (OIDC Discovery §4.3),
/// including any trailing slash: the configured value must be written the way
/// the issuer writes it, because the same string is later matched against
/// every `id_token`'s `iss`. Every endpoint must pass [`check_endpoint_url`],
/// so a document cannot downgrade the token exchange to cleartext.
///
/// # Errors
///
/// [`IdpError::Discovery`] for a malformed document, a missing field or an
/// issuer mismatch; [`IdpError::Url`] for an unusable endpoint.
pub fn parse_discovery(bytes: &[u8], expected_issuer: &str) -> Result<ProviderMetadata, IdpError> {
    let raw: Raw = serde_json::from_slice(bytes).map_err(|e| IdpError::Discovery(e.to_string()))?;
    let missing = |f: &str| IdpError::Discovery(format!("document lacks `{f}`"));
    let issuer = raw.issuer.ok_or_else(|| missing("issuer"))?;
    if issuer != expected_issuer {
        return Err(IdpError::Discovery(format!(
            "issuer `{issuer}` does not match the configured `{expected_issuer}`"
        )));
    }
    let authorization_endpoint = raw
        .authorization_endpoint
        .ok_or_else(|| missing("authorization_endpoint"))?;
    let token_endpoint = raw
        .token_endpoint
        .ok_or_else(|| missing("token_endpoint"))?;
    let jwks_uri = raw.jwks_uri.ok_or_else(|| missing("jwks_uri"))?;
    for url in [&authorization_endpoint, &token_endpoint, &jwks_uri] {
        check_endpoint_url(url)?;
    }
    if let Some(u) = &raw.userinfo_endpoint {
        check_endpoint_url(u)?;
    }
    Ok(ProviderMetadata {
        issuer,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        userinfo_endpoint: raw.userinfo_endpoint,
        id_token_signing_alg_values_supported: raw.id_token_signing_alg_values_supported,
    })
}

#[derive(Deserialize)]
struct RawToken {
    access_token: Option<String>,
    id_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Parse an OIDC token endpoint's response to a code exchange into
/// `(access_token, id_token)`. Both are required: without an `id_token` there
/// is nothing to verify, and the flow is not OIDC.
///
/// # Errors
///
/// [`IdpError::Oauth`] for an error object (checked first, whatever the
/// status), [`IdpError::Malformed`] for non-JSON or a missing/empty token.
pub fn parse_token_response(body: &[u8]) -> Result<(String, String), IdpError> {
    let raw: RawToken =
        serde_json::from_slice(body).map_err(|e| IdpError::Malformed(e.to_string()))?;
    if let Some(code) = raw.error {
        return Err(IdpError::Oauth {
            code,
            description: raw.error_description,
        });
    }
    let access = raw
        .access_token
        .filter(|t| !t.is_empty())
        .ok_or_else(|| IdpError::Malformed("response lacks `access_token`".to_owned()))?;
    let id = raw
        .id_token
        .filter(|t| !t.is_empty())
        .ok_or_else(|| IdpError::Malformed("response lacks `id_token`".to_owned()))?;
    Ok((access, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_responses() {
        let (a, i) = parse_token_response(
            br#"{"access_token":"at","token_type":"bearer","expires_in":3600,"id_token":"x.y.z"}"#,
        )
        .unwrap();
        assert_eq!((a.as_str(), i.as_str()), ("at", "x.y.z"));
        assert!(matches!(
            parse_token_response(br#"{"error":"invalid_grant","error_description":"nope"}"#),
            Err(IdpError::Oauth { ref code, .. }) if code == "invalid_grant"
        ));
        for bad in [
            &br#"{"access_token":"at"}"#[..],
            br#"{"id_token":"x"}"#,
            br#"{"access_token":"","id_token":"x"}"#,
            b"[]",
        ] {
            assert!(matches!(
                parse_token_response(bad),
                Err(IdpError::Malformed(_))
            ));
        }
    }

    /// Codeberg's document (Forgejo), trimmed to the fields of interest.
    const CODEBERG: &str = r#"{
        "issuer": "https://codeberg.org",
        "authorization_endpoint": "https://codeberg.org/login/oauth/authorize",
        "token_endpoint": "https://codeberg.org/login/oauth/access_token",
        "jwks_uri": "https://codeberg.org/login/oauth/keys",
        "userinfo_endpoint": "https://codeberg.org/login/oauth/userinfo",
        "introspection_endpoint": "https://codeberg.org/login/oauth/introspect",
        "response_types_supported": ["code", "id_token"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "subject_types_supported": ["public"],
        "scopes_supported": ["openid", "profile", "email", "groups"],
        "claims_supported": ["aud", "exp", "iat", "iss", "sub", "name", "preferred_username",
            "profile", "picture", "website", "locale", "updated_at", "email", "email_verified", "groups"],
        "code_challenge_methods_supported": ["plain", "S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"]
    }"#;

    /// GitLab.com's document, trimmed.
    const GITLAB: &str = r#"{
        "issuer": "https://gitlab.com",
        "authorization_endpoint": "https://gitlab.com/oauth/authorize",
        "token_endpoint": "https://gitlab.com/oauth/token",
        "revocation_endpoint": "https://gitlab.com/oauth/revoke",
        "introspection_endpoint": "https://gitlab.com/oauth/introspect",
        "userinfo_endpoint": "https://gitlab.com/oauth/userinfo",
        "jwks_uri": "https://gitlab.com/oauth/discovery/keys",
        "scopes_supported": ["api", "read_user", "openid", "profile", "email"],
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "sub_legacy", "name", "nickname",
            "preferred_username", "email", "email_verified", "website", "profile", "picture",
            "groups", "groups_direct"]
    }"#;

    #[test]
    fn captured_documents_parse() {
        let cb = parse_discovery(CODEBERG.as_bytes(), "https://codeberg.org").unwrap();
        assert_eq!(
            cb.token_endpoint,
            "https://codeberg.org/login/oauth/access_token"
        );
        assert_eq!(cb.jwks_uri, "https://codeberg.org/login/oauth/keys");
        assert_eq!(cb.id_token_signing_alg_values_supported, ["RS256"]);
        let gl = parse_discovery(GITLAB.as_bytes(), "https://gitlab.com").unwrap();
        assert_eq!(
            gl.authorization_endpoint,
            "https://gitlab.com/oauth/authorize"
        );
        assert_eq!(
            gl.userinfo_endpoint.as_deref(),
            Some("https://gitlab.com/oauth/userinfo")
        );
    }

    #[test]
    fn issuer_must_match_exactly() {
        for configured in [
            "https://codeberg.org/",
            "https://CODEBERG.org",
            "https://gitlab.com",
        ] {
            assert!(
                matches!(
                    parse_discovery(CODEBERG.as_bytes(), configured),
                    Err(IdpError::Discovery(_))
                ),
                "{configured}"
            );
        }
    }

    #[test]
    fn missing_fields_and_cleartext_endpoints_are_refused() {
        let mut doc: serde_json::Value = serde_json::from_str(CODEBERG).unwrap();
        doc.as_object_mut().unwrap().remove("jwks_uri");
        assert!(matches!(
            parse_discovery(doc.to_string().as_bytes(), "https://codeberg.org"),
            Err(IdpError::Discovery(_))
        ));
        let mut doc: serde_json::Value = serde_json::from_str(CODEBERG).unwrap();
        doc["token_endpoint"] = serde_json::json!("http://codeberg.org/token");
        assert!(matches!(
            parse_discovery(doc.to_string().as_bytes(), "https://codeberg.org"),
            Err(IdpError::Url(_))
        ));
        assert!(matches!(
            parse_discovery(b"<html>", "x"),
            Err(IdpError::Discovery(_))
        ));
    }
}
