//! Pure JWT verification: no IO, no clock.

use std::collections::HashSet;

use jsonwebtoken::jwk::{JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::Deserialize;

/// Why a JWT was refused.
///
/// Detail for the log and the audit trail — **never** for a response body,
/// which should be flat for every variant (no oracle).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OidcError {
    /// Not three base64url segments, or the header or claims will not decode.
    #[error("malformed JWT")]
    Malformed,
    /// The header named a `kid` that is not in the JWKS. The one variant a
    /// caller acts on: it is what a key **rotation** looks like, so refresh
    /// the JWKS once and retry.
    #[error("unknown key id {0:?}")]
    UnknownKid(String),
    /// The signature did not verify against the selected key.
    #[error("bad signature")]
    BadSignature,
    /// The `iss` claim is not the configured issuer.
    #[error("wrong issuer")]
    WrongIssuer,
    /// The `aud` claim does not contain the configured audience.
    #[error("wrong audience")]
    WrongAudience,
    /// `exp` is in the past (allowing for leeway).
    #[error("expired")]
    Expired,
    /// `nbf` or `iat` is in the future (allowing for leeway).
    #[error("not yet valid")]
    NotYetValid,
    /// A required claim is absent or unusable.
    #[error("missing or invalid claim `{0}`")]
    MissingClaim(&'static str),
    /// The header's `alg` is not on the allowlist.
    #[error("unsupported algorithm `{0}`")]
    UnsupportedAlg(String),
    /// The JWKS could not be fetched or parsed.
    #[error("JWKS unavailable: {0}")]
    Jwks(String),
    /// The `nonce` claim is absent or does not match this login's.
    #[error("nonce mismatch")]
    NonceMismatch,
    /// A multi-audience token's `azp` is not our client id.
    #[error("authorized party mismatch")]
    AzpMismatch,
    /// A verified token whose claim (`ref`, `environment`, `event_name`,
    /// `job_workflow_ref`, `ref_protected`) fails the issuer's configured
    /// claim constraints. Names the claim, never its value.
    #[error("claim `{0}` not allowed by policy")]
    ClaimNotAllowed(&'static str),
}

impl OidcError {
    /// A short stable label for structured logging and audit rows.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            OidcError::Malformed => "oidc.reject.malformed",
            OidcError::UnknownKid(_) => "oidc.reject.unknown_kid",
            OidcError::BadSignature => "oidc.reject.bad_signature",
            OidcError::WrongIssuer => "oidc.reject.wrong_issuer",
            OidcError::WrongAudience => "oidc.reject.wrong_audience",
            OidcError::Expired => "oidc.reject.expired",
            OidcError::NotYetValid => "oidc.reject.not_yet_valid",
            OidcError::MissingClaim(_) => "oidc.reject.missing_claim",
            OidcError::UnsupportedAlg(_) => "oidc.reject.unsupported_alg",
            OidcError::Jwks(_) => "oidc.reject.jwks_unavailable",
            OidcError::NonceMismatch => "oidc.reject.nonce_mismatch",
            OidcError::AzpMismatch => "oidc.reject.azp_mismatch",
            OidcError::ClaimNotAllowed(_) => "oidc.reject.claim_not_allowed",
        }
    }
}

/// The largest clock-skew margin honoured, seconds. A larger configured
/// `leeway_secs` is clamped to this by [`decode_verified`] (and refused by
/// `OidcConfig::validate`): an unbounded leeway would quietly turn expired
/// tokens back into valid ones.
pub const MAX_LEEWAY_SECS: u64 = 300;

/// The signature algorithms a verifier accepts.
///
/// Never contains an HMAC algorithm: an asymmetric issuer's JWKS holds public
/// keys, and accepting `HS*` is exactly the key-confusion attack. Pinning a
/// short explicit list (as opposed to "whatever the header asks for") makes the
/// `alg` family of attacks unrepresentable rather than merely unlikely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgPolicy(Vec<Algorithm>);

impl AlgPolicy {
    /// Build a policy. Returns `None` for an empty list or one containing an
    /// HMAC algorithm.
    #[must_use]
    pub fn new(algs: &[Algorithm]) -> Option<Self> {
        if algs.is_empty()
            || algs
                .iter()
                .any(|a| matches!(a, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512))
        {
            return None;
        }
        let mut v = algs.to_vec();
        v.dedup();
        Some(Self(v))
    }

    /// Exactly `[RS256]`: GitHub Actions, Codeberg and GitLab all sign with it.
    #[must_use]
    pub fn rs256() -> Self {
        Self(vec![Algorithm::RS256])
    }

    /// Whether `alg` is allowed.
    #[must_use]
    pub fn allows(&self, alg: Algorithm) -> bool {
        self.0.contains(&alg)
    }

    /// The allowed algorithms.
    #[must_use]
    pub fn algorithms(&self) -> &[Algorithm] {
        &self.0
    }
}

impl Default for AlgPolicy {
    fn default() -> Self {
        Self::rs256()
    }
}

/// The inputs to [`decode_verified`] other than the token and keys.
#[derive(Debug, Clone, Copy)]
pub struct VerifyParams<'a> {
    /// The expected `iss`, exact match.
    pub issuer: &'a str,
    /// An audience `aud` must contain.
    pub audience: &'a str,
    /// Allowed algorithms.
    pub algs: &'a AlgPolicy,
    /// Clock-skew margin for `exp`/`nbf`/`iat`, seconds; clamped to
    /// [`MAX_LEEWAY_SECS`].
    pub leeway_secs: u64,
    /// Current time, epoch seconds.
    pub now: u64,
}

/// The time claims every verified token is checked against. Deserialised as
/// `Option` so a missing `exp` is a nameable rejection rather than an
/// anonymous JSON error.
#[derive(Deserialize)]
struct TimeClaims {
    exp: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    iat: Option<u64>,
    sub: Option<String>,
}

/// Verify a JWT's signature, algorithm, `kid`, `iss`, `aud`, `exp`, `nbf` and `iat`
/// and deserialise its claims as `T`.
///
/// The shared core of [`verify_id_token`] and
/// [`crate::workload::verify_github_actions`]. Requires a non-empty `sub`.
///
/// # Errors
///
/// [`OidcError`]; see its variants.
pub fn decode_verified<T: DeserializeOwned>(
    jwt: &str,
    jwks: &JwkSet,
    params: &VerifyParams<'_>,
) -> Result<T, OidcError> {
    let jwt = jwt.trim();
    let header = jsonwebtoken::decode_header(jwt).map_err(|_| OidcError::Malformed)?;
    // Checked here as well as through `Validation`, so the rejection is
    // nameable rather than an anonymous decode failure.
    if !params.algs.allows(header.alg) {
        return Err(OidcError::UnsupportedAlg(format!("{:?}", header.alg)));
    }
    let kid = header.kid.ok_or(OidcError::MissingClaim("kid"))?;
    let jwk = jwks
        .find(&kid)
        // A key published for encryption is not a signing key. Absent `use`
        // is accepted: it is optional in RFC 7517.
        .filter(|jwk| !matches!(jwk.common.public_key_use, Some(PublicKeyUse::Encryption)))
        // Likewise a key whose `key_ops` (when given) exclude `verify`.
        .filter(|jwk| {
            jwk.common
                .key_operations
                .as_ref()
                .is_none_or(|ops| ops.contains(&KeyOperations::Verify))
        })
        .ok_or_else(|| OidcError::UnknownKid(kid.clone()))?;
    // A key restricted to one `alg` (RFC 7517 §4.4) verifies only that alg.
    // Compared by name: jsonwebtoken's `KeyAlgorithm` -> `Algorithm`
    // conversion is private, and the shared variants are named identically
    // (encryption-only variants never match a signing alg, as intended).
    if let Some(ka) = jwk.common.key_algorithm {
        if format!("{ka:?}") != format!("{:?}", header.alg) {
            return Err(OidcError::UnsupportedAlg(format!(
                "{:?} for a key restricted to {ka:?}",
                header.alg
            )));
        }
    }
    let key = DecodingKey::from_jwk(jwk).map_err(|e| OidcError::Jwks(e.to_string()))?;
    // An algorithm family different from the key's (an RSA key named by an
    // ES256 header) is an unsupported algorithm for this key, not a panic or
    // an anonymous error.
    if key.family() != header.alg.family() {
        return Err(OidcError::UnsupportedAlg(format!(
            "{:?} for a {:?} key",
            header.alg,
            key.family()
        )));
    }

    let mut validation = Validation::new(header.alg);
    validation.algorithms = vec![header.alg];
    validation.set_issuer(&[params.issuer]);
    validation.set_audience(&[params.audience]);
    validation.required_spec_claims = ["exp", "iss", "aud", "sub"]
        .into_iter()
        .map(str::to_owned)
        .collect::<HashSet<_>>();
    validation.validate_exp = false;
    validation.validate_nbf = false;

    let data = jsonwebtoken::decode::<serde_json::Value>(jwt, &key, &validation)
        .map_err(|e| map_jwt_error(&e))?;
    let time: TimeClaims =
        serde_json::from_value(data.claims.clone()).map_err(|_| OidcError::Malformed)?;
    let exp = time.exp.ok_or(OidcError::MissingClaim("exp"))?;
    if time.sub.as_deref().is_none_or(str::is_empty) {
        return Err(OidcError::MissingClaim("sub"));
    }
    let leeway = params.leeway_secs.min(MAX_LEEWAY_SECS);
    if exp.saturating_add(leeway) <= params.now {
        return Err(OidcError::Expired);
    }
    let not_before = params.now.saturating_add(leeway);
    if time.nbf.is_some_and(|nbf| nbf > not_before) || time.iat.is_some_and(|iat| iat > not_before)
    {
        return Err(OidcError::NotYetValid);
    }
    serde_json::from_value(data.claims).map_err(|_| OidcError::Malformed)
}

fn map_jwt_error(e: &jsonwebtoken::errors::Error) -> OidcError {
    use jsonwebtoken::errors::ErrorKind;
    match e.kind() {
        ErrorKind::InvalidSignature => OidcError::BadSignature,
        ErrorKind::InvalidIssuer => OidcError::WrongIssuer,
        ErrorKind::InvalidAudience => OidcError::WrongAudience,
        ErrorKind::ExpiredSignature => OidcError::Expired,
        ErrorKind::ImmatureSignature => OidcError::NotYetValid,
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
            OidcError::UnsupportedAlg("rejected by validation".to_owned())
        }
        ErrorKind::MissingRequiredClaim(name) => match name.as_str() {
            "exp" => OidcError::MissingClaim("exp"),
            "iss" => OidcError::MissingClaim("iss"),
            "aud" => OidcError::MissingClaim("aud"),
            "sub" => OidcError::MissingClaim("sub"),
            _ => OidcError::Malformed,
        },
        _ => OidcError::Malformed,
    }
}

/// Parse a JWKS document.
///
/// # Errors
///
/// [`OidcError::Jwks`] if the bytes are not a JWK set.
pub fn parse_jwks(bytes: &[u8]) -> Result<JwkSet, OidcError> {
    serde_json::from_slice(bytes).map_err(|e| OidcError::Jwks(e.to_string()))
}

/// What an OIDC login provider's `id_token` is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdTokenPolicy {
    /// The expected `iss` (the configured issuer).
    pub issuer: String,
    /// Our client id: `aud` must contain it, and `azp` must equal it when
    /// `aud` has more than one entry.
    pub client_id: String,
    /// Allowed signature algorithms.
    pub algs: AlgPolicy,
    /// Clock-skew margin, seconds; clamped to [`MAX_LEEWAY_SECS`].
    pub leeway_secs: u64,
}

/// The claims of a verified `id_token` that identify the user.
#[derive(Debug, Clone, PartialEq)]
pub struct IdTokenClaims {
    /// The issuer's immutable subject id.
    pub sub: String,
    /// The `email` claim, if any.
    pub email: Option<String>,
    /// `email_verified`: JSON `true`, or the string `"true"` (some issuers
    /// send strings). Anything else, including absence, is `false`.
    pub email_verified: bool,
    /// Every claim, for configurable username mapping.
    pub claims: serde_json::Map<String, serde_json::Value>,
}

impl IdTokenClaims {
    /// A string claim by name (for username mapping). Non-string claims are
    /// `None`.
    #[must_use]
    pub fn string_claim(&self, name: &str) -> Option<&str> {
        self.claims.get(name).and_then(serde_json::Value::as_str)
    }
}

/// Verify an OIDC `id_token` (OIDC Core §3.1.3.7).
///
/// On top of [`decode_verified`]: `nonce` must be present and equal
/// `expected_nonce`; a multi-audience token must carry `azp == client_id`.
///
/// # Errors
///
/// [`OidcError`].
pub fn verify_id_token(
    jwt: &str,
    jwks: &JwkSet,
    policy: &IdTokenPolicy,
    expected_nonce: &str,
    now: u64,
) -> Result<IdTokenClaims, OidcError> {
    let claims: serde_json::Map<String, serde_json::Value> = decode_verified(
        jwt,
        jwks,
        &VerifyParams {
            issuer: &policy.issuer,
            audience: &policy.client_id,
            algs: &policy.algs,
            leeway_secs: policy.leeway_secs,
            now,
        },
    )?;
    let multi_aud = claims
        .get("aud")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|a| a.len() > 1);
    if multi_aud
        && claims.get("azp").and_then(serde_json::Value::as_str) != Some(policy.client_id.as_str())
    {
        return Err(OidcError::AzpMismatch);
    }
    let nonce = claims.get("nonce").and_then(serde_json::Value::as_str);
    if expected_nonce.is_empty() || nonce != Some(expected_nonce) {
        return Err(OidcError::NonceMismatch);
    }
    let sub = claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(OidcError::MissingClaim("sub"))?
        .to_owned();
    let email = claims
        .get("email")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let email_verified = match claims.get("email_verified") {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s == "true",
        _ => false,
    };
    Ok(IdTokenClaims {
        sub,
        email,
        email_verified,
        claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        jwks, sign, sign_without_kid, KEY_A_DER_B64, KEY_A_N, KEY_B_DER_B64, KEY_B_N,
    };
    use base64::Engine as _;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    const ISSUER: &str = "https://codeberg.org";
    const CLIENT: &str = "forgs-client";

    fn policy() -> IdTokenPolicy {
        IdTokenPolicy {
            issuer: ISSUER.to_owned(),
            client_id: CLIENT.to_owned(),
            algs: AlgPolicy::rs256(),
            leeway_secs: 60,
        }
    }

    fn claims() -> serde_json::Value {
        json!({
            "iss": ISSUER, "aud": CLIENT, "sub": "12345",
            "exp": 2_000u64, "iat": 900u64, "nbf": 900u64,
            "nonce": "n0nce", "email": "a@example.com", "email_verified": true,
            "preferred_username": "alice",
        })
    }

    fn keys() -> JwkSet {
        jwks(&[("k1", KEY_A_N)])
    }

    #[test]
    fn a_good_id_token_verifies() {
        let out = verify_id_token(
            &sign("k1", KEY_A_DER_B64, &claims()),
            &keys(),
            &policy(),
            "n0nce",
            1_000,
        )
        .unwrap();
        assert_eq!(out.sub, "12345");
        assert_eq!(out.email.as_deref(), Some("a@example.com"));
        assert!(out.email_verified);
        assert_eq!(out.string_claim("preferred_username"), Some("alice"));
        assert_eq!(out.string_claim("exp"), None);
    }

    #[test]
    fn email_verified_accepts_bool_and_string_forms_only() {
        for (v, expect) in [
            (json!(true), true),
            (json!("true"), true),
            (json!(false), false),
            (json!("false"), false),
            (json!("yes"), false),
            (json!(1), false),
            (serde_json::Value::Null, false),
        ] {
            let mut c = claims();
            c["email_verified"] = v.clone();
            let out = verify_id_token(
                &sign("k1", KEY_A_DER_B64, &c),
                &keys(),
                &policy(),
                "n0nce",
                1_000,
            )
            .unwrap();
            assert_eq!(out.email_verified, expect, "{v}");
        }
        let mut c = claims();
        c.as_object_mut().unwrap().remove("email_verified");
        let out = verify_id_token(
            &sign("k1", KEY_A_DER_B64, &c),
            &keys(),
            &policy(),
            "n0nce",
            1_000,
        )
        .unwrap();
        assert!(!out.email_verified);
    }

    #[test]
    fn nonce_is_required_and_must_match() {
        let jwt = sign("k1", KEY_A_DER_B64, &claims());
        assert_eq!(
            verify_id_token(&jwt, &keys(), &policy(), "other", 1_000).unwrap_err(),
            OidcError::NonceMismatch
        );
        assert_eq!(
            verify_id_token(&jwt, &keys(), &policy(), "", 1_000).unwrap_err(),
            OidcError::NonceMismatch
        );
        let mut c = claims();
        c.as_object_mut().unwrap().remove("nonce");
        assert_eq!(
            verify_id_token(
                &sign("k1", KEY_A_DER_B64, &c),
                &keys(),
                &policy(),
                "n0nce",
                1_000
            )
            .unwrap_err(),
            OidcError::NonceMismatch
        );
    }

    #[test]
    fn audience_and_azp() {
        let mut c = claims();
        c["aud"] = json!("someone-else");
        assert_eq!(
            verify_id_token(
                &sign("k1", KEY_A_DER_B64, &c),
                &keys(),
                &policy(),
                "n0nce",
                1_000
            )
            .unwrap_err(),
            OidcError::WrongAudience
        );
        c["aud"] = json!([CLIENT, "other"]);
        assert_eq!(
            verify_id_token(
                &sign("k1", KEY_A_DER_B64, &c),
                &keys(),
                &policy(),
                "n0nce",
                1_000
            )
            .unwrap_err(),
            OidcError::AzpMismatch
        );
        c["azp"] = json!(CLIENT);
        assert!(verify_id_token(
            &sign("k1", KEY_A_DER_B64, &c),
            &keys(),
            &policy(),
            "n0nce",
            1_000
        )
        .is_ok());
        c["aud"] = json!([CLIENT]);
        c.as_object_mut().unwrap().remove("azp");
        assert!(verify_id_token(
            &sign("k1", KEY_A_DER_B64, &c),
            &keys(),
            &policy(),
            "n0nce",
            1_000
        )
        .is_ok());
    }

    #[test]
    fn algorithm_confusion_is_refused() {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("k1".to_owned());
        let jwt = jsonwebtoken::encode(
            &header,
            &claims(),
            &EncodingKey::from_secret(KEY_A_N.as_bytes()),
        )
        .unwrap();
        assert!(matches!(
            verify_id_token(&jwt, &keys(), &policy(), "n0nce", 1_000).unwrap_err(),
            OidcError::UnsupportedAlg(_)
        ));
        // Even a policy that lists RS256 and ES256 refuses an ES256 header
        // pointing at an RSA key.
        let wide = IdTokenPolicy {
            algs: AlgPolicy::new(&[Algorithm::RS256, Algorithm::ES256]).unwrap(),
            ..policy()
        };
        let good = sign("k1", KEY_A_DER_B64, &claims());
        let mut segs: Vec<String> = good.split('.').map(str::to_owned).collect();
        segs[0] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"alg": "ES256", "kid": "k1", "typ": "JWT"}).to_string());
        let forged = segs.join(".");
        assert!(matches!(
            verify_id_token(&forged, &keys(), &wide, "n0nce", 1_000).unwrap_err(),
            OidcError::UnsupportedAlg(_)
        ));
    }

    #[test]
    fn alg_policy_refuses_hmac_and_empty() {
        assert!(AlgPolicy::new(&[]).is_none());
        assert!(AlgPolicy::new(&[Algorithm::RS256, Algorithm::HS256]).is_none());
        assert!(AlgPolicy::new(&[Algorithm::HS512]).is_none());
        assert_eq!(AlgPolicy::default().algorithms(), &[Algorithm::RS256]);
    }

    #[test]
    fn signature_issuer_expiry_and_kid() {
        assert_eq!(
            verify_id_token(
                &sign("k1", KEY_B_DER_B64, &claims()),
                &keys(),
                &policy(),
                "n0nce",
                1_000
            )
            .unwrap_err(),
            OidcError::BadSignature
        );
        let mut c = claims();
        c["iss"] = json!("https://evil.example");
        assert_eq!(
            verify_id_token(
                &sign("k1", KEY_A_DER_B64, &c),
                &keys(),
                &policy(),
                "n0nce",
                1_000
            )
            .unwrap_err(),
            OidcError::WrongIssuer
        );
        let jwt = sign("k1", KEY_A_DER_B64, &claims());
        assert_eq!(
            verify_id_token(&jwt, &keys(), &policy(), "n0nce", 2_061).unwrap_err(),
            OidcError::Expired
        );
        assert!(verify_id_token(&jwt, &keys(), &policy(), "n0nce", 2_059).is_ok());
        assert_eq!(
            verify_id_token(&jwt, &keys(), &policy(), "n0nce", 800).unwrap_err(),
            OidcError::NotYetValid
        );
        assert_eq!(
            verify_id_token(
                &sign("k2", KEY_B_DER_B64, &claims()),
                &keys(),
                &policy(),
                "n0nce",
                1_000
            )
            .unwrap_err(),
            OidcError::UnknownKid("k2".to_owned())
        );
        assert!(verify_id_token(
            &sign("k2", KEY_B_DER_B64, &claims()),
            &jwks(&[("k1", KEY_A_N), ("k2", KEY_B_N)]),
            &policy(),
            "n0nce",
            1_000
        )
        .is_ok());
        assert_eq!(
            verify_id_token(
                &sign_without_kid(KEY_A_DER_B64, &claims()),
                &keys(),
                &policy(),
                "n0nce",
                1_000
            )
            .unwrap_err(),
            OidcError::MissingClaim("kid")
        );
        for drop in ["exp", "sub"] {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(drop);
            assert!(
                matches!(
                    verify_id_token(
                        &sign("k1", KEY_A_DER_B64, &c),
                        &keys(),
                        &policy(),
                        "n0nce",
                        1_000
                    )
                    .unwrap_err(),
                    OidcError::MissingClaim(_)
                ),
                "{drop}"
            );
        }
    }

    #[test]
    fn encryption_keys_are_not_signing_keys() {
        let mut set = crate::test_support::jwks_json(&[("k1", KEY_A_N)]);
        set["keys"][0]["use"] = json!("enc");
        let set: JwkSet = serde_json::from_value(set).unwrap();
        assert_eq!(
            verify_id_token(
                &sign("k1", KEY_A_DER_B64, &claims()),
                &set,
                &policy(),
                "n0nce",
                1_000
            )
            .unwrap_err(),
            OidcError::UnknownKid("k1".to_owned())
        );
    }

    #[test]
    fn garbage_is_malformed_not_a_panic() {
        for bad in ["", "  ", "not.a.jwt", "a.b", "....", "aaaa"] {
            assert_eq!(
                verify_id_token(bad, &keys(), &policy(), "n", 1_000).unwrap_err(),
                OidcError::Malformed,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn every_error_has_a_distinct_stable_label() {
        let labels = [
            OidcError::Malformed,
            OidcError::UnknownKid("k".to_owned()),
            OidcError::BadSignature,
            OidcError::WrongIssuer,
            OidcError::WrongAudience,
            OidcError::Expired,
            OidcError::NotYetValid,
            OidcError::MissingClaim("exp"),
            OidcError::UnsupportedAlg("HS256".to_owned()),
            OidcError::Jwks("x".to_owned()),
            OidcError::NonceMismatch,
            OidcError::AzpMismatch,
            OidcError::ClaimNotAllowed("ref"),
        ]
        .map(|e| e.label());
        let unique: HashSet<&str> = labels.iter().copied().collect();
        assert_eq!(unique.len(), labels.len());
        assert!(labels.iter().all(|l| l.starts_with("oidc.reject.")));
    }

    #[test]
    fn jwks_parsing_rejects_junk() {
        assert!(parse_jwks(b"{\"keys\":[]}").is_ok());
        assert!(matches!(parse_jwks(b"nope"), Err(OidcError::Jwks(_))));
    }

    fn keys_with(extra: &serde_json::Value) -> JwkSet {
        let mut set = crate::test_support::jwks_json(&[("k1", KEY_A_N)]);
        let key = set["keys"][0].as_object_mut().unwrap();
        key.remove("alg");
        for (k, v) in extra.as_object().unwrap() {
            key.insert(k.clone(), v.clone());
        }
        serde_json::from_value(set).unwrap()
    }

    #[test]
    fn a_keys_alg_and_key_ops_restrict_it() {
        let jwt = sign("k1", KEY_A_DER_B64, &claims());
        let verify = |set: &JwkSet| verify_id_token(&jwt, set, &policy(), "n0nce", 1_000);
        assert!(verify(&keys_with(&json!({}))).is_ok());
        assert!(verify(&keys_with(&json!({"alg": "RS256"}))).is_ok());
        assert!(matches!(
            verify(&keys_with(&json!({"alg": "RS384"}))).unwrap_err(),
            OidcError::UnsupportedAlg(_)
        ));
        assert!(verify(&keys_with(&json!({"key_ops": ["verify"]}))).is_ok());
        assert_eq!(
            verify(&keys_with(&json!({"key_ops": ["encrypt"]}))).unwrap_err(),
            OidcError::UnknownKid("k1".to_owned())
        );
    }

    #[test]
    fn iat_in_the_future_is_not_yet_valid() {
        let mut c = claims();
        c["iat"] = json!(2_000u64);
        c.as_object_mut().unwrap().remove("nbf");
        assert_eq!(
            verify_id_token(
                &sign("k1", KEY_A_DER_B64, &c),
                &keys(),
                &policy(),
                "n0nce",
                1_000
            )
            .unwrap_err(),
            OidcError::NotYetValid
        );
        c["iat"] = json!(1_000u64);
        assert!(verify_id_token(
            &sign("k1", KEY_A_DER_B64, &c),
            &keys(),
            &policy(),
            "n0nce",
            1_000
        )
        .is_ok());
    }

    #[test]
    fn leeway_is_clamped() {
        let huge = IdTokenPolicy {
            leeway_secs: 10_000,
            ..policy()
        };
        let jwt = sign("k1", KEY_A_DER_B64, &claims());
        // exp = 2000: within the clamped 300 s, but not 10 000.
        assert!(verify_id_token(&jwt, &keys(), &huge, "n0nce", 2_299).is_ok());
        assert_eq!(
            verify_id_token(&jwt, &keys(), &huge, "n0nce", 3_000).unwrap_err(),
            OidcError::Expired
        );
    }

    #[test]
    fn an_unknown_kid_is_escaped_in_the_message() {
        let msg = OidcError::UnknownKid("k\nINFO forged".to_owned()).to_string();
        assert!(!msg.contains('\n'), "{msg}");
        assert!(msg.contains("\\n"), "{msg}");
    }
}
