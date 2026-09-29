//! GitHub Actions **workload identity** (feature `oidc`; the fetching
//! [`GithubActionsIssuer`] also needs `client`).
//!
//! A job with `permissions: id-token: write` can mint a signed JWT from
//! `https://token.actions.githubusercontent.com`, whose public keys are
//! published at a JWKS endpoint. So this is real signature verification, and
//! no secret ever enters the runner — the entire point of the CI path.
//!
//! # What is verified, and what is merely recorded
//!
//! Verified: signature (JWKS key by mandatory `kid`), algorithm (exactly
//! `[RS256]`), issuer and audience (exact), `exp`/`nbf` against an injected
//! `now`, and that `repository` is exactly one `owner/name` pair over a
//! conservative charset (via [`forgs::subject::normalise_repo`], the same
//! function grant creation uses, so the two sides cannot disagree on case).
//!
//! Recorded but **never authorizing**: `repository_owner`, `ref`, `workflow`,
//! `job_workflow_ref`, `run_id`. In particular `repository_owner` is not
//! sufficient — a fork, or a new repo under a granted owner, must not inherit
//! access. Only the full `owner/repo` becomes the subject
//! ([`forgs::subject::workload_subject_key`]), matched against an explicit
//! grant by the caller.

use forgs::subject::{normalise_repo, workload_subject_key};
use forgs::SubjectKey;
use serde::Deserialize;

use crate::oidc::{decode_verified, AlgPolicy, JwkSet, OidcError, VerifyParams};

/// The GitHub Actions issuer.
pub const GHA_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The GitHub Actions JWKS endpoint.
pub const GHA_JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";

/// What a workload verifier accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcPolicy {
    /// The expected `iss` ([`GHA_ISSUER`]).
    pub issuer: String,
    /// The expected `aud`.
    ///
    /// **Required, with no default.** GitHub's default audience is
    /// `https://github.com/<owner>`, which is not forgs-specific: a token
    /// minted for some *other* service that also took the default would be
    /// replayable here. The app's own public URL is the intended value, and
    /// the workflow asks for it explicitly.
    pub audience: String,
    /// Clock-skew margin, in seconds, applied to `exp` and `nbf`.
    pub leeway_secs: u64,
}

impl OidcPolicy {
    /// The GitHub Actions policy for `audience`, 60 s leeway.
    #[must_use]
    pub fn github_actions(audience: impl Into<String>) -> Self {
        Self {
            issuer: GHA_ISSUER.to_owned(),
            audience: audience.into(),
            leeway_secs: 60,
        }
    }
}

/// The claims forgs cares about from a GitHub Actions OIDC token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadClaims {
    /// `owner/name`, validated and **lowercased**. The only claim that takes
    /// part in an authorization decision.
    pub repository: String,
    /// The repository's owner, lowercased. Audit only; **never** authorizing.
    pub repository_owner: String,
    /// The git ref the job ran on. Recorded, not evaluated.
    pub git_ref: Option<String>,
    /// The workflow's name.
    pub workflow: Option<String>,
    /// The fully-qualified workflow reference.
    pub job_workflow_ref: Option<String>,
    /// The Actions run id.
    pub run_id: Option<String>,
    /// The token's `sub` claim, verbatim.
    pub sub: String,
    /// The token's expiry, epoch seconds.
    pub exp: u64,
}

/// A verified workload: the subject it authenticates as, plus its claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadIdentity {
    /// `gha/workload:<owner>/<repo>`.
    pub subject: SubjectKey,
    /// The verified claims.
    pub claims: WorkloadClaims,
}

#[derive(Deserialize)]
struct RawClaims {
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    repository_owner: Option<String>,
    #[serde(default, rename = "ref")]
    git_ref: Option<String>,
    #[serde(default)]
    workflow: Option<String>,
    #[serde(default)]
    job_workflow_ref: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    sub: Option<String>,
    exp: Option<u64>,
}

/// Verify a GitHub Actions OIDC JWT against `jwks` and `policy` at `now`.
///
/// Pure: no I/O, no clock.
///
/// # Errors
///
/// [`OidcError`]. Every variant should map to the same flat `invalid_grant`
/// at the HTTP boundary; the distinction exists for the log.
pub fn verify_github_actions(
    jwt: &str,
    jwks: &JwkSet,
    policy: &OidcPolicy,
    now: u64,
) -> Result<WorkloadIdentity, OidcError> {
    let claims: RawClaims = decode_verified(
        jwt,
        jwks,
        &VerifyParams {
            issuer: &policy.issuer,
            audience: &policy.audience,
            algs: &AlgPolicy::rs256(),
            leeway_secs: policy.leeway_secs,
            now,
        },
    )?;
    let exp = claims.exp.ok_or(OidcError::MissingClaim("exp"))?;
    let sub = claims
        .sub
        .filter(|s| !s.is_empty())
        .ok_or(OidcError::MissingClaim("sub"))?;
    let repository = claims
        .repository
        .as_deref()
        .and_then(normalise_repo)
        .ok_or(OidcError::MissingClaim("repository"))?;
    let repository_owner = claims
        .repository_owner
        .filter(|s| !s.trim().is_empty())
        .ok_or(OidcError::MissingClaim("repository_owner"))?
        .to_ascii_lowercase();
    Ok(WorkloadIdentity {
        subject: workload_subject_key(&repository),
        claims: WorkloadClaims {
            repository,
            repository_owner,
            git_ref: claims.git_ref,
            workflow: claims.workflow,
            job_workflow_ref: claims.job_workflow_ref,
            run_id: claims.run_id,
            sub,
            exp,
        },
    })
}

/// An issuer of workload tokens forgs can exchange for a session.
#[async_trait::async_trait]
pub trait WorkloadIssuer: Send + Sync {
    /// A stable name for logs (`github-actions`).
    fn name(&self) -> &str;

    /// Verify `jwt` at `now` (epoch seconds, the caller's clock).
    async fn verify(&self, jwt: &str, now: u64) -> Result<WorkloadIdentity, OidcError>;
}

#[cfg(feature = "client")]
pub use issuer::GithubActionsIssuer;

#[cfg(feature = "client")]
mod issuer {
    use super::{
        verify_github_actions, OidcPolicy, WorkloadIdentity, WorkloadIssuer, GHA_JWKS_URL,
    };
    use crate::oidc::{JwksCache, OidcError};

    /// The GitHub Actions [`WorkloadIssuer`]: verification over a
    /// [`JwksCache`], with one forced refresh on an unknown `kid`.
    #[derive(Debug)]
    pub struct GithubActionsIssuer {
        policy: OidcPolicy,
        jwks: JwksCache,
    }

    impl GithubActionsIssuer {
        /// github.com's issuer and JWKS, for `audience`.
        #[must_use]
        pub fn new(audience: impl Into<String>) -> Self {
            Self::with_parts(
                OidcPolicy::github_actions(audience),
                JwksCache::new(
                    GHA_JWKS_URL,
                    JwksCache::DEFAULT_REFRESH_AFTER,
                    JwksCache::DEFAULT_MIN_REFETCH,
                ),
            )
        }

        /// Explicit policy and cache (GHES, tests).
        #[must_use]
        pub fn with_parts(policy: OidcPolicy, jwks: JwksCache) -> Self {
            Self { policy, jwks }
        }

        /// The policy.
        #[must_use]
        pub fn policy(&self) -> &OidcPolicy {
            &self.policy
        }
    }

    #[async_trait::async_trait]
    impl WorkloadIssuer for GithubActionsIssuer {
        fn name(&self) -> &'static str {
            "github-actions"
        }

        async fn verify(&self, jwt: &str, now: u64) -> Result<WorkloadIdentity, OidcError> {
            self.jwks
                .verify_with(|keys| verify_github_actions(jwt, keys, &self.policy, now))
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        jwks, sign, sign_without_kid, KEY_A_DER_B64, KEY_A_N, KEY_B_DER_B64, KEY_B_N,
    };
    use base64::Engine as _;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::json;
    use std::collections::HashSet;

    const AUDIENCE: &str = "https://forgs.example";

    fn policy() -> OidcPolicy {
        OidcPolicy::github_actions(AUDIENCE)
    }

    fn claims() -> serde_json::Value {
        json!({
            "iss": GHA_ISSUER,
            "aud": AUDIENCE,
            "sub": "repo:ariel-os/ariel-os:ref:refs/heads/main",
            "exp": 2_000u64,
            "nbf": 900u64,
            "iat": 900u64,
            "repository": "ariel-os/ariel-os",
            "repository_owner": "ariel-os",
            "ref": "refs/heads/main",
            "workflow": "hil",
            "job_workflow_ref": "ariel-os/ariel-os/.github/workflows/hil.yml@refs/heads/main",
            "run_id": "12345",
        })
    }

    fn verify(jwt: &str, keys: &JwkSet, now: u64) -> Result<WorkloadIdentity, OidcError> {
        verify_github_actions(jwt, keys, &policy(), now)
    }

    #[test]
    fn a_well_formed_token_verifies_and_lowercases_its_repo() {
        let mut c = claims();
        c["repository"] = json!("Ariel-OS/Ariel-OS");
        c["repository_owner"] = json!("Ariel-OS");
        let out = verify(
            &sign("k1", KEY_A_DER_B64, &c),
            &jwks(&[("k1", KEY_A_N)]),
            1_000,
        )
        .unwrap();
        assert_eq!(out.subject.to_string(), "gha/workload:ariel-os/ariel-os");
        assert_eq!(out.subject, workload_subject_key("ariel-os/ariel-os"));
        assert_eq!(out.claims.repository, "ariel-os/ariel-os");
        assert_eq!(out.claims.repository_owner, "ariel-os");
        assert_eq!(out.claims.git_ref.as_deref(), Some("refs/heads/main"));
        assert_eq!(out.claims.workflow.as_deref(), Some("hil"));
        assert_eq!(out.claims.run_id.as_deref(), Some("12345"));
        assert_eq!(out.claims.exp, 2_000);
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
            verify(&jwt, &jwks(&[("k1", KEY_A_N)]), 1_000).unwrap_err(),
            OidcError::UnsupportedAlg(_)
        ));
    }

    #[test]
    fn wrong_key_and_tampering_are_refused() {
        let keys = jwks(&[("k1", KEY_A_N)]);
        assert_eq!(
            verify(&sign("k1", KEY_B_DER_B64, &claims()), &keys, 1_000).unwrap_err(),
            OidcError::BadSignature
        );
        let jwt = sign("k1", KEY_A_DER_B64, &claims());
        let mut parts: Vec<&str> = jwt.split('.').collect();
        let forged = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(claims().to_string().replace("ariel-os", "attacker"));
        parts[1] = &forged;
        assert_eq!(
            verify(&parts.join("."), &keys, 1_000).unwrap_err(),
            OidcError::BadSignature
        );
    }

    #[test]
    fn issuer_audience_and_expiry_are_each_checked() {
        let keys = jwks(&[("k1", KEY_A_N)]);
        let mut c = claims();
        c["iss"] = json!("https://evil.example");
        assert_eq!(
            verify(&sign("k1", KEY_A_DER_B64, &c), &keys, 1_000).unwrap_err(),
            OidcError::WrongIssuer
        );
        // GitHub's *default* audience — not forgs-specific.
        let mut c = claims();
        c["aud"] = json!("https://github.com/ariel-os");
        assert_eq!(
            verify(&sign("k1", KEY_A_DER_B64, &c), &keys, 1_000).unwrap_err(),
            OidcError::WrongAudience
        );
        let jwt = sign("k1", KEY_A_DER_B64, &claims());
        assert_eq!(verify(&jwt, &keys, 2_061).unwrap_err(), OidcError::Expired);
        assert!(verify(&jwt, &keys, 2_059).is_ok());
        assert_eq!(
            verify(&jwt, &keys, 800).unwrap_err(),
            OidcError::NotYetValid
        );
    }

    /// `exp` 2000 is long past by any wall clock; only the injected `now`
    /// decides.
    #[test]
    fn expiry_is_decided_only_by_the_injected_clock() {
        assert!(verify(
            &sign("k1", KEY_A_DER_B64, &claims()),
            &jwks(&[("k1", KEY_A_N)]),
            1_000
        )
        .is_ok());
    }

    #[test]
    fn required_claims_are_required_not_defaulted() {
        let keys = jwks(&[("k1", KEY_A_N)]);
        for (drop, expected) in [
            ("repository", OidcError::MissingClaim("repository")),
            (
                "repository_owner",
                OidcError::MissingClaim("repository_owner"),
            ),
            ("exp", OidcError::MissingClaim("exp")),
            ("sub", OidcError::MissingClaim("sub")),
        ] {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(drop);
            assert_eq!(
                verify(&sign("k1", KEY_A_DER_B64, &c), &keys, 1_000).unwrap_err(),
                expected,
                "{drop}"
            );
        }
        for bad in ["not-a-repo", "a/b/c", "own:er/name"] {
            let mut c = claims();
            c["repository"] = json!(bad);
            assert_eq!(
                verify(&sign("k1", KEY_A_DER_B64, &c), &keys, 1_000).unwrap_err(),
                OidcError::MissingClaim("repository"),
                "{bad}"
            );
        }
    }

    #[test]
    fn kid_is_required_and_an_unknown_one_is_nameable() {
        let keys = jwks(&[("k1", KEY_A_N)]);
        assert_eq!(
            verify(&sign("k9", KEY_A_DER_B64, &claims()), &keys, 1_000).unwrap_err(),
            OidcError::UnknownKid("k9".to_owned())
        );
        assert_eq!(
            verify(&sign_without_kid(KEY_A_DER_B64, &claims()), &keys, 1_000).unwrap_err(),
            OidcError::MissingClaim("kid")
        );
    }

    #[test]
    fn a_rotated_key_set_resolves_by_kid() {
        let rotated = jwks(&[("k1", KEY_A_N), ("k2", KEY_B_N)]);
        assert!(verify(&sign("k1", KEY_A_DER_B64, &claims()), &rotated, 1_000).is_ok());
        assert!(verify(&sign("k2", KEY_B_DER_B64, &claims()), &rotated, 1_000).is_ok());
        assert_eq!(
            verify(&sign("k2", KEY_A_DER_B64, &claims()), &rotated, 1_000).unwrap_err(),
            OidcError::BadSignature
        );
    }

    #[test]
    fn garbage_is_malformed_not_a_panic() {
        let keys = jwks(&[("k1", KEY_A_N)]);
        for bad in ["", "  ", "not.a.jwt", "a.b", "....", "aaaa"] {
            assert_eq!(
                verify(bad, &keys, 1_000).unwrap_err(),
                OidcError::Malformed,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn labels_are_distinct() {
        let labels: HashSet<&str> = [
            OidcError::Malformed,
            OidcError::Expired,
            OidcError::BadSignature,
        ]
        .iter()
        .map(OidcError::label)
        .collect();
        assert_eq!(labels.len(), 3);
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn issuer_refreshes_once_for_a_rotated_key() {
        use crate::oidc::JwksCache;
        use crate::test_support::{jwks_json, Reply, StubServer};
        use std::time::Duration;

        let stub = StubServer::start(vec![(
            "/jwks".into(),
            Reply::json(&jwks_json(&[("k1", KEY_A_N)])),
        )])
        .await;
        let issuer = GithubActionsIssuer::with_parts(
            policy(),
            JwksCache::new(stub.url("/jwks"), Duration::from_secs(3600), Duration::ZERO),
        );
        assert_eq!(issuer.name(), "github-actions");
        issuer
            .verify(&sign("k1", KEY_A_DER_B64, &claims()), 1_000)
            .await
            .unwrap();
        stub.set(
            "/jwks",
            Reply::json(&jwks_json(&[("k1", KEY_A_N), ("k2", KEY_B_N)])),
        );
        let out = issuer
            .verify(&sign("k2", KEY_B_DER_B64, &claims()), 1_000)
            .await
            .unwrap();
        assert_eq!(out.subject.to_string(), "gha/workload:ariel-os/ariel-os");
        assert_eq!(stub.count("/jwks"), 2);
        assert_eq!(
            GithubActionsIssuer::new(AUDIENCE).policy().issuer,
            GHA_ISSUER
        );
    }
}
