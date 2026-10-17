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
//! `[RS256]`), issuer and audience (exact), `exp`/`nbf`/`iat` against an
//! injected `now`, a non-empty `jti`, and that `repository_id` and `repository_owner_id` are present,
//! canonical numeric ids ([`forgs::subject::normalise_github_id`]).
//!
//! **Authorizing**: only the immutable ids. The subject is
//! `<issuer label>/workload:id:<repository_owner_id>/<repository_id>`
//! ([`forgs::subject::workload_subject_key`]), matched against an explicit
//! grant by the caller. Names are reassignable — after a rename, transfer or
//! deletion anyone can register the freed `owner/repo` — so a name-keyed
//! subject would hand the old repo's grants to whoever took the name. The
//! issuer label ([`OidcPolicy::subject_ns`]) keeps two configured issuers
//! (github.com and a GHES) from ever sharing a subject.
//!
//! Recorded but **never authorizing**: `repository` (still required and
//! validated via [`forgs::subject::normalise_repo`], for display and audit),
//! `repository_owner`, `run_id`, `workflow`, `ref_type`,
//! `runner_environment`. A fork, or a new repo under a granted owner, has a
//! different `repository_id` and so matches no grant.
//!
//! **Single use** is the caller's job: this module is pure, so it only
//! requires the `jti` and reports [`WorkloadClaims::accept_until`]. forgs-http
//! records `(issuer, jti)` until then and refuses a second exchange, so a
//! leaked id token is worth at most one workload token.
//!
//! # Claim constraints: which jobs of a granted repo may exchange
//!
//! A grant names a repository, not a job. **Without constraints, every
//! workflow on every branch of a granted repo gets the full grant set**:
//! feature branches any collaborator can push, Dependabot runs,
//! `workflow_dispatch` on an arbitrary ref, and `pull_request_target` /
//! `workflow_run` jobs that may be running untrusted PR code with
//! `id-token: write`.
//!
//! [`OidcPolicy::constraints`] ([`ClaimConstraints`]) narrows that, at
//! verification time, before any grant is looked up: allowed `ref`s,
//! `environment`s and `job_workflow_ref`s, an `event_name` allow- and
//! deny-list, and `ref_protected == true`. A configured constraint whose
//! claim is absent fails closed. The constructors deny
//! `pull_request_target` by default ([`DEFAULT_DENIED_EVENTS`]); everything
//! else is opt-in. Typical hardening:
//!
//! ```
//! # use forgs_idp::workload::{ClaimConstraints, OidcPolicy};
//! let mut policy = OidcPolicy::github_actions("https://forgs.example");
//! policy.constraints = ClaimConstraints {
//!     refs: vec!["refs/heads/main".into(), "refs/tags/v*".into()],
//!     require_ref_protected: true,
//!     ..policy.constraints
//! };
//! ```
//!
//! The constraints apply to every repo verified by the issuer; the extra
//! claims (`ref`, `environment`, `event_name`, `ref_protected`,
//! `job_workflow_ref`, …) are also recorded in [`WorkloadClaims`] and in the
//! minted token's claims, for audit and for apps that want a finer,
//! per-grant rule.

use forgs::subject::{normalise_github_id, normalise_repo, workload_subject_key, WORKLOAD_NS_GHA};
use forgs::SubjectKey;
use serde::{Deserialize, Deserializer};

use crate::oidc::{decode_verified, AlgPolicy, JwkSet, OidcError, VerifyParams};

/// The GitHub Actions issuer.
pub const GHA_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The GitHub Actions JWKS endpoint.
pub const GHA_JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";

/// The `event_name`s [`OidcPolicy`]'s constructors deny by default:
/// `pull_request_target` runs in the base repo's context — with
/// `id-token: write` if the workflow asks — while commonly checking out and
/// running the PR's untrusted code.
pub const DEFAULT_DENIED_EVENTS: &[&str] = &["pull_request_target"];

/// Which jobs of a granted repository may exchange their token, evaluated
/// against the verified claims before any grant lookup.
///
/// Every list is empty = unconstrained. A pattern is an exact match, or a
/// prefix match when it ends in `*` (`refs/tags/v*`; a bare `*` matches
/// any present value). A constraint whose claim is **absent** refuses the
/// token (fail closed); so does a configured `denied_events` when
/// `event_name` is absent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClaimConstraints {
    /// Allowed `ref` values (`refs/heads/main`, `refs/tags/v*`).
    pub refs: Vec<String>,
    /// Allowed `environment` values. Since GitHub only issues an
    /// `environment` claim to a job that targets one, and an environment's
    /// protection rules (required reviewers, branch policy) gate the job,
    /// this is the strongest of the constraints.
    pub environments: Vec<String>,
    /// Allowed `job_workflow_ref` values
    /// (`owner/repo/.github/workflows/deploy.yml@refs/heads/main`, or with a
    /// trailing `*` to allow any ref of that workflow file).
    pub job_workflow_refs: Vec<String>,
    /// Allowed `event_name` values (`push`, `release`, …).
    pub events: Vec<String>,
    /// Refused `event_name` values; checked after [`Self::events`].
    pub denied_events: Vec<String>,
    /// Require `ref_protected == true`: the job ran on a ref covered by a
    /// branch-protection rule or ruleset.
    pub require_ref_protected: bool,
}

impl ClaimConstraints {
    /// The constructors' default: only [`DEFAULT_DENIED_EVENTS`] denied.
    #[must_use]
    pub fn github_default() -> Self {
        Self {
            denied_events: DEFAULT_DENIED_EVENTS
                .iter()
                .map(|e| (*e).to_owned())
                .collect(),
            ..Self::default()
        }
    }

    /// Check `claims`.
    ///
    /// # Errors
    ///
    /// [`OidcError::ClaimNotAllowed`] naming the first failing claim.
    pub fn check(&self, claims: &WorkloadClaims) -> Result<(), OidcError> {
        fn allowed(
            patterns: &[String],
            value: Option<&str>,
            claim: &'static str,
        ) -> Result<(), OidcError> {
            if patterns.is_empty() {
                return Ok(());
            }
            match value {
                Some(v) if patterns.iter().any(|p| pattern_matches(p, v)) => Ok(()),
                _ => Err(OidcError::ClaimNotAllowed(claim)),
            }
        }
        allowed(&self.refs, claims.git_ref.as_deref(), "ref")?;
        allowed(
            &self.environments,
            claims.environment.as_deref(),
            "environment",
        )?;
        allowed(
            &self.job_workflow_refs,
            claims.job_workflow_ref.as_deref(),
            "job_workflow_ref",
        )?;
        allowed(&self.events, claims.event_name.as_deref(), "event_name")?;
        if !self.denied_events.is_empty() {
            match claims.event_name.as_deref() {
                Some(e) if !self.denied_events.iter().any(|p| pattern_matches(p, e)) => {}
                _ => return Err(OidcError::ClaimNotAllowed("event_name")),
            }
        }
        if self.require_ref_protected && claims.ref_protected != Some(true) {
            return Err(OidcError::ClaimNotAllowed("ref_protected"));
        }
        Ok(())
    }
}

/// Exact, or prefix when `pattern` ends in `*`. Empty values never match.
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => pattern == value,
    }
}

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
    /// Clock-skew margin, in seconds, applied to `exp`, `nbf` and `iat`;
    /// clamped to [`MAX_LEEWAY_SECS`](crate::oidc::MAX_LEEWAY_SECS).
    pub leeway_secs: u64,
    /// The issuer label every subject verified under this policy carries
    /// (the namespace slot of `<label>/workload:id:…`). Must pass
    /// [`forgs::subject::valid_workload_ns`] and be **unique per configured
    /// issuer**: [`WORKLOAD_NS_GHA`] for github.com, something distinct
    /// (`ghes-corp`) for a GHES or enterprise custom issuer.
    pub subject_ns: String,
    /// Which jobs of a granted repo may exchange (module docs, "Claim
    /// constraints"). The constructors set
    /// [`ClaimConstraints::github_default`].
    pub constraints: ClaimConstraints,
}

impl OidcPolicy {
    /// The GitHub Actions policy for `audience`, 60 s leeway.
    #[must_use]
    pub fn github_actions(audience: impl Into<String>) -> Self {
        Self {
            issuer: GHA_ISSUER.to_owned(),
            audience: audience.into(),
            leeway_secs: 60,
            subject_ns: WORKLOAD_NS_GHA.to_owned(),
            constraints: ClaimConstraints::github_default(),
        }
    }

    /// A policy for another GitHub Actions-compatible issuer (GHES, an
    /// enterprise custom issuer), 60 s leeway. `subject_ns` must differ from
    /// every other configured issuer's label.
    #[must_use]
    pub fn custom(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        subject_ns: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            leeway_secs: 60,
            subject_ns: subject_ns.into(),
            constraints: ClaimConstraints::github_default(),
        }
    }
}

/// The claims forgs cares about from a GitHub Actions OIDC token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadClaims {
    /// The repository's immutable numeric id. Together with
    /// [`Self::repository_owner_id`], the only claim that takes part in an
    /// authorization decision.
    pub repository_id: String,
    /// The owner's immutable numeric id. Authorizing, with
    /// [`Self::repository_id`].
    pub repository_owner_id: String,
    /// `owner/name`, validated and **lowercased**. Display and audit only;
    /// **never** authorizing (names are reassignable).
    pub repository: String,
    /// The repository's owner, lowercased. Audit only; **never** authorizing.
    pub repository_owner: String,
    /// The git ref the job ran on. Evaluated only by
    /// [`ClaimConstraints::refs`].
    pub git_ref: Option<String>,
    /// `branch` or `tag`. Audit only.
    pub ref_type: Option<String>,
    /// Whether `ref` is protected (branch protection or a ruleset).
    /// Evaluated only by [`ClaimConstraints::require_ref_protected`].
    pub ref_protected: Option<bool>,
    /// The deployment environment the job targets, if any. Evaluated only
    /// by [`ClaimConstraints::environments`].
    pub environment: Option<String>,
    /// The triggering event (`push`, `pull_request_target`, …). Evaluated
    /// only by [`ClaimConstraints::events`] / `denied_events`.
    pub event_name: Option<String>,
    /// The workflow's name. Audit only.
    pub workflow: Option<String>,
    /// The fully-qualified workflow reference. Evaluated only by
    /// [`ClaimConstraints::job_workflow_refs`].
    pub job_workflow_ref: Option<String>,
    /// `github-hosted` or `self-hosted`. Audit only.
    pub runner_environment: Option<String>,
    /// The Actions run id.
    pub run_id: Option<String>,
    /// The token's `sub` claim, verbatim.
    pub sub: String,
    /// The token's expiry, epoch seconds.
    pub exp: u64,
    /// The token's `jti`, verbatim and non-empty. Unique per issuer; the
    /// caller enforces single use with it.
    pub jti: String,
    /// `exp` + the policy's (clamped) leeway: the last second this JWT
    /// verifies. A replay record must be kept until then.
    pub accept_until: u64,
}

/// A verified workload: the subject it authenticates as, plus its claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadIdentity {
    /// `<issuer label>/workload:id:<owner_id>/<repo_id>`.
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
    #[serde(default, deserialize_with = "lenient_id")]
    repository_id: Option<String>,
    #[serde(default, deserialize_with = "lenient_id")]
    repository_owner_id: Option<String>,
    #[serde(default, rename = "ref")]
    git_ref: Option<String>,
    #[serde(default)]
    ref_type: Option<String>,
    #[serde(default, deserialize_with = "lenient_bool")]
    ref_protected: Option<bool>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    event_name: Option<String>,
    #[serde(default)]
    runner_environment: Option<String>,
    #[serde(default)]
    workflow: Option<String>,
    #[serde(default)]
    job_workflow_ref: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    jti: Option<String>,
    sub: Option<String>,
    exp: Option<u64>,
}

/// A numeric-id claim: GitHub sends a string, but an unsigned integer is
/// accepted too. Any other JSON type reads as missing (and is then refused).
fn lenient_id<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(match serde_json::Value::deserialize(d)? {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Number(n) => n.as_u64().map(|n| n.to_string()),
        _ => None,
    })
}

/// A boolean claim: GitHub sends `"true"`/`"false"`, a JSON bool is
/// accepted too. Anything else reads as missing.
fn lenient_bool<'de, D: Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    Ok(match serde_json::Value::deserialize(d)? {
        serde_json::Value::Bool(b) => Some(b),
        serde_json::Value::String(s) if s == "true" => Some(true),
        serde_json::Value::String(s) if s == "false" => Some(false),
        _ => None,
    })
}

/// Verify a GitHub Actions OIDC JWT against `jwks` and `policy` at `now`.
///
/// Pure: no I/O, no clock. Applies [`OidcPolicy::constraints`] last.
///
/// # Errors
///
/// [`OidcError`] ([`OidcError::ClaimNotAllowed`] for a verified token the
/// constraints refuse). Every variant should map to the same flat `invalid_grant`
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
    let jti = claims
        .jti
        .filter(|s| !s.is_empty())
        .ok_or(OidcError::MissingClaim("jti"))?;
    let accept_until = exp.saturating_add(policy.leeway_secs.min(crate::oidc::MAX_LEEWAY_SECS));
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
    let repository_id = claims
        .repository_id
        .as_deref()
        .and_then(normalise_github_id)
        .ok_or(OidcError::MissingClaim("repository_id"))?;
    let repository_owner_id = claims
        .repository_owner_id
        .as_deref()
        .and_then(normalise_github_id)
        .ok_or(OidcError::MissingClaim("repository_owner_id"))?;
    // Ids are valid here, so `None` means a misconfigured label — which
    // `AuthContextBuilder::build` already refuses. Fail closed, never panic.
    let subject = workload_subject_key(&policy.subject_ns, &repository_owner_id, &repository_id)
        .ok_or_else(|| {
            OidcError::Jwks(format!(
                "invalid workload subject label {:?}",
                policy.subject_ns
            ))
        })?;
    let claims = WorkloadClaims {
        repository_id,
        repository_owner_id,
        repository,
        repository_owner,
        git_ref: claims.git_ref,
        ref_type: claims.ref_type,
        ref_protected: claims.ref_protected,
        environment: claims.environment,
        event_name: claims.event_name,
        workflow: claims.workflow,
        job_workflow_ref: claims.job_workflow_ref,
        runner_environment: claims.runner_environment,
        run_id: claims.run_id,
        sub,
        exp,
        jti,
        accept_until,
    };
    policy.constraints.check(&claims)?;
    Ok(WorkloadIdentity { subject, claims })
}

/// An issuer of workload tokens forgs can exchange for a session.
#[async_trait::async_trait]
pub trait WorkloadIssuer: Send + Sync {
    /// A stable name for logs and audit (`github-actions`). Must be
    /// **unique** among the configured issuers.
    fn name(&self) -> &str;

    /// The issuer label every subject this issuer verifies carries (the
    /// namespace slot of `<label>/workload:id:…`). Must pass
    /// [`forgs::subject::valid_workload_ns`] and be **unique** among the
    /// configured issuers, so two issuers never share a subject.
    fn subject_ns(&self) -> &str;

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
    use crate::identity::IdpError;
    use crate::oidc::{JwksCache, OidcError};

    /// The GitHub Actions [`WorkloadIssuer`]: verification over a
    /// [`JwksCache`], with one forced refresh on an unknown `kid`.
    #[derive(Debug)]
    pub struct GithubActionsIssuer {
        name: String,
        policy: OidcPolicy,
        jwks: JwksCache,
    }

    impl GithubActionsIssuer {
        /// github.com's issuer and JWKS, for `audience`.
        ///
        /// # Panics
        ///
        /// Never: the issuer and JWKS URLs are constants that pass the check
        /// (pinned by a test).
        #[must_use]
        pub fn new(audience: impl Into<String>) -> Self {
            Self::with_parts(
                OidcPolicy::github_actions(audience),
                JwksCache::new(
                    GHA_JWKS_URL,
                    JwksCache::DEFAULT_REFRESH_AFTER,
                    JwksCache::DEFAULT_MIN_REFETCH,
                )
                .expect("the constant GitHub JWKS URL is valid"),
            )
            .expect("the constant GitHub issuer is valid")
        }

        /// Explicit policy and cache (GHES, tests). The name defaults to
        /// `github-actions`; give a second issuer a distinct one with
        /// [`Self::with_name`].
        ///
        /// The JWKS URL is checked by [`JwksCache::new`]; this checks
        /// `policy.issuer`.
        ///
        /// # Errors
        ///
        /// [`IdpError::Url`] for an unusable issuer URL.
        pub fn with_parts(policy: OidcPolicy, jwks: JwksCache) -> Result<Self, IdpError> {
            crate::url::check_endpoint_url(&policy.issuer)?;
            Ok(Self {
                name: "github-actions".to_owned(),
                policy,
                jwks,
            })
        }

        /// The same issuer under another [`WorkloadIssuer::name`].
        #[must_use]
        pub fn with_name(self, name: impl Into<String>) -> Self {
            Self {
                name: name.into(),
                ..self
            }
        }

        /// The same issuer with `constraints` in place of the policy's
        /// (module docs, "Claim constraints").
        #[must_use]
        pub fn with_constraints(mut self, constraints: super::ClaimConstraints) -> Self {
            self.policy.constraints = constraints;
            self
        }

        /// The policy.
        #[must_use]
        pub fn policy(&self) -> &OidcPolicy {
            &self.policy
        }
    }

    #[async_trait::async_trait]
    impl WorkloadIssuer for GithubActionsIssuer {
        fn name(&self) -> &str {
            &self.name
        }

        fn subject_ns(&self) -> &str {
            &self.policy.subject_ns
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
            "repository_id": "67890",
            "repository_owner_id": "12345",
            "ref": "refs/heads/main",
            "ref_type": "branch",
            "ref_protected": "true",
            "event_name": "push",
            "environment": "hil",
            "runner_environment": "github-hosted",
            "workflow": "hil",
            "job_workflow_ref": "ariel-os/ariel-os/.github/workflows/hil.yml@refs/heads/main",
            "run_id": "12345",
            "jti": "c0ffee-1",
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
        assert_eq!(out.subject.to_string(), "gha/workload:id:12345/67890");
        assert_eq!(
            Some(out.subject),
            workload_subject_key("gha", "12345", "67890")
        );
        assert_eq!(out.claims.repository_id, "67890");
        assert_eq!(out.claims.repository_owner_id, "12345");
        assert_eq!(out.claims.repository, "ariel-os/ariel-os");
        assert_eq!(out.claims.repository_owner, "ariel-os");
        assert_eq!(out.claims.git_ref.as_deref(), Some("refs/heads/main"));
        assert_eq!(out.claims.workflow.as_deref(), Some("hil"));
        assert_eq!(out.claims.ref_type.as_deref(), Some("branch"));
        assert_eq!(out.claims.ref_protected, Some(true));
        assert_eq!(out.claims.event_name.as_deref(), Some("push"));
        assert_eq!(out.claims.environment.as_deref(), Some("hil"));
        assert_eq!(
            out.claims.runner_environment.as_deref(),
            Some("github-hosted")
        );
        assert_eq!(out.claims.run_id.as_deref(), Some("12345"));
        assert_eq!(out.claims.exp, 2_000);
        assert_eq!(out.claims.jti, "c0ffee-1");
        assert_eq!(out.claims.accept_until, 2_060);
    }

    #[test]
    fn a_missing_or_empty_jti_is_refused() {
        let keys = jwks(&[("k1", KEY_A_N)]);
        let mut c = claims();
        c["jti"] = json!("");
        assert_eq!(
            verify(&sign("k1", KEY_A_DER_B64, &c), &keys, 1_000),
            Err(OidcError::MissingClaim("jti"))
        );
        c.as_object_mut().unwrap().remove("jti");
        assert_eq!(
            verify(&sign("k1", KEY_A_DER_B64, &c), &keys, 1_000),
            Err(OidcError::MissingClaim("jti"))
        );
    }

    #[test]
    fn accept_until_uses_the_clamped_leeway_and_a_future_iat_is_refused() {
        let keys = jwks(&[("k1", KEY_A_N)]);
        let lax = OidcPolicy {
            leeway_secs: 10_000,
            ..policy()
        };
        let out = verify_github_actions(&sign("k1", KEY_A_DER_B64, &claims()), &keys, &lax, 1_000)
            .unwrap();
        assert_eq!(
            out.claims.accept_until,
            2_000 + crate::oidc::MAX_LEEWAY_SECS
        );
        let mut c = claims();
        c["iat"] = json!(1_500u64);
        assert_eq!(
            verify(&sign("k1", KEY_A_DER_B64, &c), &keys, 1_000),
            Err(OidcError::NotYetValid)
        );
    }

    fn verify_with(c: &serde_json::Value, constraints: ClaimConstraints) -> Result<(), OidcError> {
        let p = OidcPolicy {
            constraints,
            ..policy()
        };
        verify_github_actions(
            &sign("k1", KEY_A_DER_B64, c),
            &jwks(&[("k1", KEY_A_N)]),
            &p,
            1_000,
        )
        .map(|_| ())
    }

    #[test]
    fn pull_request_target_is_denied_by_default() {
        assert_eq!(policy().constraints, ClaimConstraints::github_default());
        let mut c = claims();
        c["event_name"] = json!("pull_request_target");
        assert_eq!(
            verify_with(&c, ClaimConstraints::github_default()),
            Err(OidcError::ClaimNotAllowed("event_name"))
        );
        // A configured deny-list fails closed on a missing event_name.
        c.as_object_mut().unwrap().remove("event_name");
        assert_eq!(
            verify_with(&c, ClaimConstraints::github_default()),
            Err(OidcError::ClaimNotAllowed("event_name"))
        );
        // Explicitly unconstrained: anything goes.
        assert!(verify_with(&c, ClaimConstraints::default()).is_ok());
        assert_eq!(
            OidcError::ClaimNotAllowed("ref").label(),
            "oidc.reject.claim_not_allowed"
        );
    }

    #[test]
    fn claim_constraints_are_each_enforced_and_fail_closed() {
        let ok = claims();
        let all = ClaimConstraints {
            refs: vec!["refs/heads/main".into(), "refs/tags/v*".into()],
            environments: vec!["hil".into()],
            job_workflow_refs: vec!["ariel-os/ariel-os/.github/workflows/hil.yml@*".into()],
            events: vec!["push".into(), "release".into()],
            denied_events: vec!["pull_request_target".into()],
            require_ref_protected: true,
        };
        verify_with(&ok, all.clone()).unwrap();
        let mut tag = claims();
        tag["ref"] = json!("refs/tags/v1.2");
        verify_with(&tag, all.clone()).unwrap();
        for (claim, bad) in [
            ("ref", json!("refs/heads/feature")),
            ("ref", json!("refs/heads/main2")),
            ("ref", json!("")),
            ("environment", json!("staging")),
            (
                "job_workflow_ref",
                json!("ariel-os/ariel-os/.github/workflows/evil.yml@refs/heads/main"),
            ),
            ("event_name", json!("workflow_dispatch")),
            ("ref_protected", json!("false")),
            ("ref_protected", json!("yes")),
        ] {
            let mut c = claims();
            c[claim] = bad.clone();
            let label: &'static str = match claim {
                "ref" => "ref",
                "environment" => "environment",
                "job_workflow_ref" => "job_workflow_ref",
                "event_name" => "event_name",
                _ => "ref_protected",
            };
            assert_eq!(
                verify_with(&c, all.clone()),
                Err(OidcError::ClaimNotAllowed(label)),
                "{claim}={bad}"
            );
            // Absent fails closed too.
            let mut c = claims();
            c.as_object_mut().unwrap().remove(claim);
            assert_eq!(
                verify_with(&c, all.clone()),
                Err(OidcError::ClaimNotAllowed(label)),
                "{claim} absent"
            );
        }
        // A JSON bool is accepted for ref_protected.
        let mut c = claims();
        c["ref_protected"] = json!(true);
        verify_with(&c, all.clone()).unwrap();
        // Unconstrained claims stay optional.
        let mut bare = claims();
        for k in ["ref", "environment", "job_workflow_ref", "ref_protected"] {
            bare.as_object_mut().unwrap().remove(k);
        }
        verify_with(&bare, ClaimConstraints::github_default()).unwrap();
        assert!(pattern_matches("*", "x"));
        assert!(!pattern_matches("*", ""));
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
            ("repository_id", OidcError::MissingClaim("repository_id")),
            (
                "repository_owner_id",
                OidcError::MissingClaim("repository_owner_id"),
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
    fn malformed_ids_are_refused_and_integers_accepted() {
        let keys = jwks(&[("k1", KEY_A_N)]);
        for (claim, bad) in [
            ("repository_id", json!("abc")),
            ("repository_id", json!("01")),
            ("repository_id", json!(-1)),
            ("repository_id", json!(true)),
            ("repository_id", json!("")),
            ("repository_owner_id", json!("1 ")),
            ("repository_owner_id", json!(1.5)),
            ("repository_owner_id", json!(null)),
        ] {
            let mut c = claims();
            c[claim] = bad.clone();
            assert_eq!(
                verify(&sign("k1", KEY_A_DER_B64, &c), &keys, 1_000).unwrap_err(),
                OidcError::MissingClaim(claim),
                "{claim}={bad}"
            );
        }
        let mut c = claims();
        c["repository_id"] = json!(67_890);
        c["repository_owner_id"] = json!(12_345);
        let out = verify(&sign("k1", KEY_A_DER_B64, &c), &keys, 1_000).unwrap();
        assert_eq!(out.subject.to_string(), "gha/workload:id:12345/67890");
    }

    /// The subject follows the ids, not the name: a rename keeps it, and a
    /// repo recreated under a freed name gets a new one.
    #[test]
    fn the_subject_follows_ids_not_names() {
        let keys = jwks(&[("k1", KEY_A_N)]);
        let base = verify(&sign("k1", KEY_A_DER_B64, &claims()), &keys, 1_000)
            .unwrap()
            .subject;
        let mut renamed = claims();
        renamed["repository"] = json!("new-owner/new-name");
        renamed["repository_owner"] = json!("new-owner");
        let out = verify(&sign("k1", KEY_A_DER_B64, &renamed), &keys, 1_000).unwrap();
        assert_eq!(out.subject, base);
        assert_eq!(out.claims.repository, "new-owner/new-name");
        let mut squatted = claims();
        squatted["repository_id"] = json!("99999");
        squatted["repository_owner_id"] = json!("55555");
        let out = verify(&sign("k1", KEY_A_DER_B64, &squatted), &keys, 1_000).unwrap();
        assert_ne!(out.subject, base);
        assert_eq!(out.claims.repository, "ariel-os/ariel-os");
    }

    /// The same token under two issuers' labels is two subjects.
    #[test]
    fn issuer_labels_give_distinct_subjects() {
        let keys = jwks(&[("k1", KEY_A_N)]);
        let jwt = sign("k1", KEY_A_DER_B64, &claims());
        let gha = verify(&jwt, &keys, 1_000).unwrap().subject;
        let ghes_policy = OidcPolicy {
            subject_ns: "ghes-corp".to_owned(),
            ..policy()
        };
        let ghes = verify_github_actions(&jwt, &keys, &ghes_policy, 1_000)
            .unwrap()
            .subject;
        assert_ne!(gha, ghes);
        assert_eq!(ghes.to_string(), "ghes-corp/workload:id:12345/67890");
        // A misconfigured label fails closed rather than panicking.
        let bad = OidcPolicy {
            subject_ns: "Bad/ns".to_owned(),
            ..policy()
        };
        assert!(verify_github_actions(&jwt, &keys, &bad, 1_000).is_err());
        let custom = OidcPolicy::custom("https://ghes.example/_services/token", AUDIENCE, "ghes");
        assert_eq!(custom.subject_ns, "ghes");
        assert_eq!(custom.leeway_secs, 60);
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
    #[test]
    fn the_github_issuer_builds_and_bad_issuers_are_refused() {
        use crate::oidc::JwksCache;
        use std::time::Duration;
        let _ = GithubActionsIssuer::new(AUDIENCE);
        let mut bad = policy();
        bad.issuer = "http://evil.example".to_owned();
        let jwks =
            JwksCache::new("https://idp.example/jwks", Duration::ZERO, Duration::ZERO).unwrap();
        assert!(GithubActionsIssuer::with_parts(bad, jwks).is_err());
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
            JwksCache::new(stub.url("/jwks"), Duration::from_hours(1), Duration::ZERO).unwrap(),
        )
        .unwrap();
        assert_eq!(issuer.name(), "github-actions");
        assert_eq!(issuer.subject_ns(), "gha");
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
        assert_eq!(out.subject.to_string(), "gha/workload:id:12345/67890");
        assert_eq!(stub.count("/jwks"), 2);
        let strict = GithubActionsIssuer::new(AUDIENCE).with_constraints(ClaimConstraints {
            refs: vec!["refs/heads/main".into()],
            ..ClaimConstraints::default()
        });
        assert_eq!(strict.policy().constraints.refs, ["refs/heads/main"]);
        let renamed = GithubActionsIssuer::new(AUDIENCE).with_name("github-com");
        assert_eq!(renamed.name(), "github-com");
        assert_eq!(renamed.subject_ns(), "gha");
        assert_eq!(
            GithubActionsIssuer::new(AUDIENCE).policy().issuer,
            GHA_ISSUER
        );
    }
}
