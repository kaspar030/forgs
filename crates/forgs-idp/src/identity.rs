//! The provider-neutral types: [`ExternalIdentity`], [`AuthRequest`],
//! [`ProviderTokens`], [`IdpError`] and the [`IdentityProvider`] trait.

use std::fmt;

use base64::Engine as _;
use rand_core::RngCore as _;
use sha2::Digest as _;

/// Who a provider says the user is.
///
/// The account key is `(provider, subject)`: the **configured instance name**
/// and the provider's **immutable** subject id (GitHub's numeric id, an OIDC
/// `sub`). Never the email and never the login — both are reassigned by
/// providers, and keying on either hands a departed user's account to whoever
/// picks the freed name or address up (design §4).
///
/// Only constructible through [`ExternalIdentity::verified`], which refuses an
/// identity without a verified email, so a value of this type always carries
/// one: `email_verified` is `true` on every constructed value and exists as a
/// field so the store can record it without re-deriving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalIdentity {
    provider: String,
    subject: String,
    email: String,
    email_verified: bool,
    suggested_username: Option<String>,
}

impl ExternalIdentity {
    /// Build an identity, refusing one without a verified email.
    ///
    /// `email` is trimmed but otherwise kept as the provider sent it:
    /// canonicalisation (case folding) is the store's job, which owns the
    /// uniqueness constraint it serves.
    ///
    /// # Errors
    ///
    /// [`IdpError::NoVerifiedEmail`] if `email` is absent or blank, or
    /// `email_verified` is false; [`IdpError::Malformed`] for an empty subject.
    pub fn verified(
        provider: impl Into<String>,
        subject: impl Into<String>,
        email: Option<String>,
        email_verified: bool,
        suggested_username: Option<String>,
    ) -> Result<Self, IdpError> {
        let provider = provider.into();
        let subject = subject.into();
        if subject.trim().is_empty() {
            return Err(IdpError::Malformed("empty provider subject".to_owned()));
        }
        let email = email.map(|e| e.trim().to_owned()).filter(|e| !e.is_empty());
        let (Some(email), true) = (email, email_verified) else {
            return Err(IdpError::NoVerifiedEmail { provider });
        };
        let suggested_username = suggested_username
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        Ok(Self {
            provider,
            subject,
            email,
            email_verified: true,
            suggested_username,
        })
    }

    /// The configured provider instance name (`github`, `codeberg`,
    /// `gitlab-work`).
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// The provider's immutable subject id.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The verified email address, trimmed, not canonicalised.
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Always `true`; see the type docs.
    #[must_use]
    pub fn email_verified(&self) -> bool {
        self.email_verified
    }

    /// The provider's login/handle, **only** as a suggestion for the username
    /// field at first login. Raw: it has not been through the username policy
    /// and must never be used as an identifier.
    #[must_use]
    pub fn suggested_username(&self) -> Option<&str> {
        self.suggested_username.as_deref()
    }
}

/// The per-login secrets of one authorization-code flow: `state`, `nonce` and
/// the PKCE verifier.
///
/// The caller (forgs-http) keeps these in a short-lived `HttpOnly` cookie or a
/// pending row, compares `state` on the callback, and hands the struct back to
/// [`IdentityProvider::complete`]. `Debug` redacts all three.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthRequest {
    /// Binds the callback to a login this server started (CSRF).
    pub state: String,
    /// Binds an OIDC `id_token` to this login (replay). Ignored by GitHub.
    pub nonce: String,
    /// The PKCE `code_verifier`; its S256 hash goes in the authorize URL.
    pub pkce_verifier: String,
}

impl AuthRequest {
    /// Mint fresh values: 32 random bytes each from the OS RNG, base64url
    /// without padding (43 characters, inside RFC 7636's 43..=128 range).
    #[must_use]
    pub fn generate() -> Self {
        Self {
            state: random_b64(),
            nonce: random_b64(),
            pkce_verifier: random_b64(),
        }
    }

    /// The S256 `code_challenge` for [`Self::pkce_verifier`].
    #[must_use]
    pub fn pkce_challenge(&self) -> String {
        pkce_challenge(&self.pkce_verifier)
    }
}

impl fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthRequest")
            .field("state", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("pkce_verifier", &"<redacted>")
            .finish()
    }
}

fn random_b64() -> String {
    let mut bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The `code_challenge` for a PKCE verifier: base64url-no-pad SHA-256, i.e.
/// RFC 7636's `S256` method.
#[must_use]
pub fn pkce_challenge(verifier: &str) -> String {
    let digest = sha2::Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// What a provider's token endpoint handed back for a code.
///
/// The access token is a credential for the user's account **at the
/// provider**, not at forgs. It is spent once — by
/// [`IdentityProvider::fetch_identity`], which takes this struct **by value**
/// and drops it — and never stored or logged. The type enforces as much of
/// that as a type can: no `Clone`, no `Serialize`, a redacting `Debug`, and
/// private fields with no accessor outside the crate.
pub struct ProviderTokens {
    pub(crate) access_token: String,
    pub(crate) id_token: Option<String>,
}

impl ProviderTokens {
    /// Wrap tokens (for custom [`IdentityProvider`] implementations and tests).
    #[must_use]
    pub fn new(access_token: String, id_token: Option<String>) -> Self {
        Self {
            access_token,
            id_token,
        }
    }

    /// Whether an `id_token` came back (OIDC providers only).
    #[must_use]
    pub fn has_id_token(&self) -> bool {
        self.id_token.is_some()
    }

    /// Consume into `(access_token, id_token)`, for a custom
    /// [`IdentityProvider::fetch_identity`]. Same rules apply: spend, then drop.
    #[must_use]
    pub fn into_parts(self) -> (String, Option<String>) {
        (self.access_token, self.id_token)
    }
}

impl fmt::Debug for ProviderTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderTokens")
            .field("access_token", &"<redacted>")
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Errors from a provider flow.
///
/// None of them carries a token: bodies echoed in [`IdpError::Http`] are the
/// provider's diagnostics from endpoints that do not return credentials on
/// failure.
#[derive(Debug, thiserror::Error)]
pub enum IdpError {
    /// The provider configuration is unusable.
    #[error("invalid provider configuration: {0}")]
    Config(String),
    /// A URL (configured or discovered) is unusable.
    #[error("invalid provider URL: {0}")]
    Url(String),
    /// The request could not be sent, timed out, or the body could not be read.
    #[error("provider transport error: {0}")]
    Transport(String),
    /// The provider answered with a non-2xx status.
    #[error("provider returned HTTP {status}: {body}")]
    Http {
        /// The HTTP status code.
        status: u16,
        /// The response body, lossily decoded and truncated.
        body: String,
    },
    /// The response was not the JSON shape expected.
    #[error("malformed provider response: {0}")]
    Malformed(String),
    /// The provider reported an OAuth-level error (`bad_verification_code`,
    /// `invalid_grant`, `incorrect_client_credentials`, …).
    #[error("provider OAuth error `{code}`{}", .description.as_ref().map(|d| format!(": {d}")).unwrap_or_default())]
    Oauth {
        /// The machine-readable `error` field.
        code: String,
        /// The human-readable `error_description`, when present.
        description: Option<String>,
    },
    /// The discovery document is unusable.
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
    /// The `id_token` did not verify.
    #[cfg(feature = "oidc")]
    #[error("id_token rejected: {0}")]
    IdToken(#[from] crate::oidc::OidcError),
    /// The provider did not assert a verified email address, so login is
    /// refused (design §4). The message is meant for the user.
    #[error(
        "`{provider}` did not provide a verified email address; verify an email \
         address with the provider (and make it your primary one) and try again"
    )]
    NoVerifiedEmail {
        /// The configured provider instance name.
        provider: String,
    },
}

impl IdpError {
    /// A short stable label for structured logging and audit rows.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            IdpError::Config(_) => "idp.config",
            IdpError::Url(_) => "idp.url",
            IdpError::Transport(_) => "idp.transport",
            IdpError::Http { .. } => "idp.http",
            IdpError::Malformed(_) => "idp.malformed",
            IdpError::Oauth { .. } => "idp.oauth",
            IdpError::Discovery(_) => "idp.discovery",
            #[cfg(feature = "oidc")]
            IdpError::IdToken(e) => e.label(),
            IdpError::NoVerifiedEmail { .. } => "idp.no_verified_email",
        }
    }
}

/// Render a response body for an error message: lossy UTF-8, capped so a
/// hostile or broken endpoint cannot fill the log.
#[cfg(feature = "client")]
pub(crate) fn body_text(bytes: &[u8]) -> String {
    const MAX: usize = 512;
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= MAX {
        return text.into_owned();
    }
    let mut end = MAX;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// One configured identity provider instance.
///
/// The browser flow is: [`IdentityProvider::authorization_url`] → the user
/// logs in at the provider → callback with `code` and `state` → the caller
/// checks `state` against its stored [`AuthRequest`] → [`IdentityProvider::complete`].
/// There is deliberately no device-flow method: forgs is its own device
/// authorization server and every provider is reached through the browser
/// (design §4).
///
/// `now` is epoch seconds from the caller's clock. The crate never reads the
/// wall clock itself, so a test's fixed clock is authoritative.
#[async_trait::async_trait]
pub trait IdentityProvider: Send + Sync {
    /// The configured instance name; becomes [`ExternalIdentity::provider`].
    fn name(&self) -> &str;

    /// The URL to redirect the browser to.
    ///
    /// `redirect_uri` must come from forgs' configured public URL, never from
    /// the request's `Host` header (host-header injection → account takeover).
    ///
    /// # Errors
    ///
    /// Implementation-specific; the built-in providers cannot fail here.
    fn authorization_url(&self, redirect_uri: &str, req: &AuthRequest) -> Result<String, IdpError>;

    /// Spend the callback's `code` at the token endpoint. `redirect_uri` must
    /// be byte-identical to the one passed to [`Self::authorization_url`].
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        pkce_verifier: &str,
    ) -> Result<ProviderTokens, IdpError>;

    /// Resolve the tokens to an identity, consuming (and dropping) them.
    async fn fetch_identity(
        &self,
        tokens: ProviderTokens,
        expected_nonce: &str,
        now: u64,
    ) -> Result<ExternalIdentity, IdpError>;

    /// [`Self::exchange_code`] then [`Self::fetch_identity`]. The caller must
    /// already have compared the callback's `state` with `req.state`.
    async fn complete(
        &self,
        code: &str,
        redirect_uri: &str,
        req: &AuthRequest,
        now: u64,
    ) -> Result<ExternalIdentity, IdpError> {
        let tokens = self
            .exchange_code(code, redirect_uri, &req.pkce_verifier)
            .await?;
        self.fetch_identity(tokens, &req.nonce, now).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_requires_a_verified_nonblank_email() {
        let ok = ExternalIdentity::verified(
            "github",
            "583231",
            Some("  octo@example.com ".to_owned()),
            true,
            Some("octocat".to_owned()),
        )
        .unwrap();
        assert_eq!(ok.provider(), "github");
        assert_eq!(ok.subject(), "583231");
        assert_eq!(ok.email(), "octo@example.com");
        assert!(ok.email_verified());
        assert_eq!(ok.suggested_username(), Some("octocat"));

        for (email, verified) in [
            (None, true),
            (Some(String::new()), true),
            (Some("   ".to_owned()), true),
            (Some("a@b.example".to_owned()), false),
            (None, false),
        ] {
            let err = ExternalIdentity::verified("codeberg", "7", email.clone(), verified, None)
                .unwrap_err();
            assert!(
                matches!(&err, IdpError::NoVerifiedEmail { provider } if provider == "codeberg"),
                "{email:?}/{verified}: {err:?}"
            );
            assert_eq!(err.label(), "idp.no_verified_email");
            assert!(err.to_string().contains("verified email"));
        }
        assert!(matches!(
            ExternalIdentity::verified("x", " ", Some("a@b".into()), true, None),
            Err(IdpError::Malformed(_))
        ));
    }

    #[test]
    fn blank_suggestions_are_dropped() {
        let id = ExternalIdentity::verified("x", "1", Some("a@b".into()), true, Some(" ".into()))
            .unwrap();
        assert_eq!(id.suggested_username(), None);
    }

    /// RFC 7636 §4.6's worked example.
    #[test]
    fn pkce_challenge_matches_rfc7636() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(!pkce_challenge("another").contains(['+', '/', '=']));
    }

    #[test]
    fn auth_requests_are_random_well_formed_and_redacted() {
        let a = AuthRequest::generate();
        let b = AuthRequest::generate();
        assert_ne!(a, b);
        for v in [&a.state, &a.nonce, &a.pkce_verifier] {
            assert_eq!(v.len(), 43);
            assert!(v
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
        }
        assert_ne!(a.state, a.nonce);
        let dbg = format!("{a:?}");
        assert!(
            !dbg.contains(&a.state) && !dbg.contains(&a.nonce) && !dbg.contains(&a.pkce_verifier)
        );
        assert_eq!(a.pkce_challenge(), pkce_challenge(&a.pkce_verifier));
    }

    #[test]
    fn provider_tokens_debug_redacts() {
        let t = ProviderTokens::new("gho_SECRET".to_owned(), Some("eyJ.SECRET.x".to_owned()));
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("SECRET"), "{dbg}");
        assert!(t.has_id_token());
    }

    #[cfg(feature = "client")]
    #[test]
    fn body_text_is_capped() {
        let long = "é".repeat(1000);
        let out = body_text(long.as_bytes());
        assert!(out.len() < 600);
        assert!(out.ends_with('…'));
    }
}
