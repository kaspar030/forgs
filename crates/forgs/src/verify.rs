//! Bearer-token verification: string in, authenticated identity out.
//!
//! The token's prefix decides which table is consulted, so this is one lookup,
//! not a search. Existence and expiry are checked here; **authorization is
//! not** — that is [`crate::authz`] plus the server's membership lookups,
//! operating on the `Subject` built from [`Authenticated`].
//!
//! # No oracle
//!
//! [`AuthError`] distinguishes malformed / unknown / expired / wrong-kind so the
//! server can *audit* precisely. Every variant must map to the same generic
//! 401 (or 403) response body: the caller learns that its credential did not
//! work, not why. Diagnosability lives in the audit log and in the client's own
//! local error text.
//!
//! # Audit labels
//!
//! [`AuthError::label`] is a fixed `&'static str` per variant
//! (`auth.reject.unknown` for every kind); the kind involved, including an app
//! kind's label, is available separately from [`AuthError::kind`]. fleet's
//! distinct `auth.reject.node_unknown` becomes `auth.reject.unknown` with
//! `kind() == Some(node)`.

use crate::store::{ApiKeyRecord, DeviceSecretRecord, RefreshRecord, TokenStore};
use crate::subject::SubjectKey;
use crate::token::{OpaqueToken, TokenError, TokenFormat, TokenHash, TokenKind, TokenUse};

/// Why a bearer token was rejected.
///
/// Detail for the audit log — **never** for the response body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// No bearer credential was present.
    #[error("missing bearer credential")]
    Missing,
    /// The credential did not parse as a token of this format.
    #[error("malformed bearer credential: {0}")]
    Malformed(TokenError),
    /// The credential parsed but matched no row (revoked, swept, or forged).
    #[error("unknown {0} token")]
    Unknown(TokenKind),
    /// The credential matched a row that has expired.
    #[error("expired {0} token")]
    Expired(TokenKind),
    /// A valid credential of the wrong kind for this route.
    #[error("{got} token is not valid on this route")]
    WrongKind {
        /// The kind presented.
        got: TokenKind,
    },
    /// The credential store failed. Fails closed.
    #[error("credential store error: {0}")]
    Store(String),
}

impl AuthError {
    /// A short stable label for the audit log / structured logging.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            AuthError::Missing => "auth.reject.missing",
            AuthError::Malformed(_) => "auth.reject.malformed",
            AuthError::Unknown(_) => "auth.reject.unknown",
            AuthError::Expired(_) => "auth.reject.expired",
            AuthError::WrongKind { .. } => "auth.wrong_kind",
            AuthError::Store(_) => "auth.reject.store_error",
        }
    }

    /// The token kind involved, when the rejection is about one.
    #[must_use]
    pub fn kind(&self) -> Option<TokenKind> {
        match self {
            AuthError::Unknown(k) | AuthError::Expired(k) | AuthError::WrongKind { got: k } => {
                Some(*k)
            }
            AuthError::Missing | AuthError::Malformed(_) | AuthError::Store(_) => None,
        }
    }
}

/// A verified connection credential.
///
/// Deliberately **not** a [`crate::subject::Subject`]: the server turns this
/// into a `Subject` at its single resolution seam, adding the namespace the
/// request targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// Which credential was presented.
    pub kind: TokenKind,
    /// Who it speaks for: `user:<id>` for a session, the stored subject for a
    /// workload or app token.
    pub subject: SubjectKey,
    /// Expiry, epoch seconds, if the credential has one.
    pub expires: Option<u64>,
    /// The hash the credential matched, for rotation bookkeeping and audit.
    pub hash: TokenHash,
    /// When the current token was issued (epoch seconds), for app kinds with
    /// a rotation policy. `None` otherwise.
    pub token_issued_at: Option<u64>,
}

fn parse(format: &TokenFormat, s: &str) -> Result<OpaqueToken, AuthError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(AuthError::Missing);
    }
    format.parse(s).map_err(AuthError::Malformed)
}

/// Verify a bearer credential against the store.
///
/// `bearer` is the raw credential (the value *after* `Bearer `). `now` is epoch
/// seconds. Expiry is exclusive: `now == expires` is expired.
///
/// Every [`TokenUse::RedeemOnly`] kind — refresh tokens, API keys, device
/// secrets, and redeem-only app kinds — is deliberately **not** accepted here:
/// they are redeemed at a route rather than presented on a connection, so
/// treating any of them as a connection credential is
/// [`AuthError::WrongKind`], decided **from the prefix alone, before any store
/// access**.
///
/// # Errors
///
/// Returns [`AuthError`] on any rejection. Every variant maps to the same
/// generic response; the distinction is for auditing.
pub async fn authenticate(
    format: &TokenFormat,
    store: &impl TokenStore,
    bearer: &str,
    now: u64,
) -> Result<Authenticated, AuthError> {
    let token = parse(format, bearer)?;
    let kind = token.kind();
    if format.token_use(kind) == TokenUse::RedeemOnly {
        // No store lookup at all: the prefix decides.
        return Err(AuthError::WrongKind { got: kind });
    }
    let hash = token.hash();
    let live = |expires: u64| {
        if expires <= now {
            Err(AuthError::Expired(kind))
        } else {
            Ok(())
        }
    };
    match kind {
        TokenKind::Session => {
            let session = store
                .lookup_session(&hash)
                .await
                .map_err(AuthError::Store)?
                .ok_or(AuthError::Unknown(kind))?;
            live(session.expires)?;
            Ok(Authenticated {
                kind,
                subject: SubjectKey::user(session.user_id),
                expires: Some(session.expires),
                hash,
                token_issued_at: None,
            })
        }
        TokenKind::Workload => {
            let workload = store
                .lookup_workload(&hash)
                .await
                .map_err(AuthError::Store)?
                .ok_or(AuthError::Unknown(kind))?;
            live(workload.expires)?;
            Ok(Authenticated {
                kind,
                subject: workload.subject,
                expires: Some(workload.expires),
                hash,
                token_issued_at: None,
            })
        }
        TokenKind::App(app) => {
            let record = store
                .lookup_app(app, &hash)
                .await
                .map_err(AuthError::Store)?
                .ok_or(AuthError::Unknown(kind))?;
            if let Some(e) = record.expires {
                live(e)?;
            }
            Ok(Authenticated {
                kind,
                subject: record.subject,
                expires: record.expires,
                hash,
                token_issued_at: record.issued_at,
            })
        }
        // Core redeem-only kinds were refused above; this arm is unreachable
        // for a well-formed format but still fails closed.
        TokenKind::Refresh | TokenKind::ApiKey | TokenKind::DeviceSecret => {
            Err(AuthError::WrongKind { got: kind })
        }
    }
}

/// Parse `s` and require it to be of `want` kind.
fn parse_kind(format: &TokenFormat, s: &str, want: TokenKind) -> Result<TokenHash, AuthError> {
    let token = parse(format, s)?;
    if token.kind() != want {
        return Err(AuthError::WrongKind { got: token.kind() });
    }
    Ok(token.hash())
}

/// Verify an API key presented for redemption, without consuming it.
///
/// Consumption (for a single-use key) is a single atomic store operation the
/// server performs, so that a single-use key cannot be redeemed twice
/// concurrently; this call is the shape/expiry pre-check that lets the caller
/// reject cheaply and audit precisely.
///
/// # Errors
///
/// Returns [`AuthError`] if the key is missing, malformed, of the wrong kind,
/// unknown or expired.
pub async fn verify_api_key(
    format: &TokenFormat,
    store: &impl TokenStore,
    key: &str,
    now: u64,
) -> Result<(TokenHash, ApiKeyRecord), AuthError> {
    let hash = parse_kind(format, key, TokenKind::ApiKey)?;
    let record = store
        .lookup_api_key(&hash)
        .await
        .map_err(AuthError::Store)?
        .ok_or(AuthError::Unknown(TokenKind::ApiKey))?;
    if record.expires.is_some_and(|e| e <= now) {
        return Err(AuthError::Expired(TokenKind::ApiKey));
    }
    Ok((hash, record))
}

/// Verify a refresh token presented for redemption.
///
/// Modelled on [`verify_api_key`]: kind check, then existence, then expiry.
/// **There is no consume step to follow it**, and that absence is the design
/// rather than an omission — redemption is non-rotating so that N concurrent
/// redemptions (the sidecar case) all succeed and every minted session stays
/// independently valid. See [`TokenKind::Refresh`].
///
/// # Errors
///
/// Returns [`AuthError`] if the token is missing, malformed, of the wrong
/// kind, unknown or expired. Every variant must map to the same generic
/// rejection at the route.
pub async fn verify_refresh_token(
    format: &TokenFormat,
    store: &impl TokenStore,
    token: &str,
    now: u64,
) -> Result<(TokenHash, RefreshRecord), AuthError> {
    let hash = parse_kind(format, token, TokenKind::Refresh)?;
    let record = store
        .lookup_refresh_token(&hash)
        .await
        .map_err(AuthError::Store)?
        .ok_or(AuthError::Unknown(TokenKind::Refresh))?;
    if record.expires <= now {
        return Err(AuthError::Expired(TokenKind::Refresh));
    }
    Ok((hash, record))
}

/// Verify a device secret presented to the device-flow poll route.
///
/// Kind check, then existence, then expiry. What the pending row's *state* is
/// (pending, approved, denied) is the caller's business.
///
/// # Errors
///
/// Returns [`AuthError`] if the secret is missing, malformed, of the wrong
/// kind, unknown or expired.
pub async fn verify_device_secret(
    format: &TokenFormat,
    store: &impl TokenStore,
    secret: &str,
    now: u64,
) -> Result<(TokenHash, DeviceSecretRecord), AuthError> {
    let hash = parse_kind(format, secret, TokenKind::DeviceSecret)?;
    let record = store
        .lookup_device_secret(&hash)
        .await
        .map_err(AuthError::Store)?
        .ok_or(AuthError::Unknown(TokenKind::DeviceSecret))?;
    if record.expires <= now {
        return Err(AuthError::Expired(TokenKind::DeviceSecret));
    }
    Ok((hash, record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{ApiKeyId, NsNodeId, PendingId, UserId};
    use crate::store::fake::{BrokenStore, FakeStore, PanicStore};
    use crate::store::{AppRecord, SessionRecord, WorkloadRecord};
    use crate::subject::{normalise_repo, workload_subject_key, SubjectKind};
    use crate::token::AppKind;

    fn fleet() -> (TokenFormat, AppKind, AppKind) {
        let mut b = TokenFormat::builder("prf");
        let node = b.app_kind("node", "n", TokenUse::Connection);
        let node_device = b.app_kind("node_device", "nd", TokenUse::RedeemOnly);
        (b.build().unwrap(), node, node_device)
    }

    fn alice() -> UserId {
        UserId::from_parts(1, 1)
    }

    #[tokio::test]
    async fn session_token_resolves_and_expires() {
        let f = TokenFormat::default();
        let token = f.mint(TokenKind::Session);
        let store = FakeStore::default().with_session(
            &token.hash(),
            SessionRecord {
                user_id: alice(),
                expires: 1_000,
            },
        );
        let s = token.to_secret_string();
        let auth = authenticate(&f, &store, &s, 999).await.unwrap();
        assert_eq!(auth.kind, TokenKind::Session);
        assert_eq!(auth.subject, SubjectKey::user(alice()));
        assert_eq!(auth.expires, Some(1_000));
        assert_eq!(auth.hash, token.hash());
        // Boundary: expiry is exclusive — `now == expires` is already expired.
        assert_eq!(
            authenticate(&f, &store, &s, 1_000).await.unwrap_err(),
            AuthError::Expired(TokenKind::Session)
        );
        assert_eq!(
            authenticate(&f, &store, &s, 1_001).await.unwrap_err(),
            AuthError::Expired(TokenKind::Session)
        );
    }

    /// A workload token *is* a connection credential (unlike an API key), and
    /// its subject comes from the row.
    #[tokio::test]
    async fn workload_token_resolves_and_expires() {
        let f = TokenFormat::default();
        let token = f.mint(TokenKind::Workload);
        let subject = workload_subject_key(&normalise_repo("ariel-os/ariel-os").unwrap());
        let store = FakeStore::default().with_workload(
            &token.hash(),
            WorkloadRecord {
                subject: subject.clone(),
                expires: 1_000,
            },
        );
        let s = token.to_secret_string();
        let auth = authenticate(&f, &store, &s, 999).await.unwrap();
        assert_eq!(auth.kind, TokenKind::Workload);
        assert_eq!(auth.subject, subject);
        assert_eq!(
            authenticate(&f, &store, &s, 1_000).await.unwrap_err(),
            AuthError::Expired(TokenKind::Workload)
        );
        // An unknown workload token (the exchange row swept, or forged).
        let other = f.mint(TokenKind::Workload).to_secret_string();
        assert_eq!(
            authenticate(&f, &store, &other, 0).await.unwrap_err(),
            AuthError::Unknown(TokenKind::Workload)
        );
    }

    #[tokio::test]
    async fn app_connection_kind_resolves_through_lookup_app() {
        let (f, node, _) = fleet();
        let token = f.mint(TokenKind::App(node));
        let subject =
            SubjectKey::new(Some("ns"), SubjectKind::app("node").unwrap(), "rpi-1").unwrap();
        let store = FakeStore::default().with_app(
            node,
            &token.hash(),
            AppRecord {
                subject: subject.clone(),
                expires: None,
                issued_at: Some(100),
            },
        );
        let auth = authenticate(&f, &store, &token.to_secret_string(), 1_000)
            .await
            .unwrap();
        assert_eq!(auth.kind, TokenKind::App(node));
        assert_eq!(auth.subject, subject);
        assert_eq!(auth.token_issued_at, Some(100));
        assert_eq!(auth.expires, None);
    }

    /// A revoked app credential is a deleted row: unknown, and the audit layer
    /// can tell which kind from `kind()`.
    #[tokio::test]
    async fn revoked_app_token_is_unknown_with_its_kind() {
        let (f, node, _) = fleet();
        let token = f.mint(TokenKind::App(node));
        let err = authenticate(&f, &FakeStore::default(), &token.to_secret_string(), 10)
            .await
            .unwrap_err();
        assert_eq!(err, AuthError::Unknown(TokenKind::App(node)));
        assert_eq!(err.label(), "auth.reject.unknown");
        assert_eq!(err.kind().map(TokenKind::as_str), Some("node"));
    }

    #[tokio::test]
    async fn missing_and_malformed_are_distinguished_for_audit_only() {
        let f = TokenFormat::default();
        let store = FakeStore::default();
        let err = authenticate(&f, &store, "   ", 0).await.unwrap_err();
        assert_eq!(err, AuthError::Missing);
        assert_eq!(err.label(), "auth.reject.missing");
        let err = authenticate(&f, &store, "garbage", 0).await.unwrap_err();
        assert!(matches!(err, AuthError::Malformed(_)));
        assert_eq!(err.label(), "auth.reject.malformed");
        assert_eq!(err.kind(), None);
    }

    #[tokio::test]
    async fn store_errors_fail_closed() {
        let f = TokenFormat::default();
        let s = f.mint(TokenKind::Session).to_secret_string();
        let err = authenticate(&f, &BrokenStore, &s, 0).await.unwrap_err();
        assert_eq!(err, AuthError::Store("disk on fire".into()));
        assert_eq!(err.label(), "auth.reject.store_error");
    }

    /// Every redeem-only kind — core or app — is refused as a connection
    /// credential **from its prefix alone**: the store here panics on any
    /// access, so reaching it would fail the test.
    #[tokio::test]
    async fn redeem_only_kinds_are_rejected_before_any_store_access() {
        let (f, _, node_device) = fleet();
        for kind in [
            TokenKind::Refresh,
            TokenKind::ApiKey,
            TokenKind::DeviceSecret,
            TokenKind::App(node_device),
        ] {
            let s = f.mint(kind).to_secret_string();
            let err = authenticate(&f, &PanicStore, &s, 0).await.unwrap_err();
            assert_eq!(err, AuthError::WrongKind { got: kind });
            assert_eq!(err.label(), "auth.wrong_kind");
        }
    }

    /// Even with a matching row in the store, a refresh token is `WrongKind`
    /// rather than a successful session.
    #[tokio::test]
    async fn a_refresh_token_is_not_a_connection_credential() {
        let f = TokenFormat::default();
        let refresh = f.mint(TokenKind::Refresh);
        let store = FakeStore::default().with_refresh_token(
            &refresh.hash(),
            RefreshRecord {
                user_id: alice(),
                expires: 9_999,
            },
        );
        assert_eq!(
            authenticate(&f, &store, &refresh.to_secret_string(), 0)
                .await
                .unwrap_err(),
            AuthError::WrongKind {
                got: TokenKind::Refresh
            }
        );
    }

    #[tokio::test]
    async fn refresh_token_verification_checks_kind_and_expiry() {
        let f = TokenFormat::default();
        let refresh = f.mint(TokenKind::Refresh);
        let store = FakeStore::default().with_refresh_token(
            &refresh.hash(),
            RefreshRecord {
                user_id: alice(),
                expires: 500,
            },
        );
        let s = refresh.to_secret_string();
        let (hash, record) = verify_refresh_token(&f, &store, &s, 499).await.unwrap();
        assert_eq!(hash, refresh.hash());
        assert_eq!(record.user_id, alice());
        // Expiry is exclusive, as everywhere else.
        assert_eq!(
            verify_refresh_token(&f, &store, &s, 500).await.unwrap_err(),
            AuthError::Expired(TokenKind::Refresh)
        );
        // Redemption does not consume: verifying twice keeps working.
        assert!(verify_refresh_token(&f, &store, &s, 400).await.is_ok());
        assert!(verify_refresh_token(&f, &store, &s, 400).await.is_ok());
        // A session token offered where a refresh token is expected — the
        // mix-up a `refresh_token` config field invites. No store access.
        let session = f.mint(TokenKind::Session).to_secret_string();
        assert_eq!(
            verify_refresh_token(&f, &PanicStore, &session, 0)
                .await
                .unwrap_err(),
            AuthError::WrongKind {
                got: TokenKind::Session
            }
        );
        let other = f.mint(TokenKind::Refresh).to_secret_string();
        assert_eq!(
            verify_refresh_token(&f, &store, &other, 0)
                .await
                .unwrap_err(),
            AuthError::Unknown(TokenKind::Refresh)
        );
        assert_eq!(
            verify_refresh_token(&f, &store, "", 0).await.unwrap_err(),
            AuthError::Missing
        );
    }

    #[tokio::test]
    async fn api_key_verification_checks_kind_and_expiry() {
        let f = TokenFormat::default();
        let key = f.mint(TokenKind::ApiKey);
        let record = ApiKeyRecord {
            id: ApiKeyId::from_parts(1, 1),
            ns: NsNodeId::from_parts(2, 2),
            purpose: "ci".into(),
            single_use: true,
            expires: Some(500),
            subject_name: None,
            created_by: Some(alice()),
        };
        let store = FakeStore::default().with_api_key(&key.hash(), record.clone());
        let s = key.to_secret_string();
        let (hash, got) = verify_api_key(&f, &store, &s, 499).await.unwrap();
        assert_eq!(hash, key.hash());
        assert_eq!(got, record);
        assert_eq!(
            verify_api_key(&f, &store, &s, 500).await.unwrap_err(),
            AuthError::Expired(TokenKind::ApiKey)
        );
        let session = f.mint(TokenKind::Session).to_secret_string();
        assert_eq!(
            verify_api_key(&f, &store, &session, 0).await.unwrap_err(),
            AuthError::WrongKind {
                got: TokenKind::Session
            }
        );
        // A key with no expiry never expires.
        let forever = f.mint(TokenKind::ApiKey);
        let store = store.with_api_key(
            &forever.hash(),
            ApiKeyRecord {
                expires: None,
                ..record
            },
        );
        assert!(
            verify_api_key(&f, &store, &forever.to_secret_string(), u64::MAX)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn device_secret_verification_checks_kind_and_expiry() {
        let f = TokenFormat::default();
        let secret = f.mint(TokenKind::DeviceSecret);
        let store = FakeStore::default().with_device_secret(
            &secret.hash(),
            DeviceSecretRecord {
                id: PendingId::from_parts(3, 3),
                expires: 100,
            },
        );
        let s = secret.to_secret_string();
        let (_, rec) = verify_device_secret(&f, &store, &s, 99).await.unwrap();
        assert_eq!(rec.id, PendingId::from_parts(3, 3));
        assert_eq!(
            verify_device_secret(&f, &store, &s, 100).await.unwrap_err(),
            AuthError::Expired(TokenKind::DeviceSecret)
        );
        let refresh = f.mint(TokenKind::Refresh).to_secret_string();
        assert_eq!(
            verify_device_secret(&f, &store, &refresh, 0)
                .await
                .unwrap_err(),
            AuthError::WrongKind {
                got: TokenKind::Refresh
            }
        );
    }
}
