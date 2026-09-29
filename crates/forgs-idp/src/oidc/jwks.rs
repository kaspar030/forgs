//! The JWKS fetch + cache half (features `oidc` + `client`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;

use super::jwt::{parse_jwks, OidcError};
use crate::https;

/// The cached document plus when it was fetched.
#[derive(Default)]
struct State {
    keys: Option<Arc<JwkSet>>,
    fetched_at: Option<Instant>,
    /// When the last fetch of *any* kind was attempted, including one forced
    /// by an unknown `kid`. This is what bounds the amplification.
    last_attempt: Option<Instant>,
}

/// A refreshing cache over an issuer's JWKS endpoint.
///
/// Two properties, both load-bearing and both pinned by tests:
///
/// * a **key rotation** — a token carrying a `kid` the cached set does not
///   have — is picked up by exactly one extra fetch
///   ([`JwksCache::refresh_for_unknown_kid`]), rather than by waiting out the
///   refresh interval;
/// * **every** fetch, forced or ordinary, is rate limited by `min_refetch`.
///   The token-exchange and login-callback endpoints are unauthenticated, so
///   an attacker needs no valid token at all: without the floor, plain
///   requests against a forgs whose issuer is down would each become an
///   outbound request aimed at the issuer.
///
/// A failed fetch never flushes a good cached set: an issuer outage must not
/// take login down for as long as the cached keys remain valid.
pub struct JwksCache {
    url: String,
    refresh_after: Duration,
    min_refetch: Duration,
    inner: tokio::sync::Mutex<State>,
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksCache")
            .field("url", &self.url)
            .field("refresh_after", &self.refresh_after)
            .field("min_refetch", &self.min_refetch)
            .finish_non_exhaustive()
    }
}

impl JwksCache {
    /// Default ordinary staleness horizon.
    pub const DEFAULT_REFRESH_AFTER: Duration = Duration::from_secs(3600);
    /// Default floor between any two fetches.
    pub const DEFAULT_MIN_REFETCH: Duration = Duration::from_secs(60);

    /// Build a cache over `url`.
    ///
    /// `refresh_after` is the ordinary staleness horizon; `min_refetch` the
    /// floor between any two fetches.
    #[must_use]
    pub fn new(url: impl Into<String>, refresh_after: Duration, min_refetch: Duration) -> Self {
        Self {
            url: url.into(),
            refresh_after,
            min_refetch,
            inner: tokio::sync::Mutex::new(State::default()),
        }
    }

    /// The JWKS URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The current key set, refetching it if it is missing or stale.
    ///
    /// Rate-limited by `min_refetch` exactly as
    /// [`JwksCache::refresh_for_unknown_kid`] is (see the type docs).
    ///
    /// # Errors
    ///
    /// [`OidcError::Jwks`] only when there is *no* usable cached set; a
    /// stale-but-present set survives a failed refresh.
    pub async fn get(&self) -> Result<Arc<JwkSet>, OidcError> {
        let mut state = self.inner.lock().await;
        let is_stale = state
            .fetched_at
            .is_none_or(|at| at.elapsed() >= self.refresh_after);
        if !is_stale {
            if let Some(keys) = state.keys.as_ref() {
                return Ok(Arc::clone(keys));
            }
        }
        // Keyed on `last_attempt`, not `fetched_at`, so a *failing* issuer is
        // bounded too.
        if state
            .last_attempt
            .is_some_and(|at| at.elapsed() < self.min_refetch)
        {
            return match state.keys.as_ref() {
                Some(keys) => {
                    tracing::debug!("serving a stale JWKS: refetch is rate-limited");
                    Ok(Arc::clone(keys))
                }
                None => Err(OidcError::Jwks(
                    "no cached key set; refetch is rate-limited".to_owned(),
                )),
            };
        }
        match self.fetch(&mut state).await {
            Ok(keys) => Ok(keys),
            Err(e) => match state.keys.as_ref() {
                Some(keys) => {
                    tracing::warn!(error = %e, url = %self.url, "JWKS refresh failed; serving the cached set");
                    Ok(Arc::clone(keys))
                }
                None => Err(e),
            },
        }
    }

    /// Force a refresh because a token named a `kid` we do not have.
    ///
    /// Rate-limited to one fetch per `min_refetch`; over the limit the cached
    /// set comes back unchanged, so the caller simply refuses the token.
    ///
    /// # Errors
    ///
    /// As [`JwksCache::get`].
    pub async fn refresh_for_unknown_kid(&self) -> Result<Arc<JwkSet>, OidcError> {
        let mut state = self.inner.lock().await;
        if state
            .last_attempt
            .is_some_and(|at| at.elapsed() < self.min_refetch)
        {
            tracing::debug!("JWKS refetch suppressed by the rate limit");
            return match state.keys.as_ref() {
                Some(keys) => Ok(Arc::clone(keys)),
                None => Err(OidcError::Jwks("no cached key set".to_owned())),
            };
        }
        match self.fetch(&mut state).await {
            Ok(keys) => Ok(keys),
            Err(e) => match state.keys.as_ref() {
                Some(keys) => Ok(Arc::clone(keys)),
                None => Err(e),
            },
        }
    }

    /// Verify with the cached keys; on [`OidcError::UnknownKid`] force one
    /// refresh and retry once. The shape every caller wants.
    ///
    /// # Errors
    ///
    /// Whatever `verify` returns on the final attempt, or a JWKS error.
    pub async fn verify_with<T>(
        &self,
        verify: impl Fn(&JwkSet) -> Result<T, OidcError>,
    ) -> Result<T, OidcError> {
        let keys = self.get().await?;
        match verify(&keys) {
            Err(OidcError::UnknownKid(kid)) => {
                tracing::debug!(%kid, url = %self.url, "unknown key id; refreshing the JWKS");
                let fresh = self.refresh_for_unknown_kid().await?;
                verify(&fresh)
            }
            other => other,
        }
    }

    /// Fetch and install a fresh key set. Caller holds the lock.
    async fn fetch(&self, state: &mut State) -> Result<Arc<JwkSet>, OidcError> {
        state.last_attempt = Some(Instant::now());
        let resp = https::get(&self.url, None, "application/json")
            .await
            .map_err(|e| OidcError::Jwks(e.to_string()))?;
        if !resp.is_success() {
            return Err(OidcError::Jwks(format!("HTTP {}", resp.status)));
        }
        let keys = Arc::new(parse_jwks(&resp.body)?);
        state.keys = Some(Arc::clone(&keys));
        state.fetched_at = Some(Instant::now());
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{jwks_json, Reply, StubServer, KEY_A_N, KEY_B_N};

    fn has(set: &JwkSet, kid: &str) -> bool {
        set.find(kid).is_some()
    }

    #[tokio::test]
    async fn caches_then_refreshes_for_an_unknown_kid_once_per_floor() {
        let stub = StubServer::start(vec![(
            "/jwks".into(),
            Reply::json(&jwks_json(&[("a", KEY_A_N)])),
        )])
        .await;
        let cache = JwksCache::new(stub.url("/jwks"), Duration::from_secs(3600), Duration::ZERO);
        assert!(has(&cache.get().await.unwrap(), "a"));
        assert!(has(&cache.get().await.unwrap(), "a"));
        assert_eq!(stub.count("/jwks"), 1, "fresh set is served from cache");

        stub.set(
            "/jwks",
            Reply::json(&jwks_json(&[("a", KEY_A_N), ("b", KEY_B_N)])),
        );
        let fresh = cache.refresh_for_unknown_kid().await.unwrap();
        assert!(has(&fresh, "b"));
        assert_eq!(stub.count("/jwks"), 2);
    }

    #[tokio::test]
    async fn every_fetch_is_rate_limited() {
        let stub = StubServer::start(vec![(
            "/jwks".into(),
            Reply::json(&jwks_json(&[("a", KEY_A_N)])),
        )])
        .await;
        // Always stale, but a long floor.
        let cache = JwksCache::new(stub.url("/jwks"), Duration::ZERO, Duration::from_secs(3600));
        cache.get().await.unwrap();
        for _ in 0..5 {
            cache.get().await.unwrap();
            cache.refresh_for_unknown_kid().await.unwrap();
        }
        assert_eq!(stub.count("/jwks"), 1);
    }

    #[tokio::test]
    async fn a_failing_issuer_is_bounded_and_stale_beats_none() {
        let stub = StubServer::start(vec![(
            "/jwks".into(),
            Reply::status(503, "text/plain", "down"),
        )])
        .await;
        let cache = JwksCache::new(stub.url("/jwks"), Duration::ZERO, Duration::from_secs(3600));
        assert!(matches!(cache.get().await, Err(OidcError::Jwks(_))));
        for _ in 0..5 {
            assert!(matches!(cache.get().await, Err(OidcError::Jwks(_))));
        }
        assert_eq!(
            stub.count("/jwks"),
            1,
            "cold + failing is still one fetch per floor"
        );

        // Stale keys survive a failed refresh.
        stub.set("/jwks", Reply::json(&jwks_json(&[("a", KEY_A_N)])));
        let cache = JwksCache::new(stub.url("/jwks"), Duration::ZERO, Duration::ZERO);
        cache.get().await.unwrap();
        stub.set("/jwks", Reply::status(500, "text/plain", "boom"));
        assert!(has(&cache.get().await.unwrap(), "a"));
        assert!(has(&cache.refresh_for_unknown_kid().await.unwrap(), "a"));
    }

    #[tokio::test]
    async fn junk_is_a_jwks_error() {
        let stub = StubServer::start(vec![(
            "/jwks".into(),
            Reply::ok("application/json", "nope"),
        )])
        .await;
        let cache = JwksCache::new(stub.url("/jwks"), Duration::ZERO, Duration::ZERO);
        assert!(matches!(cache.get().await, Err(OidcError::Jwks(_))));
    }
}
