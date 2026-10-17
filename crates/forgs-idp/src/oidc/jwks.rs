//! The JWKS fetch + cache half (features `oidc` + `client`).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;

use super::jwt::{parse_jwks, OidcError};
use crate::https;
use crate::identity::IdpError;

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
/// Three properties, all load-bearing and all pinned by tests:
///
/// * a **key rotation** — a token carrying a `kid` the cached set does not
///   have — is picked up by exactly one extra fetch
///   ([`JwksCache::refresh_for_unknown_kid`]), rather than by waiting out the
///   refresh interval;
/// * **every** fetch, forced or ordinary, is rate limited by `min_refetch`.
///   The token-exchange and login-callback endpoints are unauthenticated, so
///   an attacker needs no valid token at all: without the floor, plain
///   requests against a forgs whose issuer is down would each become an
///   outbound request aimed at the issuer;
/// * fetches are **single-flight and never block readers**: the HTTP request
///   runs outside the state lock, bounded by `fetch_timeout`, and while it is
///   in flight every caller holding a cached set keeps using it. Only a cold
///   cache (or an unknown-`kid` refresh) waits for the in-flight fetch, so a
///   slow or tarpitting JWKS endpoint cannot stall logins.
///
/// A failed fetch never flushes a good cached set: an issuer outage must not
/// take login down for as long as the cached keys remain valid.
pub struct JwksCache {
    url: String,
    refresh_after: Duration,
    min_refetch: Duration,
    fetch_timeout: Duration,
    /// Held only briefly, never across an `.await`.
    state: Mutex<State>,
    /// Held for the duration of a fetch: the single flight.
    fetch_gate: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksCache")
            .field("url", &self.url)
            .field("refresh_after", &self.refresh_after)
            .field("min_refetch", &self.min_refetch)
            .field("fetch_timeout", &self.fetch_timeout)
            .finish_non_exhaustive()
    }
}

impl JwksCache {
    /// Default ordinary staleness horizon.
    pub const DEFAULT_REFRESH_AFTER: Duration = Duration::from_hours(1);
    /// Default floor between any two fetches.
    pub const DEFAULT_MIN_REFETCH: Duration = Duration::from_mins(1);
    /// Default bound on one whole JWKS fetch (connect, request and body).
    pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

    /// Build a cache over `url`.
    ///
    /// `refresh_after` is the ordinary staleness horizon; `min_refetch` the
    /// floor between any two fetches.
    ///
    /// # Errors
    ///
    /// [`IdpError::Url`] unless `url` passes
    /// [`check_endpoint_url`](crate::url::check_endpoint_url): a cleartext
    /// (non-loopback `http://`) JWKS would let anyone on the path substitute
    /// the keys.
    pub fn new(
        url: impl Into<String>,
        refresh_after: Duration,
        min_refetch: Duration,
    ) -> Result<Self, IdpError> {
        let url = url.into();
        crate::url::check_endpoint_url(&url)?;
        Ok(Self::build(url, refresh_after, min_refetch))
    }

    /// [`Self::new`] for a URL already known to pass the check.
    pub(crate) fn build(url: String, refresh_after: Duration, min_refetch: Duration) -> Self {
        Self {
            url,
            refresh_after,
            min_refetch,
            fetch_timeout: Self::DEFAULT_FETCH_TIMEOUT,
            state: Mutex::new(State::default()),
            fetch_gate: tokio::sync::Mutex::new(()),
        }
    }

    /// Replace the bound on one whole fetch ([`Self::DEFAULT_FETCH_TIMEOUT`]).
    #[must_use]
    pub fn with_fetch_timeout(mut self, timeout: Duration) -> Self {
        self.fetch_timeout = timeout;
        self
    }

    /// The JWKS URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    fn lock_state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn fresh(&self, state: &State) -> Option<Arc<JwkSet>> {
        let fresh = state
            .fetched_at
            .is_some_and(|at| at.elapsed() < self.refresh_after);
        if fresh {
            state.keys.clone()
        } else {
            None
        }
    }

    /// Keyed on `last_attempt`, not `fetched_at`, so a *failing* issuer is
    /// bounded too.
    fn rate_limited(&self, state: &State) -> bool {
        state
            .last_attempt
            .is_some_and(|at| at.elapsed() < self.min_refetch)
    }

    fn cached_or(state: &State, why: &str) -> Result<Arc<JwkSet>, OidcError> {
        state
            .keys
            .clone()
            .ok_or_else(|| OidcError::Jwks(why.to_owned()))
    }

    /// The current key set, refetching it if it is missing or stale.
    ///
    /// Rate-limited by `min_refetch` exactly as
    /// [`JwksCache::refresh_for_unknown_kid`] is (see the type docs). While
    /// another caller's fetch is in flight a cached set is served at once.
    ///
    /// # Errors
    ///
    /// [`OidcError::Jwks`] only when there is *no* usable cached set; a
    /// stale-but-present set survives a failed refresh.
    pub async fn get(&self) -> Result<Arc<JwkSet>, OidcError> {
        {
            let state = self.lock_state();
            if let Some(keys) = self.fresh(&state) {
                return Ok(keys);
            }
            if self.rate_limited(&state) {
                if state.keys.is_some() {
                    tracing::debug!("serving a stale JWKS: refetch is rate-limited");
                }
                return Self::cached_or(&state, "no cached key set; refetch is rate-limited");
            }
        }
        let Ok(gate) = self.fetch_gate.try_lock() else {
            // A fetch is in flight. Readers with a cached set never wait on it.
            if let Some(keys) = self.lock_state().keys.clone() {
                return Ok(keys);
            }
            // Cold: wait for that fetch and take its result rather than
            // issuing a second one.
            let _gate = self.fetch_gate.lock().await;
            return Self::cached_or(
                &self.lock_state(),
                "no cached key set; the JWKS fetch failed",
            );
        };
        let out = self.refresh(false).await;
        drop(gate);
        out
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
        {
            let state = self.lock_state();
            if self.rate_limited(&state) {
                tracing::debug!("JWKS refetch suppressed by the rate limit");
                return Self::cached_or(&state, "no cached key set");
            }
        }
        let gate = self.fetch_gate.lock().await;
        let out = self.refresh(true).await;
        drop(gate);
        out
    }

    /// Re-check under the state lock (another fetch may just have finished),
    /// then fetch with only the gate held and install the result. The caller
    /// holds `fetch_gate`.
    async fn refresh(&self, forced: bool) -> Result<Arc<JwkSet>, OidcError> {
        {
            let mut state = self.lock_state();
            if !forced {
                if let Some(keys) = self.fresh(&state) {
                    return Ok(keys);
                }
            }
            if self.rate_limited(&state) {
                return Self::cached_or(&state, "no cached key set; refetch is rate-limited");
            }
            state.last_attempt = Some(Instant::now());
        }
        let fetched = self.fetch_once().await;
        let mut state = self.lock_state();
        match fetched {
            Ok(set) => {
                let keys = Arc::new(set);
                state.keys = Some(Arc::clone(&keys));
                state.fetched_at = Some(Instant::now());
                Ok(keys)
            }
            Err(e) => match state.keys.as_ref() {
                Some(keys) => {
                    tracing::warn!(error = %e, url = %self.url, "JWKS refresh failed; serving the cached set");
                    Ok(Arc::clone(keys))
                }
                None => Err(e),
            },
        }
    }

    /// One bounded HTTP GET + parse. Touches no state.
    async fn fetch_once(&self) -> Result<JwkSet, OidcError> {
        let fetch = async {
            let resp = https::get(&self.url, None, "application/json")
                .await
                .map_err(|e| OidcError::Jwks(e.to_string()))?;
            if !resp.is_success() {
                return Err(OidcError::Jwks(format!("HTTP {}", resp.status)));
            }
            parse_jwks(&resp.body)
        };
        tokio::time::timeout(self.fetch_timeout, fetch)
            .await
            .map_err(|_| {
                OidcError::Jwks(format!("fetch timed out after {:?}", self.fetch_timeout))
            })?
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
                // `kid` is attacker-supplied: Debug-escape it (no log forging).
                tracing::debug!(kid = ?kid, url = %self.url, "unknown key id; refreshing the JWKS");
                let fresh = self.refresh_for_unknown_kid().await?;
                verify(&fresh)
            }
            other => other,
        }
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
        let cache =
            JwksCache::new(stub.url("/jwks"), Duration::from_hours(1), Duration::ZERO).unwrap();
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
        let cache =
            JwksCache::new(stub.url("/jwks"), Duration::ZERO, Duration::from_hours(1)).unwrap();
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
        let cache =
            JwksCache::new(stub.url("/jwks"), Duration::ZERO, Duration::from_hours(1)).unwrap();
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
        let cache = JwksCache::new(stub.url("/jwks"), Duration::ZERO, Duration::ZERO).unwrap();
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
        let cache = JwksCache::new(stub.url("/jwks"), Duration::ZERO, Duration::ZERO).unwrap();
        assert!(matches!(cache.get().await, Err(OidcError::Jwks(_))));
    }

    #[tokio::test]
    async fn the_url_is_checked() {
        assert!(matches!(
            JwksCache::new("http://evil.example/jwks", Duration::ZERO, Duration::ZERO),
            Err(IdpError::Url(_))
        ));
        assert!(matches!(
            JwksCache::new(
                "https://u:p@evil.example/jwks",
                Duration::ZERO,
                Duration::ZERO
            ),
            Err(IdpError::Url(_))
        ));
        assert!(JwksCache::new("https://idp.example/jwks", Duration::ZERO, Duration::ZERO).is_ok());
        assert!(JwksCache::new("http://127.0.0.1:1/jwks", Duration::ZERO, Duration::ZERO).is_ok());
    }

    #[tokio::test]
    async fn readers_keep_the_cached_set_while_a_slow_refresh_is_in_flight() {
        let stub = StubServer::start(vec![(
            "/jwks".into(),
            Reply::json(&jwks_json(&[("a", KEY_A_N)])),
        )])
        .await;
        let cache =
            Arc::new(JwksCache::new(stub.url("/jwks"), Duration::ZERO, Duration::ZERO).unwrap());
        cache.get().await.unwrap();
        stub.set(
            "/jwks",
            Reply::json(&jwks_json(&[("b", KEY_B_N)])).delayed(Duration::from_secs(2)),
        );
        let slow = tokio::spawn({
            let cache = Arc::clone(&cache);
            async move { cache.get().await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        for _ in 0..3 {
            let keys = tokio::time::timeout(Duration::from_millis(500), cache.get())
                .await
                .expect("a reader must not wait on the in-flight fetch")
                .unwrap();
            assert!(has(&keys, "a"));
        }
        assert_eq!(stub.count("/jwks"), 2, "one in-flight refresh, no pile-up");
        assert!(has(&slow.await.unwrap().unwrap(), "b"));
    }

    #[tokio::test]
    async fn the_fetch_timeout_bounds_a_tarpit() {
        let stub = StubServer::start(vec![(
            "/jwks".into(),
            Reply::json(&jwks_json(&[("a", KEY_A_N)])).delayed(Duration::from_secs(5)),
        )])
        .await;
        let cache = JwksCache::new(stub.url("/jwks"), Duration::ZERO, Duration::ZERO)
            .unwrap()
            .with_fetch_timeout(Duration::from_millis(200));
        let started = Instant::now();
        assert!(matches!(cache.get().await, Err(OidcError::Jwks(_))));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn concurrent_cold_gets_are_single_flighted() {
        let stub = StubServer::start(vec![(
            "/jwks".into(),
            Reply::json(&jwks_json(&[("a", KEY_A_N)])).delayed(Duration::from_millis(200)),
        )])
        .await;
        let cache = Arc::new(
            JwksCache::new(stub.url("/jwks"), Duration::from_hours(1), Duration::ZERO).unwrap(),
        );
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let cache = Arc::clone(&cache);
                tokio::spawn(async move { cache.get().await })
            })
            .collect();
        for h in handles {
            assert!(has(&h.await.unwrap().unwrap(), "a"));
        }
        assert_eq!(stub.count("/jwks"), 1);
    }
}
