//! The CLI device-login driver against forgs' own device authorization
//! server (docs/design.md §4, "CLI login is forgs' own device flow").
//!
//! ```text
//! DeviceLogin::start  → POST /auth/device/start → show user_code + verification_uri
//! DeviceLogin::wait   → POST /auth/device/poll, every `interval`, until an outcome
//! ```
//!
//! Nothing here prints: the caller shows [`DeviceLogin::verification_uri`]
//! and [`DeviceLogin::user_code`] (print them **before** trying to open a
//! browser — on a headless box the printed code is the whole interface; see
//! [`crate::cli::should_try_browser`]).

use std::time::{Duration, Instant};

use forgs::api::{DevicePollResponse, DeviceStartResponse, TokenResponse};

use crate::client::ForgsClient;
use crate::error::ClientError;
use crate::secret::Secret;

/// Longest flow lifetime honoured, whatever the server reports.
pub const MAX_EXPIRES_IN: Duration = Duration::from_hours(1);
/// Longest poll interval honoured (before [`PollPolicy::min_interval`]).
pub const MAX_INTERVAL: Duration = Duration::from_mins(1);
/// Longest user code accepted from the server.
pub const MAX_USER_CODE_LEN: usize = 32;

/// Timing knobs for [`DeviceLogin::wait_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollPolicy {
    /// Floor on the poll interval, whatever the server asks for. Polling
    /// faster earns `slow_down`, which looks like a broken login.
    pub min_interval: Duration,
    /// How much a `slow_down` adds to the interval (RFC 8628 §3.5: additive,
    /// and permanent for this flow).
    pub slow_down_step: Duration,
    /// Lifetime assumed when the server reports `expires_in: 0`.
    pub default_expires_in: Duration,
    /// Consecutive transport failures tolerated before giving up. The user is
    /// mid-ceremony in a browser; one dropped packet must not make them start
    /// again, but a sustained run means the server is unreachable.
    pub max_transport_retries: u32,
}

impl Default for PollPolicy {
    fn default() -> Self {
        Self {
            min_interval: Duration::from_secs(5),
            slow_down_step: Duration::from_secs(5),
            default_expires_in: Duration::from_mins(15),
            max_transport_retries: 5,
        }
    }
}

/// A started device flow, waiting for the human.
pub struct DeviceLogin {
    start: DeviceStartResponse,
    started_at: Instant,
}

impl std::fmt::Debug for DeviceLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // DeviceStartResponse's own Debug redacts the device secret.
        f.debug_struct("DeviceLogin")
            .field("start", &self.start)
            .finish_non_exhaustive()
    }
}

impl DeviceLogin {
    /// Begin a device flow.
    ///
    /// # Errors
    ///
    /// Any [`ClientError`] from `POST /auth/device/start`, or
    /// [`ClientError::Malformed`] if the response is unsafe to show or open:
    /// a user code that is not short ASCII alphanumerics and `-`, or a
    /// verification URL that fails [`crate::cli::check_browser_url`], is on
    /// a foreign origin (see
    /// [`crate::client::ForgsClientBuilder::verification_origin`]), or is
    /// plain `http` while the client's base is `https`.
    pub async fn start(client: &ForgsClient) -> Result<Self, ClientError> {
        let start = client.device_start().await?;
        validate_start(client, &start)?;
        Ok(Self {
            start,
            started_at: Instant::now(),
        })
    }

    /// The code the human confirms in the browser (`ABCD-1234`).
    #[must_use]
    pub fn user_code(&self) -> &str {
        &self.start.user_code
    }

    /// Where the human goes. Carries no code.
    #[must_use]
    pub fn verification_uri(&self) -> &str {
        &self.start.verification_uri
    }

    /// The verification URI with the code pre-filled, if the server offers
    /// one — the better URL to open in a browser automatically.
    #[must_use]
    pub fn verification_uri_complete(&self) -> Option<&str> {
        self.start.verification_uri_complete.as_deref()
    }

    /// The URL to hand a browser: the pre-filled one if offered.
    #[must_use]
    pub fn browser_uri(&self) -> &str {
        self.verification_uri_complete()
            .unwrap_or_else(|| self.verification_uri())
    }

    /// How long the flow lives, as the server reported it, capped at
    /// [`MAX_EXPIRES_IN`].
    #[must_use]
    pub fn expires_in(&self) -> Duration {
        Duration::from_secs(self.start.expires_in).min(MAX_EXPIRES_IN)
    }

    /// [`DeviceLogin::wait_with`] under the default [`PollPolicy`].
    ///
    /// # Errors
    ///
    /// See [`DeviceLoginError`].
    pub async fn wait(self, client: &ForgsClient) -> Result<LoginSession, DeviceLoginError> {
        self.wait_with(client, PollPolicy::default()).await
    }

    /// Poll until the human approves or refuses, or the flow expires.
    ///
    /// # Errors
    ///
    /// See [`DeviceLoginError`].
    pub async fn wait_with(
        self,
        client: &ForgsClient,
        policy: PollPolicy,
    ) -> Result<LoginSession, DeviceLoginError> {
        let (deadline, mut interval) = timing(
            self.started_at,
            self.start.expires_in,
            self.start.interval,
            &policy,
        );
        let max_interval = MAX_INTERVAL.max(policy.min_interval);
        let mut transport_failures = 0_u32;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(DeviceLoginError::Expired);
            }
            // Never sleep past the deadline; the poll after it still runs,
            // since an approval may have landed in the meantime.
            tokio::time::sleep(interval.min(remaining)).await;

            match client.device_poll(&self.start.device_secret).await {
                Ok(outcome) => {
                    transport_failures = 0;
                    match outcome {
                        DevicePollResponse::Pending => {}
                        DevicePollResponse::SlowDown => {
                            interval = interval
                                .saturating_add(policy.slow_down_step)
                                .min(max_interval);
                        }
                        DevicePollResponse::Denied => return Err(DeviceLoginError::Denied),
                        DevicePollResponse::Expired => return Err(DeviceLoginError::Expired),
                        DevicePollResponse::Granted(tr) => return Ok(tr.into()),
                    }
                }
                Err(e @ ClientError::Rejected { .. }) => {
                    return Err(DeviceLoginError::Rejected(e));
                }
                Err(e @ ClientError::Url(_)) => return Err(DeviceLoginError::Unreachable(e)),
                Err(e) => {
                    transport_failures += 1;
                    if transport_failures > policy.max_transport_retries {
                        return Err(DeviceLoginError::Unreachable(e));
                    }
                }
            }
        }
    }
}

/// The flow's deadline and first poll interval, clamped so no server value
/// can overflow an `Instant` or stall the poll loop.
fn timing(
    started_at: Instant,
    expires_in: u64,
    interval: u64,
    policy: &PollPolicy,
) -> (Instant, Duration) {
    let lifetime = match expires_in {
        0 => policy.default_expires_in,
        s => Duration::from_secs(s),
    }
    .min(MAX_EXPIRES_IN);
    let deadline = started_at.checked_add(lifetime).unwrap_or(started_at);
    let interval = Duration::from_secs(interval)
        .min(MAX_INTERVAL)
        .max(policy.min_interval);
    (deadline, interval)
}

/// Refuse a device-start response whose user-facing strings could smuggle
/// terminal escapes or point the human (and their browser) somewhere else.
/// The messages never quote the offending value.
fn validate_start(client: &ForgsClient, start: &DeviceStartResponse) -> Result<(), ClientError> {
    let code = &start.user_code;
    if code.is_empty()
        || code.len() > MAX_USER_CODE_LEN
        || !code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(ClientError::Malformed(
            "device start: unusable user_code".to_owned(),
        ));
    }
    let check = |field: &str, url: &str| {
        let bad = || ClientError::Malformed(format!("device start: unsafe {field}"));
        let uri = crate::cli::check_browser_url(url).map_err(|_| bad())?;
        if uri.scheme_str() == Some("http") && !client.is_plain_http() {
            return Err(bad());
        }
        if !client.verification_origin_allowed(&uri) {
            return Err(bad());
        }
        Ok(())
    };
    check("verification_uri", &start.verification_uri)?;
    if let Some(complete) = &start.verification_uri_complete {
        check("verification_uri_complete", complete)?;
    }
    Ok(())
}

/// Why a device login did not produce a session. The messages are
/// human-readable and carry no secret.
#[derive(Debug, thiserror::Error)]
pub enum DeviceLoginError {
    /// The human refused in the browser.
    #[error("the login was refused in the browser")]
    Denied,
    /// The flow expired before it was approved.
    #[error("the login code expired before it was approved; run login again")]
    Expired,
    /// The server rejected a poll outright (e.g. an unknown device secret).
    #[error("the server rejected the login: {0}")]
    Rejected(ClientError),
    /// The server could not be reached for too many polls in a row.
    #[error("could not reach the server while waiting for approval: {0}")]
    Unreachable(ClientError),
}

/// The credentials a successful login yields.
#[derive(Clone, PartialEq, Eq)]
pub struct LoginSession {
    /// The session token.
    pub session_token: Secret,
    /// Session expiry (epoch seconds).
    pub expires: u64,
    /// The long-lived, non-rotating refresh token, if one was minted.
    pub refresh_token: Option<Secret>,
    /// The username, for display.
    pub username: Option<String>,
    /// The immutable user id.
    pub user_id: Option<String>,
}

impl From<TokenResponse> for LoginSession {
    fn from(tr: TokenResponse) -> Self {
        Self {
            session_token: tr.token.into(),
            expires: tr.expires,
            refresh_token: tr.refresh_token.map(Secret::from),
            username: tr.username,
            user_id: tr.user_id,
        }
    }
}

impl std::fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginSession")
            .field("session_token", &self.session_token)
            .field("expires", &self.expires)
            .field("refresh_token", &self.refresh_token)
            .field("username", &self.username)
            .field("user_id", &self.user_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_session_debug_is_redacted() {
        let s: LoginSession = TokenResponse {
            token: "SEKRIT-s".into(),
            expires: 9,
            username: Some("alice".into()),
            user_id: None,
            refresh_token: Some("SEKRIT-r".into()),
        }
        .into();
        let d = format!("{s:?}");
        assert!(!d.contains("SEKRIT"), "{d}");
        assert!(d.contains("alice"));
        assert_eq!(s.refresh_token.unwrap().expose(), "SEKRIT-r");
    }

    #[test]
    fn device_login_debug_is_redacted() {
        let d = DeviceLogin {
            start: DeviceStartResponse {
                device_secret: "SEKRIT".into(),
                user_code: "ABCD-1234".into(),
                verification_uri: "https://x/device".into(),
                verification_uri_complete: None,
                interval: 5,
                expires_in: 900,
            },
            started_at: Instant::now(),
        };
        let s = format!("{d:?}");
        assert!(!s.contains("SEKRIT"), "{s}");
        assert!(s.contains("ABCD-1234"));
        assert_eq!(d.browser_uri(), "https://x/device");
    }

    #[test]
    fn timing_is_clamped() {
        let p = PollPolicy::default();
        let now = Instant::now();
        let (deadline, interval) = timing(now, u64::MAX, u64::MAX, &p);
        assert_eq!(deadline - now, MAX_EXPIRES_IN);
        assert_eq!(interval, MAX_INTERVAL);
        let (deadline, interval) = timing(now, 0, 0, &p);
        assert_eq!(deadline - now, p.default_expires_in);
        assert_eq!(interval, p.min_interval);
        let (deadline, interval) = timing(now, 900, 7, &p);
        assert_eq!(deadline - now, Duration::from_mins(15));
        assert_eq!(interval, Duration::from_secs(7));
    }

    fn start_with(code: &str, uri: &str, complete: Option<&str>) -> DeviceStartResponse {
        DeviceStartResponse {
            device_secret: "s".into(),
            user_code: code.into(),
            verification_uri: uri.into(),
            verification_uri_complete: complete.map(Into::into),
            interval: 5,
            expires_in: 900,
        }
    }

    #[test]
    fn start_responses_are_validated() {
        let c = ForgsClient::new("https://auth.example/forgs", None).unwrap();
        let good = "https://auth.example/forgs/auth/device";
        let good_c = "https://auth.example/forgs/auth/device?code=ABCD-1234";
        assert!(validate_start(&c, &start_with("ABCD-1234", good, Some(good_c))).is_ok());
        assert!(validate_start(&c, &start_with("ABCD1234", good, None)).is_ok());

        let long = "A".repeat(MAX_USER_CODE_LEN + 1);
        for code in ["", "\u{1b}[2J", "AB CD", "ABCD\n", long.as_str()] {
            assert!(
                matches!(
                    validate_start(&c, &start_with(code, good, None)),
                    Err(ClientError::Malformed(_))
                ),
                "{code:?}"
            );
        }
        for uri in [
            "https://evil.example/x",
            "file:///etc/passwd",
            "http://auth.example/forgs/auth/device",
            "https://auth.example:8443/auth/device",
            "https://auth.example/a&b c",
            "https://auth.example/\u{1b}]8;;x",
            "-https://auth.example/",
        ] {
            for (u, comp) in [(uri, None), (good, Some(uri))] {
                let r = validate_start(&c, &start_with("ABCD-1234", u, comp));
                assert!(matches!(r, Err(ClientError::Malformed(_))), "{u} {comp:?}");
                let msg = r.unwrap_err().to_string();
                assert!(!msg.contains('\u{1b}') && !msg.contains("evil"), "{msg}");
            }
        }

        // An http base may get an http verification URL on its own origin.
        let c = ForgsClient::new("http://127.0.0.1:7000", None).unwrap();
        assert!(validate_start(
            &c,
            &start_with("ABCD-1234", "http://127.0.0.1:7000/auth/device", None)
        )
        .is_ok());
    }
}
