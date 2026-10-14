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
    /// Any [`ClientError`] from `POST /auth/device/start`.
    pub async fn start(client: &ForgsClient) -> Result<Self, ClientError> {
        let start = client.device_start().await?;
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

    /// How long the flow lives, as the server reported it.
    #[must_use]
    pub fn expires_in(&self) -> Duration {
        Duration::from_secs(self.start.expires_in)
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
        let lifetime = match self.start.expires_in {
            0 => policy.default_expires_in,
            s => Duration::from_secs(s),
        };
        let deadline = self.started_at + lifetime;
        let mut interval = Duration::from_secs(self.start.interval).max(policy.min_interval);
        let mut transport_failures = 0_u32;

        loop {
            if Instant::now() >= deadline {
                return Err(DeviceLoginError::Expired);
            }
            tokio::time::sleep(interval).await;

            match client.device_poll(&self.start.device_secret).await {
                Ok(outcome) => {
                    transport_failures = 0;
                    match outcome {
                        DevicePollResponse::Pending => {}
                        DevicePollResponse::SlowDown => {
                            interval = interval.saturating_add(policy.slow_down_step);
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
}
