//! Session renewal policy on top of the two refresh grants.

use forgs::api::TokenResponse;

use crate::client::ForgsClient;
use crate::error::ClientError;

/// Whether a session expiring at `expires` should be renewed at `now` (both
/// epoch seconds), leaving `margin` seconds of slack for clock skew and a
/// request in flight.
#[must_use]
pub fn needs_refresh(expires: u64, now: u64, margin: u64) -> bool {
    now.saturating_add(margin) >= expires
}

/// Renew a session.
///
/// Prefers [`ForgsClient::redeem_refresh_token`] — non-rotating, so safe to
/// race, and it works after the session has lapsed. Falls back to the
/// replacing [`ForgsClient::refresh_session`] when there is no refresh token,
/// or when the server rejects the redemption and a session token is at hand
/// (an older server that lacks the grant, or a revoked refresh token while
/// the session is still live).
///
/// # Errors
///
/// [`ClientError::Url`] if neither credential is given, else the error from
/// the last grant tried. A `401 invalid_grant` means "log in again".
pub async fn renew(
    client: &ForgsClient,
    session_token: Option<&str>,
    refresh_token: Option<&str>,
) -> Result<TokenResponse, ClientError> {
    match (refresh_token, session_token) {
        (Some(refresh), session) => match client.redeem_refresh_token(refresh).await {
            Ok(tr) => Ok(tr),
            // A server too old to know the grant rejects it as a bad request;
            // the still-valid session is the fallback. A transport failure is
            // not retried with the other grant: it would fail the same way.
            Err(e @ ClientError::Rejected { .. }) => match session {
                Some(session) => client.refresh_session(session).await,
                None => Err(e),
            },
            Err(e) => Err(e),
        },
        (None, Some(session)) => client.refresh_session(session).await,
        (None, None) => Err(ClientError::Url(
            "no session or refresh token to renew; log in first".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_margin() {
        assert!(!needs_refresh(1000, 100, 60));
        assert!(needs_refresh(1000, 940, 60));
        assert!(needs_refresh(1000, 2000, 0));
        assert!(needs_refresh(0, 0, 0));
        assert!(needs_refresh(u64::MAX, u64::MAX - 1, 60));
    }
}
