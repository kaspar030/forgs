//! [`ClientError`], the one error type for every request.

/// Errors from a request to a forgs server (or the GitHub Actions token
/// service).
///
/// Never carries a request or response body: a body may hold a credential,
/// and an error ends up in logs. What a rejection *means* is the caller's
/// business — [`crate::cli::describe`] turns codes into remediation text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The URL could not be parsed, had no host, or used an unsupported
    /// scheme.
    #[error("invalid server URL: {0}")]
    Url(String),
    /// The request could not be sent, or the response could not be read
    /// (including timeouts).
    #[error("transport error: {0}")]
    Transport(String),
    /// The server answered with a non-2xx status.
    ///
    /// Deliberately coarse, because the server's body is deliberately coarse
    /// (no oracle): the status and the machine-readable code from
    /// [`forgs::api::ErrorResponse`], or `unknown` if the body was not one.
    #[error("request rejected by the server ({status}): {code}")]
    Rejected {
        /// The HTTP status.
        status: u16,
        /// The error code, e.g. [`forgs::api::error_code::INVALID_GRANT`].
        code: String,
    },
    /// A 2xx response whose body was not what the route promises.
    #[error("malformed response: {0}")]
    Malformed(String),
}

impl ClientError {
    /// The server's error code, for a [`ClientError::Rejected`].
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Rejected { code, .. } => Some(code),
            _ => None,
        }
    }

    /// The HTTP status, for a [`ClientError::Rejected`].
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Rejected { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Whether retrying the same request might succeed: the server was not
    /// reached, or answered with something we could not read.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transport(_) | Self::Malformed(_))
    }

    /// A body-free description of a JSON decode failure.
    ///
    /// `serde_json`'s own message quotes offending values (`invalid type:
    /// string "…"`), and the value may be a token, so only the error class
    /// and position survive.
    pub(crate) fn malformed(what: &str, e: &serde_json::Error) -> Self {
        Self::Malformed(format!(
            "{what}: {:?} error at line {} column {}",
            e.classify(),
            e.line(),
            e.column()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_does_not_quote_the_body() {
        let e = serde_json::from_str::<forgs::api::TokenResponse>(
            r#"{"token": 1, "expires": "SEKRIT"}"#,
        )
        .unwrap_err();
        let m = ClientError::malformed("token response", &e);
        let e2 = serde_json::from_str::<forgs::api::TokenResponse>(r#"{"token": "SEKRIT"}"#)
            .unwrap_err();
        let m2 = ClientError::malformed("token response", &e2);
        for m in [m, m2] {
            let s = format!("{m} {m:?}");
            assert!(!s.contains("SEKRIT"), "{s}");
            assert!(m.is_transient());
        }
    }

    #[test]
    fn accessors() {
        let r = ClientError::Rejected {
            status: 401,
            code: "invalid_grant".into(),
        };
        assert_eq!(r.code(), Some("invalid_grant"));
        assert_eq!(r.status(), Some(401));
        assert!(!r.is_transient());
        assert_eq!(ClientError::Transport("x".into()).code(), None);
    }
}
