//! [`Secret`]: a string that never shows up in `Debug` output.

/// A credential held client-side: a session token, refresh token, API key or
/// OIDC token.
///
/// `Debug` prints `Secret(<redacted>)` and there is deliberately no `Display`,
/// so a secret cannot reach a log line or an error message by accident; the
/// value is reachable only through [`Secret::expose`], which is easy to grep
/// for.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wrap a secret value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The secret itself. Every call site is a place the secret leaves this
    /// wrapper; keep them few.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Unwrap into the plain string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        assert_eq!(format!("{:?}", Some(s.clone())), "Some(Secret(<redacted>))");
        assert_eq!(s.expose(), "hunter2");
        assert_eq!(s.into_inner(), "hunter2");
    }
}
