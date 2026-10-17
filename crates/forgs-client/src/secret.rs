//! [`Secret`]: a string that never shows up in `Debug` output and is wiped
//! on drop.

use zeroize::Zeroize;

/// A credential held client-side: a session token, refresh token, API key or
/// OIDC token.
///
/// `Debug` prints `Secret(<redacted>)` and there is deliberately no `Display`,
/// so a secret cannot reach a log line or an error message by accident; the
/// value is reachable only through [`Secret::expose`], which is easy to grep
/// for.
///
/// The buffer is overwritten with zeroes when the `Secret` is dropped
/// ([`zeroize`]); every clone is wiped on its own drop. That is best-effort
/// memory hygiene, not a guarantee: copies made elsewhere — the serialized
/// request body, hyper's buffers, `http::HeaderValue`, the kernel's socket
/// buffers, a `String` the caller built before wrapping it — are outside its
/// reach.
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

    /// Unwrap into the plain string. The returned `String` is **not** wiped
    /// on drop any more; that becomes the caller's job.
    #[must_use]
    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for Secret {}

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

    #[test]
    fn a_clone_survives_the_originals_drop() {
        let original = Secret::new("hunter2");
        let copy = original.clone();
        drop(original);
        assert_eq!(copy.expose(), "hunter2");
    }

    #[test]
    fn zeroize_empties_the_buffer() {
        // What `Drop` runs; observable without reading freed memory.
        let mut s = Secret::new("hunter2");
        s.0.zeroize();
        assert!(s.expose().is_empty());
    }
}
