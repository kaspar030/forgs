//! Username policy and the name-validation error shared with [`crate::schema`].
//!
//! A username is chosen by the user in forgs (docs/design.md §4) — never
//! derived from an identity provider's login — and it is also the name of the
//! user's personal namespace node, so it ends up in paths and URLs. The rules
//! follow fleet's `normalise_agent_name` reasoning:
//!
//! * **Case-folded.** `Alice` and `alice` must be one handle, or a rename and
//!   a lookup could disagree about who is meant.
//! * **`[a-z0-9-]` only.** No `/` (it is a path separator), no `:` (subject
//!   key separator), no `.` (so `.` / `..` and file-extension look-alikes are
//!   impossible), no `_` (GitHub-style handles; keeps URLs unambiguous).
//! * **Alphanumeric at both ends, no `--`.** A leading `-` reads as a flag in
//!   every CLI example that quotes the name; `--` and trailing `-` make
//!   look-alike handles (`bob-` vs `bob`).
//!
//! [`UsernamePolicy::canonicalise`] trims and lowercases and **never repairs
//! anything else**: a name that does not pass is refused with the rule named,
//! rather than silently becoming a different handle.

/// Why a name was refused. Names the violated rule, so the UI can say so.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// Empty after trimming.
    #[error("name is empty")]
    Empty,
    /// Shorter than the minimum.
    #[error("name is shorter than {min} characters")]
    TooShort {
        /// The minimum length.
        min: usize,
    },
    /// Longer than the maximum.
    #[error("name is longer than {max} characters")]
    TooLong {
        /// The maximum length.
        max: usize,
    },
    /// A character outside the allowed set.
    #[error("name contains the disallowed character {0:?}")]
    BadChar(char),
    /// The first character must be a letter or digit.
    #[error("name must start with a letter or digit")]
    BadStart,
    /// The last character must be a letter or digit.
    #[error("name must end with a letter or digit")]
    BadEnd,
    /// Two consecutive hyphens.
    #[error("name must not contain \"--\"")]
    DoubleHyphen,
    /// `.` or `..`.
    #[error("name must not be \".\" or \"..\"")]
    DotName,
    /// On the reserved list.
    #[error("name is reserved")]
    Reserved,
    /// The kind's names are chosen by the app, not by users.
    #[error("names of this kind cannot be chosen by users")]
    NotUserNameable,
    /// No such namespace kind in the schema.
    #[error("unknown namespace kind {0:?}")]
    UnknownKind(String),
}

/// Length bounds for usernames. The charset rules are fixed (see the module
/// docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsernamePolicy {
    /// Minimum length, at least 1.
    pub min_len: usize,
    /// Maximum length.
    pub max_len: usize,
}

impl Default for UsernamePolicy {
    /// 1..=39, GitHub's bounds.
    fn default() -> Self {
        Self {
            min_len: 1,
            max_len: 39,
        }
    }
}

impl UsernamePolicy {
    /// Trim, lowercase, and validate a username.
    ///
    /// # Errors
    ///
    /// Returns the first [`NameError`] rule the name violates.
    pub fn canonicalise(&self, raw: &str) -> Result<String, NameError> {
        let name = raw.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err(NameError::Empty);
        }
        if let Some(c) = name
            .chars()
            .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
        {
            return Err(NameError::BadChar(c));
        }
        let len = name.len();
        if len < self.min_len.max(1) {
            return Err(NameError::TooShort {
                min: self.min_len.max(1),
            });
        }
        if len > self.max_len {
            return Err(NameError::TooLong { max: self.max_len });
        }
        if name.starts_with('-') {
            return Err(NameError::BadStart);
        }
        if name.ends_with('-') {
            return Err(NameError::BadEnd);
        }
        if name.contains("--") {
            return Err(NameError::DoubleHyphen);
        }
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalises_by_trimming_and_lowercasing_only() {
        let p = UsernamePolicy::default();
        assert_eq!(p.canonicalise("  Alice ").as_deref(), Ok("alice"));
        assert_eq!(p.canonicalise("k-9").as_deref(), Ok("k-9"));
        assert_eq!(p.canonicalise("0").as_deref(), Ok("0"));
    }

    #[test]
    fn names_the_violated_rule() {
        let p = UsernamePolicy::default();
        assert_eq!(p.canonicalise("   "), Err(NameError::Empty));
        assert_eq!(p.canonicalise("a_b"), Err(NameError::BadChar('_')));
        assert_eq!(p.canonicalise("a.b"), Err(NameError::BadChar('.')));
        assert_eq!(p.canonicalise("a/b"), Err(NameError::BadChar('/')));
        assert_eq!(p.canonicalise("a:b"), Err(NameError::BadChar(':')));
        assert_eq!(p.canonicalise("a b"), Err(NameError::BadChar(' ')));
        assert_eq!(p.canonicalise("naïve"), Err(NameError::BadChar('ï')));
        assert_eq!(p.canonicalise("-x"), Err(NameError::BadStart));
        assert_eq!(p.canonicalise("x-"), Err(NameError::BadEnd));
        assert_eq!(p.canonicalise("a--b"), Err(NameError::DoubleHyphen));
        assert_eq!(
            p.canonicalise(&"x".repeat(40)),
            Err(NameError::TooLong { max: 39 })
        );
        assert!(p.canonicalise(&"x".repeat(39)).is_ok());
        let strict = UsernamePolicy {
            min_len: 3,
            max_len: 10,
        };
        assert_eq!(
            strict.canonicalise("ab"),
            Err(NameError::TooShort { min: 3 })
        );
    }
}
