//! App-defined, ordered role ladders.
//!
//! Roles are stored as labels and compared by rank. The default ladder is
//! `read < triage < write < maintain < admin`; fleet configures
//! `member < admin`. [`Role::satisfies`] compares by rank: a higher role
//! implies every lower one.
//!
//! Parsing is **fail closed**: an unknown label (a row written by a newer
//! ladder, a typo in config) is `None`, never a default role.

use std::fmt;

/// A rank on a [`RoleLadder`]. Only meaningful together with the ladder that
/// produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Role(u8);

impl Role {
    /// Whether this role satisfies a `required` minimum (`self >= required`).
    #[must_use]
    pub fn satisfies(self, required: Role) -> bool {
        self >= required
    }

    /// The rank, 0 being the lowest role.
    #[must_use]
    pub fn rank(self) -> u8 {
        self.0
    }
}

/// Why a [`RoleLadder`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoleLadderError {
    /// No roles at all.
    #[error("a role ladder needs at least one role")]
    Empty,
    /// More roles than fit a `u8` rank.
    #[error("a role ladder may have at most 255 roles")]
    TooMany,
    /// A label outside `[a-z_]+`.
    #[error("role label {0:?} must be non-empty [a-z_]")]
    BadLabel(String),
    /// A label appears twice.
    #[error("role label {0:?} appears twice")]
    Duplicate(String),
}

/// An ordered list of role labels, lowest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleLadder {
    labels: Vec<String>,
}

impl Default for RoleLadder {
    /// `read < triage < write < maintain < admin`.
    fn default() -> Self {
        Self::new(&["read", "triage", "write", "maintain", "admin"])
            .expect("the default ladder is valid")
    }
}

impl RoleLadder {
    /// Build a ladder from labels, lowest first.
    ///
    /// # Errors
    ///
    /// Returns [`RoleLadderError`] for an empty list, an invalid or duplicate
    /// label, or more than 255 roles.
    pub fn new(labels: &[&str]) -> Result<Self, RoleLadderError> {
        if labels.is_empty() {
            return Err(RoleLadderError::Empty);
        }
        if labels.len() > usize::from(u8::MAX) {
            return Err(RoleLadderError::TooMany);
        }
        for (i, l) in labels.iter().enumerate() {
            if l.is_empty() || !l.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
                return Err(RoleLadderError::BadLabel((*l).to_owned()));
            }
            if labels[..i].contains(l) {
                return Err(RoleLadderError::Duplicate((*l).to_owned()));
            }
        }
        Ok(Self {
            labels: labels.iter().map(|l| (*l).to_owned()).collect(),
        })
    }

    /// Parse a stored label. `None` for an unknown label: fail closed.
    #[must_use]
    pub fn parse(&self, label: &str) -> Option<Role> {
        self.labels
            .iter()
            .position(|l| l == label)
            .and_then(|i| u8::try_from(i).ok())
            .map(Role)
    }

    /// The label of `role`, or `None` if it is not on this ladder.
    #[must_use]
    pub fn label(&self, role: Role) -> Option<&str> {
        self.labels.get(usize::from(role.0)).map(String::as_str)
    }

    /// The lowest role.
    #[must_use]
    pub fn lowest(&self) -> Role {
        Role(0)
    }

    /// The highest role (what a namespace's creator gets).
    #[must_use]
    pub fn highest(&self) -> Role {
        // `new` guarantees 1..=255 labels.
        Role(u8::try_from(self.labels.len() - 1).unwrap_or(u8::MAX))
    }

    /// Every role, lowest first.
    pub fn roles(&self) -> impl Iterator<Item = Role> + '_ {
        (0..self.labels.len()).filter_map(|i| u8::try_from(i).ok().map(Role))
    }

    /// A displayable `(ladder, role)` pair.
    #[must_use]
    pub fn display(&self, role: Role) -> impl fmt::Display + '_ {
        DisplayRole(self, role)
    }
}

struct DisplayRole<'a>(&'a RoleLadder, Role);

impl fmt::Display for DisplayRole<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.label(self.1) {
            Some(l) => f.write_str(l),
            None => write!(f, "<role {}>", self.1 .0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ladder_orders_and_satisfies() {
        let l = RoleLadder::default();
        let read = l.parse("read").unwrap();
        let write = l.parse("write").unwrap();
        let admin = l.parse("admin").unwrap();
        assert!(read < write && write < admin);
        assert!(admin.satisfies(write));
        assert!(write.satisfies(write));
        assert!(!read.satisfies(write));
        assert_eq!(l.highest(), admin);
        assert_eq!(l.lowest(), read);
        assert_eq!(l.roles().count(), 5);
    }

    #[test]
    fn fleet_ladder_admin_implies_member() {
        let l = RoleLadder::new(&["member", "admin"]).unwrap();
        let member = l.parse("member").unwrap();
        let admin = l.parse("admin").unwrap();
        assert!(admin.satisfies(member));
        assert!(!member.satisfies(admin));
        assert_eq!(l.highest(), admin);
    }

    #[test]
    fn labels_round_trip_and_unknown_fails_closed() {
        let l = RoleLadder::default();
        for r in l.roles() {
            assert_eq!(l.parse(l.label(r).unwrap()), Some(r));
        }
        assert_eq!(l.parse("root"), None);
        assert_eq!(l.parse("Admin"), None);
        assert_eq!(l.parse(""), None);
        assert_eq!(l.label(Role(9)), None);
        assert_eq!(l.display(Role(4)).to_string(), "admin");
        assert_eq!(l.display(Role(9)).to_string(), "<role 9>");
    }

    #[test]
    fn bad_ladders_are_refused() {
        assert_eq!(RoleLadder::new(&[]), Err(RoleLadderError::Empty));
        assert_eq!(
            RoleLadder::new(&["a", "a"]),
            Err(RoleLadderError::Duplicate("a".into()))
        );
        assert_eq!(
            RoleLadder::new(&["Admin"]),
            Err(RoleLadderError::BadLabel("Admin".into()))
        );
        assert_eq!(
            RoleLadder::new(&[""]),
            Err(RoleLadderError::BadLabel(String::new()))
        );
    }
}
