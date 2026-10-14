//! Opaque, immutable identifiers.
//!
//! Every user, namespace node and credential has an opaque id that never
//! changes (docs/design.md §0). Paths and usernames are *handles*, resolved to
//! one of these ids once, at the point where a reference is stored (a grant, a
//! membership) — fleet's "rename-safe" rule, generalised.
//!
//! Each id is a [ULID](https://github.com/ulid/spec): 48 bits of millisecond
//! timestamp followed by 80 random bits, rendered as 26 Crockford base32
//! characters. Ids therefore sort by creation time, which keeps `SQLite`
//! B-tree inserts append-mostly.
//!
//! # Construction
//!
//! There is deliberately **no** `From<String>` or `Default`: an id is either
//! freshly generated (`generate(now_ms)`, the clock injected like everywhere
//! else in forgs) or parsed from its canonical rendering with [`UserId::parse`]
//! and friends, which reject anything that is not a well-formed ULID. Test
//! fixtures use the same production constructors (survey §5.4).
//!
//! Randomness comes from `rand_core::OsRng` rather than ulid's own generator
//! so that the dependency graph has one RNG stack (see the workspace
//! `Cargo.toml`).

use std::fmt;
use std::str::FromStr;

use ulid::Ulid;

/// Why a string did not parse as an id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// Not exactly 26 characters.
    #[error("id has the wrong length")]
    Length,
    /// A character outside the Crockford base32 alphabet.
    #[error("id contains an invalid character")]
    Char,
}

/// Parse a canonical ULID string.
fn parse_ulid(s: &str) -> Result<Ulid, IdError> {
    Ulid::from_string(s).map_err(|e| match e {
        ulid::DecodeError::InvalidLength => IdError::Length,
        ulid::DecodeError::InvalidChar => IdError::Char,
    })
}

/// Draw the 80 random bits of a fresh ULID from the OS.
///
/// # Panics
///
/// Panics if the OS random source fails, which is not a condition any caller
/// can meaningfully recover from — the same stance
/// [`crate::token::TokenFormat::mint`] takes.
fn random_u128() -> u128 {
    use rand_core::RngCore as _;
    let mut buf = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut buf);
    u128::from_le_bytes(buf)
}

macro_rules! ulid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Ulid);

        impl $name {
            /// Generate a fresh id stamped with `now_ms` (epoch milliseconds).
            ///
            /// # Panics
            ///
            /// Panics if the OS random source fails.
            #[must_use]
            pub fn generate(now_ms: u64) -> Self {
                Self(Ulid::from_parts(now_ms, random_u128()))
            }

            /// Build an id from explicit parts (timestamp, 80 random bits).
            ///
            /// Deterministic; meant for tests and for re-deriving an id, not
            /// for minting new ones.
            #[must_use]
            pub const fn from_parts(timestamp_ms: u64, random: u128) -> Self {
                Self(Ulid::from_parts(timestamp_ms, random))
            }

            /// Parse the canonical 26-character rendering.
            ///
            /// Case-insensitive, as Crockford base32 is; the rendering is
            /// always upper case.
            ///
            /// # Errors
            ///
            /// Returns [`IdError`] if `s` is not a well-formed ULID.
            pub fn parse(s: &str) -> Result<Self, IdError> {
                parse_ulid(s).map(Self)
            }

            /// The underlying ULID.
            #[must_use]
            pub const fn as_ulid(&self) -> Ulid {
                self.0
            }

            /// The creation timestamp embedded in the id (epoch milliseconds).
            #[must_use]
            pub const fn timestamp_ms(&self) -> u64 {
                self.0.timestamp_ms()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let mut buf = [0u8; ulid::ULID_LEN];
                s.serialize_str(self.0.array_to_str(&mut buf))
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
                Self::parse(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

ulid_id!(
    /// A user: the principal behind a username.
    ///
    /// Distinct from the id of the user's personal namespace node: a user and
    /// its personal node never share an id.
    UserId
);
ulid_id!(
    /// A node in the namespace tree (an org, a project, a forge, …).
    NsNodeId
);
ulid_id!(
    /// A link between a user and an external identity-provider subject.
    IdentityId
);
ulid_id!(
    /// An API key (fleet's "auth key"). Its secret is a separate token.
    ApiKeyId
);
ulid_id!(
    /// A grant: "node N's admin grants subject S ops O over selector X".
    GrantId
);
ulid_id!(
    /// A pending approval (device flow / pending registration).
    PendingId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_display_and_parse() {
        let id = UserId::generate(1_700_000_000_000);
        let s = id.to_string();
        assert_eq!(s.len(), 26);
        assert_eq!(UserId::parse(&s), Ok(id));
        assert_eq!(s.parse::<UserId>(), Ok(id));
        assert_eq!(UserId::parse(&s.to_ascii_lowercase()), Ok(id));
        assert_eq!(id.timestamp_ms(), 1_700_000_000_000);
    }

    #[test]
    fn serde_is_the_canonical_string() {
        let id = NsNodeId::from_parts(1, 2);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
        assert_eq!(serde_json::from_str::<NsNodeId>(&json).unwrap(), id);
        assert!(serde_json::from_str::<NsNodeId>("\"nope\"").is_err());
        assert!(serde_json::from_str::<NsNodeId>("42").is_err());
    }

    #[test]
    fn junk_is_rejected() {
        assert_eq!(UserId::parse(""), Err(IdError::Length));
        assert_eq!(UserId::parse("gh-42"), Err(IdError::Length));
        assert_eq!(
            UserId::parse("01D39ZY06FGSCTVN4T2V9PKHF!"),
            Err(IdError::Char)
        );
        // `U` is not in the Crockford alphabet.
        assert_eq!(
            UserId::parse("01D39ZY06FGSCTVN4T2V9PKHFU"),
            Err(IdError::Char)
        );
        assert_eq!(
            UserId::parse(" 01D39ZY06FGSCTVN4T2V9PKHFZ"),
            Err(IdError::Length)
        );
    }

    #[test]
    fn ids_order_by_time() {
        let a = GrantId::generate(1_000);
        let b = GrantId::generate(2_000);
        assert!(a < b);
        assert!(a.to_string() < b.to_string());
    }

    #[test]
    fn distinct_generations_are_distinct() {
        assert_ne!(PendingId::generate(5), PendingId::generate(5));
    }

    #[test]
    fn debug_names_the_type() {
        let id = ApiKeyId::from_parts(0, 0);
        assert_eq!(format!("{id:?}"), "ApiKeyId(00000000000000000000000000)");
    }
}
