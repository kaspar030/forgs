//! SSH public keys as a user credential (docs/design.md §3).
//!
//! A user registers OpenSSH public keys; a consumer's SSH server (git over
//! SSH, say) authenticates a connection by public key and asks forgs **whose**
//! key it is. This module is the pure half of that:
//!
//! * [`SshPublicKey`] parses and strictly validates a key, either from an
//!   `authorized_keys`-style line ([`SshPublicKey::parse_openssh`]) or from the
//!   raw wire blob an SSH library hands over ([`SshPublicKey::from_wire`]).
//! * [`SshFingerprint`] is the canonical lookup key, `SHA256:<base64>`,
//!   exactly what `ssh-keygen -lf` prints.
//! * [`authenticate_ssh_key`] maps a key to the `user:<id>` subject through
//!   the [`SshKeyStore`] seam, so the consumer evaluates membership and roles
//!   exactly as for a bearer session.
//!
//! # Accepted keys
//!
//! `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, and `ssh-rsa`
//! with a modulus of 3072 to 16384 bits. Refused: DSA, `nistp521`,
//! certificates (`*-cert-v01@openssh.com`), FIDO `sk-*` keys (a possible
//! follow-up), and anything unknown.
//!
//! # What is checked here, and what is not
//!
//! Validation is **structural**: the blob's type string matches, lengths are
//! exact, there are no trailing bytes, RSA integers are canonical and the
//! modulus is large enough. Whether an ECDSA point lies on its curve is not
//! checked: the SSH server verifies a signature with the key before it ever
//! asks forgs, and a key that is not a valid point can produce none.
//!
//! The server must also refuse SHA-1 RSA signatures (`ssh-rsa` as a
//! *signature* algorithm): only [`SshKeyType::accepted_signature_algorithms`]
//! may be offered. forgs never sees signatures, so this rule lives with the
//! consumer.

use std::fmt;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, STANDARD_PAD_INDIFFERENT};
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::ids::{SshKeyId, UserId};
use crate::store::SshKeyStore;
use crate::subject::{Subject, SubjectKey};

/// The longest `authorized_keys`-style line [`SshPublicKey::parse_openssh`]
/// accepts, in bytes. A 16384-bit RSA key is under 3 KiB of base64.
pub const MAX_LINE_LEN: usize = 16 * 1024;

/// The longest comment kept, in characters. Longer comments are truncated.
pub const MAX_COMMENT_CHARS: usize = 256;

/// The smallest accepted RSA modulus, in bits.
pub const MIN_RSA_BITS: u32 = 3072;

/// The largest accepted RSA modulus, in bits.
pub const MAX_RSA_BITS: u32 = 16384;

/// An accepted SSH public key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshKeyType {
    /// `ssh-ed25519`.
    Ed25519,
    /// `ecdsa-sha2-nistp256`.
    EcdsaP256,
    /// `ecdsa-sha2-nistp384`.
    EcdsaP384,
    /// `ssh-rsa` (the key type; signatures must be `rsa-sha2-*`).
    Rsa,
}

impl SshKeyType {
    /// Every accepted type.
    pub const ALL: [SshKeyType; 4] = [
        SshKeyType::Ed25519,
        SshKeyType::EcdsaP256,
        SshKeyType::EcdsaP384,
        SshKeyType::Rsa,
    ];

    /// The OpenSSH key type name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SshKeyType::Ed25519 => "ssh-ed25519",
            SshKeyType::EcdsaP256 => "ecdsa-sha2-nistp256",
            SshKeyType::EcdsaP384 => "ecdsa-sha2-nistp384",
            SshKeyType::Rsa => "ssh-rsa",
        }
    }

    /// The accepted type named `name` (exact match), if any.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == name)
    }

    /// The signature algorithms an SSH server may accept for a key of this
    /// type. For RSA that is `rsa-sha2-512` and `rsa-sha2-256` only: SHA-1
    /// `ssh-rsa` signatures must be refused.
    #[must_use]
    pub fn accepted_signature_algorithms(self) -> &'static [&'static str] {
        match self {
            SshKeyType::Ed25519 => &["ssh-ed25519"],
            SshKeyType::EcdsaP256 => &["ecdsa-sha2-nistp256"],
            SshKeyType::EcdsaP384 => &["ecdsa-sha2-nistp384"],
            SshKeyType::Rsa => &["rsa-sha2-512", "rsa-sha2-256"],
        }
    }

    /// Classify a type name: accepted, or why not.
    fn classify(name: &[u8]) -> Result<Self, SshKeyError> {
        if let Some(t) = std::str::from_utf8(name).ok().and_then(Self::from_name) {
            return Ok(t);
        }
        if name.ends_with(b"-cert-v01@openssh.com") {
            return Err(SshKeyError::Certificate);
        }
        if name == b"ssh-dss" {
            return Err(SshKeyError::Unsupported("ssh-dss"));
        }
        if name == b"ecdsa-sha2-nistp521" {
            return Err(SshKeyError::Unsupported("ecdsa-sha2-nistp521"));
        }
        if name.starts_with(b"sk-") {
            return Err(SshKeyError::Unsupported("sk (FIDO)"));
        }
        Err(SshKeyError::UnknownType)
    }
}

impl fmt::Display for SshKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a public key was refused.
///
/// The variants never echo attacker-chosen input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshKeyError {
    /// A known key type forgs does not accept (DSA, `nistp521`, FIDO).
    #[error("unsupported SSH key type {0}")]
    Unsupported(&'static str),
    /// An OpenSSH certificate rather than a plain public key.
    #[error("SSH certificates are not accepted; add the plain public key")]
    Certificate,
    /// A type name forgs does not know.
    #[error("unknown SSH key type")]
    UnknownType,
    /// An RSA modulus below [`MIN_RSA_BITS`].
    #[error("RSA key is too small ({bits} bits; at least {MIN_RSA_BITS} required)")]
    RsaTooSmall {
        /// The modulus size.
        bits: u32,
    },
    /// An RSA modulus above [`MAX_RSA_BITS`].
    #[error("RSA key is too large ({bits} bits; at most {MAX_RSA_BITS} accepted)")]
    RsaTooLarge {
        /// The modulus size.
        bits: u32,
    },
    /// The line or blob is not a well-formed key.
    #[error("malformed SSH public key: {0}")]
    Malformed(&'static str),
}

/// A validated SSH public key.
#[derive(Clone, PartialEq, Eq)]
pub struct SshPublicKey {
    key_type: SshKeyType,
    blob: Vec<u8>,
    comment: Option<String>,
    rsa_bits: Option<u32>,
}

impl fmt::Debug for SshPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshPublicKey")
            .field("key_type", &self.key_type)
            .field("fingerprint", &self.fingerprint().as_str())
            .field("comment", &self.comment)
            .finish_non_exhaustive()
    }
}

/// A cursor over the SSH wire encoding (RFC 4251 §5).
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn string(&mut self) -> Result<&'a [u8], SshKeyError> {
        let Some((len, rest)) = self.0.split_first_chunk::<4>() else {
            return Err(SshKeyError::Malformed("truncated length"));
        };
        let len = usize::try_from(u32::from_be_bytes(*len))
            .map_err(|_| SshKeyError::Malformed("length overflow"))?;
        if rest.len() < len {
            return Err(SshKeyError::Malformed("truncated field"));
        }
        let (field, rest) = rest.split_at(len);
        self.0 = rest;
        Ok(field)
    }

    /// A positive mpint in canonical form; returns its magnitude without a
    /// sign byte.
    fn positive_mpint(&mut self) -> Result<&'a [u8], SshKeyError> {
        let v = self.string()?;
        match v {
            [] | [0] => Err(SshKeyError::Malformed("zero integer")),
            [b, ..] if b & 0x80 != 0 => Err(SshKeyError::Malformed("negative integer")),
            [0, b, ..] if b & 0x80 == 0 => Err(SshKeyError::Malformed("non-canonical integer")),
            [0, rest @ ..] => Ok(rest),
            _ => Ok(v),
        }
    }

    fn finish(&self) -> Result<(), SshKeyError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(SshKeyError::Malformed("trailing bytes"))
        }
    }
}

/// Bit length of a big-endian magnitude with a non-zero first byte.
fn bit_len(m: &[u8]) -> u32 {
    let Some(first) = m.first() else { return 0 };
    let bytes = u32::try_from(m.len()).unwrap_or(u32::MAX);
    bytes.saturating_sub(1).saturating_mul(8) + (8 - first.leading_zeros())
}

/// Validate the type-specific body; returns the RSA modulus size for RSA.
fn validate_body(t: SshKeyType, r: &mut Reader<'_>) -> Result<Option<u32>, SshKeyError> {
    match t {
        SshKeyType::Ed25519 => {
            if r.string()?.len() != 32 {
                return Err(SshKeyError::Malformed("ed25519 key is not 32 bytes"));
            }
            Ok(None)
        }
        SshKeyType::EcdsaP256 | SshKeyType::EcdsaP384 => {
            let (curve, point_len): (&[u8], usize) = if t == SshKeyType::EcdsaP256 {
                (b"nistp256", 65)
            } else {
                (b"nistp384", 97)
            };
            if r.string()? != curve {
                return Err(SshKeyError::Malformed("curve does not match the key type"));
            }
            let point = r.string()?;
            if point.len() != point_len || point[0] != 0x04 {
                return Err(SshKeyError::Malformed("not an uncompressed curve point"));
            }
            Ok(None)
        }
        SshKeyType::Rsa => {
            let e = r.positive_mpint()?;
            let n = r.positive_mpint()?;
            let e_odd = e.last().is_some_and(|b| b & 1 == 1);
            if !e_odd || (e.len() == 1 && e[0] < 3) {
                return Err(SshKeyError::Malformed("bad RSA exponent"));
            }
            if n.last().is_some_and(|b| b & 1 == 0) {
                return Err(SshKeyError::Malformed("even RSA modulus"));
            }
            let bits = bit_len(n);
            if bits < MIN_RSA_BITS {
                return Err(SshKeyError::RsaTooSmall { bits });
            }
            if bits > MAX_RSA_BITS {
                return Err(SshKeyError::RsaTooLarge { bits });
            }
            Ok(Some(bits))
        }
    }
}

/// Clean a comment: drop control characters, trim, cap the length.
fn clean_comment(raw: &str) -> Option<String> {
    let s: String = raw.chars().filter(|c| !c.is_control()).collect();
    let s: String = s.trim().chars().take(MAX_COMMENT_CHARS).collect();
    let s = s.trim_end();
    (!s.is_empty()).then(|| s.to_owned())
}

impl SshPublicKey {
    /// Parse and validate the raw wire blob (`string type` followed by the
    /// type's fields), as SSH libraries hand it over after authentication.
    ///
    /// # Errors
    ///
    /// [`SshKeyError`] for a refused type or a malformed blob, including any
    /// trailing bytes.
    pub fn from_wire(blob: &[u8]) -> Result<Self, SshKeyError> {
        let mut r = Reader(blob);
        let key_type = SshKeyType::classify(r.string()?)?;
        let rsa_bits = validate_body(key_type, &mut r)?;
        r.finish()?;
        Ok(Self {
            key_type,
            blob: blob.to_vec(),
            comment: None,
            rsa_bits,
        })
    }

    /// Parse an `authorized_keys`-style line: `type base64 [comment]`.
    ///
    /// Leading options (`command="…" ssh-ed25519 …`) are refused: a key here
    /// is an identity, not a policy. The textual type must equal the type
    /// inside the blob. The comment has control characters removed and is
    /// capped at [`MAX_COMMENT_CHARS`].
    ///
    /// # Errors
    ///
    /// [`SshKeyError`] for a refused type or a malformed line.
    pub fn parse_openssh(line: &str) -> Result<Self, SshKeyError> {
        if line.len() > MAX_LINE_LEN {
            return Err(SshKeyError::Malformed("line too long"));
        }
        let line = line.trim();
        let (ty, rest) = line
            .split_once(|c: char| c.is_ascii_whitespace())
            .ok_or(SshKeyError::Malformed("expected `type base64 [comment]`"))?;
        if ty.contains(['=', '"', ',']) {
            return Err(SshKeyError::Malformed(
                "authorized_keys options are not accepted",
            ));
        }
        let text_type = SshKeyType::classify(ty.as_bytes())?;
        let rest = rest.trim_start();
        let (b64, comment) = rest
            .split_once(|c: char| c.is_ascii_whitespace())
            .unwrap_or((rest, ""));
        let blob = STANDARD_PAD_INDIFFERENT
            .decode(b64)
            .map_err(|_| SshKeyError::Malformed("bad base64"))?;
        let mut key = Self::from_wire(&blob)?;
        if key.key_type != text_type {
            return Err(SshKeyError::Malformed("key type does not match the blob"));
        }
        key.comment = clean_comment(comment);
        Ok(key)
    }

    /// The key's algorithm.
    #[must_use]
    pub fn key_type(&self) -> SshKeyType {
        self.key_type
    }

    /// The raw wire blob.
    #[must_use]
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// The comment from the `authorized_keys` line, cleaned; `None` for a key
    /// from [`SshPublicKey::from_wire`] or a line without one.
    #[must_use]
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// The RSA modulus size in bits; `None` for other types.
    #[must_use]
    pub fn rsa_bits(&self) -> Option<u32> {
        self.rsa_bits
    }

    /// The canonical fingerprint, `SHA256:` + unpadded base64 of the blob's
    /// SHA-256 (what `ssh-keygen -lf` prints).
    #[must_use]
    pub fn fingerprint(&self) -> SshFingerprint {
        let digest = Sha256::digest(&self.blob);
        SshFingerprint(format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)))
    }

    /// `type base64`, without the comment: the stored form.
    #[must_use]
    pub fn to_openssh(&self) -> String {
        format!("{} {}", self.key_type.as_str(), STANDARD.encode(&self.blob))
    }
}

/// A canonical SSH key fingerprint: `SHA256:` followed by 43 characters of
/// unpadded standard base64 (50 characters in all).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SshFingerprint(String);

impl SshFingerprint {
    /// Parse the canonical rendering.
    ///
    /// # Errors
    ///
    /// [`SshKeyError::Malformed`] for anything but `SHA256:` and the
    /// base64 of 32 bytes.
    pub fn parse(s: &str) -> Result<Self, SshKeyError> {
        let bad = SshKeyError::Malformed("not a SHA256 fingerprint");
        let b64 = s.strip_prefix("SHA256:").ok_or(bad.clone())?;
        match STANDARD_NO_PAD.decode(b64) {
            Ok(d) if d.len() == 32 && b64.len() == 43 => Ok(Self(s.to_owned())),
            _ => Err(bad),
        }
    }

    /// The canonical string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SshFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for SshFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SshFingerprint({})", self.0)
    }
}

/// Why an SSH key did not authenticate.
///
/// Like [`crate::verify::AuthError`], detail for the audit log: the SSH
/// client should only learn that its key was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshAuthError {
    /// No user has registered this key (or its user is disabled).
    #[error("unknown SSH key")]
    Unknown,
    /// The key's registration expired.
    #[error("expired SSH key")]
    Expired,
    /// The store failed. Fails closed.
    #[error("credential store error: {0}")]
    Store(String),
}

impl SshAuthError {
    /// A short stable label for the audit log / structured logging.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            SshAuthError::Unknown => "ssh.reject.unknown",
            SshAuthError::Expired => "ssh.reject.expired",
            SshAuthError::Store(_) => "ssh.reject.store_error",
        }
    }
}

/// An SSH key that maps to a live user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshAuthenticated {
    /// The registered key's id.
    pub key_id: SshKeyId,
    /// The user it belongs to.
    pub user_id: UserId,
    /// The key's fingerprint.
    pub fingerprint: SshFingerprint,
    /// `user:<id>`: the same subject a session of this user yields.
    pub subject: SubjectKey,
}

impl SshAuthenticated {
    /// The authenticated [`Subject`], for authz. Use
    /// [`Subject::acting_in`] to name the namespace the request targets.
    #[must_use]
    pub fn subject(&self) -> Subject {
        Subject::new(self.subject.clone())
    }
}

/// Map an SSH public key, already proven by the SSH server's signature
/// check, to the user who registered it.
///
/// `now` is epoch seconds; expiry is exclusive (`now == expires` is expired).
/// After a match the key's `last_used_at` is touched best-effort: a failure
/// there does not fail the login.
///
/// # Errors
///
/// [`SshAuthError`]; a store failure fails closed.
pub async fn authenticate_ssh_key(
    store: &impl SshKeyStore,
    key: &SshPublicKey,
    now: u64,
) -> Result<SshAuthenticated, SshAuthError> {
    let fingerprint = key.fingerprint();
    let record = store
        .lookup_ssh_key(&fingerprint)
        .await
        .map_err(SshAuthError::Store)?
        .ok_or(SshAuthError::Unknown)?;
    if record.expires.is_some_and(|e| e <= now) {
        return Err(SshAuthError::Expired);
    }
    let _ = store.touch_ssh_key(record.id, now).await;
    Ok(SshAuthenticated {
        key_id: record.id,
        user_id: record.user_id,
        fingerprint,
        subject: SubjectKey::user(record.user_id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SshKeyRecord;
    use async_trait::async_trait;
    use std::sync::Mutex;

    // Generated with ssh-keygen (OpenSSH 9.x); the fingerprints are
    // `ssh-keygen -lf` output.
    const ED25519: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATY4b5kzkNt7byYqtbEhMYuv2X22S0V57juqZYd4/vO alice@laptop";
    const ED25519_FP: &str = "SHA256:mi2ZGinIlrIIpT3ZZirp7f5x7noDhLiYkQsLyWr2Qcs";
    const P256: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAXijCLm309u0Vh4GKkt4wGLSZsOu2pTk/YbJJreoQGBTlmNGZ/+x7//fCt+5Ro1C1QUy2tb8+RGsqFOwlJPvoo= e256";
    const P256_FP: &str = "SHA256:/aWXaW+kQyVo1O/8U3iCsR4T+9qA0v9J3SAWMPpRJFI";
    const P384: &str = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJc1yKtnQ9/pFJqznAx82aOs1Ock20ZO9Uy9sFUPKIpX9MIpvZ61TSZdET5w6J4lay70BIjPi+rXH04EXAbkj75acHkR6cGKHf1wNBI6wg0imPZo+VMjLfVk5DKY8HXg/w== e384";
    const P384_FP: &str = "SHA256:/BMxU1JKXuMgBWyj+5TEhyX0y2Iu+NDw/u857GlDfWU";
    const P521: &str = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAHOTWY9AqfevNxgz/zEVQQSjb/yxrQRkJE9SqDIb6Cug04+5VU97zz9bPMfRaTsmxak1YSokAC2WJd30SWiMyq/BQCOyF4i8rbwo9Zn2GUdpKTF4CxlKhn/npoeva5oDrWX8UPVN3cXKzVuR6BwOKhM8V3B0JZCC3eho4nMANW9qehVtg==";
    const RSA3072: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCki8AyAo0U+AfoOIZsbukygDnf3qQ5AZydjFDJWGPmH67EjWewKRYSrVyYvunl2WqhpBW8KpzDGEAiiLNDc9/SSGXIRgckg2Zjk4L+yHx8/6d/IV/3vXVUCzZfkAzJHm+HzcWBZiYluDr8/1gb14BeFjRXhOXkMCCGQ/3LXswgPnxmmkpiWLhi910TU8jXCUT6sQNiosQ+FTWkzZtJcZj3DD0wzzIl2JaG0dyJfEbVGXe4saNrM1BpS90YZQj9ByCcaPG8ewrR32WptDgq21aodCODaesjTnxHoOlKK8PybYR0FiuDLjo78Njks4ls90WH6oPzWEMlO+GGUWPW9/vOFoRqSM6HVeVRBtAqWQger31qlwgt5XoWn9o7mfeXH/TjHQkohkxNmsDsYkeAKHsOSJTpuhF9xIPNkJdYbOfhLLDMBja4RUVkCAI9N5CWIpR1keSjafgYhSGyUh1fMdMbayACy5IhAMgH3tqEAGkcf32Slp18NaHahXOWibWp3SU= r3072";
    const RSA3072_FP: &str = "SHA256:FfV65FU04d3sN15d1ASFROZmNuhIQz06NnYX5BJ6Us4";
    const RSA2048: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVFKnUUhboeqqJig3/uNFZPdbcw41FAzPQeM15eo09suhE6k87YiYx7Qm7jrOb2eUMoiid8KHa90AutlRMojs443rfV3Q1KuO3G7ZwiCki41rjNpcakZpMStI481HFPpw/GM1L2fO7tO0AL5SwH7+hxoBDWRTPKzKmifLiNIZngTtUtfJ9/61yKICY6PztmMOwNvvNDhofl3OhvW/ThHTMhUP4AWNDCiASrmSf2qcctTTdVmsQTccroUVpVwTpbh7GnJNFxl5BYkh11bjg0wvcfUrYTg7Ixmet9hOvUlWhEpIT0EpZdxXw5iMITn3se6EJ73K3AmyyJ5Lv5/hd5PDt r2048";
    const ED25519_CERT: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDx1l/QfDPAwG2754mlG+W1O3Pwyyz3+ffgIxX526GMAAAAIATY4b5kzkNt7byYqtbEhMYuv2X22S0V57juqZYd4/vOAAAAAAAAAAAAAAABAAAABGNlcnQAAAAJAAAABWFsaWNlAAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIATY4b5kzkNt7byYqtbEhMYuv2X22S0V57juqZYd4/vOAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEBXnaw2OEVzjjhNlmBqeYqtRTGXZ2yXWYrRL7lEL1/RCeZ3OPAhqBhqDd8tJGLIz3V8bStEg+/SZE3EsHkM5BIB alice@laptop";

    fn s(v: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(v.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(v);
        out
    }

    fn line(ty: &str, blob: &[u8]) -> String {
        format!("{ty} {}", STANDARD.encode(blob))
    }

    fn blob_of(l: &str) -> Vec<u8> {
        STANDARD
            .decode(l.split_whitespace().nth(1).unwrap())
            .unwrap()
    }

    #[test]
    fn accepted_keys_parse_with_ssh_keygen_fingerprints() {
        for (l, ty, fp, comment) in [
            (
                ED25519,
                SshKeyType::Ed25519,
                ED25519_FP,
                Some("alice@laptop"),
            ),
            (P256, SshKeyType::EcdsaP256, P256_FP, Some("e256")),
            (P384, SshKeyType::EcdsaP384, P384_FP, Some("e384")),
            (RSA3072, SshKeyType::Rsa, RSA3072_FP, Some("r3072")),
        ] {
            let k = SshPublicKey::parse_openssh(l).unwrap();
            assert_eq!(k.key_type(), ty);
            assert_eq!(k.fingerprint().as_str(), fp);
            assert_eq!(k.comment(), comment);
            assert_eq!(SshFingerprint::parse(fp).unwrap(), k.fingerprint());
            // The stored form drops the comment and re-parses identically.
            let stored = k.to_openssh();
            assert!(l.starts_with(&stored));
            let again = SshPublicKey::parse_openssh(&stored).unwrap();
            assert_eq!(again.fingerprint(), k.fingerprint());
            assert_eq!(again.comment(), None);
            // The wire path agrees.
            let w = SshPublicKey::from_wire(k.blob()).unwrap();
            assert_eq!(w.fingerprint(), k.fingerprint());
            assert_eq!(w.key_type(), ty);
        }
        assert_eq!(
            SshPublicKey::parse_openssh(RSA3072).unwrap().rsa_bits(),
            Some(3072)
        );
        assert_eq!(
            SshPublicKey::parse_openssh(ED25519).unwrap().rsa_bits(),
            None
        );
    }

    #[test]
    fn whitespace_padding_and_comments() {
        let b64 = ED25519.split_whitespace().nth(1).unwrap();
        let unpadded = b64.trim_end_matches('=');
        let k = SshPublicKey::parse_openssh(&format!("  ssh-ed25519\t{unpadded}  \n")).unwrap();
        assert_eq!(k.fingerprint().as_str(), ED25519_FP);
        assert_eq!(k.comment(), None);
        let k = SshPublicKey::parse_openssh(&format!(
            "ssh-ed25519 {b64} my \u{1b}[31mkey\u{7} two words"
        ))
        .unwrap();
        assert_eq!(k.comment(), Some("my [31mkey two words"));
        let long = "x".repeat(1000);
        let k = SshPublicKey::parse_openssh(&format!("ssh-ed25519 {b64} {long}")).unwrap();
        assert_eq!(k.comment().unwrap().len(), MAX_COMMENT_CHARS);
    }

    #[test]
    fn refused_types() {
        assert_eq!(
            SshPublicKey::parse_openssh(RSA2048),
            Err(SshKeyError::RsaTooSmall { bits: 2048 })
        );
        assert_eq!(
            SshPublicKey::parse_openssh(ED25519_CERT),
            Err(SshKeyError::Certificate)
        );
        assert_eq!(
            SshPublicKey::parse_openssh(P521),
            Err(SshKeyError::Unsupported("ecdsa-sha2-nistp521"))
        );
        let dss = [
            s(b"ssh-dss"),
            s(&[1; 129]),
            s(&[1; 21]),
            s(&[1; 128]),
            s(&[1; 128]),
        ]
        .concat();
        assert_eq!(
            SshPublicKey::parse_openssh(&line("ssh-dss", &dss)),
            Err(SshKeyError::Unsupported("ssh-dss"))
        );
        assert_eq!(
            SshPublicKey::from_wire(&dss),
            Err(SshKeyError::Unsupported("ssh-dss"))
        );
        let sk = [s(b"sk-ssh-ed25519@openssh.com"), s(&[1; 32]), s(b"ssh:")].concat();
        assert_eq!(
            SshPublicKey::parse_openssh(&line("sk-ssh-ed25519@openssh.com", &sk)),
            Err(SshKeyError::Unsupported("sk (FIDO)"))
        );
        let unknown = [s(b"ssh-foo"), s(&[1; 32])].concat();
        assert_eq!(
            SshPublicKey::parse_openssh(&line("ssh-foo", &unknown)),
            Err(SshKeyError::UnknownType)
        );
    }

    #[test]
    fn malformed_lines() {
        let b64 = ED25519.split_whitespace().nth(1).unwrap();
        for bad in [
            String::new(),
            "ssh-ed25519".into(),
            format!("command=\"true\" ssh-ed25519 {b64}"),
            format!("no-pty,ssh-ed25519 {b64}"),
            format!("ssh-ed25519 {b64}!!"),
            format!("ssh-ed25519 {}", &b64[..b64.len() - 4]),
            format!("ssh-ed25519 {b64} {}", "x".repeat(MAX_LINE_LEN)),
        ] {
            assert!(
                matches!(
                    SshPublicKey::parse_openssh(&bad),
                    Err(SshKeyError::Malformed(_) | SshKeyError::UnknownType)
                ),
                "{bad:?}"
            );
        }
        // Textual type differs from the blob's.
        let ed = blob_of(ED25519);
        assert_eq!(
            SshPublicKey::parse_openssh(&line("ssh-rsa", &ed)),
            Err(SshKeyError::Malformed("key type does not match the blob"))
        );
    }

    #[test]
    fn malformed_blobs() {
        let ed = blob_of(ED25519);
        let mut trailing = ed.clone();
        trailing.push(0);
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0, 0, 0],
            trailing,
            ed[..ed.len() - 1].to_vec(),
            [s(b"ssh-ed25519"), s(&[1; 31])].concat(),
            [s(b"ssh-ed25519"), s(&[1; 33])].concat(),
            // Length prefix larger than the rest.
            [s(b"ssh-ed25519"), vec![0xff, 0xff, 0xff, 0xff]].concat(),
            // Wrong curve id / compressed point / wrong length.
            [
                s(b"ecdsa-sha2-nistp256"),
                s(b"nistp384"),
                s(&[[4u8].as_slice(), &[1; 64]].concat()),
            ]
            .concat(),
            [
                s(b"ecdsa-sha2-nistp256"),
                s(b"nistp256"),
                s(&[[2u8].as_slice(), &[1; 64]].concat()),
            ]
            .concat(),
            [
                s(b"ecdsa-sha2-nistp384"),
                s(b"nistp384"),
                s(&[[4u8].as_slice(), &[1; 64]].concat()),
            ]
            .concat(),
        ];
        for blob in cases {
            assert!(
                matches!(
                    SshPublicKey::from_wire(&blob),
                    Err(SshKeyError::Malformed(_))
                ),
                "{blob:?}"
            );
            if !blob.is_empty() {
                assert!(SshPublicKey::parse_openssh(&line("ssh-ed25519", &blob)).is_err());
            }
        }
    }

    #[test]
    fn rsa_integers() {
        let n = || {
            let mut n = vec![0u8];
            n.push(0xc1);
            n.extend_from_slice(&[0x55; 383]);
            n
        };
        let rsa = |e: &[u8], n: &[u8]| [s(b"ssh-rsa"), s(e), s(n)].concat();
        let ok = SshPublicKey::from_wire(&rsa(&[1, 0, 1], &n())).unwrap();
        assert_eq!(ok.rsa_bits(), Some(3072));
        let malformed = [
            // e: zero, even, 1, negative, leading zero.
            rsa(&[], &n()),
            rsa(&[2], &n()),
            rsa(&[1], &n()),
            rsa(&[0x81], &n()),
            rsa(&[0, 1, 0, 1], &n()),
            // n: negative (no sign byte), superfluous zero, even.
            rsa(&[3], &n()[1..]),
            rsa(&[3], &[[0u8, 0].as_slice(), &n()[1..]].concat()),
            rsa(&[3], &[&n()[..383], [0x54u8].as_slice()].concat()),
        ];
        for b in malformed {
            assert!(matches!(
                SshPublicKey::from_wire(&b),
                Err(SshKeyError::Malformed(_))
            ));
        }
        let mut big = vec![0u8, 0x81];
        big.extend_from_slice(&[0x55; 2048]);
        assert_eq!(
            SshPublicKey::from_wire(&rsa(&[3], &big)),
            Err(SshKeyError::RsaTooLarge { bits: 16392 })
        );
        let mut small = vec![0x41];
        small.extend_from_slice(&[0x55; 383]);
        assert_eq!(
            SshPublicKey::from_wire(&rsa(&[3], &small)),
            Err(SshKeyError::RsaTooSmall { bits: 3071 })
        );
    }

    #[test]
    fn fingerprint_parse() {
        assert!(SshFingerprint::parse(ED25519_FP).is_ok());
        for bad in [
            "",
            "SHA256:",
            "MD5:mi2ZGinIlrIIpT3ZZirp7f5x7noDhLiYkQsLyWr2Qcs",
            "SHA256:mi2ZGinIlrIIpT3ZZirp7f5x7noDhLiYkQsLyWr2Qcs=",
            "SHA256:mi2ZGinIlrIIpT3ZZirp7f5x7noDhLiYkQsLyWr2Qc",
            "sha256:mi2ZGinIlrIIpT3ZZirp7f5x7noDhLiYkQsLyWr2Qcs",
        ] {
            assert!(SshFingerprint::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn signature_algorithms_exclude_sha1() {
        assert!(!SshKeyType::Rsa
            .accepted_signature_algorithms()
            .contains(&"ssh-rsa"));
        for t in SshKeyType::ALL {
            assert_eq!(SshKeyType::from_name(t.as_str()), Some(t));
        }
    }

    struct Fake {
        record: Option<SshKeyRecord>,
        fail: bool,
        touched: Mutex<Vec<SshKeyId>>,
    }

    #[async_trait]
    impl SshKeyStore for Fake {
        async fn lookup_ssh_key(
            &self,
            fp: &SshFingerprint,
        ) -> Result<Option<SshKeyRecord>, String> {
            assert_eq!(fp.as_str(), ED25519_FP);
            if self.fail {
                return Err("disk on fire".into());
            }
            Ok(self.record.clone())
        }
        async fn touch_ssh_key(&self, id: SshKeyId, _now: u64) -> Result<(), String> {
            self.touched.lock().unwrap().push(id);
            Err("touch failures are ignored".into())
        }
    }

    fn fake(expires: Option<u64>, fail: bool) -> (Fake, SshKeyRecord) {
        let r = SshKeyRecord {
            id: SshKeyId::from_parts(1, 2),
            user_id: UserId::from_parts(3, 4),
            expires,
        };
        let f = Fake {
            record: Some(r.clone()),
            fail,
            touched: Mutex::default(),
        };
        (f, r)
    }

    #[tokio::test]
    async fn authenticate_maps_to_the_user_subject() {
        let key = SshPublicKey::parse_openssh(ED25519).unwrap();
        let (store, r) = fake(Some(101), false);
        let a = authenticate_ssh_key(&store, &key, 100).await.unwrap();
        assert_eq!(a.user_id, r.user_id);
        assert_eq!(a.key_id, r.id);
        assert_eq!(a.subject, SubjectKey::user(r.user_id));
        assert_eq!(a.subject().key(), &SubjectKey::user(r.user_id));
        assert_eq!(a.fingerprint.as_str(), ED25519_FP);
        assert_eq!(*store.touched.lock().unwrap(), vec![r.id]);

        let e = authenticate_ssh_key(&store, &key, 101).await.unwrap_err();
        assert_eq!(e, SshAuthError::Expired);
        assert_eq!(e.label(), "ssh.reject.expired");

        let (store, _) = fake(None, false);
        assert!(authenticate_ssh_key(&store, &key, u64::MAX).await.is_ok());

        let (store, _) = fake(None, true);
        let e = authenticate_ssh_key(&store, &key, 0).await.unwrap_err();
        assert_eq!(e.label(), "ssh.reject.store_error");
        assert!(store.touched.lock().unwrap().is_empty());

        let mut store = fake(None, false).0;
        store.record = None;
        let e = authenticate_ssh_key(&store, &key, 0).await.unwrap_err();
        assert_eq!(e, SshAuthError::Unknown);
        assert_eq!(e.label(), "ssh.reject.unknown");
    }
}
