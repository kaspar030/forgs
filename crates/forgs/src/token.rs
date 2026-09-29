//! Opaque bearer tokens: minting, parsing, and hashing.
//!
//! A token is a short human prefix plus 32 random bytes in base64url-no-pad.
//! With the default brand `frg`:
//!
//! ```text
//! frgs1_<43 chars>      session token   (user; short TTL, refreshable)
//! frgr1_<43 chars>      refresh token   (user; long-lived, mints sessions only)
//! frgk1_<43 chars>      API key         (namespace-scoped, revocable; redeemed)
//! frgw1_<43 chars>      workload token  (CI; one job, exchanged at /auth/token)
//! frgd1_<43 chars>      device secret   (pending device approval; redeemed)
//! ```
//!
//! Apps register extra kinds on a [`TokenFormat`] (probe-rs-fleet: `node` with
//! tag `n`, `node_device` with tag `nd`), and pick the brand (fleet keeps
//! `prf`), so the prefix is `<brand><tag>1_`.
//!
//! The prefix is load-bearing, not decoration: it tells the server which
//! table to look in *before* any database access, so a token of the wrong kind
//! for a route is rejected as a 403 rather than silently searched for
//! everywhere. Each kind is also classified by a [`TokenUse`]: a
//! [`TokenUse::RedeemOnly`] kind is refused as a connection credential from its
//! prefix alone ([`crate::verify::authenticate`]).
//!
//! The server stores only the **lowercase-hex SHA-256** of the secret
//! ([`TokenHash`]), never the token itself.
//!
//! # Design choice: the token carries its prefix
//!
//! An [`OpaqueToken`] is produced only by [`TokenFormat::mint`] or
//! [`TokenFormat::parse`], and remembers the prefix it was minted or parsed
//! with. [`OpaqueToken::to_secret_string`] therefore needs no format argument,
//! and a token can never be rendered with a different brand than it was read
//! with.

use std::fmt;

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Number of random bytes in a token secret.
const SECRET_LEN: usize = 32;

/// The default prefix brand.
pub const DEFAULT_BRAND: &str = "frg";

/// Whether a kind of token may be presented as a connection credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenUse {
    /// Presented on a connection / request (`Authorization: Bearer …`) and
    /// accepted by [`crate::verify::authenticate`].
    Connection,
    /// **Redeemed at a route, never presented as a connection credential**:
    /// [`crate::verify::authenticate`] rejects it as
    /// [`crate::verify::AuthError::WrongKind`] from its prefix alone, with no
    /// store access.
    RedeemOnly,
}

/// A handle to an app-registered token kind, returned by
/// [`TokenFormatBuilder::app_kind`].
///
/// `Copy`, and meaningful only together with the [`TokenFormat`] that
/// registered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AppKind {
    label: &'static str,
    index: usize,
}

impl AppKind {
    /// The kind's label, for logs and audit entries.
    #[must_use]
    pub fn label(self) -> &'static str {
        self.label
    }
}

/// Which credential a token is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// A user's short-lived session token. A connection credential.
    Session,
    /// A user's long-lived credential whose **only** power is minting session
    /// tokens.
    ///
    /// Three facts decide everything about this kind:
    ///
    /// * Like [`TokenKind::ApiKey`] and [`TokenKind::DeviceSecret`] it is
    ///   **redeemed at a route, never presented as a connection credential**,
    ///   so [`crate::verify::authenticate`] answers
    ///   [`crate::verify::AuthError::WrongKind`] for it — from the prefix
    ///   alone, with no store access. No route's `allowed` list contains it.
    /// * Its only power is minting session tokens for one user. It enrolls
    ///   nothing, opens nothing, and confers no operation of its own.
    /// * **Redemption does not consume it.** That is deliberate and it is what
    ///   makes the sidecar path safe: N concurrent redemptions all succeed and
    ///   every minted session is independently valid, exactly as for a
    ///   multi-use API key. The cost — a leaked refresh token is usable for
    ///   its whole TTL — is bounded by `logout --all` and expiry.
    Refresh,
    /// A pre-minted, namespace-scoped, revocable API key (fleet's "auth key").
    ///
    /// Redeemed at a route (its purpose is app-defined, with a redemption
    /// hook), never a connection credential.
    ApiKey,
    /// A CI job's per-job credential, exchanged at `POST /auth/token` from an
    /// OIDC JWT (or from a workload API key for a runner with no workload
    /// identity).
    ///
    /// Unlike [`TokenKind::ApiKey`] this **is** a connection credential. It
    /// belongs to no namespace — a workload reaches resources only through
    /// grants.
    Workload,
    /// A machine's poll credential for an approval-pending device flow.
    ///
    /// Like [`TokenKind::ApiKey`] it is **redeemed at a route, never presented
    /// as a connection credential**.
    DeviceSecret,
    /// An app-registered kind (fleet: `node`, `node_device`).
    App(AppKind),
}

impl TokenKind {
    /// A short label, for logs and audit entries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Session => "session",
            TokenKind::Refresh => "refresh",
            TokenKind::ApiKey => "api_key",
            TokenKind::Workload => "workload",
            TokenKind::DeviceSecret => "device_secret",
            TokenKind::App(k) => k.label,
        }
    }
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The five core kinds, with their tags and uses.
const CORE_KINDS: [(TokenKind, &str, TokenUse); 5] = [
    (TokenKind::Session, "s", TokenUse::Connection),
    (TokenKind::Refresh, "r", TokenUse::RedeemOnly),
    (TokenKind::ApiKey, "k", TokenUse::RedeemOnly),
    (TokenKind::Workload, "w", TokenUse::Connection),
    (TokenKind::DeviceSecret, "d", TokenUse::RedeemOnly),
];

/// Errors raised while parsing a token string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The string carried no recognised token prefix.
    #[error("token has an unrecognised prefix")]
    BadPrefix,
    /// The body was not valid base64url-no-pad.
    #[error("token body is not valid base64url")]
    BadBase64,
    /// The decoded secret was not 32 bytes.
    #[error("token body has the wrong length")]
    BadLength,
}

/// Why a [`TokenFormat`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    /// The brand is empty or not `[a-z]+`.
    #[error("token brand {0:?} must be non-empty [a-z]")]
    BadBrand(String),
    /// A tag is empty or not `[a-z]+`.
    #[error("token tag {0:?} must be non-empty [a-z]")]
    BadTag(String),
    /// A label is empty or not `[a-z_]+`.
    #[error("token kind label {0:?} must be non-empty [a-z_]")]
    BadLabel(String),
    /// Two kinds share a label (or an app label shadows a core one).
    #[error("token kind label {0:?} is used twice")]
    DuplicateLabel(String),
    /// Two kinds share a prefix.
    #[error("token prefix {0:?} is used twice")]
    DuplicatePrefix(String),
    /// One prefix is a proper prefix of another, so parsing would depend on
    /// match order.
    #[error("token prefix {0:?} is a prefix of {1:?}")]
    AmbiguousPrefix(String, String),
}

/// One kind's entry in a [`TokenFormat`].
#[derive(Debug, Clone)]
struct KindEntry {
    kind: TokenKind,
    prefix: String,
    token_use: TokenUse,
}

/// Builds a [`TokenFormat`]. See [`TokenFormat::builder`].
#[derive(Debug, Clone)]
pub struct TokenFormatBuilder {
    brand: String,
    apps: Vec<(&'static str, String, TokenUse)>,
}

impl TokenFormatBuilder {
    /// Register an app kind with `label` (for logs, `[a-z_]+`), `tag` (the
    /// prefix is `<brand><tag>1_`, `[a-z]+`) and its [`TokenUse`].
    ///
    /// Returns the handle to mint, parse and classify it with. Validation
    /// happens in [`TokenFormatBuilder::build`].
    pub fn app_kind(&mut self, label: &'static str, tag: &str, token_use: TokenUse) -> AppKind {
        let kind = AppKind {
            label,
            index: self.apps.len(),
        };
        self.apps.push((label, tag.to_owned(), token_use));
        kind
    }

    /// Validate and build the format.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError`] if the brand, a tag or a label has a bad
    /// charset, a label or prefix is duplicated, or one prefix is a proper
    /// prefix of another.
    pub fn build(self) -> Result<TokenFormat, FormatError> {
        let lower = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase());
        if !lower(&self.brand) {
            return Err(FormatError::BadBrand(self.brand));
        }
        let mut entries: Vec<KindEntry> = CORE_KINDS
            .iter()
            .map(|&(kind, tag, token_use)| KindEntry {
                kind,
                prefix: format!("{}{tag}1_", self.brand),
                token_use,
            })
            .collect();
        for (index, (label, tag, token_use)) in self.apps.iter().enumerate() {
            if label.is_empty() || !label.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
                return Err(FormatError::BadLabel((*label).to_owned()));
            }
            if !lower(tag) {
                return Err(FormatError::BadTag(tag.clone()));
            }
            if entries.iter().any(|e| e.kind.as_str() == *label) {
                return Err(FormatError::DuplicateLabel((*label).to_owned()));
            }
            entries.push(KindEntry {
                kind: TokenKind::App(AppKind { label, index }),
                prefix: format!("{}{tag}1_", self.brand),
                token_use: *token_use,
            });
        }
        for (i, a) in entries.iter().enumerate() {
            for b in &entries[i + 1..] {
                if a.prefix == b.prefix {
                    return Err(FormatError::DuplicatePrefix(a.prefix.clone()));
                }
                // With `[a-z]` tags and a fixed `1_` suffix this cannot happen,
                // but parsing's correctness must not rest on that argument.
                if b.prefix.starts_with(&a.prefix) {
                    return Err(FormatError::AmbiguousPrefix(
                        a.prefix.clone(),
                        b.prefix.clone(),
                    ));
                }
                if a.prefix.starts_with(&b.prefix) {
                    return Err(FormatError::AmbiguousPrefix(
                        b.prefix.clone(),
                        a.prefix.clone(),
                    ));
                }
            }
        }
        // Longest prefix first, so the match stays correct even if the
        // ambiguity check above were ever relaxed.
        let mut parse_order: Vec<usize> = (0..entries.len()).collect();
        parse_order.sort_by_key(|&i| std::cmp::Reverse(entries[i].prefix.len()));
        Ok(TokenFormat {
            brand: self.brand,
            entries,
            parse_order,
        })
    }
}

/// The set of token kinds an app accepts, and their prefixes.
///
/// Built once at startup. The five core kinds are always present;
/// [`TokenFormatBuilder::app_kind`] adds app kinds.
#[derive(Debug, Clone)]
pub struct TokenFormat {
    brand: String,
    /// Core kinds first (in [`CORE_KINDS`] order), then app kinds in
    /// registration order — so an [`AppKind`]'s index is `5 + index`.
    entries: Vec<KindEntry>,
    parse_order: Vec<usize>,
}

impl Default for TokenFormat {
    /// The core kinds under [`DEFAULT_BRAND`].
    fn default() -> Self {
        TokenFormat::builder(DEFAULT_BRAND)
            .build()
            .expect("the default format is valid")
    }
}

impl TokenFormat {
    /// Start a format with the given prefix brand (`[a-z]+`).
    #[must_use]
    pub fn builder(brand: &str) -> TokenFormatBuilder {
        TokenFormatBuilder {
            brand: brand.to_owned(),
            apps: Vec::new(),
        }
    }

    /// The prefix brand.
    #[must_use]
    pub fn brand(&self) -> &str {
        &self.brand
    }

    fn entry(&self, kind: TokenKind) -> &KindEntry {
        let idx = match kind {
            TokenKind::Session => 0,
            TokenKind::Refresh => 1,
            TokenKind::ApiKey => 2,
            TokenKind::Workload => 3,
            TokenKind::DeviceSecret => 4,
            TokenKind::App(k) => CORE_KINDS.len() + k.index,
        };
        let entry = self
            .entries
            .get(idx)
            .filter(|e| e.kind == kind)
            .unwrap_or_else(|| panic!("token kind {kind} is not registered on this format"));
        entry
    }

    /// The wire prefix for `kind`.
    ///
    /// # Panics
    ///
    /// Panics if `kind` is an [`AppKind`] registered on a different format — a
    /// programming error, not a runtime condition.
    #[must_use]
    pub fn prefix(&self, kind: TokenKind) -> &str {
        &self.entry(kind).prefix
    }

    /// Whether `kind` is a connection credential or redeem-only.
    ///
    /// # Panics
    ///
    /// As for [`TokenFormat::prefix`].
    #[must_use]
    pub fn token_use(&self, kind: TokenKind) -> TokenUse {
        self.entry(kind).token_use
    }

    /// Look up a registered app kind by its label.
    #[must_use]
    pub fn app_kind(&self, label: &str) -> Option<AppKind> {
        self.entries.iter().find_map(|e| match e.kind {
            TokenKind::App(k) if k.label == label => Some(k),
            _ => None,
        })
    }

    /// Every kind this format knows, core kinds first.
    pub fn kinds(&self) -> impl Iterator<Item = TokenKind> + '_ {
        self.entries.iter().map(|e| e.kind)
    }

    /// Mint a fresh random token of `kind`.
    ///
    /// # Panics
    ///
    /// Panics if the OS random source fails, which is not a condition any
    /// caller can meaningfully recover from, or if `kind` is foreign to this
    /// format (see [`TokenFormat::prefix`]).
    #[must_use]
    pub fn mint(&self, kind: TokenKind) -> OpaqueToken {
        use rand_core::RngCore as _;
        let mut secret = [0u8; SECRET_LEN];
        rand_core::OsRng.fill_bytes(&mut secret);
        OpaqueToken {
            kind,
            prefix: self.prefix(kind).to_owned(),
            secret,
        }
    }

    /// Parse a token from its string form. Surrounding whitespace is ignored.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] if the prefix is unrecognised, the body is not
    /// base64url, or the decoded secret is not 32 bytes.
    pub fn parse(&self, s: &str) -> Result<OpaqueToken, TokenError> {
        let s = s.trim();
        let (entry, body) = self
            .parse_order
            .iter()
            .map(|&i| &self.entries[i])
            .find_map(|e| s.strip_prefix(e.prefix.as_str()).map(|body| (e, body)))
            .ok_or(TokenError::BadPrefix)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| TokenError::BadBase64)?;
        let secret: [u8; SECRET_LEN] = bytes.try_into().map_err(|_| TokenError::BadLength)?;
        Ok(OpaqueToken {
            kind: entry.kind,
            prefix: entry.prefix.clone(),
            secret,
        })
    }
}

/// The lowercase-hex SHA-256 of a token secret — what the server stores.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TokenHash(String);

impl TokenHash {
    /// Borrow the hex digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first 8 hex characters, for logs and audit entries.
    ///
    /// A prefix of a *hash* is safe to log: it identifies a credential across
    /// events without being usable, and 8 characters is far too short to invert
    /// a 32-byte random secret.
    #[must_use]
    pub fn short(&self) -> &str {
        &self.0[..8.min(self.0.len())]
    }

    /// Wrap an already-computed hex digest (e.g. read from the database).
    #[must_use]
    pub fn from_hex(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The hash is not the secret, but printing it in full invites someone to
        // paste it into a bug report; the short form is what logs want anyway.
        write!(f, "TokenHash({}…)", self.short())
    }
}

impl fmt::Display for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An opaque bearer token: the secret itself.
///
/// [`fmt::Debug`] never prints the secret. Print it exactly once, when it is
/// minted for its owner to copy.
#[derive(Clone, PartialEq, Eq)]
pub struct OpaqueToken {
    kind: TokenKind,
    prefix: String,
    secret: [u8; SECRET_LEN],
}

impl OpaqueToken {
    /// The token's kind, from its prefix.
    #[must_use]
    pub fn kind(&self) -> TokenKind {
        self.kind
    }

    /// The lowercase-hex SHA-256 of the secret: what the server stores and
    /// looks up.
    #[must_use]
    pub fn hash(&self) -> TokenHash {
        let digest = Sha256::digest(self.secret);
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use fmt::Write as _;
            // Infallible: writing to a String never fails.
            let _ = write!(out, "{byte:02x}");
        }
        TokenHash(out)
    }

    /// Render the token in its copy-pasteable string form.
    ///
    /// This is the only place the secret becomes visible; call it exactly where
    /// the token is handed to its owner.
    #[must_use]
    pub fn to_secret_string(&self) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.secret);
        format!("{}{b64}", self.prefix)
    }
}

impl fmt::Debug for OpaqueToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueToken")
            .field("kind", &self.kind)
            .field("prefix", &self.prefix)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fleet-shaped format: the `prf` brand plus fleet's two app kinds.
    fn fleet() -> (TokenFormat, AppKind, AppKind) {
        let mut b = TokenFormat::builder("prf");
        let node = b.app_kind("node", "n", TokenUse::Connection);
        let node_device = b.app_kind("node_device", "nd", TokenUse::RedeemOnly);
        (b.build().unwrap(), node, node_device)
    }

    #[test]
    fn mint_parse_round_trips_for_every_kind() {
        let (format, _, _) = fleet();
        let kinds: Vec<_> = format.kinds().collect();
        assert_eq!(kinds.len(), 7);
        for kind in kinds {
            let token = format.mint(kind);
            let s = token.to_secret_string();
            assert!(
                s.starts_with(format.prefix(kind)),
                "{s} lacks {}",
                format.prefix(kind)
            );
            let back = format.parse(&s).unwrap();
            assert_eq!(back.kind(), kind);
            assert_eq!(back, token);
            assert_eq!(back.hash(), token.hash());
        }
    }

    #[test]
    fn default_format_has_the_core_prefixes() {
        let f = TokenFormat::default();
        assert_eq!(f.brand(), "frg");
        assert_eq!(f.prefix(TokenKind::Session), "frgs1_");
        assert_eq!(f.prefix(TokenKind::Refresh), "frgr1_");
        assert_eq!(f.prefix(TokenKind::ApiKey), "frgk1_");
        assert_eq!(f.prefix(TokenKind::Workload), "frgw1_");
        assert_eq!(f.prefix(TokenKind::DeviceSecret), "frgd1_");
    }

    #[test]
    fn core_kinds_have_fixed_uses() {
        let f = TokenFormat::default();
        assert_eq!(f.token_use(TokenKind::Session), TokenUse::Connection);
        assert_eq!(f.token_use(TokenKind::Workload), TokenUse::Connection);
        assert_eq!(f.token_use(TokenKind::Refresh), TokenUse::RedeemOnly);
        assert_eq!(f.token_use(TokenKind::ApiKey), TokenUse::RedeemOnly);
        assert_eq!(f.token_use(TokenKind::DeviceSecret), TokenUse::RedeemOnly);
    }

    #[test]
    fn distinct_mints_are_distinct() {
        let f = TokenFormat::default();
        assert_ne!(
            f.mint(TokenKind::Session).hash(),
            f.mint(TokenKind::Session).hash()
        );
    }

    #[test]
    fn hash_is_stable_and_64_hex() {
        let token = TokenFormat::default().mint(TokenKind::Session);
        let h = token.hash();
        assert_eq!(h.as_str().len(), 64);
        assert!(h.as_str().chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h, token.hash());
        assert_eq!(h.short().len(), 8);
        assert_eq!(TokenHash::from_hex(h.as_str()), h);
    }

    /// The prefix decides the table, so a node token must never parse as a
    /// session token: that is what makes wrong-kind-for-route a 403 rather than
    /// a lookup in the wrong place.
    #[test]
    fn prefix_determines_kind() {
        let (f, node, node_device) = fleet();
        let parse = |k| f.parse(&f.mint(k).to_secret_string()).unwrap().kind();
        assert_eq!(parse(TokenKind::App(node)), TokenKind::App(node));
        assert_eq!(parse(TokenKind::Session), TokenKind::Session);
        // `prfnd1_` vs `prfn1_`: unambiguous because neither is a prefix of the
        // other, and the strip is longest-first besides.
        assert_eq!(
            parse(TokenKind::App(node_device)),
            TokenKind::App(node_device)
        );
        assert_eq!(f.prefix(TokenKind::App(node)), "prfn1_");
        assert_eq!(f.prefix(TokenKind::App(node_device)), "prfnd1_");
        // Mistaking a refresh token for a session token would turn a credential
        // that may only be *redeemed* into one that opens a connection, which
        // is precisely what this kind must never be.
        let refresh = f.mint(TokenKind::Refresh).to_secret_string();
        assert!(!refresh.starts_with(f.prefix(TokenKind::Session)));
        for other in f.kinds().filter(|k| *k != TokenKind::Refresh) {
            assert_ne!(
                parse(other),
                TokenKind::Refresh,
                "{other} parsed as refresh"
            );
        }
    }

    /// A token of one brand is not a token of another.
    #[test]
    fn brands_do_not_mix() {
        let (fleet, _, _) = fleet();
        let s = TokenFormat::default()
            .mint(TokenKind::Session)
            .to_secret_string();
        assert_eq!(fleet.parse(&s), Err(TokenError::BadPrefix));
    }

    #[test]
    fn parse_rejects_bad_prefix() {
        let f = TokenFormat::default();
        assert_eq!(f.parse("nope_abcd"), Err(TokenError::BadPrefix));
        assert_eq!(f.parse(""), Err(TokenError::BadPrefix));
        // An app kind of another format is not known here.
        let (fleet, node, _) = fleet();
        let s = fleet.mint(TokenKind::App(node)).to_secret_string();
        assert_eq!(f.parse(&s), Err(TokenError::BadPrefix));
    }

    #[test]
    fn parse_rejects_bad_base64() {
        assert_eq!(
            TokenFormat::default().parse("frgs1_!!!not-base64!!!"),
            Err(TokenError::BadBase64)
        );
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let short = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 16]);
        assert_eq!(
            TokenFormat::default().parse(&format!("frgs1_{short}")),
            Err(TokenError::BadLength)
        );
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let f = TokenFormat::default();
        let token = f.mint(TokenKind::Workload);
        let s = format!("  {}\n", token.to_secret_string());
        assert_eq!(f.parse(&s).unwrap(), token);
    }

    #[test]
    fn debug_does_not_leak_the_secret() {
        let token = TokenFormat::default().mint(TokenKind::Session);
        let rendered = format!("{token:?}");
        assert!(rendered.contains("redacted"));
        let secret = token.to_secret_string();
        assert!(!rendered.contains(&secret[6..]));
        let hash = format!("{:?}", token.hash());
        assert!(!hash.contains(token.hash().as_str()));
    }

    #[test]
    fn app_kinds_are_looked_up_by_label() {
        let (f, node, _) = fleet();
        assert_eq!(f.app_kind("node"), Some(node));
        assert_eq!(f.app_kind("session"), None);
        assert_eq!(TokenKind::App(node).as_str(), "node");
        assert_eq!(f.token_use(TokenKind::App(node)), TokenUse::Connection);
    }

    #[test]
    fn builder_rejections() {
        assert_eq!(
            TokenFormat::builder("").build().unwrap_err(),
            FormatError::BadBrand(String::new())
        );
        assert_eq!(
            TokenFormat::builder("Prf").build().unwrap_err(),
            FormatError::BadBrand("Prf".into())
        );
        let with = |label: &'static str, tag: &str| {
            let mut b = TokenFormat::builder("prf");
            b.app_kind(label, tag, TokenUse::Connection);
            b.build().unwrap_err()
        };
        assert_eq!(with("node", "N"), FormatError::BadTag("N".into()));
        assert_eq!(with("node", "n1"), FormatError::BadTag("n1".into()));
        assert_eq!(with("node", ""), FormatError::BadTag(String::new()));
        assert_eq!(with("No de", "n"), FormatError::BadLabel("No de".into()));
        assert_eq!(
            with("session", "x"),
            FormatError::DuplicateLabel("session".into())
        );
        // Tag `s` collides with the core session prefix.
        assert_eq!(
            with("node", "s"),
            FormatError::DuplicatePrefix("prfs1_".into())
        );

        let mut b = TokenFormat::builder("prf");
        b.app_kind("a", "x", TokenUse::Connection);
        b.app_kind("a", "y", TokenUse::Connection);
        assert_eq!(
            b.build().unwrap_err(),
            FormatError::DuplicateLabel("a".into())
        );
    }

    #[test]
    #[should_panic(expected = "not registered")]
    fn a_foreign_app_kind_panics() {
        let (_, node, _) = fleet();
        let _ = TokenFormat::default().prefix(TokenKind::App(node));
    }
}
