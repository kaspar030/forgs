//! The authenticated caller: [`Subject`] and its stable identity [`SubjectKey`].
//!
//! Every authentication path — user session, workload token, app kinds such as
//! fleet's node token — resolves to this one shape, so authorization is a
//! single mechanism.
//!
//! # Rendering
//!
//! A [`SubjectKey`] renders as `[<ns>/]<kind>:<id>`:
//!
//! * `user:01J…` — a user, by immutable [`UserId`];
//! * `gha/workload:owner/repo` — a GitHub Actions workload. The `gha`
//!   namespace slot is reserved, not a namespace node;
//! * `01J…/workload:agent:builder` — a named API-key identity, scoped by the
//!   id of the namespace node that minted it.
//!
//! [`SubjectKey::parse`] splits at the first `/` **only when it comes before
//! the first `:`**, then at the first `:`. So ids may themselves contain `/`
//! and `:` (a repo, `agent:<name>`) and still round-trip, while a namespace
//! can contain neither.
//!
//! Compared to fleet, the org slot became optional (a user is no longer
//! addressed "in their personal org") and the unused `Group` is gone.

use std::fmt;

use crate::ids::{NsNodeId, UserId};

/// Which authentication path produced a [`Subject`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SubjectKind {
    /// A human, authenticated by a user session.
    User,
    /// A CI workload, authenticated by an exchanged workload token.
    Workload,
    /// An app-defined kind (fleet: `node`). The label must be `[a-z_]+` and
    /// not `user` or `workload`; see [`SubjectKind::app`].
    App(&'static str),
}

impl SubjectKind {
    /// Build an app kind, validating its label.
    ///
    /// Returns `None` for an empty label, one outside `[a-z_]`, or one that
    /// shadows a core kind.
    #[must_use]
    pub fn app(label: &'static str) -> Option<Self> {
        valid_app_label(label).then_some(SubjectKind::App(label))
    }

    /// The label this kind renders as.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SubjectKind::User => "user",
            SubjectKind::Workload => "workload",
            SubjectKind::App(label) => label,
        }
    }
}

fn valid_app_label(label: &str) -> bool {
    !label.is_empty()
        && label.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        && label != "user"
        && label != "workload"
}

impl fmt::Display for SubjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The stable identity of a [`Subject`], used for equality wherever ownership
/// matters (grant subjects, membership, audit rows).
///
/// Build it with the constructors ([`SubjectKey::user`],
/// [`workload_subject_key`], [`agent_subject_key`], [`SubjectKey::new`]) or
/// [`SubjectKey::parse`]; the fields are private so a key cannot be assembled
/// in a shape that would not round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubjectKey {
    ns: Option<String>,
    kind: SubjectKind,
    id: String,
}

impl SubjectKey {
    /// A user's key: `user:<ulid>`.
    #[must_use]
    pub fn user(id: UserId) -> Self {
        Self {
            ns: None,
            kind: SubjectKind::User,
            id: id.to_string(),
        }
    }

    /// A key from parts.
    ///
    /// Returns `None` if the parts would not round-trip through
    /// [`SubjectKey::parse`]: an empty namespace or id, a namespace containing
    /// `/` or `:`, an app kind with an invalid label, or an id with a newline.
    #[must_use]
    pub fn new(ns: Option<&str>, kind: SubjectKind, id: &str) -> Option<Self> {
        if let Some(ns) = ns {
            if ns.is_empty() || ns.contains(['/', ':']) || has_control(ns) {
                return None;
            }
        }
        if let SubjectKind::App(label) = kind {
            if !valid_app_label(label) {
                return None;
            }
        }
        if id.is_empty() || has_control(id) {
            return None;
        }
        Some(Self {
            ns: ns.map(str::to_owned),
            kind,
            id: id.to_owned(),
        })
    }

    /// The namespace slot, if any (`gha`, or a namespace node id).
    #[must_use]
    pub fn ns(&self) -> Option<&str> {
        self.ns.as_deref()
    }

    /// The kind.
    #[must_use]
    pub fn kind(&self) -> SubjectKind {
        self.kind
    }

    /// The id, unique within `(ns, kind)`.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The user id, if this is a user key.
    #[must_use]
    pub fn user_id(&self) -> Option<UserId> {
        match (self.kind, &self.ns) {
            (SubjectKind::User, None) => UserId::parse(&self.id).ok(),
            _ => None,
        }
    }

    /// Parse a rendered subject key, recognising only the core kinds.
    ///
    /// See [`SubjectKey::parse_with`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::parse_with(s, &[])
    }

    /// Parse a rendered subject key (`[<ns>/]<kind>:<id>`), also recognising
    /// the app kinds labelled in `app_kinds`.
    ///
    /// The inverse of [`fmt::Display`], used to read back the subject column
    /// of a grant or membership row. Returns `None` on any shape or kind it
    /// does not recognise — a grant whose subject will not parse must be
    /// dropped closed, never widened into a match-anything.
    #[must_use]
    pub fn parse_with(s: &str, app_kinds: &[&'static str]) -> Option<Self> {
        let colon = s.find(':')?;
        let (ns, rest) = match s.find('/') {
            Some(slash) if slash < colon => (Some(&s[..slash]), &s[slash + 1..]),
            _ => (None, s),
        };
        let (kind, id) = rest.split_once(':')?;
        let kind = match kind {
            "user" => SubjectKind::User,
            "workload" => SubjectKind::Workload,
            other => SubjectKind::App(app_kinds.iter().copied().find(|k| *k == other)?),
        };
        Self::new(ns, kind, id)
    }
}

fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

impl fmt::Display for SubjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ns) = &self.ns {
            write!(f, "{ns}/")?;
        }
        write!(f, "{}:{}", self.kind, self.id)
    }
}

/// An authenticated caller, resolved identically no matter how it proved
/// itself.
///
/// A `Subject` is deliberately **not** constructible from a bare string (no
/// `Default`, no `From<String>`): it is minted at the server's single
/// resolution seam from a verified credential.
///
/// `acting_in` is the namespace the *request* targets. A session is no longer
/// bound to one org at mint time (docs/design.md §3): the request names its
/// target and authz checks membership there. It is a claim to be checked,
/// never a grant of anything.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Subject {
    key: SubjectKey,
    acting_in: Option<NsNodeId>,
}

impl Subject {
    /// A subject acting in no particular namespace.
    #[must_use]
    pub fn new(key: SubjectKey) -> Self {
        Self {
            key,
            acting_in: None,
        }
    }

    /// The same subject, targeting `ns`.
    #[must_use]
    pub fn acting_in(self, ns: NsNodeId) -> Self {
        Self {
            acting_in: Some(ns),
            ..self
        }
    }

    /// This subject's stable identity.
    #[must_use]
    pub fn key(&self) -> &SubjectKey {
        &self.key
    }

    /// The namespace the request targets, if any.
    #[must_use]
    pub fn target(&self) -> Option<NsNodeId> {
        self.acting_in
    }

    /// The kind.
    #[must_use]
    pub fn kind(&self) -> SubjectKind {
        self.key.kind
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.key, f)
    }
}

/// The reserved namespace a GitHub Actions workload subject lives in.
///
/// A workload token proves "a job in repo `owner/name`", and that fact is
/// **namespace-independent**: the same repo may be granted access by several
/// namespaces, and belongs to none of them. So the subject key is
/// `gha/workload:<owner>/<repo>` — `gha` occupies the namespace slot, and there
/// is no namespace node named `gha` that anything is scoped to.
///
/// Two properties make this safe rather than a collision waiting to happen:
///
/// * namespace-scoped subject keys carry a node **id** (a ULID), which can
///   never equal `gha`;
/// * a grant is matched on the **whole rendered key**, so even a hypothetical
///   `gha/user:x` could not be reached by a workload token, which always
///   renders `gha/workload:…`.
///
/// `repository_owner` is deliberately *not* part of the trust decision: a fork
/// or a newly created repo under a granted owner produces a different id here
/// and therefore matches no grant.
pub const WORKLOAD_NS_GHA: &str = "gha";

/// Validate and normalise a GitHub `owner/name` repository string.
///
/// Returns the **lowercased** repo, or `None` if it is not exactly one
/// `owner/name` pair over a conservative charset (`[A-Za-z0-9._-]`).
///
/// # Why lowercase, and why in one function
///
/// GitHub repository names are case-*preserving* but case-*insensitive*, so
/// `Ariel-OS/ariel-os` and `ariel-os/ariel-os` are the same repo. A grant
/// stores this id and a workload token's claim is matched against it by exact
/// string equality, so a case difference between the two spellings would
/// become a silent denial that looks like a server bug. Both sides call
/// **this** function — grant creation on the way in and the OIDC claim on the
/// way in — so they cannot disagree.
///
/// The charset is enforced because the result becomes a subject id that is
/// rendered into `<ns>/<kind>:<id>`: a `/` or `:` in the wrong place would let
/// a repo name impersonate another subject shape. One slash is allowed (the
/// separator itself), and [`SubjectKey::parse`] splits at the *first* `/` and
/// the *first* `:`, so the result round-trips.
#[must_use]
pub fn normalise_repo(repo: &str) -> Option<String> {
    let repo = repo.trim();
    let (owner, name) = repo.split_once('/')?;
    if owner.is_empty() || name.is_empty() {
        return None;
    }
    // 39 is GitHub's owner limit and 100 its repo-name limit; the cap is here
    // to bound what a claim can write into a subject id, not to mirror GitHub
    // exactly.
    if owner.len() > 64 || name.len() > 128 {
        return None;
    }
    let ok = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    };
    if !ok(owner) || !ok(name) {
        return None;
    }
    Some(format!(
        "{}/{}",
        owner.to_ascii_lowercase(),
        name.to_ascii_lowercase()
    ))
}

/// The [`SubjectKey`] a GitHub Actions job in `repo` authenticates as.
///
/// `repo` must already have passed [`normalise_repo`]. The single constructor,
/// so the grant-creation path and the token-exchange path cannot produce two
/// different spellings of the same identity.
#[must_use]
pub fn workload_subject_key(repo: &str) -> SubjectKey {
    SubjectKey {
        ns: Some(WORKLOAD_NS_GHA.to_owned()),
        kind: SubjectKind::Workload,
        id: repo.to_owned(),
    }
}

/// Length cap on a service (API-key identity) name.
///
/// Bounds what an operator-chosen string can write into a subject id, in the
/// same spirit as [`normalise_repo`]'s owner/name caps. 64 characters is far
/// more than a readable agent name needs and far less than anything that could
/// make a rendered key unwieldy in a terminal, a log line or an audit row.
pub const MAX_SERVICE_NAME_LEN: usize = 64;

/// Validate and normalise a service name (fleet's `auth-key create --as
/// <name>`).
///
/// Returns the **lowercased** name, or `None` if it is not a non-empty string
/// of at most [`MAX_SERVICE_NAME_LEN`] characters over `[a-z0-9._-]` starting
/// with `[a-z0-9]`. Never repairs: a name that does not pass is refused at mint
/// time rather than silently becoming a different identity.
///
/// # Why each rule exists
///
/// * **Lowercasing.** An identity is a name an operator retypes months later
///   when rotating the credential. `Builder` and `builder` producing two
///   subjects would silently fork the audit trail — exactly the bug named
///   identities exist to remove. Normalising in one function is what stops
///   the mint path and the redemption path from disagreeing.
/// * **The charset.** The name is rendered into `<ns>/workload:agent:<name>`.
///   Excluding `:` makes it structurally impossible to spell another id form
///   (`key:<hash8>`) or introduce a second separator. Excluding `/` makes it
///   impossible to be mistaken for a `gha/workload:owner/repo` repo subject.
/// * **The first character.** A leading `-` reads as a flag in every message,
///   shell recipe and CLI example that quotes the name, and a leading `.`
///   invites `.` or `..`, which look like paths.
///
/// The name is **namespace-scoped**: the subject carries the namespace, so two
/// tenants may each have a `builder` without collision.
#[must_use]
pub fn normalise_service_name(name: &str) -> Option<String> {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() || name.len() > MAX_SERVICE_NAME_LEN {
        return None;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return None;
    }
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(name)
}

/// The [`SubjectKey`] an API key minted with a service name speaks as:
/// `<ns id>/workload:agent:<name>`.
///
/// `name` must already have passed [`normalise_service_name`]. The **only**
/// place the `agent:` prefix is spelled, for the reason
/// [`workload_subject_key`]'s doc gives: two spellings of one identity is the
/// failure mode.
///
/// Namespace-scoped, so it can never collide with a `gha/workload:owner/repo`
/// repo subject, and — because the charset excludes `:` — never with another
/// id spelling either.
#[must_use]
pub fn agent_subject_key(ns: &NsNodeId, name: &str) -> SubjectKey {
    SubjectKey {
        ns: Some(ns.to_string()),
        kind: SubjectKind::Workload,
        id: format!("agent:{name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_key_renders_without_namespace() {
        let id = UserId::from_parts(1, 2);
        let key = SubjectKey::user(id);
        assert_eq!(key.to_string(), format!("user:{id}"));
        assert_eq!(SubjectKey::parse(&key.to_string()), Some(key.clone()));
        assert_eq!(key.user_id(), Some(id));
        assert_eq!(key.ns(), None);
    }

    #[test]
    fn app_kinds_parse_only_when_known() {
        let node = SubjectKind::app("node").unwrap();
        let key = SubjectKey::new(Some("ns1"), node, "rpi-1").unwrap();
        assert_eq!(key.to_string(), "ns1/node:rpi-1");
        assert_eq!(SubjectKey::parse(&key.to_string()), None);
        assert_eq!(
            SubjectKey::parse_with(&key.to_string(), &["node"]),
            Some(key)
        );
        assert_eq!(SubjectKind::app("user"), None);
        assert_eq!(SubjectKind::app("workload"), None);
        assert_eq!(SubjectKind::app("No"), None);
        assert_eq!(SubjectKind::app(""), None);
    }

    /// An id containing `:` still parses: the split is at the *first* colon
    /// after the namespace, and ids are opaque.
    #[test]
    fn parse_splits_at_the_first_separators() {
        let k = SubjectKey::parse("acme/user:gh-1:2").unwrap();
        assert_eq!(k.id(), "gh-1:2");
        assert_eq!(k.ns(), Some("acme"));
        // A `/` after the first `:` belongs to the id, not the namespace.
        let k = SubjectKey::parse("workload:a/b").unwrap();
        assert_eq!(k.ns(), None);
        assert_eq!(k.id(), "a/b");
    }

    #[test]
    fn malformed_subject_keys_are_rejected_not_guessed() {
        for bad in [
            "acme/user",
            "acme/root:alice",
            "/user:alice",
            "acme/user:",
            "user:",
            "alice",
            "",
            "a/b/user:x",
            "user:a\nb",
            "node:x",
        ] {
            assert_eq!(SubjectKey::parse(bad), None, "{bad:?} should not parse");
        }
    }

    #[test]
    fn new_rejects_shapes_that_would_not_round_trip() {
        assert!(SubjectKey::new(Some("a/b"), SubjectKind::User, "x").is_none());
        assert!(SubjectKey::new(Some("a:b"), SubjectKind::User, "x").is_none());
        assert!(SubjectKey::new(Some(""), SubjectKind::User, "x").is_none());
        assert!(SubjectKey::new(None, SubjectKind::User, "").is_none());
        assert!(SubjectKey::new(None, SubjectKind::App("Bad"), "x").is_none());
    }

    #[test]
    fn subject_key_excludes_acting_in() {
        let key = SubjectKey::user(UserId::from_parts(1, 1));
        let a = Subject::new(key.clone());
        let b = Subject::new(key).acting_in(NsNodeId::from_parts(2, 2));
        assert_ne!(a, b);
        assert_eq!(a.key(), b.key());
        assert_eq!(b.target(), Some(NsNodeId::from_parts(2, 2)));
        assert_eq!(a.kind(), SubjectKind::User);
    }

    /// The workload subject shape, and the property that makes it work: an id
    /// containing a slash round-trips through `SubjectKey::parse`.
    #[test]
    fn a_workload_subject_key_round_trips_through_parse() {
        let key = workload_subject_key(&normalise_repo("ariel-os/ariel-os").unwrap());
        assert_eq!(key.to_string(), "gha/workload:ariel-os/ariel-os");
        assert_eq!(SubjectKey::parse(&key.to_string()), Some(key.clone()));
        assert_eq!(key.ns(), Some(WORKLOAD_NS_GHA));
        assert_eq!(key.kind(), SubjectKind::Workload);
    }

    /// Case-insensitivity is normalised on **both** sides (grant creation and
    /// claim ingestion) by this one function.
    #[test]
    fn repo_normalisation_lowercases_and_validates() {
        assert_eq!(
            normalise_repo("Ariel-OS/Ariel-OS").as_deref(),
            Some("ariel-os/ariel-os")
        );
        assert_eq!(normalise_repo("  a/b ").as_deref(), Some("a/b"));
        assert_eq!(
            normalise_repo("a_b.c/d-e.f").as_deref(),
            Some("a_b.c/d-e.f")
        );
        for bad in [
            "",
            "owner",
            "owner/",
            "/name",
            // A second slash, or a colon, would let a repo name impersonate
            // another subject shape once it is rendered into a subject key.
            "owner/name/extra",
            "own:er/name",
            "owner/na:me",
            "owner/na me",
            "owner/na\nme",
        ] {
            assert_eq!(normalise_repo(bad), None, "{bad:?} should not normalise");
        }
        assert_eq!(normalise_repo(&format!("{}/b", "x".repeat(65))), None);
        assert_eq!(normalise_repo(&format!("a/{}", "x".repeat(129))), None);
    }

    #[test]
    fn service_name_normalisation_lowercases_and_validates() {
        assert_eq!(
            normalise_service_name("Builder").as_deref(),
            Some("builder")
        );
        assert_eq!(normalise_service_name("  ci-2 ").as_deref(), Some("ci-2"));
        assert_eq!(
            normalise_service_name("a_b.c-9").as_deref(),
            Some("a_b.c-9")
        );
        for bad in [
            "",
            " ",
            "a b",
            // A `/` would make the name look like a repo subject once rendered.
            "a/b",
            // A `:` would let a name spell another id form.
            "key:deadbeef",
            "a:b",
            // A leading `-` reads as a flag; a leading `.` invites `..`.
            "-x",
            "..",
            ".hidden",
            "naïve",
            "a\nb",
        ] {
            assert_eq!(normalise_service_name(bad), None, "{bad:?}");
        }
        assert_eq!(
            normalise_service_name(&"x".repeat(MAX_SERVICE_NAME_LEN)).as_deref(),
            Some("x".repeat(MAX_SERVICE_NAME_LEN).as_str())
        );
        assert_eq!(
            normalise_service_name(&"x".repeat(MAX_SERVICE_NAME_LEN + 1)),
            None
        );
    }

    #[test]
    fn an_agent_subject_key_round_trips_through_parse() {
        let ns = NsNodeId::from_parts(7, 7);
        let key = agent_subject_key(&ns, "builder");
        assert_eq!(key.to_string(), format!("{ns}/workload:agent:builder"));
        assert_eq!(SubjectKey::parse(&key.to_string()), Some(key.clone()));
        assert_eq!(key.kind(), SubjectKind::Workload);
        // Namespace-scoped: the same name in two namespaces is two subjects.
        assert_ne!(
            key,
            agent_subject_key(&NsNodeId::from_parts(8, 8), "builder")
        );
        // And never the reserved `gha` namespace.
        assert_ne!(key.ns(), Some(WORKLOAD_NS_GHA));
    }
}
