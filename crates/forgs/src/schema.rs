//! The app-defined namespace schema (docs/design.md §2).
//!
//! Namespaces are a tree of typed nodes. `kind` is an app-defined string,
//! checked against a [`Schema`] the app supplies at startup:
//!
//! ```
//! use forgs::schema::{KindSpec, Schema};
//!
//! let schema = Schema::builder()
//!     .kind("org", KindSpec::root().children(&["project"]).personal_for_users())
//!     .kind("project", KindSpec::child().leaf())
//!     .reserved(&["api", "admin", "login", "settings"])
//!     .build()
//!     .unwrap();
//! assert!(schema.can_place("project", Some("org")));
//! ```
//!
//! # Placement
//!
//! A kind is either **root** (its nodes have no parent) or **child**. A child
//! kind's allowed parents may be declared from either end — on the parent with
//! [`KindSpec::children`], or on the child with [`KindSpec::under`] — or both.
//! [`SchemaBuilder::build`] takes the union and checks that where both ends
//! speak they agree: a parent that lists its children explicitly (including
//! [`KindSpec::leaf`], "no children") must list every kind that claims to go
//! under it, and a child that lists its parents explicitly must list every
//! parent that claims it.
//!
//! # Naming
//!
//! Each kind is exactly one of:
//!
//! * **user-named** (the default): names are chosen by users. They are checked
//!   against the reserved list, and a *root* user-named kind shares the root
//!   name space with usernames, so it is also held to the [`UsernamePolicy`]
//!   (GitHub's "users and orgs share one name space"). A child user-named kind
//!   uses its own [`NameRules`].
//! * **externally named** ([`KindSpec::externally_named`]): mirrored upstream
//!   names (forgefront's `github/<owner>/<repo>`). Only the kind's own rules
//!   apply — which may be looser than local ones — and they are **never**
//!   checked against local reservations. Users cannot choose them.
//! * **app-created** ([`KindSpec::app_created`]): created by the app itself
//!   (forgefront's `forge` nodes, `github`, `codeberg`). Users cannot choose
//!   them either.
//!
//! # What this module does not check
//!
//! Collision with existing siblings (root-level kinds share the root name
//! space), and with **tombstoned** released names, which are blocked forever
//! unless the store sets a cool-down (docs/design.md §2), are storage concerns: `forgs-store` enforces them
//! transactionally on every creation and rename path.

use std::collections::BTreeMap;

use crate::username::{NameError, UsernamePolicy};

/// Name rules for a kind: an ASCII alphanumeric charset plus some
/// punctuation, length bounds, and case folding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRules {
    /// Punctuation allowed in addition to ASCII letters and digits.
    pub punct: &'static str,
    /// Minimum length (at least 1 is enforced regardless).
    pub min_len: usize,
    /// Maximum length.
    pub max_len: usize,
    /// Fold ASCII upper case to lower case. Without folding, upper-case
    /// letters are kept as given.
    pub fold_case: bool,
    /// Require the first and last character to be alphanumeric.
    pub alnum_edges: bool,
}

impl Default for NameRules {
    /// `[a-z0-9._-]`, 1..=100, case-folded, alphanumeric at both ends — a
    /// project-name shape.
    fn default() -> Self {
        Self {
            punct: "._-",
            min_len: 1,
            max_len: 100,
            fold_case: true,
            alnum_edges: true,
        }
    }
}

impl NameRules {
    /// GitHub's owner/repository charset (`[A-Za-z0-9._-]`, 1..=100), folded
    /// to lower case because GitHub names are case-insensitive. Edges are not
    /// restricted: upstream names are mirrored, not judged.
    #[must_use]
    pub fn github() -> Self {
        Self {
            punct: "._-",
            min_len: 1,
            max_len: 100,
            fold_case: true,
            alnum_edges: false,
        }
    }

    /// Trim, optionally fold, and validate `raw`.
    ///
    /// # Errors
    ///
    /// Returns the first [`NameError`] rule violated.
    pub fn canonicalise(&self, raw: &str) -> Result<String, NameError> {
        let trimmed = raw.trim();
        let name = if self.fold_case {
            trimmed.to_ascii_lowercase()
        } else {
            trimmed.to_owned()
        };
        if name.is_empty() {
            return Err(NameError::Empty);
        }
        if let Some(c) = name
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || self.punct.contains(*c)))
        {
            return Err(NameError::BadChar(c));
        }
        if name == "." || name == ".." {
            return Err(NameError::DotName);
        }
        let min = self.min_len.max(1);
        if name.len() < min {
            return Err(NameError::TooShort { min });
        }
        if name.len() > self.max_len {
            return Err(NameError::TooLong { max: self.max_len });
        }
        if self.alnum_edges {
            if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
                return Err(NameError::BadStart);
            }
            if !name.ends_with(|c: char| c.is_ascii_alphanumeric()) {
                return Err(NameError::BadEnd);
            }
        }
        Ok(name)
    }
}

/// Who names a kind's nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Naming {
    /// Chosen by users; reserved names apply.
    User,
    /// Mirrored from upstream; reserved names never apply.
    External,
    /// Created by the app only.
    App,
}

/// Where a name comes from, for [`Schema::canonical_name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameOrigin {
    /// A user typed it.
    User,
    /// The app or an upstream mirror supplied it.
    App,
}

/// The description of one namespace kind. Build with [`KindSpec::root`] or
/// [`KindSpec::child`] and the chained setters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindSpec {
    root: bool,
    under: Option<Vec<String>>,
    children: Option<Vec<String>>,
    personal: bool,
    naming: Naming,
    rules: NameRules,
}

impl KindSpec {
    fn new(root: bool) -> Self {
        Self {
            root,
            under: None,
            children: None,
            personal: false,
            naming: Naming::User,
            rules: NameRules::default(),
        }
    }

    /// A kind whose nodes sit at the root of the tree.
    #[must_use]
    pub fn root() -> Self {
        Self::new(true)
    }

    /// A kind whose nodes have a parent.
    #[must_use]
    pub fn child() -> Self {
        Self::new(false)
    }

    /// The kinds this (child) kind may be placed under.
    #[must_use]
    pub fn under(mut self, parents: &[&str]) -> Self {
        self.under = Some(parents.iter().map(|s| (*s).to_owned()).collect());
        self
    }

    /// The kinds that may be placed under this kind. Replaces any earlier
    /// `children`/`leaf`.
    #[must_use]
    pub fn children(mut self, kinds: &[&str]) -> Self {
        self.children = Some(kinds.iter().map(|s| (*s).to_owned()).collect());
        self
    }

    /// No kind may be placed under this kind.
    #[must_use]
    pub fn leaf(self) -> Self {
        self.children(&[])
    }

    /// Signup creates a node of this kind named after the username. At most
    /// one kind per schema; it must be root and user-named.
    #[must_use]
    pub fn personal_for_users(mut self) -> Self {
        self.personal = true;
        self
    }

    /// Names are chosen by users (the default).
    #[must_use]
    pub fn user_named(mut self) -> Self {
        self.naming = Naming::User;
        self
    }

    /// Names are mirrored from upstream, under `rules`.
    #[must_use]
    pub fn externally_named(mut self, rules: NameRules) -> Self {
        self.naming = Naming::External;
        self.rules = rules;
        self
    }

    /// Nodes are created by the app only.
    #[must_use]
    pub fn app_created(mut self) -> Self {
        self.naming = Naming::App;
        self
    }

    /// Override the name rules.
    #[must_use]
    pub fn name_rules(mut self, rules: NameRules) -> Self {
        self.rules = rules;
        self
    }

    /// Whether nodes of this kind sit at the root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.root
    }

    /// Whether this is the personal kind.
    #[must_use]
    pub fn is_personal(&self) -> bool {
        self.personal
    }

    /// Who names nodes of this kind.
    #[must_use]
    pub fn naming(&self) -> Naming {
        self.naming
    }

    /// The kind's name rules.
    #[must_use]
    pub fn rules(&self) -> &NameRules {
        &self.rules
    }
}

/// Why a [`Schema`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    /// A kind name outside `[a-z_]+`.
    #[error("kind name {0:?} must be non-empty [a-z_]")]
    BadKindName(String),
    /// A kind declared twice.
    #[error("kind {0:?} is declared twice")]
    DuplicateKind(String),
    /// No root kind at all.
    #[error("a schema needs at least one root kind")]
    NoRootKind,
    /// A reference to an undeclared kind.
    #[error("kind {by:?} references unknown kind {missing:?}")]
    UnknownKind {
        /// The kind that made the reference.
        by: String,
        /// The kind that does not exist.
        missing: String,
    },
    /// A root kind listed as someone's child, or given parents.
    #[error("root kind {child:?} cannot be placed under {parent:?}")]
    RootAsChild {
        /// The root kind.
        child: String,
        /// The kind that would be its parent.
        parent: String,
    },
    /// A child kind with no possible parent.
    #[error("child kind {0:?} has no parent kind")]
    OrphanChild(String),
    /// The two ends of a parent/child declaration disagree.
    #[error("{child:?} is declared under {parent:?}, but the other end does not list it")]
    Inconsistent {
        /// The parent kind.
        parent: String,
        /// The child kind.
        child: String,
    },
    /// More than one personal kind.
    #[error("at most one kind may be personal_for_users")]
    MultiplePersonal,
    /// The personal kind is not root or not user-named.
    #[error("personal kind {0:?} must be a user-named root kind")]
    BadPersonal(String),
    /// Unsatisfiable name rules.
    #[error("kind {0:?} has unsatisfiable name rules")]
    BadNameRules(String),
    /// A reserved name is not in canonical (trimmed, lower-case) form.
    #[error("reserved name {0:?} is not canonical")]
    ReservedNotCanonical(String),
}

/// Builds a [`Schema`]. See [`Schema::builder`].
#[derive(Debug, Clone, Default)]
pub struct SchemaBuilder {
    kinds: Vec<(String, KindSpec)>,
    reserved: Vec<String>,
    username: UsernamePolicy,
}

impl SchemaBuilder {
    /// Declare a kind.
    #[must_use]
    pub fn kind(mut self, name: &str, spec: KindSpec) -> Self {
        self.kinds.push((name.to_owned(), spec));
        self
    }

    /// Add reserved names (canonical form). Blocks them for usernames and
    /// user-named kinds; never for externally named or app-created ones.
    #[must_use]
    pub fn reserved(mut self, names: &[&str]) -> Self {
        self.reserved.extend(names.iter().map(|s| (*s).to_owned()));
        self
    }

    /// Set the username policy (default [`UsernamePolicy::default`]).
    #[must_use]
    pub fn username_policy(mut self, policy: UsernamePolicy) -> Self {
        self.username = policy;
        self
    }

    /// Validate and build the schema.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError`] for any inconsistency (see the variants).
    pub fn build(self) -> Result<Schema, SchemaError> {
        let mut kinds: BTreeMap<String, KindSpec> = BTreeMap::new();
        for (name, spec) in &self.kinds {
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
                return Err(SchemaError::BadKindName(name.clone()));
            }
            if kinds.insert(name.clone(), spec.clone()).is_some() {
                return Err(SchemaError::DuplicateKind(name.clone()));
            }
            if spec.rules.max_len < spec.rules.min_len.max(1) {
                return Err(SchemaError::BadNameRules(name.clone()));
            }
        }
        if !kinds.values().any(|k| k.root) {
            return Err(SchemaError::NoRootKind);
        }
        let exists = |by: &str, k: &str| {
            if kinds.contains_key(k) {
                Ok(())
            } else {
                Err(SchemaError::UnknownKind {
                    by: by.to_owned(),
                    missing: k.to_owned(),
                })
            }
        };
        // Union of both declaration ends: child -> allowed parents.
        let mut parents: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, spec) in &kinds {
            for p in spec.under.iter().flatten() {
                exists(name, p)?;
                if spec.root {
                    return Err(SchemaError::RootAsChild {
                        child: name.clone(),
                        parent: p.clone(),
                    });
                }
                parents.entry(name.clone()).or_default().push(p.clone());
            }
            for c in spec.children.iter().flatten() {
                exists(name, c)?;
                if kinds[c].root {
                    return Err(SchemaError::RootAsChild {
                        child: c.clone(),
                        parent: name.clone(),
                    });
                }
                let list = parents.entry(c.clone()).or_default();
                if !list.contains(name) {
                    list.push(name.clone());
                }
            }
        }
        // Where both ends speak, they must agree.
        for (child, ps) in &parents {
            for p in ps {
                if let Some(explicit) = &kinds[p].children {
                    if !explicit.contains(child) {
                        return Err(SchemaError::Inconsistent {
                            parent: p.clone(),
                            child: child.clone(),
                        });
                    }
                }
                if let Some(explicit) = &kinds[child].under {
                    if !explicit.contains(p) {
                        return Err(SchemaError::Inconsistent {
                            parent: p.clone(),
                            child: child.clone(),
                        });
                    }
                }
            }
        }
        for (name, spec) in &kinds {
            if !spec.root && parents.get(name).is_none_or(Vec::is_empty) {
                return Err(SchemaError::OrphanChild(name.clone()));
            }
        }
        let personal = personal_kind(&kinds)?;
        for r in &self.reserved {
            if r.is_empty() || *r != r.trim().to_ascii_lowercase() {
                return Err(SchemaError::ReservedNotCanonical(r.clone()));
            }
        }
        for ps in parents.values_mut() {
            ps.sort();
        }
        Ok(Schema {
            kinds,
            parents,
            personal,
            reserved: self.reserved,
            username: self.username,
        })
    }
}

/// The single personal kind, if any; it must be a user-named root kind.
fn personal_kind(kinds: &BTreeMap<String, KindSpec>) -> Result<Option<String>, SchemaError> {
    let mut personal = None;
    for (name, spec) in kinds {
        if spec.personal {
            if personal.is_some() {
                return Err(SchemaError::MultiplePersonal);
            }
            if !spec.root || spec.naming != Naming::User {
                return Err(SchemaError::BadPersonal(name.clone()));
            }
            personal = Some(name.clone());
        }
    }
    Ok(personal)
}

/// A validated namespace schema.
#[derive(Debug, Clone)]
pub struct Schema {
    kinds: BTreeMap<String, KindSpec>,
    parents: BTreeMap<String, Vec<String>>,
    personal: Option<String>,
    reserved: Vec<String>,
    username: UsernamePolicy,
}

impl Schema {
    /// Start building a schema.
    #[must_use]
    pub fn builder() -> SchemaBuilder {
        SchemaBuilder::default()
    }

    /// Look up a kind.
    #[must_use]
    pub fn kind(&self, name: &str) -> Option<&KindSpec> {
        self.kinds.get(name)
    }

    /// Every kind name, sorted.
    pub fn kinds(&self) -> impl Iterator<Item = &str> {
        self.kinds.keys().map(String::as_str)
    }

    /// The kinds a node of `kind` may be placed under (empty for root kinds).
    #[must_use]
    pub fn parents_of(&self, kind: &str) -> &[String] {
        self.parents.get(kind).map_or(&[], Vec::as_slice)
    }

    /// The personal kind, if any.
    #[must_use]
    pub fn personal_kind(&self) -> Option<&str> {
        self.personal.as_deref()
    }

    /// The username policy.
    #[must_use]
    pub fn username_policy(&self) -> &UsernamePolicy {
        &self.username
    }

    /// Whether `name` (canonical) is reserved.
    #[must_use]
    pub fn is_reserved(&self, name: &str) -> bool {
        self.reserved.iter().any(|r| r == name)
    }

    /// Whether a node of `kind` may be placed under a node of `parent_kind`
    /// (`None`: at the root). Unknown kinds are never placeable.
    #[must_use]
    pub fn can_place(&self, kind: &str, parent_kind: Option<&str>) -> bool {
        let Some(spec) = self.kinds.get(kind) else {
            return false;
        };
        match parent_kind {
            None => spec.root,
            Some(p) => !spec.root && self.parents_of(kind).iter().any(|x| x == p),
        }
    }

    /// Canonicalise and validate a node name of `kind`.
    ///
    /// * user-named kinds: the reserved list applies, and root user-named
    ///   kinds are held to the username policy as well as their own rules;
    /// * externally named and app-created kinds: refused for
    ///   [`NameOrigin::User`] ([`NameError::NotUserNameable`]); for
    ///   [`NameOrigin::App`] only the kind's own rules apply, never the
    ///   reserved list;
    /// * every **root** kind, however named: a name that parses as an id is
    ///   refused ([`NameError::IdShaped`]). A single-segment namespace
    ///   reference may be a node id or a root name, and one string must not
    ///   mean both (security audit 2026-10, AN-5). Child names cannot be
    ///   confused with an id (their path contains a `/`), so mirrored names
    ///   below the root are unaffected.
    ///
    /// # Errors
    ///
    /// Returns the first [`NameError`] rule violated.
    pub fn canonical_name(
        &self,
        kind: &str,
        raw: &str,
        origin: NameOrigin,
    ) -> Result<String, NameError> {
        let spec = self
            .kinds
            .get(kind)
            .ok_or_else(|| NameError::UnknownKind(kind.to_owned()))?;
        let name = self.canonical_name_inner(spec, raw, origin)?;
        if spec.root && crate::ids::is_id_shaped(&name) {
            return Err(NameError::IdShaped);
        }
        Ok(name)
    }

    fn canonical_name_inner(
        &self,
        spec: &KindSpec,
        raw: &str,
        origin: NameOrigin,
    ) -> Result<String, NameError> {
        match spec.naming {
            Naming::External | Naming::App => {
                if origin == NameOrigin::User {
                    return Err(NameError::NotUserNameable);
                }
                spec.rules.canonicalise(raw)
            }
            Naming::User => {
                let name = if spec.root {
                    let name = self.username.canonicalise(raw)?;
                    spec.rules.canonicalise(&name)?
                } else {
                    spec.rules.canonicalise(raw)?
                };
                if self.is_reserved(&name) {
                    return Err(NameError::Reserved);
                }
                Ok(name)
            }
        }
    }

    /// Canonicalise and validate a username: the username policy, the
    /// reserved list, and the personal kind's own name rules if there is one
    /// (the username *is* the personal node's name).
    ///
    /// # Errors
    ///
    /// Returns the first [`NameError`] rule violated.
    pub fn validate_username(&self, raw: &str) -> Result<String, NameError> {
        let name = self.username.canonicalise(raw)?;
        if let Some(p) = &self.personal {
            self.kinds[p].rules.canonicalise(&name)?;
        }
        if self.is_reserved(&name) {
            return Err(NameError::Reserved);
        }
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESERVED: &[&str] = &["api", "admin", "login", "settings"];

    fn fleet() -> Schema {
        Schema::builder()
            .kind("org", KindSpec::root().leaf().personal_for_users())
            .reserved(RESERVED)
            .reserved(&["gha"])
            .build()
            .unwrap()
    }

    fn forge() -> Schema {
        Schema::builder()
            .kind(
                "org",
                KindSpec::root().children(&["project"]).personal_for_users(),
            )
            .kind("project", KindSpec::child().leaf())
            .reserved(RESERVED)
            .build()
            .unwrap()
    }

    fn forgefront() -> Schema {
        Schema::builder()
            .kind(
                "forge",
                KindSpec::root().app_created().children(&["remote_owner"]),
            )
            .kind(
                "remote_owner",
                KindSpec::child()
                    .under(&["forge"])
                    .externally_named(NameRules::github()),
            )
            .kind(
                "repo",
                KindSpec::child()
                    .under(&["remote_owner"])
                    .externally_named(NameRules::github())
                    .leaf(),
            )
            .kind("user", KindSpec::root().leaf().personal_for_users())
            .reserved(RESERVED)
            .reserved(&["github", "codeberg"])
            .build()
            .unwrap()
    }

    #[test]
    fn the_three_design_schemas_build() {
        let f = fleet();
        assert_eq!(f.personal_kind(), Some("org"));
        assert!(f.can_place("org", None));
        assert!(!f.can_place("org", Some("org")));

        let g = forge();
        assert!(g.can_place("project", Some("org")));
        assert!(!g.can_place("project", None));
        assert!(!g.can_place("project", Some("project")));
        assert!(!g.can_place("nope", None));

        let ff = forgefront();
        assert_eq!(ff.personal_kind(), Some("user"));
        assert!(ff.can_place("forge", None));
        assert!(ff.can_place("remote_owner", Some("forge")));
        assert!(ff.can_place("repo", Some("remote_owner")));
        assert!(!ff.can_place("repo", Some("forge")));
        assert_eq!(ff.parents_of("repo"), ["remote_owner"]);
    }

    #[test]
    fn reserved_names_are_refused_as_usernames() {
        let ff = forgefront();
        assert_eq!(ff.validate_username("github"), Err(NameError::Reserved));
        assert_eq!(ff.validate_username("API"), Err(NameError::Reserved));
        assert_eq!(ff.validate_username(" Kaspar ").as_deref(), Ok("kaspar"));
        assert_eq!(
            forge().validate_username("settings"),
            Err(NameError::Reserved)
        );
        assert_eq!(fleet().validate_username("gha"), Err(NameError::Reserved));
        assert_eq!(
            forge().validate_username("a.b"),
            Err(NameError::BadChar('.'))
        );
    }

    #[test]
    fn root_user_named_kinds_follow_the_username_policy() {
        let g = forge();
        assert_eq!(
            g.canonical_name("org", "Ariel-OS", NameOrigin::User)
                .as_deref(),
            Ok("ariel-os")
        );
        assert_eq!(
            g.canonical_name("org", "ariel_os", NameOrigin::User),
            Err(NameError::BadChar('_'))
        );
        assert_eq!(
            g.canonical_name("org", "admin", NameOrigin::User),
            Err(NameError::Reserved)
        );
        // App origin does not bypass reservations on user-named kinds.
        assert_eq!(
            g.canonical_name("org", "admin", NameOrigin::App),
            Err(NameError::Reserved)
        );
    }

    #[test]
    fn child_user_named_kinds_use_their_own_rules() {
        let g = forge();
        assert_eq!(
            g.canonical_name("project", "Ariel-OS.github.io", NameOrigin::User)
                .as_deref(),
            Ok("ariel-os.github.io")
        );
        assert_eq!(
            g.canonical_name("project", "..", NameOrigin::User),
            Err(NameError::DotName)
        );
        assert_eq!(
            g.canonical_name("project", ".x", NameOrigin::User),
            Err(NameError::BadStart)
        );
        assert_eq!(
            g.canonical_name("project", "settings", NameOrigin::User),
            Err(NameError::Reserved)
        );
        assert_eq!(
            g.canonical_name("nope", "x", NameOrigin::User),
            Err(NameError::UnknownKind("nope".into()))
        );
    }

    #[test]
    fn external_names_are_folded_and_never_reserved() {
        let ff = forgefront();
        assert_eq!(
            ff.canonical_name("remote_owner", "Some.Org_x", NameOrigin::App)
                .as_deref(),
            Ok("some.org_x")
        );
        // A mirrored upstream `admin` org is fine: reservations are local.
        assert_eq!(
            ff.canonical_name("remote_owner", "admin", NameOrigin::App)
                .as_deref(),
            Ok("admin")
        );
        assert_eq!(
            ff.canonical_name("repo", "-weird-", NameOrigin::App)
                .as_deref(),
            Ok("-weird-")
        );
        assert_eq!(
            ff.canonical_name("repo", "a/b", NameOrigin::App),
            Err(NameError::BadChar('/'))
        );
        // Users cannot name external or app-created nodes.
        assert_eq!(
            ff.canonical_name("remote_owner", "x", NameOrigin::User),
            Err(NameError::NotUserNameable)
        );
        assert_eq!(
            ff.canonical_name("forge", "github", NameOrigin::User),
            Err(NameError::NotUserNameable)
        );
        // The app creating its own forge node is not blocked by the reserved
        // list, which exists precisely to keep users off that name.
        assert_eq!(
            ff.canonical_name("forge", "GitHub", NameOrigin::App)
                .as_deref(),
            Ok("github")
        );
    }

    /// AN-5: no root name, however the kind is named, may parse as an id;
    /// child names may.
    #[test]
    fn root_names_may_not_be_id_shaped() {
        let id = crate::NsNodeId::from_parts(5, 5).to_string();
        let lower = id.to_ascii_lowercase();
        let ff = forgefront();
        assert_eq!(
            ff.canonical_name("forge", &id, NameOrigin::App),
            Err(NameError::IdShaped)
        );
        assert_eq!(
            ff.canonical_name("user", &lower, NameOrigin::User),
            Err(NameError::IdShaped)
        );
        assert_eq!(ff.validate_username(&lower), Err(NameError::IdShaped));
        assert_eq!(
            ff.canonical_name("remote_owner", &id, NameOrigin::App)
                .as_deref(),
            Ok(lower.as_str())
        );
        assert_eq!(
            forge()
                .canonical_name("project", &lower, NameOrigin::User)
                .as_deref(),
            Ok(lower.as_str())
        );
    }

    #[test]
    fn case_folding_is_optional() {
        let rules = NameRules {
            fold_case: false,
            ..NameRules::github()
        };
        assert_eq!(rules.canonicalise("Some.Org").as_deref(), Ok("Some.Org"));
        assert_eq!(
            NameRules::github().canonicalise("Some.Org").as_deref(),
            Ok("some.org")
        );
    }

    #[test]
    fn bad_schemas_fail() {
        let err = |b: SchemaBuilder| b.build().unwrap_err();
        assert_eq!(
            err(Schema::builder()
                .kind("user", KindSpec::root())
                .kind("project", KindSpec::child().under(&["org"]))),
            SchemaError::UnknownKind {
                by: "project".into(),
                missing: "org".into()
            }
        );
        assert_eq!(err(Schema::builder()), SchemaError::NoRootKind);
        assert_eq!(
            err(Schema::builder()
                .kind("org", KindSpec::root())
                .kind("project", KindSpec::child())),
            SchemaError::OrphanChild("project".into())
        );
        assert_eq!(
            err(Schema::builder()
                .kind("org", KindSpec::root().leaf())
                .kind("project", KindSpec::child().under(&["org"]))),
            SchemaError::Inconsistent {
                parent: "org".into(),
                child: "project".into()
            }
        );
        assert_eq!(
            err(Schema::builder()
                .kind("org", KindSpec::root().children(&["project"]))
                .kind("team", KindSpec::root().children(&["project"]))
                .kind("project", KindSpec::child().under(&["org"]))),
            SchemaError::Inconsistent {
                parent: "team".into(),
                child: "project".into()
            }
        );
        assert_eq!(
            err(Schema::builder()
                .kind("org", KindSpec::root().children(&["user"]))
                .kind("user", KindSpec::root())),
            SchemaError::RootAsChild {
                child: "user".into(),
                parent: "org".into()
            }
        );
        assert_eq!(
            err(Schema::builder()
                .kind("org", KindSpec::root().personal_for_users())
                .kind("user", KindSpec::root().personal_for_users())),
            SchemaError::MultiplePersonal
        );
        assert_eq!(
            err(Schema::builder()
                .kind("org", KindSpec::root().children(&["p"]))
                .kind("p", KindSpec::child().personal_for_users())),
            SchemaError::BadPersonal("p".into())
        );
        assert_eq!(
            err(Schema::builder().kind("f", KindSpec::root().app_created().personal_for_users())),
            SchemaError::BadPersonal("f".into())
        );
        assert_eq!(
            err(Schema::builder()
                .kind("org", KindSpec::root())
                .reserved(&["API"])),
            SchemaError::ReservedNotCanonical("API".into())
        );
        assert_eq!(
            err(Schema::builder()
                .kind("org", KindSpec::root())
                .kind("org", KindSpec::root())),
            SchemaError::DuplicateKind("org".into())
        );
        assert_eq!(
            err(Schema::builder().kind("Org", KindSpec::root())),
            SchemaError::BadKindName("Org".into())
        );
        assert_eq!(
            err(Schema::builder().kind(
                "org",
                KindSpec::root().name_rules(NameRules {
                    max_len: 0,
                    ..NameRules::default()
                })
            )),
            SchemaError::BadNameRules("org".into())
        );
    }
}
