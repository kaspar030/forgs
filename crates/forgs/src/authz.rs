//! Authorization evaluation — the pure half (docs/design.md §2, survey §4).
//!
//! Everything here is a function of values already loaded from storage: no
//! IO, no clock (`now` is always a parameter), so the whole
//! (subject, object, op) → allow/deny matrix is a table-driven unit test.
//!
//! # Roles inherit down the tree
//!
//! The effective role on a node is the **max** over its ancestors'
//! memberships ([`effective_role`]). Membership in `ariel-os` grants access
//! to `ariel-os/*`; a direct collaborator entry on `ariel-os/foo` can raise it
//! for one project but never lower it. Deny entries are deliberately absent:
//! they make "who can see this" unanswerable.
//!
//! # Visibility inherits restrictively
//!
//! A node's visibility is inherited from its parent unless overridden **more
//! restrictively** ([`effective_visibility`]); a less restrictive override is
//! ignored, so making a project public can never expose a private org.
//!
//! # Grants, deny by default, and the namespace fence
//!
//! A grant is "node N's admin grants subject S ops O over selector X within
//! N's subtree, expiring". The selector and op languages are app-defined
//! ([`Selector`], [`Op`]); forgs evaluates liveness and the **namespace
//! fence**: a grant only ever admits resources inside the granting node's
//! subtree, as a conjunct of every check ([`GrantScope::covers`]). This
//! matters because selector languages are namespace-blind — a grant issued in
//! A saying `tag=nrf52` must not reach B's identically tagged resource. The
//! fence *is* the tenancy boundary.
//!
//! An [`Access`] built from nothing allows nothing.
//!
//! # No oracle
//!
//! [`AuthzError`] is deliberately coarse: a caller that may not see a
//! resource gets [`AuthzError::NotFound`], exactly as if it did not exist.

use crate::ids::{GrantId, NsNodeId};
use crate::role::Role;

/// Why a request was refused. Coarse on purpose (no oracle).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthzError {
    /// The caller may see the resource but not do this to it.
    #[error("permission denied")]
    Denied,
    /// The resource does not exist **or the caller may not see it**.
    #[error("not found")]
    NotFound,
}

/// The effective role on a node, given the direct membership role (if any)
/// at each node of its ancestor chain, root first, the node itself last.
///
/// The max over the chain: roles inherit down and are never lowered. `None`
/// means no membership anywhere on the chain.
#[must_use]
pub fn effective_role(chain: &[(NsNodeId, Option<Role>)]) -> Option<Role> {
    chain.iter().filter_map(|(_, r)| *r).max()
}

/// A node's visibility, ordered from least to most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Visibility {
    /// Anyone, including anonymous callers.
    Public,
    /// Any authenticated user.
    Internal,
    /// Members (anyone with an effective role) only.
    Private,
}

impl Visibility {
    /// The stored label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Internal => "internal",
            Visibility::Private => "private",
        }
    }

    /// Parse a stored label. `None` for anything unknown — callers must treat
    /// that as [`Visibility::Private`] (fail closed).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "public" => Some(Visibility::Public),
            "internal" => Some(Visibility::Internal),
            "private" => Some(Visibility::Private),
            _ => None,
        }
    }
}

/// The effective visibility of a node, given each chain node's own setting
/// (root first, `None` = inherit).
///
/// The most restrictive setting on the chain wins: an override is honoured
/// only if it is more restrictive than what it inherits. A chain with no
/// setting at all is [`Visibility::Private`] (fail closed).
#[must_use]
pub fn effective_visibility(chain: &[Option<Visibility>]) -> Visibility {
    chain
        .iter()
        .flatten()
        .copied()
        .max()
        .unwrap_or(Visibility::Private)
}

/// Whether a caller may see a node of `visibility`.
///
/// `authenticated_user` is whether the caller is a logged-in *user* (a
/// workload is not "internal"); `role` is its effective role on the node.
#[must_use]
pub fn can_see(visibility: Visibility, authenticated_user: bool, role: Option<Role>) -> bool {
    match visibility {
        Visibility::Public => true,
        Visibility::Internal => authenticated_user || role.is_some(),
        Visibility::Private => role.is_some(),
    }
}

/// An app-defined grant operation (fleet: `attach`, `flash`, …).
pub trait Op: Copy + Ord {}

impl<T: Copy + Ord> Op for T {}

/// A resource an app authorizes access to (fleet: a board).
pub trait Resource {
    /// The namespace nodes the resource lies within: every ancestor of its
    /// owning node, including that node itself.
    fn ns_path(&self) -> &[NsNodeId];
}

/// An app-defined selector language over resources `R` (fleet's
/// `Constraint`).
///
/// **Namespace-blind by design**: tenancy is not checked here. Every caller
/// must pair it with the namespace fence — [`GrantScope::covers`] does.
pub trait Selector<R: ?Sized> {
    /// Does `resource` satisfy the selector?
    fn matches(&self, resource: &R) -> bool;
}

/// One grant, as the evaluator sees it.
///
/// Built from a stored grant row: the selector is re-parsed from its canonical
/// rendering and the ops from their labels. A row that fails to re-parse is
/// dropped **closed** by the builder — never widened into a match-anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantScope<S, O> {
    /// The grant's id, so an audit line can name what allowed a request.
    pub id: GrantId,
    /// The node that issued the grant. It only admits resources in this
    /// node's subtree — see the module docs.
    pub ns: NsNodeId,
    /// Which resources the grant covers.
    pub selector: S,
    /// Which operations it confers.
    pub ops: Vec<O>,
    /// Expiry as epoch seconds; `None` means no expiry.
    pub expires: Option<u64>,
}

impl<S, O> GrantScope<S, O> {
    /// Whether the grant is still live at `now`. Exclusive at the boundary:
    /// `now == expires` is expired.
    #[must_use]
    pub fn is_live_at(&self, now: u64) -> bool {
        self.expires.is_none_or(|e| now < e)
    }

    /// Whether the grant covers `resource`: inside the granting subtree
    /// **and** selector match.
    #[must_use]
    pub fn covers<R: Resource + ?Sized>(&self, resource: &R) -> bool
    where
        S: Selector<R>,
    {
        resource.ns_path().contains(&self.ns) && self.selector.matches(resource)
    }
}

/// Membership-derived access to one subtree: the ops the subject's role on
/// `ns` confers (the app maps role → ops).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership<O> {
    /// The node the subject is a member of; covers its whole subtree.
    pub ns: NsNodeId,
    /// The operations the membership confers.
    pub ops: Vec<O>,
}

/// Everything one authenticated subject may reach, resolved once per request
/// from the authenticated subject and never from anything the caller says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access<S, O> {
    /// Memberships (the ownership path). Workloads have none.
    pub memberships: Vec<Membership<O>>,
    /// Grants issued *to* this subject, from any namespace.
    pub grants: Vec<GrantScope<S, O>>,
}

impl<S, O> Default for Access<S, O> {
    fn default() -> Self {
        Self {
            memberships: Vec::new(),
            grants: Vec::new(),
        }
    }
}

impl<S, O: Op> Access<S, O> {
    /// The deny-everything access.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Whether this access confers nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.memberships.is_empty() && self.grants.is_empty()
    }

    fn member_ops<'a, R: Resource + ?Sized>(
        &'a self,
        resource: &'a R,
    ) -> impl Iterator<Item = O> + 'a {
        self.memberships
            .iter()
            .filter(|m| resource.ns_path().contains(&m.ns))
            .flat_map(|m| m.ops.iter().copied())
    }

    /// The first live grant covering `resource`, if any.
    ///
    /// Returned so an audit line can record *which* grant admitted a request —
    /// "allowed by membership" and "allowed by grant X" are different facts,
    /// and only the second can be revoked.
    #[must_use]
    pub fn matching_grant<R: Resource + ?Sized>(
        &self,
        resource: &R,
        now: u64,
    ) -> Option<&GrantScope<S, O>>
    where
        S: Selector<R>,
    {
        self.grants
            .iter()
            .find(|g| g.is_live_at(now) && g.covers(resource))
    }

    /// Whether the subject may reach `resource` at all (for any operation).
    #[must_use]
    pub fn may_use<R: Resource + ?Sized>(&self, resource: &R, now: u64) -> bool
    where
        S: Selector<R>,
    {
        self.memberships
            .iter()
            .any(|m| resource.ns_path().contains(&m.ns))
            || self.matching_grant(resource, now).is_some()
    }

    /// The union of operations the subject may perform on `resource`, sorted
    /// and deduplicated.
    ///
    /// Empty means "no access", and callers must treat it that way rather than
    /// as "unrestricted".
    #[must_use]
    pub fn effective_ops<R: Resource + ?Sized>(&self, resource: &R, now: u64) -> Vec<O>
    where
        S: Selector<R>,
    {
        let mut ops: Vec<O> = self
            .member_ops(resource)
            .chain(
                self.grants
                    .iter()
                    .filter(|g| g.is_live_at(now) && g.covers(resource))
                    .flat_map(|g| g.ops.iter().copied()),
            )
            .collect();
        ops.sort_unstable();
        ops.dedup();
        ops
    }

    /// Whether the subject may perform `op` on `resource` at `now`.
    #[must_use]
    pub fn allows<R: Resource + ?Sized>(&self, resource: &R, op: O, now: u64) -> bool
    where
        S: Selector<R>,
    {
        self.effective_ops(resource, now).contains(&op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::role::RoleLadder;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum TOp {
        Attach,
        Flash,
        Gdb,
        PowerCycle,
    }

    const ALL: [TOp; 4] = [TOp::Attach, TOp::Flash, TOp::Gdb, TOp::PowerCycle];

    struct Board {
        path: Vec<NsNodeId>,
        name: &'static str,
        tags: Vec<&'static str>,
    }

    impl Resource for Board {
        fn ns_path(&self) -> &[NsNodeId] {
            &self.path
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Sel {
        Name(&'static str),
        Tags(Vec<&'static str>),
    }

    impl Selector<Board> for Sel {
        fn matches(&self, b: &Board) -> bool {
            match self {
                Sel::Name(n) => b.name == *n,
                Sel::Tags(t) => t.iter().all(|t| b.tags.contains(t)),
            }
        }
    }

    fn ns(n: u64) -> NsNodeId {
        NsNodeId::from_parts(n, u128::from(n))
    }

    // Tree: 1 (org a) -> 11 (project a/x); 2 (org b); 3 (org c).
    fn board(path: &[u64], name: &'static str, tags: &[&'static str]) -> Board {
        Board {
            path: path.iter().copied().map(ns).collect(),
            name,
            tags: tags.to_vec(),
        }
    }

    fn grant(on: u64, sel: Sel, ops: &[TOp], expires: Option<u64>) -> GrantScope<Sel, TOp> {
        GrantScope {
            id: GrantId::from_parts(on, 0),
            ns: ns(on),
            selector: sel,
            ops: ops.to_vec(),
            expires,
        }
    }

    fn member(on: u64) -> Membership<TOp> {
        Membership {
            ns: ns(on),
            ops: ALL.to_vec(),
        }
    }

    const NOW: u64 = 1_000;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn access_matrix() {
        let a_board = board(&[1], "b1", &["nrf52", "lab"]);
        let proj_board = board(&[1, 11], "b2", &["nrf52"]);
        let c_board = board(&[3], "b1", &["nrf52"]);

        let member_of_a = Access {
            memberships: vec![member(1)],
            grants: vec![],
        };
        let member_of_ax = Access {
            memberships: vec![member(11)],
            grants: vec![],
        };
        let granted_flash = Access {
            memberships: vec![member(2)],
            grants: vec![grant(
                1,
                Sel::Tags(vec!["nrf52"]),
                &[TOp::Flash, TOp::Attach],
                Some(2_000),
            )],
        };
        let expired = Access {
            memberships: vec![],
            grants: vec![grant(
                1,
                Sel::Tags(vec!["nrf52"]),
                &[TOp::Attach],
                Some(NOW),
            )],
        };
        let selector_miss = Access {
            memberships: vec![],
            grants: vec![grant(1, Sel::Tags(vec!["stm32"]), &[TOp::Attach], None)],
        };
        let by_name = Access {
            memberships: vec![],
            grants: vec![grant(1, Sel::Name("b1"), &[TOp::Attach], None)],
        };
        let outsider = Access {
            memberships: vec![member(2)],
            grants: vec![],
        };

        #[allow(clippy::type_complexity)]
        let cases: &[(&str, &Access<Sel, TOp>, &Board, TOp, bool)] = &[
            (
                "member may attach",
                &member_of_a,
                &a_board,
                TOp::Attach,
                true,
            ),
            (
                "member may power-cycle",
                &member_of_a,
                &a_board,
                TOp::PowerCycle,
                true,
            ),
            // Membership inherits down the tree...
            (
                "org membership reaches a project",
                &member_of_a,
                &proj_board,
                TOp::Flash,
                true,
            ),
            // ...but never up.
            (
                "project membership does not reach the org",
                &member_of_ax,
                &a_board,
                TOp::Attach,
                false,
            ),
            (
                "non-member, no grant, is denied",
                &outsider,
                &a_board,
                TOp::Attach,
                false,
            ),
            (
                "grantee may use a granted op",
                &granted_flash,
                &a_board,
                TOp::Flash,
                true,
            ),
            (
                "grantee may not use an ungranted op",
                &granted_flash,
                &a_board,
                TOp::Gdb,
                false,
            ),
            (
                "a grant reaches the granting node's subtree",
                &granted_flash,
                &proj_board,
                TOp::Flash,
                true,
            ),
            (
                "an expired grant confers nothing",
                &expired,
                &a_board,
                TOp::Attach,
                false,
            ),
            (
                "a selector miss confers nothing",
                &selector_miss,
                &a_board,
                TOp::Attach,
                false,
            ),
            (
                "name= is a normal selector",
                &by_name,
                &a_board,
                TOp::Attach,
                true,
            ),
            // THE NAMESPACE FENCE: a grant issued in A must not reach C's
            // identically tagged / named resource.
            (
                "a grant never crosses into another namespace",
                &granted_flash,
                &c_board,
                TOp::Flash,
                false,
            ),
            (
                "a name= grant never crosses either",
                &by_name,
                &c_board,
                TOp::Attach,
                false,
            ),
            (
                "empty access allows nothing",
                &Access::none(),
                &a_board,
                TOp::Attach,
                false,
            ),
        ];
        for (why, access, board, op, expected) in cases {
            assert_eq!(access.allows(*board, *op, NOW), *expected, "{why}");
        }
    }

    #[test]
    fn empty_access_is_empty_and_uses_nothing() {
        let b = board(&[1], "b1", &[]);
        let none = Access::<Sel, TOp>::none();
        assert!(none.is_empty());
        assert!(!none.may_use(&b, NOW));
        assert_eq!(none.effective_ops(&b, NOW), Vec::<TOp>::new());
        assert!(none.matching_grant(&b, NOW).is_none());
    }

    #[test]
    fn overlapping_grants_union_their_ops() {
        let b = board(&[1], "b1", &["nrf52", "lab"]);
        let access = Access {
            memberships: vec![],
            grants: vec![
                grant(1, Sel::Tags(vec!["nrf52"]), &[TOp::Attach], None),
                grant(1, Sel::Tags(vec!["lab"]), &[TOp::Gdb, TOp::Attach], None),
            ],
        };
        assert_eq!(access.effective_ops(&b, NOW), vec![TOp::Attach, TOp::Gdb]);
    }

    #[test]
    fn expiry_is_exclusive_at_the_boundary() {
        let g = grant(1, Sel::Tags(vec![]), &[TOp::Attach], Some(NOW));
        assert!(g.is_live_at(NOW - 1));
        assert!(!g.is_live_at(NOW));
        assert!(grant(1, Sel::Tags(vec![]), &[], None).is_live_at(u64::MAX));
    }

    /// A subject with no membership but a live grant is a first-class case:
    /// CI workloads have no membership at all.
    #[test]
    fn a_grant_works_without_any_membership() {
        let b = board(&[1], "b1", &["nrf52"]);
        let access = Access {
            memberships: vec![],
            grants: vec![grant(1, Sel::Tags(vec!["nrf52"]), &[TOp::Attach], None)],
        };
        assert!(!access.is_empty());
        assert!(access.may_use(&b, NOW));
        assert_eq!(
            access.matching_grant(&b, NOW).map(|g| g.id),
            Some(GrantId::from_parts(1, 0))
        );
    }

    #[test]
    fn effective_role_is_the_max_and_never_lowered() {
        let l = RoleLadder::default();
        let r = |s| l.parse(s);
        assert_eq!(effective_role(&[]), None);
        assert_eq!(effective_role(&[(ns(1), None), (ns(2), None)]), None);
        // Inherited from the org.
        assert_eq!(
            effective_role(&[(ns(1), r("write")), (ns(2), None)]),
            r("write")
        );
        // Raised on the project.
        assert_eq!(
            effective_role(&[(ns(1), r("read")), (ns(2), r("admin"))]),
            r("admin")
        );
        // A lower direct entry does not lower it.
        assert_eq!(
            effective_role(&[(ns(1), r("maintain")), (ns(2), r("read"))]),
            r("maintain")
        );
    }

    #[test]
    fn visibility_overrides_only_restrict() {
        use Visibility::{Internal, Private, Public};
        assert_eq!(effective_visibility(&[]), Private);
        assert_eq!(effective_visibility(&[None]), Private);
        assert_eq!(effective_visibility(&[Some(Public), None]), Public);
        assert_eq!(
            effective_visibility(&[Some(Public), Some(Private)]),
            Private
        );
        // A public project under a private org stays private.
        assert_eq!(
            effective_visibility(&[Some(Private), Some(Public)]),
            Private
        );
        assert_eq!(
            effective_visibility(&[Some(Internal), Some(Public)]),
            Internal
        );
        for v in [Public, Internal, Private] {
            assert_eq!(Visibility::parse(v.as_str()), Some(v));
        }
        assert_eq!(Visibility::parse("secret"), None);
    }

    #[test]
    fn who_can_see_what() {
        use Visibility::{Internal, Private, Public};
        let role = RoleLadder::default().parse("read");
        assert!(can_see(Public, false, None));
        assert!(!can_see(Internal, false, None));
        assert!(can_see(Internal, true, None));
        assert!(!can_see(Private, true, None));
        assert!(can_see(Private, false, role));
    }
}
