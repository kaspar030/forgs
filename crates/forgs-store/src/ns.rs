//! The namespace tree: creation, renames, deletion, lookup, and the ancestor
//! chains authz evaluates over.

use forgs::schema::NameOrigin;
use forgs::{NsNodeId, Role, SubjectKey, UserId, Visibility};
use sqlx::SqliteConnection;

use crate::error::{from_ts, parse_id, ts, Result, StoreError};
use crate::users::{check_name_free, insert_tombstone};
use crate::{now_ms, Store};

/// A namespace node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsNode {
    /// Immutable id.
    pub id: NsNodeId,
    /// Parent, `None` at the root.
    pub parent: Option<NsNodeId>,
    /// App-defined kind.
    pub kind: String,
    /// Display spelling of the name.
    pub name: String,
    /// Canonical name (uniqueness, lookups).
    pub name_canonical: String,
    /// Own visibility setting; `None` inherits.
    pub visibility: Option<Visibility>,
    /// Owning user, if any.
    pub owner: Option<UserId>,
    /// Set on a user's personal node.
    pub personal_of: Option<UserId>,
    /// App-defined external reference (e.g. an upstream id).
    pub external_ref: Option<String>,
    /// Creation time, epoch seconds.
    pub created_at: u64,
}

/// A direct membership of a user, for "my namespaces".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// The namespace node.
    pub ns: NsNodeId,
    /// The direct role there.
    pub role: Role,
}

type NodeRow = (
    String,
    Option<String>,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
);

const NODE_COLS: &str = "n.id, n.parent_id, n.kind, n.name, n.name_canonical, n.visibility,
     n.owner_user_id, n.personal_of_user_id, n.external_ref, n.created_at";

fn node_from_row(r: NodeRow) -> Result<NsNode> {
    let (id, parent, kind, name, name_canonical, vis, owner, personal, external_ref, created_at) =
        r;
    Ok(NsNode {
        id: parse_id!(NsNodeId, id)?,
        parent: parent.map(|p| parse_id!(NsNodeId, p)).transpose()?,
        kind,
        name,
        name_canonical,
        visibility: vis
            .map(|v| Visibility::parse(&v).ok_or_else(|| crate::error::corrupt("visibility", &v)))
            .transpose()?,
        owner: owner.map(|o| parse_id!(UserId, o)).transpose()?,
        personal_of: personal.map(|o| parse_id!(UserId, o)).transpose()?,
        external_ref,
        created_at: from_ts(created_at),
    })
}

/// Delete a leaf node inside a transaction (no tombstone; callers add it),
/// with the workload tokens minted from its API keys.
pub(crate) async fn delete_leaf_tx(conn: &mut SqliteConnection, node: &str) -> Result<()> {
    let (children,): (bool,) =
        sqlx::query_as("SELECT EXISTS (SELECT 1 FROM forgs_ns_node WHERE parent_id = ?1)")
            .bind(node)
            .fetch_one(&mut *conn)
            .await?;
    if children {
        return Err(StoreError::HasChildren);
    }
    // The node's keys cascade with it; the workload tokens minted from them
    // carry no foreign key, so end them explicitly first.
    sqlx::query(
        "DELETE FROM forgs_workload_token WHERE api_key_id IN (
             SELECT id FROM forgs_api_key WHERE ns_node_id = ?1)",
    )
    .bind(node)
    .execute(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM forgs_ns_node WHERE id = ?1")
        .bind(node)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

impl Store {
    /// The node's kind and whether it is personal, inside `conn`.
    async fn kind_of(
        conn: &mut SqliteConnection,
        node: &str,
    ) -> Result<(String, Option<String>, bool)> {
        let row: Option<(String, Option<String>, bool)> = sqlx::query_as(
            "SELECT kind, parent_id, personal_of_user_id IS NOT NULL FROM forgs_ns_node WHERE id = ?1",
        )
        .bind(node)
        .fetch_optional(&mut *conn)
        .await?;
        row.ok_or(StoreError::NotFound)
    }

    /// Create a namespace node.
    ///
    /// Checks, in order: the parent exists; the schema allows `kind` under
    /// the parent's kind ([`forgs::Schema::can_place`]); the name is valid for
    /// the kind and `origin` ([`forgs::Schema::canonical_name`] — reserved
    /// names, and user-origin names on app-created or externally named kinds,
    /// are refused); it is not tombstoned; and it is free among the siblings
    /// (at the root: among root nodes of every kind **and** usernames).
    ///
    /// The stored display name is `raw_name` trimmed.
    ///
    /// Personal nodes are created by signup only: this path never marks a
    /// node personal, even of the personal kind (fleet's team orgs are that
    /// kind too), and so a user-origin creation of the personal kind is just
    /// an ordinary node of that kind.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] (parent), [`StoreError::BadPlacement`],
    /// [`StoreError::UnknownKind`], [`StoreError::NotUserNameable`],
    /// [`StoreError::Name`], [`StoreError::NameTombstoned`],
    /// [`StoreError::NameTaken`], [`StoreError::Dangling`] (owner), or a
    /// database error.
    pub async fn create_node(
        &self,
        parent: Option<NsNodeId>,
        kind: &str,
        raw_name: &str,
        origin: NameOrigin,
        owner: Option<UserId>,
        now: u64,
    ) -> Result<NsNodeId> {
        if self.schema.kind(kind).is_none() {
            return Err(StoreError::UnknownKind(kind.to_owned()));
        }
        let mut tx = self.begin().await?;
        let id = self
            .insert_node_tx(&mut tx, parent, kind, raw_name, origin, owner, now)
            .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// The body of [`Store::create_node`] inside `conn`; the caller has
    /// checked that `kind` is in the schema.
    #[allow(clippy::too_many_arguments)]
    async fn insert_node_tx(
        &self,
        conn: &mut SqliteConnection,
        parent: Option<NsNodeId>,
        kind: &str,
        raw_name: &str,
        origin: NameOrigin,
        owner: Option<UserId>,
        now: u64,
    ) -> Result<NsNodeId> {
        let parent_s = parent.map(|p| p.to_string());
        let parent_kind = match &parent_s {
            Some(p) => Some(Self::kind_of(conn, p).await?.0),
            None => None,
        };
        if !self.schema.can_place(kind, parent_kind.as_deref()) {
            return Err(StoreError::BadPlacement {
                kind: kind.to_owned(),
                parent_kind,
            });
        }
        let canonical = self.schema.canonical_name(kind, raw_name, origin)?;
        check_name_free(conn, parent_s.as_deref(), &canonical, None, None).await?;
        let id = NsNodeId::generate(now_ms(now));
        sqlx::query(
            "INSERT INTO forgs_ns_node (id, parent_id, kind, name, name_canonical, owner_user_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(id.to_string())
        .bind(parent_s.as_deref())
        .bind(kind)
        .bind(raw_name.trim())
        .bind(&canonical)
        .bind(owner.map(|o| o.to_string()))
        .bind(ts(now)?)
        .execute(&mut *conn)
        .await?;
        Ok(id)
    }

    /// Create a namespace node owned by `admin` and make `admin` a member
    /// with the ladder's highest role, in **one** transaction.
    ///
    /// With `max_owned = Some(cap)`, the creation is refused when `admin`
    /// already owns `cap` or more non-personal nodes of `kind` directly under
    /// `parent`. The count and the insert share a `BEGIN IMMEDIATE`
    /// transaction, so concurrent creations cannot overshoot the cap.
    /// `Some(0)` refuses every creation.
    ///
    /// The checks and naming rules are those of [`Store::create_node`].
    ///
    /// # Errors
    ///
    /// Those of [`Store::create_node`] (a missing `admin` user reports
    /// [`StoreError::Dangling`]), [`StoreError::OwnedLimit`], or
    /// [`StoreError::BadRole`] if the ladder has no label for its top role.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_node_with_admin(
        &self,
        parent: Option<NsNodeId>,
        kind: &str,
        raw_name: &str,
        origin: NameOrigin,
        admin: UserId,
        max_owned: Option<u64>,
        now: u64,
    ) -> Result<NsNodeId> {
        if self.schema.kind(kind).is_none() {
            return Err(StoreError::UnknownKind(kind.to_owned()));
        }
        let role = self
            .roles
            .label(self.roles.highest())
            .ok_or(StoreError::BadRole)?;
        let admin_s = admin.to_string();
        let mut tx = self.begin().await?;
        if let Some(cap) = max_owned {
            let (owned,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM forgs_ns_node
                 WHERE parent_id IS ?1 AND kind = ?2 AND owner_user_id = ?3
                   AND personal_of_user_id IS NULL",
            )
            .bind(parent.map(|p| p.to_string()))
            .bind(kind)
            .bind(&admin_s)
            .fetch_one(&mut *tx)
            .await?;
            if u64::try_from(owned).unwrap_or(0) >= cap {
                return Err(StoreError::OwnedLimit);
            }
        }
        let id = self
            .insert_node_tx(&mut tx, parent, kind, raw_name, origin, Some(admin), now)
            .await?;
        sqlx::query(
            "INSERT INTO forgs_membership (ns_node_id, subject, user_id, role, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(id.to_string())
        .bind(SubjectKey::user(admin).to_string())
        .bind(&admin_s)
        .bind(role)
        .bind(ts(now)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Rename a node, tombstoning its old name under its parent.
    ///
    /// A personal node is refused ([`StoreError::PersonalNode`]): it is
    /// renamed with its user by [`Store::rename_user`].
    ///
    /// # Errors
    ///
    /// As [`Store::create_node`], plus [`StoreError::PersonalNode`].
    pub async fn rename_node(
        &self,
        node: NsNodeId,
        raw_name: &str,
        origin: NameOrigin,
        now: u64,
    ) -> Result<()> {
        let node_s = node.to_string();
        let mut tx = self.begin().await?;
        let (kind, parent, personal) = Self::kind_of(&mut tx, &node_s).await?;
        if personal {
            return Err(StoreError::PersonalNode);
        }
        let canonical = self.schema.canonical_name(&kind, raw_name, origin)?;
        let (old,): (String,) =
            sqlx::query_as("SELECT name_canonical FROM forgs_ns_node WHERE id = ?1")
                .bind(&node_s)
                .fetch_one(&mut *tx)
                .await?;
        if old == canonical {
            // Display-spelling change only.
            sqlx::query("UPDATE forgs_ns_node SET name = ?2 WHERE id = ?1")
                .bind(&node_s)
                .bind(raw_name.trim())
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(());
        }
        check_name_free(&mut tx, parent.as_deref(), &canonical, None, Some(&node_s)).await?;
        sqlx::query("UPDATE forgs_ns_node SET name = ?2, name_canonical = ?3 WHERE id = ?1")
            .bind(&node_s)
            .bind(raw_name.trim())
            .bind(&canonical)
            .execute(&mut *tx)
            .await?;
        // At the root a case-only change keeps the same tombstone key; the
        // node still holds that name, so there is nothing to release.
        if crate::users::tomb_name(parent.as_deref(), &old)
            != crate::users::tomb_name(parent.as_deref(), &canonical)
        {
            insert_tombstone(
                &mut tx,
                parent.as_deref(),
                &old,
                Some(&node_s),
                None,
                ts(now)?,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Delete a leaf node, tombstoning its name. Memberships, API keys,
    /// grants and pending approvals bound to it cascade, and the workload
    /// tokens minted from its keys are deleted.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`], [`StoreError::HasChildren`],
    /// [`StoreError::PersonalNode`] (delete the user instead),
    /// [`StoreError::Dangling`] if an app table still references it, or a
    /// database error.
    pub async fn delete_node(&self, node: NsNodeId, now: u64) -> Result<()> {
        let node_s = node.to_string();
        let mut tx = self.begin().await?;
        let (_, parent, personal) = Self::kind_of(&mut tx, &node_s).await?;
        if personal {
            return Err(StoreError::PersonalNode);
        }
        let (name,): (String,) =
            sqlx::query_as("SELECT name_canonical FROM forgs_ns_node WHERE id = ?1")
                .bind(&node_s)
                .fetch_one(&mut *tx)
                .await?;
        delete_leaf_tx(&mut tx, &node_s).await?;
        insert_tombstone(
            &mut tx,
            parent.as_deref(),
            &name,
            Some(&node_s),
            None,
            ts(now)?,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Set a node's own visibility (`None` inherits).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] or a database error.
    pub async fn set_visibility(
        &self,
        node: NsNodeId,
        visibility: Option<Visibility>,
    ) -> Result<()> {
        let n = sqlx::query("UPDATE forgs_ns_node SET visibility = ?2 WHERE id = ?1")
            .bind(node.to_string())
            .bind(visibility.map(Visibility::as_str))
            .execute(&self.pool)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Set a node's app-defined external reference.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] or a database error.
    pub async fn set_external_ref(&self, node: NsNodeId, external_ref: Option<&str>) -> Result<()> {
        let n = sqlx::query("UPDATE forgs_ns_node SET external_ref = ?2 WHERE id = ?1")
            .bind(node.to_string())
            .bind(external_ref)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// A node by id.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::CorruptRow`].
    pub async fn node(&self, node: NsNodeId) -> Result<Option<NsNode>> {
        let row: Option<NodeRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {NODE_COLS} FROM forgs_ns_node n WHERE n.id = ?1"
        )))
        .bind(node.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(node_from_row).transpose()
    }

    /// The children of `parent` (`None`: the root nodes), by name.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::CorruptRow`].
    pub async fn children(&self, parent: Option<NsNodeId>) -> Result<Vec<NsNode>> {
        let rows: Vec<NodeRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {NODE_COLS} FROM forgs_ns_node n WHERE n.parent_id IS ?1 ORDER BY n.name_canonical"
        )))
        .bind(parent.map(|p| p.to_string()))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(node_from_row).collect()
    }

    /// Resolve a path of segments (`["alice", "dotfiles"]`) to a node.
    ///
    /// Each segment is canonicalised with the rules of every kind that may sit
    /// at that level under the node found so far, and looked up among that
    /// node's children. Segments are canonicalised as [`NameOrigin::App`], so
    /// lookups work for externally named and app-created kinds too; names
    /// that no kind accepts cannot exist and resolve to `None`.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::CorruptRow`].
    pub async fn node_by_path(&self, path: &[&str]) -> Result<Option<NsNode>> {
        let mut current: Option<NsNode> = None;
        for seg in path {
            let parent_kind = current.as_ref().map(|n| n.kind.as_str());
            let mut candidates: Vec<String> = self
                .schema
                .kinds()
                .filter(|k| self.schema.can_place(k, parent_kind))
                // A name no kind accepts (e.g. reserved) cannot exist here.
                .filter_map(|k| self.schema.canonical_name(k, seg, NameOrigin::App).ok())
                .collect();
            candidates.sort();
            candidates.dedup();
            let mut found = None;
            for name in candidates {
                let row: Option<NodeRow> = match &current {
                    Some(p) => {
                        sqlx::query_as(sqlx::AssertSqlSafe(format!(
                            "SELECT {NODE_COLS} FROM forgs_ns_node n
                          WHERE n.parent_id = ?1 AND n.name_canonical = ?2"
                        )))
                        .bind(p.id.to_string())
                        .bind(&name)
                        .fetch_optional(&self.pool)
                        .await?
                    }
                    None => {
                        sqlx::query_as(sqlx::AssertSqlSafe(format!(
                            "SELECT {NODE_COLS} FROM forgs_ns_node n
                          WHERE n.parent_id IS NULL AND n.name_canonical = ?1"
                        )))
                        .bind(&name)
                        .fetch_optional(&self.pool)
                        .await?
                    }
                };
                if let Some(row) = row {
                    found = Some(node_from_row(row)?);
                    break;
                }
            }
            match found {
                Some(n) => current = Some(n),
                None => return Ok(None),
            }
        }
        Ok(current)
    }

    /// The ancestor chain of `node`: root first, the node itself last. Empty
    /// if the node does not exist.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::CorruptRow`].
    pub async fn ancestors(&self, node: NsNodeId) -> Result<Vec<NsNode>> {
        let rows: Vec<NodeRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "WITH RECURSIVE chain(depth, id) AS (
                 SELECT 0, ?1
                 UNION ALL
                 SELECT chain.depth + 1, n.parent_id FROM forgs_ns_node n
                   JOIN chain ON n.id = chain.id
                  WHERE n.parent_id IS NOT NULL AND chain.depth < 1000
             )
             SELECT {NODE_COLS}
               FROM chain JOIN forgs_ns_node n ON n.id = chain.id
              ORDER BY chain.depth DESC"
        )))
        .bind(node.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(node_from_row).collect()
    }

    /// `subject`'s direct role at each node of `node`'s ancestor chain, root
    /// first — the input of [`forgs::authz::effective_role`].
    ///
    /// # Errors
    ///
    /// [`StoreError::CorruptRow`] if a stored role label is not on this
    /// store's ladder (fails closed: the caller gets no role, not a guess), or
    /// a database error.
    pub async fn role_chain(
        &self,
        node: NsNodeId,
        subject: &SubjectKey,
    ) -> Result<Vec<(NsNodeId, Option<Role>)>> {
        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "WITH RECURSIVE chain(depth, id) AS (
                 SELECT 0, ?1
                 UNION ALL
                 SELECT chain.depth + 1, n.parent_id FROM forgs_ns_node n
                   JOIN chain ON n.id = chain.id
                  WHERE n.parent_id IS NOT NULL AND chain.depth < 1000
             )
             SELECT chain.id, m.role
               FROM chain
               JOIN forgs_ns_node n ON n.id = chain.id
               LEFT JOIN forgs_membership m ON m.ns_node_id = chain.id AND m.subject = ?2
              ORDER BY chain.depth DESC",
        )
        .bind(node.to_string())
        .bind(subject.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(id, role)| {
                let id = parse_id!(NsNodeId, id)?;
                let role = role
                    .map(|r| {
                        self.roles
                            .parse(&r)
                            .ok_or_else(|| crate::error::corrupt("role", &r))
                    })
                    .transpose()?;
                Ok((id, role))
            })
            .collect()
    }

    /// `subject`'s effective role on `node`: the max over its ancestor chain.
    ///
    /// # Errors
    ///
    /// As [`Store::role_chain`].
    pub async fn effective_role(
        &self,
        node: NsNodeId,
        subject: &SubjectKey,
    ) -> Result<Option<Role>> {
        Ok(forgs::authz::effective_role(
            &self.role_chain(node, subject).await?,
        ))
    }

    /// Each chain node's own visibility setting, root first — the input of
    /// [`forgs::authz::effective_visibility`].
    ///
    /// # Errors
    ///
    /// As [`Store::ancestors`].
    pub async fn visibility_chain(&self, node: NsNodeId) -> Result<Vec<Option<Visibility>>> {
        Ok(self
            .ancestors(node)
            .await?
            .into_iter()
            .map(|n| n.visibility)
            .collect())
    }

    /// Every direct membership of `user`, for "my namespaces".
    ///
    /// **Deliberately unscoped** (see the crate docs): keyed by the
    /// authenticated user, which the caller cannot choose.
    ///
    /// # Errors
    ///
    /// [`StoreError::CorruptRow`] for an unknown role label, or a database
    /// error.
    pub async fn memberships_of_user(&self, user: UserId) -> Result<Vec<Membership>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT ns_node_id, role FROM forgs_membership WHERE user_id = ?1 ORDER BY ns_node_id",
        )
        .bind(user.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(ns, role)| {
                Ok(Membership {
                    ns: parse_id!(NsNodeId, ns)?,
                    role: self
                        .roles
                        .parse(&role)
                        .ok_or_else(|| crate::error::corrupt("role", &role))?,
                })
            })
            .collect()
    }
}
