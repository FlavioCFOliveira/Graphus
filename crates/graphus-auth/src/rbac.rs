//! The role-based access-control model shared by all three listeners (`04 §8.4`,
//! `D-auth-scheme`, `D-security-scope`).
//!
//! An identity has the **same authorization regardless of entry point** (UDS / Bolt-TCP / REST),
//! so the [`Catalog`] is the single source of truth that every listener resolves to. The model is
//! enum-based and **fine-grained** (rmp #92, the foundation half of `D-auth-scheme`):
//!
//! - A [`Privilege`] is an [`Action`] over a [`Resource`].
//! - A [`Role`] owns a set of privileges.
//! - A [`User`] is a member of zero or more roles and (optionally) holds a password hash for Bolt
//!   native auth.
//! - [`Catalog::authorize`] unions the privileges of all the user's roles and answers a single
//!   `(user, privilege)` question. **Deny by default**: anything not explicitly granted is denied.
//!
//! ## Actions (operation semantics, `04 §8.4`)
//!
//! The model separates the read pipeline into two graded actions, matching the Cypher access
//! model (and Neo4j's): seeing that an element *exists / can be traversed* is weaker than reading
//! its *properties*.
//!
//! - [`Action::Traverse`] — follow a relationship, and see that a node/relationship **exists**
//!   (its identity and labels/type), without reading any property value.
//! - [`Action::Read`] — read **property** values (and implies [`Action::Traverse`]: you cannot
//!   read a node's properties without first being allowed to see the node).
//! - [`Action::Write`] — create / set / delete data (`CREATE`/`SET`/`DELETE`/`MERGE`). A writer
//!   must also be able to see and read what it mutates, so `Write` implies `Read` (and therefore
//!   `Traverse`).
//! - [`Action::Schema`] — manage indexes, constraints and other DDL (formerly `CreateIndex`).
//! - [`Action::Admin`] — security + database administration; the super-action. Holding `Admin`
//!   over a resource implies every other action over that resource, and `Admin` over
//!   [`Resource::Database`] implies authority over everything, everywhere (the global root).
//!
//! The non-`Admin` ordering `Traverse ⊂ Read ⊂ Write` is a **graded** chain: a broader action
//! implies the narrower read-side ones. `Schema` is orthogonal (DDL is neither a read nor a write
//! of data) and is implied only by `Admin`.
//!
//! ## Resources (scope containment)
//!
//! Graphus is a multi-database server; a "graph" **is** a database (`D-multi-db`). Resources form a
//! containment tree, broadest first:
//!
//! ```text
//! Database                          (server-wide; Admin here is the global super-grant)
//! └── Graph(db)                     (a whole named database)
//!     ├── Label { db, label }       (all nodes of one label in that database)
//!     ├── RelType { db, rel_type }  (all relationships of one type in that database)
//!     └── Property { db, label, property }
//!                                   (one property of one label's nodes in that database)
//! ```
//!
//! A broader grant covers every narrower resource **within the same database**: `Graph(db)` covers
//! any `Label`/`RelType`/`Property` whose `db` matches, and `Label { db, label }` covers
//! `Property { db, label, .. }`. `Database` covers everything (it is database-agnostic — the
//! server-wide scope). Scopes never cross database boundaries: a grant on `Graph("a")` says nothing
//! about `Graph("b")`.
//!
//! **This module owns the model and its containment only.** It does **not** filter query results:
//! the Cypher executor's enforcement of `Traverse`/`Read`/`Write` at element granularity is rmp #93.
//!
//! Password storage lives on the [`User`] but the hashing/verification primitives are in
//! [`crate::password`]; this module only holds the opaque hash string.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{AuthError, Result};

/// What an actor may do. [`Action::Admin`] implies all the others over the same resource; the
/// read-side actions form the graded chain `Traverse ⊂ Read ⊂ Write` (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Action {
    /// Follow a relationship and see that a node/relationship exists (identity + labels/type), but
    /// **not** read its property values. The weakest data action.
    Traverse,
    /// Read property values (`MATCH … RETURN n.prop`). Implies [`Action::Traverse`].
    Read,
    /// Mutate data (`CREATE`/`SET`/`DELETE`/`MERGE`). Implies [`Action::Read`] (and so `Traverse`):
    /// a writer must be able to see and read what it changes.
    Write,
    /// Manage indexes, constraints and other schema/DDL. Orthogonal to the read/write chain; only
    /// [`Action::Admin`] implies it. (Formerly `CreateIndex`.)
    Schema,
    /// Administrative authority (security + database administration): implies every other action
    /// over the same resource, and over [`Resource::Database`] implies authority over everything,
    /// everywhere (the global root).
    Admin,
}

impl Action {
    /// Returns `true` if holding `self` (over a covered resource) is sufficient to satisfy a request
    /// for `wanted`. Encodes the graded read-side chain `Traverse ⊂ Read ⊂ Write` plus the
    /// `Admin`-implies-everything rule; `Schema` is implied only by `Admin` (and itself).
    ///
    /// This is action-only containment: the *resource* must already be covered by the caller
    /// ([`Privilege::implies`] checks the resource first).
    #[must_use]
    fn implies(self, wanted: Action) -> bool {
        if self == Action::Admin {
            // Admin is the super-action over a covered resource: it implies every other action.
            return true;
        }
        match wanted {
            // The graded read chain: Write ⊇ Read ⊇ Traverse.
            Action::Traverse => matches!(self, Action::Traverse | Action::Read | Action::Write),
            Action::Read => matches!(self, Action::Read | Action::Write),
            Action::Write => self == Action::Write,
            // Schema and Admin are not implied by any non-Admin action; only an exact match works
            // (Admin was handled above, so for `wanted == Admin` only `self == Admin` reaches here,
            // which it never does — the early return covered it; an exact `Schema` is the case).
            Action::Schema => self == Action::Schema,
            Action::Admin => false,
        }
    }
}

/// What a [`Privilege`] applies to (the containment tree — see the module docs).
///
/// `Ord`/`Hash` make a `(Action, Resource)` pair usable directly as a `BTreeSet` key, which is how
/// a [`Role`] stores its grants. Names (`db`, `label`, `rel_type`, `property`) are stored verbatim;
/// the catalog normalizes a database name at the lifecycle layer, so a grant's `db` is expected to
/// already be the canonical (lowercase) database name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Resource {
    /// The whole server (every database). `Admin` here is the global super-grant; any other action
    /// here applies to every database.
    Database,
    /// A whole named database (a "graph", `D-multi-db`). Covers every label, relationship type and
    /// property within that database.
    Graph(String),
    /// All nodes of one label in one database. Covers [`Resource::Property`] of that same label.
    Label {
        /// The (canonical) database name.
        db: String,
        /// The node label.
        label: String,
    },
    /// All relationships of one type in one database.
    RelType {
        /// The (canonical) database name.
        db: String,
        /// The relationship type.
        rel_type: String,
    },
    /// One property of one label's nodes in one database — the narrowest scope.
    Property {
        /// The (canonical) database name.
        db: String,
        /// The node label the property belongs to.
        label: String,
        /// The property key.
        property: String,
    },
}

impl Resource {
    /// Returns `true` if holding a grant scoped to `self` covers a request scoped to `wanted`
    /// (the resource containment tree — module docs). Database-agnostic [`Resource::Database`]
    /// covers everything; otherwise scopes never cross database boundaries.
    #[must_use]
    fn covers(&self, wanted: &Resource) -> bool {
        match self {
            // The server-wide scope covers every resource in every database.
            Resource::Database => true,
            // A whole database covers anything within that same database.
            Resource::Graph(db) => wanted.database() == Some(db.as_str()),
            // A label covers itself and its properties, within the same database.
            Resource::Label { db, label } => match wanted {
                Resource::Label {
                    db: wdb,
                    label: wlabel,
                } => db == wdb && label == wlabel,
                Resource::Property {
                    db: wdb,
                    label: wlabel,
                    ..
                } => db == wdb && label == wlabel,
                _ => false,
            },
            // A relationship-type scope covers only the exact same relationship type.
            Resource::RelType { db, rel_type } => matches!(
                wanted,
                Resource::RelType { db: wdb, rel_type: wrt } if db == wdb && rel_type == wrt
            ),
            // A property is the leaf: it covers only itself.
            Resource::Property {
                db,
                label,
                property,
            } => matches!(
                wanted,
                Resource::Property { db: wdb, label: wlabel, property: wprop }
                    if db == wdb && label == wlabel && property == wprop
            ),
        }
    }

    /// The database name a resource is scoped to, or `None` for the database-agnostic
    /// server-wide [`Resource::Database`] scope.
    #[must_use]
    pub fn database(&self) -> Option<&str> {
        match self {
            Resource::Database => None,
            Resource::Graph(db)
            | Resource::Label { db, .. }
            | Resource::RelType { db, .. }
            | Resource::Property { db, .. } => Some(db.as_str()),
        }
    }
}

/// A single grantable privilege: an [`Action`] over a [`Resource`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Privilege {
    /// The action this privilege authorizes.
    pub action: Action,
    /// The resource the action applies to.
    pub resource: Resource,
}

impl Privilege {
    /// Constructs a privilege from an action and resource.
    #[must_use]
    pub fn new(action: Action, resource: Resource) -> Self {
        Self { action, resource }
    }

    /// `Read` over the whole server (every database).
    #[must_use]
    pub fn read_database() -> Self {
        Self::new(Action::Read, Resource::Database)
    }

    /// `Write` over the whole server (every database).
    #[must_use]
    pub fn write_database() -> Self {
        Self::new(Action::Write, Resource::Database)
    }

    /// `Admin` over the whole server — the global super-grant.
    #[must_use]
    pub fn admin_database() -> Self {
        Self::new(Action::Admin, Resource::Database)
    }

    /// An action over a whole named database (`Graph(db)`).
    #[must_use]
    pub fn on_graph(action: Action, db: impl Into<String>) -> Self {
        Self::new(action, Resource::Graph(db.into()))
    }

    /// An action over all nodes of one label in one database.
    #[must_use]
    pub fn on_label(action: Action, db: impl Into<String>, label: impl Into<String>) -> Self {
        Self::new(
            action,
            Resource::Label {
                db: db.into(),
                label: label.into(),
            },
        )
    }

    /// An action over all relationships of one type in one database.
    #[must_use]
    pub fn on_rel_type(action: Action, db: impl Into<String>, rel_type: impl Into<String>) -> Self {
        Self::new(
            action,
            Resource::RelType {
                db: db.into(),
                rel_type: rel_type.into(),
            },
        )
    }

    /// An action over one property of one label's nodes in one database (the narrowest scope).
    #[must_use]
    pub fn on_property(
        action: Action,
        db: impl Into<String>,
        label: impl Into<String>,
        property: impl Into<String>,
    ) -> Self {
        Self::new(
            action,
            Resource::Property {
                db: db.into(),
                label: label.into(),
                property: property.into(),
            },
        )
    }

    /// Returns `true` if holding `self` is sufficient to satisfy a request for `wanted`.
    ///
    /// This composes the two containment dimensions (deny-by-default is enforced by the *caller*
    /// iterating only over granted privileges, never here):
    ///
    /// 1. **Resource containment**: `self`'s scope must cover `wanted`'s —
    ///    `Database ⊇ Graph(db) ⊇ {Label, RelType, Property}` within that `db`, and
    ///    `Label ⊇ Property` of the same label (module docs). Scopes never cross databases.
    /// 2. **Action containment**: over a covered resource, `Admin` implies every action and the
    ///    read-side chain grades `Traverse ⊂ Read ⊂ Write`; `Schema` is implied only by `Admin` or
    ///    an exact `Schema`.
    ///
    /// In particular `Admin` over [`Resource::Database`] implies everything, everywhere (the global
    /// root), because `Resource::Database` covers every resource and `Admin` implies every action.
    #[must_use]
    pub fn implies(&self, wanted: &Privilege) -> bool {
        self.resource.covers(&wanted.resource) && self.action.implies(wanted.action)
    }
}

/// A named role: a set of [`Privilege`]s. Users gain privileges by membership in roles.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Role {
    /// The role's unique name.
    pub name: String,
    /// The privileges granted by this role.
    pub privileges: BTreeSet<Privilege>,
}

impl Role {
    /// Creates an empty role with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            privileges: BTreeSet::new(),
        }
    }
}

/// A user account: a set of role memberships plus an optional password hash (Bolt native auth).
///
/// The password hash is an opaque PHC-format string produced by [`crate::password`]; a user with
/// no hash cannot authenticate via password (but may still authenticate via UDS peer credentials,
/// which map a uid to a user independently of any password).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct User {
    /// The user's unique name (the subject of a JWT, the Bolt `LOGON` principal).
    pub name: String,
    /// Names of the roles this user belongs to.
    pub roles: BTreeSet<String>,
    /// Argon2 PHC hash of the user's password, or `None` if password auth is not configured.
    pub password_hash: Option<String>,
}

impl User {
    /// Creates a user with no roles and no password.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            roles: BTreeSet::new(),
            password_hash: None,
        }
    }
}

/// The owning catalog of users, roles, and their grants (`04 §8.4`).
///
/// All authorization in Graphus resolves through one `Catalog`, so the three listeners share an
/// identity's privileges. Lookups are by name; `BTreeMap` keeps iteration deterministic (helpful
/// for tests and for any future stable admin listing) at no meaningful cost for the small
/// cardinalities expected here.
///
/// Deny-by-default: a freshly constructed catalog authorizes nothing.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    users: BTreeMap<String, User>,
    roles: BTreeMap<String, Role>,
}

impl Catalog {
    /// Creates an empty catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ---- User CRUD ---------------------------------------------------------------------------

    /// Creates a new user with no roles and no password.
    ///
    /// # Errors
    /// [`AuthError::AlreadyExists`] if a user of that name already exists.
    pub fn create_user(&mut self, name: impl Into<String>) -> Result<()> {
        let name = name.into();
        if self.users.contains_key(&name) {
            return Err(AuthError::AlreadyExists {
                what: format!("user {name}"),
            });
        }
        self.users.insert(name.clone(), User::new(name));
        Ok(())
    }

    /// Drops a user.
    ///
    /// # Errors
    /// [`AuthError::NotFound`] if no such user exists.
    pub fn drop_user(&mut self, name: &str) -> Result<()> {
        self.users
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| AuthError::NotFound {
                what: format!("user {name}"),
            })
    }

    /// Returns a shared reference to a user, if present.
    #[must_use]
    pub fn user(&self, name: &str) -> Option<&User> {
        self.users.get(name)
    }

    /// Returns a mutable reference to a user, if present (used to attach a password hash).
    pub fn user_mut(&mut self, name: &str) -> Option<&mut User> {
        self.users.get_mut(name)
    }

    /// Returns `true` if a user of that name exists.
    #[must_use]
    pub fn has_user(&self, name: &str) -> bool {
        self.users.contains_key(name)
    }

    /// Iterates over every user (name → [`User`]) in deterministic (name) order. Used by the
    /// durable security-catalog serializer in `graphus-server`.
    pub fn users(&self) -> impl Iterator<Item = (&str, &User)> {
        self.users.iter().map(|(name, user)| (name.as_str(), user))
    }

    /// Sets (or clears) a user's stored password **hash** directly, without re-hashing — the load
    /// path of the durable security catalog (a hash read back from disk is restored verbatim;
    /// re-hashing a plaintext is [`crate::Authenticator::set_password`]).
    ///
    /// Never accepts a plaintext: the argument is already a PHC hash string (or `None` to clear).
    ///
    /// # Errors
    /// [`AuthError::NotFound`] if the user does not exist.
    pub fn set_user_password_hash(&mut self, name: &str, hash: Option<String>) -> Result<()> {
        let user = self
            .users
            .get_mut(name)
            .ok_or_else(|| AuthError::NotFound {
                what: format!("user {name}"),
            })?;
        user.password_hash = hash;
        Ok(())
    }

    // ---- Role CRUD ---------------------------------------------------------------------------

    /// Creates a new, empty role.
    ///
    /// # Errors
    /// [`AuthError::AlreadyExists`] if a role of that name already exists.
    pub fn create_role(&mut self, name: impl Into<String>) -> Result<()> {
        let name = name.into();
        if self.roles.contains_key(&name) {
            return Err(AuthError::AlreadyExists {
                what: format!("role {name}"),
            });
        }
        self.roles.insert(name.clone(), Role::new(name));
        Ok(())
    }

    /// Drops a role and revokes it from every user that held it.
    ///
    /// Revoking from members keeps the catalog internally consistent: a user can never reference a
    /// role that no longer exists, so [`Catalog::authorize`] never has to skip dangling names.
    ///
    /// # Errors
    /// [`AuthError::NotFound`] if no such role exists.
    pub fn drop_role(&mut self, name: &str) -> Result<()> {
        if self.roles.remove(name).is_none() {
            return Err(AuthError::NotFound {
                what: format!("role {name}"),
            });
        }
        for user in self.users.values_mut() {
            user.roles.remove(name);
        }
        Ok(())
    }

    /// Returns a shared reference to a role, if present.
    #[must_use]
    pub fn role(&self, name: &str) -> Option<&Role> {
        self.roles.get(name)
    }

    /// Returns `true` if a role of that name exists.
    #[must_use]
    pub fn has_role(&self, name: &str) -> bool {
        self.roles.contains_key(name)
    }

    /// Iterates over every role (name → [`Role`]) in deterministic (name) order. Used by the
    /// durable security-catalog serializer in `graphus-server`.
    pub fn roles(&self) -> impl Iterator<Item = (&str, &Role)> {
        self.roles.iter().map(|(name, role)| (name.as_str(), role))
    }

    // ---- Grants ------------------------------------------------------------------------------

    /// Grants `role` to `user` (idempotent if already a member).
    ///
    /// # Errors
    /// [`AuthError::NotFound`] if either the user or the role does not exist.
    pub fn grant_role(&mut self, user: &str, role: &str) -> Result<()> {
        if !self.roles.contains_key(role) {
            return Err(AuthError::NotFound {
                what: format!("role {role}"),
            });
        }
        let u = self
            .users
            .get_mut(user)
            .ok_or_else(|| AuthError::NotFound {
                what: format!("user {user}"),
            })?;
        u.roles.insert(role.to_owned());
        Ok(())
    }

    /// Revokes `role` from `user` (idempotent if not a member).
    ///
    /// # Errors
    /// [`AuthError::NotFound`] if the user does not exist. Revoking a role the user never had is a
    /// no-op success; revoking a non-existent role from an existing user likewise succeeds (there
    /// is nothing to remove), keeping revoke idempotent.
    pub fn revoke_role(&mut self, user: &str, role: &str) -> Result<()> {
        let u = self
            .users
            .get_mut(user)
            .ok_or_else(|| AuthError::NotFound {
                what: format!("user {user}"),
            })?;
        u.roles.remove(role);
        Ok(())
    }

    /// Grants a privilege to a role (idempotent).
    ///
    /// # Errors
    /// [`AuthError::NotFound`] if the role does not exist.
    pub fn grant_privilege(&mut self, role: &str, privilege: Privilege) -> Result<()> {
        let r = self
            .roles
            .get_mut(role)
            .ok_or_else(|| AuthError::NotFound {
                what: format!("role {role}"),
            })?;
        r.privileges.insert(privilege);
        Ok(())
    }

    /// Revokes a privilege from a role (idempotent).
    ///
    /// # Errors
    /// [`AuthError::NotFound`] if the role does not exist.
    pub fn revoke_privilege(&mut self, role: &str, privilege: &Privilege) -> Result<()> {
        let r = self
            .roles
            .get_mut(role)
            .ok_or_else(|| AuthError::NotFound {
                what: format!("role {role}"),
            })?;
        r.privileges.remove(privilege);
        Ok(())
    }

    // ---- Authorization -----------------------------------------------------------------------

    /// Returns `true` iff `user` holds (directly through any of their roles) a privilege that
    /// implies `wanted`. **Deny by default**: an unknown user, a user with no roles, or a user
    /// whose roles grant nothing that implies `wanted`, all return `false`.
    ///
    /// The resolution unions the privileges across all the user's roles and asks
    /// [`Privilege::implies`] for each, so a single global `Admin` grant satisfies every request
    /// (`04 §8.4` "admin implies").
    #[must_use]
    pub fn authorize(&self, user: &str, wanted: &Privilege) -> bool {
        let Some(user) = self.users.get(user) else {
            return false;
        };
        user.roles
            .iter()
            .filter_map(|role_name| self.roles.get(role_name))
            .flat_map(|role| role.privileges.iter())
            .any(|granted| granted.implies(wanted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A catalog with an `alice` user in a `reader` role granted database `Read`.
    fn reader_catalog() -> Catalog {
        let mut c = Catalog::new();
        c.create_user("alice").unwrap();
        c.create_role("reader").unwrap();
        c.grant_privilege("reader", Privilege::read_database())
            .unwrap();
        c.grant_role("alice", "reader").unwrap();
        c
    }

    #[test]
    fn deny_by_default_for_unknown_user() {
        let c = Catalog::new();
        assert!(!c.authorize("nobody", &Privilege::read_database()));
    }

    #[test]
    fn deny_when_user_has_no_roles() {
        let mut c = Catalog::new();
        c.create_user("bob").unwrap();
        assert!(!c.authorize("bob", &Privilege::read_database()));
    }

    #[test]
    fn grant_then_authorize_reads() {
        let c = reader_catalog();
        assert!(c.authorize("alice", &Privilege::read_database()));
        // ...but not writes — Read does not imply Write.
        assert!(!c.authorize("alice", &Privilege::write_database()));
    }

    #[test]
    fn revoke_role_removes_authorization() {
        let mut c = reader_catalog();
        c.revoke_role("alice", "reader").unwrap();
        assert!(!c.authorize("alice", &Privilege::read_database()));
    }

    #[test]
    fn revoke_privilege_removes_authorization() {
        let mut c = reader_catalog();
        c.revoke_privilege("reader", &Privilege::read_database())
            .unwrap();
        assert!(!c.authorize("alice", &Privilege::read_database()));
    }

    #[test]
    fn privileges_union_across_multiple_roles() {
        let mut c = Catalog::new();
        c.create_user("carol").unwrap();
        c.create_role("reader").unwrap();
        c.create_role("writer").unwrap();
        c.grant_privilege("reader", Privilege::read_database())
            .unwrap();
        c.grant_privilege("writer", Privilege::write_database())
            .unwrap();
        c.grant_role("carol", "reader").unwrap();
        c.grant_role("carol", "writer").unwrap();
        // The union of the two roles grants both Read and Write.
        assert!(c.authorize("carol", &Privilege::read_database()));
        assert!(c.authorize("carol", &Privilege::write_database()));
    }

    #[test]
    fn admin_implies_every_action_globally() {
        let mut c = Catalog::new();
        c.create_user("root").unwrap();
        c.create_role("dba").unwrap();
        c.grant_privilege("dba", Privilege::admin_database())
            .unwrap();
        c.grant_role("root", "dba").unwrap();
        // Global Admin satisfies Traverse, Read, Write, Schema on the server...
        assert!(c.authorize(
            "root",
            &Privilege::new(Action::Traverse, Resource::Database)
        ));
        assert!(c.authorize("root", &Privilege::read_database()));
        assert!(c.authorize("root", &Privilege::write_database()));
        assert!(c.authorize("root", &Privilege::new(Action::Schema, Resource::Database)));
        // ...and any action on any narrower resource (database scope contains everything within).
        assert!(c.authorize("root", &Privilege::on_graph(Action::Write, "social")));
        assert!(c.authorize(
            "root",
            &Privilege::on_label(Action::Read, "social", "Person")
        ));
        assert!(c.authorize(
            "root",
            &Privilege::on_property(Action::Write, "social", "Person", "name")
        ));
    }

    #[test]
    fn database_scope_contains_graph_scope_for_same_action() {
        let mut c = Catalog::new();
        c.create_user("dave").unwrap();
        c.create_role("reader").unwrap();
        c.grant_privilege("reader", Privilege::read_database())
            .unwrap();
        c.grant_role("dave", "reader").unwrap();
        // Database-wide Read covers Read on a specific graph...
        assert!(c.authorize("dave", &Privilege::on_graph(Action::Read, "g")));
        // ...and Read on a label/property within it (read implies traverse, scope contains scope).
        assert!(c.authorize("dave", &Privilege::on_label(Action::Read, "g", "Person")));
        assert!(c.authorize(
            "dave",
            &Privilege::on_label(Action::Traverse, "g", "Person")
        ));
        assert!(c.authorize(
            "dave",
            &Privilege::on_property(Action::Read, "g", "Person", "name")
        ));
        // ...but not Write on that graph.
        assert!(!c.authorize("dave", &Privilege::on_graph(Action::Write, "g")));
    }

    #[test]
    fn graph_scope_is_not_a_database_grant() {
        let mut c = Catalog::new();
        c.create_user("erin").unwrap();
        c.create_role("g_reader").unwrap();
        c.grant_privilege("g_reader", Privilege::on_graph(Action::Read, "g"))
            .unwrap();
        c.grant_role("erin", "g_reader").unwrap();
        // Read on graph "g" does NOT grant server-wide Read...
        assert!(!c.authorize("erin", &Privilege::read_database()));
        // ...nor Read on a different graph.
        assert!(!c.authorize("erin", &Privilege::on_graph(Action::Read, "other")));
        // ...but does grant Read on "g" and on labels/properties within "g".
        assert!(c.authorize("erin", &Privilege::on_graph(Action::Read, "g")));
        assert!(c.authorize("erin", &Privilege::on_label(Action::Read, "g", "Person")));
        assert!(c.authorize(
            "erin",
            &Privilege::on_property(Action::Read, "g", "Person", "name")
        ));
    }

    #[test]
    fn graph_admin_implies_actions_on_that_graph_only() {
        let mut c = Catalog::new();
        c.create_user("frank").unwrap();
        c.create_role("g_admin").unwrap();
        c.grant_privilege("g_admin", Privilege::on_graph(Action::Admin, "g"))
            .unwrap();
        c.grant_role("frank", "g_admin").unwrap();
        // Admin on "g" implies Write/Schema/Traverse on "g" and on everything within "g"...
        assert!(c.authorize("frank", &Privilege::on_graph(Action::Write, "g")));
        assert!(c.authorize("frank", &Privilege::on_graph(Action::Schema, "g")));
        assert!(c.authorize("frank", &Privilege::on_label(Action::Write, "g", "Person")));
        assert!(c.authorize(
            "frank",
            &Privilege::on_property(Action::Write, "g", "Person", "name")
        ));
        // ...but not anything server-wide, and not Admin-as-root.
        assert!(!c.authorize("frank", &Privilege::read_database()));
        assert!(!c.authorize("frank", &Privilege::on_graph(Action::Write, "other")));
    }

    // ---- exhaustive containment matrix --------------------------------------------------------

    /// Every resource scope used in the matrix, broadest → narrowest, within database "db" (plus a
    /// sibling database / label / property to prove scopes never widen).
    fn scopes() -> Vec<Resource> {
        vec![
            Resource::Database,
            Resource::Graph("db".to_owned()),
            Resource::Label {
                db: "db".to_owned(),
                label: "Person".to_owned(),
            },
            Resource::RelType {
                db: "db".to_owned(),
                rel_type: "KNOWS".to_owned(),
            },
            Resource::Property {
                db: "db".to_owned(),
                label: "Person".to_owned(),
                property: "name".to_owned(),
            },
        ]
    }

    /// All five actions.
    fn actions() -> [Action; 5] {
        [
            Action::Traverse,
            Action::Read,
            Action::Write,
            Action::Schema,
            Action::Admin,
        ]
    }

    /// The expected resource-containment relation, independent of action (mirrors
    /// [`Resource::covers`] but written out by hand so the test is an independent oracle).
    fn resource_covers_expected(grant: &Resource, wanted: &Resource) -> bool {
        use Resource::{Database, Graph, Label, Property, RelType};
        match (grant, wanted) {
            (Database, _) => true,
            (Graph(g), w) => w.database() == Some(g.as_str()),
            (Label { db, label }, Label { db: wd, label: wl }) => db == wd && label == wl,
            (
                Label { db, label },
                Property {
                    db: wd, label: wl, ..
                },
            ) => db == wd && label == wl,
            (Label { .. }, _) => false,
            (
                RelType { db, rel_type },
                RelType {
                    db: wd,
                    rel_type: wr,
                },
            ) => db == wd && rel_type == wr,
            (RelType { .. }, _) => false,
            (
                Property {
                    db,
                    label,
                    property,
                },
                Property {
                    db: wd,
                    label: wl,
                    property: wp,
                },
            ) => db == wd && label == wl && property == wp,
            (Property { .. }, _) => false,
        }
    }

    /// The expected action-containment relation (independent oracle for [`Action::implies`]).
    fn action_implies_expected(grant: Action, wanted: Action) -> bool {
        use Action::{Admin, Read, Schema, Traverse, Write};
        matches!(
            (grant, wanted),
            (Admin, _)
                | (Write, Write | Read | Traverse)
                | (Read, Read | Traverse)
                | (Traverse, Traverse)
                | (Schema, Schema)
        )
    }

    #[test]
    fn implies_matrix_is_exhaustive_and_composed() {
        // For every (grant action × grant scope) vs (wanted action × wanted scope): a grant
        // implies a request iff BOTH the action and the resource contain it. This pins the full
        // 25×25 cross-product against two independent oracles.
        for &ga in &actions() {
            for grant_scope in scopes() {
                let grant = Privilege::new(ga, grant_scope.clone());
                for &wa in &actions() {
                    for wanted_scope in scopes() {
                        let wanted = Privilege::new(wa, wanted_scope.clone());
                        let expected = action_implies_expected(ga, wa)
                            && resource_covers_expected(&grant_scope, &wanted_scope);
                        assert_eq!(
                            grant.implies(&wanted),
                            expected,
                            "grant {ga:?}@{grant_scope:?} vs wanted {wa:?}@{wanted_scope:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn scopes_never_cross_database_boundaries() {
        // A grant on database "a" must not cover ANY resource of database "b", for any action.
        let a = Privilege::on_graph(Action::Admin, "a"); // Admin: the most permissive action.
        for wanted in [
            Privilege::on_graph(Action::Traverse, "b"),
            Privilege::on_label(Action::Traverse, "b", "Person"),
            Privilege::on_rel_type(Action::Traverse, "b", "KNOWS"),
            Privilege::on_property(Action::Traverse, "b", "Person", "name"),
        ] {
            assert!(
                !a.implies(&wanted),
                "{a:?} must not cross into db b: {wanted:?}"
            );
        }
    }

    #[test]
    fn read_implies_traverse_but_not_vice_versa() {
        // The graded read chain at a concrete scope.
        let read = Privilege::on_label(Action::Read, "db", "Person");
        let traverse = Privilege::on_label(Action::Traverse, "db", "Person");
        assert!(read.implies(&traverse), "Read implies Traverse");
        assert!(!traverse.implies(&read), "Traverse does not imply Read");
        // Write implies both.
        let write = Privilege::on_label(Action::Write, "db", "Person");
        assert!(write.implies(&read));
        assert!(write.implies(&traverse));
        assert!(!read.implies(&write));
    }

    #[test]
    fn schema_is_orthogonal_to_the_read_write_chain() {
        let schema = Privilege::on_graph(Action::Schema, "db");
        // Schema does not grant data actions...
        assert!(!schema.implies(&Privilege::on_graph(Action::Read, "db")));
        assert!(!schema.implies(&Privilege::on_graph(Action::Write, "db")));
        assert!(!schema.implies(&Privilege::on_graph(Action::Traverse, "db")));
        // ...and no data action grants Schema; only Admin (and exact Schema) does.
        assert!(!Privilege::on_graph(Action::Write, "db").implies(&schema));
        assert!(Privilege::on_graph(Action::Admin, "db").implies(&schema));
        assert!(schema.implies(&schema));
    }

    #[test]
    fn property_scope_is_the_leaf() {
        let prop = Privilege::on_property(Action::Read, "db", "Person", "name");
        // Covers only itself: not the label, not another property.
        assert!(prop.implies(&Privilege::on_property(
            Action::Read,
            "db",
            "Person",
            "name"
        )));
        assert!(!prop.implies(&Privilege::on_property(Action::Read, "db", "Person", "age")));
        assert!(!prop.implies(&Privilege::on_label(Action::Read, "db", "Person")));
        assert!(!prop.implies(&Privilege::on_graph(Action::Read, "db")));
        // ...and the label covers the property (the other direction), but not relationship types.
        let label = Privilege::on_label(Action::Read, "db", "Person");
        assert!(label.implies(&prop));
        assert!(!label.implies(&Privilege::on_rel_type(Action::Read, "db", "KNOWS")));
    }

    #[test]
    fn deny_by_default_for_ungranted_fine_grained_scopes() {
        // A reader with only `Label Read` is denied everything outside that exact scope.
        let mut c = Catalog::new();
        c.create_user("gwen").unwrap();
        c.create_role("person_reader").unwrap();
        c.grant_privilege(
            "person_reader",
            Privilege::on_label(Action::Read, "db", "Person"),
        )
        .unwrap();
        c.grant_role("gwen", "person_reader").unwrap();
        // Granted: Read/Traverse on Person and its properties.
        assert!(c.authorize("gwen", &Privilege::on_label(Action::Read, "db", "Person")));
        assert!(c.authorize(
            "gwen",
            &Privilege::on_label(Action::Traverse, "db", "Person")
        ));
        assert!(c.authorize(
            "gwen",
            &Privilege::on_property(Action::Read, "db", "Person", "name")
        ));
        // Denied: a different label, the whole graph, a relationship type, and Write on Person.
        assert!(!c.authorize("gwen", &Privilege::on_label(Action::Read, "db", "Company")));
        assert!(!c.authorize("gwen", &Privilege::on_graph(Action::Read, "db")));
        assert!(!c.authorize("gwen", &Privilege::on_rel_type(Action::Read, "db", "KNOWS")));
        assert!(!c.authorize("gwen", &Privilege::on_label(Action::Write, "db", "Person")));
    }

    // ---- CRUD edge cases ---------------------------------------------------------------------

    #[test]
    fn create_user_twice_conflicts() {
        let mut c = Catalog::new();
        c.create_user("alice").unwrap();
        assert_eq!(
            c.create_user("alice"),
            Err(AuthError::AlreadyExists {
                what: "user alice".to_owned()
            })
        );
    }

    #[test]
    fn drop_unknown_user_is_not_found() {
        let mut c = Catalog::new();
        assert_eq!(
            c.drop_user("ghost"),
            Err(AuthError::NotFound {
                what: "user ghost".to_owned()
            })
        );
    }

    #[test]
    fn grant_role_requires_both_to_exist() {
        let mut c = Catalog::new();
        c.create_user("alice").unwrap();
        // Role does not exist yet.
        assert_eq!(
            c.grant_role("alice", "reader"),
            Err(AuthError::NotFound {
                what: "role reader".to_owned()
            })
        );
        c.create_role("reader").unwrap();
        // User does not exist.
        assert_eq!(
            c.grant_role("ghost", "reader"),
            Err(AuthError::NotFound {
                what: "user ghost".to_owned()
            })
        );
    }

    #[test]
    fn dropping_a_role_revokes_it_from_members() {
        let mut c = reader_catalog();
        assert!(c.authorize("alice", &Privilege::read_database()));
        c.drop_role("reader").unwrap();
        // alice no longer references the dropped role and is denied.
        assert!(!c.authorize("alice", &Privilege::read_database()));
        assert!(c.user("alice").unwrap().roles.is_empty());
    }

    #[test]
    fn grants_are_idempotent() {
        let mut c = reader_catalog();
        // Re-granting the same role and privilege does not error or duplicate.
        c.grant_role("alice", "reader").unwrap();
        c.grant_privilege("reader", Privilege::read_database())
            .unwrap();
        assert_eq!(c.user("alice").unwrap().roles.len(), 1);
        assert_eq!(c.role("reader").unwrap().privileges.len(), 1);
    }

    #[test]
    fn revoke_is_idempotent_and_role_neednt_be_held() {
        let mut c = Catalog::new();
        c.create_user("alice").unwrap();
        // Revoking a role the user never had succeeds (nothing to remove).
        c.revoke_role("alice", "never").unwrap();
        // Revoking from an unknown user is NotFound, though.
        assert!(matches!(
            c.revoke_role("ghost", "x"),
            Err(AuthError::NotFound { .. })
        ));
    }
}
