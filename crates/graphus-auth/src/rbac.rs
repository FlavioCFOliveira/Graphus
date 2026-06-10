//! The role-based access-control model shared by all three listeners (`04 §8.4`,
//! `D-auth-scheme`, `D-security-scope`).
//!
//! An identity has the **same authorization regardless of entry point** (UDS / Bolt-TCP / REST),
//! so the [`Catalog`] is the single source of truth that every listener resolves to. The model is
//! deliberately small and enum-based (`D-security-scope` defers fine-grained access control to
//! Phase 2):
//!
//! - A [`Privilege`] is an [`Action`] over a [`Resource`].
//! - A [`Role`] owns a set of privileges.
//! - A [`User`] is a member of zero or more roles and (optionally) holds a password hash for Bolt
//!   native auth.
//! - [`Catalog::authorize`] unions the privileges of all the user's roles and answers a single
//!   `(user, privilege)` question. **Deny by default**: anything not explicitly granted is denied.
//!
//! [`Action::Admin`] is a super-action: holding `Admin` over a resource implies every other action
//! over that resource, and `Admin` over [`Resource::Database`] implies everything everywhere. This
//! keeps the common "DBA can do anything" grant a single privilege rather than an enumeration.
//!
//! Password storage lives on the [`User`] but the hashing/verification primitives are in
//! [`crate::password`]; this module only holds the opaque hash string.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{AuthError, Result};

/// What an actor may do. [`Action::Admin`] implies all the others over the same resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Action {
    /// Read data (`MATCH`, `RETURN`, traversals).
    Read,
    /// Mutate data (`CREATE`/`SET`/`DELETE`/`MERGE`).
    Write,
    /// Create or drop indexes and constraints (schema/DDL).
    CreateIndex,
    /// Administrative authority: implies every other action over the same resource, and over
    /// [`Resource::Database`] implies authority over every named graph too.
    Admin,
}

/// What a [`Privilege`] applies to.
///
/// `Ord`/`Hash` make a `(Action, Resource)` pair usable directly as a `BTreeSet` key, which is how
/// a [`Role`] stores its grants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Resource {
    /// The whole database (server-wide scope). `Admin` here is the global super-grant.
    Database,
    /// A single named graph. Graphus is a multigraph server, so most data privileges are scoped to
    /// a graph by name.
    Graph(String),
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

    /// `Read` over the whole database.
    #[must_use]
    pub fn read_database() -> Self {
        Self::new(Action::Read, Resource::Database)
    }

    /// `Write` over the whole database.
    #[must_use]
    pub fn write_database() -> Self {
        Self::new(Action::Write, Resource::Database)
    }

    /// `Admin` over the whole database — the global super-grant.
    #[must_use]
    pub fn admin_database() -> Self {
        Self::new(Action::Admin, Resource::Database)
    }

    /// Returns `true` if holding `self` is sufficient to satisfy a request for `wanted`.
    ///
    /// This encodes the implication rules (deny-by-default is enforced by the *caller* iterating
    /// only over granted privileges, never here):
    ///
    /// 1. An exact match always implies.
    /// 2. `Admin` over the same resource implies any action over that resource.
    /// 3. `Admin` over [`Resource::Database`] implies any action over any resource (global root).
    /// 4. A *database-wide* grant of an action implies that same action on any named graph
    ///    (database scope contains graph scope), e.g. database `Read` covers `Read` on `Graph(g)`.
    #[must_use]
    pub fn implies(&self, wanted: &Privilege) -> bool {
        // Rule 3: global Admin is root over everything.
        if self.action == Action::Admin && self.resource == Resource::Database {
            return true;
        }
        // Resource containment: a Database-scoped grant covers the same-or-narrower resource;
        // a Graph-scoped grant covers only that exact graph.
        let resource_covers = match (&self.resource, &wanted.resource) {
            (Resource::Database, _) => true,
            (Resource::Graph(a), Resource::Graph(b)) => a == b,
            (Resource::Graph(_), Resource::Database) => false,
        };
        if !resource_covers {
            return false;
        }
        // Rule 2: Admin over a covered resource implies any action; otherwise actions must match.
        self.action == Action::Admin || self.action == wanted.action
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
        // Global Admin satisfies Read, Write, CreateIndex on the DB...
        assert!(c.authorize("root", &Privilege::read_database()));
        assert!(c.authorize("root", &Privilege::write_database()));
        assert!(c.authorize(
            "root",
            &Privilege::new(Action::CreateIndex, Resource::Database)
        ));
        // ...and any action on any named graph (database scope contains graph scope).
        assert!(c.authorize(
            "root",
            &Privilege::new(Action::Write, Resource::Graph("social".to_owned()))
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
        assert!(c.authorize(
            "dave",
            &Privilege::new(Action::Read, Resource::Graph("g".to_owned()))
        ));
        // ...but not Write on that graph.
        assert!(!c.authorize(
            "dave",
            &Privilege::new(Action::Write, Resource::Graph("g".to_owned()))
        ));
    }

    #[test]
    fn graph_scope_is_not_a_database_grant() {
        let mut c = Catalog::new();
        c.create_user("erin").unwrap();
        c.create_role("g_reader").unwrap();
        c.grant_privilege(
            "g_reader",
            Privilege::new(Action::Read, Resource::Graph("g".to_owned())),
        )
        .unwrap();
        c.grant_role("erin", "g_reader").unwrap();
        // Read on graph "g" does NOT grant database-wide Read...
        assert!(!c.authorize("erin", &Privilege::read_database()));
        // ...nor Read on a different graph.
        assert!(!c.authorize(
            "erin",
            &Privilege::new(Action::Read, Resource::Graph("other".to_owned()))
        ));
        // ...but does grant Read on "g".
        assert!(c.authorize(
            "erin",
            &Privilege::new(Action::Read, Resource::Graph("g".to_owned()))
        ));
    }

    #[test]
    fn graph_admin_implies_actions_on_that_graph_only() {
        let mut c = Catalog::new();
        c.create_user("frank").unwrap();
        c.create_role("g_admin").unwrap();
        c.grant_privilege(
            "g_admin",
            Privilege::new(Action::Admin, Resource::Graph("g".to_owned())),
        )
        .unwrap();
        c.grant_role("frank", "g_admin").unwrap();
        // Admin on "g" implies Write/CreateIndex on "g"...
        assert!(c.authorize(
            "frank",
            &Privilege::new(Action::Write, Resource::Graph("g".to_owned()))
        ));
        // ...but not anything database-wide, and not Admin-as-root.
        assert!(!c.authorize("frank", &Privilege::read_database()));
        assert!(!c.authorize(
            "frank",
            &Privilege::new(Action::Write, Resource::Graph("other".to_owned()))
        ));
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
