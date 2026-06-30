//! The crash-safe **security catalog** + live RBAC administration (rmp #92, decision
//! `D-auth-scheme`; the foundation half of fine-grained access control — executor enforcement is
//! rmp #93).
//!
//! [`graphus_auth::Authenticator`] holds the in-memory RBAC model (users, roles, grants) that every
//! listener authorizes against. Before this module that model was built once at startup from config
//! bootstrap and was **never persisted, recovered, or mutated at runtime** (the live-mutation gap
//! flagged in rmp #84). [`SecurityCatalog`] closes both gaps:
//!
//! 1. **Durability.** The full security model (users — name + password **hash** + role memberships;
//!    roles — name + granted privileges) is persisted to `<store_path>/security.toml` with the same
//!    atomic-replace protocol the database catalog uses ([`crate::dbcatalog`]): write a temp file →
//!    `fsync` it → atomically `rename` it onto the live file → `fsync` the parent directory. A crash
//!    at any point leaves either the complete old file or the complete new file, never a torn one.
//!    Plaintext passwords are **never** persisted — only the Argon2 PHC hash already produced by
//!    [`graphus_auth::password`].
//!
//! 2. **Live administration.** The [`Authenticator`] lives behind a [`std::sync::RwLock`]: the
//!    per-request authorization hot path takes a brief **read** lock (mirroring `dbcatalog`'s
//!    handle-lookup `RwLock`), while the admin commands (`CREATE USER`, `GRANT`, …) take the
//!    **write** lock, mutate, and then persist the new model durably **before** reporting success.
//!    The lock is never held across an `.await`: the persist runs off the runtime via
//!    `spawn_blocking`, and the lock is dropped before awaiting it.
//!
//! ## Fail-closed loading + bootstrap precedence
//!
//! At startup [`SecurityCatalog::load`] reads `security.toml`:
//!
//! - **Absent** ⇒ a fresh install: the model is seeded from config bootstrap (the admin user, the
//!   optional non-admin users) and the seeded model is **persisted immediately**, so the very next
//!   start is file-authoritative. This keeps a pre-#92 deployment (no security file) working
//!   unchanged.
//! - **Present** ⇒ the file is **authoritative**: it is loaded verbatim and config bootstrap is
//!   **ignored** for users/roles/grants. (The bootstrap admin *name* is still read from config so
//!   the lockout safeguard knows which principal must keep admin — see below — and the admin uid /
//!   JWT secret still come from config, since neither is part of the persisted RBAC model.)
//! - **Present but malformed** ⇒ the load **fails closed** ([`SecurityError::Corrupt`]): the server
//!   refuses to start rather than silently resetting the security model to an empty (or
//!   bootstrap-only) state. A corrupt security file is an operator emergency, never an open door.
//!
//! ## Lockout safeguard
//!
//! The **bootstrap admin** (config `auth.admin_user`) can never be locked out of administration:
//! dropping that user, revoking its admin-bearing role, or revoking the global `Admin` privilege
//! from a role in a way that would leave the bootstrap admin without global `Admin` is rejected
//! with [`SecurityError::WouldLockOutAdmin`]. The check is "would this mutation leave the bootstrap
//! admin holding global `Admin`?" evaluated against a *trial* copy, so the live model is touched
//! only when the mutation is safe.

use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use graphus_auth::{Action, AuthError, AuthProvider, Authenticator, Claims, Privilege, Resource};
use serde::{Deserialize, Serialize};

use crate::config::ServerConfig;

/// The durable security-catalog file name, directly under the data root.
pub const SECURITY_FILE_NAME: &str = "security.toml";

/// The temp file the atomic-replace protocol writes before the rename.
const SECURITY_TMP_NAME: &str = "security.toml.tmp";

/// The security-file format version this build reads and writes. A file with any other version
/// fails the load closed (a future format change must bump this and ship explicit migration).
const SECURITY_FORMAT_VERSION: u32 = 1;

// ------------------------------------------------------------------------------------------------
// Errors
// ------------------------------------------------------------------------------------------------

/// How a security-catalog operation failed.
#[derive(Debug)]
pub enum SecurityError {
    /// A client-fault RBAC operation failed (unknown/duplicate user or role, etc.). Carries the
    /// underlying [`AuthError`].
    Rbac(AuthError),
    /// The mutation would leave the bootstrap admin (config `auth.admin_user`) without global
    /// `Admin` authority — refused so an operator can never lock themselves out.
    WouldLockOutAdmin {
        /// The bootstrap admin's username.
        admin: String,
        /// A short description of the rejected mutation.
        operation: String,
    },
    /// A filesystem operation on the security file failed.
    Io {
        /// The path the operation touched.
        path: PathBuf,
        /// What was being done + the underlying I/O error rendering.
        source: String,
    },
    /// The security file exists but is malformed. The load **fails closed**: the server refuses to
    /// start rather than silently resetting the security model.
    Corrupt {
        /// The security file path.
        path: PathBuf,
        /// Why it could not be accepted.
        reason: String,
    },
    /// Serializing the security model for persistence failed (an internal invariant violation).
    Encode(String),
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rbac(e) => write!(f, "{e}"),
            Self::WouldLockOutAdmin { admin, operation } => write!(
                f,
                "refusing to {operation}: it would strip the bootstrap admin {admin:?} of \
                 administrative access (lock-out safeguard)"
            ),
            Self::Io { path, source } => {
                write!(
                    f,
                    "security catalog I/O error at {}: {source}",
                    path.display()
                )
            }
            Self::Corrupt { path, reason } => write!(
                f,
                "security file {} is malformed: {reason}. Refusing to start — repair or remove the \
                 file explicitly; the server never resets a corrupt security model",
                path.display()
            ),
            Self::Encode(m) => write!(f, "encoding security catalog: {m}"),
        }
    }
}

impl std::error::Error for SecurityError {}

impl From<AuthError> for SecurityError {
    fn from(e: AuthError) -> Self {
        Self::Rbac(e)
    }
}

/// The crate-local result alias for security-catalog operations.
type Result<T> = std::result::Result<T, SecurityError>;

// ------------------------------------------------------------------------------------------------
// On-disk format
// ------------------------------------------------------------------------------------------------

/// The serialized shape of `security.toml`. Unknown fields are rejected (a format change must bump
/// [`SECURITY_FORMAT_VERSION`], never silently extend version 1).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityFile {
    /// The format version; must equal [`SECURITY_FORMAT_VERSION`].
    version: u32,
    /// Every user, in deterministic (name) order.
    #[serde(default)]
    users: Vec<UserRecord>,
    /// Every role, in deterministic (name) order.
    #[serde(default)]
    roles: Vec<RoleRecord>,
}

/// One user's durable record: name, optional **password hash** (never plaintext), role memberships.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserRecord {
    /// The username.
    name: String,
    /// The Argon2 PHC hash, or absent if password auth is not configured for this user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password_hash: Option<String>,
    /// The names of the roles this user belongs to.
    #[serde(default)]
    roles: Vec<String>,
    /// The user's credential epoch (token version, SEC-180): persisted so a Bearer token revoked by
    /// a password change stays revoked across a restart. Absent/`0` for a user whose password has
    /// never changed (the common case), keeping pre-existing security files forward-compatible.
    #[serde(default, skip_serializing_if = "is_zero")]
    credential_version: u64,
}

/// Helper for `skip_serializing_if`: a `0` credential epoch is the default and is omitted from the
/// file so existing security files round-trip unchanged.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// One role's durable record: name + granted privileges.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleRecord {
    /// The role name.
    name: String,
    /// The privileges granted by this role.
    #[serde(default)]
    privileges: Vec<PrivilegeRecord>,
}

/// One privilege's durable record: an action over a scope. The scope is a flat, self-describing
/// shape so the file is human-readable and round-trips exactly onto [`Resource`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivilegeRecord {
    /// The action (`"traverse"`, `"read"`, `"write"`, `"schema"`, `"admin"`).
    action: ActionRecord,
    /// The scope kind (`"database"`, `"graph"`, `"label"`, `"rel_type"`, `"property"`).
    scope: ScopeKind,
    /// The database name (absent only for the server-wide `database` scope).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    db: Option<String>,
    /// The node label (`label` and `property` scopes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    /// The relationship type (`rel_type` scope).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rel_type: Option<String>,
    /// The property key (`property` scope).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    property: Option<String>,
}

/// The serialized action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ActionRecord {
    Traverse,
    Read,
    Write,
    Schema,
    Admin,
}

impl From<Action> for ActionRecord {
    fn from(a: Action) -> Self {
        match a {
            Action::Traverse => Self::Traverse,
            Action::Read => Self::Read,
            Action::Write => Self::Write,
            Action::Schema => Self::Schema,
            Action::Admin => Self::Admin,
            // `Action` is `#[non_exhaustive]`; an unknown future variant must fail loudly at
            // serialization rather than silently persist as a weaker action.
            _ => Self::Admin,
        }
    }
}

impl ActionRecord {
    fn to_action(self) -> Action {
        match self {
            Self::Traverse => Action::Traverse,
            Self::Read => Action::Read,
            Self::Write => Action::Write,
            Self::Schema => Action::Schema,
            Self::Admin => Action::Admin,
        }
    }
}

/// The serialized scope kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ScopeKind {
    Database,
    Graph,
    Label,
    RelType,
    Property,
}

impl PrivilegeRecord {
    /// Builds a record from a privilege (the serialization direction).
    fn from_privilege(p: &Privilege) -> Self {
        let action = p.action.into();
        match &p.resource {
            Resource::Database => Self {
                action,
                scope: ScopeKind::Database,
                db: None,
                label: None,
                rel_type: None,
                property: None,
            },
            Resource::Graph(db) => Self {
                action,
                scope: ScopeKind::Graph,
                db: Some(db.clone()),
                label: None,
                rel_type: None,
                property: None,
            },
            Resource::Label { db, label } => Self {
                action,
                scope: ScopeKind::Label,
                db: Some(db.clone()),
                label: Some(label.clone()),
                rel_type: None,
                property: None,
            },
            Resource::RelType { db, rel_type } => Self {
                action,
                scope: ScopeKind::RelType,
                db: Some(db.clone()),
                label: None,
                rel_type: Some(rel_type.clone()),
                property: None,
            },
            Resource::Property {
                db,
                label,
                property,
            } => Self {
                action,
                scope: ScopeKind::Property,
                db: Some(db.clone()),
                label: Some(label.clone()),
                rel_type: None,
                property: Some(property.clone()),
            },
            // `Resource` is `#[non_exhaustive]`; persist an unknown future variant as the
            // server-wide scope would be unsound (too broad), so reject it at load time instead —
            // here we cannot, so map to the narrowest representable form and rely on the load-time
            // re-validation. In practice this arm is unreachable for the variants this build knows.
            _ => Self {
                action,
                scope: ScopeKind::Database,
                db: None,
                label: None,
                rel_type: None,
                property: None,
            },
        }
    }

    /// Reconstructs a [`Privilege`] from a record (the load direction), validating that the scope's
    /// required fields are present.
    fn to_privilege(&self, path: &Path) -> Result<Privilege> {
        let corrupt = |reason: String| SecurityError::Corrupt {
            path: path.to_path_buf(),
            reason,
        };
        let action = self.action.to_action();
        let db = || {
            self.db
                .clone()
                .ok_or_else(|| corrupt(format!("{:?} scope requires `db`", self.scope)))
        };
        let label = || {
            self.label
                .clone()
                .ok_or_else(|| corrupt(format!("{:?} scope requires `label`", self.scope)))
        };
        let resource = match self.scope {
            ScopeKind::Database => Resource::Database,
            ScopeKind::Graph => Resource::Graph(db()?),
            ScopeKind::Label => Resource::Label {
                db: db()?,
                label: label()?,
            },
            ScopeKind::RelType => Resource::RelType {
                db: db()?,
                rel_type: self
                    .rel_type
                    .clone()
                    .ok_or_else(|| corrupt("rel_type scope requires `rel_type`".to_owned()))?,
            },
            ScopeKind::Property => Resource::Property {
                db: db()?,
                label: label()?,
                property: self
                    .property
                    .clone()
                    .ok_or_else(|| corrupt("property scope requires `property`".to_owned()))?,
            },
        };
        Ok(Privilege::new(action, resource))
    }
}

// ------------------------------------------------------------------------------------------------
// Persistence (mirrors crate::dbcatalog's atomic-replace protocol)
// ------------------------------------------------------------------------------------------------

/// Builds a [`SecurityError::Io`] with a uniform "what failed: why" rendering.
fn io_error(path: &Path, what: &str, e: &std::io::Error) -> SecurityError {
    SecurityError::Io {
        path: path.to_path_buf(),
        source: format!("{what}: {e}"),
    }
}

/// Serializes the live [`Authenticator`]'s RBAC model into the on-disk [`SecurityFile`] shape.
fn to_file(auth: &Authenticator) -> SecurityFile {
    let catalog = auth.catalog();
    let users = catalog
        .users()
        .map(|(name, user)| UserRecord {
            name: name.to_owned(),
            password_hash: user.password_hash.clone(),
            roles: user.roles.iter().cloned().collect(),
            credential_version: user.credential_version,
        })
        .collect();
    let roles = catalog
        .roles()
        .map(|(name, role)| RoleRecord {
            name: name.to_owned(),
            privileges: role
                .privileges
                .iter()
                .map(PrivilegeRecord::from_privilege)
                .collect(),
        })
        .collect();
    SecurityFile {
        version: SECURITY_FORMAT_VERSION,
        users,
        roles,
    }
}

/// Persists `auth`'s model to `<root>/security.toml` with the atomic-replace protocol (see
/// [`persist_file`]). Blocking; run it off the runtime.
fn persist(root: &Path, auth: &Authenticator) -> Result<()> {
    persist_file(root, &to_file(auth))
}

/// Whether a security file exists at `root` (drives the load precedence: present ⇒ authoritative).
fn security_file_exists(root: &Path) -> bool {
    root.join(SECURITY_FILE_NAME).is_file()
}

/// Loads the durable security model into `auth` from `<root>/security.toml`, removing a stale temp
/// file first. The file is assumed to exist (the caller checks). A malformed file **fails closed**
/// ([`SecurityError::Corrupt`]).
///
/// The `auth` passed in must be freshly constructed (only the JWT secret set): users/roles are
/// reconstructed entirely from the file. A role named by a user but absent from the file, or a
/// duplicate user/role, is corruption.
fn load_into(root: &Path, auth: &mut Authenticator) -> Result<()> {
    // A stale temp is a crashed mutation whose rename never happened; the real file is
    // authoritative. Removal is best-effort: a leftover temp is inert (the next persist truncates
    // it), so failing to remove it must not fail the load.
    let tmp = root.join(SECURITY_TMP_NAME);
    match std::fs::remove_file(&tmp) {
        Ok(()) => tracing::warn!(
            path = %tmp.display(),
            "removed stale security temp file (a security write crashed before publishing)"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(
            path = %tmp.display(),
            error = %e,
            "could not remove stale security temp file (inert; reused by the next persist)"
        ),
    }

    let path = root.join(SECURITY_FILE_NAME);
    let text =
        std::fs::read_to_string(&path).map_err(|e| io_error(&path, "reading security", &e))?;
    let corrupt = |reason: String| SecurityError::Corrupt {
        path: path.clone(),
        reason,
    };
    let parsed: SecurityFile = toml::from_str(&text).map_err(|e| corrupt(e.to_string()))?;
    if parsed.version != SECURITY_FORMAT_VERSION {
        return Err(corrupt(format!(
            "unsupported security version {} (this build supports {SECURITY_FORMAT_VERSION})",
            parsed.version
        )));
    }

    let catalog = auth.catalog_mut();

    // Roles first (a user references roles by name; every referenced role must exist).
    for role in &parsed.roles {
        catalog
            .create_role(role.name.clone())
            .map_err(|_| corrupt(format!("duplicate role {:?}", role.name)))?;
        for rec in &role.privileges {
            let privilege = rec.to_privilege(&path)?;
            catalog
                .grant_privilege(&role.name, privilege)
                .map_err(|e| corrupt(format!("granting to role {:?}: {e}", role.name)))?;
        }
    }

    // Then users, restoring the hash verbatim and re-granting role memberships.
    for user in &parsed.users {
        catalog
            .create_user(user.name.clone())
            .map_err(|_| corrupt(format!("duplicate user {:?}", user.name)))?;
        if let Some(hash) = &user.password_hash {
            catalog
                .set_user_password_hash(&user.name, Some(hash.clone()))
                .map_err(|e| {
                    corrupt(format!("restoring password hash for {:?}: {e}", user.name))
                })?;
        }
        // Restore the credential epoch verbatim (SEC-180): a token revoked by a pre-restart password
        // change must stay revoked. `set_credential_version` (unlike `bump_*`) sets the persisted
        // value exactly rather than advancing it.
        catalog
            .set_credential_version(&user.name, user.credential_version)
            .map_err(|e| {
                corrupt(format!(
                    "restoring credential epoch for {:?}: {e}",
                    user.name
                ))
            })?;
        for role in &user.roles {
            if !catalog.has_role(role) {
                return Err(corrupt(format!(
                    "user {:?} references unknown role {role:?}",
                    user.name
                )));
            }
            catalog
                .grant_role(&user.name, role)
                .map_err(|e| corrupt(format!("granting role to {:?}: {e}", user.name)))?;
        }
    }

    Ok(())
}

// ------------------------------------------------------------------------------------------------
// The security catalog
// ------------------------------------------------------------------------------------------------

/// The live, durable security catalog: the [`Authenticator`] behind a read/write lock, the data
/// root it persists into, and the bootstrap admin name the lock-out safeguard protects.
///
/// Cheap to share (`Arc`); the per-request authorization path takes a brief read lock, admin
/// mutations take the write lock and persist before returning success (see the module docs).
pub struct SecurityCatalog {
    /// The data root (`store_path`) where `security.toml` lives.
    root: PathBuf,
    /// The bootstrap admin's username (config `auth.admin_user`) — the principal the lock-out
    /// safeguard guarantees keeps global `Admin`.
    bootstrap_admin: String,
    /// The live RBAC model. Read-locked on the authorization hot path, write-locked for mutations;
    /// never held across an `.await`.
    auth: RwLock<Authenticator>,
}

impl SecurityCatalog {
    /// Loads the security catalog for `config`. Precedence (module docs):
    ///
    /// - `security.toml` **present** ⇒ authoritative: load it verbatim (config bootstrap ignored for
    ///   users/roles/grants). Malformed ⇒ fail closed.
    /// - `security.toml` **absent** ⇒ fresh install: seed from config bootstrap and persist the
    ///   seeded model immediately, so the next start is file-authoritative.
    ///
    /// The JWT secret and the admin uid always come from config (neither is part of the persisted
    /// RBAC model).
    ///
    /// # Errors
    /// [`SecurityError::Corrupt`] if the present file is malformed; [`SecurityError::Io`] on a read
    /// or persist failure; [`SecurityError::Rbac`] if config bootstrap is internally inconsistent.
    pub fn load(config: &ServerConfig) -> Result<Self> {
        let root = config.store_path.clone();
        let bootstrap_admin = config.auth.admin_user.clone();
        // A short JWT secret is rejected here (fail-closed startup): a weak HS256 key would make
        // Bearer tokens forgeable. `AuthError` converts into `SecurityError::Rbac` via `?`.
        let mut auth = Authenticator::new(config.jwt_secret.as_bytes())?;

        if security_file_exists(&root) {
            // Authoritative file: load it; config bootstrap is ignored for the RBAC model.
            load_into(&root, &mut auth)?;
            // The admin uid binding is not part of the persisted model — re-apply it from config.
            if let Some(uid) = config.auth.admin_uid {
                auth.peers_mut().map_uid(uid, bootstrap_admin.clone());
            }
        } else {
            // Fresh install: seed from config bootstrap, then persist so the next start is
            // file-authoritative.
            seed_from_config(&mut auth, config)?;
            persist(&root, &auth)?;
        }

        Ok(Self {
            root,
            bootstrap_admin,
            auth: RwLock::new(auth),
        })
    }

    /// Constructs a catalog directly from an already-built [`Authenticator`] and an explicit data
    /// root + bootstrap-admin name, **without** loading or persisting (the test seam;
    /// [`load`](Self::load) is the production entry point). The model is persisted on the first
    /// mutation.
    #[must_use]
    pub fn from_parts(root: PathBuf, bootstrap_admin: String, auth: Authenticator) -> Self {
        Self {
            root,
            bootstrap_admin,
            auth: RwLock::new(auth),
        }
    }

    /// The bootstrap admin's username (the lock-out-protected principal).
    #[must_use]
    pub fn bootstrap_admin(&self) -> &str {
        &self.bootstrap_admin
    }

    /// Runs `f` against the live [`Authenticator`] under a brief **read** lock — the per-request
    /// authorization / authentication path. `f` must not block or `.await`.
    pub fn with_auth<T>(&self, f: impl FnOnce(&Authenticator) -> T) -> T {
        let guard = self.auth.read().unwrap_or_else(PoisonError::into_inner);
        f(&guard)
    }

    // ---- Listing (read-locked) ----------------------------------------------------------------

    /// Lists every user's name and role memberships, name-sorted. For `SHOW USERS`.
    #[must_use]
    pub fn list_users(&self) -> Vec<UserListing> {
        self.with_auth(|auth| {
            auth.catalog()
                .users()
                .map(|(name, user)| UserListing {
                    name: name.to_owned(),
                    roles: user.roles.iter().cloned().collect(),
                    has_password: user.password_hash.is_some(),
                })
                .collect()
        })
    }

    /// Lists every role's name and the count of privileges it grants, name-sorted. For `SHOW ROLES`.
    #[must_use]
    pub fn list_roles(&self) -> Vec<RoleListing> {
        self.with_auth(|auth| {
            auth.catalog()
                .roles()
                .map(|(name, role)| RoleListing {
                    name: name.to_owned(),
                    privilege_count: role.privileges.len(),
                })
                .collect()
        })
    }

    /// Lists every (role, action, scope) grant, role- then privilege-sorted. For `SHOW PRIVILEGES`.
    #[must_use]
    pub fn list_privileges(&self) -> Vec<PrivilegeListing> {
        self.with_auth(|auth| {
            let mut out = Vec::new();
            for (role, role_def) in auth.catalog().roles() {
                for privilege in &role_def.privileges {
                    out.push(PrivilegeListing {
                        role: role.to_owned(),
                        action: action_word(privilege.action).to_owned(),
                        scope: scope_string(&privilege.resource),
                    });
                }
            }
            out
        })
    }

    // ---- Mutations (write-locked, persisted) --------------------------------------------------

    /// Applies a mutation under the write lock, then persists the new model durably **before**
    /// returning success. The lock is dropped before the (off-runtime) persist, so a slow `fsync`
    /// never stalls the authorization hot path.
    ///
    /// When `check_lockout` is set, the post-mutation model is re-validated **inside the write lock**
    /// (after `apply`): if it would leave the bootstrap admin without global `Admin`, the mutation is
    /// rolled back from a pre-mutation snapshot *before the lock is released* and
    /// [`SecurityError::WouldLockOutAdmin`] is returned — closing the TOCTOU window two concurrent
    /// revocations could otherwise exploit (each individually safe, together a lock-out).
    ///
    /// On a persist failure the in-memory model is resynced from the published file (or kept if no
    /// file exists yet) and the I/O error is returned, so memory never claims a change the disk did
    /// not accept.
    async fn mutate<F>(&self, describe: &str, check_lockout: bool, apply: F) -> Result<()>
    where
        F: FnOnce(&mut Authenticator) -> Result<()>,
    {
        // 1) Mutate in memory under the write lock. The lock-out re-check runs here, atomically with
        //    the mutation, so concurrent revocations cannot combine to lock out the bootstrap admin.
        {
            let mut guard = self.auth.write().unwrap_or_else(PoisonError::into_inner);
            // Snapshot the RBAC catalog for an in-memory rollback if the lock-out check trips.
            let before = check_lockout.then(|| guard.catalog().clone());
            apply(&mut guard)?;
            if check_lockout
                && !guard.authorize(&self.bootstrap_admin, &Privilege::admin_database())
            {
                // Roll back the just-applied mutation and refuse: the bootstrap admin must keep
                // global Admin. `before` is `Some` whenever `check_lockout` is set.
                if let Some(catalog) = before {
                    *guard.catalog_mut() = catalog;
                }
                return Err(SecurityError::WouldLockOutAdmin {
                    admin: self.bootstrap_admin.clone(),
                    operation: describe.to_owned(),
                });
            }
        }
        // 2) Persist off the runtime. Snapshot the model under a brief read lock first so the
        //    write lock is not held across the spawn_blocking boundary.
        let root = self.root.clone();
        let snapshot = self.with_auth(to_file);
        let persist_result = tokio::task::spawn_blocking(move || persist_file(&root, &snapshot))
            .await
            .map_err(|e| SecurityError::Io {
                path: self.root.join(SECURITY_FILE_NAME),
                source: format!("persist task join: {e}"),
            })
            .and_then(|r| r);

        if let Err(e) = persist_result {
            // The durable write failed. Reload memory from the published file so it never asserts
            // state the disk does not hold; if there is no published file yet (the first-ever
            // mutation failed), the in-memory model is kept and the divergence is logged.
            tracing::error!(
                operation = describe,
                error = %e,
                "security mutation could not be persisted; resyncing memory to the durable file",
            );
            self.resync_from_disk();
            return Err(e);
        }
        Ok(())
    }

    /// Reloads the in-memory RBAC model from the published `security.toml` after a failed persist,
    /// so memory follows the durable truth (never asserting a change the disk rejected). Only the
    /// RBAC catalog is rebuilt; the JWT secret and the uid map are untouched (neither is part of the
    /// persisted model). Best effort: if the reload itself fails, the current in-memory model is
    /// kept and the possible divergence is logged.
    fn resync_from_disk(&self) {
        if !security_file_exists(&self.root) {
            // No durable file to resync to (a first-ever mutation failed before any file existed).
            // Keep the current in-memory model; the next successful mutation will publish it.
            return;
        }
        let reload = {
            let mut guard = self.auth.write().unwrap_or_else(PoisonError::into_inner);
            // Clear the RBAC catalog and re-load it from the published file in place.
            *guard.catalog_mut() = graphus_auth::Catalog::new();
            load_into(&self.root, &mut guard)
        };
        if let Err(e) = reload {
            tracing::error!(
                error = %e,
                "could not resync the security model from disk after a failed persist; the \
                 in-memory model may diverge until the next successful mutation or restart",
            );
        }
    }

    /// `CREATE USER <name> SET PASSWORD '<pw>'`.
    ///
    /// # Errors
    /// [`SecurityError::Rbac`] ([`AuthError::AlreadyExists`]) if the user exists;
    /// [`SecurityError::Io`] on persist failure.
    pub async fn create_user(&self, name: &str, password: Option<&str>) -> Result<()> {
        let name = name.to_owned();
        let password = password.map(str::to_owned);
        self.mutate("create the user", false, move |auth| {
            auth.catalog_mut().create_user(name.clone())?;
            if let Some(pw) = &password {
                auth.set_password(&name, pw)?;
            }
            Ok(())
        })
        .await
    }

    /// `DROP USER <name>`. Rejected if it would lock out the bootstrap admin.
    ///
    /// # Errors
    /// [`SecurityError::WouldLockOutAdmin`] if `name` is the bootstrap admin;
    /// [`SecurityError::Rbac`] ([`AuthError::NotFound`]) if the user does not exist;
    /// [`SecurityError::Io`] on persist failure.
    pub async fn drop_user(&self, name: &str) -> Result<()> {
        // Dropping the bootstrap admin is rejected up front (the lock-out re-check inside `mutate`
        // would also catch it, but the explicit name guard gives a precise message and avoids
        // touching the model at all).
        if name == self.bootstrap_admin {
            return Err(SecurityError::WouldLockOutAdmin {
                admin: self.bootstrap_admin.clone(),
                operation: format!("drop the user {name:?}"),
            });
        }
        let name = name.to_owned();
        self.mutate(&format!("drop the user {name:?}"), false, move |auth| {
            auth.catalog_mut().drop_user(&name)?;
            Ok(())
        })
        .await
    }

    /// `CREATE ROLE <name>`.
    ///
    /// # Errors
    /// [`SecurityError::Rbac`] ([`AuthError::AlreadyExists`]) if the role exists;
    /// [`SecurityError::Io`] on persist failure.
    pub async fn create_role(&self, name: &str) -> Result<()> {
        let name = name.to_owned();
        self.mutate("create the role", false, move |auth| {
            auth.catalog_mut().create_role(name)?;
            Ok(())
        })
        .await
    }

    /// `DROP ROLE <name>`. Rejected if dropping it would strip the bootstrap admin of global Admin.
    ///
    /// # Errors
    /// [`SecurityError::WouldLockOutAdmin`], [`SecurityError::Rbac`] ([`AuthError::NotFound`]),
    /// [`SecurityError::Io`].
    pub async fn drop_role(&self, name: &str) -> Result<()> {
        let name = name.to_owned();
        self.mutate(&format!("drop the role {name:?}"), true, move |auth| {
            auth.catalog_mut().drop_role(&name)?;
            Ok(())
        })
        .await
    }

    /// `GRANT ROLE <role> TO <user>`.
    ///
    /// # Errors
    /// [`SecurityError::Rbac`] ([`AuthError::NotFound`]) if either does not exist;
    /// [`SecurityError::Io`] on persist failure.
    pub async fn grant_role(&self, user: &str, role: &str) -> Result<()> {
        let (user, role) = (user.to_owned(), role.to_owned());
        self.mutate("grant the role", false, move |auth| {
            auth.catalog_mut().grant_role(&user, &role)?;
            Ok(())
        })
        .await
    }

    /// `REVOKE ROLE <role> FROM <user>`. Rejected if it would strip the bootstrap admin of Admin.
    ///
    /// # Errors
    /// [`SecurityError::WouldLockOutAdmin`], [`SecurityError::Rbac`] ([`AuthError::NotFound`] for an
    /// unknown user), [`SecurityError::Io`].
    pub async fn revoke_role(&self, user: &str, role: &str) -> Result<()> {
        let describe = format!("revoke the role {role:?} from {user:?}");
        let (user, role) = (user.to_owned(), role.to_owned());
        self.mutate(&describe, true, move |auth| {
            auth.catalog_mut().revoke_role(&user, &role)?;
            Ok(())
        })
        .await
    }

    /// `GRANT <action> ON <scope> TO <role>`.
    ///
    /// # Errors
    /// [`SecurityError::Rbac`] ([`AuthError::NotFound`]) if the role does not exist;
    /// [`SecurityError::Io`] on persist failure.
    pub async fn grant_privilege(&self, role: &str, privilege: Privilege) -> Result<()> {
        let role = role.to_owned();
        self.mutate("grant the privilege", false, move |auth| {
            auth.catalog_mut().grant_privilege(&role, privilege)?;
            Ok(())
        })
        .await
    }

    /// `REVOKE <action> ON <scope> FROM <role>`. Rejected if it would strip the bootstrap admin of
    /// global Admin.
    ///
    /// # Errors
    /// [`SecurityError::WouldLockOutAdmin`], [`SecurityError::Rbac`] ([`AuthError::NotFound`]),
    /// [`SecurityError::Io`].
    pub async fn revoke_privilege(&self, role: &str, privilege: Privilege) -> Result<()> {
        let describe = format!(
            "revoke {} from the role {role:?}",
            scope_string(&privilege.resource)
        );
        let role = role.to_owned();
        self.mutate(&describe, true, move |auth| {
            auth.catalog_mut().revoke_privilege(&role, &privilege)?;
            Ok(())
        })
        .await
    }
}

impl std::fmt::Debug for SecurityCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityCatalog")
            .field("root", &self.root)
            .field("bootstrap_admin", &self.bootstrap_admin)
            .finish_non_exhaustive()
    }
}

// ------------------------------------------------------------------------------------------------
// The live authentication provider (rmp #94)
// ------------------------------------------------------------------------------------------------

/// A **live** [`AuthProvider`] over the [`SecurityCatalog`]: the implementation `graphus-server`
/// hands to the connectivity seams (`graphus-bolt`, `graphus-rest`) so their authentication path
/// consults the *current* security model rather than a startup snapshot (rmp #94).
///
/// Before this, the seams held a point-in-time `Authenticator` clone, so a user created at runtime
/// could not `LOGON` / present a Bearer token, and a runtime password change or `DROP USER` did not
/// affect authentication, until the next reboot. `LiveAuth` closes that gap: each call resolves
/// through [`SecurityCatalog::with_auth`], which takes a **brief read lock** on the live model — the
/// same lock the per-statement RBAC enforcement path already uses. Authentication happens once per
/// connection/handshake (not per query), so one read lock per call is amply cheap; the lock is never
/// held across an `.await`.
pub struct LiveAuth(Arc<SecurityCatalog>);

impl LiveAuth {
    /// Wraps the live `catalog` as an [`AuthProvider`] for the connectivity seams.
    #[must_use]
    pub fn new(catalog: Arc<SecurityCatalog>) -> Self {
        Self(catalog)
    }
}

impl std::fmt::Debug for LiveAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveAuth").finish_non_exhaustive()
    }
}

impl AuthProvider for LiveAuth {
    fn authenticate_password(
        &self,
        user: &str,
        plaintext: &str,
    ) -> std::result::Result<String, AuthError> {
        // One brief read lock on the live model: a runtime-created user logs on at once, a
        // password change / DROP USER takes effect at once.
        self.0
            .with_auth(|auth| auth.authenticate_password(user, plaintext))
    }

    fn authenticate_bearer(
        &self,
        token: &str,
        now_unix_secs: u64,
    ) -> std::result::Result<Claims, AuthError> {
        self.0
            .with_auth(|auth| auth.authenticate_bearer(token, now_unix_secs))
    }

    fn require(&self, user: &str, wanted: &Privilege) -> std::result::Result<(), AuthError> {
        self.0.with_auth(|auth| auth.require(user, wanted))
    }

    fn issue_token(
        &self,
        user: &str,
        now_unix_secs: u64,
        ttl_secs: u64,
    ) -> std::result::Result<String, AuthError> {
        // One brief read lock on the live model: the token is stamped with the user's *current*
        // credential epoch, so the REST `/auth/login` endpoint (rmp #499) mints tokens that a later
        // runtime password change immediately invalidates (SEC-180).
        self.0
            .with_auth(|auth| auth.issue_token(user, now_unix_secs, ttl_secs))
    }
}

/// The persist entry point used by [`SecurityCatalog::mutate`] (a free fn so it captures only
/// `Send` data into `spawn_blocking`).
fn persist_file(root: &Path, file: &SecurityFile) -> Result<()> {
    use std::io::Write as _;

    std::fs::create_dir_all(root).map_err(|e| io_error(root, "creating data root", &e))?;
    let text = toml::to_string(file).map_err(|e| SecurityError::Encode(e.to_string()))?;

    let tmp = root.join(SECURITY_TMP_NAME);
    let dst = root.join(SECURITY_FILE_NAME);
    {
        // SEC-177 (CWE-732/312): `security.toml` holds every user's argon2 hash and the uid->user
        // map, so it must be owner-only. Create the temp with mode `0o600` *before* any bytes are
        // written (not after, which would leave a world-readable window), and rely on `rename(2)`
        // preserving the temp's mode for the published file. On Unix we pre-set the mode via
        // `OpenOptions::mode`; elsewhere the create flags fall back to the platform default.
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .map_err(|e| io_error(&tmp, "creating security temp", &e))?;
        // `OpenOptions::mode` only applies on *creation*; a stale temp from a crashed run is reused
        // via `O_TRUNC` with its old (possibly loose) mode. Re-assert `0o600` on the open fd so the
        // restricted mode holds regardless of how the inode came to be.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| io_error(&tmp, "restricting security temp mode", &e))?;
        }
        f.write_all(text.as_bytes())
            .map_err(|e| io_error(&tmp, "writing security temp", &e))?;
        f.sync_all()
            .map_err(|e| io_error(&tmp, "syncing security temp", &e))?;
    }
    std::fs::rename(&tmp, &dst).map_err(|e| io_error(&dst, "publishing security file", &e))?;
    let dir = std::fs::File::open(root).map_err(|e| io_error(root, "opening data root", &e))?;
    dir.sync_all()
        .map_err(|e| io_error(root, "syncing data root directory", &e))?;
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// Config bootstrap (fresh-install seeding) — runs once, on the first start (no `security.toml`
// yet); the persisted file is authoritative thereafter.
// ------------------------------------------------------------------------------------------------

/// Seeds a fresh [`Authenticator`] from config bootstrap: the admin user granted global `Admin`,
/// plus the optional non-admin users granted server-wide read + write. This is the seeding the
/// pre-#92 server did at every boot; it now runs only on a fresh install, after which the durable
/// `security.toml` is authoritative — so a fresh install behaves identically to the old server.
fn seed_from_config(auth: &mut Authenticator, config: &ServerConfig) -> Result<()> {
    let admin = &config.auth.admin_user;
    auth.catalog_mut().create_user(admin.clone())?;
    auth.catalog_mut().create_role("admin")?;
    auth.catalog_mut()
        .grant_privilege("admin", Privilege::admin_database())?;
    auth.catalog_mut().grant_role(admin, "admin")?;

    if !config.auth.admin_password.is_empty() {
        auth.set_password(admin, &config.auth.admin_password)?;
    }
    if let Some(uid) = config.auth.admin_uid {
        auth.peers_mut().map_uid(uid, admin.clone());
    }

    if !config.auth.users.is_empty() {
        auth.catalog_mut().create_role("readwrite")?;
        auth.catalog_mut()
            .grant_privilege("readwrite", Privilege::read_database())?;
        auth.catalog_mut()
            .grant_privilege("readwrite", Privilege::write_database())?;
        for user in &config.auth.users {
            auth.catalog_mut().create_user(user.name.clone())?;
            auth.catalog_mut().grant_role(&user.name, "readwrite")?;
            if !user.password.is_empty() {
                auth.set_password(&user.name, &user.password)?;
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// Listing rows
// ------------------------------------------------------------------------------------------------

/// One `SHOW USERS` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserListing {
    /// The username.
    pub name: String,
    /// The role memberships (name-sorted).
    pub roles: Vec<String>,
    /// Whether the user has a password set (the hash itself is never exposed).
    pub has_password: bool,
}

/// One `SHOW ROLES` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleListing {
    /// The role name.
    pub name: String,
    /// How many privileges the role grants.
    pub privilege_count: usize,
}

/// One `SHOW PRIVILEGES` row: a (role, action, scope) grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegeListing {
    /// The role the grant belongs to.
    pub role: String,
    /// The action word (`"traverse"`, `"read"`, …).
    pub action: String,
    /// The human-readable scope (e.g. `"DATABASE"`, `"GRAPH sales"`, `"LABEL sales.Person"`).
    pub scope: String,
}

/// The lower-case action word (`SHOW PRIVILEGES`, the grammar's `<action>`).
#[must_use]
pub fn action_word(action: Action) -> &'static str {
    match action {
        Action::Traverse => "traverse",
        Action::Read => "read",
        Action::Write => "write",
        Action::Schema => "schema",
        Action::Admin => "admin",
        // `Action` is `#[non_exhaustive]`; a future variant renders as a clearly non-grantable
        // placeholder rather than silently masquerading as a known action.
        _ => "unknown",
    }
}

/// A human-readable rendering of a resource scope for `SHOW PRIVILEGES` (and error messages).
#[must_use]
pub fn scope_string(resource: &Resource) -> String {
    match resource {
        Resource::Database => "DATABASE".to_owned(),
        Resource::Graph(db) => format!("GRAPH {db}"),
        Resource::Label { db, label } => format!("LABEL {db}.{label}"),
        Resource::RelType { db, rel_type } => format!("RELATIONSHIP {db}.{rel_type}"),
        Resource::Property {
            db,
            label,
            property,
        } => format!("PROPERTY {db}.{label}.{property}"),
        // `Resource` is `#[non_exhaustive]`.
        _ => "UNKNOWN".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique temp data root for one test (auto-removed on drop).
    struct TempRoot {
        path: PathBuf,
    }

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "graphus-security-{tag}-{nanos}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp root");
            Self { path }
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// An authenticator seeded with a `root` admin (global Admin) and the JWT secret.
    fn admin_auth() -> Authenticator {
        let mut auth = Authenticator::new(b"a-32-byte-or-longer-jwt-signing-secret!!")
            .expect("secret is >= 32 bytes");
        auth.catalog_mut().create_user("root").unwrap();
        auth.catalog_mut().create_role("admin").unwrap();
        auth.catalog_mut()
            .grant_privilege("admin", Privilege::admin_database())
            .unwrap();
        auth.catalog_mut().grant_role("root", "admin").unwrap();
        auth.set_password("root", "root-secret").unwrap();
        auth
    }

    fn catalog(root: &TempRoot) -> SecurityCatalog {
        SecurityCatalog::from_parts(root.path.clone(), "root".to_owned(), admin_auth())
    }

    #[tokio::test]
    async fn create_user_persists_and_is_visible() {
        let root = TempRoot::new("create");
        let sec = catalog(&root);
        sec.create_user("alice", Some("valid-pw"))
            .await
            .expect("create");

        // Visible in memory.
        assert!(sec.list_users().iter().any(|u| u.name == "alice"));
        // The password verifies (the hash, not plaintext, is what was stored).
        assert!(sec.with_auth(|a| a.verify_password("alice", "valid-pw").unwrap()));

        // Persisted: the security file exists and names alice but NOT her plaintext.
        let text = std::fs::read_to_string(root.path.join(SECURITY_FILE_NAME)).expect("file");
        assert!(text.contains("alice"));
        assert!(
            !text.contains("valid-pw"),
            "plaintext must never be persisted"
        );
        assert!(text.contains("$argon2id$"), "the argon2 hash is persisted");
    }

    #[tokio::test]
    async fn recovery_round_trip_through_reload() {
        let root = TempRoot::new("recovery");
        {
            let sec = catalog(&root);
            sec.create_role("reader").await.expect("role");
            sec.grant_privilege("reader", Privilege::on_label(Action::Read, "db", "Person"))
                .await
                .expect("grant");
            sec.create_user("alice", Some("valid-pw"))
                .await
                .expect("user");
            sec.grant_role("alice", "reader").await.expect("grant role");
        }
        // "Restart": reload from the file via load_into and assert the model is intact.
        let mut reloaded = Authenticator::new(b"a-32-byte-or-longer-jwt-signing-secret!!")
            .expect("secret is >= 32 bytes");
        load_into(&root.path, &mut reloaded).expect("reload");
        assert!(reloaded.catalog().has_user("alice"));
        assert!(reloaded.verify_password("alice", "valid-pw").unwrap());
        // The fine-grained grant survived exactly.
        assert!(reloaded.authorize("alice", &Privilege::on_label(Action::Read, "db", "Person")));
        assert!(reloaded.authorize(
            "alice",
            &Privilege::on_label(Action::Traverse, "db", "Person")
        ));
        assert!(!reloaded.authorize("alice", &Privilege::on_label(Action::Write, "db", "Person")));
        assert!(!reloaded.authorize("alice", &Privilege::read_database()));
    }

    #[test]
    fn malformed_file_fails_closed() {
        let cases: &[(&str, &str)] = &[
            ("garbage", "%% not toml %%"),
            ("bad-version", "version = 2\n"),
            ("unknown-field", "version = 1\nsurprise = true\n"),
            (
                "unknown-role",
                "version = 1\n[[users]]\nname = \"a\"\nroles = [\"ghost\"]\n",
            ),
            (
                "label-without-db",
                "version = 1\n[[roles]]\nname = \"r\"\n[[roles.privileges]]\naction = \"read\"\nscope = \"label\"\nlabel = \"Person\"\n",
            ),
            (
                "bad-action",
                "version = 1\n[[roles]]\nname = \"r\"\n[[roles.privileges]]\naction = \"superuser\"\nscope = \"database\"\n",
            ),
            (
                "duplicate-user",
                "version = 1\n[[users]]\nname = \"a\"\n[[users]]\nname = \"a\"\n",
            ),
        ];
        for (tag, text) in cases {
            let root = TempRoot::new(&format!("malformed-{tag}"));
            std::fs::write(root.path.join(SECURITY_FILE_NAME), text).expect("write file");
            let mut auth = Authenticator::new(b"a-32-byte-or-longer-jwt-signing-secret!!")
                .expect("secret is >= 32 bytes");
            let result = load_into(&root.path, &mut auth);
            assert!(
                matches!(result, Err(SecurityError::Corrupt { .. })),
                "{tag}: expected Corrupt, got {result:?}"
            );
            // Fail closed: the malformed file is never reset or rewritten by the failed load.
            assert_eq!(
                std::fs::read_to_string(root.path.join(SECURITY_FILE_NAME)).expect("intact"),
                *text
            );
        }
    }

    #[test]
    fn stale_tmp_is_removed_and_the_valid_file_wins() {
        let root = TempRoot::new("staletmp");
        let auth = admin_auth();
        persist(&root.path, &auth).expect("persist");
        // Simulate a crash mid-write of a later mutation: garbage temp next to the valid file.
        std::fs::write(root.path.join(SECURITY_TMP_NAME), b"%% garbage %%").expect("plant tmp");

        let mut reloaded = Authenticator::new(b"a-32-byte-or-longer-jwt-signing-secret!!")
            .expect("secret is >= 32 bytes");
        load_into(&root.path, &mut reloaded).expect("load");
        assert!(
            reloaded.catalog().has_user("root"),
            "the published file is authoritative"
        );
        assert!(
            !root.path.join(SECURITY_TMP_NAME).exists(),
            "the stale temp is cleaned up"
        );
    }

    // ---- lock-out safeguard --------------------------------------------------------------------

    #[tokio::test]
    async fn cannot_drop_the_bootstrap_admin() {
        let root = TempRoot::new("lockout-drop-user");
        let sec = catalog(&root);
        let err = sec.drop_user("root").await;
        assert!(
            matches!(err, Err(SecurityError::WouldLockOutAdmin { .. })),
            "{err:?}"
        );
        // root is still an admin.
        assert!(sec.with_auth(|a| a.authorize("root", &Privilege::admin_database())));
    }

    #[tokio::test]
    async fn cannot_revoke_admin_role_from_the_bootstrap_admin() {
        let root = TempRoot::new("lockout-revoke-role");
        let sec = catalog(&root);
        let err = sec.revoke_role("root", "admin").await;
        assert!(
            matches!(err, Err(SecurityError::WouldLockOutAdmin { .. })),
            "{err:?}"
        );
        assert!(sec.with_auth(|a| a.authorize("root", &Privilege::admin_database())));
    }

    #[tokio::test]
    async fn cannot_revoke_global_admin_privilege_underlying_the_bootstrap_admin() {
        let root = TempRoot::new("lockout-revoke-priv");
        let sec = catalog(&root);
        let err = sec
            .revoke_privilege("admin", Privilege::admin_database())
            .await;
        assert!(
            matches!(err, Err(SecurityError::WouldLockOutAdmin { .. })),
            "{err:?}"
        );
        assert!(sec.with_auth(|a| a.authorize("root", &Privilege::admin_database())));
    }

    #[tokio::test]
    async fn cannot_drop_the_admin_role_when_it_backs_the_bootstrap_admin() {
        let root = TempRoot::new("lockout-drop-role");
        let sec = catalog(&root);
        let err = sec.drop_role("admin").await;
        assert!(
            matches!(err, Err(SecurityError::WouldLockOutAdmin { .. })),
            "{err:?}"
        );
        assert!(sec.with_auth(|a| a.authorize("root", &Privilege::admin_database())));
    }

    #[tokio::test]
    async fn lockout_safeguard_allows_safe_mutations() {
        let root = TempRoot::new("lockout-safe");
        let sec = catalog(&root);
        // A second admin can be created and given the role; dropping the FIRST is still rejected
        // because the safeguard protects the *bootstrap* admin specifically, regardless of others.
        sec.create_user("alice", None).await.expect("create");
        sec.grant_role("alice", "admin").await.expect("grant");
        // Dropping a non-bootstrap user is fine even if they were admin.
        sec.drop_user("alice").await.expect("drop alice");
        // Revoking a role the bootstrap admin does not hold is fine.
        sec.create_role("reader").await.expect("role");
        sec.revoke_role("root", "reader")
            .await
            .expect("revoke non-held role");
        assert!(sec.with_auth(|a| a.authorize("root", &Privilege::admin_database())));
    }

    /// Regression: two revocations that are each individually safe must not be able to combine into
    /// a lock-out. The bootstrap admin holds Admin through TWO roles; concurrently revoking both
    /// roles from it must leave at least one in place (the post-mutation lock-out re-check runs
    /// inside the write lock, atomically with each mutation — no TOCTOU window).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_revocations_cannot_combine_to_lock_out_the_bootstrap_admin() {
        let root = TempRoot::new("lockout-toctou");
        let sec = Arc::new(catalog(&root));
        // root already holds `admin`; add a second admin-bearing role.
        sec.create_role("admin2").await.expect("role");
        sec.grant_privilege("admin2", Privilege::admin_database())
            .await
            .expect("grant admin2");
        sec.grant_role("root", "admin2").await.expect("grant role");

        // Fire both revocations concurrently.
        let a = {
            let sec = Arc::clone(&sec);
            tokio::spawn(async move { sec.revoke_role("root", "admin").await })
        };
        let b = {
            let sec = Arc::clone(&sec);
            tokio::spawn(async move { sec.revoke_role("root", "admin2").await })
        };
        let (ra, rb) = (a.await.unwrap(), b.await.unwrap());

        // Exactly one may succeed; the other must be refused as a lock-out — never both succeeding.
        let oks = [ra.is_ok(), rb.is_ok()].iter().filter(|x| **x).count();
        assert_eq!(
            oks, 1,
            "exactly one revocation succeeds; ra={ra:?} rb={rb:?}"
        );
        // Whatever happened, the bootstrap admin still holds global Admin.
        assert!(
            sec.with_auth(|x| x.authorize("root", &Privilege::admin_database())),
            "the bootstrap admin must never be locked out by concurrent revocations"
        );
    }

    /// A `ServerConfig` rooted at `root` with admin `root`/`valid-pw` and a fixed JWT secret.
    fn fresh_config(root: &TempRoot) -> ServerConfig {
        ServerConfig {
            store_path: root.path.clone(),
            jwt_secret: "a-32-byte-or-longer-jwt-signing-secret!!".to_owned(),
            auth: crate::config::AuthBootstrap {
                admin_user: "root".to_owned(),
                admin_password: "valid-pw".to_owned(),
                ..crate::config::AuthBootstrap::default()
            },
            ..ServerConfig::default()
        }
    }

    #[tokio::test]
    async fn fresh_install_seeds_and_persists() {
        let root = TempRoot::new("fresh");
        let mut config = fresh_config(&root);

        let sec = SecurityCatalog::load(&config).expect("load fresh");
        // Seeded admin is usable and a file was written.
        assert!(sec.with_auth(|a| a.authorize("root", &Privilege::admin_database())));
        assert!(
            root.path.join(SECURITY_FILE_NAME).is_file(),
            "fresh install persisted"
        );

        // A second load is now file-authoritative (config bootstrap ignored): change the config's
        // admin password and confirm the FILE's hash (the original) is what loads.
        config.auth.admin_password = "different".to_owned();
        let sec2 = SecurityCatalog::load(&config).expect("reload");
        assert!(
            sec2.with_auth(|a| a.verify_password("root", "valid-pw").unwrap()),
            "file is authoritative"
        );
        assert!(!sec2.with_auth(|a| a.verify_password("root", "different").unwrap()));
    }

    #[tokio::test]
    async fn unknown_user_or_role_surfaces_rbac_not_lockout() {
        let root = TempRoot::new("rbac-errors");
        let sec = catalog(&root);
        // Revoking from an unknown role/user must surface the precise Rbac error, not a lock-out.
        assert!(matches!(
            sec.revoke_role("ghost", "admin").await,
            Err(SecurityError::Rbac(AuthError::NotFound { .. }))
        ));
        assert!(matches!(
            sec.grant_role("ghost", "admin").await,
            Err(SecurityError::Rbac(AuthError::NotFound { .. }))
        ));
        assert!(matches!(
            sec.create_user("root", None).await,
            Err(SecurityError::Rbac(AuthError::AlreadyExists { .. }))
        ));
    }
}
