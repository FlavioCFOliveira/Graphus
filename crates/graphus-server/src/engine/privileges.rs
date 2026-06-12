//! The server-side [`PrivilegeOracle`] implementation that resolves a principal's fine-grained RBAC
//! against the live [`SecurityCatalog`] for one statement (rmp #93, completing #68).
//!
//! [`EffectivePrivileges`] is the bridge between `graphus-server`'s security model (the live
//! [`SecurityCatalog`] / `graphus_auth` RBAC) and `graphus-cypher`'s auth-agnostic enforcement seam
//! ([`graphus_cypher::PrivilegeOracle`] / [`graphus_cypher::AuthorizedGraph`]). The query engine
//! depends only on the boolean predicates; this type answers them by asking the catalog.
//!
//! # Resolved once per statement, against the *live* catalog
//!
//! One [`EffectivePrivileges`] is built per statement (in the connection seams, where the
//! authenticated principal and the resolved session database are both known) and handed to the
//! engine. It captures:
//!
//! - an `Arc<SecurityCatalog>` (the live, mutable RBAC model — **not** a startup snapshot), so a
//!   `GRANT`/`REVOKE` an admin applies takes effect on the principal's **next** statement (the very
//!   property #92 deferred to #93);
//! - the principal name and the canonical database the session is pinned to;
//! - a precomputed `unrestricted` flag (admin or no-principal — see below).
//!
//! Each predicate performs a brief read-locked [`SecurityCatalog::with_auth`] + one
//! [`graphus_auth::Authenticator::authorize`] over the relevant [`Privilege`]. The graded
//! `Traverse ⊂ Read ⊂ Write` chain and the `Database ⊇ Graph ⊇ {Label,RelType,Property}` containment
//! are resolved **inside** `authorize` (`graphus_auth::Privilege::implies`), so this type only has to
//! ask the narrowest question the operation needs and the catalog folds in any broader grant.
//!
//! # The unrestricted fast path
//!
//! `unrestricted` is `true` — making [`graphus_cypher::AuthorizedGraph`] a transparent pass-through —
//! when **either**:
//!
//! - the statement has **no principal** (the internal / TCK / direct-test path; no identity to
//!   restrict, so behaviour is byte-identical to a server without RBAC — this is what keeps the TCK
//!   ratchet from regressing), **or**
//! - the principal holds global `Admin` (`Admin` on [`graphus_auth::Resource::Database`]) — an administrator sees
//!   and writes everything, with no per-row filtering overhead.
//!
//! Both are computed once at construction, so the hot predicate path is a single bool check on the
//! unrestricted path and one `authorize` call otherwise.
//!
//! # The empty-label probe (`""`)
//!
//! For an **unlabelled** node, [`graphus_cypher::AuthorizedGraph`] probes write authority with an
//! empty label name (`""`). There is no `Label { label: "" }` grant, so this maps to the
//! **database-wide** write scope: an unlabelled node may be written only by a principal holding
//! `Write` on the graph/database (never by a mere label-scoped grant). [`graphus_auth::Resource::Graph`] for the
//! session database expresses exactly that, and `Database`-wide grants cover it through containment.

use std::sync::Arc;

use graphus_auth::{Action, Privilege};
use graphus_cypher::PrivilegeOracle;

use crate::security::SecurityCatalog;

/// One statement's resolved fine-grained privileges for a principal + session database, answering
/// the [`PrivilegeOracle`] predicates against the **live** [`SecurityCatalog`] (rmp #93).
///
/// Cheap to build (an `Arc` clone + two `String`s + one `authorize` for the unrestricted check) and
/// cheap to query (a brief read lock + one `authorize` per predicate, short-circuited on the
/// unrestricted path). `Send + Sync` (the catalog is `Arc<SecurityCatalog>`), so it crosses the
/// engine's command channel to the engine thread unchanged.
#[derive(Clone)]
pub struct EffectivePrivileges {
    /// The live RBAC catalog. Every predicate resolves through `with_auth` so a runtime grant/revoke
    /// is reflected on the next statement — never a stale startup snapshot.
    security: Arc<SecurityCatalog>,
    /// The authenticated principal, or `None` for the unrestricted internal/TCK/direct path.
    principal: Option<String>,
    /// The canonical (lowercase) database the session is pinned to — every scope is built against it.
    database: String,
    /// Precomputed at construction: admin or no-principal ⇒ pass-through (no filtering).
    unrestricted: bool,
}

impl EffectivePrivileges {
    /// Resolves the effective privileges for `principal` (or `None` = unrestricted) over `database`,
    /// reading the live `security` catalog.
    ///
    /// The `unrestricted` flag is computed once here: `true` when there is no principal, or when the
    /// principal holds global `Admin`. A `None` principal is the internal / TCK / direct path, which
    /// must behave exactly as a server without RBAC (so the TCK ratchet does not regress).
    #[must_use]
    pub fn resolve(
        security: Arc<SecurityCatalog>,
        principal: Option<&str>,
        database: impl Into<String>,
    ) -> Self {
        let database = database.into();
        let unrestricted = match principal {
            // No identity to restrict: the unrestricted internal/TCK/direct path.
            None => true,
            // A global admin bypasses all filtering. Resolved against the live catalog.
            Some(user) => {
                security.with_auth(|auth| auth.authorize(user, &Privilege::admin_database()))
            }
        };
        Self {
            security,
            principal: principal.map(str::to_owned),
            database,
            unrestricted,
        }
    }

    /// Whether `self.principal` is authorized for `wanted` against the live catalog. Returns `false`
    /// (deny-by-default) when there is no principal — but every caller is guarded by the
    /// `unrestricted` short-circuit, so this is only reached on the restricted (principal-present)
    /// path.
    fn authorize(&self, wanted: &Privilege) -> bool {
        match &self.principal {
            Some(user) => self.security.with_auth(|auth| auth.authorize(user, wanted)),
            None => false,
        }
    }
}

impl PrivilegeOracle for EffectivePrivileges {
    fn is_unrestricted(&self) -> bool {
        self.unrestricted
    }

    fn can_traverse_label(&self, label: &str) -> bool {
        self.authorize(&Privilege::on_label(
            Action::Traverse,
            self.database.clone(),
            label,
        ))
    }

    fn can_read_property(&self, label: &str, property: &str) -> bool {
        self.authorize(&Privilege::on_property(
            Action::Read,
            self.database.clone(),
            label,
            property,
        ))
    }

    fn can_traverse_rel_type(&self, rel_type: &str) -> bool {
        self.authorize(&Privilege::on_rel_type(
            Action::Traverse,
            self.database.clone(),
            rel_type,
        ))
    }

    fn can_read_rel_property(&self, rel_type: &str, _property: &str) -> bool {
        // Relationship properties are scoped to the relationship type (`Resource::RelType`); the model
        // has no per-relationship-property leaf, so Read on the type (or broader) authorizes reading
        // any of its properties. Keyed by type; the property name is accepted for symmetry with the
        // node side and forward compatibility.
        self.authorize(&Privilege::on_rel_type(
            Action::Read,
            self.database.clone(),
            rel_type,
        ))
    }

    fn can_write_label(&self, label: &str) -> bool {
        if label.is_empty() {
            // The empty-label probe: an unlabelled node's write authority is database/graph-wide.
            return self.authorize(&Privilege::on_graph(Action::Write, self.database.clone()));
        }
        self.authorize(&Privilege::on_label(
            Action::Write,
            self.database.clone(),
            label,
        ))
    }

    fn can_write_rel_type(&self, rel_type: &str) -> bool {
        self.authorize(&Privilege::on_rel_type(
            Action::Write,
            self.database.clone(),
            rel_type,
        ))
    }

    fn can_write_property(&self, label: &str, property: &str) -> bool {
        if label.is_empty() {
            // Unlabelled-node property write: gated by the database/graph-wide write grant.
            return self.authorize(&Privilege::on_graph(Action::Write, self.database.clone()));
        }
        self.authorize(&Privilege::on_property(
            Action::Write,
            self.database.clone(),
            label,
            property,
        ))
    }

    fn can_write_rel_property(&self, rel_type: &str, _property: &str) -> bool {
        // As with reads, relationship properties are rel-type-scoped: Write on the type authorizes
        // writing its properties.
        self.authorize(&Privilege::on_rel_type(
            Action::Write,
            self.database.clone(),
            rel_type,
        ))
    }
}

impl std::fmt::Debug for EffectivePrivileges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectivePrivileges")
            .field("principal", &self.principal)
            .field("database", &self.database)
            .field("unrestricted", &self.unrestricted)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_auth::Authenticator;

    /// A unique temp data root for one test (auto-removed on drop), for the catalogs that persist.
    struct TempRoot {
        path: std::path::PathBuf,
    }

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("graphus-priv-{tag}-{nanos}-{}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp root");
            Self { path }
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Builds an [`Authenticator`] with an admin `root` and an `alice` whose `custom` role is granted
    /// exactly `grants`.
    fn auth_with(grants: &[Privilege]) -> Authenticator {
        let mut auth = Authenticator::new(b"a-32-byte-or-longer-jwt-signing-secret!!");
        auth.catalog_mut().create_user("root").unwrap();
        auth.catalog_mut().create_role("admin").unwrap();
        auth.catalog_mut()
            .grant_privilege("admin", Privilege::admin_database())
            .unwrap();
        auth.catalog_mut().grant_role("root", "admin").unwrap();

        auth.catalog_mut().create_user("alice").unwrap();
        auth.catalog_mut().create_role("custom").unwrap();
        for g in grants {
            auth.catalog_mut()
                .grant_privilege("custom", g.clone())
                .unwrap();
        }
        auth.catalog_mut().grant_role("alice", "custom").unwrap();
        auth
    }

    /// A `SecurityCatalog` (no persistence until first mutation) carrying [`auth_with`]'s model.
    fn catalog_with(grants: &[Privilege]) -> Arc<SecurityCatalog> {
        Arc::new(SecurityCatalog::from_parts(
            std::env::temp_dir().join("graphus-priv-test-unused"),
            "root".to_owned(),
            auth_with(grants),
        ))
    }

    #[test]
    fn no_principal_is_unrestricted() {
        let cat = catalog_with(&[]);
        let p = EffectivePrivileges::resolve(cat, None, "db");
        assert!(p.is_unrestricted());
    }

    #[test]
    fn global_admin_is_unrestricted() {
        let cat = catalog_with(&[]);
        let p = EffectivePrivileges::resolve(cat, Some("root"), "db");
        assert!(p.is_unrestricted());
    }

    #[test]
    fn restricted_principal_is_not_unrestricted_and_denies_by_default() {
        let cat = catalog_with(&[]);
        let p = EffectivePrivileges::resolve(cat, Some("alice"), "db");
        assert!(!p.is_unrestricted());
        // Deny-by-default: nothing granted.
        assert!(!p.can_traverse_label("Person"));
        assert!(!p.can_read_property("Person", "name"));
        assert!(!p.can_traverse_rel_type("KNOWS"));
        assert!(!p.can_write_label("Person"));
    }

    #[test]
    fn label_read_grant_implies_traverse_and_property_read() {
        // Read on Label db.Person -> traverse Person + read any Person property (graded chain +
        // Label ⊇ Property containment, resolved inside `authorize`).
        let cat = catalog_with(&[Privilege::on_label(Action::Read, "db", "Person")]);
        let p = EffectivePrivileges::resolve(cat, Some("alice"), "db");
        assert!(p.can_traverse_label("Person"));
        assert!(p.can_read_property("Person", "name"));
        assert!(p.can_read_property("Person", "anything")); // label grant covers all its props
        // ...but not write, and not a different label.
        assert!(!p.can_write_label("Person"));
        assert!(!p.can_traverse_label("Company"));
    }

    #[test]
    fn property_grant_is_the_leaf_scope() {
        // Read on Property db.Person.name -> read `name` only; does NOT grant traverse of the label
        // (a property grant is narrower than the label) nor reading another property.
        let cat = catalog_with(&[Privilege::on_property(Action::Read, "db", "Person", "name")]);
        let p = EffectivePrivileges::resolve(cat, Some("alice"), "db");
        assert!(p.can_read_property("Person", "name"));
        assert!(!p.can_read_property("Person", "age"));
        // A property grant does not by itself grant Traverse on the label.
        assert!(!p.can_traverse_label("Person"));
    }

    #[test]
    fn graph_write_grant_covers_unlabelled_and_all_labels() {
        // Write on the whole graph -> write any label, any property, any rel type, AND the empty-label
        // (unlabelled-node) probe.
        let cat = catalog_with(&[Privilege::on_graph(Action::Write, "db")]);
        let p = EffectivePrivileges::resolve(cat, Some("alice"), "db");
        assert!(p.can_write_label("Person"));
        assert!(p.can_write_label("")); // unlabelled-node probe -> graph-wide
        assert!(p.can_write_property("Person", "name"));
        assert!(p.can_write_property("", "k")); // unlabelled property -> graph-wide
        assert!(p.can_write_rel_type("KNOWS"));
        assert!(p.can_write_rel_property("KNOWS", "since"));
        // Write implies read/traverse (graded chain).
        assert!(p.can_traverse_label("Person"));
        assert!(p.can_read_property("Person", "name"));
    }

    #[test]
    fn label_write_grant_does_not_authorize_unlabelled_probe() {
        // A mere label-scoped Write must NOT satisfy the empty-label (database-wide) probe.
        let cat = catalog_with(&[Privilege::on_label(Action::Write, "db", "Person")]);
        let p = EffectivePrivileges::resolve(cat, Some("alice"), "db");
        assert!(p.can_write_label("Person"));
        assert!(!p.can_write_label("")); // not graph-wide
        assert!(!p.can_write_property("", "k"));
    }

    #[test]
    fn scopes_are_pinned_to_the_session_database() {
        // A grant on db "other" says nothing about a session pinned to "db".
        let cat = catalog_with(&[Privilege::on_label(Action::Read, "other", "Person")]);
        let p = EffectivePrivileges::resolve(cat, Some("alice"), "db");
        assert!(!p.can_traverse_label("Person"));
        // ...and the same principal on the "other" database does see it.
        let cat2 = catalog_with(&[Privilege::on_label(Action::Read, "other", "Person")]);
        let p2 = EffectivePrivileges::resolve(cat2, Some("alice"), "other");
        assert!(p2.can_traverse_label("Person"));
    }

    #[tokio::test]
    async fn live_grant_takes_effect_on_the_next_resolve() {
        // The oracle reads the LIVE catalog: a grant applied (via the real admin mutation API) after
        // one resolve is visible to the next — and to the SAME oracle instance (it holds the Arc, not
        // a snapshot). This is the property #92 deferred to #93.
        let root = TempRoot::new("live-grant");
        let cat = Arc::new(SecurityCatalog::from_parts(
            root.path.clone(),
            "root".to_owned(),
            auth_with(&[]),
        ));
        let before = EffectivePrivileges::resolve(Arc::clone(&cat), Some("alice"), "db");
        assert!(!before.can_traverse_label("Person"));

        // Grant Read on the label through the live catalog (exactly an admin `GRANT` command).
        cat.grant_privilege("custom", Privilege::on_label(Action::Read, "db", "Person"))
            .await
            .expect("grant");

        // A freshly-resolved oracle sees it...
        let after = EffectivePrivileges::resolve(Arc::clone(&cat), Some("alice"), "db");
        assert!(after.can_traverse_label("Person"));
        // ...and so does the instance that existed *before* the grant (it queries the live Arc).
        assert!(before.can_traverse_label("Person"));
    }
}
