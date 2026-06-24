//! The server-side [`PrivilegeOracle`] implementation that resolves a principal's fine-grained RBAC
//! against the live [`SecurityCatalog`] for one statement (rmp #93, completing #68).
//!
//! [`EffectivePrivileges`] is the bridge between `graphus-server`'s security model (the live
//! [`SecurityCatalog`] / `graphus_auth` RBAC) and `graphus-cypher`'s auth-agnostic enforcement seam
//! ([`graphus_cypher::PrivilegeOracle`] / [`graphus_cypher::AuthorizedGraph`]). The query engine
//! depends only on the boolean predicates; this type answers them by asking the catalog.
//!
//! # Resolved once per statement, as a consistent snapshot (rmp #320)
//!
//! One [`EffectivePrivileges`] is built per statement (in the connection seams, where the
//! authenticated principal and the resolved session database are both known) and handed to the
//! engine. At construction it takes the live security model's read lock **exactly once** and captures:
//!
//! - the principal's **effective privilege set** — the deduplicated union of every grant of every
//!   role the principal holds ([`graphus_auth::Catalog::effective_privileges`]) — as an owned,
//!   immutable snapshot. A torn read across a concurrent `GRANT`/`REVOKE` is impossible: the union is
//!   collected under a single read guard;
//! - the canonical database the session is pinned to;
//! - a precomputed `unrestricted` flag (admin or no-principal — see below), decided under that same
//!   guard.
//!
//! Because the snapshot is taken at statement start, a `GRANT`/`REVOKE` an admin applies takes effect
//! on the principal's **next** statement, never mid-statement — the serializable-snapshot semantics
//! fine-grained RBAC requires (a single statement sees one consistent privilege view; #92/#93 deferred
//! the *liveness* property, which is preserved because a fresh snapshot is taken for each statement).
//!
//! Each predicate then answers **against the owned snapshot**: no lock, and — via the borrowed
//! [`graphus_auth::ResourceRef`] / [`graphus_auth::Privilege::implies_ref`] probe — no per-row
//! allocation. The graded `Traverse ⊂ Read ⊂ Write` chain and the
//! `Database ⊇ Graph ⊇ {Label,RelType,Property}` containment are resolved inside `implies_ref`
//! (identical to `implies`), so this type asks only the narrowest question the operation needs and the
//! snapshot folds in any broader grant.
//!
//! # Per-statement memoization (rmp #320)
//!
//! A restricted wide `MATCH` of N nodes × L labels × P properties probes the same `(label)` and
//! `(label, property)` names over and over. Each read-side predicate memoizes its answer by name in a
//! small per-statement [`std::collections::HashMap`] (behind a [`std::sync::Mutex`] so the type stays
//! `Send + Sync`), so the privilege-set walk runs **once per distinct name**, not once per probe.
//! The map uses the default SipHash hasher deliberately: the keys are client-supplied label / property
//! / relationship-type names (SEC-210 — never an attacker-tunable FxHash). The cache is **pure**: a
//! miss computes the real decision and a hit replays it, so it can never default-allow (fail-closed is
//! preserved). Its lifetime is exactly one statement (it lives on the per-statement oracle).
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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use graphus_auth::{Action, Privilege, ResourceRef};
use graphus_cypher::PrivilegeOracle;

use crate::security::SecurityCatalog;

/// One statement's resolved fine-grained privileges for a principal + session database, answering
/// the [`PrivilegeOracle`] predicates against the **live** [`SecurityCatalog`] (rmp #93).
///
/// Cheap to build (an `Arc` clone + two `String`s + one `authorize` for the unrestricted check) and
/// cheap to query (a brief read lock + one `authorize` per predicate, short-circuited on the
/// unrestricted path). `Send + Sync` (the catalog is `Arc<SecurityCatalog>`), so it crosses the
/// engine's command channel to the engine thread unchanged.
/// One statement's resolved fine-grained privileges (see the module docs).
///
/// `Clone` is hand-written rather than derived: the [`Mutex`]-guarded memo cannot be derive-cloned,
/// and a clone (the engine makes one per batch step to move the oracle into the per-step
/// [`graphus_cypher::AuthorizedGraph`]) carries the same `Arc`-shared snapshot — the decision input
/// is identical — while the memo is a pure local cache that is simply re-snapshotted. The clone is
/// the **same statement's** oracle, never a cross-statement one.
pub struct EffectivePrivileges {
    /// The principal's **effective privilege set**, snapshotted under a single read lock at statement
    /// start: the deduplicated union of every grant of every role the principal holds. Empty on the
    /// unrestricted path (never consulted there) and for a principal with no grants (deny-by-default).
    /// Owned + immutable, so every predicate answers lock-free against a consistent view.
    snapshot: Arc<[Privilege]>,
    /// The canonical (lowercase) database the session is pinned to — every scope is probed against it.
    database: String,
    /// Precomputed at construction (under the same read guard as the snapshot): admin or no-principal
    /// ⇒ pass-through (no filtering).
    unrestricted: bool,
    /// Per-statement memo of the read-side predicates, keyed by name so the snapshot walk runs once
    /// per distinct name rather than once per probe (rmp #320). `Mutex` keeps the type `Send + Sync`;
    /// the oracle is used single-threaded per dispatch, so the lock is uncontended. SipHash (the
    /// default) is deliberate: the keys are client-supplied names (SEC-210).
    memo: Mutex<Memo>,
}

/// The per-statement read-side memo (rmp #320). Each map caches the boolean decision for a distinct
/// name (or `(label, property)` / `(rel_type, property)` pair). Pure: a present entry is a previously
/// computed real decision, replayed verbatim — never a default.
#[derive(Default)]
struct Memo {
    /// `can_traverse_label(label)` by label name.
    traverse_label: HashMap<String, bool>,
    /// `can_read_property(label, property)` keyed label → property → decision. Two-level so a hit
    /// looks up by borrowed `&str` at each level (`String: Borrow<str>`), allocating nothing.
    read_property: HashMap<String, HashMap<String, bool>>,
    /// `can_traverse_rel_type(rel_type)` by rel-type name.
    traverse_rel_type: HashMap<String, bool>,
    /// `can_read_rel_property(rel_type, _)` by rel-type name (rel properties are rel-type-scoped).
    read_rel_type: HashMap<String, bool>,
}

impl Clone for EffectivePrivileges {
    fn clone(&self) -> Self {
        // Carry the same `Arc`-shared snapshot (the decision input is byte-identical) and the same
        // database + unrestricted flag. The memo is copied so a per-batch-step clone retains the
        // distinct-name caching already paid for; it is a pure cache, so copying or emptying it would
        // both be correct.
        let memo = self.memo.lock().unwrap_or_else(|e| e.into_inner());
        Self {
            snapshot: Arc::clone(&self.snapshot),
            database: self.database.clone(),
            unrestricted: self.unrestricted,
            memo: Mutex::new(Memo {
                traverse_label: memo.traverse_label.clone(),
                read_property: memo.read_property.clone(),
                traverse_rel_type: memo.traverse_rel_type.clone(),
                read_rel_type: memo.read_rel_type.clone(),
            }),
        }
    }
}

impl EffectivePrivileges {
    /// Resolves the effective privileges for `principal` (or `None` = unrestricted) over `database`,
    /// taking the live `security` catalog's read lock **exactly once** to capture a consistent
    /// snapshot of the principal's privilege union (rmp #320).
    ///
    /// The `unrestricted` flag is decided here under the same guard: `true` when there is no principal,
    /// or when the principal holds global `Admin`. A `None` principal is the internal / TCK / direct
    /// path, which must behave exactly as a server without RBAC (so the TCK ratchet does not regress);
    /// no snapshot is taken there (it is never consulted).
    #[must_use]
    pub fn resolve(
        security: Arc<SecurityCatalog>,
        principal: Option<&str>,
        database: impl Into<String>,
    ) -> Self {
        let database = database.into();
        // ONE read guard: decide unrestricted AND capture the privilege snapshot atomically, so the
        // two can never disagree and the snapshot can never be torn by a concurrent GRANT/REVOKE.
        let (unrestricted, snapshot): (bool, Arc<[Privilege]>) = match principal {
            // No identity to restrict: the unrestricted internal/TCK/direct path. No snapshot needed.
            None => (true, Arc::from([])),
            Some(user) => security.with_auth(|auth| {
                let catalog = auth.catalog();
                if catalog.authorize(user, &Privilege::admin_database()) {
                    // A global admin bypasses all filtering; no per-element snapshot is consulted.
                    (true, Arc::from([]))
                } else {
                    // Restricted: snapshot the principal's effective privilege union under this guard.
                    let set = catalog.effective_privileges(user);
                    (false, set.into_iter().collect())
                }
            }),
        };
        Self {
            snapshot,
            database,
            unrestricted,
            memo: Mutex::new(Memo::default()),
        }
    }

    /// Whether the snapshot grants `action` over the borrowed `resource` — the lock-free,
    /// allocation-free decision function every predicate composes. Deny-by-default: a request implied
    /// by no captured privilege returns `false`. Identical to
    /// `authorize(&Privilege::new(action, owned_resource))` against the live catalog at snapshot time
    /// (proven by the auth-crate `implies_ref`/`effective_privileges` oracle tests).
    fn grants(&self, action: Action, resource: &ResourceRef<'_>) -> bool {
        self.snapshot
            .iter()
            .any(|granted| granted.implies_ref(action, resource))
    }
}

impl PrivilegeOracle for EffectivePrivileges {
    fn is_unrestricted(&self) -> bool {
        self.unrestricted
    }

    fn can_traverse_label(&self, label: &str) -> bool {
        let mut memo = self.memo.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&hit) = memo.traverse_label.get(label) {
            return hit;
        }
        let decision = self.grants(
            Action::Traverse,
            &ResourceRef::Label {
                db: &self.database,
                label,
            },
        );
        memo.traverse_label.insert(label.to_owned(), decision);
        decision
    }

    fn can_read_property(&self, label: &str, property: &str) -> bool {
        let mut memo = self.memo.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&hit) = memo.read_property.get(label).and_then(|m| m.get(property)) {
            return hit;
        }
        let decision = self.grants(
            Action::Read,
            &ResourceRef::Property {
                db: &self.database,
                label,
                property,
            },
        );
        memo.read_property
            .entry(label.to_owned())
            .or_default()
            .insert(property.to_owned(), decision);
        decision
    }

    fn can_traverse_rel_type(&self, rel_type: &str) -> bool {
        let mut memo = self.memo.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&hit) = memo.traverse_rel_type.get(rel_type) {
            return hit;
        }
        let decision = self.grants(
            Action::Traverse,
            &ResourceRef::RelType {
                db: &self.database,
                rel_type,
            },
        );
        memo.traverse_rel_type.insert(rel_type.to_owned(), decision);
        decision
    }

    fn can_read_rel_property(&self, rel_type: &str, _property: &str) -> bool {
        // Relationship properties are scoped to the relationship type (`Resource::RelType`); the model
        // has no per-relationship-property leaf, so Read on the type (or broader) authorizes reading
        // any of its properties. Keyed (and memoized) by type; the property name is accepted for
        // symmetry with the node side and forward compatibility.
        let mut memo = self.memo.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&hit) = memo.read_rel_type.get(rel_type) {
            return hit;
        }
        let decision = self.grants(
            Action::Read,
            &ResourceRef::RelType {
                db: &self.database,
                rel_type,
            },
        );
        memo.read_rel_type.insert(rel_type.to_owned(), decision);
        decision
    }

    fn can_write_label(&self, label: &str) -> bool {
        if label.is_empty() {
            // The empty-label probe: an unlabelled node's write authority is database/graph-wide.
            return self.grants(Action::Write, &ResourceRef::Graph(&self.database));
        }
        self.grants(
            Action::Write,
            &ResourceRef::Label {
                db: &self.database,
                label,
            },
        )
    }

    fn can_write_rel_type(&self, rel_type: &str) -> bool {
        self.grants(
            Action::Write,
            &ResourceRef::RelType {
                db: &self.database,
                rel_type,
            },
        )
    }

    fn can_write_property(&self, label: &str, property: &str) -> bool {
        if label.is_empty() {
            // Unlabelled-node property write: gated by the database/graph-wide write grant.
            return self.grants(Action::Write, &ResourceRef::Graph(&self.database));
        }
        self.grants(
            Action::Write,
            &ResourceRef::Property {
                db: &self.database,
                label,
                property,
            },
        )
    }

    fn can_write_rel_property(&self, rel_type: &str, _property: &str) -> bool {
        // As with reads, relationship properties are rel-type-scoped: Write on the type authorizes
        // writing its properties.
        self.grants(
            Action::Write,
            &ResourceRef::RelType {
                db: &self.database,
                rel_type,
            },
        )
    }
}

impl std::fmt::Debug for EffectivePrivileges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectivePrivileges")
            .field("database", &self.database)
            .field("unrestricted", &self.unrestricted)
            .field("snapshot_len", &self.snapshot.len())
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
        let mut auth = Authenticator::new(b"a-32-byte-or-longer-jwt-signing-secret!!")
            .expect("fixture secret is >= 32 bytes");
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
    async fn live_grant_applies_on_the_next_statement_not_the_current_one() {
        // Per-statement snapshot semantics (rmp #320): `resolve` captures the principal's effective
        // privileges under ONE read lock at statement start. A grant an admin applies mid-session is
        // therefore visible to the principal's NEXT statement (a fresh `resolve`), but NOT to the
        // statement already in flight (its snapshot was frozen) — the serializable-snapshot view
        // fine-grained RBAC requires. (Liveness across statements is preserved: each statement
        // re-snapshots the live catalog, so #92's deferred property still holds.)
        let root = TempRoot::new("live-grant");
        let cat = Arc::new(SecurityCatalog::from_parts(
            root.path.clone(),
            "root".to_owned(),
            auth_with(&[]),
        ));
        // The statement already in flight: snapshotted before the grant -> denied.
        let in_flight = EffectivePrivileges::resolve(Arc::clone(&cat), Some("alice"), "db");
        assert!(!in_flight.can_traverse_label("Person"));

        // Grant Read on the label through the live catalog (exactly an admin `GRANT` command).
        cat.grant_privilege("custom", Privilege::on_label(Action::Read, "db", "Person"))
            .await
            .expect("grant");

        // The NEXT statement (a fresh resolve) sees the grant...
        let next = EffectivePrivileges::resolve(Arc::clone(&cat), Some("alice"), "db");
        assert!(next.can_traverse_label("Person"));
        // ...but the in-flight statement's snapshot is isolated: it must STILL deny (no mid-statement
        // privilege change — the required, fail-safe semantics).
        assert!(
            !in_flight.can_traverse_label("Person"),
            "a mid-session grant must not change the decision of a statement already in flight"
        );
    }

    #[tokio::test]
    async fn live_revoke_applies_on_the_next_statement_not_the_current_one() {
        // The fail-CLOSED direction of the snapshot rule: a REVOKE applied mid-session must not be
        // observable to the statement already in flight (which keeps its frozen view), but must deny on
        // the next statement. (Tightening on the next statement is the security-relevant direction;
        // proven here end-to-end through the real revoke mutation API.)
        let root = TempRoot::new("live-revoke");
        let cat = Arc::new(SecurityCatalog::from_parts(
            root.path.clone(),
            "root".to_owned(),
            auth_with(&[Privilege::on_label(Action::Read, "db", "Person")]),
        ));
        let in_flight = EffectivePrivileges::resolve(Arc::clone(&cat), Some("alice"), "db");
        assert!(in_flight.can_traverse_label("Person"));

        cat.revoke_privilege("custom", Privilege::on_label(Action::Read, "db", "Person"))
            .await
            .expect("revoke");

        // Next statement: denied. In-flight statement: keeps its (now-stale) snapshot for consistency.
        let next = EffectivePrivileges::resolve(Arc::clone(&cat), Some("alice"), "db");
        assert!(!next.can_traverse_label("Person"));
        assert!(in_flight.can_traverse_label("Person"));
    }

    #[test]
    fn memo_replays_the_same_decision_and_caches_per_distinct_name() {
        // The per-statement memo is a PURE cache: repeated probes of the same name return the same
        // decision the first probe computed (fail-closed — a miss computes the real answer, a hit
        // replays it, never a default). Drive each read-side predicate twice and assert stability.
        let cat = catalog_with(&[
            Privilege::on_label(Action::Read, "db", "Person"),
            Privilege::on_rel_type(Action::Read, "db", "KNOWS"),
        ]);
        let p = EffectivePrivileges::resolve(cat, Some("alice"), "db");

        // Granted names: stable `true` across repeats.
        assert!(p.can_traverse_label("Person"));
        assert!(p.can_traverse_label("Person"));
        assert!(p.can_read_property("Person", "name"));
        assert!(p.can_read_property("Person", "name"));
        assert!(p.can_traverse_rel_type("KNOWS"));
        assert!(p.can_traverse_rel_type("KNOWS"));
        assert!(p.can_read_rel_property("KNOWS", "since"));
        assert!(p.can_read_rel_property("KNOWS", "since"));

        // A Person label-Read grant covers ALL Person properties (label ⊇ property), so any Person
        // property reads true and stays true across repeats.
        assert!(p.can_read_property("Person", "any_person_prop"));
        assert!(p.can_read_property("Person", "any_person_prop"));
        // Denied names: stable `false` across repeats (a cached deny is still a deny).
        assert!(!p.can_traverse_label("Company"));
        assert!(!p.can_traverse_label("Company"));
        // A different label's property is denied and stays denied.
        assert!(!p.can_read_property("Company", "name"));
        assert!(!p.can_read_property("Company", "name"));
    }

    #[test]
    fn memo_decision_matches_the_uncached_snapshot_decision() {
        // For every read-side predicate, the memoized answer must equal a freshly-resolved oracle's
        // first (uncached) answer for the same name — the cache never changes the decision.
        let grants = [
            Privilege::on_label(Action::Read, "db", "Person"),
            Privilege::on_property(Action::Read, "db", "Doc", "title"),
        ];
        let cases: &[(&str, &str)] = &[
            ("Person", "name"),
            ("Person", "anything"),
            ("Doc", "title"),
            ("Doc", "body"),
            ("Secret", "x"),
        ];
        for (label, prop) in cases {
            // Fresh oracle -> first (uncached) decision.
            let fresh = EffectivePrivileges::resolve(catalog_with(&grants), Some("alice"), "db");
            let uncached_trav = fresh.can_traverse_label(label);
            let uncached_read = fresh.can_read_property(label, prop);

            // A second oracle, probed twice (warm cache on the second), must agree on both probes.
            let warm = EffectivePrivileges::resolve(catalog_with(&grants), Some("alice"), "db");
            let _ = warm.can_traverse_label(label);
            let _ = warm.can_read_property(label, prop);
            assert_eq!(warm.can_traverse_label(label), uncached_trav, "{label}");
            assert_eq!(
                warm.can_read_property(label, prop),
                uncached_read,
                "{label}.{prop}"
            );
        }
    }

    #[test]
    fn predicates_do_not_touch_the_catalog_after_resolve() {
        // Structural proof that the snapshot removes the per-probe catalog lock (rmp #320): the oracle
        // holds ONLY the owned privilege snapshot, not the `Arc<SecurityCatalog>`. Drop the catalog's
        // last strong reference right after `resolve`; if any predicate still answers, it provably did
        // not (and could not) re-take the catalog read lock. A wide restricted read is thus O(distinct
        // names) snapshot walks under ZERO catalog-lock acquisitions (the single resolve-time lock has
        // already been released here).
        let cat = catalog_with(&[Privilege::on_label(Action::Read, "db", "Person")]);
        let weak = Arc::downgrade(&cat);
        let p = EffectivePrivileges::resolve(cat, Some("alice"), "db");
        // No other strong reference exists -> dropping the local `cat` (moved into resolve and dropped
        // there) leaves the catalog deallocated. The oracle does not keep it alive.
        assert!(
            weak.upgrade().is_none(),
            "the oracle must NOT retain the SecurityCatalog (so predicates cannot lock it)"
        );
        // Predicates still answer correctly, entirely from the owned snapshot.
        assert!(p.can_traverse_label("Person"));
        assert!(p.can_read_property("Person", "name"));
        assert!(!p.can_traverse_label("Company"));
    }

    #[test]
    fn snapshot_is_send_and_sync() {
        // `EffectivePrivileges` crosses the engine command channel (needs `Send`) and is documented
        // `Send + Sync`; pin both so the `Mutex<Memo>` interior mutability never regresses the bound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EffectivePrivileges>();
    }
}
