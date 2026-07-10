//! Fine-grained **RBAC enforcement** over the executor's [`GraphAccess`] seam (rmp #93, completing
//! the access-control epic #68; the model + durable catalog + admin surface are #92).
//!
//! The Cypher executor reads and writes the graph **only** through [`GraphAccess`]
//! ([`crate::graph_access`]). That single chokepoint is what lets this module enforce label /
//! relationship-type / property privileges **uniformly** for every connection type (UDS / Bolt /
//! REST) without touching a single executor operator: wrap the per-statement seam in an
//! [`AuthorizedGraph`] and every read is filtered, every denied property hidden, and every denied
//! write rejected — exactly once, at the boundary.
//!
//! # Auth-agnostic by construction
//!
//! `graphus-cypher` must **not** depend on `graphus-auth` (the dependency would invert the layering:
//! the query engine would pull in the security model). So this module defines a narrow
//! [`PrivilegeOracle`] trait of cheap boolean predicates and enforces against *that*. The server
//! (`graphus-server`, which owns the live `SecurityCatalog`) implements the oracle over the resolved
//! principal + session database and passes it in. The query engine stays security-model-agnostic; the
//! security model stays query-engine-agnostic.
//!
//! # Semantics (the decided enforcement model, `04 §8.4`)
//!
//! All decisions are deny-by-default and scoped to the session database (the oracle already carries
//! the database, so the predicates take only the element-local name). The graded action chain is
//! `Traverse ⊂ Read ⊂ Write` (see `graphus_auth::Action`): the oracle's `can_read_*` already implies
//! `can_traverse_*`, and `can_write_*` implies both — the server resolves that, this module only asks
//! the question the operation needs.
//!
//! - **Node visibility (Traverse).** A node is visible iff the user can traverse **at least one** of
//!   its labels ([`PrivilegeOracle::can_traverse_label`]) **and no label of the node is
//!   traverse-denied** ([`PrivilegeOracle::is_denied_traverse_label`]) — broader `Graph`/`Database`
//!   grants are folded into the oracle's answer, and an explicit `DENY` on **any one** of the node's
//!   labels takes precedence over a grant on the others (Neo4j DENY-across-labels precedence; the
//!   correct rule is `(∃l: granted(l)) ∧ (∄l: denied(l))`, never `∃l: granted(l) ∧ ¬denied(l)`). A
//!   node that is not visible does not exist for this statement: it is filtered out of
//!   [`scan_nodes`](GraphAccess::scan_nodes),
//!   [`scan_nodes_by_label`](GraphAccess::scan_nodes_by_label), index seeks, expands, and as an
//!   expand endpoint, and its [`node_exists`](GraphAccess::node_exists) reads `false`. **A node with
//!   no labels at all is visible** (there is nothing to deny; it matches `MATCH (n)`), consistent with
//!   property-level security where label grants gate only the labelled rows.
//! - **Property read (Read).** A property `p` of a node is readable iff the user holds Read on `p`
//!   under **some** label the node carries and can see ([`PrivilegeOracle::can_read_property`]) **and
//!   no label of the node read-denies `p`** ([`PrivilegeOracle::is_denied_read_property`]) — a `DENY
//!   READ` on any one label wins over a grant on the others. A denied property reads back as
//!   **absent** (the node still appears; the key is simply not there) — never an error. This is
//!   property-level security: a hidden property is `NULL`, the node stays visible if traversable
//!   (`DENY READ` leaves traverse intact, so the node is not hidden — only the property).
//! - **Relationship traverse (Traverse).** A relationship of type `T` is traversable iff the user can
//!   traverse `T` ([`PrivilegeOracle::can_traverse_rel_type`]) **and both endpoints are visible**. A
//!   type-denied or now-dangling (endpoint filtered) relationship is removed from expands and
//!   relationship reads. Relationship property reads follow the Read rule, scoped by rel-type.
//! - **Writes (Write).** Creating / setting / removing a label `L`, a relationship of type `T`, or a
//!   property requires Write on the corresponding scope; a denied write is **rejected** with
//!   [`GraphusError::Security`] *before* the side effect (the inner seam is never called). Deletes
//!   require Write on the target's labels / type.
//!
//! # Zero-overhead unrestricted path
//!
//! [`PrivilegeOracle::is_unrestricted`] is the admin / no-principal (TCK, direct tests, internal)
//! fast path: when it returns `true`, **every** method delegates to the inner seam verbatim, byte for
//! byte, after a single predictable branch. There is no per-row name resolution, no allocation, no
//! behavioural change — so the unrestricted path (and therefore the TCK ratchet) is unaffected.
//!
//! # Error surfacing
//!
//! Like the [`RecordStoreGraph`](crate::record_graph::RecordStoreGraph) it wraps, the `GraphAccess`
//! write methods return `()` — they cannot signal a denial inline. A rejected write is recorded in
//! this decorator's own error cell and the inner write is **skipped**; the caller **must** inspect
//! [`take_auth_error`](AuthorizedGraph::take_auth_error) after running the cursor (exactly as it must
//! inspect the seam's own `take_error`). A captured authorization error means the statement must be
//! rolled back, never committed — a half-applied write must never become durable.

use graphus_core::Value;
use graphus_core::error::GraphusError;

use crate::graph_access::{
    DeletedEntity, ExpandDirection, GraphAccess, Incident, NodeId, RelData, RelId,
};

/// The narrow privilege interface the [`AuthorizedGraph`] enforces against, resolved **once per
/// statement** for one principal + session database (rmp #93).
///
/// Every predicate is a cheap, side-effect-free boolean. The element-local name is all the decorator
/// supplies — the database is already baked into the oracle by the implementor (`graphus-server`'s
/// `EffectivePrivileges`). The graded `Traverse ⊂ Read ⊂ Write` chain is the oracle's responsibility:
/// a `can_read_property` answer already accounts for a broader `Read`/`Write` grant on the label, the
/// graph, or the database, and `can_write_*` accounts for `Admin`.
///
/// # Auth-agnostic seam
///
/// This trait lives in `graphus-cypher` precisely so the query engine need not depend on
/// `graphus-auth`. The implementor wires it to the real RBAC catalog; the executor only ever sees
/// booleans.
pub trait PrivilegeOracle {
    /// The fast path: when `true`, the principal may do anything in this database (an admin, or the
    /// no-principal internal / TCK / direct-test path). The [`AuthorizedGraph`] then delegates every
    /// operation to the inner seam unchanged — no filtering, no overhead beyond this one check.
    fn is_unrestricted(&self) -> bool;

    /// Whether the principal may **traverse** (see the existence/labels of) nodes carrying `label`.
    /// Implied by any `Read`/`Write` the principal holds on that label (or a broader scope).
    fn can_traverse_label(&self, label: &str) -> bool;

    /// Whether the principal may **read** the value of property `property` on a node carrying
    /// `label`. Keyed by label because property grants are label-scoped (`Property { label, property }`).
    fn can_read_property(&self, label: &str, property: &str) -> bool;

    /// Whether the principal may **traverse** relationships of type `rel_type`.
    fn can_traverse_rel_type(&self, rel_type: &str) -> bool;

    /// Whether the principal may **read** the value of property `property` on a relationship of type
    /// `rel_type`. Relationship property grants are rel-type-scoped.
    fn can_read_rel_property(&self, rel_type: &str, property: &str) -> bool;

    /// Whether the principal may **write** (create / set / remove) the label `label` and data carried
    /// under it.
    fn can_write_label(&self, label: &str) -> bool;

    /// Whether the principal may **write** relationships of type `rel_type` (and their properties).
    fn can_write_rel_type(&self, rel_type: &str) -> bool;

    /// Whether the principal may **write** property `property` on a node carrying `label`.
    fn can_write_property(&self, label: &str, property: &str) -> bool;

    /// Whether the principal may **write** property `property` on a relationship of type `rel_type`.
    fn can_write_rel_property(&self, rel_type: &str, property: &str) -> bool;

    // ---- explicit-DENY predicates (CWE-863 fix) --------------------------------------------------
    //
    // The `can_*` predicates above collapse `grant ∧ ¬deny` into a single per-label boolean, so an
    // enforcement site that unions them across a multi-label node with a bare `OR`
    // (`labels.iter().any(can_*)`) computes `∃l: (granted(l) ∧ ¬denied(l))`. That is the **wrong**
    // rule for DENY, which must take precedence *across* labels: a node bearing labels `[Report,
    // Classified]` with `GRANT READ ON GRAPH` + `DENY TRAVERSE ON LABEL Classified` must be
    // invisible, because the correct Neo4j rule is `(∃l: granted(l)) ∧ (∄l: denied(l))` — a DENY on
    // **any** label of the node blocks it even when another label would grant it.
    //
    // These predicates expose the negation half **separately** (consulting only the deny snapshot),
    // so the [`AuthorizedGraph`] can enforce DENY-wins: `any(can_*) AND NOT any(is_denied_*)`. They
    // must never be `true` for an unrestricted principal (a global admin is exempt from DENY): the
    // decorator already short-circuits the unrestricted path before reaching them, and the server
    // oracle additionally holds no deny snapshot for an admin, so both layers agree.
    //
    // Relationships need no deny predicate: a relationship carries exactly **one** type, so there is
    // no cross-label union — `can_traverse_rel_type` / `can_write_rel_type` already fold the type's
    // own deny via the oracle's grant/deny composition.

    /// Whether an explicit `DENY` **blocks traversing** nodes carrying `label` (a `DENY TRAVERSE`, or
    /// any stronger deny that subsumes traverse, on that label or a broader scope). When `true`, a
    /// node bearing `label` is invisible regardless of any grant on its other labels.
    fn is_denied_traverse_label(&self, label: &str) -> bool;

    /// Whether an explicit `DENY` **blocks reading** property `property` on a node carrying `label`
    /// (a `DENY READ` on the property, its label, or a broader scope). When `true`, the property reads
    /// as absent/NULL regardless of any read grant reachable through the node's other labels.
    fn is_denied_read_property(&self, label: &str, property: &str) -> bool;

    /// Whether an explicit `DENY` **blocks writing** the label `label` (and the node's data under it).
    /// When `true`, a whole-node write (create / delete / replace) touching a node that carries
    /// `label` is rejected regardless of a grant on its other labels.
    fn is_denied_write_label(&self, label: &str) -> bool;

    /// Whether an explicit `DENY` **blocks writing** property `property` on a node carrying `label`.
    /// When `true`, setting/removing that property on a node carrying `label` is rejected regardless
    /// of a write grant reachable through the node's other labels.
    fn is_denied_write_property(&self, label: &str, property: &str) -> bool;
}

/// A [`GraphAccess`] decorator that enforces a [`PrivilegeOracle`]'s fine-grained RBAC over an inner
/// seam (rmp #93). See the module docs for the full semantics.
///
/// Wraps a `&mut dyn GraphAccess` so it composes over the concrete
/// [`RecordStoreGraph`](crate::record_graph::RecordStoreGraph) (or any other implementation) without
/// being generic over its backend, and so the executor — which already takes
/// `&mut dyn GraphAccess` — runs over it unchanged.
///
/// # Errors
///
/// Write denials are recorded internally (the trait's write methods cannot return a `Result`) and
/// surfaced through [`take_auth_error`](Self::take_auth_error); the caller must check it after the
/// statement, as it does the inner seam's `take_error`.
#[must_use]
pub struct AuthorizedGraph<'g, O: PrivilegeOracle> {
    /// The wrapped per-statement seam (the real store graph). Reads/writes that pass the privilege
    /// check are delegated here verbatim, so MVCC / transaction correctness is fully preserved
    /// (privilege filtering composes strictly *on top of* visibility).
    inner: &'g mut dyn GraphAccess,
    /// The per-statement resolved privileges. `is_unrestricted()` short-circuits every method.
    oracle: O,
    /// The first authorization error a write rejection captured, if any. While set, the statement is
    /// untrustworthy and must be rolled back (module docs). The first error is kept (usually the root
    /// cause); a later one does not overwrite it.
    auth_error: Option<GraphusError>,
}

impl<'g, O: PrivilegeOracle> AuthorizedGraph<'g, O> {
    /// Wraps `inner` to enforce `oracle`. When `oracle.is_unrestricted()` the decorator is a
    /// transparent pass-through.
    pub fn new(inner: &'g mut dyn GraphAccess, oracle: O) -> Self {
        Self {
            inner,
            oracle,
            auth_error: None,
        }
    }

    /// Takes the first captured authorization error (a rejected write), leaving the cell empty.
    ///
    /// `Some(err)` means a write was denied during the statement: its side effect was skipped, the
    /// result is **not** trustworthy, and the caller must roll the transaction back rather than commit
    /// it. `None` means no write was denied (a clean run, or a read-only statement). Mirrors
    /// [`RecordStoreGraph::take_error`](crate::record_graph::RecordStoreGraph::take_error).
    #[must_use]
    pub fn take_auth_error(&mut self) -> Option<GraphusError> {
        self.auth_error.take()
    }

    /// Whether a write denial has been captured (non-consuming peek).
    #[must_use]
    pub fn has_auth_error(&self) -> bool {
        self.auth_error.is_some()
    }

    /// Records `err` as the first captured authorization error (a later error does not overwrite the
    /// first).
    fn deny(&mut self, err: GraphusError) {
        if self.auth_error.is_none() {
            self.auth_error = Some(err);
        }
    }

    /// Builds a [`GraphusError::Security`] for a denied operation. The message names **only** the
    /// action and the element name the user themselves supplied (a label/type/property they already
    /// know) — it never leaks any value or any element the user cannot see, so the error itself is not
    /// an information-disclosure channel.
    fn forbidden(action: &str, kind: &str, name: &str) -> GraphusError {
        GraphusError::Security(format!(
            "permission denied: not authorized to {action} {kind} {name:?}"
        ))
    }

    // ---- visibility helpers (only reached on the restricted path) --------------------------------

    /// Whether `node` is visible to this principal: it exists in the inner seam **and** the user can
    /// traverse at least one of its labels (an unlabelled node is visible — nothing to deny). Used as
    /// the single node-visibility gate for every read path.
    fn node_visible(&self, node: NodeId) -> bool {
        let Some(labels) = self.inner.node_labels(node) else {
            return false; // does not exist in the inner seam (MVCC-invisible or absent)
        };
        self.labels_traversable(&labels)
    }

    /// Whether a node carrying `labels` is traversable, with **DENY-across-labels precedence**
    /// (CWE-863 fix): a `DENY TRAVERSE` on **any** of the node's labels hides it outright, even when
    /// another label would grant traversal. Otherwise the grant rule applies: no labels ⇒ visible;
    /// with labels, at least one must be traversable. The full rule is
    /// `(∄l: denied(l)) ∧ (labels.is_empty() ∨ ∃l: granted(l))` — never the flawed
    /// `∃l: granted(l) ∧ ¬denied(l)` a bare per-label union would compute. Centralises the "node
    /// visibility" rule (`04 §8.4`).
    fn labels_traversable(&self, labels: &[String]) -> bool {
        if labels
            .iter()
            .any(|l| self.oracle.is_denied_traverse_label(l))
        {
            return false; // DENY on any label wins over any grant on the others
        }
        labels.is_empty() || labels.iter().any(|l| self.oracle.can_traverse_label(l))
    }

    /// Whether property `key` is **readable** on a node carrying `labels`, with DENY-across-labels
    /// precedence (CWE-863 fix): a `DENY READ` on `key` under **any** of the node's labels hides it,
    /// even when another label would grant the read. Otherwise readable iff some label grants Read on
    /// `key`. The rule is `(∄l: denied_read(l, key)) ∧ (∃l: granted_read(l, key))`; an unlabelled
    /// node has no label to grant a read, so its properties stay hidden (unchanged behaviour).
    fn property_readable(&self, labels: &[String], key: &str) -> bool {
        if labels
            .iter()
            .any(|l| self.oracle.is_denied_read_property(l, key))
        {
            return false; // DENY READ on any label wins over any grant on the others
        }
        labels.iter().any(|l| self.oracle.can_read_property(l, key))
    }

    /// Whether `rel` is traversable: it exists, its type is traversable, **and** both endpoints are
    /// visible. The relationship-visibility gate for every read/traverse path.
    fn rel_visible(&self, rel: RelId) -> bool {
        let Some(data) = self.inner.rel_data(rel) else {
            return false;
        };
        self.oracle.can_traverse_rel_type(&data.rel_type)
            && self.node_visible(data.start)
            && self.node_visible(data.end)
    }

    /// Filters `props` of a node carrying `labels` to the readable ones (property hiding): a property
    /// is kept iff [`property_readable`](Self::property_readable) — some label grants Read on it and
    /// no label read-denies it (DENY-across-labels precedence). Used by `node_properties`.
    fn filter_node_props(
        &self,
        labels: &[String],
        props: Vec<(String, Value)>,
    ) -> Vec<(String, Value)> {
        props
            .into_iter()
            .filter(|(key, _)| self.property_readable(labels, key))
            .collect()
    }

    /// Filters `props` of a relationship of `rel_type` to the readable ones (property hiding).
    fn filter_rel_props(
        &self,
        rel_type: &str,
        props: Vec<(String, Value)>,
    ) -> Vec<(String, Value)> {
        props
            .into_iter()
            .filter(|(key, _)| self.oracle.can_read_rel_property(rel_type, key))
            .collect()
    }
}

impl<O: PrivilegeOracle> GraphAccess for AuthorizedGraph<'_, O> {
    // ---- reads -----------------------------------------------------------------------------------

    fn scan_nodes(&self) -> Vec<NodeId> {
        let ids = self.inner.scan_nodes();
        if self.oracle.is_unrestricted() {
            return ids;
        }
        ids.into_iter()
            .filter(|&id| self.node_visible(id))
            .collect()
    }

    fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
        let ids = self.inner.scan_nodes_by_label(label);
        if self.oracle.is_unrestricted() {
            return ids;
        }
        // A label scan already constrains to nodes carrying `label`; a node is still only visible if
        // at least one of its labels (not necessarily `label` itself — though it carries it) is
        // traversable. In practice carrying a non-traversable `label` does not by itself hide a node
        // that carries *another* traversable label, so re-check full visibility.
        ids.into_iter()
            .filter(|&id| self.node_visible(id))
            .collect()
    }

    fn columnar_label_property_scan(
        &self,
        label: &str,
        property: &str,
    ) -> Option<crate::graph_access::ColumnarScan> {
        // Forward the columnar accelerator (`rmp` #329), then compose RBAC. An unrestricted principal
        // sees the inner result verbatim. A restricted principal is conservatively **declined**
        // (return `None`) so the executor falls back to the row scan, which RBAC-composes exactly via
        // `scan_nodes_by_label` + `node_property`. Declining is correct because the columnar fast path
        // is a pure accelerator with an always-correct row fallback; reconstructing the RBAC-projected
        // `count(*)` (the `label_matches` denominator) here would require re-deriving traverse
        // visibility per node, duplicating the row path's gate — not worth it for the rare restricted
        // analytical scan. The common (unrestricted) analytical workload keeps the full win.
        if !self.oracle.is_unrestricted() {
            return None;
        }
        self.inner.columnar_label_property_scan(label, property)
    }

    fn project_snapshot(
        &self,
        spec: &crate::snapshot::SnapshotSpec,
    ) -> Option<crate::snapshot::GraphSnapshot> {
        // The parallel-read snapshot projection (`rmp` task #352), composed with RBAC exactly as
        // `columnar_label_property_scan` above: an unrestricted principal gets the inner projection
        // verbatim; a restricted principal is conservatively **declined** (return `None`) so the
        // executor falls back to the serial aggregation, which RBAC-composes via
        // `scan_nodes_by_label` + `node_property`. A restricted principal must never observe
        // filtered-out data through a frozen snapshot, and reconstructing the RBAC-projected column +
        // `count(*)` here would duplicate the row path's per-node traverse gate — not worth it for the
        // rare restricted analytical scan. The common (unrestricted) workload keeps the full win.
        if !self.oracle.is_unrestricted() {
            return None;
        }
        self.inner.project_snapshot(spec)
    }

    fn note_parallel_aggregate(&self) {
        // Pure observability bump (`rmp` task #352): forward unconditionally. A restricted principal
        // never reaches it (its `project_snapshot` already declined), so there is nothing to gate.
        self.inner.note_parallel_aggregate();
    }

    fn morsel_label_scan(&self, label: &str) -> Option<crate::morsel::MorselLabelScan> {
        // The morsel-driven parallel label scan (`rmp` task #339), composed with RBAC exactly as
        // `project_snapshot` above: an unrestricted principal gets the inner bundle verbatim; a
        // restricted principal is conservatively **declined** (return `None`) so the executor falls back
        // to the serial path, which RBAC-composes per node via `scan_nodes_by_label` + `node_property`.
        // A restricted principal must never read filtered-out nodes through an off-thread morsel that has
        // no per-node RBAC gate. Per-morsel RBAC is a follow-on; the common (unrestricted) analytical
        // workload keeps the full win.
        if !self.oracle.is_unrestricted() {
            return None;
        }
        self.inner.morsel_label_scan(label)
    }

    fn frontier_morsel_source(&self) -> Option<crate::morsel::MorselFrontierSource> {
        // The `rmp` #575 frontier morsel source, composed with RBAC exactly as `morsel_label_scan` above:
        // an unrestricted principal gets the inner surface verbatim; a restricted principal is
        // conservatively **declined** (return `None`) so the executor falls back to the serial pipeline,
        // which RBAC-composes per node/edge. A restricted principal must never read filtered-out
        // nodes/relationships through an off-thread morsel that has no per-node RBAC gate.
        if !self.oracle.is_unrestricted() {
            return None;
        }
        self.inner.frontier_morsel_source()
    }

    fn merge_morsel_buffer(&self, buffer: graphus_txn::SsiReadBuffer) {
        // Forward unconditionally (`rmp` task #339): a restricted principal never produced a morsel
        // buffer (its `morsel_label_scan` declined), so there is nothing to gate. The inner seam folds
        // the markers into the shared tracker on the engine thread.
        self.inner.merge_morsel_buffer(buffer);
    }

    fn expand(&self, node: NodeId, direction: ExpandDirection, types: &[String]) -> Vec<Incident> {
        let incidents = self.inner.expand(node, direction, types);
        if self.oracle.is_unrestricted() {
            return incidents;
        }
        // The anchor itself must be visible (an expand from an invisible node yields nothing), and
        // each incident relationship must be traversable (type + both endpoints visible).
        if !self.node_visible(node) {
            return Vec::new();
        }
        incidents
            .into_iter()
            .filter(|inc| self.rel_visible(inc.rel) && self.node_visible(inc.neighbour))
            .collect()
    }

    fn node_exists(&self, node: NodeId) -> bool {
        if self.oracle.is_unrestricted() {
            return self.inner.node_exists(node);
        }
        // Existence for a restricted principal means "visible": exists in the seam AND traversable.
        self.inner.node_exists(node) && self.node_visible(node)
    }

    fn rel_exists(&self, rel: RelId) -> bool {
        if self.oracle.is_unrestricted() {
            return self.inner.rel_exists(rel);
        }
        self.inner.rel_exists(rel) && self.rel_visible(rel)
    }

    fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
        let labels = self.inner.node_labels(node)?;
        if self.oracle.is_unrestricted() {
            return Some(labels);
        }
        // An invisible node is reported as non-existent (`None`); a visible node reports its full
        // label set (labels are traverse-gated as a *set*, not hidden individually — seeing the node
        // means seeing its labels, `04 §8.4`).
        if self.labels_traversable(&labels) {
            Some(labels)
        } else {
            None
        }
    }

    fn rel_data(&self, rel: RelId) -> Option<RelData> {
        let data = self.inner.rel_data(rel)?;
        if self.oracle.is_unrestricted() {
            return Some(data);
        }
        if self.oracle.can_traverse_rel_type(&data.rel_type)
            && self.node_visible(data.start)
            && self.node_visible(data.end)
        {
            Some(data)
        } else {
            None
        }
    }

    fn rel_data_including_deleted(&self, rel: RelId) -> Option<RelData> {
        // A relationship the current transaction deleted earlier in this query still yields its type
        // (`type(r)` after `DELETE r`, `clauses/return/Return2.feature` [14]). The transaction
        // necessarily had traverse access to match-and-delete it, so this forwards straight to the
        // inner record graph (the self-delete is an MVCC fact, not an RBAC question). On the
        // unrestricted/non-record paths this is just the default `rel_data` delegate.
        self.inner.rel_data_including_deleted(rel)
    }

    fn entity_deleted_by_txn(&self, entity: DeletedEntity) -> bool {
        // Self-delete is a property of this transaction's own MVCC write, independent of RBAC, so it
        // forwards to the inner graph unconditionally.
        self.inner.entity_deleted_by_txn(entity)
    }

    fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
        if self.oracle.is_unrestricted() {
            return self.inner.node_property(node, key);
        }
        // Hidden if the node is invisible, or `key` is not readable under the node's labels (no label
        // grants Read on it, or some label read-denies it — DENY-across-labels precedence).
        let labels = self.inner.node_labels(node)?;
        if !self.labels_traversable(&labels) {
            return None;
        }
        if !self.property_readable(&labels, key) {
            return None; // property hidden -> reads as absent/NULL
        }
        self.inner.node_property(node, key)
    }

    fn rel_property(&self, rel: RelId, key: &str) -> Option<Value> {
        if self.oracle.is_unrestricted() {
            return self.inner.rel_property(rel, key);
        }
        let data = self.inner.rel_data(rel)?;
        if !self.rel_visible(rel) {
            return None;
        }
        if !self.oracle.can_read_rel_property(&data.rel_type, key) {
            return None; // hidden
        }
        self.inner.rel_property(rel, key)
    }

    fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
        if self.oracle.is_unrestricted() {
            return self.inner.node_properties(node);
        }
        let labels = self.inner.node_labels(node)?;
        if !self.labels_traversable(&labels) {
            return None;
        }
        let props = self.inner.node_properties(node)?;
        Some(self.filter_node_props(&labels, props))
    }

    fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
        if self.oracle.is_unrestricted() {
            return self.inner.rel_properties(rel);
        }
        let data = self.inner.rel_data(rel)?;
        if !self.rel_visible(rel) {
            return None;
        }
        let props = self.inner.rel_properties(rel)?;
        Some(self.filter_rel_props(&data.rel_type, props))
    }

    fn index_seek_eq(&self, label: &str, property: &str, value: &Value) -> Option<Vec<NodeId>> {
        let ids = self.inner.index_seek_eq(label, property, value)?;
        if self.oracle.is_unrestricted() {
            return Some(ids);
        }
        // An index seek is a read path: the result must be filtered exactly like a scan, so the
        // index-accelerated and scan-fallback paths return the same visible rows.
        Some(
            ids.into_iter()
                .filter(|&id| self.node_visible(id))
                .collect(),
        )
    }

    fn scan_filter_eq(&self, label: &str, property: &str, value: &Value) -> Vec<NodeId> {
        // The precise equality scan (`rmp` task #325) is a read path: delegate to the inner seam (which
        // owns the tight SIREAD footprint), then apply RBAC exactly as the label scan / index seek do, so
        // the precise-scan, index-accelerated, and bare-scan paths all return the same visible rows.
        let ids = self.inner.scan_filter_eq(label, property, value);
        if self.oracle.is_unrestricted() {
            return ids;
        }
        ids.into_iter()
            .filter(|&id| self.node_visible(id))
            .collect()
    }

    fn index_seek_range(
        &self,
        label: &str,
        property: &str,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
    ) -> Option<Vec<NodeId>> {
        let ids = self.inner.index_seek_range(label, property, lower, upper)?;
        if self.oracle.is_unrestricted() {
            return Some(ids);
        }
        Some(
            ids.into_iter()
                .filter(|&id| self.node_visible(id))
                .collect(),
        )
    }

    fn index_seek_composite_eq(
        &self,
        label: &str,
        properties: &[String],
        values: &[Value],
    ) -> Option<Vec<NodeId>> {
        // A composite index seek is a read path: filter its candidates exactly like a scan / single-key
        // seek, so the index-accelerated and scan-fallback paths return the same visible rows
        // (`rmp` task #657).
        let ids = self
            .inner
            .index_seek_composite_eq(label, properties, values)?;
        if self.oracle.is_unrestricted() {
            return Some(ids);
        }
        Some(
            ids.into_iter()
                .filter(|&id| self.node_visible(id))
                .collect(),
        )
    }

    fn index_seek_rel_eq(
        &self,
        rel_type: &str,
        property: &str,
        value: &Value,
    ) -> Option<Vec<RelId>> {
        // A relationship-property index seek (`rmp` task #659) is a read path. For an **unrestricted**
        // principal (no privilege filtering to apply) delegate straight to the inner seam's seek. For a
        // **restricted** principal decline (`None`) so the executor falls back to the typed relationship
        // scan, which flows through this decorator's `expand` / `rel_data` / `rel_property` and therefore
        // enforces relationship-type traversal AND per-property read grants exactly as the pre-#659 scan
        // path did. The seek re-checks a candidate against the *raw* store value and so cannot observe a
        // `DENY READ` on the seeked property; declining keeps a restricted principal from ever seeing a
        // relationship a `WHERE r.p = v` scan would have hidden — no RBAC regression, and the common
        // unrestricted query keeps the seek (the server only wraps this decorator for restricted ones).
        if self.oracle.is_unrestricted() {
            return self.inner.index_seek_rel_eq(rel_type, property, value);
        }
        None
    }

    fn index_seek_spatial_rel(
        &self,
        rel_type: &str,
        property: &str,
        center_x: f64,
        center_y: f64,
        radius: f64,
    ) -> Option<Vec<RelId>> {
        // A relationship spatial proximity seek (`rmp` task #664) is a read path — same RBAC stance as
        // the relationship-property seek (`rmp` #659) above. For an **unrestricted** principal delegate
        // straight to the inner seam's seek; for a **restricted** principal decline (`None`) so the
        // executor falls back to the typed relationship scan, which flows through this decorator's
        // `expand` / `rel_data` / `rel_property` and therefore enforces relationship-type traversal AND
        // per-property read grants exactly as the scan path did. The seek re-checks a candidate against
        // the *raw* store value/endpoints and so cannot observe a `DENY READ` on the seeked property;
        // declining keeps a restricted principal from ever seeing a relationship a `WHERE distance(...)`
        // scan would have hidden — no RBAC regression, and the common unrestricted query keeps the seek
        // (the server only wraps this decorator for restricted principals).
        if self.oracle.is_unrestricted() {
            return self
                .inner
                .index_seek_spatial_rel(rel_type, property, center_x, center_y, radius);
        }
        None
    }

    fn index_seek_spatial(
        &self,
        label: &str,
        property: &str,
        center_x: f64,
        center_y: f64,
        radius: f64,
    ) -> Option<Vec<NodeId>> {
        let ids = self
            .inner
            .index_seek_spatial(label, property, center_x, center_y, radius)?;
        if self.oracle.is_unrestricted() {
            return Some(ids);
        }
        // A spatial proximity seek is a read path (`rmp` task #73): filter the candidate ids exactly
        // like a scan, so an RBAC-invisible node never reaches the result. The seek's residual
        // `distance` filter additionally re-checks each candidate's current value/label through this
        // same decorator, so the filters compose (visibility + label + value + RBAC).
        Some(
            ids.into_iter()
                .filter(|&id| self.node_visible(id))
                .collect(),
        )
    }

    fn index_seek_text(
        &self,
        label: &str,
        property: &str,
        op: crate::physical::TextSeekOp,
        needle: &str,
    ) -> Option<Vec<NodeId>> {
        let ids = self.inner.index_seek_text(label, property, op, needle)?;
        if self.oracle.is_unrestricted() {
            return Some(ids);
        }
        // A text (trigram) seek is a read path (`rmp` task #662): filter the candidate ids exactly like
        // a scan, so an RBAC-invisible node never reaches the result. The seek's residual string
        // predicate additionally re-checks each candidate's current value/label through this same
        // decorator, so the filters compose (visibility + label + value + RBAC).
        Some(
            ids.into_iter()
                .filter(|&id| self.node_visible(id))
                .collect(),
        )
    }

    fn fulltext_query(&self, name: &str, search: &str) -> Option<Vec<NodeId>> {
        let ids = self.inner.fulltext_query(name, search)?;
        if self.oracle.is_unrestricted() {
            return Some(ids);
        }
        // A full-text query is a read path (`rmp` task #72): filter the candidate ids exactly like a
        // scan, so an RBAC-invisible node never reaches the result. The procedure body additionally
        // re-checks each candidate's current label through this same decorator, so the two filters
        // compose (visibility + label + RBAC).
        Some(
            ids.into_iter()
                .filter(|&id| self.node_visible(id))
                .collect(),
        )
    }

    fn fulltext_score(&self, name: &str, node: NodeId, search: &str) -> Option<u64> {
        // The score is advisory and only ever requested for an already-visible candidate (the
        // procedure filters first), so forwarding to the inner seam is sufficient.
        self.inner.fulltext_score(name, node, search)
    }

    fn fulltext_query_rel(&self, name: &str, search: &str) -> Option<Vec<RelId>> {
        let ids = self.inner.fulltext_query_rel(name, search)?;
        if self.oracle.is_unrestricted() {
            return Some(ids);
        }
        // A relationship full-text query is a read path (`rmp` task #663): filter the candidate ids
        // exactly like a scan, so an RBAC-invisible relationship (traverse denied, or an endpoint not
        // visible) never reaches the result. The procedure body additionally re-checks each candidate's
        // current type through this same decorator, so the filters compose (visibility + type + RBAC).
        Some(ids.into_iter().filter(|&id| self.rel_visible(id)).collect())
    }

    fn fulltext_score_rel(&self, name: &str, rel: RelId, search: &str) -> Option<u64> {
        // Advisory, only requested for an already-visible candidate (the procedure filters first).
        self.inner.fulltext_score_rel(name, rel, search)
    }

    // ---- writes ----------------------------------------------------------------------------------

    fn create_node(&mut self, labels: &[String], properties: &[(String, Value)]) -> NodeId {
        if self.oracle.is_unrestricted() {
            return self.inner.create_node(labels, properties);
        }
        // Every label being created requires Write on that label; every property requires Write on
        // the property under at least one of the created labels (an unlabelled node's properties are
        // gated by the node's create authority — which, with no labels, requires a database/graph-wide
        // write grant, surfaced by `can_write_property` with no label matching).
        for label in labels {
            if !self.oracle.can_write_label(label) {
                self.deny(Self::forbidden("create", "label", label));
                return NodeId(u64::MAX);
            }
        }
        for (key, _) in properties {
            // Gated by `property_writable`: some created label grants Write on the property and no
            // created label write-denies it (DENY-across-labels precedence); with no labels, the
            // graph/database-wide write grant gates it via the empty-label probe.
            if !self.property_writable(labels, key) {
                self.deny(Self::forbidden("write", "property", key));
                return NodeId(u64::MAX);
            }
        }
        self.inner.create_node(labels, properties)
    }

    fn create_rel(
        &mut self,
        rel_type: &str,
        start: NodeId,
        end: NodeId,
        properties: &[(String, Value)],
    ) -> RelId {
        if self.oracle.is_unrestricted() {
            return self.inner.create_rel(rel_type, start, end, properties);
        }
        if !self.oracle.can_write_rel_type(rel_type) {
            self.deny(Self::forbidden("create", "relationship type", rel_type));
            return RelId(u64::MAX);
        }
        for (key, _) in properties {
            if !self.oracle.can_write_rel_property(rel_type, key) {
                self.deny(Self::forbidden("write", "property", key));
                return RelId(u64::MAX);
            }
        }
        self.inner.create_rel(rel_type, start, end, properties)
    }

    fn set_node_property(&mut self, node: NodeId, key: &str, value: Value) {
        if self.oracle.is_unrestricted() {
            self.inner.set_node_property(node, key, value);
            return;
        }
        if !self.node_write_property_allowed(node, key) {
            self.deny(Self::forbidden("write", "property", key));
            return;
        }
        self.inner.set_node_property(node, key, value);
    }

    fn set_rel_property(&mut self, rel: RelId, key: &str, value: Value) {
        if self.oracle.is_unrestricted() {
            self.inner.set_rel_property(rel, key, value);
            return;
        }
        if !self.rel_write_property_allowed(rel, key) {
            self.deny(Self::forbidden("write", "property", key));
            return;
        }
        self.inner.set_rel_property(rel, key, value);
    }

    fn add_labels(&mut self, node: NodeId, labels: &[String]) {
        if self.oracle.is_unrestricted() {
            self.inner.add_labels(node, labels);
            return;
        }
        for label in labels {
            if !self.oracle.can_write_label(label) {
                self.deny(Self::forbidden("add", "label", label));
                return;
            }
        }
        self.inner.add_labels(node, labels);
    }

    fn remove_labels(&mut self, node: NodeId, labels: &[String]) {
        if self.oracle.is_unrestricted() {
            self.inner.remove_labels(node, labels);
            return;
        }
        for label in labels {
            if !self.oracle.can_write_label(label) {
                self.deny(Self::forbidden("remove", "label", label));
                return;
            }
        }
        self.inner.remove_labels(node, labels);
    }

    fn remove_node_property(&mut self, node: NodeId, key: &str) {
        if self.oracle.is_unrestricted() {
            self.inner.remove_node_property(node, key);
            return;
        }
        if !self.node_write_property_allowed(node, key) {
            self.deny(Self::forbidden("remove", "property", key));
            return;
        }
        self.inner.remove_node_property(node, key);
    }

    fn remove_rel_property(&mut self, rel: RelId, key: &str) {
        if self.oracle.is_unrestricted() {
            self.inner.remove_rel_property(rel, key);
            return;
        }
        if !self.rel_write_property_allowed(rel, key) {
            self.deny(Self::forbidden("remove", "property", key));
            return;
        }
        self.inner.remove_rel_property(rel, key);
    }

    fn replace_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        if self.oracle.is_unrestricted() {
            self.inner.replace_node_properties(node, properties);
            return;
        }
        // `SET n = map` replaces the whole property set; the user must be able to write every key in
        // the new map under the node's labels. (A removed key is covered because replace clears all,
        // and clearing a property the user could not write would be a covert delete — so we require
        // write authority over the node's labels for the operation as a whole: every new key checked,
        // and the node must be writable, established by at least one writable label.)
        let labels = match self.inner.node_labels(node) {
            Some(l) => l,
            None => return, // invisible / absent node: inner is a no-op anyway
        };
        if !self.node_labels_writable(&labels) {
            self.deny(Self::forbidden(
                "replace properties on",
                "node with label",
                first_label(&labels),
            ));
            return;
        }
        for (key, _) in properties {
            if !self.property_writable(&labels, key) {
                self.deny(Self::forbidden("write", "property", key));
                return;
            }
        }
        self.inner.replace_node_properties(node, properties);
    }

    fn merge_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        if self.oracle.is_unrestricted() {
            self.inner.merge_node_properties(node, properties);
            return;
        }
        // `SET n += map` overlays each key; require write on each key under the node's labels (with
        // DENY-across-labels precedence via `property_writable`).
        let labels = match self.inner.node_labels(node) {
            Some(l) => l,
            None => return,
        };
        for (key, _) in properties {
            if !self.property_writable(&labels, key) {
                self.deny(Self::forbidden("write", "property", key));
                return;
            }
        }
        self.inner.merge_node_properties(node, properties);
    }

    fn replace_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
        if self.oracle.is_unrestricted() {
            self.inner.replace_rel_properties(rel, properties);
            return;
        }
        // `SET r = map` replaces the whole property set; require write on every key under the rel's
        // type (clearing a property the user could not write would be a covert delete).
        for (key, _) in properties {
            if !self.rel_write_property_allowed(rel, key) {
                self.deny(Self::forbidden("write", "property", key));
                return;
            }
        }
        self.inner.replace_rel_properties(rel, properties);
    }

    fn merge_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
        if self.oracle.is_unrestricted() {
            self.inner.merge_rel_properties(rel, properties);
            return;
        }
        for (key, _) in properties {
            if !self.rel_write_property_allowed(rel, key) {
                self.deny(Self::forbidden("write", "property", key));
                return;
            }
        }
        self.inner.merge_rel_properties(rel, properties);
    }

    fn incident_rels(&self, node: NodeId) -> Vec<RelId> {
        let rels = self.inner.incident_rels(node);
        if self.oracle.is_unrestricted() {
            return rels;
        }
        // Only the rels this principal can traverse are visible for a DETACH DELETE's incident
        // enumeration; an invisible incident rel does not exist for this statement.
        rels.into_iter().filter(|&r| self.rel_visible(r)).collect()
    }

    fn delete_rel(&mut self, rel: RelId) {
        if self.oracle.is_unrestricted() {
            self.inner.delete_rel(rel);
            return;
        }
        // Deleting a relationship requires Write on its type. An invisible rel is a no-op (the inner
        // seam would no-op anyway), so only a *visible but non-writable* rel is a denial.
        let Some(data) = self.inner.rel_data(rel) else {
            return; // invisible / absent: no-op (matches inner contract)
        };
        if !self.rel_visible(rel) {
            return; // invisible to this principal: no-op
        }
        if !self.oracle.can_write_rel_type(&data.rel_type) {
            self.deny(Self::forbidden(
                "delete",
                "relationship type",
                &data.rel_type,
            ));
            return;
        }
        self.inner.delete_rel(rel);
    }

    fn delete_node(&mut self, node: NodeId) {
        if self.oracle.is_unrestricted() {
            self.inner.delete_node(node);
            return;
        }
        let Some(labels) = self.inner.node_labels(node) else {
            return; // invisible / absent: no-op
        };
        if !self.labels_traversable(&labels) {
            return; // invisible to this principal: no-op
        }
        // Deleting a node requires Write authority over it: with labels, a writable label; with no
        // labels, the graph/database-wide write grant (probed via the empty label).
        if !self.node_labels_writable(&labels) {
            self.deny(Self::forbidden(
                "delete",
                "node with label",
                first_label(&labels),
            ));
            return;
        }
        self.inner.delete_node(node);
    }

    fn statistics(&self) -> Option<&dyn crate::statistics::Statistics> {
        // Statistics are aggregate cost-model inputs, not per-element data, and the planner already
        // ran before enforcement. Pass the inner seam's statistics through unchanged so cost-based
        // planning is unaffected by who is asking; enforcement is a result-set concern, not a
        // cardinality-estimation one.
        self.inner.statistics()
    }

    fn write_counters(&self) -> crate::counters::QueryCounters {
        // `rmp` #510: side effects are counted at the inner seam's write chokepoints. This decorator
        // is deny-by-default: a forbidden write returns via `deny()` WITHOUT calling inner, so it
        // never reaches a chokepoint and is correctly counted as zero. An authorized write forwards to
        // inner and is counted there. So delegating verbatim yields the exact applied-side-effect tally.
        self.inner.write_counters()
    }
}

impl<O: PrivilegeOracle> AuthorizedGraph<'_, O> {
    /// Whether the principal may write property `key` on a node carrying `labels`, with
    /// DENY-across-labels precedence (CWE-863 fix): a `DENY WRITE` on `key` under **any** of the
    /// node's labels rejects the write, even when another label would grant it. With labels, allowed
    /// iff some label grants Write on `key` and no label write-denies it
    /// (`(∄l: denied(l)) ∧ (∃l: granted(l))`); with no labels, gated by the graph/database-wide write
    /// grant (empty-label probe — an unlabelled node has no label-level deny to apply, and a
    /// graph-wide `DENY` is already folded into `can_write_property("", key)` by the oracle).
    fn property_writable(&self, labels: &[String], key: &str) -> bool {
        if labels.is_empty() {
            // No label: gated by the graph/database-wide write grant (empty-label probe).
            return self.oracle.can_write_property("", key);
        }
        if labels
            .iter()
            .any(|l| self.oracle.is_denied_write_property(l, key))
        {
            return false; // DENY WRITE on any label wins over any grant on the others
        }
        labels
            .iter()
            .any(|l| self.oracle.can_write_property(l, key))
    }

    /// Whether the principal may write property `key` on `node`, given the node's current labels. A
    /// node invisible to the principal is treated as not-writable (its labels are non-traversable),
    /// and DENY-across-labels precedence applies via [`property_writable`](Self::property_writable).
    fn node_write_property_allowed(&self, node: NodeId, key: &str) -> bool {
        let Some(labels) = self.inner.node_labels(node) else {
            return false;
        };
        if !self.labels_traversable(&labels) {
            return false;
        }
        self.property_writable(&labels, key)
    }

    /// Whether the principal may write property `key` on `rel`, given the rel's current type.
    fn rel_write_property_allowed(&self, rel: RelId, key: &str) -> bool {
        let Some(data) = self.inner.rel_data(rel) else {
            return false;
        };
        if !self.rel_visible(rel) {
            return false;
        }
        self.oracle.can_write_rel_property(&data.rel_type, key)
    }

    /// Whether the principal has write authority over a node carrying `labels` (for whole-node
    /// operations: delete, replace), with DENY-across-labels precedence (CWE-863 fix): a `DENY WRITE`
    /// on **any** label refuses the whole-node write, even when another label would grant it. With no
    /// labels, the graph/database-wide write grant gates it (empty-label probe); otherwise at least
    /// one label must be writable and none write-denied
    /// (`(∄l: denied(l)) ∧ (∃l: granted(l))`).
    fn node_labels_writable(&self, labels: &[String]) -> bool {
        if labels.is_empty() {
            return self.oracle.can_write_label("");
        }
        if labels.iter().any(|l| self.oracle.is_denied_write_label(l)) {
            return false; // DENY WRITE on any label wins over any grant on the others
        }
        labels.iter().any(|l| self.oracle.can_write_label(l))
    }
}

/// The first label of a node, for a denial message — `""` when the node is unlabelled (the message
/// then reads "node with label \"\"", an accurate "no specific label" marker).
fn first_label(labels: &[String]) -> &str {
    labels.first().map(String::as_str).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_access::MemGraph;
    use std::collections::BTreeSet;

    /// A stub oracle driven by explicit allow-lists, for direct (API-bypassing) enforcement tests.
    /// Empty sets + `unrestricted=false` ⇒ deny-by-default; `unrestricted=true` ⇒ pass-through.
    #[derive(Default)]
    struct StubOracle {
        unrestricted: bool,
        traverse_labels: BTreeSet<String>,
        read_props: BTreeSet<(String, String)>,
        traverse_rel_types: BTreeSet<String>,
        read_rel_props: BTreeSet<(String, String)>,
        write_labels: BTreeSet<String>,
        write_rel_types: BTreeSet<String>,
        write_props: BTreeSet<(String, String)>,
        write_rel_props: BTreeSet<(String, String)>,
        // Explicit denylists (CWE-863 fix): a name here blocks the capability regardless of any
        // grant, mirroring the server oracle's deny snapshot. A `can_*` grant AND a matching deny may
        // coexist (a broad grant with a carved hole) — the enforcement combines them DENY-wins.
        denied_traverse_labels: BTreeSet<String>,
        denied_read_props: BTreeSet<(String, String)>,
        denied_write_labels: BTreeSet<String>,
        denied_write_props: BTreeSet<(String, String)>,
    }

    impl StubOracle {
        fn unrestricted() -> Self {
            Self {
                unrestricted: true,
                ..Self::default()
            }
        }

        fn traverse_label(mut self, l: &str) -> Self {
            self.traverse_labels.insert(l.to_owned());
            self
        }
        fn read_property(mut self, l: &str, p: &str) -> Self {
            self.read_props.insert((l.to_owned(), p.to_owned()));
            self
        }
        fn traverse_rel_type(mut self, t: &str) -> Self {
            self.traverse_rel_types.insert(t.to_owned());
            self
        }
        fn read_rel_property(mut self, t: &str, p: &str) -> Self {
            self.read_rel_props.insert((t.to_owned(), p.to_owned()));
            self
        }
        fn write_label(mut self, l: &str) -> Self {
            self.write_labels.insert(l.to_owned());
            self
        }
        fn write_rel_type(mut self, t: &str) -> Self {
            self.write_rel_types.insert(t.to_owned());
            self
        }
        fn write_property(mut self, l: &str, p: &str) -> Self {
            self.write_props.insert((l.to_owned(), p.to_owned()));
            self
        }
        fn write_rel_property(mut self, t: &str, p: &str) -> Self {
            self.write_rel_props.insert((t.to_owned(), p.to_owned()));
            self
        }

        fn deny_traverse_label(mut self, l: &str) -> Self {
            self.denied_traverse_labels.insert(l.to_owned());
            self
        }
        fn deny_read_property(mut self, l: &str, p: &str) -> Self {
            self.denied_read_props.insert((l.to_owned(), p.to_owned()));
            self
        }
        fn deny_write_label(mut self, l: &str) -> Self {
            self.denied_write_labels.insert(l.to_owned());
            self
        }
        fn deny_write_property(mut self, l: &str, p: &str) -> Self {
            self.denied_write_props.insert((l.to_owned(), p.to_owned()));
            self
        }
    }

    impl PrivilegeOracle for StubOracle {
        fn is_unrestricted(&self) -> bool {
            self.unrestricted
        }
        fn can_traverse_label(&self, label: &str) -> bool {
            self.traverse_labels.contains(label)
        }
        fn can_read_property(&self, label: &str, property: &str) -> bool {
            self.read_props
                .contains(&(label.to_owned(), property.to_owned()))
        }
        fn can_traverse_rel_type(&self, rel_type: &str) -> bool {
            self.traverse_rel_types.contains(rel_type)
        }
        fn can_read_rel_property(&self, rel_type: &str, property: &str) -> bool {
            self.read_rel_props
                .contains(&(rel_type.to_owned(), property.to_owned()))
        }
        fn can_write_label(&self, label: &str) -> bool {
            self.write_labels.contains(label)
        }
        fn can_write_rel_type(&self, rel_type: &str) -> bool {
            self.write_rel_types.contains(rel_type)
        }
        fn can_write_property(&self, label: &str, property: &str) -> bool {
            self.write_props
                .contains(&(label.to_owned(), property.to_owned()))
        }
        fn can_write_rel_property(&self, rel_type: &str, property: &str) -> bool {
            self.write_rel_props
                .contains(&(rel_type.to_owned(), property.to_owned()))
        }
        fn is_denied_traverse_label(&self, label: &str) -> bool {
            self.denied_traverse_labels.contains(label)
        }
        fn is_denied_read_property(&self, label: &str, property: &str) -> bool {
            self.denied_read_props
                .contains(&(label.to_owned(), property.to_owned()))
        }
        fn is_denied_write_label(&self, label: &str) -> bool {
            self.denied_write_labels.contains(label)
        }
        fn is_denied_write_property(&self, label: &str, property: &str) -> bool {
            self.denied_write_props
                .contains(&(label.to_owned(), property.to_owned()))
        }
    }

    fn s(v: &str) -> Value {
        Value::String(v.to_owned())
    }

    /// A graph: Ada (:Person), Acme (:Company), Ada-[:WORKS_AT {role}]->Acme.
    fn seed() -> (MemGraph, NodeId, NodeId, RelId) {
        let mut g = MemGraph::new();
        let ada = g.add_node(["Person"], [("name", s("Ada")), ("secret", s("hush"))]);
        let acme = g.add_node(["Company"], [("name", s("Acme"))]);
        let r = g.add_rel("WORKS_AT", ada, acme, [("role", s("CEO"))]);
        (g, ada, acme, r)
    }

    #[test]
    fn unrestricted_is_byte_identical_passthrough() {
        let (mut g, ada, _acme, _r) = seed();
        let baseline = g.scan_nodes();
        let baseline_props = g.node_properties(ada);
        let mut authz = AuthorizedGraph::new(&mut g, StubOracle::unrestricted());
        assert_eq!(authz.scan_nodes(), baseline);
        assert_eq!(authz.node_properties(ada), baseline_props);
        assert!(authz.take_auth_error().is_none());
    }

    /// A [`GraphAccess`] that delegates everything to an inner [`MemGraph`] but **overrides
    /// `project_snapshot`** to return a non-`None` snapshot, so the [`AuthorizedGraph`] decorator's
    /// RBAC composition of that method (`rmp` task #352) can be tested in isolation: the default
    /// `MemGraph` impl returns `None` regardless of restriction, which would not distinguish "forwarded"
    /// from "declined".
    struct SnapshotStub(MemGraph);

    impl GraphAccess for SnapshotStub {
        fn project_snapshot(
            &self,
            spec: &crate::snapshot::SnapshotSpec,
        ) -> Option<crate::snapshot::GraphSnapshot> {
            // A faithful (if tiny) single-column snapshot for the first declared column, built from the
            // inner graph — enough that a `Some` here is observable by the decorator test.
            let (label, property) = spec.columns().first()?;
            let members = self.0.scan_nodes_by_label(label);
            let rows = members
                .iter()
                .filter_map(|&n| self.0.node_property(n, property).map(|v| (n, v)))
                .collect();
            Some(crate::snapshot::GraphSnapshot::from_label_column(
                label, property, members, rows,
            ))
        }
        // Everything else delegates to the inner MemGraph.
        fn scan_nodes(&self) -> Vec<NodeId> {
            self.0.scan_nodes()
        }
        fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
            self.0.scan_nodes_by_label(label)
        }
        fn expand(
            &self,
            node: NodeId,
            direction: ExpandDirection,
            types: &[String],
        ) -> Vec<Incident> {
            self.0.expand(node, direction, types)
        }
        fn node_exists(&self, node: NodeId) -> bool {
            self.0.node_exists(node)
        }
        fn rel_exists(&self, rel: RelId) -> bool {
            self.0.rel_exists(rel)
        }
        fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
            self.0.node_labels(node)
        }
        fn rel_data(&self, rel: RelId) -> Option<RelData> {
            self.0.rel_data(rel)
        }
        fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
            self.0.node_property(node, key)
        }
        fn rel_property(&self, rel: RelId, key: &str) -> Option<Value> {
            self.0.rel_property(rel, key)
        }
        fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
            self.0.node_properties(node)
        }
        fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
            self.0.rel_properties(rel)
        }
        fn create_node(&mut self, labels: &[String], properties: &[(String, Value)]) -> NodeId {
            self.0.create_node(labels, properties)
        }
        fn create_rel(
            &mut self,
            rel_type: &str,
            start: NodeId,
            end: NodeId,
            properties: &[(String, Value)],
        ) -> RelId {
            self.0.create_rel(rel_type, start, end, properties)
        }
        fn set_node_property(&mut self, node: NodeId, key: &str, value: Value) {
            self.0.set_node_property(node, key, value);
        }
        fn set_rel_property(&mut self, rel: RelId, key: &str, value: Value) {
            self.0.set_rel_property(rel, key, value);
        }
        fn add_labels(&mut self, node: NodeId, labels: &[String]) {
            self.0.add_labels(node, labels);
        }
        fn remove_labels(&mut self, node: NodeId, labels: &[String]) {
            self.0.remove_labels(node, labels);
        }
        fn remove_node_property(&mut self, node: NodeId, key: &str) {
            self.0.remove_node_property(node, key);
        }
        fn remove_rel_property(&mut self, rel: RelId, key: &str) {
            self.0.remove_rel_property(rel, key);
        }
        fn replace_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
            self.0.replace_node_properties(node, properties);
        }
        fn merge_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
            self.0.merge_node_properties(node, properties);
        }
        fn replace_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
            self.0.replace_rel_properties(rel, properties);
        }
        fn merge_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
            self.0.merge_rel_properties(rel, properties);
        }
        fn incident_rels(&self, node: NodeId) -> Vec<RelId> {
            self.0.incident_rels(node)
        }
        fn delete_rel(&mut self, rel: RelId) {
            self.0.delete_rel(rel);
        }
        fn delete_node(&mut self, node: NodeId) {
            self.0.delete_node(node);
        }
    }

    /// `rmp` task #352: the decorator **forwards** `project_snapshot` for an unrestricted principal
    /// (the inner `Some` snapshot reaches the caller — the common analytical path keeps the parallel
    /// win), and **declines** it (`None`) for a restricted principal, so a restricted reader can never
    /// observe filtered-out data through a frozen snapshot and instead falls back to the serial path.
    #[test]
    fn project_snapshot_forwards_unrestricted_declines_restricted() {
        let (g, _ada, _acme, _r) = seed();
        let spec = crate::snapshot::SnapshotSpec::new().with_column("Person", "name");

        // Unrestricted: the inner snapshot is forwarded verbatim.
        let mut inner_u = SnapshotStub(g.clone());
        let authz_u = AuthorizedGraph::new(&mut inner_u, StubOracle::unrestricted());
        let snap_u = authz_u
            .project_snapshot(&spec)
            .expect("unrestricted principal gets the inner snapshot");
        assert_eq!(
            snap_u.scan_nodes_by_label("Person").len(),
            1,
            "the forwarded snapshot carries the Person members"
        );

        // Restricted (even with the exact grants needed to read the data the serial path WOULD use):
        // the decorator still declines the snapshot, conservatively forcing the serial fallback.
        let mut inner_r = SnapshotStub(g);
        let oracle = StubOracle::default()
            .traverse_label("Person")
            .read_property("Person", "name");
        let authz_r = AuthorizedGraph::new(&mut inner_r, oracle);
        assert!(
            authz_r.project_snapshot(&spec).is_none(),
            "a restricted principal must be declined the parallel snapshot (serial fallback)"
        );
    }

    #[test]
    fn node_with_only_denied_label_is_invisible() {
        let (mut g, ada, acme, _r) = seed();
        // Can traverse Person, not Company.
        let oracle = StubOracle::default().traverse_label("Person");
        let authz = AuthorizedGraph::new(&mut g, oracle);
        // scan: only Ada (Person) visible, Acme (Company) filtered out.
        assert_eq!(authz.scan_nodes(), vec![ada]);
        // label scan of Company yields nothing (its only node is invisible).
        assert!(authz.scan_nodes_by_label("Company").is_empty());
        // Acme is not visible.
        assert!(!authz.node_exists(acme));
        assert!(authz.node_exists(ada));
        assert_eq!(authz.node_labels(acme), None);
    }

    #[test]
    fn denied_property_reads_as_absent_node_still_visible() {
        let (mut g, ada, _acme, _r) = seed();
        // Can see Person and read its name, but NOT its secret.
        let oracle = StubOracle::default()
            .traverse_label("Person")
            .read_property("Person", "name");
        let authz = AuthorizedGraph::new(&mut g, oracle);
        // The node stays visible.
        assert!(authz.node_exists(ada));
        // name is readable, secret is hidden (reads as None / absent).
        assert_eq!(authz.node_property(ada, "name"), Some(s("Ada")));
        assert_eq!(authz.node_property(ada, "secret"), None);
        // node_properties only returns the readable subset.
        let props = authz.node_properties(ada).expect("visible");
        assert_eq!(props, vec![("name".to_owned(), s("Ada"))]);
    }

    #[test]
    fn denied_rel_type_is_not_traversed() {
        let (mut g, ada, _acme, r) = seed();
        // Can traverse both endpoints' labels but NOT the WORKS_AT type.
        let oracle = StubOracle::default()
            .traverse_label("Person")
            .traverse_label("Company");
        let authz = AuthorizedGraph::new(&mut g, oracle);
        // expand from Ada yields nothing (type denied).
        assert!(authz.expand(ada, ExpandDirection::Both, &[]).is_empty());
        assert!(!authz.rel_exists(r));
        assert_eq!(authz.rel_data(r), None);
    }

    #[test]
    fn rel_with_invisible_endpoint_is_filtered() {
        let (mut g, ada, _acme, r) = seed();
        // Can traverse WORKS_AT and Person, but NOT Company (Acme endpoint invisible).
        let oracle = StubOracle::default()
            .traverse_label("Person")
            .traverse_rel_type("WORKS_AT");
        let authz = AuthorizedGraph::new(&mut g, oracle);
        // The rel dangles (Acme invisible) -> filtered out of the expand.
        assert!(authz.expand(ada, ExpandDirection::Both, &[]).is_empty());
        assert!(!authz.rel_exists(r));
    }

    #[test]
    fn readable_rel_property_visible_denied_hidden() {
        // Read grant on the rel property -> visible.
        let (mut g, _ada, _acme, r) = seed();
        let oracle = StubOracle::default()
            .traverse_label("Person")
            .traverse_label("Company")
            .traverse_rel_type("WORKS_AT")
            .read_rel_property("WORKS_AT", "role");
        let authz = AuthorizedGraph::new(&mut g, oracle);
        assert_eq!(authz.rel_property(r, "role"), Some(s("CEO")));

        // No read grant on the rel property (same seed, same ids) -> hidden, rel still visible.
        let (mut g2, _ada2, _acme2, r2) = seed();
        let oracle2 = StubOracle::default()
            .traverse_label("Person")
            .traverse_label("Company")
            .traverse_rel_type("WORKS_AT");
        let authz2 = AuthorizedGraph::new(&mut g2, oracle2);
        assert!(authz2.rel_exists(r2));
        assert_eq!(authz2.rel_property(r2, "role"), None);
        assert_eq!(authz2.rel_properties(r2), Some(vec![]));
    }

    #[test]
    fn write_to_denied_label_is_rejected_before_side_effect() {
        let (mut g, _ada, _acme, _r) = seed();
        let before = g.node_count();
        let oracle = StubOracle::default().write_label("Person"); // cannot write Company
        let mut authz = AuthorizedGraph::new(&mut g, oracle);
        let _ = authz.create_node(&["Company".to_owned()], &[]);
        assert!(authz.has_auth_error());
        let err = authz.take_auth_error().expect("denied");
        assert!(matches!(err, GraphusError::Security(_)));
        // No node was created (side effect rejected before the inner seam).
        assert_eq!(g.node_count(), before);
    }

    #[test]
    fn write_to_denied_property_is_rejected() {
        let (mut g, ada, _acme, _r) = seed();
        // Can write Person label but not its `name` property.
        let oracle = StubOracle::default()
            .traverse_label("Person")
            .write_label("Person");
        let mut authz = AuthorizedGraph::new(&mut g, oracle);
        authz.set_node_property(ada, "name", s("Eve"));
        assert!(authz.has_auth_error());
        // The property is unchanged in the inner graph.
        assert_eq!(g.node_property(ada, "name"), Some(s("Ada")));
    }

    #[test]
    fn write_to_denied_rel_type_is_rejected() {
        let (mut g, ada, acme, _r) = seed();
        let before = g.rel_count();
        let oracle = StubOracle::default().write_rel_type("KNOWS"); // not WORKS_AT
        let mut authz = AuthorizedGraph::new(&mut g, oracle);
        let _ = authz.create_rel("WORKS_AT", ada, acme, &[]);
        assert!(authz.has_auth_error());
        assert_eq!(g.rel_count(), before);
    }

    #[test]
    fn merge_and_replace_property_writes_are_gated() {
        // `SET n += map` and `SET n = map` require Write on each key under the node's labels.
        let (mut g, ada, _acme, _r) = seed();
        // Can write Person and its `nick`, but NOT `secret`.
        let oracle = StubOracle::default()
            .traverse_label("Person")
            .write_label("Person")
            .write_property("Person", "nick")
            .write_property("Person", "name")
            .write_property("Person", "secret");
        let mut authz = AuthorizedGraph::new(&mut g, oracle);
        // An allowed `+=` overlay succeeds.
        authz.merge_node_properties(ada, &[("nick".to_owned(), s("A"))]);
        assert!(!authz.has_auth_error());
        assert_eq!(g.node_property(ada, "nick"), Some(s("A")));

        // A `+=` overlay touching a denied key is rejected.
        let oracle2 = StubOracle::default()
            .traverse_label("Person")
            .write_label("Person")
            .write_property("Person", "name"); // not `surname`
        let mut authz2 = AuthorizedGraph::new(&mut g, oracle2);
        authz2.merge_node_properties(ada, &[("surname".to_owned(), s("Lovelace"))]);
        assert!(authz2.has_auth_error());
        assert_eq!(g.node_property(ada, "surname"), None);
    }

    #[test]
    fn write_to_denied_rel_property_is_rejected() {
        let (mut g, _ada, _acme, r) = seed();
        // Can traverse + write WORKS_AT but NOT its `role` property.
        let oracle = StubOracle::default()
            .traverse_label("Person")
            .traverse_label("Company")
            .traverse_rel_type("WORKS_AT")
            .write_rel_type("WORKS_AT");
        let mut authz = AuthorizedGraph::new(&mut g, oracle);
        authz.set_rel_property(r, "role", s("CTO"));
        assert!(authz.has_auth_error());
        assert_eq!(g.rel_property(r, "role"), Some(s("CEO")));

        // With the rel-property write grant, the same write succeeds.
        let (mut g2, _a2, _c2, r2) = seed();
        let oracle2 = StubOracle::default()
            .traverse_label("Person")
            .traverse_label("Company")
            .traverse_rel_type("WORKS_AT")
            .write_rel_type("WORKS_AT")
            .write_rel_property("WORKS_AT", "role");
        let mut authz2 = AuthorizedGraph::new(&mut g2, oracle2);
        authz2.set_rel_property(r2, "role", s("CTO"));
        assert!(!authz2.has_auth_error());
        assert_eq!(g2.rel_property(r2, "role"), Some(s("CTO")));
    }

    #[test]
    fn delete_denied_label_node_is_rejected() {
        let (mut g, ada, _acme, _r) = seed();
        let before = g.node_count();
        // Can traverse Person but not write it.
        let oracle = StubOracle::default().traverse_label("Person");
        let mut authz = AuthorizedGraph::new(&mut g, oracle);
        authz.delete_node(ada);
        assert!(authz.has_auth_error());
        assert_eq!(g.node_count(), before);
    }

    #[test]
    fn allowed_subset_matches_unrestricted_rows_exactly() {
        // A principal granted full read over every label/type/property must see EXACTLY the
        // unrestricted result for a scan + property read + expand.
        let (g_base, ada_b, acme_b, r_b) = seed();
        let base_scan = g_base.scan_nodes();
        let base_props = g_base.node_properties(ada_b);
        let base_expand = g_base.expand(ada_b, ExpandDirection::Both, &[]);
        let base_rel = g_base.rel_data(r_b);
        let _ = acme_b;

        let (mut g, ada, _acme, _r) = seed();
        let oracle = StubOracle::default()
            .traverse_label("Person")
            .traverse_label("Company")
            .read_property("Person", "name")
            .read_property("Person", "secret")
            .read_property("Company", "name")
            .traverse_rel_type("WORKS_AT")
            .read_rel_property("WORKS_AT", "role");
        let authz = AuthorizedGraph::new(&mut g, oracle);
        assert_eq!(authz.scan_nodes(), base_scan);
        assert_eq!(authz.node_properties(ada), base_props);
        assert_eq!(authz.expand(ada, ExpandDirection::Both, &[]), base_expand);
        assert_eq!(authz.rel_data(r_b), base_rel);
    }

    #[test]
    fn unlabelled_node_is_visible() {
        let mut g = MemGraph::new();
        let n = g.add_node([] as [&str; 0], [("k", Value::Integer(1))]);
        // Deny-by-default oracle (no grants at all).
        let oracle = StubOracle::default();
        let authz = AuthorizedGraph::new(&mut g, oracle);
        // An unlabelled node has nothing to deny -> visible.
        assert!(authz.node_exists(n));
        assert_eq!(authz.scan_nodes(), vec![n]);
        // ...but a property with no label-grant is still hidden (no label grants Read on it).
        assert_eq!(authz.node_property(n, "k"), None);
    }

    // ---- DENY-across-labels precedence on multi-label nodes (CWE-863 regression) ------------------
    //
    // The exploit these guard: a node bearing labels `[Report, Classified]` where a broad grant
    // reaches BOTH labels but an explicit DENY targets ONE of them. The pre-fix executor combined the
    // per-label `can_*` booleans with a bare `OR` union (`labels.iter().any(...)`), computing
    // `∃l: granted(l) ∧ ¬denied(l)` — so the node/property/write leaked through the *other*
    // (non-denied) label. The correct Neo4j rule is `(∃l: granted(l)) ∧ (∄l: denied(l))`: a DENY on
    // ANY label of the node wins. Each test grants the capability on BOTH labels (the faithful stub
    // model of a graph-wide grant that reaches every label) and denies exactly one.

    /// One multi-label node `(:Report:Classified {contents, title})` for the CWE-863 regression set.
    fn multilabel() -> (MemGraph, NodeId) {
        let mut g = MemGraph::new();
        let n = g.add_node(
            ["Report", "Classified"],
            [("contents", s("top-secret")), ("title", s("Q3"))],
        );
        (g, n)
    }

    #[test]
    fn deny_traverse_on_any_label_hides_multilabel_node() {
        // DENY TRAVERSE on :Classified hides the whole node, even though :Report grants traverse.
        let (mut g, n) = multilabel();
        let oracle = StubOracle::default()
            .traverse_label("Report")
            .traverse_label("Classified")
            .read_property("Report", "contents")
            .read_property("Classified", "contents")
            .deny_traverse_label("Classified");
        let authz = AuthorizedGraph::new(&mut g, oracle);
        // Invisible through every read path (not just the :Classified one).
        assert!(!authz.node_exists(n), "a DENY on any label hides the node");
        assert!(authz.scan_nodes().is_empty(), "scan filters it out");
        assert!(
            authz.scan_nodes_by_label("Report").is_empty(),
            "even a :Report label scan must not leak the denied node"
        );
        assert!(authz.scan_nodes_by_label("Classified").is_empty());
        assert_eq!(authz.node_labels(n), None, "labels report as absent");
        assert_eq!(
            authz.node_property(n, "contents"),
            None,
            "property unreadable"
        );
        assert_eq!(authz.node_properties(n), None);
    }

    #[test]
    fn deny_read_property_on_any_label_hides_property_not_multilabel_node() {
        // DENY READ on :Classified.contents hides that property (NULL) but leaves the node visible
        // (DENY READ does not block traverse), even though a read grant reaches contents via :Report.
        let (mut g, n) = multilabel();
        let oracle = StubOracle::default()
            .traverse_label("Report")
            .traverse_label("Classified")
            .read_property("Report", "contents")
            .read_property("Classified", "contents")
            .read_property("Report", "title")
            .read_property("Classified", "title")
            .deny_read_property("Classified", "contents");
        let authz = AuthorizedGraph::new(&mut g, oracle);
        assert!(authz.node_exists(n), "DENY READ leaves the node visible");
        assert_eq!(
            authz.node_property(n, "contents"),
            None,
            "the denied property must not leak via :Report"
        );
        assert_eq!(
            authz.node_property(n, "title"),
            Some(s("Q3")),
            "other props read"
        );
        let props = authz.node_properties(n).expect("node visible");
        assert_eq!(props.len(), 1, "only the readable prop survives: {props:?}");
        assert_eq!(props[0], ("title".to_owned(), s("Q3")));
    }

    #[test]
    fn deny_write_property_on_any_label_blocks_set_on_multilabel_node() {
        // SET n.contents: a write grant reaches contents via :Report, but DENY WRITE on
        // :Classified.contents rejects the write with no side effect.
        let (mut g, n) = multilabel();
        let oracle = StubOracle::default()
            .traverse_label("Report")
            .traverse_label("Classified")
            .write_property("Report", "contents")
            .write_property("Classified", "contents")
            .deny_write_property("Classified", "contents");
        let mut authz = AuthorizedGraph::new(&mut g, oracle);
        authz.set_node_property(n, "contents", s("leaked"));
        assert!(authz.has_auth_error(), "the denied write is captured");
        assert_eq!(
            g.node_property(n, "contents"),
            Some(s("top-secret")),
            "no side effect: the property is unchanged"
        );
    }

    #[test]
    fn deny_write_label_on_any_label_blocks_delete_of_multilabel_node() {
        // DELETE (:Report:Classified): a write grant reaches :Report, but DENY WRITE on :Classified
        // refuses the whole-node delete.
        let (mut g, n) = multilabel();
        let before = g.node_count();
        let oracle = StubOracle::default()
            .traverse_label("Report")
            .traverse_label("Classified")
            .write_label("Report")
            .write_label("Classified")
            .deny_write_label("Classified");
        let mut authz = AuthorizedGraph::new(&mut g, oracle);
        authz.delete_node(n);
        assert!(
            authz.has_auth_error(),
            "the denied whole-node write is rejected"
        );
        assert_eq!(g.node_count(), before, "no node was deleted");
    }

    #[test]
    fn deny_write_property_blocks_create_of_multilabel_node() {
        // CREATE (:Report:Classified {contents}): write granted on both labels + the property, but a
        // DENY WRITE on :Classified.contents rejects the create before any side effect.
        let mut g = MemGraph::new();
        let before = g.node_count();
        let oracle = StubOracle::default()
            .write_label("Report")
            .write_label("Classified")
            .write_property("Report", "contents")
            .write_property("Classified", "contents")
            .deny_write_property("Classified", "contents");
        let mut authz = AuthorizedGraph::new(&mut g, oracle);
        let _ = authz.create_node(
            &["Report".to_owned(), "Classified".to_owned()],
            &[("contents".to_owned(), s("top-secret"))],
        );
        assert!(
            authz.has_auth_error(),
            "the denied property on create is rejected"
        );
        assert_eq!(g.node_count(), before, "no node was created");
    }

    #[test]
    fn multilabel_node_visible_when_one_label_grants_and_none_denied() {
        // The GRANT union is PRESERVED: a node (:Report:Classified) with traverse granted on :Report
        // only (:Classified merely ungranted, NOT denied) stays visible — only an explicit DENY hides
        // it. This pins that the fix restricts on DENY, never on a mere missing grant.
        let (mut g, n) = multilabel();
        let oracle = StubOracle::default()
            .traverse_label("Report")
            .read_property("Report", "title");
        let authz = AuthorizedGraph::new(&mut g, oracle);
        assert!(
            authz.node_exists(n),
            "granted on one label, denied on none -> visible"
        );
        assert_eq!(authz.node_property(n, "title"), Some(s("Q3")));
    }
}
