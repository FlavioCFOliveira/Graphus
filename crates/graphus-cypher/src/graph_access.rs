//! The executor's **graph-access seam** (`04-technical-design.md` §7.4) and an in-memory reference
//! implementation for testing.
//!
//! The Cypher executor ([`crate::executor`]) reads and writes the graph **only** through the
//! [`GraphAccess`] trait. This mirrors how `graphus-txn` was built over a `VersionedStore` seam:
//! the executor proves its correctness against a small, fully-deterministic in-memory implementation
//! ([`MemGraph`]) here, while the *real* wiring to the `graphus-storage` / `graphus-txn` /
//! `graphus-index` stack is a **separate** follow-up (roadmap sub-task #38). Keeping the seam narrow
//! and transaction-scoped is what lets the two be developed and tested independently.
//!
//! # The seam is transaction-scoped
//!
//! All reads and writes happen inside **one logical transaction**, which the implementation owns.
//! The executor never sees timestamps, snapshots, or the WAL — it asks for nodes, relationships and
//! properties, and the implementation resolves visibility against the transaction it holds. For the
//! in-memory [`MemGraph`] there is no MVCC: the "transaction" is simply the live map, mutated in
//! place. Atomic rollback on error / cancellation is the **real** transaction layer's concern
//! (sub-task #38); see the note on [`crate::executor::CancellationToken`].
//!
//! # Identity
//!
//! Nodes and relationships are identified by an **opaque** [`NodeId`] / [`RelId`]. The executor
//! treats them as nominal handles and never inspects their representation, so the real backend is
//! free to use physical record ids, `ElementId`s, or anything else. [`MemGraph`] uses dense `u64`
//! counters.
//!
//! # Property values
//!
//! Property values are [`graphus_core::Value`]s, restricted to the **property subtype** (no
//! structural values; `04 §7.2`). The seam does **not** re-validate that restriction — write
//! callers in the executor pass already-evaluated property values, and the real backend enforces the
//! subtype at its write boundary (sub-task #38). [`MemGraph`] stores whatever it is given, which is
//! sufficient and honest for executor-correctness testing.

use std::collections::BTreeMap;

use graphus_core::Value;

use crate::ast::RelDirection;

/// An **opaque** node identifier handed out by a [`GraphAccess`] implementation.
///
/// The executor treats it as a nominal handle: it may be stored, compared for identity, and passed
/// back to the seam, but its internal representation is never interpreted. [`MemGraph`] uses a dense
/// `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub u64);

/// An **opaque** relationship identifier handed out by a [`GraphAccess`] implementation.
///
/// As with [`NodeId`], the executor never inspects the representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelId(pub u64);

/// The arrow direction a relationship expansion follows, relative to the anchor node.
///
/// Derived from the pattern's [`RelDirection`] (the executor maps the AST direction onto this seam
/// vocabulary): `(a)-[r]->(b)` expands [`Outgoing`](Self::Outgoing) from `a`, `(a)<-[r]-(b)` expands
/// [`Incoming`](Self::Incoming), and an undirected `(a)-[r]-(b)` expands [`Both`](Self::Both).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum ExpandDirection {
    /// Follow relationships where the anchor is the **start** node (`-->`).
    Outgoing,
    /// Follow relationships where the anchor is the **end** node (`<--`).
    Incoming,
    /// Follow relationships in either direction (`--`).
    Both,
}

impl ExpandDirection {
    /// Maps a pattern [`RelDirection`] onto the expansion direction relative to the **anchor** of
    /// the traversal (the already-bound `from`).
    pub fn from_pattern(direction: RelDirection) -> Self {
        match direction {
            RelDirection::LeftToRight => Self::Outgoing,
            RelDirection::RightToLeft => Self::Incoming,
            RelDirection::Undirected => Self::Both,
        }
    }
}

/// One incident relationship discovered by [`GraphAccess::expand`]: the relationship itself plus the
/// node reached through it (the **other** endpoint relative to the anchor that was expanded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Incident {
    /// The traversed relationship.
    pub rel: RelId,
    /// The node at the far end of the relationship (the endpoint that is **not** the anchor).
    pub neighbour: NodeId,
}

/// A read-only snapshot of a relationship's structural fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct RelData {
    /// The relationship type name.
    pub rel_type: String,
    /// The start (source) node.
    pub start: NodeId,
    /// The end (target) node.
    pub end: NodeId,
}

/// The graph the Cypher executor reads and writes, scoped to one logical transaction
/// (`04 §7.4`).
///
/// The executor depends on this trait alone (never on a concrete store), so it is testable against
/// [`MemGraph`] and later re-targetable to the real `graphus-storage`/`graphus-txn`/`graphus-index`
/// stack (sub-task #38) without changing the operator code.
///
/// # Reads
///
/// Scans ([`scan_nodes`](Self::scan_nodes), [`scan_nodes_by_label`](Self::scan_nodes_by_label)) and
/// expansion ([`expand`](Self::expand)) return **owned `Vec`s** in v1: this keeps the seam object-safe
/// and the in-memory implementation trivial. Tuple-at-a-time / vectorised cursors are the
/// optimisation `04 §7.4` describes ("vectorized leaf scans are an optimization, fine to do
/// tuple-at-a-time first") and are a deferred follow-up — the executor already pulls row-at-a-time on
/// top, so the result-set shape it produces is unaffected.
///
/// # Indexes
///
/// [`index_seek_eq`](Self::index_seek_eq) / [`index_seek_range`](Self::index_seek_range) are
/// **optional**: the default implementations return `None`, signalling "no index available", and the
/// executor falls back to a scan-and-filter. An implementation with real indexes overrides them.
///
/// # Writes
///
/// Writes mutate the implementation's owned transaction in place. They return the created/affected
/// ids so the executor can bind them into result rows.
pub trait GraphAccess {
    // ---- reads --------------------------------------------------------------------------------

    /// All node ids currently visible, in a deterministic order.
    fn scan_nodes(&self) -> Vec<NodeId>;

    /// All node ids carrying `label`, in a deterministic order.
    fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId>;

    /// The relationships incident to `node` in `direction`, filtered to `types` (empty = any type).
    ///
    /// Each returned [`Incident`] carries the relationship and its **other** endpoint. A self-loop
    /// (start == end == `node`) is reported **once per direction it matches**, which the executor
    /// deduplicates by relationship id where the query asks for distinct incident relationships
    /// (`04 §2.4`).
    fn expand(&self, node: NodeId, direction: ExpandDirection, types: &[String]) -> Vec<Incident>;

    /// Whether `node` currently exists (is visible).
    fn node_exists(&self, node: NodeId) -> bool;

    /// Whether `rel` currently exists (is visible).
    fn rel_exists(&self, rel: RelId) -> bool;

    /// The labels of `node` (empty if it has none), or `None` if the node does not exist.
    fn node_labels(&self, node: NodeId) -> Option<Vec<String>>;

    /// The structural fields of `rel`, or `None` if it does not exist.
    fn rel_data(&self, rel: RelId) -> Option<RelData>;

    /// The value of `node`'s property `key`, or `None` if the node or property is absent.
    fn node_property(&self, node: NodeId, key: &str) -> Option<Value>;

    /// The value of `rel`'s property `key`, or `None` if the relationship or property is absent.
    fn rel_property(&self, rel: RelId, key: &str) -> Option<Value>;

    /// All of `node`'s properties as `(key, value)` pairs in a deterministic (key-sorted) order, or
    /// `None` if the node does not exist.
    fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>>;

    /// All of `rel`'s properties as `(key, value)` pairs in a deterministic (key-sorted) order, or
    /// `None` if the relationship does not exist.
    fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>>;

    /// An **optional** index equality seek: node ids of `label` whose `property` equals `value`.
    ///
    /// Returns `None` when the implementation has no usable index (the executor then falls back to a
    /// label scan + residual filter). The default is `None`.
    fn index_seek_eq(&self, _label: &str, _property: &str, _value: &Value) -> Option<Vec<NodeId>> {
        None
    }

    /// An **optional** index range seek. `lower`/`upper` are `(value, inclusive)` bounds; either may
    /// be `None` for an open side. Returns `None` when no index is usable (default).
    fn index_seek_range(
        &self,
        _label: &str,
        _property: &str,
        _lower: Option<(&Value, bool)>,
        _upper: Option<(&Value, bool)>,
    ) -> Option<Vec<NodeId>> {
        None
    }

    // ---- writes -------------------------------------------------------------------------------

    /// Creates a node with `labels` and `properties`, returning its new id.
    fn create_node(&mut self, labels: &[String], properties: &[(String, Value)]) -> NodeId;

    /// Creates a relationship of `rel_type` from `start` to `end` with `properties`, returning its
    /// new id.
    fn create_rel(
        &mut self,
        rel_type: &str,
        start: NodeId,
        end: NodeId,
        properties: &[(String, Value)],
    ) -> RelId;

    /// Sets `node`'s property `key` to `value`. A [`Value::Null`] **removes** the property (Cypher
    /// `SET n.p = null` semantics). No-op if the node does not exist.
    fn set_node_property(&mut self, node: NodeId, key: &str, value: Value);

    /// Sets `rel`'s property `key` to `value`. A [`Value::Null`] **removes** the property. No-op if
    /// the relationship does not exist.
    fn set_rel_property(&mut self, rel: RelId, key: &str, value: Value);

    /// Adds `labels` to `node` (idempotent per label). No-op if the node does not exist.
    fn add_labels(&mut self, node: NodeId, labels: &[String]);

    /// Removes `labels` from `node` (idempotent). No-op if the node does not exist.
    fn remove_labels(&mut self, node: NodeId, labels: &[String]);

    /// Removes `node`'s property `key` (idempotent). No-op if absent.
    fn remove_node_property(&mut self, node: NodeId, key: &str);

    /// Removes `rel`'s property `key` (idempotent). No-op if absent.
    fn remove_rel_property(&mut self, rel: RelId, key: &str);

    /// Replaces `node`'s properties entirely with `properties` (`SET n = map`). No-op if absent.
    fn replace_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]);

    /// Merges `properties` into `node`'s properties, keeping unmentioned ones (`SET n += map`); a
    /// [`Value::Null`] value removes that key. No-op if absent.
    fn merge_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]);

    /// The relationship ids incident to `node` in **either** direction (used by `DETACH DELETE`).
    fn incident_rels(&self, node: NodeId) -> Vec<RelId>;

    /// Deletes `rel` (idempotent). No-op if already gone.
    fn delete_rel(&mut self, rel: RelId);

    /// Deletes `node` (idempotent). The caller (executor) is responsible for first removing incident
    /// relationships for a non-`DETACH` delete check (`04 §7.3`).
    fn delete_node(&mut self, node: NodeId);

    // ---- statistics ---------------------------------------------------------------------------

    /// An **optional** statistics view of this graph for cardinality estimation
    /// ([`crate::cardinality`]).
    ///
    /// Returns `None` by default — "no statistics available; the planner uses its documented
    /// constant fallbacks" (see [`crate::cardinality`]). A backend that tracks node/relationship
    /// counts overrides this to return `Some(self)`; [`MemGraph`] does, since it knows its full
    /// contents. Returning `Option<&dyn Statistics>` keeps the trait object-safe.
    fn statistics(&self) -> Option<&dyn crate::statistics::Statistics> {
        None
    }
}

// =================================================================================================
// MemGraph — the in-memory reference implementation
// =================================================================================================

/// A node record in [`MemGraph`].
#[derive(Debug, Clone, Default, PartialEq)]
struct MemNode {
    /// The node's labels (a set, kept sorted for determinism).
    labels: Vec<String>,
    /// The node's properties (key-sorted for determinism).
    props: BTreeMap<String, Value>,
}

/// A relationship record in [`MemGraph`].
#[derive(Debug, Clone, PartialEq)]
struct MemRel {
    rel_type: String,
    start: NodeId,
    end: NodeId,
    props: BTreeMap<String, Value>,
}

/// An in-memory [`GraphAccess`] for executor-correctness tests.
///
/// Models the property graph directly: `nodes: id -> (labels, props)` and
/// `rels: id -> (type, start, end, props)`, with dense `u64` ids issued by monotonic counters (ids
/// are never reused, so a deleted id never collides with a fresh one — matching the stable-identity
/// guarantee of `04 §2.2`). There is no MVCC; the "transaction" is the live map.
///
/// # Examples
///
/// ```
/// use graphus_core::Value;
/// use graphus_cypher::graph_access::{GraphAccess, MemGraph};
///
/// let mut g = MemGraph::new();
/// let a = g.add_node(["Person"], [("name", Value::String("Ada".into()))]);
/// let b = g.add_node(["Person"], [("name", Value::String("Bob".into()))]);
/// g.add_rel("KNOWS", a, b, [("since", Value::Integer(2010))]);
///
/// assert_eq!(g.scan_nodes_by_label("Person").len(), 2);
/// assert_eq!(g.node_property(a, "name"), Some(Value::String("Ada".into())));
/// ```
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct MemGraph {
    nodes: BTreeMap<NodeId, MemNode>,
    rels: BTreeMap<RelId, MemRel>,
    next_node: u64,
    next_rel: u64,
}

impl MemGraph {
    /// An empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seeds a node with `labels` and `properties`, returning its id (test/setup helper).
    ///
    /// Accepts any iterables of string-ish labels and `(key, value)` property pairs for ergonomic
    /// graph construction in tests.
    pub fn add_node<L, S, P, K>(&mut self, labels: L, properties: P) -> NodeId
    where
        L: IntoIterator<Item = S>,
        S: Into<String>,
        P: IntoIterator<Item = (K, Value)>,
        K: Into<String>,
    {
        let labels: Vec<String> = labels.into_iter().map(Into::into).collect();
        let props: Vec<(String, Value)> =
            properties.into_iter().map(|(k, v)| (k.into(), v)).collect();
        self.create_node(&labels, &props)
    }

    /// Seeds a relationship of `rel_type` from `start` to `end`, returning its id (test/setup
    /// helper).
    pub fn add_rel<P, K>(
        &mut self,
        rel_type: impl Into<String>,
        start: NodeId,
        end: NodeId,
        properties: P,
    ) -> RelId
    where
        P: IntoIterator<Item = (K, Value)>,
        K: Into<String>,
    {
        let props: Vec<(String, Value)> =
            properties.into_iter().map(|(k, v)| (k.into(), v)).collect();
        self.create_rel(&rel_type.into(), start, end, &props)
    }

    /// The number of live nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The number of live relationships.
    #[must_use]
    pub fn rel_count(&self) -> usize {
        self.rels.len()
    }
}

/// Whether `rel`'s type is among `types` (empty = any).
fn type_matches(rel_type: &str, types: &[String]) -> bool {
    types.is_empty() || types.iter().any(|t| t == rel_type)
}

impl GraphAccess for MemGraph {
    fn scan_nodes(&self) -> Vec<NodeId> {
        self.nodes.keys().copied().collect()
    }

    fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|(_, n)| n.labels.iter().any(|l| l == label))
            .map(|(id, _)| *id)
            .collect()
    }

    fn expand(&self, node: NodeId, direction: ExpandDirection, types: &[String]) -> Vec<Incident> {
        let mut out = Vec::new();
        for (rid, r) in &self.rels {
            if !type_matches(&r.rel_type, types) {
                continue;
            }
            // A self-loop participates in both the start- and end-side walks; we report it once per
            // matching side so the executor can deduplicate where the query demands distinctness
            // (`04 §2.4`).
            let touches_as_start = r.start == node;
            let touches_as_end = r.end == node;
            let want_out = matches!(direction, ExpandDirection::Outgoing | ExpandDirection::Both);
            let want_in = matches!(direction, ExpandDirection::Incoming | ExpandDirection::Both);
            if touches_as_start && want_out {
                out.push(Incident {
                    rel: *rid,
                    neighbour: r.end,
                });
            }
            if touches_as_end && want_in {
                out.push(Incident {
                    rel: *rid,
                    neighbour: r.start,
                });
            }
        }
        out
    }

    fn node_exists(&self, node: NodeId) -> bool {
        self.nodes.contains_key(&node)
    }

    fn rel_exists(&self, rel: RelId) -> bool {
        self.rels.contains_key(&rel)
    }

    fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
        self.nodes.get(&node).map(|n| n.labels.clone())
    }

    fn rel_data(&self, rel: RelId) -> Option<RelData> {
        self.rels.get(&rel).map(|r| RelData {
            rel_type: r.rel_type.clone(),
            start: r.start,
            end: r.end,
        })
    }

    fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
        self.nodes
            .get(&node)
            .and_then(|n| n.props.get(key).cloned())
    }

    fn rel_property(&self, rel: RelId, key: &str) -> Option<Value> {
        self.rels.get(&rel).and_then(|r| r.props.get(key).cloned())
    }

    fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
        self.nodes.get(&node).map(|n| {
            n.props
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
    }

    fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
        self.rels.get(&rel).map(|r| {
            r.props
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
    }

    fn create_node(&mut self, labels: &[String], properties: &[(String, Value)]) -> NodeId {
        let id = NodeId(self.next_node);
        self.next_node += 1;
        let mut node = MemNode::default();
        for l in labels {
            if !node.labels.iter().any(|existing| existing == l) {
                node.labels.push(l.clone());
            }
        }
        node.labels.sort();
        for (k, v) in properties {
            // A null property value is not stored (Cypher does not persist null properties).
            if !v.is_null() {
                node.props.insert(k.clone(), v.clone());
            }
        }
        self.nodes.insert(id, node);
        id
    }

    fn create_rel(
        &mut self,
        rel_type: &str,
        start: NodeId,
        end: NodeId,
        properties: &[(String, Value)],
    ) -> RelId {
        let id = RelId(self.next_rel);
        self.next_rel += 1;
        let mut props = BTreeMap::new();
        for (k, v) in properties {
            if !v.is_null() {
                props.insert(k.clone(), v.clone());
            }
        }
        self.rels.insert(
            id,
            MemRel {
                rel_type: rel_type.to_owned(),
                start,
                end,
                props,
            },
        );
        id
    }

    fn set_node_property(&mut self, node: NodeId, key: &str, value: Value) {
        if let Some(n) = self.nodes.get_mut(&node) {
            if value.is_null() {
                n.props.remove(key);
            } else {
                n.props.insert(key.to_owned(), value);
            }
        }
    }

    fn set_rel_property(&mut self, rel: RelId, key: &str, value: Value) {
        if let Some(r) = self.rels.get_mut(&rel) {
            if value.is_null() {
                r.props.remove(key);
            } else {
                r.props.insert(key.to_owned(), value);
            }
        }
    }

    fn add_labels(&mut self, node: NodeId, labels: &[String]) {
        if let Some(n) = self.nodes.get_mut(&node) {
            for l in labels {
                if !n.labels.iter().any(|existing| existing == l) {
                    n.labels.push(l.clone());
                }
            }
            n.labels.sort();
        }
    }

    fn remove_labels(&mut self, node: NodeId, labels: &[String]) {
        if let Some(n) = self.nodes.get_mut(&node) {
            n.labels.retain(|l| !labels.iter().any(|r| r == l));
        }
    }

    fn remove_node_property(&mut self, node: NodeId, key: &str) {
        if let Some(n) = self.nodes.get_mut(&node) {
            n.props.remove(key);
        }
    }

    fn remove_rel_property(&mut self, rel: RelId, key: &str) {
        if let Some(r) = self.rels.get_mut(&rel) {
            r.props.remove(key);
        }
    }

    fn replace_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        if let Some(n) = self.nodes.get_mut(&node) {
            n.props.clear();
            for (k, v) in properties {
                if !v.is_null() {
                    n.props.insert(k.clone(), v.clone());
                }
            }
        }
    }

    fn merge_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        if let Some(n) = self.nodes.get_mut(&node) {
            for (k, v) in properties {
                if v.is_null() {
                    n.props.remove(k);
                } else {
                    n.props.insert(k.clone(), v.clone());
                }
            }
        }
    }

    fn incident_rels(&self, node: NodeId) -> Vec<RelId> {
        self.rels
            .iter()
            .filter(|(_, r)| r.start == node || r.end == node)
            .map(|(id, _)| *id)
            .collect()
    }

    fn delete_rel(&mut self, rel: RelId) {
        self.rels.remove(&rel);
    }

    fn delete_node(&mut self, node: NodeId) {
        self.nodes.remove(&node);
    }

    fn statistics(&self) -> Option<&dyn crate::statistics::Statistics> {
        // MemGraph knows its full contents, so it always provides exact counts.
        Some(self)
    }
}

/// Exact, point-in-time count statistics over a [`MemGraph`]'s live map.
///
/// Since the in-memory graph owns its full contents, every query is answered **exactly** by
/// iterating the maps: per-label / per-type queries always return `Some(_)` (an absent label /
/// type is an exact `Some(0)`, never the `None` "unknown" sentinel). The counts reflect the map at
/// the instant of the call.
impl crate::statistics::Statistics for MemGraph {
    fn total_nodes(&self) -> u64 {
        self.nodes.len() as u64
    }

    fn nodes_with_label(&self, label: &str) -> Option<u64> {
        let count = self
            .nodes
            .values()
            .filter(|n| n.labels.iter().any(|l| l == label))
            .count();
        Some(count as u64)
    }

    fn total_relationships(&self) -> u64 {
        self.rels.len() as u64
    }

    fn relationships_with_type(&self, rel_type: &str) -> Option<u64> {
        let count = self
            .rels
            .values()
            .filter(|r| r.rel_type == rel_type)
            .count();
        Some(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Value {
        Value::String(v.to_owned())
    }

    #[test]
    fn seed_and_scan() {
        let mut g = MemGraph::new();
        let a = g.add_node(["Person"], [("name", s("Ada"))]);
        let b = g.add_node(["Person", "Admin"], [("name", s("Bob"))]);
        let _c = g.add_node(["Company"], [("name", s("Acme"))]);

        assert_eq!(g.scan_nodes().len(), 3);
        assert_eq!(g.scan_nodes_by_label("Person").len(), 2);
        assert_eq!(g.scan_nodes_by_label("Admin"), vec![b]);
        assert_eq!(g.node_property(a, "name"), Some(s("Ada")));
        // Labels are stored sorted and deduplicated.
        assert_eq!(
            g.node_labels(b),
            Some(vec!["Admin".to_owned(), "Person".to_owned()])
        );
    }

    #[test]
    fn expand_respects_direction_and_type() {
        let mut g = MemGraph::new();
        let a = g.add_node(["X"], [] as [(&str, Value); 0]);
        let b = g.add_node(["X"], [] as [(&str, Value); 0]);
        let r = g.add_rel("KNOWS", a, b, [] as [(&str, Value); 0]);
        let _r2 = g.add_rel("LIKES", a, b, [] as [(&str, Value); 0]);

        // Outgoing KNOWS from a → reaches b once.
        let out = g.expand(a, ExpandDirection::Outgoing, &["KNOWS".to_owned()]);
        assert_eq!(
            out,
            vec![Incident {
                rel: r,
                neighbour: b
            }]
        );
        // Incoming from a (a is never an end node) → none.
        assert!(g.expand(a, ExpandDirection::Incoming, &[]).is_empty());
        // Incoming to b for any type → both rels.
        assert_eq!(g.expand(b, ExpandDirection::Incoming, &[]).len(), 2);
        // Both directions, any type, from a → both rels (a is start of each).
        assert_eq!(g.expand(a, ExpandDirection::Both, &[]).len(), 2);
    }

    #[test]
    fn self_loop_reports_once_per_matching_side() {
        let mut g = MemGraph::new();
        let a = g.add_node(["X"], [] as [(&str, Value); 0]);
        let _ = g.add_rel("R", a, a, [] as [(&str, Value); 0]);
        // Both-direction expand sees the self-loop twice (once as start, once as end) — the
        // executor deduplicates by rel id (`04 §2.4`).
        assert_eq!(g.expand(a, ExpandDirection::Both, &[]).len(), 2);
        // A single direction sees it once.
        assert_eq!(g.expand(a, ExpandDirection::Outgoing, &[]).len(), 1);
    }

    #[test]
    fn writes_mutate_and_null_removes_property() {
        let mut g = MemGraph::new();
        let a = g.add_node([] as [&str; 0], [("p", Value::Integer(1))]);
        g.set_node_property(a, "q", Value::Integer(2));
        assert_eq!(g.node_property(a, "q"), Some(Value::Integer(2)));
        // SET ... = null removes the property.
        g.set_node_property(a, "p", Value::Null);
        assert_eq!(g.node_property(a, "p"), None);

        g.add_labels(a, &["L".to_owned(), "L".to_owned()]);
        assert_eq!(g.node_labels(a), Some(vec!["L".to_owned()]));
        g.remove_labels(a, &["L".to_owned()]);
        assert_eq!(g.node_labels(a), Some(vec![]));
    }

    #[test]
    fn merge_and_replace_properties() {
        let mut g = MemGraph::new();
        let a = g.add_node(
            [] as [&str; 0],
            [("a", Value::Integer(1)), ("b", Value::Integer(2))],
        );
        g.merge_node_properties(
            a,
            &[
                ("b".to_owned(), Value::Integer(20)),
                ("c".to_owned(), Value::Integer(3)),
            ],
        );
        assert_eq!(g.node_property(a, "a"), Some(Value::Integer(1)));
        assert_eq!(g.node_property(a, "b"), Some(Value::Integer(20)));
        assert_eq!(g.node_property(a, "c"), Some(Value::Integer(3)));
        // Replace wipes everything not in the map.
        g.replace_node_properties(a, &[("z".to_owned(), Value::Integer(9))]);
        assert_eq!(g.node_property(a, "a"), None);
        assert_eq!(g.node_property(a, "z"), Some(Value::Integer(9)));
    }

    #[test]
    fn delete_node_and_rel() {
        let mut g = MemGraph::new();
        let a = g.add_node([] as [&str; 0], [] as [(&str, Value); 0]);
        let b = g.add_node([] as [&str; 0], [] as [(&str, Value); 0]);
        let r = g.add_rel("R", a, b, [] as [(&str, Value); 0]);
        assert_eq!(g.incident_rels(a), vec![r]);
        g.delete_rel(r);
        assert!(!g.rel_exists(r));
        g.delete_node(a);
        assert!(!g.node_exists(a));
        assert!(g.node_exists(b));
    }

    #[test]
    fn ids_are_never_reused() {
        let mut g = MemGraph::new();
        let a = g.add_node([] as [&str; 0], [] as [(&str, Value); 0]);
        g.delete_node(a);
        let b = g.add_node([] as [&str; 0], [] as [(&str, Value); 0]);
        assert_ne!(a, b, "a fresh id must never collide with a deleted one");
    }
}
