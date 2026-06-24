//! **Materialized result values** (`04-technical-design.md` §7.2 structural value classes, §8.3
//! the one-`Value`-model wire boundary).
//!
//! The executor's row cells are [`RowValue`](crate::runtime::RowValue)s that carry **opaque ids**:
//! a [`Node`](crate::runtime::RowValue::Node) / [`Rel`](crate::runtime::RowValue::Rel) /
//! [`Path`](crate::runtime::RowValue::Path) is a handle resolved *lazily* through the
//! [`GraphAccess`](crate::graph_access::GraphAccess) seam (see the [`runtime`](crate::runtime) docs).
//! That laziness is exactly right inside the engine, but a **wire protocol** (Bolt PackStream, REST
//! Jolt/CBOR) must emit the entity's labels, type, endpoints and properties — not a bare id.
//!
//! [`MaterializedValue`] is the **resolved** form of a result cell: every entity has had its labels /
//! type / endpoints / properties read through the graph seam. [`Cursor::next_materialized`] (and
//! [`Cursor::materialize_row`]) produce it, reading through the **same** `&mut dyn GraphAccess` the
//! cursor already holds. Two consequences fall out for free, with no extra code:
//!
//! - **RBAC (rmp #93)**: when the cursor's graph is an
//!   [`AuthorizedGraph`](crate::authorized_graph::AuthorizedGraph), a property the principal may not
//!   see is already `None` and an invisible node is already filtered *before* materialization ever
//!   asks — the resolver inherits the decorator's filtering verbatim.
//! - **MVCC visibility**: the seam answers against the cursor's transaction snapshot, so a
//!   materialized entity reflects exactly the version the query sees.
//!
//! The lossy id-flattening this replaces lived in the server (`project_value`); it is deleted there.
//! [`graphus_core::Value`] is **unchanged** — the structural classes stay local to the query runtime
//! exactly as `04 §7.2` intends, so the executor's value-model operations (equality, ordering,
//! `DISTINCT`) and the openCypher TCK comparison path are untouched. This type exists **only** at the
//! result-egress boundary, never inside an operator.

use graphus_core::Value;

use crate::graph_access::GraphAccess;
use crate::runtime::{PathValue, Row, RowValue};

/// A fully-resolved node carried in a [`MaterializedValue`]: its id plus the labels and properties
/// read through the graph seam at materialization time.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct MaterializedNode {
    /// The opaque node id (the same `u64` the executor's [`NodeId`](crate::graph_access::NodeId)
    /// wraps).
    pub id: u64,
    /// The node's labels, in the seam's deterministic order. Empty if the node has none.
    pub labels: Vec<String>,
    /// The node's properties as ordered `(key, value)` pairs (the seam's key-sorted order). A
    /// property the active RBAC policy hides (rmp #93) is already absent here.
    pub properties: Vec<(String, Value)>,
}

/// A fully-resolved relationship carried in a [`MaterializedValue`]: its id, endpoints, type and
/// properties read through the graph seam.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct MaterializedRel {
    /// The opaque relationship id.
    pub id: u64,
    /// The start (source) node id.
    pub start: u64,
    /// The end (target) node id.
    pub end: u64,
    /// The relationship type name.
    pub rel_type: String,
    /// The relationship's properties as ordered `(key, value)` pairs.
    pub properties: Vec<(String, Value)>,
}

/// One hop of a [`MaterializedPath`], recording the relationship traversed and the direction it was
/// traversed in relative to the path's walk.
///
/// `forward == true` means the relationship was traversed start→end (its stored direction);
/// `forward == false` means against it. A Bolt `Path` encoder uses this to sign the relationship
/// index in the path's index sequence; a self-loop is always recorded as forward.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct MaterializedStep {
    /// Whether the relationship was traversed in its stored direction.
    pub forward: bool,
    /// The relationship traversed on this hop (fully resolved).
    pub rel: MaterializedRel,
    /// The node arrived at on this hop (fully resolved).
    pub node: MaterializedNode,
}

/// A fully-resolved path: the start node followed by its hops, each carrying the traversed
/// relationship (with direction) and the arrival node.
///
/// This carries enough to emit a spec-correct **Bolt `Path`** (a distinct-nodes list, a distinct
/// **unbound**-relationships list, and the alternating index sequence) — see
/// [`bolt_path_components`](Self::bolt_path_components) — as well as a structural REST/JSON path
/// (ordered `nodes` + `relationships`).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct MaterializedPath {
    /// The first node of the path.
    pub start: MaterializedNode,
    /// The subsequent hops, in traversal order. Empty for a zero-length path (a single node).
    pub steps: Vec<MaterializedStep>,
}

impl MaterializedPath {
    /// The nodes along the path, in traversal order (start first; `steps.len() + 1` entries).
    #[must_use]
    pub fn nodes(&self) -> Vec<&MaterializedNode> {
        let mut out = Vec::with_capacity(self.steps.len() + 1);
        out.push(&self.start);
        out.extend(self.steps.iter().map(|s| &s.node));
        out
    }

    /// The relationships along the path, in traversal order.
    #[must_use]
    pub fn relationships(&self) -> Vec<&MaterializedRel> {
        self.steps.iter().map(|s| &s.rel).collect()
    }

    /// The path's length (its number of relationships; openCypher `length()`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether the path is zero-length (a single node, no relationships).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Decomposes the path into the three components a **Bolt `Path`** structure (tag `0x50`) packs
    /// (Source: the Neo4j Bolt/PackStream specification — `Path` = `nodes`, `rels`, `indices`):
    ///
    /// - `nodes`: the **distinct** nodes that appear on the path, in first-appearance order. The
    ///   start node is index `0`.
    /// - `rels`: the **distinct** relationships that appear, as *unbound* relationships (id, type,
    ///   properties — no endpoints, since the path's node sequence supplies them), in
    ///   first-appearance order.
    /// - `indices`: the alternating `[rel, node, rel, node, …]` sequence (`2 * steps.len()` entries).
    ///   A node entry is the 0-based index into `nodes`. A relationship entry is **1-based** into
    ///   `rels`, **positive** when traversed forward (start→end) and **negative** when traversed
    ///   backward — this is how Bolt encodes per-hop direction without duplicating a relationship
    ///   that the walk crosses twice. (A `0` rel index is impossible by the 1-based convention.)
    ///
    /// Returns `(nodes, rels, indices)`. The `i64` indices are produced ready to pack as PackStream
    /// integers.
    #[must_use]
    pub fn bolt_path_components(
        &self,
    ) -> (Vec<&MaterializedNode>, Vec<&MaterializedRel>, Vec<i64>) {
        let mut nodes: Vec<&MaterializedNode> = Vec::with_capacity(self.steps.len() + 1);
        let mut rels: Vec<&MaterializedRel> = Vec::with_capacity(self.steps.len());
        let mut indices: Vec<i64> = Vec::with_capacity(self.steps.len() * 2);

        // The start node is always the first distinct node (index 0).
        nodes.push(&self.start);

        for step in &self.steps {
            // Deduplicate the relationship by id, keeping first-appearance order. The signed,
            // 1-based index encodes both *which* distinct relationship and the traversal direction.
            let rel_pos = match rels.iter().position(|r| r.id == step.rel.id) {
                Some(i) => i,
                None => {
                    rels.push(&step.rel);
                    rels.len() - 1
                }
            };
            // 1-based, signed by direction.
            let signed = i64::try_from(rel_pos + 1).unwrap_or(i64::MAX);
            indices.push(if step.forward { signed } else { -signed });

            // Deduplicate the arrival node by id (a path may revisit a node).
            let node_pos = match nodes.iter().position(|n| n.id == step.node.id) {
                Some(i) => i,
                None => {
                    nodes.push(&step.node);
                    nodes.len() - 1
                }
            };
            indices.push(i64::try_from(node_pos).unwrap_or(i64::MAX));
        }

        (nodes, rels, indices)
    }

    /// Owned (consuming) counterpart of [`bolt_path_components`](Self::bolt_path_components): moves
    /// the distinct nodes and relationships **out** of `self` instead of borrowing them, so a wire
    /// seam can pack a path without cloning every label/property vector on the hot result path.
    ///
    /// Returns `(nodes, rels, indices)` with exactly the same dedup-by-id ordering and signed,
    /// 1-based index convention as the borrowing form — the only difference is ownership.
    #[must_use]
    pub fn into_bolt_path_components(
        self,
    ) -> (Vec<MaterializedNode>, Vec<MaterializedRel>, Vec<i64>) {
        let mut nodes: Vec<MaterializedNode> = Vec::with_capacity(self.steps.len() + 1);
        let mut rels: Vec<MaterializedRel> = Vec::with_capacity(self.steps.len());
        let mut indices: Vec<i64> = Vec::with_capacity(self.steps.len() * 2);

        // The start node is always the first distinct node (index 0).
        nodes.push(self.start);

        for step in self.steps {
            // Deduplicate the relationship by id, keeping first-appearance order. The signed,
            // 1-based index encodes both *which* distinct relationship and the traversal direction.
            let rel_pos = match rels.iter().position(|r| r.id == step.rel.id) {
                Some(i) => i,
                None => {
                    rels.push(step.rel);
                    rels.len() - 1
                }
            };
            // 1-based, signed by direction.
            let signed = i64::try_from(rel_pos + 1).unwrap_or(i64::MAX);
            indices.push(if step.forward { signed } else { -signed });

            // Deduplicate the arrival node by id (a path may revisit a node).
            let node_pos = match nodes.iter().position(|n| n.id == step.node.id) {
                Some(i) => i,
                None => {
                    nodes.push(step.node);
                    nodes.len() - 1
                }
            };
            indices.push(i64::try_from(node_pos).unwrap_or(i64::MAX));
        }

        (nodes, rels, indices)
    }
}

/// A **materialized** result-row cell: a scalar/temporal/list/map property [`Value`] passed through,
/// or a fully-resolved graph entity (`04 §7.2` structural classes), ready for a wire encoder.
///
/// Produced by [`Cursor::next_materialized`] / [`Cursor::materialize_row`] at the result-egress
/// boundary. The wire seams (`graphus-bolt` PackStream, `graphus-rest` Jolt/CBOR) consume this and
/// never touch the lazy [`RowValue`] or the graph seam themselves.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum MaterializedValue {
    /// A property value — scalar, string, bytes, list, map, temporal, or null — passed through
    /// unchanged from [`RowValue::Value`].
    Value(Value),
    /// A resolved node (`MATCH (n) RETURN n`).
    Node(MaterializedNode),
    /// A resolved relationship (`MATCH ()-[r]->() RETURN r`).
    Relationship(MaterializedRel),
    /// A resolved path (`MATCH p = (…)-[…]->(…) RETURN p`).
    Path(MaterializedPath),
    /// A **structural** list — one that (transitively) contains an entity, materialized
    /// element-wise. A pure-property list stays a [`MaterializedValue::Value`]`(Value::List)`, so
    /// each list has one canonical representation, mirroring the [`RowValue::list`] invariant.
    List(Vec<MaterializedValue>),
}

/// Resolves a node id into a [`MaterializedNode`] through `graph`.
///
/// A node that is not visible (deleted, or filtered out by RBAC/MVCC) yields an empty node — no
/// labels, no properties — rather than an error: the executor only ever materializes ids it bound
/// from a successful scan/traversal, so an absence here means the wire form is an entity stub, which
/// is benign and never observed for a well-formed result.
fn materialize_node(
    graph: &mut dyn GraphAccess,
    id: crate::graph_access::NodeId,
) -> MaterializedNode {
    MaterializedNode {
        id: id.0,
        labels: graph.node_labels(id).unwrap_or_default(),
        properties: graph.node_properties(id).unwrap_or_default(),
    }
}

/// Resolves a relationship id into a [`MaterializedRel`] through `graph`. As with
/// [`materialize_node`], an absent relationship yields a stub (empty type/properties, zero
/// endpoints) rather than an error.
fn materialize_rel(graph: &mut dyn GraphAccess, id: crate::graph_access::RelId) -> MaterializedRel {
    let data = graph.rel_data(id);
    let (rel_type, start, end) = match data {
        Some(d) => (d.rel_type, d.start.0, d.end.0),
        None => (String::new(), 0, 0),
    };
    MaterializedRel {
        id: id.0,
        start,
        end,
        rel_type,
        properties: graph.rel_properties(id).unwrap_or_default(),
    }
}

/// Materializes a [`PathValue`] (opaque ids) into a [`MaterializedPath`] by resolving each node and
/// relationship through `graph`.
fn materialize_path(graph: &mut dyn GraphAccess, path: &PathValue) -> MaterializedPath {
    let start = materialize_node(graph, path.start);
    let steps = path
        .steps
        .iter()
        .map(|s| MaterializedStep {
            forward: s.forward,
            rel: materialize_rel(graph, s.rel),
            node: materialize_node(graph, s.node),
        })
        .collect();
    MaterializedPath { start, steps }
}

/// Materializes one [`RowValue`] cell into a [`MaterializedValue`], resolving any entity through
/// `graph`. Property values pass through; a structural list recurses element-wise.
pub(crate) fn materialize_value(graph: &mut dyn GraphAccess, rv: &RowValue) -> MaterializedValue {
    match rv {
        RowValue::Value(v) => MaterializedValue::Value(v.clone()),
        RowValue::Node(n) => MaterializedValue::Node(materialize_node(graph, n.id)),
        RowValue::Rel(r) => MaterializedValue::Relationship(materialize_rel(graph, r.id)),
        RowValue::Path(p) => MaterializedValue::Path(materialize_path(graph, p)),
        RowValue::List(items) => MaterializedValue::List(
            items
                .iter()
                .map(|it| materialize_value(graph, it))
                .collect(),
        ),
        // A structural map collapses to a property map at egress: its keys are kept and each value
        // is materialized through the property collapse (an entity/path becomes null). No result is
        // ever a structural map in practice — they exist only as transient `DELETE`-through-map
        // intermediates (Delete5.feature) — so this keeps the wire seam (PackStream/Jolt) free of a
        // structural-map case while staying total.
        RowValue::Map(entries) => MaterializedValue::Value(Value::Map(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), collapse_for_egress(v)))
                .collect(),
        )),
    }
}

/// The property collapse of a [`RowValue`] used when a structural map reaches result egress:
/// entities/paths become null, nested structural collections collapse recursively.
fn collapse_for_egress(rv: &RowValue) -> Value {
    match rv {
        RowValue::Value(v) => v.clone(),
        RowValue::Node(_) | RowValue::Rel(_) | RowValue::Path(_) => Value::Null,
        RowValue::List(items) => Value::List(items.iter().map(collapse_for_egress).collect()),
        RowValue::Map(entries) => Value::Map(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), collapse_for_egress(v)))
                .collect(),
        ),
    }
}

/// Materializes every cell of `row` through `graph`, in column order.
pub(crate) fn materialize_row(graph: &mut dyn GraphAccess, row: &Row) -> Vec<MaterializedValue> {
    row.values()
        .iter()
        .map(|rv| materialize_value(graph, rv))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_access::{MemGraph, NodeId, RelId};
    use crate::runtime::{NodeRef, PathStep, RelRef};

    fn s(v: &str) -> Value {
        Value::String(v.to_owned())
    }

    #[test]
    fn materializes_a_node_with_labels_and_properties() {
        let mut g = MemGraph::new();
        let a = g.add_node(["Person", "Admin"], [("name", s("Ada"))]);
        let mat = materialize_value(&mut g, &RowValue::Node(NodeRef { id: a }));
        match mat {
            MaterializedValue::Node(n) => {
                assert_eq!(n.id, a.0);
                assert_eq!(n.labels, vec!["Admin".to_owned(), "Person".to_owned()]);
                assert_eq!(n.properties, vec![("name".to_owned(), s("Ada"))]);
            }
            other => panic!("expected node, got {other:?}"),
        }
    }

    #[test]
    fn materializes_a_relationship_with_endpoints_and_type() {
        let mut g = MemGraph::new();
        let a = g.add_node(["X"], [] as [(&str, Value); 0]);
        let b = g.add_node(["X"], [] as [(&str, Value); 0]);
        let r = g.add_rel("KNOWS", a, b, [("since", Value::Integer(2010))]);
        let mat = materialize_value(&mut g, &RowValue::Rel(RelRef { id: r }));
        match mat {
            MaterializedValue::Relationship(rel) => {
                assert_eq!(rel.id, r.0);
                assert_eq!(rel.start, a.0);
                assert_eq!(rel.end, b.0);
                assert_eq!(rel.rel_type, "KNOWS");
                assert_eq!(
                    rel.properties,
                    vec![("since".to_owned(), Value::Integer(2010))]
                );
            }
            other => panic!("expected relationship, got {other:?}"),
        }
    }

    #[test]
    fn scalar_passes_through_unchanged() {
        let mut g = MemGraph::new();
        let mat = materialize_value(&mut g, &RowValue::Value(Value::Integer(7)));
        assert_eq!(mat, MaterializedValue::Value(Value::Integer(7)));
    }

    #[test]
    fn structural_list_materializes_element_wise() {
        let mut g = MemGraph::new();
        let a = g.add_node(["L"], [] as [(&str, Value); 0]);
        let list = RowValue::List(vec![
            RowValue::Value(Value::Integer(1)),
            RowValue::Node(NodeRef { id: a }),
        ]);
        match materialize_value(&mut g, &list) {
            MaterializedValue::List(items) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], MaterializedValue::Value(Value::Integer(1)));
                assert!(matches!(items[1], MaterializedValue::Node(_)));
            }
            other => panic!("expected list, got {other:?}"),
        }
    }

    #[test]
    fn path_components_are_bolt_spec_correct() {
        // Build a 2-hop path a -KNOWS-> b -KNOWS-> c, both forward.
        let mut g = MemGraph::new();
        let a = g.add_node(["P"], [("n", s("a"))]);
        let b = g.add_node(["P"], [("n", s("b"))]);
        let c = g.add_node(["P"], [("n", s("c"))]);
        let r1 = g.add_rel("KNOWS", a, b, [] as [(&str, Value); 0]);
        let r2 = g.add_rel("KNOWS", b, c, [] as [(&str, Value); 0]);
        let path = PathValue {
            start: a,
            steps: vec![
                PathStep {
                    forward: true,
                    rel: r1,
                    node: b,
                },
                PathStep {
                    forward: true,
                    rel: r2,
                    node: c,
                },
            ],
        };
        let mat = materialize_path(&mut g, &path);
        let (nodes, rels, indices) = mat.bolt_path_components();
        // Three distinct nodes (a=0, b=1, c=2), two distinct rels.
        assert_eq!(
            nodes.iter().map(|n| n.id).collect::<Vec<_>>(),
            vec![a.0, b.0, c.0]
        );
        assert_eq!(
            rels.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![r1.0, r2.0]
        );
        // indices = [rel1(+1), node b(1), rel2(+2), node c(2)].
        assert_eq!(indices, vec![1, 1, 2, 2]);
    }

    #[test]
    fn backward_hop_signs_the_rel_index_negative() {
        // a <-KNOWS- b  (traversed backward from a's perspective in the walk a -> b).
        let mut g = MemGraph::new();
        let a = g.add_node(["P"], [] as [(&str, Value); 0]);
        let b = g.add_node(["P"], [] as [(&str, Value); 0]);
        let r = g.add_rel("KNOWS", b, a, [] as [(&str, Value); 0]); // stored b->a
        let path = PathValue {
            start: a,
            steps: vec![PathStep {
                forward: false,
                rel: r,
                node: b,
            }],
        };
        let mat = materialize_path(&mut g, &path);
        let (_nodes, rels, indices) = mat.bolt_path_components();
        assert_eq!(rels.len(), 1);
        // rel index is 1-based and negative (backward); node b is distinct index 1.
        assert_eq!(indices, vec![-1, 1]);
    }

    #[test]
    fn absent_entity_materializes_to_a_stub_not_a_panic() {
        let mut g = MemGraph::new();
        // An id that was never created (the executor never produces this; defensive totality).
        let mat = materialize_value(&mut g, &RowValue::Node(NodeRef { id: NodeId(999) }));
        match mat {
            MaterializedValue::Node(n) => {
                assert_eq!(n.id, 999);
                assert!(n.labels.is_empty());
                assert!(n.properties.is_empty());
            }
            other => panic!("expected node stub, got {other:?}"),
        }
        let mat = materialize_value(&mut g, &RowValue::Rel(RelRef { id: RelId(999) }));
        match mat {
            MaterializedValue::Relationship(r) => {
                assert_eq!(r.id, 999);
                assert_eq!(r.start, 0);
                assert_eq!(r.end, 0);
                assert!(r.rel_type.is_empty());
            }
            other => panic!("expected rel stub, got {other:?}"),
        }
    }
}
