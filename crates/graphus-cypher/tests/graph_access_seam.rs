//! Tests the [`GraphAccess`] seam's **optional index** path end-to-end (`04 §6.6`, §7.4).
//!
//! The in-memory [`MemGraph`] has no index, so the executor's seek operators fall back to
//! scan+filter (covered by `tests/executor.rs`). Here a tiny **indexed** [`GraphAccess`] wrapper
//! overrides [`GraphAccess::index_seek_eq`] / [`index_seek_range`](GraphAccess::index_seek_range) and
//! records that it was called, proving the executor routes a planned `NodeIndexSeek` through the
//! seam's index path when one is available — exactly the contract sub-task #38's real index backend
//! will satisfy.

use std::cell::Cell;

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{
    ExpandDirection, GraphAccess, Incident, MemGraph, NodeId, RelData, RelId,
};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::semantics::analyze;

/// A [`GraphAccess`] that wraps a [`MemGraph`] and serves equality/range seeks from a real (if
/// trivial) index, flipping a flag when the index path is used.
struct IndexedGraph {
    inner: MemGraph,
    eq_seek_used: Cell<bool>,
    range_seek_used: Cell<bool>,
}

impl IndexedGraph {
    fn new(inner: MemGraph) -> Self {
        Self {
            inner,
            eq_seek_used: Cell::new(false),
            range_seek_used: Cell::new(false),
        }
    }
}

// Delegate every required method to the inner MemGraph, and override the two optional seeks.
impl GraphAccess for IndexedGraph {
    fn scan_nodes(&self) -> Vec<NodeId> {
        self.inner.scan_nodes()
    }
    fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
        self.inner.scan_nodes_by_label(label)
    }
    fn expand(&self, node: NodeId, direction: ExpandDirection, types: &[String]) -> Vec<Incident> {
        self.inner.expand(node, direction, types)
    }
    fn node_exists(&self, node: NodeId) -> bool {
        self.inner.node_exists(node)
    }
    fn rel_exists(&self, rel: RelId) -> bool {
        self.inner.rel_exists(rel)
    }
    fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
        self.inner.node_labels(node)
    }
    fn rel_data(&self, rel: RelId) -> Option<RelData> {
        self.inner.rel_data(rel)
    }
    fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
        self.inner.node_property(node, key)
    }
    fn rel_property(&self, rel: RelId, key: &str) -> Option<Value> {
        self.inner.rel_property(rel, key)
    }
    fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
        self.inner.node_properties(node)
    }
    fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
        self.inner.rel_properties(rel)
    }

    // The point of the test: serve the seek from "the index".
    fn index_seek_eq(&self, label: &str, property: &str, value: &Value) -> Option<Vec<NodeId>> {
        self.eq_seek_used.set(true);
        // A real index would probe a B+-tree; here we just compute the matching ids directly.
        Some(
            self.inner
                .scan_nodes_by_label(label)
                .into_iter()
                .filter(|id| self.inner.node_property(*id, property).as_ref() == Some(value))
                .collect(),
        )
    }

    fn index_seek_range(
        &self,
        label: &str,
        property: &str,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
    ) -> Option<Vec<NodeId>> {
        self.range_seek_used.set(true);
        use graphus_cypher::cmp_values;
        use std::cmp::Ordering;
        Some(
            self.inner
                .scan_nodes_by_label(label)
                .into_iter()
                .filter(|id| {
                    let Some(v) = self.inner.node_property(*id, property) else {
                        return false;
                    };
                    let ok_low = lower.is_none_or(|(b, inc)| {
                        let ord = cmp_values(&v, b);
                        if inc {
                            ord != Ordering::Less
                        } else {
                            ord == Ordering::Greater
                        }
                    });
                    let ok_high = upper.is_none_or(|(b, inc)| {
                        let ord = cmp_values(&v, b);
                        if inc {
                            ord != Ordering::Greater
                        } else {
                            ord == Ordering::Less
                        }
                    });
                    ok_low && ok_high
                })
                .collect(),
        )
    }

    fn create_node(&mut self, labels: &[String], properties: &[(String, Value)]) -> NodeId {
        self.inner.create_node(labels, properties)
    }
    fn create_rel(
        &mut self,
        rel_type: &str,
        start: NodeId,
        end: NodeId,
        properties: &[(String, Value)],
    ) -> RelId {
        self.inner.create_rel(rel_type, start, end, properties)
    }
    fn set_node_property(&mut self, node: NodeId, key: &str, value: Value) {
        self.inner.set_node_property(node, key, value);
    }
    fn set_rel_property(&mut self, rel: RelId, key: &str, value: Value) {
        self.inner.set_rel_property(rel, key, value);
    }
    fn add_labels(&mut self, node: NodeId, labels: &[String]) {
        self.inner.add_labels(node, labels);
    }
    fn remove_labels(&mut self, node: NodeId, labels: &[String]) {
        self.inner.remove_labels(node, labels);
    }
    fn remove_node_property(&mut self, node: NodeId, key: &str) {
        self.inner.remove_node_property(node, key);
    }
    fn remove_rel_property(&mut self, rel: RelId, key: &str) {
        self.inner.remove_rel_property(rel, key);
    }
    fn replace_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        self.inner.replace_node_properties(node, properties);
    }
    fn merge_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        self.inner.merge_node_properties(node, properties);
    }
    fn incident_rels(&self, node: NodeId) -> Vec<RelId> {
        self.inner.incident_rels(node)
    }
    fn delete_rel(&mut self, rel: RelId) {
        self.inner.delete_rel(rel);
    }
    fn delete_node(&mut self, node: NodeId) {
        self.inner.delete_node(node);
    }
}

fn seed() -> IndexedGraph {
    let mut inner = MemGraph::new();
    let _ = inner.add_node(
        ["Person"],
        [
            ("name", Value::String("Ada".into())),
            ("age", Value::Integer(36)),
        ],
    );
    let _ = inner.add_node(
        ["Person"],
        [
            ("name", Value::String("Bob".into())),
            ("age", Value::Integer(28)),
        ],
    );
    let _ = inner.add_node(
        ["Person"],
        [
            ("name", Value::String("Cara".into())),
            ("age", Value::Integer(40)),
        ],
    );
    IndexedGraph::new(inner)
}

fn run(src: &str, graph: &mut IndexedGraph, catalog: &IndexCatalog) -> Vec<Value> {
    let toks = tokenize(src).unwrap();
    let ast = parse_tokens(&toks, src).unwrap();
    let plan = plan_physical(&lower(&analyze(&ast).unwrap()), catalog);
    let bound = bind_parameters(&plan, &Parameters::new()).unwrap();
    let mut cursor = execute(&plan, &bound, graph).unwrap();
    cursor
        .collect_all()
        .unwrap()
        .iter()
        .map(|r| r.value("name"))
        .collect()
}

#[test]
fn equality_seek_uses_the_index_path() {
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "age")
        .build();
    let mut g = seed();
    let mut names = run(
        "MATCH (n:Person) WHERE n.age = 36 RETURN n.name AS name",
        &mut g,
        &catalog,
    );
    names.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    assert_eq!(names, vec![Value::String("Ada".into())]);
    assert!(
        g.eq_seek_used.get(),
        "the executor must route the equality seek through the index seam"
    );
}

#[test]
fn range_seek_uses_the_index_path() {
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "age")
        .build();
    let mut g = seed();
    let mut names = run(
        "MATCH (n:Person) WHERE n.age >= 36 RETURN n.name AS name",
        &mut g,
        &catalog,
    );
    names.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    assert_eq!(
        names,
        vec![Value::String("Ada".into()), Value::String("Cara".into())]
    );
    assert!(
        g.range_seek_used.get(),
        "the executor must route the range seek through the index seam"
    );
}
