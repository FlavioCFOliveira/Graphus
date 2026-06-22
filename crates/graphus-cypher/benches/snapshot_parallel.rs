//! Serial-vs-parallel read benchmark over the frozen [`GraphSnapshot`] (`rmp` task #351, slice 2 of
//! #335).
//!
//! The whole point of [`GraphSnapshot`] is to lift query reads off the single `!Send` engine thread:
//! once projected, the snapshot is an owned, immutable, `Send + Sync` view, so a read aggregation can
//! fan across every core with `rayon` exactly as `graphus-gds` already does over its CSR projection.
//! This benchmark quantifies that win: it projects a large snapshot, then folds a label-property read
//! aggregation **serially** (`Iterator`) and **in parallel** (`rayon::par_iter`) over the same data,
//! so Criterion reports the per-node read throughput of each and their ratio is the parallel speedup.
//!
//! The per-node work is a small CPU kernel over the node's column value and its CSR degree
//! (representative of a query read that touches each row), so the fold is compute-bound enough for
//! the parallel scaling to show rather than being pinned by memory bandwidth alone. The fold output
//! is an `i64` (associative + commutative), so the serial and parallel results are bit-identical
//! regardless of how rayon splits the work.
//!
//! `Throughput::Elements` = nodes folded, so Criterion reports **nodes/sec**. The parallel side
//! honours `RAYON_NUM_THREADS`.
//!
//! Run with: `cargo bench -p graphus-cypher --bench snapshot_parallel`
//! (pin the thread count with e.g. `RAYON_NUM_THREADS=16 cargo bench -p graphus-cypher --bench snapshot_parallel`).

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rayon::prelude::*;

use graphus_core::Value;
use graphus_cypher::graph_access::{
    ExpandDirection, GraphAccess, Incident, NodeId, RelData, RelId,
};
use graphus_cypher::snapshot::{GraphSnapshot, SnapshotSpec};

/// A minimal adjacency-list-backed [`GraphAccess`] fixture, so projecting a large snapshot is
/// `O(N + E)` (the in-tree `MemGraph::expand` scans every relationship per node — `O(N · E)` — which
/// is fine for correctness tests but pathological at benchmark scale). Read-only: every write method
/// is `unreachable!` because the benchmark never mutates it.
struct BenchGraph {
    /// Per-node `age` — every node is a `:Person { age }`.
    ages: Vec<i64>,
    /// `out[i]` = outgoing `(rel_id, neighbour_internal)` of node `i`.
    out: Vec<Vec<(u64, u32)>>,
    /// `inc[i]` = incoming `(rel_id, neighbour_internal)` of node `i`.
    inc: Vec<Vec<(u64, u32)>>,
    /// `rel_endpoints[r]` = `(start_internal, end_internal)` of relationship id `r`.
    rel_endpoints: Vec<(u32, u32)>,
}

impl BenchGraph {
    /// A ring of `n` `:Person { age }` nodes wired with a `KNOWS` ring + `+7` chords, so degrees
    /// vary (the same wiring the read-path benches and the snapshot tests use).
    fn ring(n: usize) -> Self {
        let mut g = BenchGraph {
            ages: (0..n).map(|i| (i % 80) as i64 + 18).collect(),
            out: vec![Vec::new(); n],
            inc: vec![Vec::new(); n],
            rel_endpoints: Vec::new(),
        };
        let add = |g: &mut BenchGraph, a: usize, b: usize| {
            let r = g.rel_endpoints.len() as u64;
            g.rel_endpoints.push((a as u32, b as u32));
            g.out[a].push((r, b as u32));
            g.inc[b].push((r, a as u32));
        };
        for i in 0..n {
            add(&mut g, i, (i + 1) % n);
            if i % 3 == 0 {
                add(&mut g, i, (i + 7) % n);
            }
        }
        g
    }
}

impl GraphAccess for BenchGraph {
    fn scan_nodes(&self) -> Vec<NodeId> {
        (0..self.ages.len() as u64).map(NodeId).collect()
    }
    fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
        if label == "Person" {
            self.scan_nodes()
        } else {
            Vec::new()
        }
    }
    fn expand(&self, node: NodeId, direction: ExpandDirection, _types: &[String]) -> Vec<Incident> {
        let i = node.0 as usize;
        let mut out = Vec::new();
        let want_out = matches!(direction, ExpandDirection::Outgoing | ExpandDirection::Both);
        let want_in = matches!(direction, ExpandDirection::Incoming | ExpandDirection::Both);
        if want_out {
            if let Some(es) = self.out.get(i) {
                out.extend(es.iter().map(|&(r, nb)| Incident {
                    rel: RelId(r),
                    neighbour: NodeId(u64::from(nb)),
                }));
            }
        }
        if want_in {
            if let Some(es) = self.inc.get(i) {
                out.extend(es.iter().map(|&(r, nb)| Incident {
                    rel: RelId(r),
                    neighbour: NodeId(u64::from(nb)),
                }));
            }
        }
        out
    }
    fn node_exists(&self, node: NodeId) -> bool {
        (node.0 as usize) < self.ages.len()
    }
    fn rel_exists(&self, rel: RelId) -> bool {
        (rel.0 as usize) < self.rel_endpoints.len()
    }
    fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
        self.node_exists(node).then(|| vec!["Person".to_owned()])
    }
    fn rel_data(&self, rel: RelId) -> Option<RelData> {
        self.rel_endpoints
            .get(rel.0 as usize)
            .map(|&(s, e)| RelData {
                rel_type: "KNOWS".to_owned(),
                start: NodeId(u64::from(s)),
                end: NodeId(u64::from(e)),
            })
    }
    fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
        if key == "age" {
            self.ages.get(node.0 as usize).map(|&a| Value::Integer(a))
        } else {
            None
        }
    }
    fn rel_property(&self, _rel: RelId, _key: &str) -> Option<Value> {
        None
    }
    fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
        self.node_property(node, "age")
            .map(|v| vec![("age".to_owned(), v)])
    }
    fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
        self.rel_exists(rel).then(Vec::new)
    }
    fn create_node(&mut self, _labels: &[String], _properties: &[(String, Value)]) -> NodeId {
        unreachable!("BenchGraph is read-only")
    }
    fn create_rel(
        &mut self,
        _rel_type: &str,
        _start: NodeId,
        _end: NodeId,
        _properties: &[(String, Value)],
    ) -> RelId {
        unreachable!("BenchGraph is read-only")
    }
    fn set_node_property(&mut self, _node: NodeId, _key: &str, _value: Value) {
        unreachable!("BenchGraph is read-only")
    }
    fn set_rel_property(&mut self, _rel: RelId, _key: &str, _value: Value) {
        unreachable!("BenchGraph is read-only")
    }
    fn add_labels(&mut self, _node: NodeId, _labels: &[String]) {
        unreachable!("BenchGraph is read-only")
    }
    fn remove_labels(&mut self, _node: NodeId, _labels: &[String]) {
        unreachable!("BenchGraph is read-only")
    }
    fn remove_node_property(&mut self, _node: NodeId, _key: &str) {
        unreachable!("BenchGraph is read-only")
    }
    fn remove_rel_property(&mut self, _rel: RelId, _key: &str) {
        unreachable!("BenchGraph is read-only")
    }
    fn replace_node_properties(&mut self, _node: NodeId, _properties: &[(String, Value)]) {
        unreachable!("BenchGraph is read-only")
    }
    fn merge_node_properties(&mut self, _node: NodeId, _properties: &[(String, Value)]) {
        unreachable!("BenchGraph is read-only")
    }
    fn replace_rel_properties(&mut self, _rel: RelId, _properties: &[(String, Value)]) {
        unreachable!("BenchGraph is read-only")
    }
    fn merge_rel_properties(&mut self, _rel: RelId, _properties: &[(String, Value)]) {
        unreachable!("BenchGraph is read-only")
    }
    fn incident_rels(&self, _node: NodeId) -> Vec<RelId> {
        unreachable!("BenchGraph is read-only")
    }
    fn delete_rel(&mut self, _rel: RelId) {
        unreachable!("BenchGraph is read-only")
    }
    fn delete_node(&mut self, _node: NodeId) {
        unreachable!("BenchGraph is read-only")
    }
}

/// The per-node read kernel: pull the node's `age` (a column read) and its `degree` (a CSR read),
/// then mix them through a short integer loop so the per-row cost is data-driven and non-trivial.
/// Returns an `i64` so the fold is associative + commutative (serial == parallel, bit for bit).
#[inline]
fn kernel(snap: &GraphSnapshot, n: NodeId) -> i64 {
    let age = match snap.node_property(Some("Person"), n, "age") {
        Some(Value::Integer(a)) => a,
        _ => 0,
    };
    let deg = snap.degree(n) as i64;
    let mut acc = age.wrapping_mul(31).wrapping_add(deg);
    for _ in 0..32 {
        acc = acc.wrapping_mul(1_000_003).wrapping_add(deg).rotate_left(7);
    }
    acc ^ (age & deg)
}

fn bench_snapshot_aggregation(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_read_aggregation");
    group.sample_size(20);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(3));

    for &n in &[50_000usize, 200_000] {
        let g = BenchGraph::ring(n);
        let snap = GraphSnapshot::project(&g, &SnapshotSpec::new().with_column("Person", "age"));
        let nodes = snap.scan_nodes();
        assert_eq!(nodes.len(), n);

        // Cross-check serial == parallel once before timing (also surfaces a regression cheaply).
        let serial_ref: i64 = nodes.iter().map(|&node| kernel(&snap, node)).sum();
        let parallel_ref: i64 = nodes.par_iter().map(|&node| kernel(&snap, node)).sum();
        assert_eq!(serial_ref, parallel_ref);

        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("serial", n), &nodes, |b, nodes| {
            b.iter(|| {
                let sum: i64 = nodes.iter().map(|&node| kernel(&snap, node)).sum();
                black_box(sum)
            });
        });

        group.bench_with_input(BenchmarkId::new("parallel", n), &nodes, |b, nodes| {
            b.iter(|| {
                let sum: i64 = nodes.par_iter().map(|&node| kernel(&snap, node)).sum();
                black_box(sum)
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_snapshot_aggregation);
criterion_main!(benches);
