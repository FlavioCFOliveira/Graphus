//! Read-path benchmarks for SPIKE #8 — characterizing the lock-free read side (`04 §9.1`).
//!
//! §9.1 states reads are "fully parallel and lock-free against committed versions" — they never
//! touch the log tail or the commit serialization point. This file characterizes that read side so
//! the SPIKE #8 recommendation can contrast the (serialized) write path against the (lock-free)
//! read path on the same store and hardware:
//!
//! 1. `read_traversal/incident_rels` — walk a node's incidence chain (index-free adjacency: a
//!    pointer chase, `04 §2.3`) over graphs of growing average degree. `Throughput::Elements` =
//!    edges visited, so Criterion reports **edges/sec**.
//! 2. `read_traversal/degree` — the `degree()` variant (chain walk that only counts).
//! 3. `read_scan/scan_node_ids` — a full node-store scan (`MATCH (n)` leaf), reported as
//!    **nodes/sec**, the vectorizable scan leaf of `04 §7.4`.
//!
//! All reads run against a graph already built and committed through the real commit path, so they
//! read genuine committed MVCC versions. Fixtures are built *once* and then only read (no further
//! commits during measurement), so a fixture only has to fit the storage layer's single-page
//! catalog at build time — see the "Store-size envelope" note in `commit_path.rs`. The node/edge
//! counts below are sized to stay comfortably under that ~1000-record-page cap.
//!
//! Run with: `cargo bench -p graphus-bench --bench read_path`.

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

#[path = "common.rs"]
mod common;
use common::build_graph;

/// Edges committed per transaction while building the read fixtures. Read latency is independent
/// of build batching, so a single moderate batch keeps fixture build fast.
const BUILD_BATCH: u64 = 256;

/// Group 1+2: traversal of a node's incidence chain at growing average degree.
fn bench_traversal(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_traversal");
    group.sample_size(50);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    // 2_000 nodes × up to 32 out-edges ≈ 816 record pages at the largest degree — under the
    // single-page-catalog cap (see `commit_path.rs` → "Store-size envelope").
    const NODES: u64 = 2_000;
    for &deg in &[2u64, 8, 32] {
        // `edges_per_node = deg` out-edges per node; with the ring-plus-chords wiring each node
        // also receives in-edges, so observed incidence degree is ~2*deg.
        let (mut store, ids) = build_graph(NODES, deg, BUILD_BATCH);
        // Probe a representative interior node (stable across runs).
        let probe = ids[ids.len() / 2];
        let observed_degree = store.degree(probe).expect("degree");
        assert!(observed_degree > 0, "probe node must have incident edges");

        group.throughput(Throughput::Elements(observed_degree as u64));
        group.bench_with_input(
            BenchmarkId::new("incident_rels", deg),
            &probe,
            |b, &probe| {
                b.iter(|| {
                    let rels = store
                        .incident_rels(black_box(probe))
                        .expect("incident_rels");
                    black_box(rels.len());
                });
            },
        );
        group.bench_with_input(BenchmarkId::new("degree", deg), &probe, |b, &probe| {
            b.iter(|| {
                let d = store.degree(black_box(probe)).expect("degree");
                black_box(d);
            });
        });
    }
    group.finish();
}

/// Group 3: a full node-store scan over graphs of growing node count.
fn bench_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_scan");
    group.sample_size(50);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    // Up to 20_000 nodes × 2 edges ≈ 660 record pages — under the single-page-catalog cap.
    for &nodes in &[1_000u64, 10_000, 20_000] {
        // 2 out-edges/node so the store is a real graph, not isolated vertices; the scan only
        // touches the node store.
        let (mut store, _ids) = build_graph(nodes, 2, BUILD_BATCH);
        group.throughput(Throughput::Elements(nodes));
        group.bench_with_input(BenchmarkId::new("scan_node_ids", nodes), &nodes, |b, _| {
            b.iter(|| {
                let all = store.scan_node_ids().expect("scan");
                black_box(all.len());
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_traversal, bench_scan);
criterion_main!(benches);
