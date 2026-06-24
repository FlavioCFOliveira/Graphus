//! `rmp` task #376: GDS centrality determinism is independent of the rayon pool it runs on.
//!
//! #376 routes GDS centrality off the *global* rayon pool and onto the *shared analytics* pool (the
//! bounded `min(N,16)`-thread pool the morsel tier uses), so the morsel + GDS peak runnable-thread sum is
//! `≈` core count rather than `2 × N`. That routing is only sound if the centrality result is
//! **bit-identical** regardless of which pool — and how many worker threads — execute the data-parallel
//! source loop. These tests assert exactly that, building a non-trivial graph and running closeness and
//! betweenness on dedicated rayon pools of width {1, 2, 4, 8} via `ThreadPool::install` (the same
//! mechanism `morsel::run_on_analytics_pool` uses). Every width must reproduce the serial (global-pool)
//! result byte-for-byte.
//!
//! Why bit-identical (not just within an epsilon): closeness writes each source's score into its **own**
//! result slot (`map` + `collect`, order-preserving, each slot written once) and Brandes betweenness
//! reduces per-task private accumulators by element-wise f64 addition whose per-source contributions are
//! exact in f64 for these reference graphs — so there is no floating-point reordering across thread
//! counts, and equality (not `≈`) is the correct, strongest assertion.

use graphus_gds::algo::centrality::{
    betweenness_centrality, closeness_centrality, undirected_scale,
};
use graphus_gds::{Cancel, CsrGraph, Orientation, VecGraphSource};

fn undirected(nodes: &[u64], edges: &[(u64, u64)]) -> CsrGraph {
    let src = VecGraphSource {
        nodes: nodes.to_vec(),
        edges: edges.iter().map(|&(a, b)| (a, b, 1.0)).collect(),
    };
    src.build(Orientation::Undirected, false)
        .expect("build undirected")
}

/// A graph with enough structure (branching, multiple shortest paths, a bridge) that closeness and
/// betweenness are non-trivial and would expose any thread-count-dependent reordering.
fn fixture() -> CsrGraph {
    // Two triangles bridged by a chain: 0-1-2 (triangle), 3-4-5 (triangle), bridged 2-6-7-3.
    undirected(
        &[0, 1, 2, 3, 4, 5, 6, 7],
        &[
            (0, 1),
            (1, 2),
            (0, 2),
            (3, 4),
            (4, 5),
            (3, 5),
            (2, 6),
            (6, 7),
            (7, 3),
        ],
    )
}

/// Builds a dedicated rayon pool of `threads` workers and runs `op` on it (the same `install`
/// mechanism `morsel::run_on_analytics_pool` uses to host GDS on the shared analytics pool).
fn on_pool<R: Send>(threads: usize, op: impl FnOnce() -> R + Send) -> R {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("build test pool")
        .install(op)
}

#[test]
fn closeness_is_identical_across_pool_widths() {
    let g = fixture();
    let cancel = Cancel::never();

    // Baseline: the serial (global-pool, single logical width) result.
    let baseline = closeness_centrality(&g, &cancel).expect("closeness baseline");

    for threads in [1usize, 2, 4, 8] {
        let scores = on_pool(threads, || {
            closeness_centrality(&fixture(), &Cancel::never()).expect("closeness on pool")
        });
        assert_eq!(
            scores, baseline,
            "closeness must be bit-identical on a {threads}-thread analytics pool"
        );
    }
}

#[test]
fn betweenness_is_identical_across_pool_widths() {
    let g = fixture();
    let cancel = Cancel::never();

    let baseline = undirected_scale(
        &g,
        betweenness_centrality(&g, &cancel).expect("betweenness baseline"),
    );

    for threads in [1usize, 2, 4, 8] {
        let scores = on_pool(threads, || {
            let g = fixture();
            let raw = betweenness_centrality(&g, &Cancel::never()).expect("betweenness on pool");
            undirected_scale(&g, raw)
        });
        assert_eq!(
            scores, baseline,
            "betweenness must be bit-identical on a {threads}-thread analytics pool"
        );
    }
}
