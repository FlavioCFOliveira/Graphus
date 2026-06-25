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

/// A large (>= 200-node) **non-dyadic** graph (`rmp` #421). The small dyadic fixture above is too tiny
/// to make rayon split the source loop across more than a couple of tasks, so it cannot expose a
/// thread-count-dependent reduction order. This graph is large enough that rayon splits the work
/// differently at every pool width, and it is built so betweenness carries many *fractional* σ
/// contributions (multiple equal-length shortest paths through parallel "rungs"), whose summation
/// order is exactly what f64 non-associativity makes thread-count sensitive.
///
/// Structure: a 70-rung "ladder" — two parallel rails `a_i` (ids `0..70`) and `b_i` (ids `70..140`)
/// with rungs `a_i - b_i`, rails `a_i - a_{i+1}` and `b_i - b_{i+1}`, plus diagonals `a_i - b_{i+1}`
/// that create many equal-length detours (so σ is fractional and dependency back-propagation produces
/// non-terminating binary fractions). A 70-node fan (`140..210`) hangs extra leaves off the rails to
/// push the count past 200 and lengthen the dependency sums. 210 nodes, non-power-of-two.
fn large_non_dyadic_fixture() -> CsrGraph {
    const RUNGS: u64 = 70;
    let mut nodes: Vec<u64> = (0..(3 * RUNGS)).collect();
    nodes.dedup();
    let mut edges: Vec<(u64, u64)> = Vec::new();
    for i in 0..RUNGS {
        let a = i;
        let b = RUNGS + i;
        edges.push((a, b)); // rung
        if i + 1 < RUNGS {
            edges.push((a, a + 1)); // rail A
            edges.push((b, b + 1)); // rail B
            edges.push((a, RUNGS + i + 1)); // diagonal -> multiple equal shortest paths
        }
        // Fan leaf hanging off rail A (ids 140..210), giving every rail node a pendant.
        let leaf = 2 * RUNGS + i;
        edges.push((a, leaf));
    }
    undirected(&nodes, &edges)
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

    for threads in [1usize, 2, 4, 8, 16] {
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

/// `rmp` #421 regression gate: betweenness must be **bit-identical** across pool widths on a large,
/// non-dyadic graph whose σ contributions are fractional. This is the test the old 8-node dyadic
/// fixture was too small to be: it fails before the fix (the rayon-split-dependent `try_reduce` fold
/// order makes f64 sums differ across widths) and passes after (the final accumulation is folded in a
/// fixed ascending source-id order, independent of thread count).
#[test]
fn betweenness_is_bit_identical_on_large_non_dyadic_graph() {
    let g = large_non_dyadic_fixture();
    assert!(
        g.node_count() >= 200,
        "fixture must exceed 200 nodes (got {})",
        g.node_count()
    );

    // Baseline on the global pool.
    let baseline = betweenness_centrality(&g, &Cancel::never()).expect("baseline betweenness");

    for threads in [1usize, 2, 4, 8, 16] {
        let scores = on_pool(threads, || {
            betweenness_centrality(&large_non_dyadic_fixture(), &Cancel::never())
                .expect("betweenness on pool")
        });
        assert_eq!(
            scores, baseline,
            "betweenness must be bit-identical on a {threads}-thread pool (large non-dyadic graph)"
        );
    }
}
