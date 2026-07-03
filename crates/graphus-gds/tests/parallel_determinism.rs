//! `rmp` #342 / #559 — parallel GDS must equal sequential GDS.
//!
//! Every algorithm parallelised in #342/#559 is exercised here with both [`Execution::sequential`] and
//! [`Execution::parallel`] (forced on via a `0` threshold so even a modest test graph runs through
//! `rayon`), and the two results are asserted **bit-identical** for the integer/exact algorithms and
//! **reproducible** for the floating-point ones. A subset is additionally checked to be identical
//! across `rayon` pool widths `{1, 2, 4, 8, 16}` via `ThreadPool::install` — the same mechanism the
//! server uses to host GDS on its bounded analytics pool — so the answer never depends on how the work
//! was split. The lock-free WCC union-find gets a dedicated concurrency stress test.

use graphus_gds::algo::centrality::{
    betweenness_centrality_with, closeness_centrality_with, undirected_scale,
};
use graphus_gds::algo::community::{LabelPropagationConfig, label_propagation_with};
use graphus_gds::algo::degree::{Direction, degree_centrality_with};
use graphus_gds::algo::pagerank::{PageRankConfig, pagerank_with, personalized_pagerank_with};
use graphus_gds::algo::shortest_path::{dijkstra, dijkstra_multi_source};
use graphus_gds::algo::triangles::triangle_count_with;
use graphus_gds::algo::wcc::weakly_connected_components_with;
use graphus_gds::{Cancel, CsrGraph, Execution, InternalId, Orientation, VecGraphSource};

// -------------------------------------------------------------------------------------------------
// Deterministic graph generators (a tiny LCG — no external RNG dependency).
// -------------------------------------------------------------------------------------------------

/// A minimal reproducible pseudo-random generator (SplitMix64-style) for building test graphs.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }
    fn next_u64(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
}

/// A random directed/undirected (multi)graph with `n` nodes and `n * avg_deg` random edges. Includes
/// self-loops and parallel edges naturally, exercising the multigraph paths.
fn gen_graph(
    n: usize,
    avg_deg: usize,
    seed: u64,
    orientation: Orientation,
    weighted: bool,
) -> CsrGraph {
    let mut rng = Lcg::new(seed);
    let m = n * avg_deg;
    let mut edges = Vec::with_capacity(m);
    for _ in 0..m {
        let a = rng.below(n as u64);
        let b = rng.below(n as u64);
        // Weights in [0.5, 4.5) so weighted PageRank / Dijkstra are non-trivial.
        let w = if weighted {
            0.5 + (rng.below(4000) as f64) / 1000.0
        } else {
            1.0
        };
        edges.push((a, b, w));
    }
    VecGraphSource {
        nodes: (0..n as u64).collect(),
        edges,
    }
    .build(orientation, weighted)
    .expect("build test graph")
}

/// Run `op` on a dedicated `threads`-wide rayon pool (mirrors the server's analytics-pool `install`).
fn on_pool<R: Send>(threads: usize, op: impl FnOnce() -> R + Send) -> R {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("build test pool")
        .install(op)
}

const SEQ: Execution = Execution::sequential();
/// Force parallelism even on a modest graph (`0` threshold) so the test actually exercises `rayon`.
const PAR: Execution = Execution::parallel_with_threshold(0);

// -------------------------------------------------------------------------------------------------
// PageRank
// -------------------------------------------------------------------------------------------------

#[test]
fn pagerank_parallel_equals_sequential_bit_identical() {
    let cfg = PageRankConfig::default();
    for (orient, weighted) in [
        (Orientation::Directed, false),
        (Orientation::Directed, true),
        (Orientation::Undirected, false),
        (Orientation::Undirected, true),
    ] {
        let g = gen_graph(2000, 6, 42, orient, weighted);
        let seq = pagerank_with(&g, cfg, SEQ, &Cancel::never()).unwrap();
        let par = pagerank_with(&g, cfg, PAR, &Cancel::never()).unwrap();
        assert_eq!(
            seq.rank, par.rank,
            "pagerank must be bit-identical seq vs par ({orient:?}, weighted={weighted})"
        );
        assert_eq!(seq.iterations, par.iterations);
        assert_eq!(seq.converged, par.converged);
        // Sanity: still a probability distribution.
        let sum: f64 = par.rank.iter().sum();
        assert!((sum - 1.0).abs() < 1e-6, "ranks must sum to 1, got {sum}");
    }
}

#[test]
fn pagerank_bit_identical_across_pool_widths() {
    let g = gen_graph(1500, 8, 7, Orientation::Directed, false);
    let cfg = PageRankConfig::default();
    let baseline = pagerank_with(&g, cfg, PAR, &Cancel::never()).unwrap().rank;
    for threads in [1usize, 2, 4, 8, 16] {
        let scores = on_pool(threads, || {
            pagerank_with(&g, cfg, PAR, &Cancel::never()).unwrap().rank
        });
        assert_eq!(
            scores, baseline,
            "pagerank must be bit-identical on a {threads}-thread pool"
        );
    }
}

#[test]
fn personalized_pagerank_parallel_equals_sequential() {
    let mut g = gen_graph(1200, 5, 99, Orientation::Directed, false);
    // Attach a non-uniform seed column.
    let seed: Vec<f64> = (0..g.node_count())
        .map(|i| if i % 7 == 0 { 3.0 } else { 0.1 })
        .collect();
    g.attach_node_column("seed", seed).unwrap();
    let cfg = PageRankConfig::default();
    let seq = personalized_pagerank_with(&g, "seed", cfg, SEQ, &Cancel::never()).unwrap();
    let par = personalized_pagerank_with(&g, "seed", cfg, PAR, &Cancel::never()).unwrap();
    assert_eq!(seq.rank, par.rank, "personalized pagerank seq vs par");
}

// -------------------------------------------------------------------------------------------------
// Triangle counting
// -------------------------------------------------------------------------------------------------

#[test]
fn triangles_parallel_equals_sequential_bit_identical() {
    for orient in [Orientation::Undirected, Orientation::Directed] {
        let g = gen_graph(1000, 10, 123, orient, false);
        let seq = triangle_count_with(&g, SEQ, &Cancel::never()).unwrap();
        let par = triangle_count_with(&g, PAR, &Cancel::never()).unwrap();
        assert_eq!(seq.triangles, par.triangles, "triangles ({orient:?})");
        assert_eq!(seq.coefficient, par.coefficient, "coefficient ({orient:?})");
        assert_eq!(
            seq.total_triangles, par.total_triangles,
            "total_triangles ({orient:?})"
        );
    }
}

#[test]
fn triangles_bit_identical_across_pool_widths() {
    let g = gen_graph(800, 12, 55, Orientation::Undirected, false);
    let baseline = triangle_count_with(&g, PAR, &Cancel::never())
        .unwrap()
        .triangles;
    for threads in [1usize, 2, 4, 8, 16] {
        let t = on_pool(threads, || {
            triangle_count_with(&g, PAR, &Cancel::never())
                .unwrap()
                .triangles
        });
        assert_eq!(t, baseline, "triangles on a {threads}-thread pool");
    }
}

// -------------------------------------------------------------------------------------------------
// Weakly connected components (lock-free union-find)
// -------------------------------------------------------------------------------------------------

#[test]
fn wcc_parallel_equals_sequential_bit_identical() {
    for orient in [Orientation::Directed, Orientation::Undirected] {
        // Sparse enough to have several components.
        let g = gen_graph(3000, 1, 314, orient, false);
        let seq = weakly_connected_components_with(&g, SEQ, &Cancel::never()).unwrap();
        let par = weakly_connected_components_with(&g, PAR, &Cancel::never()).unwrap();
        assert_eq!(
            seq.component, par.component,
            "wcc component labels ({orient:?})"
        );
        assert_eq!(seq.count, par.count, "wcc component count ({orient:?})");
    }
}

/// The lock-free union-find must be *correct under contention*: run the parallel engine many times on
/// a wide pool and confirm it always reproduces the sequential partition. A data race in the atomic
/// linking or path-halving would surface here as an occasional mismatch.
#[test]
fn wcc_lockfree_is_correct_under_contention() {
    let g = gen_graph(20_000, 3, 2718, Orientation::Directed, false);
    let expected = weakly_connected_components_with(&g, SEQ, &Cancel::never()).unwrap();
    for run in 0..64 {
        let got = on_pool(16, || {
            weakly_connected_components_with(&g, PAR, &Cancel::never()).unwrap()
        });
        assert_eq!(
            got.component, expected.component,
            "lock-free WCC diverged from the sequential partition on run {run}"
        );
        assert_eq!(got.count, expected.count, "component count on run {run}");
    }
}

#[test]
fn wcc_bit_identical_across_pool_widths() {
    let g = gen_graph(5000, 2, 17, Orientation::Undirected, false);
    let baseline = weakly_connected_components_with(&g, PAR, &Cancel::never())
        .unwrap()
        .component;
    for threads in [1usize, 2, 4, 8, 16] {
        let c = on_pool(threads, || {
            weakly_connected_components_with(&g, PAR, &Cancel::never())
                .unwrap()
                .component
        });
        assert_eq!(c, baseline, "wcc on a {threads}-thread pool");
    }
}

// -------------------------------------------------------------------------------------------------
// Degree centrality
// -------------------------------------------------------------------------------------------------

#[test]
fn degree_parallel_equals_sequential() {
    let g = gen_graph(2000, 5, 88, Orientation::Directed, false);
    for dir in [Direction::Out, Direction::In, Direction::Total] {
        let seq = degree_centrality_with(&g, dir, SEQ);
        let par = degree_centrality_with(&g, dir, PAR);
        assert_eq!(seq, par, "degree ({dir:?}) seq vs par");
    }
}

// -------------------------------------------------------------------------------------------------
// Closeness / betweenness (already parallel; the knob must preserve determinism)
// -------------------------------------------------------------------------------------------------

#[test]
fn closeness_parallel_equals_sequential_bit_identical() {
    for weighted in [false, true] {
        let g = gen_graph(400, 4, 61, Orientation::Undirected, weighted);
        let seq = closeness_centrality_with(&g, SEQ, &Cancel::never()).unwrap();
        let par = closeness_centrality_with(&g, PAR, &Cancel::never()).unwrap();
        assert_eq!(seq, par, "closeness seq vs par (weighted={weighted})");
    }
}

#[test]
fn betweenness_parallel_equals_sequential_bit_identical() {
    let g = gen_graph(400, 3, 71, Orientation::Undirected, false);
    let seq = undirected_scale(
        &g,
        betweenness_centrality_with(&g, SEQ, &Cancel::never()).unwrap(),
    );
    let par = undirected_scale(
        &g,
        betweenness_centrality_with(&g, PAR, &Cancel::never()).unwrap(),
    );
    assert_eq!(seq, par, "betweenness seq vs par");
}

// -------------------------------------------------------------------------------------------------
// Multi-source Dijkstra
// -------------------------------------------------------------------------------------------------

#[test]
fn dijkstra_multi_source_parallel_equals_sequential_and_single_source() {
    let g = gen_graph(600, 5, 33, Orientation::Directed, true);
    let sources: Vec<InternalId> = (0..g.node_count() as InternalId).step_by(3).collect();

    let seq = dijkstra_multi_source(&g, &sources, SEQ, &Cancel::never()).unwrap();
    let par = dijkstra_multi_source(&g, &sources, PAR, &Cancel::never()).unwrap();

    assert_eq!(seq.len(), sources.len());
    for (i, (s, p)) in seq.iter().zip(par.iter()).enumerate() {
        assert_eq!(s.dist, p.dist, "multi-source dist mismatch at index {i}");
        // Cross-check against the single-source entry point.
        let single = dijkstra(&g, sources[i], &Cancel::never()).unwrap();
        assert_eq!(
            s.dist, single.dist,
            "multi-source vs single-source at index {i}"
        );
    }
}

// -------------------------------------------------------------------------------------------------
// Label propagation — the one algorithm whose two variants may differ (documented). Each variant
// must still be internally reproducible, and both must recover obvious community structure.
// -------------------------------------------------------------------------------------------------

#[test]
fn label_propagation_synchronous_is_reproducible() {
    let g = gen_graph(1000, 6, 44, Orientation::Undirected, false);
    let cfg = LabelPropagationConfig::default();
    let a = label_propagation_with(&g, cfg, PAR, &Cancel::never()).unwrap();
    // Same input, same result every run — and identical across pool widths.
    for threads in [1usize, 2, 4, 8, 16] {
        let b = on_pool(threads, || {
            label_propagation_with(&g, cfg, PAR, &Cancel::never()).unwrap()
        });
        assert_eq!(
            a.label, b.label,
            "synchronous LPA must be reproducible ({threads} threads)"
        );
        assert_eq!(a.count, b.count);
    }
}

#[test]
fn label_propagation_both_variants_find_two_cliques() {
    // Two 3-cliques joined by a single bridge edge: both the semi-synchronous (sequential) and the
    // synchronous (parallel) variants must place each clique in one community.
    let src = VecGraphSource {
        nodes: (0..6).collect(),
        edges: [
            (0, 1),
            (1, 2),
            (0, 2), // clique A
            (3, 4),
            (4, 5),
            (3, 5), // clique B
            (2, 3), // bridge
        ]
        .iter()
        .map(|&(a, b)| (a, b, 1.0))
        .collect(),
    };
    let g = src.build(Orientation::Undirected, false).unwrap();
    let cfg = LabelPropagationConfig::default();
    for exec in [SEQ, PAR] {
        let r = label_propagation_with(&g, cfg, exec, &Cancel::never()).unwrap();
        assert_eq!(r.label[0], r.label[1], "clique A ({:?})", exec.mode());
        assert_eq!(r.label[1], r.label[2], "clique A ({:?})", exec.mode());
        assert_eq!(r.label[3], r.label[4], "clique B ({:?})", exec.mode());
        assert_eq!(r.label[4], r.label[5], "clique B ({:?})", exec.mode());
    }
}
