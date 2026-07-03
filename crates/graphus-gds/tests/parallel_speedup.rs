//! `rmp` #342 / #559 — empirical multi-core speedup harness (measure, don't assume).
//!
//! Ignored by default (it is a benchmark, not a correctness gate). Run it in release to see the
//! sequential-vs-parallel wall-clock and the effective-core count for each parallelised algorithm:
//!
//! ```text
//! cargo test -p graphus-gds --release --test parallel_speedup -- --ignored --nocapture
//! ```
//!
//! The "cores" column is `sequential_time / parallel_time` — a direct proxy for how many cores the
//! parallel path actually kept busy. The parallel run uses the global `rayon` pool (all cores).

use graphus_gds::algo::centrality::{betweenness_centrality_with, closeness_centrality_with};
use graphus_gds::algo::community::{LabelPropagationConfig, label_propagation_with};
use graphus_gds::algo::pagerank::{PageRankConfig, pagerank_with};
use graphus_gds::algo::shortest_path::dijkstra_multi_source;
use graphus_gds::algo::triangles::triangle_count_with;
use graphus_gds::algo::wcc::weakly_connected_components_with;
use graphus_gds::{Cancel, CsrGraph, Execution, InternalId, Orientation, VecGraphSource};
use std::time::{Duration, Instant};

struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }
    fn next_u64(&mut self) -> u64 {
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

fn gen_graph(n: usize, avg_deg: usize, seed: u64, orient: Orientation, weighted: bool) -> CsrGraph {
    let mut rng = Lcg::new(seed);
    let m = n * avg_deg;
    let mut edges = Vec::with_capacity(m);
    for _ in 0..m {
        let a = rng.below(n as u64);
        let b = rng.below(n as u64);
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
    .build(orient, weighted)
    .expect("build graph")
}

const SEQ: Execution = Execution::sequential();
const PAR: Execution = Execution::parallel_with_threshold(0);

/// Best-of-`runs` wall time for `f`.
fn best_of<T>(runs: u32, mut f: impl FnMut() -> T) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..runs {
        let t0 = Instant::now();
        let out = f();
        let dt = t0.elapsed();
        std::hint::black_box(out);
        best = best.min(dt);
    }
    best
}

fn report(name: &str, seq: Duration, par: Duration) {
    let cores = seq.as_secs_f64() / par.as_secs_f64().max(1e-12);
    println!(
        "{name:<28} seq {:>9.2?}   par {:>9.2?}   speedup {cores:>6.2}x",
        seq, par
    );
}

#[test]
#[ignore = "benchmark: run with --release -- --ignored --nocapture"]
fn parallel_speedup() {
    let cores = std::thread::available_parallelism().map_or(0, |p| p.get());
    println!("\n=== GDS parallel speedup (rmp #342 / #559) — {cores} logical cores ===\n");

    // PageRank: large, moderately dense directed graph.
    {
        let g = gen_graph(500_000, 12, 1, Orientation::Directed, false);
        let cfg = PageRankConfig {
            max_iter: 30,
            ..PageRankConfig::default()
        };
        let seq = best_of(3, || pagerank_with(&g, cfg, SEQ, &Cancel::never()).unwrap());
        let par = best_of(3, || pagerank_with(&g, cfg, PAR, &Cancel::never()).unwrap());
        report("pagerank (500k n / 6M e)", seq, par);
    }

    // Weighted PageRank.
    {
        let g = gen_graph(500_000, 12, 2, Orientation::Directed, true);
        let cfg = PageRankConfig {
            max_iter: 30,
            ..PageRankConfig::default()
        };
        let seq = best_of(3, || pagerank_with(&g, cfg, SEQ, &Cancel::never()).unwrap());
        let par = best_of(3, || pagerank_with(&g, cfg, PAR, &Cancel::never()).unwrap());
        report("pagerank weighted", seq, par);
    }

    // Triangle counting: denser undirected graph.
    {
        let g = gen_graph(60_000, 20, 3, Orientation::Undirected, false);
        let seq = best_of(3, || {
            triangle_count_with(&g, SEQ, &Cancel::never()).unwrap()
        });
        let par = best_of(3, || {
            triangle_count_with(&g, PAR, &Cancel::never()).unwrap()
        });
        report("triangles (60k n / 1.2M e)", seq, par);
    }

    // WCC: large sparse graph.
    {
        let g = gen_graph(2_000_000, 4, 4, Orientation::Directed, false);
        let seq = best_of(3, || {
            weakly_connected_components_with(&g, SEQ, &Cancel::never()).unwrap()
        });
        let par = best_of(3, || {
            weakly_connected_components_with(&g, PAR, &Cancel::never()).unwrap()
        });
        report("wcc (2M n / 8M e)", seq, par);
    }

    // Label propagation (synchronous parallel variant vs semi-sync sequential).
    {
        let g = gen_graph(300_000, 10, 5, Orientation::Undirected, false);
        let cfg = LabelPropagationConfig { max_iter: 10 };
        let seq = best_of(2, || {
            label_propagation_with(&g, cfg, SEQ, &Cancel::never()).unwrap()
        });
        let par = best_of(2, || {
            label_propagation_with(&g, cfg, PAR, &Cancel::never()).unwrap()
        });
        report("label propagation (10 sweeps)", seq, par);
    }

    // Multi-source Dijkstra: many sources over a weighted graph.
    {
        let g = gen_graph(50_000, 8, 6, Orientation::Directed, true);
        let sources: Vec<InternalId> = (0..2000).collect();
        let seq = best_of(3, || {
            dijkstra_multi_source(&g, &sources, SEQ, &Cancel::never()).unwrap()
        });
        let par = best_of(3, || {
            dijkstra_multi_source(&g, &sources, PAR, &Cancel::never()).unwrap()
        });
        report("dijkstra x2000 sources", seq, par);
    }

    // Closeness (BFS per source) — heavy per-source, smaller n.
    {
        let g = gen_graph(4000, 8, 7, Orientation::Undirected, false);
        let seq = best_of(3, || {
            closeness_centrality_with(&g, SEQ, &Cancel::never()).unwrap()
        });
        let par = best_of(3, || {
            closeness_centrality_with(&g, PAR, &Cancel::never()).unwrap()
        });
        report("closeness (4k n)", seq, par);
    }

    // Betweenness (Brandes per source).
    {
        let g = gen_graph(3000, 6, 8, Orientation::Undirected, false);
        let seq = best_of(2, || {
            betweenness_centrality_with(&g, SEQ, &Cancel::never()).unwrap()
        });
        let par = best_of(2, || {
            betweenness_centrality_with(&g, PAR, &Cancel::never()).unwrap()
        });
        report("betweenness (3k n)", seq, par);
    }

    println!();
}
