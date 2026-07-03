//! `rmp` #580 — the parallelism-gap probes: a PageRank thread-width sweep plus the small-graph
//! regression checks that justify the WCC and degree parallel **floors**.
//!
//! Ignored by default (these are benchmarks, not correctness gates). Run in release:
//!
//! ```text
//! cargo test -p graphus-gds --release --test perf_probe -- --ignored --nocapture
//! ```
//!
//! - [`probe_pagerank_widths`] times PageRank under a fixed-width `rayon` pool at `{1,2,4,8,16}`
//!   threads, reporting `sequential_time / parallel_time` — how many cores the pull/gather actually
//!   keeps busy. On a memory-bandwidth-bound SpMV this plateaus around the physical-core count.
//! - [`probe_degree_sizes`] / [`probe_wcc_sizes`] sweep graph size under the **production default**
//!   execution ([`Execution::parallel`], the 128 threshold) vs sequential, demonstrating that the
//!   `rmp` #580 floors keep small graphs on the (faster) sequential path — i.e. the parallel path is
//!   never slower than serial for the sizes that reach it. These are the measurements the
//!   `DEGREE_MIN_PARALLEL_NODES` / `WCC_MIN_PARALLEL_EDGES` floors are calibrated against.

use graphus_gds::algo::degree::{Direction, degree_centrality_with};
use graphus_gds::algo::pagerank::{PageRankConfig, pagerank_with};
use graphus_gds::algo::wcc::weakly_connected_components_with;
use graphus_gds::{Cancel, CsrGraph, Execution, Orientation, VecGraphSource};
use std::time::{Duration, Instant};

/// A minimal reproducible SplitMix64 generator (no external RNG dependency).
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

fn gen_graph(n: usize, avg_deg: usize, seed: u64, orient: Orientation) -> CsrGraph {
    let mut rng = Lcg::new(seed);
    let m = n * avg_deg;
    let mut edges = Vec::with_capacity(m);
    for _ in 0..m {
        let a = rng.below(n as u64);
        let b = rng.below(n as u64);
        edges.push((a, b, 1.0));
    }
    VecGraphSource {
        nodes: (0..n as u64).collect(),
        edges,
    }
    .build(orient, false)
    .expect("build graph")
}

const SEQ: Execution = Execution::sequential();
/// Force the parallel code path even on a small graph (`0` threshold), for the width sweep.
const PAR: Execution = Execution::parallel_with_threshold(0);
/// The production default: parallel above the crate threshold (128) — exercises the #580 floors.
const DEF: Execution = Execution::parallel();

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

fn on_pool<R: Send>(threads: usize, op: impl FnOnce() -> R + Send) -> R {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("pool")
        .install(op)
}

#[test]
#[ignore = "benchmark: run with --release -- --ignored --nocapture"]
fn probe_pagerank_widths() {
    let g = gen_graph(500_000, 12, 1, Orientation::Directed);
    let cfg = PageRankConfig {
        max_iter: 30,
        ..PageRankConfig::default()
    };
    let seq = best_of(3, || pagerank_with(&g, cfg, SEQ, &Cancel::never()).unwrap());
    println!("\n[pagerank 500k/6M] seq {seq:>9.2?}");
    for w in [1usize, 2, 4, 8, 16] {
        let par = on_pool(w, || {
            best_of(3, || pagerank_with(&g, cfg, PAR, &Cancel::never()).unwrap())
        });
        println!(
            "  width {w:>2}: par {:>9.2?}  speedup {:>5.2}x",
            par,
            seq.as_secs_f64() / par.as_secs_f64()
        );
    }
}

#[test]
#[ignore = "benchmark: run with --release -- --ignored --nocapture"]
fn probe_degree_sizes() {
    println!("\n[degree out-degree] seq vs DEFAULT-parallel across n (production gating):");
    for n in [1_000usize, 10_000, 100_000, 500_000, 1_000_000, 4_000_000] {
        let g = gen_graph(n, 8, 2, Orientation::Directed);
        let seq = best_of(5, || degree_centrality_with(&g, Direction::Out, SEQ));
        let par = best_of(5, || degree_centrality_with(&g, Direction::Out, DEF));
        println!(
            "  n={n:>9}: seq {seq:>9.2?}  par {par:>9.2?}  speedup {:>5.2}x",
            seq.as_secs_f64() / par.as_secs_f64().max(1e-12)
        );
    }
}

#[test]
#[ignore = "benchmark: run with --release -- --ignored --nocapture"]
fn probe_wcc_sizes() {
    println!("\n[wcc] seq vs DEFAULT-parallel across n (avg_deg 4, production gating):");
    for n in [1_000usize, 10_000, 100_000, 1_000_000, 2_000_000] {
        let g = gen_graph(n, 4, 3, Orientation::Directed);
        let seq = best_of(3, || {
            weakly_connected_components_with(&g, SEQ, &Cancel::never()).unwrap()
        });
        let par = best_of(3, || {
            weakly_connected_components_with(&g, DEF, &Cancel::never()).unwrap()
        });
        println!(
            "  n={n:>9}: seq {seq:>9.2?}  par {par:>9.2?}  speedup {:>5.2}x",
            seq.as_secs_f64() / par.as_secs_f64().max(1e-12)
        );
    }
}
