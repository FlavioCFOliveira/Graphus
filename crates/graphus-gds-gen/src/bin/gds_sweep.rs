//! `gds_sweep` — the hermetic **scalability + CSR-footprint + parallelism** sweep for
//! `examples/gds-analytics`.
//!
//! # What it measures (and why this is the *honest* sweep)
//!
//! `examples/gds-analytics` task #259 asks for a multi-core scalability sweep of the GDS algorithms.
//! We drive `graphus-gds` exactly as the server does and report only what is *actually* measured on
//! this run — never a fabricated curve.
//!
//! As of `rmp` #342 / #559 the GDS algorithm library is **multi-threaded**: a deterministic
//! [`Execution`] knob fans each parallelisable algorithm across cores with `rayon` while keeping the
//! result **bit-identical across pool widths** (the DST determinism guarantee). Parallel today:
//! **PageRank, Brandes betweenness, closeness, WCC (lock-free union-find), triangle counting,
//! out-degree, label propagation (a distinct synchronous variant) and multi-source Dijkstra**.
//! Inherently sequential (documented): **SCC (Tarjan)** and **single-source Dijkstra / Bellman-Ford**.
//!
//! This binary emits **two** honest measurements:
//!
//! 1. A **graph-SIZE sweep** (`sizes`): for each graph size, the wall time of every algorithm (run
//!    with the library's default [`Execution`], i.e. parallel above its threshold — exactly as the
//!    server runs them) plus the **resident CSR-projection footprint** via [`CsrGraph::memory_bytes`],
//!    reduced to **bytes-per-node** and **bytes-per-edge** so it can be compared across sizes.
//! 2. A **parallelism demonstration** (`parallelism`) at a single fixed graph size: each
//!    apples-to-apples parallel algorithm is timed under [`Execution::sequential`] and under
//!    [`Execution::parallel_with_threshold`]`(0)` inside **fixed-width `rayon` thread pools** (1, 2 and
//!    all cores), reporting the **real measured speedup** (`sequential_time / best_parallel_time`) and
//!    proving the results are **identical across every thread width** (bit-identical for the integer
//!    algorithms; matching to a documented `f64` tolerance for PageRank / centrality). Label
//!    propagation is excluded from this apples-to-apples set because its parallel form is a *distinct*
//!    synchronous variant (see the crate docs); SCC / single-source Dijkstra are excluded because they
//!    are sequential by construction.
//!
//! Output is machine-readable JSON that `run.sh` consumes for the evidence report + honesty gate. The
//! sweep is fully hermetic (no server, no network) and deterministic (the generator is a pure function
//! of its seed), so it is CI-runnable.
//!
//! Usage:
//! ```text
//! cargo run -p graphus-gds-gen --bin gds_sweep -- [--out <file.json>] [--sizes 40,120,...] \
//!   [--repeats N] [--par-demo-size <field_size>] [--par-demo-repeats N]
//! ```

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use graphus_gds::algo::centrality::{
    betweenness_centrality, betweenness_centrality_with, closeness_centrality,
    closeness_centrality_with, undirected_scale,
};
use graphus_gds::algo::community::{LabelPropagationConfig, label_propagation};
use graphus_gds::algo::degree::{Direction, degree_centrality, degree_centrality_with};
use graphus_gds::algo::pagerank::{PageRankConfig, pagerank, pagerank_with};
use graphus_gds::algo::scc::strongly_connected_components;
use graphus_gds::algo::shortest_path::dijkstra;
use graphus_gds::algo::triangles::{triangle_count, triangle_count_with};
use graphus_gds::algo::wcc::{weakly_connected_components, weakly_connected_components_with};
use graphus_gds::{Cancel, CsrBuilder, CsrGraph, Execution, Orientation};

use graphus_gds_gen::{Citation, GenConfig, generate};

/// One sweep record: the algorithm timings + the CSR footprint at a given graph size.
struct SweepRecord {
    field_size: u64,
    community_count: u64,
    node_count: usize,
    edge_count: usize,
    csr_bytes: usize,
    bytes_per_node: f64,
    bytes_per_edge: f64,
    timings_ms: Vec<(&'static str, f64)>,
}

/// One algorithm's parallelism measurement at the demonstration graph size.
struct ParAlgo {
    name: &'static str,
    /// Best-of-`repeats` wall time under [`Execution::sequential`], in milliseconds.
    seq_ms: f64,
    /// `(thread_width, best-of-`repeats` parallel wall time in ms)` for each fixed-width pool.
    par_ms: Vec<(usize, f64)>,
    /// The thread width that produced the fastest parallel time.
    best_width: usize,
    /// The fastest parallel wall time across all widths, in milliseconds.
    best_par_ms: f64,
    /// `seq_ms / best_par_ms` — the real measured speedup on this host, this run.
    speedup: f64,
    /// Whether the result was identical across the sequential run and every parallel width.
    deterministic: bool,
}

/// The parallelism demonstration at one fixed graph size.
struct ParallelismDemo {
    field_size: u64,
    community_count: u64,
    node_count: usize,
    edge_count: usize,
    thread_widths: Vec<usize>,
    algos: Vec<ParAlgo>,
    /// The best speedup measured across the demonstrated algorithms (the headline number).
    max_speedup: f64,
    /// `true` iff every demonstrated algorithm was identical across the sequential run and all widths.
    deterministic_across_widths: bool,
}

fn main() -> ExitCode {
    let mut out_path: Option<PathBuf> = None;
    // Default size sweep: a geometric-ish progression of field sizes (×community_count = node count).
    let mut sizes: Vec<u64> = vec![40, 120, 360, 1080];
    let mut repeats: u32 = 3;
    // The parallelism demonstration runs at one fixed, moderate graph size so its sequential baseline
    // stays a short burst (a few seconds) rather than a sustained heavy sweep. Overridable.
    let mut par_demo_field_size: u64 = 360;
    let mut par_demo_repeats: u32 = 2;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => match args.next() {
                Some(v) => out_path = Some(PathBuf::from(v)),
                None => return fail("--out requires a path"),
            },
            "--sizes" => {
                let Some(v) = args.next() else {
                    return fail("--sizes requires a comma-separated list");
                };
                let mut parsed = Vec::new();
                for tok in v.split(',') {
                    match tok.trim().parse::<u64>() {
                        Ok(n) if n >= 2 => parsed.push(n),
                        _ => return fail(&format!("invalid size '{tok}' (need integers >= 2)")),
                    }
                }
                if parsed.is_empty() {
                    return fail("--sizes produced no values");
                }
                sizes = parsed;
            }
            "--repeats" => match args.next().and_then(|v| v.parse::<u32>().ok()) {
                Some(n) if n >= 1 => repeats = n,
                _ => return fail("--repeats requires an integer >= 1"),
            },
            "--par-demo-size" => match args.next().and_then(|v| v.parse::<u64>().ok()) {
                Some(n) if n >= 2 => par_demo_field_size = n,
                _ => return fail("--par-demo-size requires an integer >= 2 (a field size)"),
            },
            "--par-demo-repeats" => match args.next().and_then(|v| v.parse::<u32>().ok()) {
                Some(n) if n >= 1 => par_demo_repeats = n,
                _ => return fail("--par-demo-repeats requires an integer >= 1"),
            },
            "-h" | "--help" => {
                eprintln!(
                    "usage: gds_sweep [--out <file.json>] [--sizes 40,120,360] [--repeats N] \
                     [--par-demo-size <field_size>] [--par-demo-repeats N]\n\
                     Multi-threaded GDS scalability + CSR-footprint sweep over graph SIZE, plus a \
                     sequential-vs-parallel speedup + cross-width determinism demonstration."
                );
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unexpected argument '{other}'")),
        }
    }

    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // The thread widths for the parallelism demonstration: 1, 2 and all cores (deduplicated, ascending).
    let mut widths = vec![1usize];
    if cores >= 2 {
        widths.push(2);
    }
    if cores > 2 {
        widths.push(cores);
    }

    eprintln!(
        "gds_sweep: GDS is multi-threaded via a deterministic Execution knob (rmp #342/#559); \
         RAYON_NUM_THREADS honoured for the default-execution size sweep. Sweeping graph SIZE on a \
         {cores}-core host (sizes={sizes:?} repeats={repeats}), then demonstrating sequential-vs-\
         parallel speedup + cross-width determinism at field_size={par_demo_field_size} across \
         widths={widths:?}."
    );

    let mut records = Vec::with_capacity(sizes.len());
    for &field_size in &sizes {
        match measure_size(field_size, repeats) {
            Ok(rec) => {
                eprintln!(
                    "  size field={field_size} nodes={} edges={} csr={} B ({:.1} B/node, {:.2} B/edge)",
                    rec.node_count,
                    rec.edge_count,
                    rec.csr_bytes,
                    rec.bytes_per_node,
                    rec.bytes_per_edge
                );
                records.push(rec);
            }
            Err(e) => return fail(&e),
        }
    }

    let demo = match measure_parallelism(par_demo_field_size, par_demo_repeats, &widths) {
        Ok(d) => {
            eprintln!(
                "  parallelism demo @ field={} nodes={} edges={} widths={:?} — deterministic across \
                 widths: {}; best measured speedup: {:.2}x",
                d.field_size,
                d.node_count,
                d.edge_count,
                d.thread_widths,
                d.deterministic_across_widths,
                d.max_speedup,
            );
            for a in &d.algos {
                eprintln!(
                    "    {:<16} seq {:>9.3} ms   par(best@{:>2}) {:>9.3} ms   speedup {:>5.2}x   \
                     deterministic {}",
                    a.name, a.seq_ms, a.best_width, a.best_par_ms, a.speedup, a.deterministic,
                );
            }
            d
        }
        Err(e) => return fail(&e),
    };

    let json = render_json(cores, repeats, &records, &demo);
    match &out_path {
        Some(p) => {
            if let Err(e) = std::fs::write(p, &json) {
                return fail(&format!("cannot write {}: {e}", p.display()));
            }
            eprintln!("gds_sweep: wrote {}", p.display());
        }
        None => println!("{json}"),
    }

    ExitCode::SUCCESS
}

/// Builds the influence-network CSR (undirected, for the symmetric centrality/community algorithms)
/// at the given `field_size`, runs every algorithm `repeats` times keeping the **minimum** wall time
/// (the least-noisy estimate), and records the CSR footprint. The algorithms run with the library's
/// DEFAULT [`Execution`] (parallel above its threshold) — exactly how the server runs them — so these
/// timings are the multi-core figures.
fn measure_size(field_size: u64, repeats: u32) -> Result<SweepRecord, String> {
    let community_count = 4;
    let (undirected, directed, node_count) = build_influence_csrs(field_size, community_count)?;

    let edge_count = undirected.edge_count();
    let csr_bytes = undirected.memory_bytes();
    let bytes_per_node = if node_count > 0 {
        csr_bytes as f64 / node_count as f64
    } else {
        0.0
    };
    let bytes_per_edge = if edge_count > 0 {
        csr_bytes as f64 / edge_count as f64
    } else {
        0.0
    };

    // Time each algorithm; keep the minimum over `repeats` runs (best-case, least scheduler noise).
    let cancel = Cancel::never();
    let mut timings_ms: Vec<(&'static str, f64)> = Vec::new();

    timings_ms.push((
        "pageRank",
        bench(repeats, || {
            let _ = pagerank(&undirected, PageRankConfig::default(), &cancel);
        }),
    ));
    timings_ms.push((
        "betweenness",
        bench(repeats, || {
            if let Ok(raw) = betweenness_centrality(&undirected, &cancel) {
                let _ = undirected_scale(&undirected, raw);
            }
        }),
    ));
    timings_ms.push((
        "degree",
        bench(repeats, || {
            let _ = degree_centrality(&undirected, Direction::Out);
        }),
    ));
    timings_ms.push((
        "closeness",
        bench(repeats, || {
            let _ = closeness_centrality(&undirected, &cancel);
        }),
    ));
    timings_ms.push((
        "wcc",
        bench(repeats, || {
            let _ = weakly_connected_components(&undirected, &cancel);
        }),
    ));
    timings_ms.push((
        "scc",
        bench(repeats, || {
            let _ = strongly_connected_components(&directed, &cancel);
        }),
    ));
    timings_ms.push((
        "triangleCount",
        bench(repeats, || {
            let _ = triangle_count(&undirected, &cancel);
        }),
    ));
    timings_ms.push((
        "labelPropagation",
        bench(repeats, || {
            let _ = label_propagation(&undirected, LabelPropagationConfig::default(), &cancel);
        }),
    ));
    timings_ms.push((
        "dijkstra",
        bench(repeats, || {
            let _ = dijkstra(&directed, 0, &cancel);
        }),
    ));

    Ok(SweepRecord {
        field_size,
        community_count,
        node_count,
        edge_count,
        csr_bytes,
        bytes_per_node,
        bytes_per_edge,
        timings_ms,
    })
}

/// The parallelism demonstration: at one fixed graph size, measure each apples-to-apples parallel
/// algorithm under [`Execution::sequential`] and under [`Execution::parallel_with_threshold`]`(0)`
/// inside fixed-width `rayon` pools, reporting the real speedup and proving the result is identical
/// across every width.
///
/// Only algorithms whose sequential and parallel forms compute the **same** function are demonstrated
/// here — PageRank, betweenness, closeness, WCC, triangle counting and out-degree — so both the
/// speedup and the cross-width equality are meaningful. Label propagation is intentionally excluded (a
/// distinct synchronous parallel variant), as are the inherently sequential SCC / single-source
/// Dijkstra.
fn measure_parallelism(
    field_size: u64,
    repeats: u32,
    widths: &[usize],
) -> Result<ParallelismDemo, String> {
    let community_count = 4;
    let (undirected, _directed, node_count) = build_influence_csrs(field_size, community_count)?;
    let edge_count = undirected.edge_count();

    // One fixed-width pool per width. `install` routes the algorithm's `rayon` work onto exactly this
    // many worker threads, so the "width" is real and controlled (not the ambient global pool).
    let mut pools: Vec<(usize, rayon::ThreadPool)> = Vec::with_capacity(widths.len());
    for &w in widths {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(w)
            .build()
            .map_err(|e| format!("failed to build a {w}-thread rayon pool: {e}"))?;
        pools.push((w, pool));
    }

    let cancel = Cancel::never();
    let pr_cfg = PageRankConfig::default();

    let mut algos = Vec::new();
    // PageRank / betweenness / closeness are f64 — the parallel path matches the sequential result to a
    // documented tolerance, so compare with a small combined absolute+relative slack (1e-9).
    algos.push(run_par_algo("pageRank", 1e-9, repeats, &pools, |e| {
        pagerank_with(&undirected, pr_cfg, e, &cancel)
            .map(|r| r.rank)
            .unwrap_or_default()
    }));
    algos.push(run_par_algo("betweenness", 1e-9, repeats, &pools, |e| {
        betweenness_centrality_with(&undirected, e, &cancel).unwrap_or_default()
    }));
    algos.push(run_par_algo("closeness", 1e-9, repeats, &pools, |e| {
        closeness_centrality_with(&undirected, e, &cancel).unwrap_or_default()
    }));
    // WCC / triangleCount / degree are integer-exact — demand BIT-IDENTICAL equality (tol = 0.0).
    algos.push(run_par_algo("wcc", 0.0, repeats, &pools, |e| {
        weakly_connected_components_with(&undirected, e, &cancel)
            .map(|r| r.component.iter().map(|&c| c as f64).collect())
            .unwrap_or_default()
    }));
    algos.push(run_par_algo("triangleCount", 0.0, repeats, &pools, |e| {
        triangle_count_with(&undirected, e, &cancel)
            .map(|r| r.triangles.iter().map(|&t| t as f64).collect())
            .unwrap_or_default()
    }));
    algos.push(run_par_algo("degree", 0.0, repeats, &pools, |e| {
        degree_centrality_with(&undirected, Direction::Out, e)
            .iter()
            .map(|&d| d as f64)
            .collect()
    }));

    let max_speedup = algos.iter().map(|a| a.speedup).fold(0.0_f64, f64::max);
    let deterministic_across_widths = algos.iter().all(|a| a.deterministic);

    Ok(ParallelismDemo {
        field_size,
        community_count,
        node_count,
        edge_count,
        thread_widths: widths.to_vec(),
        algos,
        max_speedup,
        deterministic_across_widths,
    })
}

/// Runs one algorithm under sequential execution (reference) and under forced-parallel execution in
/// each fixed-width pool, returning its timings, real speedup and cross-width determinism verdict.
///
/// `run(exec)` must return a comparable **fingerprint** of the algorithm's result (the score/label/
/// count vector, integers cast to `f64`). `tol == 0.0` demands a bit-identical fingerprint across all
/// runs (the integer algorithms); a positive `tol` allows the documented `f64` slack.
fn run_par_algo(
    name: &'static str,
    tol: f64,
    repeats: u32,
    pools: &[(usize, rayon::ThreadPool)],
    run: impl Fn(Execution) -> Vec<f64> + Sync,
) -> ParAlgo {
    // Sequential reference: forces the sequential code path (no rayon fan-out).
    let (seq_ms, reference) = timed(repeats, || run(Execution::sequential()));

    // Forced parallel (threshold 0 ⇒ always parallel, even for a small demo graph).
    let par = Execution::parallel_with_threshold(0);
    let mut par_ms = Vec::with_capacity(pools.len());
    let mut deterministic = true;
    let mut best_par_ms = f64::INFINITY;
    let mut best_width = 0usize;
    for (w, pool) in pools {
        let (ms, fp) = timed_in_pool(pool, repeats, || run(par));
        if !fingerprints_close(&reference, &fp, tol) {
            deterministic = false;
        }
        if ms < best_par_ms {
            best_par_ms = ms;
            best_width = *w;
        }
        par_ms.push((*w, ms));
    }
    let speedup = if best_par_ms > 0.0 && best_par_ms.is_finite() {
        seq_ms / best_par_ms
    } else {
        0.0
    };

    ParAlgo {
        name,
        seq_ms,
        par_ms,
        best_width,
        best_par_ms,
        speedup,
        deterministic,
    }
}

/// Builds the undirected + directed influence-network CSRs at `field_size`, returning them plus the
/// node count. Shared by the size sweep and the parallelism demo so both project the SAME graph.
fn build_influence_csrs(
    field_size: u64,
    community_count: u64,
) -> Result<(CsrGraph, CsrGraph, usize), String> {
    let config = GenConfig {
        seed: 0x06D5_A11C_5005_EEED,
        community_count,
        field_size,
        intra_citations_per_author: 8,
        inter_citations_per_author: 2,
    };
    let dataset = generate(config, "sweep");

    // UNDIRECTED, unweighted CSR over the influence network (all citation edges) — matches the
    // centrality/community projections the procedure surface builds by default.
    let undirected = build_csr(
        &dataset.citations,
        dataset.authors.len(),
        Orientation::Undirected,
    )
    .map_err(|e| format!("CSR build failed at field_size={field_size}: {e}"))?;
    // A directed CSR for SCC / Dijkstra (which need the natural orientation).
    let directed = build_csr(
        &dataset.citations,
        dataset.authors.len(),
        Orientation::Directed,
    )
    .map_err(|e| format!("directed CSR build failed at field_size={field_size}: {e}"))?;

    let node_count = undirected.node_count();
    Ok((undirected, directed, node_count))
}

/// Builds a CSR projection from a citation edge list over `node_count` authors. Authors are declared
/// `0..node_count` so isolated nodes are preserved.
fn build_csr(
    citations: &[Citation],
    node_count: usize,
    orientation: Orientation,
) -> Result<CsrGraph, graphus_gds::GdsError> {
    let mut builder = CsrBuilder::new(orientation)
        .weighted(false)
        .allow_implicit_nodes(false);
    for id in 0..node_count {
        builder.add_node(id as u64);
    }
    for c in citations {
        builder.add_edge(c.from as u64, c.to as u64, 1.0)?;
    }
    builder.build()
}

/// Element-wise comparison of two result fingerprints. `tol == 0.0` demands **bit-identical** equality
/// (the integer-exact algorithms: WCC labels, triangle counts, out-degree). A positive `tol` allows a
/// combined absolute+relative slack for the floating-point algorithms (PageRank / betweenness /
/// closeness), whose parallel form matches the sequential result to a documented tolerance.
fn fingerprints_close(a: &[f64], b: &[f64], tol: f64) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).all(|(&x, &y)| {
        if tol == 0.0 {
            x.to_bits() == y.to_bits()
        } else {
            (x - y).abs() <= tol * (1.0 + x.abs().max(y.abs()))
        }
    })
}

/// Runs `f` `repeats` times, returning the **minimum** elapsed time in milliseconds and the last
/// output (for the determinism fingerprint). The minimum is the least-contaminated estimate.
fn timed<T>(repeats: u32, mut f: impl FnMut() -> T) -> (f64, T) {
    let mut best = f64::INFINITY;
    let mut last: Option<T> = None;
    for _ in 0..repeats {
        let t0 = Instant::now();
        let out = std::hint::black_box(f());
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        best = best.min(ms);
        last = Some(out);
    }
    (best, last.expect("repeats >= 1"))
}

/// Like [`timed`], but runs `f` inside `pool` via [`rayon::ThreadPool::install`], so the algorithm's
/// `rayon` work lands on exactly this pool's worker threads (a controlled thread width).
fn timed_in_pool<T: Send>(
    pool: &rayon::ThreadPool,
    repeats: u32,
    f: impl Fn() -> T + Sync,
) -> (f64, T) {
    let mut best = f64::INFINITY;
    let mut last: Option<T> = None;
    for _ in 0..repeats {
        let t0 = Instant::now();
        let out = std::hint::black_box(pool.install(&f));
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        best = best.min(ms);
        last = Some(out);
    }
    (best, last.expect("repeats >= 1"))
}

/// Runs `f` `repeats` times and returns the **minimum** elapsed time in milliseconds. The minimum is
/// the least-contaminated estimate of the algorithm's intrinsic cost (it discards scheduler / cache
/// noise that only ever *adds* time). `std::hint::black_box` is applied inside the closures via the
/// `let _ =` discards, which the optimiser cannot fold away because the calls have observable side
/// effects (allocation).
fn bench(repeats: u32, mut f: impl FnMut()) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..repeats {
        let t0 = Instant::now();
        f();
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        if ms < best {
            best = ms;
        }
    }
    best
}

/// Renders the sweep as machine-readable JSON (hand-rolled to avoid pulling serde derives for a
/// throwaway shape; the field names are stable so `run.sh` can parse them).
fn render_json(
    cores: usize,
    repeats: u32,
    records: &[SweepRecord],
    demo: &ParallelismDemo,
) -> String {
    let mut s = String::with_capacity(2048);
    s.push_str("{\n");
    let _ = writeln!(
        s,
        "  \"engine_parallelism\": \"multi-threaded: pageRank, betweenness, closeness, wcc, \
         triangleCount, degree, labelPropagation + multi-source dijkstra are rayon-parallel via a \
         deterministic Execution knob (rmp #342/#559); scc + single-source dijkstra are sequential\","
    );
    let _ = writeln!(s, "  \"core_knob\": true,");
    let _ = writeln!(s, "  \"host_cores\": {cores},");
    let _ = writeln!(s, "  \"repeats\": {repeats},");
    s.push_str(
        "  \"note\": \"The GDS algorithm library is multi-threaded (rmp #342/#559): a deterministic \
         Execution knob fans each parallelisable algorithm across cores with rayon while keeping the \
         result bit-identical across pool widths. The `sizes` sweep varies GRAPH SIZE with the \
         library's DEFAULT execution (parallel above threshold — exactly how the server runs); \
         per-algorithm time is the minimum over repeats and csr_bytes is CsrGraph::memory_bytes() of \
         the undirected projection. The `parallelism` demo varies CORE COUNT at a fixed size, \
         reporting the REAL measured sequential-vs-parallel speedup and proving the result is \
         identical across every thread width.\",\n",
    );

    // --- The parallelism demonstration (varies CORE COUNT). ---
    s.push_str("  \"parallelism\": {\n");
    let _ = writeln!(s, "    \"field_size\": {},", demo.field_size);
    let _ = writeln!(s, "    \"community_count\": {},", demo.community_count);
    let _ = writeln!(s, "    \"node_count\": {},", demo.node_count);
    let _ = writeln!(s, "    \"edge_count\": {},", demo.edge_count);
    let widths_csv = demo
        .thread_widths
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(s, "    \"thread_widths\": [{widths_csv}],");
    let _ = writeln!(
        s,
        "    \"deterministic_across_widths\": {},",
        demo.deterministic_across_widths
    );
    let _ = writeln!(s, "    \"max_speedup\": {:.4},", demo.max_speedup);
    s.push_str("    \"algorithms\": [\n");
    for (i, a) in demo.algos.iter().enumerate() {
        s.push_str("      {\n");
        let _ = writeln!(s, "        \"name\": \"{}\",", a.name);
        let _ = writeln!(s, "        \"seq_ms\": {:.4},", a.seq_ms);
        s.push_str("        \"par_ms_by_width\": {");
        for (j, (w, ms)) in a.par_ms.iter().enumerate() {
            if j > 0 {
                s.push_str(", ");
            }
            let _ = write!(s, "\"{w}\": {ms:.4}");
        }
        s.push_str("},\n");
        let _ = writeln!(s, "        \"best_width\": {},", a.best_width);
        let _ = writeln!(s, "        \"best_par_ms\": {:.4},", a.best_par_ms);
        let _ = writeln!(s, "        \"speedup\": {:.4},", a.speedup);
        let _ = writeln!(s, "        \"deterministic\": {}", a.deterministic);
        s.push_str(if i + 1 == demo.algos.len() {
            "      }\n"
        } else {
            "      },\n"
        });
    }
    s.push_str("    ]\n");
    s.push_str("  },\n");

    // --- The graph-SIZE sweep (varies GRAPH SIZE). ---
    s.push_str("  \"sizes\": [\n");
    for (i, r) in records.iter().enumerate() {
        s.push_str("    {\n");
        let _ = writeln!(s, "      \"field_size\": {},", r.field_size);
        let _ = writeln!(s, "      \"community_count\": {},", r.community_count);
        let _ = writeln!(s, "      \"node_count\": {},", r.node_count);
        let _ = writeln!(s, "      \"edge_count\": {},", r.edge_count);
        let _ = writeln!(s, "      \"csr_bytes\": {},", r.csr_bytes);
        let _ = writeln!(s, "      \"bytes_per_node\": {:.4},", r.bytes_per_node);
        let _ = writeln!(s, "      \"bytes_per_edge\": {:.4},", r.bytes_per_edge);
        s.push_str("      \"timings_ms\": {");
        for (j, (name, ms)) in r.timings_ms.iter().enumerate() {
            if j > 0 {
                s.push_str(", ");
            }
            let _ = write!(s, "\"{name}\": {ms:.4}");
        }
        s.push_str("}\n");
        s.push_str(if i + 1 == records.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    s.push_str("  ]\n}\n");
    s
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("gds_sweep: error: {msg}");
    ExitCode::FAILURE
}
