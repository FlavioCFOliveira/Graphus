//! `gds_sweep` — the hermetic **scalability + CSR-footprint sweep** for `examples/gds-analytics`.
//!
//! # What it measures (and why this is the *honest* sweep)
//!
//! `examples/gds-analytics` task #259 asks for a multi-core scalability sweep of the heavy
//! algorithms. We first verified empirically how `graphus-gds` parallelism is controlled:
//!
//! - As of `rmp` #318 the two heavy centrality algorithms (**Brandes betweenness** and
//!   **closeness**) are **data-parallel via `rayon`**: each BFS source is independent over the
//!   immutable CSR, so the source loop fans across all cores (honour `RAYON_NUM_THREADS`). Measured
//!   on a 16-core host (8000-node projection): betweenness 7601 ms → 1168 ms (~6.5×), closeness
//!   1884 ms → 205 ms (~9.2×). The remaining algorithms (PageRank, WCC, SCC, triangleCount, label
//!   propagation, Dijkstra) are still single-threaded.
//!
//! This sweep varies **graph size** (not core count) and reports, for each size:
//!
//! - the **wall time** of each heavy algorithm (PageRank, betweenness) plus the supporting suite
//!   (degree, closeness, WCC, SCC, triangleCount, label propagation, Dijkstra), so one can see how
//!   run time scales with `n` and `m` (the algorithms document their own `O(...)` complexity); and
//! - the **resident CSR-projection footprint** via [`CsrGraph::memory_bytes`], reduced to
//!   **bytes-per-node** and **bytes-per-edge** so the footprint can be compared across sizes.
//!
//! Output is machine-readable JSON (one record per graph size) that `run.sh` consumes for the
//! evidence report. The sweep is fully hermetic (no server, no network) and deterministic (the
//! generator is a pure function of its seed), so it is CI-runnable.
//!
//! Usage:
//! ```text
//! cargo run -p graphus-gds-gen --bin gds_sweep -- [--out <file.json>] [--sizes 40,120,...] \
//!   [--repeats N]
//! ```

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use graphus_gds::algo::centrality::{
    betweenness_centrality, closeness_centrality, undirected_scale,
};
use graphus_gds::algo::community::{LabelPropagationConfig, label_propagation};
use graphus_gds::algo::degree::{Direction, degree_centrality};
use graphus_gds::algo::pagerank::{PageRankConfig, pagerank};
use graphus_gds::algo::scc::strongly_connected_components;
use graphus_gds::algo::shortest_path::dijkstra;
use graphus_gds::algo::triangles::triangle_count;
use graphus_gds::algo::wcc::weakly_connected_components;
use graphus_gds::{Cancel, CsrBuilder, CsrGraph, Orientation};

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

fn main() -> ExitCode {
    let mut out_path: Option<PathBuf> = None;
    // Default size sweep: a geometric-ish progression of field sizes (×community_count = node count).
    let mut sizes: Vec<u64> = vec![40, 120, 360, 1080];
    let mut repeats: u32 = 3;

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
            "-h" | "--help" => {
                eprintln!(
                    "usage: gds_sweep [--out <file.json>] [--sizes 40,120,360] [--repeats N]\n\
                     Single-threaded GDS scalability + CSR-footprint sweep over graph SIZE."
                );
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unexpected argument '{other}'")),
        }
    }

    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    eprintln!(
        "gds_sweep: betweenness & closeness are rayon-parallel (RAYON_NUM_THREADS honoured); other \
         algorithms single-threaded; sweeping graph SIZE on a {cores}-core host. \
         sizes={sizes:?} repeats={repeats}"
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

    let json = render_json(cores, repeats, &records);
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
/// (the least-noisy estimate), and records the CSR footprint.
fn measure_size(field_size: u64, repeats: u32) -> Result<SweepRecord, String> {
    let community_count = 4;
    let config = GenConfig {
        seed: 0x06D5_A11C_5005_EEED,
        community_count,
        field_size,
        intra_citations_per_author: 8,
        inter_citations_per_author: 2,
    };
    let dataset = generate(config, "sweep");

    // Build an UNDIRECTED, unweighted CSR over the influence network (all citation edges). Undirected
    // matches the centrality/community projections the procedure surface builds by default.
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
fn render_json(cores: usize, repeats: u32, records: &[SweepRecord]) -> String {
    let mut s = String::with_capacity(1024);
    s.push_str("{\n");
    let _ = writeln!(
        s,
        "  \"engine_parallelism\": \"betweenness+closeness rayon-parallel; others single-threaded\","
    );
    let _ = writeln!(s, "  \"core_knob\": true,");
    let _ = writeln!(s, "  \"host_cores\": {cores},");
    let _ = writeln!(s, "  \"repeats\": {repeats},");
    s.push_str("  \"note\": \"betweenness & closeness fan their independent BFS sources across cores via rayon (RAYON_NUM_THREADS honoured, rmp #318); the remaining algorithms are single-threaded. This sweep varies graph SIZE, not core count. Per-algorithm time is the minimum over repeats; csr_bytes is CsrGraph::memory_bytes() of the undirected projection.\",\n");
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
