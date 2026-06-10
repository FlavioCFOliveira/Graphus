//! `bench_gate` — the Criterion **regression gate** (`rmp` task #27, AC "benchmarks gate
//! regressions").
//!
//! The full Criterion suites (`benches/commit_path.rs`, `benches/read_path.rs`) are the *measurement
//! instrument*; running them in CI on every push and parsing their statistical output to fail a
//! build is heavy and flaky. This gate is the lightweight CI counterpart: it measures a few
//! **representative slices** of the same hot paths with a fixed warmup + sample budget, takes the
//! **median** (robust to the occasional scheduler outlier), and compares each metric against a
//! committed baseline (`crates/graphus-bench/baseline.toml`). If any metric is slower than its
//! baseline by more than the per-run tolerance, the gate exits non-zero so CI fails.
//!
//! It deliberately does **not** depend on Criterion: the metrics are wall-clock medians over the
//! real storage commit/scan path (the same `RecordStore` the Criterion benches drive), so the gate
//! is self-contained, fast (~1–2 s), and deterministic enough not to be flaky given the generous
//! default tolerance.
//!
//! ## Usage
//! ```text
//! cargo run -p graphus-bench --release --bin bench_gate                 # gate vs committed baseline
//! cargo run -p graphus-bench --release --bin bench_gate -- --update     # rewrite the baseline
//! cargo run -p graphus-bench --release --bin bench_gate -- --tolerance 0.30   # looser threshold
//! ```
//!
//! **Always run the gate in `--release`** — the baseline is recorded from a release build (the
//! profile the Criterion benches use). A debug run is ~10× slower and will spuriously "regress".

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use graphus_bench::ldbc::driver::fresh_store;
use graphus_core::{TxnId, Value};
use graphus_storage::Namespace;

/// One metric the gate measures and gates on.
struct Metric {
    /// Stable key, also the baseline-file field name.
    key: &'static str,
    /// Human description.
    label: &'static str,
    /// The measured median, in nanoseconds (filled in by [`measure_all`]).
    measured_ns: f64,
}

/// The default regression tolerance: a metric may be up to this fraction slower than baseline before
/// the gate fails. 20 % absorbs run-to-run jitter and shared-runner noise while still catching a real
/// regression (which is typically ≥ 1.5–2×). Override with `--tolerance`.
const DEFAULT_TOLERANCE: f64 = 0.20;

/// Warmup iterations discarded before timing (lets the CPU clock/caches settle).
const WARMUP: usize = 50;
/// Timed samples; the median is reported (robust to outliers).
const SAMPLES: usize = 201;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let update = args.iter().any(|a| a == "--update");
    let tolerance = parse_tolerance(&args).unwrap_or(DEFAULT_TOLERANCE);

    eprintln!(
        "[bench_gate] measuring representative commit/read slices (release build expected) …"
    );
    let metrics = measure_all();

    let baseline_path = baseline_path();

    if update {
        let toml = render_baseline(&metrics, tolerance);
        if let Err(e) = std::fs::write(&baseline_path, &toml) {
            eprintln!(
                "[bench_gate] failed to write baseline {}: {e}",
                baseline_path.display()
            );
            return ExitCode::FAILURE;
        }
        println!("[bench_gate] baseline updated:\n{toml}");
        return ExitCode::SUCCESS;
    }

    // Gate mode: load the baseline and compare.
    let baseline = match std::fs::read_to_string(&baseline_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[bench_gate] no baseline at {} ({e}). Seed it once with `--update` on a quiet \
                 release build.",
                baseline_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    let mut failed = false;
    println!("================================================================");
    println!(
        " Graphus benchmark regression gate (tolerance = {:.0}%)",
        tolerance * 100.0
    );
    println!("----------------------------------------------------------------");
    println!(
        " {:<22} {:>12} {:>12} {:>9}",
        "metric", "baseline(ns)", "measured(ns)", "delta"
    );
    println!("----------------------------------------------------------------");
    for m in &metrics {
        let base = match parse_baseline_field(&baseline, m.key) {
            Some(v) => v,
            None => {
                println!(
                    " {:<22} {:>12} {:>12} {:>9}   MISSING in baseline",
                    m.key, "-", m.measured_ns as u64, "-"
                );
                failed = true;
                continue;
            }
        };
        let delta = (m.measured_ns - base) / base;
        let verdict = if delta > tolerance { "FAIL" } else { "ok" };
        if delta > tolerance {
            failed = true;
        }
        println!(
            " {:<22} {:>12.0} {:>12.0} {:>+8.1}%  {verdict}",
            m.key,
            base,
            m.measured_ns,
            delta * 100.0
        );
    }
    println!("----------------------------------------------------------------");
    println!(
        " ({})",
        metrics
            .iter()
            .map(|m| m.label)
            .collect::<Vec<_>>()
            .join("; ")
    );

    if failed {
        println!(" RESULT: REGRESSION DETECTED — gate FAILS.");
        println!("================================================================");
        ExitCode::FAILURE
    } else {
        println!(" RESULT: all metrics within tolerance — gate PASSES.");
        println!("================================================================");
        ExitCode::SUCCESS
    }
}

/// Measures every gated metric, returning them with `measured_ns` populated.
fn measure_all() -> Vec<Metric> {
    vec![
        Metric {
            key: "commit_short_txn_ns",
            label: "commit_short_txn: 4-op write transaction commit (median)",
            measured_ns: measure_commit_short_txn(),
        },
        Metric {
            key: "scan_1k_nodes_ns",
            label: "scan_1k_nodes: full node-store scan of 1000 nodes (median)",
            measured_ns: measure_scan_1k(),
        },
    ]
}

/// Median wall-clock latency of committing a short (4-op) write transaction over the real store —
/// the same serialization point `benches/commit_path.rs` characterizes, distilled to one number.
fn measure_commit_short_txn() -> f64 {
    let mut store = fresh_store();
    let rel_type = store
        .intern_token(Namespace::RelType, "KNOWS")
        .expect("intern reltype");
    let prop_key = store
        .intern_token(Namespace::PropKey, "weight")
        .expect("intern propkey");

    // Two stable anchor nodes the edges connect.
    let mut txn_id = 0u64;
    let mut anchors = Vec::new();
    {
        txn_id += 1;
        let txn = TxnId(txn_id);
        store.begin(txn);
        for _ in 0..2 {
            let (id, _) = store.create_node(txn).expect("anchor");
            anchors.push(id);
        }
        store.commit(txn).expect("commit anchors");
    }

    // One 4-op commit: create node, create edge, set property, create node.
    let once = |store: &mut graphus_bench::ldbc::driver::Store, txn_id: &mut u64| -> Duration {
        *txn_id += 1;
        let txn = TxnId(*txn_id);
        store.begin(txn);
        let (n1, _) = store.create_node(txn).expect("n1");
        store
            .create_rel(txn, rel_type, anchors[0], anchors[1])
            .expect("rel");
        store
            .set_node_property_value(txn, anchors[0], prop_key, &Value::Integer(*txn_id as i64))
            .expect("set");
        let (_n2, _) = store.create_node(txn).expect("n2");
        let _ = n1;
        let start = Instant::now();
        store.commit(txn).expect("commit");
        start.elapsed()
    };

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..WARMUP {
        let _ = once(&mut store, &mut txn_id);
    }
    for _ in 0..SAMPLES {
        // The single-page catalog caps store growth (~1000 record pages, see commit_path.rs); the
        // short measurement stays well under it, so no store reset is needed within SAMPLES.
        samples.push(once(&mut store, &mut txn_id).as_nanos());
    }
    median(&mut samples)
}

/// Median wall-clock latency of a full node-store scan of a 1000-node store — the lock-free read
/// leaf `benches/read_path.rs` characterizes, distilled to one number.
fn measure_scan_1k() -> f64 {
    // Build a 1000-node store (no edges needed for the scan leaf), committed in one batch.
    let mut store = fresh_store();
    let txn = TxnId(1);
    store.begin(txn);
    for _ in 0..1000 {
        store.create_node(txn).expect("node");
    }
    store.commit(txn).expect("commit nodes");

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..WARMUP {
        let all = store.scan_node_ids().expect("scan");
        std::hint::black_box(all.len());
    }
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let all = store.scan_node_ids().expect("scan");
        std::hint::black_box(all.len());
        samples.push(start.elapsed().as_nanos());
    }
    median(&mut samples)
}

/// The median of a slice of nanosecond samples (sorts in place).
fn median(samples: &mut [u128]) -> f64 {
    samples.sort_unstable();
    let n = samples.len();
    if n == 0 {
        return 0.0;
    }
    if n % 2 == 1 {
        samples[n / 2] as f64
    } else {
        (samples[n / 2 - 1] + samples[n / 2]) as f64 / 2.0
    }
}

/// Renders a baseline TOML from the measured metrics.
fn render_baseline(metrics: &[Metric], tolerance: f64) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# Graphus benchmark regression-gate baseline (`rmp` task #27)."
    );
    let _ = writeln!(s, "#");
    let _ = writeln!(
        s,
        "# Per-metric median latency in nanoseconds, recorded from a RELEASE build on the"
    );
    let _ = writeln!(
        s,
        "# machine class noted below. The `bench_gate` binary fails CI if a measured metric"
    );
    let _ = writeln!(
        s,
        "# regresses past `tolerance`. Re-seed with `bench_gate --update` after an intentional"
    );
    let _ = writeln!(
        s,
        "# perf change, on a quiet release build, and commit the new numbers."
    );
    let _ = writeln!(s, "#");
    let _ = writeln!(
        s,
        "# Machine class: see RESULTS.md §1 (recorded there alongside the Criterion numbers)."
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "tolerance = {tolerance}");
    let _ = writeln!(s);
    let _ = writeln!(s, "[metrics]");
    for m in metrics {
        let _ = writeln!(s, "# {}", m.label);
        let _ = writeln!(s, "{} = {:.0}", m.key, m.measured_ns);
    }
    s
}

/// Parses a `key = number` field from the `[metrics]` table of the baseline TOML (a tiny hand-parser
/// so the gate has zero extra dependencies). Returns the value as `f64`.
fn parse_baseline_field(toml: &str, key: &str) -> Option<f64> {
    for line in toml.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                return v.trim().parse::<f64>().ok();
            }
        }
    }
    None
}

/// Parses an optional `--tolerance <f64>` argument.
fn parse_tolerance(args: &[String]) -> Option<f64> {
    let i = args.iter().position(|a| a == "--tolerance")?;
    args.get(i + 1)?.parse::<f64>().ok()
}

/// The path to the committed baseline, relative to this crate's manifest dir.
fn baseline_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("baseline.toml")
}
