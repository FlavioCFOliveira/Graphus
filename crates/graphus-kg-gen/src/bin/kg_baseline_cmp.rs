//! `kg_baseline_cmp` — the knowledge-graph-rest evidence **regression gate** (`rmp #285`).
//!
//! It loads a committed **baseline** evidence report and a **fresh** run's report and decides
//! whether the fresh run regressed. On success it prints `GRAPHUS_BASELINE_OK` and exits `0`; on a
//! regression it prints the offending metrics and exits `1`. The `examples/knowledge-graph-rest`
//! `run.sh` invokes it as the committed-baseline gate.
//!
//! ## The STABLE / MACHINE-VARIANT split (the documented threshold model)
//!
//! This example produces two very different families of evidence, and they are gated very
//! differently:
//!
//! 1. **Deterministic / structural** — byte-stable for a fixed seed + profile, so they are held to a
//!    **tight, exact-or-near-exact** bound. A drift here is a genuine regression:
//!
//!    | Metric | Source | Tolerance |
//!    |--------|--------|-----------|
//!    | dataset nodes / relationships | the seeded generator | **exact** |
//!    | JSON payload bytes (`json_bytes`) | the REST JSON encoder over a fixed result | **exact** |
//!    | CBOR payload bytes (`cbor_bytes`) | the REST CBOR encoder over a fixed result | **exact** |
//!    | CBOR/JSON ratio (`cbor_ratio`) | derived from the two above | **±0.01 band** |
//!    | NDJSON streamed rows (`ndjson_rows`) | a fixed `MATCH (d:Document)` result | **exact** |
//!    | on-disk store / WAL bytes + pages | the durable footprint of the fixed load | **15%** |
//!    | amplification ratios | derived from the same footprint | **15%** |
//!
//! 2. **Machine- and timing-variant** — depend on the host's CPU speed, scheduler, allocator and
//!    OS, so they are **NOT gated** (effectively infinite tolerance). Comparing them across the
//!    developer/CI machines a baseline is shared between would be flaky:
//!
//!    | Metric family | Why ungated |
//!    |---------------|-------------|
//!    | HTTP throughput (`ops_per_sec`) | varies with machine speed |
//!    | latency p50/p99/p999 | varies with machine speed + scheduling |
//!    | NDJSON rows/sec + bytes/sec | varies with machine speed |
//!    | server CPU seconds | varies with machine speed |
//!    | peak RSS | varies with allocator/OS/machine |
//!
//! The structural-vs-variant split is the same discipline the sibling `fraud-oltp` gate uses; this
//! example additionally tight-checks the **payload sizes per encoding** (its headline evidence), as
//! those are deterministic functions of the fixed result set and the REST encoders.

use std::process::ExitCode;

use graphus_examples_harness::{EvidenceReport, RegressionThresholds};

/// A tolerance large enough that a metric never trips the gate (the machine-variant families).
const IGNORE: f64 = f64::INFINITY;

/// The exact-match tolerance band for the CBOR/JSON ratio (a derived float: allow tiny rounding).
const RATIO_BAND: f64 = 0.01;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (baseline_path, candidate_path) = match (args.next(), args.next()) {
        (Some(b), Some(c)) => (b, c),
        _ => {
            eprintln!("usage: kg_baseline_cmp <baseline.json> <candidate.json>");
            return ExitCode::FAILURE;
        }
    };

    let baseline = match EvidenceReport::load(&baseline_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("kg_baseline_cmp: cannot load baseline {baseline_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let candidate = match EvidenceReport::load(&candidate_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("kg_baseline_cmp: cannot load candidate {candidate_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut failed = false;

    // ---- 1) Structural footprint gate (delegated to the harness) -------------------------------
    // Tight on the deterministic on-disk footprint + amplification; effectively infinite on the
    // machine-variant families (throughput/latency/CPU/memory). Abort rate is irrelevant here (this
    // is not an SSI-contention workload), so it gets a generous band too.
    let thresholds = RegressionThresholds {
        throughput_drop: IGNORE,
        latency_rise: IGNORE,
        memory_rise: IGNORE,
        storage_rise: 0.15,
        amplification_rise: 0.15,
        cpu_rise: IGNORE,
        abort_rate_rise: IGNORE,
    };
    let cmp = candidate.compare_to_baseline(&baseline, &thresholds);
    print!("{}", cmp.summary());
    if cmp.regressed {
        failed = true;
    }

    // ---- 2) Deterministic dataset gate (EXACT) -------------------------------------------------
    failed |= !check_exact_u64(
        "dataset.nodes",
        baseline.metadata.dataset.nodes,
        candidate.metadata.dataset.nodes,
    );
    failed |= !check_exact_u64(
        "dataset.relationships",
        baseline.metadata.dataset.relationships,
        candidate.metadata.dataset.relationships,
    );

    // ---- 3) Deterministic payload-size gate (EXACT bytes per encoding) -------------------------
    // The headline evidence: the JSON and CBOR encodings of a FIXED result set are byte-stable, so a
    // drift is a genuine encoder/result-shape regression. The values live in the workload param map
    // (the example feeds them via `--param`), so a baseline that predates them (no key) is skipped
    // rather than failed — keeping the gate honest if an older baseline is ever compared.
    for key in ["json_bytes", "cbor_bytes", "ndjson_rows", "ndjson_bytes"] {
        failed |= !check_exact_param(&baseline, &candidate, key);
    }
    // The derived ratio: a tiny float band (rounding only).
    failed |= !check_param_band(&baseline, &candidate, "cbor_ratio", RATIO_BAND);

    if failed {
        eprintln!(
            "kg_baseline_cmp: a structural/deterministic metric regressed beyond its threshold (see above)"
        );
        ExitCode::FAILURE
    } else {
        println!("GRAPHUS_BASELINE_OK");
        ExitCode::SUCCESS
    }
}

/// Asserts two `u64` metrics are exactly equal, printing the outcome. Returns `true` on match.
fn check_exact_u64(metric: &str, baseline: u64, candidate: u64) -> bool {
    if baseline == candidate {
        println!("  OK  {metric}: {candidate} (exact match)");
        true
    } else {
        println!("  BAD {metric}: baseline {baseline} -> candidate {candidate} (must be exact)");
        false
    }
}

/// Reads a numeric workload param from both reports and asserts EXACT equality. A param missing from
/// the BASELINE is skipped (an older baseline predates it); a param present in the baseline but
/// missing/malformed in the candidate is a failure.
fn check_exact_param(baseline: &EvidenceReport, candidate: &EvidenceReport, key: &str) -> bool {
    let Some(b) = param_f64(baseline, key) else {
        println!("  --  {key}: not in baseline, skipped");
        return true;
    };
    match param_f64(candidate, key) {
        Some(c) if (c - b).abs() < f64::EPSILON => {
            println!("  OK  {key}: {c} (exact match)");
            true
        }
        Some(c) => {
            println!("  BAD {key}: baseline {b} -> candidate {c} (must be exact)");
            false
        }
        None => {
            println!("  BAD {key}: present in baseline ({b}) but missing/malformed in candidate");
            false
        }
    }
}

/// Reads a numeric workload param from both reports and asserts it is within `±band` of baseline.
fn check_param_band(
    baseline: &EvidenceReport,
    candidate: &EvidenceReport,
    key: &str,
    band: f64,
) -> bool {
    let Some(b) = param_f64(baseline, key) else {
        println!("  --  {key}: not in baseline, skipped");
        return true;
    };
    match param_f64(candidate, key) {
        Some(c) if (c - b).abs() <= band => {
            println!("  OK  {key}: {c} (within ±{band} of {b})");
            true
        }
        Some(c) => {
            println!("  BAD {key}: baseline {b} -> candidate {c} (outside ±{band} band)");
            false
        }
        None => {
            println!("  BAD {key}: present in baseline ({b}) but missing/malformed in candidate");
            false
        }
    }
}

/// Parses a workload param as `f64`, returning `None` if absent or unparseable.
fn param_f64(report: &EvidenceReport, key: &str) -> Option<f64> {
    report.metadata.workload.get(key)?.parse().ok()
}
