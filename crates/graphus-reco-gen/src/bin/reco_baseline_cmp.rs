//! `reco_baseline_cmp` — the product-recommendation evidence **regression gate**.
//!
//! It loads a committed **baseline** evidence report and a **fresh** `reco_bench` `report.json`, then
//! decides whether the fresh run regressed by comparing ONLY the **stable, structural** metrics. On
//! success it prints `GRAPHUS_BASELINE_OK` and exits `0`; on a regression it prints the offending
//! metrics and a clear diff and exits `1`. The product-recommendation `run.sh` (a sibling task)
//! invokes it as the committed-baseline gate against a `reco_bench` `report.json`.
//!
//! ## Why a STRUCTURAL-only comparison
//!
//! Everything `reco_bench` reports about *performance* — throughput, latency percentiles, server CPU
//! seconds / core utilisation, peak RSS, disk IO, the writer abort rate — is **machine- and
//! timing-dependent**: it varies with the host's core count, its allocator, kernel scheduling, and
//! the load the box is under, so comparing those numbers across machines is inherently flaky. This
//! gate therefore holds ONLY the metrics that are **deterministic for a fixed seed + generator
//! profile** — the realised node and relationship counts and the four per-label structural counts
//! (`User`/`Product`/`FRIEND`/`PURCHASED`) the driver was told the graph contains — and gives every
//! volatile metric family an effectively-infinite tolerance.
//!
//! Unlike `social_baseline_cmp`, there is **no** durable-store byte gate here: `reco_bench` is a
//! **client-only** driver (it never links the engine, so it measures no on-disk store image). The
//! structural counts are the only deterministic signal, and they must match the baseline **exactly**.
//!
//! Hermetic: this binary needs only the harness + serde, so it is always buildable —
//! `cargo build -p graphus-reco-gen --bin reco_baseline_cmp` builds it with no engine dependency.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use graphus_examples_harness::{EvidenceReport, RegressionThresholds};

/// A tolerance large enough that a metric never trips the gate (every machine-variant family here).
const IGNORE: f64 = f64::INFINITY;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (baseline_path, candidate_path) = match (args.next(), args.next()) {
        (Some(b), Some(c)) => (b, c),
        _ => {
            eprintln!("usage: reco_baseline_cmp <baseline.json> <candidate.json>");
            return ExitCode::FAILURE;
        }
    };

    let baseline = match EvidenceReport::load(&baseline_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("reco_baseline_cmp: cannot load baseline {baseline_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let candidate = match EvidenceReport::load(&candidate_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("reco_baseline_cmp: cannot load candidate {candidate_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut failed = false;

    // ----- 1) Every harness metric family is machine/timing-variant here: IGNORE them all. --------
    // Throughput, latency, memory, storage, amplification, CPU, and the writer abort rate are all
    // given effectively-infinite tolerance, so the harness comparison can never trip the gate; it is
    // run for symmetry with `social_baseline_cmp` and to surface an (impossible) regression clearly
    // should the thresholds ever be tightened.
    let thresholds = RegressionThresholds {
        throughput_drop: IGNORE,
        latency_rise: IGNORE,
        memory_rise: IGNORE,
        storage_rise: IGNORE,
        amplification_rise: IGNORE,
        cpu_rise: IGNORE,
        abort_rate_rise: IGNORE,
    };
    let cmp = candidate.compare_to_baseline(&baseline, &thresholds);
    for d in cmp.regressions() {
        failed = true;
        eprintln!(
            "FAIL {}: {:.3} -> {:.3} ({:+.1}% worse)",
            d.metric,
            d.baseline,
            d.candidate,
            d.degradation * 100.0,
        );
    }

    // ----- 2) Exact structural counts (deterministic for a fixed seed + profile; must match). ------
    failed |= !check_exact_u64(
        "node_count",
        baseline.metadata.dataset.nodes,
        candidate.metadata.dataset.nodes,
    );
    failed |= !check_exact_u64(
        "relationship_count",
        baseline.metadata.dataset.relationships,
        candidate.metadata.dataset.relationships,
    );
    // The realised per-label counts (from the workload params) — each must match exactly too.
    for key in [
        "user_count",
        "product_count",
        "friend_count",
        "purchased_count",
    ] {
        failed |= !check_exact_param(key, &baseline, &candidate);
    }

    if failed {
        eprintln!(
            "reco_baseline_cmp: a structural metric regressed beyond its tolerance (see above)"
        );
        ExitCode::FAILURE
    } else {
        println!("GRAPHUS_BASELINE_OK");
        ExitCode::SUCCESS
    }
}

/// Reads a `u64`-valued workload param from a report (`None` if absent or unparseable).
fn param_u64(report: &EvidenceReport, key: &str) -> Option<u64> {
    report.metadata.workload.get(key)?.parse().ok()
}

/// Checks two `u64` values are equal, printing an OK / FAIL line. Returns `true` on pass.
fn check_exact_u64(name: &str, baseline: u64, candidate: u64) -> bool {
    if baseline == candidate {
        println!("OK {name}: {candidate} (== baseline)");
        true
    } else {
        eprintln!("FAIL {name}: baseline {baseline} != candidate {candidate}");
        false
    }
}

/// Checks a `u64`-valued workload param matches exactly between baseline and candidate.
fn check_exact_param(key: &str, baseline: &EvidenceReport, candidate: &EvidenceReport) -> bool {
    match (param_u64(baseline, key), param_u64(candidate, key)) {
        (Some(b), Some(c)) => check_exact_u64(key, b, c),
        _ => {
            eprintln!(
                "FAIL {key}: missing or unparseable workload param (baseline={:?}, candidate={:?})",
                baseline.metadata.workload.get(key),
                candidate.metadata.workload.get(key),
            );
            false
        }
    }
}
