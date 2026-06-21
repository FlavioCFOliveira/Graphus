//! `social_baseline_cmp` — the social-network evidence **regression gate**.
//!
//! It loads a committed **baseline** evidence report and a **fresh** run's `report.json`, then decides
//! whether the fresh run regressed by comparing ONLY the **stable, structural** metrics. On success it
//! prints `GRAPHUS_BASELINE_OK` and exits `0`; on a regression it prints the offending metrics and a
//! clear diff and exits `1`. The social-network `run.sh` (a sibling task) invokes it as the
//! committed-baseline gate against a `social_evidence` `report.json`.
//!
//! ## Why a STRUCTURAL-only comparison
//!
//! Peak RSS, throughput, CPU seconds, wall time, read latencies, and the WAL byte count (which varies
//! with segment rotation / fsync timing) are all **machine- and timing-dependent**, so comparing them
//! across machines is flaky. This gate holds only the metrics that are **deterministic for a fixed
//! seed + profile** — the realised node and relationship counts, the durable store image bytes + page
//! count, and the store-only space amplification — to a tight bound, and gives every volatile family
//! an effectively-infinite tolerance.
//!
//! ## How the two metric kinds are compared
//!
//! - **Store bytes** (a *float-comparable footprint*) is gated through the harness's
//!   [`compare_to_baseline`] with a tight `storage_rise` tolerance and `IGNORE` on every other family
//!   — exactly the iot-timeseries gate's shape. (The harness's `space_amplification` mixes in the
//!   machine-variant WAL, so it is given `IGNORE` here; the *store-only* amplification is gated
//!   separately below.)
//! - **Exact structural counts** (node count, relationship count, store pages) and the **store-only
//!   space amplification** are not covered by the harness comparison, so they are checked here
//!   directly: the counts must match **exactly** (the bulk-imported graph is fully deterministic), and
//!   the store-only amplification within a tight tolerance. They are read from the report's
//!   deterministic dataset / workload params, which `social_evidence` populates.
//!
//! Hermetic: this binary needs only the harness + serde (NO engine feature), so it is always
//! buildable — `cargo build -p graphus-social-gen --no-default-features` builds it.
//!
//! [`compare_to_baseline`]: graphus_examples_harness::EvidenceReport::compare_to_baseline

use std::process::ExitCode;

use graphus_examples_harness::{EvidenceReport, RegressionThresholds};

/// A tolerance large enough that a metric never trips the gate (the machine-variant families).
const IGNORE: f64 = f64::INFINITY;

/// The tolerance band the deterministic store-byte footprint is held to (15%, matching the
/// iot-timeseries gate). The store image is byte-stable for a fixed seed + profile, so a drift beyond
/// this band is a genuine storage-engine or generator regression.
const STORE_RISE: f64 = 0.15;

/// The tolerance band the store-only space amplification is held to.
const AMP_TOLERANCE: f64 = 0.15;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (baseline_path, candidate_path) = match (args.next(), args.next()) {
        (Some(b), Some(c)) => (b, c),
        _ => {
            eprintln!("usage: social_baseline_cmp <baseline.json> <candidate.json>");
            return ExitCode::FAILURE;
        }
    };

    let baseline = match EvidenceReport::load(&baseline_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("social_baseline_cmp: cannot load baseline {baseline_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let candidate = match EvidenceReport::load(&candidate_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("social_baseline_cmp: cannot load candidate {candidate_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut failed = false;

    // ----- 1) Store-byte footprint, via the harness gate (tight on store; IGNORE everything else). -
    // The WAL bytes, throughput, latency, CPU, and memory families get effectively-infinite tolerance;
    // only the deterministic store image is held to a tight band. (`space_amplification` is also
    // ignored here because the harness computes it over store+WAL — the WAL component is variant; the
    // store-only amplification is gated separately below.)
    let thresholds = RegressionThresholds {
        throughput_drop: IGNORE,
        latency_rise: IGNORE,
        memory_rise: IGNORE,
        storage_rise: STORE_RISE,
        amplification_rise: IGNORE,
        cpu_rise: IGNORE,
        abort_rate_rise: IGNORE,
    };
    let cmp = candidate.compare_to_baseline(&baseline, &thresholds);
    // Only the store_bytes delta is meaningful here; wal_bytes shares the `storage_rise` threshold, so
    // re-gate it to IGNORE by filtering the regression set down to the store-image metric.
    let store_regressions: Vec<_> = cmp
        .regressions()
        .into_iter()
        .filter(|d| d.metric == "storage.store_bytes")
        .collect();
    if store_regressions.is_empty() {
        let store = cmp
            .deltas
            .iter()
            .find(|d| d.metric == "storage.store_bytes");
        if let Some(d) = store {
            println!(
                "OK storage.store_bytes: {:.0} -> {:.0} ({:+.1}%, within {:.0}%)",
                d.baseline,
                d.candidate,
                d.fractional_change * 100.0,
                STORE_RISE * 100.0,
            );
        }
    } else {
        failed = true;
        for d in store_regressions {
            eprintln!(
                "FAIL storage.store_bytes: {:.0} -> {:.0} ({:+.1}% worse, threshold {:.0}%)",
                d.baseline,
                d.candidate,
                d.degradation * 100.0,
                STORE_RISE * 100.0,
            );
        }
    }

    // ----- 2) Exact structural counts (deterministic; must match EXACTLY). ------------------------
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
    // The realised label/type counts (from the workload params) — each must match exactly too.
    for key in ["user_count", "article_count", "friend_count", "like_count"] {
        failed |= !check_exact_param(key, &baseline, &candidate);
    }
    // Store page count: deterministic (ceil(store_bytes / PAGE_SIZE)); must match exactly.
    failed |= !check_exact_param("store_pages", &baseline, &candidate);

    // ----- 3) Store-only space amplification, within a tight tolerance. ---------------------------
    failed |= !check_ratio_param(
        "store_space_amplification",
        &baseline,
        &candidate,
        AMP_TOLERANCE,
    );

    if failed {
        eprintln!(
            "social_baseline_cmp: a structural metric regressed beyond its tolerance (see above)"
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

/// Reads an `f64`-valued workload param from a report.
fn param_f64(report: &EvidenceReport, key: &str) -> Option<f64> {
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

/// Checks a ratio-valued workload param is within `tolerance` of the baseline. Returns `true` on pass.
fn check_ratio_param(
    key: &str,
    baseline: &EvidenceReport,
    candidate: &EvidenceReport,
    tolerance: f64,
) -> bool {
    match (param_f64(baseline, key), param_f64(candidate, key)) {
        (Some(b), Some(c)) => {
            // Relative deviation against the baseline (a zero baseline degenerates to an absolute
            // check: any non-zero candidate then fails, which is the conservative outcome).
            let rel = if b != 0.0 {
                (c - b).abs() / b.abs()
            } else if c == 0.0 {
                0.0
            } else {
                f64::INFINITY
            };
            if rel <= tolerance {
                println!(
                    "OK {key}: {b:.4} -> {c:.4} ({:+.1}%, within {:.0}%)",
                    (c - b) / b.abs() * 100.0,
                    tolerance * 100.0,
                );
                true
            } else {
                eprintln!(
                    "FAIL {key}: {b:.4} -> {c:.4} ({:+.1}% off, tolerance {:.0}%)",
                    (c - b) / b.abs() * 100.0,
                    tolerance * 100.0,
                );
                false
            }
        }
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
