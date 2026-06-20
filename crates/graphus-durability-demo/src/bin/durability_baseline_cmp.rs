//! `durability_baseline_cmp` — the durability-crash-recovery evidence **regression gate** (rmp #278).
//!
//! It loads a committed **baseline** evidence report and a **fresh** run's report, then gates the run
//! against the baseline. On success it prints `GRAPHUS_BASELINE_OK` and exits `0`; on a regression it
//! prints the offending metrics and exits `1`. The example's `run.sh` invokes it as the
//! committed-baseline gate (mirrors bulk-etl's `bulk_baseline_cmp`, gds-analytics' `gds_baseline_cmp`,
//! and fraud-oltp's `baseline_cmp`).
//!
//! ## What is gated, and why the split is STRUCTURAL-exact vs machine-variant-ungated
//!
//! This example has a sharp deterministic/non-deterministic split, so its gate is sharper than the
//! sibling examples':
//!
//! 1. **Structural equality (EXACT)** — the DST core is a pure function of the seed range, so these are
//!    integer-stable across runs and hosts and MUST match the baseline exactly:
//!
//!    | Metric | Source | Encodes |
//!    |--------|--------|---------|
//!    | `dataset.nodes`                       | metadata    | recovered `:Person` rows for the focus seed |
//!    | `workload.recovery_records_replayed`  | workload    | acked commits ARIES redo replayed (= WAL redo records) |
//!    | `workload.recovery_inflight_undone`   | workload    | in-flight transactions ARIES undo discarded |
//!    | `workload.recovery_crashes`           | workload    | crash + ARIES restarts fired |
//!    | `workload.seeds`                      | workload    | the seed range (so the gate compares like profiles) |
//!
//!    A change to any of these means recovery itself drifted (a lost acked commit, a surviving
//!    in-flight effect, a different crash schedule, or a profile mismatch) — exactly the regression the
//!    example exists to catch. They are the deterministic *recovery-work-vs-WAL-size* signal.
//!
//! 2. **Machine-variant (UNGATED)** — the sweep wall-time / seed-rate throughput, and (when a baseline
//!    carries them from a real-server run) CPU / peak RSS / on-disk WAL bytes / wall-clock recovery
//!    time are timing- and host-dependent. They are recorded for human visibility but held to an
//!    infinite tolerance so the shared baseline never flakes across developer / CI machines.
//!
//! This mirrors the sibling gates' "structural-exact + footprint-band, machine-variant-ignored" shape,
//! specialised to a scenario whose *recovery work* (not its on-disk footprint) is the deterministic
//! quantity.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use graphus_examples_harness::{EvidenceReport, RegressionThresholds};

/// A tolerance large enough that a metric never trips the gate (the machine-variant families).
const IGNORE: f64 = f64::INFINITY;

/// The structural workload params compared at EXACT equality (deterministic for a fixed seed range).
const STRUCTURAL_PARAMS: [&str; 4] = [
    "recovery_records_replayed",
    "recovery_inflight_undone",
    "recovery_crashes",
    "seeds",
];

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (baseline_path, candidate_path) = match (args.next(), args.next()) {
        (Some(b), Some(c)) => (b, c),
        _ => {
            eprintln!("usage: durability_baseline_cmp <baseline.json> <candidate.json>");
            return ExitCode::FAILURE;
        }
    };

    let baseline = match EvidenceReport::load(&baseline_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("durability_baseline_cmp: cannot load baseline {baseline_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let candidate = match EvidenceReport::load(&candidate_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("durability_baseline_cmp: cannot load candidate {candidate_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut failed = false;

    // --- Layer 1: structural equality (integer-stable for a fixed seed range). ---
    if candidate.metadata.dataset.nodes != baseline.metadata.dataset.nodes {
        eprintln!(
            "durability_baseline_cmp: recovered dataset size drifted: baseline {} nodes, candidate \
             {} nodes (a lost/extra recovered :Person row)",
            baseline.metadata.dataset.nodes, candidate.metadata.dataset.nodes,
        );
        failed = true;
    } else {
        println!(
            "structural: recovered dataset size matches ({} nodes)",
            candidate.metadata.dataset.nodes
        );
    }

    for key in STRUCTURAL_PARAMS {
        match (
            baseline.metadata.workload.get(key),
            candidate.metadata.workload.get(key),
        ) {
            (Some(b), Some(c)) if b == c => {
                println!("structural: {key} matches ({c})");
            }
            (Some(b), Some(c)) => {
                eprintln!("durability_baseline_cmp: {key} drifted: baseline {b}, candidate {c}");
                failed = true;
            }
            _ => {
                // The baseline predates the field (or the candidate lacks it): not a hard fail, note.
                println!("structural: {key} not present in both reports (skipped)");
            }
        }
    }

    // --- Layer 2: every quantitative family is machine-variant for this scenario, so the harness diff
    // is held to an infinite tolerance — it is run purely to print the human-readable delta summary,
    // never to fail the gate. (The deterministic signal is the structural layer above.)
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
    print!("{}", cmp.summary());

    if failed {
        ExitCode::FAILURE
    } else {
        println!("GRAPHUS_BASELINE_OK");
        ExitCode::SUCCESS
    }
}
