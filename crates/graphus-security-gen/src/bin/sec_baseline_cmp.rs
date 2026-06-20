//! `sec_baseline_cmp` — the security-multitenant evidence **regression gate**.
//!
//! It loads a committed **baseline** evidence report and a **fresh** run's report, then runs the
//! harness's [`compare_to_baseline`] to decide whether the fresh run regressed. On success it prints
//! `GRAPHUS_BASELINE_OK` and exits `0`; on a regression it prints the offending metrics and exits
//! `1`. The security-multitenant `run.sh` invokes it as the committed-baseline gate.
//!
//! ## Why a STRUCTURAL-only comparison
//!
//! CPU seconds, peak RSS, throughput, and latency percentiles are **machine- and timing-dependent**
//! — comparing them across the developer/CI machines a baseline is shared between would be flaky. So
//! this gate holds only the **stable, structural** metrics (the deterministic on-disk footprint and
//! dataset size, which are byte-stable for a fixed seed + profile) to a tight bound and gives the
//! volatile families an effectively infinite tolerance.
//!
//! Named `sec_baseline_cmp` (NOT `baseline_cmp`) to avoid a `target/<profile>/baseline_cmp`
//! binary-name collision with the other example leaf crates' comparators.
//!
//! [`compare_to_baseline`]: graphus_examples_harness::EvidenceReport::compare_to_baseline

use std::process::ExitCode;

use graphus_examples_harness::{EvidenceReport, RegressionThresholds};

/// A tolerance large enough that a metric never trips the gate (the machine-variant families).
const IGNORE: f64 = f64::INFINITY;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (baseline_path, candidate_path) = match (args.next(), args.next()) {
        (Some(b), Some(c)) => (b, c),
        _ => {
            eprintln!("usage: sec_baseline_cmp <baseline.json> <candidate.json>");
            return ExitCode::FAILURE;
        }
    };

    let baseline = match EvidenceReport::load(&baseline_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sec_baseline_cmp: cannot load baseline {baseline_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let candidate = match EvidenceReport::load(&candidate_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sec_baseline_cmp: cannot load candidate {candidate_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Structural-only thresholds: tight on the deterministic footprint, infinite on the
    // machine-variant families (throughput/latency/CPU/memory).
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
        eprintln!(
            "sec_baseline_cmp: a structural metric regressed beyond its threshold (see above)"
        );
        ExitCode::FAILURE
    } else {
        println!("GRAPHUS_BASELINE_OK");
        ExitCode::SUCCESS
    }
}
