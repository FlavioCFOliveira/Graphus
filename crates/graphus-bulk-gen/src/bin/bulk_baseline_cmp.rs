//! `bulk_baseline_cmp` — the bulk-etl evidence **regression gate** (`rmp #270`).
//!
//! It loads a committed **baseline** evidence report and a **fresh** run's report, then gates the
//! run against the baseline. On success it prints `GRAPHUS_BASELINE_OK` and exits `0`; on a
//! regression it prints the offending metrics and exits `1`. The bulk-etl `run.sh` invokes it as the
//! committed-baseline gate (mirrors gds-analytics' `gds_baseline_cmp` and fraud-oltp's `baseline_cmp`).
//!
//! ## What is gated, and why only the STRUCTURAL metrics
//!
//! For a fixed seed + profile the generated dataset — and therefore the store the offline importer
//! builds from it — is **byte-stable**: the same node/relationship counts and the same on-disk
//! `store_bytes` / `store_pages` and per-element costs on every host. Those are the meaningful,
//! reproducible regression signals. By contrast ingest throughput, CPU seconds, peak RSS, and
//! wall-time are **machine-dependent**, so gating them across the developer/CI machines a baseline is
//! shared between would be flaky.
//!
//! The gate therefore has two layers:
//!
//! 1. **Structural equality** — the dataset size (`dataset.nodes` / `dataset.relationships`) and the
//!    imported-element count (`workload.imported_elements`) must match the baseline EXACTLY. A change
//!    here means the generator drifted, which the example must catch.
//! 2. **Tight-band footprint** — the harness's [`compare_to_baseline`] holds the durable store
//!    footprint encoded into the storage section to **15%**:
//!
//!    | Metric (storage section) | Encodes | Tolerance |
//!    |--------------------------|---------|-----------|
//!    | `store_bytes`            | durable graph.store image bytes | **15%** |
//!    | `space_amplification`    | store bytes-per-node            | **15%** |
//!    | `write_amplification`    | store bytes-per-edge            | **15%** |
//!    | throughput / latency / CPU / memory | machine-variant   | ignored (∞) |
//!
//! The 15% band matches the gds-analytics / fraud-oltp storage gates: tight enough to catch a real
//! footprint regression (free-list slack, record-layout, token-catalog growth), loose enough to
//! absorb the small `f64` formatting / rounding differences a re-serialized report can introduce, plus
//! the modest run-to-run WAL/page slack an offline batched load produces. The dataset size +
//! element count are gated at EXACT equality because they are integer-stable for a fixed seed.
//!
//! [`compare_to_baseline`]: graphus_examples_harness::EvidenceReport::compare_to_baseline

#![forbid(unsafe_code)]

use std::process::ExitCode;

use graphus_examples_harness::{EvidenceReport, RegressionThresholds};

/// A tolerance large enough that a metric never trips the gate (the machine-variant families).
const IGNORE: f64 = f64::INFINITY;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (baseline_path, candidate_path) = match (args.next(), args.next()) {
        (Some(b), Some(c)) => (b, c),
        _ => {
            eprintln!("usage: bulk_baseline_cmp <baseline.json> <candidate.json>");
            return ExitCode::FAILURE;
        }
    };

    let baseline = match EvidenceReport::load(&baseline_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bulk_baseline_cmp: cannot load baseline {baseline_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let candidate = match EvidenceReport::load(&candidate_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bulk_baseline_cmp: cannot load candidate {candidate_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut failed = false;

    // --- Layer 1: structural equality (integer-stable for a fixed seed). ---
    if candidate.metadata.dataset.nodes != baseline.metadata.dataset.nodes
        || candidate.metadata.dataset.relationships != baseline.metadata.dataset.relationships
    {
        eprintln!(
            "bulk_baseline_cmp: dataset size drifted: baseline {}n/{}r, candidate {}n/{}r",
            baseline.metadata.dataset.nodes,
            baseline.metadata.dataset.relationships,
            candidate.metadata.dataset.nodes,
            candidate.metadata.dataset.relationships,
        );
        failed = true;
    } else {
        println!(
            "structural: dataset size matches ({} nodes, {} relationships)",
            candidate.metadata.dataset.nodes, candidate.metadata.dataset.relationships
        );
    }

    let elems = |r: &EvidenceReport| r.metadata.workload.get("imported_elements").cloned();
    match (elems(&baseline), elems(&candidate)) {
        (Some(b), Some(c)) if b == c => {
            println!("structural: imported_elements matches ({c})");
        }
        (Some(b), Some(c)) => {
            eprintln!("bulk_baseline_cmp: imported_elements drifted: baseline {b}, candidate {c}");
            failed = true;
        }
        _ => {
            // The baseline predates the field (or the candidate lacks it): not a hard fail, but note.
            println!("structural: imported_elements not present in both reports (skipped)");
        }
    }

    // --- Layer 2: tight-band store footprint via the harness diff; machine-variant families ignored.
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
            "bulk_baseline_cmp: a structural footprint metric regressed beyond its threshold"
        );
        failed = true;
    }

    if failed {
        ExitCode::FAILURE
    } else {
        println!("GRAPHUS_BASELINE_OK");
        ExitCode::SUCCESS
    }
}
