//! `gds_baseline_cmp` — the gds-analytics evidence **regression gate** (`rmp #263`).
//!
//! It loads a committed **baseline** evidence report and a **fresh** run's report, then gates the
//! run against the baseline. On success it prints `GRAPHUS_BASELINE_OK` and exits `0`; on a
//! regression it prints the offending metrics and exits `1`. The gds-analytics `run.sh` invokes it as
//! the committed-baseline gate (mirrors fraud-oltp's `baseline_cmp`).
//!
//! ## What is gated, and why only the STRUCTURAL metrics
//!
//! For a fixed seed + profile the generated influence network — and therefore the CSR projection the
//! GDS engine builds from it — is **byte-stable**: the same node/edge counts and the same
//! `CsrGraph::memory_bytes()` on every host. Those are the meaningful, reproducible regression
//! signals. By contrast CPU seconds, peak RSS, and per-algorithm wall time are **machine-dependent**,
//! so gating them across the developer/CI machines a baseline is shared between would be flaky.
//!
//! The gate therefore has two layers:
//!
//! 1. **Structural equality** — the reference graph size (`dataset.nodes` / `dataset.relationships`)
//!    and the algorithm count (`workload.algorithm_count`) must match the baseline EXACTLY. A change
//!    here means the generator or the procedure surface drifted, which the example must catch.
//! 2. **Tight-band CSR footprint** — the deterministic resident projection, held to **15%**:
//!
//!    | Metric (workload param)         | Encodes                   | Tolerance |
//!    |---------------------------------|---------------------------|-----------|
//!    | `reference_csr_bytes`           | reference CSR total bytes | **15%** |
//!    | `reference_csr_bytes_per_node`  | CSR bytes-per-node        | **15%** |
//!    | `reference_csr_bytes_per_edge`  | CSR bytes-per-edge        | **15%** |
//!    | storage / throughput / latency / CPU / memory | machine- or path-variant | ignored (∞) |
//!
//! The 15% band matches fraud-oltp's storage gate: tight enough to catch a real footprint regression,
//! loose enough to absorb the small `f64` formatting / rounding differences a re-serialized report
//! can introduce. The graph size + algorithm count are gated at EXACT equality because they are
//! integer-stable for a fixed seed.
//!
//! ## Why the CSR gate reads the workload params (`rmp #699`)
//!
//! It used to read the **storage section**, because `gds_evidence` smuggled the CSR footprint in
//! there: `store_bytes` carried the projection's resident size, `space_amplification` carried
//! bytes-per-node and `write_amplification` bytes-per-edge. That made the committed baseline read
//! `space_amplification: 119.06` — a per-element cost in a ratio field — and left `wal_bytes: 0`, so
//! the report claimed the run wrote no redo log. The storage section now carries the server's REAL
//! on-disk store + WAL footprint (path-dependent, hence not gated), and this gate reads the CSR
//! figures from the `reference_csr_*` workload params, where they were always published correctly
//! named. Same numbers, same 15% band, no mislabelled field.
//!
//! [`compare_to_baseline`]: graphus_examples_harness::EvidenceReport::compare_to_baseline

use std::process::ExitCode;

use graphus_examples_harness::{EvidenceReport, RegressionThresholds};

/// A tolerance large enough that a metric never trips the gate (the machine-variant families).
const IGNORE: f64 = f64::INFINITY;

/// The tight band the deterministic CSR footprint is held to.
const CSR_BAND: f64 = 0.15;

/// The `reference_csr_*` workload params the CSR footprint gate holds to [`CSR_BAND`].
const CSR_PARAMS: [&str; 3] = [
    "reference_csr_bytes",
    "reference_csr_bytes_per_node",
    "reference_csr_bytes_per_edge",
];

/// Gates one deterministic workload param to a relative band. Returns `true` on a regression.
///
/// A param missing from **either** report is skipped (a baseline may predate the field); a param
/// present but unparseable is a hard failure, because a metric that cannot be read cannot be trusted.
fn csr_param_regressed(baseline: &EvidenceReport, candidate: &EvidenceReport, key: &str) -> bool {
    let (Some(b_raw), Some(c_raw)) = (
        baseline.metadata.workload.get(key),
        candidate.metadata.workload.get(key),
    ) else {
        println!("csr footprint: {key} not present in both reports (skipped)");
        return false;
    };
    let (Ok(b), Ok(c)) = (b_raw.parse::<f64>(), c_raw.parse::<f64>()) else {
        eprintln!(
            "gds_baseline_cmp: {key} is not numeric (baseline {b_raw:?}, candidate {c_raw:?})"
        );
        return true;
    };
    if b <= 0.0 {
        println!("csr footprint: {key} baseline is {b} (no band to hold; skipped)");
        return false;
    }
    let delta = (c - b) / b;
    if delta > CSR_BAND {
        eprintln!(
            "gds_baseline_cmp: {key} regressed {:+.1}% (baseline {b:.4}, candidate {c:.4}, band \
             +{:.0}%)",
            delta * 100.0,
            CSR_BAND * 100.0,
        );
        return true;
    }
    println!(
        "csr footprint: {key} {c:.4} vs baseline {b:.4} ({:+.1}%, within +{:.0}%)",
        delta * 100.0,
        CSR_BAND * 100.0,
    );
    false
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (baseline_path, candidate_path) = match (args.next(), args.next()) {
        (Some(b), Some(c)) => (b, c),
        _ => {
            eprintln!("usage: gds_baseline_cmp <baseline.json> <candidate.json>");
            return ExitCode::FAILURE;
        }
    };

    let baseline = match EvidenceReport::load(&baseline_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gds_baseline_cmp: cannot load baseline {baseline_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let candidate = match EvidenceReport::load(&candidate_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gds_baseline_cmp: cannot load candidate {candidate_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut failed = false;

    // --- Layer 1: structural equality (integer-stable for a fixed seed). ---
    if candidate.metadata.dataset.nodes != baseline.metadata.dataset.nodes
        || candidate.metadata.dataset.relationships != baseline.metadata.dataset.relationships
    {
        eprintln!(
            "gds_baseline_cmp: reference graph size drifted: baseline {}n/{}r, candidate {}n/{}r",
            baseline.metadata.dataset.nodes,
            baseline.metadata.dataset.relationships,
            candidate.metadata.dataset.nodes,
            candidate.metadata.dataset.relationships,
        );
        failed = true;
    } else {
        println!(
            "structural: reference graph size matches ({} nodes, {} relationships)",
            candidate.metadata.dataset.nodes, candidate.metadata.dataset.relationships
        );
    }

    let alg = |r: &EvidenceReport| r.metadata.workload.get("algorithm_count").cloned();
    match (alg(&baseline), alg(&candidate)) {
        (Some(b), Some(c)) if b == c => {
            println!("structural: algorithm_count matches ({c})");
        }
        (Some(b), Some(c)) => {
            eprintln!("gds_baseline_cmp: algorithm_count drifted: baseline {b}, candidate {c}");
            failed = true;
        }
        _ => {
            // The baseline predates the field (or the candidate lacks it): not a hard fail, but note.
            println!("structural: algorithm_count not present in both reports (skipped)");
        }
    }

    // --- Layer 2: tight-band CSR footprint, read from the correctly-named workload params.
    for key in CSR_PARAMS {
        if csr_param_regressed(&baseline, &candidate, key) {
            failed = true;
        }
    }

    // The report's own sections are all machine- or path-variant here (the storage section is the
    // live server's on-disk footprint, which is huge on the driver path and absent on the hermetic
    // one), so the harness diff runs for VISIBILITY only — nothing in it gates.
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

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_examples_harness::{EvidenceCollector, RunMetadata};

    /// Builds a report carrying the three `reference_csr_*` params.
    fn report(csr_bytes: f64, per_node: f64, per_edge: f64) -> EvidenceReport {
        let mut c = EvidenceCollector::new(RunMetadata::new("gds-analytics", "test"));
        {
            let w = &mut c.metadata_mut().workload;
            w.insert("reference_csr_bytes".into(), format!("{csr_bytes}"));
            w.insert("reference_csr_bytes_per_node".into(), format!("{per_node}"));
            w.insert("reference_csr_bytes_per_edge".into(), format!("{per_edge}"));
        }
        c.finish()
    }

    /// Regression (`rmp #699`): the CSR footprint gate must hold the deterministic projection from
    /// the correctly-named workload params — it used to read it out of `storage.space_amplification`
    /// / `write_amplification`, which is where the per-element costs were being smuggled.
    #[test]
    fn identical_csr_footprint_passes_every_param() {
        let base = report(514_332.0, 119.0583, 5.9573);
        let cand = report(514_332.0, 119.0583, 5.9573);
        for key in CSR_PARAMS {
            assert!(!csr_param_regressed(&base, &cand, key), "{key} flagged");
        }
    }

    #[test]
    fn csr_growth_beyond_the_band_is_a_regression() {
        let base = report(514_332.0, 119.0583, 5.9573);
        // +20% bytes-per-node: past the 15% band.
        let cand = report(514_332.0, 142.87, 5.9573);
        assert!(csr_param_regressed(
            &base,
            &cand,
            "reference_csr_bytes_per_node"
        ));
        // The untouched params still pass.
        assert!(!csr_param_regressed(&base, &cand, "reference_csr_bytes"));
    }

    #[test]
    fn csr_shrink_is_never_a_regression() {
        let base = report(514_332.0, 119.0583, 5.9573);
        let cand = report(400_000.0, 90.0, 4.0);
        for key in CSR_PARAMS {
            assert!(
                !csr_param_regressed(&base, &cand, key),
                "{key} flagged a footprint IMPROVEMENT as a regression"
            );
        }
    }

    #[test]
    fn a_missing_param_is_skipped_not_failed() {
        let base = report(514_332.0, 119.0583, 5.9573);
        let cand = EvidenceCollector::new(RunMetadata::new("gds-analytics", "test")).finish();
        for key in CSR_PARAMS {
            assert!(!csr_param_regressed(&base, &cand, key));
        }
    }

    /// A param that is present but unreadable must FAIL the gate: a metric that cannot be parsed
    /// cannot be trusted, and silently skipping it would let a real regression through.
    #[test]
    fn an_unparseable_param_fails_the_gate() {
        let base = report(514_332.0, 119.0583, 5.9573);
        let mut c = EvidenceCollector::new(RunMetadata::new("gds-analytics", "test"));
        c.metadata_mut()
            .workload
            .insert("reference_csr_bytes".into(), "not-a-number".into());
        let cand = c.finish();
        assert!(csr_param_regressed(&base, &cand, "reference_csr_bytes"));
    }
}
