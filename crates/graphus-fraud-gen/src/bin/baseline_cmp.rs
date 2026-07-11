//! `baseline_cmp` — the fraud-oltp evidence **regression gate** (`rmp #256`).
//!
//! It loads a committed **baseline** evidence report and a **fresh** run's report, then runs the
//! harness's [`compare_to_baseline`] to decide whether the fresh run regressed. On success it prints
//! `GRAPHUS_BASELINE_OK` and exits `0`; on a regression it prints the offending metrics and exits
//! `1`. The fraud-oltp `run.sh` invokes it as the committed-baseline gate.
//!
//! ## Why a STRUCTURAL-only comparison
//!
//! CPU seconds, peak RSS, throughput, and latency percentiles are **machine- and timing-dependent**
//! — comparing them across the developer/CI machines a baseline is shared between would be flaky. So
//! this gate holds only the **stable, structural** metrics to a tight bound and gives the volatile
//! ones an effectively infinite tolerance:
//!
//! | Metric family | Tolerance | Rationale |
//! |---------------|-----------|-----------|
//! | storage bytes / pages | **15%** | deterministic for a fixed seed+profile; a real footprint regression |
//! | amplification ratios  | **15%** | derived from the same deterministic on-disk footprint |
//! | abort / conflict rate | **+200% rise** | a livelock-drift guard over a scheduling-variant rate (see below) |
//! | throughput ops/sec    | ignored (∞) | varies with machine speed |
//! | latency p50/p99/p999  | ignored (∞) | varies with machine speed + scheduling |
//! | CPU seconds           | ignored (∞) | varies with machine speed |
//! | peak RSS              | ignored (∞) | varies with allocator/OS/machine |
//!
//! The storage footprint is the meaningful, reproducible regression signal here: for a fixed seed +
//! profile the generated graph — and therefore the durable store/WAL it produces — is byte-stable,
//! so a footprint that drifts beyond the band is a genuine storage-engine regression worth failing.
//!
//! `rmp #715` made this gate **stronger**, as a side effect of the workload becoming
//! production-shaped: under the old no-retry client the number of transfers that survived contention
//! varied run to run (13, then 25, then 33 of 270 — a 2.5x swing), and every surviving transfer is
//! durable bytes, so the store/WAL footprint the 15% gate compared swung with it. Under the retrying
//! client **exactly 270 of 270** business transfers commit on every run, so the dominant term of the
//! footprint is now fixed. It is not byte-identical — the handful of retried attempts that do occur
//! vary (13-15 across runs), which moves the measured store image by ~1.5% — but that is comfortably
//! inside the 15% band, where the old 2.5x swing in committed work was not.
//!
//! ## The abort-rate gate (rmp #689, retuned by rmp #715)
//!
//! `throughput.abort_rate` is the **ENGINE's** abort rate: the fraction of transaction *attempts* the
//! engine refused to serialize. The PRIMARY abort gate is the two-sided **absolute** band asserted
//! first-class by `data/concurrency.js` (`FRAUD_ABORT_FLOOR`..`FRAUD_ABORT_CEIL`); this one is only a
//! one-sided livelock-drift guard on top of it.
//!
//! Its tolerance had to be **retuned** when the example's default client became a *retrying* one
//! (`rmp #715`), because the quantity itself changed character:
//!
//! - Under the old **no-retry** client the rate was ~0.9 — structurally near-saturated, so a **+10%**
//!   rise was a meaningful livelock guard (it fired past ~0.99).
//! - Under the **retrying** client it is ~0.05: backing off after an abort spreads the writers out in
//!   time, so the per-attempt conflict rate collapses by ~18x. That rate is small and
//!   **scheduling-variant** (0.046 / 0.049 across consecutive runs is already ±6%), so a +10% gate over
//!   it would fire on ordinary run-to-run noise — a flake generator, not a regression detector.
//!
//! So the guard is now **+200%** (fires when a run's abort rate exceeds ~3x the baseline, i.e. ~0.15
//! against a ~0.05 baseline). That is still a genuine signal — a retrying client whose engine abort
//! rate tripled has lost the de-synchronising benefit of backoff — while being immune to scheduling
//! noise. The absolute floor/ceil in `concurrency.js` remains the real two-sided assertion.
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
            eprintln!("usage: baseline_cmp <baseline.json> <candidate.json>");
            return ExitCode::FAILURE;
        }
    };

    let baseline = match EvidenceReport::load(&baseline_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("baseline_cmp: cannot load baseline {baseline_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let candidate = match EvidenceReport::load(&candidate_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("baseline_cmp: cannot load candidate {candidate_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Structural-only thresholds: tight on the deterministic footprint, generous on abort rate,
    // and effectively infinite on the machine-variant families (throughput/latency/CPU/memory).
    let thresholds = RegressionThresholds {
        throughput_drop: IGNORE,
        latency_rise: IGNORE,
        memory_rise: IGNORE,
        storage_rise: 0.15,
        amplification_rise: 0.15,
        cpu_rise: IGNORE,
        // A livelock-drift guard over a SCHEDULING-VARIANT rate: against the retrying client's ~0.05
        // baseline this fires past ~0.15 (a tripling — backoff having lost its de-synchronising
        // effect), while tolerating the ±6% run-to-run noise a +10% gate would have flaked on. See the
        // module docs. The primary, two-sided abort band is asserted first-class in data/concurrency.js.
        abort_rate_rise: 2.00,
    };

    let cmp = candidate.compare_to_baseline(&baseline, &thresholds);
    print!("{}", cmp.summary());

    if cmp.regressed {
        eprintln!("baseline_cmp: a structural metric regressed beyond its threshold (see above)");
        ExitCode::FAILURE
    } else {
        println!("GRAPHUS_BASELINE_OK");
        ExitCode::SUCCESS
    }
}
