//! The DST core's standardized evidence report — built **honestly** (`rmp` #698/#699).
//!
//! Three things this module exists to get right, each of which the example previously got wrong:
//!
//! 1. **`total_millis` is the workload's wall time**, not the report-builder's. The collector times
//!    `start()`→`finish()`; the sweep had already finished by then, so the committed baseline recorded
//!    `total_millis: 0.003787` — 3.8 *microseconds* for a 416 ms sweep. It now records the measured
//!    sweep duration through [`EvidenceCollector::record_total_duration`].
//! 2. **The dataset's relationship count is real.** It used to be hard-coded `0` even though the
//!    workload relates the nodes it creates; the recovered `:KNOWS` count now comes from the run
//!    (`graphus_dst`'s `persisted_edges`, read back from the recovered engine).
//! 3. **CPU and RSS are measured, not zeroed.** The scenario is hermetic: the engine runs *in this
//!    process*, so `getrusage(RUSAGE_SELF)` IS the engine's CPU and peak RSS. The report used to emit
//!    zeros; it now emits the process's real figures. Latency percentiles, which this scenario does not
//!    measure, are left absent rather than fabricated as `0.0` — the per-seed *scenario* time is
//!    reported as the throughput window instead.

use std::time::Duration;

use graphus_examples_harness::resource::{
    Target, cpu_section, cumulative_cpu_times, peak_rss_self_bytes,
};
use graphus_examples_harness::{
    CpuSection, DatasetScale, EvidenceCollector, EvidenceReport, RunMetadata, current_rss_bytes,
};

use crate::{DurabilityRun, SweepReport, certified_properties};

/// The phase name the sweep is recorded under (also the throughput window).
pub const SWEEP_PHASE: &str =
    "durability sweep (workload + crash + ARIES recovery + 4-property oracle)";

/// Builds the deterministic core's evidence report.
///
/// `sweep_duration` is the MEASURED wall-clock of the sweep — it becomes both the report's
/// `total_millis` and the throughput window, so the two can never disagree. `process_wall` is how long
/// this process has been alive (used to derive mean core utilisation from its cumulative CPU).
#[must_use]
pub fn build_report(
    sweep: &SweepReport,
    focus: &DurabilityRun,
    sweep_duration: Duration,
    process_wall: Duration,
    fault_matrix_note: Option<String>,
) -> EvidenceReport {
    let metadata = RunMetadata::new(
        "durability-crash-recovery",
        "Deterministic OLTP durability + crash-recovery under load, driven by the DST simulator: a \
         concurrent overlapping-transaction workload under disk/clock faults and a seeded mid-workload \
         crash, rebuilt via ARIES recovery, with the four ACID-durability properties \
         (serializability / durability / atomicity / reference-model equivalence) asserted on the \
         recovered engine against the committed-only shadow LPG.",
    )
    // MEASURED (rmp #698): the recovered node AND relationship counts of the focus seed. The
    // relationship count used to be hard-coded 0 even though the workload relates the nodes it creates.
    .with_dataset(DatasetScale::new(
        focus.recovered_nodes.max(0) as u64,
        focus.recovered_edges.max(0) as u64,
    ))
    .workload_param("scenario", "oltp-durability")
    .workload_param("driver", "graphus-dst VOPR safety oracle (run_safety)")
    .workload_param(
        "seeds",
        format!("{}..{}", sweep.start, sweep.start + sweep.count),
    )
    .workload_param("clients", "6 (overlapping explicit transactions)")
    .workload_param("crashes_per_seed", "<=2 (mid-workload crash + ARIES restart)")
    .workload_param("focus_seed", focus.seed.to_string())
    .workload_param(
        "recovery_records_replayed",
        sweep.total_acked_durable().to_string(),
    )
    .workload_param(
        "recovery_inflight_undone",
        sweep.total_inflight_discarded().to_string(),
    )
    .workload_param("recovery_crashes", sweep.total_crashes().to_string())
    .workload_param(
        "focus_recovery_records_replayed",
        focus.acked_at_last_crash().to_string(),
    )
    .workload_param("focus_recovered_txns", focus.recovered_txns.to_string());

    let mut c = EvidenceCollector::new(metadata);
    c.start();

    // The sweep is the one timed phase, and its measured duration is the report's authoritative total.
    c.phase(SWEEP_PHASE, sweep_duration);
    c.record_total_duration(sweep_duration);

    // CPU + RSS: hermetic scenario ⇒ the engine IS this process, so `RUSAGE_SELF` is the engine's own
    // consumption. Measured, not zeroed.
    let cpu: CpuSection = cumulative_cpu_times(Target::SelfProcess)
        .map(|t| cpu_section(t, process_wall.max(Duration::from_millis(1))))
        .unwrap_or_default();
    *c.cpu_mut() = cpu;
    // An unreadable RSS is NOT MEASURED (absent), never `0` bytes resident (`rmp #711`).
    c.memory_mut().peak_rss_bytes = peak_rss_self_bytes();
    c.memory_mut().final_rss_bytes = current_rss_bytes(Target::SelfProcess);

    // Throughput: seeds (each a full workload + crash + ARIES recovery + 4-property oracle) per second
    // over the MEASURED sweep window. Latency percentiles are NOT measured by this scenario and are
    // therefore ABSENT from the report rather than fabricated (rmp #699 / #711); the honest
    // per-scenario cost is stated below as a note.
    let secs = sweep_duration.as_secs_f64().max(1e-9);
    let tp = c.throughput_mut();
    tp.operations = Some(sweep.count);
    tp.ops_per_sec = Some(sweep.count as f64 / secs);

    c.note(format!(
        "durability oracle: {} seed(s) checked, {} unsafe, {} non-deterministic — properties: {:?}",
        sweep.count,
        sweep.unsafe_seeds().len(),
        sweep.nondeterministic,
        certified_properties(),
    ));
    c.note(format!(
        "crash + ARIES restarts across sweep: {}; faults injected: {}; acked commits proven durable: \
         {}; in-flight transactions discarded by undo: {}; non-vacuous runs (both halves of \
         committed-or-nothing under test): {}/{}",
        sweep.total_crashes(),
        sweep.total_faults(),
        sweep.total_acked_durable(),
        sweep.total_inflight_discarded(),
        sweep.non_vacuous_runs(),
        sweep.count,
    ));
    c.note(format!(
        "recovered dataset of the focus seed (MEASURED, rmp #698): {} :Person nodes and {} :KNOWS \
         relationships, read back from the RECOVERED engine and equal to the committed-only shadow \
         model ({} nodes / {} edges). The relationship count was previously reported as 0.",
        focus.recovered_nodes, focus.recovered_edges, focus.committed_nodes, focus.committed_edges,
    ));
    c.note(format!(
        "mean cost of one full crash-recovery scenario: {:.1} ms ({} seeds in {:.1} ms). Per-seed \
         latency percentiles are NOT measured by this hermetic sweep and are therefore left at their \
         'not measured' default rather than fabricated (rmp #699).",
        sweep_duration.as_secs_f64() * 1_000.0 / sweep.count.max(1) as f64,
        sweep.count,
        sweep_duration.as_secs_f64() * 1_000.0,
    ));
    c.note(
        "the storage vector is ABSENT here BY CONSTRUCTION, not by omission: the DST core runs the \
         engine on an in-memory device + in-memory WAL sink, so there is no on-disk footprint to \
         size, and schema v3 omits what it cannot measure rather than emitting a zero. The example's \
         REAL durability vector — the redo log the crash left behind, the store image it was replayed \
         into, the WAL residual afterwards, the bytes forced to durable media, and the wall-clock + \
         peak RSS of the replay — is measured on the real on-disk store of the real-server SIGKILL \
         run, and is the example's HEADLINE report (evidence/report.json). This report used to BE the \
         headline, which is how the project's durability example came to tell its reader that \
         durability cost zero bytes (rmp #712)."
            .to_string(),
    );
    if let Some(n) = fault_matrix_note {
        c.note(n);
    }
    c.note(
        "deterministic-vs-machine-variant split: the recovery-work counts \
         (recovery_records_replayed / recovery_inflight_undone / recovery_crashes), the durability \
         verdict, the recovered hashes and the recovered dataset size are EXACTLY reproducible (a pure \
         function of the seed range) and are what the committed baseline gates; the sweep wall-time, \
         the seed-rate throughput and this process's CPU/RSS are machine-variant and are NOT gated."
            .to_string(),
    );

    c.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{run_seed, run_sweep};

    /// **Regression (`rmp` #699).** `total_millis` must be the MEASURED workload wall-time. It used to
    /// be the report-builder's own elapsed time (the committed baseline recorded 0.0038 ms for a 416 ms
    /// sweep), which is a fabricated figure.
    #[test]
    fn total_millis_is_the_measured_sweep_duration_not_the_report_build_time() {
        let sweep = run_sweep(1, 3);
        let focus = run_seed(1);
        let duration = Duration::from_millis(1234);
        let report = build_report(&sweep, &focus, duration, Duration::from_secs(2), None);

        assert!(
            (report.total_millis - 1234.0).abs() < 1e-6,
            "total_millis must be the workload wall-time (got {})",
            report.total_millis
        );
        let phase = report
            .phases
            .iter()
            .find(|p| p.name == SWEEP_PHASE)
            .expect("the sweep phase must be recorded");
        assert!(
            (phase.millis - report.total_millis).abs() < 1e-6,
            "the phase timing and the total must agree — they are the same measured window"
        );
    }

    /// **Regression (`rmp` #698).** The dataset's relationship count must be the REAL recovered edge
    /// count, not a hard-coded 0 — the workload relates every node it creates.
    #[test]
    fn the_report_states_the_recovered_relationship_count() {
        let sweep = run_sweep(1, 3);
        let focus = run_seed(1);
        let report = build_report(
            &sweep,
            &focus,
            Duration::from_millis(10),
            Duration::from_secs(1),
            None,
        );
        assert_eq!(
            report.metadata.dataset.relationships,
            focus.recovered_edges.max(0) as u64
        );
        assert!(
            report.metadata.dataset.relationships > 0,
            "the recovered graph HAS relationships; reporting 0 understates the workload"
        );
        assert_eq!(
            focus.recovered_edges, focus.committed_edges,
            "every committed relationship survived and no in-flight one persisted"
        );
    }

    /// CPU/RSS are measured for this hermetic in-process scenario (the engine IS this process), and the
    /// unmeasured latency percentiles stay at their honest "not measured" default.
    #[test]
    fn cpu_and_memory_are_measured_and_latency_is_not_fabricated() {
        let sweep = run_sweep(1, 2);
        let focus = run_seed(1);
        let report = build_report(
            &sweep,
            &focus,
            Duration::from_millis(50),
            Duration::from_secs(1),
            None,
        );
        assert!(
            report.cpu.user_secs.expect("CPU is measured here") > 0.0,
            "the sweep burned real CPU in THIS process; it must be reported"
        );
        assert!(
            report.memory.peak_rss_bytes.expect("RSS is measured here") > 0,
            "the process has a real peak RSS; it must be reported"
        );
        assert_eq!(
            report.throughput.p50_latency_ms, None,
            "an unmeasured percentile is ABSENT (rmp #711) — never invented, and never a 0.0 that \
             reads as 'instantaneous'"
        );
        assert!(report.throughput.ops_per_sec.expect("rate is measured") > 0.0);
    }
}
