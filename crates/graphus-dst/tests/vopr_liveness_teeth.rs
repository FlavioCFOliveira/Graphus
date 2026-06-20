//! The VOPR **liveness oracle** must have teeth (rmp #240; the sibling of `vopr_safety_teeth.rs`).
//!
//! Liveness mode ([`graphus_dst::vopr::run_liveness`]) runs the cooperative interleaver under a bounded,
//! recoverable fault window and asserts **two** properties on the run: progress (no deadlock / livelock
//! / hang — a progress watchdog over logical time, bounded by the hard step cap so a real hang becomes a
//! *reported* failure, never a CI hang) and fault-then-heal recovery (after the fault window heals, a
//! fresh workload batch commits and serves correct results — availability resumed). A liveness oracle
//! that always passes is worthless — this suite proves the watchdog flags a wedge, the recovery probe
//! flags a non-recovering engine, and a faithful run is `live` with zero false positives.
//!
//! The two pure arms (the watchdog state machine + the recovery-probe verdict) are exercised against
//! fabricated traces inside the crate's unit tests (they need the private `LivenessTrace` the evaluator
//! consumes); here we exercise the **end-to-end real-engine** behaviour and the **seed sweep**.

use graphus_dst::vopr::{VoprConfig, run_liveness, run_liveness_cli};

/// A faithful liveness run on a clean seed is `live`: the engine kept making progress (no stall) under
/// a recoverable fault window, and recovered availability after the heal. Non-vacuous: faults + crashes
/// genuinely fired during the window, and the post-heal recovery batch genuinely committed.
#[test]
fn liveness_run_is_live_on_a_clean_seed() {
    let r = run_liveness(VoprConfig::liveness(1));
    assert!(
        r.live,
        "a clean seed must pass the liveness oracle (no hang + recovers after heal): {:?}",
        r.failures
    );
    assert!(r.failures.is_empty());
    // No unbounded stall: the worst stall stayed well under the threshold.
    assert!(
        r.max_stall_steps < r.stall_threshold,
        "a healthy run must stay under the stall threshold ({}/{})",
        r.max_stall_steps,
        r.stall_threshold
    );
    // Non-vacuity: faults and crashes genuinely fired during this certified run.
    assert!(
        r.run.crash_restarts > 0,
        "the liveness run must actually crash + recover"
    );
    assert!(
        r.run.disk_faults + r.run.clock_faults + r.run.transport_faults > 0,
        "the liveness run must actually inject faults"
    );
    // The fault-then-heal recovery probe proved availability resumed: every fresh post-heal create
    // committed and read back correctly.
    assert!(
        r.recovery_attempted > 0,
        "the recovery probe must attempt a non-empty post-heal batch (non-vacuous)"
    );
    assert_eq!(
        r.recovery_committed, r.recovery_attempted,
        "the post-heal batch must fully commit — availability recovered"
    );
    assert!(
        r.recovery_correct,
        "the post-heal batch must read back correctly (reference model agreed)"
    );
}

/// Determinism: the same seed reproduces an identical [`graphus_dst::LivenessReport`] — verdict,
/// watchdog stats, dumped schedule, recovery counts, and the full underlying run.
#[test]
fn liveness_report_is_deterministic() {
    let cfg = VoprConfig::liveness(2);
    assert_eq!(
        run_liveness(cfg),
        run_liveness(cfg),
        "same seed ⇒ identical liveness report"
    );
}

/// **Acceptance (seed sweep, faults+crashes firing, zero spurious violations).** The liveness CLI runs
/// the progress watchdog + fault-then-heal recovery probe across a seed range under a recoverable fault
/// window and reports zero violations. This is the empirical proof the real engine keeps making
/// progress and recovers availability under fault injection — no spurious hang, no failure to recover.
/// (A wider 1..=100 sweep was run during development; this committed range stays fast in a debug build.)
#[test]
fn liveness_cli_seed_sweep_reports_zero_violations() {
    let (out, violations) = run_liveness_cli(
        ["--seed", "1", "--seeds", "30"]
            .into_iter()
            .map(String::from),
    );
    assert_eq!(
        violations, 0,
        "the liveness CLI sweep must report zero violations under faults+crashes:\n{out}"
    );
    assert!(
        out.contains("all LIVE + recovered + deterministic"),
        "{out}"
    );
}
