//! Crash-recovery acceptance for the **live-record count** half of `Statistics` (`rmp` #866),
//! driven through `graphus-dst`'s public API.
//!
//! `graphus-storage`'s `tests/count_txn_undo_866.rs` pins the interleavings at the `RecordStore`
//! layer. This file certifies the three things it cannot reach, each of which is a durability
//! question rather than an interleaving question:
//!
//! 1. a **write I/O error injected inside the commit-time catalog checkpoint**, which is the exact
//!    window `rmp` #866 restructured when it moved `commit_prepare`'s `self.active.remove(&txn)`
//!    after `checkpoint_meta` and `commit_at_no_sync`;
//! 2. the **steal** crash flavour, where an open transaction's dirty pages are written home before
//!    the crash so ARIES undo must roll them back against a real page image while the checkpointed
//!    catalog carries only the committed counts; and
//! 3. a **crash between `checkpoint_meta` and the COMMIT harden**, asserted as a winner/loser pair
//!    from one code path so neither half can pass vacuously.
//!
//! Every recovered store is checked against three independent oracles — the eager counters, a live
//! re-scan, and the MVCC-visibility-filtered (`count()`-shaped) scan — plus a hand-computed expected
//! value. See [`graphus_dst::count_txn_undo`] for the full rationale.

use graphus_dst::{
    BystanderEnding, CommitRecordFate, Crash, run_crash_between_checkpoint_and_commit_harden,
    run_io_error_at_catalog_checkpoint, run_stolen_pages_vs_checkpointed_counts,
};

/// The whole matrix: every bystander ending, every crash flavour, every COMMIT-record fate. The
/// counters of every recovered store must equal all three oracles.
#[test]
fn every_count_undo_scenario_recovers_exact_counters() {
    for ending in BystanderEnding::all() {
        let injected = run_io_error_at_catalog_checkpoint(ending);
        assert!(
            injected.holds(),
            "{ending:?} [io-error-in-checkpoint]: rmp #866 invariant violated: {injected:?}"
        );

        for crash in [Crash::NoForce, Crash::Steal] {
            let stolen = run_stolen_pages_vs_checkpointed_counts(ending, crash);
            assert!(
                stolen.holds(),
                "{ending:?}/{crash:?} [stolen-pages]: rmp #866 invariant violated: {stolen:?}"
            );
        }
    }

    for fate in CommitRecordFate::all() {
        for crash in [Crash::NoForce, Crash::Steal] {
            let report = run_crash_between_checkpoint_and_commit_harden(fate, crash);
            assert!(
                report.holds(),
                "{fate:?}/{crash:?} [torn-commit]: rmp #866 invariant violated: {report:?}"
            );
        }
    }
}

/// The counter a `count()` would be served must equal the visibility-filtered scan on **every**
/// recovered store — the storage-level statement of "a `count()`-shaped answer equals the scan".
#[test]
fn the_counter_equals_the_visibility_filtered_scan_after_every_recovery() {
    let mut checked = 0usize;
    for ending in BystanderEnding::all() {
        let r = run_io_error_at_catalog_checkpoint(ending).recovery;
        assert_eq!(
            r.recovered, r.recovered_visible,
            "{ending:?} [io-error-in-checkpoint]: a counter-served count() would not equal the \
             visibility-filtered scan: {r:?}"
        );
        checked += 1;
        for crash in [Crash::NoForce, Crash::Steal] {
            let r = run_stolen_pages_vs_checkpointed_counts(ending, crash).recovery;
            assert_eq!(
                r.recovered, r.recovered_visible,
                "{ending:?}/{crash:?} [stolen-pages]: counter != visibility-filtered scan: {r:?}"
            );
            checked += 1;
        }
    }
    for fate in CommitRecordFate::all() {
        for crash in [Crash::NoForce, Crash::Steal] {
            let r = run_crash_between_checkpoint_and_commit_harden(fate, crash);
            assert_eq!(
                r.recovered, r.recovered_visible,
                "{fate:?}/{crash:?} [torn-commit]: counter != visibility-filtered scan: {r:?}"
            );
            checked += 1;
        }
    }
    // 3 bystander endings x (1 injected-fault run + 2 crash flavours) + 2 COMMIT fates x 2 flavours.
    assert_eq!(
        checked, 13,
        "the scenario matrix shrank without the test noticing"
    );
}

/// Non-vacuity in aggregate, in the spirit of `tests/non_vacuity.rs`: across the whole matrix the
/// injected fault really fires, recovery really undoes losers, undo really writes compensations, a
/// tail really tears, and the `count()` gate really declines. If any of these were zero, "all
/// invariants hold" would be worthless.
#[test]
fn the_count_undo_matrix_is_non_vacuous() {
    let mut faults_fired = 0usize;
    let mut faults_inside_checkpoint = 0usize;
    let mut gate_declined = 0usize;
    let mut losers = 0usize;
    let mut clrs = 0usize;
    let mut torn_tails = 0usize;
    let mut deltas_withdrawn = 0usize;
    let mut strips_with_real_work = 0usize;

    for ending in BystanderEnding::all() {
        let injected = run_io_error_at_catalog_checkpoint(ending);
        if injected.fault_surfaced {
            faults_fired += 1;
        }
        if injected.failed_before_commit_record {
            faults_inside_checkpoint += 1;
        }
        if !injected.counts_match_with_bystander_open {
            gate_declined += 1;
        }
        if injected.counters_after_failed_commit != injected.counters_after_rollback {
            deltas_withdrawn += 1;
        }
        losers += injected.recovery.recovery_losers;
        clrs += injected.recovery.recovery_clrs;

        for crash in [Crash::NoForce, Crash::Steal] {
            let stolen = run_stolen_pages_vs_checkpointed_counts(ending, crash);
            if stolen.live_counters_at_checkpoint != stolen.committed_counters_at_checkpoint {
                strips_with_real_work += 1;
            }
            losers += stolen.recovery.recovery_losers;
            clrs += stolen.recovery.recovery_clrs;
        }
    }

    for fate in CommitRecordFate::all() {
        for crash in [Crash::NoForce, Crash::Steal] {
            let r = run_crash_between_checkpoint_and_commit_harden(fate, crash);
            if r.recovery_tail_truncated {
                torn_tails += 1;
            }
            losers += r.recovery_losers;
            clrs += r.recovery_clrs;
        }
    }

    assert_eq!(
        faults_fired, 3,
        "the armed write I/O error did not fire in every injected run — those runs are vacuous"
    );
    assert_eq!(
        faults_inside_checkpoint, 3,
        "the fault did not land inside `checkpoint_meta` in every injected run (a COMMIT record was \
         appended), so the window under test was never entered"
    );
    assert_eq!(
        deltas_withdrawn, 3,
        "a rollback after the failed commit withdrew nothing — there was no pending delta"
    );
    assert_eq!(
        gate_declined, 3,
        "`counts_match_committed_image` never declined while a writer was open"
    );
    assert_eq!(
        strips_with_real_work, 6,
        "a checkpoint ran with no concurrent pending delta to strip"
    );
    assert_eq!(
        torn_tails, 2,
        "the COMMIT record was never actually torn off the durable tail"
    );
    assert!(
        losers > 0,
        "recovery never rolled a transaction back across the whole matrix — undo is untested"
    );
    assert!(
        clrs > 0,
        "undo never wrote a compensation record — it found nothing to compensate"
    );
}

/// Same input ⇒ identical report, across the whole public API.
#[test]
fn the_count_undo_matrix_is_deterministic() {
    for ending in BystanderEnding::all() {
        assert_eq!(
            run_io_error_at_catalog_checkpoint(ending),
            run_io_error_at_catalog_checkpoint(ending),
            "{ending:?} [io-error-in-checkpoint] is not deterministic"
        );
        for crash in [Crash::NoForce, Crash::Steal] {
            assert_eq!(
                run_stolen_pages_vs_checkpointed_counts(ending, crash),
                run_stolen_pages_vs_checkpointed_counts(ending, crash),
                "{ending:?}/{crash:?} [stolen-pages] is not deterministic"
            );
        }
    }
    for fate in CommitRecordFate::all() {
        for crash in [Crash::NoForce, Crash::Steal] {
            assert_eq!(
                run_crash_between_checkpoint_and_commit_harden(fate, crash),
                run_crash_between_checkpoint_and_commit_harden(fate, crash),
                "{fate:?}/{crash:?} [torn-commit] is not deterministic"
            );
        }
    }
}
