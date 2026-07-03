//! Large-seed sweep for **free-list double-allocation after a live rollback** (`rmp` #578).
//!
//! Each seed drives, through the real storage/WAL/txn engine, the three-transaction interleaving the
//! storage audit root-caused: GC frees a physical id `P`; an open transaction `A` re-allocates `P`; a
//! different transaction `B` live-rolls-back (re-listing `P` from the durable catalog); a later
//! transaction `C` would then re-pop `P`, self-cycling the property/incidence chain and losing the
//! committed data threaded below it. See [`graphus_dst::freelist_reuse`] for the scenario shape and
//! why the generic harness cannot reach it (it never statement-interleaves transactions).
//!
//! The sweep is large so the family of variants (both stores, 0..3 survivors, both crash kinds) is
//! covered, and it asserts **non-vacuity**: every seed reaches the precondition (A re-allocates the
//! freed slot), the storage checker finds no `FreeListFault::StillInUse` while A holds it, and the
//! double-allocation is averted. Pre-fix (with the `RecordStore::rollback` free-list restore reverted)
//! every seed instead surfaces `StillInUse` and a `"malformed (cycle?)"` — the teeth are proven by
//! reverting the fix.

use graphus_dst::{
    FreelistReuseTarget, run_freelist_reuse_after_rollback, run_freelist_reuse_crash,
};

/// The number of seeds swept. Named so the non-vacuity assertions can reference it.
const SEEDS: u64 = 5_000;

#[test]
fn freelist_reuse_after_rollback_holds_across_five_thousand_seeds() {
    let mut prop_hits = 0u64;
    let mut rel_hits = 0u64;
    let mut precondition_hits = 0u64;

    for seed in 1..=SEEDS {
        let report = run_freelist_reuse_after_rollback(seed);

        // Determinism: re-running the same seed must reproduce the identical report.
        let again = run_freelist_reuse_after_rollback(seed);
        assert_eq!(report, again, "seed {seed} is not deterministic");

        assert!(
            report.reached_precondition,
            "seed {seed}: A did not re-allocate the GC-freed slot P (vacuous): reused={} \
             c_allocated={}\nreproduce with: \
             graphus_dst::run_freelist_reuse_after_rollback({seed})",
            report.reused_id, report.c_allocated_id
        );
        assert!(
            report.freelist_fault.is_none(),
            "seed {seed}: the storage consistency checker found a free-list fault while A still \
             held the reused slot: {:?}\nreproduce with: \
             graphus_dst::run_freelist_reuse_after_rollback({seed})",
            report.freelist_fault
        );
        assert!(
            report.double_alloc_averted,
            "seed {seed}: C re-popped P (double-allocation not averted): P={}\nreproduce with: \
             graphus_dst::run_freelist_reuse_after_rollback({seed})",
            report.reused_id
        );
        assert!(
            report.passed(),
            "seed {seed} violated an invariant after free-list reuse (target={:?}): {:?}\n\
             reproduce with: graphus_dst::run_freelist_reuse_after_rollback({seed})",
            report.target,
            report.result
        );

        precondition_hits += 1;
        match report.target {
            FreelistReuseTarget::Prop => prop_hits += 1,
            FreelistReuseTarget::Rel => rel_hits += 1,
        }
    }

    // Non-vacuity: every seed reached the precondition, and BOTH stores were exercised (the defect is
    // store-generic, so a sweep that only hit one store would leave the other unproven).
    assert_eq!(
        precondition_hits, SEEDS,
        "every seed must reach the reproduction's precondition"
    );
    assert!(
        prop_hits > 0,
        "the sweep never exercised the property store (coverage gap)"
    );
    assert!(
        rel_hits > 0,
        "the sweep never exercised the relationship store (coverage gap)"
    );
}

#[test]
fn freelist_reuse_crash_recovery_holds_across_two_thousand_seeds() {
    // The `rmp` #578 fix is live-rollback-only; crash recovery rebuilds the free list from the durable
    // catalog, so it must stay byte-identical and continue to reconstruct the committed graph exactly.
    const CRASH_SEEDS: u64 = 2_000;
    let mut steal_hits = 0u64;
    let mut no_force_hits = 0u64;

    for seed in 1..=CRASH_SEEDS {
        let report = run_freelist_reuse_crash(seed);
        let again = run_freelist_reuse_crash(seed);
        assert_eq!(
            report, again,
            "seed {seed}: crash recovery is not deterministic"
        );

        assert!(
            report.reached_precondition,
            "seed {seed}: reproduction did not reach its precondition (vacuous)\nreproduce with: \
             graphus_dst::run_freelist_reuse_crash({seed})"
        );
        assert!(
            report.passed(),
            "seed {seed}: recovered graph did not equal the model (target={:?}, steal={}): {:?}\n\
             reproduce with: graphus_dst::run_freelist_reuse_crash({seed})",
            report.target,
            report.steal,
            report.result
        );

        if report.steal {
            steal_hits += 1;
        } else {
            no_force_hits += 1;
        }
    }

    // Non-vacuity: both crash kinds were exercised.
    assert!(steal_hits > 0, "the sweep never exercised a steal crash");
    assert!(
        no_force_hits > 0,
        "the sweep never exercised a no-force crash"
    );
}
