//! Targeted torn-WAL-tail fault test (`specification/04-technical-design.md` §11.5: torn write /
//! short write at the log boundary; `04 §4.1`/`§4.8`).
//!
//! A crash can tear the WAL mid-record: the final, un-acknowledged record is partially written. ARIES
//! analysis must stop cleanly at the last *intact* record and never lose an earlier, fully-intact
//! committed record (committed-or-nothing). The harness manufactures this by appending a hardened
//! but uncommitted record to the durable log and truncating inside it, then asserts:
//!
//! * recovery reports a truncated tail (`tail_truncated`), proving the tear was real;
//! * all four invariants still hold (no acknowledged commit lost, no torn-record effect survived).

use graphus_dst::{DetRng, FaultKind, run_with_fault};

/// The torn-WAL-tail fault preserves committed-or-nothing across many seeds, and recovery observes
/// the torn tail.
#[test]
fn torn_wal_tail_preserves_committed_or_nothing() {
    let mut saw_truncation = false;
    let mut saw_commit = false;

    for seed in 1..=150u64 {
        // Advance the RNG the way `run_scenario` would before the workload, then force the fault.
        let mut rng = DetRng::new(seed);
        let report = run_with_fault(seed, FaultKind::TornWalTail, &mut rng);

        assert!(
            report.passed(),
            "seed {seed} [torn-wal-tail] violated an invariant: {:?}\n\
             reproduce by constructing run_with_fault(seed, TornWalTail, ..)",
            report.result
        );

        saw_truncation |= report.tail_truncated;
        saw_commit |= report.ledger.acknowledged_commits() > 0;
    }

    assert!(
        saw_truncation,
        "no seed produced a torn tail — the fault is not actually tearing the log"
    );
    assert!(
        saw_commit,
        "no acknowledged commits — the durability side of the check is vacuous"
    );
}

/// A single deterministic torn-tail run, re-run, must be identical (the fault's tear point is
/// seed-derived).
#[test]
fn torn_wal_tail_is_deterministic() {
    for seed in [3u64, 17, 64, 128] {
        let a = run_with_fault(seed, FaultKind::TornWalTail, &mut DetRng::new(seed));
        let b = run_with_fault(seed, FaultKind::TornWalTail, &mut DetRng::new(seed));
        assert_eq!(a, b, "seed {seed}: torn-wal-tail is not deterministic");
    }
}
