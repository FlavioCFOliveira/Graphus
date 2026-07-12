//! Regression: `rmp` #721 — the DST reproducer for an off-thread reader failing a legitimate read
//! because a concurrent writer grew the store underneath it (the stale `MetaSnapshot` page map vs. the
//! live page cache).
//!
//! Drives [`graphus_dst::reader_store_growth::run_reader_vs_store_growth`] across a seed range and
//! asserts every oracle. See that module for the full root-cause analysis; the two oracles are:
//!
//! 1. **Location** — no read through the pre-growth view may fail (`"{kind} store page N not
//!    allocated"` was the defect, surfacing to clients as `Neo.DatabaseError.General.UnknownError`).
//! 2. **Isolation** — the records the reader can now LOCATE past its snapshot must stay INVISIBLE to
//!    it. Trading the internal error for a snapshot-isolation breach would be strictly worse.
//!
//! Also asserts **determinism** (the same seed replays identically) and **non-vacuity** (the writer
//! genuinely grew the store past the reader's snapshot — otherwise the run would prove nothing).

use graphus_dst::reader_store_growth::run_reader_vs_store_growth;

#[test]
fn a_reader_never_fails_a_read_while_a_writer_grows_the_store() {
    for seed in 0..8u64 {
        let r = run_reader_vs_store_growth(seed);

        // Non-vacuity FIRST: if the writer never grew a store past the reader's snapshot, the reader
        // never had to index past its frozen map and the run would be a green no-op.
        assert!(
            r.pages_grown_after_snapshot > 0,
            "VACUOUS run at seed {seed}: the writer added no store pages after the reader's \
             snapshot, so nothing was proven. {}",
            r.detail()
        );

        // Oracle 1 — the #721 defect itself.
        assert!(
            r.read_failures.is_empty(),
            "seed {seed}: a reader failed a legitimate read while a writer grew the store \
             (`rmp` #721). {}\n  {}",
            r.detail(),
            r.read_failures.join("\n  ")
        );

        // Oracle 2 — the fix must not have bought that by breaking snapshot isolation.
        assert!(
            r.visibility_leaks.is_empty(),
            "seed {seed}: the live page map leaked post-snapshot data into a visible result. {}\n  {}",
            r.detail(),
            r.visibility_leaks.join("\n  ")
        );

        // Committed data must never become unreachable.
        assert!(
            r.lost_survivors.is_empty(),
            "seed {seed}: committed pre-snapshot data became invisible to the reader. {}\n  {}",
            r.detail(),
            r.lost_survivors.join("\n  ")
        );

        assert!(r.ok(), "seed {seed}: {}", r.detail());
    }
}

/// Determinism: the same seed must replay to an identical report (the DST contract).
#[test]
fn the_reproducer_is_deterministic() {
    for seed in [0u64, 7, 4242] {
        assert_eq!(
            run_reader_vs_store_growth(seed),
            run_reader_vs_store_growth(seed),
            "seed {seed} did not replay identically"
        );
    }
}
