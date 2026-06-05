//! MVCC visibility — the exact `04 §5.3` rules over a record's frozen `xmin`/`xmax` header words.
//!
//! A transaction `T` with snapshot `s` sees a version `v` **iff**:
//!
//! 1. `v.xmin` is committed with `commit_ts(xmin) ≤ s`, **and**
//! 2. `v.xmax` is `0`, **or** `v.xmax` is uncommitted, **or** `v.xmax` aborted, **or**
//!    `commit_ts(xmax) > s`.
//!
//! plus the override: a transaction always sees its **own** uncommitted writes (clause 1 is
//! satisfied when `xmin` is `T`'s own in-flight `TxnId`), and an own-uncommitted `xmax` hides the
//! version from its own author too (a transaction does not see what it has itself deleted).
//!
//! The two header words are raw `u64`s decoded through [`VersionStamp`];
//! the [`CommitRegistry`] resolves in-flight writers. This module is **pure** — no mutation, no
//! locking — which is exactly why reads never block writers (`04 §5.7`, NFR-4).

use crate::oracle::VersionStamp;
use crate::snapshot::{CommitRegistry, Snapshot, TxnOutcome};

/// Whether `T` (via `snapshot`) sees the version whose header carries `xmin` and `xmax`.
///
/// `xmin` is the raw `created_ts` word; `xmax` is the raw `expired_ts` word
/// (`graphus_storage::record::MvccHeader`). `registry` resolves in-flight writers to outcomes.
///
/// Implements `04 §5.3` to the letter; see the module docs for the clause breakdown.
#[must_use]
pub fn is_visible(snapshot: Snapshot, xmin: u64, xmax: u64, registry: &CommitRegistry) -> bool {
    creator_visible(snapshot, xmin, registry) && !expirer_hides(snapshot, xmax, registry)
}

/// Clause 1: is the version's **creator** visible to `snapshot`?
///
/// True when `xmin` is the snapshot owner's own in-flight write, or a committed write at
/// `commit_ts ≤ s`. An in-flight write by *another* transaction, an aborted creator, or the `0`
/// sentinel is not visible.
fn creator_visible(snapshot: Snapshot, xmin: u64, registry: &CommitRegistry) -> bool {
    match VersionStamp::from_raw(xmin) {
        VersionStamp::None => false,
        VersionStamp::Committed(ts) => ts <= snapshot.ts,
        VersionStamp::InFlight(writer) => {
            if writer == snapshot.owner {
                // Own uncommitted write: always visible to its author.
                true
            } else {
                // Another writer that the registry may meanwhile have committed.
                match registry.outcome(writer) {
                    TxnOutcome::Committed(ts) => ts <= snapshot.ts,
                    TxnOutcome::InFlight | TxnOutcome::Aborted => false,
                }
            }
        }
    }
}

/// Clause 2 (negated): does the version's **expirer** hide it from `snapshot`?
///
/// A version is hidden when `xmax` is a committed deletion at `commit_ts ≤ s`, or the snapshot
/// owner's *own* uncommitted deletion. It is **not** hidden when `xmax` is `0`, names another
/// in-flight writer, names an aborted writer, or committed at `commit_ts > s`.
fn expirer_hides(snapshot: Snapshot, xmax: u64, registry: &CommitRegistry) -> bool {
    match VersionStamp::from_raw(xmax) {
        VersionStamp::None => false, // live: not expired
        VersionStamp::Committed(ts) => ts <= snapshot.ts,
        VersionStamp::InFlight(writer) => {
            if writer == snapshot.owner {
                // We deleted it ourselves in this transaction: we no longer see it.
                true
            } else {
                // Another transaction's uncommitted (or since-committed) deletion.
                match registry.outcome(writer) {
                    TxnOutcome::Committed(ts) => ts <= snapshot.ts,
                    // Uncommitted or aborted deletion does not hide the version.
                    TxnOutcome::InFlight | TxnOutcome::Aborted => false,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::VersionStamp;
    use graphus_core::{Timestamp, TxnId};

    fn snap(owner: u64, ts: u64) -> Snapshot {
        Snapshot {
            owner: TxnId(owner),
            ts: Timestamp(ts),
        }
    }

    fn committed(ts: u64) -> u64 {
        VersionStamp::committed(Timestamp(ts))
    }

    fn inflight(txn: u64) -> u64 {
        VersionStamp::in_flight(TxnId(txn))
    }

    // ---- Clause 1: creator visibility ----

    #[test]
    fn creator_committed_before_snapshot_is_visible() {
        let reg = CommitRegistry::new();
        // xmin committed at 5, snapshot at 10, live (xmax = 0) -> visible.
        assert!(is_visible(snap(1, 10), committed(5), 0, &reg));
    }

    #[test]
    fn creator_committed_after_snapshot_is_invisible() {
        let reg = CommitRegistry::new();
        // xmin committed at 15 > snapshot 10 -> invisible (we predate it).
        assert!(!is_visible(snap(1, 10), committed(15), 0, &reg));
    }

    #[test]
    fn creator_committed_exactly_at_snapshot_is_visible() {
        let reg = CommitRegistry::new();
        // `commit_ts(xmin) ≤ s` is inclusive.
        assert!(is_visible(snap(1, 10), committed(10), 0, &reg));
    }

    #[test]
    fn another_in_flight_creator_is_invisible() {
        let mut reg = CommitRegistry::new();
        reg.register_begin(TxnId(2));
        // xmin is txn 2's in-flight write; reader is txn 1 -> invisible.
        assert!(!is_visible(snap(1, 10), inflight(2), 0, &reg));
    }

    #[test]
    fn aborted_creator_is_invisible() {
        let mut reg = CommitRegistry::new();
        reg.record_abort(TxnId(2));
        assert!(!is_visible(snap(1, 10), inflight(2), 0, &reg));
    }

    #[test]
    fn own_uncommitted_write_is_visible() {
        let reg = CommitRegistry::new();
        // xmin is the reader's own in-flight write -> always visible, even with no registry entry.
        assert!(is_visible(snap(7, 10), inflight(7), 0, &reg));
    }

    // ---- Clause 2: expirer (xmax) ----

    #[test]
    fn live_version_xmax_zero_is_visible() {
        let reg = CommitRegistry::new();
        assert!(is_visible(snap(1, 10), committed(5), 0, &reg));
    }

    #[test]
    fn expired_before_snapshot_is_invisible() {
        let reg = CommitRegistry::new();
        // Created at 5, deleted (committed) at 8, snapshot at 10 -> deletion is visible -> hidden.
        assert!(!is_visible(snap(1, 10), committed(5), committed(8), &reg));
    }

    #[test]
    fn expired_after_snapshot_is_still_visible() {
        let reg = CommitRegistry::new();
        // Concurrent xmax committed at 12 > snapshot 10 -> we still see the pre-deletion version.
        assert!(is_visible(snap(1, 10), committed(5), committed(12), &reg));
    }

    #[test]
    fn concurrent_uncommitted_xmax_does_not_hide() {
        let mut reg = CommitRegistry::new();
        reg.register_begin(TxnId(2));
        // Another txn has an uncommitted deletion -> the version is still visible to us.
        assert!(is_visible(snap(1, 10), committed(5), inflight(2), &reg));
    }

    #[test]
    fn aborted_xmax_does_not_hide() {
        let mut reg = CommitRegistry::new();
        reg.record_abort(TxnId(2));
        assert!(is_visible(snap(1, 10), committed(5), inflight(2), &reg));
    }

    #[test]
    fn own_uncommitted_deletion_hides_from_self() {
        let reg = CommitRegistry::new();
        // We created it earlier (committed at 5) and deleted it in this same txn (id 7) -> we no
        // longer see it.
        assert!(!is_visible(snap(7, 10), committed(5), inflight(7), &reg));
    }

    #[test]
    fn own_create_and_own_delete_is_invisible_to_self() {
        let reg = CommitRegistry::new();
        // Created and deleted within the same uncommitted txn -> gone for its author.
        assert!(!is_visible(snap(7, 10), inflight(7), inflight(7), &reg));
    }

    #[test]
    fn another_committed_xmax_resolved_via_registry() {
        let mut reg = CommitRegistry::new();
        // The header still holds the writer's TxnId, but it has since committed at 8.
        reg.record_commit(TxnId(2), Timestamp(8));
        assert!(!is_visible(snap(1, 10), committed(5), inflight(2), &reg));
        // ... and if that commit were after our snapshot we would still see the version.
        let mut reg2 = CommitRegistry::new();
        reg2.record_commit(TxnId(2), Timestamp(12));
        assert!(is_visible(snap(1, 10), committed(5), inflight(2), &reg2));
    }
}
