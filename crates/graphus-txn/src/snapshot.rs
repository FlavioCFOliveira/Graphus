//! Isolation levels, read snapshots, and the registry that resolves a writer's commit status.
//!
//! A [`Snapshot`] is a read timestamp plus the identity of its owning transaction (so a
//! transaction can always see its **own** uncommitted writes, `04 §5.3`). The [`IsolationLevel`]
//! selects whether the manager runs full SSI validation at commit.
//!
//! Resolving a version's visibility (`04 §5.3`) requires knowing, for any [`VersionStamp`], whether
//! the writer is committed (and at which timestamp) or aborted/in-flight. The frozen header stores
//! only the writer's `TxnId` while it is in flight; the mapping `TxnId → outcome` lives in the
//! [`CommitRegistry`], which is the manager's Active/Recent Transaction Table.

use std::collections::HashMap;

use graphus_core::{Timestamp, TxnId};

use crate::oracle::VersionStamp;

/// The isolation level a transaction runs at (`D-isolation-level`).
///
/// Both levels read from a consistent MVCC snapshot (`04 §5.3`); they differ **only** at commit:
/// [`Serializable`](IsolationLevel::Serializable) runs SSI dangerous-structure validation and may
/// abort a pivot, whereas [`Snapshot`](IsolationLevel::Snapshot) does not and therefore permits
/// write-skew (`04 §5.4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsolationLevel {
    /// **Default.** Full Serializable Snapshot Isolation: snapshot reads + SSI commit validation.
    #[default]
    Serializable,
    /// Documented weaker opt-in: plain Snapshot Isolation (no SSI validation). Permits write-skew.
    Snapshot,
}

impl IsolationLevel {
    /// Whether transactions at this level run SSI validation at commit.
    #[must_use]
    pub fn runs_ssi(self) -> bool {
        matches!(self, IsolationLevel::Serializable)
    }
}

/// A read snapshot: the begin timestamp plus the owning transaction's identity.
///
/// Carrying the [`TxnId`] lets visibility honour the "a transaction always sees its own
/// uncommitted writes" rule (`04 §5.3`) without a side lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// The transaction this snapshot belongs to.
    pub owner: TxnId,
    /// The begin timestamp `s`: a version's `xmin` must have committed `≤ s` to be visible.
    pub ts: Timestamp,
}

/// The committed/aborted outcome of a transaction (its Active/Recent Transaction Table entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxnOutcome {
    /// Still running: no commit timestamp yet.
    InFlight,
    /// Committed at the given commit timestamp.
    Committed(Timestamp),
    /// Aborted; its writes are never visible to anyone.
    Aborted,
}

/// Resolves `TxnId → outcome` for in-flight, recently-committed, and aborted writers.
///
/// Visibility (`04 §5.3`) needs this to turn a header word's in-flight `TxnId` into a commit
/// timestamp (or to learn it aborted). Entries are kept until garbage collection proves no live
/// snapshot can still observe the transaction's effect; until then they must be retained so an
/// older reader resolves the writer correctly.
#[derive(Debug, Default, Clone)]
pub struct CommitRegistry {
    outcomes: HashMap<TxnId, TxnOutcome>,
}

impl CommitRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `txn` has started (now [`TxnOutcome::InFlight`]).
    pub fn register_begin(&mut self, txn: TxnId) {
        self.outcomes.insert(txn, TxnOutcome::InFlight);
    }

    /// Records that `txn` committed at `commit_ts`.
    pub fn record_commit(&mut self, txn: TxnId, commit_ts: Timestamp) {
        self.outcomes.insert(txn, TxnOutcome::Committed(commit_ts));
    }

    /// Records that `txn` aborted.
    pub fn record_abort(&mut self, txn: TxnId) {
        self.outcomes.insert(txn, TxnOutcome::Aborted);
    }

    /// Forgets `txn` once GC proves it is no longer observable. After this, the writer must not be
    /// referenced by any live version header.
    pub fn forget(&mut self, txn: TxnId) {
        self.outcomes.remove(&txn);
    }

    /// The number of entries currently in the table (observability: GC-time pruning, `04 §5.5`,
    /// bounds this; see [`prune_settled`](Self::prune_settled)).
    #[must_use]
    pub fn len(&self) -> usize {
        self.outcomes.len()
    }

    /// Whether the table holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.outcomes.is_empty()
    }

    /// The writers currently recorded as [`TxnOutcome::Committed`], in no particular order.
    ///
    /// GC captures this set **after** its header-freeze sweep (`04 §5.5`, `rmp` task #59): the sweep
    /// rewrote every on-disk in-flight stamp of these writers to its committed timestamp, so once
    /// the freeze is durable (the GC transaction commits) every one of them may be
    /// [`forget`](Self::forget)-ten without any version becoming unresolvable.
    #[must_use]
    pub fn committed_writers(&self) -> Vec<TxnId> {
        self.outcomes
            .iter()
            .filter_map(|(txn, outcome)| match outcome {
                TxnOutcome::Committed(_) => Some(*txn),
                TxnOutcome::InFlight | TxnOutcome::Aborted => None,
            })
            .collect()
    }

    /// Prunes entries that GC has proven settled, returning how many were removed (`04 §5.5`,
    /// `rmp` task #59): every [`TxnOutcome::Aborted`] entry (an unknown id already resolves as
    /// aborted, so forgetting one is semantically a no-op) and every [`TxnOutcome::Committed`] entry
    /// whose commit timestamp is at or below `low_water` (`None` = no active transactions, so every
    /// committed entry is settled). [`TxnOutcome::InFlight`] entries are always kept.
    ///
    /// The caller must guarantee that no version header a reader can still consult carries a pruned
    /// writer's in-flight stamp — for the [`VersionedStore`](crate::store::VersionedStore) contract
    /// that holds at commit (`commit_writer` settles every stamp); for a lazy-freezing store it holds
    /// only after a durable GC freeze pass.
    pub fn prune_settled(&mut self, low_water: Option<Timestamp>) -> usize {
        let before = self.outcomes.len();
        self.outcomes.retain(|_, outcome| match outcome {
            TxnOutcome::InFlight => true,
            TxnOutcome::Aborted => false,
            TxnOutcome::Committed(ts) => low_water.is_some_and(|mark| *ts > mark),
        });
        before - self.outcomes.len()
    }

    /// The recorded outcome of `txn`. An unknown id is treated as [`TxnOutcome::Aborted`]: it was
    /// either never committed, or already GC'd because it is provably invisible — both mean its
    /// writes are not visible (`04 §5.3`).
    #[must_use]
    pub fn outcome(&self, txn: TxnId) -> TxnOutcome {
        self.outcomes
            .get(&txn)
            .copied()
            .unwrap_or(TxnOutcome::Aborted)
    }

    /// Resolves a raw header word into the committed timestamp of its writer, if any.
    ///
    /// Returns:
    /// - `Some(ts)` when the word is a committed timestamp, or an in-flight `TxnId` that the
    ///   registry has since recorded as committed at `ts`;
    /// - `None` when the word is the `0` sentinel, or names an in-flight or aborted writer.
    #[must_use]
    pub fn resolve_commit_ts(&self, word: u64) -> Option<Timestamp> {
        match VersionStamp::from_raw(word) {
            VersionStamp::None => None,
            VersionStamp::Committed(ts) => Some(ts),
            VersionStamp::InFlight(txn) => match self.outcome(txn) {
                TxnOutcome::Committed(ts) => Some(ts),
                TxnOutcome::InFlight | TxnOutcome::Aborted => None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_select_ssi_correctly() {
        assert!(IsolationLevel::default().runs_ssi());
        assert!(IsolationLevel::Serializable.runs_ssi());
        assert!(!IsolationLevel::Snapshot.runs_ssi());
    }

    #[test]
    fn unknown_writer_is_treated_as_aborted() {
        let reg = CommitRegistry::new();
        assert_eq!(reg.outcome(TxnId(9)), TxnOutcome::Aborted);
        assert_eq!(
            reg.resolve_commit_ts(VersionStamp::in_flight(TxnId(9))),
            None
        );
    }

    #[test]
    fn resolve_commit_ts_follows_outcome_transitions() {
        let mut reg = CommitRegistry::new();
        let word = VersionStamp::in_flight(TxnId(3));
        reg.register_begin(TxnId(3));
        assert_eq!(reg.resolve_commit_ts(word), None); // in flight
        reg.record_commit(TxnId(3), Timestamp(50));
        assert_eq!(reg.resolve_commit_ts(word), Some(Timestamp(50)));
        reg.record_abort(TxnId(3));
        assert_eq!(reg.resolve_commit_ts(word), None); // aborted
    }

    #[test]
    fn prune_settled_keeps_in_flight_and_unsettled_committed_entries() {
        let mut reg = CommitRegistry::new();
        reg.register_begin(TxnId(1)); // in flight: always kept
        reg.record_commit(TxnId(2), Timestamp(10)); // committed ≤ low_water: pruned
        reg.record_commit(TxnId(3), Timestamp(30)); // committed > low_water: kept
        reg.record_abort(TxnId(4)); // aborted: pruned (unknown resolves as aborted anyway)
        assert_eq!(reg.len(), 4);

        let mut committed = reg.committed_writers();
        committed.sort_unstable();
        assert_eq!(committed, vec![TxnId(2), TxnId(3)]);

        assert_eq!(reg.prune_settled(Some(Timestamp(20))), 2);
        assert_eq!(reg.outcome(TxnId(1)), TxnOutcome::InFlight);
        assert_eq!(reg.outcome(TxnId(2)), TxnOutcome::Aborted); // forgotten = unknown = aborted
        assert_eq!(reg.outcome(TxnId(3)), TxnOutcome::Committed(Timestamp(30)));
        assert_eq!(reg.len(), 2);

        // No active transactions: every committed entry is settled.
        assert_eq!(reg.prune_settled(None), 1);
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
        assert_eq!(reg.outcome(TxnId(1)), TxnOutcome::InFlight);
    }

    #[test]
    fn committed_word_resolves_without_registry_entry() {
        let reg = CommitRegistry::new();
        assert_eq!(
            reg.resolve_commit_ts(VersionStamp::committed(Timestamp(8))),
            Some(Timestamp(8))
        );
    }
}
