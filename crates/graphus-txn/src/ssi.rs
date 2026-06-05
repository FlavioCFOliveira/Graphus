//! Serializable Snapshot Isolation conflict tracking (`04 §5.4`).
//!
//! Pure Snapshot Isolation permits **write-skew** and other serialization anomalies. SSI
//! (Cahill/Fekete; PostgreSQL SSI — `04 §13` sources) upgrades SI to full serializability without
//! adding read locks, by detecting the **rw-antidependency** (read-write) edge:
//!
//! > `T1 --rw--> T2` when `T1` reads a version that `T2` then overwrites.
//!
//! **Cahill's theorem.** Every non-serializable execution contains a transaction with **both** an
//! inbound and an outbound rw-antidependency — a *dangerous structure* whose middle transaction is
//! the **pivot**. Aborting one transaction on every such structure makes all executions
//! serializable.
//!
//! ## What this module tracks
//!
//! - **SIREAD markers** (`record_read`): the non-blocking read set. A read records `(reader, key)`;
//!   it never blocks a writer (`04 §5.7`, NFR-4).
//! - **rw-antidependency edges** (`record_write`): when a transaction writes a `key` that another
//!   *concurrent* transaction has SIREAD-marked, an edge `reader --rw--> writer` is registered.
//! - **per-transaction conflict flags**: following PostgreSQL, each transaction carries
//!   `in_conflict` (has an inbound rw-edge) and `out_conflict` (has an outbound rw-edge); it is a
//!   pivot iff both are set.
//!
//! ## Pivot abort + safe retry (`04 §5.4`)
//!
//! At a transaction's commit, [`SsiTracker::detect_pivot_abort`] checks for a dangerous structure
//! `Tin --rw--> Tpivot --rw--> Tout` where the committing transaction participates, and where the
//! outbound edge's target `Tout` *committed first or is still concurrent* (Cahill's precise
//! condition that the edges can close a cycle). When found it returns the [`TxnId`] to abort.
//!
//! **Safe-retry policy (no mutual-abort livelock).** We abort the **pivot** (the middle of the
//! structure) rather than an arbitrary participant, and only when its outbound partner has already
//! committed *or* will be checked itself. Because an already-committed transaction can never be
//! chosen, every dangerous structure has at least one member that survives — at least one
//! transaction in any unsafe set commits. This is the PostgreSQL rule that prevents two
//! transactions from aborting each other forever.
//!
//! ## Read-only optimization (`04 §5.4`)
//!
//! A read-only transaction has no outbound rw-edge it can *create* by writing, so it can never be
//! the pivot of a structure that its own commit closes; [`detect_pivot_abort`](SsiTracker::detect_pivot_abort)
//! exempts a committing transaction that performed no writes, which matters under read-heavy graph
//! workloads.

use std::collections::{HashMap, HashSet};

use graphus_core::{Timestamp, TxnId};

use crate::store::Key;

/// Per-transaction SSI bookkeeping (its node in the conflict graph).
#[derive(Debug, Default)]
struct TxnConflict {
    /// Keys this transaction SIREAD-marked (its read set).
    reads: HashSet<Key>,
    /// Keys this transaction wrote (its write set).
    writes: HashSet<Key>,
    /// Has an **inbound** rw-edge `X --rw--> self` (someone read what self wrote).
    in_conflict: bool,
    /// Has an **outbound** rw-edge `self --rw--> X` (self read what someone else wrote).
    out_conflict: bool,
    /// Transactions this one has an outbound rw-edge to (`self --rw--> target`).
    out_edges: HashSet<TxnId>,
    /// Commit timestamp once committed (`None` while in flight).
    commit_ts: Option<Timestamp>,
    /// Begin timestamp (snapshot), to decide concurrency.
    begin_ts: Timestamp,
}

/// The SSI dangerous-structure tracker over all in-flight and recently-committed transactions.
#[derive(Debug, Default)]
pub struct SsiTracker {
    txns: HashMap<TxnId, TxnConflict>,
    /// For each key, the set of transactions that currently hold a SIREAD marker on it. A reverse
    /// index so a write can find concurrent readers in O(readers-of-key).
    readers_of: HashMap<Key, HashSet<TxnId>>,
}

impl SsiTracker {
    /// An empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers transaction `txn` (begun at `begin_ts`) so its conflicts can be tracked.
    pub fn register(&mut self, txn: TxnId, begin_ts: Timestamp) {
        self.txns.entry(txn).or_insert_with(|| TxnConflict {
            begin_ts,
            ..TxnConflict::default()
        });
    }

    /// Records a non-blocking SIREAD marker: `reader` read `key` (`04 §5.4`).
    ///
    /// If a *concurrent* transaction has already written `key`, this read closes an
    /// rw-antidependency `reader --rw--> writer` immediately (the read saw a stale version the
    /// writer superseded).
    pub fn record_read(&mut self, reader: TxnId, key: Key) {
        if let Some(t) = self.txns.get_mut(&reader) {
            t.reads.insert(key);
        }
        self.readers_of.entry(key).or_default().insert(reader);

        // If a concurrent writer already wrote this key, the reader has an outbound rw-edge to it.
        let concurrent_writers: Vec<TxnId> = self
            .txns
            .iter()
            .filter(|(id, t)| {
                **id != reader && t.writes.contains(&key) && self.are_concurrent(reader, **id)
            })
            .map(|(id, _)| *id)
            .collect();
        for w in concurrent_writers {
            self.add_edge(reader, w);
        }
    }

    /// Records that `writer` wrote `key`. Any *concurrent* transaction that SIREAD-marked `key`
    /// gains an outbound rw-edge `reader --rw--> writer` (`04 §5.4`).
    pub fn record_write(&mut self, writer: TxnId, key: Key) {
        if let Some(t) = self.txns.get_mut(&writer) {
            t.writes.insert(key);
        }
        let readers: Vec<TxnId> = self
            .readers_of
            .get(&key)
            .into_iter()
            .flatten()
            .copied()
            .filter(|r| *r != writer && self.are_concurrent(*r, writer))
            .collect();
        for r in readers {
            self.add_edge(r, writer);
        }
    }

    /// Whether `a` and `b` ran concurrently: neither had committed before the other began. Two
    /// in-flight transactions are always concurrent; a committed transaction is concurrent with `x`
    /// iff it committed after `x` began.
    fn are_concurrent(&self, a: TxnId, b: TxnId) -> bool {
        let (Some(ta), Some(tb)) = (self.txns.get(&a), self.txns.get(&b)) else {
            return false;
        };
        let a_before_b = ta.commit_ts.is_some_and(|c| c <= tb.begin_ts);
        let b_before_a = tb.commit_ts.is_some_and(|c| c <= ta.begin_ts);
        !a_before_b && !b_before_a
    }

    /// Adds the rw-antidependency edge `from --rw--> to` and updates the conflict flags.
    fn add_edge(&mut self, from: TxnId, to: TxnId) {
        if from == to {
            return;
        }
        if let Some(t) = self.txns.get_mut(&from) {
            t.out_conflict = true;
            t.out_edges.insert(to);
        }
        if let Some(t) = self.txns.get_mut(&to) {
            t.in_conflict = true;
        }
    }

    /// Decides whether committing `txn` must abort to break a dangerous structure (`04 §5.4`).
    ///
    /// Returns `Some(victim)` — the [`TxnId`] to abort with a serialization failure — when a
    /// dangerous structure in which `txn` participates can close a cycle, and `None` when it is safe
    /// to commit.
    ///
    /// Implements the pivot rule and the read-only optimization; see the module docs for the
    /// safe-retry guarantee.
    #[must_use]
    pub fn detect_pivot_abort(&self, txn: TxnId) -> Option<TxnId> {
        let t = self.txns.get(&txn)?;

        // Read-only optimization: a transaction that wrote nothing cannot be the pivot of a
        // structure its own commit closes (it has no outbound edge it created by writing).
        if t.writes.is_empty() && !t.out_conflict {
            return None;
        }

        // Case A: the committing transaction is itself the pivot (in + out conflict). Cahill's
        // condition: its outbound partner committed first or is concurrent (so the cycle can close).
        if t.in_conflict && t.out_conflict {
            let closes = t.out_edges.iter().any(|out| {
                self.txns.get(out).is_some_and(|o| {
                    // Outbound partner committed before us, or is still concurrent (in flight).
                    o.commit_ts.is_some() || self.are_concurrent(txn, *out)
                })
            });
            if closes {
                // Abort the pivot (self). An already-committed outbound partner can never be the
                // victim, so at least one member of every structure survives (safe retry).
                return Some(txn);
            }
        }

        // Case B: the committing transaction `Tout` is the *outbound* target of a pivot
        // `Tin --rw--> Tpivot --rw--> Tout(=txn)`. We commit `Tout`; the pivot is the still-running
        // (or to-be-checked) middle transaction, which is the safe victim because aborting the
        // pivot — not the now-committing endpoint — guarantees forward progress.
        for (&pid, p) in &self.txns {
            if pid == txn {
                continue;
            }
            if p.in_conflict
                && p.out_conflict
                && p.out_edges.contains(&txn)
                && p.commit_ts.is_none()
            {
                return Some(pid);
            }
        }

        None
    }

    /// Marks `txn` committed at `commit_ts` (kept for conflict resolution until GC).
    pub fn record_commit(&mut self, txn: TxnId, commit_ts: Timestamp) {
        if let Some(t) = self.txns.get_mut(&txn) {
            t.commit_ts = Some(commit_ts);
        }
    }

    /// Forgets `txn` entirely (aborted, or GC'd after no live snapshot can observe it).
    pub fn forget(&mut self, txn: TxnId) {
        if let Some(t) = self.txns.remove(&txn) {
            for key in t.reads {
                if let Some(set) = self.readers_of.get_mut(&key) {
                    set.remove(&txn);
                    if set.is_empty() {
                        self.readers_of.remove(&key);
                    }
                }
            }
        }
    }

    /// Whether `txn` currently has both an inbound and an outbound rw-edge (is a pivot). Test aid.
    #[must_use]
    pub fn is_pivot(&self, txn: TxnId) -> bool {
        self.txns
            .get(&txn)
            .is_some_and(|t| t.in_conflict && t.out_conflict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(n: u64) -> Timestamp {
        Timestamp(n)
    }

    #[test]
    fn no_conflict_no_abort() {
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        s.record_read(TxnId(1), 10);
        s.record_write(TxnId(2), 20); // disjoint key
        assert_eq!(s.detect_pivot_abort(TxnId(1)), None);
        assert_eq!(s.detect_pivot_abort(TxnId(2)), None);
    }

    #[test]
    fn write_skew_forms_a_pivot_and_aborts() {
        // Classic write-skew: T1 reads x writes y; T2 reads y writes x; concurrent.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        s.record_read(TxnId(1), 100); // x
        s.record_read(TxnId(2), 200); // y
        s.record_write(TxnId(1), 200); // T1 writes y -> T2 --rw--> T1
        s.record_write(TxnId(2), 100); // T2 writes x -> T1 --rw--> T2
        // Both are now pivots (in + out conflict).
        assert!(s.is_pivot(TxnId(1)));
        assert!(s.is_pivot(TxnId(2)));
        // First committer aborts itself (its outbound partner is concurrent -> cycle can close).
        let victim = s.detect_pivot_abort(TxnId(1));
        assert_eq!(victim, Some(TxnId(1)));
    }

    #[test]
    fn after_first_commits_second_commits_safely() {
        // Safe-retry: once one of the pair has committed, the structure that the *second* commit
        // would close must abort the (still-running) pivot, never the already-committed one.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        s.record_read(TxnId(1), 100);
        s.record_read(TxnId(2), 200);
        s.record_write(TxnId(1), 200);
        s.record_write(TxnId(2), 100);
        // T1 commits (it was the pivot and would normally abort, but say the manager committed it
        // because it was alone first — we model: T1 commits, then T2 tries).
        s.record_commit(TxnId(1), ts(10));
        let victim = s.detect_pivot_abort(TxnId(2));
        // T2 is itself a pivot; its outbound partner T1 already committed -> T2 aborts itself.
        assert_eq!(victim, Some(TxnId(2)));
        // The committed T1 is never selected.
        assert_ne!(victim, Some(TxnId(1)));
    }

    #[test]
    fn read_only_transaction_never_aborts_itself() {
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1)); // read-only
        s.register(TxnId(2), ts(1)); // writer
        s.record_read(TxnId(1), 100);
        s.record_write(TxnId(2), 100); // T1 --rw--> T2
        // T1 wrote nothing -> exempt.
        assert_eq!(s.detect_pivot_abort(TxnId(1)), None);
    }

    #[test]
    fn forget_clears_read_markers() {
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.record_read(TxnId(1), 100);
        s.forget(TxnId(1));
        // A later writer of key 100 finds no concurrent reader.
        s.register(TxnId(2), ts(2));
        s.record_write(TxnId(2), 100);
        assert_eq!(s.detect_pivot_abort(TxnId(2)), None);
    }

    #[test]
    fn non_concurrent_reader_creates_no_edge() {
        // A reader whose snapshot is after the writer committed is not concurrent -> no rw-edge.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.record_write(TxnId(1), 100);
        s.record_commit(TxnId(1), ts(5));
        s.register(TxnId(2), ts(10)); // begins after T1 committed
        s.record_read(TxnId(2), 100);
        assert!(!s.is_pivot(TxnId(2)));
        assert_eq!(s.detect_pivot_abort(TxnId(2)), None);
    }
}
