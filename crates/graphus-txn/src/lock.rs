//! Write-write conflict handling and the wait-for-graph deadlock detector (`04 §5.7`).
//!
//! MVCC reads never take locks (SSI uses non-blocking SIREAD markers, `04 §5.4`), so the **only**
//! true blocking in the system is **write-write**: two transactions writing the same record. This
//! module owns those write locks and the policy around them:
//!
//! - **First-updater-wins.** The first transaction to write a key holds its write lock; a second
//!   writer of the same key either *waits* for or is *aborted* on the conflict
//!   ([`acquire`](LockTable::acquire) reports which).
//! - **Deadlock detection.** Because write-lock waits can cycle, a **wait-for graph** is maintained
//!   over the waits; a cycle is broken by aborting the **youngest** transaction (the one with the
//!   largest [`TxnId`], i.e. the latest to start) with a retriable error
//!   ([`find_deadlock_victim`](LockTable::find_deadlock_victim)).
//! - **Lock-wait timeout** is the backstop the manager layers on top (it is a policy/clock concern,
//!   not modelled here): if a wait outlives the timeout, the waiter is aborted regardless.
//!
//! This is in-memory single-threaded bookkeeping: it records *who holds* and *who waits for* each
//! key so the manager can decide deterministically. In a multi-threaded promotion the same graph is
//! protected by a latch; the abort-the-youngest rule and the wait-for edges are unchanged.

use std::collections::HashMap;
use std::collections::HashSet;

use graphus_core::TxnId;

use crate::store::Key;

/// The outcome of attempting to acquire a write lock on a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOutcome {
    /// The lock was granted (the key was free, or already held by the requester — re-entrant).
    Granted,
    /// The key is held by `holder`; the requester must wait (a wait-for edge was recorded).
    Wait {
        /// The transaction currently holding the write lock.
        holder: TxnId,
    },
}

/// The write-lock table plus the wait-for graph used for deadlock detection (`04 §5.7`).
#[derive(Debug, Default)]
pub struct LockTable {
    /// `key → holding transaction` (first-updater-wins).
    holders: HashMap<Key, TxnId>,
    /// Keys each transaction holds, so release on commit/abort is O(held).
    held_by: HashMap<TxnId, HashSet<Key>>,
    /// Wait-for edges: `waiter → set of holders it is blocked on`.
    waits_for: HashMap<TxnId, HashSet<TxnId>>,
}

impl LockTable {
    /// An empty lock table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempts to acquire the write lock on `key` for `txn` (first-updater-wins).
    ///
    /// Returns [`LockOutcome::Granted`] if `key` is free or already held by `txn`; otherwise
    /// [`LockOutcome::Wait`] naming the holder, and records the wait-for edge `txn → holder` so the
    /// deadlock detector can see it.
    pub fn acquire(&mut self, txn: TxnId, key: Key) -> LockOutcome {
        match self.holders.get(&key).copied() {
            None => {
                self.holders.insert(key, txn);
                self.held_by.entry(txn).or_default().insert(key);
                LockOutcome::Granted
            }
            Some(holder) if holder == txn => LockOutcome::Granted,
            Some(holder) => {
                self.waits_for.entry(txn).or_default().insert(holder);
                LockOutcome::Wait { holder }
            }
        }
    }

    /// Releases every lock and wait held by `txn` (called on commit or abort). A waiter blocked on
    /// `txn` becomes unblocked and should retry its [`acquire`](Self::acquire).
    pub fn release_all(&mut self, txn: TxnId) {
        if let Some(keys) = self.held_by.remove(&txn) {
            for key in keys {
                if self.holders.get(&key) == Some(&txn) {
                    self.holders.remove(&key);
                }
            }
        }
        self.waits_for.remove(&txn);
        for set in self.waits_for.values_mut() {
            set.remove(&txn);
        }
    }

    /// Finds a transaction to abort to break a wait-for cycle, or `None` if the graph is acyclic.
    ///
    /// On a cycle the **youngest** transaction (largest [`TxnId`]) is chosen, so older transactions
    /// make progress and the same victim is picked deterministically (`04 §5.7`).
    #[must_use]
    pub fn find_deadlock_victim(&self) -> Option<TxnId> {
        // Depth-first cycle detection over the wait-for graph; collect every transaction on any
        // cycle, then pick the youngest.
        let mut on_cycle: HashSet<TxnId> = HashSet::new();
        let mut visiting: HashSet<TxnId> = HashSet::new();
        let mut visited: HashSet<TxnId> = HashSet::new();

        let nodes: Vec<TxnId> = self.waits_for.keys().copied().collect();
        for start in nodes {
            if !visited.contains(&start) {
                let mut stack: Vec<TxnId> = Vec::new();
                self.dfs(
                    start,
                    &mut visiting,
                    &mut visited,
                    &mut stack,
                    &mut on_cycle,
                );
            }
        }
        on_cycle.into_iter().max_by_key(|t| t.0)
    }

    fn dfs(
        &self,
        node: TxnId,
        visiting: &mut HashSet<TxnId>,
        visited: &mut HashSet<TxnId>,
        stack: &mut Vec<TxnId>,
        on_cycle: &mut HashSet<TxnId>,
    ) {
        visiting.insert(node);
        stack.push(node);
        if let Some(targets) = self.waits_for.get(&node) {
            for &next in targets {
                if visiting.contains(&next) {
                    // Found a back-edge: everything from `next` to the top of the stack is a cycle.
                    if let Some(pos) = stack.iter().position(|t| *t == next) {
                        for t in &stack[pos..] {
                            on_cycle.insert(*t);
                        }
                    }
                } else if !visited.contains(&next) {
                    self.dfs(next, visiting, visited, stack, on_cycle);
                }
            }
        }
        stack.pop();
        visiting.remove(&node);
        visited.insert(node);
    }

    /// The current holder of `key`, if any. Test/inspection aid.
    #[must_use]
    pub fn holder_of(&self, key: Key) -> Option<TxnId> {
        self.holders.get(&key).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_updater_wins_second_waits() {
        let mut lt = LockTable::new();
        assert_eq!(lt.acquire(TxnId(1), 100), LockOutcome::Granted);
        assert_eq!(
            lt.acquire(TxnId(2), 100),
            LockOutcome::Wait { holder: TxnId(1) }
        );
        // Re-entrant: the holder re-acquiring its own key is fine.
        assert_eq!(lt.acquire(TxnId(1), 100), LockOutcome::Granted);
    }

    #[test]
    fn release_unblocks_waiters() {
        let mut lt = LockTable::new();
        lt.acquire(TxnId(1), 100);
        assert!(matches!(
            lt.acquire(TxnId(2), 100),
            LockOutcome::Wait { .. }
        ));
        lt.release_all(TxnId(1));
        assert_eq!(lt.holder_of(100), None);
        // Now T2 can take it.
        assert_eq!(lt.acquire(TxnId(2), 100), LockOutcome::Granted);
    }

    #[test]
    fn no_cycle_means_no_victim() {
        let mut lt = LockTable::new();
        lt.acquire(TxnId(1), 100);
        lt.acquire(TxnId(2), 100); // T2 waits for T1; acyclic
        assert_eq!(lt.find_deadlock_victim(), None);
    }

    #[test]
    fn two_party_deadlock_aborts_youngest() {
        let mut lt = LockTable::new();
        // T1 holds A, T2 holds B.
        lt.acquire(TxnId(1), 1);
        lt.acquire(TxnId(2), 2);
        // T1 wants B (waits for T2), T2 wants A (waits for T1) -> cycle.
        assert!(matches!(lt.acquire(TxnId(1), 2), LockOutcome::Wait { .. }));
        assert!(matches!(lt.acquire(TxnId(2), 1), LockOutcome::Wait { .. }));
        assert_eq!(lt.find_deadlock_victim(), Some(TxnId(2))); // youngest
    }

    #[test]
    fn three_party_deadlock_aborts_youngest() {
        let mut lt = LockTable::new();
        lt.acquire(TxnId(1), 1);
        lt.acquire(TxnId(2), 2);
        lt.acquire(TxnId(3), 3);
        // 1 -> 2 -> 3 -> 1
        lt.acquire(TxnId(1), 2);
        lt.acquire(TxnId(2), 3);
        lt.acquire(TxnId(3), 1);
        assert_eq!(lt.find_deadlock_victim(), Some(TxnId(3)));
    }

    #[test]
    fn aborting_victim_breaks_the_cycle() {
        let mut lt = LockTable::new();
        lt.acquire(TxnId(1), 1);
        lt.acquire(TxnId(2), 2);
        lt.acquire(TxnId(1), 2);
        lt.acquire(TxnId(2), 1);
        let victim = lt.find_deadlock_victim().unwrap();
        lt.release_all(victim);
        assert_eq!(lt.find_deadlock_victim(), None);
    }
}
