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

// FxHashMap/FxHashSet: all maps and sets here are keyed by internal Key/TxnId (u64, never
// attacker-controlled) and never iterated in an order-observable way (the deadlock victim is chosen
// by `max_by_key`, not iteration order), so the faster non-cryptographic hash is safe.
use rustc_hash::FxHashMap as HashMap;
use rustc_hash::FxHashSet as HashSet;

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

    /// Drops every *pending wait-for edge* of `txn` (its outgoing `waiter → holder` edges) **without**
    /// releasing any write lock `txn` legitimately holds.
    ///
    /// This is the surgical counterpart to [`release_all`](Self::release_all) for the case where a
    /// write *wait* fails fast (write-write conflict, retriable) but the transaction **stays active**
    /// and must keep the locks it already holds. [`acquire`](Self::acquire) records the wait-for edge
    /// `waiter → holder` *before* the manager decides to fail the wait; if that edge is left behind, it
    /// becomes **stale** — the transaction is no longer waiting on anyone, yet the graph still says it
    /// is. A later legitimate wait could then close a *phantom* cycle through the stale edge and abort
    /// an innocent transaction (`rmp` #387).
    ///
    /// Removing only the *outgoing* edges of `txn` is exactly right: `txn` is the waiter on the failed
    /// acquire, so the spurious edges are the ones it authored (`waits_for[txn]`). Its incoming edges
    /// (other transactions waiting on the locks `txn` still holds) and the lock holdings themselves are
    /// **preserved**, because they remain true.
    ///
    /// Idempotent: clearing the wait edges of a transaction that has none is a no-op.
    pub fn clear_waits(&mut self, txn: TxnId) {
        self.waits_for.remove(&txn);
    }

    /// Finds the deadlock victim for the wait-for edge `waiter → holder` that [`acquire`](Self::acquire)
    /// **just** recorded, or `None` if that edge did not close a cycle.
    ///
    /// This is the hot-path entry the manager uses on every write-wait. It is an `O(cycle length)`
    /// **edge-rooted** search rather than the `O(V + E)` full-graph sweep of
    /// [`find_deadlock_victim`](Self::find_deadlock_victim), exploiting an invariant the manager
    /// maintains: **the wait-for graph is acyclic immediately before each `acquire`** (any earlier
    /// cycle was already detected and broken by aborting its victim, whose
    /// [`release_all`](Self::release_all) removed its edges). Therefore a *new* cycle can only be the
    /// one created by the just-added edge `waiter → holder`, and every such cycle must pass *through*
    /// that edge — i.e. it corresponds to a path `holder ⇝ waiter` in the pre-existing (acyclic)
    /// graph. We root the search at `holder`, collect every node that lies on some `holder ⇝ waiter`
    /// path (those, plus `waiter`, are exactly the nodes the full sweep would mark on a cycle), and
    /// pick the **youngest** (largest [`TxnId`]) — byte-for-byte the same victim the full sweep
    /// selects.
    ///
    /// In debug builds a `debug_assert!` cross-checks this narrow result against the authoritative
    /// full sweep, so the optimization can never silently diverge.
    #[must_use]
    pub fn find_deadlock_victim_for(&self, waiter: TxnId, holder: TxnId) -> Option<TxnId> {
        let victim = self.youngest_on_cycle_through(waiter, holder);

        // The narrow edge-rooted search must agree with the authoritative full-graph sweep on the
        // exact victim. The invariant that licenses the narrow search (acyclic-before-this-edge) is
        // the manager's responsibility; this assertion is the guard that it always holds in practice.
        debug_assert_eq!(
            victim,
            self.find_deadlock_victim(),
            "edge-rooted deadlock search disagreed with the full sweep for edge {waiter:?} -> \
             {holder:?}; the acyclic-before-acquire invariant was violated"
        );

        victim
    }

    /// Edge-rooted cycle search for the just-added edge `waiter → holder`.
    ///
    /// Returns the youngest [`TxnId`] on a cycle through that edge, or `None` if none closed. A cycle
    /// through `waiter → holder` is exactly a path `holder ⇝ waiter`; the nodes on *any* such path
    /// (together with `waiter`) are the cycle nodes. We find them in two cheap passes over the part
    /// of the graph reachable from `holder`: an iterative DFS from `holder` that records, for each
    /// visited node, whether it can reach `waiter` (`can_reach`). Every node with `can_reach == true`
    /// lies on a `holder ⇝ waiter` path; `waiter` itself closes the cycle. The youngest of that set
    /// is the victim. Because the pre-existing graph is acyclic this DFS visits each reachable node
    /// once (`O(cycle/reachable subgraph)`), and it is iterative so a deep chain cannot overflow the
    /// stack (SEC-199 / CWE-674).
    fn youngest_on_cycle_through(&self, waiter: TxnId, holder: TxnId) -> Option<TxnId> {
        // Fast path: the holder is the waiter (a self-edge would be a 1-cycle). `acquire` never
        // records a self wait (re-entrant acquisition returns `Granted`), but guard anyway.
        if holder == waiter {
            return Some(waiter);
        }

        // Post-order iterative DFS from `holder`, computing `can_reach[node] = node can reach waiter`.
        // A node can reach `waiter` iff it *is* a direct predecessor of `waiter` (has the edge
        // `node -> waiter`) or some neighbour can reach `waiter`.
        let mut can_reach: HashSet<TxnId> = HashSet::default();
        let mut visited: HashSet<TxnId> = HashSet::default();

        struct Frame {
            node: TxnId,
            targets: Vec<TxnId>,
            next: usize,
            reaches: bool,
        }

        let neighbours = |n: TxnId| -> Vec<TxnId> {
            self.waits_for
                .get(&n)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default()
        };

        let mut stack: Vec<Frame> = Vec::new();
        visited.insert(holder);
        stack.push(Frame {
            node: holder,
            targets: neighbours(holder),
            next: 0,
            reaches: false,
        });

        while let Some(frame) = stack.last_mut() {
            if frame.next < frame.targets.len() {
                let next = frame.targets[frame.next];
                frame.next += 1;
                if next == waiter {
                    // Direct edge `node -> waiter`: this node reaches `waiter`.
                    frame.reaches = true;
                } else if can_reach.contains(&next) {
                    // A previously-finished node already known to reach `waiter`.
                    frame.reaches = true;
                } else if visited.insert(next) {
                    // Descend into an unvisited node. (The pre-existing graph is acyclic, so `next`
                    // cannot already be on the current path — no back-edge handling needed.)
                    let targets = neighbours(next);
                    stack.push(Frame {
                        node: next,
                        targets,
                        next: 0,
                        reaches: false,
                    });
                }
                // else: `next` was visited and does NOT reach `waiter` — contributes nothing.
            } else {
                // Finished this node. If it reaches `waiter`, record it and propagate to the parent.
                let Frame { node, reaches, .. } = *frame;
                stack.pop();
                if reaches {
                    can_reach.insert(node);
                    if let Some(parent) = stack.last_mut() {
                        parent.reaches = true;
                    }
                }
            }
        }

        // No cycle: `holder` cannot reach `waiter`.
        if !can_reach.contains(&holder) {
            return None;
        }

        // The cycle nodes are `waiter` plus every node that can reach `waiter` (all of which are, by
        // construction, reachable from `holder`). Pick the youngest.
        can_reach
            .into_iter()
            .chain(std::iter::once(waiter))
            .max_by_key(|t| t.0)
    }

    /// Finds a transaction to abort to break a wait-for cycle, or `None` if the graph is acyclic.
    ///
    /// On a cycle the **youngest** transaction (largest [`TxnId`]) is chosen, so older transactions
    /// make progress and the same victim is picked deterministically (`04 §5.7`).
    ///
    /// This is the authoritative full-graph `O(V + E)` sweep. The manager uses the cheaper
    /// [`find_deadlock_victim_for`](Self::find_deadlock_victim_for) on its hot path; this form
    /// remains the debug-assert oracle and is convenient for tests that inspect a fully-built graph.
    #[must_use]
    pub fn find_deadlock_victim(&self) -> Option<TxnId> {
        // SEC-199 (CWE-674): cycle detection over the wait-for graph is **iterative** — an explicit
        // work stack rather than recursion — so an adversarially long wait-for chain
        // (T1 -> T2 -> ... -> Tn) cannot exhaust the call stack and crash the process. It collects
        // every transaction on any cycle, then picks the youngest (largest `TxnId`) as the victim,
        // exactly as the previous recursive form did.
        let mut on_cycle: HashSet<TxnId> = HashSet::default();
        let mut visited: HashSet<TxnId> = HashSet::default();

        let roots: Vec<TxnId> = self.waits_for.keys().copied().collect();
        for root in roots {
            if visited.contains(&root) {
                continue;
            }
            self.collect_cycles_from(root, &mut visited, &mut on_cycle);
        }
        on_cycle.into_iter().max_by_key(|t| t.0)
    }

    /// Iterative DFS from `root` over the wait-for graph, recording every node found on a cycle.
    ///
    /// Maintains an explicit traversal `path` (the current DFS stack of nodes) and a per-node child
    /// iterator cursor, emulating the recursion without using the call stack. A back-edge to a node
    /// already on `path` marks that suffix of `path` as a cycle. `visited` is shared across roots so
    /// the whole graph is explored in `O(V + E)` total.
    fn collect_cycles_from(
        &self,
        root: TxnId,
        visited: &mut HashSet<TxnId>,
        on_cycle: &mut HashSet<TxnId>,
    ) {
        // Each frame: the node and its outgoing neighbours captured as a Vec we index into.
        struct Frame {
            node: TxnId,
            targets: Vec<TxnId>,
            next: usize,
        }
        // `on_path` mirrors the frames for O(1) back-edge membership tests.
        let mut on_path: HashSet<TxnId> = HashSet::default();
        let mut path: Vec<TxnId> = Vec::new();
        let mut stack: Vec<Frame> = Vec::new();

        let neighbours = |n: TxnId| -> Vec<TxnId> {
            self.waits_for
                .get(&n)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default()
        };

        visited.insert(root);
        on_path.insert(root);
        path.push(root);
        stack.push(Frame {
            node: root,
            targets: neighbours(root),
            next: 0,
        });

        while let Some(frame) = stack.last_mut() {
            if frame.next < frame.targets.len() {
                let next = frame.targets[frame.next];
                frame.next += 1;
                if on_path.contains(&next) {
                    // Back-edge: everything from `next` to the top of `path` is on a cycle.
                    if let Some(pos) = path.iter().position(|t| *t == next) {
                        for t in &path[pos..] {
                            on_cycle.insert(*t);
                        }
                    }
                } else if !visited.contains(&next) {
                    visited.insert(next);
                    on_path.insert(next);
                    path.push(next);
                    let targets = neighbours(next);
                    stack.push(Frame {
                        node: next,
                        targets,
                        next: 0,
                    });
                }
            } else {
                // Done with this node; pop it off both the path and the work stack.
                on_path.remove(&frame.node);
                path.pop();
                stack.pop();
            }
        }
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

    // ---- edge-rooted detector: must agree with the full sweep on the exact victim ----

    /// The edge-rooted search returns `None` when the just-added edge does not close a cycle.
    #[test]
    fn edge_rooted_no_cycle() {
        let mut lt = LockTable::new();
        lt.acquire(TxnId(1), 100);
        // T2 waits for T1 (edge 2 -> 1); acyclic.
        assert!(matches!(
            lt.acquire(TxnId(2), 100),
            LockOutcome::Wait { .. }
        ));
        assert_eq!(lt.find_deadlock_victim_for(TxnId(2), TxnId(1)), None);
        assert_eq!(lt.find_deadlock_victim(), None);
    }

    /// Two-party cycle: edge-rooted picks the youngest, same as the full sweep.
    #[test]
    fn edge_rooted_two_party_matches_full_sweep() {
        let mut lt = LockTable::new();
        lt.acquire(TxnId(1), 1);
        lt.acquire(TxnId(2), 2);
        // T1 waits for T2 (edge 1 -> 2); still acyclic.
        assert!(matches!(lt.acquire(TxnId(1), 2), LockOutcome::Wait { .. }));
        assert_eq!(lt.find_deadlock_victim_for(TxnId(1), TxnId(2)), None);
        // T2 waits for T1 (edge 2 -> 1): closes the cycle.
        assert!(matches!(lt.acquire(TxnId(2), 1), LockOutcome::Wait { .. }));
        assert_eq!(
            lt.find_deadlock_victim_for(TxnId(2), TxnId(1)),
            Some(TxnId(2))
        );
        assert_eq!(lt.find_deadlock_victim(), Some(TxnId(2)));
    }

    /// Three-party cycle 1 -> 2 -> 3 -> 1 closed by the last edge: youngest is T3.
    #[test]
    fn edge_rooted_three_party_matches_full_sweep() {
        let mut lt = LockTable::new();
        lt.acquire(TxnId(1), 1);
        lt.acquire(TxnId(2), 2);
        lt.acquire(TxnId(3), 3);
        lt.acquire(TxnId(1), 2); // 1 -> 2
        lt.acquire(TxnId(2), 3); // 2 -> 3
        lt.acquire(TxnId(3), 1); // 3 -> 1 closes the cycle; edge is 3 -> 1
        assert_eq!(
            lt.find_deadlock_victim_for(TxnId(3), TxnId(1)),
            Some(TxnId(3))
        );
        assert_eq!(lt.find_deadlock_victim(), Some(TxnId(3)));
    }

    /// **Multiple cycles sharing the new edge.** Two disjoint `holder ⇝ waiter` paths both close on
    /// the same new edge `waiter -> holder`; the youngest across *both* paths must be the victim, and
    /// the edge-rooted search must agree with the full sweep. Here T1 is the waiter, T2 the holder;
    /// paths T2 -> T5 -> T1 and T2 -> T3 -> T1 both reach T1. Youngest overall is T5.
    #[test]
    fn edge_rooted_multiple_cycles_through_new_edge() {
        let mut lt = LockTable::new();
        for (t, k) in [(1u64, 1u64), (2, 2), (3, 3), (5, 5)] {
            lt.acquire(TxnId(t), k);
        }
        // Build the pre-existing (acyclic) edges: holder T2 reaches waiter T1 via two paths.
        lt.acquire(TxnId(2), 5); // 2 -> 5
        lt.acquire(TxnId(2), 3); // 2 -> 3
        lt.acquire(TxnId(5), 1); // 5 -> 1
        lt.acquire(TxnId(3), 1); // 3 -> 1
        // The graph is still acyclic (no path back to T2). Now T1 waits for T2: edge 1 -> 2 closes
        // BOTH cycles 1->2->5->1 and 1->2->3->1.
        assert!(matches!(lt.acquire(TxnId(1), 2), LockOutcome::Wait { .. }));
        let narrow = lt.find_deadlock_victim_for(TxnId(1), TxnId(2));
        let full = lt.find_deadlock_victim();
        assert_eq!(narrow, full, "narrow must equal full sweep");
        assert_eq!(narrow, Some(TxnId(5)), "youngest across both cycles is T5");
    }

    /// A node reachable from the holder but NOT on a path to the waiter must be excluded from the
    /// victim pool (it is not on any cycle), even though it is younger than the real victims.
    #[test]
    fn edge_rooted_excludes_off_cycle_younger_node() {
        let mut lt = LockTable::new();
        for (t, k) in [(1u64, 1u64), (2, 2), (3, 3), (9, 9)] {
            lt.acquire(TxnId(t), k);
        }
        // holder T2 reaches waiter T1 via T2 -> T3 -> T1, and ALSO has a dead-end branch
        // T2 -> T9 that never reaches T1. T9 is the youngest but must NOT be the victim.
        lt.acquire(TxnId(2), 3); // 2 -> 3
        lt.acquire(TxnId(3), 1); // 3 -> 1
        lt.acquire(TxnId(2), 9); // 2 -> 9 (dead end)
        assert!(matches!(lt.acquire(TxnId(1), 2), LockOutcome::Wait { .. }));
        let narrow = lt.find_deadlock_victim_for(TxnId(1), TxnId(2));
        assert_eq!(narrow, lt.find_deadlock_victim());
        assert_eq!(
            narrow,
            Some(TxnId(3)),
            "T9 is off-cycle; the youngest on-cycle node is T3"
        );
    }

    /// Deep chain closed by the new edge: the edge-rooted search must not overflow the stack
    /// (iterative) and must select the youngest, matching the full sweep (SEC-199 parity).
    #[test]
    fn edge_rooted_deep_chain_matches_full_sweep() {
        const DEPTH: u64 = 50_000;
        let mut lt = LockTable::new();
        for i in 0..DEPTH {
            lt.acquire(TxnId(i + 1), i);
        }
        for i in 1..DEPTH {
            lt.acquire(TxnId(i + 1), i - 1); // T(i+1) -> T(i): a long chain
        }
        // Close the cycle: head T1 waits on the tail's key (held by T(DEPTH)). Edge is 1 -> DEPTH.
        assert!(matches!(
            lt.acquire(TxnId(1), DEPTH - 1),
            LockOutcome::Wait { .. }
        ));
        assert_eq!(
            lt.find_deadlock_victim_for(TxnId(1), TxnId(DEPTH)),
            Some(TxnId(DEPTH))
        );
        assert_eq!(lt.find_deadlock_victim(), Some(TxnId(DEPTH)));
    }

    /// `clear_waits` removes only the waiter's outgoing wait edges; it preserves the locks it holds
    /// and the incoming edges of transactions waiting on those locks (`rmp` #387).
    #[test]
    fn clear_waits_drops_only_pending_wait_edges() {
        let mut lt = LockTable::new();
        // T1 holds key 1; T2 holds key 2.
        lt.acquire(TxnId(1), 1);
        lt.acquire(TxnId(2), 2);
        // T2 waits on T1 for key 1 (edge 2 -> 1). This is the edge a fast-fail would leave stale.
        assert!(matches!(lt.acquire(TxnId(2), 1), LockOutcome::Wait { .. }));
        // T1 waits on T2 for key 2 (edge 1 -> 2): an *incoming* edge to T2.
        assert!(matches!(lt.acquire(TxnId(1), 2), LockOutcome::Wait { .. }));

        // The graph now has a cycle 1 <-> 2; clearing T2's pending waits must break it without
        // touching the locks T2 holds or the edge T1 -> T2 (which is still a real wait).
        lt.clear_waits(TxnId(2));

        // T2 still holds key 2 (lock preserved).
        assert_eq!(lt.holder_of(2), Some(TxnId(2)));
        // T2's outgoing edge (2 -> 1) is gone, so there is no cycle anymore.
        assert_eq!(lt.find_deadlock_victim(), None);
        // T1's incoming-to-T2 wait edge (1 -> 2) is preserved: T1 still legitimately waits on T2.
        // Releasing T2 must therefore free key 2 for T1.
        lt.release_all(TxnId(2));
        assert_eq!(lt.acquire(TxnId(1), 2), LockOutcome::Granted);
    }

    /// Clearing the waits of a transaction that holds no pending edge is a harmless no-op.
    #[test]
    fn clear_waits_is_idempotent_no_op_without_edges() {
        let mut lt = LockTable::new();
        lt.acquire(TxnId(1), 1);
        lt.clear_waits(TxnId(1)); // T1 waits on nobody.
        lt.clear_waits(TxnId(2)); // T2 is unknown.
        assert_eq!(lt.holder_of(1), Some(TxnId(1)));
        assert_eq!(lt.find_deadlock_victim(), None);
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
