//! MVCC version history for the node **label bitmap** (`rmp` task #767).
//!
//! # Why this exists
//!
//! A node's label set lives in the `labels` `u64` **inside** the node record ([`crate::labels`],
//! `05 §9`) and is mutated **in place** — unlike a property, which is a separate `PropRecord` with
//! its own MVCC header, so a property overwrite MVCC-tombstones the old version and prepends the new
//! one (`rmp` #50, newest-**visible**-wins).
//!
//! That left the label word with the in-place half of `04 §5.1`'s ratified MVCC scheme ("store the
//! newest version in place and keep older versions as logical undo deltas") and **none** of the delta
//! half. There was no `v` for `graphus_txn::is_visible` to be applied to, so every label read
//! returned whatever the word held *at that instant*. Two anomalies followed, both reproduced on a
//! pure scan with no index involved (`graphus-cypher/tests/mvcc_label_snapshot_767.rs`):
//!
//! * a **non-repeatable read** — a committed `REMOVE n:Person` was immediately visible to a reader
//!   whose snapshot predated the commit, so one transaction's `MATCH (n:Person)` could return a node
//!   and then stop returning it;
//! * a **dirty read** — an *uncommitted* writer's label change was visible to a concurrent reader,
//!   which is below READ COMMITTED. `docs/transactions.md` documents Snapshot Isolation as the
//!   weakest tier Graphus offers, so this broke the guarantee even for a plain autocommit read.
//!
//! This module supplies the missing delta half.
//!
//! # Why the history is in memory only, and why that is sufficient
//!
//! An older version of the label word is needed by exactly one kind of caller: a **still-active**
//! transaction whose snapshot predates the change. A crash or a clean restart ends every such
//! transaction, and a recovered store's label words are the committed ones (the ARIES undo restores
//! any loser's word — `RecordStore::write_node_labels`'s CAS logical undo, `rmp` #772). So no reader
//! can ever ask for a pre-restart version, and the history needs **no durability**.
//!
//! That is what keeps the on-disk format frozen: `05 §9` is untouched, no migration, and the backup,
//! consistency-check and bulk-import paths are unaffected.
//!
//! # The steady-state cost is one atomic load
//!
//! The label bitmap is the hottest predicate in the engine (every `MATCH (n:L)` re-check goes through
//! it), so [`resolve`](LabelHistory::resolve) short-circuits on [`any`](LabelHistory::any) — a single
//! `Acquire` load (see that method for why it is not `Relaxed`) — whenever no node has a tracked
//! change. Entries are pruned at GC time (see [`prune`](LabelHistory::prune)), so a workload without
//! concurrent label churn keeps the map empty and pays only that load. The lock is taken only while
//! label history actually exists.
//!
//! # KNOWN RESIDUAL: multi-core read scaling while the history is ARMED (`rmp` #767)
//!
//! While the map is empty the gate short-circuits on a load of a read-only cache line, which stays
//! Shared across cores and costs nothing to scale. **Once the history is non-empty**, every label
//! re-check on every reader thread takes a shared [`RwLock`] acquisition — an atomic read-modify-write
//! on ONE cache line, contended by every reader.
//!
//! This is **MEASURED, and it is severe.** Aggregate off-thread label-scan throughput, 20_000 labelled
//! nodes, AMD Ryzen 9 5900HX (8C/16T), `--release`, idle host:
//!
//! | reader threads | 1 | 2 | 4 | 8 | 16 |
//! |---|---|---|---|---|---|
//! | gate UNARMED (scans/s) | 1515 | 2870 | 5380 | 7355 | **8630** |
//! | gate ARMED (scans/s)   | 1092 | 1627 | 2117 | 2125 | **824** |
//!
//! Unarmed scales to 5.7x. Armed peaks at ~1.95x by 8 threads and then **collapses to 0.75x** — slower
//! than a single thread — for a **10.5x** aggregate throughput loss at 16 threads. The lock is the
//! bottleneck, and past saturation it is actively destructive.
//!
//! Scope of the exposure: only while label history is retained, i.e. between a relabel of an
//! already-committed node and the next GC prune. Steady-state read workloads are unaffected (the
//! unarmed row is the shipped path), and the gate is what keeps it that way.
//!
//! It is left as-is DELIBERATELY, not absorbed silently: the fix is a copy-on-write snapshot
//! (`ArcSwap`-style) so readers pay one atomic load, but this workspace carries **no external
//! dependencies**, and adding one — or hand-rolling the equivalent — changes the concurrency design.
//! That is an owner decision, not something to smuggle into a correctness fix. A cheaper mitigation
//! that stays inside the current design is a lock-free pre-filter (e.g. an atomic min/max tracked-id
//! bound, or a small atomic bitset) consulted before the lock: the tracked set is typically one or two
//! nodes, so nearly every candidate would skip the lock entirely.
//!
//! # Version resolution
//!
//! Each tracked change appends `(stamp, bitmap_after)`, where `stamp` is the writer's
//! [`VersionStamp`]: the in-flight `TxnId` while the writer is open, **settled to `Committed(ts)` by
//! [`settle`](LabelHistory::settle) the moment it commits**. `base` is the bitmap as it stood before
//! the oldest retained change.
//!
//! ## Settling is eager here, unlike the record headers — and that is REQUIRED
//!
//! A record header freezes lazily at GC time (`rmp` #49) because eager settling was
//! `O(records touched)` WAL-logged page writes. This history is small and in-memory, so settling costs
//! a walk of one transaction's own entries and logs nothing.
//!
//! It is not merely an optimisation. The first cut of this module kept the raw in-flight stamp and
//! resolved it through the [`CommitRegistry`], mirroring the headers — but the GC freeze sweep walks
//! only on-disk headers, never this history, while the same pass FORGETS committed writers from the
//! registry. After that prune `CommitRegistry::outcome` maps the unknown id to `Aborted`, so the
//! version read as never-committed, [`resolve`](LabelHistory::resolve) fell back to `base`, and a
//! COMMITTED label change silently reverted for every reader until the process restarted. Settling at
//! commit removes the registry from the committed path entirely: afterwards it is consulted only for
//! genuinely in-flight writers, where "unknown ⇒ not visible" is the correct answer anyway.
//!
//! ## Entries are keyed by PHYSICAL id, which is reused
//!
//! Physical ids are reused after reclamation (`04 §2.7`), so an entry outliving its node would be
//! inherited by the next node given that slot — and since `resolve` ignores the live word whenever an
//! entry exists, and a freshly created node retains no version of its own, the dead node's bitmap
//! would stick permanently. `RecordStore::reclaim_node` therefore calls
//! [`forget_node`](LabelHistory::forget_node) before the id reaches the free list. The GC-time
//! [`prune`](LabelHistory::prune) is not sufficient on its own: an in-flight writer's version is
//! (correctly) unprunable, so it would strand there.
//!
//! A reader takes the **newest** version visible to its snapshot, falling back to `base`. When a
//! history exists the live word is deliberately **not** consulted: the live word may hold an
//! uncommitted writer's value, which is precisely the dirty read being closed.

use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use graphus_core::{Timestamp, TxnId};
use graphus_txn::{CommitRegistry, Snapshot, VersionStamp, is_visible};

/// One tracked change to a node's label bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LabelVersion {
    /// The writing transaction's [`VersionStamp`], raw — `InFlight(txn)` until it resolves, exactly
    /// as a record header's `xmin` is stamped (`rmp` #49 lazy freezing). Resolved through the
    /// [`CommitRegistry`], never interpreted directly.
    stamp: u64,
    /// The full label bitmap **after** this change (not a delta): resolution picks a version, it
    /// never replays a chain, so an interleaving of writers on one node cannot compose wrongly.
    bitmap: u64,
}

/// The retained versions of one node's label bitmap, oldest first.
#[derive(Debug, Clone, Default)]
struct NodeLabelHistory {
    /// The bitmap as it stood **before** [`versions`](Self::versions)`[0]`, i.e. the value a reader
    /// older than every retained change must see.
    base: u64,
    /// Tracked changes in write order.
    versions: Vec<LabelVersion>,
}

/// The store-wide label bitmap version history (`rmp` #767).
///
/// Shared by `Arc` between the engine thread (which records changes) and the off-thread reader pool
/// (which resolves them), so a reader thread reaches exactly the same history the writer maintains.
/// This must be shared **live** rather than captured per dispatch: the page cache the reader decodes
/// from is itself live (`rmp` #721), so a label change committed after dispatch is already visible in
/// the word the reader reads, and only a live history can undo it.
#[derive(Debug, Default)]
pub struct LabelHistory {
    /// Fast gate: `true` iff [`map`](Self::map) is non-empty. Lets the overwhelmingly common
    /// no-label-churn path skip the lock entirely.
    any: AtomicBool,
    /// `node_id -> retained versions`.
    map: RwLock<HashMap<u64, NodeLabelHistory>>,
}

impl LabelHistory {
    /// A history with no tracked changes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether any node currently has a tracked label change (the hot-path gate).
    ///
    /// # Ordering: `Acquire`/`Release`, deliberately, not `Relaxed`
    ///
    /// The gate is a **publication** flag: a writer fills the map under the lock and then arms it, and
    /// a reader that observes it armed must also observe the map contents that justify it. `Relaxed`
    /// alone does not order those two, so a reader could see `any() == true` and then take the lock
    /// and find the entry — fine — or, more dangerously, see `any() == false` and skip the lock while
    /// the entry it needed was already published.
    ///
    /// It was originally written `Relaxed`, and an audit found it was sound only by accident: the
    /// buffer pool's `RwLock` read latch (`graphus-bufpool`, taken to decode the node record one line
    /// before every gate check) supplied the missing happens-before. That is an undocumented
    /// dependency on an unrelated component, and Graphus targets aarch64 (Apple Silicon, Raspberry Pi
    /// 5) where the weaker model makes such accidents observable. Paying an `Acquire` load — free on
    /// x86-64, one cheap barrier on aarch64 — buys a property that is true by construction rather than
    /// by a neighbour's implementation detail. Measured: no detectable change on a label scan at either
    /// 1_000 or 100_000 nodes.
    #[must_use]
    #[inline]
    pub fn any(&self) -> bool {
        self.any.load(Ordering::Acquire)
    }

    /// Records that `txn` changed node `id`'s label bitmap from `prior` to `new`.
    ///
    /// Call **only** for a change to a node that already existed as a committed version. A node
    /// created by `txn` itself needs no history: the node record is invisible to every older
    /// snapshot, so no reader can ask what its labels were.
    ///
    /// A no-op change (`prior == new`) records nothing.
    pub fn record(&self, id: u64, txn: TxnId, prior: u64, new: u64) {
        if prior == new {
            return;
        }
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(id).or_insert_with(|| NodeLabelHistory {
            base: prior,
            versions: Vec::new(),
        });
        entry.versions.push(LabelVersion {
            stamp: VersionStamp::in_flight(txn),
            bitmap: new,
        });
        self.any.store(true, Ordering::Release);
    }

    /// The label bitmap node `id` presents to `snapshot`.
    ///
    /// `live` is the bitmap currently in the node record, used only when the node has no tracked
    /// change — in which case no in-flight or recently-committed writer can have perturbed it.
    ///
    /// When a history exists the live word is **not** consulted: it may hold an uncommitted writer's
    /// value.
    #[must_use]
    pub fn resolve(
        &self,
        id: u64,
        live: u64,
        snapshot: Snapshot,
        registry: &CommitRegistry,
    ) -> u64 {
        // Hot path: no node anywhere has a tracked change.
        if !self.any() {
            return live;
        }
        let map = self.map.read().unwrap_or_else(|e| e.into_inner());
        let Some(hist) = map.get(&id) else {
            return live;
        };
        // Newest visible wins, mirroring the property chain (`rmp` #50). `xmax = 0`: a label version
        // is never independently expired — it is superseded by the next entry — so `is_visible`
        // reduces to its creator clause, which is exactly the question being asked. Reusing the
        // audited predicate also keeps this off the `CommitRegistry::outcome(w) == InFlight` trap
        // (that arm is dead — a running writer has no registry entry at all).
        for v in hist.versions.iter().rev() {
            if is_visible(snapshot, v.stamp, 0, registry) {
                return v.bitmap;
            }
        }
        hist.base
    }

    /// **Settles** every version stamped by `txn` to `Committed(commit_ts)`, for use when `txn`
    /// COMMITS.
    ///
    /// # Why this is eager here, when record headers freeze lazily
    ///
    /// A record header's `xmin` is settled lazily at GC time (`rmp` #49) because settling eagerly was
    /// `O(records touched)` **WAL-logged page writes**. This history is small and purely in-memory, so
    /// settling costs a walk of one transaction's own entries and logs nothing.
    ///
    /// It is also MANDATORY, not an optimisation. A raw `InFlight(txn)` stamp is only resolvable while
    /// the [`CommitRegistry`] still holds `txn` — and a GC pass **forgets** committed writers from that
    /// registry once their record headers are frozen (`RecordStore::commit`'s `pending_gc_prune`).
    /// After that, `CommitRegistry::outcome` maps the now-unknown id to `Aborted`, so
    /// `is_visible(.., InFlight(txn), ..)` is false FOREVER, [`resolve`](Self::resolve) falls back to
    /// `base`, and a COMMITTED label change becomes permanently invisible to every reader — silently,
    /// and healed only by a restart (the on-disk word was right all along). Settling at commit removes
    /// the registry from the committed path entirely: afterwards the registry is consulted only for
    /// genuinely in-flight writers, where "unknown ⇒ not visible" is the correct answer anyway.
    /// `nodes` are the physical ids `txn` relabelled (its `ActiveTxn::labelled_nodes`). Settling is
    /// keyed on them so the commit path is `O(this transaction's own writes)`, never
    /// `O(tracked_nodes)` — the map is keyed by node id, so a blind scan would put an unbounded walk
    /// on the commit hot path.
    pub fn settle(&self, txn: TxnId, commit_ts: Timestamp, nodes: &[u64]) {
        if nodes.is_empty() {
            return;
        }
        let stamp = VersionStamp::in_flight(txn);
        let settled = VersionStamp::committed(commit_ts);
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        for id in nodes {
            if let Some(hist) = map.get_mut(id) {
                for v in &mut hist.versions {
                    if v.stamp == stamp {
                        v.stamp = settled;
                    }
                }
            }
        }
    }

    /// Whether any retained version anywhere is still stamped `InFlight(txn)` (test/assertion seam).
    ///
    /// The invariant `settle` establishes is *no `LabelHistory` stamp outlives its registry entry*;
    /// this is how a test checks it directly rather than inferring it from a symptom.
    #[must_use]
    pub fn has_inflight_versions_of(&self, txn: TxnId) -> bool {
        let stamp = VersionStamp::in_flight(txn);
        self.map
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|h| h.versions.iter().any(|v| v.stamp == stamp))
    }

    /// Whether node `id` currently has any retained version (the `alloc_id` reuse assertion).
    #[must_use]
    pub fn tracks_node(&self, id: u64) -> bool {
        self.map
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&id)
    }

    /// Drops every retained version for node `id`, for use when its physical slot is **reclaimed**.
    ///
    /// Physical ids are reused after reclamation (`04 §2.7`) and this history is keyed by physical id,
    /// so an entry outliving its node would be inherited by whatever NEW node is given that slot —
    /// and [`resolve`](Self::resolve) deliberately ignores the live word whenever an entry exists, so
    /// the new node would report the DEAD node's label bitmap. Worse, the new node records no version
    /// of its own (its creator is its own in-flight writer, which
    /// `RecordStore::track_label_history` deliberately skips), so nothing ever overrides the stale
    /// value.
    pub fn forget_node(&self, id: u64) {
        if !self.any() {
            return;
        }
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        map.remove(&id);
        self.any.store(!map.is_empty(), Ordering::Release);
    }

    /// Drops every version stamped by `txn`, for use when `txn` **rolls back**.
    ///
    /// Not required for correctness — an aborted stamp is invisible to every snapshot, so resolution
    /// would already fall through it — but it bounds the memory a churning aborted writer can pin.
    pub fn forget(&self, txn: TxnId) {
        if !self.any() {
            return;
        }
        let stamp = VersionStamp::in_flight(txn);
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, hist| {
            hist.versions.retain(|v| v.stamp != stamp);
            !hist.versions.is_empty()
        });
        self.any.store(!map.is_empty(), Ordering::Release);
    }

    /// Collapses history no live or future reader can still need.
    ///
    /// `watermark` MUST be at or below the oldest active reader's snapshot timestamp — the same
    /// contract [`RecordStore::gc`](crate::RecordStore::gc) imposes, which is where this is called
    /// from. A version committed at or before it is visible to **every** current and future snapshot,
    /// so it and everything older collapse into `base`; a node left with no retained version is
    /// dropped entirely (its live word is then authoritative again).
    pub fn prune(&self, watermark: Timestamp, registry: &CommitRegistry) {
        if !self.any() {
            return;
        }
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, hist| {
            // The newest version that every snapshot can already see.
            let cutoff = hist.versions.iter().rposition(|v| {
                registry
                    .resolve_commit_ts(v.stamp)
                    .is_some_and(|ts| ts <= watermark)
            });
            if let Some(i) = cutoff {
                hist.base = hist.versions[i].bitmap;
                hist.versions.drain(..=i);
            }
            !hist.versions.is_empty()
        });
        self.any.store(!map.is_empty(), Ordering::Release);
    }

    /// The number of nodes with retained label history (observability / tests).
    #[must_use]
    pub fn tracked_nodes(&self) -> usize {
        self.map.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(owner: u64, ts: u64) -> Snapshot {
        Snapshot {
            owner: TxnId(owner),
            ts: Timestamp(ts),
        }
    }

    #[test]
    fn no_history_returns_the_live_bitmap() {
        let h = LabelHistory::new();
        let reg = CommitRegistry::default();
        assert!(!h.any(), "a fresh history must not arm the hot-path gate");
        assert_eq!(h.resolve(1, 0b101, snap(9, 100), &reg), 0b101);
    }

    #[test]
    fn an_uncommitted_change_is_invisible_to_others_but_visible_to_its_author() {
        let h = LabelHistory::new();
        let reg = CommitRegistry::default();
        // Node 1 had bit 0; txn 7 clears it, uncommitted.
        h.record(1, TxnId(7), 0b1, 0b0);
        // Another reader must still see the committed value: THE DIRTY READ.
        assert_eq!(h.resolve(1, 0b0, snap(9, 100), &reg), 0b1);
        // The author sees its own write.
        assert_eq!(h.resolve(1, 0b0, snap(7, 100), &reg), 0b0);
    }

    #[test]
    fn a_commit_is_invisible_to_a_snapshot_that_predates_it() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::default();
        h.record(1, TxnId(7), 0b1, 0b0);
        reg.record_commit(TxnId(7), Timestamp(50));
        // Older snapshot: THE NON-REPEATABLE READ.
        assert_eq!(h.resolve(1, 0b0, snap(9, 49), &reg), 0b1);
        // At the commit timestamp, and after it.
        assert_eq!(h.resolve(1, 0b0, snap(9, 50), &reg), 0b0);
        assert_eq!(h.resolve(1, 0b0, snap(9, 51), &reg), 0b0);
    }

    #[test]
    fn an_aborted_change_is_invisible_to_everyone_else() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::default();
        h.record(1, TxnId(7), 0b1, 0b0);
        reg.record_abort(TxnId(7));
        assert_eq!(h.resolve(1, 0b0, snap(9, 100), &reg), 0b1);
    }

    #[test]
    fn stacked_writers_resolve_newest_visible_wins() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::default();
        // base 0b1 -> A sets 0b11 (commits at 10) -> B sets 0b111 (commits at 20).
        h.record(1, TxnId(1), 0b1, 0b11);
        h.record(1, TxnId(2), 0b11, 0b111);
        reg.record_commit(TxnId(1), Timestamp(10));
        reg.record_commit(TxnId(2), Timestamp(20));
        assert_eq!(h.resolve(1, 0b111, snap(9, 5), &reg), 0b1, "before both");
        assert_eq!(h.resolve(1, 0b111, snap(9, 10), &reg), 0b11, "between");
        assert_eq!(h.resolve(1, 0b111, snap(9, 15), &reg), 0b11, "between");
        assert_eq!(h.resolve(1, 0b111, snap(9, 20), &reg), 0b111, "after both");
    }

    #[test]
    fn a_no_op_change_records_nothing() {
        let h = LabelHistory::new();
        h.record(1, TxnId(7), 0b1, 0b1);
        assert!(!h.any());
        assert_eq!(h.tracked_nodes(), 0);
    }

    /// `rmp` #767, Finding 3 (adversarial audit): WHY `RecordStore::rollback` must call `forget`
    /// **after** the WAL undo, not before.
    ///
    /// This demonstrates the composition that makes the ordering load-bearing, in the one place it can
    /// be shown deterministically. `forget` drops the node's entry outright when the aborting writer
    /// was its only versioner; `resolve` then falls back to the LIVE word. Call the two in the wrong
    /// order — `forget` first, undo second — and every concurrent reader (the off-thread pool reads
    /// through the same `Arc`) sees the ABORTED value unmasked in that window: the dirty read #767
    /// exists to close, reintroduced by its own cleanup.
    #[test]
    fn forgetting_before_the_word_is_restored_would_expose_the_aborted_value() {
        let h = LabelHistory::new();
        let reg = CommitRegistry::new();
        // Committed state: bit 0 set. An in-flight writer clears it; the live word now holds 0b0.
        h.record(1, TxnId(7), 0b1, 0b0);

        // WHILE the history still holds the version, a concurrent reader is correctly masked.
        assert_eq!(
            h.resolve(1, 0b0, snap(9, 100), &reg),
            0b1,
            "precondition: the retained version masks the uncommitted word"
        );

        // The WRONG order: forget first, while the word is still the aborted 0b0.
        h.forget(TxnId(7));
        assert_eq!(
            h.resolve(1, 0b0, snap(9, 100), &reg),
            0b0,
            "THE HAZARD: with the entry dropped and the word not yet restored, the reader sees the \
             ABORTED value — this is why `rollback` calls `forget` AFTER the WAL undo"
        );

        // The RIGHT order: the undo has already restored the word, so the fallback is correct.
        assert_eq!(
            h.resolve(1, 0b1, snap(9, 100), &reg),
            0b1,
            "after the undo restores the word, dropping the entry is safe"
        );
    }

    #[test]
    fn forget_drops_an_aborted_writers_versions_and_disarms_the_gate() {
        let h = LabelHistory::new();
        h.record(1, TxnId(7), 0b1, 0b0);
        assert!(h.any());
        h.forget(TxnId(7));
        assert!(!h.any(), "the gate must disarm once the last version goes");
        assert_eq!(h.tracked_nodes(), 0);
    }

    /// `rmp` #767, Finding 4 (adversarial audit): a SETTLED version is prunable, so a full-watermark
    /// pass drains the history completely and disarms the hot-path gate.
    ///
    /// Before `settle` existed, a version whose writer the registry had forgotten resolved to no
    /// commit timestamp FOREVER, so `prune` could never collapse it: the entry leaked for the life of
    /// the process AND kept `any()` armed, putting a lock + map lookup on every label re-check in the
    /// store — the same ~2.9x class of regression the creator gate exists to avoid, arriving by
    /// another route.
    #[test]
    fn a_settled_version_is_prunable_even_after_the_registry_forgets_its_writer() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::new();
        h.record(1, TxnId(7), 0b1, 0b0);
        // The store settles at commit; the registry entry is recorded at the same moment.
        h.settle(TxnId(7), Timestamp(100), &[1]);
        reg.record_commit(TxnId(7), Timestamp(100));
        assert!(
            !h.has_inflight_versions_of(TxnId(7)),
            "settle must leave no in-flight stamp behind"
        );

        // The GC pass forgets the writer (NOT watermark-gated: `committed_writers()` returns every
        // writer currently recorded as committed, however recently).
        for w in reg.committed_writers() {
            reg.forget(w);
        }

        // The committed change is STILL visible — resolution no longer consults the registry for it.
        assert_eq!(
            h.resolve(1, 0b0, snap(99, 1000), &reg),
            0b0,
            "a settled version must resolve without its registry entry"
        );
        // And it is prunable, so nothing leaks and the gate disarms.
        h.prune(Timestamp(u64::MAX), &reg);
        assert_eq!(h.tracked_nodes(), 0, "a settled version must be prunable");
        assert!(!h.any(), "the hot-path gate must disarm");
    }

    #[test]
    fn prune_collapses_versions_below_the_watermark_and_disarms_the_gate() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::default();
        h.record(1, TxnId(1), 0b1, 0b11);
        reg.record_commit(TxnId(1), Timestamp(10));
        h.settle(TxnId(1), Timestamp(10), &[1]);
        h.prune(Timestamp(10), &reg);
        assert!(!h.any(), "fully-collapsed history must disarm the gate");
        // With the entry gone the live word is authoritative again.
        assert_eq!(h.resolve(1, 0b11, snap(9, 10), &reg), 0b11);
    }

    #[test]
    fn prune_retains_a_version_an_older_reader_still_needs() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::default();
        h.record(1, TxnId(1), 0b1, 0b11);
        reg.record_commit(TxnId(1), Timestamp(10));
        // Watermark below the commit: an older reader may still exist.
        h.prune(Timestamp(9), &reg);
        assert!(h.any(), "history needed by an older snapshot must survive");
        assert_eq!(h.resolve(1, 0b11, snap(9, 9), &reg), 0b1);
    }

    #[test]
    fn prune_keeps_an_in_flight_version_above_the_collapsed_base() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::default();
        h.record(1, TxnId(1), 0b1, 0b11);
        reg.record_commit(TxnId(1), Timestamp(10));
        h.record(1, TxnId(2), 0b11, 0b111); // still in flight
        h.prune(Timestamp(10), &reg);
        assert!(h.any(), "an in-flight version must not be pruned away");
        // A reader still sees the committed value, not the in-flight one.
        assert_eq!(h.resolve(1, 0b111, snap(9, 10), &reg), 0b11);
        // The author sees its own.
        assert_eq!(h.resolve(1, 0b111, snap(2, 10), &reg), 0b111);
    }
}
