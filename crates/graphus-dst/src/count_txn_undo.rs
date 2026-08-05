//! Focused deterministic reproducer for **a transaction's live-record COUNT delta surviving its own
//! failed, rolled-back or crashed commit** (`rmp` #866) — the counts-half twin of the schema-catalog
//! DDL undo ([`crate::catalog_rollback_undo`], `rmp` #734), the free-list double-allocation
//! ([`crate::freelist_reuse`], `rmp` #578) and the label-word clobber
//! ([`crate::label_rollback_clobber`], `rmp` #772). All four are catalog-maintenance defects reachable
//! only through statement-interleaving plus a fault the generic [`crate::harness`] never performs.
//!
//! ## The defect
//!
//! The six durable cardinality counters — `total_nodes`, `total_relationships`, `nodes_per_label`,
//! `rels_per_type` and the `rmp` #856 directional projections `rels_per_start_label_type` /
//! `rels_per_type_end_label` — are mutated **eagerly at write time** on one shared `Statistics`, so
//! the live value is always "durable image **plus** every in-flight transaction's delta". They are not
//! WAL-logged as counters: they become durable only through the commit-time catalog checkpoint
//! (`RecordStore::checkpoint_meta`), whose page writes *are* WAL-logged under the committing
//! transaction.
//!
//! That makes three moments dangerous, and `rmp` #866 fixed all three:
//!
//! 1. **A rollback must withdraw exactly its own delta.** `rollback` used to reload `Statistics`
//!    wholesale from the durable image, which is wrong in both directions under interleaving
//!    (over-count P3, under-count P4) and **permanent** — the error survives the next checkpoint and
//!    every reopen. The fix restores the *pre-rollback in-memory image minus this transaction's own
//!    delta* (`ActiveTxn.counts`, recorded by `count_bump`), the same shape as #578's free-list
//!    `pre_free`-minus-own-pushes and #734's `schema_undo`.
//! 2. **A checkpoint must not publish another open transaction's counts.** `committed_statistics`
//!    now strips **every** still-open transaction's pending delta, excluding the committing one *by
//!    name*.
//! 3. **A failed commit must leave the delta withdrawable.** `commit_prepare`'s
//!    `self.active.remove(&txn)` moved **after** `checkpoint_meta` and `commit_at_no_sync`, so a
//!    failure in either leaves the active-set entry — and with it the count delta and the schema undo
//!    log — intact for a subsequent `rollback` to withdraw. Before the move, a failure between the
//!    removal and the commit record left the counts folded into the shared tally with nothing left to
//!    withdraw them: a permanently drifted catalog while `counts_match_committed_image` still read
//!    `true`, i.e. a **wrong `count()` answer** — an ACID/TCK breach, since `rmp` #866 answers
//!    `count()` from these counters instead of scanning.
//!
//! ## What this module adds over the `RecordStore`-layer tests
//!
//! `graphus-storage`'s `tests/count_txn_undo_866.rs` pins the interleavings deterministically at the
//! record-store layer, including one crash-recovery case. It does **not** reach three things, and
//! those three are the whole point of this module:
//!
//! 1. **A fault injected *during* `checkpoint_meta`** — the exact window item 3 restructured. Armed
//!    with [`graphus_io::MemBlockDevice::arm_io_error`] through the `dst`-gated
//!    [`graphus_storage::RecordStore::with_device_mut`] seam (`rmp` #232), the catalog checkpoint
//!    fails, the commit fails with it, and the transaction must still be open so its rollback
//!    withdraws exactly its own effect. See [`run_io_error_at_catalog_checkpoint`].
//! 2. **The steal case** — the `RecordStore` test recovers *no-force*, replaying onto an empty
//!    device, so an open transaction's evicted dirty pages are never undone against a **real page
//!    image** while the checkpointed catalog carries the committed counts. See
//!    [`run_stolen_pages_vs_checkpointed_counts`], which exercises both crash flavours.
//! 3. **A crash between `checkpoint_meta` and the COMMIT harden** — the catalog pages are WAL-logged
//!    under `txn`, so a loser's checkpoint must revert; for the counts half that was asserted by
//!    design and never measured. See [`run_crash_between_checkpoint_and_commit_harden`], which tears
//!    the un-hardened COMMIT record off the durable tail and asserts the paired winner/loser outcomes
//!    from one code path.
//!
//! ## The oracle
//!
//! Every assertion compares the six counters against **two independent re-scans** of the same store,
//! plus a **hand-computed expected value** that shares no code with the engine at all:
//!
//! * [`Counters::by_rescan`] — the exact logic of `count_txn_undo_866.rs`'s
//!   `assert_all_counters_match_rescan`, copied (that file is an integration test, so it cannot be
//!   imported) and not weakened: "live" is the slot being in use **and** the record carrying no MVCC
//!   tombstone (`expired_ts == 0`), which is what the counters mean.
//! * [`Counters::by_visible_scan`] — the same scan filtered by the real MVCC predicate
//!   ([`graphus_txn::is_visible`]) at a fresh snapshot over the store's own
//!   [`commit_registry`](graphus_storage::RecordStore::commit_registry). This is the
//!   **`count()`-shaped answer**: the number a `MATCH (n:Person) RETURN count(n)` must produce. It is
//!   asserted at the storage layer rather than through the Cypher layer because `graphus-dst` cannot
//!   hand a recovered `RecordStore` to a `LocalEngine` — stated plainly rather than skipped.
//! * [`Counters::expected`] — the arithmetic the scenario knows must be true, written out by hand.
//!
//! On the **live** store the two scans deliberately disagree while a writer is open (the counters are
//! eager, the visible scan is not); that disagreement is asserted as the non-vacuity witness that
//! [`counts_match_committed_image`](graphus_storage::RecordStore::counts_match_committed_image) is
//! load-bearing rather than always-true. After recovery, with nothing open, all three must coincide.
//!
//! Both crash flavours are exercised where the engine permits, and every runner is asserted
//! deterministic (same input ⇒ identical report).
//!
//! ## Known engine limitation this module documents rather than hides
//!
//! [`run_io_error_at_catalog_checkpoint`] recovers **no-force only**. The steal flavour calls
//! [`RecordStore::flush`](graphus_storage::RecordStore::flush), and after an I/O error inside
//! `checkpoint_meta`'s metadata-chain growth the store cannot flush again: the growth loop
//! (`store.rs`, `checkpoint_meta`) does `new_page()` → `with_page_mut(...)` → `flush_unlogged(f)?` →
//! `unpin(f)`, so a failing `flush_unlogged` returns early and **leaks a pinned frame that is dirty
//! with `page_lsn == 0`**; every later `flush`/`checkpoint` then fails closed on the `rmp` #396
//! WAL-before-data guard ("dirty page N written back with page_lsn 0 under a real WAL"). That is a
//! pre-existing failure-atomicity defect in `graphus-storage`, not a counts defect: the `rmp` #866
//! invariants this module asserts all hold on the no-force path. It is reported rather than worked
//! around, and the steal flavour of that scenario should be added once the leak is fixed. The steal
//! coverage the counts half needs is delivered in full by
//! [`run_stolen_pages_vs_checkpointed_counts`] and
//! [`run_crash_between_checkpoint_and_commit_harden`].

use std::collections::BTreeMap;

use graphus_core::{PageId, TxnId};
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::{Snapshot, is_visible};
use graphus_wal::{LogSink, MemLogSink, WalManager};

use crate::catalog_rollback_undo::Crash;

/// The store type the reproducer drives: the record store over the in-memory DST device + log.
type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Buffer-pool capacity for the crash scenarios, so eviction + the WAL rule are exercised during the
/// run (the same size [`crate::catalog_rollback_undo`] uses).
const POOL_CAPACITY: usize = 16;

/// Buffer-pool capacity for the injected-I/O-error scenario. Deliberately generous: it keeps the
/// armed one-shot write error landing on the **freshly allocated metadata page's own home write**
/// inside `checkpoint_meta`, rather than on an unrelated dirty *eviction*. An eviction whose
/// write-back fails leaves a stale `Ready(idx)` page-table entry behind
/// (`graphus-bufpool`'s `evict_held` returns before removing the old mapping, then `load_into`
/// blanks the frame), which permanently wedges every later fetch of that page id — a second
/// pre-existing defect that would mask the counts invariant under test.
const FAULT_POOL_CAPACITY: usize = 64;

/// The label every node in these scenarios carries, so the per-label and both directional
/// projections are all non-trivially populated.
const SEED_LABEL: &str = "Person";
/// The relationship type every edge in these scenarios carries.
const SEED_TYPE: &str = "KNOWS";
/// How many property-key tokens the faulting transaction interns. Enough to push the encoded catalog
/// past one metadata-page chunk, so its commit's `checkpoint_meta` **must** grow the metadata chain —
/// which is a guaranteed device write inside `checkpoint_meta`, independent of buffer-pool residency
/// or replacement policy. The scenario asserts the commit actually failed, so an eroded margin fails
/// the test loudly instead of passing vacuously.
const CHAIN_GROWTH_TOKENS: usize = 1024;

// -------------------------------------------------------------------------------------------------
// The six counters, and three independent ways to obtain them
// -------------------------------------------------------------------------------------------------

/// The six durable live-record cardinality counters (`rmp` #866 + the #856 directional projections)
/// as one comparable value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    /// `Statistics::total_nodes`.
    pub total_nodes: u64,
    /// `Statistics::total_relationships`.
    pub total_relationships: u64,
    /// `Statistics::nodes_per_label`.
    pub nodes_per_label: BTreeMap<u32, u64>,
    /// `Statistics::rels_per_type`.
    pub rels_per_type: BTreeMap<u32, u64>,
    /// `Statistics::rels_per_start_label_type` (`rmp` #856).
    pub rels_per_start_label_type: BTreeMap<(u32, u32), u64>,
    /// `Statistics::rels_per_type_end_label` (`rmp` #856).
    pub rels_per_type_end_label: BTreeMap<(u32, u32), u64>,
}

impl Counters {
    /// The counters as the store currently reports them — the numbers `rmp` #866's `count()`
    /// shortcut answers from.
    #[must_use]
    pub fn from_statistics(store: &Store) -> Self {
        let s = store.statistics();
        Self {
            total_nodes: s.total_nodes(),
            total_relationships: s.total_relationships(),
            nodes_per_label: s.nodes_per_label.clone(),
            rels_per_type: s.rels_per_type.clone(),
            rels_per_start_label_type: s.rels_per_start_label_type.clone(),
            rels_per_type_end_label: s.rels_per_type_end_label.clone(),
        }
    }

    /// The independent **live** re-scan oracle, from public record reads only: a record counts when
    /// its slot is in use (`scan_*_ids`) **and** it carries no MVCC tombstone (`expired_ts == 0`).
    /// This is exactly what the eagerly-maintained counters mean, and it is the logic of
    /// `graphus-storage`'s `count_txn_undo_866.rs::assert_all_counters_match_rescan`, copied rather
    /// than weakened (that file is an integration test and cannot be imported).
    ///
    /// A self-loop's single node is both endpoints, so it contributes to both directional maps — the
    /// oracle gets that by asking the same node twice rather than by special-casing it.
    ///
    /// # Panics
    /// Panics if any store read fails — every one of them is expected to succeed here.
    #[must_use]
    pub fn by_rescan(store: &mut Store) -> Self {
        let mut out = Self::default();
        for id in store.scan_node_ids().expect("scan nodes") {
            if store.node(id).expect("read node").mvcc.expired_ts != 0 {
                continue;
            }
            out.total_nodes += 1;
            for token in store.node_labels(id).expect("node labels") {
                *out.nodes_per_label.entry(token).or_insert(0) += 1;
            }
        }
        for id in store.scan_rel_ids().expect("scan rels") {
            let rel = store.rel(id).expect("read rel");
            if rel.mvcc.expired_ts != 0 {
                continue;
            }
            out.total_relationships += 1;
            *out.rels_per_type.entry(rel.type_id).or_insert(0) += 1;
            for label in store.node_labels(rel.start_node).expect("start labels") {
                *out.rels_per_start_label_type
                    .entry((label, rel.type_id))
                    .or_insert(0) += 1;
            }
            for label in store.node_labels(rel.end_node).expect("end labels") {
                *out.rels_per_type_end_label
                    .entry((rel.type_id, label))
                    .or_insert(0) += 1;
            }
        }
        out
    }

    /// The **`count()`-shaped** oracle: the same scan filtered by the production MVCC visibility
    /// predicate ([`graphus_txn::is_visible`]) at a fresh snapshot over the store's own
    /// [`commit_registry`](RecordStore::commit_registry) — i.e. the number a
    /// `MATCH (n:Person) RETURN count(n)` must produce for a reader that starts now.
    ///
    /// This is the storage-level equivalent of driving the Cypher layer: `graphus-dst` cannot hand a
    /// recovered `RecordStore` to a `LocalEngine`, so the equivalence is asserted here, over the same
    /// visibility function the read path uses, rather than skipped.
    ///
    /// Node **labels** are read from the current bitmap rather than snapshot-filtered, because that
    /// is what the engine's own read path does: label words are mutated in place and are not
    /// snapshot-isolated (`rmp` #767, the deferral parked in #39). In these scenarios every label is
    /// written by the same transaction that creates the node, so the two agree by construction.
    ///
    /// # Panics
    /// Panics if any store read fails — every one of them is expected to succeed here.
    #[must_use]
    pub fn by_visible_scan(store: &mut Store) -> Self {
        // A reader ticket distinct from every writer, so no in-flight write is ever visible as
        // "our own" (the same device `reader_store_growth` uses).
        let snapshot = Snapshot::new(TxnId(u64::MAX), store.snapshot_ts());
        let registry = store.commit_registry().clone();
        let mut out = Self::default();
        let mut visible_node = BTreeMap::new();
        for id in store.scan_node_ids().expect("scan nodes") {
            let mvcc = store.node(id).expect("read node").mvcc;
            let visible = is_visible(snapshot, mvcc.created_ts, mvcc.expired_ts, &registry);
            visible_node.insert(id, visible);
            if !visible {
                continue;
            }
            out.total_nodes += 1;
            for token in store.node_labels(id).expect("node labels") {
                *out.nodes_per_label.entry(token).or_insert(0) += 1;
            }
        }
        for id in store.scan_rel_ids().expect("scan rels") {
            let rel = store.rel(id).expect("read rel");
            if !is_visible(
                snapshot,
                rel.mvcc.created_ts,
                rel.mvcc.expired_ts,
                &registry,
            ) {
                continue;
            }
            out.total_relationships += 1;
            *out.rels_per_type.entry(rel.type_id).or_insert(0) += 1;
            for label in store.node_labels(rel.start_node).expect("start labels") {
                *out.rels_per_start_label_type
                    .entry((label, rel.type_id))
                    .or_insert(0) += 1;
            }
            for label in store.node_labels(rel.end_node).expect("end labels") {
                *out.rels_per_type_end_label
                    .entry((rel.type_id, label))
                    .or_insert(0) += 1;
            }
        }
        out
    }

    /// The hand-computed expected value, sharing no code with the engine: in every scenario here
    /// each node carries `label` and each relationship carries `rel_type` between two `label` nodes,
    /// so both directional projections equal the relationship total.
    #[must_use]
    pub fn expected(label: u32, rel_type: u32, nodes: u64, rels: u64) -> Self {
        let mut out = Self {
            total_nodes: nodes,
            total_relationships: rels,
            ..Self::default()
        };
        if nodes > 0 {
            out.nodes_per_label.insert(label, nodes);
        }
        if rels > 0 {
            out.rels_per_type.insert(rel_type, rels);
            out.rels_per_start_label_type
                .insert((label, rel_type), rels);
            out.rels_per_type_end_label.insert((rel_type, label), rels);
        }
        out
    }
}

// -------------------------------------------------------------------------------------------------
// Scenario shape
// -------------------------------------------------------------------------------------------------

/// How the **bystander** writer — the transaction that holds a pending count delta *concurrently*
/// with the transaction under test — ends before the crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BystanderEnding {
    /// It commits: its counts must be durable after recovery.
    Commits,
    /// It is still open at the crash: recovery undoes it, so its counts must **not** be durable.
    LeftOpen,
    /// It rolls back before the crash: its counts must be withdrawn and never resurrected.
    RollsBack,
}

impl BystanderEnding {
    /// Every ending, for exhaustive test loops.
    #[must_use]
    pub fn all() -> [BystanderEnding; 3] {
        [
            BystanderEnding::Commits,
            BystanderEnding::LeftOpen,
            BystanderEnding::RollsBack,
        ]
    }

    /// Whether this ending makes the bystander's writes durable.
    #[must_use]
    fn survives(self) -> bool {
        self == BystanderEnding::Commits
    }
}

/// What one reproduction observed. Every runner returns this shape so the invariant, the oracles and
/// the non-vacuity witnesses travel together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountReport {
    /// The counters the recovered store reports — what a counter-served `count()` would answer.
    pub recovered: Counters,
    /// The independent live re-scan of the recovered store.
    pub recovered_rescan: Counters,
    /// The MVCC-visibility-filtered scan of the recovered store (the `count()`-shaped answer).
    pub recovered_visible: Counters,
    /// The hand-computed value the scenario's arithmetic demands.
    pub expected: Counters,
    /// [`counts_match_committed_image`](RecordStore::counts_match_committed_image) on the recovered
    /// store. Must be `true`: recovery leaves nothing open.
    pub recovered_counts_match_committed_image: bool,
    /// Number of loser transactions ARIES undo rolled back.
    pub recovery_losers: usize,
    /// Number of compensation log records undo wrote — the witness that undo did real work against
    /// the recovered image rather than finding nothing to do.
    pub recovery_clrs: usize,
    /// Whether recovery stopped at a truncated/torn tail.
    pub recovery_tail_truncated: bool,
}

impl CountReport {
    /// The `rmp` #866 recovery invariant: the six counters equal the independent live re-scan, equal
    /// the visibility-filtered (`count()`-shaped) scan, equal the hand-computed expectation, and
    /// nothing is left pending.
    #[must_use]
    pub fn holds(&self) -> bool {
        self.recovered == self.recovered_rescan
            && self.recovered == self.recovered_visible
            && self.recovered == self.expected
            && self.recovered_counts_match_committed_image
    }
}

// -------------------------------------------------------------------------------------------------
// Scenario 1 — an I/O error injected *inside* `checkpoint_meta`
// -------------------------------------------------------------------------------------------------

/// What [`run_io_error_at_catalog_checkpoint`] observed, in addition to the recovery outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointFaultReport {
    /// The commit returned `Err` carrying the injected I/O error. If this is `false` the fault never
    /// fired and everything below is vacuous.
    pub fault_surfaced: bool,
    /// The WAL still holds an open Active-Transaction-Table entry for the faulting transaction, i.e.
    /// **no COMMIT record was appended**. Since `commit_at_no_sync` is the only WAL append after
    /// `checkpoint_meta` in `commit_prepare`, and `checkpoint_meta` is the only fallible *device*
    /// step before it, this is the independent witness that the injected write error fired **inside
    /// `checkpoint_meta`** — not later, in the post-commit `maybe_checkpoint`.
    pub failed_before_commit_record: bool,
    /// The faulting transaction is **still in the store's active set** after its commit failed — the
    /// `rmp` #866 ordering invariant (`self.active.remove` moved after both fallible steps). Without
    /// it the delta below could never be withdrawn.
    pub txn_still_active_after_failed_commit: bool,
    /// The counters immediately after the failed commit: still carrying both the faulting
    /// transaction's and the bystander's pending deltas (nothing has been withdrawn yet).
    pub counters_after_failed_commit: Counters,
    /// The counters after the faulting transaction rolls back: the committed baseline **plus the
    /// bystander's still-pending delta**, and nothing of the aborted transaction.
    pub counters_after_rollback: Counters,
    /// The independent live re-scan at that same instant.
    pub rescan_after_rollback: Counters,
    /// What the counters must be after the rollback (hand-computed).
    pub expected_after_rollback: Counters,
    /// `counts_match_committed_image` while the bystander is still open — must be `false`, else the
    /// `count()` shortcut would serve a dirty read.
    pub counts_match_with_bystander_open: bool,
    /// The visibility-filtered scan while the bystander is open. Must differ from
    /// [`counters_after_rollback`](Self::counters_after_rollback): the counters are eager, the
    /// visible scan is not. This is the witness that the shortcut's gate is load-bearing.
    pub visible_scan_with_bystander_open: Counters,
    /// The recovery outcome after the crash.
    pub recovery: CountReport,
}

impl CheckpointFaultReport {
    /// The full `rmp` #866 invariant for this scenario.
    #[must_use]
    pub fn holds(&self) -> bool {
        self.fault_surfaced
            && self.failed_before_commit_record
            && self.txn_still_active_after_failed_commit
            && self.counters_after_rollback == self.expected_after_rollback
            && self.counters_after_rollback == self.rescan_after_rollback
            && !self.counts_match_with_bystander_open
            && self.visible_scan_with_bystander_open != self.counters_after_rollback
            && self.recovery.holds()
    }
}

/// Injects a write I/O error **inside the commit-time catalog checkpoint**, then proves the faulting
/// transaction's count delta is still withdrawable, that its rollback withdraws exactly its own
/// effect (leaving a concurrently open writer's delta untouched), and that the counters survive a
/// crash and recovery (`rmp` #866, item 3).
///
/// The fault is armed on the *live* device of a running store through the `dst`-gated
/// [`RecordStore::with_device_mut`] seam. It is aimed at `checkpoint_meta` by making the faulting
/// transaction intern [`CHAIN_GROWTH_TOKENS`] property-key tokens: the encoded catalog then no
/// longer fits one metadata-page chunk, so the checkpoint must grow the metadata chain, and that
/// growth performs a device write unconditionally — no dependence on buffer-pool residency or
/// replacement policy.
///
/// Recovers **no-force only**; see the module documentation for the pre-existing `graphus-storage`
/// failure-atomicity defect that makes a post-fault `flush` (and therefore the steal flavour)
/// impossible today.
///
/// # Panics
///
/// Panics if any store operation that is expected to succeed fails.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run_io_error_at_catalog_checkpoint(ending: BystanderEnding) -> CheckpointFaultReport {
    let mut store = create_store(FAULT_POOL_CAPACITY);

    // --- seed: two labelled nodes and one edge, committed and flushed, so nothing below can hold
    //     vacuously against an empty catalog.
    let t0 = TxnId(1);
    store.begin(t0);
    let person = store
        .intern_token(Namespace::Label, SEED_LABEL)
        .expect("intern label");
    let knows = store
        .intern_token(Namespace::RelType, SEED_TYPE)
        .expect("intern rel type");
    let (a, _) = store.create_node(t0).expect("seed node a");
    let (b, _) = store.create_node(t0).expect("seed node b");
    store.add_label(t0, a, person).expect("label a");
    store.add_label(t0, b, person).expect("label b");
    store.create_rel(t0, knows, a, b).expect("seed edge");
    store.commit(t0).expect("seed commits");
    store.flush().expect("flush seed");
    assert_eq!(
        Counters::from_statistics(&store),
        Counters::expected(person, knows, 2, 1),
        "the seed baseline must be non-empty, else every comparison below holds vacuously"
    );

    // --- BYSTANDER: moves counters and stays OPEN across the faulting transaction's whole lifecycle.
    let bystander = TxnId(2);
    store.begin(bystander);
    let (nb, _) = store.create_node(bystander).expect("bystander node");
    store
        .add_label(bystander, nb, person)
        .expect("bystander label");
    store
        .create_rel(bystander, knows, nb, a)
        .expect("bystander edge");

    // --- FAULTING transaction: a catalog big enough to force metadata-chain growth at its
    //     checkpoint, plus its own counter movement.
    let faulting = TxnId(3);
    store.begin(faulting);
    for i in 0..CHAIN_GROWTH_TOKENS {
        store
            .intern_token(Namespace::PropKey, &format!("prop_key_number_{i:08}"))
            .expect("intern chain-growth token");
    }
    let (nf, _) = store.create_node(faulting).expect("faulting node");
    store
        .add_label(faulting, nf, person)
        .expect("faulting label");
    store
        .create_rel(faulting, knows, nf, b)
        .expect("faulting edge");

    // --- the fault: the next home write fails. The first device write from here is inside
    //     `checkpoint_meta`'s metadata-chain growth.
    store.with_device_mut(MemBlockDevice::arm_io_error);
    let commit = store.commit(faulting);
    let fault_surfaced = commit
        .as_ref()
        .err()
        .is_some_and(|e| e.to_string().contains("injected I/O error"));
    // No COMMIT record ⇒ the failure landed before `commit_at_no_sync`, i.e. inside `checkpoint_meta`.
    let failed_before_commit_record = store.with_wal(|w| w.is_active(faulting));
    let txn_still_active_after_failed_commit = store.is_txn_active(faulting);
    let counters_after_failed_commit = Counters::from_statistics(&store);

    // --- the withdrawal: exactly the faulting transaction's own delta, never the bystander's.
    store
        .rollback(faulting)
        .expect("the faulting transaction must still be rollback-able");
    let counters_after_rollback = Counters::from_statistics(&store);
    let rescan_after_rollback = Counters::by_rescan(&mut store);
    // baseline (2 nodes / 1 edge) + the bystander's still-pending node and edge.
    let expected_after_rollback = Counters::expected(person, knows, 3, 2);
    let counts_match_with_bystander_open = store.counts_match_committed_image();
    let visible_scan_with_bystander_open = Counters::by_visible_scan(&mut store);

    match ending {
        BystanderEnding::Commits => store.commit(bystander).expect("bystander commits"),
        BystanderEnding::LeftOpen => {}
        BystanderEnding::RollsBack => store.rollback(bystander).expect("bystander rolls back"),
    }

    // --- crash + recover. Harden first so the loser's records are in the durable log and recovery
    //     genuinely has to undo them (otherwise the pages would simply be absent).
    store.with_wal(WalManager::flush);
    let nodes = if ending.survives() { 3 } else { 2 };
    let rels = if ending.survives() { 2 } else { 1 };
    let recovery = crash_and_report(
        store,
        Crash::NoForce,
        0,
        FAULT_POOL_CAPACITY,
        Counters::expected(person, knows, nodes, rels),
    );

    CheckpointFaultReport {
        fault_surfaced,
        failed_before_commit_record,
        txn_still_active_after_failed_commit,
        counters_after_failed_commit,
        counters_after_rollback,
        rescan_after_rollback,
        expected_after_rollback,
        counts_match_with_bystander_open,
        visible_scan_with_bystander_open,
        recovery,
    }
}

// -------------------------------------------------------------------------------------------------
// Scenario 2 — stolen uncommitted pages vs a checkpoint that carries only the committed counts
// -------------------------------------------------------------------------------------------------

/// What [`run_stolen_pages_vs_checkpointed_counts`] observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StolenCheckpointReport {
    /// The live counters at the instant the committing transaction ran its checkpoint. They carry
    /// the bystander's uncommitted delta, so the checkpoint genuinely had something to strip — the
    /// non-vacuity witness for `committed_statistics`'s counts half.
    pub live_counters_at_checkpoint: Counters,
    /// What the live counters would have been with no bystander open. If this equals
    /// [`live_counters_at_checkpoint`](Self::live_counters_at_checkpoint), the bystander contributed
    /// nothing and the scenario is vacuous.
    pub committed_counters_at_checkpoint: Counters,
    /// The recovery outcome.
    pub recovery: CountReport,
}

impl StolenCheckpointReport {
    /// The invariant: the checkpoint had a real delta to strip, and the recovered counters match
    /// every oracle.
    #[must_use]
    pub fn holds(&self) -> bool {
        self.live_counters_at_checkpoint != self.committed_counters_at_checkpoint
            && self.recovery.holds()
    }
}

/// Drives the **steal** half of `rmp` #866: a transaction commits — running the catalog checkpoint,
/// which must persist the committed counts and strip every *other* open transaction's — while a
/// bystander holds a pending count delta, and the crash then leaves that bystander's dirty pages
/// **written home**, so ARIES undo must roll them back against a real page image rather than against
/// an empty device.
///
/// `Crash::NoForce` replays onto a fresh device (the shape the `RecordStore`-layer test already
/// covers); `Crash::Steal` flushes every dirty page home first, snapshots that on-disk image and
/// recovers from it. Both must land on the same counters.
///
/// # Panics
///
/// Panics if any store operation that is expected to succeed fails.
#[must_use]
pub fn run_stolen_pages_vs_checkpointed_counts(
    ending: BystanderEnding,
    crash: Crash,
) -> StolenCheckpointReport {
    let mut store = create_store(POOL_CAPACITY);

    let t0 = TxnId(1);
    store.begin(t0);
    let person = store
        .intern_token(Namespace::Label, SEED_LABEL)
        .expect("intern label");
    let knows = store
        .intern_token(Namespace::RelType, SEED_TYPE)
        .expect("intern rel type");
    let (a, _) = store.create_node(t0).expect("seed node a");
    let (b, _) = store.create_node(t0).expect("seed node b");
    store.add_label(t0, a, person).expect("label a");
    store.add_label(t0, b, person).expect("label b");
    store.create_rel(t0, knows, a, b).expect("seed edge");
    store.commit(t0).expect("seed commits");
    store.flush().expect("flush seed");

    // --- BYSTANDER: three labelled nodes and three edges, all uncommitted, held OPEN across the
    //     committing transaction's checkpoint. Enough rows that its pages are genuinely dirty and
    //     get stolen home by the steal flush.
    let bystander = TxnId(2);
    store.begin(bystander);
    for _ in 0..3 {
        let (n, _) = store.create_node(bystander).expect("bystander node");
        store
            .add_label(bystander, n, person)
            .expect("bystander label");
        store
            .create_rel(bystander, knows, n, a)
            .expect("bystander edge");
    }

    let live_counters_at_checkpoint = Counters::from_statistics(&store);
    // The committing transaction's own contribution is included below; here we record what the
    // committed image *was* before it, i.e. what the strip must reduce the live value to (plus the
    // committer's own delta, added by its own writes below).
    let committed_counters_at_checkpoint = Counters::expected(person, knows, 2, 1);

    // --- COMMITTER: its checkpoint must persist its own counts and strip the bystander's.
    let committer = TxnId(3);
    store.begin(committer);
    let (nc, _) = store.create_node(committer).expect("committer node");
    store
        .add_label(committer, nc, person)
        .expect("committer label");
    store
        .create_rel(committer, knows, nc, b)
        .expect("committer edge");
    store.commit(committer).expect("committer commits");

    match ending {
        BystanderEnding::Commits => store.commit(bystander).expect("bystander commits"),
        BystanderEnding::LeftOpen => {}
        BystanderEnding::RollsBack => store.rollback(bystander).expect("bystander rolls back"),
    }

    store.with_wal(WalManager::flush);
    // baseline 2/1 + committer 1/1, plus the bystander's 3/3 only when it commits.
    let nodes = if ending.survives() { 6 } else { 3 };
    let rels = if ending.survives() { 5 } else { 2 };
    let recovery = crash_and_report(
        store,
        crash,
        0,
        POOL_CAPACITY,
        Counters::expected(person, knows, nodes, rels),
    );

    StolenCheckpointReport {
        live_counters_at_checkpoint,
        committed_counters_at_checkpoint,
        recovery,
    }
}

// -------------------------------------------------------------------------------------------------
// Scenario 3 — a crash between `checkpoint_meta` and the COMMIT harden
// -------------------------------------------------------------------------------------------------

/// Whether the prepared transaction's COMMIT record survives the crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitRecordFate {
    /// The COMMIT record is durable: the transaction is a **winner**, so the counts its checkpoint
    /// persisted must survive.
    Hardened,
    /// The crash landed between `checkpoint_meta` and the COMMIT harden: the record's tail is torn
    /// off, so the transaction is a **loser** and its checkpoint — counts included — must revert.
    TornOff,
}

impl CommitRecordFate {
    /// Both fates, for exhaustive test loops.
    #[must_use]
    pub fn all() -> [CommitRecordFate; 2] {
        [CommitRecordFate::Hardened, CommitRecordFate::TornOff]
    }
}

/// Drives the third `rmp` #866 gap: `commit_prepare` runs `checkpoint_meta` — persisting a catalog
/// that **includes the committing transaction's counts**, because `committed_statistics` excludes it
/// by name — and appends an un-hardened COMMIT record. The crash then lands either after that record
/// became durable (a winner) or before it (a loser, modelled by tearing the record's tail off the
/// durable log, exactly as the harness's torn-WAL-tail fault does).
///
/// The two fates come out of one code path, which is what makes each non-vacuous: the winner proves
/// the checkpoint really did persist the transaction's counts, and the loser proves that same
/// checkpoint reverted. Assert them as a pair.
///
/// # Panics
///
/// Panics if any store operation that is expected to succeed fails.
#[must_use]
pub fn run_crash_between_checkpoint_and_commit_harden(
    fate: CommitRecordFate,
    crash: Crash,
) -> CountReport {
    let mut store = create_store(POOL_CAPACITY);

    let t0 = TxnId(1);
    store.begin(t0);
    let person = store
        .intern_token(Namespace::Label, SEED_LABEL)
        .expect("intern label");
    let knows = store
        .intern_token(Namespace::RelType, SEED_TYPE)
        .expect("intern rel type");
    let (a, _) = store.create_node(t0).expect("seed node a");
    let (b, _) = store.create_node(t0).expect("seed node b");
    store.add_label(t0, a, person).expect("label a");
    store.add_label(t0, b, person).expect("label b");
    store.create_rel(t0, knows, a, b).expect("seed edge");
    store.commit(t0).expect("seed commits");
    store.flush().expect("flush seed");
    store.with_wal(WalManager::flush);

    let prepared = TxnId(2);
    store.begin(prepared);
    for _ in 0..3 {
        let (n, _) = store.create_node(prepared).expect("prepared node");
        store
            .add_label(prepared, n, person)
            .expect("prepared label");
        store
            .create_rel(prepared, knows, n, a)
            .expect("prepared edge");
    }

    // PREPARE only: the catalog checkpoint runs and the COMMIT record is appended, but no
    // `fdatasync` and no `maybe_checkpoint` — the exact window between `checkpoint_meta` and the
    // group-commit harden (`rmp` #528).
    let commit_lsn = store
        .commit_prepare(prepared)
        .expect("prepare must run the catalog checkpoint");
    assert!(
        commit_lsn.is_some(),
        "the prepared transaction wrote records, so it must NOT take the `rmp` #529 read-only fast \
         path — otherwise no checkpoint ran and this scenario is vacuous"
    );
    // Harden the prepared bytes, then decide how much of the tail the crash keeps.
    store.with_wal(WalManager::flush);

    // The COMMIT record is the LAST thing `commit_prepare` appended, so dropping the final byte tears
    // exactly that record and nothing before it: ARIES analysis stops at the last intact record.
    let truncate_by = match fate {
        CommitRecordFate::Hardened => 0,
        CommitRecordFate::TornOff => 1,
    };
    let (nodes, rels) = match fate {
        CommitRecordFate::Hardened => (5, 4),
        CommitRecordFate::TornOff => (2, 1),
    };
    crash_and_report(
        store,
        crash,
        truncate_by,
        POOL_CAPACITY,
        Counters::expected(person, knows, nodes, rels),
    )
}

// -------------------------------------------------------------------------------------------------
// Crash + recovery spine (mirrors `catalog_rollback_undo`'s, with the recovery report retained)
// -------------------------------------------------------------------------------------------------

/// A fresh store over an empty in-memory device + log.
fn create_store(capacity: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, capacity, 1).expect("create store")
}

/// Crashes `store` per `crash`, dropping `truncate_by` bytes from the durable WAL tail, recovers,
/// and reports the recovered counters against all three oracles.
fn crash_and_report(
    store: Store,
    crash: Crash,
    truncate_by: usize,
    capacity: usize,
    expected: Counters,
) -> CountReport {
    let (mut recovered, report) = match crash {
        Crash::NoForce => crash_no_force(&store, truncate_by, capacity),
        Crash::Steal => crash_steal(store, truncate_by, capacity),
    };
    CountReport {
        recovered: Counters::from_statistics(&recovered),
        recovered_rescan: Counters::by_rescan(&mut recovered),
        recovered_visible: Counters::by_visible_scan(&mut recovered),
        expected,
        recovered_counts_match_committed_image: recovered.counts_match_committed_image(),
        recovery_losers: report.losers,
        recovery_clrs: report.clrs_written,
        recovery_tail_truncated: report.tail_truncated,
    }
}

/// No-force crash: rebuild onto a fresh empty device from the durable WAL prefix (optionally torn),
/// then reopen.
fn crash_no_force(
    store: &Store,
    truncate_by: usize,
    capacity: usize,
) -> (Store, graphus_wal::RecoveryReport) {
    let mut log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    log.truncate(log.len().saturating_sub(truncate_by));
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");

    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    let report = graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    (
        RecordStore::open(device, wal, capacity).expect("open store"),
        report,
    )
}

/// Steal crash: flush dirty pages home (stealing the open transaction's uncommitted pages onto the
/// durable image), snapshot that image, then recover so undo rolls those pages back.
fn crash_steal(
    mut store: Store,
    truncate_by: usize,
    capacity: usize,
) -> (Store, graphus_wal::RecoveryReport) {
    store.flush().expect("flush (steal)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for p in &pages {
        let bytes = store.read_device_page(*p).expect("read device page");
        device.write_page(PageId(p.0), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");

    let mut log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    log.truncate(log.len().saturating_sub(truncate_by));
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    let report = graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    (
        RecordStore::open(device, wal, capacity).expect("open store"),
        report,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A write I/O error inside the commit-time catalog checkpoint must leave the faulting
    /// transaction's count delta withdrawable, and its rollback must withdraw exactly that delta —
    /// through a crash and recovery.
    #[test]
    fn an_io_error_in_the_catalog_checkpoint_leaves_the_count_delta_withdrawable() {
        for ending in BystanderEnding::all() {
            let report = run_io_error_at_catalog_checkpoint(ending);
            // Non-vacuity first: if the fault never fired, or fired somewhere other than inside
            // `checkpoint_meta`, everything below proves nothing.
            assert!(
                report.fault_surfaced,
                "{ending:?}: the armed write I/O error never surfaced — the commit succeeded, so \
                 `checkpoint_meta` performed no device write and this run is vacuous: {report:?}"
            );
            assert!(
                report.failed_before_commit_record,
                "{ending:?}: the WAL has no open entry for the faulting transaction, so a COMMIT \
                 record WAS appended — the fault fired after `commit_at_no_sync`, not inside \
                 `checkpoint_meta`: {report:?}"
            );
            assert!(
                report.counters_after_failed_commit != report.counters_after_rollback,
                "{ending:?}: the rollback withdrew nothing, so there was no pending delta to \
                 withdraw and the scenario is vacuous: {report:?}"
            );
            // The `rmp` #866 ordering invariant, stated on its own so a failure names the cause.
            assert!(
                report.txn_still_active_after_failed_commit,
                "{ending:?}: the faulting transaction was removed from the active set before the \
                 catalog checkpoint, so its count delta can never be withdrawn (rmp #866): \
                 {report:?}"
            );
            assert_eq!(
                report.counters_after_rollback, report.expected_after_rollback,
                "{ending:?}: the rollback did not withdraw exactly its own delta (rmp #866): \
                 {report:?}"
            );
            assert!(
                report.holds(),
                "{ending:?}: counts invariant violated after the injected checkpoint fault \
                 (rmp #866): {report:?}"
            );
        }
    }

    /// The shortcut's gate must DECLINE while a writer is open: the eager counters carry that
    /// writer's uncommitted rows, so they are not what a fresh reader would count.
    #[test]
    fn the_count_shortcut_declines_while_a_writer_is_open() {
        for ending in BystanderEnding::all() {
            let report = run_io_error_at_catalog_checkpoint(ending);
            assert!(
                !report.counts_match_with_bystander_open,
                "{ending:?}: `counts_match_committed_image` reported true while a writer held a \
                 pending delta — the shortcut would serve a dirty read: {report:?}"
            );
            assert_ne!(
                report.visible_scan_with_bystander_open, report.counters_after_rollback,
                "{ending:?}: the visible scan equals the eager counters, so the open writer moved \
                 nothing a reader could not see — the gate assertion above is vacuous: {report:?}"
            );
            assert!(
                report.recovery.recovered_counts_match_committed_image,
                "{ending:?}: recovery left a pending count delta behind: {report:?}"
            );
        }
    }

    /// A committing transaction's checkpoint must never publish a concurrent open transaction's
    /// counts — including when the crash STEALS that transaction's dirty pages home first, so undo
    /// runs against a real page image.
    #[test]
    fn a_checkpoint_never_publishes_a_stolen_transactions_counts() {
        for ending in BystanderEnding::all() {
            for crash in [Crash::NoForce, Crash::Steal] {
                let report = run_stolen_pages_vs_checkpointed_counts(ending, crash);
                assert_ne!(
                    report.live_counters_at_checkpoint, report.committed_counters_at_checkpoint,
                    "{ending:?}/{crash:?}: the bystander held no delta at the checkpoint, so the \
                     strip had nothing to strip and the run is vacuous: {report:?}"
                );
                // Only `LeftOpen` is in flight AT the crash, so only it makes recovery's undo phase
                // run. `RollsBack` compensated live (its CLRs are already in the durable log, which
                // redo re-applies), and `Commits` is a winner — for both, a loser count of zero is
                // the correct outcome, not a vacuous one.
                if ending == BystanderEnding::LeftOpen {
                    // The strip's teeth, stated as a value comparison: a checkpoint that did NOT
                    // strip the open bystander would have persisted exactly
                    // `live_counters_at_checkpoint` (plus the committer's own delta). Recovering
                    // something strictly smaller is the proof that it stripped.
                    assert_ne!(
                        report.recovery.recovered, report.live_counters_at_checkpoint,
                        "{ending:?}/{crash:?}: the recovered counters equal the LIVE image at the \
                         checkpoint, i.e. the open bystander's uncommitted delta was published into \
                         the durable catalog (rmp #866 `committed_statistics` counts strip): \
                         {report:?}"
                    );
                    assert!(
                        report.recovery.recovery_losers > 0,
                        "{ending:?}/{crash:?}: recovery rolled nothing back, so the bystander's \
                         rows were simply absent and undo was never exercised: {report:?}"
                    );
                    assert!(
                        report.recovery.recovery_clrs > 0,
                        "{ending:?}/{crash:?}: undo wrote no compensation records, so it found \
                         nothing to compensate — with the steal flavour that would mean the dirty \
                         pages never reached the durable image: {report:?}"
                    );
                }
                assert!(
                    report.holds(),
                    "{ending:?}/{crash:?}: counts invariant violated across a stolen-page crash \
                     (rmp #866): {report:?}"
                );
            }
        }
    }

    /// A crash between `checkpoint_meta` and the COMMIT harden must revert the loser's checkpointed
    /// counts — and, from the same code path, a hardened COMMIT record must keep them.
    #[test]
    fn a_torn_commit_record_reverts_the_checkpointed_counts() {
        for crash in [Crash::NoForce, Crash::Steal] {
            let winner =
                run_crash_between_checkpoint_and_commit_harden(CommitRecordFate::Hardened, crash);
            let loser =
                run_crash_between_checkpoint_and_commit_harden(CommitRecordFate::TornOff, crash);
            // The pairing is the non-vacuity proof: the winner shows the checkpoint really did
            // persist the transaction's counts, so the loser's baseline can only come from that same
            // checkpoint being undone.
            assert_ne!(
                winner.recovered, loser.recovered,
                "{crash:?}: the winner and the loser recovered the same counters, so tearing the \
                 COMMIT record changed nothing and the scenario is vacuous: {winner:?} / {loser:?}"
            );
            assert!(
                !winner.recovery_tail_truncated,
                "{crash:?}: the winner's log must be intact: {winner:?}"
            );
            assert!(
                loser.recovery_tail_truncated,
                "{crash:?}: the loser's durable log was not torn, so its COMMIT record survived and \
                 it is not a loser at all: {loser:?}"
            );
            assert!(
                loser.recovery_losers > 0 && loser.recovery_clrs > 0,
                "{crash:?}: undo did no work on the loser: {loser:?}"
            );
            assert!(
                winner.holds(),
                "{crash:?}: a hardened COMMIT record lost its checkpointed counts (rmp #866): \
                 {winner:?}"
            );
            assert!(
                loser.holds(),
                "{crash:?}: a loser's checkpointed counts survived recovery (rmp #866): {loser:?}"
            );
        }
    }

    /// Same input ⇒ identical report, for every runner (no clock, no threads, no randomness).
    #[test]
    fn reproduction_is_deterministic() {
        for ending in BystanderEnding::all() {
            assert_eq!(
                run_io_error_at_catalog_checkpoint(ending),
                run_io_error_at_catalog_checkpoint(ending),
                "{ending:?}: the injected-checkpoint-fault reproduction is not deterministic"
            );
            for crash in [Crash::NoForce, Crash::Steal] {
                assert_eq!(
                    run_stolen_pages_vs_checkpointed_counts(ending, crash),
                    run_stolen_pages_vs_checkpointed_counts(ending, crash),
                    "{ending:?}/{crash:?}: the stolen-page reproduction is not deterministic"
                );
            }
        }
        for fate in CommitRecordFate::all() {
            for crash in [Crash::NoForce, Crash::Steal] {
                assert_eq!(
                    run_crash_between_checkpoint_and_commit_harden(fate, crash),
                    run_crash_between_checkpoint_and_commit_harden(fate, crash),
                    "{fate:?}/{crash:?}: the torn-COMMIT reproduction is not deterministic"
                );
            }
        }
    }
}
