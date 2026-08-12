//! Focused deterministic reproducer for **node label membership not being snapshot-isolated**
//! (`rmp` #767) — the direct sibling of [`crate::label_rollback_clobber`] (`rmp` #772), which covers
//! the *write* side of the same in-place-mutated `labels` word.
//!
//! ## The defect
//!
//! A node's label set is a `u64` bitmap **inside** the node record, mutated in place. A property, by
//! contrast, is a separate `PropRecord` carrying its own MVCC header, so a property overwrite
//! MVCC-tombstones the old version and prepends the new one (`rmp` #50) and a reader resolves
//! newest-**visible**-wins. The label word had no version at all, so `graphus_txn::is_visible` had
//! nothing to filter and every label read returned whatever the word held at that instant. Two
//! anomalies followed:
//!
//! * **dirty read** — an UNCOMMITTED writer's label change was visible to any concurrent reader,
//!   which is below READ COMMITTED;
//! * **non-repeatable read** — a COMMITTED `REMOVE n:L` was visible to a reader whose snapshot
//!   predated the commit, so one transaction's `MATCH (n:L)` could return a node and then stop.
//!
//! Both are excluded by Snapshot Isolation, the weakest tier `docs/transactions.md` documents.
//!
//! ## Why the DST, not the generic harness
//!
//! The anomalies need statement-interleaved transactions over one node observed at **several explicit
//! snapshot timestamps** — a seed committing a labelled node; a writer changing the label and staying
//! *open*; then the same writer committing. Driven at the [`RecordStore`] layer (below the
//! coordinator, on the unguarded `IsolationLevel::Snapshot` path) it is fully deterministic.
//!
//! ## The invariant asserted
//!
//! `label_bitmap_at(n, live, snapshot, registry)` returns the label word **as of `snapshot`**:
//! the pre-change value while the writer is open (any other reader) and for every snapshot older than
//! its commit; the post-change value for the writer itself and for snapshots at or after the commit.
//!
//! ## The crash variant proves the durability claim
//!
//! The retained versions are **durable**: since `rmp` #968 an older label membership is an
//! `AddLabel` / `RemoveLabel` undo delta on the node's own chain, so it is WAL-logged and recovered
//! like every other record. That is asserted rather than assumed: after a crash and recovery the
//! node's label versions are STILL PRESENT, and a fresh reader observes the correct COMMITTED label
//! set, the word itself having been restored by the ARIES undo (`rmp` #772's CAS logical undo).
//!
//! The in-memory design claimed the opposite — that after a crash the history is EMPTY and the
//! recovered word is authoritative on its own — and that claim was an argument for why the versions
//! could be *lost*, not a durability guarantee. Asserting its inverse is what makes the difference
//! between the two designs observable rather than merely described.

use graphus_core::{PageId, Timestamp, TxnId};
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::RecordStore;
use graphus_txn::Snapshot;
use graphus_wal::{LogSink, MemLogSink, WalManager};

/// The store type the reproducer drives.
type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A small buffer-pool capacity, so eviction + the WAL rule are exercised during the run.
const POOL_CAPACITY: usize = 16;
/// The single label bit the writer removes.
const LABEL_BIT: u32 = 0;

fn next_txn(next: &mut u64) -> TxnId {
    let id = TxnId(*next);
    *next += 1;
    id
}

/// Whether `LABEL_BIT` is set in `bitmap`.
fn has_bit(bitmap: u64) -> bool {
    bitmap & (1u64 << LABEL_BIT) != 0
}

/// One reproduction's observations. Every field is "does node `n` carry the label, as seen by ...".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelSnapshotReport {
    /// A concurrent reader, while the writer's `remove_label` is still UNCOMMITTED. Must be `true`
    /// (the committed state). `false` is the DIRTY READ.
    pub other_reader_while_writer_open: bool,
    /// The writer itself, reading its own uncommitted change. Must be `false` (own-writes visibility).
    pub writer_sees_own_change: bool,
    /// A reader whose snapshot predates the writer's commit, read AFTER that commit. Must be `true`.
    /// `false` is the NON-REPEATABLE READ.
    pub older_reader_after_commit: bool,
    /// A reader whose snapshot is at/after the commit. Must be `false` (the change is visible).
    pub newer_reader_after_commit: bool,
}

impl LabelSnapshotReport {
    /// The `rmp` #767 invariant: no dirty read, no non-repeatable read, own writes visible, and the
    /// committed change visible to snapshots at or after it.
    #[must_use]
    pub fn snapshot_isolated(&self) -> bool {
        self.other_reader_while_writer_open
            && !self.writer_sees_own_change
            && self.older_reader_after_commit
            && !self.newer_reader_after_commit
    }
}

/// Resolves node `n`'s label bitmap as seen by `(owner, ts)`.
fn sees_label(store: &Store, n: u64, owner: TxnId, ts: u64) -> bool {
    let rec = store.node(n).expect("read node n");
    let snapshot = Snapshot::new(owner, Timestamp(ts));
    has_bit(
        store
            .label_bitmap_at(n, rec.labels, rec.mvcc.undo_ptr, snapshot)
            .expect("resolve n's labels from its undo chain"),
    )
}

/// Drives the interleaving and returns `(store, node_id, report)`.
///
/// Timeline: the seed commits the labelled node at `seed_ts`; a writer removes the label and stays
/// open (observed there); the writer commits at `commit_ts`; both an older and a newer snapshot are
/// then observed.
fn drive_scenario() -> (Store, u64, LabelSnapshotReport) {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");
    let mut next = 1u64;

    // Seed: a committed node carrying the label.
    let t0 = next_txn(&mut next);
    store.begin(t0);
    let (n, _eid) = store.create_node(t0).expect("create node");
    store.add_label(t0, n, LABEL_BIT).expect("seed label");
    store.commit(t0).expect("seed commits");
    let seed_ts = store.snapshot_ts().0;

    // A reader that exists BEFORE the writer touches anything.
    let reader = next_txn(&mut next);

    // W1: remove the label, left OPEN.
    let w1 = next_txn(&mut next);
    store.begin(w1);
    store.remove_label(w1, n, LABEL_BIT).expect("W1 remove");

    // THE DIRTY READ probe: a concurrent reader must still see the committed label.
    let other_reader_while_writer_open = sees_label(&store, n, reader, seed_ts);
    // Own-writes visibility: W1 must see its own removal.
    let writer_sees_own_change = sees_label(&store, n, w1, seed_ts);

    // W1 commits.
    store.commit(w1).expect("W1 commits");
    let commit_ts = store.snapshot_ts().0;

    // THE NON-REPEATABLE READ probe: the reader's snapshot predates the commit.
    let older_reader_after_commit = sees_label(&store, n, reader, seed_ts);
    // And a snapshot at/after the commit correctly sees the removal.
    let newer_reader_after_commit = sees_label(&store, n, reader, commit_ts);

    let report = LabelSnapshotReport {
        other_reader_while_writer_open,
        writer_sees_own_change,
        older_reader_after_commit,
        newer_reader_after_commit,
    };
    (store, n, report)
}

/// Runs the live reproduction and reports what each snapshot observed.
#[must_use]
pub fn run_label_snapshot_visibility() -> LabelSnapshotReport {
    let (_store, _n, report) = drive_scenario();
    report
}

/// Runs the reproduction, then **crashes** (no-force or steal) and recovers.
///
/// Returns `(label_present_after_recovery, label_versions_absent_after_recovery)`. The committed
/// state is "label removed", so after recovery the word must read as removed — and the node's label
/// versions must STILL BE THERE, which is the point: since `rmp` #968 they are undo deltas, WAL-logged
/// and recovered like every other record, so a reader that outlives a restart can still be served.
#[must_use]
pub fn run_label_snapshot_visibility_crash(steal: bool) -> (bool, bool) {
    let (store, n, _report) = drive_scenario();
    store.with_wal(WalManager::flush);
    let store = if steal {
        crash_steal(store)
    } else {
        crash_no_force(store)
    };
    let live = store.node(n).expect("read node n").labels;
    let history_empty = store
        .live_label_delta_census()
        .expect("census the undo area")
        .0
        == 0;
    store.flush().expect("flush after recovery");
    (has_bit(live), history_empty)
}

/// No-force crash: rebuild onto a fresh empty device from the durable WAL prefix, then reopen.
fn crash_no_force(store: Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

/// Steal crash: flush dirty pages home, snapshot that on-disk image, then recover.
fn crash_steal(store: Store) -> Store {
    store.flush().expect("flush (steal)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for p in &pages {
        let bytes = store.read_device_page(*p).expect("read device page");
        device.write_page(PageId(p.0), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");

    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

/// Drives the **physical-id-reuse** scenario and returns
/// `(reused_id_matched, resolved_bitmap, expected_bitmap)`.
///
/// The hazard this pins, in the shape the in-memory design had it: an IN-FLIGHT label writer's
/// retained version is (correctly) unprunable — its stamp resolves to no commit timestamp — so a GC
/// pass cannot collapse it. Were that writer's node meanwhile deleted by another transaction and its
/// slot reclaimed, the retained version would outlive the node. Physical ids are reused (`04 §2.7`),
/// so a brand-new node would then inherit it — permanently, because the id-keyed resolver preferred a
/// retained entry over the live word while the new node retained no version of its own.
///
/// `rmp` #968 closes both halves, and the scenario pins both. The retained version is now an undo
/// delta on the record's **own chain**, which is reclaimed with the record, so a reused slot starts at
/// `undo_ptr == 0` and has nothing to inherit; and the in-flight relabeller holds the node's chain, so
/// the concurrent delete is REFUSED with a retriable write-write conflict — which makes the dangerous
/// ordering unreachable rather than merely harmless. Id reuse is still exercised end to end: it
/// remains the thing that must not leak.
#[must_use]
pub fn run_reclaimed_id_reuse() -> (bool, u64, u64) {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store: Store =
        RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");
    let mut next = 1u64;

    let person = LABEL_BIT;
    let company = LABEL_BIT + 1;

    // Seed a committed node carrying `person`, then drain the history so the run starts clean.
    let t0 = next_txn(&mut next);
    store.begin(t0);
    let (n, _eid) = store.create_node(t0).expect("create node");
    store.add_label(t0, n, person).expect("seed label");
    store.commit(t0).expect("seed commits");
    let wm = store.snapshot_ts();
    gc_at(&mut store, next_txn(&mut next), wm);

    // An IN-FLIGHT relabeller retains a version for `n` that no GC pass can collapse.
    let t_relabel = next_txn(&mut next);
    store.begin(t_relabel);
    store
        .remove_label(t_relabel, n, person)
        .expect("in-flight relabel");

    // A DIFFERENT transaction tries to delete `n`. When this scenario was written the storage layer
    // imposed no guard here, and that was the whole exposure: the delete could commit *under* an
    // in-flight relabeller, the slot could then be reclaimed and reused, and the version the
    // relabeller had retained — keyed on the node **id** in the in-process `LabelHistory` — would be
    // inherited by whatever new node popped that id.
    //
    // `rmp` #968 closes both halves at once. The relabeller now holds the node's undo chain, so the
    // delete is REFUSED; and the retained version no longer lives in an id-keyed side map but on the
    // record's own chain, which is reclaimed with the record, so a reused slot starts at
    // `undo_ptr == 0` and has nothing to inherit. The scenario keeps testing id reuse — it is still
    // the thing that must not leak — and additionally pins the refusal that now makes the dangerous
    // ordering unreachable.
    let t_del = next_txn(&mut next);
    store.begin(t_del);
    let refused = store
        .delete_node(t_del, n)
        .expect_err("the delete must be refused while an in-flight relabeller holds the node");
    assert!(
        format!("{refused}").contains("write-write conflict"),
        "the refusal must be the retriable serialization failure, not a fatal error: {refused}",
    );
    store.rollback(t_del).expect("abandon the refused delete");

    // The relabeller commits, releasing the node...
    store.commit(t_relabel).expect("relabeller commits");

    // ...and only then can the delete succeed. The id becomes reclaimable exactly as before.
    let t_del2 = next_txn(&mut next);
    store.begin(t_del2);
    store
        .delete_node(t_del2, n)
        .expect("with no holder the same delete is allowed");
    store.commit(t_del2).expect("delete commits");

    // A GC pass at the full watermark reclaims `n`'s slot.
    let wm = store.snapshot_ts();
    gc_at(&mut store, next_txn(&mut next), wm);

    // A brand-new, unrelated node pops the freed id.
    let t_new = next_txn(&mut next);
    store.begin(t_new);
    let (m, _eid) = store.create_node(t_new).expect("create new node");
    store.add_label(t_new, m, company).expect("new label");
    store.commit(t_new).expect("new node commits");

    let rec = store.node(m).expect("read new node");
    let snapshot = Snapshot::new(TxnId(9_999), store.snapshot_ts());
    let resolved = store
        .label_bitmap_at(m, rec.labels, rec.mvcc.undo_ptr, snapshot)
        .expect("resolve m's labels from its undo chain");
    (m == n, resolved, 1u64 << company)
}

/// Runs one GC pass at `watermark`, as the engine's maintenance tick does.
fn gc_at(store: &mut Store, txn: TxnId, watermark: Timestamp) {
    store.begin(txn);
    store.gc(txn, watermark).expect("gc");
    store.commit(txn).expect("gc commit");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_reads_are_snapshot_isolated() {
        let report = run_label_snapshot_visibility();
        assert!(
            report.snapshot_isolated(),
            "rmp #767: label membership is not snapshot-isolated: {report:?}"
        );
    }

    /// Each anomaly named individually, so a regression says WHICH one came back.
    #[test]
    fn each_anomaly_is_named() {
        let r = run_label_snapshot_visibility();
        assert!(
            r.other_reader_while_writer_open,
            "rmp #767 DIRTY READ: a concurrent reader saw an UNCOMMITTED label removal"
        );
        assert!(
            !r.writer_sees_own_change,
            "own-writes visibility broken: the writer must see its own uncommitted label removal"
        );
        assert!(
            r.older_reader_after_commit,
            "rmp #767 NON-REPEATABLE READ: a snapshot older than the commit saw the removal"
        );
        assert!(
            !r.newer_reader_after_commit,
            "a snapshot at/after the commit must see the removal"
        );
    }

    /// **`rmp` #968 acceptance criterion 4, and the assertion that INVERTED.**
    ///
    /// It used to read "after a crash the history is EMPTY and the recovered word is authoritative on
    /// its own" — the in-memory-only design's central claim, which rested on no reader surviving a
    /// restart. That claim was true but it was an argument for why the versions could be *lost*, not a
    /// durability guarantee: the labels were simply not versioned on disk.
    ///
    /// Since #968 a label version is an undo delta, so it is WAL-logged and recovered like every other
    /// record. The recovered store therefore carries the versions, and that is the criterion: a node
    /// with label changes survives a restart **with** the versions an active reader could ask for.
    /// Asserting the inverse of the old claim is what makes the difference between the two designs
    /// observable rather than merely described.
    #[test]
    fn label_versions_survive_a_crash() {
        for steal in [false, true] {
            let (label_present, no_label_versions) = run_label_snapshot_visibility_crash(steal);
            assert!(
                !label_present,
                "steal={steal}: the COMMITTED label removal did not survive recovery"
            );
            assert!(
                !no_label_versions,
                "steal={steal}: the recovered store must still carry the node's label versions — \
                 they are undo deltas now, so losing them across recovery would mean an older reader \
                 could not be served after a restart (`rmp` #968 AC4)"
            );
        }
    }

    /// A reclaimed and REUSED physical id must not inherit the dead node's labels.
    ///
    /// Found by an adversarial audit of the first #767 fix, which closed the read anomalies but left
    /// the history keyed by a bare physical id with nothing purging it on reclamation.
    #[test]
    fn a_reused_physical_id_does_not_inherit_the_dead_nodes_labels() {
        let (reused, resolved, expected) = run_reclaimed_id_reuse();
        // Non-vacuity: the scenario is meaningless unless the id was actually reused.
        assert!(
            reused,
            "the freed physical id was NOT reused, so this run proves nothing"
        );
        assert_eq!(
            resolved, expected,
            "rmp #767: a brand-new node inherited the DEAD node's label bitmap through the stranded \
             history of the physical id it reused (resolved {resolved:#b}, expected {expected:#b}). \
             An in-flight writer's version is unprunable, so the GC prune cannot clear it — \
             `reclaim_node` must purge the entry before the id reaches the free list."
        );
    }

    /// `rmp` #767, Finding 4 (adversarial audit), verified through the REAL store rather than by
    /// poking the version state directly: after the GC pass forgets every committed writer, a `prune`
    /// at the MAXIMUM watermark must drain the node's live label deltas to zero.
    ///
    /// While versions carried raw in-flight stamps this was impossible: a forgotten writer's version
    /// had no resolvable commit timestamp, so no watermark could ever collapse it. The version leaked
    /// for the life of the process and kept the label fast-path gate armed, putting a lock + map lookup
    /// on every label re-check in the store.
    #[test]
    fn a_max_watermark_prune_drains_the_label_deltas_after_the_registry_forgets() {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let mut store: Store =
            RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");
        let mut next = 1u64;

        // A committed node, then a SECOND committed transaction relabels it (so a version is retained
        // — a node relabelled by its own creator is deliberately not tracked).
        let t0 = next_txn(&mut next);
        store.begin(t0);
        let (n, _eid) = store.create_node(t0).expect("create node");
        store.add_label(t0, n, LABEL_BIT).expect("seed label");
        store.commit(t0).expect("seed commits");

        let t1 = next_txn(&mut next);
        store.begin(t1);
        store.remove_label(t1, n, LABEL_BIT).expect("relabel");
        store.commit(t1).expect("relabel commits");
        assert!(
            store.live_label_delta_census().expect("census").0 > 0,
            "precondition: relabelling an already-committed node must retain a version"
        );
        assert!(
            store.live_label_delta_census().expect("census").1 == 0,
            "rmp #767: commit must SETTLE the version — an in-flight stamp outliving its registry \
             entry is the Finding 1 defect"
        );

        // A GC pass at the full watermark: it freezes headers and forgets committed writers.
        let wm = store.snapshot_ts();
        gc_at(&mut store, next_txn(&mut next), wm);

        // The auditor's assertion, on the real store.
        assert_eq!(
            store.live_label_delta_census().expect("census").0,
            0,
            "rmp #767 Finding 4: the live label deltas must drain — an unsettled version is unprunable \
             at ANY watermark and leaks for the life of the process"
        );
        assert!(
            store.live_label_delta_census().expect("census").0 == 0,
            "rmp #767 Finding 4: the hot-path gate must disarm; a permanently armed gate puts a lock \
             + map lookup on every label re-check in the store"
        );
    }

    #[test]
    fn reproduction_is_deterministic() {
        assert_eq!(
            run_label_snapshot_visibility(),
            run_label_snapshot_visibility()
        );
    }
}
