//! **`rmp` #1086 — the checkpoint's redo floor and its reclaim floor are one decision.**
//!
//! The checkpoint stopped claiming to be sharp: it samples a conservative redo floor before its
//! flush and writes that floor into the `CHECKPOINT-END` record, so recovery starts redo there
//! instead of at the record's own LSN. That fix is only half a fix. The same method **physically
//! reclaims** the WAL prefix below a floor of its own, and if that floor were left at the checkpoint
//! record's LSN it would delete exactly the records redo now starts from — turning a durability fix
//! into a durability bug by way of the log no longer being there.
//!
//! This suite pins the coupling: **the reclaimed prefix never rises above the LSN recovery starts
//! redo at.**
//!
//! # Why it is here and not in the deterministic-scheduler suite
//!
//! Measured, not assumed. `graphus-dst`'s `det_scheduler_checkpoint_redo_floor_1086` is the suite
//! that reproduces the data loss, and with **only** the reclaim half of the fix reverted it comes
//! back GREEN over all its seeds — because in that workload every commit is still unfrozen, so
//! `unfrozen_commit_lsn` already clamps the reclaim floor below anything redo needs and the coupling
//! is never what decides. A control that cannot fail is not a control, so the reclaim half gets one
//! here, in the shape where it IS what decides: a store with no unfrozen commit to clamp it.

use graphus_core::TxnId;
use graphus_io::MemBlockDevice;
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

/// Buffer-pool frames — above the working set, so nothing here is about eviction.
const POOL_PAGES: usize = 64;

/// The LSN recovery would start redo at, recovered from the store's own durable log through the real
/// recovery pass rather than re-derived from the checkpoint record by hand.
fn redo_start_of(store: &RecordStore<MemBlockDevice, MemLogSink>) -> u64 {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync the durable log prefix");
    let mut wal = WalManager::open(sink).expect("open wal");
    let mut device = MemBlockDevice::new(0);
    recover_device(&mut wal, &mut device)
        .expect("ARIES recovery")
        .redo_start
        .0
}

/// The invariant, on a store whose commits are all still unfrozen: reclamation is clamped by them,
/// and the floors agree anyway. A regression guard rather than the biting case.
#[test]
fn the_reclaimed_prefix_stays_below_redo_start_with_unfrozen_commits() {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = RecordStore::create(device, wal, POOL_PAGES, 1).expect("create store");
    store.set_checkpoint_interval_bytes(0);

    let label = store
        .intern_token(Namespace::Label, "L")
        .expect("intern a label token");
    for i in 0..8u64 {
        let txn = TxnId(i + 1);
        store.begin(txn);
        let (node, _) = store.create_node(txn).expect("create a node");
        store.add_label(txn, node, label).expect("label the node");
        store.commit(txn).expect("commit");
    }

    store.checkpoint().expect("checkpoint");

    let reclaimed = store.with_wal(|w| w.sink().reclaimed_floor());
    let redo_start = redo_start_of(&store);
    assert!(
        reclaimed <= redo_start,
        "the checkpoint reclaimed the log up to {reclaimed} but recovery starts redo at \
         {redo_start}: the records between the two are gone and cannot be replayed"
    );
}

/// The **biting** case: nothing unfrozen to clamp the reclaim floor, so the floor is whatever the
/// checkpoint itself decides. With the reclaim half reverted to the checkpoint record's own LSN this
/// assertion fails, because that LSN is above the pre-flush floor the record now advertises.
#[test]
fn the_reclaimed_prefix_stays_below_redo_start_with_nothing_to_clamp_it() {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = RecordStore::create(device, wal, POOL_PAGES, 1).expect("create store");
    store.set_checkpoint_interval_bytes(0);

    // No write commit, so `unfrozen_commit_lsn` is empty and no active transaction floors anything:
    // the reclaim floor is decided by the checkpoint alone, which is the case under test.
    store.checkpoint().expect("checkpoint");

    let reclaimed = store.with_wal(|w| w.sink().reclaimed_floor());
    let redo_start = redo_start_of(&store);
    assert!(
        reclaimed <= redo_start,
        "with nothing else to clamp it the checkpoint reclaimed up to {reclaimed} while recovery \
         starts redo at {redo_start}: the reclaim floor and the redo floor have drifted apart, and \
         the log below {reclaimed} is the log redo was told to read"
    );
}
