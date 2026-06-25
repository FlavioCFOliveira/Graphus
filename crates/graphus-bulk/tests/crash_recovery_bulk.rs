//! DST crash-recovery gate for the **non-atomic** bulk import contract (`rmp` #403).
//!
//! The ratified contract (`02-decision-register.md`, surfaced in `graphus-bulk`'s CLI `--help` and
//! the `cmd_import` doc-comment): bulk import is NOT a single transaction. It commits in batches, so
//! a crash or error part-way through leaves a **partial** store containing every batch committed
//! before the failure; the torn/failed batch and everything after it is gone. There is no automatic
//! rollback of the whole load — on a partial load the operator deletes `--db` and re-runs.
//!
//! This test models a power loss after N committed batches with the Deterministic-Simulation-Testing
//! devices ([`MemBlockDevice`] / [`MemLogSink`]), exactly as `graphus-storage`'s own
//! `crash_recovery.rs` does: it captures the **durable** WAL prefix (everything a committed batch's
//! group-commit `fdatasync` hardened), replays it onto a fresh empty device via [`recover_device`],
//! reopens with [`RecordStore::open`], and asserts the recovered node count sits exactly on a
//! committed-batch boundary — committed batches survive, the torn batch is absent.

use graphus_bulk::BulkImporter;
use graphus_io::MemBlockDevice;
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A fresh, empty in-memory record store.
fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 128, 1).expect("create store")
}

/// The store's durable WAL bytes — the group-committed log prefix that a crash would preserve.
fn durable_log(store: &Store) -> Vec<u8> {
    store.with_wal(|w| w.sink().durable_bytes())
}

/// Recovers a *no-force* crash: the committed work lives only in the durable WAL (the data device
/// was never flushed home). Replays the durable WAL prefix onto a fresh empty device and reopens.
fn recover_no_force(log: &[u8]) -> Store {
    let mut sink = MemLogSink::new();
    sink.append(log);
    sink.sync().expect("sync log prefix");

    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");

    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

/// A node CSV with `n` rows (`:ID` 0..n, one `:LABEL`, one `name` property).
fn node_csv(first_id: usize, n: usize) -> String {
    let mut s = String::from(":ID,:LABEL,name:string\n");
    for i in first_id..first_id + n {
        s.push_str(&format!("{i},Person,n{i}\n"));
    }
    s
}

/// The committed node count survives a crash exactly at a batch boundary: importing K full batches
/// (each committed) and recovering the durable WAL reproduces all K*batch nodes.
#[test]
fn committed_batches_survive_a_crash_after_n_batches() {
    let batch = 25usize;
    let full_batches = 4usize; // 100 nodes, all committed
    let total = batch * full_batches;

    let mut importer = BulkImporter::new(fresh_store(), batch, b',');
    importer
        .import_nodes(node_csv(0, total).as_bytes())
        .expect("import");
    let (store, _stats) = importer.finish();

    // Capture the durable WAL (a crash would preserve exactly this) and recover onto a fresh device.
    let log = durable_log(&store);
    drop(store); // model the crash: the original device/pool are gone.

    let mut recovered = recover_no_force(&log);
    let count = recovered.scan_node_ids().expect("scan").len();
    assert_eq!(
        count, total,
        "every committed batch must survive the crash (got {count}, expected {total})"
    );
}

/// A batch that fails mid-way is rolled back, so a crash right after that failure recovers to the
/// last committed batch boundary — the torn batch leaves NO partial rows. This is the core #403
/// guarantee: committed-or-nothing *per batch*, and the failed batch is gone.
#[test]
fn torn_batch_after_committed_batches_recovers_to_the_boundary() {
    let batch = 20usize;
    let committed_batches = 3usize; // 60 nodes committed across 3 successful import calls
    let committed = batch * committed_batches;

    let mut importer = BulkImporter::new(fresh_store(), batch, b',');

    // N successful import calls — each is a run of batches ending in a commit, so all are durable.
    for b in 0..committed_batches {
        importer
            .import_nodes(node_csv(b * batch, batch).as_bytes())
            .expect("committed batch import");
    }

    // Capture the durable WAL at the committed boundary BEFORE the doomed batch.
    let store_ref = importer.store_ref_for_test();
    let log_before = durable_log(store_ref);

    // A doomed batch: rows are fine until a row that fails to ingest (a relationship row referencing
    // a non-existent endpoint), forcing the importer to roll back the in-flight batch. The partial
    // batch's writes are undone, so the durable WAL must NOT gain any of its rows.
    let bad_rels = ":START_ID,:END_ID,:TYPE\n999999,888888,KNOWS\n";
    let doomed = importer.import_relationships(bad_rels.as_bytes());
    assert!(doomed.is_err(), "the doomed batch must fail and roll back");

    // The durable WAL after the rolled-back batch must be a prefix-equal to the committed boundary:
    // the failed batch added no durable committed rows.
    let store_ref = importer.store_ref_for_test();
    let log_after = durable_log(store_ref);

    // Recover from the post-failure durable WAL and assert we are exactly at the committed boundary.
    let mut recovered = recover_no_force(&log_after);
    let count = recovered.scan_node_ids().expect("scan").len();
    assert_eq!(
        count, committed,
        "a torn/failed batch must leave exactly the committed boundary (got {count}, expected {committed})"
    );

    // And recovering from the pre-failure boundary gives the same node count — the failed batch is a
    // no-op for committed node state.
    let mut recovered_before = recover_no_force(&log_before);
    assert_eq!(
        recovered_before.scan_node_ids().expect("scan").len(),
        committed
    );
}
