//! Crash-recovery acceptance tests for [`graphus_storage::RecordStore`] (`rmp` task #13
//! acceptance criterion 1: *CRUD persists and recovers; committed-or-nothing after a crash*).
//!
//! A crash is modelled with the Deterministic-Simulation-Testing devices: the durable WAL prefix
//! (everything a committed transaction's group-commit `fdatasync` hardened, `04 §4.2`) plus a
//! disk image. Two policies are exercised at the storage layer, mirroring the WAL's own page-level
//! `aries_recovery.rs`:
//!
//! * **No-force** — the dirty data pages were *never* flushed home; recovery's redo must
//!   reconstruct every committed change from the WAL alone (onto a fresh empty device).
//! * **Steal** — uncommitted dirty pages *were* evicted/flushed to disk (the buffer pool wrote
//!   them home only after the WAL rule hardened the log through their `page_lsn`, `04 §4.3`);
//!   recovery's undo must roll them back.
//!
//! After recovery onto the device, [`RecordStore::open`] reloads the catalog and the test asserts
//! the graph state.

use graphus_core::TxnId;
use graphus_io::{MemBlockDevice, PAGE_SIZE, Page};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Builds a fresh store over an in-memory device + log.
fn fresh(cap: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

/// The durable WAL bytes of a store (its group-committed log prefix).
fn durable_log(store: &Store) -> Vec<u8> {
    store.with_wal(|w| w.sink().durable_bytes().to_vec())
}

/// Recovers a *no-force* crash: the committed work lives only in the durable WAL; the data device
/// was never flushed. Replays the WAL onto a fresh empty device, then opens the store.
fn recover_no_force(store: &Store) -> Store {
    let log = durable_log(store);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");

    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");

    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

/// Recovers a *steal* crash: `store` is flushed so its (committed *and* uncommitted) dirty pages
/// are on disk; the disk image and durable WAL are captured, then recovery rolls back the
/// uncommitted work.
fn recover_steal(store: &mut Store) -> Store {
    store.flush().expect("flush (steal: pages written home)");
    // Snapshot the on-disk image into a fresh device.
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    {
        // Stage each mapped page, then make them durable.
        let mut staged: Vec<(u64, Box<Page>)> = Vec::new();
        for p in &pages {
            staged.push((p.0, store.read_device_page(*p).expect("read device page")));
        }
        use graphus_io::BlockDevice;
        for (idx, bytes) in staged {
            device
                .write_page(graphus_core::PageId(idx), &bytes)
                .expect("stage page");
        }
        device.sync_all().expect("persist disk image");
    }

    let log = durable_log(store);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");

    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

/// Runs one committed garbage-collection pass over `s`: reclaims every tombstone whose `xmax`
/// committed at or before the current snapshot (`04 §5.5`). Under MVCC `delete_node`/`delete_rel`
/// only stamp a tombstone, so a physical id returns to the free list only here — and the
/// reclamation writes are WAL-logged, so committing this pass is what makes the freed-id state
/// durable and crash-recoverable. The snapshot timestamp is the correct watermark in these tests:
/// no older live reader exists, so every committed tombstone is reclaimable.
fn gc_pass(s: &mut Store, txn: TxnId) {
    let watermark = s.snapshot_ts();
    s.begin(txn);
    s.gc(txn, watermark).unwrap();
    s.commit(txn).unwrap();
}

#[test]
fn committed_nodes_and_edges_survive_a_no_force_crash() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, eid_a) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let (r, eid_r) = s.create_rel(txn, t, a, b).unwrap();
    s.commit(txn).unwrap();

    let mut rec = recover_no_force(&s);

    // Records and their stable identities survived.
    assert!(rec.node(a).unwrap().mvcc.in_use());
    assert_eq!(rec.node(a).unwrap().element_id, eid_a);
    assert_eq!(rec.rel(r).unwrap().element_id, eid_r);
    // Adjacency was reconstructed.
    assert_eq!(rec.incident_rels(a).unwrap(), vec![r]);
    assert_eq!(rec.incident_rels(b).unwrap(), vec![r]);
    // The reltype token recovered.
    assert_eq!(rec.token_id(Namespace::RelType, "KNOWS"), Some(t));
}

#[test]
fn uncommitted_work_is_rolled_back_after_a_no_force_crash() {
    let mut s = fresh(64);
    // T1 commits a node.
    let t1 = TxnId(1);
    s.begin(t1);
    let (a, _) = s.create_node(t1).unwrap();
    s.commit(t1).unwrap();

    // T2 creates a node + edge but never commits (a loser).
    let t2 = TxnId(2);
    s.begin(t2);
    let (b, _) = s.create_node(t2).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let _ = s.create_rel(t2, t, a, b).unwrap();
    // Harden the loser's tail so the crash log carries it (forces undo to run).
    s.with_wal(graphus_wal::WalManager::flush);

    let mut rec = recover_no_force(&s);

    // The committed node a survives; the loser's effects on a's chain are undone.
    assert!(rec.node(a).unwrap().mvcc.in_use());
    assert_eq!(
        rec.incident_rels(a).unwrap(),
        Vec::<u64>::new(),
        "the uncommitted edge must be rolled back"
    );
}

#[test]
fn committed_state_survives_a_steal_crash() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let (c, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let r1 = s.create_rel(txn, t, a, b).unwrap().0;
    let r2 = s.create_rel(txn, t, a, c).unwrap().0;
    s.commit(txn).unwrap();

    let mut rec = recover_steal(&mut s);

    let mut a_inc = rec.incident_rels(a).unwrap();
    a_inc.sort_unstable();
    let mut expect = vec![r1, r2];
    expect.sort_unstable();
    assert_eq!(a_inc, expect);
    assert!(rec.node(c).unwrap().mvcc.in_use());
}

#[test]
fn stolen_uncommitted_pages_are_undone_after_a_steal_crash() {
    let mut s = fresh(64);
    // Committed baseline: node a with one edge to b.
    let t1 = TxnId(1);
    s.begin(t1);
    let (a, _) = s.create_node(t1).unwrap();
    let (b, _) = s.create_node(t1).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let r_ab = s.create_rel(t1, t, a, b).unwrap().0;
    s.commit(t1).unwrap();

    // T2 adds another edge a -> b but never commits; its dirty pages will be flushed home (steal).
    let t2 = TxnId(2);
    s.begin(t2);
    let _r2 = s.create_rel(t2, t, a, b).unwrap();
    s.with_wal(graphus_wal::WalManager::flush);

    let mut rec = recover_steal(&mut s);

    // Only the committed edge remains; the stolen uncommitted one is undone.
    assert_eq!(rec.incident_rels(a).unwrap(), vec![r_ab]);
    assert_eq!(rec.incident_rels(b).unwrap(), vec![r_ab]);
}

#[test]
fn tokens_and_element_id_counter_recover() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let lbl = s.intern_token(Namespace::Label, "Person").unwrap();
    let key = s.intern_token(Namespace::PropKey, "name").unwrap();
    let (a, eid_a) = s.create_node(txn).unwrap();
    s.commit(txn).unwrap();

    let mut rec = recover_no_force(&s);
    assert_eq!(rec.token_id(Namespace::Label, "Person"), Some(lbl));
    assert_eq!(rec.token_id(Namespace::PropKey, "name"), Some(key));
    assert_eq!(rec.node(a).unwrap().element_id, eid_a);

    // A new node after recovery gets a *fresh* element id (never reused).
    let txn2 = TxnId(2);
    rec.begin(txn2);
    let (_b, eid_b) = rec.create_node(txn2).unwrap();
    rec.commit(txn2).unwrap();
    assert!(
        eid_b.0 > eid_a.0,
        "element ids continue past the recovered high-water"
    );
}

#[test]
fn committed_node_labels_survive_a_no_force_crash() {
    // `rmp` task #42: node labels are WAL-logged page patches of the node record, so they recover
    // exactly like any other committed node write.
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let admin = s.intern_token(Namespace::Label, "Admin").unwrap();
    s.set_node_labels(txn, a, &[person, admin]).unwrap();
    s.commit(txn).unwrap();

    let mut rec = recover_no_force(&s);
    // The label token namespace recovered, and the node's bitmap recovered with it.
    assert_eq!(rec.token_id(Namespace::Label, "Person"), Some(person));
    let mut ids = rec.node_labels(a).unwrap();
    ids.sort_unstable();
    let mut want = vec![person, admin];
    want.sort_unstable();
    assert_eq!(ids, want);
    assert!(rec.node_has_label(a, person).unwrap());
}

#[test]
fn label_mutations_recover_under_a_steal_crash() {
    // Build a committed labelled node, then steal-crash and recover: the committed bitmap is intact.
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let l = s.intern_token(Namespace::Label, "L").unwrap();
    s.add_label(txn, a, l).unwrap();
    s.commit(txn).unwrap();

    let mut rec = recover_steal(&mut s);
    assert_eq!(rec.node_labels(a).unwrap(), vec![l]);
}

#[test]
fn uncommitted_label_change_is_rolled_back_after_a_crash() {
    // Committed baseline: node a labelled :L.
    let mut s = fresh(64);
    let t1 = TxnId(1);
    s.begin(t1);
    let (a, _) = s.create_node(t1).unwrap();
    let l = s.intern_token(Namespace::Label, "L").unwrap();
    s.add_label(t1, a, l).unwrap();
    s.commit(t1).unwrap();

    // T2 adds a second label but never commits (a loser); harden its tail so undo runs.
    let t2 = TxnId(2);
    s.begin(t2);
    let m = s.intern_token(Namespace::Label, "M").unwrap();
    s.add_label(t2, a, m).unwrap();
    s.with_wal(graphus_wal::WalManager::flush);

    let mut rec = recover_no_force(&s);
    // Only the committed label survives; the uncommitted one is undone.
    assert_eq!(
        rec.node_labels(a).unwrap(),
        vec![l],
        "the uncommitted second label must be rolled back"
    );
}

#[test]
fn free_list_recovers_so_ids_keep_reusing() {
    let mut s = fresh(64);
    let t1 = TxnId(1);
    s.begin(t1);
    let (a, _) = s.create_node(t1).unwrap();
    let (b, _) = s.create_node(t1).unwrap();
    s.commit(t1).unwrap();
    let t2 = TxnId(2);
    s.begin(t2);
    s.delete_node(t2, b).unwrap(); // tombstones b (xmax); the physical id is NOT freed yet
    s.commit(t2).unwrap();
    // Under MVCC the physical id returns to the free list only at GC, not at delete. Run a committed
    // GC pass *before* the crash (the `recover_no_force` below) so the freed-id state is part of the
    // durable WAL prefix that recovery replays — that is the state this test asserts is recovered.
    gc_pass(&mut s, TxnId(3));

    let mut rec = recover_no_force(&s);
    // The freed id is still on the recovered free list and is reused first.
    let t4 = TxnId(4);
    rec.begin(t4);
    let (c, _) = rec.create_node(t4).unwrap();
    rec.commit(t4).unwrap();
    assert_eq!(c, b, "the recovered free list reuses the freed id");
    assert!(rec.node(a).unwrap().mvcc.in_use());

    let _ = PAGE_SIZE; // documents the page-size dependency exercised by the recovery path
}

// ============================================================================================
// Checkpointing bounds crash-recovery redo (storage audit F3).
// ============================================================================================

/// A checkpoint advances recovery's redo start past the WAL header and recovery still replays the
/// **post-checkpoint** committed work that was only in the WAL — proving the checkpoint bounds redo
/// without losing data. Models a real post-checkpoint no-force crash: the checkpoint flushed the
/// pre-checkpoint page home, later committed work lives only in the durable WAL.
#[test]
fn a_checkpoint_bounds_recovery_redo_and_replays_post_checkpoint_work() {
    use graphus_io::BlockDevice;
    use graphus_wal::HEADER_LEN;

    let mut s = fresh(64);
    s.set_checkpoint_interval_bytes(0); // manual checkpoints, for a precise redo_start assertion

    // Pre-checkpoint committed work.
    let t1 = TxnId(1);
    s.begin(t1);
    let (a, eid_a) = s.create_node(t1).unwrap();
    s.commit(t1).unwrap();

    // Sharp checkpoint: a's page is now durable on the device; redo can start here.
    s.checkpoint().unwrap();
    let ckpt_end = s.with_wal(|w| w.durable_len());

    // Snapshot the post-checkpoint device image (the pool is clean after the checkpoint, so a read
    // returns the durable device bytes — a's page is present, no later work is).
    let captured: Vec<(u64, Box<Page>)> = s
        .mapped_pages()
        .into_iter()
        .map(|p| (p.0, s.read_device_page(p).expect("read page")))
        .collect();

    // Post-checkpoint committed work — durable only in the WAL (NOT flushed to the device).
    let t2 = TxnId(2);
    s.begin(t2);
    let (b, eid_b) = s.create_node(t2).unwrap();
    s.commit(t2).unwrap();

    // Stage the post-checkpoint device image and replay the full durable WAL onto it.
    let max = captured.iter().map(|(i, _)| *i).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for (idx, bytes) in &captured {
        device
            .write_page(graphus_core::PageId(*idx), bytes)
            .expect("stage page");
    }
    device.sync_all().expect("persist image");

    let log = durable_log(&s);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    let report = recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    let mut rec = RecordStore::open(device, wal, 64).expect("open store");

    // Redo started at the checkpoint — well past the WAL header (bounded redo).
    assert!(
        report.redo_start.0 > HEADER_LEN,
        "redo must start past the WAL header, at the checkpoint (got {})",
        report.redo_start.0
    );
    assert!(
        report.redo_start.0 <= ckpt_end,
        "redo starts at the checkpoint, not later"
    );
    // The pre-checkpoint node survives via its flushed page; the post-checkpoint node is replayed
    // by redo from the WAL alone.
    assert_eq!(rec.node(a).unwrap().element_id, eid_a);
    assert!(rec.node(a).unwrap().mvcc.in_use());
    assert_eq!(rec.node(b).unwrap().element_id, eid_b);
    assert!(rec.node(b).unwrap().mvcc.in_use());
}

/// The automatic checkpoint cadence fires once enough WAL has accumulated: with a small interval, a
/// run of commits produces a checkpoint, so a later crash recovers with `redo_start` past the header.
#[test]
fn automatic_checkpoint_cadence_emits_a_checkpoint() {
    use graphus_wal::HEADER_LEN;

    let mut s = fresh(64);
    s.set_checkpoint_interval_bytes(200); // tiny interval ⇒ a checkpoint after a couple of commits

    let mut last = 0u64;
    for i in 1..=8u64 {
        let txn = TxnId(i);
        s.begin(txn);
        let (n, _) = s.create_node(txn).unwrap();
        last = n;
        s.commit(txn).unwrap();
    }

    // Recover via a steal crash (everything flushed): the report's redo_start must be a checkpoint
    // the automatic cadence emitted — past the WAL header.
    let mut rec = recover_steal(&mut s);
    assert!(
        rec.node(last).unwrap().mvcc.in_use(),
        "the last node survives"
    );

    // Re-derive the redo_start from the durable log to prove a checkpoint was emitted.
    let log = durable_log(&s);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink).expect("open wal");
    let report = recover_device(&mut wal, &mut device).expect("recover");
    assert!(
        report.redo_start.0 > HEADER_LEN,
        "the automatic cadence must have emitted at least one checkpoint (redo_start past header)"
    );
}
