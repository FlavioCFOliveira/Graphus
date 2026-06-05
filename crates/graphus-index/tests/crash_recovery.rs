//! Crash-recovery acceptance tests for the B+-tree (`04-technical-design.md` §6.4; task #15
//! acceptance criterion: *indexes recover consistently after a crash — committed entries survive,
//! uncommitted are rolled back*).
//!
//! A crash is modelled exactly like `graphus-storage/tests/crash_recovery.rs`: the durable WAL
//! prefix (everything a committed transaction's group-commit `fdatasync` hardened, `04 §4.2`) plus
//! an optional on-disk page image. Two policies are exercised:
//!
//! * **No-force** — the dirty index pages were *never* flushed home; recovery's redo must
//!   reconstruct every committed entry from the WAL alone, onto a fresh empty device.
//! * **Steal** — uncommitted dirty index pages *were* flushed to disk (the pool wrote them home
//!   only after the WAL rule hardened the log through their `page_lsn`, `04 §4.3`); recovery's undo
//!   must roll them back.
//!
//! After recovery onto the device, [`BTree::open`] re-reads the root from the recovered meta page
//! and the test asserts the recovered tree equals the committed model (a `BTreeMap`). There is no
//! separate index rebuild — indexes share one log and one recovery with the base store (`04 §6.4`).

use std::collections::BTreeMap;

use graphus_bufpool::BufferPool;
use graphus_core::capability::Rng;
use graphus_core::{PageId, TxnId};
use graphus_index::BTree;
use graphus_index::keycodec::encode_i64_bits;
use graphus_index::recovery::{SharedWal, recover_index_device};
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_sim::SimRng;
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Tree = BTree<MemBlockDevice, MemLogSink>;

fn key(k: i64) -> Vec<u8> {
    encode_i64_bits(k).to_vec()
}
fn val(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}
fn decode_i64(bytes: &[u8]) -> i64 {
    let arr: [u8; 8] = bytes.try_into().expect("8-byte key");
    (u64::from_be_bytes(arr) ^ 0x8000_0000_0000_0000) as i64
}

fn fresh(cap: usize) -> Tree {
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let shared = SharedWal::new(wal);
    let pool = BufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), cap);
    BTree::create(pool, shared).expect("create btree")
}

/// The durable WAL bytes (the group-committed log prefix) of a tree.
fn durable_log(tree: &Tree) -> Vec<u8> {
    tree.with_wal(|w| w.sink().durable_bytes().to_vec())
}

/// Reopens a tree from a recovered device + the durable log sink, sharing one WAL.
fn reopen_with_sink(device: MemBlockDevice, sink: MemLogSink, base: PageId) -> Tree {
    let wal = WalManager::open(sink).expect("reopen wal");
    let shared = SharedWal::new(wal);
    let pool = BufferPool::with_wal(device, shared.clone(), 64);
    BTree::open(pool, shared, base).expect("open tree")
}

/// Snapshots the tree's on-disk image into a fresh device for the steal scenario.
fn snapshot_device(tree: &mut Tree) -> MemBlockDevice {
    let pages = tree.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    let mut staged: Vec<(u64, Box<Page>)> = Vec::new();
    for p in &pages {
        staged.push((p.0, tree.read_device_page(*p).expect("read device page")));
    }
    for (idx, bytes) in staged {
        device.write_page(PageId(idx), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");
    device
}

#[test]
fn committed_entries_survive_a_no_force_crash() {
    let mut tree = fresh(8);
    let base = tree.base();
    let txn = TxnId(1);
    tree.with_wal(|w| {
        w.begin(txn);
    });
    let mut model = BTreeMap::new();
    for k in 0..500i64 {
        tree.insert(txn, &key(k), &val(k as u64)).expect("insert");
        model.insert(k, k as u64);
    }
    tree.with_wal(|w| w.commit(txn).expect("commit"));

    // Crash with NOTHING flushed home (no-force): rebuild from the WAL alone.
    let log = durable_log(&tree);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_index_device(&mut wal, &mut device).expect("recover");

    let mut rec = reopen_with_sink(device, sink, base);
    rec.check_invariants().expect("recovered invariants");

    // Every committed entry survived.
    for (k, v) in &model {
        assert_eq!(
            rec.lookup(&key(*k)).expect("lookup"),
            Some(val(*v)),
            "committed key {k} lost after no-force crash"
        );
    }
    // The recovered ordered scan equals the committed model.
    let scanned: Vec<(i64, u64)> = rec
        .scan_all()
        .expect("scan")
        .into_iter()
        .map(|(k, v)| (decode_i64(&k), u64::from_le_bytes(v.try_into().unwrap())))
        .collect();
    assert_eq!(
        scanned,
        model.into_iter().collect::<Vec<_>>(),
        "recovered tree must equal committed model"
    );
}

#[test]
fn uncommitted_entries_are_rolled_back_after_a_no_force_crash() {
    let mut tree = fresh(8);
    let base = tree.base();

    // T1 commits some entries.
    let t1 = TxnId(1);
    tree.with_wal(|w| {
        w.begin(t1);
    });
    let mut model = BTreeMap::new();
    for k in 0..100i64 {
        tree.insert(t1, &key(k), &val(k as u64)).expect("insert");
        model.insert(k, k as u64);
    }
    tree.with_wal(|w| w.commit(t1).expect("commit"));

    // T2 inserts more but NEVER commits (a loser). Harden its tail so the crash log carries it.
    let t2 = TxnId(2);
    tree.with_wal(|w| {
        w.begin(t2);
    });
    for k in 100..300i64 {
        tree.insert(t2, &key(k), &val(k as u64)).expect("insert");
    }
    tree.with_wal(WalManager::flush);

    // Recover no-force.
    let log = durable_log(&tree);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    let report = recover_index_device(&mut wal, &mut device).expect("recover");
    assert_eq!(report.losers, 1, "T2 must be a recovered loser");

    let mut rec = reopen_with_sink(device, sink, base);
    rec.check_invariants().expect("recovered invariants");

    // Committed entries survive; uncommitted ones are gone.
    for k in 0..100i64 {
        assert_eq!(rec.lookup(&key(k)).expect("lookup"), Some(val(k as u64)));
    }
    for k in 100..300i64 {
        assert_eq!(
            rec.lookup(&key(k)).expect("lookup"),
            None,
            "uncommitted key {k} must be rolled back"
        );
    }
    let scanned: Vec<i64> = rec
        .scan_all()
        .expect("scan")
        .into_iter()
        .map(|(k, _)| decode_i64(&k))
        .collect();
    assert_eq!(scanned, model.keys().copied().collect::<Vec<_>>());
}

#[test]
fn committed_entries_survive_a_steal_crash() {
    let mut tree = fresh(8);
    let base = tree.base();
    let txn = TxnId(1);
    tree.with_wal(|w| {
        w.begin(txn);
    });
    let mut model = BTreeMap::new();
    for k in 0..400i64 {
        tree.insert(txn, &key(k), &val(k as u64)).expect("insert");
        model.insert(k, k as u64);
    }
    tree.with_wal(|w| w.commit(txn).expect("commit"));

    // Steal: flush the (committed) dirty pages home, snapshot the disk image.
    tree.flush().expect("flush");
    let mut device = snapshot_device(&mut tree);

    let log = durable_log(&tree);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_index_device(&mut wal, &mut device).expect("recover");

    let mut rec = reopen_with_sink(device, sink, base);
    rec.check_invariants().expect("recovered invariants");
    let scanned: Vec<(i64, u64)> = rec
        .scan_all()
        .expect("scan")
        .into_iter()
        .map(|(k, v)| (decode_i64(&k), u64::from_le_bytes(v.try_into().unwrap())))
        .collect();
    assert_eq!(scanned, model.into_iter().collect::<Vec<_>>());
}

#[test]
fn stolen_uncommitted_pages_are_undone_after_a_steal_crash() {
    let mut tree = fresh(8);
    let base = tree.base();

    // Committed baseline.
    let t1 = TxnId(1);
    tree.with_wal(|w| {
        w.begin(t1);
    });
    let mut model = BTreeMap::new();
    for k in 0..150i64 {
        tree.insert(t1, &key(k), &val(k as u64)).expect("insert");
        model.insert(k, k as u64);
    }
    tree.with_wal(|w| w.commit(t1).expect("commit"));

    // T2 inserts more, NEVER commits; flush home (steal) so its dirty pages reach disk.
    let t2 = TxnId(2);
    tree.with_wal(|w| {
        w.begin(t2);
    });
    for k in 150..400i64 {
        tree.insert(t2, &key(k), &val(k as u64)).expect("insert");
    }
    tree.with_wal(WalManager::flush);
    tree.flush().expect("flush (steal)");
    let mut device = snapshot_device(&mut tree);

    let log = durable_log(&tree);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_index_device(&mut wal, &mut device).expect("recover");

    let mut rec = reopen_with_sink(device, sink, base);
    rec.check_invariants().expect("recovered invariants");

    // Only the committed entries remain; the stolen uncommitted ones are undone.
    let scanned: Vec<i64> = rec
        .scan_all()
        .expect("scan")
        .into_iter()
        .map(|(k, _)| decode_i64(&k))
        .collect();
    assert_eq!(
        scanned,
        model.keys().copied().collect::<Vec<_>>(),
        "stolen uncommitted entries must be rolled back"
    );
}

#[test]
fn random_committed_then_crash_recovers_to_model() {
    // A randomised end-to-end check: random committed inserts/deletes, then a no-force crash, then
    // assert the recovered tree equals the model. Multiple seeds.
    for seed in 1..=8u64 {
        let mut rng = SimRng::new(seed);
        let mut tree = fresh(8);
        let base = tree.base();
        let mut model: BTreeMap<i64, u64> = BTreeMap::new();

        for batch in 0..4 {
            let txn = TxnId(seed * 10 + batch);
            tree.with_wal(|w| {
                w.begin(txn);
            });
            for _ in 0..60 {
                let r = rng.next_u64();
                let k = (r % 120) as i64 - 60;
                if r % 3 == 0 {
                    let removed = tree.delete(txn, &key(k)).expect("delete");
                    let m = model.remove(&k).is_some();
                    assert_eq!(removed, m);
                } else {
                    let v = rng.next_u64();
                    tree.insert(txn, &key(k), &val(v)).expect("insert");
                    model.insert(k, v);
                }
            }
            tree.with_wal(|w| w.commit(txn).expect("commit"));
        }

        let log = durable_log(&tree);
        let mut sink = MemLogSink::new();
        sink.append(&log);
        sink.sync().expect("sync");
        let mut device = MemBlockDevice::new(0);
        let mut wal = WalManager::open(sink.clone()).expect("open wal");
        recover_index_device(&mut wal, &mut device).expect("recover");

        let mut rec = reopen_with_sink(device, sink, base);
        rec.check_invariants().expect("invariants");
        let scanned: Vec<(i64, u64)> = rec
            .scan_all()
            .expect("scan")
            .into_iter()
            .map(|(k, v)| (decode_i64(&k), u64::from_le_bytes(v.try_into().unwrap())))
            .collect();
        assert_eq!(
            scanned,
            model.into_iter().collect::<Vec<_>>(),
            "seed {seed}: recovered tree must equal committed model"
        );
    }
}
