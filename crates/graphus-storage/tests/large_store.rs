//! Large-store regression test for the paged catalog (`rmp` task #51).
//!
//! Before the fix, [`RecordStore`] serialised the entire durable catalog — dominated by each
//! store's store-relative-page → device-page map at 8 bytes per page — into the single 8 KiB
//! metadata page, and `commit` panicked (`region runs past the page`) once a store grew past
//! ~1000 record pages, capping a database at a few megabytes. The catalog now spans a singly-linked
//! chain of metadata pages, so it grows without bound.
//!
//! This test grows a store well past that old one-page cap, then proves the catalog (including its
//! high device-page ids) survives a crash + ARIES recovery and a clean consistency check.

use graphus_core::{TxnId, VersionStamp};
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_storage::check::verify_on_open;
use graphus_storage::recovery::recover_device;
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Replay the durable WAL prefix onto a fresh device and reopen — a no-force crash recovery.
fn recover_no_force(store: &Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 256).expect("open store")
}

#[test]
fn store_grows_far_past_the_one_page_catalog_cap_and_recovers() {
    // 135_000 node records at 65 B each is ~1080 node pages: comfortably past the ~1008-page point
    // where the encoded catalog (≈ node_pages * 8 B + overhead) exceeds one 8 KiB page payload, so
    // the catalog must spill onto at least one continuation page. This used to panic at commit.
    const NODES: u64 = 135_000;
    const BATCH: u64 = 15_000;

    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store = RecordStore::create(device, wal, 256, 1).expect("create store");

    let mut next_txn = 1u64;
    let mut created = 0u64;
    while created < NODES {
        let txn = TxnId(next_txn);
        next_txn += 1;
        store.begin(txn);
        let upto = (created + BATCH).min(NODES);
        while created < upto {
            let (id, _eid) = store.create_node(txn).expect("create node");
            created += 1;
            // Ids are dense and 1-based, allocated sequentially.
            assert_eq!(id, created, "node ids must be dense and sequential");
        }
        // The commit checkpoints the catalog across the metadata-page chain — the operation that
        // panicked before the fix once the catalog outgrew one page.
        store.commit(txn).expect("commit batch");
    }

    // The catalog needed more than one page: head + ≥1 continuation page, then the node pages.
    // (meta head = 1; a continuation page exists iff total mapped pages exceed 1 + node_pages, and
    // node_pages alone already exceed the old ~1008-page cap.)
    let pages_before = store.mapped_pages().len();
    assert!(
        pages_before > 1010,
        "store must have grown past the old one-page catalog cap, got {pages_before} pages"
    );

    // Every node is present and the catalog is internally consistent before the crash.
    assert_eq!(store.scan_node_ids().expect("scan").len() as u64, NODES);
    verify_on_open(&mut store, &[]).expect("store consistent before crash");

    // The highest-id node lives on one of the last device pages: reading it back proves the
    // node store's device-page map (the part that overflowed) is intact.
    let last = store.node(NODES).expect("read last node");
    assert!(
        last.mvcc.in_use(),
        "last node must be a live committed version"
    );
    assert!(
        matches!(
            VersionStamp::from_raw(last.mvcc.created_ts),
            VersionStamp::Committed(_)
        ),
        "last node's xmin must be settled to a commit timestamp"
    );

    // --- crash + ARIES recovery, then reopen ---
    let mut recovered = recover_no_force(&store);

    // The catalog round-trips: identical page set (continuation pages included), every node back,
    // and a clean consistency check on the recovered image.
    assert_eq!(
        recovered.mapped_pages().len(),
        pages_before,
        "the recovered catalog must map the same pages (chain included)"
    );
    assert_eq!(
        recovered
            .scan_node_ids()
            .expect("scan after recovery")
            .len() as u64,
        NODES,
        "every committed node must survive recovery"
    );
    verify_on_open(&mut recovered, &[]).expect("recovered store consistent");

    let first = recovered.node(1).expect("read first node after recovery");
    let last = recovered
        .node(NODES)
        .expect("read last node after recovery");
    assert!(first.mvcc.in_use() && last.mvcc.in_use());

    // The id high-water mark persisted across recovery: the next allocation continues the sequence.
    let txn = TxnId(next_txn);
    recovered.begin(txn);
    let (id, _eid) = recovered.create_node(txn).expect("create after recovery");
    assert_eq!(id, NODES + 1, "high-water mark must resume after recovery");
    recovered.commit(txn).expect("commit after recovery");
}
