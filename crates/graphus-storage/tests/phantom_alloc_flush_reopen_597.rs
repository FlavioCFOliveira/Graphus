//! **Regression gate for the `rmp` #597 durability/availability fix** — a transient device write error
//! that lands on the seed `flush_unlogged` home write of a **freshly page-boundary-extended** record
//! page must NOT brick the store on reopen.
//!
//! ## The bug this guards (real ACID/availability defect, now fixed)
//!
//! When a `CREATE` crosses a record-page boundary, `bufpool::ConcurrentBufferPool::new_page` `extend`s
//! the device (zero-filling the new page) and then the store seeds that page via `flush_unlogged` — the
//! **unlogged** home-write path, which by design skips the doublewrite stager. If a one-shot device
//! write error lands on that seed flush, the allocating txn aborts and `alloc_id` un-bumps the store's
//! high-water — but the physical `extend` is NOT undone. The result is an **all-zero, checksum-invalid**
//! trailing page on the device that no store maps, no WAL record covers (so ARIES redo cannot recreate
//! it), and no doublewrite copy protects. On the next open, `reconstruct_orphan_store_pages` scans every
//! device page `0..page_count`; **before the fix** it `fetch`ed each one, and `fetch`'s checksum gate
//! rejected the phantom zero page — so `RecordStore::open` failed with `page N failed checksum
//! verification`, **bricking a healthy database after nothing worse than a transient write error**. No
//! committed data was lost (the txn aborted); only reopen broke — a durability/availability violation of
//! Graphus's inviolable ACID mandate.
//!
//! The fix reads each orphan candidate **raw** (`ConcurrentBufferPool::read_page_unverified`) and
//! classifies a checksum-invalid page: an **all-zero** page is a harmless aborted-allocation phantom and
//! is **skipped** (it holds no committed data — every committed/logged page is already redo-materialised
//! by the time this scan runs); a **non-zero** bad checksum is genuine corruption and still **fails
//! closed** (never served — the corruption mandate is preserved).
//!
//! ## What this test pins
//!
//! Direct-store, single-thread, no engine/threads (isolating the storage primitive the DST simulator's
//! rich disk-fault model could exercise but this specific *whole-open* interaction was not covered by):
//!  1. The fault genuinely creates the phantom (a create fails, the device grew by one, the trailing page
//!     is all-zero and fails its checksum).
//!  2. **The store reopens cleanly** despite the phantom (the fix; **fails without it**).
//!  3. The reopened store is **structurally consistent** (`check_store`) and **every committed node
//!     survives** (no committed-data loss) — the phantom is skipped, not mistaken for lost data.

use std::sync::{Arc, Mutex};

use graphus_bufpool::page;
use graphus_core::error::Result;
use graphus_core::{PageId, TxnId};
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE, Page};
use graphus_storage::check::check_store;
use graphus_storage::recovery::recover_device_with_dwb;
use graphus_storage::{Dwb, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

// ------- shared device (armable one-shot error, reopenable, raw inspection) -------
#[derive(Clone)]
struct SharedDevice {
    inner: Arc<Mutex<MemBlockDevice>>,
}
impl SharedDevice {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemBlockDevice::new(0))),
        }
    }
    fn arm_io_error(&self) {
        self.inner.lock().unwrap().arm_io_error();
    }
    fn raw_read(&self, page: PageId) -> Page {
        let mut buf = [0u8; PAGE_SIZE];
        self.inner
            .lock()
            .unwrap()
            .read_page(page, &mut buf)
            .unwrap();
        buf
    }
    fn count(&self) -> u64 {
        self.inner.lock().unwrap().page_count()
    }
}
impl BlockDevice for SharedDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        self.inner.lock().unwrap().read_page(page, buf)
    }
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        self.inner.lock().unwrap().write_page(page, buf)
    }
    fn sync_data(&mut self) -> Result<()> {
        self.inner.lock().unwrap().sync_data()
    }
    fn sync_all(&mut self) -> Result<()> {
        self.inner.lock().unwrap().sync_all()
    }
    fn page_count(&self) -> u64 {
        self.inner.lock().unwrap().page_count()
    }
    fn extend(&mut self, additional: u64) -> Result<()> {
        self.inner.lock().unwrap().extend(additional)
    }
}

// ------- shared WAL sink (reopenable) -------
#[derive(Clone)]
struct SharedSink {
    inner: Arc<Mutex<MemLogSink>>,
}
impl SharedSink {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemLogSink::new())),
        }
    }
}
impl LogSink for SharedSink {
    fn append(&mut self, bytes: &[u8]) {
        self.inner.lock().unwrap().append(bytes);
    }
    fn sync(&mut self) -> Result<()> {
        self.inner.lock().unwrap().sync()
    }
    fn durable_len(&self) -> u64 {
        self.inner.lock().unwrap().durable_len()
    }
    fn buffered_len(&self) -> u64 {
        self.inner.lock().unwrap().buffered_len()
    }
    fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
        self.inner.lock().unwrap().read_durable(from, into)
    }
    fn read_bounded(&self, from: u64, to: u64, into: &mut Vec<u8>) -> Result<()> {
        self.inner.lock().unwrap().read_bounded(from, to, into)
    }
    fn reclaim(&mut self, from: u64, up_to: u64) -> Result<()> {
        self.inner.lock().unwrap().reclaim(from, up_to)
    }
    fn reclaimed_floor(&self) -> u64 {
        self.inner.lock().unwrap().reclaimed_floor()
    }
}

type Store = RecordStore<SharedDevice, SharedSink>;

const POOL: usize = 128;

fn build(sink: SharedSink, dev: SharedDevice, dwb_dev: SharedDevice) -> Store {
    let wal = WalManager::create(sink).expect("create wal");
    let mut store = RecordStore::create(dev, wal, POOL, 1).expect("create store");
    store.attach_dwb(Dwb::new(dwb_dev).expect("dwb")); // exactly as dbcatalog wires production
    store
}

/// The full outcome of one run (fault-armed or control).
struct Outcome {
    /// The `create_node` index that failed (`None` == none failed).
    failed_at: Option<usize>,
    /// The device grew by exactly one page across the failing create (the phantom `extend`).
    grew_by_one: bool,
    /// The physical trailing page is all-zero (never initialised).
    phantom_is_zero: bool,
    /// The phantom page fails its checksum.
    phantom_checksum_bad: bool,
    /// How many nodes were durably committed before reopen.
    committed_nodes: u64,
    /// Reopen succeeded.
    reopen_ok: bool,
    /// The reopened store passed the consistency checker.
    reopen_consistent: bool,
    /// Live node count in the reopened store (should equal `committed_nodes`).
    live_nodes: u64,
    reopen_err: String,
}

fn run(arm: bool) -> Outcome {
    let sink = SharedSink::new();
    let dev = SharedDevice::new();
    let dwb_dev = SharedDevice::new();
    let mut store = build(sink.clone(), dev.clone(), dwb_dev.clone());

    // Phase A: commit a block of nodes spanning a few record pages, then checkpoint so every resident
    // frame is CLEAN (a later `new_page` victim, if one is even needed, writes nothing home) — so the
    // first store-device write a `new_page` triggers is the freshly-extended page's own `flush_unlogged`.
    store.begin(TxnId(1));
    for _ in 0..300 {
        store.create_node(TxnId(1)).expect("phase A create");
    }
    store.commit(TxnId(1)).expect("phase A commit");
    store.checkpoint().expect("phase A checkpoint");
    let mut committed_nodes: u64 = 300;

    let pc_before = dev.count();

    // Phase B: arm the one-shot store-device error (control: skip), then create nodes one-per-txn until
    // one FAILS. The failure lands on the `flush_unlogged` of a freshly page-boundary-extended page.
    if arm {
        dev.arm_io_error();
    }
    let mut failed_at = None;
    let mut aborted_txn = None;
    for k in 0..2000usize {
        let txn = TxnId(1000 + k as u64);
        store.begin(txn);
        match store.create_node(txn) {
            Ok(_) => {
                store.commit(txn).expect("phase B commit");
                committed_nodes += 1;
            }
            Err(_) => {
                failed_at = Some(k);
                aborted_txn = Some(txn);
                break;
            }
        }
    }
    if let Some(txn) = aborted_txn {
        // The statement aborts: roll the failed txn back, exactly as the engine does.
        let _ = store.rollback(txn);
    }

    let pc_after = dev.count();
    let grew_by_one = arm && (pc_after == pc_before + 1);

    // Inspect the physical trailing page (RAW device bytes; no pool, no checksum gate).
    let phantom = PageId(pc_after.saturating_sub(1));
    let raw = dev.raw_read(phantom);
    let phantom_is_zero = arm && raw.iter().all(|&b| b == 0);
    let phantom_checksum_bad = !page::verify_checksum(&raw);

    // Phase C: the error was one-shot (already consumed). Heal: checkpoint + flush + close.
    store
        .checkpoint()
        .expect("phase C checkpoint (device healthy again)");
    store.flush().expect("phase C flush");
    drop(store);

    // Phase D: reopen exactly as production does (DWB torn-page repair, then RecordStore::open), then
    // run the consistency checker and count live nodes.
    let mut rdev = dev.clone();
    let mut wal = WalManager::open(sink.clone()).expect("reopen wal for recovery");
    let mut dwb = Dwb::new(dwb_dev.clone()).expect("reopen dwb");
    recover_device_with_dwb(&mut wal, &mut rdev, &mut dwb).expect("dwb recovery");
    let wal = WalManager::open(sink).expect("reopen wal for store");
    let reopen = RecordStore::open(dev.clone(), wal, POOL);
    let reopen_ok = reopen.is_ok();
    let reopen_err = match &reopen {
        Ok(_) => String::new(),
        Err(e) => format!("{e}"),
    };
    let (reopen_consistent, live_nodes) = match reopen {
        Ok(mut s) => {
            let report = check_store(&mut s, &[]).expect("consistency check runs");
            (report.is_consistent(), report.live_nodes)
        }
        Err(_) => (false, 0),
    };

    Outcome {
        failed_at,
        grew_by_one,
        phantom_is_zero,
        phantom_checksum_bad,
        committed_nodes,
        reopen_ok,
        reopen_consistent,
        live_nodes,
        reopen_err,
    }
}

#[test]
fn phantom_zero_page_from_failed_alloc_flush_does_not_brick_reopen() {
    // CONTROL: identical flow, fault NOT armed -> must reopen cleanly and consistently.
    let ctrl = run(false);
    assert!(
        ctrl.failed_at.is_none(),
        "control must not see any create failure"
    );
    assert!(
        ctrl.reopen_ok && ctrl.reopen_consistent,
        "control (no fault) must reopen cleanly & consistently, got err: {}",
        ctrl.reopen_err
    );
    assert_eq!(
        ctrl.live_nodes, ctrl.committed_nodes,
        "control: every committed node must survive"
    );

    // FAULT: one-shot device write error on the alloc seed flush.
    let f = run(true);

    // (1) The fault genuinely creates the phantom: a create fails, the device grew by one page, and the
    // trailing page is all-zero with a bad checksum (the aborted-allocation residue).
    assert!(
        f.failed_at.is_some(),
        "a create_node must fail on the armed device error (the fault was not exercised)"
    );
    assert!(
        f.grew_by_one,
        "the failed alloc must have extended the device by exactly one page (the phantom)"
    );
    assert!(
        f.phantom_is_zero,
        "the phantom trailing page must be all-zero (never initialised)"
    );
    assert!(
        f.phantom_checksum_bad,
        "the phantom zero page must FAIL checksum verification (it is the exact page that bricked \
         reopen before the #597 fix)"
    );

    // (2) THE FIX: despite the checksum-invalid phantom, the store reopens cleanly. Before the fix,
    // `reconstruct_orphan_store_pages` `fetch`ed the phantom and `RecordStore::open` failed with
    // "page N failed checksum verification" — this assertion is exactly that regression gate.
    assert!(
        f.reopen_ok,
        "REGRESSION (`rmp` #597): a transient device write error during allocation must NOT brick \
         reopen — the phantom all-zero page must be skipped, not rejected. Reopen failed with: {}",
        f.reopen_err
    );

    // (3) The reopened store is consistent and every committed node survives — the phantom is skipped,
    // never mistaken for lost committed data (no committed-data loss; corruption mandate intact).
    assert!(
        f.reopen_consistent,
        "the recovered store must be structurally consistent after skipping the phantom page"
    );
    assert_eq!(
        f.live_nodes, f.committed_nodes,
        "every committed node must survive (the phantom skip must not drop any committed data): \
         expected {} live nodes, saw {}",
        f.committed_nodes, f.live_nodes
    );
}
