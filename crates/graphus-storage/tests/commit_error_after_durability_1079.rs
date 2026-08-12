//! **Regression gate for `rmp` #1079 — a commit must not report a failure for a transaction that
//! committed.**
//!
//! ## The defect
//!
//! `RecordStore::commit` runs, in order: every fallible step of the commit, the group-commit
//! `fdatasync` ([`RecordStore::harden_wal`] — **the durability point**), and then the redo-bounding
//! auto-checkpoint. Until this task the last of those three propagated its error out of `commit`, so a
//! transaction whose `COMMIT` record was already on stable storage could hand its client an `Err`.
//!
//! That is an ACID lie, and it is the worst-shaped one: the client cannot act on it correctly either
//! way. Retry and the transaction lands twice; give up and a write that is genuinely on disk is
//! treated as lost. `rmp` #1067 made the shape reachable by a new route — the checkpoint now writes a
//! catalogue image to carry the folded counter base, so a device error under that write became a
//! commit error — but the shape predates it and applies to every fallible step of a post-durability
//! checkpoint.
//!
//! ## What is asserted, and why the fault is aimed at the metadata page
//!
//! The catalogue image lives on [`META_PAGE`] and its continuation chain. Inside one `commit` that
//! page reaches the **device** exactly once, and only after the durability point: the pre-durability
//! `checkpoint_meta` writes the image into the *pooled* page (WAL-logged, left dirty), and it is the
//! post-durability checkpoint's `flush` that carries those bytes home. So a device that refuses writes
//! to `META_PAGE` injects a failure of the catalogue image write, at the one moment this task is
//! about, and at no other — which is what makes the oracle below tight rather than merely green:
//!
//!  1. **`commit` returns `Ok`** for a transaction that is durable (the fix; fails without it).
//!  2. **The injected fault actually fired** on the metadata page, so (1) is not vacuous.
//!  3. **The failure did not vanish**: the store counted the deferral and kept its message. `rmp` #1067
//!     made the durable cardinality a base plus the retained deltas, so a catalogue image that never
//!     lands costs recovery time and WAL reclamation, never committed data — but a fault that nobody
//!     can see is how a mechanism fails open, and this one is observable by construction.
//!  4. **The transaction is durable and visible after a reopen**, with the metadata page still holding
//!     the *stale* image the failed write left behind. The image is not the source of truth; the log
//!     is, and recovery redo rebuilds both the records and the catalogue page from it.
//!
//! And, because a fix that swallows too much is the same defect facing the other way:
//!
//!  5. **A fault injected BEFORE the durability point still fails the commit**, and leaves the writer
//!     open. The deferral counter stays at zero there, which is what proves the two windows are told
//!     apart by where the fault lands rather than by luck.
//!
//! Deterministic and single-threaded throughout — an in-memory device and an in-memory log sink, no
//! clock, no threads, no randomness — so every run replays byte for byte, as the project's
//! fault-injection gates require. It isolates the storage primitive directly, exactly as the `rmp`
//! #597 device-fault gate beside it does.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use graphus_core::PageId;
use graphus_core::TxnId;
use graphus_core::error::{GraphusError, Result};
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_storage::check::check_store;
use graphus_storage::recovery::recover_device;
use graphus_storage::{META_PAGE, Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

/// Buffer-pool frames. Large enough that nothing in these scenarios is ever evicted, so the only
/// device writes are the ones each phase deliberately triggers — the determinism the fault windows
/// rest on.
const POOL: usize = 256;

/// Property-key tokens the pre-durability scenario interns so its catalogue outgrows a single metadata
/// page, forcing `checkpoint_meta` to GROW the chain — a `new_page` + `flush_unlogged`, i.e. a **device
/// write inside `checkpoint_meta`**, which is where the one-shot I/O error must land. Same lever, same
/// reason, as `graphus_dst::rollback_undo_fault`.
const CHAIN_GROWTH_TOKENS: usize = 1024;

// ---------------------------------------------------------------------------------------------
// A shared, reopenable device whose write of the CATALOGUE IMAGE page can be refused on demand.
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct MetaFaultDevice {
    inner: Arc<Mutex<MemBlockDevice>>,
    /// While set, every `write_page` of [`META_PAGE`] fails.
    refuse_meta: Arc<AtomicBool>,
    /// How many writes the flag above actually refused — the non-vacuity counter.
    refused: Arc<AtomicU64>,
}

impl MetaFaultDevice {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemBlockDevice::new(0))),
            refuse_meta: Arc::new(AtomicBool::new(false)),
            refused: Arc::new(AtomicU64::new(false as u64)),
        }
    }
    fn refuse_catalog_image_writes(&self, refuse: bool) {
        self.refuse_meta.store(refuse, Ordering::SeqCst);
    }
    fn refused_catalog_image_writes(&self) -> u64 {
        self.refused.load(Ordering::SeqCst)
    }
    /// The one-shot "next write fails" seam of [`MemBlockDevice`], used by the pre-durability scenario.
    fn arm_one_shot_io_error(&self) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .arm_io_error();
    }
}

impl BlockDevice for MetaFaultDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .read_page(page, buf)
    }
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        if page == META_PAGE && self.refuse_meta.load(Ordering::SeqCst) {
            self.refused.fetch_add(1, Ordering::SeqCst);
            return Err(GraphusError::Storage(format!(
                "injected I/O error writing the catalogue image to page {} (rmp #1079)",
                page.0
            )));
        }
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .write_page(page, buf)
    }
    fn sync_data(&mut self) -> Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sync_data()
    }
    fn sync_all(&mut self) -> Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sync_all()
    }
    fn page_count(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .page_count()
    }
    fn extend(&mut self, additional: u64) -> Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(additional)
    }
}

// ------- a shared, reopenable WAL sink -------

#[derive(Clone)]
struct SharedSink {
    inner: Arc<Mutex<MemLogSink>>,
    /// While set, WAL prefix reclamation fails — the checkpoint's LAST fallible step, and a
    /// structurally different one from the catalogue image write.
    refuse_reclaim: Arc<AtomicBool>,
    /// How many reclaims the flag above actually refused — the non-vacuity counter.
    refused: Arc<AtomicU64>,
}

impl SharedSink {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemLogSink::new())),
            refuse_reclaim: Arc::new(AtomicBool::new(false)),
            refused: Arc::new(AtomicU64::new(0)),
        }
    }
    fn refuse_wal_reclaim(&self, refuse: bool) {
        self.refuse_reclaim.store(refuse, Ordering::SeqCst);
    }
    fn refused_wal_reclaims(&self) -> u64 {
        self.refused.load(Ordering::SeqCst)
    }
    fn at(&self) -> std::sync::MutexGuard<'_, MemLogSink> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl LogSink for SharedSink {
    fn append(&mut self, bytes: &[u8]) {
        self.at().append(bytes);
    }
    fn sync(&mut self) -> Result<()> {
        self.at().sync()
    }
    fn durable_len(&self) -> u64 {
        self.at().durable_len()
    }
    fn buffered_len(&self) -> u64 {
        self.at().buffered_len()
    }
    fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
        self.at().read_durable(from, into)
    }
    fn read_bounded(&self, from: u64, to: u64, into: &mut Vec<u8>) -> Result<()> {
        self.at().read_bounded(from, to, into)
    }
    fn reclaim(&mut self, from: u64, up_to: u64) -> Result<()> {
        if self.refuse_reclaim.load(Ordering::SeqCst) {
            self.refused.fetch_add(1, Ordering::SeqCst);
            return Err(GraphusError::Storage(
                "injected I/O error reclaiming the WAL prefix (rmp #1079)".to_owned(),
            ));
        }
        self.at().reclaim(from, up_to)
    }
    fn reclaimed_floor(&self) -> u64 {
        self.at().reclaimed_floor()
    }
}

type Store = RecordStore<MetaFaultDevice, SharedSink>;

fn create(dev: MetaFaultDevice, sink: SharedSink) -> Store {
    let wal = WalManager::create(sink).expect("create wal");
    let store = RecordStore::create(dev, wal, POOL, 1).expect("create store");
    // Every write commit must reach the redo-bounding auto-checkpoint, which is the post-durability
    // step under test. At the 64 MiB default it would never fire in a test this size and the whole
    // scenario would pass without ever entering the window it claims to exercise.
    store.set_checkpoint_interval_bytes(1);
    store
}

/// Reopens the store exactly as production does: ARIES recovery over the device first
/// ([`recover_device`] — this is what replays the log onto the home pages, the catalogue image page
/// among them), then [`RecordStore::open`] over the recovered device.
fn reopen(dev: &MetaFaultDevice, sink: &SharedSink) -> Store {
    let mut rwal = WalManager::open(sink.clone()).expect("reopen wal for recovery");
    let mut rdev = dev.clone();
    recover_device(&mut rwal, &mut rdev).expect("ARIES recovery");
    let wal = WalManager::open(sink.clone()).expect("reopen wal for store");
    RecordStore::open(dev.clone(), wal, POOL).expect("the store must reopen")
}

/// Commits `count` nodes in one transaction and returns the ids.
fn commit_nodes(store: &Store, txn: TxnId, count: usize) -> Vec<u64> {
    store.begin(txn);
    let ids = (0..count)
        .map(|_| store.create_node(txn).expect("create node").0)
        .collect();
    store.commit(txn).expect("commit must succeed");
    ids
}

// ---------------------------------------------------------------------------------------------
// 1..4 — the defect itself.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_failed_catalog_image_write_after_the_durability_point_does_not_fail_the_commit_1079() {
    let dev = MetaFaultDevice::new();
    let sink = SharedSink::new();
    let store = create(dev.clone(), sink.clone());

    // Phase A — a healthy committed baseline, checkpointed and flushed, so the fault below is the
    // only thing standing between the store and a clean image.
    let seeded = commit_nodes(&store, TxnId(1), 8);
    store.flush().expect("phase A flush");
    assert_eq!(
        store.deferred_checkpoints(),
        0,
        "the baseline must checkpoint cleanly, or the fault's effect cannot be attributed"
    );

    // Phase B — refuse the catalogue image write, then commit. The refusal cannot touch anything
    // before the durability point: within one commit the metadata page reaches the device only in the
    // post-durability checkpoint's flush.
    dev.refuse_catalog_image_writes(true);
    store.begin(TxnId(2));
    let committed = store.create_node(TxnId(2)).expect("create node").0;
    let outcome = store.commit(TxnId(2));

    // (2) THE FAULT FIRED. Asserted before the outcome, because a green (1) over a fault that never
    // landed is exactly the vacuous pass this gate exists to refuse.
    assert!(
        dev.refused_catalog_image_writes() > 0,
        "the injected fault never fired, so nothing below tests anything"
    );
    // (1) THE COMMIT DID NOT LIE. This is the fix.
    assert!(
        outcome.is_ok(),
        "a transaction whose COMMIT record is already durable was reported as failed: {:?}",
        outcome.err()
    );
    // (3) AND THE FAULT DID NOT VANISH.
    assert_eq!(
        store.deferred_checkpoints(),
        1,
        "the post-durability checkpoint failed and the store must have retained that fact; a \
         swallow nobody can observe is a mechanism failing open"
    );
    let message = store
        .last_deferred_checkpoint_error()
        .expect("the deferred failure must keep its message, not only its count");
    assert!(
        message.contains("rmp #1079"),
        "the retained message must be the injected fault's, not some later unrelated error: {message}"
    );

    // The store is still usable, and still committing: a second write commits and defers again rather
    // than failing, so the deferral is a steady state and not a one-off that happened to be tolerated.
    store.begin(TxnId(3));
    let second = store.create_node(TxnId(3)).expect("create node").0;
    assert!(
        store.commit(TxnId(3)).is_ok(),
        "a second commit under the same fault must also succeed"
    );
    assert_eq!(
        store.deferred_checkpoints(),
        2,
        "the checkpoint must be RETRIED on the next commit — the cadence watermark advances only on \
         success, so the debt is retained by construction"
    );

    // (4) DURABLE AND VISIBLE AFTER A REOPEN, with the catalogue image on the device still stale.
    drop(store);
    dev.refuse_catalog_image_writes(false);
    let reopened = reopen(&dev, &sink);
    let report = check_store(&reopened, &[]).expect("consistency check runs");
    assert!(
        report.is_consistent(),
        "the reopened store must be structurally consistent"
    );
    let expected = seeded.len() as u64 + 2;
    assert_eq!(
        report.live_nodes, expected,
        "every committed node must survive the reopen — the transaction whose commit returned Ok \
         under the injected fault above is {committed}, and the second is {second}"
    );
}

// ---------------------------------------------------------------------------------------------
// 5 — the boundary is preserved: BEFORE the durability point, a failure is still the commit's.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_failed_catalog_image_write_before_the_durability_point_still_fails_the_commit_1079() {
    let dev = MetaFaultDevice::new();
    let sink = SharedSink::new();
    let store = create(dev.clone(), sink.clone());

    let seeded = commit_nodes(&store, TxnId(1), 4);
    store.flush().expect("seed flush");

    // A transaction whose catalogue outgrows one metadata page: its `checkpoint_meta` must GROW the
    // chain, and that growth's `flush_unlogged` is a device write **inside** the pre-durability
    // catalogue write. Arming the one-shot error immediately before `commit` therefore lands it there.
    store.begin(TxnId(2));
    let doomed = store.create_node(TxnId(2)).expect("create node").0;
    for i in 0..CHAIN_GROWTH_TOKENS {
        store
            .intern_token(Namespace::PropKey, &format!("chain_growth_key_{i}"))
            .expect("intern property key");
    }
    dev.arm_one_shot_io_error();
    let outcome = store.commit(TxnId(2));

    assert!(
        outcome.is_err(),
        "a failure BEFORE the durability point is the commit's own and must still be reported; \
         node {doomed} must not be treated as committed"
    );
    assert_eq!(
        store.deferred_checkpoints(),
        0,
        "the fault landed before the durability point, so it must have been REPORTED, not deferred \
         — a non-zero count here means the fix swallowed an error it had no right to swallow"
    );
    assert!(
        store.is_txn_active(TxnId(2)),
        "a failed commit must leave a fully-formed open writer (rmp #955)"
    );

    store.rollback(TxnId(2)).expect("the writer rolls back");
    drop(store);

    let reopened = reopen(&dev, &sink);
    let report = check_store(&reopened, &[]).expect("consistency check runs");
    assert!(
        report.is_consistent(),
        "the reopened store must be consistent"
    );
    assert_eq!(
        report.live_nodes,
        seeded.len() as u64,
        "the transaction that was told it failed must not be on disk"
    );
}

// ---------------------------------------------------------------------------------------------
// The contract is the BOUNDARY, not one failure route: a different fallible step of the same
// post-durability checkpoint must be deferred on the same terms.
// ---------------------------------------------------------------------------------------------

/// The catalogue image write is only one of the checkpoint's fallible steps, and it is the FIRST one
/// a refused metadata-page write reaches. This drives the LAST one instead — the WAL prefix reclaim —
/// which leaves entirely different residue: the flush succeeded, the counter fold ran and published
/// its base, and only the log truncation failed. The commit must still return `Ok`, because the
/// boundary is the durability point and not the identity of the step that failed.
#[test]
fn a_failed_wal_reclaim_after_the_durability_point_is_deferred_too_1079() {
    let dev = MetaFaultDevice::new();
    let sink = SharedSink::new();
    let store = create(dev.clone(), sink.clone());

    let seeded = commit_nodes(&store, TxnId(1), 8);
    store.flush().expect("seed flush");
    assert_eq!(
        store.deferred_checkpoints(),
        0,
        "the baseline must be clean"
    );

    sink.refuse_wal_reclaim(true);
    store.begin(TxnId(2));
    let committed = store.create_node(TxnId(2)).expect("create node").0;
    let outcome = store.commit(TxnId(2));

    assert!(
        sink.refused_wal_reclaims() > 0,
        "the injected reclaim fault never fired, so nothing below tests anything"
    );
    assert!(
        outcome.is_ok(),
        "a transaction whose COMMIT record is already durable was reported as failed: {:?}",
        outcome.err()
    );
    assert_eq!(
        store.deferred_checkpoints(),
        1,
        "the failure must be retained whichever step of the checkpoint produced it"
    );
    assert!(
        store
            .last_deferred_checkpoint_error()
            .is_some_and(|m| m.contains("reclaiming the WAL prefix")),
        "the retained message must name the step that actually failed"
    );

    drop(store);
    sink.refuse_wal_reclaim(false);
    let reopened = reopen(&dev, &sink);
    let report = check_store(&reopened, &[]).expect("consistency check runs");
    assert!(
        report.is_consistent(),
        "the reopened store must be consistent"
    );
    assert_eq!(
        report.live_nodes,
        seeded.len() as u64 + 1,
        "node {committed} committed and must survive the reopen"
    );
}
