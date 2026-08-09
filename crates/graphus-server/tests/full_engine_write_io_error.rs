//! **Full-engine write-I/O-error durability regression (`rmp` #597)** — a real threaded `Engine`
//! driven through a committing write / durability flush while the underlying store **device** returns
//! a write I/O error, on genuine OS threads, over a **production-faithful doublewrite-protected store**.
//!
//! ## The gap this owns
//!
//! The deterministic simulator has a rich seed-driven disk-fault model (`graphus-io`'s `FaultPlan`:
//! bit-rot, misdirected I/O, latent sector errors, ENOSPC, write reordering) but it drives the **store
//! primitives** on one cooperative thread. The *whole engine's* reaction to a device write error that
//! lands mid-flush — does the engine surface a clean error and stay alive (a data-page write is
//! redo-able / doublewrite-repairable, unlike a WAL `fdatasync` failure, which is the fsyncgate PANIC),
//! or does it corrupt / panic? — was the "deferred full-engine write-I/O-error scenario" the reliability
//! audit flagged. This drives the real `spawn_engine` engine, wired exactly as the server wires it (a
//! store with an attached [`Dwb`] doublewrite buffer, recovery via
//! [`recover_device_with_dwb`](graphus_storage::recovery::recover_device_with_dwb)), injects a one-shot
//! device write error, and asserts:
//!
//!   1. **No panic** — the engine surfaces the failure as an error and remains responsive (a follow-up
//!      statement still runs). A DATA-page write failure is recoverable (the change is in the WAL and, on
//!      the eviction/steal path, an intact doublewrite copy), so it must NOT take the fsyncgate abort
//!      path reserved for WAL `fdatasync` failure.
//!   2. **No torn / partial state** — after the failure the store recovers to a structurally consistent
//!      image (`check_store`) — the doublewrite buffer repairs any torn home page before ARIES redo —
//!      and each write is atomic: committed-and-present or cleanly-absent, never half-applied.
//!
//! It runs a real threaded engine over a shared device, so it belongs to the ThreadSanitizer soak lane
//! (`scripts/tsan-soak.sh`) — TSan additionally validates the shared-device wrapper is race-free.
//!
//! ## Why a doublewrite buffer is required for fidelity
//!
//! Production (`graphus-server`'s `dbcatalog`) **always** attaches a `Dwb` and recovers via
//! `recover_device_with_dwb`. A store with **no** DWB that suffers a failed home write mid-eviction can
//! leave a home page whose bytes/`page_lsn` are inconsistent with the WAL — which ARIES redo (gating on
//! `page_lsn`) cannot always repair; that is the exact hole the doublewrite buffer closes (`05 §3`,
//! `04 §4.5`). Testing the *no-DWB* config would exercise a configuration the server never runs; this
//! test therefore mirrors production and proves the DWB-protected path stays consistent under the fault.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use graphus_core::capability::Clock;
use graphus_core::error::Result;
use graphus_core::{PageId, Value};
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine};
use graphus_storage::check::check_store;
use graphus_storage::recovery::recover_device_with_dwb;
use graphus_storage::{Dwb, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

/// A monotonic real clock (the engine only reads `now_nanos`).
struct RealClock;
impl Clock for RealClock {
    fn now_nanos(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

/// A shared in-memory WAL sink (`Arc<Mutex<MemLogSink>>`) so the test can reopen the store over the
/// same WAL after the engine has stopped, to run the consistency checker.
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
        self.inner.lock().expect("sink lock").append(bytes);
    }
    fn sync(&mut self) -> Result<()> {
        self.inner.lock().expect("sink lock").sync()
    }
    fn durable_len(&self) -> u64 {
        self.inner.lock().expect("sink lock").durable_len()
    }
    fn buffered_len(&self) -> u64 {
        self.inner.lock().expect("sink lock").buffered_len()
    }
    fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
        self.inner
            .lock()
            .expect("sink lock")
            .read_durable(from, into)
    }
    fn read_bounded(&self, from: u64, to: u64, into: &mut Vec<u8>) -> Result<()> {
        self.inner
            .lock()
            .expect("sink lock")
            .read_bounded(from, to, into)
    }
    fn reclaim(&mut self, from: u64, up_to: u64) -> Result<()> {
        self.inner.lock().expect("sink lock").reclaim(from, up_to)
    }
    fn reclaimed_floor(&self) -> u64 {
        self.inner.lock().expect("sink lock").reclaimed_floor()
    }
}

/// A shared [`MemBlockDevice`] the test can arm a one-shot write I/O error on, and reopen after the
/// engine stops. Used both for the store device (where the fault is armed) and the separate DWB device.
#[derive(Clone)]
struct SharedDevice {
    inner: Arc<Mutex<MemBlockDevice>>,
    /// Counts device writes actually attempted, so the test can confirm the flush path did touch the
    /// device (i.e. the armed error had a write to fail on).
    writes: Arc<AtomicU64>,
}
impl SharedDevice {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemBlockDevice::new(0))),
            writes: Arc::new(AtomicU64::new(0)),
        }
    }
    fn arm_io_error(&self) {
        self.inner.lock().expect("device lock").arm_io_error();
    }
    fn write_count(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }
}
impl BlockDevice for SharedDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        self.inner.lock().expect("device lock").read_page(page, buf)
    }
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.inner
            .lock()
            .expect("device lock")
            .write_page(page, buf)
    }
    fn sync_data(&mut self) -> Result<()> {
        self.inner.lock().expect("device lock").sync_data()
    }
    fn sync_all(&mut self) -> Result<()> {
        self.inner.lock().expect("device lock").sync_all()
    }
    fn page_count(&self) -> u64 {
        self.inner.lock().expect("device lock").page_count()
    }
    fn extend(&mut self, additional: u64) -> Result<()> {
        self.inner.lock().expect("device lock").extend(additional)
    }
}

/// Spawns a threaded engine over the shared store device + separate shared DWB device + shared WAL,
/// wired exactly as the server wires a live database: the store carries an attached doublewrite buffer,
/// so every checkpoint/flush AND eviction home write is torn-write protected.
fn spawn_dwb_engine(
    sink: SharedSink,
    store_dev: SharedDevice,
    dwb_dev: SharedDevice,
    pool_capacity: usize,
) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(RealClock);
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<SharedDevice, SharedSink, _>(
        Arc::from("io_err"),
        move || {
            let wal = WalManager::create(sink)?;
            let store = RecordStore::create(store_dev, wal, pool_capacity, 1)?;
            // Attach the doublewrite buffer over its own device, exactly as `dbcatalog` does — this also
            // installs the DWB stager on the pool so the eviction/steal home-write path is protected.
            store.attach_dwb(Dwb::new(dwb_dev)?);
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        8192,
        256,
        2,
        metrics,
        clock,
        std::sync::Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn DWB-protected engine")
}

/// One auto-commit `CREATE (:Acct {id})`, drained to end-of-stream. Returns true when it committed,
/// false when the statement returned a clean error (a device write failed under it) — so the caller can
/// correlate "acked" with "durable".
fn write_acct(handle: &EngineHandle, id: i64) -> bool {
    let Ok(ticket) = handle.begin_auto_commit_blocking(AccessMode::Write) else {
        return false;
    };
    match handle.run_blocking(
        ticket,
        "CREATE (:Acct {id: $id})".to_owned(),
        vec![("id".to_owned(), Value::Integer(id))],
        true,
        None,
        None,
    ) {
        Ok(mut reply) => loop {
            match reply.rows.next() {
                Ok(Some(_)) => {}
                Ok(None) => return true,
                Err(_) => return false,
            }
        },
        Err(_) => false,
    }
}

/// Counts `:Acct` nodes via an auto-commit read — proves the engine is still responsive (no panic).
fn count_accts(handle: &EngineHandle) -> Option<i64> {
    let ticket = handle.begin_auto_commit_blocking(AccessMode::Read).ok()?;
    let mut reply = handle
        .run_blocking(
            ticket,
            "MATCH (n:Acct) RETURN count(n)".to_owned(),
            vec![],
            true,
            None,
            None,
        )
        .ok()?;
    let mut count = None;
    while let Ok(Some(cells)) = reply.rows.next() {
        if let Some(graphus_cypher::MaterializedValue::Value(Value::Integer(n))) = cells.first() {
            count = Some(*n);
        }
    }
    count
}

/// Reopens the store over the shared device + WAL (after the engine has stopped), running the
/// doublewrite torn-page repair before ARIES redo (exactly as the server does), then the consistency
/// checker. Returns `(is_consistent, live_nodes)`.
fn reopen_and_check(
    sink: SharedSink,
    store_dev: SharedDevice,
    dwb_dev: SharedDevice,
    pool: usize,
) -> (bool, u64) {
    let mut device = store_dev.clone();
    let mut wal = WalManager::open(sink.clone()).expect("open WAL");
    // Reopen the DWB over its (shared, persisted) device — its staged copies survive — and repair any
    // torn home page before redo.
    let mut dwb = Dwb::new(dwb_dev).expect("reopen DWB");
    recover_device_with_dwb(&mut wal, &mut device, &mut dwb).expect("recover device with DWB");
    let wal = WalManager::open(sink).expect("reopen WAL");
    let store = RecordStore::open(store_dev, wal, pool).expect("open store");
    let report = check_store(&store, &[]).expect("consistency check runs");
    (report.is_consistent(), report.live_nodes)
}

fn graceful_shutdown(engine: Engine, handle: EngineHandle) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build shutdown runtime");
    // A final flush may itself fail against the (possibly still-armed) faulty device; either way the
    // engine must not hang. Submit Shutdown (exits the loop), then drop EVERY handle before joining.
    let _ = rt.block_on(handle.shutdown());
    let Engine {
        handle: owned,
        join,
    } = engine;
    drop(handle);
    drop(owned);
    join.join().expect("engine thread joins");
}

/// A device write error during a **checkpoint flush** is surfaced as a clean error (not a panic, not
/// the fsyncgate abort), the engine stays responsive, a later flush succeeds, and the reopened store is
/// consistent with every committed write intact.
#[test]
fn checkpoint_flush_device_write_error_is_clean_and_recoverable() {
    const N: i64 = 60;
    const POOL: usize = 256;

    let sink = SharedSink::new();
    let store_dev = SharedDevice::new();
    let dwb_dev = SharedDevice::new();
    let engine = spawn_dwb_engine(sink.clone(), store_dev.clone(), dwb_dev.clone(), POOL);
    let handle = engine.handle.clone();

    // Commit N writes; a large pool keeps their pages resident-dirty (nothing evicted yet), so the
    // upcoming checkpoint has real dirty pages to flush and will actually write to the device.
    for i in 0..N {
        assert!(write_acct(&handle, i), "warmup write {i} commits");
    }
    assert_eq!(
        count_accts(&handle),
        Some(N),
        "all N writes are visible pre-fault"
    );

    // Arm a one-shot store-device write error, then force a durability flush. The checkpoint's first
    // store-device write (a doublewrite-buffer batch stage is on the SEPARATE DWB device, so the fault
    // lands on a home write) hits the armed error.
    let writes_before = store_dev.write_count();
    store_dev.arm_io_error();
    let ck = handle.checkpoint_blocking();

    // (1a) The checkpoint attempted a store-device write (so the error had something to fail on).
    assert!(
        store_dev.write_count() > writes_before,
        "the checkpoint flush must have attempted a store-device write to exercise the fault"
    );
    // (1b) The device write error is surfaced as a clean error — NOT a panic (the engine thread is
    // alive below) and NOT the fsyncgate abort (a data-page write is redo/doublewrite-repairable).
    assert!(
        ck.is_err(),
        "a device write error during the checkpoint flush must surface as a clean error, got {ck:?}"
    );

    // (2) The engine is still RESPONSIVE after the fault (proof it did not panic / die): reads work,
    // every committed write is still visible, and a NEW write commits.
    assert_eq!(
        count_accts(&handle),
        Some(N),
        "the engine must stay responsive and consistent after a device write error"
    );
    assert!(
        write_acct(&handle, 1000),
        "the engine must accept new writes after surfacing the device error"
    );

    // (3) The armed error was one-shot; a subsequent checkpoint (device healthy again) succeeds.
    assert!(
        handle.checkpoint_blocking().is_ok(),
        "a checkpoint must succeed once the device is healthy again"
    );

    // (4) Shut down and reopen (with DWB torn-page repair): the store is structurally consistent, and
    // every committed write (N warmup + the post-fault write) survives — nothing torn, nothing lost.
    drop(handle);
    let final_handle = engine.handle.clone();
    graceful_shutdown(engine, final_handle);

    let (consistent, live_nodes) = reopen_and_check(sink, store_dev, dwb_dev, POOL);
    assert!(
        consistent,
        "the recovered store must be structurally consistent"
    );
    assert_eq!(
        live_nodes,
        (N + 1) as u64,
        "every committed write must survive the device write error (N warmup + 1 post-fault)"
    );
}

/// A device write error that lands **mid-commit** (during an eviction forced by a committing write in a
/// small pool) is atomic: the engine never panics, every statement is committed-and-present or
/// cleanly-absent (never torn), and the recovered store is consistent with survivors == the acked set.
///
/// **This is the regression test for the `rmp` #597 durability fix.** Before the fix,
/// `ConcurrentBufferPool::load_into` `blank`ed the victim frame when `evict_held` FAILED (the victim's
/// dirty home write hit the device error) — discarding that un-written dirty page. Its home was never
/// written and, being a freshly-allocated *unlogged* page, redo could not recreate it, so it surfaced on
/// reopen as an **all-zero phantom page inside the mapped range that fails its checksum** — a store
/// bricked by nothing worse than a transient device write error during an eviction. The fix leaves the
/// still-intact dirty victim resident (as `new_page`'s `evict_held?` path already does), so a later
/// flush writes it home and the store reopens cleanly. Without the fix, the reopen assertion below fails
/// with `page N failed checksum verification`.
///
/// Looped a few times: exactly where the one-shot error lands (which write's eviction, or the shutdown
/// flush) is workload-dependent, so the loop shakes out the mid-commit landing while the invariant
/// (acked ⇔ present, always consistent, never a panic) holds on every landing.
#[test]
fn autocommit_write_device_error_is_atomic_and_never_panics() {
    const ITERS: usize = 4;
    const PRIME: i64 = 400; // enough creates to grow past the small pool → eviction pressure
    const PROBE: i64 = 200; // the window in which the armed error lands on an eviction
    const POOL: usize = 16; // small pool → committing writes must evict (device writes) mid-commit

    for iter in 0..ITERS {
        let sink = SharedSink::new();
        let store_dev = SharedDevice::new();
        let dwb_dev = SharedDevice::new();
        let engine = spawn_dwb_engine(sink.clone(), store_dev.clone(), dwb_dev.clone(), POOL);
        let handle = engine.handle.clone();

        // Prime: fill the pool with dirty pages so subsequent creates must evict.
        for i in 0..PRIME {
            assert!(
                write_acct(&handle, i),
                "iter {iter}: prime write {i} commits"
            );
        }

        // Arm the one-shot error, then drive a probe window of writes; the error fires on some write's
        // eviction (a device write mid-commit). Record which ids the engine ACKED.
        store_dev.arm_io_error();
        let mut acked_probe = Vec::new();
        for k in 0..PROBE {
            let id = 1_000_000 + k;
            if write_acct(&handle, id) {
                acked_probe.push(id);
            }
        }

        // The engine never panicked: it is still responsive to a read.
        assert!(
            count_accts(&handle).is_some(),
            "iter {iter}: the engine must stay responsive (no panic) after a mid-commit device error"
        );

        // Shut down (a final flush may consume a still-armed error — tolerated) and reopen to check.
        drop(handle);
        let final_handle = engine.handle.clone();
        graceful_shutdown(engine, final_handle);

        let (consistent, live_nodes) = reopen_and_check(sink, store_dev, dwb_dev, POOL);
        assert!(
            consistent,
            "iter {iter}: the recovered store must be structurally consistent after a mid-commit error"
        );
        // Atomicity: every ACKED write (the PRIME set, all of which committed, + the acked probe writes)
        // survives; a write the engine rejected is absent. So the survivor count is exactly the acked
        // count — never torn (a torn write would corrupt the count or the structure).
        let expected = PRIME as u64 + acked_probe.len() as u64;
        assert_eq!(
            live_nodes,
            expected,
            "iter {iter}: survivors must equal the acked set (PRIME {PRIME} + acked probe {}) — a \
             mismatch means a write was torn or an acked write was lost",
            acked_probe.len()
        );
    }
}
