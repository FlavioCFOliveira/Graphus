//! **Real-OS-thread durability regression for `rmp` #597** — the pipelined group-commit path
//! (`rmp` #528/#532/#566) taken through a genuine **hard crash**, on real threads.
//!
//! ## The gap this owns (why DST and `autocommit_group_commit` do not cover it)
//!
//! `autocommit_group_commit.rs` (#566 T1) proves the *coalescing* of many concurrent auto-commit
//! writers' `fdatasync`s behind few shared hardens, and their durability across a **graceful**
//! restart — but its restart path calls `graceful_shutdown` first, which performs a **final harden**.
//! So it never distinguishes "acked because ack-after-fsync made it durable" from "acked, then made
//! durable by the shutdown harden". A power loss has no shutdown harden.
//!
//! The deterministic simulator (`specification/07-dst-simulator.md` §5.1) runs the engine on **one
//! cooperative OS thread with each statement atomic**, so the true-parallel group-commit pipeline —
//! N concurrent committers, the batch `fdatasync` offloaded to the dedicated `WalSyncThread`, and a
//! crash landing *in* the depth-1 overlap window — has no deterministic coverage. Its DST-level
//! counterpart is `graphus-dst`'s `deferred_fsync_overlap_recovery` (which drives the store
//! primitives single-threaded). This test is the real-OS-thread twin: it drives the **whole engine**
//! (real `spawn_engine`, real `WalSyncThread`, real concurrent auto-commit writers) and then crashes.
//!
//! It belongs to the ThreadSanitizer soak lane (`scripts/tsan-soak.sh`, `rmp` #460), NOT the
//! deterministic seed-replay gate: the interleaving is chosen by the OS scheduler.
//!
//! ## The invariant it pins (durable-prefix atomicity / ack-after-fsync)
//!
//! Driving N concurrent auto-commit writers through the pipelined group commit, then crashing with a
//! genuinely **written-but-un-synced** batch in flight (dropped by the crash, never `fdatasync`'d and
//! never acked), recovery from the durable prefix *as it stood at ack time* must show:
//!
//!   1. **Every acknowledged write survives** — the ack was ack-after-fsync, so it is durable with **no
//!      graceful final harden** (the property `autocommit_group_commit` cannot isolate).
//!   2. **The un-acked in-flight batch is dropped WHOLE** — its records were written to the WAL file but
//!      its `fdatasync` never completed, so a power loss loses it; recovery must show it neither
//!      partially nor fully (durable-prefix atomicity).
//!   3. The recovered store is **structurally consistent** (`check_store`).
//!
//! ## How the crash is made faithful (the gate)
//!
//! A real power loss stops the CPU atomically; injecting `crash()` into a *live* shared sink while the
//! engine keeps running would let the engine deliver acks a real crash never would (unfaithful). So the
//! test freezes the engine at a **clean, quiescent crash point**: a [`Gate`] blocks the deferred
//! `fdatasync` of exactly one batch (the "victim"), parking the engine in `WalSyncThread::wait` —
//! holding no sink/device lock, performing no I/O — with the victim's records written-but-un-synced and
//! un-acked. The test then snapshots the durable prefix and crashes the (shared) sink and device with
//! the engine provably idle. This is exactly the power-loss image: the durable bytes survive, the
//! un-`fdatasync`'d victim tail is gone.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use graphus_core::capability::Clock;
use graphus_core::error::Result;
use graphus_core::{PageId, Value};
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE, Page};
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine};
use graphus_storage::RecordStore;
use graphus_storage::check::check_store;
use graphus_storage::recovery::recover_device;
use graphus_wal::{FsyncJob, LogSink, MemLogSink, WalManager};

/// A monotonic real clock — the engine only reads `now_nanos` for latency/age bookkeeping.
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

/// A gate that blocks the deferred `fdatasync` of a single batch so the engine parks in
/// `WalSyncThread::wait` at a clean, I/O-free crash point.
///
/// Starts **open** (every batch's deferred harden runs through immediately). [`close`](Gate::close)
/// makes the *next* harden job block in its `run()`; when that job blocks it flips `parked`, which
/// [`wait_parked`](Gate::wait_parked) observes. [`open`](Gate::open) releases the blocked job (teardown).
struct Gate {
    state: Mutex<GateState>,
    cv: Condvar,
}

#[derive(Default)]
struct GateState {
    open: bool,
    parked: bool,
}

impl Gate {
    fn new_open() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(GateState {
                open: true,
                parked: false,
            }),
            cv: Condvar::new(),
        })
    }

    fn close(&self) {
        self.state.lock().expect("gate lock").open = false;
    }

    fn open(&self) {
        let mut s = self.state.lock().expect("gate lock");
        s.open = true;
        self.cv.notify_all();
    }

    /// Called from inside the deferred `fdatasync` job. If the gate is closed, mark the job parked
    /// (waking any `wait_parked`) and block until the gate reopens.
    fn block_if_closed(&self) {
        let mut s = self.state.lock().expect("gate lock");
        if !s.open {
            s.parked = true;
            self.cv.notify_all();
            while !s.open {
                s = self.cv.wait(s).expect("gate wait");
            }
        }
    }

    /// Blocks until the gated job has actually parked (so the engine is provably frozen in `wait`).
    fn wait_parked(&self) {
        let mut s = self.state.lock().expect("gate lock");
        while !s.parked {
            s = self.cv.wait(s).expect("gate wait");
        }
    }
}

/// Reopens the gate on drop, so a test that panics mid-crash can never hang the engine thread.
struct GateGuard(Arc<Gate>);
impl Drop for GateGuard {
    fn drop(&mut self) {
        self.0.open();
    }
}

/// A [`LogSink`] shared between the engine thread and the test thread: it wraps a **deferred-harden**
/// [`MemLogSink`] behind an `Arc<Mutex<…>>` so the test can snapshot the durable prefix and `crash()`
/// the un-synced tail from outside the engine. It also counts physical hardens (`begin_harden`/`sync`)
/// to prove the concurrent writers really coalesced through the pipelined group-commit path, and gates
/// exactly one batch's deferred `fdatasync` via [`Gate`] to create a faithful un-synced-tail crash.
#[derive(Clone)]
struct SharedGatedSink {
    inner: Arc<Mutex<MemLogSink>>,
    hardens: Arc<AtomicU64>,
    gate: Arc<Gate>,
}

impl SharedGatedSink {
    fn new(gate: Arc<Gate>) -> (Self, Arc<Mutex<MemLogSink>>, Arc<AtomicU64>) {
        // Deferred-harden mode: `begin_harden` moves the batch into the written-but-un-synced frontier
        // WITHOUT advancing `durable_len`, exactly the production commit-pipeline crash window.
        let inner = Arc::new(Mutex::new(MemLogSink::with_deferred_harden()));
        let hardens = Arc::new(AtomicU64::new(0));
        (
            Self {
                inner: Arc::clone(&inner),
                hardens: Arc::clone(&hardens),
                gate,
            },
            inner,
            hardens,
        )
    }
}

impl LogSink for SharedGatedSink {
    fn append(&mut self, bytes: &[u8]) {
        self.inner.lock().expect("sink lock").append(bytes);
    }

    fn sync(&mut self) -> Result<()> {
        self.hardens.fetch_add(1, Ordering::Relaxed);
        self.inner.lock().expect("sink lock").sync()
    }

    fn begin_harden(&mut self) -> Result<FsyncJob> {
        self.hardens.fetch_add(1, Ordering::Relaxed);
        // The inner deferred sink moves `pending` into the written-but-un-synced frontier and returns a
        // deferred (no-op `fdatasync`) job. Wrap that job's `run` behind the gate: while the gate is
        // closed the job blocks, so the engine parks in `WalSyncThread::wait` with this batch un-synced.
        let inner_job = self.inner.lock().expect("sink lock").begin_harden()?;
        let target = inner_job.target_len();
        let gate = Arc::clone(&self.gate);
        Ok(FsyncJob::deferred(
            move || {
                gate.block_if_closed();
                inner_job.run()
            },
            target,
        ))
    }

    fn complete_harden(&mut self, target_len: u64) {
        self.inner
            .lock()
            .expect("sink lock")
            .complete_harden(target_len);
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

/// A [`BlockDevice`] sharing one [`MemBlockDevice`] between the engine and the test, so the test can
/// `crash()` the un-synced page cache and snapshot the durable image from outside the engine.
#[derive(Clone)]
struct SharedDevice {
    inner: Arc<Mutex<MemBlockDevice>>,
}

impl SharedDevice {
    fn new() -> (Self, Arc<Mutex<MemBlockDevice>>) {
        let inner = Arc::new(Mutex::new(MemBlockDevice::new(0)));
        (
            Self {
                inner: Arc::clone(&inner),
            },
            inner,
        )
    }
}

impl BlockDevice for SharedDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        self.inner.lock().expect("device lock").read_page(page, buf)
    }
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
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

/// Snapshots the crashed durable page image of a shared device: drops the un-synced cache (power loss)
/// then reads back every persisted page. Must be called with the engine provably idle.
fn crash_and_snapshot_device(dev: &Arc<Mutex<MemBlockDevice>>) -> Vec<Page> {
    let mut d = dev.lock().expect("device lock");
    d.crash();
    let n = d.page_count();
    (0..n)
        .map(|i| {
            let mut buf = [0u8; PAGE_SIZE];
            d.read_page(PageId(i), &mut buf)
                .expect("read persisted page");
            buf
        })
        .collect()
}

const POOL_CAPACITY: usize = 256;

/// Spawns a threaded engine over the shared gated sink + shared device (a fresh, empty store).
fn spawn_shared_engine(sink: SharedGatedSink, device: SharedDevice) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(RealClock);
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<SharedDevice, SharedGatedSink, _>(
        Arc::from("gc_crash"),
        move || {
            let wal = WalManager::create(sink)?;
            let store = RecordStore::create(device, wal, POOL_CAPACITY, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        8192,
        256,
        2,
        metrics,
        clock,
        std::sync::Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn shared-store engine")
}

/// One auto-commit `CREATE (:Acct {id})`, drained to end-of-stream (the ack-after-fsync signal).
/// Returns true iff it committed (drained to a clean `Ok(None)` close).
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

/// Rebuilds a store from the crashed image: the durable WAL prefix + the crashed device pages, replays
/// recovery, opens, and returns the (warm) store for inspection.
fn recover_store(
    wal_bytes: &[u8],
    device_pages: &[Page],
) -> RecordStore<MemBlockDevice, MemLogSink> {
    // The recovered WAL is an ordinary (inline) sink seeded with the durable prefix.
    let mut sink = MemLogSink::new();
    sink.append(wal_bytes);
    sink.sync().expect("sync recovered WAL prefix");

    // The recovered device is the crashed durable image (dirty pages that never reached disk are absent;
    // recovery redo reconstructs them from the WAL).
    let mut device = MemBlockDevice::new(device_pages.len() as u64);
    for (i, page) in device_pages.iter().enumerate() {
        device
            .write_page(PageId(i as u64), page)
            .expect("stage recovered page");
    }
    device.sync_all().expect("persist recovered device image");

    let mut wal = WalManager::open(sink.clone()).expect("open recovered WAL");
    recover_device(&mut wal, &mut device).expect("recover device");
    let wal = WalManager::open(sink).expect("reopen recovered WAL");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open recovered store")
}

/// The full deliverable-1 scenario: N concurrent auto-commit writers coalesce through the pipelined
/// group commit; the engine is then frozen (gated) with a genuine written-but-un-synced, un-acked
/// victim batch in flight; a hard crash drops that tail; recovery from the durable prefix shows every
/// acked write survived, the un-acked victim is absent, and the store is consistent.
///
/// Looped a bounded number of times (the crash point is deterministic once parked, but the concurrent
/// coalescing that fills the pipeline is scheduler-dependent — the loop shakes out interleavings).
#[test]
fn concurrent_group_commit_survives_hard_crash_and_drops_unacked_batch() {
    const ITERS: usize = 4;
    const W: usize = 8;
    const M: i64 = 60; // writes per thread
    const SENTINEL: i64 = -777; // the victim id (never acked, must not survive)

    for iter in 0..ITERS {
        let acked_total = run_one_crash_recovery(iter, W, M, SENTINEL);
        // Every concurrent write committed (distinct ids ⇒ no SSI abort), so the acked count is exact.
        assert_eq!(
            acked_total,
            W as i64 * M,
            "iter {iter}: every concurrent auto-commit write must be acked (drained to end-of-stream)"
        );
    }
}

/// Runs one crash/recovery cycle, returning the number of concurrent writes that were acked (the
/// warmup write is separate). Panics on any invariant violation.
fn run_one_crash_recovery(iter: usize, w: usize, m: i64, sentinel: i64) -> i64 {
    let gate = Gate::new_open();
    let (sink, sink_inner, hardens) = SharedGatedSink::new(Arc::clone(&gate));
    let (device, device_inner) = SharedDevice::new();

    let engine = spawn_shared_engine(sink, device);
    let handle = engine.handle.clone();

    // Warm the catalog (intern the `Acct` label + `id` prop key) so the concurrent phase is steady state
    // and the harden baseline is captured afterwards.
    assert!(write_acct(&handle, -1), "iter {iter}: warmup write commits");
    let hardens_before = hardens.load(Ordering::Relaxed);

    // ---- Concurrent phase: W writers × M distinct-id writes through the pipelined group commit. ----
    let acked = Arc::new(AtomicU64::new(0));
    let mut writers = Vec::new();
    for t in 0..w {
        let h = handle.clone();
        let acked = Arc::clone(&acked);
        writers.push(std::thread::spawn(move || {
            let base = (t as i64 + 1) * 1_000_000;
            let mut n = 0u64;
            for k in 0..m {
                if write_acct(&h, base + k) {
                    n += 1;
                }
            }
            acked.fetch_add(n, Ordering::Relaxed);
        }));
    }
    for th in writers {
        th.join().expect("writer joins");
    }
    let acked_total = acked.load(Ordering::Relaxed) as i64;
    let total_commits = acked_total; // one commit per acked write

    // Coalescing is REAL: the concurrent phase hardened far fewer times than it committed — proof the
    // writers went through the pipelined group-commit path (not one inline `fdatasync` per statement).
    let concurrent_hardens = hardens.load(Ordering::Relaxed) - hardens_before;
    assert!(
        concurrent_hardens > 0,
        "iter {iter}: the concurrent phase must perform real hardens (durability), got 0"
    );
    assert!(
        concurrent_hardens < total_commits as u64,
        "iter {iter}: writes must COALESCE through the group commit: {concurrent_hardens} hardens for \
         {total_commits} commits (an inline-per-statement path would be >= {total_commits})"
    );

    // ---- Freeze the engine with a written-but-un-synced, un-acked VICTIM batch in flight. ----
    // Close the gate so the NEXT batch's deferred `fdatasync` blocks; the writers are all joined, so
    // the only batch after this point is the victim below.
    let _gate_guard = GateGuard(Arc::clone(&gate));
    gate.close();
    let victim = {
        let h = handle.clone();
        std::thread::spawn(move || {
            // This commit's records are written to the WAL frontier (begin_harden) but its deferred
            // `fdatasync` blocks on the gate, so it is NEVER acked before the crash. `write_acct`
            // returns only after the engine unblocks at teardown — its result is deliberately ignored.
            let _ = write_acct(&h, sentinel);
        })
    };
    // Wait until the victim's harden job has actually parked: the engine is now frozen in
    // `WalSyncThread::wait`, holding no sink/device lock and doing no I/O — a clean crash point.
    gate.wait_parked();

    // The written-but-un-synced overlap window is genuinely present: the victim's records are in the WAL
    // frontier (buffered) but not durable — exactly the crash window the DST simulator cannot express.
    let (window, durable_at_crash, wal_bytes) = {
        let g = sink_inner.lock().expect("sink lock");
        (
            g.buffered_len() - g.durable_len(),
            g.durable_len(),
            g.durable_bytes(),
        )
    };
    assert!(
        window > 0,
        "iter {iter}: the victim batch must be written-but-un-synced (buffered {} > durable {})",
        durable_at_crash + window,
        durable_at_crash
    );

    // ---- HARD CRASH image (power loss — NO graceful final harden). ----
    // `wal_bytes` above (`durable_bytes()`) is precisely the durable WAL prefix as it stood at ack time:
    // it EXCLUDES the victim's written-but-un-synced `fdatasync`-pending frontier, exactly what a power
    // loss keeps. So it already IS the crashed WAL image — we deliberately do NOT call `crash()` on the
    // LIVE sink, because the engine is still running (parked): mutating its sink out from under it would
    // later trip the engine's own ack-after-fsync invariant (`rmp` #596) when it completes the gated
    // victim, an artifact of injecting a crash into a live engine rather than a real product fault.
    //
    // The victim's data page is likewise absent from the device by construction: WAL-before-data forbids
    // evicting a dirty page whose `page_lsn` is not yet durable, and the victim's WAL is un-synced — so
    // its page cannot have reached the device. We still crash the device (drop its un-synced page cache)
    // to model the full power loss faithfully; recovery redoes the acked writes from the durable WAL.
    let device_pages = crash_and_snapshot_device(&device_inner);

    // ---- Recover from the durable prefix and assert the invariants. ----
    let mut store = recover_store(&wal_bytes, &device_pages);
    let report = check_store(&mut store, &[]).expect("consistency check runs");
    assert!(
        report.is_consistent(),
        "iter {iter}: recovered store is structurally inconsistent after the crash: {:?}",
        report.violations
    );

    // Every acked write (the warmup + all W×M concurrent writes) survives; the un-acked victim does NOT.
    // Each write is exactly one `:Acct` node, so `live_nodes` is the surviving-write count. A count of
    // `acked_total + 1` proves BOTH properties at once: all acked writes present (>= that many) AND the
    // un-acked victim absent (not one more).
    let expected_live = acked_total as u64 + 1; // + the warmup
    assert_eq!(
        report.live_nodes, expected_live,
        "iter {iter}: recovery must keep exactly the acked writes (warmup + {acked_total} concurrent) \
         and DROP the un-acked victim — expected {expected_live} live nodes, saw {}. A larger count \
         means the un-synced victim leaked (durable-prefix atomicity violated); a smaller count means \
         an acked write was lost (ack-was-not-ack-after-fsync).",
        report.live_nodes
    );

    // Belt-and-suspenders: prove the victim id is genuinely absent (not merely a coincidental count) by
    // scanning the recovered store's node properties for the sentinel value.
    assert!(
        !recovered_contains_sentinel(&mut store, sentinel),
        "iter {iter}: the un-acked victim node (id {sentinel}) must be absent after a power-loss crash"
    );

    // ---- Teardown: release the gate, let the engine ack+finish the (now-crashed) victim, shut down. ----
    drop(_gate_guard); // reopen the gate (also happens on panic)
    victim.join().expect("victim thread joins");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build shutdown runtime");
    // The engine may legitimately fail its final flush against the crashed shared device; either way it
    // must not hang. Submit Shutdown (which exits the loop), then drop EVERY handle before joining.
    let _ = rt.block_on(handle.shutdown());
    let Engine {
        handle: owned,
        join,
    } = engine;
    drop(handle);
    drop(owned);
    join.join().expect("engine thread joins");

    acked_total
}

/// Scans a recovered store for a node carrying the sentinel `id` property. Returns true iff any
/// visible node has an `id` property that decodes to `Value::Integer(sentinel)` — i.e. the un-acked
/// victim survived (which it must not).
fn recovered_contains_sentinel(
    store: &mut RecordStore<MemBlockDevice, MemLogSink>,
    sentinel: i64,
) -> bool {
    for node in store.scan_node_ids().unwrap_or_default() {
        if let Ok(props) = store.superset_scan_node_properties(node) {
            for (_pid, pr) in props.every_version() {
                if let Ok(Value::Integer(v)) =
                    graphus_storage::propenc::decode_inline(pr.type_tag, pr.value_inline)
                    && v == sentinel
                {
                    return true;
                }
            }
        }
    }
    false
}
