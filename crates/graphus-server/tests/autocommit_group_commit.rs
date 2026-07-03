//! Regression tests for rmp #566 T1 — **auto-commit write fsync coalescing / group commit**.
//!
//! Before #566, an auto-commit write (`CREATE …` sent without an explicit `BEGIN`/`COMMIT`) drove an
//! **inline `fdatasync` per statement on the engine thread**, bypassing the #528/#532 group-commit
//! coalescing that explicit `BEGIN…COMMIT` already used. #566 routes auto-commit writes through the same
//! `commit_prepare` + off-thread `WalSyncThread` harden path, so many concurrent auto-commit writers'
//! `fdatasync`s **coalesce into shared syncs off the engine thread**.
//!
//! These tests guard the two failure modes the #532 rework was reverted for twice:
//!   * **Inert offload** — the sync is not actually coalesced. Guarded by a `CountingSink` that counts
//!     every physical harden (`begin_harden` / `sync`): under concurrency the harden count MUST be
//!     strictly LESS than the commit count (many commits per sync).
//!   * **Lost / non-durable ack** — a committer is acked before its record is durable, or a committed
//!     write is lost. Guarded by draining every write to end-of-stream (the ack-after-fsync signal),
//!     asserting every write is visible, and asserting every write survives a graceful restart
//!     (recover-from-WAL reopen).
//!
//! Run: `cargo test -p graphus-server --test autocommit_group_commit`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_core::error::Result;
use graphus_io::FileBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine};
use graphus_storage::RecordStore;
use graphus_storage::recovery::recover_device;
use graphus_wal::{FileLogSink, FsyncJob, LogSink, WalManager};

/// A monotonic real clock — the engine only reads `now_nanos` (for latency/age bookkeeping).
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

/// A [`LogSink`] that wraps a real [`FileLogSink`] and counts every **physical harden** — a
/// `begin_harden` (the pipelined group-commit path's batch `fdatasync`, offloaded to `WalSyncThread`)
/// or a `sync` (an inline eviction / explicit flush harden). One harden == one real `fdatasync` event.
/// The shared counter lets the test thread observe the engine thread's harden count and assert that
/// many auto-commit commits coalesced behind few syncs (`rmp` #566, the anti-"inert offload" guard).
struct CountingSink {
    inner: FileLogSink,
    hardens: Arc<AtomicU64>,
}

impl LogSink for CountingSink {
    fn append(&mut self, bytes: &[u8]) {
        self.inner.append(bytes);
    }
    fn sync(&mut self) -> Result<()> {
        self.hardens.fetch_add(1, Ordering::Relaxed);
        self.inner.sync()
    }
    fn begin_harden(&mut self) -> Result<FsyncJob> {
        self.hardens.fetch_add(1, Ordering::Relaxed);
        self.inner.begin_harden()
    }
    fn complete_harden(&mut self, target_len: u64) {
        self.inner.complete_harden(target_len);
    }
    fn durable_len(&self) -> u64 {
        self.inner.durable_len()
    }
    fn buffered_len(&self) -> u64 {
        self.inner.buffered_len()
    }
    fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
        self.inner.read_durable(from, into)
    }
    fn read_bounded(&self, from: u64, to: u64, into: &mut Vec<u8>) -> Result<()> {
        self.inner.read_bounded(from, to, into)
    }
    fn reclaim(&mut self, from: u64, up_to: u64) -> Result<()> {
        self.inner.reclaim(from, up_to)
    }
    fn reclaimed_floor(&self) -> u64 {
        self.inner.reclaimed_floor()
    }
}

/// A unique scratch directory holding one engine's `graph.db` + `wal/`, removed on drop.
struct TempDir {
    path: PathBuf,
}
impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "graphus_t1_gc_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Spawns a threaded engine over a **fresh** file-backed store whose WAL sink is the counting wrapper.
fn create_engine(dir: &Path, hardens: Arc<AtomicU64>) -> Engine {
    let device_path = dir.join("graph.db");
    let wal_dir = dir.join("wal");
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(RealClock);
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<FileBlockDevice, CountingSink, _>(
        Arc::from("t1gc"),
        move || {
            let device = FileBlockDevice::open(&device_path)?;
            let inner = FileLogSink::open(&wal_dir)?;
            let wal = WalManager::create(CountingSink { inner, hardens })?;
            let store = RecordStore::create(device, wal, 65_536, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        8192,
        256,
        2,
        metrics,
        clock,
    )
    .expect("spawn fresh file engine")
}

/// Reopens the store from its **durable WAL** (recover then open) — models a restart, proving every
/// acknowledged auto-commit write is truly durable, not merely in-memory-visible.
fn reopen_engine(dir: &Path) -> Engine {
    let device_path = dir.join("graph.db");
    let wal_dir = dir.join("wal");
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(RealClock);
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<FileBlockDevice, FileLogSink, _>(
        Arc::from("t1gc"),
        move || {
            let mut device = FileBlockDevice::open(&device_path)?;
            let sink = FileLogSink::open(&wal_dir)?;
            let mut wal = WalManager::open(sink)?;
            recover_device(&mut wal, &mut device)?;
            let store = RecordStore::open(device, wal, 65_536)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        8192,
        256,
        2,
        metrics,
        clock,
    )
    .expect("reopen file engine")
}

/// One auto-commit write, drained to end-of-stream — the ack-after-fsync signal. Returns true iff it
/// committed (drained to a clean `Ok(None)` close, never an error).
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

/// Counts `:Acct` nodes via an auto-commit read (proves the concurrent writes are committed-visible).
fn count_accts(handle: &EngineHandle) -> i64 {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Read)
        .expect("begin read");
    let mut reply = handle
        .run_blocking(
            ticket,
            "MATCH (n:Acct) RETURN count(n)".to_owned(),
            vec![],
            true,
            None,
        )
        .expect("count runs");
    let mut count = -1;
    while let Ok(Some(cells)) = reply.rows.next() {
        if let Some(graphus_cypher::MaterializedValue::Value(Value::Integer(n))) = cells.first() {
            count = *n;
        }
    }
    count
}

/// Gracefully shuts the engine down (final harden) and joins its thread — so a subsequent reopen sees a
/// clean, fully-durable store.
fn graceful_shutdown(engine: Engine) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build shutdown runtime");
    rt.block_on(engine.handle.shutdown())
        .expect("graceful shutdown");
    engine.join.join().expect("engine thread joins");
}

/// Under concurrency, many auto-commit writers' `fdatasync`s coalesce behind FEW shared hardens (`rmp`
/// #566): the physical harden count is strictly less than the commit count (anti "inert offload"), every
/// write is committed-visible (anti "lost ack"), and every write survives a graceful restart
/// (recover-from-WAL), proving the deferred ack was truly ack-after-fsync durable.
#[test]
fn concurrent_autocommit_writes_coalesce_and_survive_restart() {
    const W: usize = 8;
    const M: i64 = 100; // writes per thread
    let total = W as i64 * M;

    let dir = TempDir::new("coalesce");
    let hardens = Arc::new(AtomicU64::new(0));

    let engine = create_engine(&dir.path, Arc::clone(&hardens));
    let handle = engine.handle.clone();

    // Warm the catalog: intern the `Acct` label + `id` prop key on one write, so the concurrent phase is
    // steady-state (no per-write catalog churn) and the harden baseline is captured after it.
    assert!(write_acct(&handle, -1), "warmup write commits");
    let hardens_before = hardens.load(Ordering::Relaxed);

    // Concurrent phase: W writers, each M distinct-id writes (distinct ids ⇒ no hot set ⇒ no SSI abort ⇒
    // every write must commit). Each write is drained to end-of-stream, so a returned `true` means the
    // engine acked it — which, per #566, happens only AFTER the batch `fdatasync` covered its commit LSN.
    let acked = Arc::new(AtomicU64::new(0));
    let mut threads = Vec::new();
    for t in 0..W {
        let h = handle.clone();
        let acked = Arc::clone(&acked);
        threads.push(std::thread::spawn(move || {
            let base = (t as i64) * 1_000_000;
            let mut n = 0u64;
            for k in 0..M {
                if write_acct(&h, base + k) {
                    n += 1;
                }
            }
            acked.fetch_add(n, Ordering::Relaxed);
        }));
    }
    for th in threads {
        th.join().expect("writer joins");
    }

    // (1) Every concurrent write was acked — the offload delivers acks (never hangs / drops them).
    assert_eq!(
        acked.load(Ordering::Relaxed),
        total as u64,
        "every concurrent auto-commit write must be acknowledged (drained to end-of-stream)"
    );

    // (2) Coalescing is REAL, not inert: the physical harden count during the concurrent phase is
    // strictly LESS than the number of commits — i.e. multiple commits shared each `fdatasync`. An inert
    // offload (or the pre-#566 inline-per-statement sync) would harden once per commit (>= `total`).
    let concurrent_hardens = hardens.load(Ordering::Relaxed) - hardens_before;
    assert!(
        concurrent_hardens > 0,
        "the concurrent phase must perform real hardens (durability), got 0"
    );
    assert!(
        concurrent_hardens < total as u64,
        "auto-commit writes must COALESCE: {concurrent_hardens} hardens for {total} commits \
         (an inert offload / inline-per-statement sync would be >= {total}) — rmp #566"
    );

    // (3) Every committed write is visible (no lost commit, no phantom).
    assert_eq!(
        count_accts(&handle),
        total + 1,
        "all concurrent writes + the warmup must be committed-visible"
    );

    // (4) Durability across a restart: graceful shutdown (final harden), reopen from the durable WAL
    // (ARIES recover), and re-count — every acked write must survive (the ack-after-fsync guarantee).
    drop(handle);
    graceful_shutdown(engine);

    let reopened = reopen_engine(&dir.path);
    let handle2 = reopened.handle.clone();
    assert_eq!(
        count_accts(&handle2),
        total + 1,
        "every acknowledged auto-commit write must survive a recover-from-WAL restart"
    );
    drop(handle2);
    graceful_shutdown(reopened);
}
