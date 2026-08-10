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
        std::sync::Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
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
        std::sync::Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
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
    {
        for j in engine.joins {
            let _ = j.join();
        }
    }
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

/// `rmp` #570 — auto-commit coalescing must NOT collapse as concurrency rises past W=4.
///
/// An auto-commit write is TWO consecutive engine commands: a `BeginAutoCommit` (the ticket
/// round-trip) then the `Run`. With many concurrent writers the engine channel interleaves their
/// `BeginAutoCommit`s BETWEEN the batchable `Run`s. Before #570 an interleaved open was treated as
/// non-batchable — it truncated the group-commit batch at the first open and dropped the engine out of
/// the pipeline loop — so coalescing COLLAPSED at higher W (measured batch ~1.8, i.e.
/// `fdatasync/commit` ~0.55, *worse* than W=4's ~0.27). #570 dispatches the durability-inert
/// transaction-open inline and keeps draining, so the batch grows with W again.
///
/// This test pins the anti-collapse property at W=16: real coalescing (avg batch strictly > 3, which a
/// collapse to ~1.8 fails) AND full durability — every write acked, committed-visible, and surviving a
/// recover-from-WAL restart. It is deliberately conservative (batch > 3, vs. the ~15 measured at W=16)
/// so it never flakes under CI load while still failing hard if the collapse is ever reintroduced.
#[test]
fn autocommit_coalescing_scales_and_does_not_collapse_at_w16() {
    const W: usize = 16;
    const M: i64 = 100; // writes per thread
    let total = W as i64 * M;

    let dir = TempDir::new("noncollapse");
    let hardens = Arc::new(AtomicU64::new(0));
    let engine = create_engine(&dir.path, Arc::clone(&hardens));
    let handle = engine.handle.clone();

    // Warm the catalog (label + prop key interned) so the concurrent phase is steady-state.
    assert!(write_acct(&handle, -1), "warmup write commits");
    let hardens_before = hardens.load(Ordering::Relaxed);

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

    // (1) Every write acked (liveness + the offload never drops/hangs an ack).
    assert_eq!(
        acked.load(Ordering::Relaxed),
        total as u64,
        "every concurrent auto-commit write must be acknowledged"
    );

    // (2) Anti-collapse: strong coalescing — the average batch is strictly > 3 commits per physical
    // harden. A collapse (batch ~1.8) would need >= total/1.8 hardens (> total/3), failing this.
    let concurrent_hardens = hardens.load(Ordering::Relaxed) - hardens_before;
    assert!(
        concurrent_hardens > 0,
        "the concurrent phase must perform real hardens (durability), got 0"
    );
    assert!(
        concurrent_hardens * 3 < total as u64,
        "auto-commit coalescing COLLAPSED at W={W}: {concurrent_hardens} hardens for {total} commits \
         (avg batch {:.2}); #570 requires the interleaved transaction-opens to be folded inline so the \
         batch stays > 3 commits per sync",
        total as f64 / concurrent_hardens as f64,
    );

    // (3) Every committed write is visible.
    assert_eq!(
        count_accts(&handle),
        total + 1,
        "all concurrent writes + the warmup must be committed-visible"
    );

    // (4) Durability across a restart — every acked write survives the recover-from-WAL reopen.
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

/// `rmp` #813 (was `rmp` #807 "a read carries none") — EVERY auto-commit result summary now carries an
/// opaque, monotonic **bookmark** (`"<db>:<ts>"`), minted by the REAL engine, matching a real Neo4j
/// server (which emits a bookmark for read transactions too). A durable WRITE mints its own commit
/// timestamp; a READ mints the DB's **durable-write high-water** — the latest already-durable write it
/// observed. This guards the engine plumbing the Bolt seam surfaces in the terminal `PULL` `SUCCESS`
/// (`finish_autocommit`/reader-pool `run_cursor` -> `bookmark_token`/`durable_write_commit_ts` ->
/// `SummarySink`), which the mock-driven `graphus-bolt` regression cannot exercise. It asserts:
///   * two writes yield strictly increasing bookmarks (causal chaining / `session.last_bookmarks()`);
///   * a read after them yields `>=` the last write's bookmark (**read-your-writes**);
///   * two reads with no write between them yield the **SAME** bookmark — proving the read source is the
///     durable-write watermark and NOT a per-read phantom tick (the `rmp` #529 `snapshot_ts` contamination
///     this task had to avoid; sourcing from `snapshot_ts` would make the two reads differ, so this is the
///     regression that fails RED under the wrong source).
#[test]
fn autocommit_write_summary_carries_a_monotonic_bookmark_and_a_read_carries_a_monotonic_bookmark() {
    let dir = TempDir::new("bookmark813");
    let hardens = Arc::new(AtomicU64::new(0));
    let engine = create_engine(&dir.path, Arc::clone(&hardens));
    let handle = engine.handle.clone();

    // The bookmark on one drained auto-commit write's summary (read AFTER end-of-stream — the
    // ack-after-fsync close is the happens-before edge that publishes the summary, `rmp` #512/#807).
    let write_bookmark = |id: i64| -> Option<String> {
        let ticket = handle
            .begin_auto_commit_blocking(AccessMode::Write)
            .expect("begin write");
        let mut reply = handle
            .run_blocking(
                ticket,
                "CREATE (:Acct {id: $id})".to_owned(),
                vec![("id".to_owned(), Value::Integer(id))],
                true,
                None,
                None,
            )
            .expect("write runs");
        while let Ok(Some(_)) = reply.rows.next() {}
        reply.summary.get().bookmark
    };
    let b1 = write_bookmark(1).expect("a durable auto-commit write mints a bookmark");
    let b2 = write_bookmark(2).expect("the second write mints a bookmark");

    // A read now carries a bookmark too (`rmp` #813): the DB's durable-write high-water, which after the
    // two writes is exactly the last durable one — read-your-writes. Run it TWICE with no write between,
    // to assert both reads return the SAME token (the watermark is not a per-read phantom tick).
    let read_once = || -> Option<String> {
        let read_ticket = handle
            .begin_auto_commit_blocking(AccessMode::Read)
            .expect("begin read");
        let mut read_reply = handle
            .run_blocking(
                read_ticket,
                "MATCH (n:Acct) RETURN count(n)".to_owned(),
                vec![],
                true,
                None,
                None,
            )
            .expect("read runs");
        while let Ok(Some(_)) = read_reply.rows.next() {}
        read_reply.summary.get().bookmark
    };
    let read1 = read_once().expect("a read auto-commit mints a bookmark (`rmp` #813)");
    let read2 = read_once().expect("a second read also mints a bookmark");

    graceful_shutdown(engine);

    // The token is the opaque `"<db>:<ts>"` shape; parse the monotonic numeric suffix.
    let seq = |bm: &str| -> u64 {
        bm.rsplit(':')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("bookmark must be a `<db>:<ts>` token, got {bm:?}"))
    };
    assert!(
        b1.contains(':') && b2.contains(':') && read1.contains(':'),
        "bookmarks are `<db>:<ts>` tokens: {b1:?}, {b2:?}, {read1:?}"
    );
    assert!(
        seq(&b2) > seq(&b1),
        "the engine's per-database write bookmark must advance monotonically: {b1} -> {b2}"
    );
    assert!(
        seq(&read1) >= seq(&b2),
        "a read's bookmark names at least the last durable write it observed (read-your-writes): \
         {b2} -> {read1}"
    );
    assert_eq!(
        read1, read2,
        "two reads with no write between them must return the SAME bookmark — the durable-write \
         high-water is not a per-read phantom tick (`rmp` #813/#529)"
    );
}
