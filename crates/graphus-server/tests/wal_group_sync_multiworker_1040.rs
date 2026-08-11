//! **The shared WAL fsync group leader under real threads, at `W > 1` (`rmp` #1040).**
//!
//! ## The gap this owns
//!
//! `autocommit_group_commit.rs` proves that concurrent auto-commit writers coalesce behind few
//! *hardens* — the group commit — and `group_commit_crash_recovery.rs` proves that a hard crash in
//! the written-but-un-synced window loses the un-acked batch whole. Both run the engine with **one**
//! worker, so neither can see the property this file exists for: what happens when several engine
//! workers are between `begin_harden` and `complete_harden` **at the same time**, over one
//! `WalManager`.
//!
//! Before `rmp` #1040 the answer was `W` independent fsync threads, each "depth-1" for itself and
//! none for the system: `W` `fdatasync`s of overlapping ranges, no coalescing between workers, and a
//! documented invariant ("at most one batch is ever written-but-un-synced") that had silently stopped
//! being true when the engine became multi-worker. Now there is ONE leader per database, and one
//! worker's `fdatasync` releases every worker waiting on a frontier at or below it.
//!
//! ## What it pins
//!
//! 1. **Every concurrent write is acked.** The shared leader must release every waiter, including the
//!    ones whose own job it folded away — a leader that released only the offering worker would hang
//!    the rest, and a leader that lost a job would hang one for good (which `wait_hardened`'s
//!    liveness assertion turns into a diagnosable abort rather than a stuck server).
//! 2. **Ack-after-fsync, observed from outside the engine.** For every write, the frontier an
//!    `fdatasync` has actually COMPLETED over — sampled from inside the syscall, not from the sink's
//!    bookkeeping about it — is, after the ack, beyond the buffered frontier sampled *before* the
//!    write was even submitted. So the ack cannot have been given over bytes no `fdatasync` had yet
//!    reached. (The engine's own always-on gate in `ack_prepared_commits` checks the exact commit LSN
//!    against the sink's watermark; this is the physical witness of the same rule, taken through the
//!    real wire path with several workers sharing one leader.)
//! 3. **Every row survives a restart**, recovered from the durable WAL and the on-disk device.
//! 4. **The leader actually FOLDS** — its `graphus_wal_fsync_coalesced_total` counter, which counts
//!    the `fdatasync`s it did not issue because a concurrent worker's job already covered the range,
//!    is non-zero — and the hardens are in turn fewer than the commits, the group commit. The fold is
//!    the part this task moved: it was structurally zero when every worker had its own fsync thread,
//!    because there was nobody to coalesce with. It is asserted from the counter rather than from a
//!    syscall ratio because a ratio measures the host's disk (see `TempDir::new`).
//!
//! Real files and a real `fdatasync` throughout: a no-op sync would drain the leader between offers
//! and there would be nothing to fold, which is precisely the interleaving that must not be assumed
//! away.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_core::error::Result;
use graphus_io::FileBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine_with_timeout};
use graphus_storage::RecordStore;
use graphus_storage::check::check_store;
use graphus_storage::recovery::recover_device;
use graphus_wal::{FileLogSink, FsyncJob, LogSink, WalManager};

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

/// What the test observes about the WAL, published from inside the sink so the test thread never has
/// to take the WAL's lock to look.
#[derive(Default)]
struct WalProbe {
    /// `begin_harden` calls that had a genuinely un-synced range to harden — the number of times a
    /// worker ASKED for durability.
    hardens: AtomicU64,
    /// Deferred jobs whose `run()` actually executed — the number of real `fdatasync`s. Lower than
    /// `hardens` exactly to the extent the leader folded concurrent offers together.
    fsyncs: AtomicU64,
    /// The highest byte offset an `fdatasync` has actually **completed** over — published from
    /// inside the job's `run()` and from `sync()`, i.e. from the syscall itself rather than from the
    /// sink's bookkeeping about it. This is what makes the ack-after-fsync witness below physical: an
    /// engine that advanced `durable_len` without waiting for the sync would move `durable` and leave
    /// this behind.
    synced: AtomicU64,
    /// The sink's `durable_len`, republished after every call that can advance it.
    durable: AtomicU64,
    /// The sink's `buffered_len`, republished after every call that can advance it. Monotone, so a
    /// value read here is always at or below the true current one — which is what makes it sound to
    /// use as a lower bound for "where this write's records must start".
    buffered: AtomicU64,
}

/// A [`LogSink`] that forwards to a real [`FileLogSink`] and publishes what the test needs to see.
struct ProbedSink {
    inner: FileLogSink,
    probe: Arc<WalProbe>,
}

impl ProbedSink {
    fn publish(&self) {
        self.probe
            .durable
            .store(self.inner.durable_len(), Ordering::Relaxed);
        self.probe
            .buffered
            .store(self.inner.buffered_len(), Ordering::Relaxed);
    }
}

impl LogSink for ProbedSink {
    fn append(&mut self, bytes: &[u8]) {
        self.inner.append(bytes);
        self.publish();
    }

    fn sync(&mut self) -> Result<()> {
        if self.inner.buffered_len() > self.inner.durable_len() {
            self.probe.hardens.fetch_add(1, Ordering::Relaxed);
            self.probe.fsyncs.fetch_add(1, Ordering::Relaxed);
        }
        let r = self.inner.sync();
        if r.is_ok() {
            self.probe
                .synced
                .fetch_max(self.inner.durable_len(), Ordering::Relaxed);
        }
        self.publish();
        r
    }

    fn begin_harden(&mut self) -> Result<FsyncJob> {
        let real = self.inner.buffered_len() > self.inner.durable_len();
        if real {
            self.probe.hardens.fetch_add(1, Ordering::Relaxed);
        }
        let job = self.inner.begin_harden()?;
        self.publish();
        // Forward the inner job's declared range UNCHANGED — a decorator that re-derived
        // `covers_from` would be claiming a durable frontier the sink underneath does not have
        // (THE SINK CONTRACT, property 2, on `FsyncJob`). Only the counting is added.
        let covers_from = job.covers_from();
        let target = job.target_len();
        let probe = Arc::clone(&self.probe);
        Ok(FsyncJob::deferred(
            move || {
                probe.fsyncs.fetch_add(1, Ordering::Relaxed);
                let r = job.run();
                if r.is_ok() {
                    // Published from the syscall's own completion, BEFORE the leader records the
                    // job as hardened and therefore before any worker can complete or ack over it.
                    probe.synced.fetch_max(target, Ordering::Relaxed);
                }
                r
            },
            covers_from,
            target,
        ))
    }

    fn complete_harden(&mut self, target_len: u64) {
        self.inner.complete_harden(target_len);
        self.publish();
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
        let r = self.inner.reclaim(from, up_to);
        self.publish();
        r
    }

    fn reclaimed_floor(&self) -> u64 {
        self.inner.reclaimed_floor()
    }
}

/// A unique scratch directory, removed on drop.
struct TempDir {
    path: PathBuf,
}
impl TempDir {
    fn new(tag: &str) -> Self {
        // `CARGO_TARGET_TMPDIR`, NOT `std::env::temp_dir()`. `temp_dir()` honours `$TMPDIR`, which CI
        // images, containers and speed-conscious developers routinely point at tmpfs — and on tmpfs
        // an `fdatasync` is nearly free, so the leader drains between offers and the fold legitimately
        // vanishes (measured: the fsync/harden ratio goes from ~0.55 to 0.877 under
        // `TMPDIR=/dev/shm`). This test asserts a property of the CODE, so it must not be measuring
        // the host's page cache. The Cargo-provided directory lives under the build's `target/`,
        // which is the same real filesystem the repository is on.
        let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "graphus_walgroup_{tag}_{}_{}",
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

/// Spawns a **multi-worker** engine over a fresh file-backed store whose WAL sink is the probe.
fn create_engine(
    dir: &Path,
    probe: Arc<WalProbe>,
    engine_workers: usize,
    metrics: Arc<graphus_server::metrics::Metrics>,
) -> Engine {
    let device_path = dir.join("graph.db");
    let wal_dir = dir.join("wal");
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(RealClock);
    spawn_engine_with_timeout::<FileBlockDevice, ProbedSink, _>(
        Arc::from("walgroup"),
        move || {
            let device = FileBlockDevice::open(&device_path)?;
            let inner = FileLogSink::open(&wal_dir)?;
            let wal = WalManager::create(ProbedSink { inner, probe })?;
            let store = RecordStore::create(device, wal, 65_536, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        8192,
        256,
        4,
        // The point of the test: several engine workers, hence several commit pipelines, over ONE
        // WAL and ONE fsync leader.
        engine_workers,
        metrics,
        clock,
        None,
        None,
        None,
        Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn multi-worker engine")
}

/// One auto-commit `CREATE (:Acct {id})`, drained to end-of-stream (the ack-after-fsync signal).
/// Returns true iff it committed.
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

/// Gracefully shuts the engine down (final harden) and joins every worker.
fn graceful_shutdown(engine: Engine) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build shutdown runtime");
    rt.block_on(engine.handle.shutdown())
        .expect("graceful shutdown");
    for j in engine.joins {
        let _ = j.join();
    }
}

/// Reopens the store from disk (recover, then open) and reports its consistency check.
fn reopen_and_check(dir: &Path) -> graphus_storage::check::ConsistencyReport {
    let device_path = dir.join("graph.db");
    let wal_dir = dir.join("wal");
    let mut device = FileBlockDevice::open(&device_path).expect("reopen device");
    let sink = FileLogSink::open(&wal_dir).expect("reopen wal");
    let mut wal = WalManager::open(sink).expect("open wal manager");
    recover_device(&mut wal, &mut device).expect("recover device");
    let sink = FileLogSink::open(&wal_dir).expect("reopen wal for the store");
    let wal = WalManager::open(sink).expect("reopen wal manager");
    let store = RecordStore::open(device, wal, 65_536).expect("reopen store");
    check_store(&store, &[]).expect("consistency check runs")
}

/// Four engine workers, eight concurrent auto-commit writers, one WAL and one fsync group leader.
#[test]
fn concurrent_workers_share_one_fsync_leader_and_every_ack_is_durable() {
    const WORKERS: usize = 4;
    const WRITERS: usize = 8;
    const PER_WRITER: i64 = 50;
    let total = WRITERS as i64 * PER_WRITER;

    let dir = TempDir::new("shared");
    let probe = Arc::new(WalProbe::default());
    // The engine's own metrics registry, held here so the test can read the counter the fsync leader
    // publishes — the same series an operator scrapes as `graphus_wal_fsync_coalesced_total`.
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    let engine = create_engine(&dir.path, Arc::clone(&probe), WORKERS, Arc::clone(&metrics));
    let handle = engine.handle.clone();

    // Warm the catalog (intern the `Acct` label and the `id` property key) so the measured phase is
    // steady state rather than first-write bookkeeping.
    assert!(write_acct(&handle, -1), "warmup write commits");
    let hardens_before = probe.hardens.load(Ordering::Relaxed);
    let fsyncs_before = probe.fsyncs.load(Ordering::Relaxed);

    let acked = Arc::new(AtomicU64::new(0));
    // Counts the writes for which the durable frontier after the ack had NOT passed the buffered
    // frontier sampled before the write was submitted — the externally visible ack-after-fsync
    // violation. Must stay zero.
    let premature = Arc::new(AtomicU64::new(0));
    let mut writers = Vec::new();
    for t in 0..WRITERS {
        let h = handle.clone();
        let acked = Arc::clone(&acked);
        let premature = Arc::clone(&premature);
        let probe = Arc::clone(&probe);
        writers.push(std::thread::spawn(move || {
            let base = (t as i64 + 1) * 1_000_000;
            for k in 0..PER_WRITER {
                // Sampled BEFORE the statement is submitted, so this write's records can only land
                // at or above it (the buffered frontier is monotone).
                let buffered_before = probe.buffered.load(Ordering::Relaxed);
                if write_acct(&h, base + k) {
                    acked.fetch_add(1, Ordering::Relaxed);
                    // The frontier an `fdatasync` has actually COMPLETED over — not the sink's
                    // bookkeeping about it — so this fails if the engine ever advances the durable
                    // watermark without waiting for the syscall it was offered to.
                    if probe.synced.load(Ordering::Relaxed) <= buffered_before {
                        premature.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for w in writers {
        w.join().expect("writer joins");
    }

    // (1) Every write was acked. Distinct ids across writers, so nothing can legitimately abort; a
    // shortfall means the leader failed to release a worker whose job it folded away.
    assert_eq!(
        acked.load(Ordering::Relaxed),
        total as u64,
        "every concurrent auto-commit write must be acknowledged with {WORKERS} engine workers \
         sharing one WAL fsync leader"
    );

    // (2) No ack ran ahead of durability.
    assert_eq!(
        premature.load(Ordering::Relaxed),
        0,
        "a write was acked while the WAL's durable frontier had not yet passed the point its own \
         records start at — the ack-after-fsync rule broken under a shared fsync leader"
    );

    let hardens = probe.hardens.load(Ordering::Relaxed) - hardens_before;
    let fsyncs = probe.fsyncs.load(Ordering::Relaxed) - fsyncs_before;

    // (3) Every row survives a restart, recovered from the durable WAL and the device image.
    graceful_shutdown(engine);
    let report = reopen_and_check(&dir.path);
    assert!(
        report.is_consistent(),
        "the reopened store is structurally inconsistent: {:?}",
        report.violations
    );
    assert_eq!(
        report.live_nodes,
        total as u64 + 1,
        "every acked write (warmup + {total} concurrent) must be present after a restart"
    );

    // (4) The coalescing this task delivered. `hardens` is how many times a worker asked for
    // durability; `fsyncs` is how many `fdatasync`s the leader actually issued for them. With one
    // fsync thread PER WORKER the second number was the first by construction — every ask was its
    // own syscall, and there was nobody to fold with.
    assert!(
        fsyncs > 0,
        "the measured phase must perform real fdatasyncs (durability), got 0"
    );
    assert!(
        hardens > 0,
        "the measured phase must perform real hardens, got 0"
    );
    // The proof is STRUCTURAL, not a ratio. The leader counts every offer it folded onto another
    // batch's job, so `> 0` says the fold happened — a fact about the code, true on any host.
    //
    // A ratio cannot say that. `fsyncs < hardens` is satisfied by a single lucky overlap (verified: a
    // build that ran every folded-away job inline instead of dropping it measured 292 fdatasyncs for
    // 293 hardens and passed it), and a material bar like `fsyncs * 4 <= hardens * 3` measures the
    // HOST: it holds at ~0.55 on a real disk and fails deterministically at ~0.88 on tmpfs, where a
    // near-free fsync drains the leader between offers. The WAL directory above is pinned to a real
    // filesystem for the same reason, so the printed ratio stays meaningful — but it is an
    // observation, recorded with the run, not the gate.
    let folds = metrics.wal_fsync_coalesced();
    assert!(
        folds > 0,
        "the shared leader folded NOTHING across {total} commits on {WORKERS} workers: every offer \
         got its own fdatasync, which is the per-worker fsync thread this replaced wearing a \
         different name"
    );
    assert!(
        hardens < total as u64,
        "the group commit must still coalesce commits into batches: {hardens} hardens for {total} \
         commits"
    );
    // Printed so the ratio is recorded with the run rather than inferred from the assertions.
    println!(
        "rmp #1040: workers={WORKERS} writers={WRITERS} commits={total} hardens={hardens} \
         fdatasyncs={fsyncs} folds={folds} (fsync/commit = {:.3}, fsync/harden = {:.3})",
        fsyncs as f64 / total as f64,
        fsyncs as f64 / hardens as f64,
    );
}
