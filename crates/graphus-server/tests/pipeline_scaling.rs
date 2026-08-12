//! MEASUREMENT harness for rmp #570 — autocommit group-commit / pipeline scaling past W=4.
//!
//! Not a regression gate (it prints, asserts only liveness). Run explicitly:
//!   cargo test -p graphus-server --test pipeline_scaling -- --ignored --nocapture
//!
//! For each writer count W it drives W disjoint auto-commit writers (distinct ids ⇒ no SSI abort) and
//! reports: throughput (commits/s), the ENGINE thread's CPU cores, the WALSYNC thread's CPU cores, and
//! the REAL fdatasync/commit ratio (a physical harden counted only when there were un-synced bytes).
//! This is the empirical basis for the #570 taper analysis (engine-thread PREPARE sequencer vs fsync).

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
use graphus_wal::{FileLogSink, FsyncJob, LogSink, WalManager};

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

/// Counts a physical harden only when there are actually un-synced bytes to make durable — the true
/// `fdatasync` count (a no-op begin_harden over an already-durable frontier is NOT counted).
struct CountingSink {
    inner: FileLogSink,
    real_fsyncs: Arc<AtomicU64>,
}
impl CountingSink {
    fn note_if_real(&self) {
        if self.inner.buffered_len() > self.inner.durable_len() {
            self.real_fsyncs.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl LogSink for CountingSink {
    fn append(&mut self, bytes: &[u8]) {
        self.inner.append(bytes);
    }
    fn sync(&mut self) -> Result<()> {
        self.note_if_real();
        self.inner.sync()
    }
    fn begin_harden(&mut self) -> Result<FsyncJob> {
        self.note_if_real();
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

struct TempDir {
    path: PathBuf,
}
impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "graphus_pipe_{tag}_{}_{}",
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

fn create_engine(dir: &Path, real_fsyncs: Arc<AtomicU64>, engine_workers: usize) -> Engine {
    let device_path = dir.join("graph.db");
    let wal_dir = dir.join("wal");
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(RealClock);
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine_with_timeout::<FileBlockDevice, CountingSink, _>(
        Arc::from("pipe"),
        move || {
            let device = FileBlockDevice::open(&device_path)?;
            let inner = FileLogSink::open(&wal_dir)?;
            let wal = WalManager::create(CountingSink { inner, real_fsyncs })?;
            let store = RecordStore::create(device, wal, 65_536, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        8192,
        256,
        4,
        // The measurement's independent variable (`rmp` #1034): how many engine workers serve the
        // command queues. The baseline this table is compared against was taken at 1, when that was
        // the only possibility.
        engine_workers,
        metrics,
        clock,
        None,
        None,
        None,
        std::sync::Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn fresh file engine")
}

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

// --- per-thread CPU sampling via /proc/self/task ------------------------------------------------

/// Sum of utime+stime (clock ticks) over every task thread whose `comm` starts with `prefix`.
fn thread_ticks(prefix: &str) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir("/proc/self/task") else {
        return 0;
    };
    for entry in entries.flatten() {
        let tid = entry.file_name();
        let comm_path = format!("/proc/self/task/{}/comm", tid.to_string_lossy());
        let Ok(comm) = std::fs::read_to_string(&comm_path) else {
            continue;
        };
        if !comm.trim_end().starts_with(prefix) {
            continue;
        }
        let stat_path = format!("/proc/self/task/{}/stat", tid.to_string_lossy());
        let Ok(stat) = std::fs::read_to_string(&stat_path) else {
            continue;
        };
        // Field 14 = utime, 15 = stime (1-indexed). The comm field (2) may contain spaces/parens, so
        // parse after the last ')'.
        if let Some(rparen) = stat.rfind(')') {
            let rest: Vec<&str> = stat[rparen + 1..].split_whitespace().collect();
            // rest[0] = state (field 3); utime is field 14 ⇒ rest[11], stime field 15 ⇒ rest[12].
            if rest.len() > 12 {
                let utime: u64 = rest[11].parse().unwrap_or(0);
                let stime: u64 = rest[12].parse().unwrap_or(0);
                total += utime + stime;
            }
        }
    }
    total
}

fn clk_tck() -> f64 {
    // POSIX _SC_CLK_TCK is 100 on Linux; hard-code (no libc dep on the sysconf path here).
    100.0
}

fn run_w(w: usize, per_thread: i64, engine_workers: usize) {
    let dir = TempDir::new(&format!("w{w}"));
    let real_fsyncs = Arc::new(AtomicU64::new(0));
    let engine = create_engine(&dir.path, Arc::clone(&real_fsyncs), engine_workers);
    let handle = engine.handle.clone();

    // Warmup: intern label+key, reach steady state.
    for i in 0..50 {
        assert!(write_acct(&handle, -1_000 - i), "warmup commits");
    }
    let fsyncs_before = real_fsyncs.load(Ordering::Relaxed);
    let eng_before = thread_ticks("graphus-engine");
    let wal_before = thread_ticks("graphus-walsync");

    let total = w as i64 * per_thread;
    let t0 = std::time::Instant::now();
    let mut threads = Vec::new();
    for t in 0..w {
        let h = handle.clone();
        threads.push(std::thread::spawn(move || {
            let base = (t as i64) * 10_000_000;
            for k in 0..per_thread {
                write_acct(&h, base + k);
            }
        }));
    }
    for th in threads {
        th.join().expect("writer joins");
    }
    let elapsed = t0.elapsed().as_secs_f64();

    let eng_ticks = thread_ticks("graphus-engine").saturating_sub(eng_before);
    let wal_ticks = thread_ticks("graphus-walsync").saturating_sub(wal_before);
    let fsyncs = real_fsyncs.load(Ordering::Relaxed) - fsyncs_before;

    let cps = total as f64 / elapsed;
    let eng_cores = (eng_ticks as f64 / clk_tck()) / elapsed;
    let wal_cores = (wal_ticks as f64 / clk_tck()) / elapsed;
    let fsync_ratio = fsyncs as f64 / total as f64;

    println!(
        "W={w:<2} | {total} commits in {elapsed:6.3}s | {cps:8.1} c/s | engine {eng_cores:4.2} cores \
         | walsync {wal_cores:4.2} cores | {fsyncs} fsyncs = {fsync_ratio:5.3} fdatasync/commit"
    );

    drop(handle);
    graceful_shutdown(engine);
}

#[test]
#[ignore = "measurement harness; run with --ignored --nocapture"]
fn pipeline_scaling_w_1_2_4_8_16() {
    let per_thread: i64 = std::env::var("PIPE_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4_000);
    println!("\n=== rmp #570 pipeline scaling ({per_thread} writes/thread) ===");
    // Two curves, and the pair is what the comparison needs (`rmp` #1034). The first repeats the
    // baseline shape — W client writers against ONE engine worker — so the numbers are directly
    // comparable with the 2026-08-05 table. The second gives the engine a worker per writer, which
    // is what layers 7a/7b/#1035 made possible and what this task exists to measure.
    println!("\n-- engine_workers = 1 (the baseline shape) --");
    for w in [1usize, 2, 4, 8, 16] {
        run_w(w, per_thread, 1);
    }
    println!("\n-- engine_workers = W (one worker per writer) --");
    for w in [1usize, 2, 4, 8, 16] {
        run_w(w, per_thread, w);
    }
    println!("=== end ===\n");
}
