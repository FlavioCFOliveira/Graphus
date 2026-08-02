//! Eviction write-back convoy harness (`rmp` #974).
//!
//! Measures **concurrent read throughput when the working set exceeds the buffer pool**, on a real
//! file-backed device, behind a real [`WalManager`] over a real `FileLogSink`, with the real
//! persistent doublewrite buffer attached. Nothing here is a mock: every `fdatasync` the pool's
//! write-back path issues is a real syscall against the real filesystem, so the measured cost is
//! the cost production pays.
//!
//! # What it is for
//!
//! Once the working set spills the pool, every cache miss must evict a victim, and a *dirty* victim
//! is written home through `write_back`. That path performs up to three `fdatasync`s — the WAL
//! (`ensure_durable`), the doublewrite area (`stage_and_sync`), and the home file (`sync_data`) —
//! and it does so while holding the victim frame's write latch. The home write additionally holds
//! the pool's **exclusive** device guard across its `fdatasync`, and every concurrent cache-miss
//! read needs a **shared** guard on that same lock. This harness quantifies what that costs the
//! readers: reader throughput as a function of reader-thread count, plus the pool's write-back
//! timers (`bufpool-probe`) attributing where the time goes.
//!
//! # Running it
//!
//! ```text
//! cargo bench -p graphus-storage --bench eviction_convoy
//! ```
//!
//! Environment overrides (all optional):
//!
//! - `CONVOY_SECS` — seconds per measured arm (default 5)
//! - `CONVOY_POOL_PAGES` — buffer pool capacity in frames (default 512)
//! - `CONVOY_WORKING_MULT` — working set as a multiple of the pool (default 2)
//! - `CONVOY_READERS` — comma-separated reader-thread counts (default `1,2,4,8,16`)
//! - `CONVOY_WRITERS` — writer threads dirtying pages (default 1)
//! - `CONVOY_DIR` — scratch directory for the store/WAL/doublewrite files

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use graphus_bufpool::{ConcurrentBufferPool, page};
use graphus_core::{Lsn, PageId, Timestamp, TxnId};
use graphus_io::{BlockDevice, FileBlockDevice, PAGE_SIZE, Page};
use graphus_storage::{Dwb, DwbPageStager, SharedWal};
use graphus_wal::{FileLogSink, WalManager};

/// The device under test: a real file-backed device, optionally with its shared durability handle
/// suppressed.
///
/// The serving engine never hands the pool a bare [`FileBlockDevice`] — it wraps every store device
/// in `graphus_server::StoreDevice`, which forwards `sync_handle` for the plaintext variant and
/// deliberately returns `None` for the encrypted one (its sync also persists the AEAD nonce counter
/// and so genuinely needs `&mut self`). Both wirings therefore exist in production, and this wrapper
/// lets the harness measure either instead of quietly reporting only the favourable one.
#[derive(Debug)]
struct ConvoyDevice {
    inner: FileBlockDevice,
    /// When false, [`BlockDevice::sync_handle`] returns `None`, so the pool falls back to issuing
    /// its barrier under the exclusive device guard — the encrypted-store wiring.
    offer_sync_handle: bool,
}

impl BlockDevice for ConvoyDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<(), graphus_core::GraphusError> {
        self.inner.read_page(page, buf)
    }
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<(), graphus_core::GraphusError> {
        self.inner.write_page(page, buf)
    }
    fn write_pages(
        &mut self,
        base: PageId,
        pages: &[&Page],
    ) -> Result<(), graphus_core::GraphusError> {
        self.inner.write_pages(base, pages)
    }
    fn sync_data(&mut self) -> Result<(), graphus_core::GraphusError> {
        self.inner.sync_data()
    }
    fn sync_all(&mut self) -> Result<(), graphus_core::GraphusError> {
        self.inner.sync_all()
    }
    fn sync_handle(&self) -> Option<Arc<dyn graphus_io::SyncHandle>> {
        if self.offer_sync_handle {
            self.inner.sync_handle()
        } else {
            None
        }
    }
    fn page_count(&self) -> u64 {
        self.inner.page_count()
    }
    fn extend(&mut self, additional: u64) -> Result<(), graphus_core::GraphusError> {
        self.inner.extend(additional)
    }
}

/// The pool under test, wired the way the record store wires it: a real file device, the real
/// `SharedWal` over a real `FileLogSink`, and (unless disabled) the real doublewrite stager.
type Pool = ConcurrentBufferPool<ConvoyDevice, SharedWal<FileLogSink>>;

/// A deterministic, per-thread xorshift64* generator. The workload must be reproducible across the
/// before/after arms, so no thread ever touches a shared RNG (which would itself be a contention
/// point and would blur the very measurement we are taking).
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Never seed with zero: xorshift64 has 0 as a fixed point.
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A value in `[0, n)`.
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// Reads a `usize` tunable from the environment, falling back to `default`.
fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The scratch directory holding this run's store, WAL and doublewrite files.
fn scratch_dir() -> PathBuf {
    if let Ok(d) = std::env::var("CONVOY_DIR") {
        return PathBuf::from(d);
    }
    let mut d = std::env::temp_dir();
    d.push(format!(
        "graphus-convoy-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |t| t.as_nanos())
    ));
    d
}

/// Seeds `pages` valid, checksummed, clean pages into a fresh store file at `path`.
///
/// Written directly through the device rather than through the pool, so the fixture is independent
/// of the very eviction path under measurement. Each page carries its own id and `page_lsn == 0`
/// (they start clean: a clean victim is evicted with no write-back at all).
fn seed_store(path: &Path, pages: u64) {
    let mut dev = FileBlockDevice::open(path).expect("open store device");
    if dev.page_count() < pages {
        dev.extend(pages - dev.page_count()).expect("extend store");
    }
    let mut buf: Box<Page> = Box::new([0u8; PAGE_SIZE]);
    for i in 0..pages {
        buf.fill(0);
        page::set_page_id(&mut buf, i);
        page::set_page_lsn(&mut buf, Lsn(0));
        page::write_checksum(&mut buf);
        dev.write_page(PageId(i), &buf).expect("seed write");
    }
    dev.sync_all().expect("seed sync");
}

/// Everything one measured arm needs, rebuilt from scratch per arm so no arm inherits another's
/// warm page cache, dirty set, or WAL length.
struct Rig {
    pool: Arc<Pool>,
    wal: SharedWal<FileLogSink>,
    dir: PathBuf,
    /// The doublewrite stager, kept so its staging timers can be read (`None` when `CONVOY_DWB=0`).
    stager: Option<Arc<DwbPageStager<FileBlockDevice>>>,
}

impl Rig {
    fn build(root: &Path, arm: usize, pool_pages: usize, working_pages: u64) -> Self {
        let dir = root.join(format!("arm{arm}"));
        std::fs::create_dir_all(&dir).expect("create arm dir");

        let store_path = dir.join("store.db");
        seed_store(&store_path, working_pages);
        let device = ConvoyDevice {
            inner: FileBlockDevice::open(&store_path).expect("reopen store device"),
            // `CONVOY_SYNC_HANDLE=0` reproduces the encrypted-store wiring, where the barrier stays
            // under the exclusive device guard.
            offer_sync_handle: env_usize("CONVOY_SYNC_HANDLE", 1) != 0,
        };

        let sink = FileLogSink::open(dir.join("wal")).expect("open wal sink");
        let wal = SharedWal::new(WalManager::create(sink).expect("create wal"));

        let pool = Arc::new(ConcurrentBufferPool::with_wal(
            device,
            wal.clone(),
            pool_pages,
        ));

        // The doublewrite stager is attached by default (the production wiring). It can be left off
        // (`CONVOY_DWB=0`) to *attribute* a bottleneck: the stager holds the DWB device mutex across
        // its own staging `fdatasync`, which serialises evictions independently of anything the pool
        // does, so an arm without it isolates the pool's own contention.
        let stager = if env_usize("CONVOY_DWB", 1) != 0 {
            let dwb_device =
                FileBlockDevice::open(dir.join("doublewrite.dwb")).expect("open dwb device");
            let dwb = Arc::new(Mutex::new(Dwb::new(dwb_device).expect("build dwb")));
            let stager = Arc::new(DwbPageStager::new(dwb));
            // `CONVOY_DWB_BARRIER_UNDER_LOCK=1` reproduces the pre-`rmp` #993 shape (staging barrier
            // inside the DWB device mutex), so both arms come from ONE binary under identical
            // instrumentation instead of from two separately patched builds.
            stager.set_barrier_under_lock(env_usize("CONVOY_DWB_BARRIER_UNDER_LOCK", 0) != 0);
            pool.set_page_stager(Arc::clone(&stager) as Arc<dyn graphus_bufpool::PageStager>);
            Some(stager)
        } else {
            None
        };

        Self {
            pool,
            wal,
            dir,
            stager,
        }
    }
}

/// One arm's measured result.
struct ArmResult {
    readers: usize,
    reader_ops: u64,
    writer_ops: u64,
    elapsed: Duration,
    probe: graphus_bufpool::probe::WriteBackProbe,
    dwb: graphus_storage::dwb::probe::DwbProbeSnapshot,
}

/// Runs one arm: `readers` reader threads and `writers` writer threads over a working set of
/// `working_pages` pages against a pool of `pool_pages` frames, for `secs` seconds.
fn run_arm(
    root: &Path,
    arm: usize,
    readers: usize,
    writers: usize,
    pool_pages: usize,
    working_pages: u64,
    secs: u64,
) -> ArmResult {
    let rig = Rig::build(root, arm, pool_pages, working_pages);
    let pool = Arc::clone(&rig.pool);
    let stop = Arc::new(AtomicBool::new(false));
    let reader_ops = Arc::new(AtomicU64::new(0));
    let writer_ops = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();

    // Writer threads: log a real WAL update record (which yields the LSN), then stamp that LSN onto
    // a page under the frame's write latch. This is exactly the store's discipline — the WAL lock is
    // released before any pool call that could trigger a write-back.
    for w in 0..writers {
        let pool = Arc::clone(&pool);
        let wal = rig.wal.clone();
        let stop = Arc::clone(&stop);
        let ops = Arc::clone(&writer_ops);
        handles.push(
            std::thread::Builder::new()
                .name(format!("convoy-writer-{w}"))
                .spawn(move || {
                    let txn = TxnId(1000 + w as u64);
                    wal.with(|m| m.begin(txn));
                    let mut rng = Rng::new(0xC0FFEE ^ (w as u64) << 32);
                    let mut n: u64 = 0;
                    let mut txn = txn;
                    while !stop.load(Ordering::Relaxed) {
                        let pid = PageId(rng.below(working_pages));
                        // 1. Append the redo record and take its LSN. The WAL lock is dropped when
                        //    `with` returns — before any pool call below.
                        let lsn = wal.with(|m| m.log_update(txn, pid, vec![0xAB; 8], Vec::new()));
                        // 2. Dirty the page, stamping the LSN so WAL-before-data is enforceable.
                        if let Ok(frame) = pool.fetch(pid) {
                            pool.with_page_mut_lsn(frame, lsn, |p| {
                                p[128] = (n & 0xFF) as u8;
                            });
                            pool.unpin(frame);
                            ops.fetch_add(1, Ordering::Relaxed);
                        }
                        n += 1;
                        // Retire the transaction periodically so the manager's in-memory undo chain
                        // stays bounded over a long arm. `commit_at_no_sync` appends the COMMIT
                        // record without an extra `fdatasync`, so the arm measures the *eviction*
                        // path's syncs rather than commit syncs.
                        if n % 512 == 0 {
                            let next = TxnId(txn.0 + 100_000);
                            wal.with(|m| {
                                let _ = m.commit_at_no_sync(txn, Timestamp(n));
                                m.begin(next);
                            });
                            txn = next;
                        }
                    }
                })
                .expect("spawn writer"),
        );
    }

    // Reader threads: the half of the system that already scales. Each fetch that misses must evict,
    // and a dirty victim drags the whole write-back chain along with it.
    for r in 0..readers {
        let pool = Arc::clone(&pool);
        let stop = Arc::clone(&stop);
        let ops = Arc::clone(&reader_ops);
        handles.push(
            std::thread::Builder::new()
                .name(format!("convoy-reader-{r}"))
                .spawn(move || {
                    let mut rng = Rng::new(0x5EED ^ (r as u64) << 32);
                    let mut local: u64 = 0;
                    let mut sink = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        let pid = PageId(rng.below(working_pages));
                        if let Ok(frame) = pool.fetch(pid) {
                            sink += u64::from(pool.with_page(frame, |p| p[128]));
                            pool.unpin(frame);
                            local += 1;
                        }
                    }
                    ops.fetch_add(local, Ordering::Relaxed);
                    // Keep the read observable so the loop cannot be optimised away.
                    std::hint::black_box(sink);
                })
                .expect("spawn reader"),
        );
    }

    // Let the pool fill and the dirty set establish before the measurement window opens, so the arm
    // measures the steady state (every miss evicting a mostly-dirty victim) rather than the cold
    // ramp where victims are still clean.
    std::thread::sleep(Duration::from_millis(750));
    reader_ops.store(0, Ordering::Relaxed);
    writer_ops.store(0, Ordering::Relaxed);
    let probe_before = pool.write_back_probe();
    let dwb_before = rig
        .stager
        .as_ref()
        .map(|s| s.probe_snapshot())
        .unwrap_or_default();
    let start = Instant::now();

    std::thread::sleep(Duration::from_secs(secs));
    let elapsed = start.elapsed();
    let probe_after = pool.write_back_probe();
    let dwb = rig
        .stager
        .as_ref()
        .map(|s| s.probe_snapshot().since(&dwb_before))
        .unwrap_or_default();
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().expect("join worker");
    }

    let probe = graphus_bufpool::probe::WriteBackProbe {
        write_backs: probe_after.write_backs - probe_before.write_backs,
        write_back_nanos: probe_after.write_back_nanos - probe_before.write_back_nanos,
        wal_ensure_calls: probe_after.wal_ensure_calls - probe_before.wal_ensure_calls,
        wal_ensure_nanos: probe_after.wal_ensure_nanos - probe_before.wal_ensure_nanos,
        wal_already_durable: probe_after.wal_already_durable - probe_before.wal_already_durable,
        device_write_guard_nanos: probe_after.device_write_guard_nanos
            - probe_before.device_write_guard_nanos,
        device_write_wait_nanos: probe_after.device_write_wait_nanos
            - probe_before.device_write_wait_nanos,
        home_syncs: probe_after.home_syncs - probe_before.home_syncs,
        home_sync_nanos: probe_after.home_sync_nanos - probe_before.home_sync_nanos,
        device_read_waits: probe_after.device_read_waits - probe_before.device_read_waits,
        device_read_wait_nanos: probe_after.device_read_wait_nanos
            - probe_before.device_read_wait_nanos,
    };

    let result = ArmResult {
        readers,
        reader_ops: reader_ops.load(Ordering::Relaxed),
        writer_ops: writer_ops.load(Ordering::Relaxed),
        elapsed,
        probe,
        dwb,
    };
    // Free the arm's files: a long sweep would otherwise leave one store + WAL + DWB per arm behind.
    drop(rig.pool);
    let _ = std::fs::remove_dir_all(&rig.dir);
    result
}

fn main() {
    let secs = env_usize("CONVOY_SECS", 5) as u64;
    let pool_pages = env_usize("CONVOY_POOL_PAGES", 512);
    let working_mult = env_usize("CONVOY_WORKING_MULT", 2) as u64;
    let writers = env_usize("CONVOY_WRITERS", 1);
    let reader_counts: Vec<usize> = std::env::var("CONVOY_READERS")
        .ok()
        .map(|v| {
            v.split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect::<Vec<usize>>()
        })
        .filter(|v: &Vec<usize>| !v.is_empty())
        .unwrap_or_else(|| vec![1, 2, 4, 8, 16]);

    let working_pages = pool_pages as u64 * working_mult;
    let root = scratch_dir();
    std::fs::create_dir_all(&root).expect("create scratch root");

    println!("# eviction write-back convoy (rmp #974)");
    println!(
        "# pool {pool_pages} frames ({} MiB) | working set {working_pages} pages ({} MiB, {working_mult}x pool) | \
         {writers} writer(s) | {secs}s per arm | dir {}",
        pool_pages * PAGE_SIZE / (1024 * 1024),
        working_pages as usize * PAGE_SIZE / (1024 * 1024),
        root.display()
    );
    println!(
        "{:>7} {:>12} {:>10} {:>10} {:>12} {:>14} {:>14} {:>14}",
        "readers",
        "read ops/s",
        "scaling",
        "wr ops/s",
        "write-backs",
        "wal_ens ms/s",
        "devguard ms/s",
        "rd_wait us/op"
    );

    let mut baseline_per_thread = 0.0f64;
    for (arm, &readers) in reader_counts.iter().enumerate() {
        let r = run_arm(
            &root,
            arm,
            readers,
            writers,
            pool_pages,
            working_pages,
            secs,
        );
        let secs_f = r.elapsed.as_secs_f64();
        let rps = r.reader_ops as f64 / secs_f;
        if arm == 0 {
            baseline_per_thread = rps / readers as f64;
        }
        let scaling = if baseline_per_thread > 0.0 {
            rps / (baseline_per_thread * readers as f64)
        } else {
            0.0
        };
        let rd_wait_us_per_op = if r.probe.device_read_waits > 0 {
            r.probe.device_read_wait_nanos as f64 / r.probe.device_read_waits as f64 / 1000.0
        } else {
            0.0
        };
        let mean = |nanos: u64, count: u64| {
            if count > 0 {
                nanos as f64 / count as f64 / 1e6
            } else {
                0.0
            }
        };
        println!(
            "{:>7} {:>12.0} {:>9.2}x {:>10.0} {:>12} {:>14.1} {:>14.1} {:>14.2}",
            r.readers,
            rps,
            scaling,
            r.writer_ops as f64 / secs_f,
            r.probe.write_backs,
            r.probe.wal_ensure_nanos as f64 / 1e6 / secs_f,
            r.probe.device_write_guard_nanos as f64 / 1e6 / secs_f,
            rd_wait_us_per_op,
        );
        println!(
            "        # misses={} wal_ensure_calls={} already_durable={} home_syncs={}",
            r.probe.device_read_waits,
            r.probe.wal_ensure_calls,
            r.probe.wal_already_durable,
            r.probe.home_syncs,
        );
        let dwb_mean = |nanos: u64, count: u64| {
            if count > 0 {
                nanos as f64 / count as f64 / 1e6
            } else {
                0.0
            }
        };
        println!(
            "        # dwb: stages={} lock_hold={:.1}ms/s lock_wait={:.1}ms/s \
             mean_hold={:.3}ms mean_barrier={:.3}ms",
            r.dwb.stages,
            r.dwb.lock_hold_nanos as f64 / 1e6 / secs_f,
            r.dwb.lock_wait_nanos as f64 / 1e6 / secs_f,
            dwb_mean(r.dwb.lock_hold_nanos, r.dwb.stages),
            dwb_mean(r.dwb.barrier_nanos, r.dwb.barriers),
        );
        println!(
            "        # mean ms: write_back={:.3} wal_ensure={:.3} home_sync={:.3} \
             devguard_hold={:.3} devguard_wait={:.3}",
            mean(r.probe.write_back_nanos, r.probe.write_backs),
            mean(r.probe.wal_ensure_nanos, r.probe.wal_ensure_calls),
            mean(r.probe.home_sync_nanos, r.probe.home_syncs),
            mean(r.probe.device_write_guard_nanos, r.probe.home_syncs.max(1)),
            mean(r.probe.device_write_wait_nanos, r.probe.home_syncs.max(1)),
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}
