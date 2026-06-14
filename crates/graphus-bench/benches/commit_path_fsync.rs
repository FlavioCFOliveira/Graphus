//! Real-disk fsync commit-path benchmark (rmp #120, sprint 6 — "Plataforma de concorrência e I/O").
//!
//! The existing `commit_path.rs` benchmark drives the commit path over the **in-memory DST
//! substrate** ([`graphus_io::MemBlockDevice`] + [`graphus_wal::MemLogSink`]), where `LogSink::sync`
//! is a buffer append with **no syscall** — so its numbers measure the commit *logic* with *no disk
//! noise* but **do not reflect physical durability**. The production-readiness audit flagged that as
//! an empirical gap: nowhere did a benchmark exercise a genuine `fdatasync` on real storage, so the
//! published throughput overstated the durable commit rate.
//!
//! This benchmark closes that gap. It is a near-clone of `commit_path.rs`'s [`CommitDriver`], but the
//! store sits on a **file-backed device** ([`graphus_io::FileBlockDevice`]) and a **file-backed log
//! sink** ([`graphus_wal::FileLogSink`]) inside a unique tempdir, so every `RecordStore::commit`
//! drives the real group-commit path all the way to `FileLogSink::sync` → `fdatasync` (data + the
//! directory entry) on a real filesystem. The measured cost therefore includes the physical fsync the
//! DST run elides — exactly what quantifies "the cost of physical durability".
//!
//! The tempdir is created per `FsyncCommitDriver` and removed on drop (and a fresh one is taken on
//! every store reset), so the benchmark leaves nothing behind.
//!
//! Read the results **side by side** with `commit_path.rs` / `RESULTS.md`: same op-mix, same
//! op-counts, same percentile reporting — the only difference is Mem* → File*, so the delta between
//! the two is the physical-fsync tax. Run with:
//! `cargo bench -p graphus-bench --bench commit_path_fsync`.
//!
//! ## Why a per-commit fsync, and what this is NOT
//!
//! Each commit here pays its own `fdatasync` (no multi-thread group-commit *batching* — the storage
//! API and this harness are single-threaded, `04 §11.1`, identical to `commit_path.rs`). So this is
//! the **worst-case, un-amortized** durable commit cost: one transaction, one fsync. A runtime-layer
//! commit queue that batches N committers behind one fsync would amortize this — that is the
//! follow-up measurement (`RESULTS.md` §7), not this bench. What this bench establishes is the floor:
//! the genuine syscall-bound per-commit latency the in-memory DST run cannot show.

use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use graphus_core::{TxnId, Value};
use graphus_io::FileBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{FileLogSink, WalManager};

#[path = "common.rs"]
mod common;
use common::POOL_CAPACITY;

/// The same conservative page cap `commit_path.rs` uses, to keep the single-page catalog
/// (`device_pages` map) well under the ~1000-page overflow point. See that file's "Store-size
/// envelope" note — the identical limit applies, since the same `RecordStore::commit` re-checkpoints
/// the whole catalog into one fixed meta page regardless of the backing device.
const PAGE_CAP: f64 = 200.0;

/// A unique temp directory holding one driver's `device` file + `wal/` log directory. Removed on
/// drop so the benchmark leaves no scratch files behind (the AC's "use a tempdir, clean up at the
/// end").
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        // A monotone-ish unique suffix: high-resolution time + pid + an atomic counter so two drivers
        // (or two store resets) never collide even within the same nanosecond.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        path.push(format!(
            "graphus-bench-fsync-{nanos}-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create bench tempdir");
        Self { path }
    }

    fn device_path(&self) -> PathBuf {
        self.path.join("graph.db")
    }

    fn wal_dir(&self) -> PathBuf {
        self.path.join("wal")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best-effort cleanup; a leftover tempdir would only waste space, never corrupt a result.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The concrete real-disk store type: the real [`RecordStore`] over a file device + file log sink.
type FsyncStore = RecordStore<FileBlockDevice, FileLogSink>;

/// Builds a fresh real-disk store inside `dir`: a file-backed block device (created empty, so
/// `RecordStore::create`'s empty-device precondition holds) and a file-backed WAL directory whose
/// `sync` performs a genuine `fdatasync`.
fn fresh_disk_store(dir: &TempDir) -> FsyncStore {
    let device = FileBlockDevice::open(dir.device_path()).expect("open file device");
    let sink = FileLogSink::open(dir.wal_dir()).expect("open file log sink");
    let wal = WalManager::create(sink).expect("create WAL");
    RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store")
}

/// Real-disk analogue of `commit_path.rs`'s `CommitDriver`. Owns the tempdir + store so the bench
/// bodies stay trivial; recreates *both* the store and the tempdir before the catalog would overflow
/// the single meta page (a fresh tempdir per store keeps each store's WAL/device independent and
/// bounds disk growth).
struct FsyncCommitDriver {
    dir: TempDir,
    store: FsyncStore,
    rel_type: u32,
    prop_key: u32,
    anchors: Vec<u64>,
    txn_id: u64,
    pages_grown: f64,
}

impl FsyncCommitDriver {
    fn new() -> Self {
        let dir = TempDir::new();
        let mut store = fresh_disk_store(&dir);
        let (rel_type, prop_key) = Self::intern(&mut store);
        Self {
            dir,
            store,
            rel_type,
            prop_key,
            anchors: Vec::new(),
            txn_id: 0,
            pages_grown: 0.0,
        }
    }

    fn intern(store: &mut FsyncStore) -> (u32, u32) {
        let rel_type = store
            .intern_token(Namespace::RelType, common::REL_TYPE)
            .expect("intern reltype");
        let prop_key = store
            .intern_token(Namespace::PropKey, common::PROP_KEY)
            .expect("intern propkey");
        (rel_type, prop_key)
    }

    /// Drops the old store + tempdir and rebuilds on a fresh tempdir. The old `TempDir`'s `Drop`
    /// removes its files; ordering is explicit (build the new dir, then overwrite the field so the
    /// old one drops).
    fn reset_store(&mut self) {
        let dir = TempDir::new();
        let mut store = fresh_disk_store(&dir);
        let (rel_type, prop_key) = Self::intern(&mut store);
        self.store = store;
        self.dir = dir; // old TempDir drops here → its files are removed.
        self.rel_type = rel_type;
        self.prop_key = prop_key;
        self.anchors.clear();
        self.pages_grown = 0.0;
    }

    /// Identical record-page growth estimate as `commit_path.rs` (the record sizes are frozen in
    /// `record.rs` and independent of the backing device).
    fn pages_per_commit(ops: u64) -> f64 {
        const NODE_RPP: f64 = ((8192 - 24) / 65) as f64;
        const REL_RPP: f64 = ((8192 - 24) / 102) as f64;
        const PROP_RPP: f64 = ((8192 - 24) / 46) as f64;
        let mut nodes = 0.0;
        let mut rels = 0.0;
        let mut props = 0.0;
        for op in 0..ops {
            match op % 3 {
                0 => nodes += 1.0,
                1 => rels += 1.0,
                _ => props += 1.0,
            }
        }
        nodes / NODE_RPP + rels / REL_RPP + props / PROP_RPP
    }

    /// Runs one short write transaction of `ops` mutations, commits (paying a real `fdatasync`), and
    /// returns **only the commit's** wall-clock latency. Same op-mix as `commit_path.rs` so the two
    /// benchmarks are directly comparable.
    fn commit_once(&mut self, ops: u64) -> Duration {
        let delta = Self::pages_per_commit(ops);
        if self.pages_grown + delta > PAGE_CAP {
            self.reset_store();
        }
        self.pages_grown += delta;

        self.txn_id += 1;
        let txn = TxnId(self.txn_id);
        let (rel_type, prop_key) = (self.rel_type, self.prop_key);
        self.store.begin(txn);
        while self.anchors.len() < 2 {
            let (id, _) = self.store.create_node(txn).expect("anchor node");
            self.anchors.push(id);
        }
        for op in 0..ops {
            match op % 3 {
                0 => {
                    let (id, _) = self.store.create_node(txn).expect("create node");
                    self.anchors.push(id);
                }
                1 => {
                    let n = self.anchors.len();
                    let src = self.anchors[(op as usize) % n];
                    let dst = self.anchors[(op as usize + 1) % n];
                    self.store
                        .create_rel(txn, rel_type, src, dst)
                        .expect("create rel");
                }
                _ => {
                    let n = self.anchors.len();
                    let target = self.anchors[(op as usize) % n];
                    self.store
                        .set_node_property_value(txn, target, prop_key, &Value::Integer(op as i64))
                        .expect("set property");
                }
            }
        }
        // Time *only* the commit: this is where the real `fdatasync` happens.
        let start = Instant::now();
        self.store.commit(txn).expect("commit");
        start.elapsed()
    }
}

/// Percentile of an already-sorted slice of nanosecond latencies (same helper as `commit_path.rs`).
fn percentile(sorted_nanos: &[u128], p: f64) -> u128 {
    if sorted_nanos.is_empty() {
        return 0;
    }
    let rank = (p * (sorted_nanos.len() - 1) as f64).round() as usize;
    sorted_nanos[rank.min(sorted_nanos.len() - 1)]
}

/// Prints a one-line latency + throughput summary to stderr, tagged `[FSYNC#120]` so it is easy to
/// grep out of the `cargo bench` output and transcribe into `RESULTS.md` next to the DST numbers.
fn report_latency(label: &str, ops_per_commit: u64, mut nanos: Vec<u128>) {
    nanos.sort_unstable();
    let n = nanos.len();
    let p50 = percentile(&nanos, 0.50);
    let p99 = percentile(&nanos, 0.99);
    let p999 = percentile(&nanos, 0.999);
    let max = *nanos.last().unwrap_or(&0);
    let sum: u128 = nanos.iter().sum();
    let mean = if n == 0 { 0 } else { sum / n as u128 };
    let commits_per_sec = if mean == 0 {
        0.0
    } else {
        1_000_000_000.0 / mean as f64
    };
    let ops_per_sec = commits_per_sec * ops_per_commit as f64;
    eprintln!(
        "[FSYNC#120] {label:<18} ops/commit={ops_per_commit:>4}  n={n:>7}  \
         mean={mean:>9}ns  p50={p50:>9}ns  p99={p99:>9}ns  p99.9={p999:>10}ns  max={max:>11}ns  \
         commits/s={commits_per_sec:>11.0}  ops/s={ops_per_sec:>12.0}",
    );
}

/// Group 1: Criterion throughput of a short real-disk write transaction at small op-counts. Mirror
/// of `commit_path.rs::bench_commit_throughput` but with a genuine fsync per commit. The sample
/// count + timing are kept modest because each iteration is syscall-bound (orders of magnitude
/// slower than the in-memory run), so a default `cargo bench` still finishes promptly.
fn bench_fsync_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("fsync_commit_throughput");
    group.sample_size(30);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(3));
    for &ops in &[1u64, 4, 16] {
        group.throughput(Throughput::Elements(ops));
        group.bench_with_input(BenchmarkId::new("short_txn", ops), &ops, |b, &ops| {
            let mut driver = FsyncCommitDriver::new();
            b.iter(|| {
                let d = driver.commit_once(ops);
                black_box(d);
            });
        });
    }
    group.finish();
}

/// Group 2: the real-disk serialization-point sweep — per-commit latency histogram (p50/p99/p99.9)
/// over op-counts, with a real fsync per commit. The companion to
/// `commit_path.rs::bench_serialization_sweep`; the delta between the two sweeps at each op-count is
/// the physical-durability tax as a function of WAL-volume-per-commit.
fn bench_fsync_serialization_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("fsync_serialization_sweep");
    group.sample_size(20);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(3));
    for &ops in &[1u64, 4, 16, 64] {
        group.throughput(Throughput::Elements(ops));
        group.bench_with_input(BenchmarkId::new("ops_per_commit", ops), &ops, |b, &ops| {
            let mut driver = FsyncCommitDriver::new();
            b.iter_custom(|iters| {
                let mut latencies = Vec::with_capacity(iters as usize);
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let d = driver.commit_once(ops);
                    total += d;
                    latencies.push(d.as_nanos());
                }
                report_latency("fsync_sweep", ops, latencies);
                total
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_fsync_throughput,
    bench_fsync_serialization_sweep
);
criterion_main!(benches);
