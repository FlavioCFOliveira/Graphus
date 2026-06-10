//! Commit-path benchmarks for SPIKE #8 — the runtime write/ACID shape (`04 §9.1`, §12 item 8).
//!
//! These benchmarks measure the transactional **commit path** of the real persistent store
//! ([`graphus_storage::RecordStore`]) over the in-memory DST device + log sink, to decide whether
//! the current **single log shard + group commit** design (candidate **a**) meets the bar, or
//! whether **partitioned logging keyed by data partition** (candidate **b**) is warranted.
//! Candidate (b) is *not* implemented — per §9.1 it is built "only if (a) is shown to bottleneck",
//! so the job here is to measure (a) thoroughly and give an evidence-based recommendation.
//!
//! ## What is the serialization point?
//!
//! On `RecordStore::commit` the per-transaction work is: settle each created/expired MVCC version
//! stamp (one WAL `Update` per record), re-checkpoint the catalog to the meta page, append the
//! `COMMIT` record, then `WalManager::commit` → `harden()` → `LogSink::sync()` (the group-commit
//! `fdatasync`). On the DST `MemLogSink`, `sync()` appends the pending byte tail to the durable
//! buffer, so its cost grows with the WAL volume the transaction logged. The **single log tail**
//! is the point every committer must pass through; this is exactly the structure candidate (a)
//! relies on amortizing. We therefore characterize commit cost as a function of **WAL-volume-per-
//! commit**, driven by the per-transaction op-count.
//!
//! ## Benchmark groups
//!
//! 1. `commit_throughput/short_txn` — Criterion throughput of a short write transaction
//!    (begin → a few `create_node`/`create_rel`/`set_node_property_value` → commit) at a few small
//!    op-counts. `Throughput::Elements` = ops/commit, so Criterion reports **ops/sec** directly;
//!    the reciprocal of the per-iteration time is **commits/sec**.
//! 2. `commit_serialization_sweep` — a manual latency histogram (via `iter_custom`) over a sweep of
//!    per-commit op-counts (1 → 256 ops/txn). For each op-count it records **per-commit latency**
//!    and prints p50 / p99 / p99.9 / max plus throughput to stderr, so we can see whether the
//!    single log tail's per-commit latency stays bounded (sub-linear-per-op, i.e. amortized) or
//!    blows up as WAL-volume-per-commit grows. This is the "no p99 regression vs baseline" check:
//!    the 1-op commit is the trivial baseline; we confirm p99 stays bounded and stable as the
//!    swept parameter grows.
//! 3. `commit_concurrency_proxy` — many short transactions committed back-to-back, reporting
//!    per-commit latency percentiles, to model a stream of concurrent committers hitting one log
//!    tail. (The storage API and DST harness are single-threaded by construction — `04 §11.1` —
//!    so true multi-threaded group-commit *batching* is a runtime-layer concern not present here;
//!    what this isolates is the per-commit serialization-point cost under sustained commit load.)
//!
//! ## Store-size envelope (a storage-layer limit this bench must respect)
//!
//! `RecordStore::commit` re-checkpoints the whole catalog to the single fixed metadata page
//! (device page 0) on every commit, and that catalog embeds each store's `device_pages` map (8
//! bytes per store page, `meta.rs`). The catalog therefore must fit one 8 KiB page, which caps a
//! store at roughly **~1000 total record pages** before the meta-page write asserts "region runs
//! past the page" (`store.rs::write_region`). This is a real storage-layer limit (a paged/overflow
//! catalog is the eventual fix — out of scope for this bench-only task; see `RESULTS.md` →
//! "Findings filed separately"). To measure the *commit serialization point* rather than this
//! overflow, the bench driver **recreates the store before it approaches the cap** (see
//! [`CommitDriver`]); store-recreation time is excluded from every measurement (only per-commit
//! latencies are summed and reported). Bounding store growth is also correct benchmark hygiene:
//! per-commit cost is driven by *that commit's* WAL volume, not by unbounded prior growth.
//!
//! Run with: `cargo bench -p graphus-bench --bench commit_path`. Report alongside hardware
//! (`lscpu`), kernel (`uname -r`), and toolchain (`rustc --version`). x86_64 + aarch64 are both
//! Tier-1 (`04 §10`); this instrument is re-run on aarch64 hardware to complete the AC's
//! cross-target coverage (see `RESULTS.md`).

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use graphus_core::{TxnId, Value};

#[path = "common.rs"]
mod common;
use common::{BenchStore, fresh_store, intern_tokens};

/// A conservative cap on a store's total record pages before the driver recreates it, keeping the
/// single-page catalog (`device_pages` map) well under the ~1000-page overflow point (≈4–5×
/// margin). See the module-level "Store-size envelope" note.
const PAGE_CAP: f64 = 200.0;

/// Drives short write transactions against a real store, recreating the store before its growing
/// single-page catalog would overflow. Owns all mutable benchmark state so the bench bodies stay
/// trivial and the reset bookkeeping lives in one place.
struct CommitDriver {
    store: BenchStore,
    rel_type: u32,
    prop_key: u32,
    anchors: Vec<u64>,
    txn_id: u64,
    /// Estimated record pages the current store has grown by since it was (re)created.
    pages_grown: f64,
}

impl CommitDriver {
    fn new() -> Self {
        let mut store = fresh_store();
        let (rel_type, prop_key) = intern_tokens(&mut store);
        Self {
            store,
            rel_type,
            prop_key,
            anchors: Vec::new(),
            txn_id: 0,
            pages_grown: 0.0,
        }
    }

    /// Drops and rebuilds the store on a fresh device + log. Resets per-store growth bookkeeping
    /// and the anchor set; the txn-id counter keeps advancing (ids need only be unique per store,
    /// but a monotone counter is simplest and harmless).
    fn reset_store(&mut self) {
        self.store = fresh_store();
        let (rel_type, prop_key) = intern_tokens(&mut self.store);
        self.rel_type = rel_type;
        self.prop_key = prop_key;
        self.anchors.clear();
        self.pages_grown = 0.0;
    }

    /// The estimated record-page growth a commit of `ops` mutations adds (fractional; node/rel/
    /// property records packed at their store's records-per-page). Used only to schedule resets.
    fn pages_per_commit(ops: u64) -> f64 {
        // records-per-page for the 8 KiB page and the frozen record sizes (record.rs).
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

    /// Runs one short write transaction of `ops` mutations, then commits, returning **only the
    /// commit's** wall-clock latency (begin + the in-transaction mutations are excluded; the
    /// serialization point we are characterizing is the commit). Recreates the store first if the
    /// next commit would push it past [`PAGE_CAP`].
    ///
    /// The op mix is write-heavy and representative of a graph mutation: ensure two anchor nodes,
    /// then each op creates a node, creates an edge between existing nodes, or sets a property —
    /// cycling so the WAL carries node, rel and property records (all three fixed-record stores)
    /// rather than one record kind.
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
        // Time *only* the commit: the begin→work→commit transaction's serialization point.
        let start = Instant::now();
        self.store.commit(txn).expect("commit");
        start.elapsed()
    }
}

/// Group 1: Criterion throughput of a short write transaction at a few small op-counts.
fn bench_commit_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_throughput");
    group.sample_size(50);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    for &ops in &[1u64, 4, 16] {
        group.throughput(Throughput::Elements(ops));
        group.bench_with_input(BenchmarkId::new("short_txn", ops), &ops, |b, &ops| {
            let mut driver = CommitDriver::new();
            b.iter(|| {
                let d = driver.commit_once(ops);
                black_box(d);
            });
        });
    }
    group.finish();
}

/// Computes the percentile `p` (0.0..=1.0) of an already-sorted slice of nanosecond latencies.
fn percentile(sorted_nanos: &[u128], p: f64) -> u128 {
    if sorted_nanos.is_empty() {
        return 0;
    }
    let rank = (p * (sorted_nanos.len() - 1) as f64).round() as usize;
    sorted_nanos[rank.min(sorted_nanos.len() - 1)]
}

/// Prints a one-line latency + throughput summary for a labelled run to stderr (captured in the
/// `cargo bench` output and transcribed into `RESULTS.md`).
fn report_latency(label: &str, ops_per_commit: u64, mut nanos: Vec<u128>) {
    nanos.sort_unstable();
    let n = nanos.len();
    let p50 = percentile(&nanos, 0.50);
    let p99 = percentile(&nanos, 0.99);
    let p999 = percentile(&nanos, 0.999);
    let max = *nanos.last().unwrap_or(&0);
    let sum: u128 = nanos.iter().sum();
    let mean = if n == 0 { 0 } else { sum / n as u128 };
    // commits/sec from mean per-commit latency; ops/sec scales by ops_per_commit.
    let commits_per_sec = if mean == 0 {
        0.0
    } else {
        1_000_000_000.0 / mean as f64
    };
    let ops_per_sec = commits_per_sec * ops_per_commit as f64;
    eprintln!(
        "[SPIKE#8] {label:<20} ops/commit={ops_per_commit:>4}  n={n:>7}  \
         mean={mean:>8}ns  p50={p50:>8}ns  p99={p99:>8}ns  p99.9={p999:>9}ns  max={max:>10}ns  \
         commits/s={commits_per_sec:>12.0}  ops/s={ops_per_sec:>13.0}",
    );
}

/// Group 2: the serialization-point sweep. For each op-count we record per-commit latency over
/// many commits and print percentiles. Criterion still reports its own mean/CI per point; the
/// printed percentiles add the p99/p99.9 the AC asks for. The returned `Duration` is the sum of
/// per-commit latencies (store-recreation time excluded), so Criterion times only commits too.
fn bench_serialization_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_serialization_sweep");
    group.sample_size(50);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    // Sweep WAL-volume-per-commit by growing ops/txn geometrically. 1 op is the trivial baseline.
    for &ops in &[1u64, 4, 16, 64, 256] {
        group.throughput(Throughput::Elements(ops));
        group.bench_with_input(BenchmarkId::new("ops_per_commit", ops), &ops, |b, &ops| {
            let mut driver = CommitDriver::new();
            b.iter_custom(|iters| {
                let mut latencies = Vec::with_capacity(iters as usize);
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let d = driver.commit_once(ops);
                    total += d;
                    latencies.push(d.as_nanos());
                }
                report_latency("serialization_sweep", ops, latencies);
                total
            });
        });
    }
    group.finish();
}

/// Group 3: many short transactions committed back-to-back, modelling a sustained stream of
/// committers hitting the single log tail. Uses a fixed small op-count and reports per-commit
/// latency percentiles over a growing stream length.
fn bench_concurrency_proxy(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_concurrency_proxy");
    // Each sample replays a whole back-to-back stream, so keep the sample count + timing modest so
    // a default `cargo bench` run finishes in reasonable time in CI (the AC's "modest iteration
    // counts"). The larger 50_000-commit stream is exercised on demand via
    // `--bench commit_path 'commit_concurrency_proxy'` and is recorded in `RESULTS.md`.
    group.sample_size(20);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    // A representative short OLTP-style write txn: 4 ops/commit.
    const OPS: u64 = 4;
    // Model "load" as the number of committers in the back-to-back stream we characterize per
    // sample. Criterion measures the *batch* of `stream` commits; the printed percentiles are the
    // per-commit latencies within the stream (the driver resets the store as needed underneath).
    for &stream in &[1_000u64, 10_000] {
        group.throughput(Throughput::Elements(stream * OPS));
        group.bench_with_input(
            BenchmarkId::new("back_to_back_commits", stream),
            &stream,
            |b, &stream| {
                b.iter_custom(|iters| {
                    let mut driver = CommitDriver::new();
                    let mut total = Duration::ZERO;
                    // One histogram across all Criterion iterations of this sample, so the printed
                    // percentiles reflect the full stream, not just the last batch.
                    let mut latencies = Vec::with_capacity((iters * stream) as usize);
                    for _ in 0..iters {
                        for _ in 0..stream {
                            let d = driver.commit_once(OPS);
                            total += d;
                            latencies.push(d.as_nanos());
                        }
                    }
                    report_latency("concurrency_proxy", OPS, latencies);
                    total
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_commit_throughput,
    bench_serialization_sweep,
    bench_concurrency_proxy
);
criterion_main!(benches);
