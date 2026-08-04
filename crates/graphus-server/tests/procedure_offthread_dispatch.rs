//! **Off-thread reader-safe procedure dispatch** (`rmp` task #546): a read-only auto-commit statement
//! that calls only reader-safe procedures (GDS algorithms, `db.*` introspection,
//! `db.index.fulltext.queryNodes`) is dispatched to the off-thread reader pool — so a procedure-heavy
//! read scales across reader cores instead of running single-threaded on the engine thread — while a
//! non-reader-safe procedure stays inline.
//!
//! ## What is asserted
//!
//! 1. **Deterministic dispatch oracle** (`reader_safe_procedure_dispatches_off_thread`): the probe
//!    procedure `ext.readerPoolWorker()` yields whether its body ran on a reader-pool worker
//!    ([`graphus_cypher::morsel::is_reader_pool_worker`]). An auto-commit `CALL` yields `true` (off-thread);
//!    the same call in an explicit transaction yields `false` (inline); a **non**-reader-safe sibling
//!    (`ext.readerPoolWorkerInline`) yields `false` even auto-commit (the negative gate). No sampling of
//!    OS threads, so it never flakes.
//! 2. **Result equivalence** (`procedure_result_is_identical_inline_vs_off_thread`): `db.*` introspection
//!    and a GDS stream return byte-identical rows whether dispatched off-thread (auto-commit) or run
//!    inline (explicit transaction).
//! 3. **Multi-core measurement** (`procedure_heavy_read_uses_multiple_cores`, `#[ignore]`): `K` client
//!    threads each looping a procedure-heavy read drive the process past one core (mean cores =
//!    (utime+stime)/wall), where a single engine thread capped it at ≈ 1. Ignored by default (a
//!    multi-second measurement, not a correctness gate); run with `--ignored --nocapture`.
//!
//! Gated on the opt-in `internal-test-udf` feature (which registers the `ext.readerPoolWorker[Inline]`
//! probes into the engine): run with
//! `cargo test -p graphus-server --features internal-test-udf --test procedure_offthread_dispatch`.
#![cfg(feature = "internal-test-udf")]

use std::sync::Arc;
// Only the `#[cfg(target_os = "linux")]` multi-core measurement test below uses these; gate the
// imports to match, so a non-Linux target (e.g. the macOS CI leg) does not see them as unused under
// `-D warnings`.
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
use std::time::Instant;

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// Spawns a threaded engine with `reader_threads` reader workers (so auto-commit reads dispatch to the
/// pool) and a generously-sized buffer pool (the working set must stay RAM-resident so a measurement is
/// CPU-bound, not I/O-bound).
fn engine(reader_threads: usize) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        std::sync::Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 65_536, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        256,
        reader_threads,
        metrics,
        clock,
        std::sync::Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn threaded engine")
}

/// Drains every row of an **auto-commit** statement (dispatched off-thread when structurally read-only +
/// reader-safe), returning `(committed, rows)` where each row is its materialized cells.
fn run_auto(
    handle: &EngineHandle,
    mode: AccessMode,
    stmt: &str,
) -> (bool, Vec<Vec<graphus_cypher::MaterializedValue>>) {
    let Ok(ticket) = handle.begin_auto_commit_blocking(mode) else {
        return (false, Vec::new());
    };
    let mut rows = Vec::new();
    match handle.run_blocking(ticket, stmt.to_owned(), vec![], true, None, None) {
        Ok(mut reply) => loop {
            match reply.rows.next() {
                Ok(Some(cells)) => rows.push(cells),
                Ok(None) => return (true, rows),
                Err(_) => return (false, rows),
            }
        },
        Err(_) => (false, Vec::new()),
    }
}

/// Drains every row of a read inside an **explicit** transaction (`auto_commit = false`), which is never
/// dispatched off-thread — it runs inline on the engine thread. Returns `(committed, rows)`.
fn run_explicit(
    handle: &EngineHandle,
    stmt: &str,
) -> (bool, Vec<Vec<graphus_cypher::MaterializedValue>>) {
    let Ok(ticket) = handle.begin_blocking(AccessMode::Read) else {
        return (false, Vec::new());
    };
    let mut rows = Vec::new();
    let ok = match handle.run_blocking(ticket, stmt.to_owned(), vec![], false, None, None) {
        Ok(mut reply) => loop {
            match reply.rows.next() {
                Ok(Some(cells)) => rows.push(cells),
                Ok(None) => break true,
                Err(_) => break false,
            }
        },
        Err(_) => false,
    };
    if ok {
        let _ = handle.commit_blocking(ticket);
    } else {
        let _ = handle.rollback_blocking(ticket);
    }
    (ok, rows)
}

/// The single Boolean cell of the first row (the `onPool` probe result), or `None` if absent.
fn first_bool(rows: &[Vec<graphus_cypher::MaterializedValue>]) -> Option<bool> {
    match rows.first()?.first()? {
        graphus_cypher::MaterializedValue::Value(Value::Boolean(b)) => Some(*b),
        _ => None,
    }
}

/// Preloads `n` `:Person {id, age}` nodes (no edges) via batched `UNWIND … CREATE`.
fn preload_people(handle: &EngineHandle, n: i64) {
    const BATCH: i64 = 2_000;
    let mut start = 0;
    while start < n {
        let end = (start + BATCH).min(n);
        let stmt = format!(
            "UNWIND range({start}, {}) AS i CREATE (:Person {{id: i, age: i % 100}})",
            end - 1
        );
        let (ok, _) = run_auto(handle, AccessMode::Write, &stmt);
        assert!(ok, "preload batch [{start},{end}) commits");
        start = end;
    }
}

/// Preloads `n` `:Person {id}` nodes wired in a `:KNOWS` chain (so a GDS projection has real topology).
/// Keep `n` small — the chain wiring is a per-anchor label scan (`O(n²)`), which is fine for a few
/// hundred nodes but must never be used for the large measurement corpus.
fn preload_social(handle: &EngineHandle, n: i64) {
    preload_people(handle, n);
    // Wire a KNOWS chain so degree/pageRank have edges (one statement, `O(n²)` — small `n` only).
    let (ok, _) = run_auto(
        handle,
        AccessMode::Write,
        "MATCH (a:Person), (b:Person) WHERE b.id = a.id + 1 CREATE (a)-[:KNOWS]->(b)",
    );
    assert!(ok, "KNOWS chain commits");
}

fn shutdown(eng: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = eng;
    drop(handle);
    drop(inner);
    join.join().expect("engine joins");
}

/// (1) Deterministic dispatch oracle: a reader-safe procedure runs on the reader pool when auto-commit,
/// inline in an explicit transaction; a non-reader-safe procedure stays inline even auto-commit.
#[test]
fn reader_safe_procedure_dispatches_off_thread() {
    let eng = engine(4);
    let handle = eng.handle.clone();

    // Reader-safe procedure, AUTO-COMMIT → dispatched to the reader pool → onPool == true.
    let (ok, rows) = run_auto(
        &handle,
        AccessMode::Read,
        "CALL ext.readerPoolWorker() YIELD onPool RETURN onPool",
    );
    assert!(ok, "auto-commit reader-safe CALL commits");
    assert_eq!(
        first_bool(&rows),
        Some(true),
        "rmp #546: a reader-safe procedure in an auto-commit read MUST run on the off-thread reader pool"
    );

    // Same procedure inside an EXPLICIT transaction → inline on the engine thread → onPool == false.
    let (ok, rows) = run_explicit(
        &handle,
        "CALL ext.readerPoolWorker() YIELD onPool RETURN onPool",
    );
    assert!(ok, "explicit-txn reader-safe CALL commits");
    assert_eq!(
        first_bool(&rows),
        Some(false),
        "an explicit-transaction read runs inline on the engine thread (never off-thread)"
    );

    // NON-reader-safe procedure, AUTO-COMMIT → stays inline → onPool == false (the negative gate).
    let (ok, rows) = run_auto(
        &handle,
        AccessMode::Read,
        "CALL ext.readerPoolWorkerInline() YIELD onPool RETURN onPool",
    );
    assert!(ok, "auto-commit non-reader-safe CALL commits");
    assert_eq!(
        first_bool(&rows),
        Some(false),
        "rmp #546: a non-reader-safe procedure MUST stay inline even in an auto-commit read"
    );

    shutdown(eng, handle);
}

/// (2) Result equivalence: `db.*` introspection and a GDS stream return byte-identical rows whether
/// dispatched off-thread (auto-commit) or run inline (explicit transaction).
#[test]
fn procedure_result_is_identical_inline_vs_off_thread() {
    let eng = engine(4);
    let handle = eng.handle.clone();
    preload_social(&handle, 300);

    // `db.propertyKeys()` — scans every node's properties; a clean reader-safe `db.*` introspection.
    let (ok_a, off) = run_auto(
        &handle,
        AccessMode::Read,
        "CALL db.propertyKeys() YIELD propertyKey RETURN propertyKey",
    );
    let (ok_b, inline) = run_explicit(
        &handle,
        "CALL db.propertyKeys() YIELD propertyKey RETURN propertyKey",
    );
    assert!(ok_a && ok_b, "db.propertyKeys commits both ways");
    assert_eq!(
        off, inline,
        "db.propertyKeys(): off-thread rows differ from inline rows"
    );
    assert!(!off.is_empty(), "db.propertyKeys yields at least one key");

    // A GDS stream over a projected graph. Project once (a write to the shared catalog), then stream the
    // read-only algorithm off-thread (auto-commit) and inline (explicit txn) — identical rows.
    let (ok, _) = run_auto(
        &handle,
        AccessMode::Write,
        "CALL gds.graph.project('g', 'Person', 'KNOWS', {}) YIELD graphName RETURN graphName",
    );
    assert!(ok, "gds.graph.project commits");

    let (ok_a, off) = run_auto(
        &handle,
        AccessMode::Read,
        "CALL gds.degree.stream('g', {}) YIELD nodeId, score RETURN nodeId, score ORDER BY nodeId",
    );
    let (ok_b, inline) = run_explicit(
        &handle,
        "CALL gds.degree.stream('g', {}) YIELD nodeId, score RETURN nodeId, score ORDER BY nodeId",
    );
    assert!(ok_a && ok_b, "gds.degree.stream commits both ways");
    assert_eq!(
        off, inline,
        "gds.degree.stream: off-thread rows differ from inline rows"
    );
    assert!(!off.is_empty(), "gds.degree.stream yields rows");

    shutdown(eng, handle);
}

/// Total process CPU time (utime + stime) in clock ticks, read from `/proc/self/stat`. Linux-only; the
/// measurement test is `#[cfg(target_os = "linux")]`.
#[cfg(target_os = "linux")]
fn process_cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").expect("read /proc/self/stat");
    // `comm` (field 2) may contain spaces/parens; split after the last ')'. The remainder begins at
    // field 3 (state), so utime = field 14 → remainder index 11, stime = field 15 → remainder index 12.
    let after = &stat[stat.rfind(')').expect("stat has comm close-paren") + 1..];
    let fields: Vec<&str> = after.split_whitespace().collect();
    let utime: u64 = fields[11].parse().expect("utime");
    let stime: u64 = fields[12].parse().expect("stime");
    utime + stime
}

/// (3) Multi-core measurement (`#[ignore]`): `K` client threads each looping a procedure-heavy read
/// drive the process past one core. Reports mean cores per `K`; the single-engine-thread baseline was
/// ≈ 1 for any `K` (every procedure read serialised on the engine thread).
#[test]
#[ignore = "multi-second CPU measurement; run with --ignored --nocapture"]
#[cfg(target_os = "linux")]
fn procedure_heavy_read_uses_multiple_cores() {
    // A graph big enough that one `db.propertyKeys()` (full node+property scan, single-threaded) is a
    // few ms of CPU — so K concurrent reads clearly light up K cores.
    let people: i64 = 20_000;
    let ticks_per_sec = 100.0; // Linux USER_HZ (sysconf(_SC_CLK_TCK)); standard on all supported targets.

    let mut report =
        String::from("\nprocedure-heavy read (CALL db.propertyKeys()) core scaling:\n");
    let mut cores_at: Vec<(usize, f64)> = Vec::new();

    for k in [1usize, 8usize] {
        let eng = engine(k);
        let handle = eng.handle.clone();
        preload_people(&handle, people);

        let per_thread_queries = 40usize;
        let barrier = Arc::new(std::sync::Barrier::new(k + 1));
        let done = Arc::new(AtomicUsize::new(0));

        let mut workers = Vec::new();
        for _ in 0..k {
            let h = handle.clone();
            let b = Arc::clone(&barrier);
            let d = Arc::clone(&done);
            workers.push(std::thread::spawn(move || {
                b.wait();
                for _ in 0..per_thread_queries {
                    let (ok, rows) = run_auto(
                        &h,
                        AccessMode::Read,
                        "CALL db.propertyKeys() YIELD propertyKey RETURN count(propertyKey)",
                    );
                    assert!(ok && !rows.is_empty(), "procedure read commits with rows");
                    d.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        // Measure the CPU/wall over the concurrent burst only.
        barrier.wait();
        let cpu0 = process_cpu_ticks();
        let wall0 = Instant::now();
        for w in workers {
            w.join().expect("worker joins");
        }
        let wall = wall0.elapsed().as_secs_f64();
        let cpu_secs = (process_cpu_ticks() - cpu0) as f64 / ticks_per_sec;
        let cores = cpu_secs / wall.max(1e-9);
        cores_at.push((k, cores));
        report.push_str(&format!(
            "  K={k:2}: {q} queries in {wall:6.3}s  →  mean cores = {cores:5.2}\n",
            q = done.load(Ordering::Relaxed),
        ));

        shutdown(eng, handle);
    }

    print!("{report}");

    let cores_1 = cores_at
        .iter()
        .find(|(k, _)| *k == 1)
        .map(|(_, c)| *c)
        .unwrap();
    let cores_8 = cores_at
        .iter()
        .find(|(k, _)| *k == 8)
        .map(|(_, c)| *c)
        .unwrap();
    assert!(
        cores_8 > 1.2 && cores_8 > cores_1 * 1.5,
        "rmp #546: a procedure-heavy read must scale past one core off-thread \
         (K=1 → {cores_1:.2} cores, K=8 → {cores_8:.2} cores)"
    );
}
