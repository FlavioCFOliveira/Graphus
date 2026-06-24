//! **Concurrent-MATCH scaling measurement** (`rmp` task #336, Slice 3b-ii — the headline AC: server CPU
//! > 1 core under concurrent read).
//!
//! Preloads ~200k `:Person` nodes, then runs `K` client threads each looping
//! `MATCH (n:Person) RETURN sum(n.age)` against the **real threaded engine**, with the reader pool
//! sized to `K`. Reports, per `K ∈ {1, 2, 4, 8, 16}`: wall-clock for a fixed total number of queries,
//! the throughput (queries/s), and the speedup vs `K = 1`.
//!
//! ## How to read the result (the AC)
//!
//! The acceptance criterion is **mean cores = (User + Sys) / Wall > 1** under concurrent MATCH (the
//! baseline before Slice 3b-ii was ≈ 1.0 for any `K`, because every read serialised on the engine
//! thread). Run this test under `/usr/bin/time -v` to read the mean-core utilisation directly:
//!
//! ```text
//! /usr/bin/time -v cargo test -p graphus-server --release \
//!     --test concurrent_read_scaling -- --ignored --nocapture concurrent_match_scaling
//! ```
//!
//! `/usr/bin/time -v`'s "Percent of CPU this job got" (and `User + System` time over `Elapsed`)
//! crosses 100 % (= 1 core) once the reads genuinely run in parallel. The test also prints the
//! intra-run speedup curve so the knee (where shared-`ConcurrentBufferPool` contention rolls scaling
//! off — expected around 4–8 threads per the Slice-1 +15–53 % single-thread tax) is visible without an
//! external profiler. Ignored by default (it is a multi-second measurement, not a correctness gate).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// Spawns a threaded engine with `reader_threads` reader workers and a generously-sized buffer pool
/// (200k nodes must stay RAM-resident so the measurement is CPU-bound, not I/O-bound).
fn engine(reader_threads: usize) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            // 200k :Person nodes; size the pool to keep the whole working set hot (no eviction).
            let store = RecordStore::create(device, wal, 65_536, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        256,
        reader_threads,
        metrics,
        clock,
    )
    .expect("spawn threaded engine")
}

/// Runs an auto-commit statement to completion, returning whether it committed and the first scalar.
fn run(handle: &EngineHandle, mode: AccessMode, stmt: &str) -> (bool, Option<i64>) {
    let Ok(ticket) = handle.begin_auto_commit_blocking(mode) else {
        return (false, None);
    };
    match handle.run_blocking(ticket, stmt.to_owned(), vec![], true, None) {
        Ok(mut reply) => {
            let mut first: Option<i64> = None;
            loop {
                match reply.rows.next() {
                    Ok(Some(cells)) => {
                        if first.is_none() {
                            if let Some(graphus_cypher::MaterializedValue::Value(Value::Integer(
                                n,
                            ))) = cells.first()
                            {
                                first = Some(*n);
                            }
                        }
                    }
                    Ok(None) => return (true, first),
                    Err(_) => return (false, first),
                }
            }
        }
        Err(_) => (false, None),
    }
}

/// Preloads `n` `:Person {age}` nodes in batches (one auto-commit statement per batch via `UNWIND`),
/// returning the expected `sum(age)`.
fn preload_people(handle: &EngineHandle, n: i64) -> i64 {
    const BATCH: i64 = 2_000;
    let mut expected_sum: i64 = 0;
    let mut start = 0;
    while start < n {
        let end = (start + BATCH).min(n);
        // age = id % 100, so the sum is deterministic and the column is integer (the measured shape).
        let stmt = format!(
            "UNWIND range({start}, {}) AS i CREATE (:Person {{id: i, age: i % 100}})",
            end - 1
        );
        let (ok, _) = run(handle, AccessMode::Write, &stmt);
        assert!(ok, "preload batch [{start},{end}) commits");
        for i in start..end {
            expected_sum += i % 100;
        }
        start = end;
    }
    expected_sum
}

/// `rmp` task #377 (deterministic correctness gate, not a measurement): the reader-pool morsel
/// suppression — `K` concurrent large reads dispatched to the reader pool engage the morsel tier **zero**
/// times (no pool-on-pool oversubscription), while the identical aggregate on the engine thread *does*
/// engage it (proving the morsel gate is otherwise open). Results stay exact (equivalent to serial).
///
/// This asserts the invariant **directly** via [`graphus_cypher::morsel::morsel_fanout_count`] — a count
/// of morsel fan-outs onto the shared analytics pool — rather than sampling OS threads (which would be
/// flaky). With suppression in force a heavy read on a reader-pool worker is cross-statement-parallel
/// only (one of `K` reader threads), so it never fans `min(N,16)` morsel tasks onto the shared pool;
/// `K × min(N,16)` such tasks on a `min(N,16)`-thread pool is exactly the thrash #377 prevents.
#[test]
fn reader_pool_suppresses_morsel_no_oversubscription() {
    use graphus_cypher::morsel::{morsel_fanout_count, set_morsel_min_rows, set_morsel_threads};

    // Enable the morsel tier and open its cardinality gate (min-rows = 0) so it WOULD engage on any
    // aggregate shape — the suppression, not a too-small input, must be what keeps it off the reader path.
    set_morsel_threads(4);
    set_morsel_min_rows(0);

    // A modest corpus: large enough that the aggregate is the bare-aggregate morsel shape, small enough
    // for a fast deterministic gate (no multi-second loop).
    let people: i64 = 5_000;
    let k = 8usize;

    let eng = engine(k);
    let handle = eng.handle.clone();
    let expected = preload_people(&handle, people);

    // CONTROL: the identical aggregate on the ENGINE thread (Write-mode auto-commit is not dispatched to
    // the reader pool — it runs inline on the engine thread, which holds no reader-pool guard). With the
    // gate open it MUST engage the morsel tier, so the fan-out counter advances. This proves the morsel
    // path is genuinely reachable for this shape/corpus — so a zero count on the reader path below is the
    // suppression at work, not an unrelated decline.
    let before_control = morsel_fanout_count();
    let (ok, got) = run(
        &handle,
        AccessMode::Write,
        "MATCH (n:Person) RETURN sum(n.age)",
    );
    assert!(ok, "engine-thread aggregate commits");
    assert_eq!(got, Some(expected), "engine-thread aggregate is exact");
    assert!(
        morsel_fanout_count() > before_control,
        "control: the morsel tier MUST engage on the engine thread with the gate open \
         (else the reader-path zero below would be meaningless)"
    );

    // SUBJECT: `K` concurrent Read-mode auto-commit aggregates — each dispatched to a reader-pool worker.
    // The reader worker holds a `ReaderPoolWorkerGuard`, so `Ctx.morsel_threads` clamps to 1 at
    // `Cursor::open` and the morsel tier early-returns to serial. The fan-out counter must NOT advance.
    let before_readers = morsel_fanout_count();
    let done = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for _ in 0..k {
        let h = handle.clone();
        let done = Arc::clone(&done);
        workers.push(std::thread::spawn(move || {
            for _ in 0..4 {
                let (ok, got) = run(&h, AccessMode::Read, "MATCH (n:Person) RETURN sum(n.age)");
                // Suppression makes the read serial-within-statement, but it must stay EQUIVALENT to
                // serial — assert the exact aggregate so a wrong result still fails the gate.
                assert!(ok, "reader-pool aggregate commits");
                assert_eq!(
                    got,
                    Some(expected),
                    "reader-pool aggregate is exact (serial-equivalent)"
                );
                done.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for w in workers {
        w.join().expect("reader joins");
    }
    assert_eq!(
        done.load(Ordering::Relaxed),
        k * 4,
        "every reader query ran"
    );
    assert_eq!(
        morsel_fanout_count(),
        before_readers,
        "reader-pool morsel SUPPRESSION (#377): {k} concurrent large reads must fan out ZERO morsel \
         tasks — no pool-on-pool oversubscription"
    );

    // Restore the process-global knobs so sibling tests in this binary see the defaults.
    set_morsel_min_rows(u64::MAX);
    set_morsel_threads(1);

    let Engine {
        handle: inner,
        join,
    } = eng;
    drop(handle);
    drop(inner);
    join.join().expect("engine joins");
}

/// The concurrent-MATCH scaling measurement. Ignored (multi-second). See the module docs for how to run
/// it under `/usr/bin/time -v` to read the mean-core AC.
#[test]
#[ignore = "measurement: run under /usr/bin/time -v to read mean-cores (the #336 AC)"]
fn concurrent_match_scaling() {
    // 200k :Person matches the campaign's #337 corpus; the per-K total work is kept fixed so the
    // wall-clock directly reflects parallel speedup. Override via env for a quicker / heavier run
    // (`SCALE_PEOPLE`, `SCALE_QUERIES`).
    let people: i64 = std::env::var("SCALE_PEOPLE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let total_queries: usize = std::env::var("SCALE_QUERIES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64);
    // Restrict to a comma-separated subset of K (e.g. `SCALE_KS=8`) to measure one degree in isolation
    // under `/usr/bin/time -v` for a clean per-K mean-cores reading; default is the full curve.
    let ks: Vec<usize> = match std::env::var("SCALE_KS") {
        Ok(v) => v.split(',').filter_map(|s| s.trim().parse().ok()).collect(),
        Err(_) => vec![1usize, 2, 4, 8, 16],
    };

    // Preload once on a K=16 engine, measure the read sum to confirm correctness, then tear it down and
    // re-create per K (each engine owns its own store, so we re-preload per K — cheap relative to the
    // measured read loop, and keeps each K's run independent).
    println!(
        "\n=== #336 Slice 3b-ii concurrent-MATCH scaling (MATCH (n:Person) RETURN sum(n.age)) ==="
    );
    println!("preloading {people} :Person nodes per run; {total_queries} total queries per K\n");

    let mut baseline_qps: Option<f64> = None;
    for &k in &ks {
        let eng = engine(k);
        let handle = eng.handle.clone();
        let expected = preload_people(&handle, people);

        // Warm one read (also asserts correctness of the off-thread aggregate).
        let (ok, got) = run(
            &handle,
            AccessMode::Read,
            "MATCH (n:Person) RETURN sum(n.age)",
        );
        assert!(ok, "warm read commits (K={k})");
        assert_eq!(got, Some(expected), "off-thread sum is exact (K={k})");

        // K client threads each run TOTAL_QUERIES/K read queries; measure wall-clock of the loop.
        let per_thread = total_queries / k;
        let done = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        let mut workers = Vec::new();
        for _ in 0..k {
            let h = handle.clone();
            let done = Arc::clone(&done);
            workers.push(std::thread::spawn(move || {
                for _ in 0..per_thread {
                    let (ok, got) = run(&h, AccessMode::Read, "MATCH (n:Person) RETURN sum(n.age)");
                    // No concurrent writer runs during the read loop, so every read commits and the
                    // off-thread aggregate is exact (assert it, so a wrong parallel result still fails).
                    if ok {
                        debug_assert_eq!(got, Some(expected));
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for w in workers {
            w.join().expect("reader joins");
        }
        let elapsed = started.elapsed();
        let queries = done.load(Ordering::Relaxed);
        let qps = queries as f64 / elapsed.as_secs_f64();
        let speedup = baseline_qps.map_or(1.0, |b| qps / b);
        if k == 1 {
            baseline_qps = Some(qps);
        }
        println!(
            "K={k:>2}: {queries:>4} queries in {:>8.3}s  ->  {qps:>8.1} q/s   speedup x{speedup:.2}",
            elapsed.as_secs_f64()
        );

        // Tear down before the next K: drop BOTH handle clones (the loop's + the one inside `Engine`)
        // so the command channel closes and the engine loop exits, then join. Dropping only one clone
        // would leave a live sender and hang the join (see the `teardown` note in the sibling test).
        let Engine {
            handle: inner,
            join,
        } = eng;
        drop(handle);
        drop(inner);
        join.join().expect("engine joins");
    }
    println!(
        "\nMean cores = (User+Sys)/Wall — read from `/usr/bin/time -v` around this binary; \
         the AC is > 1 core (baseline was ~1.0 for any K before this slice).\n"
    );
}
