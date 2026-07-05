//! **Real-thread regression for `rmp` #588 (sprint-52 Finding B1)** — maintenance GC must not reuse a
//! freed physical slot while an off-thread reader may still be walking a chain through it.
//!
//! The deterministic white-box proof lives in `graphus-storage/tests/gc_reader_slot_reuse_588.rs`;
//! this is its **true-parallel** twin — the concurrency-fidelity coverage the single-threaded DST
//! simulator structurally cannot express (the off-thread reader pool, real `checkpoint`-driven GC
//! reclaim, and physical slot reuse all running on genuine OS threads at once).
//!
//! A hub node keeps `PERM` permanent edges that are **never** deleted, so every snapshot must always
//! see exactly `PERM` of them. Concurrently, a writer churns `CHURN` edges (create → delete →
//! `CHECKPOINT` to reclaim + free their slots → create again to reuse them) while several reader
//! threads count the hub's permanent edges. Under B1, a reader walking the hub's incidence chain when
//! a reclaimed CHURN slot below a permanent edge is reused would divert into the foreign record and
//! **lose** permanent edges (count `< PERM`) or hit a malformed-chain error. With the reuse barrier a
//! freed slot is shadow-held while any predating reader is in flight, so the count is invariably `PERM`.
//!
//! It is a non-deterministic real-thread test (the OS scheduler picks the interleaving), so it is not
//! part of the deterministic seed-replay gate; it belongs on the ThreadSanitizer lane.
//!
//! **Scope note.** The *tight* B1 regression gate is the deterministic white-box twin (which fails
//! without the fix by construction); this test is **concurrency-fidelity stress coverage** — it drives
//! the real off-thread reader pool, real `checkpoint`-driven GC reclaim, and real physical slot reuse
//! on genuine OS threads, asserting no corruption / no lost committed edge / no leak. Because the
//! active readers pin the GC watermark, reclaim of the *newest* tombstones is throttled, so the exact
//! lose-an-edge interleaving is rare here — hence the deterministic twin owns the fail-without-fix
//! guarantee and this owns the "the fix behaves correctly under true parallelism" guarantee.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, TxTicket, spawn_engine};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

const PERM: i64 = 32;
const ROUNDS: usize = 600;
const READER_THREADS: usize = 4;

fn threaded_engine(reader_threads: usize) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        std::sync::Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            // A small pool so eviction/reuse activity is real under the churn.
            let store = RecordStore::create(device, wal, 512, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        1024,
        64,
        reader_threads,
        metrics,
        clock,
    )
    .expect("spawn threaded engine")
}

fn teardown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins");
}

/// Runs `stmt` in `ticket`, draining its rows; returns `(ok, rows, err)` where `err` is the failure
/// text (so the reader can distinguish a B1 malformed-chain error from a transient busy/reject).
fn run_drain(
    handle: &EngineHandle,
    ticket: TxTicket,
    stmt: &str,
) -> (bool, Vec<Vec<Value>>, Option<String>) {
    match handle.run_blocking(ticket, stmt.to_owned(), vec![], true, None) {
        Ok(mut reply) => {
            let mut rows = Vec::new();
            loop {
                match reply.rows.next() {
                    Ok(Some(cells)) => rows.push(
                        cells
                            .iter()
                            .map(|c| match c {
                                graphus_cypher::MaterializedValue::Value(v) => v.clone(),
                                other => Value::String(format!("{other:?}")),
                            })
                            .collect(),
                    ),
                    Ok(None) => return (true, rows, None),
                    Err(e) => return (false, rows, Some(format!("{e:?}"))),
                }
            }
        }
        Err(e) => (false, Vec::new(), Some(format!("{e:?}"))),
    }
}

fn auto_commit(handle: &EngineHandle, mode: AccessMode, stmt: &str) -> (bool, Vec<Vec<Value>>) {
    match handle.begin_auto_commit_blocking(mode) {
        Ok(ticket) => {
            let (ok, rows, _) = run_drain(handle, ticket, stmt);
            (ok, rows)
        }
        Err(_) => (false, Vec::new()),
    }
}

/// A read that returns `(ok, rows, err)` for the concurrent readers, so a transient reject can be told
/// apart from a corruption error.
fn read_count(handle: &EngineHandle, stmt: &str) -> (bool, Vec<Vec<Value>>, Option<String>) {
    match handle.begin_auto_commit_blocking(AccessMode::Read) {
        Ok(ticket) => run_drain(handle, ticket, stmt),
        Err(e) => (false, Vec::new(), Some(format!("{e:?}"))),
    }
}

fn one_int(rows: &[Vec<Value>]) -> Option<i64> {
    match rows.first().and_then(|r| r.first()) {
        Some(Value::Integer(n)) => Some(*n),
        _ => None,
    }
}

#[test]
fn inflight_readers_never_lose_permanent_edges_under_concurrent_gc_reuse() {
    let engine = threaded_engine(READER_THREADS);
    let handle = engine.handle.clone();

    // Build the hub with PERM permanent edges (never deleted).
    let (ok, _) = auto_commit(&handle, AccessMode::Write, "CREATE (:Hub {k: 0})");
    assert!(ok, "create hub");
    for _ in 0..PERM {
        let (ok, _) = auto_commit(
            &handle,
            AccessMode::Write,
            "MATCH (h:Hub) CREATE (h)-[:PERM]->(:Leaf)",
        );
        assert!(ok, "create permanent edge");
    }
    // Sanity: the hub sees exactly PERM permanent edges before any churn.
    let (ok, rows) = auto_commit(
        &handle,
        AccessMode::Read,
        "MATCH (:Hub)-[r:PERM]->() RETURN count(r)",
    );
    assert!(ok && one_int(&rows) == Some(PERM), "baseline PERM count");

    let stop = Arc::new(AtomicBool::new(false));
    let violations = Arc::new(AtomicU64::new(0));
    let worst = Arc::new(AtomicI64::new(PERM));
    let read_errors = Arc::new(AtomicU64::new(0));

    // Reader threads: count the hub's permanent edges; the answer must ALWAYS be exactly PERM.
    let readers: Vec<_> = (0..READER_THREADS)
        .map(|_| {
            let handle = handle.clone();
            let stop = Arc::clone(&stop);
            let violations = Arc::clone(&violations);
            let worst = Arc::clone(&worst);
            let read_errors = Arc::clone(&read_errors);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let (ok, rows, err) =
                        read_count(&handle, "MATCH (:Hub)-[r:PERM]->() RETURN count(r)");
                    if !ok {
                        // Only a corruption/malformed-chain error is a B1 symptom; a transient reject
                        // under saturation (server-busy / admission) is a legitimate outcome, not a bug.
                        let msg = err.unwrap_or_default().to_lowercase();
                        if msg.contains("malformed")
                            || msg.contains("cycle")
                            || msg.contains("chain")
                            || msg.contains("checksum")
                            || msg.contains("corrupt")
                        {
                            read_errors.fetch_add(1, Ordering::Relaxed);
                        }
                        continue;
                    }
                    match one_int(&rows) {
                        Some(n) if n == PERM => {}
                        Some(n) => {
                            violations.fetch_add(1, Ordering::Relaxed);
                            worst.fetch_min(n, Ordering::Relaxed);
                        }
                        None => {
                            violations.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
        })
        .collect();

    // Writer thread: churn CHURN edges + force GC reclaim (freeing their slots) + reuse them.
    let writer = {
        let handle = handle.clone();
        std::thread::spawn(move || {
            for _ in 0..ROUNDS {
                // Create a churn edge to a fresh temp node.
                let _ = auto_commit(
                    &handle,
                    AccessMode::Write,
                    "MATCH (h:Hub) CREATE (h)-[:CHURN]->(:Tmp)",
                );
                // Delete one churn edge and its temp node -> a reclaimable tombstone.
                let _ = auto_commit(
                    &handle,
                    AccessMode::Write,
                    "MATCH (:Hub)-[r:CHURN]->(x) WITH r, x LIMIT 1 DELETE r, x",
                );
                // Force a maintenance GC pass: reclaims the tombstone, freeing its slot (which the next
                // create reuses). Runs the reader-safe reclaim path (`rmp` #588) — the freed slot is
                // shadow-held from reuse while any reader that predates the pass is in flight.
                // NOTE: the BLOCKING variant — the async `checkpoint()` returns an un-awaited future that
                // would never actually run the pass, making this test vacuous for the reclaim it targets.
                let _ = handle.checkpoint_blocking();
            }
        })
    };

    writer.join().expect("writer joins");
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        r.join().expect("reader joins");
    }

    let v = violations.load(Ordering::Relaxed);
    let e = read_errors.load(Ordering::Relaxed);
    let w = worst.load(Ordering::Relaxed);
    assert_eq!(
        v, 0,
        "#588: an in-flight reader lost committed permanent edges under concurrent GC slot-reuse \
         ({v} bad reads; worst count {w} of {PERM})"
    );
    assert_eq!(
        e, 0,
        "#588: {e} reads failed (a malformed-chain error is a B1 symptom)"
    );

    // Final consistency: the hub still has exactly PERM permanent edges.
    let (ok, rows) = auto_commit(
        &handle,
        AccessMode::Read,
        "MATCH (:Hub)-[r:PERM]->() RETURN count(r)",
    );
    assert!(
        ok && one_int(&rows) == Some(PERM),
        "final PERM count intact"
    );

    teardown(engine, handle);
}
