//! **Real-OS-thread readers vs. a growing writer** (`rmp` #721) — the true-parallel pair to the
//! deterministic `reader_vs_store_growth` DST guard.
//!
//! # Why this test exists
//!
//! The deterministic simulator runs the engine on **one cooperative thread** with each statement
//! executed atomically to completion, so it can never place a writer's commit *inside* a reader's
//! statement. But that is exactly where `rmp` #721 lives: the off-thread reader pool captures its
//! `MetaSnapshot` at dispatch (`TxnCoordinator::read_task_inputs`) and then executes on a reader thread
//! **while the engine thread keeps committing**. The DST guard
//! ([`graphus_dst::reader_store_growth`]) reproduces the *ordering* deterministically; this test
//! reproduces the *parallelism*, through the real engine, the real reader pool, and the real
//! `ConcurrentBufferPool`.
//!
//! # The workload — the exact shape that surfaced the defect in production
//!
//! `examples/product-recommendations` (`rmp` #714) measured 2–5 of every 1500 reads per rung
//! (~0.2–0.3%) failing with `Neo.DatabaseError.General.UnknownError: Prop store page 321 not
//! allocated` in the MIXED arm, while the writers-off CONTROL arm of the same ladder was 100% clean.
//! This test runs that shape:
//!
//! - **one paced writer thread** doing `CREATE (u)-[:PURCHASED]->(p)` and
//!   `SET p.hot = coalesce(p.hot, 0) + 1` — which grows the node, rel, prop **and** strings stores and
//!   re-points the hub's incidence and property chain heads at records on **newly allocated pages**;
//! - **N reader connections** running a traversal battery (expand, property read, aggregation) against
//!   the very hub the writer is growing.
//!
//! # The invariant (`I6`, the same one the examples gate on)
//!
//! **No read fails with an internal server error.** A legitimate read of committed data must not fail
//! merely because another transaction is writing. Pre-fix this test fails with
//! `"Rel store page N not allocated"` / `"Prop store page N not allocated"`; post-fix it is clean.
//!
//! It is deliberately a non-deterministic, real-thread test (the OS scheduler decides the
//! interleaving), so — like `real_thread_supernode_stress` — it is not part of the deterministic
//! seed-replay gate; it is the true-parallel owner of this race class.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// Spawns a real threaded engine with `reader_threads` reader workers, so reads genuinely dispatch
/// off-thread and hit the buffer pool from many OS threads at once.
fn threaded_engine(reader_threads: usize) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        Arc::<str>::from("reader-vs-growth-721"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 1024, 1)?;
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

fn teardown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins");
}

/// Runs one auto-commit statement to completion, draining every row. Returns `Err(message)` if the
/// engine reported an error at ANY stage (begin, run, or mid-stream) — that is what the invariant
/// gates on.
fn run_stmt(
    handle: &EngineHandle,
    mode: AccessMode,
    stmt: &str,
    params: Vec<(String, Value)>,
) -> Result<(), String> {
    let ticket = handle
        .begin_auto_commit_blocking(mode)
        .map_err(|e| format!("begin: {e}"))?;
    let mut reply = handle
        .run_blocking(ticket, stmt.to_owned(), params, true, None)
        .map_err(|e| format!("run: {e}"))?;
    loop {
        match reply.rows.next() {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(()),
            // The failure mode of `rmp` #721 surfaces HERE: mid-stream, as the chain walk dies.
            Err(e) => return Err(format!("stream: {e}")),
        }
    }
}

/// `N` reader connections run a traversal battery against a hub that a paced writer is concurrently
/// growing. **No read may fail** (`rmp` #721 / examples invariant `I6`).
#[test]
fn concurrent_readers_never_fail_while_a_writer_grows_the_store() {
    for &readers in &[2usize, 4, 8] {
        let engine = threaded_engine(4);
        let handle = engine.handle.clone();

        // The hub the writer grows and the readers traverse.
        run_stmt(
            &handle,
            AccessMode::Write,
            "CREATE (:Product {id: 0, hot: 0})",
            vec![],
        )
        .expect("create hub");

        let stop = Arc::new(AtomicBool::new(false));
        let reads_done = Arc::new(AtomicUsize::new(0));
        let writes_done = Arc::new(AtomicUsize::new(0));
        // Every read failure the invariant forbids, verbatim.
        let failures: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        // -- the paced writer: grows the node/rel/prop/strings stores under the readers -------------
        let writer = {
            let h = handle.clone();
            let stop = Arc::clone(&stop);
            let writes_done = Arc::clone(&writes_done);
            let failures = Arc::clone(&failures);
            std::thread::spawn(move || {
                for i in 0..600i64 {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    // A purchase edge: prepends to the hub's incidence chain, growing the rel + node
                    // stores onto fresh device pages.
                    if let Err(e) = run_stmt(
                        &h,
                        AccessMode::Write,
                        "MATCH (p:Product {id: 0}) CREATE (u:User {id: $i})-[:PURCHASED]->(p)",
                        vec![("i".to_owned(), Value::Integer(i))],
                    ) {
                        failures.lock().unwrap().push(format!("writer create: {e}"));
                    }
                    // A hot-counter bump: per-value MVCC prepends a fresh property version, growing the
                    // prop store and re-pointing the hub's `first_prop`.
                    if let Err(e) = run_stmt(
                        &h,
                        AccessMode::Write,
                        "MATCH (p:Product {id: 0}) SET p.hot = coalesce(p.hot, 0) + 1",
                        vec![],
                    ) {
                        failures.lock().unwrap().push(format!("writer set: {e}"));
                    }
                    writes_done.fetch_add(1, Ordering::Relaxed);
                }
                stop.store(true, Ordering::Relaxed);
            })
        };

        // -- N reader connections: the traversal battery ---------------------------------------------
        let battery = [
            // The expand that walks the hub's (concurrently growing) incidence chain.
            "MATCH (p:Product {id: 0})<-[:PURCHASED]-(u:User) RETURN count(u) AS c",
            // The property read that walks the hub's (concurrently growing) property chain.
            "MATCH (p:Product {id: 0}) RETURN p.hot AS hot",
            // A two-hop traversal off the hub.
            "MATCH (p:Product {id: 0})<-[:PURCHASED]-(u:User)-[:PURCHASED]->(q:Product) \
             RETURN count(q) AS c",
        ];
        let reader_threads: Vec<_> = (0..readers)
            .map(|_| {
                let h = handle.clone();
                let stop = Arc::clone(&stop);
                let reads_done = Arc::clone(&reads_done);
                let failures = Arc::clone(&failures);
                std::thread::spawn(move || {
                    let mut k = 0usize;
                    while !stop.load(Ordering::Relaxed) {
                        let stmt = battery[k % battery.len()];
                        k += 1;
                        if let Err(e) = run_stmt(&h, AccessMode::Read, stmt, vec![]) {
                            failures.lock().unwrap().push(format!("read `{stmt}`: {e}"));
                        }
                        reads_done.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        writer.join().expect("writer thread joins");
        for t in reader_threads {
            t.join().expect("reader thread joins");
        }

        let reads = reads_done.load(Ordering::Relaxed);
        let writes = writes_done.load(Ordering::Relaxed);
        let failures = failures.lock().unwrap().clone();

        // NON-VACUITY: the run proves nothing unless the readers really did read while the writer
        // really did grow the store.
        assert!(
            writes > 100,
            "vacuous run at {readers} readers: the writer only committed {writes} rounds"
        );
        assert!(
            reads > 50,
            "vacuous run at {readers} readers: only {reads} reads were served"
        );

        // THE INVARIANT (`rmp` #721 / examples `I6`): a legitimate read must never fail with an
        // internal server error just because another transaction is writing.
        assert!(
            failures.is_empty(),
            "{readers} readers / {writes} writer rounds / {reads} reads: {} operation(s) FAILED — a \
             concurrent writer must never break a reader (`rmp` #721).\n  {}",
            failures.len(),
            failures.join("\n  ")
        );

        teardown(engine, handle);
    }
}
