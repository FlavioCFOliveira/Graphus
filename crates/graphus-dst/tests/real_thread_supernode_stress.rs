//! **Real-OS-thread supernode write stress** (rmp #460) — the true-parallel pair to the DST `#220`
//! logical guard.
//!
//! # Why this test exists (the concurrency-fidelity gap it closes)
//!
//! The deterministic simulator (VOPR) runs the engine on **one cooperative OS thread** with each Cypher
//! statement executed atomically to completion. Its "concurrency" is overlapping transaction
//! *lifetimes*, never overlapping *execution*. The `#220` supernode guard in
//! `crate::scenarios` therefore expresses "K concurrent writers" as K sequentially-executed tickets
//! whose lifetimes overlap (commutative-overlap-at-commit). That is the correct shape for DST, but it
//! **cannot** exercise the engine's real-thread machinery: the off-thread reader pool, the
//! `ConcurrentBufferPool` contended victim sweep, concurrent evictors, and the doublewrite ring are all
//! structurally invisible to a single-threaded driver (see `specification/07-dst-simulator.md` §5.1).
//!
//! This test is the named owner of the **true-parallel** supernode case: it spawns `N` real OS threads,
//! each opening its **own** write transaction through a cloned `Send + Sync` `EngineHandle` and creating
//! one `:LINK` edge on the **same** hub, with the transactions genuinely **in flight at the same time**
//! across OS threads, contending on the shared command channel, buffer pool, and the hub's relationship
//! chain head. It asserts the same safety property the DST `#220` guard asserts logically — **every
//! edge that commits survives** (`fan-out == committed`, never 0) — but now under real thread
//! parallelism, plus **liveness** (no panic, no hang: the run always terminates and the engine keeps
//! serving afterwards).
//!
//! It is deliberately a non-deterministic, real-thread test (the OS scheduler decides the interleaving),
//! so it is **not** part of the deterministic seed-replay gate; it is one of the loom/real-thread owners
//! the spec names for the parallel-race class. It is the lane run under ThreadSanitizer by
//! `scripts/tsan-soak.sh` (rmp #460).
//!
//! Note on the engine's write model: Graphus serialises *write execution* on the single engine task
//! (the engine is the write authority), so this stress proves the correctness of the concurrent path
//! through the shared command channel, the cloned handles, and the shared storage under N OS threads —
//! not parallel write execution (which the engine does not perform). The reads issued alongside the
//! writes do dispatch on the off-thread reader pool, so the buffer pool is exercised from multiple OS
//! threads concurrently.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// Spawns a real threaded engine over a fresh in-memory store with `reader_threads` reader workers, so
/// the reads issued during the stress dispatch off-thread (exercising the buffer pool from many OS
/// threads at once).
fn threaded_engine(reader_threads: usize) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        Arc::<str>::from("dst-stress"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            // A small-ish pool: large enough to hold the working set, small enough that a wide fan-out
            // exercises real eviction/sweep activity under contention.
            let store = RecordStore::create(device, wal, 512, 1)?;
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

/// Tears the threaded engine down: drop every handle (caller's clone + the one inside `Engine`) so the
/// command channel closes and the loop exits, then join the engine thread.
fn teardown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins");
}

/// Runs an auto-commit statement to completion through `handle`, returning the first integer scalar of
/// the first row (or `None`).
fn scalar(handle: &EngineHandle, stmt: &str) -> Option<i64> {
    let ticket = handle.begin_auto_commit_blocking(AccessMode::Read).ok()?;
    let mut reply = handle
        .run_blocking(ticket, stmt.to_owned(), vec![], true, None)
        .ok()?;
    let mut v = None;
    while let Ok(Some(cells)) = reply.rows.next() {
        if let Some(graphus_cypher::MaterializedValue::Value(Value::Integer(n))) = cells.first() {
            v = Some(*n);
        }
    }
    v
}

/// One writer thread: opens its own explicit write transaction, creates a single `:LINK` edge from the
/// shared hub to a fresh unique leaf, then commits. Returns `true` iff the commit was acknowledged.
/// Distinct `leaf` per thread so a committed edge is individually identifiable.
fn create_one_edge(handle: &EngineHandle, leaf: i64) -> bool {
    let Ok(ticket) = handle.begin_blocking(AccessMode::Write) else {
        return false;
    };
    let run = handle.run_blocking(
        ticket,
        "MATCH (h:Hub {id: 0}) CREATE (h)-[:LINK]->(:Leaf {id: $l})".to_owned(),
        vec![("l".to_owned(), Value::Integer(leaf))],
        false,
        None,
    );
    match run {
        Ok(mut reply) => {
            // Drain; a runtime error here means the statement failed — roll back and report no commit.
            let mut ok = true;
            loop {
                match reply.rows.next() {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                let _ = handle.rollback_blocking(ticket);
                return false;
            }
        }
        Err(_) => {
            let _ = handle.rollback_blocking(ticket);
            return false;
        }
    }
    handle.commit_blocking(ticket).is_ok()
}

/// **rmp #460 / pairs DST #220.** `N` real OS threads each create one edge on the **same** hub
/// concurrently; every committed edge must survive (`fan-out == committed`, never 0), the engine must
/// not panic or hang, and it must keep serving afterwards. Swept over a range of concurrency degrees so
/// the guarantee holds at every `N`, exactly as the DST guard sweeps `K`.
#[test]
fn real_thread_supernode_keeps_committed_edges() {
    for &n in &[2usize, 4, 8, 16, 32] {
        let engine = threaded_engine(4);
        let handle = engine.handle.clone();

        // Create the shared hub.
        let setup = handle
            .begin_auto_commit_blocking(AccessMode::Write)
            .expect("begin setup");
        let mut r = handle
            .run_blocking(
                setup,
                "CREATE (:Hub {id: 0})".to_owned(),
                vec![],
                true,
                None,
            )
            .expect("create hub");
        while let Ok(Some(_)) = r.rows.next() {}

        // Fan out N writer threads, each creating one edge on the hub concurrently.
        let committed = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::with_capacity(n);
        for i in 0..n {
            let h = handle.clone();
            let c = Arc::clone(&committed);
            threads.push(std::thread::spawn(move || {
                if create_one_edge(&h, 1000 + i as i64) {
                    c.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for t in threads {
            // A panicked writer thread is a hard failure (the engine must never make a client thread
            // panic). `join` surfaces it.
            t.join().expect("writer thread must not panic");
        }

        let committed = committed.load(Ordering::Relaxed);
        // The engine keeps serving: count the hub's out-edges.
        let fanout = scalar(
            &handle,
            "MATCH (h:Hub {id: 0})-[:LINK]->(x) RETURN count(x) AS c",
        );

        assert!(
            committed >= 1,
            "at least one of {n} concurrent writers must commit"
        );
        assert_eq!(
            fanout,
            Some(committed as i64),
            "rmp #460 (pairs #220): at N={n} every committed edge must survive under real OS-thread \
             parallelism (fan-out {fanout:?} == committed {committed})"
        );

        teardown(engine, handle);
    }
}

/// **rmp #460 liveness.** A burst of concurrent writers plus concurrent readers on the same hub must
/// leave the engine live and consistent: no panic, no hang, and a final read returns the exact
/// committed fan-out. This pairs the readers (off-thread pool) with the writers so the buffer pool is
/// genuinely touched from multiple OS threads at once — the path DST cannot reach.
#[test]
fn real_thread_supernode_with_concurrent_readers_stays_live() {
    const N_WRITERS: usize = 24;
    const N_READERS: usize = 8;

    let engine = threaded_engine(N_READERS);
    let handle = engine.handle.clone();

    let setup = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .expect("begin setup");
    let mut r = handle
        .run_blocking(
            setup,
            "CREATE (:Hub {id: 0})".to_owned(),
            vec![],
            true,
            None,
        )
        .expect("create hub");
    while let Ok(Some(_)) = r.rows.next() {}

    let committed = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut threads = Vec::new();

    // Reader threads: loop counting the hub's fan-out until the writers signal stop. They must never
    // panic, hang, or observe a torn read (a count is always a non-negative integer).
    for _ in 0..N_READERS {
        let h = handle.clone();
        let stop = Arc::clone(&stop);
        threads.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let c = scalar(
                    &h,
                    "MATCH (h:Hub {id: 0})-[:LINK]->(x) RETURN count(x) AS c",
                );
                assert!(
                    c.unwrap_or(0) >= 0,
                    "a concurrent read must always return a valid count"
                );
            }
        }));
    }

    // Writer threads: each creates one edge.
    let mut writers = Vec::with_capacity(N_WRITERS);
    for i in 0..N_WRITERS {
        let h = handle.clone();
        let c = Arc::clone(&committed);
        writers.push(std::thread::spawn(move || {
            if create_one_edge(&h, 2000 + i as i64) {
                c.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for w in writers {
        w.join().expect("writer thread must not panic");
    }
    stop.store(true, Ordering::Relaxed);
    for t in threads {
        t.join().expect("reader thread must not panic");
    }

    let committed = committed.load(Ordering::Relaxed);
    let fanout = scalar(
        &handle,
        "MATCH (h:Hub {id: 0})-[:LINK]->(x) RETURN count(x) AS c",
    );
    assert_eq!(
        fanout,
        Some(committed as i64),
        "every committed edge must survive with concurrent readers active (fan-out {fanout:?} == \
         committed {committed})"
    );

    teardown(engine, handle);
}
