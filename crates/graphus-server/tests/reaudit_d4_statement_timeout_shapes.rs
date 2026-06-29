//! **D4 re-audit (`rmp` #485): the per-statement timeout (`rmp` #476) fires for CPU-bomb shapes beyond
//! the cartesian product the existing `statement_timeout.rs` already covers.**
//!
//! `statement_timeout.rs` proves the deadline aborts a 3-way **cartesian** bomb (whose per-row safe point
//! trips the deadline). That exercises one operator's safe point. The CPU-exhaustion DoS the timeout
//! must bound, however, can take other shapes — the most dangerous being a **variable-length expansion**
//! over a dense graph, whose path-enumeration DFS is a *different* code path with its *own* cancellation
//! safe points. A `MATCH p = (a)-[:E*1..k]->(b)` over a near-complete graph enumerates a number of simple
//! paths that grows super-exponentially in `k`: without a dense in-DFS safe point it would pin the engine
//! thread for hours.
//!
//! These tests build a small **complete directed graph** (cheap to seed, explosive to traverse) and drive
//! a deep variable-length path-count bomb through the **real threaded engine**, on both the **inline**
//! (explicit-transaction) and **off-thread reader** (auto-commit) paths, asserting:
//!
//! * the bomb is **aborted** (a clean `Err`, not a hang, not a panic) **well within** a generous ceiling;
//! * the engine **keeps serving** afterwards (a fresh statement succeeds); and
//! * a legitimate bounded traversal under the same timeout completes unaffected (no false-cancel).
//!
//! The bomb runs on a worker thread guarded by a `recv_timeout`: if the deadline did **not** fire (a real
//! safe-point gap), the test FAILS with a clear message inside the ceiling rather than hanging CI — so a
//! genuine gap is surfaced empirically, not silently tolerated.

use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine_with_timeout};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// A short, finite per-statement budget. Generous enough that the (cheap) seed and any legitimate query
/// never approach it, short enough that the bomb is reclaimed quickly.
const TIMEOUT: Duration = Duration::from_millis(800);

/// A wall-clock ceiling for "prompt cancellation": many times `TIMEOUT`, generous for CI noise, yet far
/// below the (effectively unbounded) runtime the path-enumeration bomb would have without the deadline.
const PROMPT_CEILING: Duration = Duration::from_secs(30);

/// Order of the complete directed graph seeded for the traversal bomb. K_20 has 20·19 = 380 edges
/// (milliseconds to build) but its `*1..k` simple-path count is astronomically large.
const CLIQUE_N: usize = 20;

/// A deep variable-length path-count bomb over the complete graph. `count(p)` aggregates without
/// materializing the paths (the DFS holds one path at a time), so this is purely **CPU**-bound (no OOM):
/// only the per-step cancellation safe point can stop it.
const VARLEN_BOMB: &str = "MATCH p = (a:V)-[:E*1..15]->(b:V) RETURN count(p) AS n";

fn engine_with_timeout(timeout: Option<Duration>) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine_with_timeout::<MemBlockDevice, MemLogSink, _>(
        Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 8_192, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        256,
        2,
        metrics,
        clock,
        timeout,
        None,
    )
    .expect("spawn threaded engine")
}

/// Drains a statement to completion: `Ok(())` on a clean drain, `Err(())` on any failure (a `Run` reply
/// error or a terminal stream error) — exactly how a connection observes a cancellation.
fn run_auto(handle: &EngineHandle, mode: AccessMode, stmt: &str) -> Result<(), ()> {
    let ticket = handle.begin_auto_commit_blocking(mode).map_err(|_| ())?;
    let mut reply = handle
        .run_blocking(ticket, stmt.to_owned(), vec![], true, None)
        .map_err(|_| ())?;
    loop {
        match reply.rows.next() {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(()),
            Err(_) => return Err(()),
        }
    }
}

/// Runs a statement inside an **explicit READ transaction** so it runs **inline** on the engine thread
/// (never dispatched off-thread). Rolls the transaction back afterward regardless.
fn run_explicit_read(handle: &EngineHandle, stmt: &str) -> Result<(), ()> {
    let ticket = handle.begin_blocking(AccessMode::Read).map_err(|_| ())?;
    let outcome = match handle.run_blocking(ticket, stmt.to_owned(), vec![], false, None) {
        Ok(mut reply) => loop {
            match reply.rows.next() {
                Ok(Some(_)) => {}
                Ok(None) => break Ok(()),
                Err(_) => break Err(()),
            }
        },
        Err(_) => Err(()),
    };
    let _ = handle.rollback_blocking(ticket);
    outcome
}

/// Seeds a complete directed graph `K_n` of `:V` nodes joined by `:E` edges (cheap — well under the
/// timeout). Built in two committed auto-commit statements.
fn seed_clique(handle: &EngineHandle, n: usize) {
    run_auto(
        handle,
        AccessMode::Write,
        &format!("UNWIND range(1, {n}) AS i CREATE (:V {{id: i}})"),
    )
    .expect("seed nodes");
    // Every ordered distinct pair gets a directed edge: 380 edges for n=20.
    run_auto(
        handle,
        AccessMode::Write,
        "MATCH (a:V), (b:V) WHERE a.id <> b.id CREATE (a)-[:E]->(b)",
    )
    .expect("seed edges");
}

fn shutdown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins cleanly");
}

/// Runs `body` on a worker thread and waits up to `PROMPT_CEILING`. Returns `(outcome, elapsed)`.
/// A non-returning body (a timeout that never fired — a real safe-point gap) FAILS with a clear message
/// instead of hanging CI.
fn run_guarded<F>(label: &str, body: F) -> (Result<(), ()>, Duration)
where
    F: FnOnce() -> Result<(), ()> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let started = Instant::now();
        let res = body();
        let _ = tx.send((res, started.elapsed()));
    });
    match rx.recv_timeout(PROMPT_CEILING) {
        Ok(v) => v,
        Err(_) => panic!(
            "STATEMENT-TIMEOUT GAP ({label}): the bomb did NOT abort within {PROMPT_CEILING:?} — a \
             CPU bomb escaped the per-statement deadline (a missing cancellation safe point)"
        ),
    }
}

/// Inline path (`rmp` #476): a deep variable-length expansion bomb in an explicit transaction is aborted
/// by the per-statement deadline, and the engine keeps serving.
#[test]
fn statement_timeout_aborts_varlen_expansion_bomb_inline() {
    let eng = engine_with_timeout(Some(TIMEOUT));
    let handle = eng.handle.clone();
    seed_clique(&handle, CLIQUE_N);

    let h = handle.clone();
    let (bomb, elapsed) = run_guarded("inline varlen", move || run_explicit_read(&h, VARLEN_BOMB));
    assert!(
        bomb.is_err(),
        "the inline variable-length expansion bomb must be aborted by the per-statement timeout"
    );
    println!("[REAUDIT#485] inline varlen bomb aborted in {elapsed:?} (timeout {TIMEOUT:?})");

    assert!(
        run_auto(
            &handle,
            AccessMode::Read,
            "MATCH (n:V) RETURN count(n) AS c"
        )
        .is_ok(),
        "the engine must keep serving after the bomb was timed out"
    );

    shutdown(eng, handle);
}

/// Off-thread reader path (`rmp` #476): the same bomb as an auto-commit read is dispatched to the reader
/// pool and aborted by the same deadline (carried on the read task), and the engine keeps serving.
#[test]
fn statement_timeout_aborts_varlen_expansion_bomb_offthread() {
    let eng = engine_with_timeout(Some(TIMEOUT));
    let handle = eng.handle.clone();
    seed_clique(&handle, CLIQUE_N);

    let h = handle.clone();
    let (bomb, elapsed) = run_guarded("offthread varlen", move || {
        run_auto(&h, AccessMode::Read, VARLEN_BOMB)
    });
    assert!(
        bomb.is_err(),
        "the off-thread variable-length expansion bomb must be aborted by the per-statement timeout"
    );
    println!("[REAUDIT#485] off-thread varlen bomb aborted in {elapsed:?} (timeout {TIMEOUT:?})");

    assert!(
        run_auto(
            &handle,
            AccessMode::Read,
            "MATCH (n:V) RETURN count(n) AS c"
        )
        .is_ok(),
        "the engine must keep serving after the off-thread bomb was timed out"
    );

    shutdown(eng, handle);
}

/// No false-cancel: a legitimate **bounded-depth** traversal over the same graph completes under the same
/// short timeout. `*1..2` over K_20 is ~380 + 380·19 ≈ 7.6k paths — trivial, well inside the budget.
#[test]
fn bounded_traversal_under_timeout_completes() {
    let eng = engine_with_timeout(Some(TIMEOUT));
    let handle = eng.handle.clone();
    seed_clique(&handle, CLIQUE_N);

    assert!(
        run_auto(
            &handle,
            AccessMode::Read,
            "MATCH p = (a:V)-[:E*1..2]->(b:V) RETURN count(p) AS n"
        )
        .is_ok(),
        "a legitimate bounded traversal must complete unaffected by the timeout (no false-cancel)"
    );

    shutdown(eng, handle);
}
