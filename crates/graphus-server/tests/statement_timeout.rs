//! **Per-statement execution-timeout regression gates** (`rmp` task #476 — the reliability mandate:
//! the server must operate without failure under extreme load and concurrency).
//!
//! Before #476 an ordinary Cypher statement ran with **no execution-time / CPU budget**: a patient
//! connected client could submit a cartesian-product or deep variable-length-expansion *bomb* that
//! pins the per-database engine thread (and, via morsel parallelism, several cores) indefinitely,
//! starving every co-tenant on the same database — a per-database-thread CPU-exhaustion denial of
//! service. Only GDS procedures carried a deadline.
//!
//! These tests drive a bomb query through the **real threaded engine** with a SHORT
//! `statement_timeout` configured and assert:
//!
//! * the bomb is aborted with a clean cancellation error **within roughly the timeout** (no panic, no
//!   hang, no unbounded CPU);
//! * the engine **keeps serving** — a subsequent ordinary statement on a fresh ticket succeeds;
//! * a legitimate statement under a generous timeout completes unaffected.
//!
//! Both the **inline** engine-thread path (an explicit-transaction read) and the **off-thread reader**
//! path (an auto-commit read) are exercised, since the per-statement deadline is threaded into both.

use std::sync::Arc;
use std::time::{Duration, Instant};

use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine_with_timeout};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// A short, finite per-statement budget for the bomb tests — long enough that the (cheap) seed +
/// normal queries never approach it, short enough that a bomb is reclaimed quickly so the test is fast.
const SHORT_TIMEOUT: Duration = Duration::from_millis(300);

/// A wall-clock ceiling for "prompt cancellation": the bomb must abort comfortably inside this (it is
/// many times `SHORT_TIMEOUT`, generous for CI noise, yet nowhere near the unbounded runtime the bomb
/// would have without the fix — folding the full cartesian product would take far longer).
const PROMPT_CEILING: Duration = Duration::from_secs(20);

/// Spawns a threaded engine over an in-memory store with `statement_timeout` configured.
fn engine_with_timeout(statement_timeout: Option<Duration>) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine_with_timeout::<MemBlockDevice, MemLogSink, _>(
        Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            // A pool large enough to keep the small seeded working set RAM-resident (no eviction).
            let store = RecordStore::create(device, wal, 8_192, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        256,
        // Two reader workers so an auto-commit read genuinely dispatches off-thread (exercising the
        // `ReadTask` deadline path), while an explicit-transaction read still runs inline.
        2,
        metrics,
        clock,
        statement_timeout,
        // No max-transaction-age cap in this test (rmp #477): it exercises the per-statement timeout.
        None,
    )
    .expect("spawn threaded engine")
}

/// Seeds `n` `:N` nodes in one committed auto-commit statement (cheap — well under any timeout).
fn seed_nodes(handle: &EngineHandle, n: usize) {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .expect("begin write");
    let mut reply = handle
        .run_blocking(
            ticket,
            format!("UNWIND range(1, {n}) AS i CREATE (:N {{v: i}})"),
            vec![],
            true,
            None,
        )
        .expect("seed run");
    // Drain to completion (the write commits when its stream is drained).
    while let Ok(Some(_)) = reply.rows.next() {}
}

/// Runs an **auto-commit** statement to completion, returning `Ok(())` if it streamed cleanly or
/// `Err(())` if it failed at any stage (a `Run` reply error or a terminal stream error). A cancelled
/// statement surfaces here as `Err(())` — exactly how a connection observes it.
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

/// Runs a statement inside an **explicit READ transaction** (so it never dispatches off-thread — it
/// runs inline on the engine thread), returning `Ok(())` on a clean drain or `Err(())` on any failure.
/// The transaction is rolled back afterward regardless.
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

fn shutdown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins cleanly");
}

/// A 3-way cartesian product over the seeded `:N` set, aggregated — `n^3` intermediate rows. With a
/// few hundred nodes this is tens of millions of rows: far more than any per-statement budget allows,
/// so the executor's per-row safe point trips the deadline long before it finishes.
const CARTESIAN_BOMB: &str = "MATCH (a:N), (b:N), (c:N) RETURN count(*) AS n";

/// Inline path (`rmp` #476): an explicit-transaction read bomb on the engine thread is aborted within
/// roughly the timeout, and the engine keeps serving.
#[test]
fn statement_timeout_aborts_inline_cartesian_bomb() {
    let eng = engine_with_timeout(Some(SHORT_TIMEOUT));
    let handle = eng.handle.clone();

    seed_nodes(&handle, 400);

    // The bomb must FAIL (cancelled), and promptly.
    let started = Instant::now();
    let bomb = run_explicit_read(&handle, CARTESIAN_BOMB);
    let elapsed = started.elapsed();
    assert!(
        bomb.is_err(),
        "the inline cartesian bomb must be aborted by the per-statement timeout"
    );
    assert!(
        elapsed < PROMPT_CEILING,
        "cancellation must be prompt (≈ the timeout), took {elapsed:?}"
    );

    // The engine is still alive and serving: a normal query on a fresh ticket succeeds.
    assert!(
        run_auto(
            &handle,
            AccessMode::Read,
            "MATCH (n:N) RETURN count(n) AS c"
        )
        .is_ok(),
        "the engine must keep serving after a statement was timed out"
    );

    shutdown(eng, handle);
}

/// Off-thread reader path (`rmp` #476): an auto-commit read bomb dispatched to the reader pool is
/// aborted by the same per-statement deadline (carried on the `ReadTask`), and the engine keeps serving.
#[test]
fn statement_timeout_aborts_offthread_cartesian_bomb() {
    let eng = engine_with_timeout(Some(SHORT_TIMEOUT));
    let handle = eng.handle.clone();

    seed_nodes(&handle, 400);

    let started = Instant::now();
    let bomb = run_auto(&handle, AccessMode::Read, CARTESIAN_BOMB);
    let elapsed = started.elapsed();
    assert!(
        bomb.is_err(),
        "the off-thread cartesian bomb must be aborted by the per-statement timeout"
    );
    assert!(
        elapsed < PROMPT_CEILING,
        "off-thread cancellation must be prompt (≈ the timeout), took {elapsed:?}"
    );

    assert!(
        run_auto(
            &handle,
            AccessMode::Read,
            "MATCH (n:N) RETURN count(n) AS c"
        )
        .is_ok(),
        "the engine must keep serving after an off-thread statement was timed out"
    );

    shutdown(eng, handle);
}

/// A legitimate query under a generous timeout completes unaffected — the budget never trips, the
/// result is exact, and nothing is false-cancelled.
#[test]
fn generous_timeout_does_not_disturb_normal_queries() {
    let eng = engine_with_timeout(Some(Duration::from_secs(3600)));
    let handle = eng.handle.clone();

    seed_nodes(&handle, 50);

    // A modest cartesian (50*50 = 2_500 rows) completes well within an hour.
    assert!(
        run_auto(
            &handle,
            AccessMode::Read,
            "MATCH (a:N), (b:N) RETURN count(*) AS n"
        )
        .is_ok(),
        "a normal query under a generous timeout must complete unaffected"
    );
    // And a plain scan.
    assert!(
        run_auto(
            &handle,
            AccessMode::Read,
            "MATCH (n:N) RETURN count(n) AS c"
        )
        .is_ok(),
        "a plain scan under a generous timeout must complete unaffected"
    );

    shutdown(eng, handle);
}

/// A disabled timeout (`None`) preserves the prior unbounded behaviour for legitimate work: a normal
/// query still completes (this is the opt-out / `statement_timeout_ms = 0` config).
#[test]
fn disabled_timeout_runs_normal_queries() {
    let eng = engine_with_timeout(None);
    let handle = eng.handle.clone();

    seed_nodes(&handle, 50);
    assert!(
        run_auto(
            &handle,
            AccessMode::Read,
            "MATCH (n:N) RETURN count(n) AS c"
        )
        .is_ok(),
        "a normal query with the timeout disabled must complete"
    );

    shutdown(eng, handle);
}
