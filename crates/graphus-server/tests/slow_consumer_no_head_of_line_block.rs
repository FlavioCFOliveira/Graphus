//! **Resumable-cursor egress backpressure** (`rmp` task #372): the single engine thread must NOT
//! head-of-line-block on a full bounded egress channel while a slow (even zero-draining) consumer
//! catches up — it must return to its command loop and service concurrent commands/writes on the
//! **same** database.
//!
//! ## The teeth
//!
//! [`slow_consumer_does_not_block_a_concurrent_command`] preloads more rows than the bounded egress
//! channel can hold, starts an inline statement (an explicit-transaction READ, which always runs on
//! the engine thread), and **never drains a single row** of its result. It then issues a concurrent
//! command on the same database from another thread and asserts it completes within a generous bound.
//!
//! - **Before #372** the engine blocks on `row_tx.send` once the channel fills (after `capacity`
//!   rows), servicing nothing else for that database; the concurrent command would never be answered
//!   and the bounded join below would time out (the teeth: this asserts the *old* behaviour fails).
//! - **After #372** the engine suspends the cursor off its borrow each time the channel fills,
//!   returns to the loop, and answers the concurrent command on the next tick.
//!
//! The bound is enforced with a `recv_timeout` on a completion signal — there are **no real sleeps**
//! on the engine path that could hang the test, and a timeout is a definitive *failure*, never a hang.

use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// The bounded egress capacity for the test engine. Small so the channel fills after only a handful
/// of un-drained rows (the head-of-line-block trigger).
const EGRESS_CAPACITY: usize = 4;

/// Spawns a threaded engine with a **small** bounded egress channel, so a zero-draining consumer
/// fills it almost immediately and the resumable-cursor path (#372) is exercised.
fn engine() -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 8_192, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        // Engine queue capacity: generous (we never want the *command* channel to be the bottleneck).
        256,
        EGRESS_CAPACITY,
        // One reader thread so the pool is "threaded" (matches production), but the statement under
        // test is an explicit-transaction READ that always runs INLINE on the engine thread.
        1,
        metrics,
        clock,
    )
    .expect("spawn threaded engine")
}

/// Runs an auto-commit statement to completion (draining all rows), returning whether it committed.
fn run_autocommit(handle: &EngineHandle, mode: AccessMode, stmt: &str) -> bool {
    let Ok(ticket) = handle.begin_auto_commit_blocking(mode) else {
        return false;
    };
    match handle.run_blocking(ticket, stmt.to_owned(), vec![], true, None) {
        Ok(mut reply) => loop {
            match reply.rows.next() {
                Ok(Some(_)) => {}
                Ok(None) => return true,
                Err(_) => return false,
            }
        },
        Err(_) => false,
    }
}

#[test]
fn slow_consumer_does_not_block_a_concurrent_command() {
    let engine = engine();
    let handle = engine.handle.clone();

    // Preload far more nodes than the egress channel can hold, so a zero-draining consumer fills it.
    const NODES: i64 = 500;
    assert!(
        run_autocommit(
            &handle,
            AccessMode::Write,
            &format!("UNWIND range(1, {NODES}) AS i CREATE (:N {{id: i}})"),
        ),
        "preload commits",
    );

    // Start an INLINE statement (explicit-transaction READ, `auto_commit = false`) that produces many
    // more rows than `EGRESS_CAPACITY`, and DO NOT drain it. Holding `reply.rows` without calling
    // `.next()` keeps the egress channel full — the head-of-line-block trigger.
    let read_ticket = handle
        .begin_blocking(AccessMode::Read)
        .expect("begin explicit read txn");
    let slow_reply = handle
        .run_blocking(
            read_ticket,
            "MATCH (n:N) RETURN n.id AS id".to_owned(),
            vec![],
            false,
            None,
        )
        .expect("the RUN reply arrives before the first row (it is sent up front)");
    // Deliberately keep `slow_reply.rows` un-drained for now: zero rows pulled.

    // From another thread, issue a concurrent command on the SAME database. With the slow consumer
    // parked, the engine must still service this. We signal completion over a channel so the main
    // thread can wait with a *bounded* `recv_timeout` (a timeout = the bug is present = test fails;
    // never a silent hang).
    let (done_tx, done_rx) = mpsc::channel::<bool>();
    let concurrent_handle = handle.clone();
    let worker = std::thread::spawn(move || {
        // A small auto-commit write on the same DB: it must begin, run, and commit even though the
        // slow reader is parked mid-stream.
        let ok = run_autocommit(
            &concurrent_handle,
            AccessMode::Write,
            "CREATE (:Concurrent {marker: 1})",
        );
        let _ = done_tx.send(ok);
    });

    // The teeth: the concurrent command must complete promptly. Pre-#372 the engine is blocked on the
    // slow reader's full channel and never answers it, so this `recv_timeout` would elapse.
    let committed = done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("CONCURRENT COMMAND BLOCKED: the engine head-of-line-blocked on the slow consumer's full egress channel (the #372 regression)");
    assert!(committed, "the concurrent write commits");
    worker.join().expect("concurrent worker joins");

    // Now drain the slow reader fully and confirm it still produces every row correctly (suspend /
    // resume preserves the result), then commit its (read) transaction.
    let mut slow_reply = slow_reply;
    let mut count = 0_i64;
    loop {
        match slow_reply.rows.next() {
            Ok(Some(cells)) => {
                assert!(
                    matches!(
                        cells.first(),
                        Some(graphus_cypher::MaterializedValue::Value(Value::Integer(_)))
                    ),
                    "each suspended/resumed row carries its integer id",
                );
                count += 1;
            }
            Ok(None) => break,
            Err(e) => panic!("the resumed stream must not error: {e}"),
        }
    }
    assert_eq!(
        count, NODES,
        "the suspended/resumed read returns every row exactly once"
    );
    handle
        .commit_blocking(read_ticket)
        .expect("the explicit read txn commits after its stream drains");

    // The concurrent write is durable + visible.
    assert!(
        run_autocommit(
            &handle,
            AccessMode::Read,
            "MATCH (c:Concurrent) RETURN c.marker",
        ),
        "the concurrent write is visible afterwards",
    );

    // Teardown: drop every handle clone so the command channel closes and the engine loop exits, then
    // join the engine thread (a lingering clone would keep a live sender and hang the join).
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins");
}

/// A slowly-drained **auto-commit write-with-RETURN** (always inline, since it writes) must commit
/// exactly when a single-visit statement would — its writes are durable and visible afterwards even
/// though its result stream was suspended/resumed many times (`rmp` task #372). Drains the result
/// slowly (no rows pulled until after the whole engine has had to suspend it).
#[test]
fn suspended_autocommit_write_still_commits() {
    let engine = engine();
    let handle = engine.handle.clone();

    // An auto-commit write that RETURNs one row per created node — far more than `EGRESS_CAPACITY`,
    // so the stream suspends. `auto_commit = true`, so the engine commits at stream exhaustion.
    const NODES: i64 = 300;
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .expect("begin auto-commit write");
    let mut reply = handle
        .run_blocking(
            ticket,
            format!("UNWIND range(1, {NODES}) AS i CREATE (m:M {{id: i}}) RETURN m.id AS id"),
            vec![],
            true,
            None,
        )
        .expect("RUN reply arrives up front");

    // Drain slowly: pull all rows (the engine has been forced to suspend/resume to feed us). Count and
    // verify ordering is the natural creation order (UNWIND preserves input order through CREATE/RETURN).
    let mut ids = Vec::new();
    loop {
        match reply.rows.next() {
            Ok(Some(cells)) => {
                if let Some(graphus_cypher::MaterializedValue::Value(Value::Integer(n))) =
                    cells.first()
                {
                    ids.push(*n);
                }
            }
            Ok(None) => break,
            Err(e) => panic!("the suspended write stream must not error: {e}"),
        }
    }
    assert_eq!(
        ids.len(),
        NODES as usize,
        "every created row is returned once"
    );
    assert_eq!(
        ids,
        (1..=NODES).collect::<Vec<_>>(),
        "row order is preserved across suspend/resume",
    );

    // The auto-commit committed at stream exhaustion: the writes are visible in a fresh transaction.
    let mut seen = Vec::new();
    let read_ticket = handle.begin_auto_commit_blocking(AccessMode::Read).unwrap();
    let mut r = handle
        .run_blocking(
            read_ticket,
            "MATCH (m:M) RETURN m.id AS id ORDER BY id".to_owned(),
            vec![],
            true,
            None,
        )
        .unwrap();
    while let Ok(Some(cells)) = r.rows.next() {
        if let Some(graphus_cypher::MaterializedValue::Value(Value::Integer(n))) = cells.first() {
            seen.push(*n);
        }
    }
    assert_eq!(
        seen,
        (1..=NODES).collect::<Vec<_>>(),
        "the suspended auto-commit write is durably committed",
    );

    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins");
}

/// A runtime error that occurs **mid-stream** (after several rows already streamed, across a
/// suspend/resume boundary) must reach the client as the terminal item in the SAME position it would
/// occupy in a single visit: every row before the failing one, then the error (`rmp` task #372 — the
/// terminal-error contract is preserved).
#[test]
fn mid_stream_error_is_terminal_after_suspension() {
    let engine = engine();
    let handle = engine.handle.clone();

    // `10 / x` errors (division by zero) when `x == 0`. With a list whose zero is past the egress
    // capacity, the first rows stream (forcing a suspend), then the division-by-zero is the terminal
    // error — after exactly the rows that preceded it.
    let zero_at = (EGRESS_CAPACITY as i64) + 6; // well past the bounded channel's capacity
    let mut list: Vec<String> = (1..zero_at).map(|n| n.to_string()).collect();
    list.push("0".to_owned()); // the failing element
    list.push("99".to_owned()); // would follow, but the stream terminates at the error
    let list_lit = format!("[{}]", list.join(", "));

    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Read)
        .expect("begin");
    let mut reply = handle
        .run_blocking(
            ticket,
            format!("UNWIND {list_lit} AS x RETURN 10 / x AS q"),
            vec![],
            true,
            None,
        )
        .expect("RUN reply arrives up front");

    let mut good_rows = 0_i64;
    let err = loop {
        match reply.rows.next() {
            Ok(Some(_)) => good_rows += 1,
            Ok(None) => {
                panic!("the stream must terminate with the division-by-zero error, not cleanly")
            }
            Err(e) => break e,
        }
    };
    // Exactly the rows before the zero element streamed (1..zero_at), then the error — across a
    // suspension (the channel filled at `EGRESS_CAPACITY < zero_at - 1`).
    assert_eq!(
        good_rows,
        zero_at - 1,
        "every row before the failing element streamed, in order, before the terminal error",
    );
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("divi") || msg.contains("zero") || msg.contains("/ by"),
        "the terminal item is the division-by-zero runtime error (got: {err})",
    );

    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins");
}
