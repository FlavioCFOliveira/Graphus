//! **Several statements in flight in ONE transaction, against the real threaded engine**
//! (`rmp` task #907).
//!
//! The Bolt server keeps an ordered collection of open result streams inside an explicit transaction,
//! because the Bolt server-state specification requires it (`TX_STREAMING --RUN--> TX_STREAMING`,
//! Table 6; "TX_READY **or TX_STREAMING if there are other streams open**", Tables 7 and 8) and the
//! official drivers depend on it. That protocol-level change rests on an **engine-level premise**
//! which this suite refuses to take on trust:
//!
//! 1. two statements can be in flight on the **same `TxTicket`** at the same time — one parked on a
//!    full egress channel, the other freshly submitted — and the second one is served rather than
//!    head-of-line-blocked behind the first;
//! 2. each stream yields **its own** records, and resuming the parked one continues exactly where it
//!    left off;
//! 3. the transaction's finalization bookkeeping is still correct: `COMMIT` makes the writes of
//!    *every* statement durable, `ROLLBACK` discards them, and neither leaks the transaction.
//!
//! The tests drive [`EngineHandle`] directly — the layer where the premise actually lives — with a
//! deliberately tiny `result_buffer_capacity`, so a result of a few dozen rows genuinely fills the
//! bounded channel and genuinely parks. Every test bounds its own wall clock: a regression that
//! head-of-line-blocks or deadlocks the engine thread FAILS the test through a watchdog instead of
//! hanging the suite.
//!
//! ## The engine-thread stall this suite also pins (`rmp` #907, found while implementing it)
//!
//! A statement's **terminal error** used to be handed to the consumer with the *blocking*
//! `RowSender::send`. When the bounded egress channel was exactly full at the moment the cursor
//! errored — which happens whenever the row that filled the channel was the last one the batch could
//! send — that call parked the **engine thread**, the single thread serving the whole database, until
//! somebody drained that one channel. A consumer that has paused between pages will not. The last
//! test below reproduces it deterministically and proves the engine now parks the *statement* instead
//! of the *thread*.

use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_cypher::MaterializedValue;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, TxTicket, spawn_engine_with_timeout};
use graphus_server::metrics::Metrics;
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// The bounded result-egress capacity used throughout. Deliberately tiny so a result of a few dozen
/// rows fills it and the statement is genuinely **parked** — the state in which a second statement on
/// the same ticket used to have nowhere to go.
const EGRESS: usize = 8;

/// Rows seeded for the "large" first result: several times [`EGRESS`], so the first statement cannot
/// possibly finish inside its first visit.
const SEED: i64 = 60;

/// Wall-clock budget for a whole scenario. Generous for a loaded CI box, yet finite — the failure mode
/// being guarded against is an unbounded wedge, so any finite ceiling exposes it.
const WATCHDOG: Duration = Duration::from_secs(30);

/// Spawns a threaded engine over an in-memory store with the tiny egress capacity these tests need.
fn engine() -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(Metrics::new());
    spawn_engine_with_timeout::<MemBlockDevice, MemLogSink, _>(
        Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 8_192, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        EGRESS,
        // Two reader workers, so the off-thread read path is available. An explicit-transaction
        // statement never uses it (only auto-commit reads are dispatched off-thread), which is
        // precisely why these in-transaction statements exercise the parked inline path.
        2,
        Arc::clone(&metrics),
        clock,
        // No statement timeout and no transaction-age cap: the point is to prove the engine keeps
        // serving, never that a timeout eventually rescues it.
        None,
        None,
        None,
        Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn threaded engine")
}

/// Drops every handle and joins the engine thread, so a wedged engine also fails the teardown.
fn stop(engine: Engine) {
    let Engine { handle, join } = engine;
    drop(handle);
    join.join().expect("engine thread joins cleanly");
}

/// Runs `body` on a worker thread under [`WATCHDOG`]. A body that wedges — the exact regression these
/// tests guard — fails with `what` instead of hanging the suite for ever.
fn under_watchdog<T: Send + 'static>(what: &str, body: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::sync_channel::<T>(1);
    let worker = std::thread::spawn(move || {
        let out = body();
        // A closed receiver means the watchdog already fired; nothing to report.
        let _ = tx.send(out);
    });
    match rx.recv_timeout(WATCHDOG) {
        Ok(out) => {
            worker.join().expect("worker thread");
            out
        }
        Err(_) => panic!(
            "{what}: the engine did not respond within {WATCHDOG:?} — it is wedged (the worker \
             thread is deliberately leaked so the panic is reported rather than masked by a join)"
        ),
    }
}

/// Seeds `SEED` `:Big` nodes numbered 1..=SEED in one committed auto-commit statement.
fn seed(handle: &EngineHandle) {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .expect("begin seed");
    let mut reply = handle
        .run_blocking(
            ticket,
            format!("UNWIND range(1, {SEED}) AS i CREATE (:Big {{i: i}})"),
            vec![],
            true,
            None,
            None,
        )
        .expect("seed run");
    while reply.rows.next().expect("seed rows").is_some() {}
}

/// The integer in a single-column row.
fn int_of(row: &[MaterializedValue], what: &str) -> i64 {
    match row {
        [MaterializedValue::Value(Value::Integer(n))] => *n,
        other => panic!("{what}: expected a single integer cell, got {other:?}"),
    }
}

/// Counts the `:Marker` nodes with the given `k`, in a fresh auto-commit read.
fn markers(handle: &EngineHandle, k: i64) -> i64 {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Read)
        .expect("begin read");
    let mut reply = handle
        .run_blocking(
            ticket,
            "MATCH (m:Marker) WHERE m.k = $k RETURN count(m) AS c".to_owned(),
            vec![("k".to_owned(), Value::Integer(k))],
            true,
            None,
            None,
        )
        .expect("marker read");
    let row = reply
        .rows
        .next()
        .expect("marker rows")
        .expect("one count row");
    int_of(&row, "marker count")
}

#[test]
fn two_statements_are_in_flight_on_one_ticket_and_commit_keeps_both_their_effects() {
    // THE PREMISE, verified rather than assumed. Inside ONE explicit transaction:
    //   * statement A is a read far larger than the egress channel, of which exactly one row is
    //     consumed — so A is left PARKED with a full channel;
    //   * statement B is then submitted ON THE SAME TICKET while A is parked. If the engine could
    //     not hold two statements in flight per transaction, this call would fail or wedge;
    //   * statement C writes, in the same transaction, while A is STILL parked;
    //   * A is then drained and must yield exactly its remaining rows, in order, from where it
    //     stopped — proving the parked cursor resumed coherently rather than restarting or skipping;
    //   * COMMIT must make C's write durable and leave no transaction behind.
    let engine = engine();
    let handle = engine.handle.clone();
    seed(&handle);

    let observed = under_watchdog("second statement on the same ticket", move || {
        let ticket: TxTicket = handle.begin_blocking(AccessMode::Write).expect("BEGIN");

        // A: the large result. `run_blocking` returns as soon as the engine has sent the reply
        // (before the first row), so the engine keeps filling A's bounded channel behind us.
        let mut a = handle
            .run_blocking(
                ticket,
                "MATCH (n:Big) RETURN n.i AS i ORDER BY i".to_owned(),
                vec![],
                false,
                None,
                None,
            )
            .expect("RUN A");
        let first = a.rows.next().expect("A rows").expect("A has rows");
        assert_eq!(int_of(&first, "A row 1"), 1);

        // B: a second statement on the SAME ticket while A is parked. This is the call that proves
        // the premise; before the multi-stream work nothing in the Bolt layer could ever issue it.
        let mut b = handle
            .run_blocking(
                ticket,
                "RETURN 1 AS one".to_owned(),
                vec![],
                false,
                None,
                None,
            )
            .expect("RUN B on the same ticket while A is parked");
        let b_row = b.rows.next().expect("B rows").expect("B has a row");
        assert_eq!(int_of(&b_row, "B row"), 1, "B must yield ITS own record");
        assert!(b.rows.next().expect("B end").is_none(), "B has one row");

        // C: a WRITE in the same transaction, still with A parked.
        let mut c = handle
            .run_blocking(
                ticket,
                "CREATE (:Marker {k: 1})".to_owned(),
                vec![],
                false,
                None,
                None,
            )
            .expect("RUN C on the same ticket while A is parked");
        while c.rows.next().expect("C rows").is_some() {}

        // Now drain A: it must continue from row 2 through row SEED, in order.
        let mut rest = Vec::new();
        while let Some(row) = a.rows.next().expect("A rows") {
            rest.push(int_of(&row, "A row"));
        }

        let summary = handle.commit_blocking(ticket).expect("COMMIT");
        (rest, summary)
    });

    let (rest, _summary) = observed;
    let expected: Vec<i64> = (2..=SEED).collect();
    assert_eq!(
        rest, expected,
        "the parked statement must resume exactly where it stopped and yield every remaining row \
         in order — not restart, not skip, not interleave the other statements' rows"
    );

    // Commit bookkeeping: the write issued while another statement was in flight is durable.
    assert_eq!(
        markers(&engine.handle, 1),
        1,
        "COMMIT must publish the write made while another statement was in flight on the ticket"
    );
    stop(engine);
}

#[test]
fn rollback_with_two_statements_in_flight_discards_every_effect() {
    // The mirror of the commit case: with one statement parked and another having written, ROLLBACK
    // must discard BOTH statements' effects and leave no transaction behind.
    let engine = engine();
    let handle = engine.handle.clone();
    seed(&handle);

    under_watchdog("rollback with two statements in flight", move || {
        let ticket = handle.begin_blocking(AccessMode::Write).expect("BEGIN");
        let mut a = handle
            .run_blocking(
                ticket,
                "MATCH (n:Big) RETURN n.i AS i ORDER BY i".to_owned(),
                vec![],
                false,
                None,
                None,
            )
            .expect("RUN A");
        assert!(a.rows.next().expect("A rows").is_some());

        let mut c = handle
            .run_blocking(
                ticket,
                "CREATE (:Marker {k: 2})".to_owned(),
                vec![],
                false,
                None,
                None,
            )
            .expect("RUN C while A is parked");
        while c.rows.next().expect("C rows").is_some() {}

        // Abandon A mid-stream, exactly as a Bolt RESET drops every open stream, then roll back.
        drop(a);
        handle.rollback_blocking(ticket).expect("ROLLBACK");
    });

    assert_eq!(
        markers(&engine.handle, 2),
        0,
        "ROLLBACK must discard the write made while another statement was in flight"
    );
    // The engine is still serving, so nothing was wedged by dropping a parked stream.
    assert_eq!(markers(&engine.handle, 1), 0);
    stop(engine);
}

#[test]
fn a_terminal_error_on_a_full_egress_channel_does_not_stall_the_engine_thread() {
    // Deterministic reproduction of the engine-thread stall found while implementing `rmp` #907.
    //
    // A statement's terminal error used to be handed to the consumer with the *blocking*
    // `RowSender::send`. The statement below produces EXACTLY `EGRESS` rows and then raises a runtime
    // error, so its first visit fills the bounded egress channel to capacity with those rows and
    // reaches the error with the channel exactly full. The blocking `send` then parked the **engine
    // thread** — the one thread serving this whole database — until somebody drained that channel.
    // Nothing ever does: this test's thread does not drain, it submits the next statement, and that
    // statement was never dispatched. The engine must instead park the *statement* (holding its
    // terminal error) and keep serving; the error is delivered, in its correct terminal position,
    // once the consumer makes room.
    //
    // It must be an **explicit-transaction** statement. An auto-commit read is dispatched to the
    // off-thread reader pool (`rmp` #336/#543), which has its own backpressure path and its own
    // egress-stall ceiling; only the INLINE path — every explicit-transaction statement, and every
    // write — runs on the engine thread and can stall it. That is also what makes this hazard easy to
    // reach now that one transaction may keep several streams open: the client blocks in its next
    // `RUN` while the earlier result is parked, so it cannot drain and cannot be unblocked.
    let engine = engine();
    let handle = engine.handle.clone();

    let (rows, err_text) = under_watchdog("terminal error on a full egress channel", move || {
        let ticket = handle.begin_blocking(AccessMode::Write).expect("BEGIN");
        let stalled = handle
            .run_blocking(
                ticket,
                format!(
                    "UNWIND range(1, {}) AS i RETURN 1 / (i - {}) AS x",
                    EGRESS + 1,
                    EGRESS + 1
                ),
                vec![],
                false,
                None,
                None,
            )
            .expect("RUN the stalled statement");

        // Give the engine time to finish that first visit and reach the error with a full channel,
        // so the probe below is a genuine test of "is the engine thread still free?" rather than a
        // race the engine happens to win.
        std::thread::sleep(Duration::from_millis(250));

        // Deliberately do NOT drain it. Ask the engine for another statement on the SAME ticket
        // instead: if the engine thread is blocked inside the terminal `send`, this never returns and
        // the watchdog fires.
        let mut other = handle
            .run_blocking(
                ticket,
                "RETURN 7 AS seven".to_owned(),
                vec![],
                false,
                None,
                None,
            )
            .expect("the engine must still serve other statements");
        let row = other
            .rows
            .next()
            .expect("other rows")
            .expect("other has a row");
        assert_eq!(int_of(&row, "the unrelated statement"), 7);

        // Only now drain the stalled statement: its rows must be intact and the error must arrive as
        // the LAST item, never dropped (a dropped terminal error is a silent truncation of a failed
        // result) and never re-ordered ahead of the rows it followed.
        let mut stalled = stalled;
        let mut rows = Vec::new();
        let err_text = loop {
            match stalled.rows.next() {
                Ok(Some(row)) => rows.push(int_of(&row, "stalled row")),
                Ok(None) => break None,
                Err(e) => break Some(e.to_string()),
            }
        };
        handle.rollback_blocking(ticket).expect("ROLLBACK");
        (rows, err_text)
    });

    assert_eq!(
        rows.len(),
        EGRESS,
        "every row produced before the error must survive: {rows:?}"
    );
    assert!(
        err_text.is_some(),
        "the terminal error must still reach the consumer — dropping it would report a truncated \
         failed result as a clean end of stream"
    );
    stop(engine);
}
