//! **The client's Bolt `tx_timeout` is honoured, and clamped downward only** (`rmp` task #909).
//!
//! Before #909 the field had *zero* references repo-wide: `crates/graphus-bolt/src/server.rs` picked
//! `mode` and `db` out of a `BEGIN` / `RUN` `extra` map and discarded everything else. A client that
//! self-limited to one second silently got the server's whole per-statement budget (two minutes by
//! default) — an availability lever a tenant believed it had and did not.
//!
//! These gates drive the **real threaded engine** — the same `spawn_engine_with_timeout` the database
//! catalog starts, with a real reader pool — and assert the contract *by observing the deadline
//! actually fire*, not by checking that a field was parsed and stored:
//!
//! 1. [`a_client_budget_below_the_server_bound_is_honoured`] — a statement that would run for minutes
//!    under the server's own (generous) budget is aborted in about the *client's* second instead. The
//!    elapsed time is asserted against a ceiling far below the server's bound, so the gate can only
//!    pass if the client's figure was the one in force.
//! 2. [`a_client_budget_above_the_server_bound_does_not_raise_it`] — the mirror image: a client asking
//!    for an hour, against a server configured for a fraction of a second, is still aborted promptly.
//!    This is the security-relevant direction — `tx_timeout` must never be a one-field escape from the
//!    CPU-exhaustion defence of `rmp` #476.
//! 3. [`a_legitimate_statement_under_a_generous_client_budget_is_untouched`] — the control that stops
//!    (1) and (2) passing for the wrong reason (e.g. everything failing).
//!
//! The paired **transaction-scoped** half of the contract — `tx_timeout` on `BEGIN` bounding the whole
//! transaction, including a `COMMIT` that arrives too late — is asserted in
//! `bolt_seam_tx_timeout_909.rs` over the real Bolt seam, which is where the transaction deadline
//! lives.

use std::sync::Arc;
use std::time::{Duration, Instant};

use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine_with_timeout};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// The client's own budget in the "honoured" direction. Short enough that the assertion below can
/// separate it from the server's bound by more than an order of magnitude.
const CLIENT_SHORT: Duration = Duration::from_millis(500);

/// The server's per-statement bound in the "honoured" direction — deliberately far longer than
/// `CLIENT_SHORT`, so a gate that passed by accidentally applying the *server's* budget would have to
/// wait this long and would blow the ceiling below.
const SERVER_GENEROUS: Duration = Duration::from_secs(120);

/// The server's per-statement bound in the "cannot be raised" direction.
const SERVER_SHORT: Duration = Duration::from_millis(500);

/// The client's budget in the "cannot be raised" direction: an hour, which the server must ignore.
const CLIENT_LONG: Duration = Duration::from_secs(3_600);

/// The wall-clock ceiling a prompt abort must land inside. Generous against CI noise (60× the budgets
/// above), yet **far** below `SERVER_GENEROUS` / `CLIENT_LONG`, which is what makes the assertions
/// discriminating: whichever budget was NOT meant to apply would overshoot this by orders of magnitude.
const PROMPT_CEILING: Duration = Duration::from_secs(30);

/// A 3-way cartesian product over the seeded `:N` set — `n^3` intermediate rows. At 400 nodes that is
/// 64 million rows, far beyond any budget here, so the executor's per-row safe point trips whichever
/// deadline is in force long before the statement could finish on its own.
const CARTESIAN_BOMB: &str = "MATCH (a:N), (b:N), (c:N) RETURN count(*) AS n";

/// Spawns a threaded engine whose configured per-statement timeout is `statement_timeout` — the
/// operator's bound, the one a client must never be able to lengthen.
fn engine_with_timeout(statement_timeout: Option<Duration>) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine_with_timeout::<MemBlockDevice, MemLogSink, _>(
        Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            Ok(graphus_cypher::TxnCoordinator::new(RecordStore::create(
                device, wal, 8_192, 1,
            )?))
        },
        4096,
        256,
        // Two reader workers, so an auto-commit read genuinely dispatches off-thread and the deadline
        // is exercised on the `ReadTask` path as well as the inline one.
        2,
        // One engine worker (`rmp` #1033).
        1,
        metrics,
        clock,
        statement_timeout,
        None, // no max-transaction-age cap: this file exercises the per-statement budget
        None, // no egress-stall ceiling: it has its own gate
        Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn threaded engine")
}

/// Seeds `n` `:N` nodes in one committed auto-commit statement (cheap — well under any budget here).
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
            None,
        )
        .expect("seed run");
    while let Ok(Some(_)) = reply.rows.next() {}
}

/// Runs an auto-commit read to completion under a **caller-supplied** budget — the value a Bolt
/// `tx_timeout` becomes by the time it reaches the engine. Returns `Err(())` if the statement failed at
/// any stage, which is exactly how a connection observes a cancelled statement.
fn run_with_budget(handle: &EngineHandle, stmt: &str, budget: Option<Duration>) -> Result<(), ()> {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Read)
        .map_err(|_| ())?;
    let mut reply = handle
        .run_blocking(ticket, stmt.to_owned(), vec![], true, None, budget)
        .map_err(|_| ())?;
    loop {
        match reply.rows.next() {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(()),
            Err(_) => return Err(()),
        }
    }
}

fn shutdown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        joins,
    } = engine;
    drop(handle);
    drop(inner);
    for join in joins {
        join.join().expect("engine worker joins cleanly");
    }
}

#[test]
fn a_client_budget_below_the_server_bound_is_honoured() {
    // Server: two minutes. Client: a fraction of that. The bomb must die on the CLIENT's figure.
    let eng = engine_with_timeout(Some(SERVER_GENEROUS));
    let handle = eng.handle.clone();
    seed_nodes(&handle, 400);

    // The same bomb is run under TWO different client budgets, and the abort time is bounded from
    // BOTH sides in each case. That is what makes the gate discriminating rather than merely "a
    // statement failed":
    //
    // * the LOWER bound (`elapsed >= budget`) proves the statement genuinely ran for the time the
    //   client asked for — so it was not aborted by something else, and the bomb does not simply
    //   finish on its own inside the budget;
    // * the UPPER bound proves the abort tracked the client's figure rather than the server's
    //   `SERVER_GENEROUS`, which is orders of magnitude away;
    // * using two DIFFERENT budgets proves the honoured value is the client's actual number and not a
    //   constant that happens to sit near one of them.
    for budget in [CLIENT_SHORT, Duration::from_secs(5)] {
        let started = Instant::now();
        let bomb = run_with_budget(&handle, CARTESIAN_BOMB, Some(budget));
        let elapsed = started.elapsed();
        assert!(
            bomb.is_err(),
            "the client's tx_timeout of {budget:?} must abort the statement"
        );
        assert!(
            elapsed >= budget,
            "the statement must run for the budget the client asked for ({budget:?}), not be cut \
             short: it ended after {elapsed:?}"
        );
        assert!(
            elapsed < budget + PROMPT_CEILING,
            "the CLIENT's {budget:?} budget must be the one in force, not the server's \
             {SERVER_GENEROUS:?}; the abort took {elapsed:?}"
        );
    }

    // The engine keeps serving: a cancelled statement is a clean statement error, not engine death.
    assert!(
        run_with_budget(&handle, "MATCH (n:N) RETURN count(n) AS c", None).is_ok(),
        "the engine must keep serving after a client-budgeted statement was timed out"
    );
    shutdown(eng, handle);
}

#[test]
fn a_client_budget_above_the_server_bound_does_not_raise_it() {
    // Server: half a second. Client: an hour. The server's bound must win — this is the direction that
    // makes `tx_timeout` safe to expose at all.
    let eng = engine_with_timeout(Some(SERVER_SHORT));
    let handle = eng.handle.clone();
    seed_nodes(&handle, 400);

    let started = Instant::now();
    let bomb = run_with_budget(&handle, CARTESIAN_BOMB, Some(CLIENT_LONG));
    let elapsed = started.elapsed();
    assert!(
        bomb.is_err(),
        "the server's statement timeout must still abort the statement"
    );
    assert!(
        elapsed < PROMPT_CEILING,
        "a client asking for {CLIENT_LONG:?} must not lift the server's {SERVER_SHORT:?} bound; \
         the abort took {elapsed:?}"
    );

    assert!(
        run_with_budget(&handle, "MATCH (n:N) RETURN count(n) AS c", None).is_ok(),
        "the engine must keep serving"
    );
    shutdown(eng, handle);
}

#[test]
fn a_legitimate_statement_under_a_generous_client_budget_is_untouched() {
    // The control for both gates above: a client budget that is genuinely generous does not cancel
    // anything. Without this, a bug that cancelled EVERY budgeted statement would satisfy them both.
    let eng = engine_with_timeout(Some(SERVER_GENEROUS));
    let handle = eng.handle.clone();
    seed_nodes(&handle, 400);

    assert!(
        run_with_budget(
            &handle,
            "MATCH (n:N) RETURN count(n) AS c",
            Some(Duration::from_secs(60))
        )
        .is_ok(),
        "a generous client budget must not cancel a legitimate statement"
    );
    // And an absurd one (what a hand-rolled client sending `tx_timeout: i64::MAX` normalises to) must
    // neither cancel nor panic: the deadline arithmetic is `checked_add`, and the server's own bound
    // still applies on top.
    assert!(
        run_with_budget(
            &handle,
            "MATCH (n:N) RETURN count(n) AS c",
            Some(Duration::from_millis(i64::MAX.unsigned_abs()))
        )
        .is_ok(),
        "an absurd client budget must degrade harmlessly, not panic or cancel"
    );
    shutdown(eng, handle);
}
