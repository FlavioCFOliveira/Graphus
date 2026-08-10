//! **`rmp` #589 (sprint-52 Finding E-1) — production-stack safety of the query-clause budget.**
//!
//! E-1 has two coupled stack-overflow vectors, both an uncatchable process `abort()`: (1) value
//! nesting depth, and (2) the Volcano executor recursing one stack frame per operator level, so a long
//! `WITH … WITH … ` chain descends as many frames as there are clauses. The fix caps the parsed clause
//! count at `MAX_QUERY_CLAUSES` — but that cap is only *safe* if a query AT the cap actually EXECUTES
//! without overflowing the **production engine stack** (`QUERY_ENGINE_STACK_SIZE`), not merely
//! the (larger) TCK-harness stack. This test proves it empirically on the real threaded engine (whose
//! engine thread and reader-pool workers both run on that stack): a chain AT the cap runs to a
//! clean result, one PAST the cap is a recoverable compile error, and — the load-bearing assertion —
//! neither aborts the process (the test binary itself survives to make the follow-up assertions).

use std::sync::Arc;

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, TxTicket, spawn_engine};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

fn threaded_engine() -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        std::sync::Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 4096, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        1024,
        256,
        2,
        metrics,
        clock,
        std::sync::Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn threaded engine")
}

fn teardown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        joins,
    } = engine;
    drop(handle);
    drop(inner);
    for join in joins {
        join.join().expect("engine worker joins");
    }
}

/// Runs `stmt` auto-commit through the engine; returns `(ok, first_int)`. `ok=false` on a recoverable
/// error (the connection survives). A process abort would instead kill this test binary outright.
fn run(handle: &EngineHandle, stmt: &str) -> (bool, Option<i64>) {
    let Ok(ticket): Result<TxTicket, _> = handle.begin_auto_commit_blocking(AccessMode::Read)
    else {
        return (false, None);
    };
    match handle.run_blocking(ticket, stmt.to_owned(), vec![], true, None, None) {
        Ok(mut reply) => {
            let mut first = None;
            loop {
                match reply.rows.next() {
                    Ok(Some(cells)) => {
                        if first.is_none()
                            && let Some(graphus_cypher::MaterializedValue::Value(Value::Integer(n))) =
                                cells.first()
                        {
                            first = Some(*n);
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

/// Builds a linear `WITH 1 AS a` chain of `n` clauses ending in `RETURN a` — `n` nested `Project`
/// operators, so execution recurses `n` frames through the Volcano `next()` on the production engine stack.
fn with_chain(n: usize) -> String {
    let mut q = String::with_capacity(n * 12 + 16);
    for _ in 0..n {
        q.push_str("WITH 1 AS a ");
    }
    q.push_str("RETURN a");
    q
}

#[test]
fn a_clause_chain_at_the_budget_executes_on_the_production_engine_stack_without_aborting() {
    let engine = threaded_engine();
    let handle = engine.handle.clone();

    let cap = graphus_cypher::MAX_QUERY_CLAUSES;

    // AT the cap (the RETURN counts as a clause, so `cap - 1` WITHs + RETURN == cap clauses): must run
    // to a clean result on the production engine stack — proving the cap cannot admit a query that then
    // overflows and aborts the whole server.
    let (ok, v) = run(&handle, &with_chain(cap - 1));
    assert!(
        ok && v == Some(1),
        "a {cap}-clause chain must EXECUTE cleanly on the production engine stack (got ok={ok}, v={v:?}); \
         if this aborted, MAX_QUERY_CLAUSES is too high for QUERY_ENGINE_STACK_SIZE"
    );

    // PAST the cap: a recoverable compile error (TooManyClauses), never an abort.
    let (ok, _) = run(&handle, &with_chain(cap + 50));
    assert!(
        !ok,
        "a chain past MAX_QUERY_CLAUSES must be rejected as a recoverable error"
    );

    // The server survived both: a normal query still works.
    let (ok, v) = run(&handle, "RETURN 7 AS a");
    assert!(
        ok && v == Some(7),
        "the engine survived the deep-chain attempts and still serves queries"
    );

    teardown(engine, handle);
}
