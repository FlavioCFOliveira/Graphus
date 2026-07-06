//! Regression: `rmp` #589 (sprint-52 E-1 completeness) — a single MATCH clause with a very long path
//! pattern must NOT abort the process.
//!
//! A path `()-->()-->…->()` of K hops lowers to K nested `Expand` operators. `plan_physical`,
//! `build_operator`, the Volcano `next()`, and the operator-tree `Drop` each recurse ONE native stack
//! frame per operator level — on the production `QUERY_ENGINE_STACK_SIZE` engine/reader stack. K is one
//! clause, so `MAX_QUERY_CLAUSES` (clause count) did NOT bound it, and `MAX_EXPR_DEPTH` did not (the
//! chain parses iteratively): a 4000-hop path overflowed the stack → uncatchable SIGABRT, killing the
//! whole server. The fix charges each path hop against the same whole-statement structural budget as
//! clauses, so an over-long path is a recoverable `SyntaxError` at parse time — proven here on the real
//! threaded engine (the reader-pool worker runs on the production stack; a process abort would kill
//! this test binary outright, so reaching the assertions IS the proof of survival).

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

fn run(handle: &EngineHandle, stmt: &str) -> (bool, Option<i64>) {
    let Ok(ticket): Result<TxTicket, _> = handle.begin_auto_commit_blocking(AccessMode::Read)
    else {
        return (false, None);
    };
    match handle.run_blocking(ticket, stmt.to_owned(), vec![], true, None) {
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

/// `MATCH ()-->()-->...-->() RETURN 1 AS ok` with `hops` chain links (K nested `Expand` operators).
fn long_pattern(hops: usize) -> String {
    let mut q = String::with_capacity(hops * 5 + 32);
    q.push_str("MATCH ()");
    for _ in 0..hops {
        q.push_str("-->()");
    }
    q.push_str(" RETURN 1 AS ok");
    q
}

#[test]
fn a_very_long_single_clause_path_is_rejected_not_aborted() {
    let engine = threaded_engine();
    let handle = engine.handle.clone();

    // Far past the structural budget (4000 hops overflowed the 256 MiB reader stack before the fix).
    let (ok, _) = run(&handle, &long_pattern(4000));
    assert!(
        !ok,
        "#589: an over-long path pattern must be a recoverable error, never a process abort"
    );

    // A moderate path (well below the cap) still compiles + executes cleanly — it matches nothing on an
    // empty store, so it returns zero rows (no error), which is the correct behaviour, not a rejection.
    let (ok, _) = run(&handle, &long_pattern(64));
    assert!(
        ok,
        "a moderate path must still compile and execute (not be rejected)"
    );

    // The server survived the deep-path attempt and still serves queries.
    let (ok, v) = run(&handle, "RETURN 7 AS ok");
    assert!(
        ok && v == Some(7),
        "the server survived the deep-path attempt as a live process"
    );

    teardown(engine, handle);
}
