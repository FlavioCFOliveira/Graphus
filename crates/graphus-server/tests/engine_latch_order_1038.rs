//! **`rmp` #1038 — the rank-5 rules are enforced, on the real statement path.**
//!
//! Two properties, one per test, and both are positive controls: each one *causes* a violation and
//! requires the engine to refuse it loudly.
//!
//! 1. **Never held across statement execution.** Every execution call site in the engine loop used to
//!    hand its latch guards to the callee in argument position, where a Rust temporary lives to the end
//!    of the enclosing statement — so the guard spanned the whole query. That produces correct results
//!    and serialised workers, which is the one combination no correctness test can detect. The first
//!    test enters a rank-5 region and then drives a real statement through the real engine, which must
//!    panic rather than execute.
//!
//! 2. **At most one holder per thread.** The engine's age sweep took *open → parked* while its resume
//!    and park paths took *parked → open*. Harmless while each worker owned its own pair; a deadlock
//!    with no log line the moment `rmp` #1041 shares them. Both tables now sit at rank 5, which admits
//!    one holder, so the inversion is a single-threaded panic at the second acquisition.
//!
//! The engine driven here is [`LocalEngine`], the deterministic inline driver: it dispatches on the
//! **calling** thread, so the thread-local rank-5 depth this test manipulates is the same one the
//! engine's own code consults. Against a threaded engine the statement would run on a worker thread
//! whose depth is zero and the test would prove nothing — an instance of the trap this whole task is
//! about, and the reason the driver choice is stated rather than assumed.

use std::sync::Arc;

use graphus_core::capability::Clock;
use graphus_core::latch::EngineLatchScope;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{LocalEngine, RunReply};

struct ZeroClock;
impl Clock for ZeroClock {
    fn now_nanos(&self) -> u64 {
        0
    }
}

fn engine() -> LocalEngine<graphus_io::MemBlockDevice, graphus_wal::MemLogSink> {
    LocalEngine::in_memory(Arc::new(ZeroClock), 64).expect("in-memory engine")
}

/// Runs `query` inside the already-open explicit transaction `ticket` and drains its rows, returning
/// how many came back.
///
/// The transaction is opened by the CALLER, deliberately: `BEGIN` takes the open-transaction table for
/// its insert, so a test that held its rank-5 scope across the `BEGIN` would trip the re-entrancy
/// assertion there and never reach the statement path at all. Splitting them is what makes the scope
/// span exactly the thing under test.
///
/// An explicit transaction rather than auto-commit, because only auto-commit **reads** dispatch to the
/// reader pool (`exec::handle_run`); an explicit-transaction statement executes inline on this thread,
/// which is the path whose call site used to hand the guards over.
fn run_and_drain(
    engine: &mut LocalEngine<graphus_io::MemBlockDevice, graphus_wal::MemLogSink>,
    ticket: graphus_server::engine::TxTicket,
    query: &str,
) -> graphus_core::error::Result<usize> {
    let mut reply: RunReply = engine.run(ticket, query, Vec::new(), false, None)?;
    let mut rows = 0usize;
    while let Some(_row) = reply.rows.next()? {
        rows += 1;
    }
    Ok(rows)
}

/// The statement path must refuse to start while an engine session latch is held.
///
/// **Non-vacuity.** Deleting `assert_no_engine_latch_held("run_statement_isolated")` from
/// `engine::run_statement_isolated` makes this test fail: the query runs to completion and returns its
/// row. Verified by doing exactly that.
///
/// The assertion deliberately sits OUTSIDE the statement-panic boundary (`rmp` #386), so this panics
/// out of `run` rather than arriving as a terminal statement error. A latch-discipline violation is an
/// engine bug, not a fault in one client's query, and must not be laundered into one client's error.
///
/// The expected message is the **site name**, and that precision is load-bearing rather than
/// cosmetic. Matching on "engine session latch" made this test pass with the tripwire deleted: the
/// statement path went on to take `open` for its ticket lookup, that second rank-5 acquisition tripped
/// the *re-entrancy* assertion, and its message contains the same words. Two controls guard this shape,
/// and a test that accepts either proves neither. `run_statement_isolated` appears only in the
/// tripwire's own message, so this test now fails when — and only when — the tripwire is gone.
#[test]
#[should_panic(expected = "run_statement_isolated: reached while holding")]
fn a_statement_refuses_to_run_under_an_engine_latch() {
    let mut engine = engine();
    // Prove the fixture executes this statement when the rule is respected, so a failure below cannot
    // be a broken query, a broken engine, or a typo in the Cypher.
    let warmup = engine.begin(AccessMode::Read).expect("baseline BEGIN");
    let rows = run_and_drain(&mut engine, warmup, "RETURN 1 AS one").expect("baseline runs");
    assert_eq!(rows, 1, "baseline statement returns its row");
    engine.commit(warmup).expect("baseline COMMIT");

    // Open the transaction BEFORE entering the region — see `run_and_drain`.
    let ticket = engine
        .begin(AccessMode::Read)
        .expect("BEGIN outside the latched region");
    let _held = EngineLatchScope::new();
    let _ = run_and_drain(&mut engine, ticket, "RETURN 1 AS one");
}

/// Rank 5 admits one holder per thread, so the engine's historical *open ↔ parked* inversion cannot be
/// written any more — in either order.
///
/// **Non-vacuity.** Deleting the `ENGINE_DEPTH` assertion in `graphus_core::latch::EngineLatchScope`
/// makes this test fail: both scopes are created and nothing objects. Verified by doing exactly that.
#[test]
#[should_panic(expected = "Rank 5 is not re-entrant")]
fn two_engine_latches_on_one_thread_are_refused() {
    let _open = EngineLatchScope::new();
    let _parked = EngineLatchScope::new();
}

/// The complement, and the reason the rule is "one at a time" rather than "never": consulting one table
/// after another is exactly what the restructured age sweep, resume and park paths do, and it must stay
/// legal. Without this the assertion above could be strengthened into something that outlaws the fix.
#[test]
fn engine_latches_taken_one_after_another_are_fine() {
    for _ in 0..4 {
        let _s = EngineLatchScope::new();
    }
    assert_eq!(graphus_core::latch::engine_latch_depth(), 0);
    let mut engine = engine();
    let ticket = engine.begin(AccessMode::Read).expect("BEGIN");
    let rows = run_and_drain(&mut engine, ticket, "RETURN 1 AS one")
        .expect("a statement runs once every latch has been released");
    assert_eq!(rows, 1);
    engine.commit(ticket).expect("COMMIT");
}
