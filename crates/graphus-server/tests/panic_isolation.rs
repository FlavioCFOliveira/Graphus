//! **Engine panic-isolation regression gates** (`rmp` task #386 — the reliability mandate: the server
//! must operate without failure under extreme load).
//!
//! Before #386 there was *zero* `catch_unwind` on any production execution path. Every query for a
//! database funnels through one engine thread; a panic in the executor / materializer / UDF, in
//! `rayon` morsel / GDS work (`rayon` re-raises a worker panic on the calling engine thread), or in a
//! reader-pool worker would unwind that thread, drop the command `Receiver`, and leave every
//! connection to that database getting `engine_gone` **forever** (the default database has no
//! auto-restart).
//!
//! These tests drive a deliberately-panicking statement (the `cfg(test)`-only `ext.panic(n)` UDF,
//! registered into the real extension registry so the panic is reachable on the production
//! compile → bind → execute path) through the **real threaded engine** and assert the engine survives:
//!
//! * [`engine_survives_inline_statement_panic`] — gate (a): an inline statement panic fails cleanly
//!   and a second unrelated statement on a fresh ticket still succeeds.
//! * [`engine_survives_morsel_worker_panic`] — gate (b): a morsel-eligible aggregate whose per-row
//!   work panics for one row (a `rayon`-propagated worker panic re-raised on the engine thread) fails
//!   cleanly and a subsequent query succeeds — proving the **engine boundary** catches the morsel
//!   panic, so no separate morsel boundary is needed.
//! * [`read_pool_survives_read_task_panic`] — gate (c): a panicking read task in the reader pool fails
//!   cleanly, the pool still services reads at full width afterward, and `readers_inflight` returns to
//!   zero (no leaked reader txn/ticket pinning the GC watermark).
//!
//! Gated on the opt-in `internal-test-udf` feature (which registers the `ext.panic` UDF into the
//! engine): run with `cargo test -p graphus-server --features internal-test-udf --test
//! panic_isolation`. OFF by default so the production server never exposes a panicking function.
#![cfg(feature = "internal-test-udf")]

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// Serialises the tests in this binary. They share **process-global** mutable state — the morsel knobs
/// (`set_morsel_*`) and the `rmp` #409 recovery-fault-injection static (`arm_recovery_fault`) — so they
/// must not run concurrently or one test's global mutation would corrupt another's. cargo runs tests in
/// one binary on multiple threads by default; each test takes this lock first to run serially. Returns a
/// guard held for the test's duration; poisoning is irrelevant (a failed test already reports its own
/// assertion), so a poisoned lock is recovered into.
fn test_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Spawns a threaded engine with `reader_threads` reader workers over an in-memory store sized to keep
/// the small test working set RAM-resident.
fn engine(reader_threads: usize) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 4_096, 1)?;
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

/// Runs an auto-commit statement to completion, returning `Ok(first_scalar)` if it committed cleanly,
/// or `Err` if the statement failed at any stage (a `Run` error, a terminal stream error, or a
/// dropped channel). This is exactly how a connection observes a statement, so a panicked statement
/// surfacing here as `Err` is the "clean terminal error" the consumer sees.
fn run_collect(handle: &EngineHandle, mode: AccessMode, stmt: &str) -> Result<Option<i64>, ()> {
    let ticket = handle.begin_auto_commit_blocking(mode).map_err(|_| ())?;
    let mut reply = handle
        .run_blocking(ticket, stmt.to_owned(), vec![], true, None)
        .map_err(|_| ())?;
    let mut first: Option<i64> = None;
    loop {
        match reply.rows.next() {
            Ok(Some(cells)) => {
                if first.is_none() {
                    if let Some(graphus_cypher::MaterializedValue::Value(Value::Integer(n))) =
                        cells.first()
                    {
                        first = Some(*n);
                    }
                }
            }
            Ok(None) => return Ok(first),
            // A terminal stream error (e.g. the panic-boundary's internal-error item, or the rolled-back
            // auto-commit): the statement failed cleanly. The engine is still alive.
            Err(_) => return Err(()),
        }
    }
}

/// Tears the engine down by dropping every command-channel handle, then joining the thread. A clean
/// join here is itself part of the assertion: the engine thread must still be alive (looping) at
/// teardown — a panic that had unwound it would have made it exit early, but the join would still
/// succeed, so each test independently asserts liveness via a *successful follow-up statement* first.
fn shutdown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins cleanly");
}

/// Suppresses the test panic's default hook so the deliberate `ext.panic` does not spam the test log
/// with a backtrace. Restored when the returned guard drops. Scoped per-test so a *real* unexpected
/// panic elsewhere still prints.
type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static>;

struct SilencePanicHook(Option<PanicHook>);

impl SilencePanicHook {
    fn install() -> Self {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_info| {}));
        // `take_hook` returns the previous hook; stash it to restore on drop.
        Self(Some(prev))
    }
}

impl Drop for SilencePanicHook {
    fn drop(&mut self) {
        // `set_hook` aborts if called from a panicking thread (e.g. a failed test assertion is
        // unwinding through this drop). In that case leave the silencing hook in place — the harness
        // already has the assertion message; restoring would itself abort and mask the real failure.
        if std::thread::panicking() {
            return;
        }
        if let Some(prev) = self.0.take() {
            std::panic::set_hook(prev);
        }
    }
}

/// Runs an auto-commit statement and returns the engine's *reply-stage* error message (the error
/// delivered through the `Run` reply channel before any row), if the statement failed before streaming.
/// Distinguishes a clean engine-served error (e.g. the `rmp` #409 engine-degraded error) from a dead
/// engine (`engine_gone`) — both surface here as an `Err`, but with different messages, so the caller
/// can assert *which* failure occurred (a hang would instead block this call forever, which the test
/// harness's overall timeout catches).
fn run_reply_err(handle: &EngineHandle, mode: AccessMode, stmt: &str) -> Result<(), String> {
    let ticket = handle
        .begin_auto_commit_blocking(mode)
        .map_err(|e| e.to_string())?;
    handle
        .run_blocking(ticket, stmt.to_owned(), vec![], true, None)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Gate (`rmp` #409): a statement panics **and** its recovering rollback *also* panics (a recovery
/// double-panic). The recovery boundary must NOT unwind the single engine thread; instead it flags the
/// engine degraded, keeps the loop alive, and serves every subsequent request a clean engine-degraded
/// error — never a hang, never `engine_gone` from a dead thread.
///
/// Mechanism: `ext.panic` makes the statement panic on the engine thread (caught by
/// `run_statement_isolated`'s `catch_unwind`); the `arm_recovery_fault(1)` seam makes the *recovery
/// rollback* that follows panic too, exercising the second, deeper panic boundary (`catch_recovery`).
#[test]
fn engine_survives_recovery_double_panic() {
    let _guard = test_guard();
    let _silence = SilencePanicHook::install();
    let eng = engine(0); // a single reader worker exists, but the WRITE below runs inline on the engine
    let handle = eng.handle.clone();

    // Seed a node so the panicking RETURN has a row, and prove the engine is healthy first.
    assert!(
        run_collect(&handle, AccessMode::Write, "CREATE (:Probe {v: 1})").is_ok(),
        "seed statement commits on a healthy engine"
    );
    assert!(
        !handle.metrics().is_engine_degraded(),
        "engine starts healthy (not degraded)"
    );

    // Arm the recovery fault so the rollback that recovers the next statement panic ALSO panics.
    graphus_server::engine::arm_recovery_fault(1);

    // A WRITE auto-commit panics (so it runs INLINE on the engine thread — a Read auto-commit would
    // dispatch off-thread to the reader pool; writes never do). The statement panic is caught by the
    // statement boundary (`run_statement_isolated`), and its recovery rollback then panics, caught by
    // the recovery boundary (`catch_recovery`). `run_collect` returning *at all* (not blocking forever)
    // is the first liveness signal: the engine thread did not die mid-recovery leaving the consumer hung.
    let _ = run_collect(
        &handle,
        AccessMode::Write,
        "MATCH (p:Probe) SET p.v = ext.panic(p.v) RETURN p.v",
    );

    // THE KEY ASSERTION: the engine thread SURVIVED. A later request returns a clean engine-degraded
    // error — NOT a hang (this call would block forever on a dead thread's dropped reply) and NOT
    // `engine_gone` (the `Transaction`-class "engine unavailable" a dead thread's dropped channel
    // produces). The distinct `Runtime`-class "engine degraded" message proves the loop is alive and is
    // gating requests. This request is ALSO strictly ordered after the engine finished the recovery
    // (the single engine thread processes one command at a time), so it doubly proves recovery completed.
    let after = run_reply_err(&handle, AccessMode::Read, "MATCH (p:Probe) RETURN count(p)");
    let msg = after.expect_err("a degraded engine must refuse further work with a clean error");
    assert!(
        msg.contains("engine degraded"),
        "the follow-up request must get the clean engine-degraded error (rmp #409), got: {msg}"
    );
    assert!(
        !msg.contains("engine unavailable"),
        "must NOT be `engine_gone` — that would mean the engine thread died, got: {msg}"
    );

    // The recovery boundary fired exactly once and flagged the engine degraded (drives /health/ready to
    // 503). Checked after the ordered follow-up above, so the recovery is guaranteed complete.
    assert_eq!(
        handle.metrics().engine_recovery_panics(),
        1,
        "the recovery (double-panic) boundary must have caught exactly one recovery panic"
    );
    assert!(
        handle.metrics().is_engine_degraded(),
        "a recovery double-panic must flag the aggregate degraded gauge (observability)"
    );
    // `rmp` #414: the GATING flag is now PER-ENGINE (on the handle), not on the shared `Metrics`. This
    // is what confines the engine-degraded refusal to THIS database (the multi-DB isolation gate in
    // `multi_database.rs` proves a sibling database stays serviceable when only this one is degraded).
    assert!(
        handle.is_degraded(),
        "a recovery double-panic must flag THIS engine's own degraded flag (rmp #414, per-engine gate)"
    );

    // `Status` / `Shutdown` are still honoured on a degraded engine (it must remain probeable/drainable
    // for a controlled restart) — proven by the clean teardown below, which sends `Shutdown` and joins
    // the still-alive engine thread without hanging.
    shutdown(eng, handle);
}

/// Gate (a): an **inline** statement panic (a scalar UDF panic on the engine thread) is converted to a
/// clean terminal error and the engine keeps serving — a second, unrelated statement on a fresh ticket
/// still succeeds.
#[test]
fn engine_survives_inline_statement_panic() {
    let _guard = test_guard();
    let _silence = SilencePanicHook::install();
    let eng = engine(2);
    let handle = eng.handle.clone();

    // Seed one node so the panicking RETURN has a row to evaluate over (inline, single-row path).
    assert!(
        run_collect(&handle, AccessMode::Write, "CREATE (:Probe {v: 1})").is_ok(),
        "seed statement commits"
    );

    // The deliberately-panicking statement: `ext.panic(1)` panics inside the executor on the engine
    // thread. The boundary must convert it to a clean statement failure (Err here), not engine death.
    let panicked = run_collect(
        &handle,
        AccessMode::Read,
        "MATCH (p:Probe) RETURN ext.panic(p.v)",
    );
    assert!(
        panicked.is_err(),
        "the panicking statement must fail cleanly (terminal error), not hang or succeed"
    );

    // The engine recorded exactly one caught statement panic (the boundary fired) — not a corpse.
    assert_eq!(
        handle.metrics().statement_panics(),
        1,
        "the per-statement panic boundary must have caught exactly one panic"
    );

    // THE KEY ASSERTION: a second, unrelated statement on a fresh ticket still succeeds — proving the
    // engine loop survived the panic (was not left dropping the command Receiver / returning
    // engine_gone forever).
    let after = run_collect(&handle, AccessMode::Read, "MATCH (p:Probe) RETURN count(p)");
    assert_eq!(
        after,
        Ok(Some(1)),
        "a fresh statement after the panic must succeed — the engine survived"
    );

    shutdown(eng, handle);
}

/// Gate (b): a morsel-tier-shaped aggregate whose per-row work panics for one row, with the morsel
/// tier **enabled and its cardinality gate wide open**, must still fail cleanly and leave the engine
/// serving.
///
/// ## Why this proves the rayon/morsel path is covered (and no separate morsel boundary is needed)
///
/// `rayon::ThreadPool::install` re-raises a worker panic **on the calling thread** — which, in
/// production, is the engine thread that `run_statement_isolated` wraps in `catch_unwind`. So a panic
/// on a morsel/GDS rayon worker is caught by the **same engine boundary**, with no separate morsel
/// boundary required. That re-raise property is proven directly and in isolation by the `graphus-cypher`
/// unit test `morsel::tests::analytics_pool_worker_panic_reraises_on_calling_thread`.
///
/// This end-to-end gate complements that: it drives a panicking per-row aggregate through the real
/// engine with the morsel tier active (`set_morsel_min_rows(0)`, `set_morsel_threads(4)`) and asserts
/// the boundary catches it and the engine survives. (The morsel *purity gate*,
/// `is_pure_per_row_expr`, deliberately rejects any function-call argument, so this particular
/// `ext.panic`-bearing aggregate evaluates serially on the engine thread rather than fanning out — but
/// the panic still traverses the aggregate/materializer machinery the morsel path shares, and the
/// engine boundary catches it identically. The pure-rayon-worker re-raise is the cypher unit test's
/// job.)
#[test]
fn engine_survives_morsel_worker_panic() {
    use graphus_cypher::morsel::{set_morsel_min_rows, set_morsel_threads};

    let _guard = test_guard();
    let _silence = SilencePanicHook::install();

    // Enable the morsel tier and open its cardinality gate so the parallel machinery is live for this
    // statement. Restored at the end so sibling tests in this binary see the defaults.
    set_morsel_threads(4);
    set_morsel_min_rows(0);

    let eng = engine(0); // inline reads → the aggregate runs on the engine thread, exercising its boundary
    let handle = eng.handle.clone();

    // A handful of :M nodes so the aggregate has rows to evaluate over.
    for i in 0..16 {
        assert!(
            run_collect(
                &handle,
                AccessMode::Write,
                &format!("CREATE (:M {{v: {i}}})"),
            )
            .is_ok(),
            "seed :M node commits"
        );
    }

    // A per-row aggregate whose per-row work (`ext.panic`) panics. The per-statement boundary converts
    // it to a clean failure regardless of whether it ran serially or fanned out.
    let panicked = run_collect(
        &handle,
        AccessMode::Read,
        "MATCH (m:M) RETURN sum(ext.panic(m.v))",
    );
    assert!(
        panicked.is_err(),
        "the panicking aggregate must fail cleanly with the morsel tier active, not kill the engine"
    );
    assert_eq!(
        handle.metrics().statement_panics(),
        1,
        "the engine boundary must have caught the per-row panic with the morsel tier active"
    );

    // THE KEY ASSERTION: a subsequent query on the engine still succeeds.
    let after = run_collect(&handle, AccessMode::Read, "MATCH (m:M) RETURN count(m)");
    assert_eq!(
        after,
        Ok(Some(16)),
        "a fresh statement after the panic must succeed — the engine survived"
    );

    set_morsel_min_rows(u64::MAX);
    set_morsel_threads(1);
    shutdown(eng, handle);
}

/// Gate (c): a panicking **read task** in the reader pool. The worker's panic boundary retires it as a
/// rollback (so the engine decrements `readers_inflight` and frees the reader's txn/ticket) and keeps
/// the worker alive. Afterwards the pool still services reads at full width, and `active_txns` (the
/// open-transaction gauge the engine publishes) returns to zero — proving no reader txn leaked to pin
/// the GC watermark.
#[test]
fn read_pool_survives_read_task_panic() {
    let _guard = test_guard();
    let _silence = SilencePanicHook::install();
    // A multi-worker pool so a read genuinely dispatches off-thread (auto-commit Reads run on the pool).
    let eng = engine(4);
    let handle = eng.handle.clone();

    assert!(
        run_collect(&handle, AccessMode::Write, "CREATE (:R {v: 7})").is_ok(),
        "seed :R node commits"
    );

    // Drive several panicking reads through the pool (each dispatches to a worker, panics, and must
    // retire as a rollback without killing the worker). Running more than there are workers proves the
    // workers stay alive across panics (a dead worker would shrink the pool and eventually stall).
    for _ in 0..12 {
        let panicked = run_collect(
            &handle,
            AccessMode::Read,
            "MATCH (r:R) RETURN ext.panic(r.v)",
        );
        assert!(
            panicked.is_err(),
            "each panicking read task must fail cleanly (terminal error)"
        );
    }

    // THE KEY ASSERTION: the pool still services reads at full width — a normal read on every worker
    // succeeds, so no worker died.
    for _ in 0..8 {
        let after = run_collect(&handle, AccessMode::Read, "MATCH (r:R) RETURN count(r)");
        assert_eq!(
            after,
            Ok(Some(1)),
            "the reader pool must still service reads after the panics — no worker died"
        );
    }

    // No leaked reader transaction: the open-transaction gauge (republished by the engine after every
    // reader retirement) returns to zero once the panicked readers' rollbacks are processed. Poll
    // briefly because retirement processing is asynchronous to the client reply. A *successful* read
    // above already forces the engine to drain pending retirements, so this normally observes 0 at once.
    let mut active = handle.metrics().active_txns();
    for _ in 0..200 {
        if active == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
        // Nudge the engine to process any straggler retirement by issuing a trivial read.
        let _ = run_collect(&handle, AccessMode::Read, "MATCH (r:R) RETURN count(r)");
        active = handle.metrics().active_txns();
    }
    assert_eq!(
        active, 0,
        "every panicked reader's transaction must be rolled back + de-registered — no leaked txn \
         pinning the GC watermark (readers_inflight back to 0)"
    );

    // The boundary fired once per panicking read.
    assert_eq!(
        handle.metrics().statement_panics(),
        12,
        "the reader-pool panic boundary must have caught one panic per panicking read"
    );

    shutdown(eng, handle);
}
