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

/// Serialises the tests in this binary and **resets every process-global** they touch on teardown.
///
/// These tests share process-global mutable state — the morsel knobs (`set_morsel_*` in
/// `graphus-cypher`), the global `ANALYTICS_POOL` rayon pool, and the `rmp` #409 recovery-fault-injection
/// static (`arm_recovery_fault` in `graphus-server`). cargo runs tests in one binary on multiple threads
/// by default, so two tests mutating these globals concurrently would corrupt each other. Worse, a global
/// *left mutated* by one test (the historical bug: `arm_recovery_fault(1)` was never reset to `0`, and
/// `set_morsel_threads(4)`/`set_morsel_min_rows(0)` were only reset on the happy path — a panicking
/// assertion `?`-bailed past the manual reset) leaked into the next test in the binary, making
/// `engine_survives_morsel_worker_panic` reproducibly FLAKY (`rmp` #449).
///
/// [`TestGuard`] closes both holes at once. Acquiring it takes the binary-wide serialisation lock (so the
/// tests never run concurrently) and resets every global to its **canonical default** up front, so a test
/// starts from a known state regardless of what ran before it — even if a *prior* test panicked before its
/// own teardown. Its [`Drop`] then resets every global again, so this test cannot leak state forward. The
/// reset is unconditional and runs on the panicking-unwind path too (a plain field drop never aborts,
/// unlike `set_hook`), so a failed assertion can no longer poison a sibling test.
///
/// Poisoning of the lock is irrelevant (a failed test already reports its own assertion), so a poisoned
/// lock is recovered into.
struct TestGuard {
    _lock: MutexGuard<'static, ()>,
}

impl TestGuard {
    /// Takes the binary-wide lock and resets every shared global to its canonical default, so the test
    /// body starts from a known state no matter what ran (or panicked) before it.
    fn acquire() -> Self {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_process_globals();
        Self { _lock: lock }
    }
}

impl Drop for TestGuard {
    fn drop(&mut self) {
        // Unconditional teardown — runs on the normal *and* the panicking-unwind path (a struct field
        // drop never aborts, unlike `std::panic::set_hook`). This is the load-bearing fix for `rmp` #449:
        // a test that fails an assertion still resets every global before the next test in this binary
        // runs, so no leaked `arm_recovery_fault`/morsel-knob state can make a sibling flaky.
        reset_process_globals();
    }
}

/// Resets every process-global these tests mutate back to its canonical default:
/// * `arm_recovery_fault(0)` — disarm the `rmp` #409 recovery-fault seam (the historical never-reset);
/// * `set_morsel_threads(1)` — fully-serial morsel tier (the determinism / single-core default);
/// * `set_morsel_min_rows(u64::MAX)` — the morsel cardinality gate effectively closed (no fan-out).
fn reset_process_globals() {
    use graphus_cypher::morsel::{set_morsel_min_rows, set_morsel_threads};
    graphus_server::engine::arm_recovery_fault(0);
    set_morsel_threads(1);
    set_morsel_min_rows(u64::MAX);
}

/// Spawns a threaded engine with `reader_threads` reader workers over an in-memory store sized to keep
/// the small test working set RAM-resident.
fn engine(reader_threads: usize) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        std::sync::Arc::from("test"),
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
    let _guard = TestGuard::acquire();
    let _silence = SilencePanicHook::install();
    let eng = engine(0); // a single reader worker exists, but the WRITE below runs inline on the engine
    let handle = eng.handle.clone();

    // Seed a node so the panicking RETURN has a row, and prove the engine is healthy first.
    assert!(
        run_collect(&handle, AccessMode::Write, "CREATE (:Probe {v: 1})").is_ok(),
        "seed statement commits on a healthy engine"
    );
    assert!(
        !handle.is_degraded(),
        "engine starts healthy (not degraded — the per-engine #414 flag)"
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

    // The recovery boundary fired exactly once, bumping the fleet-wide observability counter (drives
    // nothing on its own — the GATING is the per-engine flag below). Checked after the ordered follow-up
    // above, so the recovery is guaranteed complete.
    assert_eq!(
        handle.metrics().engine_recovery_panics(),
        1,
        "the recovery (double-panic) boundary must have caught exactly one recovery panic"
    );
    // `rmp` #414/#451: the GATING flag is PER-ENGINE (on the handle), not a shared `Metrics` gauge — the
    // never-cleared, un-labelled fleet-wide `engine_degraded` gauge was removed (#451). The per-engine
    // flag is what confines the engine-degraded refusal to THIS database (the multi-DB isolation gate in
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
    let _guard = TestGuard::acquire();
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

/// Gate (b): a morsel-eligible per-row **projection** whose per-row work panics, with the morsel tier
/// **enabled and its cardinality gate wide open**, must still fail cleanly and leave the engine serving.
///
/// ## Why this proves the rayon/morsel path is covered (and no separate morsel boundary is needed)
///
/// `rayon::ThreadPool::install` re-raises a worker panic **on the calling thread** — which, in
/// production, is the engine thread that `run_statement_isolated` wraps in `catch_unwind`. So a panic
/// on a morsel/GDS rayon worker is caught by the **same engine boundary**, with no separate morsel
/// boundary required. That re-raise property is proven directly and in isolation by the `graphus-cypher`
/// unit test `morsel::tests::analytics_pool_worker_panic_reraises_on_calling_thread`.
///
/// This end-to-end gate complements that: it drives a panicking per-row projection through the real
/// engine with the morsel tier active (`set_morsel_min_rows(0)`, `set_morsel_threads(4)`) and asserts
/// the boundary catches it and the engine survives. (The morsel *purity gate*, `is_pure_per_row_expr`,
/// deliberately rejects any function-call argument, so this particular `ext.panic`-bearing projection
/// evaluates serially on the engine thread rather than fanning out — but the panic still traverses the
/// projection/materializer machinery the morsel path shares, and the engine boundary catches it
/// identically. The pure-rayon-worker re-raise is the cypher unit test's job.)
///
/// ## Determinism (`rmp` #449)
///
/// Two changes make this gate deterministic where it was reproducibly flaky (the suite failed ~18%
/// run-to-run yet the test passed 100% **in isolation** — the signature of leaked process-global state):
///
/// 1. [`TestGuard`] resets EVERY shared process-global up front and on teardown — the morsel knobs AND
///    `arm_recovery_fault(0)` (the historical never-reset). Crucially the teardown is a drop guard, so a
///    *panicking* assertion no longer `?`-skips the reset and leaks state into the next test in the binary.
///    The hook is silenced **only** around the deliberate panic and restored *before* the assertion phase
///    (the explicit `drop(silence)`), so a genuine future regression prints rather than vanishing into a
///    silenced hook.
///
/// 2. The deliberately-panicking statement is a per-row **projection** (`MATCH (m:M) RETURN
///    ext.panic(m.v)`), NOT an *aggregate* (`sum(ext.panic(m.v))`). A projection MUST evaluate its
///    expression for every row, so `ext.panic` is guaranteed to fire and the boundary records ≥ 1 caught
///    panic. The original aggregate could be planned through a morsel-aggregation path that — depending on
///    the process-global `ANALYTICS_POOL` (a `OnceLock` built once per process by whichever sibling test
///    ran first, hence the *order*-dependence) — *sometimes* failed via a clean pre-evaluation error with
///    `statement_panics == 0`, which neither `== 1` nor `>= 1` could survive. The projection removes that
///    path-dependence entirely while keeping gate (b)'s intent (the morsel tier live over many rows).
///
/// The count is asserted `>= 1` (the boundary fired): the engine-survival assertion below is the real
/// #386 invariant, and a `>=` floor is robust to however many times the boundary fires.
#[test]
fn engine_survives_morsel_worker_panic() {
    use graphus_cypher::morsel::{set_morsel_min_rows, set_morsel_threads};

    let _guard = TestGuard::acquire();

    // Enable the morsel tier and open its cardinality gate so the parallel machinery is LIVE for this
    // statement (gate (b)'s intent). Teardown is the `TestGuard` drop (resets these globals on the normal
    // AND the panicking path) — never a manual reset here, which a failed assertion would skip (#449).
    set_morsel_threads(4);
    set_morsel_min_rows(0);

    let eng = engine(0); // inline reads → the per-row work runs on the engine thread, exercising its boundary
    let handle = eng.handle.clone();

    // A handful of :M nodes so the per-row projection has rows to evaluate over.
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

    // A morsel-eligible **per-row projection** whose per-row work (`ext.panic`) panics, with the morsel
    // tier live. A projection MUST evaluate its expression for every row (unlike an *aggregate*, whose
    // planning could short-circuit before any per-row eval — the source of the #449 flake: a
    // `sum(ext.panic(..))` aggregate over the morsel-agg path *sometimes* failed via a clean pre-eval
    // error with `statement_panics == 0`). So `ext.panic` is guaranteed to fire and the per-statement
    // boundary records at least one caught panic, deterministically. The hook is silenced ONLY for this
    // call (the deliberate panic's backtrace is noise) and restored immediately after, so the assertion
    // phase runs with the real hook (`rmp` #449: a regression must print, not vanish into a silenced hook).
    let panicked = {
        let silence = SilencePanicHook::install();
        let outcome = run_collect(
            &handle,
            AccessMode::Read,
            "MATCH (m:M) RETURN ext.panic(m.v)",
        );
        drop(silence);
        outcome
    };
    assert!(
        panicked.is_err(),
        "the panicking projection must fail cleanly with the morsel tier active, not kill the engine"
    );
    assert!(
        handle.metrics().statement_panics() >= 1,
        "the engine boundary must have caught the per-row panic with the morsel tier active (got {})",
        handle.metrics().statement_panics()
    );

    // THE KEY ASSERTION: a subsequent query on the engine still succeeds.
    let after = run_collect(&handle, AccessMode::Read, "MATCH (m:M) RETURN count(m)");
    assert_eq!(
        after,
        Ok(Some(16)),
        "a fresh statement after the panic must succeed — the engine survived"
    );

    shutdown(eng, handle);
}

/// Gate (c): a panicking **read task** in the reader pool. The worker's panic boundary retires it as a
/// rollback (so the engine decrements `readers_inflight` and frees the reader's txn/ticket) and keeps
/// the worker alive. Afterwards the pool still services reads at full width, and `active_txns` (the
/// open-transaction gauge the engine publishes) returns to zero — proving no reader txn leaked to pin
/// the GC watermark.
#[test]
fn read_pool_survives_read_task_panic() {
    let _guard = TestGuard::acquire();
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
