//! **D2 re-audit (sprint 42, task #485): a panic on a RESUMED batch escapes the #386 boundary.**
//!
//! ## The defect this file proves
//!
//! The per-statement panic-isolation boundary (`rmp` #386) wraps the **first** visit of an inline
//! statement only: `run_statement_isolated` does `catch_unwind(|| handle_run(..))`. But a slow-consumer
//! statement is *suspended* on its first visit and then driven one batch per tick by the engine loop's
//! direct call to `exec::resume_inflight` (see `engine/mod.rs`, the `if let Some(parked) = inflight ...`
//! block) — and **that call has no `catch_unwind`**. `resume_inflight` → `run_batch` → `drive_batch`
//! runs the cursor (projection evaluation, UDFs, the materializer, storage decode) raw.
//!
//! So a panic on any batch **after the first** unwinds the single engine thread, drops the command
//! `Receiver`, and bricks the database — every later request to it gets `engine unavailable` forever.
//! This is the exact failure class `rmp` #386 set out to prevent, reached through the resume path the
//! boundary forgot. It manifests in **both debug and release** builds (it is a genuine panic, not a
//! `debug_assert`), so it is strictly a release-reachable engine-death DoS.
//!
//! Reachability: any statement with a result larger than the egress buffer suspends (the common large-
//! result case), and any per-row fault that triggers only on a row not in the first batch — a panicking
//! UDF, an arithmetic/`unwrap` panic on specific row data, a storage-decode panic on a later record —
//! lands on the unguarded resume path. Writes and explicit-transaction reads always run inline.
//!
//! ## Why the existing suite misses it
//!
//! `panic_isolation.rs::engine_survives_inline_statement_panic` seeds exactly ONE node and runs
//! `RETURN ext.panic(p.v)` over it, so the panic fires on the FIRST visit — inside the `handle_run`
//! `catch_unwind`. It never produces enough rows to suspend, so the resume path is structurally
//! untested. (`engine_survives_morsel_worker_panic` and `read_pool_survives_read_task_panic` likewise
//! cover first-visit / off-thread panics, not inline resume.)
//!
//! ## What this test asserts
//!
//! A wide read whose projection panics only on a late row (id = 500, via the `internal-test-udf`
//! `ext.panic`, which panics on a non-null argument) is suspended on its first batch (ids 1..8, all
//! null arguments) and then drained, driving the resume path until the late row panics. The **correct**
//! behaviour is that the panic is caught and the engine keeps serving. Two teeth:
//!   1. a FRESH, unrelated statement afterwards still succeeds (the engine survived) — on HEAD the
//!      engine thread is dead, so it returns `engine unavailable`;
//!   2. the panicked statement's own consumer observes a terminal ERROR, NOT a clean end-of-stream
//!      over its ~499-row partial result (the CWE-393 silent-truncation closure for the resume path).
//!
//! Bounded by a watchdog so a regression can never hang CI.
//!
//! Gated on `internal-test-udf` (registers `ext.panic`): run with
//! `cargo test -p graphus-server --features internal-test-udf --test reaudit_d2_resume_panic`.

#![cfg(feature = "internal-test-udf")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_cypher::MaterializedValue;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

const NODES: i64 = 600;
const PANIC_ID: i64 = 500; // a row reached only well after the first (8-row) batch suspends
const EGRESS_CAPACITY: usize = 8;
const BUDGET: Duration = Duration::from_secs(60);

/// Spawns a threaded engine with a tiny egress buffer (forces suspension) over a fresh in-memory store.
fn engine() -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        Arc::<str>::from("reaudit-d2-resume-panic"),
        move || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 256, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        64,
        EGRESS_CAPACITY,
        2,
        metrics,
        clock,
    )
    .expect("spawn threaded engine")
}

/// Seeds `NODES` `:N {id}` nodes in ascending order (so the label scan reaches `PANIC_ID` only after
/// the first batch). No RETURN ⇒ no rows ⇒ never suspends.
fn seed(handle: &EngineHandle) {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .expect("begin seed");
    let mut reply = handle
        .run_blocking(
            ticket,
            format!("UNWIND range(1, {NODES}) AS i CREATE (:N {{id: i}})"),
            vec![],
            true,
            None,
        )
        .expect("seed runs");
    while let Ok(Some(_)) = reply.rows.next() {}
}

/// Runs a small auto-commit read, returning its single integer scalar (or `None` on any failure — e.g.
/// `engine unavailable` once the engine thread has died). Used as the engine-survival probe.
fn probe_count(handle: &EngineHandle) -> Option<i64> {
    let ticket = handle.begin_auto_commit_blocking(AccessMode::Read).ok()?;
    let mut reply = handle
        .run_blocking(
            ticket,
            "MATCH (n:N) RETURN count(n) AS c".to_owned(),
            vec![],
            true,
            None,
        )
        .ok()?;
    let mut v = None;
    while let Ok(Some(cells)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::Integer(n))) = cells.first() {
            v = Some(*n);
        }
    }
    v
}

/// The process panic-hook closure type (factored out for clippy::type_complexity).
type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send + 'static>;

/// Silences the process panic hook for the duration of the deliberate engine-thread panic, restoring it
/// on drop so a genuine *unexpected* panic still prints. Scoped to this single-test binary.
struct SilencePanicHook(Option<PanicHook>);
impl SilencePanicHook {
    fn install() -> Self {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        Self(Some(prev))
    }
}
impl Drop for SilencePanicHook {
    fn drop(&mut self) {
        if let Some(prev) = self.0.take() {
            std::panic::set_hook(prev);
        }
    }
}

fn arm_watchdog(done: Arc<AtomicBool>) {
    std::thread::Builder::new()
        .name("reaudit-d2-resume-panic-watchdog".to_owned())
        .spawn(move || {
            let deadline = Instant::now() + BUDGET;
            while Instant::now() < deadline {
                if done.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            if !done.load(Ordering::Acquire) {
                eprintln!(
                    "\n[#485 D2 WATCHDOG] resume-path-panic probe exceeded {BUDGET:?} — the engine \
                     wedged (a CRITICAL liveness finding). Aborting."
                );
                std::process::abort();
            }
        })
        .expect("spawn watchdog");
}

/// **D2 #485.** A panic on a RESUMED batch of a suspended inline statement must be caught (clean
/// statement failure) and the engine must keep serving. On HEAD the resume path has no `catch_unwind`,
/// so the panic kills the engine thread and a fresh statement afterwards returns `engine unavailable`.
#[test]
fn engine_survives_panic_during_resumed_batch() {
    let done = Arc::new(AtomicBool::new(false));
    arm_watchdog(Arc::clone(&done));

    let engine = engine();
    let handle = engine.handle.clone();

    seed(&handle);

    // An EXPLICIT read (auto_commit = false ⇒ always inline, never off-thread). The projection applies
    // `ext.panic` to a value that is null for every row EXCEPT id = PANIC_ID, so it never panics on the
    // first (ids 1..8) batch — it panics only on a resumed batch when the scan reaches PANIC_ID.
    let ticket = handle
        .begin_blocking(AccessMode::Read)
        .expect("begin explicit read txn");
    let reply = handle
        .run_blocking(
            ticket,
            format!(
                "MATCH (n:N) RETURN ext.panic(CASE WHEN n.id = {PANIC_ID} THEN 1 ELSE null END) AS x"
            ),
            vec![],
            false,
            None,
        )
        .expect("the RUN reply arrives before the first row (sent up front)");

    // Let the engine fill the 8-row egress buffer and SUSPEND the statement before we pull anything, so
    // the eventual panic at id = PANIC_ID is guaranteed to land on the resume path, not the first visit.
    std::thread::sleep(Duration::from_millis(150));

    // Drain on a worker thread: each pull lets the engine resume one batch, advancing the scan toward
    // PANIC_ID. When it gets there, `drive_batch`'s `next_materialized` panics inside `resume_inflight`.
    // The drain reports how many rows it saw AND whether the stream ended with a terminal ERROR (the
    // fix) versus a clean end-of-stream (`Ok(None)` — the silent-truncation behaviour we must NOT have).
    let silence = SilencePanicHook::install();
    let (tx, rx) = mpsc::channel::<(i64, bool)>();
    let drain = {
        let mut reply = reply;
        std::thread::spawn(move || {
            let mut count = 0_i64;
            let mut saw_terminal_error = false;
            loop {
                match reply.rows.next() {
                    Ok(Some(_)) => count += 1,
                    // A clean end-of-stream: the consumer would read this as SUCCESS over a partial
                    // result (the CWE-393 silent truncation). The fix must NOT produce this.
                    Ok(None) => break,
                    // A terminal error: the consumer correctly learns the statement FAILED.
                    Err(_) => {
                        saw_terminal_error = true;
                        break;
                    }
                }
            }
            let _ = tx.send((count, saw_terminal_error));
        })
    };
    let (drained, saw_terminal_error) = rx
        .recv_timeout(BUDGET)
        .expect("draining the panicking stream must not hang (the watchdog also guards this)");
    let _ = drain.join();

    // Give the engine a beat to settle (it is either dead, on HEAD, or has cleanly recovered).
    std::thread::sleep(Duration::from_millis(100));
    drop(silence); // restore the hook before the survival probe so a real regression still prints

    // THE TEETH: a fresh, unrelated statement must still succeed — proving the engine survived the
    // resume-path panic. On HEAD the engine thread unwound and exited, so this returns None (the handle
    // gets `engine unavailable`).
    let after = probe_count(&handle);
    done.store(true, Ordering::Release);

    eprintln!(
        "[#485 D2] drained {drained} rows, saw_terminal_error = {saw_terminal_error}; post-panic \
         probe = {after:?}"
    );

    assert_eq!(
        after,
        Some(NODES),
        "a fresh statement after a panic on a RESUMED batch returned {after:?} (expected Some({NODES})) \
         — the engine thread was killed because `resume_inflight` runs outside the #386 `catch_unwind`. \
         #485 D2 finding."
    );

    // The panicked statement's consumer must observe a terminal FAILURE, not a clean end-of-stream over
    // its partial (≈499-row) result — otherwise a faulted statement is silently reported as a successful
    // truncated result (CWE-393, the same class closed for healthy statements; `rmp` #485 B2 closure).
    assert!(
        saw_terminal_error,
        "the consumer of a statement that panicked on a resumed batch saw a clean end-of-stream \
         (Ok(None)) after {drained} partial rows instead of a terminal ERROR — a silent truncation of \
         a faulted statement (CWE-393). #485 D2 B2 terminal-delivery."
    );

    // Best-effort teardown (the engine thread may already be dead on HEAD).
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    let _ = join.join();
}
