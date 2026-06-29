//! **D2 re-audit (sprint 42, task #485): two concurrent suspended inline statements collide.**
//!
//! ## The defect this file proves
//!
//! The engine thread parks **at most one** slow-consumer inline statement at a time in its single
//! `inflight: Option<InFlightInline>` slot (`rmp` #372). The suspend path asserts that invariant with a
//! *debug-only* `debug_assert!(inflight.is_none())` (see `engine/mod.rs` in `run_statement_isolated`,
//! the `RunOutcome::Suspended` arm) and then unconditionally does `*inflight = Some(*parked)`.
//!
//! That invariant is **false**. The engine loop takes a *timed* `recv_timeout` whenever
//! `inflight.is_some()` (so it can resume the parked statement each tick), which means it **keeps
//! dispatching new commands while a statement is parked**. Any second statement that also runs inline
//! and also fills its bounded egress on its first visit (a large result + a consumer that has not yet
//! drained — the common case, not just a malicious stall) returns `RunOutcome::Suspended` too. When it
//! does:
//!
//! * **debug builds** (`cargo test` default): the `debug_assert!` fires. It sits **outside** the
//!   per-statement `catch_unwind`, so it unwinds the single engine thread and bricks the database —
//!   every later request gets `engine unavailable` forever (the exact failure class `rmp` #386 set out
//!   to prevent, reached through a different door).
//! * **release builds**: the assert is compiled out; `*inflight = Some(B)` **silently overwrites** the
//!   first parked statement `A`. `A`'s `InFlightInline` is dropped, which (1) drops `A`'s `row_tx`, so
//!   `A`'s client sees a clean end-of-stream after only the rows already buffered — a **silently
//!   truncated result reported as success** (a correctness / `04 §1.3` violation) — and (2) abandons
//!   `A`'s transaction mid-statement: it is never `finalize_inflight`-d, so it is **never committed and
//!   never rolled back**, leaking an open transaction that pins the MVCC GC watermark (a memory DoS,
//!   CWE-400; and `maybe_reap_aged` excludes auto-commit txns, so the age-cap sweep never frees it).
//!
//! Reachability: both transports submit one statement per connection through `EngineHandle::run*`, so
//! two concurrent connections with large results trivially produce two concurrent inline suspensions.
//! Writes and explicit-transaction reads **always** run inline (only auto-commit reads can go
//! off-thread), so this is reachable even with the reader pool fully enabled.
//!
//! ## Why the existing suite misses it
//!
//! `slow_consumer_no_head_of_line_block.rs::slow_consumer_does_not_block_a_concurrent_command` parks
//! exactly ONE slow reader and then runs a *short* concurrent command that finishes in a single batch
//! (it never suspends), so the two-suspensions-at-once interleaving is structurally untested. This is
//! the sprint-41 lesson: defects hide in the COMBINATION the single-axis suite never crosses.
//!
//! ## What this test asserts
//!
//! Two explicit-transaction reads (always inline) over a result wider than the egress buffer are each
//! submitted and left un-drained so each suspends; then both are drained to completion. The
//! **correct** behaviour is that BOTH return their complete row set and the engine stays alive. On HEAD
//! the first one (`A`) is truncated (release) or the engine thread is dead (debug) — either way `A`
//! does not return all its rows. The test is bounded by a watchdog so a regression can never hang CI.

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

// --------------------------------------------------------------------------------------------------
// Harness
// --------------------------------------------------------------------------------------------------

/// Total rows the probe statement produces. Must be comfortably larger than `EGRESS_CAPACITY` so a
/// first visit with an un-drained consumer fills the egress buffer and suspends.
const NODES: i64 = 600;

/// The bounded per-statement egress capacity. Small so suspension is reached on the first batch with a
/// consumer that has pulled nothing yet — exactly the production "large result, client not yet
/// draining" shape.
const EGRESS_CAPACITY: usize = 8;

/// Generous hang ceiling. A healthy run finishes in well under a second; only a genuine deadlock /
/// livelock (or a wedged engine that never answers a drain) reaches this, and the watchdog then aborts
/// with a diagnostic rather than letting CI hang forever.
const BUDGET: Duration = Duration::from_secs(60);

/// Spawns a threaded engine over a fresh in-memory store with a deliberately tiny egress buffer.
fn engine() -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        Arc::<str>::from("reaudit-d2-inflight-clobber"),
        move || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            // A modest pool; the bug is about the inflight slot, not buffer-pool eviction.
            let store = RecordStore::create(device, wal, 256, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        64,              // engine command-channel capacity
        EGRESS_CAPACITY, // result_buffer_capacity — the tiny egress buffer
        2,               // reader threads (irrelevant: explicit reads always run inline)
        metrics,
        clock,
    )
    .expect("spawn threaded engine")
}

/// Seeds `NODES` `:N {id}` nodes via a single auto-commit write (no RETURN → no rows → never suspends).
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

/// Begins an EXPLICIT read transaction and runs the wide probe statement with `auto_commit = false`,
/// so it is forced down the inline path (only auto-commit reads can be dispatched off-thread). Returns
/// the open ticket and the (un-drained) reply — the caller decides when to drain.
fn start_explicit_wide_read(
    handle: &EngineHandle,
) -> (
    graphus_server::engine::TxTicket,
    graphus_server::engine::command::RunReply,
) {
    let ticket = handle
        .begin_blocking(AccessMode::Read)
        .expect("begin explicit read txn");
    let reply = handle
        .run_blocking(
            ticket,
            "MATCH (n:N) RETURN n.id AS id".to_owned(),
            vec![],
            false, // explicit txn ⇒ inline ⇒ can suspend on a full egress
            None,
        )
        .expect("the RUN reply arrives before the first row (sent up front)");
    (ticket, reply)
}

/// Drains a reply to completion on a worker thread, reporting the row count over `tx`. Each row is
/// validated as a non-torn integer. A reply whose stream errors reports a negative sentinel so the
/// caller can distinguish "errored" from "truncated".
fn drain_counting(
    mut reply: graphus_server::engine::command::RunReply,
    tx: mpsc::Sender<i64>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut count = 0_i64;
        loop {
            match reply.rows.next() {
                Ok(Some(cells)) => {
                    assert!(
                        matches!(
                            cells.first(),
                            Some(MaterializedValue::Value(Value::Integer(_)))
                        ),
                        "a resumed row must carry its integer id, never a torn value"
                    );
                    count += 1;
                }
                Ok(None) => break,
                Err(_) => {
                    let _ = tx.send(-1);
                    return;
                }
            }
        }
        let _ = tx.send(count);
    })
}

/// Arms a monitor thread that aborts the process with a diagnostic if `done` is not set within
/// [`BUDGET`] — converting a wedged-engine hang into a prompt, loud failure instead of a CI stall.
fn arm_watchdog(done: Arc<AtomicBool>) {
    std::thread::Builder::new()
        .name("reaudit-d2-clobber-watchdog".to_owned())
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
                    "\n[#485 D2 WATCHDOG] two-suspended-inline-statements probe exceeded {BUDGET:?} \
                     — the engine wedged draining a clobbered/abandoned stream (a CRITICAL liveness \
                     finding). Aborting."
                );
                std::process::abort();
            }
        })
        .expect("spawn watchdog");
}

// --------------------------------------------------------------------------------------------------
// The probe
// --------------------------------------------------------------------------------------------------

/// **D2 #485.** Two concurrent inline statements that each suspend on an un-drained consumer must both
/// still return their complete results, and the engine must stay alive. On HEAD the second suspension
/// collides with the first on the single `inflight` slot: debug builds panic the engine thread (the
/// `debug_assert!`), release builds silently clobber + truncate the first statement and leak its
/// transaction.
#[test]
fn two_concurrent_suspended_inline_statements_must_not_clobber() {
    let done = Arc::new(AtomicBool::new(false));
    arm_watchdog(Arc::clone(&done));

    let engine = engine();
    let handle = engine.handle.clone();
    let metrics = Arc::clone(handle.metrics());

    seed(&handle);

    // Statement A: submit and leave UN-DRAINED. Its first batch fills the 8-row egress buffer, so it
    // suspends and the engine parks it in `inflight`. `run_blocking` returns as soon as A's RunReply is
    // sent (before the first row), so we hold A's stream open without pulling.
    let (ticket_a, reply_a) = start_explicit_wide_read(&handle);

    // Let the engine finish A's first visit and park it before B arrives.
    std::thread::sleep(Duration::from_millis(150));

    // Statement B: also inline, also wide, also left un-drained at submit time. The engine — looping on
    // `recv_timeout` because a statement is parked — dispatches B, and B suspends too. On HEAD B's
    // suspension collided with A's single `inflight` slot; with the bounded-queue fix both coexist.
    let (ticket_b, reply_b) = start_explicit_wide_read(&handle);

    // Let the collision resolve (debug: engine panics here; release: A is overwritten).
    std::thread::sleep(Duration::from_millis(150));

    // Now drain both concurrently. A correct engine resumes each parked statement batch-by-batch as its
    // consumer pulls, so both reach `NODES`. Draining happens on worker threads, and the main thread
    // waits with a bounded `recv_timeout`, so a wedged engine fails loudly rather than hanging.
    let (tx_a, rx_a) = mpsc::channel();
    let (tx_b, rx_b) = mpsc::channel();
    let ja = drain_counting(reply_a, tx_a);
    let jb = drain_counting(reply_b, tx_b);

    let count_a = rx_a
        .recv_timeout(BUDGET)
        .expect("draining A must not hang (the watchdog also guards this)");
    let count_b = rx_b
        .recv_timeout(BUDGET)
        .expect("draining B must not hang (the watchdog also guards this)");

    let _ = ja.join();
    let _ = jb.join();
    done.store(true, Ordering::Release);

    eprintln!("[#485 D2] count_a = {count_a}, count_b = {count_b} (expected {NODES} each)");

    // The teeth. On a correct engine both statements return every row. On HEAD the first parked
    // statement (A) is the victim: truncated to ~EGRESS_CAPACITY (release) or cut off by the dead engine
    // thread (debug). Either way it does not reach NODES.
    assert_eq!(
        count_a, NODES,
        "FIRST suspended inline statement (A) returned {count_a}/{NODES} rows — it was clobbered when a \
         SECOND inline statement suspended into the same `inflight` slot (debug: engine-thread \
         debug_assert panic; release: silent overwrite + truncation). #485 D2 finding."
    );
    assert_eq!(
        count_b, NODES,
        "SECOND suspended inline statement (B) returned {count_b}/{NODES} rows — the collision also \
         damaged B (engine-thread panic in debug builds)."
    );

    // Both explicit transactions must still be COMMITTABLE after parking — proving neither was
    // clobbered/abandoned (a clobbered statement's ticket is removed from the engine's open-tx map, so
    // committing it would fail). On HEAD the first statement (A) was clobbered, so this would surface
    // the damage; with the fix both commit cleanly.
    handle
        .commit_blocking(ticket_a)
        .expect("statement A's explicit txn must still commit (it was not clobbered)");
    handle
        .commit_blocking(ticket_b)
        .expect("statement B's explicit txn commits");

    // With both transactions committed, the active-txn gauge must net back to zero — no parked
    // statement leaked its transaction into the active set (which would pin the MVCC GC watermark and
    // escape the age-cap reap). On the release-mode clobber, A's transaction was never finalized.
    let active = metrics.active_txns();
    assert_eq!(
        active, 0,
        "a parked inline transaction leaked into the active set ({active} still open after both \
         commits) — it pins the MVCC GC watermark and is excluded from the age-cap reap. #485 D2 B1."
    );

    // Best-effort teardown. If the engine thread already died (debug), the join returns Err — we do not
    // assert on it here because the row-count assertions above are the primary teeth.
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    let _ = join.join();
}
