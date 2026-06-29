//! **D4 re-audit (`rmp` #485): end-to-end enforcement of the maximum-transaction-age cap (`rmp` #477).**
//!
//! The existing `max_transaction_age_tests` in `engine/mod.rs` call [`maybe_reap_aged`] directly with an
//! injected clock — a precise *unit* test of the reap decision. They do **not** prove the cap actually
//! reaps through the **real threaded engine** (the command channel, the engine loop's wake-driven tick,
//! the coordinator's `begin_at`/`aged_transactions`/`rollback` wiring). This file closes that gap by
//! driving the production engine over an in-memory store, with a **shared, manually-advanced clock**
//! (`SharedClock`) so the age sweep is fully deterministic — no wall-clock, no flakiness.
//!
//! The headline DoS the cap defends against (CWE-400, "idle-in-transaction blocks vacuum"): a client
//! holds an explicit `BEGIN` open — *even one it keeps active by periodically touching it* so the
//! inactivity timeout never fires — pinning the MVCC GC low-water mark forever, so dead versions can
//! never be reclaimed and the store/RAM grow without bound with other transactions' write rate. The age
//! cap measures `now − begin` (NOT `now − last-touch`), so activity cannot evade it.
//!
//! These tests PROVE, through the real engine:
//!
//! 1. an **actively-touched** explicit transaction is reaped once over-age (activity does not evade);
//! 2. a **silently-held** explicit transaction is reaped purely by **co-tenant write traffic** waking the
//!    engine loop (the wake-driven reaper design — write traffic is exactly what makes the GC pin costly);
//! 3. a **young** explicit transaction is **not** reaped (no false-positive); and
//! 4. a **disabled** cap (`None`) never reaps, even an ancient transaction (the opt-out).
//!
//! In every reap case the reaped transaction's next use surfaces a clean `Err` (exactly how a client
//! observes it), and the engine's open-transaction gauge returns to zero (the watermark-pinning holder
//! is gone, so reclamation can resume).

use std::sync::Arc;
use std::time::Duration;

use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, TxTicket, spawn_engine_with_timeout};
use graphus_server::metrics::Metrics;
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// Nanoseconds per millisecond (the clock's unit is nanoseconds).
const MS: u64 = 1_000_000;

/// The age cap under test: deliberately tiny so the test drives the clock past it in a few `set`s.
const AGE_CAP: Duration = Duration::from_millis(300);

/// Spawns the **real threaded engine** over an in-memory store with a `max_transaction_age` cap and a
/// shared, manually-advanced clock. Returns the engine and a clone of its metrics (to read the
/// open-transaction gauge). The statement timeout is left `None` so only the age cap is exercised.
fn engine_with_age_cap(clock: &SharedClock, max_age: Option<Duration>) -> (Engine, Arc<Metrics>) {
    let metrics = Arc::new(Metrics::new());
    // The engine holds its own clone of the SharedClock (a cheap `Arc<AtomicU64>` clone); the test's
    // `clock.set(..)` is therefore visible to the engine thread immediately.
    let engine_clock: Arc<dyn Clock + Send + Sync> = Arc::new(clock.clone());
    let eng = spawn_engine_with_timeout::<MemBlockDevice, MemLogSink, _>(
        Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 8_192, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        256,
        // Two reader workers, matching the production auto-size shape (auto-commit reads can dispatch
        // off-thread). Explicit-transaction reads still run inline.
        2,
        Arc::clone(&metrics),
        engine_clock,
        None,
        max_age,
    )
    .expect("spawn threaded engine");
    (eng, metrics)
}

/// Runs an **auto-commit WRITE** to completion. A write always runs inline on the engine thread (never
/// dispatched off-thread), so each call is a deterministic command → loop iteration → the reaper runs at
/// the top of the *next* iteration. Used both to commit data and as a "wake + barrier" for the reaper.
fn run_auto_write(handle: &EngineHandle, stmt: &str) -> Result<(), ()> {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .map_err(|_| ())?;
    let mut reply = handle
        .run_blocking(ticket, stmt.to_owned(), vec![], true, None)
        .map_err(|_| ())?;
    loop {
        match reply.rows.next() {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(()),
            Err(_) => return Err(()),
        }
    }
}

/// Runs a trivial read inside the **explicit** transaction `ticket` and drains it. `Ok(())` means the
/// transaction is alive and usable; `Err(())` means it failed (e.g. it was reaped — the engine replies
/// with a clean "unknown transaction" error). Does NOT commit/rollback — the transaction stays open.
fn touch_explicit(handle: &EngineHandle, ticket: TxTicket) -> Result<(), ()> {
    let mut reply = handle
        .run_blocking(ticket, "RETURN 1 AS one".to_owned(), vec![], false, None)
        .map_err(|_| ())?;
    loop {
        match reply.rows.next() {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(()),
            Err(_) => return Err(()),
        }
    }
}

/// Drives several inline writes so the engine loop completes multiple iterations (each iteration runs the
/// reaper at its top). Two full `run_auto_write`s ≈ four engine commands, guaranteeing at least one reaper
/// pass at the *current* clock value before this returns.
fn pump(handle: &EngineHandle, tag: &str) {
    run_auto_write(handle, &format!("CREATE (:Pump {{tag: '{tag}-a'}})")).expect("pump write a");
    run_auto_write(handle, &format!("CREATE (:Pump {{tag: '{tag}-b'}})")).expect("pump write b");
}

fn shutdown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins cleanly");
}

/// GATE 1 — the keep-alive evasion fails: an explicit transaction that a client keeps **active** by
/// touching it (so the inactivity timeout never fires) is STILL reaped once its *lifetime* exceeds the
/// age cap. This is the precise DoS the inactivity timeout alone could not bound (`rmp` #477).
#[test]
fn age_cap_reaps_actively_touched_explicit_txn() {
    let clock = SharedClock::new(0);
    let (eng, metrics) = engine_with_age_cap(&clock, Some(AGE_CAP));
    let handle = eng.handle.clone();

    run_auto_write(&handle, "CREATE (:N {v: 0})").expect("seed");

    // Open an explicit READ transaction at t=0 (begin_nanos = 0).
    let held = handle
        .begin_blocking(AccessMode::Read)
        .expect("begin explicit read");

    // Keep it ACTIVE while time advances but stays UNDER the cap: it must survive every touch.
    clock.set(100 * MS);
    assert!(
        touch_explicit(&handle, held).is_ok(),
        "young txn usable @100ms"
    );
    pump(&handle, "under-cap"); // a reaper pass runs at t=100ms — must NOT reap
    clock.set(250 * MS);
    assert!(
        touch_explicit(&handle, held).is_ok(),
        "actively-touched txn still under the cap @250ms is usable"
    );
    pump(&handle, "still-under-cap");
    assert!(
        touch_explicit(&handle, held).is_ok(),
        "the touches keep it active but it is still within its age budget"
    );

    // Push the clock PAST the age cap. The transaction has been continuously touched (never idle), so an
    // inactivity timeout would never fire — but the age cap is measured from `begin`, so it MUST reap.
    clock.set(400 * MS);
    pump(&handle, "over-cap-wake"); // co-tenant write traffic wakes the loop → the reaper reaps `held`

    // THE GATE: the actively-touched, over-age transaction was reaped — its next use fails cleanly.
    assert!(
        touch_explicit(&handle, held).is_err(),
        "an over-age explicit transaction MUST be reaped regardless of activity (rmp #477)"
    );

    // The watermark-pinning holder is gone, so the open-transaction gauge is back to zero.
    pump(&handle, "settle");
    assert_eq!(
        metrics.active_txns(),
        0,
        "after the reap (and the auto-commit writes settling) no transaction is open"
    );

    shutdown(eng, handle);
}

/// GATE 2 — the realistic "open and walk away" holder: an explicit read transaction that is NEVER touched
/// again is reaped **purely by co-tenant write traffic** once over-age. This proves the wake-driven reaper
/// design: the reaper runs at the top of every engine tick, and write traffic — the very thing that makes
/// a pinned GC watermark *costly* (it is what accumulates dead versions) — is what wakes the loop.
#[test]
fn age_cap_reaps_silently_held_txn_under_cotenant_writes() {
    let clock = SharedClock::new(0);
    let (eng, metrics) = engine_with_age_cap(&clock, Some(AGE_CAP));
    let handle = eng.handle.clone();

    run_auto_write(&handle, "CREATE (:N {v: 0})").expect("seed");

    // A held read transaction the client opens and walks away from — never touched again.
    let held = handle
        .begin_blocking(AccessMode::Read)
        .expect("begin held read");

    // Co-tenant write churn UNDER the cap: the held transaction survives (not yet over-age). No touch on
    // `held` at all — only OTHER traffic.
    clock.set(150 * MS);
    for i in 0..4 {
        run_auto_write(&handle, &format!("CREATE (:Churn {{i: {i}}})")).expect("under-cap churn");
    }
    assert!(
        touch_explicit(&handle, held).is_ok(),
        "the silently-held read txn is still within its age budget"
    );

    // Push past the cap, then drive MORE co-tenant writes — with NO touch on `held`. This traffic alone
    // must wake the reaper and reclaim the over-age holder.
    clock.set(400 * MS);
    for i in 4..8 {
        run_auto_write(&handle, &format!("CREATE (:Churn {{i: {i}}})")).expect("over-cap churn");
    }

    // THE GATE: the silently-held, over-age transaction was reaped by co-tenant write traffic.
    assert!(
        touch_explicit(&handle, held).is_err(),
        "a silently-held over-age read txn is reaped by co-tenant write traffic alone (rmp #477)"
    );
    pump(&handle, "settle");
    assert_eq!(
        metrics.active_txns(),
        0,
        "the GC-watermark-pinning holder is gone — the open-transaction gauge is zero"
    );

    shutdown(eng, handle);
}

/// GATE 3 — no false-positive: a **young** explicit transaction (well within its age budget) is never
/// reaped, even under heavy co-tenant write traffic that drives many reaper passes.
#[test]
fn age_cap_does_not_reap_young_txn() {
    let clock = SharedClock::new(0);
    let (eng, _metrics) = engine_with_age_cap(&clock, Some(AGE_CAP));
    let handle = eng.handle.clone();

    run_auto_write(&handle, "CREATE (:N {v: 0})").expect("seed");
    let young = handle
        .begin_blocking(AccessMode::Read)
        .expect("begin young read");

    // Advance only to 250ms (under the 300ms cap) and drive a lot of write traffic (many reaper passes).
    clock.set(250 * MS);
    for i in 0..16 {
        run_auto_write(&handle, &format!("CREATE (:Churn {{i: {i}}})")).expect("churn");
    }

    assert!(
        touch_explicit(&handle, young).is_ok(),
        "a young (under-cap) explicit transaction must NOT be reaped (no false-positive)"
    );

    let _ = handle.rollback_blocking(young);
    shutdown(eng, handle);
}

/// GATE 4 — the opt-out: a disabled cap (`max_transaction_age = None`) never reaps, even a transaction
/// whose lifetime is an hour past begin, under heavy write traffic (the prior unbounded behaviour).
#[test]
fn disabled_age_cap_never_reaps_even_ancient_txn() {
    let clock = SharedClock::new(0);
    let (eng, _metrics) = engine_with_age_cap(&clock, None); // disabled
    let handle = eng.handle.clone();

    run_auto_write(&handle, "CREATE (:N {v: 0})").expect("seed");
    let ancient = handle
        .begin_blocking(AccessMode::Read)
        .expect("begin ancient read");

    // One hour later — far past any cap — with write traffic to drive reaper passes.
    clock.set(3_600_000 * MS);
    for i in 0..8 {
        run_auto_write(&handle, &format!("CREATE (:Churn {{i: {i}}})")).expect("churn");
    }

    assert!(
        touch_explicit(&handle, ancient).is_ok(),
        "with the cap disabled (None) even an hour-old transaction is never reaped (rmp #477 opt-out)"
    );

    let _ = handle.rollback_blocking(ancient);
    shutdown(eng, handle);
}
