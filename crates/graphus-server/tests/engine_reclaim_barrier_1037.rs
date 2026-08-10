//! **`rmp` #1037 — the slot-reuse barrier belongs to the engine, not to whichever worker fired it.**
//!
//! The `rmp` #588 barrier stops a GC pass from handing a freed physical slot back to the allocator
//! while a reader may still be walking a chain through it. Both of its inputs used to come from the
//! state of the ONE worker that happened to run the pass:
//!
//! * `readers_inflight`, its gate — so a pass on worker A saw zero and armed nothing while worker B
//!   had off-thread reads walking incidence chains through the very slots it was freeing;
//! * the ticket counter its floor is taken from — so even an ARMED barrier did not dominate a
//!   sibling's open tickets, because `rmp` #1035's per-worker counters advance only when their own
//!   worker mints, and a barrier of `1` from an untouched counter is satisfied at once by a sibling's
//!   already-open ticket `5`.
//!
//! Either one alone hands a live reader's slot to a writer. The reader then reads a stranger's record
//! and a committed edge below it disappears — silently, with nothing in the log. That is the `rmp`
//! #588 / `rmp` #811 class, and it is why these gates exist.
//!
//! # Why real threads
//!
//! The DST cannot reach this. `LocalEngine` drives everything inline on one thread, so it never
//! dispatches an off-thread reader, never arms the barrier, and has no second worker to race — the
//! same structural limit already recorded for `rmp` #588 and `rmp` #811. These gates therefore start a
//! real multi-worker engine with `spawn_engine_with_timeout` and drive it from OS threads.
//!
//! # Why the engines are built directly
//!
//! `admission.engine_workers` above one is still refused by configuration, now because the
//! multi-worker engine is not CERTIFIED (`rmp` #1034) rather than because this defect is open. The
//! gates call `spawn_engine_with_timeout`, the same door `tests/engine_shared_sessions_1041.rs` and
//! `tests/engine_latch_scaling_1038.rs` use.
//!
//! # What each gate proves, and how it was shown not to be vacuous
//!
//! 1. [`a_pass_on_one_worker_holds_the_slots_a_siblings_reader_may_walk`] — the headline. A reclaim
//!    pass driven on the worker that owns NO reader must still shadow-hold what it frees. Every step
//!    that could make it pass by accident is asserted rather than assumed: which worker owns the
//!    reader, which worker the checkpoint lands on, that the reader is still in flight when the pass
//!    runs, and that the pass actually freed something. Non-vacuity, measured: see the module test
//!    `engine::maintenance_tests::above_one_worker_the_barrier_does_not_trust_the_reader_count` for
//!    the unit-level mutation, and this file's own doc for the end-to-end one.
//! 2. [`the_hold_is_released_once_the_reader_retires`] — the complement, and the one that keeps the
//!    fix from being a leak: a barrier that is armed on every pass and never released would grow the
//!    held overlay without bound. Non-vacuity: it fails if the release floor never opens.
//!
//! # A premise that fell, recorded so it is not re-filed
//!
//! A third gate was written and then DELETED, because the defect it was written for does not exist.
//! The reading was: the idle timed receive is gated on `worker_id == 0`, so a reader dispatched by
//! worker 3 retires only when a command happens to land on worker 3 again — and until it does, its
//! transaction stays open and pins the GC watermark. The code refutes it. BOTH branches of the
//! receive are `recv_timeout(INDEX_BUILD_TICK)`; `rmp` #1033 made the non-`timed` one bounded too,
//! because a worker parked in a plain `recv` never observes `stopping` and hangs the shutdown. So
//! every worker wakes every tick and drains its own retirements at the top of the loop either way.
//!
//! Measured, not reasoned: with the tick forced back to `worker_id == 0 && (…)`, a read dispatched by
//! worker 1 and drained still had its transaction closed with no further command sent to the engine
//! (`graphus_active_transactions`: 1 right after dispatch, 0 right after the drain). The gate passed
//! under the mutation it was written to fail under, which is what a vacuous test looks like — and the
//! `timed` change it was written to justify would have been a REGRESSION, letting every worker drive
//! index builds whenever any read was in flight. What the flag actually selects is the CONTENT of the
//! timeout arm (index builds and the `rmp` #733 repair), which is correctly worker 0's.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, TxTicket, spawn_engine_with_timeout};
use graphus_server::metrics::Metrics;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

struct RealClock;
impl Clock for RealClock {
    fn now_nanos(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

struct TempDir {
    path: PathBuf,
}
impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "graphus_reclaim1037_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Builds an engine with `workers` workers over an in-memory store.
///
/// `result_buffer_capacity` is a parameter because the headline gate needs it small enough that an
/// undrained off-thread read fills its bounded egress channel and STAYS in flight — which is the state
/// the gate is about. `egress_stall_timeout` is `None` so a deliberately undrained reader is never
/// given up on: the gate wants the reader alive, not reaped.
fn engine(_dir: &Path, workers: usize, result_buffer_capacity: usize) -> (Engine, Arc<Metrics>) {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(RealClock);
    let metrics = Arc::new(Metrics::new());
    let engine = spawn_engine_with_timeout::<MemBlockDevice, MemLogSink, _>(
        Arc::from("reclaim1037"),
        move || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 4_096, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        8192,
        result_buffer_capacity,
        2,
        workers,
        Arc::clone(&metrics),
        clock,
        None,
        None,
        None,
        Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn engine");
    (engine, metrics)
}

fn shutdown(engine: Engine) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("shutdown runtime");
    rt.block_on(engine.handle.shutdown()).expect("shutdown");
    for j in engine.joins {
        j.join().expect("engine worker joins cleanly");
    }
}

/// One auto-commit statement, drained to exhaustion. Used to seed and to mutate.
fn run_auto(handle: &EngineHandle, query: &str) -> Result<usize, String> {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .map_err(|e| e.to_string())?;
    let mut reply = handle
        .run_blocking(ticket, query.to_owned(), Vec::new(), true, None, None)
        .map_err(|e| e.to_string())?;
    let mut n = 0usize;
    loop {
        match reply.rows.next() {
            Ok(Some(_)) => n += 1,
            Ok(None) => return Ok(n),
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Consumes ONE round-robin routing slot and reports which worker it went to.
///
/// `Begin` round-robins (no session exists yet, so any worker will do) and the ticket it returns
/// carries its worker back in `ticket % W`. `Rollback` routes by that ticket, so it consumes no
/// further slot. This is how these gates OBSERVE the routing of a command that carries no ticket —
/// `Checkpoint` is administrative and round-robins too — instead of assuming it.
fn probe_worker(handle: &EngineHandle, workers: usize) -> usize {
    let ticket = handle
        .begin_blocking(AccessMode::Read)
        .expect("probe begin");
    handle.rollback_blocking(ticket).expect("probe rollback");
    (ticket.0 as usize) % workers
}

/// The `graphus_held_slots` gauge (`rmp` #588/#1037) as an operator would read it: out of the rendered
/// Prometheus text, by exact metric name.
fn held_slots(metrics: &Metrics) -> u64 {
    for line in metrics.render_prometheus().lines() {
        if let Some(rest) = line.strip_prefix("graphus_held_slots ") {
            return rest
                .trim()
                .parse::<u64>()
                .expect("graphus_held_slots is an integer gauge");
        }
    }
    panic!("graphus_held_slots is not exported: the gate has no oracle");
}

/// Seeds a hub with `edges` relationships and then deletes half of them, committed — so a reclaim pass
/// has dead versions whose physical slots it can free. Returns the number of edges left alive.
fn seed_with_reclaimable_corpses(handle: &EngineHandle, edges: usize) -> usize {
    run_auto(handle, "CREATE (:Hub {name: 'hub'})").expect("create hub");
    for i in 0..edges {
        run_auto(
            handle,
            &format!("MATCH (h:Hub) CREATE (h)-[:LINK {{seq: {i}}}]->(:Leaf {{seq: {i}}})"),
        )
        .unwrap_or_else(|e| panic!("create edge {i}: {e}"));
    }
    // Delete every other edge and commit: the tombstones are then dead for every later snapshot, so a
    // GC pass can splice their corpses out and free the slots.
    run_auto(
        handle,
        "MATCH (:Hub)-[r:LINK]->() WHERE r.seq % 2 = 1 DELETE r",
    )
    .expect("delete half the edges");
    edges - edges / 2
}

/// **GATE 1 — a reclaim pass driven on one worker holds the slots a SIBLING's reader may walk.**
///
/// The scenario the defect describes, built so that no step can succeed by luck:
///
/// * the reader's worker is read off its ticket, not assumed;
/// * the checkpoint's worker is predicted from a probe and then CONFIRMED by a second probe, so a
///   change to the routing rules breaks the gate loudly instead of silently aiming it at the wrong
///   worker;
/// * the reader is proven to be still in flight — one row taken, thousands left — at the moment the
///   pass runs;
/// * the pass is proven to have frozen something, because a hold of zero is indistinguishable from a
///   pass that freed nothing at all.
///
/// **Non-vacuity, by mutation — and each control exercised where it is the ONLY one standing.** The
/// shipped code has two independent controls here, so a single mutation would leave the other one
/// holding and prove nothing. Both were run:
///
/// * With the barrier's `workers > 1` arm removed, so it trusts the reader count again, this gate
///   still PASSES — because the count is now the engine's, so the sibling's pass sees worker 0's
///   reader. That is the shared counter doing the work, alone.
/// * With the count ALSO restored to per-worker (emulated exactly, with a thread-local incremented at
///   dispatch and decremented at retirement — one engine worker is one thread), this gate FAILS:
///   `a reclaim pass on worker 1 freed 200 versions while worker 0 had a read in flight, and
///   shadow-held NOTHING`. That is the defect, reproduced.
/// * Putting `workers > 1` back while LEAVING the count per-worker, it passes again — the second
///   control closing the same hole on its own, which is what makes it defence in depth rather than a
///   duplicate.
#[test]
fn a_pass_on_one_worker_holds_the_slots_a_siblings_reader_may_walk() {
    const WORKERS: usize = 2;
    let dir = TempDir::new("sibling_hold");
    // A tiny egress buffer: the off-thread reader fills it after a couple of rows and blocks on the
    // send, so it stays in flight for as long as this thread declines to drain it.
    let (engine, metrics) = engine(&dir.path, WORKERS, 1);
    let handle = engine.handle.clone();

    let alive = seed_with_reclaimable_corpses(&handle, 400);

    // An auto-commit read, dispatched off-thread (structurally read-only + auto-commit is the `rmp`
    // #543 gate). Its ticket names the worker that owns it.
    let reader_ticket: TxTicket = handle
        .begin_auto_commit_blocking(AccessMode::Read)
        .expect("begin auto-commit read");
    let reader_worker = (reader_ticket.0 as usize) % WORKERS;
    let mut reader = handle
        .run_blocking(
            reader_ticket,
            "MATCH (:Hub)-[r:LINK]->(l:Leaf) RETURN l.seq".to_owned(),
            Vec::new(),
            true,
            None,
            None,
        )
        .expect("dispatch the streaming read");

    // Take ONE row. That proves the reader is running, and leaves it blocked on a full egress channel
    // with hundreds of rows still to deliver — so it is unambiguously in flight below.
    let first = reader.rows.next().expect("first row").expect("a row");
    assert!(!first.is_empty(), "the reader produced an empty row");

    // Aim the checkpoint at the OTHER worker, and confirm the aim.
    //
    // Administrative commands round-robin, so the worker a `Checkpoint` lands on is the slot after the
    // last round-robin command. `probe_worker` consumes one slot and reports where it went, so the
    // next slot is `(probe + 1) % W`. Rotate until that is the sibling.
    let mut probe = probe_worker(&handle, WORKERS);
    let mut rotations = 0;
    while (probe + 1) % WORKERS == reader_worker {
        probe = probe_worker(&handle, WORKERS);
        rotations += 1;
        assert!(
            rotations <= WORKERS,
            "the round-robin never reached a worker other than the reader's ({reader_worker})"
        );
    }
    let checkpoint_worker = (probe + 1) % WORKERS;
    assert_ne!(
        checkpoint_worker, reader_worker,
        "the whole point of this gate is a pass on the worker that owns NO reader"
    );

    let report = handle.checkpoint_blocking().expect("checkpoint");

    // CONFIRM the aim: the checkpoint must have consumed exactly the slot we predicted, so the next
    // probe lands on the one after it. Without this the gate would keep passing if the routing rules
    // changed and the checkpoint quietly went to the reader's own worker — where even the pre-#1037
    // code arms the barrier, and the gate would prove nothing.
    let after = probe_worker(&handle, WORKERS);
    assert_eq!(
        after,
        (checkpoint_worker + 1) % WORKERS,
        "the checkpoint did not consume the routing slot this gate aimed it at: it ran on some other \
         worker, so nothing below is a statement about a SIBLING's pass"
    );

    // THE WINDOW, proven rather than hoped for. An off-thread read's auto-commit transaction stays
    // OPEN until its retirement is processed, so a non-zero active-transaction gauge here — with every
    // probe transaction rolled back and nothing else running — says the reader was still in flight
    // while the pass ran. Without this a fast reader could finish first and the gate would be
    // measuring a pass with nothing to protect.
    assert!(
        gauge(&metrics, "graphus_active_transactions") > 0,
        "the reader retired before the pass ran: the window this gate exists to enter was never open"
    );

    // The pass must have done work, or a hold of zero would mean nothing.
    assert!(
        report.reclaimed > 0,
        "the reclaim pass freed nothing ({} versions), so this gate cannot tell a barrier that was \
         armed from one that was not — the fixture, not the engine, is what failed",
        report.reclaimed
    );

    // THE GATE. A pass on the sibling worker held what it froze, even though that worker has no reader
    // of its own and its ticket counter names none of the reader's.
    let held = held_slots(&metrics);
    assert!(
        held > 0,
        "#1037: a reclaim pass on worker {checkpoint_worker} freed {} versions while worker \
         {reader_worker} had a read in flight, and shadow-held NOTHING — the next write takes those \
         slots out from under the reader mid-walk",
        report.reclaimed
    );

    // Drain the reader and check the answer is intact: every surviving edge, exactly once.
    let mut rows = 1usize;
    while reader.rows.next().expect("stream").is_some() {
        rows += 1;
    }
    assert_eq!(
        rows, alive,
        "the in-flight reader lost or duplicated rows across the concurrent reclaim pass"
    );

    shutdown(engine);
}

/// **GATE 2 — the hold is not a leak: it opens once the readers it was taken for have retired.**
///
/// Above one worker the barrier is armed on EVERY pass, because `readers_inflight` no longer
/// characterises who may be walking a chain. That is only defensible if the hold still opens: a
/// barrier that is always armed and never released grows the held overlay without bound and stops the
/// allocator reusing anything, which is a slow-motion resource exhaustion rather than a wrong answer,
/// but not something to ship.
///
/// **Non-vacuity.** The gate is the transition, not the end state: it requires the hold to be non-zero
/// while the reader is in flight and zero after it retires. A release floor that never opened fails
/// the second half; a barrier that was never armed fails the first.
#[test]
fn the_hold_is_released_once_the_reader_retires() {
    const WORKERS: usize = 2;
    let dir = TempDir::new("release");
    let (engine, metrics) = engine(&dir.path, WORKERS, 1);
    let handle = engine.handle.clone();

    seed_with_reclaimable_corpses(&handle, 400);

    let reader_ticket = handle
        .begin_auto_commit_blocking(AccessMode::Read)
        .expect("begin auto-commit read");
    let mut reader = handle
        .run_blocking(
            reader_ticket,
            "MATCH (:Hub)-[r:LINK]->(l:Leaf) RETURN l.seq".to_owned(),
            Vec::new(),
            true,
            None,
            None,
        )
        .expect("dispatch the streaming read");
    let _first = reader.rows.next().expect("first row").expect("a row");

    let report = handle.checkpoint_blocking().expect("checkpoint");
    assert!(
        report.reclaimed > 0,
        "the fixture produced nothing to reclaim, so the hold below would be trivially empty"
    );
    let held_while_reading = held_slots(&metrics);
    assert!(
        held_while_reading > 0,
        "nothing was held while a read was in flight: gate 2 has no transition to observe"
    );

    // Retire the reader, and let its retirement reach the worker that dispatched it.
    while reader.rows.next().expect("stream").is_some() {}
    drop(reader);

    // Then reclaim again with nothing open. `oldest_open_ticket` is `u64::MAX`, which clears the
    // release floor unconditionally — this is the escape hatch that makes the hold bounded no matter
    // how the ticket sequence has advanced.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut held_after = held_while_reading;
    while Instant::now() < deadline {
        handle.checkpoint_blocking().expect("checkpoint");
        held_after = held_slots(&metrics);
        if held_after == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        held_after, 0,
        "#1037: {held_while_reading} slots were shadow-held for a reader that has since retired, and \
         the hold never opened — an armed-on-every-pass barrier without a release is a leak"
    );

    shutdown(engine);
}

/// A gauge value by exact metric name, out of the rendered Prometheus text.
fn gauge(metrics: &Metrics, name: &str) -> u64 {
    for line in metrics.render_prometheus().lines() {
        if let Some(rest) = line.strip_prefix(name) {
            let rest = rest.trim();
            if let Ok(v) = rest.parse::<u64>() {
                return v;
            }
        }
    }
    panic!("metric {name} not found in the Prometheus rendering");
}
