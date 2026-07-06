//! **Off-thread reader egress-stall ceiling regression gates** (`rmp` task #591 — sprint-52 finding
//! C-F1; the reliability mandate: the server must operate without failure under extreme load and
//! concurrency).
//!
//! An auto-commit read that runs on the off-thread reader pool (`rmp` #336/#543) streams its rows into
//! a bounded egress channel. If the consumer stops draining (a TCP zero-window / slow-loris on the
//! result stream), the reader backs off in `send_row_with_backpressure` waiting for room. Before #591
//! that wait was bounded ONLY by the per-statement deadline (`rmp` #476/#551). With
//! `statement_timeout_ms = 0` (a legitimate operator choice for long-running analytics) the deadline is
//! `None`, so a stalled off-thread reader spun/parked **forever** — pinning its MVCC snapshot (the GC
//! watermark, so nothing it read was ever reclaimed → unbounded RAM + disk growth) and holding a finite
//! reader-pool slot (a few such stalls exhaust the pool = read-service DoS). The aged-transaction reaper
//! (`rmp` #477) does NOT cover this: it deliberately excludes auto-commit reads.
//!
//! #591 adds an always-on **egress-stall ceiling** (`egress_stall_timeout`), independent of the
//! per-statement timeout, that bounds a full-channel no-progress wait. These tests drive the real
//! threaded engine with `statement_timeout = None` (the C-F1 scenario the per-statement timeout cannot
//! bound) and a SHORT egress ceiling, and assert:
//!
//! * a **stalled** consumer's reader is released within the ceiling — its stream terminates, its
//!   GC-watermark pin is dropped (the server-wide `active_transactions` gauge returns to 0), the stall
//!   is counted (`egress_stall_aborts`), and the reader-pool slot is freed (a follow-up read succeeds);
//! * a **slow-but-progressing** consumer (drains continuously, just slowly) is NOT false-aborted — it
//!   receives the whole result — proving the ceiling measures time-since-progress and resets on every
//!   accepted row.
//!
//! Every test bounds its own wall-clock, so a regression (a reader wedged forever) FAILS the test via a
//! guard rather than hanging the suite.

use std::sync::Arc;
use std::time::{Duration, Instant};

use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine_with_timeout};
use graphus_server::metrics::Metrics;
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// A short, finite egress-stall ceiling: long enough that the seed + normal queries never approach it,
/// short enough that a stalled reader is reclaimed quickly so the test is fast.
const SHORT_EGRESS_CEILING: Duration = Duration::from_millis(400);

/// A wall-clock ceiling for "prompt release": the stalled reader must be reclaimed comfortably inside
/// this (many times `SHORT_EGRESS_CEILING`, generous for CI noise, yet nowhere near the unbounded
/// wedge the reader would have without the fix).
const PROMPT_CEILING: Duration = Duration::from_secs(20);

/// The seeded node count. Deliberately far more than the egress buffer (256), so a fully-buffered stream
/// still has rows queued and the reader MUST block on the full channel once the consumer stops draining.
const SEED_NODES: usize = 1_000;

/// Spawns a threaded engine over an in-memory store with an explicit `statement_timeout` and
/// `egress_stall_timeout`, returning the engine plus its metrics registry (for liveness assertions).
fn engine_with(
    statement_timeout: Option<Duration>,
    egress_stall_timeout: Option<Duration>,
) -> (Engine, Arc<Metrics>) {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(Metrics::new());
    let engine = spawn_engine_with_timeout::<MemBlockDevice, MemLogSink, _>(
        Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            // A pool large enough to keep the small seeded working set RAM-resident (no eviction).
            let store = RecordStore::create(device, wal, 8_192, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        256,
        // Two reader workers so an auto-commit read genuinely dispatches off-thread.
        2,
        Arc::clone(&metrics),
        clock,
        statement_timeout,
        // No max-transaction-age cap (rmp #477): these gates exercise the egress-stall ceiling in
        // isolation, on the auto-commit-read path the age reaper explicitly excludes.
        None,
        egress_stall_timeout,
    )
    .expect("spawn threaded engine");
    (engine, metrics)
}

/// Seeds `n` `:N` nodes in one committed auto-commit statement (cheap — well under any ceiling).
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
        )
        .expect("seed run");
    while let Ok(Some(_)) = reply.rows.next() {}
}

/// Runs an auto-commit read to completion, returning `Ok(())` on a clean drain or `Err(())` on any
/// failure — exactly how a connection observes it.
fn run_auto(handle: &EngineHandle, stmt: &str) -> Result<(), ()> {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Read)
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

/// Polls `cond` until it holds or `PROMPT_CEILING` elapses; fails with `msg` on timeout.
fn wait_until(mut cond: impl FnMut() -> bool, msg: &str) {
    let deadline = Instant::now() + PROMPT_CEILING;
    while !cond() {
        assert!(Instant::now() < deadline, "{msg}");
        std::thread::sleep(Duration::from_millis(20));
    }
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

/// C-F1 (the primary regression): with the per-statement timeout DISABLED (`statement_timeout = None`),
/// a stalled off-thread reader is STILL released — bounded by the egress-stall ceiling alone. Its
/// GC-watermark pin drops (the `active_transactions` gauge returns to 0), the stall is counted, and the
/// reader-pool slot is freed.
#[test]
fn egress_stall_ceiling_releases_a_stalled_offthread_reader_with_timeout_disabled() {
    let (eng, metrics) = engine_with(None, Some(SHORT_EGRESS_CEILING));
    let handle = eng.handle.clone();

    seed_nodes(&handle, SEED_NODES);
    // The seed write has retired; no reader pins the watermark yet.
    wait_until(
        || metrics.active_txns() == 0,
        "the seed write must retire before the stalled read starts",
    );
    assert_eq!(
        metrics.egress_stall_aborts(),
        0,
        "no egress-stall abort should have happened yet"
    );

    // Dispatch an auto-commit read OFF-THREAD (Read + auto-commit + threaded pool), take the reply, and
    // DO NOT drain it — the classic stalled / TCP-zero-window consumer. The per-statement timeout is
    // disabled, so ONLY the egress-stall ceiling can bound this reader.
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Read)
        .expect("begin read");
    let reply = handle
        .run_blocking(
            ticket,
            "MATCH (n:N) RETURN n".to_owned(),
            vec![],
            true,
            None,
        )
        .expect("off-thread read dispatched");

    // The reader fills the 256-row egress buffer, then blocks on the full channel with no consumer
    // draining. The egress-stall ceiling must trip, terminate the read, and retire it — releasing its
    // snapshot from the active set. PROOF the GC-watermark pin is gone: the server-wide open-transaction
    // gauge returns to 0 (the `rmp` #386 leak oracle), and the stall is counted.
    wait_until(
        || metrics.active_txns() == 0,
        "the stalled off-thread reader was not released within the egress-stall ceiling — it is wedged \
         in a blocking egress send, pinning the GC watermark (rmp #591 C-F1 regression)",
    );
    assert!(
        metrics.egress_stall_aborts() >= 1,
        "the release must be attributed to the egress-stall ceiling (egress_stall_aborts counter)"
    );

    // Drain on a separate thread so a REGRESSION (a reader still wedged in a blocking send) fails via the
    // wall-clock guard instead of hanging the suite. With the fix the reader has already aborted and
    // dropped its sender, so the drain terminates promptly after delivering only the buffered prefix.
    let drain = std::thread::spawn(move || {
        let mut rows = reply.rows;
        let mut delivered = 0usize;
        while let Ok(Some(_)) = rows.next() {
            delivered += 1;
        }
        delivered
    });
    wait_until(
        || drain.is_finished(),
        "the stalled read's stream did not terminate — the reader is wedged (rmp #591 C-F1 regression)",
    );
    let delivered = drain.join().expect("drain thread joins");
    assert!(
        delivered < SEED_NODES,
        "the reader must have aborted before streaming the whole result (delivered {delivered} of \
         {SEED_NODES})"
    );

    // The reader-pool slot + engine recovered: a fresh read returns the full result.
    assert!(
        run_auto(&handle, "MATCH (n:N) RETURN count(n) AS c").is_ok(),
        "the engine + reader pool must keep serving after a stalled read is reaped"
    );

    shutdown(eng, handle);
}

/// The complementary property: a **slow-but-progressing** consumer (drains continuously, just slowly)
/// must NOT be false-aborted by the egress-stall ceiling, even with the per-statement timeout disabled —
/// the ceiling measures time-SINCE-PROGRESS and resets on every accepted row. The reader delivers the
/// whole result.
#[test]
fn egress_stall_ceiling_does_not_abort_a_slow_but_progressing_consumer() {
    // A generous ceiling relative to the per-row drain interval (below), so even heavy CI jitter cannot
    // make a genuinely-progressing consumer look stalled.
    let (eng, metrics) = engine_with(None, Some(Duration::from_secs(5)));
    let handle = eng.handle.clone();

    seed_nodes(&handle, SEED_NODES);

    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Read)
        .expect("begin read");
    let mut reply = handle
        .run_blocking(
            ticket,
            "MATCH (n:N) RETURN n".to_owned(),
            vec![],
            true,
            None,
        )
        .expect("off-thread read dispatched");

    // Drain SLOWLY but CONTINUOUSLY: a ~1 ms pause per row keeps the channel near-full (so the reader
    // backs off between rows) while never letting a single row wait the whole 5 s ceiling. This is the
    // "legitimately slow analytics consumer" the C-F1 fix must not punish. Runs on a guarded thread so a
    // regression (the ceiling wrongly aborting a progressing reader mid-stream) still fails, not hangs.
    let drain = std::thread::spawn(move || {
        let mut delivered = 0usize;
        loop {
            match reply.rows.next() {
                Ok(Some(_)) => {
                    delivered += 1;
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(None) => break Ok(delivered),
                Err(_) => break Err(delivered),
            }
        }
    });
    wait_until(
        || drain.is_finished(),
        "the slow-but-progressing read did not finish within the wall-clock guard",
    );
    let outcome = drain.join().expect("drain thread joins");
    assert_eq!(
        outcome,
        Ok(SEED_NODES),
        "a slow-but-progressing consumer must receive the WHOLE result (no false egress-stall abort)"
    );
    assert_eq!(
        metrics.egress_stall_aborts(),
        0,
        "a progressing consumer must never be counted as an egress stall"
    );
    // The reader retired cleanly: no leaked GC-watermark pin.
    wait_until(
        || metrics.active_txns() == 0,
        "the progressing read must retire and release its snapshot",
    );

    shutdown(eng, handle);
}
