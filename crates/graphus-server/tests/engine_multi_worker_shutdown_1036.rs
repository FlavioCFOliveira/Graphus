//! **A graceful shutdown must converge when the engine runs more than one worker** (`rmp` #1036).
//!
//! Layer 7b (`rmp` #1033) turned the engine loop into a body that `W` worker threads run, and #1035
//! gave each worker its own command queue with sessions routed by `ticket % W`. The state those
//! workers must agree on lives in `EngineShared`, and its doc-comment says it is "declared once …
//! without any of it being duplicated per worker". It was not: the struct was constructed *inside*
//! `run_engine_loop`, so every worker got its own copy of the stop flag, the live-worker count, the
//! open-transaction table and the plan cache.
//!
//! The consequence was total and silent. The worker handed `Cmd::Shutdown` raises `stopping` and then
//! waits to be the last one out — `while live_workers > 1 { yield_now() }` — on a counter that is its
//! own, starts at `W`, and that nobody else ever decrements. It spins for ever. In a server that is
//! not a hang but something worse: `stop_engine` sees no drain progress, force-detaches the engine,
//! and the spinning zombie keeps the exclusive store-open lock for the life of the process, so every
//! later `START DATABASE` for that store fails.
//!
//! ## Why no existing test caught it
//!
//! The multi-stream gate (`rmp` #907) already runs at four workers, but it stops the engine by
//! **dropping the handles**, which closes the queues and exits through `Disconnected` — a different
//! path. No test sent `Cmd::Shutdown` to an engine with `W > 1`, so the broken path was never
//! executed. These tests do exactly that, under a watchdog, so a regression fails loudly instead of
//! wedging the suite.

use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine_with_timeout};
use graphus_server::metrics::Metrics;
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// Engine workers to run. Eight, and the number is evidence-driven rather than tidy. Two failures
/// hide here and they need different widths: the stop barrier is deterministic and shows at two, but
/// the `Arc::try_unwrap` race below is probabilistic in `W` — measured at 12 occurrences in 12 runs
/// at eight workers with sixteen reader threads, and at zero in the same number of runs at four
/// workers with two. A gate at four would have called the second defect fixed while it was not.
const WORKERS: usize = 8;

/// Reader threads per worker. Sized with [`WORKERS`] for the same reason: the racing window is the
/// reader-pool teardown that happens between a worker leaving the loop and releasing its share of the
/// coordinator, so a wider pool widens the window this test has to survive.
const READER_THREADS: usize = 16;

/// Wall-clock budget for a whole scenario. The failure mode guarded against is an **unbounded** spin,
/// so any finite ceiling exposes it; this one is generous enough for a loaded CI box.
const WATCHDOG: Duration = Duration::from_secs(30);

/// Spawns a threaded engine over an in-memory store with [`WORKERS`] engine workers.
fn engine() -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(Metrics::new());
    spawn_engine_with_timeout::<MemBlockDevice, MemLogSink, _>(
        Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 8_192, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        64,
        READER_THREADS,
        WORKERS,
        Arc::clone(&metrics),
        clock,
        // No statement timeout and no transaction-age cap: the point is that the *shutdown* converges,
        // never that a timeout eventually rescues it.
        None,
        None,
        None,
        Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn threaded engine")
}

/// Runs `body` on a worker thread under [`WATCHDOG`]. A body that wedges — the exact regression these
/// tests guard — fails with `what` instead of hanging the suite for ever. The worker thread is
/// deliberately leaked on timeout, so the failure is reported rather than masked by a join that would
/// itself never return.
///
/// A **timeout** and a **panic inside the body** are reported differently on purpose. Both end the
/// `recv`, and a helper that collapsed them would report an ordinary failed assertion as "the engine
/// is wedged" — turning every diagnosis into a guess about which of the two actually happened.
fn under_watchdog<T: Send + 'static>(what: &str, body: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::sync_channel::<T>(1);
    let worker = std::thread::spawn(move || {
        let out = body();
        // A closed receiver means the watchdog already fired; nothing to report.
        let _ = tx.send(out);
    });
    match rx.recv_timeout(WATCHDOG) {
        Ok(out) => {
            worker.join().expect("worker thread");
            out
        }
        // The sender was dropped without a value: the body panicked. Re-raise it on this thread so the
        // original assertion message is what the report shows.
        Err(mpsc::RecvTimeoutError::Disconnected) => match worker.join() {
            Ok(_) => panic!("{what}: the body ended without producing a value"),
            Err(payload) => std::panic::resume_unwind(payload),
        },
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("{what}: no response within {WATCHDOG:?} — the engine is wedged")
        }
    }
}

/// A single-threaded runtime for the async handle calls, built per use (these tests are not hot).
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build test runtime")
}

/// Commits one auto-commit write, so the engine has real state to drain at shutdown.
fn write_one(handle: &EngineHandle, i: i64) {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .expect("begin auto-commit");
    let mut reply = handle
        .run_blocking(
            ticket,
            format!("CREATE (:Acct {{i: {i}}})"),
            vec![],
            true,
            None,
            None,
        )
        .expect("auto-commit run");
    while reply.rows.next().expect("rows").is_some() {}
}

/// How many engine lifecycles the shutdown gate runs. One would settle the deterministic half of the
/// regression (the stop barrier) and leave the probabilistic half — the `try_unwrap` race — to
/// chance. Repetition is what turns "did not happen this time" into evidence.
const SHUTDOWN_CYCLES: usize = 8;

/// **The regression itself**, in both of its halves.
///
/// *The barrier.* The worker handed `Shutdown` waits for every other worker to leave. With the stop
/// state built per worker it waits on its own counter, which nobody else decrements, and spins for
/// ever: the reply never arrives and the watchdog fires.
///
/// *The race underneath it.* Making the counter shared is not enough. `Shutdown` calls
/// `Arc::try_unwrap` on the coordinator, which needs sole ownership and panics without it, so the
/// count has to mean "every worker released its share" — not "every worker left the loop". A worker
/// that announces its exit before tearing down its reader pool and dropping its share leaves a window
/// in which `try_unwrap` panics, `harden_store` never runs, and the shutdown returns
/// `DatabaseUnavailable` with no final flush. That window widens with `W` and with the reader pool.
///
/// Non-vacuity, for each half: the barrier half asserts the call returned *and* all `WORKERS` threads
/// joined — reverting the shared stop state makes it time out. The race half is the reason for
/// [`SHUTDOWN_CYCLES`], [`WORKERS`] and [`READER_THREADS`]: at these widths the unfixed exit order was
/// measured to panic in every one of twelve attempts, so a clean run of eight cycles is a signal, not
/// an absence.
#[test]
fn graceful_shutdown_converges_with_multiple_engine_workers() {
    under_watchdog("graceful shutdown with multiple engine workers", || {
        for cycle in 0..SHUTDOWN_CYCLES {
            let engine = engine();
            // Real work first, spread over several sessions so more than one worker has state to
            // drain and the reader pools have been touched.
            for i in 0..(WORKERS as i64 * 4) {
                write_one(&engine.handle, i);
            }
            let Engine { handle, joins } = engine;
            rt().block_on(handle.shutdown())
                .unwrap_or_else(|e| panic!("cycle {cycle}: graceful shutdown completes, got {e}"));
            drop(handle);
            assert_eq!(joins.len(), WORKERS, "every worker was spawned");
            for (id, join) in joins.into_iter().enumerate() {
                join.join()
                    .unwrap_or_else(|_| panic!("cycle {cycle}: engine worker {id} joins cleanly"));
            }
        }
    });
}

/// **`Status` counts the engine's transactions, not the answering worker's.**
///
/// This one pins a property that already held, and it is worth saying why it is here rather than
/// quietly dropped. `Status` is administrative, so it round-robins to *some* worker, and each worker
/// still keeps its own `OpenTxTable` — the arrangement that makes the `Shutdown` drain reach only one
/// of them (`rmp` #1041). It survives that only because the handler answers from
/// `coord.active_count()` on the shared coordinator instead of from the local table. Nothing states
/// that; rerouting the handler through `shared.open`, which would look like a simplification, would
/// silently make the count depend on which worker replied. This test is that missing statement.
///
/// Non-vacuity: the transactions are opened through `begin`, which round-robins, and the test asserts
/// they landed on more than one worker before it asserts the count — so a count of `WORKERS` means
/// the answer crossed workers rather than one worker happening to hold everything.
#[test]
fn status_counts_open_transactions_across_every_worker() {
    under_watchdog("status across workers", || {
        let engine = engine();
        let handle = engine.handle.clone();
        let opened: Vec<_> = (0..WORKERS)
            .map(|_| {
                handle
                    .begin_blocking(AccessMode::Write)
                    .expect("begin explicit transaction")
            })
            .collect();
        // The tickets must genuinely land on different workers, or the test would prove nothing about
        // sharing. That is `rmp` #1035's routing rule, asserted here rather than assumed.
        let workers_touched: std::collections::HashSet<usize> =
            opened.iter().map(|t| (t.0 as usize) % WORKERS).collect();
        assert!(
            workers_touched.len() > 1,
            "the open transactions must be spread over more than one worker for this to test \
             anything; they landed on {workers_touched:?}"
        );

        let open = rt()
            .block_on(handle.status_open_txns())
            .expect("status responds");
        assert_eq!(
            open, WORKERS,
            "every open transaction must be visible to the status probe, whichever worker answers it"
        );

        for ticket in opened {
            handle.rollback_blocking(ticket).expect("rollback");
        }
        let Engine { handle: h, joins } = engine;
        rt().block_on(h.shutdown()).expect("graceful shutdown");
        drop(h);
        drop(handle);
        for join in joins {
            join.join().expect("engine worker joins cleanly");
        }
    });
}
