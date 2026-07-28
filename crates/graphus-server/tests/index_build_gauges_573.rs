//! The **index-build gauges** must be published by the real engine loop (`rmp` task #573).
//!
//! `rmp` #573's operability claim is that an operator can tell a normal index-build *window* from a
//! permanent *stall*. The two pre-existing signals cannot do it: `graphus_index_builds_poisoned_total`
//! and `graphus_index_fail_closed_total` are cumulative event counters, so they record that something
//! happened once and say nothing about *now*. The gauges can — but only if the engine actually publishes
//! them.
//!
//! The gauge type's own arithmetic (additivity across engines, the `Drop` retraction) is unit-tested next
//! to it in `engine::index_build_gauge_tests`. What **no** unit test can cover is the call site: deleting
//! the loop's `publish` left every one of those unit tests green. So this drives the **real threaded
//! engine** and observes the gauges from the outside, through the shared `Metrics` — the only way to pin
//! that the loop publishes at all.
//!
//! # Why the observation is not a race
//!
//! The engine advances a build by `INDEX_BUILD_CHUNK` (512) nodes per `INDEX_BUILD_TICK` (2 ms), so a
//! build of `N` nodes occupies roughly `N / 512 * 2 ms` of **wall clock** — a rate set by the tick, not by
//! the host's CPU, so a fast machine does not shrink it. At `SEED` that is ~16 ms, which the 100 us poll
//! below samples ~160 times. The test asserts what it actually observed rather than assuming it, so it
//! fails loudly instead of passing vacuously if the window is ever missed.

use std::sync::Arc;

use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::{AccessMode, IndexCommand};
use graphus_server::engine::{Engine, EngineHandle, TxTicket, spawn_engine};
use graphus_server::metrics::Metrics;
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// Nodes to index. At 512 nodes per 2 ms tick this is a build window of roughly
/// `4000 / 512 * 2 ms` ~= 16 ms — set by the engine's tick rate, so it does not shrink on a fast host.
/// Kept small because seeding dominates this test's runtime (~0.2 ms/node in a debug build).
const SEED: usize = 4_000;

fn threaded_engine(metrics: Arc<Metrics>) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 8192, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        1024,
        256,
        2,
        metrics,
        clock,
        std::sync::Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn threaded engine")
}

/// Shuts the engine down. BOTH handles must be dropped before the join: the engine loop terminates on
/// its command channel closing, and the channel stays open while ANY `EngineHandle` clone lives — so
/// joining with the test's own clone still in scope deadlocks forever.
fn teardown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins");
}

fn run(handle: &EngineHandle, stmt: &str) {
    let ticket: TxTicket = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .expect("begin");
    let mut reply = handle
        .run_blocking(ticket, stmt.to_owned(), vec![], true, None)
        .expect("run");
    while reply.rows.next().expect("rows pull").is_some() {}
}

/// **THE GATE.** The engine loop must publish the index-build gauges: an in-flight build must be visible
/// as `graphus_index_builds_pending > 0` with a falling `graphus_index_build_entities_remaining`, and both
/// must return to zero once the build completes.
///
/// Deleting the loop's `publish` call leaves every gauge unit test green; this test is what fails.
#[test]
fn the_engine_loop_publishes_the_index_build_gauges() {
    let metrics = Arc::new(Metrics::new());
    let engine = threaded_engine(Arc::clone(&metrics));
    let handle = engine.handle.clone();

    run(
        &handle,
        &format!("UNWIND range(1, {SEED}) AS i CREATE (:Person {{a: i}})"),
    );

    // Nothing is building yet: the baseline the observations below must differ from.
    assert_eq!(
        metrics.index_builds_pending(),
        0,
        "no build is in flight before the CREATE INDEX"
    );
    assert_eq!(metrics.index_build_entities_remaining(), 0);

    handle
        .index_ddl_blocking(IndexCommand::CreateNodePropertyIndex {
            name: Some("ix_a".to_owned()),
            label: "Person".to_owned(),
            properties: vec!["a".to_owned()],
            if_not_exists: false,
        })
        .expect("create index");

    // Sample the window. The build is tick-paced, so it stays open for ~16 ms while this polls every
    // 100 us; `saw_pending` records what was actually observed rather than assumed.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut saw_pending = false;
    let mut max_remaining = 0;
    let mut min_remaining_seen = u64::MAX;
    while std::time::Instant::now() < deadline {
        let pending = metrics.index_builds_pending();
        let remaining = metrics.index_build_entities_remaining();
        if pending > 0 {
            saw_pending = true;
            max_remaining = max_remaining.max(remaining);
            if remaining > 0 {
                min_remaining_seen = min_remaining_seen.min(remaining);
            }
        }
        // The window has closed: the build finished and the gauges came back to rest. BOTH must be
        // settled before breaking — `add_index_build_deltas` writes the three gauges as three separate
        // non-atomic read-modify-writes (`pending` first, `remaining` last), so breaking on `pending == 0`
        // alone can observe a stale non-zero `remaining` and fail the post-loop assertion spuriously.
        if saw_pending && pending == 0 && remaining == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_micros(100));
    }

    // (1) The window was observed at all — the publish happens.
    assert!(
        saw_pending,
        "graphus_index_builds_pending never rose above zero during a {SEED}-node build: the engine \
         loop is not publishing the index-build gauges"
    );
    // (2) The remainder is the real one, not a placeholder: it must have been within the build's size.
    assert!(
        max_remaining > 0 && max_remaining <= SEED as u64,
        "graphus_index_build_entities_remaining must report the real remainder of a {SEED}-node \
         build, saw a maximum of {max_remaining}"
    );
    // (3) It PROGRESSED: a later sample was strictly smaller than the largest. A gauge stuck at its
    // initial value would satisfy (1) and (2) but not this.
    assert!(
        min_remaining_seen < max_remaining,
        "graphus_index_build_entities_remaining never fell ({max_remaining} -> {min_remaining_seen}): \
         it must track the build's progress, not sit at a constant"
    );
    // (4) The gauges come back to rest, so a closed window is distinguishable from a stall.
    assert_eq!(
        metrics.index_builds_pending(),
        0,
        "the completed build must leave the pending gauge at zero"
    );
    assert_eq!(
        metrics.index_build_entities_remaining(),
        0,
        "the completed build must leave no remainder"
    );
    // Nothing was poisoned on a healthy device, so the stall signal stayed silent throughout.
    assert_eq!(
        metrics.index_builds_parked(),
        0,
        "a healthy build must never raise the PARKED (stall) gauge"
    );

    teardown(engine, handle);
}
