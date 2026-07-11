//! **Regression for `rmp` #694** — an operator-triggered `CHECKPOINT DATABASE` must be COUNTED by the
//! maintenance metric family, exactly as the background cadence is.
//!
//! `graphus_maintenance_checkpoints_total`, `graphus_maintenance_versions_reclaimed_total` and
//! `graphus_maintenance_stamps_frozen_total` document themselves as
//! *"operator `CHECKPOINT DATABASE` **+** the background cadence"* (`Metrics::render_prometheus`), and
//! `EngineCommand::Checkpoint`'s own docs say it is *"driven by the over-the-wire `CHECKPOINT DATABASE`
//! admin statement **and** the engine's background maintenance cadence"*. In practice only the cadence
//! (`maybe_run_maintenance`) ever recorded into them: the `Cmd::Checkpoint` dispatch arm reclaimed
//! version slots and froze stamps **without touching the counters**, so an operator-driven reclamation
//! pass was completely invisible on `/metrics`.
//!
//! That is not a cosmetic gap. The reclamation counters are the *only* server-side channel proving a
//! `CHECKPOINT DATABASE` actually did work — an attached / remote instance exposes no `/proc` and no
//! store files. `examples/iot-timeseries` scrapes exactly this family to prove its storage-reclamation
//! plateau is caused by reclamation rather than by an absence of writes. A counter that stays at `0`
//! while slots are demonstrably being freed is a false negative on the one signal an operator alerts on.
//!
//! The test drives the REAL threaded engine: it churns nodes (create → delete), issues an explicit
//! `EngineCommand::Checkpoint` (the exact command the `CHECKPOINT DATABASE` admin statement dispatches
//! to), and asserts the rendered Prometheus text advanced. Pre-fix it fails on `checkpoints_total == 0`.

use std::sync::Arc;

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine};
use graphus_server::metrics::Metrics;
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// How many nodes the churn creates and then deletes — enough that a GC pass has real work to reclaim.
const CHURN: i64 = 200;

fn threaded_engine(metrics: Arc<Metrics>) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        std::sync::Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 512, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        1024,
        64,
        1,
        metrics,
        clock,
    )
    .expect("spawn threaded engine")
}

fn teardown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins");
}

/// Runs one auto-commit write statement to completion, draining its rows.
fn write(handle: &EngineHandle, stmt: &str) {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .expect("begin auto-commit write");
    let mut reply = handle
        .run_blocking(ticket, stmt.to_owned(), vec![], true, None)
        .unwrap_or_else(|e| panic!("run {stmt:?}: {e:?}"));
    while reply.rows.next().expect("drain rows").is_some() {}
}

/// Extracts a Prometheus counter's value out of the rendered text (`name value` on its own line).
fn counter(text: &str, name: &str) -> u64 {
    text.lines()
        .find(|l| !l.starts_with('#') && l.split_whitespace().next() == Some(name))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("counter {name} absent from the /metrics render"))
}

#[test]
fn operator_checkpoint_increments_the_maintenance_counters() {
    let metrics = Arc::new(Metrics::new());
    let engine = threaded_engine(Arc::clone(&metrics));
    let handle = engine.handle.clone();

    // A quiescent server has run no maintenance at all.
    let before = metrics.render_prometheus();
    assert_eq!(
        counter(&before, "graphus_maintenance_checkpoints_total"),
        0,
        "no checkpoint has run yet"
    );
    assert_eq!(
        counter(&before, "graphus_maintenance_versions_reclaimed_total"),
        0,
        "nothing reclaimed yet"
    );

    // Churn: create CHURN nodes, then delete them all. The deletes leave MVCC tombstones that only a
    // GC pass physically reclaims — real work for the checkpoint to do.
    for i in 0..CHURN {
        write(&handle, &format!("CREATE (:Churn {{n: {i}}})"));
    }
    write(&handle, "MATCH (c:Churn) DELETE c");

    // The workload alone must NOT have moved the maintenance counters (this WAL is orders of magnitude
    // below the background cadence's reclaim interval, whose floor is 8 MiB, so no automatic pass
    // fired). That is what makes the post-checkpoint delta below cleanly attributable to the OPERATOR
    // trigger rather than to the cadence.
    let mid = metrics.render_prometheus();
    assert_eq!(
        counter(&mid, "graphus_maintenance_checkpoints_total"),
        0,
        "the background cadence must not fire at this tiny WAL size — otherwise the operator-trigger \
         attribution below would not be clean"
    );

    // The operator trigger: the exact EngineCommand the `CHECKPOINT DATABASE <name>` admin statement
    // dispatches to (admin.rs → DbCatalog::checkpoint → EngineHandle::checkpoint).
    let report = handle.checkpoint_blocking().expect("operator checkpoint");
    assert!(
        report.reclaimed > 0,
        "the GC pass must have physically reclaimed the deleted versions (reclaimed={})",
        report.reclaimed
    );

    // THE REGRESSION: the operator pass must be visible on /metrics.
    let after = metrics.render_prometheus();
    assert_eq!(
        counter(&after, "graphus_maintenance_checkpoints_total"),
        1,
        "an operator CHECKPOINT DATABASE must increment graphus_maintenance_checkpoints_total (the \
         metric documents itself as 'operator CHECKPOINT DATABASE + the background cadence')"
    );
    assert_eq!(
        counter(&after, "graphus_maintenance_versions_reclaimed_total"),
        report.reclaimed as u64,
        "graphus_maintenance_versions_reclaimed_total must carry exactly what the pass reported \
         reclaimed — it is the only server-side proof the checkpoint freed anything"
    );
    assert_eq!(
        counter(&after, "graphus_maintenance_stamps_frozen_total"),
        report.frozen as u64,
        "graphus_maintenance_stamps_frozen_total must carry exactly what the pass reported frozen"
    );
    // A successful checkpoint is never a maintenance failure.
    assert_eq!(
        counter(&after, "graphus_maintenance_failures_total"),
        0,
        "a successful operator checkpoint is not a maintenance failure"
    );

    // A second operator checkpoint increments again (the counter is cumulative, not a one-shot flag).
    handle.checkpoint_blocking().expect("second checkpoint");
    let after2 = metrics.render_prometheus();
    assert_eq!(
        counter(&after2, "graphus_maintenance_checkpoints_total"),
        2,
        "the checkpoint counter is cumulative across operator triggers"
    );

    // The engine still serves traffic after the reclaim passes (the free slots are reusable).
    write(&handle, "CREATE (:Churn {n: 999})");
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Read)
        .expect("begin read");
    let mut reply = handle
        .run_blocking(
            ticket,
            "MATCH (c:Churn) RETURN count(c) AS c".to_owned(),
            vec![],
            true,
            None,
        )
        .expect("count after reclaim");
    let row = reply
        .rows
        .next()
        .expect("count row")
        .expect("one count row");
    let live = match row.first() {
        Some(graphus_cypher::MaterializedValue::Value(Value::Integer(n))) => *n,
        other => panic!("unexpected count cell: {other:?}"),
    };
    while reply.rows.next().expect("drain").is_some() {}
    assert_eq!(live, 1, "the reclaimed store still serves fresh writes");

    teardown(engine, handle);
}
