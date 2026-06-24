//! The **single engine task**: the one place all query execution is funnelled, owning the
//! [`graphus_storage::RecordStore`] + [`graphus_cypher::TxnCoordinator`]
//! (`04-technical-design.md` §9.1 sharded write/ACID path, v1 = one shard; §1.3 request lifecycle).
//!
//! ## Why a single task on a dedicated thread
//!
//! The cypher engine is **single-threaded** (`!Sync`, `Rc<RefCell<…>>`-backed). The server is a
//! multi-threaded Tokio runtime. Rather than wrap the coordinator in a lock (which would serialise
//! anyway and risk holding a guard across `.await`), we run it on **one dedicated OS thread** and
//! serve [`EngineCommand`]s over a **bounded** `std::sync::mpsc` channel ([`EngineHandle`]). The
//! engine executes each command serially against the coordinator and streams result rows back over a
//! bounded channel ([`stream`]). This is the §9.1 "small set of shards" model with one shard, and
//! the single-node single-writer ACID core. The thread is **not** a Tokio worker, so the
//! coordinator's blocking work (storage I/O, the WAL group-commit `fdatasync`) runs off the runtime
//! exactly as §9.1 requires.
//!
//! ## Transactions
//!
//! Connections refer to transactions by an opaque [`TxTicket`] the engine mints. An explicit
//! transaction (`BEGIN … COMMIT`) is driven by the connection. An **auto-commit** statement opens an
//! internal transaction, runs, and the engine commits it **when the result stream is fully drained**
//! (so the side effects and the streamed rows agree). Read serialisation through the engine is the
//! v1 behaviour; lock-free concurrent reads against committed versions are the documented follow-up
//! (§9.1).

pub mod bolt_values;
pub mod command;
mod exec;
mod handle;
mod local;
pub mod privileges;
mod read_pool;
pub mod rest_values;
mod seam_bolt;
mod seam_rest;
pub mod stream;

use std::collections::HashMap;
use std::sync::Arc;

use graphus_core::error::{GraphusError, Result};
use graphus_cypher::TxnCoordinator;
use graphus_io::BlockDevice;
use graphus_storage::RecordStore;
use graphus_txn::IsolationLevel;
use graphus_wal::LogSink;

pub use command::{
    AccessMode, CheckpointReply, ConstraintCommand, EngineCommand, IndexCommand, IndexDdlReply,
    RunReply, RunSummary,
};
pub use handle::{EngineHandle, ServerBusy};
pub use local::LocalEngine;
pub use privileges::EffectivePrivileges;
pub use seam_bolt::BoltEngineExecutor;
pub use seam_rest::{RestAuthObserver, RestEngineAdapter};

use crate::metrics::Metrics;
use command::EngineCommand as Cmd;
use graphus_core::{TxnId, Value};
use graphus_storage::{ConstraintKind, IndexState};

/// How many nodes a single [`TxnCoordinator::advance_index_builds`] call indexes per tick while a
/// non-blocking index build is in progress (`rmp` task #91).
///
/// Chosen as a balance between throughput and responsiveness on the single engine thread: large
/// enough that the per-call fixed overhead (a `front_mut`, the slice bounds) is negligible against
/// the per-node store reads, yet small enough that a chunk completes in well under a millisecond on
/// commodity hardware — so a command arriving mid-build waits at most one chunk, not a whole index.
/// 512 lands in the documented 256–1024 window; a build of `N` nodes completes in `ceil(N/512)`
/// ticks of work interleaved with command handling.
const INDEX_BUILD_CHUNK: usize = 512;

/// How long the engine loop waits for a command before stealing a slice of build work, while a
/// non-blocking index build is in progress (`rmp` task #91).
///
/// On an idle-but-building engine this bounds the build's wall-clock progress rate to roughly one
/// [`INDEX_BUILD_CHUNK`] per tick; on a busy engine the timeout rarely fires (commands arrive first)
/// and the post-command `advance_index_builds` drives progress instead. 2 ms keeps a fully idle
/// build progressing briskly without a tight spin, and is short enough that a build of a populated
/// store finishes in a fraction of a second even with no traffic. When **no** build is pending the
/// loop reverts to a plain blocking `recv()` — zero idle wakeups (no busy-loop).
const INDEX_BUILD_TICK: std::time::Duration = std::time::Duration::from_millis(2);

/// WAL bytes the engine lets accumulate since the last **maintenance checkpoint** before driving the
/// next one automatically (`rmp` #305 background cadence). A maintenance checkpoint runs a reader-safe
/// GC pass (reclaim dead versions + freeze committed MVCC stamps, lowering the WAL reclaim floor) and a
/// sharp checkpoint that physically reclaims the WAL prefix below the floor — so RAM (the in-memory WAL
/// tail), disk (sealed WAL segments) and version slots are reclaimed without an operator trigger.
///
/// Distinct from [`graphus_storage::DEFAULT_CHECKPOINT_INTERVAL_BYTES`] (the store's own redo-bounding
/// checkpoint, which cannot lower the floor on its own because only the GC freeze sweep settles the
/// `unfrozen_commit_lsn` map). 256 MiB amortises the GC sweep's full-store scan against sustained write
/// load while keeping the steady-state footprint bounded; it is checked only after a mutating command,
/// so a fully idle engine (no WAL growth, nothing to reclaim) never wakes to run it.
const MAINTENANCE_CHECKPOINT_INTERVAL_BYTES: u64 = 256 * 1024 * 1024;

/// An opaque handle to a transaction the engine opened.
///
/// Both connectivity seams refer to a transaction by this ticket (the Bolt session tracks its single
/// current one; the stateless REST router stores it per public tx id). It is a thin newtype over the
/// coordinator's [`TxnId`] so the engine maps it back without a side table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxTicket(pub u64);

impl AccessMode {
    /// The SSI isolation level for this access mode. Both run at SERIALIZABLE in v1 (the coordinator
    /// validates writes; a read-only transaction simply performs no writes), matching the
    /// 100%-ACID mandate. The access mode is additionally enforced at the seam (a write statement in
    /// a `Read` transaction is rejected — `06 §4`).
    fn isolation(self) -> IsolationLevel {
        IsolationLevel::Serializable
    }
}

/// State the engine task keeps for one open transaction.
///
/// Whether a transaction is auto-commit is carried per-statement on the [`EngineCommand::Run`]
/// (and the seam opens the implicit transaction via [`EngineCommand::BeginAutoCommit`]), so it is not
/// stored here — the engine commits/rolls-back an auto-commit transaction in the `Run` handler when
/// its stream drains (see [`exec`]).
struct OpenTx {
    /// The coordinator's transaction id.
    txn: TxnId,
    /// The access mode (so a write statement in a `Read` transaction is rejected — `06 §4`).
    mode: AccessMode,
}

/// Runs the engine event loop until a [`EngineCommand::Shutdown`] (or the command channel closes).
///
/// Owns `coordinator` and the result-egress bound (`result_buffer_capacity`). Each command is
/// handled serially; `Run` executes the full compile→bind→execute pipeline (see [`exec`]) and
/// streams rows back over a bounded channel sized by `result_buffer_capacity`.
///
/// This function **blocks** the calling thread for the engine's lifetime; spawn it on a dedicated
/// OS thread (see [`spawn_engine`]).
fn run_engine_loop<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coordinator: TxnCoordinator<D, S>,
    rx: std::sync::mpsc::Receiver<EngineCommand>,
    result_buffer_capacity: usize,
    reader_threads: usize,
    metrics: Arc<Metrics>,
    clock: Arc<dyn graphus_core::capability::Clock + Send + Sync>,
) {
    let mut open: HashMap<u64, OpenTx> = HashMap::new();
    let mut next_ticket: u64 = 0;
    // The extension registry (user-defined functions/procedures, `rmp` task #75). Built **once** on
    // the engine thread, then `Arc`-shared so an off-thread reader resolves UDF/UDP plans against the
    // SAME registry that backed compilation (`rmp` task #336 — `ExtensionRegistry` is `Send + Sync`,
    // so this is sound). The engine borrows it immutably for each `Run`; commands are serial.
    let extensions = Arc::new(exec::install_extensions());
    // The off-thread reader pool (`rmp` task #336, Slice 3b-ii): read-only auto-commit statements run
    // on it concurrently with this engine thread. Workers post retirements back on a **dedicated**
    // retirement channel (NOT the command channel — keeping it separate avoids the worker clones
    // pinning the command channel open and lets the loop tear the pool down on a clean channel-close
    // shutdown). The work queue is bounded (no unbounded channel — `04 §9.3`); a full queue makes the
    // dispatch site fall back to the inline path.
    let (retire_tx, retire_rx) = std::sync::mpsc::channel::<read_pool::ReadRetirement>();
    let dispatch = read_pool::ReadDispatch::Threaded(read_pool::ReadPool::spawn(
        reader_threads,
        reader_threads.saturating_mul(8).max(16),
        retire_tx,
    ));
    // How many readers are dispatched-but-not-yet-retired. While `> 0` the loop polls the retirement
    // channel each tick so a retirement (which finalises the reader's auto-commit + closes its egress)
    // is processed promptly even if no client command arrives. Incremented at dispatch, decremented as
    // each retirement is processed.
    let mut readers_inflight: u64 = 0;
    // The single suspended inline statement, if any (`rmp` task #372). An inline `Run` whose bounded
    // egress channel fills with a slow consumer draining is parked here instead of blocking this
    // thread on `row_tx.send`; the loop resumes it one batch per tick (gated into `timed` below) until
    // its cursor exhausts. At most one exists at a time — the engine processes one `Run` per tick.
    let mut inflight: Option<exec::InFlightInline> = None;
    // Held in an `Option` so the terminal `Shutdown` can move the coordinator out to consume it for
    // the final flush (`TxnCoordinator::into_store` is by-value). It is always `Some` while the loop
    // is processing commands.
    let mut coordinator = Some(coordinator);
    // The WAL `durable_len` captured at the last background maintenance checkpoint (`rmp` #305). The
    // cadence fires when growth past it crosses `MAINTENANCE_CHECKPOINT_INTERVAL_BYTES`, reclaiming
    // RAM/disk/version slots without an operator trigger. Seeded from the current WAL length so a
    // freshly-opened engine does not immediately run a (no-op) pass.
    let mut wal_at_last_maintenance: u64 = coordinator
        .as_ref()
        .expect("INVARIANT: coordinator is Some at startup")
        .wal_durable_len();

    'engine: loop {
        // Drain any reader retirements that have arrived (M1 merge → auto-commit, on this thread, in
        // arrival order). Done first each iteration so a retirement is never starved behind a blocking
        // command `recv`. Returns false only on `Shutdown`, which cannot arrive here (retirements are
        // not commands), so the result is ignored.
        process_retirements(
            &retire_rx,
            &mut coordinator,
            &mut open,
            &mut readers_inflight,
            &metrics,
        );

        // Resume one batch of the suspended inline statement, if any (`rmp` task #372). Done each tick
        // — before the (timed) command receive — so a draining consumer makes progress promptly even
        // when no client command arrives. `resume_inflight` returns `false` once the statement is
        // finalised (cursor exhausted / runtime error / disconnect), clearing the slot. Because this
        // runs between commands, a concurrent write/command on the SAME database is serviced on the
        // very next tick even while the consumer drains zero rows — the head-of-line block is gone.
        if let Some(parked) = inflight.as_mut() {
            if let Some(coord) = coordinator.as_mut() {
                if !exec::resume_inflight(parked, coord, &mut open, &extensions, &metrics, &clock) {
                    inflight = None;
                }
            }
        }

        // A timed receive is needed when EITHER a non-blocking index build is in progress (`rmp` #91)
        // OR readers are in flight (so their retirements are polled) OR a suspended inline statement is
        // parked (so it is resumed each tick even with no command). Otherwise block plainly (no idle
        // wakeups — a fully idle engine with nothing pending parks on `recv` exactly as before).
        let building = coordinator
            .as_ref()
            .expect("INVARIANT: coordinator is Some until Shutdown breaks the loop")
            .has_pending_index_builds();
        let timed = building || readers_inflight > 0 || inflight.is_some();

        if timed {
            match rx.recv_timeout(INDEX_BUILD_TICK) {
                Ok(cmd) => {
                    if !dispatch_command(
                        cmd,
                        &mut coordinator,
                        &mut open,
                        &mut next_ticket,
                        &extensions,
                        &dispatch,
                        &mut readers_inflight,
                        &mut inflight,
                        result_buffer_capacity,
                        &metrics,
                        &clock,
                    ) {
                        break 'engine; // Shutdown handled (drained + hardened) inside the dispatch.
                    }
                    drive_index_build(&mut coordinator);
                    maybe_run_maintenance(&mut coordinator, &mut wal_at_last_maintenance, &metrics);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // No command this tick: advance any build, then loop (which drains retirements).
                    drive_index_build(&mut coordinator);
                }
                // Channel closed (all client senders dropped): the engine is being torn down without a
                // graceful `Shutdown`. Stop serving.
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break 'engine,
            }
        } else {
            // No build pending and no readers in flight: a plain blocking receive (the original
            // behaviour). `Err` is the closed-channel EOF the old `while let Ok(..)` terminated on.
            let Ok(cmd) = rx.recv() else { break 'engine };
            if !dispatch_command(
                cmd,
                &mut coordinator,
                &mut open,
                &mut next_ticket,
                &extensions,
                &dispatch,
                &mut readers_inflight,
                &mut inflight,
                result_buffer_capacity,
                &metrics,
                &clock,
            ) {
                break 'engine;
            }
            maybe_run_maintenance(&mut coordinator, &mut wal_at_last_maintenance, &metrics);
        }
    }

    // The loop has exited (Shutdown or channel close): tear down the reader pool so no worker thread
    // outlives the engine. `shutdown` drops the work-queue sender (ending each worker's `recv`) and
    // joins them. Any reader still in flight finished its rows already (it sends the retirement after
    // its cursor drains); a retirement that arrives after the loop exited is dropped here — its
    // transaction was already rolled back by `Shutdown`'s `drain_inflight`, never left half-applied.
    if let read_pool::ReadDispatch::Threaded(pool) = dispatch {
        pool.shutdown();
    }
}

/// Drains and processes every reader retirement currently available on `retire_rx` (`rmp` task #336,
/// Slice 3b-ii), on the engine thread, in arrival order. Non-blocking: stops when the channel is
/// momentarily empty. Each retirement is finalised by [`finish_reader`].
fn process_retirements<D: BlockDevice, S: LogSink>(
    retire_rx: &std::sync::mpsc::Receiver<read_pool::ReadRetirement>,
    coordinator: &mut Option<TxnCoordinator<D, S>>,
    open: &mut HashMap<u64, OpenTx>,
    readers_inflight: &mut u64,
    metrics: &Metrics,
) {
    while let Ok(retirement) = retire_rx.try_recv() {
        if let Some(coord) = coordinator.as_mut() {
            finish_reader(coord, open, retirement, metrics);
        }
        *readers_inflight = readers_inflight.saturating_sub(1);
        metrics.set_active_txns(coordinator.as_ref().map_or(0, |c| c.active_count() as u64));
    }
}

/// Finalises an off-thread reader's retirement on the **engine thread** (`rmp` task #336, Slice
/// 3b-ii) — the M1 serializability barrier + the auto-commit.
///
/// 1. **Merge (M1):** fold the reader's SIREAD buffer into the shared SSI tracker *before* the
///    auto-commit's `detect_pivot_abort`, so the reader's rw-edges are present when its (or a
///    concurrent writer's) pivot is checked. Because this runs on the single engine thread, in the
///    retirement channel's arrival order, the no-lost-edge proof reduces to in-order event processing.
/// 2. **Auto-commit (the terminal-error contract):** on a clean `outcome`, `commit` the reader — which
///    may itself SSI-abort it (a writeless reader can be another transaction's pivot-victim). A commit
///    failure is sent as a **terminal error** through the still-open egress channel `row_tx`, exactly
///    as the inline auto-commit does (`exec::finish_autocommit`), so a rolled-back read is reported to
///    the client as failed — never a silent success. On an `outcome` error (a runtime / captured /
///    write-degrade error, R3) the reader is rolled back. Dropping `row_tx` here closes the stream.
/// 3. **De-registration:** `commit`/`rollback` remove the reader from the coordinator's active set,
///    releasing its hold on the GC watermark (`oldest_active_snapshot`) — only now, after its cursor
///    fully drained (the reader sent this retirement post-drain). The `open` ticket is removed too.
fn finish_reader<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    retirement: read_pool::ReadRetirement,
    metrics: &Metrics,
) {
    let read_pool::ReadRetirement {
        txn,
        ticket,
        buffer,
        outcome,
        row_tx,
    } = retirement;

    // (1) M1: merge the reader's SIREAD markers into the shared tracker BEFORE any commit's pivot
    // detection. On the single engine thread, so it is correctly ordered w.r.t. every other commit.
    coordinator.merge_read_buffer(buffer);

    // Remove the open-tx ticket (the engine owns its lifecycle now). A reader that the client
    // disconnected from mid-stream still retires here and is finalised exactly once.
    let still_open = open.remove(&ticket.0).is_some();

    if !still_open {
        // The ticket was already finalised (e.g. an explicit rollback raced the retirement). The
        // merge above is harmless; just drop the egress channel.
        drop(row_tx);
        return;
    }

    // (2) Auto-commit: commit on a clean outcome, roll back on a read error (R3 — a captured
    // deferral / write-degrade error must surface, never a silent commit over an untrustworthy read).
    match outcome {
        Ok(()) => match coordinator.commit(txn) {
            Ok(_) => metrics.record_commit(),
            Err(e) => {
                // The COMMIT failed (e.g. an SSI serialization abort): the transaction is rolled back.
                // Deliver the failure to the consumer as a terminal stream item BEFORE closing the
                // egress channel — a rolled-back auto-commit must be reported as failed/retriable, never
                // a silent success over undone work (`04 §1.3` step 6; the rmp #238 atomicity divergence).
                let _ = row_tx.send(Err(e));
                metrics.record_abort();
            }
        },
        Err(read_err) => {
            // The read itself errored (runtime / captured / write-degrade). The terminal error was
            // already streamed by the reader (`run_read_task` sends it for auth/deferral errors); roll
            // the transaction back so nothing is committed over an untrustworthy result.
            let _ = read_err; // already surfaced to the consumer by the reader.
            let _ = coordinator.rollback(txn);
            metrics.record_abort();
        }
    }
    // Closing the egress channel: every row + any terminal error has been sent.
    drop(row_tx);
}

/// Drives the **background maintenance cadence** (`rmp` #305): once the WAL has grown by
/// [`MAINTENANCE_CHECKPOINT_INTERVAL_BYTES`] since the last maintenance pass, run a
/// [`TxnCoordinator::checkpoint`] (reader-safe GC + sharp checkpoint) so RAM (the in-memory WAL tail),
/// disk (sealed WAL segments below the floor) and version slots are reclaimed without an operator
/// trigger. Called between commands on the engine thread, where the store is not borrowed by any
/// statement seam — the same discipline [`TxnCoordinator::with_store_mut`] requires; off-thread readers
/// hold a cloned read-view, never the store's `RefCell` borrow, so they do not conflict.
///
/// The GC watermark is derived from the oldest open reader's snapshot inside `checkpoint`, so a pass
/// run with readers in flight can never reclaim a version any of them must still observe (the #220
/// premature-reclamation guard). A maintenance failure is **logged and swallowed**: it must never take
/// the engine down (durability is unaffected — nothing was reclaimed below the floor), and the next
/// tick retries once more WAL accrues.
fn maybe_run_maintenance<D: BlockDevice, S: LogSink>(
    coordinator: &mut Option<TxnCoordinator<D, S>>,
    wal_at_last_maintenance: &mut u64,
    metrics: &Metrics,
) {
    let Some(coord) = coordinator.as_mut() else {
        return;
    };
    let durable = coord.wal_durable_len();
    if durable.saturating_sub(*wal_at_last_maintenance) < MAINTENANCE_CHECKPOINT_INTERVAL_BYTES {
        return;
    }
    match coord.checkpoint() {
        Ok(report) => {
            metrics.record_maintenance_checkpoint(report.reclaimed as u64, report.frozen as u64);
        }
        Err(e) => {
            // Never fatal: the floor was respected, so durability is intact; just record and retry later.
            tracing::warn!("background maintenance checkpoint failed (will retry): {e}");
        }
    }
    // Re-read: the checkpoint reclaimed the WAL prefix, so anchor the next interval at the new length.
    *wal_at_last_maintenance = coord.wal_durable_len();
}

/// Advances the front non-blocking index build by one [`INDEX_BUILD_CHUNK`] (`rmp` task #91). A
/// no-op when no build is pending. Kept tiny and inline-friendly so the loop's two call sites read
/// clearly.
fn drive_index_build<D: BlockDevice, S: LogSink>(coordinator: &mut Option<TxnCoordinator<D, S>>) {
    if let Some(coord) = coordinator.as_mut() {
        let _remaining = coord.advance_index_builds(INDEX_BUILD_CHUNK);
    }
}

/// Dispatches one [`EngineCommand`] against the coordinator. Returns `true` to keep the loop running,
/// `false` once a [`EngineCommand::Shutdown`] has drained + hardened the store (the loop then exits).
///
/// Factored out of [`run_engine_loop`] so the loop can choose its receive strategy (blocking vs.
/// build-driving timed receive) without duplicating the command-dispatch arm.
#[allow(clippy::too_many_arguments)] // The engine loop threads all execution context through here.
fn dispatch_command<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    cmd: EngineCommand,
    coordinator: &mut Option<TxnCoordinator<D, S>>,
    open: &mut HashMap<u64, OpenTx>,
    next_ticket: &mut u64,
    extensions: &Arc<graphus_cypher::extension::ExtensionRegistry>,
    dispatch: &read_pool::ReadDispatch<D, S>,
    readers_inflight: &mut u64,
    inflight: &mut Option<exec::InFlightInline>,
    result_buffer_capacity: usize,
    metrics: &Arc<Metrics>,
    clock: &Arc<dyn graphus_core::capability::Clock + Send + Sync>,
) -> bool {
    let coord = coordinator
        .as_mut()
        .expect("INVARIANT: coordinator is Some until Shutdown breaks the loop");
    match cmd {
        Cmd::Begin { mode, reply } => {
            let ticket = open_tx(coord, open, next_ticket, mode);
            metrics.set_active_txns(coord.active_count() as u64);
            let _ = reply.send(Ok(ticket));
        }
        Cmd::BeginAutoCommit { mode, reply } => {
            let ticket = open_tx(coord, open, next_ticket, mode);
            metrics.set_active_txns(coord.active_count() as u64);
            let _ = reply.send(Ok(ticket));
        }
        Cmd::Run {
            ticket,
            query,
            params,
            auto_commit,
            privileges,
            reply,
        } => {
            let outcome = exec::handle_run(
                coord,
                open,
                ticket,
                &query,
                params,
                auto_commit,
                privileges.map(|p| *p),
                extensions,
                dispatch,
                result_buffer_capacity,
                metrics,
                clock,
                reply,
            );
            match outcome {
                // A read dispatched off-thread retires later (it is not yet finalised); track it so
                // the engine loop polls the retirement channel until it returns.
                exec::RunOutcome::OffThreadReader => *readers_inflight += 1,
                // The egress channel filled with a slow consumer draining (`rmp` task #372): park the
                // statement so the loop resumes it one batch per tick without head-of-line-blocking
                // this thread. There is at most one in-flight inline statement (the engine processes
                // one `Run` at a time), so a single slot suffices.
                exec::RunOutcome::Suspended(parked) => {
                    debug_assert!(
                        inflight.is_none(),
                        "INVARIANT: at most one suspended inline statement at a time"
                    );
                    *inflight = Some(*parked);
                }
                // An inline statement that finished within its visit already committed/rolled back.
                exec::RunOutcome::Done => {}
            }
            metrics.set_active_txns(coord.active_count() as u64);
        }
        Cmd::Commit { ticket, reply } => {
            let out = commit_tx(coord, open, ticket, metrics);
            metrics.set_active_txns(coord.active_count() as u64);
            let _ = reply.send(out);
        }
        Cmd::Rollback { ticket, reply } => {
            let out = rollback_tx(coord, open, ticket, metrics);
            metrics.set_active_txns(coord.active_count() as u64);
            let _ = reply.send(out);
        }
        Cmd::Status { reply } => {
            let _ = reply.send(coord.active_count());
        }
        Cmd::IndexDdl { command, reply } => {
            let out = handle_index_ddl(coord, &command);
            let _ = reply.send(out);
        }
        Cmd::ConstraintDdl { command, reply } => {
            let out = handle_constraint_ddl(coord, &command);
            let _ = reply.send(out);
        }
        Cmd::Backup { reply } => {
            let out = handle_backup(coord);
            let _ = reply.send(out);
        }
        Cmd::Checkpoint { reply } => {
            let out = handle_checkpoint(coord);
            let _ = reply.send(out);
        }
        Cmd::Shutdown { reply } => {
            // Drain stragglers through `&mut`, then consume the coordinator for the final flush. An
            // in-flight index build is left durably `Populating`: it resumes and completes on the
            // next open via `TxnCoordinator::new`'s crash-recovery path (no force-drain needed —
            // re-deriving the candidate index is cheap and always correct).
            drain_inflight(coord, open, metrics);
            let coordinator = coordinator
                .take()
                .expect("INVARIANT: coordinator is Some at Shutdown");
            let out = harden_store(coordinator);
            metrics.set_active_txns(0);
            let _ = reply.send(out);
            // Drained + durable: signal the loop to exit so the thread can join.
            return false;
        }
    }
    true
}

/// Executes one index-DDL command against the coordinator's node-property index catalog (`rmp` task
/// #91). `CREATE` starts a non-blocking background build (returning promptly, no rows); `DROP`
/// removes the index (no rows); `SHOW INDEXES` lists every declared index with its build state.
///
/// Runs on the engine thread, so it may touch the (`!Send`) coordinator directly. The non-blocking
/// `CREATE` is what keeps the engine responsive: it enqueues the build and returns, and the loop
/// drives the build between subsequent commands.
fn handle_index_ddl<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    command: &IndexCommand,
) -> Result<IndexDdlReply> {
    match command {
        IndexCommand::CreateNodePropertyIndex { label, property } => {
            coordinator.begin_online_node_property_index(label, property)?;
            Ok(IndexDdlReply::default())
        }
        IndexCommand::DropNodePropertyIndex { label, property } => {
            coordinator.drop_node_property_index(label, property)?;
            Ok(IndexDdlReply::default())
        }
        IndexCommand::ShowIndexes => {
            let fields = vec![
                "label".to_owned(),
                "property".to_owned(),
                "state".to_owned(),
            ];
            let rows = coordinator
                .list_node_property_indexes()
                .into_iter()
                .map(|(label, property, state)| {
                    let state = match state {
                        IndexState::Online => "online",
                        IndexState::Populating => "populating",
                    };
                    vec![
                        Value::String(label),
                        Value::String(property),
                        Value::String(state.to_owned()),
                    ]
                })
                .collect();
            Ok(IndexDdlReply { fields, rows })
        }
        IndexCommand::CreateFulltextIndex {
            name,
            label,
            properties,
            analyzer,
        } => {
            // Validate the analyzer name against the supported set; an unknown one is a clear,
            // side-effect-free error (`rmp` task #72).
            let analyzer = graphus_cypher::Analyzer::from_name(analyzer).ok_or_else(|| {
                GraphusError::Compile(format!(
                    "unknown full-text analyzer {analyzer:?}; expected 'standard' or 'keyword'"
                ))
            })?;
            coordinator.create_fulltext_index(name, label, properties, analyzer)?;
            Ok(IndexDdlReply::default())
        }
        IndexCommand::DropFulltextIndex { name } => {
            coordinator.drop_fulltext_index(name)?;
            Ok(IndexDdlReply::default())
        }
        IndexCommand::ShowFulltextIndexes => {
            let fields = vec![
                "name".to_owned(),
                "label".to_owned(),
                "properties".to_owned(),
                "analyzer".to_owned(),
                "state".to_owned(),
            ];
            let rows = coordinator
                .list_fulltext_indexes()
                .into_iter()
                .map(|(name, label, properties, analyzer, state)| {
                    let state = match state {
                        IndexState::Online => "online",
                        IndexState::Populating => "populating",
                    };
                    vec![
                        Value::String(name),
                        Value::String(label),
                        // The covered properties as a Cypher list of strings.
                        Value::List(properties.into_iter().map(Value::String).collect()),
                        Value::String(analyzer.name().to_owned()),
                        Value::String(state.to_owned()),
                    ]
                })
                .collect();
            Ok(IndexDdlReply { fields, rows })
        }
        IndexCommand::CreatePointIndex {
            name,
            label,
            property,
        } => {
            // A spatial index has no analyzer to validate (unlike the full-text index): start the
            // non-blocking online build directly (`rmp` task #98).
            coordinator.create_point_index(name, label, property)?;
            Ok(IndexDdlReply::default())
        }
        IndexCommand::DropPointIndex { name } => {
            coordinator.drop_point_index(name)?;
            Ok(IndexDdlReply::default())
        }
        IndexCommand::ShowPointIndexes => {
            let fields = vec![
                "name".to_owned(),
                "label".to_owned(),
                "property".to_owned(),
                "state".to_owned(),
            ];
            let rows = coordinator
                .list_point_indexes()
                .into_iter()
                .map(|(name, label, property, state)| {
                    let state = match state {
                        IndexState::Online => "online",
                        IndexState::Populating => "populating",
                    };
                    vec![
                        Value::String(name),
                        Value::String(label),
                        Value::String(property),
                        Value::String(state.to_owned()),
                    ]
                })
                .collect();
            Ok(IndexDdlReply { fields, rows })
        }
    }
}

/// Captures an **online backup chain artifact** of the live store (`rmp` task #149) on the engine
/// thread, returning its encoded plaintext bytes.
///
/// The store is borrowed mutably (without consuming the coordinator — see
/// [`TxnCoordinator::with_store_mut`]) and a backup *chain* is captured rather than a bare full
/// artifact: `begin_chain` quiesces (flush + checkpoint) and frames the base full image at the WAL
/// watermark, then `capture_increment` appends the WAL tail accumulated since. The resulting
/// `(manifest, links)` pair restores to **any committed point** in `[base_lsn, tip]` via
/// `restore_to`/`restore_chain_file_atomic` — i.e. it supports PITR (`RestoreTarget::Latest`/`Lsn`/
/// `Timestamp`), not just a whole-snapshot restore.
///
/// The identity [`Plain`](graphus_storage::Plain) codec is used here: the chain bytes are plaintext.
/// Confidentiality at rest of the *operator backup file* is the catalog's responsibility (it seals
/// the encoded artifact under the master key when the database is encrypted, rmp #89), keeping the
/// `!Send` engine thread free of key material.
fn handle_backup<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
) -> Result<Vec<u8>> {
    use graphus_storage::{ChainArtifact, ChainLinks, Plain, begin_chain, capture_increment};

    coordinator.with_store_mut(|store| {
        let codec = Plain;
        // Base full artifact + the WAL watermark at base time.
        let (mut manifest, base) = begin_chain(store, &codec)?;
        // The WAL tail since the base watermark: an empty increment (no commits since the
        // checkpoint) is a benign zero-length marker that `restore_to` handles transparently.
        let increment = capture_increment(store, &mut manifest, &codec)?;
        let artifact = ChainArtifact {
            manifest,
            links: ChainLinks {
                base,
                increments: vec![increment],
            },
        };
        Ok(artifact.encode())
    })
}

/// Drives a maintenance checkpoint of the live store on the engine thread (`rmp` #305): a reader-safe
/// GC pass (reclaim + freeze, lowering the WAL reclaim floor) followed by a sharp store checkpoint
/// (flush dirty pages home + physically reclaim the WAL prefix below the floor). Releases RAM, disk
/// and version slots that previously had no production reclamation trigger (`rmp` #305 / #313 / #315).
/// Touches the (`!Send`) coordinator directly, between commands, never under a held statement seam.
fn handle_checkpoint<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
) -> Result<CheckpointReply> {
    let report = coordinator.checkpoint()?;
    Ok(CheckpointReply {
        reclaimed: report.reclaimed,
        frozen: report.frozen,
    })
}

/// Executes one constraint-DDL command against the coordinator's constraint catalog (`rmp` task
/// #99). `CREATE` validates existing data and declares the constraint synchronously (no rows; an
/// error without side effects if existing data violates it); `DROP` removes it (no rows);
/// `SHOW CONSTRAINTS` lists every declared constraint.
///
/// Runs on the engine thread, so it may touch the (`!Send`) coordinator directly. Unlike index DDL
/// there is no non-blocking build: a uniqueness constraint's backing index is (re)built synchronously
/// inside `create_constraint`, which is acceptable because schema DDL is rare and serialised.
fn handle_constraint_ddl<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    command: &ConstraintCommand,
) -> Result<IndexDdlReply> {
    match command {
        ConstraintCommand::CreateUnique {
            name,
            label,
            property,
        } => {
            coordinator.create_constraint(name, label, property, ConstraintKind::Unique)?;
            Ok(IndexDdlReply::default())
        }
        ConstraintCommand::CreateExistence {
            name,
            label,
            property,
        } => {
            coordinator.create_constraint(name, label, property, ConstraintKind::Existence)?;
            Ok(IndexDdlReply::default())
        }
        ConstraintCommand::CreateNodeKey {
            name,
            label,
            properties,
        } => {
            let props: Vec<&str> = properties.iter().map(String::as_str).collect();
            coordinator.create_constraint_general(
                name,
                label,
                &props,
                ConstraintKind::NodeKey,
                None,
            )?;
            Ok(IndexDdlReply::default())
        }
        ConstraintCommand::CreatePropertyType {
            name,
            label,
            property,
            declared_type,
        } => {
            coordinator.create_constraint_general(
                name,
                label,
                &[property],
                ConstraintKind::PropertyType,
                Some(declared_type.clone()),
            )?;
            Ok(IndexDdlReply::default())
        }
        ConstraintCommand::Drop { name } => {
            coordinator.drop_constraint(name)?;
            Ok(IndexDdlReply::default())
        }
        ConstraintCommand::Show => {
            let fields = vec![
                "name".to_owned(),
                "label".to_owned(),
                "property".to_owned(),
                "type".to_owned(),
            ];
            let rows = coordinator
                .list_constraints()
                .into_iter()
                .map(|info| {
                    // Neo4j-compatible `type` strings for `SHOW CONSTRAINTS`. A property-type constraint
                    // additionally appends its declared type (e.g. `NODE_PROPERTY_TYPE INTEGER`) so the
                    // declared type is visible in the listing.
                    let kind = match info.kind {
                        ConstraintKind::Unique => "UNIQUENESS".to_owned(),
                        ConstraintKind::Existence => "NODE_PROPERTY_EXISTENCE".to_owned(),
                        ConstraintKind::NodeKey => "NODE_KEY".to_owned(),
                        ConstraintKind::PropertyType => match &info.type_descriptor {
                            Some(d) => format!(
                                "NODE_PROPERTY_TYPE {}",
                                graphus_cypher::constraint::type_descriptor_name(d)
                            ),
                            None => "NODE_PROPERTY_TYPE".to_owned(),
                        },
                    };
                    // A composite node key lists its whole tuple, comma-separated.
                    let property = info.properties.join(", ");
                    vec![
                        Value::String(info.name),
                        Value::String(info.label),
                        Value::String(property),
                        Value::String(kind),
                    ]
                })
                .collect();
            Ok(IndexDdlReply { fields, rows })
        }
    }
}

/// Opens a transaction in the coordinator, tracks it, and returns its freshly-minted ticket.
fn open_tx<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    next_ticket: &mut u64,
    mode: AccessMode,
) -> TxTicket {
    let txn = coordinator.begin(mode.isolation());
    *next_ticket += 1;
    let ticket = *next_ticket;
    open.insert(ticket, OpenTx { txn, mode });
    TxTicket(ticket)
}

/// Commits the explicit transaction `ticket`. Translates a coordinator commit into a [`RunSummary`]
/// and bumps the commit/abort metrics (a serialization-failure abort counts as an abort).
fn commit_tx<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    ticket: TxTicket,
    metrics: &Metrics,
) -> Result<RunSummary> {
    let Some(tx) = open.remove(&ticket.0) else {
        return Err(GraphusError::Transaction(format!(
            "commit of unknown transaction {}",
            ticket.0
        )));
    };
    match coordinator.commit(tx.txn) {
        Ok(_commit_ts) => {
            metrics.record_commit();
            Ok(RunSummary::default())
        }
        Err(e) => {
            // The coordinator already rolled the victim back on a serialization failure; count it.
            metrics.record_abort();
            Err(e)
        }
    }
}

/// Rolls back `ticket`. Idempotent: an unknown ticket is `Ok(())` (mirrors the REST seam contract),
/// so the inactivity sweep and an explicit rollback cannot race into a spurious failure.
fn rollback_tx<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    ticket: TxTicket,
    metrics: &Metrics,
) -> Result<()> {
    let Some(tx) = open.remove(&ticket.0) else {
        // Idempotent no-op.
        return Ok(());
    };
    let out = coordinator.rollback(tx.txn);
    if out.is_ok() {
        metrics.record_abort();
    }
    out
}

/// Graceful-shutdown drain (`04 §9.4`), part 1: roll back every still-open transaction. Uncommitted
/// work is always safe to undo — recovery would undo it anyway — so a hard deadline upstream can
/// force this without risking durability. Runs through `&mut` so the coordinator can then be consumed
/// for the final flush.
fn drain_inflight<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    metrics: &Metrics,
) {
    // Collect tickets first to avoid borrowing `open` across the mutation.
    let tickets: Vec<u64> = open.keys().copied().collect();
    for t in tickets {
        if let Some(tx) = open.remove(&t) {
            // Best-effort: a rollback error on one straggler should not block hardening the rest.
            if coordinator.rollback(tx.txn).is_ok() {
                metrics.record_abort();
            }
        }
    }
}

/// Graceful-shutdown drain (`04 §9.4`), part 2: consume the (now transaction-free) coordinator to
/// reclaim the store, then flush dirty pages home and `sync_all` the device (the buffer pool enforces
/// the WAL rule before each write-back). Runs on the dedicated engine thread, so the blocking sync is
/// off the runtime (`04 §9.1`). This is the durable, clean checkpoint the superblock reflects on
/// reopen — the store dropping afterwards releases the device + WAL file handles.
fn harden_store<D: BlockDevice, S: LogSink>(coordinator: TxnCoordinator<D, S>) -> Result<()> {
    // Safe: `drain_inflight` left no open transaction and no statement seam is live here.
    let mut store: RecordStore<D, S> = coordinator.into_store();
    store.flush()
    // `store` drops here, closing the file-backed device and WAL sink cleanly.
}

/// The running engine: the client handle and the engine thread's join handle.
pub struct Engine {
    /// The shared, cloneable client every connection task uses.
    pub handle: EngineHandle,
    /// The engine thread, joined at shutdown (after [`EngineHandle::shutdown`] returns).
    pub join: std::thread::JoinHandle<()>,
}

/// Spawns the engine on a dedicated OS thread, **constructing the (`!Send`) coordinator inside that
/// thread** from the `Send` `build` closure, and returns the running [`Engine`] once startup
/// succeeds.
///
/// ## Why the coordinator is built on the thread
///
/// [`TxnCoordinator`] (and the [`RecordStore`] it owns) are `!Send` — they hold `Rc<RefCell<…>>`
/// internally — so they **cannot** be moved across the thread boundary. The only sound way to run a
/// `!Send` value on a dedicated thread is to construct it *there*, from `Send` ingredients (file
/// paths, config). So `build` runs on the engine thread and does the whole
/// open-device → recover → open-WAL → `RecordStore::open` → `verify_on_open` → `TxnCoordinator::new`
/// sequence; its `Result` (which is `Send`) is reported back so `Server::run` can fail startup
/// cleanly on a corrupt store (`04 §4.6`/§4.8).
///
/// The command channel is **bounded** by `engine_queue_capacity` (no unbounded channel on the
/// request path — `04 §9.3`). The thread name is `graphus-engine`.
///
/// # Errors
/// Returns the spawn error if the OS thread cannot be created, or the `build` error (e.g. an
/// integrity-check failure) if the store cannot be opened/verified.
pub fn spawn_engine<D, S, B>(
    build: B,
    engine_queue_capacity: usize,
    result_buffer_capacity: usize,
    reader_threads: usize,
    metrics: Arc<Metrics>,
    clock: Arc<dyn graphus_core::capability::Clock + Send + Sync>,
) -> Result<Engine>
where
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
    B: FnOnce() -> Result<TxnCoordinator<D, S>> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel::<EngineCommand>(engine_queue_capacity);
    // Report startup success/failure back from the thread (a `Send` `Result`), so the coordinator
    // itself never crosses the boundary.
    let (init_tx, init_rx) = std::sync::mpsc::sync_channel::<Result<()>>(1);
    let loop_metrics = Arc::clone(&metrics);
    let join = std::thread::Builder::new()
        .name("graphus-engine".to_owned())
        .spawn(move || match build() {
            Ok(coordinator) => {
                // Startup succeeded: signal readiness, then run the loop until Shutdown. The loop
                // spawns the off-thread reader pool internally (`rmp` task #336, Slice 3b-ii).
                let _ = init_tx.send(Ok(()));
                run_engine_loop(
                    coordinator,
                    rx,
                    result_buffer_capacity,
                    reader_threads,
                    loop_metrics,
                    clock,
                );
            }
            Err(e) => {
                // Startup failed (e.g. corrupt store): report it and exit without serving.
                let _ = init_tx.send(Err(e));
            }
        })
        .map_err(|e| GraphusError::Storage(format!("spawning engine thread: {e}")))?;

    // Wait for the thread's startup result before returning a usable handle.
    match init_rx.recv() {
        Ok(Ok(())) => Ok(Engine {
            handle: EngineHandle::new(tx, metrics),
            join,
        }),
        Ok(Err(e)) => {
            // The thread already exited; join it to avoid a detached thread, then surface the error.
            let _ = join.join();
            Err(e)
        }
        Err(_) => {
            let _ = join.join();
            Err(GraphusError::Storage(
                "engine thread exited before reporting startup".to_owned(),
            ))
        }
    }
}
