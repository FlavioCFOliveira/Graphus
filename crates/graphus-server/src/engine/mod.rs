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

pub mod command;
mod exec;
mod handle;
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

pub use command::{AccessMode, EngineCommand, RunReply, RunSummary};
pub use handle::{EngineHandle, ServerBusy};
pub use seam_bolt::BoltEngineExecutor;
pub use seam_rest::RestEngineAdapter;

use crate::metrics::Metrics;
use command::EngineCommand as Cmd;
use graphus_core::TxnId;

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
fn run_engine_loop<D: BlockDevice, S: LogSink>(
    coordinator: TxnCoordinator<D, S>,
    rx: std::sync::mpsc::Receiver<EngineCommand>,
    result_buffer_capacity: usize,
    metrics: Arc<Metrics>,
) {
    let mut open: HashMap<u64, OpenTx> = HashMap::new();
    let mut next_ticket: u64 = 0;
    // Held in an `Option` so the terminal `Shutdown` can move the coordinator out to consume it for
    // the final flush (`TxnCoordinator::into_store` is by-value). It is always `Some` while the loop
    // is processing commands.
    let mut coordinator = Some(coordinator);

    while let Ok(cmd) = rx.recv() {
        let coord = coordinator
            .as_mut()
            .expect("INVARIANT: coordinator is Some until Shutdown breaks the loop");
        match cmd {
            Cmd::Begin { mode, reply } => {
                let ticket = open_tx(coord, &mut open, &mut next_ticket, mode);
                metrics.set_active_txns(coord.active_count() as u64);
                let _ = reply.send(Ok(ticket));
            }
            Cmd::BeginAutoCommit { mode, reply } => {
                let ticket = open_tx(coord, &mut open, &mut next_ticket, mode);
                metrics.set_active_txns(coord.active_count() as u64);
                let _ = reply.send(Ok(ticket));
            }
            Cmd::Run {
                ticket,
                query,
                params,
                auto_commit,
                reply,
            } => {
                exec::handle_run(
                    coord,
                    &mut open,
                    ticket,
                    &query,
                    params,
                    auto_commit,
                    result_buffer_capacity,
                    &metrics,
                    reply,
                );
                metrics.set_active_txns(coord.active_count() as u64);
            }
            Cmd::Commit { ticket, reply } => {
                let out = commit_tx(coord, &mut open, ticket, &metrics);
                metrics.set_active_txns(coord.active_count() as u64);
                let _ = reply.send(out);
            }
            Cmd::Rollback { ticket, reply } => {
                let out = rollback_tx(coord, &mut open, ticket, &metrics);
                metrics.set_active_txns(coord.active_count() as u64);
                let _ = reply.send(out);
            }
            Cmd::Status { reply } => {
                let _ = reply.send(coord.active_count());
            }
            Cmd::Shutdown { reply } => {
                // Drain stragglers through `&mut`, then consume the coordinator for the final flush.
                drain_inflight(coord, &mut open, &metrics);
                let coordinator = coordinator
                    .take()
                    .expect("INVARIANT: coordinator is Some at Shutdown");
                let out = harden_store(coordinator);
                metrics.set_active_txns(0);
                let _ = reply.send(out);
                // Drained + durable: leave the loop so the thread can join.
                break;
            }
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
    metrics: Arc<Metrics>,
) -> Result<Engine>
where
    D: BlockDevice + 'static,
    S: LogSink + 'static,
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
                // Startup succeeded: signal readiness, then run the loop until Shutdown.
                let _ = init_tx.send(Ok(()));
                run_engine_loop(coordinator, rx, result_buffer_capacity, loop_metrics);
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
