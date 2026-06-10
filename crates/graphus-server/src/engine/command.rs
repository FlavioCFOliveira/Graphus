//! The command protocol between the connection tasks (Bolt/REST) and the single engine task
//! (`04-technical-design.md` §9.1: the sharded write/ACID path; v1 = one shard).
//!
//! The cypher engine is single-threaded (`!Sync`, `Rc<RefCell<…>>`-backed — see the crate docs and
//! [`graphus_cypher::TxnCoordinator`]), but the server is a multi-threaded Tokio runtime. We bridge
//! the two by funnelling **all** query execution through one engine thread that owns the
//! [`graphus_storage::RecordStore`] + `TxnCoordinator`, and serving [`EngineCommand`]s over a
//! **bounded** channel. Each connection submits a command carrying its authenticated identity +
//! access mode and a [`tokio::sync::oneshot`] reply sender, then awaits the reply.
//!
//! Reads serialize through the engine too in v1; lock-free concurrent reads against committed
//! versions are the documented follow-up (`04 §9.1`).

use graphus_core::{GraphusError, Value};

use super::stream::RowReceiver;
use crate::engine::TxTicket;

/// The engine's end of a command reply: a one-shot, capacity-1 [`std::sync::mpsc::SyncSender`].
///
/// Replies use a **std** channel (not `tokio::sync::oneshot`) deliberately. The blocking seams (Bolt,
/// and REST whose synchronous handlers run inside a `Handle::block_on` on a blocking thread) must be
/// able to receive a reply **synchronously**; `oneshot::blocking_recv` panics when called inside a
/// runtime context (which `Handle::block_on` establishes), whereas a std `recv` has no such guard and
/// works on any thread. The async [`crate::engine::EngineHandle`] methods (admin/shutdown) await the
/// std receive via `spawn_blocking`.
pub struct Reply<T>(std::sync::mpsc::SyncSender<T>);

impl<T> Reply<T> {
    /// Sends the reply, returning `Err(value)` if the receiver was already dropped (e.g. a
    /// disconnected client). The engine uses the error to detect a gone consumer and clean up an
    /// orphaned auto-commit transaction.
    pub fn send(self, value: T) -> Result<(), T> {
        self.0.send(value).map_err(|e| e.0)
    }
}

/// The submitter's end of a command reply.
pub struct ReplyReceiver<T>(std::sync::mpsc::Receiver<T>);

impl<T> ReplyReceiver<T> {
    /// Blocking receive — usable on any thread (no runtime-context guard).
    ///
    /// # Errors
    /// Returns `Err` if the engine dropped the sender (engine gone).
    pub fn recv(self) -> Result<T, std::sync::mpsc::RecvError> {
        self.0.recv()
    }
}

/// Creates a one-shot reply channel (capacity 1).
#[must_use]
pub fn reply_channel<T>() -> (Reply<T>, ReplyReceiver<T>) {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    (Reply(tx), ReplyReceiver(rx))
}

/// The access mode of a transaction, unified across both connectivity seams.
///
/// `graphus_bolt::AccessMode` and `graphus_rest::AccessMode` are distinct types (each crate owns
/// its own), so the engine carries this neutral copy and the adapters convert at their boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessMode {
    /// Read-only: write statements are rejected.
    Read,
    /// Read-write (the default).
    #[default]
    Write,
}

/// The reply to a [`EngineCommand::Run`]: the result column names and a bounded receiver the caller
/// pulls rows from, or the engine's error if the query failed before producing any row.
#[derive(Debug)]
pub struct RunReply {
    /// The result column names, in projection order (the `fields` metadata).
    pub fields: Vec<String>,
    /// The bounded row stream; pull rows until it yields `None` (exhausted) or a row `Err`.
    pub rows: RowReceiver,
}

/// One request to the engine task. Every variant carries a `oneshot` sender for its reply, so the
/// submitting (async) task awaits the engine's serial execution without blocking a runtime worker.
pub enum EngineCommand {
    /// Open an explicit transaction in `mode`, replying with its [`TxTicket`].
    Begin {
        /// Read/write access mode for the transaction.
        mode: AccessMode,
        /// Reply channel: the new transaction's ticket, or a transaction error.
        reply: Reply<Result<TxTicket, GraphusError>>,
    },
    /// Run `query` with `params` inside the transaction identified by `ticket`, replying with the
    /// result stream (or the engine error if it failed before the first row).
    ///
    /// `auto_commit` requests the auto-commit shape: the engine commits the (internally-opened)
    /// transaction once the result stream is fully consumed. For an explicit transaction the caller
    /// drives `Commit`/`Rollback` itself.
    Run {
        /// The transaction to run within.
        ticket: TxTicket,
        /// The Cypher query text.
        query: String,
        /// Bound parameters as `(name, value)` pairs.
        params: Vec<(String, Value)>,
        /// Whether this is an auto-commit statement (commit on stream exhaustion).
        auto_commit: bool,
        /// Reply channel: the result stream, or a compile/runtime/transaction error.
        reply: Reply<Result<RunReply, GraphusError>>,
    },
    /// Begin an auto-commit transaction, returning its ticket. Used by the seams to open the
    /// implicit transaction a bare `RUN` / `POST …/tx/commit` runs in (the engine commits it when
    /// the resulting [`EngineCommand::Run`]'s stream is drained, when `auto_commit` is set).
    BeginAutoCommit {
        /// Read/write access mode.
        mode: AccessMode,
        /// Reply channel: the implicit transaction's ticket.
        reply: Reply<Result<TxTicket, GraphusError>>,
    },
    /// Commit the explicit transaction identified by `ticket`, replying with its summary.
    Commit {
        /// The transaction to commit.
        ticket: TxTicket,
        /// Reply channel: the commit summary, or a (possibly retriable) transaction error.
        reply: Reply<Result<RunSummary, GraphusError>>,
    },
    /// Roll back the transaction identified by `ticket`. Idempotent: rolling back an unknown ticket
    /// is `Ok(())` so the REST inactivity sweep and an explicit `DELETE` cannot race into a spurious
    /// failure (mirrors `graphus_rest::RestEngine::rollback`).
    Rollback {
        /// The transaction to roll back.
        ticket: TxTicket,
        /// Reply channel: `Ok(())` on success or idempotent no-op, else a genuine engine fault.
        reply: Reply<Result<(), GraphusError>>,
    },
    /// Drain in-flight transactions for graceful shutdown (`04 §9.4`): roll back every still-open
    /// transaction, flush + sync the store, and reply once the store is durable and clean. After
    /// this the engine task exits its loop.
    Shutdown {
        /// Reply channel: `Ok(())` once drained + durable, else the flush/sync error.
        reply: Reply<Result<(), GraphusError>>,
    },
    /// Publish the current open-transaction count to the metrics gauge (cheap status probe). Used by
    /// the admin status endpoint and periodic observability.
    Status {
        /// Reply channel: the number of currently-open transactions.
        reply: Reply<usize>,
    },
}

/// The summary metadata for a finished result / committed transaction, unified across both seams.
///
/// Mirrors `graphus_bolt::QuerySummary` / `graphus_rest::RunSummary`; the adapters convert at their
/// boundary so the engine carries one neutral type.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunSummary {
    /// The query type code (`"r"`/`"rw"`/`"w"`/`"s"`), if known.
    pub query_type: Option<String>,
    /// Side-effect counters (e.g. `nodes-created`), in order.
    pub stats: Vec<(String, Value)>,
}
