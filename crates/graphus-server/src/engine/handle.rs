//! [`EngineHandle`] — the `Send + Sync`, cloneable client of the single engine task
//! (`04-technical-design.md` §9.1, §9.3).
//!
//! Every connection task (Bolt session, REST handler) holds a clone of the handle and submits
//! [`EngineCommand`]s through it. The handle also owns the **global admission semaphore** (`04 §9.3`):
//! a query must acquire a permit before it executes, and excess work is **fast-rejected** with a
//! retriable "server busy" error rather than queuing unboundedly.
//!
//! The command channel is a **bounded** `std::sync::mpsc::SyncSender` (set at [`super::spawn_engine`]),
//! so even the submission path exerts backpressure (no unbounded channel — `04 §9.3`). Submitting
//! from an async context never blocks a runtime worker: a non-full channel sends immediately, and the
//! rare full-channel case is bridged through `spawn_blocking`. The reply is awaited on a `oneshot`.

use std::sync::Arc;

use graphus_core::{GraphusError, Value};
use tokio::sync::Semaphore;

use super::TxTicket;
use super::command::{
    AccessMode, ConstraintCommand, EngineCommand, IndexCommand, IndexDdlReply, ReplyReceiver,
    RunReply, RunSummary, reply_channel,
};
use super::privileges::EffectivePrivileges;
use crate::metrics::Metrics;

/// A permit proving a query has been admitted; releasing it (on drop) frees a slot and decrements
/// the in-flight gauge. Held for the duration of a query's execution + streaming.
#[derive(Debug)]
pub struct AdmissionPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    metrics: Arc<Metrics>,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        self.metrics.record_admission_released();
    }
}

/// The error a fast-reject produces: the server is at its admission limit and the client should
/// retry (`04 §9.3`). Mapped to a Bolt `TransientError` / REST `503` by the seams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerBusy;

impl std::fmt::Display for ServerBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("server busy: admission limit reached, retry")
    }
}

impl std::error::Error for ServerBusy {}

/// The shared, cloneable client of the engine task.
#[derive(Clone)]
pub struct EngineHandle {
    /// Bounded command channel to the engine thread.
    tx: std::sync::mpsc::SyncSender<EngineCommand>,
    /// Global admission control: a bounded count of concurrently-executing queries (`04 §9.3`).
    admission: Arc<Semaphore>,
    /// Observability counters.
    metrics: Arc<Metrics>,
}

impl EngineHandle {
    /// Builds a handle over the engine's command sender. The admission limit is configured later via
    /// [`with_admission_limit`](Self::with_admission_limit) (the server sets it from config); until
    /// then a generous default is used so unit tests need no setup.
    #[must_use]
    pub(super) fn new(
        tx: std::sync::mpsc::SyncSender<EngineCommand>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            tx,
            admission: Arc::new(Semaphore::new(Semaphore::MAX_PERMITS)),
            metrics,
        }
    }

    /// Sets the global admission limit (max concurrently-executing queries, `04 §9.3`).
    ///
    /// Returns a new handle sharing the same engine channel + metrics but with a fresh semaphore of
    /// `max_concurrent` permits. Called once by the server at startup.
    #[must_use]
    pub fn with_admission_limit(&self, max_concurrent: usize) -> Self {
        Self {
            tx: self.tx.clone(),
            admission: Arc::new(Semaphore::new(max_concurrent.max(1))),
            metrics: Arc::clone(&self.metrics),
        }
    }

    /// The shared metrics registry.
    #[must_use]
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Tries to admit a query: acquires an admission permit without waiting, or fast-rejects with
    /// [`ServerBusy`] when the limit is reached (`04 §9.3` load shedding). The returned permit must
    /// be held for the query's whole execution + result streaming.
    ///
    /// # Errors
    /// [`ServerBusy`] if no permit is available (the caller maps it to a retriable busy error).
    pub fn try_admit(&self) -> Result<AdmissionPermit, ServerBusy> {
        match Arc::clone(&self.admission).try_acquire_owned() {
            Ok(permit) => {
                self.metrics.record_admission_acquired();
                Ok(AdmissionPermit {
                    _permit: permit,
                    metrics: Arc::clone(&self.metrics),
                })
            }
            Err(_) => {
                self.metrics.record_admission_rejection();
                Err(ServerBusy)
            }
        }
    }

    // ---- Async submit (REST handlers await these directly) ---------------------------------------

    /// Opens an explicit transaction in `mode`.
    ///
    /// # Errors
    /// [`GraphusError`] if the engine cannot start the transaction (or the engine is shut down).
    pub async fn begin(&self, mode: AccessMode) -> Result<TxTicket, GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit(EngineCommand::Begin { mode, reply }).await?;
        recv_async(rx).await?
    }

    /// Opens an internal auto-commit transaction in `mode` (the engine commits it when the matching
    /// [`run`](Self::run) with `auto_commit = true` drains its stream).
    ///
    /// # Errors
    /// [`GraphusError`] as [`begin`](Self::begin).
    pub async fn begin_auto_commit(&self, mode: AccessMode) -> Result<TxTicket, GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit(EngineCommand::BeginAutoCommit { mode, reply })
            .await?;
        recv_async(rx).await?
    }

    /// Runs `query` with `params` inside `ticket`, returning the result stream.
    ///
    /// `privileges` carries the principal's resolved fine-grained RBAC for this statement (rmp #93);
    /// `None` (or an admin/unrestricted set) disables filtering. See [`EngineCommand::Run`].
    ///
    /// # Errors
    /// [`GraphusError`] for a compile/runtime/transaction error raised before the first row.
    pub async fn run(
        &self,
        ticket: TxTicket,
        query: String,
        params: Vec<(String, Value)>,
        auto_commit: bool,
        privileges: Option<EffectivePrivileges>,
    ) -> Result<RunReply, GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit(EngineCommand::Run {
            ticket,
            query,
            params,
            auto_commit,
            privileges: privileges.map(Box::new),
            reply,
        })
        .await?;
        recv_async(rx).await?
    }

    /// Commits the explicit transaction `ticket`.
    ///
    /// # Errors
    /// [`GraphusError`] on an unknown ticket or a serialization failure (retriable).
    pub async fn commit(&self, ticket: TxTicket) -> Result<RunSummary, GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit(EngineCommand::Commit { ticket, reply }).await?;
        recv_async(rx).await?
    }

    /// Rolls back `ticket` (idempotent for an unknown ticket).
    ///
    /// # Errors
    /// [`GraphusError`] only for a genuine engine fault.
    pub async fn rollback(&self, ticket: TxTicket) -> Result<(), GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit(EngineCommand::Rollback { ticket, reply })
            .await?;
        recv_async(rx).await?
    }

    /// Drains in-flight work, flushes + syncs the store, and asks the engine to exit (`04 §9.4`).
    ///
    /// # Errors
    /// [`GraphusError`] if the final flush/sync fails.
    pub async fn shutdown(&self) -> Result<(), GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit(EngineCommand::Shutdown { reply }).await?;
        recv_async(rx).await?
    }

    /// The number of currently-open transactions (status probe).
    ///
    /// # Errors
    /// [`GraphusError`] if the engine is shut down.
    pub async fn status_open_txns(&self) -> Result<usize, GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit(EngineCommand::Status { reply }).await?;
        recv_async(rx).await
    }

    /// Submits an index-DDL statement (`CREATE/DROP INDEX`, `SHOW INDEXES`) to the engine, returning
    /// its buffered fields + rows (`rmp` task #91). `CREATE` starts a **non-blocking** background
    /// build and returns promptly, so the await completes without waiting for the index to populate.
    ///
    /// Index DDL takes **no admission permit**: like the DATABASE admin commands it is a control
    /// operation, not a query, and the engine serialises it itself. The caller is responsible for the
    /// admin-privilege gate **before** calling this (see [`crate::admin::AdminContext::authorize_admin`]).
    ///
    /// # Errors
    /// [`GraphusError`] for a storage fault while declaring/dropping/listing the index, or if the
    /// engine is shut down.
    pub async fn index_ddl(&self, command: IndexCommand) -> Result<IndexDdlReply, GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit(EngineCommand::IndexDdl { command, reply })
            .await?;
        recv_async(rx).await?
    }

    /// Executes a **constraint-DDL** statement (`CREATE/DROP CONSTRAINT`, `SHOW CONSTRAINTS`) against
    /// the coordinator's constraint catalog (`rmp` task #99). Like [`index_ddl`](Self::index_ddl) this
    /// takes **no admission permit** (it is schema control, not a query) and the caller is responsible
    /// for the admin-privilege gate before calling it.
    ///
    /// # Errors
    /// [`GraphusError::Runtime`] (constraint-validation class) if existing data violates a `CREATE`,
    /// a storage fault while declaring/dropping/listing, or if the engine is shut down.
    pub async fn constraint_ddl(
        &self,
        command: ConstraintCommand,
    ) -> Result<IndexDdlReply, GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit(EngineCommand::ConstraintDdl { command, reply })
            .await?;
        recv_async(rx).await?
    }

    // ---- Blocking submit (the Bolt session, on a blocking task, uses these) ----------------------

    /// Blocking variant of [`begin`](Self::begin) for the synchronous Bolt seam (called on a
    /// `spawn_blocking` thread — see the `listeners::bolt` module).
    ///
    /// # Errors
    /// As [`begin`](Self::begin).
    pub fn begin_blocking(&self, mode: AccessMode) -> Result<TxTicket, GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit_blocking(EngineCommand::Begin { mode, reply })?;
        recv_blocking(rx)?
    }

    /// Blocking variant of [`begin_auto_commit`](Self::begin_auto_commit).
    ///
    /// # Errors
    /// As [`begin_auto_commit`](Self::begin_auto_commit).
    pub fn begin_auto_commit_blocking(&self, mode: AccessMode) -> Result<TxTicket, GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit_blocking(EngineCommand::BeginAutoCommit { mode, reply })?;
        recv_blocking(rx)?
    }

    /// Blocking variant of [`run`](Self::run).
    ///
    /// # Errors
    /// As [`run`](Self::run).
    pub fn run_blocking(
        &self,
        ticket: TxTicket,
        query: String,
        params: Vec<(String, Value)>,
        auto_commit: bool,
        privileges: Option<EffectivePrivileges>,
    ) -> Result<RunReply, GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit_blocking(EngineCommand::Run {
            ticket,
            query,
            params,
            auto_commit,
            privileges: privileges.map(Box::new),
            reply,
        })?;
        recv_blocking(rx)?
    }

    /// Blocking variant of [`commit`](Self::commit).
    ///
    /// # Errors
    /// As [`commit`](Self::commit).
    pub fn commit_blocking(&self, ticket: TxTicket) -> Result<RunSummary, GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit_blocking(EngineCommand::Commit { ticket, reply })?;
        recv_blocking(rx)?
    }

    /// Blocking variant of [`rollback`](Self::rollback).
    ///
    /// # Errors
    /// As [`rollback`](Self::rollback).
    pub fn rollback_blocking(&self, ticket: TxTicket) -> Result<(), GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit_blocking(EngineCommand::Rollback { ticket, reply })?;
        recv_blocking(rx)?
    }

    /// Blocking variant of [`index_ddl`](Self::index_ddl) for the synchronous Bolt/REST seams (called
    /// on a `spawn_blocking` thread / inside a `Handle::block_on`).
    ///
    /// # Errors
    /// As [`index_ddl`](Self::index_ddl).
    pub fn index_ddl_blocking(&self, command: IndexCommand) -> Result<IndexDdlReply, GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit_blocking(EngineCommand::IndexDdl { command, reply })?;
        recv_blocking(rx)?
    }

    /// Blocking variant of [`constraint_ddl`](Self::constraint_ddl) for the synchronous Bolt/REST
    /// seams (called on a `spawn_blocking` thread / inside a `Handle::block_on`).
    ///
    /// # Errors
    /// As [`constraint_ddl`](Self::constraint_ddl).
    pub fn constraint_ddl_blocking(
        &self,
        command: ConstraintCommand,
    ) -> Result<IndexDdlReply, GraphusError> {
        let (reply, rx) = reply_channel();
        self.submit_blocking(EngineCommand::ConstraintDdl { command, reply })?;
        recv_blocking(rx)?
    }

    // ---- internals ------------------------------------------------------------------------------

    /// Sends a command to the engine from an async context without blocking a runtime worker.
    ///
    /// A non-full bounded channel sends immediately. On the rare full-channel case the blocking
    /// `send` is offloaded to `spawn_blocking` so the worker is never parked on the channel (the same
    /// pattern `graphus_io::FsyncPool` uses for its bounded submit path — `04 §9.3`).
    async fn submit(&self, cmd: EngineCommand) -> Result<(), GraphusError> {
        match self.tx.try_send(cmd) {
            Ok(()) => Ok(()),
            Err(std::sync::mpsc::TrySendError::Full(cmd)) => {
                let tx = self.tx.clone();
                tokio::task::spawn_blocking(move || tx.send(cmd))
                    .await
                    .map_err(|e| GraphusError::Runtime(format!("engine submit join: {e}")))?
                    .map_err(|_| engine_gone())
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => Err(engine_gone()),
        }
    }

    /// Blocking send for the synchronous (Bolt) seam: parks the calling blocking thread on a full
    /// bounded channel (the intended submission backpressure), never a runtime worker.
    fn submit_blocking(&self, cmd: EngineCommand) -> Result<(), GraphusError> {
        self.tx.send(cmd).map_err(|_| engine_gone())
    }
}

/// Awaits a std reply from an async context by offloading the blocking `recv` to `spawn_blocking`,
/// so a runtime worker is never parked on the channel (`04 §9.1`). Maps a dropped sender (engine
/// gone) to a transaction error.
async fn recv_async<T: Send + 'static>(rx: ReplyReceiver<T>) -> Result<T, GraphusError> {
    tokio::task::spawn_blocking(move || rx.recv())
        .await
        .map_err(|e| GraphusError::Runtime(format!("engine reply join: {e}")))?
        .map_err(|_| engine_gone())
}

/// Receives a std reply synchronously (the blocking seams). Usable on any thread — including inside a
/// `Handle::block_on` (the REST bridge) — because a std `recv` has no runtime-context guard.
fn recv_blocking<T>(rx: ReplyReceiver<T>) -> Result<T, GraphusError> {
    rx.recv().map_err(|_| engine_gone())
}

/// The error when the engine task has stopped (channel closed / reply dropped).
fn engine_gone() -> GraphusError {
    GraphusError::Transaction("engine unavailable (server shutting down)".to_owned())
}

impl std::fmt::Debug for EngineHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineHandle")
            .field("admission_permits", &self.admission.available_permits())
            .finish_non_exhaustive()
    }
}
