//! [`LocalEngine`] — the **inline, single-threaded, deterministic** engine driver
//! (`04-technical-design.md` §11 Deterministic Simulation Testing; decision `D-dst-investment`).
//!
//! ## Why a second engine driver
//!
//! Production runs the (`!Send`) [`graphus_cypher::TxnCoordinator`] on a **dedicated OS thread**
//! reached through a bounded channel ([`super::EngineHandle`] / [`super::spawn_engine`]). That model
//! is correct for a multi-threaded Tokio server, but it is **non-deterministic**: thread scheduling,
//! channel wake-ups and the wall clock all leak timing into behaviour, so a run cannot be replayed
//! bit-for-bit from a seed.
//!
//! The external Deterministic Simulation Testing harness (TigerBeetle's VOPR model, adapted) needs
//! the *exact opposite*: the **real** engine running in **one thread**, driven step-by-step, with a
//! **simulated clock** ([`graphus_sim::SimClock`], injected as a [`Clock`]) so the same seed yields
//! the same execution. `LocalEngine` is that driver. It reuses the production command-dispatch logic
//! **verbatim** — [`super::dispatch_command`] → [`super::exec::handle_run`] → the coordinator — so the
//! simulator exercises the *same* code paths the server does, not a parallel re-implementation.
//!
//! ## How it stays single-threaded
//!
//! `handle_run` streams result rows into a **bounded** egress channel and relies on a *concurrent*
//! consumer to drain it (the threaded server has one). With no second thread, a bounded channel would
//! dead-lock once full. `LocalEngine` therefore drives execution with an **effectively-unbounded**
//! egress capacity ([`LOCAL_RESULT_BUFFER`]): every row a statement produces is buffered, the
//! producer never blocks, and the caller drains the [`RowReceiver`] afterwards. Memory is bounded by
//! the result size — acceptable (and observable) in a simulation.
//!
//! Each `dispatch` runs to completion before returning, sending its reply over a one-shot channel the
//! same call then receives — a fully synchronous request/response with no thread hand-off.

use std::collections::HashMap;
use std::sync::Arc;

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_core::error::{GraphusError, Result};
use graphus_cypher::TxnCoordinator;
use graphus_cypher::extension::ExtensionRegistry;
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::RecordStore;
use graphus_wal::{LogSink, MemLogSink, WalManager};

use super::bulk_load::{BulkImportBatchInput, BulkImportBatchOutcome, LoadingSession};
use super::bulk_load_b::{BulkImportModeBChunkInput, BulkImportModeBChunkOutcome};
use super::command::{
    AccessMode, ConstraintCommand, EngineCommand, IndexCommand, IndexDdlReply, RunReply,
    RunSummary, reply_channel,
};
use super::privileges::EffectivePrivileges;
use super::read_pool::ReadDispatch;
use super::{OpenTx, TxTicket, dispatch_command};
use crate::metrics::Metrics;

/// The egress capacity used for the inline driver: **unbounded** so a single-threaded statement never
/// blocks on a full result channel with no concurrent consumer (see the module docs). The production
/// path uses a small bounded capacity for backpressure (`04 §9.3`); that trade-off (backpressure) is
/// deliberately swapped for determinism here.
const LOCAL_RESULT_BUFFER: usize = super::stream::UNBOUNDED;

/// How many index entries an inline index build advances per step while draining a non-blocking
/// build to completion. Large enough that any realistic simulation index finishes in one step.
///
/// NOTE for tests (`rmp` task #573): because this is unbounded, [`LocalEngine::dispatch`]'s post-command
/// drain finishes the **entire** build — so *any* command completes it, whatever the store's size. A test
/// that wants to observe a build mid-flight must therefore not observe it through a dispatched command:
/// the observation would consume what it measures, and seeding more nodes cannot buy a longer window.
/// Use the coordinator directly (see the test module's `show_index_row_no_drain`).
const LOCAL_INDEX_BUILD_BUDGET: usize = usize::MAX;

/// An inline, single-threaded driver of the real Graphus engine for Deterministic Simulation Testing.
///
/// Owns the (`!Send`) [`TxnCoordinator`] directly and dispatches each operation synchronously on the
/// calling thread. Construct one over the simulated in-memory store with [`Self::in_memory`], or over
/// an arbitrary already-built coordinator with [`Self::new`].
pub struct LocalEngine<D: BlockDevice, S: LogSink> {
    /// The real coordinator, in an `Option` so [`Self::shutdown`] can consume it (mirrors the engine
    /// loop). `Some` until shutdown.
    coordinator: Option<TxnCoordinator<D, S>>,
    /// Open transactions, keyed by the ticket id the engine mints (same bookkeeping the loop keeps).
    open: HashMap<u64, OpenTx>,
    /// Monotonic ticket counter (same as the loop's).
    next_ticket: u64,
    /// The compiled-in UDF/UDP + GDS registry, built once (as the engine thread does). `Arc`-wrapped to
    /// match the threaded engine's shape (`rmp` task #336); the inline driver never moves it to a
    /// thread, but the shared signature keeps one execution path.
    extensions: Arc<ExtensionRegistry>,
    /// The read dispatcher: **always [`ReadDispatch::Inline`]** for the deterministic driver (`rmp`
    /// task #336, Slice 3b-ii). Read-only statements run **inline on the calling thread**, not on a
    /// reader pool — so the same seed yields the same execution (no OS thread to interleave), keeping
    /// the DST/VOPR/Elle harness bit-deterministic. This is the load-bearing duality: production injects
    /// [`ReadDispatch::Threaded`]; the simulator injects [`ReadDispatch::Inline`].
    dispatch: ReadDispatch<D, S>,
    /// A throwaway in-flight-reader counter `dispatch_command` writes through; under inline dispatch a
    /// read never dispatches off-thread, so this stays `0` (every statement finalises synchronously).
    readers_inflight: u64,
    /// The engine's compiled-plan cache (`rmp` task #322), mirroring the threaded loop. Inline and
    /// single-threaded by construction, so the same reuse + schema-version invalidation applies, and
    /// the same seed still yields the same execution (the cache changes *how fast* a plan is obtained,
    /// never *which* plan — exact-text keying is deterministic).
    plan_cache: super::exec::EnginePlanCache,
    /// Observability counters (a private registry; the simulator may read it for liveness checks).
    metrics: Arc<Metrics>,
    /// This inline engine's own degraded flag (`rmp` #414), mirroring the threaded engine. Single-
    /// engine inline driver, so it gates only itself; exposed for determinism parity with production.
    degraded: super::EngineDegraded,
    /// This inline engine's own reclamation-degraded flag (`rmp` #394/#435), mirroring the threaded
    /// engine. Single-engine inline driver, so it gates only itself; present for determinism parity.
    maintenance_degraded: super::MaintenanceDegraded,
    /// This inline engine's contribution to the (private) server-wide open-transaction gauge
    /// (`rmp` #418): published additively, exactly as the threaded loop does.
    active_txns: super::ActiveTxnGauge,
    /// The database name labelling this inline engine's per-database metric series (`rmp` #463). A
    /// fixed label for the single-database DST driver.
    db_name: Arc<str>,
    /// The injected (simulated) clock; threaded into execution so latency/timing is deterministic.
    clock: Arc<dyn Clock + Send + Sync>,
    /// Network bulk-import Mode A session state (`rmp` #519), mirroring the threaded loop's
    /// `loading_session` local — see [`super::bulk_load`]'s module docs. `None` until the first
    /// `BulkImportBatch` dispatch; DST scenarios drive this via [`Self::bulk_import_batch`].
    loading_session: Option<LoadingSession>,
}

impl<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static> LocalEngine<D, S> {
    /// Builds a driver over an already-constructed coordinator and an injected clock.
    #[must_use]
    pub fn new(coordinator: TxnCoordinator<D, S>, clock: Arc<dyn Clock + Send + Sync>) -> Self {
        let metrics = Arc::new(Metrics::new());
        // The single-database DST driver labels its per-database metric series with a fixed name
        // (`rmp` #463); the inline engine never multiplexes databases.
        let db_name: Arc<str> = Arc::from("local");
        Self {
            coordinator: Some(coordinator),
            open: HashMap::new(),
            next_ticket: 0,
            extensions: Arc::new(super::exec::install_extensions()),
            // Inline (deterministic) read dispatch — never a pool. See the field docs.
            dispatch: ReadDispatch::Inline,
            readers_inflight: 0,
            plan_cache: super::exec::EnginePlanCache::new(),
            degraded: super::EngineDegraded::new(),
            maintenance_degraded: super::MaintenanceDegraded::new(),
            active_txns: super::ActiveTxnGauge::new(Arc::clone(&metrics), Arc::clone(&db_name)),
            db_name,
            metrics,
            clock,
            loading_session: None,
        }
    }

    /// The driver's metrics registry (commits/aborts/admission/latency), for liveness assertions.
    #[must_use]
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Dispatches one command inline against the coordinator, returning whether the engine is still
    /// live (`false` after a [`EngineCommand::Shutdown`] consumed the coordinator).
    fn dispatch(&mut self, cmd: EngineCommand) -> bool {
        // The inline DST driver uses an UNBOUNDED egress channel (`LOCAL_RESULT_BUFFER`), so
        // `try_send` never reports `Full` and the resumable-cursor path (`rmp` task #372) never
        // suspends — `handle_run` always returns `Done`/`OffThreadReader`. A never-populated slot
        // preserves the inline driver's bit-determinism (asserted below).
        let mut inflight = None;
        // The inline driver processes exactly ONE command per dispatch (there is no command channel to
        // drain), so a `Cmd::Commit` PREPAREs into this batch and is hardened + acked immediately below —
        // a group-commit batch of one, byte-for-byte identical to the pre-`rmp`-#528 inline commit. This
        // keeps the DST/VOPR replay deterministic (no channel-drain non-determinism ever forms a batch >1).
        let mut commit_batch: Vec<super::PendingCommit> = Vec::new();
        let live = dispatch_command(
            cmd,
            &mut self.coordinator,
            &mut self.open,
            &mut self.next_ticket,
            &mut self.plan_cache,
            &self.extensions,
            &self.dispatch,
            &mut self.readers_inflight,
            &mut inflight,
            LOCAL_RESULT_BUFFER,
            &self.metrics,
            &self.db_name,
            &self.degraded,
            &self.maintenance_degraded,
            &mut self.active_txns,
            &self.clock,
            // The deterministic DST driver runs statements with **no** wall-clock timeout (`rmp` #476):
            // a per-statement deadline would read `Instant::now()` and leak non-determinism into the
            // replay. The inline engine runs each statement atomically anyway, and the statement timeout
            // is a production-thread CPU-exhaustion defence, not a correctness property — so disabling it
            // here keeps the VOPR replay bit-deterministic while exercising the same dispatch code path.
            None,
            &mut self.loading_session,
            &mut commit_batch,
        );
        // Harden + ack the (at most one) PREPAREd commit immediately: one command in, one durable commit
        // out, exactly as before group commit (`rmp` #528). A no-op when the command was not a durable
        // write commit. The redo-bounding checkpoint runs identically to the pre-split path.
        super::flush_commit_batch(
            &mut self.coordinator,
            &mut commit_batch,
            &self.metrics,
            &self.db_name,
        );
        super::checkpoint_after_batch(&mut self.coordinator);
        debug_assert!(
            inflight.is_none(),
            "INVARIANT: the unbounded inline DST driver never suspends a cursor (rmp #372)"
        );
        // The threaded loop drives non-blocking index builds between commands; inline, drive any
        // pending build to completion now so a `CREATE INDEX` is fully `Online` before the next
        // operation observes it (deterministic, no background progress to interleave).
        self.drain_index_builds();
        live
    }

    /// Drives any pending non-blocking index build to completion (a no-op when none is pending), then
    /// attempts to repair a fail-closed index set (`rmp` task #733).
    ///
    /// The repair is a **single bounded attempt** per operation, never a loop: a permanently-faulting
    /// store must not hang the deterministic driver. While it stays degraded the engine is still
    /// **correct** (every read path is on the exact store scan) — just unaccelerated — and the
    /// `SHOW INDEXES` surfaces report the affected indexes as `POPULATING`, so a DST scenario can observe
    /// the degradation rather than mistake it for a healthy engine.
    fn drain_index_builds(&mut self) {
        if let Some(coord) = self.coordinator.as_mut() {
            // Resurrect any build a storage fault parked, BEFORE the drain (`rmp` task #733, M1) — never
            // inside it: a build that failed again would be re-enqueued within the `while` below and the
            // loop would never terminate.
            let _resurrected = coord.retry_poisoned_index_builds();
            while coord.has_pending_index_builds() {
                coord.advance_index_builds(LOCAL_INDEX_BUILD_BUDGET);
            }
            let _healed = coord.retry_degraded_index_rebuild();
        }
    }

    /// Opens an explicit transaction in `mode` and returns its ticket.
    ///
    /// # Errors
    /// [`GraphusError`] if the engine has been shut down.
    pub fn begin(&mut self, mode: AccessMode) -> Result<TxTicket> {
        let (reply, rx) = reply_channel();
        self.dispatch(EngineCommand::Begin { mode, reply });
        rx.recv().map_err(|_| gone())?
    }

    /// Opens an internal auto-commit transaction in `mode` (committed when the matching auto-commit
    /// [`run`](Self::run)'s stream is drained).
    ///
    /// # Errors
    /// [`GraphusError`] if the engine has been shut down.
    pub fn begin_auto_commit(&mut self, mode: AccessMode) -> Result<TxTicket> {
        let (reply, rx) = reply_channel();
        self.dispatch(EngineCommand::BeginAutoCommit { mode, reply });
        rx.recv().map_err(|_| gone())?
    }

    /// Runs `query` with `params` inside `ticket`, returning the result stream (fully buffered).
    ///
    /// With `auto_commit = true` the engine commits (or rolls back on a runtime error) when the
    /// returned [`RunReply`]'s row stream is drained. `privileges` carries the principal's RBAC
    /// (`None` disables filtering — the direct/simulation path).
    ///
    /// # Errors
    /// [`GraphusError`] for a compile/runtime/transaction error raised before the first row.
    pub fn run(
        &mut self,
        ticket: TxTicket,
        query: impl Into<String>,
        params: Vec<(String, Value)>,
        auto_commit: bool,
        privileges: Option<EffectivePrivileges>,
    ) -> Result<RunReply> {
        let (reply, rx) = reply_channel();
        self.dispatch(EngineCommand::Run {
            ticket,
            query: query.into(),
            params,
            auto_commit,
            privileges: privileges.map(Box::new),
            reply,
        });
        rx.recv().map_err(|_| gone())?
    }

    /// Commits the explicit transaction `ticket`.
    ///
    /// # Errors
    /// [`GraphusError`] on an unknown ticket or a serialization failure (retriable).
    pub fn commit(&mut self, ticket: TxTicket) -> Result<RunSummary> {
        let (reply, rx) = reply_channel();
        self.dispatch(EngineCommand::Commit { ticket, reply });
        rx.recv().map_err(|_| gone())?
    }

    /// Rolls back `ticket` (idempotent for an unknown ticket).
    ///
    /// # Errors
    /// [`GraphusError`] only for a genuine engine fault.
    pub fn rollback(&mut self, ticket: TxTicket) -> Result<()> {
        let (reply, rx) = reply_channel();
        self.dispatch(EngineCommand::Rollback { ticket, reply });
        rx.recv().map_err(|_| gone())?
    }

    /// The number of currently-open transactions.
    ///
    /// # Errors
    /// [`GraphusError`] if the engine has been shut down.
    pub fn status_open_txns(&mut self) -> Result<usize> {
        let (reply, rx) = reply_channel();
        self.dispatch(EngineCommand::Status { reply });
        rx.recv().map_err(|_| gone())
    }

    /// Executes an index-DDL statement (`CREATE/DROP INDEX`, `SHOW INDEXES`). A `CREATE` build is
    /// driven to completion inline before this returns (deterministic).
    ///
    /// # Errors
    /// [`GraphusError`] for a storage fault while declaring/dropping/listing the index.
    pub fn index_ddl(&mut self, command: IndexCommand) -> Result<IndexDdlReply> {
        let (reply, rx) = reply_channel();
        self.dispatch(EngineCommand::IndexDdl { command, reply });
        rx.recv().map_err(|_| gone())?
    }

    /// Executes a constraint-DDL statement (`CREATE/DROP CONSTRAINT`, `SHOW CONSTRAINTS`).
    ///
    /// # Errors
    /// [`GraphusError`] if existing data violates a `CREATE`, or a storage fault.
    pub fn constraint_ddl(&mut self, command: ConstraintCommand) -> Result<IndexDdlReply> {
        let (reply, rx) = reply_channel();
        self.dispatch(EngineCommand::ConstraintDdl { command, reply });
        rx.recv().map_err(|_| gone())?
    }

    /// A snapshot of the engine's compiled-plan cache counters (`rmp` task #322) — cumulative hits /
    /// misses / current size / capacity. Lets a test observe that a repeated query text reuses a cached
    /// plan (a hit) and that a schema change invalidates it (the next compile is a miss again).
    pub fn plan_cache_stats(&self) -> graphus_cypher::CacheStats {
        self.plan_cache.stats()
    }

    /// Captures an online backup chain artifact of the live store, returning its plaintext bytes.
    ///
    /// # Errors
    /// [`GraphusError::Storage`] if the capture fails.
    pub fn backup(&mut self) -> Result<Vec<u8>> {
        let (reply, rx) = reply_channel();
        self.dispatch(EngineCommand::Backup { reply });
        rx.recv().map_err(|_| gone())?
    }

    /// Ingests one batch of a network bulk-import Mode A session (`rmp` #519), driving the same
    /// `bulk_load::handle_bulk_import_batch` dispatch the production engine loop uses — the DST/VOPR
    /// seam for `network_bulk_ingest_mode_a` (`07-dst-simulator.md`).
    ///
    /// # Errors
    /// A header/value-parse/storage error from the batch (the batch's transaction is rolled back on
    /// any error), or [`GraphusError`] if the engine has been shut down.
    pub fn bulk_import_batch(
        &mut self,
        batch: BulkImportBatchInput,
    ) -> Result<BulkImportBatchOutcome> {
        let (reply, rx) = reply_channel();
        self.dispatch(EngineCommand::BulkImportBatch { batch, reply });
        rx.recv().map_err(|_| gone())?
    }

    /// Ingests one chunk of a network bulk-import **Mode B** batch (`rmp` #520), driving the same
    /// `bulk_load_b::ingest_mode_b_chunk` dispatch the production engine loop uses — the DST/VOPR seam
    /// for `network_bulk_ingest_mode_b` (`07-dst-simulator.md`). `ticket` must already be an open
    /// transaction (see [`Self::begin`]); does not commit.
    ///
    /// # Errors
    /// [`GraphusError::Transaction`] (retriable) on a write-write/SSI conflict or an unknown ticket; a
    /// terminal error for a malformed row / unknown endpoint; or if the engine has been shut down.
    pub fn bulk_import_mode_b_chunk(
        &mut self,
        ticket: TxTicket,
        chunk: BulkImportModeBChunkInput,
    ) -> Result<BulkImportModeBChunkOutcome> {
        let (reply, rx) = reply_channel();
        self.dispatch(EngineCommand::BulkImportModeBChunk {
            ticket,
            chunk,
            reply,
        });
        rx.recv().map_err(|_| gone())?
    }

    /// Borrows the engine's live block device for the duration of `f`, returning its result — the
    /// **Deterministic Simulation Testing fault seam** (rmp #236). The VOPR harness uses it to arm a
    /// disk [`FaultPlan`](graphus_io::FaultPlan) (or a one-shot I/O error) on the *running* engine's
    /// store mid-workload, so a fault fires during interleaved transactions rather than only on a
    /// device owned before construction. Returns `None` if the engine has already been shut down (the
    /// coordinator was consumed), so a caller can never panic on a spent engine.
    ///
    /// Mirrors [`RecordStore::device_mut`](graphus_storage::RecordStore::device_mut): gated behind the
    /// `dst` cargo feature so the production build never compiles this seam — the device stays
    /// encapsulated and the cost is exactly zero (the method does not exist on the production path).
    ///
    /// # Panics
    /// Panics only if the coordinator's store is already mutably borrowed (a live statement seam is
    /// held) — the same misuse [`TxnCoordinator::with_store_mut`] rejects; the VOPR harness only arms
    /// faults *between* dispatched steps, when no statement seam is live.
    #[cfg(feature = "dst")]
    pub fn with_device_mut<R>(&mut self, f: impl FnOnce(&mut D) -> R) -> Option<R> {
        self.coordinator
            .as_ref()
            .map(|c| c.with_store_mut(|store| store.with_device_mut(f)))
    }

    /// Drains in-flight transactions, flushes + syncs the store, and consumes the engine. After this
    /// the driver is spent (every further operation errors with "engine unavailable").
    ///
    /// # Errors
    /// [`GraphusError`] if the final flush/sync fails.
    pub fn shutdown(&mut self) -> Result<()> {
        let (reply, rx) = reply_channel();
        self.dispatch(EngineCommand::Shutdown { reply });
        rx.recv().map_err(|_| gone())?
    }
}

impl LocalEngine<MemBlockDevice, MemLogSink> {
    /// Builds an inline driver over a **fresh in-memory store** (`MemBlockDevice` + `MemLogSink`) —
    /// the simulated-disk world the DST harness already uses (`graphus-dst`). `pool_pages` sizes the
    /// buffer pool; `clock` is the (simulated) time source.
    ///
    /// # Errors
    /// [`GraphusError::Storage`] if the in-memory store cannot be created (WAL/superblock init).
    pub fn in_memory(clock: Arc<dyn Clock + Send + Sync>, pool_pages: usize) -> Result<Self> {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new())?;
        let store = RecordStore::create(device, wal, pool_pages, 1)?;
        let coordinator = TxnCoordinator::new(store);
        Ok(Self::new(coordinator, clock))
    }

    /// The durable (synced) bytes of this engine's write-ahead log — the prefix that would survive a
    /// power loss. Used to model crash recovery (see [`Self::crash_restart`]).
    #[must_use]
    pub fn wal_durable_bytes(&self) -> Vec<u8> {
        self.coordinator
            .as_ref()
            .map(|c| c.with_store_mut(|s| s.with_wal(|w| w.sink().durable_bytes().to_vec())))
            .unwrap_or_default()
    }

    /// Models a **crash + restart**: rebuilds a fresh engine purely from this engine's *durable* WAL
    /// prefix via ARIES recovery (`graphus_storage::recovery::recover_device`), exactly as a real
    /// reopen does. The in-memory page cache and any un-acknowledged/in-flight state are discarded;
    /// every acknowledged commit (which is in the durable WAL by the group-commit rule) is replayed.
    /// The caller drops the old engine (the "crash") and continues against the returned one.
    ///
    /// This is the wire-level analogue of the storage harness's `recover_no_force`, so the DST can
    /// prove end-to-end durability **over the protocols** (rmp #167), atop the same recovery path the
    /// storage harness already certifies.
    ///
    /// # Errors
    /// [`GraphusError::Storage`] if recovery or the reopen fails (which itself signals a durability
    /// bug worth surfacing).
    pub fn crash_restart(
        &self,
        clock: Arc<dyn Clock + Send + Sync>,
        pool_pages: usize,
    ) -> Result<Self> {
        use graphus_storage::recovery::recover_device;

        // Reconstruct the durable WAL into a fresh sink (the new "disk"); rebuild the device purely
        // from it — no page-cache, no device sharing — so only durable state survives.
        let log = self.wal_durable_bytes();
        let mut sink = MemLogSink::new();
        sink.append(&log);
        sink.sync()?;

        // Recover the device and open the store on the **same** WAL manager. ARIES undo writes per-loser
        // CLRs and an ABORT end-record into the WAL during recovery; the store must continue on the WAL
        // that carries them. A previous version recovered into one `WalManager` and then opened the store
        // on a fresh `WalManager` over a *clone* of the pre-recovery sink — leaving those CLRs/ABORT
        // markers only in the throwaway clone. A *subsequent* crash then replayed a durable WAL whose
        // loser transactions were never neutralized and resurrected their uncommitted effects (an
        // atomicity violation: uncommitted `:Person` nodes reappearing after a second crash, surfaced by
        // the rmp #239 safety oracle). Opening the store on the post-recovery `wal` keeps the loser
        // markers durable, so every later recovery sees the losers correctly aborted.
        let mut device = MemBlockDevice::new(0);
        let mut wal = WalManager::open(sink)?;
        recover_device(&mut wal, &mut device)?;

        let store = RecordStore::open(device, wal, pool_pages)?;
        let coordinator = TxnCoordinator::new(store);
        Ok(Self::new(coordinator, clock))
    }
}

/// The error when the engine has been consumed by [`LocalEngine::shutdown`] (mirrors the threaded
/// handle's `engine_gone`).
fn gone() -> GraphusError {
    GraphusError::Transaction("engine unavailable (local engine shut down)".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_sim::SimClock;

    /// A `Clock` whose ticks the test controls; wrapping a `SimClock` in an `Arc` lets the engine
    /// read it while the test holds the same value (the engine only reads `now_nanos`).
    fn sim_clock(start: u64) -> Arc<dyn Clock + Send + Sync> {
        Arc::new(SimClock::new(start))
    }

    fn engine(clock: Arc<dyn Clock + Send + Sync>) -> LocalEngine<MemBlockDevice, MemLogSink> {
        LocalEngine::in_memory(clock, 64).expect("build in-memory local engine")
    }

    /// Drains a `RunReply` into a vector of rows (each row a vector of materialized cells rendered as
    /// debug strings, so two runs can be compared structurally without depending on cell identity).
    fn drain(reply: &mut RunReply) -> Vec<Vec<String>> {
        let mut out = Vec::new();
        while let Some(row) = reply.rows.next().expect("row stream pulls without error") {
            out.push(row.iter().map(|c| format!("{c:?}")).collect());
        }
        out
    }

    /// Seeds `n` `(:Person {a: i})` nodes through the engine's normal auto-commit write path.
    fn seed_people(eng: &mut LocalEngine<MemBlockDevice, MemLogSink>, n: usize) {
        let tx = eng.begin_auto_commit(AccessMode::Write).expect("begin");
        let mut reply = eng
            .run(
                tx,
                format!("UNWIND range(1, {n}) AS i CREATE (:Person {{a: i}})"),
                vec![],
                true,
                None,
            )
            .expect("seed runs");
        let _ = drain(&mut reply);
    }

    /// A `SHOW INDEXES` command covering every index kind.
    fn show_indexes_cmd() -> IndexCommand {
        IndexCommand::ShowIndexes {
            filter: crate::engine::IndexTypeFilter::All,
            tail: None,
        }
    }

    /// Reads `(state, populationPercent)` for the index named `name` out of a rendered `SHOW INDEXES`
    /// reply, by column name (never by position).
    fn read_index_row(reply: &IndexDdlReply, name: &str) -> (String, f64) {
        use graphus_core::Value;

        let col = |c: &str| {
            reply
                .fields
                .iter()
                .position(|f| f == c)
                .unwrap_or_else(|| panic!("a {c} column"))
        };
        let (name_c, state_c, pct_c) = (col("name"), col("state"), col("populationPercent"));
        let row = reply
            .rows
            .iter()
            .find(|r| r[name_c] == Value::String(name.to_owned()))
            .unwrap_or_else(|| panic!("index {name} must be listed"));
        let state = match &row[state_c] {
            Value::String(s) => s.clone(),
            other => panic!("state must be a string: {other:?}"),
        };
        let pct = match row[pct_c] {
            Value::Float(f) => f,
            ref other => panic!("populationPercent must be a Float: {other:?}"),
        };
        (state, pct)
    }

    /// Reads a `SHOW INDEXES` row through the engine's **full dispatch** — which drains any pending
    /// build *after* the command it dispatched, so the reply reflects the pre-drain state but the build
    /// is complete on return. Fine for a single observation; see [`show_index_row_no_drain`] for
    /// repeated ones.
    fn show_index_row(
        eng: &mut LocalEngine<MemBlockDevice, MemLogSink>,
        name: &str,
    ) -> (String, f64) {
        let reply = eng.index_ddl(show_indexes_cmd()).expect("show indexes");
        read_index_row(&reply, name)
    }

    /// Reads a `SHOW INDEXES` row **without advancing the build** — the observation must not perturb what
    /// it observes.
    ///
    /// `LocalEngine::dispatch` drains pending builds after every command with `LOCAL_INDEX_BUILD_BUDGET`
    /// (`usize::MAX`), so *any* command completes the whole build in one step. A test that samples a build
    /// repeatedly through [`show_index_row`] therefore gets exactly ONE sample, whatever the store's size
    /// — the instrument consumes the thing being measured. Seeding more nodes cannot help: an unbounded
    /// budget always finishes the build on the first drain.
    ///
    /// So this calls the engine's index-DDL handler directly, bypassing only the `dispatch` wrapper (and
    /// hence its drain). It is still the REAL render: `handle_index_ddl` is where the `SHOW INDEXES` arm
    /// builds its `IndexSources` — including `builds: coordinator.index_build_progress()` — and calls
    /// `index_show::build_rows`. Nothing about the rendering is reimplemented or stubbed here.
    fn show_index_row_no_drain(
        coord: &mut TxnCoordinator<MemBlockDevice, MemLogSink>,
        name: &str,
    ) -> (String, f64) {
        let reply =
            crate::engine::handle_index_ddl(coord, &show_indexes_cmd()).expect("show indexes");
        read_index_row(&reply, name)
    }

    /// **`rmp` task #573 — THE GATE.** A `Populating` index must report its build's REAL progress in
    /// `SHOW INDEXES`' `populationPercent`, not the constant `0.0` it reported before.
    ///
    /// This drives the whole chain the server actually uses: the build's `cursor`/`snapshot` →
    /// `TxnCoordinator::index_build_progress` → `IndexSources::builds` → `index_show::build_rows` →
    /// the rendered `populationPercent` column, through the real `ShowIndexes` engine command.
    ///
    /// The build is advanced by a **bounded budget** rather than drained, which is what makes a mid-build
    /// observation deterministic: `LocalEngine::dispatch` drains only *after* the command it dispatched,
    /// so the `SHOW INDEXES` below renders the partial state, and the drain that follows completes it.
    ///
    /// # The non-vacuity controls
    ///
    /// A test that only asserted "some percentage" would pass against the old constant. So:
    /// * the mid-build value must be **strictly** between 0 and 100 — the old constant `0.0` fails this,
    ///   and so does any implementation that reports a state-derived value;
    /// * an `Online` index must still report **exactly** `100.0` (`ONLINE ⇒ 100.0`, as in Neo4j);
    /// * the percentage must match the cursor **exactly**, so the number is the real one and not a
    ///   plausible-looking fabrication.
    #[test]
    fn show_indexes_reports_real_population_percent_mid_build() {
        const N: usize = 200;
        // A budget that leaves the build genuinely unfinished: small enough that several advances still
        // do not reach N, so the observed cursor is strictly inside (0, N).
        const BUDGET: usize = 20;

        let mut eng = engine(sim_clock(0));
        seed_people(&mut eng, N);

        // Enqueue the build directly on the coordinator (the DDL command would be drained to completion
        // by `dispatch`), then advance it by a bounded budget to land mid-build.
        let coord = eng.coordinator.as_mut().expect("coordinator");
        coord
            .begin_online_node_property_index_named(Some("ix_a"), "Person", "a", false)
            .expect("declare the build");
        coord.advance_index_builds(BUDGET);

        // The coordinator's own view of the build: strictly partial, and not poisoned.
        let progress = coord.index_build_progress();
        assert_eq!(
            progress.len(),
            1,
            "exactly one build in flight: {progress:?}"
        );
        let (done, total) = (progress[0].done, progress[0].total);
        assert_eq!(progress[0].name, "ix_a");
        assert!(!progress[0].poisoned, "a healthy build is not poisoned");
        assert_eq!(total, N, "the snapshot covers every seeded node");
        assert!(
            done > 0 && done < total,
            "the build must be STRICTLY mid-flight for this test to mean anything, got {done}/{total}"
        );

        // THE ASSERTION: the rendered column carries the real progress.
        let (state, pct) = show_index_row(&mut eng, "ix_a");
        assert_eq!(state, "POPULATING", "the build has not finished");
        assert!(
            pct > 0.0 && pct < 100.0,
            "populationPercent must report REAL progress strictly inside (0, 100) mid-build — the \
             pre-#573 constant reported 0.0; got {pct}"
        );
        // An INDEPENDENT oracle, not a re-derivation: `BUDGET` of `N` is 20 of 200, which is exactly
        // 10.0 — a literal this test can state without reusing the implementation's own arithmetic.
        // (Re-deriving `done * 100 / total` here would compare the implementation against a copy of
        // itself and could not fail.)
        assert_eq!(done, 20, "the cursor advanced by exactly BUDGET");
        assert_eq!(total, 200, "the snapshot is exactly N");
        assert!(
            (pct - 10.0).abs() < 1e-9,
            "20 of 200 nodes indexed must render as exactly 10.0, got {pct}"
        );

        // The control: once built, exactly 100.0 / ONLINE. `ONLINE ⇒ 100.0` is Neo4j's invariant, and it
        // is what proves the mid-build value above is a real measurement rather than a broken constant.
        eng.coordinator
            .as_mut()
            .expect("coordinator")
            .advance_index_builds(usize::MAX);
        let (state, pct) = show_index_row(&mut eng, "ix_a");
        assert_eq!(state, "ONLINE", "the drained build is promoted");
        assert!(
            (pct - 100.0).abs() < f64::EPSILON,
            "an Online index reports exactly 100.0, got {pct}"
        );
    }

    /// `rmp` task #573: the **rendered** `populationPercent` must never exceed 100 and must not go
    /// backwards **within one build** — the Neo4j-facing contract of the column.
    ///
    /// Sampled off a real `SHOW INDEXES` render at every step of a build advanced **one entity at a
    /// time** — the finest granularity the build loop has — so any transient overshoot or regression
    /// inside a single generation is caught.
    ///
    /// Two properties of the harness are load-bearing:
    ///
    /// * It reads the **rendered column** rather than re-computing `done * 100 / total` from the cursor.
    ///   Re-deriving the formula would compare the implementation against a copy of itself and could not
    ///   fail for any change to `population_percent`.
    /// * It observes via [`show_index_row_no_drain`], because the ordinary `LocalEngine` dispatch drains
    ///   the whole build after every command (`LOCAL_INDEX_BUILD_BUDGET` is `usize::MAX`) — the act of
    ///   observing would otherwise consume what is being observed, and the loop below would get exactly
    ///   one sample and prove nothing.
    #[test]
    fn population_percent_is_monotonic_and_bounded_within_one_build() {
        const N: usize = 40;

        let mut eng = engine(sim_clock(0));
        seed_people(&mut eng, N);
        let coord = eng.coordinator.as_mut().expect("coordinator");
        coord
            .begin_online_node_property_index_named(Some("ix_a"), "Person", "a", false)
            .expect("declare the build");

        let mut last = 0.0_f64;
        let mut samples = 0;
        let mut saw_populating = false;
        while coord.has_pending_index_builds() {
            let (state, pct) = show_index_row_no_drain(coord, "ix_a");
            assert!(
                (0.0..=100.0).contains(&pct),
                "populationPercent left [0, 100]: {pct}"
            );
            assert!(
                pct >= last,
                "populationPercent went BACKWARDS within one build: {last} -> {pct}"
            );
            if state == "POPULATING" {
                saw_populating = true;
            }
            last = pct;
            samples += 1;
            // One entity per step — the finest granularity the build loop offers.
            coord.advance_index_builds(1);
        }
        // NON-VACUITY. The loop must have sampled a RISING percentage many times over. With one sample
        // "monotonic" is a statement about nothing, so this guard is what gives the assertions above their
        // teeth: it is the reason the observation had to stop draining the build.
        assert!(
            samples > 2,
            "the build must have been sampled repeatedly (got {samples} samples)"
        );
        assert!(
            saw_populating,
            "the build must have been observed while POPULATING"
        );
        assert!(
            last > 0.0,
            "the sampled percentage must have risen above 0 (got {last})"
        );
    }

    #[test]
    fn auto_commit_create_then_match_is_visible() {
        let mut eng = engine(sim_clock(0));

        // CREATE in an auto-commit transaction.
        let tx = eng.begin_auto_commit(AccessMode::Write).expect("begin");
        let mut reply = eng
            .run(tx, "CREATE (:Person {name: 'Ada'})", vec![], true, None)
            .expect("create runs");
        let _ = drain(&mut reply); // drain so the auto-commit fires
        drop(reply);

        // MATCH it back in a fresh auto-commit read.
        let tx = eng.begin_auto_commit(AccessMode::Read).expect("begin read");
        let mut reply = eng
            .run(tx, "MATCH (p:Person) RETURN p.name", vec![], true, None)
            .expect("match runs");
        let rows = drain(&mut reply);
        assert_eq!(rows.len(), 1, "the committed node is visible");
        assert!(
            rows[0][0].contains("Ada"),
            "row carries the created name: {rows:?}"
        );
    }

    #[test]
    fn same_seed_same_clock_yields_identical_results() {
        // Two independent engines on the same simulated clock run the same script; their observable
        // outputs must be byte-identical — the determinism the DST harness depends on.
        let script = [
            "CREATE (:N {v: 1})",
            "CREATE (:N {v: 2})",
            "CREATE (:N {v: 3})",
            "MATCH (n:N) RETURN n.v ORDER BY n.v",
        ];

        let run_once = || {
            let mut eng = engine(sim_clock(42));
            let mut last = Vec::new();
            for stmt in script {
                let tx = eng.begin_auto_commit(AccessMode::Write).expect("begin");
                let mut reply = eng.run(tx, stmt, vec![], true, None).expect("run");
                last = drain(&mut reply);
            }
            last
        };

        let a = run_once();
        let b = run_once();
        assert_eq!(
            a, b,
            "identical script on identical clock ⇒ identical results"
        );
        assert_eq!(
            a.len(),
            3,
            "the final MATCH returns the three created nodes"
        );
    }

    #[test]
    fn explicit_rollback_discards_writes() {
        let mut eng = engine(sim_clock(0));

        let tx = eng.begin(AccessMode::Write).expect("begin");
        let mut reply = eng
            .run(tx, "CREATE (:Temp {x: 1})", vec![], false, None)
            .expect("create runs");
        let _ = drain(&mut reply);
        drop(reply);
        eng.rollback(tx).expect("rollback");

        let tx = eng.begin_auto_commit(AccessMode::Read).expect("begin read");
        let mut reply = eng
            .run(tx, "MATCH (t:Temp) RETURN t", vec![], true, None)
            .expect("match runs");
        let rows = drain(&mut reply);
        assert!(
            rows.is_empty(),
            "rolled-back writes are not visible: {rows:?}"
        );
    }

    #[test]
    fn read_only_transaction_rejects_writes() {
        let mut eng = engine(sim_clock(0));
        let tx = eng.begin(AccessMode::Read).expect("begin read");
        let err = eng
            .run(tx, "CREATE (:Nope)", vec![], false, None)
            .expect_err("write in a READ transaction is rejected");
        let _ = err; // the precise message is asserted by the seam tests; here we only need the reject
        eng.rollback(tx).expect("rollback");
    }

    #[test]
    fn show_indexes_renders_composite_property_tuple() {
        // `rmp` task #657: a composite index shows `type` RANGE, `entityType` NODE and a MULTI-element
        // `properties` list (`[a, b]`), alongside single-property indexes.
        use graphus_core::Value;

        let mut eng = engine(sim_clock(0));
        // Seed a node so the label exists, then declare a single-property and a composite index.
        let tx = eng.begin_auto_commit(AccessMode::Write).expect("begin");
        let mut reply = eng
            .run(
                tx,
                "CREATE (:Person {a: 1, b: 2, c: 3})",
                vec![],
                true,
                None,
            )
            .expect("create runs");
        let _ = drain(&mut reply);
        drop(reply);

        eng.index_ddl(IndexCommand::CreateNodePropertyIndex {
            name: Some("ix_a".to_owned()),
            label: "Person".to_owned(),
            properties: vec!["a".to_owned()],
            if_not_exists: false,
        })
        .expect("create single-property index");
        eng.index_ddl(IndexCommand::CreateNodePropertyIndex {
            name: Some("ix_ab".to_owned()),
            label: "Person".to_owned(),
            properties: vec!["a".to_owned(), "b".to_owned()],
            if_not_exists: false,
        })
        .expect("create composite index");

        // The unified `SHOW INDEXES` renders the full Neo4j column set (`rmp` #660); the engine returns
        // `index_show::COLUMNS_FULL`, so columns are read by name rather than by position.
        let reply = eng
            .index_ddl(IndexCommand::ShowIndexes {
                filter: crate::engine::IndexTypeFilter::All,
                tail: None,
            })
            .expect("show indexes");
        let col = |name: &str| {
            reply
                .fields
                .iter()
                .position(|f| f == name)
                .unwrap_or_else(|| panic!("a {name} column"))
        };
        let (name_col, props_col, type_col, entity_col) = (
            col("name"),
            col("properties"),
            col("type"),
            col("entityType"),
        );

        // The composite row carries the two-element ordered property list.
        let composite_row = reply
            .rows
            .iter()
            .find(|r| matches!(&r[name_col], Value::String(n) if n == "ix_ab"))
            .expect("the composite index is listed");
        assert_eq!(
            composite_row[props_col],
            Value::List(vec![
                Value::String("a".to_owned()),
                Value::String("b".to_owned())
            ]),
            "composite properties render as a multi-element list [a, b]"
        );
        assert_eq!(composite_row[type_col], Value::String("RANGE".to_owned()));
        assert_eq!(composite_row[entity_col], Value::String("NODE".to_owned()));

        // The single-property row still renders a one-element list.
        let single_row = reply
            .rows
            .iter()
            .find(|r| matches!(&r[name_col], Value::String(n) if n == "ix_a"))
            .expect("the single-property index is listed");
        assert_eq!(
            single_row[props_col],
            Value::List(vec![Value::String("a".to_owned())])
        );
    }

    /// `rmp` task #671 end-to-end: a `CREATE VECTOR INDEX … OPTIONS { indexConfig { … } }` parsed off the
    /// admin grammar and driven through the engine builds an `Online` index that `SHOW INDEXES` renders
    /// as `type = VECTOR` (with the full `indexConfig` in `options` and a round-trippable
    /// `createStatement`); `SHOW VECTOR INDEXES` filters to it; the unified `DROP INDEX <name>` resolves
    /// the vector catalog and removes it; and an `IF NOT EXISTS` re-create is an idempotent no-op.
    #[test]
    fn vector_index_create_show_filter_and_drop() {
        use crate::admin::{AdminParse, parse_admin_statement};
        use crate::engine::IndexTypeFilter;
        use graphus_core::Value;

        // Parses an index-DDL statement off the admin grammar into an `IndexCommand`.
        let parse = |stmt: &str| match parse_admin_statement(stmt) {
            AdminParse::Index(cmd) => cmd,
            other => panic!("expected an index command for {stmt:?}, got {other:?}"),
        };

        let mut eng = engine(sim_clock(0));

        // Seed a node carrying a 4-dimensional embedding so the index has content to build from.
        let tx = eng.begin_auto_commit(AccessMode::Write).expect("begin");
        let mut reply = eng
            .run(
                tx,
                "CREATE (:Doc {embedding: [1.0, 2.0, 3.0, 4.0]})",
                vec![],
                true,
                None,
            )
            .expect("create runs");
        let _ = drain(&mut reply);
        drop(reply);

        // CREATE VECTOR INDEX through the full parse → engine path.
        let create = parse(
            "CREATE VECTOR INDEX emb FOR (n:Doc) ON (n.embedding) \
             OPTIONS { indexConfig: { `vector.dimensions`: 4, \
             `vector.similarity_function`: 'cosine', `vector.hnsw.m`: 16, \
             `vector.hnsw.ef_construction`: 100 } }",
        );
        let created = eng.index_ddl(create).expect("create vector index");
        assert!(created.mutated, "a fresh CREATE mutates the schema");

        // SHOW INDEXES renders the full Neo4j column set; read columns by name.
        let reply = eng
            .index_ddl(IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::All,
                tail: None,
            })
            .expect("show indexes");
        let col = |name: &str| {
            reply
                .fields
                .iter()
                .position(|f| f == name)
                .unwrap_or_else(|| panic!("a {name} column"))
        };
        let (name_c, type_c, entity_c, labels_c, props_c, provider_c, state_c, options_c, create_c) = (
            col("name"),
            col("type"),
            col("entityType"),
            col("labelsOrTypes"),
            col("properties"),
            col("indexProvider"),
            col("state"),
            col("options"),
            col("createStatement"),
        );
        let vrow = reply
            .rows
            .iter()
            .find(|r| matches!(&r[name_c], Value::String(n) if n == "emb"))
            .expect("the vector index is listed under SHOW INDEXES");
        assert_eq!(vrow[type_c], Value::String("VECTOR".to_owned()));
        assert_eq!(vrow[entity_c], Value::String("NODE".to_owned()));
        assert_eq!(
            vrow[labels_c],
            Value::List(vec![Value::String("Doc".to_owned())])
        );
        assert_eq!(
            vrow[props_c],
            Value::List(vec![Value::String("embedding".to_owned())])
        );
        assert_eq!(vrow[provider_c], Value::String("vector-2.0".to_owned()));
        assert_eq!(
            vrow[state_c],
            Value::String("ONLINE".to_owned()),
            "a synchronously-built vector index is Online"
        );
        assert_eq!(
            vrow[options_c],
            Value::Map(vec![(
                "indexConfig".to_owned(),
                Value::Map(vec![
                    ("vector.dimensions".to_owned(), Value::Integer(4)),
                    (
                        "vector.similarity_function".to_owned(),
                        Value::String("cosine".to_owned()),
                    ),
                    ("vector.hnsw.m".to_owned(), Value::Integer(16)),
                    (
                        "vector.hnsw.ef_construction".to_owned(),
                        Value::Integer(100),
                    ),
                ]),
            )]),
            "the embedding shape surfaces in options.indexConfig"
        );
        // The createStatement re-parses to an equivalent CreateVectorIndex.
        let Value::String(create_stmt) = &vrow[create_c] else {
            panic!("createStatement is a string");
        };
        assert_eq!(
            parse(create_stmt),
            IndexCommand::CreateVectorIndex {
                name: Some("emb".to_owned()),
                entity: graphus_cypher::VectorEntity::Node,
                label_or_type: "Doc".to_owned(),
                property: "embedding".to_owned(),
                dimensions: 4,
                similarity: graphus_cypher::VectorSimilarity::Cosine,
                m: 16,
                ef_construction: 100,
                if_not_exists: false,
            },
            "the reported createStatement round-trips: {create_stmt}"
        );

        // SHOW VECTOR INDEXES filters to exactly the one vector row.
        let filtered = eng
            .index_ddl(IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::Vector,
                tail: None,
            })
            .expect("show vector indexes");
        assert_eq!(
            filtered.rows.len(),
            1,
            "only the vector index matches VECTOR"
        );
        assert_eq!(filtered.rows[0][name_c], Value::String("emb".to_owned()));

        // An `IF NOT EXISTS` re-create is an idempotent no-op (does not mutate).
        let recreate = parse(
            "CREATE VECTOR INDEX emb IF NOT EXISTS FOR (n:Doc) ON (n.embedding) \
             OPTIONS { indexConfig: { `vector.dimensions`: 4, \
             `vector.similarity_function`: 'cosine' } }",
        );
        assert!(
            !eng.index_ddl(recreate)
                .expect("idempotent recreate")
                .mutated,
            "IF NOT EXISTS on an existing index is a no-op"
        );

        // The unified `DROP INDEX <name>` (no VECTOR keyword) resolves the vector catalog and removes it.
        let dropped = eng
            .index_ddl(parse("DROP INDEX emb"))
            .expect("unified drop by name");
        assert!(
            dropped.mutated,
            "the vector index is removed by unified DROP"
        );

        let after = eng
            .index_ddl(IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::All,
                tail: None,
            })
            .expect("show indexes after drop");
        assert!(
            !after
                .rows
                .iter()
                .any(|r| matches!(&r[name_c], Value::String(n) if n == "emb")),
            "the vector index is gone after DROP"
        );
    }
}
