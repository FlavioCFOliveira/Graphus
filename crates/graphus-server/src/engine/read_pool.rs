//! The **off-thread reader pool**: runs `AccessMode::Read` auto-commit statements on dedicated worker
//! threads, concurrently with the single writer (the engine thread), so multiple `MATCH`es push the
//! server past one core (`rmp` task #336, Slice 3b-ii — the payoff slice that turns on cross-thread
//! read parallelism).
//!
//! ## Why a pool, and the dispatch duality
//!
//! Production runs the [`graphus_cypher::TxnCoordinator`] on **one** engine thread reached
//! through a bounded channel ([`super::EngineHandle`]). Reads serialised on that thread in v1; this
//! module breaks that serialisation for read-only statements by:
//!
//! 1. capturing — **on the engine thread** — the owned `Send` pieces a reader needs
//!    ([`graphus_cypher::ReadTaskInputs`]) plus a clone of the `Send + Sync` extension registry;
//! 2. dispatching a [`ReadTask`] to a **bounded `std::thread` pool** draining a bounded MPMC queue (a
//!    full queue fast-rejects with [`super::ServerBusy`] — it never blocks the engine);
//! 3. the worker builds a [`ReadOnlyGraph`](graphus_cypher::ReadOnlyGraph) over the captured view,
//!    streams its rows into the egress channel, and posts a [`ReadRetirement`] back to the engine loop
//!    via the [`EngineEvent`](super::command::EngineEvent) channel — which the loop processes serially
//!    (M1 merge → auto-commit), so **all** coordinator mutation stays on the one engine thread.
//!
//! The **deterministic** driver ([`super::LocalEngine`], used by the `graphus-dst` VOPR/Elle harness)
//! has no second thread: it runs each command inline on the calling thread. So this module exposes a
//! [`ReadDispatch`] abstraction with two shapes — [`ReadDispatch::Threaded`] (the production pool) and
//! [`ReadDispatch::Inline`] (run the reader **synchronously** on the calling thread, retiring inline).
//! The inline shape is what keeps DST bit-deterministic: no OS thread, no channel, the same seed yields
//! the same execution. [`super::run_engine_loop`] injects the threaded shape; `LocalEngine` injects the
//! inline shape. **This duality is the load-bearing design point of Slice 3b-ii.**
//!
//! ## Serializability (inviolable)
//!
//! A reader's SIREAD markers accumulate in its **own** [`SsiReadBuffer`](graphus_txn::SsiReadBuffer)
//! (no shared lock); the engine folds them into the shared SSI tracker at retirement via
//! [`TxnCoordinator::merge_read_buffer`](graphus_cypher::TxnCoordinator::merge_read_buffer) **before**
//! the auto-commit's `detect_pivot_abort`. Because the reader's transaction was registered with the
//! tracker and the active set at `begin` — **before** dispatch — a concurrent writer always sees it and
//! forms any rw-edge; and the reader keeps pinning the GC watermark until it is removed at retirement.
//! The Slice 3b no-lost-edge proof (memory `graphus-multithread-audit-sprint36` §3) holds because
//! `are_concurrent` uses begin/commit timestamps captured on the engine thread, not wall-clock.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, SyncSender};

use graphus_core::TxnId;
use graphus_core::error::GraphusError;
use graphus_cypher::extension::ExtensionRegistry;
use graphus_cypher::{AuthorizedGraph, PrivilegeOracle, ReadOnlyGraph, ReadTaskInputs};
use graphus_io::BlockDevice;
use graphus_wal::LogSink;

use super::command::Reply;
use super::exec::run_cursor;
use super::privileges::EffectivePrivileges;
use super::stream::SummarySink;
use super::stream::{RowItem, RowSender};
use super::{RunReply, TxTicket};
use crate::metrics::Metrics;

/// A read-only statement packaged for off-thread execution (`rmp` task #336, Slice 3b-ii).
///
/// Every field is `Send`, so the whole task moves cleanly to a worker thread (or, in DST, is run
/// inline). The plan + bound were compiled on the engine thread; the [`ReadTaskInputs`] were captured
/// there too; `extensions` is an `Arc`-shared clone of the engine's `Send + Sync` registry (so a
/// UDF/UDP in a read plan resolves against the **same** registry that backed compilation — no decline).
pub struct ReadTask<D: BlockDevice, S: LogSink> {
    /// The reader's transaction id (registered + active-set-inserted on the engine thread at `begin`).
    pub txn: TxnId,
    /// The open-transaction ticket, echoed back at retirement so the engine finalises the right entry.
    pub ticket: TxTicket,
    /// The compiled physical plan, shared from the engine's `Arc`-valued plan cache (`rmp` task #531).
    /// `Arc<PhysicalPlan>` is `Send + Sync` (the plan is pure data — no `Rc`), so it moves cleanly to
    /// the reader thread; capturing it on the engine thread is an `Arc::clone`, not a deep tree clone.
    pub plan: Arc<graphus_cypher::PhysicalPlan>,
    /// The bound parameters for this execution.
    pub bound: graphus_cypher::BoundParameters,
    /// The owned, engine-thread-captured store read view + token snapshot + read snapshot + commit
    /// fresh SIREAD buffer. It carries no commit-registry clone since `rmp` #1069 phase 3: the
    /// captured `view` resolves a record stamp against its own `commit.store`.
    pub inputs: ReadTaskInputs<D, S>,
    /// This auto-commit read's Bolt causal **bookmark** (`rmp` task #813), minted on the engine thread at
    /// dispatch from the DB's durable-write high-water (`"<db>:<durable_write_commit_ts>"`). Carried on
    /// the `Send` task so the reader thread places it in the terminal `PULL` `SUCCESS` — matching a real
    /// Neo4j server, which emits a bookmark for read transactions too. Always `Some` on the dispatch path
    /// (an empty DB mints `"<db>:0"`).
    pub read_bookmark: Option<String>,
    /// The shared extension registry (functions + procedures), `Arc`-shared from the engine.
    pub extensions: Arc<ExtensionRegistry>,
    /// The principal's resolved RBAC for this statement (`None`/unrestricted = no filtering).
    pub privileges: Option<EffectivePrivileges>,
    /// The per-statement wall-clock deadline (`rmp` #476), captured on the engine thread at statement
    /// start, or `None` when no statement timeout is configured. Bounds this off-thread read's CPU to the
    /// same budget an inline statement gets: the reader builds its cursor's deadline-bearing
    /// cancellation token from it.
    pub deadline: Option<std::time::Instant>,
    /// The intended intra-query **morsel width** for this read (`rmp` task #575-g.1), chosen on the engine
    /// thread at dispatch from `readers_inflight` via
    /// [`reader_pool_morsel_width`](graphus_cypher::morsel::reader_pool_morsel_width). The worker enters a
    /// [`ReaderPoolWorkerGuard`](graphus_cypher::morsel::ReaderPoolWorkerGuard) with this width, so a lone
    /// heavy read fans out across the whole analytics pool while `K` concurrent reads share it without
    /// over-subscription (their widths sum to `<= pool capacity`). `1` = serial-within-statement.
    pub morsel_width: usize,
    /// The egress channel the reader streams rows into; handed back at retirement so the engine can
    /// send a terminal auto-commit error through it (the auto-commit terminal-error contract).
    pub row_tx: RowSender,
    /// The egress receiver, moved into the [`RunReply`] the reader sends over `reply` (the consumer
    /// pulls rows from it). Created on the engine thread alongside `row_tx`.
    pub row_rx: Receiver<RowItem>,
    /// The reply channel for the [`RunReply`] (fields + receiver), sent before the first row.
    pub reply: Reply<Result<RunReply, GraphusError>>,
}

/// What an off-thread reader delivers back to the engine thread when it retires (`rmp` task #336,
/// Slice 3b-ii). The engine processes this on whichever worker reaches the ENGINE's one retirement
/// channel (`rmp` #1039 — the order across readers is unobservable; see `finish_reader`'s M1'), from a
/// retirement channel: it merges the SIREAD buffer (M1) and then auto-commits (commit on `outcome` ok,
/// rollback on error), sending any terminal commit error through `row_tx` before dropping it.
///
/// **Deliberately not generic over `D, S`:** none of its fields carry the store types (the view that
/// did is consumed when the reader ran). So a single retirement-channel type backs every engine
/// instantiation, and the production [`super::EngineHandle`] never needs to become generic.
pub struct ReadRetirement {
    /// The reader's transaction id.
    pub txn: TxnId,
    /// The open-transaction ticket to finalise.
    pub ticket: TxTicket,
    /// The reader's accumulated SIREAD markers, to fold into the shared tracker before commit.
    pub buffer: graphus_txn::SsiReadBuffer,
    /// Whether the read produced rows cleanly (`Ok`) or hit a runtime / captured / deferral error
    /// (`Err`) — including any [`ReadOnlyGraph::take_error`](graphus_cypher::ReadOnlyGraph::take_error)
    /// write-degrade. On `Err` the engine rolls the reader back instead of committing.
    pub outcome: Result<(), GraphusError>,
    /// The egress channel, still open, so the engine can deliver a terminal auto-commit (e.g. an SSI
    /// serialization-abort) error to the consumer before closing it.
    pub row_tx: RowSender,
}

/// Runs a [`ReadTask`] to completion against a freshly-built [`ReadOnlyGraph`], streaming its rows and
/// returning the [`ReadRetirement`] the engine must process. **Pure of the coordinator** — it touches
/// only the owned, `Send` task pieces — so it runs identically on a worker thread (threaded dispatch)
/// or on the calling thread (inline dispatch).
///
/// Mirrors the inline [`stream_rows`](super::exec) contract: it opens the cursor, sends the
/// [`RunReply`] over `reply` **before** the first row (so the consumer can drain concurrently), streams
/// rows, then surfaces — in priority order — an authorization denial, then the seam's captured
/// error/write-degrade (R3), as the `outcome`. The engine then merges + auto-commits.
pub fn run_read_task<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    task: ReadTask<D, S>,
    // The pool-wide egress-stall ceiling (`rmp` #591 C-F1), captured once at [`ReadPool::spawn`]: the
    // maximum no-progress wait an off-thread read may spend blocked on a full result-egress channel before
    // it is aborted (releasing its GC-watermark pin + pool slot) — independent of the per-statement
    // deadline. `None` disables it.
    egress_stall_timeout: Option<std::time::Duration>,
    // For the `graphus_egress_stall_aborts_total` counter, recorded when the ceiling trips.
    metrics: &Metrics,
) -> ReadRetirement {
    let ReadTask {
        txn,
        ticket,
        plan,
        bound,
        inputs,
        read_bookmark,
        extensions,
        privileges,
        deadline,
        // The morsel width is consumed by the worker loop (to enter the `ReaderPoolWorkerGuard`) *before*
        // the task is moved here, so `run_read_task` itself ignores it.
        morsel_width: _,
        row_tx,
        row_rx,
        reply,
    } = task;
    let ReadTaskInputs {
        view,
        tokens,
        snapshot,
        buffer,
        fulltext,
        index_candidates,
        count_store,
    } = inputs;

    // Build the off-thread read-only seam over the captured view. It accumulates this reader's SIREAD
    // markers into `buffer` (handed back below) and captures any storage / deferral / write-degrade
    // error into its own cell (surfaced as the outcome). The captured full-text catalogue (`rmp` #546)
    // lets an off-thread `CALL db.index.fulltext.queryNodes` resolve the index by name and recompute
    // its matches from this reader's snapshot.
    // The captured index-candidate memo (`rmp` #755) lets an off-thread indexed `MATCH` serve a REAL
    // `index_seek_eq` — the engine thread pre-ran the seek and handed over the raw candidate ids, and the
    // reader re-checks them through the same lifted body the inline seam uses. An empty capture (any
    // non-indexed read, or a gate refusal) simply declines to the exact scan, as before.
    let mut graph = ReadOnlyGraph::new(view, tokens, snapshot, txn, buffer)
        // The captured count-store memo (`rmp` #866) lets an off-thread ungrouped `count()` over a bare
        // label/type scan answer from a counter instead of reading every record. An empty capture — no
        // count-store operator in the plan, or an equivalence predicate that did not hold on the engine
        // thread — declines to the `Aggregation`-over-scan subtree, which is the reference path.
        .with_fulltext(fulltext)
        .with_index_candidates(index_candidates)
        .with_count_store(count_store);

    // RBAC (rmp #93) composes exactly as the inline path: a restricted principal wraps the seam in an
    // `AuthorizedGraph` so reads are filtered uniformly; `None`/admin runs the bare seam (zero cost).
    // `run_cursor` is reused verbatim — it sends the `RunReply` (fields + receiver) over `reply` before
    // the first row, then streams into `row_tx`.
    let mut auth_error: Option<GraphusError> = None;
    let produced_ok = match privileges {
        Some(privileges) if !privileges.is_unrestricted() => {
            let mut authz = AuthorizedGraph::new(&mut graph, privileges);
            let ok = run_cursor(
                &plan,
                &bound,
                &mut authz,
                &extensions,
                deadline,
                egress_stall_timeout,
                metrics,
                &row_tx,
                row_rx,
                // A fresh read-only summary sink; `run_cursor` fills it with the `r` query type
                // before the caller drops `row_tx` (`rmp` #512).
                SummarySink::new(),
                // The auto-commit read's causal bookmark (`rmp` #813), minted at dispatch.
                read_bookmark,
                reply,
            );
            auth_error = authz.take_auth_error();
            ok
        }
        _ => run_cursor(
            &plan,
            &bound,
            &mut graph,
            &extensions,
            deadline,
            egress_stall_timeout,
            metrics,
            &row_tx,
            row_rx,
            // A fresh read-only summary sink; `run_cursor` fills it with the `r` query type before
            // the caller drops `row_tx` (`rmp` #512).
            SummarySink::new(),
            // The auto-commit read's causal bookmark (`rmp` #813), minted at dispatch.
            read_bookmark,
            reply,
        ),
    };

    // Determine the outcome the engine acts on (commit vs rollback), in the SAME priority order the
    // inline `stream_rows` uses: a runtime error already streamed a terminal item; otherwise an authz
    // denial; otherwise the seam's captured deferral / write-degrade (R3 — never silently dropped).
    // `GraphusError` is not `Clone`, so the consumer-facing error is **moved** into `row_tx` and the
    // engine-facing `outcome` carries a lightweight rollback marker (its only role is to select
    // rollback-vs-commit; the real error already reached the consumer as the stream's terminal item).
    let outcome = if !produced_ok {
        // A runtime error was already sent through `row_tx` inside `run_cursor`; just signal rollback.
        Err(rollback_marker())
    } else if let Some(err) = auth_error {
        let _ = row_tx.send(Err(err));
        Err(rollback_marker())
    } else if let Some(err) = graph.take_error() {
        let _ = row_tx.send(Err(err));
        Err(rollback_marker())
    } else {
        Ok(())
    };

    // Reclaim the reader's SIREAD buffer for the engine-thread merge (M1). `take_buffer` empties the
    // seam's cell; after this the (now-dropped) graph records no further markers.
    let buffer = graph.take_buffer();

    ReadRetirement {
        txn,
        ticket,
        buffer,
        outcome,
        row_tx,
    }
}

/// How read-only statements are dispatched off the inline path (`rmp` task #336, Slice 3b-ii) — the
/// duality that lets production run readers on threads while DST runs them inline-deterministically.
pub enum ReadDispatch<D: BlockDevice, S: LogSink> {
    /// The production shape: submit the task to a bounded worker pool; on a full queue, the dispatch
    /// site fast-rejects with [`super::ServerBusy`] and falls back to the inline engine-thread path.
    Threaded(ReadPool<D, S>),
    /// The deterministic shape (`LocalEngine` / DST): there is no worker pool and no retirement
    /// channel. The dispatch site runs the reader **inline on the calling thread** and retires it
    /// inline, so the same seed yields the same execution (no OS thread to interleave).
    Inline,
}

impl<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>
    ReadDispatch<D, S>
{
    /// Whether this dispatcher runs readers off-thread (production) — so the dispatch site knows to
    /// capture inputs + package a task rather than execute inline. `false` for [`Self::Inline`].
    #[must_use]
    pub fn is_threaded(&self) -> bool {
        matches!(self, ReadDispatch::Threaded(_))
    }

    /// Tries to submit `task` to the worker pool, returning it back (`Err`) if the dispatcher is inline
    /// or the bounded queue is full (the dispatch site then runs it on the engine thread / fast-rejects).
    // The `Err` variant intentionally carries the whole `ReadTask` back (the `SyncSender::try_send`
    // fall-the-task-back contract): the caller reuses its locals to run inline. Boxing it would force a
    // heap allocation on the **common success path** too, for no benefit on the rare full-queue path.
    #[allow(clippy::result_large_err)]
    pub fn try_submit(&self, task: ReadTask<D, S>) -> Result<(), ReadTask<D, S>> {
        match self {
            ReadDispatch::Threaded(pool) => pool.try_submit(task),
            ReadDispatch::Inline => Err(task),
        }
    }
}

/// A bounded pool of reader worker threads draining a bounded MPMC queue (`rmp` task #336, Slice
/// 3b-ii). Each worker pulls a [`ReadTask`], runs it via [`run_read_task`], and posts the
/// [`ReadRetirement`] back to the engine loop through the [`EngineEvent`] channel. The queue is bounded
/// (no unbounded channel on the request path — `04 §9.3`); a full queue is the dispatch site's
/// fast-reject signal.
pub struct ReadPool<D: BlockDevice, S: LogSink> {
    /// The bounded work queue's sender. Behind a `Mutex<Option<..>>` since `rmp` #1039, for one reason:
    /// the pool became the ENGINE's and is shared by every worker behind an `Arc`, so shutting it down
    /// can no longer consume `self`. Closing the queue is therefore `take()`-ing the sender, which also
    /// makes [`Self::shutdown`] idempotent — the first caller closes and joins, and a second finds
    /// `None` and returns. A concurrent [`Self::try_submit`] then hands its task back and the caller
    /// runs it inline, which is the same contract a full queue already has.
    ///
    /// The lock is held for a `try_send` and nothing else. Reader workers never touch it: they pull
    /// from the receiver half, which has its own lock.
    work_tx: std::sync::Mutex<Option<SyncSender<ReadTask<D, S>>>>,
    /// The worker join handles, joined at [`Self::shutdown`] by whichever caller closes the queue.
    workers: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>,
}

/// How many reader pools have been spawned in this process, ever (`rmp` #1039).
static POOLS_SPAWNED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// How many reader WORKER THREADS have been spawned in this process, ever (`rmp` #1039).
static READER_THREADS_SPAWNED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Reader pools spawned since the process started.
///
/// A test counts a DELTA across one `spawn_engine_with_timeout` and requires it to be `1` whatever `W`
/// is. Counting the `Builder::spawn` calls rather than reading `/proc/self/task` is deliberate: the
/// procfs route is Linux-only, so the gate would silently assert nothing on the macOS leg, and a gate
/// that quietly skips is indistinguishable from one that passes.
#[must_use]
pub fn pools_spawned() -> u64 {
    POOLS_SPAWNED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Reader worker threads spawned since the process started. See [`pools_spawned`].
#[must_use]
pub fn reader_threads_spawned() -> u64 {
    READER_THREADS_SPAWNED.load(std::sync::atomic::Ordering::Relaxed)
}

impl<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static> ReadPool<D, S> {
    /// Spawns `threads` reader workers draining a queue of capacity `queue_capacity`. Each worker posts
    /// retirements back to the engine through `retire_tx` (a dedicated retirement channel the engine
    /// loop polls — kept separate from the command channel so the workers' clones never pin the command
    /// channel open). `threads` is clamped to at least 1; `queue_capacity` to at least 1.
    #[must_use]
    pub fn spawn(
        threads: usize,
        queue_capacity: usize,
        // The pool-wide egress-stall ceiling (`rmp` #591 C-F1): threaded from the engine config into every
        // worker so a stalled consumer releases its reader's GC-watermark pin + pool slot even when the
        // per-statement timeout is disabled. Captured once here — it is a server policy, not per-task.
        egress_stall_timeout: Option<std::time::Duration>,
        retire_tx: Sender<ReadRetirement>,
        metrics: Arc<Metrics>,
    ) -> Self {
        let threads = threads.max(1);
        POOLS_SPAWNED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        READER_THREADS_SPAWNED.fetch_add(threads as u64, std::sync::atomic::Ordering::Relaxed);
        let (work_tx, work_rx) =
            std::sync::mpsc::sync_channel::<ReadTask<D, S>>(queue_capacity.max(1));
        // One shared, lockable receiver: `std::sync::mpsc::Receiver` is `!Sync`, so wrap it in a
        // `Mutex` for the workers to pull from (a brief lock to dequeue one task — the per-task read
        // work dwarfs it). This is the standard MPMC-over-mpsc worker pattern.
        let work_rx = Arc::new(std::sync::Mutex::new(work_rx));
        let mut workers = Vec::with_capacity(threads);
        for i in 0..threads {
            let work_rx = Arc::clone(&work_rx);
            let retire_tx = retire_tx.clone();
            let metrics = Arc::clone(&metrics);
            let join = std::thread::Builder::new()
                .name(format!("graphus-reader-{i}"))
                // Reader workers run the full read pipeline (parse/analyze/lower/eval), which recurses
                // on AST depth, so they need the same large stack as the engine thread (`rmp` #473):
                // the default ~2 MiB stack overflows on a legal at-the-limit query and a stack overflow
                // aborts the whole process.
                .stack_size(super::QUERY_ENGINE_STACK_SIZE)
                .spawn(move || {
                    // `rmp` #973: reader-pool workers are deliberately OUTSIDE the deterministic
                    // scheduler. They block in `recv()` on a bounded `sync_channel`, and a thread
                    // that parks in `recv()` holding the execution token freezes the whole
                    // simulation — bringing them under it needs the channel handled as a scheduled
                    // resource, which is a task of its own.
                    graphus_core::sched::exempt();
                    worker_loop(&work_rx, egress_stall_timeout, &retire_tx, &metrics);
                })
                // A failure to spawn a worker is a startup-time OS resource error; surfacing it as a
                // panic here is acceptable (the server is coming up and the pool size is bounded/small).
                .expect("INVARIANT: spawning a bounded reader worker thread");
            workers.push(join);
        }
        Self {
            work_tx: std::sync::Mutex::new(Some(work_tx)),
            workers: std::sync::Mutex::new(workers),
        }
    }

    /// Tries to enqueue `task` without blocking, returning it back (`Err`) if the bounded queue is full
    /// (the dispatch site then fast-rejects with [`super::ServerBusy`] / runs inline). A disconnected
    /// queue (workers gone) likewise returns the task back.
    // The `Err`-returns-the-task contract again (see [`ReadDispatch::try_submit`]); boxing would tax the
    // common success path.
    #[allow(clippy::result_large_err)]
    pub fn try_submit(&self, task: ReadTask<D, S>) -> Result<(), ReadTask<D, S>> {
        let guard = self
            .work_tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The queue is closed (shutdown ran): hand the task back, exactly as a full queue does. The
        // caller runs it inline, which is correct — just serial.
        let Some(tx) = guard.as_ref() else {
            return Err(task);
        };
        match tx.try_send(task) {
            Ok(()) => Ok(()),
            Err(std::sync::mpsc::TrySendError::Full(task))
            | Err(std::sync::mpsc::TrySendError::Disconnected(task)) => Err(task),
        }
    }

    /// Closes the work queue (so the workers' `recv` ends) and joins every worker, so no reader thread
    /// outlives the engine.
    ///
    /// Takes `&self` and is IDEMPOTENT (`rmp` #1039): the pool is the engine's and is shared by every
    /// worker, so there is no single owner to consume it. Whichever caller arrives first takes the
    /// sender and joins; a later caller finds the queue already closed and returns without joining
    /// twice. Both the `Shutdown` command handler and the loop-exit teardown call it, and either may
    /// be the first depending on how the engine stops.
    pub fn shutdown(&self) {
        // Taking `work_tx` closes the queue; each worker's blocking `recv` then returns `Err` and the
        // worker loop ends.
        let closed = self
            .work_tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if closed.is_none() {
            return; // already shut down; the joins below have already run
        }
        drop(closed);
        // Join OUTSIDE the sender lock: a worker finishing its last task may still be running, and
        // holding the submit lock across the join would block every concurrent `try_submit` for the
        // duration of a read rather than letting it fall back to the inline path.
        let workers = std::mem::take(
            &mut *self
                .workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for join in workers {
            let _ = join.join();
        }
    }
}

/// One reader worker's loop: pull a task under the shared lock, run it, post the retirement. Ends when
/// the work queue is closed (the engine dropped the sender at shutdown). If the engine's retirement
/// channel is closed (engine gone), the send fails harmlessly and the worker drains the rest.
fn worker_loop<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    work_rx: &Arc<std::sync::Mutex<Receiver<ReadTask<D, S>>>>,
    egress_stall_timeout: Option<std::time::Duration>,
    retire_tx: &Sender<ReadRetirement>,
    metrics: &Metrics,
) {
    loop {
        // Briefly lock the shared receiver to dequeue one task (released immediately so other workers
        // can pull concurrently). A poisoned lock (a worker panicked mid-dequeue) is recovered: the
        // receiver itself is intact, so we proceed.
        let task = {
            let guard = match work_rx.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.recv()
        };
        let Ok(task) = task else {
            // Queue closed: the engine is shutting down. Exit so the worker can be joined.
            return;
        };
        // `rmp` tasks #377 / #575-g.1: mark this thread a reader-pool worker for the read's duration,
        // carrying the **adaptive morsel width** the engine dispatch site chose from `readers_inflight`
        // (`Ctx.morsel_threads` reads this width at every `Cursor::open` on this thread). A lone heavy
        // read (reader pool otherwise idle) was dispatched with the FULL analytics-pool width, so it fans
        // out across all cores (the `rmp` #575 intra-query win); `K` concurrent reads were each dispatched
        // with width `<= P/K`, so the SUM of their fan-outs never exceeds the analytics pool capacity `P`
        // (the `rmp` #377 no-oversubscription guarantee — width collapses to `1`, i.e. serial-per-read, at
        // `K >= P`). The width is snapshotted here *before* `task` is moved into `run_read_task`. The guard
        // restores the prior width on drop (incl. panic-unwind), so it never leaks to the next task this
        // reused worker runs.
        // `rmp` task #386: isolate the read behind a panic boundary. A panic in a read task (executor,
        // materializer, UDF, or a `rayon`-propagated morsel/GDS worker panic re-raised on *this* worker
        // thread) must NOT kill the worker — that would silently shrink the pool, leak
        // `readers_inflight`, and pin the GC watermark forever (the reader's txn/ticket never retires).
        // Instead it becomes a retirement with an `Err` outcome, so the engine rolls the reader back +
        // decrements `readers_inflight`, and the worker stays alive to serve the next task.
        //
        // We snapshot the fields the catch handler needs (`txn`, `ticket`, a clone of `row_tx`, and a
        // fresh empty SIREAD buffer) *before* moving the task into `run_read_task`, because a panic
        // consumes the task's own copies. A fresh empty buffer is correct: an aborted read contributes
        // no SIREAD markers, so the engine's M1 merge is a no-op before the rollback. `AssertUnwindSafe`
        // is sound because the recovery path observes none of the task's partially-mutated state — it
        // builds the retirement purely from the pre-captured `Send` snapshot, and the engine's
        // `finish_reader` rolls the reader's transaction back regardless of where the panic struck.
        let txn = task.txn;
        let ticket = task.ticket;
        let morsel_width = task.morsel_width;
        let row_tx_fallback = task.row_tx.clone();
        let retirement = {
            let _morsel_width =
                graphus_cypher::morsel::ReaderPoolWorkerGuard::enter_with_width(morsel_width);
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_read_task(task, egress_stall_timeout, metrics)
            })) {
                Ok(retirement) => retirement,
                Err(panic_payload) => {
                    metrics.record_statement_panic();
                    tracing::error!(
                        target: "graphus::engine",
                        ticket = ticket.0,
                        panic = %panic_detail(&panic_payload),
                        "read task panicked; retiring it as a rollback and keeping the worker alive (rmp #386)",
                    );
                    // Deliver a clean terminal error to the consumer (no-op if the reader already sent a
                    // terminal item or the consumer is gone), then retire as a rollback.
                    let _ = row_tx_fallback.send(Err(GraphusError::Runtime(format!(
                        "internal error: read statement aborted ({})",
                        panic_detail(&panic_payload)
                    ))));
                    ReadRetirement {
                        txn,
                        ticket,
                        buffer: graphus_txn::SsiReadBuffer::new(txn),
                        outcome: Err(rollback_marker()),
                        row_tx: row_tx_fallback,
                    }
                }
            }
        };
        // Post the retirement back to the engine loop. The std `send` Release/Acquire is the
        // happens-before that publishes the buffer + all the reader's memory effects to the engine
        // thread before it merges. A closed channel (engine gone) is harmless: the reader already
        // streamed its rows; nothing further to coordinate.
        let _ = retire_tx.send(retirement);
    }
}

/// A lightweight error marking a retirement `outcome` as "roll back" (`rmp` task #336, Slice 3b-ii).
/// The reader has **already** streamed the real error to the consumer as the terminal stream item; the
/// engine only needs `outcome.is_err()` to choose rollback over commit. (Re-using the real error here
/// would require it to be `Clone`, which [`GraphusError`] is not.)
fn rollback_marker() -> GraphusError {
    GraphusError::Runtime(
        "read statement rolled back (error already streamed to client)".to_owned(),
    )
}

/// Extracts a human-readable message from a caught read-task panic payload (`rmp` task #386), covering
/// the two payload shapes the std panic hook produces (`&str` and `String`).
fn panic_detail(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}
