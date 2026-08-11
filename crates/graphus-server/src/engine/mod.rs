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
pub(crate) mod bulk_load;
pub(crate) mod bulk_load_b;
pub mod command;
pub(crate) mod constraint_show;
mod exec;
mod handle;
pub(crate) mod index_show;
mod latch;
mod local;
mod managed;
pub mod privileges;
/// The off-thread reader pool and its retirement channel (`rmp` task #336). Public since `rmp` #1039
/// only so that `pools_spawned` / `reader_threads_spawned` — the counters the "one pool per engine"
/// gate reads — are reachable from an integration test.
pub mod read_pool;
pub mod rest_values;
mod seam_bolt;
mod seam_rest;
pub mod stream;

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use graphus_core::error::{GraphusError, Result};
use graphus_cypher::{IndexBuildTotals, IndexCollectionTotals, TxnCoordinator};
use graphus_io::BlockDevice;
use graphus_storage::{GcPassReport, RecordStore};
use graphus_txn::IsolationLevel;
use graphus_wal::LogSink;

pub use bulk_load::{BulkImportBatchInput, BulkImportBatchOutcome};
pub use bulk_load_b::{BulkImportModeBChunkInput, BulkImportModeBChunkOutcome};
pub use command::{
    AccessMode, CheckpointReply, ConstraintCommand, ConstraintCreateKind, ConstraintEntity,
    ConstraintTypeFilter, CreateConstraint, EngineCommand, IndexCommand, IndexDdlReply,
    IndexTypeFilter, NodePropertyIndexRef, RelPropertyIndexRef, RunReply, RunSummary,
};
pub use handle::{EngineHandle, ServerBusy};
// `EngineDegraded` is defined in this module (below); re-export note: it is `pub` here.
pub use local::LocalEngine;
pub use privileges::EffectivePrivileges;
pub use seam_bolt::BoltEngineExecutor;
pub use seam_rest::{RestAuthObserver, RestEngineAdapter};

use crate::metrics::Metrics;
use command::EngineCommand as Cmd;
use graphus_core::latch::assert_no_engine_latch_held;
use graphus_core::{TxnId, Value};
use graphus_storage::ConstraintKind;
use latch::EngineLatch;

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
/// `unfrozen_commit_lsn` map). It is checked only after a mutating command, so a fully idle engine (no
/// WAL growth, nothing to reclaim) never wakes to run it.
///
/// Since `rmp` #556 this 256 MiB value is the **upper cap** of the adaptive ordinary cadence
/// ([`maintenance_interval_bytes`]), not the interval itself: a store at least
/// `256 MiB / WAL_STORE_RATIO_TARGET` (= 64 MiB) large keeps exactly this historical cadence, so
/// large-store reclamation is never made *less* frequent than before; a smaller OLTP store reclaims
/// proportionally sooner, so its on-disk WAL cannot grow to tens of times the store size.
const MAINTENANCE_CHECKPOINT_INTERVAL_BYTES: u64 = 256 * 1024 * 1024;

/// Target ceiling for the on-disk WAL/store byte ratio under the ordinary (non-`Loading`) cadence
/// (`rmp` #556). The reclaiming maintenance checkpoint fires once the un-reclaimed WAL grows past
/// `WAL_STORE_RATIO_TARGET × store_bytes`, so the physically-retained WAL is bounded to ≈ this multiple
/// of the live store instead of the fixed 256 MiB that left a 7 MB OLTP store with a ~180 MB WAL.
///
/// The bound is durability-neutral: recovery redo is already bounded by the store's own
/// [`graphus_storage::DEFAULT_CHECKPOINT_INTERVAL_BYTES`] flush, and reclamation only ever frees the WAL
/// prefix provably below the reclaim floor (`min(checkpoint_lsn, oldest_unfrozen_commit_lsn,
/// oldest_active_first_lsn)`). Reclaiming *more* often is strictly safer (a shorter recovery scan), so a
/// smaller multiple only trades a little extra checkpoint I/O for a smaller footprint.
const WAL_STORE_RATIO_TARGET: u64 = 4;

/// Floor of the adaptive ordinary cadence (`rmp` #556): never run a maintenance checkpoint more often
/// than every 8 MiB of WAL growth, so a tiny store is not checkpointed on a hair-trigger (each pass is
/// a full-store GC scan + a dirty-page flush + one fsync). 8 MiB of retained WAL is a negligible
/// absolute footprint even when it dwarfs a sub-megabyte store, and one extra fsync per ~8 MiB of WAL
/// is immaterial against the per-commit group-commit fsyncs already on the write path.
const MAINTENANCE_CHECKPOINT_MIN_INTERVAL_BYTES: u64 = 8 * 1024 * 1024;

/// After this many **consecutive** background maintenance checkpoint failures, reclamation is treated
/// as persistently stalled and this database's engine is flagged **degraded** (`rmp` #394/#435): the
/// **per-engine** [`MaintenanceDegraded`] flag flips, which drives `/health/ready` to `503` for that
/// database. A single transient failure (e.g. a brief I/O hiccup) is logged and retried without
/// escalation; only a run of failures — the signature of a stuck reclamation that would otherwise leak
/// memory behind a green readiness probe (a slow-motion OOM) — escalates. Any success on this engine
/// resets its streak and clears its own flag.
///
/// `pub` (mirroring [`arm_recovery_fault`]) so the multi-tenant readiness/isolation gate can drive
/// exactly `K` simulated failures.
pub const MAINTENANCE_FAILURE_ESCALATION_THRESHOLD: u32 = 3;

/// Stack size for every thread that **compiles or evaluates a Cypher query**: the single engine
/// thread and each off-thread reader-pool worker (`rmp` task #473).
///
/// The compile/execute pipeline is recursive-descent over the AST (parser, semantic analysis,
/// lowering, evaluation), so its peak stack usage is proportional to the *structural depth* of the
/// query's expressions/clauses. The cypher crate bounds that depth at compile time — expression
/// nesting by [`graphus_cypher::MAX_EXPR_DEPTH`] (≈ 1 000) and stacked clauses by
/// [`graphus_cypher::MAX_QUERY_CLAUSES`] (1 024, `rmp` #589) — converting anything deeper into a
/// recoverable compile error rather than a native stack overflow. But a Rust stack overflow **aborts
/// the whole process** (the guard-page handler calls `abort()`, which no `catch_unwind` can
/// intercept), so the thread must carry enough stack to absorb a *legal*, at-the-limit query with
/// comfortable margin. The default thread stack (~2 MiB on Linux) is **not** enough.
///
/// The **clause budget** dominates the sizing (`rmp` #589): the Volcano executor recurses one frame
/// per nested operator, so a legal `MAX_QUERY_CLAUSES`-clause chain descends ~1 024 frames of the
/// (heavy) `next()` → `project_row` → `eval` path *on this thread*. Measured empirically on the real
/// reader-pool path (debug build): a `WITH 1 AS a` chain overflows a 64 MiB stack at ~975 clauses, so
/// 64 MiB gave **no** margin for the 1 024 cap (it aborted). The cost is ~linear in stack size; at
/// **256 MiB** a 1 024-clause chain runs with the full cap fitting in **half** the stack (verified:
/// 1 024 clauses execute cleanly on 128 MiB), i.e. **≥ 2× margin** — and ≈ 3.8× versus the ~975/64 MiB
/// overflow point. The larger reservation costs only address space (lazily paged; RSS grows only with
/// actual depth), a handful of threads per database.
pub const QUERY_ENGINE_STACK_SIZE: usize = 256 * 1024 * 1024;

/// The maximum number of write commits coalesced into a single group-commit `fdatasync` (`rmp` #528,
/// `04 §4.2`).
///
/// The engine batches only commits **already queued** on its command channel: the drain stops the
/// instant `try_recv` reports the channel momentarily empty, so under low load a lone committer still
/// hardens immediately (a batch of one). This cap bounds the pathological case where commits arrive
/// faster than one `fdatasync` completes — it caps how many are PREPAREd (a handful of microseconds of
/// in-memory work + one WAL append each) before the batch is forced to harden, so a committer's added
/// latency is at most `MAX_COMMIT_BATCH − 1` cheap prepares plus one shared sync, never unbounded.
/// 128 is comfortably above the number of writer connections a single-writer engine services between
/// two `fdatasync`s on any realistic durable device, so in practice the natural channel-drain bound
/// (not this cap) ends every batch.
const MAX_COMMIT_BATCH: usize = 128;

/// The hard cap on how many commands ONE [`drain_commit_batch`] call processes before it returns to the
/// engine loop, regardless of how many of them join the group-commit batch (`rmp` task #583, F1).
///
/// [`MAX_COMMIT_BATCH`] bounds only the **durable-write** commits folded into the batch. But the drain
/// also processes, *without growing the batch*, two other command kinds and KEEPS DRAINING: auto-commit
/// **reads** (dispatched off-thread, `rmp` #543) and `Begin`/`BeginAutoCommit` **transaction-opens**
/// (dispatched inline, `rmp` #570). So a concurrent burst of reads/opens interleaved on the channel could
/// otherwise stretch a single drain far past `MAX_COMMIT_BATCH` iterations — and while the engine is
/// inside the drain it never returns to the loop top, starving [`process_retirements`] (which releases
/// off-thread readers' GC-watermark pins), [`maybe_reap_aged`] and [`resume_parked_statements`]. Capping
/// the TOTAL commands processed guarantees the drain returns — and that maintenance sweep runs — after at
/// most `MAX_DRAIN_COMMANDS`, at the cost only of a marginally smaller batch under extreme mixed pressure
/// (the leftover queued commits simply form the next batch). `2 × MAX_COMMIT_BATCH` leaves ample room for
/// a full write batch plus its interleaved opens/reads before the bound bites.
const MAX_DRAIN_COMMANDS: usize = 2 * MAX_COMMIT_BATCH;

/// A dedicated blocking thread that runs the offloaded WAL `fdatasync` of the **pipelined**
/// group-commit harden (`rmp` #532, commit pipelining / fsync offload).
///
/// # What it buys
///
/// [`WalManager::begin_harden`](graphus_wal::WalManager::begin_harden) writes a commit batch's
/// records to the log file *without* `fdatasync`ing and hands back a [`FsyncJob`]. The engine
/// [`submit`](WalSyncThread::submit)s that job here and, while the `fdatasync` runs on this thread,
/// PREPAREs the **next** consecutive commit batch (and retires reads) on the engine thread; it then
/// [`wait`](WalSyncThread::wait)s and completes the harden. So the durability sync of batch *K*
/// overlaps the CPU work of batch *K+1*, instead of the engine thread blocking on every `fdatasync`.
///
/// # Strict depth-1
///
/// The job channel is bounded at **1** and the engine always `wait`s for the outstanding job before
/// `submit`ting the next, so at most **one** batch is ever written-but-un-synced. The on-disk crash
/// state is therefore the same *category* as inline group commit (a torn tail of one un-synced batch,
/// which recovery truncates whole), so crash recovery is unchanged.
///
/// # Why a bare `std::thread`, not `graphus_io::FsyncPool`
///
/// The async runtime is Tokio, but this engine loop is a plain, blocking thread that must
/// `submit`/`wait` synchronously. `graphus_io::FsyncPool` is Tokio-only (its handles are futures),
/// unusable from here — so this is a `std::thread` with std channels.
///
/// # fsyncgate (`04 §4.9`)
///
/// A failed `fdatasync` is unrecoverable: [`wait`](WalSyncThread::wait) PANICs (a controlled abort)
/// **before** any committer of that batch is acked, so a lost batch is never acknowledged — the
/// ack-after-fsync rule, identical in effect to the inline `harden`'s panic policy.
struct WalSyncThread {
    /// Submits a job to the fsync thread. Bounded at 1 (depth-1): a job is submitted, then always
    /// `wait`ed on before the next submit, so `send` never blocks. `Option` so [`Drop`] can close it
    /// (ending the thread's loop) before joining. `None` only transiently during drop.
    job_tx: Option<std::sync::mpsc::SyncSender<graphus_wal::FsyncJob>>,
    /// The FIFO outcome of each submitted job: `Ok(target_len)` (the write frontier the `fdatasync`
    /// made durable, passed to `complete_harden`) or the storage error (→ fsyncgate PANIC).
    result_rx: std::sync::mpsc::Receiver<Result<u64>>,
    /// Joined on drop so the fsync thread never outlives the engine.
    handle: Option<std::thread::JoinHandle<()>>,
}

impl WalSyncThread {
    /// Spawns the dedicated fsync thread for the database `db_name`.
    fn spawn(db_name: &str) -> Self {
        let (job_tx, job_rx) = std::sync::mpsc::sync_channel::<graphus_wal::FsyncJob>(1);
        let (result_tx, result_rx) = std::sync::mpsc::channel::<Result<u64>>();
        let handle = std::thread::Builder::new()
            .name(format!("graphus-walsync-{db_name}"))
            .spawn(move || {
                // `rmp` #973: deliberately OUTSIDE the deterministic scheduler. This thread exists to
                // take a blocking `fdatasync` off the engine thread; scheduling it would put a real
                // syscall on the critical path of the token, and durability latency is not what a
                // deterministic interleaving is trying to model. Marked EXPLICITLY rather than left
                // unregistered, so an unmarked thread reaching a yield point still fails loudly.
                graphus_core::sched::exempt();
                // Run each submitted `fdatasync` in order, forwarding its outcome. The loop ends (and
                // the thread exits cleanly) when the engine drops `job_tx` at shutdown, or if the
                // result channel is gone (engine already torn down).
                for job in job_rx.iter() {
                    let target = job.target_len();
                    let outcome = job.run().map(|()| target);
                    if result_tx.send(outcome).is_err() {
                        break;
                    }
                }
            })
            .expect("INVARIANT: spawning the WAL fsync thread must succeed");
        Self {
            job_tx: Some(job_tx),
            result_rx,
            handle: Some(handle),
        }
    }

    /// Submits `job`'s `fdatasync` to run on the dedicated thread. Never blocks under the depth-1
    /// discipline (the previous job was always [`wait`](WalSyncThread::wait)ed on first).
    fn submit(&self, job: graphus_wal::FsyncJob) {
        self.job_tx
            .as_ref()
            .expect("INVARIANT: job_tx present for the engine's lifetime")
            .send(job)
            .expect("INVARIANT: the WAL fsync thread is alive for the engine's lifetime");
    }

    /// Waits for the in-flight `fdatasync` and returns the write frontier it hardened (for
    /// `complete_harden`).
    ///
    /// # Panics
    /// Panics (fsyncgate, `04 §4.9`) if the `fdatasync` failed — deliberately BEFORE any committer is
    /// acked, so a lost batch is never acknowledged.
    fn wait(&self) -> u64 {
        match self
            .result_rx
            .recv()
            .expect("INVARIANT: the WAL fsync thread is alive for the engine's lifetime")
        {
            Ok(target) => target,
            Err(e) => {
                panic!("WAL fdatasync failed; aborting to avoid silent data loss (fsyncgate): {e}")
            }
        }
    }
}

impl Drop for WalSyncThread {
    fn drop(&mut self) {
        // Close the job channel first (ends the thread's `iter()`), THEN join — so the fsync thread
        // never outlives the engine and any final in-flight `fdatasync` completes. Under depth-1 the
        // engine always waits before dropping, so no job is ever in flight at drop time.
        drop(self.job_tx.take());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A **test-only fault-injection seam** (`rmp` #409): the count of upcoming statement-recovery
/// rollbacks/commits that should *themselves* panic, simulating the historical `RefCell`-double-borrow
/// in `store.rs` (or the #359 buffer-pool replay panic class) striking inside the recovery path. Lets
/// the double-panic regression gate drive a deterministic recovery panic through the real engine
/// without corrupting the store. Compiled in only under the opt-in `internal-test-udf` feature (OFF in
/// production). A process-global atomic (not a thread-local) because the arming test thread and the
/// consuming engine thread are different OS threads.
#[cfg(feature = "internal-test-udf")]
static RECOVERY_FAULT_ARMED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Arms the recovery fault-injection seam for the next `n` recovery attempts (`rmp` #409, test-only).
#[cfg(feature = "internal-test-udf")]
pub fn arm_recovery_fault(n: u32) {
    RECOVERY_FAULT_ARMED.store(n, std::sync::atomic::Ordering::SeqCst);
}

/// A **test-only fault-injection seam** (`rmp` #450): the number of milliseconds the engine should
/// **block** at the start of its `Shutdown` handler, simulating a *wedged* engine thread (a hung
/// storage syscall / buffer-pool livelock) that never drains promptly. Lets the graceful-shutdown
/// timeout gate prove that [`crate::DatabaseCatalog::stop_engine`] force-detaches a wedged engine within
/// its deadline (rather than hanging `shutdown_all` under the admin lock — the #450 cross-tenant
/// availability hazard) without needing an actually-hung syscall. Compiled in only under the opt-in
/// `internal-test-udf` feature (OFF in production). A process-global atomic because the arming test
/// thread and the consuming engine thread are different OS threads. The block is **bounded** by the
/// armed value (the thread still eventually exits, so a test never permanently leaks an engine thread).
#[cfg(feature = "internal-test-udf")]
static SHUTDOWN_HANG_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Arms the shutdown-hang fault-injection seam: the next engine `Shutdown` blocks for `ms` milliseconds
/// before draining (`rmp` #450, test-only). `0` disarms.
#[cfg(feature = "internal-test-udf")]
pub fn arm_shutdown_hang(ms: u64) {
    SHUTDOWN_HANG_MS.store(ms, std::sync::atomic::Ordering::SeqCst);
}

/// Blocks for the armed shutdown-hang duration (consuming the arm), at the start of the engine's
/// `Shutdown` handler (`rmp` #450, test-only). A no-op (and zero-cost) in production where the feature
/// is off (the body compiles away entirely).
#[cfg(feature = "internal-test-udf")]
#[inline]
fn shutdown_hang_check() {
    use std::sync::atomic::Ordering;
    // Take-and-clear so a single arm fires exactly once (the wedged engine, once drained/detached, is
    // gone — a re-armed value would be for a fresh test).
    let ms = SHUTDOWN_HANG_MS.swap(0, Ordering::SeqCst);
    if ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

#[cfg(not(feature = "internal-test-udf"))]
#[inline]
fn shutdown_hang_check() {}

/// A **test-only fault-injection seam** (`rmp` #563): a *slow-but-progressing* `Shutdown` — the engine
/// takes a long time to drain but keeps making forward progress (bumping its drain-progress beacon), as
/// a healthy large-store flush / long GC pass does. Packs `cycles` into the high 32 bits and the
/// per-cycle `interval_ms` into the low 32 bits of one atomic. Used to prove
/// [`crate::DatabaseCatalog::stop_engine`]'s progress-aware drain does **not** force-detach such an
/// engine (the #563 regression), the complement of the `arm_shutdown_hang` (no-progress → force-detach)
/// seam. Compiled in only under `internal-test-udf`.
#[cfg(feature = "internal-test-udf")]
static SHUTDOWN_PROGRESS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Arms the slow-but-progressing shutdown seam: the next engine `Shutdown` heartbeats its drain-progress
/// beacon `cycles` times, `interval_ms` apart, before draining (`rmp` #563, test-only). `(0, _)` disarms.
#[cfg(feature = "internal-test-udf")]
pub fn arm_shutdown_progress(cycles: u32, interval_ms: u32) {
    let packed = (u64::from(cycles) << 32) | u64::from(interval_ms);
    SHUTDOWN_PROGRESS.store(packed, std::sync::atomic::Ordering::SeqCst);
}

/// Simulates a slow-but-progressing drain at the start of the engine's `Shutdown` handler: bumps the
/// store's drain-progress beacon `cycles` times, sleeping `interval_ms` between bumps (`rmp` #563,
/// test-only). A no-op (zero-cost) in production.
#[cfg(feature = "internal-test-udf")]
#[inline]
fn shutdown_progress_check<D: BlockDevice, S: LogSink>(coord: &TxnCoordinator<D, S>) {
    use std::sync::atomic::Ordering;
    let packed = SHUTDOWN_PROGRESS.swap(0, Ordering::SeqCst);
    let cycles = (packed >> 32) as u32;
    let interval_ms = u64::from(packed as u32);
    for _ in 0..cycles {
        coord.with_store_mut(|s| s.bump_drain_progress());
        std::thread::sleep(std::time::Duration::from_millis(interval_ms));
    }
}

#[cfg(not(feature = "internal-test-udf"))]
#[inline]
fn shutdown_progress_check<D: BlockDevice, S: LogSink>(_coord: &TxnCoordinator<D, S>) {}

/// Panics if the recovery fault seam is armed, decrementing the armed count (`rmp` #409, test-only).
/// Called at the start of each recovery rollback/commit so an armed fault makes the recovery itself
/// panic. A no-op (and near-zero-cost) in production, where the feature is off (the function body
/// compiles away entirely).
#[cfg(feature = "internal-test-udf")]
#[inline]
fn recovery_fault_check() {
    use std::sync::atomic::Ordering;
    // Decrement-if-positive: fire (and consume one arm) only while armed.
    let fire = RECOVERY_FAULT_ARMED
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n > 0).then(|| n - 1)
        })
        .is_ok();
    if fire {
        panic!("rmp #409: deliberate recovery double-panic (test fault injection)");
    }
}

#[cfg(not(feature = "internal-test-udf"))]
#[inline]
fn recovery_fault_check() {}

/// A **per-engine** "degraded" flag (`rmp` #414): set when a statement-recovery double-panic
/// (`rmp` #409) breaks a deep storage/MVCC invariant on *this* database's engine, so the engine
/// refuses further work over its no-longer-trustworthy in-memory state.
///
/// ## Why per-engine, not on the shared [`Metrics`]
///
/// Every database engine shares one [`Arc<Metrics>`] (the catalog clones it into each engine). The
/// pre-`rmp`-#414 design flagged degradation on a single `engine_degraded` atomic *on that shared
/// `Metrics`*, so the moment ONE database's engine caught a recovery double-panic, the per-statement
/// gate refused work on **every** database — a multi-tenant isolation breach (one corrupt secondary
/// database could take down the rest, violating the `CLAUDE.md` guarantee). Moving the *gating* flag
/// onto each engine confines the refusal to the affected database; a healthy database stays
/// serviceable. The aggregate `graphus_engine_recovery_panics_total` **counter** stays on `Metrics`
/// for observability (it is fleet-wide telemetry, not a gate).
///
/// Cloneable + `Send + Sync` (an `Arc<AtomicBool>`) so the same flag is shared between the engine
/// thread (the sole writer, via [`EngineDegraded::set`]) and every [`EngineHandle`] clone + the
/// `/health/ready` readiness aggregation (readers). There is **no auto-clear**: a broken in-memory
/// invariant is only safely resolved by a controlled engine/process restart.
#[derive(Clone, Debug, Default)]
pub struct EngineDegraded(Arc<AtomicBool>);

impl EngineDegraded {
    /// A fresh, not-degraded flag.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Flags this engine degraded (the recovery double-panic boundary, `rmp` #409/#414). Idempotent.
    pub fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether this engine is currently degraded — read by the per-statement gate and by
    /// `/health/ready`.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// A **per-engine** "maintenance/reclamation degraded" flag (`rmp` #394/#435): set when this
/// database's background maintenance checkpoint has failed
/// [`MAINTENANCE_FAILURE_ESCALATION_THRESHOLD`] times **consecutively** (reclamation is persistently
/// stuck — RAM/disk/version slots stop being freed while writes accrue, a slow-motion OOM), cleared
/// the moment a checkpoint on **this** engine succeeds.
///
/// ## Why per-engine, not on the shared [`Metrics`]
///
/// Every database engine shares one [`Arc<Metrics>`]. The pre-`rmp`-#435 design flagged the
/// reclamation-degraded *gating* state on a single `maintenance_degraded` atomic *on that shared
/// `Metrics`* (the residual sibling of the #414 `engine_degraded` cross-tenant breach). That had two
/// symmetric multi-tenant hazards: (1) ONE database's `K` consecutive maintenance failures flipped the
/// shared gauge, so `/health/ready` returned `503` for the **whole node** — taking a healthy default
/// database out of rotation; (2) ANY OTHER engine's *successful* checkpoint `store(0)`d the same gauge,
/// **false-clearing** a still-stuck database's degraded flag and masking a real stall. Moving the
/// *gating* flag onto each engine confines both the escalation and the clear to the affected database:
/// the engine that escalates sets its OWN flag, and a checkpoint success on engine A clears ONLY A's
/// flag (never B's). The aggregate `graphus_maintenance_failures_total` **counter** stays on `Metrics`
/// for observability (it is fleet-wide telemetry, not a gate).
///
/// Cloneable + `Send + Sync` (an `Arc<AtomicBool>`) so the same flag is shared between the engine
/// thread (the sole writer, via [`MaintenanceDegraded::set`]/[`clear`](Self::clear)) and every
/// [`EngineHandle`] clone + the `/health/ready` readiness aggregation (readers). Unlike
/// [`EngineDegraded`], maintenance degradation **does** auto-clear: a checkpoint that succeeds proves
/// reclamation is making progress again.
#[derive(Clone, Debug, Default)]
pub struct MaintenanceDegraded(Arc<AtomicBool>);

impl MaintenanceDegraded {
    /// A fresh, not-degraded flag.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Flags this engine's reclamation degraded (`K` consecutive maintenance failures, `rmp`
    /// #394/#435). Idempotent.
    pub fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Clears this engine's reclamation-degraded flag (a maintenance checkpoint on **this** engine
    /// succeeded, `rmp` #394/#435). Idempotent. Clears ONLY this engine's flag — never another
    /// engine's, which is the whole point of the #435 fix.
    pub fn clear(&self) {
        self.0.store(false, Ordering::SeqCst);
    }

    /// Whether **this** engine's reclamation is currently flagged degraded — read by `/health/ready`'s
    /// per-database readiness aggregation.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Per-engine bookkeeping that publishes this engine's open-transaction count into the
/// **server-wide** additive gauge (`rmp` #418).
///
/// Each engine owns one. [`publish`](Self::publish) folds the *signed delta* between the engine's
/// previously-published count and its current coordinator `active_count` into
/// [`Metrics::add_active_txns_delta`], so the shared `graphus_active_transactions` gauge equals the
/// SUM across every database engine — not whichever engine `store`d last (the pre-`rmp`-#418 bug that
/// made the `rmp` #386 leak oracle unsound under multi-DB). On drop (engine teardown) it retracts its
/// whole remaining contribution so a stopped engine leaves no phantom open-transaction count behind.
///
/// **One per ENGINE, not per worker** (`rmp` #1041). "Each engine owns one" was the intent from the
/// day it was written and stopped being true when the loop body became a worker body: it was
/// constructed inside `run_engine_loop`, so W workers each held one, and each folded the same
/// coordinator-wide `active_count` into the same additive gauge. The server-wide series then read up
/// to W times the truth for as long as transactions stayed open — self-correcting once they closed,
/// which is precisely what makes that kind of defect survive a glance at a dashboard. It is now built
/// once by [`spawn_engine_with_timeout`] and shared, which is also why `publish` takes `&self` and
/// swaps rather than read-compare-writing.
struct ActiveTxnGauge {
    metrics: Arc<Metrics>,
    /// The database name labelling this engine's per-database open-transaction gauge (`rmp` #463).
    db_name: Arc<str>,
    /// What this engine last contributed: `(open transactions, retained SSI conflict records)`.
    ///
    /// The second is the `graphus_ssi_tracked_transactions` gauge (`rmp` #591 D-#1), published at the
    /// SAME cadence as the first — every begin/commit/rollback/retire/reap/maintenance publish — so the
    /// gauge is never stale and equals the SUM across databases.
    ///
    /// Behind ONE lock, and the fold happens under it. Atomics are not enough here, which is worth
    /// spelling out because the lock-free version looks obviously correct and is not. Swapping the
    /// remembered value and folding the delta are two steps, so two workers can swap in one order and
    /// fold in the other — and `Metrics::add_delta` **saturates at zero** on a decrement. A `-3` that
    /// lands before the `+3` it was computed against is therefore clamped away and never recovered:
    /// `publish(3)` then `publish(0)`, folded in the reverse order, leaves the gauge permanently
    /// reading 3 against a truth of 0. The sum of the deltas telescopes; the gauge does not, because
    /// the clamp is not linear. Holding the lock across the fold makes the fold order the swap order,
    /// which is the property the telescoping argument actually needs.
    last: std::sync::Mutex<(u64, u64)>,
}

impl ActiveTxnGauge {
    fn new(metrics: Arc<Metrics>, db_name: Arc<str>) -> Self {
        Self {
            metrics,
            db_name,
            last: std::sync::Mutex::new((0, 0)),
        }
    }

    /// Publishes this engine's `active` open-transaction count and `ssi_tracked` retained-conflict-record
    /// count, folding only the delta since the last publish of each into the corresponding shared additive
    /// gauge(s): the open-transaction count into BOTH the aggregate and this database's per-database gauge
    /// (`rmp` #463), and the SSI-tracked count into the aggregate `graphus_ssi_tracked_transactions`
    /// gauge (`rmp` #591 D-#1). Both are cheap O(1) coordinator reads taken by the caller.
    fn publish(&self, active: usize, ssi_tracked: usize) {
        let active = active as u64;
        // The counts published here are the COORDINATOR's — engine-wide figures every worker reads and
        // republishes — so with W workers this is called concurrently, with values that differ only by
        // how recently each worker looked. Remembering and folding under ONE lock is what makes each
        // call fold exactly the change from the value it replaced, IN THAT ORDER; see the field docs
        // for why doing those two steps separately is unsound rather than merely racy.
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (prev, prev_ssi) = *last;
        let ssi_tracked = ssi_tracked as u64;
        *last = (active, ssi_tracked);
        if active != prev {
            self.metrics
                .add_active_txns_delta_for(&self.db_name, signed_delta(active, prev));
        }
        if ssi_tracked != prev_ssi {
            self.metrics
                .add_ssi_tracked_delta(signed_delta(ssi_tracked, prev_ssi));
        }
    }
}

/// The signed change from `before` to `now`, for an **additively-published** gauge (`rmp` #418).
///
/// `i128` headroom so the subtraction cannot overflow `i64` for any realistic count (both operands are
/// small `u64`s derived from a `usize`); the clamp handles the impossible-in-practice saturating case, and
/// makes the `as i64` provably lossless. Shared by [`ActiveTxnGauge`] and [`IndexBuildGauge`] so the
/// delta arithmetic is written once — the caller-side twin of [`crate::metrics`]'s `add_delta`.
///
/// NOTE: were the clamp ever to saturate, the caller's `last = now` would record the full value while only
/// `i64::MAX` was folded in, permanently skewing the gauge. That needs `> 9.2e18` concurrent items, so it
/// is unreachable — but it is the classic saturation-desync, and it is left recorded here rather than
/// silently assumed away.
fn signed_delta(now: u64, before: u64) -> i64 {
    (i128::from(now) - i128::from(before)).clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

impl Drop for ActiveTxnGauge {
    fn drop(&mut self) {
        // Retract this engine's whole remaining contribution so a stopped/torn-down engine never
        // leaves a phantom count in the server-wide gauge(s) OR this database's per-database gauge
        // (`rmp` #418/#463/#591).
        // Same lock, same reason — and it must not be the thing that turns a teardown into an abort: a
        // poisoned lock here guards two counters with no invariant a panic could have broken, so the
        // value is recovered rather than propagated. `Drop` is the one place where refusing to unwrap
        // aborts the process instead of reporting anything.
        let (last, last_ssi) = {
            let mut guard = self
                .last
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *guard)
        };
        if last != 0 {
            self.metrics.add_active_txns_delta_for(
                &self.db_name,
                -(i64::try_from(last).unwrap_or(i64::MAX)),
            );
        }
        if last_ssi != 0 {
            self.metrics
                .add_ssi_tracked_delta(-(i64::try_from(last_ssi).unwrap_or(i64::MAX)));
        }
        // `rmp` #992: withdraw this database's derived-index footprint too. Its trees are in-memory and
        // die with the engine, so a `STOP`/`DROP DATABASE` that left the last published count standing
        // would inflate the server-wide GAUGE for ever — the failure mode a monotone counter like
        // `wal_bytes_written` is immune to and a gauge is not. Publishing `0` folds in exactly `-last`.
        self.metrics
            .publish_derived_index_entries_for(&self.db_name, 0);
    }
}

/// This engine's contribution to the server-wide **index-build** gauges (`rmp` task #573) — the sibling
/// of [`ActiveTxnGauge`], following the same additive discipline for the same reason (`rmp` #418): with
/// `N` database engines sharing one gauge, a last-writer-wins `store` would report whichever engine wrote
/// last instead of the fleet total, so each engine folds in only the delta since its own last publish.
///
/// Its sibling's `rmp` #1041 correction applies here identically, and the exposure was larger: this one
/// republishes on EVERY loop iteration, so with a gauge per worker each of the W workers folded the
/// same engine-wide `index_build_totals` every tick. `parked` is an alerting signal, which makes a
/// W-fold reading an operator-facing fault rather than a cosmetic one. Built once per engine and
/// shared, so `publish` takes `&self`.
struct IndexBuildGauge {
    metrics: Arc<Metrics>,
    /// The counts this engine last contributed to each shared gauge (pending, parked, remaining).
    ///
    /// Behind a plain `Mutex` because the three fields must move together: `publish` compares all
    /// three and folds all three, and with W workers republishing the same engine-wide totals every
    /// tick a per-field atomic would let two workers interleave into a fold neither of them intended.
    /// Deliberately NOT an [`EngineLatch`] — rank 5 is the engine's session state, and this is a
    /// metrics fold held for three integer comparisons and never across any work.
    last: std::sync::Mutex<IndexBuildTotals>,
}

impl IndexBuildGauge {
    fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            metrics,
            last: std::sync::Mutex::new(IndexBuildTotals::default()),
        }
    }

    /// Publishes `totals`, folding only the change since the last publish into the shared gauges. A no-op
    /// when nothing changed — which is the overwhelmingly common case (no build running), so this costs an
    /// integer compare per engine-loop iteration.
    ///
    /// Both sides are **destructured** deliberately: a field added to [`IndexBuildTotals`] must not be
    /// able to slip through un-published (and, via [`Drop`], un-retracted) while the derived `PartialEq`
    /// above quietly keeps comparing it. Destructuring turns that omission into a compile error.
    fn publish(&self, totals: IndexBuildTotals) {
        // A poisoned lock guards three counters with no invariant a panic could have broken, and this
        // is reached from `Drop` — where refusing to unwrap would turn engine teardown into a double
        // panic and abort the process. Recover the value instead.
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if totals == *last {
            return;
        }
        let IndexBuildTotals {
            pending,
            parked,
            entities_remaining,
        } = totals;
        let IndexBuildTotals {
            pending: was_pending,
            parked: was_parked,
            entities_remaining: was_remaining,
        } = *last;
        self.metrics.add_index_build_deltas(
            signed_delta(pending as u64, was_pending as u64),
            signed_delta(parked as u64, was_parked as u64),
            signed_delta(entities_remaining as u64, was_remaining as u64),
        );
        *last = totals;
    }
}

impl Drop for IndexBuildGauge {
    fn drop(&mut self) {
        // Retract this engine's whole remaining contribution, so a stopped or torn-down engine never
        // leaves a phantom build in the server-wide gauges (`rmp` #418). This matters most for `parked`:
        // it is an alerting signal, and a leaked one would page an operator about an index build on a
        // database that no longer exists.
        self.publish(IndexBuildTotals::default());
    }
}

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
/// (and the seam opens the implicit transaction via [`EngineCommand::BeginAutoCommit`]); the engine
/// commits/rolls-back an auto-commit transaction in the `Run` handler when its stream drains (see
/// [`exec`]). We **also** record it here so the maximum-transaction-age sweep ([`maybe_reap_aged`],
/// `rmp` #477) can tell an explicit `BEGIN … COMMIT` transaction (which a client can hold open across
/// statements — the idle-in-transaction DoS surface) from a transient auto-commit statement (already
/// bounded by the per-statement timeout, and possibly mid-flight on an off-thread reader the sweep must
/// not race).
struct OpenTx {
    /// The coordinator's transaction id.
    txn: TxnId,
    /// The access mode (so a write statement in a `Read` transaction is rejected — `06 §4`).
    mode: AccessMode,
    /// Whether this transaction backs a single auto-commit statement (`true`) or is an explicit
    /// `BEGIN … COMMIT` transaction (`false`). The age sweep reaps only the latter (`rmp` #477).
    auto_commit: bool,
}

/// How many reaped tickets [`ReapedTickets`] remembers before the oldest is forgotten.
///
/// Sized so a client that is going to come back at all has long since done so: the ledger only holds
/// transactions the age sweep killed and whose owner has **not yet** been told, and each entry is
/// dropped the moment its owner is told. Reaching this bound therefore needs a thousand-plus reaped
/// transactions whose owners all vanished without ever touching them again.
const REAPED_LEDGER_CAP: usize = 1024;

/// A bounded, FIFO ledger of the tickets the maximum-transaction-age sweep rolled back (`rmp` #988).
///
/// # Why it exists
///
/// The sweep removes the transaction from the open table, so by the time its owner's next `RUN` or
/// `COMMIT` arrives the ticket is simply *absent* — indistinguishable from an id that was never issued
/// or one already spent. Both are permanent client faults, but they are **different** facts, and only
/// one of them tells an operator what actually happened. Reporting a reaped transaction as
/// "does not exist" sends them hunting a transaction-lifecycle bug when the cause is
/// `timing.max_transaction_age_ms`. This ledger preserves that fact for exactly as long as it takes to
/// deliver it.
///
/// # Why it is safe to bound
///
/// An entry is consumed the first time its owner is told, so the steady-state size is "reaped but not
/// yet observed", which is the same order as the number of open transactions. The cap only matters if
/// owners abandon their reaped transactions en masse, and overflowing it is a **graceful degradation**,
/// never a correctness fault: the oldest entry is forgotten and that ticket falls back to
/// `Neo.ClientError.Transaction.TransactionNotFound` — the same classification, the same
/// non-retryability, the same HTTP class, only a less specific title.
///
/// Ticket ids are issued by a monotonically increasing counter and are **never reused**
/// ([`open_tx`] post-increments `next_ticket`), so a remembered id can never be confused with a
/// future transaction.
#[derive(Debug, Default)]
struct ReapedTickets {
    /// The tickets currently remembered, for O(1) lookup.
    ids: std::collections::HashSet<u64>,
    /// The same ids in insertion order, so the oldest can be evicted at the cap.
    order: VecDeque<u64>,
}

impl ReapedTickets {
    /// Remembers `ticket` as reaped for age, evicting the oldest entry past [`REAPED_LEDGER_CAP`].
    fn record(&mut self, ticket: u64) {
        if self.ids.insert(ticket) {
            self.order.push_back(ticket);
        }
        while self.order.len() > REAPED_LEDGER_CAP {
            if let Some(oldest) = self.order.pop_front() {
                self.ids.remove(&oldest);
            }
        }
    }

    /// Reports whether `ticket` was reaped for age, **consuming** the record.
    ///
    /// Consuming is deliberate: the fact exists to be delivered once, to the owner asking now. An id
    /// left in `order` after its `ids` entry is taken is harmless — evicting it later removes an
    /// already-absent key.
    fn take(&mut self, ticket: u64) -> bool {
        self.ids.remove(&ticket)
    }
}

/// **Which worker owns a ticket** (`rmp` #1035, load-bearing since `rmp` #1041).
///
/// A worker mints `worker_id + W·n`, so `ticket % W` names its owner: routing, uniqueness and
/// ownership all come from one fact instead of from a table that could disagree with it.
///
/// Until `rmp` #1041 this was only the *handle's* concern — the engine side could not get it wrong,
/// because each worker's open-transaction table held only tickets that worker had minted, so a
/// foreign ticket was invisible rather than merely unclaimed. Sharing the table removed that
/// accident: every worker now sees every transaction, and the two passes that walk the table looking
/// for work to do — the age sweep and the parked-statement resume — must ask this question out loud.
/// The invariant they are protecting is that **a transaction is only ever touched by the worker that
/// owns its session**, which is what makes one transaction single-threaded in a multi-worker engine.
#[derive(Debug, Clone, Copy)]
struct WorkerAffinity {
    /// This worker's id, and the residue class of every ticket it mints.
    id: u64,
    /// How many workers the engine runs: the modulus, and the minting stride.
    workers: u64,
}

impl WorkerAffinity {
    /// `workers` is floored at one: a zero modulus is a division by zero, and an engine always has at
    /// least the worker asking the question.
    fn new(worker_id: usize, workers: usize) -> Self {
        Self {
            id: worker_id as u64,
            workers: workers.max(1) as u64,
        }
    }

    /// Whether `ticket` was minted by — and therefore belongs to — this worker.
    ///
    /// `true` for every ticket when the engine runs one worker, which is what keeps the single-worker
    /// engine byte-identical to its pre-`rmp` #1041 behaviour: every pass still considers everything.
    fn owns(self, ticket: u64) -> bool {
        ticket % self.workers == self.id
    }
}

/// **The engine's ONE ticket sequence** (`rmp` #1035, re-seated by `rmp` #1037).
///
/// Every ticket satisfies `ticket % W == worker_id`, so a ticket names the worker that owns its
/// session and the handle can route by arithmetic, with no lookup table and therefore no second
/// source of truth that could drift from the first. That part is `rmp` #1035's and it is right.
///
/// # Why the counter is the engine's and not each worker's
///
/// `rmp` #1035 gave each worker its own counter striding by `W`. The residue class came out correct,
/// and — silently — the one property every OTHER consumer of a ticket depends on did not: that ticket
/// order is TIME order. A per-worker counter advances only when its own worker mints, so worker 1's
/// brand-new ticket `3` is *smaller* than worker 0's hour-old ticket `2000`. Comparing two workers'
/// tickets then answers nothing at all, and two things compare them:
///
/// * [`gc_reuse_barrier`], whose floor has to exceed EVERY open ticket. Taken from one worker's
///   counter it exceeded that worker's tickets and nobody else's — worker 0 with an untouched counter
///   produced a barrier of `1`, which a sibling's already-open ticket `5` satisfies immediately, so
///   [`RecordStore::release_held`](graphus_storage::RecordStore::release_held) hands a live reader's
///   slot straight back to the allocator. That is `rmp` #1037's second defect, and it is the reason
///   this task is wider than sharing the reader counter.
/// * `oldest_open_ticket`, the release threshold, which since `rmp` #1041 is a MINIMUM over the
///   engine-wide open table and therefore mixes the residue classes on every read.
///
/// One shared sequence restores the premise rather than patching each consumer: the `n`-th ticket the
/// ENGINE issues is `(n + 1)·W + worker`. It is still exactly the owner's residue class (`worker < W`),
/// still never zero, and now strictly increasing in issue order across every worker, since
/// `(n+1)·W + w < (n+2)·W + w'` for any `w, w' < W`. At `W = 1` it is the historical sequence
/// 1, 2, 3, … — byte-identical, which is what keeps the single-worker engine and the DST golden traces
/// untouched.
#[derive(Debug)]
struct TicketSequencer {
    /// How many tickets this ENGINE has issued: the index of the next one.
    issued: AtomicU64,
    /// How many workers the engine runs: the stride, and the width of one issue slot.
    workers: u64,
}

impl TicketSequencer {
    fn new(workers: usize) -> Self {
        Self {
            issued: AtomicU64::new(0),
            // Floored at one for the same reason [`WorkerAffinity::new`] floors it: a zero stride
            // collapses every worker onto ticket `worker`, and a zero modulus is a division by zero.
            workers: workers.max(1) as u64,
        }
    }

    /// Issues the next ticket for `worker`, in that worker's residue class and never zero.
    fn issue(&self, worker: u64) -> u64 {
        (self.issued.fetch_add(1, Ordering::Relaxed) + 1) * self.workers + worker
    }

    /// The engine-wide ticket **high-water**: a value no ticket issued so far exceeds.
    ///
    /// With `n` tickets issued the occupied slots are `1..=n`, so the largest ticket that can exist is
    /// `n·W + (W − 1)` — slot `n` taken by the highest-numbered worker. Reading `issued` instead of
    /// remembering the maximum actually handed out is what makes this correct without a second atomic
    /// and without a per-worker scan: the barrier needs an UPPER bound, and this is one.
    ///
    /// Saturating, and the direction is chosen rather than inherited: a saturated high-water yields a
    /// barrier that holds slots for longer, where a wrapped one would release them early.
    fn high_water(&self) -> u64 {
        self.issued
            .load(Ordering::Relaxed)
            .saturating_mul(self.workers)
            .saturating_add(self.workers - 1)
    }
}

/// This worker's window onto the engine's [`TicketSequencer`] (`rmp` #1035).
///
/// Keeping the affinity WITH the sequence is the point: a caller cannot mint a ticket in the wrong
/// residue class by forgetting an argument — and the same [`WorkerAffinity`] the minter issues in is
/// the one the engine's cross-worker passes ask for ownership, so the two can never be derived from
/// different numbers.
#[derive(Debug)]
struct TicketMinter {
    /// The ENGINE's sequence, shared by every worker. See [`TicketSequencer`] for why one worker's
    /// own counter cannot answer any question that spans workers.
    seq: Arc<TicketSequencer>,
    /// Whose tickets these are: the residue class and the ownership test, in one value.
    affinity: WorkerAffinity,
}

impl TicketMinter {
    fn new(affinity: WorkerAffinity, seq: Arc<TicketSequencer>) -> Self {
        Self { seq, affinity }
    }

    /// The next ticket, never zero — zero is the unused value the open-table tests rely on.
    fn mint(&self) -> u64 {
        self.seq.issue(self.affinity.id)
    }

    /// Whose tickets these are. Read by the passes that walk the engine-wide session tables, so the
    /// ownership test and the issuing residue class can only ever come from the same number
    /// (`rmp` #1041).
    fn affinity(&self) -> WorkerAffinity {
        self.affinity
    }
}

/// **The stop protocol, shared by every worker of one engine** (`rmp` #1036).
///
/// This is the state that has no meaning per worker: a worker cannot count how many *other* workers
/// are still running, and a stop that only one worker can see is not a stop. It is therefore built
/// once in [`spawn_engine_with_timeout`] and handed to each worker as an `Arc` — the shape
/// [`EngineSessions`] took for the session tables in `rmp` #1041, for the same reason.
///
/// It was originally a pair of fields inside the per-worker struct, whose doc-comment claimed it was
/// "declared once … without any of it being duplicated per worker" while the code constructed it
/// *inside* `run_engine_loop`. Every worker therefore counted itself and W−1 phantoms, so the worker
/// handling `Shutdown` waited for a number that nobody else could ever move, and spun for the life
/// of the process. In a server that is not a hang but a permanent one: `stop_engine` observes no
/// drain progress, force-detaches, and the spinning zombie keeps the exclusive store-open lock, so
/// every later `START DATABASE` for that store fails.
struct EngineStop {
    /// How many workers are still inside the loop. The worker that handles `Shutdown` must be the
    /// LAST one out, because the shutdown path consumes the coordinator for the final flush and
    /// `Arc::try_unwrap` needs sole ownership. It raises `stopping`, waits for this to reach one,
    /// and only then drains and hardens.
    ///
    /// The count means **"workers that may still hold a share of the coordinator"**, not "workers
    /// that are still looping" — see the exit sequence at the end of [`run_engine_loop`], which
    /// releases the share *before* decrementing. A counter decremented any earlier cannot support
    /// the `try_unwrap`, which is the whole reason the barrier exists.
    live_workers: AtomicUsize,
    /// Raised by whichever worker handles `Shutdown`. Every worker checks it before blocking on its
    /// queue, so a stop reaches all of them and not only the one that was handed the command.
    /// Without it the others would sit in `recv` until the last client sender dropped — which is a
    /// different, later, and unrelated event.
    stopping: AtomicBool,
}

impl EngineStop {
    fn new(workers: usize) -> Self {
        Self {
            live_workers: AtomicUsize::new(workers),
            stopping: AtomicBool::new(false),
        }
    }
}

/// **The engine's SESSION state, shared by every worker of one engine** (`rmp` #1041).
///
/// This is the state a worker cannot keep a private copy of and still be right. It is built once in
/// [`spawn_engine_with_timeout`] and handed to each worker as an `Arc` — like [`EngineStop`], and for
/// the same reason: a table only one worker can see answers questions about that worker, and every
/// consumer below asks about the *engine*.
///
/// # What was wrong while each worker had its own, stated as measurements
///
/// * **The `Shutdown` drain reached one worker.** [`drain_inflight`] rolls back every still-open
///   transaction so a clean stop leaves recovery nothing to undo. Over a per-worker table it drained
///   the table of whichever worker happened to receive `Shutdown` — measured with
///   `graphus_transactions_aborted_total`, which it increments once per rollback: **one of four at
///   `W = 4`, one of one at `W = 1`, and the shutdown reported success either way**. Durability
///   survived (no `COMMIT` record was ever written, so ARIES undoes the rest on reopen), but the
///   property the code documents — a clean stop leaves nothing to undo — was false,
///   `record_abort_for` under-counted, and the next open paid for undo it should never have faced.
/// * **Plan-cache invalidation reached one worker.** Measured with `engine_workers = 4`, on one
///   engine and one query text: a `USING INDEX` plan compiled and cached on worker 0 was still
///   ACCEPTED after a `DROP INDEX` that landed on worker 1, which rejected it with "planner hint
///   cannot be satisfied". The same query was therefore accepted on one connection and rejected on
///   another, for as long as the process lived. Whether a query is *accepted* must not depend on which
///   connection served it — a Cypher-conformance property, not a performance one. Only the
///   ASYNCHRONOUS property-index build self-healed, because [`invalidate_cache_on_build_completion`]
///   reads the *shared* `has_pending_index_builds`; every synchronous DDL (any `DROP INDEX`,
///   `CREATE`/`DROP` of FULLTEXT/POINT/TEXT/VECTOR, and all constraint DDL) and the `rmp` #733
///   fail-closed index repair diverged permanently, and only a restart cleared it.
/// * **`open` and `parked` cannot be separated.** The age sweep excludes suspended statements by
///   testing them against the parked queue, so sharing `open` alone would let a worker reap a
///   transaction whose suspended cursor is alive on another. They are shared together — and because a
///   statement *executing* inline is in neither table, that exclusion is not sufficient on its own:
///   the sweep also reaps only what this worker [`owns`](WorkerAffinity::owns). See
///   [`maybe_reap_aged`].
///
/// # Why each is latched separately, and why that is the whole design
///
/// One lock around this struct — or, worse, held around the command dispatch — is how W threads end up
/// taking turns: *apparent* parallelism, indistinguishable from a multi-writer engine except by CPU
/// occupancy, which then reads one core however many workers the engine was given. The separation is
/// what keeps the long part of a statement outside every lock:
///
/// * `open` is consulted by `exec::handle_run` to copy the entry's two `Copy` fields, and again when
///   the statement finalises. Nothing between those two points touches it. Short commands (`BEGIN`,
///   `COMMIT`, `ROLLBACK`, `STATUS`) reach it once, for an `O(1)` table operation.
/// * `plan_cache` is consulted once per statement to look a plan up, and once to install one. The
///   compile between them runs unlatched.
/// * `parked` is touched only when a statement suspends or resumes.
///
/// Until `rmp` #1038 that was true of the *data* and false of the *guards*, which is not a distinction
/// the machine makes. Every execution call site passed its guard in argument position — and a Rust
/// temporary lives to the end of the statement that created it, so each of those guards spanned the
/// query it was nominally protecting a table lookup for. The tables are [`EngineLatch`]es (rank 5),
/// which cannot be handed over that way and whose tripwire fires if one is still held when execution
/// begins. That work had to land first: sharing tables that were acquired in two opposite orders (the
/// age sweep took *open -> parked*, the resume and park paths took *parked -> open*) would have turned
/// a latent ABBA into a real deadlock on the day of this change. Rank 5 refuses the second acquisition
/// outright, so the cycle cannot be re-formed by a later edit either.
///
/// Measured, in `tests/engine_latch_scaling_1038.rs`. That gate predicted this change before it landed,
/// by hoisting the three tables into process-wide statics: **3.95 of 4 cores**. Run against the real
/// sharing it reports **3.93 of 4**, against 0.99 for a single worker. Sharing is not what costs;
/// holding a latch across a statement is, and `rmp` #1038 is what stopped that.
struct EngineSessions {
    /// The explicit transactions this ENGINE has open, keyed by ticket.
    open: EngineLatch<OpenTxTable>,
    /// Compiled plans, keyed by query text and schema generation.
    plan_cache: EngineLatch<exec::EnginePlanCache>,
    /// Statements suspended mid-execution, oldest first (`rmp` #485). Engine-wide, so
    /// `max_parked_inline` now bounds the ENGINE rather than each worker separately.
    parked: EngineLatch<VecDeque<exec::InFlightInline>>,
}

impl EngineSessions {
    fn new() -> Self {
        Self {
            open: EngineLatch::new(OpenTxTable::new()),
            plan_cache: EngineLatch::new(exec::EnginePlanCache::new()),
            parked: EngineLatch::new(VecDeque::new()),
        }
    }
}

// The current thread's reclaim-gate nesting depth (`rmp` #1037). Always absent in a release build:
// the whole tripwire is `debug_assertions`-only, so production pays nothing for it.
#[cfg(debug_assertions)]
thread_local! {
    static RECLAIM_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// The debug-only half of [`ReclaimPassGuard`]: proves the reclaim gate is never re-entered.
///
/// `std::sync::Mutex` is not reentrant, so a second acquisition on a thread that already holds it is
/// a silent, permanent hang for [`EngineReclaim::enter_pass`] and a wrong `None` for
/// [`EngineReclaim::try_enter_pass`] — the second of which is worse, because it looks like "another
/// worker is reclaiming" and simply skips the pass forever. Today the four doors into the gate cannot
/// nest, which is a fact about four call sites in this file and not about the type. This makes it a
/// fact about the type: the assertion fires at the acquisition that commits the error, in every debug
/// build, including the whole workspace test suite and the DST batteries.
///
/// It is NOT one of `graphus_core::latch`'s ranked tripwires, and the difference is the point. Every
/// scope in that module asserts that its lock does not span a durability barrier. This gate exists
/// precisely to span one — it is held across the reclaim pass's own `fdatasync` — so arming a scope
/// that promises the opposite would be a false statement, not a stronger one.
#[cfg(debug_assertions)]
struct ReclaimDepth;

#[cfg(debug_assertions)]
impl ReclaimDepth {
    fn enter() -> Self {
        RECLAIM_DEPTH.with(|d| d.set(1));
        Self
    }
}

/// Refuses a reclaim-gate acquisition by a thread that is already inside one.
///
/// Called at BOTH doors, and BEFORE either of them touches the mutex — which is the only placement
/// that catches the dangerous half. Arming the tripwire when the guard is constructed catches the
/// `enter_pass` hang (a hang reports nothing, but at least the thread never gets a guard to arm), and
/// misses `try_enter_pass` entirely: that door returns `None` without constructing anything, so a
/// self-inflicted refusal is indistinguishable from a sibling's legitimate one and the maintenance
/// cadence is skipped for the life of the process, silently. The check has to be at the door.
///
/// Compiles away entirely in a release build.
fn assert_not_already_reclaiming() {
    #[cfg(debug_assertions)]
    RECLAIM_DEPTH.with(|d| {
        assert_eq!(
            d.get(),
            0,
            "the engine reclaim gate is not re-entrant: this thread is already inside a reclaim \
             section, so `enter_pass` would hang here and `try_enter_pass` would answer `None` — \
             indistinguishable from a sibling's pass, and skipping this one forever (rmp #1037)"
        );
    });
}

#[cfg(debug_assertions)]
impl Drop for ReclaimDepth {
    fn drop(&mut self) {
        RECLAIM_DEPTH.with(|d| d.set(0));
    }
}

/// The right to be the engine's reclaiming worker, for as long as this guard lives (`rmp` #1037).
///
/// Field order is the release order and it is chosen rather than inherited: struct fields drop in
/// declaration order, so the mutex is released first and only then does this thread stop counting as
/// the holder. That is the same RAII discipline [`latch::EngineLatchGuard`] follows, and stating it is
/// what makes a future reordering a decision instead of an accident.
struct ReclaimPassGuard<'a> {
    _guard: std::sync::MutexGuard<'a, ()>,
    #[cfg(debug_assertions)]
    _depth: ReclaimDepth,
}

impl<'a> ReclaimPassGuard<'a> {
    fn new(guard: std::sync::MutexGuard<'a, ()>) -> Self {
        Self {
            _guard: guard,
            #[cfg(debug_assertions)]
            _depth: ReclaimDepth::enter(),
        }
    }
}

/// **The engine's RECLAMATION state, shared by every worker of one engine** (`rmp` #1037).
///
/// The last piece of [`run_engine_loop`]'s state that had no per-worker meaning, after [`EngineStop`]
/// (`rmp` #1036) and [`EngineSessions`] (`rmp` #1041). What is left genuinely per worker is one value:
/// the [`TicketMinter`], because its residue class *is* `rmp` #1035's routing — and even that now
/// issues from the engine's one [`TicketSequencer`], because the ticket ORDER belongs to the engine
/// even though the residue class belongs to the worker.
///
/// # What was wrong while each worker had its own, stated as the failure it produced
///
/// * **The slot-reuse barrier read one worker's reader count.** `readers_inflight` gates the `rmp`
///   #588 barrier. Worker A ran a maintenance pass, saw its own count at zero, armed nothing, and the
///   slots that pass freed were immediately reusable — while worker B had off-thread reads walking
///   incidence chains through them. The next write takes the slot and the reader in flight reads a
///   stranger's record: a silently wrong answer, the `rmp` #811 class, with nothing in the log.
/// * **The barrier's floor came from one worker's counter.** See [`TicketSequencer`]: with per-worker
///   counters a barrier derived from worker A's counter does not dominate worker B's open tickets, so
///   `release_held` fires under a live reader even when the barrier IS armed. Sharing the reader
///   count alone would have fixed the first half and left this one standing.
/// * **The maintenance cadence ran W times.** `maybe_run_maintenance` is called from the tail of
///   `process_command`, which every worker runs, each against its own WAL watermark — so `W`
///   independent cadences, each deciding on its own numbers. Worse than redundant: the reuse barrier
///   is ONE atomic shared by all six stores (`graphus_storage::idalloc::SharedReuseBarrier`,
///   `rmp` #1025) and `TxnCoordinator::checkpoint_reader_safe` disarms it unconditionally when its
///   pass ends, so two overlapping passes make the first one's disarm leave the second one's frees
///   UNSTAMPED — the exact hole `rmp` #1025 closed, re-opened from above.
///
/// # The release floor, and why the barrier alone is not enough above one worker
///
/// At `W = 1` arming, freeing and minting all happen on the same thread, so no transaction can be
/// born between the arm and the last free and `high_water + 1` dominates every ticket that could be
/// walking a chain. Above one worker that is false: a sibling opens transactions *while* the pass
/// runs, and those tickets are above the barrier, so they do not hold anything back — yet their read
/// views can predate a free.
///
/// [`release_floor`](Self::release_floor) closes that by reasoning at the END of the pass instead of
/// at its start: the engine records the ticket high-water once the pass has finished freeing, and
/// releases NOTHING until the oldest open transaction has passed that mark. Every transaction alive
/// at any instant of the pass was issued before that mark (its ticket is published by
/// [`TicketSequencer::issue`] before `open_tx` returns, and no read view is captured until after it
/// returns), so the gate is exactly "everyone who could have been walking has retired". Anything
/// issued after the mark took its read view after the last free and is not at risk.
///
/// The floor is raised only at `W > 1`: at one worker it stays `0`, every real ticket exceeds `0`, and
/// the gate is transparent — which is what keeps the single-worker engine byte-identical.
/// Marks a transaction that has begun opening and is not yet visible in the open table
/// (`rmp` #1037). See [`EngineReclaim::opening`] and [`open_tx`].
struct OpeningGuard<'a> {
    reclaim: &'a EngineReclaim,
}

impl Drop for OpeningGuard<'_> {
    fn drop(&mut self) {
        // `fetch_sub`, and it cannot underflow: every decrement is paired with the increment that
        // created this guard, and the guard is the only way to make one.
        self.reclaim.opens_in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

struct EngineReclaim {
    /// The engine's one ticket sequence, shared with every worker's [`TicketMinter`].
    tickets: Arc<TicketSequencer>,
    /// Off-thread reads currently in flight across the WHOLE engine (`rmp` #336) — the reuse
    /// barrier's gate at `W = 1`, the adaptive morsel width's divisor, and the tick condition.
    readers_inflight: AtomicU64,
    /// **The single-flight gate over every reuse-barrier-armed section**: the background maintenance
    /// cadence, `CHECKPOINT DATABASE`, and a Mode A bulk-import batch. One at a time per engine,
    /// because the barrier they arm is one shared atomic and each disarms it on the way out.
    ///
    /// A plain `Mutex<()>`: it guards no data, only the right to be the engine's reclaiming worker,
    /// and it is deliberately held across the pass's own I/O and durability barriers — which is why it
    /// is NOT one of the ranked latches (nothing in `graphus_core::latch` may span a barrier). It is
    /// the outermost lock a worker takes: [`enter_pass`](Self::enter_pass) asserts that no rank-5
    /// engine session latch is held, so the order *session latch → reclaim gate* can never form and
    /// the gate cannot take part in a cycle.
    pass: std::sync::Mutex<()>,
    /// The WAL `durable_len` at the last maintenance checkpoint — ONE cadence for the engine. Read and
    /// written only under [`pass`](Self#structfield.pass), which is what makes the read-decide-write
    /// of the cadence atomic and stops `W` workers from each firing the same pass.
    wal_at_last_maintenance: AtomicU64,
    /// The engine-wide ticket high-water at the END of the last reclaim pass. Nothing shadow-held is
    /// released until the oldest open transaction has passed it. `0` (transparent) at `W = 1`.
    release_floor: AtomicU64,
    /// How many transactions are between "about to be minted" and "visible in the open table"
    /// (`rmp` #1037). Non-zero means the open table is NOT a complete census, so
    /// [`release_threshold`](Self::release_threshold) refuses to release anything — see [`open_tx`],
    /// which explains why the window exists at all and why it is invisible at one worker.
    opens_in_flight: AtomicUsize,
    /// How many workers this engine runs. Decides whether the barrier is armed unconditionally and
    /// whether the release floor is raised at all.
    workers: u64,
}

impl EngineReclaim {
    /// `wal_at_open` is the store's WAL `durable_len` at the moment the engine opened, so a freshly
    /// opened engine does not immediately fire a (no-op) maintenance pass.
    fn new(workers: usize, wal_at_open: u64) -> Self {
        Self {
            tickets: Arc::new(TicketSequencer::new(workers)),
            readers_inflight: AtomicU64::new(0),
            pass: std::sync::Mutex::new(()),
            wal_at_last_maintenance: AtomicU64::new(wal_at_open),
            release_floor: AtomicU64::new(0),
            opens_in_flight: AtomicUsize::new(0),
            workers: workers.max(1) as u64,
        }
    }

    /// This engine's ticket sequence, for a worker building its [`TicketMinter`].
    fn tickets(&self) -> Arc<TicketSequencer> {
        Arc::clone(&self.tickets)
    }

    /// Marks this thread as OPENING a transaction until the returned guard drops.
    ///
    /// RAII rather than a bare pair of calls because the middle of the window is
    /// `TxnCoordinator::begin_at`, which can panic (the recovery boundary above it is what makes that
    /// survivable) — and a leaked count here does not fail loudly, it silently stops the engine ever
    /// releasing a shadow-held slot again. Unwinding restores it.
    fn opening(&self) -> OpeningGuard<'_> {
        self.opens_in_flight.fetch_add(1, Ordering::AcqRel);
        OpeningGuard { reclaim: self }
    }

    /// Becomes the engine's reclaiming worker, blocking until the current pass (if any) ends.
    ///
    /// Poison is recovered rather than propagated: the gate guards `()`, so there is no state a panic
    /// could have left inconsistent, and refusing every later pass would turn one panic into a
    /// permanent reclamation stall — a slow-motion OOM behind a green readiness probe, which is the
    /// failure `rmp` #394 exists to make loud rather than to cause.
    fn enter_pass(&self) -> ReclaimPassGuard<'_> {
        graphus_core::latch::assert_no_engine_latch_held("engine reclaim pass");
        assert_not_already_reclaiming();
        // The depth is armed AFTER the lock is in hand, not before: a thread that is about to block
        // here is not yet a holder, and arming first would report the re-entry against itself.
        ReclaimPassGuard::new(
            self.pass
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Becomes the engine's reclaiming worker, or declines because another worker already is.
    ///
    /// The background cadence uses this: a pass another worker is already running does the same work,
    /// so waiting for it would only park a worker that could be serving commands.
    fn try_enter_pass(&self) -> Option<ReclaimPassGuard<'_>> {
        graphus_core::latch::assert_no_engine_latch_held("engine reclaim pass (try)");
        assert_not_already_reclaiming();
        match self.pass.try_lock() {
            Ok(guard) => Some(ReclaimPassGuard::new(guard)),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                Some(ReclaimPassGuard::new(poisoned.into_inner()))
            }
            // A `None` here means ANOTHER worker is reclaiming. It cannot mean "this thread already
            // is", because the tripwire above refuses that outright in a debug build — which is the
            // whole reason it exists: a self-inflicted `None` is indistinguishable from a legitimate
            // decline and would skip the maintenance cadence for the life of the process.
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }

    /// The reuse barrier for a pass starting now — see [`gc_reuse_barrier`].
    fn reuse_barrier(&self) -> Option<u64> {
        gc_reuse_barrier(
            self.tickets.high_water(),
            self.readers_inflight.load(Ordering::Relaxed),
            self.workers,
        )
    }

    /// Records that a reclaim pass has just finished freeing, so nothing it shadow-held is released
    /// until every transaction that could have been walking during it has retired.
    ///
    /// Monotone (`fetch_max`): two passes can only raise the bar, never lower it, so a slot held by an
    /// older pass is covered by the newer pass's floor as well — conservative in the one direction
    /// that is safe.
    fn note_pass_finished(&self) {
        if self.workers > 1 {
            self.release_floor
                .fetch_max(self.tickets.high_water(), Ordering::AcqRel);
        }
    }

    /// The threshold to hand [`RecordStore::release_held`](graphus_storage::RecordStore::release_held).
    ///
    /// `oldest_open_ticket` when the engine is provably past the last pass's floor, and `0` otherwise.
    /// `0` releases nothing at all — every barrier is `high_water + 1 >= 1` — so this expresses "hold
    /// everything" without a second code path, and without the storage layer needing to know that a
    /// multi-worker engine exists.
    fn release_threshold(&self, oldest_open_ticket: u64) -> u64 {
        // The census must be COMPLETE before its minimum means anything (`rmp` #1037). A transaction
        // that has begun opening is in no table yet, so a minimum taken now can miss it — and when it
        // is the only transaction that minimum is `u64::MAX`, which releases every shadow-held slot.
        // Read BEFORE the floor: if this is zero now, every snapshot that exists is already in the
        // table (the count is raised before the ticket is minted, and the ticket before the snapshot),
        // and a transaction that starts after this read takes its snapshot after the pass that armed
        // the hold had finished freeing. At one worker this is always zero here — opening and
        // releasing are the same thread — so the whole check is transparent.
        if self.opens_in_flight.load(Ordering::Acquire) != 0 {
            return 0;
        }
        if oldest_open_ticket > self.release_floor.load(Ordering::Acquire) {
            oldest_open_ticket
        } else {
            0
        }
    }

    /// Whether the release must be DEFERRED until after the pass that is about to run.
    ///
    /// At one worker it must not be: the pass's own release runs with `oldest_open_ticket` sampled
    /// before it started, and on one thread nothing can open a transaction in between, so that sample
    /// describes the whole pass. Keeping that path is what makes `W = 1` byte-identical.
    ///
    /// Above one worker that sample is a statement about one instant, not about the pass. In
    /// particular a pre-pass reading of "no transaction is open" (`u64::MAX`, the threshold that
    /// releases EVERYTHING) can be true at the arm and false a microsecond later, while the pass is
    /// still freeing — so the pass's own release would hand back the very slots it had just held, to a
    /// sibling's transaction that opened while it ran. The release therefore moves after
    /// [`note_pass_finished`](Self::note_pass_finished), where the floor already covers that
    /// transaction. See [`release_after_pass`].
    fn defers_release(&self) -> bool {
        self.workers > 1
    }

    /// The threshold for the release the PASS ITSELF performs, from a value sampled before it ran.
    fn in_pass_release_threshold(&self, oldest_open_ticket: u64) -> u64 {
        if self.defers_release() {
            0
        } else {
            oldest_open_ticket
        }
    }
}

/// Lifts the reuse hold on every slot the engine is provably past, after a reclaim pass has ended
/// (`rmp` #1037).
///
/// A no-op at one worker, where the pass's own release already did this with a threshold that was
/// correct for the whole of the pass — see [`EngineReclaim::defers_release`] for why that stops being
/// true above one worker, and why doing it here instead is what makes the difference.
///
/// The caller must still be inside the reclaim section: the floor has to be raised, and this release
/// has to happen, before another worker's pass can start stamping slots that this threshold was not
/// computed for.
fn release_after_pass<D: BlockDevice, S: LogSink>(
    coord: &TxnCoordinator<D, S>,
    open: &EngineLatch<OpenTxTable>,
    reclaim: &EngineReclaim,
) {
    if !reclaim.defers_release() {
        return;
    }
    // Read under the latch, release it, then act: `release_reusable_slots` walks the store's held
    // overlay, which is store work and has no business running at rank 5.
    let oldest_open_ticket = { open.lock().keys().copied().min().unwrap_or(u64::MAX) };
    coord.release_reusable_slots(reclaim.release_threshold(oldest_open_ticket));
}

/// The engine's open-transaction table, plus the [`ReapedTickets`] ledger that travels with it.
///
/// The ledger is bundled here rather than threaded as a separate argument because it is needed at
/// exactly the three places the table already reaches — the age sweep that writes it, and the `RUN`
/// and `COMMIT` unknown-ticket paths that read it — and every one of those already receives `open`.
/// [`Deref`]/[`DerefMut`] to the underlying map keep every existing `open.get` / `open.insert` /
/// `open.remove` / `open.iter` call site working unchanged; only the sites that care about *reaping*
/// use the two inherent methods, so an ordinary `remove` (a normal commit or rollback) can never
/// accidentally record a reap.
#[derive(Default)]
struct OpenTxTable {
    live: HashMap<u64, OpenTx>,
    reaped: ReapedTickets,
}

impl OpenTxTable {
    fn new() -> Self {
        Self::default()
    }

    /// Records that the age sweep rolled `ticket` back (see [`maybe_reap_aged`]).
    fn record_reaped(&mut self, ticket: u64) {
        self.reaped.record(ticket);
    }

    /// The error for a request naming `ticket`, which the table does not hold.
    ///
    /// Distinguishes the two permanent causes: a transaction the age sweep stopped
    /// (`Neo.ClientError.Transaction.TransactionTimedOut` — it existed, and here is why it is gone)
    /// from one that genuinely never existed or is already spent
    /// (`Neo.ClientError.Transaction.TransactionNotFound`). Both are non-retryable `ClientError`s, so
    /// the driver's behaviour is identical either way and only the diagnosis differs.
    fn unknown_ticket_error(&mut self, ticket: u64, what: &str) -> GraphusError {
        if self.reaped.take(ticket) {
            graphus_core::status::transaction_timed_out(&format!("{what} {ticket}"))
        } else {
            graphus_core::status::transaction_not_found(&format!("{what} {ticket}"))
        }
    }
}

impl std::ops::Deref for OpenTxTable {
    type Target = HashMap<u64, OpenTx>;
    fn deref(&self) -> &Self::Target {
        &self.live
    }
}

impl std::ops::DerefMut for OpenTxTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.live
    }
}

/// A write commit that has been group-commit **PREPAREd** (SSI-validated + `COMMIT` record appended,
/// `fdatasync` deferred) and is awaiting the batch harden before its client is acknowledged (`rmp`
/// #528/#532/#566, `04 §4.2`).
///
/// The committer is acknowledged only after [`flush_commit_batch`] / [`pipelined_group_commit`] has
/// hardened an `fdatasync` that made `commit_lsn` durable — the ACID-inviolable **ack-after-fsync**
/// rule: a committer is told its commit succeeded only once an `fdatasync` covering its commit record
/// has completed. If the batch harden PANICS (fsyncgate, `04 §4.9`) the whole batch fails together and
/// NONE of its members is acked, so no committer is ever acked for an un-hardened commit.
///
/// Two shapes of committer share the one batch (`rmp` #566): an **explicit** `BEGIN…COMMIT` blocked on
/// a one-shot reply, and an **auto-commit** single write statement whose acknowledgement is the close
/// of its still-open result-egress channel. Both are hardened by the SAME `fdatasync`, so concurrent
/// auto-commit writers coalesce exactly as explicit committers already did — the T1 fix that stops
/// auto-commit writes bypassing the group-commit machinery (they previously did an inline `fdatasync`
/// per statement on the engine thread).
enum PendingCommit {
    /// An explicit `BEGIN…COMMIT` committer blocked on a one-shot reply (`rmp` #528).
    Explicit {
        /// The one-shot reply the committer's connection is blocked on.
        reply: command::Reply<Result<RunSummary>>,
        /// The LSN of this transaction's `COMMIT` record; the batch harden must advance the durable
        /// watermark past it before this reply is sent (asserted in [`ack_prepared_commits`]).
        commit_lsn: graphus_core::Lsn,
        /// This write transaction's causal **bookmark** (`rmp` #807): `"<db>:<commit_ts>"`, minted at
        /// prepare time and returned in the `COMMIT` `SUCCESS` metadata once the commit is durable
        /// (`ack`), so a driver can chain it. Always `Some` for this durable-write variant.
        bookmark: Option<String>,
    },
    /// An **auto-commit** single write statement (`rmp` #566): its client is acknowledged by the
    /// **close of the result-egress channel**, not a one-shot reply. `row_tx` is a *clone* of the
    /// statement's egress sender, held open across the batch so the channel stays open until the
    /// harden makes `commit_lsn` durable; the statement's own sender drops when its `handle_run`
    /// returns, so this clone is the LAST sender — dropping it at ack time closes the channel, which is
    /// the consumer's end-of-stream (the ack-after-fsync signal for auto-commit). The result summary
    /// was already published into the shared `SummarySink` before the statement returned, and the
    /// consumer reads it only after observing the close, so the summary ordering still holds.
    Autocommit {
        /// The held-open clone of the statement's egress sender (see the variant docs). Dropped by
        /// [`ack_prepared_commits`] after the harden — the client's ack-after-fsync end-of-stream.
        row_tx: stream::RowSender,
        /// The LSN of this transaction's `COMMIT` record; the batch harden must advance the durable
        /// watermark past it before the egress channel is closed (asserted in [`ack_prepared_commits`]).
        commit_lsn: graphus_core::Lsn,
    },
}

impl PendingCommit {
    /// The LSN of this committer's `COMMIT` record — the watermark the batch harden must make durable
    /// before this committer is acked (the ack-after-fsync assertion in [`ack_prepared_commits`]).
    fn commit_lsn(&self) -> graphus_core::Lsn {
        match self {
            PendingCommit::Explicit { commit_lsn, .. }
            | PendingCommit::Autocommit { commit_lsn, .. } => *commit_lsn,
        }
    }

    /// Acknowledges this committer AFTER its `COMMIT` record is `fdatasync`-durable (the ack-after-fsync
    /// rule). Explicit: send the one-shot `Ok` the connection is blocked on. Auto-commit: drop the
    /// held-open egress sender, closing the channel — the consumer's end-of-stream.
    fn ack(self) {
        match self {
            PendingCommit::Explicit {
                reply, bookmark, ..
            } => {
                // The durable-write `COMMIT` `SUCCESS` carries this transaction's causal bookmark
                // (`rmp` #807); it is sent only here, AFTER the batch `fdatasync` made the commit
                // durable — so the bookmark a driver receives always names an already-durable commit.
                let _ = reply.send(Ok(RunSummary {
                    bookmark,
                    ..RunSummary::default()
                }));
            }
            // Dropping the last egress sender closes the channel — the auto-commit statement's
            // ack-after-fsync end-of-stream (the summary was already published into the shared sink).
            PendingCommit::Autocommit { row_tx, .. } => drop(row_tx),
        }
    }
}

/// Runs the engine event loop until a [`EngineCommand::Shutdown`] (or the command channel closes).
///
/// Owns `coordinator` and the result-egress bound (`result_buffer_capacity`). Each command is
/// handled serially; `Run` executes the full compile→bind→execute pipeline (see [`exec`]) and
/// streams rows back over a bounded channel sized by `result_buffer_capacity`.
///
/// This function **blocks** the calling thread for the engine's lifetime; spawn it on a dedicated
/// OS thread (see [`spawn_engine`]).
#[allow(clippy::too_many_arguments)] // The engine loop threads its whole execution context here.
fn run_engine_loop<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    db_name: Arc<str>,
    coordinator: Arc<TxnCoordinator<D, S>>,
    // THIS worker's command queue (`rmp` #1035): one queue per worker, with a session always routed
    // to the same one, because a shared queue does not preserve the order of one session's commands.
    // `std::sync::mpsc::Receiver` is `!Sync`, so it is still reached under a lock — uncontended, as
    // no other worker reads it — and the lock covers only the dequeue, never the work that follows.
    //
    // Deliberately a plain `Mutex` and NOT an [`EngineLatch`] (`rmp` #1038). Rank 5 is the engine's
    // *session state*, and its rules do not fit this: the receive legitimately BLOCKS for up to a tick
    // with the lock held, which is the opposite of a rank whose whole point is short critical sections.
    // What matters at the receive is the complementary property — that no session latch is held while
    // this thread waits for a command that may never arrive — and that is asserted directly at both
    // receive sites rather than inferred from a rank the lock does not belong to.
    rx: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<EngineCommand>>>,
    // The stop protocol, shared by every worker of this engine (`rmp` #1036). Built once by the
    // spawner: a worker cannot count how many *others* are still running, and a stop only one worker
    // can see is not a stop.
    stop: Arc<EngineStop>,
    // The session state, shared by every worker of this engine (`rmp` #1041). Built once by the
    // spawner for the same reason the stop protocol is: the `Shutdown` drain, the plan cache and the
    // age sweep are all statements about the ENGINE, and a per-worker copy of any of them answers a
    // different question — see [`EngineSessions`] for what each of those answered wrongly.
    sessions: Arc<EngineSessions>,
    // The reclamation state, shared by every worker of this engine (`rmp` #1037). Built once by the
    // spawner, for the third instance of the same reason: the reuse barrier, the ticket order it takes
    // its floor from, and the maintenance cadence are all statements about the ENGINE and its ONE
    // store. See [`EngineReclaim`] for what each per-worker copy got wrong — the first of them
    // silently, by handing a live reader's slot back to a writer.
    reclaim: Arc<EngineReclaim>,
    // Which worker this is. Worker 0's idle timeout additionally drives index builds and the
    // degraded-index/vector/full-text repairs; every worker's timeout is bounded either way, so every
    // worker drains its own reader retirements and resumes its own parked statements regardless. The
    // maintenance cadence is NOT tied to worker 0 — see [`maybe_run_maintenance`], which every worker
    // calls and exactly one at a time runs.
    worker_id: usize,
    // How many workers this engine runs. Seeds the ticket minter's stride, so every ticket this
    // worker mints satisfies `ticket % W == worker_id` (`rmp` #1035), and is the modulus the two
    // cross-worker passes over the shared tables use to tell their own transactions from the rest.
    engine_workers: usize,
    result_buffer_capacity: usize,
    // The ENGINE's reader pool and the ENGINE's retirement channel (`rmp` #1039), both built once by
    // [`spawn_engine_with_timeout`] and shared by every worker.
    //
    // They used to be built HERE, so a `W`-worker engine ran `W` pools: `W * min(cores, 16)` reader
    // threads on a machine with `cores` cores, each sized as if it were the only one, plus `W`
    // retirement channels. The measurement `rmp` #1034 exists to take would have been of contention
    // rather than of scale.
    //
    // The receiver is behind a `Mutex` because `std::sync::mpsc::Receiver` is `!Sync` — the same shape
    // this worker's own command queue already has. Whichever worker reaches it drains it; see
    // [`process_retirements`] for why any worker may finalise any reader, and [`finish_reader`] for the
    // reformulated M1 ordering proof that replaces "it is all one thread".
    dispatch: Arc<read_pool::ReadDispatch<D, S>>,
    retire_rx: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<read_pool::ReadRetirement>>>,
    metrics: Arc<Metrics>,
    degraded: EngineDegraded,
    maintenance_degraded: MaintenanceDegraded,
    clock: Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    statement_timeout: Option<std::time::Duration>,
    max_transaction_age: Option<std::time::Duration>,
    // The bound on **concurrently parked (suspended) inline statements** (`rmp` #485, finding B1).
    // Several slow-consumer inline statements can be parked at once (writes + explicit-txn reads run
    // inline and any can fill its bounded egress on its first visit), so a single slot is unsound: a
    // second suspension would clobber the first (silent result truncation + leaked txn in release; a
    // `debug_assert` engine-thread panic in debug). The true upstream bound is the admission limit
    // (`AdmissionConfig::max_concurrent_queries`): a parked statement holds its admission permit for its
    // whole stream lifetime, so at most `max_concurrent_queries` can be parked at once. The engine is
    // sized with `engine_queue_capacity` (≥ `max_concurrent_queries` in any sane config), so this cap is
    // a never-reached defense-in-depth ceiling against an admission bypass — not a routine limit.
    max_parked_inline: usize,
    // This engine's gauge folds, shared by every worker (`rmp` #1041) — see the binding below.
    active_txns: Arc<ActiveTxnGauge>,
    index_builds: Arc<IndexBuildGauge>,
    // The server-wide live-transaction registry (`rmp` #637/#903), shared with both connectivity seams.
    // The engine registers its **own** validating `CREATE CONSTRAINT` transactions here so they appear
    // in `SHOW TRANSACTIONS` while they run and can be stopped by `TERMINATE TRANSACTIONS`. It is
    // deliberately NOT an `Option`: an engine without a registry would silently lose that visibility,
    // which is precisely the failure mode this wiring exists to remove, so the type system requires one.
    transactions: Arc<crate::txn_registry::TransactionRegistry>,
) {
    // This ENGINE's contribution to the two gauge families, shared by every worker (`rmp` #1041).
    // Both publish figures the coordinator computes for the whole engine — `active_count`,
    // `ssi_tracked_len`, `index_build_totals` — so one fold per engine is the correct number of folds.
    // Constructed per worker, each one folded the same engine-wide value into the same additive gauge,
    // and the server-wide series read up to W times the truth until the counts came back to rest.
    // Retracted when the LAST worker drops its share, which is what keeps a stopped engine from
    // leaving a phantom count behind (`rmp` #418/#463/#573).
    let active_txns = &*active_txns;
    let index_builds = &*index_builds;
    // ALL that is left of the loop's state with no engine-wide meaning, once [`EngineStop`]
    // (`rmp` #1036), [`EngineSessions`] (`rmp` #1041) and [`EngineReclaim`] (`rmp` #1037) have taken
    // the rest: this worker's window onto the engine's ticket sequence. The residue class it issues in
    // IS this worker's identity (`rmp` #1035), which is the whole reason it is not shared — while the
    // ORDER the tickets come in belongs to the engine, which is why the counter behind it is.
    let minter = TicketMinter::new(
        WorkerAffinity::new(worker_id, engine_workers),
        reclaim.tickets(),
    );
    // Which tickets this worker owns. Read once: the modulus never changes for the life of a worker,
    // and the two passes that walk the shared tables (the age sweep and the parked-statement resume)
    // both need it on every tick.
    let affinity = minter.affinity();
    // The engine's ONE plan cache, named locally because the loop reaches it from a dozen places.
    //
    // Shared rather than per worker, decided by measurement (`rmp` #1041) against the alternative of a
    // cache per worker with the schema version in a shared atomic. Both are correct; the shared one is
    // faster where it was expected to be slower and simpler where it matters. On the workload most
    // dominated by the cache — `RETURN 1 AS x`, W = 8, both shapes alternated inside one process so
    // host drift hits them equally — the shared latch cost 174 780 against 175 349 statements per
    // second, a 0.33 % difference inside a 1.3 % run-to-run spread. On a COLD workload of 400 distinct
    // texts the per-worker shape cost 6.2 % more engine CPU and 5.8 % more wall time, because a text
    // compiled on one worker is a miss on every other and the engine compiles it up to W times instead
    // of once. It would also hold W x 512 plans instead of 512, and it needs a second coherence
    // protocol — a shared version plus a sync-on-use step — whose failure mode is a stale plan served
    // silently, which is the defect this task exists to remove, and which fails OPEN.
    let plan_cache = &sessions.plan_cache;

    // The engine's compiled-plan cache (`rmp` task #322): reuses a compiled `PhysicalPlan` for an
    // identical query text instead of re-running the ~7–9 µs compile pipeline on every `Run`. Shared by
    // every worker of this engine since `rmp` #1041, behind its own rank-5 latch, so a DDL on one
    // worker invalidates the plans every other worker is serving. Invalidated by a schema-version bump
    // on any planner-visible catalog change (DDL, the `rmp` #733 fail-closed index repair, or an online
    // index build promoting `Populating`→`Online`).

    // Whether an index build was pending at the end of the previous tick. A `true`→`false` transition
    // means a build just completed (an index promoted `Populating`→`Online`), which changes the
    // planner-visible catalog (`TxnCoordinator::catalog` now exposes the new index) and so must
    // invalidate the plan cache. Seeded from the current state so a freshly-opened engine with a
    // recovered pending build is handled on the tick its build finishes.
    let mut builds_were_pending = coordinator.has_pending_index_builds();
    // How many index fail-closed events (`rmp` task #733) this engine has already logged + metered, so
    // each new one is reported exactly once. Seeded from the coordinator so a freshly-opened engine whose
    // open-time rebuild already failed closed reports it on its first tick.
    let mut index_health_seen = IndexHealthSeen::seed(&coordinator);
    // The extension registry (user-defined functions/procedures, `rmp` task #75). Built **once** on
    // the engine thread, then `Arc`-shared so an off-thread reader resolves UDF/UDP plans against the
    // SAME registry that backed compilation (`rmp` task #336 — `ExtensionRegistry` is `Send + Sync`,
    // so this is sound). The engine borrows it immutably for each `Run`; commands are serial.
    let extensions = Arc::new(exec::install_extensions());
    // How many readers are dispatched-but-not-yet-retired. While `> 0` the loop polls the retirement
    // channel each tick so a retirement (which finalises the reader's auto-commit + closes its egress)
    // is processed promptly even if no client command arrives. Incremented at dispatch, decremented as
    // each retirement is processed.
    // The suspended inline statements (`rmp` task #372; bounded-queue generalization `rmp` #485 B1). An
    // inline `Run` whose bounded egress channel fills with a slow consumer draining is parked here
    // instead of blocking this thread on `row_tx.send`; the loop resumes each one batch per tick
    // (round-robin, gated into `timed` below) until its cursor exhausts. **Multiple** can be parked at
    // once — writes and explicit-transaction reads run inline and any can suspend, and the engine keeps
    // dispatching new commands while statements are parked (the #372 no-head-of-line-block property) —
    // so this is a FIFO `VecDeque`, bounded by `max_parked_inline`. The historical single-`Option` slot
    // silently clobbered the first parked statement when a second suspended (`rmp` #485 finding B1).

    // Held in an `Option` so the terminal `Shutdown` can move the coordinator out to consume it for
    // the final flush (`TxnCoordinator::into_store` is by-value). It is always `Some` while the loop
    // is processing commands.
    // `Arc` since `rmp` #1033: the coordinator is `Send + Sync` and every method takes `&self`, so
    // several engine workers can hold it at once. The `Option` remains because `Shutdown` must take
    // SOLE ownership back — `into_store` is by-value — which is what `Arc::try_unwrap` below asserts.
    // The share this worker holds. The `Option` remains because `Shutdown` takes it back to consume
    // it — and by then this worker is the last one, so the `Arc::try_unwrap` below succeeds.
    let mut coordinator: Option<Arc<TxnCoordinator<D, S>>> = Some(coordinator);
    // The WAL `durable_len` captured at the last background maintenance checkpoint (`rmp` #305). The
    // cadence fires when growth past it crosses `MAINTENANCE_CHECKPOINT_INTERVAL_BYTES`, reclaiming
    // RAM/disk/version slots without an operator trigger.
    //
    // It lives in [`EngineReclaim`] since `rmp` #1037 and is seeded ONCE, in
    // [`spawn_engine_with_timeout`], from the store this engine just opened. It used to be a local
    // seeded here — so every worker seeded its own copy and the engine ran W independent cadences.
    // Read here only to baseline the metric below, which every worker may do because the baseline is a
    // `store` of the same absolute offset, not a fold.
    let wal_at_last_maintenance: u64 = reclaim.wal_at_last_maintenance.load(Ordering::Relaxed);
    // Seed this database's WAL-volume fold baseline (`rmp` #745) from the SAME already-computed offset,
    // BEFORE the loop accepts a single command. `graphus_wal_bytes_written_total` counts bytes *this
    // process wrote*, so the WAL history this database already had on disk (which can be gigabytes) must
    // be baselined out rather than folded in as if this engine had just written it — and baselining it
    // here, ahead of any request, is also what makes the very first scrape correct: a client that scrapes
    // before the first commit sees `0`, not a phantom jump. Re-seeding per incarnation (rather than
    // trusting a monotone-max of the raw offset) is also what keeps the counter honest across a
    // `STOP`/`START DATABASE` and across a `DROP` + re-`CREATE` of the same name, whose new log restarts
    // near offset 0. See `Metrics::rebaseline_wal_bytes_for`.
    metrics.rebaseline_wal_bytes_for(&db_name, wal_at_last_maintenance);
    // Consecutive background-maintenance-checkpoint failures (`rmp` #394). Persists across maintenance
    // ticks; once it reaches `MAINTENANCE_FAILURE_ESCALATION_THRESHOLD` the reclamation-degraded gauge
    // is set (driving `/health/ready` to 503). Reset to 0 by any successful checkpoint.
    let mut maintenance_consecutive_failures: u32 = 0;
    // Network bulk-import Mode A session state (`rmp` #519, `08 §5.1/§7.1`): `None` until the first
    // `BulkImportBatch` dispatch, `Some` for the session's lifetime, reset to `None` by
    // `BulkImportBatchInput::End`. Lives here (not inside `dispatch_command`) because it must persist
    // across many command dispatches within one session — see `crate::engine::bulk_load`'s module docs.
    let mut loading_session: Option<bulk_load::LoadingSession> = None;
    // A command a group-commit batch drain pulled off the channel but did NOT batch (the first
    // non-`Commit` command, which ends the drain — `rmp` #528). It is processed on the NEXT loop
    // iteration, IN ORDER, after the batch it followed has been hardened + acked — never reordered ahead
    // of the batch, and never dropped.
    let mut pending_cmd: Option<EngineCommand> = None;
    // The dedicated WAL fsync thread (`rmp` #532): the pipelined group-commit harden offloads each
    // batch's `fdatasync` here so it overlaps the CPU work of PREPAREing the next batch. Depth-1 (a
    // capacity-1 job channel), so at most one batch is ever written-but-un-synced — the on-disk crash
    // state stays the same category as inline group commit. Joined when this loop returns (its `Drop`).
    let wal_sync = WalSyncThread::spawn(&db_name);

    'engine: loop {
        // Drain any reader retirements that have arrived (M1' merge → auto-commit). The channel is the
        // ENGINE's since `rmp` #1039, so this drains whatever is there, not only what this worker
        // dispatched. Done first each iteration so a retirement is never starved behind a blocking
        // command `recv`. Returns false only on `Shutdown`, which cannot arrive here (retirements are
        // not commands), so the result is ignored.
        process_retirements(
            &retire_rx,
            &coordinator,
            &sessions.open,
            &reclaim,
            &metrics,
            &db_name,
            &degraded,
            active_txns,
        );

        // Maximum-transaction-age sweep (`rmp` #477): reap any **explicit** transaction whose lifetime
        // has exceeded the configured cap, measured on the **monotonic** clock (`rmp` #395, so an NTP
        // step cannot mis-fire). Runs each engine tick — every command and every timed wake — which is
        // exactly when the denial of service it guards against can manifest: a long-running reader pins
        // the MVCC GC low-water mark, but dead versions only *accumulate* (so the pin only *costs*) under
        // other transactions' write traffic, and that traffic is what wakes this loop. Disabled (`None`)
        // ⇒ a cheap no-op. Excludes auto-commit statements (transient, bounded by the per-statement
        // timeout, possibly mid-flight on an off-thread reader), every parked statement, and — since the
        // table became engine-wide (`rmp` #1041) — every transaction another worker owns, so a reap
        // never races a live read or a live statement.
        maybe_reap_aged(
            &coordinator,
            &sessions.open,
            &sessions.parked,
            affinity,
            max_transaction_age,
            &clock,
            &metrics,
            &db_name,
            active_txns,
        );

        // Resume ONE batch of EACH suspended inline statement THIS worker owns (`rmp` task #372;
        // round-robin over the bounded queue per `rmp` #485 B1). Done each tick — before the (timed)
        // command receive — so every draining consumer makes progress promptly even when no client
        // command arrives, and a concurrent write/command on the SAME database is still serviced on the
        // very next tick (the head-of-line block stays gone for N parked statements, not just one).
        // Each resume runs behind a panic-isolation boundary (`rmp` #485 B2): a panic on a resumed batch
        // rolls that statement back and keeps the engine alive instead of unwinding the engine thread.
        resume_parked_statements(
            &sessions.parked,
            &coordinator,
            &sessions.open,
            affinity,
            &extensions,
            &metrics,
            &db_name,
            &degraded,
            &clock,
            active_txns,
        );

        // Prefer a command a group-commit batch drain stashed (a non-`Commit` command that ended the
        // batch, `rmp` #528): process it NOW — in channel order, after its preceding batch was hardened
        // + acked — without a fresh receive.
        if let Some(cmd) = pending_cmd.take() {
            let Some(cmd) = intercept_simulate_maintenance(
                cmd,
                &mut maintenance_consecutive_failures,
                &metrics,
                &maintenance_degraded,
            ) else {
                continue 'engine;
            };
            if !process_command(ProcessCtx {
                cmd,
                rx: &rx,
                coordinator: &mut coordinator,
                open: &sessions.open,
                next_ticket: &minter,
                plan_cache,
                extensions: &extensions,
                dispatch: &dispatch,
                reclaim: &reclaim,
                parked: &sessions.parked,
                max_parked_inline,
                result_buffer_capacity,
                metrics: &metrics,
                db: &db_name,
                degraded: &degraded,
                maintenance_degraded: &maintenance_degraded,
                active_txns,
                clock: &clock,
                statement_timeout,
                loading_session: &mut loading_session,
                maintenance_consecutive_failures: &mut maintenance_consecutive_failures,
                builds_were_pending: &mut builds_were_pending,
                pending_cmd: &mut pending_cmd,
                wal_sync: &wal_sync,
                retire_rx: &retire_rx,
                transactions: &transactions,
            }) {
                break 'engine;
            }
            continue 'engine;
        }

        // A timed receive is needed when EITHER a non-blocking index build is in progress (`rmp` #91)
        // OR readers are in flight (so their retirements are polled) OR a suspended inline statement is
        // parked (so it is resumed each tick even with no command). Otherwise block plainly (no idle
        // wakeups — a fully idle engine with nothing pending parks on `recv` exactly as before).
        let building = coordinator
            .as_ref()
            .expect("INVARIANT: coordinator is Some until Shutdown breaks the loop")
            .has_pending_index_builds();
        // A degraded index set (`rmp` task #733) is also pending work: a storage fault wiped the derived
        // indexes fail-closed, and the engine must tick so it can log/meter the event and RETRY the
        // rebuild — a transient fault would otherwise leave the process scan-only until it is restarted.
        // (It is deliberately NOT folded into `has_pending_index_builds`, whose callers spin on it and
        // would hang forever on a permanently-faulting store; the retry itself is backed off inside the
        // coordinator.)
        let indexes_degraded = coordinator
            .as_ref()
            .expect("INVARIANT: coordinator is Some until Shutdown breaks the loop")
            .indexes_degraded();
        // A VECTOR index blocked by a `rmp` #780 build conflict is pending work too, for the same
        // reason a degraded index set is: while blocked, its every k-NN runs an exact O(entities x dim)
        // scan, and the repair (`retry_conflicted_vector_builds`, inside `advance_index_builds`) only
        // runs when the engine ticks. Without this, an engine that went idle right after the conflict
        // would park on a plain `recv` and stay on the slow path until the next command arrived — and
        // the degradation would never be logged.
        //
        // Like `indexes_degraded`, this is deliberately NOT folded into `has_pending_index_builds`,
        // whose callers SPIN on it: no amount of pumping can resolve another transaction, so a blocking
        // writer that stayed open would turn that loop into a 100%-CPU hang. Making the engine *tick*
        // is bounded (one `is_txn_active` lookup per recorded writer, then an early return); making it
        // *spin* is not.
        let vector_blocked = coordinator
            .as_ref()
            .expect("INVARIANT: coordinator is Some until Shutdown breaks the loop")
            .blocked_vector_indexes()
            > 0;
        // A poisoned full-text/spatial marker (`rmp` task #803) is pending work for the same reason:
        // every TEXT / FULLTEXT / SPATIAL seek is on the exact scan until a rebuild clears it, and that
        // rebuild only runs when the engine ticks. Without this, an engine that went idle right after
        // the poison would park on a plain `recv` and stay degraded until the next command — which is
        // exactly how this defect reached example scale.
        let ft_spatial_poisoned = coordinator
            .as_ref()
            .expect("INVARIANT: coordinator is Some until Shutdown breaks the loop")
            .ft_spatial_poisoned();
        // Publish the index-build gauges (`rmp` task #573). Here, because this point is reached on EVERY
        // iteration — after each command (so a `CREATE INDEX`'s new build shows up at once) and after each
        // build tick (so progress falls and completion returns the gauges to zero) — and because it is the
        // last thing evaluated before the loop may block on `recv`, so the published values are the ones
        // that stay true while the engine is idle. `index_build_totals` allocates nothing and reads no
        // store: with no build running it is three `len()`s on empty collections, so it adds no per-tick
        // cost to the build loop.
        index_builds.publish(
            coordinator
                .as_ref()
                .expect("INVARIANT: coordinator is Some until Shutdown breaks the loop")
                .index_build_totals(),
        );
        // Whether this worker's timeout does MAINTENANCE WORK, and nothing else (`rmp` #1033).
        //
        // Be exact about what this flag does not decide, because the comment here used to say the
        // opposite and it is the kind of claim that gets built on. It said only worker 0 "takes the
        // timed tick" while "every other worker blocks on `recv` and serves commands only", and that
        // every worker's tick would "run W passes over the same store". Neither is what the code below
        // does. BOTH branches of the receive are `recv_timeout(INDEX_BUILD_TICK)` — `rmp` #1033 made
        // the other one bounded too, because a worker parked in a plain `recv` never observes
        // `stopping` and hangs the shutdown. So every worker wakes every tick either way, and every
        // worker therefore drains its own reader retirements and resumes its own parked statements at
        // the top of the loop, whatever this flag says. Verified by execution while `rmp` #1037 was
        // reworking this: with the flag forced false for every worker but 0, a read dispatched by
        // worker 1 still retired promptly and its transaction still closed with no further command.
        //
        // What the flag actually selects is the CONTENT of the timeout arm: `drive_index_build`, the
        // `rmp` #733 degraded-index repair, and the plan-cache invalidation that follows them. Those
        // are engine-wide repairs over one store, and running them on W workers would run each of them
        // W times — so they stay worker 0's. The reader/parked conditions are here because they make
        // the timeout arm's work worth doing at all on an otherwise idle engine, not because a worker
        // would fail to wake without them.
        //
        // The maintenance CADENCE is not decided here at all — see [`maybe_run_maintenance`], which
        // every worker calls from the tail of `process_command` and exactly one at a time runs.
        //
        // `readers_inflight` is the engine's since `rmp` #1037, so worker 0 now ticks for any worker's
        // in-flight read rather than only its own — which is the correct reading of a question about
        // the engine.
        let timed = worker_id == 0
            && (building
                || indexes_degraded
                || vector_blocked
                || ft_spatial_poisoned
                || reclaim.readers_inflight.load(Ordering::Relaxed) > 0
                || !sessions.parked.lock().is_empty());

        // A stop raised by another worker ends this one too, checked before it blocks. The
        // decrement happens at the single exit below, so a worker that leaves here is counted out
        // exactly once.
        if stop.stopping.load(Ordering::Acquire) {
            break 'engine;
        }

        let cmd = if timed {
            // The lock covers the DEQUEUE only — it is released the moment a command is in
            // hand, so the work that follows runs with no worker waiting on this one. And no engine
            // session latch may be held while this thread parks for up to a tick (`rmp` #1038):
            // waiting for a command with the open-transaction table in hand would stall every other
            // worker on an event that may never come.
            assert_no_engine_latch_held("engine command receive (timed)");
            let received = {
                let guard = rx
                    .lock()
                    .expect("INVARIANT: the command-queue latch is not poisoned");
                guard.recv_timeout(INDEX_BUILD_TICK)
            };
            match received {
                Ok(cmd) => cmd,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // No command this tick: advance any build, then loop (which drains retirements).
                    drive_index_build(&coordinator);
                    // Surface and repair a fail-closed index set (`rmp` task #733). Any repair changes
                    // what `catalog()` exposes (indexes come back `Online`), so the plan cache must be
                    // invalidated exactly as a completed build does — otherwise plans compiled while
                    // degraded (scan-only) would be served from cache forever.
                    if maintain_degraded_indexes(
                        &coordinator,
                        &metrics,
                        &db_name,
                        &mut index_health_seen,
                    ) {
                        plan_cache.lock().bump_schema();
                    }
                    invalidate_cache_on_build_completion(
                        &coordinator,
                        plan_cache,
                        &mut builds_were_pending,
                    );
                    continue 'engine;
                }
                // Channel closed (all client senders dropped): the engine is being torn down without a
                // graceful `Shutdown`. Stop serving.
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break 'engine,
            }
        } else {
            // This WAS a plain blocking `recv`, and with more than one worker that is a deadlock
            // (`rmp` #1033): a worker parked in `recv` never observes `stopping`, so the worker
            // handling `Shutdown` waits for it to leave while it waits for a command that will never
            // come. Found by running the multi-stream gate with four workers, where it hung — with
            // W = 1 it cannot happen, which is exactly why the knob had to be exercised rather than
            // merely threaded.
            //
            // A bounded wait costs one wake per idle worker per tick and makes the stop observable.
            assert_no_engine_latch_held("engine command receive");
            let received = {
                let guard = rx
                    .lock()
                    .expect("INVARIANT: the command-queue latch is not poisoned");
                guard.recv_timeout(INDEX_BUILD_TICK)
            };
            match received {
                Ok(cmd) => cmd,
                // Nothing this tick: loop round, re-check `stopping`, and wait again.
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue 'engine,
                // Channel closed (every client sender dropped): stop serving.
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break 'engine,
            }
        };
        // A `Shutdown` is intercepted BEFORE it is dispatched (`rmp` #1033). The dispatch's
        // shutdown path consumes the coordinator for the final flush, and `Arc::try_unwrap` needs
        // sole ownership — so this worker must be the LAST one inside the loop before it runs.
        // Raise the stop, then wait for the others to leave. Every worker checks `stopping` before
        // it blocks, so a worker sitting in `recv` leaves on its next turn; one executing a
        // statement leaves when that statement finishes, which is what a graceful stop means.
        if matches!(cmd, Cmd::Shutdown { .. }) {
            stop.stopping.store(true, Ordering::Release);
            while stop.live_workers.load(Ordering::Acquire) > 1 {
                std::thread::yield_now();
            }
        }
        // Test-only (`rmp` #435): intercept the simulated-maintenance driver here in the loop, where the
        // per-engine flag + the consecutive-failure streak live, so it exercises the REAL escalation
        // path confined to this engine. Returns the original command in production builds (identity).
        let Some(cmd) = intercept_simulate_maintenance(
            cmd,
            &mut maintenance_consecutive_failures,
            &metrics,
            &maintenance_degraded,
        ) else {
            continue 'engine;
        };
        if !process_command(ProcessCtx {
            cmd,
            rx: &rx,
            coordinator: &mut coordinator,
            open: &sessions.open,
            next_ticket: &minter,
            plan_cache,
            extensions: &extensions,
            dispatch: &dispatch,
            reclaim: &reclaim,
            parked: &sessions.parked,
            max_parked_inline,
            result_buffer_capacity,
            metrics: &metrics,
            db: &db_name,
            degraded: &degraded,
            maintenance_degraded: &maintenance_degraded,
            active_txns,
            clock: &clock,
            statement_timeout,
            loading_session: &mut loading_session,
            maintenance_consecutive_failures: &mut maintenance_consecutive_failures,
            builds_were_pending: &mut builds_were_pending,
            pending_cmd: &mut pending_cmd,
            wal_sync: &wal_sync,
            retire_rx: &retire_rx,
            transactions: &transactions,
        }) {
            // Tell every other worker to stop before leaving: they are blocked in `recv` and
            // would otherwise wait for the last client sender to drop, which is a later and
            // unrelated event (`rmp` #1033).
            stop.stopping.store(true, Ordering::Release);
            break 'engine; // Shutdown handled (drained + hardened) inside the dispatch.
        }
    }

    // ---- the exit sequence, and why its ORDER is the whole correctness argument (`rmp` #1036) ----
    //
    // The worker running `Shutdown` waits for `live_workers` to reach one and then calls
    // `Arc::try_unwrap` on the coordinator, which needs sole ownership and PANICS without it. So the
    // count this worker decrements must mean "I no longer hold anything that shares the coordinator"
    // — which makes the release of those things part of the protocol, not cleanup that may follow it.
    //
    // 1. The reader pool goes first. `shutdown` drops the work-queue sender (ending each reader's
    //    `recv`) and joins them, so no reader of THIS worker survives into the final flush — which
    //    consumes the store the readers read. A retirement that arrives after the loop exited is
    //    dropped: its transaction is rolled back by `Shutdown`'s `drain_inflight`, never left
    //    half-applied. That justification is only sound because the open-transaction table is
    //    engine-wide (`rmp` #1041): the dropped retirement belongs to a reader THIS worker dispatched,
    //    so its ticket lives in this worker's residue class — and until the table was shared, the
    //    drain ran over the table of whichever worker received `Shutdown` and reached this one's
    //    transactions only when they happened to be the same worker. The order below is what makes
    //    the timing work: every other worker has left the loop before the shutdown worker passes its
    //    barrier, so every late retirement has already been dropped when the drain runs.
    // 2. Then this worker's share of the coordinator is released.
    // 3. Only then is the exit announced.
    //
    // The previous order decremented FIRST, to avoid holding the stop behind a slow teardown. That
    // reasoning was sound while `live_workers` was per worker and the barrier could never fire; the
    // moment the counter became real, the same order would let `try_unwrap` run against a share this
    // worker still held. A slower stop is the price, and it is bounded by a join of threads that
    // have already been told to finish.
    // The pool is the ENGINE's since `rmp` #1039, so this is a shared, idempotent close rather than a
    // consuming one: whichever worker leaves last closes the queue and joins the readers, and the ones
    // before it find it already closed. A worker still dispatching while another closes gets its task
    // handed back and runs it inline — the same contract a full queue has always had.
    if let read_pool::ReadDispatch::Threaded(pool) = &*dispatch {
        pool.shutdown();
    }
    drop(coordinator.take());
    // Counted out exactly once, at the single exit, after everything above has been released.
    stop.live_workers.fetch_sub(1, Ordering::AcqRel);
}

/// Drains and processes every reader retirement currently available on the ENGINE's retirement channel
/// (`rmp` task #336 Slice 3b-ii; engine-wide since `rmp` #1039). Non-blocking: stops when the channel
/// is momentarily empty. Each retirement is finalised by [`finish_reader`].
///
/// # Any worker may drain it, and any worker may finalise any reader
///
/// The channel is one per engine, so a reader dispatched by worker 3 can be finalised by worker 1.
/// That is deliberate — it makes retirement latency the minimum over the workers' ticks rather than the
/// wait for one particular worker — and it is admissible for a reason narrower than it looks.
///
/// The `rmp` #1041 rule is not "a worker must not touch a foreign transaction"; it is "a worker must
/// not reap or resume a transaction whose owner may be INSIDE it". An off-thread reader satisfies the
/// same condition [`drain_inflight`] relies on: its dispatching worker returned
/// `RunOutcome::OffThreadReader` and holds no further reference to the statement, and the reader thread
/// has finished — posting the retirement is the last thing it does. The age sweep cannot contend
/// either: it declines every auto-commit entry unconditionally, and an off-thread reader is auto-commit
/// by construction. The one remaining race, a client `Rollback` for the same ticket, is resolved where
/// it always was — by the `open.remove` claim in [`finish_reader`], which is atomic across workers
/// because the table is engine-wide.
///
/// The lock is taken for the DEQUEUE ONLY. [`finish_reader`] takes the rank-5 open-table latch and runs
/// a commit; holding a plain mutex across that would convoy every worker behind one reader's
/// finalisation, which is the `rmp` #1038 shape. Poison is recovered rather than propagated: a poisoned
/// retire lock would pin the GC watermark forever and leak every in-flight reader's egress channel, and
/// there is no state a panic could have left inconsistent — the `Receiver` is intact.
#[allow(clippy::too_many_arguments)] // The retirement path threads its execution context here.
fn process_retirements<D: BlockDevice, S: LogSink>(
    retire_rx: &std::sync::Mutex<std::sync::mpsc::Receiver<read_pool::ReadRetirement>>,
    coordinator: &Option<Arc<TxnCoordinator<D, S>>>,
    open: &EngineLatch<OpenTxTable>,
    reclaim: &EngineReclaim,
    metrics: &Metrics,
    db: &str,
    degraded: &EngineDegraded,
    active_txns: &ActiveTxnGauge,
) {
    let mut any_retired = false;
    loop {
        let Ok(retirement) = ({
            let rx = retire_rx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            rx.try_recv()
        }) else {
            break;
        };
        if let Some(coord) = coordinator.as_deref() {
            finish_reader(coord, open, retirement, metrics, db, degraded);
        }
        // `fetch_update`, not `fetch_sub`: the original was a `saturating_sub`, and the two differ
        // exactly at zero — `fetch_sub` wraps to `u64::MAX`, which would report an engine with
        // eighteen quintillion readers in flight and make the drain barrier never finish.
        let _ = reclaim
            .readers_inflight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(1))
            });
        active_txns.publish(
            coordinator
                .as_deref()
                .map_or(0, TxnCoordinator::active_count),
            coordinator
                .as_deref()
                .map_or(0, TxnCoordinator::ssi_tracked_len),
        );
        any_retired = true;
    }
    // `rmp` #588: a retired reader may have been the last one predating some GC-freed slot's reuse
    // barrier — lift the hold on every slot the (now-advanced) oldest open transaction has passed, so a
    // freed slot becomes reusable promptly rather than waiting for the next maintenance pass. Cheap: a
    // no-op when nothing is shadow-held.
    if any_retired && let Some(coord) = coordinator.as_deref() {
        // Read the watermark under the latch, release, then act on it: `release_reusable_slots` walks
        // the store's shadow-held slots, which is store work of unbounded size and has no business
        // running at rank 5.
        //
        // Under the reclaim gate (`rmp` #1037), and declining rather than waiting. A release that runs
        // WHILE another worker's pass is freeing would judge that pass's fresh stamps against a
        // threshold computed for the world before it — and at `oldest == u64::MAX` (nothing open at
        // this instant) that threshold releases everything, including what the pass has just held.
        // Skipping is free: the pass ends with a release of its own.
        //
        // At one worker the gate is never contended here (this runs between commands, never inside a
        // pass), so this is the same unconditional release it has always been.
        //
        // `release_threshold`, not the raw minimum: above one worker a slot may only be released once
        // the oldest open transaction has passed the ticket high-water the last reclaim pass ENDED at,
        // because a sibling can open a transaction — and take its read view — while that pass is still
        // freeing. At one worker the floor is `0` and this is the identity.
        if let Some(_pass) = reclaim.try_enter_pass() {
            let oldest_open_ticket = { open.lock().keys().copied().min().unwrap_or(u64::MAX) };
            coord.release_reusable_slots(reclaim.release_threshold(oldest_open_ticket));
            // Republish here too (`rmp` #1037): a retirement is the OTHER thing that opens the hold,
            // and without this the gauge kept reporting the pre-release figure until the next reclaim
            // pass happened to run — so the one number an operator has for deferred reuse read high
            // for exactly as long as nothing was reclaiming.
            metrics.publish_held_slots_for(db, coord.held_slots_len() as u64);
        }
    }
}

/// Finalises an off-thread reader's retirement on the **engine thread** (`rmp` task #336, Slice
/// 3b-ii) — the M1 serializability barrier + the auto-commit.
///
/// 1. **Merge (M1):** fold the reader's SIREAD buffer into the shared SSI tracker *before* the
///    auto-commit's `detect_pivot_abort`, so the reader's rw-edges are present when its (or a
///    concurrent writer's) pivot is checked.
///
///    The old justification was "this runs on ONE thread — the worker that dispatched the reader, in
///    its own retirement channel's arrival order — so no-lost-edge reduces to in-order event
///    processing". `rmp` #1039 makes the retirement channel the ENGINE's, so a reader dispatched by
///    worker 3 may be finalised by worker 1 and two retirements may be finalised concurrently. That
///    premise is gone and is NOT replaced by a weaker version of itself. What replaces it:
///
///    **M1′.** For every off-thread reader `R`, `merge_read_buffer(R)` runs exactly once, under
///    exclusive access to the tracker, and strictly before `detect_pivot_abort(R)` — on whichever
///    worker drains `R`'s retirement. The DRAIN ORDER IS UNOBSERVABLE, because merging `R`'s buffer
///    can only touch edges incident on `R`: it calls `record_read`/`record_predicate_read` and nothing
///    else, and those add `R` to a key's reader set and `add_edge(R, w)` for concurrent writers of
///    that key. Two readers' merges therefore touch disjoint edge sets, and interleaving them changes
///    nothing. Exclusivity comes from the tracker's own lock (`SharedCell`), not from being one
///    thread — which is what makes "whichever worker" sound.
///
///    Nor does the merge need to be ordered against a concurrent WRITE: rw-edge formation is symmetric
///    in the two reverse indexes (`record_read` consults `writers_of`, `record_write` consults
///    `readers_of`), so whichever lands second closes the edge; and a merge that lands after the
///    writer already committed is caught by `add_edge`'s eager committed-pivot break, which dooms the
///    still-active endpoint.
///
///    WHAT WOULD BREAK M1′, stated because each is one edit away: moving the merge after the commit
///    below, or after the `still_open` early return (the merge is deliberately done BEFORE the ticket
///    claim, so a reader whose rollback raced still contributes its markers); making `record_read`
///    stop consulting `writers_of` or `record_write` stop consulting `readers_of`; removing the
///    committed-pivot break; or ever letting an off-thread reader WRITE, which would give it an
///    inbound edge and destroy the disjointness the whole argument rests on.
///
///    M1′ does NOT close the window between a writer's `detect_pivot_abort` and its `record_commit`,
///    which are separate tracker acquisitions with store work between them. A merge landing inside it
///    sees the writer neither validated-with-the-edge nor committed. That window is not opened by the
///    shared channel — an inline read on any worker merges through the same function — it opens the
///    moment `W > 1`, and it is why `admission.engine_workers` above one is still refused.
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
    coordinator: &TxnCoordinator<D, S>,
    open: &EngineLatch<OpenTxTable>,
    retirement: read_pool::ReadRetirement,
    metrics: &Metrics,
    db: &str,
    degraded: &EngineDegraded,
) {
    let read_pool::ReadRetirement {
        txn,
        ticket,
        buffer,
        outcome,
        row_tx,
    } = retirement;

    // (1) M1: merge the reader's SIREAD markers into the shared tracker BEFORE any commit's pivot
    // detection. This worker need not be the one that dispatched the reader (`rmp` #1039); see M1′ in
    // the doc comment for why the drain order is unobservable, and what would break that.
    coordinator.merge_read_buffer(buffer);

    // Remove the open-tx ticket (the engine owns its lifecycle now). A reader that the client
    // disconnected from mid-stream still retires here and is finalised exactly once.
    // Removing the ticket IS the claim on this retirement: whoever takes it out of the table owns the
    // commit/rollback that follows, and exactly one caller can. So the latch covers the claim and
    // nothing else — the commit below is a WAL append plus a possible `fdatasync`, which at rank 5
    // would convoy every worker of the engine behind one reader's durability barrier.
    let still_open = { open.lock().remove(&ticket.0).is_some() };

    if !still_open {
        // The ticket was already finalised (e.g. an explicit rollback raced the retirement). The
        // merge above is harmless; just drop the egress channel.
        drop(row_tx);
        return;
    }

    // (2) Auto-commit: commit on a clean outcome, roll back on a read error (R3 — a captured
    // deferral / write-degrade error must surface, never a silent commit over an untrustworthy read).
    // `rmp` #409: the auto-commit `commit`/`rollback` below run on the engine thread OUTSIDE any
    // `catch_unwind`, and both are fallible WAL/buffer-pool paths that can themselves panic. Wrap each
    // in `catch_recovery` so a recovery double-panic flags the engine degraded and keeps the loop alive,
    // rather than unwinding the single engine thread (`engine_gone` forever — the #386 failure, deeper).
    match outcome {
        Ok(()) => match catch_recovery(metrics, degraded, "reader commit", || {
            coordinator.commit(txn)
        }) {
            Some(Ok(_)) => metrics.record_commit_for(db),
            Some(Err(e)) => {
                // The COMMIT failed. An SSI abort is already rolled back; a store-level failure is not
                // (`rmp` #955), and this reader's ticket is already gone from `open`.
                resolve_failed_commit(coordinator, txn, degraded, "failed-reader-commit rollback");
                // The transaction is rolled back either way.
                // Deliver the failure to the consumer as a terminal stream item BEFORE closing the
                // egress channel — a rolled-back auto-commit must be reported as failed/retriable, never
                // a silent success over undone work (`04 §1.3` step 6; the rmp #238 atomicity divergence).
                let _ = row_tx.send(Err(e));
                metrics.record_abort_for(db);
            }
            // Recovery double-panicked: the engine is flagged degraded (gauge + metric set inside
            // `catch_recovery`). Surface a clean terminal error to this consumer so it does not hang on
            // the dropped egress channel; subsequent requests get the engine-degraded error.
            None => {
                let _ = row_tx.send(Err(GraphusError::Runtime(
                    "internal error: engine degraded (commit recovery panicked)".to_owned(),
                )));
            }
        },
        Err(read_err) => {
            // The read itself errored (runtime / captured / write-degrade). The terminal error was
            // already streamed by the reader (`run_read_task` sends it for auth/deferral errors); roll
            // the transaction back so nothing is committed over an untrustworthy result.
            let _ = read_err; // already surfaced to the consumer by the reader.
            match catch_recovery(metrics, degraded, "reader rollback", || {
                coordinator.rollback(txn)
            }) {
                Some(Ok(())) => metrics.record_abort_for(db),
                Some(Err(e)) => {
                    // `rmp` #955: an `Err` here is usually the benign idempotent rollback (which the
                    // pre-#955 code accounted as an abort — kept, so the metric is unchanged for it).
                    // A rollback that left the transaction OPEN in the store is not benign.
                    degrade_on_incomplete_undo(coordinator, txn, degraded, "reader rollback", &e);
                    metrics.record_abort_for(db);
                }
                None => {
                    let _ = row_tx.send(Err(GraphusError::Runtime(
                        "internal error: engine degraded (rollback recovery panicked)".to_owned(),
                    )));
                }
            }
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
/// premature-reclamation guard).
///
/// A maintenance failure is **never fatal** — durability is unaffected (nothing was reclaimed below
/// the floor) so the engine must stay up and retry. But a *persistent* failure means reclamation has
/// stalled while writes keep accruing — a slow-motion OOM that a swallow-and-retry would hide behind a
/// green readiness probe (`rmp` #394). So each failure increments the `maintenance_failures` metric and
/// the consecutive-failure streak; once the streak reaches
/// [`MAINTENANCE_FAILURE_ESCALATION_THRESHOLD`] the server is flagged **degraded** (the
/// `maintenance_degraded` gauge → `1`, which drives `/health/ready` to `503`). A single transient
/// failure does not escalate. Any success resets the streak and clears the gauge.
///
/// `consecutive_failures` is owned by the engine loop and threaded in by `&mut` so the streak persists
/// across maintenance ticks (each tick processes at most one checkpoint).
///
/// The adaptive cadence (`rmp` #556) is now used for **both** ordinary traffic and a `Loading` Mode A
/// bulk-import session (`rmp` #590). Historically a `Loading` session used a much wider fixed cadence
/// (4 GiB) to dodge a measured O(N²) maintenance cost — each pass ran a full-store GC scan whose cost
/// grew with the store. `rmp` #522 made the freeze sweep O(Δ), and `rmp` #590 makes the mid-load pass
/// **freeze-only** (skipping the still-O(store) property sweep, which the Mode A checkpoint sentinel
/// otherwise gates ON every batch), so a mid-load pass is now O(Δ) too and can run on the ordinary tight
/// cadence. That bounds the WAL a load retains to ≤ this cadence at ANY crash/`STOP` point *before*
/// `?end=true` — the fix for the reopen-OOM the un-reclaimed multi-GB WAL used to cause (`rmp` #590).
fn maintenance_interval_bytes(store_bytes: u64) -> u64 {
    // Adaptive cadence (`rmp` #556): reclaim proportionally to the live store size so the on-disk
    // WAL/store ratio is bounded to ≈ WAL_STORE_RATIO_TARGET, instead of at a fixed absolute
    // threshold that leaves a small OLTP store with a WAL tens of times its size. Clamped so a tiny
    // store is not checkpointed on a hair-trigger (FLOOR) and a large store is never checkpointed
    // *less* often than the historical 256 MiB cadence (CAP) — so this can only make reclamation more
    // frequent, never less, and is therefore durability- and regression-safe by construction.
    // `clamp` is panic-safe: `MIN < CAP` is asserted at compile time in `maintenance_tests`.
    WAL_STORE_RATIO_TARGET.saturating_mul(store_bytes).clamp(
        MAINTENANCE_CHECKPOINT_MIN_INTERVAL_BYTES,
        MAINTENANCE_CHECKPOINT_INTERVAL_BYTES,
    )
}

/// **`rmp` #588 (sprint-52 B1).** The reuse barrier for a GC pass that may free record slots while an
/// off-thread reader (`rmp` #336) is walking a chain through them.
///
/// Returns `Some(ticket_high_water + 1)` when the barrier must be armed, and `None` otherwise. The
/// `+ 1` is load-bearing: [`TicketSequencer::high_water`] is an upper bound that an issued ticket may
/// EQUAL, and [`RecordStore::release_held`](graphus_storage::RecordStore::release_held) releases a
/// held slot once `oldest_open_ticket >= barrier`, so a barrier that merely equalled the newest open
/// ticket would let that reader — while it is the oldest open — release the slot under its own feet
/// and reopen #588.
///
/// At `W = 1` the gate is unchanged: `readers_inflight == 0` (the inline/DST driver never dispatches
/// an off-thread reader) gives `None`, so `held_slots` stays empty and the freed-id reuse order —
/// hence the DST golden trace — is byte-identical to before this task.
///
/// # Above one worker (`rmp` #1037)
///
/// Both inputs used to come from per-worker state, and both were wrong for it.
///
/// `ticket_high_water` is now the ENGINE's (see [`TicketSequencer::high_water`]). A floor taken from
/// one worker's counter dominated that worker's tickets and nobody else's — worker 0 with an untouched
/// counter produced a barrier of `1`, which a sibling's already-open ticket `5` satisfies at once.
///
/// `readers_inflight` is now the ENGINE's too, and above one worker it no longer decides anything:
/// **at `W > 1` the barrier is armed unconditionally.** Three code-level facts force that, and each
/// one is sufficient on its own.
///
/// 1. Off-thread readers are no longer the only concurrent chain-walkers. A sibling worker runs
///    explicit-transaction reads, writes and resumed parked batches INLINE, against the same store,
///    at the same time as this pass. At `W = 1` those were the pass's own thread and could not race
///    it; above one worker they are exactly the `rmp` #588 hazard with a different thread on it, and
///    `readers_inflight` does not count them.
/// 2. The counter is incremented AFTER `ReadDispatch::try_submit` returns, so an off-thread reader is
///    already running while it still reads zero. At `W = 1` that window closes before the same thread
///    reaches its maintenance tail; above one worker nothing closes it.
/// 3. A reader may be dispatched by a sibling at any point *during* the pass, so no value sampled
///    when the pass begins can characterise the whole of it.
///
/// The cost is deferred reuse, paid only at `W > 1`: freed slots (including a concurrent rollback's,
/// which the armed barrier also stamps) stay shadow-held until `EngineReclaim::release_threshold`
/// opens. The cost of the other direction is a silently wrong row, so this is not a trade that has two
/// sides. `EngineReclaim::release_floor` is what stops the hold from becoming a leak.
fn gc_reuse_barrier(ticket_high_water: u64, readers_inflight: u64, workers: u64) -> Option<u64> {
    // `saturating_add`: at the u64 ceiling a wrap would produce `0`, which `release_held` treats as
    // "release everything". Saturating holds instead, which is the direction that costs space rather
    // than correctness.
    (workers > 1 || readers_inflight > 0).then(|| ticket_high_water.saturating_add(1))
}

/// **ONE cadence per engine** (`rmp` #1037). This is called from the tail of `process_command`, which
/// EVERY worker runs — the comment that said only worker 0 drives maintenance described the idle tick,
/// not this. It used to read and write a `wal_at_last_maintenance` local of each worker, so a
/// `W`-worker engine ran `W` independent cadences, each deciding on its own numbers and all of them
/// arming the ONE shared reuse barrier (`graphus_storage::idalloc::SharedReuseBarrier`) that each
/// disarms on the way out — so an overlapping pass's frees went unstamped.
///
/// Both halves are fixed by the same lock: the cadence watermark lives in [`EngineReclaim`] and is
/// read-decided-written under its single-flight gate, so the pass runs once. `try_enter_pass` rather
/// than `enter_pass`: a worker that finds the gate taken has nothing to add — the pass in progress is
/// the pass it wanted — and must go back to serving commands rather than park behind an O(store)
/// sweep.
#[allow(clippy::too_many_arguments)] // the engine loop threads its maintenance context through here
fn maybe_run_maintenance<D: BlockDevice, S: LogSink>(
    coordinator: &Option<Arc<TxnCoordinator<D, S>>>,
    reclaim: &EngineReclaim,
    // The ENGINE's open-transaction table (`rmp` #1041), for the release threshold. Sampled INSIDE the
    // reclaim gate rather than handed in: the value has to describe the same pass it is used for.
    open: &EngineLatch<OpenTxTable>,
    consecutive_failures: &mut u32,
    metrics: &Metrics,
    // The database name labelling this engine's per-database series (`rmp` #463) — needed here so the
    // pass can publish the WAL byte offset it re-reads below (`rmp` #745).
    db: &str,
    maintenance_degraded: &MaintenanceDegraded,
    loading_session_active: bool,
    loading_just_ended: bool,
) {
    let Some(coord) = coordinator.as_deref() else {
        return;
    };
    // Another worker is already reclaiming for this engine: its pass does this one's work.
    let Some(_pass) = reclaim.try_enter_pass() else {
        return;
    };
    // The engine's cadence watermark. Read here and written back below, both under the gate, so the
    // read-decide-write that used to be a per-worker local is now one indivisible decision.
    let wal_at_last_maintenance = reclaim.wal_at_last_maintenance.load(Ordering::Relaxed);
    // `rmp` #588: the oldest open transaction's ticket (`u64::MAX` when none is open), which becomes
    // the release threshold once `EngineReclaim` has decided whether the engine is past the last
    // pass's floor. Read under the rank-5 latch and released at once — never held across the pass.
    let oldest_open_ticket = { open.lock().keys().copied().min().unwrap_or(u64::MAX) };
    // `rmp` #565 — do NOT fire a maintenance GC pass on the loading→not-loading edge. When a Mode A
    // network bulk-import session ends (`End`), the session flag has just cleared, so this tick would
    // otherwise run a FULL `coord.checkpoint()` — and while the freeze sweep is O(Δ) (`rmp` #522) and the
    // mid-load passes ran freeze-only (`rmp` #590), a FULL pass still runs the **O(total store size)
    // property sweep** (`sweep_property_chains`, gated ON because the load's checkpoint sentinel tombstones
    // a property version per batch; measured 1.7 s → 18 s as the store grows). That scan runs synchronously
    // on the engine thread as the tail of the `End` command, *ahead of the `Shutdown` that a `STOP DATABASE`
    // — which normally follows `End` — has already queued*; because the engine is single-threaded it cannot
    // acknowledge `Shutdown` until the scan finishes, so `stop_engine`'s drain deadline elapses and it
    // force-detaches a perfectly healthy engine (the root cause of the `rmp` #555 force-detach →
    // concurrent-reopen corruption). Instead we re-anchor the maintenance watermark to the current WAL
    // length and skip the pass: the FULL end-of-load reclaim already ran inside the `End` handler *before*
    // this point (`rmp` #579, `bulk_load::reclaim_after_bulk_load`), and any residual is reclaimed by the
    // ordinary background cadence after the next `START DATABASE`, on the live database — never on the drain
    // path. Durability is untouched: recovery redo stays bounded because the store's per-commit
    // auto-checkpoint (`DEFAULT_CHECKPOINT_INTERVAL_BYTES`, 64 MiB) flushed every dirty page home throughout
    // the load, so the unreclaimed WAL below the redo floor is skipped by recovery, not replayed. The
    // progress-aware drain (`rmp` #563) is the general safety net for any *other* long maintenance pass that
    // a `STOP` may still race; this removes the specific, reproducible bulk-import trigger.
    if loading_just_ended {
        let anchored = coord.wal_durable_len();
        reclaim
            .wal_at_last_maintenance
            .store(anchored, Ordering::Relaxed);
        metrics.publish_wal_bytes_for(db, anchored);
        return;
    }
    // Size the reclaim interval against the live store (`rmp` #556): a cheap, non-allocating page count.
    let interval = maintenance_interval_bytes(coord.store_byte_len());
    let durable = coord.wal_durable_len();
    // Publish the WAL byte offset the cadence check just read (`rmp` #745) — free, and it runs on every
    // engine tick. This is the seam that keeps `graphus_wal_bytes_written_total` fresh for WAL writers
    // that do NOT pass through `ack_prepared_commits` — notably a Mode A/B bulk-import session, whose
    // batches harden the log directly. Nothing could be *lost* without it (each publish carries the
    // ABSOLUTE offset, so a later one always catches up), but a long bulk load would otherwise show a
    // flat counter until its end-of-load checkpoint, which is exactly the kind of measurement blind spot
    // this metric exists to remove.
    metrics.publish_wal_bytes_for(db, durable);
    if durable.saturating_sub(wal_at_last_maintenance) < interval {
        return;
    }
    // `rmp` #588 (sprint-52 B1): reader-safe reclaim — shadow-hold the slots this pass frees from reuse
    // while an off-thread reader that predates the pass may still be walking a chain through them, then
    // lift the hold for every slot whose predating readers have all retired. With no open reader
    // `oldest_open_ticket` is `u64::MAX`, so the hold is released immediately (the inline/DST path and the
    // no-reader fast path are unchanged).
    //
    // `rmp` #590: while a Mode A bulk-import session is `Loading`, run a **freeze-only** pass. It advances
    // the WAL reclaim floor (the incremental freeze sweep drains `unfrozen_commit_lsn`) so a crash/`STOP`
    // *before* `?end=true` cannot leave a multi-GB un-reclaimed WAL for the next `START DATABASE` to
    // materialise into its recovery heap — WITHOUT paying the O(store) property sweep the Mode A checkpoint
    // sentinel would otherwise gate ON every batch (which, on this now-tight cadence, would reintroduce the
    // O(N²) cost `rmp` #556/#565 had widened the loading cadence to avoid). The few dead property versions
    // the load defers are reclaimed by the ordinary full cadence after `START`, or by the FULL end-of-load
    // checkpoint (`rmp` #579) at a clean `End`. Ordinary traffic uses the full reclaim.
    //
    // The barrier is derived HERE, inside the gate, from the ENGINE's ticket high-water — never from
    // the calling worker's own counter, which dominates nobody else's tickets (`rmp` #1037). The
    // release threshold is likewise the engine's decision, not the raw minimum: see
    // [`EngineReclaim::release_threshold`].
    let reuse_barrier = reclaim.reuse_barrier();
    let in_pass_release = reclaim.in_pass_release_threshold(oldest_open_ticket);
    let outcome = if loading_session_active {
        coord.checkpoint_reader_safe_freeze_only(reuse_barrier, in_pass_release)
    } else {
        coord.checkpoint_reader_safe(reuse_barrier, in_pass_release)
    };
    // The pass has finished freeing: fix the mark that every later release has to clear, so a
    // transaction a sibling opened WHILE the pass ran still holds this pass's slots back. Raised on
    // both outcomes — a failed pass may still have freed slots before it failed. Then do the release
    // the pass deferred, still inside the gate, so no other worker's pass can stamp slots in between.
    reclaim.note_pass_finished();
    release_after_pass(coord, open, reclaim);
    match outcome {
        Ok(report) => {
            // Success: record progress (aggregate observability counters) and clear **this engine's
            // own** reclamation-degraded flag (`rmp` #435 — never another engine's); reset the streak.
            metrics.record_maintenance_checkpoint(report.reclaimed as u64, report.frozen as u64);
            // `rmp` #809: raise the durability alert if the release-active freeze-frontier audit found a
            // committed stamp stranded unfrozen (the pass already skipped the prune fail-closed, so no
            // data was lost — this makes the regression observable). Zero on every healthy pass.
            note_freeze_frontier_violations(metrics, &report, db);
            // `rmp` #992: republish this database's derived-index footprint. The pass has just
            // collected the entries its reclaimed versions orphaned, so this is the point at which the
            // number is meaningful — and a gauge that climbs under a steady write workload with no
            // growth in the data is the signature of that collection regressing.
            metrics.publish_derived_index_entries_for(db, coord.derived_index_entries() as u64);
            publish_index_collection(metrics, db, &coord.index_collection_totals());
            maintenance_degraded.clear();
            *consecutive_failures = 0;
        }
        Err(e) => {
            // Never fatal: the floor was respected, so durability is intact. But surface the failure
            // (metric) and escalate a *persistent* run of failures so a stuck reclamation cannot leak
            // memory silently behind a green probe (`rmp` #394).
            record_maintenance_failure(consecutive_failures, metrics, maintenance_degraded, &e);
        }
    }
    // Re-read: a successful checkpoint reclaimed the WAL prefix, so anchor the next interval at the new
    // length. On failure the length is unchanged, so the next tick re-attempts immediately.
    let anchored = coord.wal_durable_len();
    reclaim
        .wal_at_last_maintenance
        .store(anchored, Ordering::Relaxed);
    // The checkpoint itself appended WAL (its checkpoint record), and it RECLAIMED sealed segments —
    // deleting files without moving the byte offset. Publishing the re-read offset here (`rmp` #745) is
    // the seam that proves the point of the whole metric: the counter keeps climbing across exactly the
    // event where an external, poll-the-directory reconstruction loses whole segments and silently
    // under-counts.
    metrics.publish_wal_bytes_for(db, anchored);
    // `rmp` #1037: how many physical slots this engine is still shadow-holding from reuse. Published
    // here because a pass is the only thing that adds to the hold, and because above one worker the
    // barrier is armed unconditionally — deferred reuse is then a resource the server is carrying, and
    // a resource an operator cannot see is one nobody can size.
    metrics.publish_held_slots_for(db, coord.held_slots_len() as u64);
}

/// The **maximum-transaction-age sweep** (`rmp` #477): aborts any open **explicit** transaction whose
/// lifetime (now − begin, on the **monotonic** clock per `rmp` #395) has reached
/// `max_transaction_age`, freeing the MVCC GC low-water mark it would otherwise pin indefinitely.
///
/// This is the engine-level half of the guard whose detection lives in
/// [`TxnCoordinator::aged_transactions`]: a long-running reader — a single sustained `BEGIN`, or one a
/// client keeps *active* by periodically touching it so the inactivity sweep never fires — holds
/// [`TxnCoordinator::oldest_active_snapshot`] back forever, so dead versions can never be reclaimed and
/// the store and RAM grow without bound (the classic "idle-in-transaction blocks vacuum" denial of
/// service, CWE-400). Reaping the over-age holder with a clean [`TxnCoordinator::rollback`] removes it
/// from the active set, so the watermark advances and the next maintenance pass reclaims what it had
/// pinned. The abort is a clean rollback (no partial commit); the client sees a retriable
/// [`GraphusError::Transaction`] on its next use of the now-closed transaction.
///
/// ## Exclusions (so a reap never races a live read)
///
/// - **Disabled** (`max_transaction_age == None`): a cheap no-op.
/// - **Auto-commit statements** are excluded: they are transient single-statement units already bounded
///   by the per-statement timeout (`rmp` #476), and a read-only auto-commit may be **mid-flight on an
///   off-thread reader** (`rmp` #336) whose retirement still merges its SIREAD buffer back — reaping it
///   would resurrect a forgotten reader in the conflict graph. The age cap targets *explicit*
///   `BEGIN … COMMIT` transactions, which are the only ones a client can hold open across statements.
/// - **Every statement currently parked** (`parked`) is skipped: reaping one would pull the
///   per-statement seam out from under a live (suspended) cursor. Several can be parked at once
///   (`rmp` #485 B1), so ALL of their transactions are excluded, not just one. Each is reaped on a
///   later tick once idle (and is itself bounded by the per-statement timeout meanwhile).
/// - **Every transaction this worker does not own** is skipped (`rmp` #1041). This is the exclusion
///   that replaced an accident, and it is worth being exact about which one. The list above used to
///   read "parked/executing inline", crediting the parked queue with covering both — but a statement
///   that is *executing* is in neither `parked` nor anywhere else the sweep can see. What actually
///   protected it was that `open` held only this worker's transactions, so a foreign one was invisible
///   rather than merely unclaimed, and this worker cannot be sweeping and executing at the same time.
///   Sharing `open` removed exactly that, and a shared `parked` does not put it back: it makes
///   suspended cursors visible, not running ones. So the sweep asks
///   [`WorkerAffinity::owns`] and reaps only its own, which restores the property by stating it —
///   every worker still sweeps, and between them they still cover every transaction.
///
///   Be exact about what that reap costs, because it is not what the parked case costs and the
///   difference decides how it can be tested. Measured with the affinity test removed
///   (`tests/engine_shared_sessions_1041.rs`): a sibling worker rolled the transaction back 100 ms
///   into a 700 ms statement, and the statement then ran to completion, produced the correct
///   aggregate, and reported SUCCESS — because it read no store data, so nothing it did afterwards
///   consulted the transaction that no longer existed. A reaped *parked* statement fails loudly
///   ("statement in inactive txn"); a reaped *executing* one can be entirely silent, and the client
///   is told its statement succeeded inside a transaction that was destroyed while it ran. That is
///   why the gate for this exclusion asserts on `graphus_transactions_aborted_total` and not on the
///   statement's result.
#[allow(clippy::too_many_arguments)] // the engine loop threads its execution context through here
fn maybe_reap_aged<D: BlockDevice, S: LogSink>(
    coordinator: &Option<Arc<TxnCoordinator<D, S>>>,
    open: &EngineLatch<OpenTxTable>,
    parked: &EngineLatch<VecDeque<exec::InFlightInline>>,
    // Whose transactions this sweep may reap. One worker owns every ticket, so a single-worker engine
    // sweeps exactly what it always did.
    affinity: WorkerAffinity,
    max_transaction_age: Option<std::time::Duration>,
    clock: &Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    metrics: &Metrics,
    db: &str,
    active_txns: &ActiveTxnGauge,
) {
    let Some(max_age) = max_transaction_age else {
        return; // cap disabled — opt-out, unbounded lifetime
    };
    let Some(coord) = coordinator.as_deref() else {
        return; // coordinator already consumed by Shutdown
    };
    let max_age_nanos = u64::try_from(max_age.as_nanos()).unwrap_or(u64::MAX);
    let aged = coord.aged_transactions(clock.now_nanos(), max_age_nanos);
    if aged.is_empty() {
        return; // the common case: nothing over-age
    }
    // SNAPSHOT the parked transactions, then release the queue. This pass used to hold `parked` and
    // `open` at the same time, in that order, while the resume and park paths held them the other way
    // round — the `rmp` #1038 ABBA. Rank 5 now refuses the pair outright, and this is why it can: the
    // queue is read for one thing only, the set of transactions that must be skipped, and a `Vec` of
    // `TxnId` answers that question for the whole pass. It is a snapshot of a moment, which is all the
    // old code had too: a statement could park or resume between two iterations of the loop below.
    let parked_txns: Vec<TxnId> = {
        parked
            .lock()
            .iter()
            .map(exec::InFlightInline::txn)
            .collect()
    };
    let mut reaped = 0u64;
    for txn in aged {
        // Any inline statement currently parked (suspended mid-stream) must not be reaped: it holds a
        // live cursor that resumes on a later tick. Several can be parked at once (`rmp` #485 B1).
        if parked_txns.contains(&txn) {
            continue; // executing/parked inline now — reap on a later (idle) tick
        }
        // Reverse-map txn -> ticket, read its auto-commit flag, and remove it — ONE critical section,
        // because the find and the remove together are what claims this transaction. Split across two
        // acquisitions, two workers could both find the same ticket and both go on to roll it back.
        let claimed = {
            let mut open = open.lock();
            match open
                .iter()
                .find(|(_, t)| t.txn == txn)
                .map(|(ticket, t)| (*ticket, t.auto_commit))
            {
                // NOT IN THE TABLE AT ALL: an internal maintenance transaction the coordinator runs
                // for itself, which no ticket names — leave it to its owner. Since `rmp` #1041 this
                // arm no longer also absorbs "belongs to another worker": the table is shared, so a
                // sibling's transaction IS found here, and it is the `owns` test below that declines
                // it. Reading the two cases as one is how a foreign transaction would be reaped while
                // its owner ran a statement in it.
                None => None,
                // A transient auto-commit unit is never the idle-holder threat, and may be mid-flight
                // on an off-thread reader.
                Some((_, true)) => None,
                // Another worker's session. Its owner sweeps on its own tick with the same cap, so
                // nothing goes unswept; what would go wrong here is claiming a transaction whose
                // owner may be executing a statement in it right now.
                Some((ticket, false)) if !affinity.owns(ticket) => None,
                Some((ticket, false)) => {
                    open.remove(&ticket);
                    Some(ticket)
                }
            }
        };
        let Some(ticket) = claimed else {
            continue;
        };
        // A clean rollback: discards the transaction's writes/locks/SSI footprint atomically and removes
        // it from the active set so `oldest_active_snapshot` advances. Idempotent-safe: `rollback` only
        // errs for an already-inactive txn, which cannot happen here (we just observed it active). It is
        // an ARIES undo of everything the transaction wrote, so it runs with the latch released.
        if coord.rollback(txn).is_ok() {
            // Remember WHY this ticket vanished (`rmp` #988). Without this the owner's next `RUN` or
            // `COMMIT` could only be told "no such transaction", which is a different fact and sends
            // an operator hunting a lifecycle bug instead of reading `timing.max_transaction_age_ms`.
            // The record is consumed the first time it is delivered.
            open.lock().record_reaped(ticket);
            metrics.record_abort_for(db);
            reaped += 1;
        }
    }
    if reaped > 0 {
        // The active set shrank — refresh the open-transaction gauge so observability reflects the reap.
        active_txns.publish(coord.active_count(), coord.ssi_tracked_len());
    }
}

/// Resumes ONE batch of EACH currently-parked inline statement **this worker owns** (`rmp` task #372;
/// bounded-queue round-robin generalization per `rmp` #485 B1), each behind a panic-isolation boundary
/// (`rmp` #485 B2).
///
/// Only the statements parked at entry get a turn this tick (a re-suspended one is appended and waits
/// for the next tick), so the pass is bounded and fair across N slow consumers. For each statement:
///
/// * `resume_inflight` → `true` (egress filled again): push it back; resume next tick.
/// * `resume_inflight` → `false` (cursor exhausted / runtime error / disconnect): it already finalised
///   (auto-commit/rollback); drop it (closing its egress).
/// * `resume_inflight` **panics**: [`recover_panicked_resume`] rolls its transaction back + records the
///   panic, then it is dropped — and the engine thread stays alive. Without this boundary the panic
///   unwinds the single engine thread and bricks the database (the `rmp` #485 B2 finding: the
///   first-visit boundary in [`run_statement_isolated`] never covered the resume path).
///
/// [`AssertUnwindSafe`] is sound for the same reason as in [`run_statement_isolated`]: on a caught
/// panic no partially-mutated coordinator state is observed on any success path — the statement is
/// rolled back via ARIES undo, and the per-statement seam's `RefCell` borrows are released by
/// unwinding RAII guards before this frame regains control.
///
/// ## Why a shared queue is still resumed by the owner only (`rmp` #1041)
///
/// The queue became engine-wide with the open-transaction table, because the age sweep has to see
/// every suspended cursor to avoid reaping one. Resuming is a different matter: a resumed batch runs
/// real operators against the statement's transaction, and the transaction is the unit `rmp` #1035's
/// session affinity keeps single-threaded. A client may hold several results open in one transaction
/// (see `InFlightInline::pending_error`), so its owning worker can be running a second statement in
/// that very transaction while this pass looks at the first. Resuming a foreign statement would put two
/// threads inside one transaction's write buffer and SSI footprint — with no lock between them, because
/// there has never needed to be one. A statement that is not this worker's is therefore returned to the
/// queue untouched, and its owner picks it up on its own tick.
#[allow(clippy::too_many_arguments)] // the engine loop threads its execution context through here
fn resume_parked_statements<
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
>(
    parked: &EngineLatch<VecDeque<exec::InFlightInline>>,
    coordinator: &Option<Arc<TxnCoordinator<D, S>>>,
    open: &EngineLatch<OpenTxTable>,
    // Whose parked statements this pass may resume. One worker owns every ticket, so a single-worker
    // engine resumes exactly what it always did, in exactly the same order.
    affinity: WorkerAffinity,
    extensions: &Arc<graphus_cypher::extension::ExtensionRegistry>,
    metrics: &Arc<Metrics>,
    db: &str,
    degraded: &EngineDegraded,
    clock: &Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    active_txns: &ActiveTxnGauge,
) {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let mut finalized_any = false;
    // The budget: how many statements THIS WORKER owns, snapshotted at entry. A statement that
    // re-suspends is pushed to the back and only gets its next batch on the following tick, so the pass
    // never spins on one fast-refilling consumer.
    //
    // Counting only our own is the `rmp` #1041 half. The queue is engine-wide now, and a budget of
    // `len()` would grant this worker's statements one extra turn for every sibling's statement sitting
    // beside them — quietly undoing the "one batch each per tick" fairness the whole loop exists to
    // provide. At `W = 1` every entry is owned and this is `len()`, exactly as it always was.
    let mut budget = parked
        .lock()
        .iter()
        .filter(|stmt| affinity.owns(stmt.ticket().0))
        .count();
    while budget > 0 {
        budget -= 1;
        // TAKE under the latch, RESUME with it released. Removing the statement is what takes ownership
        // of it — it is out of the queue, so no other worker can reach it — and resuming it runs a batch
        // of a real query. Holding the queue across that was one half of the `rmp` #1038 defect and,
        // with `open` held too, the other half of its ABBA. The removal is deliberately its own `let`
        // statement rather than a `let … else` scrutinee, so the guard's release is visibly bound to a
        // statement end instead of resting on the temporary-scope rules for `let`-`else`.
        //
        // It takes the OLDEST statement this worker owns and leaves every sibling's where it is. The
        // obvious alternative — pop the head, and push it back if it turns out to belong to someone
        // else — reorders the queue as a side effect of looking at it: two workers doing that at the
        // same moment can swap the relative order of a THIRD worker's statements, and the order of the
        // queue is precisely what the fairness claim above is made of. Scanning costs a walk of a queue
        // whose length is bounded by `max_parked_inline` and is empty in the ordinary case.
        let popped = {
            let mut queue = parked.lock();
            queue
                .iter()
                .position(|stmt| affinity.owns(stmt.ticket().0))
                .and_then(|i| queue.remove(i))
        };
        let Some(mut stmt) = popped else {
            break; // nothing of ours left this tick
        };
        let Some(coord) = coordinator.as_deref() else {
            // Coordinator already consumed (Shutdown in progress): put it back and stop; Shutdown's
            // `drain_inflight` rolls its transaction back — every worker's, since `rmp` #1041 — and the
            // queue drops when the last worker releases the session state. At the head rather than at
            // the index it came from, which is a position this pass no longer strictly owns; on the
            // shutdown path there is no next tick for the order to matter to.
            parked.lock().push_front(stmt);
            break;
        };
        let txn = stmt.txn();
        // Outside the panic boundary, as in [`run_statement_isolated`]: a resumed batch runs a real
        // query, and the queue guard that popped this statement must already be gone (`rmp` #1038).
        assert_no_engine_latch_held("resume_parked_statements");
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            exec::resume_inflight(
                &mut stmt, coord, open, extensions, metrics, db, degraded, clock,
            )
        }));
        match outcome {
            // Re-suspended: round-robin to the back of the queue for the next tick.
            Ok(true) => parked.lock().push_back(stmt),
            // Finalised (committed/rolled back inside `resume_inflight`): drop `stmt` (closes egress).
            Ok(false) => finalized_any = true,
            // Panicked on this resumed batch (`rmp` #485 B2): roll the txn back, deliver a terminal
            // FAILURE to the consumer, then drop `stmt` (closing its egress). Ordering is rollback →
            // terminal error → drop, so the client sees a clean failure rather than a partial result
            // reported as a successful end-of-stream (the CWE-393 class). No terminal was sent before
            // the panic (it interrupts `drive_batch` at `next_materialized`, before any terminal send),
            // so this is the first and only terminal item. Covers a per-row execution panic AND a
            // commit panic inside the resumed auto-commit's `finalize_inflight` — both surface here.
            Err(panic_payload) => {
                recover_panicked_resume(
                    coord,
                    open,
                    txn,
                    metrics,
                    db,
                    degraded,
                    panic_payload.as_ref(),
                );
                stmt.deliver_terminal_error(GraphusError::Runtime(
                    "internal error: statement aborted (panic during resumed execution)".to_owned(),
                ));
                finalized_any = true;
            }
        }
    }
    if finalized_any {
        // A parked statement finalised/aborted — refresh the open-transaction gauge so observability
        // reflects it promptly (the threaded loop otherwise publishes only after a dispatched command).
        active_txns.publish(
            coordinator
                .as_deref()
                .map_or(0, TxnCoordinator::active_count),
            coordinator
                .as_deref()
                .map_or(0, TxnCoordinator::ssi_tracked_len),
        );
    }
}

/// Recovers from a panic caught while **resuming** a parked inline statement (`rmp` #485 B2), mirroring
/// [`rollback_panicked_statement`] for the resume path: roll the statement's transaction back (so no
/// half-applied write buffer survives — for a write that suspended mid-statement this discards the
/// partial buffer via ARIES undo), account the abort, and record the statement panic. The engine
/// thread stays alive.
///
/// The rollback runs through [`catch_recovery`] so a rollback that *itself* double-panics flags the
/// engine **degraded** (`rmp` #409) rather than unwinding the thread — identical to the first-visit
/// path. A panic *inside* `resume_inflight`'s own auto-commit (`finalize_inflight`'s `commit`) is
/// caught by the caller's boundary too and treated as a statement-level abort, exactly as the
/// first-visit inline path treats a commit panic (only the off-thread reader path flags degraded on a
/// commit panic).
///
/// This handles only the **coordinator-side** recovery (txn rollback + accounting). The caller
/// delivers the consumer-facing terminal FAILURE via
/// [`InFlightInline::deliver_terminal_error`](exec::InFlightInline) *after* this returns (rollback →
/// terminal error → drop), so the consumer sees an explicit error rather than a clean end-of-stream
/// over a partial result (`rmp` #485 B2).
fn recover_panicked_resume<D: BlockDevice, S: LogSink>(
    coord: &TxnCoordinator<D, S>,
    open: &EngineLatch<OpenTxTable>,
    txn: TxnId,
    metrics: &Metrics,
    db: &str,
    degraded: &EngineDegraded,
    panic_payload: &(dyn std::any::Any + Send),
) {
    let detail = panic_message(panic_payload);
    tracing::error!(
        target: "graphus::engine",
        panic = %detail,
        "inline statement panicked on a RESUMED batch; rolling back its transaction and keeping the \
         engine alive (rmp #386/#485 B2)",
    );
    // `InFlightInline.ticket` is private to `exec`; reverse-map txn → ticket via `open` (as
    // `maybe_reap_aged` does) so the open-tx entry is removed exactly once. Find and remove share ONE
    // critical section — together they are the claim — and the ARIES undo below runs outside it.
    {
        let mut open = open.lock();
        if let Some(ticket) = open.iter().find(|(_, t)| t.txn == txn).map(|(k, _)| *k) {
            open.remove(&ticket);
        }
    }
    recovery_rollback(
        coord,
        txn,
        metrics,
        degraded,
        db,
        "resumed statement rollback",
    );
    metrics.record_statement_panic();
}

/// Moves the statement THIS dispatch just suspended (if any) into the bounded `parked` queue (`rmp`
/// #485 B1). A newly-suspended statement is **appended** — it never overwrites an already-parked one
/// (the historical single-slot clobber bug). If the queue is at `max_parked` — a defense-in-depth
/// ceiling the upstream admission limit (`max_concurrent_queries`) normally keeps far out of reach,
/// since a parked statement holds its admission permit for its whole lifetime — the NEWCOMER (never an
/// already-parked statement) is rolled back and dropped, preserving all existing parked work.
#[allow(clippy::too_many_arguments)] // the engine loop threads its execution context through here
fn enqueue_suspended<D: BlockDevice, S: LogSink>(
    parked: &EngineLatch<VecDeque<exec::InFlightInline>>,
    just_suspended: &mut Option<exec::InFlightInline>,
    max_parked: usize,
    coordinator: &Option<Arc<TxnCoordinator<D, S>>>,
    open: &EngineLatch<OpenTxTable>,
    metrics: &Metrics,
    db: &str,
    degraded: &EngineDegraded,
) {
    let Some(stmt) = just_suspended.take() else {
        return; // the common case: the dispatch ran to completion / off-thread, nothing to park
    };
    // The capacity test and the push are ONE critical section: they are a check-then-act, and split in
    // two they stop bounding anything — W workers each read a length below the cap and each push, so
    // the queue overshoots by up to W. The statement is handed back out of the block when there is no
    // room, which is also how the latch is released before the overflow path below does real work.
    let overflowed = {
        let mut queue = parked.lock();
        if queue.len() < max_parked.max(1) {
            queue.push_back(stmt);
            return;
        }
        (stmt, queue.len())
    };
    let (stmt, parked_len) = overflowed;
    // Overflow — unreachable under correct admission. Roll back the NEWCOMER (never an existing parked
    // statement) so the bound holds without losing already-parked work, then deliver a clean retriable
    // FAILURE to its consumer (rollback → terminal error → drop) so it is reported as busy/aborted, not
    // a partial result over a successful end-of-stream (the CWE-393 class).
    let txn = stmt.txn();
    if let Some(coord) = coordinator.as_deref() {
        // Find + remove in one critical section (the claim); the undo runs with the latch released.
        // This is also the path whose *parked → open* order, against the age sweep's *open → parked*,
        // was the `rmp` #1038 ABBA — gone now that the queue is released before the table is touched.
        {
            let mut open = open.lock();
            if let Some(ticket) = open.iter().find(|(_, t)| t.txn == txn).map(|(k, _)| *k) {
                open.remove(&ticket);
            }
        }
        recovery_rollback(
            coord,
            txn,
            metrics,
            degraded,
            db,
            "overflow statement rollback",
        );
    }
    stmt.deliver_terminal_error(GraphusError::Runtime(
        "server busy: in-flight statement capacity reached, retry".to_owned(),
    ));
    tracing::warn!(
        target: "graphus::engine",
        parked = parked_len,
        "parked-inline-statement queue at capacity; rolled back a newly-suspended statement (rmp #485 \
         B1) — admission did not bound concurrency as expected",
    );
    drop(stmt);
}

/// Accounts one **failed** background maintenance checkpoint and escalates a persistent run of them
/// (`rmp` #394). Records the failure metric, bumps the consecutive-failure streak, and — once the
/// streak reaches [`MAINTENANCE_FAILURE_ESCALATION_THRESHOLD`] — flips the reclamation-degraded gauge
/// (driving `/health/ready` to `503`) and logs at `error`; a sub-threshold failure logs at `warn` and
/// does not escalate. Factored out of [`maybe_run_maintenance`] so the escalation decision is unit-
/// testable without a real failing coordinator.
fn record_maintenance_failure(
    consecutive_failures: &mut u32,
    metrics: &Metrics,
    maintenance_degraded: &MaintenanceDegraded,
    err: &dyn std::fmt::Display,
) {
    metrics.record_maintenance_failure();
    *consecutive_failures = consecutive_failures.saturating_add(1);
    if *consecutive_failures >= MAINTENANCE_FAILURE_ESCALATION_THRESHOLD {
        // Flag **this engine's own** reclamation degraded (`rmp` #435 — per-engine, not the shared
        // gauge, so one tenant's stall never marks the whole node not-ready).
        maintenance_degraded.set();
        tracing::error!(
            consecutive_failures = *consecutive_failures,
            "background maintenance checkpoint has failed repeatedly; reclamation is DEGRADED \
             (readiness now reports not-ready) — investigate storage/IO: {err}"
        );
    } else {
        tracing::warn!(
            consecutive_failures = *consecutive_failures,
            "background maintenance checkpoint failed (will retry): {err}"
        );
    }
}

/// Publishes a coordinator's lifetime index-collection totals (`rmp` #992). Both maintenance paths —
/// the background cadence and an operator `CHECKPOINT DATABASE` — run the same GC pass, so both
/// publish the same three numbers; this keeps that from being two copies of the same conversion.
fn publish_index_collection(metrics: &Metrics, db: &str, totals: &IndexCollectionTotals) {
    metrics.publish_index_collection_for(
        db,
        totals.entries_removed + totals.entities_purged,
        totals.keys_retained,
        totals.abandonments,
    );
}

/// Raises the `rmp` #809 durability alert for a GC report whose release-active freeze-frontier audit
/// found a stranded committed stamp. Increments `graphus_freeze_frontier_violations_total` and logs at
/// `error` with the exact offending store/id/stamps (the storage crate carries no logger, so it surfaced
/// the detail on the report). A no-op on the healthy path (`freeze_violations == 0`, every normal pass).
///
/// The GC pass has ALREADY taken the protective action — it skipped the registry prune, so every affected
/// committed writer stays resolvable and no committed version is forgotten (`RecordStore::gc`, `rmp`
/// #809). This is purely the observability half: it makes a freeze-frontier regression (the `rmp` #522
/// silent-committed-data-loss class) loud and alertable instead of silently degrading GC.
fn note_freeze_frontier_violations(metrics: &Metrics, report: &GcPassReport, db: &str) {
    if report.freeze_violations == 0 {
        return;
    }
    metrics.record_freeze_frontier_violations(report.freeze_violations);
    if let Some(v) = report.first_freeze_violation {
        tracing::error!(
            database = db,
            violations = report.freeze_violations,
            store = ?v.kind,
            record_id = v.id,
            xmin = format_args!("{:#018x}", v.xmin),
            xmax = format_args!("{:#018x}", v.xmax),
            "rmp #809 DURABILITY ALERT: the GC freeze-frontier audit found an in-use record still \
             bearing an unfrozen committed stamp before the registry prune (the rmp #522 \
             silent-committed-data-loss invariant). The pass SKIPPED the prune fail-closed, so no \
             committed data was lost, but the Active/Recent Transaction Table is no longer being pruned \
             — a freeze-frontier regression is live; investigate immediately."
        );
    }
}

/// **Test-only** (`rmp` #435, `internal-test-udf`): handles a [`EngineCommand::SimulateMaintenance`]
/// in the engine loop, driving the REAL per-engine escalation/clear path with this engine's own
/// `consecutive_failures` streak + [`MaintenanceDegraded`] flag, then returns `None` (the command was
/// consumed). Any other command is returned unchanged as `Some(cmd)` so the caller dispatches it.
///
/// In production (feature off) this compiles to a trivial identity (`Some(cmd)`), so the engine loop
/// is unchanged. The seam lets the multi-tenant isolation gate flag exactly one engine degraded
/// (and clear exactly one) without growing the WAL past [`MAINTENANCE_CHECKPOINT_INTERVAL_BYTES`].
#[cfg(feature = "internal-test-udf")]
fn intercept_simulate_maintenance(
    cmd: EngineCommand,
    consecutive_failures: &mut u32,
    metrics: &Metrics,
    maintenance_degraded: &MaintenanceDegraded,
) -> Option<EngineCommand> {
    match cmd {
        EngineCommand::SimulateMaintenance { fail, reply } => {
            if fail {
                // Mirror the background failure arm exactly: the real escalation sets THIS engine's
                // flag once the streak reaches the threshold.
                record_maintenance_failure(
                    consecutive_failures,
                    metrics,
                    maintenance_degraded,
                    &"simulated maintenance failure (test)",
                );
            } else {
                // Mirror the background success arm exactly: clear THIS engine's flag, reset the streak.
                metrics.record_maintenance_checkpoint(0, 0);
                maintenance_degraded.clear();
                *consecutive_failures = 0;
            }
            let _ = reply.send(Ok(maintenance_degraded.is_degraded()));
            None
        }
        other => Some(other),
    }
}

/// Production identity (`rmp` #435): the simulated-maintenance seam is compiled out, so the engine
/// loop dispatches every command unchanged.
#[cfg(not(feature = "internal-test-udf"))]
#[inline]
fn intercept_simulate_maintenance(
    cmd: EngineCommand,
    _consecutive_failures: &mut u32,
    _metrics: &Metrics,
    _maintenance_degraded: &MaintenanceDegraded,
) -> Option<EngineCommand> {
    Some(cmd)
}

/// Advances the front non-blocking index build by one [`INDEX_BUILD_CHUNK`] (`rmp` task #91). A
/// no-op when no build is pending. Kept tiny and inline-friendly so the loop's two call sites read
/// clearly.
fn drive_index_build<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    coordinator: &Option<Arc<TxnCoordinator<D, S>>>,
) {
    if let Some(coord) = coordinator.as_deref() {
        let _remaining = coord.advance_index_builds(INDEX_BUILD_CHUNK);
    }
}

/// Surfaces and repairs a **fail-closed** index set (`rmp` task #733), returning whether this call
/// actually repaired one (so the caller can invalidate the plan cache).
///
/// A fail-closed means a storage fault made the derived indexes untrustworthy, so the engine wiped them
/// and dropped every read path to the exact store scan. Answers stay **correct** — that is the whole
/// point of failing closed — which is precisely why it must not pass unnoticed: without a signal, a
/// degraded engine is indistinguishable from a healthy-but-slow one, and an operator (or an automated
/// readiness poll) would keep attributing scan latencies to indexes that are not being used.
///
/// So each new event is logged at `ERROR` and metered, and the rebuild is retried. The retry is bounded
/// and exponentially backed off inside the coordinator, so a persistently-faulting store cannot make the
/// engine thread re-scan the whole store on every tick.
/// The engine-loop-local edge detectors for [`maintain_degraded_indexes`].
///
/// Every index-health signal the engine reports is a *delta* against what it has already reported, so
/// each needs a "last seen" companion. Bundled into one struct rather than passed as loose `&mut`
/// arguments: the set grows every time a new degradation mode is made observable (`rmp` #733 → #780 →
/// #803), and a nine-argument function is both a clippy failure and genuinely easy to mis-order at the
/// call site, since several of them are `&mut u64`.
#[derive(Debug)]
struct IndexHealthSeen {
    /// Fail-closed events already reported (`rmp` #733).
    fail_closed: u64,
    /// Poisoned index builds already reported (`rmp` #733, M1).
    poisoned_builds: u64,
    /// VECTOR build-conflict entries already reported (`rmp` #780).
    vector_conflicts: u64,
    /// How many VECTOR indexes were blocked at the previous tick, for the recovery edge (`rmp` #780).
    vector_blocked: usize,
    /// Full-text/spatial marker poisonings already reported (`rmp` #803).
    ft_poison: u64,
    /// Whether the marker was poisoned at the previous tick, for the recovery edge (`rmp` #803).
    ft_poisoned: bool,
}

impl IndexHealthSeen {
    /// Seeds every detector from the coordinator's CURRENT state, so a freshly-opened engine whose
    /// open-time rebuild already failed closed (or already poisoned the marker) reports it on its first
    /// tick rather than treating the pre-existing condition as old news.
    fn seed<D: BlockDevice, S: LogSink>(coordinator: &TxnCoordinator<D, S>) -> Self {
        Self {
            fail_closed: coordinator.index_fail_closed_events(),
            poisoned_builds: coordinator.index_build_poison_events(),
            vector_conflicts: coordinator.vector_index_conflict_events(),
            vector_blocked: coordinator.blocked_vector_indexes(),
            ft_poison: coordinator.ft_spatial_poison_events(),
            ft_poisoned: coordinator.ft_spatial_poisoned(),
        }
    }
}

fn maintain_degraded_indexes<D: BlockDevice, S: LogSink>(
    coordinator: &Option<Arc<TxnCoordinator<D, S>>>,
    metrics: &Arc<Metrics>,
    db_name: &str,
    seen: &mut IndexHealthSeen,
) -> bool {
    let Some(coord) = coordinator.as_deref() else {
        return false;
    };
    // Report any VECTOR index that entered the `rmp` #780 blocked state since the last tick: its build
    // was cut short by an uncommitted writer, so it declines every k-NN to an exact brute-force scan.
    // Queries stay CORRECT — the scan is exact where the ANN is approximate — but they now cost
    // `O(covered entities x dim)`, and the index still reports `ONLINE`, so nothing else would ever
    // reveal it. Same reasoning as the fail-closed report below (`rmp` #733): a silent degradation is
    // indistinguishable from a healthy-but-slow engine.
    let conflicts = coord.vector_index_conflict_events();
    if conflicts > seen.vector_conflicts {
        let new = conflicts - seen.vector_conflicts;
        seen.vector_conflicts = conflicts;
        metrics.record_vector_index_conflicts(new);
        tracing::warn!(
            database = %db_name,
            events = new,
            total = conflicts,
            blocked = coord.blocked_vector_indexes(),
            "a VECTOR index build was cut short by an UNCOMMITTED writer holding the newest covered \
             embedding. Its k-NN answers stay CORRECT but now run as an exact O(entities x dim) \
             brute-force scan instead of an ANN descent, while SHOW INDEXES still reports ONLINE. It \
             repairs itself once every blocking transaction commits or rolls back — if this persists, \
             look for a long-running open transaction writing that property (rmp #780)."
        );
    }
    // And the recovery edge, so the WARN above is never left dangling with no resolution.
    let blocked = coord.blocked_vector_indexes();
    if blocked < seen.vector_blocked {
        tracing::info!(
            database = %db_name,
            blocked,
            "a VECTOR index was re-filled from committed state and is back on the ANN fast path \
             (rmp #780)"
        );
    }
    seen.vector_blocked = blocked;
    // Report a newly POISONED full-text/spatial marker (`rmp` task #803). While poisoned, every node
    // and relationship TEXT / FULLTEXT / SPATIAL seek in this database declines to the exact scan —
    // including the off-thread reader pool, so `executeRead` is not a workaround — while SHOW INDEXES
    // still reports ONLINE. Answers stay CORRECT; the index costs strictly more than not having one.
    // This went unnoticed to production-example scale (411 consecutive declines) precisely because
    // nothing reported it.
    let marker_poisons = coord.ft_spatial_poison_events();
    if marker_poisons > seen.ft_poison {
        let new = marker_poisons - seen.ft_poison;
        seen.ft_poison = marker_poisons;
        metrics.record_ft_spatial_poison(new);
        tracing::warn!(
            database = %db_name,
            events = new,
            total = marker_poisons,
            "the cross-snapshot full-text/spatial freshness marker was POISONED: a transaction that \
             removed or replaced an indexed posting rolled back, so the in-memory index may be missing \
             a committed entry. Every TEXT, FULLTEXT and SPATIAL seek now falls back to an exact full \
             scan (answers stay CORRECT but slower than having no index), while SHOW INDEXES still \
             reports ONLINE. The engine will rebuild the derived indexes to clear it (rmp #803)."
        );
    }
    // And the recovery edge, so the WARN above always resolves.
    let poisoned_now = coord.ft_spatial_poisoned();
    if seen.ft_poisoned && !poisoned_now {
        tracing::info!(
            database = %db_name,
            "the full-text/spatial freshness marker was cleared by a rebuild: TEXT, FULLTEXT and \
             SPATIAL seeks are back on the index fast path (rmp #803)"
        );
    }
    seen.ft_poisoned = poisoned_now;
    // Report any build POISONED since the last tick (`rmp` task #733, M1): a build a storage fault stopped
    // for good. Its index stays `Populating` — queries remain correct, on the exact scan — but it is not
    // being built, and that must not pass silently.
    let poisons = coord.index_build_poison_events();
    if poisons > seen.poisoned_builds {
        let new = poisons - seen.poisoned_builds;
        seen.poisoned_builds = poisons;
        metrics.record_index_builds_poisoned(new);
        tracing::error!(
            database = %db_name,
            events = new,
            total = poisons,
            parked = coord.poisoned_index_builds(),
            "an index build was stopped by a storage fault and PARKED. Its index stays POPULATING, so \
             queries remain CORRECT but run unaccelerated (full scans). The build will be resurrected \
             once the store reads cleanly again; investigate the storage device."
        );
    }
    // Resurrect parked builds once the store reads cleanly again. Called HERE, around the drain — never
    // inside `advance_index_builds`, where a build that failed again would be re-enqueued within the same
    // `while has_pending_index_builds()` loop and never let it terminate.
    if coord.retry_poisoned_index_builds() {
        tracing::warn!(
            database = %db_name,
            "a parked index build was resurrected: the store reads cleanly again (rmp #733)"
        );
    }
    // Report any fail-closed that happened since the last tick (an index rebuild — hence a fail-closed —
    // can be triggered by a DDL command, not just by this tick).
    let events = coord.index_fail_closed_events();
    if events > seen.fail_closed {
        let new = events - seen.fail_closed;
        seen.fail_closed = events;
        metrics.record_index_fail_closed(new);
        tracing::error!(
            database = %db_name,
            events = new,
            total = events,
            "a storage fault made the derived indexes untrustworthy: they were wiped FAIL-CLOSED. \
             Queries remain CORRECT but run unaccelerated (full scans), and the affected indexes now \
             report POPULATING rather than ONLINE. The engine will keep retrying the rebuild; \
             investigate the storage device."
        );
    }
    // `rmp` #803: a poisoned marker is repairable through the SAME driver, so this gate must admit it
    // — otherwise the widened trigger is unreachable from the threaded engine and only the inline one
    // repairs, which is the exact divergence `rmp` #780 found.
    if !coord.indexes_degraded() && !coord.ft_spatial_poisoned() {
        return false;
    }
    if coord.retry_degraded_index_rebuild() {
        tracing::warn!(
            database = %db_name,
            "the derived indexes were rebuilt successfully: the engine is no longer degraded (rmp #733)"
        );
        return true;
    }
    false
}

/// Invalidates the plan cache if an asynchronous index build completed since the previous tick
/// (`rmp` task #322). A build promoting `Populating`→`Online` makes [`TxnCoordinator::catalog`] start
/// exposing the new index, so any plan compiled before the promotion (which fell back to a scan) is
/// now stale and must be recompiled. Detected as a `true`→`false` transition of
/// [`has_pending_index_builds`](TxnCoordinator::has_pending_index_builds): when the last pending build
/// drains, bump the schema version. `builds_were_pending` is updated in place to track the edge.
fn invalidate_cache_on_build_completion<D: BlockDevice, S: LogSink>(
    coordinator: &Option<Arc<TxnCoordinator<D, S>>>,
    plan_cache: &EngineLatch<exec::EnginePlanCache>,
    builds_were_pending: &mut bool,
) {
    // The coordinator is asked FIRST, unlatched: `has_pending_index_builds` reads the build registry,
    // which is not the plan cache's business, and the latch is only needed for the bump it may lead to.
    let now_pending = coordinator
        .as_deref()
        .is_some_and(TxnCoordinator::has_pending_index_builds);
    if *builds_were_pending && !now_pending {
        // The last in-flight build just promoted to `Online`: the catalog changed, so invalidate.
        plan_cache.lock().bump_schema();
    }
    *builds_were_pending = now_pending;
}

/// The clean error a degraded engine returns to every request (`rmp` #409): a recovery double-panic
/// broke a deep in-memory invariant, so the engine refuses to execute over possibly-corrupt state. A
/// `Runtime`-class error so a client sees a definite failure (not a hang) and an orchestrator —
/// alerted via `/health/ready` `503` — can trigger a controlled restart.
fn engine_degraded_error() -> GraphusError {
    GraphusError::Runtime(
        "engine degraded: a statement-recovery rollback/commit panicked, so the in-memory state is no \
         longer trustworthy; the engine is refusing further work pending a controlled restart (rmp #409)"
            .to_owned(),
    )
}

/// Serves a clean **engine-degraded** error (`rmp` #409) for an executing/transactional command when
/// the engine has been flagged degraded by a recovery double-panic. Returns `None` once the command's
/// reply has been answered (handled — the caller keeps the loop alive without touching the suspect
/// coordinator), or `Some(cmd)` for the two control commands that must still run on a degraded engine —
/// `Shutdown` (so the engine can be drained + a restart proceed) and `Status` (a cheap probe) — which
/// the caller dispatches normally.
fn reply_engine_degraded(cmd: EngineCommand) -> Option<EngineCommand> {
    match cmd {
        // Control commands that must keep working so the node can be drained / probed / restarted.
        cmd @ (Cmd::Shutdown { .. } | Cmd::Status { .. }) => Some(cmd),
        // Test-only (`rmp` #435): a control-class driver; pass it through so the loop's intercept runs.
        #[cfg(feature = "internal-test-udf")]
        cmd @ Cmd::SimulateMaintenance { .. } => Some(cmd),
        Cmd::Begin { reply, .. } | Cmd::BeginAutoCommit { reply, .. } => {
            let _ = reply.send(Err(engine_degraded_error()));
            None
        }
        Cmd::Run { reply, .. } => {
            let _ = reply.send(Err(engine_degraded_error()));
            None
        }
        Cmd::Commit { reply, .. } => {
            let _ = reply.send(Err(engine_degraded_error()));
            None
        }
        Cmd::Rollback { reply, .. } => {
            let _ = reply.send(Err(engine_degraded_error()));
            None
        }
        Cmd::IndexDdl { reply, .. } | Cmd::ConstraintDdl { reply, .. } => {
            let _ = reply.send(Err(engine_degraded_error()));
            None
        }
        Cmd::Backup { reply, .. } => {
            let _ = reply.send(Err(engine_degraded_error()));
            None
        }
        Cmd::Checkpoint { reply, .. } => {
            let _ = reply.send(Err(engine_degraded_error()));
            None
        }
        Cmd::BulkImportBatch { reply, .. } => {
            let _ = reply.send(Err(engine_degraded_error()));
            None
        }
        Cmd::BulkImportModeBChunk { reply, .. } => {
            let _ = reply.send(Err(engine_degraded_error()));
            None
        }
    }
}

/// The whole mutable execution context [`process_command`] threads through per command (`rmp` #528).
///
/// Bundled into one struct rather than ~24 positional `&mut` arguments: the engine loop owns every
/// field and hands the whole context to `process_command`, which dispatches the command, coalesces any
/// group-commit batch, and runs the post-command maintenance/cache steps.
struct ProcessCtx<'a, D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static> {
    cmd: EngineCommand,
    /// The command channel, so a group-commit batch can non-blockingly drain further queued commits.
    rx: &'a std::sync::Mutex<std::sync::mpsc::Receiver<EngineCommand>>,
    coordinator: &'a mut Option<Arc<TxnCoordinator<D, S>>>,
    /// The LATCH, not a borrow of the table (`rmp` #1033): dispatching a command runs a statement,
    /// and holding the table across that is exactly what would serialise W workers. Each arm takes it
    /// for its own duration — an `O(1)` table operation for the short commands, and for `RUN` only at
    /// the two edges of the statement, never across it. Between `rmp` #1033 and #1038 that was the
    /// intent and not the code: `RUN` handed a *guard* to the executor, which held the table for the
    /// whole query. Since `rmp` #1041 the table behind it is the ENGINE's, so those critical sections
    /// are contended for real and their length is no longer a hypothetical.
    open: &'a EngineLatch<OpenTxTable>,
    /// THIS worker's ticket minter (`rmp` #1035) — the one piece of session state that must not be
    /// shared, because its residue class is what routes a session back to this worker.
    next_ticket: &'a TicketMinter,
    /// The ENGINE's plan cache (`rmp` #1041), so a DDL dispatched here invalidates the plans every
    /// other worker is serving and not only this one's.
    plan_cache: &'a EngineLatch<exec::EnginePlanCache>,
    extensions: &'a Arc<graphus_cypher::extension::ExtensionRegistry>,
    dispatch: &'a read_pool::ReadDispatch<D, S>,
    /// The ENGINE's reclamation state (`rmp` #1037): the shared in-flight reader count, the one ticket
    /// sequence the `rmp` #588 barrier's floor comes from, the single-flight gate every
    /// reuse-barrier-armed section takes, and the release floor nothing is freed below.
    reclaim: &'a EngineReclaim,
    /// The ENGINE's parked-statement queue (`rmp` #1041), so the age sweep sees every suspended cursor.
    /// A statement is still only ever RESUMED by the worker that owns its session.
    parked: &'a EngineLatch<VecDeque<exec::InFlightInline>>,
    max_parked_inline: usize,
    result_buffer_capacity: usize,
    metrics: &'a Arc<Metrics>,
    db: &'a Arc<str>,
    degraded: &'a EngineDegraded,
    maintenance_degraded: &'a MaintenanceDegraded,
    active_txns: &'a ActiveTxnGauge,
    clock: &'a Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    statement_timeout: Option<std::time::Duration>,
    loading_session: &'a mut Option<bulk_load::LoadingSession>,
    maintenance_consecutive_failures: &'a mut u32,
    builds_were_pending: &'a mut bool,
    /// A command a group-commit batch drain pulled but did not batch, stashed for the loop's next tick.
    pending_cmd: &'a mut Option<EngineCommand>,
    /// The dedicated WAL fsync thread the pipelined group-commit harden offloads each batch's
    /// `fdatasync` to (`rmp` #532). Lives for the engine's lifetime.
    wal_sync: &'a WalSyncThread,
    /// The off-thread reader retirement channel (`rmp` #336). Threaded in so [`pipelined_group_commit`]
    /// can release readers' GC-watermark pins BETWEEN hardened batches under a sustained write storm,
    /// instead of leaving them pinned until the engine loop's next top-of-tick sweep (`rmp` #583, F1b).
    retire_rx: &'a std::sync::Mutex<std::sync::mpsc::Receiver<read_pool::ReadRetirement>>,
    /// The server-wide live-transaction registry (`rmp` #637/#903): where a validating
    /// `CREATE CONSTRAINT` registers itself, so it is visible to `SHOW TRANSACTIONS` and stoppable by
    /// `TERMINATE TRANSACTIONS` for as long as its validation walk runs.
    transactions: &'a Arc<crate::txn_registry::TransactionRegistry>,
}

/// Processes one received [`EngineCommand`] end-to-end (`rmp` #528): dispatches it, coalesces a
/// group-commit batch if it PREPAREd a durable write commit, and runs the post-command maintenance /
/// plan-cache steps. Returns `false` once a [`EngineCommand::Shutdown`] has drained + hardened the
/// store (the loop then exits), `true` otherwise.
///
/// **Group commit (`04 §4.2`).** A `Cmd::Commit` for a durable write transaction is PREPAREd (SSI +
/// `COMMIT` record appended, no `fdatasync`) into a fresh `commit_batch` by [`dispatch_command`]. When
/// that happens, [`drain_commit_batch`] non-blockingly pulls further consecutive queued commits into the
/// same batch, and [`flush_commit_batch`] issues ONE `harden_wal` for all of them before acking — so `K`
/// concurrent committers pay one `fdatasync`, not `K`. The redo-bounding checkpoint is taken once, after
/// the acks ([`checkpoint_after_batch`]). Crucially, the maintenance sweep ([`maybe_run_maintenance`],
/// which can *reclaim* the WAL) runs only AFTER the batch is hardened + acked, so no durability watermark
/// is ever advanced over an un-`fdatasync`'d commit record.
fn process_command<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    ctx: ProcessCtx<'_, D, S>,
) -> bool {
    let ProcessCtx {
        cmd,
        rx,
        coordinator,
        open,
        next_ticket,
        plan_cache,
        extensions,
        dispatch,
        reclaim,
        parked,
        max_parked_inline,
        result_buffer_capacity,
        metrics,
        db,
        degraded,
        maintenance_degraded,
        active_txns,
        clock,
        statement_timeout,
        loading_session,
        maintenance_consecutive_failures,
        builds_were_pending,
        pending_cmd,
        wal_sync,
        retire_rx,
        transactions,
    } = ctx;

    // Whether a Mode A bulk-import loading session is active **before** this command is dispatched, so
    // the loading→not-loading edge (an `End` command) can be detected after dispatch to suppress the
    // maintenance GC pass that would otherwise block the following `Shutdown` (`rmp` #565, see
    // [`maybe_run_maintenance`]).
    let was_loading = loading_session.is_some();
    // A per-dispatch slot for the (at most one) statement THIS command suspends; drained into the bounded
    // `parked` queue below (`rmp` #485 B1). And a fresh, empty group-commit batch (`rmp` #528).
    let mut just_suspended: Option<exec::InFlightInline> = None;
    let mut commit_batch: Vec<PendingCommit> = Vec::new();
    if !dispatch_command(
        cmd,
        coordinator,
        open,
        next_ticket,
        plan_cache,
        extensions,
        dispatch,
        reclaim,
        &mut just_suspended,
        result_buffer_capacity,
        metrics,
        db,
        degraded,
        maintenance_degraded,
        active_txns,
        clock,
        statement_timeout,
        loading_session,
        &mut commit_batch,
        transactions,
    ) {
        return false; // Shutdown handled (drained + hardened) inside the dispatch.
    }

    // Group commit + **pipelining** (`rmp` #528 + #532): if this command PREPAREd a durable write
    // commit, coalesce further queued commits into the SAME batch, then harden the batch with the
    // pipelined split — `begin_harden` writes its records to the file and the `fdatasync` is offloaded
    // to `wal_sync` while the engine PREPAREs the NEXT consecutive batch (depth-1), then wait + complete
    // + ack (ack-after-fsync). The drain stashes the first non-commit command into `pending_cmd`
    // (processed next tick, in order).
    if !commit_batch.is_empty() {
        pipelined_group_commit(
            wal_sync,
            rx,
            coordinator,
            open,
            next_ticket,
            plan_cache,
            extensions,
            dispatch,
            reclaim,
            &mut commit_batch,
            pending_cmd,
            parked,
            max_parked_inline,
            result_buffer_capacity,
            metrics,
            db,
            degraded,
            maintenance_degraded,
            active_txns,
            clock,
            statement_timeout,
            loading_session,
            retire_rx,
            transactions,
        );
        // The redo-bounding checkpoint, once, AFTER every batch is acked (the commits are all durable).
        checkpoint_after_batch(coordinator);
    }

    enqueue_suspended(
        parked,
        &mut just_suspended,
        max_parked_inline,
        coordinator,
        open,
        metrics,
        db,
        degraded,
    );
    drive_index_build(coordinator);
    invalidate_cache_on_build_completion(coordinator, plan_cache, builds_were_pending);
    // The loading→not-loading edge (`rmp` #565): a bulk-import session that was active before this
    // command is now gone — this command was the `End`. On that edge `maybe_run_maintenance` re-anchors
    // its watermark and skips the O(N) GC pass so it cannot block the `Shutdown` a `STOP DATABASE` queues
    // right after `End` (the force-detach trigger).
    let loading_just_ended = was_loading && loading_session.is_none();
    // `rmp` #588 / `rmp` #1037: the barrier and the release threshold are BOTH derived inside
    // `maybe_run_maintenance` now, under the engine's reclaim gate — the barrier from the ENGINE's
    // ticket high-water rather than from a counter that dominates only the calling worker's tickets,
    // and the threshold from a sample of the open table taken for the same pass it is used for.
    maybe_run_maintenance(
        coordinator,
        reclaim,
        open,
        maintenance_consecutive_failures,
        metrics,
        db,
        maintenance_degraded,
        loading_session.is_some(),
        loading_just_ended,
    );
    true
}

/// Dispatches one [`EngineCommand`] against the coordinator. Returns `true` to keep the loop running,
/// `false` once a [`EngineCommand::Shutdown`] has drained + hardened the store (the loop then exits).
///
/// Factored out of [`run_engine_loop`] so the loop can choose its receive strategy (blocking vs.
/// build-driving timed receive) without duplicating the command-dispatch arm.
#[allow(clippy::too_many_arguments)] // The engine loop threads all execution context through here.
fn dispatch_command<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    cmd: EngineCommand,
    coordinator: &mut Option<Arc<TxnCoordinator<D, S>>>,
    // The LATCH (`rmp` #1033): this function runs statements, so it must be free to
    // release the table before execution rather than hold it across one.
    open: &EngineLatch<OpenTxTable>,
    next_ticket: &TicketMinter,
    plan_cache: &EngineLatch<exec::EnginePlanCache>,
    extensions: &Arc<graphus_cypher::extension::ExtensionRegistry>,
    dispatch: &read_pool::ReadDispatch<D, S>,
    reclaim: &EngineReclaim,
    inflight: &mut Option<exec::InFlightInline>,
    result_buffer_capacity: usize,
    metrics: &Arc<Metrics>,
    db: &str,
    degraded: &EngineDegraded,
    maintenance_degraded: &MaintenanceDegraded,
    active_txns: &ActiveTxnGauge,
    clock: &Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    statement_timeout: Option<std::time::Duration>,
    loading_session: &mut Option<bulk_load::LoadingSession>,
    // Group commit (`rmp` #528): a `Cmd::Commit` for a durable write transaction is PREPAREd (SSI +
    // `COMMIT` record appended, no `fdatasync`) and its deferred `(reply, commit_lsn)` pushed here
    // instead of replied inline; the caller drains more queued commits into the same batch and issues
    // ONE `harden_wal` for all of them (see `flush_commit_batch`). Read-only and SSI-aborted commits are
    // still answered immediately and never join the batch.
    commit_batch: &mut Vec<PendingCommit>,
    // The server-wide live-transaction registry (`rmp` #637/#903), for the one command that registers a
    // transaction of the engine's own: the validating `CREATE CONSTRAINT`.
    transactions: &Arc<crate::txn_registry::TransactionRegistry>,
) -> bool {
    // `rmp` #409 / #414: once a statement-recovery double-panic has flagged **this** engine degraded,
    // the coordinator's in-memory state can no longer be trusted (a deep storage/MVCC invariant broke).
    // Stop executing statements/transactions over it — serve each request a clean engine-degraded error
    // so a client sees a definite failure (not a hang, not `engine_gone` from a dead thread). The flag is
    // **per-engine** (`rmp` #414): a degraded secondary database refuses its own work while every other
    // database keeps serving (no shared-`Metrics` cross-database lockout). `Shutdown` and `Status` are
    // still honoured so this engine can be drained / probed and a controlled restart can proceed. The
    // engine thread itself stays alive (the loop keeps spinning); the per-engine flag drives
    // `/health/ready` to `503` for this database via the catalog's per-DB readiness aggregation.
    let cmd = if degraded.is_degraded() {
        match reply_engine_degraded(cmd) {
            // Handled: a clean engine-degraded error was delivered. Keep the loop alive.
            None => return true,
            // Pass-through (`Shutdown` / `Status`): continue to the normal dispatch below.
            Some(cmd) => cmd,
        }
    } else {
        cmd
    };
    let coord = coordinator
        .as_deref()
        .expect("INVARIANT: coordinator is Some until Shutdown breaks the loop");
    match cmd {
        Cmd::Begin { mode, reply } => {
            let ticket = open_tx(
                coord,
                open,
                next_ticket,
                reclaim,
                mode,
                false,
                clock.now_nanos(),
            );
            active_txns.publish(coord.active_count(), coord.ssi_tracked_len());
            let _ = reply.send(Ok(ticket));
        }
        Cmd::BeginAutoCommit { mode, reply } => {
            let ticket = open_tx(
                coord,
                open,
                next_ticket,
                reclaim,
                mode,
                true,
                clock.now_nanos(),
            );
            active_txns.publish(coord.active_count(), coord.ssi_tracked_len());
            let _ = reply.send(Ok(ticket));
        }
        Cmd::Run {
            ticket,
            query,
            params,
            auto_commit,
            privileges,
            timeout,
            reply,
        } => {
            // `rmp` task #386: isolate per-statement execution behind a panic boundary so a panic in
            // the executor / materializer / a UDF (or a `rayon`-propagated morsel/GDS worker panic,
            // which re-raises on *this* engine thread inside `handle_run`'s synchronous
            // `analytics_pool().install`) becomes a clean terminal statement error — never engine
            // death. `coord` is reborrowed from `coordinator` here so the borrow can be handed to the
            // catch handler for the rollback after `catch_unwind` consumes the closure's reborrow.
            let coord = coordinator
                .as_deref()
                .expect("INVARIANT: coordinator is Some until Shutdown breaks the loop");
            run_statement_isolated(
                coord,
                open,
                plan_cache,
                ticket,
                &query,
                params,
                auto_commit,
                privileges.map(|p| *p),
                extensions,
                dispatch,
                reclaim,
                inflight,
                result_buffer_capacity,
                metrics,
                db,
                degraded,
                clock,
                statement_timeout,
                timeout,
                commit_batch,
                reply,
            );
            active_txns.publish(coord.active_count(), coord.ssi_tracked_len());
        }
        Cmd::Commit { ticket, reply } => {
            // Group commit (`rmp` #528): PREPARE the commit (SSI + append `COMMIT`, no `fdatasync`) and
            // DEFER the ack into `commit_batch`; the caller hardens the whole batch with one sync and
            // then replies. A read-only or SSI-aborted commit is answered here and never batched.
            commit_prepare_tx(
                coord,
                open,
                ticket,
                reply,
                commit_batch,
                metrics,
                db,
                degraded,
            );
            active_txns.publish(coord.active_count(), coord.ssi_tracked_len());
        }
        Cmd::Rollback { ticket, reply } => {
            let out = rollback_tx(coord, open, ticket, metrics, db, degraded);
            active_txns.publish(coord.active_count(), coord.ssi_tracked_len());
            let _ = reply.send(out);
        }
        Cmd::Status { reply } => {
            let _ = reply.send(coord.active_count());
        }
        Cmd::IndexDdl { command, reply } => {
            let mutating = !matches!(command, IndexCommand::ShowIndexes { .. });
            let mut out = handle_index_ddl(coord, &command);
            // Invalidate the plan cache on a successful *mutating* index DDL (`rmp` task #322): a DROP
            // (and a fulltext/spatial CREATE, which is synchronous) changes the planner-visible catalog
            // immediately. A node-property CREATE only starts a `Populating` build whose later
            // promotion is caught by `invalidate_cache_on_build_completion`, but bumping here too is
            // harmless (it just recompiles against the unchanged catalog once) and keeps the rule
            // simple: any mutating DDL bumps the version.
            if mutating && out.is_ok() {
                plan_cache.lock().bump_schema();
            }
            // `rmp` #813: a schema DDL is a committing transaction, so — like a real Neo4j server — it
            // carries the DB's durable-write bookmark on its terminal `PULL` `SUCCESS`. A CREATE/DROP is
            // itself a durable catalog write (its commit advanced the high-water); a SHOW is a read that
            // observes it. The Bolt seam copies this onto the DDL result summary.
            if let Ok(reply_ref) = out.as_mut() {
                reply_ref.bookmark =
                    Some(exec::bookmark_token(db, coord.durable_write_commit_ts()));
            }
            let _ = reply.send(out);
        }
        Cmd::ConstraintDdl {
            command,
            principal,
            reply,
        } => {
            let mutating = !matches!(command, ConstraintCommand::Show { .. });
            let mut out = handle_constraint_ddl(
                coord,
                &command,
                transactions,
                db,
                principal.as_deref(),
                active_txns,
            );
            // A successful mutating constraint DDL changes the schema (a new/dropped unique/existence/
            // node-key/property-type rule) — invalidate so no plan compiled under the old schema is
            // reused (`rmp` task #322).
            if mutating && out.is_ok() {
                plan_cache.lock().bump_schema();
            }
            // `rmp` #813: a constraint DDL is a committing transaction — carry the DB's durable-write
            // bookmark on its terminal `PULL` `SUCCESS`, exactly as Neo4j does (the seam copies it onto
            // the summary). A CREATE/DROP constraint advanced the high-water; a SHOW observes it.
            if let Ok(reply_ref) = out.as_mut() {
                reply_ref.bookmark =
                    Some(exec::bookmark_token(db, coord.durable_write_commit_ts()));
            }
            let _ = reply.send(out);
        }
        Cmd::Backup { reply } => {
            let out = handle_backup(coord);
            let _ = reply.send(out);
        }
        Cmd::Checkpoint { reply } => {
            // `rmp` #588: an explicit `CHECKPOINT DATABASE` runs the same reader-unsafe GC reclaim as the
            // background cadence, so it must bracket the pass with the reuse barrier too — otherwise a
            // slot it frees could be reused while a concurrent off-thread reader walks a chain through it.
            //
            // `rmp` #1037: and it must take the engine's reclaim gate, for the same reason the cadence
            // does. The barrier is ONE shared atomic and every armed section disarms it on the way out,
            // so an operator checkpoint overlapping a background pass on another worker would leave that
            // pass's remaining frees unstamped. `enter_pass`, not `try_enter_pass`: an operator asked for
            // this pass and must get it, so it waits for the one in progress rather than declining.
            let out = {
                let _pass = reclaim.enter_pass();
                let reuse_barrier = reclaim.reuse_barrier();
                let oldest_open_ticket = open.lock().keys().copied().min().unwrap_or(u64::MAX);
                let out = handle_checkpoint(
                    coord,
                    reuse_barrier,
                    reclaim.in_pass_release_threshold(oldest_open_ticket),
                    metrics,
                    db,
                );
                reclaim.note_pass_finished();
                release_after_pass(coord, open, reclaim);
                metrics.publish_held_slots_for(db, coord.held_slots_len() as u64);
                out
            };
            // A manual (admin-triggered) checkpoint that succeeds is proof reclamation is making
            // progress again, so clear **this engine's own** maintenance-degraded flag (`rmp` #435 —
            // never another engine's). On failure the flag is left as-is (an operator's manual probe
            // does not escalate the background streak).
            //
            // `rmp` #694: it must ALSO be COUNTED. `graphus_maintenance_checkpoints_total` /
            // `_versions_reclaimed_total` / `_stamps_frozen_total` document themselves as "operator
            // `CHECKPOINT DATABASE` **+** the background cadence" (see `Metrics::render_prometheus`),
            // yet only the background cadence (`maybe_run_maintenance`) ever recorded into them — an
            // operator-triggered pass reclaimed slots and froze stamps completely invisibly. Those
            // counters are the ONLY server-side channel proving a `CHECKPOINT DATABASE` did any work
            // (an attached/remote instance exposes no `/proc` and no store files), so a counter frozen
            // at `0` while slots are demonstrably freed is a false negative on the signal operators
            // alert on. Record exactly what the cadence records, from the same `CheckpointReply`.
            // Regression: `graphus-server/tests/checkpoint_maintenance_metrics_694.rs`.
            if let Ok(summary) = &out {
                metrics
                    .record_maintenance_checkpoint(summary.reclaimed as u64, summary.frozen as u64);
                maintenance_degraded.clear();
            }
            // `rmp` #745: an operator checkpoint both APPENDS WAL (its checkpoint record) and RECLAIMS
            // sealed segments. Publish the resulting offset so `graphus_wal_bytes_written_total` is
            // current the instant `CHECKPOINT DATABASE` returns — an operator who checkpoints and then
            // scrapes must see the checkpoint's own WAL bytes, and must NOT see the counter dip because
            // segment files vanished. Safe here: the checkpoint has returned, so nothing holds a store
            // borrow or the WAL lock that `wal_durable_len()` re-takes.
            if let Some(coord) = coordinator.as_ref() {
                metrics.publish_wal_bytes_for(db, coord.wal_durable_len());
            }
            let _ = reply.send(out);
        }
        Cmd::BulkImportBatch { batch, reply } => {
            // `rmp` #588: a Mode A `End` runs `reclaim_after_bulk_load`'s GC reclaim, which — if the
            // target database carried pre-existing tombstones — frees record slots that a concurrent
            // off-thread reader could still be walking through. Bracket the batch with the reuse barrier
            // so any freed slot is shadow-held from reuse until predating readers retire (ingest itself
            // frees nothing, so the barrier only bites at the reclaiming `End`).
            //
            // `rmp` #1037: under the engine's reclaim gate, because the barrier it arms is the same one
            // atomic the maintenance cadence and `CHECKPOINT DATABASE` arm — two overlapping armed
            // sections and the first disarm silently unstamps the second's frees.
            let _pass = reclaim.enter_pass();
            let reuse_barrier = reclaim.reuse_barrier();
            let oldest_open_ticket = open.lock().keys().copied().min().unwrap_or(u64::MAX);
            coord.set_reuse_barrier(reuse_barrier);
            let out = bulk_load::handle_bulk_import_batch(coord, loading_session, batch);
            coord.set_reuse_barrier(None);
            reclaim.note_pass_finished();
            if reclaim.defers_release() {
                release_after_pass(coord, open, reclaim);
            } else {
                coord.release_reusable_slots(oldest_open_ticket);
            }
            let _ = reply.send(out);
        }
        Cmd::BulkImportModeBChunk {
            ticket,
            chunk,
            reply,
        } => run_mode_b_chunk_isolated(coord, open, ticket, chunk, metrics, db, degraded, reply),
        // Test-only (`rmp` #435): the threaded engine loop intercepts this before dispatch, so it only
        // reaches here on the `LocalEngine` inline path — drive the same real per-engine escalation.
        #[cfg(feature = "internal-test-udf")]
        Cmd::SimulateMaintenance { fail, reply } => {
            if fail {
                maintenance_degraded.set();
            } else {
                maintenance_degraded.clear();
            }
            let _ = reply.send(Ok(maintenance_degraded.is_degraded()));
        }
        Cmd::Shutdown { reply } => {
            // Test-only (`rmp` #450): simulate a wedged engine by blocking here before draining, so the
            // graceful-shutdown timeout gate can prove `stop_engine` force-detaches within its deadline.
            // Identity (zero-cost) in production.
            shutdown_hang_check();
            // Test-only (`rmp` #563): simulate a slow-but-*progressing* drain (heartbeating the beacon),
            // so the complementary gate can prove `stop_engine` does NOT force-detach a healthy engine.
            shutdown_progress_check(coord);
            // Drain stragglers through `&mut`, then consume the coordinator for the final flush. An
            // in-flight index build is left durably `Populating`: it resumes and completes on the
            // next open via `TxnCoordinator::new`'s crash-recovery path (no force-drain needed —
            // re-deriving the candidate index is cheap and always correct).
            drain_inflight(coord, open, metrics, db);
            let coordinator = coordinator
                .take()
                .expect("INVARIANT: coordinator is Some at Shutdown");
            // Sole ownership, asserted rather than assumed: the final flush consumes the coordinator,
            // so every worker must already have dropped its share. A live share here means a worker
            // outlived the shutdown barrier — the failure is loud instead of a silently skipped flush.
            let coordinator = Arc::try_unwrap(coordinator).unwrap_or_else(|_| {
                panic!(
                    "INVARIANT: every engine worker has dropped its coordinator share before the \
                     final flush (`rmp` #1033)"
                )
            });
            let (out, final_wal_len) = harden_store(coordinator);
            // `rmp` #745 — the one publish site that is required for CORRECTNESS, not freshness. The
            // final flush above appends WAL (its checkpoint record) AFTER the last commit's publish. If
            // those bytes were never published, a subsequent `START DATABASE` would re-baseline the fold
            // at the higher on-disk offset (`rebaseline_wal_bytes_for`) and they would be dropped from
            // the counter FOREVER — a permanent, silent, one-sided under-count, i.e. precisely the
            // disease this metric exists to cure. Publishing the post-flush offset closes that gap, so
            // the counter is continuous across a `STOP`/`START DATABASE` cycle.
            metrics.publish_wal_bytes_for(db, final_wal_len);
            // Retract this engine's whole contribution from the server-wide gauge (`rmp` #418); the
            // `ActiveTxnGauge` drop at loop exit would also do this, but publishing 0 here keeps the
            // gauge correct the instant the engine drains. The coordinator is consumed above, so its
            // retained-SSI count is now 0 too (`rmp` #591 D-#1).
            active_txns.publish(0, 0);
            let _ = reply.send(out);
            // Drained + durable: signal the loop to exit so the thread can join.
            return false;
        }
    }
    true
}

/// Runs one `Run` statement behind a **panic-isolation boundary** (`rmp` task #386), then applies its
/// [`exec::RunOutcome`] to the loop bookkeeping. This is the single production hardening that turns a
/// panic *anywhere* in synchronous statement execution — the executor, the materializer, a UDF, or a
/// `rayon`-propagated morsel/GDS worker panic (`rayon::install` re-raises a worker panic on the
/// **calling** thread, which is this engine thread) — into a clean terminal statement error while
/// keeping the engine loop alive. Without it, any such panic unwinds the engine thread, drops the
/// command `Receiver`, and every connection to this database gets `engine_gone` forever (`dbcatalog`
/// `stop_engine` only logs the corpse).
///
/// ## Unwind-safety justification (the load-bearing reasoning)
///
/// The closure captures `&TxnCoordinator` (and the open-tx map), which is `!UnwindSafe` because
/// the coordinator transitively holds `Rc<RefCell<…>>`. [`AssertUnwindSafe`] is sound here because we
/// **do not** observe any partially-mutated state across the boundary: on a caught panic we run
/// [`rollback_panicked_statement`], which calls [`TxnCoordinator::rollback`] (→ ARIES
/// `store.abort_writer` / `rollback`) on the statement's transaction, discarding the entire
/// half-applied write buffer and **restoring the durable store state via ARIES undo** regardless of
/// *where* mid-write the panic struck. No `RefCell` is left borrowed: the per-statement seam
/// ([`RecordStoreGraph`]) borrows the store only transiently *inside* each operation via RAII guards,
/// so unwinding drops every live `Ref`/`RefMut` before this frame regains control. No lock is poisoned
/// either: the coordinator's shared state lives behind `Rc<RefCell>` (single-thread, no `Mutex`), and
/// the rollback is the explicit recovery. The transaction is therefore left *rolled back*, never
/// half-applied.
///
/// ## What the rollback does and does NOT undo (`rmp` #410 — be precise)
///
/// [`coordinator::abort`](TxnCoordinator) rolls back the **durable store** (ARIES undo of the write
/// buffer) but does **not** undo the in-memory derived secondary indexes. Two index shapes behave
/// differently:
///
/// * **Insert-only candidate indexes** (the node-property index the planner actually uses) are
///   *candidate sources* reconciled by the executor's **query-time re-check** against the MVCC store,
///   so a stale entry left by an aborted write is dropped at read time — safe.
/// * **Membership-exact indexes** (bitmap, full-text, spatial) maintain themselves with a
///   *remove-then-reinsert* on a property change (`record_graph.rs`, `index_set.rs`, `fulltext.rs`),
///   so a panic *between* the remove and the reinsert could leave a committed node's entry **missing**.
///   This is **not** abort-undone today and is safe only because: (1) the **bitmap** index is not yet
///   wired into the planner (test-only consumers — see the warning at its seek consumers in
///   `index_set.rs`), so a missing bitmap entry is never read on a production plan; and (2) full-text /
///   spatial maintenance reaches that window only on allocation failure, which **aborts** (it does not
///   `panic`/unwind), so no production-reachable unwind strikes mid-reinsert. **Wiring bitmap into the
///   planner — or making membership-exact maintenance able to panic — requires either abort-undo of the
///   in-memory index or a dedicated panic-window regression test first.**
#[allow(clippy::too_many_arguments)]
fn run_statement_isolated<
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
>(
    coord: &TxnCoordinator<D, S>,
    // The LATCHES, never guards (`rmp` #1038). This function runs a whole query — compile, execute,
    // materialise, morsel, GDS — and the two tables it forwards are consulted for a handful of `O(1)`
    // operations at its edges. Taking them here, or receiving guards taken by the caller, would put the
    // entire query inside both critical sections; `exec::handle_run` takes each one where it uses it.
    open: &EngineLatch<OpenTxTable>,
    plan_cache: &EngineLatch<exec::EnginePlanCache>,
    ticket: TxTicket,
    query: &str,
    params: Vec<(String, Value)>,
    auto_commit: bool,
    privileges: Option<EffectivePrivileges>,
    extensions: &Arc<graphus_cypher::extension::ExtensionRegistry>,
    dispatch: &read_pool::ReadDispatch<D, S>,
    reclaim: &EngineReclaim,
    inflight: &mut Option<exec::InFlightInline>,
    result_buffer_capacity: usize,
    metrics: &Arc<Metrics>,
    db: &str,
    degraded: &EngineDegraded,
    clock: &Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    statement_timeout: Option<std::time::Duration>,
    // The caller's own budget for THIS statement (`rmp` #909) — the Bolt `tx_timeout` a client set on
    // its `BEGIN` / auto-commit `RUN`, already normalised. It can only tighten `statement_timeout`
    // (`exec::handle_run` takes the smaller of the two), never relax it.
    client_timeout: Option<std::time::Duration>,
    // Group commit (`rmp` #566): a durable auto-commit WRITE that finishes within its visit PREPAREs +
    // defers its ack into this batch (a clone of its egress sender held open until the batch harden),
    // instead of the pre-#566 inline `fdatasync` per statement — so concurrent auto-commit writers
    // coalesce onto one sync exactly as explicit committers do. `exec::finalize_inflight` pushes into it.
    commit_batch: &mut Vec<PendingCommit>,
    reply: command::Reply<std::result::Result<RunReply, GraphusError>>,
) {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    // THE rank-5 tripwire (`rmp` #1038), and note WHERE it is: immediately OUTSIDE the panic boundary
    // below. That boundary exists to turn a fault in the executor — a bug in a query's execution — into
    // a clean terminal error for that one statement. A latch held across a statement is not that: it is
    // an engine-discipline violation that would silently serialise every worker, and laundering it into
    // one client's error message is precisely how it would go unnoticed. Placed here rather than inside
    // `exec::handle_run` for the same reason, and only here, so the check has exactly one home and a
    // test that exercises it cannot be satisfied by a second copy.
    assert_no_engine_latch_held("run_statement_isolated");

    // A second handle on the same one-shot reply channel, kept *outside* the catch boundary so that a
    // panic *before* the executor delivered its reply can still hand the waiting consumer a clean
    // terminal error (rather than letting the connection hang on a dropped sender). If the executor
    // already replied, this fallback finds the capacity-1 buffer full and is a harmless no-op.
    let fallback = reply.fallback();

    let result = catch_unwind(AssertUnwindSafe(|| {
        exec::handle_run(
            coord,
            open,
            plan_cache,
            ticket,
            query,
            params,
            auto_commit,
            privileges,
            extensions,
            dispatch,
            // The engine's in-flight reader count (`rmp` task #575-g.1, `rmp` #1039). Handed over as the
            // COUNTER, not a snapshot of it: the dispatch site both sizes this read's adaptive morsel
            // width from it and counts this read into it, and the counting has to happen before the
            // submit — see its parameter docs in `exec::handle_run`.
            &reclaim.readers_inflight,
            result_buffer_capacity,
            metrics,
            db,
            degraded,
            clock,
            statement_timeout,
            client_timeout,
            commit_batch,
            reply,
        )
    }));

    match result {
        Ok(outcome) => match outcome {
            // A read dispatched off-thread retires later (it is not yet finalised). It was counted into
            // `readers_inflight` at the dispatch site rather than here (`rmp` #1039): the reader can
            // retire before this frame regains control, and since the retirement channel became the
            // engine's, the matching decrement can run on another worker — so an increment here could
            // land after it and be lost at zero.
            exec::RunOutcome::OffThreadReader => {}
            // The egress channel filled with a slow consumer draining (`rmp` task #372): hand the
            // suspended statement back through this dispatch's `inflight` slot. `inflight` is a
            // **per-dispatch** `Option` (a fresh `None` for each `Run`; the engine loop drains it into
            // its bounded `parked` queue, and the `LocalEngine` inline driver never suspends), so a
            // single `Run` parks at most one statement here — the assert holds trivially. Multiple
            // statements CAN be parked across dispatches; that breadth lives in the loop's bounded
            // `VecDeque`, never in this slot (`rmp` #485 B1 — the historical shared single slot here
            // silently clobbered an already-parked statement when a second one suspended).
            exec::RunOutcome::Suspended(parked) => {
                debug_assert!(
                    inflight.is_none(),
                    "INVARIANT: a single Run dispatch suspends at most one inline statement"
                );
                *inflight = Some(*parked);
            }
            // An inline statement that finished within its visit already committed/rolled back.
            exec::RunOutcome::Done => {}
        },
        Err(panic_payload) => {
            rollback_panicked_statement(
                coord,
                open,
                ticket,
                metrics,
                db,
                degraded,
                &fallback,
                &panic_payload,
            );
        }
    }
}

/// Runs one [`bulk_load_b::ingest_mode_b_chunk`] dispatch behind the **same panic-isolation
/// boundary** [`run_statement_isolated`] uses (`rmp` #386, reproduced here for `rmp` #520's Mode B
/// chunk command): a panic during row ingestion (a malformed value, an unexpected internal-state
/// corner case) becomes a clean terminal [`GraphusError`] instead of unwinding the single engine
/// thread. Unlike a `Run` statement's own auto-commit bookkeeping, a Mode B chunk never commits or
/// closes its ticket itself (see [`bulk_load_b`]'s module docs) — a caught panic therefore rolls the
/// **whole batch's transaction** back and removes its ticket from `open`, exactly mirroring what the
/// driver's own error path would have done via an explicit `Rollback`, so a panicked chunk can never
/// leave `ticket` open (leaking an SSI/lock/SIREAD footprint) or silently hang the waiting HTTP call.
#[allow(clippy::too_many_arguments)]
fn run_mode_b_chunk_isolated<
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
>(
    coord: &TxnCoordinator<D, S>,
    // The LATCH, not a guard (`rmp` #1038): a Mode B chunk ingests a whole batch of rows, and the
    // table is consulted only to resolve the ticket at the start and to claim the rollback on a panic.
    open: &EngineLatch<OpenTxTable>,
    ticket: TxTicket,
    chunk: bulk_load_b::BulkImportModeBChunkInput,
    metrics: &Metrics,
    db: &str,
    degraded: &EngineDegraded,
    reply: command::Reply<
        std::result::Result<bulk_load_b::BulkImportModeBChunkOutcome, GraphusError>,
    >,
) {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    // Outside the panic boundary, for the reason given in [`run_statement_isolated`]: ingesting a chunk
    // is work of unbounded duration and must not begin with an engine latch held (`rmp` #1038).
    assert_no_engine_latch_held("run_mode_b_chunk_isolated");
    let fallback = reply.fallback();
    let result = catch_unwind(AssertUnwindSafe(|| {
        bulk_load_b::ingest_mode_b_chunk(coord, open, ticket, chunk)
    }));

    match result {
        Ok(out) => {
            let _ = reply.send(out);
        }
        Err(panic_payload) => {
            let detail = panic_message(&*panic_payload);
            tracing::error!(
                target: "graphus::engine",
                ticket = ticket.0,
                panic = %detail,
                "bulk-import Mode B chunk panicked; rolling back its transaction and keeping the \
                 engine alive (rmp #386/#520)",
            );
            let claimed = open.lock().remove(&ticket.0);
            if let Some(tx) = claimed {
                recovery_rollback(
                    coord,
                    tx.txn,
                    metrics,
                    degraded,
                    db,
                    "mode-b chunk rollback",
                );
            }
            metrics.record_statement_panic();
            let _ = fallback.try_send_fallback(Err(GraphusError::Runtime(format!(
                "internal error: bulk-import Mode B chunk aborted ({detail})"
            ))));
        }
    }
}

/// Recovers from a statement panic caught in [`run_statement_isolated`] (`rmp` task #386): roll back
/// the statement's transaction so no half-applied write buffer survives, account the abort, and hand
/// the waiting consumer a clean terminal error so the connection is freed (never `engine_gone`).
///
/// The rollback is unconditional and idempotent: [`TxnCoordinator::rollback`] is a no-op for an
/// already-finalised / unknown txn (e.g. the panic happened after an auto-commit already committed, or
/// in an explicit transaction the connection will roll back itself), so this is always safe to call.
/// For an explicit (`BEGIN`) transaction it additionally undoes the in-flight statement's writes —
/// the connection's own later `ROLLBACK` would otherwise find the txn already gone; we remove the
/// ticket from `open` so that later `ROLLBACK` is the documented idempotent no-op.
#[allow(clippy::too_many_arguments)] // The recovery path threads its execution context here.
fn rollback_panicked_statement<D: BlockDevice, S: LogSink>(
    coord: &TxnCoordinator<D, S>,
    open: &EngineLatch<OpenTxTable>,
    ticket: TxTicket,
    metrics: &Metrics,
    db: &str,
    degraded: &EngineDegraded,
    fallback: &command::Reply<std::result::Result<RunReply, GraphusError>>,
    panic_payload: &(dyn std::any::Any + Send),
) {
    let detail = panic_message(panic_payload);
    tracing::error!(
        target: "graphus::engine",
        ticket = ticket.0,
        panic = %detail,
        "statement panicked; rolling back its transaction and keeping the engine alive (rmp #386)",
    );
    let claimed = open.lock().remove(&ticket.0);
    if let Some(tx) = claimed {
        // Discard the entire half-applied write buffer (ARIES undo). A failure here is itself
        // best-effort: the txn is being torn down regardless and recovery would undo it anyway.
        //
        // `rmp` #409: the rollback is a fallible WAL-undo + buffer-pool-replay path that can *itself*
        // panic (the historical `store.rs` `RefCell`-double-borrow, the #359 pool replay class). That
        // recovery panic runs OUTSIDE `run_statement_isolated`'s `catch_unwind`, so without this guard
        // it would unwind the single engine thread — the exact `engine_gone`-forever failure #386 set
        // out to prevent, one panic deeper. Wrap it so a double-panic flags the engine degraded and
        // keeps the loop alive instead of killing the thread.
        // `Some(Ok(()))` = rollback ran and succeeded → account the abort. `Some(Err(_))` is benign
        // ONLY when the transaction is already resolved; one that left it open in the store flags the
        // engine degraded (`rmp` #955). `None` (a caught recovery double-panic) already flagged it
        // inside `catch_recovery`.
        recovery_rollback(coord, tx.txn, metrics, degraded, db, "statement rollback");
    }
    metrics.record_statement_panic();
    // Best-effort terminal error to the consumer (no-op if the executor already replied / consumer
    // gone). The error is an internal-error class so a client sees a clean, retriable failure.
    let _ = fallback.try_send_fallback(Err(GraphusError::Runtime(format!(
        "internal error: statement aborted ({detail})"
    ))));
}

/// Runs a **statement-recovery** rollback/commit (`f`) behind its own panic boundary (`rmp` #409).
///
/// The recovery rollback/commit invoked after a caught statement panic (or at reader retirement) is a
/// fallible WAL-undo + buffer-pool-replay path that can *itself* panic — and it runs OUTSIDE
/// [`run_statement_isolated`]'s `catch_unwind`, so an un-guarded recovery panic would unwind the single
/// engine thread and brick the database (`engine_gone` forever, the very failure `rmp` #386 fixed —
/// one panic deeper). This wraps it so:
///
/// * `Some(r)` — recovery ran without panicking; the caller applies its `Result` as usual.
/// * `None` — recovery **double-panicked**: a deep storage/buffer-pool/MVCC invariant is broken, so the
///   database's in-memory state can no longer be trusted. We do **not** unwind the engine thread.
///   Instead we account a recovery-panic metric and flip the engine-degraded gauge (driving
///   `/health/ready` to `503`, mirroring the `rmp` #394 reclamation-degraded pattern); the engine loop
///   stays alive and [`dispatch_command`] serves every subsequent request a clean engine-degraded
///   error rather than dying.
///
/// The handler is deliberately **allocation-light and infallible** so it cannot itself panic inside the
/// catch (the `label` is a `&'static str`, the metric writes are lock-free atomics, and the `tracing`
/// call borrows the caught message): a panic in the catch handler would re-introduce the very thread
/// death this guards against.
///
/// `AssertUnwindSafe` is sound here for the same reason as in [`run_statement_isolated`]: on a caught
/// recovery panic we observe **no** partially-mutated coordinator state — the engine is flagged degraded
/// and stops executing statements, so the possibly-inconsistent in-memory state is never read again on a
/// success path.
fn catch_recovery<R>(
    metrics: &Metrics,
    degraded: &EngineDegraded,
    label: &'static str,
    f: impl FnOnce() -> R,
) -> Option<R> {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    match catch_unwind(AssertUnwindSafe(|| {
        recovery_fault_check();
        f()
    })) {
        Ok(r) => Some(r),
        Err(payload) => {
            let detail = panic_message(payload.as_ref());
            tracing::error!(
                target: "graphus::engine",
                recovery = label,
                panic = %detail,
                "RECOVERY DOUBLE-PANIC: a statement-recovery {label} panicked — a deep storage/MVCC \
                 invariant is broken, flagging THIS database's engine DEGRADED (readiness now reports \
                 not-ready for this database); the engine stays alive but will serve an engine-degraded \
                 error until a controlled restart (rmp #409/#414)",
            );
            // Allocation-light, infallible: atomic stores only. Must never panic inside the catch.
            // The aggregate recovery-panic COUNTER stays on the shared `Metrics` (fleet telemetry), but
            // the GATING flag is **per-engine** (`rmp` #414) so only the affected database refuses work.
            metrics.record_engine_recovery_panic();
            degraded.set();
            None
        }
    }
}

/// Flags **this database's** engine degraded when a rollback returned an error and left the
/// transaction still OPEN in the store (`rmp` #955).
///
/// A rollback that fails part-way is not a tidy no-op: the WAL undo, the compensation replay and the
/// catalog reload are one indivisible repair, and the store cannot restart it from an arbitrary
/// mid-point. So [`RecordStore::rollback`](graphus_storage::RecordStore::rollback) keeps the
/// transaction in its active set, where every "is a writer holding uncommitted state?" gate — the
/// `rmp` #902 constraint-DDL guard above all — keeps answering *yes*. That is the honest answer, and
/// it is fail-safe, but it is also permanent: nothing will ever resolve that transaction. Continuing
/// to serve statements over such a store would be serving over data the engine has admitted it cannot
/// account for, so the database is taken out of rotation for a controlled restart, exactly as a
/// recovery double-panic does (`rmp` #409).
///
/// The flag is **per-engine** and never fleet-wide (`rmp` #414): one database's unfinishable undo must
/// not refuse work on its healthy neighbours.
///
/// The guard is [`TxnCoordinator::store_txn_unresolved`] and not "the rollback returned `Err`",
/// because the overwhelmingly common `Err` is the benign idempotent one — a rollback of a transaction
/// that was already committed, already rolled back, or never known — which leaves nothing unresolved
/// and must never degrade anything.
fn degrade_on_incomplete_undo<D: BlockDevice, S: LogSink>(
    coord: &TxnCoordinator<D, S>,
    txn: TxnId,
    degraded: &EngineDegraded,
    label: &'static str,
    error: &GraphusError,
) {
    if !coord.store_txn_unresolved(txn) {
        return; // Benign: an idempotent rollback of an already-resolved transaction.
    }
    tracing::error!(
        target: "graphus::engine",
        recovery = label,
        txn = txn.0,
        error = %error,
        "ROLLBACK LEFT A TRANSACTION HALF-UNDONE: the durable undo failed with the transaction still \
         open in the store, so its uncommitted writes are physically present and nothing will undo \
         them — flagging THIS database's engine DEGRADED (readiness now reports not-ready for this \
         database); the engine stays alive but will serve an engine-degraded error until a controlled \
         restart (rmp #955, mirroring rmp #409/#414)",
    );
    degraded.set();
}

/// Resolves a transaction whose **COMMIT failed** (`rmp` #955).
///
/// Every commit call site removes the transaction's ticket from `open` *before* asking the coordinator
/// to commit, and each of them documents its error arm as "an SSI serialization abort (or an inactive
/// txn): the coordinator already rolled it back". That is true of the SSI arm and only of the SSI arm.
/// `TxnCoordinator::commit_prepare` propagates a **storage** failure from
/// `RecordStore::commit_prepare` — a failed catalog checkpoint, a failed `COMMIT` append — with the
/// transaction deliberately left OPEN, because `rmp` #866 needs its count delta and schema undo log to
/// survive for the rollback that must follow. With the ticket already gone, no client `ROLLBACK` and no
/// inactivity sweep could ever reach it: the transaction stayed open forever, its rows physically
/// present, holding the `rmp` #902 constraint-DDL guard closed and the GC watermark pinned for the life
/// of the process. This is that rollback.
///
/// Guarded by [`TxnCoordinator::store_txn_unresolved`] so the SSI arm — which really has already rolled
/// back — is not rolled back twice, and so a transaction that was never active is left alone.
fn resolve_failed_commit<D: BlockDevice, S: LogSink>(
    coord: &TxnCoordinator<D, S>,
    txn: TxnId,
    degraded: &EngineDegraded,
    label: &'static str,
) {
    if !coord.store_txn_unresolved(txn) {
        return;
    }
    if let Err(e) = coord.rollback(txn) {
        degrade_on_incomplete_undo(coord, txn, degraded, label, &e);
    }
}

/// Runs a statement-recovery rollback behind [`catch_recovery`], accounts the abort on success, and
/// degrades the engine when the undo was left incomplete (`rmp` #955).
///
/// The three outcomes, and why each is handled as it is:
///
/// * `Some(Ok(()))` — the undo completed; account the abort.
/// * `Some(Err(e))` — the undo returned an error. Benign if the transaction was already resolved;
///   otherwise the store is left half-undone, so [`degrade_on_incomplete_undo`] takes this database
///   out of rotation.
/// * `None` — the undo **panicked**. [`catch_recovery`] has already flagged the engine degraded, and
///   the store has kept the transaction open across the unwind (the active-set entry is released only
///   after the last fallible step, so there is no half-released entry to repair).
fn recovery_rollback<D: BlockDevice, S: LogSink>(
    coord: &TxnCoordinator<D, S>,
    txn: TxnId,
    metrics: &Metrics,
    degraded: &EngineDegraded,
    db: &str,
    label: &'static str,
) {
    match catch_recovery(metrics, degraded, label, || coord.rollback(txn)) {
        Some(Ok(())) => metrics.record_abort_for(db),
        Some(Err(e)) => degrade_on_incomplete_undo(coord, txn, degraded, label, &e),
        None => {}
    }
}

/// Extracts a human-readable message from a caught panic payload (`rmp` task #386), covering the two
/// payload shapes the std panic hook produces (`&str` and `String`); anything else is reported
/// opaquely.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

/// Executes one index-DDL command against the coordinator's node-property index catalog (`rmp` task
/// #91). `CREATE` starts a non-blocking background build (returning promptly, no rows); `DROP`
/// removes the index (no rows); `SHOW INDEXES` lists every declared index with its build state.
///
/// Runs on the engine thread, so it may touch the coordinator directly. The non-blocking
/// `CREATE` is what keeps the engine responsive: it enqueues the build and returns, and the loop
/// drives the build between subsequent commands.
fn handle_index_ddl<D: BlockDevice, S: LogSink>(
    coordinator: &TxnCoordinator<D, S>,
    command: &IndexCommand,
) -> Result<IndexDdlReply> {
    // A synchronous index build (full-text, spatial, vector) scans the store, and `SHOW INDEXES`
    // renders the whole catalogue: neither belongs inside a rank-5 critical section (`rmp` #1038).
    assert_no_engine_latch_held("handle_index_ddl");
    match command {
        IndexCommand::CreateNodePropertyIndex {
            name,
            label,
            properties,
            if_not_exists,
        } => {
            // `mutated == false` is an idempotent `IF NOT EXISTS` no-op → the seam reports 0 added. The
            // coordinator entry point delegates arity-1 to the single-property path and builds a
            // standalone composite index for arity ≥ 2 (`rmp` task #657).
            let mutated = coordinator.begin_online_node_composite_index_named(
                name.as_deref(),
                label,
                properties,
                *if_not_exists,
            )?;
            Ok(IndexDdlReply::mutation(mutated))
        }
        IndexCommand::DropNodePropertyIndex { index, if_exists } => {
            // `mutated == false` is a no-op drop (missing index) → the seam reports 0 removed.
            let mutated = match index {
                // `DROP INDEX <name>` does not spell the index kind: resolve the (globally-unique)
                // name against the node, relationship and composite property index catalogs
                // (`rmp` tasks #646 / #657).
                NodePropertyIndexRef::Named(name) => {
                    coordinator.drop_property_index_by_name(name, *if_exists)?
                }
                // The by-target form is already idempotent (a no-op success on a missing target), so
                // `IF EXISTS` needs no extra handling here. A single-property tuple drops the
                // single-property index; a multi-property tuple drops the composite (`rmp` task #657).
                NodePropertyIndexRef::Target { label, properties } => match properties.as_slice() {
                    [property] => coordinator.drop_node_property_index(label, property)?,
                    _ => coordinator.drop_node_composite_index(label, properties)?,
                },
            };
            Ok(IndexDdlReply::mutation(mutated))
        }
        IndexCommand::ShowIndexes { filter, tail: _ } => {
            // The **unified** Neo4j-conformant listing (`rmp` task #660): the engine renders the FULL
            // column set (`index_show::COLUMNS_FULL`) for *every* index kind — node/relationship-property
            // and composite RANGE, FULLTEXT, POINT, and the two always-on token LOOKUP indexes —
            // filtered by `filter`. The seams then project to the default columns (a bare listing) or
            // re-run the `YIELD`/`WHERE`/`RETURN` `tail` (`index_show::finish`), exactly as
            // `SHOW CONSTRAINTS` does (`rmp` #653); the `tail` is read off the command by the seam.
            let sources = index_show::IndexSources {
                node_property: coordinator.list_node_property_indexes(),
                composite: coordinator.list_composite_indexes(),
                rel_property: coordinator.list_rel_property_indexes(),
                rel_composite: coordinator.list_rel_composite_indexes(),
                fulltext: coordinator.list_fulltext_indexes(),
                point: coordinator.list_point_indexes(),
                point_rel: coordinator.list_point_rel_indexes(),
                text: coordinator.list_text_indexes(),
                node_lookup_usable: coordinator.label_lookup_usable(),
                vector: coordinator.list_vector_index_listings(),
                constraints: coordinator.list_constraints(),
                // The in-flight / parked builds, so a `Populating` index reports its REAL
                // `populationPercent` rather than a constant 0.0 (`rmp` task #573).
                builds: coordinator.index_build_progress(),
            };
            let rows = index_show::build_rows(*filter, sources);
            Ok(IndexDdlReply {
                fields: index_show::COLUMNS_FULL
                    .iter()
                    .map(|c| (*c).to_owned())
                    .collect(),
                rows,
                mutated: false, // a SHOW is a read; the mutated flag is unused.
                bookmark: None, // stamped by the dispatch_command handler (`rmp` #813).
            })
        }
        IndexCommand::CreateRelPropertyIndex {
            name,
            rel_type,
            properties,
            if_not_exists,
        } => {
            // `mutated == false` is an idempotent `IF NOT EXISTS` no-op → the seam reports 0 added. The
            // coordinator entry point delegates arity-1 to the single-property relationship path and
            // builds a standalone composite relationship index for arity ≥ 2 (`rmp` task #666).
            let mutated = coordinator.begin_online_rel_composite_index_named(
                name.as_deref(),
                rel_type,
                properties,
                *if_not_exists,
            )?;
            Ok(IndexDdlReply::mutation(mutated))
        }
        IndexCommand::DropRelPropertyIndex { index, if_exists } => {
            // `mutated == false` is a no-op drop (missing index) → the seam reports 0 removed.
            let mutated = match index {
                RelPropertyIndexRef::Named(name) => {
                    coordinator.drop_rel_property_index_by_name(name, *if_exists)?
                }
                // The by-target form is already idempotent (a no-op success on a missing target). A
                // single-property tuple drops the single-property relationship index; a multi-property
                // tuple drops the composite relationship index (`rmp` task #666).
                RelPropertyIndexRef::Target {
                    rel_type,
                    properties,
                } => match properties.as_slice() {
                    [property] => coordinator.drop_rel_property_index(rel_type, property)?,
                    _ => coordinator.drop_rel_composite_index(rel_type, properties)?,
                },
            };
            Ok(IndexDdlReply::mutation(mutated))
        }
        IndexCommand::CreateFulltextIndex {
            name,
            entity,
            labels_or_types,
            properties,
            analyzer,
            if_not_exists,
        } => {
            // Validate the analyzer name against the supported set; an unknown one is a clear,
            // side-effect-free error (`rmp` task #72).
            let analyzer = graphus_cypher::Analyzer::from_name(analyzer).ok_or_else(|| {
                GraphusError::Compile(format!(
                    "unknown full-text analyzer {analyzer:?}; expected 'standard' or 'keyword'"
                ))
            })?;
            // `mutated == false` is an idempotent `IF NOT EXISTS` no-op → the seam reports 0 added;
            // otherwise a create (a re-declare replaces) mutates → 1 added (`rmp` tasks #72, #661, #663).
            // Route by entity: a node index builds non-blockingly; a relationship index builds
            // synchronously (`rmp` #663).
            let mutated = if entity.is_relationship() {
                coordinator.create_fulltext_rel_index(
                    name,
                    labels_or_types,
                    properties,
                    analyzer,
                    *if_not_exists,
                )?
            } else {
                coordinator.create_fulltext_index(
                    name,
                    labels_or_types,
                    properties,
                    analyzer,
                    *if_not_exists,
                )?
            };
            Ok(IndexDdlReply::mutation(mutated))
        }
        IndexCommand::DropFulltextIndex { name, if_exists } => {
            // `mutated == false` is an `IF EXISTS` no-op drop of a missing index → 0 removed; a missing
            // index without `IF EXISTS` is an error (`rmp` tasks #72, #661).
            let mutated = coordinator.drop_fulltext_index(name, *if_exists)?;
            Ok(IndexDdlReply::mutation(mutated))
        }
        IndexCommand::CreatePointIndex {
            name,
            entity,
            label,
            property,
            if_not_exists,
        } => {
            // A spatial index has no analyzer to validate (unlike the full-text index). Route by entity
            // (`rmp` task #664): a node index builds non-blockingly (`rmp` #98); a relationship index
            // builds synchronously-`Online` (like the relationship full-text / property indexes).
            // `mutated == false` is an idempotent `IF NOT EXISTS` no-op → 0 added; otherwise 1 added.
            let mutated = if entity.is_relationship() {
                coordinator.create_point_rel_index(name, label, property, *if_not_exists)?
            } else {
                coordinator.create_point_index(name, label, property, *if_not_exists)?
            };
            Ok(IndexDdlReply::mutation(mutated))
        }
        IndexCommand::DropPointIndex { name, if_exists } => {
            // `mutated == false` is an `IF EXISTS` no-op drop of a missing index → 0 removed; a missing
            // index without `IF EXISTS` is an error (`rmp` tasks #98, #661).
            let mutated = coordinator.drop_point_index(name, *if_exists)?;
            Ok(IndexDdlReply::mutation(mutated))
        }
        IndexCommand::CreateTextIndex {
            name,
            label,
            property,
            if_not_exists,
        } => {
            // A text (trigram) index is built synchronously (ending `Online`) like a composite / rel
            // index, so this returns once the build completes (`rmp` task #662). `mutated == false` is an
            // idempotent `IF NOT EXISTS` no-op → 0 added; otherwise 1 added.
            let mutated = coordinator.create_text_index(name, label, property, *if_not_exists)?;
            Ok(IndexDdlReply::mutation(mutated))
        }
        IndexCommand::DropTextIndex { name, if_exists } => {
            // `mutated == false` is an `IF EXISTS` no-op drop of a missing index → 0 removed; a missing
            // index without `IF EXISTS` is an error (`rmp` task #662).
            let mutated = coordinator.drop_text_index(name, *if_exists)?;
            Ok(IndexDdlReply::mutation(mutated))
        }
        IndexCommand::CreateVectorIndex {
            name,
            entity,
            label_or_type,
            property,
            dimensions,
            similarity,
            m,
            ef_construction,
            if_not_exists,
        } => {
            // A vector (HNSW) index is declared durably then built synchronously from the current data
            // (ending `Online`), routing to the #669 coordinator entry point (which auto-names when `name`
            // is `None`). `mutated == false` is an idempotent `IF NOT EXISTS` no-op → 0 added; otherwise 1
            // added (`rmp` task #671).
            let mutated = coordinator.begin_online_vector_index_named(
                name.as_deref(),
                *entity,
                label_or_type,
                property,
                *dimensions,
                *similarity,
                *m,
                *ef_construction,
                *if_not_exists,
            )?;
            Ok(IndexDdlReply::mutation(mutated))
        }
        IndexCommand::DropVectorIndex { name, if_exists } => {
            // `mutated == false` is an `IF EXISTS` no-op drop of a missing index → 0 removed; a missing
            // index without `IF EXISTS` is an error (`rmp` task #671).
            let mutated = coordinator.drop_vector_index(name, *if_exists)?;
            Ok(IndexDdlReply::mutation(mutated))
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
/// engine thread free of key material.
fn handle_backup<D: BlockDevice, S: LogSink>(
    coordinator: &TxnCoordinator<D, S>,
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
/// Touches the coordinator directly, between commands, never under a held statement seam.
fn handle_checkpoint<D: BlockDevice, S: LogSink>(
    coordinator: &TxnCoordinator<D, S>,
    reuse_barrier: Option<u64>,
    oldest_open_ticket: u64,
    metrics: &Metrics,
    db: &str,
) -> Result<CheckpointReply> {
    // `rmp` #588: reader-safe reclaim — shadow-hold freed slots from reuse while a predating off-thread
    // reader may still be walking a chain through them (see `TxnCoordinator::checkpoint_reader_safe`).
    let report = coordinator.checkpoint_reader_safe(reuse_barrier, oldest_open_ticket)?;
    // `rmp` #809: an operator `CHECKPOINT DATABASE` runs the same GC pass as the background cadence, so it
    // must raise the same freeze-frontier durability alert (the pass already skipped the prune fail-closed
    // if it fired). No-op on the healthy path.
    note_freeze_frontier_violations(metrics, &report, db);
    // `rmp` #992: an operator `CHECKPOINT DATABASE` runs the same pass, so it republishes the same
    // derived-index footprint gauge as the background cadence.
    metrics.publish_derived_index_entries_for(db, coordinator.derived_index_entries() as u64);
    publish_index_collection(metrics, db, &coordinator.index_collection_totals());
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
/// Runs on the engine thread, so it may touch the coordinator directly. Unlike index DDL
/// there is no non-blocking build: a uniqueness constraint's backing index is (re)built synchronously
/// inside `create_constraint`, which is acceptable because schema DDL is rare and serialised.
/// Maps a parsed [`CreateConstraint`]'s `(entity, kind)` pair onto the durable
/// [`ConstraintKind`] wire discriminant + optional type descriptor (`rmp` #638). Relationship
/// entities select the reserved relationship discriminants; node entities the original four.
fn constraint_storage_kind(
    create: &CreateConstraint,
) -> (
    ConstraintKind,
    Option<graphus_storage::ConstraintTypeDescriptor>,
) {
    let is_rel = create.entity.is_relationship();
    match (&create.kind, is_rel) {
        (ConstraintCreateKind::Unique, false) => (ConstraintKind::Unique, None),
        (ConstraintCreateKind::Existence, false) => (ConstraintKind::Existence, None),
        (ConstraintCreateKind::Key, false) => (ConstraintKind::NodeKey, None),
        (ConstraintCreateKind::PropertyType { declared_type }, false) => {
            (ConstraintKind::PropertyType, Some(declared_type.clone()))
        }
        (ConstraintCreateKind::Unique, true) => (ConstraintKind::RelUnique, None),
        (ConstraintCreateKind::Existence, true) => (ConstraintKind::RelExistence, None),
        (ConstraintCreateKind::Key, true) => (ConstraintKind::RelKey, None),
        (ConstraintCreateKind::PropertyType { declared_type }, true) => {
            (ConstraintKind::RelPropertyType, Some(declared_type.clone()))
        }
    }
}

fn handle_constraint_ddl<D: BlockDevice, S: LogSink>(
    coordinator: &TxnCoordinator<D, S>,
    command: &ConstraintCommand,
    transactions: &Arc<crate::txn_registry::TransactionRegistry>,
    db: &str,
    principal: Option<&str>,
    active_txns: &ActiveTxnGauge,
) -> Result<IndexDdlReply> {
    // A `CREATE CONSTRAINT` validates by walking every entity carrying the covered token — work of
    // unbounded duration, so no engine session latch may be held here (`rmp` #1038).
    assert_no_engine_latch_held("handle_constraint_ddl");
    match command {
        ConstraintCommand::Create(create) => {
            let (kind, descriptor) = constraint_storage_kind(create);
            let props: Vec<&str> = create.properties.iter().map(String::as_str).collect();
            // Register this DDL as a first-class live transaction (`rmp` task #903) for the whole of
            // its validate-and-declare run. Two operator-facing properties come from it:
            //
            // * `SHOW TRANSACTIONS` lists it while it runs, so schema work that reads user property
            //   values is no longer the one class of database activity an administrator cannot see;
            // * `TERMINATE TRANSACTIONS` can stop it, which matters because the validation walk is
            //   O(entities carrying the covered token) — a `CREATE CONSTRAINT` on a large label is a
            //   realistic runaway.
            //
            // Only `CREATE` is registered. `DROP` is a single catalogue write with no walk, and `SHOW`
            // is a read of the catalogue: neither can run long, and neither reads user data, so an entry
            // for them would be noise in an operator's listing rather than information.
            let guard = transactions.register_internal(
                db,
                principal,
                AccessMode::Write,
                graphus_cypher::CancellationToken::new(),
            );
            // The rendered statement, as the `currentQuery` column. Reuses the audit trail's own
            // renderer so an operator reads the same text in `SHOW TRANSACTIONS` and in the audit log,
            // with the same redaction applied.
            guard.set_current_query(&crate::audit::redact_constraint_detail(command));
            // The idempotent entry point (`rmp` #638) handles `IF NOT EXISTS` (equivalent existing →
            // no-op, `mutated == false`) and `OR REPLACE` (drop same-named then create) around the
            // synchronous validate-and-declare path.
            let outcome = coordinator.create_constraint_ddl_cancellable(
                &create.name,
                create.entity.covering_name(),
                &props,
                kind,
                descriptor,
                create.if_not_exists,
                create.or_replace,
                guard.cancellation(),
            );
            // A terminated DDL reports the registry's own wording, so an operator sees the same message
            // whichever kind of transaction they stopped. Only an ERROR is re-labelled: a DDL that had
            // already reached its uninterruptible tail committed, and reporting that as "terminated"
            // would tell the operator the opposite of what happened. The coordinator guarantees the
            // error case left no trace — no catalogue entry, no in-memory rule, no index rebuild, and no
            // entry in its active set or SSI tracker — so a terminated DDL and a refused one are
            // indistinguishable in their after-effects.
            let outcome = if outcome.is_err() && guard.is_terminated() {
                Err(crate::txn_registry::terminated_error())
            } else {
                outcome
            };
            // Deregisters the entry (RAII). Runs on every path out of this arm, including the error one.
            drop(guard);
            // Republish the true open-transaction / SSI-tracked counts. The DDL's own transaction is
            // registered in both while it runs (`rmp` task #903), and a successful one leaves a
            // committed entry in the SSI tracker until GC prunes it, so the gauges move here. The
            // counts are read AFTER the DDL, never anticipated: a DDL refused before it opened a
            // transaction must not be reported as having held one.
            active_txns.publish(coordinator.active_count(), coordinator.ssi_tracked_len());
            Ok(IndexDdlReply::mutation(outcome?))
        }
        ConstraintCommand::Drop { name, if_exists } => {
            // `mutated == false` is a no-op drop of a missing constraint → 0 removed. With `IF EXISTS`
            // a missing constraint is always a clean no-op; without it the current behaviour is
            // likewise lenient (a missing constraint is a no-op success — see `drop_constraint`).
            let _ = if_exists;
            let mutated = coordinator.drop_constraint(name)?;
            Ok(IndexDdlReply::mutation(mutated))
        }
        ConstraintCommand::Show { filter, tail: _ } => {
            // Render the Neo4j-5.x-faithful **full 10-column** row set (`rmp` task #653), filtered by the
            // requested kind filter. The `tail` (YIELD/WHERE) is handled by the seams, which re-run a
            // translated read query over these rows (or project to the 8 default columns for a bare
            // listing) — see `constraint_show`. The engine always produces the full shape.
            let rows = constraint_show::build_rows(coordinator.list_constraints(), *filter);
            let fields = constraint_show::COLUMNS_FULL
                .iter()
                .map(|c| (*c).to_owned())
                .collect();
            Ok(IndexDdlReply {
                fields,
                rows,
                mutated: false, // a SHOW is a read; the mutated flag is unused.
                bookmark: None, // stamped by the dispatch_command handler (`rmp` #813).
            })
        }
    }
}

/// Opens a transaction in the coordinator, tracks it, and returns its freshly-minted ticket.
///
/// `begin_nanos` is the **monotonic**-clock reading at open (`rmp` #395/#477): the coordinator stamps
/// the active entry with it so the engine's age sweep can reap a transaction whose lifetime exceeds the
/// configured cap. `auto_commit` records whether this transaction backs a single auto-commit statement
/// (excluded from the age sweep) or an explicit `BEGIN … COMMIT` (the sweep's target).
fn open_tx<D: BlockDevice, S: LogSink>(
    coordinator: &TxnCoordinator<D, S>,
    open: &EngineLatch<OpenTxTable>,
    next_ticket: &TicketMinter,
    // `rmp` #1037: the engine's reclamation state, for the OPENING guard below. A transaction is
    // "opening" from before its ticket exists until it is visible in `open`, and the reuse-barrier
    // release refuses to run while any transaction is in that state.
    reclaim: &EngineReclaim,
    mode: AccessMode,
    auto_commit: bool,
    begin_nanos: u64,
) -> TxTicket {
    // **The order of these three steps is the release rule's proof, and it was wrong** (`rmp` #1037).
    //
    // The `rmp` #588 reuse barrier releases a shadow-held slot once the OLDEST OPEN TICKET has passed
    // the mark, which is only sound if the open table is a complete census of everything that can walk
    // a chain. Two gaps had to close for that to be true, and `_opening` plus this ordering are what
    // close them.
    //
    // 1. `begin_at` registers the transaction in the active set WITH ITS SNAPSHOT. Minting after it —
    //    which is what this used to do — left a window in which a live MVCC snapshot existed and no
    //    ticket did, so `TicketSequencer::high_water` did not dominate it and the pass-end floor did
    //    not cover it. Minting FIRST makes "every snapshot that exists has a ticket at or below the
    //    high-water" a fact about this function rather than a claim about it.
    // 2. Between the mint and the insert the transaction is in NO table, so a concurrent
    //    `release_after_pass` on a sibling worker takes a minimum that does not see it — and if it is
    //    the only transaction, that minimum is `u64::MAX`, the threshold that releases EVERYTHING. The
    //    `_opening` guard is what makes that window visible: `EngineReclaim::release_threshold` holds
    //    everything while it is non-zero, so a census is only ever taken when it is complete.
    //
    // Neither gap could be reached at one worker, where opening and releasing are the same thread.
    let _opening = reclaim.opening();
    // `+ step` rather than `+ 1`: the ticket must stay in this worker's residue class, and it must
    // never be zero (an unused ticket value the tests rely on).
    let ticket = next_ticket.mint();
    // `begin_at` mints a transaction id, registers it with the SSI tracker and inserts it into the
    // active set — it descends through ranks 20 and below, and there is no reason for the engine's
    // table to be held while it does.
    let txn = coordinator.begin_at(mode.isolation(), begin_nanos);
    open.lock().insert(
        ticket,
        OpenTx {
            txn,
            mode,
            auto_commit,
        },
    );
    TxTicket(ticket)
}

/// Group-commit PREPARE of the explicit transaction `ticket` (`rmp` #528, `04 §4.2`): runs SSI
/// validation and appends the `COMMIT` record WITHOUT the `fdatasync`, then either answers the
/// committer immediately or defers its ack into `commit_batch` for the batch harden:
///
/// * **unknown/inactive ticket** → immediate `Err` (nothing was prepared).
/// * **SSI serialization abort** → the coordinator already rolled the pivot back; the committer gets
///   the retriable error immediately (an aborted pivot appended no record, so it NEVER joins a batch —
///   the inviolable invariant that an aborted transaction contributes no COMMIT record).
/// * **read-only commit** (`rmp` #529, nothing durable to harden) → immediate `Ok` (no `fdatasync`
///   needed, so no reason to make the client wait for the batch).
/// * **durable write commit** → `(reply, commit_lsn)` is pushed onto `commit_batch`; the reply is held
///   until [`flush_commit_batch`] has hardened a covering `fdatasync` (ack-after-fsync).
#[allow(clippy::too_many_arguments)] // the commit path threads its execution context here
fn commit_prepare_tx<D: BlockDevice, S: LogSink>(
    coordinator: &TxnCoordinator<D, S>,
    open: &EngineLatch<OpenTxTable>,
    ticket: TxTicket,
    reply: command::Reply<Result<RunSummary>>,
    commit_batch: &mut Vec<PendingCommit>,
    metrics: &Metrics,
    db: &str,
    degraded: &EngineDegraded,
) {
    // The removal is the claim on this commit, and the diagnosis of a ticket that is not there has to
    // share its critical section: `unknown_ticket_error` CONSUMES the reap record, so the failed remove
    // and the reason for it must be read as one step or a concurrent second attempt could take the
    // record and leave this one saying "never existed" about a transaction the age sweep stopped.
    let claimed = {
        let mut open = open.lock();
        match open.remove(&ticket.0) {
            Some(tx) => Ok(tx),
            None => Err(open.unknown_ticket_error(ticket.0, "COMMIT of transaction")),
        }
    };
    let tx = match claimed {
        Ok(tx) => tx,
        // The COMMIT twin of the unknown-ticket RUN in `exec.rs`: a permanent, NON-retryable client
        // fault (`rmp` #988), not a serialization abort. `unknown_ticket_error` separates the two
        // causes — a transaction the age sweep stopped (`TransactionTimedOut`, which says why) from
        // one that never existed or is already spent (`TransactionNotFound`).
        Err(e) => {
            let _ = reply.send(Err(e));
            return;
        }
    };
    // SSI validation plus a `COMMIT` record appended to the WAL — real work, run with the latch
    // released so a commit never stands between another worker and its own table lookup.
    match coordinator.commit_prepare(tx.txn) {
        // A durable write commit: defer the ack until the batch `fdatasync` covers `commit_lsn`. Mint
        // the causal bookmark now from the commit timestamp (`rmp` #807) — monotonic per database — and
        // carry it in the deferred reply so the `COMMIT` `SUCCESS` returns it once durable.
        Ok((commit_ts, Some(commit_lsn))) => commit_batch.push(PendingCommit::Explicit {
            reply,
            commit_lsn,
            bookmark: Some(exec::bookmark_token(db, commit_ts)),
        }),
        // A read-only commit (`rmp` #529): nothing was appended, so no sync is needed — ack now. It
        // still returns the DB's **durable-write** bookmark on its `COMMIT` `SUCCESS` (`rmp` #813) —
        // matching a real Neo4j server, which emits a bookmark for read transactions too. The token is
        // the monotonic `"<db>:<durable_write_commit_ts>"` high-water: it names an already-durable commit
        // and equals what a subsequent read returns absent a write, NOT this transaction's own
        // (phantom-ticked, `rmp` #529) `commit_ts` — so two read-only commits with no write between them
        // return the SAME bookmark.
        Ok((_commit_ts, None)) => {
            metrics.record_commit_for(db);
            let _ = reply.send(Ok(RunSummary {
                bookmark: Some(exec::bookmark_token(
                    db,
                    coordinator.durable_write_commit_ts(),
                )),
                ..RunSummary::default()
            }));
        }
        // An SSI serialization abort (or an inactive txn) has already been rolled back by the
        // coordinator; a STORE-level prepare failure has NOT, and this ticket is already out of `open`,
        // so nothing else ever would (`rmp` #955).
        Err(e) => {
            resolve_failed_commit(coordinator, tx.txn, degraded, "failed-commit rollback");
            metrics.record_abort_for(db);
            let _ = reply.send(Err(e));
        }
    }
}

/// Group-commit HARDEN + ACK (`rmp` #528, `04 §4.2`): issues ONE `harden_wal` (`fdatasync`) covering
/// every PREPAREd write commit in `batch`, then acknowledges each committer `Ok` — the ack-after-fsync
/// durability rule. Called when the command channel momentarily drains, when the batch reaches
/// [`MAX_COMMIT_BATCH`], or before the loop processes a non-commit command.
///
/// The single `harden_wal` `fdatasync`s the WAL's whole pending buffer — every batched `COMMIT` record
/// plus the data/catalog records that preceded them — so `K` concurrent committers are hardened by ONE
/// sync instead of `K`. A `harden_wal` **failure PANICS** (fsyncgate, `04 §4.9`): the whole batch fails
/// together and NONE of its members is acked, which is correct — recovery undoes any un-`fdatasync`'d
/// record, so there is no partial commit and no committer was ever told its (lost) commit succeeded.
///
/// The redo-bounding auto-checkpoint is deliberately NOT taken here (see
/// [`checkpoint_after_batch`]); it runs after the acks, because the commits are already durable and a
/// checkpoint only bounds later recovery redo.
fn flush_commit_batch<D: BlockDevice, S: LogSink>(
    coordinator: &Option<Arc<TxnCoordinator<D, S>>>,
    batch: &mut Vec<PendingCommit>,
    metrics: &Metrics,
    db: &str,
) {
    if batch.is_empty() {
        return;
    }
    let Some(coord) = coordinator.as_deref() else {
        // The coordinator was consumed (Shutdown). Unreachable in practice: `Shutdown` drains before
        // consuming and a commit batch is always flushed within the same loop iteration that filled it,
        // before any `Shutdown` is dispatched. Drop the deferred replies (their connections error out
        // cleanly on the dropped one-shot) rather than panic.
        batch.clear();
        return;
    };
    // ONE fdatasync hardens the whole pending buffer, making every batched COMMIT record durable. A
    // failure here PANICS (fsyncgate) — no committer below is acked, and recovery undoes the un-synced
    // tail, so the batch is lost WHOLE (never partially applied), matching what each committer was (not)
    // told.
    coord.harden_wal();
    ack_prepared_commits(coord.wal_durable_len(), batch, metrics, db);
}

/// **Pipelined** group-commit harden + ack (`rmp` #532, commit pipelining), the async-engine
/// counterpart of the inline [`flush_commit_batch`] (which the DST/`LocalEngine` driver keeps, for a
/// bit-identical synchronous replay). Depth-1: the `fdatasync` of the current batch is offloaded to
/// `wal_sync` while this thread PREPAREs the **next** consecutive commit batch, then it waits +
/// completes + acks.
///
/// # Per-batch phases
/// 1. **begin_harden** — [`TxnCoordinator::begin_harden_wal`] writes the batch's records to the log
///    file (advancing the WAL write frontier) WITHOUT `fdatasync`ing, returning the deferred job.
/// 2. **submit** — hand the job to `wal_sync` (the fsync runs off the engine thread).
/// 3. **overlap** — PREPARE the next consecutive commit batch ([`drain_commit_batch`], append-only,
///    so the WAL write frontier does NOT advance — preserving depth-1). Skipped once a non-commit
///    command has been stashed in `pending_cmd` (it must be processed before any later command).
/// 4. **wait** — [`WalSyncThread::wait`] blocks for the `fdatasync`; a failure PANICs (fsyncgate)
///    BEFORE any ack.
/// 5. **complete_harden** — [`TxnCoordinator::complete_harden_wal`] advances the durable watermark
///    (monotonic — race-free with an eviction's inline harden during the overlap, which shares the
///    same WAL manager lock).
/// 6. **ack** — acknowledge every committer of the just-hardened batch (ack-after-fsync).
///
/// # WAL-before-data during the overlap
/// Between phases 1 and 5 the WAL has `durable_len < written_len`. The buffer pool shares the same
/// [`WalManager`](graphus_wal::WalManager) via `SharedWal`, so an eviction that must write a data page
/// home whose `page_lsn` is in that window re-enters `ensure_durable` under the same lock and hardens
/// the written range inline — no home page is ever written over an un-synced WAL record.
#[allow(clippy::too_many_arguments)] // the engine loop threads its execution context through here
fn pipelined_group_commit<
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
>(
    wal_sync: &WalSyncThread,
    rx: &std::sync::Mutex<std::sync::mpsc::Receiver<EngineCommand>>,
    coordinator: &mut Option<Arc<TxnCoordinator<D, S>>>,
    // The latch: this path re-enters the dispatch (`rmp` #1033).
    open: &EngineLatch<OpenTxTable>,
    next_ticket: &TicketMinter,
    plan_cache: &EngineLatch<exec::EnginePlanCache>,
    extensions: &Arc<graphus_cypher::extension::ExtensionRegistry>,
    dispatch: &read_pool::ReadDispatch<D, S>,
    reclaim: &EngineReclaim,
    commit_batch: &mut Vec<PendingCommit>,
    pending_cmd: &mut Option<EngineCommand>,
    parked: &EngineLatch<VecDeque<exec::InFlightInline>>,
    max_parked_inline: usize,
    result_buffer_capacity: usize,
    metrics: &Arc<Metrics>,
    db: &str,
    degraded: &EngineDegraded,
    maintenance_degraded: &MaintenanceDegraded,
    active_txns: &ActiveTxnGauge,
    clock: &Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    statement_timeout: Option<std::time::Duration>,
    loading_session: &mut Option<bulk_load::LoadingSession>,
    retire_rx: &std::sync::Mutex<std::sync::mpsc::Receiver<read_pool::ReadRetirement>>,
    transactions: &Arc<crate::txn_registry::TransactionRegistry>,
) {
    // The current PREPAREd batch (batch K). First coalesce further queued commits into it, exactly as
    // the inline path did before hardening — so a burst that is all already-queued still forms ONE
    // batch. Skipped when a non-commit command was already stashed (ordering).
    let mut batch = std::mem::take(commit_batch);
    if pending_cmd.is_none() {
        drain_commit_batch(
            rx,
            coordinator,
            open,
            next_ticket,
            plan_cache,
            extensions,
            dispatch,
            reclaim,
            &mut batch,
            pending_cmd,
            parked,
            max_parked_inline,
            result_buffer_capacity,
            metrics,
            db,
            degraded,
            maintenance_degraded,
            active_txns,
            clock,
            statement_timeout,
            loading_session,
            transactions,
        );
    }

    while !batch.is_empty() {
        // If the coordinator was consumed (Shutdown) — unreachable here, a `Cmd::Commit` never
        // consumes it — drop the deferred replies rather than panic.
        let Some(coord) = coordinator.as_deref() else {
            batch.clear();
            return;
        };
        // (1) begin_harden + (2) submit: write the batch's records to the file, offload the fdatasync.
        let job = coord.begin_harden_wal();
        wal_sync.submit(job);

        // (3) OVERLAP: PREPARE the next consecutive commit batch while the fdatasync is in flight.
        // Only if the prior drain didn't stash a non-commit command (which must be processed first).
        let mut next_batch: Vec<PendingCommit> = Vec::new();
        if pending_cmd.is_none() {
            drain_commit_batch(
                rx,
                coordinator,
                open,
                next_ticket,
                plan_cache,
                extensions,
                dispatch,
                reclaim,
                &mut next_batch,
                pending_cmd,
                parked,
                max_parked_inline,
                result_buffer_capacity,
                metrics,
                db,
                degraded,
                maintenance_degraded,
                active_txns,
                clock,
                statement_timeout,
                loading_session,
                transactions,
            );
        }

        // (4) WAIT for the in-flight fdatasync (depth-1). PANICs on failure (fsyncgate) BEFORE any ack.
        let target = wal_sync.wait();
        // (5) complete_harden: advance the durable watermark (monotonic / race-free). (6) ack the batch.
        if let Some(coord) = coordinator.as_deref() {
            coord.complete_harden_wal(target);
            ack_prepared_commits(coord.wal_durable_len(), &mut batch, metrics, db);
        } else {
            batch.clear();
        }

        // Release off-thread reader GC-watermark pins BETWEEN hardened batches (`rmp` #583, F1b). Under a
        // sustained write storm this outer loop hardens batch after batch without returning to the engine
        // loop, so the loop's top-of-tick [`process_retirements`] would not run and any off-thread reader
        // (`rmp` #543) that finished mid-pipeline would keep pinning `oldest_active_snapshot` for the whole
        // storm — letting dead versions accumulate in proportion to its duration. Draining retirements here
        // finalises each finished reader (M1 merge + auto-commit) so its snapshot stops pinning the GC
        // watermark within one batch. Safe for the same reason the top-of-loop sweep is — this is exactly
        // that sweep at a finer granularity — and since `rmp` #1039 that reason is M1' rather than "the same
        // thread, in arrival order": a reader's merge only touches edges incident on that reader, so which
        // worker drains it, and in what order, is unobservable. See [`finish_reader`].
        process_retirements(
            retire_rx,
            coordinator,
            open,
            reclaim,
            metrics,
            db,
            degraded,
            active_txns,
        );

        // Resume PARKED slow-consumer statements BETWEEN hardened batches (`rmp` #593, sprint-52 F C-F2).
        // Symmetric to the `process_retirements` sweep above: under a sustained group-commit write storm
        // this outer loop hardens batch after batch without returning to the engine loop, so the loop's
        // top-of-tick [`resume_parked_statements`] would not run — a coexisting parked statement (an
        // auto-commit read that fell back inline on a full reader queue, an explicit-txn read, or a
        // `… RETURN`-bearing write whose consumer briefly filled its bounded egress) would starve for the
        // whole storm: its consumer stalled, its transaction's GC-pin held, and its per-statement deadline
        // unenforced (cooperative, checked only on resume). Resuming here delivers each parked statement's
        // next batch within one hardened batch. Safe: same engine worker thread; a statement that
        // re-suspends is pushed to the back and only gets its next batch on the following pass (its own
        // budget snapshot), so this never spins on one fast-refilling consumer. Same worker, so the
        // affinity test inside the pass admits exactly the statements this drain could have parked.
        resume_parked_statements(
            parked,
            coordinator,
            open,
            // The affinity comes from the minter rather than from a parameter of its own: the stride
            // that produced a ticket and the modulus that claims it must be one number, not two that a
            // future signature change could set apart.
            next_ticket.affinity(),
            extensions,
            metrics,
            db,
            degraded,
            clock,
            active_txns,
        );

        batch = next_batch;
    }
}

/// Acknowledges every PREPAREd committer in `batch` `Ok` once the group-commit harden has advanced the
/// durable watermark to `durable` past their `COMMIT` records — the ack-after-fsync durability rule,
/// shared by the inline [`flush_commit_batch`] and the [`pipelined_group_commit`] paths.
fn ack_prepared_commits(durable: u64, batch: &mut Vec<PendingCommit>, metrics: &Metrics, db: &str) {
    // Publish the WAL's absolute durable byte offset (`rmp` #745). This is the primary seam of
    // `graphus_wal_bytes_written_total`: EVERY durable commit — inline (`flush_commit_batch`) and
    // pipelined (`pipelined_group_commit`) alike — funnels through here, and `durable` is the offset
    // BOTH callers had to compute anyway (`coord.wal_durable_len()`) to enforce the ack-after-fsync gate
    // below. So the metric costs one relaxed load + one relaxed add per hardened BATCH (not per commit),
    // takes no lock, touches no WAL state, and is published only for bytes that are already
    // `fdatasync`-durable — it cannot run ahead of durability. Publishing here rather than per-commit
    // also means an empty batch is a no-op fold.
    metrics.publish_wal_bytes_for(db, durable);
    for pending in batch.drain(..) {
        // ALWAYS-ON ack-after-fsync gate (`rmp` #596; was a `debug_assert!`). The group-commit harden
        // MUST have advanced the durable watermark past every batched commit LSN before this committer is
        // acked. If not, the durable-watermark accounting is corrupt — fail CLOSED with a controlled
        // panic BEFORE any ack (exactly the fsyncgate posture: `04 §4.9`), never acknowledge a commit
        // that is not yet `fdatasync`-durable (false durability — the cardinal ACID violation). The
        // invariant holds by construction on every path (`target` = `written_len` at `begin_harden`;
        // `complete_harden` makes `durable_len ≥ target > every batched commit_lsn`); promoting it to an
        // always-on gate is the last-line guard that stops a future refactor from silently acking a
        // non-durable commit in a release build. It is exact integer arithmetic — no false positive — and
        // a controlled abort here is strictly safer than a false "committed" reply (which "drop without
        // ack" would wrongly signal for an auto-commit, whose channel-close IS its success signal).
        assert!(
            pending.commit_lsn().0 < durable,
            "INVARIANT VIOLATED (ack-after-fsync, rmp #528/#532/#566/#596): the group-commit harden did \
             NOT advance the durable watermark ({durable}) past batched commit LSN ({}) — refusing to \
             ack a non-durable commit",
            pending.commit_lsn().0
        );
        metrics.record_commit_for(db);
        // Explicit: send the one-shot `Ok`. Auto-commit (`rmp` #566): drop the held-open egress sender,
        // closing the channel — the consumer's ack-after-fsync end-of-stream. Both only now, after the
        // `fdatasync` above made `commit_lsn` durable.
        pending.ack();
    }
}

/// Non-blocking drain of consecutive queued **batchable** commands into the current group-commit batch:
/// explicit `Cmd::Commit`s (`rmp` #528) AND auto-commit `Cmd::Run`s (`rmp` #566). Each is dispatched via
/// [`dispatch_command`] into the SAME batch, so ONE later harden's `fdatasync` covers them all — the
/// coalescing that makes `K` concurrent committers pay one sync, not `K`. A `Begin`/`BeginAutoCommit`
/// transaction-open (the durability-inert ticket round-trip that precedes every auto-commit write) is
/// dispatched INLINE and the drain CONTINUES (`rmp` #570) — it appends nothing to the WAL and joins no
/// batch, so processing it here (rather than truncating the batch) keeps concurrent auto-commit writers
/// coalescing at `W > 4` instead of collapsing to ~1 commit per sync. Stops at [`MAX_COMMIT_BATCH`], at
/// the first OTHER non-batchable command (stashed into `pending_cmd` for the loop to process next — IN
/// ORDER, only after the batch is hardened and acked), or when `try_recv` reports the channel momentarily
/// empty / disconnected.
///
/// **Why auto-commit `Run`s are drained here (`rmp` #566).** An auto-commit write's execution and its
/// commit are the SAME command (a `Cmd::Run { auto_commit: true }`), unlike an explicit transaction whose
/// writes ran in earlier `Run`s and whose commit is a cheap standalone `Cmd::Commit`. So to coalesce
/// concurrent auto-commit writers the drain must EXECUTE each queued auto-commit `Run` (which, for a
/// durable write, PREPAREs + defers its ack into the batch via [`exec::finish_autocommit`]); accumulating
/// several before ONE harden is durability-equivalent to a single multi-write explicit transaction (many
/// un-synced writes then one `fdatasync`), a path the buffer pool's WAL-before-data eviction rule already
/// covers. A drained auto-commit read dispatches off-thread (it never joins the batch); a drained write
/// whose slow consumer fills its bounded egress **suspends** — it is parked (it has NOT committed, so it
/// never joined the batch) and finalised later on resume. Explicit (`auto_commit = false`) `Run`s are
/// NOT drained (they carry ongoing-transaction state) — they end the drain like any other command.
///
/// **Causal safety under Bolt pipelining.** Draining only *consecutive* batchable commands is safe: for
/// one to be immediately available here, that transaction's earlier commands sit EARLIER in the channel
/// and are therefore already processed. A non-batchable command ends the drain and is NEVER reordered
/// ahead of the batch (its predecessors were already ahead of it in channel order), so order is preserved.
#[allow(clippy::too_many_arguments)] // the engine loop threads its execution context through here
fn drain_commit_batch<
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
>(
    rx: &std::sync::Mutex<std::sync::mpsc::Receiver<EngineCommand>>,
    coordinator: &mut Option<Arc<TxnCoordinator<D, S>>>,
    // The latch, for the same reason as `dispatch_command` (`rmp` #1033).
    open: &EngineLatch<OpenTxTable>,
    next_ticket: &TicketMinter,
    plan_cache: &EngineLatch<exec::EnginePlanCache>,
    extensions: &Arc<graphus_cypher::extension::ExtensionRegistry>,
    dispatch: &read_pool::ReadDispatch<D, S>,
    reclaim: &EngineReclaim,
    commit_batch: &mut Vec<PendingCommit>,
    pending_cmd: &mut Option<EngineCommand>,
    parked: &EngineLatch<VecDeque<exec::InFlightInline>>,
    max_parked_inline: usize,
    result_buffer_capacity: usize,
    metrics: &Arc<Metrics>,
    db: &str,
    degraded: &EngineDegraded,
    maintenance_degraded: &MaintenanceDegraded,
    active_txns: &ActiveTxnGauge,
    clock: &Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    statement_timeout: Option<std::time::Duration>,
    loading_session: &mut Option<bulk_load::LoadingSession>,
    transactions: &Arc<crate::txn_registry::TransactionRegistry>,
) {
    // `rmp` #583 (F1): bound the drain by TOTAL commands processed as well as by batch size — reads and
    // transaction-opens are processed here without growing `commit_batch`, so `MAX_COMMIT_BATCH` alone
    // does not bound the drain length under a concurrent read/open burst (see `MAX_DRAIN_COMMANDS`).
    let mut processed = 0usize;
    while commit_batch.len() < MAX_COMMIT_BATCH && processed < MAX_DRAIN_COMMANDS {
        // Dequeue under the latch, act outside it: the batch this builds is committed with the
        // queue free, so another worker can keep serving while this one hardens.
        assert_no_engine_latch_held("group-commit batch drain");
        let received = {
            let guard = rx
                .lock()
                .expect("INVARIANT: the command-queue latch is not poisoned");
            guard.try_recv()
        };
        match received {
            // An explicit COMMIT (`rmp` #528) OR an auto-commit statement (`rmp` #566): dispatch it into
            // the SAME batch. An explicit `Commit` PREPAREs (cheap, never suspends). An auto-commit `Run`
            // EXECUTES then — if it is a durable write — PREPAREs + defers its ack into the batch; an
            // auto-commit read dispatches off-thread (never joins the batch); a write whose slow consumer
            // filled its bounded egress suspends and is parked below.
            Ok(
                cmd @ (Cmd::Commit { .. }
                | Cmd::Run {
                    auto_commit: true, ..
                }),
            ) => {
                processed += 1; // `rmp` #583 (F1): count every processed command toward the drain cap.
                let mut just_suspended: Option<exec::InFlightInline> = None;
                let _keep_running = dispatch_command(
                    cmd,
                    coordinator,
                    open,
                    next_ticket,
                    plan_cache,
                    extensions,
                    dispatch,
                    reclaim,
                    &mut just_suspended,
                    result_buffer_capacity,
                    metrics,
                    db,
                    degraded,
                    maintenance_degraded,
                    active_txns,
                    clock,
                    statement_timeout,
                    loading_session,
                    commit_batch,
                    transactions,
                );
                // Park a suspended auto-commit `Run` (slow consumer, `rmp` #372/#485) so the loop resumes
                // it — it has NOT committed (mid-stream), so it never joined the batch; its later resume
                // finalises it inline. A `Commit` never suspends, so this is a no-op for that arm.
                enqueue_suspended(
                    parked,
                    &mut just_suspended,
                    max_parked_inline,
                    coordinator,
                    open,
                    metrics,
                    db,
                    degraded,
                );
            }
            // A transaction-OPEN (`rmp` #570). An auto-commit write is TWO consecutive channel commands —
            // a `BeginAutoCommit` (the ticket round-trip) then the `Run` — so with `W` concurrent writers
            // the channel interleaves their `BeginAutoCommit`s BETWEEN batchable `Run`s. Treating a
            // `Begin`/`BeginAutoCommit` as non-batchable (stash + break) truncated the coalescing batch at
            // the first interleaved open and dropped the engine out of this pipeline loop back to the main
            // loop, which processed the queued opens ONE PER `recv` tick — the measured W>4 coalescing
            // COLLAPSE (batch ~3.7→~1.8, `fdatasync/commit` 0.27→0.55). A transaction-open is WAL-neutral
            // and durability-inert: it only allocates a ticket, opens an MVCC snapshot, and replies — it
            // appends NOTHING to the WAL and commits NOTHING. So it is dispatched INLINE here and the drain
            // KEEPS GOING, keeping the pipeline hardening back-to-back batches and promptly unblocking the
            // ticket-waiting writers (whose next `Run`s then flow back into a following batch).
            //
            // Ordering / causal safety is preserved: the open runs AFTER its channel-predecessors (already
            // in `commit_batch`) and BEFORE its successors (still queued), so global channel order among
            // processed commands is unchanged. Its MVCC snapshot is identical whether taken now or after
            // the batch's ack: the batch is already `commit_prepare`d (its writes are visible in the MVCC
            // timeline) and the ack is only the *client-facing* durability signal, which never alters
            // server-visible state. Any OTHER non-batchable command still stashes + breaks (below).
            Ok(cmd @ (Cmd::Begin { .. } | Cmd::BeginAutoCommit { .. })) => {
                processed += 1; // `rmp` #583 (F1): a processed inline open counts toward the drain cap too.
                let mut ignored: Option<exec::InFlightInline> = None;
                let _keep_running = dispatch_command(
                    cmd,
                    coordinator,
                    open,
                    next_ticket,
                    plan_cache,
                    extensions,
                    dispatch,
                    reclaim,
                    &mut ignored,
                    result_buffer_capacity,
                    metrics,
                    db,
                    degraded,
                    maintenance_degraded,
                    active_txns,
                    clock,
                    statement_timeout,
                    loading_session,
                    commit_batch,
                    transactions,
                );
                debug_assert!(
                    ignored.is_none(),
                    "a transaction-open (Begin/BeginAutoCommit) never suspends a statement"
                );
            }
            // A non-batchable command ends the drain: stash it so the loop processes it next, in order,
            // AFTER the batch is hardened + acked (never reordered ahead of the batch).
            Ok(other) => {
                *pending_cmd = Some(other);
                break;
            }
            // Channel momentarily empty, or all senders dropped (teardown): flush what we have.
            Err(_) => break,
        }
    }
}

/// Takes the redo-bounding auto-checkpoint once per drained group-commit batch (`rmp` #528), AFTER its
/// committers have been acknowledged by [`flush_commit_batch`]. The commits are already durable (the
/// batch `fdatasync` completed), so a checkpoint here only bounds later crash-recovery redo — it can
/// never affect the durability of the just-acked commits. A checkpoint failure is therefore
/// **non-fatal**: it is logged and retried on the next batch (or by the background maintenance cadence),
/// never turned into a spurious commit failure over already-durable data.
fn checkpoint_after_batch<D: BlockDevice, S: LogSink>(
    coordinator: &Option<Arc<TxnCoordinator<D, S>>>,
) {
    if let Some(coord) = coordinator.as_deref() {
        if let Err(e) = coord.checkpoint_if_due() {
            tracing::warn!(
                target: "graphus::engine",
                error = %e,
                "deferred group-commit checkpoint failed; the batch's commits are already durable, so \
                 this only defers redo bounding — will retry on a later batch (rmp #528)",
            );
        }
    }
}

/// Rolls back `ticket`. Idempotent: an unknown ticket is `Ok(())` (mirrors the REST seam contract),
/// so the inactivity sweep and an explicit rollback cannot race into a spurious failure.
///
/// A client-driven rollback whose durable undo fails leaves the transaction open in the store with
/// its writes physically present, exactly as a recovery-path one does — so it degrades this database's
/// engine on the same terms (`rmp` #955). The error is still returned to the client: it is a real
/// failure of the statement, not only of the engine.
fn rollback_tx<D: BlockDevice, S: LogSink>(
    coordinator: &TxnCoordinator<D, S>,
    open: &EngineLatch<OpenTxTable>,
    ticket: TxTicket,
    metrics: &Metrics,
    db: &str,
    degraded: &EngineDegraded,
) -> Result<()> {
    // The removal claims the rollback; the ARIES undo below is unbounded in the size of the write
    // buffer it discards and runs with the latch released.
    let claimed = open.lock().remove(&ticket.0);
    let Some(tx) = claimed else {
        // Idempotent no-op.
        return Ok(());
    };
    // The undo is a fallible WAL + buffer-pool path that PANICS on an `fdatasync` failure (`04 §4.9`).
    // Unguarded, that panic unwinds the single engine thread — `engine_gone` forever, the exact `rmp`
    // #386 failure the statement path is already protected from, reached through a client `ROLLBACK`
    // instead of through a statement. `catch_recovery` gives it the same boundary: the engine is
    // flagged degraded and the loop stays alive (`rmp` #955).
    match catch_recovery(metrics, degraded, "client rollback", || {
        coordinator.rollback(tx.txn)
    }) {
        Some(Ok(())) => {
            metrics.record_abort_for(db);
            Ok(())
        }
        Some(Err(e)) => {
            degrade_on_incomplete_undo(coordinator, tx.txn, degraded, "client rollback", &e);
            Err(e)
        }
        // The undo double-panicked; `catch_recovery` has already flagged the engine degraded.
        None => Err(engine_degraded_error()),
    }
}

/// Graceful-shutdown drain (`04 §9.4`), part 1: roll back every still-open transaction **of the
/// engine**. Uncommitted work is always safe to undo — recovery would undo it anyway — so a hard
/// deadline upstream can force this without risking durability.
///
/// "Of the engine" is the whole of `rmp` #1041 in three words. While the open-transaction table was
/// built per worker this drained the table of whichever worker received `Shutdown`, and reported
/// success having rolled back one of `W` workers' transactions — measured with
/// `graphus_transactions_aborted_total`, which the loop below increments once per rollback: one of
/// four at `W = 4`. Nothing became *corrupt* (no `COMMIT` record exists for an undrained transaction,
/// so ARIES undoes it on reopen), but the guarantee [`harden_store`] rests on — that a clean stop
/// leaves recovery nothing to do — was simply not true, and the next open silently paid for the undo.
fn drain_inflight<D: BlockDevice, S: LogSink>(
    coordinator: &TxnCoordinator<D, S>,
    open: &EngineLatch<OpenTxTable>,
    metrics: &Metrics,
    db: &str,
) {
    // Drain the whole table in ONE critical section and roll the stragglers back outside it. Draining
    // rather than iterating is what makes each undo a claim: this runs on the worker that intercepted
    // `Shutdown`, and by then every other worker has left the loop, but a drain states the exclusivity
    // instead of inheriting it from the shutdown barrier's current shape. No affinity test here, and
    // that is the point of the pass — the age sweep declines another worker's transaction because its
    // owner may be inside it, while here there is no owner left to be inside anything.
    let stragglers: Vec<OpenTx> = {
        let mut open = open.lock();
        let tickets: Vec<u64> = open.keys().copied().collect();
        tickets
            .into_iter()
            .filter_map(|t| open.remove(&t))
            .collect()
    };
    for tx in stragglers {
        // Best-effort: a rollback error on one straggler should not block hardening the rest.
        if coordinator.rollback(tx.txn).is_ok() {
            metrics.record_abort_for(db);
        }
    }
}

/// Graceful-shutdown drain (`04 §9.4`), part 2: consume the (now transaction-free) coordinator to
/// reclaim the store, then flush dirty pages home and `sync_all` the device (the buffer pool enforces
/// the WAL rule before each write-back). Runs on the dedicated engine thread, so the blocking sync is
/// off the runtime (`04 §9.1`). This is the durable, clean checkpoint the superblock reflects on
/// reopen — the store dropping afterwards releases the device + WAL file handles.
///
/// Returns the flush outcome AND the WAL's **final absolute durable byte offset** (`rmp` #745), read
/// after the flush and before the store drops — the last chance to observe it, since the sink is closed
/// on the next line. The caller folds it into `graphus_wal_bytes_written_total` so the bytes this final
/// flush appended are not lost to the next incarnation's fold baseline. The offset is read on the
/// failure path too: whatever the flush *did* harden before erroring is genuinely on disk and must be
/// counted (durability is unaffected either way — this is pure observability).
fn harden_store<D: BlockDevice, S: LogSink>(
    coordinator: TxnCoordinator<D, S>,
) -> (Result<()>, u64) {
    // Safe: `drain_inflight` left no open transaction — of ANY worker, since `rmp` #1041 made the
    // table it drains engine-wide — and no statement seam is live here, because the shutdown worker
    // only reaches this point once every other worker has left the loop.
    let store: RecordStore<D, S> = coordinator.into_store();
    let out = store.flush();
    // Safe: `flush` has returned, so nothing holds the WAL lock this re-takes (no re-entrancy).
    let wal_len = store.with_wal(|w| w.durable_len());
    (out, wal_len)
    // `store` drops here, closing the file-backed device and WAL sink cleanly.
}

/// The running engine: the client handle and the engine thread's join handle.
pub struct Engine {
    /// The shared, cloneable client every connection task uses.
    pub handle: EngineHandle,
    /// The engine worker threads, joined at shutdown (after [`EngineHandle::shutdown`] returns).
    ///
    /// A `Vec` since `rmp` #1033: the loop body is a worker body and the engine runs W of them over
    /// one command queue. Every one must be joined, and the shutdown path already guarantees the
    /// order — the worker handling `Shutdown` waits to be the last inside the loop.
    pub joins: Vec<std::thread::JoinHandle<()>>,
}

/// Spawns the engine on a dedicated OS thread, constructing the coordinator inside that thread from
/// the `Send` `build` closure, and returns the running [`Engine`] once startup succeeds.
///
/// ## Why the coordinator is built on the thread
///
/// **This used to be a necessity and is now a choice — read the difference before relying on it.**
///
/// Until `rmp` #1010, [`TxnCoordinator`] was `!Send`: it held its shared state in `Rc<RefCell<…>>`,
/// so it could not cross a thread boundary at all, and the only sound way to run it on a dedicated
/// thread was to construct it *there*, from `Send` ingredients (file paths, config). That constraint
/// is **gone**. The coordinator is `Send` (`crates/graphus-cypher/tests/coordinator_is_send_1010.rs`
/// asserts it), and [`RecordStore`] has been `Send + Sync` since `rmp` #337.
///
/// Build-on-the-thread is retained because it is still the right shape for two reasons that have
/// nothing to do with `Send`:
///
/// 1. **Startup failure reporting.** `build` does the whole
///    open-device → recover → open-WAL → `RecordStore::open` → `verify_on_open` → `TxnCoordinator::new`
///    sequence, and its `Result` (which is `Send`) comes back over a channel so `Server::run` can fail
///    startup cleanly on a corrupt store (`04 §4.6`/§4.8). Moving that work to the caller would hand
///    the caller a half-open store to unwind instead.
/// 2. **Ownership stays where the work is**, so no handle to the store escapes to a thread that has
///    no business flushing it.
///
/// What changes for `rmp` #975's later layers: N worker threads no longer need this closure dance.
/// They can share one `Arc<TxnCoordinator>` built once, here, and that is exactly what layer 7
/// (`rmp` #1016) does. Nothing in *this* function has to move for that to be possible — the type
/// boundary it was working around no longer exists.
///
/// The command channel is **bounded** by `engine_queue_capacity` (no unbounded channel on the
/// request path — `04 §9.3`). The thread name is `graphus-engine`.
///
/// `db_name` is the canonical database name this engine serves; it labels the per-database metric
/// series (`rmp` #463) so an operator can attribute transaction/latency/abort counts to a single tenant.
///
/// This convenience spawns an engine with **no per-statement timeout, no transaction-age cap, and no
/// egress-stall ceiling** (the prior behaviour); the production path uses [`spawn_engine_with_timeout`]
/// to install the configured per-statement CPU budget (`rmp` #476), age cap (`rmp` #477) and off-thread
/// reader egress-stall ceiling (`rmp` #591).
///
/// # Errors
/// Returns the spawn error if the OS thread cannot be created, or the `build` error (e.g. an
/// integrity-check failure) if the store cannot be opened/verified.
#[allow(clippy::too_many_arguments)] // Mirrors `spawn_engine_with_timeout`'s parameter list.
pub fn spawn_engine<D, S, B>(
    db_name: Arc<str>,
    build: B,
    engine_queue_capacity: usize,
    result_buffer_capacity: usize,
    reader_threads: usize,
    metrics: Arc<Metrics>,
    clock: Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    transactions: Arc<crate::txn_registry::TransactionRegistry>,
) -> Result<Engine>
where
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
    B: FnOnce() -> Result<TxnCoordinator<D, S>> + Send + 'static,
{
    spawn_engine_with_timeout(
        db_name,
        build,
        engine_queue_capacity,
        result_buffer_capacity,
        reader_threads,
        // `spawn_engine` keeps the historical single-worker engine; the multi-worker knob is opted
        // into through `spawn_engine_with_timeout` (`rmp` #1033).
        1,
        metrics,
        clock,
        None,
        None,
        None,
        transactions,
    )
}

/// How many engine retirement channels have been created in this process, ever (`rmp` #1039).
///
/// There must be exactly ONE per engine whatever `W` is; `tests/engine_shared_reader_pool_1039.rs`
/// asserts the delta across a spawn. See [`read_pool::pools_spawned`] for why this is a spawn counter
/// rather than a scan of the process's threads.
static RETIREMENT_CHANNELS_CREATED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Engine retirement channels created since the process started.
#[must_use]
pub fn retirement_channels_created() -> u64 {
    RETIREMENT_CHANNELS_CREATED.load(Ordering::Relaxed)
}

/// [`spawn_engine`] with an explicit per-statement execution **timeout** (`rmp` #476) and
/// maximum-transaction-age cap (`rmp` #477).
///
/// A finite `statement_timeout` installs a per-statement wall-clock deadline on the Cypher executor's
/// cancellation token, so a runaway query (a cartesian / variable-length-expansion bomb) is
/// cooperatively aborted instead of pinning the engine thread and starving co-tenants. A finite
/// `max_transaction_age` installs a background sweep that aborts any explicit transaction whose
/// lifetime exceeds it, freeing the MVCC GC watermark a long-running reader would otherwise pin
/// indefinitely (the idle-in-transaction DoS). A finite `egress_stall_timeout` bounds how long an
/// off-thread reader-pool read may block on a full result-egress channel with no progress before it is
/// aborted (releasing its GC-watermark pin + pool slot) — INDEPENDENTLY of `statement_timeout`, so a
/// stalled/zero-window consumer cannot pin a reader forever even when the per-statement timeout is
/// disabled (`rmp` #591 C-F1). Any `None` disables the respective guard (identical to [`spawn_engine`]).
///
/// # Errors
/// As [`spawn_engine`].
#[allow(clippy::too_many_arguments)] // engine sizing + clock + per-statement/per-transaction/egress budgets — all positional knobs
pub fn spawn_engine_with_timeout<D, S, B>(
    db_name: Arc<str>,
    build: B,
    engine_queue_capacity: usize,
    result_buffer_capacity: usize,
    reader_threads: usize,
    // How many engine WORKERS serve the command queues (`rmp` #1033).
    //
    // The maintenance cadence is NOT worker 0's. This said it was, and the code never made it so:
    // `maybe_run_maintenance` is called from the tail of `process_command`, which every worker runs.
    // What worker 0 owns is the IDLE TICK that drives index builds and the degraded-index / vector /
    // full-text repairs. Since `rmp` #1037 the cadence is single-flight over the engine's reclaim
    // gate, so a checkpoint or GC pass does happen once and not W times — by exclusion, which is
    // enforceable, rather than by a worker id, which was not.
    //
    // Session affinity now exists (`rmp` #1035): there is one queue PER WORKER and a session always
    // reaches the same one, because a shared queue does not preserve the order of one session's
    // commands. Measured before that landed: the multi-stream gate (`rmp` #907) with four workers
    // failed with `TransactionNotFound` on a `RUN` that followed its own session's `BEGIN`, and no
    // amount of latching underneath fixes it — the ordering came from having a single consumer. Both
    // reference engines reach the same conclusion by binding a session (Memgraph) or a transaction
    // (Neo4j) to a thread: the affinity IS the ordering.
    //
    // `admission.engine_workers` above one is nevertheless still refused by configuration — see
    // `Config::validate`, which lists what remains — because the multi-worker engine is not yet
    // certified (`rmp` #1034). This parameter is exercised above one by tests, which is what keeps
    // the path honest.
    engine_workers: usize,
    metrics: Arc<Metrics>,
    clock: Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    statement_timeout: Option<std::time::Duration>,
    max_transaction_age: Option<std::time::Duration>,
    egress_stall_timeout: Option<std::time::Duration>,
    transactions: Arc<crate::txn_registry::TransactionRegistry>,
) -> Result<Engine>
where
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
    B: FnOnce() -> Result<TxnCoordinator<D, S>> + Send + 'static,
{
    // ONE QUEUE PER WORKER (`rmp` #1035), not one shared queue. A shared queue does not preserve the
    // order of one session's commands — two consecutive ones can be dequeued by different workers —
    // and no latch underneath fixes that, because the ordering came from having a single consumer.
    // The handle routes a session always to the same worker, so the order is restored by
    // construction. The capacity is split across the queues so the engine's total admission is
    // unchanged, with a floor of one so a tiny configured capacity still yields a usable queue.
    let per_worker_capacity = (engine_queue_capacity / engine_workers.max(1)).max(1);
    let mut senders = Vec::with_capacity(engine_workers);
    let mut receivers = Vec::with_capacity(engine_workers);
    for _ in 0..engine_workers {
        let (tx, rx) = std::sync::mpsc::sync_channel::<EngineCommand>(per_worker_capacity);
        senders.push(tx);
        receivers.push(rx);
    }
    // No startup channel (`rmp` #1033): the coordinator is built HERE, before any worker exists, so
    // a build failure is simply this function's `Err`. The channel existed only to carry a `Send`
    // `Result` back out of the thread that built it — necessary while the coordinator itself could
    // not cross a thread boundary, which layer 7b ended.
    let loop_metrics = Arc::clone(&metrics);
    // This engine's OWN degraded flag (`rmp` #414): shared (cloned) between the engine thread's
    // recovery boundary (the sole writer) and the `EngineHandle` clones + `/health/ready` readers, so a
    // recovery double-panic confines the engine-degraded refusal to THIS database.
    let degraded = EngineDegraded::new();
    let loop_degraded = degraded.clone();
    // This engine's OWN maintenance/reclamation-degraded flag (`rmp` #394/#435): shared (cloned)
    // between the engine thread's maintenance pass (the sole writer) and the `EngineHandle` clones +
    // `/health/ready` readers, so a stalled-reclamation secondary database is surfaced as not-ready
    // for THAT database only — one tenant's stall never blanket-503s the node, and one engine's
    // checkpoint success never false-clears another's stall.
    let maintenance_degraded = MaintenanceDegraded::new();
    let loop_maintenance_degraded = maintenance_degraded.clone();
    // The drain-progress beacon (`rmp` #563): created here so BOTH the engine thread (which installs it
    // into the store and lets its long GC/flush loops heartbeat it) and the returned `EngineHandle`
    // (which `stop_engine` polls) share the SAME `AtomicU64`.
    let drain_progress = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let loop_drain_progress = Arc::clone(&drain_progress);
    // The coordinator is built ONCE, here, and shared. It used to be built inside the thread — the
    // comment said "so the coordinator itself never crosses the boundary", which was true while it
    // was `!Send`. Layer 7b made it `Send + Sync`, so the premise is gone and every worker can hold
    // a share of one coordinator instead of there being only one thread that may touch it.
    let coordinator = match build() {
        Ok(coordinator) => Arc::new(coordinator),
        // Startup failed (e.g. corrupt store): report it without spawning anything.
        Err(e) => return Err(e),
    };
    // The drain-progress beacon is installed once, on the shared coordinator.
    coordinator.set_drain_progress(loop_drain_progress);
    // The stop protocol, built HERE and shared by every worker (`rmp` #1036). It used to live in the
    // per-worker struct `run_engine_loop` constructs — so each worker counted itself plus W−1
    // phantoms, and the `Shutdown` barrier waited on a number nobody else could move.
    let stop = Arc::new(EngineStop::new(engine_workers));
    // The session state, built HERE for the same reason (`rmp` #1041): the open-transaction table, the
    // parked-statement queue and the plan cache describe the ENGINE, so a copy per worker gives W
    // partial answers and no whole one. `run_engine_loop` used to construct them, which is how the
    // `Shutdown` drain came to reach one worker's transactions and a `DROP INDEX` on one worker left
    // every other worker serving the plan it invalidated.
    let sessions = Arc::new(EngineSessions::new());
    // The reclamation state, built HERE and shared for the third time and the third reason
    // (`rmp` #1037): the `rmp` #588 reuse barrier, the ticket ORDER its floor is taken from, and the
    // maintenance cadence all describe the engine's ONE store. Seeded with the WAL length the store
    // opened at, so a freshly opened engine does not immediately fire a no-op pass — the seed used to
    // be taken independently by each worker, which is how the engine came to run W cadences.
    let reclaim = Arc::new(EngineReclaim::new(
        engine_workers,
        coordinator.wal_durable_len(),
    ));
    // The gauge folds, likewise once per engine (`rmp` #1041). They publish engine-wide counts, so W
    // folds of the same value inflate the server-wide series W-fold until it settles.
    let active_txns = Arc::new(ActiveTxnGauge::new(
        Arc::clone(&metrics),
        Arc::clone(&db_name),
    ));
    let index_builds = Arc::new(IndexBuildGauge::new(Arc::clone(&metrics)));
    // The ENGINE's off-thread reader pool and its ONE retirement channel (`rmp` task #336 Slice 3b-ii;
    // engine-wide since `rmp` #1039). Built here, beside the other structures that are the engine's
    // rather than a worker's, and for the same reason: built inside the worker loop it was built `W`
    // times, so an engine with `W` workers ran `W * reader_threads` reader threads — each pool sized as
    // if it were the only one — and `W` retirement channels. `reader_threads` is already auto-sized to
    // `min(cores, 16)`, so at `W = 8` on a 16-core host that is 128 reader threads for one database, and
    // the multi-writer measurement of `rmp` #1034 would have been of contention rather than of scale.
    //
    // Retirements come back on a channel of their OWN, not the command channel: keeping them separate
    // stops the workers' sender clones pinning the command channel open, and lets the loop tear the pool
    // down on a clean channel-close shutdown. The queue is bounded (`04 §9.3`); a full queue makes the
    // dispatch site fall back to running the read inline.
    RETIREMENT_CHANNELS_CREATED.fetch_add(1, Ordering::Relaxed);
    let (retire_tx, retire_rx) = std::sync::mpsc::channel::<read_pool::ReadRetirement>();
    let dispatch = Arc::new(read_pool::ReadDispatch::Threaded(
        read_pool::ReadPool::spawn(
            reader_threads,
            reader_threads.saturating_mul(8).max(16),
            egress_stall_timeout,
            retire_tx,
            Arc::clone(&metrics),
        ),
    ));
    // `Receiver` is `!Sync`, so the workers share it under a lock — the same shape their own command
    // queues already have. Whichever worker reaches it drains it; see `process_retirements`.
    let retire_rx = Arc::new(std::sync::Mutex::new(retire_rx));

    let mut joins = Vec::with_capacity(engine_workers);
    for (worker_id, rx) in receivers.into_iter().enumerate() {
        let db_name = Arc::clone(&db_name);
        let coordinator = Arc::clone(&coordinator);
        let stop = Arc::clone(&stop);
        let sessions = Arc::clone(&sessions);
        let reclaim = Arc::clone(&reclaim);
        let active_txns = Arc::clone(&active_txns);
        let index_builds = Arc::clone(&index_builds);
        let dispatch = Arc::clone(&dispatch);
        let retire_rx = Arc::clone(&retire_rx);
        // Its OWN queue: no latch, because no other worker reads it (`rmp` #1035).
        let rx = Arc::new(std::sync::Mutex::new(rx));
        let loop_metrics = Arc::clone(&loop_metrics);
        let loop_degraded = loop_degraded.clone();
        let loop_maintenance_degraded = loop_maintenance_degraded.clone();
        let clock = Arc::clone(&clock);
        let transactions = Arc::clone(&transactions);
        let join = std::thread::Builder::new()
            .name(format!("graphus-engine-{worker_id}"))
            // A large stack: query compile/execute recurses on AST depth (`rmp` #473). See
            // [`QUERY_ENGINE_STACK_SIZE`] — the default ~2 MiB stack overflows on a legal
            // at-the-limit query, and a stack overflow aborts the whole process.
            .stack_size(QUERY_ENGINE_STACK_SIZE)
            .spawn(move || {
                // `rmp` #973: the server's engine threads are deliberately OUTSIDE the deterministic
                // scheduler. Bringing them under it needs the blocking command/reply channels
                // handled first (a thread parked in `recv()` holding the execution token freezes the
                // run), which is its own task; the DST drives `LocalEngine` inline instead. Marked
                // explicitly so it never reaches a yield point unregistered.
                graphus_core::sched::exempt();
                run_engine_loop(
                    db_name,
                    coordinator,
                    rx,
                    stop,
                    sessions,
                    reclaim,
                    worker_id,
                    engine_workers,
                    result_buffer_capacity,
                    dispatch,
                    retire_rx,
                    loop_metrics,
                    loop_degraded,
                    loop_maintenance_degraded,
                    clock,
                    statement_timeout,
                    max_transaction_age,
                    // Bound on concurrently parked (suspended) inline statements (`rmp` #485 B1).
                    // Since `rmp` #1041 the queue is engine-wide, so this bounds the ENGINE rather
                    // than each worker — while the command queues it is derived from are
                    // `engine_queue_capacity / W` each. Total admitted work is unchanged; the parked
                    // ceiling is now tighter relative to admission at `W > 1`. It remains a
                    // defence-in-depth ceiling that correct admission keeps far out of reach, not a
                    // routine limit, so the tightening costs nothing that is reachable.
                    engine_queue_capacity,
                    active_txns,
                    index_builds,
                    transactions,
                );
            })
            .map_err(|e| {
                GraphusError::Storage(format!("spawning engine worker {worker_id}: {e}"))
            })?;
        joins.push(join);
    }
    // Release the spawner's own shares, so the retraction in each gauge's `Drop` runs when the LAST
    // WORKER exits rather than when this `Engine` value is eventually dropped. Holding one here would
    // keep a stopped engine's contribution standing in the server-wide gauges for as long as the
    // catalog kept the handle — the phantom-count failure the retraction exists to prevent.
    drop(active_txns);
    drop(index_builds);

    // Startup already succeeded: the coordinator was built above, before any worker existed, so
    // there is no thread whose startup result has to be waited for (`rmp` #1033).
    Ok(Engine {
        handle: EngineHandle::new(
            senders,
            metrics,
            degraded,
            maintenance_degraded,
            drain_progress,
        ),
        joins,
    })
}

#[cfg(test)]
mod ticket_affinity_1035 {
    use super::*;

    /// **A worker's tickets are exactly its residue class, and never zero.**
    ///
    /// This is what makes the handle's routing correct: it computes `ticket % W` and expects the
    /// owning worker back. If a minter ever handed out a ticket outside its class, the command would
    /// be routed to a worker that has never heard of that transaction — the `TransactionNotFound`
    /// that a shared queue produced before `rmp` #1035, arriving by a different road.
    #[test]
    fn every_ticket_names_its_own_worker() {
        const WORKERS: usize = 4;
        let seq = Arc::new(TicketSequencer::new(WORKERS));
        for worker_id in 0..WORKERS {
            let minter =
                TicketMinter::new(WorkerAffinity::new(worker_id, WORKERS), Arc::clone(&seq));
            for _ in 0..64 {
                let ticket = minter.mint();
                assert_ne!(
                    ticket, 0,
                    "ticket 0 is the unused value the open table relies on"
                );
                assert_eq!(
                    ticket as usize % WORKERS,
                    worker_id,
                    "worker {worker_id} minted {ticket}, which routes to worker {}",
                    ticket as usize % WORKERS
                );
            }
        }
    }

    /// **No two workers ever mint the same ticket.**
    ///
    /// Distinct residue classes give this for free — which is the reason to encode the worker in the
    /// ticket rather than keep a routing table beside it: uniqueness and routing come from one fact
    /// instead of two that could disagree.
    #[test]
    fn workers_never_collide() {
        const WORKERS: usize = 8;
        let seq = Arc::new(TicketSequencer::new(WORKERS));
        let minters: Vec<_> = (0..WORKERS)
            .map(|w| TicketMinter::new(WorkerAffinity::new(w, WORKERS), Arc::clone(&seq)))
            .collect();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..128 {
            for minter in &minters {
                assert!(
                    seen.insert(minter.mint()),
                    "two workers minted the same ticket"
                );
            }
        }
        assert_eq!(seen.len(), WORKERS * 128);
    }

    /// The single-worker case stays exactly what it was: stride 1, tickets 1, 2, 3, …
    #[test]
    fn one_worker_is_the_historical_sequence() {
        let minter =
            TicketMinter::new(WorkerAffinity::new(0, 1), Arc::new(TicketSequencer::new(1)));
        assert_eq!(
            (1..=5).map(|_| minter.mint()).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
    }

    /// **`rmp` #1037 GATE — a ticket's order is the ENGINE's, not its worker's.**
    ///
    /// `rmp` #1035's per-worker counters made ticket order meaningless across workers: a counter
    /// advances only when its own worker mints, so a busy worker's old ticket is numerically far above
    /// an idle worker's new one. Every consumer that compares two workers' tickets is then wrong, and
    /// two do — the `rmp` #588 reuse barrier and `oldest_open_ticket`.
    ///
    /// **Non-vacuity, measured.** Minting is deliberately interleaved unevenly (worker 0 mints a
    /// hundred times before worker 1 mints once), which is exactly the shape the old code got wrong.
    /// With `TicketSequencer::issue` reverted to `rmp` #1035's per-worker counters this fails:
    /// `ticket 261 from worker 1 does not follow 676`.
    #[test]
    fn issue_order_is_ticket_order_across_workers() {
        const WORKERS: usize = 4;
        let seq = Arc::new(TicketSequencer::new(WORKERS));
        let minters: Vec<_> = (0..WORKERS)
            .map(|w| TicketMinter::new(WorkerAffinity::new(w, WORKERS), Arc::clone(&seq)))
            .collect();
        let mut previous = 0u64;
        // A deliberately lopsided schedule: worker 0 races ahead, then a laggard mints.
        let schedule = (0..100)
            .map(|_| 0usize)
            .chain([1, 0, 0, 3, 2, 1, 1, 0, 3, 3, 2]);
        for worker in schedule {
            let ticket = minters[worker].mint();
            assert!(
                ticket > previous,
                "ticket {ticket} from worker {worker} does not follow {previous}: issue order must \
                 BE ticket order, else the reuse barrier's floor dominates only its own worker"
            );
            assert_eq!(ticket as usize % WORKERS, worker, "residue class lost");
            previous = ticket;
        }
    }

    /// **`rmp` #1037 GATE — the engine's high-water dominates every issued ticket.**
    ///
    /// This is the property the `rmp` #588 barrier is built on: `high_water + 1` must strictly exceed
    /// every ticket that can be open, whichever worker issued it. Checked after each mint, so a worker
    /// that has just taken the top slot of the current issue index is covered too.
    ///
    /// **Non-vacuity, measured.** With `TicketSequencer::issue` reverted to `rmp` #1035's per-worker
    /// counters, this gate fails — `issued ticket 676 exceeds the engine high-water …` — as does
    /// [`issue_order_is_ticket_order_across_workers`] (`ticket 261 from worker 1 does not follow 676`).
    #[test]
    fn the_high_water_dominates_every_workers_ticket() {
        const WORKERS: usize = 3;
        let seq = Arc::new(TicketSequencer::new(WORKERS));
        let minters: Vec<_> = (0..WORKERS)
            .map(|w| TicketMinter::new(WorkerAffinity::new(w, WORKERS), Arc::clone(&seq)))
            .collect();
        // Nothing issued yet: any barrier is above every (absent) ticket.
        let mut issued: Vec<u64> = Vec::new();
        for round in 0..20 {
            // An uneven schedule again: not every worker mints in every round.
            for (w, minter) in minters.iter().enumerate() {
                if (round + w) % 3 == 0 {
                    issued.push(minter.mint());
                }
            }
            let high_water = seq.high_water();
            for &ticket in &issued {
                assert!(
                    ticket <= high_water,
                    "issued ticket {ticket} exceeds the engine high-water {high_water}: the barrier \
                     derived from it would not hold that transaction's slots"
                );
            }
        }
    }
}

#[cfg(test)]
mod maintenance_tests {
    use super::*;

    /// `rmp` #588 (sprint-52 B1) GATE: the GC reuse barrier must **strictly exceed** the newest open
    /// transaction's ticket, and — at one worker — must be `None` when no off-thread reader is in
    /// flight.
    ///
    /// [`TicketSequencer::high_water`] is an upper bound an issued ticket may EQUAL, and
    /// [`RecordStore::release_held`] releases a slot held at barrier `b` once `oldest_open_ticket >= b`;
    /// if the barrier merely equalled the newest ticket, that reader — while it is the oldest open —
    /// would release the slot under its own feet and reopen #588. The `+ 1` (this test's invariant)
    /// makes `barrier > oldest_open_ticket` hold while the newest reader is still open. Gating on
    /// `readers_inflight` keeps `held_slots` empty on the inline/DST path (no off-thread reader),
    /// preserving the deterministic golden trace.
    #[test]
    fn gc_reuse_barrier_strictly_exceeds_the_newest_open_ticket() {
        // A reader holding the top ticket of the current issue index has ticket == high_water, and is
        // the newest — hence the oldest open when it is the only one. The barrier must be `> N`.
        for high_water in [1u64, 2, 7, 1000, u64::MAX - 1] {
            let barrier = gc_reuse_barrier(high_water, 1, 1).expect("a reader is in flight");
            assert!(
                barrier > high_water,
                "#588 off-by-one: barrier {barrier} must strictly exceed the newest open ticket \
                 {high_water}, else release_held frees the slot under the newest reader"
            );
        }
        // No off-thread reader in flight AT ONE WORKER => no hold (the inline/DST path stays
        // byte-identical, and `held_slots` stays empty).
        assert_eq!(gc_reuse_barrier(42, 0, 1), None);
        assert_eq!(gc_reuse_barrier(0, 0, 1), None);
        // Any positive reader count arms the barrier.
        assert_eq!(gc_reuse_barrier(5, 3, 1), Some(6));
    }

    /// **`rmp` #1037 GATE — above one worker the barrier is armed whether or not a reader is counted.**
    ///
    /// `readers_inflight` counts off-thread reads only. Above one worker a sibling runs
    /// explicit-transaction reads, writes and resumed parked batches INLINE against the same store, and
    /// the counter is incremented only after `try_submit` returns, so zero readers counted does not
    /// mean nobody is walking a chain. See [`gc_reuse_barrier`] for the three facts.
    #[test]
    fn above_one_worker_the_barrier_does_not_trust_the_reader_count() {
        for workers in [2u64, 4, 16] {
            assert_eq!(
                gc_reuse_barrier(42, 0, workers),
                Some(43),
                "at W = {workers} a pass with no COUNTED reader must still hold what it frees: a \
                 sibling worker executes statements inline against the same store"
            );
        }
        // And the single-worker gate is untouched by the same call.
        assert_eq!(gc_reuse_barrier(42, 0, 1), None);
    }

    /// **`rmp` #1037 GATE — the release floor, and why `0` is how it says "hold everything".**
    ///
    /// Non-vacuity is carried by the end-to-end gate in `tests/engine_reclaim_barrier_1037.rs`: with
    /// `release_threshold` forced to `0`, 3404 slots stayed shadow-held for a reader that had long
    /// since retired and the hold never opened.
    ///
    /// Above one worker a transaction opened WHILE a pass runs takes a ticket above that pass's
    /// barrier, so it holds nothing back — yet its read view can predate a free. The engine therefore
    /// records the ticket high-water at the END of the pass and releases nothing until the oldest open
    /// transaction has passed it. `0` is the threshold that releases nothing at all, because every
    /// barrier is `high_water + 1 >= 1`; expressing "hold everything" that way is what keeps the
    /// storage layer ignorant of how many workers the engine runs.
    #[test]
    fn the_release_floor_holds_everything_until_the_pass_is_cleared() {
        let reclaim = EngineReclaim::new(4, 0);
        // Nothing reclaimed yet: the floor is transparent.
        assert_eq!(reclaim.release_threshold(7), 7);
        // Issue some tickets, then finish a pass: the floor is now the high-water.
        let minter = TicketMinter::new(WorkerAffinity::new(1, 4), reclaim.tickets());
        let ticket = minter.mint();
        reclaim.note_pass_finished();
        let floor = reclaim.release_floor.load(Ordering::Acquire);
        assert!(
            floor >= ticket,
            "the floor {floor} must cover the ticket {ticket} that was open across the pass"
        );
        // A transaction that was alive across the pass cannot open the gate ...
        assert_eq!(reclaim.release_threshold(ticket), 0);
        assert_eq!(reclaim.release_threshold(floor), 0);
        // ... and quiescence (no open transaction) always can, so the hold is never a leak.
        assert_eq!(reclaim.release_threshold(u64::MAX), u64::MAX);
        assert_eq!(reclaim.release_threshold(floor + 1), floor + 1);

        // At ONE worker the floor is never raised, so this whole mechanism is the identity — which is
        // what keeps the single-worker engine byte-identical to its pre-#1037 behaviour.
        let single = EngineReclaim::new(1, 0);
        let minter = TicketMinter::new(WorkerAffinity::new(0, 1), single.tickets());
        let ticket = minter.mint();
        single.note_pass_finished();
        assert_eq!(single.release_threshold(ticket), ticket);
        assert_eq!(single.release_floor.load(Ordering::Acquire), 0);
    }

    /// **`rmp` #1037 GATE — the barrier the ENGINE arms dominates every worker's open ticket.**
    ///
    /// [`gc_reuse_barrier`] is checked directly by its own tests, and [`TicketSequencer`] by
    /// [`ticket_tests::the_high_water_dominates_every_workers_ticket`]. Neither of them checks the WIRE
    /// between the two — that [`EngineReclaim::reuse_barrier`] takes its floor from the engine's
    /// sequence and not from something narrower — and the wire is precisely where the defect lived:
    /// with `rmp` #1035's per-worker counters, the floor a pass computed dominated its own worker's
    /// tickets and nobody else's.
    ///
    /// That gap was not hypothetical. Measured while closing this task: with `reuse_barrier` passing a
    /// per-worker peek instead of `tickets().high_water()`, every gate in the tree stayed green —
    /// `tests/engine_reclaim_barrier_1037.rs`, `tests/gc_reader_reclaim_reuse_588.rs` and every unit
    /// test here — because above one worker the release FLOOR happens to cover the same ground, and at
    /// one worker no gate reads the barrier's value at all. A headline change that no gate can
    /// falsify is the `rmp` #960 shape, so this test exists to falsify it.
    ///
    /// **Non-vacuity, measured.** With `reuse_barrier`'s floor replaced by `0` (an untouched
    /// per-worker minter) this fails at the first worker it checks: `at W = 1, barrier 1 does not
    /// exceed the open ticket 1`.
    #[test]
    fn the_armed_barrier_exceeds_every_workers_open_ticket() {
        for workers in [1usize, 2, 4] {
            let reclaim = EngineReclaim::new(workers, 0);
            // A read is in flight, so the barrier is armed at one worker too — otherwise the W = 1
            // case would be `None` for the unrelated reason that nothing needs holding.
            reclaim.readers_inflight.fetch_add(1, Ordering::Relaxed);
            let minters: Vec<_> = (0..workers)
                .map(|w| TicketMinter::new(WorkerAffinity::new(w, workers), reclaim.tickets()))
                .collect();
            // Lopsided on purpose: the last worker to mint is not the one with the most tickets, which
            // is the shape a per-worker floor gets wrong.
            let mut open = Vec::new();
            for round in 0..7 {
                for (w, minter) in minters.iter().enumerate() {
                    if (round + w) % 2 == 0 {
                        open.push(minter.mint());
                    }
                }
                let barrier = reclaim
                    .reuse_barrier()
                    .expect("a reader is in flight, so a pass must arm the barrier");
                for &ticket in &open {
                    assert!(
                        barrier > ticket,
                        "at W = {workers}, barrier {barrier} does not exceed the open ticket \
                         {ticket}: `release_held` frees that transaction's slots while it is still \
                         walking them (the `rmp` #588 defect, through the `rmp` #1035 door)"
                    );
                }
            }
        }
    }

    /// **`rmp` #1037 GATE — the reclaim gate refuses re-entry from the thread that holds it.**
    ///
    /// Without this, a future call site that reaches a reclaim section from inside one gets a silent
    /// hang from `enter_pass` or — worse — a `None` from `try_enter_pass` that reads as "another
    /// worker is already reclaiming" and skips the maintenance cadence forever.
    ///
    /// **Non-vacuity.** This is a positive control for the tripwire: it fails (no panic) if
    /// `ReclaimDepth::enter` is removed or if either door stops arming it.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "the engine reclaim gate is not re-entrant")]
    fn the_reclaim_gate_refuses_re_entry() {
        let reclaim = EngineReclaim::new(4, 0);
        let _held = reclaim.try_enter_pass().expect("the gate starts open");
        // A second door, on a thread that is already inside: `try_enter_pass` would otherwise answer
        // `None` and be indistinguishable from a sibling's pass.
        let _second = reclaim.try_enter_pass();
    }

    /// **`rmp` #1037 GATE — the reclaim gate admits exactly one worker at a time.**
    ///
    /// Two overlapping reuse-barrier-armed sections is not a redundancy, it is a correctness hole: the
    /// barrier is ONE shared atomic (`graphus_storage::idalloc::SharedReuseBarrier`, `rmp` #1025) and
    /// each section disarms it on the way out, so the first disarm leaves the second's remaining frees
    /// unstamped and immediately reusable.
    ///
    /// **Non-vacuity, measured.** With `try_enter_pass` handing out a fresh lock per caller instead of
    /// the engine's one gate, this fails on its own message: `a second worker must not enter a reclaim
    /// section while one is in progress`.
    #[test]
    fn only_one_worker_reclaims_at_a_time() {
        let reclaim = Arc::new(EngineReclaim::new(4, 0));
        let held = reclaim.try_enter_pass().expect("the gate starts open");
        // A real second THREAD, because a second worker IS one — and because the re-entrancy tripwire
        // correctly refuses a same-thread second acquisition, which would be a different fault.
        let sibling = Arc::clone(&reclaim);
        let refused = std::thread::spawn(move || sibling.try_enter_pass().is_none())
            .join()
            .expect("the sibling thread does not panic");
        assert!(
            refused,
            "a second worker must not enter a reclaim section while one is in progress"
        );
        drop(held);
        let sibling = Arc::clone(&reclaim);
        let admitted = std::thread::spawn(move || sibling.try_enter_pass().is_some())
            .join()
            .expect("the sibling thread does not panic");
        assert!(admitted, "the gate must reopen once the pass ends");
    }

    /// rmp #556 GATE: traffic uses an **adaptive** cadence proportional to the live store size, clamped
    /// to `[FLOOR, 256 MiB]`, so a small OLTP store's on-disk WAL is bounded to ≈ `WAL_STORE_RATIO_TARGET
    /// × store` instead of the fixed 256 MiB that produced 7–60x ratios. The clamp guarantees this can
    /// only make reclamation *more* frequent than the historical cadence, never less (a large store
    /// at/above the cap keeps exactly the old 256 MiB interval).
    ///
    /// rmp #590 GATE: a `Loading` Mode A bulk-import session now uses this SAME tight adaptive cadence
    /// (it historically used a 4 GiB fixed interval to dodge an O(N²) maintenance cost). `rmp` #522 made
    /// the freeze sweep O(Δ) and `rmp` #590 makes the mid-load pass freeze-only (skipping the still-O(store)
    /// property sweep), so a mid-load pass is O(Δ) and safe to run on this tight cadence — which bounds
    /// the WAL a load retains to ≤ the cadence at any pre-`End` crash point (the reopen-OOM fix). The
    /// interval helper is therefore store-size-only; the freeze-only vs full decision lives in
    /// [`maybe_run_maintenance`] (keyed on `loading_session_active`), asserted separately below.
    #[test]
    fn cadence_is_adaptive_and_bounded() {
        const MIB: u64 = 1024 * 1024;
        // Large store (≥ 256 MiB / RATIO = 64 MiB): capped at exactly the historical cadence, so
        // large-store reclamation is never made less frequent.
        assert_eq!(
            maintenance_interval_bytes(512 * MIB),
            MAINTENANCE_CHECKPOINT_INTERVAL_BYTES,
            "a large store must keep the historical 256 MiB cap"
        );
        assert_eq!(
            maintenance_interval_bytes(64 * MIB),
            MAINTENANCE_CHECKPOINT_INTERVAL_BYTES,
            "exactly at the cap boundary (RATIO × 64 MiB == 256 MiB)"
        );
        // A very large store (a big bulk load) is still capped at 256 MiB — so the retained WAL a load
        // can leave un-reclaimed at a crash point is bounded regardless of the eventual store size.
        assert_eq!(
            maintenance_interval_bytes(64 * 1024 * MIB),
            MAINTENANCE_CHECKPOINT_INTERVAL_BYTES,
            "even a multi-GB bulk load caps the retained WAL at the 256 MiB cadence (rmp #590)"
        );
        // Mid-size store (7 MiB, the fraud-OLTP regime): RATIO × store, well under the cap and above the
        // floor — bounds the ratio to WAL_STORE_RATIO_TARGET.
        assert_eq!(
            maintenance_interval_bytes(7 * MIB),
            WAL_STORE_RATIO_TARGET * 7 * MIB,
            "a small OLTP store must reclaim proportionally to its size"
        );
        // Tiny store: the floor prevents a hair-trigger cadence.
        assert_eq!(
            maintenance_interval_bytes(256 * 1024),
            MAINTENANCE_CHECKPOINT_MIN_INTERVAL_BYTES,
            "a tiny store must be floored, not checkpointed on every commit"
        );
        assert_eq!(
            maintenance_interval_bytes(0),
            MAINTENANCE_CHECKPOINT_MIN_INTERVAL_BYTES,
            "an empty store falls back to the floor"
        );
        const {
            assert!(
                MAINTENANCE_CHECKPOINT_MIN_INTERVAL_BYTES < MAINTENANCE_CHECKPOINT_INTERVAL_BYTES,
                "the adaptive floor must be below the cap"
            );
        }
    }

    /// End-to-end confirmation that [`maybe_run_maintenance`] actually **honors**
    /// `loading_session_active` rather than just computing the right interval and ignoring it: with
    /// `wal_at_last_maintenance` fixed at 0 and a fresh (near-empty) coordinator's `wal_durable_len()`
    /// comfortably below the adaptive interval, calling with `loading_session_active: true`
    /// vs `false` must not observably diverge from the "insufficient growth yet" no-op path in either
    /// case at this WAL size — this pins the call signature/wiring so a future refactor cannot silently
    /// drop the parameter (a compile-time-only regression that unit tests on the pure helper above
    /// would miss). The freeze-only-vs-full behaviour the flag now also selects (`rmp` #590) is exercised
    /// at scale by the `graphus-dst` bulk-load recovery gate.
    #[test]
    fn maybe_run_maintenance_accepts_loading_flag_and_stays_a_noop_below_either_interval() {
        let device = graphus_io::MemBlockDevice::new(0);
        let wal = graphus_wal::WalManager::create(graphus_wal::MemLogSink::new()).expect("wal");
        let store: RecordStore<graphus_io::MemBlockDevice, graphus_wal::MemLogSink> =
            RecordStore::create(device, wal, 256, 1).expect("store");
        let coordinator = Some(Arc::new(TxnCoordinator::new(store)));
        // One worker, watermark pinned at 0 — the shape the pre-`rmp` #1037 local had.
        let reclaim = EngineReclaim::new(1, 0);
        // No transaction open, so the release threshold the pass computes is `u64::MAX` (release
        // everything) — the `rmp` #588 no-hold fast path this unit test exercises.
        let open: EngineLatch<OpenTxTable> = EngineLatch::new(OpenTxTable::new());
        let mut consecutive_failures = 0u32;
        let metrics = Metrics::new();
        let maintenance_degraded = MaintenanceDegraded::new();
        let before = coordinator.as_ref().unwrap().wal_durable_len();

        for loading in [false, true] {
            maybe_run_maintenance(
                &coordinator,
                &reclaim,
                &open,
                &mut consecutive_failures,
                &metrics,
                "test",
                &maintenance_degraded,
                loading,
                false,
            );
        }

        // A near-empty store's WAL is far below even the narrow interval, so neither call should have
        // run a checkpoint (no growth requiring reclamation) — the engine's watermark stays at its
        // initial value and the WAL length itself is unchanged.
        assert_eq!(reclaim.wal_at_last_maintenance.load(Ordering::Relaxed), 0);
        assert_eq!(coordinator.as_ref().unwrap().wal_durable_len(), before);
    }

    /// `rmp` #565 GATE: on the loading→not-loading edge (`loading_just_ended == true`)
    /// [`maybe_run_maintenance`] must **re-anchor its watermark to the current WAL length and skip the
    /// GC pass**, even when the WAL has grown far past the ordinary interval — so the O(N) full-store
    /// scan can never run synchronously as the tail of `End` and block the `Shutdown` a `STOP DATABASE`
    /// queues right after it (the force-detach trigger this fix removes). We simulate "a large loaded
    /// store" by pinning `wal_at_last_maintenance` far below the live WAL length: without the edge guard
    /// this delta would exceed the 256 MiB interval and fire a checkpoint; with it, the pass is skipped
    /// and the watermark jumps to the current length (never firing on the drain path).
    #[test]
    fn loading_just_ended_skips_the_gc_pass_and_reanchors_the_watermark() {
        let device = graphus_io::MemBlockDevice::new(0);
        let wal = graphus_wal::WalManager::create(graphus_wal::MemLogSink::new()).expect("wal");
        let store: RecordStore<graphus_io::MemBlockDevice, graphus_wal::MemLogSink> =
            RecordStore::create(device, wal, 256, 1).expect("store");
        let coordinator = Some(Arc::new(TxnCoordinator::new(store)));
        // Pretend the WAL has grown a full interval past the last maintenance (a freshly loaded store),
        // so the ordinary path WOULD fire a checkpoint. The edge guard must override that.
        let reclaim = EngineReclaim::new(1, 0);
        let open: EngineLatch<OpenTxTable> = EngineLatch::new(OpenTxTable::new());
        let mut consecutive_failures = 0u32;
        let metrics = Metrics::new();
        let maintenance_degraded = MaintenanceDegraded::new();
        let live = coordinator.as_ref().unwrap().wal_durable_len();

        maybe_run_maintenance(
            &coordinator,
            &reclaim,
            &open,
            &mut consecutive_failures,
            &metrics,
            "test",
            &maintenance_degraded,
            false, // session already cleared by the `End` handler
            true,  // ...but it JUST ended: this is the edge
        );

        // Watermark re-anchored to the live WAL length (the pass was skipped, not run).
        assert_eq!(
            reclaim.wal_at_last_maintenance.load(Ordering::Relaxed),
            live,
            "the loading-ended edge must re-anchor the maintenance watermark to the live WAL length"
        );
    }

    /// rmp #394/#435 GATE: repeated maintenance-checkpoint failures increment the (aggregate) failure
    /// metric on every failure and, after K **consecutive** failures, flip **this engine's own**
    /// reclamation-degraded flag (which drives `/health/ready` to 503 for THAT database). A single
    /// transient failure must NOT escalate.
    #[test]
    fn repeated_maintenance_failures_escalate_to_degraded() {
        let metrics = Metrics::new();
        let maintenance_degraded = MaintenanceDegraded::new();
        let mut consecutive: u32 = 0;
        let err = "simulated checkpoint I/O failure";

        // Fewer than K failures: the metric counts each, but this engine is NOT yet flagged degraded.
        for i in 1..MAINTENANCE_FAILURE_ESCALATION_THRESHOLD {
            record_maintenance_failure(&mut consecutive, &metrics, &maintenance_degraded, &err);
            assert_eq!(consecutive, i);
            assert!(
                !maintenance_degraded.is_degraded(),
                "must not escalate before {MAINTENANCE_FAILURE_ESCALATION_THRESHOLD} consecutive failures"
            );
        }

        // The K-th consecutive failure escalates: this engine's reclamation is flagged degraded.
        record_maintenance_failure(&mut consecutive, &metrics, &maintenance_degraded, &err);
        assert_eq!(consecutive, MAINTENANCE_FAILURE_ESCALATION_THRESHOLD);
        assert!(
            maintenance_degraded.is_degraded(),
            "K consecutive failures must flag this engine's reclamation degraded (readiness → 503)"
        );
    }

    /// rmp #394/#435: a successful checkpoint after failures clears **this engine's own** degraded
    /// flag and resets the streak, so that database recovers readiness automatically once its
    /// reclamation resumes. A single transient failure (below the threshold) likewise never escalates.
    #[test]
    fn a_success_clears_degraded_and_resets_the_streak() {
        let metrics = Metrics::new();
        let maintenance_degraded = MaintenanceDegraded::new();
        let mut consecutive: u32 = 0;
        let err = "transient failure";

        // Drive past the threshold so this engine is degraded.
        for _ in 0..MAINTENANCE_FAILURE_ESCALATION_THRESHOLD {
            record_maintenance_failure(&mut consecutive, &metrics, &maintenance_degraded, &err);
        }
        assert!(maintenance_degraded.is_degraded());

        // A successful checkpoint clears this engine's flag; mirror the loop's success arm.
        metrics.record_maintenance_checkpoint(0, 0);
        maintenance_degraded.clear();
        consecutive = 0;
        assert!(
            !maintenance_degraded.is_degraded(),
            "a successful checkpoint must clear this engine's degraded flag"
        );

        // A single subsequent transient failure does not re-escalate (streak was reset).
        record_maintenance_failure(&mut consecutive, &metrics, &maintenance_degraded, &err);
        assert_eq!(consecutive, 1);
        assert!(
            !maintenance_degraded.is_degraded(),
            "one isolated failure after recovery must not flag degraded"
        );
    }

    /// rmp #435 GATE (the residual cross-tenant breach #414 left): the reclamation-degraded flag is
    /// **per-engine**, so (1) escalating engine A's maintenance failures NEVER flags engine B, and
    /// (2) a checkpoint SUCCESS on engine B (which clears B's own flag) NEVER false-clears A's still-
    /// stuck flag. Pre-#435 both engines shared a single `Metrics` gauge, so this isolation was
    /// impossible. The aggregate failure counter is shared (fleet observability) and is unaffected.
    #[test]
    fn maintenance_degraded_is_isolated_per_engine() {
        // One shared Metrics (as the catalog clones into every engine), two independent per-engine flags.
        let metrics = Metrics::new();
        let engine_a = MaintenanceDegraded::new();
        let engine_b = MaintenanceDegraded::new();
        let err = "simulated checkpoint I/O failure";

        // Escalate engine A only.
        let mut a_streak: u32 = 0;
        for _ in 0..MAINTENANCE_FAILURE_ESCALATION_THRESHOLD {
            record_maintenance_failure(&mut a_streak, &metrics, &engine_a, &err);
        }
        assert!(engine_a.is_degraded(), "engine A escalated");
        assert!(
            !engine_b.is_degraded(),
            "engine A's stall must NOT flag engine B (no shared-gauge blanket-503)"
        );

        // A successful checkpoint on engine B clears ONLY B's flag — A stays degraded.
        engine_b.clear(); // mirror the loop's success arm for B (a checkpoint on B succeeded)
        assert!(
            engine_a.is_degraded(),
            "engine B's checkpoint success must NOT false-clear engine A's stuck flag (the #435 bug)"
        );
    }
}

#[cfg(test)]
mod max_transaction_age_tests {
    //! `rmp` #477: the engine-level half of the maximum-transaction-age guard. [`maybe_reap_aged`]
    //! reaps an over-age **explicit** transaction (freeing the GC watermark), while excluding
    //! auto-commit statements and under-age transactions, and is a no-op when the cap is disabled.
    //!
    //! The clock is a fixed [`graphus_sim::SimClock`] and each transaction's begin reading is supplied
    //! explicitly to [`open_tx`], so ages — and therefore the reap decision — are fully deterministic.

    use super::*;
    use graphus_io::MemBlockDevice;
    use graphus_storage::RecordStore;
    use graphus_wal::{MemLogSink, WalManager};

    type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

    fn fresh_coord() -> Coord {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("wal");
        let store: RecordStore<MemBlockDevice, MemLogSink> =
            RecordStore::create(device, wal, 256, 1).expect("store");
        TxnCoordinator::new(store)
    }

    fn clock_at(now_nanos: u64) -> Arc<dyn graphus_core::capability::Clock + Send + Sync> {
        Arc::new(graphus_sim::SimClock::new(now_nanos))
    }

    /// THE GATE. With a 60s cap and the clock at 61s: an over-age **explicit** transaction is reaped
    /// (removed from `open`, rolled back, dropping the active count and releasing the watermark), an
    /// over-age **auto-commit** transaction is left alone (transient / possibly mid-flight), and a
    /// **young** explicit transaction is untouched.
    #[test]
    fn reaps_over_age_explicit_txn_only() {
        let coord = fresh_coord();
        let open: EngineLatch<OpenTxTable> = EngineLatch::new(OpenTxTable::new());
        // A single worker in the fixture: stride 1 (`rmp` #1035), which owns every ticket.
        let affinity = WorkerAffinity::new(0, 1);
        let reclaim = EngineReclaim::new(1, 0);
        let next_ticket = TicketMinter::new(affinity, reclaim.tickets());
        let cap = std::time::Duration::from_secs(60);
        let now = 61 * 1_000_000_000u64; // 61s in nanos — past the cap
        let clock = clock_at(now);
        let metrics = Arc::new(Metrics::new());
        let gauge = ActiveTxnGauge::new(Arc::clone(&metrics), Arc::from("test"));

        // Over-age explicit reader (begin at t=0 ⇒ age 61s ≥ cap).
        let aged_explicit = open_tx(
            &coord,
            &open,
            &next_ticket,
            &reclaim,
            AccessMode::Read,
            false,
            0,
        );
        // Over-age auto-commit statement (same age, but excluded from the sweep).
        let aged_auto = open_tx(
            &coord,
            &open,
            &next_ticket,
            &reclaim,
            AccessMode::Read,
            true,
            0,
        );
        // Young explicit reader (begin just now ⇒ age 1ns ≪ cap).
        let young_explicit = open_tx(
            &coord,
            &open,
            &next_ticket,
            &reclaim,
            AccessMode::Read,
            false,
            now - 1,
        );
        assert_eq!(coord.active_count(), 3);

        let coordinator = Some(Arc::new(coord));
        maybe_reap_aged(
            &coordinator,
            &open,
            &EngineLatch::new(VecDeque::new()), // nothing parked inline
            affinity,
            Some(cap),
            &clock,
            &metrics,
            "test",
            &gauge,
        );
        let coord = coordinator
            .as_ref()
            .expect("coordinator survives the sweep");

        // Only the over-age explicit transaction was reaped (the `open` map is keyed by ticket).
        assert_eq!(coord.active_count(), 2, "exactly one transaction reaped");
        assert!(
            !open.lock().contains_key(&aged_explicit.0),
            "the over-age explicit transaction must be removed from the open map"
        );
        assert!(
            open.lock().contains_key(&aged_auto.0),
            "the over-age auto-commit statement must be left alone (transient / possibly mid-flight)"
        );
        assert!(
            open.lock().contains_key(&young_explicit.0),
            "the young explicit transaction (under the cap) must be untouched"
        );
    }

    /// A disabled cap (`None`) is a no-op: even a transaction far past any sane cap stays open.
    #[test]
    fn disabled_cap_reaps_nothing() {
        let coord = fresh_coord();
        let open: EngineLatch<OpenTxTable> = EngineLatch::new(OpenTxTable::new());
        // A single worker in the fixture: stride 1 (`rmp` #1035), which owns every ticket.
        let affinity = WorkerAffinity::new(0, 1);
        let reclaim = EngineReclaim::new(1, 0);
        let next_ticket = TicketMinter::new(affinity, reclaim.tickets());
        let clock = clock_at(u64::MAX); // arbitrarily far in the future
        let metrics = Arc::new(Metrics::new());
        let gauge = ActiveTxnGauge::new(Arc::clone(&metrics), Arc::from("test"));

        let _ = open_tx(
            &coord,
            &open,
            &next_ticket,
            &reclaim,
            AccessMode::Read,
            false,
            0,
        );
        assert_eq!(coord.active_count(), 1);

        let coordinator = Some(Arc::new(coord));
        maybe_reap_aged(
            &coordinator,
            &open,
            &EngineLatch::new(VecDeque::new()),
            affinity,
            None, // cap disabled
            &clock,
            &metrics,
            "test",
            &gauge,
        );
        assert_eq!(
            coordinator.as_ref().unwrap().active_count(),
            1,
            "a disabled cap must never reap"
        );
        assert_eq!(
            open.lock().len(),
            1,
            "the open map is untouched when the cap is disabled"
        );
    }
}

#[cfg(test)]
mod index_build_gauge_tests {
    //! The server-wide **index-build gauges** (`rmp` task #573).
    //!
    //! The two pre-existing signals (`graphus_index_builds_poisoned_total` /
    //! `graphus_index_fail_closed_total`) are cumulative event counters: they record that something
    //! happened, never whether it is happening *now*. These gauges are what separate a normal build
    //! window from a permanent stall, so their arithmetic must hold under the two conditions the `rmp`
    //! #418 lesson taught: multiple engines share one gauge (hence additive publishing), and an engine
    //! can be torn down at any time (hence the `Drop` retraction — a leaked `parked` would page an
    //! operator about a database that no longer exists).

    use super::*;

    fn totals(pending: usize, parked: usize, remaining: usize) -> IndexBuildTotals {
        IndexBuildTotals {
            pending,
            parked,
            entities_remaining: remaining,
        }
    }

    /// A single engine's publishes move each gauge to the published value, in both directions.
    #[test]
    fn publishing_tracks_the_totals_in_both_directions() {
        let metrics = Arc::new(Metrics::new());
        let gauge = IndexBuildGauge::new(Arc::clone(&metrics));
        assert_eq!(metrics.index_builds_pending(), 0, "starts empty");

        // A build starts.
        gauge.publish(totals(1, 0, 500));
        assert_eq!(metrics.index_builds_pending(), 1);
        assert_eq!(metrics.index_builds_parked(), 0);
        assert_eq!(metrics.index_build_entities_remaining(), 500);

        // It progresses: the remainder FALLS (a rising gauge would be a sign inversion).
        gauge.publish(totals(1, 0, 200));
        assert_eq!(metrics.index_build_entities_remaining(), 200);

        // It gets poisoned: pending drops, parked rises — the window/stall transition.
        gauge.publish(totals(0, 1, 0));
        assert_eq!(metrics.index_builds_pending(), 0);
        assert_eq!(metrics.index_builds_parked(), 1);
        assert_eq!(metrics.index_build_entities_remaining(), 0);

        // It is resurrected and completes.
        gauge.publish(totals(0, 0, 0));
        assert_eq!(metrics.index_builds_parked(), 0);
    }

    /// **The `rmp` #418 invariant.** With several engines sharing the gauges, each publishing only its own
    /// delta, every gauge equals the SUM across engines — never whichever engine wrote last.
    #[test]
    fn gauges_sum_across_engines_rather_than_last_writer_wins() {
        let metrics = Arc::new(Metrics::new());
        let a = IndexBuildGauge::new(Arc::clone(&metrics));
        let b = IndexBuildGauge::new(Arc::clone(&metrics));

        a.publish(totals(1, 0, 100));
        b.publish(totals(2, 1, 300));
        assert_eq!(metrics.index_builds_pending(), 3, "1 + 2, not 2");
        assert_eq!(metrics.index_builds_parked(), 1);
        assert_eq!(metrics.index_build_entities_remaining(), 400, "100 + 300");

        // One engine going idle must not zero the other's contribution.
        a.publish(totals(0, 0, 0));
        assert_eq!(
            metrics.index_builds_pending(),
            2,
            "engine B's builds survive engine A going idle"
        );
        assert_eq!(metrics.index_build_entities_remaining(), 300);
    }

    /// A torn-down engine retracts its whole contribution, so no phantom build is left behind. This
    /// matters most for `parked`, which is an alerting signal.
    #[test]
    fn dropping_an_engines_gauge_retracts_its_contribution() {
        let metrics = Arc::new(Metrics::new());
        let survivor = IndexBuildGauge::new(Arc::clone(&metrics));
        survivor.publish(totals(1, 0, 50));
        {
            let dying = IndexBuildGauge::new(Arc::clone(&metrics));
            dying.publish(totals(3, 2, 900));
            assert_eq!(metrics.index_builds_parked(), 2);
        } // `dying` is dropped here.
        assert_eq!(
            metrics.index_builds_parked(),
            0,
            "a torn-down engine must not leave a phantom PARKED build alerting forever"
        );
        assert_eq!(
            metrics.index_builds_pending(),
            1,
            "only the dead engine's contribution is retracted"
        );
        assert_eq!(metrics.index_build_entities_remaining(), 50);
    }

    /// The gauges render as Prometheus **gauges** (not counters) with their metric names.
    #[test]
    fn gauges_render_in_the_prometheus_exposition() {
        let metrics = Arc::new(Metrics::new());
        let gauge = IndexBuildGauge::new(Arc::clone(&metrics));
        gauge.publish(totals(1, 2, 42));
        let out = metrics.render_prometheus();
        for name in [
            "graphus_index_builds_pending",
            "graphus_index_builds_parked",
            "graphus_index_build_entities_remaining",
        ] {
            assert!(
                out.contains(&format!("# TYPE {name} gauge")),
                "{name} must be exposed as a gauge:\n{out}"
            );
        }
        assert!(out.contains("\ngraphus_index_builds_parked 2\n"), "{out}");
        assert!(
            out.contains("\ngraphus_index_build_entities_remaining 42\n"),
            "{out}"
        );
    }
}

#[cfg(test)]
mod active_txn_gauge_tests {
    //! **The additive fold must be ordered with the value it remembers** (`rmp` #1041).
    //!
    //! [`ActiveTxnGauge`] became one per ENGINE when the engine became several workers, so `publish`
    //! is now called concurrently — by workers reporting the same coordinator-wide count, each having
    //! read it at a slightly different moment. Each call folds the signed delta between what it
    //! publishes and what the gauge last remembered.
    //!
    //! The obvious implementation remembers with an atomic swap and then folds. That is unsound, and
    //! not merely racy, because [`crate::metrics`]'s `add_delta` **saturates at zero** on a decrement:
    //! if two workers swap in one order and fold in the other, a decrement can land while the gauge is
    //! still below it, be clamped, and never be recovered by the increment it was computed against.
    //! The sum of the deltas telescopes; the gauge does not, because the clamp is not linear. The
    //! residue is permanent — a restart is the only cure — which is exactly the phantom count the
    //! additive discipline (`rmp` #418/#463) exists to prevent.
    //!
    //! This is tested here rather than through the engine because the window is a handful of
    //! instructions: the end-to-end gate can drive a few thousand publishes, this one drives a few
    //! hundred thousand, and only the second reliably catches the swap-then-fold shape (verified —
    //! the end-to-end test passes with it, this one fails).

    use super::*;

    /// Every publisher ends on the same value, so the gauge must end on it too — whatever order the
    /// folds took. Threads deliberately publish DIFFERENT values along the way: identical values fold
    /// nothing and would make the test agree with any implementation.
    #[test]
    fn concurrent_publishes_leave_the_gauge_on_the_last_value() {
        const THREADS: usize = 8;
        const ROUNDS: usize = 40_000;
        let metrics = Arc::new(Metrics::new());
        let gauge = Arc::new(ActiveTxnGauge::new(
            Arc::clone(&metrics),
            Arc::from("gaugetest"),
        ));

        let threads: Vec<_> = (0..THREADS)
            .map(|t| {
                let gauge = Arc::clone(&gauge);
                std::thread::spawn(move || {
                    for round in 0..ROUNDS {
                        // Small counts that cross zero constantly: a decrement is only *clamped* when
                        // it exceeds the gauge, so a defect needs the gauge to spend time near zero.
                        gauge.publish((round + t) % 4, (round + t) % 3);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("publisher joins");
        }

        // Quiesce: one last publish, from one thread, is what every engine does when its last
        // transaction closes.
        gauge.publish(0, 0);
        assert_eq!(
            metrics.active_txns(),
            0,
            "the open-transaction gauge did not return to the last published value: a fold was \
             applied out of order with the value it was computed against, and the saturating \
             decrement discarded it permanently (rmp #1041)"
        );
        assert_eq!(
            metrics.ssi_tracked(),
            0,
            "the SSI-tracked gauge has the same fold and the same failure mode"
        );
    }
}
