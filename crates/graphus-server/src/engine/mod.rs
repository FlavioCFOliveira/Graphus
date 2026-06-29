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

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
// `EngineDegraded` is defined in this module (below); re-export note: it is `pub` here.
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
/// query's expressions/clauses. The cypher crate bounds that depth at compile time
/// ([`graphus_cypher::MAX_EXPR_DEPTH`] ≈ 1 000) and converts anything deeper into a recoverable
/// compile error rather than a native stack overflow — but a Rust stack overflow **aborts the whole
/// process** (the guard-page handler calls `abort()`, which no `catch_unwind` can intercept), so the
/// thread must carry enough stack to absorb a *legal*, at-the-limit query with comfortable margin.
/// The default thread stack (~2 MiB on Linux) is **not** enough: a depth-1 000 expression overflows
/// it during parsing/evaluation. 64 MiB matches the dedicated stack the TCK harness already runs the
/// engine on and was measured (`rmp` #473) to absorb the depth bound with ≥5× headroom, while costing
/// only reserved address space (lazily paged, a handful of threads per database).
pub const QUERY_ENGINE_STACK_SIZE: usize = 64 * 1024 * 1024;

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
struct ActiveTxnGauge {
    metrics: Arc<Metrics>,
    /// The database name labelling this engine's per-database open-transaction gauge (`rmp` #463).
    db_name: Arc<str>,
    /// The count this engine last contributed to the shared gauge.
    last: u64,
}

impl ActiveTxnGauge {
    fn new(metrics: Arc<Metrics>, db_name: Arc<str>) -> Self {
        Self {
            metrics,
            db_name,
            last: 0,
        }
    }

    /// Publishes this engine's `current` open-transaction count, folding only the delta since the last
    /// publish into BOTH the shared additive gauge and this database's per-database gauge (`rmp` #463).
    fn publish(&mut self, current: usize) {
        let current = current as u64;
        if current == self.last {
            return;
        }
        // `i128` headroom so the subtraction never overflows `i64` for any realistic open-txn count
        // (which is a small `usize`); clamp into `i64` for the (impossible-in-practice) saturating case.
        let delta = (i128::from(current) - i128::from(self.last))
            .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
        self.metrics.add_active_txns_delta_for(&self.db_name, delta);
        self.last = current;
    }
}

impl Drop for ActiveTxnGauge {
    fn drop(&mut self) {
        // Retract this engine's whole remaining contribution so a stopped/torn-down engine never
        // leaves a phantom count in the server-wide gauge OR this database's per-database gauge
        // (`rmp` #418/#463).
        if self.last != 0 {
            self.metrics.add_active_txns_delta_for(
                &self.db_name,
                -(i64::try_from(self.last).unwrap_or(i64::MAX)),
            );
            self.last = 0;
        }
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
    coordinator: TxnCoordinator<D, S>,
    rx: std::sync::mpsc::Receiver<EngineCommand>,
    result_buffer_capacity: usize,
    reader_threads: usize,
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
) {
    // This engine's contribution to the server-wide open-transaction gauge (`rmp` #418): published
    // additively so the gauge sums across every database engine. Also folds the same delta into THIS
    // database's per-database gauge (`rmp` #463). Dropped (retracting its contribution from both) when the
    // loop exits. `db_name` labels the per-database series for every metric family below.
    let mut active_txns = ActiveTxnGauge::new(Arc::clone(&metrics), Arc::clone(&db_name));
    let mut open: HashMap<u64, OpenTx> = HashMap::new();
    let mut next_ticket: u64 = 0;
    // The engine's compiled-plan cache (`rmp` task #322): reuses a compiled `PhysicalPlan` for an
    // identical query text instead of re-running the ~7–9 µs compile pipeline on every `Run`. Owned by
    // (and `&mut`-borrowed on) this single engine thread, so its single-threaded contract holds with no
    // synchronisation. Invalidated by a schema-version bump on any planner-visible catalog change (DDL
    // or an online index build promoting `Populating`→`Online`).
    let mut plan_cache = exec::EnginePlanCache::new();
    // Whether an index build was pending at the end of the previous tick. A `true`→`false` transition
    // means a build just completed (an index promoted `Populating`→`Online`), which changes the
    // planner-visible catalog (`TxnCoordinator::catalog` now exposes the new index) and so must
    // invalidate the plan cache. Seeded from the current state so a freshly-opened engine with a
    // recovered pending build is handled on the tick its build finishes.
    let mut builds_were_pending = coordinator.has_pending_index_builds();
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
        Arc::clone(&metrics),
    ));
    // How many readers are dispatched-but-not-yet-retired. While `> 0` the loop polls the retirement
    // channel each tick so a retirement (which finalises the reader's auto-commit + closes its egress)
    // is processed promptly even if no client command arrives. Incremented at dispatch, decremented as
    // each retirement is processed.
    let mut readers_inflight: u64 = 0;
    // The suspended inline statements (`rmp` task #372; bounded-queue generalization `rmp` #485 B1). An
    // inline `Run` whose bounded egress channel fills with a slow consumer draining is parked here
    // instead of blocking this thread on `row_tx.send`; the loop resumes each one batch per tick
    // (round-robin, gated into `timed` below) until its cursor exhausts. **Multiple** can be parked at
    // once — writes and explicit-transaction reads run inline and any can suspend, and the engine keeps
    // dispatching new commands while statements are parked (the #372 no-head-of-line-block property) —
    // so this is a FIFO `VecDeque`, bounded by `max_parked_inline`. The historical single-`Option` slot
    // silently clobbered the first parked statement when a second suspended (`rmp` #485 finding B1).
    let mut parked: VecDeque<exec::InFlightInline> = VecDeque::new();
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
    // Consecutive background-maintenance-checkpoint failures (`rmp` #394). Persists across maintenance
    // ticks; once it reaches `MAINTENANCE_FAILURE_ESCALATION_THRESHOLD` the reclamation-degraded gauge
    // is set (driving `/health/ready` to 503). Reset to 0 by any successful checkpoint.
    let mut maintenance_consecutive_failures: u32 = 0;

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
            &db_name,
            &degraded,
            &mut active_txns,
        );

        // Maximum-transaction-age sweep (`rmp` #477): reap any **explicit** transaction whose lifetime
        // has exceeded the configured cap, measured on the **monotonic** clock (`rmp` #395, so an NTP
        // step cannot mis-fire). Runs each engine tick — every command and every timed wake — which is
        // exactly when the denial of service it guards against can manifest: a long-running reader pins
        // the MVCC GC low-water mark, but dead versions only *accumulate* (so the pin only *costs*) under
        // other transactions' write traffic, and that traffic is what wakes this loop. Disabled (`None`)
        // ⇒ a cheap no-op. Skips the one statement executing inline and excludes auto-commit statements
        // (transient, bounded by the per-statement timeout, possibly mid-flight on an off-thread reader),
        // so a reap never races a live read.
        maybe_reap_aged(
            &mut coordinator,
            &mut open,
            &parked,
            max_transaction_age,
            &clock,
            &metrics,
            &db_name,
            &mut active_txns,
        );

        // Resume ONE batch of EACH suspended inline statement (`rmp` task #372; round-robin over the
        // bounded queue per `rmp` #485 B1). Done each tick — before the (timed) command receive — so
        // every draining consumer makes progress promptly even when no client command arrives, and a
        // concurrent write/command on the SAME database is still serviced on the very next tick (the
        // head-of-line block stays gone for N parked statements, not just one). Each resume runs behind
        // a panic-isolation boundary (`rmp` #485 B2): a panic on a resumed batch rolls that statement
        // back and keeps the engine alive instead of unwinding the single engine thread.
        resume_parked_statements(
            &mut parked,
            &mut coordinator,
            &mut open,
            &extensions,
            &metrics,
            &db_name,
            &degraded,
            &clock,
            &mut active_txns,
        );

        // A timed receive is needed when EITHER a non-blocking index build is in progress (`rmp` #91)
        // OR readers are in flight (so their retirements are polled) OR a suspended inline statement is
        // parked (so it is resumed each tick even with no command). Otherwise block plainly (no idle
        // wakeups — a fully idle engine with nothing pending parks on `recv` exactly as before).
        let building = coordinator
            .as_ref()
            .expect("INVARIANT: coordinator is Some until Shutdown breaks the loop")
            .has_pending_index_builds();
        let timed = building || readers_inflight > 0 || !parked.is_empty();

        if timed {
            match rx.recv_timeout(INDEX_BUILD_TICK) {
                Ok(cmd) => {
                    // Test-only (`rmp` #435): intercept the simulated-maintenance driver here in the
                    // loop, where the per-engine flag + the consecutive-failure streak live, so it
                    // exercises the REAL escalation path confined to this engine. Returns the original
                    // command if it was not a `SimulateMaintenance` (production builds: identity).
                    let Some(cmd) = intercept_simulate_maintenance(
                        cmd,
                        &mut maintenance_consecutive_failures,
                        &metrics,
                        &maintenance_degraded,
                    ) else {
                        continue 'engine;
                    };
                    // A per-dispatch slot for the (at most one) statement THIS `Run` suspends; drained
                    // into the bounded `parked` queue below so a newly-suspended statement never
                    // overwrites an already-parked one (`rmp` #485 B1).
                    let mut just_suspended: Option<exec::InFlightInline> = None;
                    if !dispatch_command(
                        cmd,
                        &mut coordinator,
                        &mut open,
                        &mut next_ticket,
                        &mut plan_cache,
                        &extensions,
                        &dispatch,
                        &mut readers_inflight,
                        &mut just_suspended,
                        result_buffer_capacity,
                        &metrics,
                        &db_name,
                        &degraded,
                        &maintenance_degraded,
                        &mut active_txns,
                        &clock,
                        statement_timeout,
                    ) {
                        break 'engine; // Shutdown handled (drained + hardened) inside the dispatch.
                    }
                    enqueue_suspended(
                        &mut parked,
                        &mut just_suspended,
                        max_parked_inline,
                        &mut coordinator,
                        &mut open,
                        &metrics,
                        &db_name,
                        &degraded,
                    );
                    drive_index_build(&mut coordinator);
                    invalidate_cache_on_build_completion(
                        &coordinator,
                        &mut plan_cache,
                        &mut builds_were_pending,
                    );
                    maybe_run_maintenance(
                        &mut coordinator,
                        &mut wal_at_last_maintenance,
                        &mut maintenance_consecutive_failures,
                        &metrics,
                        &maintenance_degraded,
                    );
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // No command this tick: advance any build, then loop (which drains retirements).
                    drive_index_build(&mut coordinator);
                    invalidate_cache_on_build_completion(
                        &coordinator,
                        &mut plan_cache,
                        &mut builds_were_pending,
                    );
                }
                // Channel closed (all client senders dropped): the engine is being torn down without a
                // graceful `Shutdown`. Stop serving.
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break 'engine,
            }
        } else {
            // No build pending and no readers in flight: a plain blocking receive (the original
            // behaviour). `Err` is the closed-channel EOF the old `while let Ok(..)` terminated on.
            let Ok(cmd) = rx.recv() else { break 'engine };
            // Test-only (`rmp` #435): intercept the simulated-maintenance driver (identity in
            // production). See the `timed` branch for the rationale.
            let Some(cmd) = intercept_simulate_maintenance(
                cmd,
                &mut maintenance_consecutive_failures,
                &metrics,
                &maintenance_degraded,
            ) else {
                continue 'engine;
            };
            // A per-dispatch slot for the (at most one) statement THIS `Run` suspends; drained into the
            // bounded `parked` queue below (`rmp` #485 B1 — never clobber an already-parked statement).
            let mut just_suspended: Option<exec::InFlightInline> = None;
            if !dispatch_command(
                cmd,
                &mut coordinator,
                &mut open,
                &mut next_ticket,
                &mut plan_cache,
                &extensions,
                &dispatch,
                &mut readers_inflight,
                &mut just_suspended,
                result_buffer_capacity,
                &metrics,
                &db_name,
                &degraded,
                &maintenance_degraded,
                &mut active_txns,
                &clock,
                statement_timeout,
            ) {
                break 'engine;
            }
            enqueue_suspended(
                &mut parked,
                &mut just_suspended,
                max_parked_inline,
                &mut coordinator,
                &mut open,
                &metrics,
                &db_name,
                &degraded,
            );
            // A DDL command dispatched here may have started a build; reflect that in the edge tracker
            // so its later completion invalidates the cache (the no-build blocking path never advances
            // a build itself, but the next `timed` tick will).
            invalidate_cache_on_build_completion(
                &coordinator,
                &mut plan_cache,
                &mut builds_were_pending,
            );
            maybe_run_maintenance(
                &mut coordinator,
                &mut wal_at_last_maintenance,
                &mut maintenance_consecutive_failures,
                &metrics,
                &maintenance_degraded,
            );
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
#[allow(clippy::too_many_arguments)] // The retirement path threads its execution context here.
fn process_retirements<D: BlockDevice, S: LogSink>(
    retire_rx: &std::sync::mpsc::Receiver<read_pool::ReadRetirement>,
    coordinator: &mut Option<TxnCoordinator<D, S>>,
    open: &mut HashMap<u64, OpenTx>,
    readers_inflight: &mut u64,
    metrics: &Metrics,
    db: &str,
    degraded: &EngineDegraded,
    active_txns: &mut ActiveTxnGauge,
) {
    while let Ok(retirement) = retire_rx.try_recv() {
        if let Some(coord) = coordinator.as_mut() {
            finish_reader(coord, open, retirement, metrics, db, degraded);
        }
        *readers_inflight = readers_inflight.saturating_sub(1);
        active_txns.publish(coordinator.as_ref().map_or(0, TxnCoordinator::active_count));
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
                // The COMMIT failed (e.g. an SSI serialization abort): the transaction is rolled back.
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
                Some(_) => metrics.record_abort_for(db),
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
fn maybe_run_maintenance<D: BlockDevice, S: LogSink>(
    coordinator: &mut Option<TxnCoordinator<D, S>>,
    wal_at_last_maintenance: &mut u64,
    consecutive_failures: &mut u32,
    metrics: &Metrics,
    maintenance_degraded: &MaintenanceDegraded,
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
            // Success: record progress (aggregate observability counters) and clear **this engine's
            // own** reclamation-degraded flag (`rmp` #435 — never another engine's); reset the streak.
            metrics.record_maintenance_checkpoint(report.reclaimed as u64, report.frozen as u64);
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
    *wal_at_last_maintenance = coord.wal_durable_len();
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
/// - **Every statement currently parked/executing inline** (`parked`) is skipped: reaping one would
///   pull the per-statement seam out from under a live (suspended) cursor. Several can be parked at
///   once (`rmp` #485 B1), so ALL of their transactions are excluded, not just one. Each is reaped on a
///   later tick once idle (and is itself bounded by the per-statement timeout meanwhile).
#[allow(clippy::too_many_arguments)] // the engine loop threads its execution context through here
fn maybe_reap_aged<D: BlockDevice, S: LogSink>(
    coordinator: &mut Option<TxnCoordinator<D, S>>,
    open: &mut HashMap<u64, OpenTx>,
    parked: &VecDeque<exec::InFlightInline>,
    max_transaction_age: Option<std::time::Duration>,
    clock: &Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    metrics: &Metrics,
    db: &str,
    active_txns: &mut ActiveTxnGauge,
) {
    let Some(max_age) = max_transaction_age else {
        return; // cap disabled — opt-out, unbounded lifetime
    };
    let Some(coord) = coordinator.as_mut() else {
        return; // coordinator already consumed by Shutdown
    };
    let max_age_nanos = u64::try_from(max_age.as_nanos()).unwrap_or(u64::MAX);
    let aged = coord.aged_transactions(clock.now_nanos(), max_age_nanos);
    if aged.is_empty() {
        return; // the common case: nothing over-age
    }
    let mut reaped = 0u64;
    for txn in aged {
        // Any inline statement currently parked (suspended mid-stream) must not be reaped: it holds a
        // live cursor that resumes on a later tick. Several can be parked at once (`rmp` #485 B1).
        if parked.iter().any(|p| p.txn() == txn) {
            continue; // executing/parked inline now — reap on a later (idle) tick
        }
        // Reverse-map txn -> ticket and read its auto-commit flag in one immutable borrow, so the
        // subsequent `open.remove` mutable borrow is unobstructed. Reap only explicit transactions.
        let Some((ticket, auto_commit)) = open
            .iter()
            .find(|(_, t)| t.txn == txn)
            .map(|(ticket, t)| (*ticket, t.auto_commit))
        else {
            continue; // not engine-tracked (an internal maintenance txn) — leave it to its owner
        };
        if auto_commit {
            continue; // transient single-statement unit — never the idle-holder threat
        }
        open.remove(&ticket);
        // A clean rollback: discards the transaction's writes/locks/SSI footprint atomically and removes
        // it from the active set so `oldest_active_snapshot` advances. Idempotent-safe: `rollback` only
        // errs for an already-inactive txn, which cannot happen here (we just observed it active).
        if coord.rollback(txn).is_ok() {
            metrics.record_abort_for(db);
            reaped += 1;
        }
    }
    if reaped > 0 {
        // The active set shrank — refresh the open-transaction gauge so observability reflects the reap.
        active_txns.publish(coord.active_count());
    }
}

/// Resumes ONE batch of EACH currently-parked inline statement (`rmp` task #372; bounded-queue
/// round-robin generalization per `rmp` #485 B1), each behind a panic-isolation boundary (`rmp` #485 B2).
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
#[allow(clippy::too_many_arguments)] // the engine loop threads its execution context through here
fn resume_parked_statements<
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
>(
    parked: &mut VecDeque<exec::InFlightInline>,
    coordinator: &mut Option<TxnCoordinator<D, S>>,
    open: &mut HashMap<u64, OpenTx>,
    extensions: &Arc<graphus_cypher::extension::ExtensionRegistry>,
    metrics: &Arc<Metrics>,
    db: &Arc<str>,
    degraded: &EngineDegraded,
    clock: &Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    active_txns: &mut ActiveTxnGauge,
) {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let mut finalized_any = false;
    // Snapshot the count at entry: a statement that re-suspends is pushed to the back and only gets its
    // next batch on the following tick, so this never spins on one fast-refilling consumer.
    let mut budget = parked.len();
    while budget > 0 {
        budget -= 1;
        let Some(mut stmt) = parked.pop_front() else {
            break;
        };
        let Some(coord) = coordinator.as_mut() else {
            // Coordinator already consumed (Shutdown in progress): put it back and stop; Shutdown's
            // `drain_inflight` rolls its transaction back and the queue drops at loop exit.
            parked.push_front(stmt);
            break;
        };
        let txn = stmt.txn();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            exec::resume_inflight(&mut stmt, coord, open, extensions, metrics, db, clock)
        }));
        match outcome {
            // Re-suspended: round-robin to the back of the queue for the next tick.
            Ok(true) => parked.push_back(stmt),
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
        active_txns.publish(coordinator.as_ref().map_or(0, TxnCoordinator::active_count));
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
    coord: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
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
    // `maybe_reap_aged` does) so the open-tx entry is removed exactly once.
    if let Some(ticket) = open.iter().find(|(_, t)| t.txn == txn).map(|(k, _)| *k) {
        open.remove(&ticket);
    }
    if let Some(Ok(())) = catch_recovery(metrics, degraded, "resumed statement rollback", || {
        coord.rollback(txn)
    }) {
        metrics.record_abort_for(db);
    }
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
    parked: &mut VecDeque<exec::InFlightInline>,
    just_suspended: &mut Option<exec::InFlightInline>,
    max_parked: usize,
    coordinator: &mut Option<TxnCoordinator<D, S>>,
    open: &mut HashMap<u64, OpenTx>,
    metrics: &Metrics,
    db: &str,
    degraded: &EngineDegraded,
) {
    let Some(stmt) = just_suspended.take() else {
        return; // the common case: the dispatch ran to completion / off-thread, nothing to park
    };
    if parked.len() < max_parked.max(1) {
        parked.push_back(stmt);
        return;
    }
    // Overflow — unreachable under correct admission. Roll back the NEWCOMER (never an existing parked
    // statement) so the bound holds without losing already-parked work, then deliver a clean retriable
    // FAILURE to its consumer (rollback → terminal error → drop) so it is reported as busy/aborted, not
    // a partial result over a successful end-of-stream (the CWE-393 class).
    let txn = stmt.txn();
    if let Some(coord) = coordinator.as_mut() {
        if let Some(ticket) = open.iter().find(|(_, t)| t.txn == txn).map(|(k, _)| *k) {
            open.remove(&ticket);
        }
        if let Some(Ok(())) =
            catch_recovery(metrics, degraded, "overflow statement rollback", || {
                coord.rollback(txn)
            })
        {
            metrics.record_abort_for(db);
        }
    }
    stmt.deliver_terminal_error(GraphusError::Runtime(
        "server busy: in-flight statement capacity reached, retry".to_owned(),
    ));
    tracing::warn!(
        target: "graphus::engine",
        parked = parked.len(),
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
fn drive_index_build<D: BlockDevice, S: LogSink>(coordinator: &mut Option<TxnCoordinator<D, S>>) {
    if let Some(coord) = coordinator.as_mut() {
        let _remaining = coord.advance_index_builds(INDEX_BUILD_CHUNK);
    }
}

/// Invalidates the plan cache if an asynchronous index build completed since the previous tick
/// (`rmp` task #322). A build promoting `Populating`→`Online` makes [`TxnCoordinator::catalog`] start
/// exposing the new index, so any plan compiled before the promotion (which fell back to a scan) is
/// now stale and must be recompiled. Detected as a `true`→`false` transition of
/// [`has_pending_index_builds`](TxnCoordinator::has_pending_index_builds): when the last pending build
/// drains, bump the schema version. `builds_were_pending` is updated in place to track the edge.
fn invalidate_cache_on_build_completion<D: BlockDevice, S: LogSink>(
    coordinator: &Option<TxnCoordinator<D, S>>,
    plan_cache: &mut exec::EnginePlanCache,
    builds_were_pending: &mut bool,
) {
    let now_pending = coordinator
        .as_ref()
        .map(TxnCoordinator::has_pending_index_builds)
        .unwrap_or(false);
    if *builds_were_pending && !now_pending {
        // The last in-flight build just promoted to `Online`: the catalog changed, so invalidate.
        plan_cache.bump_schema();
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
    plan_cache: &mut exec::EnginePlanCache,
    extensions: &Arc<graphus_cypher::extension::ExtensionRegistry>,
    dispatch: &read_pool::ReadDispatch<D, S>,
    readers_inflight: &mut u64,
    inflight: &mut Option<exec::InFlightInline>,
    result_buffer_capacity: usize,
    metrics: &Arc<Metrics>,
    db: &str,
    degraded: &EngineDegraded,
    maintenance_degraded: &MaintenanceDegraded,
    active_txns: &mut ActiveTxnGauge,
    clock: &Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    statement_timeout: Option<std::time::Duration>,
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
        .as_mut()
        .expect("INVARIANT: coordinator is Some until Shutdown breaks the loop");
    match cmd {
        Cmd::Begin { mode, reply } => {
            let ticket = open_tx(coord, open, next_ticket, mode, false, clock.now_nanos());
            active_txns.publish(coord.active_count());
            let _ = reply.send(Ok(ticket));
        }
        Cmd::BeginAutoCommit { mode, reply } => {
            let ticket = open_tx(coord, open, next_ticket, mode, true, clock.now_nanos());
            active_txns.publish(coord.active_count());
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
            // `rmp` task #386: isolate per-statement execution behind a panic boundary so a panic in
            // the executor / materializer / a UDF (or a `rayon`-propagated morsel/GDS worker panic,
            // which re-raises on *this* engine thread inside `handle_run`'s synchronous
            // `analytics_pool().install`) becomes a clean terminal statement error — never engine
            // death. `coord` is reborrowed from `coordinator` here so the borrow can be handed to the
            // catch handler for the rollback after `catch_unwind` consumes the closure's reborrow.
            let coord = coordinator
                .as_mut()
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
                readers_inflight,
                inflight,
                result_buffer_capacity,
                metrics,
                db,
                degraded,
                clock,
                statement_timeout,
                reply,
            );
            active_txns.publish(coord.active_count());
        }
        Cmd::Commit { ticket, reply } => {
            let out = commit_tx(coord, open, ticket, metrics, db);
            active_txns.publish(coord.active_count());
            let _ = reply.send(out);
        }
        Cmd::Rollback { ticket, reply } => {
            let out = rollback_tx(coord, open, ticket, metrics, db);
            active_txns.publish(coord.active_count());
            let _ = reply.send(out);
        }
        Cmd::Status { reply } => {
            let _ = reply.send(coord.active_count());
        }
        Cmd::IndexDdl { command, reply } => {
            let mutating = !matches!(
                command,
                IndexCommand::ShowIndexes
                    | IndexCommand::ShowFulltextIndexes
                    | IndexCommand::ShowPointIndexes
            );
            let out = handle_index_ddl(coord, &command);
            // Invalidate the plan cache on a successful *mutating* index DDL (`rmp` task #322): a DROP
            // (and a fulltext/spatial CREATE, which is synchronous) changes the planner-visible catalog
            // immediately. A node-property CREATE only starts a `Populating` build whose later
            // promotion is caught by `invalidate_cache_on_build_completion`, but bumping here too is
            // harmless (it just recompiles against the unchanged catalog once) and keeps the rule
            // simple: any mutating DDL bumps the version.
            if mutating && out.is_ok() {
                plan_cache.bump_schema();
            }
            let _ = reply.send(out);
        }
        Cmd::ConstraintDdl { command, reply } => {
            let mutating = !matches!(command, ConstraintCommand::Show);
            let out = handle_constraint_ddl(coord, &command);
            // A successful mutating constraint DDL changes the schema (a new/dropped unique/existence/
            // node-key/property-type rule) — invalidate so no plan compiled under the old schema is
            // reused (`rmp` task #322).
            if mutating && out.is_ok() {
                plan_cache.bump_schema();
            }
            let _ = reply.send(out);
        }
        Cmd::Backup { reply } => {
            let out = handle_backup(coord);
            let _ = reply.send(out);
        }
        Cmd::Checkpoint { reply } => {
            let out = handle_checkpoint(coord);
            // A manual (admin-triggered) checkpoint that succeeds is proof reclamation is making
            // progress again, so clear **this engine's own** maintenance-degraded flag (`rmp` #435 —
            // never another engine's). On failure the flag is left as-is (an operator's manual probe
            // does not escalate the background streak).
            if out.is_ok() {
                maintenance_degraded.clear();
            }
            let _ = reply.send(out);
        }
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
            // Drain stragglers through `&mut`, then consume the coordinator for the final flush. An
            // in-flight index build is left durably `Populating`: it resumes and completes on the
            // next open via `TxnCoordinator::new`'s crash-recovery path (no force-drain needed —
            // re-deriving the candidate index is cheap and always correct).
            drain_inflight(coord, open, metrics, db);
            let coordinator = coordinator
                .take()
                .expect("INVARIANT: coordinator is Some at Shutdown");
            let out = harden_store(coordinator);
            // Retract this engine's whole contribution from the server-wide gauge (`rmp` #418); the
            // `ActiveTxnGauge` drop at loop exit would also do this, but publishing 0 here keeps the
            // gauge correct the instant the engine drains.
            active_txns.publish(0);
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
/// The closure captures `&mut TxnCoordinator` (and the open-tx map), which is `!UnwindSafe` because
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
    coord: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    plan_cache: &mut exec::EnginePlanCache,
    ticket: TxTicket,
    query: &str,
    params: Vec<(String, Value)>,
    auto_commit: bool,
    privileges: Option<EffectivePrivileges>,
    extensions: &Arc<graphus_cypher::extension::ExtensionRegistry>,
    dispatch: &read_pool::ReadDispatch<D, S>,
    readers_inflight: &mut u64,
    inflight: &mut Option<exec::InFlightInline>,
    result_buffer_capacity: usize,
    metrics: &Arc<Metrics>,
    db: &str,
    degraded: &EngineDegraded,
    clock: &Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    statement_timeout: Option<std::time::Duration>,
    reply: command::Reply<std::result::Result<RunReply, GraphusError>>,
) {
    use std::panic::{AssertUnwindSafe, catch_unwind};

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
            result_buffer_capacity,
            metrics,
            db,
            clock,
            statement_timeout,
            reply,
        )
    }));

    match result {
        Ok(outcome) => match outcome {
            // A read dispatched off-thread retires later (it is not yet finalised); track it so the
            // engine loop polls the retirement channel until it returns.
            exec::RunOutcome::OffThreadReader => *readers_inflight += 1,
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
    coord: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
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
    if let Some(tx) = open.remove(&ticket.0) {
        // Discard the entire half-applied write buffer (ARIES undo). A failure here is itself
        // best-effort: the txn is being torn down regardless and recovery would undo it anyway.
        //
        // `rmp` #409: the rollback is a fallible WAL-undo + buffer-pool-replay path that can *itself*
        // panic (the historical `store.rs` `RefCell`-double-borrow, the #359 pool replay class). That
        // recovery panic runs OUTSIDE `run_statement_isolated`'s `catch_unwind`, so without this guard
        // it would unwind the single engine thread — the exact `engine_gone`-forever failure #386 set
        // out to prevent, one panic deeper. Wrap it so a double-panic flags the engine degraded and
        // keeps the loop alive instead of killing the thread.
        let txn = tx.txn;
        // `Some(Ok(()))` = rollback ran and succeeded → account the abort. `Some(Err(_))` (a benign
        // rollback failure on a torn-down txn) and `None` (a caught recovery double-panic, which already
        // flagged the engine degraded inside `catch_recovery`) both need no extra action here.
        if let Some(Ok(())) = catch_recovery(metrics, degraded, "statement rollback", || {
            coord.rollback(txn)
        }) {
            metrics.record_abort_for(db);
        }
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
///
/// `begin_nanos` is the **monotonic**-clock reading at open (`rmp` #395/#477): the coordinator stamps
/// the active entry with it so the engine's age sweep can reap a transaction whose lifetime exceeds the
/// configured cap. `auto_commit` records whether this transaction backs a single auto-commit statement
/// (excluded from the age sweep) or an explicit `BEGIN … COMMIT` (the sweep's target).
fn open_tx<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    next_ticket: &mut u64,
    mode: AccessMode,
    auto_commit: bool,
    begin_nanos: u64,
) -> TxTicket {
    let txn = coordinator.begin_at(mode.isolation(), begin_nanos);
    *next_ticket += 1;
    let ticket = *next_ticket;
    open.insert(
        ticket,
        OpenTx {
            txn,
            mode,
            auto_commit,
        },
    );
    TxTicket(ticket)
}

/// Commits the explicit transaction `ticket`. Translates a coordinator commit into a [`RunSummary`]
/// and bumps the commit/abort metrics (a serialization-failure abort counts as an abort).
fn commit_tx<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    ticket: TxTicket,
    metrics: &Metrics,
    db: &str,
) -> Result<RunSummary> {
    let Some(tx) = open.remove(&ticket.0) else {
        return Err(GraphusError::Transaction(format!(
            "commit of unknown transaction {}",
            ticket.0
        )));
    };
    match coordinator.commit(tx.txn) {
        Ok(_commit_ts) => {
            metrics.record_commit_for(db);
            Ok(RunSummary::default())
        }
        Err(e) => {
            // The coordinator already rolled the victim back on a serialization failure; count it.
            metrics.record_abort_for(db);
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
    db: &str,
) -> Result<()> {
    let Some(tx) = open.remove(&ticket.0) else {
        // Idempotent no-op.
        return Ok(());
    };
    let out = coordinator.rollback(tx.txn);
    if out.is_ok() {
        metrics.record_abort_for(db);
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
    db: &str,
) {
    // Collect tickets first to avoid borrowing `open` across the mutation.
    let tickets: Vec<u64> = open.keys().copied().collect();
    for t in tickets {
        if let Some(tx) = open.remove(&t) {
            // Best-effort: a rollback error on one straggler should not block hardening the rest.
            if coordinator.rollback(tx.txn).is_ok() {
                metrics.record_abort_for(db);
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
/// `db_name` is the canonical database name this engine serves; it labels the per-database metric
/// series (`rmp` #463) so an operator can attribute transaction/latency/abort counts to a single tenant.
///
/// This convenience spawns an engine with **no per-statement timeout** (the prior behaviour); the
/// production path uses [`spawn_engine_with_timeout`] to install the configured per-statement CPU
/// budget (`rmp` #476).
///
/// # Errors
/// Returns the spawn error if the OS thread cannot be created, or the `build` error (e.g. an
/// integrity-check failure) if the store cannot be opened/verified.
pub fn spawn_engine<D, S, B>(
    db_name: Arc<str>,
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
    spawn_engine_with_timeout(
        db_name,
        build,
        engine_queue_capacity,
        result_buffer_capacity,
        reader_threads,
        metrics,
        clock,
        None,
        None,
    )
}

/// [`spawn_engine`] with an explicit per-statement execution **timeout** (`rmp` #476) and
/// maximum-transaction-age cap (`rmp` #477).
///
/// A finite `statement_timeout` installs a per-statement wall-clock deadline on the Cypher executor's
/// cancellation token, so a runaway query (a cartesian / variable-length-expansion bomb) is
/// cooperatively aborted instead of pinning the engine thread and starving co-tenants. A finite
/// `max_transaction_age` installs a background sweep that aborts any explicit transaction whose
/// lifetime exceeds it, freeing the MVCC GC watermark a long-running reader would otherwise pin
/// indefinitely (the idle-in-transaction DoS). Either `None` disables the respective guard (identical
/// to [`spawn_engine`]).
///
/// # Errors
/// As [`spawn_engine`].
#[allow(clippy::too_many_arguments)] // engine sizing + clock + per-statement/per-transaction budgets — all positional knobs
pub fn spawn_engine_with_timeout<D, S, B>(
    db_name: Arc<str>,
    build: B,
    engine_queue_capacity: usize,
    result_buffer_capacity: usize,
    reader_threads: usize,
    metrics: Arc<Metrics>,
    clock: Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    statement_timeout: Option<std::time::Duration>,
    max_transaction_age: Option<std::time::Duration>,
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
    let join = std::thread::Builder::new()
        .name("graphus-engine".to_owned())
        // A large stack: query compile/execute recurses on AST depth (`rmp` #473). See
        // [`QUERY_ENGINE_STACK_SIZE`] — the default ~2 MiB stack overflows on a legal at-the-limit
        // query, and a stack overflow aborts the whole process.
        .stack_size(QUERY_ENGINE_STACK_SIZE)
        .spawn(move || match build() {
            Ok(coordinator) => {
                // Startup succeeded: signal readiness, then run the loop until Shutdown. The loop
                // spawns the off-thread reader pool internally (`rmp` task #336, Slice 3b-ii).
                let _ = init_tx.send(Ok(()));
                run_engine_loop(
                    db_name,
                    coordinator,
                    rx,
                    result_buffer_capacity,
                    reader_threads,
                    loop_metrics,
                    loop_degraded,
                    loop_maintenance_degraded,
                    clock,
                    statement_timeout,
                    max_transaction_age,
                    // Bound on concurrently parked (suspended) inline statements (`rmp` #485 B1). The
                    // command channel is sized `engine_queue_capacity`, which in any sane config is ≥
                    // `max_concurrent_queries` (the admission limit that actually bounds how many
                    // statements can be parked at once), so this is a generous never-reached ceiling.
                    engine_queue_capacity,
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
            handle: EngineHandle::new(tx, metrics, degraded, maintenance_degraded),
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

#[cfg(test)]
mod maintenance_tests {
    use super::*;

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
        let mut coord = fresh_coord();
        let mut open: HashMap<u64, OpenTx> = HashMap::new();
        let mut next_ticket: u64 = 0;
        let cap = std::time::Duration::from_secs(60);
        let now = 61 * 1_000_000_000u64; // 61s in nanos — past the cap
        let clock = clock_at(now);
        let metrics = Arc::new(Metrics::new());
        let mut gauge = ActiveTxnGauge::new(Arc::clone(&metrics), Arc::from("test"));

        // Over-age explicit reader (begin at t=0 ⇒ age 61s ≥ cap).
        let aged_explicit = open_tx(
            &mut coord,
            &mut open,
            &mut next_ticket,
            AccessMode::Read,
            false,
            0,
        );
        // Over-age auto-commit statement (same age, but excluded from the sweep).
        let aged_auto = open_tx(
            &mut coord,
            &mut open,
            &mut next_ticket,
            AccessMode::Read,
            true,
            0,
        );
        // Young explicit reader (begin just now ⇒ age 1ns ≪ cap).
        let young_explicit = open_tx(
            &mut coord,
            &mut open,
            &mut next_ticket,
            AccessMode::Read,
            false,
            now - 1,
        );
        assert_eq!(coord.active_count(), 3);

        let mut coordinator = Some(coord);
        maybe_reap_aged(
            &mut coordinator,
            &mut open,
            &VecDeque::new(), // nothing parked inline
            Some(cap),
            &clock,
            &metrics,
            "test",
            &mut gauge,
        );
        let coord = coordinator
            .as_ref()
            .expect("coordinator survives the sweep");

        // Only the over-age explicit transaction was reaped (the `open` map is keyed by ticket).
        assert_eq!(coord.active_count(), 2, "exactly one transaction reaped");
        assert!(
            !open.contains_key(&aged_explicit.0),
            "the over-age explicit transaction must be removed from the open map"
        );
        assert!(
            open.contains_key(&aged_auto.0),
            "the over-age auto-commit statement must be left alone (transient / possibly mid-flight)"
        );
        assert!(
            open.contains_key(&young_explicit.0),
            "the young explicit transaction (under the cap) must be untouched"
        );
    }

    /// A disabled cap (`None`) is a no-op: even a transaction far past any sane cap stays open.
    #[test]
    fn disabled_cap_reaps_nothing() {
        let mut coord = fresh_coord();
        let mut open: HashMap<u64, OpenTx> = HashMap::new();
        let mut next_ticket: u64 = 0;
        let clock = clock_at(u64::MAX); // arbitrarily far in the future
        let metrics = Arc::new(Metrics::new());
        let mut gauge = ActiveTxnGauge::new(Arc::clone(&metrics), Arc::from("test"));

        let _ = open_tx(
            &mut coord,
            &mut open,
            &mut next_ticket,
            AccessMode::Read,
            false,
            0,
        );
        assert_eq!(coord.active_count(), 1);

        let mut coordinator = Some(coord);
        maybe_reap_aged(
            &mut coordinator,
            &mut open,
            &VecDeque::new(),
            None, // cap disabled
            &clock,
            &metrics,
            "test",
            &mut gauge,
        );
        assert_eq!(
            coordinator.as_ref().unwrap().active_count(),
            1,
            "a disabled cap must never reap"
        );
        assert_eq!(
            open.len(),
            1,
            "the open map is untouched when the cap is disabled"
        );
    }
}
