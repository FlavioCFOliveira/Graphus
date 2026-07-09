//! Morsel-driven intra-query parallelism for the bare-aggregate shape (`rmp` task #339, Slice 3a —
//! the first slice that makes a **single** heavy analytical query use more than one core).
//!
//! # The problem #339 solves (and how it differs from #352)
//!
//! `rmp` #352 added a "parallel label-property aggregation" tier, but it parallelized only the
//! **fold** over an owned, *serially-projected* column — and measured **zero** end-to-end gain,
//! because the real cost is the per-candidate MVCC-revalidating **read** (the `store.node` +
//! `node_has_label` + property-chain decode loop on the engine thread), not the trivial fold. Slice
//! 3a parallelizes **that read**: it splits the label's candidate-id vector into contiguous *morsels*
//! and reads each morsel concurrently on a dedicated worker pool, against the shared
//! [`Arc<ConcurrentBufferPool>`](graphus_bufpool::ConcurrentBufferPool) the `rmp` #337 Slice-1/2 work
//! made `Send + Sync`.
//!
//! # The substrate (verified, see the module docs of [`crate::read_source`] / `graphus-storage`)
//!
//! Each morsel runs over a **cheap clone** of the engine-thread-captured read surface:
//!
//! * a [`StoreReadView`] — `#[derive(Clone)]` over `(Arc<pool>, MetaSnapshot)`; cloning it is a handful
//!   of `Arc` refcount bumps, **no page copy**;
//! * a [`TokenSnapshot`] — `Clone` is one `Arc` bump;
//! * this query's pinned [`Snapshot`] (`Copy`) and a clone of its [`CommitRegistry`];
//! * its **own** fresh [`SsiReadBuffer`] (`Send`, no shared lock).
//!
//! The morsel reads through the already-source-generic `read_source::filter_label_candidates` /
//! `node_property` (the *same* code the live `RecordStoreGraph` and the off-thread `ReadOnlyGraph`
//! run), so a morsel produces **byte-identical** values and SIREAD markers to the serial path.
//!
//! # SSI markers (the serializability invariant)
//!
//! Every morsel records its per-candidate SIREAD markers into its **own** buffer (tagged with the one
//! query transaction). The **coarse** predicate footprint (`PredicateRead::Label` +
//! `mark_all_live_nodes`) is registered **once on the engine thread** when the bundle is built — exactly
//! as the serial `RecordStoreGraph::columnar_label_pass` / `scan_nodes_by_label` registers it. At
//! convergence the executor folds every morsel buffer into the statement's tracker via
//! [`SsiTracker::merge_read_buffer`](graphus_txn::SsiTracker::merge_read_buffer), which sorts, dedups
//! and replays through the existing `record_read`; those ops are commutative and idempotent, so the
//! merged conflict graph is the **union** of the morsels' markers, identical to the serial scan's marker
//! set (the Slice-3a equivalence test asserts that union byte-for-byte).
//!
//! # Type erasure (the key design problem, resolved)
//!
//! The executor's `Ctx.graph` is a `&mut dyn GraphAccess`, so the concrete `(D, S)` of the store are
//! **erased** at that boundary — yet the morsel runner needs them (the `StoreReadView<D, S>` is
//! generic). The resolution: an **object-safe** [`MorselSource`] trait (`Send + Sync`) that captures
//! `(D, S)` *inside* the implementor [`MorselView`] and exposes only `(D, S)`-free operations — read a
//! candidate slice, and `clone_box` (a cheap `Arc`-bump clone). The engine-thread bundle
//! [`MorselLabelScan`] then holds a `Box<dyn MorselSource>` plus the plain candidate vector, so it is a
//! concrete, `(D, S)`-free, `Send` value the executor can partition and dispatch without ever naming
//! `D`/`S`. `clone_box` preserving the cheap-clone property is what keeps per-morsel setup ~free.
//!
//! # Scope (Slice 3a only)
//!
//! Only the bare-aggregate shape (`MATCH (n:Label) RETURN <exact-agg>(n.p)`): scan → exact/associative
//! aggregate, with the read parallelized across morsels and the (trivial) fold + converge on the engine
//! thread. Filter/project rows-out, ORDER BY / top-k, and expand/FoF are Slices 3b/3c. The morsel tier
//! runs on a **shared analytics** pool ([`analytics_pool`], `rmp` task #376 — never the global `rayon`
//! pool; GDS centrality now shares *this same* pool via [`run_on_analytics_pool`] so the morsel + GDS
//! peak runnable-thread sum is bounded to one `min(N,16)`-thread pool rather than `2 × N`).
//!
//! On a `rmp` #336 off-thread reader-pool worker the fan-out width is **adaptive** (`rmp` tasks #377 /
//! #575-g.1): the engine dispatch site, which knows `readers_inflight`, chooses a width of
//! `floor(analytics_pool_threads / (readers_inflight + 1))` via [`reader_pool_morsel_width`] and carries
//! it into [`ReaderPoolWorkerGuard::enter_with_width`], so [`Ctx.morsel_threads`](crate::executor) at
//! cursor-open on that worker is that width. A **lone** heavy read (reader pool otherwise idle) engages
//! the **full** analytics pool (all cores — the `rmp` #575 win, previously lost to the `rmp` #377 v1 hard
//! clamp-to-1). The `+ 1` counts the arriving read itself, so a read that starts while `K` others are
//! in flight fans out to `<= P/(K+1)`, and no single read ever oversubscribes the pool on its own. The
//! **hard** no-oversubscription guarantee, though, comes from the substrate, not the arithmetic: the
//! analytics pool is a **fixed `P`-thread** `rayon` pool (`rmp` #377), so the total number of *runnable*
//! morsel threads is capped at `P` for any mix of widths — reads arriving sequentially see decreasing
//! `readers_inflight` and so take widths `P, P/2, P/3, …` whose instantaneous sum can exceed `P`, but that
//! only enqueues extra rayon tasks behind the `P` threads (finer fan-out granularity / scheduling
//! interference), never more concurrent OS threads. Width collapses to `1` once `readers_inflight >= P`
//! (exactly the #377 v1 clamp: each read serial on its own reader thread). The engine-thread heavy-query
//! path (never a reader-pool worker) always keeps the full morsel fan-out.

use std::cell::Cell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use graphus_core::error::GraphusError;
use graphus_core::{TxnId, Value};
use graphus_storage::{StoreReadView, TokenSnapshot};
use graphus_txn::{CommitRegistry, PredicateRead, Snapshot, SsiReadBuffer};

use graphus_io::BlockDevice;
use graphus_wal::LogSink;

use crate::ast::{Expr, RelDirection, RelType};
use crate::binding::BoundParameters;
use crate::eval::eval;
use crate::function_registry::FunctionSet;
use crate::graph_access::{ExpandDirection, GraphAccess, NodeId};
use crate::logical::{ProjectionColumn, SortKey, Var};
use crate::read_only_graph::ReadOnlyGraph;
use crate::read_source::{self, ReadSink, ReadViewSource, VisCtx};
use crate::runtime::{NodeRef, RelRef, Row, RowValue};
use crate::statement_clock::StatementClock;

/// How many candidates / anchors a morsel worker processes between two wall-clock **deadline** polls
/// (`rmp` #476): the per-statement timeout's cooperative safe point inside a (potentially large) morsel.
/// `Instant::now()` is read only once per this many rows, so it never dominates the per-row work, yet a
/// runaway morsel still abandons within this many rows of the deadline — keeping cancellation prompt
/// across cores. A power of two so the gate is a mask. The morsel tier is OFF in the deterministic engine
/// (`morsel_threads <= 1`), so this wall-clock poll never perturbs DST determinism.
const MORSEL_DEADLINE_POLL_STRIDE: u64 = 1024;

/// Whether the per-statement wall-clock deadline (if any) has elapsed (`rmp` #476). A `None` deadline (no
/// configured timeout — and every deterministic / test path) returns `false` without reading the clock.
#[inline]
fn deadline_exceeded(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() >= d)
}

/// The error a morsel worker records when the per-statement deadline elapses mid-morsel (`rmp` #476).
/// Like every other morsel error it makes the executor discard the parallel result and fall back to the
/// serial pipeline, whose first per-row safe point re-observes the elapsed deadline and surfaces
/// [`crate::executor::ExecError::Cancelled`] — so the user sees a clean cancellation, never this string.
fn statement_timeout_error() -> GraphusError {
    GraphusError::Runtime("query cancelled by statement timeout".to_owned())
}

// =================================================================================================
// The knob — process-global effective morsel-thread count
// =================================================================================================

/// The effective morsel-thread count, set once on engine startup from
/// `AdmissionConfig::morsel_parallelism()` and read by the tier. `0` is the un-initialised sentinel
/// meaning "default" → [`morsel_threads`] reports `1` (fully serial), so the library / `MemGraph` /
/// doctest path is serial unless a caller (the server, or a test/bench) explicitly opts in. Note the
/// **server** does opt in by default: it resolves `AdmissionConfig::morsel_parallelism = 0` (the config
/// default) to `min(available_parallelism(), 16)` at startup, so a production multi-core server has the
/// morsel tier **enabled by default** (every ineligible query shape still declines to serial via the
/// tier's exhaustive gate). A determinism-sensitive deployment (Raspberry Pi, a bit-repro run) pins the
/// knob to `1`; DST stays deterministic regardless because it drives `LocalEngine` inline, never the
/// server config path.
///
/// A process-global is the same shape the existing `rmp` #352 tier already reads
/// (`rayon::current_num_threads()`); the per-statement [`Ctx.morsel_threads`](crate::executor) field
/// is populated from it at cursor-open so the value flows in-band to the tier.
static MORSEL_THREADS: AtomicUsize = AtomicUsize::new(0);

/// Sets the process-global effective morsel-thread count (`rmp` task #339). Called once on engine
/// startup with the resolved `AdmissionConfig::morsel_parallelism()` (and by tests/benches that want
/// to drive the tier). `1` keeps the tier fully serial (it early-returns `None`); `>= 2` enables
/// morsel parallelism with that worker count.
pub fn set_morsel_threads(threads: usize) {
    MORSEL_THREADS.store(threads, Ordering::Relaxed);
}

thread_local! {
    /// Per-thread **intended intra-query morsel width** for a `rmp` #336 off-thread reader-pool worker
    /// (`rmp` tasks #377 / #575-g.1). `0` is the sentinel "this thread is **not** a reader-pool worker"
    /// (the engine thread, a GDS rayon worker, a test thread); `>= 1` means "this thread is a reader-pool
    /// worker whose reads should fan out to **this many** morsel workers".
    ///
    /// The reader pool runs `AccessMode::Read` auto-commit statements on up-to-`min(N,16)` worker
    /// threads, concurrently with the engine thread, so *separate* reads scale across cores
    /// (cross-statement parallelism). The morsel tier (`rmp` #339) makes a *single* heavy read scale
    /// across cores (intra-statement parallelism) by fanning a scan onto the shared analytics pool.
    /// Engaging both **without a bound** is what `rmp` #377 guarded against: `K` concurrent large reads,
    /// each fanning `min(N,16)` morsel tasks onto the *shared* `min(N,16)`-thread analytics pool, is
    /// `K × min(N,16)` tasks for `min(N,16)` cores. `rmp` #377 v1 fixed this by clamping every reader-pool
    /// read to a **single** morsel (serial-within-statement) — which left a *lone* heavy read (the reader
    /// pool otherwise idle) stuck on one core, since it, too, was clamped.
    ///
    /// **The `rmp` #575-g.1 refinement (adaptive width):** instead of a hard clamp to `1`, the engine
    /// **dispatch site** — which knows `readers_inflight` — computes an intended width of
    /// `floor(analytics_pool_threads / (readers_inflight + 1))` (see [`reader_pool_morsel_width`]) and
    /// carries it into this cell via [`ReaderPoolWorkerGuard::enter_with_width`]. A lone read
    /// (`readers_inflight == 0`) gets the **full** pool → all cores; a read that starts while `K` others
    /// are already in flight gets `<= P/(K+1)`, so no single read oversubscribes the pool on its own, now
    /// without starving the lone read. At `readers_inflight >= P` the width collapses to `1`, reproducing
    /// `rmp` #377 v1 **exactly** (each read serial on its own reader thread, no fan-out overhead). The
    /// no-oversubscription guarantee is enforced by the **substrate**, not the arithmetic: the analytics
    /// pool is a **fixed** `P`-thread `rayon` pool, so the *runnable* thread count is capped at `P` for
    /// **any** mix of widths. (Reads arriving sequentially see decreasing `readers_inflight` and take widths
    /// `P, P/2, P/3, …` whose instantaneous sum can exceed `P`; that only queues extra rayon tasks behind
    /// the `P` threads — finer fan-out granularity and cross-read scheduling interference — never more OS
    /// threads.)
    static READER_POOL_MORSEL_WIDTH: Cell<usize> = const { Cell::new(0) };
}

/// An RAII guard that marks the current thread as a `rmp` #336 reader-pool worker for its lifetime,
/// carrying the **intended intra-query morsel width** the dispatch site chose (`rmp` tasks #377 /
/// #575-g.1), and restoring the prior value on drop. The server's reader `worker_loop` holds one of
/// these around each [`run_read_task`](../../graphus_server) so every `Cursor::open` on that thread reads
/// `morsel_threads() == width` (the adaptive fan-out); the engine thread never holds one, so its heavy
/// queries keep the full morsel fan-out.
///
/// Restoring the prior value (rather than unconditionally clearing) keeps the guard correct under
/// nesting and panic-unwind: a worker thread is reused across many tasks, and a panic inside
/// `run_read_task` still runs the guard's `Drop`, so the width never leaks to the next task on that
/// thread.
#[must_use = "the guard restores the reader-pool morsel width when dropped; bind it to a name"]
pub struct ReaderPoolWorkerGuard {
    prev: usize,
}

impl ReaderPoolWorkerGuard {
    /// Marks the current thread as a reader-pool worker whose reads fan out to **one** morsel worker
    /// (serial-within-statement — the `rmp` #377 v1 hard clamp), until the returned guard is dropped.
    /// Equivalent to [`enter_with_width(1)`](Self::enter_with_width); retained for the `rmp` #377
    /// suppression unit tests and any caller that wants the unconditional clamp.
    pub fn enter() -> Self {
        Self::enter_with_width(1)
    }

    /// Marks the current thread as a reader-pool worker whose reads fan out to `width` morsel workers
    /// (`rmp` task #575-g.1), until the returned guard is dropped. `width` is floored at `1` (a reader
    /// worker is always flagged, so [`is_reader_pool_worker`] stays `true`; `width == 1` means serial
    /// within the statement). The server's reader `worker_loop` passes the dispatch-computed
    /// [`reader_pool_morsel_width`] here.
    pub fn enter_with_width(width: usize) -> Self {
        let prev = READER_POOL_MORSEL_WIDTH.with(|f| f.replace(width.max(1)));
        Self { prev }
    }
}

impl Drop for ReaderPoolWorkerGuard {
    fn drop(&mut self) {
        READER_POOL_MORSEL_WIDTH.with(|f| f.set(self.prev));
    }
}

/// Whether the current thread is a `rmp` #336 off-thread reader-pool worker (`rmp` task #377). Read by
/// [`morsel_threads`] to apply the adaptive per-read morsel width on the reader-pool path, and by the
/// `ext.readerPoolWorker` dispatch-oracle probe (`rmp` #546).
#[must_use]
pub fn is_reader_pool_worker() -> bool {
    READER_POOL_MORSEL_WIDTH.with(Cell::get) != 0
}

/// The effective morsel-thread count (`rmp` task #339): the value [`set_morsel_threads`] last stored,
/// or `1` (fully serial) when never set (the un-initialised `0` sentinel). Read at every `Ctx`
/// construction to populate `Ctx.morsel_threads`.
///
/// **Reader-pool adaptive width (`rmp` tasks #377 / #575-g.1):** when the calling thread is an off-thread
/// reader-pool worker ([`is_reader_pool_worker`]), this reports the **intended width** the dispatch site
/// chose (carried in [`ReaderPoolWorkerGuard`]), **capped by the configured count** — so a lone heavy read
/// engages the full pool while `K` concurrent reads share it without exceeding its capacity, and a
/// determinism-pinned deployment (configured count `1`) still forces every reader-pool read serial. See
/// [`ReaderPoolWorkerGuard`] and [`reader_pool_morsel_width`].
#[must_use]
pub fn morsel_threads() -> usize {
    let configured = match MORSEL_THREADS.load(Ordering::Relaxed) {
        0 => 1,
        n => n,
    };
    match READER_POOL_MORSEL_WIDTH.with(Cell::get) {
        0 => configured, // engine thread / non-reader: full configured width
        width => width.min(configured).max(1), // reader-pool worker: adaptive width, capped by the knob
    }
}

/// The intended intra-query morsel width for a read about to be **dispatched to the reader pool**, given
/// how many reads are already in flight (`rmp` task #575-g.1). Computed on the engine thread at dispatch
/// and carried into the worker's [`ReaderPoolWorkerGuard::enter_with_width`].
///
/// `floor(analytics_pool_threads / (readers_inflight + 1))`, floored at `1`: the `+ 1` counts the read
/// being dispatched, so a **lone** read (`readers_inflight == 0`) gets the whole analytics pool (all
/// cores), and a read starting while `K` others are already in flight gets `<= P/(K+1)` — so no single
/// read over-fans the shared analytics pool on its own. At `readers_inflight >= P` the width is `1`,
/// reproducing the `rmp` #377 v1 clamp exactly (each read serial on its own reader thread). When the
/// morsel tier is globally disabled (configured count `<= 1` — e.g. a determinism-pinned Raspberry Pi),
/// the width is `1` regardless, so a reader-pool read stays serial.
///
/// The **hard** no-oversubscription guarantee is the substrate's, not this arithmetic's: the analytics
/// pool is a **fixed** `P`-thread `rayon` pool, so the runnable morsel-thread count is capped at `P` for
/// any mix of widths. Reads that arrive sequentially each see a smaller `readers_inflight` than the final
/// concurrency and so take widths `P, P/2, P/3, …` whose *instantaneous* sum can exceed `P` — that merely
/// enqueues extra rayon tasks behind the `P` threads (finer granularity / scheduling interference), never
/// more OS threads. Counting **all** inflight reads (not just the morsel-eligible ones) is deliberately
/// conservative: a heavy read concurrent with several trivial point-lookups gets a smaller width than it
/// strictly needs, which only ever *under*-fans.
#[must_use]
pub fn reader_pool_morsel_width(readers_inflight: u64) -> usize {
    let configured = match MORSEL_THREADS.load(Ordering::Relaxed) {
        0 => 1,
        n => n,
    };
    if configured <= 1 {
        return 1; // morsel globally disabled (determinism pin): keep reader-pool reads serial.
    }
    let pool = analytics_pool_threads().max(1) as u64;
    let concurrent = readers_inflight.saturating_add(1);
    let width = (pool / concurrent).max(1);
    (width as usize).min(configured).max(1)
}

/// The minimum estimated label cardinality at which the morsel tier is even attempted (`rmp` task
/// #339). Below this the dispatch + per-morsel setup cannot recover its fixed cost, so the serial
/// vectorized / Volcano tiers — whose setup is ~free — win. Tuned to the same crossover the `rmp` #352
/// tier uses (`PARALLEL_AGG_MIN_ROWS`); the morsel win is on the *large* analytical scans #339 targets.
///
/// This is the **default**; [`morsel_min_rows`] returns the effective value, which a test / bench can
/// lower via [`set_morsel_min_rows`] (e.g. to `0` so the openCypher TCK exercises the morsel ordering
/// path on its *small* fixtures, proving conformance flows through the parallel converge — not just past
/// the cardinality gate).
pub const MORSEL_MIN_ROWS: f64 = 50_000.0;

/// The effective minimum-rows gate override (`rmp` task #339, Slice 3b): `u64::MAX` is the un-initialised
/// sentinel meaning "use [`MORSEL_MIN_ROWS`]". A test/bench lowers it (e.g. to `0`) so the morsel tier
/// engages on small inputs; production never sets it, so the tuned default stands.
static MORSEL_MIN_ROWS_OVERRIDE: AtomicU64 = AtomicU64::new(u64::MAX);

/// Sets the effective minimum-rows gate (`rmp` task #339, Slice 3b): the morsel tiers engage only when the
/// estimated label cardinality is at least this. Used by the TCK / equivalence runs to force the morsel
/// path on small inputs (`0`), and by benches. Production leaves it unset (the [`MORSEL_MIN_ROWS`] default
/// stands).
pub fn set_morsel_min_rows(rows: u64) {
    MORSEL_MIN_ROWS_OVERRIDE.store(rows, Ordering::Relaxed);
}

/// The effective minimum-rows gate (`rmp` task #339, Slice 3b): the [`set_morsel_min_rows`] override if
/// set, else the [`MORSEL_MIN_ROWS`] default. Read by every morsel tier's cardinality gate.
#[must_use]
pub fn morsel_min_rows() -> f64 {
    match MORSEL_MIN_ROWS_OVERRIDE.load(Ordering::Relaxed) {
        u64::MAX => MORSEL_MIN_ROWS,
        n => n as f64,
    }
}

/// The minimum contiguous morsel size (`rmp` task #339): a morsel never covers fewer than this many
/// candidate ids, so a small label never fans out into a swarm of tiny tasks whose scheduling cost
/// dwarfs their work. The adaptive morsel size is `max(MORSEL_MIN_CHUNK, n / (threads * 4))` — the `* 4`
/// over-subscribes so work-stealing balances a skewed candidate distribution.
pub const MORSEL_MIN_CHUNK: usize = 4096;

// =================================================================================================
// The shared analytics pool (morsel fan-out + GDS)
// =================================================================================================

/// The configured analytics-pool worker count (`rmp` task #376): `0` is the un-initialised sentinel
/// meaning "default" → [`analytics_pool_threads`] computes `min(available_parallelism(), 16)`. The
/// server sets this once at startup via [`set_analytics_pool_threads`] from the resolved config; a
/// determinism-sensitive deployment may pin it. Independent of [`MORSEL_THREADS`]: the morsel
/// *enablement* knob (`1` = serial-within-statement) must not shrink the pool GDS shares, or pinning
/// morsel to serial would also serialise GDS.
static ANALYTICS_POOL_THREADS: AtomicUsize = AtomicUsize::new(0);

/// Sets the process-global analytics-pool worker count (`rmp` task #376), shared by the morsel tier and
/// GDS. Called once on engine startup with the resolved core-bounded width (`min(N, 16)`); `0` restores
/// the computed default. Has no effect after the pool is first built (see [`analytics_pool`]).
pub fn set_analytics_pool_threads(threads: usize) {
    ANALYTICS_POOL_THREADS.store(threads, Ordering::Relaxed);
}

/// The effective analytics-pool worker count (`rmp` task #376): the [`set_analytics_pool_threads`]
/// value, or — when unset (`0`) — `min(available_parallelism(), 16)`, the same core-bounded default the
/// reader and morsel pools use. This is the **single** compute-thread budget the morsel fan-out and GDS
/// both draw from, so their peak runnable threads is `≈` core count rather than `2 ×` it.
#[must_use]
pub fn analytics_pool_threads() -> usize {
    match ANALYTICS_POOL_THREADS.load(Ordering::Relaxed) {
        0 => std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(16),
        n => n,
    }
}

/// The dedicated [`rayon::ThreadPool`] the morsel fan-out **and** GDS run on (`rmp` tasks #339, #376),
/// built lazily on first engagement and sized to [`analytics_pool_threads`].
///
/// **Not** the global `rayon` pool, and **shared** between the two analytical consumers. Before `rmp`
/// #376 GDS used the *global* pool (`= N`) while the morsel tier used this dedicated pool (`= min(N,16)`)
/// and the `rmp` #336 reader pool was a third `min(N,16)`-thread `std::thread` pool — `≈ 3 × N` runnable
/// compute threads under a mixed analytical + GDS + read-storm workload, causing scheduler thrash and
/// degraded tail latency. Routing GDS onto this same pool (via
/// [`run_on_analytics_pool`]) bounds the morsel + GDS sum to one `min(N,16)`-thread pool; with the `rmp`
/// #377 reader-pool morsel suppression the reader pool never *also* drives this pool, so the peak is
/// `≈ N` cores.
static ANALYTICS_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

/// The shared analytics pool, built (once) sized to [`analytics_pool_threads`]. Process-global and sized
/// at first use; a later knob change does not resize it (the engine sets the knob before the first query,
/// so it is fixed for the process lifetime in production).
fn analytics_pool() -> &'static rayon::ThreadPool {
    ANALYTICS_POOL.get_or_init(|| {
        let threads = analytics_pool_threads().max(1);
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("graphus-analytics-{i}"))
            .build()
            .unwrap_or_else(|_| {
                // A pool build failure is exceedingly unlikely (only on resource exhaustion); fall back
                // to a single-thread pool so the tier still produces a correct (serial) result rather
                // than panicking the engine thread.
                rayon::ThreadPoolBuilder::new()
                    .num_threads(1)
                    .build()
                    .expect("INVARIANT: a 1-thread rayon pool always builds")
            })
    })
}

/// Runs `op` on the shared analytics pool (`rmp` task #376), so any `rayon` parallelism inside it (e.g.
/// GDS centrality's `into_par_iter`) executes on that **bounded** pool rather than the global one.
///
/// # Determinism (inviolable — GDS must be bit-identical regardless of thread count)
///
/// `rayon::ThreadPool::install` only changes *which* worker threads run the parallel work; it does not
/// change the work decomposition or the reduction. The GDS centrality algorithms are written so their
/// result is independent of the worker count: closeness writes each source's score into its **own**
/// result slot (a `map` + `collect` — order-preserving, each slot written once), and Brandes betweenness
/// reduces per-task private accumulators by **element-wise f64 addition** whose per-source contributions
/// are exact in f64 (see `graphus-gds` `algo::centrality` docs). So the pool a `par_iter` lands on is
/// irrelevant to the *value*; only the *threads doing the work* change. Determinism is preserved.
///
/// # No deadlock under nested fan-out
///
/// `install` runs `op` on a pool worker and **blocks the calling thread** until `op` returns, but it does
/// not consume a pool worker for the duration — and rayon's `join`/`par_iter` use work-stealing, not
/// blocking handoff, so a task already on this pool that *itself* fans out (nested `par_iter`) is
/// serviced by the same workers via stealing without a thread-starvation deadlock. The morsel tier's own
/// `install` sites and a GDS `install` are therefore safe to share one pool.
pub fn run_on_analytics_pool<R: Send>(op: impl FnOnce() -> R + Send) -> R {
    analytics_pool().install(op)
}

/// A process-global count of how many times the morsel tier has **fanned out** onto the analytics pool
/// (`rmp` task #377): incremented once per [`install_morsel_fanout`] call (i.e. per morsel-parallelised
/// scan), *not* by GDS's [`run_on_analytics_pool`]. It exists so a test can assert the pool-on-pool
/// invariant *directly* and deterministically: with the reader-pool morsel suppression in force, `K`
/// concurrent large reads dispatched to the reader pool must produce **zero** morsel engagements (each
/// read is cross-statement-parallel, never intra-statement-parallel), so no read fans `min(N,16)` morsel
/// tasks onto the shared `min(N,16)`-thread pool. The counter is a `Relaxed` atomic on the *cold* fan-out
/// path (a heavy scan), so it adds no measurable cost to the hot per-row path.
static MORSEL_FANOUTS: AtomicU64 = AtomicU64::new(0);

/// The number of morsel fan-outs since process start (`rmp` task #377) — see [`MORSEL_FANOUTS`]. A test
/// snapshots this before and after a workload to assert the morsel tier engaged exactly as expected
/// (e.g. `0` times on the reader-pool path).
#[must_use]
pub fn morsel_fanout_count() -> u64 {
    MORSEL_FANOUTS.load(Ordering::Relaxed)
}

/// Runs a morsel fan-out `op` on the shared analytics pool, counting the engagement (`rmp` tasks #339,
/// #377). Every morsel tier runner routes its `analytics_pool().install` through here so the
/// [`MORSEL_FANOUTS`] counter sees exactly the morsel engagements (and GDS, via
/// [`run_on_analytics_pool`], is excluded).
fn install_morsel_fanout<R: Send>(op: impl FnOnce() -> R + Send) -> R {
    MORSEL_FANOUTS.fetch_add(1, Ordering::Relaxed);
    analytics_pool().install(op)
}

// =================================================================================================
// MorselSource — the object-safe, (D, S)-erased read surface a morsel runs over
// =================================================================================================

/// The result of reading one morsel of label candidates (`rmp` task #339): the surviving nodes'
/// aggregate-column values, the morsel's `count(*)` contribution, its accumulated SIREAD markers, and
/// the first read error (if any).
///
/// The executor folds `values` into the aggregate accumulators and folds `buffer` into the statement's
/// SSI tracker at convergence. A non-`None` `error` aborts the parallel path (the executor captures it
/// and falls back to the serial tier, which re-registers markers identically).
#[must_use]
pub struct MorselReadOutcome {
    /// The aggregate-column value of every surviving (label-carrying, visible, property-present) node
    /// in this morsel, in candidate order. The executor folds these with the shared `Accumulator`.
    pub values: Vec<Value>,
    /// The number of visible label-carrying nodes in this morsel (the morsel's `count(*)` contribution,
    /// counting every matched node whether or not it holds the aggregate property).
    pub label_matches: usize,
    /// This morsel's accumulated SIREAD markers (per-candidate `note_read`), tagged with the query txn.
    /// Folded into the statement tracker at convergence via `SsiTracker::merge_read_buffer`.
    pub buffer: SsiReadBuffer,
    /// The first storage / deferred-feature error the morsel hit, or `None`. While set, the morsel's
    /// `values`/`label_matches` are untrustworthy and the parallel path must be abandoned.
    pub error: Option<GraphusError>,
}

impl MorselReadOutcome {
    /// An empty, **timeout-abandoned** outcome (`rmp` #476): the per-statement deadline elapsed before
    /// this morsel started, so it carries no values and a timeout error tagged `txn`, which the executor
    /// treats like any other morsel error — discard the parallel result and fall back to the serial
    /// pipeline, whose first per-row safe point surfaces a clean [`ExecError::Cancelled`]. The empty
    /// buffer is dropped (the executor never folds the buffers of an errored morsel).
    fn cancelled(txn: TxnId) -> Self {
        Self {
            values: Vec::new(),
            label_matches: 0,
            buffer: SsiReadBuffer::new(txn),
            error: Some(statement_timeout_error()),
        }
    }
}

/// The result of reading + filtering + projecting one morsel of label candidates (`rmp` task #339,
/// Slice 3b): the surviving (visible, label-carrying, filter-`TRUE`) candidates' **projected rows** in
/// candidate order, this morsel's accumulated SIREAD markers, and the first read / evaluation error
/// (if any).
///
/// The executor **concatenates** the `rows` of the morsels in ascending source-index (`lo`) order at
/// convergence (reproducing the serial scan→filter→project candidate order byte-for-byte), and folds
/// `buffer` into the statement's SSI tracker exactly as the Slice-3a aggregate path does. A non-`None`
/// `error` aborts the parallel path (the executor discards every morsel's rows + buffers and falls back
/// to the serial pipeline, which re-registers markers and re-hits the fault identically).
#[must_use]
pub struct MorselRowsOutcome {
    /// The projected rows of every surviving candidate in this morsel, **in candidate order** (so the
    /// ascending-`lo` concat of the morsels reproduces the serial candidate order). For a `Sort` /
    /// `TopN` converge the morsel pre-sorts these by [`keys`](Self::keys) (stably, preserving candidate
    /// order on ties) before the engine-thread stable k-way merge.
    pub rows: Vec<Row>,
    /// The pre-computed sort-key vector of each row in [`rows`](Self::rows), **parallel** (same index,
    /// same order) — empty when no `Sort` / `TopN` sits above (Shape A, contiguous concat). Computed on
    /// the worker by evaluating the sort-key expressions against the *projected* row, so the
    /// engine-thread merge needs no graph access. When non-empty, `rows` is already stably sorted by
    /// these keys within the morsel (ties keep candidate order).
    pub keys: Vec<Vec<RowValue>>,
    /// This morsel's accumulated SIREAD markers (per-candidate `note_read` plus any per-row property
    /// reads the filter / projection / sort-key evaluation performed), tagged with the query txn. Folded
    /// into the statement tracker at convergence via `SsiTracker::merge_read_buffer`.
    pub buffer: SsiReadBuffer,
    /// The first storage / deferred-feature / evaluation error the morsel hit, or `None`. While set, the
    /// morsel's `rows` are untrustworthy and the parallel path must be abandoned.
    pub error: Option<GraphusError>,
}

/// One contiguous-anchor morsel's contribution to a **traversal-heavy** query (`rmp` task #339,
/// Slice 3c — the final slice, parallelizing the per-anchor `ExpandAll` of degree / friends / FoF /
/// mutual shapes), in one of two forms depending on the shape above the expand:
///
/// * **Aggregate-over-expand** (`MATCH (a:L)-->(b) RETURN count(b) | count(*)`, the degree shape) —
///   only [`partial_count`](Self::partial_count) is populated: the sum, over every anchor in this
///   morsel's slice, of the number of relationship-expansion rows the serial `Operator::Expand`
///   would produce for that anchor (i.e. the anchor's matching degree, after self-loop dedup +
///   relationship-isomorphism + direction filtering). The executor sums the morsels' counts (an
///   order-independent combine). `rows` is empty.
/// * **Rows-over-expand** (`MATCH (a:L)-[r]->(b) RETURN <per-row projection of a/r/b>`, the
///   neighbour-collect shape) — [`rows`](Self::rows) holds the **projected** expansion rows of every
///   anchor in this morsel's slice, **in (anchor, then per-anchor expansion) order**, so an
///   ascending-`lo` contiguous concat reproduces the serial scan→expand→project row sequence exactly.
///   `partial_count` is `0`.
///
/// In both forms [`buffer`](Self::buffer) accumulates this morsel's SIREAD markers — the per-anchor
/// label-scan markers AND, crucially, the relationship-pattern predicate marker + every per-edge
/// marker the per-anchor [`GraphAccess::expand`] records (byte-identical to serial, since the morsel
/// drives the same lifted `read_source::expand` body over a [`ReadOnlyGraph`]). A non-`None`
/// [`error`](Self::error) aborts the parallel path (the executor discards every morsel's rows, counts,
/// and buffers and re-runs the serial pipeline, which re-registers the markers and re-hits the fault
/// identically).
#[must_use]
pub struct MorselExpandOutcome {
    /// The projected expansion rows of every anchor in this morsel's slice (rows-over-expand shape),
    /// **in (anchor, then per-anchor expansion) order** — empty for the aggregate-over-expand shape.
    pub rows: Vec<Row>,
    /// This morsel's `count(b)` / `count(*)`-over-expand contribution (aggregate-over-expand shape):
    /// the total number of expansion rows the serial path would produce over this morsel's anchors —
    /// `0` for the rows-over-expand shape.
    pub partial_count: i64,
    /// This morsel's accumulated SIREAD markers (per-anchor label-scan `note_read` + the per-anchor
    /// `expand`'s relationship-pattern predicate + per-edge `note_read`), tagged with the query txn.
    /// Folded into the statement tracker at convergence via `SsiTracker::merge_read_buffer`.
    pub buffer: SsiReadBuffer,
    /// The first storage / evaluation error the morsel hit, or `None`. While set, the morsel's
    /// `rows` / `partial_count` are untrustworthy and the parallel path must be abandoned.
    pub error: Option<GraphusError>,
}

/// The post-work a Slice-3c [`expand_morsel`](MorselSource::expand_morsel) performs over each
/// expansion row, distinguishing the **aggregate-over-expand** (degree / `count`) shape from the
/// **rows-over-expand** (neighbour-collect) shape (`rmp` task #339, Slice 3c).
pub enum MorselExpandPostWork<'p> {
    /// Count the expansion rows (the degree shape: `RETURN count(b)` / `count(*)`). The morsel sums
    /// the per-anchor matching degree into its `partial_count`; no row is materialized.
    Count,
    /// Project each expansion row through these per-row columns (the neighbour-collect shape:
    /// `RETURN <projection of a / r / b>`). Every column must be **pure per-row**
    /// ([`is_pure_per_row_expr`]) — checked on the engine thread — so the contiguous concat is
    /// provably serial-identical. The expansion row binding is the serial one: the anchor `from`, the
    /// relationship var, and the far-endpoint `to`.
    Project(&'p [ProjectionColumn]),
}

/// The single-hop `ExpandAll` pattern + post-work a Slice-3c [`expand_morsel`] reproduces per anchor
/// (`rmp` task #339, Slice 3c). All fields mirror the serial `Operator::Expand` plan pieces, captured
/// once on the engine thread and borrowed by every morsel (no per-morsel clone of the AST).
///
/// Scope (first cut): a **fixed-length, fresh** single hop — `range` is `None` (no variable-length
/// `*m..n`) and the relationship variable is **not** pre-bound on the input. The executor recognizer
/// declines anything outside this shape, so the morsel only ever runs the
/// [`expand_into_pending`](crate::executor) equivalent.
pub struct MorselExpandPlan<'p> {
    /// The anchor (scanned-node) variable bound by the label scan — the `from` of the expand.
    pub from: &'p Var,
    /// The relationship variable the traversal binds.
    pub relationship: &'p Var,
    /// The far-endpoint variable the traversal binds.
    pub to: &'p Var,
    /// The traversal direction relative to the anchor.
    pub direction: RelDirection,
    /// The relationship-type alternatives; empty means "any type".
    pub types: &'p [RelType],
    /// The post-work over each expansion row (count, or per-row projection).
    pub post: MorselExpandPostWork<'p>,
}

/// The recognized **bare grouped-aggregation** shape the `rmp` #360 grouped morsel tier reproduces per
/// morsel: `MATCH (n:Label) RETURN <bare group keys>, <bare aggregates>` (no interposed Filter / Expand,
/// no DISTINCT projection, no composite aggregate columns). Borrows the plan columns (no AST clone) so
/// the morsel evaluates the *identical* expressions the serial `aggregate_rows` would.
///
/// The recognizer (engine thread) guarantees: each `group_keys[i].expr` and each `aggregates[j]`'s
/// single argument is **pure per-row** ([`is_pure_per_row_expr`]); each aggregate column is a *bare*
/// aggregate (no surrounding arithmetic) over the scan var; and the admitted aggregate kinds are exactly
/// the **mergeable** ones (`count(*)` / `count` / `sum` / `min` / `max` / `collect`, with `DISTINCT`
/// only on `count`/`collect`) — `avg` and the percentiles are excluded (their parallel merge is not
/// provably bit-identical to serial), so any query carrying one declines to the serial path.
pub struct MorselGroupSpec<'p> {
    /// The scanned node variable (the `n` of `MATCH (n:Label)`), bound to each survivor as the lone row
    /// binding the keys / aggregate arguments evaluate against.
    pub scan_var: &'p str,
    /// The GROUP BY key columns (bare, pure per-row — typically `n.<prop>` or the scan var), in the
    /// serial `group_keys` order, so the key tuple is built identically.
    pub group_keys: &'p [ProjectionColumn],
    /// The aggregate columns (each a bare, mergeable aggregate over the scan var), in the serial
    /// `aggregates` order, so each morsel builds one local [`Accumulator`](crate::executor::Accumulator)
    /// per column in the same slot.
    pub aggregates: &'p [ProjectionColumn],
}

/// The recognized **grouped-aggregation-over-expand** shape the `rmp` #558 / #340 morsel tier reproduces
/// per anchor-morsel: `MATCH (a:Label)-[r(:T…)?]->(b) [WHERE <pure residual>] WITH <bare group keys>,
/// <bare aggregates>` — the `top_liked` class (`MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*) …`).
/// It **fuses** the Slice-3c per-anchor `ExpandAll` (parallelizing the traversal) with the #360 grouped
/// merge (parallelizing the group-by), so a single heavy expand-then-group-by-target query runs across
/// all cores. Borrows the plan columns (no AST clone) so the morsel evaluates the *identical* expressions
/// the serial `Filter` / `aggregate_rows` would.
///
/// The recognizer (engine thread) guarantees: the anchor input is a bare label scan whose scanned
/// variable IS the expand's `from`; the hop is a **fixed-length, fresh** single `ExpandAll` (`range`
/// `None`, no prior / bound relationship, no inline rel-prop map — [`crate::executor`]'s
/// `recognize_morsel_expand`); the optional residual `filter` and every `group_keys[i].expr` are **pure
/// per-row** ([`is_pure_per_row_expr`]) over the expansion-row variables (`from`/`relationship`/`to`);
/// and every aggregate is a *bare* **mergeable** aggregate (`count(*)`/`count`/`sum`/`min`/`max`/
/// `collect`, `DISTINCT` only on `count`/`collect`) over those variables — `avg` / percentiles / composite
/// columns decline to the serial path.
pub struct MorselExpandGroupSpec<'p> {
    /// The anchor (scanned-node) variable bound by the label scan — the `from` of the expand.
    pub from: &'p Var,
    /// The relationship variable the traversal binds.
    pub relationship: &'p Var,
    /// The far-endpoint variable the traversal binds (typically the group key, e.g. `a`).
    pub to: &'p Var,
    /// The traversal direction relative to the anchor.
    pub direction: RelDirection,
    /// The relationship-type alternatives; empty means "any type".
    pub types: &'p [RelType],
    /// The optional residual per-expansion-row predicate (the interposed `Filter`, e.g. `a:ARTICLE`),
    /// evaluated under three-valued logic exactly as the serial `Operator::Filter`; `None` when the
    /// far-endpoint carries no label / property predicate. Guaranteed pure per-row by the recognizer.
    pub filter: Option<&'p Expr>,
    /// The GROUP BY key columns (bare, pure per-row over the expansion-row variables — typically the far
    /// node `to` or `to.<prop>`), in the serial `group_keys` order, so the key tuple is built identically.
    pub group_keys: &'p [ProjectionColumn],
    /// The aggregate columns (each a bare, mergeable aggregate over the expansion-row variables), in the
    /// serial `aggregates` order, so each morsel builds one local
    /// [`Accumulator`](crate::executor::Accumulator) per column in the same slot.
    pub aggregates: &'p [ProjectionColumn],
}

/// The recognized **frontier-seeded grouped-aggregation-over-a-final-expand** shape the `rmp` #575 tier
/// reproduces per anchor-morsel: the `r3_fof3` reco class —
/// `MATCH (me:User {id:$id})-[:FRIEND]-()-[:FRIEND]-()-[:FRIEND]-(f3) WHERE f3.id<>$id
///  MATCH (f3)-[:PURCHASED]->(p:Product) WHERE NOT (me)-[:PURCHASED]->(p)
///  RETURN p.id, count(DISTINCT f3) …`.
///
/// Unlike [`MorselExpandGroupSpec`] (whose anchors come from a **bare label scan**), this tier's anchors
/// are an arbitrary **frontier** — the distinct `from` (e.g. `f3`) node-ids the query's *earlier*
/// sub-plan binds, materialized **serially on the engine thread** (so the whole multi-hop first `MATCH`,
/// with its exact relationship-isomorphism + label filters + SIREAD markers, runs byte-identically to
/// serial before the parallel section begins). The morsel then parallelizes only the **final** expand +
/// the residual filters (including a graph **anti-join** pattern predicate) + the grouped
/// `count(DISTINCT <anchor>)`.
///
/// The recognizer (engine thread) guarantees: the final hop is a **fixed-length, fresh** single
/// `ExpandAll` (`range` `None`, `prior_rels` empty, no inline rel-prop map) whose `from` IS the frontier
/// anchor; each residual filter is either **pure per-row** ([`is_pure_per_row_expr`]) OR a deterministic
/// **pattern-existence** predicate (a `(Not-wrapped) EXISTS { pattern }` from a `WHERE (a)-…-(b)` — no
/// function call / nested full-query subquery, so it is a read-only, snapshot-deterministic, cross-row-free
/// graph read); every `group_keys[i].expr` is pure per-row over the expansion-row / constant vars; and
/// every aggregate is a **bare mergeable** aggregate (`count`/`sum`/`min`/`max`/`collect`, `DISTINCT` only
/// on `count`/`collect`). Borrows the plan columns (no AST clone).
pub struct MorselFrontierExpandGroupSpec<'p> {
    /// The frontier anchor variable bound by the (serially-materialized) earlier sub-plan — the `from`
    /// of the final expand (e.g. `f3`). Every morsel row binds it to `Node(anchor)`, so
    /// `count(DISTINCT <this var>)` counts the distinct anchors reaching each group.
    pub from: &'p Var,
    /// The relationship variable the final hop binds.
    pub relationship: &'p Var,
    /// The far-endpoint variable the final hop binds (typically the group key, e.g. `p`).
    pub to: &'p Var,
    /// The final-hop traversal direction relative to the anchor.
    pub direction: RelDirection,
    /// The final-hop relationship-type alternatives; empty means "any type".
    pub types: &'p [RelType],
    /// The residual per-expansion-row predicates ABOVE the final expand, in **serial application order**
    /// (innermost `Filter` first) — e.g. `[p:Product, NOT (me)-[:PURCHASED]->(p)]`. Each is evaluated
    /// under the identical three-valued logic the serial `Operator::Filter` uses (kept iff `TRUE`);
    /// a graph pattern-existence predicate here records its own SIREAD markers into the morsel buffer,
    /// byte-identical to the serial anti-join. Borrowed as references into the plan (no AST clone).
    pub residual_filters: &'p [&'p Expr],
    /// The GROUP BY key columns (bare, pure per-row over the expansion-row / constant vars — typically
    /// the far node `to.<prop>`), in the serial `group_keys` order.
    pub group_keys: &'p [ProjectionColumn],
    /// The aggregate columns (each a bare, mergeable aggregate — typically `count(DISTINCT <from>)`), in
    /// the serial `aggregates` order.
    pub aggregates: &'p [ProjectionColumn],
    /// The **constant** bindings the residual filters / keys / aggregates reference that are NOT
    /// expansion-row vars (e.g. the single seed `me`) — extracted once from the materialized frontier
    /// rows (constant across the whole frontier) and injected into every morsel row so `eval` resolves
    /// them identically to serial. Empty when the downstream references only expansion-row vars.
    pub constants: &'p [(String, RowValue)],
}

/// One local group a morsel accumulated for the `rmp` #360 grouped tier: its group-key tuple (the
/// merge key), its per-aggregate-column partial accumulators (one slot per `spec.aggregates`), and the
/// **local survivor rank** of the first survivor in this morsel that created the group. The engine
/// thread prefix-sums the local rank against the running survivor-count total (morsels iterated in
/// ascending-`lo` order) into a global first-seen rank, then sorts the merged groups by it — reproducing
/// serial first-seen output order exactly (the candidate order is order-isomorphic to first-seen rank).
#[must_use]
pub struct MorselLocalGroup {
    /// The group-key tuple (in `spec.group_keys` order) — the merge key, compared with the same
    /// [`row_values_equivalent`](crate::runtime::row_values_equivalent) serial uses.
    pub key: Vec<RowValue>,
    /// One partial accumulator per aggregate column, folded over this morsel's members of the group.
    /// Merged on the engine thread via [`Accumulator::combine`](crate::executor::Accumulator).
    pub accs: Vec<crate::executor::Accumulator>,
    /// The local survivor rank (0-based, among THIS morsel's survivors in candidate order) of the first
    /// survivor that created this group — prefix-summed into a global first-seen rank at merge.
    pub first_seen_local: u64,
}

/// One grouped-aggregation morsel's contribution (`rmp` task #360): its local groups, its total survivor
/// count (the prefix-sum increment so the next morsel's local ranks map to global ranks), its SIREAD
/// markers, and the first read / evaluation error (if any).
///
/// The executor merges the local groups into a global table (keyed identically to serial), prefix-summing
/// `first_seen_local + survivor_prefix` into the global first-seen rank and combining accumulators, then
/// emits groups sorted by global first-seen rank — byte-identical to serial. A non-`None` `error` aborts
/// the parallel path (the executor discards every morsel's groups + buffers and re-runs the serial
/// pipeline, which re-registers the markers and re-raises the identical error).
#[must_use]
pub struct MorselGroupOutcome {
    /// This morsel's local groups (group-key tuple → partial accumulators + local first-seen rank), in
    /// arbitrary order (the engine thread re-keys + globally orders them).
    pub groups: Vec<MorselLocalGroup>,
    /// The number of visible label-carrying survivors in this morsel (the prefix-sum increment that maps
    /// the next ascending-`lo` morsel's local survivor ranks into the global survivor-rank space).
    pub survivors: u64,
    /// This morsel's accumulated SIREAD markers (per-candidate `note_read` plus any per-row property
    /// reads the key / aggregate-argument evaluation performed), tagged with the query txn. Folded into
    /// the statement tracker at convergence via `SsiTracker::merge_read_buffer`.
    pub buffer: SsiReadBuffer,
    /// The first storage / evaluation error the morsel hit, or `None`. While set, the morsel's `groups`
    /// are untrustworthy and the parallel path must be abandoned.
    pub error: Option<GraphusError>,
}

/// The store-side read surface one morsel runs over (`rmp` task #339), **object-safe** and
/// `Send + Sync` so it can be boxed into a `(D, S)`-free [`MorselLabelScan`] bundle and cloned per
/// morsel onto the worker pool.
///
/// It exposes exactly two operations, both `(D, S)`-free:
///
/// * [`read_label_morsel`](Self::read_label_morsel) — filter a contiguous candidate slice to the
///   visible label-carrying nodes and read each survivor's aggregate-column value, recording the
///   per-candidate SIREAD markers into a fresh buffer (the expensive, parallelized work);
/// * [`clone_box`](Self::clone_box) — a **cheap** clone (a few `Arc` refcount bumps, no page / id
///   copy), so each morsel gets its own handle to dispatch onto a worker thread.
///
/// The single implementor [`MorselView`] holds the concrete `(D, S)` read view + token snapshot; the
/// `dyn MorselSource` boundary erases them, which is what lets the executor — holding only a
/// `&mut dyn GraphAccess` — drive the morsel read without ever naming `D`/`S`.
pub trait MorselSource: Send + Sync {
    /// Filters the contiguous candidate slice `ids` to the nodes that **currently** carry
    /// `label_token` and are **visible** to `snapshot` (resolved through `registry`), reads each
    /// survivor's `property` value (newest-visible-wins), and records the per-candidate SIREAD markers
    /// into a fresh [`SsiReadBuffer`] tagged with `txn` (`rmp` task #339). Returns the survivors'
    /// values, the morsel's visible-label-carrying count, the buffer, and the first read error.
    ///
    /// This is **byte-identical** to the serial path: it drives the same source-generic
    /// `read_source::filter_label_candidates` + `node_property` the live `RecordStoreGraph` and the
    /// off-thread `ReadOnlyGraph` run, over a `ReadViewSource` clone of this source.
    fn read_label_morsel(
        &self,
        ids: &[u64],
        label_token: u32,
        property: &str,
        txn: TxnId,
        snapshot: Snapshot,
        registry: &CommitRegistry,
    ) -> MorselReadOutcome;

    /// Filters the contiguous candidate slice `ids` to visible, label-carrying nodes, then for each
    /// survivor evaluates the **pure per-row residual predicate** `filter` (kept iff `TRUE` under
    /// three-valued logic, or unconditionally kept when `filter` is `None`) and the **per-row
    /// projection** `projection`, producing one [`Row`] per surviving candidate in candidate order
    /// (`rmp` task #339, Slice 3b). Records the per-candidate SIREAD markers into a fresh
    /// [`SsiReadBuffer`] tagged with `txn`.
    ///
    /// `filter`, every `projection` expression, and every `sort_keys` expression must have passed
    /// [`is_pure_per_row_expr`] on the engine thread (no aggregates / subqueries / comprehensions /
    /// quantifiers / function calls), so the evaluation here is **deterministic and confined to this one
    /// row + the per-row graph read** — which is what makes the contiguous-concat of the morsels' rows
    /// byte-identical to the serial scan→filter→project candidate order.
    ///
    /// When `sort_keys` is non-empty, each surviving row's sort-key vector is also evaluated (against the
    /// *projected* row, so the keys reference projected columns / pre-projection variables still in
    /// scope — exactly the serial `sort_rows` evaluation), the morsel's rows are **stably sorted** by
    /// those keys (ties preserving candidate order), and the parallel `keys`/`rows` vectors are returned
    /// for the engine-thread stable k-way merge. When empty, the rows are returned in candidate order
    /// for the contiguous concat.
    ///
    /// Internally this builds a [`ReadOnlyGraph`] over a cheap clone of this source (the same `Send`,
    /// off-thread `GraphAccess` the `rmp` #336 Slice 3b-i reader uses) and drives [`crate::eval::eval`] —
    /// the *identical* per-row evaluator the serial `Operator::Filter` / `Operator::Project` / `sort_rows`
    /// run — so a morsel produces byte-identical values, three-valued filter decisions, sort keys, and
    /// SIREAD markers to the serial path. `params` supplies any `$param` the predicate / projection /
    /// sort key reads.
    ///
    /// `deadline` is the per-statement wall-clock budget (`rmp` #476): the worker abandons (recording a
    /// timeout error so the executor falls back to the serial pipeline, which surfaces a clean
    /// cancellation) if it elapses mid-morsel. `None` means no budget — the worker runs to completion.
    #[allow(clippy::too_many_arguments)] // a per-morsel read worker; the seams are positional
    fn read_filter_project_morsel(
        &self,
        ids: &[u64],
        label_token: u32,
        scan_var: &str,
        filter: Option<&Expr>,
        projection: &[ProjectionColumn],
        sort_keys: &[SortKey],
        params: &BoundParameters,
        txn: TxnId,
        snapshot: Snapshot,
        registry: &CommitRegistry,
        deadline: Option<Instant>,
    ) -> MorselRowsOutcome;

    /// Filters the contiguous **anchor** candidate slice `ids` to visible, label-carrying nodes, then
    /// for each surviving anchor performs the single-hop `ExpandAll` described by `plan` and either
    /// **counts** the produced rows (the degree / `count(b)` shape) or **projects** them
    /// (`plan.projection`, the neighbour-collect shape), producing this morsel's
    /// [`MorselExpandOutcome`] in (anchor, then per-anchor expansion) order (`rmp` task #339, Slice 3c
    /// — the final slice, parallelizing the traversal). Records the per-anchor label-scan markers AND
    /// the per-anchor `expand`'s relationship-pattern predicate + per-edge markers into a fresh
    /// [`SsiReadBuffer`] tagged with `txn`.
    ///
    /// Internally this builds a [`ReadOnlyGraph`] over a cheap clone of this source — the **same**
    /// `Send`, off-thread `GraphAccess` (incl. its `expand`, which routes through the identical lifted
    /// `read_source::expand` body the live `RecordStoreGraph` uses) the `rmp` #336 Slice 3b-i reader is
    /// built on — then reproduces the serial `Operator::Expand` semantics **exactly**: self-loops
    /// reported once per matching side are deduplicated per anchor by relationship id, prior-pattern
    /// relationships are excluded (relationship isomorphism), and (for the rows shape) each surviving
    /// `(a, r, b)` is evaluated through the identical [`crate::eval::eval`] — so a morsel produces
    /// byte-identical rows / counts, visibility, and SIREAD markers to the serial scan→expand path.
    /// `params` supplies any `$param` the projection reads.
    ///
    /// `deadline` is the per-statement wall-clock budget (`rmp` #476): the traversal abandons (recording
    /// a timeout error so the executor falls back to the serial pipeline, which surfaces a clean
    /// cancellation) if it elapses mid-morsel — polled both per anchor and, for a high-degree anchor,
    /// periodically within its expansion. `None` means no budget.
    #[allow(clippy::too_many_arguments)] // a per-morsel read worker; the seams are positional
    fn expand_morsel(
        &self,
        ids: &[u64],
        label_token: u32,
        plan: &MorselExpandPlan<'_>,
        params: &BoundParameters,
        txn: TxnId,
        snapshot: Snapshot,
        registry: &CommitRegistry,
        deadline: Option<Instant>,
    ) -> MorselExpandOutcome;

    /// Filters the contiguous candidate slice `ids` to visible, label-carrying nodes, then **groups +
    /// aggregates** the survivors locally per the recognized bare grouped shape `spec` — `MATCH
    /// (n:Label) RETURN <bare group keys>, <bare aggregates>` (`rmp` task #360, the grouped morsel tier
    /// extending Slice 3a). For each surviving candidate it builds the single-binding row
    /// `{scan_var: Node(id)}`, evaluates the group-key expressions and each aggregate's argument via
    /// [`crate::eval::eval`] (the identical per-row evaluator the serial `aggregate_rows` runs), and folds
    /// the survivor into that group's local [`Accumulator`](crate::executor::Accumulator)s — building a
    /// LOCAL group table keyed by the same SipHash digest +
    /// [`row_values_equivalent`](crate::runtime::row_values_equivalent) resolution serial uses, so grouping
    /// semantics are identical. Records the per-candidate SIREAD markers into a fresh
    /// [`SsiReadBuffer`] tagged with `txn`.
    ///
    /// Returns the morsel's local groups (each carrying its key tuple, per-column partial accumulators,
    /// and the **local survivor rank** of the first survivor that created it — the engine thread
    /// prefix-sums these into a global first-seen rank so the merged output order is byte-identical to
    /// serial first-seen order), the morsel's total survivor count (for the prefix sum), the buffer, and
    /// the first read / evaluation error.
    ///
    /// Internally this builds a [`ReadOnlyGraph`] over a cheap clone of this source (the same `Send`,
    /// off-thread `GraphAccess` the `rmp` #336 Slice 3b-i reader uses) and drives the identical `eval` /
    /// [`Accumulator`](crate::executor::Accumulator) fold the serial path runs, so a morsel produces
    /// byte-identical group state, values, and SIREAD markers. `params` supplies any `$param` the keys /
    /// aggregate arguments read. The recognizer (engine thread) guarantees every key + aggregate-argument
    /// expression is pure per-row ([`is_pure_per_row_expr`]), so the off-thread evaluation is
    /// deterministic and cross-row-free.
    ///
    /// `deadline` is the per-statement wall-clock budget (`rmp` #476): the worker abandons (recording a
    /// timeout error so the executor falls back to the serial pipeline, which surfaces a clean
    /// cancellation) if it elapses mid-morsel. `None` means no budget.
    #[allow(clippy::too_many_arguments)] // a per-morsel read worker; the seams are positional
    fn group_aggregate_morsel(
        &self,
        ids: &[u64],
        label_token: u32,
        spec: &MorselGroupSpec<'_>,
        params: &BoundParameters,
        txn: TxnId,
        snapshot: Snapshot,
        registry: &CommitRegistry,
        deadline: Option<Instant>,
    ) -> MorselGroupOutcome;

    /// Filters the contiguous **anchor** candidate slice `ids` to visible, label-carrying nodes, then for
    /// each surviving anchor performs the single-hop `ExpandAll` described by `spec` and **groups +
    /// aggregates the surviving expansion rows** locally per the recognized grouped-over-expand shape
    /// (`rmp` task #558 / #340, the `top_liked` class — `MATCH (a:L)-[r]->(b) [WHERE …] WITH <keys>,
    /// <aggs>`, e.g. `MATCH (:USER)-[:LIKE]->(a:ARTICLE) WITH a, count(*)`). It **fuses** the Slice-3c
    /// per-anchor traversal (`expand_morsel`) with the #360 grouped fold (`group_aggregate_morsel`):
    ///
    /// * builds the serial expansion-row binding `{from: a, relationship: r, to: b}` for every produced
    ///   incidence side (self-loops reported once per matching direction are deduplicated per anchor by
    ///   relationship id, byte-identical to `Operator::Expand`);
    /// * applies the optional residual `spec.filter` (the interposed `Operator::Filter`, e.g. `b:ARTICLE`)
    ///   under three-valued logic — keeping the row iff the predicate is `TRUE` (NULL / FALSE drop it),
    ///   exactly as [`read_filter_project_morsel`](Self::read_filter_project_morsel);
    /// * for each **surviving** row, evaluates the group-key tuple + folds every aggregate column into that
    ///   group's local [`Accumulator`](crate::executor::Accumulator)s, keyed on the same SipHash digest +
    ///   [`row_values_equivalent`](crate::runtime::row_values_equivalent) resolution serial uses.
    ///
    /// The per-group `first_seen_local` rank and the morsel's `survivors` count are over the **surviving
    /// expansion rows** (post-filter, the rows that reach the group-by) — the same first-seen rank space
    /// the serial `aggregate_rows` observes — so the engine-thread [`converge_group_aggregate_outcomes`]
    /// merge reproduces serial first-seen output order byte-for-byte, independent of the worker count. The
    /// returned [`MorselGroupOutcome`] is the **identical** type the #360 grouped tier converges, so the
    /// merge is reused verbatim.
    ///
    /// Records the per-anchor label-scan markers, the per-anchor `expand`'s relationship-pattern predicate
    /// and per-edge markers, AND every per-row property / label read the filter / keys / aggregate
    /// arguments perform, into a fresh [`SsiReadBuffer`] tagged with `txn` — byte-identical to the serial
    /// scan→expand→filter→aggregate marker set. `deadline` is the per-statement wall-clock budget
    /// (`rmp` #476), polled per anchor and, for a high-degree anchor, per stride of edges.
    #[allow(clippy::too_many_arguments)] // a per-morsel read worker; the seams are positional
    fn expand_group_aggregate_morsel(
        &self,
        ids: &[u64],
        label_token: u32,
        spec: &MorselExpandGroupSpec<'_>,
        params: &BoundParameters,
        txn: TxnId,
        snapshot: Snapshot,
        registry: &CommitRegistry,
        deadline: Option<Instant>,
    ) -> MorselGroupOutcome;

    /// Treats the contiguous slice `anchors` (an arbitrary **frontier** of node-ids — NOT filtered by a
    /// label, since the earlier sub-plan already validated them under this snapshot) as the `from` of a
    /// **fixed-length, fresh** single-hop `ExpandAll`, and per anchor: expands `spec.direction` /
    /// `spec.types`, injects `spec.constants` into the expansion-row binding `{constants…, from: a,
    /// relationship: r, to: b}`, applies `spec.residual_filters` in order under three-valued logic
    /// (keeping a row iff **every** predicate is `TRUE`), then groups + aggregates the survivors per
    /// `spec.group_keys` / `spec.aggregates` into a LOCAL group table — building the identical
    /// [`MorselGroupOutcome`] the `rmp` #360 / #558 tiers converge (`rmp` task #575, the `r3_fof3` reco
    /// class). Records the final-hop relationship-pattern predicate + per-edge markers, every per-row
    /// property/label read the filters / keys / aggregates perform, AND every read the anti-join
    /// pattern-existence predicate performs, into a fresh [`SsiReadBuffer`] tagged with `txn`.
    ///
    /// Byte-identical to the serial scan→expand→filter→aggregate over this frontier: it drives the SAME
    /// lifted `read_source::expand` body + the SAME [`crate::eval::eval`] (over a [`ReadOnlyGraph`]) serial
    /// runs, so a morsel produces byte-identical rows, three-valued filter decisions (incl. the anti-join),
    /// grouped values, and SIREAD markers. Because the frontier is a **disjoint** partition of the distinct
    /// anchors, a `count(DISTINCT <anchor>)` per group is the set-union of the morsels' partials at
    /// convergence — worker-count-independent. `deadline` is the per-statement wall-clock budget
    /// (`rmp` #476), polled per anchor and per stride of edges.
    #[allow(clippy::too_many_arguments)] // a per-morsel read worker; the seams are positional
    fn frontier_expand_group_aggregate_morsel(
        &self,
        anchors: &[u64],
        spec: &MorselFrontierExpandGroupSpec<'_>,
        params: &BoundParameters,
        txn: TxnId,
        snapshot: Snapshot,
        registry: &CommitRegistry,
        deadline: Option<Instant>,
    ) -> MorselGroupOutcome;

    /// A **cheap** clone of this source as a fresh boxed handle (`rmp` task #339): a handful of `Arc`
    /// refcount bumps (the page-cache `Arc`, the `MetaSnapshot`'s per-store `Arc<[PageId]>`, the
    /// `TokenSnapshot`'s `Arc<TokenStore>`) — **no** page copy and **no** candidate-id copy. Each morsel
    /// dispatched onto the worker pool gets its own clone, so the workers share the underlying page
    /// cache (per-frame `RwLock` read latches make concurrent reads safe) with no per-morsel allocation
    /// beyond the refcount bumps.
    fn clone_box(&self) -> Box<dyn MorselSource>;
}

/// The concrete [`MorselSource`] over an owned, `Send + Sync` [`StoreReadView`] + [`TokenSnapshot`]
/// captured on the engine thread (`rmp` task #339). Generic over `(D, S)` exactly like the view it
/// reads through; the `dyn MorselSource` boundary in [`MorselLabelScan`] erases them.
pub struct MorselView<D: BlockDevice, S: LogSink> {
    /// The owned, `Send + Sync` decode surface (`Arc<pool>` + `MetaSnapshot`).
    view: StoreReadView<D, S>,
    /// The owned, `Send + Sync` token dictionary (`id ↔ name`).
    tokens: TokenSnapshot,
}

impl<D: BlockDevice, S: LogSink> MorselView<D, S> {
    /// Wraps an engine-thread-captured read view + token snapshot as a morsel source. Used by the
    /// `RecordStoreGraph::morsel_label_scan` seam impl.
    #[must_use]
    pub fn new(view: StoreReadView<D, S>, tokens: TokenSnapshot) -> Self {
        Self { view, tokens }
    }

    /// This source's [`ReadViewSource`] over the owned view + token snapshot (the per-call source the
    /// lifted read body runs over).
    #[inline]
    fn source(&self) -> ReadViewSource<'_, D, S> {
        ReadViewSource {
            view: &self.view,
            tokens: &self.tokens,
        }
    }
}

impl<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static> MorselSource
    for MorselView<D, S>
{
    fn read_label_morsel(
        &self,
        ids: &[u64],
        label_token: u32,
        property: &str,
        txn: TxnId,
        snapshot: Snapshot,
        registry: &CommitRegistry,
    ) -> MorselReadOutcome {
        let src = self.source();
        let ctx = VisCtx {
            snapshot,
            registry,
            txn,
        };
        // A per-morsel sink: the morsel's own SIREAD buffer (tagged with the query txn) + its own first
        // captured error. No shared lock — every morsel mutates only its own sink.
        let sink = MorselSink::new(txn);

        // The fused morsel scan: read each candidate's node ONCE (mark + visible + label re-check) and
        // read the property for survivors — byte-identical to `filter_label_candidates` +
        // `node_property` over the same ids, but with fewer per-candidate node reads (no separate
        // existence probe), which matters under buffer-pool contention when many morsels read at once.
        let (label_matches, values) =
            read_source::scan_label_property_morsel(&src, &ctx, &sink, label_token, property, ids);

        let (buffer, error) = sink.into_parts();
        MorselReadOutcome {
            values,
            label_matches,
            buffer,
            error,
        }
    }

    fn read_filter_project_morsel(
        &self,
        ids: &[u64],
        label_token: u32,
        scan_var: &str,
        filter: Option<&Expr>,
        projection: &[ProjectionColumn],
        sort_keys: &[SortKey],
        params: &BoundParameters,
        txn: TxnId,
        snapshot: Snapshot,
        registry: &CommitRegistry,
        deadline: Option<Instant>,
    ) -> MorselRowsOutcome {
        // Build a `Send`, off-thread read-only `GraphAccess` over a CHEAP CLONE of this source (a few
        // `Arc` bumps, no page copy). It owns a fresh `SsiReadBuffer` tagged with `txn`, so every
        // per-candidate label-scan marker AND every per-row property read the filter / projection
        // performs lands in this morsel's own buffer — exactly the markers the serial path records, taken
        // back below and folded at convergence. This is the identical `GraphAccess` the `rmp` #336
        // Slice 3b-i reader uses, so `eval` produces byte-identical values + three-valued filter
        // decisions + markers to the serial `Operator::Filter` / `Operator::Project`.
        let graph = ReadOnlyGraph::new(
            self.view.clone(),
            self.tokens.clone(),
            snapshot,
            registry.clone(),
            txn,
            SsiReadBuffer::new(txn),
        );

        // First, the SAME visible-label-carrying candidate set the serial `scan_nodes_by_label` index arm
        // produces (the lifted `filter_label_candidates` over the same ids, recording the same
        // per-candidate SIREAD markers into `graph`'s buffer). The morsel's candidate slice is contiguous,
        // so its survivors are in the serial candidate order.
        let members = graph.filter_label_candidates(label_token, ids.to_vec());

        // The per-row evaluator state: the empty UDF set (no projection / filter / sort-key expression
        // survives the purity gate with a function call, so the registry is provably never consulted), and
        // a captured statement clock (likewise never consulted — every temporal constructor is a function
        // call the gate rejects). Both exist only to satisfy `eval`'s signature.
        let functions = empty_function_set();
        let clock = StatementClock::capture();

        let mut rows: Vec<Row> = Vec::with_capacity(members.len());
        // The parallel sort-key vectors (one per kept row), evaluated against the *projected* row exactly
        // as serial `sort_rows`. Empty stays empty when there are no sort keys (Shape A).
        let mut keyed: Vec<Vec<RowValue>> = if sort_keys.is_empty() {
            Vec::new()
        } else {
            Vec::with_capacity(members.len())
        };
        let mut first_error: Option<GraphusError> = None;
        for (i, node) in members.into_iter().enumerate() {
            // Per-statement timeout safe point (`rmp` #476): bound a large morsel's CPU under the
            // configured deadline. Polled at a strided cadence so the wall-clock read never dominates the
            // per-row work; on elapse the morsel abandons with a timeout error and the executor surfaces a
            // clean `Cancelled` via the serial fallback.
            if (i as u64) & (MORSEL_DEADLINE_POLL_STRIDE - 1) == 0 && deadline_exceeded(deadline) {
                first_error.get_or_insert_with(statement_timeout_error);
                break;
            }
            // The single-binding input row the serial label scan feeds the `Filter` / `Projection`:
            // `{scan_var: Node(id)}`.
            let row =
                Row::from_pairs([(scan_var.to_owned(), RowValue::Node(NodeRef { id: node }))]);

            // The residual predicate (`Operator::Filter`): keep the row iff the predicate is `TRUE` under
            // three-valued logic (NULL / FALSE drop it), or unconditionally when there is no filter.
            if let Some(pred) = filter {
                match eval(pred, &row, params, &graph, functions, &clock) {
                    Ok(RowValue::Value(Value::Boolean(true))) => {}
                    Ok(RowValue::Value(Value::Boolean(false)) | RowValue::Value(Value::Null)) => {
                        continue;
                    }
                    Ok(_) => {
                        // A non-boolean, non-null predicate is a runtime type error — exactly what the
                        // serial `predicate_truth` raises. The precise error never reaches the user (any
                        // morsel error makes the executor discard the parallel result and re-run the
                        // serial pipeline, which raises the identical error); this only signals "abandon".
                        first_error.get_or_insert(GraphusError::Runtime(
                            "WHERE/predicate must be a boolean".to_owned(),
                        ));
                        break;
                    }
                    Err(e) => {
                        first_error.get_or_insert_with(|| eval_error_to_graphus(&e));
                        break;
                    }
                }
            }

            // The per-row projection (`Operator::Project` / `project_row`): evaluate each column against
            // the input row and bind it to the column alias.
            let mut out = Row::empty();
            for col in projection {
                match eval(&col.expr, &row, params, &graph, functions, &clock) {
                    Ok(v) => out.set(col.alias.clone(), v),
                    Err(e) => {
                        first_error.get_or_insert_with(|| eval_error_to_graphus(&e));
                        break;
                    }
                }
            }
            if first_error.is_some() {
                break;
            }

            // The sort-key vector (serial `sort_rows`): pre-compute each key value against the PROJECTED
            // row (the row that flows into `Sort`), so the engine-thread merge is a pure comparison with
            // no graph access. Identical to serial — same `eval`, same projected row, same key order.
            if !sort_keys.is_empty() {
                let mut kvs = Vec::with_capacity(sort_keys.len());
                for k in sort_keys {
                    match eval(&k.expr, &out, params, &graph, functions, &clock) {
                        Ok(v) => kvs.push(v),
                        Err(e) => {
                            first_error.get_or_insert_with(|| eval_error_to_graphus(&e));
                            break;
                        }
                    }
                }
                if first_error.is_some() {
                    break;
                }
                keyed.push(kvs);
            }

            rows.push(out);
        }

        // A storage fault captured by a read inside `eval` (a torn page, an overflow bitmap) also makes
        // the result untrustworthy — surface it so the executor abandons the parallel path.
        let read_error = graph.take_error();
        let error = first_error.or(read_error);
        // Take the morsel's accumulated SIREAD markers back (the engine thread folds them at convergence).
        let buffer = graph.take_buffer();

        // When sorting, pre-sort this morsel's rows by their keys — STABLY, so ties preserve candidate
        // order (the ascending-`lo` morsel order + per-morsel candidate order together reproduce the
        // serial stable `sort_by`). The engine-thread k-way merge then merges the pre-sorted morsels.
        if !sort_keys.is_empty() && error.is_none() {
            stable_sort_keyed_rows(&mut keyed, &mut rows, sort_keys);
        }

        MorselRowsOutcome {
            rows,
            keys: keyed,
            buffer,
            error,
        }
    }

    fn expand_morsel(
        &self,
        ids: &[u64],
        label_token: u32,
        plan: &MorselExpandPlan<'_>,
        params: &BoundParameters,
        txn: TxnId,
        snapshot: Snapshot,
        registry: &CommitRegistry,
        deadline: Option<Instant>,
    ) -> MorselExpandOutcome {
        // Build a `Send`, off-thread read-only `GraphAccess` over a CHEAP CLONE of this source (a few
        // `Arc` bumps, no page copy) — the identical `GraphAccess` the `rmp` #336 Slice 3b-i reader uses.
        // Its `expand` routes through the SAME lifted `read_source::expand` body the live
        // `RecordStoreGraph::expand` calls, so a morsel's traversal records byte-identical markers (the
        // rel-pattern predicate + every examined edge) and visibility decisions to serial. Its own fresh
        // `SsiReadBuffer` (tagged `txn`) catches every per-anchor label-scan marker AND every per-edge
        // marker, taken back below and folded at convergence.
        let graph = ReadOnlyGraph::new(
            self.view.clone(),
            self.tokens.clone(),
            snapshot,
            registry.clone(),
            txn,
            SsiReadBuffer::new(txn),
        );

        // The SAME visible-label-carrying ANCHOR set the serial `scan_nodes_by_label` index arm produces
        // (the lifted `filter_label_candidates` over the same ids, recording the same per-candidate SIREAD
        // markers into `graph`'s buffer). The slice is contiguous ⇒ survivors are in serial anchor order.
        let anchors = graph.filter_label_candidates(label_token, ids.to_vec());

        // Resolve the expand pieces ONCE (shared across every anchor in this morsel). The
        // `ExpandDirection` mapping + the rel-type name vector are exactly what the serial
        // `expand_into_pending` derives per call; computing them once here is a pure perf factoring, the
        // produced incidents are identical.
        let dir = ExpandDirection::from_pattern(plan.direction);
        let type_names: Vec<String> = plan.types.iter().map(|t| t.name.clone()).collect();
        let projection = match &plan.post {
            MorselExpandPostWork::Count => None,
            MorselExpandPostWork::Project(cols) => Some(*cols),
        };

        // The per-row evaluator state for the projection (rows shape only): the empty UDF set + a captured
        // clock, both provably never consulted (the engine-thread purity gate rejects every projection
        // expression containing a function call). They exist only to satisfy `eval`'s signature, exactly as
        // the Slice-3b `read_filter_project_morsel` does.
        let functions = empty_function_set();
        let clock = StatementClock::capture();

        let mut rows: Vec<Row> = Vec::new();
        let mut partial_count: i64 = 0;
        let mut first_error: Option<GraphusError> = None;

        // Per-edge deadline-poll counter (`rmp` #476): a single high-degree anchor (a supernode) can
        // expand over millions of edges, so the per-statement timeout is also polled *within* one
        // anchor's expansion, strided so the wall-clock read never dominates the per-edge work.
        let mut edges_seen: u64 = 0;
        'anchors: for (anchor_i, anchor) in anchors.into_iter().enumerate() {
            // Per-statement timeout safe point (`rmp` #476): bound a large morsel's traversal CPU under the
            // configured deadline. Strided so the wall-clock read is amortized; on elapse the morsel
            // abandons with a timeout error and the executor surfaces a clean `Cancelled` via serial fallback.
            if (anchor_i as u64) & (MORSEL_DEADLINE_POLL_STRIDE - 1) == 0
                && deadline_exceeded(deadline)
            {
                first_error.get_or_insert_with(statement_timeout_error);
                break 'anchors;
            }
            // Reproduce the serial `Operator::Expand` / `expand_into_pending` EXACTLY (`04 §2.4`):
            //   1. `expand` returns the incident sides (a self-loop is reported once PER matching
            //      direction — twice for `Both` — and the live + reader paths share the body, so the
            //      reported sides are identical);
            //   2. a self-loop is collapsed to ONE produced row by deduplicating relationship ids per
            //      anchor (`seen_rel`);
            //   3. (prior-pattern isomorphism: there are no prior rels in the first-cut shape, so this is
            //      vacuous — but kept structurally so the morsel matches serial even were it extended).
            let incidents = graph.expand(anchor, dir, &type_names);
            // A storage fault captured inside `expand` makes this anchor's incidents untrustworthy; bail to
            // the post-loop error handling (the executor will discard + re-run serial).
            if graph.has_error() {
                break 'anchors;
            }
            let mut seen_rel = std::collections::BTreeSet::new();
            for inc in incidents {
                // Bound a single supernode's expansion under the deadline too (strided per edge).
                edges_seen = edges_seen.wrapping_add(1);
                if edges_seen & (MORSEL_DEADLINE_POLL_STRIDE - 1) == 0
                    && deadline_exceeded(deadline)
                {
                    first_error.get_or_insert_with(statement_timeout_error);
                    break 'anchors;
                }
                if !seen_rel.insert(inc.rel) {
                    // A self-loop's second side (same rel id) — serial emits ONE row for it. Skip the dup.
                    continue;
                }
                match projection {
                    // Degree / `count` shape: every surviving expansion side is one matched row.
                    None => {
                        partial_count = partial_count.saturating_add(1);
                    }
                    // Neighbour-collect shape: build the serial expansion row binding
                    // `{from: a, relationship: r, to: b}` and project it through the pure per-row columns.
                    // `eval` resolves any `r`/`b` property against this same `graph` (registering its own
                    // SIREAD markers into the morsel buffer, exactly as the serial projection's reads do).
                    Some(cols) => {
                        let in_row = Row::from_pairs([
                            (
                                plan.from.name.clone(),
                                RowValue::Node(NodeRef { id: anchor }),
                            ),
                            (
                                plan.relationship.name.clone(),
                                RowValue::Rel(RelRef { id: inc.rel }),
                            ),
                            (
                                plan.to.name.clone(),
                                RowValue::Node(NodeRef { id: inc.neighbour }),
                            ),
                        ]);
                        let mut out = Row::empty();
                        for col in cols {
                            match eval(&col.expr, &in_row, params, &graph, functions, &clock) {
                                Ok(v) => out.set(col.alias.clone(), v),
                                Err(e) => {
                                    first_error.get_or_insert_with(|| eval_error_to_graphus(&e));
                                    break;
                                }
                            }
                        }
                        if first_error.is_some() {
                            break 'anchors;
                        }
                        rows.push(out);
                    }
                }
            }
        }

        // A storage fault captured by any read (the per-anchor `expand`, or a projection property read)
        // makes the whole morsel untrustworthy — surface it so the executor abandons the parallel path.
        let read_error = graph.take_error();
        let error = first_error.or(read_error);
        let buffer = graph.take_buffer();

        MorselExpandOutcome {
            rows,
            partial_count,
            buffer,
            error,
        }
    }

    #[allow(clippy::too_many_arguments)] // a per-morsel read worker; the seams are positional
    fn group_aggregate_morsel(
        &self,
        ids: &[u64],
        label_token: u32,
        spec: &MorselGroupSpec<'_>,
        params: &BoundParameters,
        txn: TxnId,
        snapshot: Snapshot,
        registry: &CommitRegistry,
        deadline: Option<Instant>,
    ) -> MorselGroupOutcome {
        // Build a `Send`, off-thread read-only `GraphAccess` over a CHEAP CLONE of this source (a few
        // `Arc` bumps, no page copy) — the identical `GraphAccess` the `rmp` #336 Slice 3b-i reader uses,
        // so `eval` over it produces byte-identical key values + aggregate-argument values + markers to
        // the serial path. Its own fresh `SsiReadBuffer` (tagged `txn`) catches every per-candidate
        // label-scan marker AND every per-row property read, taken back below and folded at convergence.
        let graph = ReadOnlyGraph::new(
            self.view.clone(),
            self.tokens.clone(),
            snapshot,
            registry.clone(),
            txn,
            SsiReadBuffer::new(txn),
        );

        // The SAME visible-label-carrying candidate set the serial `scan_nodes_by_label` index arm
        // produces (the lifted `filter_label_candidates` over the same ids, recording the same
        // per-candidate SIREAD markers). The slice is contiguous ⇒ survivors are in serial candidate
        // order, so the local survivor rank below is monotone in global scan position.
        let members = graph.filter_label_candidates(label_token, ids.to_vec());
        let survivors = members.len() as u64;

        // The per-row evaluator state: the empty UDF set + a captured clock, both provably never consulted
        // (the engine-thread purity gate rejects every key / aggregate-argument expression containing a
        // function call — and an *aggregate* is a function call, so the bare-aggregate columns are
        // recognized structurally, not via `eval`). They exist only to satisfy `eval`'s signature.
        let functions = empty_function_set();
        let clock = StatementClock::capture();

        // The local group table, mirroring the serial `aggregate_rows` index EXACTLY: a SipHash digest of
        // the key tuple (DoS-resistant per the SEC-210 invariant — group keys are client-derived property
        // values) → the indices of local groups whose key hashes there; a bucket collision falls back to
        // the same `row_values_equivalent` resolution, so grouping semantics are identical.
        let mut groups: Vec<MorselLocalGroup> = Vec::new();
        // `rmp` #371: keyed on the already-DoS-resistant `group_key_hash` `u64` digest, so the outer
        // index buckets it with `FxHasher` (the digest itself stays SipHash) — byte-identical grouping,
        // no wasted re-hash.
        let mut index: rustc_hash::FxHashMap<u64, Vec<usize>> = rustc_hash::FxHashMap::default();
        let mut first_error: Option<GraphusError> = None;

        for (rank, node) in members.into_iter().enumerate() {
            // Per-statement timeout safe point (`rmp` #476): bound a large grouped morsel's CPU under the
            // configured deadline (strided wall-clock poll). On elapse the morsel abandons with a timeout
            // error and the executor surfaces a clean `Cancelled` via the serial fallback.
            if (rank as u64) & (MORSEL_DEADLINE_POLL_STRIDE - 1) == 0 && deadline_exceeded(deadline)
            {
                first_error.get_or_insert_with(statement_timeout_error);
                break;
            }
            let row = Row::from_pairs([(
                spec.scan_var.to_owned(),
                RowValue::Node(NodeRef { id: node }),
            )]);

            // The group key tuple (serial `aggregate_rows`: evaluate each key column against the row).
            let mut key_vals = Vec::with_capacity(spec.group_keys.len());
            for col in spec.group_keys {
                match eval(&col.expr, &row, params, &graph, functions, &clock) {
                    Ok(v) => key_vals.push(v),
                    Err(e) => {
                        first_error.get_or_insert_with(|| eval_error_to_graphus(&e));
                        break;
                    }
                }
            }
            if first_error.is_some() {
                break;
            }

            // Hash the whole key tuple, then resolve within the (normally singleton) bucket by exact
            // equivalence — byte-identical to serial `aggregate_rows`' index (the SAME SipHash digest).
            let key_hash = crate::executor::group_key_hash(&key_vals);
            let bucket = index.entry(key_hash).or_default();
            let found = bucket.iter().copied().find(|&gi| {
                let g: &MorselLocalGroup = &groups[gi];
                g.key.len() == key_vals.len()
                    && g.key
                        .iter()
                        .zip(&key_vals)
                        .all(|(x, y)| crate::runtime::row_values_equivalent(x, y))
            });
            let gi = match found {
                Some(i) => i,
                None => {
                    let gi = groups.len();
                    groups.push(MorselLocalGroup {
                        key: key_vals,
                        accs: spec
                            .aggregates
                            .iter()
                            .map(|c| crate::executor::Accumulator::new(&c.expr))
                            .collect(),
                        first_seen_local: rank as u64,
                    });
                    bucket.push(gi);
                    gi
                }
            };

            // Fold this survivor into the group's per-column accumulators. Each aggregate column is a
            // BARE aggregate (the recognizer guaranteed it), so the fold mirrors serial `Accumulator::
            // update` exactly: `count(*)` increments the row count; every other admitted kind evaluates
            // the single argument against the row and folds the resulting `RowValue` via the shared
            // `fold_rowvalue` (the post-evaluation body serial `update` runs).
            for (col, acc) in spec.aggregates.iter().zip(groups[gi].accs.iter_mut()) {
                if let Err(e) = acc.fold_bare(&col.expr, &row, params, &graph, functions, &clock) {
                    // The precise variant is immaterial — any morsel error makes the executor discard the
                    // parallel result and re-run the serial pipeline, which raises the identical precise
                    // error to the user; this only needs to be non-`None` to signal "abandon".
                    first_error.get_or_insert_with(|| GraphusError::Runtime(e.to_string()));
                    break;
                }
            }
            if first_error.is_some() {
                break;
            }
        }

        // A storage fault captured by a read inside `eval` (a torn page, an overflow bitmap) also makes
        // the result untrustworthy — surface it so the executor abandons the parallel path.
        let read_error = graph.take_error();
        let error = first_error.or(read_error);
        let buffer = graph.take_buffer();

        MorselGroupOutcome {
            groups,
            survivors,
            buffer,
            error,
        }
    }

    #[allow(clippy::too_many_arguments)] // a per-morsel read worker; the seams are positional
    fn expand_group_aggregate_morsel(
        &self,
        ids: &[u64],
        label_token: u32,
        spec: &MorselExpandGroupSpec<'_>,
        params: &BoundParameters,
        txn: TxnId,
        snapshot: Snapshot,
        registry: &CommitRegistry,
        deadline: Option<Instant>,
    ) -> MorselGroupOutcome {
        // Off-thread read-only `GraphAccess` over a CHEAP CLONE of this source (the `rmp` #336 Slice-3b-i
        // reader): its `expand` routes through the SAME lifted `read_source::expand` body serial's
        // `Operator::Expand` runs, and `eval` over it produces byte-identical filter decisions + key /
        // aggregate-argument values. Its own fresh `SsiReadBuffer` (tagged `txn`) catches every per-anchor
        // label-scan marker, every per-edge marker, AND every per-row property / label read the filter /
        // keys / aggregate arguments perform — taken back below and folded at convergence.
        let graph = ReadOnlyGraph::new(
            self.view.clone(),
            self.tokens.clone(),
            snapshot,
            registry.clone(),
            txn,
            SsiReadBuffer::new(txn),
        );

        // The SAME visible-label-carrying ANCHOR set the serial `scan_nodes_by_label` index arm produces,
        // in serial anchor order (the slice is contiguous) — so the surviving-row rank below is monotone in
        // global scan→expand position, which is what makes the merge's global first-seen order = serial's.
        let anchors = graph.filter_label_candidates(label_token, ids.to_vec());

        // Resolve the expand pieces ONCE (shared across every anchor) — identical incidents to serial.
        let dir = ExpandDirection::from_pattern(spec.direction);
        let type_names: Vec<String> = spec.types.iter().map(|t| t.name.clone()).collect();

        // The per-row evaluator state: the empty UDF set + a captured clock, both provably never consulted
        // (the recognizer's purity gate rejects every filter / key / aggregate-argument expression
        // containing a function call — and an *aggregate* is recognized structurally, not via `eval`). They
        // exist only to satisfy `eval`'s signature, exactly as the sibling morsel workers.
        let functions = empty_function_set();
        let clock = StatementClock::capture();

        // The local group table, mirroring serial `aggregate_rows` EXACTLY: a SipHash digest of the key
        // tuple (DoS-resistant per SEC-210 — group keys are client-derived property values) → the indices
        // of local groups whose key hashes there; a collision falls back to the same `row_values_equivalent`
        // resolution, so grouping semantics are identical.
        let mut groups: Vec<MorselLocalGroup> = Vec::new();
        // `rmp` #371: keyed on the already-DoS-resistant `group_key_hash` `u64` digest (the digest stays
        // SipHash); the outer index buckets it with `FxHasher`. Byte-identical grouping, no wasted re-hash.
        let mut index: rustc_hash::FxHashMap<u64, Vec<usize>> = rustc_hash::FxHashMap::default();
        let mut first_error: Option<GraphusError> = None;

        // The post-filter surviving-expansion-row counter — the LOCAL first-seen rank space (0-based),
        // incremented once per expansion row that passes the residual filter and reaches the group-by. It is
        // exactly the first-seen rank space the serial `aggregate_rows` observes (filtered-out rows never
        // reach the aggregation, so they must not advance the rank). `survivors` (the engine-thread
        // prefix-sum increment) is its final value; the ascending-`lo` prefix + the local ranks together
        // reproduce the serial surviving-row first-seen order, independent of the worker count.
        let mut produced: u64 = 0;

        // Per-edge deadline-poll counter (`rmp` #476): a single high-degree anchor can expand over millions
        // of edges, so the per-statement timeout is polled *within* one anchor's expansion, strided.
        let mut edges_seen: u64 = 0;
        'anchors: for (anchor_i, anchor) in anchors.into_iter().enumerate() {
            // Per-statement timeout safe point (`rmp` #476), strided per anchor.
            if (anchor_i as u64) & (MORSEL_DEADLINE_POLL_STRIDE - 1) == 0
                && deadline_exceeded(deadline)
            {
                first_error.get_or_insert_with(statement_timeout_error);
                break 'anchors;
            }
            // Reproduce serial `Operator::Expand` / `expand_into_pending` EXACTLY: `expand` returns the
            // incident sides (a self-loop reported once per matching direction — twice for `Both`); a
            // self-loop is collapsed to ONE produced row by deduplicating relationship ids per anchor.
            let incidents = graph.expand(anchor, dir, &type_names);
            if graph.has_error() {
                break 'anchors;
            }
            let mut seen_rel = std::collections::BTreeSet::new();
            for inc in incidents {
                // Bound a single supernode's expansion under the deadline too (strided per edge).
                edges_seen = edges_seen.wrapping_add(1);
                if edges_seen & (MORSEL_DEADLINE_POLL_STRIDE - 1) == 0
                    && deadline_exceeded(deadline)
                {
                    first_error.get_or_insert_with(statement_timeout_error);
                    break 'anchors;
                }
                if !seen_rel.insert(inc.rel) {
                    // A self-loop's second side (same rel id) — serial emits ONE row for it. Skip the dup.
                    continue;
                }

                // The serial expansion-row binding `{from: a, relationship: r, to: b}` — the row the serial
                // `Filter` / `Aggregation` see. `eval` resolves any `a`/`r`/`b` property or label against
                // this same `graph` (registering its own SIREAD markers, exactly as serial's reads do).
                let row = Row::from_pairs([
                    (
                        spec.from.name.clone(),
                        RowValue::Node(NodeRef { id: anchor }),
                    ),
                    (
                        spec.relationship.name.clone(),
                        RowValue::Rel(RelRef { id: inc.rel }),
                    ),
                    (
                        spec.to.name.clone(),
                        RowValue::Node(NodeRef { id: inc.neighbour }),
                    ),
                ]);

                // The residual filter (the interposed `Operator::Filter`, e.g. `b:ARTICLE`): keep the row
                // iff the predicate is `TRUE` under three-valued logic (NULL / FALSE drop it), byte-identical
                // to serial `read_filter_project_morsel` / `Operator::Filter`. Filtered-out rows are skipped
                // WITHOUT advancing `produced` (they never reach the serial aggregation).
                if let Some(pred) = spec.filter {
                    match eval(pred, &row, params, &graph, functions, &clock) {
                        Ok(RowValue::Value(Value::Boolean(true))) => {}
                        Ok(
                            RowValue::Value(Value::Boolean(false)) | RowValue::Value(Value::Null),
                        ) => {
                            continue;
                        }
                        Ok(_) => {
                            // A non-boolean, non-null predicate is a runtime type error — the serial path
                            // raises the identical error on fallback; this only signals "abandon".
                            first_error.get_or_insert(GraphusError::Runtime(
                                "WHERE/predicate must be a boolean".to_owned(),
                            ));
                            break 'anchors;
                        }
                        Err(e) => {
                            first_error.get_or_insert_with(|| eval_error_to_graphus(&e));
                            break 'anchors;
                        }
                    }
                }

                // A SURVIVING row: build the group-key tuple (serial `aggregate_rows`: evaluate each key
                // column against the row).
                let mut key_vals = Vec::with_capacity(spec.group_keys.len());
                for col in spec.group_keys {
                    match eval(&col.expr, &row, params, &graph, functions, &clock) {
                        Ok(v) => key_vals.push(v),
                        Err(e) => {
                            first_error.get_or_insert_with(|| eval_error_to_graphus(&e));
                            break;
                        }
                    }
                }
                if first_error.is_some() {
                    break 'anchors;
                }

                // Hash the whole key tuple, then resolve within the (normally singleton) bucket by exact
                // equivalence — byte-identical to serial `aggregate_rows`' index (the SAME SipHash digest).
                let key_hash = crate::executor::group_key_hash(&key_vals);
                let bucket = index.entry(key_hash).or_default();
                let found = bucket.iter().copied().find(|&gi| {
                    let g: &MorselLocalGroup = &groups[gi];
                    g.key.len() == key_vals.len()
                        && g.key
                            .iter()
                            .zip(&key_vals)
                            .all(|(x, y)| crate::runtime::row_values_equivalent(x, y))
                });
                let gi = match found {
                    Some(i) => i,
                    None => {
                        let gi = groups.len();
                        groups.push(MorselLocalGroup {
                            key: key_vals,
                            accs: spec
                                .aggregates
                                .iter()
                                .map(|c| crate::executor::Accumulator::new(&c.expr))
                                .collect(),
                            // The surviving-row rank at which this group was first created (pre-increment).
                            first_seen_local: produced,
                        });
                        bucket.push(gi);
                        gi
                    }
                };

                // Fold this surviving row into the group's per-column accumulators — identical to serial
                // `Accumulator::update` (via the shared `fold_bare`: `count(*)` increments; every other
                // admitted kind evaluates its single argument against the row and folds it).
                for (col, acc) in spec.aggregates.iter().zip(groups[gi].accs.iter_mut()) {
                    if let Err(e) =
                        acc.fold_bare(&col.expr, &row, params, &graph, functions, &clock)
                    {
                        first_error.get_or_insert_with(|| GraphusError::Runtime(e.to_string()));
                        break;
                    }
                }
                if first_error.is_some() {
                    break 'anchors;
                }

                // This row reached the group-by: advance the surviving-row rank.
                produced = produced.saturating_add(1);
            }
        }

        // A storage fault captured by any read (the per-anchor `expand`, or a filter / key / aggregate
        // property read) makes the whole morsel untrustworthy — surface it so the executor abandons.
        let read_error = graph.take_error();
        let error = first_error.or(read_error);
        let buffer = graph.take_buffer();

        MorselGroupOutcome {
            groups,
            // The prefix-sum increment is the count of SURVIVING (post-filter) expansion rows, so the
            // ascending-`lo` merge maps this morsel's local ranks into the global surviving-row rank space.
            survivors: produced,
            buffer,
            error,
        }
    }

    fn frontier_expand_group_aggregate_morsel(
        &self,
        anchors: &[u64],
        spec: &MorselFrontierExpandGroupSpec<'_>,
        params: &BoundParameters,
        txn: TxnId,
        snapshot: Snapshot,
        registry: &CommitRegistry,
        deadline: Option<Instant>,
    ) -> MorselGroupOutcome {
        // Off-thread read-only `GraphAccess` over a CHEAP CLONE of this source (the `rmp` #336 Slice-3b-i
        // reader): its `expand` routes through the SAME lifted `read_source::expand` body serial's
        // `Operator::Expand` runs, and `eval` over it produces byte-identical filter decisions (INCLUDING
        // the anti-join pattern-existence predicate, which reads the graph through this same seam) + key /
        // aggregate-argument values. Its own fresh `SsiReadBuffer` (tagged `txn`) catches every per-edge
        // marker AND every per-row property / label / anti-join read — taken back below and folded at
        // convergence, so the merged conflict graph is the UNION of the morsels' markers = serial's.
        let graph = ReadOnlyGraph::new(
            self.view.clone(),
            self.tokens.clone(),
            snapshot,
            registry.clone(),
            txn,
            SsiReadBuffer::new(txn),
        );

        // Resolve the final-hop pieces ONCE (shared across every anchor) — identical incidents to serial.
        let dir = ExpandDirection::from_pattern(spec.direction);
        let type_names: Vec<String> = spec.types.iter().map(|t| t.name.clone()).collect();

        // The per-row evaluator state: the empty UDF set + a captured clock. The recognizer's purity gate
        // rejects a function call in every group key / aggregate argument and in the anti-join pattern, so
        // neither is ever consulted; both exist only to satisfy `eval`'s signature (as the sibling workers).
        let functions = empty_function_set();
        let clock = StatementClock::capture();

        // The local group table, mirroring serial `aggregate_rows` EXACTLY (SipHash digest of the key tuple
        // + `row_values_equivalent` collision resolution), so grouping semantics are identical.
        let mut groups: Vec<MorselLocalGroup> = Vec::new();
        let mut index: rustc_hash::FxHashMap<u64, Vec<usize>> = rustc_hash::FxHashMap::default();
        let mut first_error: Option<GraphusError> = None;

        // The post-filter surviving-expansion-row counter — the LOCAL first-seen rank space. (The group
        // output order is re-sorted by the query's ORDER BY above the aggregation, so this rank only needs
        // to be well-defined + worker-count-independent; the surviving-row count is that.)
        let mut produced: u64 = 0;
        let mut edges_seen: u64 = 0;
        'anchors: for (anchor_i, &anchor) in anchors.iter().enumerate() {
            // Per-statement timeout safe point (`rmp` #476), strided per anchor.
            if (anchor_i as u64) & (MORSEL_DEADLINE_POLL_STRIDE - 1) == 0
                && deadline_exceeded(deadline)
            {
                first_error.get_or_insert_with(statement_timeout_error);
                break 'anchors;
            }
            // Reproduce serial `Operator::Expand` EXACTLY: `expand` returns the incident sides (a self-loop
            // reported once per matching direction — twice for `Both`); dedup relationship-ids per anchor so
            // a self-loop yields ONE row, byte-identical to the serial expand.
            let incidents = graph.expand(NodeId(anchor), dir, &type_names);
            if graph.has_error() {
                break 'anchors;
            }
            let mut seen_rel = std::collections::BTreeSet::new();
            for inc in incidents {
                edges_seen = edges_seen.wrapping_add(1);
                if edges_seen & (MORSEL_DEADLINE_POLL_STRIDE - 1) == 0
                    && deadline_exceeded(deadline)
                {
                    first_error.get_or_insert_with(statement_timeout_error);
                    break 'anchors;
                }
                if !seen_rel.insert(inc.rel) {
                    continue; // a self-loop's second side (same rel id) — serial emits ONE row for it.
                }

                // The serial expansion-row binding `{constants…, from: a, relationship: r, to: b}` — the row
                // the serial `Filter` / `Aggregation` see. The constants (e.g. the single seed `me`) are the
                // downstream-referenced vars the earlier sub-plan bound to a value constant across the whole
                // frontier; injecting them lets `eval` resolve the anti-join's `me` identically to serial.
                let mut row = Row::empty();
                for (name, value) in spec.constants {
                    row.set(name.clone(), value.clone());
                }
                row.set(
                    spec.from.name.clone(),
                    RowValue::Node(NodeRef { id: NodeId(anchor) }),
                );
                row.set(
                    spec.relationship.name.clone(),
                    RowValue::Rel(RelRef { id: inc.rel }),
                );
                row.set(
                    spec.to.name.clone(),
                    RowValue::Node(NodeRef { id: inc.neighbour }),
                );

                // The residual filters (the interposed `Operator::Filter`s, e.g. `p:Product` then
                // `NOT (me)-[:PURCHASED]->(p)`), in serial application order: keep the row iff EVERY
                // predicate is `TRUE` under three-valued logic (NULL / FALSE drop it). Filtered-out rows are
                // skipped WITHOUT advancing `produced` (they never reach the serial aggregation). The
                // anti-join reads the graph through `graph`, recording its markers into this morsel's buffer.
                let mut kept = true;
                for &pred in spec.residual_filters {
                    match eval(pred, &row, params, &graph, functions, &clock) {
                        Ok(RowValue::Value(Value::Boolean(true))) => {}
                        Ok(
                            RowValue::Value(Value::Boolean(false)) | RowValue::Value(Value::Null),
                        ) => {
                            kept = false;
                            break;
                        }
                        Ok(_) => {
                            first_error.get_or_insert(GraphusError::Runtime(
                                "WHERE/predicate must be a boolean".to_owned(),
                            ));
                            break 'anchors;
                        }
                        Err(e) => {
                            first_error.get_or_insert_with(|| eval_error_to_graphus(&e));
                            break 'anchors;
                        }
                    }
                }
                if !kept {
                    continue;
                }

                // A SURVIVING row: build the group-key tuple (serial `aggregate_rows`).
                let mut key_vals = Vec::with_capacity(spec.group_keys.len());
                for col in spec.group_keys {
                    match eval(&col.expr, &row, params, &graph, functions, &clock) {
                        Ok(v) => key_vals.push(v),
                        Err(e) => {
                            first_error.get_or_insert_with(|| eval_error_to_graphus(&e));
                            break;
                        }
                    }
                }
                if first_error.is_some() {
                    break 'anchors;
                }

                let key_hash = crate::executor::group_key_hash(&key_vals);
                let bucket = index.entry(key_hash).or_default();
                let found = bucket.iter().copied().find(|&gi| {
                    let g: &MorselLocalGroup = &groups[gi];
                    g.key.len() == key_vals.len()
                        && g.key
                            .iter()
                            .zip(&key_vals)
                            .all(|(x, y)| crate::runtime::row_values_equivalent(x, y))
                });
                let gi = match found {
                    Some(i) => i,
                    None => {
                        let gi = groups.len();
                        groups.push(MorselLocalGroup {
                            key: key_vals,
                            accs: spec
                                .aggregates
                                .iter()
                                .map(|c| crate::executor::Accumulator::new(&c.expr))
                                .collect(),
                            first_seen_local: produced,
                        });
                        bucket.push(gi);
                        gi
                    }
                };

                // Fold this surviving row into the group's per-column accumulators — identical to serial
                // (via `fold_bare`: `count(*)` increments; `count(DISTINCT from)` dedups the anchor node by
                // identity into the group's distinct set; every other admitted kind folds its argument).
                for (col, acc) in spec.aggregates.iter().zip(groups[gi].accs.iter_mut()) {
                    if let Err(e) =
                        acc.fold_bare(&col.expr, &row, params, &graph, functions, &clock)
                    {
                        first_error.get_or_insert_with(|| GraphusError::Runtime(e.to_string()));
                        break;
                    }
                }
                if first_error.is_some() {
                    break 'anchors;
                }

                produced = produced.saturating_add(1);
            }
        }

        let read_error = graph.take_error();
        let error = first_error.or(read_error);
        let buffer = graph.take_buffer();

        MorselGroupOutcome {
            groups,
            survivors: produced,
            buffer,
            error,
        }
    }

    fn clone_box(&self) -> Box<dyn MorselSource> {
        // Cheap: `StoreReadView::clone` is a few `Arc` bumps and `TokenSnapshot::clone` is one. No page
        // or id-vector copy.
        Box::new(MorselView {
            view: self.view.clone(),
            tokens: self.tokens.clone(),
        })
    }
}

/// A per-morsel [`ReadSink`]: the morsel's **own** owned [`SsiReadBuffer`] (no shared lock) plus its
/// **own** first-captured-error cell (`rmp` task #339). Mutated only by the one worker that owns the
/// morsel, through `&self` (the [`ReadSink`] methods take `&self`), so the interior
/// [`RefCell`](std::cell::RefCell)s are sound — the sink is never shared across threads.
struct MorselSink {
    buffer: std::cell::RefCell<SsiReadBuffer>,
    error: std::cell::RefCell<Option<GraphusError>>,
}

impl MorselSink {
    fn new(txn: TxnId) -> Self {
        Self {
            buffer: std::cell::RefCell::new(SsiReadBuffer::new(txn)),
            error: std::cell::RefCell::new(None),
        }
    }

    /// Consumes the sink into its accumulated buffer + first captured error.
    fn into_parts(self) -> (SsiReadBuffer, Option<GraphusError>) {
        (self.buffer.into_inner(), self.error.into_inner())
    }
}

impl ReadSink for MorselSink {
    fn note_read(&self, key: u64) {
        self.buffer.borrow_mut().record_read(key);
    }

    fn note_predicate_read(&self, predicate: PredicateRead) {
        // A morsel records only per-candidate (key) markers; the coarse predicate footprint
        // (`PredicateRead::Label` + `mark_all_live_nodes`) is registered ONCE on the engine thread when
        // the bundle is built. But `filter_label_candidates` itself records no predicate marker, so this
        // is reached only defensively — buffer it anyway so no marker is ever silently dropped.
        self.buffer.borrow_mut().record_predicate_read(predicate);
    }

    fn capture(&self, err: GraphusError) {
        let mut slot = self.error.borrow_mut();
        if slot.is_none() {
            *slot = Some(err);
        }
    }
}

// =================================================================================================
// Per-row evaluation helpers (Slice 3b) — the empty UDF set, error mapping, and the purity gate
// =================================================================================================

/// A process-global **empty** [`FunctionSet`] (`rmp` task #339, Slice 3b). The morsel scan→filter→project
/// path drives [`crate::eval::eval`], whose signature requires a `&dyn FunctionRegistry`, but the
/// engine-thread purity gate ([`is_pure_per_row_expr`]) rejects every expression containing a function
/// call before the morsel path is taken — so this registry is **provably never consulted**. It exists
/// only to satisfy the signature, allocated once.
fn empty_function_set() -> &'static FunctionSet {
    static EMPTY: OnceLock<FunctionSet> = OnceLock::new();
    EMPTY.get_or_init(FunctionSet::new)
}

/// Maps an [`EvalError`](crate::eval::EvalError) hit on the morsel path to a [`GraphusError`] (`rmp` task
/// #339, Slice 3b). The precise variant is immaterial — any morsel error makes the executor discard the
/// parallel result and re-run the serial pipeline, which raises the **identical** precise error to the
/// user — so the morsel error only needs to be non-`None` to signal "abandon". Mirrors the executor's
/// `From<ExecError> for GraphusError` (every evaluation failure is a Cypher *runtime* error).
fn eval_error_to_graphus(e: &crate::eval::EvalError) -> GraphusError {
    GraphusError::Runtime(e.to_string())
}

/// Whether `expr` is a **pure, per-row** expression the Slice-3b morsel path may evaluate off the engine
/// thread (`rmp` task #339): one whose value depends only on this single row's bindings and the per-row
/// graph read, is **deterministic**, and forms **no cross-row dependency** — so the contiguous-concat of
/// the morsels' rows (and the per-morsel sort feeding the stable k-way merge) is provably byte-identical
/// to the serial scan→filter→project / ORDER BY.
///
/// # The allowlist (conservative by design — `false` ⇒ the executor runs the serial pipeline verbatim)
///
/// Accepted: literals, parameters, variables, the arithmetic / comparison / boolean / string-list-null
/// operators, property access, list indexing / slicing, label predicates, list / map literals, and
/// `CASE` — provided **every** sub-expression is itself pure. These read only the row + a single node's /
/// relationship's snapshot-visible properties, deterministically, with no cross-row state.
///
/// Rejected (⇒ serial): **any function call** (`FunctionCall` — even a deterministic built-in like
/// `toUpper`; v1 takes the safe blanket exclusion so a non-deterministic built-in such as `rand()` /
/// `randomUUID()` / `timestamp()` can never slip through — a deterministic-builtin allowlist is a
/// follow-on), `count(*)` and every aggregate (cross-row by definition), list / pattern comprehensions
/// and quantifiers (`all`/`any`/`none`/`single`, which run an embedded traversal whose order /
/// `collect` semantics the contiguous concat cannot prove identical), and existential subqueries (which
/// execute a whole nested query). Excluding these guarantees the per-row evaluator on a worker thread is
/// deterministic and cross-row-free.
#[must_use]
pub fn is_pure_per_row_expr(expr: &Expr) -> bool {
    use crate::ast::ExprKind;
    match &expr.kind {
        // Leaves that read only the row / params / a literal — always pure.
        ExprKind::Literal(_) | ExprKind::Parameter(_) | ExprKind::Variable(_) => true,

        // Operators / accessors / constructors: pure iff every operand is pure.
        ExprKind::Binary { lhs, rhs, .. } => is_pure_per_row_expr(lhs) && is_pure_per_row_expr(rhs),
        ExprKind::Unary { operand, .. } => is_pure_per_row_expr(operand),
        ExprKind::Predicate { operand, rhs, .. } => {
            is_pure_per_row_expr(operand) && rhs.as_deref().is_none_or(is_pure_per_row_expr)
        }
        ExprKind::Property { base, .. } => is_pure_per_row_expr(base),
        ExprKind::Index { base, index } => {
            is_pure_per_row_expr(base) && is_pure_per_row_expr(index)
        }
        ExprKind::Slice { base, low, high } => {
            is_pure_per_row_expr(base)
                && low.as_deref().is_none_or(is_pure_per_row_expr)
                && high.as_deref().is_none_or(is_pure_per_row_expr)
        }
        ExprKind::HasLabels { operand, .. }
        | ExprKind::TypePredicate { operand, .. }
        | ExprKind::NormalizedPredicate { operand, .. } => is_pure_per_row_expr(operand),
        ExprKind::List(items) => items.iter().all(is_pure_per_row_expr),
        ExprKind::Map(entries) => entries.iter().all(|(_, v)| is_pure_per_row_expr(v)),
        ExprKind::Case(case) => {
            case.subject.as_deref().is_none_or(is_pure_per_row_expr)
                && case
                    .alternatives
                    .iter()
                    .all(|alt| is_pure_per_row_expr(&alt.when) && is_pure_per_row_expr(&alt.then))
                && case.else_expr.as_deref().is_none_or(is_pure_per_row_expr)
        }

        // Cross-row / non-deterministic / nested-query shapes: always decline (serial path). `reduce`
        // and map projection are pure per row, but — like the comprehensions / quantifiers above —
        // are declined here conservatively: the intra-query morsel fast-path stays limited to the
        // simple operator/accessor shapes, and these forms fall to the (correct) serial evaluator.
        ExprKind::FunctionCall { .. }
        | ExprKind::CountStar
        | ExprKind::ListComprehension(_)
        | ExprKind::PatternComprehension(_)
        | ExprKind::Quantifier(_)
        | ExprKind::Reduce(_)
        | ExprKind::MapProjection(_)
        | ExprKind::ExistsSubquery(_)
        | ExprKind::CountSubquery(_)
        | ExprKind::CollectSubquery(_) => false,
    }
}

// =================================================================================================
// MorselLabelScan — the engine-thread bundle handed to the tier
// =================================================================================================

/// The concrete, `(D, S)`-free, `Send` bundle the `RecordStoreGraph::morsel_label_scan` seam hands the
/// executor's morsel tier (`rmp` task #339): the authoritative candidate-id vector for a label scan,
/// the resolved label token, an erased [`MorselSource`] over the engine-thread-captured read view, and
/// the visibility inputs (pinned snapshot + cloned commit registry + the query txn).
///
/// The coarse predicate footprint (`PredicateRead::Label` + `mark_all_live_nodes`) is **already
/// registered on the engine thread** by the seam impl before this bundle is returned, so taking the
/// morsel path closes the same phantom rw-edges the serial scan would.
///
/// It is `Send` (asserted below) so the tier can partition it and dispatch each morsel onto the
/// dedicated worker pool; it is `(D, S)`-free because the only store-touching field is a
/// `Box<dyn MorselSource>`.
#[must_use]
pub struct MorselLabelScan {
    /// The authoritative current candidate ids for the label scan (the same source
    /// `scan_nodes_by_label` drives off: an index `seek_label`, or a full id scan), captured on the
    /// engine thread. Partitioned into contiguous morsels by the tier.
    pub candidates: Vec<u64>,
    /// The resolved `Label`-namespace token id of the scanned label.
    pub label_token: u32,
    /// The erased read surface every morsel runs over (cheap-cloned per morsel via `clone_box`).
    pub source: Box<dyn MorselSource>,
    /// This query's pinned MVCC read snapshot.
    pub snapshot: Snapshot,
    /// A clone of this query's commit registry (resolves an in-flight writer to its outcome).
    pub registry: CommitRegistry,
    /// The transaction this query runs in (every morsel's markers are tagged with it).
    pub txn: TxnId,
    /// The per-statement wall-clock **deadline** (`rmp` #476), or `None` when no statement timeout is
    /// configured. The seam builds this `None`; the executor's morsel tier sets it from the cursor's
    /// [`CancellationToken::deadline`](crate::executor::CancellationToken::deadline) before dispatch, so
    /// every morsel worker shares the same cooperative CPU budget the serial safe points enforce — a
    /// runaway parallel scan abandons rather than pinning every core. `None` (the deterministic engine,
    /// where the morsel tier is off anyway, and the no-timeout config) leaves the workers wall-clock-free.
    pub deadline: Option<Instant>,
}

// `rmp` #339, Slice 3a: `MorselLabelScan` must be `Send` so the tier can move morsels onto the worker
// pool. A compile-time assertion (no runtime body): it fails to build the instant a non-`Send` field is
// introduced. `Box<dyn MorselSource>` is `Send` because the trait is `Send + Sync`; `Vec<u64>` / `u32`
// / `Snapshot` / `CommitRegistry` / `TxnId` are plain `Send` data.
const _: () = {
    fn assert_send<T: Send>() {}
    fn assert_morsel_label_scan() {
        assert_send::<MorselLabelScan>();
    }
    let _ = assert_morsel_label_scan;
};

impl MorselLabelScan {
    /// Reads `candidates[range]` as one morsel on the **current** thread (`rmp` task #339): cheap-clones
    /// the source and drives [`MorselSource::read_label_morsel`] over the slice. Called by the tier
    /// inside the dedicated worker pool, once per morsel.
    pub fn read_morsel(&self, lo: usize, hi: usize, property: &str) -> MorselReadOutcome {
        let slice = &self.candidates[lo..hi];
        self.source.clone_box().read_label_morsel(
            slice,
            self.label_token,
            property,
            self.txn,
            self.snapshot,
            &self.registry,
        )
    }

    /// Reads + filters + projects `candidates[lo..hi]` as one morsel on the **current** thread (`rmp`
    /// task #339, Slice 3b): cheap-clones the source and drives
    /// [`MorselSource::read_filter_project_morsel`] over the slice with `scan_var` / `filter` /
    /// `projection` / `sort_keys` / `params`. Called by [`run_scan_filter_morsels`] inside the dedicated
    /// worker pool, once per morsel.
    #[allow(clippy::too_many_arguments)] // a per-morsel read worker; the seams are positional
    pub fn read_filter_project_morsel(
        &self,
        lo: usize,
        hi: usize,
        scan_var: &str,
        filter: Option<&Expr>,
        projection: &[ProjectionColumn],
        sort_keys: &[SortKey],
        params: &BoundParameters,
    ) -> MorselRowsOutcome {
        let slice = &self.candidates[lo..hi];
        self.source.clone_box().read_filter_project_morsel(
            slice,
            self.label_token,
            scan_var,
            filter,
            projection,
            sort_keys,
            params,
            self.txn,
            self.snapshot,
            &self.registry,
            self.deadline,
        )
    }

    /// Expands `candidates[lo..hi]` (the anchors) as one morsel on the **current** thread (`rmp` task
    /// #339, Slice 3c): cheap-clones the source and drives [`MorselSource::expand_morsel`] over the
    /// slice with the single-hop `plan` + `params`. Called by [`run_expand_morsels`] inside the
    /// dedicated worker pool, once per morsel.
    pub fn expand_morsel(
        &self,
        lo: usize,
        hi: usize,
        plan: &MorselExpandPlan<'_>,
        params: &BoundParameters,
    ) -> MorselExpandOutcome {
        let slice = &self.candidates[lo..hi];
        self.source.clone_box().expand_morsel(
            slice,
            self.label_token,
            plan,
            params,
            self.txn,
            self.snapshot,
            &self.registry,
            self.deadline,
        )
    }

    /// Groups + aggregates `candidates[lo..hi]` as one morsel on the **current** thread (`rmp` task
    /// #360): cheap-clones the source and drives [`MorselSource::group_aggregate_morsel`] over the slice
    /// with the recognized `spec` + `params`. Called by [`run_group_aggregate_morsels`] inside the
    /// dedicated worker pool, once per morsel.
    pub fn group_aggregate_morsel(
        &self,
        lo: usize,
        hi: usize,
        spec: &MorselGroupSpec<'_>,
        params: &BoundParameters,
    ) -> MorselGroupOutcome {
        let slice = &self.candidates[lo..hi];
        self.source.clone_box().group_aggregate_morsel(
            slice,
            self.label_token,
            spec,
            params,
            self.txn,
            self.snapshot,
            &self.registry,
            self.deadline,
        )
    }

    /// Expands + groups + aggregates `candidates[lo..hi]` (the anchors) as one morsel on the **current**
    /// thread (`rmp` task #558 / #340): cheap-clones the source and drives
    /// [`MorselSource::expand_group_aggregate_morsel`] over the slice with the recognized `spec` +
    /// `params`. Called by [`run_expand_group_aggregate_morsels`] inside the dedicated worker pool, once
    /// per morsel.
    pub fn expand_group_aggregate_morsel(
        &self,
        lo: usize,
        hi: usize,
        spec: &MorselExpandGroupSpec<'_>,
        params: &BoundParameters,
    ) -> MorselGroupOutcome {
        let slice = &self.candidates[lo..hi];
        self.source.clone_box().expand_group_aggregate_morsel(
            slice,
            self.label_token,
            spec,
            params,
            self.txn,
            self.snapshot,
            &self.registry,
            self.deadline,
        )
    }
}

/// Stably sorts the parallel `(keys, rows)` vectors by `sort_keys` (`rmp` task #339, Slice 3b), keeping
/// the two in lockstep and preserving input order on ties — exactly the serial `sort_rows`' stable
/// `keyed.sort_by(compare_sort_keys)`. Used per-morsel before the engine-thread stable k-way merge.
fn stable_sort_keyed_rows(
    keys: &mut Vec<Vec<RowValue>>,
    rows: &mut Vec<Row>,
    sort_keys: &[SortKey],
) {
    debug_assert_eq!(keys.len(), rows.len());
    // Zip into pairs so the stable sort keeps each row with its key vector, then unzip back.
    let mut paired: Vec<(Vec<RowValue>, Row)> = std::mem::take(keys)
        .into_iter()
        .zip(std::mem::take(rows))
        .collect();
    paired.sort_by(|a, b| crate::executor::compare_sort_keys(&a.0, &b.0, sort_keys));
    let (k, r): (Vec<_>, Vec<_>) = paired.into_iter().unzip();
    *keys = k;
    *rows = r;
}

/// Runs `scan`'s candidate read across contiguous morsels on the dedicated worker pool (`rmp` task
/// #339), returning one [`MorselReadOutcome`] per morsel in **ascending candidate order** (so a later
/// concat / fold reproduces the serial candidate order exactly). `threads` is the effective morsel
/// worker count (`>= 2` when this is called).
///
/// The partition is `max(MORSEL_MIN_CHUNK, n / (threads * 4))` contiguous ids per morsel — the `* 4`
/// over-subscribes so rayon's work-stealing balances a skewed distribution. Each morsel cheap-clones
/// the source and reads its slice concurrently against the shared page cache (per-frame `RwLock` read
/// latches make this safe — `rmp` #337 §1.5).
#[must_use]
pub fn run_morsels(
    scan: &MorselLabelScan,
    property: &str,
    threads: usize,
) -> Vec<MorselReadOutcome> {
    use rayon::prelude::*;

    let bounds = morsel_bounds(scan.candidates.len(), threads);
    if bounds.is_empty() {
        return Vec::new();
    }

    let deadline = scan.deadline;
    // Fan out on the DEDICATED pool (never the global rayon pool). `map` preserves input (ascending-lo)
    // order, so the returned outcomes are in ascending candidate order — the serial scan order.
    install_morsel_fanout(|| {
        bounds
            .par_iter()
            .map(|&(lo, hi)| {
                // Per-statement timeout gate (`rmp` #476): a morsel whose turn comes after the deadline
                // abandons immediately rather than reading its slice — the executor then surfaces a clean
                // `Cancelled` via the serial fallback. The bare-aggregate worker (`read_label_morsel`) does
                // O(1)-per-node work with no `eval`, so per-morsel granularity bounds it tightly enough
                // without taxing the hot per-node read with a wall-clock poll.
                if deadline_exceeded(deadline) {
                    return MorselReadOutcome::cancelled(scan.txn);
                }
                scan.read_morsel(lo, hi, property)
            })
            .collect()
    })
}

/// The contiguous morsel `[lo, hi)` boundaries for `n` candidates over `threads` workers (`rmp` task
/// #339): `max(MORSEL_MIN_CHUNK, n / (threads * 4))` ids per morsel, in ascending order — the `* 4`
/// over-subscribes so rayon's work-stealing balances a skewed distribution. Returns an empty `Vec` for
/// `n == 0`. Shared by the Slice-3a aggregate and Slice-3b row runners so they partition identically.
fn morsel_bounds(n: usize, threads: usize) -> Vec<(usize, usize)> {
    if n == 0 {
        return Vec::new();
    }
    let chunk = (n / threads.saturating_mul(4).max(1))
        .max(MORSEL_MIN_CHUNK)
        .max(1);
    (0..n)
        .step_by(chunk)
        .map(|lo| (lo, (lo + chunk).min(n)))
        .collect()
}

/// Runs `scan`'s candidate read + filter + projection across contiguous morsels on the dedicated worker
/// pool (`rmp` task #339, Slice 3b), then **converges** the morsels into a single ordered row stream
/// **byte-identical to the serial scan→filter→project (+ ORDER BY / TopN)**:
///
/// * **No `sort_keys` (Shape A)** — the morsels' projected rows are **concatenated in ascending source
///   index (`lo`) order**. Each morsel reads a *contiguous* candidate slice and
///   `filter_label_candidates` preserves input order, so the concat reproduces the serial candidate
///   order exactly, independent of the worker count.
/// * **With `sort_keys` (Shape B)** — each morsel pre-sorts its rows **stably** by the keys (ties keep
///   candidate order); a **stable k-way merge** ([`stable_kway_merge`]) over the per-morsel runs, using
///   the same total order ([`crate::executor::compare_sort_keys`]) with the ascending-`lo` morsel index
///   as the tiebreak, reproduces the serial stable `sort_by` byte-for-byte. `top_n`, when given, bounds
///   the merge output to the first `n` rows (the `TopN` fusion) — identical to serial `sort_rows`'
///   `truncate(n)` over the fully stable order.
///
/// Returns the converged rows in result order, the **concatenation** of every morsel's SIREAD buffer
/// markers (the executor folds them back via `merge_morsel_buffer`, whose sort+dedup yields the union =
/// the serial marker set), and the first morsel error (if any — the executor then discards everything and
/// falls back to the serial pipeline). `threads` is the effective worker count (`>= 2` when called).
#[allow(clippy::too_many_arguments)] // a fan-out entry point; the plan pieces are positional borrows
pub fn run_scan_filter_morsels(
    scan: &MorselLabelScan,
    scan_var: &str,
    filter: Option<&Expr>,
    projection: &[ProjectionColumn],
    sort_keys: &[SortKey],
    top_n: Option<usize>,
    params: &BoundParameters,
    threads: usize,
) -> ScanFilterConverged {
    use rayon::prelude::*;

    let bounds = morsel_bounds(scan.candidates.len(), threads);
    if bounds.is_empty() {
        return ScanFilterConverged::default();
    }

    // Fan out on the DEDICATED pool (never the global rayon pool). `map` preserves input (ascending-lo)
    // order, so the outcomes are in ascending candidate order — the serial scan order.
    let outcomes: Vec<MorselRowsOutcome> = install_morsel_fanout(|| {
        bounds
            .par_iter()
            .map(|&(lo, hi)| {
                scan.read_filter_project_morsel(
                    lo, hi, scan_var, filter, projection, sort_keys, params,
                )
            })
            .collect()
    });

    converge_scan_filter_outcomes(outcomes, sort_keys, top_n)
}

/// Converges the per-morsel scan→filter→project `outcomes` (in **ascending source-index order**) into one
/// ordered row stream + the morsels' buffers (`rmp` task #339, Slice 3b). Split out of
/// [`run_scan_filter_morsels`] so the fan-out and the converge are testable independently (the
/// equivalence test drives an explicit morsel split through this exact converge):
///
/// * **No `sort_keys`** — contiguous concat in input (ascending-lo) order = the serial candidate order.
/// * **With `sort_keys`** — stable k-way merge of the per-morsel **pre-sorted** runs (ties → ascending-lo
///   = serial candidate order), then `top_n` truncation = serial `sort_rows`' stable sort + `truncate(n)`.
///
/// On any morsel error the rows are returned empty (the caller discards them and the buffers, then runs
/// serial), with the first error surfaced.
pub fn converge_scan_filter_outcomes(
    outcomes: Vec<MorselRowsOutcome>,
    sort_keys: &[SortKey],
    top_n: Option<usize>,
) -> ScanFilterConverged {
    // The buffers are concatenated (the executor's `merge_morsel_buffer` sorts + dedups them into the
    // union); the first error (if any) is surfaced so the caller abandons.
    let mut buffers: Vec<SsiReadBuffer> = Vec::with_capacity(outcomes.len());
    let mut first_error: Option<GraphusError> = None;
    // The per-morsel rows (and, for Shape B, their parallel pre-sorted key vectors), in ascending-lo
    // order — the merge / concat input.
    let mut runs: Vec<(Vec<Vec<RowValue>>, Vec<Row>)> = Vec::with_capacity(outcomes.len());
    for o in outcomes {
        if first_error.is_none() && o.error.is_some() {
            first_error = o.error;
        }
        buffers.push(o.buffer);
        runs.push((o.keys, o.rows));
    }

    // On any morsel error, the rows are untrustworthy — return them empty (the caller discards them and
    // every buffer too, then runs serial). The buffers are still returned so a defensive caller could
    // inspect, but the executor tier drops them on the error path.
    let rows = if first_error.is_some() {
        Vec::new()
    } else if sort_keys.is_empty() {
        // Shape A: contiguous concat in ascending-lo order.
        let mut out = Vec::with_capacity(runs.iter().map(|(_, r)| r.len()).sum());
        for (_, r) in runs {
            out.extend(r);
        }
        out
    } else {
        // Shape B: stable k-way merge of the per-morsel stably-sorted runs, ties broken by ascending-lo.
        let key_runs: Vec<Vec<Vec<RowValue>>> = runs.iter().map(|(k, _)| k.clone()).collect();
        let row_runs: Vec<Vec<Row>> = runs.into_iter().map(|(_, r)| r).collect();
        stable_kway_merge(key_runs, row_runs, sort_keys, top_n)
    };

    ScanFilterConverged {
        rows,
        buffers,
        error: first_error,
    }
}

/// The converged result of [`run_scan_filter_morsels`] (`rmp` task #339, Slice 3b): the ordered rows,
/// every morsel's SIREAD buffer (the executor folds each back via `merge_morsel_buffer`), and the first
/// morsel error (if any). On an error the `rows` are empty and the caller discards the buffers too,
/// falling back to the serial pipeline.
#[must_use]
#[derive(Default)]
pub struct ScanFilterConverged {
    /// The converged rows in result order (contiguous concat, or stable-merged + `TopN`-truncated).
    pub rows: Vec<Row>,
    /// Every morsel's SIREAD buffer, in ascending-lo order. The executor merges each into the statement
    /// tracker (sort + dedup ⇒ union = the serial marker set). Returned even on the error path so the
    /// caller can drop them explicitly.
    pub buffers: Vec<SsiReadBuffer>,
    /// The first morsel error, or `None`. While set, `rows` is empty and the caller runs serial.
    pub error: Option<GraphusError>,
}

/// A **stable** k-way merge of per-morsel **pre-sorted** runs (`rmp` task #339, Slice 3b), reproducing
/// the serial stable `sort_rows` byte-for-byte. `key_runs[m]` / `row_runs[m]` are morsel `m`'s rows
/// already stably sorted by `keys`; the merge repeatedly takes the **globally smallest** head across the
/// runs, and on a tie takes the **lowest morsel index** (= ascending-`lo` = the serial candidate order)
/// — so equal-key rows keep exactly the order serial's stable `sort_by` would give them. `top_n` bounds
/// the output to the first `n` rows (the `TopN` fusion).
///
/// Complexity: a linear scan of the (≤ #morsels) run heads per emitted row. The morsel count is bounded
/// (oversubscribe × worker count), so this is effectively O(rows × morsels) with a tiny constant — and
/// `top_n` short-circuits after `n` rows.
fn stable_kway_merge(
    key_runs: Vec<Vec<Vec<RowValue>>>,
    row_runs: Vec<Vec<Row>>,
    keys: &[SortKey],
    top_n: Option<usize>,
) -> Vec<Row> {
    debug_assert_eq!(key_runs.len(), row_runs.len());
    // A cursor (next-unconsumed index) into each run.
    let mut cursors: Vec<usize> = vec![0; key_runs.len()];
    let total: usize = row_runs.iter().map(Vec::len).sum();
    let cap = top_n.map_or(total, |n| n.min(total));
    let mut out: Vec<Row> = Vec::with_capacity(cap);

    // `row_runs` is consumed by moving each row out as it is emitted; track the rows via `Option` so a
    // taken row leaves a hole without shifting the rest. (Cloning the `Row` would also be correct but
    // copies node/rel ids needlessly.)
    let mut row_runs: Vec<Vec<Option<Row>>> = row_runs
        .into_iter()
        .map(|r| r.into_iter().map(Some).collect())
        .collect();

    loop {
        if let Some(n) = top_n {
            if out.len() >= n {
                break;
            }
        }
        // Find the run whose current head is the globally smallest key, ties → lowest run index.
        let mut best: Option<usize> = None;
        for (m, cur) in cursors.iter().enumerate() {
            if *cur >= key_runs[m].len() {
                continue; // this run is exhausted
            }
            best = Some(match best {
                None => m,
                Some(b) => {
                    // Strictly-less wins; on Equal keep the lower index `b` (stable: ascending-lo). Since
                    // we iterate `m` ascending and only replace on strictly-less, equal heads keep `b`.
                    if crate::executor::compare_sort_keys(
                        &key_runs[m][*cur],
                        &key_runs[b][cursors[b]],
                        keys,
                    ) == std::cmp::Ordering::Less
                    {
                        m
                    } else {
                        b
                    }
                }
            });
        }
        let Some(m) = best else { break }; // all runs exhausted
        let idx = cursors[m];
        // Move the chosen row out (it is `Some` — the cursor points at an unconsumed slot).
        if let Some(row) = row_runs[m][idx].take() {
            out.push(row);
        }
        cursors[m] += 1;
    }
    out
}

// =================================================================================================
// Slice 3c — the traversal (ExpandAll-over-anchor) runner + converge
// =================================================================================================

/// The converged result of [`run_expand_morsels`] (`rmp` task #339, Slice 3c): the converged rows
/// (rows-over-expand shape) **or** the summed count (aggregate-over-expand shape), every morsel's
/// SIREAD buffer (the executor folds each back via `merge_morsel_buffer`), and the first morsel error
/// (if any). On an error the `rows` are empty / `count` is `0` and the caller discards the buffers
/// too, falling back to the serial pipeline.
#[must_use]
#[derive(Default)]
pub struct ExpandConverged {
    /// The converged projected expansion rows in result order (contiguous concat in ascending anchor
    /// source-index = the serial scan→expand→project order) — empty for the aggregate-over-expand
    /// (degree) shape.
    pub rows: Vec<Row>,
    /// The summed `count(b)` / `count(*)`-over-expand value (aggregate-over-expand shape) — `0` for the
    /// rows-over-expand shape. The combine is a plain saturating sum, order-independent.
    pub count: i64,
    /// Every morsel's SIREAD buffer, in ascending-anchor-source-index order. The executor merges each
    /// into the statement tracker (sort + dedup ⇒ union = the serial scan→expand marker set). Returned
    /// even on the error path so the caller can drop them explicitly.
    pub buffers: Vec<SsiReadBuffer>,
    /// The first morsel error, or `None`. While set, `rows`/`count` are empty and the caller runs serial.
    pub error: Option<GraphusError>,
}

/// Runs `scan`'s anchor expand (`ExpandAll` per anchor) across contiguous morsels on the dedicated
/// worker pool (`rmp` task #339, Slice 3c), then **converges** them **byte-identically to the serial
/// scan→expand[→project]**:
///
/// * **Aggregate-over-expand (`plan.post == Count`)** — the morsels' per-anchor matching degrees are
///   **summed** (a saturating, order-independent combine), reproducing serial `count(b)` / `count(*)`.
/// * **Rows-over-expand (`plan.post == Project`)** — the morsels' projected expansion rows are
///   **concatenated in ascending anchor source-index (`lo`) order**. Each morsel expands a *contiguous*
///   anchor slice in serial anchor order (and per anchor, in the serial expansion order), so the concat
///   reproduces the serial scan→expand→project row sequence exactly, **independent of the worker
///   count**. (There is no ORDER BY in the first-cut 3c shape — a `Sort` above declines the tier and
///   re-sorts the concat serially, still correct.)
///
/// Returns the converged rows (or count), the **concatenation** of every morsel's SIREAD buffer markers
/// (the executor folds them back via `merge_morsel_buffer`, whose sort+dedup yields the union = the
/// serial marker set), and the first morsel error (if any). `threads` is the effective worker count
/// (`>= 2` when called).
pub fn run_expand_morsels(
    scan: &MorselLabelScan,
    plan: &MorselExpandPlan<'_>,
    params: &BoundParameters,
    threads: usize,
) -> ExpandConverged {
    use rayon::prelude::*;

    let bounds = morsel_bounds(scan.candidates.len(), threads);
    if bounds.is_empty() {
        return ExpandConverged::default();
    }

    // Fan out on the DEDICATED pool (never the global rayon pool). `map` preserves input (ascending-lo)
    // order, so the outcomes are in ascending anchor order — the serial scan→expand order.
    let outcomes: Vec<MorselExpandOutcome> = install_morsel_fanout(|| {
        bounds
            .par_iter()
            .map(|&(lo, hi)| scan.expand_morsel(lo, hi, plan, params))
            .collect()
    });

    converge_expand_outcomes(outcomes)
}

/// Converges the per-morsel expand `outcomes` (in **ascending anchor source-index order**) into one
/// ordered row stream + summed count + the morsels' buffers (`rmp` task #339, Slice 3c). Split out of
/// [`run_expand_morsels`] so the fan-out and the converge are testable independently (the equivalence
/// test drives an explicit morsel split through this exact converge):
///
/// * the `rows` are the **contiguous concat** in input (ascending-lo) order = the serial
///   scan→expand→project order (rows shape; empty for the degree shape);
/// * the `count` is the **saturating sum** of the per-morsel partial counts = serial `count` (degree
///   shape; `0` for the rows shape);
/// * on any morsel error the rows are returned empty / count `0` (the caller discards them + the buffers,
///   then runs serial), with the first error surfaced.
pub fn converge_expand_outcomes(outcomes: Vec<MorselExpandOutcome>) -> ExpandConverged {
    let mut buffers: Vec<SsiReadBuffer> = Vec::with_capacity(outcomes.len());
    let mut first_error: Option<GraphusError> = None;
    let mut count: i64 = 0;
    // The per-morsel rows in ascending-lo order — the concat input.
    let mut runs: Vec<Vec<Row>> = Vec::with_capacity(outcomes.len());
    for o in outcomes {
        if first_error.is_none() && o.error.is_some() {
            first_error = o.error;
        }
        count = count.saturating_add(o.partial_count);
        buffers.push(o.buffer);
        runs.push(o.rows);
    }

    if first_error.is_some() {
        // The result is untrustworthy — empty rows + zero count (the caller discards them + every buffer,
        // then runs serial). The buffers are still returned so a defensive caller could inspect.
        return ExpandConverged {
            rows: Vec::new(),
            count: 0,
            buffers,
            error: first_error,
        };
    }

    // Contiguous concat in ascending-lo order (each morsel's rows are already in serial anchor →
    // per-anchor expansion order).
    let mut rows = Vec::with_capacity(runs.iter().map(Vec::len).sum());
    for r in runs {
        rows.extend(r);
    }

    ExpandConverged {
        rows,
        count,
        buffers,
        error: first_error,
    }
}

// =================================================================================================
// rmp #360 — the grouped-aggregation (GROUP BY non-empty) runner + deterministic merge
// =================================================================================================

/// One fully-merged output group of the `rmp` #360 grouped tier: its group-key tuple (in
/// `spec.group_keys` order) and its per-aggregate-column combined accumulators (one per
/// `spec.aggregates`). The executor `finish`es each accumulator into the group's output row. The merge
/// produces these in **serial first-seen order** (sorted by the global first-seen rank), so the executor
/// emits them in the byte-identical order the serial `aggregate_rows` would.
#[must_use]
pub struct MergedGroup {
    /// The group-key tuple (in `spec.group_keys` order).
    pub key: Vec<RowValue>,
    /// One combined accumulator per aggregate column (in `spec.aggregates` order).
    pub accs: Vec<crate::executor::Accumulator>,
}

/// The converged result of [`run_group_aggregate_morsels`] (`rmp` task #360): the fully-merged groups in
/// serial first-seen order, every morsel's SIREAD buffer (the executor folds each back via
/// `merge_morsel_buffer`), and the first morsel error (if any). On an error the `groups` are empty and the
/// caller discards the buffers too, falling back to the serial pipeline.
#[must_use]
#[derive(Default)]
pub struct GroupAggConverged {
    /// The fully-merged groups in serial first-seen order (sorted by global first-seen rank) — empty on
    /// the error path.
    pub groups: Vec<MergedGroup>,
    /// Every morsel's SIREAD buffer, in ascending-`lo` order. The executor merges each into the statement
    /// tracker (sort + dedup ⇒ union = the serial scan's marker set). Returned even on the error path so
    /// the caller can drop them explicitly.
    pub buffers: Vec<SsiReadBuffer>,
    /// The first morsel error, or `None`. While set, `groups` is empty and the caller runs serial.
    pub error: Option<GraphusError>,
}

/// Runs `scan`'s grouped aggregation across contiguous morsels on the dedicated worker pool (`rmp` task
/// #360), then **merges** them into one group stream **byte-identical to the serial `aggregate_rows`**:
///
/// * each morsel builds a LOCAL group table over its contiguous candidate slice (same SipHash digest +
///   `row_values_equivalent` resolution serial uses) and folds survivors into per-column
///   [`Accumulator`](crate::executor::Accumulator)s;
/// * the engine thread merges the morsels **in ascending-`lo` order** into a global table — combining
///   accumulators via [`Accumulator::combine`](crate::executor::Accumulator) (associative for
///   `count`/`sum`/`min`/`max`; order-preserving for `collect`/`DISTINCT`, which is why the merge order
///   is ascending-`lo`), and reducing the global first-seen rank to the MIN across morsels of
///   `survivor_prefix(morsel) + first_seen_local`;
/// * the merged groups are emitted **sorted by global first-seen rank** — and because the contiguous
///   candidate order is order-isomorphic to serial first-seen order, this reproduces serial first-seen
///   output order EXACTLY, **independent of the worker count** (the AC's determinism).
///
/// Returns the merged groups, the **concatenation** of every morsel's SIREAD buffer (the executor folds
/// them back via `merge_morsel_buffer`, whose sort+dedup yields the union = the serial marker set), and
/// the first morsel error (if any — the executor then discards everything and runs serial). `threads` is
/// the effective worker count (`>= 2` when called).
pub fn run_group_aggregate_morsels(
    scan: &MorselLabelScan,
    spec: &MorselGroupSpec<'_>,
    params: &BoundParameters,
    threads: usize,
) -> GroupAggConverged {
    use rayon::prelude::*;

    let bounds = morsel_bounds(scan.candidates.len(), threads);
    if bounds.is_empty() {
        return GroupAggConverged::default();
    }

    // Fan out on the DEDICATED pool (never the global rayon pool). `map` preserves input (ascending-lo)
    // order, so the outcomes are in ascending candidate order — the serial scan order, which the merge
    // relies on for the survivor prefix-sum and the order-sensitive `collect` / `DISTINCT` combine.
    let outcomes: Vec<MorselGroupOutcome> = install_morsel_fanout(|| {
        bounds
            .par_iter()
            .map(|&(lo, hi)| scan.group_aggregate_morsel(lo, hi, spec, params))
            .collect()
    });

    converge_group_aggregate_outcomes(outcomes)
}

/// Runs `scan`'s **grouped aggregation over an expand** across contiguous ANCHOR morsels on the dedicated
/// worker pool (`rmp` task #558 / #340 — the `top_liked` class), then **merges** them into one group
/// stream **byte-identical to the serial scan→expand→filter→aggregate**:
///
/// * each morsel expands a *contiguous* anchor slice through the same lifted `read_source::expand` body
///   serial runs (over a [`ReadOnlyGraph`]), applies the optional residual filter, and folds each
///   surviving `(a, r, b)` row into a LOCAL group table (same SipHash digest + `row_values_equivalent`
///   resolution serial uses) — its `first_seen_local` rank + `survivors` count are over the SURVIVING
///   (post-filter) expansion rows, the serial first-seen rank space;
/// * the engine thread reuses the #360 [`converge_group_aggregate_outcomes`] **verbatim** — the
///   per-morsel outcome is the identical [`MorselGroupOutcome`] type — combining accumulators
///   (associative for `count`/`sum`/`min`/`max`; order-preserving ascending-`lo` for `collect`/`DISTINCT`)
///   and reducing the global first-seen rank to the MIN across morsels of
///   `survivor_prefix(morsel) + first_seen_local`, emitting groups **sorted by global first-seen rank**
///   (= serial first-seen output order, independent of the worker count).
///
/// Returns the merged groups, the concatenation of every morsel's SIREAD buffer (the executor folds them
/// back via `merge_morsel_buffer`, whose sort+dedup yields the union = the serial marker set), and the
/// first morsel error (if any — the executor then discards everything and runs serial). `threads` is the
/// effective worker count (`>= 2` when called).
pub fn run_expand_group_aggregate_morsels(
    scan: &MorselLabelScan,
    spec: &MorselExpandGroupSpec<'_>,
    params: &BoundParameters,
    threads: usize,
) -> GroupAggConverged {
    use rayon::prelude::*;

    let bounds = morsel_bounds(scan.candidates.len(), threads);
    if bounds.is_empty() {
        return GroupAggConverged::default();
    }

    // Fan out on the DEDICATED pool (never the global rayon pool). `map` preserves input (ascending-lo)
    // order, so the outcomes are in ascending anchor order — the serial scan→expand order, which the merge
    // relies on for the surviving-row prefix-sum and the order-sensitive `collect` / `DISTINCT` combine.
    let outcomes: Vec<MorselGroupOutcome> = install_morsel_fanout(|| {
        bounds
            .par_iter()
            .map(|&(lo, hi)| scan.expand_group_aggregate_morsel(lo, hi, spec, params))
            .collect()
    });

    // The #360 grouped merge is shape-agnostic — it needs only that `survivors` maps local first-seen ranks
    // into the global rank space, which the surviving-row counts satisfy — so it is reused verbatim.
    converge_group_aggregate_outcomes(outcomes)
}

// =================================================================================================
// rmp #575 — the frontier-seeded grouped-aggregation-over-a-final-expand (the `r3_fof3` reco class)
// =================================================================================================

/// The minimum contiguous frontier-morsel size (`rmp` task #575): a frontier morsel never covers fewer
/// than this many anchors. Much smaller than [`MORSEL_MIN_CHUNK`] because each frontier anchor drives
/// **substantial** per-anchor work (a fresh expand of its final-hop edges + the residual filters —
/// including the graph anti-join — + the grouped fold), not the O(1) property read a bare label-scan
/// candidate does. So a frontier of a few thousand anchors still fans across every core; the `* 4`
/// over-subscribe (below) then lets work-stealing balance a skewed final-hop-degree distribution.
pub const MORSEL_FRONTIER_MIN_CHUNK: usize = 256;

/// The contiguous frontier-morsel `[lo, hi)` boundaries for `n` anchors over `threads` workers
/// (`rmp` task #575): `max(MORSEL_FRONTIER_MIN_CHUNK, n / (threads * 4))` anchors per morsel, ascending.
/// Empty for `n == 0`. Analogous to [`morsel_bounds`] but with the smaller heavy-per-anchor min chunk.
fn frontier_morsel_bounds(n: usize, threads: usize) -> Vec<(usize, usize)> {
    if n == 0 {
        return Vec::new();
    }
    let chunk = (n / threads.saturating_mul(4).max(1))
        .max(MORSEL_FRONTIER_MIN_CHUNK)
        .max(1);
    (0..n)
        .step_by(chunk)
        .map(|lo| (lo, (lo + chunk).min(n)))
        .collect()
}

/// The engine-thread-captured **read surface + visibility inputs** the `rmp` #575 frontier tier's seam
/// ([`GraphAccess::frontier_morsel_source`](crate::graph_access::GraphAccess::frontier_morsel_source))
/// hands the executor, *before* it materializes the frontier anchors. Unlike
/// [`MorselLabelScan`] the seam registers **no** coarse predicate footprint (there is no label scan to
/// guard — see [`MorselFrontierScan`]); it only captures the owned, `Send`, cheap-cloneable
/// [`MorselSource`] + the pinned snapshot / commit registry / txn. The executor drains the earlier
/// sub-plan serially, dedups the anchors, and combines them with this into a [`MorselFrontierScan`].
#[must_use]
pub struct MorselFrontierSource {
    /// The erased read surface every morsel runs over (an owned `StoreReadView` + `TokenSnapshot`).
    pub source: Box<dyn MorselSource>,
    /// This query's pinned MVCC read snapshot.
    pub snapshot: Snapshot,
    /// A clone of this query's commit registry.
    pub registry: CommitRegistry,
    /// The transaction this query runs in.
    pub txn: TxnId,
}

/// The engine-thread bundle the `rmp` #575 frontier tier hands the fan-out: the distinct **frontier
/// anchor** ids (the earlier sub-plan's `from`, e.g. `f3`, materialized + deduped serially — every
/// first-`MATCH` marker already recorded on the engine thread), an erased [`MorselSource`] over the
/// engine-thread-captured read surface (cheap-cloned per morsel), and the visibility inputs.
///
/// Unlike [`MorselLabelScan`] there is **no** coarse label-scan predicate footprint to register here: the
/// anchors are bound nodes (not a label scan), the final hop's relationship-pattern predicate + per-edge
/// markers are recorded by each morsel's own `expand`, and the earlier sub-plan already registered the
/// `mark_all_live_nodes` phantom footprint for the anchor set on the engine thread — so the parallel
/// path's marker UNION is byte-identical to serial without any coarse registration in the seam.
#[must_use]
pub struct MorselFrontierScan {
    /// The distinct frontier anchor ids, partitioned into contiguous morsels by the tier.
    pub anchors: Vec<u64>,
    /// The erased read surface every morsel runs over (cheap-cloned per morsel via `clone_box`).
    pub source: Box<dyn MorselSource>,
    /// This query's pinned MVCC read snapshot.
    pub snapshot: Snapshot,
    /// A clone of this query's commit registry (resolves an in-flight writer to its outcome).
    pub registry: CommitRegistry,
    /// The transaction this query runs in (every morsel's markers are tagged with it).
    pub txn: TxnId,
    /// The per-statement wall-clock deadline (`rmp` #476), set by the executor before dispatch.
    pub deadline: Option<Instant>,
}

// `MorselFrontierScan` must be `Send` so the tier can move morsels onto the worker pool (as
// `MorselLabelScan`); a compile-time assertion that fails the instant a non-`Send` field is introduced.
const _: () = {
    fn assert_send<T: Send>() {}
    fn assert_frontier_scan() {
        assert_send::<MorselFrontierScan>();
    }
    let _ = assert_frontier_scan;
};

impl MorselFrontierScan {
    /// Expands + filters + groups + aggregates `anchors[lo..hi]` as one morsel on the **current** thread
    /// (`rmp` task #575): cheap-clones the source and drives
    /// [`MorselSource::frontier_expand_group_aggregate_morsel`]. Called inside the dedicated worker pool.
    fn frontier_morsel(
        &self,
        lo: usize,
        hi: usize,
        spec: &MorselFrontierExpandGroupSpec<'_>,
        params: &BoundParameters,
    ) -> MorselGroupOutcome {
        let slice = &self.anchors[lo..hi];
        self.source
            .clone_box()
            .frontier_expand_group_aggregate_morsel(
                slice,
                spec,
                params,
                self.txn,
                self.snapshot,
                &self.registry,
                self.deadline,
            )
    }
}

/// Runs `scan`'s frontier expand + residual-filter + grouped aggregation across contiguous anchor morsels
/// on the dedicated worker pool (`rmp` task #575, the `r3_fof3` reco class), then **merges** them via the
/// #360 [`converge_group_aggregate_outcomes`] **verbatim** — byte-identical to the serial
/// scan→expand→filter→aggregate over the same frontier, worker-count-independent (a
/// `count(DISTINCT <anchor>)` per group is the set-union of the morsels' partials, and the disjoint
/// anchor partition makes that union exact). `threads` is the effective worker count (`>= 2` when called).
pub fn run_frontier_expand_group_aggregate_morsels(
    scan: &MorselFrontierScan,
    spec: &MorselFrontierExpandGroupSpec<'_>,
    params: &BoundParameters,
    threads: usize,
) -> GroupAggConverged {
    use rayon::prelude::*;

    let bounds = frontier_morsel_bounds(scan.anchors.len(), threads);
    if bounds.is_empty() {
        return GroupAggConverged::default();
    }

    // Fan out on the DEDICATED pool (never the global rayon pool). `map` preserves input (ascending-lo)
    // order, so the outcomes are in ascending anchor order — the serial-frontier order the merge relies on
    // for the survivor prefix-sum and the order-sensitive `collect` / `DISTINCT` combine.
    let outcomes: Vec<MorselGroupOutcome> = install_morsel_fanout(|| {
        bounds
            .par_iter()
            .map(|&(lo, hi)| scan.frontier_morsel(lo, hi, spec, params))
            .collect()
    });

    converge_group_aggregate_outcomes(outcomes)
}

/// Merges the per-morsel grouped `outcomes` (in **ascending-`lo` order**) into one group stream in serial
/// first-seen order + the morsels' buffers (`rmp` task #360). Split out of
/// [`run_group_aggregate_morsels`] so the fan-out and the merge are testable independently (the
/// equivalence / determinism tests drive an explicit morsel split through this exact merge).
///
/// The merge keys a global table on the SAME SipHash digest + `row_values_equivalent` resolution the
/// morsels (and serial `aggregate_rows`) use, so grouping is identical. Morsels are folded in
/// ascending-`lo` order, maintaining a running survivor prefix; each local group's global first-seen rank
/// is `survivor_prefix + first_seen_local`, reduced by MIN across the (one) morsel that first created the
/// key. Accumulators combine via `Accumulator::combine` (the lower-`lo` partition is always `self`, so the
/// order-sensitive `collect` / `DISTINCT` combine appends in scan order). The merged groups are returned
/// sorted by global first-seen rank — the serial first-seen order.
///
/// On any morsel error the groups are returned empty (the caller discards them and the buffers, then runs
/// serial), with the first error surfaced.
pub fn converge_group_aggregate_outcomes(outcomes: Vec<MorselGroupOutcome>) -> GroupAggConverged {
    let mut buffers: Vec<SsiReadBuffer> = Vec::with_capacity(outcomes.len());
    let mut first_error: Option<GraphusError> = None;

    // The global merged group table: a SipHash digest of the key tuple → indices into `merged` whose key
    // hashes there (the same bucketed index serial / the morsels use; a collision falls back to the exact
    // `row_values_equivalent`). Each merged slot carries the key, the combined accumulators, and the
    // running MIN global first-seen rank.
    struct GlobalGroup {
        key: Vec<RowValue>,
        accs: Vec<crate::executor::Accumulator>,
        first_seen_global: u64,
    }
    let mut merged: Vec<GlobalGroup> = Vec::new();
    // `rmp` #371: the merge index is keyed on the same already-DoS-resistant `group_key_hash` `u64`
    // digest (the digest stays SipHash); buckets it with `FxHasher`.
    let mut index: rustc_hash::FxHashMap<u64, Vec<usize>> = rustc_hash::FxHashMap::default();
    // The running survivor prefix: the total survivor count of every morsel BEFORE the current one (in
    // ascending-`lo` order), so a local survivor rank maps into the global survivor-rank space.
    let mut survivor_prefix: u64 = 0;

    for o in outcomes {
        if first_error.is_none() && o.error.is_some() {
            first_error = o.error;
        }
        buffers.push(o.buffer);
        // Even on an error we keep draining buffers (above) but skip merging untrustworthy groups.
        if first_error.is_some() {
            continue;
        }
        for local in o.groups {
            let global_rank = survivor_prefix.saturating_add(local.first_seen_local);
            let key_hash = crate::executor::group_key_hash(&local.key);
            let bucket = index.entry(key_hash).or_default();
            let found = bucket.iter().copied().find(|&gi| {
                let g = &merged[gi];
                g.key.len() == local.key.len()
                    && g.key
                        .iter()
                        .zip(&local.key)
                        .all(|(x, y)| crate::runtime::row_values_equivalent(x, y))
            });
            match found {
                Some(gi) => {
                    // Combine this morsel's partial into the global group. `self` (the global group) was
                    // first created by a lower-or-equal-`lo` morsel, so combining `local` (this
                    // higher-`lo` morsel) as `other` appends its `collect` / `DISTINCT` elements AFTER —
                    // reproducing scan order. The MIN keeps the earliest creator's rank.
                    let g = &mut merged[gi];
                    if global_rank < g.first_seen_global {
                        g.first_seen_global = global_rank;
                    }
                    for (acc, other) in g.accs.iter_mut().zip(local.accs) {
                        acc.combine(other);
                    }
                    // Per-value memory budget on `collect` (`SEC-191`, CWE-770 / CWE-789): each morsel's
                    // local fold already capped its own partition, but merging partitions of the SAME group
                    // could push the union over [`MAX_VALUE_BYTES`] while no single morsel did. If so, the
                    // parallel result is over budget: surface a typed error so the engine thread DECLINES
                    // the parallel path and falls back to serial, which re-folds and raises the identical
                    // `ResourceLimit` (`collected list exceeds the N-byte value limit`) the serial path
                    // owns — never returning the oversized value to the client.
                    let limit = crate::value_size::max_value_bytes();
                    if first_error.is_none() && g.accs.iter().any(|a| a.collected_bytes() > limit) {
                        first_error = Some(eval_error_to_graphus(
                            &crate::eval::EvalError::ResourceLimit {
                                detail: format!(
                                    "collected list exceeds the {limit}-byte value limit"
                                ),
                            },
                        ));
                    }
                }
                None => {
                    let gi = merged.len();
                    merged.push(GlobalGroup {
                        key: local.key,
                        accs: local.accs,
                        first_seen_global: global_rank,
                    });
                    bucket.push(gi);
                }
            }
        }
        survivor_prefix = survivor_prefix.saturating_add(o.survivors);
    }

    if first_error.is_some() {
        return GroupAggConverged {
            groups: Vec::new(),
            buffers,
            error: first_error,
        };
    }

    // Emit groups in serial first-seen order: sort by the global first-seen rank ascending. Each rank is a
    // unique global survivor index (one row created the group), so the order is total — no ties, no
    // worker-scheduling dependence. This is the load-bearing determinism step (`rmp` task #360 AC).
    merged.sort_by_key(|g| g.first_seen_global);
    let groups = merged
        .into_iter()
        .map(|g| MergedGroup {
            key: g.key,
            accs: g.accs,
        })
        .collect();

    GroupAggConverged {
        groups,
        buffers,
        error: first_error,
    }
}

#[cfg(test)]
mod reader_pool_suppression_tests {
    //! `rmp` task #377: the reader-pool morsel suppression — `morsel_threads()` must clamp to `1` on a
    //! thread holding a [`ReaderPoolWorkerGuard`], and restore exactly on drop (incl. nesting/unwind),
    //! while the engine-thread path (no guard) keeps the configured count. Deterministic; no sleeps.

    use super::*;

    /// Serializes the few tests that mutate the process-global `MORSEL_THREADS`, so they cannot race on
    /// the shared atomic when the test harness runs them on different threads.
    static KNOB_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn guard_clamps_to_one_and_restores() {
        let _lock = KNOB_LOCK.lock().unwrap();
        let prev = MORSEL_THREADS.load(Ordering::Relaxed);
        set_morsel_threads(8);

        // Engine-thread path (no guard): full configured width.
        assert!(!is_reader_pool_worker());
        assert_eq!(morsel_threads(), 8);

        {
            let _g = ReaderPoolWorkerGuard::enter();
            assert!(is_reader_pool_worker());
            // Suppressed to serial-within-statement regardless of the configured width.
            assert_eq!(morsel_threads(), 1);
        }

        // Restored exactly on drop.
        assert!(!is_reader_pool_worker());
        assert_eq!(morsel_threads(), 8);

        MORSEL_THREADS.store(prev, Ordering::Relaxed);
    }

    #[test]
    fn guard_nesting_restores_prior_value() {
        let _lock = KNOB_LOCK.lock().unwrap();
        let prev = MORSEL_THREADS.load(Ordering::Relaxed);
        set_morsel_threads(4);

        assert!(!is_reader_pool_worker());
        let outer = ReaderPoolWorkerGuard::enter();
        assert!(is_reader_pool_worker());
        {
            let inner = ReaderPoolWorkerGuard::enter();
            assert!(is_reader_pool_worker());
            drop(inner);
            // Dropping the inner guard restores the *prior* value (still set by `outer`), not `false`.
            assert!(is_reader_pool_worker());
            assert_eq!(morsel_threads(), 1);
        }
        drop(outer);
        assert!(!is_reader_pool_worker());
        assert_eq!(morsel_threads(), 4);

        MORSEL_THREADS.store(prev, Ordering::Relaxed);
    }

    #[test]
    fn guard_clears_on_panic_unwind() {
        let _lock = KNOB_LOCK.lock().unwrap();
        let prev = MORSEL_THREADS.load(Ordering::Relaxed);
        set_morsel_threads(8);

        let r = std::panic::catch_unwind(|| {
            let _g = ReaderPoolWorkerGuard::enter();
            assert!(is_reader_pool_worker());
            panic!("boom");
        });
        assert!(r.is_err());
        // The guard's Drop ran during unwind, so the flag does not leak to the next task on this thread.
        assert!(!is_reader_pool_worker());

        MORSEL_THREADS.store(prev, Ordering::Relaxed);
    }

    /// `rmp` task #386: a panic inside the work `op` of the shared analytics pool — i.e. a panic on a
    /// `rayon` worker thread, exactly as a morsel per-row evaluation or a GDS algorithm would raise —
    /// is **re-raised by `rayon::ThreadPool::install` on the CALLING thread**, so a `catch_unwind` on
    /// the calling thread (the engine thread, in production) catches it. This is the proof that the
    /// engine's per-statement panic boundary (`run_statement_isolated` in `graphus-server`) subsumes
    /// the morsel/GDS rayon path: no separate morsel boundary is needed, because the rayon re-raise
    /// surfaces synchronously on the very thread the boundary wraps.
    #[test]
    fn analytics_pool_worker_panic_reraises_on_calling_thread() {
        let _lock = KNOB_LOCK.lock().unwrap();
        set_morsel_threads(4); // real workers, so `op` genuinely runs on a pool worker, not inline

        let caught = std::panic::catch_unwind(|| {
            // `op` runs on a rayon worker; `install` blocks the calling thread until it returns or
            // (here) re-raises the worker's panic on this thread.
            run_on_analytics_pool(|| {
                panic!("deliberate analytics-pool worker panic (rmp #386)");
            })
        });
        assert!(
            caught.is_err(),
            "a panic on a rayon analytics-pool worker must re-raise on the calling thread so the \
             engine's catch_unwind boundary catches it"
        );

        // The pool is still usable afterwards (a worker panic does not poison the shared pool): a
        // subsequent install computes normally on the same thread.
        let ok = run_on_analytics_pool(|| 21_i32 * 2);
        assert_eq!(
            ok, 42,
            "the analytics pool still serves work after a worker panic"
        );

        set_morsel_threads(1);
    }

    #[test]
    fn flag_is_thread_local_not_global() {
        let _lock = KNOB_LOCK.lock().unwrap();
        let _g = ReaderPoolWorkerGuard::enter();
        assert!(is_reader_pool_worker());
        // A freshly spawned thread does NOT inherit the flag (it is thread-local), so the engine thread
        // is never suppressed by a reader worker's guard.
        let observed = std::thread::spawn(is_reader_pool_worker).join().unwrap();
        assert!(!observed);
    }

    #[test]
    fn analytics_pool_width_is_bounded_and_independent_of_morsel_knob() {
        let _lock = KNOB_LOCK.lock().unwrap();
        let prev_morsel = MORSEL_THREADS.load(Ordering::Relaxed);
        let prev_analytics = ANALYTICS_POOL_THREADS.load(Ordering::Relaxed);

        // Pinning morsel to serial must NOT shrink the analytics pool GDS shares.
        set_morsel_threads(1);
        set_analytics_pool_threads(0); // computed default
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        assert_eq!(analytics_pool_threads(), cores.min(16));
        assert!(analytics_pool_threads() >= 1);

        // An explicit pin is honoured and bounded.
        set_analytics_pool_threads(3);
        assert_eq!(analytics_pool_threads(), 3);

        set_analytics_pool_threads(prev_analytics);
        MORSEL_THREADS.store(prev_morsel, Ordering::Relaxed);
    }

    /// `rmp` task #575-g.1: `enter_with_width` carries the dispatch-chosen adaptive width, and
    /// `morsel_threads()` reports it on the reader-pool worker (capped by the configured count), restoring
    /// exactly on drop.
    #[test]
    fn enter_with_width_reports_adaptive_width_capped_by_knob() {
        let _lock = KNOB_LOCK.lock().unwrap();
        let prev = MORSEL_THREADS.load(Ordering::Relaxed);
        set_morsel_threads(8);

        // A lone read gets the full pool width; the reader path reports it.
        {
            let _g = ReaderPoolWorkerGuard::enter_with_width(8);
            assert!(is_reader_pool_worker());
            assert_eq!(
                morsel_threads(),
                8,
                "reader worker reports its intended width"
            );
        }
        assert!(
            !is_reader_pool_worker(),
            "width restored to the not-a-worker sentinel on drop"
        );
        assert_eq!(morsel_threads(), 8);

        // An intended width above the configured knob is capped by the knob (never over-fans).
        {
            let _g = ReaderPoolWorkerGuard::enter_with_width(64);
            assert_eq!(
                morsel_threads(),
                8,
                "width is capped by the configured morsel-thread count"
            );
        }

        // Width 1 (K >= P collapse) reproduces the #377 v1 serial-per-read clamp.
        {
            let _g = ReaderPoolWorkerGuard::enter_with_width(1);
            assert!(is_reader_pool_worker());
            assert_eq!(morsel_threads(), 1);
        }

        // Width 0 is floored to 1 (a reader worker is always flagged).
        {
            let _g = ReaderPoolWorkerGuard::enter_with_width(0);
            assert!(is_reader_pool_worker());
            assert_eq!(morsel_threads(), 1);
        }

        MORSEL_THREADS.store(prev, Ordering::Relaxed);
    }

    /// `rmp` task #575-g.1: the dispatch-site width formula — a lone read gets the whole pool, `K`
    /// concurrent reads get `<= P/K` each (sum `<= P`, no over-subscription), width collapses to `1` at
    /// `K >= P` (exact #377 v1 clamp), and a disabled morsel knob keeps every reader read serial.
    #[test]
    fn reader_pool_morsel_width_bounds_the_concurrent_fanout_sum() {
        let _lock = KNOB_LOCK.lock().unwrap();
        let prev_morsel = MORSEL_THREADS.load(Ordering::Relaxed);
        let prev_analytics = ANALYTICS_POOL_THREADS.load(Ordering::Relaxed);

        set_morsel_threads(16);
        set_analytics_pool_threads(8); // fixed pool P = 8 for a deterministic assertion

        // Lone read (0 already in flight → this read is the 1st): full pool.
        assert_eq!(
            reader_pool_morsel_width(0),
            8,
            "a lone read fans across the whole analytics pool"
        );

        // K concurrent reads: each gets <= P/K, and the SUM never exceeds P (no over-subscription).
        for k in 1u64..=12 {
            // `k-1` already in flight when the k-th read dispatches.
            let width = reader_pool_morsel_width(k - 1);
            let expected = (8 / k).max(1) as usize;
            assert_eq!(width, expected, "width at k={k} inflight");
            // If all k reads dispatched at the same inflight snapshot, the worst-case sum is bounded by P
            // (+ the min-1 floor once k > P, where each read is serial on its own reader thread).
            assert!(
                width * (k as usize) <= 8 || width == 1,
                "sum bound at k={k}"
            );
        }

        // K >= P: width collapses to exactly 1 (the #377 v1 serial-per-read clamp).
        assert_eq!(reader_pool_morsel_width(8), 1);
        assert_eq!(reader_pool_morsel_width(50), 1);

        // Morsel globally disabled (determinism pin): every reader-pool read stays serial regardless.
        set_morsel_threads(1);
        assert_eq!(
            reader_pool_morsel_width(0),
            1,
            "disabled morsel keeps a lone reader read serial"
        );
        assert_eq!(reader_pool_morsel_width(3), 1);

        set_analytics_pool_threads(prev_analytics);
        MORSEL_THREADS.store(prev_morsel, Ordering::Relaxed);
    }
}
