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
//! runs on a **dedicated** pool (never the global `rayon` pool — GDS and the `rmp` #336 reader pool must
//! not contend) and is engaged only on the engine-thread inline path + the bench (off inside the #336
//! reader pool, to avoid pool-on-pool oversubscription).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use graphus_core::error::GraphusError;
use graphus_core::{TxnId, Value};
use graphus_storage::{StoreReadView, TokenSnapshot};
use graphus_txn::{CommitRegistry, PredicateRead, Snapshot, SsiReadBuffer};

use graphus_io::BlockDevice;
use graphus_wal::LogSink;

use crate::read_source::{self, ReadSink, ReadViewSource, VisCtx};

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

/// The effective morsel-thread count (`rmp` task #339): the value [`set_morsel_threads`] last stored,
/// or `1` (fully serial) when never set (the un-initialised `0` sentinel). Read at every `Ctx`
/// construction to populate `Ctx.morsel_threads`.
#[must_use]
pub fn morsel_threads() -> usize {
    match MORSEL_THREADS.load(Ordering::Relaxed) {
        0 => 1,
        n => n,
    }
}

/// The minimum estimated label cardinality at which the morsel tier is even attempted (`rmp` task
/// #339). Below this the dispatch + per-morsel setup cannot recover its fixed cost, so the serial
/// vectorized / Volcano tiers — whose setup is ~free — win. Tuned to the same crossover the `rmp` #352
/// tier uses (`PARALLEL_AGG_MIN_ROWS`); the morsel win is on the *large* analytical scans #339 targets.
pub const MORSEL_MIN_ROWS: f64 = 50_000.0;

/// The minimum contiguous morsel size (`rmp` task #339): a morsel never covers fewer than this many
/// candidate ids, so a small label never fans out into a swarm of tiny tasks whose scheduling cost
/// dwarfs their work. The adaptive morsel size is `max(MORSEL_MIN_CHUNK, n / (threads * 4))` — the `* 4`
/// over-subscribes so work-stealing balances a skewed candidate distribution.
pub const MORSEL_MIN_CHUNK: usize = 4096;

// =================================================================================================
// The dedicated worker pool
// =================================================================================================

/// The dedicated [`rayon::ThreadPool`] the morsel fan-out runs on (`rmp` task #339), built lazily on
/// first engagement and sized to [`morsel_threads`]. **Not** the global `rayon` pool: GDS uses the
/// global pool (`graphus-gds`) and the `rmp` #336 off-thread reader pool is a separate `std::thread`
/// pool — a dedicated pool here keeps the three from contending, and makes the morsel worker count an
/// explicit, bounded resource.
static MORSEL_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

/// The dedicated morsel pool, built (once) sized to the effective [`morsel_threads`]. The pool is
/// process-global and sized at first use; a later knob change does not resize it (the engine sets the
/// knob before the first query, so this is fixed for the process lifetime in production).
fn morsel_pool() -> &'static rayon::ThreadPool {
    MORSEL_POOL.get_or_init(|| {
        let threads = morsel_threads().max(1);
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("graphus-morsel-{i}"))
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

    let n = scan.candidates.len();
    if n == 0 {
        return Vec::new();
    }
    let chunk = (n / threads.saturating_mul(4).max(1))
        .max(MORSEL_MIN_CHUNK)
        .max(1);

    // The contiguous morsel boundaries, in ascending order: [0, chunk), [chunk, 2*chunk), …, [_, n).
    let bounds: Vec<(usize, usize)> = (0..n)
        .step_by(chunk)
        .map(|lo| (lo, (lo + chunk).min(n)))
        .collect();

    // Fan out on the DEDICATED pool (never the global rayon pool). `map` preserves input (ascending-lo)
    // order, so the returned outcomes are in ascending candidate order — the serial scan order.
    morsel_pool().install(|| {
        bounds
            .par_iter()
            .map(|&(lo, hi)| scan.read_morsel(lo, hi, property))
            .collect()
    })
}
