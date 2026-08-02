//! A concurrent, latched buffer pool ([`ConcurrentBufferPool`]) usable from many threads at
//! once, validated with `loom` (`specification/04-technical-design.md` §3.3–§3.6).
//!
//! This is the multi-threaded sibling of the single-threaded [`crate::BufferPool`]. It keeps
//! the exact same correctness contract — checksum verification on load, the write-ahead-log
//! ordering rule before any dirty write-back, CLOCK eviction that never evicts a pinned frame —
//! but lets independent threads fetch, pin, modify and unpin *different* pages without
//! contending, while still guaranteeing that a page is loaded from the device **at most once**
//! no matter how many threads race to fetch it.
//!
//! The single-threaded pool is left untouched and remains what `graphus-storage` and
//! `graphus-index` build on today; migrating them onto this pool is a separate, documented
//! follow-up.
//!
//! # Concurrency design
//!
//! ## Frame slots and latches (§3.3)
//!
//! The pool is a fixed array of frame slots. Each slot has:
//!
//! - a **reader/writer latch** (an `RwLock` from the internal `sync` seam) over its `FrameMeta`:
//!   the page id it currently holds, the page bytes, and the dirty flag. The latch protects the
//!   *physical* page; many readers may share it, a writer (a mutator or the evictor) holds it
//!   exclusively;
//! - an atomic **pin count**. A pinned frame is never chosen as an eviction victim;
//! - an atomic **reference bit** for the CLOCK sweep.
//!
//! ## Sharded frame table (§3.3)
//!
//! The `PageId -> frame index` map is split into [`ConcurrentBufferPool::shard_count`]
//! independent shards, each a `Mutex<HashMap<…>>`. Lookups for pages that hash to different
//! shards never contend. Each table entry is either `Ready(idx)` (a frame holds the page) or
//! `Loading(idx)` (a thread has *reserved* a victim frame and is currently reading the page into
//! it from the device). The `Loading` reservation is what guarantees **exactly one device load**
//! for a contended page: the first thread to miss installs the reservation under the shard lock;
//! every later thread sees the reservation and waits for it to become `Ready` rather than
//! starting its own device read.
//!
//! ## Device and WAL serialization
//!
//! [`BlockDevice`] splits its surface by mutability: `read_page` and `page_count` take `&self`,
//! while the mutating methods (`write_page`, `extend`, `sync_*`) take `&mut self`. The pool puts
//! the device behind a **`RwLock<D>`** (`rmp` #362) and matches the lock mode to the access:
//!
//! - a **read** guard for the read-only methods — crucially the cache-**miss** physical read in
//!   [`ConcurrentBufferPool::load_into`], so many threads that miss the pool at once read their
//!   *distinct* pages from the device **concurrently** instead of serialising on one lock (the
//!   structural cap that previously throttled off-thread reads (#336) and morsel parallelism (#339)
//!   to ~1× once the working set spilled the pool);
//! - a **write** guard for the mutating methods (`write_page` on write-back, `extend`+`page_count`
//!   on allocation, `sync_*` on flush), which still serialise — correctly, since they need `&mut D`.
//!
//! [`WalRule::ensure_durable`] takes `&mut self`, so the WAL stays behind its own `Mutex`. The
//! device `RwLock` does **not** change the lock *ordering* below: a device guard (read or write) is
//! still taken **innermost**, only while a frame write latch is held, never while a shard lock is
//! held — so concurrent device reads add no new wait edge.
//!
//! ## Durability barriers are issued outside the locks (`rmp` #974)
//!
//! Every `fdatasync` on the write-back path used to run inside the locks above, and that — not the
//! locks themselves — was the pool's dominant scalability limit once the working set exceeded the
//! pool. Measured on a 16-core host with a working set 2× the pool: the **exclusive** device guard
//! was occupied 87–92 % of wall time, 98 % of each hold was the barrier itself, and concurrent
//! cache-miss reads (which need that same lock in *shared* mode) queued 27 µs at one reader rising
//! to 323 µs at sixteen. Two changes remove the barriers from the locks:
//!
//! - **The WAL harden is hoisted out of the frame latch.** The chain used to be
//!   *frame latch → WAL mutex → `fdatasync`*, and because that mutex is shared with the store's
//!   commit path, one eviction's sync convoyed every other evictor **and** every concurrent commit.
//!   [`ConcurrentBufferPool::select_victim`] now **declines** a dirty victim whose `page_lsn` the log
//!   is not yet durable through ([`VictimChoice::NeedsWalHarden`]), releasing its latch so the
//!   caller can harden holding nothing and re-sweep. The batch flush paths do the same with the
//!   batch's maximum `page_lsn`, so they never hold N latches across a sync. The pool's *only*
//!   hardening entry point is [`ConcurrentBufferPool::harden_wal`], which asserts (debug builds,
//!   [`graphus_core::latch`]) that no frame latch is held, and the WAL's own `harden` asserts it
//!   again at the barrier itself.
//! - **The home-file barrier is issued off the device lock**, through the device's shared
//!   [`graphus_io::SyncHandle`] (a duplicated descriptor). The exclusive guard now covers the
//!   `pwrite` alone. This is a pure concurrency change: a barrier flushes the *file*, not a
//!   per-descriptor view, and it is issued only after the write it must cover has returned.
//!
//! Neither change relaxes WAL-before-data. The home-write path still refuses to write a page whose
//! redo record is not durable — it simply *verifies* that now
//! ([`ConcurrentBufferPool::assert_wal_covers`], fail-closed) instead of syncing to make it true
//! while holding a latch. Dedicated fsync threads (§3.6) remain a separate future option.
//!
//! ## Lock ordering — why this is deadlock-free
//!
//! There are three lock classes, always acquired in this strict order, and the pool never holds
//! two locks of the *same* class at once — so a wait cycle cannot form:
//!
//! 1. **shard lock** (a frame-table shard `Mutex`): only ever one held at a time, always
//!    released before any device or WAL lock;
//! 2. **frame latch** (per-frame `RwLock`): on the load path the victim latch is acquired during
//!    the CLOCK sweep with `try_write` *only* — a frame held by anyone else is skipped — so the
//!    reserving thread is always the exclusive holder and the acquisition can never block;
//! 3. **device / WAL lock**: innermost, taken only while holding a frame *write* latch, never
//!    while holding a shard lock. The device lock is a `RwLock<D>` (`rmp` #362): a **read** guard
//!    on the cache-miss `read_page` (so concurrent misses on distinct frames read in parallel) and
//!    a **write** guard on the `&mut`-mutators (`write_page`/`extend`/`sync_*`). The mode does not
//!    change the *class*: every device guard, read or write, is still innermost and short-lived, so
//!    making several reads concurrent introduces no new wait edge (a reader holds only a device
//!    *read* lock plus its own frame *write* latch, which no other thread is contending — the
//!    victim latch was won non-blocking by `try_write`).
//!
//! The only cross-class overlaps are:
//!
//! - **reserve:** hold the target page's shard lock and `try_write` the victim latch. Because it
//!   is `try_write` on a frame no one else holds, it never blocks, so this `shard → frame` edge
//!   can never be part of a wait cycle.
//! - **evict:** hold the victim's write latch and take the *old* page's shard lock to remove its
//!   mapping (`frame → shard`). This is the reverse direction, but it is safe: the shard lock is
//!   a leaf taken with a blocking `lock()`, and no code path holds a frame latch *and* a shard
//!   lock while another thread holds that shard lock *and* waits for that frame latch — the only
//!   `shard → frame` edge uses `try_write` (non-blocking), so it cannot wait.
//!
//! The `rmp` #974 hoist **removes** wait edges and adds none. Two edges that used to exist are gone:
//!
//! - the *frame latch → WAL mutex* edge on the eviction write-back. `select_victim` consults the
//!   WAL's durability **only through the lock-free `wal_durable` mirror** — it takes no WAL lock at
//!   all, not even a `try_lock`. That is not fastidiousness: `self.wal` guards the rule *object*,
//!   whereas the production rule keeps the real `WalManager` behind its own mutex, so a `try_lock`
//!   here would succeed on the wrapper and then block inside `durable_len`, potentially behind a
//!   commit's `fdatasync`, while this thread holds a frame latch and its caller holds a shard lock.
//!   The sweep therefore keeps its non-blocking, loom-finite contract, and every blocking WAL
//!   acquisition (`wal_covers_after_refresh`, `harden_wal`) happens on the hoist path, from a thread
//!   holding nothing — a wait on a leaf;
//! - the *frame latch → WAL mutex* edge in `guard_wal_before_data`, which read `tracks_lsn()`
//!   through the mutex — under **every** dirty frame's latch in the batch paths. That value is now
//!   cached at construction.
//!
//! The device edge is likewise weakened, never strengthened: the barrier that used to be issued
//! under the exclusive device guard is now issued through a handle that takes no device lock at all.
//!
//! Latches are short-lived and the spec forbids holding them across `.await`; this pool is fully
//! synchronous, so that rule is upheld by construction (there is no `.await` anywhere).

// FxHashMap: each shard is keyed by internal PageIds (never attacker-controlled), so the faster
// non-cryptographic hash is safe and cuts SipHash overhead on every sharded lookup.
use rustc_hash::FxHashMap as HashMap;

use graphus_core::error::{GraphusError, Result};
use graphus_core::{Lsn, PageId};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};

use crate::page;
use crate::pool::{NoWal, WalRule};
use crate::sync::{
    Arc, AtomicU64, AtomicUsize, Backoff, Mutex, MutexGuard, Ordering, RwLock, RwLockReadGuard,
    RwLockWriteGuard,
};

/// Number of frame-table shards. Always a power of two, because a page maps to its shard by
/// `hash % SHARD_COUNT` and a power-of-two modulus is the cheap masked form the optimiser lowers to.
///
/// The value is **cfg-split on `loom`** because the two builds optimise for opposite things:
///
/// - **Under `--cfg loom`** (model checking) the count is kept at the minimum that still exercises
///   the *sharded* lookup path, `4`. loom explores an exponential interleaving space, and every
///   extra independent lock multiplies the state to search; a small shard count keeps the model
///   tractable (the loom models deliberately use 1–3 pages / 2 threads for the same reason). The
///   shard count does **not** affect any correctness property loom proves — those turn on the
///   shard-lock / frame-latch / device-lock *ordering*, which is identical regardless of how many
///   shards exist — so shrinking it for the model loses no coverage of the invariants.
///
/// - **Under `#[cfg(not(loom))]`** (production) the count is `64`. The frame-table shards are the
///   pool's contention point on the lookup path: every `fetch`/`with_page_fetched`/`new_page` takes
///   exactly one shard `Mutex` to read or mutate the `PageId -> frame` mapping, and two pages that
///   hash to the *same* shard serialise there even though they touch different frames. With the
///   per-shard work now tiny (the device read itself moved out from under any shard lock and the
///   device lock is a `RwLock` that lets concurrent cache-miss reads proceed in parallel — `rmp`
///   #362), the shard `Mutex` is what remains to serialise concurrent lookups, so it must offer at
///   least one independent lock per worker for a many-core host. `64` gives a 16-thread host ≥ 4
///   shards per thread (low same-shard collision probability by the birthday bound) with ample
///   headroom for the 16-/32-/64-core targets, while staying a power of two. Cache-line padding of
///   the shards (§10) remains a separate measurement-gated follow-up.
#[cfg(loom)]
const SHARD_COUNT: usize = 4;
#[cfg(not(loom))]
const SHARD_COUNT: usize = 64;

/// Bound on `fetch`/`new_page` victim-acquisition retries before giving up. A retry happens only on a
/// **transient** condition — a lost hit-race, a peer already `Loading` the same page, or an empty
/// victim sweep ([`VictimChoice::Contended`] *or* a **transient** [`VictimChoice::AllPinned`]
/// snapshot, both of which clear under a correct workload — see the miss-arm of
/// [`ConcurrentBufferPool::fetch`] for why even "every frame pinned right now" clears microseconds
/// later, a property `loom_fetch_under_contention_never_spuriously_fails` proves). A **sustained**
/// `AllPinned` run (a real caller pin-leak / a genuinely full pool) is caught far sooner by the
/// separate, shorter [`PERSISTENT_ALL_PINNED_SWEEPS`] bound (`rmp` #594 D-#4); this 1 M cap remains the
/// backstop for the transient `Contended` live-lock, which still retries the *full* budget so the
/// `rmp` #359 read-integrity fix is untouched. Each retry first backs off (see [`Backoff`]): the loop
/// spreads
/// heavily-contended threads out in *time* so the in-flight loader/holder herd drains and a victim
/// becomes takeable, instead of re-contending the same latches in lockstep (the positive-feedback
/// live-lock the measured `rmp` #359 spurious-fetch-error came from — a *tight* retry made the
/// `morsel_expand` flake worse, not better).
///
/// With backoff the convergence is fast (a clean run drains in a few thousand spins — `max_retry_iters`
/// measured ~3.5k under a 16-reader/24-frame chain storm), so this is a deliberately **generous**
/// live-lock backstop, NOT a steady-state count: it turns a genuinely wedged pool — one truly exhausted
/// by *long-lived* pins (a caller pin-leak bug), which no amount of retrying can resolve — into a clear
/// error rather than a hang. Sized at 1 M (≈ 300× the measured clean-run worst case) so a heavily
/// loaded host whose scheduler starves the backoff still converges rather than surfacing a spurious
/// "could not reserve a victim" under extreme thrash (measurement: a 100 k budget passed 10/10 even
/// loaded; 1 M is comfortable headroom). The magnitude is irrelevant to loom (it resolves each retry
/// the instant a peer releases its latch, in a handful of model yields, never approaching the cap).
const MAX_FETCH_RETRIES: usize = 1_000_000;

/// Consecutive [`VictimChoice::AllPinned`] sweeps — with **no** interleaved progress — after which
/// `fetch`/`new_page` stop retrying and surface the clear "pool full of pinned pages" error, well
/// before the full [`MAX_FETCH_RETRIES`] live-lock budget (`rmp` #594 D-#4).
///
/// ## Why a *separate*, shorter bound for `AllPinned` — and why it cannot regress `rmp` #359
///
/// [`ConcurrentBufferPool::select_victim`] distinguishes two empty-sweep reasons ([`VictimChoice`]).
/// [`VictimChoice::Contended`] (an unpinned frame exists but was momentarily latch-contended) is the
/// **transient** #359 case and MUST keep retrying the *full* `MAX_FETCH_RETRIES` budget — erroring on
/// it is the exact read-integrity regression (#359/#339, a spurious `Err` swallowed into `Value::Null`)
/// this must never reintroduce. This shorter bound is applied ONLY to the *other* outcome,
/// [`VictimChoice::AllPinned`] (literally **every** frame pinned this sweep), and ONLY when it is
/// **sustained**: the caller resets the counter to zero on ANY interleaved progress — a hit, a peer
/// `Loading`, a lost-pin-race `Ready`, OR a `Contended` sweep (an unpinned frame is/was present). So
/// the error trips only after this many sweeps *in a row* all saw the pool wholly pinned with not one
/// evictable frame appearing between them — the signature of a genuine caller **pin leak** or true
/// capacity exhaustion (e.g. a fully-pinned pool), which no further retry can resolve.
///
/// Under a correct concurrent-reader workload `AllPinned` is observed **zero** times (the misses are
/// 100% `Contended`; `eviction_chain_repro.rs` asserts `all_pinned == 0` whenever readers < frames),
/// and a genuine *transient* all-pinned snapshot (the lone free frame pinned by a peer loader in the
/// instant between its load-publish and the caller's unpin) clears in microseconds — the very next
/// sweep sees an unpinned frame and resets the counter. So a sustained run of `100_000` PURE
/// (progress-free) `AllPinned` sweeps cannot arise transiently; it is unreachable except under a real
/// leak / capacity wall. The value is deliberately generous — 100 k is ≈ 30× the measured clean-run
/// worst case (~3.5 k) yet 10× shorter than the 1 M live-lock backstop — so even a scheduler-starved
/// host never trips it spuriously, while still turning a genuinely wedged pool into a clear error ~10×
/// sooner. Irrelevant to loom (which resolves each retry in a handful of model yields, never
/// approaching either bound).
const PERSISTENT_ALL_PINNED_SWEEPS: usize = 100_000;

/// Bound on the **WAL hoist-and-retry** rounds a home-write path will take before giving up
/// (`rmp` #974).
///
/// A round is: discover under the frame latch that the log is not durable through a dirty page's
/// `page_lsn`, release the latch, harden with nothing held, re-take the latch. One harden makes the
/// *entire* appended log durable, so every page dirtied before it is covered — a second round is
/// therefore only ever needed when a concurrent writer stamped a fresh LSN in the instant between
/// the harden and the re-sweep.
///
/// The bound caps how many hardens **one call** will pay for. What happens past it differs by path,
/// and the difference is deliberate:
///
/// * `fetch` / `new_page` stop hardening and fall back to the ordinary backed-off retry, so
///   [`MAX_FETCH_RETRIES`] remains the single backstop. They must never surface an error here: a
///   spurious `Err` out of `fetch` is swallowed by the read-view chain into a `Value::Null` — a
///   *wrong answer* rather than a visible failure, the `rmp` #359/#339 read-integrity class;
/// * the flush paths return a clean error, which their callers handle correctly — the checkpoint
///   propagates it before advancing any floor, and the pages stay dirty and resident, so nothing is
///   lost and a later flush captures them.
///
/// Neither path ever falls back to the one thing that must not happen: an `fdatasync` issued inside
/// a latched region.
const WAL_HOIST_ATTEMPTS: usize = 1024;

/// The reservation state of a page, as recorded in a frame-table shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// A frame holds this page and may be pinned.
    Ready(usize),
    /// A thread reserved frame `idx` and is loading this page into it from the device.
    Loading(usize),
}

/// The latched contents of one frame: the page it holds, its bytes, and whether it is dirty.
struct FrameMeta {
    page_id: Option<PageId>,
    data: Box<Page>,
    dirty: bool,
}

impl FrameMeta {
    fn empty() -> Self {
        Self {
            page_id: None,
            data: Box::new([0u8; PAGE_SIZE]),
            dirty: false,
        }
    }
}

/// One frame: a reader/writer-latched page plus its atomic pin count and CLOCK reference bit.
struct FrameSlot {
    /// The reader/writer **latch** protecting the physical page (`specification` §3.3).
    meta: RwLock<FrameMeta>,
    /// Atomic pin count; a frame with `pin_count > 0` is never evicted.
    pin_count: AtomicUsize,
    /// CLOCK reference bit (0 or 1).
    ref_bit: AtomicUsize,
}

impl FrameSlot {
    fn empty() -> Self {
        Self {
            meta: RwLock::new(FrameMeta::empty()),
            pin_count: AtomicUsize::new(0),
            ref_bit: AtomicUsize::new(0),
        }
    }
}

/// Stages a single dirty data-page image into a **doublewrite area** and makes it durable, so the
/// image survives a torn home write (`05 §3`, `04 §4.5`).
///
/// The buffer pool calls [`stage_and_sync`](PageStager::stage_and_sync) **before** it writes any
/// dirty data page to its home location on the *eviction/steal* path ([`write_back`]). This closes
/// the last doublewrite hole (`rmp` #407): without it, the evictor wrote dirty home pages directly,
/// so a power loss mid-eviction-write could leave a torn page whose garbage `page_lsn` makes ARIES
/// redo skip its repair — latent corruption. With it, every dirty data page (checkpoint-flushed
/// **and** evicted) has an intact doublewrite copy at every crash point.
///
/// The implementation lives in `graphus-storage` over the **same persistent doublewrite buffer**
/// the checkpoint path uses ([`graphus_storage::RecordStore`]); it serialises concurrent evictions
/// behind its own interior lock, so this trait stays `&self`. It is `Send + Sync` because the
/// concurrent pool is shared across threads behind an [`Arc`].
///
/// # Errors
/// Returns a storage error if the doublewrite write or its sync fails. The pool **never** proceeds
/// to the home write after a staging error: it propagates, so a home page is never written without a
/// durable doublewrite copy (the InnoDB ordering, `05 §3`).
pub trait PageStager: Send + Sync {
    /// Stages `image` (the exact bytes about to be written to home page `page_id`, checksum already
    /// stamped) into the doublewrite area, fsyncs it, then runs `home_write` to write the page home
    /// **and make that home write durable** — all while the doublewrite area's slot for this page is
    /// still reserved. Used by the **eviction/steal** path, which writes one page home at a time under
    /// its frame latch.
    ///
    /// ## Why the home write is a callback (`rmp` #411)
    ///
    /// The doublewrite area protected by this stager holds exactly **one** batch region. If staging
    /// merely fsynced the copy and *returned* — letting the caller do the home write afterwards,
    /// unserialised — two concurrent evictors would race: evictor T1 stages page A (region = {A}),
    /// evictor T2 stages page B (region **overwritten** = {B}), then T1's home write of A tears on a
    /// crash. Recovery reads the single region, sees only {B}, and A's torn home page is
    /// **unrecoverable** — the corruption the doublewrite buffer exists to prevent (`rmp` #411,
    /// reopening the `rmp` #407 hole under concurrency). The InnoDB invariant (`05 §3`) is: a
    /// doublewrite slot must NOT be reused until the prior occupant's home write is **durably
    /// complete**. By running the home write *inside* the staging critical section (the implementation
    /// holds its interior lock across `home_write`), the slot's occupant is guaranteed durable on the
    /// home device before the next evictor can reuse the region. `home_write` MUST make its home write
    /// durable (write the page **and** sync the home device) before it returns.
    ///
    /// # Errors
    /// Returns a storage error if the doublewrite write/sync fails (then `home_write` is **not** run —
    /// no home page is written without a durable doublewrite copy), or propagates an error from
    /// `home_write` itself (a home write/sync failure surfaces, never hidden).
    fn stage_and_sync(
        &self,
        page_id: PageId,
        image: &[u8],
        home_write: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()>;

    /// Stages a whole **batch** of `(page_id, image)` pairs into the doublewrite area as ONE durable
    /// batch (a single fsync), so every page in the batch has an intact doublewrite copy before any
    /// of the batch's pages are written home. Used by the **checkpoint/flush** path
    /// ([`ConcurrentBufferPool::flush_pages`]/[`flush_all`](ConcurrentBufferPool::flush_all)): it must
    /// stage the entire batch up front because the doublewrite area holds exactly one batch at a time,
    /// so staging pages one-by-one would leave all but the last unprotected when the home writes run.
    ///
    /// The caller guarantees `batch.len()` does not exceed the doublewrite area's batch capacity.
    ///
    /// # Errors
    /// Returns a storage error if the doublewrite write or its sync fails; the caller must not write
    /// any of the batch's pages home after an error.
    fn stage_batch_and_sync(&self, batch: &[(PageId, &[u8])]) -> Result<()>;
}

/// A handle to a pinned frame, valid until it is unpinned. Kept distinct from the
/// single-threaded [`crate::FrameId`] so the two pools' handles cannot be confused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedFrame(usize);

impl PinnedFrame {
    /// The underlying frame index (useful for tests and diagnostics).
    #[must_use]
    pub fn index(self) -> usize {
        self.0
    }
}

/// A concurrent, latched buffer pool over a [`BlockDevice`] and a [`WalRule`].
///
/// Share it across threads by wrapping it in an `Arc` via [`ConcurrentBufferPool::shared`]
/// (under `--cfg loom` this is `loom`'s `Arc`). Every public method takes `&self`.
///
/// # Examples
///
/// ```
/// use graphus_bufpool::ConcurrentBufferPool;
/// use graphus_io::MemBlockDevice;
///
/// let pool = ConcurrentBufferPool::new(MemBlockDevice::new(0), 4);
/// let (frame, id) = pool.new_page().unwrap();
/// pool.with_page_mut(frame, |p| p[100] = 0xAA);
/// pool.unpin(frame);
///
/// let g = pool.fetch(id).unwrap();
/// assert_eq!(pool.with_page(g, |p| p[100]), 0xAA);
/// pool.unpin(g);
/// ```
pub struct ConcurrentBufferPool<D: BlockDevice, W: WalRule = NoWal> {
    /// The block device, behind a `RwLock<D>` (`rmp` #362). Read-only device access (`read_page`
    /// on a cache miss, `page_count`) takes a **read** guard so concurrent misses on distinct
    /// frames read from the device in parallel; mutating access (`write_page`/`extend`/`sync_*`,
    /// all `&mut D`) takes a **write** guard and therefore still serialises. Always taken
    /// innermost (only under a frame write latch, never under a shard lock), so the device-read
    /// concurrency adds no new lock-ordering edge.
    device: RwLock<D>,
    /// Serializes WAL-rule checks (`ensure_durable`).
    wal: Mutex<W>,
    /// Whether the WAL rule tracks real LSNs, cached once at construction (`rmp` #974).
    ///
    /// [`WalRule::tracks_lsn`] is a *static* property of the rule, but reading it went through the
    /// `wal` mutex — an acquisition on the write-back path, taken while holding a frame latch (and,
    /// in the batch flush paths, while holding **every** dirty frame's latch). Caching it removes
    /// that lock from the latched region entirely.
    wal_tracks_lsn: bool,
    /// The WAL's **durable frontier**, cached lock-free (`rmp` #974).
    ///
    /// A monotonically increasing (`fetch_max`) mirror of [`WalRule::durable_len`], refreshed
    /// whenever this pool holds the WAL mutex anyway. It is the pool's cheap answer to *"is this
    /// page's `page_lsn` already covered by durable log?"*, which is what lets the eviction path
    /// decide — **before** it commits to a victim — whether a harden is needed, and hoist that
    /// harden out from under the frame latch when it is.
    ///
    /// # Staleness is safe in exactly one direction
    ///
    /// The store hardens the same log directly on its commit path, without going through this pool,
    /// so this value can lag the true frontier. That is **stale-low**: the pool then believes a page
    /// is uncovered when it is really durable, hoists, and calls `ensure_durable`, which no-ops. The
    /// cost is a wasted victim sweep; the durability decision is unaffected. It can never be
    /// stale-**high** — every value published here was read from the rule under the WAL mutex, and a
    /// log's durable length never decreases while the log is open — so the pool can never conclude a
    /// page is covered when it is not, which is the only direction that would break WAL-before-data.
    wal_durable: AtomicU64,
    /// The device's **shared** durability handle (`rmp` #974), obtained once at construction.
    ///
    /// When present, the home-write barrier is issued through this handle with **no device guard
    /// held at all**, instead of under the exclusive write guard that every concurrent cache-miss
    /// read needs in shared mode. `None` for a device that cannot offer one (the in-memory DST
    /// device, the encrypted device whose sync also persists a counter), in which case the
    /// historical guarded path is used unchanged.
    sync_handle: Option<std::sync::Arc<dyn graphus_io::SyncHandle>>,
    frames: Vec<FrameSlot>,
    table: Vec<Mutex<HashMap<PageId, Slot>>>,
    clock: AtomicUsize,
    /// The optional **doublewrite stager** that protects the *eviction/steal* home-write path
    /// (`rmp` #407, `05 §3`). Installed once at store open via [`set_page_stager`](Self::set_page_stager)
    /// and never replaced thereafter, so a plain cloned [`Arc`] — read under no lock — suffices; the
    /// stager's own interior lock serialises concurrent evictions' staging. When present, [`write_back`]
    /// stages-and-syncs each dirty *logged* data page into the doublewrite area before writing it home,
    /// so a torn eviction write is repairable on the next open
    /// ([`crate::page`]; `graphus_storage::recovery::recover_device_with_dwb`). `None` for a pool with
    /// no doublewrite protection (e.g. a transient scratch store, or before the stager is attached).
    dwb_stager: Mutex<Option<Arc<dyn PageStager>>>,
    /// Eviction-diagnostics counters (`rmp` #359, `bufpool-probe` feature only). Compiled out of the
    /// production build (zero cost: the field does not exist).
    #[cfg(feature = "bufpool-probe")]
    probe: probe::Probe,
}

impl<D: BlockDevice> ConcurrentBufferPool<D, NoWal> {
    /// Creates a pool of `capacity` frames over `device`, with no WAL coupling.
    ///
    /// # Panics
    /// Panics if `capacity` is zero.
    pub fn new(device: D, capacity: usize) -> Self {
        Self::with_wal(device, NoWal, capacity)
    }
}

impl<D: BlockDevice, W: WalRule> ConcurrentBufferPool<D, W> {
    /// Creates a pool of `capacity` frames with an explicit [`WalRule`].
    ///
    /// # Panics
    /// Panics if `capacity` is zero.
    pub fn with_wal(device: D, mut wal: W, capacity: usize) -> Self {
        assert!(capacity > 0, "buffer pool capacity must be > 0");
        let frames = (0..capacity).map(|_| FrameSlot::empty()).collect();
        let table = (0..SHARD_COUNT)
            .map(|_| Mutex::new(HashMap::default()))
            .collect();
        // Cache the rule's static properties and seed the durable-frontier mirror once, here, where
        // no latch is held and nothing is racing (`rmp` #974).
        let wal_tracks_lsn = wal.tracks_lsn();
        let wal_durable = AtomicU64::new(wal.durable_len());
        // Take the device's shared durability handle once; it is reused for the pool's lifetime, so
        // duplicating a descriptor never lands on a hot path.
        let sync_handle = device.sync_handle();
        Self {
            device: RwLock::new(device),
            wal: Mutex::new(wal),
            wal_tracks_lsn,
            wal_durable,
            sync_handle,
            frames,
            table,
            clock: AtomicUsize::new(0),
            dwb_stager: Mutex::new(None),
            #[cfg(feature = "bufpool-probe")]
            probe: probe::Probe::default(),
        }
    }

    /// Installs the **doublewrite stager** that protects the eviction/steal home-write path
    /// (`rmp` #407, `05 §3`). Call this once at store open, right where the persistent doublewrite
    /// buffer is attached, **before serving any traffic**: from then on every dirty *logged* data
    /// page the pool writes home — on a checkpoint/flush *or* on an eviction/steal — is first
    /// staged-and-synced into the doublewrite area, so a torn home write is repairable on the next
    /// open.
    ///
    /// Takes `&self` (the pool is already shared behind an [`Arc`] by open time) and stores the
    /// stager behind a short-lived `Mutex` whose guard is **never** held across a device write: the
    /// home-write path clones the [`Arc`] out under the guard and drops the guard before staging, so
    /// the stager's own interior lock (not this one) is what serialises concurrent evictions.
    /// Idempotent-by-contract: a second install replaces the stager (used by tests); production
    /// installs exactly once.
    pub fn set_page_stager(&self, stager: Arc<dyn PageStager>) {
        *unwrap_lock(self.dwb_stager.lock()) = Some(stager);
    }

    /// Clones out the currently-installed doublewrite stager (if any), holding the `dwb_stager`
    /// guard only for the clone — never across a device write. Returns `None` when no stager is
    /// installed (an unprotected pool), so the caller skips staging.
    fn page_stager(&self) -> Option<Arc<dyn PageStager>> {
        unwrap_lock(self.dwb_stager.lock()).clone()
    }

    /// Wraps the pool in an `Arc` (the `sync` seam's, i.e. `loom`'s under `--cfg loom`) for
    /// sharing across threads.
    #[must_use]
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// The number of frame-table shards (constant; exposed for tests and diagnostics).
    #[must_use]
    pub fn shard_count(&self) -> usize {
        SHARD_COUNT
    }

    /// The number of frames in the pool.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.frames.len()
    }

    /// The number of pages on the underlying device (its current size in pages). Mirrors the
    /// single-threaded [`BufferPool::page_count`](crate::BufferPool::page_count): used by crash
    /// recovery to scan every device page (`rmp` #239) without exposing the device itself. Takes a
    /// device **read** guard (`page_count` is `&self`), so it does not block concurrent cache-miss
    /// reads.
    #[must_use]
    pub fn page_count(&self) -> u64 {
        self.read_device().page_count()
    }

    /// Reads page `pid`'s raw bytes straight from the backing device, **WITHOUT** verifying its
    /// checksum and **WITHOUT** inserting it into the pool. Takes only a device **read** guard.
    ///
    /// Used by store-open orphan-page reconstruction (`rmp` #597) to *classify* a page that [`fetch`]
    /// would reject before it could be classified. A transient device write error on a freshly
    /// page-boundary-extended record page's seed flush can leave an extended-but-never-initialised
    /// **all-zero, checksum-invalid** page on the device (an aborted allocation holding no committed
    /// data, with no WAL record and no doublewrite copy — the seed flush uses the unlogged path).
    /// [`fetch`] fails that page's checksum and bricks `open`; a raw read lets the caller tell that
    /// harmless phantom (all-zero ⇒ skip) apart from untrusted corruption (non-zero bad checksum ⇒
    /// still fail closed, never served). Correct for the cold-open reconstruction scan: the pool holds
    /// no resident copy of an unmapped orphan page there, so the device image is authoritative.
    ///
    /// # Errors
    /// Propagates a device read failure.
    pub fn read_page_unverified(&self, pid: PageId) -> Result<Box<Page>> {
        let mut buf: Box<Page> = Box::new([0u8; PAGE_SIZE]);
        self.read_device().read_page(pid, &mut buf)?;
        Ok(buf)
    }

    /// Resolves a frame handle to its slot with an explicit bounds check (CWE-129 defence in
    /// depth). [`PinnedFrame`] handles are minted only by this pool, so `f.0` is in-bounds by
    /// construction today; this checked accessor makes that invariant load-bearing in code rather
    /// than implicit, so a future refactor that derived a frame index from an attacker-controlled
    /// `page_id` or a persisted slot could never turn `self.frames[f.0]` into an out-of-bounds
    /// access. The hot path keeps a `debug_assert` (zero release-mode cost) and a `.get(...)` whose
    /// `None` arm is unreachable for a pool-minted handle.
    #[inline]
    fn slot(&self, f: PinnedFrame) -> &FrameSlot {
        debug_assert!(
            f.0 < self.frames.len(),
            "frame handle {} out of bounds (capacity {}): handles must be pool-minted",
            f.0,
            self.frames.len()
        );
        self.frames.get(f.0).unwrap_or_else(|| {
            panic!(
                "frame handle {} out of bounds (capacity {})",
                f.0,
                self.frames.len()
            )
        })
    }

    /// The checked counterpart of [`slot`](Self::slot) that returns a clean error instead of
    /// panicking on an out-of-range handle, for callers that may hold an untrusted handle.
    #[inline]
    fn try_slot(&self, f: PinnedFrame) -> Result<&FrameSlot> {
        self.frames.get(f.0).ok_or_else(|| {
            GraphusError::Storage(format!(
                "frame handle {} out of bounds (capacity {})",
                f.0,
                self.frames.len()
            ))
        })
    }

    fn shard_of(&self, page_id: PageId) -> &Mutex<HashMap<PageId, Slot>> {
        // A cheap, deterministic spread; the exact hash is not load-bearing for correctness.
        let h = page_id.0.wrapping_mul(0x9E37_79B9_7F4A_7C15) as usize;
        &self.table[h % SHARD_COUNT]
    }

    fn lock_shard(&self, page_id: PageId) -> MutexGuard<'_, HashMap<PageId, Slot>> {
        unwrap_lock(self.shard_of(page_id).lock())
    }

    /// Acquires a **shared read** guard on the device for the `&self` methods (`read_page`,
    /// `page_count`). Many threads may hold this at once, so concurrent cache-miss reads on
    /// distinct frames proceed in parallel (`rmp` #362). Recovers a poisoned lock (see
    /// [`unwrap_lock`]): the device bytes are checksummed and the WAL provides recovery, so a prior
    /// panic must not permanently wedge the pool.
    fn read_device(&self) -> RwLockReadGuard<'_, D> {
        unwrap_lock(self.device.read())
    }

    /// Acquires an **exclusive write** guard on the device for the `&mut`-mutators (`write_page`,
    /// `extend`, `sync_*`). These serialise — correctly, since they need `&mut D`. Recovers a
    /// poisoned lock for the same reason as [`read_device`](Self::read_device).
    fn write_device(&self) -> RwLockWriteGuard<'_, D> {
        unwrap_lock(self.device.write())
    }

    /// Runs `func` with mutable access to the underlying block device, for **Deterministic
    /// Simulation Testing only** (`04 §11`): a DST harness uses it to arm a [`graphus_io::FaultPlan`]
    /// (or a one-shot I/O error / torn write) on the *live* device of a running pool, so a fault can
    /// be injected mid-workload rather than only on a device the harness owns before construction.
    ///
    /// This is the concurrent-pool counterpart of the single-threaded
    /// [`BufferPool::device_mut`](crate::BufferPool::device_mut). The device lives behind the pool's
    /// `RwLock<D>`, so mutable access takes the **write** guard (exclusive) for the closure's
    /// duration (a `&mut D` cannot be handed out from `&self`); the harness arms the fault inside
    /// `func`.
    ///
    /// Gated behind the `dst` cargo feature so the production build never compiles this seam — the
    /// device stays fully encapsulated on the production path (zero-cost: the method does not exist).
    #[cfg(feature = "dst")]
    pub fn with_device_mut<R>(&self, func: impl FnOnce(&mut D) -> R) -> R {
        func(&mut self.write_device())
    }

    /// Borrows the cached page held by a pinned frame and applies `func` to it.
    ///
    /// Takes the frame's **read latch** for the duration of `func`; many threads may read
    /// distinct frames concurrently. `func` must not block or call back into the pool with this
    /// frame.
    pub fn with_page<R>(&self, f: PinnedFrame, func: impl FnOnce(&Page) -> R) -> R {
        let meta = unwrap_lock(self.slot(f).meta.read());
        func(&meta.data)
    }

    /// The fallible counterpart of [`with_page`](Self::with_page): returns a clean storage error
    /// for an out-of-range frame handle instead of panicking (CWE-129). Use this on any path where
    /// the handle is not provably pool-minted.
    ///
    /// # Errors
    /// Returns a storage error if `f` is out of bounds for this pool.
    pub fn try_with_page<R>(&self, f: PinnedFrame, func: impl FnOnce(&Page) -> R) -> Result<R> {
        let slot = self.try_slot(f)?;
        let meta = unwrap_lock(slot.meta.read());
        Ok(func(&meta.data))
    }

    /// Fetches `page_id` and applies `func` to its cached bytes under a **single** read latch, then
    /// unpins — the combined, fast counterpart of `fetch` → [`with_page`](Self::with_page) → `unpin`
    /// for the overwhelmingly common case of reading a **resident** page.
    ///
    /// # Why this exists (perf, `rmp` #337 Slice 1)
    ///
    /// The separate three-call form takes the frame read latch **twice** on a hit: once inside
    /// [`fetch`](Self::fetch) to re-validate the frame's identity against an evictor, and again in
    /// [`with_page`](Self::with_page) to read. On a hot read scan (e.g. a `MATCH (n)` node-store
    /// sweep) that doubled latch traffic is a measurable single-thread tax over the single-threaded
    /// [`BufferPool`](crate::BufferPool) it replaced. This method folds the re-validation and the read
    /// into **one** latch acquisition on the hit path, recovering most of that tax while preserving
    /// the exact pin → re-validate-under-latch → eviction-race discipline `fetch` uses. The cold paths
    /// (miss / concurrent load in progress / lost the pin race) fall back to the full `fetch` so the
    /// load-once and publish-before-pin guarantees are unchanged.
    ///
    /// `func` must not block or call back into the pool with this page (it runs under the read latch).
    ///
    /// # Errors
    /// Returns an error if the page must be loaded and the device read fails, the loaded page fails
    /// its checksum, the pool is full of pinned frames, or a contended load fails to resolve within
    /// the internal retry bound.
    pub fn with_page_fetched<R>(
        &self,
        page_id: PageId,
        func: impl FnOnce(&Page) -> R,
    ) -> Result<R> {
        // Hit fast path: pin under the shard lock, then take the read latch ONCE to both re-validate
        // identity (the same evictor race `fetch` guards) and run `func`.
        {
            let shard = self.lock_shard(page_id);
            if let Some(Slot::Ready(idx)) = shard.get(&page_id).copied() {
                self.frames[idx].pin_count.fetch_add(1, Ordering::Acquire);
                self.frames[idx].ref_bit.store(1, Ordering::Relaxed);
                drop(shard);
                // Own the pin in an RAII guard BEFORE taking the read latch, so a panic in `func`
                // (or the lost-race fall-through below) still runs the matching `unpin` on unwind
                // (`rmp` #594) instead of stranding the frame permanently unevictable. `guard` is
                // declared before `meta`, and Rust drops locals in reverse declaration order, so on
                // every scope exit — normal return OR unwinding — the later-declared `meta` (the read
                // latch) drops FIRST and `guard` (the `unpin`) SECOND: the pre-existing
                // latch-before-unpin discipline (`rmp` #337 Slice 1) is preserved with no second latch
                // acquisition and no extra per-hit cost.
                let guard = self.pin_guard(PinnedFrame(idx));
                let meta = unwrap_lock(self.frames[idx].meta.read());
                if meta.page_id == Some(page_id) {
                    let r = func(&meta.data);
                    drop(meta); // release the read latch first...
                    drop(guard); // ...then the pin, matching the historical ordering.
                    return Ok(r);
                }
                // Lost the race with an evictor between lookup and pin: release the latch then the
                // pin (via the guard) and fall through to the slow path.
                drop(meta);
                drop(guard);
            }
        }
        // Cold path (miss / Loading / lost race): the full fetch keeps the load-once + publish-before-
        // pin guarantees, then read under a fresh latch. Own the pin in a guard so a panic in `func`
        // inside `with_page` unpins on unwind (`rmp` #594) rather than stranding the frame; `with_page`
        // manages (and releases) its own read latch, so here only the pin needs guarding.
        let f = self.fetch(page_id)?;
        let guard = self.pin_guard(f);
        let r = self.with_page(f, func);
        drop(guard);
        Ok(r)
    }

    /// Mutably borrows the page held by a pinned frame, marks it dirty, and applies `func`.
    ///
    /// Takes the frame's **write latch** for the duration of `func` (exclusive). `func` must not
    /// block or call back into the pool with this frame.
    pub fn with_page_mut<R>(&self, f: PinnedFrame, func: impl FnOnce(&mut Page) -> R) -> R {
        let mut meta = unwrap_lock(self.slot(f).meta.write());
        meta.dirty = true;
        func(&mut meta.data)
    }

    /// Like [`with_page_mut`](Self::with_page_mut) but **stamps `lsn` as the page's `page_lsn`** under
    /// the write latch before applying `func` — the first-class way to record a WAL-logged change so
    /// the WAL-before-data rule holds at write-back (storage audit F6).
    ///
    /// Any mutation backed by a WAL record MUST use this (or stamp `page_lsn` inside
    /// `with_page_mut`'s closure): a dirty page written home with `page_lsn == 0` under a real
    /// [`WalRule`] would make [`write_back`](Self::write_back)'s `ensure_durable(0)` a no-op and
    /// silently break WAL-before-data. `with_page_mut` is for stamp-free work only (e.g. zero-init of
    /// a freshly allocated page); `write_back` enforces the invariant in release builds (it returns
    /// an error for a logged-but-unstamped dirty page; see `guard_wal_before_data`).
    pub fn with_page_mut_lsn<R>(
        &self,
        f: PinnedFrame,
        lsn: Lsn,
        func: impl FnOnce(&mut Page) -> R,
    ) -> R {
        let mut meta = unwrap_lock(self.slot(f).meta.write());
        meta.dirty = true;
        page::set_page_lsn(&mut meta.data, lsn);
        func(&mut meta.data)
    }

    /// Decrements the pin count of a frame (`Release`), so the frame can later be evicted once no
    /// pins remain. Saturating at zero, so a stray double-unpin cannot underflow.
    pub fn unpin(&self, f: PinnedFrame) {
        // A saturating decrement keeps the count from wrapping below zero even under a buggy
        // double-unpin; the `Release` ordering publishes the caller's page writes before the
        // frame becomes evictable.
        let _ = self
            .slot(f)
            .pin_count
            .fetch_update(Ordering::Release, Ordering::Relaxed, |c| {
                Some(c.saturating_sub(1))
            });
    }

    /// The current pin count of a frame (diagnostics / tests).
    #[must_use]
    pub fn pin_count(&self, f: PinnedFrame) -> usize {
        self.slot(f).pin_count.load(Ordering::Acquire)
    }

    /// Wraps an already-established pin — one the caller has just published with
    /// `pin_count.fetch_add(1, …)` — in a [`PinGuard`] whose `Drop` runs the matching
    /// [`unpin`](Self::unpin) on **every** exit path, including a panic in a visit closure
    /// (`rmp` #594). The caller must NOT also call `unpin` for this frame: the guard becomes the
    /// single owner of the pin, and a second `unpin` would double-decrement and break the
    /// strictly-additive pin invariant (`fetch_add` ⇔ exactly one `unpin`) the eviction protocol
    /// relies on. Release the pin by dropping the guard (at scope end or via `drop(guard)`).
    #[inline]
    fn pin_guard(&self, f: PinnedFrame) -> PinGuard<'_, D, W> {
        PinGuard {
            pool: self,
            frame: f,
        }
    }

    /// Fetches `page_id`, loading it from the device on a miss (verifying its checksum) and
    /// pinning it. Concurrent fetches of the same missing page perform **exactly one** device
    /// read; all callers receive a consistent, pinned view.
    ///
    /// # Errors
    /// Returns an error if the device read fails, the loaded page fails its checksum, the pool is
    /// full of pinned frames so no victim can be evicted, or a contended load fails to resolve
    /// within the internal retry bound (a live-lock backstop).
    pub fn fetch(&self, page_id: PageId) -> Result<PinnedFrame> {
        // One backoff per `fetch` call: it escalates across the transient retries below (lost hit-race,
        // peer `Loading`, contended victim sweep) so a herd of concurrent fetchers spreads out in time
        // and the in-flight loader latches drain — instead of re-contending in lockstep, the
        // positive-feedback live-lock the measured `rmp` #359 spurious error came from. Reset to the
        // cheapest step whenever real progress is made (a load completes), so an unrelated later
        // transient does not inherit a long backoff.
        let mut backoff = Backoff::new();
        // Consecutive PURE `AllPinned` sweeps with no interleaved progress (`rmp` #594 D-#4). Reset to
        // zero on ANY progress below (a hit returns; a lost-pin-race `Ready`, a peer `Loading`, and a
        // `Contended` sweep each reset before retrying); only an uninterrupted run trips the shorter
        // [`PERSISTENT_ALL_PINNED_SWEEPS`] error, never the transient #359 `Contended` live-lock.
        let mut consecutive_all_pinned = 0usize;
        // Hoist rounds taken on this call (`rmp` #974): a liveness backstop so a `WalRule` whose
        // harden never advances its durability yields a clean, diagnostic error instead of spinning
        // the retry budget.
        let mut wal_hoists = 0usize;
        #[cfg(feature = "bufpool-probe")]
        let mut iter = 0u64;
        for _ in 0..MAX_FETCH_RETRIES {
            // --- Decide under the target shard lock. ---
            let victim = {
                let mut shard = self.lock_shard(page_id);
                match shard.get(&page_id).copied() {
                    Some(Slot::Ready(idx)) => {
                        // Pin first (Acquire), then drop the shard lock and re-validate the frame
                        // identity under its read latch: this closes the race with an evictor
                        // that might replace the frame between our lookup and our pin.
                        self.frames[idx].pin_count.fetch_add(1, Ordering::Acquire);
                        self.frames[idx].ref_bit.store(1, Ordering::Relaxed);
                        drop(shard);
                        let meta = unwrap_lock(self.frames[idx].meta.read());
                        if meta.page_id == Some(page_id) {
                            #[cfg(feature = "bufpool-probe")]
                            self.probe.record_retry_iters(iter);
                            return Ok(PinnedFrame(idx));
                        }
                        drop(meta);
                        self.unpin(PinnedFrame(idx)); // lost the race; undo and retry
                        consecutive_all_pinned = 0; // progress: a `Ready` frame existed (not all-pinned)
                        #[cfg(feature = "bufpool-probe")]
                        {
                            iter += 1;
                        }
                        backoff.spin();
                        continue;
                    }
                    Some(Slot::Loading(_)) => {
                        // Another thread is loading this exact page; back off (let it finish) and retry.
                        drop(shard);
                        consecutive_all_pinned = 0; // progress: a peer load is in flight
                        #[cfg(feature = "bufpool-probe")]
                        {
                            iter += 1;
                        }
                        backoff.spin();
                        continue;
                    }
                    None => {
                        // Miss: reserve a victim while still holding the shard lock. A `Contended`
                        // sweep (an unpinned frame exists but is momentarily write-latched) and a
                        // *single* `AllPinned` snapshot (every frame pinned *this instant*) are BOTH
                        // **transient** under a correct workload, so both back off and retry (bounded by
                        // `MAX_FETCH_RETRIES`), never fail fast on one occurrence (`rmp` #359).
                        //
                        // Why a single `AllPinned` is transient too (the loom-proven subtlety): a frame's
                        // pin is held only across a single record decode (`with_page_fetched` pins,
                        // decodes, unpins) or across the publish window of a concurrent loader (`fetch`
                        // pins its freshly-loaded frame just before returning, and the caller unpins after
                        // the decode). So a snapshot where *every* frame happens to be pinned right now
                        // (e.g. the one free frame is pinned by a peer loader in the instant between its
                        // load-publish and the caller's unpin) clears microseconds later. Erroring on it
                        // was a spurious `Err("buffer pool is full of pinned pages")` that the read-view
                        // chain swallows into `Value::Null` via the `Option`-returning
                        // `GraphAccess::node_property` — a present property silently read as absent (the
                        // #339 read-integrity violation), seen ONLY under eviction since a pool >= the
                        // working set never misses-needing-a-victim.
                        //
                        // The one refinement (`rmp` #594 D-#4): a `Contended` sweep resets
                        // `consecutive_all_pinned` and retries the FULL budget (the #359 fix is exact and
                        // untouched), while a **sustained** run of PURE `AllPinned` sweeps — the pool
                        // wholly pinned with not one evictable frame appearing between them, the signature
                        // of a genuine caller pin-leak or true capacity — trips the shorter
                        // `PERSISTENT_ALL_PINNED_SWEEPS` error ~10× sooner. The `VictimChoice` split now
                        // drives that one distinction (and still feeds probe diagnostics); the escalating
                        // `backoff` drains the loader/holder herd so a transient case converges instead of
                        // live-locking, and `MAX_FETCH_RETRIES` remains the backstop for `Contended`.
                        match self.select_victim() {
                            VictimChoice::Found(victim) => {
                                shard.insert(page_id, Slot::Loading(victim.idx));
                                victim
                                // shard lock dropped here
                            }
                            VictimChoice::NeedsWalHarden(lsn) => {
                                // The victim is dirty and its redo record is not durable yet. Its
                                // latch was already released by the sweep; drop the shard lock so we
                                // hold NOTHING, harden the log, and re-sweep (`rmp` #974). This is
                                // the hoist: the `fdatasync` happens here, outside every latch,
                                // instead of inside `write_back`.
                                drop(shard);
                                // Progress of a kind was made: an evictable victim exists, it is
                                // simply not yet write-back-eligible. Never let this look like the
                                // capacity wall.
                                consecutive_all_pinned = 0;
                                #[cfg(feature = "bufpool-probe")]
                                {
                                    iter += 1;
                                }
                                // Re-check against the refreshed frontier BEFORE paying for a
                                // harden: a peer's `harden_wal` may already have covered this LSN
                                // and merely not been visible in the mirror when the sweep ran, and
                                // the store's own commit path advances the log without telling this
                                // pool at all. The refresh takes the WAL lock — legal here, holding
                                // nothing — and never syncs.
                                if self.wal_covers_after_refresh(lsn) {
                                    continue;
                                }
                                // A harden is genuinely needed. Bound how many we will pay for on
                                // one call, but NEVER turn exhaustion into an error: a spurious
                                // `Err` out of `fetch` is swallowed by the read-view chain into a
                                // `Value::Null` — a wrong answer rather than a visible failure (the
                                // `rmp` #359/#339 read-integrity class). Past the bound we simply
                                // stop hardening and fall back to the ordinary backed-off retry, so
                                // `MAX_FETCH_RETRIES` stays the single, well-understood backstop.
                                if wal_hoists < WAL_HOIST_ATTEMPTS {
                                    wal_hoists += 1;
                                    self.harden_wal(lsn)?;
                                } else {
                                    backoff.spin();
                                }
                                continue;
                            }
                            VictimChoice::Contended => {
                                // An unpinned frame exists but was momentarily latch-contended — the
                                // **transient** #359 case. Drop the shard lock (hold NO lock across the
                                // wait), reset the persistent-all-pinned signal (a victim is destined to
                                // free), back off, and retry the FULL budget — the next sweep finds it.
                                drop(shard);
                                consecutive_all_pinned = 0;
                                #[cfg(feature = "bufpool-probe")]
                                {
                                    iter += 1;
                                }
                                backoff.spin();
                                continue;
                            }
                            VictimChoice::AllPinned => {
                                // Every frame pinned this sweep. A SINGLE such snapshot is still transient
                                // (the lone free frame pinned by a peer loader between its load-publish and
                                // the caller's unpin), so we back off and retry like `Contended`. But if it
                                // is SUSTAINED for `PERSISTENT_ALL_PINNED_SWEEPS` consecutive sweeps with no
                                // interleaved progress, the pool is genuinely wedged by long-lived pins (a
                                // caller pin-leak) or truly at capacity — no further retry can conjure a
                                // victim — so fail with the clear error ~10× sooner than the full budget
                                // (`rmp` #594 D-#4). Only a PURE run trips: any progress above reset the
                                // counter, so this never fires on the transient #359 contention.
                                drop(shard);
                                consecutive_all_pinned += 1;
                                if consecutive_all_pinned >= PERSISTENT_ALL_PINNED_SWEEPS {
                                    return Err(GraphusError::Storage(format!(
                                        "fetch of page {} found the buffer pool full of pinned pages for \
                                         {PERSISTENT_ALL_PINNED_SWEEPS} consecutive victim sweeps with no \
                                         evictable frame appearing between them — the pool is wedged by \
                                         long-lived pins (a caller pin-leak) or genuinely at capacity; a \
                                         transient all-pinned snapshot clears in microseconds, so a run \
                                         this sustained cannot be transient",
                                        page_id.0
                                    )));
                                }
                                #[cfg(feature = "bufpool-probe")]
                                {
                                    iter += 1;
                                }
                                backoff.spin();
                                continue;
                            }
                        }
                    }
                }
            };

            // --- Load under the victim's exclusive write latch (shard lock released). ---
            //
            // `load_into` returns the victim with its write latch **still held** on success, so we
            // publish the `Ready` entry and pin the frame *before* releasing the latch. This is
            // load-bearing: if we released the latch first, an evictor could select the frame
            // (its pin count is still 0), evict our just-loaded page and load a different one,
            // and we would then pin and return a frame holding the wrong page. Holding the latch
            // until the pin is in place closes that window (loom scenario 2 found exactly this).
            match self.load_into(victim, page_id) {
                Ok(victim) => {
                    let idx = victim.idx;
                    let mut shard = self.lock_shard(page_id);
                    shard.insert(page_id, Slot::Ready(idx));
                    // SAFETY (pin accounting): publish OUR pin with `fetch_add(1)`, NOT an absolute
                    // `store(1)`. The `Loading` reservation makes us the exclusive loader of this
                    // page, but it does NOT make us the exclusive *pinner* of this frame: a hit-path
                    // reader (`fetch`/`with_page_fetched`) that found the frame's PREVIOUS occupant
                    // via `Ready(old)->idx` may have already done its optimistic `fetch_add(1)`
                    // before `evict_held` removed that mapping, so a stale pin for the old page can
                    // be in flight on this very frame. An absolute `store(1)` would *discard* that
                    // pin; the stale reader then re-validates, sees the new `page_id`, and `unpin`s —
                    // decrementing OUR pin instead of its own, dropping the frame's count below the
                    // number of live holders. A later evictor would then reload the frame while a
                    // holder is still about to read it, returning another page's bytes (the #339
                    // read-integrity bug). `fetch_add(1)` keeps pins strictly additive: every
                    // `fetch_add` is balanced by exactly one `unpin`, so the count always equals the
                    // live-holder total and a pinned frame is never evicted out from under a reader.
                    // `Release` publishes our load (the frame bytes) before the pin becomes visible.
                    self.frames[idx].pin_count.fetch_add(1, Ordering::Release);
                    self.frames[idx].ref_bit.store(1, Ordering::Relaxed);
                    drop(shard);
                    drop(victim); // release the write latch only now, after the pin is set
                    #[cfg(feature = "bufpool-probe")]
                    self.probe.record_retry_iters(iter);
                    return Ok(PinnedFrame(idx));
                }
                Err((idx, e)) => {
                    let mut shard = self.lock_shard(page_id);
                    if shard.get(&page_id) == Some(&Slot::Loading(idx)) {
                        shard.remove(&page_id);
                    }
                    drop(shard);
                    return Err(e);
                }
            }
        }
        Err(GraphusError::Storage(format!(
            "fetch of page {} did not resolve within {MAX_FETCH_RETRIES} retries under sustained \
             contention (a peer load never completed, or evictable victims stayed latch-contended for \
             the entire backed-off budget); a genuinely full pool of pinned pages errors immediately, \
             so this is the extreme-over-subscription / pin-leak backstop, not the capacity limit",
            page_id.0
        )))
    }

    /// Allocates a fresh zero page at the end of the device, pins it, and returns its handle and
    /// id.
    ///
    /// # Errors
    /// Returns an error if the pool is full of pinned frames, evicting the chosen victim fails
    /// (WAL rule / device write), or extending the device fails.
    pub fn new_page(&self) -> Result<(PinnedFrame, PageId)> {
        // Reserve a victim first so a fully-pinned pool fails before we grow the device. As in `fetch`'s
        // miss-arm, a `Contended` sweep (an unpinned frame momentarily write-latched) and a *single*
        // `AllPinned` snapshot (every frame pinned *this instant*, e.g. the lone free frame pinned by a
        // peer loader between its load-publish and the caller's unpin) are BOTH **transient** under a
        // correct workload, so both retry with the escalating backoff that drains the holder herd, never
        // surfacing a spurious "full" error on one occurrence (`rmp` #359; the single-`AllPinned`-is-also-
        // transient subtlety is loom-proven by `loom_fetch_under_contention_never_spuriously_fails`).
        // D-#4 (`rmp` #594): a `Contended` sweep resets the persistent-all-pinned counter and retries the
        // FULL budget, while a **sustained** PURE `AllPinned` run (a genuine pin-leak / true capacity,
        // e.g. `a_fully_pinned_pool_cannot_evict`) trips the shorter `PERSISTENT_ALL_PINNED_SWEEPS` error
        // ~10× sooner. No lock is held here, so the retry is a plain backed-off loop; `MAX_FETCH_RETRIES`
        // remains the `Contended` backstop.
        let mut backoff = Backoff::new();
        let mut consecutive_all_pinned = 0usize;
        // Hoist rounds taken on this call (`rmp` #974) — the liveness backstop, as in `fetch`.
        let mut wal_hoists = 0usize;
        let mut victim = 'pick: {
            for _ in 0..MAX_FETCH_RETRIES {
                match self.select_victim() {
                    VictimChoice::Found(v) => break 'pick v,
                    VictimChoice::NeedsWalHarden(lsn) => {
                        // The victim is dirty with an un-hardened `page_lsn`; its latch was already
                        // released by the sweep. Harden with nothing held and re-sweep (`rmp` #974),
                        // so the `fdatasync` never runs inside a latched region. Identical shape to
                        // `fetch`'s arm: re-check first (a peer or the commit path may already have
                        // covered it), bound the hardens, and degrade to backoff rather than to a
                        // spurious error.
                        consecutive_all_pinned = 0;
                        if self.wal_covers_after_refresh(lsn) {
                            continue;
                        }
                        if wal_hoists < WAL_HOIST_ATTEMPTS {
                            wal_hoists += 1;
                            self.harden_wal(lsn)?;
                        } else {
                            backoff.spin();
                        }
                        continue;
                    }
                    VictimChoice::Contended => {
                        // Transient: an unpinned frame exists — reset the persistent signal and retry.
                        consecutive_all_pinned = 0;
                        backoff.spin();
                        continue;
                    }
                    VictimChoice::AllPinned => {
                        // Sustained PURE all-pinned ⇒ genuine capacity / pin-leak: fail ~10× sooner than
                        // the full live-lock budget. A single snapshot is still transient (#359), so only
                        // an uninterrupted consecutive run trips.
                        consecutive_all_pinned += 1;
                        if consecutive_all_pinned >= PERSISTENT_ALL_PINNED_SWEEPS {
                            return Err(GraphusError::Storage(format!(
                                "new_page found the buffer pool full of pinned pages for \
                                 {PERSISTENT_ALL_PINNED_SWEEPS} consecutive victim sweeps with no \
                                 evictable frame appearing between them — the pool is wedged by \
                                 long-lived pins (a caller pin-leak) or genuinely at capacity; a \
                                 transient all-pinned snapshot clears in microseconds, so a run this \
                                 sustained cannot be transient"
                            )));
                        }
                        backoff.spin();
                        continue;
                    }
                }
            }
            return Err(GraphusError::Storage(
                "buffer pool could not reserve a victim within the retry budget (sustained \
                 contention or a pool wedged by long-lived pins)"
                    .to_owned(),
            ));
        };
        // Evict the victim's previous occupant (if any) under its write latch.
        self.evict_held(&mut victim)?;
        let page_id = {
            // Allocation needs `&mut D` (`extend`) and must read `page_count` then grow atomically,
            // so it takes the device **write** guard. This serialises allocations against each other
            // and excludes concurrent device reads for its (brief) duration — which is required for
            // soundness, not just consistency: `extend` takes `&mut D` and a backing store may
            // reallocate its buffer when it grows (e.g. a `Vec::resize`), so a concurrent `&self`
            // `read_page` racing it would be a data race. The `RwLock`'s read/write exclusion forbids
            // exactly that overlap, while still letting reads run concurrently with *each other*.
            let mut device = self.write_device();
            let id = PageId(device.page_count());
            device.extend(1)?;
            id
        };
        let idx = victim.idx;
        {
            let meta = &mut *victim.guard;
            *meta.data = [0u8; PAGE_SIZE];
            page::set_page_id(&mut meta.data, page_id.0);
            page::write_checksum(&mut meta.data);
            meta.page_id = Some(page_id);
            meta.dirty = true;
        }
        let mut shard = self.lock_shard(page_id);
        shard.insert(page_id, Slot::Ready(idx));
        // SAFETY (pin accounting): additive publish, NOT an absolute `store(1)` — identical
        // reasoning to `fetch`'s publish above. A stale optimistic pin from the victim's PREVIOUS
        // occupant (a hit-path reader that did `fetch_add(1)` on `Ready(old)->idx` before
        // `evict_held` removed that mapping) may still be in flight on this frame; an absolute store
        // would discard it and the subsequent stale `unpin` would then decrement OUR pin. Keeping
        // pins strictly additive (`fetch_add`/`unpin` always balanced) is what guarantees a
        // just-allocated page is never evicted out from under its allocator.
        self.frames[idx].pin_count.fetch_add(1, Ordering::Release);
        self.frames[idx].ref_bit.store(1, Ordering::Relaxed);
        drop(shard);
        drop(victim); // release the write latch
        Ok((PinnedFrame(idx), page_id))
    }

    /// Writes a frame back to the device if it is dirty (honouring the WAL rule first).
    ///
    /// The WAL harden the rule may require is **hoisted out of the frame latch** (`rmp` #974): the
    /// latch is taken, the page's `page_lsn` inspected, and if the log is not durable through it the
    /// latch is *released*, the log hardened with nothing held, and the attempt retried. So this
    /// method never issues an `fdatasync` inside a latched region.
    ///
    /// # Errors
    /// Propagates a WAL-rule or device-write failure, or reports failure to converge within
    /// [`WAL_HOIST_ATTEMPTS`] hoist-and-retry rounds (only reachable if a concurrent writer re-dirties
    /// the frame with a fresh LSN on every single round).
    pub fn flush(&self, f: PinnedFrame) -> Result<()> {
        for _ in 0..WAL_HOIST_ATTEMPTS {
            let needs_harden = {
                let latch = graphus_core::latch::FrameLatchScope::new();
                let mut meta = unwrap_lock(self.frames[f.0].meta.write());
                if !meta.dirty {
                    return Ok(());
                }
                let lsn = page::page_lsn(&meta.data);
                if self.wal_covers(lsn) {
                    return self.write_back(&mut meta, false);
                }
                drop(meta);
                drop(latch);
                lsn
            };
            // No latch held: this is where the `fdatasync` is allowed to happen. Refresh first —
            // the mirror may simply have been stale-low because the store's commit path advanced
            // the log without going through this pool.
            if !self.wal_covers_after_refresh(needs_harden) {
                self.harden_wal(needs_harden)?;
            }
        }
        Err(GraphusError::Storage(format!(
            "flush of frame {} did not converge within {WAL_HOIST_ATTEMPTS} WAL hoist rounds: the \
             frame was re-dirtied with a not-yet-durable page_lsn on every round",
            f.0
        )))
    }

    /// Writes a frame back that intentionally carries **no WAL-logged change** (its `page_lsn` is
    /// `0`), seeding a valid checksum on disk for a freshly-allocated page before its first logged
    /// write — e.g. a record/metadata page header stamped at allocation, then filled by later
    /// WAL-logged `with_page_mut_lsn` writes.
    ///
    /// This is the one legitimate exception to the WAL-before-data debug-assert in
    /// [`write_back`](Self::write_back): an unlogged page has *nothing in the WAL that must precede
    /// it*, so writing it home with `page_lsn == 0` (an `ensure_durable(0)` no-op) is sound — exactly
    /// the semantics the single-threaded [`BufferPool::flush`](crate::BufferPool::flush) gave this
    /// idiom. Use [`flush`](Self::flush) for every page that *does* carry a logged change; this method
    /// only for the seed-checksum case.
    ///
    /// # Errors
    /// Propagates a WAL-rule or device-write failure.
    pub fn flush_unlogged(&self, f: PinnedFrame) -> Result<()> {
        // No hoist loop is needed: an unlogged page has nothing in the WAL that must precede it, so
        // this path never hardens. The tripwire is still armed, so a future change that introduces a
        // barrier here is caught rather than silently reopening the `rmp` #974 convoy.
        let _latch = graphus_core::latch::FrameLatchScope::new();
        let mut meta = unwrap_lock(self.frames[f.0].meta.write());
        self.write_back(&mut meta, true)
    }

    /// Writes every dirty frame back (each under its own write latch) and syncs the device.
    ///
    /// # Concurrency contract (storage audit F12)
    /// This is **not** a global barrier under concurrent writers: each frame's latch is released
    /// after its write-back, so a writer can re-dirty a frame *after* it was written but *before* the
    /// final `sync_all`. Such a page is left dirty (its dirty flag is re-set) and is captured by a
    /// later `flush_all` — so **no committed change is ever lost**, but a returned `Ok` does not mean
    /// "every page dirty at the call instant is now durable". A caller needing that stronger barrier
    /// (a *sharp* checkpoint) must **quiesce writers** for the duration — which the single-threaded
    /// storage engine's checkpoint does by construction (it owns the only writer). Do not rely on
    /// `flush_all` alone as a checkpoint barrier from multiple concurrent writers.
    ///
    /// # Errors
    /// Propagates the first WAL-rule, device-write or sync failure.
    pub fn flush_all(&self) -> Result<()> {
        self.flush_batch(None)
    }

    /// Writes back **only** the dirty frames whose home `PageId` is in `pages`, then syncs the
    /// device once. This is the targeted counterpart of [`flush_all`](Self::flush_all): it lets a
    /// caller flush a *bounded subset* of the dirty set home without writing the rest, which the
    /// doublewrite-protected checkpoint requires — each batch's home pages must only be written
    /// *after that batch's* images are durable in the doublewrite buffer, never before
    /// ([`crate::page`]; `graphus_storage::RecordStore::flush_protected`, `05 §3`).
    ///
    /// Every per-page durability guarantee of `flush_all` is preserved for the selected pages: the
    /// checksum is stamped and the WAL-before-data rule is enforced *before* the page's bytes are
    /// written home, frames are flushed under their write latch (held across the device write so no
    /// concurrent mutator or the evictor can tear the in-flight image), and a single trailing
    /// `sync_all` barrier is issued after the batch. Frames not in `pages` are left dirty and
    /// untouched, captured by a later flush.
    ///
    /// The same F12 concurrency contract applies: a selected frame re-dirtied after its latch is
    /// released here is captured by a later flush; a sharp checkpoint still requires the
    /// (single-writer) engine to quiesce writers, which it does by construction.
    ///
    /// # Errors
    /// Propagates the first WAL-rule, device-write or sync failure.
    pub fn flush_pages(&self, pages: &[PageId]) -> Result<()> {
        let wanted: rustc_hash::FxHashSet<u64> = pages.iter().map(|p| p.0).collect();
        self.flush_batch(Some(&wanted))
    }

    /// The shared implementation behind [`flush_all`](Self::flush_all) (`want == None`, every dirty
    /// frame) and [`flush_pages`](Self::flush_pages) (`want == Some`, the selected home page ids).
    ///
    /// The two differed only in which frames they latched; every durability step was duplicated
    /// line-for-line, including the WAL-before-data ordering that `rmp` #974 had to restructure.
    /// Unifying them means that ordering exists in exactly one place.
    ///
    /// # WAL-before-data, hoisted (`rmp` #974)
    ///
    /// The old shape held **every** dirty frame's write latch and then, still holding all of them,
    /// ran `ensure_durable(page_lsn)` per page — N latches held across up to N `fdatasync`s, through
    /// the mutex the store's commit path shares. The harden is now hoisted:
    ///
    /// 1. latch the batch's dirty frames (Phase 1);
    /// 2. take the batch's **maximum** `page_lsn`. Because coverage is monotone in the LSN, the log
    ///    being durable through that maximum covers every page in the batch;
    /// 3. if it is not covered, **release every latch**, harden with nothing held, and retry from 1.
    ///
    /// Step 3 is what makes the barrier latch-free. It terminates: one harden makes the whole
    /// appended log durable, and these paths run on the checkpointing writer, so a second round only
    /// occurs if another thread dirtied a page in between. [`WAL_HOIST_ATTEMPTS`] bounds it, and
    /// exhausting it returns a clean error with every page still dirty and resident — nothing is
    /// lost, a later flush captures them.
    ///
    /// # Errors
    /// Propagates the first WAL-rule, device-write or sync failure, or reports failure to converge
    /// within [`WAL_HOIST_ATTEMPTS`] hoist rounds.
    fn flush_batch(&self, want: Option<&rustc_hash::FxHashSet<u64>>) -> Result<()> {
        for _ in 0..WAL_HOIST_ATTEMPTS {
            // Phase 1: collect the batch's dirty frames with their write latches held. The tripwire
            // is armed for exactly as long as those latches are (`FlushBatch` drops the guards
            // first, then the scope), so any durability barrier reached from inside this region
            // panics in a debug build instead of silently restoring the convoy.
            //
            // Latches are acquired in **frame-index order** (the `self.frames` scan order), the same
            // order eviction would, so there is no lock-ordering cycle.
            let mut batch = FlushBatch::collect(self, want);
            if batch.guards.is_empty() {
                drop(batch);
                // Nothing to write home; still issue the trailing barrier the callers rely on. It
                // goes through the shared handle, so it holds no device guard.
                return self.barrier_sync_all();
            }

            // Phase 2: stamp each dirty page's checksum and enforce the page-level WAL invariants.
            // Neither step syncs: `guard_wal_before_data` is the release-built `page_lsn == 0`
            // check (`rmp` #396), reading the rule property cached at construction rather than
            // taking the WAL mutex under these N latches.
            let mut max_lsn = Lsn(0);
            for (_, meta) in &mut batch.guards {
                let page_id = meta.page_id.ok_or_else(|| {
                    GraphusError::Storage("a dirty frame must hold a page".to_owned())
                })?;
                page::write_checksum(&mut meta.data);
                let lsn = page::page_lsn(&meta.data);
                // WAL-before-data invariant, release-enforced (`rmp` #396): batch flushes only ever
                // write logged pages home (no `allow_unlogged` path), so a `page_lsn == 0` under a
                // real WAL is always a caller error that must fail closed, not a silent durability
                // hole.
                self.guard_wal_before_data(page_id, lsn, false)?;
                max_lsn = Lsn(max_lsn.0.max(lsn.0));
            }

            // Phase 2a: THE HOIST. If the log is not durable through the batch's highest `page_lsn`,
            // release every latch and harden outside the latched region, then retry. Coverage is
            // monotone in the LSN, so one check over the maximum decides the whole batch.
            if !self.wal_covers(max_lsn) {
                drop(batch);
                // Latches released: refresh the mirror (it may merely be stale-low after a commit
                // this pool did not drive) and harden only if the log really is behind.
                if !self.wal_covers_after_refresh(max_lsn) {
                    self.harden_wal(max_lsn)?;
                }
                continue;
            }

            // Phase 3: order the held frames by page id and coalesce contiguous runs. A gap in page
            // ids (next.page_id != prev.page_id + 1) breaks the run, so only pages at adjacent file
            // offsets are ever combined into one vectored/sequential device write (`rmp` #374).
            batch
                .guards
                .sort_by_key(|(_, meta)| meta.page_id.expect("dirty frame holds a page").0);

            // Phase 3a: doublewrite protection (`rmp` #407, `05 §3`). When a stager is installed,
            // stage the ENTIRE batch into the doublewrite area as one durable batch BEFORE any of
            // its pages are written home — so every page written home below has an intact
            // doublewrite copy and a torn home write is repairable on the next open. The caller
            // (`RecordStore::flush_protected`) bounds each batch to the doublewrite batch capacity.
            // The staging takes the DWB lock AFTER the frame latches are already held (Phase 1), so
            // the global lock order is uniformly **frame-latch → DWB**, matching the eviction path's
            // `write_back` — no ABBA deadlock between a checkpoint and a concurrent
            // reader-triggered eviction. The checksums were stamped in Phase 2, so the staged bytes
            // equal the bytes about to land home.
            //
            // Only the *targeted* path stages: `flush_all` is the unprotected whole-pool flush and
            // has never staged (its callers own doublewrite protection themselves, if any).
            if want.is_some()
                && let Some(stager) = self.page_stager()
            {
                let staged: Vec<(PageId, &[u8])> = batch
                    .guards
                    .iter()
                    .map(|(_, meta)| {
                        (
                            meta.page_id.expect("dirty frame holds a page"),
                            &meta.data[..],
                        )
                    })
                    .collect();
                stager.stage_batch_and_sync(&staged)?;
            }

            {
                let mut device = self.write_device();
                let mut run_start = 0usize; // index into `guards` where the current run begins
                for i in 1..=batch.guards.len() {
                    let break_run = i == batch.guards.len() || {
                        let prev = batch.guards[i - 1]
                            .1
                            .page_id
                            .expect("dirty frame holds a page")
                            .0;
                        let cur = batch.guards[i]
                            .1
                            .page_id
                            .expect("dirty frame holds a page")
                            .0;
                        cur != prev + 1
                    };
                    if break_run {
                        let base = batch.guards[run_start]
                            .1
                            .page_id
                            .expect("dirty frame holds a page");
                        let run: Vec<&Page> = batch.guards[run_start..i]
                            .iter()
                            .map(|(_, meta)| &*meta.data)
                            .collect();
                        device.write_pages(base, &run)?;
                        run_start = i;
                    }
                }
                // The exclusive device guard is released HERE, before the barrier (`rmp` #974): it
                // is needed for the `&mut` writes, never for the durability barrier, and holding it
                // across the barrier is what blocked every concurrent cache-miss read.
            }

            // Phase 4: the bytes are home — mark every flushed frame clean, then release the latches
            // and issue the single trailing durability barrier exactly once, holding no device
            // guard. The barrier still happens-after the writes above (they returned before it was
            // issued), so the ordering the callers rely on is unchanged.
            for (_, meta) in &mut batch.guards {
                meta.dirty = false;
            }
            drop(batch);
            return self.barrier_sync_all();
        }
        Err(GraphusError::Storage(format!(
            "batch flush did not converge within {WAL_HOIST_ATTEMPTS} WAL hoist rounds: a \
             concurrent writer re-dirtied the batch with a not-yet-durable page_lsn on every round"
        )))
    }

    /// A snapshot count of currently dirty frames (diagnostics / tests).
    #[must_use]
    pub fn dirty_frames(&self) -> usize {
        self.frames
            .iter()
            .filter(|s| unwrap_lock(s.meta.read()).dirty)
            .count()
    }

    /// A snapshot of the eviction-diagnostics probe counters (`rmp` #359, `bufpool-probe` feature
    /// only). Lets a fast runtime repro read how often a `select_victim` sweep came up empty because
    /// every frame was genuinely pinned (capacity) vs because an unpinned frame was momentarily
    /// latch-contended (transient) — the measurement that pins down the precise mechanism. Compiled
    /// out of the production build.
    /// A snapshot of the **write-back durability timers** (`rmp` #974, `bufpool-probe` feature only):
    /// where an eviction write-back spends its time, and — the number this task turns on — how long
    /// concurrent cache-miss reads spent *waiting* for the device read guard while another thread
    /// was fsyncing under the exclusive write guard. Compiled out of the production build.
    #[cfg(feature = "bufpool-probe")]
    #[must_use]
    pub fn write_back_probe(&self) -> probe::WriteBackProbe {
        self.probe.snapshot_write_back()
    }

    #[cfg(feature = "bufpool-probe")]
    #[must_use]
    pub fn probe_snapshot(&self) -> probe::ProbeSnapshot {
        probe::ProbeSnapshot {
            victim_miss_all_pinned: self.probe.all_pinned(),
            victim_miss_contended: self.probe.contended(),
            max_retry_iters: self.probe.max_retry_iters(),
        }
    }

    /// A non-blocking **prefetch hint** for a single page (`specification` §3.5).
    ///
    /// If the page is not resident and a victim is available, it is loaded and *immediately
    /// unpinned*, warming the cache without keeping a pin. Best-effort: any error (a full pool, a
    /// transient device error) is swallowed, because a prefetch must never affect correctness —
    /// only latency. Returns `true` if the page is resident after the call.
    ///
    /// Adjacency-aware prefetch (§3.5) — fetching the next relationship record's page while the
    /// current one is processed — plugs in here by feeding the predicted next [`PageId`]s; that
    /// integration lives in the traversal layer and is the documented seam.
    pub fn prefetch(&self, page_id: PageId) -> bool {
        match self.fetch(page_id) {
            Ok(frame) => {
                self.unpin(frame);
                true
            }
            Err(_) => false,
        }
    }

    /// Sequential read-ahead (`specification` §3.5): prefetches `count` consecutive pages
    /// starting at `start`. Best-effort (each page is loaded then immediately unpinned). Returns
    /// how many of the requested pages are resident afterwards.
    pub fn prefetch_sequential(&self, start: PageId, count: u64) -> u64 {
        let mut warmed = 0;
        for offset in 0..count {
            let pid = PageId(start.0.saturating_add(offset));
            if self.prefetch(pid) {
                warmed += 1;
            }
        }
        warmed
    }

    // --- internals -------------------------------------------------------------------------

    /// Selects an evictable victim frame, returning it with its write latch already held, or
    /// classifying *why* a bounded sweep found none ([`VictimChoice`]).
    ///
    /// CLOCK sweep: a candidate is acquired with `try_write` (so two threads never pick the same
    /// frame, and a busy frame is skipped), skipped if pinned, and given a second chance — clearing
    /// its reference bit — if its reference bit is set and it is occupied. The first unpinned,
    /// unreferenced frame whose latch we win is the victim; empty frames are taken eagerly.
    ///
    /// When the bounded (`4*n` hand advances) sweep finds no takeable victim it **distinguishes** the
    /// two reasons so the caller never mistakes one for the other (`rmp` #359 read-integrity bug):
    /// [`VictimChoice::AllPinned`] (every frame pinned — the genuine capacity limit, fail fast) vs
    /// [`VictimChoice::Contended`] (an unpinned frame exists but was momentarily latch-contended —
    /// transient, retry with backoff). The sweep itself only takes non-blocking `try_write` latches,
    /// so it never blocks and is loom-finite; the *patience* (backing off + retrying the `Contended`
    /// case) lives in the caller, which drops its shard lock first so no lock is held across a wait.
    fn select_victim(&self) -> VictimChoice<'_> {
        let n = self.frames.len();
        // `all_pinned` stays true only if EVERY frame examined this sweep was **pinned** — the genuine
        // capacity signal (fail fast). The instant any frame is seen *unpinned* (even one we could not
        // latch right now), it clears: an unpinned frame is an evictable victim whose latch frees in
        // microseconds, so the outcome is `Contended` (retry with backoff), not `AllPinned`. This is
        // the distinction the `rmp` #359 fix turns on: instrumentation proved `AllPinned` is observed
        // **zero** times under a concurrent-reader eviction storm (the misses are 100% transient
        // contention), so collapsing the two — erroring on any empty sweep — surfaced a spurious
        // `Err` that the read path swallowed into `Value::Null` / a truncated chain (a wrong result).
        let mut all_pinned = true;
        // Several full sweeps give CLOCK room to clear reference bits and absorb frames briefly
        // latched by other threads, while staying bounded for loom.
        for _ in 0..(4 * n) {
            let idx = self.clock.fetch_add(1, Ordering::Relaxed) % n;
            let slot = &self.frames[idx];
            if slot.pin_count.load(Ordering::Acquire) > 0 {
                continue; // pinned right now: not a candidate this instant (keeps `all_pinned`).
            }
            // Unpinned ⇒ a real eviction candidate, even if we cannot take it this pass.
            all_pinned = false;
            // `try_write` never blocks: a frame momentarily latched by a reader/loader is skipped this
            // pass — it is unpinned, so it WILL become takeable shortly (the caller retries).
            let Ok(guard) = slot.meta.try_write() else {
                continue;
            };
            // Arm the frame-latch tripwire the instant the latch is won, NOT later at the `Found`
            // return: everything between here and the return runs with the latch held, so anything
            // that region reaches must be visible to the tripwire (`rmp` #974). Arming it only on
            // the accepted path would leave the WAL-coverage check below — the one place the sweep
            // deliberately touches WAL state under a latch — unchecked, which is precisely the
            // region the tripwire exists to police.
            let latch = graphus_core::latch::FrameLatchScope::new();
            // Re-check the pin count now that we hold the latch (a pin may have raced in).
            if slot.pin_count.load(Ordering::Acquire) > 0 {
                continue;
            }
            if slot.ref_bit.swap(0, Ordering::Relaxed) == 1 && guard.page_id.is_some() {
                continue; // second chance for a referenced, occupied frame
            }
            // WAL-BEFORE-DATA, HOISTED (`rmp` #974). This is the last point at which the harden can
            // still be moved out of the latched region: from here the latch is held continuously
            // through `load_into` → `evict_held` → `write_back`, so a harden discovered later would
            // necessarily run *under* the latch — the convoy this task removed.
            //
            // If the victim is dirty and its `page_lsn` is not already covered by durable log, we
            // therefore **decline this victim**: the guard is dropped (releasing the latch) and the
            // caller hardens with nothing held, then re-sweeps. This mirrors PostgreSQL's
            // `GetVictimBuffer`, which rejects a victim on `XLogNeedsFlush` rather than flush under
            // the buffer lock.
            //
            // The check is exact for the write-back that follows: because the latch is held
            // continuously from here to `write_back`, no writer can re-dirty this frame or advance
            // its `page_lsn` in between, so a victim accepted here is still covered when its bytes
            // are written home.
            //
            // It consults ONLY the lock-free mirror — never the WAL lock. That restriction is
            // load-bearing, not stylistic: `self.wal` guards the rule *object*, while the production
            // rule keeps the real `WalManager` behind its own mutex, so even a `try_lock` here would
            // fall through into a blocking acquisition that can park behind a commit's `fdatasync` —
            // while this thread holds a frame latch AND the caller holds a shard lock. That would
            // re-create the convoy one lock deeper and add a `shard → WAL` wait edge the lock-order
            // proof forbids. A stale-low mirror simply costs one decline-and-retry: the hoist path
            // refreshes it with nothing held, and `ensure_durable` no-ops when the log is in fact
            // already durable.
            if self.wal_tracks_lsn && guard.dirty {
                let lsn = page::page_lsn(&guard.data);
                if !self.wal_covers(lsn) {
                    drop(guard); // release the latch BEFORE the caller hardens
                    drop(latch); // and disarm the tripwire with it
                    return VictimChoice::NeedsWalHarden(lsn);
                }
            }
            return VictimChoice::Found(Victim {
                idx,
                guard,
                _latch: latch,
            });
        }
        #[cfg(feature = "bufpool-probe")]
        self.probe.record_victim_miss(all_pinned);
        if all_pinned {
            VictimChoice::AllPinned
        } else {
            VictimChoice::Contended
        }
    }

    /// Writes back the victim's previous occupant (if dirty, honouring the WAL rule) and removes
    /// it from its shard, leaving the latched frame a clean blank slate. Caller holds the latch
    /// via `victim`.
    fn evict_held(&self, victim: &mut Victim<'_>) -> Result<()> {
        let old = victim.guard.page_id;
        self.write_back(&mut victim.guard, false)?;
        if let Some(old_id) = old {
            // Remove the old mapping under the old page's shard lock (frame latch already held).
            let mut shard = self.lock_shard(old_id);
            if shard.get(&old_id) == Some(&Slot::Ready(victim.idx)) {
                shard.remove(&old_id);
            }
            drop(shard);
            victim.guard.page_id = None;
        }
        Ok(())
    }

    /// Reads `page_id` from the device into the (write-latched) victim frame, verifying the
    /// checksum, after evicting the victim's previous occupant.
    ///
    /// On success the victim is **returned with its write latch still held**, so the caller can
    /// publish the table entry and set the pin count before releasing the latch (closing the
    /// publish-before-pin eviction window). On failure it returns `(idx, err)` after blanking the
    /// frame so it is reusable, and the latch is released as the victim is dropped here.
    fn load_into<'a>(
        &self,
        mut victim: Victim<'a>,
        page_id: PageId,
    ) -> std::result::Result<Victim<'a>, (usize, GraphusError)> {
        let idx = victim.idx;
        if let Err(e) = self.evict_held(&mut victim) {
            self.blank(&mut victim);
            return Err((idx, e));
        }
        // Read under a device **read** guard into the latched frame's bytes (`rmp` #362). This is
        // the hot concurrency win: `read_page(&self, ...)` only reads the device, so many threads
        // that miss the pool at once may hold the read guard *simultaneously* and read their
        // distinct pages in parallel — they no longer serialise on one device mutex. Correctness is
        // unchanged: each reading thread owns a *different* victim frame (its own exclusive write
        // latch, won non-blocking by `try_write` in `select_victim`), so the two reads write to
        // disjoint frame buffers; the read guard is the innermost lock (taken under that frame
        // latch, never under a shard lock) and is released the instant the read returns, so the
        // lock-ordering proof is preserved (device innermost, no new wait edge). The exclusive write
        // guard taken by `write_page`/`extend`/`sync_*` still fences these reads against a concurrent
        // device mutation, so a page can never be read while it is being relocated/grown.
        {
            #[cfg(feature = "bufpool-probe")]
            let wait_start = std::time::Instant::now();
            let device = self.read_device();
            #[cfg(feature = "bufpool-probe")]
            self.probe
                .record_device_read_wait(wait_start.elapsed().as_nanos() as u64);
            if let Err(e) = device.read_page(page_id, &mut victim.guard.data) {
                drop(device);
                self.blank(&mut victim);
                return Err((idx, e));
            }
        }
        if !page::verify_checksum(&victim.guard.data) {
            self.blank(&mut victim);
            return Err((
                idx,
                GraphusError::Storage(format!("page {} failed checksum verification", page_id.0)),
            ));
        }
        victim.guard.page_id = Some(page_id);
        victim.guard.dirty = false;
        Ok(victim)
    }

    /// Blanks a frame (after a failed load) so it is reusable as an empty slot. Caller holds the
    /// frame's write latch via `victim`.
    fn blank(&self, victim: &mut Victim<'_>) {
        victim.guard.page_id = None;
        victim.guard.dirty = false;
        // SAFETY (pin accounting): do NOT force the pin to 0. `blank` runs only on the LOAD-FAILURE
        // path, where this thread (the loader) never added a pin — the additive `fetch_add` publish
        // in `fetch`/`new_page` is success-only. The only pins that can be present here are stale
        // optimistic pins placed by a hit-path reader on this frame's PREVIOUS occupant (via
        // `Ready(old)->idx`) before `evict_held` removed that mapping; each is balanced by that
        // reader's own `unpin`. Storing 0 would discard them and break the strictly-additive
        // invariant (`fetch_add`⇔`unpin`) the whole protocol relies on, and could expose the frame
        // (now `page_id == None`, an "empty" slot taken eagerly by `select_victim`) for reload while
        // a stale `PinnedFrame(idx)` handle is still outstanding. Leaving the count alone keeps the
        // frame reserved until its real holders unpin — `select_victim` already guaranteed
        // `pin_count == 0` when it picked this victim, so any nonzero count here is exactly those
        // self-balancing stale pins and can never wedge the frame.
        self.frames[victim.idx].ref_bit.store(0, Ordering::Relaxed);
    }

    /// Writes a frame back if dirty. Caller holds the write latch (passed as `meta`).
    fn write_back(&self, meta: &mut FrameMeta, allow_unlogged: bool) -> Result<()> {
        if !meta.dirty {
            return Ok(());
        }
        #[cfg(feature = "bufpool-probe")]
        let wb_start = std::time::Instant::now();
        let r = self.write_back_dirty(meta, allow_unlogged);
        #[cfg(feature = "bufpool-probe")]
        self.probe
            .record_write_back(wb_start.elapsed().as_nanos() as u64);
        r
    }

    /// The dirty branch of [`write_back`](Self::write_back), split out so the whole home-write path
    /// can be timed by the `bufpool-probe` seam with a single wrapper.
    fn write_back_dirty(&self, meta: &mut FrameMeta, allow_unlogged: bool) -> Result<()> {
        let page_id = meta
            .page_id
            .ok_or_else(|| GraphusError::Storage("a dirty frame must hold a page".to_owned()))?;
        page::write_checksum(&mut meta.data);
        let lsn = page::page_lsn(&meta.data);
        // WAL-before-data invariant (storage audit F6, `rmp` #396): under a real WAL every dirty
        // page that carries a logged change must hold a non-zero `page_lsn`, else `ensure_durable(0)`
        // is a no-op and the data could reach the device before its redo record is durable. A
        // `page_lsn` of 0 means the mutation did not stamp it (use `with_page_mut_lsn`). The one
        // legitimate exception is `allow_unlogged` (via [`flush_unlogged`]): a freshly-allocated,
        // not-yet-logged page being seeded with a valid checksum, which by contract has nothing in
        // the WAL that must precede it. This is enforced as a **release-built** invariant: a single
        // caller mistake (a logged write reaching here without a stamped LSN) would otherwise be a
        // silent CRITICAL durability bug in release, so we fail closed with an error rather than a
        // `debug_assert` that compiles out.
        self.guard_wal_before_data(page_id, lsn, allow_unlogged)?;
        // WAL rule: the log must be durable through this page's LSN before the data is written home
        // (`specification` §3.2 page_lsn, §4.3 steal/no-force).
        //
        // HOISTED (`rmp` #974). This used to be `ensure_durable(lsn)` — an `fdatasync` issued right
        // here, under the caller's frame latch, through the mutex the store's commit path shares.
        // The harden now happens *before* the latch is taken (`select_victim` hoists it for the
        // eviction path; the flush paths hoist it in their own pre-pass), so all that remains here
        // is the **verification**, which never syncs. It is fail-closed: an uncovered page is
        // refused, never written home.
        // The exemption is the **null LSN**, not the `allow_unlogged` flag. `allow_unlogged` exists
        // so a freshly-allocated page with `page_lsn == 0` can be seeded with a valid checksum, and
        // for that page there is by definition nothing in the log that must precede it. But
        // `flush_unlogged` is a public API: gating on the flag would mean a caller passing a page
        // that *does* carry a stamped LSN gets no ordering check at all — strictly weaker than the
        // pre-`rmp` #974 code, which ran the rule unconditionally. Gating on `lsn == 0` keeps the
        // exemption exactly as narrow as its justification.
        if lsn.0 != 0 {
            self.assert_wal_covers(page_id, lsn)?;
        }
        // Doublewrite protection of the home write (`rmp` #407, `05 §3`). Before the page reaches its
        // home location, stage its EXACT image (checksum already stamped just above, so the staged
        // bytes equal the bytes about to land home) into the doublewrite area and fsync it. After
        // `stage_and_sync` returns, an intact copy of this page is durable, so a torn home write below
        // is repairable on the next open (`recover_device_with_dwb`). This protects EVERY dirty data
        // page written home — the checkpoint/flush path (`flush_pages`/`flush_all`, which already
        // stage their batch in `RecordStore::flush_protected`) AND, crucially, the eviction/steal path
        // (`evict_held`/`load_into`/`new_page`), which previously wrote dirty home pages directly with
        // no doublewrite copy. The stager's own interior lock serialises concurrent evictions' staging.
        //
        // `allow_unlogged` pages are SKIPPED: a freshly-allocated, not-yet-logged page (seeded with a
        // valid checksum via `flush_unlogged`/`new_page`'s blank-then-checksum) carries no committed
        // data, so a torn write of it loses nothing that recovery must reconstruct — redo recreates it
        // from the WAL once it is logged. Staging it would only cost a doublewrite fsync for no
        // durability gain. Logged pages (the steal of a dirty, WAL-stamped page) are always staged.
        //
        // SLOT-REUSE-AFTER-DURABLE INVARIANT (`rmp` #411): the doublewrite area holds ONE batch
        // region, so the staged copy of THIS page must remain the region's occupant until this page's
        // home write is DURABLY complete — otherwise a concurrent evictor reuses the region and a torn
        // home write of this page becomes unrecoverable. We therefore do the home write **inside** the
        // stager's `stage_and_sync` callback: the stager holds its interior DWB lock across the staging
        // fsync AND the home write below, so the region is not freed for reuse until this page is
        // durable home. The callback writes the page home and `sync_data`s the home device (making the
        // evicted page durable) before returning. `write_page`/`sync_data` are `&mut D`, taking the
        // device **write** guard (exclusive): write-backs serialise against each other and against
        // concurrent device reads — correct, the WAL rule above and the exclusive guard keep the
        // steal/no-force ordering intact. Lock order is uniformly frame-latch → DWB → device (the
        // checkpoint path stages under held frame latches then takes the device only after releasing
        // the DWB lock, so nothing ever takes device-then-DWB — no ABBA deadlock, `rmp` #407).
        if !allow_unlogged && let Some(stager) = self.page_stager() {
            // Borrow only the immutable parts the callback needs (`&meta.data` + `self`), so the
            // closure's borrow of `meta` ends when `stage_and_sync` returns and we can clear the dirty
            // flag afterwards.
            let data: &Page = &meta.data;
            {
                let mut home_write = || -> Result<()> {
                    // The exclusive device guard is now held for the `pwrite` ALONE (`rmp` #974).
                    // It used to span the `fdatasync` too, and that barrier — measured at 98 % of
                    // the hold — is exactly what every concurrent cache-miss `read_page` queued
                    // behind, since it needs a *shared* guard on this same lock.
                    #[cfg(feature = "bufpool-probe")]
                    let wait_start = std::time::Instant::now();
                    {
                        let mut device = self.write_device();
                        #[cfg(feature = "bufpool-probe")]
                        let hold_start = {
                            let now = std::time::Instant::now();
                            self.probe.record_device_write_wait(
                                now.duration_since(wait_start).as_nanos() as u64,
                            );
                            now
                        };
                        let r = device.write_page(page_id, data);
                        drop(device);
                        #[cfg(feature = "bufpool-probe")]
                        self.probe
                            .record_device_write_guard(hold_start.elapsed().as_nanos() as u64);
                        r?;
                    }
                    // Make the evicted home page durable BEFORE the stager releases the DWB region:
                    // only a durable home write may free the slot for reuse (`rmp` #411). The
                    // barrier goes through the device's shared handle, so it holds NO device guard —
                    // concurrent readers and other evictors' home writes proceed in parallel with
                    // it. Ordering is preserved: our `write_page` above has already returned, so the
                    // bytes are submitted before the barrier is issued, and a barrier is never
                    // scoped to one page (a concurrent writer's bytes merely get flushed too).
                    #[cfg(feature = "bufpool-probe")]
                    let sync_start = std::time::Instant::now();
                    let r = self.barrier_sync_data();
                    #[cfg(feature = "bufpool-probe")]
                    self.probe
                        .record_home_sync(sync_start.elapsed().as_nanos() as u64);
                    r
                };
                stager.stage_and_sync(page_id, &data[..], &mut home_write)?;
            }
            meta.dirty = false;
            return Ok(());
        }
        // Unprotected path (no stager installed, or an `allow_unlogged` seed write): no doublewrite
        // region to coordinate, so the home write happens directly. `write_page` is `&mut D`, taking
        // the device **write** guard (exclusive): write-backs serialise against each other and against
        // concurrent device reads — correct, the WAL rule above keeps the steal/no-force ordering.
        self.write_device().write_page(page_id, &meta.data)?;
        meta.dirty = false;
        Ok(())
    }

    /// Enforces the WAL-before-data (steal/no-force) home-write invariant as a **release-built**
    /// check (`rmp` #396): a dirty page carrying a logged change must hold a non-zero `page_lsn` so
    /// that [`ensure_durable`](Self::ensure_durable) actually waits for its redo record before the
    /// bytes are written home. Returns an error (never a `debug_assert`, which compiles out in
    /// release) when a logged-but-unstamped page would otherwise be written home, so a caller
    /// mistake degrades to a hard failure instead of a silent durability hole.
    ///
    /// The sole legitimate `page_lsn == 0` path is `allow_unlogged` (a freshly-allocated,
    /// not-yet-logged page seeded with a valid checksum via [`flush_unlogged`]), which by contract
    /// has nothing in the WAL that must precede it.
    ///
    /// # Errors
    /// Returns [`GraphusError::Storage`] if the page is logged (the WAL tracks LSNs) yet carries
    /// `page_lsn == 0` and `allow_unlogged` is not set.
    fn guard_wal_before_data(&self, page_id: PageId, lsn: Lsn, allow_unlogged: bool) -> Result<()> {
        // `tracks_lsn` is read from the value cached at construction (`rmp` #974) rather than
        // through the WAL mutex: it is a static property of the rule, and this check runs on the
        // home-write path with a frame latch held — in the batch paths, with *every* dirty frame's
        // latch held. Taking the WAL mutex there was a needless edge into the latched region.
        if allow_unlogged || lsn.0 != 0 || !self.wal_tracks_lsn {
            return Ok(());
        }
        Err(GraphusError::Storage(format!(
            "dirty page {} written back with page_lsn 0 under a real WAL: its mutation did not \
             stamp page_lsn (use with_page_mut_lsn) — WAL-before-data would be violated",
            page_id.0
        )))
    }

    // --- WAL-before-data, hoisted out of the frame latch (`rmp` #974) -------------------------
    //
    // NOTE: the pool has exactly ONE entry point that can harden the log — [`harden_wal`] — and it
    // asserts that no frame latch is held. There is deliberately no other `ensure_durable` wrapper:
    // its absence is what makes "the pool never syncs the WAL under a latch" a property of the type,
    // checkable by reading the call graph, rather than a convention.
    //
    // The rule is unchanged and absolute: a dirty page's `page_lsn` must be durable in the log
    // *before* its bytes reach their home location. What changed is **where** the `fdatasync` that
    // makes it so is issued. It used to run inside `write_back`, under the victim frame's write
    // latch, chaining *frame latch → WAL mutex → fdatasync* — and because that mutex is the same one
    // the store's commit path takes, one eviction's sync convoyed every other evictor and every
    // concurrent commit. Now the decision and the sync are split:
    //
    //   * `wal_covers` answers "already durable?" **lock-free**, from the `wal_durable` mirror;
    //   * `harden_wal` performs the sync, and is only ever called with **no frame latch held**;
    //   * the home-write path only ever *verifies* coverage and refuses to write home without it.
    //
    // The verification is fail-closed: a page that reaches the home write uncovered is a caller
    // protocol violation and returns an error rather than being written home, so the invariant
    // cannot degrade into a silent durability hole.

    /// Whether the log is known durable through `lsn`, answered **lock-free** from the cached
    /// frontier.
    ///
    /// Mirrors `WalManager::ensure_durable`'s own predicate exactly: that method hardens when
    /// `durable_len() <= up_to.0`, so "already durable" is the strict `durable_len() > lsn.0`.
    /// A `false` here may be stale-low (see [`Self::wal_durable`]) — conservative, never unsafe.
    #[inline]
    fn wal_covers(&self, lsn: Lsn) -> bool {
        !self.wal_tracks_lsn || self.wal_durable.load(Ordering::Acquire) > lsn.0
    }

    /// Publishes an observed durable frontier into the lock-free mirror, keeping it monotonic.
    #[inline]
    fn publish_wal_durable(&self, observed: u64) {
        self.wal_durable.fetch_max(observed, Ordering::Release);
    }

    /// Refreshes the cached frontier from the rule and re-answers
    /// [`wal_covers`](Self::wal_covers). **Never** issues a durability barrier.
    ///
    /// # Contract: no frame latch, no shard lock
    ///
    /// This acquires the WAL lock **blocking**, so it must be called holding neither. That is not a
    /// theoretical restriction. `self.wal` is a `Mutex<W>` around the *rule object*, not around the
    /// log: the production rule (`graphus_storage::SharedWal`) holds the real `WalManager` behind
    /// its own `Arc<Mutex<…>>`, and `durable_len` takes *that* lock unconditionally. A `try_lock` on
    /// the outer wrapper therefore proves nothing about whether this call blocks — it can still park
    /// behind a commit that is holding the manager across an `fdatasync`. Calling it from inside the
    /// victim sweep would have re-created exactly the convoy `rmp` #974 removed, one lock deeper,
    /// and would have added a `shard → WAL` wait edge the lock-order proof does not permit.
    ///
    /// The sweep therefore consults only the lock-free mirror and declines the victim when it reads
    /// stale-low; this refresh runs on the hoist path, where nothing is held.
    fn wal_covers_after_refresh(&self, lsn: Lsn) -> bool {
        if self.wal_covers(lsn) {
            return true;
        }
        debug_assert_eq!(
            graphus_core::latch::frame_latch_depth(),
            0,
            "wal_covers_after_refresh takes the WAL lock blocking and must never run with a frame \
             latch held (`rmp` #974)"
        );
        let observed = unwrap_lock(self.wal.lock()).durable_len();
        self.publish_wal_durable(observed);
        observed > lsn.0
    }

    /// Hardens the log through `up_to` and republishes the cached frontier.
    ///
    /// # Contract
    /// The caller MUST hold **no frame latch**. This is the method that can issue an `fdatasync`,
    /// and hoisting it out of the latched region is the whole point of `rmp` #974; the WAL's own
    /// `harden` asserts the property in debug builds via [`graphus_core::latch`].
    ///
    /// # Errors
    /// Propagates a WAL-rule failure.
    /// # Watermark publication
    ///
    /// On success the mirror is advanced to the frontier the rule reports through
    /// [`WalRule::durable_len`] — and to *nothing else*. That value is an observation of the log,
    /// taken under the WAL lock, so it can never overstate durability.
    ///
    /// In particular the mirror is **never** advanced to `up_to + 1`, even though a successful
    /// `ensure_durable(up_to)` does imply the log is durable through `up_to`. `up_to` is a page's
    /// `page_lsn` — data read out of a frame, not an observation of the log — and the mirror is
    /// pool-wide and monotone. Folding page-derived data into it would mean one page carrying a
    /// too-high `page_lsn` (a restored/PITR-truncated image, a mis-stamped write) permanently
    /// certifying WAL-before-data for *every* page with a lower LSN. Keeping the mirror sourced
    /// purely from the log confines any such page to being wrong about itself.
    fn harden_wal(&self, up_to: Lsn) -> Result<()> {
        debug_assert_eq!(
            graphus_core::latch::frame_latch_depth(),
            0,
            "harden_wal must never run with a frame latch held (`rmp` #974)"
        );
        #[cfg(feature = "bufpool-probe")]
        let start = std::time::Instant::now();
        let mut wal = unwrap_lock(self.wal.lock());
        let r = wal.ensure_durable(up_to);
        // The rule's reported frontier is the only thing published (see the doc above). Reading it
        // after a FAILED harden is still correct and useful: it reports what is durable now, which
        // is simply less than the caller asked for.
        let observed = wal.durable_len();
        drop(wal);
        #[cfg(feature = "bufpool-probe")]
        self.probe
            .record_wal_ensure(start.elapsed().as_nanos() as u64);
        self.publish_wal_durable(observed);
        r
    }

    /// Verifies WAL-before-data for a page about to be written home, **without** ever syncing.
    ///
    /// # Errors
    /// Returns a storage error when the log is not durable through `lsn`. That is a caller protocol
    /// violation — every home-write path hoists its harden first — and failing closed here keeps the
    /// invariant intact instead of writing data ahead of its log.
    fn assert_wal_covers(&self, page_id: PageId, lsn: Lsn) -> Result<()> {
        if self.wal_covers(lsn) {
            #[cfg(feature = "bufpool-probe")]
            self.probe.record_wal_already_durable();
            return Ok(());
        }
        Err(GraphusError::Storage(format!(
            "WAL-before-data: page {} (page_lsn {}) reached the home write before the log was \
             hardened through it (durable frontier {}). The home-write paths must hoist the harden \
             out of the frame latch first (`rmp` #974); writing the page home here would put data \
             ahead of its redo record",
            page_id.0,
            lsn.0,
            self.wal_durable.load(Ordering::Acquire)
        )))
    }

    // --- Device durability barriers, issued off the device lock (`rmp` #974) -------------------

    /// Issues the home-file data barrier, preferring the device's shared [`graphus_io::SyncHandle`]
    /// so **no device guard is held** for the duration.
    ///
    /// This is the measured lever of `rmp` #974: the barrier used to run under the pool's
    /// **exclusive** device guard, which is the very lock every concurrent cache-miss `read_page`
    /// needs in *shared* mode, and 98 % of each exclusive hold was the barrier itself. Issuing it
    /// through a duplicated descriptor keeps the identical durability guarantee (the kernel flushes
    /// the file, not a per-descriptor view) while letting concurrent readers — and other evictors'
    /// home writes — run in parallel with it.
    ///
    /// Falls back to the guarded `&mut` path for a device that offers no handle, so behaviour is
    /// unchanged there.
    ///
    /// # Errors
    /// Propagates the barrier failure.
    fn barrier_sync_data(&self) -> Result<()> {
        match &self.sync_handle {
            Some(h) => h.sync_data(),
            None => self.write_device().sync_data(),
        }
    }

    /// Issues the full (data + metadata) barrier, preferring the shared handle. See
    /// [`barrier_sync_data`](Self::barrier_sync_data).
    ///
    /// # Errors
    /// Propagates the barrier failure.
    fn barrier_sync_all(&self) -> Result<()> {
        match &self.sync_handle {
            Some(h) => h.sync_all(),
            None => self.write_device().sync_all(),
        }
    }
}

/// A selected eviction victim: the frame index and its held write latch. Dropping it releases
/// the latch.
struct Victim<'a> {
    idx: usize,
    guard: RwLockWriteGuard<'a, FrameMeta>,
    /// The frame-latch tripwire (`rmp` #974), armed for exactly as long as the latch is held.
    ///
    /// Declared **after** `guard` so Rust's field drop order (declaration order) releases the latch
    /// first and disarms the tripwire second — the scope therefore covers the entire window in which
    /// this thread holds the victim's latch, which is the whole of
    /// `select_victim` → `load_into` → `evict_held` → `write_back`.
    _latch: graphus_core::latch::FrameLatchScope,
}

/// The dirty frames of one batch flush, with their write latches held.
///
/// A named type rather than a bare `Vec` so the frame-latch tripwire (`rmp` #974) is armed for
/// exactly as long as the latches are: the fields drop in declaration order, so the guards are
/// released first and the scope disarmed second.
struct FlushBatch<'a> {
    guards: Vec<(usize, RwLockWriteGuard<'a, FrameMeta>)>,
    _latch: graphus_core::latch::FrameLatchScope,
}

impl<'a> FlushBatch<'a> {
    /// Latches every dirty frame the batch selects: all of them when `want` is `None`
    /// ([`ConcurrentBufferPool::flush_all`]), otherwise those whose home page id is in `want`
    /// ([`ConcurrentBufferPool::flush_pages`]). Clean and unselected frames are released
    /// immediately.
    fn collect<D: BlockDevice, W: WalRule>(
        pool: &'a ConcurrentBufferPool<D, W>,
        want: Option<&rustc_hash::FxHashSet<u64>>,
    ) -> Self {
        let latch = graphus_core::latch::FrameLatchScope::new();
        let mut guards: Vec<(usize, RwLockWriteGuard<'a, FrameMeta>)> = Vec::new();
        for (idx, slot) in pool.frames.iter().enumerate() {
            let meta = unwrap_lock(slot.meta.write());
            let selected = meta.dirty
                && match want {
                    None => true,
                    Some(w) => meta.page_id.is_some_and(|p| w.contains(&p.0)),
                };
            if selected {
                guards.push((idx, meta));
            }
        }
        Self {
            guards,
            _latch: latch,
        }
    }
}

/// An RAII guard that owns one frame **pin** and releases it (via
/// [`ConcurrentBufferPool::unpin`]) exactly once when it drops — on the normal return, on any early
/// `?`/`return`, AND on **unwind** if a visit closure passed to
/// [`with_page`](ConcurrentBufferPool::with_page) /
/// [`with_page_fetched`](ConcurrentBufferPool::with_page_fetched) **panics** (`rmp` #594).
///
/// # Why this exists (panic-safety of the pin → visit → unpin window)
///
/// The hot read paths pin a frame (`pin_count.fetch_add(1, Acquire)`), run a caller closure over the
/// page bytes under the frame's read latch, then `unpin`. If that closure panics, the *latch* (a
/// `parking_lot`/`std` guard) is released as the stack unwinds, but a bare `self.unpin(f)` written
/// *after* the closure is **never reached** — the pin is stranded forever, the frame permanently
/// unevictable. One stranded frame per panic is enough to eventually turn
/// [`select_victim`](ConcurrentBufferPool::select_victim) into an `AllPinned`/`Contended` backoff
/// storm and finally the "could not reserve a victim" error — a latent availability cliff. Routing the
/// pin through this guard makes the matching `unpin` run on *every* exit path, so a panicking closure
/// leaves the pin count **exactly balanced** (the frame stays evictable). The guard owns no resource
/// other than the logical pin, so its `Drop` is just the one `unpin` — no measurable per-hit cost.
///
/// # Ordering (hit path)
///
/// On the `with_page_fetched` hit path the read latch MUST be released before the `unpin` (`rmp` #337
/// Slice 1). The guard is therefore constructed **before** the latch is taken: Rust drops locals in
/// reverse declaration order, so on scope exit (normal or unwinding) the later-declared latch drops
/// first and this earlier-declared guard (the `unpin`) drops second — preserving the historical
/// latch-before-unpin discipline with no second latch acquisition.
#[must_use = "a PinGuard must be held until the pin should be released; dropping it early unpins the frame"]
struct PinGuard<'a, D: BlockDevice, W: WalRule> {
    pool: &'a ConcurrentBufferPool<D, W>,
    frame: PinnedFrame,
}

impl<D: BlockDevice, W: WalRule> Drop for PinGuard<'_, D, W> {
    fn drop(&mut self) {
        // The sole action: release the pin this guard owns. `unpin` is a saturating `Release`
        // decrement, balanced against the caller's `fetch_add(1)` exactly once — the strictly-additive
        // pin invariant the whole eviction protocol relies on.
        self.pool.unpin(self.frame);
    }
}

/// The outcome of one bounded [`ConcurrentBufferPool::select_victim`] sweep. Separating the two
/// failure modes is the crux of the `rmp` #359 read-integrity fix: a transient contention must
/// **retry** (with backoff), never surface as an error — collapsing it into the genuine-capacity case
/// produced a spurious `Err` that the read-view chain swallowed into `Value::Null` / a truncated
/// chain (a wrong query result, seen only under eviction).
enum VictimChoice<'a> {
    /// An evictable victim, with its write latch already held.
    Found(Victim<'a>),
    /// **Every** frame examined this sweep was pinned. A *single* such snapshot is still **transient**
    /// (the lone free frame pinned by a peer loader in the instant between its load-publish and the
    /// caller's unpin), so the caller backs off and retries — erroring on one occurrence is the exact
    /// `rmp` #359/#339 read-integrity regression. Only a **sustained** run of `PERSISTENT_ALL_PINNED_SWEEPS`
    /// consecutive `AllPinned` sweeps with no interleaved progress — the genuine "buffer pool full of
    /// pinned pages" capacity limit, or a caller pin-leak — trips the clear error (`rmp` #594 D-#4), since
    /// no further retry can conjure a victim. (Instrumentation: `AllPinned` is observed **zero** times
    /// under a concurrent-reader eviction storm with readers < frames; a persistent run indicates a real
    /// pin-leak / capacity wall, not normal pressure.)
    AllPinned,
    /// At least one frame was **unpinned** but could not be taken this sweep (its write latch was
    /// momentarily held by a concurrent reader/loader, or it was given a CLOCK second chance).
    /// **Transient**: an unpinned frame is an evictable victim whose latch frees in microseconds, so
    /// the caller MUST retry (after dropping its shard lock and backing off), never error.
    Contended,
    /// An evictable victim was found but it is **dirty with a `page_lsn` the log is not yet durable
    /// through**, so writing it home would need a WAL harden — and the sweep already holds its latch
    /// (`rmp` #974). The victim's latch has been **released**; the caller must drop its shard lock,
    /// call [`ConcurrentBufferPool::harden_wal`] with nothing held, and re-sweep.
    ///
    /// This is the hoist: it converts "sync while latched" into "release, sync, retry", so the
    /// `fdatasync` — and the WAL mutex the store's commit path shares — is never taken inside a
    /// latched region. Always **transient**: one harden covers the whole appended log, so the very
    /// next sweep finds the same (or any other) dirty victim already covered.
    NeedsWalHarden(Lsn),
}

/// Acquires a latch/mutex guard, **recovering it even if a prior holder panicked** (storage audit
/// F14). A poisoned latch must not permanently wedge a frame (every later access would panic, an
/// availability failure under extreme load): the protected state is just page bytes + a dirty flag,
/// and the WAL provides durability/recovery for any change a panicking mutation left partial, so the
/// guard is taken via [`PoisonError::into_inner`] rather than re-panicking.
fn unwrap_lock<G>(r: std::result::Result<G, std::sync::PoisonError<G>>) -> G {
    r.unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Eviction-diagnostics probe (`rmp` #359, `bufpool-probe` feature only). A small set of atomic
/// counters a fast runtime repro reads to MEASURE the precise mechanism of a spurious-fetch-error /
/// wrong-bytes bug under an eviction storm, instead of guessing at it. The whole module is compiled
/// out of the production build.
#[cfg(feature = "bufpool-probe")]
pub mod probe {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Per-pool diagnostics counters.
    #[derive(Default)]
    pub struct Probe {
        /// `select_victim` came up empty with **every** examined frame pinned (genuine capacity).
        all_pinned: AtomicU64,
        /// `select_victim` came up empty although ≥1 frame was unpinned (transient latch contention).
        contended: AtomicU64,
        /// The **maximum** number of retry iterations any single `fetch`/`new_page` call has taken to
        /// resolve. Small ⇒ the backoff drains contention fast (no live-lock); near
        /// `MAX_FETCH_RETRIES` ⇒ a near-wedge. The whole point of the `rmp` #359 fix is to keep this
        /// small even under an eviction storm.
        max_retry_iters: AtomicU64,

        // ---- Write-back durability timers (`rmp` #974) ----
        //
        // The eviction write-back path performs up to three `fdatasync`s (WAL, doublewrite area,
        // home file). These counters attribute where that time goes and, crucially, how much of it a
        // *reader* pays for: `device_read_wait_nanos` is the time a cache-miss read spent blocked
        // acquiring the device read guard, which is exactly the convoy a concurrent reader suffers
        // when an unrelated thread is fsyncing under the exclusive device guard.
        /// Number of dirty write-backs performed (the eviction/flush home-write path).
        write_backs: AtomicU64,
        /// Total nanoseconds spent in the dirty branch of `write_back` (whole home-write path).
        write_back_nanos: AtomicU64,
        /// Number of `ensure_durable` (WAL-before-data harden) calls made from a write-back.
        wal_ensure_calls: AtomicU64,
        /// Total nanoseconds spent inside `ensure_durable` — WAL mutex acquisition **plus** the
        /// `fdatasync` it performs.
        wal_ensure_nanos: AtomicU64,
        /// Total nanoseconds a write-back **held** the exclusive device write guard. Every
        /// nanosecond here blocks every concurrent cache-miss device read.
        device_write_guard_nanos: AtomicU64,
        /// Total nanoseconds a write-back spent **waiting** to acquire the exclusive device write
        /// guard (queued behind another thread's home write).
        device_write_wait_nanos: AtomicU64,
        /// Total nanoseconds spent in the home-file `sync_data` itself, and how many were issued.
        home_sync_nanos: AtomicU64,
        home_syncs: AtomicU64,
        /// Number of cache-miss device reads (`load_into`).
        device_read_waits: AtomicU64,
        /// Total nanoseconds cache-miss reads spent **waiting** to acquire the device read guard.
        device_read_wait_nanos: AtomicU64,
        /// Number of times a write-back completed with the WAL already durable through the page's
        /// LSN, so no `fdatasync` was needed under the frame latch. Large relative to `write_backs`
        /// ⇒ the pre-harden is doing its job.
        wal_already_durable: AtomicU64,
    }

    impl Probe {
        /// Adds `nanos` to `counter` and bumps `calls` by one, both relaxed (pure diagnostics).
        #[inline]
        fn add(counter: &AtomicU64, calls: &AtomicU64, nanos: u64) {
            counter.fetch_add(nanos, Ordering::Relaxed);
            calls.fetch_add(1, Ordering::Relaxed);
        }

        /// Records one dirty `write_back` taking `nanos`.
        #[inline]
        pub(crate) fn record_write_back(&self, nanos: u64) {
            Self::add(&self.write_back_nanos, &self.write_backs, nanos);
        }

        /// Records one `ensure_durable` call from a write-back taking `nanos`.
        #[inline]
        pub(crate) fn record_wal_ensure(&self, nanos: u64) {
            Self::add(&self.wal_ensure_nanos, &self.wal_ensure_calls, nanos);
        }

        /// Records one write-back that needed no harden (the WAL was already durable through the
        /// page's LSN when the frame latch was taken).
        #[inline]
        pub(crate) fn record_wal_already_durable(&self) {
            self.wal_already_durable.fetch_add(1, Ordering::Relaxed);
        }

        /// Records `nanos` spent holding the exclusive device write guard on a home write.
        #[inline]
        pub(crate) fn record_device_write_guard(&self, nanos: u64) {
            self.device_write_guard_nanos
                .fetch_add(nanos, Ordering::Relaxed);
        }

        /// Records `nanos` spent waiting to acquire the exclusive device write guard.
        #[inline]
        pub(crate) fn record_device_write_wait(&self, nanos: u64) {
            self.device_write_wait_nanos
                .fetch_add(nanos, Ordering::Relaxed);
        }

        /// Records one home-file `sync_data` taking `nanos`.
        #[inline]
        pub(crate) fn record_home_sync(&self, nanos: u64) {
            Self::add(&self.home_sync_nanos, &self.home_syncs, nanos);
        }

        /// Records one cache-miss device read that waited `nanos` for the device read guard.
        #[inline]
        pub(crate) fn record_device_read_wait(&self, nanos: u64) {
            Self::add(&self.device_read_wait_nanos, &self.device_read_waits, nanos);
        }

        /// Records one empty `select_victim` sweep, classified by whether every frame was pinned.
        #[inline]
        pub(crate) fn record_victim_miss(&self, all_pinned: bool) {
            if all_pinned {
                self.all_pinned.fetch_add(1, Ordering::Relaxed);
            } else {
                self.contended.fetch_add(1, Ordering::Relaxed);
            }
        }

        /// Records that a `fetch`/`new_page` resolved after `iters` retry iterations, keeping the
        /// running maximum (a lock-free monotonic max).
        #[inline]
        pub(crate) fn record_retry_iters(&self, iters: u64) {
            let mut cur = self.max_retry_iters.load(Ordering::Relaxed);
            while iters > cur {
                match self.max_retry_iters.compare_exchange_weak(
                    cur,
                    iters,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(observed) => cur = observed,
                }
            }
        }

        pub(crate) fn all_pinned(&self) -> u64 {
            self.all_pinned.load(Ordering::Relaxed)
        }

        pub(crate) fn contended(&self) -> u64 {
            self.contended.load(Ordering::Relaxed)
        }

        pub(crate) fn max_retry_iters(&self) -> u64 {
            self.max_retry_iters.load(Ordering::Relaxed)
        }

        pub(crate) fn snapshot_write_back(&self) -> WriteBackProbe {
            WriteBackProbe {
                write_backs: self.write_backs.load(Ordering::Relaxed),
                write_back_nanos: self.write_back_nanos.load(Ordering::Relaxed),
                wal_ensure_calls: self.wal_ensure_calls.load(Ordering::Relaxed),
                wal_ensure_nanos: self.wal_ensure_nanos.load(Ordering::Relaxed),
                wal_already_durable: self.wal_already_durable.load(Ordering::Relaxed),
                device_write_guard_nanos: self.device_write_guard_nanos.load(Ordering::Relaxed),
                device_write_wait_nanos: self.device_write_wait_nanos.load(Ordering::Relaxed),
                home_syncs: self.home_syncs.load(Ordering::Relaxed),
                home_sync_nanos: self.home_sync_nanos.load(Ordering::Relaxed),
                device_read_waits: self.device_read_waits.load(Ordering::Relaxed),
                device_read_wait_nanos: self.device_read_wait_nanos.load(Ordering::Relaxed),
            }
        }
    }

    /// The write-back durability timers (`rmp` #974). All times are wall-clock nanoseconds summed
    /// across every thread, so a figure may exceed the elapsed wall time of the run.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct WriteBackProbe {
        /// Dirty write-backs performed.
        pub write_backs: u64,
        /// Total time in the dirty branch of `write_back`.
        pub write_back_nanos: u64,
        /// `ensure_durable` calls made **while a frame latch was held**.
        pub wal_ensure_calls: u64,
        /// Total time in `ensure_durable` (WAL mutex + `fdatasync`).
        pub wal_ensure_nanos: u64,
        /// Write-backs that found the WAL already durable through the page LSN (no harden needed).
        pub wal_already_durable: u64,
        /// Total time the **exclusive** device write guard was held on the home-write path.
        pub device_write_guard_nanos: u64,
        /// Total time write-backs spent queued waiting for the exclusive device write guard.
        pub device_write_wait_nanos: u64,
        /// Home-file `sync_data` calls issued by the write-back path.
        pub home_syncs: u64,
        /// Total time in the home-file `sync_data` itself.
        pub home_sync_nanos: u64,
        /// Cache-miss device reads performed.
        pub device_read_waits: u64,
        /// Total time cache-miss reads spent waiting for the device **read** guard — the convoy a
        /// concurrent reader pays when another thread fsyncs under the exclusive device guard.
        pub device_read_wait_nanos: u64,
    }

    /// A snapshot of the probe counters, returned by [`super::ConcurrentBufferPool::probe_snapshot`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ProbeSnapshot {
        /// Empty sweeps where every frame was genuinely pinned (true capacity exhaustion).
        pub victim_miss_all_pinned: u64,
        /// Empty sweeps where an unpinned frame existed but could not be latched this pass
        /// (transient contention — a victim is about to become available).
        pub victim_miss_contended: u64,
        /// The maximum retry-iteration depth any single `fetch`/`new_page` reached. Small ⇒ the
        /// backoff converges fast; near the retry bound ⇒ a near-wedge / live-lock.
        pub max_retry_iters: u64,
    }
}

// The behavioural tests below run under the *normal* `cargo test` gate (no loom). They mirror the
// single-threaded pool's tests through the concurrent type, and add a real multi-threaded stress
// test as the runtime complement to loom's exhaustive model checking. They use std primitives
// (loom replaces those only under `--cfg loom`).
#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use graphus_core::Lsn;
    use graphus_io::MemBlockDevice;
    use std::sync::atomic::{AtomicU64, Ordering as StdOrdering};
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use std::thread;

    fn pool(cap: usize) -> ConcurrentBufferPool<MemBlockDevice> {
        ConcurrentBufferPool::new(MemBlockDevice::new(0), cap)
    }

    /// A [`WalRule`] that records the highest LSN it was asked to harden and reports `tracks_lsn`
    /// like a real WAL — so a write-back's WAL-rule call can be observed.
    #[derive(Default)]
    struct RecordingWal {
        max_hardened: u64,
    }
    impl WalRule for RecordingWal {
        fn ensure_durable(&mut self, up_to: Lsn) -> Result<()> {
            self.max_hardened = self.max_hardened.max(up_to.0);
            Ok(())
        }
        /// Everything asked for is hardened immediately, so the frontier is past every LSN handed
        /// to this rule; reporting the recorded high-water + 1 mirrors that exactly.
        fn durable_len(&mut self) -> u64 {
            self.max_hardened.saturating_add(1)
        }
    }

    /// F6: a write-back hardens the page's **stamped** redo LSN (via `with_page_mut_lsn`), not `0` —
    /// proving the WAL-before-data rule sees the real LSN once the concurrent pool backs a real WAL.
    #[test]
    fn write_back_hardens_the_stamped_lsn() {
        let p = ConcurrentBufferPool::with_wal(MemBlockDevice::new(0), RecordingWal::default(), 2);
        let (f, _id) = p.new_page().unwrap();
        // Write into the page BODY (offset >= HEADER_SIZE); the page_lsn header lives at offset 8.
        p.with_page_mut_lsn(f, Lsn(4242), |page| page[100] = 0x7);
        p.unpin(f);
        p.flush_all().unwrap();
        assert_eq!(
            p.wal.lock().unwrap().max_hardened,
            4242,
            "write-back must harden the mutation's stamped LSN, not 0"
        );
    }

    /// `rmp` #396: the WAL-before-data home-write guard is enforced in **release** builds. A
    /// logged-but-unstamped dirty page (dirtied via `with_page_mut`, which never stamps `page_lsn`)
    /// under a real WAL must make `write_back` / `flush_all` / `flush_pages` return an `Err` rather
    /// than write home — closing the silent-durability-hole window that a `debug_assert` (compiled
    /// out in release) left open.
    #[test]
    fn logged_but_unstamped_dirty_page_is_rejected_on_home_write() {
        // `RecordingWal` reports `tracks_lsn() == true` (a real WAL), so a `page_lsn == 0` dirty
        // page is the illegal logged-but-unstamped case the guard must reject.
        let p = ConcurrentBufferPool::with_wal(MemBlockDevice::new(0), RecordingWal::default(), 2);
        let (f, _id) = p.new_page().unwrap();
        // Dirty the page WITHOUT stamping `page_lsn` (the caller-mistake this guard catches).
        p.with_page_mut(f, |page| page[100] = 0x7);

        // write_back (held-latch core) must fail closed, not write home.
        {
            let slot = p.slot(f);
            let mut meta = slot.meta.write().unwrap();
            let err = p.write_back(&mut meta, false);
            assert!(
                err.is_err(),
                "write_back of a logged-but-unstamped dirty page must return Err"
            );
            assert!(
                meta.dirty,
                "a rejected page must stay dirty (never written home)"
            );
        }

        // flush_all (batch, all dirty) must fail closed.
        assert!(
            p.flush_all().is_err(),
            "flush_all of a logged-but-unstamped dirty page must return Err"
        );
        // flush_pages (targeted batch) must fail closed.
        assert!(
            p.flush_pages(&[_id]).is_err(),
            "flush_pages of a logged-but-unstamped dirty page must return Err"
        );
        assert_eq!(
            p.dirty_frames(),
            1,
            "the rejected page must remain dirty after every failed home-write"
        );
        assert_eq!(
            p.wal.lock().unwrap().max_hardened,
            0,
            "the guard must trip BEFORE ensure_durable — no LSN was hardened"
        );
        p.unpin(f);
    }

    /// `rmp` #396: the `allow_unlogged` seed path (a freshly-allocated, not-yet-logged page with a
    /// valid checksum) is the one legitimate `page_lsn == 0` write-back and must still succeed under
    /// a real WAL — the guard must not over-reject.
    #[test]
    fn allow_unlogged_seed_write_back_still_succeeds() {
        let p = ConcurrentBufferPool::with_wal(MemBlockDevice::new(0), RecordingWal::default(), 2);
        let (f, _id) = p.new_page().unwrap();
        p.with_page_mut(f, |page| page[100] = 0x7);
        {
            let slot = p.slot(f);
            let mut meta = slot.meta.write().unwrap();
            p.write_back(&mut meta, true)
                .expect("allow_unlogged write-back of an unstamped page must succeed");
            assert!(!meta.dirty, "a successful write-back clears the dirty flag");
        }
        p.unpin(f);
    }

    /// F14: a panic inside a `with_page_mut` closure must not permanently wedge the frame — the
    /// poisoned latch is recovered and the pool stays usable.
    #[test]
    fn a_panicking_mutation_does_not_wedge_the_pool() {
        let p = pool(2);
        let (f, _id) = p.new_page().unwrap();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            p.with_page_mut(f, |_page| panic!("boom in mutation"));
        }));
        assert!(panicked.is_err(), "the mutation closure panicked");
        // The frame is still usable (latch recovered from poison, not wedged).
        p.with_page_mut(f, |page| page[5] = 0x9);
        assert_eq!(
            p.with_page(f, |page| page[5]),
            0x9,
            "the frame must be usable after a panicked mutation"
        );
        p.unpin(f);
        p.flush_all().unwrap();
    }

    /// F12: a page re-dirtied after a `flush_all` is tracked as dirty again (not lost) and a later
    /// `flush_all` clears it — the documented no-loss property of the non-barrier flush.
    #[test]
    fn a_redirtied_page_is_preserved_and_flushed_later() {
        let p = pool(2);
        let (f, _id) = p.new_page().unwrap();
        p.with_page_mut(f, |page| page[0] = 1);
        p.flush_all().unwrap();
        assert_eq!(p.dirty_frames(), 0, "first flush clears the dirty page");
        // Re-dirty after the flush: it must be tracked again, so a later flush persists it.
        p.with_page_mut(f, |page| page[0] = 2);
        assert_eq!(
            p.dirty_frames(),
            1,
            "a re-dirtied page is dirty again, never silently lost"
        );
        p.flush_all().unwrap();
        assert_eq!(
            p.dirty_frames(),
            0,
            "the later flush captures the re-dirtied page"
        );
        p.unpin(f);
    }

    #[test]
    fn new_page_is_cached_and_readable() {
        let p = pool(4);
        let (f, id) = p.new_page().unwrap();
        p.with_page_mut(f, |page| page[100] = 0xAA);
        p.unpin(f);
        let g = p.fetch(id).unwrap();
        assert_eq!(p.with_page(g, |page| page[100]), 0xAA);
        p.unpin(g);
    }

    /// `rmp` #337: the combined read fast path reads a resident page correctly, leaves no pin, and
    /// (on a miss) loads then reads via the fallback — matching `fetch` + `with_page` + `unpin`.
    #[test]
    fn with_page_fetched_reads_resident_and_loads_on_miss() {
        let p = pool(1); // 1 frame so the second page forces an eviction + reload on the miss path.
        let (fa, a) = p.new_page().unwrap();
        p.with_page_mut(fa, |page| page[100] = 0xAA);
        p.flush(fa).unwrap();
        p.unpin(fa);

        // Hit fast path: page a is resident; read it and verify no pin leaks.
        assert_eq!(p.with_page_fetched(a, |page| page[100]).unwrap(), 0xAA);
        let again = p.fetch(a).unwrap();
        assert_eq!(p.pin_count(again), 1, "fast path must leave no pin behind");
        p.unpin(again);

        // Allocate a second page (evicts a), then with_page_fetched(a) must take the MISS fallback,
        // reload a from disk (checksum-verified), and return the right byte.
        let (fb, _b) = p.new_page().unwrap();
        p.unpin(fb);
        assert_eq!(
            p.with_page_fetched(a, |page| page[100]).unwrap(),
            0xAA,
            "miss fallback must reload the correct page"
        );
        let after = p.fetch(a).unwrap();
        assert_eq!(p.pin_count(after), 1, "miss fallback must leave no pin");
        p.unpin(after);
    }

    #[test]
    fn eviction_writes_dirty_then_reload_verifies_checksum() {
        let p = pool(1);
        let (fa, a) = p.new_page().unwrap();
        p.with_page_mut(fa, |page| page[100] = 0xAA);
        p.unpin(fa);
        let (fb, _b) = p.new_page().unwrap(); // evicts a, writing it back
        p.unpin(fb);
        let g = p.fetch(a).unwrap(); // miss -> reload, checksum verified
        assert_eq!(p.with_page(g, |page| page[100]), 0xAA);
        p.unpin(g);
    }

    /// `rmp` #594 (acceptance criterion 1): a panic **inside** a `with_page_fetched` visit closure must
    /// leave the pin count exactly balanced — the RAII [`PinGuard`] runs the matching `unpin` on unwind,
    /// so the frame stays evictable rather than being stranded permanently unevictable. Covers the HIT
    /// fast path (the panic fires under the single re-validated read latch).
    #[test]
    fn with_page_fetched_hit_panic_leaves_pin_balanced_and_frame_evictable() {
        // Cap 1 makes evictability a hard, observable property: if the panicking read stranded its pin,
        // the later `new_page` (which must evict this only frame) would spin to the persistent-all-pinned
        // bound and error. With the guard the pin is released on unwind, so the frame stays evictable.
        let p = pool(1);
        let (fa, a) = p.new_page().unwrap();
        p.with_page_mut(fa, |page| page[100] = 0xAA);
        p.flush(fa).unwrap();
        p.unpin(fa);
        assert_eq!(
            p.pin_count(fa),
            0,
            "precondition: page resident and unpinned"
        );

        // Hit fast path with a deliberately panicking visit closure.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = p.with_page_fetched(a, |_page| -> u8 { panic!("boom in hit-path visit") });
        }));
        assert!(panicked.is_err(), "the visit closure must have panicked");

        // The pin the hit path took must have been released on unwind (RAII), NOT stranded.
        assert_eq!(
            p.pin_count(fa),
            0,
            "a panicking with_page_fetched visit must leave the pin balanced (frame evictable)"
        );

        // Prove evictability directly: the frame is the pool's ONLY frame, so allocating a new page
        // must evict it. A leaked pin would instead ride the retry bound and error here.
        let (fb, _b) = p
            .new_page()
            .expect("the only frame must be evictable after the panicked read");
        p.unpin(fb);
        // And the original page (flushed before the panic) reloads intact.
        assert_eq!(p.with_page_fetched(a, |page| page[100]).unwrap(), 0xAA);
    }

    /// `rmp` #594 (acceptance criterion 1): the COLD/miss path of `with_page_fetched` is equally
    /// panic-safe — the panic fires inside `with_page` after the full `fetch`, and the guard still
    /// unpins on unwind so the reloaded frame is not stranded.
    #[test]
    fn with_page_fetched_miss_panic_leaves_pin_balanced() {
        let p = pool(1);
        let (fa, a) = p.new_page().unwrap();
        p.with_page_mut(fa, |page| page[100] = 0xAA);
        p.flush(fa).unwrap();
        p.unpin(fa);
        // Evict `a` so the next access takes the MISS fallback (fetch -> with_page -> panic).
        let (fb, _b) = p.new_page().unwrap();
        p.unpin(fb);

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = p.with_page_fetched(a, |_page| -> u8 { panic!("boom in miss-path visit") });
        }));
        assert!(panicked.is_err(), "the visit closure must have panicked");

        // The reloaded frame's pin must be balanced; the pool (cap 1) must stay evictable.
        let (fc, _c) = p
            .new_page()
            .expect("the reloaded frame must be evictable after the panicked miss read");
        p.unpin(fc);
        // Every frame is unpinned.
        for slot in &p.frames {
            assert_eq!(
                slot.pin_count.load(Ordering::Acquire),
                0,
                "a panicking miss read must leave no stranded pin"
            );
        }
    }

    /// `rmp` #594 (acceptance criterion 1): the raw `fetch` -> `with_page` -> `unpin` triple — the shape
    /// used across the codebase — is panic-safe when its pin is owned by a [`PinGuard`]. A panic in the
    /// `with_page` visit closure runs the guard's `Drop` on unwind, balancing the pin.
    #[test]
    fn pin_guard_balances_the_fetch_with_page_triple_on_panic() {
        let p = pool(2);
        let (fa, a) = p.new_page().unwrap();
        p.with_page_mut(fa, |page| page[7] = 0x5);
        p.flush(fa).unwrap();
        p.unpin(fa);

        // Call-site pattern: fetch -> (guard owns the pin) -> with_page(panicking) -> drop(guard). On
        // unwind the explicit `drop(guard)` is skipped, but the guard's `Drop` still runs the `unpin`.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let f = p.fetch(a).unwrap();
            let guard = p.pin_guard(f);
            let _ = p.with_page(f, |_page| -> u8 { panic!("boom in triple") });
            drop(guard);
        }));
        assert!(panicked.is_err(), "the visit closure must have panicked");
        assert_eq!(
            p.pin_count(fa),
            0,
            "the PinGuard must release the pin on unwind, leaving the triple balanced"
        );

        // Evictable: fill both frames with fresh pages (must evict `a`), then reload `a` intact.
        let (f1, _id1) = p.new_page().unwrap();
        let (f2, _id2) = p.new_page().unwrap();
        p.unpin(f1);
        p.unpin(f2);
        assert_eq!(p.with_page_fetched(a, |page| page[7]).unwrap(), 0x5);
    }

    /// `rmp` #594 (D-#4, regression): a fetch that needs a victim while EVERY frame is pinned for a
    /// **sustained** stretch (a genuine capacity wall / pin-leak, here the single frame pinned for the
    /// whole test) must surface the clear error via [`PERSISTENT_ALL_PINNED_SWEEPS`] and terminate —
    /// NOT spin the full 1 M budget, and NOT serve a wrong result. This exercises the fetch miss-arm's
    /// `AllPinned` branch; the transient-`Contended` #359 path keeps its full budget (proven by the
    /// `eviction_chain_repro` / loom storm tests, which never trip this because a victim always frees).
    #[test]
    fn fetch_on_a_sustained_all_pinned_pool_surfaces_the_clear_error() {
        let p = pool(1);
        // Put page 0 on disk, then evict it into disk by allocating page 1 into the single frame;
        // page 1 stays PINNED (f1 never unpinned) for the rest of the test — a sustained all-pinned.
        let (f0, p0) = p.new_page().unwrap();
        p.with_page_mut(f0, |page| page[10] = 0x1);
        p.flush(f0).unwrap();
        p.unpin(f0);
        let (_f1, _p1) = p.new_page().unwrap(); // evicts p0 (clean) to disk; p1 resident AND pinned

        // Fetch the on-disk-but-not-resident p0: it misses, finds the one frame pinned on every sweep,
        // and — because that all-pinned condition never clears — surfaces the clear D-#4 error.
        let r = p.fetch(p0);
        assert!(
            r.is_err(),
            "a fetch needing a victim in a sustained-all-pinned pool must surface the clear error, \
             not spin or return a wrong page"
        );
        let msg = format!("{}", r.unwrap_err());
        assert!(
            msg.contains("consecutive victim sweeps"),
            "the error must be the D-#4 persistent-all-pinned message, got: {msg}"
        );
    }

    #[test]
    fn a_fully_pinned_pool_cannot_evict() {
        let p = pool(1);
        let (_fa, _a) = p.new_page().unwrap(); // pinned
        assert!(p.new_page().is_err());
    }

    /// Regression (`rmp` #302): the concurrent pool must be robust at the same misconfigured tiny
    /// capacities as the single-threaded pool — {1,2,3,4}. Forcing real eviction pressure (allocate
    /// well past capacity, unpinning each so the next allocation evicts + writes back) must never
    /// panic, and every id must reload the exact bytes written before eviction. Unlike the
    /// single-threaded pool this cannot hit a `RefCell` re-entrancy (its WAL rule is behind its own
    /// `Mutex`), but it must still degrade cleanly rather than aborting mid-operation.
    #[test]
    fn tiny_concurrent_pool_evicts_and_reloads_without_panic() {
        for cap in 1..=4usize {
            let p = pool(cap); // NoWal: unlogged writes are permitted by write_back
            let mut ids = Vec::new();
            for i in 0..(cap + 3) {
                let (f, id) = p.new_page().unwrap();
                p.with_page_mut(f, |page| page[10] = i as u8);
                p.unpin(f);
                ids.push(id);
            }
            for (i, id) in ids.iter().enumerate() {
                let f = p.fetch(*id).unwrap();
                assert_eq!(
                    p.with_page(f, |page| page[10]),
                    i as u8,
                    "cap={cap}: page {id:?} must reload the exact bytes written before eviction"
                );
                p.unpin(f);
            }
        }
    }

    /// Regression (`rmp` #302): a fully **pinned** concurrent pool at every tiny capacity {1,2,3,4}
    /// must surface the clean `AllPinned` capacity error, never panic. This is the concurrent twin of
    /// `fully_pinned_tiny_pool_returns_clean_error` in the single-threaded pool.
    #[test]
    fn fully_pinned_tiny_concurrent_pool_returns_clean_error() {
        for cap in 1..=4usize {
            let p = pool(cap);
            let mut held = Vec::new();
            for _ in 0..cap {
                let (f, _id) = p.new_page().unwrap(); // left pinned
                held.push(f);
            }
            assert!(
                p.new_page().is_err(),
                "cap={cap}: a fully pinned concurrent pool must return Err, never panic"
            );
            for f in held {
                p.unpin(f);
            }
        }
    }

    #[test]
    fn fetch_hit_increments_pin_count() {
        let p = pool(4);
        let (f, id) = p.new_page().unwrap();
        assert_eq!(p.pin_count(f), 1);
        let g = p.fetch(id).unwrap(); // hit, same frame
        assert_eq!(g.index(), f.index());
        assert_eq!(p.pin_count(f), 2);
        p.unpin(f);
        assert_eq!(p.pin_count(g), 1);
        p.unpin(g);
        assert_eq!(p.pin_count(g), 0);
    }

    /// Regression: SEC-212 — an out-of-range frame handle must yield a controlled error through the
    /// checked accessor (`try_with_page`), never an out-of-bounds slice panic (CWE-129). The
    /// infallible `slot()` keeps a `debug_assert`; this proves the fallible path callers use when a
    /// handle is not provably pool-minted.
    #[test]
    fn out_of_range_frame_handle_yields_error_not_oob() {
        let p = pool(2);
        // A handle one past the last valid frame: never minted by the pool, models a future
        // refactor that derived a frame index from an attacker-controlled page id.
        let evil = PinnedFrame(p.capacity());
        let r = p.try_with_page(evil, |_page| 0u8);
        assert!(
            r.is_err(),
            "an out-of-range handle must return Err, not index out of bounds"
        );
        // A second handle far out of range — same controlled-error contract.
        assert!(p.try_with_page(PinnedFrame(usize::MAX), |_p| ()).is_err());
        // A valid, pool-minted handle still works through the same checked accessor.
        let (f, _id) = p.new_page().unwrap();
        assert!(p.try_with_page(f, |_p| ()).is_ok());
        p.unpin(f);
    }

    #[test]
    fn unpin_saturates_at_zero() {
        let p = pool(2);
        let (f, _id) = p.new_page().unwrap();
        p.unpin(f);
        p.unpin(f); // extra unpin must not underflow
        assert_eq!(p.pin_count(f), 0);
    }

    #[test]
    fn wal_rule_is_enforced_before_write_back() {
        struct FailWal;
        impl WalRule for FailWal {
            fn ensure_durable(&mut self, _up_to: Lsn) -> Result<()> {
                Err(GraphusError::Storage("wal not durable".to_owned()))
            }
            /// Nothing is ever durable — this rule refuses every harden.
            fn durable_len(&mut self) -> u64 {
                0
            }
        }
        let p = ConcurrentBufferPool::with_wal(MemBlockDevice::new(0), FailWal, 2);
        let (f, _id) = p.new_page().unwrap();
        // Stamp a real redo LSN (a WAL-logged change always does), so the write-back exercises the
        // ensure_durable failure path rather than the unstamped-page debug-assert.
        p.with_page_mut_lsn(f, Lsn(1), |page| page[100] = 1);
        assert!(p.flush(f).is_err()); // the WAL rule refuses, so the write-back fails
    }

    /// An eviction whose victim is **not yet covered** by the durable log must run the WAL rule
    /// before the page reaches the device.
    ///
    /// The oracle is deliberately *not* "the rule is called on every write-back" any more. Since
    /// `rmp` #974 the pool consults the rule's reported frontier first and hardens only when the
    /// page is genuinely uncovered — which is exactly what `WalManager::ensure_durable` itself does
    /// internally (it no-ops when `durable_len() > up_to`), so no durability is lost. A call-count
    /// oracle would now be asserting an implementation detail the design intentionally removed: one
    /// harden legitimately covers every page dirtied before it.
    ///
    /// The rule below therefore starts uncovered and becomes covered once hardened, so the test
    /// still pins the property that matters — the harden happens, and it happens before the write.
    #[test]
    fn wal_rule_records_log_before_data() {
        #[derive(Clone)]
        struct OrderLog(StdArc<StdMutex<Vec<&'static str>>>);
        /// Nothing is durable until the first harden; after it, everything is.
        struct RecordingWal {
            log: OrderLog,
            durable: StdArc<std::sync::atomic::AtomicU64>,
        }
        impl WalRule for RecordingWal {
            fn ensure_durable(&mut self, _up_to: Lsn) -> Result<()> {
                self.log.0.lock().unwrap().push("wal");
                self.durable
                    .store(u64::MAX, std::sync::atomic::Ordering::Release);
                Ok(())
            }
            fn durable_len(&mut self) -> u64 {
                self.durable.load(std::sync::atomic::Ordering::Acquire)
            }
        }
        let log = OrderLog(StdArc::new(StdMutex::new(Vec::new())));
        let durable = StdArc::new(std::sync::atomic::AtomicU64::new(0));
        let p = ConcurrentBufferPool::with_wal(
            MemBlockDevice::new(0),
            RecordingWal {
                log: log.clone(),
                durable: StdArc::clone(&durable),
            },
            1,
        );
        let (fa, _a) = p.new_page().unwrap();
        p.with_page_mut(fa, |page| page[10] = 1);
        p.unpin(fa);
        // Force a write-back via eviction (capacity 1).
        let (fb, _b) = p.new_page().unwrap();
        p.unpin(fb);
        // The harden ran, and by construction it ran BEFORE the home write: `write_back` refuses to
        // write a page home unless the log already covers its `page_lsn`, so the only way this
        // eviction completed is that the hoist hardened first.
        let entries = log.0.lock().unwrap();
        assert!(
            entries.contains(&"wal"),
            "an uncovered victim must be hardened before it is written home"
        );
    }

    #[test]
    fn prefetch_warms_then_leaves_unpinned() {
        let p = pool(4);
        let (f, id) = p.new_page().unwrap();
        p.with_page_mut(f, |page| page[5] = 7);
        p.flush(f).unwrap();
        p.unpin(f);
        // Drop residency by churning (cap 4, so allocate 4 more to evict id eventually); simpler:
        // prefetch the same id (already resident) returns true and stays unpinned.
        let before = p.pin_count(f);
        assert!(p.prefetch(id));
        assert_eq!(p.pin_count(f), before, "prefetch must not leave a pin");
    }

    #[test]
    fn prefetch_sequential_warms_existing_pages() {
        let p = pool(8);
        let mut ids = Vec::new();
        for _ in 0..4 {
            let (f, id) = p.new_page().unwrap();
            p.flush(f).unwrap();
            p.unpin(f);
            ids.push(id);
        }
        let warmed = p.prefetch_sequential(ids[0], 4);
        assert_eq!(warmed, 4);
    }

    #[test]
    fn concurrent_fetch_same_page_loads_once() {
        // Two threads fetch the same pre-existing on-disk page; the device counts reads.
        // Exactly one device read must occur even though both call fetch.
        struct CountingDevice {
            inner: MemBlockDevice,
            reads: StdArc<AtomicU64>,
        }
        impl BlockDevice for CountingDevice {
            fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
                self.reads.fetch_add(1, StdOrdering::SeqCst);
                self.inner.read_page(page, buf)
            }
            fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
                self.inner.write_page(page, buf)
            }
            fn sync_data(&mut self) -> Result<()> {
                self.inner.sync_data()
            }
            fn sync_all(&mut self) -> Result<()> {
                self.inner.sync_all()
            }
            fn page_count(&self) -> u64 {
                self.inner.page_count()
            }
            fn extend(&mut self, additional: u64) -> Result<()> {
                self.inner.extend(additional)
            }
        }

        // Prepare one durable page (id 0) with a known byte.
        let mut prep = MemBlockDevice::new(0);
        prep.extend(1).unwrap();
        let mut page = [0u8; PAGE_SIZE];
        page::set_page_id(&mut page, 0);
        page[100] = 0xCD;
        page::write_checksum(&mut page);
        prep.write_page(PageId(0), &page).unwrap();
        prep.sync_all().unwrap();

        let reads = StdArc::new(AtomicU64::new(0));
        let dev = CountingDevice {
            inner: prep,
            reads: reads.clone(),
        };
        let pool = StdArc::new(ConcurrentBufferPool::new(dev, 2));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let pool = pool.clone();
            handles.push(thread::spawn(move || {
                let f = pool.fetch(PageId(0)).unwrap();
                let v = pool.with_page(f, |p| p[100]);
                pool.unpin(f);
                v
            }));
        }
        for h in handles {
            assert_eq!(h.join().unwrap(), 0xCD);
        }
        assert_eq!(
            reads.load(StdOrdering::SeqCst),
            1,
            "page must be loaded from the device exactly once despite concurrent fetches"
        );
    }

    /// `rmp` #374: a `flush_all` of many dirty frames whose page ids are **contiguous** must (a)
    /// coalesce into far fewer device write operations than one-per-page, and (b) leave a
    /// byte-identical on-disk image. We wrap a real `FileBlockDevice` (the only device that actually
    /// coalesces) in a counter that records every `write_pages` run and every `write_page` call,
    /// then compare against an independently-built per-page reference image.
    #[test]
    fn flush_all_coalesces_contiguous_runs_and_is_byte_identical() {
        use graphus_io::FileBlockDevice;

        struct CountingFile {
            inner: FileBlockDevice,
            runs: StdArc<AtomicU64>, // # of write_pages calls (≈ syscalls on the file device)
            single_writes: StdArc<AtomicU64>, // # of bare write_page calls
        }
        impl BlockDevice for CountingFile {
            fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
                self.inner.read_page(page, buf)
            }
            fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
                self.single_writes.fetch_add(1, StdOrdering::SeqCst);
                self.inner.write_page(page, buf)
            }
            fn write_pages(&mut self, base: PageId, pages: &[&Page]) -> Result<()> {
                self.runs.fetch_add(1, StdOrdering::SeqCst);
                self.inner.write_pages(base, pages)
            }
            fn sync_data(&mut self) -> Result<()> {
                self.inner.sync_data()
            }
            fn sync_all(&mut self) -> Result<()> {
                self.inner.sync_all()
            }
            fn page_count(&self) -> u64 {
                self.inner.page_count()
            }
            fn extend(&mut self, additional: u64) -> Result<()> {
                self.inner.extend(additional)
            }
        }

        fn tmp(tag: &str) -> std::path::PathBuf {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, StdOrdering::Relaxed);
            std::env::temp_dir().join(format!(
                "graphus-bufpool-374-{}-{tag}-{n}.blk",
                std::process::id()
            ))
        }

        const N: usize = 16;
        let coalesced_path = tmp("coalesced");
        let reference_path = tmp("reference");

        // Build the pool over the counting file device. A pool capacity >= N keeps every page
        // resident and dirty until the single flush_all, so the run is one contiguous span 0..N.
        let runs = StdArc::new(AtomicU64::new(0));
        let singles = StdArc::new(AtomicU64::new(0));
        let dev = CountingFile {
            inner: FileBlockDevice::open(&coalesced_path).unwrap(),
            runs: runs.clone(),
            single_writes: singles.clone(),
        };
        let pool = ConcurrentBufferPool::new(dev, N + 4);

        // Allocate N pages (ids 0..N, contiguous) and stamp a distinct body byte into each.
        let mut ids = Vec::new();
        for i in 0..N {
            let (f, id) = pool.new_page().unwrap();
            pool.with_page_mut_lsn(f, Lsn((i as u64) + 1), |p| p[200] = 0xB0 ^ (i as u8));
            pool.unpin(f);
            ids.push(id);
        }
        // Sanity: page ids are the contiguous run 0..N.
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(id.0, i as u64, "expected contiguous page ids from new_page");
        }

        pool.flush_all().unwrap();

        // (a) Coalescing: the whole contiguous span collapsed to a single write_pages run, and the
        // default per-page loop was NOT taken on this path.
        assert_eq!(
            runs.load(StdOrdering::SeqCst),
            1,
            "N contiguous dirty pages must coalesce into exactly ONE write_pages run"
        );
        assert_eq!(
            singles.load(StdOrdering::SeqCst),
            0,
            "the coalesced flush must not fall back to per-page write_page"
        );

        // Build the per-page reference image independently: same ids, same bytes, same checksums.
        {
            let mut ref_dev = FileBlockDevice::open(&reference_path).unwrap();
            ref_dev.extend(N as u64).unwrap();
            for i in 0..N {
                let mut page = [0u8; PAGE_SIZE];
                page::set_page_id(&mut page, i as u64);
                page::set_page_lsn(&mut page, Lsn((i as u64) + 1));
                page[200] = 0xB0 ^ (i as u8);
                page::write_checksum(&mut page);
                ref_dev.write_page(PageId(i as u64), &page).unwrap();
            }
            ref_dev.sync_all().unwrap();
        }

        // (b) Byte-identical on-disk image.
        let a = std::fs::read(&coalesced_path).unwrap();
        let b = std::fs::read(&reference_path).unwrap();
        assert_eq!(
            a, b,
            "coalesced flush_all image must be byte-identical to the per-page reference image"
        );

        std::fs::remove_file(&coalesced_path).ok();
        std::fs::remove_file(&reference_path).ok();
    }

    /// `rmp` #374: a **gap** in dirty page ids must break the coalesced run — only adjacent offsets
    /// are combined. We make pages 0,1 and 3 dirty (page 2 untouched/clean) and assert flush_all
    /// emits two separate runs.
    #[test]
    fn flush_all_gap_breaks_into_two_runs() {
        struct RunCounter {
            inner: MemBlockDevice,
            runs: StdArc<AtomicU64>,
            run_lens: StdArc<StdMutex<Vec<usize>>>,
        }
        impl BlockDevice for RunCounter {
            fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
                self.inner.read_page(page, buf)
            }
            fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
                self.inner.write_page(page, buf)
            }
            fn write_pages(&mut self, base: PageId, pages: &[&Page]) -> Result<()> {
                self.runs.fetch_add(1, StdOrdering::SeqCst);
                self.run_lens.lock().unwrap().push(pages.len());
                // Default-style fan-out to the underlying mem device (preserves its semantics).
                for (i, p) in pages.iter().enumerate() {
                    self.inner.write_page(PageId(base.0 + i as u64), p)?;
                }
                Ok(())
            }
            fn sync_data(&mut self) -> Result<()> {
                self.inner.sync_data()
            }
            fn sync_all(&mut self) -> Result<()> {
                self.inner.sync_all()
            }
            fn page_count(&self) -> u64 {
                self.inner.page_count()
            }
            fn extend(&mut self, additional: u64) -> Result<()> {
                self.inner.extend(additional)
            }
        }

        let runs = StdArc::new(AtomicU64::new(0));
        let run_lens = StdArc::new(StdMutex::new(Vec::new()));
        let dev = RunCounter {
            inner: MemBlockDevice::new(0),
            runs: runs.clone(),
            run_lens: run_lens.clone(),
        };
        let pool = ConcurrentBufferPool::new(dev, 8);

        // Allocate pages 0,1,2,3. Flush 2 to disk and leave it CLEAN; dirty 0,1,3.
        let mut frames = Vec::new();
        for i in 0..4u64 {
            let (f, id) = pool.new_page().unwrap();
            assert_eq!(id.0, i);
            frames.push(f);
        }
        // Dirty 0,1,3 via a stamped mutation; flush page 2 alone so it is clean at flush_all time.
        for &i in &[0usize, 1, 3] {
            pool.with_page_mut_lsn(frames[i], Lsn((i as u64) + 1), |p| p[10] = i as u8);
        }
        pool.flush(frames[2]).unwrap(); // page 2 written + marked clean
        for f in &frames {
            pool.unpin(*f);
        }
        // Reset the run counter so we only observe the flush_all below.
        runs.store(0, StdOrdering::SeqCst);
        run_lens.lock().unwrap().clear();

        pool.flush_all().unwrap();

        assert_eq!(
            runs.load(StdOrdering::SeqCst),
            2,
            "dirty pages 0,1 and 3 with a clean gap at 2 must form exactly two runs"
        );
        let mut lens = run_lens.lock().unwrap().clone();
        lens.sort_unstable();
        assert_eq!(
            lens,
            vec![1, 2],
            "runs must be [0,1] (len 2) and [3] (len 1)"
        );
    }

    #[test]
    fn multithreaded_stress_no_panic_and_consistent() {
        // Many threads hammer fetch/unpin/new_page on a shared pool; assert invariants hold and
        // all pins are released at the end. This is the runtime complement to loom.
        let pool = StdArc::new(ConcurrentBufferPool::new(MemBlockDevice::new(0), 8));

        // Pre-create a handful of pages so fetch has hits to find.
        let mut ids = Vec::new();
        for _ in 0..4 {
            let (f, id) = pool.new_page().unwrap();
            pool.flush(f).unwrap();
            pool.unpin(f);
            ids.push(id);
        }
        let ids = StdArc::new(ids);

        let threads = 8;
        let iters = 200;
        let mut handles = Vec::new();
        for t in 0..threads {
            let pool = pool.clone();
            let ids = ids.clone();
            handles.push(thread::spawn(move || {
                for i in 0..iters {
                    let id = ids[(t + i) % ids.len()];
                    if let Ok(f) = pool.fetch(id) {
                        // Read and occasionally write, then always unpin.
                        let _ = pool.with_page(f, |p| p[0]);
                        if i % 3 == 0 {
                            pool.with_page_mut(f, |p| p[1] = (t as u8).wrapping_add(i as u8));
                        }
                        pool.unpin(f);
                    }
                    // Occasionally allocate a brand-new page and immediately unpin it.
                    if i % 7 == 0 {
                        if let Ok((f, _id)) = pool.new_page() {
                            pool.unpin(f);
                        }
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread must not panic");
        }

        // Final invariant: every frame is unpinned (no leaked pins) and the table is consistent
        // with the frames (each Ready entry points at a frame holding that page).
        for slot in &pool.frames {
            assert_eq!(slot.pin_count.load(Ordering::Acquire), 0, "leaked pin");
        }
        for shard in &pool.table {
            let shard = shard.lock().unwrap();
            for (pid, slot) in shard.iter() {
                if let Slot::Ready(idx) = slot {
                    let meta = pool.frames[*idx].meta.read().unwrap();
                    assert_eq!(
                        meta.page_id,
                        Some(*pid),
                        "table entry {pid:?} -> frame {idx} mismatched frame identity"
                    );
                }
            }
        }
        // A final fetch of each id still works and yields a checksummed page.
        for &id in ids.iter() {
            let f = pool.fetch(id).unwrap();
            pool.unpin(f);
        }
    }

    /// `rmp` #374 measurement (run with `--ignored --nocapture`): a checkpoint of N contiguous dirty
    /// pages issues ONE coalesced device write versus N per-page writes, with the wall-clock for
    /// each, over a real `FileBlockDevice` (so the syscall count is real `pwrite`s). Reports the
    /// device-write-op count and elapsed time for both the coalesced `flush_all` and a per-page loop.
    #[test]
    #[ignore = "measurement bench; run explicitly with --ignored --nocapture"]
    fn bench_flush_all_coalesced_vs_per_page() {
        use graphus_io::FileBlockDevice;
        use std::time::Instant;

        struct CountingFile {
            inner: FileBlockDevice,
            ops: StdArc<AtomicU64>, // every device write op (write_page OR write_pages run)
        }
        impl BlockDevice for CountingFile {
            fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
                self.inner.read_page(page, buf)
            }
            fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
                self.ops.fetch_add(1, StdOrdering::SeqCst);
                self.inner.write_page(page, buf)
            }
            fn write_pages(&mut self, base: PageId, pages: &[&Page]) -> Result<()> {
                self.ops.fetch_add(1, StdOrdering::SeqCst);
                self.inner.write_pages(base, pages)
            }
            fn sync_data(&mut self) -> Result<()> {
                self.inner.sync_data()
            }
            fn sync_all(&mut self) -> Result<()> {
                self.inner.sync_all()
            }
            fn page_count(&self) -> u64 {
                self.inner.page_count()
            }
            fn extend(&mut self, additional: u64) -> Result<()> {
                self.inner.extend(additional)
            }
        }

        fn tmp(tag: &str) -> std::path::PathBuf {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, StdOrdering::Relaxed);
            std::env::temp_dir().join(format!(
                "graphus-bench-374-{}-{tag}-{n}.blk",
                std::process::id()
            ))
        }

        // Measure the device-WRITE phase in isolation (the part coalescing changes), separately
        // from the trailing fsync barrier (identical in both paths and the dominant durability
        // cost), across several N. For each N: stage N checksummed pages, then time (a) N per-page
        // `write_page`s and (b) one coalesced `write_pages` run, each followed by its own fsync.
        for &n in &[64usize, 512, 4096] {
            // Stage the page bytes once; both paths write identical content.
            let mut staged: Vec<Box<Page>> = Vec::with_capacity(n);
            for i in 0..n {
                let mut page = Box::new([0u8; PAGE_SIZE]);
                page::set_page_id(&mut page, i as u64);
                page::set_page_lsn(&mut page, Lsn((i as u64) + 1));
                page[300] = i as u8;
                page::write_checksum(&mut page);
                staged.push(page);
            }

            // (a) Per-page path.
            let ppath = tmp("perpage");
            let pops = StdArc::new(AtomicU64::new(0));
            let mut pdev = CountingFile {
                inner: FileBlockDevice::open(&ppath).unwrap(),
                ops: pops.clone(),
            };
            pdev.extend(n as u64).unwrap();
            let tw = Instant::now();
            for (i, page) in staged.iter().enumerate() {
                pdev.write_page(PageId(i as u64), page).unwrap();
            }
            let perpage_write = tw.elapsed();
            let ts = Instant::now();
            pdev.sync_all().unwrap();
            let perpage_sync = ts.elapsed();
            let perpage_ops = pops.load(StdOrdering::SeqCst);

            // (b) Coalesced path: one write_pages run over the same contiguous pages.
            let cpath = tmp("coalesced");
            let cops = StdArc::new(AtomicU64::new(0));
            let mut cdev = CountingFile {
                inner: FileBlockDevice::open(&cpath).unwrap(),
                ops: cops.clone(),
            };
            cdev.extend(n as u64).unwrap();
            let run: Vec<&Page> = staged.iter().map(|b| &**b).collect();
            let tw = Instant::now();
            cdev.write_pages(PageId(0), &run).unwrap();
            let coalesced_write = tw.elapsed();
            let ts = Instant::now();
            cdev.sync_all().unwrap();
            let coalesced_sync = ts.elapsed();
            let coalesced_ops = cops.load(StdOrdering::SeqCst);

            assert_eq!(
                coalesced_ops, 1,
                "contiguous run must coalesce to one device write op"
            );
            assert_eq!(perpage_ops as usize, n, "baseline issues one op per page");

            // Byte-identical image sanity.
            assert_eq!(
                std::fs::read(&ppath).unwrap(),
                std::fs::read(&cpath).unwrap(),
                "coalesced image must equal per-page image"
            );

            eprintln!(
                "rmp#374 N={n:>4} ({} KiB): write-ops {perpage_ops}->{coalesced_ops}  | \
                 write-phase {perpage_write:>10?} -> {coalesced_write:>10?}  | \
                 fsync (same barrier) {perpage_sync:?} vs {coalesced_sync:?}",
                n * PAGE_SIZE / 1024
            );

            std::fs::remove_file(&ppath).ok();
            std::fs::remove_file(&cpath).ok();
        }
    }
}
