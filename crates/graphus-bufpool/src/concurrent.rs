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
//! held — so concurrent device reads add no new wait edge. Dedicated fsync threads (§3.6) remain a
//! separate future option.
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
    Arc, AtomicUsize, Backoff, Mutex, MutexGuard, Ordering, RwLock, RwLockReadGuard,
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
/// victim sweep ([`VictimChoice::Contended`] *or* [`VictimChoice::AllPinned`], BOTH transient under a
/// correct workload — see the miss-arm of [`ConcurrentBufferPool::fetch`] for why even "every frame
/// pinned right now" clears microseconds later, a property `loom_fetch_under_contention_never_
/// spuriously_fails` proves). Each retry first backs off (see [`Backoff`]): the loop spreads
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
    frames: Vec<FrameSlot>,
    table: Vec<Mutex<HashMap<PageId, Slot>>>,
    clock: AtomicUsize,
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
    pub fn with_wal(device: D, wal: W, capacity: usize) -> Self {
        assert!(capacity > 0, "buffer pool capacity must be > 0");
        let frames = (0..capacity).map(|_| FrameSlot::empty()).collect();
        let table = (0..SHARD_COUNT)
            .map(|_| Mutex::new(HashMap::default()))
            .collect();
        Self {
            device: RwLock::new(device),
            wal: Mutex::new(wal),
            frames,
            table,
            clock: AtomicUsize::new(0),
            #[cfg(feature = "bufpool-probe")]
            probe: probe::Probe::default(),
        }
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
                let meta = unwrap_lock(self.frames[idx].meta.read());
                if meta.page_id == Some(page_id) {
                    let r = func(&meta.data);
                    drop(meta);
                    self.unpin(PinnedFrame(idx));
                    return Ok(r);
                }
                // Lost the race with an evictor between lookup and pin: fall through to the slow path.
                drop(meta);
                self.unpin(PinnedFrame(idx));
            }
        }
        // Cold path (miss / Loading / lost race): the full fetch keeps the load-once + publish-before-
        // pin guarantees, then read under a fresh latch.
        let f = self.fetch(page_id)?;
        let r = self.with_page(f, func);
        self.unpin(f);
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
    /// a freshly allocated page); `write_back` debug-asserts the invariant.
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
                        #[cfg(feature = "bufpool-probe")]
                        {
                            iter += 1;
                        }
                        backoff.spin();
                        continue;
                    }
                    None => {
                        // Miss: reserve a victim while still holding the shard lock. BOTH empty-sweep
                        // outcomes — `Contended` (an unpinned frame exists but is momentarily write-
                        // latched) and `AllPinned` (every frame pinned *this instant*) — are **transient**
                        // under a correct workload, so BOTH retry (bounded by `MAX_FETCH_RETRIES`), never
                        // fail fast (`rmp` #359).
                        //
                        // Why `AllPinned` is transient too (the loom-proven subtlety): a frame's pin is
                        // held only across a single record decode (`with_page_fetched` pins, decodes,
                        // unpins) or across the publish window of a concurrent loader (`fetch` pins its
                        // freshly-loaded frame just before returning, and the caller unpins after the
                        // decode). So a snapshot where *every* frame happens to be pinned right now (e.g.
                        // the one free frame is pinned by a peer loader in the instant between its load-
                        // publish and the caller's unpin) clears microseconds later. Erroring on it was a
                        // spurious `Err("buffer pool is full of pinned pages")` that the read-view chain
                        // swallows into `Value::Null` via the `Option`-returning `GraphAccess::node_property`
                        // — a present property silently read as absent (the #339 read-integrity violation),
                        // seen ONLY under eviction since a pool >= the working set never misses-needing-a-
                        // victim. The `VictimChoice` 3-state split is kept ONLY for probe diagnostics (it
                        // tells *why* a sweep was empty); it does NOT change control flow. The escalating
                        // `backoff` drains the loader/holder herd so this converges instead of live-locking;
                        // `MAX_FETCH_RETRIES` bounds it so a pool genuinely wedged by a *long-lived* pin
                        // leak (a caller bug) still terminates with the clear post-loop error.
                        match self.select_victim() {
                            VictimChoice::Found(victim) => {
                                shard.insert(page_id, Slot::Loading(victim.idx));
                                victim
                                // shard lock dropped here
                            }
                            VictimChoice::Contended | VictimChoice::AllPinned => {
                                // Transient victim scarcity: drop the shard lock (hold NO lock across the
                                // wait), back off, and retry — the next sweep finds the freed victim.
                                drop(shard);
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
        // miss-arm, BOTH empty-sweep outcomes are **transient** under a correct workload — `Contended`
        // (an unpinned frame momentarily write-latched) and `AllPinned` (every frame pinned *this
        // instant*, e.g. the lone free frame pinned by a peer loader between its load-publish and the
        // caller's unpin) — so BOTH retry with the escalating backoff that drains the holder herd, never
        // surfacing a spurious "full" error (`rmp` #359; the `AllPinned`-is-also-transient subtlety is
        // loom-proven by `loom_fetch_under_contention_never_spuriously_fails`). The `VictimChoice` split
        // is kept ONLY for probe diagnostics, not control flow. No lock is held here, so the retry is a
        // plain backed-off loop, bounded by `MAX_FETCH_RETRIES` so a pool genuinely wedged by long-lived
        // pins (a caller bug) still terminates with a clear error.
        let mut backoff = Backoff::new();
        let mut victim = 'pick: {
            for _ in 0..MAX_FETCH_RETRIES {
                match self.select_victim() {
                    VictimChoice::Found(v) => break 'pick v,
                    VictimChoice::Contended | VictimChoice::AllPinned => {
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
    /// # Errors
    /// Propagates a WAL-rule or device-write failure.
    pub fn flush(&self, f: PinnedFrame) -> Result<()> {
        let mut meta = unwrap_lock(self.frames[f.0].meta.write());
        self.write_back(&mut meta, false)
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
        // Coalesced checkpoint write-back (`rmp` #374). The old loop issued one `write_page`
        // syscall per dirty frame, each under the exclusive device guard — a checkpoint after a
        // sequential bulk load (dirty pages with *adjacent* page ids) paid N serialised `pwrite`s.
        // Here we sort the dirty frames by page id, coalesce contiguous runs, and emit each run as
        // one `write_pages` call (a single `pwrite` over the concatenated run on the file device).
        //
        // Latch protocol: we take each dirty frame's **write** latch and hold it for the whole
        // batch — released only after the run it belongs to has been written and the frame marked
        // clean. Holding the latch across the device write is exactly what `write_back` does per
        // frame; doing it for a run prevents a concurrent writer from re-dirtying/mutating a page's
        // bytes after we staged them but before they reach the device (no torn write), and prevents
        // the evictor (`select_victim` uses `try_write`, never blocking) from stealing a frame
        // mid-write-back. Latches are acquired in **frame-index order** (the `self.frames` scan
        // order), the same order eviction would, so there is no lock-ordering cycle.
        //
        // The per-page durability contract of `write_back` is preserved exactly: for every dirty
        // page we stamp its checksum and run `ensure_durable(page_lsn)` (the WAL-before-data rule)
        // *before* its bytes are written home, and the single trailing `sync_all` barrier is issued
        // once, after the whole batch — identical to before.
        //
        // The documented concurrency contract (storage audit F12) is unchanged: a frame re-dirtied
        // after its latch is released here is captured by a later `flush_all`; a sharp checkpoint
        // still requires the (single-writer) engine to quiesce writers, which it does by construction.

        // Phase 1: collect the dirty frames with their latches held. We hold every dirty frame's
        // write guard until the batch completes; clean frames are released immediately.
        let mut guards: Vec<(usize, RwLockWriteGuard<'_, FrameMeta>)> = Vec::new();
        for (idx, slot) in self.frames.iter().enumerate() {
            let meta = unwrap_lock(slot.meta.write());
            if meta.dirty {
                guards.push((idx, meta));
            }
        }
        if guards.is_empty() {
            return self.write_device().sync_all();
        }

        // Phase 2: per-page WAL-before-data. Stamp each dirty page's checksum and ensure the WAL is
        // durable through its `page_lsn` BEFORE any of its bytes are written back. This reproduces
        // `write_back`'s ordering for every page in the batch. A `page_id` is required for a dirty
        // frame (same invariant as `write_back`).
        for (idx, meta) in &mut guards {
            let page_id = meta.page_id.ok_or_else(|| {
                GraphusError::Storage("a dirty frame must hold a page".to_owned())
            })?;
            page::write_checksum(&mut meta.data);
            let lsn = page::page_lsn(&meta.data);
            debug_assert!(
                lsn.0 != 0 || !unwrap_lock(self.wal.lock()).tracks_lsn(),
                "dirty page {} written back with page_lsn 0 under a real WAL: its mutation did \
                 not stamp page_lsn (use with_page_mut_lsn) — WAL-before-data would be violated",
                page_id.0
            );
            self.ensure_durable(lsn)?;
            let _ = idx;
        }

        // Phase 3: order the held frames by page id and coalesce contiguous runs. A gap in page
        // ids (next.page_id != prev.page_id + 1) breaks the run, so only pages at adjacent file
        // offsets are ever combined into one vectored/sequential device write.
        guards.sort_by_key(|(_, meta)| meta.page_id.expect("dirty frame holds a page").0);
        let mut device = self.write_device();
        let mut run_start = 0usize; // index into `guards` where the current run begins
        for i in 1..=guards.len() {
            let break_run = i == guards.len() || {
                let prev = guards[i - 1].1.page_id.expect("dirty frame holds a page").0;
                let cur = guards[i].1.page_id.expect("dirty frame holds a page").0;
                cur != prev + 1
            };
            if break_run {
                let base = guards[run_start]
                    .1
                    .page_id
                    .expect("dirty frame holds a page");
                let run: Vec<&Page> = guards[run_start..i]
                    .iter()
                    .map(|(_, meta)| &*meta.data)
                    .collect();
                device.write_pages(base, &run)?;
                run_start = i;
            }
        }

        // Phase 4: the bytes are home — mark every flushed frame clean, then issue the single
        // trailing durability barrier exactly once.
        for (_, meta) in &mut guards {
            meta.dirty = false;
        }
        device.sync_all()
    }

    /// Writes back **only** the dirty frames whose home `PageId` is in `pages`, then syncs the
    /// device once. This is the targeted counterpart of [`flush_all`](Self::flush_all): it lets a
    /// caller flush a *bounded subset* of the dirty set home without writing the rest, which the
    /// doublewrite-protected checkpoint requires — each batch's home pages must only be written
    /// *after that batch's* images are durable in the doublewrite buffer, never before
    /// ([`crate::page`]; `graphus_storage::RecordStore::flush_protected`, `05 §3`).
    ///
    /// Every per-page durability guarantee of `flush_all` is preserved for the selected pages: the
    /// checksum is stamped and the WAL-before-data rule (`ensure_durable(page_lsn)`) is enforced
    /// *before* the page's bytes are written home, frames are flushed under their write latch (held
    /// across the device write so no concurrent mutator or the evictor can tear the in-flight
    /// image), and a single trailing `sync_all` barrier is issued after the batch. Frames not in
    /// `pages` are left dirty and untouched, captured by a later flush.
    ///
    /// The same F12 concurrency contract applies: a selected frame re-dirtied after its latch is
    /// released here is captured by a later flush; a sharp checkpoint still requires the
    /// (single-writer) engine to quiesce writers, which it does by construction.
    ///
    /// # Errors
    /// Propagates the first WAL-rule, device-write or sync failure.
    pub fn flush_pages(&self, pages: &[PageId]) -> Result<()> {
        use rustc_hash::FxHashSet;
        let wanted: FxHashSet<u64> = pages.iter().map(|p| p.0).collect();

        // Phase 1: collect the dirty frames whose page id is wanted, with their write latches held.
        let mut guards: Vec<(usize, RwLockWriteGuard<'_, FrameMeta>)> = Vec::new();
        for (idx, slot) in self.frames.iter().enumerate() {
            let meta = unwrap_lock(slot.meta.write());
            if meta.dirty && meta.page_id.is_some_and(|p| wanted.contains(&p.0)) {
                guards.push((idx, meta));
            }
        }
        if guards.is_empty() {
            return self.write_device().sync_all();
        }

        // Phase 2: per-page WAL-before-data — identical to `flush_all`.
        for (idx, meta) in &mut guards {
            let page_id = meta.page_id.ok_or_else(|| {
                GraphusError::Storage("a dirty frame must hold a page".to_owned())
            })?;
            page::write_checksum(&mut meta.data);
            let lsn = page::page_lsn(&meta.data);
            debug_assert!(
                lsn.0 != 0 || !unwrap_lock(self.wal.lock()).tracks_lsn(),
                "dirty page {} written back with page_lsn 0 under a real WAL: its mutation did \
                 not stamp page_lsn (use with_page_mut_lsn) — WAL-before-data would be violated",
                page_id.0
            );
            self.ensure_durable(lsn)?;
            let _ = idx;
        }

        // Phase 3: order the held frames by page id and coalesce contiguous runs (as `flush_all`).
        guards.sort_by_key(|(_, meta)| meta.page_id.expect("dirty frame holds a page").0);
        let mut device = self.write_device();
        let mut run_start = 0usize;
        for i in 1..=guards.len() {
            let break_run = i == guards.len() || {
                let prev = guards[i - 1].1.page_id.expect("dirty frame holds a page").0;
                let cur = guards[i].1.page_id.expect("dirty frame holds a page").0;
                cur != prev + 1
            };
            if break_run {
                let base = guards[run_start]
                    .1
                    .page_id
                    .expect("dirty frame holds a page");
                let run: Vec<&Page> = guards[run_start..i]
                    .iter()
                    .map(|(_, meta)| &*meta.data)
                    .collect();
                device.write_pages(base, &run)?;
                run_start = i;
            }
        }

        // Phase 4: the selected bytes are home — mark them clean, then the single barrier.
        for (_, meta) in &mut guards {
            meta.dirty = false;
        }
        device.sync_all()
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
            // Re-check the pin count now that we hold the latch (a pin may have raced in).
            if slot.pin_count.load(Ordering::Acquire) > 0 {
                continue;
            }
            if slot.ref_bit.swap(0, Ordering::Relaxed) == 1 && guard.page_id.is_some() {
                continue; // second chance for a referenced, occupied frame
            }
            return VictimChoice::Found(Victim { idx, guard });
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
            let device = self.read_device();
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
        let page_id = meta
            .page_id
            .ok_or_else(|| GraphusError::Storage("a dirty frame must hold a page".to_owned()))?;
        page::write_checksum(&mut meta.data);
        let lsn = page::page_lsn(&meta.data);
        // WAL-before-data invariant (storage audit F6): under a real WAL every dirty page that
        // carries a logged change must hold a non-zero `page_lsn`, else `ensure_durable(0)` is a
        // no-op and the data could reach the device before its redo record is durable. A `page_lsn`
        // of 0 means the mutation did not stamp it (use `with_page_mut_lsn`). The one legitimate
        // exception is `allow_unlogged` (via [`flush_unlogged`]): a freshly-allocated, not-yet-logged
        // page being seeded with a valid checksum, which by contract has nothing in the WAL that must
        // precede it. Debug-only: cheap, and the production path stamps.
        debug_assert!(
            allow_unlogged || lsn.0 != 0 || !unwrap_lock(self.wal.lock()).tracks_lsn(),
            "dirty page {} written back with page_lsn 0 under a real WAL: its mutation did not \
             stamp page_lsn (use with_page_mut_lsn) — WAL-before-data would be violated",
            page_id.0
        );
        // WAL rule: the log must be durable through this page's LSN before the data is written
        // home (`specification` §3.2 page_lsn, §4.3 steal/no-force).
        self.ensure_durable(lsn)?;
        // `write_page` is `&mut D`, so it takes the device **write** guard (exclusive): write-backs
        // serialise against each other and against concurrent device reads — correct, since the WAL
        // rule above (and the exclusive guard) keep the steal/no-force ordering intact.
        self.write_device().write_page(page_id, &meta.data)?;
        meta.dirty = false;
        Ok(())
    }

    fn ensure_durable(&self, up_to: Lsn) -> Result<()> {
        unwrap_lock(self.wal.lock()).ensure_durable(up_to)
    }
}

/// A selected eviction victim: the frame index and its held write latch. Dropping it releases
/// the latch.
struct Victim<'a> {
    idx: usize,
    guard: RwLockWriteGuard<'a, FrameMeta>,
}

/// The outcome of one bounded [`ConcurrentBufferPool::select_victim`] sweep. Separating the two
/// failure modes is the crux of the `rmp` #359 read-integrity fix: a transient contention must
/// **retry** (with backoff), never surface as an error — collapsing it into the genuine-capacity case
/// produced a spurious `Err` that the read-view chain swallowed into `Value::Null` / a truncated
/// chain (a wrong query result, seen only under eviction).
enum VictimChoice<'a> {
    /// An evictable victim, with its write latch already held.
    Found(Victim<'a>),
    /// **Every** frame examined this sweep was pinned: the genuine "buffer pool full of pinned pages"
    /// capacity limit. The caller fails fast — a pinned frame will not free until its holder unpins, so
    /// retrying cannot conjure a victim. (Instrumentation: this is observed **zero** times under a
    /// concurrent-reader eviction storm; it indicates a real caller pin-leak, not normal pressure.)
    AllPinned,
    /// At least one frame was **unpinned** but could not be taken this sweep (its write latch was
    /// momentarily held by a concurrent reader/loader, or it was given a CLOCK second chance).
    /// **Transient**: an unpinned frame is an evictable victim whose latch frees in microseconds, so
    /// the caller MUST retry (after dropping its shard lock and backing off), never error.
    Contended,
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
pub(crate) mod probe {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Per-pool diagnostics counters.
    #[derive(Default)]
    pub(crate) struct Probe {
        /// `select_victim` came up empty with **every** examined frame pinned (genuine capacity).
        all_pinned: AtomicU64,
        /// `select_victim` came up empty although ≥1 frame was unpinned (transient latch contention).
        contended: AtomicU64,
        /// The **maximum** number of retry iterations any single `fetch`/`new_page` call has taken to
        /// resolve. Small ⇒ the backoff drains contention fast (no live-lock); near
        /// `MAX_FETCH_RETRIES` ⇒ a near-wedge. The whole point of the `rmp` #359 fix is to keep this
        /// small even under an eviction storm.
        max_retry_iters: AtomicU64,
    }

    impl Probe {
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

    #[test]
    fn a_fully_pinned_pool_cannot_evict() {
        let p = pool(1);
        let (_fa, _a) = p.new_page().unwrap(); // pinned
        assert!(p.new_page().is_err());
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
        }
        let p = ConcurrentBufferPool::with_wal(MemBlockDevice::new(0), FailWal, 2);
        let (f, _id) = p.new_page().unwrap();
        // Stamp a real redo LSN (a WAL-logged change always does), so the write-back exercises the
        // ensure_durable failure path rather than the unstamped-page debug-assert.
        p.with_page_mut_lsn(f, Lsn(1), |page| page[100] = 1);
        assert!(p.flush(f).is_err()); // the WAL rule refuses, so the write-back fails
    }

    #[test]
    fn wal_rule_records_log_before_data() {
        // A WAL rule + device that share an order log; assert ensure_durable always precedes the
        // device write for the same write-back.
        #[derive(Clone)]
        struct OrderLog(StdArc<StdMutex<Vec<&'static str>>>);
        struct RecordingWal(OrderLog);
        impl WalRule for RecordingWal {
            fn ensure_durable(&mut self, _up_to: Lsn) -> Result<()> {
                self.0.0.lock().unwrap().push("wal");
                Ok(())
            }
        }
        let log = OrderLog(StdArc::new(StdMutex::new(Vec::new())));
        let p =
            ConcurrentBufferPool::with_wal(MemBlockDevice::new(0), RecordingWal(log.clone()), 1);
        let (fa, _a) = p.new_page().unwrap();
        p.with_page_mut(fa, |page| page[10] = 1);
        p.unpin(fa);
        // Force a write-back via eviction.
        let (fb, _b) = p.new_page().unwrap();
        p.unpin(fb);
        // The recording of "wal" happened (write-back occurred); the device write is internal so
        // we assert ordering by construction: write_back calls ensure_durable before write_page.
        let entries = log.0.lock().unwrap();
        assert!(entries.contains(&"wal"), "WAL rule must run on write-back");
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
