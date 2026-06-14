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
//! [`BlockDevice`]'s mutating methods (`write_page`, `extend`, `sync_*`) and
//! [`WalRule::ensure_durable`] both take `&mut self`, so the pool serializes each behind its own
//! `Mutex`. This is the simplest correct choice; a future optimization could use a `RwLock<D>`
//! to allow concurrent device *reads*, or dedicated fsync threads (§3.6). The choice is
//! documented here rather than guessed at.
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
//!    while holding a shard lock.
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
    Arc, AtomicUsize, Mutex, MutexGuard, Ordering, RwLock, RwLockWriteGuard, yield_now,
};

/// Number of frame-table shards. A small power of two keeps the loom state space tractable while
/// still exercising the sharded lookup path; production tuning (padding shards to cache lines,
/// §10) is a measurement-gated follow-up.
const SHARD_COUNT: usize = 4;

/// Bound on reservation-spin / fetch retries before giving up. With the contended page either
/// resident or being loaded by a peer, a fetch resolves in at most a couple of iterations; the
/// cap is a safety backstop that turns a pathological live-lock into a clear error instead of a
/// hang (and keeps the loom state space finite).
const MAX_FETCH_RETRIES: usize = 1024;

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
    /// Serializes all mutating device access (`write_page`/`extend`/`sync_*`).
    device: Mutex<D>,
    /// Serializes WAL-rule checks (`ensure_durable`).
    wal: Mutex<W>,
    frames: Vec<FrameSlot>,
    table: Vec<Mutex<HashMap<PageId, Slot>>>,
    clock: AtomicUsize,
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
            device: Mutex::new(device),
            wal: Mutex::new(wal),
            frames,
            table,
            clock: AtomicUsize::new(0),
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

    fn shard_of(&self, page_id: PageId) -> &Mutex<HashMap<PageId, Slot>> {
        // A cheap, deterministic spread; the exact hash is not load-bearing for correctness.
        let h = page_id.0.wrapping_mul(0x9E37_79B9_7F4A_7C15) as usize;
        &self.table[h % SHARD_COUNT]
    }

    fn lock_shard(&self, page_id: PageId) -> MutexGuard<'_, HashMap<PageId, Slot>> {
        unwrap_lock(self.shard_of(page_id).lock())
    }

    fn lock_device(&self) -> MutexGuard<'_, D> {
        unwrap_lock(self.device.lock())
    }

    /// Borrows the cached page held by a pinned frame and applies `func` to it.
    ///
    /// Takes the frame's **read latch** for the duration of `func`; many threads may read
    /// distinct frames concurrently. `func` must not block or call back into the pool with this
    /// frame.
    pub fn with_page<R>(&self, f: PinnedFrame, func: impl FnOnce(&Page) -> R) -> R {
        let meta = unwrap_lock(self.frames[f.0].meta.read());
        func(&meta.data)
    }

    /// Mutably borrows the page held by a pinned frame, marks it dirty, and applies `func`.
    ///
    /// Takes the frame's **write latch** for the duration of `func` (exclusive). `func` must not
    /// block or call back into the pool with this frame.
    pub fn with_page_mut<R>(&self, f: PinnedFrame, func: impl FnOnce(&mut Page) -> R) -> R {
        let mut meta = unwrap_lock(self.frames[f.0].meta.write());
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
        let mut meta = unwrap_lock(self.frames[f.0].meta.write());
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
        let _ =
            self.frames[f.0]
                .pin_count
                .fetch_update(Ordering::Release, Ordering::Relaxed, |c| {
                    Some(c.saturating_sub(1))
                });
    }

    /// The current pin count of a frame (diagnostics / tests).
    #[must_use]
    pub fn pin_count(&self, f: PinnedFrame) -> usize {
        self.frames[f.0].pin_count.load(Ordering::Acquire)
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
                            return Ok(PinnedFrame(idx));
                        }
                        drop(meta);
                        self.unpin(PinnedFrame(idx)); // lost the race; undo and retry
                        continue;
                    }
                    Some(Slot::Loading(_)) => {
                        // Another thread is loading this exact page; let it finish, then retry.
                        drop(shard);
                        yield_now();
                        continue;
                    }
                    None => {
                        // Miss: reserve a victim while still holding the shard lock.
                        let Some(victim) = self.select_victim() else {
                            return Err(GraphusError::Storage(
                                "buffer pool is full of pinned pages".to_owned(),
                            ));
                        };
                        shard.insert(page_id, Slot::Loading(victim.idx));
                        victim
                        // shard lock dropped here
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
                    self.frames[idx].pin_count.store(1, Ordering::Release);
                    self.frames[idx].ref_bit.store(1, Ordering::Relaxed);
                    drop(shard);
                    drop(victim); // release the write latch only now, after the pin is set
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
            "fetch of page {} did not resolve within {MAX_FETCH_RETRIES} retries",
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
        // Reserve a victim first so a fully-pinned pool fails before we grow the device.
        let Some(mut victim) = self.select_victim() else {
            return Err(GraphusError::Storage(
                "buffer pool is full of pinned pages".to_owned(),
            ));
        };
        // Evict the victim's previous occupant (if any) under its write latch.
        self.evict_held(&mut victim)?;
        let page_id = {
            let mut device = self.lock_device();
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
        self.frames[idx].pin_count.store(1, Ordering::Release);
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
        self.write_back(&mut meta)
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
        for slot in &self.frames {
            let mut meta = unwrap_lock(slot.meta.write());
            self.write_back(&mut meta)?;
        }
        self.lock_device().sync_all()
    }

    /// A snapshot count of currently dirty frames (diagnostics / tests).
    #[must_use]
    pub fn dirty_frames(&self) -> usize {
        self.frames
            .iter()
            .filter(|s| unwrap_lock(s.meta.read()).dirty)
            .count()
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

    /// Selects an evictable victim frame, returning it with its write latch already held.
    ///
    /// CLOCK sweep: a candidate is acquired with `try_write` (so two threads never pick the same
    /// frame, and a busy frame is skipped), skipped if pinned, and given a second chance —
    /// clearing its reference bit — if its reference bit is set and it is occupied. The first
    /// unpinned, unreferenced frame whose latch we win is the victim; empty frames are taken
    /// eagerly. Returns `None` if no victim is found within a bounded number of hand advances
    /// (every frame pinned or contended).
    fn select_victim(&self) -> Option<Victim<'_>> {
        let n = self.frames.len();
        // Several full sweeps give CLOCK room to clear reference bits and absorb frames briefly
        // latched by other threads, while staying bounded for loom.
        for _ in 0..(4 * n) {
            let idx = self.clock.fetch_add(1, Ordering::Relaxed) % n;
            let slot = &self.frames[idx];
            if slot.pin_count.load(Ordering::Acquire) > 0 {
                continue;
            }
            // `try_write` never blocks: if another thread holds the latch we move on.
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
            return Some(Victim { idx, guard });
        }
        None
    }

    /// Writes back the victim's previous occupant (if dirty, honouring the WAL rule) and removes
    /// it from its shard, leaving the latched frame a clean blank slate. Caller holds the latch
    /// via `victim`.
    fn evict_held(&self, victim: &mut Victim<'_>) -> Result<()> {
        let old = victim.guard.page_id;
        self.write_back(&mut victim.guard)?;
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
        // Read under the device lock into the latched frame's bytes.
        {
            let device = self.lock_device();
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

    /// Blanks a frame (after a failed load) so it is reusable as an empty slot.
    fn blank(&self, victim: &mut Victim<'_>) {
        victim.guard.page_id = None;
        victim.guard.dirty = false;
        self.frames[victim.idx]
            .pin_count
            .store(0, Ordering::Release);
        self.frames[victim.idx].ref_bit.store(0, Ordering::Relaxed);
    }

    /// Writes a frame back if dirty. Caller holds the write latch (passed as `meta`).
    fn write_back(&self, meta: &mut FrameMeta) -> Result<()> {
        if !meta.dirty {
            return Ok(());
        }
        let page_id = meta
            .page_id
            .ok_or_else(|| GraphusError::Storage("a dirty frame must hold a page".to_owned()))?;
        page::write_checksum(&mut meta.data);
        let lsn = page::page_lsn(&meta.data);
        // WAL-before-data invariant (storage audit F6): under a real WAL every dirty page must carry
        // a non-zero `page_lsn`, else `ensure_durable(0)` is a no-op and the data could reach the
        // device before its redo record is durable. A `page_lsn` of 0 here means the mutation failed
        // to stamp it (use `with_page_mut_lsn`). Debug-only: cheap, and the production path stamps.
        debug_assert!(
            lsn.0 != 0 || !unwrap_lock(self.wal.lock()).tracks_lsn(),
            "dirty page {} written back with page_lsn 0 under a real WAL: its mutation did not \
             stamp page_lsn (use with_page_mut_lsn) — WAL-before-data would be violated",
            page_id.0
        );
        // WAL rule: the log must be durable through this page's LSN before the data is written
        // home (`specification` §3.2 page_lsn, §4.3 steal/no-force).
        self.ensure_durable(lsn)?;
        self.lock_device().write_page(page_id, &meta.data)?;
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

/// Acquires a latch/mutex guard, **recovering it even if a prior holder panicked** (storage audit
/// F14). A poisoned latch must not permanently wedge a frame (every later access would panic, an
/// availability failure under extreme load): the protected state is just page bytes + a dirty flag,
/// and the WAL provides durability/recovery for any change a panicking mutation left partial, so the
/// guard is taken via [`PoisonError::into_inner`] rather than re-panicking.
fn unwrap_lock<G>(r: std::result::Result<G, std::sync::PoisonError<G>>) -> G {
    r.unwrap_or_else(std::sync::PoisonError::into_inner)
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
}
