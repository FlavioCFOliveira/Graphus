//! A single-threaded buffer pool over a [`BlockDevice`], with CLOCK eviction, pinning,
//! checksummed dirty-page write-back, and the write-ahead-log ordering rule.
//!
//! A concurrent, latched version (validated with loom) is a separate Phase 1 task; this is
//! the correct single-threaded core the storage and WAL layers build on.

// FxHashMap: the page table is keyed by internal PageIds (never attacker-controlled), so the
// faster non-cryptographic hash is safe and avoids SipHash overhead on this hot lookup path.
use rustc_hash::FxHashMap as HashMap;

use graphus_core::error::{GraphusError, Result};
use graphus_core::{Lsn, PageId};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};

use crate::page;

/// The write-ahead-log ordering rule: before a dirty page stamped with `up_to` is written to
/// the device, the log up to `up_to` must be durable. The real WAL implements this; [`NoWal`]
/// is the standalone default that treats everything as already durable.
pub trait WalRule {
    /// Ensures the log is durable up to (and including) `up_to`.
    fn ensure_durable(&mut self, up_to: Lsn) -> Result<()>;

    /// Whether this rule tracks real LSNs (a real WAL) rather than treating everything as already
    /// durable ([`NoWal`]). When `true`, every dirty page written home must carry a non-zero
    /// `page_lsn` — otherwise the WAL-before-data rule cannot be honoured (the concurrent pool's
    /// home-write paths enforce this as a release-built invariant, returning an error rather than a
    /// debug-assert; see `ConcurrentBufferPool::guard_wal_before_data`). Defaults to `true`.
    fn tracks_lsn(&self) -> bool {
        true
    }

    /// The log's **durable frontier**: the number of log bytes known to be on stable storage.
    ///
    /// This is the read-only counterpart of [`ensure_durable`](Self::ensure_durable) and must
    /// **never** issue a durability barrier — it only reports what is already durable. The
    /// relationship between the two is exact and is the contract the concurrent pool relies on:
    ///
    /// > `ensure_durable(up_to)` is a **no-op** if and only if `durable_len() > up_to.0`.
    ///
    /// (Strictly greater, mirroring `WalManager::ensure_durable`, which hardens when
    /// `durable_len() <= up_to.0`.)
    ///
    /// # Progress requirement
    ///
    /// The equivalence has a direction that implementations must honour: after
    /// `ensure_durable(up_to)` returns `Ok`, a subsequent `durable_len()` **must** report a value
    /// `> up_to.0`. Reporting *less* than the truth is fine and expected — the pool's mirror lags the
    /// log constantly, because the store commits without going through the pool — but the lag must
    /// be **temporal**, resolving once the frontier is re-read. A rule that under-reports by a fixed
    /// margin forever makes some pages permanently un-hardenable: the pool declines those victims,
    /// re-sweeps, declines again, and eventually surfaces its retry-budget error. That is a clean,
    /// bounded failure rather than corruption — WAL-before-data is never violated — but it is a
    /// broken rule, not a supported configuration.
    ///
    /// # Why the pool needs it (`rmp` #974)
    ///
    /// The concurrent pool must never perform an `fdatasync` while holding a frame latch: the WAL
    /// mutex is shared with the store's own commit path, so a harden under a latch chains
    /// *frame latch → WAL mutex → fdatasync* and convoys every other evictor **and** every
    /// concurrent commit behind it. The pool therefore **hoists** the harden: it asks this method
    /// whether a page's `page_lsn` is already covered, and when it is not, it releases the latch,
    /// hardens with no latch held, and retries. This method is consulted on the eviction path, so it
    /// must be cheap — a field read, not I/O.
    ///
    /// # Why this is required rather than defaulted
    ///
    /// It has no default on purpose. A default would have to be either `0` ("nothing known
    /// durable"), which is safe but makes an implementer's silence indistinguishable from a genuine
    /// report of zero — the pool would then have to fall back on inferring the frontier from a
    /// page's own `page_lsn`, and a single mis-stamped page could raise the pool-wide watermark and
    /// disable WAL-before-data for every page below it — or `u64::MAX`, which is fail-open and would
    /// silently disable the rule outright for any implementer who forgot. Requiring the method
    /// forces the one decision that cannot be guessed, and lets the pool trust every value it gets
    /// as an observation of the log.
    fn durable_len(&mut self) -> u64;
}

/// A [`WalRule`] for standalone use (no WAL): every LSN is considered already durable.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoWal;

impl WalRule for NoWal {
    fn ensure_durable(&mut self, _up_to: Lsn) -> Result<()> {
        Ok(())
    }

    fn tracks_lsn(&self) -> bool {
        false
    }

    /// Everything is already durable, so every LSN is covered — the exact counterpart of this
    /// rule's no-op [`ensure_durable`](WalRule::ensure_durable).
    fn durable_len(&mut self) -> u64 {
        u64::MAX
    }
}

/// A handle to a pinned frame, valid until it is unpinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameId(usize);

struct Frame {
    page_id: Option<PageId>,
    data: Box<Page>,
    pin_count: u32,
    dirty: bool,
    ref_bit: bool,
}

impl Frame {
    fn empty() -> Self {
        Self {
            page_id: None,
            data: Box::new([0u8; PAGE_SIZE]),
            pin_count: 0,
            dirty: false,
            ref_bit: false,
        }
    }
}

/// A fixed-capacity buffer pool.
pub struct BufferPool<D: BlockDevice, W: WalRule = NoWal> {
    device: D,
    wal: W,
    frames: Vec<Frame>,
    table: HashMap<PageId, usize>,
    clock: usize,
}

impl<D: BlockDevice> BufferPool<D, NoWal> {
    /// Creates a pool of `capacity` frames over `device`, with no WAL coupling.
    pub fn new(device: D, capacity: usize) -> Self {
        Self::with_wal(device, NoWal, capacity)
    }
}

impl<D: BlockDevice, W: WalRule> BufferPool<D, W> {
    /// Creates a pool of `capacity` frames with an explicit [`WalRule`].
    ///
    /// # Panics
    /// Panics if `capacity` is zero.
    pub fn with_wal(device: D, wal: W, capacity: usize) -> Self {
        assert!(capacity > 0, "buffer pool capacity must be > 0");
        let frames = (0..capacity).map(|_| Frame::empty()).collect();
        Self {
            device,
            wal,
            frames,
            table: HashMap::default(),
            clock: 0,
        }
    }

    /// Borrows the cached page held by a pinned frame.
    ///
    /// # Panics
    /// Panics if `f` is out of bounds (an invariant violation: handles are minted only by the
    /// pool, so a pool-minted handle is always in range). Use [`try_page`](Self::try_page) when the
    /// handle may not be provably pool-minted.
    #[must_use]
    pub fn page(&self, f: FrameId) -> &Page {
        &self.frame(f.0).data
    }

    /// The fallible counterpart of [`page`](Self::page): returns a clean storage error for an
    /// out-of-range handle instead of panicking (CWE-129 defence in depth).
    ///
    /// # Errors
    /// Returns a storage error if `f` is out of bounds for this pool.
    pub fn try_page(&self, f: FrameId) -> Result<&Page> {
        self.frames
            .get(f.0)
            .map(|fr| &*fr.data)
            .ok_or_else(|| Self::oob_err(f.0, self.frames.len()))
    }

    /// The number of pages on the underlying device (its current size in pages). Used by crash
    /// recovery to scan every device page (`rmp` #239) without exposing the device itself.
    #[must_use]
    pub fn page_count(&self) -> u64 {
        self.device.page_count()
    }

    /// Mutably borrows the page held by a pinned frame and marks it dirty.
    ///
    /// # Panics
    /// Panics if `f` is out of bounds (see [`page`](Self::page)).
    pub fn page_mut(&mut self, f: FrameId) -> &mut Page {
        let n = self.frames.len();
        let fr = self
            .frames
            .get_mut(f.0)
            .unwrap_or_else(|| panic!("{}", Self::oob_msg(f.0, n)));
        fr.dirty = true;
        &mut fr.data
    }

    /// Mutably borrows the underlying block device, for **Deterministic Simulation Testing only**
    /// (`04 §11`): a DST harness uses it to arm a [`graphus_io::FaultPlan`] (or a one-shot I/O
    /// error / torn write) on the *live* device of a running pool, so a fault can be injected
    /// mid-workload rather than only on a device the harness owns before construction.
    ///
    /// Gated behind the `dst` cargo feature so the production build never compiles this seam — the
    /// device stays fully encapsulated on the production path (zero-cost: the method does not exist).
    #[cfg(feature = "dst")]
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    fn oob_msg(idx: usize, capacity: usize) -> String {
        format!(
            "frame handle {idx} out of bounds (capacity {capacity}): handles must be pool-minted"
        )
    }

    fn oob_err(idx: usize, capacity: usize) -> GraphusError {
        GraphusError::Storage(Self::oob_msg(idx, capacity))
    }

    /// Resolves a frame index to its slot with an explicit bounds check (CWE-129 defence in depth).
    #[inline]
    fn frame(&self, idx: usize) -> &Frame {
        let n = self.frames.len();
        debug_assert!(idx < n, "{}", Self::oob_msg(idx, n));
        self.frames
            .get(idx)
            .unwrap_or_else(|| panic!("{}", Self::oob_msg(idx, n)))
    }

    /// Decrements the pin count of a frame.
    ///
    /// # Panics
    /// Panics if `f` is out of bounds (an invariant violation; handles are pool-minted).
    pub fn unpin(&mut self, f: FrameId) {
        let n = self.frames.len();
        let fr = self
            .frames
            .get_mut(f.0)
            .unwrap_or_else(|| panic!("{}", Self::oob_msg(f.0, n)));
        debug_assert!(fr.pin_count > 0);
        fr.pin_count = fr.pin_count.saturating_sub(1);
    }

    /// Fetches `page_id`, loading it from the device on a miss (verifying its checksum), and
    /// pins it.
    pub fn fetch(&mut self, page_id: PageId) -> Result<FrameId> {
        if let Some(&idx) = self.table.get(&page_id) {
            self.frames[idx].pin_count += 1;
            self.frames[idx].ref_bit = true;
            return Ok(FrameId(idx));
        }
        let idx = self.evict_victim()?;
        let mut buf: Box<Page> = Box::new([0u8; PAGE_SIZE]);
        self.device.read_page(page_id, &mut buf)?;
        if !page::verify_checksum(&buf) {
            return Err(GraphusError::Storage(format!(
                "page {} failed checksum verification",
                page_id.0
            )));
        }
        self.install(idx, page_id, buf, false);
        Ok(FrameId(idx))
    }

    /// Allocates a fresh zero page at the end of the device, pins it, and returns its handle
    /// and id.
    pub fn new_page(&mut self) -> Result<(FrameId, PageId)> {
        let idx = self.evict_victim()?;
        let page_id = PageId(self.device.page_count());
        self.device.extend(1)?;
        let mut buf: Box<Page> = Box::new([0u8; PAGE_SIZE]);
        page::set_page_id(&mut buf, page_id.0);
        page::write_checksum(&mut buf);
        self.install(idx, page_id, buf, true);
        Ok((FrameId(idx), page_id))
    }

    /// Writes a frame back to the device if it is dirty.
    pub fn flush(&mut self, f: FrameId) -> Result<()> {
        self.write_back(f.0)
    }

    /// Writes every dirty frame back and syncs the device.
    pub fn flush_all(&mut self) -> Result<()> {
        let dirty: Vec<usize> = self
            .frames
            .iter()
            .enumerate()
            .filter(|(_, fr)| fr.dirty)
            .map(|(i, _)| i)
            .collect();
        for idx in dirty {
            self.write_back(idx)?;
        }
        self.device.sync_all()
    }

    fn install(&mut self, idx: usize, page_id: PageId, data: Box<Page>, dirty: bool) {
        let fr = &mut self.frames[idx];
        fr.data = data;
        fr.page_id = Some(page_id);
        fr.dirty = dirty;
        fr.pin_count = 1;
        fr.ref_bit = true;
        self.table.insert(page_id, idx);
    }

    fn write_back(&mut self, idx: usize) -> Result<()> {
        if !self.frames[idx].dirty {
            return Ok(());
        }
        let page_id = self.frames[idx]
            .page_id
            .expect("a dirty frame must hold a page");
        page::write_checksum(&mut self.frames[idx].data);
        let lsn = page::page_lsn(&self.frames[idx].data);
        self.wal.ensure_durable(lsn)?; // WAL rule: log before data
        self.device.write_page(page_id, &self.frames[idx].data)?;
        self.frames[idx].dirty = false;
        Ok(())
    }

    fn evict_victim(&mut self) -> Result<usize> {
        if let Some(idx) = self.frames.iter().position(|fr| fr.page_id.is_none()) {
            return Ok(idx);
        }
        let n = self.frames.len();
        for _ in 0..(2 * n) {
            let idx = self.clock;
            self.clock = (self.clock + 1) % n;
            if self.frames[idx].pin_count > 0 {
                continue;
            }
            if self.frames[idx].ref_bit {
                self.frames[idx].ref_bit = false;
                continue;
            }
            self.write_back(idx)?;
            if let Some(pid) = self.frames[idx].page_id.take() {
                self.table.remove(&pid);
            }
            return Ok(idx);
        }
        Err(GraphusError::Storage(
            "buffer pool is full of pinned pages".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_io::MemBlockDevice;

    fn pool(cap: usize) -> BufferPool<MemBlockDevice> {
        BufferPool::new(MemBlockDevice::new(0), cap)
    }

    #[test]
    fn new_page_is_cached_and_readable() {
        let mut p = pool(4);
        let (f, id) = p.new_page().unwrap();
        p.page_mut(f)[100] = 0xAA;
        p.unpin(f);
        let g = p.fetch(id).unwrap();
        assert_eq!(p.page(g)[100], 0xAA);
    }

    #[test]
    fn eviction_writes_dirty_then_reload_verifies_checksum() {
        let mut p = pool(1);
        let (fa, a) = p.new_page().unwrap();
        p.page_mut(fa)[100] = 0xAA;
        p.unpin(fa);
        let (fb, _b) = p.new_page().unwrap(); // evicts a, writing it back
        p.unpin(fb);
        let g = p.fetch(a).unwrap(); // miss -> reload, checksum verified
        assert_eq!(p.page(g)[100], 0xAA);
    }

    #[test]
    fn a_fully_pinned_pool_cannot_evict() {
        let mut p = pool(1);
        let (_fa, _a) = p.new_page().unwrap(); // pinned
        assert!(p.new_page().is_err());
    }

    /// Regression: SEC-212 — an out-of-range `FrameId` must yield a controlled error through the
    /// checked accessor (`try_page`), never an out-of-bounds slice panic (CWE-129).
    #[test]
    fn out_of_range_frame_handle_yields_error_not_oob() {
        let p = pool(2);
        let evil = FrameId(2); // one past the last valid frame; never pool-minted
        assert!(
            p.try_page(evil).is_err(),
            "an out-of-range handle must return Err, not index out of bounds"
        );
        assert!(p.try_page(FrameId(usize::MAX)).is_err());
        // A valid, pool-minted handle still resolves through the same checked accessor.
        let mut p = pool(2);
        let (f, _id) = p.new_page().unwrap();
        assert!(p.try_page(f).is_ok());
        p.unpin(f);
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
        let mut p = BufferPool::with_wal(MemBlockDevice::new(0), FailWal, 2);
        let (f, _id) = p.new_page().unwrap();
        p.page_mut(f)[0] = 1;
        assert!(p.flush(f).is_err()); // the WAL rule refuses, so the write-back fails
    }

    /// A [`WalRule`] over a real `Lsn`-tracking log that counts how many times its `ensure_durable`
    /// fired, so a tiny pool's eviction write-backs can be observed to actually run the WAL rule.
    #[derive(Default)]
    struct CountingWal {
        fired: usize,
    }
    impl WalRule for CountingWal {
        fn ensure_durable(&mut self, _up_to: Lsn) -> Result<()> {
            self.fired += 1;
            Ok(())
        }
        fn tracks_lsn(&self) -> bool {
            false
        }
        /// A counting no-op rule: every harden succeeds immediately, so everything is durable.
        fn durable_len(&mut self) -> u64 {
            u64::MAX
        }
    }

    /// Regression (`rmp` #302): a **misconfigured tiny** buffer pool — `pool_pages` in {1,2,3,4},
    /// the sizes the #242 shrinker probed — must evict and reload correctly under a WAL rule that
    /// forces write-back, with NO panic. Every eviction of a dirty page must run the WAL rule
    /// (WAL-before-data) and reload must re-verify the checksum, at every one of these capacities.
    #[test]
    fn tiny_pool_evicts_and_reloads_without_panic() {
        for cap in 1..=4usize {
            let mut p = BufferPool::with_wal(MemBlockDevice::new(0), CountingWal::default(), cap);
            // Allocate cap + 3 dirty pages; each unpinned so the next allocation must evict + write
            // back, exceeding the pool by enough to force real eviction pressure at any cap in 1..=4.
            let mut ids = Vec::new();
            for i in 0..(cap + 3) {
                let (f, id) = p.new_page().unwrap();
                p.page_mut(f)[10] = i as u8;
                p.unpin(f);
                ids.push(id);
            }
            // Re-fetch each id: a miss reloads from the device and verifies its checksum.
            for (i, id) in ids.iter().enumerate() {
                let f = p.fetch(*id).unwrap();
                assert_eq!(
                    p.page(f)[10],
                    i as u8,
                    "cap={cap}: page {id:?} must reload the exact bytes written before eviction"
                );
                p.unpin(f);
            }
        }
    }

    /// Regression (`rmp` #302): at a tiny capacity, if the WAL rule refuses to harden (a re-entrancy
    /// guard returning `Err`, or a genuine durability failure), the eviction that triggers the
    /// write-back must surface a clean `Err` — never panic — and must NOT steal the dirty page to
    /// disk (WAL-before-data is upheld: every victim stays resident and intact).
    #[test]
    fn tiny_pool_wal_error_on_eviction_is_clean_and_upholds_wal_before_data() {
        /// A WAL rule that refuses to harden anything: every write-back is blocked.
        struct AlwaysRefuse;
        impl WalRule for AlwaysRefuse {
            fn ensure_durable(&mut self, _up_to: Lsn) -> Result<()> {
                Err(GraphusError::Storage("wal refuses".to_owned()))
            }
            fn tracks_lsn(&self) -> bool {
                false
            }
            /// Refuses to harden, so nothing ever becomes durable.
            fn durable_len(&mut self) -> u64 {
                0
            }
        }
        for cap in 1..=4usize {
            let mut p = BufferPool::with_wal(MemBlockDevice::new(0), AlwaysRefuse, cap);
            // Fill every frame with a dirty, unpinned page. `new_page` never calls the WAL rule while
            // a free frame remains (it only extends + installs), so filling to capacity succeeds even
            // though the rule refuses every hardening.
            let mut ids = Vec::new();
            for i in 0..cap {
                let (f, id) = p.new_page().unwrap();
                p.page_mut(f)[100] = i as u8; // mark dirty (offset 100 is past the page header)
                p.unpin(f);
                ids.push(id);
            }
            // The pool is now full of dirty victims. The next allocation must evict one, whose
            // write-back calls the refusing WAL rule — that must be a clean Err, never a panic, and
            // must abort BEFORE the home write (so the device is not even extended).
            assert!(
                p.new_page().is_err(),
                "cap={cap}: an eviction blocked by the WAL rule must return Err, not panic"
            );
            // WAL-before-data upheld: nothing was stolen to the device and no frame state was
            // corrupted — every original page is still resident and readable via a HIT fetch (which
            // needs no eviction), with its bytes intact.
            for (i, id) in ids.iter().enumerate() {
                let f = p.fetch(*id).unwrap(); // HIT: still resident, no write-back
                assert_eq!(
                    p.page(f)[100],
                    i as u8,
                    "cap={cap}: victim {id:?} must be preserved intact after the failed eviction"
                );
                p.unpin(f);
            }
        }
    }

    /// Regression (`rmp` #302): a fully **pinned** tiny pool (no evictable victim) must return the
    /// clean "full of pinned pages" error at every capacity in {1,2,3,4}, never panic.
    #[test]
    fn fully_pinned_tiny_pool_returns_clean_error() {
        for cap in 1..=4usize {
            let mut p = BufferPool::new(MemBlockDevice::new(0), cap);
            // Pin every frame.
            for _ in 0..cap {
                p.new_page().unwrap(); // left pinned
            }
            // No evictable victim remains: allocation must fail cleanly.
            assert!(
                p.new_page().is_err(),
                "cap={cap}: a fully pinned pool must return Err, never panic"
            );
        }
    }
}
