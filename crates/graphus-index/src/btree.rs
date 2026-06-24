//! A WAL-logged B+-tree over the buffer pool (`04-technical-design.md` §6.1, §6.4).
//!
//! The tree maps **order-preserving encoded keys** (see [`crate::keycodec`]) to opaque payload
//! bytes (for the index kinds, a record id). It supports point lookup, ordered range scan, insert,
//! and delete, with node split on overflow and a documented delete policy (entries are removed
//! in-place; nodes are allowed to underflow and are reclaimed only when fully empty — see
//! [`BTree::delete`]).
//!
//! ## Storage & ownership model
//!
//! Each tree lives in its own logical-page space inside a [`BufferPool`]. Page `0` of that space is
//! the **B+-tree meta page** holding the current root page id (and the format version); the root
//! is created lazily on the first insert. The tree owns no WAL itself: every mutation is logged
//! through the **same** [`SharedWal`] the pool's WAL rule enforces, so
//! the WAL-rule borrow and the logging borrow never overlap (the storage core's discipline,
//! `graphus-storage::wal_rule`): the WAL borrow is always *dropped* before any pool method that can
//! trigger a write-back. This is the single-threaded correct core; the latch-coupling /
//! crabbing / B-link concurrency discipline (`04 §6.1`) is documented in [`BTree::lookup`] and is a
//! later concurrency task, exactly as the buffer pool and record store stage it.
//!
//! ## WAL logging of index pages (`04 §6.4`)
//!
//! Index pages are ordinary logical pages, so a modification is a WAL `Update` whose redo is the
//! post-image patch of the changed page payload and whose undo is its pre-image patch — the *same*
//! intra-page `(offset, bytes)` patch encoding the record store uses ([`crate::recovery::encode_patch`]).
//! Because a structural change (split) can rewrite a whole node, the patch covers the node payload
//! (bytes after the 24-byte header up to the special area) — physiological redo, physical undo —
//! and is replayed by the very same ARIES machinery (`graphus_wal::recover`). There is no separate
//! index rebuild on crash.
//!
//! ## MVCC awareness (`04 §6.3`)
//!
//! Index entries are **not** separately versioned. A payload is an opaque candidate record id; the
//! transaction layer resolves visibility against the record's MVCC header. See the crate root for
//! the documented SIREAD / predicate-marker seam.

use std::collections::HashSet;

use graphus_bufpool::BufferPool;
use graphus_bufpool::page::{self, HEADER_SIZE};
use graphus_core::error::{GraphusError, Result};
use graphus_core::{Lsn, PageId, TxnId};
use graphus_io::{BlockDevice, PAGE_SIZE};
use graphus_wal::LogSink;

use crate::node::{
    CELL_LIMIT, Cell, NodeMut, NodeView, PAGE_TYPE_BTREE_INTERNAL, PAGE_TYPE_BTREE_LEAF,
    PAGE_TYPE_BTREE_META, SLOT_DIR_START,
};
use crate::recovery::{SharedWal, encode_patch};

/// Offset of the meta payload (root page id) within the meta page.
const META_ROOT_OFF: usize = HEADER_SIZE; // u64 root page id (0 = no root yet)
const META_VERSION_OFF: usize = HEADER_SIZE + 8; // u32 format version
const BTREE_FORMAT_VERSION: u32 = 1;

/// Byte offset of the `page_type` word within the frozen 24-byte page header (`05 §6`). The
/// bufpool keeps this private, so it is re-stated here to WAL-log the meta page's type byte (and is
/// guarded against drift by a compile-time assertion below).
const OFF_PAGE_TYPE: usize = 4;

/// Reserved system transaction id for the standalone meta-page write at `create` (mirrors
/// `graphus-storage`'s catalog `SYSTEM_TXN`): a structural change that must be durable on its own.
const SYSTEM_TXN: TxnId = TxnId(u64::MAX);

/// The page within a tree's space that always holds its meta record.
const META_PAGE_REL: u64 = 0;

/// A B+-tree over a buffer pool, with WAL-logged mutations recoverable by ARIES.
///
/// Generic over the block device `D` and the WAL sink `S`, exactly like the record store, so it
/// runs over the production file device + log and the in-memory DST device + log used by the
/// crash-recovery tests.
pub struct BTree<D: BlockDevice, S: LogSink> {
    pool: BufferPool<D, SharedWal<S>>,
    wal: SharedWal<S>,
    /// Device page id of this tree's meta page (its space base; relative page `r` maps to
    /// `base + r`). With one tree per pool today `base` is `PageId(0)`.
    base: PageId,
    /// Cached root page id (device page id); `None` until the first insert creates it.
    root: Option<PageId>,
    /// Highest device page id this tree has allocated (the on-disk image spans `0..=max_page`).
    /// Tracked so Deterministic-Simulation-Testing can snapshot every mapped page for the steal
    /// crash scenario (`04 §11`), mirroring `graphus-storage`'s `mapped_pages`.
    max_page: u64,
    /// Test/bench-only switch: when `false`, [`Self::validate_cached`] always runs the full
    /// `validate()` walk (never consults or fills the cache), so the `#[ignore]` micro-bench can
    /// measure the un-amortized "before" arm against the amortized "after" arm in one process. Has no
    /// effect on production behavior (always `true`).
    #[cfg(test)]
    validate_cache_enabled: bool,
    /// Per-page **validated-bit cache** keyed by `(PageId, page_lsn)` — the SEC-207 amortization of
    /// the slot-directory walk. A B+-tree page's content is fully determined by its `(id, page_lsn)`:
    /// every mutation stamps a fresh, strictly increasing `page_lsn` via `page::set_page_lsn` (the
    /// ARIES pageLSN, monotone within a run), so a key that is already in the set names *exactly* the
    /// bytes that previously passed [`NodeView::validate`]. The hot read paths therefore run the
    /// O(slot_count) walk **once per distinct page image** instead of once per fetch, then rely on the
    /// bounds-checked `try_*` accessors for every actual field read. See [`Self::validate_cached`] for
    /// the no-stale-skip argument and the SEC-207 sign-off.
    validated: HashSet<(PageId, Lsn)>,
}

/// Upper bound on the validated-bit cache before it is cleared wholesale. The cache is a pure
/// optimization — dropping it only forces a re-validation (never a correctness change) — so a flat
/// cap keeps its memory bounded without an LRU. A B+-tree large enough to exceed this many distinct
/// hot page images is rare; when it happens the clear costs at most one extra walk per page.
const VALIDATED_CACHE_CAP: usize = 1 << 16;

impl<D: BlockDevice, S: LogSink> BTree<D, S> {
    /// Creates a brand-new B+-tree on an empty `pool`, initialising its meta page (the tree has no
    /// root until the first [`Self::insert`]). The `pool` must already be wired to `wal` as its
    /// [`WalRule`](graphus_bufpool::WalRule).
    ///
    /// # Errors
    /// Returns a storage error if the meta page cannot be allocated or hardened.
    pub fn create(mut pool: BufferPool<D, SharedWal<S>>, wal: SharedWal<S>) -> Result<Self> {
        let (f, page_id) = pool.new_page()?;
        pool.flush(f)?; // a valid checksum lands on disk so a later fetch verifies
        pool.unpin(f);

        let mut tree = Self {
            pool,
            wal,
            base: page_id,
            root: None,
            max_page: page_id.0,
            validated: HashSet::new(),
            #[cfg(test)]
            validate_cache_enabled: true,
        };
        // WAL-log the meta page (its type byte + payload) under a committed system transaction,
        // exactly as the record store logs its catalog page (`graphus-storage`), so redo rebuilds
        // the meta page on a no-force crash (it was never flushed home) — there is no separate index
        // rebuild (`04 §6.4`).
        tree.wal.with(|w| {
            w.begin(SYSTEM_TXN);
        });
        tree.init_meta(SYSTEM_TXN)?;
        tree.wal.with(|w| w.commit(SYSTEM_TXN))?;
        Ok(tree)
    }

    /// Writes the meta page's type byte (header offset 4) and payload (root pointer = none, format
    /// version) as WAL-logged updates under `txn`, so a no-force recovery reconstructs both.
    fn init_meta(&mut self, txn: TxnId) -> Result<()> {
        // Log the page-type byte so it survives a no-force crash (a `0..=PAGE_SIZE` patch may target
        // any offset, including the 24-byte header).
        let type_off = OFF_PAGE_TYPE;
        let f = self.pool.fetch(self.base)?;
        let pre_type = self.pool.page(f)[type_off];
        let redo_t = encode_patch(type_off, &[PAGE_TYPE_BTREE_META]);
        let undo_t = encode_patch(type_off, &[pre_type]);
        let lsn_t = self
            .wal
            .with(|w| w.log_update(txn, self.base, redo_t, undo_t));
        {
            let p = self.pool.page_mut(f);
            page::set_page_type(p, PAGE_TYPE_BTREE_META);
            page::set_page_lsn(p, lsn_t);
        }
        // Log the meta payload.
        let pre = self.pool.page(f)[META_ROOT_OFF..META_VERSION_OFF + 4].to_vec();
        let mut post = Vec::with_capacity(12);
        post.extend_from_slice(&0u64.to_le_bytes()); // root = none
        post.extend_from_slice(&BTREE_FORMAT_VERSION.to_le_bytes());
        let redo = encode_patch(META_ROOT_OFF, &post);
        let undo = encode_patch(META_ROOT_OFF, &pre);
        let lsn = self.wal.with(|w| w.log_update(txn, self.base, redo, undo));
        let p = self.pool.page_mut(f);
        p[META_ROOT_OFF..META_ROOT_OFF + 8].copy_from_slice(&post[0..8]);
        p[META_VERSION_OFF..META_VERSION_OFF + 4].copy_from_slice(&post[8..12]);
        page::set_page_lsn(p, lsn);
        self.pool.unpin(f);
        Ok(())
    }

    /// Reopens an existing B+-tree after recovery, reading its root from the durable meta page.
    ///
    /// # Errors
    /// Returns a storage error if the meta page is missing or not a B+-tree meta page.
    pub fn open(
        mut pool: BufferPool<D, SharedWal<S>>,
        wal: SharedWal<S>,
        base: PageId,
    ) -> Result<Self> {
        let f = pool.fetch(base)?;
        let p = pool.page(f);
        if page::page_type(p) != PAGE_TYPE_BTREE_META {
            pool.unpin(f);
            return Err(GraphusError::Storage(
                "B+-tree base page is not a meta page".to_owned(),
            ));
        }
        let version = read_u32(p, META_VERSION_OFF);
        if version != BTREE_FORMAT_VERSION {
            pool.unpin(f);
            return Err(GraphusError::Storage(format!(
                "unsupported B+-tree format version {version}"
            )));
        }
        let root_raw = read_u64(p, META_ROOT_OFF);
        pool.unpin(f);
        let root = (root_raw != 0).then_some(PageId(root_raw));
        let mut tree = Self {
            pool,
            wal,
            base,
            root,
            max_page: base.0,
            validated: HashSet::new(),
            #[cfg(test)]
            validate_cache_enabled: true,
        };
        // Discover the highest reachable page id so the on-disk image can be re-snapshotted.
        tree.max_page = tree.discover_max_page()?;
        Ok(tree)
    }

    /// Walks every reachable node to find the highest device page id (test/DST support).
    fn discover_max_page(&mut self) -> Result<u64> {
        let mut max = self.base.0;
        if let Some(root) = self.root {
            let mut stack = vec![root];
            while let Some(p) = stack.pop() {
                max = max.max(p.0);
                let f = self.pool.fetch(p)?;
                let is_leaf = NodeView::new(self.pool.page(f)).is_leaf();
                // SEC-203: validate an internal node's slot directory before reading its child
                // slots. A page that is corrupt yet CRC-valid (an adversarially tampered
                // index/backup file) would otherwise drive an out-of-bounds panic here during
                // `BTree::open`, crashing the server at startup/recovery. A malformed internal node
                // surfaces as a `Storage` error. Leaves are not slot-accessed by this walk, so they
                // are validated by the read/write paths that do touch their slots (SEC-206).
                // Cached by `(id, page_lsn)` (SEC-207).
                if !is_leaf {
                    if let Err(e) = self.validate_cached(p, f) {
                        self.pool.unpin(f);
                        return Err(e);
                    }
                    let v = NodeView::new(self.pool.page(f));
                    let lm = v.leftmost_child();
                    if lm != 0 {
                        stack.push(PageId(lm));
                    }
                    for i in 0..v.slot_count() {
                        let c = v.child(i);
                        if c != 0 {
                            stack.push(PageId(c));
                        }
                    }
                }
                self.pool.unpin(f);
            }
        }
        Ok(max)
    }

    /// The device page id of this tree's meta/base page.
    #[must_use]
    pub fn base(&self) -> PageId {
        self.base
    }

    /// Runs `f` with the shared WAL manager (test/inspection helper, mirrors the record store).
    pub fn with_wal<R>(&self, f: impl FnOnce(&mut graphus_wal::WalManager<S>) -> R) -> R {
        self.wal.with(f)
    }

    /// Flushes every dirty page home (respecting the WAL rule) and syncs the device.
    ///
    /// # Errors
    /// Propagates a buffer-pool or device error.
    pub fn flush(&mut self) -> Result<()> {
        self.pool.flush_all()
    }

    /// The device `PageId`s this tree currently maps (`0..=max_page`). A DST helper to snapshot the
    /// on-disk image after a (partial) flush for the steal crash scenario (`04 §11`), mirroring
    /// `graphus-storage::RecordStore::mapped_pages`.
    #[must_use]
    pub fn mapped_pages(&self) -> Vec<PageId> {
        (0..=self.max_page).map(PageId).collect()
    }

    /// Reads device page `page` through the pool (verifying its checksum), returning its bytes. A
    /// DST helper for snapshotting the on-disk image (`04 §11`).
    ///
    /// # Errors
    /// Returns a storage error if the page is missing or fails checksum verification.
    pub fn read_device_page(&mut self, page: PageId) -> Result<Box<graphus_io::Page>> {
        let f = self.pool.fetch(page)?;
        let bytes = Box::new(*self.pool.page(f));
        self.pool.unpin(f);
        Ok(bytes)
    }

    /// Validates a freshly fetched node **at most once per distinct page image** (SEC-207).
    ///
    /// The key is `(page_id, page::page_lsn(bytes))`. Because every B+-tree mutation stamps a fresh,
    /// strictly increasing `page_lsn` (`page::set_page_lsn`, the ARIES pageLSN), that pair is a
    /// content hash: the same key can only ever name the *same* slot directory that previously passed
    /// [`NodeView::validate`]. So a cache hit is sound to skip — there is **no stale skip**:
    /// - A page that is mutated gets a new `page_lsn`, hence a new key, hence a forced re-validation
    ///   (a cached entry for the old LSN can never be matched by the new bytes).
    /// - A page re-fetched after eviction carries the same `(id, lsn)` only if its bytes are the same
    ///   image (the buffer pool verifies the CRC on the cold read, so a corrupted re-read is rejected
    ///   before it ever reaches here — see the SEC-207 layer argument below).
    ///
    /// ## SEC-207 sign-off (defense-in-depth invariants)
    ///
    /// The full per-read walk is *amortized*, not removed, and the hot path stays memory-safe under an
    /// adversarially forged-but-CRC-valid page because three independent layers each hold:
    /// 1. **Page CRC (cold path, `graphus_bufpool`):** every fetch from the device verifies the
    ///    CRC32C body checksum, catching bit-rot / truncation before the bytes enter this layer. A
    ///    forged page must therefore carry a *recomputed* valid CRC to reach validation at all.
    /// 2. **validate-at-fetch (this method):** the first time a given `(id, lsn)` image is seen, the
    ///    O(slot_count) [`NodeView::validate`] runs and rejects any slot directory whose cells fall
    ///    outside the heap region — so a forged image surfaces as a `Storage` error, never a panic.
    /// 3. **`try_*` bounds checks (every field read):** even if validation were somehow bypassed, the
    ///    accessors actually used on the hot search path — [`NodeView::key`]/[`value`]/[`child`] —
    ///    delegate to [`NodeView::try_key`]/[`try_value`]/[`try_child`], which `get(off..end)` on the
    ///    page slice and return `None` (a graceful expect-message panic, never UB / OOB read) on any
    ///    out-of-range offset. The amortized walk can thus only ever turn a *panic that validate would
    ///    have caught* into a *different panic the accessor catches* — it can **never** introduce an
    ///    out-of-bounds slice or undefined behavior that `try_*` would not already stop.
    ///
    /// Net: removing the per-read full walk is safe precisely because every field access on the
    /// relaxed hot path is bounds-checked by `try_*`, and the CRC + validate-at-fetch layers keep a
    /// forged image from corrupting *results*.
    fn validate_cached(&mut self, page_id: PageId, f: graphus_bufpool::FrameId) -> Result<()> {
        // The frame `f` is already pinned by the caller; the page header (and thus the LSN) is part of
        // those bytes, so the cache key is read with no extra pin churn.
        let v = NodeView::new(self.pool.page(f));
        let key = (page_id, Lsn(v.page_lsn()));
        #[cfg(test)]
        if !self.validate_cache_enabled {
            // Bench "before" arm: always pay the full walk, never cache.
            return v.validate();
        }
        if self.validated.contains(&key) {
            return Ok(());
        }
        v.validate()?;
        if self.validated.len() >= VALIDATED_CACHE_CAP {
            self.validated.clear();
        }
        self.validated.insert(key);
        Ok(())
    }

    /// Test/bench-only: toggle the validated-bit cache (see [`Self::validate_cache_enabled`]).
    #[cfg(test)]
    fn set_validate_cache_enabled(&mut self, on: bool) {
        self.validate_cache_enabled = on;
        if !on {
            self.validated.clear();
        }
    }

    /// Allocates a fresh page through the pool, tracking the high-water mark for [`Self::mapped_pages`].
    fn alloc_page(&mut self) -> Result<(graphus_bufpool::FrameId, PageId)> {
        let (f, id) = self.pool.new_page()?;
        self.max_page = self.max_page.max(id.0);
        Ok((f, id))
    }

    // --------------------------------------------------------------------- read

    /// Looks up the payload bytes stored for `key`, or `None`.
    ///
    /// Descent reads each node, binary-searches its directory, and follows the child pointer; at a
    /// leaf it returns the exact-match payload. Under the future concurrent pool this descent uses
    /// **latch coupling** (acquire the child latch before releasing the parent) and the **B-link**
    /// right-sibling pointer to retry a node that split out from under the descent (`04 §6.1`);
    /// the single-threaded core here needs neither, but the right-sibling links are maintained so
    /// the discipline drops in unchanged.
    ///
    /// # Errors
    /// Propagates a buffer-pool fetch error.
    pub fn lookup(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(root) = self.root else {
            return Ok(None);
        };
        let leaf = self.descend_to_leaf(root, key)?;
        let f = self.pool.fetch(leaf)?;
        // Validate at most once per distinct page image (SEC-207); the hot find_exact/value below
        // then runs over the validated directory. `descend_to_leaf` already validated this leaf, so
        // this is a cache hit in the common case.
        if let Err(e) = self.validate_cached(leaf, f) {
            self.pool.unpin(f);
            return Err(e);
        }
        let v = NodeView::new(self.pool.page(f));
        let out = Ok(v.find_exact(key).map(|i| v.value(i).to_vec()));
        self.pool.unpin(f);
        out
    }

    /// Collects all `(key, value)` entries with `lo <= key < hi` in ascending key order
    /// (half-open range). `lo`/`hi` are encoded keys; pass an empty `hi` slice for "unbounded
    /// above" via [`Self::range_from`].
    ///
    /// The scan finds the leaf containing `lo`, then walks the **right-sibling chain** emitting
    /// in-order entries until it passes `hi`. This is the O(result) range seek a planner range
    /// predicate compiles to.
    ///
    /// # Errors
    /// Propagates a buffer-pool fetch error.
    pub fn range(&mut self, lo: &[u8], hi: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.range_impl(lo, Some(hi))
    }

    /// Like [`Self::range`] but unbounded above (`key >= lo`).
    ///
    /// # Errors
    /// Propagates a buffer-pool fetch error.
    pub fn range_from(&mut self, lo: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.range_impl(lo, None)
    }

    /// All entries in ascending key order.
    ///
    /// # Errors
    /// Propagates a buffer-pool fetch error.
    pub fn scan_all(&mut self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.range_impl(&[], None)
    }

    fn range_impl(&mut self, lo: &[u8], hi: Option<&[u8]>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        use std::cell::RefCell;
        // PERF/I3: a multi-leaf scan reserves each leaf's contribution up front (see
        // `range_for_each_impl`'s `on_leaf` hook) so `out` grows in leaf-sized steps. The visitor
        // emits keys/values in exactly the eager order, so the collected `Vec` is byte-identical to
        // the prior hand-rolled loop (the `streaming_form_matches_eager_form` regression asserts it).
        // The `on_leaf` reserve hook and the per-row push both mutate `out`, so it is shared through a
        // single-threaded `RefCell` (the two closures borrow it disjointly in time).
        let out: RefCell<Vec<(Vec<u8>, Vec<u8>)>> = RefCell::new(Vec::new());
        self.range_for_each_impl(
            lo,
            hi,
            |hint| out.borrow_mut().reserve(hint),
            |k, v| out.borrow_mut().push((k.to_vec(), v.to_vec())),
        )?;
        Ok(out.into_inner())
    }

    /// Visits every `(key, value)` entry with `lo <= key < hi` (half-open; pass `None` for `hi` to
    /// mean "unbounded above"), in ascending key order, **without allocating an owned pair per row**.
    ///
    /// This is the allocation-free streaming twin of [`Self::range`]: the prior eager form returned a
    /// `Vec<(Vec<u8>, Vec<u8>)>` — two heap allocations per entry — even when the caller only needed
    /// to decode an 8-byte rid out of each value and threw the key copy away (`TokenIndex::scan_token`,
    /// `PropertyIndex::seek_*`/`build_histogram`). `range_for_each` instead hands the caller borrowed
    /// **slices** into the live leaf page, so a caller that decodes-and-discards pays **zero** per-row
    /// allocations.
    ///
    /// The visitor `f(&key, &value)` is invoked **exactly once per matching entry, in the same order
    /// and over the same bytes** the eager [`Self::range`] would have collected — it is a pure
    /// allocation optimization, never a behavioral change.
    ///
    /// ## Slice lifetime vs. page latch (soundness)
    ///
    /// Each yielded `&[u8]` borrows the bytes of the leaf page currently **pinned** in the buffer pool.
    /// The scan keeps that page pinned (`fetch` … `unpin`) across the whole inner loop, so every
    /// `f(k, v)` call for that leaf runs *while the page is valid*; only **after** the last entry of a
    /// leaf is visited does the scan `unpin` it and fetch the next right-sibling. The borrowed slice
    /// therefore cannot outlive the pin — the higher-ranked `FnMut(&[u8], &[u8])` bound prevents the
    /// closure from smuggling a slice out (it would not name a lifetime long enough), so a caller can
    /// only *use* the bytes during the callback (typically copying out a decoded id). This mirrors the
    /// existing latch discipline of [`Self::range_impl`], which copies each cell out before unpinning.
    ///
    /// # Errors
    /// Propagates a buffer-pool fetch error (or a `Storage` error from a forged-but-CRC-valid page).
    pub fn range_for_each<F: FnMut(&[u8], &[u8])>(
        &mut self,
        lo: &[u8],
        hi: &[u8],
        f: F,
    ) -> Result<()> {
        self.range_for_each_impl(lo, Some(hi), |_| {}, f)
    }

    /// Like [`Self::range_for_each`] but unbounded above (`key >= lo`).
    ///
    /// # Errors
    /// Propagates a buffer-pool fetch error.
    pub fn range_from_for_each<F: FnMut(&[u8], &[u8])>(&mut self, lo: &[u8], f: F) -> Result<()> {
        self.range_for_each_impl(lo, None, |_| {}, f)
    }

    /// Visits every entry in ascending key order (the streaming twin of [`Self::scan_all`]).
    ///
    /// # Errors
    /// Propagates a buffer-pool fetch error.
    pub fn scan_all_for_each<F: FnMut(&[u8], &[u8])>(&mut self, f: F) -> Result<()> {
        self.range_for_each_impl(&[], None, |_| {}, f)
    }

    /// The single scan engine behind both the eager `range_*` collectors and the streaming
    /// `range_*_for_each` visitors. `on_leaf(hint)` is called once per visited leaf with the number of
    /// entries it will contribute (so the eager collector can reserve), then `f(key, value)` is called
    /// for each matching entry while its leaf is pinned. Keeping one engine guarantees the eager and
    /// streaming forms visit byte-identical keys/values in identical order.
    fn range_for_each_impl<H: FnMut(usize), F: FnMut(&[u8], &[u8])>(
        &mut self,
        lo: &[u8],
        hi: Option<&[u8]>,
        mut on_leaf: H,
        mut f: F,
    ) -> Result<()> {
        let Some(root) = self.root else {
            return Ok(());
        };
        let mut leaf = self.descend_to_leaf(root, lo)?;
        loop {
            let fr = self.pool.fetch(leaf)?;
            if let Err(e) = self.validate_cached(leaf, fr) {
                self.pool.unpin(fr);
                return Err(e);
            }
            let v = NodeView::new(self.pool.page(fr));
            let start = v.lower_bound(lo);
            on_leaf(v.slot_count().saturating_sub(start));
            let mut passed_hi = false;
            for i in start..v.slot_count() {
                // `k`/`val` borrow the pinned page `fr`; the closure runs here, before any `unpin`,
                // so the borrowed slices are always valid (see `range_for_each` soundness note).
                let k = v.key(i);
                if let Some(h) = hi {
                    if !h.is_empty() && k >= h {
                        passed_hi = true;
                        break;
                    }
                }
                f(k, v.value(i));
            }
            let next = v.right_sibling();
            self.pool.unpin(fr);
            if passed_hi || next == 0 {
                break;
            }
            leaf = PageId(next);
        }
        Ok(())
    }

    /// Descends from `from` to the leaf that would contain `key`.
    fn descend_to_leaf(&mut self, from: PageId, key: &[u8]) -> Result<PageId> {
        let mut cur = from;
        loop {
            let f = self.pool.fetch(cur)?;
            if let Err(e) = self.validate_cached(cur, f) {
                self.pool.unpin(f);
                return Err(e);
            }
            let v = NodeView::new(self.pool.page(f));
            if v.is_leaf() {
                self.pool.unpin(f);
                return Ok(cur);
            }
            let child = v.child_for(key);
            self.pool.unpin(f);
            if child == 0 {
                return Err(GraphusError::Storage(
                    "B+-tree internal node has a null child pointer".to_owned(),
                ));
            }
            cur = PageId(child);
        }
    }

    // -------------------------------------------------------------------- write

    /// Inserts or replaces the entry `(key, value)` under transaction `txn`. WAL-logged and
    /// recoverable.
    ///
    /// On a leaf overflow the leaf splits, a separator is pushed into the parent, and splits
    /// cascade upward; a root split grows the tree by one level. The right-sibling chain is
    /// maintained across splits so range scans stay correct.
    ///
    /// # Errors
    /// Propagates a buffer-pool or WAL failure, or [`GraphusError::Storage`] if a single
    /// `(key, value)` is too large to ever fit a leaf.
    pub fn insert(&mut self, txn: TxnId, key: &[u8], value: &[u8]) -> Result<()> {
        let root = match self.root {
            Some(r) => r,
            None => self.create_root(txn)?,
        };
        match self.insert_descend(txn, root, key, value)? {
            None => Ok(()),
            Some(split) => self.grow_root(txn, root, split),
        }
    }

    /// Removes the entry for `key` under `txn`, returning `true` if it was present. WAL-logged.
    ///
    /// **Delete policy (documented):** the entry is removed in-place from its leaf; the leaf is
    /// allowed to underflow (no eager rebalancing/merge), which keeps deletes O(height) and
    /// crash-recovery simple. A leaf that becomes empty stays linked in the right-sibling chain.
    /// Point and range correctness are unaffected by an underfull-but-sorted leaf, which the
    /// property tests assert against a `BTreeMap` model across long delete sequences.
    ///
    /// **Page reclamation (audited — rmp #222):** because the page allocator is append-only (no
    /// free-list), an emptied leaf's page is not returned to the device here. A storage-engine audit
    /// established this is a *bounded* space amplification, never an ACID/correctness defect:
    /// - **Common case (delete-then-reinsert churn):** the emptied-but-linked leaf is **reused** —
    ///   parent separators are unchanged, so a later in-range key routes back to the same physical
    ///   page and refills it. Net page leak is **zero** (see the `btree_props` reclamation tests).
    /// - **Worst case (delete-without-reinsert on a monotonic key space — time-series/TTL):** the
    ///   drained leaves are stranded for the database's lifetime.
    ///
    /// Whole-page reclamation needs a persistent free-list plus a crash-safe empty-leaf unlink
    /// (`04 §6.3` GC), tracked as a dedicated feature (rmp #225) rather than landed inline here: its
    /// worst-case crash behaviour must be proven never to leave a page both reachable and
    /// free-listed before it can touch the certified recovery path.
    ///
    /// # Errors
    /// Propagates a buffer-pool or WAL failure.
    pub fn delete(&mut self, txn: TxnId, key: &[u8]) -> Result<bool> {
        let Some(root) = self.root else {
            return Ok(false);
        };
        let leaf = self.descend_to_leaf(root, key)?;
        let f = self.pool.fetch(leaf)?;
        // SEC-206: validate the leaf before probing its slots. `descend_to_leaf` validates every
        // node it routes *through*, but the destination leaf is read here for the first time; a
        // forged-but-CRC-valid leaf would otherwise panic OOB inside `find_exact`. Reject it as a
        // `Storage` error instead of crashing on a `delete`. (Cached by `(id, page_lsn)`, SEC-207.)
        if let Err(e) = self.validate_cached(leaf, f) {
            self.pool.unpin(f);
            return Err(e);
        }
        let present = NodeView::new(self.pool.page(f)).find_exact(key).is_some();
        if !present {
            self.pool.unpin(f);
            return Ok(false);
        }
        // Edit a scratch copy, then log+apply the payload patch.
        let mut scratch = self.payload_copy(f);
        {
            let mut n = NodeMut::new(&mut scratch);
            let _ = n.leaf_remove(key);
            n.compact();
        }
        self.log_and_apply_payload(txn, leaf, f, &scratch)?;
        self.pool.unpin(f);
        Ok(true)
    }

    /// Recursive insert. Returns `Some((sep_key, right_page))` if `node` split and the parent must
    /// absorb the separator.
    fn insert_descend(
        &mut self,
        txn: TxnId,
        node: PageId,
        key: &[u8],
        value: &[u8],
    ) -> Result<Option<(Vec<u8>, PageId)>> {
        let f = self.pool.fetch(node)?;
        // SEC-206: validate the node before any slot access (read of cells on the leaf path, or
        // `child_for` on the internal path). The write descent does not go through the validating
        // `descend_to_leaf`, so a forged-but-CRC-valid page would otherwise panic OOB on an
        // `insert`. Reject it as a `Storage` error. (Cached by `(id, page_lsn)`, SEC-207.)
        if let Err(e) = self.validate_cached(node, f) {
            self.pool.unpin(f);
            return Err(e);
        }
        let is_leaf = NodeView::new(self.pool.page(f)).is_leaf();

        if is_leaf {
            let mut scratch = self.payload_copy(f);
            let fits = {
                let mut n = NodeMut::new(&mut scratch);
                n.leaf_insert(key, value)
            };
            if fits {
                self.log_and_apply_payload(txn, node, f, &scratch)?;
                self.pool.unpin(f);
                return Ok(None);
            }
            // Overflow: split this leaf.
            self.pool.unpin(f);
            return self.split_leaf(txn, node, key, value).map(Some);
        }

        // Internal: route to the child, recurse, then possibly absorb a child split.
        let child = NodeView::new(self.pool.page(f)).child_for(key);
        self.pool.unpin(f);
        if child == 0 {
            return Err(GraphusError::Storage(
                "B+-tree internal node has a null child pointer".to_owned(),
            ));
        }
        let Some((sep, right)) = self.insert_descend(txn, PageId(child), key, value)? else {
            return Ok(None);
        };
        // Insert the separator into this internal node.
        let f = self.pool.fetch(node)?;
        let mut scratch = self.payload_copy(f);
        let fits = {
            let mut n = NodeMut::new(&mut scratch);
            n.internal_insert(&sep, right.0)
        };
        if fits {
            self.log_and_apply_payload(txn, node, f, &scratch)?;
            self.pool.unpin(f);
            return Ok(None);
        }
        self.pool.unpin(f);
        self.split_internal(txn, node, &sep, right).map(Some)
    }

    /// Splits a full leaf `node` while inserting `(key, value)`, returning the median separator and
    /// the new right leaf. Maintains the right-sibling chain.
    fn split_leaf(
        &mut self,
        txn: TxnId,
        node: PageId,
        key: &[u8],
        value: &[u8],
    ) -> Result<(Vec<u8>, PageId)> {
        // Gather all existing cells + the new one, merged in sorted order.
        let f = self.pool.fetch(node)?;
        let mut cells = self.read_cells(f);
        let old_right = NodeView::new(self.pool.page(f)).right_sibling();
        self.pool.unpin(f);

        let new_cell = Cell {
            key: key.to_vec(),
            value: value.to_vec(),
            child: 0,
        };
        // Replace if the key already exists (leaf_insert would have replaced; preserve that).
        match cells.binary_search_by(|c| c.key.as_slice().cmp(key)) {
            Ok(i) => cells[i] = new_cell,
            Err(i) => cells.insert(i, new_cell),
        }
        if cells.len() < 2 {
            return Err(GraphusError::Storage(
                "key/value pair too large for a B+-tree leaf".to_owned(),
            ));
        }
        let mid = cells.len() / 2;
        let sep = cells[mid].key.clone();
        let (left_cells, right_cells) = cells.split_at(mid);

        // Allocate the new right leaf.
        let (rf, right_id) = self.alloc_page()?;
        {
            let mut rn = NodeMut::new(self.pool.page_mut(rf));
            rn.init(0);
            rn.set_right_sibling(old_right);
            if !rn.append_cells(right_cells) {
                self.pool.unpin(rf);
                return Err(GraphusError::Storage(
                    "right leaf overflow during split".to_owned(),
                ));
            }
            page::set_page_type(self.pool.page_mut(rf), PAGE_TYPE_BTREE_LEAF);
        }
        // Log the right leaf's full payload (it is freshly built; pre-image is the zeroed page).
        self.log_and_apply_new(txn, right_id, rf)?;
        self.pool.unpin(rf);

        // Rewrite the left leaf to its half and point its right-sibling at the new leaf.
        let lf = self.pool.fetch(node)?;
        let mut scratch = self.payload_copy(lf);
        {
            let mut ln = NodeMut::new(&mut scratch);
            ln.init(0);
            ln.set_right_sibling(right_id.0);
            if !ln.append_cells(left_cells) {
                self.pool.unpin(lf);
                return Err(GraphusError::Storage(
                    "left leaf overflow during split".to_owned(),
                ));
            }
        }
        self.log_and_apply_payload(txn, node, lf, &scratch)?;
        self.pool.unpin(lf);

        Ok((sep, right_id))
    }

    /// Splits a full internal `node` while inserting separator `(sep, right_child)`.
    fn split_internal(
        &mut self,
        txn: TxnId,
        node: PageId,
        sep: &[u8],
        right_child: PageId,
    ) -> Result<(Vec<u8>, PageId)> {
        let f = self.pool.fetch(node)?;
        let mut cells = self.read_cells(f);
        let leftmost = NodeView::new(self.pool.page(f)).leftmost_child();
        let old_right_sibling = NodeView::new(self.pool.page(f)).right_sibling();
        let level = NodeView::new(self.pool.page(f)).level();
        self.pool.unpin(f);

        let new_cell = Cell {
            key: sep.to_vec(),
            value: Vec::new(),
            child: right_child.0,
        };
        match cells.binary_search_by(|c| c.key.as_slice().cmp(sep)) {
            Ok(i) => cells[i] = new_cell,
            Err(i) => cells.insert(i, new_cell),
        }
        // For an internal split the median key moves *up* (it is not kept in either child).
        let mid = cells.len() / 2;
        let up_key = cells[mid].key.clone();
        let up_child = cells[mid].child; // becomes the new right node's leftmost child
        let left_cells = cells[..mid].to_vec();
        let right_cells = cells[mid + 1..].to_vec();

        // New right internal node.
        let (rf, right_id) = self.alloc_page()?;
        {
            let mut rn = NodeMut::new(self.pool.page_mut(rf));
            rn.init(level);
            rn.set_leftmost_child(up_child);
            rn.set_right_sibling(old_right_sibling);
            if !rn.append_cells(&right_cells) {
                self.pool.unpin(rf);
                return Err(GraphusError::Storage(
                    "right internal overflow during split".to_owned(),
                ));
            }
            page::set_page_type(self.pool.page_mut(rf), PAGE_TYPE_BTREE_INTERNAL);
        }
        self.log_and_apply_new(txn, right_id, rf)?;
        self.pool.unpin(rf);

        // Rewrite the left internal node.
        let lf = self.pool.fetch(node)?;
        let mut scratch = self.payload_copy(lf);
        {
            let mut ln = NodeMut::new(&mut scratch);
            ln.init(level);
            ln.set_leftmost_child(leftmost);
            ln.set_right_sibling(right_id.0);
            if !ln.append_cells(&left_cells) {
                self.pool.unpin(lf);
                return Err(GraphusError::Storage(
                    "left internal overflow during split".to_owned(),
                ));
            }
        }
        self.log_and_apply_payload(txn, node, lf, &scratch)?;
        self.pool.unpin(lf);

        Ok((up_key, right_id))
    }

    /// Grows the tree by one level after the root split into `(old_root, (sep, right))`.
    fn grow_root(&mut self, txn: TxnId, old_root: PageId, split: (Vec<u8>, PageId)) -> Result<()> {
        let (sep, right) = split;
        let old_level = {
            let f = self.pool.fetch(old_root)?;
            let l = NodeView::new(self.pool.page(f)).level();
            self.pool.unpin(f);
            l
        };
        let (nf, new_root) = self.alloc_page()?;
        {
            let mut n = NodeMut::new(self.pool.page_mut(nf));
            n.init(old_level + 1);
            n.set_leftmost_child(old_root.0);
            if !n.internal_insert(&sep, right.0) {
                self.pool.unpin(nf);
                return Err(GraphusError::Storage(
                    "new root could not hold the first separator".to_owned(),
                ));
            }
            page::set_page_type(self.pool.page_mut(nf), PAGE_TYPE_BTREE_INTERNAL);
        }
        self.log_and_apply_new(txn, new_root, nf)?;
        self.pool.unpin(nf);
        self.set_root(txn, new_root)?;
        Ok(())
    }

    /// Creates the first (leaf) root.
    fn create_root(&mut self, txn: TxnId) -> Result<PageId> {
        let (f, root) = self.alloc_page()?;
        {
            let mut n = NodeMut::new(self.pool.page_mut(f));
            n.init(0);
            page::set_page_type(self.pool.page_mut(f), PAGE_TYPE_BTREE_LEAF);
        }
        self.log_and_apply_new(txn, root, f)?;
        self.pool.unpin(f);
        self.set_root(txn, root)?;
        Ok(root)
    }

    /// Persists the root page id into the meta page (WAL-logged) and updates the cache.
    fn set_root(&mut self, txn: TxnId, root: PageId) -> Result<()> {
        let f = self.pool.fetch(self.base)?;
        let pre = self.pool.page(f)[META_ROOT_OFF..META_ROOT_OFF + 8].to_vec();
        let post = root.0.to_le_bytes().to_vec();
        let redo = encode_patch(META_ROOT_OFF, &post);
        let undo = encode_patch(META_ROOT_OFF, &pre);
        let lsn = self.wal.with(|w| w.log_update(txn, self.base, redo, undo));
        let p = self.pool.page_mut(f);
        p[META_ROOT_OFF..META_ROOT_OFF + 8].copy_from_slice(&post);
        page::set_page_lsn(p, lsn);
        self.pool.unpin(f);
        self.root = Some(root);
        Ok(())
    }

    // ------------------------------------------------------------ WAL plumbing

    /// A **full-page** scratch copy of the node, edited via [`NodeMut`] (which uses page-absolute
    /// offsets, including the special area at the page end). The change is logged through
    /// [`Self::log_and_apply_payload`], which extracts only the payload region for the WAL patch.
    fn payload_copy(&self, f: graphus_bufpool::FrameId) -> Vec<u8> {
        self.pool.page(f).to_vec()
    }

    /// Reads all cells out of a node frame.
    fn read_cells(&self, f: graphus_bufpool::FrameId) -> Vec<Cell> {
        let v = NodeView::new(self.pool.page(f));
        (0..v.slot_count()).map(|i| v.cell(i)).collect()
    }

    /// WAL-logs the change of `page`'s payload to `full_page_post`'s payload region (post-image),
    /// with the page's current payload as the undo image, then applies the post-image to the cached
    /// frame and stamps the new `page_lsn`. `full_page_post` is a [`Self::payload_copy`] full-page
    /// scratch; only its `[HEADER_SIZE..PAGE_SIZE]` region (the node body, including the special
    /// area) is logged. The WAL borrow is dropped before any pool write path runs.
    fn log_and_apply_payload(
        &mut self,
        txn: TxnId,
        page: PageId,
        f: graphus_bufpool::FrameId,
        full_page_post: &[u8],
    ) -> Result<()> {
        let post = &full_page_post[HEADER_SIZE..PAGE_SIZE];
        let pre = self.pool.page(f)[HEADER_SIZE..PAGE_SIZE].to_vec();
        let redo = encode_patch(HEADER_SIZE, post);
        let undo = encode_patch(HEADER_SIZE, &pre);
        let lsn = self.wal.with(|w| w.log_update(txn, page, redo, undo));
        let p = self.pool.page_mut(f);
        p[HEADER_SIZE..PAGE_SIZE].copy_from_slice(post);
        page::set_page_lsn(p, lsn);
        Ok(())
    }

    /// WAL-logs a freshly built page (its current frame content is the post-image; the undo image
    /// is the zeroed payload it had before allocation, so undo reverts the page to empty). Used for
    /// split-created and root pages.
    fn log_and_apply_new(
        &mut self,
        txn: TxnId,
        page: PageId,
        f: graphus_bufpool::FrameId,
    ) -> Result<()> {
        let post = self.pool.page(f)[HEADER_SIZE..PAGE_SIZE].to_vec();
        let zero = vec![0u8; PAGE_SIZE - HEADER_SIZE];
        let redo = encode_patch(HEADER_SIZE, &post);
        let undo = encode_patch(HEADER_SIZE, &zero);
        let lsn = self.wal.with(|w| w.log_update(txn, page, redo, undo));
        page::set_page_lsn(self.pool.page_mut(f), lsn);
        Ok(())
    }

    // ------------------------------------------------------- structural checks

    /// Validates the structural invariants (test/inspection helper):
    /// every node's keys are sorted; the leaf right-sibling chain links all leaves in key order
    /// with no key out of order across leaves.
    ///
    /// # Errors
    /// Returns a description of the first invariant violated.
    pub fn check_invariants(&mut self) -> Result<()> {
        let Some(root) = self.root else {
            return Ok(());
        };
        // Walk every node reachable; check sortedness.
        self.check_node_sorted(root)?;
        // Walk the leaf chain and check global ordering.
        let mut leaf = self.leftmost_leaf(root)?;
        let mut last: Option<Vec<u8>> = None;
        loop {
            let f = self.pool.fetch(leaf)?;
            let v = NodeView::new(self.pool.page(f));
            for i in 0..v.slot_count() {
                let k = v.key(i).to_vec();
                if let Some(prev) = &last {
                    if &k <= prev {
                        self.pool.unpin(f);
                        return Err(GraphusError::Storage(
                            "leaf chain keys not globally ascending".to_owned(),
                        ));
                    }
                }
                last = Some(k);
            }
            let next = v.right_sibling();
            self.pool.unpin(f);
            if next == 0 {
                break;
            }
            leaf = PageId(next);
        }
        Ok(())
    }

    fn check_node_sorted(&mut self, node: PageId) -> Result<()> {
        let f = self.pool.fetch(node)?;
        let v = NodeView::new(self.pool.page(f));
        for i in 1..v.slot_count() {
            if v.key(i - 1) >= v.key(i) {
                self.pool.unpin(f);
                return Err(GraphusError::Storage("node keys not sorted".to_owned()));
            }
        }
        let is_leaf = v.is_leaf();
        let children: Vec<u64> = if is_leaf {
            Vec::new()
        } else {
            let mut c = vec![v.leftmost_child()];
            c.extend((0..v.slot_count()).map(|i| v.child(i)));
            c
        };
        self.pool.unpin(f);
        for c in children {
            if c != 0 {
                self.check_node_sorted(PageId(c))?;
            }
        }
        Ok(())
    }

    fn leftmost_leaf(&mut self, from: PageId) -> Result<PageId> {
        let mut cur = from;
        loop {
            let f = self.pool.fetch(cur)?;
            let v = NodeView::new(self.pool.page(f));
            if v.is_leaf() {
                self.pool.unpin(f);
                return Ok(cur);
            }
            let next = v.leftmost_child();
            self.pool.unpin(f);
            cur = PageId(next);
        }
    }

    /// The current tree height (0 = empty/no root, 1 = single leaf). Test helper.
    ///
    /// # Errors
    /// Propagates a fetch error.
    pub fn height(&mut self) -> Result<u16> {
        let Some(root) = self.root else { return Ok(0) };
        let f = self.pool.fetch(root)?;
        let h = NodeView::new(self.pool.page(f)).level() + 1;
        self.pool.unpin(f);
        Ok(h)
    }
}

// Compile-time guard: a node's directory must start within the payload and the cell limit must
// leave room for at least one slot. Catches a future page-layout regression.
const _: () = assert!(SLOT_DIR_START < CELL_LIMIT);

fn read_u64(p: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(p[off..off + 8].try_into().expect("8-byte slice"))
}
fn read_u32(p: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(p[off..off + 4].try_into().expect("4-byte slice"))
}

/// Documents that the meta page lives at the tree's relative page 0 (used by multi-tree layouts).
pub const fn meta_page_rel() -> u64 {
    META_PAGE_REL
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_io::MemBlockDevice;
    use graphus_wal::MemLogSink;

    fn fresh() -> BTree<MemBlockDevice, MemLogSink> {
        let wal = graphus_wal::WalManager::create(MemLogSink::new()).unwrap();
        let shared = SharedWal::new(wal);
        let pool = BufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), 32);
        BTree::create(pool, shared).unwrap()
    }

    /// Guards the locally re-stated `OFF_PAGE_TYPE` against drift from the bufpool's private const:
    /// a patch at `OFF_PAGE_TYPE` must be observed by `page::page_type`.
    #[test]
    fn off_page_type_matches_bufpool_page_type_accessor() {
        let mut p = [0u8; PAGE_SIZE];
        p[OFF_PAGE_TYPE] = PAGE_TYPE_BTREE_META;
        assert_eq!(page::page_type(&p), PAGE_TYPE_BTREE_META);
    }

    #[test]
    fn empty_tree_lookup_and_range_are_empty() {
        let mut t = fresh();
        assert_eq!(t.lookup(b"x").unwrap(), None);
        assert!(t.range(b"a", b"z").unwrap().is_empty());
        assert_eq!(t.height().unwrap(), 0);
    }

    #[test]
    fn insert_then_lookup_single_entry() {
        let mut t = fresh();
        let txn = TxnId(1);
        t.with_wal(|w| {
            w.begin(txn);
        });
        t.insert(txn, b"key", b"value").unwrap();
        t.with_wal(|w| w.commit(txn).unwrap());
        assert_eq!(t.lookup(b"key").unwrap(), Some(b"value".to_vec()));
        assert_eq!(t.height().unwrap(), 1); // single leaf
    }

    // 1000 inserts drive many page splits through the buffer pool + WAL; under the miri interpreter
    // that page churn takes minutes. The split/grow *logic* is also covered by the smaller tests
    // above that run fast under miri, and full-scale B+-tree campaigns live in `tests/btree_props.rs`
    // (run natively). So this is skipped under miri purely for runtime — it hides no UB. (See
    // `VERIFICATION.md` → miri gate.)
    #[cfg_attr(
        miri,
        ignore = "1000-insert page churn is impractically slow under the miri interpreter"
    )]
    #[test]
    fn many_inserts_grow_the_tree_height() {
        let mut t = fresh();
        let txn = TxnId(1);
        t.with_wal(|w| {
            w.begin(txn);
        });
        for i in 0u32..1000 {
            t.insert(txn, &i.to_be_bytes(), &i.to_le_bytes()).unwrap();
        }
        t.with_wal(|w| w.commit(txn).unwrap());
        assert!(t.height().unwrap() >= 2, "should have split past one leaf");
        t.check_invariants().unwrap();
    }

    #[test]
    fn meta_page_rel_is_zero() {
        assert_eq!(meta_page_rel(), 0);
    }

    #[test]
    fn validated_bit_cache_is_a_hit_on_repeated_lookup() {
        // The same leaf, fetched twice without an intervening mutation, keeps the same
        // (page_id, page_lsn), so the second descent finds the validated bit already set.
        let mut t = fresh();
        let txn = TxnId(1);
        t.with_wal(|w| {
            w.begin(txn);
        });
        for i in 0u32..200 {
            t.insert(txn, &i.to_be_bytes(), &i.to_le_bytes()).unwrap();
        }
        t.with_wal(|w| w.commit(txn).unwrap());
        let before = t.validated.len();
        // A second lookup of an already-seen key adds no new validated entries for unchanged pages.
        let _ = t.lookup(&7u32.to_be_bytes()).unwrap();
        let mid = t.validated.len();
        let _ = t.lookup(&7u32.to_be_bytes()).unwrap();
        let after = t.validated.len();
        assert!(
            before > 0,
            "the build path should have validated some pages"
        );
        assert_eq!(
            mid, after,
            "a repeat lookup must not re-validate (cache hit)"
        );
    }

    /// Micro-bench (`#[ignore]`): per-node CPU of point lookups and range scans, with the
    /// validated-bit cache ON (amortized validate, the change) vs OFF (full `validate()` per fetch,
    /// the prior behavior). Run with:
    ///   `cargo test -p graphus-index --release validate_amortization_microbench -- --ignored --nocapture`
    #[test]
    #[ignore = "micro-bench; run explicitly with --ignored --release --nocapture"]
    fn validate_amortization_microbench() {
        use std::time::Instant;

        // Build a multi-level tree so descents touch internal + leaf nodes (validation per node).
        let mut t = fresh();
        let txn = TxnId(1);
        t.with_wal(|w| {
            w.begin(txn);
        });
        const N: u32 = 20_000;
        for i in 0u32..N {
            t.insert(txn, &i.to_be_bytes(), &i.to_le_bytes()).unwrap();
        }
        t.with_wal(|w| w.commit(txn).unwrap());
        assert!(t.height().unwrap() >= 2, "want a multi-level tree");

        const LOOKUPS: u32 = 200_000;
        let bench_lookups = |t: &mut BTree<MemBlockDevice, MemLogSink>| -> std::time::Duration {
            let start = Instant::now();
            let mut hits = 0u64;
            for r in 0..LOOKUPS {
                let k = (r % N).to_be_bytes();
                if t.lookup(&k).unwrap().is_some() {
                    hits += 1;
                }
            }
            std::hint::black_box(hits);
            start.elapsed()
        };

        // OFF = prior behavior (full validate() on every fetched node).
        t.set_validate_cache_enabled(false);
        let off = bench_lookups(&mut t);
        // ON = amortized validate (validate once per (id, lsn) image).
        t.set_validate_cache_enabled(true);
        let on = bench_lookups(&mut t);

        let off_ns = off.as_nanos() as f64 / f64::from(LOOKUPS);
        let on_ns = on.as_nanos() as f64 / f64::from(LOOKUPS);
        println!(
            "point-lookup: validate-every-fetch {off_ns:.1} ns/op  vs  amortized {on_ns:.1} ns/op  \
             ({:.2}x)",
            off_ns / on_ns,
        );

        // Range scan over the whole key space (one descent + a long right-sibling leaf walk, each
        // leaf validated per fetch in the OFF arm).
        const RANGES: u32 = 2_000;
        let bench_range = |t: &mut BTree<MemBlockDevice, MemLogSink>| -> std::time::Duration {
            let start = Instant::now();
            let mut total = 0u64;
            for _ in 0..RANGES {
                total += t.scan_all().unwrap().len() as u64;
            }
            std::hint::black_box(total);
            start.elapsed()
        };
        t.set_validate_cache_enabled(false);
        let roff = bench_range(&mut t);
        t.set_validate_cache_enabled(true);
        let ron = bench_range(&mut t);
        println!(
            "full-range-scan: validate-every-fetch {:.2} ms  vs  amortized {:.2} ms  ({:.2}x)",
            roff.as_secs_f64() * 1e3 / f64::from(RANGES),
            ron.as_secs_f64() * 1e3 / f64::from(RANGES),
            roff.as_secs_f64() / ron.as_secs_f64(),
        );
    }
}
