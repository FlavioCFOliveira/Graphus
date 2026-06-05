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

use graphus_bufpool::BufferPool;
use graphus_bufpool::page::{self, HEADER_SIZE};
use graphus_core::error::{GraphusError, Result};
use graphus_core::{PageId, TxnId};
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
}

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
                let v = NodeView::new(self.pool.page(f));
                if !v.is_leaf() {
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
        let v = NodeView::new(self.pool.page(f));
        let out = v.find_exact(key).map(|i| v.value(i).to_vec());
        self.pool.unpin(f);
        Ok(out)
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
        let mut out = Vec::new();
        let Some(root) = self.root else {
            return Ok(out);
        };
        let mut leaf = self.descend_to_leaf(root, lo)?;
        loop {
            let f = self.pool.fetch(leaf)?;
            let v = NodeView::new(self.pool.page(f));
            let start = v.lower_bound(lo);
            let mut passed_hi = false;
            for i in start..v.slot_count() {
                let k = v.key(i);
                if let Some(h) = hi {
                    if !h.is_empty() && k >= h {
                        passed_hi = true;
                        break;
                    }
                }
                out.push((k.to_vec(), v.value(i).to_vec()));
            }
            let next = v.right_sibling();
            self.pool.unpin(f);
            if passed_hi || next == 0 {
                break;
            }
            leaf = PageId(next);
        }
        Ok(out)
    }

    /// Descends from `from` to the leaf that would contain `key`.
    fn descend_to_leaf(&mut self, from: PageId, key: &[u8]) -> Result<PageId> {
        let mut cur = from;
        loop {
            let f = self.pool.fetch(cur)?;
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
    /// crash-recovery simple. A leaf that becomes empty stays linked in the right-sibling chain (a
    /// future GC/merge pass reclaims empty leaves, `04 §6.3` GC). Point and range correctness are
    /// unaffected by an underfull-but-sorted leaf, which the property tests assert against a
    /// `BTreeMap` model across long delete sequences.
    ///
    /// # Errors
    /// Propagates a buffer-pool or WAL failure.
    pub fn delete(&mut self, txn: TxnId, key: &[u8]) -> Result<bool> {
        let Some(root) = self.root else {
            return Ok(false);
        };
        let leaf = self.descend_to_leaf(root, key)?;
        let f = self.pool.fetch(leaf)?;
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
}
