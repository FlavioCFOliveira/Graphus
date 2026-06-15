//! The B+-tree slotted-page layout (`04-technical-design.md` §3.2, §6.1; this format is the one
//! `05-storage-format.md` §8 explicitly defers to the `graphus-index` task — it is **defined and
//! frozen here**).
//!
//! An index page is an ordinary logical page: it begins with the frozen 24-byte page header
//! (`05 §6`, [`graphus_bufpool::page::HEADER_SIZE`]). Everything after the header is owned by this
//! module and is laid out as a **slotted page** with a B+-tree **special area** at the very end of
//! the page (`04 §3.2`).
//!
//! ```text
//!  ┌──────────────── logical page (8192 B) ─────────────────┐
//!  │ 24-byte page header (05 §6: checksum,type,page_lsn,id)  │  bytes  0..24
//!  ├────────────────────────────────────────────────────────┤
//!  │ node header (this module): level, slot_count           │  bytes 24..28
//!  │ slot directory: slot_count × (off:u16, klen:u16, ...)   │  grows downward
//!  │ ……………………… free space ……………………………                    │
//!  │ cell heap (keys + payloads)  ← grows upward             │
//!  ├────────────────────────────────────────────────────────┤
//!  │ special area: right_sibling:u64 (B-link, 04 §6.1)       │  last 8 bytes
//!  └────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Node header (4 bytes, right after the page header)
//!
//! | Offset | Size | Field | Meaning |
//! | --- | --- | --- | --- |
//! | 24 | 2 | `level` | `0` = leaf, `>0` = internal (height above the leaves). |
//! | 26 | 2 | `slot_count` | number of live cells. |
//!
//! ## Slot directory
//!
//! Fixed-width 8-byte slots, kept **sorted by key** so a slot binary-search gives ordered access
//! and range scans are a directory walk. Each slot is:
//!
//! | Size | Field | Meaning |
//! | --- | --- | --- |
//! | 2 | `cell_off` | byte offset of the cell within the page. |
//! | 2 | `key_len` | length of the key bytes in the cell. |
//! | 2 | `val_len` | length of the payload (leaf: encoded record-id list segment; internal: unused, child is the payload). |
//! | 2 | `reserved` | zero (alignment / future flags). |
//!
//! ## Cell heap
//!
//! Cells grow upward from just below the special area toward the directory. A **leaf cell** is
//! `key_bytes ++ value_bytes`, where the value is the encoded payload for that key (for the index
//! kinds this is a record-id, but the B+-tree treats it as opaque bytes). An **internal cell** is
//! `key_bytes` only; the associated child `PageId` is stored in a parallel child array packed
//! immediately after the key inside the cell as a trailing `u64` (so an internal cell is
//! `key_bytes ++ child:u64`). Internal nodes hold `slot_count` keys and `slot_count + 1` children:
//! the **leftmost child** (`P0`) is stored in the special area's secondary slot (see
//! [`SPECIAL_LEFTMOST`]); key `i` separates child `i` (`< key[i]`) from child `i+1` (`>= key[i]`).
//!
//! ## Special area (last 16 bytes of the page)
//!
//! | From page end | Size | Field | Meaning |
//! | --- | --- | --- | --- |
//! | −8 | 8 | `right_sibling` | next leaf/internal at this level (B-link pointer, `04 §6.1`); `0` = none. |
//! | −16 | 8 | `leftmost_child` | internal-only: `P0`, the child holding keys `< key[0]`. |
//!
//! The right-sibling chain links **all leaves in key order**, which is what makes a range scan an
//! O(result) walk and is the structural invariant the property tests check. Latch-coupling
//! (crabbing) and B-link concurrency discipline are documented in [`crate::btree`]; this module is
//! pure byte layout.

use graphus_bufpool::page::HEADER_SIZE;
use graphus_io::PAGE_SIZE;

/// Page-type byte for a B+-tree leaf (`05 §6`: low byte = type).
pub const PAGE_TYPE_BTREE_LEAF: u8 = 6;
/// Page-type byte for a B+-tree internal node.
pub const PAGE_TYPE_BTREE_INTERNAL: u8 = 7;
/// Page-type byte for the B+-tree meta page (root pointer + free list head).
pub const PAGE_TYPE_BTREE_META: u8 = 8;

/// Offset of the node header within the page (right after the 24-byte page header).
const OFF_LEVEL: usize = HEADER_SIZE; // u16
const OFF_SLOT_COUNT: usize = HEADER_SIZE + 2; // u16
/// Offset where the slot directory begins.
pub const SLOT_DIR_START: usize = HEADER_SIZE + 4;

/// One slot directory entry is 8 bytes.
pub const SLOT_SIZE: usize = 8;

/// Size of the special area at the end of the page: `right_sibling` (8) + `leftmost_child` (8).
pub const SPECIAL_SIZE: usize = 16;
/// Byte offset of `right_sibling` within the page.
pub const SPECIAL_RIGHT: usize = PAGE_SIZE - 8;
/// Byte offset of `leftmost_child` (`P0`) within the page (internal nodes only).
pub const SPECIAL_LEFTMOST: usize = PAGE_SIZE - 16;

/// Highest byte a cell may occupy (cells grow upward toward the directory, but never into the
/// special area).
pub const CELL_LIMIT: usize = SPECIAL_LEFTMOST;

/// A typed, read-only view over a B+-tree page's bytes.
#[derive(Debug, Clone, Copy)]
pub struct NodeView<'a> {
    bytes: &'a [u8],
}

/// A logical cell read out of a node: its key and (leaf) value or (internal) child pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    /// The order-preserving encoded key bytes.
    pub key: Vec<u8>,
    /// Leaf payload bytes (empty for an internal cell).
    pub value: Vec<u8>,
    /// Internal child page id (`0` for a leaf cell).
    pub child: u64,
}

fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().expect("2-byte slice"))
}

fn rd_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().expect("8-byte slice"))
}

/// A bounds-checked 2-byte little-endian read: `Some(value)` when `[off, off+2)` lies inside `b`,
/// `None` otherwise. The defense-in-depth primitive behind the safe accessors (SEC-207): an
/// adversarially forged page whose checksum was recomputed can name an out-of-range offset, and a
/// read on a hot path must surface that as a graceful error, never an out-of-bounds slice panic.
fn try_rd_u16(b: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    b.get(off..end)
        .map(|s| u16::from_le_bytes(s.try_into().expect("2-byte slice")))
}

/// A bounds-checked 8-byte little-endian read (see [`try_rd_u16`]).
fn try_rd_u64(b: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    b.get(off..end)
        .map(|s| u64::from_le_bytes(s.try_into().expect("8-byte slice")))
}

impl<'a> NodeView<'a> {
    /// Wraps a page's bytes for reading.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// The node level (`0` = leaf).
    #[must_use]
    pub fn level(&self) -> u16 {
        rd_u16(self.bytes, OFF_LEVEL)
    }

    /// Whether this node is a leaf.
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.level() == 0
    }

    /// The number of live slots.
    #[must_use]
    pub fn slot_count(&self) -> usize {
        rd_u16(self.bytes, OFF_SLOT_COUNT) as usize
    }

    /// The right-sibling page id (B-link pointer); `0` = none.
    #[must_use]
    pub fn right_sibling(&self) -> u64 {
        rd_u64(self.bytes, SPECIAL_RIGHT)
    }

    /// The leftmost child `P0` (internal nodes); meaningless for a leaf.
    #[must_use]
    pub fn leftmost_child(&self) -> u64 {
        rd_u64(self.bytes, SPECIAL_LEFTMOST)
    }

    fn slot_off(i: usize) -> usize {
        SLOT_DIR_START + i * SLOT_SIZE
    }

    /// Validates that the slot directory is internally consistent before the hot read paths iterate
    /// over it, so a page that is *corrupt yet survives the page checksum* (e.g. bit-rot that happens
    /// to keep a valid CRC, or a malformed image) cannot drive an [`assert!`] panic or an
    /// out-of-bounds slice in [`key`](Self::key) / [`value`](Self::value) / [`child`](Self::child)
    /// during a client query. This is **defense-in-depth**: a well-formed page always passes, and the
    /// accessors keep their existing fast (unchecked) bodies — callers on the hot read paths gate on
    /// this once per fetched page instead of paying a bounds check per slot access.
    ///
    /// A node is well-formed when every slot's cell `[off, off + klen + vlen)` lies wholly within the
    /// cell-heap region `[dir_end, CELL_LIMIT]` (so it neither overlaps the slot directory nor runs
    /// into the special area), and — for an internal node — the trailing `u64` child pointer at
    /// `off + klen` also fits.
    ///
    /// # Errors
    /// Returns [`graphus_core::GraphusError::Storage`] describing the first inconsistency found.
    pub fn validate(&self) -> graphus_core::error::Result<()> {
        let n = self.slot_count();
        let dir_end = SLOT_DIR_START + n * SLOT_SIZE;
        // The directory itself must fit ahead of the special area; an absurd slot_count would make
        // `slot_off` read past the page.
        if dir_end > CELL_LIMIT {
            return Err(graphus_core::GraphusError::Storage(format!(
                "corrupt index page: slot_count {n} overflows the page directory",
            )));
        }
        let is_leaf = self.level() == 0;
        for i in 0..n {
            let slot = Self::slot_off(i);
            let off = rd_u16(self.bytes, slot) as usize;
            let klen = rd_u16(self.bytes, slot + 2) as usize;
            let vlen = rd_u16(self.bytes, slot + 4) as usize;
            // The cell body must sit inside the heap region, never inside the directory or past the
            // special area. `checked_add` guards the (already u16-bounded) arithmetic defensively.
            let cell_end = off
                .checked_add(klen)
                .and_then(|e| e.checked_add(vlen))
                .ok_or_else(|| {
                    graphus_core::GraphusError::Storage(format!(
                        "corrupt index page: slot {i} cell length overflows",
                    ))
                })?;
            if off < dir_end || cell_end > CELL_LIMIT {
                return Err(graphus_core::GraphusError::Storage(format!(
                    "corrupt index page: slot {i} cell [{off}, {cell_end}) outside heap [{dir_end}, {CELL_LIMIT}]",
                )));
            }
            // An internal cell also carries a trailing `u64` child at `off + klen`; ensure it fits.
            if !is_leaf {
                let child_end = off.checked_add(klen).and_then(|e| e.checked_add(8)).filter(|e| *e <= CELL_LIMIT);
                if child_end.is_none() {
                    return Err(graphus_core::GraphusError::Storage(format!(
                        "corrupt index page: slot {i} internal child pointer outside the page",
                    )));
                }
            }
        }
        Ok(())
    }

    /// The encoded key bytes of slot `i`, or `None` if the slot index is out of range **or** the
    /// page bytes are inconsistent (a slot/cell offset that runs past the page).
    ///
    /// This is the bounds-checked primitive (SEC-207, defense-in-depth): it never slices
    /// out-of-bounds, so a forged-but-CRC-valid page cannot drive a panic through it. The panicking
    /// [`key`](Self::key) is a thin wrapper for the validated hot paths.
    #[must_use]
    pub fn try_key(&self, i: usize) -> Option<&'a [u8]> {
        if i >= self.slot_count() {
            return None;
        }
        let slot = Self::slot_off(i);
        let off = try_rd_u16(self.bytes, slot)? as usize;
        let klen = try_rd_u16(self.bytes, slot + 2)? as usize;
        let end = off.checked_add(klen)?;
        self.bytes.get(off..end)
    }

    /// The leaf payload bytes of slot `i`, or `None` on an out-of-range index or an inconsistent
    /// page (the bounds-checked counterpart of [`value`](Self::value); SEC-207).
    #[must_use]
    pub fn try_value(&self, i: usize) -> Option<&'a [u8]> {
        if i >= self.slot_count() {
            return None;
        }
        let slot = Self::slot_off(i);
        let off = try_rd_u16(self.bytes, slot)? as usize;
        let klen = try_rd_u16(self.bytes, slot + 2)? as usize;
        let vlen = try_rd_u16(self.bytes, slot + 4)? as usize;
        let start = off.checked_add(klen)?;
        let end = start.checked_add(vlen)?;
        self.bytes.get(start..end)
    }

    /// The internal child pointer of slot `i`, or `None` on a leaf, an out-of-range index, or an
    /// inconsistent page (the bounds-checked counterpart of [`child`](Self::child); SEC-207).
    #[must_use]
    pub fn try_child(&self, i: usize) -> Option<u64> {
        if self.is_leaf() || i >= self.slot_count() {
            return None;
        }
        let slot = Self::slot_off(i);
        let off = try_rd_u16(self.bytes, slot)? as usize;
        let klen = try_rd_u16(self.bytes, slot + 2)? as usize;
        let child_off = off.checked_add(klen)?;
        try_rd_u64(self.bytes, child_off)
    }

    /// The encoded key bytes of slot `i`.
    ///
    /// # Panics
    /// Panics if `i >= slot_count()` or the page is inconsistent (a corrupt cell offset). Callers on
    /// the hot read paths must first run [`validate`](Self::validate); use [`try_key`](Self::try_key)
    /// to handle corruption gracefully instead.
    #[must_use]
    pub fn key(&self, i: usize) -> &'a [u8] {
        self.try_key(i)
            .expect("slot out of range or corrupt index page (call validate() first)")
    }

    /// The leaf payload bytes of slot `i` (empty for an internal node).
    ///
    /// # Panics
    /// Panics if `i >= slot_count()` or the page is inconsistent; see [`key`](Self::key).
    #[must_use]
    pub fn value(&self, i: usize) -> &'a [u8] {
        self.try_value(i)
            .expect("slot out of range or corrupt index page (call validate() first)")
    }

    /// The internal child pointer of slot `i` (the child for keys `>= key(i)` and `< key(i+1)`).
    ///
    /// # Panics
    /// Panics if `i >= slot_count()`, the node is a leaf, or the page is inconsistent; see
    /// [`key`](Self::key).
    #[must_use]
    pub fn child(&self, i: usize) -> u64 {
        self.try_child(i)
            .expect("child() on a leaf, slot out of range, or corrupt index page (validate() first)")
    }

    /// Reads slot `i` into an owned [`Cell`].
    ///
    /// # Panics
    /// Panics if `i >= slot_count()`.
    #[must_use]
    pub fn cell(&self, i: usize) -> Cell {
        if self.is_leaf() {
            Cell {
                key: self.key(i).to_vec(),
                value: self.value(i).to_vec(),
                child: 0,
            }
        } else {
            Cell {
                key: self.key(i).to_vec(),
                value: Vec::new(),
                child: self.child(i),
            }
        }
    }

    /// Returns the index of the first slot whose key is `>= probe` (lower bound), via binary
    /// search over the sorted directory. Returns `slot_count()` if all keys are `< probe`.
    #[must_use]
    pub fn lower_bound(&self, probe: &[u8]) -> usize {
        let mut lo = 0usize;
        let mut hi = self.slot_count();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.key(mid) < probe {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// The exact slot index of `probe`, if present (a leaf point lookup).
    #[must_use]
    pub fn find_exact(&self, probe: &[u8]) -> Option<usize> {
        let i = self.lower_bound(probe);
        if i < self.slot_count() && self.key(i) == probe {
            Some(i)
        } else {
            None
        }
    }

    /// For an internal node, the child page id to descend into for `probe` (`04 §6.2` separator
    /// semantics: key `i` separates child `i` from child `i+1`, so we follow `leftmost_child` when
    /// `probe < key[0]` else the child of the greatest key `<= probe`).
    ///
    /// # Panics
    /// Panics if called on a leaf.
    #[must_use]
    pub fn child_for(&self, probe: &[u8]) -> u64 {
        assert!(!self.is_leaf(), "child_for on a leaf");
        // First slot with key > probe; descend into the child just left of it.
        let mut lo = 0usize;
        let mut hi = self.slot_count();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.key(mid) <= probe {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            self.leftmost_child()
        } else {
            self.child(lo - 1)
        }
    }
}

/// A mutable builder/editor over a B+-tree page's bytes. All edits keep the slot directory sorted
/// and the cell heap compact; on overflow they report failure so the caller can split.
pub struct NodeMut<'a> {
    bytes: &'a mut [u8],
}

fn wr_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn wr_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

impl<'a> NodeMut<'a> {
    /// Wraps a page's bytes for mutation.
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }

    /// Initialises a fresh, empty node of the given `level` (0 = leaf), clearing the slot
    /// directory and special area. Does not touch the 24-byte page header.
    pub fn init(&mut self, level: u16) {
        wr_u16(self.bytes, OFF_LEVEL, level);
        wr_u16(self.bytes, OFF_SLOT_COUNT, 0);
        wr_u64(self.bytes, SPECIAL_RIGHT, 0);
        wr_u64(self.bytes, SPECIAL_LEFTMOST, 0);
    }

    /// A read view over the same bytes.
    #[must_use]
    pub fn view(&self) -> NodeView<'_> {
        NodeView::new(self.bytes)
    }

    fn slot_count(&self) -> usize {
        rd_u16(self.bytes, OFF_SLOT_COUNT) as usize
    }

    fn set_slot_count(&mut self, n: usize) {
        // A slot count never legitimately exceeds `u16::MAX` (the page holds far fewer slots than
        // 65 535), but make the narrowing explicit so a future regression that miscomputes `n`
        // fails loudly instead of silently truncating the directory length (SEC-208, CWE-190).
        debug_assert!(n <= u16::MAX as usize, "slot_count {n} exceeds u16");
        let n16 = u16::try_from(n).expect("INVARIANT: slot_count fits a u16 (page-bounded)");
        wr_u16(self.bytes, OFF_SLOT_COUNT, n16);
    }

    /// Sets the right-sibling pointer (B-link).
    pub fn set_right_sibling(&mut self, page: u64) {
        wr_u64(self.bytes, SPECIAL_RIGHT, page);
    }

    /// Sets the leftmost child `P0` (internal nodes).
    pub fn set_leftmost_child(&mut self, page: u64) {
        wr_u64(self.bytes, SPECIAL_LEFTMOST, page);
    }

    /// The lowest byte currently occupied by the cell heap (cells grow upward from `CELL_LIMIT`).
    fn heap_floor(&self) -> usize {
        let n = self.slot_count();
        let mut floor = CELL_LIMIT;
        for i in 0..n {
            let off = rd_u16(self.bytes, SLOT_DIR_START + i * SLOT_SIZE) as usize;
            if off < floor {
                floor = off;
            }
        }
        floor
    }

    /// Bytes of free space available for a new cell + its directory slot.
    #[must_use]
    pub fn free_space(&self) -> usize {
        let n = self.slot_count();
        let dir_end = SLOT_DIR_START + n * SLOT_SIZE;
        self.heap_floor().saturating_sub(dir_end)
    }

    /// Inserts (or replaces) a leaf entry, keeping the directory sorted. Returns `false` (without
    /// modifying the node) if there is not enough free space — the caller must then split.
    ///
    /// On a key already present, the value is replaced (same-or-shorter values reuse the cell;
    /// otherwise the old cell is abandoned and a new one appended — space is reclaimed by
    /// [`Self::compact`]).
    #[must_use]
    pub fn leaf_insert(&mut self, key: &[u8], value: &[u8]) -> bool {
        debug_assert_eq!(self.view().level(), 0, "leaf_insert on an internal node");
        if let Some(i) = self.view().find_exact(key) {
            return self.replace_value(i, key, value);
        }
        self.insert_cell(key, value, 0)
    }

    /// Inserts an internal separator `key` whose right child is `child` (the child for keys
    /// `>= key`). Returns `false` if the node is full.
    #[must_use]
    pub fn internal_insert(&mut self, key: &[u8], child: u64) -> bool {
        debug_assert!(self.view().level() > 0, "internal_insert on a leaf");
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(&child.to_le_bytes());
        self.insert_cell(key, &payload, 0)
    }

    fn replace_value(&mut self, i: usize, key: &[u8], value: &[u8]) -> bool {
        let slot = SLOT_DIR_START + i * SLOT_SIZE;
        let old_vlen = rd_u16(self.bytes, slot + 4) as usize;
        if value.len() <= old_vlen {
            let off = rd_u16(self.bytes, slot) as usize;
            let klen = rd_u16(self.bytes, slot + 2) as usize;
            self.bytes[off + klen..off + klen + value.len()].copy_from_slice(value);
            // `value.len() <= old_vlen <= u16::MAX` here (it replaces an existing cell in place), so
            // the narrowing is lossless; assert it to catch a future regression (SEC-208).
            wr_u16(
                self.bytes,
                slot + 4,
                u16::try_from(value.len()).expect("INVARIANT: replacement value fits the cell (u16)"),
            );
            true
        } else {
            // Remove and re-insert with the larger value.
            self.remove_at(i);
            self.insert_cell(key, value, 0)
        }
    }

    /// Inserts a new cell `(key ++ payload)`, placing its slot at the sorted position. `_child` is
    /// reserved for a future split path; payload already carries the child for internal cells.
    fn insert_cell(&mut self, key: &[u8], payload: &[u8], _child: u64) -> bool {
        let cell_len = key.len() + payload.len();
        let need = cell_len + SLOT_SIZE;
        if self.free_space() < need {
            return false;
        }
        let n = self.slot_count();
        let new_floor = self.heap_floor() - cell_len;
        // Write the cell bytes.
        self.bytes[new_floor..new_floor + key.len()].copy_from_slice(key);
        self.bytes[new_floor + key.len()..new_floor + cell_len].copy_from_slice(payload);
        // Find the sorted insertion index.
        let pos = self.view().lower_bound(key);
        // Shift slots [pos, n) up by one to make room.
        let src = SLOT_DIR_START + pos * SLOT_SIZE;
        let dst = src + SLOT_SIZE;
        let bytes_to_move = (n - pos) * SLOT_SIZE;
        self.bytes.copy_within(src..src + bytes_to_move, dst);
        // Write the new slot. Every quantity here is bounded by `CELL_LIMIT < PAGE_SIZE` (well
        // under `u16::MAX`), so the narrowings are lossless; `try_from` makes a future layout
        // regression a loud panic instead of a silent truncation (SEC-208, CWE-190).
        wr_u16(
            self.bytes,
            src,
            u16::try_from(new_floor).expect("INVARIANT: cell offset is page-bounded (u16)"),
        );
        wr_u16(
            self.bytes,
            src + 2,
            u16::try_from(key.len()).expect("INVARIANT: key length is page-bounded (u16)"),
        );
        wr_u16(
            self.bytes,
            src + 4,
            u16::try_from(payload.len()).expect("INVARIANT: payload length is page-bounded (u16)"),
        );
        wr_u16(self.bytes, src + 6, 0);
        self.set_slot_count(n + 1);
        true
    }

    /// Removes the slot at index `i` (its cell bytes are abandoned; reclaim with [`Self::compact`]).
    ///
    /// # Panics
    /// Panics if `i >= slot_count()`.
    pub fn remove_at(&mut self, i: usize) {
        let n = self.slot_count();
        assert!(i < n, "remove slot out of range");
        let src = SLOT_DIR_START + (i + 1) * SLOT_SIZE;
        let dst = SLOT_DIR_START + i * SLOT_SIZE;
        let bytes_to_move = (n - i - 1) * SLOT_SIZE;
        self.bytes.copy_within(src..src + bytes_to_move, dst);
        self.set_slot_count(n - 1);
    }

    /// Removes the leaf entry for `key`, returning `true` if it was present.
    #[must_use]
    pub fn leaf_remove(&mut self, key: &[u8]) -> bool {
        if let Some(i) = self.view().find_exact(key) {
            self.remove_at(i);
            true
        } else {
            false
        }
    }

    /// Compacts the cell heap, removing the gaps left by replaced/removed cells, so the node
    /// reclaims fragmentation. Rebuilds the heap from the current (sorted) directory.
    pub fn compact(&mut self) {
        let n = self.slot_count();
        // Collect current cells in slot order.
        let mut cells: Vec<(Vec<u8>, usize, usize)> = Vec::with_capacity(n);
        for i in 0..n {
            let slot = SLOT_DIR_START + i * SLOT_SIZE;
            let off = rd_u16(self.bytes, slot) as usize;
            let klen = rd_u16(self.bytes, slot + 2) as usize;
            let vlen = rd_u16(self.bytes, slot + 4) as usize;
            cells.push((self.bytes[off..off + klen + vlen].to_vec(), klen, vlen));
        }
        // Rewrite cells packed against CELL_LIMIT, top-down.
        let mut floor = CELL_LIMIT;
        for (i, (cell, klen, vlen)) in cells.iter().enumerate() {
            floor -= cell.len();
            self.bytes[floor..floor + cell.len()].copy_from_slice(cell);
            let slot = SLOT_DIR_START + i * SLOT_SIZE;
            // All page-bounded (< CELL_LIMIT); explicit narrowings catch a future regression (SEC-208).
            wr_u16(
                self.bytes,
                slot,
                u16::try_from(floor).expect("INVARIANT: compacted cell offset is page-bounded (u16)"),
            );
            wr_u16(
                self.bytes,
                slot + 2,
                u16::try_from(*klen).expect("INVARIANT: key length is page-bounded (u16)"),
            );
            wr_u16(
                self.bytes,
                slot + 4,
                u16::try_from(*vlen).expect("INVARIANT: value length is page-bounded (u16)"),
            );
            wr_u16(self.bytes, slot + 6, 0);
        }
    }

    /// Truncates the node to its first `keep` slots (used by split to keep the left half). The
    /// abandoned cells are reclaimed by a following [`Self::compact`].
    pub fn truncate(&mut self, keep: usize) {
        debug_assert!(keep <= self.slot_count());
        self.set_slot_count(keep);
    }

    /// Bulk-appends `cells` (already in sorted order, all greater than any current key) for the
    /// right half of a split. Returns `false` if they do not fit.
    #[must_use]
    pub fn append_cells(&mut self, cells: &[Cell]) -> bool {
        for c in cells {
            let ok = if self.view().is_leaf() {
                self.insert_cell(&c.key, &c.value, 0)
            } else {
                let mut payload = Vec::with_capacity(8);
                payload.extend_from_slice(&c.child.to_le_bytes());
                self.insert_cell(&c.key, &payload, 0)
            };
            if !ok {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank_page() -> Vec<u8> {
        vec![0u8; PAGE_SIZE]
    }

    #[test]
    fn leaf_insert_keeps_sorted_order() {
        let mut page = blank_page();
        let mut n = NodeMut::new(&mut page);
        n.init(0);
        assert!(n.leaf_insert(b"c", b"3"));
        assert!(n.leaf_insert(b"a", b"1"));
        assert!(n.leaf_insert(b"b", b"2"));
        let v = n.view();
        assert_eq!(v.slot_count(), 3);
        assert_eq!(v.key(0), b"a");
        assert_eq!(v.key(1), b"b");
        assert_eq!(v.key(2), b"c");
        assert_eq!(v.value(1), b"2");
    }

    #[test]
    fn leaf_point_lookup() {
        let mut page = blank_page();
        let mut n = NodeMut::new(&mut page);
        n.init(0);
        assert!(n.leaf_insert(b"alpha", b"x"));
        assert!(n.leaf_insert(b"gamma", b"z"));
        let v = n.view();
        assert_eq!(v.find_exact(b"alpha"), Some(0));
        assert_eq!(v.find_exact(b"beta"), None);
        assert_eq!(v.find_exact(b"gamma"), Some(1));
    }

    #[test]
    fn replace_value_in_place_when_shorter_or_equal() {
        let mut page = blank_page();
        let mut n = NodeMut::new(&mut page);
        n.init(0);
        assert!(n.leaf_insert(b"k", b"long-value"));
        assert!(n.leaf_insert(b"k", b"short")); // replace
        let v = n.view();
        assert_eq!(v.slot_count(), 1);
        assert_eq!(v.value(0), b"short");
    }

    #[test]
    fn remove_then_lookup_misses() {
        let mut page = blank_page();
        let mut n = NodeMut::new(&mut page);
        n.init(0);
        assert!(n.leaf_insert(b"a", b"1"));
        assert!(n.leaf_insert(b"b", b"2"));
        assert!(n.leaf_remove(b"a"));
        assert!(!n.leaf_remove(b"a"));
        let v = n.view();
        assert_eq!(v.slot_count(), 1);
        assert_eq!(v.find_exact(b"a"), None);
        assert_eq!(v.find_exact(b"b"), Some(0));
    }

    #[test]
    fn internal_child_routing() {
        let mut page = blank_page();
        let mut n = NodeMut::new(&mut page);
        n.init(1); // internal
        n.set_leftmost_child(100);
        assert!(n.internal_insert(b"m", 200)); // keys >= "m" -> child 200
        assert!(n.internal_insert(b"t", 300)); // keys >= "t" -> child 300
        let v = n.view();
        assert_eq!(v.child_for(b"a"), 100); // < "m" -> leftmost
        assert_eq!(v.child_for(b"m"), 200); // == "m"
        assert_eq!(v.child_for(b"s"), 200); // between "m" and "t"
        assert_eq!(v.child_for(b"t"), 300);
        assert_eq!(v.child_for(b"z"), 300);
    }

    #[test]
    fn right_sibling_round_trips() {
        let mut page = blank_page();
        let mut n = NodeMut::new(&mut page);
        n.init(0);
        n.set_right_sibling(77);
        assert_eq!(n.view().right_sibling(), 77);
    }

    #[test]
    fn free_space_shrinks_with_inserts_and_compact_reclaims() {
        let mut page = blank_page();
        let mut n = NodeMut::new(&mut page);
        n.init(0);
        let before = n.free_space();
        assert!(n.leaf_insert(b"key", b"value-data"));
        let after = n.free_space();
        assert!(after < before);
        // Replace with a larger value (abandons the old cell), then compact reclaims it.
        assert!(n.leaf_insert(b"key", b"a-much-larger-value-than-before"));
        n.compact();
        assert_eq!(n.view().value(0), b"a-much-larger-value-than-before");
    }

    #[test]
    fn validate_accepts_a_well_formed_node() {
        let mut page = blank_page();
        let mut n = NodeMut::new(&mut page);
        n.init(0);
        assert!(n.leaf_insert(b"a", b"1"));
        assert!(n.leaf_insert(b"b", b"22"));
        n.view().validate().expect("a well-formed leaf must validate");

        let mut ipage = blank_page();
        let mut ni = NodeMut::new(&mut ipage);
        ni.init(1);
        ni.set_leftmost_child(100);
        assert!(ni.internal_insert(b"m", 200));
        ni.view().validate().expect("a well-formed internal node must validate");
    }

    #[test]
    fn validate_rejects_a_corrupt_slot_directory_instead_of_panicking() {
        // Regression for auditor finding #3: a page that survives the checksum but has an internally
        // inconsistent slot directory must be reported as a Storage error on the read path, never
        // panic or slice out of bounds. We forge such corruption directly in the bytes.
        let mut page = blank_page();
        let mut n = NodeMut::new(&mut page);
        n.init(0);
        assert!(n.leaf_insert(b"a", b"1"));

        // (a) An absurd slot_count makes the directory run past the page.
        wr_u16(&mut page, OFF_SLOT_COUNT, u16::MAX);
        assert!(
            NodeView::new(&page).validate().is_err(),
            "an out-of-range slot_count must be rejected",
        );

        // (b) A single slot whose cell offset points past the special area.
        let mut page2 = blank_page();
        let mut n2 = NodeMut::new(&mut page2);
        n2.init(0);
        assert!(n2.leaf_insert(b"a", b"1"));
        let slot = SLOT_DIR_START; // first (and only) slot
        wr_u16(&mut page2, slot, (CELL_LIMIT - 1) as u16); // off near the very end
        wr_u16(&mut page2, slot + 2, 64); // klen that now runs past CELL_LIMIT
        assert!(
            NodeView::new(&page2).validate().is_err(),
            "a cell running past the heap region must be rejected",
        );

        // (c) A cell offset that points *into* the slot directory.
        let mut page3 = blank_page();
        let mut n3 = NodeMut::new(&mut page3);
        n3.init(0);
        assert!(n3.leaf_insert(b"a", b"1"));
        wr_u16(&mut page3, SLOT_DIR_START, (SLOT_DIR_START) as u16); // off inside the directory
        assert!(
            NodeView::new(&page3).validate().is_err(),
            "a cell overlapping the slot directory must be rejected",
        );
    }

    #[test]
    fn lower_bound_is_correct() {
        let mut page = blank_page();
        let mut n = NodeMut::new(&mut page);
        n.init(0);
        for k in [b"b", b"d", b"f"] {
            assert!(n.leaf_insert(k, b"v"));
        }
        let v = n.view();
        assert_eq!(v.lower_bound(b"a"), 0);
        assert_eq!(v.lower_bound(b"b"), 0);
        assert_eq!(v.lower_bound(b"c"), 1);
        assert_eq!(v.lower_bound(b"f"), 2);
        assert_eq!(v.lower_bound(b"g"), 3);
    }
}
