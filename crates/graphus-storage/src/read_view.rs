//! An owned, `Send + Sync` read view over a [`RecordStore`](crate::store::RecordStore)'s committed
//! state (`rmp` task #336, Slice 3a — the off-thread-read enabler, design "Approach (2): lighter
//! read-view").
//!
//! # What this is and why it exists
//!
//! Slice 1 (`a76c941`) put every store page behind an [`Arc<ConcurrentBufferPool>`] accessed via the
//! latched closure API; Slice 2 (`e547909`) made every store read method `&self` and proved
//! `RecordStore<D, S>: Send + Sync`. Slice 3a is the next, still-single-threaded step: factor the
//! read-**decode** path so it runs identically over an **owned** `(Arc<pool>, MetaSnapshot)` view as
//! it does over `&RecordStore`. Slice 3b then moves that owned, `Send + Sync` view onto reader threads
//! to run concurrent OLTP reads — with **no further storage change**.
//!
//! The crux ([[graphus-multithread-audit-sprint36]] §1.5 / the Slice-3a decision) is that the
//! read-decode methods depend on **only three things**:
//!
//! 1. `pool` — already an [`Arc<ConcurrentBufferPool>`], accessed through `&self` (Slice 1);
//! 2. `device_page(kind, rel_page)` — a **pure lookup** in a store's page map ([`graphus_pagemap`]:
//!    **no** fault-in, **no** mutation);
//! 3. `alloc.high_water()` — the scan upper bound.
//!
//! # What a read view snapshots, and what it does NOT (`rmp` #721)
//!
//! An owned read view freezes the **scan bound** and shares the **location oracle** live. That
//! asymmetry is the whole correctness argument, and getting it wrong was a production defect:
//!
//! - **`high_water` is SNAPSHOTTED.** It bounds the id range a scan visits (`1..high_water`), so it
//!   must not be chased by a concurrent writer. This is MVCC-superset-safe: any id allocated after the
//!   capture belongs to a writer that commits *after* the reader's snapshot timestamp, so it is
//!   invisible anyway — visibility is decided **above** this layer by `graphus_txn::is_visible_via`
//!   against the reader's own cloned `CommitRegistry`.
//!
//! - **The page map is LIVE.** The original design froze it too, on the argument that "the writer only
//!   appends, so a reader scanning `1..high_water` only ever indexes already-existing entries; any id
//!   allocated later is invisible anyway". That argument is true for **scans** and false for **chain
//!   walks** — and the reader does both. A chain walk FOLLOWS POINTERS (`node.first_rel`,
//!   `node.first_prop`, `prop.next_prop`, `HeapBlock::next_block`) read out of the **live**,
//!   in-place-updated record content this view shares through the page cache. A concurrently committed
//!   writer prepends its new record to a chain head, so the reader legitimately reaches a record on a
//!   page allocated after its capture. The "invisible anyway" clause cannot save it, because
//!   **visibility is decided ABOVE the location oracle**: a record the reader cannot LOCATE is never
//!   filtered — the walk dies first, with `"{kind} store page N not allocated"` surfacing to the client
//!   as an internal server error (`Neo.DatabaseError.*`).
//!
//! Resolving against the live map is sound because the map is **monotone** (append-only; never
//! remapped, never shrunk, never undone by a rollback), and it costs nothing: capture is now four
//! `Arc` refcount bumps instead of a deep copy of every store's page list *per read dispatch*. See
//! [`graphus_pagemap`] for the structure and its publication ordering.
//!
//! # One decode impl, no duplication
//!
//! The decode bodies live here once, as free functions taking borrows
//! `(pool, pages: &impl StorePages, …)`. Both the existing [`RecordStore`](crate::store::RecordStore)
//! `&self` read methods **and** [`StoreReadView`] delegate to them. The [`StorePages`] trait abstracts
//! "give me this store's `device_page`, `high_water` and live page count": `RecordStore` implements it
//! by borrowing `&self.stores` **directly** (so the hot read path allocates / clones **nothing** per
//! call), while [`MetaSnapshot`] implements it over its snapshotted bounds and `Arc`-shared live page
//! maps.

use std::sync::Arc;

use graphus_bufpool::ConcurrentBufferPool;
use graphus_core::error::{GraphusError, Result};
use graphus_core::{PageId, Value};
use graphus_io::BlockDevice;
use graphus_pagemap::PageMap;
use graphus_txn::{CommitOracle, CommitRegistry, Snapshot, View, is_visible_via};
use graphus_wal::LogSink;

use crate::heap::{HeapBlock, STRINGS_RECORD_SIZE};
use crate::idalloc::NULL_ID;
use crate::paging;
use crate::record::{
    MVCC_HEADER_SIZE, MvccHeader, NODE_RECORD_SIZE, NodeRecord, PROP_RECORD_SIZE, PropRecord,
    REL_RECORD_SIZE, RelRecord,
};
use crate::scan_polarity::{
    DecidedProperties, DecisionFold, DeltaVerdict, PropertyDelta, SupersetProperties, delta_verdict,
};
use crate::store::{STORE_COUNT, StoreKind};
use crate::undo::{self, CommitSlot, UndoAction, UndoDelta};
use crate::wal_rule::SharedWal;
use crate::{labels, valenc};

/// The page cache type the read path goes through, shared behind an [`Arc`] (Slice 1).
type Pool<D, S> = ConcurrentBufferPool<D, SharedWal<S>>;

/// A read-only projection of one fixed-record store's read metadata: everything the decode path needs
/// to map a record id to a device page and to bound a scan (`rmp` #336, Slice 3a; corrected by
/// `rmp` #721).
///
/// The two fields are deliberately of **different kinds**, and conflating them was the #721 defect:
///
/// - `high_water` is **snapshotted** — it is a *bound* on a scan's id range, and must not be chased by
///   a concurrent writer while the scan runs.
/// - `device_pages` is **live** — it is the *location oracle*, and the record content it locates is
///   itself live (the page cache is `Arc`-shared). A chain walk follows pointers out of live,
///   in-place-updated content and can therefore legitimately reach a record on a page allocated after
///   this capture. A frozen map answered "not allocated" for such a page, failing a legitimate read
///   with an internal error; visibility is decided ABOVE this layer, so a record that cannot be
///   LOCATED is never filtered — the walk dies first. See [`graphus_pagemap`].
///
/// Both fields are cheap: cloning a whole [`MetaSnapshot`] is four `Arc` refcount bumps and four `u64`
/// copies — no page-list copy at all (before #721, capture deep-copied every store's page list on
/// *every read dispatch*).
#[derive(Debug, Clone)]
pub struct StoreMetaSnapshot {
    /// The store's id high-water mark **at capture**: the scan upper bound (`1..high_water`).
    pub high_water: u64,
    /// A shared handle on the store's **live**, append-only page map (`rmp` #721).
    pub device_pages: Arc<PageMap>,
}

/// An owned, `Send + Sync + Clone` snapshot of a store's per-[`StoreKind`] location metadata
/// (`rmp` task #336, Slice 3a): the `high_water` bound + the `device_pages` index for each of the
/// four fixed-record stores. Captured on the engine thread by
/// [`RecordStore::capture_read_meta`](crate::store::RecordStore::capture_read_meta) and (Slice 3b)
/// handed to a reader thread, where it drives the decode path through a [`StoreReadView`] with **no**
/// live access to the store's mutable fields.
///
/// Cheap to clone (four [`Arc`] refcount bumps). Indexed by `StoreKind as usize`, mirroring
/// `RecordStore::stores`.
#[derive(Debug, Clone)]
pub struct MetaSnapshot {
    stores: [StoreMetaSnapshot; STORE_COUNT],
}

// `rmp` #336, Slice 3a: the metadata snapshot must be `Send + Sync` so Slice 3b can move it to a
// reader thread. A compile-time assertion (no runtime body) — it fails to build the moment a
// non-`Sync` field is introduced. `Arc<PageMap>` is `Send + Sync` (the map is built from atomics and
// `OnceLock`, `rmp` #721) and `u64` is, so the auto derivation holds with no `unsafe impl`.
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_meta_snapshot() {
        assert_send_sync::<MetaSnapshot>();
        assert_send_sync::<StoreMetaSnapshot>();
    }
    let _ = assert_meta_snapshot;
};

impl MetaSnapshot {
    /// Builds a snapshot from the four per-store `(high_water, device_pages)` pairs, in
    /// [`StoreKind`] order (`Node`, `Rel`, `Prop`, `Strings`). Used by
    /// [`RecordStore::capture_read_meta`](crate::store::RecordStore::capture_read_meta).
    #[must_use]
    pub fn new(stores: [StoreMetaSnapshot; STORE_COUNT]) -> Self {
        Self { stores }
    }

    /// This snapshot's metadata for `kind`.
    #[must_use]
    pub fn store(&self, kind: StoreKind) -> &StoreMetaSnapshot {
        &self.stores[kind as usize]
    }
}

/// The read path's location oracle: maps a record id to its device page and bounds a scan, for one
/// store kind at a time (`rmp` #336, Slice 3a). Implemented for both the live store (`&[FixedStore]`,
/// borrowed directly — **no per-call allocation**) and an owned [`MetaSnapshot`], so the single
/// decode impl below runs identically over either.
pub trait StorePages {
    /// The device page backing store-relative page `rel_page` of `kind`, or a storage error if that
    /// page is not allocated (the same error `RecordStore::device_page` returns). A **pure** lookup:
    /// no fault-in, no mutation.
    ///
    /// **Live** (`rmp` #721): resolves against the store's current, monotone page map, so a chain walk
    /// that legitimately reaches a record on a page allocated after the reader's snapshot can still
    /// LOCATE it. Whether that record is *visible* is decided above this layer.
    fn device_page(&self, kind: StoreKind, rel_page: u64) -> Result<PageId>;

    /// `kind`'s id high-water mark: the **scan** upper bound (`1..high_water`). Snapshotted for an
    /// owned read view, so a scan is not chased by a concurrent writer.
    fn high_water(&self, kind: StoreKind) -> u64;

    /// The number of device pages `kind`'s store currently maps — **live** and monotone.
    ///
    /// This is the chain-walk cycle guard's bound (`rmp` #721). It must be live, not the snapshotted
    /// `high_water`: a chain walk reads LIVE content, so a concurrent writer prepending to a chain head
    /// can legitimately make the walk take more steps than the reader's snapshot high-water allows —
    /// which a `high_water`-derived guard would misreport as a malformed chain (a *cycle*). The number
    /// of allocated record slots (`mapped_page_count * records_per_page`) is the true upper bound on the
    /// length of any acyclic chain, it is always `>= high_water` (the catalog's
    /// `high_water <= addressable capacity` invariant, `rmp` #479), and it grows with the writer — so it
    /// can never false-positive on a legitimate walk while still terminating any genuine cycle.
    fn mapped_page_count(&self, kind: StoreKind) -> u64;
}

/// The upper bound on the number of records `kind`'s store can currently address: the live number of
/// mapped device pages times the records each page holds. Bounds any acyclic chain walk (`rmp` #721).
fn slot_capacity<P: StorePages>(pages: &P, kind: StoreKind) -> u64 {
    pages
        .mapped_page_count(kind)
        .saturating_mul(paging::records_per_page(kind.record_size()) as u64)
}

impl StorePages for MetaSnapshot {
    fn device_page(&self, kind: StoreKind, rel_page: u64) -> Result<PageId> {
        usize::try_from(rel_page)
            .ok()
            .and_then(|p| self.store(kind).device_pages.get(p))
            .ok_or_else(|| {
                GraphusError::Storage(format!("{kind:?} store page {rel_page} not allocated"))
            })
    }

    fn high_water(&self, kind: StoreKind) -> u64 {
        self.store(kind).high_water
    }

    fn mapped_page_count(&self, kind: StoreKind) -> u64 {
        self.store(kind).device_pages.len() as u64
    }
}

// ----------------------------- the single decode impl -----------------------------
//
// Every function here is the ONE authoritative body for its read; the `RecordStore` `&self` methods
// and `StoreReadView` both delegate to it. Each takes `(pool, pages, …)` so the caller supplies the
// page cache and the location oracle (a live `&self.stores` borrow, or a `MetaSnapshot`).

/// Decodes the [`NodeRecord`] at `id` (the body of `RecordStore::read_node`).
///
/// # Errors
/// Returns a storage error if `id`'s page is not allocated or the page read fails.
pub fn read_node<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    id: u64,
) -> Result<NodeRecord> {
    let (rel_page, off) = paging::record_location(id, NODE_RECORD_SIZE);
    let dev = pages.device_page(StoreKind::Node, rel_page)?;
    pool.with_page_fetched(dev, |p| NodeRecord::decode(&p[off..off + NODE_RECORD_SIZE]))
}

/// Decodes the [`RelRecord`] at `id` (the body of `RecordStore::read_rel`).
///
/// # Errors
/// Returns a storage error if `id`'s page is not allocated or the page read fails.
pub fn read_rel<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    id: u64,
) -> Result<RelRecord> {
    let (rel_page, off) = paging::record_location(id, REL_RECORD_SIZE);
    let dev = pages.device_page(StoreKind::Rel, rel_page)?;
    pool.with_page_fetched(dev, |p| RelRecord::decode(&p[off..off + REL_RECORD_SIZE]))
}

/// Decodes the [`PropRecord`] at `id` (the body of `RecordStore::read_prop`).
///
/// # Errors
/// Returns a storage error if `id`'s page is not allocated or the page read fails.
pub fn read_prop<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    id: u64,
) -> Result<PropRecord> {
    // `rmp` #967 AC 2: the sole `PropRecord` decode in the workspace, so counting here counts every
    // `props.store` record read on every read path — the inline one and the off-thread reader pool
    // alike. Compiles to nothing unless the `read-probe` feature is on (see `crate::read_probe`).
    crate::read_probe::note_prop_read();
    let (rel_page, off) = paging::record_location(id, PROP_RECORD_SIZE);
    let dev = pages.device_page(StoreKind::Prop, rel_page)?;
    pool.with_page_fetched(dev, |p| PropRecord::decode(&p[off..off + PROP_RECORD_SIZE]))
}

/// Decodes the [`HeapBlock`] at `id` (the body of `RecordStore::read_block`).
///
/// # Errors
/// Returns a storage error if `id`'s page is not allocated or the page read fails.
pub fn read_block<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    id: u64,
) -> Result<HeapBlock> {
    let (rel_page, off) = paging::record_location(id, STRINGS_RECORD_SIZE);
    let dev = pages.device_page(StoreKind::Strings, rel_page)?;
    pool.with_page_fetched(dev, |p| {
        HeapBlock::decode(&p[off..off + STRINGS_RECORD_SIZE])
    })
}

/// Reads just the 25-byte MVCC header of record `id` in `kind`'s store (the body of
/// `RecordStore::read_mvcc`).
///
/// # Errors
/// Returns a storage error if `id`'s page is not allocated or the page read fails.
pub fn read_mvcc<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
    id: u64,
) -> Result<MvccHeader> {
    let (rel_page, off) = paging::record_location(id, kind.record_size());
    let dev = pages.device_page(kind, rel_page)?;
    pool.with_page_fetched(dev, |p| MvccHeader::read(&p[off..off + MVCC_HEADER_SIZE]))
}

// ------------------------- the undo area, from either read path -------------------------
//
// `rmp` #967. Once a property's old values live on the undo chain, **reading a property means
// reading the undo area** — so the undo area's decoders must live here, in the single decode impl,
// exactly as `read_prop` does. Routing only the inline `&RecordStore` path through them and leaving
// the reader pool to answer from something else is the #755/#768/#769/#770 defect family verbatim:
// the pool quietly served a different mechanism from the inline path, and the divergence was
// invisible until it produced wrong rows.

/// The upper bound on an undo-area id for `kind`, for the range check below.
///
/// **Live**, not the snapshotted `high_water`, for the `rmp` #721 reason: a reader walking a chain
/// follows pointers out of live record content, so a writer that prepended a delta after this
/// reader's capture can legitimately put a delta id above the captured high-water on a chain the
/// reader must still traverse. Bounding by the captured mark would fail that legitimate walk with
/// "id is outside 1..N" — and a record that cannot be LOCATED is never filtered, because visibility
/// is decided above this layer. The live slot capacity is `>= high_water` always, grows with the
/// writer, and still catches a genuinely dangling pointer.
fn undo_id_bound<P: StorePages>(pages: &P, kind: StoreKind) -> u64 {
    slot_capacity(pages, kind).max(pages.high_water(kind))
}

/// Copies the `len` raw bytes of undo-area record `id` out from its resident page under one read
/// latch, bounds-checked first so a dangling chain pointer is reported rather than silently reading
/// a neighbouring slot.
fn read_undo_slot_bytes<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
    id: u64,
    len: usize,
) -> Result<Vec<u8>> {
    let bound = undo_id_bound(pages, kind);
    if id == NULL_ID || id >= bound {
        return Err(GraphusError::Storage(format!(
            "{kind:?} store id {id} is outside 1..{bound}"
        )));
    }
    let (rel_page, off) = paging::record_location(id, kind.record_size());
    let dev = pages.device_page(kind, rel_page)?;
    pool.with_page_fetched(dev, |p| p[off..off + len].to_vec())
}

/// Decodes the `undo.store` delta at `id` (the body of `RecordStore::read_delta`).
///
/// Returns `Ok(None)` for a slot that is entirely zero — never written — which is not a delta at all
/// (`05 §12.3`: action `0` is reserved). Any other malformed slot is an error, never a
/// plausible-looking delta. A *reclaimed* slot decodes normally with its `in_use` bit clear.
///
/// # Errors
/// Returns a storage error if `id` is out of range, its page is unreadable, or the slot is occupied
/// but does not decode.
pub fn read_delta<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    id: u64,
) -> Result<Option<UndoDelta>> {
    // `rmp` #967 AC 2: the sole `UndoDelta` decode in the workspace, so this count is every delta
    // read on every read path — inline and off-thread alike. It exists so the record-read proof
    // cannot be satisfied by relocating the walk from `props.store` into `undo.store`. Compiles to
    // nothing unless the `read-probe` feature is on (see `crate::read_probe`).
    crate::read_probe::note_undo_read();
    let buf = read_undo_slot_bytes(pool, pages, StoreKind::Undo, id, undo::UNDO_RECORD_SIZE)?;
    if undo::is_zeroed(&buf) {
        return Ok(None);
    }
    UndoDelta::decode(&buf)
        .map(Some)
        .map_err(|e| GraphusError::Storage(format!("undo delta {id}: {e}")))
}

/// Decodes the `commit.store` slot at `id` (the body of `RecordStore::read_commit_slot`).
/// `Ok(None)` for a zeroed slot, exactly as [`read_delta`].
///
/// # Errors
/// Returns a storage error if `id` is out of range, its page is unreadable, or the slot is occupied
/// but does not decode.
pub fn read_commit_slot<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    id: u64,
) -> Result<Option<CommitSlot>> {
    // Counted separately from the delta reads so that relocating the visibility walk into the commit
    // indirection shows up as growth here rather than passing as an O(1) property read.
    crate::read_probe::note_commit_slot_read();
    let buf = read_undo_slot_bytes(pool, pages, StoreKind::Commit, id, undo::COMMIT_RECORD_SIZE)?;
    if undo::is_zeroed(&buf) {
        return Ok(None);
    }
    CommitSlot::decode(&buf)
        .map(Some)
        .map_err(|e| GraphusError::Storage(format!("commit slot {id}: {e}")))
}

/// Walks entity `(kind, entity)`'s undo chain newest-first, returning `(delta id, delta)` pairs (the
/// body of `RecordStore::undo_chain`).
///
/// The walk threads through **corpse** deltas (an aborted transaction's, whose `in_use` bit its
/// creation undo cleared) exactly as the incidence walk threads through a dead-link relationship
/// corpse: their action is never applied, but their `next` is still the way to the older versions
/// below them.
///
/// # Errors
/// Returns a storage error if a link dangles (points at a zeroed or out-of-range slot) or the chain
/// fails to terminate within the store's live slot capacity — both of which are corruption, not
/// states a healthy store can reach.
pub fn undo_chain<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
    entity: u64,
) -> Result<Vec<(u64, UndoDelta)>> {
    let head = read_mvcc(pool, pages, kind, entity)?.undo_ptr;
    let mut out = Vec::new();
    walk_undo_chain(pool, pages, kind, entity, head, |id, delta| {
        out.push((id, delta));
        Ok(true)
    })?;
    Ok(out)
}

/// The one chain walk: follows `head` newest-first, invoking `visit(id, delta)` for each link and
/// stopping early when it returns `Ok(false)`.
///
/// The cycle guard is the store's **live** slot capacity (`rmp` #721 — see [`undo_id_bound`]): a
/// well-formed chain visits each delta at most once, so exceeding the number of addressable slots
/// proves a cycle without a visited set on the hot path.
fn walk_undo_chain<D, S, P, F>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
    entity: u64,
    head: u64,
    mut visit: F,
) -> Result<()>
where
    D: BlockDevice,
    S: LogSink,
    P: StorePages,
    F: FnMut(u64, UndoDelta) -> Result<bool>,
{
    let guard = undo_id_bound(pages, StoreKind::Undo);
    let mut cur = head;
    let mut steps = 0u64;
    while cur != NULL_ID {
        steps += 1;
        if steps > guard {
            return Err(GraphusError::Storage(format!(
                "undo chain of {kind:?} {entity} is malformed (cycle?)"
            )));
        }
        let Some(delta) = read_delta(pool, pages, cur)? else {
            return Err(GraphusError::Storage(format!(
                "undo chain of {kind:?} {entity} reaches empty delta slot {cur}"
            )));
        };
        let next = delta.next;
        if !visit(cur, delta)? {
            return Ok(());
        }
        cur = next;
    }
    Ok(())
}

/// Collects entity `(kind, entity)`'s **whole** undo chain with each live delta's commit slot already
/// resolved — the superset-polarity half of a property read (`rmp` #967).
///
/// A **corpse** delta's slot is deliberately not read: the corpse is skipped before its commit
/// information is ever needed, so reading it would be one wasted record read per corpse on a path
/// whose record-read count is an acceptance criterion.
///
/// # Errors
/// As [`undo_chain`], plus a storage error if a **live** delta's `commit_info` names a slot that
/// holds no record — the one thing `05 §12.4` promises can never happen, so it is failed closed
/// here rather than dropped.
fn collect_undo_history<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
    entity: u64,
    head: u64,
) -> Result<Vec<PropertyDelta>> {
    let mut out = Vec::new();
    let mut fault = None;
    walk_undo_chain(pool, pages, kind, entity, head, |id, delta| {
        let slot = if delta.in_use() {
            let resolved = read_commit_slot(pool, pages, delta.commit_info)?;
            if resolved.is_none() {
                fault = Some((id, delta.commit_info));
            }
            resolved
        } else {
            None
        };
        out.push(PropertyDelta { id, delta, slot });
        Ok(true)
    })?;
    if let Some((id, commit_info)) = fault {
        return Err(GraphusError::Storage(format!(
            "undo delta {id} names commit slot {commit_info} which holds no record; a slot must \
             outlive its last reference (`05 §12.4`), so this version cannot be resolved"
        )));
    }
    Ok(out)
}

/// Reconstructs entity `(kind, entity)`'s properties as of `snapshot`, **stopping the chain walk at
/// the first delta the snapshot already reflects** (`rmp` #967, `04 §5.6`).
///
/// This is why it is a separate walk from `collect_undo_history` + [`SupersetProperties::decide`]
/// rather than a fold over it, and the difference is the whole acceptance criterion: the superset
/// walk must read the entity's *entire* chain (a population path needs every historical value), while
/// a reader that sees the live value must read exactly **one** delta and **one** commit slot no
/// matter how many times the key has been overwritten. Both apply the identical
/// [`delta_verdict`] + [`DecisionFold`] logic, so they cannot disagree about the answer — only about
/// how many records they touch to reach it.
///
/// # Errors
/// As [`undo_chain`], plus a storage error if a live delta's commit slot cannot be resolved.
fn decide_properties<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
    entity: u64,
    head: u64,
    cells: &[(u64, PropRecord)],
    snapshot: Snapshot,
) -> Result<DecidedProperties> {
    let mut fold = DecisionFold::seed(cells);
    let mut failure = None;
    walk_undo_chain(pool, pages, kind, entity, head, |id, delta| {
        let slot = if delta.in_use() {
            read_commit_slot(pool, pages, delta.commit_info)?
        } else {
            None
        };
        match delta_verdict(&delta, slot, snapshot, id) {
            Ok(DeltaVerdict::Skip) => Ok(true),
            Ok(DeltaVerdict::Apply) => {
                fold.apply(&delta, id);
                Ok(true)
            }
            Ok(DeltaVerdict::Stop) => Ok(false),
            Err(e) => {
                failure = Some(e);
                Ok(false)
            }
        }
    })?;
    match failure {
        Some(e) => Err(e),
        None => Ok(DecidedProperties::from_fold(fold, snapshot)),
    }
}

/// Whether entity `(kind, id)` **exists** as of `snapshot`, at statement granularity (`rmp` #972,
/// `04 §5.1.4`).
///
/// [`graphus_txn::is_visible_via`] answers the same question across *transactions*, from the two header
/// words alone. It cannot answer it within one transaction, because the header records only *which*
/// transaction created or expired the entity and never *which statement of it* — that lives on the
/// undo chain, where `05 §12.2` froze a `command_id` on every delta. So this refines `is_visible_via`
/// exactly where the header runs out of information, and nowhere else.
///
/// # Why this costs nothing on the paths that do not need it
///
/// Three gates, in order, and the ordinary read fails the first:
///
/// 1. under [`View::New`] the two answers are identical by construction, because
///    [`Snapshot::hides_own_command`] is `false` for every own write — so the walk is never entered;
/// 2. the statement question only arises for an entity **this** transaction created or deleted while
///    still in flight, which is what `own` tests for;
/// 3. and such an entity with no chain at all cannot have a statement to distinguish.
///
/// So a scan under the default view pays one `View` comparison per row, and an `OLD`-view scan over
/// entities the reader did not itself create pays two `u64` comparisons more.
///
/// # Why the walk terminates where it does
///
/// A creation writes `DeleteObject` and a deletion writes `RecreateObject` (`05 §12.3` — the action
/// is the inverse of the event), so applying one flips existence and applying the other flips it
/// back. Our own deltas sit at the head of the chain with descending `command_id`, so the walk stops
/// at the first delta from a command the reader already reflects — for a node created by an earlier
/// statement, that is the very first delta it reads.
///
/// # Errors
/// As [`undo_chain`], plus a storage error if a live delta's commit slot cannot be resolved. A read
/// fault is **never** answered with the header's own verdict: an entity whose existence cannot be
/// resolved must fail the read, not be guessed either way (the fail-closed-on-read-fault contract,
/// `rmp` #733).
pub fn entity_visible_at<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
    id: u64,
    mvcc: MvccHeader,
    snapshot: Snapshot,
    registry: &CommitRegistry,
) -> Result<bool> {
    let header_says = is_visible_via(registry, snapshot, mvcc.created_ts, mvcc.expired_ts)?;
    if snapshot.view == View::New || mvcc.undo_ptr == NULL_ID {
        return Ok(header_says);
    }
    // "Is this stamp MY own in-flight write?" through the one door (`rmp` #1069), instead of
    // comparing against an open-coded `VersionStamp::in_flight(snapshot.owner)` word. When the header
    // stops carrying a `TxnId` (phase 3) this rule changes in `CommitOracle`, not here.
    if !registry.names_own_write(mvcc.created_ts, snapshot.owner)?
        && !registry.names_own_write(mvcc.expired_ts, snapshot.owner)?
    {
        return Ok(header_says);
    }
    let mut exists = header_says;
    let mut failure = None;
    walk_undo_chain(pool, pages, kind, id, mvcc.undo_ptr, |delta_id, delta| {
        let slot = if delta.in_use() {
            read_commit_slot(pool, pages, delta.commit_info)?
        } else {
            None
        };
        match delta_verdict(&delta, slot, snapshot, delta_id) {
            Ok(DeltaVerdict::Skip) => Ok(true),
            Ok(DeltaVerdict::Apply) => {
                match delta.action {
                    // Undoing a creation: as of this snapshot the entity is not there yet.
                    UndoAction::DeleteObject => exists = false,
                    // Undoing a deletion: as of this snapshot the entity is still there.
                    UndoAction::RecreateObject => exists = true,
                    // Not an existence event — this chain carries every kind of version.
                    _ => {}
                }
                Ok(true)
            }
            Ok(DeltaVerdict::Stop) => Ok(false),
            Err(e) => {
                failure = Some(e);
                Ok(false)
            }
        }
    })?;
    match failure {
        Some(e) => Err(e),
        None => Ok(exists),
    }
}

/// The label bitmap node `id` presents to `snapshot`, reconstructed from the entity's undo chain
/// (`rmp` #968).
///
/// `live` is the word currently in the record and `head` its `undo_ptr`; both are taken from the
/// caller because every caller on the hot path has just decoded the record for its own MVCC
/// visibility check, so this costs **zero** extra record reads for the overwhelmingly common node
/// whose labels no open transaction has touched: `head == NULL_ID` returns `live` without reading
/// anything. That short-circuit is the whole reason the seam takes `head` instead of re-reading the
/// node, and it is what keeps a pure label scan at its pre-versioning cost.
///
/// The walk is the label twin of [`decide_properties`] and shares its two rules exactly, because it
/// walks the **same** chain: [`delta_verdict`] decides per delta, and the walk stops at the first
/// delta the snapshot already reflects. A delta records the *inverse* of the event
/// (`RemoveLabel` undoes an add, `AddLabel` undoes a removal), so applying one is a single bit flip
/// — idempotent and order-independent, which is why a per-bit delta is sufficient where a per-word
/// one would clobber bits another transaction owns. Deltas of any other action on the chain
/// (`SetProperty`, `RecreateObject`, …) are stepped over, exactly as
/// [`DecisionFold::apply`](crate::scan_polarity::DecisionFold) steps over these.
///
/// # Errors
/// As [`undo_chain`], plus a storage error if a live delta's commit slot cannot be resolved. A read
/// fault is **never** answered with the live word: that would be a silent dirty read of whatever an
/// uncommitted writer happened to leave in the record (the fail-closed-on-read-fault contract,
/// `rmp` #733).
pub fn label_bitmap_at<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    id: u64,
    live: u64,
    head: u64,
    snapshot: Snapshot,
) -> Result<u64> {
    if head == NULL_ID {
        return Ok(live);
    }
    let mut bitmap = live;
    let mut failure = None;
    walk_undo_chain(pool, pages, StoreKind::Node, id, head, |delta_id, delta| {
        let slot = if delta.in_use() {
            read_commit_slot(pool, pages, delta.commit_info)?
        } else {
            None
        };
        match delta_verdict(&delta, slot, snapshot, delta_id) {
            Ok(DeltaVerdict::Skip) => Ok(true),
            Ok(DeltaVerdict::Apply) => {
                match delta.action {
                    UndoAction::AddLabel => bitmap |= 1u64 << delta.token,
                    UndoAction::RemoveLabel => bitmap &= !(1u64 << delta.token),
                    // Not a label event: this chain carries every kind of version for the entity.
                    _ => {}
                }
                Ok(true)
            }
            Ok(DeltaVerdict::Stop) => Ok(false),
            Err(e) => {
                failure = Some(e);
                Ok(false)
            }
        }
    })?;
    match failure {
        Some(e) => Err(e),
        None => Ok(bitmap),
    }
}

/// The union of every label bitmap node `id` could present to **any** snapshot — the live word
/// widened by every label an [`UndoAction::AddLabel`] delta on its chain could restore (`rmp` #968).
///
/// The candidate-membership superset an index refill must gate on (`rmp` #904). It replaces
/// the retired `LabelHistory::candidate_superset`, and the widening rule is the same one stated in
/// direction: `AddLabel` is the delta written when a label is **removed**, so it names exactly a label
/// some older snapshot still sees. `RemoveLabel` names one an older snapshot does *not* see, and the
/// live word already carries it, so it widens nothing.
///
/// Deliberately snapshot-free and deliberately generous: it walks the **whole** chain, corpses
/// included, without consulting commit status. A refill has no snapshot to resolve against, and the
/// only safe error direction is a false positive — every consumer of these trees re-checks membership
/// against its own snapshot through [`label_bitmap_at`], and a seek's re-check can drop a candidate
/// but can never resurrect one.
///
/// # Errors
/// As [`undo_chain`].
pub fn node_label_superset_bitmap<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    id: u64,
    live: u64,
    head: u64,
) -> Result<u64> {
    if head == NULL_ID {
        return Ok(live);
    }
    let mut superset = live;
    walk_undo_chain(pool, pages, StoreKind::Node, id, head, |_id, delta| {
        if delta.action == UndoAction::AddLabel {
            superset |= 1u64 << delta.token;
        }
        Ok(true)
    })?;
    Ok(superset)
}

/// Reassembles the byte payload of the overflow heap chain whose head block is `head` (the body of
/// `RecordStore::read_chain`).
///
/// # Errors
/// Returns a storage error if the chain references a freed block or does not terminate within the
/// cycle guard (`Strings` high-water + 1).
pub fn read_chain<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    head: u64,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = head;
    // LIVE bound (`rmp` #721): a concurrent writer can grow the strings heap under this walk, so the
    // guard must be the live slot capacity, not the reader's snapshotted high-water (which a legitimate
    // live walk can now exceed). See `StorePages::mapped_page_count`.
    let guard = slot_capacity(pages, StoreKind::Strings) + 1;
    let mut steps = 0u64;
    while cur != NULL_ID {
        steps += 1;
        if steps > guard {
            return Err(GraphusError::Storage(format!(
                "overflow chain at head {head} is malformed (cycle?)"
            )));
        }
        let block = read_block(pool, pages, cur)?;
        if !block.mvcc.in_use() {
            return Err(GraphusError::Storage(format!(
                "overflow chain at head {head} references freed block {cur}"
            )));
        }
        out.extend_from_slice(block.bytes());
        cur = block.next_block;
    }
    Ok(out)
}

/// Decodes a property value from its `(type_tag, value_inline)` pair (the body of
/// `RecordStore::decode_property_value`): an inline scalar decodes directly; an overflow value is
/// reassembled from its [`read_chain`] payload.
///
/// # Errors
/// Returns a storage error if the value class cannot be decoded, or the overflow chain is unreadable.
pub fn decode_property_value<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    type_tag: u8,
    value_inline: u64,
) -> Result<Value> {
    if type_tag & valenc::OVERFLOW_BIT == 0 {
        return crate::propenc::decode_inline(type_tag, value_inline).map_err(GraphusError::from);
    }
    let class_tag = type_tag & !valenc::OVERFLOW_BIT;
    let bytes = read_chain(pool, pages, value_inline)?;
    valenc::decode(class_tag, &bytes).map_err(GraphusError::from)
}

/// **Page-batched scan primitive** (`rmp` #365): visits every record slot in the physical-id range
/// `1..high_water` of `kind`'s store, pinning + read-latching **each device page exactly once** and
/// walking all of that page's in-range slots under that single latch, then advancing to the next
/// page. For each slot it invokes `visit(id, &page_slice_of_the_record)` where `page_slice` is the
/// `record_size`-byte slice of the record at that slot — letting the caller decode just the bytes it
/// needs (an MVCC header, a full record) without re-entering the pool per id.
///
/// # Why one latch per page, not per record (the perf fix)
///
/// The per-id read path ([`read_node`]/[`read_rel`]/[`read_mvcc`]) calls
/// [`ConcurrentBufferPool::with_page_fetched`] once **per record id**: pin (`fetch_add`) → read
/// latch → decode → unpin. With 125 node records / 80 rel / 177 prop per 8 KiB page, the *same*
/// resident page is pinned + latched + unpinned 125× (resp. 80×, 177×) to read what one latch could
/// serve. The measured `read_scan/scan_node_ids` was a flat ~58 Melem/s (~17 ns/record) independent
/// of corpus size — dominated by that per-record synchronisation, not decode. This primitive folds
/// the whole page's slot walk into **one** `with_page_fetched` call per page.
///
/// # Correctness — pin/latch protocol (concurrent.rs)
///
/// This delegates the pin + identity re-validation + unpin entirely to
/// [`ConcurrentBufferPool::with_page_fetched`] (concurrent.rs:442), which on the hit path pins the
/// frame under the shard lock (`fetch_add`, additive — never an absolute `store`, so a concurrent
/// optimistic pin is preserved, concurrent.rs:452/654), re-validates the frame's `page_id` **under**
/// the read latch (concurrent.rs:456), runs the closure, then `unpin`s; the cold path falls back to
/// the full `fetch` with the load-once `Loading` reservation. So a pinned-and-latched page is never
/// evicted out from under us (CLOCK's `select_victim` skips any frame with `pin_count > 0`,
/// concurrent.rs:896/907), the bytes can never be torn (the read latch excludes the write-latched
/// evictor/mutator, concurrent.rs:479), and a concurrent writer to the same page is serialised by the
/// per-frame `RwLock` exactly as for a per-id read. Holding the read latch across a whole page's slot
/// walk does **not** widen any lock-ordering edge: the latch is still innermost-but-the-device-lock,
/// taken with no shard lock held, released before the next page — identical to the per-id path, just
/// amortised. It is pure decode work (no I/O, no pool re-entry), so it cannot block writers
/// pathologically: a single page latch is held for one page's worth of `MvccHeader::read`s.
///
/// **MVCC visibility is decided ABOVE this layer**: this returns *raw slot-occupied* records exactly
/// as the per-id loop did (`mvcc.in_use()`), leaving tombstone / snapshot filtering precisely where it
/// was (`graphus-cypher`'s `RecordStoreGraph`). It changes *how* the bytes are read, never *which*
/// records are seen.
///
/// # Errors
/// Returns a storage error if a store page in the range cannot be read (same surface as the per-id
/// loop, raised on the first failing page).
fn for_each_record_slot<D, S, P, F>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
    from: u64,
    visit: F,
) -> Result<()>
where
    D: BlockDevice,
    S: LogSink,
    P: StorePages,
    F: FnMut(u64, &[u8]) -> Result<()>,
{
    // The unbounded scan is exactly the bounded scan whose upper bound is the store's `high_water`.
    for_each_record_slot_bounded(pool, pages, kind, from, pages.high_water(kind), visit)
}

/// Like [`for_each_record_slot`] but stops at the exclusive id bound `to` (clamped to the store's
/// `high_water`), visiting only `from.max(1)..min(to, high_water)` (`rmp` #809). A caller that must
/// bound the *cost* of one scan — the release-active freeze-frontier audit sweeps a fixed-size id
/// window per GC pass — passes `to = from + window` so the work is `O(window)` regardless of store
/// size. Passing `to = high_water` reproduces [`for_each_record_slot`] byte-for-byte.
fn for_each_record_slot_bounded<D, S, P, F>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
    from: u64,
    to: u64,
    mut visit: F,
) -> Result<()>
where
    D: BlockDevice,
    S: LogSink,
    P: StorePages,
    F: FnMut(u64, &[u8]) -> Result<()>,
{
    let high_water = pages.high_water(kind);
    // Never visit an id at or beyond the high-water mark (an unallocated slot), whatever `to` requests.
    let to = to.min(high_water);
    if to <= 1 {
        return Ok(()); // ids start at 1 (id 0 is the reserved null pointer)
    }
    let record_size = kind.record_size();
    let rpp = paging::records_per_page(record_size) as u64;
    // Visit the id range `from.max(1)..to`, ascending (`rmp` #522: a `from > 1` lets the freeze
    // sweep skip every already-settled record below the frontier by starting on the page that holds
    // `from`; `rmp` #809: a `to < high_water` caps the window's span). The range spans store-relative
    // pages `first_page..=last_page` (id 1 lives on page 0 since `rpp >= 1`; the highest visited id is
    // `to - 1`). Walk those pages inclusively.
    let from = from.max(1);
    if from >= to {
        return Ok(()); // nothing in the requested (clamped) range
    }
    let first_page = from / rpp;
    let last_page = (to - 1) / rpp;
    for rel_page in first_page..=last_page {
        let dev = pages.device_page(kind, rel_page)?;
        // The first id this page holds, and the (exclusive) id one past its last in-range slot. Clamp
        // the upper bound to `to` so the final page never visits an id at or beyond the window end, and
        // clamp the lower bound to `from` (>= 1) so the null-pointer slot 0 of page 0 — and every
        // already-settled slot below the frontier — is skipped.
        let page_first_id = rel_page * rpp;
        let id_lo = page_first_id.max(from);
        let id_hi = (page_first_id + rpp).min(to);
        // ONE pin + read latch for the whole page (concurrent.rs:442): walk every in-range slot under
        // it. The closure does pure decode work; it never re-enters the pool with this page.
        pool.with_page_fetched(dev, |p| -> Result<()> {
            for id in id_lo..id_hi {
                // `record_location` is the single authoritative id → (page, byte-offset) mapping
                // (paging.rs:69): reuse it so the slot offset can never drift from the per-id path.
                // The page index it returns equals `rel_page` by construction here.
                let (slot_page, off) = paging::record_location(id, record_size);
                debug_assert_eq!(slot_page, rel_page);
                visit(id, &p[off..off + record_size])?;
            }
            Ok(())
        })??;
    }
    Ok(())
}

/// Enumerates the slot-occupied (`in_use`) node ids in `1..high_water`, ascending (the body of
/// `RecordStore::scan_node_ids`). The `high_water` bound comes from `pages`, so an owned snapshot
/// scans the as-of-capture id range.
///
/// Page-batched (`rmp` #365): pins + read-latches each node store page **once** and walks all 125
/// of its slots under that latch, rather than the former one-latch-per-record loop. See
/// [`for_each_record_slot`] for the pin/latch protocol and the unchanged MVCC-visibility boundary.
///
/// # Errors
/// Returns a storage error if a node store page in the range cannot be read.
pub fn scan_node_ids<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    for_each_record_slot(pool, pages, StoreKind::Node, 1, |id, rec| {
        // The `in_use` flag lives in the first MVCC-header byte of every record (record.rs:30): read
        // just that header from the slot, exactly as `read_node(...).mvcc.in_use()` did.
        if MvccHeader::read(&rec[..MVCC_HEADER_SIZE]).in_use() {
            out.push(id);
        }
        Ok(())
    })?;
    Ok(out)
}

/// Enumerates the slot-occupied (`in_use`) relationship ids in `1..high_water`, ascending (the body
/// of `RecordStore::scan_rel_ids`).
///
/// Page-batched (`rmp` #365): one pin + read latch per rel store page (80 slots), not per record.
///
/// # Errors
/// Returns a storage error if a relationship store page in the range cannot be read.
pub fn scan_rel_ids<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    for_each_record_slot(pool, pages, StoreKind::Rel, 1, |id, rec| {
        if MvccHeader::read(&rec[..MVCC_HEADER_SIZE]).in_use() {
            out.push(id);
        }
        Ok(())
    })?;
    Ok(out)
}

/// Page-batched enumeration of the MVCC header of every **slot-occupied** (`in_use`) record in
/// `kind`'s store, ascending by id (`rmp` #365). Returns `(id, MvccHeader)` for each in-use slot,
/// pinning + read-latching each store page **once** and reading all its slot headers under that
/// latch — the read half of the GC reclaim sweep and the freeze sweep, which formerly called
/// `read_rel`/`read_node`/`read_mvcc` once per id (store.rs GC ~1284-1320 / freeze ~1416). The
/// returned ids let the mutating half (reclaim / header-freeze patches, which need the **write**
/// latch and a WAL record per change) iterate only the occupied slots without re-reading them.
///
/// Visibility / reclaimability is still decided by the caller above this layer; this only batches
/// the physical read.
///
/// # Errors
/// Returns a storage error if a store page in the range cannot be read.
pub fn scan_in_use_mvcc<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
) -> Result<Vec<(u64, MvccHeader)>> {
    scan_in_use_mvcc_from(pool, pages, kind, 1)
}

/// Like [`scan_in_use_mvcc`] but visits only the id range `from..high_water` (`rmp` #522): the
/// incremental freeze sweep passes its per-kind freeze frontier as `from`, so it reads only the
/// records that may still carry an unfrozen stamp instead of re-scanning the whole store every
/// maintenance tick. `from == 1` is exactly [`scan_in_use_mvcc`].
///
/// # Errors
/// Returns a storage error if a store page in the range cannot be read.
pub fn scan_in_use_mvcc_from<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
    from: u64,
) -> Result<Vec<(u64, MvccHeader)>> {
    let mut out = Vec::new();
    for_each_record_slot(pool, pages, kind, from, |id, rec| {
        let mvcc = MvccHeader::read(&rec[..MVCC_HEADER_SIZE]);
        if mvcc.in_use() {
            out.push((id, mvcc));
        }
        Ok(())
    })?;
    Ok(out)
}

/// Counts the in-use `props.store` cells that carry an MVCC **tombstone** (`expired_ts != 0`), the
/// shape a **pre-`rmp`-#967** build left behind for a removed or overwritten property (`rmp` #967
/// audit).
///
/// This build never writes one — [`RecordStore::write_prop_cell`](crate::RecordStore) refuses a
/// non-zero `expired_ts`, and `D-property-removal` empties the cell in place instead — so on a store
/// this build created the answer is always `(0, None)` and the scan exists solely to decide whether a
/// **legacy** image may be opened at all. The predicate is deliberately identical to the consistency
/// checker's [`MvccHeaderFault::PropertyCellTombstoned`](crate::check::MvccHeaderFault), so the two
/// tiers cannot disagree about what a tombstoned cell is.
///
/// Returns `(count, first)`: how many offending cells the store holds, and the lowest offending
/// `(physical_id, expired_ts)` for the operator-facing diagnostic. It is a full pass over
/// `props.store` rather than a stop-at-first scan because the count is what tells an operator whether
/// they are looking at one stale cell or a whole graph's worth of removals, and because the answer
/// `(0, None)` — the case that decides an open succeeds — costs the full pass either way.
///
/// # Errors
/// Returns a storage error if a `props.store` page cannot be read.
pub fn scan_property_tombstones<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
) -> Result<(usize, Option<(u64, u64)>)> {
    let mut count = 0usize;
    let mut first: Option<(u64, u64)> = None;
    for_each_record_slot(pool, pages, StoreKind::Prop, 1, |id, rec| {
        let mvcc = MvccHeader::read(&rec[..MVCC_HEADER_SIZE]);
        if mvcc.in_use() && mvcc.expired_ts != 0 {
            count += 1;
            // The walk is ascending by id, so the first hit is the lowest.
            first.get_or_insert((id, mvcc.expired_ts));
        }
        Ok(())
    })?;
    Ok((count, first))
}

/// Like [`scan_in_use_mvcc_from`] but visits only the **bounded window** `from..min(from+max_ids,
/// high_water)` (`rmp` #809): the release-active freeze-frontier audit sweeps one such window per GC
/// pass so its cost is `O(max_ids)` — a constant tax on the GC path, independent of store size — while
/// a per-kind rotating cursor gives full coverage of the id space over successive passes. Returns the
/// in-use `(id, MvccHeader)` slots inside the window, and `next_from` = the first id NOT covered (the
/// clamped window end): when `next_from >= high_water` the store has been fully swept from `from`, and
/// the caller wraps its cursor back to `1`.
///
/// # Errors
/// Returns a storage error if a store page in the window cannot be read.
pub fn scan_in_use_mvcc_window<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
    from: u64,
    max_ids: u64,
) -> Result<(Vec<(u64, MvccHeader)>, u64)> {
    let high_water = pages.high_water(kind);
    let from = from.max(1);
    // The exclusive window end, clamped so a scan never runs past the allocated id space. `next_from`
    // is exactly this bound: a later pass resumes here, or the caller wraps when it reaches `high_water`.
    let to = from.saturating_add(max_ids).min(high_water);
    let mut out = Vec::new();
    if from < to {
        for_each_record_slot_bounded(pool, pages, kind, from, to, |id, rec| {
            let mvcc = MvccHeader::read(&rec[..MVCC_HEADER_SIZE]);
            if mvcc.in_use() {
                out.push((id, mvcc));
            }
            Ok(())
        })?;
    }
    Ok((out, to))
}

/// The `Label`-namespace token ids of node `id`'s labels, ascending (the body of
/// `RecordStore::node_labels`).
///
/// # Errors
/// As [`read_node`], plus a runtime error if the node's label bitmap is in overflow form (#39).
pub fn node_labels<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    id: u64,
) -> Result<Vec<u32>> {
    let node = read_node(pool, pages, id)?;
    labels::token_ids(node.labels).map_err(GraphusError::from)
}

/// Whether node `id` carries the label with `label_token_id` (the body of
/// `RecordStore::node_has_label`).
///
/// # Errors
/// As [`read_node`], plus a runtime error if `label_token_id >= 63` or the bitmap is overflow-form.
pub fn node_has_label<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    id: u64,
    label_token_id: u32,
) -> Result<bool> {
    let node = read_node(pool, pages, id)?;
    labels::has_label(node.labels, label_token_id).map_err(GraphusError::from)
}

/// How many times a property read re-reads an entity's cells while trying to observe them together
/// with an undo-chain head that did not move underneath them (`rmp` #1057).
///
/// A **liveness** backstop, not a correctness parameter: correctness comes from the validation
/// itself, which either succeeds or retries. One attempt is enough unless a writer mutated *this*
/// entity's properties during *this* entity's cell walk, so the loop is expected to run once; the
/// bound exists so that a pathological writer hammering one entity cannot spin a reader forever.
/// Exhausting it is answered with a **retriable** [`GraphusError::Transaction`] rather than with a
/// value, because the alternative is returning an image the store never held (the
/// fail-closed-on-read-fault contract, `rmp` #733).
const CHAIN_HEAD_STABILISE_ATTEMPTS: u32 = 1_024;

/// `(kind, entity)`'s property-chain head and undo-chain head, from **one** record read — so the two
/// words are mutually consistent by construction (one latched decode of one record).
///
/// # Errors
/// As [`read_node`] / [`read_rel`], plus a storage error if `kind` owns no property chain.
fn chain_anchor<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
    entity: u64,
) -> Result<(u64, u64)> {
    match kind {
        StoreKind::Node => {
            let node = read_node(pool, pages, entity)?;
            Ok((node.first_prop, node.mvcc.undo_ptr))
        }
        StoreKind::Rel => {
            let rel = read_rel(pool, pages, entity)?;
            Ok((rel.first_prop, rel.mvcc.undo_ptr))
        }
        other => Err(GraphusError::Storage(format!(
            "{other:?} records own no property chain, so they anchor no property read"
        ))),
    }
}

/// Reads `(kind, entity)`'s property cells **together with an undo-chain head they are consistent
/// with** — the atomicity a property read needs and did not have (`rmp` #1057).
///
/// # The defect this closes
///
/// A property read reconstructs a version from two things that live in **different records, on
/// different pages, under different latches**: the *current* value of each key (the `props.store`
/// cells) and the *older* values (the entity's undo chain, reached through the `undo_ptr` word of the
/// entity's own record). Nothing made the pair atomic, and the write path publishes the two halves in
/// this order (`RecordStore::link_delta` step 3, whose order is itself non-negotiable — the delta is
/// written in full and only then does the head name it):
///
/// 1. write the delta carrying the **old** value, and publish it as the entity's new chain head;
/// 2. rewrite the cell in place with the **new** value.
///
/// A reader that sampled the head **before** step 1 and the cell **after** step 2 therefore held a
/// new value with no delta above its head to undo it — and kept it, whoever wrote it. Measured on
/// `rmp` #1057: an off-thread reader summing 50 `:Account` balances returned a total off by exactly
/// one transfer leg, because for one account it had observed the value of a transaction that had not
/// merely committed after its snapshot but **had not committed at all** — a dirty read. The captured
/// interleaving (four real threads, storage layer, the reader's snapshot timestamp published only
/// after `commit` returned so no commit-slot state could have made the writer visible):
///
/// ```text
/// W  SET node 3 = 1000 (leg a of txn 21966)     <- in flight; delta 43749 published, cell rewritten
/// R0 READ node 3 @ts 21867: head 43748->43749 => 1000    <- kept the in-flight value
/// W  SET node 4 = 1010 (leg b of txn 21966)
/// R0 VIOLATION sum 7990 != 8000
/// ```
///
/// where a re-read of the very same node at the very same snapshot answered `1010` — the read was
/// not a function of the snapshot, which is what a torn read *is*.
///
/// # Why a validated re-read, and not simply reading the head last
///
/// Reading the head *after* the cells looks like the whole answer, and for the write path it is: the
/// writer publishes the pointer before the data, so a reader that reads the data before the pointer
/// cannot see data whose pointer it missed. But the **abort** path publishes the two halves in the
/// opposite order — [`RecordStore::rollback`] restores the cells (`apply_own_deltas`) and only then
/// detaches the deltas (`detach_own_deltas`) — so "head last" would newly expose a reader that
/// sampled a cell still holding an aborted value and then a head from which that value's delta had
/// already been detached. One read order cannot be safe against two opposite publication orders.
///
/// Validation is safe against both, because it does not depend on which order a writer publishes in:
/// it accepts the cells only if the head *did not move* across the walk that read them. Every
/// mutation of an entity's property cells is preceded by linking a delta onto that entity's chain
/// (`rmp` #970 made that true with no exceptions — an unversioned cell is a hole, not a shortcut), so
/// a head that is unchanged before and after the walk is a witness that no cell under it was
/// rewritten in between.
///
/// # Cost
///
/// **One extra 24-byte header read per property read** in the expected case — the `undo_ptr` word of
/// a record whose page the anchor read has just made resident, so a page-table lookup, a frame latch
/// and a decode, with no device I/O.
///
/// Measured, rather than asserted, on the worst *relative* case — an entity holding exactly ONE
/// property, warm pool, release build, `best of 7 × 400 000` reads on this host:
///
/// | | ns per visible-property read |
/// |---|---|
/// | before (head sampled first, no validation) | 139.5 |
/// | after (this function) | 155.8 / 158.0 / 160.8 |
///
/// so **+16 to +21 ns, ~+13%** where the added read is the largest possible fraction of the whole,
/// and proportionally less on every entity holding more than one key (`cargo bench -p graphus-bench
/// --bench prop_overwrite`, `distinct keys` arms at K = 1000: 38.2 µs before, 38.4 µs after — inside
/// the run-to-run spread, because one header read joins a thousand cell reads).
///
/// The `read_prop` / `read_delta` / `read_commit_slot` counts the `rmp` #967 acceptance criterion
/// pins are **unchanged** — this reads neither a property record, nor a delta, nor a commit slot, and
/// `tests/prop_visible_read_record_count.rs` still passes with its exact triple. A retry costs one
/// more anchor read plus one more cell walk, and only happens when a writer touched this entity
/// during this read.
///
/// # Errors
/// As [`read_node`] / [`read_rel`] and [`collect_prop_chain`], plus a **retriable**
/// [`GraphusError::Transaction`] if the head could not be observed stable within
/// [`CHAIN_HEAD_STABILISE_ATTEMPTS`].
fn cells_with_consistent_head<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    kind: StoreKind,
    entity: u64,
    owner_label: &str,
) -> Result<(Vec<(u64, PropRecord)>, u64)> {
    let (mut first_prop, mut head) = chain_anchor(pool, pages, kind, entity)?;
    for _ in 0..CHAIN_HEAD_STABILISE_ATTEMPTS {
        let cells = collect_prop_chain(pool, pages, first_prop, owner_label, entity)?;
        // The validation, and the only line that makes the pair atomic: the head this image will be
        // reconstructed against is the head that was already in place when the walk began.
        if read_mvcc(pool, pages, kind, entity)?.undo_ptr == head {
            return Ok((cells, head));
        }
        // It moved: a writer linked (or an abort detached) a delta on this entity while the cells
        // were being read, so the image and the chain describe different instants. Re-anchor — the
        // record's `first_prop` may have moved too, a prepend being how an added key arrives — and
        // read the cells again.
        let (moved_first_prop, moved_head) = chain_anchor(pool, pages, kind, entity)?;
        first_prop = moved_first_prop;
        head = moved_head;
    }
    Err(GraphusError::Transaction(format!(
        "property read of {owner_label} {entity} could not observe its cells and its undo-chain head \
         at one instant within {CHAIN_HEAD_STABILISE_ATTEMPTS} attempts; retry"
    )))
}

/// The **superset**-polarity read of `node_id`'s properties (the body of
/// `RecordStore::superset_scan_node_properties`): every slot-occupied cell in its `first_prop` chain
/// **and** its whole undo-delta history, which after `rmp` #967 is where every older value lives.
///
/// # Errors
/// Returns a storage error if a chain page is missing, a chain does not terminate, or a live delta's
/// commit slot cannot be resolved.
pub fn superset_scan_node_properties<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    node_id: u64,
) -> Result<SupersetProperties> {
    // `rmp` #1057: the cells and the head they are read against must be one instant, superset
    // polarity included — a cell rewritten under a head this walk never saw is a version the
    // "superset" would be missing, which is exactly what the polarity promises it never does.
    let (cells, head) = cells_with_consistent_head(pool, pages, StoreKind::Node, node_id, "node")?;
    let history = collect_undo_history(pool, pages, StoreKind::Node, node_id, head)?;
    Ok(SupersetProperties::from_chain(cells, history))
}

/// The **superset**-polarity read of `rel_id`'s properties — the relationship twin of
/// [`superset_scan_node_properties`], with the same two halves.
///
/// # Errors
/// As [`superset_scan_node_properties`].
pub fn superset_scan_rel_properties<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    rel_id: u64,
) -> Result<SupersetProperties> {
    // `rmp` #1057 — see [`cells_with_consistent_head`].
    let (cells, head) = cells_with_consistent_head(pool, pages, StoreKind::Rel, rel_id, "rel")?;
    let history = collect_undo_history(pool, pages, StoreKind::Rel, rel_id, head)?;
    Ok(SupersetProperties::from_chain(cells, history))
}

/// The **decision**-polarity read of `node_id`'s properties (the body of
/// `RecordStore::decision_scan_node_properties`): exactly what `snapshot` sees, reconstructed by the
/// early-stopping chain walk.
///
/// # Errors
/// Returns a storage error if a chain page is missing, a chain does not terminate, or a live delta's
/// commit slot cannot be resolved.
pub fn decision_scan_node_properties<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    node_id: u64,
    snapshot: Snapshot,
) -> Result<DecidedProperties> {
    // `rmp` #1057: the cells and the chain head are ONE observation, or this read reconstructs a
    // version out of two instants that never coexisted — see [`cells_with_consistent_head`].
    let (cells, head) = cells_with_consistent_head(pool, pages, StoreKind::Node, node_id, "node")?;
    decide_properties(
        pool,
        pages,
        StoreKind::Node,
        node_id,
        head,
        &cells,
        snapshot,
    )
}

/// The **decision**-polarity read of `rel_id`'s properties — the relationship twin of
/// [`decision_scan_node_properties`].
///
/// # Errors
/// As [`decision_scan_node_properties`].
pub fn decision_scan_rel_properties<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    rel_id: u64,
    snapshot: Snapshot,
) -> Result<DecidedProperties> {
    // `rmp` #1057 — see [`cells_with_consistent_head`].
    let (cells, head) = cells_with_consistent_head(pool, pages, StoreKind::Rel, rel_id, "rel")?;
    decide_properties(pool, pages, StoreKind::Rel, rel_id, head, &cells, snapshot)
}

/// The shared property-chain walk behind [`superset_scan_node_properties`] /
/// [`superset_scan_rel_properties`] (`rmp` #326's newest-wins is applied by the caller above this
/// layer; here we collect every `in_use` record head to tail). `owner_kind` / `owner_id` are only used
/// in the cycle-guard diagnostic, matching the exact messages
/// `RecordStore::superset_scan_{node,rel}_properties` produce.
fn collect_prop_chain<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    first_prop: u64,
    owner_kind: &str,
    owner_id: u64,
) -> Result<Vec<(u64, PropRecord)>> {
    let mut out = Vec::new();
    let mut cur = first_prop;
    // LIVE bound (`rmp` #721) — see `StorePages::mapped_page_count`.
    let guard = slot_capacity(pages, StoreKind::Prop) + 1;
    let mut steps = 0u64;
    while cur != NULL_ID {
        steps += 1;
        if steps > guard {
            return Err(GraphusError::Storage(format!(
                "property chain of {owner_kind} {owner_id} is malformed (cycle?)"
            )));
        }
        let p = read_prop(pool, pages, cur)?;
        let next = p.next_prop;
        if p.mvcc.in_use() {
            out.push((cur, p));
        }
        cur = next;
    }
    Ok(out)
}

/// The **superset**-polarity decoded read of relationship `rel_id`'s properties as
/// `(physical_id, key_token, Value)`, decoding inline scalars and overflow values (the body of
/// `RecordStore::superset_scan_rel_property_values`) — every slot-occupied version, tombstones
/// included.
///
/// # Errors
/// Returns a storage error if the property chain or an overflow chain is unreadable/corrupt.
pub fn superset_scan_rel_property_values<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    rel_id: u64,
) -> Result<Vec<(u64, u32, Value)>> {
    let chain = superset_scan_rel_properties(pool, pages, rel_id)?;
    let candidates: Vec<_> = chain.candidates().collect();
    let mut out = Vec::with_capacity(candidates.len());
    for c in candidates {
        let value = decode_property_value(pool, pages, c.type_tag, c.value_inline)?;
        out.push((c.source.id(), c.key, value));
    }
    Ok(out)
}

/// Enumerates the physical ids of the relationships incident to `node_id`, deduping a self-loop's two
/// chain links and threading transparently through dead-link corpses (the body of
/// `RecordStore::incident_rels`). The cycle guard uses the `Rel` high-water from `pages`.
///
/// # Errors
/// Returns a storage error if a chain page is missing or the chain does not terminate.
pub fn incident_rels<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    node_id: u64,
) -> Result<Vec<u64>> {
    use crate::record::ChainSide;

    let node = read_node(pool, pages, node_id)?;
    let mut out = Vec::new();
    let mut cur = node.first_rel;
    // LIVE bound (`rmp` #721) — see `StorePages::mapped_page_count`. The `2 *` accounts for a self-loop
    // being threaded into the chain twice.
    let guard = 2 * slot_capacity(pages, StoreKind::Rel) + 2;
    let mut steps = 0u64;
    let mut prev_link = NULL_ID;
    while cur != NULL_ID {
        steps += 1;
        if steps > guard {
            return Err(GraphusError::Storage(format!(
                "incidence chain of node {node_id} is malformed (cycle?)"
            )));
        }
        let r = read_rel(pool, pages, cur)?;
        let is_loop = r.start_node == node_id && r.end_node == node_id;
        if r.mvcc.in_use() && out.last() != Some(&cur) {
            out.push(cur);
        }
        let next = if is_loop {
            let (end_prev, end_next) = r.chain_pointers(ChainSide::End);
            if end_prev == prev_link || prev_link == NULL_ID {
                end_next
            } else {
                r.chain_pointers(ChainSide::Start).1
            }
        } else if r.start_node == node_id {
            r.start_next_rel
        } else {
            r.end_next_rel
        };
        prev_link = cur;
        cur = next;
    }
    Ok(out)
}

/// Enumerates `(physical_id, record)` for the relationships incident to `node_id`, reading each
/// chain link **exactly once** and — when `wanted_types` is non-empty — returning only the records
/// whose `type_id` is in `wanted_types` (`rmp` #324, "Win 1"). An empty `wanted_types` returns every
/// incident relationship (the untyped expand path), making this a strict superset enumeration
/// identical in membership to [`incident_rels`].
///
/// This is the single-pass twin of `incident_rels` + a per-id `read_rel`: the Cypher `expand` body
/// re-read every returned id with a second `rel()` call and then filtered by type, so a type-selective
/// traversal read every non-matching edge **twice** and SSI-marked it. Returning the decoded record
/// here lets the caller skip both the second read and the SSI mark of non-matching edges, while the
/// chain walk itself is byte-for-byte the same traversal (same self-loop dedupe via `out.last()`
/// identity check, same corpse threading through `!in_use` links, same cycle guard), so the #220
/// corpse splice, multigraph parallel edges, and untyped enumeration are all unaffected. MVCC
/// visibility is still decided **above** this layer.
///
/// # Errors
/// Returns a storage error if a chain page is missing or the chain does not terminate.
pub fn incident_rels_typed<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    node_id: u64,
    wanted_types: &[u32],
) -> Result<Vec<(u64, RelRecord)>> {
    use crate::record::ChainSide;

    let node = read_node(pool, pages, node_id)?;
    let mut out: Vec<(u64, RelRecord)> = Vec::new();
    let mut cur = node.first_rel;
    // LIVE bound (`rmp` #721) — see `StorePages::mapped_page_count`. The `2 *` accounts for a self-loop
    // being threaded into the chain twice.
    let guard = 2 * slot_capacity(pages, StoreKind::Rel) + 2;
    let mut steps = 0u64;
    let mut prev_link = NULL_ID;
    while cur != NULL_ID {
        steps += 1;
        if steps > guard {
            return Err(GraphusError::Storage(format!(
                "incidence chain of node {node_id} is malformed (cycle?)"
            )));
        }
        let r = read_rel(pool, pages, cur)?;
        let is_loop = r.start_node == node_id && r.end_node == node_id;
        // Self-loop dedupe is by physical-id identity exactly as `incident_rels`: a self-loop is
        // threaded into the chain twice, so we only emit it on the first visit. The type filter is
        // applied AFTER the in_use/dedupe gate so the emitted set is a faithful subset of
        // `incident_rels` restricted to `wanted_types`.
        if r.mvcc.in_use()
            && out.last().map(|(id, _)| *id) != Some(cur)
            && (wanted_types.is_empty() || wanted_types.contains(&r.type_id))
        {
            out.push((cur, r));
        }
        let next = if is_loop {
            let (end_prev, end_next) = r.chain_pointers(ChainSide::End);
            if end_prev == prev_link || prev_link == NULL_ID {
                end_next
            } else {
                r.chain_pointers(ChainSide::Start).1
            }
        } else if r.start_node == node_id {
            r.start_next_rel
        } else {
            r.end_next_rel
        };
        prev_link = cur;
        cur = next;
    }
    Ok(out)
}

// --------------------------------- StoreReadView ---------------------------------

/// An owned, `Send + Sync` read handle over a [`RecordStore`](crate::store::RecordStore)'s committed
/// state (`rmp` task #336, Slice 3a): an [`Arc`]-shared page cache plus a [`MetaSnapshot`] captured on
/// the engine thread. It exposes exactly the read surface the Cypher `GraphAccess` layer
/// (`graphus-cypher`) drives (the analogues of `node` / `rel` /
/// `scan_*` / `node_labels` / `node_has_label` / `superset_scan_node_properties` /
/// `superset_scan_rel_properties` / `superset_scan_rel_property_values` / `incident_rels` and the
/// low-level `read_*`), computed **purely** from `(pool, meta)` — it never touches the store's
/// mutable fields (`tokens` / `statistics` / `element_ids` / free lists), so the writer keeps
/// exclusive `&RecordStore` and the write/commit/GC/alloc path is untouched.
///
/// It carries **no** snapshot/visibility logic of its own: a returned record's `xmin`/`xmax` is
/// filtered by `graphus_txn::is_visible_via` against the caller's own cloned `CommitRegistry` and
/// snapshot timestamp, exactly as the `&RecordStore` path is filtered above this layer. Capturing the
/// `high_water` bound at dispatch is MVCC-superset-safe (a later-allocated id commits after the
/// reader's snapshot and is invisible anyway), so the view sees a strict superset of the ids the
/// reader could legally observe and the visibility filter above removes the rest.
///
/// Slice 3a is **single-threaded and behaviour-preserving**: this view is proven byte-identical to
/// the `&RecordStore` read methods (the equivalence test). Slice 3b moves it onto reader threads.
///
/// Cloning a [`StoreReadView`] is **cheap** — a handful of [`Arc`] refcount bumps (the page-cache
/// `Arc` and the [`MetaSnapshot`]'s four per-store `Arc<[PageId]>`), **no page copy**. A hand-written
/// [`Clone`] is used instead of `#[derive(Clone)]` because the derive would spuriously require
/// `D: Clone, S: Clone` (it bounds every type parameter), whereas the view only ever clones an
/// `Arc<…>` — which clones regardless of `D`/`S`. This is what makes the per-morsel `clone_box`
/// (`rmp` task #339) ~free.
pub struct StoreReadView<D: BlockDevice, S: LogSink> {
    pool: Arc<Pool<D, S>>,
    meta: MetaSnapshot,
}

impl<D: BlockDevice, S: LogSink> Clone for StoreReadView<D, S> {
    fn clone(&self) -> Self {
        Self {
            pool: Arc::clone(&self.pool),
            meta: self.meta.clone(),
        }
    }
}

// `rmp` #336, Slice 3a: `StoreReadView<D, S>` must be `Send + Sync` so Slice 3b can move it onto a
// reader thread. Proven by the `store_read_view_is_send_and_sync` test below (concrete + generic),
// mirroring `RecordStore`'s `record_store_is_send_and_sync` in `store.rs` so deleting a field's
// `Sync`-ness fails a test rather than silently compiling. The auto derivation holds with no
// `unsafe impl`: the only shared-ownership fields are `pool: Arc<ConcurrentBufferPool>` (`Send + Sync`
// from Slice 1, bounded `D, S: Send + Sync` — the same bound the concurrent pool's own auto
// `Send + Sync` requires) and `meta: MetaSnapshot` (whose sole shared field is `Arc<[PageId]>`,
// asserted above).
impl<D: BlockDevice, S: LogSink> StoreReadView<D, S> {
    /// Builds a read view from an [`Arc`]-shared page cache and a captured [`MetaSnapshot`]. Used by
    /// [`RecordStore::read_view`](crate::store::RecordStore::read_view).
    #[must_use]
    pub fn new(pool: Arc<Pool<D, S>>, meta: MetaSnapshot) -> Self {
        Self { pool, meta }
    }

    /// The shared node label-bitmap version history (`rmp` task #767) this view resolves labels
    /// The location metadata snapshot this view reads through.
    #[must_use]
    pub fn meta(&self) -> &MetaSnapshot {
        &self.meta
    }

    /// Decodes the [`NodeRecord`] at `id`. See [`read_node`].
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated or the read fails.
    pub fn node(&self, id: u64) -> Result<NodeRecord> {
        read_node(&self.pool, &self.meta, id)
    }

    /// Decodes the [`RelRecord`] at `id`. See [`read_rel`].
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated or the read fails.
    pub fn rel(&self, id: u64) -> Result<RelRecord> {
        read_rel(&self.pool, &self.meta, id)
    }

    /// Decodes the [`PropRecord`] at `id`. See [`read_prop`].
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated or the read fails.
    pub fn read_prop(&self, id: u64) -> Result<PropRecord> {
        read_prop(&self.pool, &self.meta, id)
    }

    /// Decodes the [`HeapBlock`] at `id`. See [`read_block`].
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated or the read fails.
    pub fn read_block(&self, id: u64) -> Result<HeapBlock> {
        read_block(&self.pool, &self.meta, id)
    }

    /// Reads the MVCC header of record `id` in `kind`'s store. See [`read_mvcc`].
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated or the read fails.
    pub fn read_mvcc(&self, kind: StoreKind, id: u64) -> Result<MvccHeader> {
        read_mvcc(&self.pool, &self.meta, kind, id)
    }

    /// Enumerates the slot-occupied node ids in the snapshot's `1..high_water`. See [`scan_node_ids`].
    ///
    /// # Errors
    /// Returns a storage error if a node store page in the range cannot be read.
    pub fn scan_node_ids(&self) -> Result<Vec<u64>> {
        scan_node_ids(&self.pool, &self.meta)
    }

    /// Enumerates the slot-occupied relationship ids in the snapshot's `1..high_water`. See
    /// [`scan_rel_ids`].
    ///
    /// # Errors
    /// Returns a storage error if a relationship store page in the range cannot be read.
    pub fn scan_rel_ids(&self) -> Result<Vec<u64>> {
        scan_rel_ids(&self.pool, &self.meta)
    }

    /// The `Label`-namespace token ids of node `id`'s labels, ascending. See [`node_labels`].
    ///
    /// # Errors
    /// As [`StoreReadView::node`], plus a runtime error for an overflow-form label bitmap.
    pub fn node_labels(&self, id: u64) -> Result<Vec<u32>> {
        node_labels(&self.pool, &self.meta, id)
    }

    /// The label bitmap node `id` presents to `snapshot` (`rmp` task #767), given the `live` word
    /// already decoded from its record.
    ///
    /// Takes `live` and the record's `undo_ptr` as `head` rather than re-reading the record, because
    /// every caller on the hot path has just decoded both for the MVCC visibility check. Resolves
    /// through the node's own undo chain (`rmp` #968), so an uncommitted or after-the-snapshot label
    /// change is undone instead of leaking into the read — and an untouched node costs no read at all.
    ///
    /// # Errors
    /// Returns a storage error if the node's undo chain cannot be walked (`rmp` #968).
    pub fn label_bitmap_at(
        &self,
        id: u64,
        live: u64,
        head: u64,
        snapshot: Snapshot,
    ) -> Result<u64> {
        label_bitmap_at(&self.pool, &self.meta, id, live, head, snapshot)
    }

    /// Whether entity `(kind, id)` exists as of `snapshot`, at statement granularity. See
    /// [`entity_visible_at`].
    ///
    /// # Errors
    /// Returns a storage error if the entity's undo chain cannot be walked (`rmp` #972).
    pub fn entity_visible_at(
        &self,
        kind: StoreKind,
        id: u64,
        mvcc: MvccHeader,
        snapshot: Snapshot,
        registry: &CommitRegistry,
    ) -> Result<bool> {
        entity_visible_at(&self.pool, &self.meta, kind, id, mvcc, snapshot, registry)
    }

    /// Whether node `id` carries the label with `label_token_id`. See [`node_has_label`].
    ///
    /// # Errors
    /// As [`StoreReadView::node`], plus a runtime error for `label_token_id >= 63` / overflow form.
    pub fn node_has_label(&self, id: u64, label_token_id: u32) -> Result<bool> {
        node_has_label(&self.pool, &self.meta, id, label_token_id)
    }

    /// The **superset**-polarity read of `node_id`'s property chain. See
    /// [`superset_scan_node_properties`].
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing or the chain does not terminate.
    pub fn superset_scan_node_properties(&self, node_id: u64) -> Result<SupersetProperties> {
        superset_scan_node_properties(&self.pool, &self.meta, node_id)
    }

    /// The **superset**-polarity read of `rel_id`'s property chain. See
    /// [`superset_scan_rel_properties`].
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing or the chain does not terminate.
    pub fn superset_scan_rel_properties(&self, rel_id: u64) -> Result<SupersetProperties> {
        superset_scan_rel_properties(&self.pool, &self.meta, rel_id)
    }

    /// The **decision**-polarity read of `node_id`'s properties. See
    /// [`decision_scan_node_properties`].
    ///
    /// This is the reader pool's half of the `rmp` #967 parity contract: the off-thread path
    /// reconstructs an older property version through **the same** undo-chain walk the inline
    /// `RecordStore` path uses. A reader pool that answered from a different mechanism is the
    /// #755/#768/#769/#770 defect family, and the reason both sides delegate to one body here.
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing, a chain does not terminate, or a live
    /// delta's commit slot cannot be resolved.
    pub fn decision_scan_node_properties(
        &self,
        node_id: u64,
        snapshot: Snapshot,
    ) -> Result<DecidedProperties> {
        decision_scan_node_properties(&self.pool, &self.meta, node_id, snapshot)
    }

    /// The **decision**-polarity read of `rel_id`'s properties. See
    /// [`decision_scan_rel_properties`].
    ///
    /// # Errors
    /// As [`StoreReadView::decision_scan_node_properties`].
    pub fn decision_scan_rel_properties(
        &self,
        rel_id: u64,
        snapshot: Snapshot,
    ) -> Result<DecidedProperties> {
        decision_scan_rel_properties(&self.pool, &self.meta, rel_id, snapshot)
    }

    /// Decodes the `undo.store` delta at `id`. See [`read_delta`].
    ///
    /// # Errors
    /// Returns a storage error if `id` is out of range or the slot is occupied but does not decode.
    pub fn read_delta(&self, id: u64) -> Result<Option<UndoDelta>> {
        read_delta(&self.pool, &self.meta, id)
    }

    /// Decodes the `commit.store` slot at `id`. See [`read_commit_slot`].
    ///
    /// # Errors
    /// Returns a storage error if `id` is out of range or the slot is occupied but does not decode.
    pub fn read_commit_slot(&self, id: u64) -> Result<Option<CommitSlot>> {
        read_commit_slot(&self.pool, &self.meta, id)
    }

    /// Walks entity `(kind, entity)`'s undo chain newest-first. See [`undo_chain`].
    ///
    /// # Errors
    /// Returns a storage error if a link dangles or the chain does not terminate.
    pub fn undo_chain(&self, kind: StoreKind, entity: u64) -> Result<Vec<(u64, UndoDelta)>> {
        undo_chain(&self.pool, &self.meta, kind, entity)
    }

    /// The **superset**-polarity decoded read of relationship `rel_id`'s properties as
    /// `(physical_id, key_token, Value)`. See [`superset_scan_rel_property_values`].
    ///
    /// # Errors
    /// Returns a storage error if the property chain or an overflow chain is unreadable/corrupt.
    pub fn superset_scan_rel_property_values(&self, rel_id: u64) -> Result<Vec<(u64, u32, Value)>> {
        superset_scan_rel_property_values(&self.pool, &self.meta, rel_id)
    }

    /// Decodes a property value from its `(type_tag, value_inline)` pair. See
    /// [`decode_property_value`].
    ///
    /// # Errors
    /// Returns a storage error if the value class cannot be decoded or the overflow chain is unreadable.
    pub fn decode_property_value(&self, type_tag: u8, value_inline: u64) -> Result<Value> {
        decode_property_value(&self.pool, &self.meta, type_tag, value_inline)
    }

    /// The physical ids of the relationships incident to `node_id`. See [`incident_rels`].
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing or the chain does not terminate.
    pub fn incident_rels(&self, node_id: u64) -> Result<Vec<u64>> {
        incident_rels(&self.pool, &self.meta, node_id)
    }

    /// The `(physical_id, record)` of the relationships incident to `node_id`, read once each and
    /// filtered to `wanted_types` (empty = all). See [`incident_rels_typed`] (`rmp` #324).
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing or the chain does not terminate.
    pub fn incident_rels_typed(
        &self,
        node_id: u64,
        wanted_types: &[u32],
    ) -> Result<Vec<(u64, RelRecord)>> {
        incident_rels_typed(&self.pool, &self.meta, node_id, wanted_types)
    }
}

#[cfg(test)]
mod tests {
    use graphus_io::MemBlockDevice;
    use graphus_wal::MemLogSink;

    use super::*;

    /// `StoreReadView<D, S>` and [`MetaSnapshot`] must be `Send + Sync` so Slice 3b (`rmp` #336) can
    /// move the read view onto a reader thread. Asserted both for the concrete DST instantiation (the
    /// production file device + file log is the same shape) and generically over the
    /// `D, S: Send + Sync` bound the concurrent pool's auto `Send + Sync` itself requires — mirroring
    /// `RecordStore::record_store_is_send_and_sync` in `store.rs`, so removing a field's `Sync`-ness
    /// fails this test rather than silently compiling.
    #[test]
    fn store_read_view_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StoreReadView<MemBlockDevice, MemLogSink>>();
        assert_send_sync::<MetaSnapshot>();
        fn assert_generic<D: BlockDevice + Send + Sync, S: LogSink + Send + Sync>() {
            fn inner<T: Send + Sync>() {}
            inner::<StoreReadView<D, S>>();
        }
        assert_generic::<MemBlockDevice, MemLogSink>();
    }
}
