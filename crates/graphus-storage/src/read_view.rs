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
//! 2. `device_page(kind, rel_page)` — a **pure index** into a store's `device_pages: Vec<PageId>`
//!    (`store.rs::device_page`: `.get(rel_page).copied()`, **no** fault-in, **no** mutation);
//! 3. `alloc.high_water()` — the scan / cycle-guard upper bound.
//!
//! The single writer only ever **appends** to `device_pages` and **advances** `high_water`. So a
//! reader that captures `(high_water, device_pages snapshot)` at dispatch and scans `1..high_water`
//! only ever indexes **already-existing, never-mutated** entries. This is MVCC-superset-safe: any id
//! allocated after the snapshot belongs to a writer that commits *after* the reader's snapshot
//! timestamp, so it is invisible anyway — visibility is still decided **above** this layer by
//! `graphus_txn::is_visible` against the reader's own cloned `CommitRegistry`, exactly as before.
//!
//! # One decode impl, no duplication
//!
//! The decode bodies live here once, as free functions taking borrows
//! `(pool, pages: &impl StorePages, …)`. Both the existing [`RecordStore`](crate::store::RecordStore)
//! `&self` read methods **and** [`StoreReadView`] delegate to them. The [`StorePages`] trait abstracts
//! "give me this store's `device_page` and `high_water`": `RecordStore` implements it by borrowing
//! `&self.stores` **directly** (so the hot read path allocates / clones **nothing** per call — the
//! Slice-1 single-thread tax is not increased), while [`MetaSnapshot`] implements it over its owned,
//! `Arc`-shared page lists.

use std::sync::Arc;

use graphus_bufpool::ConcurrentBufferPool;
use graphus_core::error::{GraphusError, Result};
use graphus_core::{PageId, Value};
use graphus_io::BlockDevice;
use graphus_wal::LogSink;

use crate::heap::{HeapBlock, STRINGS_RECORD_SIZE};
use crate::idalloc::NULL_ID;
use crate::paging;
use crate::record::{
    MVCC_HEADER_SIZE, MvccHeader, NODE_RECORD_SIZE, NodeRecord, PROP_RECORD_SIZE, PropRecord,
    REL_RECORD_SIZE, RelRecord,
};
use crate::store::{STORE_COUNT, StoreKind};
use crate::wal_rule::SharedWal;
use crate::{labels, valenc};

/// The page cache type the read path goes through, shared behind an [`Arc`] (Slice 1).
type Pool<D, S> = ConcurrentBufferPool<D, SharedWal<S>>;

/// A read-only projection of one fixed-record store's location metadata: everything the decode path
/// needs to map a record id to a device page and to bound a scan (`rmp` #336, Slice 3a).
///
/// `device_pages` is held as an [`Arc<[PageId]>`] so cloning a whole [`MetaSnapshot`] is a refcount
/// bump per store (four bumps), never a `Vec` copy. The list is the writer's `device_pages` captured
/// at one instant; because the writer only ever **appends** to it, every index this snapshot can name
/// stays valid for the snapshot's lifetime.
#[derive(Debug, Clone)]
pub struct StoreMetaSnapshot {
    /// The store's id high-water mark at capture: the scan upper bound (`1..high_water`) and the
    /// chain-walk cycle guard (`high_water + 1`).
    pub high_water: u64,
    /// The store-relative-page → device-`PageId` map at capture, shared cheaply across clones.
    pub device_pages: Arc<[PageId]>,
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
// non-`Sync` field is introduced. `Arc<[PageId]>` is `Send + Sync` (`PageId` is `Copy` POD) and
// `u64` is, so the auto derivation holds with no `unsafe impl`.
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
    fn device_page(&self, kind: StoreKind, rel_page: u64) -> Result<PageId>;

    /// `kind`'s id high-water mark: the scan upper bound and the chain-walk cycle guard.
    fn high_water(&self, kind: StoreKind) -> u64;
}

impl StorePages for MetaSnapshot {
    fn device_page(&self, kind: StoreKind, rel_page: u64) -> Result<PageId> {
        self.store(kind)
            .device_pages
            .get(rel_page as usize)
            .copied()
            .ok_or_else(|| {
                GraphusError::Storage(format!("{kind:?} store page {rel_page} not allocated"))
            })
    }

    fn high_water(&self, kind: StoreKind) -> u64 {
        self.store(kind).high_water
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
    let guard = pages.high_water(StoreKind::Strings) + 1;
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

/// Enumerates the slot-occupied (`in_use`) node ids in `1..high_water`, ascending (the body of
/// `RecordStore::scan_node_ids`). The `high_water` bound comes from `pages`, so an owned snapshot
/// scans the as-of-capture id range.
///
/// # Errors
/// Returns a storage error if a node store page in the range cannot be read.
pub fn scan_node_ids<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
) -> Result<Vec<u64>> {
    let high_water = pages.high_water(StoreKind::Node);
    let mut out = Vec::new();
    for id in 1..high_water {
        if read_node(pool, pages, id)?.mvcc.in_use() {
            out.push(id);
        }
    }
    Ok(out)
}

/// Enumerates the slot-occupied (`in_use`) relationship ids in `1..high_water`, ascending (the body
/// of `RecordStore::scan_rel_ids`).
///
/// # Errors
/// Returns a storage error if a relationship store page in the range cannot be read.
pub fn scan_rel_ids<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
) -> Result<Vec<u64>> {
    let high_water = pages.high_water(StoreKind::Rel);
    let mut out = Vec::new();
    for id in 1..high_water {
        if read_rel(pool, pages, id)?.mvcc.in_use() {
            out.push(id);
        }
    }
    Ok(out)
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

/// Collects every live property `(physical_id, record)` in `node_id`'s chain, head to tail (the body
/// of `RecordStore::node_properties`). The cycle guard uses the `Prop` high-water from `pages`.
///
/// # Errors
/// Returns a storage error if a chain page is missing or the chain does not terminate.
pub fn node_properties<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    node_id: u64,
) -> Result<Vec<(u64, PropRecord)>> {
    let node = read_node(pool, pages, node_id)?;
    collect_prop_chain(pool, pages, node.first_prop, "node", node_id)
}

/// Collects every live property `(physical_id, record)` in `rel_id`'s chain, head to tail (the body
/// of `RecordStore::rel_properties`).
///
/// # Errors
/// Returns a storage error if a chain page is missing or the chain does not terminate.
pub fn rel_properties<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    rel_id: u64,
) -> Result<Vec<(u64, PropRecord)>> {
    let rel = read_rel(pool, pages, rel_id)?;
    collect_prop_chain(pool, pages, rel.first_prop, "rel", rel_id)
}

/// The shared property-chain walk behind [`node_properties`] / [`rel_properties`] (`rmp` #326's
/// newest-wins is applied by the caller above this layer; here we collect every `in_use` record head
/// to tail). `owner_kind` / `owner_id` are only used in the cycle-guard diagnostic, matching the
/// exact messages `RecordStore::{node,rel}_properties` produce.
fn collect_prop_chain<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    first_prop: u64,
    owner_kind: &str,
    owner_id: u64,
) -> Result<Vec<(u64, PropRecord)>> {
    let mut out = Vec::new();
    let mut cur = first_prop;
    let guard = pages.high_water(StoreKind::Prop) + 1;
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

/// Collects relationship `rel_id`'s live properties as `(physical_id, key_token, Value)`, decoding
/// inline scalars and overflow values (the body of `RecordStore::rel_property_values`).
///
/// # Errors
/// Returns a storage error if the property chain or an overflow chain is unreadable/corrupt.
pub fn rel_property_values<D: BlockDevice, S: LogSink, P: StorePages>(
    pool: &Pool<D, S>,
    pages: &P,
    rel_id: u64,
) -> Result<Vec<(u64, u32, Value)>> {
    let chain = rel_properties(pool, pages, rel_id)?;
    let mut out = Vec::with_capacity(chain.len());
    for (pid, prop) in chain {
        let value = decode_property_value(pool, pages, prop.type_tag, prop.value_inline)?;
        out.push((pid, prop.key, value));
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
    let guard = 2 * pages.high_water(StoreKind::Rel) + 2;
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

// --------------------------------- StoreReadView ---------------------------------

/// An owned, `Send + Sync` read handle over a [`RecordStore`](crate::store::RecordStore)'s committed
/// state (`rmp` task #336, Slice 3a): an [`Arc`]-shared page cache plus a [`MetaSnapshot`] captured on
/// the engine thread. It exposes exactly the read surface the Cypher `GraphAccess` layer
/// (`graphus-cypher`) drives (the analogues of `node` / `rel` /
/// `scan_*` / `node_labels` / `node_has_label` / `node_properties` / `rel_properties` /
/// `rel_property_values` / `incident_rels` and the low-level `read_*`), computed **purely** from
/// `(pool, meta)` — it never touches the store's mutable fields (`tokens` / `statistics` /
/// `element_ids` / free lists), so the writer keeps exclusive `&mut RecordStore` and the
/// write/commit/GC/alloc path is untouched.
///
/// It carries **no** snapshot/visibility logic of its own: a returned record's `xmin`/`xmax` is
/// filtered by `graphus_txn::is_visible` against the caller's own cloned `CommitRegistry` and
/// snapshot timestamp, exactly as the `&RecordStore` path is filtered above this layer. Capturing the
/// `high_water` bound at dispatch is MVCC-superset-safe (a later-allocated id commits after the
/// reader's snapshot and is invisible anyway), so the view sees a strict superset of the ids the
/// reader could legally observe and the visibility filter above removes the rest.
///
/// Slice 3a is **single-threaded and behaviour-preserving**: this view is proven byte-identical to
/// the `&RecordStore` read methods (the equivalence test). Slice 3b moves it onto reader threads.
#[derive(Clone)]
pub struct StoreReadView<D: BlockDevice, S: LogSink> {
    pool: Arc<Pool<D, S>>,
    meta: MetaSnapshot,
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

    /// Whether node `id` carries the label with `label_token_id`. See [`node_has_label`].
    ///
    /// # Errors
    /// As [`StoreReadView::node`], plus a runtime error for `label_token_id >= 63` / overflow form.
    pub fn node_has_label(&self, id: u64, label_token_id: u32) -> Result<bool> {
        node_has_label(&self.pool, &self.meta, id, label_token_id)
    }

    /// Collects every live property `(physical_id, record)` in `node_id`'s chain. See
    /// [`node_properties`].
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing or the chain does not terminate.
    pub fn node_properties(&self, node_id: u64) -> Result<Vec<(u64, PropRecord)>> {
        node_properties(&self.pool, &self.meta, node_id)
    }

    /// Collects every live property `(physical_id, record)` in `rel_id`'s chain. See
    /// [`rel_properties`].
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing or the chain does not terminate.
    pub fn rel_properties(&self, rel_id: u64) -> Result<Vec<(u64, PropRecord)>> {
        rel_properties(&self.pool, &self.meta, rel_id)
    }

    /// Collects relationship `rel_id`'s live properties as `(physical_id, key_token, Value)`. See
    /// [`rel_property_values`].
    ///
    /// # Errors
    /// Returns a storage error if the property chain or an overflow chain is unreadable/corrupt.
    pub fn rel_property_values(&self, rel_id: u64) -> Result<Vec<(u64, u32, Value)>> {
        rel_property_values(&self.pool, &self.meta, rel_id)
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
