//! The record store: WAL-logged CRUD on nodes, relationships and properties with index-free
//! adjacency, over the buffer pool and the ARIES WAL (`04-technical-design.md` §2, §3, §4).
//!
//! [`RecordStore`] owns the three fixed-record stores (`nodes`, `rels`, `props`), the token
//! dictionaries, the id allocators, the free lists, and the durable catalog ([`crate::meta`]).
//! Every mutation follows the **physiological-redo / logical-undo** discipline of `04 §4.1`:
//!
//! 1. allocate an [`Lsn`](graphus_core::Lsn) by appending a WAL `Update` record whose `redo` is
//!    the post-image patch of the changed page region and whose `undo` is its pre-image patch
//!    ([`crate::paging`]);
//! 2. stamp that LSN as the page's `page_lsn` ([`graphus_bufpool::page::set_page_lsn`]) and apply
//!    the post-image to the cached page through the buffer pool.
//!
//! Pages are written home under **steal + no-force** (`04 §4.3`): the buffer pool consults the
//! [`crate::wal_rule::SharedWal`] WAL rule before any write-back, so the log is always durable
//! through a page's `page_lsn` first. A crash is recovered by [`crate::recovery`], which replays
//! this WAL against the raw device, after which [`RecordStore::open`] reloads the catalog.
//!
//! ## Index-free adjacency
//!
//! A relationship is threaded into two doubly-linked incidence chains at once (`04 §2.3`): the
//! chain through its `start_node` and the chain through its `end_node`. Insertion pushes the new
//! relationship at the head of each endpoint's chain in O(1); deletion unlinks it from both
//! chains in O(1). A self-loop is threaded twice into its node's single chain — once per side —
//! and traversal dedupes it by relationship id (`04 §2.4`). [`RecordStore::incident_rels`] walks
//! a node's chain in O(degree) with no index probe.

use std::collections::{BTreeMap, HashMap, VecDeque};

use std::sync::Arc;

use graphus_bufpool::ConcurrentBufferPool;
use graphus_bufpool::page::{self, HEADER_SIZE};
use graphus_core::error::{GraphusError, Result};
use graphus_core::{ElementId, Lsn, MAX_TIMESTAMP, PageId, Timestamp, TxnId, VersionStamp};
use graphus_io::{BlockDevice, PAGE_SIZE};
use graphus_pagemap::PageMapWriter;
use graphus_txn::{CommitRegistry, Snapshot, TxnOutcome};
use graphus_wal::{LogSink, WalManager};

use crate::heap::{self, BLOCK_PAYLOAD, HeapBlock, STRINGS_RECORD_SIZE};
use crate::idalloc::{ElementIdAllocator, FreeList, NULL_ID, PhysicalAllocator};
use crate::labels;
use crate::meta::{
    CompositeIndexEntry, ConstraintEntry, CountKey, FulltextIndexEntry, IndexState,
    LEGACY_FORMAT_VERSION, Meta, PROPERTY_UNDO_CHAIN_FORMAT_VERSION, RelCompositeIndexEntry,
    SchemaKey, SchemaValue, SpatialIndexEntry, Statistics, StoreMeta, TextIndexEntry, VectorEntity,
    VectorIndexEntry,
};
use crate::paging;
use crate::read_view::{self, MetaSnapshot, StoreMetaSnapshot, StorePages, StoreReadView};
use crate::record::{
    CHAIN_FLAG_END_FIRST, CHAIN_FLAG_START_FIRST, ChainSide, MVCC_HEADER_SIZE, MVCC_OFF_CREATED_TS,
    MVCC_OFF_EXPIRED_TS, MVCC_OFF_UNDO_PTR, MvccHeader, NODE_OFF_FIRST_PROP, NODE_OFF_FIRST_REL,
    NODE_OFF_LABELS, NODE_RECORD_SIZE, NodeRecord, PROP_CELL_REGION, PROP_RECORD_SIZE, PropRecord,
    REL_OFF_CHAIN_FLAGS, REL_OFF_END_PREV, REL_OFF_FIRST_PROP, REL_OFF_START_PREV, REL_RECORD_SIZE,
    RelRecord,
};
use crate::scan_polarity::{DecidedProperties, SupersetProperties};
use crate::tokens::{Namespace, TokenSnapshot, TokenStore};
use crate::undo::{self, CommitSlot, UndoAction, UndoDelta};
use crate::valenc;
use crate::wal_rule::SharedWal;

/// The device page reserved for the head of the durable catalog chain ([`crate::meta`]).
pub const META_PAGE: PageId = PageId(0);

/// Usable catalog bytes per metadata page. The durable catalog ([`Meta::encode`]) is split into
/// chunks of this size across a singly-linked chain of metadata pages rooted at [`META_PAGE`]
/// (`rmp` task #51), so the catalog can grow far past one page — previously a store panicked once
/// its device-page maps pushed the encoded catalog past a single 8 KiB page (a ~1000-page cap).
///
/// Each metadata page lays out, at offset [`HEADER_SIZE`], `chunk_len: u32` then `next_page: u64`
/// (the device id of the next link, or `0` to terminate — [`META_PAGE`] is never a link target, so
/// `0` is an unambiguous sentinel) then `chunk_len` catalog bytes. The 12-byte frame is subtracted
/// here so a full chunk written at `HEADER_SIZE` never runs past the page.
const META_CHUNK_CAP: usize = paging::PAGE_PAYLOAD - 12;

/// Bit set in the **head** metadata page's `chunk_len` field by every build that writes the undo
/// area, i.e. by on-disk format version 2 and up (`05 §12.6`, `rmp` #966).
///
/// It is set **unconditionally on every catalog this build writes**, so it keeps protecting each
/// later version for free: a version-3 store (`rmp` #967) carries the same bit and a pre-#966 build
/// refuses it by the same guard. The bit says "an undo-area-era catalog"; it does not encode *which*
/// version, and it does not need to — the number in the payload does that, and only a build that can
/// read the block gets that far.
///
/// # Why a flag bit in a length field
///
/// `05 §12.6` requires that "opening a store of a newer version under an older build must be
/// **refused** rather than misread". An older build cannot be taught a new version check after the fact — it is
/// already shipped — so the refusal has to come from a validation it *already* performs. It performs
/// exactly one on this frame: [`read_meta`](RecordStore::read_meta) rejects a chunk whose length runs
/// past the page. Setting bit 31 of `chunk_len` makes the length astronomically larger than a page,
/// so a pre-#966 build fails its own guard deterministically ("metadata chunk runs past the page")
/// instead of parsing a catalog whose trailing undo-area block it would silently drop — which would
/// orphan the two undo stores and strand every `undo_ptr` in the record stores.
///
/// A real chunk length is at most [`META_CHUNK_CAP`] (a few kilobytes), so the bit can never collide
/// with a genuine value. This build masks it off and treats its presence as informational; the
/// authoritative version is the one in the catalog payload ([`Meta`]).
///
/// **Ratified on 2026-08-03**, deliberately and with the trade-off stated: an old build failing
/// immediately on an undo-area-era store is worth more than one reading it wrongly and then writing over
/// it, and the error message it produces — "metadata chunk runs past the page", which does not name
/// the version — is the accepted price. This is a design decision, not an accident of the encoding:
/// removing the bit re-opens the silent-misread path (`05 §12.6`).
const META_FORMAT_V2_FLAG: u32 = 0x8000_0000;

/// Reserved system transaction id for standalone catalog writes (`04 §2.6`): a token/catalog
/// change that must be durable on its own (e.g. at `create`) uses this transaction.
const SYSTEM_TXN: TxnId = TxnId(u64::MAX);

/// Page-type byte for a record-store page (`05 §6`: low byte = type, high bytes = flags).
const PAGE_TYPE_RECORD: u8 = 1;
/// Page-type byte for the metadata page.
const PAGE_TYPE_META: u8 = 5;

/// The number of fixed-record stores backed by the catalog (`nodes`, `rels`, `props`, the
/// `strings.store` overflow heap, `04 §2.1`, and the undo area's `undo.store` / `commit.store` pair,
/// `05 §12.1`). Indexed by [`StoreKind`] `as usize`.
pub const STORE_COUNT: usize = 6;

/// Which of the fixed-record stores a record id belongs to (`04 §2.1`, `05 §12.1`).
///
/// The first four are the **MVCC record stores plus their overflow heap**; the last two are the
/// **undo area** (`rmp` #966). The split matters: only the first three carry the 25-byte MVCC header
/// of `05 §7`, so the freeze sweep, the tombstone reclamation and the version-visibility rules apply
/// to them and to nothing else. The undo area's records are pure storage — framed, checksummed,
/// WAL-logged and recovered exactly like any other page, but never version-stamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    /// The node store (`nodes.store`).
    Node = 0,
    /// The relationship store (`rels.store`).
    Rel = 1,
    /// The property store (`props.store`).
    Prop = 2,
    /// The `strings.store` variable-length overflow heap (`04 §2.1`, `rmp` task #43): its
    /// fixed-size "records" are the [`HeapBlock`]s of a value's block chain.
    Strings = 3,
    /// The `undo.store` delta store (`05 §12.1`, `rmp` #966): one 56-byte
    /// [`UndoDelta`](crate::undo::UndoDelta) per record — the inverse of one change to one entity.
    Undo = 4,
    /// The `commit.store` commit-info store (`05 §12.1`, `rmp` #966): one 32-byte
    /// [`CommitSlot`](crate::undo::CommitSlot) per writing transaction — the commit indirection
    /// point every one of that transaction's deltas resolves its status through.
    Commit = 5,
}

/// The six [`StoreKind`]s indexed by their discriminant (`kind as usize`), so a subtype byte can be
/// mapped back to its kind without a fallible `match` (`rmp` #398 orphan-page attribution).
pub(crate) const ALL_STORE_KINDS: [StoreKind; STORE_COUNT] = [
    StoreKind::Node,
    StoreKind::Rel,
    StoreKind::Prop,
    StoreKind::Strings,
    StoreKind::Undo,
    StoreKind::Commit,
];

/// The three stores whose records carry the frozen MVCC header of `05 §7` and are therefore subject
/// to version stamping, the freeze sweep and tombstone reclamation. The `strings.store` heap blocks
/// carry a header but are never visibility-checked; the undo area's records carry none at all.
const MVCC_STORE_KINDS: [StoreKind; 3] = [StoreKind::Node, StoreKind::Rel, StoreKind::Prop];

impl StoreKind {
    /// The fixed record size of this store in bytes.
    #[must_use]
    pub fn record_size(self) -> usize {
        match self {
            StoreKind::Node => NODE_RECORD_SIZE,
            StoreKind::Rel => REL_RECORD_SIZE,
            StoreKind::Prop => PROP_RECORD_SIZE,
            StoreKind::Strings => crate::heap::STRINGS_RECORD_SIZE,
            StoreKind::Undo => crate::undo::UNDO_RECORD_SIZE,
            StoreKind::Commit => crate::undo::COMMIT_RECORD_SIZE,
        }
    }

    /// Whether records of this store carry the frozen 25-byte MVCC header (`05 §7`) — i.e. whether
    /// they can be version-stamped, frozen, tombstoned and anchored to an undo chain. False for the
    /// undo area's own two stores, whose records are pure storage.
    #[must_use]
    pub fn is_versioned(self) -> bool {
        matches!(self, StoreKind::Node | StoreKind::Rel | StoreKind::Prop)
    }
}

/// In-memory handle to one fixed-record store: its kind, id allocator, free list, and the
/// store-relative-page → device-`PageId` map.
///
/// `device_pages` is a [`PageMapWriter`] — the append side of a **live**, append-only, lock-free map
/// whose read side ([`Arc<PageMap>`]) is shared with every off-thread reader (`rmp` #721). It is
/// deliberately NOT a `Vec` owned solely by the writer: the reader's location oracle must be live,
/// because the record *content* it navigates is live. The writer token is not `Clone` and appending
/// takes `&mut`, so the borrow checker still enforces the single-writer contract exactly as it did for
/// the old `Vec<PageId>`. See [`crate::pagemap`] for the monotonicity invariant, the publication
/// ordering, and why the single-writer contract is load-bearing for durability.
struct FixedStore {
    kind: StoreKind,
    alloc: PhysicalAllocator,
    free: FreeList,
    device_pages: PageMapWriter,
}

impl FixedStore {
    /// Builds a store handle from a durable catalog entry, including a **fresh** page map. Used on
    /// `open` / `create` / `restore` — the paths that build a `RecordStore` from scratch, where no
    /// reader can hold a handle to the old map yet.
    ///
    /// A rollback's catalog reload must NOT use this: it would hand the store a brand-new map and
    /// strand every in-flight reader on the old one. See
    /// [`RecordStore::reload_catalog`](RecordStore::reload_catalog).
    ///
    /// # Errors
    /// Returns a storage error if the catalog's page list exceeds the page map's addressable ceiling.
    fn from_meta(kind: StoreKind, m: &StoreMeta) -> Result<Self> {
        Ok(Self {
            kind,
            alloc: PhysicalAllocator::restore(m.high_water.max(1)),
            free: m.free_list.clone(),
            device_pages: PageMapWriter::from_pages(m.device_pages.iter().copied().map(PageId))?,
        })
    }

    /// A brand-new, empty store handle (the `create` path): an empty page map, a fresh allocator.
    fn empty(kind: StoreKind) -> Self {
        Self {
            kind,
            alloc: PhysicalAllocator::restore(1),
            free: FreeList::default(),
            device_pages: PageMapWriter::new(),
        }
    }

    fn to_meta(&self) -> StoreMeta {
        StoreMeta {
            high_water: self.alloc.high_water(),
            free_list: self.free.clone(),
            device_pages: self.device_pages.iter().map(|p| p.0).collect(),
        }
    }
}

/// The live-store location oracle (`rmp` #336, Slice 3a): the `RecordStore` read path drives the
/// single decode impl in [`crate::read_view`] through this, borrowing `&self.stores` **directly** so
/// the hot read path allocates / clones **nothing** per call (the Slice-1 single-thread tax is not
/// increased). The owned [`MetaSnapshot`] implements the same trait over `Arc`-shared page lists for
/// the off-thread view.
impl StorePages for [FixedStore; STORE_COUNT] {
    fn device_page(&self, kind: StoreKind, rel_page: u64) -> Result<PageId> {
        usize::try_from(rel_page)
            .ok()
            .and_then(|p| self[kind as usize].device_pages.get(p))
            .ok_or_else(|| {
                GraphusError::Storage(format!("{kind:?} store page {rel_page} not allocated"))
            })
    }

    fn high_water(&self, kind: StoreKind) -> u64 {
        self[kind as usize].alloc.high_water()
    }

    fn mapped_page_count(&self, kind: StoreKind) -> u64 {
        self[kind as usize].device_pages.len() as u64
    }
}

/// The set of records a still-open transaction has version-stamped, so its commit can **settle**
/// their MVCC headers from the in-flight `TxnId` to the assigned commit timestamp (`04 §5.2`).
/// `created` are records this txn stamped `xmin = in_flight(txn)`; `expired` are records it
/// tombstoned `xmax = in_flight(txn)`.
///
/// Node, relationship **and property** records are tracked: all three are MVCC-versioned and
/// visibility-filtered (`04 §5.3`). Per-value property MVCC (`rmp` task #50) makes a property write
/// a tombstone of the old version + a fresh version, so old values survive for older snapshots and
/// the reader layer filters them by visibility; the commit settle loop is kind-agnostic, so tracking
/// `StoreKind::Prop` ids alongside nodes/rels is all it takes. The `strings.store` overflow heap
/// blocks owned by a property are *not* tracked: they are never visibility-checked and are freed with
/// their owning property at GC.
/// One delta a still-open transaction has linked onto an entity's undo chain (`rmp` #966).
///
/// Recorded in link order so a rollback can decide, per delta, whether its slot is free again. See
/// [`ActiveTxn::undo_links`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UndoLink {
    /// The store the entity lives in (always a [`StoreKind::is_versioned`] one).
    kind: StoreKind,
    /// Physical id of the entity whose chain the delta was prepended onto.
    entity: u64,
    /// Physical id of the delta in `undo.store`.
    delta: u64,
}

#[derive(Debug, Default, Clone)]
struct ActiveTxn {
    created: Vec<(StoreKind, u64)>,
    expired: Vec<(StoreKind, u64)>,
    /// Physical ids this transaction pushed onto a store's free list (`rmp` #578). Only the
    /// GC/reclaim paths free ids, and they route every push through
    /// [`free_push`](RecordStore::free_push), which records it here. On a **live** rollback these
    /// pushes must be withdrawn from the in-memory free list the catalog reload restores: the WAL
    /// undo has just restored each reclaimed record's `in_use` bit, so leaving its id on the free
    /// list would hand out a still-live slot (the free-list twin of the #220/#172 monotonic
    /// high-water floor). A normal write transaction pushes nothing here (it only *pops* ids via
    /// [`alloc_id`](RecordStore::alloc_id)), so this stays empty for it.
    freed_ids: Vec<(StoreKind, u64)>,
    /// Physical ids this transaction **popped** (reused) from a store's free list via
    /// [`alloc_id`](RecordStore::alloc_id) (`rmp` #581). On a **live** rollback each such reused id was
    /// never actually consumed (the transaction aborted), so its slot should return to the free list —
    /// but ONLY when it did not become a live-referenced **corpse** (a concurrently-committed writer
    /// prepended onto it, the `rmp` #220/#172 pattern, which the GC corpse splice owns). The rollback
    /// re-pushes exactly the genuinely-UNREFERENCED pops
    /// ([`reclaim_aborted_pops`](RecordStore::reclaim_aborted_pops)); the rest are left for GC, never
    /// double-freed. Empty for a GC pass (which only frees, never pops). This is the symmetric
    /// reclaim that closes the bounded space leak the #578 fix documented.
    popped_ids: Vec<(StoreKind, u64)>,
    /// The `(owner_kind, owner_id)` a popped **property** id was prepended onto (`rmp` #581). A prop
    /// record carries no back-pointer to its owner, so — unlike a relationship (whose endpoints live
    /// in its own body) — the rollback needs the owner to walk the chain and decide whether the popped
    /// prop became a live-referenced corpse. Recorded by [`add_node_property`](RecordStore::add_node_property)
    /// / [`add_rel_property`](RecordStore::add_rel_property) only for ids that were pops (a subset of
    /// `popped_ids`, so bounded by the free list size at begin). A popped prop with no recorded owner
    /// is conservatively **not** re-pushed (a safe leak, never a double-free).
    popped_prop_owners: Vec<(u64, StoreKind, u64)>,
    /// **`rmp` #966.** The `commit.store` physical id of this transaction's **commit-info slot** —
    /// its commit indirection point (`04 §5.1.3`). Allocated lazily, on the first delta the
    /// transaction writes, so a read-only or delta-free transaction allocates nothing. Every delta
    /// this transaction creates names this slot, and the commit publishes it with a single store.
    commit_slot: Option<u64>,
    /// **`rmp` #966.** Every delta this transaction linked onto an entity's undo chain, in link
    /// order.
    ///
    /// A delta's creation is undone by the compare-and-set undo of the entity's `undo_ptr`
    /// ([`write_chain_head`](RecordStore::write_chain_head)), which fires **only if this
    /// transaction's delta is still the head** — so after the undo a delta is either unreachable
    /// (its slot is free again) or still threaded as a corpse, because another transaction prepended
    /// on top of it. [`reclaim_aborted_undo`](RecordStore::reclaim_aborted_undo) decides which by
    /// re-walking each touched entity's chain, exactly as
    /// [`reclaim_aborted_pops`](RecordStore::reclaim_aborted_pops) re-walks an incidence chain for
    /// the same question about a reused relationship slot.
    undo_links: Vec<UndoLink>,
    /// This transaction's own pending **schema-catalog DDL**, as a per-entry undo log (`rmp` #734) —
    /// the `Statistics` twin of [`freed_ids`](Self#structfield.freed_ids) / [`popped_ids`](Self#structfield.popped_ids).
    ///
    /// Unlike a record write, catalog DDL is not WAL-logged: it mutates one shared in-memory
    /// [`Statistics`] and becomes durable only via the commit-time `checkpoint_meta`. So a rollback
    /// cannot undo it by replaying the log — it has to know, per entry, what this transaction changed
    /// and what the entry held before. Each [`SchemaUndo`] records exactly that, appended in mutation
    /// order by [`with_schema_undo`](RecordStore::with_schema_undo) and replayed newest-first by
    /// [`apply_schema_undo`](RecordStore::apply_schema_undo) on rollback.
    ///
    /// Empty for the overwhelming majority of transactions: only a DDL statement writes here.
    schema_undo: Vec<SchemaUndo>,
    /// This transaction's net change to the six **live-record cardinality counters** (`rmp` #866) —
    /// the counts-half twin of [`schema_undo`](Self#structfield.schema_undo).
    ///
    /// Every counter mutation is recorded here by [`count_bump`](RecordStore::count_bump) at the same
    /// instant it is applied to the shared [`Statistics`], so both places that need the *committed*
    /// image can reconstruct it by withdrawing a delta: [`rollback`](RecordStore::rollback) withdraws
    /// exactly the aborting transaction's own, and
    /// [`committed_statistics`](RecordStore::committed_statistics) withdraws every still-open
    /// transaction's before a checkpoint persists the catalog.
    counts: CountDelta,
}

/// One transaction's pending, not-yet-committed change to the six live-record cardinality counters
/// of [`Statistics`] (`rmp` #866): a signed net delta per [`CountKey`].
///
/// # Why this needs none of [`SchemaUndo`]'s machinery
///
/// The catalog-DDL undo of `rmp` #734 needs a per-entry `seq` generation, an owner witness and a
/// predecessor-chain splice, because a DDL entry holds an **opaque value** on shared unversioned
/// state: restoring it means "put back what was there before *me*", which is only meaningful while
/// nobody else has written since, and out-of-order aborts break the chain.
///
/// Counters are not values, they are **counts**: integer addition is commutative and associative,
/// and every delta is exactly invertible by its negation. `committed + d₁ + d₂ − d₁` equals
/// `committed + d₂` no matter what order the transactions arrive, abort or commit in — so there is
/// no last-writer question to answer, no generation to witness, no ABA to distinguish and no chain
/// to splice. That is the whole reason this type is a handful of maps rather than an undo log, and
/// it is worth stating because the neighbouring [`SchemaUndo`] looks like the template to copy and
/// is not.
///
/// A create/delete pair inside one transaction nets to zero and is **pruned**, so
/// [`is_empty`](Self::is_empty) is exactly "this transaction has moved no counter", and the maps
/// stay bounded by the distinct labels/types the transaction actually touched (never by its row
/// count).
#[derive(Debug, Default, Clone)]
struct CountDelta {
    total_nodes: i64,
    total_relationships: i64,
    per_label: BTreeMap<u32, i64>,
    per_type: BTreeMap<u32, i64>,
    per_start_label_type: BTreeMap<(u32, u32), i64>,
    per_type_end_label: BTreeMap<(u32, u32), i64>,
}

impl CountDelta {
    /// Accumulates `delta` (always `±1` from a single write) under `key`.
    fn record(&mut self, key: CountKey, delta: i64) {
        match key {
            CountKey::TotalNodes => {
                self.total_nodes = self.total_nodes.saturating_add(delta);
            }
            CountKey::TotalRelationships => {
                self.total_relationships = self.total_relationships.saturating_add(delta);
            }
            CountKey::Label(token) => Self::accumulate(&mut self.per_label, token, delta),
            CountKey::RelType(token) => Self::accumulate(&mut self.per_type, token, delta),
            CountKey::StartLabelType(label, ty) => {
                Self::accumulate(&mut self.per_start_label_type, (label, ty), delta);
            }
            CountKey::TypeEndLabel(ty, label) => {
                Self::accumulate(&mut self.per_type_end_label, (ty, label), delta);
            }
        }
    }

    /// Adds `delta` to one keyed slot, **removing** the entry when it nets back to zero. The pruning
    /// is what makes "the map is empty" and "every delta is zero" the same statement, which
    /// [`is_empty`](Self::is_empty) — and therefore the checkpoint fast path — relies on.
    fn accumulate<K: Ord>(map: &mut BTreeMap<K, i64>, key: K, delta: i64) {
        match map.entry(key) {
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let next = slot.get().saturating_add(delta);
                if next == 0 {
                    slot.remove();
                } else {
                    *slot.get_mut() = next;
                }
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                if delta != 0 {
                    slot.insert(delta);
                }
            }
        }
    }

    /// `true` when this transaction has moved no counter at all — the case for every read-only
    /// transaction, every pure property write, and every DDL statement.
    fn is_empty(&self) -> bool {
        self.total_nodes == 0
            && self.total_relationships == 0
            && self.per_label.is_empty()
            && self.per_type.is_empty()
            && self.per_start_label_type.is_empty()
            && self.per_type_end_label.is_empty()
    }

    /// Un-applies this delta from `stats`, i.e. applies its exact negation. Turns an image that
    /// **includes** this transaction's pending counts into one that excludes them, which is what both
    /// the rollback (withdraw my own) and the checkpoint (withdraw every open transaction's) need.
    fn withdraw_from(&self, stats: &mut Statistics) {
        stats.apply_count_delta(CountKey::TotalNodes, self.total_nodes.saturating_neg());
        stats.apply_count_delta(
            CountKey::TotalRelationships,
            self.total_relationships.saturating_neg(),
        );
        for (&token, &d) in &self.per_label {
            stats.apply_count_delta(CountKey::Label(token), d.saturating_neg());
        }
        for (&token, &d) in &self.per_type {
            stats.apply_count_delta(CountKey::RelType(token), d.saturating_neg());
        }
        for (&(label, ty), &d) in &self.per_start_label_type {
            stats.apply_count_delta(CountKey::StartLabelType(label, ty), d.saturating_neg());
        }
        for (&(ty, label), &d) in &self.per_type_end_label {
            stats.apply_count_delta(CountKey::TypeEndLabel(ty, label), d.saturating_neg());
        }
    }
}

/// One entry of a transaction's catalog-DDL undo log (`rmp` #734): the schema-catalog entry a
/// mutation touched, and the value it held **before** that mutation.
///
/// A restore is conditioned on this transaction still being the entry's **last writer**, so a
/// rollback never clobbers DDL that has since been written by somebody else. The witness for that is
/// deliberately the generation stamp [`seq`](Self#structfield.seq) and **not** the value the mutation
/// left behind: comparing values cannot distinguish "nobody has written since" from "somebody wrote
/// the identical value since" (a plain ABA). Two concurrent `ANALYZE` passes computing the same
/// histogram bytes, or two racing `CREATE INDEX … IF NOT EXISTS` both writing `IndexState::Online`,
/// hit that case — and a value-witnessed undo would silently revert the other transaction's still-
/// pending write, which is the very lost-update #734 exists to prevent, mirrored.
#[derive(Debug, Clone)]
struct SchemaUndo {
    /// Store-global mutation generation, unique and strictly increasing across **all** transactions
    /// (`RecordStore::schema_seq`). Serves two purposes.
    ///
    /// As an **owner witness**: the restore fires only while `schema_last_seq[key] == seq`, i.e. only
    /// while this exact mutation is still the entry's most recent one — regardless of what value any
    /// later writer happened to store.
    ///
    /// As a **global order**: undoing one transaction's log needs only its own order, but building the
    /// committed catalog image ([`RecordStore::committed_statistics`]) undoes several open
    /// transactions' logs together, and those must be replayed in reverse *global* order. Undoing
    /// X-then-Y when Y wrote the same entry last would strand the entry at Y's `prev` (which is X's
    /// value) instead of walking it back to the committed value.
    seq: u64,
    /// The generation that owned this entry immediately **before** this mutation (`0` = no recorded
    /// writer). Restoring rolls `schema_last_seq[key]` back to this, so a chain of mutations by the
    /// same transaction unwinds one link at a time instead of stalling after the newest.
    prev_seq: u64,
    /// The schema-catalog entry this undo restores.
    key: SchemaKey,
    /// What the entry held before this transaction's mutation ([`None`] = the entry was absent).
    prev: Option<SchemaValue>,
}

/// What one [`RecordStore::gc`] pass did (observability, NFR-10; `rmp` task #59).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GcPassReport {
    /// Physical record versions reclaimed (slots freed, `04 §5.5`). Counts **record** slots only —
    /// nodes, relationships, property versions and heap blocks. Undo deltas are reported separately
    /// by [`undo_deltas_reclaimed`](Self#structfield.undo_deltas_reclaimed) so this number keeps its
    /// pre-`rmp`-#966 meaning.
    pub reclaimed: usize,
    /// **`rmp` #966.** Undo-delta slots reclaimed by the Phase F version-chain sweep: deltas no live
    /// snapshot can reach any more (`05 §12`). Separate from
    /// [`reclaimed`](Self#structfield.reclaimed) because a delta is not a record version — a caller
    /// tracking live-record cardinality must not see chain maintenance in that figure.
    pub undo_deltas_reclaimed: usize,
    /// MVCC header words (`xmin`/`xmax`) frozen from a committed writer's in-flight `TxnId` to its
    /// `Committed(ts)` stamp (`rmp` task #59), making those versions self-describing.
    pub frozen: usize,
    /// Committed writers scheduled to be forgotten from the Active/Recent Transaction Table when
    /// the GC transaction commits (a mid-pass rollback discards the schedule and prunes nothing).
    pub prune_scheduled: usize,
    /// The total physical-id span the **freeze sweep** visited across the three MVCC stores this pass
    /// (`rmp` #522 observability): `Σ (high_water - freeze_low)` per kind. On a steadily-growing store
    /// this stays ≈ the records added since the last pass (O(Δ)) instead of the whole store (O(N)) — the
    /// direct evidence the maintenance cost is no longer quadratic.
    pub freeze_scanned: u64,
    /// **`rmp` #809 — release-active freeze-frontier audit.** How many in-use MVCC records the bounded
    /// rotating-window audit ([`audit_freeze_frontier_window`](RecordStore::audit_freeze_frontier_window))
    /// found still bearing an **unfrozen committed-writer stamp** *after* the freeze sweep and *before*
    /// the registry prune — the exact silent-committed-data-loss invariant of `rmp` #522, verified in an
    /// ordinary release build (the [`debug_assert_freeze_complete`](RecordStore::debug_assert_freeze_complete)
    /// full scan runs only under `debug_assertions`/`check-cold-assert`). Normally `0`. A non-zero value
    /// means a freeze-frontier regression stranded a committed stamp: this pass **skipped the prune** as
    /// a fail-closed protective response (the affected writers stay resolvable, so no committed version is
    /// forgotten), and the caller must raise the operator alert.
    pub freeze_violations: u64,
    /// The first stranded record the `rmp` #809 audit found this pass (for the operator-facing WARN/ERROR
    /// log), or `None` when `freeze_violations == 0`. The storage crate carries no logger, so it surfaces
    /// the offending store/id/stamps here for the server maintenance loop to log.
    pub first_freeze_violation: Option<FreezeFrontierViolation>,
}

/// What one property-chain sweep did, per owner and in total (`rmp` #967).
///
/// Two numbers rather than one because the gate that decides whether the **next** pass runs the sweep
/// at all needs the second: `reclaimed` says what the pass achieved, `deferred_empty` says what it
/// left behind and must come back for. A pass can legitimately reclaim nothing and still owe work —
/// an empty cell whose watermark has not moved, or whose owner still holds a version chain — and
/// disarming the gate on that pass strands those cells until an unrelated removal re-arms it. See
/// [`RecordStore::gc_property_chain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct PropChainSweep {
    /// Property slots freed this sweep: reclaimable empty cells plus dead-link corpses.
    reclaimed: usize,
    /// Empty cells the sweep **saw but could not free yet** (condition 2 or 3 of
    /// [`RecordStore::gc_property_chain`] unmet). Non-zero means a later pass still has work.
    deferred_empty: usize,
}

impl std::ops::AddAssign for PropChainSweep {
    fn add_assign(&mut self, rhs: Self) {
        self.reclaimed += rhs.reclaimed;
        self.deferred_empty += rhs.deferred_empty;
    }
}

/// One in-use MVCC record found by the `rmp` #809 release-active freeze-frontier audit to still bear an
/// **unfrozen committed-writer in-flight stamp** after the freeze sweep — i.e. a stamp whose writer the
/// registry records as `Committed` but whose on-disk word is still the in-flight `TxnId` form. Forgetting
/// that writer at the following prune would make this version read as **invisible** (silent lost committed
/// data; the `rmp` #522 class). Carried out of the storage layer (which has no logger) so the server can
/// emit the structured alert naming the exact store/id/stamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreezeFrontierViolation {
    /// Which MVCC store the stranded record lives in.
    pub kind: StoreKind,
    /// The stranded record's physical id.
    pub id: u64,
    /// The record's raw `xmin` (created-ts) header word at detection.
    pub xmin: u64,
    /// The record's raw `xmax` (expired-ts) header word at detection.
    pub xmax: u64,
}

/// The prune a completed [`RecordStore::gc`] freeze sweep scheduled, held until its GC transaction
/// resolves (`rmp` task #59): [`RecordStore::commit`] of `gc_txn` forgets `writers` from the
/// Active/Recent Transaction Table (the freeze that made them forgettable is durable from that
/// point on); [`RecordStore::rollback`] of `gc_txn` discards the schedule, because the rollback's
/// WAL undo restores the in-flight header stamps that still need those entries to resolve.
#[derive(Debug)]
struct PendingGcPrune {
    gc_txn: TxnId,
    writers: Vec<TxnId>,
}

/// Both **directional** relationship-count projections of `rmp` task #856:
/// `(by_start_label_type, by_type_end_label)`, keyed `(startLabelToken, typeToken)` and
/// `(typeToken, endLabelToken)` respectively.
///
/// The return shape of [`RecordStore::recount_directional_rel_counts`], named so the pair reads as one
/// thing rather than as two anonymous maps whose key orders are easy to transpose.
pub type DirectionalRelCounts = (
    std::collections::BTreeMap<(u32, u32), u64>,
    std::collections::BTreeMap<(u32, u32), u64>,
);

/// A record store with index-free adjacency, over a buffer pool and the ARIES WAL.
///
/// `RecordStore` is generic over the block device `D` and the WAL log sink `S` so it runs over
/// the production file device + file log and over the in-memory DST device + log used by the
/// crash-recovery tests (`04 §11`).
pub struct RecordStore<D: BlockDevice, S: LogSink> {
    /// The page cache. `rmp` #337, Slice 1 swapped the single-threaded `BufferPool` for the
    /// loom-validated [`ConcurrentBufferPool`] (every method `&self`, shared behind an [`Arc`]), as
    /// the mechanical foundation for the later off-thread concurrent-read slices (#336/#339). This
    /// slice is **behaviour-preserving and still single-threaded**: the store methods stay
    /// `&mut self`, no reader threads are spawned, and the closure latch API (`with_page` /
    /// `with_page_mut` / `with_page_mut_lsn`) is used on every page access so the §1.5 GC
    /// lazy-freeze's two non-atomic 8-byte header writes are always under a per-frame write latch
    /// (and every read under a read latch), excluding the torn-word hazard once readers do go
    /// off-thread.
    pool: Arc<ConcurrentBufferPool<D, SharedWal<S>>>,
    wal: SharedWal<S>,
    element_ids: ElementIdAllocator,
    tokens: TokenStore,
    stores: [FixedStore; STORE_COUNT],
    /// The largest MVCC commit timestamp issued so far (`04 §5.2`); persisted in [`Meta`] so it
    /// resumes monotonically after reopen. The next commit timestamp is `commit_ts_hw + 1`, and a
    /// fresh reader's snapshot timestamp is `commit_ts_hw` (it sees exactly what has committed).
    commit_ts_hw: u64,
    /// Durable-write commit timestamps that have been PREPAREd (a `COMMIT` record appended) but whose
    /// group-commit `fdatasync` may not yet have hardened, as `(commit_lsn, commit_ts)` pairs in
    /// ascending `commit_lsn` order (`commit_prepare` runs serially on the engine thread, so pushes are
    /// naturally ordered). Drained into `durable_write_commit_ts_hw` by
    /// [`advance_durable_write_watermark`](Self::advance_durable_write_watermark) once the WAL
    /// `durable_len` covers each `commit_lsn`. A read-only commit appends nothing (`rmp` #529 fast
    /// path), so it never enters this queue — the whole point of the `rmp` #813 read-bookmark source
    /// being this queue rather than the phantom-tick-contaminated `commit_ts_hw`.
    pending_write_commits: VecDeque<(Lsn, Timestamp)>,
    /// The **durable-write commit-timestamp high-water** (`rmp` task #813): the largest commit timestamp
    /// of a write commit whose `COMMIT` record is `fdatasync`-durable. It is the source of a read
    /// transaction's Bolt causal **bookmark** (`"<db>:<durable_write_commit_ts_hw>"`): it always names an
    /// already-durable commit, is non-decreasing, and is IDENTICAL for two reads with no write between
    /// them (Neo4j read-bookmark semantics). Unlike [`snapshot_ts`](Self::snapshot_ts) / `commit_ts_hw`
    /// it is NOT advanced by a read-only commit's `rmp` #529 phantom tick, so it is a faithful
    /// durable-write high-water rather than the issued-timestamp high-water. Seeded on open from the
    /// recovered `commit_ts_hw` (which, post-recovery, reflects the last durable write — phantom ticks do
    /// not survive a crash), so it never steps backwards across a restart.
    durable_write_commit_ts_hw: u64,
    /// Per-open-transaction version-stamp bookkeeping, consumed at [`commit`](Self::commit) to
    /// settle in-flight headers to the commit timestamp (`04 §5.2`).
    active: HashMap<TxnId, ActiveTxn>,
    /// Set whenever a **catalog-only** mutation (one that changes durable [`Meta`] state *without*
    /// logging a WAL data record) has run since the last checkpoint — token interning
    /// ([`intern_token`](Self::intern_token)) and the histogram / index / full-text / spatial /
    /// constraint declarations. It is the second half of the read-only-commit signal (`rmp` #529):
    /// [`commit`](Self::commit) takes its zero-append/zero-`fdatasync` fast path only when the
    /// transaction both logged no WAL data record (`WalManager::is_active` is false) **and** dirtied no
    /// catalog here, because such a mutation is durable **only** via the commit-time
    /// [`checkpoint_meta`](Self::checkpoint_meta) the fast path would otherwise skip. Cleared after any
    /// durable commit persists the catalog and on [`rollback`](Self::rollback) (which reloads it) —
    /// in both cases **only if no still-open transaction holds pending schema DDL**, which a checkpoint
    /// deliberately does not persist (`rmp` #734, [`committed_statistics`](Self::committed_statistics)).
    /// The count mutators (`inc_node`/`inc_rel`/…) are *not* tracked here: they only ever run inside a
    /// record-writing operation, so `WalManager::is_active` already covers them.
    catalog_dirty: bool,
    /// Monotonic stamp handed to each [`SchemaUndo`] so catalog mutations carry a **store-global**
    /// order (`rmp` #734). Purely in-memory: undo logs never outlive the transactions that own them,
    /// so this needs no durability and is not part of [`Meta`].
    schema_seq: u64,
    /// The generation ([`SchemaUndo::seq`]) of the most recent mutation of each schema-catalog entry
    /// (`rmp` #734) — the **owner witness** an undo is conditioned on.
    ///
    /// Answers "am I still the last writer of this entry?" without comparing values, so an undo can
    /// tell "nobody wrote since" apart from "somebody wrote the identical value since". Bounded by the
    /// number of distinct catalog entries ever mutated in this process (tens, in practice: one per
    /// declared index, name, constraint or histogram), and purely in-memory — a stamp left behind by a
    /// long-resolved transaction is inert, because generations are unique and never reissued, so no
    /// live undo entry can ever match it by accident.
    schema_last_seq: HashMap<SchemaKey, u64>,
    /// The metadata **continuation** pages (device ids of the catalog chain after [`META_PAGE`]),
    /// in chain order (`rmp` task #51). Rebuilt from disk on open/recovery by walking the chain, and
    /// grown on demand at [`checkpoint_meta`](Self::checkpoint_meta) when the encoded catalog needs
    /// more than the head page. Device-page maps only ever grow, so this list never shrinks; it is
    /// surfaced through [`mapped_pages`](Self::mapped_pages) so backup, the consistency checker and
    /// the crash-recovery harness treat these as part of the durable image.
    meta_chain: Vec<PageId>,
    /// The Active/Recent Transaction Table (`04 §5.2`, `rmp` task #49). With **lazy GC-time header
    /// freezing**, [`commit`](Self::commit) no longer rewrites every version's header to settle its
    /// in-flight `TxnId` to the commit timestamp — it just records the `(TxnId → commit_ts)` here.
    /// Visibility and reclamation resolve an on-disk in-flight stamp through this table
    /// ([`is_reclaimable`](Self::is_reclaimable); readers via [`commit_registry`](Self::commit_registry)).
    /// Rebuilt on reopen from the WAL's commit records (each carries its `commit_ts`), so a
    /// committed-but-unfrozen version stays resolvable across a crash. The table is **bounded** by
    /// GC-time header freezing (`rmp` task #59): a [`gc`](Self::gc) pass rewrites every in-flight
    /// stamp of a committed writer to its `Committed(ts)` form and, once that freeze is durable
    /// (the GC transaction commits), forgets the now-unreferenced writers from this table.
    commit_registry: CommitRegistry,
    /// MVCC version history for the node **label bitmap** (`rmp` task #767).
    ///
    /// The label word is mutated IN PLACE inside the node record, so — unlike a property, which is a
    /// separate MVCC-versioned `PropRecord` — it has no version for `graphus_txn::is_visible` to
    /// filter. Without this, a label read returned whatever the word held at that instant: an
    /// uncommitted writer's change was visible to a concurrent reader (a **dirty read**) and a
    /// committed one was visible to a reader whose snapshot predated it (a **non-repeatable read**).
    /// This supplies the "older versions as logical undo deltas" half of `04 §5.1`'s ratified scheme
    /// that the in-place label write never had.
    ///
    /// `Arc`-shared with every [`StoreReadView`] so an off-thread reader resolves against the SAME
    /// live history (the page cache it decodes from is itself live, `rmp` #721, so a change committed
    /// after dispatch is already in the word it reads and only a live history can undo it).
    /// The registry prune the last completed [`gc`](Self::gc) freeze sweep scheduled, applied at
    /// the GC transaction's [`commit`](Self::commit) and discarded at its
    /// [`rollback`](Self::rollback) (`rmp` task #59). `None` while no GC pass is pending.
    pending_gc_prune: Option<PendingGcPrune>,
    /// **Incremental-GC state** (`rmp` #522). Before this, every maintenance [`gc`](Self::gc) pass
    /// re-scanned the ENTIRE store (freeze sweep, reclaim sweep, corpse walk, property sweep) even when
    /// almost nothing had changed since the last pass. On a monotonically growing store that made the
    /// background-maintenance cadence O(store size) per tick and O(store size²) in aggregate. These
    /// fields drive each sweep from only the work accrued since the previous pass, so a pass is
    /// amortised O(Δ) instead of O(N). All are pure in-memory optimisation state: they are NOT part of
    /// the durable [`Meta`], and are re-initialised on every [`open`](Self::open) so crash recovery and
    /// the on-disk format are byte-for-byte unchanged.
    ///
    /// The **freeze frontier**: `freeze_low[kind]` is the smallest physical id that may still carry an
    /// unfrozen committed-in-flight MVCC stamp. The freeze sweep visits only `[freeze_low, high_water)`.
    /// Invariant: every in-use record below `freeze_low[kind]` has all its committed-writer stamps
    /// already frozen to `Committed(ts)` and carries no in-flight-writer stamp. It is LOWERED to `id`
    /// by [`note_created`](Self::note_created) / [`note_expired`](Self::note_expired) (a fresh
    /// `xmin`/`xmax` in-flight stamp at `id`) and RAISED by the freeze sweep to the smallest id in the
    /// range still bearing an in-flight-writer stamp (or `high_water` if none). Initialised to `1` on
    /// open, so the first pass is a full freeze that settles every pre-existing on-disk stamp.
    freeze_low: [u64; STORE_COUNT],
    /// **`rmp` #809 — release-active freeze-frontier audit cursor.** Per-kind resume id for the bounded
    /// rotating-window audit ([`audit_freeze_frontier_window`](Self::audit_freeze_frontier_window)) that
    /// runs on every GC pass in an ordinary release build. Each pass scans `[freeze_audit_from[kind],
    /// +[`FREEZE_AUDIT_WINDOW_IDS`])` of each MVCC store and advances the cursor, wrapping to `1` at
    /// `high_water` — so the whole id space is re-verified every `⌈high_water / FREEZE_AUDIT_WINDOW_IDS⌉`
    /// passes at a fixed `O(window)` per-pass cost, independent of store size. Pure in-memory, rebuilt
    /// from `1` every open (no on-disk representation, so the store format and crash recovery are
    /// unchanged). Index `Strings` is unused (heap blocks carry no MVCC stamps).
    freeze_audit_from: [u64; STORE_COUNT],
    /// Reclaim candidates: per-kind physical ids of MVCC tombstones (`xmax` set) awaiting reclamation
    /// (`rmp` #522). The reclaim sweep iterates ONLY these ids instead of scanning the whole store —
    /// reclaiming those whose `xmax` has committed at or below the watermark and dropping entries that
    /// are no longer in-use tombstones (reclaimed, or reverted-to-live by an abort). Populated by
    /// [`note_expired`](Self::note_expired) and by the first full freeze sweep (which observes every
    /// pre-existing on-disk tombstone). `Node`/`Rel` drive the direct reclaim; `Prop` gates the
    /// property-chain sweep (prop tombstones are reclaimed owner-side by
    /// [`gc_property_chain`](Self::gc_property_chain)). `Strings` is unused (heap blocks are freed with
    /// their owning property, never tombstoned).
    pending_tombstones: [std::collections::BTreeSet<u64>; STORE_COUNT],
    /// Relationship dead-link **corpse** candidates (`rmp` #220 / #522): rel ids a rolled-back creation
    /// left `!in_use`-but-threaded. The corpse splice runs only when this is non-empty (or a full scan
    /// is pending), so a no-abort workload skips the whole-store corpse walk. Populated on
    /// [`rollback`](Self::rollback) from the aborting transaction's created rels; crash-materialised
    /// corpses are caught by the full first pass. Cleared when the splice runs (it collects every
    /// corpse in one walk).
    pending_corpse_rels: std::collections::BTreeSet<u64>,
    /// Whether property dead-link corpses (`rmp` #172) may exist since the last property sweep (`rmp`
    /// #522): set on [`rollback`](Self::rollback) of a transaction that created properties, cleared when
    /// the property sweep runs. Together with a non-empty `pending_tombstones[Prop]` it gates the
    /// property-chain sweep so a workload with no property deletes/aborts skips it entirely.
    pending_prop_corpses: bool,
    /// Whether an **unreclaimed empty** property cell (`rmp` #967, `D-property-removal`) may exist:
    /// set by [`empty_prop_cell`](Self::empty_prop_cell), and **re-derived** after every property
    /// sweep from what that sweep actually saw ([`PropChainSweep::deferred_empty`]) rather than
    /// cleared unconditionally.
    ///
    /// This replaces `pending_tombstones[Prop]` as the property sweep's gate. It has to: after #967 a
    /// property operation never stamps `xmax`, so that set is never populated again and gating on it
    /// would have left the sweep permanently off — the property store would grow without bound on any
    /// workload that removes properties, with every test still green because nothing asserts that a
    /// sweep *ran*.
    ///
    /// The re-derivation restores the one property the retired set had for free: it was reseeded from
    /// on-disk state by the freeze sweep every pass, so a pass that reclaimed nothing left the gate
    /// armed. A plain "clear after every sweep" does not, and the resulting stranding is reachable
    /// with one long-running reader (`rmp` #967 audit): the reader holds the watermark, a `REMOVE`
    /// commits, the pass defers the cell and disarms the gate, and the cell then survives every
    /// subsequent pass until an unrelated removal re-arms it or the store reopens.
    pending_empty_prop_cells: bool,
    /// Forces the first [`gc`](Self::gc) pass after [`open`](Self::open) to run the FULL corpse walk and
    /// property sweep (`rmp` #522), so any pre-existing on-disk corpses / tombstones a fresh process has
    /// no in-memory record of are caught. Cleared after that first pass; thereafter the gated
    /// incremental sweeps suffice because every new unit of work flows through the tracking above.
    gc_full_scan_pending: bool,
    /// The `(gc_txn, freeze_low-before-freeze)` savepoint of the in-progress GC pass (`rmp` #522). A GC
    /// pass's freeze sweep advances [`freeze_low`](Self::freeze_low), but a rollback of that pass's
    /// transaction restores (via WAL undo) the in-flight stamps it had frozen — which now sit BELOW the
    /// advanced frontier and would be skipped by the next sweep, silently stranding a committed writer's
    /// stamp unfrozen (an unbounded Active/Recent-Transaction-Table leak). So [`gc`](Self::gc) snapshots
    /// the frontier here before freezing; [`rollback`](Self::rollback) restores it if the aborting
    /// transaction is this GC pass, and [`commit_prepare`](Self::commit_prepare) clears it. `None`
    /// outside a GC pass. Mirrors [`pending_gc_prune`](Self::pending_gc_prune)'s lifecycle.
    gc_freeze_low_savepoint: Option<(TxnId, [u64; STORE_COUNT])>,
    /// **`rmp` #588 (sprint-52 B1) — reader-safe physical-slot reuse.** A per-kind, in-memory overlay
    /// of GC-freed physical ids that [`alloc_id`](Self::alloc_id) must NOT hand back out **yet**,
    /// mapping `id -> reuse barrier`. A [`gc`](Self::gc)-freed relationship/node/property slot keeps its
    /// record body (chain pointers) intact — only its `in_use` bit is cleared — so a still-in-flight
    /// **off-thread reader** (`rmp` #336) that cached `predecessor.next = id` across an unlatched hop
    /// still threads correctly THROUGH the freed corpse to the live record below it. The hazard is
    /// **reuse**: if a later create pops `id` and overwrites its body while that reader is mid-walk, the
    /// reader reads a FOREIGN record and diverts — losing a committed live edge or reporting a foreign
    /// one (an ACID Isolation violation). So a freed id is *listed* on the durable free list at reclaim
    /// (recovery has no in-flight readers → it is immediately reusable after a restart) but is **shadow-
    /// held** here until every reader that predates the free has retired, tracked by comparing the
    /// barrier (the engine's `next_ticket` at free time — every open transaction then has a strictly
    /// smaller ticket) against the oldest open transaction's ticket in [`release_held`](Self::release_held).
    /// Empty on the inline/DST path and whenever no transaction is open (immediate reuse — the pre-#588
    /// behaviour), so it is allocation-free and deterministic there.
    held_slots: [HashMap<u64, u64>; STORE_COUNT],
    /// **`rmp` #588.** The reuse barrier stamped onto every [`free_push`](Self::free_push) while a GC
    /// pass runs with at least one open transaction. `None` outside a bracketed GC pass (set by the
    /// engine via [`set_reuse_barrier`](Self::set_reuse_barrier) around [`gc`](Self::gc)), in which case
    /// a freed id is immediately reusable — the inline/DST path and the no-open-reader fast path.
    reuse_barrier: Option<u64>,
    /// **`rmp` #966.** The on-disk format version the durable catalog carried when this store was
    /// opened (`05 §12.6`); [`graphus_core::constants::FORMAT_VERSION`] for a store this build
    /// created. Surfaced by [`opened_format_version`](Self::opened_format_version) so a caller can
    /// see that an upgrade happened; the store itself always writes the current version.
    opened_format_version: u32,
    /// **`rmp` #966 — the undo-delta slab.** A half-open run `[next, end)` of freshly-allocated
    /// `undo.store` physical ids, all inside **one** store page, from which
    /// [`alloc_undo_id`](Self::alloc_undo_id) hands out deltas by a bare counter increment.
    ///
    /// This is the store-record form of Memgraph's `delta_container`, whose whole purpose is that a
    /// transaction does not pay an allocation per delta
    /// (`/data/refsrc/memgraph/src/storage/v2/delta_container.hpp:57-60`). Here the cost avoided is
    /// [`alloc_id`](Self::alloc_id)'s per-id free-list probe and `ensure_store_page` growth check; the
    /// locality gained matters more: a transaction's deltas land contiguously in one page, so its
    /// chain writes dirty one page and its WAL patches all name that page.
    ///
    /// Purely in-memory and never persisted: it is refilled from the allocator on demand and dropped
    /// on rollback. An open slab's unconsumed tail is therefore *leaked* across a close/crash — at
    /// most one page's worth of 56-byte slots (8 KiB) for the life of a store, and invisible to the
    /// consistency checker, which does not require an allocated id to be either in use or free.
    undo_slab: Option<(u64, u64)>,
    /// **`rmp` #966.** Entities whose undo chain has grown since the last GC pass and may therefore
    /// have become reclaimable: `(kind as u8, physical id)`. The GC chain sweep iterates exactly this
    /// set instead of scanning the record stores, mirroring the `rmp` #522 pending-tombstone design.
    /// Reseeded by a full scan on the first pass after [`open`](Self::open)
    /// (`gc_full_scan_pending`), which is what makes a crash-recovered store's chains reclaimable
    /// without any of this in-memory state surviving.
    pending_undo_chains: std::collections::BTreeSet<(u8, u64)>,
    /// **`rmp` #966.** Set when a rollback left one of its deltas threaded on an entity's chain as a
    /// corpse (only possible when another transaction prepended onto the *same* entity in between),
    /// which also strands that transaction's commit slot. The next full GC pass resolves it with a
    /// reference sweep over `undo.store`; until then the slot is a bounded leak, never a hazard.
    undo_orphan_slots_possible: bool,
    /// Exact, persisted live-record cardinalities for the planner's cardinality estimator
    /// (`rmp` task #79): per-label node counts and per-relationship-type counts. Part of the durable
    /// catalog ([`Meta`]) — mutated incrementally on the committed transitions that change a record's
    /// live label/type contribution (`create_rel`, `delete_node`/`delete_rel`, the label-set
    /// mutators), snapshotted at [`checkpoint_meta`](Self::checkpoint_meta) and reloaded wholesale on
    /// rollback / [`open`](Self::open), so it shares the id high-water marks' durability lifecycle and
    /// is correct after abort and after crash recovery. See [`Statistics`].
    statistics: Statistics,
    /// Take an automatic checkpoint once this many WAL bytes have been appended since the last one
    /// (`04 §4.7`, `rmp` storage audit F3). `0` disables the automatic cadence (manual
    /// [`checkpoint`](Self::checkpoint) only). Bounds crash-recovery **redo** to roughly this much
    /// log, instead of replaying the whole history. Defaults to
    /// [`DEFAULT_CHECKPOINT_INTERVAL_BYTES`].
    checkpoint_interval_bytes: u64,
    /// Whether the store sizes the WAL's segment seal threshold proportionally to its live data image
    /// (`rmp` #706). When `true` (the default) [`apply_adaptive_wal_segment_target`](Self::apply_adaptive_wal_segment_target)
    /// seals WAL segments at [`graphus_wal::segment_target_for_store`] of the store size at open and on
    /// every checkpoint, so a small database's WAL is reclaimed in small chunks instead of only in fixed
    /// 64 MiB units. When `false` the WAL keeps whatever fixed segment size its sink was constructed with
    /// (reproducing the pre-#706 behaviour). Toggled via [`set_wal_segment_sizing_adaptive`](Self::set_wal_segment_sizing_adaptive).
    wal_segment_sizing_adaptive: bool,
    /// The WAL `durable_len` captured at the last checkpoint (or at open); the automatic cadence
    /// fires when `durable_len - this >= checkpoint_interval_bytes`.
    wal_len_at_last_checkpoint: u64,
    /// Commit-record LSN of every committed-but-not-yet-GC-frozen transaction (`rmp` #114, the
    /// lazy-freeze interaction of #49/#59). A committed version may still carry its writer's in-flight
    /// `TxnId` on disk until GC freezes it; resolving that stamp after a crash needs the writer's
    /// commit record. WAL reclamation must therefore never drop a commit record below the **oldest**
    /// entry here. Populated at commit and on reopen (from the durable commit records), pruned when a
    /// GC freeze settles + forgets a writer — exactly tracking [`commit_registry`](Self::commit_registry).
    unfrozen_commit_lsn: BTreeMap<TxnId, Lsn>,
    /// The largest real transaction id present in the durable WAL at [`open`](Self::open) time (or `0`
    /// for a freshly [`create`](Self::create)d store). Transaction ids are written into the WAL but are
    /// not otherwise persisted, so a reopened engine must restart its id counter **past** this value or
    /// it would reuse ids already in the log — which silently breaks ARIES loser/winner classification
    /// on the next crash (see [`WalManager::max_recovered_txn_id`]). Surfaced through
    /// [`recovered_txn_hw`](Self::recovered_txn_hw) so the coordinator that owns the id counter
    /// (`graphus_cypher::TxnCoordinator`) can seed it monotonically across recovery.
    recovered_txn_hw: u64,
    /// The optional **doublewrite buffer** protecting this store's home-page writes from torn writes
    /// (`05 §3`, `04 §4.5`; `rmp` #384). When present, [`checkpoint`](Self::checkpoint) and
    /// [`flush`](Self::flush) route their home flush through [`flush_protected`](Self::flush_protected)
    /// — every dirty home page is staged-and-synced into the DWB before it is written home, so a torn
    /// home page can be repaired from its intact DWB copy on the next open
    /// ([`crate::recovery::recover_device_with_dwb`]). The DWB device is the **same** [`BlockDevice`]
    /// type as the store's own device, so an encrypted store's DWB is an encrypted device sharing the
    /// store's key (no plaintext page image is ever written to the DWB area). `None` for an
    /// unprotected store (e.g. a transient in-memory scratch store with no torn-write threat).
    ///
    /// Behind an `Arc<Mutex<…>>` (`rmp` #407) because the **same** persistent DWB now protects two
    /// home-write paths: the checkpoint/flush path here ([`flush_protected`](Self::flush_protected))
    /// **and** the buffer pool's *eviction/steal* path, via a [`crate::dwb::DwbPageStager`] installed
    /// into the pool at [`attach_dwb`](Self::attach_dwb). The `Mutex` makes the two share one DWB
    /// owner and serialises their staging (one DWB-device writer at a time); the `Arc` lets the
    /// pool's stager hold a second handle to the same DWB.
    dwb: Option<Arc<std::sync::Mutex<crate::dwb::Dwb<D>>>>,
    /// A monotonic **drain-progress beacon** (`rmp` #563): the store bumps it as its long-running
    /// engine-thread operations make forward progress — every doublewrite flush chunk written home
    /// ([`flush_protected_with_attached_dwb`](Self::flush_protected_with_attached_dwb)) and every step of
    /// the O(N) GC scan ([`gc`](Self::gc), [`freeze_store_headers`](Self::freeze_store_headers)). The
    /// server's `stop_engine` polls this same [`AtomicU64`] (a clone shared via the engine handle) while
    /// draining an engine, so it can tell a **healthy-but-slow** engine (this counter still advancing)
    /// from a genuinely **wedged** one (a hung syscall / livelock — the counter frozen) and force-detach
    /// only the latter. `None` for a store with no beacon installed (an in-memory DST/scratch store).
    drain_progress: Option<Arc<std::sync::atomic::AtomicU64>>,
    /// An opaque RAII guard held for the store's **entire lifetime** and dropped when the store closes
    /// — declared **last** so it drops *after* every other field (the device, the pool and the WAL),
    /// i.e. after the final flush has run and the file handles are closed. Its sole purpose is
    /// drop-ordering: the server installs the exclusive store-open advisory lock
    /// ([`graphus_io::StoreOpenLock`], an `flock` on `store.lock`) here so that lock is released only
    /// once this store — including a force-detached zombie's in-progress flush — is fully done writing
    /// (`rmp` #563: the force-detach → concurrent-reopen corruption). The storage layer never inspects
    /// the guard; it only guarantees it outlives all store I/O. `None` for a store with no such lock
    /// (an in-memory DST/scratch store, or any store opened without the server's file-lock wiring).
    /// `Send + Sync` so [`RecordStore`] stays `Send + Sync` (the `record_store_is_send_and_sync` gate);
    /// the installed [`graphus_io::StoreOpenLock`] (a `File` + `PathBuf`) satisfies both.
    open_guard: Option<Box<dyn Send + Sync>>,
}

/// Default automatic-checkpoint cadence: take a checkpoint every ~64 MiB of appended WAL. Chosen to
/// bound crash-recovery redo work while keeping the checkpoint's flush amortised under steady load;
/// tunable per store via [`RecordStore::set_checkpoint_interval_bytes`].
pub const DEFAULT_CHECKPOINT_INTERVAL_BYTES: u64 = 64 * 1024 * 1024;

/// **`rmp` #809 — release-active freeze-frontier audit window.** How many physical ids of *each* MVCC
/// store the always-on prune-soundness audit re-verifies per GC pass (see
/// [`RecordStore::audit_freeze_frontier_window`]). It bounds the audit's per-pass cost to a fixed
/// `3 * O(FREEZE_AUDIT_WINDOW_IDS)` (constant, independent of store size), while the per-kind rotating
/// cursor re-covers the whole id space every `⌈high_water / FREEZE_AUDIT_WINDOW_IDS⌉` passes. `8192`
/// was chosen empirically (`freeze_audit_window_cost_is_negligible_809`): at this size the three windows
/// add on the order of tens of microseconds to a GC pass — negligible next to the pass's own freeze /
/// reclaim / checkpoint work — while a store of a few hundred thousand records is fully re-audited within
/// a few dozen maintenance ticks (and a *systematic* freeze regression, which strands stamps densely, is
/// caught in far fewer). One page holds 125 node / 80 rel / ~146 prop records, so a window spans ~55–100
/// store pages — a handful of page fetches per kind.
const FREEZE_AUDIT_WINDOW_IDS: u64 = 8192;

impl<D: BlockDevice, S: LogSink> RecordStore<D, S> {
    /// Creates a brand-new record store on an empty `device`, with `wal` an already-created WAL,
    /// `pool_capacity` buffer frames, and `element_id_seed` the first `ElementId` to allocate
    /// (seedable for reproducible tests, `04 §2.2`). Initialises and hardens the catalog.
    ///
    /// # Errors
    /// Returns a storage error if the device is unwritable or the catalog cannot be persisted.
    ///
    /// # Panics
    /// Panics if the WAL's durability `fdatasync` fails (`04 §4.9`).
    pub fn create(
        device: D,
        wal: WalManager<S>,
        pool_capacity: usize,
        element_id_seed: u128,
    ) -> Result<Self> {
        if device.page_count() != 0 {
            return Err(GraphusError::Storage(
                "RecordStore::create requires an empty device".to_owned(),
            ));
        }
        let shared = SharedWal::new(wal);
        let pool = ConcurrentBufferPool::with_wal(device, shared.clone(), pool_capacity).shared();
        let mut store = Self {
            pool,
            wal: shared,
            element_ids: ElementIdAllocator::new(element_id_seed.max(1)),
            tokens: TokenStore::new(),
            stores: ALL_STORE_KINDS.map(FixedStore::empty),
            commit_ts_hw: 0,
            // A fresh store has made no durable write, so both the queue and the bookmark high-water start
            // empty/zero (`rmp` #813): a read before the first write mints `"<db>:0"`.
            pending_write_commits: VecDeque::new(),
            durable_write_commit_ts_hw: 0,
            active: HashMap::new(),
            catalog_dirty: false,
            schema_seq: 0,
            schema_last_seq: HashMap::default(),
            meta_chain: Vec::new(),
            commit_registry: CommitRegistry::new(),
            pending_gc_prune: None,
            // `rmp` #522 incremental-GC state (pure in-memory; rebuilt from scratch every open). The
            // freeze frontier starts at `1` so the first pass fully settles every pre-existing on-disk
            // stamp; `gc_full_scan_pending` forces that first pass to also do the full corpse/property
            // sweep for anything a fresh process has no in-memory record of.
            freeze_low: [1; STORE_COUNT],
            // `rmp` #809: the release-active freeze-frontier audit starts each store's rotating window
            // at id 1 (pure in-memory; rebuilt every open, so the on-disk format is unchanged).
            freeze_audit_from: [1; STORE_COUNT],
            pending_tombstones: Default::default(),
            pending_corpse_rels: std::collections::BTreeSet::new(),
            pending_prop_corpses: false,
            pending_empty_prop_cells: false,
            gc_full_scan_pending: true,
            gc_freeze_low_savepoint: None,
            // `rmp` #588: reader-safe slot-reuse overlay (in-memory; empty unless off-thread readers hold a slot).
            held_slots: std::array::from_fn(|_| HashMap::new()),
            reuse_barrier: None,
            opened_format_version: graphus_core::constants::FORMAT_VERSION,
            // `rmp` #966 undo-area state: all in-memory, all rebuilt from scratch every open. The
            // chain sweep's pending set is reseeded by the first pass's full scan
            // (`gc_full_scan_pending`), so a crash-recovered store reclaims its chains normally.
            undo_slab: None,
            pending_undo_chains: std::collections::BTreeSet::new(),
            undo_orphan_slots_possible: false,
            statistics: Statistics::new(),
            checkpoint_interval_bytes: DEFAULT_CHECKPOINT_INTERVAL_BYTES,
            wal_segment_sizing_adaptive: true,
            wal_len_at_last_checkpoint: 0,
            unfrozen_commit_lsn: BTreeMap::new(),
            // A fresh store has no prior transactions in its (just-created) WAL.
            recovered_txn_hw: 0,
            // No doublewrite buffer until one is attached ([`attach_dwb`]); the fresh-create flush
            // below therefore runs unprotected, which is correct — there is no committed data yet.
            dwb: None,
            // No drain-progress beacon until the engine installs one ([`set_drain_progress`], #563).
            drain_progress: None,
            // No exclusive store-open lock until the server installs one ([`hold_open_guard`], #563).
            open_guard: None,
        };
        store.init_meta_page()?;
        store.checkpoint_meta(SYSTEM_TXN, true)?;
        store.flush()?;
        store.wal_len_at_last_checkpoint = store.wal.with(|w| w.durable_len());
        // Size the WAL segment seal threshold to the (tiny) fresh store, so segments start small and
        // the very first maintenance checkpoint can free WAL disk (`rmp` #706).
        store.apply_adaptive_wal_segment_target();
        Ok(store)
    }

    /// Reopens an existing record store (after [`crate::recovery::recover_device`] has replayed the WAL
    /// onto the device), rebuilding the in-memory catalog from the durable metadata page.
    ///
    /// # Errors
    /// Returns a storage error if the metadata page is missing or malformed.
    pub fn open(device: D, wal: WalManager<S>, pool_capacity: usize) -> Result<Self> {
        let shared = SharedWal::new(wal);
        let pool = ConcurrentBufferPool::with_wal(device, shared.clone(), pool_capacity).shared();
        let (meta, meta_chain) = Self::read_meta(&pool)?;
        // Rebuild the Active/Recent Transaction Table from the WAL's commit records (`rmp` task #49):
        // with lazy GC-time freezing a committed version may still carry its writer's in-flight
        // `TxnId` on disk, so visibility/reclamation must resolve that id to the commit timestamp the
        // commit record durably holds. The scan is robust to checkpoint truncation (the timestamp
        // lives in each commit record, not derived from log position). Writers a pre-crash GC pass
        // had already frozen and pruned (`rmp` task #59) reappear here; that is harmless — no header
        // references them, so the entries are never consulted and the next GC pass prunes them again.
        let mut commit_registry = CommitRegistry::new();
        let mut unfrozen_commit_lsn = BTreeMap::new();
        for (committed_txn, ts, lsn) in shared.with(|w| w.committed_transactions())? {
            commit_registry.record_commit(committed_txn, ts);
            // Conservatively treat every surviving committed txn as possibly-unfrozen (a pre-crash GC
            // may have frozen some, harmlessly re-included; the next GC pass re-prunes them). This
            // floors WAL reclamation so no commit record an unfrozen version needs is dropped.
            unfrozen_commit_lsn.insert(committed_txn, lsn);
        }
        // `Meta::decode` has already decided the format-version question (`05 §12.6`): a version-1
        // image arrives here with two EMPTY undo-area stores — which is exactly the state of a store
        // that has no version chains, so the upgrade is a no-op rather than a conversion — and an
        // image newer than this build understands never arrives at all, because `decode` refuses it.
        // What `decode` CANNOT decide is whether an older image's properties still mean what this
        // build reads; that is `refuse_legacy_property_tombstones` below (`rmp` #967).
        let store_format_version = meta.format_version;
        let mut stores = [
            FixedStore::from_meta(StoreKind::Node, &meta.stores[0])?,
            FixedStore::from_meta(StoreKind::Rel, &meta.stores[1])?,
            FixedStore::from_meta(StoreKind::Prop, &meta.stores[2])?,
            FixedStore::from_meta(StoreKind::Strings, &meta.stores[3])?,
            FixedStore::from_meta(StoreKind::Undo, &meta.stores[4])?,
            FixedStore::from_meta(StoreKind::Commit, &meta.stores[5])?,
        ];
        // Re-attribute every record page the device holds back to its owning store (`rmp` #239). The
        // durable catalog persists a store's `device_pages`/`high_water` only at a *commit*; a page
        // allocated solely by aborted transactions exists on disk (ARIES redo re-materialised it) but is
        // mapped by no store. A committed node's `first_rel` can legitimately still reference such a page
        // (an aborted shared-node edge leaves a not-in-use dead-link corpse the forward walk threads
        // through, repaired lazily at GC — `rmp` #220). This reconstruction makes those orphan pages
        // addressable again so the walk reads the corpse and threads through it to NULL, instead of
        // failing with "store page not allocated" (the seed-10 double-crash ReadBack failure).
        Self::reconstruct_orphan_store_pages(&pool, &mut stores)?;
        // Cover dead-link corpses (`rmp` #220) that ARIES redo materialised on an **already-mapped**
        // (committed-catalog) page *above* the durable high-water — the residue self-loop churn on a
        // single node leaves when a loser's record shares a densely-packed record page with a
        // committed record, so `reconstruct_orphan_store_pages` (orphan-pages only) cannot reach it
        // (`rmp` #468). Without this the incidence-walk cycle guard (`2 * high_water + 2`) is too
        // small to thread the corpse run to the committed head, so committed relationships below the
        // run become unreadable, and the allocator would re-hand-out a still-referenced corpse slot.
        Self::floor_high_water_over_mapped_corpses(&pool, &mut stores);
        // `rmp` #967: a version-1 image may carry property MVCC tombstones this build cannot read.
        // Runs after the two page-map reconstructions above so the scan sees every mapped record page,
        // and before anything else touches a property cell.
        Self::refuse_legacy_property_tombstones(&pool, &stores, store_format_version)?;
        let shared_len = shared.with(|w| w.durable_len());
        // Restore the transaction-id high-water from the durable WAL so the coordinator's id counter
        // resumes *past* every id already in the log. Without this the counter would restart low and
        // reuse ids, which breaks ARIES loser/winner classification on a later crash and can resurrect
        // uncommitted records (the atomicity violation this fixes). See
        // [`WalManager::max_recovered_txn_id`].
        let recovered_txn_hw = shared.with(|w| w.max_recovered_txn_id())?;
        let mut store = Self {
            pool,
            wal: shared,
            element_ids: ElementIdAllocator::new(meta.element_id_next.max(1)),
            tokens: meta.tokens,
            stores,
            commit_ts_hw: meta.commit_ts_hw,
            // Nothing is un-hardened at open (recovery truncated the un-synced WAL tail). Seed the
            // durable-write bookmark high-water from the recovered `commit_ts_hw` (`rmp` #813): after a
            // crash only durable commit records survive, so this reflects the last durable write and can
            // never step backwards across a restart. (In the rare case a checkpoint had persisted a
            // read-only phantom tick into `meta.commit_ts_hw`, this is at most a harmless slight
            // over-estimate — still durable, still monotonic.)
            pending_write_commits: VecDeque::new(),
            durable_write_commit_ts_hw: meta.commit_ts_hw,
            active: HashMap::new(),
            catalog_dirty: false,
            schema_seq: 0,
            schema_last_seq: HashMap::default(),
            meta_chain,
            commit_registry,
            pending_gc_prune: None,
            // `rmp` #522 incremental-GC state (pure in-memory; rebuilt from scratch every open). The
            // freeze frontier starts at `1` so the first pass fully settles every pre-existing on-disk
            // stamp; `gc_full_scan_pending` forces that first pass to also do the full corpse/property
            // sweep for anything a fresh process has no in-memory record of.
            freeze_low: [1; STORE_COUNT],
            // `rmp` #809: the release-active freeze-frontier audit starts each store's rotating window
            // at id 1 (pure in-memory; rebuilt every open, so the on-disk format is unchanged).
            freeze_audit_from: [1; STORE_COUNT],
            pending_tombstones: Default::default(),
            pending_corpse_rels: std::collections::BTreeSet::new(),
            pending_prop_corpses: false,
            pending_empty_prop_cells: false,
            gc_full_scan_pending: true,
            gc_freeze_low_savepoint: None,
            // `rmp` #588: reader-safe slot-reuse overlay (in-memory; empty unless off-thread readers hold a slot).
            held_slots: std::array::from_fn(|_| HashMap::new()),
            reuse_barrier: None,
            opened_format_version: store_format_version,
            // `rmp` #966 undo-area state: all in-memory, all rebuilt from scratch every open. The
            // chain sweep's pending set is reseeded by the first pass's full scan
            // (`gc_full_scan_pending`), so a crash-recovered store reclaims its chains normally.
            undo_slab: None,
            pending_undo_chains: std::collections::BTreeSet::new(),
            undo_orphan_slots_possible: false,
            statistics: meta.statistics,
            checkpoint_interval_bytes: DEFAULT_CHECKPOINT_INTERVAL_BYTES,
            wal_segment_sizing_adaptive: true,
            wal_len_at_last_checkpoint: shared_len,
            unfrozen_commit_lsn,
            recovered_txn_hw,
            // No doublewrite buffer until the caller attaches one ([`attach_dwb`]). The DWB-aware
            // torn-page repair runs in [`crate::recovery::recover_device_with_dwb`] *before* this
            // `open`, so the store opens onto an already-repaired device; the attached DWB then
            // protects subsequent checkpoint/flush home writes.
            dwb: None,
            // No drain-progress beacon until the engine installs one ([`set_drain_progress`], #563).
            drain_progress: None,
            // No exclusive store-open lock until the server installs one ([`hold_open_guard`], #563).
            open_guard: None,
        };
        // Size the WAL segment seal threshold to the RECOVERED store, so a reopened database immediately
        // uses a segment size matched to its data image rather than the sink's default 64 MiB (`rmp` #706).
        store.apply_adaptive_wal_segment_target();
        Ok(store)
    }

    /// The largest real transaction id present in the durable WAL when this store was opened (`0` for a
    /// freshly created store). The transaction coordinator seeds its monotonic id counter from this so
    /// reopened engines never reuse a transaction id across recovery (which would break ARIES
    /// loser/winner classification — see [`WalManager::max_recovered_txn_id`]).
    #[must_use]
    pub fn recovered_txn_hw(&self) -> u64 {
        self.recovered_txn_hw
    }

    /// Runs `f` with the shared WAL manager (test/inspection helper).
    pub fn with_wal<R>(&self, f: impl FnOnce(&mut WalManager<S>) -> R) -> R {
        self.wal.with(f)
    }

    // ------------------------------- catalog -------------------------------

    fn store(&self, kind: StoreKind) -> &FixedStore {
        &self.stores[kind as usize]
    }

    fn store_mut(&mut self, kind: StoreKind) -> &mut FixedStore {
        &mut self.stores[kind as usize]
    }

    fn snapshot_meta(&self, committing: TxnId) -> Meta {
        Meta {
            // Every catalog this build writes is a format-version-3 image, so a store opened at an
            // earlier version is UPGRADED by its first checkpoint (`05 §12.6`). From version 1 the
            // upgrade adds the two (empty) undo-area stores and loses nothing — a version-1 store has
            // no chains, which is precisely what an empty undo area describes. From version 2 it
            // changes nothing but the number: version 2 and version 3 differ only in what a property
            // cell MEANS, and `refuse_legacy_property_tombstones` has already established at `open`
            // that this image holds no cell whose meaning would change (`rmp` #967).
            format_version: graphus_core::constants::FORMAT_VERSION,
            element_id_next: self.element_ids.peek(),
            commit_ts_hw: self.commit_ts_hw,
            stores: std::array::from_fn(|i| self.stores[i].to_meta()),
            tokens: self.tokens.clone(),
            // Clones the whole `Statistics` (counts *and* the `rmp` task #81 property-histogram map):
            // the histogram blobs ride the same checkpoint-at-commit path as the counts with no
            // special-casing — `Statistics` is cloned structurally. The SCHEMA half is taken from the
            // COMMITTED image, not the live one (`rmp` #734): the live `Statistics` also carries any
            // still-open transaction's uncommitted DDL, and checkpointing that would publish an
            // in-flight schema change as committed. See `committed_statistics`.
            statistics: self.committed_statistics(committing),
        }
    }

    /// Allocates and initialises the metadata page (device page `0`) on a fresh device. Uses the
    /// pool's `new_page` so the page is written with a valid checksum; only used at `create`
    /// before the first catalog checkpoint.
    ///
    /// # Errors
    /// Returns a storage error if the freshly allocated page is not the reserved [`META_PAGE`].
    fn init_meta_page(&mut self) -> Result<()> {
        let (f, page_id) = self.pool.new_page()?;
        if page_id != META_PAGE {
            self.pool.unpin(f);
            return Err(GraphusError::Storage(format!(
                "metadata page must be device page 0, got {}",
                page_id.0
            )));
        }
        self.pool.with_page_mut(f, |p| {
            page::set_page_type(p, PAGE_TYPE_META);
            page::set_page_id(p, META_PAGE.0);
        });
        // Seed a valid checksum on disk before any fetch verifies it. This page carries no logged
        // change yet (its catalog bytes are written by the WAL-logged checkpoint that follows), so it
        // is flushed via `flush_unlogged` (page_lsn 0, a no-op `ensure_durable(0)`) — `rmp` #337.
        self.pool.flush_unlogged(f)?;
        self.pool.unpin(f);
        Ok(())
    }

    /// Reads and decodes the durable metadata catalog by walking the metadata-page chain from
    /// [`META_PAGE`], concatenating each page's chunk until the terminating link (`next == 0`).
    /// Returns the decoded catalog and the continuation-page ids (the chain after the head), which
    /// the caller records as [`meta_chain`](Self#structfield.meta_chain).
    ///
    /// # Errors
    /// Returns a storage error if a page is unreadable/fails checksum, a chunk runs past its page,
    /// the chain is cyclic, or the concatenated payload is malformed.
    fn read_meta(pool: &ConcurrentBufferPool<D, SharedWal<S>>) -> Result<(Meta, Vec<PageId>)> {
        let mut payload = Vec::new();
        let mut chain = Vec::new();
        let mut page = META_PAGE;
        loop {
            let f = pool.fetch(page)?;
            // Decode the chunk header and copy out this page's catalog chunk under the read latch;
            // the chunk bytes escape the borrow (they are appended to `payload`), so they are copied
            // out inside the closure (`rmp` #337, Slice 1 closure-API conversion).
            let chunk_and_next: Result<(Vec<u8>, u64)> = pool.with_page(f, |p| {
                // Mask off the format-version flag (`META_FORMAT_V2_FLAG`) an undo-area build sets on
                // the head page: it is a tripwire for OLDER builds, not a length.
                let chunk_len = (u32::from_le_bytes(
                    p[HEADER_SIZE..HEADER_SIZE + 4]
                        .try_into()
                        .expect("4-byte slice"),
                ) & !META_FORMAT_V2_FLAG) as usize;
                let next = u64::from_le_bytes(
                    p[HEADER_SIZE + 4..HEADER_SIZE + 12]
                        .try_into()
                        .expect("8-byte slice"),
                );
                let start = HEADER_SIZE + 12;
                if start + chunk_len > p.len() {
                    return Err(GraphusError::Storage(
                        "metadata chunk runs past the page".to_owned(),
                    ));
                }
                Ok((p[start..start + chunk_len].to_vec(), next))
            });
            pool.unpin(f);
            let (chunk, next) = chunk_and_next?;
            payload.extend_from_slice(&chunk);
            if next == 0 {
                break;
            }
            let next = PageId(next);
            // Guard a corrupt/cyclic chain: a link must reach a fresh page and never the head, so a
            // damaged metadata region fails the open rather than looping forever. Continuation pages
            // are only ever appended, so this membership scan stays short (one entry per ~8 KiB of
            // catalog) and runs only on open/recovery.
            if next == META_PAGE || chain.contains(&next) {
                return Err(GraphusError::Storage(
                    "metadata chain is cyclic or points at the head page".to_owned(),
                ));
            }
            chain.push(next);
            page = next;
        }
        Ok((Meta::decode(&payload)?, chain))
    }

    /// Re-attributes every record page on the device back to its owning fixed-record store after crash
    /// recovery, rebuilding `device_pages` (and flooring `high_water`) for **orphan** pages the durable
    /// catalog does not map (`rmp` #239).
    ///
    /// ## Why orphan pages exist
    ///
    /// A store's `device_pages`/`high_water` are persisted only in the durable catalog, which is
    /// checkpointed at a transaction's **commit** ([`checkpoint_meta`](Self::checkpoint_meta)). A device
    /// page allocated by [`ensure_store_page`](Self::ensure_store_page) for a transaction that ultimately
    /// **aborts** (or is a crash loser) is nonetheless materialised on disk — its allocation flush
    /// hardened the page header, and ARIES redo re-applies the record writes — yet no commit ever folded
    /// it into the catalog. On reopen, [`FixedStore::from_meta`] therefore omits it.
    ///
    /// This is normally invisible (the aborted records are unreachable), but `rmp` #220 makes it
    /// reachable: an aborted shared-node edge creation leaves a not-in-use **dead-link corpse**, and the
    /// node head's compare-and-set undo can legitimately leave a *committed* node's `first_rel` pointing
    /// at that corpse (the head is repaired lazily at GC, not at abort). Reading the corpse to thread the
    /// incidence walk through it to NULL needs its page mapped — otherwise the walk fails with "store page
    /// not allocated" (the seed-10 double-crash `ReadBack` failure).
    ///
    /// ## How attribution is sound
    ///
    /// Each record page is stamped at allocation with its store kind in the page **subtype** byte
    /// ([`page::set_page_subtype`]). Device pages are allocated globally-monotonically and, within one
    /// store, in ascending store-relative order, so a store's device pages are strictly increasing in
    /// device id and the committed catalog holds the lowest (earliest) prefix. Scanning device pages in
    /// ascending id and appending each store's *unmapped* record pages therefore preserves store-relative
    /// order. `high_water` is floored to cover the full capacity of the now-mapped pages so the corpse id
    /// is in range for the in-use-filtered scans and is never re-handed-out by the allocator.
    ///
    /// # Errors
    /// Returns a storage error if a device page cannot be read.
    /// Cross-validates one orphan record page's bytes against the [`StoreKind`] its subtype byte
    /// claims, to catch an in-range-but-**wrong** subtype that CRC32C cannot (`rmp` #398). Returns
    /// `true` only if every in-use record slot — laid out densely at `kind`'s stride — carries a
    /// well-formed MVCC header (`05 §7`):
    ///
    /// * an in-use record has a non-zero creator stamp (`xmin` is never the `0` none-sentinel), and
    /// * if both `xmin` and `xmax` are *committed* timestamps, `xmin <= xmax` (no version that
    ///   expired before it was created).
    ///
    /// These are the same MVCC-header invariants the offline checker enforces
    /// ([`crate::check::MvccHeaderFault`]); applied at the *claimed* stride they reject a
    /// mis-attributed page, because a page written at a different record size lands its dense MVCC
    /// headers mid-record at this stride, where they are overwhelmingly malformed (an `in_use` flag
    /// over a zero creator, or a wildly inverted timestamp pair). The scan is **page-local and
    /// bounded** (at most `records_per_page` header reads, no chain following), so it does not change
    /// `open`'s O(device-pages) cost.
    ///
    /// An entirely-empty page (no in-use slot) is accepted: it is structurally indistinguishable
    /// across kinds and harmless to attribute (it floors no high-water beyond its capacity and
    /// references nothing).
    fn orphan_page_records_well_formed(page: &[u8], kind: StoreKind) -> bool {
        let record_size = kind.record_size();
        let rpp = paging::records_per_page(record_size);
        // The undo area's records carry NO MVCC header (`05 §12`), so the header-shaped validation
        // below would read their `action` / `commit_info` / `next` bytes as version stamps and reject a
        // perfectly good page — bricking `open` on nothing worse than an aborted transaction having
        // grown `undo.store` (`rmp` #966). Their own strict codecs are the right — and sharper —
        // cross-validation: they reject an unknown action byte, a non-zero reserved field, and a
        // payload field set on an action that does not own it, none of which survive being read at the
        // wrong stride.
        if !kind.is_versioned() {
            for slot in 0..rpp {
                let off = HEADER_SIZE + slot * record_size;
                if off + record_size > page.len() {
                    break;
                }
                let bytes = &page[off..off + record_size];
                if undo::is_zeroed(bytes) {
                    continue; // never-written slot: carries no invariant
                }
                let decodes = match kind {
                    StoreKind::Undo => UndoDelta::decode(bytes).is_ok(),
                    _ => CommitSlot::decode(bytes).is_ok(),
                };
                if !decodes {
                    return false;
                }
            }
            return true;
        }
        for slot in 0..rpp {
            let off = HEADER_SIZE + slot * record_size;
            // Defensive bound (the arithmetic above never overruns for a valid `rpp`, but a future
            // record-size change must not turn this into an out-of-bounds slice).
            if off + MVCC_HEADER_SIZE > page.len() {
                break;
            }
            let mvcc = MvccHeader::read(&page[off..off + MVCC_HEADER_SIZE]);
            if !mvcc.in_use() {
                continue; // free/never-written slots carry no invariant
            }
            // An in-use record must name its creator.
            if VersionStamp::from_raw(mvcc.created_ts) == VersionStamp::None {
                return false;
            }
            // No committed/committed timestamp inversion.
            if let (VersionStamp::Committed(c), VersionStamp::Committed(e)) = (
                VersionStamp::from_raw(mvcc.created_ts),
                VersionStamp::from_raw(mvcc.expired_ts),
            ) {
                if c.0 > e.0 {
                    return false;
                }
            }
        }
        true
    }

    fn reconstruct_orphan_store_pages(
        pool: &ConcurrentBufferPool<D, SharedWal<S>>,
        stores: &mut [FixedStore; STORE_COUNT],
    ) -> Result<()> {
        // Pages already mapped by some store's committed catalog must not be re-appended.
        let mut mapped: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for s in stores.iter() {
            for p in s.device_pages.iter() {
                mapped.insert(p.0);
            }
        }
        let page_count = pool.page_count();
        // Collect orphan record pages per store kind, in ascending device order (preserves store-relative
        // order, see the doc comment).
        let mut orphans: [Vec<PageId>; STORE_COUNT] = std::array::from_fn(|_| Vec::new());
        for dev in 0..page_count {
            let pid = PageId(dev);
            if mapped.contains(&dev) {
                continue;
            }
            // Read the RAW device bytes without the pool's checksum gate (`rmp` #597). `pool.fetch`
            // verifies the checksum and would hard-fail here on a page it cannot classify — which
            // bricks `open` after nothing worse than a transient device write error during allocation:
            // when a freshly page-boundary-extended record page's seed `flush_unlogged` home write
            // fails, `new_page`'s device `extend` has already left an **all-zero, checksum-invalid**
            // page on the device that no store maps and no WAL record covers (the aborting txn's page,
            // written on the unlogged path, so ARIES redo cannot recreate it and it has no doublewrite
            // copy). Reading raw lets us classify it below instead of rejecting it.
            let raw = pool.read_page_unverified(pid)?;
            let page: &graphus_io::Page = &raw;
            if !page::verify_checksum(page) {
                // A checksum-invalid page is EITHER an aborted-allocation phantom (all-zero) OR
                // untrusted corruption (non-zero). By the time this scan runs, ARIES redo has already
                // re-materialised every COMMITTED (logged) page — so any all-zero page here holds no
                // committed data and is unambiguously never-written (`new_page` zero-fills the extend;
                // a failed seed flush left the real bytes only in a now-lost dirty frame, `rmp` #597).
                // Skip it — it is not a record-store page and mapping/serving it would be unsound. A
                // NON-zero bad checksum is genuine corruption: fail closed (Graphus's first mandate —
                // never serve a page it cannot trust, `04 §4.6`/§4.8 startup).
                if page.iter().all(|&b| b == 0) {
                    continue;
                }
                return Err(GraphusError::Storage(format!(
                    "page {} failed checksum verification during orphan-page reconstruction \
                     (non-zero bytes — untrusted corruption); refusing to serve",
                    pid.0
                )));
            }
            let is_record = page::page_type(page) == PAGE_TYPE_RECORD;
            let subtype = page::page_subtype(page);
            if !is_record {
                continue; // META pages and (valid, non-record) pages are not record-store pages
            }
            // The subtype indexes a `StoreKind`; ignore an out-of-range value defensively (a torn or
            // pre-`#239` page) rather than trusting it.
            if (subtype as usize) >= STORE_COUNT {
                continue;
            }
            let kind = ALL_STORE_KINDS[subtype as usize];
            // `rmp` #398: the subtype byte is the *only* thing attributing this orphan page to a
            // store, and it passed CRC32C — so a byte-flip (or a page written by store Y mislabelled
            // as X) that lands an **in-range but wrong** subtype would silently attach the page to
            // the wrong store and floor that store's high-water to a mismatched capacity, reading
            // every record at the wrong stride forever after. CRC alone cannot catch this (the bytes
            // are self-consistent), so cross-validate the page's own records against the claimed
            // kind's shape: at the wrong stride the dense MVCC headers land mid-record and are
            // overwhelmingly malformed. A bounded, page-local scan (no chain following) keeps `open`
            // O(device pages) as it already is. On mismatch we fail closed — Graphus's first mandate
            // is to never serve a page it cannot trust (`04 §4.6`/§4.8 startup).
            let well_formed = Self::orphan_page_records_well_formed(page, kind);
            if !well_formed {
                return Err(GraphusError::Storage(format!(
                    "orphan record page {} carries subtype {} ({:?}) but its records are not \
                     well-formed for that store (mis-attributed page — possible corruption); \
                     refusing to serve",
                    pid.0, subtype, kind
                )));
            }
            orphans[subtype as usize].push(pid);
        }
        for (i, store_orphans) in orphans.into_iter().enumerate() {
            if store_orphans.is_empty() {
                continue;
            }
            let kind = stores[i].kind;
            // `open` is single-threaded and no reader holds a handle yet, so appending here needs no
            // extra ordering — `push` publishes each entry regardless (`rmp` #721).
            for p in &store_orphans {
                stores[i].device_pages.push(*p)?;
            }
            // Floor the high-water so every record slot on the now-mapped pages is addressable and the
            // allocator never re-hands-out a corpse slot. `observe(n - 1)` lifts the high-water to `n`
            // without inventing a fresh id (`observe` records the largest id seen).
            let rpp = paging::records_per_page(kind.record_size()) as u64;
            let capacity = stores[i].device_pages.len() as u64 * rpp;
            if capacity > stores[i].alloc.high_water() {
                stores[i].alloc.observe(capacity.saturating_sub(1));
            }
        }
        Ok(())
    }

    /// Floors each store's high-water past any **dead-link corpse** (`rmp` #220) materialised on an
    /// **already-mapped** (committed-catalog) page *above* the durable high-water — the residue a
    /// crash recovery leaves when a loser transaction's record was allocated on the *same* record
    /// page as an earlier committed record (`rmp` #468).
    ///
    /// ## The gap [`reconstruct_orphan_store_pages`] leaves
    ///
    /// A store's durable `high_water` is persisted only at a **commit**. ARIES redo re-materialises a
    /// loser's record writes on the device, but the loser's high-water bump was never folded into the
    /// catalog, so on reopen `high_water` can sit **below** corpse slots that physically exist. When
    /// such corpses land on a *new* page, [`reconstruct_orphan_store_pages`] maps the orphan page and
    /// floors high-water to its full capacity. But when a loser's record was allocated on the **same**
    /// densely-packed page as an earlier committed record — e.g. self-loop churn on a single node,
    /// where the committed self-loops and the loser self-loops share one rel page
    /// (`records_per_page(102) == 80`) — that page IS in the committed catalog, so orphan
    /// reconstruction skips it (`mapped.contains` → continue) and the corpse slots above `high_water`
    /// are left uncovered. Two consequences, both ACID-critical:
    ///
    ///   1. The incidence-walk cycle guard is `2 * high_water + 2`; an uncovered corpse run makes the
    ///      committed head unreachable within the guard, so [`incident_rels`](Self::incident_rels) of
    ///      a node whose `first_rel` the CAS chain-head undo legitimately left pointing at a corpse
    ///      (`rmp` #220) errors "malformed (cycle?)" — the committed relationships threaded below the
    ///      corpse run become unreadable (**committed-data loss** after a crash).
    ///   2. The allocator would **re-hand-out** a corpse slot on the next `create_rel`, overwriting a
    ///      record the node's incidence chain still threads through (**silent chain corruption**).
    ///
    /// ## Why a bounded forward scan suffices
    ///
    /// Corpse ids form a **dense, contiguous run** starting at the durable `high_water` (the allocator
    /// hands ids out densely and monotonically, and abort/recovery never frees a corpse slot back to
    /// the free list — it stays allocated until GC). So a forward scan from `high_water`, stopping at
    /// the first all-zero (never-written) slot, covers the whole run: a never-written slot is all-zero
    /// (pages are zeroed when extended), whereas a corpse keeps its non-zero record body — only its
    /// 25-byte MVCC header was reverted by the header-only creation undo (`rmp` #220). The common
    /// no-corpse reopen costs a single slot read (the slot at `high_water` is empty). The scan never
    /// crosses onto an **unmapped** page: a corpse run that spills onto a new page is already covered
    /// by [`reconstruct_orphan_store_pages`], whose full-capacity floor lifts `high_water` past it, so
    /// this scan starts beyond it. Flooring is via [`PhysicalAllocator::observe`], exactly as the
    /// orphan path floors whole orphan pages, keeping `high_water <= capacity` (the `rmp` #452 bound).
    ///
    /// ## Robust to corruption (never fails `open`)
    ///
    /// An unreadable boundary page (e.g. on-disk corruption that breaks its checksum) stops the scan
    /// for that store rather than failing [`open`](Self::open): `open` must stay robust and defer
    /// corruption detection to [`crate::verify_on_open`], which re-reads the durable image and refuses
    /// to serve a corrupt store. An un-floored high-water is moot for a store that will not be served;
    /// a corrupt page also fails its checksum on fetch, so it is never cached here, preserving the
    /// checker's cold-pool detection (`rmp` #426). For a healthy store the fetch always succeeds.
    fn floor_high_water_over_mapped_corpses(
        pool: &ConcurrentBufferPool<D, SharedWal<S>>,
        stores: &mut [FixedStore; STORE_COUNT],
    ) {
        for store in stores.iter_mut() {
            let record_size = store.kind.record_size();
            let start = store.alloc.high_water();
            let mut last_materialised = NULL_ID;
            let mut id = start;
            loop {
                let (rel_page, off) = paging::record_location(id, record_size);
                // Stop at the first slot whose page is not mapped to this store: the dense corpse run
                // cannot cross onto an unmapped page (a spill onto a new page is already floored by
                // `reconstruct_orphan_store_pages`).
                let Some(pid) = usize::try_from(rel_page)
                    .ok()
                    .and_then(|p| store.device_pages.get(p))
                else {
                    break;
                };
                // An unreadable page (corruption) is left to `verify_on_open`; do not fail `open`.
                let Ok(f) = pool.fetch(pid) else {
                    break;
                };
                let materialised =
                    pool.with_page(f, |p| p[off..off + record_size].iter().any(|&b| b != 0));
                pool.unpin(f);
                // A never-written slot is all-zero; the dense corpse run ends at the first such slot.
                if !materialised {
                    break;
                }
                last_materialised = id;
                let Some(next) = id.checked_add(1) else {
                    break;
                };
                id = next;
            }
            if last_materialised >= start {
                store.alloc.observe(last_materialised);
            }
        }
    }

    /// **Refuses to open** a legacy store whose property chains still carry MVCC tombstones — the one
    /// pre-`rmp`-#967 image this build would silently *misread* (`rmp` #967 audit, `05 §12.6`).
    ///
    /// # What the hazard is
    ///
    /// Before `D-property-removal`, a committed `REMOVE n.p` was one `props.store` cell left `in_use`
    /// with its `expired_ts` stamped and **its value intact**; an overwrite was the same stamp plus a
    /// new cell prepended above it. Visibility came from the cell's MVCC header. After #967 it does
    /// not: the undo chain is the sole oracle, so
    /// [`DecisionFold::seed`](crate::scan_polarity::DecisionFold) filters on `type_tag` alone and
    /// [`read_view::collect_prop_chain`](crate::read_view) admits every `in_use` cell. Point this
    /// build at such a store and every committed removal comes back holding its last value, the next
    /// `SET` on those keys fails for ever ([`write_prop_cell`](Self::write_prop_cell) refuses a
    /// non-zero `expired_ts`), and the superseded versions never reclaim (the sweep now keys on an
    /// EMPTY cell, which a stamped one is not). Nothing else stops it: `Meta::decode` accepts a
    /// version-1 image as an explicit lossless upgrade, and no property-chain migration exists.
    ///
    /// So the store is refused, exactly as `05 §12.6` already requires in the opposite direction ("a
    /// store of a newer version under an older build must be refused rather than misread"). A wrong
    /// answer that looks like data is worse than a failed startup.
    ///
    /// # Which versions this covers, and why it is both of them
    ///
    /// Every version **below** [`PROPERTY_UNDO_CHAIN_FORMAT_VERSION`] — 1 and 2 alike — was written
    /// under the old property model, so both carry the hazard:
    ///
    /// * **version 1** is what every *released* build writes (v0.0.10 and earlier);
    /// * **version 2** is what an *unreleased* build between `rmp` #966 and #967 writes — #966 bumped
    ///   the version for the undo area while the property path was still tombstone-and-prepend.
    ///
    /// Version 3 (`rmp` #967) is the first version whose property cells mean what this build reads,
    /// and it differs from version 2 **only in that number** — no field moved. That is precisely why
    /// the number had to be bumped: without it the two images are indistinguishable, and the gate
    /// below would have nothing to key on.
    ///
    /// # Why the tombstone scan, rather than refusing every pre-version-3 store
    ///
    /// Refusing unconditionally is one comparison and no I/O, but it also refuses every legacy store
    /// that carries **no** property tombstone — which `Meta::decode` deliberately treats as a lossless
    /// upgrade, and which is the normal state of any store whose GC has caught up with its removals,
    /// or that never removed or overwrote a property at all. Those stores upgrade correctly and there
    /// is no reason to strand them.
    ///
    /// The scan is paid **only** by a pre-version-3 image: every catalog this build writes is version
    /// 3 ([`snapshot_meta`](Self::snapshot_meta)), so the first checkpoint after a successful upgrade
    /// retires the cost permanently, and a store this build created never pays it once. It is also a
    /// pass this store already performs: the first GC pass after every `open` scans `props.store` from
    /// id 1 (`freeze_low` starts at `1`, `gc_full_scan_pending` is `true`), so the marginal cost of
    /// the gate is one extra linear pass over the property store, once, on a legacy image.
    ///
    /// **Measured** before the choice was taken, on this project's file-backed device
    /// (`FileBlockDevice` + `FileLogSink`, 8192-frame pool, release build, x86-64):
    ///
    /// | property cells | store size | this scan | whole `RecordStore::open` | share |
    /// | --- | --- | --- | --- | --- |
    /// | 1 000 000 | 127 MiB | 19.0 ms | 455 ms | 4.2 % |
    /// | 4 000 000 | 509 MiB | 77.5 ms | 1.85 s | 4.2 % |
    ///
    /// Linear at ≈19 ns per cell and a constant fraction of an open that already reads those pages.
    /// A one-off 4 % on the single open that upgrades a legacy store is not a reason to strand every
    /// tombstone-free legacy store, which is what the unconditional refusal would do.
    ///
    /// # The second tier, which this does not replace
    ///
    /// This gate answers at `open`, before a single property is read, and it is the tier that can name
    /// the cause and the migration route. It is not the only one: the consistency checker reports
    /// every such cell as
    /// [`MvccHeaderFault::PropertyCellTombstoned`](crate::check::MvccHeaderFault), and
    /// [`verify_on_open`](crate::check::verify_on_open) — the server's inviolable gate on every
    /// database it opens (`04 §4.6`/§4.8) — turns that into a refusal to serve. The two are
    /// independent: the checker would still catch a tombstoned cell in a version-3 image, which is a
    /// state no version number can describe and only a bug could produce.
    ///
    /// # Errors
    /// Returns a storage error naming the cause and the migration route when `format_version` is below
    /// [`PROPERTY_UNDO_CHAIN_FORMAT_VERSION`] and any in-use property cell carries a non-zero
    /// `expired_ts`, or if the `props.store` scan cannot read a page.
    fn refuse_legacy_property_tombstones(
        pool: &ConcurrentBufferPool<D, SharedWal<S>>,
        stores: &[FixedStore; STORE_COUNT],
        format_version: u32,
    ) -> Result<()> {
        if format_version >= PROPERTY_UNDO_CHAIN_FORMAT_VERSION {
            return Ok(());
        }
        let (count, first) = read_view::scan_property_tombstones(pool, stores)?;
        let Some((id, expired_ts)) = first else {
            return Ok(()); // a tombstone-free legacy image: the upgrade is lossless, open it
        };
        // Name the origin truthfully for each version rather than for the common one: a version-2
        // image was NOT written by a released build, and telling an operator to go back to v0.0.10 to
        // drain it would send them to a build that cannot open it.
        let provenance = if format_version == LEGACY_FORMAT_VERSION {
            "written by a released build, Graphus v0.0.10 or earlier"
        } else {
            "written by an unreleased build between `rmp` #966 (which added the undo area) and #967 \
             (which moved the property path onto it)"
        };
        Err(GraphusError::Storage(format!(
            "refusing to open this store: it carries on-disk format version {format_version} \
             ({provenance}, so its properties predate `D-property-visibility`) and its property \
             chains still hold {count} MVCC property tombstone(s) — the first at props.store record \
             {id}, expired_ts {expired_ts:#018x}. This build (format version \
             {PROPERTY_UNDO_CHAIN_FORMAT_VERSION}) resolves a property's visibility from the owning \
             entity's undo chain and no longer reads a property cell's `xmax` (`rmp` #967), so \
             opening this store would report every committed property removal as if the property \
             were still present, reject the next write to each of those keys, and never reclaim \
             their slots. Refusing to open rather than misread (`05 §12.6`). There is no in-place \
             upgrade — the property cell's layout did not change, its MEANING did, so no catalog \
             rewrite can recover which cells were removals. To migrate: open the store with the \
             build that wrote it, export the graph from it (`graphus-bulk dump` writes the node and \
             relationship CSV pair), and load that export into a NEW store created by this build."
        )))
    }

    /// Persists the in-memory catalog to the metadata page as one WAL-logged update under `txn`.
    /// When `commit` is set, `txn` is begun and committed around the write (standalone catalog
    /// change, `04 §2.6`); otherwise the write joins the caller's open `txn`.
    fn checkpoint_meta(&mut self, txn: TxnId, commit: bool) -> Result<()> {
        let meta = self.snapshot_meta(txn);
        let payload = meta.encode()?;
        // Split the catalog into [`META_CHUNK_CAP`]-byte chunks across the metadata-page chain. At
        // least one page (the head) is always written, even for an empty chunk.
        let n_chunks = payload.len().div_ceil(META_CHUNK_CAP).max(1);
        let n_cont = n_chunks - 1;

        if commit {
            self.wal.with(|w| {
                w.begin(txn);
            });
        }

        // Grow the continuation chain on demand. A fresh continuation page is allocated like a
        // record page (extend the device, stamp a meta-type header, flush so a later fetch verifies
        // a valid checksum); the chunk + link bytes that follow are WAL-logged, so a crash
        // mid-checkpoint recovers atomically — a loser's link reverts and the orphan page is left
        // harmlessly unreferenced, exactly as for record-page growth (`04 §4.4`).
        while self.meta_chain.len() < n_cont {
            let (f, dev_page) = self.pool.new_page()?;
            self.pool.with_page_mut(f, |p| {
                page::set_page_type(p, PAGE_TYPE_META);
                page::set_page_id(p, dev_page.0);
            });
            // The chunk + link bytes are written WAL-logged below; this only seeds a valid checksum
            // for the freshly-allocated, not-yet-logged page (`flush_unlogged`, `rmp` #337).
            self.pool.flush_unlogged(f)?;
            self.pool.unpin(f);
            self.meta_chain.push(dev_page);
        }

        // Write the head plus *every* owned continuation page (copied so the loop can take
        // `&mut self`). Chunks past the catalog's end are written empty: this keeps the whole owned
        // chain reachable on reopen even in the rare event the catalog shrank across a page boundary
        // (device-page maps only grow, so in practice the chain matches the catalog exactly), so no
        // allocated page is ever orphaned by a checkpoint.
        let total = 1 + self.meta_chain.len();
        let mut pages = Vec::with_capacity(total);
        pages.push(META_PAGE);
        pages.extend_from_slice(&self.meta_chain);

        for i in 0..total {
            let lo = (i * META_CHUNK_CAP).min(payload.len());
            let hi = ((i + 1) * META_CHUNK_CAP).min(payload.len());
            let chunk = &payload[lo..hi];
            let next = if i + 1 < total { pages[i + 1].0 } else { 0 };
            let mut framed = Vec::with_capacity(12 + chunk.len());
            // The head page carries the format-version tripwire; continuation pages do not, because a
            // pre-#966 build never reaches one — it fails on the head (`META_FORMAT_V2_FLAG`).
            let framed_len = if i == 0 {
                chunk.len() as u32 | META_FORMAT_V2_FLAG
            } else {
                chunk.len() as u32
            };
            framed.extend_from_slice(&framed_len.to_le_bytes());
            framed.extend_from_slice(&next.to_le_bytes());
            framed.extend_from_slice(chunk);
            self.write_region(pages[i], HEADER_SIZE, &framed, txn)?;
        }

        if commit {
            self.wal.with(|w| w.commit(txn))?;
        }
        Ok(())
    }

    // ----------------------------- page writing -----------------------------

    /// Maps a store-relative page index to its device `PageId`, growing the store (extending the
    /// device, initialising a record-page header, recording the mapping) as needed, under `txn`.
    fn ensure_store_page(&mut self, kind: StoreKind, rel_page: u64, txn: TxnId) -> Result<PageId> {
        let rel_page = rel_page as usize;
        while self.store(kind).device_pages.len() <= rel_page {
            let (f, dev_page) = self.pool.new_page()?;
            self.pool.with_page_mut(f, |p| {
                page::set_page_type(p, PAGE_TYPE_RECORD);
                page::set_page_id(p, dev_page.0);
            });
            // Seed the page header's checksum; the record writes that follow are WAL-logged (and the
            // type/subtype is also WAL-logged via `write_region_keep` below), so this freshly-grown
            // page carries no logged change yet — `flush_unlogged` (page_lsn 0, `rmp` #337).
            self.pool.flush_unlogged(f)?;
            self.pool.unpin(f);
            // PUBLISH the page to every reader (`rmp` #721). This is a `Release` store of the map's
            // length, and it happens HERE — strictly before the caller writes the record content that
            // will point into `dev_page`, and strictly before that content is published to readers by
            // the buffer pool's per-frame latch. So a reader that can see a pointer into this page can
            // always LOCATE it; the reverse order would resurrect the "store page N not allocated"
            // defect this fix closes. The page is fully initialised (header seeded, `flush_unlogged`d,
            // unpinned) before it is published, so a reader can never observe a half-built page.
            self.store_mut(kind).device_pages.push(dev_page)?;
            // WAL-log the record page's type+subtype header word with **undo == redo** (`rmp` #239).
            //
            // The per-store device-page map (`device_pages`) is persisted only in the durable catalog at
            // a *commit*'s `checkpoint_meta`. A device page allocated solely by transactions that ABORT
            // (never commit) is still materialised on disk — but under no-force crash recovery the device
            // is rebuilt purely from the WAL, so a page header that was only `flush`ed (not WAL-logged) is
            // LOST: recovery's `DeviceTarget::apply` re-creates the page from a zero image and patches
            // only the record regions, never the type/subtype bytes. To make a store's pages
            // re-attributable after such a recovery (so a committed node's `first_rel` can still read an
            // aborted-edge dead-link corpse on an orphan page — `rmp` #220), the store-kind tag must be
            // **redo-durable**. Logging the type/subtype word here means ARIES redo restores it. Using
            // undo == redo (a no-op on abort) keeps the tag even when the allocating txn aborts: page
            // growth is never undone, so the page stays a tagged record page regardless of txn outcome,
            // and `reconstruct_orphan_store_pages` can rebuild `device_pages`/`high_water` on open.
            let mut hdr = [0u8; 2];
            hdr[0] = PAGE_TYPE_RECORD;
            hdr[1] = kind as u8;
            self.write_region_keep(dev_page, page::OFF_PAGE_TYPE, &hdr, txn)?;
        }
        self.store(kind).device_pages.get(rel_page).ok_or_else(|| {
            GraphusError::Storage(format!("{kind:?} store page {rel_page} not allocated"))
        })
    }

    /// Writes `bytes` at `offset` within device `page` as one WAL-logged update under `txn` with
    /// **undo == redo** (a no-op on abort/recovery). Used for structural writes that must persist
    /// regardless of the writing transaction's outcome — currently the record-page type/subtype header
    /// stamp (`rmp` #239), since page growth is never undone.
    fn write_region_keep(
        &mut self,
        page: PageId,
        offset: usize,
        bytes: &[u8],
        txn: TxnId,
    ) -> Result<()> {
        let end = offset + bytes.len();
        assert!(end <= PAGE_SIZE, "region runs past the page");
        // Inline patch (`rmp` #373): undo == redo, so build it once and hand the WAL a borrowed
        // redo plus an owned undo (the only image the WAL retains). The redo never allocates.
        let redo = paging::encode_patch(offset, bytes);
        let undo = redo.clone().into_vec();
        let f = self.pool.fetch(page)?;
        // The WAL borrow is released (the `with` closure ends) before the pool write latch is taken,
        // upholding the lock-ordering rule (`crate::wal_rule`): never hold the WAL lock across a pool
        // call. `with_page_mut_lsn` stamps `page_lsn` and applies the post-image under one write
        // latch (`rmp` #337, Slice 1).
        let lsn = self
            .wal
            .with(|w| w.log_update_borrowed(txn, page, &redo, undo));
        self.pool.with_page_mut_lsn(f, lsn, |p| {
            p[offset..end].copy_from_slice(bytes);
        });
        self.pool.unpin(f);
        Ok(())
    }

    /// Writes `bytes` at `offset` within device `page` as one WAL-logged update under `txn`:
    /// appends an `Update` record (redo = post-image patch, undo = pre-image patch), stamps the
    /// page's `page_lsn`, and applies the post-image to the cached page (`04 §4.1`).
    ///
    /// The WAL borrow is released before any pool write path runs, so the pool's WAL rule can
    /// re-borrow the shared manager safely (see [`crate::wal_rule`]).
    fn write_region(
        &mut self,
        page: PageId,
        offset: usize,
        bytes: &[u8],
        txn: TxnId,
    ) -> Result<()> {
        let end = offset + bytes.len();
        assert!(end <= PAGE_SIZE, "region runs past the page");
        let f = self.pool.fetch(page)?;
        // Build the undo patch from the still-unmodified page slice (read latch) before the in-place
        // overwrite (write latch) below. The frame stays pinned across the two sequential — never
        // nested — latch acquisitions (`rmp` #337, Slice 1 closure-API conversion).
        // Capture the undo pre-image STRICTLY before the post-image overwrite below (`rmp` #373): the
        // read latch reads the still-unmodified region into an inline patch; only this undo image is
        // retained by the WAL (taken by value). The redo post-image is built inline and lent to the
        // WAL by borrow, so the redo never heap-allocates.
        let undo = self
            .pool
            .with_page(f, |p| paging::encode_patch(offset, &p[offset..end]))
            .into_vec();
        let redo = paging::encode_patch(offset, bytes);
        // WAL borrow dropped before the pool write latch (lock-ordering rule, `crate::wal_rule`).
        let lsn = self
            .wal
            .with(|w| w.log_update_borrowed(txn, page, &redo, undo));
        self.pool.with_page_mut_lsn(f, lsn, |p| {
            p[offset..end].copy_from_slice(bytes);
        });
        self.pool.unpin(f);
        Ok(())
    }

    /// Rewrites property cell `id` **in place** — the whole of `rmp` #967's write path — as ONE page
    /// latch, ONE WAL record and ONE contiguous byte patch over `PROP_CELL_REGION`.
    ///
    /// # Why exactly these bytes, and why one patch
    ///
    /// The region is `created_ts`, `expired_ts`, `undo_ptr`, `key`, `type_tag`, `value_inline` — every
    /// field the value-level write owns — and it deliberately excludes both ends of the record:
    ///
    /// * **byte 0, `flags`.** The in-use bit is the slot's *structural* state, shared with the
    ///   creation undo, the corpse discipline and GC. A value write never changes it, so it must not
    ///   appear in this write's pre-image either.
    /// * **`next_prop` (bytes 38..46).** The shared chain word, legitimately owned by
    ///   [`gc_property_chain`](Self::gc_property_chain)'s splice and by a concurrent prepend. A
    ///   whole-record [`write_prop`](Self::write_prop) here would log a whole-record pre-image undo of
    ///   a word this transaction does not own, which is the exact `rmp` #172 / #220 / #239 defect
    ///   family: an out-of-LIFO abort reverts a neighbour's committed chain edit and severs the chain.
    ///
    /// It is one patch rather than two (say, "stamp then value") because
    /// [`read_view::read_prop`](crate::read_view::read_prop) copies all 46 bytes under a **single**
    /// read latch: two `write_region` calls would open a window in which an off-thread reader
    /// observes the new value with the old stamp, or the reverse — a version no writer ever produced.
    /// Fields that do not change are carried through unchanged, which costs nothing (they are already
    /// in the encoded record) and keeps the patch contiguous.
    ///
    /// # The abort story
    ///
    /// The undo is a **plain pre-image** of the region, which is exact here — unlike every other
    /// shared-field write in this store — because the entity-granularity write-conflict check
    /// ([`ensure_no_conflicting_writer`](Self::ensure_no_conflicting_writer)) means no other
    /// transaction can be on this entity's property write path while this one holds it, so the
    /// pre-image cannot go stale. See that method for the four-part proof obligation.
    ///
    /// `link_delta` writes the delta **before** this cell write, so a WAL rollback (newest-LSN-first)
    /// restores the cell first and clears the delta's `in_use` flag second. The only observable
    /// intermediate state is therefore (cell restored, delta still reading live), in which a
    /// concurrent reader applies the delta and writes back the value already in the cell —
    /// idempotent. The reverse ordering would expose (cell still new, delta already dead), in which
    /// the reader keeps a value the aborting transaction wrote. That is why the order is fixed and
    /// not incidental.
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated or the write fails, or — failing
    /// closed — if `cell` carries a non-zero `expired_ts` or `undo_ptr`. Neither is reachable through
    /// this path: `expired_ts` is never written by a property operation after `D-property-removal`,
    /// and a `props.store` record never anchors an undo chain (the `SetProperty` delta anchors on the
    /// **owning** node/relationship). Writing either would build a second, invisible chain family.
    fn write_prop_cell(&mut self, id: u64, cell: &PropRecord, txn: TxnId) -> Result<()> {
        if cell.mvcc.expired_ts != 0 || cell.mvcc.undo_ptr != 0 {
            return Err(GraphusError::Storage(format!(
                "property cell {id} would be written with expired_ts {} / undo_ptr {}; after `rmp` \
                 #967 a property operation never stamps `xmax`, and a property record never anchors \
                 an undo chain (the `SetProperty` delta anchors on the owning entity)",
                cell.mvcc.expired_ts, cell.mvcc.undo_ptr
            )));
        }
        // `rmp` #522 FREEZE FRONTIER, re-armed for the `rmp` #967 in-place write path.
        //
        // This is the one place a property cell is rewritten IN PLACE, and every such rewrite restamps
        // `created_ts` to the writer's in-flight stamp. Before #967 a property write always ALLOCATED a
        // record, so a fresh in-flight stamp could only ever appear at or above the frontier and
        // `note_created`'s `lower_freeze_low` was enough. After #967 a `SET`/`REMOVE` of an existing key
        // restamps an EXISTING id, which is very often far BELOW the frontier — so the incremental
        // freeze sweep (`[freeze_low, high_water)`) never revisits it, the stamp is never settled to
        // `Committed(ts)`, and once the registry forgets that writer `is_visible` reads the stamp as
        // unresolvable. That is the exact #522 silent-lost-committed-data shape, reopened from a new
        // direction; `debug_assert_freeze_complete` caught it (DST
        // `bulk_load_mid_abort_wal_bound_590` / `reader_store_growth`, "in-use Prop record N still
        // bears an unfrozen committed-writer in-flight stamp").
        //
        // Lowering the frontier is the same remedy `note_created` documents for a reused id, and it
        // fails CLOSED: the only cost of lowering it too far is a wider sweep on the next GC pass.
        self.lower_freeze_low(StoreKind::Prop, id);
        let mut buf = [0u8; PROP_RECORD_SIZE];
        cell.encode(&mut buf);
        let (rel_page, off) = paging::record_location(id, PROP_RECORD_SIZE);
        let dev = self.device_page(StoreKind::Prop, rel_page)?;
        self.write_region(
            dev,
            off + PROP_CELL_REGION.start,
            &buf[PROP_CELL_REGION],
            txn,
        )
    }

    fn write_record(&mut self, kind: StoreKind, id: u64, buf: &[u8], txn: TxnId) -> Result<()> {
        let (rel_page, offset) = paging::record_location(id, kind.record_size());
        let dev_page = self.ensure_store_page(kind, rel_page, txn)?;
        self.write_region(dev_page, offset, buf, txn)
    }

    fn device_page(&self, kind: StoreKind, rel_page: u64) -> Result<PageId> {
        usize::try_from(rel_page)
            .ok()
            .and_then(|p| self.store(kind).device_pages.get(p))
            .ok_or_else(|| {
                GraphusError::Storage(format!("{kind:?} store page {rel_page} not allocated"))
            })
    }

    // ----------------------------- record I/O ------------------------------

    /// Returns a reusable physical id for `kind`: a freed id from the store's free list when one is
    /// available, otherwise a fresh high-water id whose store page is **mapped before the id is
    /// handed out**.
    ///
    /// # Mapping the page at allocation time (`rmp` #479)
    ///
    /// A fresh id's device page is mapped here — eagerly — rather than lazily at write time. This keeps
    /// the catalog invariant **`high_water <= addressable capacity`** (every allocated physical id has a
    /// mapped device page) true the instant the id is handed out. The durable-catalog decoder
    /// ([`crate::meta::Meta::decode`], `rmp` #452), the rollback catalog reload
    /// ([`reload_catalog`](Self::reload_catalog)), the orphan-page reconstruction
    /// ([`reconstruct_orphan_store_pages`](Self::reconstruct_orphan_store_pages)) and every store scan
    /// all rely on it.
    ///
    /// Previously the page was mapped lazily inside [`write_record`](Self::write_record). A transaction
    /// that advanced the high-water here and then failed a LATER fallible step **before** writing the
    /// record — e.g. [`create_rel`](Self::create_rel) crossing a relationship page boundary in
    /// `alloc_id` and then surfacing a disk-fault checksum error in `relink_old_head`/`read_node` —
    /// left the high-water one past the mapped capacity. A subsequent checkpoint persisted that
    /// inconsistent catalog (`high_water > capacity`); a later rollback's `reload_catalog` then rejected
    /// it, and (because rollback's page-map restore was skipped on that error) every store's
    /// `device_pages` was emptied, blank pages were re-allocated over committed records, and committed
    /// data was silently lost — an ACID durability violation surfaced by VOPR seed 5043221. Mapping the
    /// page up front (and un-bumping the high-water if the mapping itself fails) closes that hole.
    ///
    /// # Errors
    /// Returns a storage error if the store's physical-id space is exhausted (`rmp` #452, see
    /// [`PhysicalAllocator::alloc_fresh`]) or if mapping the fresh id's page fails (e.g. ENOSPC).
    /// Pops the next **reusable** freed physical id of `kind`, or `None` when the free list is empty
    /// or holds only ids still shadow-held for an in-flight off-thread reader (`rmp` #588).
    ///
    /// Held ids are stashed and re-listed so they stay free for later reuse once released; if only
    /// held ids remain this returns `None` and the caller grows a fresh id rather than reusing one.
    /// On the common path (`held_slots` empty) this is the pre-#588 single pop.
    fn pop_free_id(&mut self, kind: StoreKind) -> Option<u64> {
        if self.held_slots[kind as usize].is_empty() {
            return self.store_mut(kind).free.pop();
        }
        let mut stash: Vec<u64> = Vec::new();
        let picked = loop {
            match self.store_mut(kind).free.pop() {
                Some(id) if self.held_slots[kind as usize].contains_key(&id) => stash.push(id),
                other => break other,
            }
        };
        for id in stash {
            self.store_mut(kind).free.push(id);
        }
        picked
    }

    /// Records that `txn` **popped** (reused) freed physical id `id` of `kind`, so a live rollback can
    /// return it to the free list if the transaction aborts without the slot becoming a
    /// live-referenced corpse (`rmp` #581). Mirrors the `SYSTEM_TXN` guard of
    /// [`note_created`](Self::note_created) / [`free_push`](Self::free_push): the system transaction
    /// never pops-then-aborts and is never rolled back.
    fn note_popped_id(&mut self, txn: TxnId, kind: StoreKind, id: u64) {
        if txn != SYSTEM_TXN {
            self.active
                .entry(txn)
                .or_default()
                .popped_ids
                .push((kind, id));
        }
    }

    fn alloc_id(&mut self, kind: StoreKind, txn: TxnId) -> Result<u64> {
        // A freed id is reused first: its store page already exists (the record once lived there), so
        // no growth — and no fallibility — is needed. `rmp` #588: SKIP any freed id still shadow-held
        // for an in-flight off-thread reader (see [`held_slots`](Self#structfield.held_slots)) — reusing
        // its slot would let that reader read a foreign record mid chain-walk (an ACID Isolation
        // violation). Held ids are stashed and re-listed so they stay free for later reuse once released;
        // if only held ids remain we grow a fresh id rather than reuse one. On the common path
        // (`held_slots` empty) `contains_key` is a cheap miss and this is the pre-#588 single pop.
        // (`rmp` #968 retired the id-keyed label history that used to make a reused id dangerous here:
        // a node's label versions are deltas on its own record's chain, reclaimed with the record, so a
        // reused slot starts at `undo_ptr == 0` with nothing to inherit.)
        if let Some(id) = self.pop_free_id(kind) {
            self.note_popped_id(txn, kind, id);
            return Ok(id);
        }
        // Fresh id: `alloc_fresh` first (it fails closed at the `u64::MAX` ceiling, `rmp` #452, so we
        // never compute a page index for an astronomically large id), then map the page the id lands
        // on. A within-page id finds its page already mapped (a cheap no-op); only a page-boundary
        // crossing actually grows `device_pages` — exactly the growth `write_record` would have done,
        // just up front.
        let id = self.store_mut(kind).alloc.alloc_fresh()?;
        let (rel_page, _) = paging::record_location(id, kind.record_size());
        if let Err(e) = self.ensure_store_page(kind, rel_page, txn) {
            // Mapping failed (e.g. ENOSPC growing the device): un-bump the high-water so it never
            // exceeds the mapped capacity. `id` was never written, so re-handing it out is safe.
            self.store_mut(kind).alloc = PhysicalAllocator::restore(id.max(1));
            return Err(e);
        }
        Ok(id)
    }

    // The read-decode methods below delegate to the single authoritative impl in
    // [`crate::read_view`] (`rmp` #336, Slice 3a), passing `&self.stores` as the live location oracle
    // (a direct borrow — no per-call allocation). The exact same free functions back the off-thread
    // [`StoreReadView`], so the two read paths are byte-identical by construction (proven by the
    // equivalence test). `with_page_fetched` reads the resident page under a single latch (the hot
    // read path); the decoded record is owned so it escapes the borrow (`rmp` #337 Slice 1).
    fn read_node(&self, id: u64) -> Result<NodeRecord> {
        read_view::read_node(&self.pool, &self.stores, id)
    }

    fn read_rel(&self, id: u64) -> Result<RelRecord> {
        read_view::read_rel(&self.pool, &self.stores, id)
    }

    fn read_prop(&self, id: u64) -> Result<PropRecord> {
        read_view::read_prop(&self.pool, &self.stores, id)
    }

    fn read_block(&self, id: u64) -> Result<HeapBlock> {
        read_view::read_block(&self.pool, &self.stores, id)
    }

    fn write_block(&mut self, id: u64, rec: &HeapBlock, txn: TxnId) -> Result<()> {
        let mut buf = [0u8; STRINGS_RECORD_SIZE];
        rec.encode(&mut buf);
        self.write_record(StoreKind::Strings, id, &buf, txn)
    }

    fn write_node(&mut self, id: u64, rec: &NodeRecord, txn: TxnId) -> Result<()> {
        let mut buf = [0u8; NODE_RECORD_SIZE];
        rec.encode(&mut buf);
        self.write_record(StoreKind::Node, id, &buf, txn)
    }

    fn write_rel(&mut self, id: u64, rec: &RelRecord, txn: TxnId) -> Result<()> {
        let mut buf = [0u8; REL_RECORD_SIZE];
        rec.encode(&mut buf);
        self.write_record(StoreKind::Rel, id, &buf, txn)
    }

    fn write_prop(&mut self, id: u64, rec: &PropRecord, txn: TxnId) -> Result<()> {
        let mut buf = [0u8; PROP_RECORD_SIZE];
        rec.encode(&mut buf);
        self.write_record(StoreKind::Prop, id, &buf, txn)
    }

    // ------------------------- transaction control -------------------------

    /// The Active/Recent Transaction Table (`rmp` task #49). The reader layer
    /// ([`RecordStoreGraph`](../../graphus_cypher)) resolves an on-disk in-flight `xmin`/`xmax`
    /// stamp to its writer's commit timestamp — or learns the writer is still in flight or aborted —
    /// through this, since lazy freezing leaves a committed version stamped with its writer's
    /// `TxnId` until a [`gc`](Self::gc) pass freezes it to `Committed(ts)` and prunes the entry
    /// (`rmp` task #59). Borrowed read-only; the store owns the table.
    #[must_use]
    pub fn commit_registry(&self) -> &CommitRegistry {
        &self.commit_registry
    }

    /// Whether `txn` is a **live, unresolved** transaction of this store: it has
    /// [`begin`](Self::begin)-ed and has neither committed nor rolled back.
    ///
    /// # Use this, not `commit_registry().outcome(txn) == TxnOutcome::InFlight`
    ///
    /// That predicate is **dead — always `false`** — and mistaking it for this one has now caused two
    /// separate silent-data-loss defects (`rmp` #522, `rmp` #778). The registry records an outcome only
    /// when a transaction *resolves*: [`commit`](Self::commit) inserts `Committed(ts)` and
    /// [`rollback`](Self::rollback) inserts `Aborted`. A still-running transaction therefore has **no
    /// registry entry at all**, and [`CommitRegistry::outcome`](graphus_txn::CommitRegistry::outcome)
    /// maps an unknown id to `Aborted`, never `InFlight` — so the naive predicate silently reports every
    /// genuinely open writer as resolved. Live membership in the Active Transaction Table is the correct
    /// "this writer might still commit, so treat its versions as uncommitted" signal.
    #[must_use]
    pub fn is_txn_active(&self, txn: TxnId) -> bool {
        self.active.contains_key(&txn)
    }

    /// How many **live label deltas** the undo area currently holds, and how many of them belong to
    /// still-unresolved transactions (`rmp` #968).
    ///
    /// The chain-native replacement for the retired `LabelHistory`'s `any()` / `tracked_nodes()` /
    /// `has_inflight_versions_of()`, which existed for exactly this question: is there label version
    /// state outstanding, and does any of it belong to a writer that has not resolved? It is an
    /// observability seam, not a read path — it scans `undo.store` — so it belongs in scenario
    /// oracles and diagnostics, never in a query.
    ///
    /// Counts only `AddLabel` / `RemoveLabel` deltas whose slot is still `in_use`; a corpse (an
    /// aborted writer's) is not outstanding state, and neither is a reclaimed slot.
    ///
    /// # Errors
    /// Returns a storage error if an `undo.store` page cannot be read.
    pub fn live_label_delta_census(&self) -> Result<(usize, usize)> {
        let mut live = 0usize;
        let mut unresolved = 0usize;
        let high = self.stores[StoreKind::Undo as usize].alloc.high_water();
        for id in 1..high {
            let Some(delta) = self.read_delta(id)? else {
                continue;
            };
            if !delta.in_use()
                || !matches!(delta.action, UndoAction::AddLabel | UndoAction::RemoveLabel)
            {
                continue;
            }
            live += 1;
            if let Some(slot) = self.read_commit_slot(delta.commit_info)?
                && let Some(holder) = crate::scan_polarity::open_writer_of(slot)
                && self.is_txn_active(holder)
            {
                unresolved += 1;
            }
        }
        Ok((live, unresolved))
    }

    /// The lowest-numbered **open transaction that has already written data**, or [`None`] when every
    /// open transaction is read-only (`rmp` task #902).
    ///
    /// "Has written data" means its mutations are already **physically present** in the store — a
    /// record it created or tombstoned, a label bitmap it changed, or a property value it overwrote in
    /// place — and would therefore be observed by any caller that reads the store raw instead of
    /// through a [`Snapshot`](graphus_txn::Snapshot). The four lists this reads are exactly the ones
    /// the commit/rollback paths consume to settle or undo those mutations, so a transaction with all
    /// four empty has changed nothing a raw scan can see, and its future writes are subject to whatever
    /// the caller declares in the meantime.
    ///
    /// # Why `undo_links` is in that set (`rmp` #967)
    ///
    /// A property write used to PREPEND a new record and tombstone the old one, so it always showed up
    /// in `created` + `expired`. After `rmp` #967 (`D-property-removal`) it is written **in place**:
    /// no record is created, none is tombstoned, no label word moves — the only trace it leaves in the
    /// Active Transaction Table is the `SetProperty` delta it linked onto the entity's undo chain.
    ///
    /// Without this clause a transaction whose only uncommitted mutation is `SET n.p = …` became
    /// INVISIBLE to this predicate, which silently disabled the `rmp` #902 fail-closed guard: the
    /// constraint DDL judged the committed image alone, ACCEPTED `IS UNIQUE`, and the open writer then
    /// committed a duplicate under a live constraint — a committed duplicate no SSI edge can undo,
    /// because the DDL takes no predicate marker. Pinned by
    /// `graphus-cypher/tests/constraint_validation_visibility.rs::create_constraint_refuses_while_another_transaction_holds_uncommitted_writes`,
    /// which caught exactly this regression.
    ///
    /// This is the store's answer to "is the committed image decidable right now?", used by the
    /// constraint DDL to refuse rather than judge existing data it cannot resolve
    /// (`TxnCoordinator::create_constraint_general`). It deliberately reports the **lowest** such id
    /// rather than an arbitrary one: `active` is a `HashMap`, so returning "any" would make the error
    /// message — and any test over it — non-deterministic, which DST forbids.
    ///
    /// Read-only transactions are excluded on purpose. They hold no uncommitted state, so they cannot
    /// make the committed image ambiguous, and refusing a schema change merely because a session has
    /// an open read would be disproportionate on a server whose mandate is extreme concurrency.
    ///
    /// That is a statement about *this* predicate only, and not a claim that an open reader is harmless
    /// to a constraint. An open transaction whose **snapshot** predates a row committed before the
    /// constraint was declared can still write a duplicate it cannot itself see; nothing here detects
    /// that, because there is nothing uncommitted to detect. Closing it needs the DDL to carry an SSI
    /// predicate marker (`rmp` task #903) — see the caller for the full scenario.
    #[must_use]
    pub fn uncommitted_data_writer(&self) -> Option<TxnId> {
        self.active
            .iter()
            .filter(|(_, a)| {
                !a.created.is_empty() || !a.expired.is_empty() || !a.undo_links.is_empty()
            })
            .map(|(txn, _)| *txn)
            .min()
    }

    /// Opens transaction `txn`'s MVCC version-stamp bookkeeping. The WAL `BEGIN` is **lazy** (`rmp`
    /// #529): it is *not* emitted here — the WAL Active-Transaction-Table entry is created on demand by
    /// the first data record ([`WalManager::log_update`]'s `or_insert`). A read-only transaction
    /// therefore appends **zero** WAL bytes across its whole lifecycle (begin *and* commit), which is
    /// what lets [`commit`](Self::commit) skip its `fdatasync` entirely.
    ///
    /// This is durability-neutral: ARIES recovery keys off each record's own `TxnId` and never assumes
    /// a `BEGIN` exists — analysis adds a transaction to the Active-Transaction-Table on the first
    /// record it sees for that id (begin *or* update, [`graphus_wal::recover`]), and a loser's
    /// undo back-chain terminates at `prev_lsn == 0` whether that first record is a begin or the first
    /// update. The reclaim floor and the oldest-active-first-LSN backup window
    /// ([`WalManager::oldest_active_first_lsn`]) are likewise driven by the *earliest logged record*,
    /// so a transaction that logs nothing correctly contributes no floor (it has no undo chain to
    /// protect).
    pub fn begin(&mut self, txn: TxnId) {
        self.active.insert(txn, ActiveTxn::default());
    }

    /// The current MVCC read snapshot timestamp (`04 §5.2`): the largest commit timestamp issued so
    /// far, so a reader that begins now sees exactly every transaction that has already committed
    /// and nothing committed later. A fresh store (no commits yet) returns `Timestamp(0)`.
    #[must_use]
    pub fn snapshot_ts(&self) -> Timestamp {
        Timestamp(self.commit_ts_hw)
    }

    /// The **durable-write commit-timestamp high-water** (`rmp` task #813): the largest commit timestamp
    /// of a write commit whose `COMMIT` record is `fdatasync`-durable. This is the source of a read
    /// transaction's Bolt causal bookmark — it always names an already-durable commit, never decreases,
    /// and (unlike [`snapshot_ts`](Self::snapshot_ts)) is unaffected by a read-only commit's `rmp` #529
    /// phantom tick, so two reads with no write between them observe the SAME value (Neo4j semantics).
    ///
    /// First drains any PREPAREd write whose `commit_lsn` the WAL has since hardened, so a read that runs
    /// between two batch hardens still reflects exactly what is durable at that instant (and never a
    /// prepared-but-un-hardened write).
    pub fn durable_write_commit_ts(&mut self) -> Timestamp {
        self.advance_durable_write_watermark();
        Timestamp(self.durable_write_commit_ts_hw)
    }

    /// Promotes every PREPAREd durable-write commit (`rmp` task #813) whose `commit_lsn` the WAL has now
    /// hardened (`durable_len`) into `durable_write_commit_ts_hw`. The queue is in ascending `commit_lsn`
    /// order and `commit_ts` is monotonic with it, so this pops a hardened prefix and takes the max.
    /// Called after every harden (bounding the queue to at most one un-hardened batch) and on each read
    /// of the watermark.
    fn advance_durable_write_watermark(&mut self) {
        let durable = self.wal.with(|w| w.durable_len());
        while let Some(&(lsn, ts)) = self.pending_write_commits.front() {
            if lsn.0 <= durable {
                self.durable_write_commit_ts_hw = self.durable_write_commit_ts_hw.max(ts.0);
                self.pending_write_commits.pop_front();
            } else {
                break;
            }
        }
    }

    /// Captures this store's per-[`StoreKind`] read metadata into an owned, `Send + Sync`
    /// [`MetaSnapshot`] (`rmp` task #336, Slice 3a; corrected by `rmp` #721): each store's
    /// **snapshotted** `high_water` bound + a **live**, shared handle on its page map. Call this on the
    /// engine thread (where the store is exclusively held); the result drives the off-thread read path
    /// through a [`StoreReadView`] (Slice 3b) with no `&mut` access to the store.
    ///
    /// # Why the page map is LIVE and the high-water is SNAPSHOTTED (`rmp` #721)
    ///
    /// These two are not the same kind of thing, and freezing both was the defect.
    ///
    /// - `high_water` is a **bound**: it delimits the id range a scan visits (`1..high_water`). It must
    ///   be snapshotted, so a scan is not chased by a concurrent writer and so it remains an
    ///   MVCC-superset of what the reader may legally see.
    /// - The page map is a **location oracle**: it answers "which device page holds record id X". It
    ///   must be LIVE, because the record *content* the reader navigates is live (the page cache is
    ///   `Arc`-shared) and a chain walk FOLLOWS POINTERS out of that live content. A concurrently
    ///   committed writer prepends to a chain head, so the reader can legitimately reach a record on a
    ///   page allocated after its snapshot. Freezing the map made that read fail with
    ///   `"{kind} store page N not allocated"` — an internal error on a legitimate read — because
    ///   **visibility is decided ABOVE this layer**: a record the reader cannot LOCATE is never
    ///   filtered; the walk dies first.
    ///
    /// Resolving against the live map is sound precisely because the map is **monotone**: pages are
    /// only ever appended, never remapped or removed, and page growth is never undone by a rollback
    /// (`rmp` #239). Locating a post-snapshot record is harmless — `graphus_txn::is_visible` still
    /// filters it out above. The capture is now also strictly cheaper: one `Arc` refcount bump per
    /// store instead of a full copy of every store's page list on every read dispatch.
    #[must_use]
    pub fn capture_read_meta(&self) -> MetaSnapshot {
        let snap = |kind: StoreKind| {
            let s = self.store(kind);
            StoreMetaSnapshot {
                high_water: s.alloc.high_water(),
                device_pages: s.device_pages.reader(),
            }
        };
        // Every store, including the undo area's two: the off-thread read path resolves a record's
        // location through this snapshot, and a reader that walks a version chain (`rmp` #966 and the
        // tasks built on it) must be able to locate a delta exactly as it locates a record.
        MetaSnapshot::new(ALL_STORE_KINDS.map(snap))
    }

    /// Builds an owned, `Send + Sync` [`StoreReadView`] over this store's committed state (`rmp` task
    /// #336, Slice 3a): an [`Arc`]-shared clone of the page cache plus a freshly
    /// [`capture_read_meta`](Self::capture_read_meta)d [`MetaSnapshot`]. The view exposes the same read
    /// surface the Cypher layer drives, computed purely from `(pool, meta)`; it carries no
    /// snapshot/visibility logic of its own (the caller filters returned records by
    /// `graphus_txn::is_visible` against its own cloned `CommitRegistry`, exactly as the `&self` read
    /// methods are filtered above this layer). Slice 3a is single-threaded and behaviour-preserving
    /// (the view is proven byte-identical to the `&self` methods); Slice 3b moves it onto reader
    /// threads.
    #[must_use]
    pub fn read_view(&self) -> StoreReadView<D, S> {
        StoreReadView::new(Arc::clone(&self.pool), self.capture_read_meta())
    }

    /// Commits `txn`: persists the catalog under `txn`, then group-commits the WAL so all of
    /// `txn`'s work (records, catalog growth, token creation) is durable (`04 §4.2`).
    ///
    /// This is the eager single-commit path: [`commit_prepare`](Self::commit_prepare) (assign the
    /// commit timestamp, publish the outcome, append the `COMMIT` record) immediately followed by the
    /// group-commit `fdatasync` ([`harden_wal`](Self::harden_wal)) and the redo-bounding auto-checkpoint
    /// (`maybe_checkpoint`) — byte-for-byte and behaviourally identical to the
    /// pre-split path. The engine's cross-transaction group-commit path (`rmp` #528) instead calls
    /// `commit_prepare` for **many** transactions and then a **single** [`harden_wal`](Self::harden_wal),
    /// coalescing their `fdatasync`s.
    ///
    /// **Read-only fast path (`rmp` #529):** a transaction that logged nothing durable (a read-only
    /// transaction — see [`begin`](Self::begin)'s lazy `BEGIN`) has nothing to persist, so it performs
    /// **zero** WAL appends and **zero** `fdatasync`: the catalog checkpoint, the WAL `COMMIT` record
    /// and the group-commit sync are all skipped. The commit-timestamp oracle is still advanced (so the
    /// coordinator's SSI `record_commit` sees a fresh timestamp, byte-identical to before), it is just
    /// not made durable — a harmless post-crash reissue, since the transaction produced no versions.
    ///
    /// # Errors
    /// Returns a storage error if the catalog cannot be persisted or `txn` is not active.
    ///
    /// # Panics
    /// Panics if the commit `fdatasync` fails (`04 §4.9`) — for a read-only commit no sync is issued.
    pub fn commit(&mut self, txn: TxnId) -> Result<()> {
        match self.commit_prepare(txn)? {
            // Read-only fast path (`rmp` #529): nothing was appended, so there is nothing to harden and
            // no checkpoint to take.
            None => Ok(()),
            // A durable write commit: harden the just-appended records (the group-commit `fdatasync`)
            // and take the redo-bounding auto-checkpoint. Identical to the pre-#528 inline path (same
            // durable bytes, same fsync placement observationally, same checkpoint cadence).
            Some(_commit_lsn) => {
                self.harden_wal();
                self.maybe_checkpoint()
            }
        }
    }

    /// Commit-**PREPARE** (cross-transaction group commit, phase 1, `04 §4.2` / `rmp` #528): runs the
    /// entire in-memory commit of `txn` EXCEPT the group-commit `fdatasync` and the redo-bounding
    /// auto-checkpoint. It assigns the commit timestamp, records the commit in the Active/Recent
    /// Transaction Table (so `txn` is committed-**visible** to new readers the instant this returns),
    /// persists any catalog delta, and appends the WAL `COMMIT` record — but leaves that record
    /// **un-hardened** in the sink's pending buffer for a later batch [`harden_wal`](Self::harden_wal).
    ///
    /// Returns `Some(commit_lsn)` when a durable `COMMIT` record was appended (a real write commit the
    /// batch `fdatasync` must cover), or `None` when the read-only fast path applied (`rmp` #529 —
    /// nothing appended, nothing to harden). The caller MUST issue a [`harden_wal`](Self::harden_wal)
    /// (which advances the durable watermark past the returned LSN) **before** acknowledging `txn` to
    /// its client — the ack-after-fsync durability rule. A crash before that harden loses this record
    /// (recovery truncates the un-synced tail), which is correct precisely because the client was never
    /// acked.
    ///
    /// **Ordering note (`rmp` #528):** the post-append bookkeeping below (`catalog_dirty = false`, the
    /// `unfrozen_commit_lsn` insert, the GC-prune) runs here — *before* the deferred harden — rather
    /// than after an inline `fdatasync` as the pre-split path did. This is sound because the only failure
    /// mode of the deferred harden is a PANIC (`04 §4.9`, fsyncgate) that aborts the process, after which
    /// this in-memory state is irrelevant (recovery rebuilds from the durable WAL); on a *successful*
    /// harden the resulting state is exactly what the pre-split ordering produced. No watermark is
    /// advanced here (the `unfrozen_commit_lsn` floor only ever *lowers* what reclaim may drop, and
    /// reclaim itself runs only in `maybe_checkpoint`, after the batch harden).
    ///
    /// # Errors
    /// Returns a storage error if the catalog cannot be persisted or `txn` is not active.
    pub fn commit_prepare(&mut self, txn: TxnId) -> Result<Option<Lsn>> {
        // Assign this transaction's commit timestamp (`04 §5.2`). **Lazy GC-time freezing**
        // (`04 §5.5`, hint-bit style, `rmp` task #49): do NOT settle each version's header from the
        // in-flight `TxnId` to the commit timestamp here — that was O(records touched) WAL-logged
        // header writes (the eager, correctness-first path of task #45). Instead record the outcome
        // in the Active/Recent Transaction Table; a reader resolves an in-flight stamp to its commit
        // timestamp through that table ([`is_reclaimable`](Self::is_reclaimable) and the cypher
        // visibility layer via [`commit_registry`](Self::commit_registry)); the GC-time header
        // freeze (`rmp` task #59) later settles the stamps and prunes the entries, bounding the
        // table. What makes a committed insert/delete survive a crash is now the WAL commit record
        // carrying `commit_ts` (`commit_at_no_sync`): recovery rebuilds the table from it
        // ([`open`](Self::open)). Commit is now O(1) in header writes.
        // Did `txn` change anything durable? Two independent signals (`rmp` #529):
        //   * `wrote_durable` — it logged a WAL data record. Because `BEGIN` is lazy and every record
        //     write goes through [`WalManager::log_update`] (which creates the WAL Active-Transaction-
        //     Table entry on the first write), "has a WAL active entry" is exactly "wrote durable
        //     data". Captured **before** `checkpoint_meta` below, which would itself create the entry.
        //   * `catalog_dirty` — it made a catalog-only change (token intern, histogram / index /
        //     full-text / spatial / constraint declaration) that logs no data record and is durable
        //     ONLY via the commit-time `checkpoint_meta`; missing it would silently drop a committed
        //     catalog change (the `statistics` reopen tests are the regression guard).
        let wrote_durable = self.wal.with(|w| w.is_active(txn));
        let commit_ts = self.next_commit_ts();
        // Settle this transaction's retained label versions from its in-flight stamp to
        // `Committed(commit_ts)` (`rmp` #767). Unlike the record headers above — settled lazily at GC
        // time because doing it eagerly was O(records) WAL-logged page writes — this history is small
        // and purely in-memory, so settling now is free and logs nothing.
        //
        // It is REQUIRED, not an optimisation: a raw in-flight stamp is only resolvable while the
        // `commit_registry` still holds `txn`, and a GC pass FORGETS committed writers from that
        // registry once their headers are frozen (`pending_gc_prune`, applied below). After that the
        // registry maps the unknown id to `Aborted`, so the version would read as never-committed and
        // every reader would fall back to the PRE-CHANGE bitmap — a committed label change silently
        // reverting in memory, healed only by a restart.
        // The settle itself is DEFERRED to [`settle_committed_txn`](Self::settle_committed_txn), which
        // runs at each of this method's two exits — and at neither of them before every fallible step
        // has succeeded (`rmp` #955). Until then NOTHING of this transaction's bookkeeping is released:
        // not the active-set entry (`rmp` #866), not the linked undo deltas, not the freeze-frontier
        // savepoint. That is what keeps a FAILED commit recoverable: the transaction is still, in every
        // respect the store can be asked about, an open writer holding uncommitted state, so
        // [`uncommitted_data_writer`](Self::uncommitted_data_writer) keeps naming it (the `rmp` #902
        // constraint-DDL guard stays fail-CLOSED) and a subsequent [`rollback`](Self::rollback)
        // withdraws exactly its own effect.
        //
        // Releasing a label writer's bookkeeping here — as this did until #955, when labels were tracked
        // in a separate list — broke both halves. A transaction whose ONLY uncommitted mutation is a
        // label change (`MATCH (n) SET n:L`, which writes the label word in place and creates no record)
        // vanished from `uncommitted_data_writer` the instant its commit was attempted, so a
        // `CREATE CONSTRAINT` racing a failed commit was ADMITTED over uncommitted data. Since `rmp`
        // #968 a label change links an undo delta, so `undo_links` names such a writer for exactly as
        // long as a property-only writer is named, and the two halves are one mechanism.
        //
        // `committed_statistics(txn)` excludes the committing transaction BY NAME rather than by it
        // having already been removed, so the checkpoint below still persists its counts and DDL. The
        // rest of the per-txn created/expired bookkeeping fed the old eager settle loop and is dead once
        // the commit-registry entry exists; it is dropped with the entry.

        // Read-only fast path (`rmp` #529): a transaction that changed nothing durable — and is not a
        // GC pass with a scheduled Active/Recent-Transaction-Table prune to apply — has nothing to
        // persist. Skip the catalog checkpoint, the WAL `COMMIT` record and the group-commit
        // `fdatasync` entirely: it produced no version, so no on-disk in-flight stamp bears its `TxnId`
        // (no `commit_registry` entry is needed — no reader/GC will ever resolve it), and its bumped
        // `commit_ts` is intentionally NOT made durable. After a crash that `commit_ts` is simply
        // reissued, which is harmless precisely because the transaction produced no versions (nothing on
        // disk references it). ALL in-memory bookkeeping the coordinator relies on is preserved: the
        // commit-ts oracle advanced above (so [`snapshot_ts`](Self::snapshot_ts) returns this
        // transaction's timestamp for the coordinator's `ssi.record_commit`), and the GC watermark
        // (`oldest_active_snapshot`) is a coordinator-level concern.
        // `commit_ts_hw` monotonicity across a later rollback's `reload_catalog` is preserved by that
        // method taking `max` (a read-only bump is not durable, so the persisted catalog lags it).
        let is_gc_prune = self
            .pending_gc_prune
            .as_ref()
            .is_some_and(|p| p.gc_txn == txn);
        if !wrote_durable && !self.catalog_dirty && !is_gc_prune {
            // Nothing fallible remains, so the bookkeeping can go (`rmp` #866 / #955). A transaction on
            // this path wrote no record, so its count delta is empty and there is nothing to withdraw.
            debug_assert!(
                self.active.get(&txn).is_none_or(|a| a.counts.is_empty()),
                "the `rmp` #529 read-only fast path must never hold a count delta: a counter mutation \
                 implies a record write, which implies WAL activity"
            );
            self.settle_committed_txn(txn, commit_ts);
            return Ok(None);
        }

        // THE COMMIT INDIRECTION POINT (`04 §5.1.3`, `rmp` #966). Publish `txn`'s commit timestamp
        // into its commit slot — one write that commits every delta it created — before the catalog
        // checkpoint and the `COMMIT` record, so it is covered by this transaction's own WAL frames
        // and by the same `fdatasync`. A transaction that created no delta owns no slot and this is a
        // no-op. It is fallible, so it sits INSIDE the fallible section: a failure here leaves `txn` a
        // fully-formed open writer whose slot still carries its in-flight stamp, i.e. uncommitted,
        // which is exactly what a subsequent rollback expects to find (`rmp` #955).
        debug_assert!(
            wrote_durable
                || self
                    .active
                    .get(&txn)
                    .is_none_or(|a| a.commit_slot.is_none()),
            "a transaction that owns a commit slot has written a record, so it must be WAL-active"
        );
        self.checkpoint_meta(txn, false)?;
        // PUBLISH THE COMMIT SLOT LAST among the fallible steps (`rmp` #968), and immediately before
        // the WAL `COMMIT` record — which it must still precede, so recovery replays it as part of the
        // committed transaction.
        //
        // Order matters because the slot is a SECOND visibility oracle. A record header's in-flight
        // stamp is resolved through the commit registry, which is published only once every fallible
        // step has succeeded; a delta's status is resolved through this slot. Published before
        // `checkpoint_meta`, a failure in `checkpoint_meta` left the two disagreeing: the registry
        // still said "in flight" while the slot already said `Committed(commit_ts)`, so any reader
        // resolving through the chain saw an uncommitted transaction's change as committed — while
        // the comment above promised exactly the opposite ("a failure here leaves `txn` a
        // fully-formed open writer whose slot still carries its in-flight stamp"). The window existed
        // from `rmp` #967, when deltas first carried a value; #968 made it observable, because a
        // label change — unlike a property overwrite by the same failing writer — is read by
        // `label_bitmap_at` on a node every snapshot can see.
        self.publish_commit_slot(txn, commit_ts)?;
        // PREPARE: append the `COMMIT` record with NO `fdatasync` (the group-commit deferral, `rmp`
        // #528). The caller hardens the whole batch with a single `harden_wal`.
        let commit_lsn = self.wal.with(|w| w.commit_at_no_sync(txn, commit_ts))?;
        // COMMIT SETTLED. Every fallible step has succeeded, so — and not one line earlier — this
        // transaction becomes committed-visible and its bookkeeping is released.
        //
        // The registry entry is PUBLISHED here rather than before `checkpoint_meta` (`rmp` #955). It is
        // what resolves an in-flight `xmin`/`xmax` stamp, and every record this transaction wrote still
        // carries one, so writing it earlier meant that a `checkpoint_meta` failure left the whole
        // uncommitted write set resolving as `Committed(commit_ts)` — a dirty read of data the caller
        // is about to roll back, and a permanent one if that rollback also fails. Publishing it after
        // the last fallible step makes the absence of an entry (which
        // [`CommitRegistry::outcome`](graphus_txn::CommitRegistry::outcome) reads as `Aborted`) the
        // fail-safe answer for exactly the window where the outcome is not yet decided.
        //
        // It is published BEFORE the label settle below, not after: between the two, a concurrent
        // reader resolves an `InFlight(txn)` label version through the registry and gets
        // `Committed(commit_ts)` — the same answer the settle then writes down. The reverse order would
        // open a window in which a settled label version read as committed while the record headers of
        // the same transaction still read as aborted.
        self.commit_registry.record_commit(txn, commit_ts);
        // Releases the active-set entry — and with it this transaction's count delta and schema undo log
        // (`rmp` #866). This must happen before `open_txn_holds_pending_ddl()` below, which asks whether
        // any *other* open transaction still holds unpersisted DDL and would otherwise count this one's.
        self.settle_committed_txn(txn, commit_ts);
        // `rmp` #813: record this durable write's `(commit_lsn, commit_ts)` so a read transaction's causal
        // bookmark can advance to it — but ONLY once the deferred harden makes `commit_lsn` durable. The
        // pair is drained into `durable_write_commit_ts_hw` at the next harden (or lazily on a read of the
        // watermark), so a read never surfaces a not-yet-`fdatasync`'d write's timestamp. A read-only
        // commit returned early above (the `rmp` #529 fast path) and so never reaches this push.
        self.pending_write_commits
            .push_back((commit_lsn, commit_ts));
        // The catalog (any pending token intern / index / histogram / constraint change) will be durable
        // once this commit record's `fdatasync` (the deferred `harden_wal`) completes, so the next
        // read-only commit may safely take its fast path (`rmp` #529). Cleared here (before the deferred
        // harden) is sound: the only harden failure is a PANIC (fsyncgate), after which this flag is moot.
        //
        // ...UNLESS another open transaction still holds pending schema DDL (`rmp` #734). The checkpoint
        // above deliberately did NOT persist that DDL (`committed_statistics`), so the catalog still has
        // un-persisted schema state and the flag must stay set — otherwise that transaction's own commit
        // would take the #529 fast path and silently drop its committed DDL, which is precisely the
        // silent-drop `rmp` #534 was written to prevent, arriving through the commit path instead of the
        // rollback path.
        self.catalog_dirty = self.open_txn_holds_pending_ddl();
        // Remember this commit record's LSN until a GC freeze settles `txn`'s versions: WAL
        // reclamation must keep it readable so a crash can still resolve an unfrozen in-flight stamp
        // (`rmp` #114 / the lazy freeze of #49/#59). This only ever LOWERS the reclaim floor, and reclaim
        // runs only in the post-harden `maybe_checkpoint`, so setting it pre-harden advances no watermark.
        self.unfrozen_commit_lsn.insert(txn, commit_lsn);
        // If `txn` was a GC pass, its header freeze is durable once the deferred harden completes (`rmp`
        // task #59): every writer the pass scheduled is no longer referenced by any on-disk in-flight
        // stamp, so the Active/Recent Transaction Table entries can be forgotten — this bounds the table.
        // A crash before the harden loses this GC commit record, and recovery rebuilds the table from the
        // still-durable writer commit records, so pruning here (pre-harden) cannot lose a needed entry.
        if is_gc_prune {
            let pending = self
                .pending_gc_prune
                .take()
                .expect("is_gc_prune ⇒ Some(gc_txn == txn)");
            for writer in pending.writers {
                self.commit_registry.forget(writer);
                // The writer's versions are now frozen (commit-ts stamps on disk): its commit record
                // is no longer needed to resolve any stamp, so it stops flooring WAL reclamation.
                self.unfrozen_commit_lsn.remove(&writer);
            }
        }
        Ok(Some(commit_lsn))
    }

    /// Releases `txn`'s per-transaction bookkeeping now that its commit is **settled** (`rmp` #955).
    ///
    /// Every step here is infallible, and that is the point: [`commit_prepare`](Self::commit_prepare)
    /// calls it at each of its two exits and at neither of them before the last fallible step has
    /// succeeded. While a commit is still in doubt the transaction must stay, in every respect the
    /// store can be asked about, an open writer holding uncommitted state — otherwise a failed commit
    /// leaves mutations that are physically present but attributable to nobody.
    ///
    /// It does three things, in this order:
    ///
    /// 1. **Settles the retained label versions** from the in-flight stamp to `Committed(commit_ts)`
    ///    (`rmp` #767). Unlike the record headers — settled lazily at GC time because doing it eagerly
    ///    was `O(records)` WAL-logged page writes — this history is small and purely in-memory, so
    ///    settling now is free and logs nothing. It is REQUIRED, not an optimisation: a raw in-flight
    ///    stamp is only resolvable while the [`CommitRegistry`] still holds `txn`, and a GC pass
    ///    FORGETS committed writers from that registry once their headers are frozen. After that the
    ///    registry maps the unknown id to `Aborted`, so the version would read as never-committed and
    ///    every reader would fall back to the PRE-CHANGE bitmap — a committed label change silently
    ///    reverting in memory, healed only by a restart.
    /// 2. **Clears the GC freeze-frontier savepoint** (`rmp` #522). This GC pass is committing, so its
    ///    freeze-frontier advance is permanent and the rollback savepoint is no longer needed. A no-op
    ///    for any transaction that is not the in-progress GC pass.
    /// 3. **Removes the active-set entry**, and with it the count delta (`rmp` #866) and the schema
    ///    undo log (`rmp` #734) a rollback would otherwise have withdrawn.
    fn settle_committed_txn(&mut self, txn: TxnId, _commit_ts: Timestamp) {
        if self
            .gc_freeze_low_savepoint
            .is_some_and(|(sp_txn, _)| sp_txn == txn)
        {
            self.gc_freeze_low_savepoint = None;
        }
        self.active.remove(&txn);
    }

    /// Group-commit **HARDEN** (phase 2, `04 §4.2` / `rmp` #528): `fdatasync`s the WAL, making every
    /// record appended by the [`commit_prepare`](Self::commit_prepare)s since the last harden durable in
    /// ONE sync — the whole batch of concurrent committers. Call after the last PREPARE and **before**
    /// acknowledging any of the batch's committers (the ack-after-fsync rule).
    ///
    /// A no-op syscall when the sink's pending buffer is empty (e.g. a batch of only read-only commits
    /// appended nothing — the production [`FileLogSink`](graphus_wal::FileLogSink) skips the real
    /// `fdatasync`), so a read-only batch costs zero real syncs.
    ///
    /// # Panics
    /// Panics (controlled abort) if the durability `fdatasync` fails (`04 §4.9`, fsyncgate).
    pub fn harden_wal(&mut self) {
        self.wal.with(|w| w.flush());
        // `rmp` #813: the flush hardened every PREPAREd `COMMIT` record, so promote their write commit
        // timestamps into the durable-write bookmark high-water (a no-op for a read-only batch, whose
        // queue is empty).
        self.advance_durable_write_watermark();
    }

    /// Group-commit **HARDEN — PREPARE half** of a *pipelined* commit (`rmp` #532): writes every
    /// PREPAREd record to the WAL backing store (advancing its write frontier) and returns the
    /// deferred [`FsyncJob`](graphus_wal::FsyncJob), WITHOUT `fdatasync`ing. The engine hands the job
    /// to a dedicated fsync thread, overlaps the sync with preparing the next batch, then calls
    /// [`complete_harden_wal`](Self::complete_harden_wal) with the job's `target_len` after the job
    /// runs — the two-phase split of [`harden_wal`](Self::harden_wal).
    ///
    /// # WAL-before-data
    /// Between this call and its paired `complete_harden_wal`, the WAL has `durable_len < written_len`.
    /// The buffer pool shares **the same** [`WalManager`] via [`SharedWal`](crate::SharedWal) (the
    /// pool's `WalRule` and this store are clones over one `Arc<Mutex<WalManager>>`), so an eviction's
    /// `ensure_durable` during the overlap re-enters that manager under the same lock and hardens the
    /// written-but-un-synced range inline — a home page is never written over an un-synced WAL record.
    ///
    /// # Panics
    /// Panics (controlled abort, fsyncgate `04 §4.9`) if writing the records to the backing store
    /// fails — an unrecoverable I/O error, exactly like a failed `fdatasync`.
    pub fn begin_harden_wal(&mut self) -> graphus_wal::FsyncJob {
        self.wal.with(|w| {
            w.begin_harden().unwrap_or_else(|e| {
                panic!(
                    "WAL begin_harden write failed; aborting to avoid silent data loss (fsyncgate): {e}"
                )
            })
        })
    }

    /// Group-commit **HARDEN — COMPLETE half** of a pipelined commit (`rmp` #532): advances the WAL
    /// durable watermark to `target_len` (the `FsyncJob::target_len` of the job returned by
    /// [`begin_harden_wal`](Self::begin_harden_wal)) after that job's `fdatasync` has run. Monotonic,
    /// so it composes with an eviction's inline hardening during the overlap. Call **before**
    /// acknowledging any committer whose record the job covered (ack-after-fsync).
    pub fn complete_harden_wal(&mut self, target_len: u64) {
        self.wal.with(|w| w.complete_harden(target_len));
        // `rmp` #813: advance the durable-write bookmark high-water for every PREPAREd write this job just
        // hardened (its `commit_lsn <= target_len`, now that `durable_len` reached it).
        self.advance_durable_write_watermark();
    }

    /// Runs the redo-bounding auto-checkpoint if enough WAL has accumulated since the last one (`rmp`
    /// storage audit F3), a no-op otherwise. Exposed so the engine's group-commit path can take it
    /// **once per drained batch**, after the batch's committers have been acknowledged (their commits
    /// are already durable — a checkpoint only bounds later recovery redo, never their durability).
    ///
    /// # Errors
    /// Returns a storage error if flushing the dirty pages or syncing the device fails.
    pub fn checkpoint_if_due(&mut self) -> Result<()> {
        self.maybe_checkpoint()
    }

    /// Overrides the automatic-checkpoint cadence (WAL bytes between checkpoints). `0` disables it
    /// (manual [`checkpoint`](Self::checkpoint) only). See [`DEFAULT_CHECKPOINT_INTERVAL_BYTES`].
    pub fn set_checkpoint_interval_bytes(&mut self, bytes: u64) {
        self.checkpoint_interval_bytes = bytes;
    }

    /// Takes a **checkpoint** (`04 §4.7`, `rmp` storage audit F3), bounding crash-recovery redo to
    /// the work logged since the previous checkpoint instead of replaying the whole history.
    ///
    /// This is a **sharp** checkpoint: it first flushes every dirty page home (each write-back
    /// enforces the WAL rule, so the log is durable through the page's `page_lsn` before the page
    /// lands) and syncs the device, so **every change logged so far is durable on its data page**.
    /// It then appends a `CHECKPOINT-END` with an empty Dirty Page Table and hardens it. Because the
    /// flush made everything prior durable, recovery's redo can begin at this checkpoint's LSN (see
    /// [`graphus_wal::recover`]) — nothing before it needs replay.
    ///
    /// Physical reclamation of the now-redundant WAL prefix (bounding **disk** and the analysis
    /// scan) is the separate follow-up to this redo-bounding step.
    ///
    /// # Errors
    /// Returns a storage error if flushing the dirty pages or syncing the device fails.
    ///
    /// # Panics
    /// Panics if the checkpoint `fdatasync` fails (`04 §4.9`), inherited from
    /// [`WalManager::checkpoint`].
    pub fn checkpoint(&mut self) -> Result<()> {
        // Sharp checkpoint: make every logged change durable on its data page (WAL-before-data is
        // enforced per page inside the flush), then mark the clean point in the log. When a
        // doublewrite buffer is attached (`rmp` #384) the home flush is routed through it, so a torn
        // home write during the checkpoint is repairable from the DWB copy on the next open; without
        // one it is the historical bare `flush_all`. `flush` selects the right path.
        self.flush()?;
        // Reclaim the WAL prefix that recovery no longer needs (`rmp` #114): below the checkpoint
        // (redo floor — everything before is flushed) AND below the oldest unfrozen committed
        // transaction's commit record (so an unfrozen in-flight stamp stays resolvable). The WAL
        // additionally clamps to the oldest active transaction's first record (loser undo).
        let oldest_unfrozen = self.unfrozen_commit_lsn.values().map(|l| l.0).min();
        // Compute the EXACT reclaim floor here (the same clamp `reclaim` applies, including the WAL's
        // oldest-active-first-lsn), so the doublewrite floor we persist below matches the WAL prefix
        // about to be dropped.
        let (ckpt_lsn, reclaim_floor) = self.wal.with(|w| {
            let ckpt_lsn = w.checkpoint(&[]);
            let floor = oldest_unfrozen.map_or(ckpt_lsn.0, |u| ckpt_lsn.0.min(u));
            let floor = w
                .oldest_active_first_lsn()
                .map_or(floor, |oldest| floor.min(oldest.0));
            (ckpt_lsn, floor)
        });
        let _ = ckpt_lsn;
        // DOUBLEWRITE FLOOR (`rmp` #437): persist the reclaim floor durably in the DWB **before** the
        // WAL prefix below it is reclaimed. On the next open, eviction-ring recovery ignores any ring
        // slot whose staged `page_lsn` is below this floor (provably superseded by a flushed home
        // page), so a stale ring slot can never restore an older committed image over a torn newer
        // home page once the redo records that would have rolled it forward are gone. Ordering is the
        // crux: the floor is durable (write + sync of the DWB batch header inside `set_floor`) before
        // `reclaim` drops the records — so a crash between the two leaves either the old floor + the
        // not-yet-reclaimed WAL (safe) or the new floor + the reclaimed WAL (safe). The floor is
        // monotonic inside `set_floor`. No per-eviction fsync is added (the #431 convoy property is
        // preserved): this is one extra header fsync **per checkpoint**, on the checkpoint thread.
        if let Some(dwb) = self.dwb.as_ref() {
            let dwb = Arc::clone(dwb);
            let mut guard = dwb
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.set_floor(Lsn(reclaim_floor))?;
        }
        // Now reclaim the WAL prefix below the (now durable) floor.
        self.wal
            .with(|w| -> Result<()> { w.reclaim(Lsn(reclaim_floor)) })?;
        self.wal_len_at_last_checkpoint = self.wal.with(|w| w.durable_len());
        // Re-size the WAL segment seal threshold to the current store (`rmp` #706), so as the data image
        // grows or shrinks the reclaim granularity tracks it — a segment always seals well within one
        // maintenance interval, so the NEXT checkpoint has sealed segments below the floor to free.
        self.apply_adaptive_wal_segment_target();
        Ok(())
    }

    /// Sizes the WAL's segment seal threshold proportionally to the live store (`rmp` #706), so a small
    /// database's WAL is reclaimed in small chunks (via [`graphus_wal::segment_target_for_store`])
    /// instead of only in fixed 64 MiB units. A no-op when adaptive sizing is disabled
    /// ([`set_wal_segment_sizing_adaptive`](Self::set_wal_segment_sizing_adaptive)) or on a non-segmented
    /// WAL sink (e.g. the in-memory DST sink, which frees exact byte ranges).
    ///
    /// Called at [`create`](Self::create) / [`open`](Self::open) (so a store immediately uses a segment
    /// size matched to its data image) and on every [`checkpoint`](Self::checkpoint) (so the size tracks
    /// the store as it grows/shrinks). The reclaim granularity thus stays proportional to the data image,
    /// matching the store-proportional maintenance CADENCE `rmp` #556 already established. It only affects
    /// FUTURE segment rolls, never any already-written segment, so it is durability-neutral.
    fn apply_adaptive_wal_segment_target(&mut self) {
        if !self.wal_segment_sizing_adaptive {
            return;
        }
        let store_bytes = self.store_page_count().saturating_mul(PAGE_SIZE as u64);
        let target = graphus_wal::segment_target_for_store(store_bytes);
        self.wal.with(|w| w.set_segment_target(target));
    }

    /// Enables (default) or disables the store-proportional WAL segment sizing of `rmp` #706, then
    /// applies it immediately. When enabled the store seals WAL segments at
    /// [`graphus_wal::segment_target_for_store`] of its live data image; when disabled the WAL keeps
    /// whatever fixed segment size its sink was constructed with, reproducing the pre-#706
    /// fixed-64-MiB behaviour. The regression guard for #706 uses this to drive the reverted defect on a
    /// real file-backed WAL.
    pub fn set_wal_segment_sizing_adaptive(&mut self, adaptive: bool) {
        self.wal_segment_sizing_adaptive = adaptive;
        self.apply_adaptive_wal_segment_target();
    }

    /// Fires an automatic [`checkpoint`](Self::checkpoint) when `checkpoint_interval_bytes` of WAL
    /// have been appended since the last one (`0` disables the cadence). Called after each commit.
    fn maybe_checkpoint(&mut self) -> Result<()> {
        if self.checkpoint_interval_bytes == 0 {
            return Ok(());
        }
        let durable = self.wal.with(|w| w.durable_len());
        if durable.saturating_sub(self.wal_len_at_last_checkpoint) >= self.checkpoint_interval_bytes
        {
            self.checkpoint()?;
        }
        Ok(())
    }

    /// Issues the next strictly-monotonic commit timestamp (`04 §5.2`), advancing the durable
    /// high-water mark (persisted by the [`checkpoint_meta`](Self::checkpoint_meta) that follows in
    /// [`commit`](Self::commit)).
    ///
    /// # Panics
    /// Panics if the 63-bit timestamp space is exhausted (in practice unreachable; the assertion
    /// guards the version-stamp discriminant just like the transaction oracle's).
    fn next_commit_ts(&mut self) -> Timestamp {
        self.commit_ts_hw += 1;
        assert!(
            self.commit_ts_hw <= MAX_TIMESTAMP,
            "commit timestamp space exhausted (63-bit)"
        );
        Timestamp(self.commit_ts_hw)
    }

    /// Overwrites the 8-byte MVCC header word at `field_off` (one of [`MVCC_OFF_CREATED_TS`] /
    /// [`MVCC_OFF_EXPIRED_TS`]) of record `id` in `kind`'s store with `word`, as one WAL-logged
    /// update under `txn`. Used to stamp a tombstone (`xmax`) and to settle in-flight stamps at
    /// commit — both touch only the header word, never the record body.
    fn patch_header_word(
        &mut self,
        kind: StoreKind,
        id: u64,
        field_off: usize,
        word: u64,
        txn: TxnId,
    ) -> Result<()> {
        let (rel_page, off) = paging::record_location(id, kind.record_size());
        let dev = self.device_page(kind, rel_page)?;
        self.write_region(dev, off + field_off, &word.to_le_bytes(), txn)
    }

    /// Stamps the 8-byte MVCC header word at `field_off` of record `id` in `kind`'s store to
    /// `new_word` (redo = a plain post-image patch, so recovery redo repeats history byte-for-byte),
    /// but logs a **compare-and-set logical undo** (`rmp` #301, mirroring [`write_chain_head`] and the
    /// `rmp` #239 chain-pointer fix): the undo restores the pre-image `old_word` **only if the word is
    /// still `new_word`** — i.e. only if this transaction's write is still the one on the page. If a
    /// concurrently-interleaved transaction has since re-stamped the same header word, the undo
    /// no-ops, so a **non-LIFO** abort of this transaction never clobbers the newer stamp.
    ///
    /// This is the header-word twin of the free-list / high-water monotonic restores (`rmp` #578 /
    /// #220): a plain pre-image undo of a **shared** header word is unsafe under statement-granularity
    /// interleaving because a later writer can legitimately own the word by abort time; a plain undo
    /// would then resurrect a stale stamp (a lost-update / visibility breach). Used for the MVCC
    /// **tombstone** (`xmax = in_flight(txn)`) writes of [`delete_node`](Self::delete_node),
    /// [`delete_rel`](Self::delete_rel) and [`tombstone_props_for_key`](Self::tombstone_props_for_key).
    /// The GC-time freeze ([`freeze_store_headers`](Self::freeze_store_headers)) keeps the plain
    /// [`patch_header_word`](Self::patch_header_word): it runs only inside a GC pass that holds the
    /// store exclusively (no interleaving mutator), so its undo can never race a concurrent writer.
    fn patch_header_word_cas(
        &mut self,
        kind: StoreKind,
        id: u64,
        field_off: usize,
        new_word: u64,
        txn: TxnId,
    ) -> Result<()> {
        let (rel_page, off) = paging::record_location(id, kind.record_size());
        let dev = self.device_page(kind, rel_page)?;
        let abs = off + field_off;
        let f = self.pool.fetch(dev)?;
        // Capture the pre-image (`old_word`) under a read latch before the overwrite — the frame stays
        // pinned across the two sequential latches (`rmp` #337, Slice 1), exactly as `write_region` /
        // `write_chain_head` do.
        let old_word = self.pool.with_page(f, |p| {
            u64::from_le_bytes(p[abs..abs + 8].try_into().expect("8-byte slice"))
        });
        // Redo is a plain, unconditional post-image (byte-identical to `patch_header_word`'s redo, so
        // recovery redo is unchanged). Undo is the compare-and-set: reset to `old_word` iff the word is
        // still `new_word` (this txn's own stamp). Redo lent by borrow; undo retained by value.
        let redo = paging::encode_patch(abs, &new_word.to_le_bytes());
        let undo = paging::encode_cas_patch(abs, new_word, old_word).into_vec();
        let lsn = self
            .wal
            .with(|w| w.log_update_borrowed(txn, dev, &redo, undo));
        self.pool.with_page_mut_lsn(f, lsn, |p| {
            p[abs..abs + 8].copy_from_slice(&new_word.to_le_bytes());
        });
        self.pool.unpin(f);
        Ok(())
    }

    // ------------- chain-safe writes (logical-undo discipline, `rmp` #220 / #172) -------------
    //
    // Three writes participate in a graph chain and must NOT log a plain whole-record pre-image undo,
    // because under STATEMENT-granularity interleaving a concurrently-committed writer can prepend a
    // record on top of (or relink into) the very field this txn touched. A plain pre-image abort would
    // then clobber that committed structure. The fixes below replace the unsafe plain undos with the
    // logical compensations the surviving `paging`/recovery contract replays identically live and on
    // crash (`04 §4.1`):
    //
    //   * `write_chain_head`  — pushing a record onto a `first_rel`/`first_prop` head: undo is a
    //     compare-and-set ([`paging::encode_cas_patch`]) that resets the head to its old value ONLY if
    //     it is still this txn's pushed id (else a later writer owns the head — no-op).
    //   * `write_*_create`    — first write of a freshly-allocated rel/prop record: undo reverts ONLY
    //     the MVCC header (marks the slot not-in-use), PRESERVING the record body (its forward chain
    //     pointers). A surviving writer that prepended onto this record then threads THROUGH the dead
    //     record to its successor instead of having the chain severed by a body-zeroing undo.
    //   * `write_rel_field_keep` — a side write whose plain pre-image undo would also be unsafe (e.g.
    //     `relink_old_head` making the old head look like the chain head): logged with undo == redo,
    //     a no-op on abort; the GC corpse splice re-establishes the correct neighbour state. It writes
    //     ONLY the touched chain-pointer/flags fields, never the MVCC header — so an out-of-LIFO abort
    //     of two interleaved prependers cannot resurrect a neighbour record's in-use bit (`rmp` #239).

    /// Writes the 8-byte chain-head field at `field_off` of record `id` in `kind`'s store to
    /// `new_head`, logging a **compare-and-set logical undo** (`rmp` #220 / #172): redo installs
    /// `new_head`; undo resets the field to `old_head` *only if it still equals `new_head`*. This is
    /// the correct compensation for "push `new_head` onto the head" — it never clobbers a later
    /// committed writer that has since pushed on top (its push moved the head off `new_head`, so the
    /// CAS no-ops). Replays identically in live rollback (`PoolTarget`) and crash recovery
    /// (`DeviceTarget`) via [`paging::apply_patch`].
    fn write_chain_head(
        &mut self,
        kind: StoreKind,
        id: u64,
        field_off: usize,
        new_head: u64,
        old_head: u64,
        txn: TxnId,
    ) -> Result<()> {
        let (rel_page, off) = paging::record_location(id, kind.record_size());
        let dev = self.device_page(kind, rel_page)?;
        let abs = off + field_off;
        // CAS-undo framing is byte-identical (`rmp` #220 / #172 depend on the exact undo bytes): the
        // logical compare-and-set undo is still produced by `encode_cas_patch`; only the in-flight
        // buffer type changed to an inline `Patch`. Redo is lent by borrow, undo retained by value.
        let redo = paging::encode_patch(abs, &new_head.to_le_bytes());
        let undo = paging::encode_cas_patch(abs, new_head, old_head).into_vec();
        let f = self.pool.fetch(dev)?;
        let lsn = self
            .wal
            .with(|w| w.log_update_borrowed(txn, dev, &redo, undo));
        self.pool.with_page_mut_lsn(f, lsn, |p| {
            p[abs..abs + 8].copy_from_slice(&new_head.to_le_bytes());
        });
        self.pool.unpin(f);
        Ok(())
    }

    // ------------------- the undo area (`rmp` #966, `05 §12`, `04 §5.1`) -------------------
    //
    // `undo_ptr` is a chain head with exactly the shape of `first_rel` / `first_prop`: writers
    // PREPEND to it and never rewrite an already-linked delta. It therefore inherits the whole
    // chain-safety discipline established above, and for the same reasons:
    //
    //   * the head is published with `write_chain_head`, whose undo is a compare-and-set — an abort
    //     never clobbers a head a later writer legitimately owns;
    //   * a delta's first (and only) write uses a **header-only creation undo** that reverts just the
    //     `flags` byte, so an aborted delta becomes a *corpse* whose `next` is intact and a survivor
    //     that prepended on top still threads through it to its successor (`rmp` #220);
    //   * the publication ORDER is fixed and normative (`04 §5.1.2` step 3): the delta is written in
    //     full, with `next` already pointing at the current head, and the head is published LAST. A
    //     concurrent reader, or the GC, therefore observes either the old chain or the new one, never
    //     a partially-linked one.

    /// Reads the `undo.store` delta at physical id `id`.
    ///
    /// Returns `Ok(None)` for a slot that is entirely zero — never written — which is not a delta at
    /// all (`05 §12.3`: action `0` is reserved). Any other malformed slot is an error, never a
    /// plausible-looking delta. A *reclaimed* slot decodes normally with its `in_use` bit clear: like
    /// every other store here, freeing a slot clears the flag and leaves the body until the slot is
    /// reused, so the whole record need not be rewritten to free it.
    ///
    /// # Errors
    /// Returns a storage error if `id` is out of range, its page is unreadable, or the slot is
    /// occupied but does not decode.
    fn read_delta(&self, id: u64) -> Result<Option<UndoDelta>> {
        // `rmp` #967: one body, shared with the off-thread reader pool. The inline path and
        // `StoreReadView` MUST decode a delta through the same code, or the pool answers a property
        // read from a different mechanism than this path does — the #755/#768/#769/#770 family. The
        // record-read probe lives there for the same reason.
        read_view::read_delta(&self.pool, &self.stores, id)
    }

    /// Reads the `commit.store` slot at physical id `id`. `Ok(None)` for a zeroed slot, exactly as
    /// [`read_delta`](Self::read_delta).
    ///
    /// # Errors
    /// Returns a storage error if `id` is out of range, its page is unreadable, or the slot is
    /// occupied but does not decode.
    fn read_commit_slot(&self, id: u64) -> Result<Option<CommitSlot>> {
        // One body, shared with the off-thread reader pool — see [`read_delta`](Self::read_delta).
        read_view::read_commit_slot(&self.pool, &self.stores, id)
    }

    /// Returns a physical id for a fresh `undo.store` delta: a reclaimed id when one is available,
    /// otherwise the next id of this store's **slab**.
    ///
    /// The slab is the store-record form of Memgraph's `delta_container`
    /// (`/data/refsrc/memgraph/src/storage/v2/delta_container.hpp:57-60`): rather than allocating per
    /// delta, one page's worth of contiguous ids is claimed at a time and handed out by a counter
    /// increment. Reuse is still preferred over growth, so the store does not grow while reclaimed
    /// slots are available. See [`undo_slab`](Self#structfield.undo_slab).
    ///
    /// # Errors
    /// Returns a storage error if the slab cannot be refilled (id-space exhaustion, or a failure
    /// mapping the slab's page).
    fn alloc_undo_id(&mut self, txn: TxnId) -> Result<u64> {
        if let Some(id) = self.pop_free_id(StoreKind::Undo) {
            self.note_popped_id(txn, StoreKind::Undo, id);
            return Ok(id);
        }
        let (next, end) = match self.undo_slab {
            Some((next, end)) if next < end => (next, end),
            _ => self.refill_undo_slab(txn)?,
        };
        self.undo_slab = Some((next + 1, end));
        Ok(next)
    }

    /// Claims the rest of the current `undo.store` page as a fresh slab and returns its `[next, end)`
    /// range. The slab never crosses a page boundary, so a transaction's deltas cluster in one page:
    /// one dirty page and one WAL-patch target for the whole chain-writing burst.
    fn refill_undo_slab(&mut self, txn: TxnId) -> Result<(u64, u64)> {
        let rpp = paging::records_per_page(undo::UNDO_RECORD_SIZE) as u64;
        let first = self.store(StoreKind::Undo).alloc.high_water().max(1);
        let rel_page = first / rpp;
        // Fail closed rather than compute a wrapped range: a wrapped `end <= first` would make the
        // slab permanently empty and every refill a no-op, i.e. a livelock on a path that is supposed
        // to report exhaustion. `alloc_fresh` fails closed at the same ceiling for the same reason
        // (`rmp` #452).
        let end = rel_page
            .checked_add(1)
            .and_then(|p| p.checked_mul(rpp))
            .filter(|&end| end > first)
            .ok_or_else(|| {
                GraphusError::Storage(
                    "undo.store physical-id space is exhausted; no delta slab can be claimed"
                        .to_owned(),
                )
            })?;
        // Bump the allocator over the whole run BEFORE mapping the page, then un-bump on a mapping
        // failure — the same fail-closed discipline `alloc_id` uses, and for the same reason: the
        // catalog invariant `high_water <= addressable capacity` must hold the instant it can be
        // observed. No id in the run has been written, so re-handing them out later is safe.
        for _ in first..end {
            self.store_mut(StoreKind::Undo).alloc.alloc_fresh()?;
        }
        if let Err(e) = self.ensure_store_page(StoreKind::Undo, rel_page, txn) {
            self.store_mut(StoreKind::Undo).alloc = PhysicalAllocator::restore(first);
            return Err(e);
        }
        self.undo_slab = Some((first, end));
        Ok((first, end))
    }

    /// The `commit.store` slot of `txn`, allocating and writing it on first use (`04 §5.1.3`).
    ///
    /// The slot opens carrying `txn`'s **in-flight** version stamp, which is what makes an
    /// unpublished slot self-describing: a delta that resolves through it reads "still in flight",
    /// and after a crash a slot still carrying an in-flight stamp names a loser transaction
    /// (`05 §12.5`).
    ///
    /// # Errors
    /// Returns a storage error if the slot cannot be allocated or written.
    fn commit_slot_for(&mut self, txn: TxnId) -> Result<u64> {
        if let Some(id) = self.active.get(&txn).and_then(|a| a.commit_slot) {
            return Ok(id);
        }
        let id = self.alloc_id(StoreKind::Commit, txn)?;
        let mut buf = [0u8; undo::COMMIT_RECORD_SIZE];
        CommitSlot::open(txn.0, VersionStamp::in_flight(txn)).encode(&mut buf);
        // Header-only creation undo, as for a relationship/property record (`rmp` #220): an abort
        // clears the slot's `in_use` bit and leaves `txn_id` and the in-flight stamp in place, so a
        // delta that survived the abort as a corpse can still be attributed to the transaction that
        // failed to commit.
        self.write_undo_area_create(StoreKind::Commit, id, &buf, undo::COMMIT_OFF_FLAGS, txn)?;
        self.active.entry(txn).or_default().commit_slot = Some(id);
        Ok(id)
    }

    /// Prepends `delta` to entity `(kind, entity)`'s undo chain under `txn` and publishes it as the
    /// new chain head, returning the delta's physical id (`04 §5.1.2` steps 2–3).
    ///
    /// `delta`'s `commit_info` and `next` are filled in here — a caller supplies only the action and
    /// its payload, because the transaction owns the slot and the chain owns the link.
    ///
    /// # Errors
    /// Returns a storage error if the entity's header cannot be read, the delta cannot be allocated
    /// or written, or the chain head cannot be published.
    fn link_delta(
        &mut self,
        kind: StoreKind,
        entity: u64,
        mut delta: UndoDelta,
        txn: TxnId,
    ) -> Result<u64> {
        debug_assert!(
            kind.is_versioned(),
            "only a record carrying the `05 §7` MVCC header can anchor an undo chain"
        );
        let slot = self.commit_slot_for(txn)?;
        let head = self.read_mvcc(kind, entity)?.undo_ptr;
        // STEP 1 (`04 §5.1.2`), and it belongs HERE rather than in each caller. The read path's
        // early stop (`DeltaVerdict::Stop`) is the claim that commit timestamps never ascend down a
        // chain, and the only thing that makes that true is refusing to interleave two open
        // transactions' deltas on one chain. `link_delta` is the single door a delta passes through,
        // so guarding the door covers every writer — the property path, the deletion path
        // (`note_entity_deleted`), and everything sprint 96 adds after it — instead of relying on
        // each new writer to remember. Costs nothing on a fresh chain and reuses the `head` already
        // read above.
        self.ensure_chain_head_unheld(kind, entity, head, txn)?;
        let id = self.alloc_undo_id(txn)?;
        delta.flags = undo::FLAG_IN_USE;
        delta.commit_info = slot;
        delta.next = head;
        let mut buf = [0u8; undo::UNDO_RECORD_SIZE];
        delta.encode(&mut buf);
        // STEP 3, and its order is not negotiable: the delta is written IN FULL — `next` already
        // naming the current head — and only then is the head republished. Reversed, a reader or the
        // GC could observe an `undo_ptr` pointing at a slot that is not yet a valid delta.
        self.write_undo_area_create(StoreKind::Undo, id, &buf, undo::UNDO_OFF_FLAGS, txn)?;
        self.write_chain_head(kind, entity, MVCC_OFF_UNDO_PTR, id, head, txn)?;
        self.active
            .entry(txn)
            .or_default()
            .undo_links
            .push(UndoLink {
                kind,
                entity,
                delta: id,
            });
        // The chain just grew, so it becomes a candidate for the GC chain sweep (`rmp` #522's
        // pending-set design, applied to chains): the sweep iterates this set instead of scanning.
        self.pending_undo_chains.insert((kind as u8, entity));
        Ok(id)
    }

    /// First write of a freshly-allocated undo-area record, with the **header-only creation undo**
    /// (`rmp` #220): redo installs the whole record, undo reverts only the `flags` byte at
    /// `flags_off`. An aborted delta therefore keeps its `next`, and an aborted commit slot keeps its
    /// `txn_id` — both of which a survivor still has to be able to read.
    fn write_undo_area_create(
        &mut self,
        kind: StoreKind,
        id: u64,
        buf: &[u8],
        flags_off: usize,
        txn: TxnId,
    ) -> Result<()> {
        let (rel_page, off) = paging::record_location(id, kind.record_size());
        let dev = self.ensure_store_page(kind, rel_page, txn)?;
        let end = off + buf.len();
        let f = self.pool.fetch(dev)?;
        // Capture the one-byte flags pre-image under a read latch, strictly before the whole-record
        // post-image overwrite under the write latch (frame pinned across both, `rmp` #337).
        let undo_img = self
            .pool
            .with_page(f, |p| {
                paging::encode_patch(off + flags_off, &p[off + flags_off..off + flags_off + 1])
            })
            .into_vec();
        let redo = paging::encode_patch(off, buf);
        let lsn = self
            .wal
            .with(|w| w.log_update_borrowed(txn, dev, &redo, undo_img));
        self.pool.with_page_mut_lsn(f, lsn, |p| {
            p[off..end].copy_from_slice(buf);
        });
        self.pool.unpin(f);
        Ok(())
    }

    /// Patches one 8-byte word of commit slot `id` under `txn`, with a plain pre-image undo.
    ///
    /// A plain undo is correct here — and only here among the undo area's writes — because a commit
    /// slot is **private to one transaction**: no other writer ever touches it, so its pre-image can
    /// never go stale the way a shared chain head's can.
    fn patch_commit_slot_word(
        &mut self,
        id: u64,
        field_off: usize,
        word: u64,
        txn: TxnId,
    ) -> Result<()> {
        let (rel_page, off) = paging::record_location(id, undo::COMMIT_RECORD_SIZE);
        let dev = self.device_page(StoreKind::Commit, rel_page)?;
        self.write_region(dev, off + field_off, &word.to_le_bytes(), txn)
    }

    /// **The commit indirection point** (`04 §5.1.3`, `05 §12.4`): publishes `txn`'s commit into its
    /// commit slot, which commits **every one of its deltas at the same instant**.
    ///
    /// The write order is normative: `delta_count` first, `commit_ts` **last**. Until `commit_ts` is
    /// published no reader treats this transaction as committed, so the earlier write is never
    /// observable as a partial commit; publishing `commit_ts` last is what makes a reader see either
    /// the whole transaction or none of it — atomicity expressed in the data structure rather than
    /// reconstructed by a sweep.
    ///
    /// A no-op for a transaction that created no delta (it has no slot).
    ///
    /// # Errors
    /// Returns a storage error if either word cannot be written.
    fn publish_commit_slot(&mut self, txn: TxnId, commit_ts: Timestamp) -> Result<()> {
        let Some(active) = self.active.get(&txn) else {
            return Ok(());
        };
        let Some(slot) = active.commit_slot else {
            return Ok(());
        };
        let count = active.undo_links.len() as u64;
        self.patch_commit_slot_word(slot, undo::COMMIT_OFF_DELTA_COUNT, count, txn)?;
        self.patch_commit_slot_word(
            slot,
            undo::COMMIT_OFF_COMMIT_TS,
            VersionStamp::committed(commit_ts),
            txn,
        )?;
        Ok(())
    }

    /// Walks entity `(kind, entity)`'s undo chain newest-first, returning `(delta id, delta)` pairs.
    ///
    /// The walk threads through **corpse** deltas (an aborted transaction's, whose `in_use` bit its
    /// creation undo cleared) exactly as the incidence walk threads through a dead-link relationship
    /// corpse: their action is never applied, but their `next` is still the way to the older versions
    /// below them.
    ///
    /// # Errors
    /// Returns a storage error if a link dangles (points at a zeroed or out-of-range slot) or the
    /// chain fails to terminate within the store's id space — both of which are corruption, not
    /// states a healthy store can reach.
    fn undo_chain(&self, kind: StoreKind, entity: u64) -> Result<Vec<(u64, UndoDelta)>> {
        // One body, shared with the off-thread reader pool — see [`read_delta`](Self::read_delta).
        read_view::undo_chain(&self.pool, &self.stores, kind, entity)
    }

    /// Detaches entity `(kind, entity)`'s **whole** undo chain under `txn` and reclaims every delta on
    /// it, returning how many deltas were freed.
    ///
    /// Detaching before freeing is what keeps the chain valid at every instant: the head is set to
    /// `0` first — with the same compare-and-set undo its publication used — so nothing can reach a
    /// delta whose slot is about to be listed as free.
    ///
    /// # Errors
    /// Returns a storage error if the chain is malformed or a write fails.
    fn free_undo_chain(&mut self, kind: StoreKind, entity: u64, txn: TxnId) -> Result<usize> {
        let chain = self.undo_chain(kind, entity)?;
        if chain.is_empty() {
            return Ok(0);
        }
        let head = chain[0].0;
        self.write_chain_head(kind, entity, MVCC_OFF_UNDO_PTR, NULL_ID, head, txn)?;
        for &(id, delta) in &chain {
            self.free_delta(id, delta, txn)?;
        }
        // The candidate entry is deliberately LEFT in `pending_undo_chains`. Dropping it here would be
        // wrong if this transaction later rolls back — the WAL undo restores the chain, but nothing
        // would restore the candidate, so the chain would go unswept until the next post-open full
        // scan. The next pass reads an empty chain and drops the entry then, which is self-healing
        // under both outcomes and costs one header read.
        Ok(chain.len())
    }

    /// Reclaims one unreachable delta: frees the `strings.store` overflow chain it owns (if any),
    /// clears its `in_use` bit, releases its hold on its commit slot, and returns its id to the free
    /// list.
    ///
    /// Only the flag byte is written, not the whole record — the same discipline every other store
    /// uses when it frees a slot (the body survives until the slot is reused), and one 1-byte WAL
    /// patch instead of 56.
    ///
    /// # The overflow chain, and the one gate that must never be removed
    ///
    /// After `rmp` #967 a live [`SetProperty`](UndoAction::SetProperty) delta is the **sole owner**
    /// of the old value's overflow chain: the cell stopped naming it the moment the new value was
    /// written in place, and exactly one record names any `strings.store` head (the consistency
    /// checker enforces that —
    /// [`HeapChainFault::AliasedBetweenCellAndDelta`](crate::check::HeapChainFault::AliasedBetweenCellAndDelta)).
    /// So freeing the delta must free the chain, or the blocks leak for the life of the store.
    ///
    /// **But only if the delta is live.** A `!in_use` delta is a *corpse* — an aborting transaction's,
    /// whose creation undo cleared the flag while preserving the body. Its transaction's WAL rollback
    /// already restored the pre-image of the cell, so the chain the corpse still names is the one the
    /// **live cell** owns again. Freeing it here would hand those blocks to the free list while a
    /// live property still reads through them: silent corruption, surfacing later as one property's
    /// value appearing inside another's. [`delta_is_dead`](Self::delta_is_dead) returns `true` for a
    /// corpse, so [`free_undo_chain`](Self::free_undo_chain) *does* reach this line with one. The
    /// `in_use()` gate is the whole defence, and
    /// `tests/property_undo_chain_967.rs::the_corpse_delta_of_an_aborted_overwrite_never_frees_the_restored_chain`
    /// is what keeps it here.
    fn free_delta(&mut self, id: u64, delta: UndoDelta, txn: TxnId) -> Result<()> {
        if delta.in_use()
            && delta.action == UndoAction::SetProperty
            && delta.type_tag & valenc::OVERFLOW_BIT != 0
            && delta.value_inline != NULL_ID
        {
            self.free_chain(txn, delta.value_inline)?;
        }
        let (rel_page, off) = paging::record_location(id, undo::UNDO_RECORD_SIZE);
        let dev = self.device_page(StoreKind::Undo, rel_page)?;
        self.write_region(dev, off + undo::UNDO_OFF_FLAGS, &[0u8], txn)?;
        self.release_commit_slot(delta.commit_info, txn)?;
        self.free_push(StoreKind::Undo, id, txn);
        Ok(())
    }

    /// Decrements commit slot `slot`'s `delta_count` for one reclaimed delta and frees the slot when
    /// the count reaches zero (`05 §12.4`).
    ///
    /// The invariant this maintains is that **a slot outlives its last delta**: no delta may ever
    /// refer to a freed or reused slot, because a delta's committed-ness is only knowable through it.
    /// An **aborted** transaction's slot never carries a count (it never committed), so it is left
    /// alone here and reclaimed by the orphan sweep once nothing names it.
    fn release_commit_slot(&mut self, slot: u64, txn: TxnId) -> Result<()> {
        let Some(rec) = self.read_commit_slot(slot)? else {
            return Ok(());
        };
        if !rec.in_use() {
            // A corpse slot: its transaction aborted, so there is no count to decrement. Whether it is
            // still named by another corpse delta is a question only a reference sweep can answer.
            self.undo_orphan_slots_possible = true;
            return Ok(());
        }
        let remaining = rec.delta_count.saturating_sub(1);
        self.patch_commit_slot_word(slot, undo::COMMIT_OFF_DELTA_COUNT, remaining, txn)?;
        if remaining == 0 {
            let (rel_page, off) = paging::record_location(slot, undo::COMMIT_RECORD_SIZE);
            let dev = self.device_page(StoreKind::Commit, rel_page)?;
            self.write_region(dev, off + undo::COMMIT_OFF_FLAGS, &[0u8], txn)?;
            self.free_push(StoreKind::Commit, slot, txn);
        }
        Ok(())
    }

    /// **The write-conflict check** (`D-property-write-conflict`, ratified 2026-08-03): refuses a
    /// property write on `(kind, entity)` while another **still-open** transaction holds that
    /// entity's undo chain.
    ///
    /// The head of an entity's chain names the last transaction to have written it. If that
    /// transaction is still open, letting a second writer prepend on top would interleave two
    /// transactions' deltas on one chain — and then their commit timestamps can end up **ascending**
    /// down the chain, because commit order is not link order. The read path's `Stop` rule
    /// ([`DeltaVerdict::Stop`](crate::scan_polarity::DeltaVerdict)) is precisely the claim that they
    /// cannot: it ends the walk at the first delta the snapshot already reflects, which is only sound
    /// if everything below committed no later. So this check is not a nicety layered on top of the
    /// read path — it is the read path's precondition.
    ///
    /// The granularity is the **entity**, not the property, matching Memgraph's `PrepareForWrite`
    /// (`/data/refsrc/memgraph/src/storage/v2/mvcc.hpp`, read 2026-08-03), which every mutating
    /// accessor calls before linking its delta. The Cypher seam already imposed exactly this rule
    /// keyed on the node id (`RecordGraph::set_node_property` → `note_write`), so the coordinated
    /// path's behaviour is unchanged; what becomes newly constrained is the direct `RecordStore`
    /// caller.
    ///
    /// Uses [`is_txn_active`](Self::is_txn_active) and **never**
    /// `CommitRegistry::outcome(w) == InFlight`, which is documented on that method as dead — always
    /// `false` — and has already caused two silent-data-loss defects (`rmp` #522, #778).
    ///
    /// # It is also what makes the in-place cell undo exact
    ///
    /// [`write_prop_cell`](Self::write_prop_cell) logs a **plain pre-image** undo of the cell region,
    /// which is only correct if no other transaction can rewrite that region between the write and
    /// the abort. Four things have to hold, and each was verified in the code rather than assumed:
    ///
    /// 1. **No concurrent property writer.** This check: while `W` holds the entity, every other
    ///    transaction's property write on it is refused.
    /// 2. **The freeze sweep will not touch it.**
    ///    [`freeze_store_headers_incremental`](Self::freeze_store_headers_incremental) rewrites only
    ///    stamps that [`frozen_word`](Self::frozen_word) resolves to a **committed** writer;
    ///    `W` is unresolved, so its `created_ts` is skipped.
    /// 3. **GC will not reclaim the cell.** [`gc_property_chain`](Self::gc_property_chain) requires
    ///    the owner's `undo_ptr == 0`, and `W`'s open delta is on that chain, so the head is non-zero.
    /// 4. **The whole chain will not be freed.** [`free_property_chain`](Self::free_property_chain)
    ///    runs only from [`reclaim_node`](Self::reclaim_node) / [`reclaim_rel`](Self::reclaim_rel),
    ///    which need the owner tombstoned **and** committed at or below the GC watermark — and `W`
    ///    holds the entity, so nothing tombstoned it.
    ///
    /// # Errors
    /// Returns [`GraphusError::Transaction`] — a **retriable serialization failure** — when the chain
    /// head belongs to another open transaction, and a storage error if the chain head dangles.
    fn ensure_no_conflicting_writer(&self, kind: StoreKind, entity: u64, txn: TxnId) -> Result<()> {
        let head = self.read_mvcc(kind, entity)?.undo_ptr;
        self.ensure_chain_head_unheld(kind, entity, head, txn)
    }

    /// [`ensure_no_conflicting_writer`](Self::ensure_no_conflicting_writer) for a caller that has
    /// **already read** the chain head, so the check costs no redundant header read (`rmp` #968).
    ///
    /// This is the form [`link_delta`](Self::link_delta) uses, and using it there is what turns the
    /// check from a property-path convention into a **structural** guarantee: `link_delta` is the one
    /// door through which a delta reaches a chain, so guarding it covers every delta writer by
    /// construction rather than by each one remembering to ask.
    ///
    /// # Errors
    /// As [`ensure_no_conflicting_writer`](Self::ensure_no_conflicting_writer).
    fn ensure_chain_head_unheld(
        &self,
        kind: StoreKind,
        entity: u64,
        head: u64,
        txn: TxnId,
    ) -> Result<()> {
        if head == NULL_ID {
            return Ok(());
        }
        let Some(delta) = self.read_delta(head)? else {
            // A chain head that names a zeroed slot is corruption, not a state to be tolerated:
            // fail closed rather than proceed as if the entity were unheld.
            return Err(GraphusError::Storage(format!(
                "undo chain of {kind:?} {entity} reaches empty delta slot {head}"
            )));
        };
        if !delta.in_use() {
            // A corpse head: its transaction aborted, so it holds nothing.
            return Ok(());
        }
        let Some(slot) = self.read_commit_slot(delta.commit_info)? else {
            return Err(GraphusError::Storage(format!(
                "undo delta {head} names commit slot {} which holds no record (`05 §12.4`)",
                delta.commit_info
            )));
        };
        if let Some(holder) = crate::scan_polarity::open_writer_of(slot)
            && holder != txn
            && self.is_txn_active(holder)
        {
            return Err(GraphusError::Transaction(format!(
                "write-write conflict: {kind:?} {entity} held by transaction {}; retry \
                 (serialization failure)",
                holder.0
            )));
        }
        Ok(())
    }

    /// Links the [`UndoAction::SetProperty`] delta that records one property write on
    /// `(kind, entity)`, carrying the value the key held **before** it (`05 §12.3`).
    ///
    /// The delta anchors on the **owning node or relationship**, never on the `props.store` cell:
    /// a cell is the entity's current value for a key, not a versioned entity of its own, and its
    /// `undo_ptr` stays `0` forever (the consistency checker enforces that —
    /// [`UndoChainFault::PropertyCellAnchorsChain`](crate::check::UndoChainFault)). The debug
    /// assertion below is the near-miss guard: [`StoreKind::is_versioned`] answers `true` for `Prop`
    /// as well, so `link_delta(StoreKind::Prop, …)` would compile and silently build a second,
    /// parallel chain family that nothing reads.
    ///
    /// `old_type_tag` of [`undo::TYPE_TAG_ABSENT`] with a zero `old_value` is the **"the key was
    /// absent"** encoding, which is what makes an added key invisible to an older snapshot. It is not
    /// optional: after `D-property-visibility` the cell's own stamp decides nothing, so without this
    /// delta an older snapshot would read a key that a still-open transaction had just added.
    ///
    /// A no-op for the reserved [`SYSTEM_TXN`], which writes only the catalog, is never rolled back,
    /// and has no [`VersionStamp`] form — exactly as [`note_entity_deleted`](Self::note_entity_deleted).
    ///
    /// # Errors
    /// Returns a storage error if the delta cannot be allocated, written, or linked.
    /// Links one delta per label bit `txn` is changing on node `id`, carrying the membership the node
    /// held **before** the change (`rmp` #968, `05 §12.3`).
    ///
    /// A delta records the **inverse** of the event, exactly as `DeleteObject` records a creation:
    /// adding a label writes [`UndoAction::RemoveLabel`], removing one writes
    /// [`UndoAction::AddLabel`]. This is Memgraph's shape — `ADD_LABEL` and `REMOVE_LABEL` are delta
    /// actions like any other (`/data/refsrc/memgraph/src/storage/v2/delta.hpp`) — and it is what
    /// retires `LabelHistory`: the previous membership stops living in an in-process map that a
    /// restart loses and becomes a durable version on the same chain as everything else.
    ///
    /// One delta **per changed bit**, not one per word, because a delta's payload is a single `token`
    /// (`05 §12.2` froze the record at 56 bytes with no room for a bitmap) and because per-bit is the
    /// granularity a reader needs anyway: replaying a bit flip is idempotent and order-independent
    /// within one transaction, whereas replaying a whole word would clobber bits a *different*
    /// transaction legitimately owns. The label word is a 63-bit token-id bitmap ([`crate::labels`]),
    /// so a changed bit *is* the label token id and needs no lookup.
    ///
    /// # The creator gate is kept, and why that is still sound
    ///
    /// A node whose `xmin` is `txn`'s own in-flight stamp is invisible to every other snapshot, so no
    /// reader can ask what its labels were before, and `txn` reads its own latest write. Its rollback
    /// is covered by the node's own creation undo, which removes the node outright — the labels of a
    /// node that never existed need no version. Skipping it is not an optimisation detail: `CREATE
    /// (:L)` goes through this path, so without the gate a bulk load of N labelled nodes would link N
    /// deltas that nothing can ever read (measured at ~2.9x on a pure label scan when the equivalent
    /// gate was absent from `LabelHistory` — see [`track_label_history`](Self::track_label_history)).
    ///
    /// # Errors
    /// Returns a storage error if a delta cannot be allocated, written, or linked, and
    /// [`GraphusError::Transaction`] — retriable — if another open transaction holds the node's chain
    /// ([`link_delta`](Self::link_delta) performs that check for every delta writer).
    fn link_label_deltas(
        &mut self,
        id: u64,
        txn: TxnId,
        old_labels: u64,
        new_labels: u64,
        creator: u64,
    ) -> Result<()> {
        if txn == SYSTEM_TXN {
            debug_assert!(
                false,
                "SYSTEM_TXN changed node {id}'s labels; the undo chain cannot version it"
            );
            return Ok(());
        }
        if VersionStamp::from_raw(creator) == VersionStamp::InFlight(txn) {
            return Ok(()); // the creator gate — see the doc above
        }
        let mut changed = old_labels ^ new_labels;
        while changed != 0 {
            let bit = changed.trailing_zeros();
            changed &= changed - 1;
            debug_assert!(
                bit <= crate::labels::MAX_INLINE_LABEL_ID,
                "bit {bit} is the overflow flag, not a label token; an overflowed label set (`rmp` \
                 #39) cannot be versioned one token at a time and must be rejected before here"
            );
            // The INVERSE of the event: what the reader must apply to undo it.
            let action = if new_labels & (1u64 << bit) != 0 {
                UndoAction::RemoveLabel // the label was added, so undoing removes it
            } else {
                UndoAction::AddLabel // the label was removed, so undoing restores it
            };
            let mut delta = UndoDelta::new(action, 0, 0, 0);
            delta.token = bit;
            self.link_delta(StoreKind::Node, id, delta, txn)?;
        }
        Ok(())
    }

    fn link_set_property(
        &mut self,
        kind: StoreKind,
        entity: u64,
        token: u32,
        old_type_tag: u8,
        old_value: u64,
        txn: TxnId,
    ) -> Result<()> {
        debug_assert!(
            matches!(kind, StoreKind::Node | StoreKind::Rel),
            "a SetProperty delta anchors on the OWNING entity; anchoring it on the `props.store` \
             cell would build a second chain family that no reader walks"
        );
        if txn == SYSTEM_TXN {
            return Ok(());
        }
        let mut delta = UndoDelta::new(UndoAction::SetProperty, 0, 0, 0);
        delta.token = token;
        delta.type_tag = old_type_tag;
        delta.value_inline = old_value;
        self.link_delta(kind, entity, delta, txn)?;
        Ok(())
    }

    /// The live `props.store` cell holding `key` on the chain rooted at `first_prop`, if any.
    ///
    /// `O(K)` in the number of **distinct keys** the entity holds — not `O(M)` in the number of times
    /// the key has been written, which is the whole point of `rmp` #967. It is honestly not `O(1)`:
    /// an entity with K properties keeps K cells on one singly-linked chain, and finding one key
    /// means walking it. Threads through `!in_use` corpses exactly as every other chain walk does.
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing or the chain does not terminate.
    fn find_live_prop_cell(
        &self,
        first_prop: u64,
        key: u32,
        owner_label: &str,
    ) -> Result<Option<(u64, PropRecord)>> {
        let mut cur = first_prop;
        let guard = self.store(StoreKind::Prop).alloc.high_water() + 1;
        let mut steps = 0u64;
        while cur != NULL_ID {
            steps += 1;
            if steps > guard {
                return Err(GraphusError::Storage(format!(
                    "property chain of {owner_label} is malformed (cycle?)"
                )));
            }
            let prop = self.read_prop(cur)?;
            if prop.mvcc.in_use() && prop.key == key {
                return Ok(Some((cur, prop)));
            }
            cur = prop.next_prop;
        }
        Ok(None)
    }

    /// Every live `props.store` cell on the chain rooted at `first_prop`, head to tail.
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing or the chain does not terminate.
    fn live_prop_cells(
        &self,
        first_prop: u64,
        owner_label: &str,
    ) -> Result<Vec<(u64, PropRecord)>> {
        let mut out = Vec::new();
        let mut cur = first_prop;
        let guard = self.store(StoreKind::Prop).alloc.high_water() + 1;
        let mut steps = 0u64;
        while cur != NULL_ID {
            steps += 1;
            if steps > guard {
                return Err(GraphusError::Storage(format!(
                    "property chain of {owner_label} is malformed (cycle?)"
                )));
            }
            let prop = self.read_prop(cur)?;
            if prop.mvcc.in_use() {
                out.push((cur, prop));
            }
            cur = prop.next_prop;
        }
        Ok(out)
    }

    /// The `first_prop` chain head of a node or relationship owner, and a label for diagnostics.
    fn owner_chain_head(&self, kind: StoreKind, id: u64) -> Result<u64> {
        Ok(match kind {
            StoreKind::Node => self.read_node(id)?.first_prop,
            StoreKind::Rel => self.read_rel(id)?.first_prop,
            StoreKind::Prop | StoreKind::Strings | StoreKind::Undo | StoreKind::Commit => {
                return Err(GraphusError::Storage(format!(
                    "{kind:?} is not a property-chain owner"
                )));
            }
        })
    }

    /// Writes the `DeleteObject` delta that records the creation of node / relationship `id` under
    /// `txn`, and returns the `undo_ptr` the caller must put into the **new record it is about to
    /// write** (`05 §12.3`).
    ///
    /// **The action is the inverse of the event**, which is the convention of this whole subsystem: a
    /// creation is undone by a deletion, so a creation writes `DeleteObject`.
    ///
    /// # Why a creation publishes its chain head differently
    ///
    /// Every other mutation publishes the head with a separate compare-and-set chain-head write
    /// ([`link_delta`](Self::link_delta)), because the entity already exists and a concurrent writer
    /// may own its head. A **creation** has neither problem: there is no prior head to displace, and
    /// nothing can observe — let alone prepend to — a record that does not exist yet. So the head
    /// rides along in the record's own first write, and the publication order of `04 §5.1.2` step 3 is
    /// still honoured exactly: the delta is written in full **before** the record that names it.
    ///
    /// That is worth one WAL record and one page fetch per created entity, which on the hottest write
    /// path in the engine is not a rounding error — **measured over 1000 `create_node`s: 398 WAL bytes
    /// per node with a separate chain-head write, 311 with the head inline** (the pre-`rmp`-#966
    /// baseline, with no chain at all, is 192). The budget is pinned by
    /// `tests/undo_chain.rs::the_wal_cost_of_a_created_entity_stays_within_its_budget`.
    ///
    /// The abort story is unchanged and needs no compare-and-set: a creation's undo reverts the new
    /// record's MVCC header — `undo_ptr` included — so an aborted creation leaves the head at `0`,
    /// which is exactly what the compare-and-set undo would have restored.
    ///
    /// Returns `0` (no chain) for the reserved [`SYSTEM_TXN`], which writes only the catalog, is never
    /// rolled back and has no [`VersionStamp`] form (its id does not fit the stamp's 63-bit payload),
    /// so it can neither own a commit slot nor need one.
    ///
    /// # Errors
    /// Returns a storage error if the delta cannot be allocated or written.
    fn creation_chain_head(&mut self, kind: StoreKind, id: u64, txn: TxnId) -> Result<u64> {
        if txn == SYSTEM_TXN {
            return Ok(NULL_ID);
        }
        let slot = self.commit_slot_for(txn)?;
        let delta_id = self.alloc_undo_id(txn)?;
        let mut buf = [0u8; undo::UNDO_RECORD_SIZE];
        UndoDelta::new(UndoAction::DeleteObject, slot, 0, NULL_ID).encode(&mut buf);
        self.write_undo_area_create(StoreKind::Undo, delta_id, &buf, undo::UNDO_OFF_FLAGS, txn)?;
        self.active
            .entry(txn)
            .or_default()
            .undo_links
            .push(UndoLink {
                kind,
                entity: id,
                delta: delta_id,
            });
        self.pending_undo_chains.insert((kind as u8, id));
        Ok(delta_id)
    }

    /// Links the `RecreateObject` delta that records the MVCC deletion of node / relationship `id`
    /// under `txn` (`05 §12.3`) — the inverse of the event, exactly as a creation's `DeleteObject` is
    /// ([`creation_chain_head`](Self::creation_chain_head)).
    ///
    /// Unlike a creation, this goes through the full [`link_delta`](Self::link_delta) publication: the
    /// entity already exists, already has a chain head to displace, and a concurrently-interleaved
    /// transaction may legitimately own that head — so the head must be published by the
    /// compare-and-set chain-head write, not carried in a record body.
    ///
    /// # Errors
    /// Returns a storage error if the delta cannot be allocated, written, or linked.
    fn note_entity_deleted(&mut self, kind: StoreKind, id: u64, txn: TxnId) -> Result<()> {
        if txn == SYSTEM_TXN {
            return Ok(());
        }
        self.link_delta(
            kind,
            id,
            UndoDelta::new(UndoAction::RecreateObject, 0, 0, 0),
            txn,
        )?;
        Ok(())
    }

    /// Reclaims the undo-area slots of a transaction that has just **aborted**, given the deltas it
    /// linked and the commit slot it owned (`rmp` #966).
    ///
    /// Called from [`rollback`](Self::rollback) *after* the WAL undo has run, so every one of this
    /// transaction's chain-head publications has already been compare-and-set-undone and every one of
    /// its deltas has already had its `in_use` bit cleared. What is left to decide is purely a space
    /// question, and it is decided **by re-walking each touched entity's chain** rather than by
    /// assuming the undo fired: a delta another transaction prepended on top of would still be
    /// threaded, as a corpse, and its slot must NOT be handed out again — the delta twin of
    /// [`reclaim_aborted_pops`](Self::reclaim_aborted_pops).
    ///
    /// **Since `rmp` #968 that threaded state has no reachable live route**, and the re-walk is kept
    /// as defence in depth rather than as a path taken. `link_delta` now refuses to prepend onto a
    /// chain head an *open* transaction holds, so an aborting transaction's delta is always still the
    /// head at its own rollback and its compare-and-set undo always fires. The re-walk stays because
    /// it is cheap, because it is the fail-safe direction (leaking a slot is safe, handing out a
    /// threaded one is not), and because it must remain correct for the sprint-96 writers still to
    /// come; the cost of the assumption being wrong is a corpse double-free, so it is not an
    /// assumption worth making.
    ///
    /// Infallible and best-effort by construction: it performs no page write (rollback's post-undo
    /// section must stay infallible, `rmp` #955) and any read error simply leaves the slot leaked,
    /// which is safe. A leaked slot is reclaimed later by the GC chain sweep or its orphan pass.
    fn reclaim_aborted_undo(&mut self, links: &[UndoLink], commit_slot: Option<u64>) {
        if links.is_empty() {
            // No delta ⇒ nothing can name the slot, so an allocated-but-unused slot is free again.
            if let Some(slot) = commit_slot {
                self.free_orphan_slot(StoreKind::Commit, slot);
            }
            return;
        }
        // One walk per touched entity, not per delta: a transaction that linked several deltas onto
        // the same entity (create-then-delete in one transaction) must not walk it twice.
        let mut entities: Vec<(StoreKind, u64)> =
            links.iter().map(|l| (l.kind, l.entity)).collect();
        entities.sort_unstable_by_key(|&(kind, id)| (kind as u8, id));
        entities.dedup();
        let mut still_threaded = std::collections::BTreeSet::new();
        for (kind, entity) in entities {
            match self.undo_chain(kind, entity) {
                Ok(chain) => {
                    if chain.is_empty() {
                        continue;
                    }
                    // The entity still has a chain, so at least one delta on it survived this abort —
                    // it belongs to another writer, or it is one of ours that a later prepend pinned.
                    self.pending_undo_chains.insert((kind as u8, entity));
                    still_threaded.extend(chain.iter().map(|&(id, _)| id));
                }
                // Cannot prove the chain no longer reaches our deltas ⇒ free none of this entity's
                // (a safe leak, never a double-free).
                Err(_) => still_threaded.extend(
                    links
                        .iter()
                        .filter(|l| l.kind == kind && l.entity == entity)
                        .map(|l| l.delta),
                ),
            }
        }
        let mut any_threaded = false;
        for link in links {
            if still_threaded.contains(&link.delta) {
                any_threaded = true;
            } else {
                self.free_orphan_slot(StoreKind::Undo, link.delta);
            }
        }
        match commit_slot {
            // A threaded corpse delta still names this slot, so the slot must outlive it (`05 §12.4`).
            // It carries no delta count (it never committed), so only a reference sweep can free it.
            Some(_) if any_threaded => self.undo_orphan_slots_possible = true,
            Some(slot) => self.free_orphan_slot(StoreKind::Commit, slot),
            None => {}
        }
    }

    /// Returns a provably-unreferenced undo-area id to its store's free list **without** a page write
    /// and without the per-transaction bookkeeping [`free_push`](Self::free_push) records.
    ///
    /// Both omissions are deliberate. The slot's `in_use` bit has already been cleared — by the WAL
    /// undo on the rollback path, or by an explicit write on the GC path — so no write is owed; and
    /// the transaction this id belonged to has already ended, so there is no rollback left to withdraw
    /// the push. The `rmp` #588 reuse hold still applies: an off-thread reader mid-walk may hold a
    /// pointer into the slot.
    fn free_orphan_slot(&mut self, kind: StoreKind, id: u64) {
        if self.store(kind).free.ids().contains(&id) {
            return;
        }
        self.store_mut(kind).free.push(id);
        if let Some(barrier) = self.reuse_barrier {
            self.held_slots[kind as usize].insert(id, barrier);
        }
    }

    /// GC phase F (`rmp` #966): reclaims every undo chain no live snapshot can still reach, and
    /// returns how many deltas were freed.
    ///
    /// **The rule.** A chain is reclaimed *whole*, from the entity's `undo_ptr` down, and only when
    /// **every** delta on it is dead — either an aborted transaction's corpse, or committed at or
    /// before `watermark` (the oldest active snapshot, `04 §5.5`). Whole-chain reclamation is what
    /// keeps a delta immutable once linked (`05 §12.2`): nothing is ever spliced out of the middle of
    /// a chain, so no delta's `next` is ever rewritten. The per-delta test is needed as well as the
    /// head's, because statement-granularity interleaving can leave a *newer* committed delta above an
    /// *older* still-in-flight one.
    ///
    /// The candidate set is the entities whose chains grew since the last pass
    /// ([`pending_undo_chains`](Self#structfield.pending_undo_chains)), reseeded by a full scan on the
    /// first pass after `open` — the same incremental shape the `rmp` #522 tombstone sweep uses, and
    /// what makes a crash-recovered store (which has none of this in-memory state) reclaim normally.
    ///
    /// # Errors
    /// Returns a storage error if a chain is malformed or a write fails.
    fn gc_reclaim_undo_chains(&mut self, txn: TxnId, watermark: Timestamp) -> Result<usize> {
        // The chain-head census, collected only on the pass that scans the record stores anyway. It is
        // what lets the orphan sweep below free a delta a CRASH stranded (see
        // [`gc_sweep_undo_orphans`](Self::gc_sweep_undo_orphans)).
        let chain_heads = if self.gc_full_scan_pending {
            Some(self.seed_pending_undo_chains()?)
        } else {
            None
        };
        let candidates: Vec<(u8, u64)> = self.pending_undo_chains.iter().copied().collect();
        let mut freed = 0usize;
        for (kind_byte, entity) in candidates {
            let kind = ALL_STORE_KINDS[kind_byte as usize];
            let chain = self.undo_chain(kind, entity)?;
            if chain.is_empty() {
                self.pending_undo_chains.remove(&(kind_byte, entity));
                continue;
            }
            let mut all_dead = true;
            for &(_, delta) in &chain {
                if !self.delta_is_dead(delta, watermark)? {
                    all_dead = false;
                    break;
                }
            }
            if all_dead {
                freed += self.free_undo_chain(kind, entity, txn)?;
            }
        }
        // The reference sweep runs when something may have been stranded: a rollback that left a
        // threaded corpse, or the first pass after `open` (which is where a crash-stranded delta is
        // collected — and the only pass that holds the chain-head census it needs).
        if self.undo_orphan_slots_possible || chain_heads.is_some() {
            freed += self.gc_sweep_undo_orphans(txn, chain_heads.as_ref())?;
        }
        Ok(freed)
    }

    /// Whether `delta` can no longer be needed by any live snapshot: its transaction aborted (the
    /// delta is a corpse, or its slot is), or it committed at or before the GC `watermark`.
    ///
    /// Every one of those questions is answered **through the commit slot** — the indirection point
    /// (`04 §5.1.3`). That is the whole economy of the design: one word per transaction decides the
    /// fate of all of its deltas, instead of a stamp per record that a freeze sweep has to rewrite.
    fn delta_is_dead(&self, delta: UndoDelta, watermark: Timestamp) -> Result<bool> {
        if !delta.in_use() {
            return Ok(true);
        }
        let Some(slot) = self.read_commit_slot(delta.commit_info)? else {
            // The slot is gone, so nothing can resolve this delta's status any more. That must never
            // happen (`05 §12.4`: a slot outlives its last delta) and the checker reports it; treat the
            // delta as live here so GC never compounds the damage by freeing more.
            return Ok(false);
        };
        if !slot.in_use() {
            return Ok(true); // aborted transaction
        }
        Ok(match VersionStamp::from_raw(slot.commit_ts) {
            VersionStamp::Committed(ts) => ts <= watermark,
            // Still open — or a writer whose commit the registry has since resolved but whose slot is
            // this build's durable record of it. Either way, not reclaimable yet.
            VersionStamp::InFlight(_) | VersionStamp::None => false,
        })
    }

    /// Rebuilds [`pending_undo_chains`](Self#structfield.pending_undo_chains) by scanning the three
    /// versioned stores for a non-zero `undo_ptr`.
    ///
    /// Runs only on the first GC pass after `open` (the `gc_full_scan_pending` gate every other
    /// full-store sweep shares), which is exactly what a crash-recovered store needs: the pending set
    /// is in-memory only, so without this a recovered store would never reclaim the chains ARIES redo
    /// rebuilt for it.
    /// Also returns the set of **chain heads** it saw — every non-zero `undo_ptr` in the store. That
    /// set is the half of the delta-reference census the undo store cannot supply on its own, and it
    /// is what lets [`gc_sweep_undo_orphans`](Self::gc_sweep_undo_orphans) free a delta a **crash**
    /// stranded (see that method).
    fn seed_pending_undo_chains(&mut self) -> Result<std::collections::BTreeSet<u64>> {
        let mut heads = std::collections::BTreeSet::new();
        for kind in MVCC_STORE_KINDS {
            let hw = self.store(kind).alloc.high_water();
            for id in 1..hw {
                let head = self.read_mvcc(kind, id)?.undo_ptr;
                if head != NULL_ID {
                    self.pending_undo_chains.insert((kind as u8, id));
                    heads.insert(head);
                }
            }
        }
        Ok(heads)
    }

    /// The undo area's **reference sweep**: frees every delta and every commit slot that nothing names
    /// any more (`rmp` #966). Returns how many deltas it freed.
    ///
    /// It is the reclaimer of last resort, for the two lifetimes the precise paths cannot cover:
    ///
    /// * **A delta a crash stranded.** A creation writes its delta and then the record that names it.
    ///   A crash between the two leaves a delta the ARIES undo turns into a corpse but that no chain
    ///   ever reached, and — unlike a live rollback, where
    ///   [`reclaim_aborted_undo`](Self::reclaim_aborted_undo) knows exactly which deltas the aborting
    ///   transaction linked — nothing in memory survives a crash to say so. Only a census can.
    /// * **An aborted transaction's slot that a threaded corpse delta still named** when its rollback
    ///   ran. Such a slot never carries a `delta_count` (it never committed), so the count rule of
    ///   `05 §12.4` cannot free it either.
    ///
    /// **The census.** A delta is reachable exactly when it is some record's `undo_ptr` or some live
    /// delta's `next`; a slot is reachable exactly when some live delta names it as `commit_info`. The
    /// undo-store scan supplies the `next` and `commit_info` halves; `chain_heads` supplies the
    /// `undo_ptr` half, and is `Some` only on a pass that has just scanned the record stores for it
    /// ([`seed_pending_undo_chains`](Self::seed_pending_undo_chains)). Without it the delta phase is
    /// skipped rather than guessed — a skipped reclamation is a bounded leak, a wrong one is corruption.
    ///
    /// Two conservative rules, both in the safe direction:
    ///
    /// * a **freed** delta's body is not rewritten when it is freed (only its flag is cleared), so its
    ///   stale `next` must not be counted as a reference — free-listed deltas are excluded from the
    ///   census;
    /// * a slot owned by a **still-open** transaction is never freed, because that transaction may be
    ///   between allocating its slot and linking its first delta, at which instant nothing names it.
    ///
    /// If the GC pass that ran this sweep later **rolls back**, its frees are undone by the WAL while
    /// the in-memory gate stays cleared, so the next sweep is deferred to the following post-open full
    /// pass. That is a bounded space leak and never a correctness problem: an orphan is unreachable by
    /// construction, so nothing resolves through it either way.
    fn gc_sweep_undo_orphans(
        &mut self,
        txn: TxnId,
        chain_heads: Option<&std::collections::BTreeSet<u64>>,
    ) -> Result<usize> {
        let undo_hw = self.store(StoreKind::Undo).alloc.high_water();
        let mut freed_deltas = 0usize;
        if let Some(heads) = chain_heads {
            // Phase 1 — unreachable deltas. `next` links come from deltas that are themselves still
            // allocated; a free-listed delta's stale body is not a reference.
            let mut reachable = heads.clone();
            let mut corpses: Vec<u64> = Vec::new();
            for id in 1..undo_hw {
                if self.store(StoreKind::Undo).free.ids().contains(&id) {
                    continue;
                }
                let Some(delta) = self.read_delta(id)? else {
                    continue;
                };
                if delta.next != NULL_ID {
                    reachable.insert(delta.next);
                }
                if !delta.in_use() {
                    corpses.push(id);
                }
            }
            for id in corpses {
                if !reachable.contains(&id) {
                    self.free_orphan_slot(StoreKind::Undo, id);
                    freed_deltas += 1;
                }
            }
        }

        // Phase 2 — unreachable commit slots, over what phase 1 left standing.
        let mut referenced = std::collections::BTreeSet::new();
        for id in 1..undo_hw {
            if self.store(StoreKind::Undo).free.ids().contains(&id) {
                continue;
            }
            if let Some(delta) = self.read_delta(id)? {
                referenced.insert(delta.commit_info);
            }
        }
        let open: std::collections::BTreeSet<u64> =
            self.active.values().filter_map(|a| a.commit_slot).collect();
        let commit_hw = self.store(StoreKind::Commit).alloc.high_water();
        for id in 1..commit_hw {
            if referenced.contains(&id)
                || open.contains(&id)
                || self.store(StoreKind::Commit).free.ids().contains(&id)
            {
                continue;
            }
            let Some(slot) = self.read_commit_slot(id)? else {
                continue;
            };
            if slot.in_use() {
                // A committed slot with no surviving delta: the `delta_count` rule owns it and has
                // already freed it, so reaching here means the count and the references disagree. The
                // checker reports that; do not act on it.
                continue;
            }
            let (rel_page, off) = paging::record_location(id, undo::COMMIT_RECORD_SIZE);
            let dev = self.device_page(StoreKind::Commit, rel_page)?;
            self.write_region(dev, off, &[0u8; undo::COMMIT_RECORD_SIZE], txn)?;
            self.free_push(StoreKind::Commit, id, txn);
        }
        self.undo_orphan_slots_possible = false;
        Ok(freed_deltas)
    }

    /// Writes node `id`'s 8-byte `labels` bitmap word to `new_labels`, logging a **compare-and-set
    /// logical undo** (`rmp` #772): redo installs `new_labels`; undo resets the word to `old_labels`
    /// *only if it still equals `new_labels`* (this txn's own write is still the one on the page).
    ///
    /// # Why a whole-record undo here is unsound (the `rmp` #772 breach)
    ///
    /// [`add_label`](Self::add_label) / [`remove_label`](Self::remove_label) change ONLY the `labels`
    /// word, but used to persist the change with [`write_node`](Self::write_node) — a plain
    /// **whole-record** pre-image undo (`write_region`). The node record's OTHER words are
    /// concurrently shared: a different transaction's [`add_node_property`](Self::add_node_property) /
    /// [`create_rel`](Self::create_rel) pushes onto `first_prop` / `first_rel` via
    /// [`write_chain_head`](Self::write_chain_head), and its delete/tombstone re-stamps the MVCC
    /// header via [`patch_header_word_cas`](Self::patch_header_word_cas). Under statement-granularity
    /// interleaving that writer can COMMIT between the label change and its abort, so the aborting
    /// label change's whole-record pre-image no longer describes those words. Replaying it on abort
    /// reverted `first_prop` to its pre-commit value, orphaning the committed property version (whose
    /// predecessor the committing writer had MVCC-tombstoned on a byte region the whole-record undo
    /// does not restore) — the committed value read back as `Null`: an atomicity + durability breach.
    ///
    /// Scoping the write and its undo to the `labels` word alone — with the same CAS discipline the
    /// three chain-participating writes above already use — reverts ONLY this transaction's own label
    /// change and never a concurrently-committed writer's `first_prop` / `first_rel` / MVCC word. The
    /// CAS (rather than a plain pre-image of just the word) also protects the `labels` word itself: a
    /// later committed writer that legitimately owns it by abort time is preserved (the CAS no-ops),
    /// exactly as [`patch_header_word_cas`](Self::patch_header_word_cas) reasons for the header word.
    /// Replays identically in live rollback (`PoolTarget`) and crash recovery (`DeviceTarget`) via
    /// [`paging::apply_patch`].
    fn write_node_labels(
        &mut self,
        id: u64,
        new_labels: u64,
        old_labels: u64,
        txn: TxnId,
        creator: u64,
    ) -> Result<()> {
        // Retain the pre-change membership as durable MVCC versions BEFORE overwriting the word
        // (`rmp` #968): the word is mutated in place, so without the deltas the old value would
        // survive only in the WAL undo image, which no reader can reach.
        //
        // SAFETY-CRITICAL ORDERING — do NOT move this below the in-place page write. A reader that
        // observes the new word under the buffer-pool page read latch must already be able to observe
        // the deltas that undo it; the delta writes happen-before the latched word write, so it can
        // never decode an uncommitted word with no version behind it (a dirty read). This is the same
        // ordering obligation the retired `TrackedFilter` arming had, discharged by the same latch.
        //
        // The link also carries the write-conflict check (`link_delta`), so a label change on a node
        // another open transaction holds is refused here rather than interleaved onto its chain.
        self.link_label_deltas(id, txn, old_labels, new_labels, creator)?;
        let (rel_page, off) = paging::record_location(id, StoreKind::Node.record_size());
        let dev = self.device_page(StoreKind::Node, rel_page)?;
        let abs = off + NODE_OFF_LABELS;
        let redo = paging::encode_patch(abs, &new_labels.to_le_bytes());
        let undo = paging::encode_cas_patch(abs, new_labels, old_labels).into_vec();
        let f = self.pool.fetch(dev)?;
        let lsn = self
            .wal
            .with(|w| w.log_update_borrowed(txn, dev, &redo, undo));
        self.pool.with_page_mut_lsn(f, lsn, |p| {
            p[abs..abs + 8].copy_from_slice(&new_labels.to_le_bytes());
        });
        self.pool.unpin(f);
        Ok(())
    }

    /// Writes the full body of record `id` in `kind`'s store, logging a **header-only undo**: the
    /// redo is the whole-record post-image; the undo restores ONLY the 25-byte MVCC header captured
    /// live from the page before the overwrite. On abort/recovery this reverts the slot to not-in-use
    /// while PRESERVING the record's body — crucially its forward chain pointers — so a surviving
    /// writer that prepended onto this record threads transparently through the dead record to its
    /// successor instead of the chain being severed (`rmp` #220 / #172).
    ///
    /// Sound because `id` is the creating txn's freshly-allocated, slot-private record: no concurrent
    /// txn ever mutates a not-yet-committed creator's own new slot, so the header pre-image is never
    /// stale (unlike the chain-head field, which IS concurrently shared — hence `write_chain_head`).
    fn write_record_header_undo(
        &mut self,
        kind: StoreKind,
        id: u64,
        buf: &[u8],
        txn: TxnId,
    ) -> Result<()> {
        let (rel_page, off) = paging::record_location(id, kind.record_size());
        let dev = self.ensure_store_page(kind, rel_page, txn)?;
        let end = off + buf.len();
        let f = self.pool.fetch(dev)?;
        // Capture the live header pre-image (the only bytes the undo restores) before overwriting:
        // read latch, then a separate write latch for the post-image (frame pinned across both).
        // Header-only undo captured STRICTLY before the whole-record post-image overwrite (`rmp`
        // #220 / #172): same bytes (the 25-byte MVCC header pre-image), inline buffer. Retained undo
        // taken by value; redo lent by borrow.
        let undo = self
            .pool
            .with_page(f, |p| {
                paging::encode_patch(off, &p[off..off + MVCC_HEADER_SIZE])
            })
            .into_vec();
        let redo = paging::encode_patch(off, buf);
        let lsn = self
            .wal
            .with(|w| w.log_update_borrowed(txn, dev, &redo, undo));
        self.pool.with_page_mut_lsn(f, lsn, |p| {
            p[off..end].copy_from_slice(buf);
        });
        self.pool.unpin(f);
        Ok(())
    }

    /// First write of a freshly-created relationship record, with the header-only creation undo
    /// (`rmp` #220). See [`write_record_header_undo`](Self::write_record_header_undo).
    fn write_rel_create(&mut self, id: u64, rec: &RelRecord, txn: TxnId) -> Result<()> {
        let mut buf = [0u8; REL_RECORD_SIZE];
        rec.encode(&mut buf);
        self.write_record_header_undo(StoreKind::Rel, id, &buf, txn)
    }

    /// First write of a freshly-created property record, with the header-only creation undo
    /// (`rmp` #172). See [`write_record_header_undo`](Self::write_record_header_undo).
    fn write_prop_create(&mut self, id: u64, rec: &PropRecord, txn: TxnId) -> Result<()> {
        let mut buf = [0u8; PROP_RECORD_SIZE];
        rec.encode(&mut buf);
        self.write_record_header_undo(StoreKind::Prop, id, &buf, txn)
    }

    /// Records that `txn` version-stamped (created) record `id` in `kind`'s store, so `commit` can
    /// settle its `xmin`. A no-op for the reserved system transaction, which never creates records.
    fn note_created(&mut self, txn: TxnId, kind: StoreKind, id: u64) {
        // `rmp` #522: a fresh `xmin = in_flight(txn)` stamp at `id` needs freezing once `txn` commits.
        // Lower the freeze frontier so the next freeze sweep re-visits `id` (a no-op for the common case
        // where `id >= freeze_low[kind]` — a fresh append above the frontier — but load-bearing when a
        // reused id lands below it). Recorded even for `SYSTEM_TXN` so a system-created record is frozen.
        self.lower_freeze_low(kind, id);
        if txn != SYSTEM_TXN {
            self.active.entry(txn).or_default().created.push((kind, id));
        }
    }

    /// Lowers the `rmp` #522 freeze frontier for `kind` to cover `id` (a no-op if `id` is already at or
    /// above it). See [`freeze_low`](Self::freeze_low).
    fn lower_freeze_low(&mut self, kind: StoreKind, id: u64) {
        let slot = &mut self.freeze_low[kind as usize];
        if id < *slot {
            *slot = id;
        }
    }

    /// Records that `txn` tombstoned (expired) record `id` in `kind`'s store, so `commit` can settle
    /// its `xmax`.
    fn note_expired(&mut self, txn: TxnId, kind: StoreKind, id: u64) {
        // `rmp` #522: a fresh `xmax = in_flight(txn)` stamp both needs freezing (lower the frontier) and
        // makes `id` a reclaim candidate once the tombstone commits at or below the GC watermark. The
        // reclaim sweep iterates this set instead of scanning the whole store.
        self.lower_freeze_low(kind, id);
        self.pending_tombstones[kind as usize].insert(id);
        if txn != SYSTEM_TXN {
            self.active.entry(txn).or_default().expired.push((kind, id));
        }
    }

    /// Returns physical id `id` to `kind`'s in-memory free list AND records the push under `txn`
    /// (`rmp` #578). **Every** GC/reclaim free-list push must go through this — never
    /// `store_mut(kind).free.push(id)` directly — so a **live** rollback of the freeing transaction
    /// can withdraw its own pushes.
    ///
    /// The hazard it closes is the free-list twin of the `rmp` #220/#172 monotonic high-water floor:
    /// [`reload_catalog`](Self::reload_catalog) restores the free list to the last *durably committed*
    /// image, but under statement-granularity interleaving a still-open **concurrent** transaction may
    /// have already **popped** a freed id (via [`alloc_id`](Self::alloc_id)). Re-listing the committed
    /// image would hand that id out **again** — two live records sharing one physical slot, whose
    /// property/incidence chains then self-cycle (`P.next_prop = P` / `P.start_next = P`). [`rollback`]
    /// (Self::rollback) instead restores the *pre-rollback* in-memory list (which already reflects every
    /// concurrent pop) and removes exactly the ids recorded here, so an aborted GC pass — whose WAL undo
    /// restores each reclaimed record's `in_use` bit — leaves no freed id whose slot is once again live.
    /// Mirrors [`note_created`](Self::note_created) / [`note_expired`](Self::note_expired), including the
    /// `SYSTEM_TXN` guard (the system transaction never frees records and is never rolled back).
    fn free_push(&mut self, kind: StoreKind, id: u64, txn: TxnId) {
        self.store_mut(kind).free.push(id);
        if txn != SYSTEM_TXN {
            self.active
                .entry(txn)
                .or_default()
                .freed_ids
                .push((kind, id));
        }
        // `rmp` #588: while a GC pass runs with open transactions, shadow-hold the freed id so
        // [`alloc_id`](Self::alloc_id) does not reuse its slot until every reader that predates the free
        // has retired (see [`held_slots`](Self#structfield.held_slots)). Overwriting an existing entry is
        // correct — the id is on the free list only because THIS push listed it, so its recorded barrier
        // is always the current (newest) one. Outside a bracketed GC pass (`reuse_barrier == None`) — the
        // inline/DST path and every non-GC free (e.g. a rollback of a just-popped id) — the slot is
        // immediately reusable, exactly as before #588.
        if let Some(barrier) = self.reuse_barrier {
            self.held_slots[kind as usize].insert(id, barrier);
        }
    }

    /// Moves one **live-record cardinality counter** by `±1` under `txn` AND records the move in
    /// `txn`'s pending count delta (`rmp` #866). **Every** counter mutation must go through this —
    /// never `self.statistics.inc_*()` / `dec_*()` directly, which is why those are private to
    /// [`meta`](crate::meta) — so a rollback can withdraw exactly this transaction's own effect and a
    /// checkpoint can persist the committed image. The counts twin of
    /// [`free_push`](Self::free_push) (`rmp` #578) and of
    /// [`with_schema_undo`](Self::with_schema_undo) (`rmp` #734).
    ///
    /// # The hazard it closes
    ///
    /// The counters move **eagerly at write time**, but [`rollback`](Self::rollback) used to restore
    /// them via `reload_catalog`'s wholesale revert to the *durable* image. Under statement-
    /// granularity interleaving that is wrong in both directions and the error is **permanent**:
    ///
    /// * a concurrent transaction that COMMITS while this one is open checkpoints the live counter,
    ///   which already carries this one's uncommitted increment — so this one's later rollback
    ///   *reloads its own uncommitted count back* as though it had committed (over-count);
    /// * a rollback reverting to the durable image WIPES a concurrent open transaction's pending
    ///   increments, and that transaction's own commit then checkpoints the wiped value
    ///   (under-count).
    ///
    /// Both drifts survive every reopen. They were tolerable while the counters were an advisory
    /// planner statistic; `rmp` #866 answers `count()` from them, which makes a drifted counter a
    /// **wrong query answer** — an ACID/TCK breach.
    ///
    /// # The shared/live semantics are deliberately unchanged
    ///
    /// The mutation is still applied to the shared [`Statistics`] immediately, so the live counters
    /// remain "committed image + every in-flight delta". Deferring application to commit would be a
    /// different (and much larger) behaviour change; what is added here is only the bookkeeping that
    /// makes the committed image *recoverable* from the live one.
    ///
    /// # No active entry, no record
    ///
    /// Deliberately `get_mut`, not `entry(txn).or_default()` — the same choice, for the same reason,
    /// as [`with_schema_undo`](Self::with_schema_undo): inserting here would make an unbegun
    /// transaction look **open** to [`is_txn_active`](Self::is_txn_active) and to the active-set
    /// emptiness checks, and since nothing will ever commit or roll it back, its phantom entry would
    /// strip these counts from *every future checkpoint*, permanently under-counting the durable
    /// catalog. Recording nothing is the lesser failure, and the debug assertion below turns any such
    /// call site into a failing test. (It also makes the [`SYSTEM_TXN`] guard the other `note_*`
    /// helpers carry unnecessary here: the system transaction is never in `active`, and it never
    /// mutates a counter.)
    fn count_bump(&mut self, txn: TxnId, key: CountKey, increment: bool) {
        debug_assert!(
            self.is_txn_active(txn),
            "count mutation {key:?} for {txn:?}, which is not an open transaction: its delta could \
             never be withdrawn, so the counter would drift permanently"
        );
        let delta = if increment { 1 } else { -1 };
        self.statistics.apply_count_delta(key, delta);
        if let Some(active) = self.active.get_mut(&txn) {
            active.counts.record(key, delta);
        }
    }

    /// Whether the live counters currently equal the **committed** image — i.e. no open transaction
    /// holds a pending count delta (`rmp` #866).
    ///
    /// # What it is for
    ///
    /// It is one half of the equivalence predicate a counter-served `count()` needs. Reading a
    /// cardinality straight out of [`Statistics`] instead of scanning is only sound when that number
    /// is what the caller's snapshot would have counted, which takes **two** independent facts:
    ///
    /// 1. **nothing uncommitted is folded into the counter** — this method; and
    /// 2. **nothing has committed since the reader took its snapshot** — `snapshot_ts() ==
    ///    snapshot.ts`, which the caller checks (it owns the snapshot; the store does not).
    ///
    /// Both must hold. This one alone would still let a writer that committed *after* the reader's
    /// snapshot show through.
    ///
    /// # A `false` means SCAN, never "approximate"
    ///
    /// The counters move eagerly at write time, so while any writer is open the live value is the
    /// committed image **plus** that writer's uncommitted rows — a dirty read. There is no correction
    /// factor and no tolerance: a `false` here means the shortcut is unavailable and the caller must
    /// fall back to the ordinary visibility-filtered scan, exactly as it would for an index that
    /// declines to serve a predicate (`rmp` #738: decline, never return a wrong-but-close answer).
    #[must_use]
    pub fn counts_match_committed_image(&self) -> bool {
        self.active.values().all(|a| a.counts.is_empty())
    }

    /// **`rmp` #588.** Sets (or clears) the reuse barrier stamped onto GC-pass frees. The engine brackets
    /// each maintenance [`gc`](Self::gc) pass with `Some(next_ticket)` … `None` so only that pass's freed
    /// slots are shadow-held (see [`held_slots`](Self#structfield.held_slots)); every open transaction at
    /// that instant has a strictly smaller ticket, so [`release_held`](Self::release_held) can later tell
    /// when they have all retired.
    pub fn set_reuse_barrier(&mut self, barrier: Option<u64>) {
        self.reuse_barrier = barrier;
    }

    /// **`rmp` #588.** Releases every shadow-held slot whose reuse barrier is now safe: a slot held at
    /// barrier `b` becomes reusable once no transaction older than `b` is still open, i.e. once the
    /// **oldest open transaction's ticket** `oldest_open_ticket` has reached `b` (`b <= oldest_open_ticket`).
    /// `u64::MAX` (no open transaction) releases everything. The released ids are already on the durable
    /// free list — this only lifts the in-memory reuse hold — so [`alloc_id`](Self::alloc_id) may hand
    /// them out again. Called by the engine after each maintenance pass and as readers retire.
    pub fn release_held(&mut self, oldest_open_ticket: u64) {
        for k in 0..STORE_COUNT {
            if !self.held_slots[k].is_empty() {
                self.held_slots[k].retain(|_id, &mut barrier| barrier > oldest_open_ticket);
            }
        }
    }

    /// **`rmp` #588** (observability / tests): the total number of physical slots currently shadow-held
    /// from reuse across all stores. `0` on the inline/DST path and whenever no off-thread reader is
    /// holding a freed slot.
    #[must_use]
    pub fn held_slots_len(&self) -> usize {
        self.held_slots.iter().map(HashMap::len).sum()
    }

    /// **`rmp` #588** (observability / tests): the number of physical slots of **one** store currently
    /// shadow-held from reuse. Sharper than [`held_slots_len`](Self::held_slots_len) for a caller that
    /// cares about a specific store, since a GC pass also holds the undo-area slots it frees
    /// (`rmp` #966) — conservatively, because an off-thread reader walking a version chain has exactly
    /// the same mid-walk hazard as one walking an incidence chain.
    #[must_use]
    pub fn held_slots_len_of(&self, kind: StoreKind) -> usize {
        self.held_slots[kind as usize].len()
    }

    /// Records that property `pid` was prepended onto `(owner_kind, owner_id)` — but only if `pid` was
    /// a **popped** (reused) id of `txn` (`rmp` #581). A prop carries no owner back-pointer, so the
    /// rollback needs this to walk the owner's chain and decide whether an aborted pop became a live
    /// corpse. Recorded lazily (only for pops), so a transaction that never reuses a freed prop id
    /// stores nothing. Mirrors the `SYSTEM_TXN` guard of [`free_push`](Self::free_push).
    fn note_popped_prop_owner(
        &mut self,
        txn: TxnId,
        pid: u64,
        owner_kind: StoreKind,
        owner_id: u64,
    ) {
        if txn == SYSTEM_TXN {
            return;
        }
        if let Some(a) = self.active.get_mut(&txn)
            && a.popped_ids
                .iter()
                .any(|&(k, id)| k == StoreKind::Prop && id == pid)
        {
            a.popped_prop_owners.push((pid, owner_kind, owner_id));
        }
    }

    /// Whether `mvcc` is a **live version**: its slot is in use and it carries no expiry tombstone
    /// (`xmax == 0`). A tombstoned record keeps its `in_use` slot (it survives for older snapshots
    /// until GC) but is no longer the live version, so it must not be re-deleted or re-stamped.
    fn is_live_version(mvcc: MvccHeader) -> bool {
        mvcc.in_use() && mvcc.expired_ts == 0
    }

    /// Whether a tombstoned record is reclaimable at `watermark`: it occupies its slot, carries an
    /// expiry, and that expiry **committed** at or before `watermark` — so no live or future
    /// snapshot can still observe it (`04 §5.5`). A still-in-flight or yet-uncommitted tombstone is
    /// not reclaimable.
    fn is_reclaimable(mvcc: MvccHeader, watermark: Timestamp, registry: &CommitRegistry) -> bool {
        if !mvcc.in_use() {
            return false;
        }
        // Resolve the expiry stamp through the Active/Recent Transaction Table (`rmp` task #49): a
        // frozen tombstone carries `Committed(ts)` directly; a lazily-committed one still carries the
        // deleter's in-flight `TxnId`, which the registry maps to its commit timestamp. A live
        // (`xmax == 0`), still-in-flight, or aborted expiry resolves to `None` and is not reclaimable.
        match registry.resolve_commit_ts(mvcc.expired_ts) {
            Some(ts) => ts <= watermark,
            None => false,
        }
    }

    /// Garbage-collects MVCC tombstones under `txn`: physically reclaims every relationship, node
    /// **and per-value property version** whose `xmax` committed at or before `watermark` — i.e. is
    /// invisible to every live and future snapshot (`04 §5.5`) — and returns the number of records
    /// reclaimed.
    ///
    /// `watermark` MUST be at or below the oldest active reader's snapshot timestamp, so no live
    /// transaction can still observe a reclaimed version (the caller, which owns the timestamp
    /// oracle's low-water mark, guarantees this). Relationships are reclaimed before nodes, and a
    /// node is reclaimed only once no live (not-yet-reclaimed) relationship still references it, so
    /// referential integrity and the incidence chains stay well-formed throughout — the consistency
    /// checker passes both before and after a GC pass.
    ///
    /// After the node/relationship sweep, every **still-live** node and relationship has its property
    /// chain swept ([`gc_property_chain`](Self::gc_property_chain)): a tombstoned property version
    /// (`rmp` task #50) whose `xmax` committed at or before `watermark` is freed (record + overflow
    /// blocks) and spliced out of the chain. A reclaimed owner's chain is freed wholesale by its
    /// reclamation, so only surviving owners are swept here — no chain is touched twice.
    ///
    /// The caller owns the transaction lifecycle (it must later commit or roll back `txn`), exactly
    /// as for any other mutator; the reclamation writes are WAL-logged and crash-recovered the same.
    ///
    /// ## GC-time header freezing + table pruning (`rmp` task #59)
    ///
    /// After the reclamation sweeps, every surviving record of **all MVCC record kinds** (nodes,
    /// relationships, per-value property versions) has its header **frozen**
    /// ([`freeze_store_headers`](Self::freeze_store_headers)): an `xmin`/`xmax` word that carries a
    /// committed writer's in-flight `TxnId` is rewritten — WAL-logged under `txn`, like every other
    /// header write — to the `Committed(ts)` form the Active/Recent Transaction Table resolves it
    /// to. Still-in-flight stamps (no committed outcome) are left untouched. The freeze sweep walks
    /// each store's full physical-id range, independent of chain structure and of `watermark`, so a
    /// single pass provably visits every record: after it, **no** in-use record references any
    /// writer the table records as committed.
    ///
    /// The pass therefore schedules every such writer to be **forgotten** from the table — but only
    /// once the freeze is durable: the prune applies when `txn` **commits**
    /// ([`commit`](Self::commit)) and is discarded if `txn` rolls back
    /// ([`rollback`](Self::rollback)), whose WAL undo restores the in-flight stamps that still need
    /// the entries. A crash before the GC commit recovers the same way (the GC txn is a loser; the
    /// table is rebuilt from the WAL commit records on [`open`](Self::open)). This freeze-then-prune
    /// cycle is what bounds the table on a long-lived server: it ends each completed pass holding
    /// only still-in-flight writers plus writers that committed after the pass's freeze sweep.
    ///
    /// # Errors
    /// Returns a storage error if a record read or a reclamation/freeze write fails.
    pub fn gc(&mut self, txn: TxnId, watermark: Timestamp) -> Result<GcPassReport> {
        self.gc_inner(txn, watermark, false)
    }

    /// A **freeze-only** GC pass (`rmp` #590): runs only the incremental freeze sweep (Phase E) and the
    /// registry-prune scheduling, **skipping** the reclamation sweeps (Phases A–D: relationship/node
    /// tombstone reclaim, the corpse splice, and the property-chain sweep). Its sole purpose is to drain
    /// the store's `unfrozen_commit_lsn` map — i.e. to **lower the WAL reclaim floor** — as cheaply as
    /// possible, so a caller can bound the retained WAL without paying the reclamation sweeps.
    ///
    /// Why this exists: a network Mode A bulk-import updates a durable checkpoint-sentinel node's
    /// counters **every batch** (`graphus_server`'s `bulk_load::checkpoint_sentinel`), and each update
    /// tombstones the prior property version, so `pending_tombstones[Prop]` is never empty during a load
    /// and the Phase D property sweep — a full `O(store)` scan of every live owner's property chain —
    /// gates ON on every pass. Running that sweep on a *tightened* mid-load cadence would reintroduce the
    /// exact `O(N²)` maintenance cost `rmp` #556/#565 widened the loading cadence to avoid, even though
    /// the freeze sweep itself is `O(Δ)` since `rmp` #522. The freeze sweep is all that is needed to
    /// advance the WAL floor; the (few, sentinel-only) dead property versions a load leaves behind are
    /// reclaimed later by the ordinary full cadence after the next `START DATABASE`, or by the FULL
    /// end-of-load checkpoint (`rmp` #579) at a clean `End`.
    ///
    /// Soundness: the prune's precondition is *freeze completeness* (every committed writer's on-disk
    /// in-flight stamps settled to `Committed(ts)`), which the Phase E freeze establishes independently
    /// of whether dead slots are reclaimed; the freeze-frontier invariant (see [`freeze_low`](Self::freeze_low))
    /// likewise holds whether or not a tombstone below the frontier is physically freed (its stamps are
    /// frozen either way). This pass therefore leaves the store's *committed, visible* image and its
    /// crash-recovery behaviour identical to a full pass — only deferred slot reclamation differs.
    ///
    /// # Errors
    /// Returns a storage error if a record read or a freeze write fails.
    pub fn gc_freeze_only(&mut self, txn: TxnId, watermark: Timestamp) -> Result<GcPassReport> {
        self.gc_inner(txn, watermark, true)
    }

    /// Shared body of [`gc`](Self::gc) (`freeze_only == false`) and
    /// [`gc_freeze_only`](Self::gc_freeze_only) (`freeze_only == true`). When `freeze_only` is set the
    /// reclamation sweeps (Phases A–D) are skipped; only the incremental freeze sweep and the prune
    /// scheduling run. See [`gc_freeze_only`](Self::gc_freeze_only) for why.
    fn gc_inner(
        &mut self,
        txn: TxnId,
        watermark: Timestamp,
        freeze_only: bool,
    ) -> Result<GcPassReport> {
        let mut reclaimed = 0usize;
        let mut undo_deltas_reclaimed = 0usize;

        // `rmp` #522: snapshot the freeze frontier BEFORE the freeze sweep advances it, so a rollback of
        // this GC pass (whose WAL undo restores the stamps it froze) can restore the frontier and not
        // strand those now-un-frozen stamps below it. Cleared at this pass's commit. No other transaction
        // runs between here and this pass's commit/rollback (the single engine thread holds the store), so
        // the savepoint's frontier is exactly the pre-freeze value.
        self.gc_freeze_low_savepoint = Some((txn, self.freeze_low));

        // `rmp` #563: heartbeat the drain-progress beacon across every phase of this GC pass so a
        // `STOP DATABASE` that races it sees a *progressing* engine and waits rather than force-detaching.
        self.bump_drain_progress();

        // ---- Phases A–D: reclamation sweeps. SKIPPED in a freeze-only pass (`rmp` #590). ----
        // A freeze-only pass exists solely to advance the WAL reclaim floor (Phase E) cheaply during a
        // bulk load; the reclamation sweeps are what make a mid-load pass `O(store)` (the Phase D property
        // sweep gates ON every batch because the load's checkpoint sentinel tombstones a property version
        // per batch), so they are deferred to the next full pass. See [`gc_freeze_only`](Self::gc_freeze_only).
        if !freeze_only {
            // ---- Phase A: reclaim reclaimable RELATIONSHIP tombstones (`rmp` #522: pending-set driven). ----
            // Was an O(store) `scan_in_use_mvcc(Rel)` every tick; now iterates only the tombstones tracked
            // since the last pass (with a full-scan fallback on the first post-open pass, which also seeds the
            // pending set). Reclaimable ones are freed; the rest stay pending. Runs before the corpse splice
            // (so a corpse whose neighbour was just reclaimed sees the updated chain) and before the node
            // sweep (so a node whose only incidences were reclaimed becomes reclaimable this pass).
            reclaimed += self.reclaim_pending(StoreKind::Rel, txn, watermark)?;

            // ---- Phase B: splice out dead-link RELATIONSHIP corpses (`rmp` #220), gated (`rmp` #522). ----
            // A corpse is a slot an aborted/crashed creation left `!in_use`-but-threaded; reads and the
            // checker thread transparently THROUGH it, so it is harmless until reclaimed. The whole-store
            // corpse walk runs ONLY when a rolled-back creation may have left one (`pending_corpse_rels`
            // non-empty) or on the first post-open pass — a no-abort workload skips it entirely. The splice
            // is walk-driven (re-derives each corpse's true chain position), so it never severs a live chain.
            if self.gc_full_scan_pending || !self.pending_corpse_rels.is_empty() {
                self.bump_drain_progress();
                reclaimed += self.gc_splice_corpses(txn)?;
                self.pending_corpse_rels.clear();
            }

            // ---- Phase C: reclaim reclaimable NODE tombstones (pending-set driven). ----
            // A node is reclaimed only once no live (not-yet-reclaimed) relationship still references it, so
            // referential integrity and the incidence chains stay well-formed throughout.
            reclaimed += self.reclaim_pending(StoreKind::Node, txn, watermark)?;

            // ---- Phase F: reclaim undo chains no live snapshot can reach (`rmp` #966). ----
            // Runs after the node/relationship sweeps, so an entity reclaimed above has already had
            // its own chain freed with it and is not walked again here. Candidate-set driven exactly
            // as Phases A–C are, with the same first-post-open full-scan seeding.
            //
            // ORDER (`rmp` #967): it runs BEFORE the property sweep, and that is a LATENCY choice,
            // not a correctness one. Phase D reclaims an empty property cell only once its owner's
            // `undo_ptr` is `0` — a conservative, O(1) proof that Phase F has already retired the
            // owner's whole history, NOT (as an earlier version of this comment claimed) because a
            // reconstruction could land in the cell; it never does, and
            // [`gc_property_chain`](Self::gc_property_chain) documents the worked counter-example.
            // Running D first would therefore find every just-written owner still chained and defer
            // every empty cell to the next pass. Freeing the chains first restores single-pass
            // reclamation: F clears `undo_ptr`, D then sees an unchained owner. Both orders are
            // correct; this one is one pass faster and keeps the property store's steady-state
            // footprint independent of the GC cadence.
            self.bump_drain_progress();
            undo_deltas_reclaimed = self.gc_reclaim_undo_chains(txn, watermark)?;

            // ---- Phase D: sweep PROPERTY chains, gated (`rmp` #522). ----
            // Reclaims **empty** property cells (`rmp` #967, `D-property-removal`) and dead-link
            // property corpses (#172) from every surviving owner's chain. The full owner walk runs
            // ONLY when an empty cell or a corpse may exist (`pending_empty_prop_cells`,
            // `pending_prop_corpses`, or the first post-open pass) — a workload with no property
            // removals or aborts skips it. A reclaimed owner's whole chain was already freed by its
            // reclamation, so re-checking liveness here reclaims each once.
            if self.gc_full_scan_pending
                || self.pending_empty_prop_cells
                || self.pending_prop_corpses
            {
                let sweep = self.sweep_property_chains(txn, watermark)?;
                reclaimed += sweep.reclaimed;
                // A corpse is reclaimed unconditionally by the walk that finds it, so the corpse gate
                // is genuinely satisfied by one sweep. An EMPTY CELL is not: it is deferred whenever
                // the watermark has not passed the write that emptied it, or the owner still holds a
                // chain. Re-arm the gate from what the sweep actually saw, so a pass that reclaimed
                // nothing does not disarm it (`rmp` #967 audit — a long-running reader used to leave
                // the cells stranded until an unrelated removal re-armed the flag or the store
                // reopened). This is the on-disk-derived, self-healing signal the retired
                // `pending_tombstones[Prop]` gate had, recovered without its per-id bookkeeping.
                self.pending_prop_corpses = false;
                self.pending_empty_prop_cells = sweep.deferred_empty > 0;
                self.prune_settled_tombstones(StoreKind::Prop)?;
            }
        }

        // ---- Phase E: freeze committed-but-unfrozen MVCC stamps (`rmp` task #59), frontier-based. ----
        // Settle every surviving committed in-flight stamp to its durable `Committed(ts)` form across the
        // three MVCC record stores (heap blocks carry no version stamps). Was an O(store)
        // `scan_in_use_mvcc` per kind every tick; now the freeze frontier (`freeze_low`) starts each scan
        // at the smallest id that may still bear an unfrozen stamp, so a steadily-growing store freezes
        // only the records added since the last pass (`rmp` #522). Runs AFTER the reclamation sweeps so
        // reclaimed slots (no longer `in_use`) are skipped. After this pass no in-use record references
        // any writer the registry records as committed, which is the precondition for the prune below.
        let mut frozen = 0usize;
        let mut freeze_scanned = 0u64;
        for kind in [StoreKind::Rel, StoreKind::Node, StoreKind::Prop] {
            self.bump_drain_progress();
            let (f, s) = self.freeze_store_headers_incremental(txn, kind)?;
            frozen += f;
            freeze_scanned += s;
        }

        // The first post-open pass has now discovered every pre-existing on-disk corpse/tombstone and
        // seeded the tracking sets, so subsequent passes can safely run the gated incremental sweeps.
        // A freeze-only pass (`rmp` #590) SKIPPED those seeding scans (Phases A–D), so it must NOT clear
        // the flag — the next FULL pass still owes the one-time seeding scan (a freeze-only pass never
        // relies on the tracking sets, since it reclaims nothing).
        if !freeze_only {
            self.gc_full_scan_pending = false;
        }

        // `rmp` #522 (durability-audit W1 regression guard): before scheduling the prune that will
        // forget every committed writer, assert the freeze sweep actually settled ALL of their on-disk
        // in-flight stamps — the invariant the prune's soundness rests on (a stranded committed stamp
        // whose writer is forgotten reads as invisible: silent lost committed data). This FULL-store
        // scan is compiled out (costs nothing) in an ordinary release build; it stays the strongest
        // guarantee under `debug_assertions`/`check-cold-assert`. See [`debug_assert_freeze_complete`].
        self.debug_assert_freeze_complete();

        // `rmp` #809: the always-on, release-active counterpart of the guard above. It re-verifies the
        // SAME invariant over a bounded rotating id window (so full-store coverage every N passes at a
        // fixed O(window) per-pass cost), and reports any stranded committed stamp it finds — the tier
        // that runs in production, where the full scan does not. See [`audit_freeze_frontier_window`].
        let (freeze_violations, first_freeze_violation) = self.audit_freeze_frontier_window();

        if freeze_violations == 0 {
            // Normal path: schedule the table prune. Every writer recorded as committed at this point had
            // ALL of its on-disk in-flight stamps rewritten by the freeze sweep (the frontier invariant
            // guarantees no in-use record below `freeze_low` bears an unfrozen committed stamp, and the
            // sweep froze the rest), so each becomes forgettable the moment the freeze is durable — i.e.
            // when `txn` commits. The GC transaction itself, and any transaction that commits between
            // here and that commit, is not in this set and is pruned by a later pass.
            let writers = self.commit_registry.committed_writers();
            let prune_scheduled = writers.len();
            self.pending_gc_prune = Some(PendingGcPrune {
                gc_txn: txn,
                writers,
            });
            Ok(GcPassReport {
                reclaimed,
                undo_deltas_reclaimed,
                frozen,
                prune_scheduled,
                freeze_scanned,
                freeze_violations: 0,
                first_freeze_violation: None,
            })
        } else {
            // `rmp` #809 fail-closed response: a committed stamp is stranded unfrozen below the frontier,
            // so pruning now would forget a writer that a live version still needs to resolve — the exact
            // `rmp` #522 silent-committed-data-loss failure. **Skip the prune this pass** (leave every
            // committed writer in the Active/Recent Transaction Table, so its version stays visible) and
            // surface the violation to the caller for the operator alert. This is strictly safer than
            // pruning-then-losing-data, and safer than aborting the whole database on a durability path (a
            // false abort is itself a durability hazard); a later pass reprunes once the condition clears.
            // Not scheduling `pending_gc_prune` mirrors exactly what a rolled-back GC pass does.
            Ok(GcPassReport {
                reclaimed,
                undo_deltas_reclaimed,
                frozen,
                prune_scheduled: 0,
                freeze_scanned,
                freeze_violations,
                first_freeze_violation,
            })
        }
    }

    /// **Release-active freeze-frontier audit** (`rmp` #809) — the always-on counterpart of
    /// [`debug_assert_freeze_complete`](Self::debug_assert_freeze_complete). Called by
    /// [`gc`](Self::gc)/[`gc_freeze_only`](Self::gc_freeze_only) after the freeze sweep and immediately
    /// before the registry prune, in **every** build (not just debug/`check-cold-assert`).
    ///
    /// It re-verifies the `rmp` #522 prune-soundness invariant — *no in-use MVCC record still bears an
    /// unfrozen committed-writer in-flight stamp* — using the exact [`frozen_word`](Self::frozen_word)
    /// predicate the sweep clears (`frozen_word(word).is_some()` ⇔ an unfrozen committed stamp). The
    /// difference from the debug guard is **cost, not correctness**: the debug guard scans the *whole*
    /// store on every prune (O(store), too dear for production); this scans a fixed-size id **window**
    /// (`FREEZE_AUDIT_WINDOW_IDS` ids of each MVCC store) and advances a per-kind rotating cursor, so the
    /// per-pass cost is `O(window)` — constant, independent of store size — and the whole id space is
    /// re-verified every `⌈high_water / FREEZE_AUDIT_WINDOW_IDS⌉` passes.
    ///
    /// **Detection latency.** A *systematic* freeze-frontier regression (the real failure mode: e.g. the
    /// dead `outcome == InFlight` predicate that caused `rmp` #522) strands committed stamps *densely* —
    /// essentially every record a GC pass raised the frontier past while a writer was in flight — so the
    /// window hits one within a handful of passes (O(1) in the density). An *isolated* single stranding
    /// is caught within one full sweep of the id space (the bound above). Either way this is eventual, not
    /// per-prune, detection — acceptable for a defense-in-depth guard over a path already audited SOUND,
    /// and the caller's fail-closed prune-skip means the FIRST detection prevents the data loss regardless
    /// of how many passes it took (the writers are not forgotten until a clean pass finds zero violations).
    ///
    /// Returns `(violation_count, first_violation)` for this pass's windows. Read-only + best-effort: a
    /// page-read error surfaces nothing and leaves the cursor put (the next pass retries) rather than
    /// failing the GC pass — a transient read fault must not turn a maintenance tick into an abort.
    fn audit_freeze_frontier_window(&mut self) -> (u64, Option<FreezeFrontierViolation>) {
        let mut violations = 0u64;
        let mut first: Option<FreezeFrontierViolation> = None;
        // The three MVCC stores (heap `Strings` blocks carry no version stamps). Each advances its own
        // window cursor every pass, so total per-pass cost is `3 * O(FREEZE_AUDIT_WINDOW_IDS)`.
        for kind in [StoreKind::Node, StoreKind::Rel, StoreKind::Prop] {
            let ki = kind as usize;
            let from = self.freeze_audit_from[ki];
            let (records, next_from) = match read_view::scan_in_use_mvcc_window(
                &self.pool,
                &self.stores,
                kind,
                from,
                FREEZE_AUDIT_WINDOW_IDS,
            ) {
                Ok(v) => v,
                // Best-effort: a read fault must never fail the maintenance pass. Leave the cursor so the
                // next pass re-covers this window; report no violation (we simply did not observe here).
                Err(_) => continue,
            };
            for (id, mvcc) in records {
                // The SAME "unfrozen committed stamp" predicate the freeze sweep clears (`frozen_word`
                // is `Some` only for an in-flight stamp whose writer the registry records as Committed).
                // A genuinely-open writer's stamp maps to `None` (correctly not a violation — it is frozen
                // once that writer commits), so this never fires on legitimately in-flight data.
                if self.frozen_word(mvcc.created_ts).is_some()
                    || self.frozen_word(mvcc.expired_ts).is_some()
                {
                    violations += 1;
                    if first.is_none() {
                        first = Some(FreezeFrontierViolation {
                            kind,
                            id,
                            xmin: mvcc.created_ts,
                            xmax: mvcc.expired_ts,
                        });
                    }
                }
            }
            // Advance the rotating cursor: resume at `next_from`, or wrap to `1` once the window reached
            // this store's high-water (a full sweep of its id space is complete).
            let high_water = self.store(kind).alloc.high_water();
            self.freeze_audit_from[ki] = if next_from >= high_water {
                1
            } else {
                next_from
            };
        }
        (violations, first)
    }

    /// Reads just the 25-byte MVCC header of record `id` in `kind`'s store (freeze-sweep helper —
    /// avoids decoding the full record when only the header words matter).
    fn read_mvcc(&self, kind: StoreKind, id: u64) -> Result<MvccHeader> {
        read_view::read_mvcc(&self.pool, &self.stores, kind, id)
    }

    /// The `Committed(ts)` word to freeze `word` to, if it is the in-flight stamp of a writer the
    /// Active/Recent Transaction Table records as committed (`rmp` task #59). `None` for the `0`
    /// sentinel, an already-committed stamp, and a still-in-flight or aborted writer (an aborted
    /// writer's stamps are reverted by its rollback's WAL undo, never frozen).
    fn frozen_word(&self, word: u64) -> Option<u64> {
        match VersionStamp::from_raw(word) {
            VersionStamp::InFlight(writer) => match self.commit_registry.outcome(writer) {
                TxnOutcome::Committed(ts) => Some(VersionStamp::committed(ts)),
                TxnOutcome::InFlight | TxnOutcome::Aborted => None,
            },
            VersionStamp::None | VersionStamp::Committed(_) => None,
        }
    }

    /// **Debug-only invariant check** for the `rmp` #522 incremental-freeze prune (the W1 regression
    /// guard from the 2026-07 durability audit). Called by [`gc`](Self::gc) after the freeze sweep and
    /// immediately before it schedules the Active/Recent-Transaction-Table prune: it asserts that **no
    /// in-use record in any MVCC store still bears an unfrozen committed-writer in-flight stamp**.
    ///
    /// That is exactly the precondition the prune's soundness rests on — every writer the registry
    /// records as `Committed` must have had *all* of its on-disk in-flight stamps rewritten to
    /// `Committed(ts)` by the freeze sweep — and it holds only if the incremental freeze frontier
    /// (`freeze_low`) actually covered every such record. The **full-range** scan here (not just
    /// `[freeze_low, high_water)`) is what surfaces a stamp stranded **below** the frontier;
    /// [`frozen_word`](Self::frozen_word)`.is_some()` is the exact "unfrozen committed stamp" predicate
    /// the sweep clears. A firing means a committed version would be forgotten while still keyed by an
    /// unresolvable in-flight `TxnId` — which [`is_visible`](graphus_txn::is_visible) reads as
    /// **invisible**, i.e. silent lost committed data (the class the frontier carry-forward fix in
    /// [`is_inflight_of_inflight_writer`](Self::is_inflight_of_inflight_writer) closes). Compiled out in
    /// an ordinary release build (the full-store scan is O(store) per GC pass), but **opt-in for release**
    /// via the `check-cold-assert` feature (`rmp` #596): a paranoid deployment or a release certification
    /// run can enable it to get an always-on runtime guard against this silent-lost-committed-data class,
    /// not just the debug/DST coverage.
    #[cfg(any(debug_assertions, feature = "check-cold-assert"))]
    fn debug_assert_freeze_complete(&self) {
        for kind in [StoreKind::Rel, StoreKind::Node, StoreKind::Prop] {
            let in_use = read_view::scan_in_use_mvcc(&self.pool, &self.stores, kind)
                .expect("W1 freeze-completeness guard reads only in-use MVCC headers");
            for &(id, mvcc) in &in_use {
                assert!(
                    self.frozen_word(mvcc.created_ts).is_none()
                        && self.frozen_word(mvcc.expired_ts).is_none(),
                    "rmp #522 freeze-frontier invariant VIOLATED: in-use {kind:?} record {id} still \
                     bears an unfrozen committed-writer in-flight stamp (xmin={:#018x}, \
                     xmax={:#018x}) after the freeze sweep. Its writer committed but the incremental \
                     freeze never settled the stamp (the frontier was raised past it), so forgetting \
                     that writer at the prune below would make its committed version read as INVISIBLE \
                     (silent lost committed data).",
                    mvcc.created_ts,
                    mvcc.expired_ts,
                );
            }
        }
    }

    /// Release-build no-op counterpart of the W1 freeze-completeness guard (`rmp` #522/#596): the
    /// full-store scan it performs is O(store) per GC pass, so it costs nothing in an ordinary optimized
    /// build (enable the `check-cold-assert` feature to run it in release — see the active counterpart).
    #[cfg(not(any(debug_assertions, feature = "check-cold-assert")))]
    #[inline]
    fn debug_assert_freeze_complete(&self) {}

    /// Freezes **every** committed-but-unfrozen MVCC header in all three record stores under `txn`,
    /// settling each in-flight `TxnId` stamp to its durable `Committed(ts)` form (the freeze sweep of
    /// [`gc`](Self::gc), without any reclamation). After this commits, every committed version on disk
    /// carries a self-describing commit timestamp, so the image is **MVCC-resolvable without the WAL's
    /// commit records** — which is exactly what a backup needs: a restored store opens with a *fresh*
    /// WAL (the backup carries the data image, not the log), so any header still keyed by an in-flight
    /// `TxnId` would be unresolvable and read as invisible. Freezing before capture makes the backup
    /// base self-sufficient (`rmp` task #149; this also closes the same latent gap for the full-backup
    /// path of `rmp` task #23 — a backup taken before any GC pass had frozen recent commits).
    ///
    /// `txn` must be a fresh, not-yet-begun id; the caller drives `begin(txn)` → this →
    /// `commit(txn)`. Returns the number of header words frozen.
    ///
    /// # Errors
    /// Returns a storage error if a header read or a freeze patch write fails.
    pub fn freeze_committed_headers(&mut self, txn: TxnId) -> Result<usize> {
        let mut frozen = 0usize;
        frozen += self.freeze_store_headers(txn, StoreKind::Rel)?;
        frozen += self.freeze_store_headers(txn, StoreKind::Node)?;
        frozen += self.freeze_store_headers(txn, StoreKind::Prop)?;
        // Schedule the same Active/Recent Transaction Table prune `gc` does: the sweep rewrote every
        // committed writer's on-disk in-flight stamps, so each becomes forgettable once this freeze is
        // durable (when `txn` commits). Mirrors `gc`'s prune scheduling so the table stays bounded.
        let writers = self.commit_registry.committed_writers();
        let prune_scheduled = writers.len();
        if prune_scheduled > 0 {
            self.pending_gc_prune = Some(PendingGcPrune {
                gc_txn: txn,
                writers,
            });
        }
        Ok(frozen)
    }

    /// Freezes the MVCC headers of every in-use record in `kind`'s store (`rmp` task #59): each
    /// `xmin`/`xmax` word carrying a committed writer's in-flight `TxnId` is rewritten to its
    /// `Committed(ts)` form via the same WAL-logged 8-byte header patch as a tombstone or the old
    /// eager commit settle ([`patch_header_word`](Self::patch_header_word)), under the GC `txn`.
    /// Walks the full physical-id range `1..high_water`, so the sweep is complete regardless of
    /// chain reachability. Returns the number of header words frozen.
    fn freeze_store_headers(&mut self, txn: TxnId, kind: StoreKind) -> Result<usize> {
        // Page-batched read (`rmp` #365): read every in-use record's MVCC header with ONE pin + read
        // latch per store page (was one `read_mvcc` — one latch — per id), then freeze the committed-
        // but-unfrozen words id-by-id. `scan_in_use_mvcc` already filters to `in_use`, so the freed-
        // slot skip the former loop did per id is folded into the scan. The freeze itself
        // (`patch_header_word`) is a WAL-logged 8-byte patch under the per-record **write** latch — the
        // read is batched, the mutating write is not (no latch downgrade).
        let in_use = read_view::scan_in_use_mvcc(&self.pool, &self.stores, kind)?;
        let mut frozen = 0usize;
        for (i, &(id, mvcc)) in in_use.iter().enumerate() {
            if let Some(word) = self.frozen_word(mvcc.created_ts) {
                self.patch_header_word(kind, id, MVCC_OFF_CREATED_TS, word, txn)?;
                frozen += 1;
            }
            if let Some(word) = self.frozen_word(mvcc.expired_ts) {
                self.patch_header_word(kind, id, MVCC_OFF_EXPIRED_TS, word, txn)?;
                frozen += 1;
            }
            // Heartbeat the drain-progress beacon across this O(N) freeze sweep (`rmp` #563).
            if i % 4096 == 0 {
                self.bump_drain_progress();
            }
        }
        Ok(frozen)
    }

    /// The incremental freeze sweep of [`gc`](Self::gc) (`rmp` #522): freezes committed-but-unfrozen
    /// MVCC stamps in `kind`'s store, but starting the scan at the **freeze frontier**
    /// [`freeze_low[kind]`](Self::freeze_low) instead of at id `1`. On a steadily-growing store this
    /// visits only the records added since the last pass — the fix for the O(store²) maintenance cost.
    ///
    /// Correctness rests on the frontier invariant (see [`freeze_low`](Self::freeze_low)): every in-use
    /// record below `freeze_low[kind]` already has all committed-writer stamps frozen and bears no
    /// in-flight-writer stamp. A fresh in-flight stamp below the frontier lowers it
    /// ([`note_created`](Self::note_created) / [`note_expired`](Self::note_expired)), and a committed
    /// writer's stamps always sit at or above the frontier (nothing below it was in-flight), so this
    /// bounded scan still freezes **every** committed writer's stamps — the precondition the GC prune
    /// relies on. After the scan the frontier is raised to the smallest id still bearing an
    /// in-flight-writer stamp (or `high_water` if none remain).
    ///
    /// It also (re)seeds [`pending_tombstones[kind]`](Self::pending_tombstones) from every tombstone it
    /// observes, which — because the first post-open pass starts at `freeze_low == 1` (a full scan) —
    /// discovers every pre-existing on-disk tombstone that a fresh process has no in-memory record of.
    fn freeze_store_headers_incremental(
        &mut self,
        txn: TxnId,
        kind: StoreKind,
    ) -> Result<(usize, u64)> {
        let from = self.freeze_low[kind as usize];
        let high_water = self.store(kind).alloc.high_water();
        let scanned = high_water.saturating_sub(from.max(1));
        let in_use = read_view::scan_in_use_mvcc_from(&self.pool, &self.stores, kind, from)?;
        let mut frozen = 0usize;
        // The next frontier: the smallest id in the scanned range still bearing an in-flight-writer
        // stamp after this pass. If none, advance to `high_water` (everything at/above `from` settled).
        let mut new_low = high_water;
        for (i, &(id, mvcc)) in in_use.iter().enumerate() {
            if let Some(word) = self.frozen_word(mvcc.created_ts) {
                self.patch_header_word(kind, id, MVCC_OFF_CREATED_TS, word, txn)?;
                frozen += 1;
            }
            if let Some(word) = self.frozen_word(mvcc.expired_ts) {
                self.patch_header_word(kind, id, MVCC_OFF_EXPIRED_TS, word, txn)?;
                frozen += 1;
            }
            // A tombstone (in-use, `xmax` set) is a reclaim candidate — seed the reclaim set (idempotent).
            if mvcc.expired_ts != 0 {
                self.pending_tombstones[kind as usize].insert(id);
            }
            // Still bearing an in-flight-writer stamp (a committed writer's stamp was just frozen above,
            // so it no longer counts)? Then it must stay covered by the frontier for a later pass.
            if self.is_inflight_of_inflight_writer(mvcc.created_ts)
                || self.is_inflight_of_inflight_writer(mvcc.expired_ts)
            {
                new_low = new_low.min(id);
            }
            if i % 4096 == 0 {
                self.bump_drain_progress();
            }
        }
        self.freeze_low[kind as usize] = new_low;
        Ok((frozen, scanned))
    }

    /// Whether `word` is an in-flight stamp of a writer that is **still open** (`rmp` #522, the
    /// freeze-frontier's carry-forward test): such a stamp cannot be frozen yet — its writer has not
    /// committed, so [`frozen_word`](Self::frozen_word) declines it — and its record MUST stay covered
    /// by the frontier so a later pass (after the writer commits) freezes it. A committed-writer stamp
    /// (frozen this pass) and an aborted-writer stamp (reverted by that writer's undo) both return
    /// `false`.
    ///
    /// **Openness is tested against the store's [`active`](Self#structfield.active) set, NOT
    /// `commit_registry.outcome(w) == InFlight`.** The [`CommitRegistry`] only ever records a writer at
    /// *commit* ([`record_commit`](graphus_txn::CommitRegistry)) — a begun-but-uncommitted writer has
    /// no entry, and [`outcome`](graphus_txn::CommitRegistry::outcome) maps an unknown id to
    /// `Aborted`, never `InFlight`. So the old `outcome(w) == InFlight` predicate was **dead — always
    /// `false`** — which raised the frontier PAST records still bearing a genuinely open writer's
    /// stamp whenever a maintenance GC ran while that writer was in-flight (an explicit `BEGIN … RUN
    /// …` spanning engine commands). When the writer then committed, the next incremental sweep skipped
    /// those records (now below the frontier), left their committed stamps **unfrozen**, and the GC
    /// prune forgot the writer — so [`is_visible`](graphus_txn::is_visible) resolved the version's
    /// stamp against a now-unknown (→ aborted) writer and read the committed value as **invisible**:
    /// silent lost committed data (regression `tests/incremental_freeze_inflight_writer.rs`). Testing
    /// live membership in `active` is the correct "the writer might still commit, so keep covering it"
    /// signal.
    fn is_inflight_of_inflight_writer(&self, word: u64) -> bool {
        matches!(VersionStamp::from_raw(word), VersionStamp::InFlight(w)
            if self.is_txn_active(w))
    }

    /// Reclaims the reclaimable MVCC tombstones of `kind` (`Rel` or `Node`) under `txn` (`rmp` #522).
    /// Iterates only the tracked [`pending_tombstones[kind]`](Self::pending_tombstones) set — with a
    /// full-store fallback on the first post-open pass (`gc_full_scan_pending`), which also seeds the set
    /// from every pre-existing on-disk tombstone. A candidate whose `xmax` has committed at or before
    /// `watermark` (and, for a node, that no live relationship still references) is reclaimed and dropped
    /// from the set; a candidate that is no longer an in-use tombstone (already reclaimed, or reverted to
    /// live by an abort) is dropped; the rest stay pending for a later pass. Returns the count reclaimed.
    fn reclaim_pending(
        &mut self,
        kind: StoreKind,
        txn: TxnId,
        watermark: Timestamp,
    ) -> Result<usize> {
        let candidates: Vec<u64> = if self.gc_full_scan_pending {
            // First post-open pass: discover every on-disk tombstone by a full scan (and seed the set).
            read_view::scan_in_use_mvcc(&self.pool, &self.stores, kind)?
                .into_iter()
                .filter(|&(_, m)| m.expired_ts != 0)
                .map(|(id, _)| id)
                .collect()
        } else {
            self.pending_tombstones[kind as usize]
                .iter()
                .copied()
                .collect()
        };
        let mut reclaimed = 0usize;
        for (i, id) in candidates.into_iter().enumerate() {
            let mvcc = self.read_mvcc(kind, id)?;
            // Not (any longer) an in-use tombstone: drop the stale entry.
            if !(mvcc.in_use() && mvcc.expired_ts != 0) {
                self.pending_tombstones[kind as usize].remove(&id);
                continue;
            }
            let reclaimable = Self::is_reclaimable(mvcc, watermark, &self.commit_registry)
                && (kind != StoreKind::Node || !self.has_live_incident_rels(id)?);
            if reclaimable {
                match kind {
                    StoreKind::Rel => self.reclaim_rel(txn, id)?,
                    StoreKind::Node => self.reclaim_node(txn, id)?,
                    // Only nodes and relationships are entity tombstones. Property versions are
                    // reclaimed by the Phase D chain sweep; heap blocks and the undo area's records
                    // carry no visibility of their own and are freed with whatever owns them.
                    StoreKind::Prop | StoreKind::Strings | StoreKind::Undo | StoreKind::Commit => {}
                }
                self.pending_tombstones[kind as usize].remove(&id);
                reclaimed += 1;
            } else {
                // Still a tombstone but not yet reclaimable (watermark hasn't passed, or a live node
                // still references it): keep it pending. `insert` seeds it on the full-scan path.
                self.pending_tombstones[kind as usize].insert(id);
            }
            if i % 4096 == 0 {
                self.bump_drain_progress();
            }
        }
        Ok(reclaimed)
    }

    /// The property-chain sweep of [`gc`](Self::gc) (`rmp` #522, Phase D): for every surviving live node
    /// and relationship owner, [`gc_property_chain`](Self::gc_property_chain) reclaims its **empty**
    /// property cells (`rmp` #967) and its dead-link property corpses. Gated by the caller so it runs
    /// only when an empty cell or a corpse may exist.
    ///
    /// Returns the whole-sweep [`PropChainSweep`]: what it freed, and — the number the caller's gate
    /// depends on — how many empty cells it saw and had to defer. Because this walks **every**
    /// surviving owner, `deferred_empty == 0` is a complete statement about the store, which is what
    /// makes it safe to disarm the gate on (`rmp` #967 audit).
    fn sweep_property_chains(
        &mut self,
        txn: TxnId,
        watermark: Timestamp,
    ) -> Result<PropChainSweep> {
        let mut total = PropChainSweep::default();
        self.bump_drain_progress();
        let node_live = read_view::scan_in_use_mvcc(&self.pool, &self.stores, StoreKind::Node)?;
        for (i, &(id, mvcc)) in node_live.iter().enumerate() {
            if Self::is_live_version(mvcc) {
                total += self.gc_property_chain(txn, StoreKind::Node, id, watermark)?;
            }
            if i % 4096 == 0 {
                self.bump_drain_progress();
            }
        }
        self.bump_drain_progress();
        let rel_live = read_view::scan_in_use_mvcc(&self.pool, &self.stores, StoreKind::Rel)?;
        for (i, &(id, mvcc)) in rel_live.iter().enumerate() {
            if Self::is_live_version(mvcc) {
                total += self.gc_property_chain(txn, StoreKind::Rel, id, watermark)?;
            }
            if i % 4096 == 0 {
                self.bump_drain_progress();
            }
        }
        Ok(total)
    }

    /// Drops entries from [`pending_tombstones[kind]`](Self::pending_tombstones) whose record is no
    /// longer an in-use tombstone (`rmp` #522) — reclaimed (by the property sweep) or reverted to live
    /// by an abort. Keeps the pending set bounded to the still-pending tombstones.
    fn prune_settled_tombstones(&mut self, kind: StoreKind) -> Result<()> {
        let ids: Vec<u64> = self.pending_tombstones[kind as usize]
            .iter()
            .copied()
            .collect();
        for id in ids {
            let mvcc = self.read_mvcc(kind, id)?;
            if !(mvcc.in_use() && mvcc.expired_ts != 0) {
                self.pending_tombstones[kind as usize].remove(&id);
            }
        }
        Ok(())
    }

    /// Rolls `txn` back: undoes its logged page changes newest-first (writing CLRs and applying
    /// the compensating images to the cached pages), then reloads the catalog from the now-reverted
    /// metadata page so the in-memory allocators, free lists and tokens match (`04 §4.4`).
    ///
    /// Note: catalog state (token interning, id high-water, free-list, page growth) is only
    /// persisted at commit, so an aborted transaction's catalog effects are discarded by the
    /// reload. The page growth itself is not reverted (a grown device page is harmless: it holds no
    /// live records and will be reused), matching the "physical ids may be reused" model (`04 §2.7`).
    ///
    /// # Failure leaves the transaction OPEN (`rmp` #955)
    ///
    /// The active-set entry is released only once **every** fallible step below has succeeded. A
    /// rollback that fails — or that unwinds on the WAL `fdatasync` panic — therefore leaves `txn`
    /// in the active set, where [`is_txn_active`](Self::is_txn_active) and
    /// [`uncommitted_data_writer`](Self::uncommitted_data_writer) keep reporting it as a live writer
    /// holding uncommitted state. That is the truth: its effects were not undone, so every gate that
    /// asks "may I decide the committed image right now?" must keep answering *no*.
    ///
    /// The store cannot repair itself from here — the undo is not restartable from an arbitrary
    /// mid-point — so the caller MUST treat an `Err` (or a caught unwind) as a hard failure of this
    /// database and stop serving over the suspect in-memory state; on the server that is the
    /// per-engine degraded flag (`rmp` #409/#414), which is per-database and never fleet-wide. What
    /// the caller must NOT do is drop the entry to "tidy up": that flips the `rmp` #902 constraint-DDL
    /// guard from fail-safe to fail-open at exactly the moment it matters most.
    ///
    /// # Errors
    /// Returns a storage error if undo apply fails or the catalog cannot be reloaded.
    ///
    /// # Panics
    /// Panics if the WAL `fdatasync` fails (`04 §4.9`).
    pub fn rollback(&mut self, txn: TxnId) -> Result<()> {
        // PEEK at this transaction's pending catalog DDL — do NOT take the entry (`rmp` #955). The
        // entry stays in `active` across every fallible step below and is removed only once they have
        // all succeeded; see the method docs. The `pre_statistics` guard further down is the one thing
        // that needs to know, before the undo runs, whether this transaction holds DDL of its own.
        let holds_schema_undo = self
            .active
            .get(&txn)
            .is_some_and(|a| !a.schema_undo.is_empty());
        // Snapshot the in-memory free lists BEFORE the catalog reload (`rmp` #578). The free list has
        // the SAME monotonicity hazard as the high-water / token / device-page state restored below,
        // but — unlike them — is NOT monotonic (ids are popped as well as pushed), so it cannot use a
        // simple floor. `reload_catalog` resets it to the last DURABLY-COMMITTED image, yet under
        // STATEMENT-granularity interleaving a still-open CONCURRENT transaction may already have
        // POPPED a freed id (via `alloc_id`): re-listing the committed image would hand that id out
        // AGAIN, so two live records would share one physical slot and their property / incidence
        // chains self-cycle (the #578 "malformed (cycle?)"). This pre-rollback snapshot already
        // reflects every concurrent pop (and this txn's own pushes), so restoring IT — minus this
        // txn's own pushes — is the free-list twin of the #220/#172 high-water floor.
        let pre_free: [FreeList; STORE_COUNT] =
            std::array::from_fn(|i| self.stores[i].free.clone());
        // The live-record COUNTERS have exactly the same hazard, for exactly the same reason (`rmp`
        // #866). They move eagerly at write time, so the in-memory value is "durable image + every
        // in-flight transaction's delta", and `reload_catalog` below throws all of that away. Snapshot
        // them now — the snapshot already reflects every CONCURRENT open transaction's increments and
        // decrements — so that after the reload the counters can be restored to this image MINUS this
        // transaction's own delta (`aborted_counts`, withdrawn below). That is the free-list
        // `pre_free`-minus-`aborted_freed_ids` shape, applied to the counts.
        //
        // Captured UNCONDITIONALLY, unlike the `rmp` #534 `pre_statistics` below. That capture is
        // guarded on "some transaction holds pending DDL", but a plain data-writing transaction holds
        // pending COUNTS with an empty `schema_undo`, so the guard does not cover this half. Cloning
        // only the counts (never the twelve DDL maps) keeps the unconditional capture cheap: it is
        // bounded by the number of distinct labels/relationship types in the schema, not by the number
        // of records the transaction touched.
        let pre_counts = self.statistics.counts_image();
        // Capture the in-memory physical-id high-water marks BEFORE the catalog reload (`rmp` #220 /
        // #172). `reload_catalog` restores the allocators from the last COMMITTED metadata — but under
        // STATEMENT-granularity interleaving a CONCURRENT, still-open transaction may have advanced a
        // high-water by allocating its own fresh records, which are not in that committed checkpoint.
        // Reloading wholesale would lower the high-water below those ids, so a later commit of the
        // concurrent txn leaves its records OUTSIDE the scanned `1..high_water` range — invisible to
        // every label/full scan (the engine-level face of #220/#172: committed leaves/edges vanish).
        // Like device-page growth below, the physical-id high-water is monotonic and must never be
        // lowered by an unrelated txn's rollback. (A physical id once allocated to a concurrent writer
        // must not be re-handed-out either; flooring the high-water preserves that too.)
        let pre_high_water: [u64; STORE_COUNT] =
            std::array::from_fn(|i| self.stores[i].alloc.high_water());
        // Same monotonicity hazard for the **token dictionary** and the **`ElementId` allocator**
        // (`rmp` #220 / #172). `reload_catalog` resets both to the last committed catalog, but a
        // concurrent open txn may have interned a relationship-type/label/key token (e.g. `LINK`) and
        // allocated `ElementId`s for records it will soon commit. Dropping those tokens strands a
        // committed rel's `type_id` on a now-unknown token (a `[:LINK]` type filter then matches
        // nothing — the engine-level face of #220 where the typed edges "vanish"); lowering the
        // `ElementId` high-water could re-hand-out a public identity a committed record already uses.
        // Both are append-only and never reused, so a SUPERSET is always safe; preserve the richer
        // in-memory views over the committed reload (a token interned only by the aborting txn is
        // harmless to keep — an unused id, idempotent on re-intern).
        let pre_tokens = self.tokens.clone();
        let pre_element_next = self.element_ids.peek();
        // Same monotonicity hazard for the **schema-catalog** half of `Statistics` — the twelve
        // `catalog_dirty`-guarded DDL maps (declared indexes of every kind, their names, constraints,
        // property histograms) (`rmp` #534, defense-in-depth for the `rmp` #529 read-only-commit fast
        // path). `reload_catalog` reverts the WHOLE `Statistics` to the durable committed image, which
        // is correct for the live-record COUNTS (it discards this aborting txn's create/delete
        // increments) but would wipe a CONCURRENT open txn's pending catalog DDL, which — unlike a data
        // write — is durable ONLY via the commit-time `checkpoint_meta`, so wiping it (together with the
        // `catalog_dirty = false` above) lets that txn's later commit take the #529 fast path and
        // SILENTLY DROP its committed DDL.
        //
        // Snapshot the in-memory schema now so it can be superset-preserved after the reload — but ONLY
        // when a concurrent transaction is still open to OWN a pending DDL change. `txn`'s own entry is
        // still in `active` (it is released only after the fallible steps, `rmp` #955), so it is
        // excluded BY NAME here rather than by having already been removed. With no concurrent
        // transaction the reload is the whole story (a lone transaction's own DDL is correctly
        // discarded), so the common single-writer path clones NOTHING and is byte-identical to the
        // pre-#534 behaviour. The counts this also clones are discarded — `adopt_schema_from` moves only
        // the schema half.
        // Also snapshot when THIS transaction holds catalog DDL of its own, even with no concurrent
        // transaction open (`rmp` #734). The tempting shortcut — "alone ⇒ the reload discards exactly
        // my DDL" — is FALSE: a concurrent transaction that committed and has since resolved may have
        // checkpointed this transaction's still-pending DDL into the durable image on its way out, in
        // which case `reload_catalog` restores that DDL rather than discarding it, and the undo below
        // is the only thing that removes it. (`committed_statistics` stops new checkpoints from
        // capturing pending DDL; this keeps the rollback correct regardless.) A transaction with no
        // catalog DDL and no concurrent transaction still clones nothing — the common path is unchanged.
        let pre_statistics = (self.active.keys().any(|t| *t != txn) || holds_schema_undo)
            .then(|| self.statistics.clone());
        // ------------------------------------------------------------------------------------------
        // FALLIBLE SECTION (`rmp` #955). Everything from here to `reload_catalog` can fail — with an
        // `Err` from the pool/catalog, or by unwinding out of the WAL `fdatasync` panic. NOTHING in it
        // may release or mutate this transaction's bookkeeping: its active-set entry, its count delta,
        // its schema undo log, the scheduled GC prune and the freeze-frontier savepoint all stay
        // exactly as they were, so a failure leaves `txn` a fully-formed open writer rather than a
        // half-dismantled one. That is why the entry is removed BELOW this section and not above it,
        // and why the removal needs no unwind guard: an entry that is never taken cannot be dropped on
        // the way out.
        // ------------------------------------------------------------------------------------------
        // `rmp` #337, Slice 1: drive the WAL rollback with a *recording* target that captures the
        // compensating page images WITHOUT touching the pool while the WAL lock is held, then replay
        // them into the pool AFTER the lock is released. This breaks the eviction-during-rollback
        // reentrancy that would otherwise deadlock the shared WAL handle (it panicked as a RefCell
        // double-borrow under the old single-threaded handle when a rollback's working set exceeded
        // the pool capacity). The WAL `rollback` hardens the CLRs + ABORT before returning, so the
        // CLRs are durable before any pool write here; a crash between the durable ABORT and this
        // replay is recovered identically by ARIES redo of the CLRs (see `mod pool_target`).
        let mut target = pool_target::RecordingTarget::new();
        self.wal.with(|w| w.rollback(txn, &mut target))?;
        // Lock-free replay: the WAL lock is released, so an eviction triggered by these `fetch`es can
        // take it with no holder. Stamp each page's `page_lsn` to the CLR's lsn via
        // `with_page_mut_lsn` so a dirty replayed page written home later carries a real redo LSN
        // (the WAL-before-data invariant — a page_lsn of 0 would make the pool's `ensure_durable(0)`
        // a no-op; Tier-1 storage audit F6).
        for comp in target.into_compensations() {
            let f = self.pool.fetch(comp.page)?;
            let r = self
                .pool
                .with_page_mut_lsn(f, comp.lsn, |p| paging::apply_patch(p, &comp.image));
            self.pool.unpin(f);
            r?;
        }
        // The device-page maps are NOT touched here (`rmp` #721). They used to be `std::mem::take`-n
        // out of every store, handed to `reload_catalog` (which rebuilt each store wholesale from the
        // durable catalog, shrinking the map back to the last committed prefix), and then re-extended
        // with the dropped tail — a dance whose successful path reconstructed *exactly* what it took,
        // and whose failure path had to hand-restore the maps or silently destroy committed data (the
        // seed-5043221 durability breach, `rmp` #479).
        //
        // Since #721 the map is an `Arc<PageMap>` shared LIVE with every off-thread reader, and that
        // dance is not merely unnecessary but unsound: a taken map is an EMPTY map, and a reader
        // indexing it mid-window would be told a committed record's page "is not allocated" — a worse
        // failure than the one #721 fixes. So the hazard is removed **structurally**, not patched: the
        // map is never taken, never emptied, never rebuilt. `reload_catalog` now PRESERVES each store's
        // live map (page growth is never undone, and the durable catalog's map is always a prefix of
        // it — an invariant `reload_catalog` asserts and fails closed on), so there is no window in
        // which a reader can observe anything but the true, monotone map. Exception safety is likewise
        // structural: a failing `reload_catalog` cannot strand a map it never moved.
        self.reload_catalog()?;
        // ------------------------------------------------------------------------------------------
        // UNDO SETTLED (`rmp` #955). Every fallible step has succeeded and nothing below can fail, so
        // the transaction's bookkeeping is released here — and only here.
        // ------------------------------------------------------------------------------------------
        // Drop the version-stamp bookkeeping: every stamp this txn wrote (in-flight `xmin`/`xmax`) has
        // just been reverted by the WAL undo above, and the commit timestamp was never issued (only
        // `commit` advances it), so nothing of this txn remains visible or durable. Take the removed
        // entry so we can withdraw this transaction's OWN free-list pushes below (`rmp` #578): only a
        // GC pass populates `freed_ids`; a normal write transaction's is empty. Also take its `rmp`
        // #581 pop bookkeeping (`popped_ids` / `popped_prop_owners`) so a normal write transaction's
        // own reused-id pops can be RECLAIMED to the free list after the restore below.
        // Also take its `rmp` #866 pending COUNT delta, withdrawn from the pre-rollback counter image
        // below.
        let ActiveTxn {
            created: aborted_created,
            freed_ids: aborted_freed_ids,
            popped_ids: aborted_popped_ids,
            popped_prop_owners: aborted_prop_owners,
            schema_undo: aborted_schema_undo,
            counts: aborted_counts,
            commit_slot: aborted_commit_slot,
            undo_links: aborted_undo_links,
            ..
        } = self.active.remove(&txn).unwrap_or_default();
        // The in-memory delta slab is dropped, never carried across a rollback (`rmp` #966): the
        // catalog reload below resets this store's allocator to the durable image, so a slab cursor
        // captured before it could hand out an id the allocator no longer considers taken. Dropping it
        // costs at most one page of undo slots, and only on a transaction that actually aborted.
        self.undo_slab = None;
        // Any catalog-only change this txn made has been discarded by the `reload_catalog` above (`rmp`
        // #529): clear the dirty flag so the NEXT transaction's read-only fast path is not forced onto
        // the durable path by this aborted transaction's un-persisted mutation. (A token this txn
        // interned is kept in memory by the superset restore below, but as an unused id it needs no
        // durability — it rides the next durable commit's checkpoint if a later write actually uses it.)
        // A CONCURRENT open transaction's still-pending catalog DDL, by contrast, IS restored below and
        // must stay flagged: the `rmp` #534 superset-preserve block re-sets this flag when it keeps one.
        self.catalog_dirty = false;
        // If `txn` was a GC pass, discard its scheduled registry prune (`rmp` task #59): the WAL
        // undo above restored the in-flight header stamps the freeze had rewritten, and those
        // stamps still need their Active/Recent Transaction Table entries to resolve. A rolled-back
        // GC pass must therefore prune NOTHING — otherwise a restored in-flight stamp would be
        // stranded as unresolvable (it would wrongly read as aborted).
        if self
            .pending_gc_prune
            .as_ref()
            .is_some_and(|p| p.gc_txn == txn)
        {
            self.pending_gc_prune = None;
        }
        // `rmp` #522: if `txn` is the in-progress GC pass, restore the freeze frontier its freeze sweep
        // advanced. The WAL undo above un-froze the stamps this pass had frozen (restoring them to
        // their in-flight form); without restoring the frontier those records would sit below it and the
        // next freeze sweep would skip them, stranding a committed writer's stamp unfrozen forever. Taken
        // (not just read) so a normal write transaction — whose savepoint this never is — leaves it be.
        if let Some((sp_txn, saved)) = self.gc_freeze_low_savepoint
            && sp_txn == txn
        {
            self.freeze_low = saved;
            self.gc_freeze_low_savepoint = None;
        }
        self.tokens = pre_tokens;
        // Restore the live-record COUNTERS to their pre-rollback in-memory image, then withdraw
        // exactly this transaction's own delta (`rmp` #866) — the counts twin of the `pre_free` minus
        // `aborted_freed_ids` free-list restore below.
        //
        // `reload_catalog` has just reverted them wholesale to the durable image, which is right only
        // when this transaction is the only one that ever moved them. Under statement-granularity
        // interleaving it is wrong in both directions, permanently:
        //
        // * a CONCURRENT open transaction's increments live ONLY in memory (the catalog is
        //   checkpointed at commit), so the wholesale revert WIPES them — and that transaction's own
        //   commit then checkpoints the wiped value, durably under-counting;
        // * conversely, a concurrent transaction that COMMITTED while this one was open checkpointed
        //   the live counter, which already carried THIS transaction's uncommitted increments, so the
        //   durable image this reload restores hands them back as though they had committed, durably
        //   over-counting. (`committed_statistics` now strips open transactions' counts, so new
        //   checkpoints no longer bake them; restoring the pre-rollback image rather than the durable
        //   one keeps the rollback correct regardless of what older checkpoints hold.)
        //
        // Withdrawing `aborted_counts` from the pre-rollback image discards precisely this
        // transaction's own effect and nothing else. Ordering is irrelevant — integer counts are
        // commutative and every delta is exactly invertible — which is why this needs none of the
        // generation/witness/splice machinery the schema undo below requires (see `CountDelta`).
        self.statistics.restore_counts(pre_counts);
        aborted_counts.withdraw_from(&mut self.statistics);
        // `rmp` #534: superset-preserve the schema-catalog half of `Statistics` for a CONCURRENT open
        // transaction (`pre_statistics` is `Some` exactly when one was open at capture, above).
        // `reload_catalog` reverted the whole `Statistics` to the durable image (counts AND schema);
        // the schema equals `pre_statistics`'s only when nothing is pending. When it DIVERGES, a
        // concurrent transaction holds an uncommitted catalog DDL change — restore it, and keep the
        // store flagged catalog-dirty so that transaction's later commit does NOT take the `rmp` #529
        // read-only fast path and drop it (overriding the `catalog_dirty = false` above).
        //
        // This block touches ONLY the schema half: `adopt_schema_from` moves the twelve DDL maps and
        // leaves the counters exactly as the `rmp` #866 restore above left them, which is the
        // pre-rollback image minus this transaction's own count delta. (The comment that used to
        // stand here said the counts "stay at the durable image ... correctly discarding this
        // aborting transaction's create/delete increments". That was true only when no other
        // transaction was open — the very case the rest of this method exists to handle — and it is
        // the defect #866 closes.)
        //
        // A *rolling-back* transaction's OWN pending DDL is removed from that restored image first
        // (`rmp` #734): `apply_schema_undo` walks this transaction's per-entry undo log newest-first,
        // reverting each entry it still owns to the value that entry held before it touched it. What
        // survives into `adopt_schema_from` is therefore the in-memory schema MINUS this transaction's
        // own DDL — every other open transaction's pending DDL, and nothing else.
        //
        // Before #734 the two halves could not be separated: the whole in-memory schema was preserved
        // whenever any unrelated transaction was open, so a rolling-back transaction's own DDL survived
        // its rollback (in memory and, via the next commit's `checkpoint_meta`, durably). The face of it
        // was worse than "rollback does not undo": it was NON-DETERMINISTIC, because whether the DDL was
        // discarded depended only on whether some unrelated transaction happened to be open. The comment
        // that used to stand here argued the case was unreachable, on the grounds that catalog DDL runs
        // ONLY as a yield-free auto-commit transaction. THAT PRECONDITION IS FALSE: `rmp` #572's
        // `db.resampleIndex` was the first procedure to mutate the catalog from inside a caller's
        // explicit transaction, and it reproduced exactly this. #572 then moved its own resample into a
        // private auto-commit transaction (independently correct — Neo4j schedules a background job that
        // ignores the caller's transaction), which stopped that one procedure from standing on the hole
        // without closing it. It is closed here, for every catalog mutator, reachable or not.
        //
        // With no concurrent transaction `pre_statistics` is `None` and the durable revert alone is the
        // whole story: the in-memory schema is the durable image plus this transaction's own pending DDL,
        // so reloading discards precisely that (the `rolled_back_index_declaration_is_discarded` /
        // `rolled_back_histogram_change_is_discarded` guards) and the undo log has nothing to add.
        if let Some(mut pre_statistics) = pre_statistics {
            // Borrowed in place, never moved out: a `mem::take` here would leave the witness map
            // empty if anything between the take and the restore ever unwound. `active` is borrowed
            // alongside it so a declined mutation can be spliced out of the chains the transactions
            // still open are holding — see `apply_schema_undo`.
            let Self {
                active,
                schema_last_seq,
                ..
            } = self;
            Self::apply_schema_undo(
                &mut pre_statistics,
                schema_last_seq,
                active,
                &aborted_schema_undo,
            );
            if !self.statistics.schema_eq(&pre_statistics) {
                self.statistics.adopt_schema_from(pre_statistics);
                self.catalog_dirty = true;
            }
        }
        if pre_element_next > self.element_ids.peek() {
            self.element_ids = ElementIdAllocator::new(pre_element_next);
        }
        // Floor each allocator at its pre-rollback high-water so a concurrent open txn's freshly
        // allocated (and possibly soon-committed) ids stay within the scanned range and are never
        // re-handed-out. `observe(hw - 1)` lifts the high-water to `hw` without inventing a new id.
        for (i, hw) in pre_high_water.into_iter().enumerate() {
            if hw > self.stores[i].alloc.high_water() {
                self.stores[i].alloc.observe(hw - 1);
            }
        }
        // Restore the free lists to their pre-rollback in-memory image, then withdraw exactly this
        // transaction's own pushes (`rmp` #578). Restoring `pre_free` (not the committed
        // `reload_catalog` image) preserves every CONCURRENT open transaction's pops, so a popped id
        // stays OUT of the free list and is never double-allocated. Withdrawing `aborted_freed_ids`
        // undoes a GC pass's reclamations: the WAL undo above just restored each reclaimed record's
        // `in_use` bit, so its slot must NOT remain free. A normal write transaction pushes nothing,
        // so its `pre_free` is restored verbatim. Ordering is irrelevant: `aborted_freed_ids` and the
        // concurrent pops are disjoint id sets (a popped id is off the list; a freed id was in use).
        for (i, pf) in pre_free.into_iter().enumerate() {
            self.stores[i].free = pf;
        }
        for (kind, id) in aborted_freed_ids {
            self.stores[kind as usize].free.remove_id(id);
        }
        // `rmp` #581: RECLAIM this transaction's own reused-id pops. Every pop the abort left as a
        // genuinely-unreferenced dead slot returns to the free list (bounded by the pops the txn made);
        // pops that a concurrently-committed writer turned into a live corpse are left for the #220/#172
        // GC splice, never double-freed. Runs AFTER the free-list restore above so a re-push cannot be
        // undone by it, and after the WAL undo (which reverted each pop's slot to `!in_use`).
        self.reclaim_aborted_pops(&aborted_popped_ids, &aborted_prop_owners);
        // `rmp` #966: the same question, asked of this transaction's undo-area slots. Runs AFTER the
        // free-list restore above (like `reclaim_aborted_pops`) so its pushes are not undone by it.
        self.reclaim_aborted_undo(&aborted_undo_links, aborted_commit_slot);
        // `rmp` #522: a rolled-back creation may leave a dead-link corpse — a relationship threaded in an
        // incidence chain by a concurrently-committed prepend (#220) or a property threaded in a property
        // chain (#172). Register them so the NEXT GC pass runs the corpse splice / property sweep it
        // otherwise skips. Over-inclusive by design (a non-threaded aborted creation is simply not found
        // by the walk); the alternative — never registering — would silently leak a threaded corpse once
        // the incremental sweeps stopped scanning the whole store.
        for (kind, id) in aborted_created {
            match kind {
                StoreKind::Rel => {
                    self.pending_corpse_rels.insert(id);
                }
                StoreKind::Prop => self.pending_prop_corpses = true,
                _ => {}
            }
        }
        Ok(())
    }

    /// Returns this aborting transaction's genuinely-**unused** reused-id pops to the free list
    /// (`rmp` #581) — the symmetric reclaim the #578 fix left as a documented bounded leak.
    ///
    /// A physical id this transaction popped from the free list (`popped_ids`) and then aborted was
    /// never actually consumed, so its slot ought to be free again. The WAL undo has already reverted
    /// each such slot to `!in_use`. It is safe to re-push **only** when the slot is not part of any
    /// live chain: if a concurrently-committed writer prepended onto it (the `rmp` #220/#172 pattern),
    /// the slot is a **live-referenced corpse** the GC splice owns, and re-pushing it would hand a
    /// still-threaded slot back to the allocator — the exact `rmp` #578 double-allocation, in reverse.
    /// So each pop is re-pushed only after a per-kind **referenced** check:
    ///
    /// * **Node** — a node is a chain *anchor*, never a chain member, and a committed relationship
    ///   cannot reference an uncommitted-then-aborted node (MVCC hides it). Safe once `!in_use`.
    /// * **Strings** — overflow-heap blocks are built into a property's *private* chain that is never
    ///   shared or prepended onto by another transaction, so an aborted pop is never referenced. Safe
    ///   once `!in_use`.
    /// * **Rel** — walk the two endpoint incidence chains (the endpoints live in the corpse's own
    ///   preserved body); re-push only if the slot is not threaded into either.
    /// * **Prop** — walk the recorded owner's property chain; re-push only if the slot is not threaded
    ///   into it. A popped prop with no recorded owner is conservatively NOT re-pushed (a safe leak).
    ///
    /// Best-effort and never fatal: any read/walk error skips that id (leaving it leaked, the pre-#581
    /// behaviour) rather than failing the rollback — the reclaim is a space optimisation, never a
    /// durability obligation.
    fn reclaim_aborted_pops(
        &mut self,
        popped_ids: &[(StoreKind, u64)],
        prop_owners: &[(u64, StoreKind, u64)],
    ) {
        for &(kind, id) in popped_ids {
            // Never create a duplicate free-list entry (a re-pushed id must be unique).
            if self.store(kind).free.ids().contains(&id) {
                continue;
            }
            let safe = match kind {
                // Anchors / private heap blocks: unreferenced once their slot is reverted to `!in_use`.
                StoreKind::Node => matches!(self.read_node(id), Ok(n) if !n.mvcc.in_use()),
                StoreKind::Strings => matches!(self.read_block(id), Ok(b) if !b.mvcc.in_use()),
                StoreKind::Rel => match self.read_rel(id) {
                    Ok(r) if !r.mvcc.in_use() => {
                        // Endpoints come from the corpse's own preserved body (`rmp` #220): a
                        // header-only creation undo keeps the record body intact.
                        !self.rel_slot_referenced(id, &r).unwrap_or(true)
                    }
                    _ => false,
                },
                // The undo area's own slots are never *popped* by a data transaction: a delta id comes
                // from `alloc_undo_id` (which records its pops the same way) and a commit slot from
                // `alloc_id`, and both are reclaimed by `reclaim_aborted_undo`, which asks the sharper
                // question — whether the slot is still threaded on a chain. Re-pushing here would risk
                // a double free, so decline (a safe leak, exactly as for an unknown-owner property).
                StoreKind::Undo | StoreKind::Commit => false,
                StoreKind::Prop => match self.read_prop(id) {
                    Ok(p) if !p.mvcc.in_use() => {
                        match prop_owners.iter().find(|&&(pid, _, _)| pid == id) {
                            Some(&(_, owner_kind, owner_id)) => !self
                                .prop_chain_visits(owner_kind, owner_id, id)
                                .unwrap_or(true),
                            // Owner unknown ⇒ cannot prove it is unreferenced ⇒ leave it (safe leak).
                            None => false,
                        }
                    }
                    _ => false,
                },
            };
            if safe {
                self.store_mut(kind).free.push(id);
            }
        }
    }

    /// Whether relationship slot `id` (whose current image is `rel`) is still threaded into either of
    /// its endpoints' incidence chains (`rmp` #581 corpse check). Walks each endpoint chain from the
    /// node's `first_rel`, so it is robust to the corpse's own possibly-stale link pointers — exactly
    /// the walk-driven discipline [`gc_splice_corpses`](Self::gc_splice_corpses) uses.
    fn rel_slot_referenced(&mut self, id: u64, rel: &RelRecord) -> Result<bool> {
        if rel.start_node != NULL_ID && self.chain_visits_rel(rel.start_node, id)? {
            return Ok(true);
        }
        if rel.end_node != NULL_ID
            && rel.end_node != rel.start_node
            && self.chain_visits_rel(rel.end_node, id)?
        {
            return Ok(true);
        }
        Ok(false)
    }

    /// Whether `target` appears as a link in node `node_id`'s incidence chain (`rmp` #581). Mirrors
    /// [`read_view::incident_rels`](crate::read_view)'s walk exactly (same self-loop side selection,
    /// same threading through `!in_use` corpse links, same `2 * high_water + 2` cycle guard), but
    /// returns as soon as it reaches `target` rather than collecting live rels.
    fn chain_visits_rel(&mut self, node_id: u64, target: u64) -> Result<bool> {
        let mut cur = self.read_node(node_id)?.first_rel;
        let guard = self
            .store(StoreKind::Rel)
            .alloc
            .high_water()
            .saturating_mul(2)
            .saturating_add(2);
        let mut steps = 0u64;
        let mut prev_link = NULL_ID;
        while cur != NULL_ID {
            if cur == target {
                return Ok(true);
            }
            steps += 1;
            if steps > guard {
                return Err(GraphusError::Storage(format!(
                    "incidence chain of node {node_id} is malformed (cycle?)"
                )));
            }
            let r = self.read_rel(cur)?;
            let is_loop = r.start_node == node_id && r.end_node == node_id;
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
        Ok(false)
    }

    /// Whether `target` appears in the property chain of `(owner_kind, owner_id)` (`rmp` #581). A
    /// singly-linked walk from the owner's `first_prop` following `next_prop`, cycle-guarded by the
    /// `Prop` high-water, mirroring [`gc_property_chain`](Self::gc_property_chain)'s traversal.
    fn prop_chain_visits(
        &mut self,
        owner_kind: StoreKind,
        owner_id: u64,
        target: u64,
    ) -> Result<bool> {
        let mut cur = self.owner_first_prop(owner_kind, owner_id)?;
        let guard = self.store(StoreKind::Prop).alloc.high_water() + 1;
        let mut steps = 0u64;
        while cur != NULL_ID {
            if cur == target {
                return Ok(true);
            }
            steps += 1;
            if steps > guard {
                return Err(GraphusError::Storage(format!(
                    "property chain of {owner_kind:?} {owner_id} is malformed (cycle?)"
                )));
            }
            cur = self.read_prop(cur)?.next_prop;
        }
        Ok(false)
    }

    /// Rebuilds the in-memory catalog from the durable metadata page.
    fn reload_catalog(&mut self) -> Result<()> {
        let (meta, meta_chain) = Self::read_meta(&self.pool)?;
        self.element_ids = ElementIdAllocator::new(meta.element_id_next.max(1));
        // The commit-timestamp oracle is a strictly-monotonic counter that only ever ADVANCES (at
        // commit) and must NEVER move backwards within a running process — a reissued timestamp could
        // collide with one a still-tracked committed transaction holds and confuse SSI's concurrency
        // determination. Since `rmp` #529 a read-only commit advances `commit_ts_hw` in memory WITHOUT
        // persisting it (it writes no catalog), so the durable `meta.commit_ts_hw` legitimately LAGS the
        // in-memory value; a rollback's reload must therefore keep the higher in-memory high-water, not
        // lower it to the persisted catalog. (Before #529 the two were always equal at any rollback
        // point — every durable commit persisted its own timestamp — so this `max` is a no-op for the
        // pre-#529 behaviour and strictly preserves monotonicity now.)
        self.commit_ts_hw = self.commit_ts_hw.max(meta.commit_ts_hw);
        // THE LIVE PAGE MAP IS PRESERVED — by never being touched (`rmp` #721).
        //
        // Every other per-store field is restored from the durable committed catalog. The page map is
        // NOT, because:
        //
        // 1. **Page growth is never undone.** A device page allocated by a transaction that then aborts
        //    stays allocated and stays attributed to its store (its type/subtype header word is
        //    WAL-logged with `undo == redo` for exactly this reason, `rmp` #239). So the durable
        //    catalog's map is always a PREFIX of the live map, never a correction of it: rebuilding from
        //    it would only throw away the tail, which the caller then had to laboriously re-append.
        // 2. **Readers hold it.** The map is shared live with every in-flight off-thread reader
        //    (`Arc<PageMap>`). Swapping in a fresh map would strand them on one that stops growing —
        //    resurrecting the very defect #721 fixes — and any window in which the field held an EMPTY
        //    map (as the old `std::mem::take` + reload + re-extend dance briefly did) would tell a
        //    reader that a committed record's page "is not allocated".
        //
        // Validate FIRST, mutate second, so a rejected catalog leaves every store untouched (exception
        // safety: `rmp` #479's seed-5043221 durability breach was a rollback that failed *after* it had
        // already dismantled the page maps).
        for (i, sm) in meta.stores.iter().enumerate() {
            let kind = self.stores[i].kind;
            let live = &self.stores[i].device_pages;
            // The durable-prefix invariant is load-bearing, so it is CHECKED, not assumed — and checked
            // in RELEASE, not behind a `debug_assert`. A durable map that is longer than, or diverges
            // from, the live map's prefix means the in-memory map lost or remapped pages a checkpoint
            // had already persisted: memory/catalog divergence. There is no safe way to serve a store
            // whose location oracle we cannot trust, so fail closed (`04 §4.6`). This is O(durable
            // pages) once per rollback, against a `reload_catalog` that already decodes the whole
            // catalog — asymptotically free.
            if sm.device_pages.len() > live.len() {
                return Err(GraphusError::Storage(format!(
                    "{kind:?} store catalog maps {} device pages but the live page map has only {} — \
                     the durable map must always be a prefix of the live one (page growth is never \
                     undone); refusing to serve",
                    sm.device_pages.len(),
                    live.len()
                )));
            }
            if let Some((p, dev)) = sm
                .device_pages
                .iter()
                .enumerate()
                .find(|&(p, &dev)| live.get(p) != Some(PageId(dev)))
            {
                return Err(GraphusError::Storage(format!(
                    "{kind:?} store catalog maps store-relative page {p} to device page {dev}, but the \
                     live page map has {:?} — the durable map diverged from the live map's prefix \
                     (a device page was remapped, which must never happen); refusing to serve",
                    live.get(p)
                )));
            }
        }
        for (i, sm) in meta.stores.iter().enumerate() {
            // Restore ONLY the allocator and the free list. `device_pages` is left exactly as it is.
            self.stores[i].alloc = PhysicalAllocator::restore(sm.high_water.max(1));
            self.stores[i].free = sm.free_list.clone();
        }
        self.tokens = meta.tokens;
        // Restore the whole `Statistics` from the durable catalog (`rmp` task #79 / #81). This is a
        // WHOLESALE revert of both halves — the live-record counters and the schema-catalog DDL maps —
        // and, exactly like the id high-water / free-list restore above, it is only ever *part* of the
        // answer: it drops every in-memory change since the last checkpoint, including changes that
        // belong to a CONCURRENT still-open transaction rather than to the one rolling back. Both
        // halves are therefore layered back on by `rollback`, which is this method's only caller:
        // `restore_counts` + the aborting transaction's `CountDelta` withdrawal for the counters
        // (`rmp` #866), and `adopt_schema_from` + `apply_schema_undo` for the schema (`rmp` #534 /
        // #734). Do NOT read this line as "a rollback discards the aborting transaction's counts": it
        // discards *everybody's*, and the caller puts the others back.
        self.statistics = meta.statistics;
        // The catalog is only ever checkpointed at commit, so during an open transaction the chain
        // already matches disk; reload (rollback / recovery) restores the durable committed chain.
        self.meta_chain = meta_chain;
        Ok(())
    }

    // -------------------------------- tokens --------------------------------

    /// Interns a token in `ns`, returning its id. A newly created token becomes durable when the
    /// caller's transaction commits (`04 §2.6`).
    ///
    /// # Errors
    /// Returns a storage error if the namespace id space is exhausted.
    pub fn intern_token(&mut self, ns: Namespace, name: &str) -> Result<u32> {
        let (id, created) = self.tokens.intern(ns, name)?;
        // A newly-interned token is a catalog-only change (no WAL data record), durable only via the
        // commit-time `checkpoint_meta` — flag it so `commit` does not take its read-only fast path and
        // drop it (`rmp` #529). A re-intern of an existing token changed nothing, so it need not flag.
        if created {
            self.catalog_dirty = true;
        }
        Ok(id)
    }

    /// The name for a token id in `ns`, if present.
    #[must_use]
    pub fn token_name(&self, ns: Namespace, id: u32) -> Option<&str> {
        self.tokens.name(ns, id)
    }

    /// The id for a token name in `ns`, if present.
    #[must_use]
    pub fn token_id(&self, ns: Namespace, name: &str) -> Option<u32> {
        self.tokens.id(ns, name)
    }

    /// Captures this store's token dictionary into an owned, `Send + Sync`, cheap-to-clone
    /// [`TokenSnapshot`] (`rmp` task #336, Slice 3b-i): the `id ↔ name` resolution surface a reader
    /// thread needs alongside its [`StoreReadView`], which lacks token access.
    ///
    /// Call this on the engine thread (where the store is exclusively held). The resulting snapshot
    /// resolves `token_id` / `token_name` exactly as the live store would, frozen at this instant. It
    /// is MVCC-superset-safe: tokens are append-only, so any token interned after capture belongs to a
    /// writer committing after the reader's snapshot timestamp and the records referencing it are
    /// invisible to the reader anyway (see [`TokenSnapshot`]).
    ///
    /// For Slice 3b-i this clones the in-memory dictionary once into a fresh [`Arc`]; the
    /// coordinator-side epoch-cached, no-deep-clone optimisation (tokens only grow, so a cached `Arc`
    /// can be reused while the epoch is unchanged) is Slice 3b-ii — the write path / `tokens` field
    /// shape is **not** touched here.
    #[must_use]
    pub fn token_snapshot(&self) -> TokenSnapshot {
        TokenSnapshot::new(Arc::new(self.tokens.clone()))
    }

    // ------------------------------- node CRUD ------------------------------

    /// Creates a node under `txn`, allocating a fresh physical id and a never-reused
    /// [`ElementId`]; returns `(physical_id, element_id)`.
    ///
    /// # Errors
    /// Returns a storage error if the write fails.
    pub fn create_node(&mut self, txn: TxnId) -> Result<(u64, ElementId)> {
        let id = self.alloc_id(StoreKind::Node, txn)?;
        let eid = self.element_ids.alloc()?;
        // Stamp `xmin` with the writer's in-flight `TxnId` (`04 §5.2`); `commit` settles it to the
        // commit timestamp. Until then the version is visible only to its own transaction.
        let mut rec = NodeRecord::new(eid, VersionStamp::in_flight(txn));
        // The version chain's first link (`04 §5.1.1`, `05 §12.3`): creating an entity writes a
        // `DeleteObject` delta, because deleting it is what undoes the creation. The delta is written
        // FIRST and its id rides into the record's own first write as `undo_ptr` — see
        // [`creation_chain_head`](Self::creation_chain_head) for why a creation may publish its head
        // that way and every other mutation may not. Memgraph likewise makes the first delta of any
        // newly created object a `DELETE_OBJECT`
        // (`/data/refsrc/memgraph/src/storage/v2/mvcc.hpp:236-249`).
        rec.mvcc.undo_ptr = self.creation_chain_head(StoreKind::Node, id, txn)?;
        self.write_node(id, &rec, txn)?;
        self.note_created(txn, StoreKind::Node, id);
        // Maintain the grand-total live-node count (`rmp` task #82): once per node, labelled or not —
        // an unlabelled node contributes to no per-label count but is still a node. In-memory only;
        // durable at the commit checkpoint, and withdrawn from `txn`'s pending delta on rollback
        // ([`count_bump`], `rmp` #866).
        self.count_bump(txn, CountKey::TotalNodes, true);
        Ok((id, eid))
    }

    /// Reads the node record at physical id `id`.
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated.
    pub fn node(&self, id: u64) -> Result<NodeRecord> {
        self.read_node(id)
    }

    /// Enumerates the physical ids of every **slot-occupied** node (`in_use`), in ascending id
    /// order. This includes MVCC tombstones not yet GC'd (a deleted node keeps its slot until
    /// reclamation, `04 §5.5`): whether a returned node is *visible* to a given reader is decided by
    /// the snapshot/visibility layer above (`graphus-cypher`'s `RecordStoreGraph`, `04 §5.3`), which
    /// filters these ids through `graphus_txn::is_visible` on each record's `xmin`/`xmax`.
    ///
    /// The node store's physical-id space is `1..high_water` (id `0` is the reserved null pointer
    /// and real records start at id `1`, `04 §2.2`); this walks that range and keeps the ids whose
    /// node record is in use. A full scan is O(high-water): a vectorised / segment-skipping leaf
    /// scan is the optimisation `04 §7.4` flags, not required for correctness. Index-accelerated
    /// label scans are the follow-up #48.
    ///
    /// # Errors
    /// Returns a storage error if a node store page in the range cannot be read.
    pub fn scan_node_ids(&self) -> Result<Vec<u64>> {
        read_view::scan_node_ids(&self.pool, &self.stores)
    }

    /// Enumerates the physical ids of every **slot-occupied** relationship (`in_use`), in ascending
    /// id order — the relationship analogue of [`scan_node_ids`](Self::scan_node_ids).
    ///
    /// As with nodes this includes MVCC tombstones not yet GC'd; *visibility* to a given reader is
    /// decided by the snapshot/visibility layer above. The relationship store's physical-id space is
    /// `1..high_water` (id `0` is the reserved null pointer). Used by whole-store export (`rmp` task
    /// #22) to walk every relationship without a per-node incidence-chain traversal.
    ///
    /// # Errors
    /// Returns a storage error if a relationship store page in the range cannot be read.
    pub fn scan_rel_ids(&self) -> Result<Vec<u64>> {
        read_view::scan_rel_ids(&self.pool, &self.stores)
    }

    /// **MVCC-deletes** the node at `id` under `txn` by stamping its `xmax` tombstone (`04 §5.3`).
    ///
    /// The record keeps its slot, its label bitmap and its property chain: an older snapshot that
    /// could see the node must still see it until no live snapshot can, at which point
    /// [`gc`](Self::gc) physically reclaims it ([`reclaim_node`](Self::reclaim_node)). The caller is
    /// expected to have MVCC-deleted the node's relationships first (`DETACH DELETE`); GC will not
    /// reclaim a node while a live relationship still references it.
    ///
    /// # Errors
    /// Returns a storage error if the node is not a live version (already deleted or never in use)
    /// or the write fails.
    pub fn delete_node(&mut self, txn: TxnId, id: u64) -> Result<()> {
        let rec = self.read_node(id)?;
        if !Self::is_live_version(rec.mvcc) {
            return Err(GraphusError::Storage(format!("node {id} is not in use")));
        }
        // Drop this node's contribution to every per-label count before stamping the tombstone
        // (`rmp` task #79): the labels are read from the still-live record. An overflow-form bitmap
        // (a #39 build's, which this build never writes) contributes to no inline-label count, so it
        // is skipped rather than erroring the delete; the inline counts only ever tracked inline
        // labels. Reclamation at GC ([`reclaim_node`]) must NOT decrement again. On rollback these
        // decrements are withdrawn from `txn`'s pending delta ([`count_bump`], `rmp` #866).
        if let Ok(label_ids) = labels::token_ids(rec.labels) {
            for token_id in label_ids {
                self.count_bump(txn, CountKey::Label(token_id), false);
            }
        }
        // Drop this node's contribution to the grand-total live-node count (`rmp` task #82): once per
        // node, alongside the per-label decrements and independent of how many labels it carried.
        // Reclamation at GC ([`reclaim_node`]) must NOT decrement again.
        self.count_bump(txn, CountKey::TotalNodes, false);
        // Link the `RecreateObject` delta BEFORE the in-place mutation that follows (`04 §5.1.2`,
        // steps 3 then 4): the previous state must be recoverable from a linked delta before the
        // record stops describing it.
        self.note_entity_deleted(StoreKind::Node, id, txn)?;
        // `rmp` #301: compare-and-set undo for the tombstone stamp, so a non-LIFO abort never clobbers
        // a header word a concurrently-interleaved transaction has since re-stamped.
        self.patch_header_word_cas(
            StoreKind::Node,
            id,
            MVCC_OFF_EXPIRED_TS,
            VersionStamp::in_flight(txn),
            txn,
        )?;
        self.note_expired(txn, StoreKind::Node, id);
        Ok(())
    }

    /// Physically reclaims a tombstoned node under `txn` (called by [`gc`](Self::gc) once the node
    /// is invisible to every live snapshot): frees its property chain (records + overflow blocks, no
    /// leak), clears the record, and returns its physical id to the free list (`04 §2.7`). This is
    /// the old single-version delete body, now gated behind the MVCC tombstone + GC watermark.
    fn reclaim_node(&mut self, txn: TxnId, id: u64) -> Result<()> {
        // Free the node's property chain first so a reclaimed node leaves nothing live behind (the
        // executor no longer clears it eagerly — the tombstone defers everything to here). Uses the
        // entity-agnostic chain free (not `clear_node_properties`, whose live-version precondition
        // would reject the tombstoned node we are reclaiming).
        let first_prop = self.read_node(id)?.first_prop;
        let _freed = self.free_property_chain(txn, id, first_prop)?;
        // Free this node's whole undo chain BEFORE the header (and with it `undo_ptr`) is cleared
        // (`rmp` #966). ORDER IS LOAD-BEARING, and getting it wrong is silent: `MvccHeader::default()`
        // below zeroes `undo_ptr`, so a `free_undo_chain` placed after the write reads an EMPTY chain,
        // frees nothing, and leaks every delta the node ever accumulated — with no error and no
        // failing invariant, because an unreachable delta is indistinguishable from a reclaimed one
        // except by counting. It was placed after the write in the first cut of #966 and cost 25
        // leaked delta slots per churn tick, growing `undo.store` without bound while every other
        // store plateaued (`crates/graphus-iot-gen/tests/churn_plateau.rs` is the gate that caught it).
        //
        // The GC precondition for reclaiming a record — no live snapshot can see it — is strictly
        // stronger than the one for reclaiming its chain, so the chain is unconditionally dead here.
        //
        // `rmp` #968: this is also what makes a reused physical id safe for LABELS. They used to be
        // versioned in an id-keyed in-process map, so an entry surviving here was inherited by
        // whatever new node was handed this slot — reporting the dead node's labels permanently.
        // A label version is now a delta on this very chain, so freeing the chain frees them, and the
        // cleared header hands the slot on with `undo_ptr == 0` and nothing to inherit.
        self.free_undo_chain(StoreKind::Node, id, txn)?;
        let mut dead = self.read_node(id)?;
        dead.first_prop = NULL_ID;
        dead.mvcc = MvccHeader::default(); // clears in_use
        self.write_node(id, &dead, txn)?;
        self.free_push(StoreKind::Node, id, txn);
        Ok(())
    }

    // ------------------------------ node labels -----------------------------
    //
    // A node's label set is encoded in the frozen `NodeRecord.labels` u64 as a
    // `Label`-namespace token-id bitmap (`05 §9`; `rmp` task #42). Bit `i` set <=> the node has the
    // label with token id `i`, for `i` in `0..=62`; bit 63 is the overflow flag. The token-list
    // overflow block (a label token id >= 63, or > 63 labels) is the follow-up #39 and is signalled
    // here as a clear `LabelError` rather than a wrong or partial write. See `crate::labels`.
    //
    // Every label mutation rewrites the node record through the same WAL-logged page-patch path as
    // any other node write ([`write_node`] -> [`write_region`]), so a label change is durable on
    // commit and recovered (redo/undo) by the same three-phase ARIES machinery (`04 §4`).

    /// Replaces node `id`'s label set with exactly `label_token_ids` (the bitmap is overwritten),
    /// under `txn`. Duplicate ids are idempotent; the order is irrelevant.
    ///
    /// # Errors
    /// - [`GraphusError::Storage`] if the node is not in use or a write fails.
    /// - [`GraphusError::Runtime`] (from [`LabelError::Overflow`](crate::labels::LabelError::Overflow),
    ///   `04 §2.6` / `05 §9`) if any token id is `>= 63` (the inline bitmap is full and the overflow
    ///   block is the follow-up #39).
    pub fn set_node_labels(&mut self, txn: TxnId, id: u64, label_token_ids: &[u32]) -> Result<()> {
        let node = self.read_node(id)?;
        if !Self::is_live_version(node.mvcc) {
            return Err(GraphusError::Storage(format!("node {id} not in use")));
        }
        // Encode the requested set first so an overflowing token id errors before any mutation or
        // count change (no partial write, no count drift).
        let new_labels = labels::encode_set(label_token_ids).map_err(GraphusError::from)?;
        let old_labels = node.labels;
        // Goes through [`write_node_labels`](Self::write_node_labels) rather than mutating the record
        // and calling `write_node` (`rmp` #968, acceptance criterion 5).
        //
        // The old form logged a **whole-record pre-image** undo. That is the exact shape `rmp` #772
        // was: a concurrently-committed writer legitimately owns `first_prop` / `first_rel` / the MVCC
        // word by abort time, and replaying a whole-record image reverts those too, destroying a
        // committed version. It was unreachable in production only because every production caller
        // happened to operate on a node its own transaction had just created — a property of the
        // callers, not of the code, so any future caller reopened #772. `write_node_labels` scopes
        // both the write and its undo to the `labels` word under the same compare-and-set discipline
        // the chain-participating writes use, and links the label deltas, so this path and the
        // per-bit path are now one path with one set of guarantees.
        self.write_node_labels(id, new_labels, old_labels, txn, node.mvcc.created_ts)?;
        // Adjust the per-label counts by the membership delta of this live node (`rmp` task #79), and
        // re-key the directional relationship counters this node's edges contribute to (`rmp` #856).
        self.apply_label_count_delta(txn, id, old_labels, new_labels)?;
        Ok(())
    }

    /// Applies the per-label live-node count change for a single node whose label bitmap moved from
    /// `old` to `new` (`rmp` task #79): each token id newly set is incremented, each newly cleared is
    /// decremented. A bit unchanged in both is left alone. Only inline membership bits (`0..=62`) are
    /// considered; the overflow flag is never a counted label. Call only after a successful node-label
    /// write on a **live** node, so the count tracks exactly the live nodes' contributions.
    ///
    /// Takes the owning `txn` because every counter move must be recorded in that transaction's
    /// pending count delta (`rmp` #866) — see [`count_bump`](Self::count_bump). It is the same reason
    /// every other mutating store API takes it, and the reason the DDL seam does
    /// ([`with_schema_undo`](Self::with_schema_undo)).
    fn apply_label_count_delta(&mut self, txn: TxnId, id: u64, old: u64, new: u64) -> Result<()> {
        // `token_ids` cannot error here: both bitmaps come from this build's inline writes (overflow
        // flag clear). The bit arithmetic isolates the changed bits without enumerating unchanged ones.
        let added = new & !old;
        let removed = old & !new;
        if let Ok(ids) = labels::token_ids(added) {
            for token_id in ids {
                self.count_bump(txn, CountKey::Label(token_id), true);
            }
        }
        if let Ok(ids) = labels::token_ids(removed) {
            for token_id in ids {
                self.count_bump(txn, CountKey::Label(token_id), false);
            }
        }
        if added != 0 || removed != 0 {
            self.apply_directional_label_change(txn, id, added, removed)?;
        }
        Ok(())
    }

    /// Re-keys the **directional** relationship counters (`rmp` task #856) after node `id`'s label set
    /// gained the bits in `added` and lost those in `removed`.
    ///
    /// Both projections are keyed on an endpoint's labels, so changing a node's labels moves the
    /// contribution of **every relationship incident to that node** from one key to another. There is no
    /// cheaper formulation: the counters are per `(label, type)` pair, and only a walk of the node's
    /// incidence chain reveals which types it participates in and on which side.
    ///
    /// # Cost
    ///
    /// **O(degree of `id`)** — a label change on a supernode walks that supernode's whole chain. This is
    /// inherent to keeping the counters exact, and Neo4j's counts store pays the same price for the same
    /// reason. It is charged only when the label set actually changes (an idempotent re-`SET` of a label
    /// already present has `added == removed == 0` and is skipped by the caller), and the walk is the
    /// single-pass `incident_rels_typed`, so each chain link is read once.
    ///
    /// A **self-loop** satisfies both branches below and is therefore counted on both sides, matching
    /// how [`apply_directional_rel_counts`](Self::apply_directional_rel_counts) created it.
    ///
    /// # Errors
    /// Propagates a chain-walk failure. A walk that fails leaves the counters partially adjusted, which
    /// is why the caller performs it *after* the node write has succeeded — and why a partial
    /// adjustment is still safe: every bump it did make is in `txn`'s pending count delta, so the
    /// rollback that must follow a failed statement withdraws exactly those (`rmp` #866).
    fn apply_directional_label_change(
        &mut self,
        txn: TxnId,
        id: u64,
        added: u64,
        removed: u64,
    ) -> Result<()> {
        let added_ids = labels::token_ids(added)?;
        let removed_ids = labels::token_ids(removed)?;
        // Empty `wanted_types` means "every type"; one pass over the chain yields each record.
        let incident = self.incident_rels_typed(id, &[])?;
        for (rel_id, rel) in incident {
            // A tombstoned relationship no longer contributes to any live count — its `delete_rel`
            // already removed it — so re-keying it would corrupt the balance in both directions.
            if !Self::is_live_version(rel.mvcc) {
                debug_assert!(rel_id != 0, "chain yielded a null relationship id");
                continue;
            }
            if rel.start_node == id {
                for &label in &added_ids {
                    self.count_bump(txn, CountKey::StartLabelType(label, rel.type_id), true);
                }
                for &label in &removed_ids {
                    self.count_bump(txn, CountKey::StartLabelType(label, rel.type_id), false);
                }
            }
            if rel.end_node == id {
                for &label in &added_ids {
                    self.count_bump(txn, CountKey::TypeEndLabel(rel.type_id, label), true);
                }
                for &label in &removed_ids {
                    self.count_bump(txn, CountKey::TypeEndLabel(rel.type_id, label), false);
                }
            }
        }
        Ok(())
    }

    /// Adds the label with `label_token_id` to node `id` under `txn` (idempotent — a label already
    /// present is a no-op write).
    ///
    /// # Errors
    /// - [`GraphusError::Storage`] if the node is not in use or a write fails.
    /// - [`GraphusError::Runtime`] (from [`LabelError`](crate::labels::LabelError)) if
    ///   `label_token_id` is `>= 63`, or the node's bitmap is already in overflow form (#39).
    pub fn add_label(&mut self, txn: TxnId, id: u64, label_token_id: u32) -> Result<()> {
        let node = self.read_node(id)?;
        if !Self::is_live_version(node.mvcc) {
            return Err(GraphusError::Storage(format!("node {id} not in use")));
        }
        let next = labels::with_label(node.labels, label_token_id).map_err(GraphusError::from)?;
        if next == node.labels {
            return Ok(()); // already present: no write, no WAL churn, no count change
        }
        let old_labels = node.labels;
        // Scope the write and its undo to the `labels` word alone, with CAS logical undo, so a
        // rolled-back label change never clobbers a concurrently-committed writer's `first_prop` /
        // `first_rel` / MVCC word on the same node record (`rmp` #772). `write_node` (whole-record
        // pre-image undo) was the breach.
        self.write_node_labels(id, next, old_labels, txn, node.mvcc.created_ts)?;
        // Exactly one bit was newly set: increment its per-label count (`rmp` task #79) and re-key the
        // directional relationship counters of this node's edges onto the new label (`rmp` #856).
        self.apply_label_count_delta(txn, id, old_labels, next)?;
        Ok(())
    }

    /// Removes the label with `label_token_id` from node `id` under `txn` (idempotent — removing an
    /// absent label is a no-op write).
    ///
    /// # Errors
    /// - [`GraphusError::Storage`] if the node is not in use or a write fails.
    /// - [`GraphusError::Runtime`] (from [`LabelError`](crate::labels::LabelError)) if
    ///   `label_token_id` is `>= 63`, or the node's bitmap is already in overflow form (#39).
    pub fn remove_label(&mut self, txn: TxnId, id: u64, label_token_id: u32) -> Result<()> {
        let node = self.read_node(id)?;
        if !Self::is_live_version(node.mvcc) {
            return Err(GraphusError::Storage(format!("node {id} not in use")));
        }
        let next =
            labels::without_label(node.labels, label_token_id).map_err(GraphusError::from)?;
        if next == node.labels {
            return Ok(()); // already absent: no write, no count change
        }
        let old_labels = node.labels;
        // Scope the write and its undo to the `labels` word alone, with CAS logical undo, so a
        // rolled-back label change never clobbers a concurrently-committed writer's `first_prop` /
        // `first_rel` / MVCC word on the same node record (`rmp` #772). `write_node` (whole-record
        // pre-image undo) was the breach.
        self.write_node_labels(id, next, old_labels, txn, node.mvcc.created_ts)?;
        // Exactly one bit was newly cleared: decrement its per-label count (`rmp` task #79) and re-key
        // the directional relationship counters of this node's edges off the old label (`rmp` #856).
        self.apply_label_count_delta(txn, id, old_labels, next)?;
        Ok(())
    }

    /// The `Label`-namespace token ids of node `id`'s labels, ascending.
    ///
    /// # Errors
    /// - [`GraphusError::Storage`] if `id`'s page is not allocated.
    /// - [`GraphusError::Runtime`] (from
    ///   [`LabelError::OverflowFlagSet`](crate::labels::LabelError::OverflowFlagSet)) if the node's
    ///   bitmap is in overflow form (its labels live in a #39 token-list block this build cannot
    ///   read).
    pub fn node_labels(&self, id: u64) -> Result<Vec<u32>> {
        read_view::node_labels(&self.pool, &self.stores, id)
    }

    /// The `Label`-namespace token ids node `id` carries under **any** snapshot, ascending — the
    /// candidate-membership superset an index refill must gate on (`rmp` task #904).
    ///
    /// This is [`node_labels`](Self::node_labels) widened by every label an `AddLabel` delta on the
    /// node's undo chain could restore (`rmp` #968), so it holds the union of the live word and every
    /// version the chain still retains — committed, in flight, and not yet reclaimed.
    ///
    /// # Why a refill must use this and never the raw live word
    ///
    /// Labels are mutated **in place**, so the live word carries an uncommitted writer's changes. A
    /// refill that reads it decides membership from a bitmap that may be neither the committed set nor
    /// the one any reader will end up seeing:
    ///
    /// * a refill run while a writer holds an uncommitted `REMOVE n:L` writes a **subset** — the node
    ///   is excluded from every `(L, *)` index, the writer then rolls back, the record carries `:L`
    ///   again, and nothing re-inserts the entry. A seek's re-check can REMOVE a candidate but never
    ///   RESURRECT one, so that committed row is invisible to every future seek for the life of the
    ///   process — and, because the uniqueness / node-key duplicate checks read those same trees as an
    ///   exact candidate source, a live `IS UNIQUE` constraint then ADMITS a duplicate;
    /// * a refill that read the newest *committed* bitmap instead would merely move the victim, losing
    ///   an uncommitted writer's ADDED label, which `commit` never re-inserts (index entries are made
    ///   eagerly at write time).
    ///
    /// The union is the only image that serves both. Its extra entries are false positives that every
    /// consumer of these trees drops: each re-checks label membership against the reader's own snapshot
    /// via [`label_bitmap_at`](Self::label_bitmap_at) (`graphus_cypher::read_source`'s
    /// `filter_label_candidates` / `filter_any_label_candidates`, and the vector procedure's
    /// `node_labels`).
    ///
    /// # Errors
    /// As [`node_labels`](Self::node_labels).
    pub fn node_label_superset(&self, id: u64) -> Result<Vec<u32>> {
        let node = self.read_node(id)?;
        let superset = read_view::node_label_superset_bitmap(
            &self.pool,
            &self.stores,
            id,
            node.labels,
            node.mvcc.undo_ptr,
        )?;
        labels::token_ids(superset).map_err(GraphusError::from)
    }

    /// Whether node `id` carries the label with `label_token_id`.
    ///
    /// # Errors
    /// - [`GraphusError::Storage`] if `id`'s page is not allocated.
    /// - [`GraphusError::Runtime`] (from [`LabelError`](crate::labels::LabelError)) if
    ///   `label_token_id` is `>= 63`, or the node's bitmap is in overflow form (#39).
    pub fn node_has_label(&self, id: u64, label_token_id: u32) -> Result<bool> {
        read_view::node_has_label(&self.pool, &self.stores, id, label_token_id)
    }

    /// The label bitmap node `id` presents to `snapshot` (`rmp` task #767), given the `live` word
    /// already decoded from its record.
    ///
    /// The inline twin of [`StoreReadView::label_bitmap_at`]. Takes `live` rather than re-reading the
    /// record because every caller on the hot path has just decoded it for the MVCC visibility check.
    ///
    /// [`node_labels`](Self::node_labels) / [`node_has_label`](Self::node_has_label) deliberately do
    /// NOT apply this: they report the CURRENT word, for the write-path enforcement that acts on it.
    ///
    /// An index build must use neither. It has no snapshot to resolve against, and the current word is
    /// **not** the candidate superset this doc once claimed it was — it is a subset whenever an
    /// uncommitted writer has removed a label (`rmp` task #904). The build's gate is
    /// [`node_label_superset`](Self::node_label_superset); the snapshot-correct narrowing then happens
    /// at seek time in `graphus_cypher::read_source::filter_label_candidates`, which routes back
    /// through this method.
    ///
    /// # Errors
    /// Returns a storage error if the node's undo chain cannot be walked (`rmp` #968). A read fault is
    /// never answered with the live word, which would be a dirty read of an uncommitted writer's
    /// in-place change.
    pub fn label_bitmap_at(
        &self,
        id: u64,
        live: u64,
        head: u64,
        snapshot: Snapshot,
    ) -> Result<u64> {
        read_view::label_bitmap_at(&self.pool, &self.stores, id, live, head, snapshot)
    }

    // --------------------------- relationship CRUD --------------------------

    /// Creates a relationship of `type_id` from `start` to `end` under `txn`, threading it into
    /// both endpoints' incidence chains (a self-loop is threaded into the single chain twice,
    /// `04 §2.4`). Returns `(physical_id, element_id)`.
    ///
    /// # Errors
    /// Returns a storage error if either endpoint is not in use or a write fails.
    pub fn create_rel(
        &mut self,
        txn: TxnId,
        type_id: u32,
        start: u64,
        end: u64,
    ) -> Result<(u64, ElementId)> {
        let start_node = self.read_node(start)?;
        if !Self::is_live_version(start_node.mvcc) {
            return Err(GraphusError::Storage(format!(
                "start node {start} not in use"
            )));
        }
        let id = self.alloc_id(StoreKind::Rel, txn)?;
        let eid = self.element_ids.alloc()?;
        self.note_created(txn, StoreKind::Rel, id);
        // Stamp `xmin` with the writer's in-flight `TxnId` (`04 §5.2`); settled at commit.
        let mut rel = RelRecord::new(eid, VersionStamp::in_flight(txn), type_id, start, end);
        // The creation's `DeleteObject` delta, written before the record that names it, exactly as for
        // a node ([`creation_chain_head`](Self::creation_chain_head)). Both branches below write the
        // record through `write_rel_create`, whose header-only creation undo reverts `undo_ptr` along
        // with the rest of the MVCC header on abort — so an aborted creation leaves no chain head.
        rel.mvcc.undo_ptr = self.creation_chain_head(StoreKind::Rel, id, txn)?;

        if start == end {
            // Self-loop: thread into the single chain twice. New head order:
            //   end-side(id) -> start-side(id) -> old_head
            let old_head = start_node.first_rel;
            rel.set_chain_pointers(ChainSide::Start, id, old_head); // prev = end-side of self
            rel.set_chain_pointers(ChainSide::End, NULL_ID, id); // end-side is the new head
            rel.chain_flags |= CHAIN_FLAG_END_FIRST;
            if old_head != NULL_ID {
                self.relink_old_head(old_head, start, id, txn)?;
            }
            // The new rel record is written with the header-only creation undo (`rmp` #220): a loser's
            // abort reverts only its slot's in-use bit and PRESERVES its body, so a committed prepend
            // on top threads through it. The chain head is pushed via the compare-and-set logical undo
            // — NOT carried in a plain `write_node` body — so the abort never clobbers a later
            // committed head (it CAS-no-ops once a committed writer pushed on top).
            self.write_rel_create(id, &rel, txn)?;
            self.write_chain_head(
                StoreKind::Node,
                start,
                NODE_OFF_FIRST_REL,
                id,
                old_head,
                txn,
            )?;
            // Maintain the per-relationship-type live count (`rmp` task #79) and the grand-total
            // live-relationship count (`rmp` task #82): the self-loop is now a live version. Both
            // endpoints are the (validated) live start node, so the increment is unconditional here.
            // This branch is mutually exclusive with the normal branch below, so the grand total is
            // incremented exactly once per relationship. In-memory only; durable at the commit
            // checkpoint, withdrawn from `txn`'s pending delta on rollback (`rmp` #866).
            self.count_bump(txn, CountKey::RelType(type_id), true);
            self.count_bump(txn, CountKey::TotalRelationships, true);
            // Directional projections (`rmp` task #856). A self-loop's one node is both endpoints, so its
            // label word is passed for both sides — it really does contribute to each map.
            self.apply_directional_rel_counts(
                txn,
                type_id,
                start_node.labels,
                start_node.labels,
                true,
            )?;
            return Ok((id, eid));
        }

        let end_node = self.read_node(end)?;
        if !Self::is_live_version(end_node.mvcc) {
            return Err(GraphusError::Storage(format!("end node {end} not in use")));
        }

        // Push at the head of the START node's chain.
        let start_head = start_node.first_rel;
        rel.set_chain_pointers(ChainSide::Start, NULL_ID, start_head);
        rel.chain_flags |= CHAIN_FLAG_START_FIRST;
        if start_head != NULL_ID {
            self.relink_old_head(start_head, start, id, txn)?;
        }

        // Push at the head of the END node's chain.
        let end_head = end_node.first_rel;
        rel.set_chain_pointers(ChainSide::End, NULL_ID, end_head);
        rel.chain_flags |= CHAIN_FLAG_END_FIRST;
        if end_head != NULL_ID {
            self.relink_old_head(end_head, end, id, txn)?;
        }

        // Header-only creation undo for the new rel + compare-and-set logical undo for BOTH endpoint
        // chain heads (`rmp` #220). The endpoint `first_rel` is pushed through `write_chain_head`, NOT
        // carried in a plain `write_node` body — otherwise a loser's abort would restore a stale head
        // over a concurrently-committed prepend, collapsing a shared supernode's fan-out.
        self.write_rel_create(id, &rel, txn)?;
        self.write_chain_head(
            StoreKind::Node,
            start,
            NODE_OFF_FIRST_REL,
            id,
            start_head,
            txn,
        )?;
        self.write_chain_head(StoreKind::Node, end, NODE_OFF_FIRST_REL, id, end_head, txn)?;
        // Maintain the per-relationship-type live count (`rmp` task #79) and the grand-total
        // live-relationship count (`rmp` task #82): the relationship is now a written, live version
        // and both endpoints are validated. The self-loop branch above returns early, so the grand
        // total is incremented exactly once per relationship. In-memory only; durable at the commit
        // checkpoint, withdrawn from `txn`'s pending delta on rollback (`rmp` #866).
        self.count_bump(txn, CountKey::RelType(type_id), true);
        self.count_bump(txn, CountKey::TotalRelationships, true);
        // Directional projections (`rmp` task #856), from the label words of the two endpoint records
        // this function already read and validated — no extra I/O on the common inline-bitmap path.
        self.apply_directional_rel_counts(txn, type_id, start_node.labels, end_node.labels, true)?;
        Ok((id, eid))
    }

    /// Applies one relationship's contribution to the two **directional** count projections of
    /// `rmp` task #856: `(startLabel, type)` for every label the start node carries, and
    /// `(type, endLabel)` for every label the end node carries.
    ///
    /// `start_labels` / `end_labels` are the endpoints' raw inline label words, which every caller has
    /// already decoded from the endpoint record it had to read anyway — so the common case costs no
    /// extra I/O, only a bitmap walk. Pass the SAME word twice for a self-loop: its one node is
    /// genuinely both the start and the end of that relationship, so it contributes to both maps.
    ///
    /// In-memory only, exactly like the per-type and grand-total counters: durable at the commit
    /// checkpoint, and withdrawn from `txn`'s pending count delta on rollback (`rmp` #866). That is
    /// what keeps a rolled-back transaction from leaving the counters drifted, and it is why `txn`
    /// must be the transaction that owns the write — see [`count_bump`](Self::count_bump).
    ///
    /// # Errors
    /// Propagates [`LabelError::OverflowFlagSet`](crate::labels::LabelError::OverflowFlagSet) if an
    /// endpoint's label set is in the #39 overflow form this build cannot enumerate. Failing closed is
    /// deliberate: a label set this build cannot read is one whose counters it cannot keep exact, and an
    /// inexact counter the planner trusts is worse than a refused write. No node can reach that form in
    /// this build (`encode_set` rejects a token id at or above the inline limit), so the branch is
    /// defensive rather than reachable.
    fn apply_directional_rel_counts(
        &mut self,
        txn: TxnId,
        type_id: u32,
        start_labels: u64,
        end_labels: u64,
        increment: bool,
    ) -> Result<()> {
        for label in crate::labels::token_ids(start_labels)? {
            self.count_bump(txn, CountKey::StartLabelType(label, type_id), increment);
        }
        for label in crate::labels::token_ids(end_labels)? {
            self.count_bump(txn, CountKey::TypeEndLabel(type_id, label), increment);
        }
        Ok(())
    }

    /// Points the `prev` pointer of `old_head`'s **head link** at `new_id` and clears its
    /// first-in-chain marker. Used when pushing a new head onto `node`'s chain.
    ///
    /// Only the link whose `prev == NULL` (the current head) is repointed — crucial for a
    /// self-loop `old_head`, where both sides face `node` but only one side is the head link; the
    /// other side's `prev` must keep pointing to the head link inside the same record.
    fn relink_old_head(&mut self, old_head: u64, node: u64, new_id: u64, txn: TxnId) -> Result<()> {
        let old = self.read_rel(old_head)?;
        // Recompute the exact post-image of the two back-pointer fields and the flags byte, then write
        // ONLY those fields (`rmp` #220 / #239). Earlier this wrote the whole record body via
        // `write_rel_keep`, which carries the MVCC header in its undo == redo image. That was unsafe
        // under a non-LIFO abort of two interleaved prependers (`rmp` #239, seed 10): if prepender A
        // (older) aborts *before* prepender B (newer) — both having pushed onto the same node head and
        // B having relinked A's record as the old head — then B's relink-undo re-applies A's full body
        // (header included) AFTER A's own header-only creation undo already marked A's slot not-in-use.
        // That resurrects A as `in_use=true`: A becomes a live relationship that was never committed (an
        // atomicity violation — `first_rel` then points at a phantom edge). Restricting this write to the
        // chain-pointer fields makes the relink touch ONLY what it actually changes (never the MVCC
        // header), so an out-of-order abort can no longer resurrect a neighbour's in-use bit; A stays a
        // proper not-in-use dead-link corpse that the forward walk threads through to NULL.
        //
        // undo == redo per field is preserved (`rmp` #220): a plain pre-image undo would restore the old
        // head's `prev == NULL` / first-in-chain flag, making it look like the chain head and letting GC
        // reclaim it on top of a committed prepend. The GC corpse splice re-points `prev`/flags back to
        // head form when the new (loser) record becomes a corpse.
        let mut start_prev = old.start_prev_rel;
        let mut end_prev = old.end_prev_rel;
        let mut flags = old.chain_flags;
        if old.start_node == node && old.start_prev_rel == NULL_ID {
            start_prev = new_id;
            flags &= !CHAIN_FLAG_START_FIRST;
        }
        if old.end_node == node && old.end_prev_rel == NULL_ID {
            end_prev = new_id;
            flags &= !CHAIN_FLAG_END_FIRST;
        }
        self.write_rel_field_keep(old_head, REL_OFF_START_PREV, &start_prev.to_le_bytes(), txn)?;
        self.write_rel_field_keep(old_head, REL_OFF_END_PREV, &end_prev.to_le_bytes(), txn)?;
        self.write_rel_field_keep(old_head, REL_OFF_CHAIN_FLAGS, &[flags], txn)?;
        Ok(())
    }

    /// Writes a single field region of relationship record `id` with **undo == redo** (a no-op on
    /// abort/recovery), touching ONLY `[field_off, field_off + bytes.len())` and never the MVCC header
    /// (`rmp` #239). The narrow-field, header-preserving counterpart used by
    /// [`relink_old_head`](Self::relink_old_head) so a relink's undo cannot clobber a neighbour record's
    /// MVCC header (which an out-of-LIFO abort of interleaved prependers would otherwise use to resurrect
    /// an aborted record's in-use bit). The undo equals the redo, so the GC corpse splice — not this
    /// write's undo — re-establishes the correct neighbour state.
    fn write_rel_field_keep(
        &mut self,
        id: u64,
        field_off: usize,
        bytes: &[u8],
        txn: TxnId,
    ) -> Result<()> {
        let (rel_page, off) = paging::record_location(id, REL_RECORD_SIZE);
        let dev = self.ensure_store_page(StoreKind::Rel, rel_page, txn)?;
        let abs = off + field_off;
        let end = abs + bytes.len();
        // undo == redo no-op-on-abort image (`rmp` #239), built once as an inline patch: redo lent by
        // borrow, undo retained by value. Byte-identical to the prior `Vec`/`clone` path.
        let redo = paging::encode_patch(abs, bytes);
        let undo = redo.clone().into_vec();
        let f = self.pool.fetch(dev)?;
        let lsn = self
            .wal
            .with(|w| w.log_update_borrowed(txn, dev, &redo, undo));
        self.pool.with_page_mut_lsn(f, lsn, |p| {
            p[abs..end].copy_from_slice(bytes);
        });
        self.pool.unpin(f);
        Ok(())
    }

    /// Reads the relationship record at physical id `id`.
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated.
    pub fn rel(&self, id: u64) -> Result<RelRecord> {
        self.read_rel(id)
    }

    /// **MVCC-deletes** relationship `id` under `txn` by stamping its `xmax` tombstone (`04 §5.3`).
    ///
    /// The record keeps its slot, its incidence-chain links and its property chain, so an older
    /// snapshot that could traverse to it still does until no live snapshot can — at which point
    /// [`gc`](Self::gc) physically unlinks and reclaims it ([`reclaim_rel`](Self::reclaim_rel)).
    /// Read-side traversal ([`RecordStore::incident_rels`]) is unchanged; visibility filtering of a
    /// tombstoned relationship is the reader's (snapshot's) concern, layered above the store.
    ///
    /// # Errors
    /// Returns a storage error if the relationship is not a live version (already deleted or never
    /// in use) or a write fails.
    pub fn delete_rel(&mut self, txn: TxnId, id: u64) -> Result<()> {
        let rel = self.read_rel(id)?;
        if !Self::is_live_version(rel.mvcc) {
            return Err(GraphusError::Storage(format!("rel {id} is not in use")));
        }
        // Link the `RecreateObject` delta BEFORE the in-place mutation (`04 §5.1.2`, steps 3 then 4).
        self.note_entity_deleted(StoreKind::Rel, id, txn)?;
        // `rmp` #301: compare-and-set undo for the tombstone stamp (non-LIFO-safe, see
        // [`patch_header_word_cas`](Self::patch_header_word_cas)).
        self.patch_header_word_cas(
            StoreKind::Rel,
            id,
            MVCC_OFF_EXPIRED_TS,
            VersionStamp::in_flight(txn),
            txn,
        )?;
        self.note_expired(txn, StoreKind::Rel, id);
        // The relationship ceases to be a live version on this committed transition (`rmp` task #79 /
        // #82): drop its contribution to the per-type count and the grand-total live-relationship
        // count. Reclamation at GC ([`reclaim_rel`]) must NOT decrement again — the counts already
        // reflect the deletion from here. On rollback these decrements are withdrawn from `txn`'s
        // pending count delta (`rmp` #866), so an aborted delete does not undercount.
        self.count_bump(txn, CountKey::RelType(rel.type_id), false);
        self.count_bump(txn, CountKey::TotalRelationships, false);
        // Directional projections (`rmp` task #856). Unlike the per-type count, whose key is the
        // relationship's own immutable `type_id`, these are keyed on the ENDPOINTS' labels, which are
        // not in the relationship record — so the two endpoint records must be read here. The labels
        // read are the CURRENT ones, which is exactly right: a `SET`/`REMOVE label` in between already
        // moved this relationship's contribution to the counters it now sits in, so decrementing the
        // current keys is what balances the books. A self-loop is read once and counted on both sides,
        // mirroring the create path.
        let start_labels = self.read_node(rel.start_node)?.labels;
        let end_labels = if rel.start_node == rel.end_node {
            start_labels
        } else {
            self.read_node(rel.end_node)?.labels
        };
        self.apply_directional_rel_counts(txn, rel.type_id, start_labels, end_labels, false)?;
        Ok(())
    }

    /// Physically reclaims a tombstoned relationship under `txn` (called by [`gc`](Self::gc) once it
    /// is invisible to every live snapshot): unlinks it from both endpoints' incidence chains (or the
    /// single chain twice, for a self-loop), **frees its property chain** (every property record and
    /// any `strings.store` overflow chain those properties own, `rmp` task #44; no leak), and frees
    /// its physical id (`04 §2.4`, `04 §2.7`). This is the old single-version delete body, now gated
    /// behind the MVCC tombstone + GC watermark — it preserves the no-leak invariant the regression
    /// tests assert via [`heap_block_usage`](Self::heap_block_usage) and the consistency checker.
    fn reclaim_rel(&mut self, txn: TxnId, id: u64) -> Result<()> {
        let rel = self.read_rel(id)?;
        // Free the relationship's property chain first (records + overflow chains), so a reclaimed
        // relationship leaves nothing live behind (`rmp` task #44; no leak). This walks and frees the
        // same `first_prop`-rooted chain the node path frees via `clear_node_properties`.
        let _freed = self.free_property_chain(txn, id, rel.first_prop)?;

        if rel.start_node == rel.end_node {
            // Self-loop: unlink both links from the one chain. Re-read between unlinks because the
            // first unlink rewrites neighbours that the second consults.
            self.unlink_side(id, ChainSide::End, rel.end_node, txn)?;
            let mid = self.read_rel(id)?;
            self.unlink_side_with(id, &mid, ChainSide::Start, mid.start_node, txn)?;
        } else {
            self.unlink_side(id, ChainSide::Start, rel.start_node, txn)?;
            self.unlink_side(id, ChainSide::End, rel.end_node, txn)?;
        }

        // Free this relationship's undo chain BEFORE the header (and with it `undo_ptr`) is cleared:
        // once the header is zeroed the chain is unreachable and its deltas would leak (`rmp` #966).
        // As for a node, the record's own reclamation precondition already implies the chain's.
        self.free_undo_chain(StoreKind::Rel, id, txn)?;
        let mut dead = self.read_rel(id)?;
        dead.first_prop = NULL_ID; // the chain is freed; drop the now-dangling head pointer
        dead.mvcc = MvccHeader::default();
        self.write_rel(id, &dead, txn)?;
        self.free_push(StoreKind::Rel, id, txn);
        Ok(())
    }

    /// Whether relationship slot `id` is a **dead-link corpse** (`rmp` #220): a slot below the
    /// high-water that is `!in_use` (its header-only creation undo cleared the in-use bit on an
    /// aborted/crashed creation) yet is NOT on the free list (no reclamation ever freed it).
    ///
    /// Whether node `node_id` has any **live** (in-use) incident relationship, transparently threading
    /// through any dead-link corpses (`rmp` #220). The GC node-reclaim guard must not be fooled into
    /// keeping a node alive by a corpse, nor reclaim a node a committed relationship still references;
    /// [`incident_rels`](Self::incident_rels) already collects only in-use rels while threading through
    /// corpses, so "empty" here means "no live incident rel".
    fn has_live_incident_rels(&mut self, node_id: u64) -> Result<bool> {
        Ok(!self.incident_rels(node_id)?.is_empty())
    }

    // --------------------- dead-link corpse reclamation (`rmp` #220) --------------------
    //
    // An aborted/crashed shared-node edge creation leaves a relationship **corpse**: a slot that the
    // header-only creation undo ([`write_record_header_undo`]) flipped to `!in_use` while PRESERVING
    // its body — its `start_node`/`end_node`, its four incidence-chain pointers, and its
    // `chain_flags` — so a concurrently-committed prepend that threaded onto it stays reachable: the
    // forward walk ([`incident_rels`], the consistency checker) passes transparently THROUGH the
    // corpse to its live successor. The corpse is correct for ACID (no committed data is lost) but it
    // is never visibility-reclaimed: it is not a live version, so [`is_reclaimable`] returns false and
    // [`reclaim_rel`] is never reached for it. Left alone it is an UNBOUNDED space leak — one dead rel
    // slot per aborted creation, forever (`rmp` #220).
    //
    // `gc_splice_corpses` reclaims it crash-safely. Two hazards a naive splice must avoid:
    //
    //   1. A corpse's OWN stored `prev`/`next`/head-flag can be **stale**. When the corpse was the
    //      chain head and a later committed writer's compare-and-set push installed a new head on top
    //      of it ([`write_chain_head`]), the node's `first_rel` no longer points at the corpse, yet the
    //      corpse still records `prev == NULL` and its first-in-chain marker. Trusting those stored
    //      pointers to find neighbours would mis-locate the splice and sever the live chain.
    //   2. Corpses can be **consecutive**: several aborted creations in a row leave a run of corpses
    //      between two live links. Bridging each corpse to its immediate neighbour would leave a live
    //      link pointing at a corpse slot that a later step frees and zeroes — a dangling pointer that
    //      drops the rest of the chain.
    //
    // Both are dissolved by re-deriving structure from a **live-chain walk**, never from the corpses'
    // own pointers, and bridging per **maximal run of consecutive corpses**: a run between live links
    // `L` (or the node head) and `R` (or the chain tail) is collapsed by repointing `L`'s facing-side
    // `next` directly at `R` and `R`'s facing-side `prev` directly at `L` (or marking `R` the new head
    // when `L` is the head). Every bridge connects LIVE-to-LIVE (or head/tail), so it never references
    // a corpse slot and the order in which corpses are later freed is irrelevant. A live relationship
    // reached *through* the run is `R` itself, which the bridge preserves, so no live thread is severed.
    // A corpse is freed once **all** its runs (it is in up to two endpoint chains; a self-loop corpse is
    // in one chain twice) have been bridged. All bridge and free writes go through the ordinary
    // WAL-logged record/node patches, so the splice replays identically under ARIES recovery: a crash
    // mid-GC makes the GC txn a loser whose undo restores the corpses in place (the pre-`#220`
    // behaviour), and redo on a committed pass completes it — no new WAL record type, the same
    // redo-repeats-history / pre-image-undo discipline as every other mutation.

    /// Splices out and frees every dead-link relationship corpse reachable from a live node's
    /// incidence chain (`rmp` #220), returning the number of corpse slots reclaimed. Called by
    /// [`gc`](Self::gc) before the node reclamation sweep so a freed corpse no longer pins its slot.
    ///
    /// Walks each live node's chain to discover maximal runs of consecutive corpses with their live
    /// endpoints (see the module comment above), bridges each run LIVE-to-LIVE with WAL-logged record
    /// patches, then frees each corpse once every run it was in has been bridged. Crash-safe and
    /// live-chain-preserving by construction.
    fn gc_splice_corpses(&mut self, txn: TxnId) -> Result<usize> {
        // Phase 1 — discover. Walk every live node's chain and collect (a) the per-chain corpse runs to
        // bridge and (b) the set of all corpse ids to free. A corpse threaded into two endpoint chains
        // contributes a run on each; a self-loop corpse contributes to its node's single chain twice.
        let mut runs: Vec<CorpseRun> = Vec::new();
        let mut corpses: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        let node_hw = self.store(StoreKind::Node).alloc.high_water();
        for node_id in 1..node_hw {
            if !Self::is_live_version(self.read_node(node_id)?.mvcc) {
                continue;
            }
            self.collect_corpse_runs(node_id, &mut runs, &mut corpses)?;
        }

        // Phase 2 — bridge every run LIVE-to-LIVE. Each bridge touches only the pointers facing the
        // run's node, so runs are independent and order-free; none references a corpse slot.
        for run in &runs {
            self.bridge_corpse_run(run, txn)?;
        }

        // Phase 3 — free the now-unreferenced corpse slots. PRESERVE the corpse body (its start/end
        // nodes and the four incidence-chain pointers), exactly as `reclaim_rel` does for a tombstoned
        // rel: a still-in-flight off-thread reader (`rmp` #336) that entered a node's incidence walk
        // holding `cur == corpse_id` BEFORE phase 2 bridged it out still threads correctly THROUGH the
        // freed corpse to the live record below it. The old code wrote `RelRecord::new(element_id, 0, 0,
        // 0, 0)`, zeroing the forward pointer, which severed such a reader's walk mid-flight and dropped
        // every live rel threaded below the corpse — a silent short (wrong) traversal result confirmed
        // by a two-thread reproduction (`rmp` #811). Only the now-dangling prop head is dropped and the
        // in-use bit stays clear; the slot is reuse-deferred by `held_slots` (#588) until every
        // predating reader retires, after which a fresh allocation overwrites the body wholesale — so
        // the "zero it so a reused slot starts clean" rationale is moot (both hazards close together).
        for &corpse_id in &corpses {
            let mut dead = self.read_rel(corpse_id)?;
            dead.first_prop = NULL_ID; // the chain is freed; drop the now-dangling head pointer
            dead.mvcc = MvccHeader::default(); // in_use stays clear
            self.write_rel(corpse_id, &dead, txn)?;
            self.free_push(StoreKind::Rel, corpse_id, txn);
        }
        Ok(corpses.len())
    }

    /// Walks `node_id`'s incidence chain (mirroring [`incident_rels`](Self::incident_rels)) and appends
    /// one [`CorpseRun`] per maximal run of consecutive corpses, recording the live predecessor (`pred`,
    /// `NULL_ID` when the run starts at the head) and live successor (`succ`, `NULL_ID` at the chain
    /// tail) that the run collapses to. Also inserts every corpse id into `corpses` for the free phase.
    /// Because `pred`/`succ` are LIVE links from the walk (never the corpses' own stale pointers),
    /// bridging is robust to stale head markers and to runs of any length.
    fn collect_corpse_runs(
        &mut self,
        node_id: u64,
        runs: &mut Vec<CorpseRun>,
        corpses: &mut std::collections::BTreeSet<u64>,
    ) -> Result<()> {
        let mut cur = self.read_node(node_id)?.first_rel;
        // Bound a corrupt cyclic incidence chain. The guard is `2 * high_water + 2` (a chain can thread
        // each rel from both ends, so up to `2 * high_water` link steps, plus slack); computed with
        // `saturating_mul`/`saturating_add` so it can never WRAP. An unchecked `2 * high_water + 2`
        // overflows for `high_water > (u64::MAX - 2) / 2` (≈ 2^63) and wraps to a tiny value — or to
        // `0` — which would DEFEAT the very cycle protection this guard exists to provide (`rmp` #452).
        // Saturation pins it at `u64::MAX` in that regime, keeping the bound monotone and sound.
        let guard = self
            .store(StoreKind::Rel)
            .alloc
            .high_water()
            .saturating_mul(2)
            .saturating_add(2);
        let mut steps = 0u64;
        let mut prev_link = NULL_ID; // the link traversed before `cur` (live or corpse)
        let mut last_live = NULL_ID; // the last LIVE link seen (an open run's `pred`)
        let mut open_run = false; // whether we are inside a corpse run awaiting its live `succ`
        while cur != NULL_ID {
            steps += 1;
            if steps > guard {
                return Err(GraphusError::Storage(format!(
                    "incidence chain of node {node_id} is malformed (cycle?)"
                )));
            }
            let r = self.read_rel(cur)?;
            let is_loop = r.start_node == node_id && r.end_node == node_id;
            // Pick the side to follow, exactly as `incident_rels`: for a self-loop, follow END's next
            // when arriving at the head/via END, else START's next.
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
            if r.mvcc.in_use() {
                // A live link closes any open corpse run: bridge `last_live -> this live link`.
                if open_run {
                    runs.push(CorpseRun {
                        node: node_id,
                        pred: last_live,
                        succ: cur,
                    });
                    open_run = false;
                }
                last_live = cur;
            } else {
                corpses.insert(cur);
                open_run = true;
            }
            prev_link = cur;
            cur = next;
        }
        // A run that reaches the chain tail closes with `succ == NULL_ID`.
        if open_run {
            runs.push(CorpseRun {
                node: node_id,
                pred: last_live,
                succ: NULL_ID,
            });
        }
        Ok(())
    }

    /// Bridges one [`CorpseRun`] LIVE-to-LIVE: repoints the run's live predecessor (or the node head) at
    /// the run's live successor, and the successor's facing-side `prev` back at the predecessor (setting
    /// it to NULL with the first-in-chain marker when the predecessor is the head). The repointing
    /// matches the side facing `run.node` whose pointer currently leads INTO the run (i.e. points at a
    /// corpse), so it bridges a run of any length without enumerating the corpse ids. It touches only
    /// the pointers facing `run.node`, never a neighbour's other-side pointers, so it cannot disturb any
    /// other chain. WAL-logged.
    fn bridge_corpse_run(&mut self, run: &CorpseRun, txn: TxnId) -> Result<()> {
        // Forward link: pred.next_facing_node := succ  (or node.first_rel := succ when pred is head).
        if run.pred == NULL_ID {
            let mut n = self.read_node(run.node)?;
            n.first_rel = run.succ;
            self.write_node(run.node, &n, txn)?;
        } else {
            self.relink_run_endpoint(run.pred, run.node, run.succ, NeighbourPtr::Next, txn)?;
        }
        // Back link: succ.prev_facing_node := pred  (NULL + first-in-chain marker when pred is head).
        if run.succ != NULL_ID {
            self.relink_run_endpoint(run.succ, run.node, run.pred, NeighbourPtr::Prev, txn)?;
        }
        Ok(())
    }

    /// On the live relationship `endpoint`, repoint the `which` pointer (`prev`/`next`) of every side
    /// facing `node` whose value currently leads INTO the just-collapsed corpse run — i.e. points at a
    /// dead-link corpse (`!in_use` rel) — to `replacement`, marking a new head when a `prev` becomes
    /// `NULL`. Unlike [`repoint_neighbour`](Self::repoint_neighbour) (which matches a specific known id),
    /// this matches "points at a corpse", so it bridges a run of any length without the corpse ids.
    fn relink_run_endpoint(
        &mut self,
        endpoint: u64,
        node: u64,
        replacement: u64,
        which: NeighbourPtr,
        txn: TxnId,
    ) -> Result<()> {
        let mut ep = self.read_rel(endpoint)?;
        let mut changed = false;
        for side in [ChainSide::Start, ChainSide::End] {
            let faces = match side {
                ChainSide::Start => ep.start_node == node,
                ChainSide::End => ep.end_node == node,
            };
            if !faces {
                continue;
            }
            let (mut p, mut nx) = ep.chain_pointers(side);
            let target = match which {
                NeighbourPtr::Next => nx,
                NeighbourPtr::Prev => p,
            };
            // The endpoint's pointer leads into the run iff it points at a corpse (`!in_use`). At bridge
            // time that target is exactly the run's first (for `Next`) / last (for `Prev`) corpse.
            if target != NULL_ID && !self.read_rel(target)?.mvcc.in_use() {
                match which {
                    NeighbourPtr::Next => nx = replacement,
                    NeighbourPtr::Prev => {
                        p = replacement;
                        if replacement == NULL_ID {
                            ep.chain_flags |= match side {
                                ChainSide::Start => CHAIN_FLAG_START_FIRST,
                                ChainSide::End => CHAIN_FLAG_END_FIRST,
                            };
                        }
                    }
                }
                ep.set_chain_pointers(side, p, nx);
                changed = true;
            }
        }
        if changed {
            self.write_rel(endpoint, &ep, txn)?;
        }
        Ok(())
    }

    /// Frees **every** still-`in_use` property record in the chain rooted at `first_prop` — live and
    /// tombstoned alike — and any overflow heap chain each owns, returning each record's id to the
    /// free list (`rmp` task #44; no leak), and returns the number of records freed. The `owner_id`
    /// is used only for the cycle-guard diagnostic. Entity-agnostic and used only when the **owner
    /// itself is being reclaimed** ([`reclaim_node`](Self::reclaim_node) /
    /// [`reclaim_rel`](Self::reclaim_rel)): the whole chain dies with the owner, so visibility is
    /// moot. For a *surviving* owner, GC uses [`gc_property_chain`](Self::gc_property_chain) instead,
    /// which frees only the reclaimable tombstoned versions and splices the chain.
    fn free_property_chain(&mut self, txn: TxnId, owner_id: u64, first_prop: u64) -> Result<usize> {
        let mut freed = 0usize;
        let mut cur = first_prop;
        let guard = self.store(StoreKind::Prop).alloc.high_water() + 1;
        let mut steps = 0u64;
        while cur != NULL_ID {
            steps += 1;
            if steps > guard {
                return Err(GraphusError::Storage(format!(
                    "property chain of entity {owner_id} is malformed (cycle?)"
                )));
            }
            let prop = self.read_prop(cur)?;
            let next = prop.next_prop;
            if prop.mvcc.in_use() {
                self.free_property_overflow(txn, &prop)?;
                let mut dead = prop;
                dead.mvcc = MvccHeader::default(); // clears in_use
                dead.next_prop = NULL_ID;
                self.write_prop(cur, &dead, txn)?;
                self.free_push(StoreKind::Prop, cur, txn);
                freed += 1;
            }
            cur = next;
        }
        Ok(freed)
    }

    /// Garbage-collects the property chain of a **still-live** owner: walks the chain rooted at
    /// `owner_kind`/`owner_id`'s `first_prop` and physically reclaims every cell that is no longer
    /// needed, returning how many it reclaimed.
    ///
    /// # What is reclaimable after `rmp` #967 — and why the old rule became silently dead
    ///
    /// This method used to key on `expired_ts != 0` (an MVCC tombstone whose `xmax` committed at or
    /// before `watermark`). After `D-property-removal` **a property operation never writes
    /// `expired_ts` again**, so that arm would have matched nothing, for ever, while still looking
    /// like a working reclaimer: a permanently dead, silently-vacuous GC path, and the property store
    /// would have grown without bound on any workload that removes properties. It is replaced rather
    /// than left alone.
    ///
    /// A cell is reclaimable when **all three** hold:
    ///
    /// 1. it is **empty** (`type_tag == 0 && value_inline == 0`) — the key is gone, not merely
    ///    overwritten. An overwritten key keeps its cell: that cell IS the current value.
    /// 2. the write that emptied it is **committed at or before `watermark`**, so no live or future
    ///    snapshot resolves the cell as present;
    /// 3. the **owner's `undo_ptr` is `0`** — the owner has no version chain at all.
    ///
    /// # What condition 3 does and does NOT buy (`rmp` #967 audit)
    ///
    /// An earlier version of this comment justified condition 3 by claiming that, while any delta
    /// survives, some snapshot may still reconstruct a value **into this cell**, so reclaiming the
    /// cell would splice away the row the reconstruction lands in. **That is false, and the code says
    /// so:** no reconstruction ever lands in a cell.
    /// [`DecisionFold::seed`](crate::scan_polarity::DecisionFold) drops every empty cell *before* the
    /// fold begins, and `DecisionFold::apply` therefore finds the key absent and **pushes** a fresh
    /// `CandidateSource::Delta` candidate. The reconstructed value is carried entirely by the delta;
    /// the cell contributes nothing to it, present or reclaimed.
    ///
    /// Visibility is settled by condition 2 alone. Worked counter-example to the old claim: `REMOVE
    /// n.k` commits at `ts = 5` (cell emptied, delta `D_k` carries the old value), `SET n.j` commits
    /// at `ts = 8` (delta `D_j`), and a reader holds `watermark = 6`. Condition 2 holds for the cell
    /// (`5 <= 6`) while condition 3 does not (`D_j` is alive, so `undo_ptr != 0`). Reclaiming the cell
    /// anyway would still read correctly at snapshot 6: the seed drops the empty cell either way, the
    /// walk applies `D_j` (committed 8 > 6) and then **stops** at `D_k` (committed 5 <= 6), so `k`
    /// reads absent — which is right. Condition 3 is therefore **sufficient, not necessary**.
    ///
    /// What it does buy is a cheap structural proof, and that is why it is kept. `undo_ptr == 0` is
    /// this store's only O(1) evidence that **Phase F has already retired the owner's entire
    /// history** — [`gc_reclaim_undo_chains`](Self::gc_reclaim_undo_chains) frees a chain
    /// all-or-nothing, and only once *every* delta on it is dead. An empty cell is consequently only
    /// ever unlinked from an owner for which no reader has any history left to reconstruct, so the
    /// splice can never race a reader that is at that moment mid-reconstruction on the same owner —
    /// the property-chain and undo-chain walks being two separate, non-atomic reads of one entity
    /// (`read_view::decision_scan_node_properties`). Re-deriving that per cell would cost a
    /// commit-slot resolution per delta per cell; this costs one header read per owner. The gate is
    /// fail-safe in the only direction that matters: getting it wrong defers a reclamation, never a
    /// read.
    ///
    /// Because it is conservative, it **defers**: a cell that satisfies (1) and (2) but not (3) is
    /// counted in [`PropChainSweep::deferred_empty`] and re-arms
    /// [`pending_empty_prop_cells`](Self#structfield.pending_empty_prop_cells), so the next pass
    /// looks again. That re-arming is what makes "a one-pass-later reclamation and never a leak" a
    /// true statement rather than an aspiration (`rmp` #967 audit): the flag used to be cleared
    /// unconditionally after every sweep, so a pass that deferred everything disarmed the gate and
    /// the cells stayed until an unrelated removal re-armed it or the store reopened.
    ///
    /// The **corpse** arm is unchanged (`rmp` #172): a `!in_use` cell not on the free list, left by
    /// an aborted/crashed creation, is spliced out and freed here. Its overflow heap is NOT freed —
    /// the aborting transaction already released those blocks through its own WAL undo, so freeing
    /// again would double-free.
    ///
    /// For each reclaimed cell it clears the in-use bit **while PRESERVING its `next_prop` forward
    /// link** (`rmp` #821/#811 — see the inline note), returns its id to the Prop free list, and
    /// splices it out of the chain.
    ///
    /// `owner_kind` MUST be [`StoreKind::Node`] or [`StoreKind::Rel`]; the owner is expected to be a
    /// live version (a tombstoned owner is reclaimed wholesale by
    /// [`reclaim_node`](Self::reclaim_node) / [`reclaim_rel`](Self::reclaim_rel), which frees the
    /// entire chain).
    ///
    /// # Errors
    /// Returns a storage error if a chain read/write fails or the chain does not terminate within the
    /// cycle guard.
    fn gc_property_chain(
        &mut self,
        txn: TxnId,
        owner_kind: StoreKind,
        owner_id: u64,
        watermark: Timestamp,
    ) -> Result<PropChainSweep> {
        let mut first_prop = self.owner_first_prop(owner_kind, owner_id)?;
        // Read once, before the walk: `undo_ptr == 0` is the O(1) proof that Phase F has already
        // retired this owner's whole history (see the method docs for what that does and does not
        // buy). While it is non-zero the empty cells below are DEFERRED, not skipped for ever.
        let owner_has_chain = self.read_mvcc(owner_kind, owner_id)?.undo_ptr != NULL_ID;
        let mut sweep = PropChainSweep::default();
        let mut prev: u64 = NULL_ID; // last *kept* property record (NULL => list head is the owner)
        let mut cur = first_prop;
        let guard = self.store(StoreKind::Prop).alloc.high_water() + 1;
        let mut steps = 0u64;
        while cur != NULL_ID {
            steps += 1;
            if steps > guard {
                return Err(GraphusError::Storage(format!(
                    "property chain of {owner_kind:?} {owner_id} is malformed (cycle?)"
                )));
            }
            let prop = self.read_prop(cur)?;
            let next = prop.next_prop;
            // Condition 1 on its own: the cell is EMPTY. Split out from the reclaim test so a cell
            // that is empty but not yet reclaimable can be counted as deferred below — the liveness
            // signal that keeps the sweep gate armed until it really is reclaimed (`rmp` #967 audit).
            let is_empty_cell = prop.mvcc.in_use()
                && prop.type_tag == undo::TYPE_TAG_ABSENT
                && prop.value_inline == NULL_ID;
            let is_tombstone = is_empty_cell
                && !owner_has_chain
                && self
                    .commit_registry
                    .resolve_commit_ts(prop.mvcc.created_ts)
                    .is_some_and(|ts| ts <= watermark);
            // A dead-link property **corpse** (`rmp` #172): a `!in_use` record not on the free list,
            // left by an aborted/crashed property creation whose header-only undo cleared in-use while
            // PRESERVING its `next_prop` body (so live walks thread through it to the committed
            // successor below it). GC splices it out and frees its slot here. Its overflow heap is NOT
            // freed: the aborting txn already released those blocks through its own WAL undo, so the
            // blocks are no longer in-use and freeing again would double-free.
            let is_corpse =
                !prop.mvcc.in_use() && !self.store(StoreKind::Prop).free.ids().contains(&cur);
            if is_tombstone || is_corpse {
                // An EMPTY cell owns no overflow chain by construction (`type_tag == 0` carries no
                // value), and a corpse's blocks were already released by its transaction's WAL undo.
                // So — unlike the pre-#967 tombstone arm — neither branch frees a heap chain here.
                // The old value's chain is owned by the delta that carries it and is freed with the
                // delta in [`free_delta`](Self::free_delta): exactly one owner, exactly one free.
                debug_assert!(
                    !is_tombstone || prop.type_tag & valenc::OVERFLOW_BIT == 0,
                    "an empty cell must not carry the overflow bit",
                );
                let mut dead = prop;
                dead.mvcc = MvccHeader::default(); // clears in_use (no-op for a corpse, already clear)
                // `rmp` #821/#811: PRESERVE `dead.next_prop` (do NOT zero it). This tombstone/corpse sits
                // on a **live** owner's chain, so an off-thread reader (`read_view::collect_prop_chain`,
                // behind `superset_scan_node_properties`/`superset_scan_rel_properties`) that
                // captured a pointer to `cur` — from the owner's `first_prop` or a predecessor's
                // `next_prop` — BEFORE the bridge below still
                // reads this record and must thread through its `next_prop` to the live successor it
                // points at. The reader correctly SKIPS this record (its `!in_use` bit hides the
                // tombstone), but it walks the chain LIVE and non-atomically: zeroing `next_prop` made
                // that reader observe `!in_use` **and** `next_prop == 0`, terminating its walk and
                // silently dropping every committed, snapshot-visible property below the tombstone — a
                // property-chain instance of the `rmp` #811 severance. The rel corpse/tombstone paths
                // (`gc_splice_corpses` phase 3, `reclaim_rel`) preserve their incidence pointers for the
                // identical reason; this brings the property chain in line. The GC watermark protects
                // VISIBILITY (the reader skips the tombstone), not STRUCTURAL traversal (it must still
                // thread `next_prop` to reach the live successor). The bridge below unlinks `cur` for
                // FRESH walks that start after it; `held_slots` (#588) defers slot **reuse** while a
                // predating reader is in flight; and a later `write_prop_create` overwrites the slot
                // wholesale, so no stale pointer ever survives into a reused slot.
                self.write_prop(cur, &dead, txn)?;
                self.free_push(StoreKind::Prop, cur, txn);
                if prev == NULL_ID {
                    first_prop = next;
                    self.set_owner_first_prop(owner_kind, owner_id, first_prop, txn)?;
                } else {
                    let mut p = self.read_prop(prev)?;
                    p.next_prop = next;
                    self.write_prop(prev, &p, txn)?;
                }
                sweep.reclaimed += 1;
            } else {
                // An empty cell that survives this pass failed condition 2 or condition 3, both of
                // which a later pass can satisfy (the watermark advances; Phase F retires the chain).
                // Count it so the caller keeps the sweep gate armed instead of disarming it on a pass
                // that reclaimed nothing.
                if is_empty_cell {
                    sweep.deferred_empty += 1;
                }
                prev = cur; // kept: it becomes the predecessor of whatever follows
            }
            cur = next;
        }
        Ok(sweep)
    }

    /// Reads the `first_prop` head pointer of a node or relationship owner (GC helper).
    fn owner_first_prop(&mut self, owner_kind: StoreKind, owner_id: u64) -> Result<u64> {
        Ok(match owner_kind {
            StoreKind::Node => self.read_node(owner_id)?.first_prop,
            StoreKind::Rel => self.read_rel(owner_id)?.first_prop,
            StoreKind::Prop | StoreKind::Strings | StoreKind::Undo | StoreKind::Commit => {
                return Err(GraphusError::Storage(format!(
                    "{owner_kind:?} is not a property-chain owner"
                )));
            }
        })
    }

    /// Repoints the `first_prop` head pointer of a node or relationship owner, rewriting the owner
    /// record under `txn` (GC helper, used when the head property is spliced out).
    fn set_owner_first_prop(
        &mut self,
        owner_kind: StoreKind,
        owner_id: u64,
        first_prop: u64,
        txn: TxnId,
    ) -> Result<()> {
        match owner_kind {
            StoreKind::Node => {
                let mut node = self.read_node(owner_id)?;
                node.first_prop = first_prop;
                self.write_node(owner_id, &node, txn)
            }
            StoreKind::Rel => {
                let mut rel = self.read_rel(owner_id)?;
                rel.first_prop = first_prop;
                self.write_rel(owner_id, &rel, txn)
            }
            StoreKind::Prop | StoreKind::Strings | StoreKind::Undo | StoreKind::Commit => Err(
                GraphusError::Storage(format!("{owner_kind:?} is not a property-chain owner")),
            ),
        }
    }

    fn unlink_side(&mut self, id: u64, side: ChainSide, node: u64, txn: TxnId) -> Result<()> {
        let rel = self.read_rel(id)?;
        self.unlink_side_with(id, &rel, side, node, txn)
    }

    /// Unlinks one chain side of relationship `id` (whose current image is `rel`) from `node`'s
    /// incidence chain: bridges its neighbours and, if it was the head, repoints `first_rel`.
    fn unlink_side_with(
        &mut self,
        id: u64,
        rel: &RelRecord,
        side: ChainSide,
        node: u64,
        txn: TxnId,
    ) -> Result<()> {
        let (prev, next) = rel.chain_pointers(side);
        if prev == NULL_ID {
            let mut n = self.read_node(node)?;
            n.first_rel = next;
            self.write_node(node, &n, txn)?;
        } else {
            self.repoint_neighbour(prev, node, id, next, NeighbourPtr::Next, txn)?;
        }
        if next != NULL_ID {
            self.repoint_neighbour(next, node, id, prev, NeighbourPtr::Prev, txn)?;
        }
        Ok(())
    }

    /// On relationship `neighbour`, replace the `which` pointer (`prev`/`next`) of every side
    /// facing `node` that currently equals `id` with `replacement`; mark a new head when a `prev`
    /// becomes `NULL`.
    fn repoint_neighbour(
        &mut self,
        neighbour: u64,
        node: u64,
        id: u64,
        replacement: u64,
        which: NeighbourPtr,
        txn: TxnId,
    ) -> Result<()> {
        let mut nb = self.read_rel(neighbour)?;
        let patch = |side: ChainSide, n: &mut RelRecord| {
            let (mut p, mut nx) = n.chain_pointers(side);
            match which {
                NeighbourPtr::Next if nx == id => nx = replacement,
                NeighbourPtr::Prev if p == id => {
                    p = replacement;
                    if replacement == NULL_ID {
                        n.chain_flags |= match side {
                            ChainSide::Start => CHAIN_FLAG_START_FIRST,
                            ChainSide::End => CHAIN_FLAG_END_FIRST,
                        };
                    }
                }
                _ => {}
            }
            n.set_chain_pointers(side, p, nx);
        };
        if nb.start_node == node {
            patch(ChainSide::Start, &mut nb);
        }
        if nb.end_node == node {
            patch(ChainSide::End, &mut nb);
        }
        self.write_rel(neighbour, &nb, txn)
    }

    // ----------------------------- property CRUD ----------------------------

    /// Creates a property `(key, type_tag, value_inline)` under `txn` and prepends it to node
    /// `node_id`'s property chain; returns the property's physical id.
    ///
    /// # This is the LOW-LEVEL cell primitive, and it is not isolation-aware
    ///
    /// It writes a cell and nothing else: no write-conflict check, and **no undo delta**. After
    /// `rmp` #967's `D-property-visibility` a cell's own `created_ts` decides nothing — the undo
    /// chain is the sole visibility oracle for a property's value — so a cell created through this
    /// method alone is visible to **every** snapshot the instant it is written, including snapshots
    /// older than `txn`, and including while `txn` is still open.
    ///
    /// That is correct for its callers and wrong for anything else. Use it only where the writer
    /// holds the entity exclusively and no concurrent reader can observe an intermediate state — a
    /// bulk import into a database not yet serving traffic, or a test fixture. **Every production
    /// path must go through [`set_node_property_value`](Self::set_node_property_value)**, which runs
    /// the conflict check and links the "the key was absent" delta that hides the new key from an
    /// older snapshot. That method calls this one only after doing both.
    ///
    /// # Errors
    /// Returns a storage error if the node is not in use or a write fails.
    pub fn add_node_property(
        &mut self,
        txn: TxnId,
        node_id: u64,
        key: u32,
        type_tag: u8,
        value_inline: u64,
    ) -> Result<u64> {
        let node = self.read_node(node_id)?;
        if !Self::is_live_version(node.mvcc) {
            return Err(GraphusError::Storage(format!("node {node_id} not in use")));
        }
        let pid = self.alloc_id(StoreKind::Prop, txn)?;
        // `rmp` #581: if `pid` reused a freed slot, remember its owner so a live rollback can decide
        // whether the popped id became a live-referenced corpse (walk this node's prop chain) or a
        // reclaimable dead slot.
        self.note_popped_prop_owner(txn, pid, StoreKind::Node, node_id);
        // Stamp `xmin` with the writer's in-flight `TxnId` (`04 §5.2`; per-value MVCC, `rmp` task
        // #50); `commit` settles it to the commit timestamp. Until then the version is visible only
        // to its own transaction.
        let mut prop = PropRecord::new(VersionStamp::in_flight(txn), key, type_tag, value_inline);
        prop.next_prop = node.first_prop;
        let old_head = node.first_prop;
        // Header-only creation undo for the prop + compare-and-set logical undo for the owner's
        // `first_prop` head (`rmp` #172). A loser's abort then reverts only the prop's in-use bit (its
        // `next_prop` body is preserved, so a committed prepend threads through it) and CAS-no-ops the
        // head if a committed writer has since pushed on top — so an unrelated committed property
        // version below the loser's record is never severed.
        self.write_prop_create(pid, &prop, txn)?;
        self.note_created(txn, StoreKind::Prop, pid);
        self.write_chain_head(
            StoreKind::Node,
            node_id,
            NODE_OFF_FIRST_PROP,
            pid,
            old_head,
            txn,
        )?;
        Ok(pid)
    }

    /// Reads the property record at physical id `id`.
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated.
    pub fn property(&self, id: u64) -> Result<PropRecord> {
        self.read_prop(id)
    }

    /// The **superset**-polarity read of node `node_id`'s property chain: every **slot-occupied**
    /// (`in_use`) `(physical_id, record)`, head to tail — which is prepend order, so the FIRST
    /// occurrence of a key is its NEWEST version (`rmp` task #905 named the polarity; see
    /// [`scan_polarity`](crate::scan_polarity) for the taxonomy).
    ///
    /// # This includes every historical value
    ///
    /// After `rmp` #967 the entity's *older* values are not cells at all — they are `SetProperty`
    /// deltas on its undo chain — so the superset is `cells + delta history`, reached through
    /// [`SupersetProperties::candidates`]. A caller that reads only the cells sees the **current**
    /// image and silently loses every value an older snapshot still needs. That is the point: an
    /// index refill has no snapshot and must populate a **superset** its consumers re-check
    /// (`rmp` task #766).
    ///
    /// # It is the wrong read for a decision
    ///
    /// A caller whose answer is final and is never re-checked — a constraint verdict, above all — must
    /// call [`decision_scan_node_properties`](Self::decision_scan_node_properties), or narrow this
    /// chain itself with [`SupersetProperties::decide`], which requires the deciding
    /// [`Snapshot`]. This doc comment used to say "every **live** property", which is what the code
    /// does NOT do; a caller that believed it counted a committed `REMOVE n.p` as a present value
    /// (`rmp` task #902).
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing.
    pub fn superset_scan_node_properties(&self, node_id: u64) -> Result<SupersetProperties> {
        read_view::superset_scan_node_properties(&self.pool, &self.stores, node_id)
    }

    /// The **decision**-polarity read of node `node_id`'s properties: the newest version of each key
    /// that `snapshot` can see, and nothing else (`rmp` task #905).
    ///
    /// This is [`superset_scan_node_properties`](Self::superset_scan_node_properties) narrowed by
    /// [`SupersetProperties::decide`] against this store's [`CommitRegistry`] — that is, by the same
    /// [`graphus_txn::is_visible`] predicate the query read path applies, so the caller decides over
    /// exactly the graph a `MATCH` in the same transaction would return.
    ///
    /// Use it wherever the answer is **final**: nothing downstream re-checks a constraint verdict, so
    /// reading the superset there counted a committed `REMOVE n.p` as a present value and both refused
    /// valid constraints and admitted invalid ones (`rmp` task #902).
    ///
    /// # Errors
    /// As [`superset_scan_node_properties`](Self::superset_scan_node_properties). Values are not
    /// decoded here, so an unreadable overflow chain belonging to an uninvolved property does not fail
    /// the caller (`rmp` task #733).
    pub fn decision_scan_node_properties(
        &self,
        node_id: u64,
        snapshot: Snapshot,
    ) -> Result<DecidedProperties> {
        read_view::decision_scan_node_properties(&self.pool, &self.stores, node_id, snapshot)
    }

    // ---------- the value-level property write path (`rmp` #967, `04 §5.1.2` / §5.1.5) ----------
    //
    // Three operations — SET, REMOVE and "replace the whole set" — over two owner kinds, all built
    // from the same four steps, in this order and no other:
    //
    //   1. the owner must be a live version;
    //   2. `ensure_no_conflicting_writer` (`D-property-write-conflict`);
    //   3. `link_set_property` — the delta carrying the OLD value, written IN FULL and published as
    //      the entity's chain head;
    //   4. `write_prop_cell` — the new value, in place, as one contiguous patch.
    //
    // Steps 3 and 4 are ordered, not incidental: see `write_prop_cell`'s "abort story".
    //
    // What is NOT here any more is the whole of the old mechanism: no `xmax` stamp, no fresh record,
    // no `first_prop` prepend, and no walk of the entity's accumulated versions. `tombstone_props_for_key`
    // — which walked the entity's WHOLE chain on every write regardless of the key filter, and was
    // the quadratic term `rmp` #967 exists to remove — is retired, together with the `Prop` arm of
    // `note_expired` / `pending_tombstones` that fed the tombstone reclamation.

    /// Sets `(kind, entity)`'s property `key` to `value` under `txn`, replacing whatever it held.
    /// Returns the physical id of the cell that now holds the value.
    fn set_entity_property_value(
        &mut self,
        txn: TxnId,
        kind: StoreKind,
        entity: u64,
        key: u32,
        value: &graphus_core::Value,
    ) -> Result<u64> {
        // P2: encode first, so a value this build cannot persist errors before any mutation.
        let (type_tag, value_inline) = self.encode_property_value(txn, value)?;
        debug_assert_ne!(
            type_tag,
            undo::TYPE_TAG_ABSENT,
            "no encoder may emit the absent sentinel; `undo::TYPE_TAG_ABSENT` would become \
             ambiguous with a real value (pinned by `undo::tests::no_encoder_can_emit_the_absent_type_tag`)"
        );
        let label = Self::owner_label(kind, entity);
        if !Self::is_live_version(self.read_mvcc(kind, entity)?) {
            return Err(GraphusError::Storage(format!("{label} not in use")));
        }
        self.ensure_no_conflicting_writer(kind, entity, txn)?; // P1
        let first_prop = self.owner_chain_head(kind, entity)?;
        match self.find_live_prop_cell(first_prop, key, &label)? {
            // (a) The key already has a cell — live or emptied by an earlier `REMOVE`. Reuse it: the
            // old value (or its absence) descends onto the chain and the cell is rewritten in place.
            // No allocation, no `first_prop` change, no tombstone. That is the whole quadratic
            // removal.
            Some((pid, cell)) => {
                self.link_set_property(kind, entity, key, cell.type_tag, cell.value_inline, txn)?;
                let mut next = cell;
                next.mvcc.created_ts = VersionStamp::in_flight(txn);
                next.type_tag = type_tag;
                next.value_inline = value_inline;
                self.write_prop_cell(pid, &next, txn)?;
                Ok(pid)
            }
            // (b) The key is absent. The "was absent" delta is written FIRST and is not optional: it
            // is the only thing that hides the new key from an older snapshot now that the cell's own
            // stamp decides nothing (`D-property-visibility`).
            None => {
                self.link_set_property(kind, entity, key, undo::TYPE_TAG_ABSENT, NULL_ID, txn)?;
                self.add_entity_property(txn, kind, entity, key, type_tag, value_inline)
            }
        }
    }

    /// Removes `(kind, entity)`'s property `key` under `txn`, returning whether anything changed.
    fn remove_entity_property_value(
        &mut self,
        txn: TxnId,
        kind: StoreKind,
        entity: u64,
        key: u32,
    ) -> Result<bool> {
        let label = Self::owner_label(kind, entity);
        if !Self::is_live_version(self.read_mvcc(kind, entity)?) {
            return Err(GraphusError::Storage(format!("{label} not in use")));
        }
        self.ensure_no_conflicting_writer(kind, entity, txn)?; // P1
        let first_prop = self.owner_chain_head(kind, entity)?;
        let Some((pid, cell)) = self.find_live_prop_cell(first_prop, key, &label)? else {
            return Ok(false);
        };
        if cell.type_tag == undo::TYPE_TAG_ABSENT {
            // Already empty: the key is absent, so removing it changes nothing and must not push a
            // delta (a chain of no-op deltas would grow without bound under a repeated `REMOVE`).
            return Ok(false);
        }
        self.link_set_property(kind, entity, key, cell.type_tag, cell.value_inline, txn)?;
        self.empty_prop_cell(pid, cell, txn)?;
        Ok(true)
    }

    /// Empties every live property cell of `(kind, entity)` under `txn` (`SET n = map`), returning
    /// how many cells were cleared.
    fn clear_entity_properties(
        &mut self,
        txn: TxnId,
        kind: StoreKind,
        entity: u64,
    ) -> Result<usize> {
        let label = Self::owner_label(kind, entity);
        if !Self::is_live_version(self.read_mvcc(kind, entity)?) {
            return Err(GraphusError::Storage(format!("{label} not in use")));
        }
        // ONE conflict check for the whole operation: it is the entity that is held, not the key.
        self.ensure_no_conflicting_writer(kind, entity, txn)?; // P1
        let first_prop = self.owner_chain_head(kind, entity)?;
        // Collect before mutating: the walk reads the same records the loop rewrites.
        let cells = self.live_prop_cells(first_prop, &label)?;
        let mut cleared = 0usize;
        for (pid, cell) in cells {
            if cell.type_tag == undo::TYPE_TAG_ABSENT {
                continue; // already empty — nothing to descend onto the chain
            }
            self.link_set_property(
                kind,
                entity,
                cell.key,
                cell.type_tag,
                cell.value_inline,
                txn,
            )?;
            self.empty_prop_cell(pid, cell, txn)?;
            cleared += 1;
        }
        Ok(cleared)
    }

    /// Rewrites cell `pid` in place to the **empty** form (`D-property-removal`): `type_tag = 0`,
    /// `value_inline = 0`, `created_ts` restamped to this writer, `in_use` and `next_prop` untouched
    /// so the cell keeps its slot and its place in the owner's chain and a later `SET` of the same
    /// key reuses it with no allocation.
    ///
    /// The caller MUST already have linked the delta carrying the old value: after this write the
    /// cell no longer names the old `strings.store` chain, so the delta is its **only** owner. That
    /// is exactly the single-owner rule that makes the empty cell safe to reclaim later.
    fn empty_prop_cell(&mut self, pid: u64, cell: PropRecord, txn: TxnId) -> Result<()> {
        let mut empty = cell;
        empty.mvcc.created_ts = VersionStamp::in_flight(txn);
        empty.type_tag = undo::TYPE_TAG_ABSENT;
        empty.value_inline = NULL_ID;
        self.write_prop_cell(pid, &empty, txn)?;
        // An empty cell is what GC's property sweep now reclaims, so gate the sweep on one existing.
        self.pending_empty_prop_cells = true;
        Ok(())
    }

    /// Dispatches the low-level cell creation to the owner kind's chain.
    fn add_entity_property(
        &mut self,
        txn: TxnId,
        kind: StoreKind,
        entity: u64,
        key: u32,
        type_tag: u8,
        value_inline: u64,
    ) -> Result<u64> {
        match kind {
            StoreKind::Node => self.add_node_property(txn, entity, key, type_tag, value_inline),
            StoreKind::Rel => self.add_rel_property(txn, entity, key, type_tag, value_inline),
            StoreKind::Prop | StoreKind::Strings | StoreKind::Undo | StoreKind::Commit => Err(
                GraphusError::Storage(format!("{kind:?} is not a property-chain owner")),
            ),
        }
    }

    /// `"node 5"` / `"rel 7"` — the diagnostic label the chain walks and errors use.
    fn owner_label(kind: StoreKind, id: u64) -> String {
        match kind {
            StoreKind::Node => format!("node {id}"),
            StoreKind::Rel => format!("rel {id}"),
            other => format!("{other:?} {id}"),
        }
    }

    // --------------------- strings.store overflow heap ----------------------
    //
    // The `strings.store` variable-length value heap (`04 §2.1`, `04 §2.3`; `rmp` task #43). A byte
    // payload is stored as a chain of fixed-size [`HeapBlock`]s (one block per `BLOCK_PAYLOAD`-byte
    // chunk, see [`crate::heap`]); the chain is addressed by the physical id of its **head** block —
    // the id a property record holds in `value_inline` with the `type_tag` overflow bit set. Blocks
    // are allocated/freed through the same WAL-logged page-patch path and per-store free list as
    // every other record, so a chain is durable on commit and recovered (redo/undo) by the same
    // three-phase ARIES machinery (`04 §4`); freeing a chain returns its blocks to the free list so
    // a later allocation reuses them (no leak).

    /// Allocates a block chain holding `payload` and returns the physical id of its **head** block
    /// (`rmp` task #43). The chain always has at least one block (an empty payload allocates one
    /// empty block), so the returned head id is a valid, non-null pointer (`04 §2.2`).
    ///
    /// Blocks are linked tail-to-head: each block's `next_block` points at the block holding the
    /// following chunk. Freed block ids are reused before the store is extended (`04 §2.7`).
    ///
    /// # Errors
    /// Returns a storage error if a block write fails.
    pub fn alloc_chain(&mut self, txn: TxnId, payload: &[u8]) -> Result<u64> {
        let n_blocks = heap::blocks_needed(payload.len());
        // Build the chain from the tail back to the head so each block knows its successor's id.
        let mut next = NULL_ID;
        let mut head = NULL_ID;
        // An empty payload still allocates a single empty block (`04 §2.2`); a non-empty payload is
        // split into `BLOCK_PAYLOAD`-sized chunks. Iterate the chunks directly in reverse (tail to
        // head) without collecting them into a temporary `Vec`. The empty-payload branch yields one
        // empty chunk, matching the previous `payload_chunks` invariant exactly.
        let mut empty_iter = std::iter::once::<&[u8]>(&[]);
        let mut chunk_iter = payload.chunks(BLOCK_PAYLOAD).rev();
        let chunks: &mut dyn Iterator<Item = &[u8]> = if payload.is_empty() {
            &mut empty_iter
        } else {
            &mut chunk_iter
        };
        // `rmp` #410: the heap block's creator stamp is `txn.0`, which becomes the in-use block's MVCC
        // `xmin`. The #398 orphan well-formedness check's heap arm
        // ([`orphan_page_records_well_formed`]) treats a `0` `xmin` as the `VersionStamp::None`
        // none-sentinel and *rejects* the page as malformed — so a heap write under `TxnId(0)` would
        // make a legitimately-written page fail orphan re-attribution on the next open. `TxnId(0)` is
        // reserved (never handed to a real transaction) precisely so this never happens; assert it here
        // so a future change that violates the reservation fails loudly at the write site rather than
        // silently producing pages that vanish on recovery.
        assert!(
            txn.0 != 0,
            "INVARIANT: heap writes must use a real TxnId; TxnId(0) is reserved (its 0 xmin is the \
             MVCC none-sentinel the #398 orphan check rejects)"
        );
        for chunk in chunks {
            let id = self.alloc_id(StoreKind::Strings, txn)?;
            let block = HeapBlock::new(txn.0, chunk, next);
            self.write_block(id, &block, txn)?;
            next = id;
            head = id;
        }
        debug_assert_ne!(head, NULL_ID, "a chain always has >= 1 block");
        debug_assert!(n_blocks >= 1);
        Ok(head)
    }

    /// Reads back the byte payload of the chain whose head block is `head`, concatenating each
    /// block's used bytes head-to-tail (`rmp` task #43).
    ///
    /// # Errors
    /// Returns a storage error if a block page is missing, a block id is out of range, or the chain
    /// does not terminate within a cycle guard (a corrupted chain is *reported*, never looped on —
    /// mirrors the property/adjacency chain guards).
    pub fn read_chain(&self, head: u64) -> Result<Vec<u8>> {
        read_view::read_chain(&self.pool, &self.stores, head)
    }

    /// Frees every block of the chain whose head is `head`, clearing each block's `in_use` bit (a
    /// WAL-logged write) and returning its id to the free list so it is reused (`04 §2.7`; no leak).
    ///
    /// # Errors
    /// Returns a storage error if a block read/write fails or the chain does not terminate within a
    /// cycle guard.
    pub fn free_chain(&mut self, txn: TxnId, head: u64) -> Result<()> {
        let mut cur = head;
        let guard = self.store(StoreKind::Strings).alloc.high_water() + 1;
        let mut steps = 0u64;
        while cur != NULL_ID {
            steps += 1;
            if steps > guard {
                return Err(GraphusError::Storage(format!(
                    "overflow chain at head {head} is malformed (cycle?)"
                )));
            }
            let mut block = self.read_block(cur)?;
            let next = block.next_block;
            if block.mvcc.in_use() {
                block.mvcc = MvccHeader::default(); // clears in_use
                self.write_block(cur, &block, txn)?;
                self.free_push(StoreKind::Strings, cur, txn);
            }
            cur = next;
        }
        Ok(())
    }

    /// The number of currently-allocated (in-use, not freed) heap blocks — i.e. the heap's live
    /// block usage. A test asserts an overwrite/removal frees the old chain by checking this does
    /// **not** grow across an overwrite (no block leak, `rmp` task #43).
    ///
    /// # Errors
    /// Returns a storage error if a heap page cannot be read.
    pub fn heap_block_usage(&mut self) -> Result<u64> {
        let high_water = self.store(StoreKind::Strings).alloc.high_water();
        let freed: std::collections::BTreeSet<u64> = self
            .store(StoreKind::Strings)
            .free
            .ids()
            .iter()
            .copied()
            .collect();
        let mut live = 0u64;
        for id in 1..high_water {
            if !freed.contains(&id) && self.read_block(id)?.mvcc.in_use() {
                live += 1;
            }
        }
        Ok(live)
    }

    // -------------------- value-level node property API ---------------------
    //
    // The value-level layer (`rmp` task #43) sits above the low-level inline `add_node_property`:
    // it takes a typed [`Value`], stores inline scalars exactly as #38 did, and overflows String /
    // List values to the `strings.store` heap, stamping the `type_tag` overflow bit and the head
    // block id into the property record's `value_inline`. Reading reverses the choice.

    /// Sets node `node_id`'s property `key` to `value` under `txn`, **replacing** any current value
    /// of that key (`rmp` #967, `04 §5.1.5`).
    ///
    /// The newest version is written **in place**: the key's existing cell — creating one only if the
    /// key is genuinely absent — is rewritten with the new `(type_tag, value_inline)`, and the value
    /// it held descends onto the owning node's undo-delta chain as a
    /// [`SetProperty`](UndoAction::SetProperty) delta, which is what an older snapshot reconstructs
    /// its view from (`D-property-visibility`). Nothing is tombstoned, nothing is prepended, and the
    /// property chain does not grow — so overwriting one key M times costs `Θ(M)` in total rather
    /// than the `Θ(M²)` the tombstone-and-prepend path cost.
    ///
    /// Inline scalars (`Integer`/`Float`/`Boolean`) stay inline (#38); `String`/`List`/temporal values
    /// are serialized to the `strings.store` overflow heap and the cell holds the head block id with
    /// the `type_tag` overflow bit set (`04 §2.3`). The **old** value's overflow chain is not freed
    /// here: once the delta is linked the delta owns it exclusively, and GC frees it with the delta.
    ///
    /// Returns the physical id of the cell that now holds the value.
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] — a **retriable serialization failure** — if another still-open
    ///   transaction holds this node (`D-property-write-conflict`; see
    ///   `ensure_no_conflicting_writer`).
    /// - [`GraphusError::Storage`] if the node is not in use or a write fails.
    /// - [`GraphusError::Runtime`] (from the value codecs) if `value` is `Null` (not persisted) or a
    ///   class this build cannot store (e.g. `Map`, a heterogeneous `List`).
    pub fn set_node_property_value(
        &mut self,
        txn: TxnId,
        node_id: u64,
        key: u32,
        value: &graphus_core::Value,
    ) -> Result<u64> {
        self.set_entity_property_value(txn, StoreKind::Node, node_id, key, value)
    }

    /// Removes node `node_id`'s property `key` under `txn` (`rmp` #967, `D-property-removal`).
    ///
    /// The cell is rewritten **in place** to the empty form (`type_tag = 0`, `value_inline = 0`),
    /// keeping its `in_use` bit and its place in the node's `first_prop` chain, and the removed value
    /// descends onto the node's undo chain so an older snapshot still reads it. There is no `xmax`
    /// tombstone: after this task a property operation never writes `expired_ts` at all. A later
    /// `SET` of the same key reuses the empty cell with no allocation.
    ///
    /// Returns whether anything changed, so a caller can distinguish a real removal from a no-op
    /// (`REMOVE n.p` on a key the node does not hold).
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] on a write-write conflict, as
    ///   [`set_node_property_value`](Self::set_node_property_value).
    /// - [`GraphusError::Storage`] if the node is not in use or a write fails.
    pub fn remove_node_property_value(
        &mut self,
        txn: TxnId,
        node_id: u64,
        key: u32,
    ) -> Result<bool> {
        self.remove_entity_property_value(txn, StoreKind::Node, node_id, key)
    }

    /// Encodes `value` into the `(type_tag, value_inline)` pair to store in a property record,
    /// allocating an overflow chain for `String`/`List`/temporal values.
    fn encode_property_value(
        &mut self,
        txn: TxnId,
        value: &graphus_core::Value,
    ) -> Result<(u8, u64)> {
        // Inline scalars (Integer/Float/Boolean) keep the #38 inline path verbatim.
        match crate::propenc::encode_inline(value) {
            Ok(pair) => return Ok(pair),
            Err(crate::propenc::PropEncodeError::Null) => {
                return Err(GraphusError::from(crate::propenc::PropEncodeError::Null));
            }
            // Not inline: fall through to the overflow heap (String / List / temporal); a class
            // neither the inline codec nor the overflow codec accepts is surfaced by
            // `valenc::encode` below.
            Err(crate::propenc::PropEncodeError::NonInline { .. }) => {}
        }
        let (class_tag, bytes) = valenc::encode(value).map_err(GraphusError::from)?;
        let head = self.alloc_chain(txn, &bytes)?;
        Ok((class_tag | valenc::OVERFLOW_BIT, head))
    }

    /// Decodes a property record's `(type_tag, value_inline)` into a [`Value`](graphus_core::Value),
    /// reading the overflow heap chain when the `type_tag`'s overflow bit is set (`04 §2.3`,
    /// `rmp` task #43).
    ///
    /// # Errors
    /// Returns a storage error if the chain is unreadable/corrupt or the tag is one this build does
    /// not understand.
    pub fn decode_property_value(
        &self,
        type_tag: u8,
        value_inline: u64,
    ) -> Result<graphus_core::Value> {
        read_view::decode_property_value(&self.pool, &self.stores, type_tag, value_inline)
    }

    /// The **superset**-polarity read of node `node_id`'s properties, **decoded**: every
    /// slot-occupied `(physical_id, key_token, Value)` in the chain, decoding both inline scalars and
    /// overflow `String`/`List`/temporal values (`rmp` task #43).
    ///
    /// The decoded twin of
    /// [`superset_scan_node_properties`](Self::superset_scan_node_properties), and it carries
    /// exactly the same polarity: the chain is walked head-to-tail (prepend order, so newest first
    /// per key) and **every** version is returned — MVCC tombstones and uncommitted versions
    /// included. This doc comment used to say "live properties", the same false claim `rmp` task
    /// #902 had to correct on the undecoded twin.
    ///
    /// Values are decoded eagerly, so it cannot be the read a decision path uses: pick a version
    /// first, through [`decision_scan_node_properties`](Self::decision_scan_node_properties), and
    /// decode only that one (`rmp` tasks #733, #905).
    ///
    /// # Errors
    /// Returns a storage error if the property chain or an overflow chain is unreadable/corrupt.
    pub fn superset_scan_node_property_values(
        &self,
        node_id: u64,
    ) -> Result<Vec<(u64, u32, graphus_core::Value)>> {
        let chain = self.superset_scan_node_properties(node_id)?;
        let candidates: Vec<_> = chain.candidates().collect();
        let mut out = Vec::with_capacity(candidates.len());
        for c in candidates {
            let value = self.decode_property_value(c.type_tag, c.value_inline)?;
            out.push((c.source.id(), c.key, value));
        }
        Ok(out)
    }

    /// Clears **all** of node `node_id`'s properties under `txn` — the storage half of `SET n = map`,
    /// which replaces the whole property set (`rmp` #967).
    ///
    /// Every live cell is emptied **in place** exactly as
    /// [`remove_node_property_value`](Self::remove_node_property_value) empties one, each preceded by
    /// its own `SetProperty` delta carrying that cell's old `(key, type_tag, value)`, so an older
    /// snapshot reconstructs the complete previous property set. The cells keep their slots and their
    /// `next_prop` links, and `first_prop` is not reset.
    ///
    /// Returns the number of cells **cleared** — note the changed meaning: it used to be the number
    /// of records tombstoned. A cell that was already empty is not counted (and pushes no delta),
    /// so callers comparing against `0` still read "did anything change?".
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] on a write-write conflict, as
    ///   [`set_node_property_value`](Self::set_node_property_value).
    /// - [`GraphusError::Storage`] if the node is not in use or a write fails.
    pub fn clear_node_properties(&mut self, txn: TxnId, node_id: u64) -> Result<usize> {
        self.clear_entity_properties(txn, StoreKind::Node, node_id)
    }

    /// Frees the overflow heap chain a property record owns, if any: a no-op for an inline scalar;
    /// for an overflowed `String`/`List`/temporal value it frees the chain whose head is
    /// `value_inline` (`rmp` task #43).
    ///
    /// **Not used by the value-level write path** since `rmp` #967, and it must not be: an overwrite
    /// or a removal hands the old chain to the `SetProperty` delta that carries it, and the delta is
    /// then its **sole** owner until GC frees the two together
    /// (`free_delta`). Freeing here as well would be a double-free. Its
    /// remaining caller is `free_property_chain`, which reclaims a
    /// deleted entity's cells and the chains those cells still own.
    ///
    /// # Errors
    /// Returns a storage error if freeing the chain fails.
    pub fn free_property_overflow(&mut self, txn: TxnId, prop: &PropRecord) -> Result<()> {
        if prop.type_tag & valenc::OVERFLOW_BIT != 0 && prop.value_inline != NULL_ID {
            self.free_chain(txn, prop.value_inline)?;
        }
        Ok(())
    }

    // ---------------- relationship property CRUD (`rmp` task #44) -----------------
    //
    // Relationship properties mirror the node-property path exactly (`04 §2.3`, `05 §9`): a
    // relationship's property chain is rooted at [`RelRecord.first_prop`](crate::record::RelRecord)
    // — the relationship analogue of `NodeRecord.first_prop` — and threaded through the **same**
    // `props.store` records via `PropRecord.next_prop`, with the **same** `strings.store` overflow
    // heap for `String`/`List`/temporal values (`rmp` task #43) and the same prepend-chain +
    // newest-wins discipline. Every write is WAL-logged and crash-recoverable through the same
    // ARIES machinery (`04 §4`). Index seeks + MVCC over these chains remain `rmp` task #39,
    // untouched here.

    /// Creates a property `(key, type_tag, value_inline)` under `txn` and prepends it to relationship
    /// `rel_id`'s property chain (`rmp` task #44); returns the property's physical id. The low-level
    /// inline counterpart to [`add_node_property`](Self::add_node_property), over
    /// [`RelRecord.first_prop`](crate::record::RelRecord) — **including its isolation contract**:
    /// no conflict check, no undo delta, so the cell it writes is visible to every snapshot at once.
    /// Read that method's docs before calling this one.
    ///
    /// # Errors
    /// Returns a storage error if the relationship is not in use or a write fails.
    pub fn add_rel_property(
        &mut self,
        txn: TxnId,
        rel_id: u64,
        key: u32,
        type_tag: u8,
        value_inline: u64,
    ) -> Result<u64> {
        let rel = self.read_rel(rel_id)?;
        if !Self::is_live_version(rel.mvcc) {
            return Err(GraphusError::Storage(format!("rel {rel_id} not in use")));
        }
        let pid = self.alloc_id(StoreKind::Prop, txn)?;
        // `rmp` #581: remember the owner of a reused prop slot for the rollback corpse check.
        self.note_popped_prop_owner(txn, pid, StoreKind::Rel, rel_id);
        // Stamp `xmin` with the writer's in-flight `TxnId` (`04 §5.2`; per-value MVCC, `rmp` task
        // #50); `commit` settles it to the commit timestamp.
        let mut prop = PropRecord::new(VersionStamp::in_flight(txn), key, type_tag, value_inline);
        prop.next_prop = rel.first_prop;
        let old_head = rel.first_prop;
        // Header-only creation undo + compare-and-set head undo (`rmp` #172), mirroring
        // `add_node_property`: a loser's abort never severs an unrelated committed property version
        // below this record, nor clobbers a committed head.
        self.write_prop_create(pid, &prop, txn)?;
        self.note_created(txn, StoreKind::Prop, pid);
        self.write_chain_head(
            StoreKind::Rel,
            rel_id,
            REL_OFF_FIRST_PROP,
            pid,
            old_head,
            txn,
        )?;
        Ok(pid)
    }

    /// The **superset**-polarity read of relationship `rel_id`'s property chain (`rmp` task #44): every
    /// **slot-occupied** (`in_use`) `(physical_id, record)`, head to tail. The relationship analogue of
    /// [`superset_scan_node_properties`](Self::superset_scan_node_properties), including its
    /// treatment of MVCC tombstones and its polarity — read that doc before judging a version.
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing or the chain is malformed (cycle-guarded).
    pub fn superset_scan_rel_properties(&self, rel_id: u64) -> Result<SupersetProperties> {
        read_view::superset_scan_rel_properties(&self.pool, &self.stores, rel_id)
    }

    /// The **decision**-polarity read of relationship `rel_id`'s properties (`rmp` task #905): the
    /// relationship analogue of
    /// [`decision_scan_node_properties`](Self::decision_scan_node_properties), with the same
    /// obligation — use it wherever the answer is final and nothing re-checks it.
    ///
    /// # Errors
    /// As [`superset_scan_rel_properties`](Self::superset_scan_rel_properties).
    pub fn decision_scan_rel_properties(
        &self,
        rel_id: u64,
        snapshot: Snapshot,
    ) -> Result<DecidedProperties> {
        read_view::decision_scan_rel_properties(&self.pool, &self.stores, rel_id, snapshot)
    }

    /// Sets relationship `rel_id`'s property `key` to `value` under `txn`, **replacing** any current
    /// value of that key — the relationship analogue of
    /// [`set_node_property_value`](Self::set_node_property_value), with the same in-place write, the
    /// same `SetProperty` delta on the **relationship's** undo chain, and the same overflow
    /// ownership rule. Returns the physical id of the cell that now holds the value.
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] — a retriable serialization failure — if another still-open
    ///   transaction holds this relationship.
    /// - [`GraphusError::Storage`] if the relationship is not in use or a write fails.
    /// - [`GraphusError::Runtime`] (from the value codecs) if `value` is `Null` (not persisted) or a
    ///   class this build cannot store (e.g. `Map`, a heterogeneous `List`).
    pub fn set_rel_property_value(
        &mut self,
        txn: TxnId,
        rel_id: u64,
        key: u32,
        value: &graphus_core::Value,
    ) -> Result<u64> {
        self.set_entity_property_value(txn, StoreKind::Rel, rel_id, key, value)
    }

    /// Removes relationship `rel_id`'s property `key` under `txn` — the relationship analogue of
    /// [`remove_node_property_value`](Self::remove_node_property_value): the cell is emptied in place
    /// and the removed value descends onto the relationship's undo chain. Returns whether anything
    /// changed, so `REMOVE r.p` can distinguish a real removal from a no-op.
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] on a write-write conflict.
    /// - [`GraphusError::Storage`] if the relationship is not in use or a write fails.
    pub fn remove_rel_property_value(&mut self, txn: TxnId, rel_id: u64, key: u32) -> Result<bool> {
        self.remove_entity_property_value(txn, StoreKind::Rel, rel_id, key)
    }

    /// The **superset**-polarity read of relationship `rel_id`'s properties, **decoded** (`rmp` task
    /// #44): the relationship analogue of
    /// [`superset_scan_node_property_values`](Self::superset_scan_node_property_values), with the
    /// same polarity and the same caveat — every slot-occupied version is returned, tombstones
    /// included, and a decision path must narrow through
    /// [`decision_scan_rel_properties`](Self::decision_scan_rel_properties) instead.
    ///
    /// # Errors
    /// Returns a storage error if the property chain or an overflow chain is unreadable/corrupt.
    pub fn superset_scan_rel_property_values(
        &self,
        rel_id: u64,
    ) -> Result<Vec<(u64, u32, graphus_core::Value)>> {
        read_view::superset_scan_rel_property_values(&self.pool, &self.stores, rel_id)
    }

    /// Clears **all** of relationship `rel_id`'s properties under `txn` (`SET r = map`) — the
    /// relationship analogue of [`clear_node_properties`](Self::clear_node_properties), including its
    /// changed return value: the number of cells **cleared**, not of records tombstoned.
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] on a write-write conflict.
    /// - [`GraphusError::Storage`] if the relationship is not in use or a write fails.
    pub fn clear_rel_properties(&mut self, txn: TxnId, rel_id: u64) -> Result<usize> {
        self.clear_entity_properties(txn, StoreKind::Rel, rel_id)
    }

    // ------------------------------ adjacency -------------------------------

    /// Enumerates the physical ids of the relationships incident to `node_id`, walking its
    /// incidence chain in O(degree) with no index probe (index-free adjacency, `04 §2.3`).
    ///
    /// A self-loop appears **once**: it is threaded into the chain twice (`04 §2.4`) but deduped
    /// here by relationship id, as a distinct-incident-relationships traversal requires.
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing or the chain is malformed (a cycle
    /// guard caps the walk).
    /// Whether `node_id` has any incident relationships, without materialising the chain.
    ///
    /// The incidence walk in [`incident_rels`](Self::incident_rels) starts at the node's `first_rel`
    /// head pointer and stops at `NULL_ID`; an empty chain is therefore exactly `first_rel ==
    /// NULL_ID`. This avoids the full `Vec` allocation when the caller only needs emptiness (e.g. the
    /// GC reclaimability check).
    pub fn has_incident_rels(&self, node_id: u64) -> Result<bool> {
        Ok(self.read_node(node_id)?.first_rel != NULL_ID)
    }

    pub fn incident_rels(&self, node_id: u64) -> Result<Vec<u64>> {
        read_view::incident_rels(&self.pool, &self.stores, node_id)
    }

    /// The `(physical_id, record)` of the relationships incident to `node_id`, reading each chain link
    /// once and filtering to `wanted_types` (empty = all). The single-pass twin of `incident_rels` +
    /// per-id `rel()` used by the Cypher typed-expand fast path (`rmp` #324, "Win 1"). The chain walk
    /// is byte-identical to [`incident_rels`](Self::incident_rels), so corpse threading, self-loop
    /// dedupe, and multigraph semantics are unchanged; MVCC visibility is filtered above this layer.
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing or the chain does not terminate.
    pub fn incident_rels_typed(
        &self,
        node_id: u64,
        wanted_types: &[u32],
    ) -> Result<Vec<(u64, RelRecord)>> {
        read_view::incident_rels_typed(&self.pool, &self.stores, node_id, wanted_types)
    }

    /// The degree of `node_id` (distinct incident relationships, self-loops counted once).
    ///
    /// # Errors
    /// Propagates a chain-walk failure.
    pub fn degree(&self, node_id: u64) -> Result<usize> {
        Ok(self.incident_rels(node_id)?.len())
    }

    /// The number of **used** relationship slots: physical ids below the high-water that are NOT on
    /// the free list. This counts every allocated rel record — live versions, MVCC tombstones awaiting
    /// GC, AND dead-link corpses (`rmp` #220) — so it is the high-water-style measure that exposes a
    /// slot leak: a corpse that GC never freed would keep this count growing under create/abort churn
    /// even as the logical relationship count stays flat. After [`gc`](Self::gc) splices and frees the
    /// corpses, the freed slots return to the free list and this count drops back to the no-corpse
    /// baseline (`high_water - 1 - free_list_len`). Used by the leak-boundary regression tests.
    #[must_use]
    pub fn used_rel_slots(&self) -> u64 {
        let store = self.store(StoreKind::Rel);
        // ids run 1..high_water (id 0 is the reserved null), minus those returned to the free list.
        (store.alloc.high_water().saturating_sub(1)).saturating_sub(store.free.len() as u64)
    }

    /// The number of **used** property slots, the [`used_rel_slots`](Self::used_rel_slots) measure
    /// applied to `props.store`: physical ids below the high-water that are NOT on the free list.
    ///
    /// It counts every allocated property record — live cells, **empty** cells awaiting reclamation
    /// (`rmp` #967) and dead-link corpses (#172) — so it is the measure that exposes a property-slot
    /// leak. After a `REMOVE` the key's cell stays allocated and empty until a GC pass whose watermark
    /// has passed the removal (and whose owner has no surviving version chain) frees it; this count is
    /// what proves that pass actually happened, which no value-level read can show.
    #[must_use]
    pub fn used_prop_slots(&self) -> u64 {
        let store = self.store(StoreKind::Prop);
        (store.alloc.high_water().saturating_sub(1)).saturating_sub(store.free.len() as u64)
    }

    /// Stamps `expired_ts` on property cell `prop_id` — a **forging accessor for tests**
    /// (`rmp` #967), in the spirit of
    /// [`clear_directional_rel_counts_for_test`](Self::clear_directional_rel_counts_for_test).
    ///
    /// It exists to construct the one state this build's write path can no longer produce: the
    /// pre-#967 property MVCC tombstone (`D-property-removal` empties the cell in place instead, and
    /// `write_prop_cell` fails closed on a non-zero `expired_ts`). That state is exactly what the
    /// legacy-image gate `refuse_legacy_property_tombstones` must detect at `open`, and there is no
    /// other way to reach it from inside this build.
    ///
    /// Not a repair tool and not a write path: it patches one header word under `txn`, leaving every
    /// other invariant to the caller. A store this is used on is, by construction, one this build
    /// considers ill-formed.
    ///
    /// # Errors
    /// Returns a storage error if `prop_id`'s page is not allocated or the patch write fails.
    pub fn stamp_property_tombstone_for_test(
        &mut self,
        txn: TxnId,
        prop_id: u64,
        expired_ts: u64,
    ) -> Result<()> {
        self.patch_header_word(
            StoreKind::Prop,
            prop_id,
            MVCC_OFF_EXPIRED_TS,
            expired_ts,
            txn,
        )
    }

    /// Empties both directional relationship-count projections — an **inspection accessor for tests**
    /// (`rmp` task #856).
    ///
    /// It exists to construct the one state the incremental path cannot produce: a catalogue that holds
    /// relationships but no directional counters, which is what a database predating the projections
    /// looks like after it loads. The backfill test needs that state to prove convergence, and
    /// truncating a real catalogue image cannot produce it in a live store.
    ///
    /// Not a repair tool: [`backfill_directional_rel_counts`](Self::backfill_directional_rel_counts)
    /// replaces both maps outright, so nothing needs to clear them first.
    pub fn clear_directional_rel_counts_for_test(&mut self) {
        self.statistics.rels_per_start_label_type.clear();
        self.statistics.rels_per_type_end_label.clear();
    }

    /// Rebuilds both **directional** relationship-count projections from a full scan of the
    /// relationship store, replacing whatever they held (`rmp` task #856).
    ///
    /// This is the backfill path, needed for two cases the incremental maintenance cannot cover:
    ///
    /// * a database whose catalogue **predates** the projections, which decodes them empty (the
    ///   append-only image rule) and would otherwise never acquire them, since only new writes
    ///   increment;
    /// * a repair, if the counters were ever suspected of having drifted.
    ///
    /// It reads every allocated relationship slot in `1..high_water` and counts only **live versions**,
    /// which is exactly the population the incremental path maintains — so the result is the number a
    /// test can compare the incremental counters against, and equality between the two is the whole
    /// correctness argument for this task.
    ///
    /// # Cost
    ///
    /// O(relationship slots) reads plus up to two endpoint reads per relationship. It is an explicit
    /// operator/maintenance action, never on a query path.
    ///
    /// # Errors
    /// Propagates a read failure. A slot that is not allocated is **skipped**, not an error: the id
    /// space below the high-water legitimately contains freed slots.
    ///
    /// **Not routed through `count_bump`** (`rmp` #866). This replaces the two directional maps
    /// wholesale, outside the per-transaction delta discipline every other count mutation obeys, so
    /// no `ActiveTxn` records it and no rollback withdraws it. Sound only because it has no
    /// production caller and because the maps it touches — the `rmp` #856 directional projections —
    /// are read by the cardinality estimator alone and never by the #866 count-store path, whose
    /// equivalence predicate would otherwise be answering about a tally it does not govern. Noted so
    /// that "`apply_count_delta` is the only door" is not believed absolute: a future caller must
    /// either run inside a transaction whose delta it records, or stay off the count-store path.
    pub fn backfill_directional_rel_counts(&mut self) -> Result<()> {
        let rebuilt = self.recount_directional_rel_counts()?;
        self.statistics.rels_per_start_label_type = rebuilt.0;
        self.statistics.rels_per_type_end_label = rebuilt.1;
        Ok(())
    }

    /// Counts both directional projections from a full scan **without** installing them
    /// (`rmp` task #856).
    ///
    /// The measurement half of [`backfill_directional_rel_counts`](Self::backfill_directional_rel_counts),
    /// exposed so a test can assert that the incrementally-maintained counters equal a fresh recount —
    /// the property that makes "exact" a claim rather than a hope.
    ///
    /// # Errors
    /// Propagates a read failure other than an unallocated slot.
    pub fn recount_directional_rel_counts(&self) -> Result<DirectionalRelCounts> {
        let mut by_start = std::collections::BTreeMap::new();
        let mut by_end = std::collections::BTreeMap::new();
        let high_water = self.store(StoreKind::Rel).alloc.high_water();
        // Ids run `1..high_water`; id 0 is the reserved null.
        for id in 1..high_water {
            let Ok(rel) = self.read_rel(id) else {
                // A freed or never-allocated slot below the high-water: not an error, just not a
                // relationship. Skipping it is what makes the recount equal the live population.
                continue;
            };
            if !Self::is_live_version(rel.mvcc) {
                continue;
            }
            let start_labels = self.read_node(rel.start_node)?.labels;
            let end_labels = if rel.start_node == rel.end_node {
                start_labels
            } else {
                self.read_node(rel.end_node)?.labels
            };
            for label in crate::labels::token_ids(start_labels)? {
                *by_start.entry((label, rel.type_id)).or_insert(0) += 1;
            }
            for label in crate::labels::token_ids(end_labels)? {
                *by_end.entry((rel.type_id, label)).or_insert(0) += 1;
            }
        }
        Ok((by_start, by_end))
    }

    /// Reads the raw MVCC header of record `id` in `kind`'s store — an inspection accessor exposing
    /// the private `read_mvcc` so the Slice-3a read-view equivalence test (`rmp` #336) can compare the
    /// live store's low-level header read against [`StoreReadView::read_mvcc`]. Behaviour-identical to
    /// the internal read.
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated or the read fails.
    pub fn read_mvcc_for_test(&self, kind: StoreKind, id: u64) -> Result<MvccHeader> {
        self.read_mvcc(kind, id)
    }

    /// Reads the raw [`HeapBlock`] at `id` — an inspection accessor exposing the private `read_block`
    /// so the Slice-3a read-view equivalence test (`rmp` #336) can compare the live store's low-level
    /// block read against [`StoreReadView::read_block`]. Behaviour-identical to the internal read.
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated or the read fails.
    pub fn read_block_for_test(&self, id: u64) -> Result<HeapBlock> {
        self.read_block(id)
    }

    /// The relationship store's physical high-water mark: the exclusive upper bound of the allocated
    /// id space (`1..high_water`). A monotonically growing high-water under create/abort churn would
    /// be the signature of an unreclaimed-corpse leak; the leak-boundary regression test asserts it
    /// stays bounded once freed slots are reused (`rmp` #220).
    #[must_use]
    pub fn rel_high_water(&self) -> u64 {
        self.store(StoreKind::Rel).alloc.high_water()
    }

    /// The node store's physical high-water mark: the exclusive upper bound of the allocated id space
    /// (`1..high_water`). The node analogue of [`rel_high_water`](Self::rel_high_water); used by the
    /// zone-map data-skipping scan (`rmp` #331) to bound the id ranges it examines.
    #[must_use]
    pub fn node_high_water(&self) -> u64 {
        self.store(StoreKind::Node).alloc.high_water()
    }

    // --------------------------------- flush --------------------------------

    /// Flushes every dirty page home and syncs the device. The buffer pool enforces the WAL rule
    /// (log durable through each page's `page_lsn`) on every write-back (`04 §4.3`).
    ///
    /// # Errors
    /// Returns a storage error if a write-back or device sync fails.
    pub fn flush(&mut self) -> Result<()> {
        // When a doublewrite buffer is attached ([`attach_dwb`], `rmp` #384), route the home flush
        // through it so a torn home write is repairable on the next open. Otherwise (no DWB attached
        // — e.g. a transient scratch store) flush directly, the historical behaviour.
        if self.dwb.is_some() {
            self.flush_protected_with_attached_dwb()
        } else {
            self.pool.flush_all()
        }
    }

    /// Attaches a persistent doublewrite buffer to this store (`rmp` #384). Once attached,
    /// [`checkpoint`](Self::checkpoint) and [`flush`](Self::flush) route their home writes through
    /// [`flush_protected`](Self::flush_protected): every dirty home page is staged-and-synced into
    /// the DWB before it is written home, so a torn home write is repairable from the DWB copy by
    /// [`crate::recovery::recover_device_with_dwb`] on the next open.
    ///
    /// The DWB device must be the **same** [`BlockDevice`] type as the store's device (so an
    /// encrypted store gets an encrypted DWB, keeping page images off disk in plaintext). The caller
    /// constructs the (persistent) DWB device — a file alongside the store — and hands it here at
    /// open time, before serving any traffic.
    ///
    /// Beyond routing the checkpoint/flush path through the DWB, this also installs a
    /// [`crate::dwb::DwbPageStager`] into the buffer pool ([`ConcurrentBufferPool::set_page_stager`])
    /// so the pool's **eviction/steal** home-write path is doublewrite-protected too (`rmp` #407):
    /// previously the evictor wrote dirty home pages directly, so a torn eviction write had no copy to
    /// repair from. The stager shares the **same** `Arc<Mutex<Dwb>>` as the checkpoint path, so there
    /// is one DWB owner and concurrent evictions + checkpoints serialise their staging through the one
    /// `Mutex`.
    ///
    /// Bounded on `D: Send + Sync + 'static` because the stager is handed to the (thread-shared) pool
    /// as an `Arc<dyn PageStager>`; the production [`graphus_io`] devices satisfy this, and the bound
    /// is only required where a DWB is actually attached.
    pub fn attach_dwb(&mut self, dwb: crate::dwb::Dwb<D>)
    where
        D: Send + Sync + 'static,
    {
        let shared = Arc::new(std::sync::Mutex::new(dwb));
        // Install the eviction-path stager over the SAME shared DWB before recording it, so every
        // home write from now on — checkpoint AND eviction — is doublewrite-protected.
        let stager = Arc::new(crate::dwb::DwbPageStager::new(Arc::clone(&shared)));
        self.pool.set_page_stager(stager);
        self.dwb = Some(shared);
    }

    /// `true` when a doublewrite buffer is attached and protecting this store's home writes.
    #[must_use]
    pub fn has_dwb(&self) -> bool {
        self.dwb.is_some()
    }

    /// Installs an opaque RAII guard tied to this store's lifetime (`rmp` #563). The guard is held in
    /// the store's **last-dropped** field, so it is released only when the store is fully closed —
    /// after the final [`flush`](Self::flush) and after the device / WAL file handles are dropped. The
    /// store never inspects it.
    ///
    /// The server passes the **exclusive store-open advisory lock** ([`graphus_io::StoreOpenLock`], an
    /// `flock` on `store.lock`) here so a concurrent reopen of the same store — a `START DATABASE`
    /// racing a force-detached zombie engine that is still flushing these files — is denied until this
    /// store (including that zombie's in-progress flush) has stopped writing. Panics-safe: on an engine
    /// thread unwind the guard drops during unwinding, after the store's writes have ceased, so the
    /// lock is never released while a writer is still live.
    pub fn hold_open_guard(&mut self, guard: Box<dyn Send + Sync>) {
        self.open_guard = Some(guard);
    }

    /// Installs the shared **drain-progress beacon** (`rmp` #563). The engine hands the same
    /// [`AtomicU64`](std::sync::atomic::AtomicU64) it exposes on its handle so the store's long
    /// operations ([`gc`](Self::gc), [`flush`](Self::flush)) heartbeat it and the server's `stop_engine`
    /// can distinguish a slow-but-progressing drain from a wedged one. Idempotent; overwrites any prior
    /// beacon.
    pub fn set_drain_progress(&mut self, beacon: Arc<std::sync::atomic::AtomicU64>) {
        self.drain_progress = Some(beacon);
    }

    /// Bumps the drain-progress beacon by one, if installed (`rmp` #563). A single **relaxed** atomic
    /// increment — negligible in the hot loops that call it, and correct for a liveness signal: a poller
    /// only ever asks "did this value change since I last looked?", which needs no ordering with other
    /// memory. Cheap no-op when no beacon is installed. Public so the engine's drain-progress test seam
    /// can drive it deterministically through the coordinator.
    #[inline]
    pub fn bump_drain_progress(&self) {
        if let Some(beacon) = &self.drain_progress {
            beacon.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Flushes every dirty home page under doublewrite protection using the **attached** shared DWB
    /// — via the [`crate::dwb::DwbPageStager`] installed into the buffer pool by
    /// [`attach_dwb`](Self::attach_dwb) (`rmp` #407). Only called when `self.dwb.is_some()`.
    ///
    /// CRITICAL — why this does NOT lock the DWB itself: the pool's
    /// [`flush_pages`](graphus_bufpool::ConcurrentBufferPool::flush_pages) acquires its dirty frames'
    /// write latches and *then* stages the batch into the DWB through the installed stager (lock
    /// order **frame-latch → DWB**), matching the eviction path's `write_back`. If this method held
    /// the shared DWB mutex across `flush_pages`, two deadlocks would arise: (1) a same-thread
    /// reentrant lock when the staging re-locks the very mutex this method holds, and (2) a
    /// cross-thread ABBA with a concurrent reader-triggered eviction (which holds a frame latch and
    /// then wants the DWB). So this method holds **no** DWB lock; it only drives the dirty set through
    /// `flush_pages` in doublewrite-batch-sized chunks (the DWB area holds one batch at a time), and
    /// the pool does the staging under the correct lock order.
    ///
    /// Mirrors [`flush_protected`](Self::flush_protected)'s chunking, but lets the pool stage (rather
    /// than staging explicitly into a borrowed `&mut Dwb`), so the production attached path and the
    /// eviction path share one stager and one consistent lock order.
    fn flush_protected_with_attached_dwb(&mut self) -> Result<()> {
        // Chunk the mapped set to the DWB batch capacity. `flush_pages` only writes home the dirty
        // members of each chunk (over-listing clean pages is harmless) and stages exactly those dirty
        // pages via the installed stager before writing them home — the doublewrite invariant for any
        // dirty-set size (`rmp` #385/#407).
        let pages = self.mapped_pages();
        for chunk in pages.chunks(crate::dwb::DWB_MAX_BATCH) {
            self.pool.flush_pages(chunk)?;
            // Heartbeat the drain-progress beacon per flushed chunk (`rmp` #563) so a large but healthy
            // final flush at shutdown is observed as *progressing* and is never force-detached.
            self.bump_drain_progress();
        }
        // After every home page is durable the current DWB batch is no longer needed; clear it
        // (best-effort hygiene — a stale-but-valid batch is still safe, recovery only restores a page
        // that fails its own checksum / AEAD tag). Take the shared DWB lock transiently (no frame
        // latch is held here, so this cannot deadlock with the pool's frame-latch→DWB order).
        let shared = Arc::clone(self.dwb.as_ref().expect(
            "INVARIANT: flush_protected_with_attached_dwb is only called when a DWB is set",
        ));
        let mut dwb = shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        dwb.clear()
    }

    /// Flushes every dirty page home **under doublewrite protection** (`05 §3`, `04 §4.5`): the
    /// to-be-flushed page images are first staged into the doublewrite buffer `dwb` and made durable,
    /// and only then written to their home locations. This is the InnoDB-style protocol that lets
    /// crash recovery repair a torn home page from its intact doublewrite copy
    /// ([`crate::recovery::recover_device_with_dwb`]).
    ///
    /// The current image of every mapped page is snapshotted through the pool (the dirty image if
    /// resident, else the on-disk image) and staged; over-staging a clean page is harmless (it only
    /// costs DWB I/O, never correctness — recovery restores a home page *only* if it fails its own
    /// checksum).
    ///
    /// ## The doublewrite invariant, for **any** dirty-set size (`rmp` #385)
    ///
    /// The dirty set is processed in batches of [`crate::dwb::DWB_MAX_BATCH`] pages — the DWB area
    /// holds at most one batch ([`crate::dwb::dwb_device_pages`]), so the **whole** image set cannot
    /// be staged at once when it exceeds the cap. For each batch we therefore stage-and-sync that
    /// batch into the DWB and only then write home **exactly the pages of that batch** via
    /// [`ConcurrentBufferPool::flush_pages`](graphus_bufpool::ConcurrentBufferPool::flush_pages) —
    /// never the whole dirty pool. This guarantees the protocol invariant for any dirty-set size:
    /// *every dirty home page is staged-and-synced into the doublewrite area before it is written
    /// home*. (The previous code flushed the **whole** pool per batch, so for a dirty set larger
    /// than one batch the home pages of batches 2..N were written home before their DWB image
    /// existed — a tear on such a page had no intact copy to repair from.)
    ///
    /// A dirty page sits in the pool with its body finalised but its **checksum field stale**: the
    /// pool recomputes the checksum only at write-back (`graphus_bufpool` `write_back` →
    /// `page::write_checksum`). The doublewrite copy must be the *exact image that lands home*, so we
    /// re-stamp the checksum on our private snapshot — identical to what write-back will write.
    /// Without this the DWB would hold a copy that fails its own checksum and could not repair a torn
    /// home page.
    ///
    /// # Errors
    /// Returns a storage error if a page read, a DWB stage/sync, or the home flush fails. A DWB
    /// error aborts before any home write, preserving the protocol's ordering.
    pub fn flush_protected<W: BlockDevice>(&mut self, dwb: &mut crate::dwb::Dwb<W>) -> Result<()> {
        let pages = self.mapped_pages();
        let mut images: Vec<(PageId, Box<graphus_io::Page>)> = Vec::with_capacity(pages.len());
        for p in &pages {
            let mut img = self.read_device_page(*p)?;
            page::write_checksum(&mut img);
            images.push((*p, img));
        }
        for chunk in images.chunks(crate::dwb::DWB_MAX_BATCH) {
            let batch: Vec<(PageId, &graphus_io::Page)> =
                chunk.iter().map(|(p, img)| (*p, img.as_ref())).collect();
            // 1. Stage this batch's images into the DWB and make them durable.
            dwb.stage_batch(&batch)?;
            // 2. Only now write home EXACTLY this batch's pages — never the whole pool. Every page
            //    written here has its intact DWB copy already durable, so a torn home write among
            //    them is repairable; a page belonging to a later batch is not touched until its own
            //    image is staged (the doublewrite invariant, `05 §3`).
            let batch_ids: Vec<PageId> = chunk.iter().map(|(p, _)| *p).collect();
            self.pool.flush_pages(&batch_ids)?;
        }
        Ok(())
    }

    /// The device `PageId`s this store currently maps (the metadata-page chain plus every allocated
    /// record-store page). Used by Deterministic Simulation Testing to snapshot the on-disk image
    /// after a (partial) flush so a crash + recovery can be exercised against a real disk state
    /// (`04 §11`).
    #[must_use]
    pub fn mapped_pages(&self) -> Vec<PageId> {
        let mut pages = vec![META_PAGE];
        // The catalog's continuation pages are part of the durable image too (`rmp` task #51).
        pages.extend_from_slice(&self.meta_chain);
        for s in &self.stores {
            pages.extend(s.device_pages.iter());
        }
        pages
    }

    /// The count of durable device pages this store maps — the meta page, the catalog continuation
    /// chain, and every record store's data pages — **without** allocating the `Vec` that
    /// [`mapped_pages`](Self::mapped_pages) builds. `O(number of record stores)`, a small constant.
    ///
    /// The engine's adaptive maintenance cadence (`rmp` #556) reads this on every mutating command to
    /// size the WAL reclaim interval proportionally to the live store size, so it must stay cheap.
    #[must_use]
    pub fn store_page_count(&self) -> u64 {
        let mut n = 1u64; // META_PAGE
        n += self.meta_chain.len() as u64;
        for s in &self.stores {
            n += s.device_pages.len() as u64;
        }
        n
    }

    /// The next [`ElementId`] this store would allocate (one past the largest issued so far,
    /// `04 §2.2`). Read-only; embedded as the creation marker of an offline backup
    /// ([`crate::backup`]).
    #[must_use]
    pub fn element_id_next(&self) -> u128 {
        self.element_ids.peek()
    }

    /// The durable live-record cardinalities (`rmp` task #79): per-label node counts and
    /// per-relationship-type counts, for the planner's cardinality estimator. O(1) borrow; the maps
    /// inside are O(log n) keyed by token id ([`Statistics::node_count_for_label`] /
    /// [`Statistics::rel_count_for_type`]). These are exact counts of the currently-live records (a
    /// version is live when its slot is in use and it carries no MVCC tombstone), maintained
    /// incrementally and persisted with the catalog — equivalent to a full re-scan but without one.
    #[must_use]
    pub fn statistics(&self) -> &Statistics {
        &self.statistics
    }

    /// The number of currently-live nodes carrying the label with `label_token_id` (`0` if none),
    /// from the persisted statistics (`rmp` task #79). Convenience over [`statistics`](Self::statistics).
    #[must_use]
    pub fn node_count_for_label(&self, label_token_id: u32) -> u64 {
        self.statistics.node_count_for_label(label_token_id)
    }

    /// The number of currently-live relationships of relationship-type `type_token_id` (`0` if none),
    /// from the persisted statistics (`rmp` task #79). Convenience over [`statistics`](Self::statistics).
    #[must_use]
    pub fn rel_count_for_type(&self, type_token_id: u32) -> u64 {
        self.statistics.rel_count_for_type(type_token_id)
    }

    /// The number of currently-live relationships of type `type_token_id` whose **start** node carries
    /// `label_token_id` (`0` if none) — the `(label, type, *)` directional projection (`rmp` task #856).
    ///
    /// Read one pair at a time: summing this over labels overcounts a multi-labelled endpoint, exactly
    /// as summing [`node_count_for_label`](Self::node_count_for_label) over labels overcounts a
    /// multi-labelled node.
    #[must_use]
    pub fn rel_count_for_start_label_type(&self, label_token_id: u32, type_token_id: u32) -> u64 {
        self.statistics
            .rel_count_for_start_label_type(label_token_id, type_token_id)
    }

    /// The number of currently-live relationships of type `type_token_id` whose **end** node carries
    /// `label_token_id` (`0` if none) — the `(*, type, label)` directional projection (`rmp` task #856).
    #[must_use]
    pub fn rel_count_for_type_end_label(&self, type_token_id: u32, label_token_id: u32) -> u64 {
        self.statistics
            .rel_count_for_type_end_label(type_token_id, label_token_id)
    }

    /// Whether this store's catalogue holds any directional relationship count (`rmp` task #856).
    ///
    /// The distinction a bare zero cannot make: "this catalogue predates the projections, or has never
    /// been backfilled" versus "the graph genuinely has no such relationship". A consumer that reads a
    /// zero from the former as a real degree would estimate a fan-out of nothing; it must fall back to
    /// the graph-wide degree instead.
    #[must_use]
    pub fn has_directional_rel_counts(&self) -> bool {
        self.statistics.has_directional_rel_counts()
    }

    /// The total number of currently-live nodes, **labelled or not**, from the persisted statistics
    /// (`rmp` task #82). This is the planner's required grand total — not the sum of the per-label
    /// counts, which would over- or under-count nodes carrying several labels or none. Convenience
    /// over [`statistics`](Self::statistics).
    #[must_use]
    pub fn total_node_count(&self) -> u64 {
        self.statistics.total_nodes()
    }

    /// The total number of currently-live relationships, from the persisted statistics
    /// (`rmp` task #82). Convenience over [`statistics`](Self::statistics).
    #[must_use]
    pub fn total_relationship_count(&self) -> u64 {
        self.statistics.total_relationships()
    }

    /// Borrows the durable opaque value histogram for the node-label property
    /// `(label_token, prop_token)`, or [`None`] if none has been recorded (`rmp` task #81).
    ///
    /// The bytes are returned uninterpreted: storage stores them verbatim and never decodes them
    /// (doing so would require depending on `graphus-index`, which depends on this crate). Only the
    /// query-layer producer/consumer knows their encoding.
    #[must_use]
    pub fn property_histogram(&self, label_token: u32, prop_token: u32) -> Option<&[u8]> {
        self.statistics.property_histogram(label_token, prop_token)
    }

    // ---- Schema-catalog DDL: the per-transaction undo seam (`rmp` #734) --------------------------
    //
    // EVERY catalog mutator below routes its mutation through `with_schema_undo` and takes the
    // owning `txn` — the same shape as every other mutating store API (`set_node_labels`,
    // `set_node_property_value`, ...). Passing the transaction is not bookkeeping ceremony: catalog
    // DDL is the one class of mutation the WAL does not log, so the undo log recorded here is the
    // ONLY thing that can roll it back. A mutator that skipped this seam would be silently
    // un-rollbackable.

    /// Applies one schema-catalog mutation on behalf of `txn`, recording the per-entry undo that lets
    /// a later rollback discard **exactly this transaction's** change (`rmp` #734).
    ///
    /// `keys` must list every schema-catalog entry `apply` can touch, without repeats. Most mutators
    /// touch one; the index-name setters touch two (they clear any prior name for the same target to
    /// preserve the one-name-per-target invariant). Over-listing a key is harmless — an untouched entry
    /// records `prev` equal to what it already holds, so its undo restores the same value.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if the recorded undo is not a faithful inverse of `apply` — i.e. if
    /// `apply` changed a schema-catalog entry that `keys` did not list, or one whose map is missing
    /// from the `schema_catalog_table!` in [`meta`](crate::meta). This is the backstop that keeps the
    /// undo log complete as new catalog mutators are added; it is the reason an omission surfaces as a
    /// failing test rather than as a silently un-undoable DDL.
    fn with_schema_undo<F>(&mut self, txn: TxnId, keys: &[SchemaKey], apply: F)
    where
        F: FnOnce(&mut Statistics),
    {
        // The undo is only ever consulted for a transaction that is still open — `rollback` reads it
        // out of the active-set entry. A mutator called with a transaction that never began (or has
        // already resolved) would therefore record an undo nobody can replay, leaving its DDL
        // un-rollbackable: exactly the #734 defect, reintroduced one call site at a time. Catch a
        // mis-threaded `txn` at the source. (`is_txn_active` is the live-writer predicate — active-set
        // membership; the commit registry only gains an entry once a transaction *resolves*.)
        debug_assert!(
            self.is_txn_active(txn),
            "catalog DDL for {txn:?}, which is not an open transaction: its undo could never be replayed"
        );
        debug_assert!(
            keys.iter().enumerate().all(|(i, k)| !keys[..i].contains(k)),
            "with_schema_undo: duplicate key in {keys:?} — each entry must be listed once so its \
             generation chain unwinds exactly one link per replay step"
        );

        #[cfg(debug_assertions)]
        let before = self.statistics.clone();
        #[cfg(debug_assertions)]
        let before_seq = self.schema_last_seq.clone();

        let prevs: Vec<(Option<SchemaValue>, u64)> = keys
            .iter()
            .map(|k| {
                (
                    self.statistics.schema_get(k),
                    self.schema_last_seq.get(k).copied().unwrap_or(0),
                )
            })
            .collect();
        apply(&mut self.statistics);
        let entries: Vec<SchemaUndo> = keys
            .iter()
            .zip(prevs)
            .map(|(key, (prev, prev_seq))| {
                self.schema_seq += 1;
                self.schema_last_seq.insert(key.clone(), self.schema_seq);
                SchemaUndo {
                    seq: self.schema_seq,
                    prev_seq,
                    key: key.clone(),
                    prev,
                }
            })
            .collect();

        // Faithful-inverse check: replaying the undo we just recorded, against the state the mutation
        // just produced, must reproduce the pre-mutation schema AND the pre-mutation generations
        // exactly. Checking the generations too is what catches a mutator that touches an entry `keys`
        // did not list: such an entry keeps its stale generation, and the comparison fails.
        #[cfg(debug_assertions)]
        {
            let mut probe = self.statistics.clone();
            let mut probe_seq = self.schema_last_seq.clone();
            // Every entry just recorded IS its own entry's last writer, so all of them fire and the
            // splice target is never touched — a scratch map keeps the real logs out of the probe.
            let mut probe_live = HashMap::new();
            Self::apply_schema_undo(&mut probe, &mut probe_seq, &mut probe_live, &entries);
            debug_assert!(
                probe.schema_eq(&before) && probe_seq == before_seq,
                "catalog undo over {keys:?} is not a faithful inverse of the mutation"
            );
        }

        // Deliberately NOT `self.active.entry(txn).or_default()`: inserting an entry here would make
        // an unbegun transaction look *open* to `is_txn_active` and to the active-set emptiness checks,
        // and — since nothing will ever commit or roll it back — its phantom entry would suppress the
        // catalog checkpoint forever (`committed_statistics`). Recording nothing is the lesser failure,
        // and the debug assertion above turns any such call site into a failing test.
        if let Some(active) = self.active.get_mut(&txn) {
            active.schema_undo.extend(entries);
        }
        self.catalog_dirty = true;
    }

    /// Rolls back a transaction's catalog undo log into `stats` (and its generations into `last_seq`),
    /// newest-first, splicing any declined mutation out of the predecessor chains still held by the
    /// transactions in `live` (`rmp` #734).
    ///
    /// Newest-first is what makes repeated writes to one entry collapse correctly: each step restores
    /// the value the step before it observed, walking the entry back to what it held before this
    /// transaction touched it at all.
    ///
    /// # Why the splice is not optional
    ///
    /// The undo log is a **chain**: every entry names the generation it superseded, and restoring
    /// means "put back what my predecessor left". Aborts do not have to arrive newest-first. When an
    /// older writer aborts while a newer one is still open, its entry correctly declines — it is no
    /// longer the last writer — but the newer writer's entry still names it as its predecessor. Undo
    /// that link later and the newer writer restores a value written **only** by the transaction that
    /// already aborted: both transactions rolled back, yet a value neither of them committed is live,
    /// and the next checkpoint publishes it. Splicing on the declined branch keeps every live chain
    /// rooted in a value that was actually committed. (Same idiom as the `rmp` #220/#172 chain-head
    /// logical undo, and the same defect family as the `rmp` #239 non-LIFO prepender abort.)
    ///
    /// The splice only ever runs on the declined branch: an entry that FIRES was the entry's last
    /// writer, so by definition no live successor names it.
    fn apply_schema_undo(
        stats: &mut Statistics,
        last_seq: &mut HashMap<SchemaKey, u64>,
        live: &mut HashMap<TxnId, ActiveTxn>,
        undo: &[SchemaUndo],
    ) {
        // One transaction's log is appended in ascending `seq`, so reverse iteration IS descending
        // global order — no sort needed here (`committed_statistics` merges several logs and does).
        // Descending order is also what makes the splice cascade: a chain of this transaction's own
        // writes is unwound link by link, each decline re-pointing the live successors one step older.
        for entry in undo.iter().rev() {
            if !Self::undo_schema_entry(stats, last_seq, entry) {
                Self::splice_schema_predecessor(live, entry);
            }
        }
    }

    /// Removes `dead` from the predecessor chain of every still-live undo entry, so no future rollback
    /// can restore the value `dead`'s transaction wrote (`rmp` #734).
    ///
    /// A successor inherits `dead`'s own predecessor link, which is by construction a state `dead`
    /// itself observed — so the chain stays rooted wherever it was rooted before `dead` joined it.
    fn splice_schema_predecessor(live: &mut HashMap<TxnId, ActiveTxn>, dead: &SchemaUndo) {
        for active in live.values_mut() {
            for successor in &mut active.schema_undo {
                if successor.prev_seq == dead.seq {
                    // Generations are globally unique and each belongs to exactly one entry, so
                    // naming `dead`'s generation already implies naming `dead`'s key.
                    debug_assert_eq!(
                        successor.key, dead.key,
                        "generation {} is claimed as predecessor by a different catalog entry",
                        dead.seq
                    );
                    successor.prev.clone_from(&dead.prev);
                    successor.prev_seq = dead.prev_seq;
                }
            }
        }
    }

    /// Restores one [`SchemaUndo`] entry, **iff** its transaction is still the entry's last writer
    /// (`rmp` #734). Returns whether it fired. The single guarded step both undo paths are built from.
    ///
    /// The guard compares **generations**, not values. An entry some other transaction has written
    /// since is left alone — this transaction's write is already gone, and restoring over the newer
    /// value would discard DDL belonging to someone else. Comparing the stored value instead would miss
    /// exactly the case where that other transaction happened to write the *same* value, silently
    /// reverting its still-pending write.
    fn undo_schema_entry(
        stats: &mut Statistics,
        last_seq: &mut HashMap<SchemaKey, u64>,
        entry: &SchemaUndo,
    ) -> bool {
        if last_seq.get(&entry.key).copied().unwrap_or(0) != entry.seq {
            return false;
        }
        stats.schema_put(&entry.key, entry.prev.clone());
        if entry.prev_seq == 0 {
            last_seq.remove(&entry.key);
        } else {
            last_seq.insert(entry.key.clone(), entry.prev_seq);
        }
        true
    }

    /// The **committed** catalog image: the live [`Statistics`] with every still-open transaction's
    /// pending schema DDL undone (`rmp` #734) **and** its pending live-record counts withdrawn
    /// (`rmp` #866).
    ///
    /// This is what a checkpoint must persist. The live `Statistics` is shared by every transaction,
    /// so it also holds the *uncommitted* state of whatever transactions happen to be open — and
    /// persisting that would publish an in-flight change as though it had committed. The failure is
    /// not hypothetical, and it is identical for both halves: a crash while such a transaction is open
    /// recovers state nobody committed, and a crash **after** that transaction rolled back resurrects
    /// the very change the rollback discarded (the in-memory undo is correct, but the durable image
    /// predates it). Both are atomicity breaches, and both are the reason a checkpoint may not simply
    /// clone the live image.
    ///
    /// The counts half was left un-stripped until `rmp` #866, on the stated grounds that it "rides the
    /// existing checkpoint-at-commit contract unchanged". It does not: the counters move eagerly at
    /// **write** time, not at commit, so a concurrent commit's checkpoint published an open
    /// transaction's uncommitted rows — and, worse, that transaction's own later rollback read them
    /// back out of the durable image as though they had committed, drifting the catalog permanently.
    ///
    /// Tokens *are* deliberately left as they are: they are append-only and monotonic, so persisting
    /// an as-yet-unused one is the documented `rmp` #220/#172 superset stance.
    ///
    /// # The committing transaction is EXCLUDED explicitly, not by removal order
    ///
    /// `committing` names the transaction whose commit is being checkpointed; its entry is skipped, so
    /// its own counts and DDL are persisted while every OTHER still-open transaction's are stripped.
    /// Were it the other way round, this would persist a catalog that omits a committed write — one
    /// drift traded for another.
    ///
    /// This used to be achieved *implicitly*, by `commit_prepare` removing `txn` from
    /// [`active`](Self#structfield.active) before checkpointing, so the committing transaction simply
    /// was not in the iterated set. That worked, but it forced the removal to precede two fallible
    /// steps (`checkpoint_meta`, `commit_at_no_sync`) — and on a failure between them the transaction's
    /// delta was already gone, so a subsequent [`rollback`](Self::rollback) would restore the
    /// pre-rollback image *including* its counts and withdraw nothing, drifting the catalog permanently
    /// while [`counts_match_committed_image`](Self::counts_match_committed_image) still reported
    /// `true`: a wrong `count()` answer (`rmp` #866). It was unreachable only because no `?` happened
    /// to sit between the removal and `record_commit`, which nothing stated or checked. Naming the
    /// exclusion here lets the removal move *after* the fallible steps, where a failure leaves the
    /// active-set entry — and therefore the undo — intact. `rmp` #734's schema strip inherits the same
    /// fix; `a_committed_writes_counts_survive_the_checkpoint_and_reopen` is the regression guard.
    ///
    /// [`SYSTEM_TXN`] is never in `active`, so passing it (the fresh-store checkpoint) excludes nothing.
    ///
    /// Costs nothing in the ordinary case: with no open transaction holding DDL or counts — which is
    /// every workload that is not interleaving writes across statements — this is exactly the clone it
    /// always was, plus one `is_empty` check per open transaction.
    fn committed_statistics(&self, committing: TxnId) -> Statistics {
        let mut committed = self.statistics.clone();
        // Counts half (`rmp` #866). Order-independent, but NOT because "integer deltas commute" on its
        // own: `add_keyed`/`add_total` saturate at 0, and saturation does not commute. It holds because
        // an intermediate withdrawal can never go negative — each negative unit in a delta is a
        // distinct entity that transaction removed, and two open transactions cannot have removed the
        // same entity (write-write conflict detection stops the second). So no ordering of the
        // withdrawals can reach the saturating rail, and the sum over a HashMap's unstable iteration
        // order is deterministic without sorting. That determinism is load-bearing twice over: the
        // value is written into a DURABLE catalog, and an order-dependent one would also break DST
        // reproducibility. The schema half below cannot make the same argument and sorts by `seq`.
        for (txn, active) in &self.active {
            if *txn == committing {
                continue;
            }
            active.counts.withdraw_from(&mut committed);
        }
        // Schema half (`rmp` #734).
        if self
            .active
            .iter()
            .all(|(txn, a)| *txn == committing || a.schema_undo.is_empty())
        {
            return committed;
        }
        // Merge every open transaction's undo log and replay it in reverse GLOBAL order. Sorting by
        // the store-global `seq` is also what makes the result deterministic: `active` is a HashMap,
        // so its iteration order is not stable, but `seq` is unique and totally ordered.
        let mut pending: Vec<&SchemaUndo> = self
            .active
            .iter()
            .filter(|(txn, _)| **txn != committing)
            .flat_map(|(_, a)| a.schema_undo.iter())
            .collect();
        pending.sort_unstable_by_key(|e| std::cmp::Reverse(e.seq));
        // A scratch copy of the generations: this is a read-only view of the catalog, so the store's
        // own witness map must survive it untouched.
        let mut last_seq = self.schema_last_seq.clone();
        for entry in pending {
            // No splice here, and none is needed. A decline means some transaction wrote this entry
            // after `entry` and is not in `pending` — i.e. it COMMITTED, and its log was dropped with
            // its active-set slot. Its value is therefore the committed one, which is exactly what
            // declining leaves in place. Every link that is still live is present in `pending` (a
            // rollback splices out the ones that are not), so live chains unwind here without gaps.
            Self::undo_schema_entry(&mut committed, &mut last_seq, entry);
        }
        committed
    }

    /// Whether any currently-open transaction still holds pending schema DDL (`rmp` #734) — i.e.
    /// whether the catalog has in-memory schema state a checkpoint has deliberately NOT persisted.
    ///
    /// [`commit`](Self::commit) uses this to decide whether `catalog_dirty` may be cleared: clearing
    /// it while another transaction's DDL is still unpersisted would let that transaction's own commit
    /// take the `rmp` #529 read-only fast path and silently drop its committed DDL.
    fn open_txn_holds_pending_ddl(&self) -> bool {
        self.active.values().any(|a| !a.schema_undo.is_empty())
    }

    /// Records (or replaces) the opaque value histogram for the node-label property
    /// `(label_token, prop_token)` with `bytes`, stored verbatim (`rmp` task #81).
    ///
    /// The mutation is purely in-memory here. Like the `rmp` task #79 count mutators, it becomes
    /// **durable when `txn` commits** (the catalog is checkpointed at commit) and is **discarded when
    /// `txn` rolls back** — precisely, leaving any concurrent transaction's pending DDL intact
    /// (`rmp` #734).
    ///
    /// An empty `bytes` removes any existing entry: a histogram is never zero-length, so an empty
    /// value is meaningless and would not survive the codec round-trip.
    pub fn set_property_histogram(
        &mut self,
        txn: TxnId,
        label_token: u32,
        prop_token: u32,
        bytes: Vec<u8>,
    ) {
        self.with_schema_undo(
            txn,
            &[SchemaKey::NodePropHistogram((label_token, prop_token))],
            |s| s.set_property_histogram(label_token, prop_token, bytes),
        );
    }

    /// Removes the durable value histogram for the node-label property `(label_token, prop_token)`,
    /// if present (`rmp` task #81). Removing an absent entry is a harmless no-op.
    ///
    /// Like [`set_property_histogram`](Self::set_property_histogram), the removal is in-memory and
    /// becomes durable at `txn`'s commit, and is discarded on `txn`'s rollback.
    pub fn remove_property_histogram(&mut self, txn: TxnId, label_token: u32, prop_token: u32) {
        self.with_schema_undo(
            txn,
            &[SchemaKey::NodePropHistogram((label_token, prop_token))],
            |s| s.remove_property_histogram(label_token, prop_token),
        );
    }

    /// Lists every declared node-property index as `(label_token, prop_token, state)` from the durable
    /// catalog (`rmp` task #90), ascending by key.
    ///
    /// This is what makes index *registration* survive a crash: a fresh coordinator over a recovered
    /// store reads this to re-register the previously-declared property indexes before its index
    /// rebuild, so a recovered store's indexes are repopulated automatically (the gap fixed by `rmp`
    /// task #90). Tokens are returned as ids; the caller resolves their names via the token store.
    #[must_use]
    pub fn node_property_indexes(&self) -> Vec<(u32, u32, IndexState)> {
        self.statistics.node_property_indexes()
    }

    /// The durable build [`IndexState`] of the node-property index on `(label_token, prop_token)`, or
    /// [`None`] if no such index is declared (`rmp` task #90).
    #[must_use]
    pub fn node_property_index_state(
        &self,
        label_token: u32,
        prop_token: u32,
    ) -> Option<IndexState> {
        self.statistics
            .node_property_index_state(label_token, prop_token)
    }

    /// Declares (or updates the state of) the node-property index on `(label_token, prop_token)` in the
    /// durable catalog (`rmp` task #90).
    ///
    /// The mutation is purely in-memory here. Like the `rmp` task #79 count mutators and the
    /// `rmp` task #81 histogram mutators, it becomes **durable when `txn` commits** (the catalog is
    /// checkpointed at commit) and is **discarded when `txn` rolls back** (`rmp` #734). Re-recording an
    /// existing key flips its state.
    pub fn set_node_property_index(
        &mut self,
        txn: TxnId,
        label_token: u32,
        prop_token: u32,
        state: IndexState,
    ) {
        self.with_schema_undo(
            txn,
            &[SchemaKey::NodePropertyIndex((label_token, prop_token))],
            |s| s.set_node_property_index(label_token, prop_token, state),
        );
    }

    /// Removes the node-property index on `(label_token, prop_token)` from the durable catalog, if
    /// declared (`rmp` task #90). Removing an absent entry is a harmless no-op.
    ///
    /// Like [`set_node_property_index`](Self::set_node_property_index), the removal is in-memory and
    /// becomes durable at `txn`'s commit, and is discarded on `txn`'s rollback.
    pub fn remove_node_property_index(&mut self, txn: TxnId, label_token: u32, prop_token: u32) {
        self.with_schema_undo(
            txn,
            &[SchemaKey::NodePropertyIndex((label_token, prop_token))],
            |s| s.remove_node_property_index(label_token, prop_token),
        );
    }

    /// The `(label_token, prop_token)` a named node-property index covers, or [`None`] if no index of
    /// that name is declared (`rmp` task #623) — the durable resolver behind `DROP INDEX <name>` and
    /// the global name-uniqueness check.
    #[must_use]
    pub fn node_property_index_name(&self, name: &str) -> Option<(u32, u32)> {
        self.statistics.node_property_index_name(name)
    }

    /// The declared **name** of the node-property index on `(label_token, prop_token)`, or [`None`] if
    /// the index is nameless (a not-yet-backfilled legacy index) (`rmp` task #623). Returned owned so a
    /// caller holding a `borrow()` of the store need not keep the borrow to read the name.
    #[must_use]
    pub fn node_property_index_name_for(
        &self,
        label_token: u32,
        prop_token: u32,
    ) -> Option<String> {
        self.statistics
            .node_property_index_name_for(label_token, prop_token)
            .map(str::to_owned)
    }

    /// Records (or replaces) the name of the node-property index on `(label_token, prop_token)` in the
    /// durable catalog (`rmp` task #623). In-memory here; durable at `txn`'s commit, discarded on
    /// `txn`'s rollback (like [`set_node_property_index`](Self::set_node_property_index)).
    /// Global name uniqueness is the Cypher layer's responsibility, enforced before this is called.
    pub fn set_node_property_index_name(
        &mut self,
        txn: TxnId,
        name: String,
        label_token: u32,
        prop_token: u32,
    ) {
        // TWO entries: the name being recorded, and any name already mapping to this target — which
        // the one-name-per-target invariant makes this setter clear. Both must be undoable, or a
        // rollback would leave the displaced name lost.
        let mut keys = vec![SchemaKey::NodePropertyIndexName(name.clone())];
        // Skip when the target already carries exactly this name: the setter then removes and
        // reinserts the same entry, and listing the key twice would make the generation chain need two
        // replay steps where the undo does one.
        if let Some(displaced) = self
            .statistics
            .node_property_index_name_for(label_token, prop_token)
            .filter(|d| *d != name)
        {
            keys.push(SchemaKey::NodePropertyIndexName(displaced.to_owned()));
        }
        self.with_schema_undo(txn, &keys, |s| {
            s.set_node_property_index_name(name, label_token, prop_token);
        });
    }

    /// Removes the name entry `name` from the durable catalog, if present (`rmp` task #623) — the
    /// durable half of `DROP INDEX <name>`. In-memory here; durable at `txn`'s commit, discarded on
    /// `txn`'s rollback.
    pub fn remove_node_property_index_name(&mut self, txn: TxnId, name: &str) {
        self.with_schema_undo(
            txn,
            &[SchemaKey::NodePropertyIndexName(name.to_owned())],
            |s| s.remove_node_property_index_name(name),
        );
    }

    /// Removes whatever name maps to `(label_token, prop_token)`, if any (`rmp` task #623) — used by the
    /// by-target `DROP INDEX FOR (n:L) ON (n.p)` shape so the name is cleared alongside the index. A
    /// no-op for a nameless (legacy) index. In-memory here; durable at `txn`'s commit, discarded on
    /// `txn`'s rollback.
    pub fn remove_node_property_index_name_for(
        &mut self,
        txn: TxnId,
        label_token: u32,
        prop_token: u32,
    ) {
        // Resolve the target's name first: the undo log is keyed by name, and after the removal there
        // is nothing left to resolve. Nameless target -> nothing to remove and nothing to undo.
        let Some(name) = self
            .statistics
            .node_property_index_name_for(label_token, prop_token)
            .map(str::to_owned)
        else {
            return;
        };
        self.with_schema_undo(txn, &[SchemaKey::NodePropertyIndexName(name)], |s| {
            s.remove_node_property_index_name_for(label_token, prop_token);
        });
    }

    /// Lists every named node-property index as `(name, label_token, prop_token)` from the durable
    /// catalog (`rmp` task #623), ascending by name.
    #[must_use]
    pub fn node_property_index_names(&self) -> Vec<(String, u32, u32)> {
        self.statistics.node_property_index_names()
    }

    // ---- Relationship-property index catalog delegation (`rmp` task #646) -------------------------
    // Structural twins of the node-property index catalog delegators above. Every mutator flags
    // `catalog_dirty` and becomes durable at the enclosing transaction's commit / discarded on
    // rollback, exactly like the node-property catalog.

    /// Lists every declared relationship-property index as `(type_token, prop_token, state)` from the
    /// durable catalog (`rmp` task #646), ascending by key. What makes a rel-property index
    /// *registration* survive a crash: a fresh coordinator re-registers these before its index rebuild.
    #[must_use]
    pub fn rel_property_indexes(&self) -> Vec<(u32, u32, IndexState)> {
        self.statistics.rel_property_indexes()
    }

    /// The durable build [`IndexState`] of the relationship-property index on `(type_token, prop_token)`,
    /// or [`None`] if no such index is declared (`rmp` task #646).
    #[must_use]
    pub fn rel_property_index_state(&self, type_token: u32, prop_token: u32) -> Option<IndexState> {
        self.statistics
            .rel_property_index_state(type_token, prop_token)
    }

    /// Declares (or updates the state of) the relationship-property index on `(type_token, prop_token)`
    /// in the durable catalog (`rmp` task #646). In-memory here; durable at `txn`'s commit, discarded
    /// on `txn`'s rollback.
    pub fn set_rel_property_index(
        &mut self,
        txn: TxnId,
        type_token: u32,
        prop_token: u32,
        state: IndexState,
    ) {
        self.with_schema_undo(
            txn,
            &[SchemaKey::RelPropertyIndex((type_token, prop_token))],
            |s| s.set_rel_property_index(type_token, prop_token, state),
        );
    }

    /// Removes the relationship-property index on `(type_token, prop_token)` from the durable catalog,
    /// if declared (`rmp` task #646). In-memory here; durable at `txn`'s commit, discarded on `txn`'s
    /// rollback.
    pub fn remove_rel_property_index(&mut self, txn: TxnId, type_token: u32, prop_token: u32) {
        self.with_schema_undo(
            txn,
            &[SchemaKey::RelPropertyIndex((type_token, prop_token))],
            |s| s.remove_rel_property_index(type_token, prop_token),
        );
    }

    /// The `(type_token, prop_token)` a named relationship-property index covers, or [`None`] if no
    /// index of that name is declared (`rmp` task #646) — the durable resolver behind `DROP INDEX
    /// <name>` and the global name-uniqueness check.
    #[must_use]
    pub fn rel_property_index_name(&self, name: &str) -> Option<(u32, u32)> {
        self.statistics.rel_property_index_name(name)
    }

    /// The declared **name** of the relationship-property index on `(type_token, prop_token)`, or
    /// [`None`] if the index is nameless (`rmp` task #646). Returned owned so a caller holding a
    /// `borrow()` of the store need not keep the borrow to read the name.
    #[must_use]
    pub fn rel_property_index_name_for(&self, type_token: u32, prop_token: u32) -> Option<String> {
        self.statistics
            .rel_property_index_name_for(type_token, prop_token)
            .map(str::to_owned)
    }

    /// Records (or replaces) the name of the relationship-property index on `(type_token, prop_token)`
    /// in the durable catalog (`rmp` task #646). In-memory here; durable at `txn`'s commit, discarded
    /// on `txn`'s rollback. Global name uniqueness is the Cypher layer's responsibility, enforced
    /// before this call.
    pub fn set_rel_property_index_name(
        &mut self,
        txn: TxnId,
        name: String,
        type_token: u32,
        prop_token: u32,
    ) {
        // Two entries, exactly as in the node twin: the new name plus any name this setter displaces
        // to keep one name per target.
        let mut keys = vec![SchemaKey::RelPropertyIndexName(name.clone())];
        // Skip when the target already carries exactly this name: the setter then removes and
        // reinserts the same entry, and listing the key twice would make the generation chain need two
        // replay steps where the undo does one.
        if let Some(displaced) = self
            .statistics
            .rel_property_index_name_for(type_token, prop_token)
            .filter(|d| *d != name)
        {
            keys.push(SchemaKey::RelPropertyIndexName(displaced.to_owned()));
        }
        self.with_schema_undo(txn, &keys, |s| {
            s.set_rel_property_index_name(name, type_token, prop_token);
        });
    }

    /// Removes the name entry `name` from the durable catalog, if present (`rmp` task #646) — the
    /// durable half of `DROP INDEX <name>`. In-memory here; durable at `txn`'s commit, discarded on
    /// `txn`'s rollback.
    pub fn remove_rel_property_index_name(&mut self, txn: TxnId, name: &str) {
        self.with_schema_undo(
            txn,
            &[SchemaKey::RelPropertyIndexName(name.to_owned())],
            |s| s.remove_rel_property_index_name(name),
        );
    }

    /// Removes whatever name maps to `(type_token, prop_token)`, if any (`rmp` task #646) — used by the
    /// by-target `DROP INDEX FOR ()-[r:T]-() ON (r.p)` shape so the name is cleared alongside the index.
    /// In-memory here; durable at `txn`'s commit, discarded on `txn`'s rollback.
    pub fn remove_rel_property_index_name_for(
        &mut self,
        txn: TxnId,
        type_token: u32,
        prop_token: u32,
    ) {
        let Some(name) = self
            .statistics
            .rel_property_index_name_for(type_token, prop_token)
            .map(str::to_owned)
        else {
            return;
        };
        self.with_schema_undo(txn, &[SchemaKey::RelPropertyIndexName(name)], |s| {
            s.remove_rel_property_index_name_for(type_token, prop_token);
        });
    }

    /// Lists every named relationship-property index as `(name, type_token, prop_token)` from the
    /// durable catalog (`rmp` task #646), ascending by name.
    #[must_use]
    pub fn rel_property_index_names(&self) -> Vec<(String, u32, u32)> {
        self.statistics.rel_property_index_names()
    }

    /// The durable full-text index entry named `name`, or [`None`] if no such index is declared
    /// (`rmp` task #72). Tokens are returned as ids; the caller resolves their names via the token
    /// store. Cloned so the borrow of `self` does not outlive the call.
    #[must_use]
    pub fn fulltext_index(&self, name: &str) -> Option<FulltextIndexEntry> {
        self.statistics.fulltext_index(name).cloned()
    }

    /// Lists every declared full-text index as `(name, entry)` from the durable catalog (`rmp` task
    /// #72), ascending by name. Like [`node_property_indexes`](Self::node_property_indexes) this is
    /// what makes a full-text index *registration* survive a crash: a fresh coordinator reads this to
    /// re-register the previously-declared full-text indexes before rebuilding their inverted index
    /// from the store.
    #[must_use]
    pub fn fulltext_indexes(&self) -> Vec<(String, FulltextIndexEntry)> {
        self.statistics.fulltext_indexes()
    }

    /// Declares (or replaces) the full-text index named `name` in the durable catalog (`rmp` task
    /// #72).
    ///
    /// The mutation is purely in-memory here; like the node-property index mutators it becomes
    /// **durable when the enclosing transaction commits** (the catalog is checkpointed at commit) and
    /// is **discarded on rollback** (the catalog is reloaded from the last committed metadata page).
    /// Re-recording an existing name overwrites the entry (e.g. to flip its state).
    pub fn set_fulltext_index(&mut self, txn: TxnId, name: String, entry: FulltextIndexEntry) {
        self.with_schema_undo(txn, &[SchemaKey::FulltextIndex(name.clone())], |s| {
            s.set_fulltext_index(name, entry);
        });
    }

    /// Removes the full-text index named `name` from the durable catalog, if declared (`rmp` task
    /// #72). Removing an absent entry is a harmless no-op. Durable at the enclosing transaction's
    /// commit, discarded on rollback.
    pub fn remove_fulltext_index(&mut self, txn: TxnId, name: &str) {
        self.with_schema_undo(txn, &[SchemaKey::FulltextIndex(name.to_owned())], |s| {
            s.remove_fulltext_index(name);
        });
    }

    /// The durable spatial (point) index entry named `name`, or [`None`] if no such index is declared
    /// (`rmp` task #98). Tokens are returned as ids; the caller resolves their names via the token
    /// store. Cloned so the borrow of `self` does not outlive the call.
    #[must_use]
    pub fn spatial_index(&self, name: &str) -> Option<SpatialIndexEntry> {
        self.statistics.spatial_index(name).cloned()
    }

    /// Lists every declared spatial index as `(name, entry)` from the durable catalog (`rmp` task
    /// #98), ascending by name. Like [`fulltext_indexes`](Self::fulltext_indexes) this is what makes a
    /// spatial index *registration* survive a crash: a fresh coordinator reads this to re-register the
    /// previously-declared spatial indexes before rebuilding their grid from the store.
    #[must_use]
    pub fn spatial_indexes(&self) -> Vec<(String, SpatialIndexEntry)> {
        self.statistics.spatial_indexes()
    }

    /// Declares (or replaces) the spatial index named `name` in the durable catalog (`rmp` task #98).
    ///
    /// The mutation is purely in-memory here; like the full-text index mutators it becomes
    /// **durable when the enclosing transaction commits** (the catalog is checkpointed at commit) and
    /// is **discarded on rollback** (the catalog is reloaded from the last committed metadata page).
    /// Re-recording an existing name overwrites the entry (e.g. to flip its state).
    pub fn set_spatial_index(&mut self, txn: TxnId, name: String, entry: SpatialIndexEntry) {
        self.with_schema_undo(txn, &[SchemaKey::SpatialIndex(name.clone())], |s| {
            s.set_spatial_index(name, entry);
        });
    }

    /// Removes the spatial index named `name` from the durable catalog, if declared (`rmp` task #98).
    /// Removing an absent entry is a harmless no-op. Durable at the enclosing transaction's commit,
    /// discarded on rollback.
    pub fn remove_spatial_index(&mut self, txn: TxnId, name: &str) {
        self.with_schema_undo(txn, &[SchemaKey::SpatialIndex(name.to_owned())], |s| {
            s.remove_spatial_index(name);
        });
    }

    /// The durable composite (multi-property) node index entry named `name`, or [`None`] if no such
    /// index is declared (`rmp` task #657). Tokens are returned as ids; the caller resolves their names
    /// via the token store. Cloned so the borrow of `self` does not outlive the call.
    #[must_use]
    pub fn composite_index(&self, name: &str) -> Option<CompositeIndexEntry> {
        self.statistics.composite_index(name).cloned()
    }

    /// Lists every declared composite index as `(name, entry)` from the durable catalog (`rmp` task
    /// #657), ascending by name. Like [`fulltext_indexes`](Self::fulltext_indexes) this is what makes a
    /// composite index *registration* survive a crash: a fresh coordinator reads this to re-register
    /// the previously-declared composite indexes before rebuilding their B+-tree from the store.
    #[must_use]
    pub fn composite_indexes(&self) -> Vec<(String, CompositeIndexEntry)> {
        self.statistics.composite_indexes()
    }

    /// The **name** of the composite index covering exactly `(label_token, property_tokens)` — same
    /// label and same **ordered** property tuple — or [`None`] if none is declared (`rmp` task #657).
    /// Backs the `IF NOT EXISTS` schema-equivalence check.
    #[must_use]
    pub fn composite_index_name_for(
        &self,
        label_token: u32,
        property_tokens: &[u32],
    ) -> Option<String> {
        self.statistics
            .composite_index_name_for(label_token, property_tokens)
            .map(str::to_owned)
    }

    /// Declares (or replaces) the composite index named `name` in the durable catalog (`rmp` task
    /// #657).
    ///
    /// The mutation is purely in-memory here; like the spatial index mutators it becomes **durable when
    /// the enclosing transaction commits** (the catalog is checkpointed at commit) and is **discarded
    /// on rollback** (the catalog is reloaded from the last committed metadata page). Re-recording an
    /// existing name overwrites the entry (e.g. to flip its state).
    pub fn set_composite_index(&mut self, txn: TxnId, name: String, entry: CompositeIndexEntry) {
        self.with_schema_undo(txn, &[SchemaKey::CompositeIndex(name.clone())], |s| {
            s.set_composite_index(name, entry);
        });
    }

    /// Removes the composite index named `name` from the durable catalog, if declared (`rmp` task
    /// #657). Removing an absent entry is a harmless no-op. Durable at the enclosing transaction's
    /// commit, discarded on rollback.
    pub fn remove_composite_index(&mut self, txn: TxnId, name: &str) {
        self.with_schema_undo(txn, &[SchemaKey::CompositeIndex(name.to_owned())], |s| {
            s.remove_composite_index(name);
        });
    }

    /// The durable composite (multi-property) **relationship** index entry named `name`, or [`None`] if
    /// no such index is declared (`rmp` task #666). Tokens are returned as ids; the caller resolves
    /// their names via the token store. Cloned so the borrow of `self` does not outlive the call.
    #[must_use]
    pub fn rel_composite_index(&self, name: &str) -> Option<RelCompositeIndexEntry> {
        self.statistics.rel_composite_index(name).cloned()
    }

    /// Lists every declared composite relationship index as `(name, entry)` from the durable catalog
    /// (`rmp` task #666), ascending by name. Like [`composite_indexes`](Self::composite_indexes) this is
    /// what makes a composite relationship index *registration* survive a crash: a fresh coordinator
    /// reads this to re-register the previously-declared indexes before rebuilding their B+-tree.
    #[must_use]
    pub fn rel_composite_indexes(&self) -> Vec<(String, RelCompositeIndexEntry)> {
        self.statistics.rel_composite_indexes()
    }

    /// The **name** of the composite relationship index covering exactly `(type_token, property_tokens)`
    /// — same relationship type and same **ordered** property tuple — or [`None`] if none is declared
    /// (`rmp` task #666). Backs the `IF NOT EXISTS` schema-equivalence check.
    #[must_use]
    pub fn rel_composite_index_name_for(
        &self,
        type_token: u32,
        property_tokens: &[u32],
    ) -> Option<String> {
        self.statistics
            .rel_composite_index_name_for(type_token, property_tokens)
            .map(str::to_owned)
    }

    /// Declares (or replaces) the composite relationship index named `name` in the durable catalog
    /// (`rmp` task #666). Purely in-memory here; becomes **durable when the enclosing transaction
    /// commits** and is **discarded on rollback**, exactly like [`set_composite_index`](Self::set_composite_index).
    pub fn set_rel_composite_index(
        &mut self,
        txn: TxnId,
        name: String,
        entry: RelCompositeIndexEntry,
    ) {
        self.with_schema_undo(txn, &[SchemaKey::RelCompositeIndex(name.clone())], |s| {
            s.set_rel_composite_index(name, entry);
        });
    }

    /// Removes the composite relationship index named `name` from the durable catalog, if declared
    /// (`rmp` task #666). Removing an absent entry is a harmless no-op. Durable at the enclosing
    /// transaction's commit, discarded on rollback.
    pub fn remove_rel_composite_index(&mut self, txn: TxnId, name: &str) {
        self.with_schema_undo(txn, &[SchemaKey::RelCompositeIndex(name.to_owned())], |s| {
            s.remove_rel_composite_index(name);
        });
    }

    /// The durable text (trigram) node index entry named `name`, or [`None`] if no such index is
    /// declared (`rmp` task #662). Tokens are returned as ids; the caller resolves their names via the
    /// token store. Cloned so the borrow of `self` does not outlive the call.
    #[must_use]
    pub fn text_index(&self, name: &str) -> Option<TextIndexEntry> {
        self.statistics.text_index(name).cloned()
    }

    /// Lists every declared text index as `(name, entry)` from the durable catalog (`rmp` task #662),
    /// ascending by name. Like [`spatial_indexes`](Self::spatial_indexes) this is what makes a text
    /// index *registration* survive a crash: a fresh coordinator reads this to re-register the
    /// previously-declared text indexes before rebuilding their trigram index from the store.
    #[must_use]
    pub fn text_indexes(&self) -> Vec<(String, TextIndexEntry)> {
        self.statistics.text_indexes()
    }

    /// The **name** of the text index covering exactly `(label_token, property_token)`, or [`None`] if
    /// none is declared (`rmp` task #662). Backs the `IF NOT EXISTS` schema-equivalence check.
    #[must_use]
    pub fn text_index_name_for(&self, label_token: u32, property_token: u32) -> Option<String> {
        self.statistics
            .text_index_name_for(label_token, property_token)
            .map(str::to_owned)
    }

    /// Declares (or replaces) the text index named `name` in the durable catalog (`rmp` task #662).
    ///
    /// The mutation is purely in-memory here; like the spatial index mutators it becomes **durable when
    /// the enclosing transaction commits** (the catalog is checkpointed at commit) and is **discarded
    /// on rollback** (the catalog is reloaded from the last committed metadata page). Re-recording an
    /// existing name overwrites the entry (e.g. to flip its state).
    pub fn set_text_index(&mut self, txn: TxnId, name: String, entry: TextIndexEntry) {
        self.with_schema_undo(txn, &[SchemaKey::TextIndex(name.clone())], |s| {
            s.set_text_index(name, entry);
        });
    }

    /// Removes the text index named `name` from the durable catalog, if declared (`rmp` task #662).
    /// Removing an absent entry is a harmless no-op. Durable at the enclosing transaction's commit,
    /// discarded on rollback.
    pub fn remove_text_index(&mut self, txn: TxnId, name: &str) {
        self.with_schema_undo(txn, &[SchemaKey::TextIndex(name.to_owned())], |s| {
            s.remove_text_index(name);
        });
    }

    /// The durable vector (HNSW) index entry named `name`, or [`None`] if no such index is declared
    /// (`rmp` task #669). Tokens are returned as ids; the caller resolves their names via the token
    /// store. Cloned so the borrow of `self` does not outlive the call.
    #[must_use]
    pub fn vector_index(&self, name: &str) -> Option<VectorIndexEntry> {
        self.statistics.vector_index(name).cloned()
    }

    /// Lists every declared vector index as `(name, entry)` from the durable catalog (`rmp` task #669),
    /// ascending by name. Like [`text_indexes`](Self::text_indexes) this is what makes a vector index
    /// *registration* survive a crash: a fresh coordinator reads this to re-register the previously-
    /// declared vector indexes before rebuilding their HNSW graph from the store.
    #[must_use]
    pub fn vector_indexes(&self) -> Vec<(String, VectorIndexEntry)> {
        self.statistics.vector_indexes()
    }

    /// The **name** of the vector index covering exactly `(entity, token, property_token)`, or [`None`]
    /// if none is declared (`rmp` task #669). Backs the `IF NOT EXISTS` schema-equivalence check; the
    /// [`VectorEntity`] disambiguates a node label token from a numerically-equal relationship-type
    /// token.
    #[must_use]
    pub fn vector_index_name_for(
        &self,
        entity: VectorEntity,
        token: u32,
        property_token: u32,
    ) -> Option<String> {
        self.statistics
            .vector_index_name_for(entity, token, property_token)
            .map(str::to_owned)
    }

    /// Declares (or replaces) the vector index named `name` in the durable catalog (`rmp` task #669).
    /// Purely in-memory here; becomes **durable when the enclosing transaction commits** and is
    /// **discarded on rollback**, exactly like [`set_text_index`](Self::set_text_index).
    pub fn set_vector_index(&mut self, txn: TxnId, name: String, entry: VectorIndexEntry) {
        self.with_schema_undo(txn, &[SchemaKey::VectorIndex(name.clone())], |s| {
            s.set_vector_index(name, entry);
        });
    }

    /// Removes the vector index named `name` from the durable catalog, if declared (`rmp` task #669).
    /// Removing an absent entry is a harmless no-op. Durable at the enclosing transaction's commit,
    /// discarded on rollback.
    pub fn remove_vector_index(&mut self, txn: TxnId, name: &str) {
        self.with_schema_undo(txn, &[SchemaKey::VectorIndex(name.to_owned())], |s| {
            s.remove_vector_index(name);
        });
    }

    /// The durable constraint entry named `name`, or [`None`] if no such constraint is declared
    /// (`rmp` task #99). Tokens are returned as ids; the caller resolves their names via the token
    /// store. Cloned so the borrow of `self` does not outlive the call.
    #[must_use]
    pub fn constraint(&self, name: &str) -> Option<ConstraintEntry> {
        self.statistics.constraint(name).cloned()
    }

    /// Lists every declared constraint as `(name, entry)` from the durable catalog (`rmp` task #99),
    /// ascending by name. Like [`spatial_indexes`](Self::spatial_indexes) this is what makes a
    /// constraint *declaration* survive a crash: a fresh coordinator reads this to re-register the
    /// previously-declared constraints (and rebuild a uniqueness constraint's backing index from the
    /// store) on open.
    #[must_use]
    pub fn constraints(&self) -> Vec<(String, ConstraintEntry)> {
        self.statistics.constraints()
    }

    /// Declares (or replaces) the constraint named `name` in the durable catalog (`rmp` task #99).
    ///
    /// The mutation is purely in-memory here; like the index mutators it becomes **durable when the
    /// enclosing transaction commits** (the catalog is checkpointed at commit) and is **discarded on
    /// rollback** (the catalog is reloaded from the last committed metadata page). Re-recording an
    /// existing name overwrites the entry.
    pub fn set_constraint(&mut self, txn: TxnId, name: String, entry: ConstraintEntry) {
        self.with_schema_undo(txn, &[SchemaKey::Constraint(name.clone())], |s| {
            s.set_constraint(name, entry);
        });
    }

    /// Removes the constraint named `name` from the durable catalog, if declared (`rmp` task #99).
    /// Removing an absent entry is a harmless no-op. Durable at the enclosing transaction's commit,
    /// discarded on rollback.
    pub fn remove_constraint(&mut self, txn: TxnId, name: &str) {
        self.with_schema_undo(txn, &[SchemaKey::Constraint(name.to_owned())], |s| {
            s.remove_constraint(name);
        });
    }

    /// Reads device page `page` through the pool (verifying its checksum), returning its bytes.
    /// A DST helper for snapshotting the on-disk image (`04 §11`).
    ///
    /// # Errors
    /// Returns a storage error if the page is missing or fails checksum verification.
    pub fn read_device_page(&mut self, page: PageId) -> Result<Box<graphus_io::Page>> {
        self.pool.with_page_fetched(page, |p| Box::new(*p))
    }

    /// Runs `f` with mutable access to the underlying block device, for **Deterministic Simulation
    /// Testing only** (`04 §11`). A DST harness uses it to arm a [`graphus_io::FaultPlan`] (or the
    /// one-shot `arm_io_error` / `arm_torn_write` seams) on the *live* device of a **running** store,
    /// so a fault can be injected mid-workload — a write I/O error on the next home write, bit-rot on
    /// a later read — instead of only on a device the harness owned before construction. This composes
    /// with the existing crash/recover spine: arm the fault, drive more work (the next flush /
    /// eviction surfaces a write error; the next fetch surfaces a read corruption), then crash and
    /// run ARIES recovery exactly as the un-faulted scenarios do.
    ///
    /// `rmp` #337, Slice 1: the store now builds on the concurrent buffer pool, whose device lives
    /// behind a `Mutex<D>`, so this is a **closure** accessor (`with_device_mut`) rather than the old
    /// `&mut D` borrow — a `&mut D` cannot be handed out from the shared pool. The harness arms the
    /// fault inside `f`.
    ///
    /// Gated behind the `dst` cargo feature (which forwards to `graphus-bufpool/dst`) so the
    /// production build never compiles this seam — the device stays encapsulated and the cost is
    /// zero (the method does not exist on the production path).
    #[cfg(feature = "dst")]
    pub fn with_device_mut<R>(&mut self, f: impl FnOnce(&mut D) -> R) -> R {
        self.pool.with_device_mut(f)
    }

    // ---------------------------- consistency checker ----------------------------
    //
    // Read-only accessors and a fetch wrapper the offline consistency checker
    // ([`crate::check`]) needs over otherwise-private catalog state. They never mutate the store
    // and are crate-private: the checker lives in this crate but in a sibling module, so it cannot
    // reach `RecordStore`'s private fields directly.

    /// The physical-id high-water mark of `kind`'s store (one past the largest id ever allocated,
    /// `04 §2.2`): live ids of that store are a subset of `1..high_water`.
    pub(crate) fn checker_high_water(&self, kind: StoreKind) -> u64 {
        self.store(kind).alloc.high_water()
    }

    /// The freed physical ids of `kind`'s store (`04 §2.7`).
    pub(crate) fn checker_free_ids(&self, kind: StoreKind) -> Vec<u64> {
        self.store(kind).free.ids().to_vec()
    }

    /// The number of interned `PropKey`-namespace tokens (`04 §2.6`): key token ids are dense in
    /// `0..prop_key_token_count`. The consistency checker uses this to flag a `SetProperty` delta
    /// that names a key the token store does not have (`rmp` #967).
    pub(crate) fn checker_prop_key_token_count(&self) -> usize {
        self.tokens.len(Namespace::PropKey)
    }

    /// The number of interned `Label`-namespace tokens (`04 §2.6`): label token ids are dense in
    /// `0..label_token_count`. The consistency checker uses this to verify that a node's label
    /// bitmap references only token ids that exist in the token store (`rmp` task #42).
    pub(crate) fn checker_label_token_count(&self) -> usize {
        self.tokens.len(Namespace::Label)
    }

    /// The **version chain** of entity `(kind, id)`, newest delta first (`05 §12`, `04 §5.1`;
    /// `rmp` #966): `(delta id, delta)` pairs from the record's `undo_ptr` down to the end of the
    /// chain, an empty vector when the entity has no chain.
    ///
    /// This is the read side of the undo area. Reconstructing the version a given snapshot may see
    /// means starting from the in-place record image and applying these deltas in order until the
    /// snapshot's visibility rule is satisfied (`04 §5.3`); resolving each delta's commit status means
    /// reading its [`commit_slot`](Self::commit_slot).
    ///
    /// The walk threads through **corpse** deltas (an aborted transaction's, whose `in_use` bit is
    /// clear): they are returned, because a caller reconstructing a version has to skip them
    /// explicitly rather than have the chain silently end at one.
    ///
    /// # Errors
    /// Returns a storage error if the entity cannot be read, a link dangles, or the chain fails to
    /// terminate — all of which are corruption the consistency checker also reports.
    pub fn version_chain(&self, kind: StoreKind, id: u64) -> Result<Vec<(u64, UndoDelta)>> {
        self.undo_chain(kind, id)
    }

    /// Observability for the undo area (`rmp` #966): `(deltas, commit slots)` currently on their
    /// store's free list — i.e. reclaimed and available for reuse.
    ///
    /// Surfaced because the two numbers are the direct evidence that chain reclamation and abort
    /// reclamation actually happen: a store whose chains are built but never reclaimed reports
    /// `(0, 0)` for ever while `undo.store` grows without bound.
    #[must_use]
    pub fn undo_area_free_counts(&self) -> (usize, usize) {
        (
            self.store(StoreKind::Undo).free.len(),
            self.store(StoreKind::Commit).free.len(),
        )
    }

    /// The commit-info slot at `commit.store` id `slot` — the indirection point through which every
    /// delta of one transaction resolves its commit status (`04 §5.1.3`). `None` for a zeroed slot.
    ///
    /// # Errors
    /// Returns a storage error if `slot` is out of range or occupied but undecodable.
    pub fn commit_slot(&self, slot: u64) -> Result<Option<CommitSlot>> {
        self.read_commit_slot(slot)
    }

    /// Reads the `strings.store` overflow-heap block at physical id `id` (`rmp` task #43). Used by
    /// the consistency checker to scan and validate overflow chains.
    pub(crate) fn checker_block(&mut self, id: u64) -> Result<HeapBlock> {
        self.read_block(id)
    }

    /// The `undo.store` delta at `id`, or `None` for a zeroed (never-written / reclaimed) slot
    /// (`rmp` #966). An occupied-but-undecodable slot is an error, which the checker reports.
    pub(crate) fn checker_delta(&self, id: u64) -> Result<Option<UndoDelta>> {
        self.read_delta(id)
    }

    /// The `commit.store` slot at `id`, or `None` for a zeroed slot (`rmp` #966).
    pub(crate) fn checker_commit_slot(&self, id: u64) -> Result<Option<CommitSlot>> {
        self.read_commit_slot(id)
    }

    /// The on-disk format version this store was **opened** at (`05 §12.6`).
    ///
    /// [`graphus_core::constants::FORMAT_VERSION`] for a store this build created; `1` for one
    /// created before the undo area existed (`rmp` #966) and `2` for one created before the property
    /// path moved onto it (`rmp` #967). Both earlier versions are upgraded in place at the first
    /// catalog checkpoint — a version-1 image is a version-2 image with no chains, and a version-2
    /// image is a version-3 image whose property cells this build has already proved carry no
    /// tombstone (`RecordStore::refuse_legacy_property_tombstones` runs first, at `open`).
    #[must_use]
    pub fn opened_format_version(&self) -> u32 {
        self.opened_format_version
    }

    /// The number of currently **dirty** buffer-pool frames (#426). The offline consistency checker
    /// uses this to enforce its *cold-open* contract: it verifies on-disk checksums by re-reading
    /// pages through the pool, but a resident **dirty** page is served from cache without a disk
    /// read, so resident corruption (or a stale checksum) would be silently missed. A cold pool has
    /// zero dirty frames, so `checker_dirty_frames() == 0` is the precise, cheap invariant the
    /// checker asserts before trusting its checksum pass (see [`crate::check::assert_cold_open`]).
    ///
    /// Gated to the `check-cold-assert` feature: it is read only by the feature-gated cold-open
    /// enforcement, so the default build does not compile it (no dead-code).
    #[cfg(feature = "check-cold-assert")]
    pub(crate) fn checker_dirty_frames(&self) -> usize {
        self.pool.dirty_frames()
    }
}

/// Which neighbour pointer is being repaired during an unlink.
#[derive(Clone, Copy)]
enum NeighbourPtr {
    Prev,
    Next,
}

/// One maximal run of consecutive dead-link corpses discovered by a live-chain walk (`rmp` #220): the
/// run sits in `node`'s incidence chain between the live link `pred` (`NULL_ID` when the run starts at
/// the chain head, reached straight from `first_rel`) and the live link `succ` (`NULL_ID` at the chain
/// tail). `pred`/`succ` are LIVE positions from the walk, never the corpses' own (possibly stale)
/// stored pointers — see [`RecordStore::gc_splice_corpses`](RecordStore::gc_splice_corpses). Bridging
/// collapses the whole run by repointing `pred` and `succ` directly at each other.
#[derive(Clone, Copy)]
struct CorpseRun {
    node: u64,
    pred: u64,
    succ: u64,
}

/// A **recording** [`ApplyTarget`](graphus_wal::ApplyTarget) used for **live rollback** only
/// (`04 §4.4`, `rmp` #337 Slice 1).
///
/// During live rollback the WAL manager calls only [`apply`](graphus_wal::ApplyTarget::apply)
/// (never `page_lsn`), once per compensating intra-page patch, **while holding the WAL manager
/// lock**. On the concurrent buffer pool that lock and the pool's internal WAL-rule lock wrap the
/// same [`WalManager`] (see [`crate::wal_rule`]): applying the patch *through the pool* inside
/// `apply` would `fetch` a page, and if that fetch evicts a dirty victim the pool's write-back
/// re-enters the WAL rule and tries to take the WAL lock again — a self-deadlock (it panicked as a
/// `RefCell` double-borrow under the old single-threaded handle; the `rmp` #337 audit proved a
/// rollback whose working set exceeds the pool capacity hits exactly this).
///
/// The fix (the ARIES-precedent "don't nest the buffer-pool flush under the log latch", as InnoDB /
/// PostgreSQL / SQLite all do): this target merely **records** each `(page, lsn, image)` while the
/// lock is held — touching the pool not at all — and [`RecordStore::rollback`] **replays** them into
/// the pool *after* the WAL lock is released. By then the CLRs the WAL appended are already durable
/// (rollback hardens once before returning), so an eviction during replay takes the WAL lock with no
/// holder, and a crash between the (durable) ABORT and the replay is recovered identically by ARIES
/// redo of the CLRs against the device. Crash recovery itself uses [`crate::recovery::DeviceTarget`]
/// (direct device writes, no pool, no reentrancy).
mod pool_target {
    use graphus_core::Lsn;
    use graphus_core::PageId;
    use graphus_core::error::Result;

    /// One recorded compensating page image to replay into the pool after the WAL lock is released.
    pub struct Compensation {
        pub page: PageId,
        pub lsn: Lsn,
        pub image: Vec<u8>,
    }

    /// A recorder that captures the compensating images the WAL emits during rollback, applying
    /// nothing to the pool itself (see module docs for why deferral is required and safe).
    #[derive(Default)]
    pub struct RecordingTarget {
        compensations: Vec<Compensation>,
    }

    impl RecordingTarget {
        /// A fresh recorder with no captured compensations.
        pub fn new() -> Self {
            Self::default()
        }

        /// Consumes the recorder, yielding the captured compensations in apply order (newest-first,
        /// exactly as the WAL emitted them).
        pub fn into_compensations(self) -> Vec<Compensation> {
            self.compensations
        }
    }

    impl graphus_wal::ApplyTarget for RecordingTarget {
        fn page_lsn(&self, _page: PageId) -> Lsn {
            // Never consulted during live rollback (the WAL manager calls only `apply`).
            Lsn(0)
        }

        fn apply(&mut self, page: PageId, lsn: Lsn, image: &[u8]) -> Result<()> {
            // Record only — no pool access while the WAL lock is held. Replay happens lock-free in
            // `RecordStore::rollback` after the WAL `rollback` returns.
            self.compensations.push(Compensation {
                page,
                lsn,
                image: image.to_vec(),
            });
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    //! Node-labels API unit tests over a real in-memory store (`rmp` task #42). The bitmap codec
    //! itself is tested in [`crate::labels`]; here we test the WAL-logged store methods end to end.
    use super::*;
    use graphus_io::MemBlockDevice;
    use graphus_wal::{MemLogSink, WalManager};

    type Store = RecordStore<MemBlockDevice, MemLogSink>;

    fn fresh() -> Store {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        RecordStore::create(device, wal, 64, 1).expect("create store")
    }

    /// Snapshots a store's flushed on-disk image into a fresh, openable [`MemBlockDevice`] (the
    /// `recover_steal` image technique): flush the store home, then copy every mapped page into a new
    /// device whose page count covers them. The returned device opens cleanly via
    /// [`RecordStore::open`]; tests then perturb it before reopening.
    fn snapshot_device(store: &mut Store) -> MemBlockDevice {
        store.flush().expect("flush store home");
        let pages = store.mapped_pages();
        let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
        let mut device = MemBlockDevice::new(max + 1);
        for p in &pages {
            let bytes = store.read_device_page(*p).expect("read device page");
            device.write_page(*p, &bytes).expect("stage page");
        }
        device.sync_all().expect("persist disk image");
        device
    }

    /// Builds one record page whose dense records (laid out at `record_kind`'s stride) are crafted by
    /// `fill`, then stamps the page header as a [`PAGE_TYPE_RECORD`] page of `subtype_kind` at device
    /// id `pid` with a valid CRC32C. Used to plant a hand-crafted **orphan** page on a device.
    fn build_record_page(
        pid: PageId,
        subtype_kind: StoreKind,
        record_kind: StoreKind,
        fill: impl Fn(usize, &mut [u8]),
    ) -> Box<graphus_io::Page> {
        let mut page = Box::new([0u8; graphus_io::PAGE_SIZE]);
        let rs = record_kind.record_size();
        let rpp = paging::records_per_page(rs);
        for slot in 0..rpp {
            let off = HEADER_SIZE + slot * rs;
            fill(slot, &mut page[off..off + rs]);
        }
        page::set_page_id(&mut page, pid.0);
        page::set_page_type(&mut page, PAGE_TYPE_RECORD);
        page::set_page_subtype(&mut page, subtype_kind as u8);
        // A valid checksum: the corruption this models passes CRC32C, so the wrong-subtype byte
        // cannot be caught by the per-page checksum (the whole point of `rmp` #398).
        page::write_checksum(&mut page);
        page
    }

    /// `rmp` #398 (unit): the bounded orphan-page cross-check rejects a page whose claimed-kind
    /// interpretation has an in-use record with no creator stamp, and accepts a genuinely
    /// well-formed page (and an entirely-empty one).
    #[test]
    fn orphan_page_well_formedness_check() {
        // Well-formed: every slot is a live record with a real creator stamp → accepted.
        let good = build_record_page(PageId(7), StoreKind::Rel, StoreKind::Rel, |_slot, rec| {
            MvccHeader::live(VersionStamp::committed(Timestamp(10))).write(rec);
        });
        assert!(
            RecordStore::<MemBlockDevice, MemLogSink>::orphan_page_records_well_formed(
                &good[..],
                StoreKind::Rel
            )
        );

        // Empty page (no in-use slot) → harmlessly accepted.
        let empty = build_record_page(PageId(7), StoreKind::Rel, StoreKind::Rel, |_slot, _rec| {});
        assert!(
            RecordStore::<MemBlockDevice, MemLogSink>::orphan_page_records_well_formed(
                &empty[..],
                StoreKind::Rel
            )
        );

        // Malformed: an in-use record with created_ts == 0 (no creator) → rejected.
        let bad = build_record_page(PageId(7), StoreKind::Rel, StoreKind::Rel, |slot, rec| {
            if slot == 0 {
                // in_use set but created_ts left 0 → malformed (no creator).
                let h = MvccHeader {
                    flags: crate::record::FLAG_IN_USE,
                    created_ts: 0,
                    expired_ts: 0,
                    undo_ptr: 0,
                };
                h.write(rec);
            }
        });
        assert!(
            !RecordStore::<MemBlockDevice, MemLogSink>::orphan_page_records_well_formed(
                &bad[..],
                StoreKind::Rel
            )
        );
    }

    /// `rmp` #410: a normal heap write uses a real, non-zero `TxnId`, so the `alloc_chain` reservation
    /// assert (`txn.0 != 0`) holds and the chain round-trips. This pins the invariant the #398 orphan
    /// heap arm silently depends on (a `0` `xmin` is the none-sentinel it rejects), so a future change
    /// that wrote the heap under `TxnId(0)` would fail this test (and the assert) loudly.
    #[test]
    fn heap_write_uses_a_nonzero_txn_id() {
        let mut s = fresh();
        let t = TxnId(1);
        s.begin(t);
        let head = s
            .alloc_chain(t, b"graphus #410 heap chain")
            .expect("alloc heap chain");
        s.commit(t).unwrap();
        assert_eq!(
            s.read_chain(head).expect("read heap chain"),
            b"graphus #410 heap chain",
            "a heap chain written under a real TxnId round-trips"
        );
    }

    /// `rmp` #398 (gate): an orphan record page carrying a **valid CRC** but a wrong-but-in-range
    /// subtype must be caught by `open()` (returns `Err`) rather than silently attributing the page to
    /// the wrong store and flooring its high-water to a mismatched capacity. The page's records are
    /// malformed for the claimed kind (an in-use slot with no creator), modelling a corruption CRC32C
    /// cannot detect.
    #[test]
    fn orphan_page_with_mismatched_subtype_is_rejected_or_quarantined() {
        // A valid, openable on-disk image (META page + node-store structure).
        let mut s = fresh();
        let t = TxnId(1);
        s.begin(t);
        let _ = s.create_node(t).unwrap();
        s.commit(t).unwrap();
        let mut device = snapshot_device(&mut s);

        // Plant an orphan record page at the next free device id: subtype = Strings (in range, wrong),
        // but its records are malformed for ANY kind (slot 0 in-use with created_ts == 0). It is NOT
        // referenced by the durable catalog, so `reconstruct_orphan_store_pages` sees it as an orphan
        // and attributes it by subtype — where the cross-check must reject it.
        let orphan_id = PageId(device.page_count());
        device.extend(1).expect("grow device for the orphan page");
        let orphan = build_record_page(
            orphan_id,
            StoreKind::Strings,
            StoreKind::Strings,
            |slot, rec| {
                if slot == 0 {
                    // in_use, created_ts == 0 → malformed for ANY kind (no creator).
                    let h = MvccHeader {
                        flags: crate::record::FLAG_IN_USE,
                        created_ts: 0,
                        expired_ts: 0,
                        undo_ptr: 0,
                    };
                    h.write(rec);
                }
            },
        );
        device
            .write_page(orphan_id, &orphan)
            .expect("plant orphan page");
        device.sync_all().expect("persist orphan");

        // Reopen onto the perturbed device. `open` rebuilds the catalog from the durable WAL of the
        // original store, then re-attributes orphan pages — the planted page must fail closed.
        let log = s.with_wal(|w| w.sink().durable_bytes().to_vec());
        let mut sink = MemLogSink::new();
        sink.append(&log);
        sink.sync().expect("sync log");
        let wal = WalManager::open(sink).expect("open wal");
        let err = RecordStore::open(device, wal, 64);
        assert!(
            err.is_err(),
            "open() must reject an orphan page whose in-range subtype mismatches its record shape, \
             not silently mis-attribute it"
        );
    }

    /// `rmp` #337, Slice 2: the store must be `Send + Sync` so Slice 3 (#336, gated on #341) can hand
    /// an `Arc<RecordStore>` to off-thread readers. A compile-time assertion (no runtime body) — it
    /// fails to build the moment a non-`Sync` field is introduced. Slice 1 already made the two shared
    /// fields (`pool: Arc<ConcurrentBufferPool>` and `wal: SharedWal`) `Send + Sync`
    /// ([`crate::wal_rule`] asserts the latter); every other field is plain owned data (`Vec` /
    /// `HashMap` / `BTreeMap` / scalars / `Statistics` / `TokenStore` / `CommitRegistry`), so the auto
    /// derivation holds with **no** `unsafe impl`. Bounded on `D, S: Send + Sync`, the bound the
    /// concurrent pool's auto `Send + Sync` itself requires (its `Mutex<D>` / `Mutex<W>` need `D, W:
    /// Send`, and `SharedWal<S>: Send + Sync` needs `S: Send + Sync`).
    #[test]
    fn record_store_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        // The concrete DST instantiation used throughout these tests (the production file device + file
        // log instantiation is the same shape; both `D` and `S` are `Send + Sync`).
        assert_send_sync::<Store>();
        // And generically, so the property is stated as a bound rather than only for one `D, S` pair.
        fn assert_generic<D: BlockDevice + Send + Sync, S: LogSink + Send + Sync>() {
            assert_send_sync::<RecordStore<D, S>>();
        }
        assert_generic::<MemBlockDevice, MemLogSink>();
    }

    /// A [`BlockDevice`] wrapper that records, into a *shared* event log, the order and page id of
    /// every page written through it. The same log is shared between the home device and the
    /// doublewrite device so the test can reconstruct the **global** interleaving of stage-into-DWB
    /// vs write-home events and assert the doublewrite invariant. (`rmp` #385.)
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum WriteEvent {
        /// A page image staged into the doublewrite area (the home id read from the image header).
        Stage(u64),
        /// A page written to its home location on the data device.
        Home(u64),
    }

    struct RecordingDevice {
        inner: MemBlockDevice,
        log: std::rc::Rc<std::cell::RefCell<Vec<WriteEvent>>>,
        /// `true` for the doublewrite device (records `Stage`), `false` for the home device
        /// (records `Home`). A staged image self-identifies via its `page_id` header, so a DWB
        /// data-slot write is recorded under the *home* page id it carries, not the slot id.
        is_dwb: bool,
    }

    impl RecordingDevice {
        fn record(&mut self, buf: &graphus_io::Page) {
            // The DWB header slot is not a protected home page (it carries the batch's metadata,
            // page_id 0); skip it so only real staged home images are recorded.
            let pid = page::page_id(buf);
            let ev = if self.is_dwb {
                if !page::verify_checksum(buf) || page::page_type(buf) == 0 && pid == 0 {
                    // header slot or a non-page write — not a staged home image
                    return;
                }
                WriteEvent::Stage(pid)
            } else {
                WriteEvent::Home(pid)
            };
            self.log.borrow_mut().push(ev);
        }
    }

    impl BlockDevice for RecordingDevice {
        fn read_page(&self, page: PageId, buf: &mut graphus_io::Page) -> Result<()> {
            self.inner.read_page(page, buf)
        }
        fn write_page(&mut self, page: PageId, buf: &graphus_io::Page) -> Result<()> {
            self.record(buf);
            self.inner.write_page(page, buf)
        }
        fn write_pages(&mut self, base: PageId, pages: &[&graphus_io::Page]) -> Result<()> {
            for p in pages {
                self.record(p);
            }
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

    /// `rmp` #385 — the doublewrite invariant for a dirty set **larger than one DWB batch**: every
    /// dirty home page must be staged-and-synced into the doublewrite area *before* it is written
    /// home. The previous `flush_protected` flushed the **whole** pool inside its batch loop, so a
    /// page in batch 2..N was written home by batch 1's flush, *before* its DWB image existed — a
    /// tear on it had no intact copy to repair from. This test allocates more than
    /// [`crate::dwb::DWB_MAX_BATCH`] mapped pages, dirties a page in the second batch (image index
    /// `>= DWB_MAX_BATCH`) as well as the first, records every (stage, home) event through wrapper
    /// devices sharing one log, and asserts that for **every** page its first stage precedes its
    /// first home write.
    #[test]
    fn flush_protected_stages_every_page_before_any_home_write() {
        use crate::dwb::{DWB_MAX_BATCH, Dwb};

        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::<WriteEvent>::new()));
        let home_dev = RecordingDevice {
            inner: MemBlockDevice::new(0),
            log: std::rc::Rc::clone(&log),
            is_dwb: false,
        };
        // A pool large enough to keep every allocated page resident-and-dirty through to the flush,
        // so the home-write side touches a page in the second batch.
        let pool_capacity = DWB_MAX_BATCH + 256;
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let mut store: RecordStore<RecordingDevice, MemLogSink> =
            RecordStore::create(home_dev, wal, pool_capacity, 1).expect("create store");

        // Allocate more node-store pages than one DWB batch can hold, so the image set spans >= 2
        // batches. `ensure_store_page` allocates a page and leaves it dirty (WAL-logged type word).
        let txn = TxnId(1);
        store.begin(txn);
        let target_pages = DWB_MAX_BATCH + 64; // image set crosses the first batch boundary
        for rel_page in 0..target_pages as u64 {
            store
                .ensure_store_page(StoreKind::Node, rel_page, txn)
                .expect("ensure store page");
        }
        store.commit(txn).expect("commit");

        // The mapped image set must exceed one batch, or the test would not exercise the bug.
        let mapped = store.mapped_pages().len();
        assert!(
            mapped > DWB_MAX_BATCH,
            "test must map more than one DWB batch ({mapped} <= {DWB_MAX_BATCH})"
        );

        // Discard every write recorded during store setup (page allocation, the commit's
        // checkpoint_meta, evictions) — only the `flush_protected` interleaving is under test.
        log.borrow_mut().clear();

        // Flush under doublewrite protection through a recording DWB device sharing the same log.
        let dwb_dev = RecordingDevice {
            inner: MemBlockDevice::new(0),
            log: std::rc::Rc::clone(&log),
            is_dwb: true,
        };
        let mut dwb = Dwb::new(dwb_dev).expect("dwb");
        store.flush_protected(&mut dwb).expect("flush_protected");

        // Assert the invariant: for every page that was written home, its first stage event in the
        // global log precedes its first home-write event. A pre-#385 `flush_protected` flushed the
        // whole pool in batch 1, so a batch-2 page's Home event appeared before its Stage event.
        let events = log.borrow();
        let mut first_stage: std::collections::HashMap<u64, usize> =
            std::collections::HashMap::new();
        let mut first_home: std::collections::HashMap<u64, usize> =
            std::collections::HashMap::new();
        for (i, ev) in events.iter().enumerate() {
            match ev {
                WriteEvent::Stage(p) => {
                    first_stage.entry(*p).or_insert(i);
                }
                WriteEvent::Home(p) => {
                    first_home.entry(*p).or_insert(i);
                }
            }
        }
        assert!(
            !first_home.is_empty(),
            "the flush must have written home pages (none recorded)"
        );
        let mut checked_beyond_first_batch = false;
        for (page, &home_at) in &first_home {
            let stage_at = first_stage.get(page).copied().unwrap_or_else(|| {
                panic!("page {page} was written home but never staged into the DWB")
            });
            assert!(
                stage_at < home_at,
                "page {page}: home write at event {home_at} preceded its DWB stage at event \
                 {stage_at} — the doublewrite invariant is violated (a tear on it would be \
                 unrepairable)"
            );
            // Track whether at least one of the checked home pages lives in the second-or-later
            // batch (the exact pages the pre-#385 bug wrote home unprotected).
            if let Some(pos) = store.mapped_pages().iter().position(|m| m.0 == *page) {
                if pos >= DWB_MAX_BATCH {
                    checked_beyond_first_batch = true;
                }
            }
        }
        assert!(
            checked_beyond_first_batch,
            "the test must exercise at least one dirty home page beyond the first DWB batch \
             (image index >= {DWB_MAX_BATCH}), which is exactly what the pre-#385 code wrote \
             home unprotected"
        );
    }

    /// `rmp` #385 — crash variant: a torn home page in a **beyond-first-batch** position must be
    /// repaired by `recover_home` from its doublewrite copy. With the pre-#385 whole-pool flush, a
    /// batch-2 page was written home before its DWB image existed, so a tear on it had **no** copy
    /// to repair from. With the per-batch home write, the batch-2 page's DWB copy is durable before
    /// its home write, so the tear is repaired.
    #[test]
    fn flush_protected_repairs_a_torn_beyond_first_batch_page() {
        use crate::dwb::{DWB_MAX_BATCH, Dwb};

        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let pool_capacity = DWB_MAX_BATCH + 256;
        let mut store: Store = RecordStore::create(device, wal, pool_capacity, 1).expect("create");

        let txn = TxnId(1);
        store.begin(txn);
        let target_pages = DWB_MAX_BATCH + 64;
        for rel_page in 0..target_pages as u64 {
            store
                .ensure_store_page(StoreKind::Node, rel_page, txn)
                .expect("ensure store page");
        }
        store.commit(txn).expect("commit");

        // Flush under doublewrite protection into a DWB device we then snapshot.
        let mut dwb = Dwb::new(MemBlockDevice::new(0)).expect("dwb");
        store.flush_protected(&mut dwb).expect("flush_protected");

        // Snapshot the home image; tear a page BEYOND the first DWB batch (image index
        // >= DWB_MAX_BATCH) — exactly the page class the pre-#385 bug wrote home unprotected.
        let mapped = store.mapped_pages();
        assert!(
            mapped.len() > DWB_MAX_BATCH,
            "test must map more than one DWB batch"
        );
        let staged: Vec<(u64, Box<graphus_io::Page>)> = mapped
            .iter()
            .map(|p| (p.0, store.read_device_page(*p).expect("read device page")))
            .collect();

        // Pick a beyond-first-batch page and a prefix whose tear provably corrupts it. A torn write
        // keeps the new image's first `prefix` bytes and reverts the rest to the home device's prior
        // bytes (all-zero on this fresh device). A freshly-allocated record page is non-zero only in
        // its header (checksum + page_id/type + the logged type word) and otherwise zero, so a
        // *small* prefix that keeps the checksum field (bytes 0..4) but zeroes the page_id/type that
        // follow makes the checksum fail — a real, repairable tear. We scan prefixes to find one.
        let mut torn = None;
        let mut prefix = 0usize;
        'outer: for (image_idx, (idx, bytes)) in staged.iter().enumerate() {
            if image_idx < DWB_MAX_BATCH || *idx == 0 {
                continue;
            }
            for cut in [8usize, 16, 24, 32, 64] {
                let mut sim = [0u8; PAGE_SIZE];
                sim[..cut].copy_from_slice(&bytes[..cut]);
                if !page::verify_checksum(&sim) {
                    torn = Some(*idx);
                    prefix = cut;
                    break 'outer;
                }
            }
        }
        let torn = torn.expect("a beyond-first-batch page with a corrupting prefix tear");
        assert!(
            mapped.iter().position(|m| m.0 == torn).expect("mapped") >= DWB_MAX_BATCH,
            "the torn page must be beyond the first DWB batch"
        );

        // Materialise the on-disk home image, tearing the chosen page.
        let max = mapped.iter().map(|p| p.0).max().unwrap();
        let mut home = MemBlockDevice::new(max + 1);
        for (idx, bytes) in &staged {
            if *idx == torn {
                home.arm_torn_write(PageId(*idx), prefix);
            }
            home.write_page(PageId(*idx), bytes).expect("write home");
        }
        home.sync_all().expect("sync home");

        // Precondition: the tear actually landed (the home page now fails its checksum).
        let mut buf = [0u8; PAGE_SIZE];
        home.read_page(PageId(torn), &mut buf).expect("read torn");
        assert!(
            !page::verify_checksum(&buf),
            "the simulated tear must corrupt home page {torn}"
        );

        // Snapshot the DWB device and run the DWB repair pass (the recovery-side of the protocol).
        let dwb_pages = dwb.device().page_count();
        let mut dwb_dev = MemBlockDevice::new(dwb_pages);
        for i in 0..dwb_pages {
            let mut b = [0u8; PAGE_SIZE];
            dwb.device().read_page(PageId(i), &mut b).expect("read dwb");
            dwb_dev.write_page(PageId(i), &b).expect("stage dwb");
        }
        dwb_dev.sync_all().expect("sync dwb");
        let mut dwb_restore = Dwb::new(dwb_dev).expect("dwb restore");

        let repaired = dwb_restore.recover_home(&mut home).expect("recover_home");
        assert_eq!(
            repaired, 1,
            "the beyond-first-batch torn page must be repaired from its DWB copy"
        );

        // The repaired home page must now be intact and equal to the staged image.
        let mut got = [0u8; PAGE_SIZE];
        home.read_page(PageId(torn), &mut got)
            .expect("read repaired");
        assert!(
            page::verify_checksum(&got),
            "home page {torn} must be intact after DWB repair"
        );
        let original = &staged
            .iter()
            .find(|(idx, _)| *idx == torn)
            .expect("staged")
            .1;
        assert_eq!(
            &got[..],
            &original[..][..],
            "repaired page must equal its doublewrite copy"
        );
    }

    #[test]
    fn recovered_txn_hw_resumes_past_every_durable_id() {
        use crate::recovery::recover_device;

        // Regression for the cross-recovery transaction-id-reuse atomicity bug (uncommitted records
        // resurrected after a *second* crash). A reopened store must report a transaction-id high-water
        // that is past every id written into the durable WAL, so the coordinator that seeds its id
        // counter from it never reuses an id across recovery (which silently breaks ARIES loser/winner
        // classification — see `WalManager::max_recovered_txn_id`).
        let mut s = fresh();
        assert_eq!(
            s.recovered_txn_hw(),
            0,
            "a freshly created store has no prior txns"
        );

        // A committed transaction at id 5 and an in-flight loser at id 9 (no commit/abort).
        s.begin(TxnId(5));
        let _ = s.create_node(TxnId(5)).unwrap();
        s.commit(TxnId(5)).unwrap();
        s.begin(TxnId(9));
        let _ = s.create_node(TxnId(9)).unwrap(); // uncommitted at the "crash"
        // Model steal/no-force: the loser's log is forced durable (e.g. its dirty page was evicted
        // under the WAL rule) even though it never committed — exactly the case recovery must undo,
        // and the case whose id must still bound the recovered high-water.
        s.wal.with(|w| w.flush());

        // Capture the durable WAL prefix (what survives a power loss) and recover from it, exactly as
        // a reopen does.
        let log = s.wal.with(|w| {
            let mut b = Vec::new();
            w.read_durable(Lsn(0), &mut b).unwrap();
            b
        });
        let mut sink = MemLogSink::new();
        sink.append(&log);
        sink.sync().unwrap();
        let mut device = MemBlockDevice::new(0);
        let mut wal = WalManager::open(sink).unwrap();
        recover_device(&mut wal, &mut device).unwrap();
        let reopened = RecordStore::open(device, wal, 64).unwrap();

        assert_eq!(
            reopened.recovered_txn_hw(),
            9,
            "the counter must resume past the largest durable id (9, the in-flight loser), so a \
             post-recovery transaction never reuses ids 1..=9"
        );
    }

    /// **`rmp` #528 group-commit crash-mid-batch recovery (store layer).** A crash that lands after one
    /// group-commit batch's `fdatasync` but during a SECOND, un-hardened batch recovers ONLY the hardened
    /// batch's committed nodes — the un-`fdatasync`'d batch is lost WHOLE, never partially applied. This
    /// is the store-level ACID proof of the ack-after-fsync rule: a committer whose batch `fdatasync`
    /// never completed was never acked, so losing it (all of it) is correct. Deterministic (MemLogSink
    /// power-loss model + the real ARIES `recover_device` path), the DST/VOPR discipline.
    #[test]
    fn group_commit_crash_mid_batch_recovers_only_the_hardened_batch() {
        use crate::recovery::recover_device;

        let mut s = fresh();

        // --- Batch A: two write commits PREPAREd, then HARDENED by one fdatasync (durable, "acked"). ---
        for i in 1..=2u64 {
            s.begin(TxnId(i));
            s.create_node(TxnId(i)).unwrap();
            assert!(s.commit_prepare(TxnId(i)).unwrap().is_some());
        }
        s.harden_wal(); // ONE group-commit fdatasync hardens batch A

        // --- Batch B: two more write commits PREPAREd, but the batch fdatasync NEVER completes. ---
        for i in 3..=4u64 {
            s.begin(TxnId(i));
            s.create_node(TxnId(i)).unwrap();
            assert!(s.commit_prepare(TxnId(i)).unwrap().is_some());
        }
        // Power loss BEFORE batch B's `harden_wal`: the un-synced tail is dropped whole. Capture the
        // DURABLE prefix (what survived) — it holds batch A but not batch B (never fdatasync'd).
        let log = s.wal.with(|w| {
            let mut b = Vec::new();
            w.read_durable(Lsn(0), &mut b).unwrap();
            b
        });

        // Recover a fresh device purely from the durable WAL prefix, exactly as a reopen does.
        let mut sink = MemLogSink::new();
        sink.append(&log);
        sink.sync().unwrap();
        let mut device = MemBlockDevice::new(0);
        let mut wal = WalManager::open(sink).unwrap();
        recover_device(&mut wal, &mut device).unwrap();
        let reopened = RecordStore::open(device, wal, 64).unwrap();

        // Only batch A's two committed nodes survive; batch B's two are gone (never a partial batch).
        let live = reopened.scan_node_ids().unwrap();
        assert_eq!(
            live.len(),
            2,
            "only the hardened batch's committed nodes survive a mid-batch crash; the un-fdatasync'd \
             batch is lost WHOLE (live nodes: {live:?})"
        );
    }

    #[test]
    fn label_set_get_add_remove_round_trip() {
        let mut s = fresh();
        let txn = TxnId(1);
        s.begin(txn);
        let (a, _) = s.create_node(txn).unwrap();
        let person = s.intern_token(Namespace::Label, "Person").unwrap();
        let admin = s.intern_token(Namespace::Label, "Admin").unwrap();

        // A fresh node has no labels.
        assert_eq!(s.node_labels(a).unwrap(), Vec::<u32>::new());
        assert!(!s.node_has_label(a, person).unwrap());

        // set_node_labels overwrites the whole set.
        s.set_node_labels(txn, a, &[person, admin]).unwrap();
        let mut ids = s.node_labels(a).unwrap();
        ids.sort_unstable();
        let mut want = vec![person, admin];
        want.sort_unstable();
        assert_eq!(ids, want);
        assert!(s.node_has_label(a, person).unwrap());
        assert!(s.node_has_label(a, admin).unwrap());

        // add_label is idempotent; remove_label clears one bit.
        s.add_label(txn, a, person).unwrap();
        s.remove_label(txn, a, admin).unwrap();
        assert_eq!(s.node_labels(a).unwrap(), vec![person]);
        assert!(s.node_has_label(a, person).unwrap());
        assert!(!s.node_has_label(a, admin).unwrap());

        // Removing an absent label is a no-op (idempotent).
        s.remove_label(txn, a, admin).unwrap();
        assert_eq!(s.node_labels(a).unwrap(), vec![person]);

        s.commit(txn).unwrap();
    }

    #[test]
    fn labels_are_independent_per_node() {
        let mut s = fresh();
        let txn = TxnId(1);
        s.begin(txn);
        let (a, _) = s.create_node(txn).unwrap();
        let (b, _) = s.create_node(txn).unwrap();
        let l0 = s.intern_token(Namespace::Label, "L0").unwrap();
        let l1 = s.intern_token(Namespace::Label, "L1").unwrap();
        s.add_label(txn, a, l0).unwrap();
        s.add_label(txn, b, l1).unwrap();
        assert_eq!(s.node_labels(a).unwrap(), vec![l0]);
        assert_eq!(s.node_labels(b).unwrap(), vec![l1]);
        s.commit(txn).unwrap();
    }

    #[test]
    fn label_token_id_at_overflow_boundary_is_a_clear_error() {
        let mut s = fresh();
        let txn = TxnId(1);
        s.begin(txn);
        let (a, _) = s.create_node(txn).unwrap();
        // Token ids 0..=62 fit inline; id 63 is the overflow flag and must be rejected.
        let err = s.add_label(txn, a, 63).unwrap_err();
        assert!(matches!(err, GraphusError::Runtime(_)));
        assert!(err.to_string().contains("#39"), "got: {err}");
        // The node is unchanged (no partial write).
        assert_eq!(s.node_labels(a).unwrap(), Vec::<u32>::new());
        s.commit(txn).unwrap();
    }

    #[test]
    fn label_ops_on_a_missing_node_are_a_storage_error() {
        let mut s = fresh();
        let txn = TxnId(1);
        s.begin(txn);
        let (a, _) = s.create_node(txn).unwrap();
        s.delete_node(txn, a).unwrap();
        let err = s.add_label(txn, a, 0).unwrap_err();
        assert!(matches!(err, GraphusError::Storage(_)));
        s.commit(txn).unwrap();
    }

    // ------------------ per-value property MVCC (`rmp` task #50, `rmp` #967) ------------------
    //
    // Regression guards for the dirty-read bug per-value MVCC fixes: `set_*_property_value` used to
    // *compact* (free the old record + overflow chain, prepend the new), so a concurrent older
    // snapshot could no longer read the previous value.
    //
    // `rmp` #967 changed WHERE the old value survives, not WHETHER it does. It is no longer a
    // tombstoned cell in the owner's `first_prop` chain; it is a `SetProperty` delta on the owner's
    // undo chain, and the newest value is written into the cell in place. The tests below were
    // rewritten accordingly — each retired mechanism assertion replaced by a named semantic
    // equivalent that is at least as strong (`D-retired-mechanism-tests`), which in practice means
    // asserting the EXACT old value an older snapshot reads rather than merely that the cell count
    // changed.

    use graphus_core::{Value, VersionStamp};

    /// Runs one GC pass under a fresh `txn` at the given `watermark` (see [`RecordStore::gc`]).
    fn gc_at(s: &mut Store, txn: TxnId, watermark: Timestamp) -> usize {
        s.begin(txn);
        let report = s.gc(txn, watermark).unwrap();
        s.commit(txn).unwrap();
        report.reclaimed
    }

    /// **Semantic equivalent of** the retired
    /// `overwriting_a_node_property_tombstones_the_old_version_and_keeps_both_until_gc`.
    ///
    /// That test asserted the retired *mechanism*: two cells in the chain, one live and one carrying
    /// a committed `xmax`. This asserts the *semantic* the mechanism existed for, and asserts more of
    /// it: that an older snapshot reads back the **exact previous value**, that the newest value is
    /// in the cell, that the old one lives on the undo chain, and that GC honours the watermark in
    /// both directions.
    ///
    /// The strengthening matters. The failure mode this task introduces is that an older snapshot
    /// finds no value at all and reads the property as *absent* — every "the value is not 2"
    /// assertion passes in that case, and this one does not.
    #[test]
    fn overwriting_a_node_property_keeps_the_exact_old_value_readable_until_gc() {
        let mut s = fresh();
        let key = s.intern_token(Namespace::PropKey, "v").unwrap();

        // Txn 1: create a node with `v = 1`, commit.
        let t1 = TxnId(1);
        s.begin(t1);
        let (n, _) = s.create_node(t1).unwrap();
        let cell = s
            .set_node_property_value(t1, n, key, &Value::Integer(1))
            .unwrap();
        s.commit(t1).unwrap();
        let snap_after_v1 = s.snapshot_ts(); // a reader that began here must still see `v = 1`

        // Txn 2: overwrite to `v = 2`, commit. The cell is rewritten IN PLACE — same physical id,
        // no new record — and `1` descends onto the node's undo chain.
        let t2 = TxnId(2);
        s.begin(t2);
        let same_cell = s
            .set_node_property_value(t2, n, key, &Value::Integer(2))
            .unwrap();
        s.commit(t2).unwrap();
        assert_eq!(
            same_cell, cell,
            "the overwrite must reuse the cell, not allocate a new one",
        );

        let chain = s.superset_scan_node_properties(n).unwrap();
        assert_eq!(chain.len(), 1, "exactly one cell, rewritten in place");
        let cells = chain.cells_ignoring_history();
        assert_eq!(
            s.decode_property_value(cells[0].1.type_tag, cells[0].1.value_inline)
                .unwrap(),
            Value::Integer(2),
            "the cell holds the newest value",
        );
        assert_eq!(
            cells[0].1.mvcc.expired_ts, 0,
            "`D-property-removal`: a property operation never stamps `xmax` again",
        );
        assert_eq!(
            cells[0].1.mvcc.undo_ptr, 0,
            "a property cell never anchors a chain; the delta anchors on the owning node",
        );

        // The superset carries BOTH values — the current one from the cell and the previous one from
        // the chain — which is what keeps an index refill correct after this task.
        let mut candidates: Vec<Value> = chain
            .candidates()
            .map(|c| s.decode_property_value(c.type_tag, c.value_inline).unwrap())
            .collect();
        candidates.sort_by_key(|v| match v {
            Value::Integer(i) => *i,
            _ => unreachable!("integers only"),
        });
        assert_eq!(
            candidates,
            vec![Value::Integer(1), Value::Integer(2)],
            "the superset must contain every value any snapshot can ask for",
        );

        // THE POINT: the older snapshot reads the EXACT old value, not merely "not 2", and above all
        // not `None`.
        let old_reader = Snapshot {
            owner: TxnId(90),
            ts: snap_after_v1,
        };
        let decided = s.decision_scan_node_properties(n, old_reader).unwrap();
        let seen = decided
            .visible_version(key)
            .expect("the older snapshot must still HOLD the key, not read it as absent");
        assert_eq!(
            s.decode_property_value(seen.type_tag, seen.value_inline)
                .unwrap(),
            Value::Integer(1),
            "an older snapshot reads the exact previous value",
        );

        // Snapshot isolation: GC at a watermark BELOW the overwrite's commit timestamp must NOT
        // reclaim the delta the older reader still needs.
        gc_at(&mut s, TxnId(3), snap_after_v1);
        assert_eq!(
            s.superset_scan_node_properties(n).unwrap().history_len(),
            3,
            "GC must not reclaim a delta an older snapshot can still resolve through (the chain is \
             `SET v=2` / `v was absent` / `node created`, and a chain is reclaimed WHOLE or not at \
             all — the newest delta committed after this watermark, so none of them goes)",
        );
        let seen = s
            .decision_scan_node_properties(n, old_reader)
            .unwrap()
            .visible_version(key)
            .expect("still readable after a too-early GC");
        assert_eq!(
            s.decode_property_value(seen.type_tag, seen.value_inline)
                .unwrap(),
            Value::Integer(1),
        );

        // Once no live snapshot predates the overwrite, GC reclaims the whole chain and the cell
        // stands alone holding the current value.
        let latest = s.snapshot_ts();
        gc_at(&mut s, TxnId(4), latest);
        let chain = s.superset_scan_node_properties(n).unwrap();
        assert_eq!(chain.len(), 1, "the cell survives");
        assert_eq!(chain.history_len(), 0, "the undo chain is reclaimed at GC");
        assert_eq!(
            s.superset_scan_node_property_values(n).unwrap(),
            vec![(cell, key, Value::Integer(2))]
        );
    }

    /// The removal twin, and the same strengthening: after a committed `REMOVE` the key is absent to
    /// a new reader and reads back its **exact** old value to an older one.
    #[test]
    fn removing_a_node_property_empties_the_cell_and_keeps_the_exact_old_value() {
        let mut s = fresh();
        let key = s.intern_token(Namespace::PropKey, "v").unwrap();
        let t1 = TxnId(1);
        s.begin(t1);
        let (n, _) = s.create_node(t1).unwrap();
        let cell = s
            .set_node_property_value(t1, n, key, &Value::Integer(7))
            .unwrap();
        s.commit(t1).unwrap();
        let before_removal = s.snapshot_ts();

        let t2 = TxnId(2);
        s.begin(t2);
        assert!(s.remove_node_property_value(t2, n, key).unwrap());
        s.commit(t2).unwrap();

        // The cell keeps its slot and its place in the chain, emptied in place.
        let chain = s.superset_scan_node_properties(n).unwrap();
        assert_eq!(chain.len(), 1, "the cell keeps its slot");
        let (pid, emptied) = chain.cells_ignoring_history()[0];
        assert_eq!(pid, cell);
        assert!(
            emptied.mvcc.in_use(),
            "`in_use` keeps its structural meaning"
        );
        assert_eq!(emptied.type_tag, undo::TYPE_TAG_ABSENT);
        assert_eq!(emptied.value_inline, 0);
        assert_eq!(emptied.mvcc.expired_ts, 0, "no `xmax` tombstone");

        let now = Snapshot {
            owner: TxnId(90),
            ts: s.snapshot_ts(),
        };
        assert!(
            s.decision_scan_node_properties(n, now)
                .unwrap()
                .visible_version(key)
                .is_none(),
            "a committed removal makes the key absent",
        );

        let old = Snapshot {
            owner: TxnId(91),
            ts: before_removal,
        };
        let seen = s
            .decision_scan_node_properties(n, old)
            .unwrap()
            .visible_version(key)
            .expect("an older snapshot must still hold the key");
        assert_eq!(
            s.decode_property_value(seen.type_tag, seen.value_inline)
                .unwrap(),
            Value::Integer(7),
        );

        // A later SET of the same key REUSES the empty cell — no allocation (`D-property-removal`).
        let t3 = TxnId(3);
        s.begin(t3);
        let reused = s
            .set_node_property_value(t3, n, key, &Value::Integer(8))
            .unwrap();
        s.commit(t3).unwrap();
        assert_eq!(reused, cell, "a later SET reuses the emptied cell");
        assert_eq!(s.superset_scan_node_properties(n).unwrap().len(), 1);
    }

    #[test]
    fn new_property_version_is_in_flight_then_settles_at_commit() {
        let mut s = fresh();
        let key = s.intern_token(Namespace::PropKey, "v").unwrap();
        let t1 = TxnId(7);
        s.begin(t1);
        let (n, _) = s.create_node(t1).unwrap();
        let pid = s
            .set_node_property_value(t1, n, key, &Value::Integer(42))
            .unwrap();
        // Before commit, the new version's `xmin` is the writer's in-flight TxnId (per-value MVCC).
        let pre = s.property(pid).unwrap();
        assert_eq!(
            VersionStamp::from_raw(pre.mvcc.created_ts),
            VersionStamp::InFlight(t1)
        );
        s.commit(t1).unwrap();
        // After commit (lazy GC-time freezing, `rmp` task #49): `xmin` is NOT settled — it keeps the
        // writer's in-flight TxnId — but the Active/Recent Transaction Table resolves it to the
        // commit timestamp. Per-value property versions resolve through the same table as node/rel
        // versions; GC freezes the header later.
        let post = s.property(pid).unwrap();
        assert_eq!(
            VersionStamp::from_raw(post.mvcc.created_ts),
            VersionStamp::InFlight(t1)
        );
        assert!(
            s.commit_registry()
                .resolve_commit_ts(post.mvcc.created_ts)
                .is_some(),
            "the transaction table resolves the property version's in-flight xmin to its commit ts"
        );
        assert_eq!(
            post.mvcc.expired_ts, 0,
            "the live version carries no tombstone"
        );
    }

    /// `rmp` #301 regression: the MVCC **tombstone** (`xmax`) header write uses a **compare-and-set
    /// logical undo** ([`RecordStore::patch_header_word_cas`]), so a **non-LIFO** abort never clobbers
    /// an `xmax` word that a concurrently-interleaved transaction has since re-stamped. A plain
    /// pre-image undo (the pre-#301 behaviour) would restore the aborting transaction's stale
    /// pre-image over the newer stamp — a lost-update / visibility breach mirroring the `rmp` #239
    /// non-LIFO relationship-recovery defect and the `rmp` #578 free-list-restore hazard.
    ///
    /// **Retargeted for `rmp` #967, not weakened.** The primitive under test is unchanged and so is
    /// the property it proves; only the *store* changed. `rmp` #967 retired the property tombstone
    /// (`D-property-removal`: a removal empties the cell in place, and `expired_ts` is never written
    /// by a property operation again), so a `Prop` `xmax` is no longer a state the store can hold —
    /// the consistency checker now reports one as
    /// [`MvccHeaderFault::PropertyCellTombstoned`](crate::check::MvccHeaderFault). The CAS undo's
    /// remaining users are the node and relationship delete tombstones
    /// ([`delete_node`](RecordStore::delete_node) / [`delete_rel`](RecordStore::delete_rel)), so the
    /// test now drives the identical two-writer interleaving on a **node**'s `xmax`. Swapping
    /// `patch_header_word_cas` back to the plain `patch_header_word` still makes the final assertion
    /// fail (T1's abort restores `0`, clobbering T2).
    ///
    /// Reachability: the public delete/tombstone API is guarded by
    /// [`is_live_version`](RecordStore::is_live_version), which — with the single-threaded engine and
    /// SSI — currently serialises `xmax` writes so two live transactions cannot stamp the same word.
    /// This is therefore a **defense-in-depth** hardening of the storage undo primitive (the `rmp`
    /// #220/#239 discipline: a shared-field undo must be intrinsically non-LIFO-safe, never rely on a
    /// higher layer). The test drives the primitive directly to model exactly the two-writer
    /// interleaving the guard elides.
    #[test]
    fn tombstone_xmax_undo_is_non_lifo_safe_301() {
        let mut s = fresh();

        // A committed node H, live (xmax == 0).
        let setup = TxnId(1);
        s.begin(setup);
        let (h, _) = s.create_node(setup).unwrap();
        s.commit(setup).unwrap();
        assert_eq!(s.node(h).unwrap().mvcc.expired_ts, 0, "H starts live");

        // Two concurrently-open transactions BOTH stamp H's xmax. T1 stamps first, T2 second — the
        // interleaving the `is_live_version` guard elides, modelled directly on the storage primitive.
        let t1 = TxnId(2);
        let t2 = TxnId(3);
        s.begin(t1);
        s.begin(t2);
        s.patch_header_word_cas(
            StoreKind::Node,
            h,
            MVCC_OFF_EXPIRED_TS,
            VersionStamp::in_flight(t1),
            t1,
        )
        .unwrap();
        s.patch_header_word_cas(
            StoreKind::Node,
            h,
            MVCC_OFF_EXPIRED_TS,
            VersionStamp::in_flight(t2),
            t2,
        )
        .unwrap();
        assert_eq!(
            VersionStamp::from_raw(s.node(h).unwrap().mvcc.expired_ts),
            VersionStamp::InFlight(t2),
            "T2's stamp is the current xmax before the non-LIFO abort"
        );

        // NON-LIFO abort: the EARLIER writer (T1) rolls back while the LATER writer (T2) still owns the
        // word. The CAS undo reverts only if xmax is still T1's stamp — it is not (T2 overwrote it), so
        // it no-ops and T2's stamp is PRESERVED. A plain pre-image undo would restore 0 (a clobber).
        s.rollback(t1).unwrap();
        assert_eq!(
            VersionStamp::from_raw(s.node(h).unwrap().mvcc.expired_ts),
            VersionStamp::InFlight(t2),
            "rmp #301: T1's non-LIFO abort must NOT clobber T2's concurrent xmax stamp"
        );

        // T2 commits: its tombstone stands (no lost update). Then GC + consistency check.
        s.commit(t2).unwrap();
        assert!(
            s.commit_registry()
                .resolve_commit_ts(s.node(h).unwrap().mvcc.expired_ts)
                .is_some(),
            "H's tombstone resolves to T2's commit ts — the delete survived"
        );
        let watermark = s.snapshot_ts();
        s.begin(TxnId(4));
        s.gc(TxnId(4), watermark).unwrap();
        s.commit(TxnId(4)).unwrap();
        let report = crate::check::check_store(&mut s, &[]).unwrap();
        assert!(
            report.is_consistent(),
            "store consistent after #301 non-LIFO abort: {:?}",
            report.violations
        );
    }

    /// **Semantic equivalent of** the retired
    /// `tombstone_xmax_lifo_single_txn_abort_restores_live_301`, which asserted the ordinary LIFO
    /// abort of a property `REMOVE` restored `xmax == 0` on the tombstoned record.
    ///
    /// After `rmp` #967 a `REMOVE` does not stamp anything — it rewrites the cell in place — so the
    /// mechanism that test guarded no longer exists. The **semantic** it guarded does, and it is
    /// asserted here in its stronger form: an aborted `REMOVE` must leave the property readable
    /// **with its exact previous value**, not merely leave some record un-tombstoned. The plain
    /// pre-image undo of the cell region ([`RecordStore::write_prop_cell`]) is what has to hold, and
    /// the abort window's benign ordering (delta written before cell, so rollback restores cell
    /// first) is what makes it hold.
    #[test]
    fn a_single_txn_abort_of_a_removal_restores_the_exact_value_967() {
        let mut s = fresh();
        let key = s.intern_token(Namespace::PropKey, "v").unwrap();
        let setup = TxnId(1);
        s.begin(setup);
        let (h, _) = s.create_node(setup).unwrap();
        let v0 = s
            .set_node_property_value(setup, h, key, &Value::Integer(1))
            .unwrap();
        s.commit(setup).unwrap();

        // A real removal via the public API, then a single-transaction abort.
        let t1 = TxnId(2);
        s.begin(t1);
        s.remove_node_property_value(t1, h, key).unwrap();
        assert_eq!(
            s.property(v0).unwrap().type_tag,
            undo::TYPE_TAG_ABSENT,
            "the cell is emptied in place before the abort"
        );
        s.rollback(t1).unwrap();

        let cell = s.property(v0).unwrap();
        assert_eq!(
            s.decode_property_value(cell.type_tag, cell.value_inline)
                .unwrap(),
            Value::Integer(1),
            "the abort restores the EXACT previous value into the cell, not merely a live slot",
        );
        assert_eq!(cell.mvcc.expired_ts, 0);
        assert_eq!(
            s.superset_scan_node_property_values(h).unwrap(),
            vec![(v0, key, Value::Integer(1))],
            "the property is readable again after the abort, with nothing left on the chain",
        );
        let report = crate::check::check_store(&mut s, &[]).unwrap();
        assert!(
            report.is_consistent(),
            "store consistent after the aborted removal: {:?}",
            report.violations
        );
    }

    /// Commits a node H with one property, then deletes that property and GCs, so its physical id `P`
    /// is freed and the durably-committed `Prop` free list is exactly `[P]`. Returns `(h, key, P)`.
    fn setup_freed_prop_slot(s: &mut Store) -> (u64, u32, u64) {
        let key = s.intern_token(Namespace::PropKey, "v").unwrap();
        let t0 = TxnId(1);
        s.begin(t0);
        let (h, _) = s.create_node(t0).unwrap();
        let p = s.add_node_property(t0, h, key, 1, 0x10).unwrap();
        s.commit(t0).unwrap();
        let t_del = TxnId(2);
        s.begin(t_del);
        s.remove_node_property_value(t_del, h, key).unwrap();
        s.commit(t_del).unwrap();
        let wm = s.snapshot_ts();
        s.begin(TxnId(3));
        s.gc(TxnId(3), wm).unwrap();
        s.commit(TxnId(3)).unwrap();
        assert_eq!(
            s.store(StoreKind::Prop).free.ids(),
            &[p],
            "setup: the deleted property's slot P is on the free list after GC"
        );
        (h, key, p)
    }

    /// Commits two nodes A, B and one `LINK` relationship between them, then deletes that relationship
    /// and GCs, so its physical id `R` is freed and the durably-committed `Rel` free list is exactly
    /// `[R]` (both endpoints back to an empty incidence chain). Returns `(A, B, LINK type, R)`. The
    /// `Rel` twin of [`setup_freed_prop_slot`].
    fn setup_freed_rel_slot(s: &mut Store) -> (u64, u64, u32, u64) {
        let ty = s.intern_token(Namespace::RelType, "LINK").unwrap();
        let t0 = TxnId(1);
        s.begin(t0);
        let (a, _) = s.create_node(t0).unwrap();
        let (b, _) = s.create_node(t0).unwrap();
        let (r, _) = s.create_rel(t0, ty, a, b).unwrap();
        s.commit(t0).unwrap();
        let t_del = TxnId(2);
        s.begin(t_del);
        s.delete_rel(t_del, r).unwrap();
        s.commit(t_del).unwrap();
        let wm = s.snapshot_ts();
        s.begin(TxnId(3));
        s.gc(TxnId(3), wm).unwrap();
        s.commit(TxnId(3)).unwrap();
        assert_eq!(
            s.store(StoreKind::Rel).free.ids(),
            &[r],
            "setup: the deleted relationship's slot R is on the free list after GC"
        );
        assert_eq!(
            s.read_node(a).unwrap().first_rel,
            NULL_ID,
            "setup: A's incidence chain is empty after the delete + GC unlinked R"
        );
        assert_eq!(
            s.read_node(b).unwrap().first_rel,
            NULL_ID,
            "setup: B's incidence chain is empty after the delete + GC unlinked R"
        );
        (a, b, ty, r)
    }

    /// `rmp` #581: an aborting transaction's OWN reused-id pop that ends up UNREFERENCED is returned to
    /// the free list (reclaimed), closing the reuse-then-abort bounded space leak the #578 fix
    /// documented. Deterministic RecordStore repro (the #578 DST-harness style).
    #[test]
    fn aborted_unreferenced_pop_is_reclaimed_to_the_free_list_581() {
        let mut s = fresh();
        let (h, key, p) = setup_freed_prop_slot(&mut s);

        // T1 pops P (reuses the freed slot) as a new property head, then aborts with NO concurrent
        // prepend, so the chain-head CAS undo unlinks P and it ends up unreferenced.
        let t1 = TxnId(4);
        s.begin(t1);
        let reused = s.add_node_property(t1, h, key, 1, 0x20).unwrap();
        assert_eq!(
            reused, p,
            "T1 popped the freed slot P (precondition reached)"
        );
        assert!(
            s.store(StoreKind::Prop).free.is_empty(),
            "P is off the free list while T1 holds it"
        );
        s.rollback(t1).unwrap();

        // #581: P was never consumed (T1 aborted) and is unreferenced, so it is BACK on the free list.
        assert_eq!(
            s.store(StoreKind::Prop).free.ids(),
            &[p],
            "rmp #581: the aborted unreferenced pop is reclaimed to the free list"
        );
        // Observable end-to-end: the next allocation reuses P (pre-#581 it leaked and allocated fresh).
        let t2 = TxnId(5);
        s.begin(t2);
        let again = s.add_node_property(t2, h, key, 1, 0x30).unwrap();
        assert_eq!(
            again, p,
            "the reclaimed slot P is reused by the next allocation"
        );
        s.commit(t2).unwrap();
        let report = crate::check::check_store(&mut s, &[]).unwrap();
        assert!(
            report.is_consistent(),
            "store consistent after #581 reclaim + reuse: {:?}",
            report.violations
        );
    }

    /// `rmp` #581 (safety boundary): an aborting transaction's own reused-id pop that a
    /// concurrently-committed writer prepended onto is a LIVE-REFERENCED corpse (the #220/#172
    /// pattern) and MUST NOT be re-pushed — re-freeing a still-threaded slot would be the #578
    /// double-allocation in reverse. It stays a corpse the GC property-chain splice reclaims, and the
    /// storage consistency checker stays green throughout.
    #[test]
    fn aborted_pop_that_became_a_live_corpse_is_not_reclaimed_581() {
        let mut s = fresh();
        let (h, key, p) = setup_freed_prop_slot(&mut s);

        // T1 pops P and links it as H's property head, staying OPEN.
        let t1 = TxnId(4);
        s.begin(t1);
        let reused = s.add_node_property(t1, h, key, 1, 0x20).unwrap();
        assert_eq!(reused, p, "T1 popped the freed slot P");

        // A concurrent committed writer C prepends a NEW property Q on TOP of P (so P becomes
        // referenced by Q.next_prop). C allocates fresh — T1's pop emptied the free list.
        let c = TxnId(5);
        s.begin(c);
        let q = s.add_node_property(c, h, key + 1, 1, 0x30).unwrap();
        assert_ne!(q, p, "C allocates a fresh slot (T1 emptied the free list)");
        s.commit(c).unwrap();

        // T1 aborts (non-LIFO relative to C): P is now a live-referenced corpse (H -> Q -> P -> NULL).
        s.rollback(t1).unwrap();
        assert!(
            s.store(StoreKind::Prop).free.is_empty(),
            "rmp #581: a referenced-corpse pop must NOT be reclaimed (no double-free of a threaded slot)"
        );
        assert!(
            !s.property(p).unwrap().mvcc.in_use(),
            "P is a not-in-use corpse threaded below the committed prepend"
        );
        // The checker tolerates the corpse threaded in the live chain (no StillInUse / ReferencedByLiveChain).
        let report = crate::check::check_store(&mut s, &[]).unwrap();
        assert!(
            report.is_consistent(),
            "corpse-threaded chain is consistent: {:?}",
            report.violations
        );
        // A subsequent allocation does NOT hand out the still-referenced corpse slot P.
        let t2 = TxnId(6);
        s.begin(t2);
        let fresh_id = s.add_node_property(t2, h, key + 2, 1, 0x40).unwrap();
        assert_ne!(
            fresh_id, p,
            "the corpse slot P is not handed out (still referenced)"
        );
        s.commit(t2).unwrap();

        // GC reclaims the corpse P via the property-chain splice; the checker stays green.
        let wm2 = s.snapshot_ts();
        s.begin(TxnId(7));
        s.gc(TxnId(7), wm2).unwrap();
        s.commit(TxnId(7)).unwrap();
        let report = crate::check::check_store(&mut s, &[]).unwrap();
        assert!(
            report.is_consistent(),
            "store consistent after GC reclaims the corpse: {:?}",
            report.violations
        );
    }

    /// `rmp` #581 (safety boundary, REL branch): the `Rel` mirror of
    /// [`aborted_pop_that_became_a_live_corpse_is_not_reclaimed_581`]. An aborting transaction's own
    /// reused-id relationship pop that a concurrently-committed writer prepended onto is a
    /// LIVE-REFERENCED corpse (the #220/#172 pattern) and MUST NOT be re-pushed: re-freeing a slot
    /// still threaded into a live incidence chain would hand the allocator a slot a committed edge
    /// points at — the `rmp` #578 double-allocation in reverse, i.e. committed-data corruption. This
    /// drives [`rel_slot_referenced`](Self::rel_slot_referenced) to return `true` so the decline at the
    /// `Rel` arm of [`reclaim_aborted_pops`](Self::reclaim_aborted_pops) fires; the slot stays a corpse
    /// the GC incidence-chain splice reclaims, and the consistency checker stays green throughout.
    #[test]
    fn aborted_rel_pop_that_became_a_live_corpse_is_not_reclaimed_581() {
        let mut s = fresh();
        let (a, b, ty, r) = setup_freed_rel_slot(&mut s);

        // T1 pops R by creating a fresh A-[:LINK]->B relationship (reuses the freed slot), staying
        // OPEN. R is now the head of BOTH endpoints' incidence chains (A.first_rel == B.first_rel == R),
        // written in-place via the structural chain-head CAS so a concurrent writer observes it.
        let t1 = TxnId(4);
        s.begin(t1);
        let (reused, _) = s.create_rel(t1, ty, a, b).unwrap();
        assert_eq!(reused, r, "T1 popped the freed rel slot R");
        assert!(
            s.store(StoreKind::Rel).free.is_empty(),
            "R is off the free list while T1 holds it"
        );

        // A concurrent committed writer C prepends a NEW parallel A-[:LINK]->B relationship S on TOP of
        // R (multigraph): S becomes each chain's head and threads through R (S.start_next == R and
        // S.end_next == R). C allocates a FRESH slot — T1's pop emptied the free list.
        let c = TxnId(5);
        s.begin(c);
        let (sid, _) = s.create_rel(c, ty, a, b).unwrap();
        assert_ne!(
            sid, r,
            "C allocates a fresh slot (T1 emptied the free list)"
        );
        s.commit(c).unwrap();

        // Precondition proof of the corpse topology: R is genuinely threaded below the committed S in
        // BOTH endpoint chains — exactly the state that makes `rel_slot_referenced(R)` return true.
        let s_rec = s.read_rel(sid).unwrap();
        assert_eq!(
            s.read_node(a).unwrap().first_rel,
            sid,
            "S is A's chain head"
        );
        assert_eq!(
            s.read_node(b).unwrap().first_rel,
            sid,
            "S is B's chain head"
        );
        assert_eq!(
            s_rec.start_next_rel, r,
            "S's start-side chain link threads through R (R referenced by A's live chain)"
        );
        assert_eq!(
            s_rec.end_next_rel, r,
            "S's end-side chain link threads through R (R referenced by B's live chain)"
        );

        // T1 aborts (non-LIFO relative to C): R is now a live-referenced corpse (A/B -> S -> R -> NULL).
        s.rollback(t1).unwrap();
        assert!(
            s.store(StoreKind::Rel).free.is_empty(),
            "rmp #581: a referenced-corpse rel pop must NOT be reclaimed (no double-free of a threaded \
             slot)"
        );
        assert!(
            !s.read_rel(r).unwrap().mvcc.in_use(),
            "R is a not-in-use corpse threaded below the committed prepend"
        );
        // The corpse is still threaded below S in both chains (the abort's chain-head CAS no-oped
        // because C had already pushed S on top, so `first_rel` no longer equals R).
        assert_eq!(
            s.read_rel(sid).unwrap().start_next_rel,
            r,
            "R is still threaded below S after the abort (the CAS chain-head undo no-oped)"
        );
        // The checker tolerates the corpse threaded in the live chain (no double-free / dangling link).
        let report = crate::check::check_store(&mut s, &[]).unwrap();
        assert!(
            report.is_consistent(),
            "corpse-threaded rel chain is consistent: {:?}",
            report.violations
        );
        // A subsequent rel allocation does NOT hand out the still-referenced corpse slot R.
        let t2 = TxnId(6);
        s.begin(t2);
        let (fresh_rel, _) = s.create_rel(t2, ty, a, b).unwrap();
        assert_ne!(
            fresh_rel, r,
            "the corpse slot R is not handed out (still referenced)"
        );
        s.commit(t2).unwrap();

        // GC reclaims the corpse R via the incidence-chain splice; the checker stays green.
        let wm2 = s.snapshot_ts();
        s.begin(TxnId(7));
        s.gc(TxnId(7), wm2).unwrap();
        s.commit(TxnId(7)).unwrap();
        assert!(
            !s.read_rel(r).unwrap().mvcc.in_use(),
            "R is still a not-in-use slot after GC spliced it out of the chains"
        );
        let report = crate::check::check_store(&mut s, &[]).unwrap();
        assert!(
            report.is_consistent(),
            "store consistent after GC reclaims the rel corpse: {:?}",
            report.violations
        );
    }

    /// `rmp` #581: a reused-id pop that a transaction COMMITS is untouched — the pop reclaim fires only
    /// on rollback, and a committed reuse is a live record, never returned to the free list.
    #[test]
    fn committed_pop_is_not_reclaimed_581() {
        let mut s = fresh();
        let (h, key, p) = setup_freed_prop_slot(&mut s);
        let t1 = TxnId(4);
        s.begin(t1);
        let reused = s.add_node_property(t1, h, key, 1, 0x20).unwrap();
        assert_eq!(reused, p);
        s.commit(t1).unwrap();
        assert!(
            s.store(StoreKind::Prop).free.is_empty(),
            "a committed reuse leaves nothing on the free list"
        );
        assert!(
            s.property(p).unwrap().mvcc.in_use(),
            "the committed reused slot holds a live record"
        );
        let report = crate::check::check_store(&mut s, &[]).unwrap();
        assert!(report.is_consistent(), "{:?}", report.violations);
    }

    /// Runs a GC pass over `s` at the current snapshot as its own transaction, returning the report.
    /// **The undo area's orphan-page cross-validation must use its own codec, not the MVCC header
    /// shape** (`rmp` #966).
    ///
    /// `reconstruct_orphan_store_pages` attributes an orphan record page to a store by its subtype
    /// byte and then cross-validates the page's records against that claimed kind (`rmp` #398),
    /// because CRC32C cannot catch an in-range but WRONG subtype and reading a store at the wrong
    /// stride would corrupt every record it serves. That cross-validation reads a 25-byte MVCC header
    /// out of each slot — and the undo area's records have no MVCC header (`05 §12`): a delta's bytes
    /// 1..25 are its `action`, `type_tag`, `direction`, `command_id` and `commit_info`.
    ///
    /// This test asserts BOTH directions of the fix, which is what makes it non-vacuous:
    ///
    /// 1. a page of well-formed, in-use deltas is ACCEPTED for `StoreKind::Undo` — and the assertion
    ///    below shows it would have been REJECTED by the MVCC-header reading, so the fix is
    ///    load-bearing rather than cosmetic;
    /// 2. a page of deltas is still REJECTED when the subtype claims a *versioned* store, so the
    ///    mis-attribution defence the check exists for is not weakened.
    #[test]
    fn an_undo_page_is_cross_validated_by_its_own_codec_not_the_mvcc_header() {
        use crate::undo::{UndoAction, UndoDelta};

        // A page of live deltas, exactly as `write_undo_area_create` lays them out.
        let mut page = vec![0u8; PAGE_SIZE];
        let rpp = paging::records_per_page(undo::UNDO_RECORD_SIZE);
        for slot in 0..rpp {
            let off = HEADER_SIZE + slot * undo::UNDO_RECORD_SIZE;
            let next = if slot == 0 { 0 } else { slot as u64 };
            UndoDelta::new(UndoAction::DeleteObject, 1, 0, next)
                .encode(&mut page[off..off + undo::UNDO_RECORD_SIZE]);
        }

        // (1) Accepted as what it is.
        assert!(
            Store::orphan_page_records_well_formed(&page, StoreKind::Undo),
            "a page of well-formed deltas must be accepted for `StoreKind::Undo`"
        );

        // …and the MVCC-header reading the check used to apply would have REJECTED it. This is the
        // proof that the codec branch is load-bearing: without it, `open` fails closed on a perfectly
        // good undo page with "mis-attributed page — possible corruption".
        let mut header_check_would_reject = false;
        for slot in 0..rpp {
            let off = HEADER_SIZE + slot * undo::UNDO_RECORD_SIZE;
            let mvcc = MvccHeader::read(&page[off..off + MVCC_HEADER_SIZE]);
            if !mvcc.in_use() {
                continue;
            }
            if VersionStamp::from_raw(mvcc.created_ts) == VersionStamp::None {
                header_check_would_reject = true;
            }
            if let (VersionStamp::Committed(c), VersionStamp::Committed(e)) = (
                VersionStamp::from_raw(mvcc.created_ts),
                VersionStamp::from_raw(mvcc.expired_ts),
            ) && c.0 > e.0
            {
                header_check_would_reject = true;
            }
        }
        assert!(
            header_check_would_reject,
            "NON-VACUITY: the MVCC-header reading must actually reject this page, or the codec \
             branch this test exists to justify would be a no-op"
        );

        // (2) The mis-attribution defence is intact: the same bytes claimed as a versioned store are
        //     still rejected, so a flipped subtype byte cannot smuggle an undo page into the node
        //     store.
        assert!(
            !Store::orphan_page_records_well_formed(&page, StoreKind::Node),
            "delta bytes read at the node stride must still be rejected — that is the check's whole \
             purpose (`rmp` #398)"
        );

        // A zeroed page carries no invariant for either kind (a never-written slot).
        let blank = vec![0u8; PAGE_SIZE];
        assert!(Store::orphan_page_records_well_formed(
            &blank,
            StoreKind::Undo
        ));
        assert!(Store::orphan_page_records_well_formed(
            &blank,
            StoreKind::Commit
        ));
    }

    fn gc_pass(s: &mut Store, txn: u64) -> GcPassReport {
        let wm = s.snapshot_ts();
        s.begin(TxnId(txn));
        let report = s.gc(TxnId(txn), wm).unwrap();
        s.commit(TxnId(txn)).unwrap();
        report
    }

    /// `rmp` #522 (measurement): the incremental freeze sweep visits only the records added since the
    /// previous maintenance pass, so on a monotonically growing store the per-pass cost is O(Δ), not
    /// O(store size). Grows the store in equal stages, runs one GC pass per stage, and asserts each
    /// steady-state pass scans ≈ one stage's worth of ids — a small, bounded FRACTION of the whole
    /// store — rather than the whole store every tick (the pre-#522 O(N²)-in-aggregate behaviour).
    #[test]
    fn gc_freeze_scan_is_incremental_not_quadratic_522() {
        let mut s = fresh();
        const STAGE: u64 = 250;
        const STAGES: u64 = 8;
        let mut next_txn = 1u64;
        let mut scanned_per_pass = Vec::new();

        for stage in 0..STAGES {
            // Create one stage's worth of committed nodes.
            let t = TxnId(next_txn);
            next_txn += 1;
            s.begin(t);
            for _ in 0..STAGE {
                s.create_node(t).unwrap();
            }
            s.commit(t).unwrap();
            // One maintenance GC pass.
            let report = gc_pass(&mut s, next_txn);
            next_txn += 1;
            scanned_per_pass.push(report.freeze_scanned);
            let _ = stage;
        }

        let total_ids = STAGE * STAGES;
        // The first pass is a full scan (freeze frontier starts at id 1). Every steady-state pass after
        // it must scan only ≈ one stage delta, INDEPENDENT of how large the store has grown.
        for (i, &scanned) in scanned_per_pass.iter().enumerate().skip(1) {
            assert!(
                scanned <= 2 * STAGE,
                "pass {i}: freeze_scanned={scanned} must be ≈ a stage delta ({STAGE}), not the whole \
                 {total_ids}-id store — the O(Δ) incremental-GC property"
            );
        }
        // The decisive contrast: the LAST pass, over the FULLEST store, scans a small fraction of it.
        // Pre-#522 every pass re-scanned the whole store, so this would have been ≈ total_ids.
        let last = *scanned_per_pass.last().unwrap();
        assert!(
            last * 4 < total_ids,
            "the final pass scanned {last} of {total_ids} ids — a per-tick cost proportional to the \
             whole store would fail here (that is exactly the reverted O(N²) behaviour)"
        );
    }

    /// `rmp` #522 (equivalence / safety): the incremental GC leaves the store in the SAME state a full
    /// whole-store scan would. After a mixed workload (creates, deletes, aborts) driven through the
    /// incremental sweeps, forcing a FULL-scan GC pass at the same watermark must find NOTHING left to
    /// freeze or reclaim and must not change a single record — proving the incremental sweeps never miss
    /// a freeze (which would silently strand a committed writer) or a reclaimable tombstone.
    #[test]
    fn incremental_gc_equals_full_gc_522() {
        let mut s = fresh();
        let rt = s.intern_token(Namespace::RelType, "R").unwrap();
        let key = s.intern_token(Namespace::PropKey, "v").unwrap();
        let mut next = 1u64;
        let mut nodes = Vec::new();

        // Build a hub + leaves with properties and edges.
        let t = TxnId(next);
        next += 1;
        s.begin(t);
        let (hub, _) = s.create_node(t).unwrap();
        for _ in 0..12 {
            let (n, _) = s.create_node(t).unwrap();
            s.add_node_property(t, n, key, 1, 0x10).unwrap();
            s.create_rel(t, rt, hub, n).unwrap();
            nodes.push(n);
        }
        s.commit(t).unwrap();

        // Delete half the leaves' properties and some edges (creates tombstones), commit.
        let t = TxnId(next);
        next += 1;
        s.begin(t);
        for &n in nodes.iter().step_by(2) {
            s.remove_node_property_value(t, n, key).unwrap();
        }
        s.commit(t).unwrap();

        // Interleaved aborts: create a property + a self-loop on the hub, then roll back (leaves corpses
        // / exercises the pop-reclaim + corpse-registration paths).
        let t = TxnId(next);
        next += 1;
        s.begin(t);
        s.add_node_property(t, hub, key, 1, 0x99).unwrap();
        s.create_rel(t, rt, hub, hub).unwrap();
        s.rollback(t).unwrap();

        // Drive the INCREMENTAL GC to steady state (two passes so watermark-gated reclaims complete).
        gc_pass(&mut s, next);
        next += 1;
        gc_pass(&mut s, next);
        next += 1;

        // Fingerprint the store: every in-use record's (id, xmin, xmax) per kind + the free lists.
        let fingerprint = |s: &mut Store| -> Vec<(u8, u64, u64, u64)> {
            let mut out = Vec::new();
            for kind in [
                StoreKind::Node,
                StoreKind::Rel,
                StoreKind::Prop,
                StoreKind::Strings,
            ] {
                for (id, m) in read_view::scan_in_use_mvcc(&s.pool, &s.stores, kind).unwrap() {
                    out.push((kind as u8, id, m.created_ts, m.expired_ts));
                }
                for &fid in s.store(kind).free.ids() {
                    out.push((kind as u8, fid, u64::MAX, u64::MAX)); // free-list marker
                }
            }
            out.sort_unstable();
            out
        };
        let before = fingerprint(&mut s);

        // Force a FULL-scan GC pass at the SAME watermark: reset the freeze frontier and the full-scan
        // flag (the child test module reaches the private incremental-GC state directly).
        s.freeze_low = [1; STORE_COUNT];
        s.gc_full_scan_pending = true;
        let wm = s.snapshot_ts();
        s.begin(TxnId(next));
        let full = s.gc(TxnId(next), wm).unwrap();
        s.commit(TxnId(next)).unwrap();

        assert_eq!(
            full.frozen, 0,
            "a full scan found unfrozen stamps the incremental sweep missed (a stranded-writer bug)"
        );
        assert_eq!(
            full.reclaimed, 0,
            "a full scan found reclaimable records the incremental sweep missed (a space leak)"
        );
        assert_eq!(
            fingerprint(&mut s),
            before,
            "the forced full GC changed the store — the incremental GC was not equivalent"
        );
        let report = crate::check::check_store(&mut s, &[]).unwrap();
        assert!(
            report.is_consistent(),
            "store consistent after #522 equivalence check: {:?}",
            report.violations
        );
    }

    /// `rmp` #809 (healthy path — the always-on audit is a no-op on a well-formed store, in EVERY build).
    /// A normal mixed workload driven through real `gc()` passes must report zero freeze-frontier
    /// violations and still schedule its prunes: the release-active audit must never fire on legitimately
    /// in-flight or correctly-frozen data (the "does NOT fire in the normal case" half of AC#3).
    #[test]
    fn freeze_frontier_audit_silent_on_healthy_store_809() {
        let mut s = fresh();
        let key = s.intern_token(Namespace::PropKey, "v").unwrap();
        let mut next = 1u64;
        // Several rounds of create + property + a GC pass each; every pass must stay silent.
        for round in 0..4u64 {
            let t = TxnId(next);
            next += 1;
            s.begin(t);
            for _ in 0..30 {
                let (n, _) = s.create_node(t).unwrap();
                s.add_node_property(t, n, key, 1, round + 1).unwrap();
            }
            s.commit(t).unwrap();
            let report = gc_pass(&mut s, next);
            next += 1;
            assert_eq!(
                report.freeze_violations, 0,
                "round {round}: the audit must not fire on a healthy store"
            );
            assert!(
                report.first_freeze_violation.is_none(),
                "round {round}: no violation detail on a clean pass"
            );
        }
    }

    /// `rmp` #809 (non-vacuity — the audit FIRES on an injected stranded stamp, and stays SILENT in the
    /// normal case). This tests the release-active [`audit_freeze_frontier_window`] predicate DIRECTLY
    /// (build-independent: it bypasses the debug-only `debug_assert_freeze_complete`, which would panic
    /// on the same state before the audit ran). It models the exact `rmp` #522 failure: a committed
    /// writer whose on-disk in-flight stamp the incremental freeze sweep never settled because the
    /// frontier was raised past it.
    #[test]
    fn freeze_frontier_audit_fires_on_stranded_committed_stamp_809() {
        let mut s = fresh();

        // A committed node whose xmin is still the writer's in-flight TxnId (headers are frozen lazily at
        // GC, never at commit — see `commit`). So after this the registry says W is Committed while the
        // on-disk stamp is unfrozen: exactly the "committed but unfrozen" condition the audit hunts.
        let w = TxnId(1);
        s.begin(w);
        let (nid, _) = s.create_node(w).unwrap();
        s.commit(w).unwrap();

        // Model the #522 stranding: raise the freeze frontier PAST the node, so the (frontier-bounded)
        // incremental freeze sweep would skip it, leaving the committed stamp unfrozen forever.
        s.freeze_low[StoreKind::Node as usize] = nid + 1;
        // Prove the frontier-bounded sweep really does MISS it (it scans only `[freeze_low, high_water)`).
        let (missed, _) =
            read_view::scan_in_use_mvcc_from(&s.pool, &s.stores, StoreKind::Node, s.freeze_low[0])
                .map(|v| (v.iter().any(|&(id, _)| id == nid), v))
                .unwrap();
        assert!(
            !missed,
            "the frontier-bounded sweep must skip the stranded node — that is what makes it invisible \
             to the incremental freeze (the #522 hole)"
        );

        // The full-range window audit (frontier-agnostic) MUST catch it.
        s.freeze_audit_from = [1; STORE_COUNT];
        let (violations, first) = s.audit_freeze_frontier_window();
        assert!(
            violations >= 1,
            "the release-active audit must detect the stranded committed stamp (got {violations})"
        );
        let v = first.expect("a firing audit reports the offending record");
        assert_eq!(v.kind, StoreKind::Node, "the stranded record is a node");
        assert_eq!(v.id, nid, "the audit names the exact stranded id");
        assert_eq!(
            v.xmin,
            VersionStamp::in_flight(w),
            "the reported xmin is the unfrozen in-flight stamp of the committed writer"
        );

        // Now settle the stamp properly (a real full freeze) and re-audit: it must go SILENT. Reset the
        // frontier so the sweep actually visits the node, then freeze under a fresh GC-style txn.
        s.freeze_low[StoreKind::Node as usize] = 1;
        let g = TxnId(2);
        s.begin(g);
        let (frozen, _) = s
            .freeze_store_headers_incremental(g, StoreKind::Node)
            .unwrap();
        s.commit(g).unwrap();
        assert!(frozen >= 1, "the freeze sweep settled the committed stamp");

        s.freeze_audit_from = [1; STORE_COUNT];
        let (violations_after, first_after) = s.audit_freeze_frontier_window();
        assert_eq!(
            violations_after, 0,
            "after a proper freeze the audit must be SILENT (no stranded stamp remains)"
        );
        assert!(first_after.is_none(), "no violation detail on a clean pass");
    }

    /// `rmp` #809 (fail-closed integration — a firing audit SKIPS the prune, a clean pass prunes normally).
    /// Drives real `gc()` passes end to end. The full-store `debug_assert_freeze_complete` panics on a
    /// stranded stamp *before* the release-active audit runs, so the firing half is exercised only where
    /// that assert is compiled out — an ordinary release build. Run with `cargo test --release`.
    #[test]
    #[cfg_attr(
        any(debug_assertions, feature = "check-cold-assert"),
        ignore = "debug_assert_freeze_complete panics before the release-active audit; run under --release"
    )]
    fn freeze_frontier_audit_skips_prune_fail_closed_809() {
        let mut s = fresh();

        // Healthy pass first: a committed node, a normal gc() → zero violations and the prune IS scheduled.
        let t = TxnId(1);
        s.begin(t);
        let (nid, _) = s.create_node(t).unwrap();
        s.commit(t).unwrap();
        let clean = gc_pass(&mut s, 2);
        assert_eq!(
            clean.freeze_violations, 0,
            "a healthy pass reports no freeze-frontier violation"
        );
        assert!(
            clean.prune_scheduled > 0,
            "a healthy pass schedules the registry prune (a committed writer became forgettable)"
        );

        // Inject a stranding: a second committed node whose stamp we strand by raising the frontier past
        // it, so the next gc()'s frontier-bounded freeze sweep leaves it committed-but-unfrozen.
        let t = TxnId(3);
        s.begin(t);
        let (nid2, _) = s.create_node(t).unwrap();
        s.commit(t).unwrap();
        s.freeze_low[StoreKind::Node as usize] = nid2 + 1;
        // Aim the audit window at the node store so this pass definitely covers the stranded id.
        s.freeze_audit_from = [1; STORE_COUNT];

        let poisoned = gc_pass(&mut s, 4);
        assert!(
            poisoned.freeze_violations >= 1,
            "the release-active audit fires inside gc() on the stranded stamp"
        );
        assert_eq!(
            poisoned.prune_scheduled, 0,
            "fail-closed: a gc() pass that detects a stranded committed stamp SKIPS the prune, so no \
             committed writer is forgotten (the #522 data-loss is prevented)"
        );
        let v = poisoned
            .first_freeze_violation
            .expect("the report carries the offending record for the operator alert");
        assert_eq!((v.kind, v.id), (StoreKind::Node, nid2));
        let _ = nid;
    }

    /// `rmp` #809 (AC#2 measurement, `#[ignore]`d — a reproducible benchmark, not a CI assertion). Prints
    /// the per-GC-pass cost the release-active window audit ADDS, the full-store scan cost it AVOIDS (what
    /// a periodic-tick design would spike to every Nth pass), and a steady-state `gc()` pass cost for
    /// scale — so the "negligible" claim is backed by numbers on the running host. Run with:
    /// `cargo test --release -p graphus-storage -- --ignored --nocapture freeze_audit_window_cost`.
    #[test]
    #[ignore = "measurement/benchmark; run explicitly with --ignored --nocapture"]
    fn freeze_audit_window_cost_is_negligible_809() {
        use std::time::Instant;

        const N: u64 = 200_000;
        // A representative buffer pool (production auto-sizes to hardware — a 64-frame pool would thrash a
        // 200k-record scan through eviction, exaggerating the audit's page-fetch cost). Large enough to
        // hold the node store's pages warm.
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let mut s = RecordStore::create(device, wal, 4096, 1).expect("create store");

        // Build N committed nodes in batches, then a steady-state gc() so everything is frozen and pruned
        // (the realistic state the audit runs against on every subsequent maintenance tick).
        let mut txn = 1u64;
        const BATCH: u64 = 20_000;
        let mut made = 0u64;
        while made < N {
            let t = TxnId(txn);
            txn += 1;
            s.begin(t);
            for _ in 0..BATCH {
                s.create_node(t).unwrap();
            }
            s.commit(t).unwrap();
            made += BATCH;
        }
        gc_pass(&mut s, txn);
        txn += 1;

        // (a) The 3-kind window audit's per-pass added cost at the SHIPPING window size, averaged over
        // many calls (the cursor rotates, so successive calls cover successive windows).
        const ITERS: u32 = 500;
        s.freeze_audit_from = [1; STORE_COUNT];
        let t0 = Instant::now();
        let mut sink = 0u64;
        for _ in 0..ITERS {
            let (v, _) = s.audit_freeze_frontier_window();
            sink = sink.wrapping_add(v);
        }
        let audit_ns = t0.elapsed().as_nanos() / ITERS as u128;

        // (a') The raw window scan+predicate cost for several candidate window sizes on the Node store, to
        // justify the chosen constant (this isolates one kind's window, so multiply by ~3 for a full pass).
        let mut per_w = Vec::new();
        for w in [1024u64, 2048, 4096, 8192] {
            let mut from = 1u64;
            let mut acc = 0u128;
            let reps = 300u32;
            for _ in 0..reps {
                let t = Instant::now();
                let (recs, next) = read_view::scan_in_use_mvcc_window(
                    &s.pool,
                    &s.stores,
                    StoreKind::Node,
                    from,
                    w,
                )
                .unwrap();
                let mut bad = 0u64;
                for (_, mvcc) in &recs {
                    if s.frozen_word(mvcc.created_ts).is_some()
                        || s.frozen_word(mvcc.expired_ts).is_some()
                    {
                        bad += 1;
                    }
                }
                acc += t.elapsed().as_nanos();
                sink = sink.wrapping_add(bad);
                let hw = s.store(StoreKind::Node).alloc.high_water();
                from = if next >= hw { 1 } else { next };
            }
            per_w.push((w, acc / reps as u128));
        }

        // (b) The full-store scan cost (all three MVCC kinds) — the periodic-tick spike the window avoids.
        let t1 = Instant::now();
        let mut fullsink = 0u64;
        for kind in [StoreKind::Node, StoreKind::Rel, StoreKind::Prop] {
            let in_use = read_view::scan_in_use_mvcc(&s.pool, &s.stores, kind).unwrap();
            for &(_, mvcc) in &in_use {
                if s.frozen_word(mvcc.created_ts).is_some()
                    || s.frozen_word(mvcc.expired_ts).is_some()
                {
                    fullsink += 1;
                }
            }
        }
        let full_ns = t1.elapsed().as_nanos();

        // (c) A realistic maintenance operation for scale: a full store checkpoint (flush dirty pages home
        // + WAL reclaim), which is what the background cadence actually runs around each gc() pass.
        let t2 = Instant::now();
        gc_pass(&mut s, txn);
        s.checkpoint().unwrap();
        let ckpt_ns = t2.elapsed().as_nanos();

        println!(
            "rmp #809 freeze-audit cost @ N={N} nodes, pool=4096 frames:\n  \
             3-kind window audit ADDED/pass (W={FREEZE_AUDIT_WINDOW_IDS}) : {audit_ns:>10} ns\n  \
             full-store scan (AVOIDED periodic-tick spike)   : {full_ns:>10} ns\n  \
             gc()+checkpoint (a real maintenance pass)       : {ckpt_ns:>10} ns\n  \
             audit / maintenance pass                        : {:.4}%\n  \
             per-window (Node only) 1024/2048/4096/8192 ns   : {:?}\n  \
             (sink={sink}, full_flagged={fullsink})",
            audit_ns as f64 / ckpt_ns as f64 * 100.0,
            per_w
        );
    }

    /// **Semantic equivalent of** the retired
    /// `gc_reclaims_only_committed_tombstones_below_the_watermark`, which counted cells in the
    /// `first_prop` chain (2 before GC, 1 after) — a count the in-place write path no longer
    /// produces.
    ///
    /// The semantic it protected is the one that matters and is asserted here directly: GC reclaims
    /// an old value **only** once no live or future snapshot can resolve it, and never while the
    /// writing transaction is still open. It is asserted on the structure that now holds the old
    /// value (the undo chain) *and* on the observable answer (what an older snapshot reads), so it
    /// cannot pass by counting the wrong thing.
    #[test]
    fn gc_reclaims_an_old_property_value_only_below_the_watermark() {
        let mut s = fresh();
        let key = s.intern_token(Namespace::PropKey, "v").unwrap();
        let t1 = TxnId(1);
        s.begin(t1);
        let (n, _) = s.create_node(t1).unwrap();
        s.set_node_property_value(t1, n, key, &Value::Integer(1))
            .unwrap();
        s.commit(t1).unwrap();
        let after_v1 = s.snapshot_ts();

        // An IN-FLIGHT write's delta is never reclaimable: GC inside the still-open writing txn
        // leaves the chain alone.
        let t2 = TxnId(2);
        s.begin(t2);
        s.set_node_property_value(t2, n, key, &Value::Integer(2))
            .unwrap();
        let wm = s.snapshot_ts();
        assert_eq!(
            s.gc(t2, wm).unwrap().undo_deltas_reclaimed,
            0,
            "an in-flight write's delta is not reclaimable",
        );
        s.commit(t2).unwrap();

        // Committed, but a snapshot older than the overwrite still exists: still not reclaimable,
        // and that snapshot still reads the exact old value.
        gc_at(&mut s, TxnId(3), after_v1);
        let old_reader = Snapshot {
            owner: TxnId(90),
            ts: after_v1,
        };
        let seen = s
            .decision_scan_node_properties(n, old_reader)
            .unwrap()
            .visible_version(key)
            .expect("the older snapshot still holds the key");
        assert_eq!(
            s.decode_property_value(seen.type_tag, seen.value_inline)
                .unwrap(),
            Value::Integer(1),
        );

        // Once the watermark passes the overwrite, the whole chain goes and the cell stands alone.
        let latest = s.snapshot_ts();
        gc_at(&mut s, TxnId(4), latest);
        let chain = s.superset_scan_node_properties(n).unwrap();
        assert_eq!(chain.history_len(), 0, "the chain is reclaimed");
        assert_eq!(
            chain.len(),
            1,
            "the cell holding the current value survives"
        );
        assert_eq!(
            s.superset_scan_node_property_values(n).unwrap(),
            vec![(chain.cells_ignoring_history()[0].0, key, Value::Integer(2))],
        );
    }

    #[test]
    fn scan_rel_ids_enumerates_live_relationships() {
        let mut s = fresh();
        let txn = TxnId(1);
        s.begin(txn);
        let (a, _) = s.create_node(txn).unwrap();
        let (b, _) = s.create_node(txn).unwrap();
        let (c, _) = s.create_node(txn).unwrap();
        let t = s.intern_token(Namespace::RelType, "LINK").unwrap();
        let (r1, _) = s.create_rel(txn, t, a, b).unwrap();
        let (r2, _) = s.create_rel(txn, t, b, c).unwrap();
        s.commit(txn).unwrap();

        // Both relationships are slot-occupied and enumerated in ascending id order.
        let mut ids = s.scan_rel_ids().unwrap();
        ids.sort_unstable();
        assert_eq!(ids, vec![r1, r2]);

        // A deleted relationship's slot is still occupied (MVCC tombstone) until GC; scan_rel_ids
        // mirrors scan_node_ids in returning slot-occupied ids (visibility is decided above).
        let t2 = TxnId(2);
        s.begin(t2);
        s.delete_rel(t2, r1).unwrap();
        s.commit(t2).unwrap();
        let latest = s.snapshot_ts();
        gc_at(&mut s, TxnId(3), latest);
        // After GC reclaims the tombstone, only the surviving relationship remains.
        assert_eq!(s.scan_rel_ids().unwrap(), vec![r2]);
    }

    // ---- `rmp` #365: page-batched scan primitive equivalence regressions ----
    //
    // The page-batched `scan_node_ids` / `scan_rel_ids` (one pin + read latch per page) MUST return
    // the exact same id set as the original one-latch-per-record loop, across page boundaries, with
    // free-list holes, and after GC. These tests assert that against an independent per-id oracle.

    /// The independent per-id reference oracle: the pre-#365 loop body (`read_node`/`read_rel` per id,
    /// keeping `in_use` slots). Equivalence of the batched scan against this proves the optimisation
    /// preserves the returned id set exactly.
    fn per_id_scan_node_ids(s: &Store) -> Vec<u64> {
        let hw = s.store(StoreKind::Node).alloc.high_water();
        (1..hw)
            .filter(|&id| s.read_node(id).unwrap().mvcc.in_use())
            .collect()
    }

    fn per_id_scan_rel_ids(s: &Store) -> Vec<u64> {
        let hw = s.store(StoreKind::Rel).alloc.high_water();
        (1..hw)
            .filter(|&id| s.read_rel(id).unwrap().mvcc.in_use())
            .collect()
    }

    #[test]
    fn batched_scan_node_ids_equals_per_id_across_page_boundaries() {
        // 125 node records per 8 KiB page (paging::records_per_page(NODE_RECORD_SIZE) == 125): create
        // 300 nodes so the scan crosses three pages and the final page is partially filled.
        let mut s = fresh();
        let txn = TxnId(1);
        s.begin(txn);
        for _ in 0..300 {
            s.create_node(txn).unwrap();
        }
        s.commit(txn).unwrap();

        let batched = s.scan_node_ids().unwrap();
        let oracle = per_id_scan_node_ids(&s);
        assert_eq!(batched, oracle, "batched scan must equal the per-id oracle");
        // Ascending and complete: ids 1..=300, no gaps yet.
        assert_eq!(batched, (1..=300).collect::<Vec<_>>());
    }

    #[test]
    fn batched_scan_node_ids_equals_per_id_with_free_list_holes() {
        // Create across pages, then delete + GC a scattered subset so the physical id space has holes
        // (freed slots that are `!in_use`). The batched scan must skip exactly the freed slots — the
        // same set the per-id oracle skips.
        let mut s = fresh();
        let t1 = TxnId(1);
        s.begin(t1);
        let mut ids = Vec::new();
        for _ in 0..260 {
            ids.push(s.create_node(t1).unwrap().0);
        }
        s.commit(t1).unwrap();

        // Delete a scattered subset spanning all pages (page 0: <125, page 1: 125..250, page 2: >=250).
        let to_delete = [1u64, 7, 64, 124, 125, 130, 200, 249, 250, 259];
        let t2 = TxnId(2);
        s.begin(t2);
        for &id in &to_delete {
            s.delete_node(t2, id).unwrap();
        }
        s.commit(t2).unwrap();
        let latest = s.snapshot_ts();
        gc_at(&mut s, TxnId(3), latest); // reclaim the tombstones → free-list holes

        let batched = s.scan_node_ids().unwrap();
        let oracle = per_id_scan_node_ids(&s);
        assert_eq!(
            batched, oracle,
            "batched scan must equal the per-id oracle with free-list holes"
        );
        for &id in &to_delete {
            assert!(
                !batched.contains(&id),
                "freed slot {id} must not be scanned"
            );
        }
        assert!(batched.len() < 260, "some slots were freed");
    }

    #[test]
    fn batched_scan_rel_ids_equals_per_id_across_pages_and_after_gc() {
        // 80 rel records per page: create 200 rels (spanning three pages), delete + GC a subset.
        let mut s = fresh();
        let txn = TxnId(1);
        s.begin(txn);
        let nodes: Vec<u64> = (0..10).map(|_| s.create_node(txn).unwrap().0).collect();
        let t = s.intern_token(Namespace::RelType, "LINK").unwrap();
        let mut rels = Vec::new();
        for i in 0..200u64 {
            let a = nodes[(i as usize) % nodes.len()];
            let b = nodes[((i + 1) as usize) % nodes.len()];
            rels.push(s.create_rel(txn, t, a, b).unwrap().0);
        }
        s.commit(txn).unwrap();

        assert_eq!(s.scan_rel_ids().unwrap(), per_id_scan_rel_ids(&s));

        let t2 = TxnId(2);
        s.begin(t2);
        for &id in &[rels[0], rels[79], rels[80], rels[159], rels[199]] {
            s.delete_rel(t2, id).unwrap();
        }
        s.commit(t2).unwrap();
        let latest = s.snapshot_ts();
        gc_at(&mut s, TxnId(3), latest);

        let batched = s.scan_rel_ids().unwrap();
        let oracle = per_id_scan_rel_ids(&s);
        assert_eq!(
            batched, oracle,
            "batched rel scan must equal the per-id oracle after GC"
        );
    }

    #[test]
    fn batched_scan_in_use_mvcc_matches_headers_and_in_use_set() {
        // The GC/freeze read primitive (`scan_in_use_mvcc`) must return the MVCC header of every
        // in-use record, ids ascending, and the id subset must equal `scan_node_ids`.
        let mut s = fresh();
        let txn = TxnId(1);
        s.begin(txn);
        for _ in 0..150 {
            s.create_node(txn).unwrap();
        }
        s.commit(txn).unwrap();

        let scanned = read_view::scan_in_use_mvcc(&s.pool, &s.stores, StoreKind::Node).unwrap();
        let ids: Vec<u64> = scanned.iter().map(|&(id, _)| id).collect();
        assert_eq!(ids, s.scan_node_ids().unwrap(), "in-use id sets must match");
        // Ascending.
        assert!(ids.windows(2).all(|w| w[0] < w[1]), "ids must be ascending");
        // Each returned header equals the per-id `read_mvcc` of that id (byte-for-byte struct equal).
        for &(id, mvcc) in &scanned {
            assert_eq!(
                mvcc,
                s.read_mvcc_for_test(StoreKind::Node, id).unwrap(),
                "batched header must equal the per-id read_mvcc for id {id}"
            );
            assert!(
                mvcc.in_use(),
                "scan_in_use_mvcc must only return in-use slots"
            );
        }
    }

    /// Regression (`rmp` #452): the corrupt-cyclic-chain guard in `collect_corpse_runs`
    /// (`2 * high_water + 2`) must be computed with saturating arithmetic so that, near the
    /// `high_water == u64::MAX` ceiling, it saturates to `u64::MAX` rather than WRAPPING to a tiny
    /// value (or `0`) and thereby DEFEATING the very cycle protection it exists to provide. This
    /// reproduces the exact expression at the `2 * self.store(StoreKind::Rel).alloc.high_water() + 2`
    /// guard site and asserts the property at and around the ceiling.
    #[test]
    fn corpse_walk_guard_saturates_to_u64_max_near_ceiling() {
        // The production expression (mirrors the guard site verbatim).
        let guard = |hw: u64| hw.saturating_mul(2).saturating_add(2);
        // What the OLD unchecked `2 * hw + 2` would compute (release: wraps silently).
        let unchecked = |hw: u64| hw.wrapping_mul(2).wrapping_add(2);

        // At the very ceiling: the fixed guard pins at u64::MAX; the unchecked form wraps to 0.
        assert_eq!(
            guard(u64::MAX),
            u64::MAX,
            "guard at high_water == u64::MAX must saturate to u64::MAX, not wrap"
        );
        assert_eq!(
            unchecked(u64::MAX),
            0,
            "the unchecked 2*hw+2 wraps to 0 here — the bug this fixes"
        );

        // Just past the overflow threshold (hw > (u64::MAX - 2)/2): still saturates, never small.
        let threshold = (u64::MAX - 2) / 2; // largest hw for which 2*hw+2 does NOT overflow
        assert_eq!(guard(threshold), u64::MAX - 1); // 2*threshold+2 == u64::MAX-1, no saturation yet
        assert_eq!(guard(threshold + 1), u64::MAX); // one past: fixed guard saturates...
        assert!(
            unchecked(threshold + 1) < 4,
            "...whereas the unchecked form wraps to a tiny value, defeating the cycle guard"
        );

        // In the normal (non-overflowing) regime the guard is the plain arithmetic value — the fix is
        // transparent for every real store.
        assert_eq!(guard(0), 2);
        assert_eq!(guard(125), 252);
        assert_eq!(guard(1_000_000), 2_000_002);

        // And it is strictly positive everywhere, so `steps > guard` can always eventually trip — the
        // walk can never loop forever on a corrupt cycle.
        for hw in [0u64, 1, 2, threshold, threshold + 1, u64::MAX] {
            assert_ne!(
                guard(hw),
                NULL_ID,
                "guard must never be 0 (would disable the bound)"
            );
        }
    }

    /// Regression (`rmp` #452): an `alloc_fresh` at the physical-id ceiling surfaces a clean
    /// `Err(Storage)` all the way out through `create_node`, rather than wrapping to the reserved NULL
    /// id. We force the Node allocator to the ceiling on a real store, then attempt a create.
    #[test]
    fn create_node_at_physical_id_ceiling_errors_not_wraps() {
        let mut s = fresh();
        // Force the Node store's allocator high-water mark to u64::MAX (the corrupt-catalog state the
        // `Meta::decode` bound rejects on open; here we install it directly to prove the allocator
        // itself fails closed even if such a state were ever reached in memory).
        s.store_mut(StoreKind::Node).alloc = PhysicalAllocator::restore(u64::MAX);
        let txn = TxnId(1);
        s.begin(txn);
        let r = s.create_node(txn);
        assert!(
            r.is_err(),
            "create_node must fail closed at the id ceiling, never hand out the wrapped NULL id 0"
        );
        // No record id 0 was minted: the allocator high-water is unchanged (no silent advance).
        assert_eq!(s.store(StoreKind::Node).alloc.high_water(), u64::MAX);
    }

    /// `rmp` #821 (deterministic RED→GREEN for the property-chain `rmp` #811 severance): a reclaimable
    /// tombstone on a **live** owner's chain must keep its `next_prop` forward link after GC frees its
    /// slot, so an off-thread reader (`read_view::collect_prop_chain`) that captured a pointer to it
    /// still threads THROUGH it to the live property below. Pre-fix the reclaim zeroed `next_prop`, so a
    /// reader reading the reclaimed record observed `!in_use` **and** `next_prop == 0` and dropped every
    /// live property beneath the tombstone. This asserts the preserved link directly (no threads), so it
    /// is a hard, timing-free regression guard (RED before the fix — `next_prop` reads back `0`).
    #[test]
    fn gc_property_chain_preserves_reclaimed_tombstone_next_prop_811() {
        let mut s = fresh();
        let ka = s.intern_token(Namespace::PropKey, "a").unwrap();
        let kb = s.intern_token(Namespace::PropKey, "b").unwrap();

        // Chain head B -> A: create A (older, stays live), then B (newer head), both COMMITTED.
        let t0 = TxnId(1);
        s.begin(t0);
        let (node, _) = s.create_node(t0).unwrap();
        let a = s.add_node_property(t0, node, ka, 1, 0xAA).unwrap();
        let b = s.add_node_property(t0, node, kb, 1, 0xBB).unwrap();
        s.commit(t0).unwrap();
        assert_eq!(
            s.property(b).unwrap().next_prop,
            a,
            "precondition: the chain head B links down to the older property A"
        );

        // Delete B: MVCC-tombstones it (xmax committed), leaving the chain B(tomb) -> A(live).
        let t_del = TxnId(2);
        s.begin(t_del);
        assert!(s.remove_node_property_value(t_del, node, kb).unwrap());
        s.commit(t_del).unwrap();

        // GC past B's expiry reclaims the tombstone B and frees its slot.
        let wm = s.snapshot_ts();
        s.begin(TxnId(3));
        s.gc(TxnId(3), wm).unwrap();
        s.commit(TxnId(3)).unwrap();
        assert!(
            s.store(StoreKind::Prop).free.ids().contains(&b),
            "the reclaimed tombstone B is returned to the Prop free list"
        );

        // THE INVARIANT: B's forward link is PRESERVED (RED before the fix: reads back 0), so a reader
        // mid-walk on B still reaches A instead of terminating on a zeroed pointer.
        assert_eq!(
            s.property(b).unwrap().next_prop,
            a,
            "rmp #821/#811: a reclaimed tombstone prop MUST preserve next_prop so an off-thread reader \
             threading through it reaches the live property A below (zeroing it silently drops A)"
        );

        // End-to-end proof: replay `collect_prop_chain`'s exact skip-`!in_use`-then-follow-`next` walk
        // from the STALE captured head B (what a reader holds when GC bridges the owner out from under
        // it) and assert it still threads through to the live property A.
        let mut cur = b;
        let mut steps = 0u64;
        let mut reached_a = false;
        while cur != NULL_ID {
            steps += 1;
            assert!(
                steps <= s.store(StoreKind::Prop).alloc.high_water() + 1,
                "the stale-head walk must terminate within the cycle guard"
            );
            let p = s.property(cur).unwrap();
            let next = p.next_prop;
            if p.mvcc.in_use() && cur == a {
                reached_a = true;
            }
            cur = next;
        }
        assert!(
            reached_a,
            "a reader walking from the stale head B must still thread through to the live property A"
        );

        // No corruption and no leak: the checker stays green, and the owner's LIVE chain is bridged to
        // exactly the live property A (B is unlinked and reclaimed).
        let report = crate::check::check_store(&mut s, &[]).unwrap();
        assert!(
            report.is_consistent(),
            "store consistent after the property-chain GC: {:?}",
            report.violations
        );
        assert_eq!(
            s.superset_scan_node_properties(node)
                .unwrap()
                .cells_ignoring_history()
                .iter()
                .map(|(pid, _)| *pid)
                .collect::<Vec<_>>(),
            vec![a],
            "the owner's live chain is bridged to exactly the live property A"
        );
    }

    /// `rmp` #821 (threaded stress — also closes the GAP-A concurrency-coverage gap of the v0.0.9
    /// storage re-audit): an off-thread reader hammering `superset_scan_node_properties` on a
    /// **live** owner whose chain is `B(tombstone) -> A(live)` must NEVER lose the live property A
    /// while the engine
    /// repeatedly runs a GC pass that reclaims the tombstone B above it. Pre-fix the GC zeroed B's
    /// `next_prop`, and a reader that read the owner's (not-yet-bridged) head B and then read B after
    /// the zero terminated its walk and dropped A. This drives REAL threads over the shared
    /// `Arc<pool>` (the production `rmp` #336 off-thread-reader path — `read_view()` is `Send + Sync`),
    /// so it exercises the exact non-atomic live chain walk vs. in-place GC mutation race.
    #[test]
    fn offthread_reader_never_loses_live_property_across_gc_811() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

        let mut s = fresh();
        let ka = s.intern_token(Namespace::PropKey, "a").unwrap();
        let kb = s.intern_token(Namespace::PropKey, "b").unwrap();

        // Owner with the live property A, then the head property B, both committed. Capture the
        // (`Send + Sync`) read view AFTER both exist so its snapshot high-water covers A and B; the
        // churn below reuses B's freed slot, so no new Prop page ever appears above that snapshot.
        let t0 = TxnId(1);
        s.begin(t0);
        let (node, _) = s.create_node(t0).unwrap();
        let a = s.add_node_property(t0, node, ka, 1, 0xAA).unwrap();
        let _b = s.add_node_property(t0, node, kb, 1, 0xBB).unwrap();
        s.commit(t0).unwrap();

        let view = s.read_view(); // owns Arc clones of the live page cache + live page map: Send + Sync
        let stop = Arc::new(AtomicBool::new(false));
        let losses = Arc::new(AtomicU64::new(0));
        let reads = Arc::new(AtomicU64::new(0));

        let reader = {
            let view = view;
            let stop = Arc::clone(&stop);
            let losses = Arc::clone(&losses);
            let reads = Arc::clone(&reads);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match view.superset_scan_node_properties(node) {
                        // The live property A (pid `a`) is NEVER deleted, so it must be present on every
                        // read: only a severed walk can drop it.
                        Ok(props) => {
                            if !props
                                .cells_ignoring_history()
                                .iter()
                                .any(|(pid, _)| *pid == a)
                            {
                                losses.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        // A live-chain walk must never error either (a torn pointer would surface here).
                        Err(_) => {
                            losses.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    reads.fetch_add(1, Ordering::Relaxed);
                }
            })
        };

        // Churn: each cycle re-tombstones B, GC-reclaims it (the severance window), then re-adds B
        // (reusing the freed slot). Every cycle is a fresh `B(tomb) -> A(live)` reclaim the reader races.
        let cycles = 20_000u64;
        let mut txn = 10u64;
        for _ in 0..cycles {
            s.begin(TxnId(txn));
            s.remove_node_property_value(TxnId(txn), node, kb).unwrap();
            s.commit(TxnId(txn)).unwrap();
            txn += 1;

            let wm = s.snapshot_ts();
            s.begin(TxnId(txn));
            s.gc(TxnId(txn), wm).unwrap();
            s.commit(TxnId(txn)).unwrap();
            txn += 1;

            s.begin(TxnId(txn));
            s.add_node_property(TxnId(txn), node, kb, 1, 0xBB).unwrap();
            s.commit(TxnId(txn)).unwrap();
            txn += 1;
        }

        stop.store(true, Ordering::Relaxed);
        reader.join().expect("reader thread joined");

        assert!(
            reads.load(Ordering::Relaxed) > 0,
            "the reader must have actually run concurrently with the churn"
        );
        assert_eq!(
            losses.load(Ordering::Relaxed),
            0,
            "rmp #821/#811: an off-thread reader lost the live property A while GC reclaimed the \
             tombstone above it (over {} reads)",
            reads.load(Ordering::Relaxed)
        );
    }

    // -------- read-only transactions perform ZERO WAL append + ZERO fdatasync (`rmp` #529) --------

    mod read_only_zero_sync {
        use super::*;
        use graphus_wal::LogSink;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        /// A [`LogSink`] that counts `append` bytes and `sync` calls (each `sync` is exactly one
        /// `fdatasync` of group commit), forwarding every operation to a wrapped [`MemLogSink`]. This
        /// is the in-test counter-probe the task calls for — a `CountingSink`-style stand-in for
        /// `strace`, proving a read-only transaction appends **zero** WAL bytes and issues **zero**
        /// syncs across its whole lifecycle, while a write still issues exactly one.
        struct SyncCountingSink {
            inner: MemLogSink,
            appended: Arc<AtomicU64>,
            syncs: Arc<AtomicU64>,
        }

        impl SyncCountingSink {
            fn new(appended: Arc<AtomicU64>, syncs: Arc<AtomicU64>) -> Self {
                Self {
                    inner: MemLogSink::new(),
                    appended,
                    syncs,
                }
            }
        }

        impl LogSink for SyncCountingSink {
            fn append(&mut self, bytes: &[u8]) {
                self.appended
                    .fetch_add(bytes.len() as u64, Ordering::SeqCst);
                self.inner.append(bytes);
            }
            fn sync(&mut self) -> Result<()> {
                self.syncs.fetch_add(1, Ordering::SeqCst);
                self.inner.sync()
            }
            fn durable_len(&self) -> u64 {
                self.inner.durable_len()
            }
            fn buffered_len(&self) -> u64 {
                self.inner.buffered_len()
            }
            fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
                self.inner.read_durable(from, into)
            }
            fn read_bounded(&self, from: u64, to: u64, into: &mut Vec<u8>) -> Result<()> {
                self.inner.read_bounded(from, to, into)
            }
            fn reclaim(&mut self, from: u64, up_to: u64) -> Result<()> {
                self.inner.reclaim(from, up_to)
            }
            fn reclaimed_floor(&self) -> u64 {
                self.inner.reclaimed_floor()
            }
        }

        type CountingStore = RecordStore<MemBlockDevice, SyncCountingSink>;

        /// A fresh store over a [`SyncCountingSink`], with the automatic-checkpoint cadence disabled so
        /// no maintenance sync can perturb the per-transaction counts. Returns the store and the
        /// `(appended_bytes, syncs)` counters, RESET to zero after `create`'s own initial catalog
        /// harden (so a test measures only the transactions it drives).
        fn fresh_counting() -> (CountingStore, Arc<AtomicU64>, Arc<AtomicU64>) {
            let appended = Arc::new(AtomicU64::new(0));
            let syncs = Arc::new(AtomicU64::new(0));
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(SyncCountingSink::new(
                Arc::clone(&appended),
                Arc::clone(&syncs),
            ))
            .expect("create wal");
            let mut store = RecordStore::create(device, wal, 256, 1).expect("create store");
            store.set_checkpoint_interval_bytes(0);
            appended.store(0, Ordering::SeqCst);
            syncs.store(0, Ordering::SeqCst);
            (store, appended, syncs)
        }

        /// **The `rmp` #529 acceptance proof.** A read-only auto-commit transaction (begin → commit,
        /// no writes) appends ZERO WAL bytes and performs ZERO `fdatasync` across its whole lifecycle,
        /// while an equivalent write transaction performs exactly one group-commit `fdatasync`.
        #[test]
        fn read_only_commit_appends_nothing_and_never_syncs_but_a_write_syncs_once() {
            let (mut s, appended, syncs) = fresh_counting();

            // --- Read-only auto-commit transaction: begin + commit, no writes. ---
            let ro = TxnId(1);
            s.begin(ro);
            s.commit(ro).unwrap();
            assert_eq!(
                appended.load(Ordering::SeqCst),
                0,
                "a read-only transaction must append ZERO WAL bytes (lazy BEGIN + skipped COMMIT)"
            );
            assert_eq!(
                syncs.load(Ordering::SeqCst),
                0,
                "a read-only transaction must perform ZERO fdatasync"
            );

            // --- Write auto-commit transaction: begin + create_node + commit. ---
            appended.store(0, Ordering::SeqCst);
            syncs.store(0, Ordering::SeqCst);
            let w = TxnId(2);
            s.begin(w);
            s.create_node(w).unwrap();
            s.commit(w).unwrap();
            assert!(
                appended.load(Ordering::SeqCst) > 0,
                "a write transaction must append WAL bytes"
            );
            assert_eq!(
                syncs.load(Ordering::SeqCst),
                1,
                "a write transaction must perform exactly one group-commit fdatasync"
            );
        }

        /// A read-only ROLLBACK (an SSI pivot victim is the real-world case) is likewise free: it
        /// appends nothing and never syncs, because a transaction that logged nothing has no undo
        /// chain, no CLRs, and no `ABORT` record.
        #[test]
        fn read_only_rollback_appends_nothing_and_never_syncs() {
            let (mut s, appended, syncs) = fresh_counting();
            let ro = TxnId(1);
            s.begin(ro);
            s.rollback(ro).unwrap();
            assert_eq!(
                appended.load(Ordering::SeqCst),
                0,
                "read-only rollback appends nothing"
            );
            assert_eq!(
                syncs.load(Ordering::SeqCst),
                0,
                "read-only rollback never syncs"
            );
        }

        /// A read-only commit still advances the commit-timestamp oracle (so the coordinator's SSI
        /// `record_commit` sees a fresh, unique timestamp, byte-identical to before #529) — and that
        /// advance is never rolled BACKWARDS by a subsequent transaction's rollback, even though the
        /// read-only bump was never persisted to the catalog. This guards the `reload_catalog`
        /// monotonicity fix: a reissued commit timestamp could collide with one a still-tracked
        /// committed transaction holds.
        #[test]
        fn read_only_commit_advances_the_oracle_monotonically_across_a_later_rollback() {
            let (mut s, _appended, _syncs) = fresh_counting();

            let base = s.snapshot_ts().0;
            // A read-only commit advances the oracle by one.
            let ro = TxnId(1);
            s.begin(ro);
            s.commit(ro).unwrap();
            let after_ro = s.snapshot_ts().0;
            assert_eq!(
                after_ro,
                base + 1,
                "a read-only commit advances the commit-ts oracle"
            );

            // A later transaction that rolls back must NOT lower the oracle below the read-only bump —
            // even though that bump was never made durable (the persisted catalog high-water lags it).
            let w = TxnId(2);
            s.begin(w);
            s.create_node(w).unwrap();
            s.rollback(w).unwrap();
            assert!(
                s.snapshot_ts().0 >= after_ro,
                "reload_catalog on rollback must never roll the commit-ts oracle backwards \
                 (was {after_ro}, now {})",
                s.snapshot_ts().0
            );
        }

        /// **The `rmp` #528 group-commit acceptance proof (store layer).** `K` write transactions
        /// PREPAREd (`commit_prepare`, no `fdatasync`) and then hardened by a SINGLE `harden_wal`
        /// perform exactly ONE group-commit `fdatasync`, not `K` — while every one of them is
        /// committed-durable afterwards. This is the storage-layer half of the cross-transaction
        /// group-commit (`§4.2`); the engine layer wires the batch drain that feeds it.
        #[test]
        fn group_commit_prepares_k_writes_then_one_harden_issues_one_fdatasync() {
            let (mut s, appended, syncs) = fresh_counting();

            const K: u64 = 16;
            // PREPARE K write transactions: each appends a data record + a COMMIT record, but NO sync.
            for i in 1..=K {
                let txn = TxnId(i);
                s.begin(txn);
                s.create_node(txn).unwrap();
                let lsn = s.commit_prepare(txn).unwrap();
                assert!(
                    lsn.is_some(),
                    "a write commit_prepare must append a durable COMMIT record"
                );
            }
            assert!(
                appended.load(Ordering::SeqCst) > 0,
                "the batch appended WAL bytes (K data + K commit records)"
            );
            assert_eq!(
                syncs.load(Ordering::SeqCst),
                0,
                "PREPARE issues ZERO fdatasyncs — all {K} commits sit un-synced in the WAL buffer"
            );

            // HARDEN the whole batch with ONE fdatasync.
            s.harden_wal();
            assert_eq!(
                syncs.load(Ordering::SeqCst),
                1,
                "the whole batch of {K} committers is hardened by exactly ONE group-commit fdatasync"
            );

            // Every prepared commit is now committed-visible and durable: the snapshot oracle advanced
            // to the last commit timestamp, and the WAL holds K committed transactions.
            assert_eq!(
                s.snapshot_ts().0,
                K,
                "the commit-ts oracle advanced once per batched commit"
            );
            let committed: std::collections::BTreeSet<u64> = s
                .with_wal(|w| w.committed_transactions().unwrap())
                .into_iter()
                .map(|(t, _, _)| t.0)
                .collect();
            for i in 1..=K {
                assert!(
                    committed.contains(&i),
                    "batched write commit txn {i} must be durable after the single fdatasync \
                     (committed set: {committed:?})"
                );
            }

            // A subsequent isolated single commit still hardens exactly once (no regression).
            syncs.store(0, Ordering::SeqCst);
            let solo = TxnId(K + 1);
            s.begin(solo);
            s.create_node(solo).unwrap();
            s.commit(solo).unwrap();
            assert_eq!(
                syncs.load(Ordering::SeqCst),
                1,
                "an isolated commit still performs exactly one fdatasync"
            );
        }
    }
}
