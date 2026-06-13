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

use std::collections::HashMap;

use graphus_bufpool::BufferPool;
use graphus_bufpool::page::{self, HEADER_SIZE};
use graphus_core::error::{GraphusError, Result};
use graphus_core::{ElementId, MAX_TIMESTAMP, PageId, Timestamp, TxnId, VersionStamp};
use graphus_io::{BlockDevice, PAGE_SIZE};
use graphus_txn::{CommitRegistry, TxnOutcome};
use graphus_wal::{LogSink, WalManager};

use crate::heap::{self, BLOCK_PAYLOAD, HeapBlock, STRINGS_RECORD_SIZE};
use crate::idalloc::{ElementIdAllocator, FreeList, NULL_ID, PhysicalAllocator};
use crate::labels;
use crate::meta::{
    ConstraintEntry, FulltextIndexEntry, IndexState, Meta, SpatialIndexEntry, Statistics, StoreMeta,
};
use crate::paging;
use crate::record::{
    CHAIN_FLAG_END_FIRST, CHAIN_FLAG_START_FIRST, ChainSide, MVCC_HEADER_SIZE, MVCC_OFF_CREATED_TS,
    MVCC_OFF_EXPIRED_TS, MvccHeader, NODE_RECORD_SIZE, NodeRecord, PROP_RECORD_SIZE, PropRecord,
    REL_RECORD_SIZE, RelRecord,
};
use crate::tokens::{Namespace, TokenStore};
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

/// Reserved system transaction id for standalone catalog writes (`04 §2.6`): a token/catalog
/// change that must be durable on its own (e.g. at `create`) uses this transaction.
const SYSTEM_TXN: TxnId = TxnId(u64::MAX);

/// Page-type byte for a record-store page (`05 §6`: low byte = type, high bytes = flags).
const PAGE_TYPE_RECORD: u8 = 1;
/// Page-type byte for the metadata page.
const PAGE_TYPE_META: u8 = 5;

/// The number of fixed-record stores backed by the catalog (`nodes`, `rels`, `props`, and the
/// `strings.store` overflow heap, `04 §2.1`). Indexed by [`StoreKind`] `as usize`.
pub const STORE_COUNT: usize = 4;

/// Which of the fixed-record stores a record id belongs to (`04 §2.1`).
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
}

impl StoreKind {
    /// The fixed record size of this store in bytes.
    #[must_use]
    pub fn record_size(self) -> usize {
        match self {
            StoreKind::Node => NODE_RECORD_SIZE,
            StoreKind::Rel => REL_RECORD_SIZE,
            StoreKind::Prop => PROP_RECORD_SIZE,
            StoreKind::Strings => crate::heap::STRINGS_RECORD_SIZE,
        }
    }
}

/// In-memory handle to one fixed-record store: its kind, id allocator, free list, and the
/// store-relative-page → device-`PageId` map.
struct FixedStore {
    kind: StoreKind,
    alloc: PhysicalAllocator,
    free: FreeList,
    device_pages: Vec<PageId>,
}

impl FixedStore {
    fn from_meta(kind: StoreKind, m: &StoreMeta) -> Self {
        Self {
            kind,
            alloc: PhysicalAllocator::restore(m.high_water.max(1)),
            free: m.free_list.clone(),
            device_pages: m.device_pages.iter().copied().map(PageId).collect(),
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
#[derive(Debug, Default, Clone)]
struct ActiveTxn {
    created: Vec<(StoreKind, u64)>,
    expired: Vec<(StoreKind, u64)>,
}

/// What one [`RecordStore::gc`] pass did (observability, NFR-10; `rmp` task #59).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GcPassReport {
    /// Physical record versions reclaimed (slots freed, `04 §5.5`).
    pub reclaimed: usize,
    /// MVCC header words (`xmin`/`xmax`) frozen from a committed writer's in-flight `TxnId` to its
    /// `Committed(ts)` stamp (`rmp` task #59), making those versions self-describing.
    pub frozen: usize,
    /// Committed writers scheduled to be forgotten from the Active/Recent Transaction Table when
    /// the GC transaction commits (a mid-pass rollback discards the schedule and prunes nothing).
    pub prune_scheduled: usize,
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

/// A record store with index-free adjacency, over a buffer pool and the ARIES WAL.
///
/// `RecordStore` is generic over the block device `D` and the WAL log sink `S` so it runs over
/// the production file device + file log and over the in-memory DST device + log used by the
/// crash-recovery tests (`04 §11`).
pub struct RecordStore<D: BlockDevice, S: LogSink> {
    pool: BufferPool<D, SharedWal<S>>,
    wal: SharedWal<S>,
    element_ids: ElementIdAllocator,
    tokens: TokenStore,
    stores: [FixedStore; STORE_COUNT],
    /// The largest MVCC commit timestamp issued so far (`04 §5.2`); persisted in [`Meta`] so it
    /// resumes monotonically after reopen. The next commit timestamp is `commit_ts_hw + 1`, and a
    /// fresh reader's snapshot timestamp is `commit_ts_hw` (it sees exactly what has committed).
    commit_ts_hw: u64,
    /// Per-open-transaction version-stamp bookkeeping, consumed at [`commit`](Self::commit) to
    /// settle in-flight headers to the commit timestamp (`04 §5.2`).
    active: HashMap<TxnId, ActiveTxn>,
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
    /// The registry prune the last completed [`gc`](Self::gc) freeze sweep scheduled, applied at
    /// the GC transaction's [`commit`](Self::commit) and discarded at its
    /// [`rollback`](Self::rollback) (`rmp` task #59). `None` while no GC pass is pending.
    pending_gc_prune: Option<PendingGcPrune>,
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
    /// The WAL `durable_len` captured at the last checkpoint (or at open); the automatic cadence
    /// fires when `durable_len - this >= checkpoint_interval_bytes`.
    wal_len_at_last_checkpoint: u64,
}

/// Default automatic-checkpoint cadence: take a checkpoint every ~64 MiB of appended WAL. Chosen to
/// bound crash-recovery redo work while keeping the checkpoint's flush amortised under steady load;
/// tunable per store via [`RecordStore::set_checkpoint_interval_bytes`].
pub const DEFAULT_CHECKPOINT_INTERVAL_BYTES: u64 = 64 * 1024 * 1024;

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
        let pool = BufferPool::with_wal(device, shared.clone(), pool_capacity);
        let mut store = Self {
            pool,
            wal: shared,
            element_ids: ElementIdAllocator::new(element_id_seed.max(1)),
            tokens: TokenStore::new(),
            stores: [
                FixedStore::from_meta(StoreKind::Node, &StoreMeta::default()),
                FixedStore::from_meta(StoreKind::Rel, &StoreMeta::default()),
                FixedStore::from_meta(StoreKind::Prop, &StoreMeta::default()),
                FixedStore::from_meta(StoreKind::Strings, &StoreMeta::default()),
            ],
            commit_ts_hw: 0,
            active: HashMap::new(),
            meta_chain: Vec::new(),
            commit_registry: CommitRegistry::new(),
            pending_gc_prune: None,
            statistics: Statistics::new(),
            checkpoint_interval_bytes: DEFAULT_CHECKPOINT_INTERVAL_BYTES,
            wal_len_at_last_checkpoint: 0,
        };
        store.init_meta_page()?;
        store.checkpoint_meta(SYSTEM_TXN, true)?;
        store.flush()?;
        store.wal_len_at_last_checkpoint = store.wal.with(|w| w.durable_len());
        Ok(store)
    }

    /// Reopens an existing record store (after [`crate::recovery::recover_device`] has replayed the WAL
    /// onto the device), rebuilding the in-memory catalog from the durable metadata page.
    ///
    /// # Errors
    /// Returns a storage error if the metadata page is missing or malformed.
    pub fn open(device: D, wal: WalManager<S>, pool_capacity: usize) -> Result<Self> {
        let shared = SharedWal::new(wal);
        let mut pool = BufferPool::with_wal(device, shared.clone(), pool_capacity);
        let (meta, meta_chain) = Self::read_meta(&mut pool)?;
        // Rebuild the Active/Recent Transaction Table from the WAL's commit records (`rmp` task #49):
        // with lazy GC-time freezing a committed version may still carry its writer's in-flight
        // `TxnId` on disk, so visibility/reclamation must resolve that id to the commit timestamp the
        // commit record durably holds. The scan is robust to checkpoint truncation (the timestamp
        // lives in each commit record, not derived from log position). Writers a pre-crash GC pass
        // had already frozen and pruned (`rmp` task #59) reappear here; that is harmless — no header
        // references them, so the entries are never consulted and the next GC pass prunes them again.
        let mut commit_registry = CommitRegistry::new();
        for (committed_txn, ts) in shared.with(|w| w.committed_transactions())? {
            commit_registry.record_commit(committed_txn, ts);
        }
        let stores = [
            FixedStore::from_meta(StoreKind::Node, &meta.stores[0]),
            FixedStore::from_meta(StoreKind::Rel, &meta.stores[1]),
            FixedStore::from_meta(StoreKind::Prop, &meta.stores[2]),
            FixedStore::from_meta(StoreKind::Strings, &meta.stores[3]),
        ];
        let shared_len = shared.with(|w| w.durable_len());
        Ok(Self {
            pool,
            wal: shared,
            element_ids: ElementIdAllocator::new(meta.element_id_next.max(1)),
            tokens: meta.tokens,
            stores,
            commit_ts_hw: meta.commit_ts_hw,
            active: HashMap::new(),
            meta_chain,
            commit_registry,
            pending_gc_prune: None,
            statistics: meta.statistics,
            checkpoint_interval_bytes: DEFAULT_CHECKPOINT_INTERVAL_BYTES,
            wal_len_at_last_checkpoint: shared_len,
        })
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

    fn snapshot_meta(&self) -> Meta {
        Meta {
            element_id_next: self.element_ids.peek(),
            commit_ts_hw: self.commit_ts_hw,
            stores: [
                self.stores[0].to_meta(),
                self.stores[1].to_meta(),
                self.stores[2].to_meta(),
                self.stores[3].to_meta(),
            ],
            tokens: self.tokens.clone(),
            // Clones the whole `Statistics` (counts *and* the `rmp` task #81 property-histogram map):
            // the histogram blobs ride the same checkpoint-at-commit path as the counts with no
            // special-casing — `Statistics` is cloned structurally.
            statistics: self.statistics.clone(),
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
        let p = self.pool.page_mut(f);
        page::set_page_type(p, PAGE_TYPE_META);
        page::set_page_id(p, META_PAGE.0);
        self.pool.flush(f)?; // valid checksum on disk before any fetch verifies it
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
    fn read_meta(pool: &mut BufferPool<D, SharedWal<S>>) -> Result<(Meta, Vec<PageId>)> {
        let mut payload = Vec::new();
        let mut chain = Vec::new();
        let mut page = META_PAGE;
        loop {
            let f = pool.fetch(page)?;
            let p = pool.page(f);
            let chunk_len = u32::from_le_bytes(
                p[HEADER_SIZE..HEADER_SIZE + 4]
                    .try_into()
                    .expect("4-byte slice"),
            ) as usize;
            let next = u64::from_le_bytes(
                p[HEADER_SIZE + 4..HEADER_SIZE + 12]
                    .try_into()
                    .expect("8-byte slice"),
            );
            let start = HEADER_SIZE + 12;
            if start + chunk_len > p.len() {
                pool.unpin(f);
                return Err(GraphusError::Storage(
                    "metadata chunk runs past the page".to_owned(),
                ));
            }
            payload.extend_from_slice(&p[start..start + chunk_len]);
            pool.unpin(f);
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

    /// Persists the in-memory catalog to the metadata page as one WAL-logged update under `txn`.
    /// When `commit` is set, `txn` is begun and committed around the write (standalone catalog
    /// change, `04 §2.6`); otherwise the write joins the caller's open `txn`.
    fn checkpoint_meta(&mut self, txn: TxnId, commit: bool) -> Result<()> {
        let meta = self.snapshot_meta();
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
            let p = self.pool.page_mut(f);
            page::set_page_type(p, PAGE_TYPE_META);
            page::set_page_id(p, dev_page.0);
            self.pool.flush(f)?;
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
            framed.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
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
    /// device, initialising a record-page header, recording the mapping) as needed.
    fn ensure_store_page(&mut self, kind: StoreKind, rel_page: u64) -> Result<PageId> {
        let rel_page = rel_page as usize;
        while self.store(kind).device_pages.len() <= rel_page {
            let (f, dev_page) = self.pool.new_page()?;
            let p = self.pool.page_mut(f);
            page::set_page_type(p, PAGE_TYPE_RECORD);
            page::set_page_id(p, dev_page.0);
            self.pool.flush(f)?; // header durable; the record writes that follow are WAL-logged
            self.pool.unpin(f);
            self.store_mut(kind).device_pages.push(dev_page);
        }
        Ok(self.store(kind).device_pages[rel_page])
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
        let pre = self.pool.page(f)[offset..end].to_vec();
        let redo = paging::encode_patch(offset, bytes);
        let undo = paging::encode_patch(offset, &pre);
        let lsn = self.wal.with(|w| w.log_update(txn, page, redo, undo));
        let p = self.pool.page_mut(f);
        p[offset..end].copy_from_slice(bytes);
        page::set_page_lsn(p, lsn);
        self.pool.unpin(f);
        Ok(())
    }

    fn write_record(&mut self, kind: StoreKind, id: u64, buf: &[u8], txn: TxnId) -> Result<()> {
        let (rel_page, offset) = paging::record_location(id, kind.record_size());
        let dev_page = self.ensure_store_page(kind, rel_page)?;
        self.write_region(dev_page, offset, buf, txn)
    }

    fn device_page(&self, kind: StoreKind, rel_page: u64) -> Result<PageId> {
        self.store(kind)
            .device_pages
            .get(rel_page as usize)
            .copied()
            .ok_or_else(|| {
                GraphusError::Storage(format!("{kind:?} store page {rel_page} not allocated"))
            })
    }

    // ----------------------------- record I/O ------------------------------

    fn alloc_id(&mut self, kind: StoreKind) -> u64 {
        let s = self.store_mut(kind);
        s.free.pop().unwrap_or_else(|| s.alloc.alloc_fresh())
    }

    fn read_node(&mut self, id: u64) -> Result<NodeRecord> {
        let (rel_page, off) = paging::record_location(id, NODE_RECORD_SIZE);
        let dev = self.device_page(StoreKind::Node, rel_page)?;
        let f = self.pool.fetch(dev)?;
        let rec = NodeRecord::decode(&self.pool.page(f)[off..off + NODE_RECORD_SIZE]);
        self.pool.unpin(f);
        Ok(rec)
    }

    fn read_rel(&mut self, id: u64) -> Result<RelRecord> {
        let (rel_page, off) = paging::record_location(id, REL_RECORD_SIZE);
        let dev = self.device_page(StoreKind::Rel, rel_page)?;
        let f = self.pool.fetch(dev)?;
        let rec = RelRecord::decode(&self.pool.page(f)[off..off + REL_RECORD_SIZE]);
        self.pool.unpin(f);
        Ok(rec)
    }

    fn read_prop(&mut self, id: u64) -> Result<PropRecord> {
        let (rel_page, off) = paging::record_location(id, PROP_RECORD_SIZE);
        let dev = self.device_page(StoreKind::Prop, rel_page)?;
        let f = self.pool.fetch(dev)?;
        let rec = PropRecord::decode(&self.pool.page(f)[off..off + PROP_RECORD_SIZE]);
        self.pool.unpin(f);
        Ok(rec)
    }

    fn read_block(&mut self, id: u64) -> Result<HeapBlock> {
        let (rel_page, off) = paging::record_location(id, STRINGS_RECORD_SIZE);
        let dev = self.device_page(StoreKind::Strings, rel_page)?;
        let f = self.pool.fetch(dev)?;
        let rec = HeapBlock::decode(&self.pool.page(f)[off..off + STRINGS_RECORD_SIZE]);
        self.pool.unpin(f);
        Ok(rec)
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

    /// Begins transaction `txn` in the WAL and opens its MVCC version-stamp bookkeeping.
    pub fn begin(&mut self, txn: TxnId) {
        self.wal.with(|w| {
            w.begin(txn);
        });
        self.active.insert(txn, ActiveTxn::default());
    }

    /// The current MVCC read snapshot timestamp (`04 §5.2`): the largest commit timestamp issued so
    /// far, so a reader that begins now sees exactly every transaction that has already committed
    /// and nothing committed later. A fresh store (no commits yet) returns `Timestamp(0)`.
    #[must_use]
    pub fn snapshot_ts(&self) -> Timestamp {
        Timestamp(self.commit_ts_hw)
    }

    /// Commits `txn`: persists the catalog under `txn`, then group-commits the WAL so all of
    /// `txn`'s work (records, catalog growth, token creation) is durable (`04 §4.2`).
    ///
    /// # Errors
    /// Returns a storage error if the catalog cannot be persisted or `txn` is not active.
    ///
    /// # Panics
    /// Panics if the commit `fdatasync` fails (`04 §4.9`).
    pub fn commit(&mut self, txn: TxnId) -> Result<()> {
        // Assign this transaction's commit timestamp (`04 §5.2`). **Lazy GC-time freezing**
        // (`04 §5.5`, hint-bit style, `rmp` task #49): do NOT settle each version's header from the
        // in-flight `TxnId` to the commit timestamp here — that was O(records touched) WAL-logged
        // header writes (the eager, correctness-first path of task #45). Instead record the outcome
        // in the Active/Recent Transaction Table; a reader resolves an in-flight stamp to its commit
        // timestamp through that table ([`is_reclaimable`](Self::is_reclaimable) and the cypher
        // visibility layer via [`commit_registry`](Self::commit_registry)); the GC-time header
        // freeze (`rmp` task #59) later settles the stamps and prunes the entries, bounding the
        // table. What makes a committed insert/delete survive a crash is now the WAL commit record
        // carrying `commit_ts` (`commit_at`): recovery rebuilds the table from it
        // ([`open`](Self::open)). Commit is now O(1) in header writes.
        let commit_ts = self.next_commit_ts();
        // Drop the per-txn created/expired bookkeeping (it fed the old eager settle loop; the table
        // entry below is all the durable/visible state a committed version now needs).
        self.active.remove(&txn);
        self.commit_registry.record_commit(txn, commit_ts);
        self.checkpoint_meta(txn, false)?;
        self.wal.with(|w| w.commit_at(txn, commit_ts))?;
        // If `txn` was a GC pass, its header freeze is durable from here on (`rmp` task #59): every
        // writer the pass scheduled is no longer referenced by any on-disk in-flight stamp, so the
        // Active/Recent Transaction Table entries can be forgotten — this, after the freeze, is what
        // bounds the table. Pruning strictly AFTER the commit hardens means a crash or rollback
        // before this point leaves the table intact for the restored in-flight stamps.
        if self
            .pending_gc_prune
            .as_ref()
            .is_some_and(|p| p.gc_txn == txn)
        {
            let pending = self.pending_gc_prune.take().expect("checked Some above");
            for writer in pending.writers {
                self.commit_registry.forget(writer);
            }
        }
        // Bound crash-recovery redo: take a checkpoint once enough WAL has accumulated since the last
        // one (`rmp` storage audit F3). The commit above is already durable, so a checkpoint here only
        // adds a flush + marker — never affecting this transaction's durability.
        self.maybe_checkpoint()?;
        Ok(())
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
        // enforced per page inside `flush_all`), then mark the clean point in the log.
        self.pool.flush_all()?;
        self.wal.with(|w| w.checkpoint(&[]));
        self.wal_len_at_last_checkpoint = self.wal.with(|w| w.durable_len());
        Ok(())
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

    /// Records that `txn` version-stamped (created) record `id` in `kind`'s store, so `commit` can
    /// settle its `xmin`. A no-op for the reserved system transaction, which never creates records.
    fn note_created(&mut self, txn: TxnId, kind: StoreKind, id: u64) {
        if txn != SYSTEM_TXN {
            self.active.entry(txn).or_default().created.push((kind, id));
        }
    }

    /// Records that `txn` tombstoned (expired) record `id` in `kind`'s store, so `commit` can settle
    /// its `xmax`.
    fn note_expired(&mut self, txn: TxnId, kind: StoreKind, id: u64) {
        if txn != SYSTEM_TXN {
            self.active.entry(txn).or_default().expired.push((kind, id));
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
        let mut reclaimed = 0usize;

        let rel_hw = self.store(StoreKind::Rel).alloc.high_water();
        for id in 1..rel_hw {
            let mvcc = self.read_rel(id)?.mvcc;
            if Self::is_reclaimable(mvcc, watermark, &self.commit_registry) {
                self.reclaim_rel(txn, id)?;
                reclaimed += 1;
            }
        }

        let node_hw = self.store(StoreKind::Node).alloc.high_water();
        for id in 1..node_hw {
            let mvcc = self.read_node(id)?.mvcc;
            if Self::is_reclaimable(mvcc, watermark, &self.commit_registry)
                && self.incident_rels(id)?.is_empty()
            {
                self.reclaim_node(txn, id)?;
                reclaimed += 1;
            }
        }

        // Sweep the property chains of the owners that survived the node/rel reclamation above. A
        // reclaimed owner's whole chain was already freed by its reclamation, so re-checking
        // liveness here (after the sweeps) keeps each chain reclaimed exactly once.
        for id in 1..node_hw {
            if Self::is_live_version(self.read_node(id)?.mvcc) {
                reclaimed += self.gc_property_chain(txn, StoreKind::Node, id, watermark)?;
            }
        }
        for id in 1..rel_hw {
            if Self::is_live_version(self.read_rel(id)?.mvcc) {
                reclaimed += self.gc_property_chain(txn, StoreKind::Rel, id, watermark)?;
            }
        }

        // Freeze sweep (`rmp` task #59): settle every surviving committed in-flight stamp across
        // all three MVCC record stores (the `strings.store` heap blocks carry no version stamps —
        // they are never visibility-checked). Runs after the reclamation sweeps so reclaimed slots
        // (no longer `in_use`) are skipped, and over the full id ranges so even records the
        // reclamation sweeps could not reach (e.g. the property chain of a tombstoned-but-retained
        // owner) are frozen.
        let mut frozen = 0usize;
        frozen += self.freeze_store_headers(txn, StoreKind::Rel)?;
        frozen += self.freeze_store_headers(txn, StoreKind::Node)?;
        frozen += self.freeze_store_headers(txn, StoreKind::Prop)?;

        // Schedule the table prune: every writer recorded as committed at this point had ALL of its
        // on-disk in-flight stamps rewritten by the sweep above (it covered every in-use record), so
        // each becomes forgettable the moment the freeze is durable — i.e. when `txn` commits. The
        // GC transaction itself, and any transaction that commits between here and that commit, is
        // not in this set and is pruned by a later pass.
        let writers = self.commit_registry.committed_writers();
        let prune_scheduled = writers.len();
        self.pending_gc_prune = Some(PendingGcPrune {
            gc_txn: txn,
            writers,
        });

        Ok(GcPassReport {
            reclaimed,
            frozen,
            prune_scheduled,
        })
    }

    /// Reads just the 25-byte MVCC header of record `id` in `kind`'s store (freeze-sweep helper —
    /// avoids decoding the full record when only the header words matter).
    fn read_mvcc(&mut self, kind: StoreKind, id: u64) -> Result<MvccHeader> {
        let (rel_page, off) = paging::record_location(id, kind.record_size());
        let dev = self.device_page(kind, rel_page)?;
        let f = self.pool.fetch(dev)?;
        let mvcc = MvccHeader::read(&self.pool.page(f)[off..off + MVCC_HEADER_SIZE]);
        self.pool.unpin(f);
        Ok(mvcc)
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

    /// Freezes the MVCC headers of every in-use record in `kind`'s store (`rmp` task #59): each
    /// `xmin`/`xmax` word carrying a committed writer's in-flight `TxnId` is rewritten to its
    /// `Committed(ts)` form via the same WAL-logged 8-byte header patch as a tombstone or the old
    /// eager commit settle ([`patch_header_word`](Self::patch_header_word)), under the GC `txn`.
    /// Walks the full physical-id range `1..high_water`, so the sweep is complete regardless of
    /// chain reachability. Returns the number of header words frozen.
    fn freeze_store_headers(&mut self, txn: TxnId, kind: StoreKind) -> Result<usize> {
        let high_water = self.store(kind).alloc.high_water();
        let mut frozen = 0usize;
        for id in 1..high_water {
            let mvcc = self.read_mvcc(kind, id)?;
            if !mvcc.in_use() {
                continue; // freed slot (or reclaimed earlier this pass): no stamps to freeze
            }
            if let Some(word) = self.frozen_word(mvcc.created_ts) {
                self.patch_header_word(kind, id, MVCC_OFF_CREATED_TS, word, txn)?;
                frozen += 1;
            }
            if let Some(word) = self.frozen_word(mvcc.expired_ts) {
                self.patch_header_word(kind, id, MVCC_OFF_EXPIRED_TS, word, txn)?;
                frozen += 1;
            }
        }
        Ok(frozen)
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
    /// # Errors
    /// Returns a storage error if undo apply fails or the catalog cannot be reloaded.
    ///
    /// # Panics
    /// Panics if the WAL `fdatasync` fails (`04 §4.9`).
    pub fn rollback(&mut self, txn: TxnId) -> Result<()> {
        // Drop the version-stamp bookkeeping: every stamp this txn wrote (in-flight `xmin`/`xmax`)
        // is reverted by the WAL undo below, and the commit timestamp was never issued (only
        // `commit` advances it), so nothing of this txn remains visible or durable.
        self.active.remove(&txn);
        // If `txn` was a GC pass, discard its scheduled registry prune (`rmp` task #59): the WAL
        // undo below restores the in-flight header stamps the freeze had rewritten, and those
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
        let device_pages: [Vec<PageId>; STORE_COUNT] = [
            self.stores[0].device_pages.clone(),
            self.stores[1].device_pages.clone(),
            self.stores[2].device_pages.clone(),
            self.stores[3].device_pages.clone(),
        ];
        let mut target = pool_target::PoolTarget::new(&mut self.pool);
        self.wal.with(|w| w.rollback(txn, &mut target))?;
        self.reload_catalog()?;
        // Page growth is not undone; restore the in-memory page maps that the catalog reload (from
        // the pre-growth metadata) shrank, so already-allocated device pages stay addressable.
        for (i, pages) in device_pages.into_iter().enumerate() {
            if pages.len() > self.stores[i].device_pages.len() {
                self.stores[i].device_pages = pages;
            }
        }
        Ok(())
    }

    /// Rebuilds the in-memory catalog from the durable metadata page.
    fn reload_catalog(&mut self) -> Result<()> {
        let (meta, meta_chain) = Self::read_meta(&mut self.pool)?;
        self.element_ids = ElementIdAllocator::new(meta.element_id_next.max(1));
        self.commit_ts_hw = meta.commit_ts_hw;
        for (i, sm) in meta.stores.iter().enumerate() {
            let kind = self.stores[i].kind;
            self.stores[i] = FixedStore::from_meta(kind, sm);
        }
        self.tokens = meta.tokens;
        // Restore the live-record cardinalities from the durable catalog (`rmp` task #79): on
        // rollback this discards the aborting transaction's in-memory increments/decrements (it never
        // checkpointed them), exactly as the id high-water / free-list restore above does, so a
        // rolled-back create/delete/label-change leaves the counts at their last committed values. The
        // `rmp` task #81 property-histogram map is a field of `Statistics`, so this same assignment
        // discards a rolled-back `set_property_histogram`/`remove_property_histogram` too.
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
        let (id, _created) = self.tokens.intern(ns, name)?;
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

    // ------------------------------- node CRUD ------------------------------

    /// Creates a node under `txn`, allocating a fresh physical id and a never-reused
    /// [`ElementId`]; returns `(physical_id, element_id)`.
    ///
    /// # Errors
    /// Returns a storage error if the write fails.
    pub fn create_node(&mut self, txn: TxnId) -> Result<(u64, ElementId)> {
        let id = self.alloc_id(StoreKind::Node);
        let eid = self.element_ids.alloc();
        // Stamp `xmin` with the writer's in-flight `TxnId` (`04 §5.2`); `commit` settles it to the
        // commit timestamp. Until then the version is visible only to its own transaction.
        let rec = NodeRecord::new(eid, VersionStamp::in_flight(txn));
        self.write_node(id, &rec, txn)?;
        self.note_created(txn, StoreKind::Node, id);
        // Maintain the grand-total live-node count (`rmp` task #82): once per node, labelled or not —
        // an unlabelled node contributes to no per-label count but is still a node. In-memory only;
        // durable at the commit checkpoint, reverted by `reload_catalog` on rollback.
        self.statistics.inc_node();
        Ok((id, eid))
    }

    /// Reads the node record at physical id `id`.
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated.
    pub fn node(&mut self, id: u64) -> Result<NodeRecord> {
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
    pub fn scan_node_ids(&mut self) -> Result<Vec<u64>> {
        let high_water = self.store(StoreKind::Node).alloc.high_water();
        let mut out = Vec::new();
        for id in 1..high_water {
            if self.read_node(id)?.mvcc.in_use() {
                out.push(id);
            }
        }
        Ok(out)
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
    pub fn scan_rel_ids(&mut self) -> Result<Vec<u64>> {
        let high_water = self.store(StoreKind::Rel).alloc.high_water();
        let mut out = Vec::new();
        for id in 1..high_water {
            if self.read_rel(id)?.mvcc.in_use() {
                out.push(id);
            }
        }
        Ok(out)
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
        // labels. Reclamation at GC ([`reclaim_node`]) must NOT decrement again. On rollback the
        // counts are restored by `reload_catalog`.
        if let Ok(label_ids) = labels::token_ids(rec.labels) {
            for token_id in label_ids {
                self.statistics.dec_label(token_id);
            }
        }
        // Drop this node's contribution to the grand-total live-node count (`rmp` task #82): once per
        // node, alongside the per-label decrements and independent of how many labels it carried.
        // Reclamation at GC ([`reclaim_node`]) must NOT decrement again; rollback restores it via
        // `reload_catalog`.
        self.statistics.dec_node();
        self.patch_header_word(
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
        let mut dead = self.read_node(id)?;
        dead.first_prop = NULL_ID;
        dead.mvcc = MvccHeader::default(); // clears in_use
        self.write_node(id, &dead, txn)?;
        self.store_mut(StoreKind::Node).free.push(id);
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
        let mut node = self.read_node(id)?;
        if !Self::is_live_version(node.mvcc) {
            return Err(GraphusError::Storage(format!("node {id} not in use")));
        }
        // Encode the requested set first so an overflowing token id errors before any mutation or
        // count change (no partial write, no count drift).
        let new_labels = labels::encode_set(label_token_ids).map_err(GraphusError::from)?;
        let old_labels = node.labels;
        node.labels = new_labels;
        self.write_node(id, &node, txn)?;
        // Adjust the per-label counts by the membership delta of this live node (`rmp` task #79).
        self.apply_label_count_delta(old_labels, new_labels);
        Ok(())
    }

    /// Applies the per-label live-node count change for a single node whose label bitmap moved from
    /// `old` to `new` (`rmp` task #79): each token id newly set is incremented, each newly cleared is
    /// decremented. A bit unchanged in both is left alone. Only inline membership bits (`0..=62`) are
    /// considered; the overflow flag is never a counted label. Call only after a successful node-label
    /// write on a **live** node, so the count tracks exactly the live nodes' contributions.
    fn apply_label_count_delta(&mut self, old: u64, new: u64) {
        // `token_ids` cannot error here: both bitmaps come from this build's inline writes (overflow
        // flag clear). The bit arithmetic isolates the changed bits without enumerating unchanged ones.
        let added = new & !old;
        let removed = old & !new;
        if let Ok(ids) = labels::token_ids(added) {
            for token_id in ids {
                self.statistics.inc_label(token_id);
            }
        }
        if let Ok(ids) = labels::token_ids(removed) {
            for token_id in ids {
                self.statistics.dec_label(token_id);
            }
        }
    }

    /// Adds the label with `label_token_id` to node `id` under `txn` (idempotent — a label already
    /// present is a no-op write).
    ///
    /// # Errors
    /// - [`GraphusError::Storage`] if the node is not in use or a write fails.
    /// - [`GraphusError::Runtime`] (from [`LabelError`](crate::labels::LabelError)) if
    ///   `label_token_id` is `>= 63`, or the node's bitmap is already in overflow form (#39).
    pub fn add_label(&mut self, txn: TxnId, id: u64, label_token_id: u32) -> Result<()> {
        let mut node = self.read_node(id)?;
        if !Self::is_live_version(node.mvcc) {
            return Err(GraphusError::Storage(format!("node {id} not in use")));
        }
        let next = labels::with_label(node.labels, label_token_id).map_err(GraphusError::from)?;
        if next == node.labels {
            return Ok(()); // already present: no write, no WAL churn, no count change
        }
        let old_labels = node.labels;
        node.labels = next;
        self.write_node(id, &node, txn)?;
        // Exactly one bit was newly set: increment its per-label count (`rmp` task #79).
        self.apply_label_count_delta(old_labels, next);
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
        let mut node = self.read_node(id)?;
        if !Self::is_live_version(node.mvcc) {
            return Err(GraphusError::Storage(format!("node {id} not in use")));
        }
        let next =
            labels::without_label(node.labels, label_token_id).map_err(GraphusError::from)?;
        if next == node.labels {
            return Ok(()); // already absent: no write, no count change
        }
        let old_labels = node.labels;
        node.labels = next;
        self.write_node(id, &node, txn)?;
        // Exactly one bit was newly cleared: decrement its per-label count (`rmp` task #79).
        self.apply_label_count_delta(old_labels, next);
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
    pub fn node_labels(&mut self, id: u64) -> Result<Vec<u32>> {
        let node = self.read_node(id)?;
        labels::token_ids(node.labels).map_err(GraphusError::from)
    }

    /// Whether node `id` carries the label with `label_token_id`.
    ///
    /// # Errors
    /// - [`GraphusError::Storage`] if `id`'s page is not allocated.
    /// - [`GraphusError::Runtime`] (from [`LabelError`](crate::labels::LabelError)) if
    ///   `label_token_id` is `>= 63`, or the node's bitmap is in overflow form (#39).
    pub fn node_has_label(&mut self, id: u64, label_token_id: u32) -> Result<bool> {
        let node = self.read_node(id)?;
        labels::has_label(node.labels, label_token_id).map_err(GraphusError::from)
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
        let mut start_node = self.read_node(start)?;
        if !Self::is_live_version(start_node.mvcc) {
            return Err(GraphusError::Storage(format!(
                "start node {start} not in use"
            )));
        }
        let id = self.alloc_id(StoreKind::Rel);
        let eid = self.element_ids.alloc();
        self.note_created(txn, StoreKind::Rel, id);
        // Stamp `xmin` with the writer's in-flight `TxnId` (`04 §5.2`); settled at commit.
        let mut rel = RelRecord::new(eid, VersionStamp::in_flight(txn), type_id, start, end);

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
            start_node.first_rel = id;
            self.write_rel(id, &rel, txn)?;
            self.write_node(start, &start_node, txn)?;
            // Maintain the per-relationship-type live count (`rmp` task #79) and the grand-total
            // live-relationship count (`rmp` task #82): the self-loop is now a live version. Both
            // endpoints are the (validated) live start node, so the increment is unconditional here.
            // This branch is mutually exclusive with the normal branch below, so the grand total is
            // incremented exactly once per relationship. In-memory only; durable at the commit
            // checkpoint, reverted by `reload_catalog` on rollback.
            self.statistics.inc_rel_type(type_id);
            self.statistics.inc_rel();
            return Ok((id, eid));
        }

        let mut end_node = self.read_node(end)?;
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
        start_node.first_rel = id;

        // Push at the head of the END node's chain.
        let end_head = end_node.first_rel;
        rel.set_chain_pointers(ChainSide::End, NULL_ID, end_head);
        rel.chain_flags |= CHAIN_FLAG_END_FIRST;
        if end_head != NULL_ID {
            self.relink_old_head(end_head, end, id, txn)?;
        }
        end_node.first_rel = id;

        self.write_rel(id, &rel, txn)?;
        self.write_node(start, &start_node, txn)?;
        self.write_node(end, &end_node, txn)?;
        // Maintain the per-relationship-type live count (`rmp` task #79) and the grand-total
        // live-relationship count (`rmp` task #82): the relationship is now a written, live version
        // and both endpoints are validated. The self-loop branch above returns early, so the grand
        // total is incremented exactly once per relationship. In-memory only; durable at the commit
        // checkpoint, reverted by `reload_catalog` on rollback.
        self.statistics.inc_rel_type(type_id);
        self.statistics.inc_rel();
        Ok((id, eid))
    }

    /// Points the `prev` pointer of `old_head`'s **head link** at `new_id` and clears its
    /// first-in-chain marker. Used when pushing a new head onto `node`'s chain.
    ///
    /// Only the link whose `prev == NULL` (the current head) is repointed — crucial for a
    /// self-loop `old_head`, where both sides face `node` but only one side is the head link; the
    /// other side's `prev` must keep pointing to the head link inside the same record.
    fn relink_old_head(&mut self, old_head: u64, node: u64, new_id: u64, txn: TxnId) -> Result<()> {
        let mut old = self.read_rel(old_head)?;
        if old.start_node == node && old.start_prev_rel == NULL_ID {
            old.start_prev_rel = new_id;
            old.chain_flags &= !CHAIN_FLAG_START_FIRST;
        }
        if old.end_node == node && old.end_prev_rel == NULL_ID {
            old.end_prev_rel = new_id;
            old.chain_flags &= !CHAIN_FLAG_END_FIRST;
        }
        self.write_rel(old_head, &old, txn)
    }

    /// Reads the relationship record at physical id `id`.
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated.
    pub fn rel(&mut self, id: u64) -> Result<RelRecord> {
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
        self.patch_header_word(
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
        // reflect the deletion from here. On rollback they are restored by `reload_catalog`, so an
        // aborted delete does not undercount.
        self.statistics.dec_rel_type(rel.type_id);
        self.statistics.dec_rel();
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

        let mut dead = self.read_rel(id)?;
        dead.first_prop = NULL_ID; // the chain is freed; drop the now-dangling head pointer
        dead.mvcc = MvccHeader::default();
        self.write_rel(id, &dead, txn)?;
        self.store_mut(StoreKind::Rel).free.push(id);
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
                self.store_mut(StoreKind::Prop).free.push(cur);
                freed += 1;
            }
            cur = next;
        }
        Ok(freed)
    }

    /// Garbage-collects the property chain of a **still-live** owner (`rmp` task #50): walks the
    /// chain rooted at `owner_kind`/`owner_id`'s `first_prop` and physically reclaims every property
    /// record that [`is_reclaimable`](Self::is_reclaimable) at `watermark` — a tombstone whose `xmax`
    /// committed at or before `watermark`, so no live or future snapshot can still see that version.
    /// Returns the number of records reclaimed.
    ///
    /// For each reclaimable record it frees the property's overflow heap chain, clears the record
    /// (`MvccHeader::default()` + `next_prop = NULL_ID`), returns its id to the Prop free list, and
    /// **splices it out** of the chain: if it was the head (no kept predecessor) the owner's
    /// `first_prop` is repointed past it and the owner record rewritten, otherwise the last kept
    /// predecessor's `next_prop` is repointed past it. A non-reclaimable record (a live version, or a
    /// not-yet-committed / not-yet-old-enough tombstone) is kept and becomes the new predecessor.
    /// This mirrors the splice the pre-MVCC `remove_*_property_value` performed, but gates removal on
    /// the GC watermark rather than a key match — so chains stay well-formed and leak-free (the
    /// consistency checker passes after a GC pass).
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
    ) -> Result<usize> {
        let mut first_prop = self.owner_first_prop(owner_kind, owner_id)?;
        let mut reclaimed = 0usize;
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
            if Self::is_reclaimable(prop.mvcc, watermark, &self.commit_registry) {
                // Free the overflow chain, clear and free the record, splice it out of the chain.
                self.free_property_overflow(txn, &prop)?;
                let mut dead = prop;
                dead.mvcc = MvccHeader::default(); // clears in_use
                dead.next_prop = NULL_ID;
                self.write_prop(cur, &dead, txn)?;
                self.store_mut(StoreKind::Prop).free.push(cur);
                if prev == NULL_ID {
                    first_prop = next;
                    self.set_owner_first_prop(owner_kind, owner_id, first_prop, txn)?;
                } else {
                    let mut p = self.read_prop(prev)?;
                    p.next_prop = next;
                    self.write_prop(prev, &p, txn)?;
                }
                reclaimed += 1;
            } else {
                prev = cur; // kept: it becomes the predecessor of whatever follows
            }
            cur = next;
        }
        Ok(reclaimed)
    }

    /// Reads the `first_prop` head pointer of a node or relationship owner (GC helper).
    fn owner_first_prop(&mut self, owner_kind: StoreKind, owner_id: u64) -> Result<u64> {
        Ok(match owner_kind {
            StoreKind::Node => self.read_node(owner_id)?.first_prop,
            StoreKind::Rel => self.read_rel(owner_id)?.first_prop,
            StoreKind::Prop | StoreKind::Strings => {
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
            StoreKind::Prop | StoreKind::Strings => Err(GraphusError::Storage(format!(
                "{owner_kind:?} is not a property-chain owner"
            ))),
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
        let mut node = self.read_node(node_id)?;
        if !Self::is_live_version(node.mvcc) {
            return Err(GraphusError::Storage(format!("node {node_id} not in use")));
        }
        let pid = self.alloc_id(StoreKind::Prop);
        // Stamp `xmin` with the writer's in-flight `TxnId` (`04 §5.2`; per-value MVCC, `rmp` task
        // #50); `commit` settles it to the commit timestamp. Until then the version is visible only
        // to its own transaction.
        let mut prop = PropRecord::new(VersionStamp::in_flight(txn), key, type_tag, value_inline);
        prop.next_prop = node.first_prop;
        self.write_prop(pid, &prop, txn)?;
        self.note_created(txn, StoreKind::Prop, pid);
        node.first_prop = pid;
        self.write_node(node_id, &node, txn)?;
        Ok(pid)
    }

    /// Reads the property record at physical id `id`.
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated.
    pub fn property(&mut self, id: u64) -> Result<PropRecord> {
        self.read_prop(id)
    }

    /// Collects every live property `(physical_id, record)` in `node_id`'s chain, head to tail.
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing.
    pub fn node_properties(&mut self, node_id: u64) -> Result<Vec<(u64, PropRecord)>> {
        let node = self.read_node(node_id)?;
        let mut out = Vec::new();
        let mut cur = node.first_prop;
        let guard = self.store(StoreKind::Prop).alloc.high_water() + 1;
        let mut steps = 0u64;
        while cur != NULL_ID {
            steps += 1;
            if steps > guard {
                return Err(GraphusError::Storage(format!(
                    "property chain of node {node_id} is malformed (cycle?)"
                )));
            }
            let p = self.read_prop(cur)?;
            let next = p.next_prop;
            if p.mvcc.in_use() {
                out.push((cur, p));
            }
            cur = next;
        }
        Ok(out)
    }

    /// MVCC-tombstones the **live** property records in the chain rooted at `owner_first_prop`
    /// (`rmp` task #50): for each prop that [`is_live_version`](Self::is_live_version) and — when
    /// `key_filter` is `Some(k)` — whose `key == k`, it stamps `xmax = in_flight(txn)` via
    /// [`patch_header_word`](Self::patch_header_word) and notes it expired so `commit` settles the
    /// stamp. A `key_filter` of `None` tombstones every live property in the chain (used by
    /// `clear_*_properties` for `SET n = map`).
    ///
    /// This is the property analogue of [`delete_node`](Self::delete_node) /
    /// [`delete_rel`](Self::delete_rel): the tombstoned record keeps its `in_use` slot, its
    /// `next_prop` link and its overflow heap chain, so an older snapshot still observes the old
    /// value and the chain stays well-formed for the consistency checker. Physical reclamation
    /// (record + overflow blocks + splice) is deferred to [`gc`](Self::gc) via
    /// [`gc_property_chain`](Self::gc_property_chain) once no live snapshot can see the old version.
    /// It therefore frees nothing, clears nothing and splices nothing here.
    ///
    /// `owner_label` is only used in the cycle-guard diagnostic (e.g. `"node 5"` / `"rel 7"`).
    /// Returns the number of property records tombstoned (callers that only need "did anything
    /// change?" compare it against `0`).
    ///
    /// # Errors
    /// Returns a storage error if a chain read or a tombstone write fails, or the chain does not
    /// terminate within the cycle guard.
    fn tombstone_props_for_key(
        &mut self,
        txn: TxnId,
        owner_first_prop: u64,
        key_filter: Option<u32>,
        owner_label: &str,
    ) -> Result<usize> {
        let mut tombstoned = 0usize;
        let mut cur = owner_first_prop;
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
            let next = prop.next_prop;
            if Self::is_live_version(prop.mvcc) && key_filter.is_none_or(|key| prop.key == key) {
                self.patch_header_word(
                    StoreKind::Prop,
                    cur,
                    MVCC_OFF_EXPIRED_TS,
                    VersionStamp::in_flight(txn),
                    txn,
                )?;
                self.note_expired(txn, StoreKind::Prop, cur);
                tombstoned += 1;
            }
            cur = next;
        }
        Ok(tombstoned)
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
        for chunk in payload_chunks(payload).into_iter().rev() {
            let id = self.alloc_id(StoreKind::Strings);
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
    pub fn read_chain(&mut self, head: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
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
            let block = self.read_block(cur)?;
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
                self.store_mut(StoreKind::Strings).free.push(cur);
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
    /// of that key via per-value MVCC (`rmp` task #50): it **MVCC-tombstones** every live property
    /// record for `key` (stamping `xmax = in_flight(txn)`, like a node/rel delete in `rmp` task #45),
    /// then prepends a fresh, in-flight version. The old version keeps its slot and its overflow
    /// chain so an older snapshot still reads the previous value; physical reclamation of the
    /// tombstoned record and its overflow blocks happens at [`gc`](Self::gc), not here. Inline
    /// scalars (`Integer`/`Float`/`Boolean`) stay inline (#38); `String`/`List`/temporal values are
    /// serialized to the `strings.store` overflow heap and the property holds the head block id with
    /// the `type_tag` overflow bit set (`04 §2.3`). Returns the new property's physical id.
    ///
    /// # Errors
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
        // Encode first so a non-persistable value errors before any mutation (no partial write).
        let (type_tag, value_inline) = self.encode_property_value(txn, value)?;
        let node = self.read_node(node_id)?;
        if !Self::is_live_version(node.mvcc) {
            return Err(GraphusError::Storage(format!("node {node_id} not in use")));
        }
        self.tombstone_props_for_key(txn, node.first_prop, Some(key), &format!("node {node_id}"))?;
        self.add_node_property(txn, node_id, key, type_tag, value_inline)
    }

    /// Removes node `node_id`'s property `key` under `txn` via per-value MVCC (`rmp` task #50):
    /// **MVCC-tombstones** every live property record for `key` (stamping `xmax = in_flight(txn)`)
    /// rather than freeing it immediately. The tombstoned record keeps its slot, its `next_prop`
    /// link and its overflow heap chain so an older snapshot still observes the value; physical
    /// reclamation (record + overflow blocks + splice) is deferred to [`gc`](Self::gc). Returns
    /// whether anything was tombstoned (so a caller can distinguish a real removal from a no-op,
    /// e.g. for `REMOVE n.p`).
    ///
    /// # Errors
    /// Returns a storage error if the node is not in use or a write fails.
    pub fn remove_node_property_value(
        &mut self,
        txn: TxnId,
        node_id: u64,
        key: u32,
    ) -> Result<bool> {
        let node = self.read_node(node_id)?;
        if !Self::is_live_version(node.mvcc) {
            return Err(GraphusError::Storage(format!("node {node_id} not in use")));
        }
        let tombstoned = self.tombstone_props_for_key(
            txn,
            node.first_prop,
            Some(key),
            &format!("node {node_id}"),
        )?;
        Ok(tombstoned > 0)
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
        &mut self,
        type_tag: u8,
        value_inline: u64,
    ) -> Result<graphus_core::Value> {
        if type_tag & valenc::OVERFLOW_BIT == 0 {
            return crate::propenc::decode_inline(type_tag, value_inline)
                .map_err(GraphusError::from);
        }
        let class_tag = type_tag & !valenc::OVERFLOW_BIT;
        let bytes = self.read_chain(value_inline)?;
        valenc::decode(class_tag, &bytes).map_err(GraphusError::from)
    }

    /// Collects node `node_id`'s live properties as `(physical_id, key_token, Value)`, decoding both
    /// inline scalars and overflow `String`/`List`/temporal values (`rmp` task #43). The chain is
    /// walked head-to-tail; the caller applies newest-wins per key (the chain is prepend-ordered).
    ///
    /// # Errors
    /// Returns a storage error if the property chain or an overflow chain is unreadable/corrupt.
    pub fn node_property_values(
        &mut self,
        node_id: u64,
    ) -> Result<Vec<(u64, u32, graphus_core::Value)>> {
        let chain = self.node_properties(node_id)?;
        let mut out = Vec::with_capacity(chain.len());
        for (pid, prop) in chain {
            let value = self.decode_property_value(prop.type_tag, prop.value_inline)?;
            out.push((pid, prop.key, value));
        }
        Ok(out)
    }

    /// Clears **all** of node `node_id`'s properties under `txn` via per-value MVCC (`rmp` task #50):
    /// **MVCC-tombstones** every live property record in the node's chain (stamping
    /// `xmax = in_flight(txn)`), leaving the slots, the `next_prop` links and the overflow chains in
    /// place so older snapshots still observe the old property set. Used by `SET n = map`, which
    /// replaces the whole property set. The head pointer `first_prop` is **not** reset (the
    /// tombstoned records stay linked until GC); physical reclamation (records + overflow blocks +
    /// splice) is deferred to [`gc`](Self::gc). Returns the number of property records tombstoned.
    ///
    /// # Errors
    /// Returns a storage error if the node is not in use or a write fails.
    pub fn clear_node_properties(&mut self, txn: TxnId, node_id: u64) -> Result<usize> {
        let node = self.read_node(node_id)?;
        if !Self::is_live_version(node.mvcc) {
            return Err(GraphusError::Storage(format!("node {node_id} not in use")));
        }
        self.tombstone_props_for_key(txn, node.first_prop, None, &format!("node {node_id}"))
    }

    /// Frees the overflow heap chain a property record owns, if any: a no-op for an inline scalar;
    /// for an overflowed `String`/`List`/temporal value it frees the chain whose head is
    /// `value_inline` (`rmp` task #43). Used when a property value is overwritten or removed so its
    /// old bytes are not leaked.
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
    /// [`RelRecord.first_prop`](crate::record::RelRecord).
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
        let mut rel = self.read_rel(rel_id)?;
        if !Self::is_live_version(rel.mvcc) {
            return Err(GraphusError::Storage(format!("rel {rel_id} not in use")));
        }
        let pid = self.alloc_id(StoreKind::Prop);
        // Stamp `xmin` with the writer's in-flight `TxnId` (`04 §5.2`; per-value MVCC, `rmp` task
        // #50); `commit` settles it to the commit timestamp.
        let mut prop = PropRecord::new(VersionStamp::in_flight(txn), key, type_tag, value_inline);
        prop.next_prop = rel.first_prop;
        self.write_prop(pid, &prop, txn)?;
        self.note_created(txn, StoreKind::Prop, pid);
        rel.first_prop = pid;
        self.write_rel(rel_id, &rel, txn)?;
        Ok(pid)
    }

    /// Collects every live property `(physical_id, record)` in relationship `rel_id`'s chain, head to
    /// tail (`rmp` task #44). The relationship analogue of
    /// [`node_properties`](Self::node_properties).
    ///
    /// # Errors
    /// Returns a storage error if a chain page is missing or the chain is malformed (cycle-guarded).
    pub fn rel_properties(&mut self, rel_id: u64) -> Result<Vec<(u64, PropRecord)>> {
        let rel = self.read_rel(rel_id)?;
        let mut out = Vec::new();
        let mut cur = rel.first_prop;
        let guard = self.store(StoreKind::Prop).alloc.high_water() + 1;
        let mut steps = 0u64;
        while cur != NULL_ID {
            steps += 1;
            if steps > guard {
                return Err(GraphusError::Storage(format!(
                    "property chain of rel {rel_id} is malformed (cycle?)"
                )));
            }
            let p = self.read_prop(cur)?;
            let next = p.next_prop;
            if p.mvcc.in_use() {
                out.push((cur, p));
            }
            cur = next;
        }
        Ok(out)
    }

    /// Sets relationship `rel_id`'s property `key` to `value` under `txn`, **replacing** any current
    /// value of that key via per-value MVCC (`rmp` task #50): it **MVCC-tombstones** every live
    /// property record for `key` (stamping `xmax = in_flight(txn)`, like a node/rel delete in
    /// `rmp` task #45), then prepends a fresh, in-flight version. The old version keeps its slot and
    /// its overflow chain so an older snapshot still reads the previous value; physical reclamation
    /// happens at [`gc`](Self::gc), not here. Inline scalars (`Integer`/`Float`/`Boolean`) stay
    /// inline (#38); `String`/`List`/temporal values overflow to the `strings.store` heap with
    /// the `type_tag` overflow bit set (`04 §2.3`). Returns the new property's physical id. The
    /// relationship analogue of [`set_node_property_value`](Self::set_node_property_value).
    ///
    /// # Errors
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
        // Encode first so a non-persistable value errors before any mutation (no partial write).
        let (type_tag, value_inline) = self.encode_property_value(txn, value)?;
        let rel = self.read_rel(rel_id)?;
        if !Self::is_live_version(rel.mvcc) {
            return Err(GraphusError::Storage(format!("rel {rel_id} not in use")));
        }
        self.tombstone_props_for_key(txn, rel.first_prop, Some(key), &format!("rel {rel_id}"))?;
        self.add_rel_property(txn, rel_id, key, type_tag, value_inline)
    }

    /// Removes relationship `rel_id`'s property `key` under `txn` via per-value MVCC (`rmp` task
    /// #50): **MVCC-tombstones** every live property record for `key` (stamping
    /// `xmax = in_flight(txn)`) rather than freeing it immediately. The tombstoned record keeps its
    /// slot, its `next_prop` link and its overflow heap chain so an older snapshot still observes the
    /// value; physical reclamation is deferred to [`gc`](Self::gc). Returns whether anything was
    /// tombstoned (so `REMOVE r.p` can distinguish a real removal from a no-op). The relationship
    /// analogue of [`remove_node_property_value`](Self::remove_node_property_value).
    ///
    /// # Errors
    /// Returns a storage error if the relationship is not in use or a write fails.
    pub fn remove_rel_property_value(&mut self, txn: TxnId, rel_id: u64, key: u32) -> Result<bool> {
        let rel = self.read_rel(rel_id)?;
        if !Self::is_live_version(rel.mvcc) {
            return Err(GraphusError::Storage(format!("rel {rel_id} not in use")));
        }
        let tombstoned =
            self.tombstone_props_for_key(txn, rel.first_prop, Some(key), &format!("rel {rel_id}"))?;
        Ok(tombstoned > 0)
    }

    /// Collects relationship `rel_id`'s live properties as `(physical_id, key_token, Value)`, decoding
    /// both inline scalars and overflow `String`/`List`/temporal values (`rmp` task #44). The
    /// chain is walked head-to-tail; the caller applies newest-wins per key (the chain is
    /// prepend-ordered). The relationship analogue of
    /// [`node_property_values`](Self::node_property_values).
    ///
    /// # Errors
    /// Returns a storage error if the property chain or an overflow chain is unreadable/corrupt.
    pub fn rel_property_values(
        &mut self,
        rel_id: u64,
    ) -> Result<Vec<(u64, u32, graphus_core::Value)>> {
        let chain = self.rel_properties(rel_id)?;
        let mut out = Vec::with_capacity(chain.len());
        for (pid, prop) in chain {
            let value = self.decode_property_value(prop.type_tag, prop.value_inline)?;
            out.push((pid, prop.key, value));
        }
        Ok(out)
    }

    /// Clears **all** of relationship `rel_id`'s properties under `txn` via per-value MVCC (`rmp`
    /// task #50): **MVCC-tombstones** every live property record in the relationship's chain
    /// (stamping `xmax = in_flight(txn)`), leaving the slots, the `next_prop` links and the overflow
    /// chains in place so older snapshots still observe the old property set. Used by `SET r = map`,
    /// which replaces the whole property set. The head pointer `first_prop` is **not** reset (the
    /// tombstoned records stay linked until GC); physical reclamation is deferred to
    /// [`gc`](Self::gc). Returns the number of property records tombstoned. The relationship analogue
    /// of [`clear_node_properties`](Self::clear_node_properties).
    ///
    /// # Errors
    /// Returns a storage error if the relationship is not in use or a write fails.
    pub fn clear_rel_properties(&mut self, txn: TxnId, rel_id: u64) -> Result<usize> {
        let rel = self.read_rel(rel_id)?;
        if !Self::is_live_version(rel.mvcc) {
            return Err(GraphusError::Storage(format!("rel {rel_id} not in use")));
        }
        self.tombstone_props_for_key(txn, rel.first_prop, None, &format!("rel {rel_id}"))
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
    pub fn incident_rels(&mut self, node_id: u64) -> Result<Vec<u64>> {
        let node = self.read_node(node_id)?;
        let mut out = Vec::new();
        let mut cur = node.first_rel;
        // The walk visits each chain link once; a self-loop contributes two links. The guard is
        // generous (twice the rel high-water) and only catches a corrupted cycle.
        let guard = 2 * self.store(StoreKind::Rel).alloc.high_water() + 2;
        let mut steps = 0u64;
        let mut prev_link = NULL_ID;
        while cur != NULL_ID {
            steps += 1;
            if steps > guard {
                return Err(GraphusError::Storage(format!(
                    "incidence chain of node {node_id} is malformed (cycle?)"
                )));
            }
            let r = self.read_rel(cur)?;
            let is_loop = r.start_node == node_id && r.end_node == node_id;
            // Record the rel once (dedupe a self-loop's two consecutive links).
            if out.last() != Some(&cur) {
                out.push(cur);
            }
            // Choose the side to follow. For a self-loop, the two links are reached via the END
            // side (head) then the START side; pick whichever side we did *not* arrive through.
            let next = if is_loop {
                let (end_prev, end_next) = r.chain_pointers(ChainSide::End);
                if end_prev == prev_link || prev_link == NULL_ID {
                    // arrived via the END side (or at head): follow END's next (the START link)
                    end_next
                } else {
                    // arrived via the START side: follow START's next (past the loop)
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

    /// The degree of `node_id` (distinct incident relationships, self-loops counted once).
    ///
    /// # Errors
    /// Propagates a chain-walk failure.
    pub fn degree(&mut self, node_id: u64) -> Result<usize> {
        Ok(self.incident_rels(node_id)?.len())
    }

    // --------------------------------- flush --------------------------------

    /// Flushes every dirty page home and syncs the device. The buffer pool enforces the WAL rule
    /// (log durable through each page's `page_lsn`) on every write-back (`04 §4.3`).
    ///
    /// # Errors
    /// Returns a storage error if a write-back or device sync fails.
    pub fn flush(&mut self) -> Result<()> {
        self.pool.flush_all()
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
            pages.extend_from_slice(&s.device_pages);
        }
        pages
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

    /// Records (or replaces) the opaque value histogram for the node-label property
    /// `(label_token, prop_token)` with `bytes`, stored verbatim (`rmp` task #81).
    ///
    /// The mutation is purely in-memory here. Like the `rmp` task #79 count mutators, it becomes
    /// **durable when the enclosing transaction commits** (the catalog is checkpointed at commit) and
    /// is **discarded on rollback** (the catalog is reloaded from the last committed metadata page).
    ///
    /// An empty `bytes` removes any existing entry: a histogram is never zero-length, so an empty
    /// value is meaningless and would not survive the codec round-trip.
    pub fn set_property_histogram(&mut self, label_token: u32, prop_token: u32, bytes: Vec<u8>) {
        self.statistics
            .set_property_histogram(label_token, prop_token, bytes);
    }

    /// Removes the durable value histogram for the node-label property `(label_token, prop_token)`,
    /// if present (`rmp` task #81). Removing an absent entry is a harmless no-op.
    ///
    /// Like [`set_property_histogram`](Self::set_property_histogram), the removal is in-memory and
    /// becomes durable at the enclosing transaction's commit, and is discarded on rollback.
    pub fn remove_property_histogram(&mut self, label_token: u32, prop_token: u32) {
        self.statistics
            .remove_property_histogram(label_token, prop_token);
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
    /// `rmp` task #81 histogram mutators, it becomes **durable when the enclosing transaction commits**
    /// (the catalog is checkpointed at commit) and is **discarded on rollback** (the catalog is
    /// reloaded from the last committed metadata page). Re-recording an existing key flips its state.
    pub fn set_node_property_index(
        &mut self,
        label_token: u32,
        prop_token: u32,
        state: IndexState,
    ) {
        self.statistics
            .set_node_property_index(label_token, prop_token, state);
    }

    /// Removes the node-property index on `(label_token, prop_token)` from the durable catalog, if
    /// declared (`rmp` task #90). Removing an absent entry is a harmless no-op.
    ///
    /// Like [`set_node_property_index`](Self::set_node_property_index), the removal is in-memory and
    /// becomes durable at the enclosing transaction's commit, and is discarded on rollback.
    pub fn remove_node_property_index(&mut self, label_token: u32, prop_token: u32) {
        self.statistics
            .remove_node_property_index(label_token, prop_token);
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
    pub fn set_fulltext_index(&mut self, name: String, entry: FulltextIndexEntry) {
        self.statistics.set_fulltext_index(name, entry);
    }

    /// Removes the full-text index named `name` from the durable catalog, if declared (`rmp` task
    /// #72). Removing an absent entry is a harmless no-op. Durable at the enclosing transaction's
    /// commit, discarded on rollback.
    pub fn remove_fulltext_index(&mut self, name: &str) {
        self.statistics.remove_fulltext_index(name);
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
    pub fn set_spatial_index(&mut self, name: String, entry: SpatialIndexEntry) {
        self.statistics.set_spatial_index(name, entry);
    }

    /// Removes the spatial index named `name` from the durable catalog, if declared (`rmp` task #98).
    /// Removing an absent entry is a harmless no-op. Durable at the enclosing transaction's commit,
    /// discarded on rollback.
    pub fn remove_spatial_index(&mut self, name: &str) {
        self.statistics.remove_spatial_index(name);
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
    pub fn set_constraint(&mut self, name: String, entry: ConstraintEntry) {
        self.statistics.set_constraint(name, entry);
    }

    /// Removes the constraint named `name` from the durable catalog, if declared (`rmp` task #99).
    /// Removing an absent entry is a harmless no-op. Durable at the enclosing transaction's commit,
    /// discarded on rollback.
    pub fn remove_constraint(&mut self, name: &str) {
        self.statistics.remove_constraint(name);
    }

    /// Reads device page `page` through the pool (verifying its checksum), returning its bytes.
    /// A DST helper for snapshotting the on-disk image (`04 §11`).
    ///
    /// # Errors
    /// Returns a storage error if the page is missing or fails checksum verification.
    pub fn read_device_page(&mut self, page: PageId) -> Result<Box<graphus_io::Page>> {
        let f = self.pool.fetch(page)?;
        let bytes = Box::new(*self.pool.page(f));
        self.pool.unpin(f);
        Ok(bytes)
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

    /// The number of interned `Label`-namespace tokens (`04 §2.6`): label token ids are dense in
    /// `0..label_token_count`. The consistency checker uses this to verify that a node's label
    /// bitmap references only token ids that exist in the token store (`rmp` task #42).
    pub(crate) fn checker_label_token_count(&self) -> usize {
        self.tokens.len(Namespace::Label)
    }

    /// Reads the `strings.store` overflow-heap block at physical id `id` (`rmp` task #43). Used by
    /// the consistency checker to scan and validate overflow chains.
    pub(crate) fn checker_block(&mut self, id: u64) -> Result<HeapBlock> {
        self.read_block(id)
    }
}

/// Which neighbour pointer is being repaired during an unlink.
#[derive(Clone, Copy)]
enum NeighbourPtr {
    Prev,
    Next,
}

/// Splits `payload` into [`BLOCK_PAYLOAD`]-sized chunks for the overflow heap (`rmp` task #43). An
/// **empty** payload yields a single empty chunk, so a chain always has at least one block and its
/// head id is a valid, non-null pointer (`04 §2.2`).
fn payload_chunks(payload: &[u8]) -> Vec<&[u8]> {
    if payload.is_empty() {
        vec![&[]]
    } else {
        payload.chunks(BLOCK_PAYLOAD).collect()
    }
}

/// A buffer-pool-backed [`ApplyTarget`](graphus_wal::ApplyTarget) used for **live rollback** only
/// (`04 §4.4`).
///
/// During live rollback the WAL manager calls only [`apply`](graphus_wal::ApplyTarget::apply)
/// (never `page_lsn`), so this target applies each compensating intra-page patch to the cached
/// page and re-stamps the page's `page_lsn`. Crash recovery uses [`crate::recovery::DeviceTarget`]
/// instead, which can read each page's `page_lsn` to guard redo.
mod pool_target {
    use super::{page, paging};
    use graphus_bufpool::{BufferPool, WalRule};
    use graphus_core::error::Result;
    use graphus_core::{Lsn, PageId};
    use graphus_io::BlockDevice;

    /// See module docs.
    pub struct PoolTarget<'a, D: BlockDevice, W: WalRule> {
        pool: &'a mut BufferPool<D, W>,
    }

    impl<'a, D: BlockDevice, W: WalRule> PoolTarget<'a, D, W> {
        /// Wraps a buffer pool for live-rollback compensation.
        pub fn new(pool: &'a mut BufferPool<D, W>) -> Self {
            Self { pool }
        }
    }

    impl<D: BlockDevice, W: WalRule> graphus_wal::ApplyTarget for PoolTarget<'_, D, W> {
        fn page_lsn(&self, _page: PageId) -> Lsn {
            // Never consulted during live rollback (the WAL manager calls only `apply`).
            Lsn(0)
        }

        fn apply(&mut self, page: PageId, lsn: Lsn, image: &[u8]) -> Result<()> {
            let f = self.pool.fetch(page)?;
            let p = self.pool.page_mut(f);
            paging::apply_patch(p, image)?;
            page::set_page_lsn(p, lsn);
            self.pool.unpin(f);
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

    // ----------------------- per-value property MVCC (`rmp` task #50) -----------------------
    //
    // Regression guards for the dirty-read bug per-value MVCC fixes: `set_*_property_value` used to
    // *compact* (free the old record + overflow chain, prepend the new), so a concurrent older
    // snapshot could no longer read the previous value. The fix tombstones the old version (it keeps
    // its slot, its chain link and its overflow chain) and prepends a fresh version, deferring
    // physical reclamation to GC -- so an older snapshot still observes the old value until no live
    // snapshot can. These tests assert the store-level mechanics that make that possible; the
    // reader-side visibility filtering lives in `graphus-cypher` (out of scope here).

    use graphus_core::{Value, VersionStamp};

    /// Runs one GC pass under a fresh `txn` at the given `watermark` (see [`RecordStore::gc`]).
    fn gc_at(s: &mut Store, txn: TxnId, watermark: Timestamp) -> usize {
        s.begin(txn);
        let report = s.gc(txn, watermark).unwrap();
        s.commit(txn).unwrap();
        report.reclaimed
    }

    #[test]
    fn overwriting_a_node_property_tombstones_the_old_version_and_keeps_both_until_gc() {
        let mut s = fresh();
        let key = s.intern_token(Namespace::PropKey, "v").unwrap();

        // Txn 1: create a node with `v = 1`, commit.
        let t1 = TxnId(1);
        s.begin(t1);
        let (n, _) = s.create_node(t1).unwrap();
        s.set_node_property_value(t1, n, key, &Value::Integer(1))
            .unwrap();
        s.commit(t1).unwrap();
        let snap_after_v1 = s.snapshot_ts(); // a reader that began here must still see `v = 1`

        // Txn 2: overwrite to `v = 2`, commit. The old version is tombstoned, not freed.
        let t2 = TxnId(2);
        s.begin(t2);
        s.set_node_property_value(t2, n, key, &Value::Integer(2))
            .unwrap();
        s.commit(t2).unwrap();

        // The chain now holds BOTH in-use records: the new live one (xmax == 0) and the old
        // tombstoned one (xmax committed). `node_properties` returns every in-use record (the reader
        // layer filters by visibility), so we see exactly two.
        let chain = s.node_properties(n).unwrap();
        assert_eq!(chain.len(), 2, "old version tombstoned, not freed");
        let live: Vec<_> = chain
            .iter()
            .filter(|(_, p)| Store::is_live_version(p.mvcc))
            .collect();
        assert_eq!(live.len(), 1, "exactly one live version");
        assert_eq!(
            s.decode_property_value(live[0].1.type_tag, live[0].1.value_inline)
                .unwrap(),
            Value::Integer(2)
        );
        let tomb: Vec<_> = chain
            .iter()
            .filter(|(_, p)| p.mvcc.in_use() && p.mvcc.expired_ts != 0)
            .collect();
        assert_eq!(tomb.len(), 1, "exactly one tombstoned old version");
        assert_eq!(
            s.decode_property_value(tomb[0].1.type_tag, tomb[0].1.value_inline)
                .unwrap(),
            Value::Integer(1),
            "the old value survives for an older snapshot"
        );

        // Snapshot isolation: GC at a watermark BELOW the tombstone's commit timestamp (the snapshot
        // an older reader holds) must NOT reclaim the old version -- it is still observable.
        assert_eq!(
            gc_at(&mut s, TxnId(3), snap_after_v1),
            0,
            "GC must not reclaim a version an older snapshot can still see"
        );
        assert_eq!(
            s.node_properties(n).unwrap().len(),
            2,
            "old version still present after a too-early GC"
        );

        // Once no live snapshot predates the overwrite (watermark = latest commit), GC reclaims the
        // tombstoned old version and splices it out, leaving exactly the live one.
        let latest = s.snapshot_ts();
        gc_at(&mut s, TxnId(4), latest);
        let chain = s.node_properties(n).unwrap();
        assert_eq!(chain.len(), 1, "tombstoned old version reclaimed at GC");
        assert_eq!(
            s.node_property_values(n).unwrap(),
            vec![(chain[0].0, key, Value::Integer(2))]
        );
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

    #[test]
    fn gc_reclaims_only_committed_tombstones_below_the_watermark() {
        let mut s = fresh();
        let key = s.intern_token(Namespace::PropKey, "v").unwrap();
        let t1 = TxnId(1);
        s.begin(t1);
        let (n, _) = s.create_node(t1).unwrap();
        s.set_node_property_value(t1, n, key, &Value::Integer(1))
            .unwrap();
        s.commit(t1).unwrap();

        // An in-flight (uncommitted) tombstone is never reclaimable: GC inside the still-open writing
        // txn leaves the old version in place.
        let t2 = TxnId(2);
        s.begin(t2);
        s.set_node_property_value(t2, n, key, &Value::Integer(2))
            .unwrap();
        // Within t2 the old version's xmax is in-flight; a GC at the current watermark cannot touch
        // it (and would be unsafe to). We run GC under t2's own id so the chain is consistent.
        let wm = s.snapshot_ts();
        assert_eq!(
            s.gc(t2, wm).unwrap().reclaimed,
            0,
            "an in-flight tombstone is not reclaimable"
        );
        s.commit(t2).unwrap();
        assert_eq!(s.node_properties(n).unwrap().len(), 2);

        // After commit, a GC at the latest watermark reclaims it.
        let latest = s.snapshot_ts();
        gc_at(&mut s, TxnId(3), latest);
        assert_eq!(s.node_properties(n).unwrap().len(), 1);
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
}
