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

use graphus_bufpool::BufferPool;
use graphus_bufpool::page::{self, HEADER_SIZE};
use graphus_core::error::{GraphusError, Result};
use graphus_core::{ElementId, PageId, TxnId};
use graphus_io::{BlockDevice, PAGE_SIZE};
use graphus_wal::{LogSink, WalManager};

use crate::heap::{self, BLOCK_PAYLOAD, HeapBlock, STRINGS_RECORD_SIZE};
use crate::idalloc::{ElementIdAllocator, FreeList, NULL_ID, PhysicalAllocator};
use crate::labels;
use crate::meta::{Meta, StoreMeta};
use crate::paging;
use crate::record::{
    CHAIN_FLAG_END_FIRST, CHAIN_FLAG_START_FIRST, ChainSide, MvccHeader, NODE_RECORD_SIZE,
    NodeRecord, PROP_RECORD_SIZE, PropRecord, REL_RECORD_SIZE, RelRecord,
};
use crate::tokens::{Namespace, TokenStore};
use crate::valenc;
use crate::wal_rule::SharedWal;

/// The device page reserved for the durable catalog ([`crate::meta`]).
pub const META_PAGE: PageId = PageId(0);

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
}

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
        };
        store.init_meta_page()?;
        store.checkpoint_meta(SYSTEM_TXN, true)?;
        store.flush()?;
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
        let meta = Self::read_meta(&mut pool)?;
        let stores = [
            FixedStore::from_meta(StoreKind::Node, &meta.stores[0]),
            FixedStore::from_meta(StoreKind::Rel, &meta.stores[1]),
            FixedStore::from_meta(StoreKind::Prop, &meta.stores[2]),
            FixedStore::from_meta(StoreKind::Strings, &meta.stores[3]),
        ];
        Ok(Self {
            pool,
            wal: shared,
            element_ids: ElementIdAllocator::new(meta.element_id_next.max(1)),
            tokens: meta.tokens,
            stores,
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
            stores: [
                self.stores[0].to_meta(),
                self.stores[1].to_meta(),
                self.stores[2].to_meta(),
                self.stores[3].to_meta(),
            ],
            tokens: self.tokens.clone(),
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

    /// Reads and decodes the durable metadata catalog.
    fn read_meta(pool: &mut BufferPool<D, SharedWal<S>>) -> Result<Meta> {
        let f = pool.fetch(META_PAGE)?;
        let p = pool.page(f);
        let len = u32::from_le_bytes(
            p[HEADER_SIZE..HEADER_SIZE + 4]
                .try_into()
                .expect("4-byte slice"),
        ) as usize;
        let start = HEADER_SIZE + 4;
        if start + len > p.len() {
            pool.unpin(f);
            return Err(GraphusError::Storage(
                "metadata length runs past the page".to_owned(),
            ));
        }
        let payload = p[start..start + len].to_vec();
        pool.unpin(f);
        Meta::decode(&payload)
    }

    /// Persists the in-memory catalog to the metadata page as one WAL-logged update under `txn`.
    /// When `commit` is set, `txn` is begun and committed around the write (standalone catalog
    /// change, `04 §2.6`); otherwise the write joins the caller's open `txn`.
    fn checkpoint_meta(&mut self, txn: TxnId, commit: bool) -> Result<()> {
        let meta = self.snapshot_meta();
        let payload = meta.encode()?;
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        framed.extend_from_slice(&payload);

        if commit {
            self.wal.with(|w| {
                w.begin(txn);
            });
        }
        self.write_region(META_PAGE, HEADER_SIZE, &framed, txn)?;
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

    /// Begins transaction `txn` in the WAL.
    pub fn begin(&mut self, txn: TxnId) {
        self.wal.with(|w| {
            w.begin(txn);
        });
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
        self.checkpoint_meta(txn, false)?;
        self.wal.with(|w| w.commit(txn))?;
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
    /// # Errors
    /// Returns a storage error if undo apply fails or the catalog cannot be reloaded.
    ///
    /// # Panics
    /// Panics if the WAL `fdatasync` fails (`04 §4.9`).
    pub fn rollback(&mut self, txn: TxnId) -> Result<()> {
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
        let meta = Self::read_meta(&mut self.pool)?;
        self.element_ids = ElementIdAllocator::new(meta.element_id_next.max(1));
        for (i, sm) in meta.stores.iter().enumerate() {
            let kind = self.stores[i].kind;
            self.stores[i] = FixedStore::from_meta(kind, sm);
        }
        self.tokens = meta.tokens;
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
        let rec = NodeRecord::new(eid, txn.0);
        self.write_node(id, &rec, txn)?;
        Ok((id, eid))
    }

    /// Reads the node record at physical id `id`.
    ///
    /// # Errors
    /// Returns a storage error if `id`'s page is not allocated.
    pub fn node(&mut self, id: u64) -> Result<NodeRecord> {
        self.read_node(id)
    }

    /// Enumerates the physical ids of every **live** (in-use) node, in ascending id order.
    ///
    /// The node store's physical-id space is `1..high_water` (id `0` is the reserved null pointer
    /// and real records start at id `1`, `04 §2.2`); this walks that range and keeps the ids whose
    /// node record is in use. A full scan is O(high-water): a vectorised / segment-skipping leaf
    /// scan is the optimisation `04 §7.4` flags, not required for correctness. Used by the Cypher
    /// executor's all-nodes scan over the real store (`rmp` task #38); label-restricted scans are a
    /// follow-up (#39) since the label-set API does not exist yet.
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

    /// Deletes the node at `id` under `txn` (clearing `in_use`) and frees its physical id. The
    /// caller must have detached the node's relationships first; remaining properties are not
    /// auto-deleted here.
    ///
    /// # Errors
    /// Returns a storage error if the node is not in use or the write fails.
    pub fn delete_node(&mut self, txn: TxnId, id: u64) -> Result<()> {
        let mut rec = self.read_node(id)?;
        if !rec.mvcc.in_use() {
            return Err(GraphusError::Storage(format!("node {id} is not in use")));
        }
        rec.mvcc = MvccHeader::default(); // clears in_use
        self.write_node(id, &rec, txn)?;
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
        if !node.mvcc.in_use() {
            return Err(GraphusError::Storage(format!("node {id} not in use")));
        }
        node.labels = labels::encode_set(label_token_ids).map_err(GraphusError::from)?;
        self.write_node(id, &node, txn)
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
        if !node.mvcc.in_use() {
            return Err(GraphusError::Storage(format!("node {id} not in use")));
        }
        let next = labels::with_label(node.labels, label_token_id).map_err(GraphusError::from)?;
        if next == node.labels {
            return Ok(()); // already present: no write, no WAL churn
        }
        node.labels = next;
        self.write_node(id, &node, txn)
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
        if !node.mvcc.in_use() {
            return Err(GraphusError::Storage(format!("node {id} not in use")));
        }
        let next =
            labels::without_label(node.labels, label_token_id).map_err(GraphusError::from)?;
        if next == node.labels {
            return Ok(()); // already absent: no write
        }
        node.labels = next;
        self.write_node(id, &node, txn)
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
        if !start_node.mvcc.in_use() {
            return Err(GraphusError::Storage(format!(
                "start node {start} not in use"
            )));
        }
        let id = self.alloc_id(StoreKind::Rel);
        let eid = self.element_ids.alloc();
        let mut rel = RelRecord::new(eid, txn.0, type_id, start, end);

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
            return Ok((id, eid));
        }

        let mut end_node = self.read_node(end)?;
        if !end_node.mvcc.in_use() {
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

    /// Deletes relationship `id` under `txn`, unlinking it from both endpoints' incidence chains
    /// (or the single chain twice, for a self-loop), **freeing its property chain** (every property
    /// record and any `strings.store` overflow chain those properties own, `rmp` task #44; no leak),
    /// and freeing its physical id (`04 §2.4`, `04 §2.7`).
    ///
    /// Freeing the property chain mirrors what `DELETE`/`DETACH DELETE` requires of a relationship:
    /// a deleted relationship leaves no live property records nor live overflow blocks behind (the
    /// no-leak invariant the regression tests assert via [`heap_block_usage`](Self::heap_block_usage)
    /// and the consistency checker's free-list pass). Unlike `delete_node` — whose property chain the
    /// executor clears explicitly before deletion — `delete_rel` owns its relationship's properties
    /// outright, so it frees them here.
    ///
    /// # Errors
    /// Returns a storage error if the relationship is not in use or a write fails.
    pub fn delete_rel(&mut self, txn: TxnId, id: u64) -> Result<()> {
        let rel = self.read_rel(id)?;
        if !rel.mvcc.in_use() {
            return Err(GraphusError::Storage(format!("rel {id} is not in use")));
        }
        // Free the relationship's property chain first (records + overflow chains), so a deleted
        // relationship leaves nothing live behind (`rmp` task #44; no leak). This walks and frees the
        // same `first_prop`-rooted chain the node path frees via `clear_node_properties`.
        let _freed = self.free_rel_property_chain(txn, id, rel.first_prop)?;

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

    /// Frees every live property record in the chain rooted at `first_prop` (and any overflow heap
    /// chain each owns), returning each record's id to the free list (`rmp` task #44; no leak), and
    /// returns the number of live records freed. The owner `rel_id` is used only for the cycle-guard
    /// diagnostic. Shared by [`delete_rel`](Self::delete_rel) and
    /// [`clear_rel_properties`](Self::clear_rel_properties).
    fn free_rel_property_chain(
        &mut self,
        txn: TxnId,
        rel_id: u64,
        first_prop: u64,
    ) -> Result<usize> {
        let mut freed = 0usize;
        let mut cur = first_prop;
        let guard = self.store(StoreKind::Prop).alloc.high_water() + 1;
        let mut steps = 0u64;
        while cur != NULL_ID {
            steps += 1;
            if steps > guard {
                return Err(GraphusError::Storage(format!(
                    "property chain of rel {rel_id} is malformed (cycle?)"
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
        if !node.mvcc.in_use() {
            return Err(GraphusError::Storage(format!("node {node_id} not in use")));
        }
        let pid = self.alloc_id(StoreKind::Prop);
        let mut prop = PropRecord::new(txn.0, key, type_tag, value_inline);
        prop.next_prop = node.first_prop;
        self.write_prop(pid, &prop, txn)?;
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
    /// of that key: it first removes every existing property record for `key` (freeing each one's
    /// overflow chain so nothing leaks, `rmp` task #43), then writes the new value. Inline scalars
    /// (`Integer`/`Float`/`Boolean`) stay inline (#38); `String`/`List` values are serialized to the
    /// `strings.store` overflow heap and the property holds the head block id with the `type_tag`
    /// overflow bit set (`04 §2.3`). Returns the new property's physical id.
    ///
    /// Replacing (rather than merely prepending a shadowing record) keeps the chain compact and is
    /// what guarantees an overwrite frees the old chain — the no-leak invariant the regression tests
    /// assert via [`heap_block_usage`](Self::heap_block_usage).
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
        self.remove_node_property_value(txn, node_id, key)?;
        self.add_node_property(txn, node_id, key, type_tag, value_inline)
    }

    /// Removes node `node_id`'s property `key` under `txn`: unlinks **every** live property record
    /// for `key` from the node's chain, freeing each record's physical id and any overflow heap
    /// chain it owns (`rmp` task #43; no leak). Returns whether anything was removed (so a caller can
    /// distinguish a real removal from a no-op, e.g. for `REMOVE n.p`).
    ///
    /// # Errors
    /// Returns a storage error if the node is not in use or a write fails.
    pub fn remove_node_property_value(
        &mut self,
        txn: TxnId,
        node_id: u64,
        key: u32,
    ) -> Result<bool> {
        let mut node = self.read_node(node_id)?;
        if !node.mvcc.in_use() {
            return Err(GraphusError::Storage(format!("node {node_id} not in use")));
        }
        // Walk the singly-linked chain, rebuilding it without any record whose key matches; free
        // each removed record (and its overflow chain). The chain is short (per-entity), so the
        // O(chain) rewrite is cheap and keeps the structure compact.
        let mut removed_any = false;
        let mut prev: u64 = NULL_ID; // last *kept* property record (NULL => list head is `node`)
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
            let prop = self.read_prop(cur)?;
            let next = prop.next_prop;
            if prop.mvcc.in_use() && prop.key == key {
                // Remove this record: free its overflow chain, splice it out, free its id.
                self.free_property_overflow(txn, &prop)?;
                let mut dead = prop;
                dead.mvcc = MvccHeader::default(); // clears in_use
                dead.next_prop = NULL_ID;
                self.write_prop(cur, &dead, txn)?;
                self.store_mut(StoreKind::Prop).free.push(cur);
                if prev == NULL_ID {
                    node.first_prop = next;
                    self.write_node(node_id, &node, txn)?;
                } else {
                    let mut p = self.read_prop(prev)?;
                    p.next_prop = next;
                    self.write_prop(prev, &p, txn)?;
                }
                removed_any = true;
            } else if prop.mvcc.in_use() {
                prev = cur;
            }
            cur = next;
        }
        Ok(removed_any)
    }

    /// Encodes `value` into the `(type_tag, value_inline)` pair to store in a property record,
    /// allocating an overflow chain for `String`/`List` values.
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
            // Not inline: fall through to the overflow heap (String / List); a class neither the
            // inline codec nor the overflow codec accepts is surfaced by `valenc::encode` below.
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
    /// inline scalars and overflow `String`/`List` values (`rmp` task #43). The chain is walked
    /// head-to-tail; the caller applies newest-wins per key (the chain is prepend-ordered).
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

    /// Clears **all** of node `node_id`'s properties under `txn`, freeing each property record's id
    /// and any overflow heap chain it owns (`rmp` task #43; no leak). Used by `SET n = map`, which
    /// replaces the whole property set. Returns the number of property records removed.
    ///
    /// # Errors
    /// Returns a storage error if the node is not in use or a write fails.
    pub fn clear_node_properties(&mut self, txn: TxnId, node_id: u64) -> Result<usize> {
        let mut node = self.read_node(node_id)?;
        if !node.mvcc.in_use() {
            return Err(GraphusError::Storage(format!("node {node_id} not in use")));
        }
        let mut removed = 0usize;
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
            let prop = self.read_prop(cur)?;
            let next = prop.next_prop;
            if prop.mvcc.in_use() {
                self.free_property_overflow(txn, &prop)?;
                let mut dead = prop;
                dead.mvcc = MvccHeader::default();
                dead.next_prop = NULL_ID;
                self.write_prop(cur, &dead, txn)?;
                self.store_mut(StoreKind::Prop).free.push(cur);
                removed += 1;
            }
            cur = next;
        }
        node.first_prop = NULL_ID;
        self.write_node(node_id, &node, txn)?;
        Ok(removed)
    }

    /// Frees the overflow heap chain a property record owns, if any: a no-op for an inline scalar;
    /// for an overflowed `String`/`List` it frees the chain whose head is `value_inline`
    /// (`rmp` task #43). Used when a property value is overwritten or removed so its old bytes are
    /// not leaked.
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
    // heap for `String`/`List` values (`rmp` task #43) and the same prepend-chain + newest-wins
    // discipline. Every write is WAL-logged and crash-recoverable through the same ARIES machinery
    // (`04 §4`). Index seeks + MVCC over these chains remain `rmp` task #39, untouched here.

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
        if !rel.mvcc.in_use() {
            return Err(GraphusError::Storage(format!("rel {rel_id} not in use")));
        }
        let pid = self.alloc_id(StoreKind::Prop);
        let mut prop = PropRecord::new(txn.0, key, type_tag, value_inline);
        prop.next_prop = rel.first_prop;
        self.write_prop(pid, &prop, txn)?;
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
    /// value of that key (`rmp` task #44): it first removes every existing property record for `key`
    /// (freeing each one's overflow chain so nothing leaks, `rmp` task #43), then writes the new
    /// value. Inline scalars (`Integer`/`Float`/`Boolean`) stay inline (#38); `String`/`List` values
    /// overflow to the `strings.store` heap with the `type_tag` overflow bit set (`04 §2.3`). Returns
    /// the new property's physical id. The relationship analogue of
    /// [`set_node_property_value`](Self::set_node_property_value).
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
        self.remove_rel_property_value(txn, rel_id, key)?;
        self.add_rel_property(txn, rel_id, key, type_tag, value_inline)
    }

    /// Removes relationship `rel_id`'s property `key` under `txn`: unlinks **every** live property
    /// record for `key` from the relationship's chain, freeing each record's id and any overflow heap
    /// chain it owns (`rmp` task #44; no leak). Returns whether anything was removed (so `REMOVE r.p`
    /// can distinguish a real removal from a no-op). The relationship analogue of
    /// [`remove_node_property_value`](Self::remove_node_property_value).
    ///
    /// # Errors
    /// Returns a storage error if the relationship is not in use or a write fails.
    pub fn remove_rel_property_value(&mut self, txn: TxnId, rel_id: u64, key: u32) -> Result<bool> {
        let mut rel = self.read_rel(rel_id)?;
        if !rel.mvcc.in_use() {
            return Err(GraphusError::Storage(format!("rel {rel_id} not in use")));
        }
        // Walk the singly-linked chain, rebuilding it without any record whose key matches; free each
        // removed record (and its overflow chain). Mirrors `remove_node_property_value`.
        let mut removed_any = false;
        let mut prev: u64 = NULL_ID; // last *kept* property record (NULL => list head is the rel)
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
            let prop = self.read_prop(cur)?;
            let next = prop.next_prop;
            if prop.mvcc.in_use() && prop.key == key {
                // Remove this record: free its overflow chain, splice it out, free its id.
                self.free_property_overflow(txn, &prop)?;
                let mut dead = prop;
                dead.mvcc = MvccHeader::default(); // clears in_use
                dead.next_prop = NULL_ID;
                self.write_prop(cur, &dead, txn)?;
                self.store_mut(StoreKind::Prop).free.push(cur);
                if prev == NULL_ID {
                    rel.first_prop = next;
                    self.write_rel(rel_id, &rel, txn)?;
                } else {
                    let mut p = self.read_prop(prev)?;
                    p.next_prop = next;
                    self.write_prop(prev, &p, txn)?;
                }
                removed_any = true;
            } else if prop.mvcc.in_use() {
                prev = cur;
            }
            cur = next;
        }
        Ok(removed_any)
    }

    /// Collects relationship `rel_id`'s live properties as `(physical_id, key_token, Value)`, decoding
    /// both inline scalars and overflow `String`/`List` values (`rmp` task #44). The chain is walked
    /// head-to-tail; the caller applies newest-wins per key (the chain is prepend-ordered). The
    /// relationship analogue of [`node_property_values`](Self::node_property_values).
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

    /// Clears **all** of relationship `rel_id`'s properties under `txn`, freeing each property
    /// record's id and any overflow heap chain it owns (`rmp` task #44; no leak). Used by `SET r =
    /// map`, which replaces the whole property set, and shares the chain-freeing helper with
    /// [`delete_rel`](Self::delete_rel). Returns the number of property records removed. The
    /// relationship analogue of [`clear_node_properties`](Self::clear_node_properties).
    ///
    /// # Errors
    /// Returns a storage error if the relationship is not in use or a write fails.
    pub fn clear_rel_properties(&mut self, txn: TxnId, rel_id: u64) -> Result<usize> {
        let mut rel = self.read_rel(rel_id)?;
        if !rel.mvcc.in_use() {
            return Err(GraphusError::Storage(format!("rel {rel_id} not in use")));
        }
        // Free the whole `first_prop`-rooted chain (records + overflow chains), then null the head
        // pointer so the relationship has no properties (`rmp` task #44; no leak).
        let removed = self.free_rel_property_chain(txn, rel_id, rel.first_prop)?;
        rel.first_prop = NULL_ID;
        self.write_rel(rel_id, &rel, txn)?;
        Ok(removed)
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

    /// The device `PageId`s this store currently maps (the metadata page plus every allocated
    /// record-store page). Used by Deterministic Simulation Testing to snapshot the on-disk image
    /// after a (partial) flush so a crash + recovery can be exercised against a real disk state
    /// (`04 §11`).
    #[must_use]
    pub fn mapped_pages(&self) -> Vec<PageId> {
        let mut pages = vec![META_PAGE];
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
}
