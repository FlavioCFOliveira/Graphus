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

use crate::idalloc::{ElementIdAllocator, FreeList, NULL_ID, PhysicalAllocator};
use crate::meta::{Meta, StoreMeta};
use crate::paging;
use crate::record::{
    CHAIN_FLAG_END_FIRST, CHAIN_FLAG_START_FIRST, ChainSide, MvccHeader, NODE_RECORD_SIZE,
    NodeRecord, PROP_RECORD_SIZE, PropRecord, REL_RECORD_SIZE, RelRecord,
};
use crate::tokens::{Namespace, TokenStore};
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

/// Which of the three fixed-record stores a record id belongs to (`04 §2.1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    /// The node store (`nodes.store`).
    Node = 0,
    /// The relationship store (`rels.store`).
    Rel = 1,
    /// The property store (`props.store`).
    Prop = 2,
}

impl StoreKind {
    /// The fixed record size of this store in bytes.
    #[must_use]
    pub fn record_size(self) -> usize {
        match self {
            StoreKind::Node => NODE_RECORD_SIZE,
            StoreKind::Rel => REL_RECORD_SIZE,
            StoreKind::Prop => PROP_RECORD_SIZE,
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
    stores: [FixedStore; 3],
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
        let device_pages: [Vec<PageId>; 3] = [
            self.stores[0].device_pages.clone(),
            self.stores[1].device_pages.clone(),
            self.stores[2].device_pages.clone(),
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
    /// (or the single chain twice, for a self-loop) and freeing its physical id (`04 §2.4`,
    /// `04 §2.7`).
    ///
    /// # Errors
    /// Returns a storage error if the relationship is not in use or a write fails.
    pub fn delete_rel(&mut self, txn: TxnId, id: u64) -> Result<()> {
        let rel = self.read_rel(id)?;
        if !rel.mvcc.in_use() {
            return Err(GraphusError::Storage(format!("rel {id} is not in use")));
        }
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
        dead.mvcc = MvccHeader::default();
        self.write_rel(id, &dead, txn)?;
        self.store_mut(StoreKind::Rel).free.push(id);
        Ok(())
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
}

/// Which neighbour pointer is being repaired during an unlink.
#[derive(Clone, Copy)]
enum NeighbourPtr {
    Prev,
    Next,
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
