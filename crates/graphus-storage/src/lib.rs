//! `graphus-storage` — the custom record store with **index-free adjacency**, MVCC-native record
//! headers, tokens and stable element-id mapping for Graphus (`specification/04-technical-design.md`
//! §2; `specification/05-storage-format.md` §6–§7).
//!
//! This crate is the durability core's record layer. It lays nodes, relationships and properties
//! out as fixed-size records in paged stores ([`record`], [`paging`]), threads each relationship
//! into two doubly-linked incidence chains so adjacency is a constant-time pointer chase with no
//! index probe ([`store`]), and makes every mutation crash-safe by logging it to the ARIES WAL
//! and modifying pages through the buffer pool under **steal + no-force** ([`store`],
//! [`recovery`]).
//!
//! ## Building blocks
//!
//! - [`graphus_io::BlockDevice`] — page-granular synchronous I/O (and the DST device).
//! - [`graphus_bufpool::BufferPool`] — the page cache; its [`WalRule`](graphus_bufpool::WalRule)
//!   is wired to the WAL by [`wal_rule::SharedWal`] so a dirty page is never written home before
//!   the log is durable through its `page_lsn` (`04 §4.3`).
//! - [`graphus_wal::WalManager`] — the ARIES log; mutations append redo/undo intra-page patches
//!   and recovery replays them ([`recovery::recover_device`]).
//!
//! ## Read polarity (`rmp` task #905)
//!
//! Every read in this crate returns **raw physical state**: the slot's current contents, MVCC
//! tombstones the GC has not reclaimed included, versions whose writer has not committed included,
//! and — for labels, which are mutated in place — a word a rollback will change back. That is not a
//! defect, it is the layer's contract; deciding what a version means belongs above it.
//!
//! What the caller owes back is one of **three** different answers, and using the wrong one is the
//! single mistake behind `rmp` tasks #771, #902 and #904. [`scan_polarity`] states the three
//! obligations, and separates the first two in the type system: a decision-grade read takes the
//! deciding [`Snapshot`](graphus_txn::Snapshot) and returns a
//! [`DecidedProperties`](scan_polarity::DecidedProperties) that has no other constructor, while the
//! raw [`SupersetProperties`](scan_polarity::SupersetProperties) cannot be walked without naming
//! the polarity out loud. Read that module before adding a read, and before *changing* one: the
//! docstrings it replaced asserted the wrong polarity and were believed.
//!
//! ## Frozen layouts
//!
//! The 25-byte MVCC record header (`05 §7`) and the type-specific record tails (`04 §2.3`) are
//! frozen as the size constants in [`record`]; the 24-byte page header is owned by
//! [`graphus_bufpool::page`]. Record `i` of a store lives at byte `24 + (i % records_per_page) *
//! record_size` of store-relative page `i / records_per_page` ([`paging`]). Physical id `0` is the
//! reserved null pointer; real records start at id `1` (`04 §2.2`).
//!
//! ## Typical lifecycle
//!
//! ```
//! use graphus_io::MemBlockDevice;
//! use graphus_wal::{MemLogSink, WalManager};
//! use graphus_storage::{RecordStore, recovery};
//! use graphus_core::TxnId;
//!
//! // Create a store on a fresh in-memory device + log.
//! let device = MemBlockDevice::new(0);
//! let wal = WalManager::create(MemLogSink::new()).unwrap();
//! let mut store = RecordStore::create(device, wal, 64, 1).unwrap();
//!
//! // A committed transaction: two nodes and an edge between them.
//! let txn = TxnId(1);
//! store.begin(txn);
//! let (a, _) = store.create_node(txn).unwrap();
//! let (b, _) = store.create_node(txn).unwrap();
//! let rt = store.intern_token(graphus_storage::Namespace::RelType, "KNOWS").unwrap();
//! let (_r, _) = store.create_rel(txn, rt, a, b).unwrap();
//! store.commit(txn).unwrap();
//!
//! // Index-free adjacency: a and b are each incident to exactly one relationship.
//! assert_eq!(store.degree(a).unwrap(), 1);
//! assert_eq!(store.degree(b).unwrap(), 1);
//! ```
#![forbid(unsafe_code)]

pub mod backup;
pub mod check;
pub mod dwb;
pub mod heap;
pub mod idalloc;
pub mod incremental;
pub mod labels;
pub mod meta;
pub mod paging;
pub mod propenc;
pub mod read_probe;
pub mod read_view;
pub mod record;
pub mod recovery;
pub mod scan_polarity;
pub mod store;
pub mod tokens;
pub mod undo;
pub mod valenc;
pub mod wal_rule;

pub use backup::{
    BACKUP_FORMAT_VERSION, BACKUP_MAGIC, backup_creation_marker, backup_store, restore,
    restore_file_atomic, restore_onto, verify_backup,
};
pub use check::{
    AdjacencyFault, AgreementFault, ConsistencyReport, FreeListFault, HeapChainFault,
    IndexAgreement, IndexEntry, LabelBitmapFault, PropertyFault, UndoChainFault, UndoSlotFault,
    Violation, verify_on_open, verify_warm,
};
pub use dwb::{DWB_EVICT_RING_SLOTS, DWB_MAX_BATCH, Dwb, DwbPageStager, dwb_device_pages};
/// The page-header codec (checksum / `page_id` / `page_lsn` / type accessors) the storage layer
/// stamps on every device page, re-exported from `graphus_bufpool` so callers above this crate
/// (the server's recovery/repair tests, offline tools) can inspect on-disk page headers without a
/// direct dependency on the buffer-pool crate.
pub use graphus_bufpool::page;
/// The live, append-only, lock-free device-page map behind every store's location oracle
/// (`rmp` #721), re-exported from the leaf `graphus-pagemap` crate so callers above this crate reach it
/// without a direct dependency.
pub use graphus_pagemap::{PageMap, PageMapWriter};
pub use heap::{BLOCK_PAYLOAD, HeapBlock, STRINGS_RECORD_SIZE};
pub use idalloc::{
    AllocGuard, Allocation, ElementIdAllocator, FreeList, NULL_ID, PhysicalAllocator,
    SharedReuseBarrier, StoreAllocator,
};
pub use incremental::{
    CHAIN_FORMAT_VERSION, ChainArtifact, ChainLinks, ChainManifest, IncrementMeta, LinkCodec,
    Plain, RestoreOutcome, RestoreTarget, begin_chain, capture_increment,
    restore_chain_file_atomic, restore_to, verify_chain,
};
pub use labels::{LabelError, MAX_INLINE_LABEL_ID, OVERFLOW_BIT};
pub use meta::{
    CompositeIndexEntry, ConstraintEntry, ConstraintKind, ConstraintTypeDescriptor, FulltextEntity,
    FulltextIndexEntry, IndexState, Meta, RelCompositeIndexEntry, SpatialEntity, SpatialIndexEntry,
    Statistics, StoreMeta, TextIndexEntry, VectorEntity, VectorIndexEntry, VectorSimilarity,
};
pub use propenc::{
    PropDecodeError, PropEncodeError, TAG_BOOL, TAG_FLOAT, TAG_INT, decode_inline, encode_inline,
};
pub use read_view::{MetaSnapshot, StoreMetaSnapshot, StorePages, StoreReadView};
pub use record::{
    ChainSide, MVCC_HEADER_SIZE, MvccHeader, NODE_RECORD_SIZE, NodeRecord, PROP_RECORD_SIZE,
    PropRecord, REL_RECORD_SIZE, RelRecord,
};
/// The read-polarity taxonomy (`rmp` task #905): which of superset / decision / conservative a
/// storage read is required to answer, and the two types that keep the first two apart — plus the
/// candidate type both deal in since the property path moved onto the undo chain (`rmp` #967).
pub use scan_polarity::{
    CandidateSource, DecidedProperties, DeltaVerdict, PropertyCandidate, PropertyDelta,
    SupersetProperties,
};
pub use store::{
    DEFAULT_CHECKPOINT_INTERVAL_BYTES, DeadIndexKey, DirectionalRelCounts, FreezeFrontierViolation,
    GcPassReport, IndexInterest, META_PAGE, RecordStore, STORE_COUNT, StoreKind,
};
pub use tokens::{Namespace, TokenSnapshot, TokenStore};
/// The undo area (`05-storage-format.md` §12, `rmp` #966): the delta record that carries the inverse
/// of one change to one entity, and the per-transaction commit-info slot every delta resolves its
/// commit status through.
pub use undo::{
    COMMIT_RECORD_SIZE, CommitSlot, IncidentDirection, UNDO_RECORD_SIZE, UndoAction, UndoDelta,
};
pub use valenc::{
    OVERFLOW_BIT as PROP_OVERFLOW_BIT, TAG_DATE, TAG_DURATION, TAG_LIST, TAG_LOCAL_DATE_TIME,
    TAG_LOCAL_TIME, TAG_STRING, TAG_ZONED_DATE_TIME, TAG_ZONED_TIME, ValueDecodeError,
    ValueEncodeError,
};
pub use wal_rule::SharedWal;
