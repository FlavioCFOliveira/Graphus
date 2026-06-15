//! The offline **consistency checker** and the **startup integrity hook** (`04-technical-design.md`
//! §4.6, "integrity is inviolable; we never serve a page we cannot trust").
//!
//! Graphus's first inviolable mandate is *never corrupt* (`CLAUDE.md`): a store that is internally
//! inconsistent must never be served. This module provides a **pure, read-only** pass over a
//! [`RecordStore`] (and, optionally, indexes built over it) that collects **every** structural
//! violation it can find — it never stops at the first — and a startup hook,
//! [`verify_on_open`], that runs the pass and **refuses to serve** (returns an error) if any
//! violation is present, taking the store to a safe stopped state (`04 §4.6`/§4.8 startup).
//!
//! # What is checked
//!
//! 1. **Checksum & page identity** ([`Violation::Checksum`], [`Violation::PageId`], `04 §4.6`,
//!    `05 §6`): every mapped page (the metadata page plus every allocated record-store page) passes
//!    its CRC32C, and each page's self-referential `page_id` header equals its device location.
//! 2. **Adjacency well-formedness** ([`Violation::Adjacency`], `04 §2.3`–§2.4): every live
//!    relationship is threaded into **both** endpoints' incidence chains; the doubly-linked
//!    `(rel, side)` links are mutually consistent (each link's `next` has a matching-side successor
//!    whose `prev` points back; a head link has `prev == 0`); no chain references a freed,
//!    out-of-range or dead record (no dangling rel ids); a self-loop appears twice in the one chain
//!    and is deduped to degree 1; and the chain-walked incidence of every node matches an
//!    independent re-derivation from the live relationships.
//! 3. **Referential integrity** ([`Violation::Referential`], [`Violation::PropertyChain`]): every
//!    live relationship's `start_node`/`end_node` reference live, in-use node records; every entity's
//!    property chain terminates (cycle-guarded), references only in-use property records, and
//!    `first_prop`/`next_prop` stay in range. *Entity* here is both nodes **and relationships**: a
//!    relationship's property chain (rooted at [`RelRecord::first_prop`](crate::record::RelRecord),
//!    `rmp` task #44) is walked by the very same property-chain pass as a node's, and its overflow
//!    chains by the heap-chain / free-list passes — no relationship-specific code, because
//!    relationship and node properties share the one `props.store` and `strings.store`.
//! 4. **Store/index agreement** ([`Violation::IndexAgreement`]): see [`IndexAgreement`] for the
//!    exact (and deliberately scoped) properties verified.
//! 5. **Free-list sanity** ([`Violation::FreeList`], `04 §2.7`): no freed id is in use or referenced
//!    by a live chain; freed ids are in range and not duplicated; and every store's free list and
//!    high-water mark are mutually consistent.
//! 6. **Label-bitmap well-formedness** ([`Violation::LabelBitmap`], `05 §9`, `rmp` task #42): every
//!    live node's `labels` bitmap has its overflow flag clear (this build never sets it; the
//!    token-list overflow block is the follow-up #39) and references only `Label`-namespace token
//!    ids that exist in the token store (no dangling label reference).
//! 7. **Overflow-heap-chain well-formedness** ([`Violation::HeapChain`], `04 §2.1`/§2.3,
//!    `rmp` task #43): every live overflow property's `strings.store` block chain has no dangling /
//!    out-of-range / freed block ids and terminates (cycle-guarded). Combined with the free-list
//!    check, this proves a freed heap block is never referenced by a live property.
//!
//! # Termination on a corrupted store
//!
//! A corrupted store can contain a cyclic chain pointer. **Every** chain walk in this module is
//! bounded by a generous guard derived from the store's high-water mark, so the checker always
//! terminates and *reports* a malformed chain rather than looping forever.
//!
//! # Read-only guarantee
//!
//! [`check_store`] takes `&mut RecordStore` only because reading a record pins/unpins a buffer-pool
//! frame; it performs **no logical mutation** — no WAL append, no record write, no catalog change.

use std::collections::{BTreeMap, BTreeSet};

use graphus_bufpool::page;
use graphus_core::error::{GraphusError, Result};
use graphus_core::{PageId, VersionStamp};
use graphus_io::BlockDevice;
use graphus_wal::LogSink;

use crate::heap::{BLOCK_PAYLOAD, HeapBlock};
use crate::idalloc::NULL_ID;
use crate::record::{ChainSide, MvccHeader, NodeRecord, PropRecord, RelRecord};
use crate::store::{RecordStore, STORE_COUNT, StoreKind};
use crate::valenc::OVERFLOW_BIT as PROP_OVERFLOW_BIT;

/// One structural inconsistency found by [`check_store`]. Each variant names the offending ids /
/// pages so an operator (or a test) can pinpoint the fault (`04 §4.6` alerting).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// A mapped page failed CRC32C verification (`04 §4.6`): its body does not match its stored
    /// checksum — torn write or bit-rot. `page` is the device page id.
    Checksum {
        /// The device page that failed verification.
        page: u64,
    },
    /// A page's self-referential `page_id` header (`05 §6`) does not equal its device location:
    /// the page was written to the wrong place or its header is corrupt.
    PageId {
        /// The device page where the page actually lives.
        page: u64,
        /// The `page_id` the header claims.
        stored: u64,
    },
    /// A live record's MVCC header (`05 §7`) is internally inconsistent — a timestamp inversion, a
    /// missing creator, or a dangling `undo_ptr` — which would feed `graphus-txn` visibility
    /// unpredictable inputs (`rmp` storage audit F8).
    MvccHeader {
        /// `StoreKind` of the record whose MVCC header is malformed.
        kind: StoreKind,
        /// Physical id of the offending record.
        id: u64,
        /// Which MVCC-header rule was broken.
        detail: MvccHeaderFault,
    },
    /// An adjacency / incidence-chain invariant was violated (`04 §2.3`–§2.4). `node` is the chain
    /// owner; `rel` the offending relationship (`0` if not link-specific); `detail` the precise rule.
    Adjacency {
        /// The node whose incidence chain is malformed.
        node: u64,
        /// The relationship implicated (`0` when the fault is the node's `first_rel` head).
        rel: u64,
        /// Which adjacency rule was broken.
        detail: AdjacencyFault,
    },
    /// A live relationship references an endpoint node that is not a live, in-use node record.
    Referential {
        /// The relationship with the bad endpoint.
        rel: u64,
        /// The dangling endpoint node id.
        node: u64,
        /// Which side is dangling.
        side: ChainSide,
    },
    /// An entity's property chain is malformed (`04 §2.3`).
    PropertyChain {
        /// `StoreKind` of the chain owner (`Node` or `Rel`).
        owner_kind: StoreKind,
        /// Physical id of the chain owner.
        owner: u64,
        /// Physical id of the offending property record (`0` for the owner's `first_prop` head).
        prop: u64,
        /// Which property-chain rule was broken.
        detail: PropertyFault,
    },
    /// A store/index agreement property was violated (see [`IndexAgreement`]).
    IndexAgreement {
        /// A human-readable name for the index being checked (caller-supplied).
        index: String,
        /// Which agreement rule was broken.
        detail: AgreementFault,
    },
    /// A free-list / id-allocation invariant was violated (`04 §2.7`).
    FreeList {
        /// `StoreKind` of the store whose free list is inconsistent.
        kind: StoreKind,
        /// Physical id implicated (`0` when the fault is not id-specific).
        id: u64,
        /// Which free-list rule was broken.
        detail: FreeListFault,
    },
    /// A live node's label bitmap is malformed (`05 §9`; `rmp` task #42 — node labels).
    LabelBitmap {
        /// The node whose `labels` bitmap is inconsistent.
        node: u64,
        /// Which label-bitmap rule was broken.
        detail: LabelBitmapFault,
    },
    /// An overflow property's `strings.store` block chain is malformed (`04 §2.1`, `04 §2.3`;
    /// `rmp` task #43 — the string/list overflow heap).
    HeapChain {
        /// Physical id of the property record whose overflow chain is malformed.
        prop: u64,
        /// Physical id of the heap block implicated (`0` for the property's `value_inline` head).
        block: u64,
        /// Which heap-chain rule was broken.
        detail: HeapChainFault,
    },
}

/// The precise adjacency rule broken by a [`Violation::Adjacency`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdjacencyFault {
    /// A chain referenced a relationship id outside `1..high_water` (out of range).
    RelOutOfRange,
    /// A chain referenced a freed or dead (not in-use) relationship record (dangling id).
    DeadRel,
    /// A chain link's relationship is not incident to the chain's node on the followed side.
    NotIncident,
    /// The head link's `prev` is not `NULL` (a head must have no predecessor).
    HeadPrevNotNull,
    /// A link's `next` successor's matching-side `prev` does not point back (broken back-link).
    AsymmetricLink,
    /// The chain did not terminate within the cycle guard (a corrupted cycle).
    NonTerminating,
    /// The chain-walked incidence set differs from the independent re-derivation (degree mismatch
    /// or a missing/extra relationship).
    IncidenceMismatch,
}

/// The precise property-chain rule broken by a [`Violation::PropertyChain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyFault {
    /// A `first_prop`/`next_prop` pointer is outside `1..high_water` (out of range).
    PropOutOfRange,
    /// The chain references a property record that is not in use (freed/dead).
    DeadProp,
    /// The chain did not terminate within the cycle guard (a corrupted cycle).
    NonTerminating,
}

/// The precise store/index agreement rule broken by a [`Violation::IndexAgreement`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgreementFault {
    /// An index entry points at a record id outside `1..high_water` of the indexed store.
    RidOutOfRange {
        /// The dangling record id.
        rid: u64,
    },
    /// An index entry points at a record that is not live / in use.
    DeadRecord {
        /// The dead record id.
        rid: u64,
    },
    /// An index entry is present that the expected model does not contain — i.e. a stale entry whose
    /// indexed value no longer matches the record (or a spurious entry).
    UnexpectedEntry {
        /// The offending record id.
        rid: u64,
    },
    /// An expected entry is missing from the index (a live, indexable record has no entry).
    MissingEntry {
        /// The record id whose entry is missing.
        rid: u64,
    },
}

/// The precise label-bitmap rule broken by a [`Violation::LabelBitmap`] (`05 §9`, `rmp` task #42).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelBitmapFault {
    /// The node's bitmap has the overflow flag ([`OVERFLOW_BIT`](crate::labels::OVERFLOW_BIT)) set,
    /// but this build never writes that flag and the token-list overflow block (#39) is not present,
    /// so the flag is necessarily stale/corrupt. (A future #39 build that legitimately uses the flag
    /// would teach the checker to validate the referenced overflow block instead.)
    OverflowFlagSet,
    /// The node's bitmap sets the bit for a `Label`-namespace token id that does not exist in the
    /// token store (`id >= label_token_count`): a dangling label reference.
    UnknownLabelToken {
        /// The dangling label token id the bitmap references.
        token_id: u32,
    },
}

/// The precise overflow-heap-chain rule broken by a [`Violation::HeapChain`] (`04 §2.1`, `04 §2.3`;
/// `rmp` task #43).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapChainFault {
    /// A `value_inline` head, or a block's `next_block`, references a block id outside
    /// `1..high_water` of `strings.store` (out of range / dangling).
    BlockOutOfRange,
    /// The chain references a freed or dead (not in-use) heap block (dangling-by-reuse).
    DeadBlock,
    /// The chain did not terminate within the cycle guard (a corrupted cycle).
    NonTerminating,
    /// A heap block is reachable from **two** distinct live overflow chains (an aliased block — its
    /// payload would be shared/corrupted between two property values). `other_owner` is the first
    /// property record already found to own the block (`rmp` storage audit F13).
    SharedBlock {
        /// The property record that first claimed this block (the current owner is the
        /// [`Violation::HeapChain::prop`]).
        other_owner: u64,
    },
    /// A block's `len` field exceeds [`BLOCK_PAYLOAD`](crate::heap::BLOCK_PAYLOAD): a corrupt length
    /// that `HeapBlock::bytes` would otherwise clamp silently (`rmp` storage audit F13).
    BlockLenTooLong {
        /// The corrupt `len` value.
        len: u16,
    },
}

/// The precise MVCC-header rule broken by a [`Violation::MvccHeader`] (`05 §7`; `rmp` storage
/// audit F8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MvccHeaderFault {
    /// A live (in-use) record has no creator stamp (`created_ts`/`xmin` is the `0` *none* sentinel):
    /// every committed-or-in-flight version must record who created it.
    NoCreator,
    /// Both `created_ts` (`xmin`) and `expired_ts` (`xmax`) are **committed** timestamps but the
    /// creation timestamp is strictly greater than the expiry timestamp — a version that expired
    /// before it was created (`04 §5.2`). (Mixed in-flight/committed stamps live in disjoint number
    /// spaces and are not compared.)
    TimestampInversion {
        /// The creating transaction's commit timestamp.
        created: u64,
        /// The expiring transaction's commit timestamp.
        expired: u64,
    },
    /// `undo_ptr` (the older-version back-pointer) is non-zero but outside `1..high_water` of the
    /// record's own store — a dangling version-chain pointer (`05 §7`).
    UndoPtrOutOfRange {
        /// The dangling `undo_ptr` value.
        undo_ptr: u64,
    },
}

/// The precise free-list rule broken by a [`Violation::FreeList`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeListFault {
    /// A freed id is `>= high_water` (it was never allocated) or is the reserved null id `0`.
    OutOfRange,
    /// The same id appears more than once on the free list (double-free).
    Duplicate,
    /// A freed id's record is still in use (a live record sitting on the free list).
    StillInUse,
    /// A freed id is referenced by some live incidence/property chain.
    ReferencedByLiveChain,
}

/// One index entry, as enumerated from a live index, for an [`IndexAgreement`] check: the candidate
/// record id the entry points at (`04 §6.2`). An optional `key` carries the encoded index key so a
/// caller can pretty-print, but agreement is checked on `rid` against the caller's expected set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// The candidate record id this entry resolves to.
    pub rid: u64,
    /// The encoded index key (optional context; not required for the rid-level checks).
    pub key: Vec<u8>,
}

impl IndexEntry {
    /// An entry that resolves to `rid` with no key context.
    #[must_use]
    pub fn rid(rid: u64) -> Self {
        Self {
            rid,
            key: Vec::new(),
        }
    }
}

/// A store/index agreement check request (`04 §6.3` index/record consistency).
///
/// # Scope (read carefully — this is the honest boundary)
///
/// The base store records do **not** expose enough to independently re-derive an index key in the
/// general case: a node's `labels` field is an opaque packed `u64`, and a property's `value_inline`
/// is an opaque `u64`/overflow-block id whose original [`Value`](graphus_core::Value) is not
/// reconstructable from the record alone (the string/overflow heap is a deferred task, `04 §2.3`).
/// The checker therefore verifies the two agreement properties it **can** prove soundly:
///
/// * **Index → store (no dangling / dead entries):** every live index entry points at a record id
///   that is in range and **live (in use)** in the indexed store. This is fully store-derived and
///   needs no caller input.
/// * **Index ⇔ expected set (value-match + completeness):** the set of record ids the index
///   actually contains equals the `expected` set the caller derives from the live records it
///   indexed. A *stale* entry whose value no longer matches surfaces as
///   [`AgreementFault::UnexpectedEntry`]; a *missing* entry as [`AgreementFault::MissingEntry`].
///
/// The caller owns the value-to-key mapping (only it knows what each record was indexed under), so
/// `expected` is caller-supplied. Where a caller has no expectation model it may pass `expected:
/// None` to check only the dangling/dead property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexAgreement {
    /// A human-readable name for the index (used in violations).
    pub name: String,
    /// Which store the index's record ids point into.
    pub indexed_store: StoreKind,
    /// The entries enumerated from the live index.
    pub entries: Vec<IndexEntry>,
    /// The record ids the index is expected to contain, derived by the caller from the live records.
    /// `None` skips the value-match/completeness comparison and checks only dangling/dead entries.
    pub expected: Option<BTreeSet<u64>>,
}

/// The structured result of a consistency pass: the collected violations (empty == healthy) plus
/// the live-record counts the pass derived (useful for an operator log).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
pub struct ConsistencyReport {
    /// Every violation found, in checking order. **Empty means the store is consistent.**
    pub violations: Vec<Violation>,
    /// Number of live (in-use, not freed) node records.
    pub live_nodes: u64,
    /// Number of live relationship records.
    pub live_rels: u64,
    /// Number of live property records.
    pub live_props: u64,
    /// Number of live `strings.store` overflow-heap blocks (`rmp` task #43).
    pub live_blocks: u64,
}

impl ConsistencyReport {
    /// Whether the store passed (no violations).
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.violations.is_empty()
    }

    fn push(&mut self, v: Violation) {
        self.violations.push(v);
    }
}

/// Runs the full **read-only** consistency pass over `store`, plus the store/index agreement checks
/// for each entry of `indexes`. Collects **all** violations (does not stop at the first).
///
/// Pass an empty `indexes` slice to check the store alone.
///
/// # Errors
/// All structural inconsistencies — including unreadable/corrupt pages and unreadable records — are
/// **reported in the [`ConsistencyReport`]**, never returned as `Err`: a corrupt page surfaces as a
/// [`Violation::Checksum`] and its records are skipped, so the pass always completes and collects
/// the full violation set. An `Err` is reserved for a hard I/O failure of one of the sub-passes
/// (none of which can fail on the in-memory or file devices in normal operation).
pub fn check_store<D: BlockDevice, S: LogSink>(
    store: &mut RecordStore<D, S>,
    indexes: &[IndexAgreement],
) -> Result<ConsistencyReport> {
    let mut report = ConsistencyReport::default();

    // Snapshot the catalog the checks need (read-only).
    let cat = Catalog::snapshot(store);

    check_checksums_and_page_ids(store, &cat, &mut report)?;
    let scan = scan_records(store, &cat, &mut report)?;
    report.live_nodes = scan.live_nodes.len() as u64;
    report.live_rels = scan.live_rels.len() as u64;
    report.live_props = scan.live_props.len() as u64;
    report.live_blocks = scan.live_blocks.len() as u64;

    check_referential(&scan, &mut report);
    check_property_chains(store, &cat, &scan, &mut report)?;
    check_adjacency(store, &cat, &scan, &mut report)?;
    check_heap_chains(&cat, &scan, &mut report);
    check_mvcc_headers(&cat, &scan, &mut report);
    check_free_lists(&cat, &scan, &mut report);
    check_label_bitmaps(&cat, &scan, &mut report);

    for ix in indexes {
        check_index_agreement(&scan, ix, &mut report);
    }

    Ok(report)
}

/// The **startup integrity hook** (`04 §4.6`/§4.8): runs [`check_store`] and **refuses to serve**
/// (returns `Err`) if the store is inconsistent, taking it to a safe stopped state. A consistent
/// store returns `Ok(())`.
///
/// Call this immediately after [`RecordStore::open`] (post-recovery), before accepting any client
/// work. The error message names how many violations were found and the first one, so the operator
/// alert is actionable; the full set is available via [`check_store`] for diagnostics.
///
/// # Errors
/// Returns [`GraphusError::Storage`] if any violation is found, or propagates a hard I/O failure
/// from [`check_store`].
pub fn verify_on_open<D: BlockDevice, S: LogSink>(
    store: &mut RecordStore<D, S>,
    indexes: &[IndexAgreement],
) -> Result<()> {
    let report = check_store(store, indexes)?;
    if report.is_consistent() {
        return Ok(());
    }
    Err(GraphusError::Storage(format!(
        "integrity check failed: {} violation(s), refusing to serve (first: {:?})",
        report.violations.len(),
        report.violations[0]
    )))
}

// ===========================================================================================
// Internal machinery
// ===========================================================================================

/// A read-only snapshot of the per-store catalog the checker needs.
struct Catalog {
    high_water: [u64; STORE_COUNT],
    free: [Vec<u64>; STORE_COUNT],
    pages: Vec<PageId>,
    /// Number of interned `Label`-namespace tokens; valid label token ids are `0..label_token_count`
    /// (`04 §2.6`). Used to flag a node label bitmap that references a non-existent label (#42).
    label_token_count: usize,
}

impl Catalog {
    fn snapshot<D: BlockDevice, S: LogSink>(store: &RecordStore<D, S>) -> Self {
        Self {
            high_water: [
                store.checker_high_water(StoreKind::Node),
                store.checker_high_water(StoreKind::Rel),
                store.checker_high_water(StoreKind::Prop),
                store.checker_high_water(StoreKind::Strings),
            ],
            free: [
                store.checker_free_ids(StoreKind::Node),
                store.checker_free_ids(StoreKind::Rel),
                store.checker_free_ids(StoreKind::Prop),
                store.checker_free_ids(StoreKind::Strings),
            ],
            pages: store.mapped_pages(),
            label_token_count: store.checker_label_token_count(),
        }
    }

    fn high_water(&self, kind: StoreKind) -> u64 {
        self.high_water[kind as usize]
    }

    fn free(&self, kind: StoreKind) -> &[u64] {
        &self.free[kind as usize]
    }
}

/// The live-record picture derived by a single forward scan of every store.
struct Scan {
    /// Live (in-use, not freed) node ids -> their record.
    live_nodes: BTreeMap<u64, NodeRecord>,
    /// Live relationship ids -> their record.
    live_rels: BTreeMap<u64, RelRecord>,
    /// **Dead-link corpse** relationship ids -> their record (`rmp` #220): slots that are `!in_use`
    /// and NOT on the free list, left by an aborted/crashed relationship creation whose header-only
    /// creation undo cleared the in-use bit while PRESERVING the body's forward chain pointers. They
    /// are transparently threaded THROUGH by [`RecordStore::incident_rels`] until GC splices them out;
    /// the adjacency check must thread through them the same way rather than flag a broken chain.
    corpse_rels: BTreeMap<u64, RelRecord>,
    /// Live property ids -> their record.
    live_props: BTreeMap<u64, PropRecord>,
    /// Live `strings.store` overflow-heap block ids -> their block (`rmp` task #43).
    live_blocks: BTreeMap<u64, HeapBlock>,
    /// Freed ids per store (from the catalog), as a set for O(log n) membership.
    freed: [BTreeSet<u64>; STORE_COUNT],
    /// Per-store ids that are on the free list yet whose on-disk record still reads `in_use` — a
    /// contradiction the free-list check reports as [`FreeListFault::StillInUse`].
    freed_but_in_use: [BTreeSet<u64>; STORE_COUNT],
}

impl Scan {
    fn is_live(&self, kind: StoreKind, id: u64) -> bool {
        match kind {
            StoreKind::Node => self.live_nodes.contains_key(&id),
            StoreKind::Rel => self.live_rels.contains_key(&id),
            StoreKind::Prop => self.live_props.contains_key(&id),
            StoreKind::Strings => self.live_blocks.contains_key(&id),
        }
    }
}

/// Scans every store `1..high_water`, classifying records as live or not, and recording the freed
/// sets. A freed id whose record still reads `in_use` is **not** counted live (the free list is
/// authoritative for "this slot is dead"); that contradiction is reported by the free-list check.
fn scan_records<D: BlockDevice, S: LogSink>(
    store: &mut RecordStore<D, S>,
    cat: &Catalog,
    _report: &mut ConsistencyReport,
) -> Result<Scan> {
    let freed: [BTreeSet<u64>; STORE_COUNT] = [
        cat.free(StoreKind::Node).iter().copied().collect(),
        cat.free(StoreKind::Rel).iter().copied().collect(),
        cat.free(StoreKind::Prop).iter().copied().collect(),
        cat.free(StoreKind::Strings).iter().copied().collect(),
    ];

    // A per-record read can fail if the record's page is corrupt (checksum). That page is already
    // reported by `check_checksums_and_page_ids`; here we simply skip the unreadable record so the
    // pass completes and collects the rest of the violations rather than aborting. Freed ids are
    // *not* counted live, but they are still read so that a freed slot whose record contradicts the
    // free list (still `in_use`) is caught (`FreeListFault::StillInUse`).
    let mut freed_but_in_use: [BTreeSet<u64>; STORE_COUNT] = Default::default();

    let mut live_nodes = BTreeMap::new();
    for id in 1..cat.high_water(StoreKind::Node) {
        let Ok(rec) = store.node(id) else { continue };
        if freed[StoreKind::Node as usize].contains(&id) {
            if rec.mvcc.in_use() {
                freed_but_in_use[StoreKind::Node as usize].insert(id);
            }
        } else if rec.mvcc.in_use() {
            live_nodes.insert(id, rec);
        }
    }

    let mut live_rels = BTreeMap::new();
    let mut corpse_rels = BTreeMap::new();
    for id in 1..cat.high_water(StoreKind::Rel) {
        let Ok(rec) = store.rel(id) else { continue };
        if freed[StoreKind::Rel as usize].contains(&id) {
            if rec.mvcc.in_use() {
                freed_but_in_use[StoreKind::Rel as usize].insert(id);
            }
        } else if rec.mvcc.in_use() {
            live_rels.insert(id, rec);
        } else {
            // !in_use and not on the free list: a dead-link corpse the adjacency walk threads through.
            corpse_rels.insert(id, rec);
        }
    }

    let mut live_props = BTreeMap::new();
    for id in 1..cat.high_water(StoreKind::Prop) {
        let Ok(rec) = store.property(id) else {
            continue;
        };
        if freed[StoreKind::Prop as usize].contains(&id) {
            if rec.mvcc.in_use() {
                freed_but_in_use[StoreKind::Prop as usize].insert(id);
            }
        } else if rec.mvcc.in_use() {
            live_props.insert(id, rec);
        }
    }

    // The `strings.store` overflow heap (`rmp` task #43): heap blocks are fixed-size records with the
    // same MVCC `in_use` discipline, so they are scanned identically.
    let mut live_blocks = BTreeMap::new();
    for id in 1..cat.high_water(StoreKind::Strings) {
        let Ok(block) = store.checker_block(id) else {
            continue;
        };
        if freed[StoreKind::Strings as usize].contains(&id) {
            if block.mvcc.in_use() {
                freed_but_in_use[StoreKind::Strings as usize].insert(id);
            }
        } else if block.mvcc.in_use() {
            live_blocks.insert(id, block);
        }
    }

    Ok(Scan {
        corpse_rels,
        live_nodes,
        live_rels,
        live_props,
        live_blocks,
        freed,
        freed_but_in_use,
    })
}

/// 1. Checksum integrity & page identity (`04 §4.6`, `05 §6`).
fn check_checksums_and_page_ids<D: BlockDevice, S: LogSink>(
    store: &mut RecordStore<D, S>,
    cat: &Catalog,
    report: &mut ConsistencyReport,
) -> Result<()> {
    for &p in &cat.pages {
        match store.read_device_page(p) {
            // `read_device_page` goes through the pool's `fetch`, which verifies the CRC32C on a
            // disk read and returns `Err` on a mismatch (`04 §4.6`). A freshly-opened store has a
            // cold pool, so this hits the disk and verifies — exactly the startup scenario in which
            // `verify_on_open` runs. We treat that `Err` as the checksum violation it reports (the
            // page is in range and the device is readable; the only failure mode here is the
            // verification the pool performs on the disk read).
            //
            // Note (documented scope): a page that is *resident and dirty* in the pool is returned
            // from cache without a disk read, so its on-disk image is not re-verified here. This
            // check is therefore meaningful against the **durable** image — i.e. right after
            // [`RecordStore::open`], which is the only place the startup hook runs. We do not
            // re-verify the cached bytes, because a dirty cached page legitimately carries a stale
            // checksum field until write-back, which would be a false positive.
            Err(_) => report.push(Violation::Checksum { page: p.0 }),
            Ok(bytes) => {
                let stored = page::page_id(&bytes);
                if stored != p.0 {
                    report.push(Violation::PageId { page: p.0, stored });
                }
                // NOTE: the page-type header byte (`05 §6`) is deliberately NOT validated here. It is
                // set in memory at allocation but is not part of the WAL redo image, so a crash +
                // ARIES recovery legitimately reconstructs pages with a zero type byte; it is also
                // never read to interpret a page (records are located by store-kind arithmetic, not by
                // page_type), so it is not load-bearing. Enforcing it would require making it
                // recovery-durable for no correctness benefit (storage audit F8: page-type sub-check
                // intentionally not implemented).
            }
        }
    }
    Ok(())
}

/// 3a. Referential integrity of relationship endpoints (`04 §2.3`).
fn check_referential(scan: &Scan, report: &mut ConsistencyReport) {
    for (&rid, rel) in &scan.live_rels {
        for (side, node) in [
            (ChainSide::Start, rel.start_node),
            (ChainSide::End, rel.end_node),
        ] {
            if !scan.is_live(StoreKind::Node, node) {
                report.push(Violation::Referential {
                    rel: rid,
                    node,
                    side,
                });
            }
        }
    }
}

/// 3b. Property-chain integrity for both nodes and relationships (`04 §2.3`; `rmp` task #44 wires
/// relationship properties to the same `props.store` chain, so the relationship pass below is the
/// identical walk over [`RelRecord::first_prop`](crate::record::RelRecord) as the node pass over
/// `NodeRecord.first_prop`).
fn check_property_chains<D: BlockDevice, S: LogSink>(
    _store: &mut RecordStore<D, S>,
    cat: &Catalog,
    scan: &Scan,
    report: &mut ConsistencyReport,
) -> Result<()> {
    let prop_hw = cat.high_water(StoreKind::Prop);
    // Generous guard: a well-formed chain has at most `prop_hw` links; double it for slack.
    let guard = prop_hw.saturating_mul(2).saturating_add(2);

    let walk =
        |owner_kind: StoreKind, owner: u64, first_prop: u64, report: &mut ConsistencyReport| {
            let mut cur = first_prop;
            let mut steps = 0u64;
            let mut seen: BTreeSet<u64> = BTreeSet::new();
            let mut prev = NULL_ID; // the record that pointed at `cur` (owner head = NULL)
            while cur != NULL_ID {
                steps += 1;
                if steps > guard || !seen.insert(cur) {
                    report.push(Violation::PropertyChain {
                        owner_kind,
                        owner,
                        prop: prev,
                        detail: PropertyFault::NonTerminating,
                    });
                    return;
                }
                if cur == 0 || cur >= prop_hw {
                    report.push(Violation::PropertyChain {
                        owner_kind,
                        owner,
                        prop: cur,
                        detail: PropertyFault::PropOutOfRange,
                    });
                    return;
                }
                let Some(rec) = scan.live_props.get(&cur) else {
                    report.push(Violation::PropertyChain {
                        owner_kind,
                        owner,
                        prop: cur,
                        detail: PropertyFault::DeadProp,
                    });
                    return;
                };
                prev = cur;
                cur = rec.next_prop;
            }
        };

    for (&nid, n) in &scan.live_nodes {
        walk(StoreKind::Node, nid, n.first_prop, report);
    }
    for (&rid, r) in &scan.live_rels {
        walk(StoreKind::Rel, rid, r.first_prop, report);
    }
    Ok(())
}

/// 2. Adjacency well-formedness (`04 §2.3`–§2.4).
///
/// Two complementary checks, both purely from the live-record snapshot:
///
/// * **Per-node chain walk** — starting at `first_rel`, follow the doubly-linked `(rel, side)`
///   links, asserting: every link's relationship is live and incident; the head link's `prev` is
///   `NULL`; each link's `next` successor's matching-side `prev` points back; the walk terminates
///   under a cycle guard; a self-loop's two links are deduped to one incident relationship.
/// * **Independent re-derivation** — the multiset of incidences implied by the live relationships'
///   endpoints (a self-loop counted once per node) must equal the chain-walked incidence of every
///   node. This catches a relationship that *should* be in a chain but is missing, and vice-versa.
fn check_adjacency<D: BlockDevice, S: LogSink>(
    _store: &mut RecordStore<D, S>,
    cat: &Catalog,
    scan: &Scan,
    report: &mut ConsistencyReport,
) -> Result<()> {
    let rel_hw = cat.high_water(StoreKind::Rel);
    // A chain visits each link once; a self-loop contributes two links. Twice the rel high-water
    // plus slack catches any corrupted cycle (mirrors `store::incident_rels`' guard).
    let guard = rel_hw.saturating_mul(2).saturating_add(2);

    // Independent re-derivation from the live relationships, of both:
    //   * the distinct incident relationships per node (self-loop counted once), and
    //   * the number of chain *links* per node (self-loop counted twice — it is threaded into the
    //     one chain via both sides), which the forward walk must traverse exactly.
    // The link count catches a broken self-loop whose forward walk short-circuits to the right
    // *set* of distinct rels but skips its second link (`04 §2.4`).
    let mut expected: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    let mut expected_links: BTreeMap<u64, u64> = BTreeMap::new();
    for &nid in scan.live_nodes.keys() {
        expected.entry(nid).or_default();
        expected_links.entry(nid).or_insert(0);
    }
    for (&rid, rel) in &scan.live_rels {
        // Only count incidences whose endpoint is a live node; a dangling endpoint is the
        // referential check's concern and must not skew the link-count comparison.
        if scan.is_live(StoreKind::Node, rel.start_node) {
            expected.entry(rel.start_node).or_default().insert(rid);
            *expected_links.entry(rel.start_node).or_insert(0) += 1;
        }
        if scan.is_live(StoreKind::Node, rel.end_node) {
            expected.entry(rel.end_node).or_default().insert(rid); // self-loop: set dedupes
            *expected_links.entry(rel.end_node).or_insert(0) += 1; // self-loop: counts twice
        }
    }

    for (&nid, node) in &scan.live_nodes {
        let (walked, links) = walk_incidence(nid, node, scan, rel_hw, guard, report);
        let exp = expected.get(&nid).cloned().unwrap_or_default();
        let exp_links = expected_links.get(&nid).copied().unwrap_or(0);
        if walked != exp || links != exp_links {
            report.push(Violation::Adjacency {
                node: nid,
                rel: NULL_ID,
                detail: AdjacencyFault::IncidenceMismatch,
            });
        }
    }
    Ok(())
}

/// Walks node `nid`'s incidence chain, validating the doubly-linked `(rel, side)` link invariants,
/// and returns `(distinct live relationships enumerated, number of links traversed)` — a self-loop
/// contributes one to the set and two to the link count. Pushes a [`Violation::Adjacency`] for every
/// fault found; on a fault that prevents safe continuation it stops walking (and the
/// incidence-mismatch check will also fire, the intended belt-and-braces signal).
fn walk_incidence(
    nid: u64,
    node: &NodeRecord,
    scan: &Scan,
    rel_hw: u64,
    guard: u64,
    report: &mut ConsistencyReport,
) -> (BTreeSet<u64>, u64) {
    let mut out: BTreeSet<u64> = BTreeSet::new();
    let mut links = 0u64;
    let mut cur = node.first_rel;
    let mut prev_link = NULL_ID; // the rel id of the link we arrived through (NULL at head)
    let mut steps = 0u64;
    let mut last_pushed = NULL_ID; // dedupe a self-loop's two consecutive links

    while cur != NULL_ID {
        steps += 1;
        if steps > guard {
            report.push(Violation::Adjacency {
                node: nid,
                rel: cur,
                detail: AdjacencyFault::NonTerminating,
            });
            break;
        }
        // Range check before any record access.
        if cur == 0 || cur >= rel_hw {
            report.push(Violation::Adjacency {
                node: nid,
                rel: cur,
                detail: AdjacencyFault::RelOutOfRange,
            });
            break;
        }
        // A dead-link **corpse** (`rmp` #220) is threaded through transparently: it is not counted as
        // an incident relationship and its (possibly stale) prev pointer is not held to the chain's
        // symmetry invariant — we just follow its preserved forward pointer to the next link, exactly
        // as `incident_rels` does, until GC splices it out.
        if let Some(corpse) = scan.corpse_rels.get(&cur) {
            let is_loop = corpse.start_node == nid && corpse.end_node == nid;
            let (_, next) = link_of(corpse, nid, prev_link, is_loop);
            prev_link = cur;
            cur = next;
            continue;
        }

        let Some(rel) = scan.live_rels.get(&cur) else {
            report.push(Violation::Adjacency {
                node: nid,
                rel: cur,
                detail: AdjacencyFault::DeadRel,
            });
            break;
        };

        let is_loop = rel.start_node == nid && rel.end_node == nid;
        let incident = rel.start_node == nid || rel.end_node == nid;
        if !incident {
            report.push(Violation::Adjacency {
                node: nid,
                rel: cur,
                detail: AdjacencyFault::NotIncident,
            });
            break;
        }

        // Determine the side (and its prev/next) we are traversing for `cur`.
        let (prev, next) = link_of(rel, nid, prev_link, is_loop);

        // Head link must have prev == NULL; a non-head link's prev must equal the link we came from.
        // A corpse predecessor breaks the strict `prev == prev_link` symmetry (the live link's `prev`
        // points at the corpse we threaded past, not at the last LIVE link), so accept a `prev` that
        // resolves to a corpse as well.
        if prev != prev_link && !scan.corpse_rels.contains_key(&prev) {
            // Distinguish the two head/back-link faults for a sharper report.
            if prev_link == NULL_ID {
                report.push(Violation::Adjacency {
                    node: nid,
                    rel: cur,
                    detail: AdjacencyFault::HeadPrevNotNull,
                });
            } else {
                report.push(Violation::Adjacency {
                    node: nid,
                    rel: cur,
                    detail: AdjacencyFault::AsymmetricLink,
                });
            }
            break;
        }

        // Count this link, and record the relationship once (dedupe a self-loop's two links).
        links += 1;
        if last_pushed != cur {
            out.insert(cur);
            last_pushed = cur;
        }

        prev_link = cur;
        cur = next;
    }
    (out, links)
}

/// The `(prev, next)` chain pointers for relationship `rel` on the side facing `node`, when arriving
/// from the link `from` (`NULL` at the head). For a self-loop both sides face `node`; the END side
/// is the head link (`create_rel` makes END the new head, `04 §2.4`) and the START side follows it,
/// so we pick the side whose `prev` matches `from` (or END at the head). Mirrors the traversal in
/// [`RecordStore::incident_rels`](crate::store::RecordStore::incident_rels) and the chain-link check
/// in `tests/adjacency_props.rs`.
fn link_of(rel: &RelRecord, node: u64, from: u64, is_loop: bool) -> (u64, u64) {
    if is_loop {
        let end = rel.chain_pointers(ChainSide::End);
        if from == NULL_ID || end.0 == from {
            end
        } else {
            rel.chain_pointers(ChainSide::Start)
        }
    } else if rel.start_node == node {
        rel.chain_pointers(ChainSide::Start)
    } else {
        rel.chain_pointers(ChainSide::End)
    }
}

/// 5. Free-list sanity (`04 §2.7`).
fn check_free_lists(cat: &Catalog, scan: &Scan, report: &mut ConsistencyReport) {
    // Build the set of ids referenced by any live chain (incidence + property + overflow heap), per
    // store, so we can flag a freed id that is still live-referenced.
    let mut referenced_rels: BTreeSet<u64> = BTreeSet::new();
    let mut referenced_props: BTreeSet<u64> = BTreeSet::new();
    let mut referenced_blocks: BTreeSet<u64> = BTreeSet::new();
    for n in scan.live_nodes.values() {
        if n.first_rel != NULL_ID {
            referenced_rels.insert(n.first_rel);
        }
        if n.first_prop != NULL_ID {
            referenced_props.insert(n.first_prop);
        }
    }
    for r in scan.live_rels.values() {
        for p in [
            r.start_prev_rel,
            r.start_next_rel,
            r.end_prev_rel,
            r.end_next_rel,
        ] {
            if p != NULL_ID {
                referenced_rels.insert(p);
            }
        }
        if r.first_prop != NULL_ID {
            referenced_props.insert(r.first_prop);
        }
    }
    for p in scan.live_props.values() {
        if p.next_prop != NULL_ID {
            referenced_props.insert(p.next_prop);
        }
        // An overflowed property's `value_inline` is its chain head; track it (and the chain's
        // links) so a freed heap block still referenced by a live property is flagged.
        if p.type_tag & PROP_OVERFLOW_BIT != 0 && p.value_inline != NULL_ID {
            referenced_blocks.insert(p.value_inline);
        }
    }
    for b in scan.live_blocks.values() {
        if b.next_block != NULL_ID {
            referenced_blocks.insert(b.next_block);
        }
    }

    for kind in [
        StoreKind::Node,
        StoreKind::Rel,
        StoreKind::Prop,
        StoreKind::Strings,
    ] {
        let hw = cat.high_water(kind);
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        for &id in cat.free(kind) {
            // Out of range / null.
            if id == NULL_ID || id >= hw {
                report.push(Violation::FreeList {
                    kind,
                    id,
                    detail: FreeListFault::OutOfRange,
                });
                continue;
            }
            // Double free.
            if !seen.insert(id) {
                report.push(Violation::FreeList {
                    kind,
                    id,
                    detail: FreeListFault::Duplicate,
                });
            }
            // A freed id whose on-disk record still reads `in_use` is a contradiction (a live record
            // sitting on the free list).
            if scan.freed_but_in_use[kind as usize].contains(&id) {
                report.push(Violation::FreeList {
                    kind,
                    id,
                    detail: FreeListFault::StillInUse,
                });
            }
            // A freed id referenced by a live chain is dangling-by-reuse.
            let referenced = match kind {
                StoreKind::Rel => referenced_rels.contains(&id),
                StoreKind::Prop => referenced_props.contains(&id),
                StoreKind::Strings => referenced_blocks.contains(&id),
                // Nodes are not chained, so a freed node id cannot be live-referenced via a chain;
                // a relationship endpoint pointing at a freed node is caught by `check_referential`.
                StoreKind::Node => false,
            };
            if referenced {
                report.push(Violation::FreeList {
                    kind,
                    id,
                    detail: FreeListFault::ReferencedByLiveChain,
                });
            }
        }
    }
}

/// 6. Label-bitmap well-formedness (`05 §9`, `rmp` task #42).
///
/// For every live node, validates its `labels` bitmap (purely from the live-record snapshot plus the
/// catalog's `Label`-namespace token count):
///
/// * the overflow flag must be clear — this build never sets it and the overflow block (#39) is not
///   present, so a set flag is necessarily stale/corrupt ([`LabelBitmapFault::OverflowFlagSet`]);
/// * every membership bit must reference a `Label` token id that exists in the token store
///   (`id < label_token_count`), else it is a dangling label reference
///   ([`LabelBitmapFault::UnknownLabelToken`]).
fn check_label_bitmaps(cat: &Catalog, scan: &Scan, report: &mut ConsistencyReport) {
    let token_count = cat.label_token_count as u32;
    for (&nid, node) in &scan.live_nodes {
        if crate::labels::is_overflowed(node.labels) {
            report.push(Violation::LabelBitmap {
                node: nid,
                detail: LabelBitmapFault::OverflowFlagSet,
            });
            // The inline bits are not the authoritative set under overflow, so do not also flag them
            // as unknown tokens; the overflow violation is the actionable one.
            continue;
        }
        // `token_ids` cannot error here: we already excluded the overflow case.
        let Ok(ids) = crate::labels::token_ids(node.labels) else {
            continue;
        };
        for id in ids {
            if id >= token_count {
                report.push(Violation::LabelBitmap {
                    node: nid,
                    detail: LabelBitmapFault::UnknownLabelToken { token_id: id },
                });
            }
        }
    }
}

/// 7. Overflow-heap-chain well-formedness (`04 §2.1`, `04 §2.3`; `rmp` task #43).
///
/// For every live property record whose `type_tag` has the overflow bit set, walks the
/// `strings.store` block chain whose head is the property's `value_inline`, asserting purely from
/// the live-record snapshot:
///
/// * every block id (the head and each `next_block`) is in range `1..high_water` of `strings.store`
///   ([`HeapChainFault::BlockOutOfRange`]);
/// * every block is **live** (in use, not freed) — no dangling-by-reuse reference
///   ([`HeapChainFault::DeadBlock`]);
/// * the chain terminates within a generous cycle guard ([`HeapChainFault::NonTerminating`]).
///
/// This is the overflow-heap analogue of [`check_property_chains`]: it proves *"no dangling block
/// ids, chain terminates, freed blocks not referenced"* (`rmp` task #43 acceptance).
/// Validates the MVCC header (`05 §7`) of every live node, relationship and property record — the
/// version-visibility metadata `graphus-txn` reads directly. A corrupt header here is silent
/// isolation corruption: an inverted or dangling stamp feeds the visibility rule unpredictable
/// inputs. Checks, per live record (`rmp` storage audit F8):
///
/// * **A creator is present** ([`MvccHeaderFault::NoCreator`]): an in-use version's `created_ts`
///   (`xmin`) is never the `0` none-sentinel.
/// * **No timestamp inversion** ([`MvccHeaderFault::TimestampInversion`]): when both `xmin` and
///   `xmax` are *committed* timestamps, `xmin <= xmax`. Mixed in-flight/committed stamps occupy
///   disjoint number spaces (`VersionStamp`'s in-flight bit) and are deliberately not compared, so a
///   lazily-unfrozen committed version (whose `xmin` is still its writer's `TxnId`) is never a false
///   positive.
/// * **`undo_ptr` is in range** ([`MvccHeaderFault::UndoPtrOutOfRange`]): the older-version
///   back-pointer is `0` (none) or a physical id in `1..high_water` of the record's own store. The
///   per-value version chain is a documented follow-up, so today `undo_ptr` is always `0`; this guard
///   catches a dangling pointer now and the future unbounded-loop hazard the moment chains activate.
fn check_mvcc_headers(cat: &Catalog, scan: &Scan, report: &mut ConsistencyReport) {
    let mut check = |kind: StoreKind, id: u64, mvcc: MvccHeader| {
        if VersionStamp::from_raw(mvcc.created_ts) == VersionStamp::None {
            report.push(Violation::MvccHeader {
                kind,
                id,
                detail: MvccHeaderFault::NoCreator,
            });
        }
        if let (VersionStamp::Committed(c), VersionStamp::Committed(e)) = (
            VersionStamp::from_raw(mvcc.created_ts),
            VersionStamp::from_raw(mvcc.expired_ts),
        ) {
            if c.0 > e.0 {
                report.push(Violation::MvccHeader {
                    kind,
                    id,
                    detail: MvccHeaderFault::TimestampInversion {
                        created: c.0,
                        expired: e.0,
                    },
                });
            }
        }
        if mvcc.undo_ptr != NULL_ID && mvcc.undo_ptr >= cat.high_water(kind) {
            report.push(Violation::MvccHeader {
                kind,
                id,
                detail: MvccHeaderFault::UndoPtrOutOfRange {
                    undo_ptr: mvcc.undo_ptr,
                },
            });
        }
    };
    for (&id, rec) in &scan.live_nodes {
        check(StoreKind::Node, id, rec.mvcc);
    }
    for (&id, rec) in &scan.live_rels {
        check(StoreKind::Rel, id, rec.mvcc);
    }
    for (&id, rec) in &scan.live_props {
        check(StoreKind::Prop, id, rec.mvcc);
    }
}

fn check_heap_chains(cat: &Catalog, scan: &Scan, report: &mut ConsistencyReport) {
    let block_hw = cat.high_water(StoreKind::Strings);
    // A well-formed chain has at most `block_hw` blocks; double it for slack against a corrupt cycle.
    let guard = block_hw.saturating_mul(2).saturating_add(2);

    // Global block -> first-owning property, across ALL live chains: a block reachable from two
    // distinct chains is an aliased block whose 48-byte payload would be shared between two property
    // values (`rmp` storage audit F13). `live_props` is a `BTreeMap`, so the "first owner" is
    // deterministically the smallest property id referencing the block.
    let mut block_owner: BTreeMap<u64, u64> = BTreeMap::new();

    for (&pid, prop) in &scan.live_props {
        if prop.type_tag & PROP_OVERFLOW_BIT == 0 {
            continue; // inline scalar: no overflow chain to validate
        }
        let mut cur = prop.value_inline;
        let mut steps = 0u64;
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        while cur != NULL_ID {
            steps += 1;
            if steps > guard || !seen.insert(cur) {
                report.push(Violation::HeapChain {
                    prop: pid,
                    block: cur,
                    detail: HeapChainFault::NonTerminating,
                });
                break;
            }
            if cur == 0 || cur >= block_hw {
                report.push(Violation::HeapChain {
                    prop: pid,
                    block: cur,
                    detail: HeapChainFault::BlockOutOfRange,
                });
                break;
            }
            let Some(block) = scan.live_blocks.get(&cur) else {
                report.push(Violation::HeapChain {
                    prop: pid,
                    block: cur,
                    detail: HeapChainFault::DeadBlock,
                });
                break;
            };
            // Cross-chain aliasing: this block already belongs to an earlier chain.
            if let Some(&other_owner) = block_owner.get(&cur) {
                report.push(Violation::HeapChain {
                    prop: pid,
                    block: cur,
                    detail: HeapChainFault::SharedBlock { other_owner },
                });
                break;
            }
            block_owner.insert(cur, pid);
            // A corrupt `len` would be clamped silently by `HeapBlock::bytes`; report it here.
            if block.len as usize > BLOCK_PAYLOAD {
                report.push(Violation::HeapChain {
                    prop: pid,
                    block: cur,
                    detail: HeapChainFault::BlockLenTooLong { len: block.len },
                });
            }
            cur = block.next_block;
        }
    }
}

/// 4. Store/index agreement (`04 §6.3`). See [`IndexAgreement`] for the scoped properties.
///
/// Verifies, for one index:
/// * every live index entry's `rid` is in range and points at a **live** record of `indexed_store`
///   ([`AgreementFault::RidOutOfRange`] / [`AgreementFault::DeadRecord`]);
/// * if `expected` is supplied, the set of record ids the index contains equals it — extras are
///   [`AgreementFault::UnexpectedEntry`] (stale / wrong value), gaps are
///   [`AgreementFault::MissingEntry`].
fn check_index_agreement(scan: &Scan, ix: &IndexAgreement, report: &mut ConsistencyReport) {
    let mut present: BTreeSet<u64> = BTreeSet::new();
    let high_water = scan_high_water(scan, ix.indexed_store);
    for e in &ix.entries {
        present.insert(e.rid);
        if e.rid == NULL_ID || e.rid >= high_water {
            report.push(Violation::IndexAgreement {
                index: ix.name.clone(),
                detail: AgreementFault::RidOutOfRange { rid: e.rid },
            });
            continue;
        }
        if !scan.is_live(ix.indexed_store, e.rid) {
            report.push(Violation::IndexAgreement {
                index: ix.name.clone(),
                detail: AgreementFault::DeadRecord { rid: e.rid },
            });
        }
    }
    if let Some(expected) = &ix.expected {
        for rid in present.difference(expected) {
            report.push(Violation::IndexAgreement {
                index: ix.name.clone(),
                detail: AgreementFault::UnexpectedEntry { rid: *rid },
            });
        }
        for rid in expected.difference(&present) {
            report.push(Violation::IndexAgreement {
                index: ix.name.clone(),
                detail: AgreementFault::MissingEntry { rid: *rid },
            });
        }
    }
}

/// The high-water mark for a store, recovered from the scan's freed sets + live maps. (The scan does
/// not carry the catalog, so we approximate "in range" as `<= max(live id, max freed id) + 1`. A
/// caller-supplied entry id beyond that is reported out of range either way.)
fn scan_high_water(scan: &Scan, kind: StoreKind) -> u64 {
    let live_max = match kind {
        StoreKind::Node => scan.live_nodes.keys().next_back().copied(),
        StoreKind::Rel => scan.live_rels.keys().next_back().copied(),
        StoreKind::Prop => scan.live_props.keys().next_back().copied(),
        StoreKind::Strings => scan.live_blocks.keys().next_back().copied(),
    }
    .unwrap_or(0);
    let freed_max = scan.freed[kind as usize]
        .iter()
        .next_back()
        .copied()
        .unwrap_or(0);
    live_max.max(freed_max).saturating_add(1)
}

#[cfg(test)]
mod tests {
    //! Unit tests for the report/violation surface and the pure helpers; the heavy
    //! healthy-store-passes / injected-corruption tests live in `tests/consistency.rs`.
    use super::*;

    #[test]
    fn empty_report_is_consistent() {
        let r = ConsistencyReport::default();
        assert!(r.is_consistent());
    }

    #[test]
    fn report_with_a_violation_is_inconsistent() {
        let mut r = ConsistencyReport::default();
        r.push(Violation::Checksum { page: 3 });
        assert!(!r.is_consistent());
        assert_eq!(r.violations.len(), 1);
    }

    #[test]
    fn index_entry_rid_constructor() {
        let e = IndexEntry::rid(42);
        assert_eq!(e.rid, 42);
        assert!(e.key.is_empty());
    }
}
