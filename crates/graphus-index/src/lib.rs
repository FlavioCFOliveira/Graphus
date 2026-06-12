//! `graphus-index` — B+-tree, token-lookup, composite and relationship-property indexes and
//! constraints (`04-technical-design.md` §6, `D-v1-index-types`).
//!
//! This crate is the access-layer indexing subsystem. It builds four v1 index kinds on a single
//! WAL-logged, ARIES-recoverable [`BTree`], plus uniqueness/existence constraints. Everything is
//! the single-threaded **correct core** the rest of the storage core is staged at; the concurrent
//! latch-coupled / B-link version (`04 §6.1`) is a later task, documented at the seams.
//!
//! # Modules
//!
//! - [`keycodec`] — the order-preserving byte encoding (`04 §6.2`, §7.6): Cypher value order ==
//!   encoded byte order, so a memcmp B+-tree is a Cypher-ordered index. The crux of the crate and
//!   the most heavily property-tested module.
//! - [`node`] — the slotted B+-tree page layout (`04 §3.2`); this format is the one
//!   `05-storage-format.md` §8 defers here, and it is defined and frozen in that module.
//! - [`btree`] — the [`BTree`] itself: point lookup, range scan, insert, delete, split, with every
//!   mutation WAL-logged (redo + undo) and recoverable by ARIES (`04 §6.4`).
//! - [`recovery`] — the WAL ordering rule ([`SharedWal`]), the intra-page patch encoding, and the
//!   [`ApplyTarget`](graphus_wal::ApplyTarget) that replays index pages on crash recovery.
//! - [`kinds`] — the four v1 index kinds as thin key-composition layers over [`BTree`]:
//!   token-lookup, property (range/equality), composite, and relationship-property.
//! - [`fulltext`] — the full-text index (`rmp` task #72): a documented text [`Analyzer`] and an
//!   in-memory [`InvertedIndex`] (term → sorted postings + forward map). Unlike the B+-tree kinds it
//!   is a self-contained, store-independent data structure; its catalog durability and MVCC re-check
//!   are layered on in `graphus-cypher`/`graphus-storage`, mirroring the derived `IndexSet`.
//! - [`constraint`] — uniqueness (via a unique index, commit-time validated) and existence
//!   (checked on write) constraints (`04 §6.5`).
//! - [`histogram`] — equi-depth property histograms over the order-preserving encoding, plus a
//!   builder that derives one by scanning a [`kinds::PropertyIndex`]. The planner's cardinality- and
//!   selectivity-estimation input; decode-free because the encoding is Cypher-ordered.
//!
//! # MVCC awareness & the transaction-layer seam (`04 §6.3`)
//!
//! Index entries are **not** separately versioned. A lookup returns **candidate record ids**;
//! whether a candidate is visible to a reader's snapshot is resolved by the record's MVCC header
//! in `graphus-txn`, not here. Concretely:
//!
//! - The index APIs ([`kinds`]) return record ids ([`u64`] physical ids). They never filter by
//!   visibility — that is the transaction layer's job.
//! - When a new record version is created the txn layer inserts an index entry; the old entry is
//!   removed lazily by GC once the old version is dead (`04 §6.3`, `05 §5`). This crate provides
//!   the `insert`/`delete` primitives the txn layer drives.
//! - **SIREAD / predicate-marker registration** for index range reads (so SSI catches phantoms,
//!   `04 §5.4`, §6.3) happens in the transaction layer. `graphus-txn` currently operates over its
//!   own `VersionedStore` abstraction (the §12 representation spike is still open),
//!   so wiring real index seeks into SSI read-set tracking is a **documented follow-up**, not
//!   faked here. The seam is: a range/point seek returns its candidate ids *and the key range it
//!   covered*, which the txn layer turns into a predicate read marker. [`kinds::PropertyIndex`]
//!   range methods are shaped to make that range explicit.
//!
//! # Crash recovery (`04 §6.4`)
//!
//! Because index pages share one WAL and one recovery with the base store, after a crash the
//! recovered B+-tree is exactly consistent with the committed state — committed entries survive
//! (redo), uncommitted are rolled back (undo). [`recovery::recover_index_device`] runs that, and
//! the integration test `tests/crash_recovery.rs` models the crash like
//! `graphus-storage/tests/crash_recovery.rs` and asserts the recovered tree equals the committed
//! model.
#![forbid(unsafe_code)]

pub mod btree;
pub mod constraint;
pub mod fulltext;
pub mod histogram;
pub mod keycodec;
pub mod kinds;
pub mod node;
pub mod recovery;

pub use btree::BTree;
pub use constraint::{ConstraintError, ExistenceConstraint, UniqueConstraint};
pub use fulltext::{Analyzer, InvertedIndex, MatchSemantics};
pub use histogram::{HistogramDecodeError, PropertyHistogram};
pub use keycodec::{KeyEncodeError, encode_composite, encode_single, encode_value};
pub use kinds::{CompositeIndex, PropertyIndex, RelPropertyIndex, TokenIndex};
pub use recovery::{SharedWal, recover_index_device};
