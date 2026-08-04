//! The metadata page (device page `0`): the durable root of all in-memory store state
//! (`04-technical-design.md` §2.1, §2.6, §2.7).
//!
//! Every store's in-memory state — physical-id high-water marks, free lists, the token
//! dictionaries, the [`ElementId`](graphus_core::ElementId) seed, and each store's
//! store-relative-page → device-page map — is rooted in a single metadata page so the whole
//! catalog can be re-derived on recovery by reloading one page. Mutations to it go through the
//! WAL like any other page (`04 §2.6`: token creation is WAL-logged), so a crash mid-write
//! recovers atomically.
//!
//! The metadata payload is a self-describing, length-prefixed serialization that lives entirely
//! within one page's payload (`05 §6`); the encoder asserts it fits.

use std::collections::BTreeMap;

use graphus_core::error::{GraphusError, Result};

use crate::idalloc::FreeList;
use crate::store::STORE_COUNT;
use crate::tokens::TokenStore;

/// The number of fixed-record stores a **format version 1** catalog describes: the node,
/// relationship and property stores plus the `strings.store` overflow heap (`04 §2.1`).
///
/// The catalog's first four store entries keep their historic position and byte layout for ever, so
/// a version-1 image and the version-1 prefix of a version-2 image are byte-identical up to the
/// statistics block. The undo area's two stores (`05 §12.1`) live in the trailing block instead —
/// the same append-only rule every other catalog extension follows.
const LEGACY_STORE_COUNT: usize = 4;

/// The on-disk format version of a catalog image that carries **no** undo-area block: everything
/// this project wrote before `rmp` #966 (`05 §12.6`).
pub(crate) const LEGACY_FORMAT_VERSION: u32 = 1;

/// The first on-disk format version in which a `props.store` cell's MVCC header no longer carries
/// the property's visibility (`rmp` #967, `D-property-visibility`).
///
/// Every **earlier** version — 1 and 2 alike — recorded a removed or overwritten property as a cell
/// left in use with `expired_ts` stamped and its value intact, which this build reads as a live
/// value. So the legacy-image gate
/// (`RecordStore::refuse_legacy_property_tombstones`) keys on `format_version <` this constant, not
/// on the legacy version alone: version 2 differs from version 3 only in this number, and carries
/// exactly the same hazard.
///
/// Named separately from [`FORMAT_VERSION`](graphus_core::constants::FORMAT_VERSION) on purpose. A
/// future bump for an unrelated layout change must NOT make the gate start scanning version-3 stores,
/// which are already written under the new property model.
pub(crate) const PROPERTY_UNDO_CHAIN_FORMAT_VERSION: u32 = 3;

const _: () = assert!(
    PROPERTY_UNDO_CHAIN_FORMAT_VERSION <= graphus_core::constants::FORMAT_VERSION,
    "the property-model version must be one this build can actually write",
);

/// Magic word introducing the trailing undo-area block (`rmp` #966). Chosen so a truncated or
/// garbage tail cannot be mistaken for the block: `b"GRPHUNDO"` read little-endian.
const UNDO_AREA_MAGIC: u64 = u64::from_le_bytes(*b"GRPHUNDO");

/// The durable catalog stored in the metadata page.
///
/// Holds, for each of the three record stores, the physical-id high-water mark, the free list,
/// and the store-relative-page → device-`PageId` map; plus the shared token store and the
/// next `ElementId` to allocate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    /// The on-disk format version this catalog image was written by
    /// ([`FORMAT_VERSION`](graphus_core::constants::FORMAT_VERSION), `05 §12.6`).
    ///
    /// A **version-1** image (everything written before `rmp` #966) has no undo-area block at all;
    /// [`decode`](Self::decode) reports it as `1` with two empty undo-area stores, which is exactly
    /// the state a store with no version chains is in, so opening one is a lossless **upgrade**
    /// rather than a conversion. An image whose version is *newer* than this build's is **refused**
    /// by `decode`, never partially interpreted.
    pub format_version: u32,
    /// Next `ElementId` to allocate (never-reused monotonic counter, `04 §2.2`).
    pub element_id_next: u128,
    /// The largest MVCC commit timestamp issued so far (`04 §5.2`). Persisted so the timestamp
    /// oracle resumes strictly monotonically after reopen/recovery — a reader's snapshot and a new
    /// committer's timestamp must never alias or regress past a durable committed version.
    pub commit_ts_hw: u64,
    /// Per-store state, indexed by [`StoreKind`](crate::store::StoreKind) `as usize` (the node, rel
    /// and prop stores plus the `strings.store` overflow heap, `04 §2.1`, and — from format version
    /// 2 — the `undo.store` / `commit.store` pair of the undo area, `05 §12.1`).
    pub stores: [StoreMeta; STORE_COUNT],
    /// The token dictionaries (`04 §2.6`).
    pub tokens: TokenStore,
    /// Exact, persisted live-record cardinalities for the planner's cardinality estimator
    /// (`rmp` task #79): per-label node counts and per-relationship-type counts.
    pub statistics: Statistics,
}

/// The durable build state of a declared node-property index (`rmp` task #90).
///
/// An index is created [`Populating`](Self::Populating) and promoted to [`Online`](Self::Online)
/// once its backing entries are fully built; only an `Online` index may serve query seeks (a
/// `Populating` one falls back to a label-scan + filter). Population is **synchronous** in `rmp`
/// task #90 — a successful `create` ends `Online` — but the two-state distinction is recorded
/// durably now so the non-blocking incremental build (`rmp` task #91) can persist an in-progress
/// `Populating` index across a crash and resume it.
///
/// # Wire encoding
///
/// Encoded as a single byte (see [`Statistics::encode`]). A future `Failed` (or `Dropping`) state
/// is reserved by leaving the unused discriminants free; [`from_byte`](Self::from_byte) rejects any
/// unknown byte so a forward-incompatible image is caught rather than silently mis-decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub enum IndexState {
    /// The index is declared but its entries are still being built; it must **not** serve seeks.
    Populating,
    /// The index is fully built and usable for query seeks.
    Online,
}

impl IndexState {
    /// The single-byte wire discriminant (`rmp` task #90). Discriminants `2..` are reserved for a
    /// future `Failed` / `Dropping` state.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Populating => 0,
            Self::Online => 1,
        }
    }

    /// Decodes a single-byte wire discriminant, or [`None`] for an unknown (reserved/future) byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Populating),
            1 => Some(Self::Online),
            _ => None,
        }
    }
}

/// The **entity dimension** a full-text index covers: node labels or relationship types
/// (`rmp` task #663).
///
/// Neo4j-5.x full-text indexes come in two flavours — one over **nodes** (`FOR (n:A|B)`, queried by
/// `db.index.fulltext.queryNodes`) and one over **relationships** (`FOR ()-[r:T]-()`, queried by
/// `db.index.fulltext.queryRelationships`). Both share the analyzer, the covered property set and the
/// inverted-index machinery; only the covered token namespace ([`Label`](crate::tokens::Namespace::Label)
/// vs [`RelType`](crate::tokens::Namespace::RelType)) and the query surface differ. This one-byte
/// discriminant records which flavour a [`FulltextIndexEntry`] is.
///
/// # Wire encoding
///
/// Encoded as a single byte in the **backward-compatible full-text extension block** (see
/// [`Statistics::encode`]), never in the base full-text catalog block. A pre-#663 image has no
/// extension block, so every legacy entry decodes as [`Node`](Self::Node) — the only flavour that
/// existed before #663. [`from_byte`](Self::from_byte) rejects an unknown byte (a forward-incompatible
/// image), mirroring [`IndexState::from_byte`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[must_use]
pub enum FulltextEntity {
    /// The index covers **node labels** (`FOR (n:Label…)`), queried by `db.index.fulltext.queryNodes`.
    /// The default and the only flavour a pre-#663 image knows.
    #[default]
    Node,
    /// The index covers **relationship types** (`FOR ()-[r:Type…]-()`), queried by
    /// `db.index.fulltext.queryRelationships` (`rmp` task #663).
    Relationship,
}

impl FulltextEntity {
    /// The single-byte wire discriminant (`rmp` task #663). Discriminants `2..` are reserved.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Node => 0,
            Self::Relationship => 1,
        }
    }

    /// Decodes a single-byte wire discriminant, or [`None`] for an unknown (reserved/future) byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Node),
            1 => Some(Self::Relationship),
            _ => None,
        }
    }

    /// Whether this is a **relationship** full-text index (its covered tokens are
    /// [`RelType`](crate::tokens::Namespace::RelType) tokens, queried by `queryRelationships`).
    #[must_use]
    pub const fn is_relationship(self) -> bool {
        matches!(self, Self::Relationship)
    }
}

/// A durable **full-text index** catalog entry (`rmp` tasks #72, #663).
///
/// A full-text index is identified by a server-unique **name** (unlike a node-property index, which
/// `(label_token, prop_key)` identifies), covers — per its [`entity`](Self::entity) —  **one or more**
/// node labels *or* relationship types (the [`tokens`](Self::tokens) set, `rmp` #663 widened this from
/// a single label token) and **one or more** string properties, and is analyzed by a fixed analyzer
/// recorded as a single byte (the [`graphus_index::Analyzer`] discriminant — storage does not depend
/// on `graphus-index`, so the byte is stored verbatim and interpreted by the query layer, exactly as
/// the histogram blobs are).
///
/// This rides the **identical** durability lifecycle as the node-property index catalog and the
/// counts/histograms: checkpointed at commit, reloaded on rollback and on open. Its presence
/// invariant is "an entry exists iff a full-text index of that name is declared". The inverted index
/// *data* itself is never persisted (it is ephemeral and rebuilt from the store on open, like the
/// derived `IndexSet`), so only this catalog entry needs durability.
///
/// # Backward-compatible encoding (`rmp` task #663)
///
/// The base full-text catalog block still writes a **single** covering token (`tokens[0]`) so its byte
/// layout is unchanged; a pre-#663 image decodes to `entity: Node` + `tokens: [that token]`. The
/// `entity` and any **additional** covering tokens (`tokens[1..]`) live in a trailing extension block
/// keyed by name (present only for a relationship index or a multi-token one), so a legacy single-label
/// node index needs no extension entry. See [`Statistics::encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulltextIndexEntry {
    /// Whether the index covers node labels or relationship types (`rmp` task #663).
    pub entity: FulltextEntity,
    /// The covering tokens the index spans, in declared order (one or more): node
    /// [`Label`](crate::tokens::Namespace::Label) tokens when [`entity`](Self::entity) is
    /// [`Node`](FulltextEntity::Node), relationship [`RelType`](crate::tokens::Namespace::RelType)
    /// tokens when it is [`Relationship`](FulltextEntity::Relationship). A node with **any** covered
    /// label (a relationship of **any** covered type) is indexed — Neo4j multi-label/-type semantics.
    pub tokens: Vec<u32>,
    /// The property-key-namespace tokens the index covers, in declared order (one or more).
    pub property_tokens: Vec<u32>,
    /// The analyzer discriminant byte (the [`graphus_index::Analyzer`] `as_byte`, stored verbatim).
    pub analyzer: u8,
    /// The build state of the index (the same state machine as a node-property index).
    pub state: IndexState,
}

impl FulltextIndexEntry {
    /// The **primary** covering token — the single token the base catalog block persists (`tokens[0]`).
    ///
    /// # Panics
    /// Panics if `tokens` is empty; the write path and [`decode`](Statistics::decode) both guarantee at
    /// least one covering token (a full-text index always covers ≥1 label/type).
    #[must_use]
    pub fn primary_token(&self) -> u32 {
        *self
            .tokens
            .first()
            .expect("INVARIANT: a full-text index covers at least one label/type token")
    }

    /// Whether the base + extension encoding must emit an **extension entry** for this index: a
    /// relationship index (to record `entity`) or any multi-token index (to record `tokens[1..]`). A
    /// single-token **node** index needs none (the base block's single token + the default
    /// [`FulltextEntity::Node`] fully describe it), keeping a legacy image extension-free.
    #[must_use]
    fn needs_extension(&self) -> bool {
        self.entity.is_relationship() || self.tokens.len() > 1
    }
}

/// The **entity dimension** a spatial (point) index covers: node labels or relationship types
/// (`rmp` task #664).
///
/// Neo4j-5.x point indexes come in two flavours — one over **nodes** (`FOR (n:L) ON (n.p)`) and one
/// over **relationships** (`FOR ()-[r:T]-() ON (r.p)`). Both share the grid machinery and the
/// single-point-property shape; only the covered token namespace ([`Label`](crate::tokens::Namespace::Label)
/// vs [`RelType`](crate::tokens::Namespace::RelType)) and the access path (a node label scan vs a typed
/// relationship traversal) differ. This one-byte discriminant records which flavour a
/// [`SpatialIndexEntry`] is — the exact twin of [`FulltextEntity`].
///
/// # Wire encoding
///
/// Encoded as a single byte in the **backward-compatible spatial extension block** (see
/// [`Statistics::encode`]), never in the base spatial catalog block. A pre-#664 image has no extension
/// block, so every legacy entry decodes as [`Node`](Self::Node) — the only flavour that existed before
/// #664. [`from_byte`](Self::from_byte) rejects an unknown byte (a forward-incompatible image),
/// mirroring [`IndexState::from_byte`] / [`FulltextEntity::from_byte`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[must_use]
pub enum SpatialEntity {
    /// The index covers **node labels** (`FOR (n:L) ON (n.p)`). The default and the only flavour a
    /// pre-#664 image knows.
    #[default]
    Node,
    /// The index covers **relationship types** (`FOR ()-[r:T]-() ON (r.p)`, `rmp` task #664).
    Relationship,
}

impl SpatialEntity {
    /// The single-byte wire discriminant (`rmp` task #664). Discriminants `2..` are reserved.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Node => 0,
            Self::Relationship => 1,
        }
    }

    /// Decodes a single-byte wire discriminant, or [`None`] for an unknown (reserved/future) byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Node),
            1 => Some(Self::Relationship),
            _ => None,
        }
    }

    /// Whether this is a **relationship** point index (its covered token is a
    /// [`RelType`](crate::tokens::Namespace::RelType) token, served by a typed relationship traversal).
    #[must_use]
    pub const fn is_relationship(self) -> bool {
        matches!(self, Self::Relationship)
    }
}

/// A durable **spatial (point) index** catalog entry (`rmp` tasks #98, #664).
///
/// A spatial index is identified by a server-unique **name** (like a full-text index, and unlike a
/// node-property index which `(label_token, prop_key)` identifies), covers — per its
/// [`entity`](Self::entity) — one node label *or* one relationship type (the
/// [`label_token`](Self::label_token) slot) and **exactly one** point property, and — unlike the
/// full-text index — carries **no analyzer**: a grid spatial index simply buckets the covered point
/// property's coordinates, so only the covered label/type, the covered property and the build state
/// need to be recorded.
///
/// This rides the **identical** durability lifecycle as the full-text index catalog and the
/// counts/histograms: checkpointed at commit, reloaded on rollback and on open. Its presence
/// invariant is "an entry exists iff a spatial index of that name is declared". The grid *data*
/// itself is never persisted (it is ephemeral and rebuilt from the store on open, like the derived
/// `IndexSet`), so only this catalog entry needs durability.
///
/// # Backward-compatible encoding (`rmp` task #664)
///
/// The base spatial catalog block still writes the covered token in the same `label_token` slot so its
/// byte layout is unchanged; a pre-#664 image decodes to `entity: Node` + that token. The
/// [`entity`](Self::entity) lives in a trailing extension block keyed by name (present only for a
/// relationship index), so a legacy node index needs no extension entry. See [`Statistics::encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpatialIndexEntry {
    /// Whether the index covers a node label or a relationship type (`rmp` task #664).
    pub entity: SpatialEntity,
    /// The covered token: a node [`Label`](crate::tokens::Namespace::Label) token when
    /// [`entity`](Self::entity) is [`Node`](SpatialEntity::Node), a relationship
    /// [`RelType`](crate::tokens::Namespace::RelType) token when it is
    /// [`Relationship`](SpatialEntity::Relationship). Persisted verbatim in the base block's single
    /// token slot, so a pre-#664 image decodes this as a node label token.
    pub label_token: u32,
    /// The property-key-namespace token the index covers (a single point property).
    pub property_token: u32,
    /// The build state of the index (the same state machine as a node-property / full-text index).
    pub state: IndexState,
}

impl SpatialIndexEntry {
    /// Whether the base + extension encoding must emit an **extension entry** for this index: a
    /// relationship index (to record its [`SpatialEntity`]). A **node** index needs none (the base
    /// block's token + the default [`SpatialEntity::Node`] fully describe it), keeping a legacy image
    /// extension-free — the twin of [`FulltextIndexEntry::needs_extension`].
    #[must_use]
    fn needs_extension(&self) -> bool {
        self.entity.is_relationship()
    }
}

/// A durable **composite (multi-property) node index** catalog entry (`rmp` task #657).
///
/// A composite RANGE index is identified by a server-unique **name** (like a full-text or spatial
/// index, and unlike a single-property node index which `(label_token, prop_key)` identifies),
/// covers one node label and **two or more** property tokens **in declared order** (the key order is
/// significant — `(a, b)` differs from `(b, a)`). It is the multi-key generalisation of the
/// single-property node index: a `MATCH (n:L {a: …, b: …})` consumes the leading equality conjuncts
/// into one composite seek. Unlike a node-key constraint's backing composite (`rmp` task #100), a
/// standalone composite index enforces **no uniqueness** — it is a pure query accelerator.
///
/// This rides the **identical** durability lifecycle as the full-text / spatial index catalogs:
/// checkpointed at commit, reloaded on rollback and on open. Its presence invariant is "an entry
/// exists iff a composite index of that name is declared". The backing B+-tree *data* itself is never
/// persisted (it is ephemeral and rebuilt from the store on open, like the derived `IndexSet`), so
/// only this catalog entry needs durability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeIndexEntry {
    /// The node label-namespace token the index covers.
    pub label_token: u32,
    /// The property-key-namespace tokens the index covers, **in declared order** (two or more; the
    /// arity-1 case is served by the single-property node-property index, never recorded here).
    pub property_tokens: Vec<u32>,
    /// The build state of the index (the same state machine as a node-property / full-text index).
    pub state: IndexState,
}

/// A durable **composite (multi-property) relationship index** catalog entry (`rmp` task #666) — the
/// relationship analogue of [`CompositeIndexEntry`].
///
/// A composite relationship RANGE index is identified by a server-unique **name**, covers one
/// relationship **type** and **two or more** property tokens **in declared order** (the key order is
/// significant — `(a, b)` differs from `(b, a)`). It is the multi-key generalisation of the
/// single-property relationship index (`rmp` task #646): a `MATCH ()-[r:T {a: …, b: …}]-()` consumes
/// the leading equality conjuncts into one composite relationship seek. It enforces **no uniqueness**
/// — a pure query accelerator.
///
/// It is kept in its **own** durable catalog (not merged into the node [`composite_indexes`] map)
/// because a relationship-type token and a node-label token share the numeric token space: mixing them
/// in one map keyed by token could conflate a relationship index with a node index of the same numeric
/// token. This mirrors how the relationship-property index catalog is kept separate from the
/// node-property one, and how the in-memory `IndexSet` keeps `spatial_rel` / `fulltext_rel` separate
/// from their node maps.
///
/// This rides the **identical** durability lifecycle as the node composite catalog: checkpointed at
/// commit, reloaded on rollback and on open. Its presence invariant is "an entry exists iff a composite
/// relationship index of that name is declared". The backing B+-tree *data* itself is never persisted
/// (it is ephemeral and rebuilt from the store on open, like the derived `IndexSet`), so only this
/// catalog entry needs durability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelCompositeIndexEntry {
    /// The relationship-type-namespace token the index covers.
    pub type_token: u32,
    /// The property-key-namespace tokens the index covers, **in declared order** (two or more; the
    /// arity-1 case is served by the single-property relationship-property index, never recorded here).
    pub property_tokens: Vec<u32>,
    /// The build state of the index (the same state machine as a relationship-property index).
    pub state: IndexState,
}

/// A durable **text (trigram) node index** catalog entry (`rmp` task #662).
///
/// A `TEXT` index is a **distinct native string index** — not a synonym of `RANGE` — that accelerates
/// the `CONTAINS`, `ENDS WITH` and `STARTS WITH` predicates a forward-ordered B-tree cannot serve
/// (substring/suffix are not a contiguous key range). Like a spatial index it is identified by a
/// server-unique **name**, covers **one** node label and **exactly one** string property, and its
/// backing structure (`graphus_index::TrigramIndex`) is derived/ephemeral (rebuilt from the store on
/// open, like the derived `IndexSet`), so **only this catalog entry needs durability**.
///
/// This rides the **identical** durability lifecycle as the full-text / spatial / composite index
/// catalogs: checkpointed at commit, reloaded on rollback and on open. Its presence invariant is "an
/// entry exists iff a text index of that name is declared".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextIndexEntry {
    /// The node label-namespace token the index covers.
    pub label_token: u32,
    /// The property-key-namespace token the index covers (exactly one — a text index is single-property).
    pub property_token: u32,
    /// The build state of the index (the same state machine as a node-property / spatial index).
    pub state: IndexState,
}

/// The **entity dimension** a vector (HNSW) index covers: node labels or relationship types
/// (`rmp` task #669) — the vector analogue of [`FulltextEntity`] / [`SpatialEntity`].
///
/// A vector index comes in two flavours — one over **nodes** (`FOR (n:Label) ON (n.embedding)`) and
/// one over **relationships** (`FOR ()-[r:Type]-() ON (r.embedding)`). Both share the HNSW machinery,
/// the covered embedding property, the dimension, the similarity metric and the build parameters; only
/// the covered token namespace ([`Label`](crate::tokens::Namespace::Label) vs
/// [`RelType`](crate::tokens::Namespace::RelType)) differs. This one-byte discriminant records which
/// flavour a [`VectorIndexEntry`] is.
///
/// # Wire encoding
///
/// Encoded verbatim as a single byte inside the vector catalog block (see [`Statistics::encode`]).
/// Unlike the full-text / spatial entity (which rides a trailing extension block for byte-compatibility
/// with a pre-existing base block), the vector catalog is a **wholly new** trailing block, so the
/// entity is stored inline. [`from_byte`](Self::from_byte) rejects an unknown byte (a
/// forward-incompatible image), mirroring [`IndexState::from_byte`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[must_use]
pub enum VectorEntity {
    /// The index covers **node labels** (`FOR (n:Label) ON (n.embedding)`). The default.
    #[default]
    Node,
    /// The index covers **relationship types** (`FOR ()-[r:Type]-() ON (r.embedding)`).
    Relationship,
}

impl VectorEntity {
    /// The single-byte wire discriminant (`rmp` task #669). Discriminants `2..` are reserved.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Node => 0,
            Self::Relationship => 1,
        }
    }

    /// Decodes a single-byte wire discriminant, or [`None`] for an unknown (reserved/future) byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Node),
            1 => Some(Self::Relationship),
            _ => None,
        }
    }

    /// Whether this is a **relationship** vector index (its covered token is a
    /// [`RelType`](crate::tokens::Namespace::RelType) token).
    #[must_use]
    pub const fn is_relationship(self) -> bool {
        matches!(self, Self::Relationship)
    }
}

/// The similarity metric a vector (HNSW) index uses (`rmp` task #669), fixed at declaration.
///
/// Mirrors `graphus_index::Similarity`, but storage does **not** depend on `graphus-index` (exactly as
/// the full-text analyzer byte is interpreted by the query layer, not storage). The query layer maps
/// this durable discriminant to the in-memory `Similarity` when it (re)builds the HNSW graph on open.
/// [`from_byte`](Self::from_byte) rejects an unknown byte so a forward-incompatible image is caught
/// rather than silently mis-decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[must_use]
pub enum VectorSimilarity {
    /// Cosine similarity (vectors unit-normalised on insert). The default.
    #[default]
    Cosine,
    /// Euclidean similarity (squared L2 distance).
    Euclidean,
}

impl VectorSimilarity {
    /// The single-byte wire discriminant (`rmp` task #669). Discriminants `2..` are reserved.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Cosine => 0,
            Self::Euclidean => 1,
        }
    }

    /// Decodes a single-byte wire discriminant, or [`None`] for an unknown (reserved/future) byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Cosine),
            1 => Some(Self::Euclidean),
            _ => None,
        }
    }
}

/// A durable **vector (HNSW) index** catalog entry (`rmp` task #669).
///
/// A vector index is an approximate-nearest-neighbour (ANN) index over a dense `f32` embedding
/// property, built on an HNSW graph (`graphus_index::VectorIndex`, `rmp` task #668). It is identified by
/// a server-unique **name** (like a full-text / spatial / text index), covers — per its
/// [`entity`](Self::entity) — **one** node label *or* relationship type and **exactly one** embedding
/// property, and carries its fixed shape: the embedding [`dimensions`](Self::dimensions), the
/// [`similarity`](Self::similarity) metric and the HNSW build parameters
/// [`m`](Self::m) / [`ef_construction`](Self::ef_construction).
///
/// Its backing HNSW graph is derived/ephemeral (rebuilt from the store on open, like every other
/// derived index), so **only this catalog entry needs durability**. It rides the **identical**
/// durability lifecycle as the full-text / spatial / composite / text index catalogs: checkpointed at
/// commit, reloaded on rollback and on open. Its presence invariant is "an entry exists iff a vector
/// index of that name is declared".
///
/// # Wire encoding (`rmp` task #669)
///
/// Encoded in its **own** trailing catalog block, appended LAST (after the relationship composite
/// block), so a pre-#669 image — ending after that block — decodes to an empty vector catalog via the
/// end-of-input guard. Because the block is wholly new (no pre-existing base block to stay
/// byte-compatible with), every field — including the [`entity`](Self::entity) — is stored inline; there
/// is no split base + extension block as full-text / spatial use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorIndexEntry {
    /// Whether the index covers a node label or a relationship type (`rmp` task #669).
    pub entity: VectorEntity,
    /// The covered token: a node [`Label`](crate::tokens::Namespace::Label) token when
    /// [`entity`](Self::entity) is [`Node`](VectorEntity::Node), a relationship
    /// [`RelType`](crate::tokens::Namespace::RelType) token when it is
    /// [`Relationship`](VectorEntity::Relationship).
    pub token: u32,
    /// The property-key-namespace token the embedding property occupies (exactly one).
    pub property_token: u32,
    /// The embedding dimension (`> 0`; the covered property must be a numeric list of this length).
    pub dimensions: u32,
    /// The similarity metric the HNSW graph navigates by (`rmp` task #669).
    pub similarity: VectorSimilarity,
    /// The HNSW `m` build parameter (target out-degree per layer).
    pub m: u32,
    /// The HNSW `ef_construction` build parameter (construction candidate-list size).
    pub ef_construction: u32,
    /// The build state of the index (the same state machine as a node-property / spatial index).
    pub state: IndexState,
}

/// The kind of a declared constraint (`rmp` tasks #99, #100).
///
/// A constraint is one of four schema rules over the nodes of a label:
///
/// - [`Unique`](Self::Unique) — a **uniqueness** constraint: no two nodes carrying the label may
///   share the same value for the covered property (a duplicate write is rejected before commit).
/// - [`Existence`](Self::Existence) — an **existence** (`NOT NULL`) constraint: every node carrying
///   the label must carry the covered property with a non-null value (a write that omits or nulls it
///   is rejected before commit).
/// - [`NodeKey`](Self::NodeKey) — a **node-key** constraint (`rmp` task #100): the combination of the
///   covered (one or more) properties must be both **present** (every property non-null — existence)
///   **and unique** as a tuple across all nodes carrying the label. It is the composite generalisation
///   of `Unique` + `Existence` over the property *tuple* (a single-property node key is the common
///   degenerate case).
/// - [`PropertyType`](Self::PropertyType) — a **property-type** constraint (`rmp` task #100): when the
///   covered property is present on a node carrying the label, its value's type must match the
///   constraint's declared [`ConstraintTypeDescriptor`] (a write storing a value of the wrong type is
///   rejected before commit). It does **not** require the property to be present — only that, *if*
///   present, it conforms to the declared type.
///
/// # Wire encoding
///
/// Encoded as a single byte (see [`Statistics::encode`]). Future kinds (a relationship-property
/// constraint) are reserved by leaving the unused discriminants free; [`from_byte`](Self::from_byte)
/// rejects any unknown byte so a forward-incompatible image is caught rather than silently
/// mis-decoded — the same defensive stance as [`IndexState::from_byte`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub enum ConstraintKind {
    /// A uniqueness constraint: the covered property's value is unique across all nodes of the label.
    Unique,
    /// An existence (`NOT NULL`) constraint: every node of the label must carry the covered property.
    Existence,
    /// A node-key constraint (`rmp` task #100): the covered property *tuple* is present on, and unique
    /// across, every node of the label.
    NodeKey,
    /// A property-type constraint (`rmp` task #100): the covered property, when present on a node of
    /// the label, has a value matching the declared [`ConstraintTypeDescriptor`].
    PropertyType,
    /// A **relationship** uniqueness constraint (`rmp` #638): the covered property's value is unique
    /// across all relationships of the type. The [`ConstraintEntry::label_token`] holds the
    /// relationship-**type** token (not a label token) for every `Rel*` kind.
    RelUnique,
    /// A **relationship** existence (`NOT NULL`) constraint (`rmp` #638): every relationship of the
    /// type must carry the covered property.
    RelExistence,
    /// A **relationship** key constraint (`rmp` #638): the covered property *tuple* is present on, and
    /// unique across, every relationship of the type.
    RelKey,
    /// A **relationship** property-type constraint (`rmp` #638): the covered property, when present on
    /// a relationship of the type, matches the declared [`ConstraintTypeDescriptor`].
    RelPropertyType,
}

impl ConstraintKind {
    /// The single-byte wire discriminant (`rmp` tasks #99, #100, #638). Discriminants `4..=7` carry the
    /// relationship-constraint kinds (`rmp` #638); `8..` remain reserved.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Unique => 0,
            Self::Existence => 1,
            Self::NodeKey => 2,
            Self::PropertyType => 3,
            Self::RelUnique => 4,
            Self::RelExistence => 5,
            Self::RelKey => 6,
            Self::RelPropertyType => 7,
        }
    }

    /// Decodes a single-byte wire discriminant, or [`None`] for an unknown (reserved/future) byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Unique),
            1 => Some(Self::Existence),
            2 => Some(Self::NodeKey),
            3 => Some(Self::PropertyType),
            4 => Some(Self::RelUnique),
            5 => Some(Self::RelExistence),
            6 => Some(Self::RelKey),
            7 => Some(Self::RelPropertyType),
            _ => None,
        }
    }

    /// Whether this is a **relationship** constraint kind (`rmp` #638) — i.e. its covering token is a
    /// relationship-type token, and it is validated/enforced against relationships rather than nodes.
    #[must_use]
    pub const fn is_relationship(self) -> bool {
        matches!(
            self,
            Self::RelUnique | Self::RelExistence | Self::RelKey | Self::RelPropertyType
        )
    }
}

/// The declared value type a [`ConstraintKind::PropertyType`] constraint enforces (`rmp` tasks #100,
/// #652).
///
/// Models the **closed set of property types** a Neo4j-5.x `IS :: <TYPE>` property-type constraint can
/// declare: the scalar types `BOOLEAN`, `STRING`, `INTEGER`, `FLOAT`, the temporal types (`DATE`,
/// `LOCAL TIME`, `ZONED TIME`, `LOCAL DATETIME`, `ZONED DATETIME`, `DURATION`), `POINT`; a
/// `LIST<inner>` of one of those (a Neo4j constraint list element is always `NOT NULL`, which the value
/// model enforces for free — a `null` never matches a concrete scalar); and a closed dynamic
/// [`Union`](Self::Union) of the above (`INTEGER | STRING`). Storage carries this descriptor
/// **verbatim** and never matches a value against it — the query layer (`graphus-cypher`) maps each
/// variant onto the [`graphus_core::Value`](graphus_core::Value) model and performs the type check.
/// Defining it here keeps the durable [`ConstraintEntry`] self-contained and lets the byte encoding
/// live beside the other catalog blocks.
///
/// # Wire encoding
///
/// A scalar is a single tag byte; a [`List`](Self::List) is its tag byte followed by its element
/// descriptor's own encoding; a [`Union`](Self::Union) is its tag byte, a `u8` member count, then each
/// member's own encoding. The scalar tags `0..=5` (`INTEGER`/`FLOAT`/`STRING`/`BOOLEAN`/`LIST`/`ANY`)
/// keep the exact discriminants of the original #100 encoding, so a pre-#652 image decodes unchanged;
/// the temporal/point/union tags occupy `6..=13`. [`Any`](Self::Any) survives only for backward
/// compatibility as a list-element wildcard (legacy `LIST<ANY>`); it is never a valid top-level Neo4j
/// constraint type. [`decode`](Self::decode) rejects an unknown tag (forward-incompatible image),
/// a member count that would exceed [`MAX_UNION_MEMBERS`](Self::MAX_UNION_MEMBERS), and a nesting
/// depth beyond [`MAX_TYPE_DEPTH`](Self::MAX_TYPE_DEPTH) (a defensive bound against a crafted image).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintTypeDescriptor {
    /// openCypher `INTEGER` — a [`Value::Integer`](graphus_core::Value::Integer).
    Integer,
    /// openCypher `FLOAT` — a [`Value::Float`](graphus_core::Value::Float).
    Float,
    /// openCypher `STRING` — a [`Value::String`](graphus_core::Value::String).
    String,
    /// openCypher `BOOLEAN` — a [`Value::Boolean`](graphus_core::Value::Boolean).
    Boolean,
    /// openCypher `LIST<inner NOT NULL>` — a [`Value::List`](graphus_core::Value::List) whose every
    /// element matches `inner` (a boxed element descriptor). A `null` element never matches a concrete
    /// scalar, so the `NOT NULL` element guarantee holds by construction. Legacy images may carry
    /// [`Any`](Self::Any) as `inner` (a bare `LIST<ANY>`).
    List(Box<ConstraintTypeDescriptor>),
    /// "Any type" — a legacy [`List`](Self::List) element placeholder (`LIST<ANY>`); never a valid
    /// top-level Neo4j constraint type. Retained only so a pre-#652 image decodes.
    Any,
    /// openCypher `DATE` — a [`Value::Date`](graphus_core::Value::Date).
    Date,
    /// openCypher `LOCAL TIME` — a [`Value::LocalTime`](graphus_core::Value::LocalTime).
    LocalTime,
    /// openCypher `ZONED TIME` — a [`Value::ZonedTime`](graphus_core::Value::ZonedTime).
    ZonedTime,
    /// openCypher `LOCAL DATETIME` — a [`Value::LocalDateTime`](graphus_core::Value::LocalDateTime).
    LocalDateTime,
    /// openCypher `ZONED DATETIME` — a [`Value::ZonedDateTime`](graphus_core::Value::ZonedDateTime).
    ZonedDateTime,
    /// openCypher `DURATION` — a [`Value::Duration`](graphus_core::Value::Duration).
    Duration,
    /// openCypher `POINT` — a [`Value::Point`](graphus_core::Value::Point).
    Point,
    /// A closed dynamic union `A | B | …` (`INTEGER | STRING`): matches a value conforming to **any**
    /// member. Always carries two or more members (a lone member collapses to that member at parse
    /// time).
    Union(Vec<ConstraintTypeDescriptor>),
}

impl ConstraintTypeDescriptor {
    /// The upper bound on [`Union`](Self::Union) members accepted by [`decode`](Self::decode). The
    /// closed property-type set is ~18 members, so a `u8` count (max 255) is generous while bounding a
    /// crafted image's allocation. **The write path MUST reject a descriptor exceeding this** (the DDL
    /// parser in `graphus-server`) so nothing undecodable is ever persisted (`rmp` #652).
    pub const MAX_UNION_MEMBERS: usize = 255;

    /// The maximum descriptor nesting depth accepted by [`decode`](Self::decode) — the storage-decode
    /// depth of the deepest node (a top-level scalar is depth `0`; `LIST<scalar>` puts its element at
    /// depth `1`; a `Union` puts each member one deeper). A Neo4j constraint type nests at most
    /// `LIST<scalar>` inside a `union`, so `8` is far beyond any real declaration while preventing a
    /// crafted image from exhausting the stack via nested `LIST`/`Union` tags. **The write path MUST
    /// reject a descriptor whose [`storage_depth`](Self::storage_depth) exceeds this** (the DDL parser
    /// in `graphus-server`) so a committed `CREATE CONSTRAINT` can never persist an image `decode`
    /// rejects — which would leave the store unopenable (`rmp` #652).
    pub const MAX_TYPE_DEPTH: usize = 8;

    /// The maximum storage-decode depth of any node in this descriptor — the depth
    /// [`decode`](Self::decode) reaches: a scalar is `0`, a [`List`](Self::List) is `1 +
    /// inner.storage_depth()`, and a [`Union`](Self::Union) is `1 + max(member depth)`. The write path
    /// (the DDL parser) rejects a descriptor whose value exceeds
    /// [`MAX_TYPE_DEPTH`](Self::MAX_TYPE_DEPTH), guaranteeing every persisted descriptor round-trips
    /// through [`decode`](Self::decode) (`rmp` #652).
    #[must_use]
    pub fn storage_depth(&self) -> usize {
        match self {
            Self::List(inner) => 1 + inner.storage_depth(),
            Self::Union(members) => 1 + members.iter().map(Self::storage_depth).max().unwrap_or(0),
            _ => 0,
        }
    }

    /// The single tag byte for this descriptor (`rmp` tasks #100, #652). For a [`List`](Self::List)
    /// this is just the list tag; its element descriptor is encoded separately by
    /// [`encode`](Self::encode). Discriminants `0..=5` are frozen from the #100 encoding.
    const fn tag_byte(&self) -> u8 {
        match self {
            Self::Integer => 0,
            Self::Float => 1,
            Self::String => 2,
            Self::Boolean => 3,
            Self::List(_) => 4,
            Self::Any => 5,
            Self::Date => 6,
            Self::LocalTime => 7,
            Self::ZonedTime => 8,
            Self::LocalDateTime => 9,
            Self::ZonedDateTime => 10,
            Self::Duration => 11,
            Self::Point => 12,
            Self::Union(_) => 13,
        }
    }

    /// Appends the self-describing byte encoding of this descriptor to `out` (`rmp` tasks #100, #652):
    /// the tag byte, followed — for a [`List`](Self::List) — by its element descriptor's own encoding,
    /// or — for a [`Union`](Self::Union) — by a `u8` member count then each member's encoding.
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.tag_byte());
        match self {
            Self::List(inner) => inner.encode(out),
            Self::Union(members) => {
                debug_assert!(
                    members.len() <= Self::MAX_UNION_MEMBERS,
                    "constraint union exceeds the encodable member count"
                );
                out.push(members.len() as u8);
                for member in members {
                    member.encode(out);
                }
            }
            _ => {}
        }
    }

    /// Decodes a descriptor from `bytes` starting at `cur`, advancing past it (`rmp` tasks #100, #652).
    ///
    /// # Errors
    /// Returns a storage error on truncation, an unknown tag byte (a forward-incompatible image), a
    /// union member count above [`MAX_UNION_MEMBERS`](Self::MAX_UNION_MEMBERS), or a nesting depth
    /// beyond [`MAX_TYPE_DEPTH`](Self::MAX_TYPE_DEPTH).
    fn decode(bytes: &[u8], cur: &mut usize) -> Result<Self> {
        Self::decode_at_depth(bytes, cur, 0)
    }

    fn decode_at_depth(bytes: &[u8], cur: &mut usize, depth: usize) -> Result<Self> {
        if depth > Self::MAX_TYPE_DEPTH {
            return Err(GraphusError::Storage(
                "constraint type descriptor nests beyond the maximum depth".to_owned(),
            ));
        }
        let tag = read_u8(bytes, cur)?;
        match tag {
            0 => Ok(Self::Integer),
            1 => Ok(Self::Float),
            2 => Ok(Self::String),
            3 => Ok(Self::Boolean),
            4 => Ok(Self::List(Box::new(Self::decode_at_depth(
                bytes,
                cur,
                depth + 1,
            )?))),
            5 => Ok(Self::Any),
            6 => Ok(Self::Date),
            7 => Ok(Self::LocalTime),
            8 => Ok(Self::ZonedTime),
            9 => Ok(Self::LocalDateTime),
            10 => Ok(Self::ZonedDateTime),
            11 => Ok(Self::Duration),
            12 => Ok(Self::Point),
            13 => {
                let n = read_u8(bytes, cur)? as usize;
                if n > Self::MAX_UNION_MEMBERS {
                    return Err(GraphusError::Storage(format!(
                        "constraint union holds too many members ({n})"
                    )));
                }
                let mut members = Vec::with_capacity(n);
                for _ in 0..n {
                    members.push(Self::decode_at_depth(bytes, cur, depth + 1)?);
                }
                Ok(Self::Union(members))
            }
            other => Err(GraphusError::Storage(format!(
                "constraint type descriptor holds unknown tag byte {other}"
            ))),
        }
    }
}

/// A durable **constraint** catalog entry (`rmp` task #99).
///
/// A constraint is identified by a server-unique **name** (like a full-text or spatial index, and
/// unlike a node-property index which `(label_token, prop_key)` identifies), covers one node label
/// and **one or more** properties (v1 declares exactly one property per constraint; the field is a
/// `Vec` so a future composite node-key fits the same record), and carries its [`ConstraintKind`].
///
/// This rides the **identical** durability lifecycle as the index catalogs and the
/// counts/histograms: checkpointed at commit, reloaded on rollback and on open. Its presence
/// invariant is "an entry exists iff a constraint of that name is declared". Unlike an index there is
/// **no build state**: a constraint is validated against existing data **synchronously** at creation
/// time (creation fails if any existing node violates it), so a successfully-created constraint is
/// always fully in force — there is no `Populating` analogue. For a uniqueness or node-key constraint
/// the coordinator additionally maintains a backing in-memory index (rebuilt from the store on open,
/// like every derived index), so only this catalog entry needs durability.
///
/// # Composite & typed kinds (`rmp` task #100)
///
/// `property_tokens` is a [`Vec`] so a [`ConstraintKind::NodeKey`] node-key constraint records its
/// whole composite property tuple in declared order. The [`type_descriptor`](Self::type_descriptor)
/// field carries the declared value type of a [`ConstraintKind::PropertyType`] constraint and is
/// [`None`] for every other kind — see its docs for the backward-compatible encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintEntry {
    /// The covering token: a **node label** token for the node kinds
    /// (`Unique`/`Existence`/`NodeKey`/`PropertyType`), or a **relationship-type** token for the
    /// `Rel*` kinds (`rmp` #638). Which namespace it lives in is selected by
    /// [`ConstraintKind::is_relationship`].
    pub label_token: u32,
    /// The property-key-namespace tokens the constraint covers, in declared order (one or more; one
    /// for `Unique`/`Existence`/`PropertyType`, one-or-more for a composite `NodeKey`).
    pub property_tokens: Vec<u32>,
    /// Whether the constraint is a uniqueness, existence, node-key or property-type rule.
    pub kind: ConstraintKind,
    /// The declared value type of a [`ConstraintKind::PropertyType`] constraint (`rmp` task #100), or
    /// [`None`] for every other kind. Encoded in a **backward-compatible trailing block** of the
    /// constraint catalog (a per-entry presence byte + the descriptor), so a pre-#100 image — written
    /// before this field existed and ending after the per-entry `kind` byte — decodes every entry with
    /// `type_descriptor: None`. See [`Statistics::encode`].
    pub type_descriptor: Option<ConstraintTypeDescriptor>,
}

/// Exact live-record cardinalities maintained in the durable catalog (`rmp` task #79).
///
/// Holds, for the planner's cardinality estimator, the grand-total live-node and live-relationship
/// counts (`rmp` task #82), plus how many currently-**live** nodes carry each
/// [`Label`](crate::tokens::Namespace::Label)-namespace token id, and how many currently-live
/// relationships have each [`RelType`](crate::tokens::Namespace::RelType)-namespace token id, so the
/// planner gets exact cardinalities by an O(1) lookup with no scan.
///
/// # Why the grand totals are stored, not derived
///
/// The planner's `Statistics` seam needs a **non-optional** total live-node count and total
/// live-relationship count. Neither is recoverable from the per-label / per-type maps: a node may
/// carry several labels (summing `nodes_per_label` overcounts) or none (summing undercounts). The
/// grand totals are therefore maintained at the node-/relationship-creation and -deletion sites,
/// once per record, independently of any label or type contribution.
///
/// # What "live" means here, and why it is crash- and abort-safe
///
/// A record is *live* for counting exactly when it is the latest visible version: its slot is in use
/// **and** it carries no MVCC expiry tombstone (`xmax == 0`) — the
/// [`RecordStore::is_live_version`](crate::RecordStore) predicate. The store therefore adjusts these
/// counts on the **committed transition** that changes a record's live contribution:
/// `create_node`/`create_rel` increment (the grand totals once per record, the per-type map once per
/// relationship); `delete_node`/`delete_rel` (which stamp the `xmax` tombstone, `04 §5.3`) decrement;
/// `set_node_labels`/`add_label`/`remove_label` adjust the per-label delta on a live node (the grand
/// total is unaffected — a label change never creates or destroys a node).
/// GC reclamation ([`reclaim_node`](crate::RecordStore)/[`reclaim_rel`](crate::RecordStore)) does
/// **not** touch the counts — the decrement already happened at the tombstone-stamping delete.
///
/// Because the whole catalog (this struct included) is persisted only at commit by
/// [`checkpoint_meta`](crate::RecordStore) and reloaded wholesale on rollback and on
/// [`open`](crate::RecordStore) (post-recovery) from the durable metadata page, these counts follow
/// the **identical** durability lifecycle as the id high-water marks and free lists: an aborted
/// transaction's in-memory increments/decrements are discarded by the catalog reload, and a crash
/// recovers the last committed counts. No path overcounts on abort or double-counts on replay.
///
/// # Determinism and the zero-count invariant
///
/// The maps are [`BTreeMap`]s so the encoding (and [`PartialEq`]) is deterministic. A token id whose
/// count reaches `0` is **removed** from the map rather than left at `0`, so equality against a fresh
/// full re-scan (which only ever inserts positive counts) always holds.
///
/// # Property histograms (`rmp` task #81)
///
/// Beyond the two cardinality maps, the catalog also carries opaque per-indexed-property value
/// histograms, keyed by `(label_token, property_key_token)` — see
/// [`node_prop_histograms`](Self#structfield.node_prop_histograms). Storage stores those bytes
/// **verbatim** and never interprets them; they ride the exact same durability lifecycle as the
/// counts (checkpointed at commit, reloaded on rollback and on open). Their presence invariant is
/// "an entry exists iff a histogram exists" — there is no zero-count analogue, but a zero-length
/// blob is rejected (a histogram is never empty).
///
/// # Node-property index catalog (`rmp` task #90)
///
/// The catalog also records the **set of declared node-property indexes** and each one's build
/// [`IndexState`], keyed by `(label_token, property_key_token)` — see
/// [`node_property_indexes`](Self#structfield.node_property_indexes). This is what makes index
/// *registration* durable: before this task the set of registered node-property indexes lived only
/// in the in-memory `IndexSet`, so after a crash + reopen the rebuilt empty `IndexSet` found no
/// registered indexes and the index was silently lost. Persisting the catalog here lets a recovered
/// store repopulate its indexes automatically. The map rides the **identical** durability lifecycle
/// as the counts and histograms (checkpointed at commit, reloaded on rollback and on open). Its
/// presence invariant is "an entry exists iff an index is declared"; the value is the index's
/// current state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Statistics {
    /// The total number of currently-live nodes, **labelled or not** (`rmp` task #82). This is the
    /// grand total the planner's `Statistics` seam requires; it is *not* derivable from
    /// [`nodes_per_label`](Self#structfield.nodes_per_label): a node may carry several labels (so
    /// summing the per-label counts overcounts) or none (so summing undercounts). It is therefore
    /// maintained at the node-creation/-deletion site, once per node, independently of labels.
    pub total_nodes: u64,
    /// The total number of currently-live relationships (`rmp` task #82). Maintained once per
    /// relationship at the create/delete site. Unlike a per-type sum this is exact even though a
    /// relationship always has exactly one type — kept symmetric with [`total_nodes`](Self#structfield.total_nodes)
    /// and a single O(1) read for the planner's grand total.
    pub total_relationships: u64,
    /// `nodes_per_label[t]` is the number of currently-live nodes carrying the `Label`-namespace
    /// token id `t`. A node with `k` labels contributes `1` to each of its `k` entries; an unlabelled
    /// node contributes to none. Absent key == count `0`.
    pub nodes_per_label: BTreeMap<u32, u64>,
    /// `rels_per_type[t]` is the number of currently-live relationships whose `RelType`-namespace
    /// token id is `t`. Absent key == count `0`.
    pub rels_per_type: BTreeMap<u32, u64>,
    /// `rels_per_start_label_type[(l, t)]` is the number of currently-live relationships of `RelType`
    /// token `t` whose **start** node carries `Label` token `l` (`rmp` task #856). Absent key == `0`.
    ///
    /// One of the two **directional** projections the planner needs to tell a selective anchor from a
    /// fan-out one. [`rels_per_type`](Self#structfield.rels_per_type) alone gives a single graph-wide
    /// degree per type, which makes both ends of a relationship look identical: measured on the
    /// evaluation store, `LIKES` estimates a degree of 9.7 from *any* anchor while the true out-degree
    /// is about 10 from a `USER` and about 333 from an `ARTICLE`.
    ///
    /// A start node with `k` labels contributes `1` to each of its `k` entries, exactly as
    /// [`nodes_per_label`](Self#structfield.nodes_per_label) does — so summing this map over labels
    /// overcounts a multi-labelled endpoint and is never the way to recover a per-type total. Read one
    /// `(label, type)` pair at a time, which is the only shape the estimator asks for.
    ///
    /// This is the `(label, type, *)` wildcard projection, not the full `(label, type, label)` matrix:
    /// the matrix is quadratic in the label space for an estimate that needs only the anchor's side.
    pub rels_per_start_label_type: BTreeMap<(u32, u32), u64>,
    /// `rels_per_type_end_label[(t, l)]` is the number of currently-live relationships of `RelType`
    /// token `t` whose **end** node carries `Label` token `l` (`rmp` task #856). Absent key == `0`.
    ///
    /// The `(*, type, label)` mirror of
    /// [`rels_per_start_label_type`](Self#structfield.rels_per_start_label_type); every note there
    /// applies here with the endpoints exchanged. A **self-loop** contributes to both maps, because its
    /// one node is genuinely both the start and the end of that relationship.
    pub rels_per_type_end_label: BTreeMap<(u32, u32), u64>,
    /// Opaque, encoded per-(label-token, property-key-token) value histograms produced by the query
    /// layer (a later sub-task of `rmp` task #81; the planner's `ANALYZE`). Stored **verbatim** —
    /// storage never interprets the bytes (decoding would require a dependency on `graphus-index`,
    /// which depends on this crate, so doing so would form a dependency cycle).
    ///
    /// The key is `(label_token, property_key_token)`. **Scope: node label properties only** for this
    /// task; relationship-property histograms are deliberately deferred (consistent with the physical
    /// planner deferring relationship-index routing) and will be a separate map if/when added.
    ///
    /// Unlike the count maps there is no zero-value invariant: an entry is present **iff** a histogram
    /// exists for that `(label, property)` pair. The blob is always non-empty — a zero-length value is
    /// never stored (rejected by `set_property_histogram` and by [`decode`](Self::decode)).
    pub node_prop_histograms: BTreeMap<(u32, u32), Vec<u8>>,
    /// The durable **node-property index catalog** (`rmp` task #90): the set of declared node-property
    /// indexes and each one's build [`IndexState`], keyed by `(label_token, property_key_token)`.
    ///
    /// Persisting this set is what makes index *registration* survive a crash: the in-memory `IndexSet`
    /// holding the registered set is rebuilt empty on open, so without this map a recovered store had no
    /// record of which property indexes existed and silently lost them. An entry is present **iff** the
    /// index is declared; the value is its current build state. **Scope: node label properties only**
    /// (the same scope as [`node_prop_histograms`](Self#structfield.node_prop_histograms)).
    pub node_property_indexes: BTreeMap<(u32, u32), IndexState>,
    /// The durable **full-text index catalog** (`rmp` task #72): the set of declared full-text
    /// indexes keyed by their server-unique **name**, each carrying the covered label, the covered
    /// property tokens, the analyzer byte and the build [`IndexState`]. See [`FulltextIndexEntry`].
    ///
    /// Persisting this set is what makes a full-text index *registration* survive a crash: the
    /// inverted index itself is ephemeral (rebuilt from the store on open, like the derived
    /// `IndexSet`), so without this map a recovered store would have no record of which full-text
    /// indexes existed and would silently lose them. An entry is present **iff** an index of that
    /// name is declared. The map rides the **identical** durability lifecycle as the other catalogs.
    pub fulltext_indexes: BTreeMap<String, FulltextIndexEntry>,
    /// The durable **spatial (point) index catalog** (`rmp` task #98): the set of declared spatial
    /// indexes keyed by their server-unique **name**, each carrying the covered label, the covered
    /// point property token and the build [`IndexState`]. See [`SpatialIndexEntry`].
    ///
    /// Persisting this set is what makes a spatial index *registration* survive a crash: the grid
    /// itself is ephemeral (rebuilt from the store on open, like the derived `IndexSet`), so without
    /// this map a recovered store would have no record of which spatial indexes existed and would
    /// silently lose them. An entry is present **iff** an index of that name is declared. The map
    /// rides the **identical** durability lifecycle as the other catalogs.
    pub spatial_indexes: BTreeMap<String, SpatialIndexEntry>,
    /// The durable **constraint catalog** (`rmp` task #99): the set of declared constraints keyed by
    /// their server-unique **name**, each carrying the covered label, the covered property tokens and
    /// the [`ConstraintKind`]. See [`ConstraintEntry`].
    ///
    /// Persisting this set is what makes a constraint *declaration* survive a crash: write-time
    /// enforcement consults the live constraints, and a uniqueness constraint's backing index is
    /// ephemeral (rebuilt from the store on open, like the derived indexes), so without this map a
    /// recovered store would have no record of which constraints existed and would silently stop
    /// enforcing them. An entry is present **iff** a constraint of that name is declared. The map
    /// rides the **identical** durability lifecycle as the other catalogs.
    pub constraints: BTreeMap<String, ConstraintEntry>,
    /// The durable **node-property index name catalog** (`rmp` task #623): the server-unique **name**
    /// of each declared node-property index, keyed by name and mapping to the index's covered
    /// `(label_token, property_key_token)`.
    ///
    /// # Why a *separate* name map (and not a field on the anonymous catalog)
    ///
    /// The core node-property index catalog
    /// ([`node_property_indexes`](Self#structfield.node_property_indexes)) is keyed by
    /// `(label_token, property_key_token)` and carries no name — it predates named indexes. Rather
    /// than widen that block's per-entry record (which a pre-#623 reader could not skip, breaking the
    /// on-disk format for old images), the names live in their own appended, name-keyed block. A
    /// pre-#623 image ends after the constraint type-descriptor block, so this block decodes **empty**
    /// and every declared index is simply *nameless* — a legacy anonymous index. The Cypher layer
    /// backfills a deterministic auto-name for such indexes on open (`rmp` task #624), so nameless is
    /// only ever the transient pre-migration state.
    ///
    /// An entry is present **iff** a name is recorded for that index; the target `(label, property)`
    /// **must** name a declared node-property index (the two are set and removed together), which
    /// [`decode`](Self::decode) enforces. Names are globally unique across *all* schema catalogs — the
    /// uniqueness rule is enforced by the Cypher layer at declaration time, not here. This map rides
    /// the **identical** durability lifecycle as the other catalogs.
    pub node_property_index_names: BTreeMap<String, (u32, u32)>,
    /// The durable **relationship-property index catalog** (`rmp` task #646): the set of declared
    /// relationship-property indexes and each one's build [`IndexState`], keyed by
    /// `(rel_type_token, property_key_token)` — the relationship analogue of
    /// [`node_property_indexes`](Self#structfield.node_property_indexes).
    ///
    /// Persisting this set is what makes a relationship-property index *registration* survive a crash:
    /// the backing in-memory [`crate`]-external `RelPropertyIndex` is ephemeral (rebuilt from the store
    /// on open, like the derived `IndexSet`), so without this map a recovered store had no record of
    /// which relationship-property indexes existed and silently lost them. An entry is present **iff**
    /// the index is declared; the value is its current build state. The covering token is a
    /// **relationship-type** token (the [`RelType`](crate::tokens::Namespace::RelType) namespace), not a
    /// label token — a numeric value it can share with a label token, so the two catalogs never mix.
    /// The map rides the **identical** durability lifecycle as the other catalogs.
    pub rel_property_indexes: BTreeMap<(u32, u32), IndexState>,
    /// The durable **relationship-property index name catalog** (`rmp` task #646): the server-unique
    /// **name** of each declared relationship-property index, keyed by name and mapping to the index's
    /// covered `(rel_type_token, property_key_token)` — the relationship analogue of
    /// [`node_property_index_names`](Self#structfield.node_property_index_names).
    ///
    /// An entry is present **iff** a name is recorded for that index; the target `(rel_type, property)`
    /// **must** name a declared relationship-property index (the two are set and removed together),
    /// which [`decode`](Self::decode) enforces. Names are globally unique across *all* schema catalogs
    /// (node + relationship indexes, full-text, spatial, constraints) — the uniqueness rule is enforced
    /// by the Cypher layer at declaration time, not here. This map rides the **identical** durability
    /// lifecycle as the other catalogs.
    pub rel_property_index_names: BTreeMap<String, (u32, u32)>,
    /// The durable **composite (multi-property) node index catalog** (`rmp` task #657): the set of
    /// declared standalone composite indexes keyed by their server-unique **name**, each carrying the
    /// covered label token, the covered property-key tokens (in declared order, two or more) and the
    /// build [`IndexState`]. See [`CompositeIndexEntry`].
    ///
    /// Persisting this set is what makes a composite index *registration* survive a crash: the backing
    /// B+-tree is ephemeral (rebuilt from the store on open, like the derived `IndexSet`), so without
    /// this map a recovered store would have no record of which composite indexes existed and would
    /// silently lose them. An entry is present **iff** an index of that name is declared. The map rides
    /// the **identical** durability lifecycle as the other catalogs; it holds **only** arity-≥2 indexes
    /// (a single-property index lives in [`node_property_indexes`](Self#structfield.node_property_indexes)).
    pub composite_indexes: BTreeMap<String, CompositeIndexEntry>,
    /// The durable **composite (multi-property) relationship index catalog** (`rmp` task #666): the set
    /// of declared standalone composite relationship indexes keyed by their server-unique **name**, each
    /// carrying the covered relationship-type token, the covered property-key tokens (in declared order,
    /// two or more) and the build [`IndexState`]. See [`RelCompositeIndexEntry`].
    ///
    /// Kept **separate** from [`composite_indexes`](Self#structfield.composite_indexes) so a
    /// relationship-type token never conflates with a numerically-equal node-label token (exactly as
    /// [`rel_property_indexes`](Self#structfield.rel_property_indexes) is separate from the node one).
    /// Persisting this set is what makes a composite relationship index *registration* survive a crash;
    /// the backing B+-tree is ephemeral (rebuilt from the store on open). It holds **only** arity-≥2
    /// indexes (a single-property relationship index lives in
    /// [`rel_property_indexes`](Self#structfield.rel_property_indexes)).
    pub rel_composite_indexes: BTreeMap<String, RelCompositeIndexEntry>,
    /// The durable **text (trigram) node index catalog** (`rmp` task #662): the set of declared text
    /// indexes keyed by their server-unique **name**, each carrying the covered label token, the single
    /// covered property token and the build [`IndexState`]. See [`TextIndexEntry`].
    ///
    /// Persisting this set is what makes a text index *registration* survive a crash: the backing
    /// trigram index is ephemeral (rebuilt from the store on open, like the derived `IndexSet`), so
    /// without this map a recovered store would have no record of which text indexes existed and would
    /// silently lose them. An entry is present **iff** an index of that name is declared. The map rides
    /// the **identical** durability lifecycle as the other catalogs.
    pub text_indexes: BTreeMap<String, TextIndexEntry>,
    /// The durable **vector (HNSW) index catalog** (`rmp` task #669): the set of declared vector indexes
    /// keyed by their server-unique **name**, each carrying the covered entity + token, the single
    /// covered embedding property token, the embedding dimensions, the similarity metric, the HNSW build
    /// parameters and the build [`IndexState`]. See [`VectorIndexEntry`].
    ///
    /// Persisting this set is what makes a vector index *registration* survive a crash: the backing HNSW
    /// graph is ephemeral (rebuilt from the store on open, like the derived `IndexSet`), so without this
    /// map a recovered store would have no record of which vector indexes existed and would silently lose
    /// them. An entry is present **iff** an index of that name is declared. A single map holds both node
    /// and relationship vector indexes (distinguished by [`VectorIndexEntry::entity`]); it rides the
    /// **identical** durability lifecycle as the other catalogs.
    pub vector_indexes: BTreeMap<String, VectorIndexEntry>,
}

/// Declares the per-entry access table for the twelve schema-catalog maps of [`Statistics`] — the
/// `catalog_dirty`-guarded half that [`Statistics::schema_eq`] compares and
/// [`Statistics::adopt_schema_from`] moves (`rmp` #734).
///
/// One line per map generates, in lock-step: a [`SchemaKey`] variant, a [`SchemaValue`] variant, and
/// the matching [`Statistics::schema_get`] / [`Statistics::schema_put`] arms. Generating all four
/// from one table is what makes it impossible for the read and write halves to disagree about a
/// map's key or value type — the pairing is established once, here.
///
/// # Adding a schema-catalog map
///
/// A new map must be listed **here as well as** in `schema_eq` and `adopt_schema_from` (both of which
/// stop compiling until it is). Only those two are compile-enforced; this table is not. The backstop
/// is the debug-only faithful-inverse assertion in `RecordStore::with_schema_undo`, which fires the
/// first time a catalog mutator touching an unlisted map is exercised — so an omission surfaces as a
/// failing test, never as a silently un-undoable DDL.
macro_rules! schema_catalog_table {
    ( $( $map:ident : $key_variant:ident ( $key_ty:ty ) => $value_variant:ident ( $value_ty:ty ) ),+ $(,)? ) => {
        /// Identifies **one entry** of one schema-catalog map of [`Statistics`] (`rmp` #734): which
        /// map, and which key within it. The unit of per-transaction catalog undo — a rolling-back
        /// transaction restores exactly the entries it touched, leaving every other entry (including
        /// a concurrent transaction's pending DDL in the *same* map) untouched.
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub(crate) enum SchemaKey {
            $( $key_variant($key_ty), )+
        }

        /// The value stored at a [`SchemaKey`] (`rmp` #734). One variant per map, so a value is
        /// always bound to the map it came from and can never be written back into another.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub(crate) enum SchemaValue {
            $( $value_variant($value_ty), )+
        }

        fn schema_catalog_get(stats: &Statistics, key: &SchemaKey) -> Option<SchemaValue> {
            match key {
                $(
                    SchemaKey::$key_variant(k) => {
                        stats.$map.get(k).cloned().map(SchemaValue::$value_variant)
                    }
                )+
            }
        }

        fn schema_catalog_put(stats: &mut Statistics, key: &SchemaKey, value: Option<SchemaValue>) {
            match (key, value) {
                $(
                    (SchemaKey::$key_variant(k), None) => {
                        stats.$map.remove(k);
                    }
                    (SchemaKey::$key_variant(k), Some(SchemaValue::$value_variant(v))) => {
                        stats.$map.insert(k.clone(), v);
                    }
                )+
                // Unreachable by construction: every `SchemaValue` in this crate is produced by a
                // `schema_get` on the very `SchemaKey` it is later written back with, so the two
                // variants always agree. Assert loudly in debug; in release, decline the write rather
                // than corrupt an unrelated catalog map.
                (_, Some(_)) => {
                    debug_assert!(false, "schema_put: value kind does not match key {key:?}");
                }
            }
        }
    };
}

schema_catalog_table! {
    node_prop_histograms:      NodePropHistogram((u32, u32))  => Histogram(Vec<u8>),
    node_property_indexes:     NodePropertyIndex((u32, u32))  => NodePropertyIndexState(IndexState),
    node_property_index_names: NodePropertyIndexName(String)  => NodePropertyIndexTarget((u32, u32)),
    rel_property_indexes:      RelPropertyIndex((u32, u32))   => RelPropertyIndexState(IndexState),
    rel_property_index_names:  RelPropertyIndexName(String)   => RelPropertyIndexTarget((u32, u32)),
    fulltext_indexes:          FulltextIndex(String)          => Fulltext(FulltextIndexEntry),
    spatial_indexes:           SpatialIndex(String)           => Spatial(SpatialIndexEntry),
    composite_indexes:         CompositeIndex(String)         => Composite(CompositeIndexEntry),
    rel_composite_indexes:     RelCompositeIndex(String)      => RelComposite(RelCompositeIndexEntry),
    text_indexes:              TextIndex(String)              => Text(TextIndexEntry),
    vector_indexes:            VectorIndex(String)            => Vector(VectorIndexEntry),
    constraints:               Constraint(String)             => Constraint(ConstraintEntry),
}

/// A detached copy of the six **live-record cardinality counters** of a [`Statistics`], without its
/// twelve schema-catalog DDL maps (`rmp` #866).
///
/// Produced by [`Statistics::counts_image`] and consumed by [`Statistics::restore_counts`]. It is a
/// distinct type rather than a `Statistics` so that "restore the counts, keep the schema" cannot be
/// spelt wrongly, and so the rollback path never pays to clone DDL maps it is not restoring.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CountsImage {
    pub(crate) total_nodes: u64,
    pub(crate) total_relationships: u64,
    pub(crate) nodes_per_label: BTreeMap<u32, u64>,
    pub(crate) rels_per_type: BTreeMap<u32, u64>,
    pub(crate) rels_per_start_label_type: BTreeMap<(u32, u32), u64>,
    pub(crate) rels_per_type_end_label: BTreeMap<(u32, u32), u64>,
}

/// Names exactly one of [`Statistics`]'s six **live-record cardinality counters** — the counts half
/// of the catalog, as opposed to the twelve schema-catalog DDL maps a [`SchemaKey`] names.
///
/// It is the address a signed count change is applied at
/// ([`Statistics::apply_count_delta`]) and the key a transaction's pending count delta is
/// accumulated under (`RecordStore`'s `CountDelta`, `rmp` #866). The two directional variants carry
/// their pair in the same field order as the map they address, so a reader never has to remember
/// which way round it is: `StartLabelType(label, type)` for `rels_per_start_label_type`,
/// `TypeEndLabel(type, label)` for `rels_per_type_end_label` (`rmp` task #856).
///
/// `Copy` on purpose: it is passed by value through the whole write path and stored in the delta
/// maps' keys as its payload, never as the enum, so it never allocates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CountKey {
    /// [`Statistics::total_nodes`] — the grand-total live-node count (`rmp` task #82).
    TotalNodes,
    /// [`Statistics::total_relationships`] — the grand-total live-relationship count (`rmp` task #82).
    TotalRelationships,
    /// `nodes_per_label[label_token]` (`rmp` task #79).
    Label(u32),
    /// `rels_per_type[type_token]` (`rmp` task #79).
    RelType(u32),
    /// `rels_per_start_label_type[(label_token, type_token)]` (`rmp` task #856).
    StartLabelType(u32, u32),
    /// `rels_per_type_end_label[(type_token, label_token)]` (`rmp` task #856).
    TypeEndLabel(u32, u32),
}

impl Statistics {
    /// An empty statistics catalog (every count `0`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` iff the **schema-catalog** half of `self` equals `other`'s — the twelve
    /// `catalog_dirty`-guarded DDL maps (declared node/relationship property, composite, full-text,
    /// text, spatial, vector indexes; their names; constraints; and the opaque property histograms)
    /// — **ignoring** the six live-record cardinality counters
    /// ([`total_nodes`](Self#structfield.total_nodes) /
    /// [`total_relationships`](Self#structfield.total_relationships) /
    /// [`nodes_per_label`](Self#structfield.nodes_per_label) /
    /// [`rels_per_type`](Self#structfield.rels_per_type) /
    /// [`rels_per_start_label_type`](Self#structfield.rels_per_start_label_type) /
    /// [`rels_per_type_end_label`](Self#structfield.rels_per_type_end_label)).
    ///
    /// `rmp` #534: the rollback path uses this to detect whether a **concurrent** open transaction left
    /// a pending catalog DDL change that a wholesale count-revert would otherwise silently drop. It is
    /// the exact complement of [`adopt_schema_from`](Self::adopt_schema_from): the fields this compares
    /// are precisely the fields that method moves — the exhaustive destructure below keeps the two in
    /// lock-step (a newly-added `Statistics` field forces a compile decision in *both* places).
    #[must_use]
    pub fn schema_eq(&self, other: &Self) -> bool {
        // Exhaustive destructure so adding a field to `Statistics` cannot silently escape this
        // comparison: categorise the new field as a live-record COUNTER (bound to `_`, ignored) or a
        // schema-catalog DDL map (bound and compared — an unused binding is a `-D warnings` error).
        let Self {
            // Live-record cardinality counters: NOT part of the schema — deliberately ignored.
            total_nodes: _,
            total_relationships: _,
            nodes_per_label: _,
            rels_per_type: _,
            // The directional projections of `rmp` task #856 are counters too, not schema.
            rels_per_start_label_type: _,
            rels_per_type_end_label: _,
            // Schema-catalog DDL (the `catalog_dirty`-guarded half): compared.
            node_prop_histograms,
            node_property_indexes,
            fulltext_indexes,
            spatial_indexes,
            constraints,
            node_property_index_names,
            rel_property_indexes,
            rel_property_index_names,
            composite_indexes,
            rel_composite_indexes,
            text_indexes,
            vector_indexes,
        } = self;
        *node_prop_histograms == other.node_prop_histograms
            && *node_property_indexes == other.node_property_indexes
            && *fulltext_indexes == other.fulltext_indexes
            && *spatial_indexes == other.spatial_indexes
            && *constraints == other.constraints
            && *node_property_index_names == other.node_property_index_names
            && *rel_property_indexes == other.rel_property_indexes
            && *rel_property_index_names == other.rel_property_index_names
            && *composite_indexes == other.composite_indexes
            && *rel_composite_indexes == other.rel_composite_indexes
            && *text_indexes == other.text_indexes
            && *vector_indexes == other.vector_indexes
    }

    /// Moves the **schema-catalog** half of `src` into `self`, leaving `self`'s six live-record
    /// cardinality counters untouched. The twelve fields moved are exactly those compared by
    /// [`schema_eq`](Self::schema_eq) and guarded by the store's `catalog_dirty` flag.
    ///
    /// `rmp` #534: on a rollback that must **superset-preserve** a concurrent open transaction's pending
    /// catalog DDL, the store first reverts the whole `Statistics` to the durable committed image
    /// (correctly discarding the aborting transaction's count increments/decrements, `rmp` task #79)
    /// and then calls this to restore the richer in-memory schema — the `Statistics` twin of the tokens
    /// / free-list superset restore. Consuming `src` avoids re-cloning the (potentially large) DDL maps.
    pub fn adopt_schema_from(&mut self, src: Self) {
        // Exhaustive destructure: a newly-added `Statistics` field forces a compile decision here
        // (a COUNTER is dropped so `self` keeps its durable-reverted value; a DDL map is moved into
        // `self`). Missing a field is a `pattern does not mention field …` compile error.
        let Self {
            // Live-record cardinality counters: dropped — `self` keeps its durable-reverted values.
            total_nodes: _,
            total_relationships: _,
            nodes_per_label: _,
            rels_per_type: _,
            // The directional projections of `rmp` task #856 are counters too, not schema.
            rels_per_start_label_type: _,
            rels_per_type_end_label: _,
            // Schema-catalog DDL (the `catalog_dirty`-guarded half): moved into `self`.
            node_prop_histograms,
            node_property_indexes,
            fulltext_indexes,
            spatial_indexes,
            constraints,
            node_property_index_names,
            rel_property_indexes,
            rel_property_index_names,
            composite_indexes,
            rel_composite_indexes,
            text_indexes,
            vector_indexes,
        } = src;
        self.node_prop_histograms = node_prop_histograms;
        self.node_property_indexes = node_property_indexes;
        self.fulltext_indexes = fulltext_indexes;
        self.spatial_indexes = spatial_indexes;
        self.constraints = constraints;
        self.node_property_index_names = node_property_index_names;
        self.rel_property_indexes = rel_property_indexes;
        self.rel_property_index_names = rel_property_index_names;
        self.composite_indexes = composite_indexes;
        self.rel_composite_indexes = rel_composite_indexes;
        self.text_indexes = text_indexes;
        self.vector_indexes = vector_indexes;
    }

    /// Detaches a copy of the **counts** half — the six live-record cardinality counters — leaving
    /// `self` untouched. The exact counterpart of the schema half's `clone()` + [`adopt_schema_from`]
    /// (Self::adopt_schema_from), and paired with [`restore_counts`](Self::restore_counts), which
    /// puts one back.
    ///
    /// `rmp` #866: the rollback path captures this **before** `reload_catalog` reverts the whole
    /// `Statistics` to the durable image, so it can restore the counters a concurrent open transaction
    /// had already moved (which are in no durable image, since the catalog is only checkpointed at
    /// commit). It exists instead of a whole-`Statistics` clone because that would also copy the
    /// twelve schema-catalog DDL maps on **every** rollback, which the `rmp` #534 capture deliberately
    /// avoids on the common single-writer path. What is copied here is bounded by the number of
    /// distinct labels and relationship types in the schema, never by the number of records.
    #[must_use]
    pub(crate) fn counts_image(&self) -> CountsImage {
        // Exhaustive destructure so a newly-added `Statistics` field forces a compile decision here
        // (a COUNTER must join `CountsImage`; a schema-catalog DDL map is bound to `_`), keeping this
        // in lock-step with `schema_eq` / `adopt_schema_from`, which make the opposite choice.
        let Self {
            total_nodes,
            total_relationships,
            nodes_per_label,
            rels_per_type,
            rels_per_start_label_type,
            rels_per_type_end_label,
            // Schema-catalog DDL (the `catalog_dirty`-guarded half): not part of the counts image.
            node_prop_histograms: _,
            node_property_indexes: _,
            fulltext_indexes: _,
            spatial_indexes: _,
            constraints: _,
            node_property_index_names: _,
            rel_property_indexes: _,
            rel_property_index_names: _,
            composite_indexes: _,
            rel_composite_indexes: _,
            text_indexes: _,
            vector_indexes: _,
        } = self;
        CountsImage {
            total_nodes: *total_nodes,
            total_relationships: *total_relationships,
            nodes_per_label: nodes_per_label.clone(),
            rels_per_type: rels_per_type.clone(),
            rels_per_start_label_type: rels_per_start_label_type.clone(),
            rels_per_type_end_label: rels_per_type_end_label.clone(),
        }
    }

    /// Installs `image` as the counts half, leaving the twelve schema-catalog DDL maps untouched —
    /// the inverse of [`counts_image`](Self::counts_image) and the counts twin of
    /// [`adopt_schema_from`](Self::adopt_schema_from). Consumes `image` so the maps are moved, not
    /// re-cloned.
    pub(crate) fn restore_counts(&mut self, image: CountsImage) {
        let CountsImage {
            total_nodes,
            total_relationships,
            nodes_per_label,
            rels_per_type,
            rels_per_start_label_type,
            rels_per_type_end_label,
        } = image;
        self.total_nodes = total_nodes;
        self.total_relationships = total_relationships;
        self.nodes_per_label = nodes_per_label;
        self.rels_per_type = rels_per_type;
        self.rels_per_start_label_type = rels_per_start_label_type;
        self.rels_per_type_end_label = rels_per_type_end_label;
    }

    /// Reads one schema-catalog entry by [`SchemaKey`], cloned out — [`None`] when the key is absent.
    ///
    /// The single-entry read half of the per-transaction catalog undo (`rmp` #734). Paired with
    /// [`schema_put`](Self::schema_put), which is its exact inverse: `schema_put(k, schema_get(k))` is
    /// a no-op for every key.
    pub(crate) fn schema_get(&self, key: &SchemaKey) -> Option<SchemaValue> {
        schema_catalog_get(self, key)
    }

    /// Writes one schema-catalog entry by [`SchemaKey`]: `Some(v)` inserts/replaces, [`None`] removes.
    ///
    /// The single-entry write half of the per-transaction catalog undo (`rmp` #734). It deliberately
    /// bypasses the invariant-enforcing mutators (e.g. `set_node_property_index_name`'s
    /// one-name-per-target clear): this replays a **previously observed** state, so re-running those
    /// invariants would be wrong — the state being restored already satisfied them when it was captured.
    pub(crate) fn schema_put(&mut self, key: &SchemaKey, value: Option<SchemaValue>) {
        schema_catalog_put(self, key, value);
    }

    /// The number of currently-live nodes carrying the label `token_id` (`0` if none).
    #[must_use]
    pub fn node_count_for_label(&self, token_id: u32) -> u64 {
        self.nodes_per_label.get(&token_id).copied().unwrap_or(0)
    }

    /// The number of currently-live relationships of relationship-type `token_id` (`0` if none).
    #[must_use]
    pub fn rel_count_for_type(&self, token_id: u32) -> u64 {
        self.rels_per_type.get(&token_id).copied().unwrap_or(0)
    }

    /// The total number of currently-live nodes, labelled or not (`rmp` task #82).
    #[must_use]
    pub fn total_nodes(&self) -> u64 {
        self.total_nodes
    }

    /// The total number of currently-live relationships (`rmp` task #82).
    #[must_use]
    pub fn total_relationships(&self) -> u64 {
        self.total_relationships
    }

    /// Applies a **signed** change `delta` to the single live-record counter named by `key` — the one
    /// and only crate-visible count mutator (`rmp` #866).
    ///
    /// # Why this is the only door
    ///
    /// The counters are per-transaction state pretending to be shared state: they move eagerly at
    /// write time, so at any instant the live value is `committed image + every in-flight
    /// transaction's delta`. Both the rollback path (withdraw exactly the aborting transaction's own
    /// delta, `rmp` #866) and the checkpoint path (persist the committed image, so strip every *open*
    /// transaction's delta) therefore have to *un-apply* a delta, which the ±1 helpers below cannot
    /// express. Routing every mutation through one signed entry point is also what lets the store
    /// record the delta at the same instant it applies it: `RecordStore::count_bump` is the sole
    /// caller, and the ±1 helpers are private, so no write path can move a counter without its
    /// transaction's delta moving with it. This is the `Statistics` twin of `rmp` #578's
    /// "every free-list push goes through `RecordStore::free_push`".
    ///
    /// A `delta` of `0` is a no-op — in particular it never materialises a zero-valued map entry,
    /// which would break the zero-count invariant (an absent key and a `0` count must be the same
    /// thing, so that equality against a fresh re-scan holds).
    ///
    /// Saturating in release, asserted in debug: see [`add_total`](Self::add_total) /
    /// [`add_keyed`](Self::add_keyed).
    pub(crate) fn apply_count_delta(&mut self, key: CountKey, delta: i64) {
        if delta == 0 {
            return;
        }
        match key {
            CountKey::TotalNodes => Self::add_total(&mut self.total_nodes, delta, "total_nodes"),
            CountKey::TotalRelationships => {
                Self::add_total(&mut self.total_relationships, delta, "total_relationships")
            }
            CountKey::Label(token_id) => {
                Self::add_keyed(&mut self.nodes_per_label, token_id, delta)
            }
            CountKey::RelType(token_id) => {
                Self::add_keyed(&mut self.rels_per_type, token_id, delta)
            }
            CountKey::StartLabelType(label_id, type_id) => Self::add_keyed(
                &mut self.rels_per_start_label_type,
                (label_id, type_id),
                delta,
            ),
            CountKey::TypeEndLabel(type_id, label_id) => Self::add_keyed(
                &mut self.rels_per_type_end_label,
                (type_id, label_id),
                delta,
            ),
        }
    }

    /// Shared grand-total signed add. In a release build a decrement below `0` saturates (never wraps
    /// to a huge count) so a logic slip can never silently corrupt the catalog into an absurd
    /// cardinality the planner would trust; in a debug build it is caught (every decrement must match
    /// a prior increment of a live record).
    fn add_total(count: &mut u64, delta: i64, which: &str) {
        if delta >= 0 {
            *count = count.saturating_add(delta.unsigned_abs());
            return;
        }
        let down = delta.unsigned_abs();
        if down > *count {
            debug_assert!(
                false,
                "statistics {which} decrement underflow ({down} from {count})"
            );
            *count = 0;
            return;
        }
        *count -= down;
    }

    /// Shared keyed-counter signed add, for both the token-keyed maps (`rmp` task #79) and the
    /// pair-keyed directional projections (`rmp` task #856).
    ///
    /// Reaching exactly `0` **removes** the entry (the zero-count invariant: an absent key and a `0`
    /// count must be indistinguishable, so equality against a fresh re-scan holds). A decrement past
    /// `0` saturates there in release and is caught in debug, for the same reason as
    /// [`add_total`](Self::add_total). `delta == 0` never reaches here (filtered by
    /// [`apply_count_delta`](Self::apply_count_delta)), so no zero-valued entry is ever inserted.
    fn add_keyed<K: Ord + std::fmt::Debug>(map: &mut BTreeMap<K, u64>, key: K, delta: i64) {
        if delta >= 0 {
            let slot = map.entry(key).or_insert(0);
            *slot = slot.saturating_add(delta.unsigned_abs());
            return;
        }
        let down = delta.unsigned_abs();
        match map.get_mut(&key) {
            Some(c) if *c > down => *c -= down,
            Some(c) => {
                debug_assert!(
                    *c == down,
                    "statistics count decrement underflow at {key:?} ({down} from {c})"
                );
                map.remove(&key);
            }
            None => debug_assert!(
                false,
                "statistics count decrement underflow at absent key {key:?}"
            ),
        }
    }

    /// The number of currently-live relationships of type `type_id` whose start node carries
    /// `label_id` (`0` if none) — the `(label, type, *)` projection (`rmp` task #856).
    #[must_use]
    pub fn rel_count_for_start_label_type(&self, label_id: u32, type_id: u32) -> u64 {
        self.rels_per_start_label_type
            .get(&(label_id, type_id))
            .copied()
            .unwrap_or(0)
    }

    /// The number of currently-live relationships of type `type_id` whose end node carries `label_id`
    /// (`0` if none) — the `(*, type, label)` projection (`rmp` task #856).
    #[must_use]
    pub fn rel_count_for_type_end_label(&self, type_id: u32, label_id: u32) -> u64 {
        self.rels_per_type_end_label
            .get(&(type_id, label_id))
            .copied()
            .unwrap_or(0)
    }

    /// Whether either directional projection holds any entry (`rmp` task #856).
    ///
    /// Distinguishes "this catalogue predates the directional counters, or has never been backfilled"
    /// from "the graph genuinely has no relationships". The estimator must not read a zero from the
    /// former as a real degree of zero — it has to fall back to the graph-wide degree — and an absent
    /// key is indistinguishable from a genuine zero on its own.
    #[must_use]
    pub fn has_directional_rel_counts(&self) -> bool {
        !self.rels_per_start_label_type.is_empty() || !self.rels_per_type_end_label.is_empty()
    }

    /// Borrows the stored opaque histogram blob for `(label_token, prop_token)`, or [`None`] if no
    /// histogram has been recorded for that node-label property (`rmp` task #81).
    ///
    /// The bytes are returned uninterpreted; only the producer/consumer in the query layer knows their
    /// encoding.
    #[must_use]
    pub fn property_histogram(&self, label_token: u32, prop_token: u32) -> Option<&[u8]> {
        self.node_prop_histograms
            .get(&(label_token, prop_token))
            .map(Vec::as_slice)
    }

    /// Records (or replaces) the opaque histogram blob for the node-label property
    /// `(label_token, prop_token)` (`rmp` task #81). An **empty** `bytes` is treated as a removal: a
    /// histogram is never zero-length, so storing one would be meaningless and would not survive the
    /// codec round-trip (which rejects zero-length blobs). The bytes are stored verbatim.
    pub(crate) fn set_property_histogram(
        &mut self,
        label_token: u32,
        prop_token: u32,
        bytes: Vec<u8>,
    ) {
        if bytes.is_empty() {
            self.node_prop_histograms.remove(&(label_token, prop_token));
        } else {
            self.node_prop_histograms
                .insert((label_token, prop_token), bytes);
        }
    }

    /// Removes the histogram blob for `(label_token, prop_token)`, if present (`rmp` task #81).
    pub(crate) fn remove_property_histogram(&mut self, label_token: u32, prop_token: u32) {
        self.node_prop_histograms.remove(&(label_token, prop_token));
    }

    /// The durable build [`IndexState`] of the node-property index on `(label_token, prop_token)`, or
    /// [`None`] if no such index is declared (`rmp` task #90).
    #[must_use]
    pub fn node_property_index_state(
        &self,
        label_token: u32,
        prop_token: u32,
    ) -> Option<IndexState> {
        self.node_property_indexes
            .get(&(label_token, prop_token))
            .copied()
    }

    /// Declares (or updates the state of) the node-property index on `(label_token, prop_token)`
    /// (`rmp` task #90). Idempotent on the key: re-recording flips the stored state.
    pub(crate) fn set_node_property_index(
        &mut self,
        label_token: u32,
        prop_token: u32,
        state: IndexState,
    ) {
        self.node_property_indexes
            .insert((label_token, prop_token), state);
    }

    /// Removes the node-property index on `(label_token, prop_token)`, if declared (`rmp` task #90).
    /// Removing an absent entry is a harmless no-op.
    pub(crate) fn remove_node_property_index(&mut self, label_token: u32, prop_token: u32) {
        self.node_property_indexes
            .remove(&(label_token, prop_token));
    }

    /// Lists every declared node-property index as `(label_token, prop_token, state)`, ascending by
    /// key (the [`BTreeMap`] order, deterministic) (`rmp` task #90).
    #[must_use]
    pub fn node_property_indexes(&self) -> Vec<(u32, u32, IndexState)> {
        self.node_property_indexes
            .iter()
            .map(|(&(label_token, prop_token), &state)| (label_token, prop_token, state))
            .collect()
    }

    /// The `(label_token, prop_token)` a named node-property index covers, or [`None`] if no index of
    /// that name is declared (`rmp` task #623). The name → target resolver behind `DROP INDEX <name>`
    /// and the global name-uniqueness check.
    #[must_use]
    pub fn node_property_index_name(&self, name: &str) -> Option<(u32, u32)> {
        self.node_property_index_names.get(name).copied()
    }

    /// The declared **name** of the node-property index on `(label_token, prop_token)`, or [`None`] if
    /// the index is nameless (a legacy anonymous index not yet backfilled) (`rmp` task #623). A linear
    /// scan of the (small) name map — there is no reverse index, and the map holds one entry per named
    /// index, so this is cheap in practice.
    #[must_use]
    pub fn node_property_index_name_for(&self, label_token: u32, prop_token: u32) -> Option<&str> {
        self.node_property_index_names
            .iter()
            .find(|&(_, &target)| target == (label_token, prop_token))
            .map(|(name, _)| name.as_str())
    }

    /// Records the name of the node-property index on `(label_token, prop_token)`, **enforcing the
    /// one-name-per-target invariant** (`rmp` task #623). Global name uniqueness across catalogs is the
    /// Cypher layer's responsibility (its `unique_auto_index_name` / explicit-name checks guarantee
    /// `name` is free or already owned by this same target before calling); this is the durable write
    /// behind it.
    pub(crate) fn set_node_property_index_name(
        &mut self,
        name: String,
        label_token: u32,
        prop_token: u32,
    ) {
        // Debug-time mirror of the decode invariants (`decode_index_name_catalog`): a name maps to at
        // most one target. A name already mapping to a *different* target is a name-theft (the caller's
        // uniqueness check failed) that would produce an image decode still accepts but which points
        // `DROP INDEX <name>` at the wrong index — catch it at the source in debug builds
        // (`rmp` #624 durability audit, MEDIUM).
        debug_assert!(
            self.node_property_index_names
                .get(&name)
                .is_none_or(|&t| t == (label_token, prop_token)),
            "index name {name:?} already maps to a different target than ({label_token}, {prop_token})"
        );
        // Write-path invariant: at most one name per target. Clear any prior name mapping to this
        // `(label_token, prop_token)` before inserting the new one, so the durable catalog can never
        // hold two names for the same target — a state `decode_index_name_catalog` rejects, which
        // would leave the store unable to reopen (`rmp` #624 durability audit, HIGH). Enforcing the
        // invariant here (not only at decode time) makes it hold for every caller, including the
        // positional `create_node_property_index` API used by benches/tools.
        self.remove_node_property_index_name_for(label_token, prop_token);
        self.node_property_index_names
            .insert(name, (label_token, prop_token));
    }

    /// Removes the name entry `name`, if present (`rmp` task #623). Removing an absent entry is a
    /// harmless no-op. Used by `DROP INDEX <name>`.
    pub(crate) fn remove_node_property_index_name(&mut self, name: &str) {
        self.node_property_index_names.remove(name);
    }

    /// Removes whatever name maps to `(label_token, prop_token)`, if any (`rmp` task #623). Used by
    /// the by-target `DROP INDEX FOR (n:L) ON (n.p)` shape so the name entry is cleared alongside the
    /// index. A no-op for a nameless (legacy) index.
    pub(crate) fn remove_node_property_index_name_for(
        &mut self,
        label_token: u32,
        prop_token: u32,
    ) {
        // Collect first (the map is small) to avoid holding an iterator borrow across the removal.
        if let Some(name) = self.node_property_index_name_for(label_token, prop_token) {
            let name = name.to_owned();
            self.node_property_index_names.remove(&name);
        }
    }

    /// Lists every named node-property index as `(name, label_token, prop_token)`, ascending by name
    /// (the [`BTreeMap`] order, deterministic) (`rmp` task #623).
    #[must_use]
    pub fn node_property_index_names(&self) -> Vec<(String, u32, u32)> {
        self.node_property_index_names
            .iter()
            .map(|(name, &(label_token, prop_token))| (name.clone(), label_token, prop_token))
            .collect()
    }

    // ---- Relationship-property index catalog (`rmp` task #646) -------------------------------------
    // Structural twins of the node-property index accessors above, keyed by
    // `(rel_type_token, prop_token)` in a **separate** namespace so a numeric collision between a
    // relationship-type token and a label token never mixes the two catalogs.

    /// The durable build [`IndexState`] of the relationship-property index on
    /// `(type_token, prop_token)`, or [`None`] if no such index is declared (`rmp` task #646).
    #[must_use]
    pub fn rel_property_index_state(&self, type_token: u32, prop_token: u32) -> Option<IndexState> {
        self.rel_property_indexes
            .get(&(type_token, prop_token))
            .copied()
    }

    /// Declares (or updates the state of) the relationship-property index on `(type_token, prop_token)`
    /// (`rmp` task #646). Idempotent on the key: re-recording flips the stored state.
    pub(crate) fn set_rel_property_index(
        &mut self,
        type_token: u32,
        prop_token: u32,
        state: IndexState,
    ) {
        self.rel_property_indexes
            .insert((type_token, prop_token), state);
    }

    /// Removes the relationship-property index on `(type_token, prop_token)`, if declared (`rmp` task
    /// #646). Removing an absent entry is a harmless no-op.
    pub(crate) fn remove_rel_property_index(&mut self, type_token: u32, prop_token: u32) {
        self.rel_property_indexes.remove(&(type_token, prop_token));
    }

    /// Lists every declared relationship-property index as `(type_token, prop_token, state)`, ascending
    /// by key (the [`BTreeMap`] order, deterministic) (`rmp` task #646).
    #[must_use]
    pub fn rel_property_indexes(&self) -> Vec<(u32, u32, IndexState)> {
        self.rel_property_indexes
            .iter()
            .map(|(&(type_token, prop_token), &state)| (type_token, prop_token, state))
            .collect()
    }

    /// The `(type_token, prop_token)` a named relationship-property index covers, or [`None`] if no
    /// index of that name is declared (`rmp` task #646). The name → target resolver behind
    /// `DROP INDEX <name>` and the global name-uniqueness check.
    #[must_use]
    pub fn rel_property_index_name(&self, name: &str) -> Option<(u32, u32)> {
        self.rel_property_index_names.get(name).copied()
    }

    /// The declared **name** of the relationship-property index on `(type_token, prop_token)`, or
    /// [`None`] if the index is nameless (`rmp` task #646). A linear scan of the (small) name map.
    #[must_use]
    pub fn rel_property_index_name_for(&self, type_token: u32, prop_token: u32) -> Option<&str> {
        self.rel_property_index_names
            .iter()
            .find(|&(_, &target)| target == (type_token, prop_token))
            .map(|(name, _)| name.as_str())
    }

    /// Records the name of the relationship-property index on `(type_token, prop_token)`, **enforcing
    /// the one-name-per-target invariant** (`rmp` task #646). Global name uniqueness across catalogs is
    /// the Cypher layer's responsibility; this is the durable write behind it. Mirrors
    /// [`set_node_property_index_name`](Self::set_node_property_index_name) exactly (including its
    /// debug-time decode-invariant mirror and its remove-any-prior-name-for-this-target write rule, so
    /// a re-declare that computes a different name can never persist two names for one target — a state
    /// [`decode`](Self::decode) rejects, which would leave the store unable to reopen).
    pub(crate) fn set_rel_property_index_name(
        &mut self,
        name: String,
        type_token: u32,
        prop_token: u32,
    ) {
        debug_assert!(
            self.rel_property_index_names
                .get(&name)
                .is_none_or(|&t| t == (type_token, prop_token)),
            "rel index name {name:?} already maps to a different target than ({type_token}, {prop_token})"
        );
        self.remove_rel_property_index_name_for(type_token, prop_token);
        self.rel_property_index_names
            .insert(name, (type_token, prop_token));
    }

    /// Removes the name entry `name`, if present (`rmp` task #646). A harmless no-op when absent. Used
    /// by `DROP INDEX <name>`.
    pub(crate) fn remove_rel_property_index_name(&mut self, name: &str) {
        self.rel_property_index_names.remove(name);
    }

    /// Removes whatever name maps to `(type_token, prop_token)`, if any (`rmp` task #646). Used by the
    /// by-target `DROP INDEX FOR ()-[r:T]-() ON (r.p)` shape so the name entry is cleared alongside the
    /// index. A no-op for a nameless index.
    pub(crate) fn remove_rel_property_index_name_for(&mut self, type_token: u32, prop_token: u32) {
        if let Some(name) = self.rel_property_index_name_for(type_token, prop_token) {
            let name = name.to_owned();
            self.rel_property_index_names.remove(&name);
        }
    }

    /// Lists every named relationship-property index as `(name, type_token, prop_token)`, ascending by
    /// name (the [`BTreeMap`] order, deterministic) (`rmp` task #646).
    #[must_use]
    pub fn rel_property_index_names(&self) -> Vec<(String, u32, u32)> {
        self.rel_property_index_names
            .iter()
            .map(|(name, &(type_token, prop_token))| (name.clone(), type_token, prop_token))
            .collect()
    }

    // ---- Composite (multi-property) node index catalog (`rmp` task #657) --------------------------

    /// The durable composite index entry named `name`, or [`None`] if no such index is declared
    /// (`rmp` task #657).
    #[must_use]
    pub fn composite_index(&self, name: &str) -> Option<&CompositeIndexEntry> {
        self.composite_indexes.get(name)
    }

    /// Declares (or replaces) the composite index named `name` (`rmp` task #657). Idempotent on the
    /// name: re-recording overwrites the entry (e.g. to flip its state `Populating` → `Online`).
    pub(crate) fn set_composite_index(&mut self, name: String, entry: CompositeIndexEntry) {
        self.composite_indexes.insert(name, entry);
    }

    /// Removes the composite index named `name`, if declared (`rmp` task #657). Removing an absent
    /// entry is a harmless no-op.
    pub(crate) fn remove_composite_index(&mut self, name: &str) {
        self.composite_indexes.remove(name);
    }

    /// Lists every declared composite index as `(name, entry)`, ascending by name (the [`BTreeMap`]
    /// order, deterministic) (`rmp` task #657).
    #[must_use]
    pub fn composite_indexes(&self) -> Vec<(String, CompositeIndexEntry)> {
        self.composite_indexes
            .iter()
            .map(|(name, entry)| (name.clone(), entry.clone()))
            .collect()
    }

    /// The **name** of the composite index covering exactly `(label_token, property_tokens)` — same
    /// label and same **ordered** property tuple — or [`None`] if no such index is declared (`rmp` task
    /// #657). Backs the `IF NOT EXISTS` schema-equivalence check (composite key order is significant).
    #[must_use]
    pub fn composite_index_name_for(
        &self,
        label_token: u32,
        property_tokens: &[u32],
    ) -> Option<&str> {
        self.composite_indexes
            .iter()
            .find(|&(_, entry)| {
                entry.label_token == label_token && entry.property_tokens == property_tokens
            })
            .map(|(name, _)| name.as_str())
    }

    // ---- Composite (multi-property) relationship index catalog (`rmp` task #666) ------------------

    /// The durable composite relationship index entry named `name`, or [`None`] if no such index is
    /// declared (`rmp` task #666).
    #[must_use]
    pub fn rel_composite_index(&self, name: &str) -> Option<&RelCompositeIndexEntry> {
        self.rel_composite_indexes.get(name)
    }

    /// Declares (or replaces) the composite relationship index named `name` (`rmp` task #666).
    /// Idempotent on the name: re-recording overwrites the entry (e.g. to flip its state).
    pub(crate) fn set_rel_composite_index(&mut self, name: String, entry: RelCompositeIndexEntry) {
        self.rel_composite_indexes.insert(name, entry);
    }

    /// Removes the composite relationship index named `name`, if declared (`rmp` task #666). Removing
    /// an absent entry is a harmless no-op.
    pub(crate) fn remove_rel_composite_index(&mut self, name: &str) {
        self.rel_composite_indexes.remove(name);
    }

    /// Lists every declared composite relationship index as `(name, entry)`, ascending by name (the
    /// [`BTreeMap`] order, deterministic) (`rmp` task #666).
    #[must_use]
    pub fn rel_composite_indexes(&self) -> Vec<(String, RelCompositeIndexEntry)> {
        self.rel_composite_indexes
            .iter()
            .map(|(name, entry)| (name.clone(), entry.clone()))
            .collect()
    }

    /// The **name** of the composite relationship index covering exactly `(type_token,
    /// property_tokens)` — same relationship type and same **ordered** property tuple — or [`None`] if
    /// no such index is declared (`rmp` task #666). Backs the `IF NOT EXISTS` schema-equivalence check
    /// (composite key order is significant).
    #[must_use]
    pub fn rel_composite_index_name_for(
        &self,
        type_token: u32,
        property_tokens: &[u32],
    ) -> Option<&str> {
        self.rel_composite_indexes
            .iter()
            .find(|&(_, entry)| {
                entry.type_token == type_token && entry.property_tokens == property_tokens
            })
            .map(|(name, _)| name.as_str())
    }

    // ---- Text (trigram) node index catalog (`rmp` task #662) --------------------------------------

    /// The durable text index entry named `name`, or [`None`] if no such index is declared
    /// (`rmp` task #662).
    #[must_use]
    pub fn text_index(&self, name: &str) -> Option<&TextIndexEntry> {
        self.text_indexes.get(name)
    }

    /// Declares (or replaces) the text index named `name` (`rmp` task #662). Idempotent on the name:
    /// re-recording overwrites the entry (e.g. to flip its state `Populating` → `Online`).
    pub(crate) fn set_text_index(&mut self, name: String, entry: TextIndexEntry) {
        self.text_indexes.insert(name, entry);
    }

    /// Removes the text index named `name`, if declared (`rmp` task #662). Removing an absent entry is
    /// a harmless no-op.
    pub(crate) fn remove_text_index(&mut self, name: &str) {
        self.text_indexes.remove(name);
    }

    /// Lists every declared text index as `(name, entry)`, ascending by name (the [`BTreeMap`] order,
    /// deterministic) (`rmp` task #662).
    #[must_use]
    pub fn text_indexes(&self) -> Vec<(String, TextIndexEntry)> {
        self.text_indexes
            .iter()
            .map(|(name, entry)| (name.clone(), entry.clone()))
            .collect()
    }

    /// The **name** of the text index covering exactly `(label_token, property_token)`, or [`None`] if
    /// no such index is declared (`rmp` task #662). Backs the `IF NOT EXISTS` schema-equivalence check.
    #[must_use]
    pub fn text_index_name_for(&self, label_token: u32, property_token: u32) -> Option<&str> {
        self.text_indexes
            .iter()
            .find(|&(_, entry)| {
                entry.label_token == label_token && entry.property_token == property_token
            })
            .map(|(name, _)| name.as_str())
    }

    // ---- Vector (HNSW) index catalog (`rmp` task #669) --------------------------------------------

    /// The durable vector index entry named `name`, or [`None`] if no such index is declared
    /// (`rmp` task #669).
    #[must_use]
    pub fn vector_index(&self, name: &str) -> Option<&VectorIndexEntry> {
        self.vector_indexes.get(name)
    }

    /// Declares (or replaces) the vector index named `name` (`rmp` task #669). Idempotent on the name:
    /// re-recording overwrites the entry (e.g. to flip its state `Populating` → `Online`).
    pub(crate) fn set_vector_index(&mut self, name: String, entry: VectorIndexEntry) {
        self.vector_indexes.insert(name, entry);
    }

    /// Removes the vector index named `name`, if declared (`rmp` task #669). Removing an absent entry is
    /// a harmless no-op.
    pub(crate) fn remove_vector_index(&mut self, name: &str) {
        self.vector_indexes.remove(name);
    }

    /// Lists every declared vector index as `(name, entry)`, ascending by name (the [`BTreeMap`] order,
    /// deterministic) (`rmp` task #669).
    #[must_use]
    pub fn vector_indexes(&self) -> Vec<(String, VectorIndexEntry)> {
        self.vector_indexes
            .iter()
            .map(|(name, entry)| (name.clone(), entry.clone()))
            .collect()
    }

    /// The **name** of the vector index covering exactly `(entity, token, property_token)`, or [`None`]
    /// if no such index is declared (`rmp` task #669). Backs the `IF NOT EXISTS` schema-equivalence
    /// check; the [`VectorEntity`] disambiguates a node label token from a numerically-equal
    /// relationship-type token.
    #[must_use]
    pub fn vector_index_name_for(
        &self,
        entity: VectorEntity,
        token: u32,
        property_token: u32,
    ) -> Option<&str> {
        self.vector_indexes
            .iter()
            .find(|&(_, entry)| {
                entry.entity == entity
                    && entry.token == token
                    && entry.property_token == property_token
            })
            .map(|(name, _)| name.as_str())
    }

    /// The durable full-text index entry named `name`, or [`None`] if no such index is declared
    /// (`rmp` task #72).
    #[must_use]
    pub fn fulltext_index(&self, name: &str) -> Option<&FulltextIndexEntry> {
        self.fulltext_indexes.get(name)
    }

    /// Declares (or replaces) the full-text index named `name` (`rmp` task #72). Idempotent on the
    /// name: re-recording overwrites the entry (e.g. to flip its state `Populating` → `Online`).
    pub(crate) fn set_fulltext_index(&mut self, name: String, entry: FulltextIndexEntry) {
        self.fulltext_indexes.insert(name, entry);
    }

    /// Removes the full-text index named `name`, if declared (`rmp` task #72). Removing an absent
    /// entry is a harmless no-op.
    pub(crate) fn remove_fulltext_index(&mut self, name: &str) {
        self.fulltext_indexes.remove(name);
    }

    /// Lists every declared full-text index as `(name, entry)`, ascending by name (the [`BTreeMap`]
    /// order, deterministic) (`rmp` task #72).
    #[must_use]
    pub fn fulltext_indexes(&self) -> Vec<(String, FulltextIndexEntry)> {
        self.fulltext_indexes
            .iter()
            .map(|(name, entry)| (name.clone(), entry.clone()))
            .collect()
    }

    /// The durable spatial (point) index entry named `name`, or [`None`] if no such index is declared
    /// (`rmp` task #98).
    #[must_use]
    pub fn spatial_index(&self, name: &str) -> Option<&SpatialIndexEntry> {
        self.spatial_indexes.get(name)
    }

    /// Declares (or replaces) the spatial index named `name` (`rmp` task #98). Idempotent on the
    /// name: re-recording overwrites the entry (e.g. to flip its state `Populating` → `Online`).
    pub(crate) fn set_spatial_index(&mut self, name: String, entry: SpatialIndexEntry) {
        self.spatial_indexes.insert(name, entry);
    }

    /// Removes the spatial index named `name`, if declared (`rmp` task #98). Removing an absent entry
    /// is a harmless no-op.
    pub(crate) fn remove_spatial_index(&mut self, name: &str) {
        self.spatial_indexes.remove(name);
    }

    /// Lists every declared spatial index as `(name, entry)`, ascending by name (the [`BTreeMap`]
    /// order, deterministic) (`rmp` task #98).
    #[must_use]
    pub fn spatial_indexes(&self) -> Vec<(String, SpatialIndexEntry)> {
        self.spatial_indexes
            .iter()
            .map(|(name, entry)| (name.clone(), entry.clone()))
            .collect()
    }

    /// The durable constraint entry named `name`, or [`None`] if no such constraint is declared
    /// (`rmp` task #99).
    #[must_use]
    pub fn constraint(&self, name: &str) -> Option<&ConstraintEntry> {
        self.constraints.get(name)
    }

    /// Declares (or replaces) the constraint named `name` (`rmp` task #99). Idempotent on the name:
    /// re-recording overwrites the entry.
    pub(crate) fn set_constraint(&mut self, name: String, entry: ConstraintEntry) {
        self.constraints.insert(name, entry);
    }

    /// Removes the constraint named `name`, if declared (`rmp` task #99). Removing an absent entry is
    /// a harmless no-op.
    pub(crate) fn remove_constraint(&mut self, name: &str) {
        self.constraints.remove(name);
    }

    /// Lists every declared constraint as `(name, entry)`, ascending by name (the [`BTreeMap`] order,
    /// deterministic) (`rmp` task #99).
    #[must_use]
    pub fn constraints(&self) -> Vec<(String, ConstraintEntry)> {
        self.constraints
            .iter()
            .map(|(name, entry)| (name.clone(), entry.clone()))
            .collect()
    }

    /// Serialises the statistics to a self-describing byte image.
    ///
    /// Layout: `total_nodes(u64) | total_relationships(u64) | n_labels(u32) | [ token_id(u32) |
    /// count(u64) ]* | n_types(u32) | [ token_id(u32) | count(u64) ]* | n_hist(u32) | [
    /// label_token(u32) | prop_token(u32) | blob_len(u32) | blob_bytes[blob_len] ]* | n_idx(u32) | [
    /// label_token(u32) | prop_token(u32) | state(u8) ]*`, each map in ascending-key ([`BTreeMap`])
    /// order so the image is deterministic. The two grand totals are a fixed 16-byte header
    /// (`rmp` task #82) read before the maps; the histogram block follows the two count blocks
    /// (`rmp` task #81); the node-property index catalog (`rmp` task #90) is appended last.
    ///
    /// # Backward compatibility with pre-#90 images
    ///
    /// The index-catalog block is **appended after** the histogram block, so an image written before
    /// `rmp` task #90 (which ends after the histograms) is decoded as having an **empty** index
    /// catalog: [`decode`](Self::decode) treats end-of-input where the index block's count `u32`
    /// would start as "no catalog" rather than truncation. The full-text catalog block (`rmp` task
    /// #72) is appended **after** the index catalog by the same rule, so a pre-#72 image decodes to
    /// an empty full-text catalog. The spatial catalog block (`rmp` task #98) is appended **after**
    /// the full-text catalog by the same rule, so a pre-#98 image decodes to an empty spatial
    /// catalog. The constraint catalog block (`rmp` task #99) is appended **after** the spatial
    /// catalog by the same rule, so a pre-#99 image decodes to an empty constraint catalog. The
    /// constraint type-descriptor block (`rmp` task #100) is appended **after** the constraint catalog
    /// by the same rule, so a pre-#100 image (ending after the constraint catalog) decodes with every
    /// constraint's `type_descriptor` left `None`. The node-property index **name** catalog (`rmp` task
    /// #623) is appended **after** the type-descriptor block by the same rule, so a pre-#623 image
    /// decodes to an empty name catalog (every declared index nameless, backfilled on open). The
    /// relationship-property index catalog and its name catalog (`rmp` task #646) are appended **after**
    /// the node-property index name catalog by the same rule (in that order), so a pre-#646 image
    /// (ending after the node-property name catalog) decodes both to empty — no declared
    /// relationship-property index. No format-version byte is needed because every prior block is
    /// length-exact and self-describing, so each parse position is unambiguous.
    ///
    /// # Why the property-type descriptors are a *separate* trailing block (`rmp` task #100)
    ///
    /// The per-entry `kind` byte of the constraint catalog block is the byte a pre-#100 image ends each
    /// constraint entry on. Rather than widen that entry (which a pre-#100 reader could not skip), the
    /// property-type descriptors live in their own appended block keyed by constraint name: a pre-#100
    /// image ends right after the constraint catalog, so the descriptor block decodes empty and every
    /// entry keeps `type_descriptor: None`. Only the named `PropertyType` constraints contribute an
    /// entry to this block.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let hist_bytes: usize = self
            .node_prop_histograms
            .values()
            .map(|b| 12 + b.len())
            .sum();
        let mut out = Vec::with_capacity(
            16 + 8
                + self.nodes_per_label.len() * 12
                + self.rels_per_type.len() * 12
                + 4
                + hist_bytes
                + 4
                + self.node_property_indexes.len() * 9,
        );
        // Grand-total header first (`rmp` task #82): two fixed-width LE u64s.
        out.extend_from_slice(&self.total_nodes.to_le_bytes());
        out.extend_from_slice(&self.total_relationships.to_le_bytes());
        Self::encode_map(&mut out, &self.nodes_per_label);
        Self::encode_map(&mut out, &self.rels_per_type);
        Self::encode_histograms(&mut out, &self.node_prop_histograms);
        Self::encode_index_catalog(&mut out, &self.node_property_indexes);
        Self::encode_fulltext_catalog(&mut out, &self.fulltext_indexes);
        Self::encode_spatial_catalog(&mut out, &self.spatial_indexes);
        Self::encode_constraint_catalog(&mut out, &self.constraints);
        Self::encode_constraint_type_block(&mut out, &self.constraints);
        Self::encode_index_name_catalog(&mut out, &self.node_property_index_names);
        // The relationship-property index catalog + its name catalog (`rmp` task #646), appended after
        // every prior block by the same append-only rule, so a pre-#646 image (ending after the
        // node-property index name catalog) decodes both to empty. Their wire layout is byte-identical
        // to the node-property index catalog / name catalog, so the same encoders serve both.
        Self::encode_index_catalog(&mut out, &self.rel_property_indexes);
        Self::encode_index_name_catalog(&mut out, &self.rel_property_index_names);
        // The standalone composite (multi-property) node index catalog (`rmp` task #657), appended
        // after every prior block by the same append-only rule, so a pre-#657 image (ending after the
        // relationship-property index name catalog) decodes it to empty.
        Self::encode_composite_catalog(&mut out, &self.composite_indexes);
        // The text (trigram) node index catalog (`rmp` task #662), appended by the same append-only
        // rule, so a pre-#662 image (ending after the composite catalog) decodes it to empty.
        Self::encode_text_catalog(&mut out, &self.text_indexes);
        // The full-text extension block (`rmp` task #663), appended after the text catalog — carrying
        // the entity + extra covering tokens of any relationship / multi-token full-text index — so a
        // pre-#663 image (ending after the text catalog) decodes it empty and every legacy full-text
        // entry keeps its node + single-token shape.
        Self::encode_fulltext_extension_block(&mut out, &self.fulltext_indexes);
        // The spatial extension block (`rmp` task #664) — carrying the entity of any relationship point
        // index — so a pre-#664 image (ending after the full-text extension block) decodes it empty and
        // every legacy spatial entry keeps its node shape.
        Self::encode_spatial_extension_block(&mut out, &self.spatial_indexes);
        // The standalone composite (multi-property) **relationship** index catalog (`rmp` task #666),
        // appended by the same append-only rule, so a pre-#666 image (ending after the spatial
        // extension block) decodes it to empty. Byte layout mirrors the node composite catalog exactly
        // (the `type_token` occupies the slot the node block's `label_token` does).
        Self::encode_rel_composite_catalog(&mut out, &self.rel_composite_indexes);
        // The vector (HNSW) index catalog (`rmp` task #669), appended LAST by the same append-only rule,
        // so a pre-#669 image (ending after the relationship composite block) decodes it to empty. It is
        // a wholly new block, so every field — including the entity — is stored inline (no base +
        // extension split).
        Self::encode_vector_catalog(&mut out, &self.vector_indexes);
        // The two directional relationship-count projections (`rmp` task #856), appended LAST by the
        // same append-only rule, so a pre-#856 image (ending after the vector catalog) decodes both to
        // empty. They are *counters*, not schema, and so sit apart from the count maps at the head of
        // the image only because the format is append-only — an image's field order is history, not
        // meaning.
        Self::encode_pair_map(&mut out, &self.rels_per_start_label_type);
        Self::encode_pair_map(&mut out, &self.rels_per_type_end_label);
        out
    }

    /// Encodes a pair-keyed counter map: a `u32` entry count, then `(u32, u32, u64)` per entry
    /// (`rmp` task #856). `BTreeMap` iteration is key-ordered, so the image is byte-deterministic for a
    /// given map — which the checkpoint's page comparison relies on.
    fn encode_pair_map(out: &mut Vec<u8>, map: &BTreeMap<(u32, u32), u64>) {
        debug_assert!(
            map.len() <= u32::MAX as usize,
            "directional count map too large to frame"
        );
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (&(a, b), &count) in map {
            out.extend_from_slice(&a.to_le_bytes());
            out.extend_from_slice(&b.to_le_bytes());
            out.extend_from_slice(&count.to_le_bytes());
        }
    }

    fn encode_map(out: &mut Vec<u8>, map: &BTreeMap<u32, u64>) {
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (&token_id, &count) in map {
            out.extend_from_slice(&token_id.to_le_bytes());
            out.extend_from_slice(&count.to_le_bytes());
        }
    }

    fn encode_histograms(out: &mut Vec<u8>, map: &BTreeMap<(u32, u32), Vec<u8>>) {
        // The blob length and the entry count are framed as `u32`. Both are unreachable in practice
        // (a histogram blob is kilobytes; the token space is far below 2^32), but assert it in debug
        // so a future regression that produced an oversized blob is caught at the source rather than
        // silently truncating the frame — same defense-in-depth stance as `dec_total`.
        debug_assert!(
            map.len() <= u32::MAX as usize,
            "histogram entry count exceeds u32"
        );
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (&(label_token, prop_token), blob) in map {
            debug_assert!(
                blob.len() <= u32::MAX as usize,
                "histogram blob exceeds u32 length"
            );
            out.extend_from_slice(&label_token.to_le_bytes());
            out.extend_from_slice(&prop_token.to_le_bytes());
            out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            out.extend_from_slice(blob);
        }
    }

    fn encode_index_catalog(out: &mut Vec<u8>, map: &BTreeMap<(u32, u32), IndexState>) {
        // The entry count is framed as a `u32`; the token space is far below 2^32, so this is
        // unreachable in practice — asserted in debug, mirroring `encode_histograms`.
        debug_assert!(
            map.len() <= u32::MAX as usize,
            "index-catalog entry count exceeds u32"
        );
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (&(label_token, prop_token), &state) in map {
            out.extend_from_slice(&label_token.to_le_bytes());
            out.extend_from_slice(&prop_token.to_le_bytes());
            out.push(state.as_byte());
        }
    }

    /// Encodes the full-text index catalog block (`rmp` task #72), appended after the node-property
    /// index catalog so a pre-#72 image (ending after it) decodes to an empty full-text catalog.
    ///
    /// Layout: `n(u32) | [ name_len(u32) | name_bytes[name_len] | primary_token(u32) |
    /// n_props(u32) | prop_token(u32)*n_props | analyzer(u8) | state(u8) ]*`, entries in
    /// ascending-name ([`BTreeMap`]) order so the image is deterministic.
    ///
    /// # Single primary token (`rmp` task #663)
    ///
    /// This block persists exactly **one** covering token (`tokens[0]`), byte-for-byte as the pre-#663
    /// `label_token` slot, so the layout is unchanged and a pre-#663 image decodes here as a node index
    /// over that one token. The [`entity`](FulltextIndexEntry::entity) and any additional covering
    /// tokens (`tokens[1..]`) — a relationship index or a multi-label/-type one — ride the trailing
    /// [`encode_fulltext_extension_block`](Self::encode_fulltext_extension_block).
    fn encode_fulltext_catalog(out: &mut Vec<u8>, map: &BTreeMap<String, FulltextIndexEntry>) {
        debug_assert!(
            map.len() <= u32::MAX as usize,
            "full-text catalog entry count exceeds u32"
        );
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (name, entry) in map {
            let name_bytes = name.as_bytes();
            debug_assert!(
                name_bytes.len() <= u32::MAX as usize,
                "full-text index name exceeds u32 length"
            );
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            // The single primary token (`tokens[0]`), byte-identical to the pre-#663 `label_token` slot.
            // `tokens` is non-empty at every write-path construction site; assert it in debug so a future
            // empty-token entry is caught here rather than panicking inside `primary_token()`.
            debug_assert!(
                !entry.tokens.is_empty(),
                "full-text catalog entry has no covering token"
            );
            out.extend_from_slice(&entry.primary_token().to_le_bytes());
            debug_assert!(
                entry.property_tokens.len() <= u32::MAX as usize,
                "full-text property-token count exceeds u32"
            );
            out.extend_from_slice(&(entry.property_tokens.len() as u32).to_le_bytes());
            for &prop in &entry.property_tokens {
                out.extend_from_slice(&prop.to_le_bytes());
            }
            out.push(entry.analyzer);
            out.push(entry.state.as_byte());
        }
    }

    /// Encodes the trailing full-text **extension block** (`rmp` task #663), appended **last** (after
    /// the text catalog) so a pre-#663 image — ending after the text catalog — decodes it as empty and
    /// every legacy full-text entry keeps the [`FulltextEntity::Node`] + single-token shape the base
    /// block decoded.
    ///
    /// Layout: `n(u32) | [ name_len(u32) | name_bytes[name_len] | entity(u8) | n_extra(u32) |
    /// extra_token(u32)*n_extra ]*`, one entry **per full-text index that needs it** — a relationship
    /// index (to record its [`FulltextEntity`]) or any multi-token index (to record its additional
    /// covering tokens `tokens[1..]`) — in ascending-name ([`BTreeMap`]) order so the image is
    /// deterministic. A single-token **node** index contributes nothing (its base row + the default
    /// entity fully describe it), so a store using only pre-#663-shaped indexes writes an empty
    /// (`0`-count) block, keeping the extension byte-cost zero for the common case.
    fn encode_fulltext_extension_block(
        out: &mut Vec<u8>,
        map: &BTreeMap<String, FulltextIndexEntry>,
    ) {
        let extended: Vec<(&String, &FulltextIndexEntry)> = map
            .iter()
            .filter(|(_, entry)| entry.needs_extension())
            .collect();
        debug_assert!(
            extended.len() <= u32::MAX as usize,
            "full-text extension entry count exceeds u32"
        );
        out.extend_from_slice(&(extended.len() as u32).to_le_bytes());
        for (name, entry) in extended {
            let name_bytes = name.as_bytes();
            debug_assert!(
                name_bytes.len() <= u32::MAX as usize,
                "full-text index name exceeds u32 length"
            );
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.push(entry.entity.as_byte());
            // The additional covering tokens beyond the base block's `tokens[0]`. `needs_extension()`
            // only selected relationship / multi-token entries, both of which carry ≥1 token; the write
            // path (the coordinator's create sites) guarantees `tokens` is non-empty for every entry, so
            // the slice never underflows. Asserted in debug as defense-in-depth against a future path
            // that constructs an entry with empty `tokens` (which would panic mid-checkpoint here).
            debug_assert!(
                !entry.tokens.is_empty(),
                "full-text extension entry has no covering token"
            );
            let extra = &entry.tokens[1..];
            debug_assert!(
                extra.len() <= u32::MAX as usize,
                "full-text extra-token count exceeds u32"
            );
            out.extend_from_slice(&(extra.len() as u32).to_le_bytes());
            for &tok in extra {
                out.extend_from_slice(&tok.to_le_bytes());
            }
        }
    }

    /// Encodes the trailing spatial **extension block** (`rmp` task #664), appended **last** (after the
    /// full-text extension block) so a pre-#664 image — ending after the full-text extension block —
    /// decodes it as empty and every legacy spatial entry keeps the [`SpatialEntity::Node`] shape the
    /// base block decoded.
    ///
    /// Layout: `n(u32) | [ name_len(u32) | name_bytes[name_len] | entity(u8) ]*`, one entry **per
    /// spatial index that needs it** — a relationship index (to record its [`SpatialEntity`]) — in
    /// ascending-name ([`BTreeMap`]) order so the image is deterministic. A **node** index contributes
    /// nothing (its base row + the default entity fully describe it), so a store using only
    /// pre-#664-shaped (node) point indexes writes an empty (`0`-count) block, keeping the extension
    /// byte-cost zero for the common case. Unlike the full-text extension block there are no extra
    /// covering tokens (a spatial index covers exactly one label/type).
    fn encode_spatial_extension_block(
        out: &mut Vec<u8>,
        map: &BTreeMap<String, SpatialIndexEntry>,
    ) {
        let extended: Vec<(&String, &SpatialIndexEntry)> = map
            .iter()
            .filter(|(_, entry)| entry.needs_extension())
            .collect();
        debug_assert!(
            extended.len() <= u32::MAX as usize,
            "spatial extension entry count exceeds u32"
        );
        out.extend_from_slice(&(extended.len() as u32).to_le_bytes());
        for (name, entry) in extended {
            let name_bytes = name.as_bytes();
            debug_assert!(
                name_bytes.len() <= u32::MAX as usize,
                "spatial index name exceeds u32 length"
            );
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.push(entry.entity.as_byte());
        }
    }

    /// Encodes the spatial (point) index catalog block (`rmp` task #98), appended last so a pre-#98
    /// image (ending after the full-text catalog) decodes to an empty spatial catalog.
    ///
    /// Layout: `n(u32) | [ name_len(u32) | name_bytes[name_len] | label_token(u32) |
    /// property_token(u32) | state(u8) ]*`, entries in ascending-name ([`BTreeMap`]) order so the
    /// image is deterministic. Unlike the full-text block there is no analyzer byte and exactly one
    /// property token (a spatial index covers a single point property).
    ///
    /// # Single covered token (`rmp` task #664)
    ///
    /// This block persists the covered token in the same slot regardless of entity, byte-for-byte as
    /// the pre-#664 `label_token` slot, so the layout is unchanged and a pre-#664 image decodes here as
    /// a node index over that token. The [`entity`](SpatialIndexEntry::entity) — a relationship index —
    /// rides the trailing [`encode_spatial_extension_block`](Self::encode_spatial_extension_block).
    fn encode_spatial_catalog(out: &mut Vec<u8>, map: &BTreeMap<String, SpatialIndexEntry>) {
        debug_assert!(
            map.len() <= u32::MAX as usize,
            "spatial catalog entry count exceeds u32"
        );
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (name, entry) in map {
            let name_bytes = name.as_bytes();
            debug_assert!(
                name_bytes.len() <= u32::MAX as usize,
                "spatial index name exceeds u32 length"
            );
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&entry.label_token.to_le_bytes());
            out.extend_from_slice(&entry.property_token.to_le_bytes());
            out.push(entry.state.as_byte());
        }
    }

    /// Encodes the constraint catalog block (`rmp` task #99), appended last so a pre-#99 image
    /// (ending after the spatial catalog) decodes to an empty constraint catalog.
    ///
    /// Layout: `n(u32) | [ name_len(u32) | name_bytes[name_len] | label_token(u32) |
    /// n_props(u32) | prop_token(u32)*n_props | kind(u8) ]*`, entries in ascending-name
    /// ([`BTreeMap`]) order so the image is deterministic. Mirrors the full-text block (one or more
    /// property tokens) but carries a [`ConstraintKind`] byte in place of the analyzer + state bytes
    /// (a constraint has no build state — see [`ConstraintEntry`]).
    fn encode_constraint_catalog(out: &mut Vec<u8>, map: &BTreeMap<String, ConstraintEntry>) {
        debug_assert!(
            map.len() <= u32::MAX as usize,
            "constraint catalog entry count exceeds u32"
        );
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (name, entry) in map {
            let name_bytes = name.as_bytes();
            debug_assert!(
                name_bytes.len() <= u32::MAX as usize,
                "constraint name exceeds u32 length"
            );
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&entry.label_token.to_le_bytes());
            debug_assert!(
                entry.property_tokens.len() <= u32::MAX as usize,
                "constraint property-token count exceeds u32"
            );
            out.extend_from_slice(&(entry.property_tokens.len() as u32).to_le_bytes());
            for &prop in &entry.property_tokens {
                out.extend_from_slice(&prop.to_le_bytes());
            }
            out.push(entry.kind.as_byte());
        }
    }

    /// Encodes the constraint **type-descriptor** block (`rmp` task #100), appended after the
    /// constraint catalog so a pre-#100 image (ending after that catalog) decodes with every
    /// constraint's `type_descriptor` left `None`.
    ///
    /// Layout: `n(u32) | [ name_len(u32) | name_bytes[name_len] | descriptor ]*`, one entry **per
    /// named constraint that carries a `type_descriptor`** (only [`ConstraintKind::PropertyType`]
    /// constraints do), entries in ascending-name ([`BTreeMap`]) order so the image is deterministic.
    /// The `descriptor` is the self-describing byte encoding from
    /// [`ConstraintTypeDescriptor::encode`]. Constraints without a descriptor contribute nothing, so a
    /// store using only #99-era kinds writes an empty (`0`-count) block.
    fn encode_constraint_type_block(out: &mut Vec<u8>, map: &BTreeMap<String, ConstraintEntry>) {
        let typed: Vec<(&String, &ConstraintTypeDescriptor)> = map
            .iter()
            .filter_map(|(name, entry)| entry.type_descriptor.as_ref().map(|d| (name, d)))
            .collect();
        debug_assert!(
            typed.len() <= u32::MAX as usize,
            "constraint type-descriptor entry count exceeds u32"
        );
        out.extend_from_slice(&(typed.len() as u32).to_le_bytes());
        for (name, descriptor) in typed {
            let name_bytes = name.as_bytes();
            debug_assert!(
                name_bytes.len() <= u32::MAX as usize,
                "constraint name exceeds u32 length"
            );
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            descriptor.encode(out);
        }
    }

    /// Encodes the node-property index **name** catalog block (`rmp` task #623), appended after the
    /// constraint type-descriptor block so a pre-#623 image (ending after that block) decodes to an
    /// empty name catalog — i.e. every declared node-property index is nameless (a legacy anonymous
    /// index), which the Cypher layer backfills a deterministic auto-name for on open.
    ///
    /// Layout: `n(u32) | [ name_len(u32) | name_bytes[name_len] | label_token(u32) |
    /// prop_token(u32) ]*`, entries in ascending-name ([`BTreeMap`]) order so the image is
    /// deterministic. Mirrors the spatial block (single property token) but carries a name → target
    /// mapping with **no** state byte — the build state lives in the anonymous index catalog, keyed by
    /// the same `(label_token, prop_token)`.
    fn encode_index_name_catalog(out: &mut Vec<u8>, map: &BTreeMap<String, (u32, u32)>) {
        debug_assert!(
            map.len() <= u32::MAX as usize,
            "index-name catalog entry count exceeds u32"
        );
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (name, &(label_token, prop_token)) in map {
            let name_bytes = name.as_bytes();
            debug_assert!(
                name_bytes.len() <= u32::MAX as usize,
                "index name exceeds u32 length"
            );
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&label_token.to_le_bytes());
            out.extend_from_slice(&prop_token.to_le_bytes());
        }
    }

    /// Encodes the composite (multi-property) node index catalog block (`rmp` task #657), appended
    /// last so a pre-#657 image (ending after the relationship-property index name catalog) decodes to
    /// an empty composite catalog.
    ///
    /// Layout: `n(u32) | [ name_len(u32) | name_bytes[name_len] | label_token(u32) |
    /// n_props(u32) | prop_token(u32)*n_props | state(u8) ]*`, entries in ascending-name
    /// ([`BTreeMap`]) order so the image is deterministic. Mirrors the full-text block (one or more
    /// property tokens) but carries a build-[`IndexState`] byte in place of the analyzer + state bytes
    /// (a composite index has a build state but no analyzer).
    fn encode_composite_catalog(out: &mut Vec<u8>, map: &BTreeMap<String, CompositeIndexEntry>) {
        debug_assert!(
            map.len() <= u32::MAX as usize,
            "composite catalog entry count exceeds u32"
        );
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (name, entry) in map {
            let name_bytes = name.as_bytes();
            debug_assert!(
                name_bytes.len() <= u32::MAX as usize,
                "composite index name exceeds u32 length"
            );
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&entry.label_token.to_le_bytes());
            debug_assert!(
                entry.property_tokens.len() <= u32::MAX as usize,
                "composite property-token count exceeds u32"
            );
            out.extend_from_slice(&(entry.property_tokens.len() as u32).to_le_bytes());
            for &prop in &entry.property_tokens {
                out.extend_from_slice(&prop.to_le_bytes());
            }
            out.push(entry.state.as_byte());
        }
    }

    /// Encodes the composite (multi-property) **relationship** index catalog block (`rmp` task #666),
    /// appended LAST so a pre-#666 image (ending after the spatial extension block) decodes to an empty
    /// relationship composite catalog.
    ///
    /// Layout: `n(u32) | [ name_len(u32) | name_bytes[name_len] | type_token(u32) |
    /// n_props(u32) | prop_token(u32)*n_props | state(u8) ]*`, entries in ascending-name
    /// ([`BTreeMap`]) order so the image is deterministic. Byte-identical to the node composite block
    /// ([`encode_composite_catalog`](Self::encode_composite_catalog)); the `type_token` occupies the
    /// slot the node block's `label_token` does.
    fn encode_rel_composite_catalog(
        out: &mut Vec<u8>,
        map: &BTreeMap<String, RelCompositeIndexEntry>,
    ) {
        debug_assert!(
            map.len() <= u32::MAX as usize,
            "relationship composite catalog entry count exceeds u32"
        );
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (name, entry) in map {
            let name_bytes = name.as_bytes();
            debug_assert!(
                name_bytes.len() <= u32::MAX as usize,
                "relationship composite index name exceeds u32 length"
            );
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&entry.type_token.to_le_bytes());
            debug_assert!(
                entry.property_tokens.len() <= u32::MAX as usize,
                "relationship composite property-token count exceeds u32"
            );
            out.extend_from_slice(&(entry.property_tokens.len() as u32).to_le_bytes());
            for &prop in &entry.property_tokens {
                out.extend_from_slice(&prop.to_le_bytes());
            }
            out.push(entry.state.as_byte());
        }
    }

    /// Encodes the vector (HNSW) index catalog block (`rmp` task #669), appended LAST so a pre-#669
    /// image (ending after the relationship composite catalog) decodes to an empty vector catalog.
    ///
    /// Layout: `n(u32) | [ name_len(u32) | name_bytes[name_len] | entity(u8) | token(u32) |
    /// property_token(u32) | dimensions(u32) | similarity(u8) | m(u32) | ef_construction(u32) |
    /// state(u8) ]*`, entries in ascending-name ([`BTreeMap`]) order so the image is deterministic. A
    /// wholly new block: unlike the full-text / spatial catalogs there is no base + trailing-extension
    /// split, so the entity + the full HNSW shape are all stored inline.
    fn encode_vector_catalog(out: &mut Vec<u8>, map: &BTreeMap<String, VectorIndexEntry>) {
        debug_assert!(
            map.len() <= u32::MAX as usize,
            "vector catalog entry count exceeds u32"
        );
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (name, entry) in map {
            let name_bytes = name.as_bytes();
            debug_assert!(
                name_bytes.len() <= u32::MAX as usize,
                "vector index name exceeds u32 length"
            );
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.push(entry.entity.as_byte());
            out.extend_from_slice(&entry.token.to_le_bytes());
            out.extend_from_slice(&entry.property_token.to_le_bytes());
            out.extend_from_slice(&entry.dimensions.to_le_bytes());
            out.push(entry.similarity.as_byte());
            out.extend_from_slice(&entry.m.to_le_bytes());
            out.extend_from_slice(&entry.ef_construction.to_le_bytes());
            out.push(entry.state.as_byte());
        }
    }

    /// Encodes the text (trigram) node index catalog block (`rmp` task #662), appended last so a
    /// pre-#662 image (ending after the composite catalog) decodes to an empty text catalog.
    ///
    /// Layout: `n(u32) | [ name_len(u32) | name_bytes[name_len] | label_token(u32) |
    /// property_token(u32) | state(u8) ]*`, entries in ascending-name ([`BTreeMap`]) order so the image
    /// is deterministic. Byte-identical to the spatial block (one label token + one property token +
    /// a state byte) — a text index, like a spatial index, covers exactly one property.
    fn encode_text_catalog(out: &mut Vec<u8>, map: &BTreeMap<String, TextIndexEntry>) {
        debug_assert!(
            map.len() <= u32::MAX as usize,
            "text catalog entry count exceeds u32"
        );
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (name, entry) in map {
            let name_bytes = name.as_bytes();
            debug_assert!(
                name_bytes.len() <= u32::MAX as usize,
                "text index name exceeds u32 length"
            );
            out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&entry.label_token.to_le_bytes());
            out.extend_from_slice(&entry.property_token.to_le_bytes());
            out.push(entry.state.as_byte());
        }
    }

    /// Rebuilds the statistics from an image produced by [`encode`](Self::encode).
    ///
    /// # Errors
    /// Returns a storage error if the image is truncated, a count is `0` (violates the zero-count
    /// invariant — such an image was never produced by [`encode`](Self::encode)), a token id appears
    /// twice in one count map, a histogram blob is zero-length, a `(label, property)` histogram key
    /// appears twice, an index-catalog state byte is unknown (reserved/future), or an index-catalog
    /// `(label, property)` key appears twice. A pre-`rmp`-task-#90 image (ending after the histogram
    /// block) is accepted and decodes to an empty index catalog.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cur = 0usize;
        // Grand-total header first (`rmp` task #82); `read_u64` is truncation-safe, so a too-short
        // image is rejected here before any map is read.
        let total_nodes = read_u64(bytes, &mut cur)?;
        let total_relationships = read_u64(bytes, &mut cur)?;
        let nodes_per_label = Self::decode_map(bytes, &mut cur, "nodes_per_label")?;
        let rels_per_type = Self::decode_map(bytes, &mut cur, "rels_per_type")?;
        let node_prop_histograms = Self::decode_histograms(bytes, &mut cur)?;
        let node_property_indexes = Self::decode_index_catalog(bytes, &mut cur)?;
        // Kept mutable: the trailing full-text extension block (`rmp` task #663), decoded after the text
        // catalog, patches each relationship / multi-token index's entity + additional covering tokens
        // back onto its entry here (exactly as the constraint type-descriptor block patches constraints).
        let mut fulltext_indexes = Self::decode_fulltext_catalog(bytes, &mut cur)?;
        // Kept mutable: the trailing spatial extension block (`rmp` task #664), decoded last, patches
        // each relationship point index's entity back onto its entry here (like the full-text one).
        let mut spatial_indexes = Self::decode_spatial_catalog(bytes, &mut cur)?;
        let mut constraints = Self::decode_constraint_catalog(bytes, &mut cur)?;
        // Merge the trailing property-type descriptor block (`rmp` task #100) back onto its named
        // constraints. A pre-#100 image ends after the constraint catalog, so this block decodes empty
        // and every entry keeps the `type_descriptor: None` the catalog decode already set.
        Self::decode_constraint_type_block(bytes, &mut cur, &mut constraints)?;
        // Decode the trailing node-property index **name** catalog (`rmp` task #623). A pre-#623 image
        // ends after the type-descriptor block, so this block decodes empty and every declared index is
        // nameless (backfilled with an auto-name by the Cypher layer on open). Validated against the
        // anonymous index catalog: every name must target a declared index.
        let node_property_index_names =
            Self::decode_index_name_catalog(bytes, &mut cur, &node_property_indexes)?;
        // Decode the trailing relationship-property index catalog + its name catalog (`rmp` task #646).
        // A pre-#646 image ends after the node-property index name catalog, so both blocks decode empty
        // via the shared decoders' end-of-input guard. The name catalog is validated against the
        // relationship-property index catalog (every name must target a declared rel-property index).
        let rel_property_indexes = Self::decode_index_catalog(bytes, &mut cur)?;
        let rel_property_index_names =
            Self::decode_index_name_catalog(bytes, &mut cur, &rel_property_indexes)?;
        // Decode the trailing composite (multi-property) node index catalog (`rmp` task #657). A
        // pre-#657 image ends after the relationship-property index name catalog, so this block decodes
        // empty via the end-of-input guard.
        let composite_indexes = Self::decode_composite_catalog(bytes, &mut cur)?;
        // Decode the trailing text (trigram) node index catalog (`rmp` task #662). A pre-#662 image ends
        // after the composite catalog, so this block decodes empty via the end-of-input guard.
        let text_indexes = Self::decode_text_catalog(bytes, &mut cur)?;
        // Merge the trailing full-text extension block (`rmp` task #663) back onto its named indexes. A
        // pre-#663 image ends after the text catalog, so this block decodes empty and every full-text
        // entry keeps the node + single-token shape the catalog decode set.
        Self::decode_fulltext_extension_block(bytes, &mut cur, &mut fulltext_indexes)?;
        // Merge the trailing spatial extension block (`rmp` task #664) back onto its named indexes. A
        // pre-#664 image ends after the full-text extension block, so this block decodes empty and
        // every spatial entry keeps the node shape the catalog decode set.
        Self::decode_spatial_extension_block(bytes, &mut cur, &mut spatial_indexes)?;
        // Decode the trailing composite (multi-property) **relationship** index catalog (`rmp` task
        // #666). A pre-#666 image ends after the spatial extension block, so this block decodes empty
        // via the end-of-input guard.
        let rel_composite_indexes = Self::decode_rel_composite_catalog(bytes, &mut cur)?;
        // Decode the trailing vector (HNSW) index catalog (`rmp` task #669), the LAST block. A pre-#669
        // image ends after the relationship composite block, so this block decodes empty via the
        // end-of-input guard.
        let vector_indexes = Self::decode_vector_catalog(bytes, &mut cur)?;
        // Decode the two trailing directional relationship-count projections (`rmp` task #856), the LAST
        // blocks. A pre-#856 image ends after the vector catalog, so both decode empty via the
        // end-of-input guard — the database then simply has no directional input for the estimator, which
        // falls back to the graph-wide degree until a backfill runs.
        let rels_per_start_label_type =
            Self::decode_pair_map(bytes, &mut cur, "rels_per_start_label_type")?;
        let rels_per_type_end_label =
            Self::decode_pair_map(bytes, &mut cur, "rels_per_type_end_label")?;
        Ok(Self {
            total_nodes,
            total_relationships,
            nodes_per_label,
            rels_per_type,
            rels_per_start_label_type,
            rels_per_type_end_label,
            node_prop_histograms,
            node_property_indexes,
            fulltext_indexes,
            spatial_indexes,
            constraints,
            node_property_index_names,
            rel_property_indexes,
            rel_property_index_names,
            composite_indexes,
            rel_composite_indexes,
            text_indexes,
            vector_indexes,
        })
    }

    /// Decodes a pair-keyed counter map (`rmp` task #856), tolerating a pre-#856 image that simply ends
    /// where this block would start.
    ///
    /// Enforces the same two invariants [`decode_map`](Self::decode_map) does — no stored zero (the
    /// zero-count invariant that makes equality against a fresh re-scan meaningful) and no repeated key
    /// — because a violated invariant here would hand the planner a cardinality it must not trust, and a
    /// corrupt catalogue must be rejected rather than silently believed.
    fn decode_pair_map(
        bytes: &[u8],
        cur: &mut usize,
        which: &str,
    ) -> Result<BTreeMap<(u32, u32), u64>> {
        let mut map = BTreeMap::new();
        // Backward compatibility (`rmp` task #856): a pre-#856 image ends exactly here.
        if *cur == bytes.len() {
            return Ok(map);
        }
        let n = read_u32(bytes, cur)? as usize;
        for _ in 0..n {
            let a = read_u32(bytes, cur)?;
            let b = read_u32(bytes, cur)?;
            let count = read_u64(bytes, cur)?;
            if count == 0 {
                return Err(GraphusError::Storage(format!(
                    "statistics {which} holds a zero count for key ({a}, {b})"
                )));
            }
            if map.insert((a, b), count).is_some() {
                return Err(GraphusError::Storage(format!(
                    "statistics {which} repeats key ({a}, {b})"
                )));
            }
        }
        Ok(map)
    }

    fn decode_map(bytes: &[u8], cur: &mut usize, which: &str) -> Result<BTreeMap<u32, u64>> {
        let n = read_u32(bytes, cur)? as usize;
        let mut map = BTreeMap::new();
        for _ in 0..n {
            let token_id = read_u32(bytes, cur)?;
            let count = read_u64(bytes, cur)?;
            if count == 0 {
                return Err(GraphusError::Storage(format!(
                    "statistics {which} holds a zero count for token id {token_id}"
                )));
            }
            if map.insert(token_id, count).is_some() {
                return Err(GraphusError::Storage(format!(
                    "statistics {which} repeats token id {token_id}"
                )));
            }
        }
        Ok(map)
    }

    fn decode_histograms(bytes: &[u8], cur: &mut usize) -> Result<BTreeMap<(u32, u32), Vec<u8>>> {
        let n = read_u32(bytes, cur)? as usize;
        let mut map = BTreeMap::new();
        for _ in 0..n {
            let label_token = read_u32(bytes, cur)?;
            let prop_token = read_u32(bytes, cur)?;
            let blob_len = read_u32(bytes, cur)? as usize;
            if blob_len == 0 {
                return Err(GraphusError::Storage(format!(
                    "statistics histogram for ({label_token}, {prop_token}) is zero-length"
                )));
            }
            let end = take(bytes, cur, blob_len)?;
            let blob = bytes[end - blob_len..end].to_vec();
            if map.insert((label_token, prop_token), blob).is_some() {
                return Err(GraphusError::Storage(format!(
                    "statistics histogram repeats key ({label_token}, {prop_token})"
                )));
            }
        }
        Ok(map)
    }

    fn decode_index_catalog(
        bytes: &[u8],
        cur: &mut usize,
    ) -> Result<BTreeMap<(u32, u32), IndexState>> {
        let mut map = BTreeMap::new();
        // Backward compatibility (`rmp` task #90): a pre-#90 image ends exactly here (after the
        // histogram block), so end-of-input where the count `u32` would start means "no index
        // catalog", not truncation. Any *partial* count word that follows is still a genuine
        // truncation and is rejected by `read_u32` below.
        if *cur == bytes.len() {
            return Ok(map);
        }
        let n = read_u32(bytes, cur)? as usize;
        for _ in 0..n {
            let label_token = read_u32(bytes, cur)?;
            let prop_token = read_u32(bytes, cur)?;
            let state_byte = read_u8(bytes, cur)?;
            let state = IndexState::from_byte(state_byte).ok_or_else(|| {
                GraphusError::Storage(format!(
                    "statistics index catalog holds unknown state byte {state_byte} for \
                     ({label_token}, {prop_token})"
                ))
            })?;
            if map.insert((label_token, prop_token), state).is_some() {
                return Err(GraphusError::Storage(format!(
                    "statistics index catalog repeats key ({label_token}, {prop_token})"
                )));
            }
        }
        Ok(map)
    }

    /// Decodes the full-text index catalog block (`rmp` task #72). Like the node-property index
    /// catalog this is the last block, so end-of-input where its count `u32` would start means "no
    /// full-text catalog" (a pre-#72 image), not truncation.
    ///
    /// The analyzer byte is **not** validated here (it is the query layer's domain, stored verbatim
    /// like a histogram blob); the `state` byte is range-checked. A repeated name, an empty name, or
    /// a zero property-token count is rejected (none is ever produced by [`encode`](Self::encode)).
    fn decode_fulltext_catalog(
        bytes: &[u8],
        cur: &mut usize,
    ) -> Result<BTreeMap<String, FulltextIndexEntry>> {
        let mut map = BTreeMap::new();
        // Backward compatibility (`rmp` task #72): a pre-#72 image ends exactly here.
        if *cur == bytes.len() {
            return Ok(map);
        }
        let n = read_u32(bytes, cur)? as usize;
        for _ in 0..n {
            let name_len = read_u32(bytes, cur)? as usize;
            let end = take(bytes, cur, name_len)?;
            let name = String::from_utf8(bytes[end - name_len..end].to_vec()).map_err(|_| {
                GraphusError::Storage("full-text catalog name is not valid UTF-8".to_owned())
            })?;
            if name.is_empty() {
                return Err(GraphusError::Storage(
                    "full-text catalog holds an empty index name".to_owned(),
                ));
            }
            let primary_token = read_u32(bytes, cur)?;
            let n_props = read_u32(bytes, cur)? as usize;
            if n_props == 0 {
                return Err(GraphusError::Storage(format!(
                    "full-text index {name:?} declares no properties"
                )));
            }
            // Cap the pre-allocation by the bytes remaining: `n_props` is an untrusted on-disk u32
            // and each property is a 4-byte `read_u32`, so the real count cannot exceed `bytes.len()`.
            // Without the cap, `n_props = 0xFFFF_FFFF` would force a multi-GiB allocation (OOM) before
            // the per-element bounds checks below ever run. The reads still validate every element.
            let mut property_tokens = Vec::with_capacity(n_props.min(bytes.len()));
            for _ in 0..n_props {
                property_tokens.push(read_u32(bytes, cur)?);
            }
            let analyzer = read_u8(bytes, cur)?;
            let state_byte = read_u8(bytes, cur)?;
            let state = IndexState::from_byte(state_byte).ok_or_else(|| {
                GraphusError::Storage(format!(
                    "full-text index {name:?} holds unknown state byte {state_byte}"
                ))
            })?;
            if map
                .insert(
                    name.clone(),
                    // The base row always decodes as a **node** index over the single primary token
                    // (`rmp` task #663); a trailing extension block (if any) patches the entity and
                    // appends the additional covering tokens. A pre-#663 image has no extension, so
                    // this node + single-token shape is final — matching the legacy semantics exactly.
                    FulltextIndexEntry {
                        entity: FulltextEntity::Node,
                        tokens: vec![primary_token],
                        property_tokens,
                        analyzer,
                        state,
                    },
                )
                .is_some()
            {
                return Err(GraphusError::Storage(format!(
                    "full-text catalog repeats index name {name:?}"
                )));
            }
        }
        Ok(map)
    }

    /// Decodes the trailing full-text **extension block** (`rmp` task #663) and merges each entry's
    /// entity + additional covering tokens onto its named index in `fulltext_indexes`. Like every later
    /// block, end-of-input where its count `u32` would start means "no extension block" (a pre-#663
    /// image), not truncation — leaving every entry with the [`FulltextEntity::Node`] + single-token
    /// shape [`decode_fulltext_catalog`](Self::decode_fulltext_catalog) already set.
    ///
    /// # Errors
    /// Returns a storage error on truncation, a repeated / empty / non-UTF-8 name, an unknown entity
    /// byte (a forward-incompatible image), or a name with no matching full-text index (an orphan
    /// extension — never produced by [`encode`](Self::encode), which only ever writes an extension for a
    /// declared index).
    fn decode_fulltext_extension_block(
        bytes: &[u8],
        cur: &mut usize,
        fulltext_indexes: &mut BTreeMap<String, FulltextIndexEntry>,
    ) -> Result<()> {
        // Backward compatibility (`rmp` task #663): a pre-#663 image ends exactly here.
        if *cur == bytes.len() {
            return Ok(());
        }
        let n = read_u32(bytes, cur)? as usize;
        let mut seen: BTreeMap<String, ()> = BTreeMap::new();
        for _ in 0..n {
            let name_len = read_u32(bytes, cur)? as usize;
            let end = take(bytes, cur, name_len)?;
            let name = String::from_utf8(bytes[end - name_len..end].to_vec()).map_err(|_| {
                GraphusError::Storage("full-text extension name is not valid UTF-8".to_owned())
            })?;
            if name.is_empty() {
                return Err(GraphusError::Storage(
                    "full-text extension block holds an empty index name".to_owned(),
                ));
            }
            let entity_byte = read_u8(bytes, cur)?;
            let entity = FulltextEntity::from_byte(entity_byte).ok_or_else(|| {
                GraphusError::Storage(format!(
                    "full-text index {name:?} holds unknown entity byte {entity_byte}"
                ))
            })?;
            let n_extra = read_u32(bytes, cur)? as usize;
            // Cap the pre-allocation by the bytes remaining (see the base decoder): `n_extra` is an
            // untrusted on-disk u32 and each token is a 4-byte read, so the real count cannot exceed
            // `bytes.len()`. Prevents an OOM from a forged count before the per-element reads validate.
            let mut extra = Vec::with_capacity(n_extra.min(bytes.len()));
            for _ in 0..n_extra {
                extra.push(read_u32(bytes, cur)?);
            }
            if seen.insert(name.clone(), ()).is_some() {
                return Err(GraphusError::Storage(format!(
                    "full-text extension block repeats index name {name:?}"
                )));
            }
            match fulltext_indexes.get_mut(&name) {
                Some(entry) => {
                    entry.entity = entity;
                    entry.tokens.extend(extra);
                }
                None => {
                    return Err(GraphusError::Storage(format!(
                        "full-text extension block names unknown index {name:?}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Decodes the trailing spatial **extension block** (`rmp` task #664) and merges each entry's entity
    /// onto its named index in `spatial_indexes`. Like every later block, end-of-input where its count
    /// `u32` would start means "no extension block" (a pre-#664 image), not truncation — leaving every
    /// entry with the [`SpatialEntity::Node`] shape [`decode_spatial_catalog`](Self::decode_spatial_catalog)
    /// already set.
    ///
    /// # Errors
    /// Returns a storage error on truncation, a repeated / empty / non-UTF-8 name, an unknown entity
    /// byte (a forward-incompatible image), or a name with no matching spatial index (an orphan
    /// extension — never produced by [`encode`](Self::encode), which only ever writes an extension for a
    /// declared relationship index).
    fn decode_spatial_extension_block(
        bytes: &[u8],
        cur: &mut usize,
        spatial_indexes: &mut BTreeMap<String, SpatialIndexEntry>,
    ) -> Result<()> {
        // Backward compatibility (`rmp` task #664): a pre-#664 image ends exactly here.
        if *cur == bytes.len() {
            return Ok(());
        }
        let n = read_u32(bytes, cur)? as usize;
        let mut seen: BTreeMap<String, ()> = BTreeMap::new();
        for _ in 0..n {
            let name_len = read_u32(bytes, cur)? as usize;
            let end = take(bytes, cur, name_len)?;
            let name = String::from_utf8(bytes[end - name_len..end].to_vec()).map_err(|_| {
                GraphusError::Storage("spatial extension name is not valid UTF-8".to_owned())
            })?;
            if name.is_empty() {
                return Err(GraphusError::Storage(
                    "spatial extension block holds an empty index name".to_owned(),
                ));
            }
            let entity_byte = read_u8(bytes, cur)?;
            let entity = SpatialEntity::from_byte(entity_byte).ok_or_else(|| {
                GraphusError::Storage(format!(
                    "spatial index {name:?} holds unknown entity byte {entity_byte}"
                ))
            })?;
            if seen.insert(name.clone(), ()).is_some() {
                return Err(GraphusError::Storage(format!(
                    "spatial extension block repeats index name {name:?}"
                )));
            }
            match spatial_indexes.get_mut(&name) {
                Some(entry) => entry.entity = entity,
                None => {
                    return Err(GraphusError::Storage(format!(
                        "spatial extension block names unknown index {name:?}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Decodes the spatial (point) index catalog block (`rmp` task #98). Like the full-text catalog
    /// this is the last block, so end-of-input where its count `u32` would start means "no spatial
    /// catalog" (a pre-#98 image), not truncation.
    ///
    /// The `state` byte is range-checked. A repeated name or an empty name is rejected (neither is
    /// ever produced by [`encode`](Self::encode)).
    fn decode_spatial_catalog(
        bytes: &[u8],
        cur: &mut usize,
    ) -> Result<BTreeMap<String, SpatialIndexEntry>> {
        let mut map = BTreeMap::new();
        // Backward compatibility (`rmp` task #98): a pre-#98 image ends exactly here.
        if *cur == bytes.len() {
            return Ok(map);
        }
        let n = read_u32(bytes, cur)? as usize;
        for _ in 0..n {
            let name_len = read_u32(bytes, cur)? as usize;
            let end = take(bytes, cur, name_len)?;
            let name = String::from_utf8(bytes[end - name_len..end].to_vec()).map_err(|_| {
                GraphusError::Storage("spatial catalog name is not valid UTF-8".to_owned())
            })?;
            if name.is_empty() {
                return Err(GraphusError::Storage(
                    "spatial catalog holds an empty index name".to_owned(),
                ));
            }
            let label_token = read_u32(bytes, cur)?;
            let property_token = read_u32(bytes, cur)?;
            let state_byte = read_u8(bytes, cur)?;
            let state = IndexState::from_byte(state_byte).ok_or_else(|| {
                GraphusError::Storage(format!(
                    "spatial index {name:?} holds unknown state byte {state_byte}"
                ))
            })?;
            if map
                .insert(
                    name.clone(),
                    // The base row always decodes as a **node** index over the covered token (`rmp`
                    // task #664); a trailing extension block (if any) patches the entity. A pre-#664
                    // image has no extension, so this node shape is final — matching legacy semantics.
                    SpatialIndexEntry {
                        entity: SpatialEntity::Node,
                        label_token,
                        property_token,
                        state,
                    },
                )
                .is_some()
            {
                return Err(GraphusError::Storage(format!(
                    "spatial catalog repeats index name {name:?}"
                )));
            }
        }
        Ok(map)
    }

    /// Decodes the composite (multi-property) node index catalog block (`rmp` task #657). Like every
    /// later block, end-of-input where its count `u32` would start means "no composite catalog" (a
    /// pre-#657 image), not truncation.
    ///
    /// The `state` byte is range-checked. A repeated name, an empty name, or a zero property-token
    /// count is rejected (none is ever produced by [`encode`](Self::encode)). A single-property entry
    /// (`n_props == 1`) is not rejected here (the block is self-describing), but the Cypher layer never
    /// writes one — arity-1 lives in the single-property node index catalog.
    fn decode_composite_catalog(
        bytes: &[u8],
        cur: &mut usize,
    ) -> Result<BTreeMap<String, CompositeIndexEntry>> {
        let mut map = BTreeMap::new();
        // Backward compatibility (`rmp` task #657): a pre-#657 image ends exactly here.
        if *cur == bytes.len() {
            return Ok(map);
        }
        let n = read_u32(bytes, cur)? as usize;
        for _ in 0..n {
            let name_len = read_u32(bytes, cur)? as usize;
            let end = take(bytes, cur, name_len)?;
            let name = String::from_utf8(bytes[end - name_len..end].to_vec()).map_err(|_| {
                GraphusError::Storage("composite catalog name is not valid UTF-8".to_owned())
            })?;
            if name.is_empty() {
                return Err(GraphusError::Storage(
                    "composite catalog holds an empty index name".to_owned(),
                ));
            }
            let label_token = read_u32(bytes, cur)?;
            let n_props = read_u32(bytes, cur)? as usize;
            if n_props == 0 {
                return Err(GraphusError::Storage(format!(
                    "composite index {name:?} covers no properties"
                )));
            }
            // Cap by the bytes remaining (see the full-text decoder above): `n_props` is an untrusted
            // u32 and each property is a 4-byte read, so capacity never legitimately exceeds
            // `bytes.len()`. Prevents an OOM from a forged count before the per-element reads validate.
            let mut property_tokens = Vec::with_capacity(n_props.min(bytes.len()));
            for _ in 0..n_props {
                property_tokens.push(read_u32(bytes, cur)?);
            }
            let state_byte = read_u8(bytes, cur)?;
            let state = IndexState::from_byte(state_byte).ok_or_else(|| {
                GraphusError::Storage(format!(
                    "composite index {name:?} holds unknown state byte {state_byte}"
                ))
            })?;
            if map
                .insert(
                    name.clone(),
                    CompositeIndexEntry {
                        label_token,
                        property_tokens,
                        state,
                    },
                )
                .is_some()
            {
                return Err(GraphusError::Storage(format!(
                    "composite catalog repeats index name {name:?}"
                )));
            }
        }
        Ok(map)
    }

    /// Decodes the composite (multi-property) **relationship** index catalog block (`rmp` task #666) —
    /// the LAST block. End-of-input where its count `u32` would start means "no relationship composite
    /// catalog" (a pre-#666 image), not truncation.
    ///
    /// The `state` byte is range-checked. A repeated name, an empty name, or a zero property-token
    /// count is rejected (none is ever produced by [`encode`](Self::encode)). A single-property entry
    /// (`n_props == 1`) is not rejected here (the block is self-describing), but the Cypher layer never
    /// writes one — arity-1 lives in the single-property relationship-property index catalog. Byte-for-
    /// byte mirrors the node composite decoder ([`decode_composite_catalog`](Self::decode_composite_catalog)).
    fn decode_rel_composite_catalog(
        bytes: &[u8],
        cur: &mut usize,
    ) -> Result<BTreeMap<String, RelCompositeIndexEntry>> {
        let mut map = BTreeMap::new();
        // Backward compatibility (`rmp` task #666): a pre-#666 image ends exactly here.
        if *cur == bytes.len() {
            return Ok(map);
        }
        let n = read_u32(bytes, cur)? as usize;
        for _ in 0..n {
            let name_len = read_u32(bytes, cur)? as usize;
            let end = take(bytes, cur, name_len)?;
            let name = String::from_utf8(bytes[end - name_len..end].to_vec()).map_err(|_| {
                GraphusError::Storage(
                    "relationship composite catalog name is not valid UTF-8".to_owned(),
                )
            })?;
            if name.is_empty() {
                return Err(GraphusError::Storage(
                    "relationship composite catalog holds an empty index name".to_owned(),
                ));
            }
            let type_token = read_u32(bytes, cur)?;
            let n_props = read_u32(bytes, cur)? as usize;
            if n_props == 0 {
                return Err(GraphusError::Storage(format!(
                    "relationship composite index {name:?} covers no properties"
                )));
            }
            // Cap by the bytes remaining (see the node composite decoder above): `n_props` is an
            // untrusted u32 and each property is a 4-byte read, so capacity never legitimately exceeds
            // `bytes.len()`. Prevents an OOM from a forged count before the per-element reads validate.
            let mut property_tokens = Vec::with_capacity(n_props.min(bytes.len()));
            for _ in 0..n_props {
                property_tokens.push(read_u32(bytes, cur)?);
            }
            let state_byte = read_u8(bytes, cur)?;
            let state = IndexState::from_byte(state_byte).ok_or_else(|| {
                GraphusError::Storage(format!(
                    "relationship composite index {name:?} holds unknown state byte {state_byte}"
                ))
            })?;
            if map
                .insert(
                    name.clone(),
                    RelCompositeIndexEntry {
                        type_token,
                        property_tokens,
                        state,
                    },
                )
                .is_some()
            {
                return Err(GraphusError::Storage(format!(
                    "relationship composite catalog repeats index name {name:?}"
                )));
            }
        }
        Ok(map)
    }

    /// Decodes the vector (HNSW) index catalog block (`rmp` task #669) — the LAST block. End-of-input
    /// where its count `u32` would start means "no vector catalog" (a pre-#669 image), not truncation.
    ///
    /// The `entity`, `similarity` and `state` bytes are each range-checked (an unknown byte is a
    /// forward-incompatible image, rejected). A repeated name, an empty name, or a **zero dimension** is
    /// rejected — none is ever produced by [`encode`](Self::encode), and a zero dimension would make the
    /// backing HNSW graph unconstructable on rebuild.
    fn decode_vector_catalog(
        bytes: &[u8],
        cur: &mut usize,
    ) -> Result<BTreeMap<String, VectorIndexEntry>> {
        let mut map = BTreeMap::new();
        // Backward compatibility (`rmp` task #669): a pre-#669 image ends exactly here.
        if *cur == bytes.len() {
            return Ok(map);
        }
        let n = read_u32(bytes, cur)? as usize;
        for _ in 0..n {
            let name_len = read_u32(bytes, cur)? as usize;
            let end = take(bytes, cur, name_len)?;
            let name = String::from_utf8(bytes[end - name_len..end].to_vec()).map_err(|_| {
                GraphusError::Storage("vector catalog name is not valid UTF-8".to_owned())
            })?;
            if name.is_empty() {
                return Err(GraphusError::Storage(
                    "vector catalog holds an empty index name".to_owned(),
                ));
            }
            let entity_byte = read_u8(bytes, cur)?;
            let entity = VectorEntity::from_byte(entity_byte).ok_or_else(|| {
                GraphusError::Storage(format!(
                    "vector index {name:?} holds unknown entity byte {entity_byte}"
                ))
            })?;
            let token = read_u32(bytes, cur)?;
            let property_token = read_u32(bytes, cur)?;
            let dimensions = read_u32(bytes, cur)?;
            if dimensions == 0 {
                return Err(GraphusError::Storage(format!(
                    "vector index {name:?} declares a zero dimension"
                )));
            }
            let similarity_byte = read_u8(bytes, cur)?;
            let similarity = VectorSimilarity::from_byte(similarity_byte).ok_or_else(|| {
                GraphusError::Storage(format!(
                    "vector index {name:?} holds unknown similarity byte {similarity_byte}"
                ))
            })?;
            let m = read_u32(bytes, cur)?;
            let ef_construction = read_u32(bytes, cur)?;
            let state_byte = read_u8(bytes, cur)?;
            let state = IndexState::from_byte(state_byte).ok_or_else(|| {
                GraphusError::Storage(format!(
                    "vector index {name:?} holds unknown state byte {state_byte}"
                ))
            })?;
            if map
                .insert(
                    name.clone(),
                    VectorIndexEntry {
                        entity,
                        token,
                        property_token,
                        dimensions,
                        similarity,
                        m,
                        ef_construction,
                        state,
                    },
                )
                .is_some()
            {
                return Err(GraphusError::Storage(format!(
                    "vector catalog repeats index name {name:?}"
                )));
            }
        }
        Ok(map)
    }

    /// Decodes the text (trigram) node index catalog block (`rmp` task #662). Like every later block,
    /// end-of-input where its count `u32` would start means "no text catalog" (a pre-#662 image), not
    /// truncation.
    ///
    /// The `state` byte is range-checked; a repeated name or an empty name is rejected (neither is ever
    /// produced by [`encode`](Self::encode)). Byte-for-byte mirrors the spatial decoder (one label
    /// token + one property token + a state byte).
    fn decode_text_catalog(
        bytes: &[u8],
        cur: &mut usize,
    ) -> Result<BTreeMap<String, TextIndexEntry>> {
        let mut map = BTreeMap::new();
        // Backward compatibility (`rmp` task #662): a pre-#662 image ends exactly here.
        if *cur == bytes.len() {
            return Ok(map);
        }
        let n = read_u32(bytes, cur)? as usize;
        for _ in 0..n {
            let name_len = read_u32(bytes, cur)? as usize;
            let end = take(bytes, cur, name_len)?;
            let name = String::from_utf8(bytes[end - name_len..end].to_vec()).map_err(|_| {
                GraphusError::Storage("text catalog name is not valid UTF-8".to_owned())
            })?;
            if name.is_empty() {
                return Err(GraphusError::Storage(
                    "text catalog holds an empty index name".to_owned(),
                ));
            }
            let label_token = read_u32(bytes, cur)?;
            let property_token = read_u32(bytes, cur)?;
            let state_byte = read_u8(bytes, cur)?;
            let state = IndexState::from_byte(state_byte).ok_or_else(|| {
                GraphusError::Storage(format!(
                    "text index {name:?} holds unknown state byte {state_byte}"
                ))
            })?;
            if map
                .insert(
                    name.clone(),
                    TextIndexEntry {
                        label_token,
                        property_token,
                        state,
                    },
                )
                .is_some()
            {
                return Err(GraphusError::Storage(format!(
                    "text catalog repeats index name {name:?}"
                )));
            }
        }
        Ok(map)
    }

    /// Decodes the constraint catalog block (`rmp` task #99). Like the spatial catalog this is the
    /// last block, so end-of-input where its count `u32` would start means "no constraint catalog" (a
    /// pre-#99 image), not truncation.
    ///
    /// The `kind` byte is range-checked. A repeated name, an empty name, or a zero property-token
    /// count is rejected (none is ever produced by [`encode`](Self::encode)).
    fn decode_constraint_catalog(
        bytes: &[u8],
        cur: &mut usize,
    ) -> Result<BTreeMap<String, ConstraintEntry>> {
        let mut map = BTreeMap::new();
        // Backward compatibility (`rmp` task #99): a pre-#99 image ends exactly here.
        if *cur == bytes.len() {
            return Ok(map);
        }
        let n = read_u32(bytes, cur)? as usize;
        for _ in 0..n {
            let name_len = read_u32(bytes, cur)? as usize;
            let end = take(bytes, cur, name_len)?;
            let name = String::from_utf8(bytes[end - name_len..end].to_vec()).map_err(|_| {
                GraphusError::Storage("constraint catalog name is not valid UTF-8".to_owned())
            })?;
            if name.is_empty() {
                return Err(GraphusError::Storage(
                    "constraint catalog holds an empty constraint name".to_owned(),
                ));
            }
            let label_token = read_u32(bytes, cur)?;
            let n_props = read_u32(bytes, cur)? as usize;
            if n_props == 0 {
                return Err(GraphusError::Storage(format!(
                    "constraint {name:?} covers no properties"
                )));
            }
            // Cap by the bytes remaining (see the full-text decoder above): `n_props` is an untrusted
            // u32 and each property is a 4-byte read, so capacity never legitimately exceeds
            // `bytes.len()`. Prevents an OOM from a forged count before the per-element reads validate.
            let mut property_tokens = Vec::with_capacity(n_props.min(bytes.len()));
            for _ in 0..n_props {
                property_tokens.push(read_u32(bytes, cur)?);
            }
            let kind_byte = read_u8(bytes, cur)?;
            let kind = ConstraintKind::from_byte(kind_byte).ok_or_else(|| {
                GraphusError::Storage(format!(
                    "constraint {name:?} holds unknown kind byte {kind_byte}"
                ))
            })?;
            if map
                .insert(
                    name.clone(),
                    ConstraintEntry {
                        label_token,
                        property_tokens,
                        kind,
                        // The descriptor (if any) is merged in by `decode_constraint_type_block`.
                        type_descriptor: None,
                    },
                )
                .is_some()
            {
                return Err(GraphusError::Storage(format!(
                    "constraint catalog repeats constraint name {name:?}"
                )));
            }
        }
        Ok(map)
    }

    /// Decodes the trailing constraint **type-descriptor** block (`rmp` task #100) and merges each
    /// descriptor onto its named constraint in `constraints`. Like every later block, end-of-input
    /// where its count `u32` would start means "no descriptor block" (a pre-#100 image), not
    /// truncation — leaving every entry's `type_descriptor` as the `None` the catalog decode set.
    ///
    /// # Errors
    /// Returns a storage error on truncation, a repeated/empty name, a name with no matching
    /// constraint, or an unknown descriptor tag byte (none is ever produced by [`encode`](Self::encode)).
    fn decode_constraint_type_block(
        bytes: &[u8],
        cur: &mut usize,
        constraints: &mut BTreeMap<String, ConstraintEntry>,
    ) -> Result<()> {
        // Backward compatibility (`rmp` task #100): a pre-#100 image ends exactly here.
        if *cur == bytes.len() {
            return Ok(());
        }
        let n = read_u32(bytes, cur)? as usize;
        let mut seen: BTreeMap<String, ()> = BTreeMap::new();
        for _ in 0..n {
            let name_len = read_u32(bytes, cur)? as usize;
            let end = take(bytes, cur, name_len)?;
            let name = String::from_utf8(bytes[end - name_len..end].to_vec()).map_err(|_| {
                GraphusError::Storage(
                    "constraint type-descriptor name is not valid UTF-8".to_owned(),
                )
            })?;
            if name.is_empty() {
                return Err(GraphusError::Storage(
                    "constraint type-descriptor block holds an empty constraint name".to_owned(),
                ));
            }
            let descriptor = ConstraintTypeDescriptor::decode(bytes, cur)?;
            if seen.insert(name.clone(), ()).is_some() {
                return Err(GraphusError::Storage(format!(
                    "constraint type-descriptor block repeats constraint name {name:?}"
                )));
            }
            match constraints.get_mut(&name) {
                Some(entry) => entry.type_descriptor = Some(descriptor),
                None => {
                    return Err(GraphusError::Storage(format!(
                        "constraint type-descriptor block names unknown constraint {name:?}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Decodes the trailing node-property index **name** catalog block (`rmp` task #623). Like every
    /// later block, end-of-input where its count `u32` would start means "no name catalog" (a pre-#623
    /// image), not truncation — leaving every declared index nameless (backfilled on open).
    ///
    /// # Errors
    /// Returns a storage error on truncation, a repeated / empty / non-UTF-8 name, a repeated
    /// `(label, property)` **target** (an index has at most one name), or a name whose target is **not**
    /// a declared node-property index (an orphan name — never produced by [`encode`](Self::encode),
    /// which only ever records a name alongside a declared index).
    fn decode_index_name_catalog(
        bytes: &[u8],
        cur: &mut usize,
        node_property_indexes: &BTreeMap<(u32, u32), IndexState>,
    ) -> Result<BTreeMap<String, (u32, u32)>> {
        let mut map = BTreeMap::new();
        // Backward compatibility (`rmp` task #623): a pre-#623 image ends exactly here.
        if *cur == bytes.len() {
            return Ok(map);
        }
        let n = read_u32(bytes, cur)? as usize;
        // Track targets so two names cannot claim the same index.
        let mut seen_targets: BTreeMap<(u32, u32), ()> = BTreeMap::new();
        for _ in 0..n {
            let name_len = read_u32(bytes, cur)? as usize;
            let end = take(bytes, cur, name_len)?;
            let name = String::from_utf8(bytes[end - name_len..end].to_vec()).map_err(|_| {
                GraphusError::Storage("index-name catalog name is not valid UTF-8".to_owned())
            })?;
            if name.is_empty() {
                return Err(GraphusError::Storage(
                    "index-name catalog holds an empty index name".to_owned(),
                ));
            }
            let label_token = read_u32(bytes, cur)?;
            let prop_token = read_u32(bytes, cur)?;
            if !node_property_indexes.contains_key(&(label_token, prop_token)) {
                return Err(GraphusError::Storage(format!(
                    "index-name catalog names {name:?} for ({label_token}, {prop_token}), which is \
                     not a declared node-property index"
                )));
            }
            if seen_targets.insert((label_token, prop_token), ()).is_some() {
                return Err(GraphusError::Storage(format!(
                    "index-name catalog gives a second name {name:?} to ({label_token}, {prop_token})"
                )));
            }
            if map
                .insert(name.clone(), (label_token, prop_token))
                .is_some()
            {
                return Err(GraphusError::Storage(format!(
                    "index-name catalog repeats index name {name:?}"
                )));
            }
        }
        Ok(map)
    }
}

/// Durable per-store catalog: id high-water mark, free list, and the device-page map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StoreMeta {
    /// Physical-id high-water mark — one past the largest id ever allocated (`04 §2.2`).
    pub high_water: u64,
    /// Stack of freed physical ids available for reuse (`04 §2.7`).
    pub free_list: FreeList,
    /// `device_pages[i]` is the device `PageId` holding this store's store-relative page `i`.
    pub device_pages: Vec<u64>,
}

impl Meta {
    /// A fresh catalog with the given `ElementId` seed, empty stores and tokens.
    #[must_use]
    pub fn new(element_id_seed: u128) -> Self {
        Self {
            format_version: graphus_core::constants::FORMAT_VERSION,
            element_id_next: element_id_seed,
            commit_ts_hw: 0,
            stores: Default::default(),
            tokens: TokenStore::new(),
            statistics: Statistics::new(),
        }
    }

    /// Serialises the catalog into a flat byte buffer.
    ///
    /// The buffer is persisted by [`RecordStore::checkpoint_meta`](crate::RecordStore) across a
    /// singly-linked **chain** of metadata pages rooted at the metadata page (`rmp` task #51), so
    /// the catalog is no longer bounded by a single page payload — a store can grow to many
    /// thousands of record pages (whose device-page maps dominate this buffer) without overflow.
    ///
    /// # Errors
    /// Currently infallible; returns [`Result`] for symmetry with [`decode`](Self::decode) and to
    /// keep the signature stable if a future encoding step can fail.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.element_id_next.to_le_bytes());
        out.extend_from_slice(&self.commit_ts_hw.to_le_bytes());
        // The FOUR version-1 stores keep their historic position and layout, so a version-1 image and
        // the version-1 prefix of a version-2 image are byte-identical up to the statistics block.
        // The undo area's two stores are appended in the trailing block below.
        for s in &self.stores[..LEGACY_STORE_COUNT] {
            Self::encode_store(&mut out, s);
        }
        let tok = self.tokens.encode();
        out.extend_from_slice(&(tok.len() as u32).to_le_bytes());
        out.extend_from_slice(&tok);
        // Statistics are appended after the tokens (`rmp` task #79). Length-prefixed like the token
        // image so a future field can follow without ambiguity.
        let stats = self.statistics.encode();
        out.extend_from_slice(&(stats.len() as u32).to_le_bytes());
        out.extend_from_slice(&stats);
        // ---- The undo-area block (`rmp` #966, `05 §12.6`): format version 2 and up. ----
        //
        // Its LAYOUT has not changed since #966; version 3 (`rmp` #967) reuses it byte for byte and
        // only writes a different number into the version field, because what #967 changed is what a
        // property cell MEANS, not where anything sits. That is why the block needs no versioned
        // parsing here: every version from 2 up decodes identically.
        //
        // Appended after every prior block by this catalog's established append-only rule, so a
        // version-1 image simply ENDS where this block would start and `decode` reports version 1
        // with two empty undo-area stores. The block leads with a magic word rather than a bare
        // version number so the decoder can tell "no block" from "a block it must parse" without
        // relying on the payload length alone — a bare trailing `u32` would be indistinguishable
        // from a truncated or garbage tail.
        out.extend_from_slice(&UNDO_AREA_MAGIC.to_le_bytes());
        out.extend_from_slice(&self.format_version.to_le_bytes());
        for s in &self.stores[LEGACY_STORE_COUNT..] {
            Self::encode_store(&mut out, s);
        }
        Ok(out)
    }

    /// Encodes one store's durable catalog entry: high-water, length-prefixed free list, then the
    /// length-prefixed device-page map. Byte-identical to the inline encoding it replaces.
    fn encode_store(out: &mut Vec<u8>, s: &StoreMeta) {
        out.extend_from_slice(&s.high_water.to_le_bytes());
        let fl = s.free_list.encode();
        out.extend_from_slice(&(fl.len() as u32).to_le_bytes());
        out.extend_from_slice(&fl);
        out.extend_from_slice(&(s.device_pages.len() as u32).to_le_bytes());
        for &p in &s.device_pages {
            out.extend_from_slice(&p.to_le_bytes());
        }
    }

    /// Rebuilds a catalog from a metadata payload produced by [`encode`](Self::encode).
    ///
    /// # Errors
    /// Returns a storage error if the payload is truncated or malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cur = 0usize;
        let element_id_next = read_u128(bytes, &mut cur)?;
        let commit_ts_hw = read_u64(bytes, &mut cur)?;
        let mut stores: [StoreMeta; STORE_COUNT] = Default::default();
        for (idx, s) in stores.iter_mut().enumerate().take(LEGACY_STORE_COUNT) {
            *s = Self::decode_store(bytes, &mut cur, idx)?;
        }
        let tok_len = read_u32(bytes, &mut cur)? as usize;
        let tok_end = take(bytes, &mut cur, tok_len)?;
        let tokens = TokenStore::decode(&bytes[cur - tok_len..tok_end])?;
        // Statistics follow the tokens (`rmp` task #79).
        let stats_len = read_u32(bytes, &mut cur)? as usize;
        let stats_end = take(bytes, &mut cur, stats_len)?;
        let statistics = Statistics::decode(&bytes[cur - stats_len..stats_end])?;
        // ---- The trailing undo-area block (`rmp` #966, `05 §12.6`). ----
        //
        // Absent ⇒ a **version-1** image: no undo area, every `undo_ptr` in the store is `0`, and the
        // two undo-area stores stay at their `Default` (empty, high-water 0) value. That is a valid,
        // chain-free image, so opening it is an upgrade and not a conversion — the first checkpoint
        // this build takes rewrites the catalog with the block present.
        //
        // Present ⇒ read the version and REFUSE anything this build does not understand, rather than
        // interpreting a layout it has never seen (`05 §12.6`: "opening a store of a newer version
        // under an older build must be refused rather than misread" — the same rule, applied
        // forwards).
        let format_version = if cur >= bytes.len() {
            LEGACY_FORMAT_VERSION
        } else {
            let magic = read_u64(bytes, &mut cur)?;
            if magic != UNDO_AREA_MAGIC {
                return Err(GraphusError::Storage(format!(
                    "metadata undo-area block has a bad magic ({magic:#018x}, expected \
                     {UNDO_AREA_MAGIC:#018x})"
                )));
            }
            let version = read_u32(bytes, &mut cur)?;
            if version <= LEGACY_FORMAT_VERSION || version > graphus_core::constants::FORMAT_VERSION
            {
                return Err(GraphusError::Storage(format!(
                    "store on-disk format version {version} is not readable by this build (which \
                     supports up to version {}); a store written by a newer build must be opened by \
                     that build",
                    graphus_core::constants::FORMAT_VERSION
                )));
            }
            for (idx, s) in stores.iter_mut().enumerate().skip(LEGACY_STORE_COUNT) {
                *s = Self::decode_store(bytes, &mut cur, idx)?;
            }
            version
        };
        Ok(Self {
            format_version,
            element_id_next,
            commit_ts_hw,
            stores,
            tokens,
            statistics,
        })
    }

    /// Decodes one store's durable catalog entry (`idx` is its [`StoreKind`](crate::store::StoreKind)
    /// discriminant, used both for the record-size bound below and for the error message).
    ///
    /// # Errors
    /// Returns a storage error if the entry is truncated, its free list is malformed, or its
    /// high-water mark exceeds the capacity its device-page map addresses.
    fn decode_store(bytes: &[u8], cur: &mut usize, idx: usize) -> Result<StoreMeta> {
        let mut s = StoreMeta {
            high_water: read_u64(bytes, cur)?,
            ..StoreMeta::default()
        };
        {
            let fl_len = read_u32(bytes, cur)? as usize;
            let fl_end = take(bytes, cur, fl_len)?;
            s.free_list = FreeList::decode(&bytes[*cur - fl_len..fl_end])?;
            let n_pages = read_u32(bytes, cur)? as usize;
            // Cap by the bytes remaining: each device-page entry is an 8-byte `read_u64`, so the real
            // count cannot exceed `bytes.len()`. Without the cap a forged `n_pages = 0xFFFF_FFFF`
            // forces a multi-GiB allocation (OOM) before the per-element reads validate the input.
            s.device_pages = Vec::with_capacity(n_pages.min(bytes.len()));
            for _ in 0..n_pages {
                s.device_pages.push(read_u64(bytes, cur)?);
            }
            // Fail closed on an out-of-range high-water mark (`rmp` #452). `high_water` is one past the
            // largest physical id ever allocated; real ids start at `1` (id `0` is the reserved null), so
            // a never-used store legitimately carries `high_water == 1` with ZERO mapped pages (the next
            // id it would hand out is `1`). Record `id` lives at store-relative page `id / rpp`, so id `i`
            // is addressable iff `i < device_pages.len() * rpp` (= `capacity`). The largest id ever
            // allocated is `high_water - 1`; when at least one real id has been allocated
            // (`high_water >= 2`) that id must be addressable, i.e. `high_water - 1 < capacity`, i.e.
            // `high_water <= capacity`. Folding in the `high_water <= 1` empty-store case yields the exact
            // bound: reject iff `high_water > capacity.max(1)`. (Verified empirically: a recovered catalog
            // floors every untouched store to `high_water == 1` / `0` pages — see
            // `recovered_txn_hw_resumes_past_every_durable_id` — and the off-by-one-page corruption
            // `high_water == capacity + 1` is still caught because a real allocation past a page boundary
            // maps the new page in the same catalog commit.)
            //
            // Without this bound a corrupt-but-CRC-valid catalog page (a mis-replayed WAL frame onto the
            // metadata page, a storage fault later flushed home, or raw file-write access) could seed the
            // id allocator at `u64::MAX`; the next `alloc_fresh` does `+= 1`, and because the release
            // profile leaves `overflow-checks` off, the second allocation WRAPS to `0` and hands out the
            // reserved NULL id (id `0` aliases every "none" pointer — `first_rel`/`first_prop`/`next_prop`)
            // as a live record id, violating the inviolable ACID/identity guarantee. (`element_id_next`
            // has no page-based ceiling — it is a never-reused 128-bit identity, not a slot index — so its
            // corruption blast radius is bounded downstream by the `checked_add` in
            // `ElementIdAllocator::alloc`.)
            let record_size = match idx {
                0 => crate::record::NODE_RECORD_SIZE,
                1 => crate::record::REL_RECORD_SIZE,
                2 => crate::record::PROP_RECORD_SIZE,
                // The fourth catalog store is the `strings.store` overflow heap (`04 §2.1`).
                3 => crate::heap::STRINGS_RECORD_SIZE,
                // The undo area's two stores (`05 §12.1`), present from format version 2.
                4 => crate::undo::UNDO_RECORD_SIZE,
                _ => crate::undo::COMMIT_RECORD_SIZE,
            };
            // `records_per_page` is a non-zero, page-bounded constant for every real store, so the only
            // overflow risk is the `n_pages * rpp` product; `saturating_mul` keeps the ceiling sound (a
            // saturated `u64::MAX` can only ever *accept*, and a forged page count is already rejected by
            // the bounded read loop above, so this never masks a forged `high_water`).
            let rpp = crate::paging::records_per_page(record_size) as u64;
            let capacity = (s.device_pages.len() as u64).saturating_mul(rpp);
            if s.high_water > capacity.max(1) {
                return Err(GraphusError::Storage(format!(
                    "metadata high_water {} for store {} exceeds addressable capacity {} \
                     ({} pages x {} records/page)",
                    s.high_water,
                    idx,
                    capacity,
                    s.device_pages.len(),
                    rpp
                )));
            }
        }
        Ok(s)
    }
}

fn take(bytes: &[u8], cur: &mut usize, len: usize) -> Result<usize> {
    let end = cur
        .checked_add(len)
        .filter(|&e| e <= bytes.len())
        .ok_or_else(|| GraphusError::Storage("metadata truncated".to_owned()))?;
    *cur = end;
    Ok(end)
}

fn read_u8(b: &[u8], cur: &mut usize) -> Result<u8> {
    let end = take(b, cur, 1)?;
    Ok(b[end - 1])
}

fn read_u32(b: &[u8], cur: &mut usize) -> Result<u32> {
    let end = take(b, cur, 4)?;
    Ok(u32::from_le_bytes(b[end - 4..end].try_into().expect("4")))
}

fn read_u64(b: &[u8], cur: &mut usize) -> Result<u64> {
    let end = take(b, cur, 8)?;
    Ok(u64::from_le_bytes(b[end - 8..end].try_into().expect("8")))
}

fn read_u128(b: &[u8], cur: &mut usize) -> Result<u128> {
    let end = take(b, cur, 16)?;
    Ok(u128::from_le_bytes(
        b[end - 16..end].try_into().expect("16"),
    ))
}

/// Unit-test conveniences: the `±1` spellings the write path used to call directly.
///
/// They are `#[cfg(test)]` **on purpose**. Since `rmp` #866 the production write path must move a
/// counter only through `RecordStore::count_bump`, which applies the change *and* records it in the
/// owning transaction's pending delta; a counter moved by any other route would be un-withdrawable
/// and would drift the catalog permanently. Keeping these out of the release build makes that a
/// property of the code rather than of a convention: [`Statistics::apply_count_delta`] is the only
/// count mutator a non-test caller can reach.
#[cfg(test)]
impl Statistics {
    pub(crate) fn inc_node(&mut self) {
        self.apply_count_delta(CountKey::TotalNodes, 1);
    }

    pub(crate) fn dec_node(&mut self) {
        self.apply_count_delta(CountKey::TotalNodes, -1);
    }

    pub(crate) fn inc_rel(&mut self) {
        self.apply_count_delta(CountKey::TotalRelationships, 1);
    }

    pub(crate) fn inc_label(&mut self, token_id: u32) {
        self.apply_count_delta(CountKey::Label(token_id), 1);
    }

    pub(crate) fn dec_label(&mut self, token_id: u32) {
        self.apply_count_delta(CountKey::Label(token_id), -1);
    }

    pub(crate) fn inc_rel_type(&mut self, token_id: u32) {
        self.apply_count_delta(CountKey::RelType(token_id), 1);
    }

    pub(crate) fn dec_rel_type(&mut self, token_id: u32) {
        self.apply_count_delta(CountKey::RelType(token_id), -1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paging::PAGE_PAYLOAD;
    use crate::tokens::Namespace;

    #[test]
    fn empty_meta_round_trips() {
        let m = Meta::new(1);
        let back = Meta::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(back, m);
    }

    /// Regression (storage audit, finding 3 / SEV 3): a forged full-text catalog whose `n_props`
    /// field is a huge untrusted u32 must not drive a multi-gigabyte pre-allocation (OOM). The
    /// decoder caps `Vec::with_capacity` at the input length and then fails fast when the (absent)
    /// per-property reads run. It must return an error, not abort on an allocation.
    #[test]
    fn decode_fulltext_catalog_with_forged_n_props_does_not_oom() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 index entry
        let name = b"idx";
        bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(&7u32.to_le_bytes()); // label_token
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // forged n_props = u32::MAX
        // No property-token bytes follow: the first per-property read is truncated.
        let mut cur = 0usize;
        assert!(Statistics::decode_fulltext_catalog(&bytes, &mut cur).is_err());
    }

    /// Regression (`rmp` #663 storage audit, residual LOW): a forged full-text **extension** block whose
    /// `n_extra` field is a huge untrusted u32 must not drive a multi-gigabyte pre-allocation. The
    /// decoder caps `Vec::with_capacity` at the input length and then fails fast when the (absent)
    /// per-token reads run — returning an error, not aborting on an allocation.
    #[test]
    fn decode_fulltext_extension_block_with_forged_n_extra_does_not_oom() {
        // A base full-text catalog with one entry "idx" (so the extension names an existing index and
        // gets past the orphan check to reach the `n_extra` allocation), then an extension entry with a
        // forged `n_extra = u32::MAX` and no token bytes.
        let mut base = Statistics::new();
        base.set_fulltext_index(
            "idx".to_owned(),
            FulltextIndexEntry {
                entity: FulltextEntity::Node,
                tokens: vec![7],
                property_tokens: vec![9],
                analyzer: 0,
                state: IndexState::Online,
            },
        );
        // Decode the base catalog to obtain the map the extension patches.
        let mut fulltext = {
            let mut image = Vec::new();
            Statistics::encode_fulltext_catalog(&mut image, &base.fulltext_indexes);
            let mut cur = 0usize;
            Statistics::decode_fulltext_catalog(&image, &mut cur).unwrap()
        };
        // A forged extension block: 1 entry naming "idx", entity Node, n_extra = u32::MAX, no tokens.
        let mut ext = Vec::new();
        ext.extend_from_slice(&1u32.to_le_bytes()); // 1 extension entry
        ext.extend_from_slice(&3u32.to_le_bytes()); // name_len 3
        ext.extend_from_slice(b"idx");
        ext.push(FulltextEntity::Node.as_byte());
        ext.extend_from_slice(&u32::MAX.to_le_bytes()); // forged n_extra
        let mut cur = 0usize;
        assert!(
            Statistics::decode_fulltext_extension_block(&ext, &mut cur, &mut fulltext).is_err()
        );
    }

    /// Regression (storage audit, finding 3 / SEV 3): same OOM guard for the constraint catalog.
    #[test]
    fn decode_constraint_catalog_with_forged_n_props_does_not_oom() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 constraint entry
        let name = b"c1";
        bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(&3u32.to_le_bytes()); // label_token
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // forged n_props = u32::MAX
        let mut cur = 0usize;
        assert!(Statistics::decode_constraint_catalog(&bytes, &mut cur).is_err());
    }

    /// Regression (storage audit, finding 3 / SEV 3): a forged `Meta` image whose per-store
    /// `device_pages` count is a huge untrusted u32 must not OOM on the `Vec::with_capacity`. We
    /// craft the minimal prefix `Meta::decode` reads up to the first store's `n_pages`, set it to
    /// `u32::MAX`, and supply no page bytes; the decode must error, not abort.
    #[test]
    fn decode_meta_with_forged_device_pages_count_does_not_oom() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u128.to_le_bytes()); // element_id_next
        bytes.extend_from_slice(&0u64.to_le_bytes()); // commit_ts_hw
        // First store: high_water(u64), free_list len(u32)+bytes, then n_pages(u32).
        bytes.extend_from_slice(&0u64.to_le_bytes()); // high_water
        // A minimal valid free-list image is a 4-byte count word of 0 (an empty free list).
        bytes.extend_from_slice(&4u32.to_le_bytes()); // free_list byte length = 4
        bytes.extend_from_slice(&0u32.to_le_bytes()); // free-list count = 0
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // forged n_pages = u32::MAX
        // No device-page bytes follow.
        assert!(Meta::decode(&bytes).is_err());
    }

    /// Regression (`rmp` #452): a corrupt-but-otherwise-well-formed catalog whose Node `high_water`
    /// is forged to `u64::MAX` must be REJECTED by `Meta::decode`, not restored. Without the bound the
    /// allocator is seeded at `u64::MAX`; the second `alloc_fresh` wraps (release: `overflow-checks`
    /// off) to `0` and hands out the reserved NULL id as a live record id — an ACID/identity
    /// violation. We build a valid populated image, splice `u64::MAX` over the first store's (Node's)
    /// `high_water` field at its exact byte offset, and assert the decode fails closed.
    #[test]
    fn decode_rejects_node_high_water_forged_to_u64_max() {
        // A well-formed catalog whose real Node high_water (9) is in range for its 3 mapped pages
        // (3 * 125 records/page = 375 >= 9), so the only thing that makes the forged image illegal is
        // the spliced `high_water`.
        let mut m = Meta::new(1);
        m.stores[0].high_water = 9;
        m.stores[0].device_pages = vec![1, 4, 9];
        let mut bytes = m.encode().unwrap();
        // Encode layout (see `Meta::encode`): element_id_next(16) | commit_ts_hw(8) | then store 0
        // begins with its `high_water` (u64). So Node's high_water occupies bytes [24, 32).
        const NODE_HIGH_WATER_OFFSET: usize = 16 + 8;
        bytes[NODE_HIGH_WATER_OFFSET..NODE_HIGH_WATER_OFFSET + 8]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        // Sanity: the splice landed on the field we think it did — the unforged image decodes, and the
        // forged one differs only in that field.
        let err = Meta::decode(&bytes);
        assert!(
            err.is_err(),
            "Meta::decode must reject a Node high_water of u64::MAX (3 pages cap 375), not restore it \
             and let the id allocator wrap to the reserved NULL id"
        );
        match err {
            Err(GraphusError::Storage(msg)) => assert!(
                msg.contains("high_water") && msg.contains("capacity"),
                "error must name the out-of-range high_water bound, got: {msg}"
            ),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    /// Regression (`rmp` #452): the high-water bound's exact boundaries. `high_water` is one-past the
    /// largest id ever allocated and real ids start at `1`, so:
    ///   * `high_water == 1` with ZERO pages is the legitimate empty/untouched-store state (the next id
    ///     it would hand out is `1`) and MUST be accepted — a recovered catalog floors every untouched
    ///     store to exactly this (see `store::recovered_txn_hw_resumes_past_every_durable_id`);
    ///   * any `high_water >= 2` with ZERO pages is unaddressable (the claimed live id has no slot) and
    ///     MUST be rejected;
    ///   * `high_water == capacity` is the full-store boundary (largest live id `capacity - 1` is on the
    ///     last mapped page) and MUST be accepted;
    ///   * `high_water == capacity + 1` is the off-by-one-page corruption (the largest claimed id needs
    ///     a page that is not mapped) and MUST be rejected.
    ///
    /// One Rel page (store 1) maps `8168 / 102 = 80` records.
    #[test]
    fn decode_high_water_bound_boundaries() {
        // Empty store: high_water == 1, no pages → accepted (the fresh/recovered empty state).
        let mut empty = Meta::new(1);
        empty.stores[1].high_water = 1;
        empty.stores[1].device_pages = Vec::new();
        assert!(
            Meta::decode(&empty.encode().unwrap()).is_ok(),
            "high_water == 1 with no pages is the legitimate empty store and must be accepted"
        );

        // A claimed live id (high_water == 2) with no page to hold it → rejected.
        let mut unbacked = Meta::new(1);
        unbacked.stores[1].high_water = 2;
        unbacked.stores[1].device_pages = Vec::new();
        assert!(
            Meta::decode(&unbacked.encode().unwrap()).is_err(),
            "high_water >= 2 with no mapped pages (capacity 0) must be rejected"
        );

        // Full-store boundary: high_water == capacity (80) for one Rel page → accepted.
        let mut full = Meta::new(1);
        full.stores[1].high_water = 80;
        full.stores[1].device_pages = vec![1];
        assert!(
            Meta::decode(&full.encode().unwrap()).is_ok(),
            "high_water == capacity (80 for one Rel page) must be accepted"
        );

        // One past capacity (the off-by-one-page corruption) → rejected.
        let mut over = Meta::new(1);
        over.stores[1].high_water = 81;
        over.stores[1].device_pages = vec![1];
        assert!(
            Meta::decode(&over.encode().unwrap()).is_err(),
            "high_water one past capacity (81 for one Rel page) must be rejected"
        );
    }

    #[test]
    fn populated_meta_round_trips() {
        let mut m = Meta::new(0x1234_5678_9ABC);
        m.stores[0].high_water = 9;
        m.stores[0].free_list.push(3);
        m.stores[0].free_list.push(7);
        m.stores[0].device_pages = vec![1, 4, 9];
        m.stores[1].high_water = 2;
        m.stores[1].device_pages = vec![2];
        m.stores[2].device_pages = vec![3, 5];
        // The strings.store overflow heap (`rmp` task #43) is the fourth catalog store.
        m.stores[3].high_water = 4;
        m.stores[3].free_list.push(2);
        m.stores[3].device_pages = vec![6, 7];
        m.tokens.intern(Namespace::Label, "Person").unwrap();
        m.tokens.intern(Namespace::RelType, "KNOWS").unwrap();
        // Populate the statistics catalog too (`rmp` task #79) so its round-trip is exercised here.
        m.statistics.inc_label(0); // Person: 2 live nodes
        m.statistics.inc_label(0);
        m.statistics.inc_label(5); // another label token: 1 live node
        m.statistics.inc_rel_type(0); // KNOWS: 3 live rels
        m.statistics.inc_rel_type(0);
        m.statistics.inc_rel_type(0);
        // Grand totals (`rmp` task #82): the node total is independent of the per-label sum (a node
        // may carry several labels or none), and the relationship total is independent of the
        // per-type sum, so populate both explicitly.
        m.statistics.inc_node(); // 4 live nodes total (incl. unlabelled ones)
        m.statistics.inc_node();
        m.statistics.inc_node();
        m.statistics.inc_node();
        m.statistics.inc_rel(); // 3 live rels total
        m.statistics.inc_rel();
        m.statistics.inc_rel();
        // Populate the property-histogram catalog too (`rmp` task #81) so its round-trip is exercised
        // here alongside the counts.
        m.statistics.set_property_histogram(0, 1, vec![1, 2, 3, 4]); // (Person, prop 1)
        m.statistics.set_property_histogram(5, 9, vec![0xAB]); // (label 5, prop 9)
        // Populate the node-property index catalog too (`rmp` task #90), with both states, so its
        // round-trip is exercised here alongside the histograms and counts.
        m.statistics
            .set_node_property_index(0, 1, IndexState::Online); // (Person, prop 1): Online
        m.statistics
            .set_node_property_index(5, 9, IndexState::Populating); // (label 5, prop 9): Populating
        // Populate the spatial index catalog too (`rmp` task #98), with both states, so its
        // round-trip is exercised here alongside the other catalogs.
        m.statistics.set_spatial_index(
            "by_loc".to_owned(),
            SpatialIndexEntry {
                entity: SpatialEntity::Node,
                label_token: 0,
                property_token: 3,
                state: IndexState::Online,
            },
        );
        m.statistics.set_spatial_index(
            "by_home".to_owned(),
            SpatialIndexEntry {
                entity: SpatialEntity::Node,
                label_token: 5,
                property_token: 7,
                state: IndexState::Populating,
            },
        );
        // Populate the constraint catalog too (`rmp` task #99), with both kinds, so its round-trip is
        // exercised here alongside the other catalogs.
        m.statistics.set_constraint(
            "person_email_unique".to_owned(),
            ConstraintEntry {
                label_token: 0,
                property_tokens: vec![1],
                kind: ConstraintKind::Unique,
                type_descriptor: None,
            },
        );
        m.statistics.set_constraint(
            "person_name_exists".to_owned(),
            ConstraintEntry {
                label_token: 0,
                property_tokens: vec![2],
                kind: ConstraintKind::Existence,
                type_descriptor: None,
            },
        );
        // A composite node-key and a typed property-type constraint (`rmp` task #100) round-trip too,
        // exercising the multi-property `Vec` and the trailing type-descriptor block.
        m.statistics.set_constraint(
            "person_id_key".to_owned(),
            ConstraintEntry {
                label_token: 0,
                property_tokens: vec![1, 2],
                kind: ConstraintKind::NodeKey,
                type_descriptor: None,
            },
        );
        m.statistics.set_constraint(
            "person_age_int".to_owned(),
            ConstraintEntry {
                label_token: 0,
                property_tokens: vec![2],
                kind: ConstraintKind::PropertyType,
                type_descriptor: Some(ConstraintTypeDescriptor::List(Box::new(
                    ConstraintTypeDescriptor::Integer,
                ))),
            },
        );
        // Relationship constraints (`rmp` #638) round-trip through the same catalog: the covering token
        // is a relationship-type token, and the `Rel*` kinds use the reserved discriminants 4..=7. A
        // relationship key (composite) + a relationship property-type (typed) exercise both the
        // multi-property `Vec` and the trailing type-descriptor block for the relationship kinds.
        m.statistics.set_constraint(
            "rated_key".to_owned(),
            ConstraintEntry {
                label_token: 0,
                property_tokens: vec![1, 2],
                kind: ConstraintKind::RelKey,
                type_descriptor: None,
            },
        );
        m.statistics.set_constraint(
            "weighs_typed".to_owned(),
            ConstraintEntry {
                label_token: 0,
                property_tokens: vec![1],
                kind: ConstraintKind::RelPropertyType,
                type_descriptor: Some(ConstraintTypeDescriptor::Integer),
            },
        );

        let back = Meta::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.tokens.id(Namespace::Label, "Person"), Some(0));
        assert_eq!(back.statistics.node_count_for_label(0), 2);
        assert_eq!(back.statistics.node_count_for_label(5), 1);
        assert_eq!(back.statistics.rel_count_for_type(0), 3);
        assert_eq!(back.statistics.total_nodes(), 4);
        assert_eq!(back.statistics.total_relationships(), 3);
        assert_eq!(
            back.statistics.property_histogram(0, 1),
            Some(&[1, 2, 3, 4][..])
        );
        assert_eq!(back.statistics.property_histogram(5, 9), Some(&[0xAB][..]));
        assert_eq!(back.statistics.property_histogram(0, 9), None);
        assert_eq!(
            back.statistics.node_property_index_state(0, 1),
            Some(IndexState::Online)
        );
        assert_eq!(
            back.statistics.node_property_index_state(5, 9),
            Some(IndexState::Populating)
        );
        assert_eq!(back.statistics.node_property_index_state(0, 9), None);
        // Spatial index catalog (`rmp` task #98) round-trips alongside the other catalogs.
        assert_eq!(
            back.statistics.spatial_index("by_loc"),
            Some(&SpatialIndexEntry {
                entity: SpatialEntity::Node,
                label_token: 0,
                property_token: 3,
                state: IndexState::Online,
            })
        );
        assert_eq!(
            back.statistics.spatial_index("by_home"),
            Some(&SpatialIndexEntry {
                entity: SpatialEntity::Node,
                label_token: 5,
                property_token: 7,
                state: IndexState::Populating,
            })
        );
        assert_eq!(back.statistics.spatial_index("nope"), None);
        // Constraint catalog (`rmp` task #99) round-trips alongside the other catalogs.
        assert_eq!(
            back.statistics.constraint("person_email_unique"),
            Some(&ConstraintEntry {
                label_token: 0,
                property_tokens: vec![1],
                kind: ConstraintKind::Unique,
                type_descriptor: None,
            })
        );
        assert_eq!(
            back.statistics.constraint("person_name_exists"),
            Some(&ConstraintEntry {
                label_token: 0,
                property_tokens: vec![2],
                kind: ConstraintKind::Existence,
                type_descriptor: None,
            })
        );
        // The composite node-key keeps its whole property tuple; the property-type keeps its descriptor.
        assert_eq!(
            back.statistics.constraint("person_id_key"),
            Some(&ConstraintEntry {
                label_token: 0,
                property_tokens: vec![1, 2],
                kind: ConstraintKind::NodeKey,
                type_descriptor: None,
            })
        );
        assert_eq!(
            back.statistics.constraint("person_age_int"),
            Some(&ConstraintEntry {
                label_token: 0,
                property_tokens: vec![2],
                kind: ConstraintKind::PropertyType,
                type_descriptor: Some(ConstraintTypeDescriptor::List(Box::new(
                    ConstraintTypeDescriptor::Integer,
                ))),
            })
        );
        assert_eq!(back.statistics.constraint("nope"), None);
    }

    #[test]
    fn statistics_constraint_catalog_round_trips_and_pre_99_image_decodes_empty() {
        // Empty map: the constraint block is just a `0` count, and the round-trip is identity.
        let empty = Statistics::new();
        assert_eq!(Statistics::decode(&empty.encode()).unwrap(), empty);

        // One entry, then several entries (mixed kinds), keyed by name.
        let mut s = Statistics::new();
        s.set_constraint(
            "a".to_owned(),
            ConstraintEntry {
                label_token: 1,
                property_tokens: vec![2],
                kind: ConstraintKind::Unique,
                type_descriptor: None,
            },
        );
        assert_eq!(Statistics::decode(&s.encode()).unwrap(), s);
        s.set_constraint(
            "b".to_owned(),
            ConstraintEntry {
                label_token: 3,
                property_tokens: vec![4],
                kind: ConstraintKind::Existence,
                type_descriptor: None,
            },
        );
        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.constraints().len(), 2);

        // A pre-#99 image (a spatial-catalog-terminated image with NO constraint block) decodes to an
        // empty constraint catalog, not a truncation error. Build such an image by encoding a
        // statistics value that carries a spatial index, then truncating off BOTH trailing zero-count
        // blocks: the empty constraint catalog (`rmp` task #99) and the empty constraint type-descriptor
        // block (`rmp` task #100), each a 4-byte `u32` of `0` (8 bytes total).
        let mut pre99 = Statistics::new();
        pre99.set_spatial_index(
            "loc".to_owned(),
            SpatialIndexEntry {
                entity: SpatialEntity::Node,
                label_token: 1,
                property_token: 2,
                state: IndexState::Online,
            },
        );
        let mut image = pre99.encode();
        // The last 8 bytes are the empty-constraint-block count + the empty type-descriptor-block count
        // (`0u32` each); dropping them yields the exact byte image a pre-#99 build would have written.
        image.truncate(image.len() - 8);
        let decoded = Statistics::decode(&image).unwrap();
        assert!(decoded.constraints().is_empty());
        assert_eq!(decoded.spatial_indexes().len(), 1);
    }

    #[test]
    fn statistics_composite_catalog_round_trips_and_pre_657_image_decodes_empty() {
        // Empty map: the composite block is just a `0` count, and the round-trip is identity.
        let empty = Statistics::new();
        assert_eq!(Statistics::decode(&empty.encode()).unwrap(), empty);

        // One entry, then several (varying arity + order), keyed by name.
        let mut s = Statistics::new();
        s.set_composite_index(
            "index_Person_a_b".to_owned(),
            CompositeIndexEntry {
                label_token: 1,
                property_tokens: vec![2, 3],
                state: IndexState::Online,
            },
        );
        assert_eq!(Statistics::decode(&s.encode()).unwrap(), s);
        // Order is significant: (b, a) is a distinct entry from (a, b).
        s.set_composite_index(
            "index_Person_b_a".to_owned(),
            CompositeIndexEntry {
                label_token: 1,
                property_tokens: vec![3, 2],
                state: IndexState::Populating,
            },
        );
        s.set_composite_index(
            "index_Doc_x_y_z".to_owned(),
            CompositeIndexEntry {
                label_token: 9,
                property_tokens: vec![4, 5, 6],
                state: IndexState::Online,
            },
        );
        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.composite_indexes().len(), 3);
        // The equivalence resolver finds the exact ordered tuple, and distinguishes (a,b) from (b,a).
        assert_eq!(
            back.composite_index_name_for(1, &[2, 3]),
            Some("index_Person_a_b")
        );
        assert_eq!(
            back.composite_index_name_for(1, &[3, 2]),
            Some("index_Person_b_a")
        );
        assert_eq!(back.composite_index_name_for(1, &[2, 4]), None);

        // A pre-#657 image (a rel-property-name-catalog-terminated image with NO composite block)
        // decodes to an empty composite catalog, not a truncation error. Build such an image by encoding
        // a value with no composite indexes and truncating off the trailing zero-count composite block
        // (a 4-byte `u32` of `0`).
        let mut pre657 = Statistics::new();
        pre657.set_node_property_index(1, 2, IndexState::Online);
        let mut image = pre657.encode();
        image.truncate(image.len() - 4);
        let decoded = Statistics::decode(&image).unwrap();
        assert!(decoded.composite_indexes().is_empty());
        assert_eq!(decoded.node_property_indexes().len(), 1);
    }

    #[test]
    fn statistics_rel_composite_catalog_round_trips_and_pre_666_image_decodes_empty() {
        // `rmp` task #666: the composite RELATIONSHIP index catalog rides the same append-only trailing
        // block discipline as the node composite catalog. Empty map: the block is just a `0` count.
        let empty = Statistics::new();
        assert_eq!(Statistics::decode(&empty.encode()).unwrap(), empty);

        // One entry, then several (varying arity + order), keyed by name.
        let mut s = Statistics::new();
        s.set_rel_composite_index(
            "index_KNOWS_a_b".to_owned(),
            RelCompositeIndexEntry {
                type_token: 1,
                property_tokens: vec![2, 3],
                state: IndexState::Online,
            },
        );
        assert_eq!(Statistics::decode(&s.encode()).unwrap(), s);
        // Order is significant: (b, a) is a distinct entry from (a, b).
        s.set_rel_composite_index(
            "index_KNOWS_b_a".to_owned(),
            RelCompositeIndexEntry {
                type_token: 1,
                property_tokens: vec![3, 2],
                state: IndexState::Populating,
            },
        );
        s.set_rel_composite_index(
            "index_RATED_x_y_z".to_owned(),
            RelCompositeIndexEntry {
                type_token: 9,
                property_tokens: vec![4, 5, 6],
                state: IndexState::Online,
            },
        );
        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.rel_composite_indexes().len(), 3);
        // The equivalence resolver finds the exact ordered tuple, and distinguishes (a,b) from (b,a).
        assert_eq!(
            back.rel_composite_index_name_for(1, &[2, 3]),
            Some("index_KNOWS_a_b")
        );
        assert_eq!(
            back.rel_composite_index_name_for(1, &[3, 2]),
            Some("index_KNOWS_b_a")
        );
        assert_eq!(back.rel_composite_index_name_for(1, &[2, 4]), None);
        // A relationship-type token never conflates with a node composite over the same numeric token.
        let mut mixed = back.clone();
        mixed.set_composite_index(
            "index_KNOWS_a_b_node".to_owned(),
            CompositeIndexEntry {
                label_token: 1,
                property_tokens: vec![2, 3],
                state: IndexState::Online,
            },
        );
        let mixed_back = Statistics::decode(&mixed.encode()).unwrap();
        assert_eq!(mixed_back, mixed);
        assert_eq!(mixed_back.rel_composite_indexes().len(), 3);
        assert_eq!(mixed_back.composite_indexes().len(), 1);

        // A pre-#666 image (ending after the spatial extension block, with NO relationship composite
        // block) decodes to an empty relationship composite catalog, not a truncation error. Build such
        // an image by encoding a value with no relationship composite indexes and truncating off the two
        // trailing zero-count blocks (a 4-byte `u32` of `0` each): the relationship composite block and,
        // now that it exists, the vector block (`rmp` task #669) which is the LAST block.
        let mut pre666 = Statistics::new();
        pre666.set_composite_index(
            "index_Person_a_b".to_owned(),
            CompositeIndexEntry {
                label_token: 1,
                property_tokens: vec![2, 3],
                state: IndexState::Online,
            },
        );
        let mut image = pre666.encode();
        image.truncate(image.len() - 8);
        let decoded = Statistics::decode(&image).unwrap();
        assert!(decoded.rel_composite_indexes().is_empty());
        assert!(decoded.vector_indexes().is_empty());
        assert_eq!(decoded.composite_indexes().len(), 1);
    }

    #[test]
    fn statistics_vector_catalog_round_trips_and_pre_669_image_decodes_empty() {
        // `rmp` task #669: the vector (HNSW) index catalog rides the same append-only trailing-block
        // discipline as every other catalog, and is the LAST block. Empty map: the block is just a `0`
        // count, and the round-trip is identity.
        let empty = Statistics::new();
        assert_eq!(Statistics::decode(&empty.encode()).unwrap(), empty);

        // A node entry (cosine) and a relationship entry (euclidean) over the SAME numeric token: the
        // `entity` byte disambiguates them, so both survive and the equivalence resolver never conflates
        // a node label token with a relationship-type token.
        let mut s = Statistics::new();
        s.set_vector_index(
            "vector_index_Doc_embedding".to_owned(),
            VectorIndexEntry {
                entity: VectorEntity::Node,
                token: 1,
                property_token: 2,
                dimensions: 384,
                similarity: VectorSimilarity::Cosine,
                m: 16,
                ef_construction: 200,
                state: IndexState::Online,
            },
        );
        assert_eq!(Statistics::decode(&s.encode()).unwrap(), s);
        s.set_vector_index(
            "vector_rel_index_SIMILAR_vec".to_owned(),
            VectorIndexEntry {
                entity: VectorEntity::Relationship,
                token: 1,
                property_token: 2,
                dimensions: 3,
                similarity: VectorSimilarity::Euclidean,
                m: 32,
                ef_construction: 100,
                state: IndexState::Populating,
            },
        );
        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.vector_indexes().len(), 2);
        // The equivalence resolver keys on (entity, token, property): the node and rel entries over the
        // same (1, 2) are distinct.
        assert_eq!(
            back.vector_index_name_for(VectorEntity::Node, 1, 2),
            Some("vector_index_Doc_embedding")
        );
        assert_eq!(
            back.vector_index_name_for(VectorEntity::Relationship, 1, 2),
            Some("vector_rel_index_SIMILAR_vec")
        );
        assert_eq!(back.vector_index_name_for(VectorEntity::Node, 1, 9), None);

        // A pre-#669 image (ending after the relationship composite block, with NO vector block) decodes
        // to an empty vector catalog, not a truncation error. Build one by encoding a value with no
        // vector indexes and truncating off the trailing zero-count block (a 4-byte `u32` of `0`), which
        // is now the LAST block.
        let mut pre669 = Statistics::new();
        pre669.set_text_index(
            "text_Person_name".to_owned(),
            TextIndexEntry {
                label_token: 1,
                property_token: 2,
                state: IndexState::Online,
            },
        );
        let mut image = pre669.encode();
        image.truncate(image.len() - 4);
        let decoded = Statistics::decode(&image).unwrap();
        assert!(decoded.vector_indexes().is_empty());
        assert_eq!(decoded.text_indexes().len(), 1);

        // An unknown similarity byte (a forward-incompatible image) is rejected, not silently
        // mis-decoded — the same defense-in-depth as the state / entity bytes. Encode a single-entry
        // catalog (the vector block is last, so its lone entry trails the whole image) and corrupt its
        // similarity byte.
        let mut one = Statistics::new();
        one.set_vector_index(
            "v".to_owned(),
            VectorIndexEntry {
                entity: VectorEntity::Node,
                token: 7,
                property_token: 8,
                dimensions: 4,
                similarity: VectorSimilarity::Cosine,
                m: 16,
                ef_construction: 200,
                state: IndexState::Online,
            },
        );
        let mut forged = one.encode();
        // The lone vector entry ends as: … | similarity(1) | m(4) | ef_construction(4) | state(1), so
        // the similarity byte sits `1 + 4 + 4 = 9` bytes before the entry's final `state` byte. The
        // entry is no longer at the very END of the image — `rmp` task #856 appended two directional
        // count blocks after the vector catalog — so the offset is measured back from where the vector
        // block ends, not from where the image ends. `trailing` is DERIVED, so appending another block
        // does not silently move the offset onto the wrong byte.
        let trailing = {
            let mut tail = Vec::new();
            Statistics::encode_pair_map(&mut tail, &BTreeMap::new());
            Statistics::encode_pair_map(&mut tail, &BTreeMap::new());
            tail.len()
        };
        let sim_pos = forged.len() - trailing - 10;
        assert_eq!(
            forged[sim_pos],
            VectorSimilarity::Cosine as u8,
            "the derived offset must land on the entry's similarity byte"
        );
        // Corrupt it to `2` (a reserved discriminant).
        forged[sim_pos] = 2;
        assert!(Statistics::decode(&forged).is_err());
    }

    #[test]
    fn statistics_text_catalog_round_trips_and_pre_662_image_decodes_empty() {
        // Empty map: the text block is just a `0` count, and the round-trip is identity.
        let empty = Statistics::new();
        assert_eq!(Statistics::decode(&empty.encode()).unwrap(), empty);

        // One entry, then several (varying label/property/state), keyed by name.
        let mut s = Statistics::new();
        s.set_text_index(
            "text_Person_name".to_owned(),
            TextIndexEntry {
                label_token: 1,
                property_token: 2,
                state: IndexState::Online,
            },
        );
        assert_eq!(Statistics::decode(&s.encode()).unwrap(), s);
        s.set_text_index(
            "text_Doc_title".to_owned(),
            TextIndexEntry {
                label_token: 9,
                property_token: 4,
                state: IndexState::Populating,
            },
        );
        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.text_indexes().len(), 2);
        // The equivalence resolver finds the exact `(label, property)`.
        assert_eq!(back.text_index_name_for(1, 2), Some("text_Person_name"));
        assert_eq!(back.text_index_name_for(9, 4), Some("text_Doc_title"));
        assert_eq!(back.text_index_name_for(1, 4), None);

        // A pre-#662 image (a composite-catalog-terminated image with NO text block) decodes to an
        // empty text catalog, not a truncation error. Build such an image by encoding a value with no
        // text indexes and truncating off the trailing zero-count text block (a 4-byte `u32` of `0`).
        let mut pre662 = Statistics::new();
        pre662.set_node_property_index(1, 2, IndexState::Online);
        let mut image = pre662.encode();
        image.truncate(image.len() - 4);
        let decoded = Statistics::decode(&image).unwrap();
        assert!(decoded.text_indexes().is_empty());
        assert_eq!(decoded.node_property_indexes().len(), 1);
    }

    #[test]
    fn statistics_constraint_type_descriptor_round_trips_and_pre_100_image_decodes_none() {
        // Every descriptor variant (including a nested LIST<LIST<...>> and a bare LIST<Any>) round-trips
        // through a `PropertyType` constraint.
        for descriptor in [
            ConstraintTypeDescriptor::Integer,
            ConstraintTypeDescriptor::Float,
            ConstraintTypeDescriptor::String,
            ConstraintTypeDescriptor::Boolean,
            ConstraintTypeDescriptor::List(Box::new(ConstraintTypeDescriptor::String)),
            ConstraintTypeDescriptor::List(Box::new(ConstraintTypeDescriptor::Any)),
            ConstraintTypeDescriptor::List(Box::new(ConstraintTypeDescriptor::List(Box::new(
                ConstraintTypeDescriptor::Integer,
            )))),
        ] {
            let mut s = Statistics::new();
            s.set_constraint(
                "t".to_owned(),
                ConstraintEntry {
                    label_token: 1,
                    property_tokens: vec![2],
                    kind: ConstraintKind::PropertyType,
                    type_descriptor: Some(descriptor.clone()),
                },
            );
            let back = Statistics::decode(&s.encode()).unwrap();
            assert_eq!(back, s);
            assert_eq!(
                back.constraint("t").unwrap().type_descriptor,
                Some(descriptor)
            );
        }

        // A composite NODE KEY constraint (multi-property, no type descriptor) round-trips, proving the
        // `property_tokens` Vec carries the whole tuple and the type-descriptor block stays empty for it.
        let mut s = Statistics::new();
        s.set_constraint(
            "k".to_owned(),
            ConstraintEntry {
                label_token: 7,
                property_tokens: vec![10, 11, 12],
                kind: ConstraintKind::NodeKey,
                type_descriptor: None,
            },
        );
        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(
            back.constraint("k").unwrap().property_tokens,
            vec![10, 11, 12]
        );

        // A pre-#100 image: a #99-era store that has a Unique constraint but NO type-descriptor block.
        // We synthesise it by encoding a Unique constraint, then dropping the trailing 4-byte
        // empty-type-descriptor-block count (`0u32`). The reader must decode the constraint with
        // `type_descriptor: None`, not raise a truncation error.
        let mut pre100 = Statistics::new();
        pre100.set_constraint(
            "u".to_owned(),
            ConstraintEntry {
                label_token: 1,
                property_tokens: vec![2],
                kind: ConstraintKind::Unique,
                type_descriptor: None,
            },
        );
        let mut image = pre100.encode();
        image.truncate(image.len() - 4);
        let decoded = Statistics::decode(&image).unwrap();
        assert_eq!(decoded.constraints().len(), 1);
        assert_eq!(decoded.constraint("u").unwrap().type_descriptor, None);
        assert_eq!(
            decoded.constraint("u").unwrap().kind,
            ConstraintKind::Unique
        );
    }

    #[test]
    fn statistics_spatial_catalog_round_trips_and_pre_98_image_decodes_empty() {
        // Empty map: the spatial block is just a `0` count, and the round-trip is identity.
        let empty = Statistics::new();
        assert_eq!(Statistics::decode(&empty.encode()).unwrap(), empty);

        // One entry, then several entries (mixed states), keyed by name.
        let mut s = Statistics::new();
        s.set_spatial_index(
            "a".to_owned(),
            SpatialIndexEntry {
                entity: SpatialEntity::Node,
                label_token: 1,
                property_token: 2,
                state: IndexState::Online,
            },
        );
        assert_eq!(Statistics::decode(&s.encode()).unwrap(), s);
        s.set_spatial_index(
            "b".to_owned(),
            SpatialIndexEntry {
                entity: SpatialEntity::Node,
                label_token: 3,
                property_token: 4,
                state: IndexState::Populating,
            },
        );
        // Mixing in a full-text entry proves the spatial block is read AFTER the full-text block.
        s.set_fulltext_index(
            "ft".to_owned(),
            FulltextIndexEntry {
                entity: FulltextEntity::Node,
                tokens: vec![9],
                property_tokens: vec![1],
                analyzer: 0,
                state: IndexState::Online,
            },
        );
        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.spatial_indexes().len(), 2);

        // A pre-#98 image (ending exactly after the full-text catalog block) must decode to an empty
        // spatial catalog, not a truncation error. We synthesise one by encoding a statistics value
        // that has a full-text entry but no spatial entry, then truncating the trailing spatial block
        // (a single `0u32` count). The reader treats end-of-input where the count would start as "no
        // spatial catalog".
        let mut pre98 = Statistics::new();
        pre98.set_fulltext_index(
            "ft".to_owned(),
            FulltextIndexEntry {
                entity: FulltextEntity::Node,
                tokens: vec![9],
                property_tokens: vec![1],
                analyzer: 0,
                state: IndexState::Online,
            },
        );
        let mut image = pre98.encode();
        // Drop the trailing 4-byte spatial-count word so the image ends right after the full-text block.
        image.truncate(image.len() - 4);
        let decoded = Statistics::decode(&image).unwrap();
        assert!(decoded.spatial_indexes().is_empty());
        assert_eq!(decoded.fulltext_indexes().len(), 1);
    }

    #[test]
    fn statistics_spatial_extension_round_trips_relationship_and_node_needs_none() {
        // `rmp` task #664: a RELATIONSHIP point index records its entity in the trailing spatial
        // extension block; a plain NODE index (no extension entry) round-trips too, and the extension
        // block stays empty for a node-only store.
        let mut s = Statistics::new();
        // A node point index: no extension entry.
        s.set_spatial_index(
            "by_loc".to_owned(),
            SpatialIndexEntry {
                entity: SpatialEntity::Node,
                label_token: 0,
                property_token: 3,
                state: IndexState::Online,
            },
        );
        // A relationship point index: entity Relationship carried in the extension.
        s.set_spatial_index(
            "rel_at".to_owned(),
            SpatialIndexEntry {
                entity: SpatialEntity::Relationship,
                label_token: 7,
                property_token: 2,
                state: IndexState::Populating,
            },
        );
        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(
            back.spatial_index("by_loc").map(|e| e.entity),
            Some(SpatialEntity::Node)
        );
        assert_eq!(
            back.spatial_index("rel_at").map(|e| e.entity),
            Some(SpatialEntity::Relationship)
        );

        // A node-only store writes a 0-count (4-byte) spatial extension block as the LAST bytes.
        let mut node_only = Statistics::new();
        node_only.set_spatial_index(
            "by_loc".to_owned(),
            SpatialIndexEntry {
                entity: SpatialEntity::Node,
                label_token: 1,
                property_token: 2,
                state: IndexState::Online,
            },
        );
        let image = node_only.encode();
        assert_eq!(
            &image[image.len() - 4..],
            &0u32.to_le_bytes(),
            "a node-only store's spatial extension block must be empty (0 count)"
        );
    }

    #[test]
    fn statistics_pre_664_image_decodes_relationship_slot_as_node() {
        // `rmp` task #664: a pre-#664 image ends after the full-text extension block (no spatial
        // extension block). A point index — the exact legacy shape — must decode as a NODE index over
        // the base token slot, exactly as a pre-#664 build would have written it.
        let mut pre664 = Statistics::new();
        pre664.set_spatial_index(
            "loc".to_owned(),
            SpatialIndexEntry {
                entity: SpatialEntity::Node,
                label_token: 5,
                property_token: 9,
                state: IndexState::Online,
            },
        );
        let mut image = pre664.encode();
        // Drop the trailing 4-byte spatial-extension count word so the image ends right after the
        // full-text extension block — the exact byte image a pre-#664 build would have produced.
        image.truncate(image.len() - 4);
        let decoded = Statistics::decode(&image).unwrap();
        assert_eq!(
            decoded.spatial_index("loc"),
            Some(&SpatialIndexEntry {
                entity: SpatialEntity::Node,
                label_token: 5,
                property_token: 9,
                state: IndexState::Online,
            })
        );
    }

    #[test]
    fn statistics_decode_rejects_orphan_spatial_extension() {
        // `rmp` task #664: an extension entry naming an index not present in the base catalog is corrupt
        // (never produced by encode). Build a minimal image: empty base spatial catalog, then an
        // extension block that names a non-existent index. Decode must reject it.
        let empty = Statistics::new();
        let base = empty.encode();
        let mut ext = Vec::new();
        ext.extend_from_slice(&1u32.to_le_bytes()); // 1 extension entry
        ext.extend_from_slice(&(3u32).to_le_bytes()); // name_len
        ext.extend_from_slice(b"idx");
        ext.push(SpatialEntity::Relationship.as_byte());
        // Drop the empty base image's own trailing 4-byte spatial-extension count and splice ours in.
        let mut image = base[..base.len() - 4].to_vec();
        image.extend_from_slice(&ext);
        let mut cur = image.len() - ext.len();
        let mut spatial: BTreeMap<String, SpatialIndexEntry> = BTreeMap::new();
        assert!(
            Statistics::decode_spatial_extension_block(&image, &mut cur, &mut spatial).is_err(),
            "an orphan spatial extension entry must be rejected"
        );
    }

    #[test]
    fn statistics_decode_rejects_unknown_spatial_entity_byte() {
        // `rmp` task #664: a forward-incompatible entity byte (`2..`) in the extension is rejected, like
        // an unknown state byte — never silently mapped to a known flavour.
        let mut s = Statistics::new();
        s.set_spatial_index(
            "idx".to_owned(),
            SpatialIndexEntry {
                entity: SpatialEntity::Node,
                label_token: 1,
                property_token: 2,
                state: IndexState::Online,
            },
        );
        let base = s.encode();
        let mut ext = Vec::new();
        ext.extend_from_slice(&1u32.to_le_bytes()); // 1 extension entry naming the real index
        ext.extend_from_slice(&(3u32).to_le_bytes());
        ext.extend_from_slice(b"idx");
        ext.push(2); // unknown entity byte
        let mut image = base[..base.len() - 4].to_vec();
        image.extend_from_slice(&ext);
        assert!(
            Statistics::decode(&image).is_err(),
            "an unknown spatial entity byte must be rejected"
        );
    }

    #[test]
    fn statistics_round_trip_and_zero_count_invariant() {
        let mut s = Statistics::new();
        assert_eq!(s.node_count_for_label(7), 0);
        s.inc_label(7);
        s.inc_label(7);
        s.inc_rel_type(3);
        // Decrementing to 0 removes the entry (zero-count invariant): the map must not linger a 0.
        s.dec_rel_type(3);
        assert!(s.rels_per_type.is_empty(), "a 0 count must not linger");
        s.dec_label(7);
        assert_eq!(s.node_count_for_label(7), 1);
        // Grand totals (`rmp` task #82) round-trip alongside the maps.
        s.inc_node();
        s.inc_node();
        s.dec_node(); // back to 1
        s.inc_rel();

        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.node_count_for_label(7), 1);
        assert_eq!(back.total_nodes(), 1);
        assert_eq!(back.total_relationships(), 1);
    }

    #[test]
    fn grand_total_decrement_saturates_at_zero() {
        // In a release build an over-decrement saturates at 0 rather than wrapping to u64::MAX, so a
        // logic slip can never corrupt the catalog into an absurd cardinality (`rmp` task #82). A
        // debug build catches the slip via `debug_assert!`, so this is a release-only assertion.
        #[cfg(not(debug_assertions))]
        {
            // Spelt through `apply_count_delta` rather than the `±1` conveniences above: this pins the
            // saturation contract of the ONE signed mutator every count change goes through, and it
            // keeps the conveniences free of a method that only a release build would ever call.
            let mut s = Statistics::new();
            s.apply_count_delta(CountKey::TotalNodes, -1);
            s.apply_count_delta(CountKey::TotalRelationships, -1);
            assert_eq!(s.total_nodes(), 0);
            assert_eq!(s.total_relationships(), 0);
            // A multi-step over-decrement saturates just the same (the `rmp` #866 withdrawal path
            // applies whole deltas, not repeated `-1`s).
            s.apply_count_delta(CountKey::TotalNodes, -7);
            assert_eq!(s.total_nodes(), 0);
        }
    }

    #[test]
    fn statistics_decode_rejects_truncation_of_the_grand_total_header() {
        // The grand-total header is a fixed 16-byte prefix (`rmp` task #82). An image shorter than the
        // two u64s must be rejected by the truncation-safe reader.
        let mut s = Statistics::new();
        s.inc_node();
        s.inc_rel();
        let mut bytes = s.encode();
        bytes.truncate(15); // one byte short of the 16-byte header
        assert!(Statistics::decode(&bytes).is_err());
    }

    #[test]
    fn statistics_decode_rejects_a_zero_count() {
        // A hand-built image with an explicit 0 count must be rejected (encode never produces one).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_nodes header (`rmp` task #82)
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_relationships header
        bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 label entry
        bytes.extend_from_slice(&4u32.to_le_bytes()); // token id 4
        bytes.extend_from_slice(&0u64.to_le_bytes()); // count 0 (invalid)
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 rel-type entries
        assert!(Statistics::decode(&bytes).is_err());
    }

    #[test]
    fn statistics_decode_rejects_truncation() {
        let mut s = Statistics::new();
        s.inc_label(1);
        let mut bytes = s.encode();
        bytes.truncate(bytes.len() - 1);
        assert!(Statistics::decode(&bytes).is_err());
    }

    #[test]
    fn statistics_histograms_round_trip() {
        // Empty map: the histogram block is just a `0` count, and the round-trip is identity.
        let empty = Statistics::new();
        assert_eq!(Statistics::decode(&empty.encode()).unwrap(), empty);

        // One entry, then several entries (mixed blob sizes), keyed by (label, property).
        let mut s = Statistics::new();
        s.set_property_histogram(2, 3, vec![9]);
        assert_eq!(Statistics::decode(&s.encode()).unwrap(), s);

        s.set_property_histogram(0, 0, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        s.set_property_histogram(2, 1, vec![0xFF; 257]);
        // Mixing in counts proves the histogram block is read after both count blocks.
        s.inc_label(4);
        s.inc_rel_type(7);
        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.property_histogram(2, 3), Some(&[9][..]));
        assert_eq!(back.property_histogram(0, 0).map(<[u8]>::len), Some(8));
        assert_eq!(back.property_histogram(2, 1).map(<[u8]>::len), Some(257));
        assert_eq!(back.property_histogram(9, 9), None);
    }

    #[test]
    fn set_property_histogram_with_empty_bytes_removes_the_entry() {
        let mut s = Statistics::new();
        s.set_property_histogram(1, 1, vec![7, 7]);
        assert_eq!(s.property_histogram(1, 1), Some(&[7, 7][..]));
        // An empty blob is meaningless (a histogram is never zero-length): it removes the entry.
        s.set_property_histogram(1, 1, Vec::new());
        assert_eq!(s.property_histogram(1, 1), None);
        assert!(s.node_prop_histograms.is_empty());
        // An empty blob on an absent key is a no-op, not an inserted empty entry.
        s.set_property_histogram(2, 2, Vec::new());
        assert!(s.node_prop_histograms.is_empty());
    }

    #[test]
    fn remove_property_histogram_drops_the_entry() {
        let mut s = Statistics::new();
        s.set_property_histogram(1, 1, vec![1]);
        s.set_property_histogram(1, 2, vec![2]);
        s.remove_property_histogram(1, 1);
        assert_eq!(s.property_histogram(1, 1), None);
        assert_eq!(s.property_histogram(1, 2), Some(&[2][..]));
        // Removing an absent key is a harmless no-op.
        s.remove_property_histogram(9, 9);
        assert_eq!(s.property_histogram(1, 2), Some(&[2][..]));
    }

    #[test]
    fn statistics_decode_rejects_a_zero_length_histogram_blob() {
        // A hand-built image with a 0-length blob must be rejected (encode never produces one).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_nodes header (`rmp` task #82)
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_relationships header
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 label entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 rel-type entries
        bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 histogram entry
        bytes.extend_from_slice(&4u32.to_le_bytes()); // label token 4
        bytes.extend_from_slice(&2u32.to_le_bytes()); // prop token 2
        bytes.extend_from_slice(&0u32.to_le_bytes()); // blob_len 0 (invalid)
        assert!(Statistics::decode(&bytes).is_err());
    }

    #[test]
    fn statistics_decode_rejects_a_duplicate_histogram_key() {
        // Two entries with the same (label, prop) key must be rejected (encode never produces them:
        // the BTreeMap deduplicates by key).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_nodes header (`rmp` task #82)
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_relationships header
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 label entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 rel-type entries
        bytes.extend_from_slice(&2u32.to_le_bytes()); // 2 histogram entries
        for _ in 0..2 {
            bytes.extend_from_slice(&1u32.to_le_bytes()); // label token 1
            bytes.extend_from_slice(&1u32.to_le_bytes()); // prop token 1 (same key both times)
            bytes.extend_from_slice(&1u32.to_le_bytes()); // blob_len 1
            bytes.push(0xAA); // blob byte
        }
        assert!(Statistics::decode(&bytes).is_err());
    }

    #[test]
    fn statistics_decode_rejects_histogram_truncation() {
        // Truncating mid-blob (the length header promises more bytes than remain) must be rejected.
        let mut s = Statistics::new();
        s.set_property_histogram(1, 2, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let mut bytes = s.encode();
        bytes.truncate(bytes.len() - 3);
        assert!(Statistics::decode(&bytes).is_err());
    }

    #[test]
    fn statistics_index_catalog_round_trips() {
        // Empty catalog: the index block is just a `0` count, and the round-trip is identity.
        let empty = Statistics::new();
        assert_eq!(Statistics::decode(&empty.encode()).unwrap(), empty);

        // One entry, then mixed states and mixed keys.
        let mut s = Statistics::new();
        s.set_node_property_index(2, 3, IndexState::Online);
        assert_eq!(Statistics::decode(&s.encode()).unwrap(), s);

        s.set_node_property_index(0, 0, IndexState::Populating);
        s.set_node_property_index(7, 1, IndexState::Online);
        // Mixing in counts and a histogram proves the index block is read after both count blocks and
        // the histogram block (parse-position is unambiguous).
        s.inc_label(4);
        s.inc_rel_type(7);
        s.set_property_histogram(2, 3, vec![0xCD, 0xEF]);
        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(
            back.node_property_index_state(2, 3),
            Some(IndexState::Online)
        );
        assert_eq!(
            back.node_property_index_state(0, 0),
            Some(IndexState::Populating)
        );
        assert_eq!(
            back.node_property_index_state(7, 1),
            Some(IndexState::Online)
        );
        assert_eq!(back.node_property_index_state(9, 9), None);
        // Listing is ascending by key and reports the state.
        assert_eq!(
            back.node_property_indexes(),
            vec![
                (0, 0, IndexState::Populating),
                (2, 3, IndexState::Online),
                (7, 1, IndexState::Online),
            ]
        );
    }

    #[test]
    fn set_and_remove_node_property_index() {
        let mut s = Statistics::new();
        assert_eq!(s.node_property_index_state(1, 2), None);
        s.set_node_property_index(1, 2, IndexState::Populating);
        assert_eq!(
            s.node_property_index_state(1, 2),
            Some(IndexState::Populating)
        );
        // Re-recording flips the state (idempotent on the key).
        s.set_node_property_index(1, 2, IndexState::Online);
        assert_eq!(s.node_property_index_state(1, 2), Some(IndexState::Online));
        // Removal drops the entry; removing an absent key is a harmless no-op.
        s.remove_node_property_index(1, 2);
        assert_eq!(s.node_property_index_state(1, 2), None);
        s.remove_node_property_index(9, 9);
        assert!(s.node_property_indexes.is_empty());
    }

    #[test]
    fn statistics_decode_accepts_a_pre_task_90_image_as_empty_index_catalog() {
        // A pre-`rmp`-task-#90 image ends after the histogram block (no index-catalog block). Build
        // exactly such an image by hand and confirm decode accepts it with an empty index catalog.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&3u64.to_le_bytes()); // total_nodes
        bytes.extend_from_slice(&1u64.to_le_bytes()); // total_relationships
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 label entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 rel-type entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 histogram entries -- image ends here (pre-#90)
        let back = Statistics::decode(&bytes).unwrap();
        assert_eq!(back.total_nodes(), 3);
        assert_eq!(back.total_relationships(), 1);
        assert!(back.node_property_indexes.is_empty());
        // And it re-encodes with an explicit (empty) index-catalog block appended.
        assert_eq!(Statistics::decode(&back.encode()).unwrap(), back);
    }

    #[test]
    fn statistics_decode_rejects_an_unknown_index_state_byte() {
        // A hand-built image with a reserved/unknown state byte (2) must be rejected: encode only ever
        // produces 0 (Populating) or 1 (Online), and accepting an unknown byte would silently lose the
        // forward-incompatible state.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_nodes
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_relationships
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 label entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 rel-type entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 histogram entries
        bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 index-catalog entry
        bytes.extend_from_slice(&1u32.to_le_bytes()); // label token 1
        bytes.extend_from_slice(&2u32.to_le_bytes()); // prop token 2
        bytes.push(2); // state byte 2 (unknown / reserved)
        assert!(Statistics::decode(&bytes).is_err());
    }

    #[test]
    fn statistics_decode_rejects_a_duplicate_index_catalog_key() {
        // Two entries with the same (label, prop) key must be rejected (encode never produces them).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_nodes
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_relationships
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 label entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 rel-type entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 histogram entries
        bytes.extend_from_slice(&2u32.to_le_bytes()); // 2 index-catalog entries
        for _ in 0..2 {
            bytes.extend_from_slice(&1u32.to_le_bytes()); // label token 1
            bytes.extend_from_slice(&1u32.to_le_bytes()); // prop token 1 (same key both times)
            bytes.push(1); // Online
        }
        assert!(Statistics::decode(&bytes).is_err());
    }

    #[test]
    fn statistics_decode_rejects_index_catalog_truncation() {
        // Truncating mid-entry (the count word promises an entry the bytes do not hold) must be
        // rejected — distinct from the clean pre-#90 end-of-input, which lands exactly on the count
        // word's start.
        let mut s = Statistics::new();
        s.set_node_property_index(1, 2, IndexState::Online);
        let mut bytes = s.encode();
        bytes.truncate(bytes.len() - 1); // drop the state byte of the only entry
        assert!(Statistics::decode(&bytes).is_err());
    }

    // ---------------------------------------------------------------------------------------------
    // Node-property index NAME catalog (`rmp` task #623)
    // ---------------------------------------------------------------------------------------------

    /// Builds an image whose preamble (through the empty constraint blocks) is produced by the real
    /// encoder for a `Statistics` declaring the index `target`, with its trailing empty (`0`-count)
    /// name block replaced by `name_block`. Lets the rejection tests hand-craft only the name block.
    /// Splices `name_block` in as the node-property index-name catalog of an image that declares the
    /// index `target`, leaving every other block intact.
    ///
    /// The position is **derived** by differencing an image that carries a name against one that does
    /// not: the first byte where they differ is where the name catalog's count begins. It used to be
    /// found by truncating the last 4 bytes of the image — which stopped pointing at the name catalog
    /// the moment `rmp` #646 appended blocks after it, and every append since widened the gap. The
    /// rejection tests below were consequently passing because the decoder choked on a *later* block
    /// fed the forged bytes, not because it rejected the forged name catalog. Deriving the offset makes
    /// them test what they claim, and keeps them correct however many blocks are appended in future
    /// (`rmp` task #856 found this while adding two).
    fn image_with_index_and_name_block(target: (u32, u32), name_block: &[u8]) -> Vec<u8> {
        let mut without = Statistics::new();
        without.set_node_property_index(target.0, target.1, IndexState::Online);
        let mut with = without.clone();
        with.set_node_property_index_name("probe".to_owned(), target.0, target.1);
        let plain = without.encode();
        let named = with.encode();
        let start = plain
            .iter()
            .zip(named.iter())
            .position(|(a, b)| a != b)
            .expect("the two images must differ inside the name catalog");
        assert_eq!(
            &plain[start..start + 4],
            &[0, 0, 0, 0],
            "the derived offset must land on the empty name catalog's u32 count"
        );
        let mut out = plain[..start].to_vec();
        out.extend_from_slice(name_block);
        out.extend_from_slice(&plain[start + 4..]);
        out
    }

    #[test]
    fn statistics_index_name_catalog_round_trips() {
        // Empty name catalog: the block is just a `0` count, and the round-trip is identity.
        let empty = Statistics::new();
        assert_eq!(Statistics::decode(&empty.encode()).unwrap(), empty);

        let mut s = Statistics::new();
        s.set_node_property_index(2, 3, IndexState::Online);
        s.set_node_property_index(7, 1, IndexState::Populating);
        s.set_node_property_index_name("ix_a".to_owned(), 2, 3);
        s.set_node_property_index_name("ix_b".to_owned(), 7, 1);
        // Interleave counts + a histogram to prove the name block is read after every prior block
        // (its parse position is unambiguous).
        s.inc_label(4);
        s.set_property_histogram(2, 3, vec![0xAB, 0xCD]);
        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        // Forward and reverse resolution both work.
        assert_eq!(back.node_property_index_name("ix_a"), Some((2, 3)));
        assert_eq!(back.node_property_index_name("ix_b"), Some((7, 1)));
        assert_eq!(back.node_property_index_name("missing"), None);
        assert_eq!(back.node_property_index_name_for(2, 3), Some("ix_a"));
        assert_eq!(back.node_property_index_name_for(7, 1), Some("ix_b"));
        assert_eq!(back.node_property_index_name_for(9, 9), None);
        // Listing is ascending by name.
        assert_eq!(
            back.node_property_index_names(),
            vec![("ix_a".to_owned(), 2, 3), ("ix_b".to_owned(), 7, 1)]
        );
    }

    #[test]
    fn constraint_type_descriptor_full_set_round_trips() {
        use ConstraintKind as K;
        use ConstraintTypeDescriptor as T;
        let mk = |kind: K, td: Option<T>| ConstraintEntry {
            label_token: 1,
            property_tokens: vec![2],
            kind,
            type_descriptor: td,
        };
        let mut s = Statistics::new();
        // One property-type constraint per new (`rmp` #652) type, plus a list and a nested union.
        s.set_constraint("c_date".to_owned(), mk(K::PropertyType, Some(T::Date)));
        s.set_constraint(
            "c_ltime".to_owned(),
            mk(K::PropertyType, Some(T::LocalTime)),
        );
        s.set_constraint(
            "c_ztime".to_owned(),
            mk(K::PropertyType, Some(T::ZonedTime)),
        );
        s.set_constraint(
            "c_ldt".to_owned(),
            mk(K::PropertyType, Some(T::LocalDateTime)),
        );
        s.set_constraint(
            "c_zdt".to_owned(),
            mk(K::PropertyType, Some(T::ZonedDateTime)),
        );
        s.set_constraint("c_dur".to_owned(), mk(K::PropertyType, Some(T::Duration)));
        s.set_constraint("c_point".to_owned(), mk(K::PropertyType, Some(T::Point)));
        s.set_constraint(
            "c_list".to_owned(),
            mk(K::PropertyType, Some(T::List(Box::new(T::LocalDateTime)))),
        );
        s.set_constraint(
            "c_union".to_owned(),
            mk(
                K::RelPropertyType,
                Some(T::Union(vec![
                    T::Integer,
                    T::String,
                    T::List(Box::new(T::Point)),
                ])),
            ),
        );
        let back = Statistics::decode(&s.encode()).expect("full descriptor set must round-trip");
        assert_eq!(back, s);
        // A legacy `LIST<ANY>` descriptor (a pre-#652 element wildcard) still decodes unchanged.
        s.set_constraint(
            "c_legacy".to_owned(),
            mk(K::PropertyType, Some(T::List(Box::new(T::Any)))),
        );
        assert_eq!(Statistics::decode(&s.encode()).unwrap(), s);
    }

    #[test]
    fn constraint_type_descriptor_storage_depth_matches_decode_depth() {
        use ConstraintTypeDescriptor as T;
        // A scalar is depth 0; each LIST / Union level adds one; a union takes its deepest member.
        assert_eq!(T::Integer.storage_depth(), 0);
        assert_eq!(T::List(Box::new(T::Integer)).storage_depth(), 1);
        assert_eq!(
            T::List(Box::new(T::List(Box::new(T::Integer)))).storage_depth(),
            2
        );
        assert_eq!(T::Union(vec![T::Integer, T::String]).storage_depth(), 1);
        assert_eq!(
            T::Union(vec![T::Integer, T::List(Box::new(T::Point))]).storage_depth(),
            2
        );
        // A descriptor at exactly MAX_TYPE_DEPTH round-trips; storage_depth must agree so the write
        // path's boundary matches the decoder's (`rmp` #652).
        let mut deepest = T::Integer;
        for _ in 0..T::MAX_TYPE_DEPTH {
            deepest = T::List(Box::new(deepest));
        }
        assert_eq!(deepest.storage_depth(), T::MAX_TYPE_DEPTH);
        let mut bytes = Vec::new();
        deepest.encode(&mut bytes);
        let mut cur = 0;
        assert!(
            T::decode(&bytes, &mut cur).is_ok(),
            "a descriptor at storage_depth == MAX_TYPE_DEPTH must decode"
        );
        // One level deeper is exactly what the decoder rejects.
        let over = T::List(Box::new(deepest));
        assert_eq!(over.storage_depth(), T::MAX_TYPE_DEPTH + 1);
        let mut bytes = Vec::new();
        over.encode(&mut bytes);
        let mut cur = 0;
        assert!(
            T::decode(&bytes, &mut cur).is_err(),
            "a descriptor one level past MAX_TYPE_DEPTH must be rejected by decode"
        );
    }

    #[test]
    fn constraint_type_descriptor_decode_rejects_unknown_tag_and_overdeep_nesting() {
        use ConstraintTypeDescriptor as T;
        // An unknown tag byte is a forward-incompatible image, not a panic.
        let mut cur = 0;
        assert!(T::decode(&[99u8], &mut cur).is_err());
        // A crafted chain of nested LIST tags (tag 4) beyond the depth bound is rejected, not a stack
        // overflow.
        let deep = vec![4u8; T::MAX_TYPE_DEPTH + 2];
        let mut cur = 0;
        assert!(T::decode(&deep, &mut cur).is_err());
    }

    #[test]
    fn set_resolve_and_remove_node_property_index_name() {
        let mut s = Statistics::new();
        s.set_node_property_index(1, 2, IndexState::Online);
        assert_eq!(s.node_property_index_name("ix"), None);
        s.set_node_property_index_name("ix".to_owned(), 1, 2);
        assert_eq!(s.node_property_index_name("ix"), Some((1, 2)));
        assert_eq!(s.node_property_index_name_for(1, 2), Some("ix"));
        // Removal by name.
        s.remove_node_property_index_name("ix");
        assert_eq!(s.node_property_index_name("ix"), None);
        // Removal by target clears whatever name maps to it; a no-op for a nameless index.
        s.set_node_property_index_name("ix2".to_owned(), 1, 2);
        s.remove_node_property_index_name_for(1, 2);
        assert!(s.node_property_index_names.is_empty());
        s.remove_node_property_index_name_for(9, 9); // absent target: harmless.
        s.remove_node_property_index_name("absent"); // absent name: harmless.
    }

    #[test]
    fn statistics_decode_accepts_a_pre_task_623_image_as_empty_name_catalog() {
        // A pre-#623 image ends after the constraint type-descriptor block (no name block). An index
        // that still carries a name-catalog entry in a newer image loses none of its declared indexes
        // when read as pre-#623 — it is simply nameless (backfilled on open by the Cypher layer).
        let mut s = Statistics::new();
        s.set_node_property_index(5, 6, IndexState::Online);
        s.inc_label(5);
        let mut bytes = s.encode();
        // Drop the trailing empty (`0`-count) name block: this is a byte-exact pre-#623 image.
        bytes.truncate(bytes.len() - 4);
        let back = Statistics::decode(&bytes).unwrap();
        assert_eq!(
            back.node_property_indexes(),
            vec![(5, 6, IndexState::Online)],
            "the declared index survives"
        );
        assert!(
            back.node_property_index_names.is_empty(),
            "a pre-#623 image has no names (every index nameless)"
        );
        // Re-encoding appends an explicit (empty) name block; the round-trip is then stable.
        assert_eq!(Statistics::decode(&back.encode()).unwrap(), back);
    }

    #[test]
    fn statistics_decode_rejects_a_duplicate_index_name() {
        // Two name entries with the same name must be rejected (encode never produces them).
        let mut nb = Vec::new();
        nb.extend_from_slice(&2u32.to_le_bytes()); // 2 name entries
        for _ in 0..2 {
            nb.extend_from_slice(&2u32.to_le_bytes()); // name_len 2
            nb.extend_from_slice(b"ix"); // name "ix" (same both times)
            nb.extend_from_slice(&1u32.to_le_bytes()); // label token 1
            nb.extend_from_slice(&2u32.to_le_bytes()); // prop token 2
        }
        assert!(Statistics::decode(&image_with_index_and_name_block((1, 2), &nb)).is_err());
    }

    #[test]
    fn statistics_decode_rejects_an_empty_index_name() {
        let mut nb = Vec::new();
        nb.extend_from_slice(&1u32.to_le_bytes()); // 1 name entry
        nb.extend_from_slice(&0u32.to_le_bytes()); // name_len 0 (empty)
        nb.extend_from_slice(&1u32.to_le_bytes()); // label token 1
        nb.extend_from_slice(&2u32.to_le_bytes()); // prop token 2
        assert!(Statistics::decode(&image_with_index_and_name_block((1, 2), &nb)).is_err());
    }

    #[test]
    fn statistics_decode_rejects_a_non_utf8_index_name() {
        let mut nb = Vec::new();
        nb.extend_from_slice(&1u32.to_le_bytes()); // 1 name entry
        nb.extend_from_slice(&2u32.to_le_bytes()); // name_len 2
        nb.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        nb.extend_from_slice(&1u32.to_le_bytes()); // label token 1
        nb.extend_from_slice(&2u32.to_le_bytes()); // prop token 2
        assert!(Statistics::decode(&image_with_index_and_name_block((1, 2), &nb)).is_err());
    }

    #[test]
    fn statistics_decode_rejects_an_orphan_index_name() {
        // A name whose target is not a declared node-property index is corruption (encode only ever
        // records a name alongside a declared index). The declared index here is (1, 2); the name
        // targets (9, 9), which is not declared.
        let mut nb = Vec::new();
        nb.extend_from_slice(&1u32.to_le_bytes()); // 1 name entry
        nb.extend_from_slice(&2u32.to_le_bytes()); // name_len 2
        nb.extend_from_slice(b"ix");
        nb.extend_from_slice(&9u32.to_le_bytes()); // label token 9 (no such index)
        nb.extend_from_slice(&9u32.to_le_bytes()); // prop token 9
        assert!(Statistics::decode(&image_with_index_and_name_block((1, 2), &nb)).is_err());
    }

    #[test]
    fn statistics_decode_rejects_a_second_name_for_the_same_target() {
        // Two distinct names claiming the same declared index (1, 2): an index has at most one name.
        let mut nb = Vec::new();
        nb.extend_from_slice(&2u32.to_le_bytes()); // 2 name entries
        for name in [b"ix_a", b"ix_b"] {
            nb.extend_from_slice(&2u32.to_le_bytes()); // name_len 2
            nb.extend_from_slice(name);
            nb.extend_from_slice(&1u32.to_le_bytes()); // label token 1 (same target both times)
            nb.extend_from_slice(&2u32.to_le_bytes()); // prop token 2
        }
        assert!(Statistics::decode(&image_with_index_and_name_block((1, 2), &nb)).is_err());
    }

    #[test]
    fn set_node_property_index_name_enforces_one_name_per_target_and_reopens() {
        // Write-path invariant (rmp #624 durability audit, HIGH): setting a second name for the same
        // target REPLACES the first, so the durable catalog can never hold two names for one target —
        // the exact state `statistics_decode_rejects_a_second_name_for_the_same_target` shows makes a
        // store unopenable. Here the write path prevents it at the source, and the image reopens.
        let mut s = Statistics::new();
        s.set_node_property_index(1, 2, IndexState::Online);
        s.set_node_property_index_name("ix_a".to_owned(), 1, 2);
        s.set_node_property_index_name("ix_b".to_owned(), 1, 2); // same target -> replaces ix_a
        assert_eq!(
            s.node_property_index_names(),
            vec![("ix_b".to_owned(), 1, 2)]
        );
        assert_eq!(s.node_property_index_name("ix_a"), None);
        assert_eq!(s.node_property_index_name("ix_b"), Some((1, 2)));
        // The resulting image round-trips (the store reopens) rather than being rejected on decode.
        let back = Statistics::decode(&s.encode()).expect("one-name-per-target image must reopen");
        assert_eq!(back, s);
    }

    #[test]
    fn statistics_decode_rejects_index_name_catalog_truncation() {
        // The count word promises an entry the bytes do not hold: a genuine truncation, distinct from
        // the clean pre-#623 end-of-input that lands exactly on the count word's start.
        let mut nb = Vec::new();
        nb.extend_from_slice(&1u32.to_le_bytes()); // promises 1 entry
        nb.extend_from_slice(&2u32.to_le_bytes()); // name_len 2 ... but no name bytes follow
        assert!(Statistics::decode(&image_with_index_and_name_block((1, 2), &nb)).is_err());
    }

    #[test]
    fn set_resolve_and_remove_rel_property_index_and_name() {
        // The relationship-property index catalog (`rmp` task #646) is a structural twin of the
        // node-property catalog, keyed by a separate `(rel_type_token, prop_token)` namespace.
        let mut s = Statistics::new();
        assert_eq!(s.rel_property_index_state(3, 4), None);
        s.set_rel_property_index(3, 4, IndexState::Populating);
        assert_eq!(
            s.rel_property_index_state(3, 4),
            Some(IndexState::Populating)
        );
        s.set_rel_property_index(3, 4, IndexState::Online); // idempotent on key: flips state
        assert_eq!(s.rel_property_index_state(3, 4), Some(IndexState::Online));

        // Name resolution both directions.
        assert_eq!(s.rel_property_index_name("ix_rel"), None);
        s.set_rel_property_index_name("ix_rel".to_owned(), 3, 4);
        assert_eq!(s.rel_property_index_name("ix_rel"), Some((3, 4)));
        assert_eq!(s.rel_property_index_name_for(3, 4), Some("ix_rel"));

        // A relationship-type token can numerically coincide with a label token; the two catalogs are
        // independent — declaring a NODE index on (3, 4) must not touch the REL index on (3, 4).
        s.set_node_property_index(3, 4, IndexState::Online);
        s.set_node_property_index_name("ix_node".to_owned(), 3, 4);
        assert_eq!(s.rel_property_index_name("ix_node"), None);
        assert_eq!(s.node_property_index_name("ix_rel"), None);
        assert_eq!(
            s.rel_property_indexes(),
            vec![(3, 4, IndexState::Online)],
            "the rel catalog holds exactly its own entry"
        );

        // Removal by target clears both the entry and its name.
        s.remove_rel_property_index(3, 4);
        s.remove_rel_property_index_name_for(3, 4);
        assert_eq!(s.rel_property_index_state(3, 4), None);
        assert!(s.rel_property_index_names.is_empty());
        // The coincident node index is untouched.
        assert_eq!(s.node_property_index_state(3, 4), Some(IndexState::Online));
    }

    #[test]
    fn rel_property_index_catalog_round_trips_after_every_prior_block() {
        // A rel-property catalog + name catalog round-trips, and rides AFTER the node-property name
        // catalog (populate node + rel + a mix of counts/histograms/constraints to prove ordering).
        let mut s = Statistics::new();
        s.inc_label(4);
        s.inc_rel_type(2);
        s.set_property_histogram(0, 0, vec![9, 8, 7]);
        s.set_node_property_index(1, 2, IndexState::Online);
        s.set_node_property_index_name("ix_node".to_owned(), 1, 2);
        s.set_rel_property_index(10, 20, IndexState::Online);
        s.set_rel_property_index(11, 21, IndexState::Populating);
        s.set_rel_property_index_name("ix_since".to_owned(), 10, 20);
        // Leave (11, 21) nameless to prove a rel index may be anonymous.

        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(
            back.rel_property_indexes(),
            vec![
                (10, 20, IndexState::Online),
                (11, 21, IndexState::Populating)
            ]
        );
        assert_eq!(back.rel_property_index_name("ix_since"), Some((10, 20)));
        assert_eq!(back.rel_property_index_name_for(11, 21), None);
    }

    #[test]
    fn statistics_decode_accepts_a_pre_task_646_image_as_empty_rel_catalog() {
        // A pre-#646 image ends after the node-property index NAME catalog (no rel blocks). Encoding
        // then truncating the two trailing empty (`0`-count) rel blocks yields a byte-exact pre-#646
        // image: it must decode with an empty rel catalog while every earlier block survives intact.
        let mut s = Statistics::new();
        s.set_node_property_index(5, 6, IndexState::Online);
        s.set_node_property_index_name("ix".to_owned(), 5, 6);
        s.inc_label(5);
        let mut bytes = s.encode();
        // Drop the two trailing empty rel blocks (each a bare `0`-count u32): the byte-exact pre-#646
        // image ends right after the node-property name catalog.
        bytes.truncate(bytes.len() - 8);
        let back = Statistics::decode(&bytes).unwrap();
        assert_eq!(
            back.node_property_indexes(),
            vec![(5, 6, IndexState::Online)],
            "the node index survives a pre-#646 read"
        );
        assert_eq!(back.node_property_index_name("ix"), Some((5, 6)));
        assert!(
            back.rel_property_indexes.is_empty() && back.rel_property_index_names.is_empty(),
            "a pre-#646 image has no relationship-property indexes"
        );
        // Re-encoding appends the explicit (empty) rel blocks; the round-trip is then stable.
        assert_eq!(Statistics::decode(&back.encode()).unwrap(), back);
    }

    #[test]
    fn set_rel_property_index_name_enforces_one_name_per_target_and_reopens() {
        // Write-path invariant twin of the node case: a second name for the same rel target REPLACES
        // the first, so the durable image never holds two names for one target (which decode rejects).
        let mut s = Statistics::new();
        s.set_rel_property_index(1, 2, IndexState::Online);
        s.set_rel_property_index_name("ix_a".to_owned(), 1, 2);
        s.set_rel_property_index_name("ix_b".to_owned(), 1, 2); // same target -> replaces ix_a
        assert_eq!(
            s.rel_property_index_names(),
            vec![("ix_b".to_owned(), 1, 2)]
        );
        assert_eq!(s.rel_property_index_name("ix_a"), None);
        let back =
            Statistics::decode(&s.encode()).expect("one-name-per-target rel image must reopen");
        assert_eq!(back, s);
    }

    #[test]
    fn statistics_fulltext_catalog_round_trips() {
        // A full-text catalog with multiple indexes (varied analyzers, property arities, states)
        // round-trips, and rides after the node-property index catalog (set one to prove ordering).
        let mut s = Statistics::new();
        s.set_node_property_index(1, 2, IndexState::Online);
        s.set_fulltext_index(
            "articles".to_owned(),
            FulltextIndexEntry {
                entity: FulltextEntity::Node,
                tokens: vec![3],
                property_tokens: vec![7, 8],
                analyzer: 0, // standard
                state: IndexState::Online,
            },
        );
        s.set_fulltext_index(
            "tags".to_owned(),
            FulltextIndexEntry {
                entity: FulltextEntity::Node,
                tokens: vec![5],
                property_tokens: vec![9],
                analyzer: 1, // keyword
                state: IndexState::Populating,
            },
        );
        // Mix in counts/histograms to prove the full-text block is read after every prior block.
        s.inc_label(4);
        s.set_property_histogram(0, 0, vec![1, 2, 3]);

        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(
            back.fulltext_index("articles")
                .map(|e| e.property_tokens.clone()),
            Some(vec![7, 8])
        );
        assert_eq!(back.fulltext_index("tags").map(|e| e.analyzer), Some(1));
        assert_eq!(
            back.fulltext_index("tags").map(|e| e.state),
            Some(IndexState::Populating)
        );
        assert_eq!(back.fulltext_index("missing"), None);
        assert_eq!(back.fulltext_indexes().len(), 2);
    }

    #[test]
    fn statistics_fulltext_extension_round_trips_node_multilabel_and_relationship() {
        // `rmp` task #663: a relationship full-text index and a multi-label node full-text index carry
        // their entity + additional covering tokens in the trailing extension block. Both must
        // round-trip, and a plain single-label node index (no extension entry) must too.
        let mut s = Statistics::new();
        // A single-label node index: no extension entry.
        s.set_fulltext_index(
            "node_single".to_owned(),
            FulltextIndexEntry {
                entity: FulltextEntity::Node,
                tokens: vec![3],
                property_tokens: vec![7],
                analyzer: 0,
                state: IndexState::Online,
            },
        );
        // A multi-label node index: entity Node + extra tokens [5, 6] in the extension.
        s.set_fulltext_index(
            "node_multi".to_owned(),
            FulltextIndexEntry {
                entity: FulltextEntity::Node,
                tokens: vec![4, 5, 6],
                property_tokens: vec![7, 8],
                analyzer: 1,
                state: IndexState::Online,
            },
        );
        // A relationship index (single type): entity Relationship, no extra tokens.
        s.set_fulltext_index(
            "rel_single".to_owned(),
            FulltextIndexEntry {
                entity: FulltextEntity::Relationship,
                tokens: vec![9],
                property_tokens: vec![7],
                analyzer: 0,
                state: IndexState::Online,
            },
        );
        // A relationship index over multiple types: entity Relationship + extra tokens [11].
        s.set_fulltext_index(
            "rel_multi".to_owned(),
            FulltextIndexEntry {
                entity: FulltextEntity::Relationship,
                tokens: vec![10, 11],
                property_tokens: vec![7, 8],
                analyzer: 1,
                state: IndexState::Populating,
            },
        );
        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(
            back, s,
            "every full-text entity/token shape must round-trip"
        );
        // Spot-check the recovered shapes.
        assert_eq!(
            back.fulltext_index("node_multi").map(|e| e.tokens.clone()),
            Some(vec![4, 5, 6])
        );
        assert_eq!(
            back.fulltext_index("rel_single").map(|e| e.entity),
            Some(FulltextEntity::Relationship)
        );
        assert_eq!(
            back.fulltext_index("rel_multi").map(|e| e.tokens.clone()),
            Some(vec![10, 11])
        );
        assert_eq!(
            back.fulltext_index("node_single").map(|e| e.entity),
            Some(FulltextEntity::Node)
        );
    }

    #[test]
    fn statistics_decode_accepts_a_pre_task_663_image_as_node_single_label() {
        // A pre-#663 image ends after the text catalog (no full-text extension block). Build one that
        // carries a full-text entry via the base catalog block only, and confirm it decodes as a
        // single-label NODE index — the exact legacy shape — with the extension block absent.
        let mut pre663 = Statistics::new();
        pre663.set_fulltext_index(
            "legacy".to_owned(),
            FulltextIndexEntry {
                entity: FulltextEntity::Node,
                tokens: vec![42],
                property_tokens: vec![7, 8],
                analyzer: 0,
                state: IndexState::Online,
            },
        );
        let mut image = pre663.encode();
        // Drop the trailing 4-byte full-text extension count word so the image ends right after the
        // text catalog — exactly where a pre-#663 image ends.
        image.truncate(image.len() - 4);
        let decoded = Statistics::decode(&image).unwrap();
        let entry = decoded
            .fulltext_index("legacy")
            .expect("legacy index decodes");
        assert_eq!(entry.entity, FulltextEntity::Node);
        assert_eq!(entry.tokens, vec![42]);
        assert_eq!(entry.property_tokens, vec![7, 8]);
    }

    #[test]
    fn statistics_decode_rejects_orphan_fulltext_extension() {
        // An extension entry naming an index not present in the base catalog is corrupt (never produced
        // by encode). Build a minimal image: empty base full-text catalog, then an extension block that
        // names "ghost".
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_nodes
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_relationships
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 label entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 rel-type entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 histogram entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 index-catalog entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 full-text entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 spatial entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 constraint entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 constraint type-descriptors
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 node index names
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 rel-property indexes
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 rel-property index names
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 composite entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 text entries
        bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 full-text EXTENSION entry
        bytes.extend_from_slice(&5u32.to_le_bytes()); // name_len 5
        bytes.extend_from_slice(b"ghost"); // name "ghost" (no matching base entry)
        bytes.push(FulltextEntity::Relationship.as_byte()); // entity
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 extra tokens
        assert!(Statistics::decode(&bytes).is_err());
    }

    #[test]
    fn statistics_decode_accepts_a_pre_task_72_image_as_empty_fulltext_catalog() {
        // A pre-`rmp`-task-#72 image ends after the node-property index-catalog block. Build exactly
        // such an image and confirm decode accepts it with an empty full-text catalog.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes()); // total_nodes
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_relationships
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 label entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 rel-type entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 histogram entries
        bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 index-catalog entry
        bytes.extend_from_slice(&1u32.to_le_bytes()); // label token 1
        bytes.extend_from_slice(&2u32.to_le_bytes()); // prop token 2
        bytes.push(1); // Online -- image ends here (pre-#72)
        let back = Statistics::decode(&bytes).unwrap();
        assert_eq!(back.total_nodes(), 2);
        assert_eq!(back.node_property_indexes().len(), 1);
        assert!(back.fulltext_indexes.is_empty());
        // It re-encodes with an explicit (empty) full-text block appended and stays stable.
        assert_eq!(Statistics::decode(&back.encode()).unwrap(), back);
    }

    #[test]
    fn statistics_decode_rejects_a_duplicate_fulltext_name() {
        // Two full-text entries with the same name must be rejected (encode never produces them).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_nodes
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_relationships
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 label entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 rel-type entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 histogram entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 index-catalog entries
        bytes.extend_from_slice(&2u32.to_le_bytes()); // 2 full-text entries
        for _ in 0..2 {
            bytes.extend_from_slice(&2u32.to_le_bytes()); // name_len 2
            bytes.extend_from_slice(b"ft"); // name "ft" (same both times)
            bytes.extend_from_slice(&1u32.to_le_bytes()); // label token 1
            bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 property token
            bytes.extend_from_slice(&5u32.to_le_bytes()); // prop token 5
            bytes.push(0); // analyzer standard
            bytes.push(1); // Online
        }
        assert!(Statistics::decode(&bytes).is_err());
    }

    #[test]
    fn statistics_decode_rejects_fulltext_with_no_properties() {
        // A full-text index must declare at least one property; a zero count is rejected.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_nodes
        bytes.extend_from_slice(&0u64.to_le_bytes()); // total_relationships
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 label entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 rel-type entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 histogram entries
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 index-catalog entries
        bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 full-text entry
        bytes.extend_from_slice(&1u32.to_le_bytes()); // name_len 1
        bytes.extend_from_slice(b"x"); // name "x"
        bytes.extend_from_slice(&1u32.to_le_bytes()); // label token 1
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 property tokens (invalid)
        assert!(Statistics::decode(&bytes).is_err());
    }

    #[test]
    fn statistics_fulltext_remove_drops_the_entry() {
        let mut s = Statistics::new();
        s.set_fulltext_index(
            "a".to_owned(),
            FulltextIndexEntry {
                entity: FulltextEntity::Node,
                tokens: vec![1],
                property_tokens: vec![2],
                analyzer: 0,
                state: IndexState::Online,
            },
        );
        assert!(s.fulltext_index("a").is_some());
        s.remove_fulltext_index("a");
        assert!(s.fulltext_index("a").is_none());
        // Removing an absent name is a harmless no-op.
        s.remove_fulltext_index("nope");
        assert!(s.fulltext_indexes.is_empty());
    }

    #[test]
    fn large_device_page_map_round_trips_past_one_page() {
        // A catalog whose device-page maps far exceed one page payload must still round-trip:
        // the single-page cap was the `rmp` task #51 defect (it capped a store at ~1000 pages).
        // 4000 pages/store * 8 B ≈ 128 KiB total — an order of magnitude past one 8 KiB page.
        let mut m = Meta::new(7);
        for (k, s) in m.stores.iter_mut().enumerate() {
            s.high_water = 4000;
            s.device_pages = (0..4000).map(|i| (k as u64 * 4000) + i + 1).collect();
        }
        let bytes = m.encode().unwrap();
        assert!(
            bytes.len() > PAGE_PAYLOAD,
            "test must exceed one page payload to be meaningful: {} <= {PAGE_PAYLOAD}",
            bytes.len()
        );
        let back = Meta::decode(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn decode_rejects_truncation() {
        let m = Meta::new(1);
        let mut bytes = m.encode().unwrap();
        bytes.truncate(3);
        assert!(Meta::decode(&bytes).is_err());
    }
}
