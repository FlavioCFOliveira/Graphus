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

/// The durable catalog stored in the metadata page.
///
/// Holds, for each of the three record stores, the physical-id high-water mark, the free list,
/// and the store-relative-page → device-`PageId` map; plus the shared token store and the
/// next `ElementId` to allocate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    /// Next `ElementId` to allocate (never-reused monotonic counter, `04 §2.2`).
    pub element_id_next: u128,
    /// The largest MVCC commit timestamp issued so far (`04 §5.2`). Persisted so the timestamp
    /// oracle resumes strictly monotonically after reopen/recovery — a reader's snapshot and a new
    /// committer's timestamp must never alias or regress past a durable committed version.
    pub commit_ts_hw: u64,
    /// Per-store state, indexed by [`StoreKind`](crate::store::StoreKind) `as usize` (the node, rel
    /// and prop stores plus the `strings.store` overflow heap, `04 §2.1`).
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

/// A durable **full-text index** catalog entry (`rmp` task #72).
///
/// A full-text index is identified by a server-unique **name** (unlike a node-property index, which
/// `(label_token, prop_key)` identifies), covers one node label and **one or more** string
/// properties, and is analyzed by a fixed analyzer recorded as a single byte (the
/// [`graphus_index::Analyzer`] discriminant — storage does not depend on `graphus-index`, so the
/// byte is stored verbatim and interpreted by the query layer, exactly as the histogram blobs are).
///
/// This rides the **identical** durability lifecycle as the node-property index catalog and the
/// counts/histograms: checkpointed at commit, reloaded on rollback and on open. Its presence
/// invariant is "an entry exists iff a full-text index of that name is declared". The inverted index
/// *data* itself is never persisted (it is ephemeral and rebuilt from the store on open, like the
/// derived `IndexSet`), so only this catalog entry needs durability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulltextIndexEntry {
    /// The node label-namespace token the index covers.
    pub label_token: u32,
    /// The property-key-namespace tokens the index covers, in declared order (one or more).
    pub property_tokens: Vec<u32>,
    /// The analyzer discriminant byte (the [`graphus_index::Analyzer`] `as_byte`, stored verbatim).
    pub analyzer: u8,
    /// The build state of the index (the same state machine as a node-property index).
    pub state: IndexState,
}

/// A durable **spatial (point) index** catalog entry (`rmp` task #98).
///
/// A spatial index is identified by a server-unique **name** (like a full-text index, and unlike a
/// node-property index which `(label_token, prop_key)` identifies), covers one node label and
/// **exactly one** point property, and — unlike the full-text index — carries **no analyzer**: a
/// grid spatial index simply buckets the covered point property's coordinates, so only the covered
/// label, the covered property and the build state need to be recorded.
///
/// This rides the **identical** durability lifecycle as the full-text index catalog and the
/// counts/histograms: checkpointed at commit, reloaded on rollback and on open. Its presence
/// invariant is "an entry exists iff a spatial index of that name is declared". The grid *data*
/// itself is never persisted (it is ephemeral and rebuilt from the store on open, like the derived
/// `IndexSet`), so only this catalog entry needs durability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpatialIndexEntry {
    /// The node label-namespace token the index covers.
    pub label_token: u32,
    /// The property-key-namespace token the index covers (a single point property).
    pub property_token: u32,
    /// The build state of the index (the same state machine as a node-property / full-text index).
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
}

impl ConstraintKind {
    /// The single-byte wire discriminant (`rmp` tasks #99, #100). Discriminants `4..` are reserved for
    /// a future relationship-property constraint kind.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Unique => 0,
            Self::Existence => 1,
            Self::NodeKey => 2,
            Self::PropertyType => 3,
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
            _ => None,
        }
    }
}

/// The declared value type a [`ConstraintKind::PropertyType`] constraint enforces (`rmp` task #100).
///
/// Models the subset of the openCypher type system a `IS :: <TYPE>` property-type constraint can
/// declare: the scalar types `INTEGER`, `FLOAT`, `STRING`, `BOOLEAN`, and a `LIST<...>` of an
/// (optional) element type. Storage carries this descriptor **verbatim** and never matches a value
/// against it — the query layer (`graphus-cypher`) maps each variant onto the
/// [`graphus_core::Value`](graphus_core::Value) model and performs the type check (exactly as it
/// interprets the opaque analyzer / histogram bytes). Defining it here keeps the durable
/// [`ConstraintEntry`] self-contained and lets the byte encoding live beside the other catalog blocks.
///
/// # Wire encoding
///
/// A scalar is a single tag byte; a list is the [`List`](Self::List) tag byte followed by its element
/// descriptor's own encoding (so `LIST<INTEGER>` is two bytes and a bare `LIST` — element type
/// unconstrained — is the list tag followed by the [`Any`](Self::Any) tag). [`Any`](Self::Any) exists
/// only as a list element placeholder ("any element type"); it is never a top-level constraint type.
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
    /// openCypher `LIST<inner>` — a [`Value::List`](graphus_core::Value::List) whose every element
    /// matches `inner` (a boxed element descriptor). A bare `LIST` (no element type) carries
    /// [`Any`](Self::Any) as `inner`.
    List(Box<ConstraintTypeDescriptor>),
    /// "Any type" — only ever a [`List`](Self::List) element placeholder, never a top-level type.
    Any,
}

impl ConstraintTypeDescriptor {
    /// The single tag byte for a scalar / list / any descriptor (`rmp` task #100). For a
    /// [`List`](Self::List) this is just the list tag; its element descriptor is encoded separately by
    /// [`encode`](Self::encode).
    const fn tag_byte(&self) -> u8 {
        match self {
            Self::Integer => 0,
            Self::Float => 1,
            Self::String => 2,
            Self::Boolean => 3,
            Self::List(_) => 4,
            Self::Any => 5,
        }
    }

    /// Appends the self-describing byte encoding of this descriptor to `out` (`rmp` task #100): the tag
    /// byte, followed — for a [`List`](Self::List) — by its element descriptor's own encoding.
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.tag_byte());
        if let Self::List(inner) = self {
            inner.encode(out);
        }
    }

    /// Decodes a descriptor from `bytes` starting at `cur`, advancing past it (`rmp` task #100).
    ///
    /// # Errors
    /// Returns a storage error on truncation or an unknown tag byte (a forward-incompatible image).
    fn decode(bytes: &[u8], cur: &mut usize) -> Result<Self> {
        let tag = read_u8(bytes, cur)?;
        match tag {
            0 => Ok(Self::Integer),
            1 => Ok(Self::Float),
            2 => Ok(Self::String),
            3 => Ok(Self::Boolean),
            4 => Ok(Self::List(Box::new(Self::decode(bytes, cur)?))),
            5 => Ok(Self::Any),
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
    /// The node label-namespace token the constraint covers.
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
}

impl Statistics {
    /// An empty statistics catalog (every count `0`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

    /// Adds `1` to the grand-total live-node count (`rmp` task #82). Called once per node created,
    /// labelled or not — distinct from [`inc_label`](Self::inc_label), which a node triggers once per
    /// label it carries.
    pub(crate) fn inc_node(&mut self) {
        self.total_nodes += 1;
    }

    /// Subtracts `1` from the grand-total live-node count (`rmp` task #82), called once per node
    /// deleted (at the tombstone-stamping step, not at GC reclaim).
    ///
    /// Saturates at `0` defensively: a logic slip that decremented past zero would otherwise wrap to
    /// `u64::MAX` and corrupt the catalog into an absurd cardinality the planner would trust. In a
    /// debug build the slip is caught instead.
    pub(crate) fn dec_node(&mut self) {
        Self::dec_total(&mut self.total_nodes, "total_nodes");
    }

    /// Adds `1` to the grand-total live-relationship count (`rmp` task #82). Called once per
    /// relationship created (covering both the self-loop and the normal branch of `create_rel`).
    pub(crate) fn inc_rel(&mut self) {
        self.total_relationships += 1;
    }

    /// Subtracts `1` from the grand-total live-relationship count (`rmp` task #82), called once per
    /// relationship deleted (at the tombstone-stamping step, not at GC reclaim). Saturates at `0`
    /// defensively for the same reason as [`dec_node`](Self::dec_node).
    pub(crate) fn dec_rel(&mut self) {
        Self::dec_total(&mut self.total_relationships, "total_relationships");
    }

    /// Shared grand-total decrement: `count -= 1`, saturating at `0`. In a release build an
    /// already-zero count saturates (never wraps to a huge count) so a logic slip can never silently
    /// corrupt the catalog; in a debug build it is caught (every decrement must match a prior
    /// increment of a live record).
    fn dec_total(count: &mut u64, which: &str) {
        if *count == 0 {
            debug_assert!(false, "statistics {which} decrement underflow");
            return;
        }
        *count -= 1;
    }

    /// Adds `1` to the live-node count for label `token_id`.
    pub(crate) fn inc_label(&mut self, token_id: u32) {
        *self.nodes_per_label.entry(token_id).or_insert(0) += 1;
    }

    /// Subtracts `1` from the live-node count for label `token_id`, removing the entry when it
    /// reaches `0` so equality against a fresh re-scan holds (the zero-count invariant).
    ///
    /// # Panics
    /// Panics (debug builds) if the count is already `0` or absent: that is an internal invariant
    /// violation — every decrement must correspond to a prior increment of a live node's label.
    pub(crate) fn dec_label(&mut self, token_id: u32) {
        Self::dec(&mut self.nodes_per_label, token_id);
    }

    /// Adds `1` to the live-relationship count for relationship-type `token_id`.
    pub(crate) fn inc_rel_type(&mut self, token_id: u32) {
        *self.rels_per_type.entry(token_id).or_insert(0) += 1;
    }

    /// Subtracts `1` from the live-relationship count for relationship-type `token_id`, removing the
    /// entry when it reaches `0` (the zero-count invariant).
    ///
    /// # Panics
    /// Panics (debug builds) if the count is already `0` or absent (an internal invariant violation).
    pub(crate) fn dec_rel_type(&mut self, token_id: u32) {
        Self::dec(&mut self.rels_per_type, token_id);
    }

    /// Shared decrement-with-removal: `count -= 1`, dropping the entry at `0`. In a release build a
    /// missing/zero entry saturates at `0` (never wraps to a huge count) so a logic slip can never
    /// silently corrupt the catalog into an absurd cardinality; in a debug build it is caught.
    fn dec(map: &mut BTreeMap<u32, u64>, token_id: u32) {
        match map.get_mut(&token_id) {
            Some(c) if *c > 1 => *c -= 1,
            Some(_) => {
                map.remove(&token_id);
            }
            None => {
                debug_assert!(
                    false,
                    "statistics decrement underflow for token id {token_id}"
                );
            }
        }
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
    /// constraint's `type_descriptor` left `None`. No format-version byte is needed because every prior
    /// block is length-exact and self-describing, so each parse position is unambiguous.
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
        out
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

    /// Encodes the full-text index catalog block (`rmp` task #72), appended last so a pre-#72 image
    /// (ending after the node-property index catalog) decodes to an empty full-text catalog.
    ///
    /// Layout: `n(u32) | [ name_len(u32) | name_bytes[name_len] | label_token(u32) |
    /// n_props(u32) | prop_token(u32)*n_props | analyzer(u8) | state(u8) ]*`, entries in
    /// ascending-name ([`BTreeMap`]) order so the image is deterministic.
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
            out.extend_from_slice(&entry.label_token.to_le_bytes());
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

    /// Encodes the spatial (point) index catalog block (`rmp` task #98), appended last so a pre-#98
    /// image (ending after the full-text catalog) decodes to an empty spatial catalog.
    ///
    /// Layout: `n(u32) | [ name_len(u32) | name_bytes[name_len] | label_token(u32) |
    /// property_token(u32) | state(u8) ]*`, entries in ascending-name ([`BTreeMap`]) order so the
    /// image is deterministic. Unlike the full-text block there is no analyzer byte and exactly one
    /// property token (a spatial index covers a single point property).
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
        let fulltext_indexes = Self::decode_fulltext_catalog(bytes, &mut cur)?;
        let spatial_indexes = Self::decode_spatial_catalog(bytes, &mut cur)?;
        let mut constraints = Self::decode_constraint_catalog(bytes, &mut cur)?;
        // Merge the trailing property-type descriptor block (`rmp` task #100) back onto its named
        // constraints. A pre-#100 image ends after the constraint catalog, so this block decodes empty
        // and every entry keeps the `type_descriptor: None` the catalog decode already set.
        Self::decode_constraint_type_block(bytes, &mut cur, &mut constraints)?;
        Ok(Self {
            total_nodes,
            total_relationships,
            nodes_per_label,
            rels_per_type,
            node_prop_histograms,
            node_property_indexes,
            fulltext_indexes,
            spatial_indexes,
            constraints,
        })
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
            let label_token = read_u32(bytes, cur)?;
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
                    FulltextIndexEntry {
                        label_token,
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
                    SpatialIndexEntry {
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
        for s in &self.stores {
            out.extend_from_slice(&s.high_water.to_le_bytes());
            let fl = s.free_list.encode();
            out.extend_from_slice(&(fl.len() as u32).to_le_bytes());
            out.extend_from_slice(&fl);
            out.extend_from_slice(&(s.device_pages.len() as u32).to_le_bytes());
            for &p in &s.device_pages {
                out.extend_from_slice(&p.to_le_bytes());
            }
        }
        let tok = self.tokens.encode();
        out.extend_from_slice(&(tok.len() as u32).to_le_bytes());
        out.extend_from_slice(&tok);
        // Statistics are appended after the tokens (`rmp` task #79). Length-prefixed like the token
        // image so a future field can follow without ambiguity.
        let stats = self.statistics.encode();
        out.extend_from_slice(&(stats.len() as u32).to_le_bytes());
        out.extend_from_slice(&stats);
        Ok(out)
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
        for (idx, s) in stores.iter_mut().enumerate() {
            s.high_water = read_u64(bytes, &mut cur)?;
            let fl_len = read_u32(bytes, &mut cur)? as usize;
            let fl_end = take(bytes, &mut cur, fl_len)?;
            s.free_list = FreeList::decode(&bytes[cur - fl_len..fl_end])?;
            let n_pages = read_u32(bytes, &mut cur)? as usize;
            // Cap by the bytes remaining: each device-page entry is an 8-byte `read_u64`, so the real
            // count cannot exceed `bytes.len()`. Without the cap a forged `n_pages = 0xFFFF_FFFF`
            // forces a multi-GiB allocation (OOM) before the per-element reads validate the input.
            s.device_pages = Vec::with_capacity(n_pages.min(bytes.len()));
            for _ in 0..n_pages {
                s.device_pages.push(read_u64(bytes, &mut cur)?);
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
                _ => crate::heap::STRINGS_RECORD_SIZE,
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
        let tok_len = read_u32(bytes, &mut cur)? as usize;
        let tok_end = take(bytes, &mut cur, tok_len)?;
        let tokens = TokenStore::decode(&bytes[cur - tok_len..tok_end])?;
        // Statistics follow the tokens (`rmp` task #79).
        let stats_len = read_u32(bytes, &mut cur)? as usize;
        let stats_end = take(bytes, &mut cur, stats_len)?;
        let statistics = Statistics::decode(&bytes[cur - stats_len..stats_end])?;
        Ok(Self {
            element_id_next,
            commit_ts_hw,
            stores,
            tokens,
            statistics,
        })
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
                label_token: 0,
                property_token: 3,
                state: IndexState::Online,
            },
        );
        m.statistics.set_spatial_index(
            "by_home".to_owned(),
            SpatialIndexEntry {
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
                label_token: 0,
                property_token: 3,
                state: IndexState::Online,
            })
        );
        assert_eq!(
            back.statistics.spatial_index("by_home"),
            Some(&SpatialIndexEntry {
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
                label_token: 1,
                property_token: 2,
                state: IndexState::Online,
            },
        );
        assert_eq!(Statistics::decode(&s.encode()).unwrap(), s);
        s.set_spatial_index(
            "b".to_owned(),
            SpatialIndexEntry {
                label_token: 3,
                property_token: 4,
                state: IndexState::Populating,
            },
        );
        // Mixing in a full-text entry proves the spatial block is read AFTER the full-text block.
        s.set_fulltext_index(
            "ft".to_owned(),
            FulltextIndexEntry {
                label_token: 9,
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
                label_token: 9,
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
            let mut s = Statistics::new();
            s.dec_node();
            s.dec_rel();
            assert_eq!(s.total_nodes(), 0);
            assert_eq!(s.total_relationships(), 0);
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

    #[test]
    fn statistics_fulltext_catalog_round_trips() {
        // A full-text catalog with multiple indexes (varied analyzers, property arities, states)
        // round-trips, and rides after the node-property index catalog (set one to prove ordering).
        let mut s = Statistics::new();
        s.set_node_property_index(1, 2, IndexState::Online);
        s.set_fulltext_index(
            "articles".to_owned(),
            FulltextIndexEntry {
                label_token: 3,
                property_tokens: vec![7, 8],
                analyzer: 0, // standard
                state: IndexState::Online,
            },
        );
        s.set_fulltext_index(
            "tags".to_owned(),
            FulltextIndexEntry {
                label_token: 5,
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
                label_token: 1,
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
