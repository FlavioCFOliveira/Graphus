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
    /// an empty full-text catalog. No format-version byte is needed because every prior block is
    /// length-exact and self-describing, so each parse position is unambiguous.
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
        Ok(Self {
            total_nodes,
            total_relationships,
            nodes_per_label,
            rels_per_type,
            node_prop_histograms,
            node_property_indexes,
            fulltext_indexes,
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
            let mut property_tokens = Vec::with_capacity(n_props);
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
        for s in &mut stores {
            s.high_water = read_u64(bytes, &mut cur)?;
            let fl_len = read_u32(bytes, &mut cur)? as usize;
            let fl_end = take(bytes, &mut cur, fl_len)?;
            s.free_list = FreeList::decode(&bytes[cur - fl_len..fl_end])?;
            let n_pages = read_u32(bytes, &mut cur)? as usize;
            s.device_pages = Vec::with_capacity(n_pages);
            for _ in 0..n_pages {
                s.device_pages.push(read_u64(bytes, &mut cur)?);
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
