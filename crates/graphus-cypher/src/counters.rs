//! Exact side-effect **query counters** for a Cypher statement (`rmp` task #510).
//!
//! Every write a statement applies through the [`GraphAccess`](crate::graph_access::GraphAccess)
//! seam is tallied into a [`QueryCounters`], queryable after execution via
//! [`GraphAccess::write_counters`](crate::graph_access::GraphAccess::write_counters). These counters
//! are the foundation a later task wires to the Bolt / REST result summary (`metadata.stats`); this
//! module is purely the cypher-layer accumulation, with no wire coupling.
//!
//! # Counting model: Bolt operation-count, not openCypher observability
//!
//! Graphus has **two** distinct side-effect models, and they intentionally disagree:
//!
//! - **[`QueryCounters`] (this module)** is the **Bolt / Neo4j operation-count** model: it tallies
//!   the operations a statement actually *applied*. `CREATE (n) DELETE n` reports
//!   `nodes_created = 1, nodes_deleted = 1` — two operations happened, even though the net graph
//!   change is nothing. This is what the official Neo4j driver ecosystem expects in a result
//!   summary's `SummaryCounters`.
//! - The **in-repo openCypher TCK runner** (`graphus-tck`) measures side effects by **diffing graph
//!   snapshots** (the openCypher *observability* model): `CREATE (n) DELETE n` is **no** side effect
//!   (the before/after graphs are identical). That model is correct for the TCK and is **not** what
//!   this struct computes — the two are deliberately separate and must not be reconciled.
//!
//! # Neo4j counting semantics (authoritative)
//!
//! The rules below are taken from the Neo4j `SummaryCounters` contract and are enforced at the
//! lowest shared write chokepoints of each [`GraphAccess`](crate::graph_access::GraphAccess)
//! implementation:
//!
//! - `properties_set` counts a property *write*, **including re-setting a property to the value it
//!   already holds** (`SET n.p = n.p` over a matched node still counts). Setting a property to `null`
//!   (`SET n.p = null`) and `REMOVE n.p` are **removals**, not sets, and do **not** count (there is no
//!   "properties removed" counter in the data-counter set Graphus emits).
//! - labels: adding a label a node already carries counts `0`; removing a label a node does not carry
//!   counts `0` (`labels_added` / `labels_removed` count only the bits that actually flipped).
//! - `nodes_deleted` / `relationships_deleted` count only deletes that actually removed a live,
//!   visible entity; deleting the same entity twice in one statement counts **once** (the second
//!   delete is an idempotent no-op at the seam). `DETACH DELETE` deletes each incident relationship
//!   before the node, so each incident relationship is counted.
//! - `MERGE` that *matches* an existing pattern creates nothing (`0` creates); `MERGE` that *creates*
//!   counts the create. `ON CREATE SET` / `ON MATCH SET` count as ordinary property sets.

/// The exact side effects a Cypher statement applied, in the Bolt / Neo4j operation-count model.
///
/// All fields are monotonically-accumulated operation tallies for **one** statement's execution (the
/// seam is reset per statement, so a fresh transaction-scoped [`GraphAccess`] starts at
/// [`QueryCounters::default`]). See the [module docs](crate::counters) for the exact Neo4j semantics
/// each field follows.
///
/// # Examples
///
/// ```
/// use graphus_cypher::QueryCounters;
///
/// let mut a = QueryCounters {
///     nodes_created: 2,
///     properties_set: 3,
///     ..Default::default()
/// };
/// assert!(a.contains_updates());
/// assert!(!a.is_empty());
///
/// let b = QueryCounters {
///     relationships_created: 1,
///     ..Default::default()
/// };
/// a.add(&b);
/// assert_eq!(a.nodes_created, 2);
/// assert_eq!(a.relationships_created, 1);
///
/// assert!(QueryCounters::default().is_empty());
/// assert!(!QueryCounters::default().contains_updates());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
pub struct QueryCounters {
    /// Nodes created (`CREATE`, and the create branch of `MERGE`).
    pub nodes_created: u64,
    /// Nodes deleted (counted once per actually-removed live node; idempotent double-delete = 1).
    pub nodes_deleted: u64,
    /// Relationships created.
    pub relationships_created: u64,
    /// Relationships deleted (counted once per actually-removed live relationship).
    pub relationships_deleted: u64,
    /// Properties set — **including** re-setting to an equal value; **excluding** `null`-set / remove.
    pub properties_set: u64,
    /// Labels added (only bits that were not already set; idempotent re-add = 0).
    pub labels_added: u64,
    /// Labels removed (only bits that were actually present; removing an absent label = 0).
    pub labels_removed: u64,
}

impl QueryCounters {
    /// Adds `other` into `self` field-wise (saturating is unnecessary — a single statement's
    /// operation count cannot approach [`u64::MAX`]).
    ///
    /// Used to fold the counters of several statements into a transaction-wide total, or to merge a
    /// sub-scope's tally into its parent.
    pub fn add(&mut self, other: &QueryCounters) {
        self.nodes_created += other.nodes_created;
        self.nodes_deleted += other.nodes_deleted;
        self.relationships_created += other.relationships_created;
        self.relationships_deleted += other.relationships_deleted;
        self.properties_set += other.properties_set;
        self.labels_added += other.labels_added;
        self.labels_removed += other.labels_removed;
    }

    /// Whether **no** side effect was recorded (every field is zero).
    ///
    /// This is the signal the wire layer uses to decide whether to emit a `stats` block at all: an
    /// empty counter set means a read-only statement, whose Bolt summary carries no counters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == QueryCounters::default()
    }

    /// Whether the statement applied **any** update (at least one field is non-zero).
    ///
    /// The complement of [`is_empty`](Self::is_empty); named to mirror Neo4j's
    /// `SummaryCounters.containsUpdates()`.
    #[must_use]
    pub fn contains_updates(&self) -> bool {
        !self.is_empty()
    }
}
