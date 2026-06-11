//! The planner's **statistics seam** (`00-overview` §6 — the Phase 2 cost-based optimiser foundation).
//!
//! [`Statistics`] is the narrow, object-safe seam through which the cardinality estimator
//! ([`crate::cardinality`]) reads the *shape* of the live graph — how many nodes and relationships
//! exist, and how they distribute across labels and relationship types. It deliberately exposes
//! **only counts**, never the data itself: an estimator must never touch user values, and a count is
//! all a row-cardinality model needs to turn a logical operator into an estimated output size.
//!
//! # Why a seam (not a concrete type)
//!
//! Mirroring [`crate::graph_access::GraphAccess`], the estimator depends on this trait alone, so it
//! can be exercised against the deterministic in-memory [`crate::graph_access::MemGraph`] here while
//! the *real* counts come later from the `graphus-storage` / `graphus-index` statistics catalogue
//! (a follow-up sub-task) — without the estimator changing. A [`GraphAccess`](crate::graph_access::GraphAccess)
//! implementation surfaces its statistics through
//! [`GraphAccess::statistics`](crate::graph_access::GraphAccess::statistics), which returns `None`
//! when the backend keeps no counts (the estimator then falls back to documented constants; see
//! [`crate::cardinality`]).
//!
//! # Snapshot semantics
//!
//! Every method returns a **point-in-time** count: the value reflects the graph as the implementation
//! sees it at the moment of the call (for [`MemGraph`](crate::graph_access::MemGraph), the live map;
//! for the real backend, the transaction's snapshot). The estimator treats the returned numbers as a
//! consistent snapshot for the duration of one planning pass; it never assumes they stay valid across
//! graph mutations.

/// Read-only **count** statistics about a graph, for cardinality estimation
/// ([`crate::cardinality`]).
///
/// All counts are a **point-in-time snapshot** (see the [module docs](self)). An implementation that
/// knows its full contents (such as [`MemGraph`](crate::graph_access::MemGraph)) answers every query
/// exactly; one backed by sampled or approximate catalogue statistics may answer approximately, and
/// one that tracks no per-label / per-type breakdown returns `None` from the label/type queries to
/// signal "unknown" (the estimator then applies a documented selectivity fallback).
///
/// The trait is **object-safe**: it is consumed as `&dyn Statistics` so the planner can thread an
/// optional statistics source through without monomorphising on the concrete backend.
pub trait Statistics {
    /// The total number of nodes in the graph snapshot.
    ///
    /// Always a concrete count (never `None`): the estimator needs a total to scale label
    /// selectivities against, so every implementation must be able to report one.
    fn total_nodes(&self) -> u64;

    /// The number of nodes carrying `label`, or `None` if the implementation does not track
    /// per-label counts.
    ///
    /// `None` means **unknown** — the caller should fall back to a documented selectivity estimate
    /// (see [`crate::cardinality::DEFAULT_LABEL_SELECTIVITY`]). A label that genuinely matches no
    /// node returns `Some(0)`, which is *not* the same as unknown: `Some(0)` is an exact answer.
    fn nodes_with_label(&self, label: &str) -> Option<u64>;

    /// The total number of relationships in the graph snapshot.
    ///
    /// Always a concrete count (never `None`), for the same reason as [`total_nodes`](Self::total_nodes).
    fn total_relationships(&self) -> u64;

    /// The number of relationships of type `rel_type`, or `None` if the implementation does not track
    /// per-type counts.
    ///
    /// As with [`nodes_with_label`](Self::nodes_with_label), `None` means **unknown** (fall back to a
    /// documented estimate) while `Some(0)` is an exact "no such relationship".
    fn relationships_with_type(&self, rel_type: &str) -> Option<u64>;
}
