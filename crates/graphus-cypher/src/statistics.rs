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
//!
//! # Property selectivity (the histogram seam)
//!
//! Beyond the bare label/type counts, the trait exposes three **property-selectivity** methods —
//! [`estimate_nodes_label_property_eq`](Statistics::estimate_nodes_label_property_eq),
//! [`estimate_nodes_label_property_range`](Statistics::estimate_nodes_label_property_range) and
//! [`distinct_label_property_values`](Statistics::distinct_label_property_values) — through which the
//! estimator reads how a labelled property's values are *distributed* (not just how many nodes carry
//! the label). They back the cardinality estimator's filter selectivity with **equi-depth histograms**
//! ([`graphus_index::histogram::PropertyHistogram`]): a `MATCH (n:Person) WHERE n.age = 30` no longer
//! collapses to a flat constant, but to an estimate derived from the real value distribution.
//!
//! Two contracts make these methods safe to consume:
//!
//! - **Absolute count, never a fraction.** Each estimate is an **absolute row count** (e.g. "≈ 12
//!   nodes match"), *not* a selectivity fraction. The estimator multiplies fractions elsewhere; these
//!   methods already return the product, so the caller uses the value directly (clamped to its input
//!   cardinality — a filter never adds rows). This mirrors [`nodes_with_label`](Statistics::nodes_with_label),
//!   which is likewise an absolute count.
//! - **`None` means "no estimate; fall back".** A method returns `None` when the implementation keeps
//!   no histogram for that `label.property`, or when the query value is not index-encodable (`Null` /
//!   `List` / `Map` cannot be ordered, so no histogram can place them). The estimator then reverts to
//!   its documented constant ([`crate::cardinality::DEFAULT_PREDICATE_SELECTIVITY`]). A *populated*
//!   histogram over an absent value legitimately returns `Some(0.0)` — an exact "nothing matches",
//!   which is **not** the same as the `None` "unknown" sentinel (exactly as `Some(0)` versus `None`
//!   on the count methods).
//!
//! All three property methods share the snapshot semantics above: the histogram reflects the graph at
//! the instant of the call.

use graphus_core::Value;

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

    /// Estimated number of nodes carrying `label` whose `property` **equals** `value` — an **absolute
    /// row count**, not a fraction (see the [module docs](self)).
    ///
    /// Backed by an equi-depth histogram over `label.property`
    /// ([`graphus_index::histogram::PropertyHistogram::estimate_eq`]). Returns:
    ///
    /// - `Some(count)` when a histogram exists and `value` is index-encodable — `count` is the
    ///   histogram's equality estimate (`>= 0.0`; `Some(0.0)` is an exact "no match", e.g. a value
    ///   outside the observed range or a label that no node carries).
    /// - `None` when the implementation keeps **no** histogram for this `label.property`, or `value`
    ///   is not index-encodable (`Null` / `List` / `Map`). The estimator then falls back to its
    ///   documented constant ([`crate::cardinality::DEFAULT_PREDICATE_SELECTIVITY`]).
    ///
    /// The **default** implementation returns `None`, so an implementor that tracks only counts (or a
    /// test double) keeps compiling and transparently exercises the estimator's fallback path.
    fn estimate_nodes_label_property_eq(
        &self,
        _label: &str,
        _property: &str,
        _value: &Value,
    ) -> Option<f64> {
        None
    }

    /// Estimated number of nodes carrying `label` whose `property` lies in the given range — an
    /// **absolute row count**, not a fraction (see the [module docs](self)).
    ///
    /// The range may be half-open or fully unbounded: a `None` bound is open on that side, and the
    /// `*_inclusive` flag selects `>`/`>=` (low) or `<`/`<=` (high). Backed by
    /// [`graphus_index::histogram::PropertyHistogram::estimate_range`]. Returns:
    ///
    /// - `Some(count)` when a histogram exists and every **present** bound is index-encodable —
    ///   `count` is the histogram's range estimate (`>= 0.0`; `Some(0.0)` is an exact "no match").
    /// - `None` when no histogram exists for this `label.property`, or a **present** bound value is
    ///   not index-encodable (`Null` / `List` / `Map`). The estimator then falls back to its
    ///   documented constant.
    ///
    /// The **default** implementation returns `None` (the documented fallback).
    fn estimate_nodes_label_property_range(
        &self,
        _label: &str,
        _property: &str,
        _lo: Option<&Value>,
        _lo_inclusive: bool,
        _hi: Option<&Value>,
        _hi_inclusive: bool,
    ) -> Option<f64> {
        None
    }

    /// The number of **distinct** indexed values for `label.property`, or `None` if the implementation
    /// keeps no histogram for it.
    ///
    /// Backed by [`graphus_index::histogram::PropertyHistogram::distinct`]. A populated histogram with
    /// no values for the column (no node carries `label` with `property` set) is an exact `Some(0)`,
    /// *not* the `None` "unknown" sentinel. The estimator does not yet branch on this value; it is
    /// exposed for the upcoming cost model and for cross-checking selectivity in tests.
    ///
    /// The **default** implementation returns `None`.
    fn distinct_label_property_values(&self, _label: &str, _property: &str) -> Option<u64> {
        None
    }
}
