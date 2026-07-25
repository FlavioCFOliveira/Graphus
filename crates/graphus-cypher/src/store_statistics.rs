//! Shared **store-catalogue statistics readers** (`rmp` tasks #79/#81/#82): the count and histogram
//! lookups behind every [`Statistics`](crate::statistics::Statistics) implementation that answers
//! from a real [`RecordStore`]'s durable catalogue.
//!
//! Two seams answer the planner from the same catalogue:
//!
//! * [`RecordStoreGraph`](crate::record_graph::RecordStoreGraph) — the per-statement executor seam.
//!   It owns an error-capture channel, so a *corrupt* stored histogram is captured (the caller's
//!   `take_error` surfaces it) and reported as "no estimate".
//! * [`CoordinatorStatistics`](crate::coordinator::CoordinatorStatistics) — the compile-time seam the
//!   production paths use (`rmp` task #82). It has **no** error channel, so a corrupt histogram
//!   degrades silently to the estimator's constant fallback (mis-costing a plan is acceptable;
//!   panicking or failing compilation over an advisory statistic is not).
//!
//! Factoring the lookups here keeps the two impls byte-for-byte agreed on the load-bearing
//! semantics — a never-interned token is an exact-zero count and "no histogram"; an unindexable
//! query value is the `None` "fall back" sentinel — while leaving each seam its own error-delivery
//! policy (that policy difference is exactly why [`decode_histogram`] returns
//! `Result<Option<_>, _>` instead of collapsing the error itself).

use graphus_core::Value;
use graphus_core::error::GraphusError;
use graphus_index::histogram::PropertyHistogram;
use graphus_index::keycodec::encode_single;
use graphus_io::BlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::LogSink;

/// The number of nodes carrying `label`, from the store's durable per-label catalogue counts
/// (`rmp` task #79).
///
/// A label that was never interned can have no live node, so it is an **exact zero** — the
/// `Statistics` callers wrap this in `Some(..)`, never the `None` "unknown" sentinel (the backend
/// genuinely tracks per-label counts). The read resolves the token *without* interning: asking for a
/// count must not mint a durable token.
pub(crate) fn nodes_with_label<D: BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    label: &str,
) -> u64 {
    store
        .token_id(Namespace::Label, label)
        .map_or(0, |token| store.node_count_for_label(token))
}

/// The number of relationships of type `rel_type`, from the durable per-type catalogue counts
/// (`rmp` task #79). A never-interned type is an exact zero (see [`nodes_with_label`]).
pub(crate) fn relationships_with_type<D: BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    rel_type: &str,
) -> u64 {
    store
        .token_id(Namespace::RelType, rel_type)
        .map_or(0, |token| store.rel_count_for_type(token))
}

/// The `(startLabel, type)` directional count, or `None` when this catalogue has no directional
/// projections at all (`rmp` task #856).
///
/// The `None` is load-bearing and is why this cannot simply return `0`: a catalogue that predates the
/// projections, or that has never been backfilled, holds an empty map, and a consumer reading its zero
/// as a real count would estimate a fan-out of nothing rather than falling back to the graph-wide
/// degree. Once the projections hold anything, an absent key is a genuine zero — a never-interned label
/// or type included, since neither can have a live relationship.
pub(crate) fn rels_from_label_with_type<D: BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    start_label: &str,
    rel_type: &str,
) -> Option<u64> {
    if !store.has_directional_rel_counts() {
        return None;
    }
    let label = store.token_id(Namespace::Label, start_label);
    let ty = store.token_id(Namespace::RelType, rel_type);
    match (label, ty) {
        (Some(l), Some(t)) => Some(store.rel_count_for_start_label_type(l, t)),
        // A never-interned label or type can have no live relationship: an exact zero, not unknown.
        _ => Some(0),
    }
}

/// The `(type, endLabel)` directional count, or `None` when untracked — the mirror of
/// [`rels_from_label_with_type`] (`rmp` task #856).
pub(crate) fn rels_with_type_to_label<D: BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    rel_type: &str,
    end_label: &str,
) -> Option<u64> {
    if !store.has_directional_rel_counts() {
        return None;
    }
    let ty = store.token_id(Namespace::RelType, rel_type);
    let label = store.token_id(Namespace::Label, end_label);
    match (ty, label) {
        (Some(t), Some(l)) => Some(store.rel_count_for_type_end_label(t, l)),
        _ => Some(0),
    }
}

/// Decodes the durable histogram stored for `(label, property)` (`rmp` task #81).
///
/// Returns:
///
/// * `Ok(None)` — the label / property token was never interned, or no histogram is recorded for
///   the pair (the column was never `ANALYZE`d): the estimator falls back to its constant.
/// * `Ok(Some(hist))` — an **owned** decoded histogram, so no borrow of the store escapes through
///   the return value.
/// * `Err(..)` — the stored bytes are corrupt or truncated. The error is returned (not swallowed)
///   so each caller applies its own policy: the statement seam captures it into its error channel,
///   the coordinator seam degrades it to the fallback (see the [module docs](self)).
pub(crate) fn decode_histogram<D: BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    label: &str,
    property: &str,
) -> Result<Option<PropertyHistogram>, GraphusError> {
    let Some(label_token) = store.token_id(Namespace::Label, label) else {
        return Ok(None);
    };
    let Some(prop_token) = store.token_id(Namespace::PropKey, property) else {
        return Ok(None);
    };
    let Some(bytes) = store.property_histogram(label_token, prop_token) else {
        return Ok(None);
    };
    PropertyHistogram::decode(bytes).map(Some).map_err(|e| {
        GraphusError::Storage(format!(
            "corrupt property histogram for ({label}.{property}): {e}"
        ))
    })
}

/// The histogram's equality estimate for `value`, or `None` when `value` is not index-encodable
/// (`Null` / `List` / `Map` cannot be placed in encoded order — the documented "fall back"
/// sentinel of [`Statistics::estimate_nodes_label_property_eq`](crate::statistics::Statistics::estimate_nodes_label_property_eq)).
pub(crate) fn histogram_estimate_eq(hist: &PropertyHistogram, value: &Value) -> Option<f64> {
    let encoded = encode_single(value).ok()?;
    Some(hist.estimate_eq(&encoded))
}

/// The histogram's range estimate over `[lo, hi]` with per-bound inclusivity, or `None` when a
/// **present** bound is not index-encodable (the range cannot be placed soundly, so fall back
/// rather than silently dropping the bound). An *absent* bound is simply open on that side:
/// `transpose` turns `Option<Result<_>>` into `Result<Option<_>>`, so only a present-but-
/// unindexable bound short-circuits to `None`.
pub(crate) fn histogram_estimate_range(
    hist: &PropertyHistogram,
    lo: Option<&Value>,
    lo_inclusive: bool,
    hi: Option<&Value>,
    hi_inclusive: bool,
) -> Option<f64> {
    let lo_enc = lo.map(encode_single).transpose().ok()?;
    let hi_enc = hi.map(encode_single).transpose().ok()?;
    Some(hist.estimate_range(
        lo_enc.as_deref(),
        lo_inclusive,
        hi_enc.as_deref(),
        hi_inclusive,
    ))
}
