//! `BitmapIndex` — a **derived, in-memory** Roaring-bitmap secondary index for **low-cardinality**
//! node-property columns (`rmp` task #328).
//!
//! # Why a bitmap (and only for low cardinality)
//!
//! A [`PropertyIndex`](crate::PropertyIndex) stores one `(token, value) → rid` posting per row in a
//! B+-tree: 16–24 bytes per entry, and a multi-predicate conjunction (`n.a = x AND n.b = y`) becomes
//! one index seek followed by a per-row `Filter`. For a **low-cardinality** column (a boolean, an
//! enum-like string, a status flag — a handful of distinct values over many rows) a Roaring bitmap
//! instead stores, per distinct value, a compressed bitmap of the node ids that carry it: on the
//! order of **~1 bit per row** for a two-value column (≈100× smaller than the B+-tree postings), and
//! two predicates intersect with a single `RoaringTreemap & RoaringTreemap` in microseconds rather
//! than a seek-plus-scan. That is the entire point of this index, and the reason it is **gated
//! strictly to low cardinality**: on a high-cardinality column (near-unique values) each bitmap holds
//! one or a few ids, the per-value overhead dominates, and the B+-tree — which also serves *range*
//! predicates the bitmap cannot — is the right structure.
//!
//! # Cardinality gate (`rmp` task #453, F-IDX-5)
//!
//! Declaration is gated by an **exact runtime distinct-value cap** ([`MAX_DISTINCT_VALUES`]). The
//! caller (`TxnCoordinator::declare_bitmap_index`) populates the index by scanning the store and, if
//! the live distinct-value count exceeds the cap, **refuses** the declaration (it tears the half-built
//! bitmap down and returns a clear error) rather than letting one `RoaringTreemap`-per-value structure
//! grow unbounded on a near-unique column — an out-of-memory footgun. The cap is checked against the
//! true built cardinality ([`BitmapIndex::distinct`]), not an estimate, so it is exact regardless of
//! whether a cost histogram exists for the column.
//!
//! # Lifecycle: derived, never persisted (the candidate contract)
//!
//! Like the full-text inverted index ([`crate::fulltext`]) and the spatial grid
//! ([`crate::spatial`]), a `BitmapIndex` is a **derived in-memory accelerator**: it is rebuilt by
//! scanning the authoritative record store on open, it is **never persisted, never WAL-logged, never
//! recovered**, and it adds **zero** durability / ACID / recovery surface. A seek returns a
//! **candidate** `Vec<u64>` of node ids; the caller re-checks each candidate's MVCC visibility and
//! the exact predicate before emitting a row, exactly as it does for every other index kind.
//!
//! Because it is used as a **candidate source** (the membership the caller iterates), the bitmap must
//! be kept **membership-exact** under writes: a stale bitmap that *omits* a matching node would make
//! the caller miss a row (a subset — never correct), unlike the read-only
//! [`ColumnCache`](../../graphus_cypher/column_cache/index.html) where staleness only triggers a
//! fallback read. Maintenance is therefore a wholesale per-node re-index on every write (mirroring
//! the spatial grid): the node is removed from every value-bitmap of the column and re-inserted under
//! its current value (or simply removed if it lost the covered label / value). A *superset* (a node
//! left in a bitmap whose value has since changed, before its re-index runs) is harmless — the
//! caller's predicate re-check drops it.

use std::collections::HashMap;

use graphus_core::Value;
use roaring::RoaringTreemap;

use crate::keycodec;

/// The maximum number of **distinct values** a bitmap index may hold (`rmp` task #453, F-IDX-5).
///
/// A bitmap index is for *low-cardinality* columns — booleans, enums, status flags: a handful of
/// distinct values over many rows. Each distinct value costs one [`RoaringTreemap`] (a B-tree of
/// containers), so an unbounded distinct count on a near-unique column would let the index grow to one
/// (or more) container per row — an out-of-memory footgun, and the regime where the B+-tree property
/// index (which also serves ranges) is the right structure. `1024` is a deliberately generous ceiling:
/// it comfortably admits every genuine low-cardinality column (a country code, an HTTP status, an enum
/// of a few hundred members) while still bounding a near-unique column's blow-up to a small, fixed
/// number of bitmaps. The declaration path enforces it against the **true built** cardinality, so it
/// is exact (not an estimate). A column above the cap is refused, not silently capped, so the operator
/// learns the column is unsuited to a bitmap index.
pub const MAX_DISTINCT_VALUES: usize = 1024;

/// A low-cardinality Roaring-bitmap index over one node-property column: a map from each distinct
/// **encoded value** to the [`RoaringTreemap`] of node ids that currently carry it.
///
/// Node ids are the store's physical record ids — `u64`, sparse and up to 64-bit — so the 64-bit
/// [`RoaringTreemap`] (a B-tree of 32-bit `RoaringBitmap` containers keyed by the id's high 32 bits)
/// is the correct bitmap type; a 32-bit `RoaringBitmap` could not address the id space. Values are
/// keyed by [`keycodec::encode_single`], the same canonical encoding the B+-tree property index uses,
/// so two values that are equal under Cypher semantics map to the same bitmap.
#[derive(Default)]
#[must_use]
pub struct BitmapIndex {
    /// `encode_single(value) → ids carrying that value`. An empty bitmap is never retained (a value
    /// whose last id is removed drops out of the map), so [`Self::distinct`] is exact.
    by_value: HashMap<Vec<u8>, RoaringTreemap>,
}

impl BitmapIndex {
    /// An empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that node `id` currently carries `value`. A `Null` (or otherwise unindexable) value is
    /// silently skipped — `Null` is never a stored property value, exactly as the B+-tree property
    /// index treats it as absent.
    pub fn insert(&mut self, value: &Value, id: u64) {
        let Ok(key) = keycodec::encode_single(value) else {
            return; // unindexable value (e.g. Null) — treated as absent, like PropertyIndex.
        };
        self.by_value.entry(key).or_default().insert(id);
    }

    /// Removes node `id` from `value`'s bitmap, returning whether it was present. A value-bitmap that
    /// becomes empty is dropped so the distinct-value count stays exact.
    pub fn remove(&mut self, value: &Value, id: u64) -> bool {
        let Ok(key) = keycodec::encode_single(value) else {
            return false;
        };
        let mut removed = false;
        if let Some(bm) = self.by_value.get_mut(&key) {
            removed = bm.remove(id);
            if bm.is_empty() {
                self.by_value.remove(&key);
            }
        }
        removed
    }

    /// Removes node `id` from **every** value-bitmap of this column (used by the wholesale per-node
    /// re-index when the node's prior value is unknown — a label loss, a delete, or any value change).
    /// Cheap because the column is low-cardinality (few bitmaps). Empty bitmaps are dropped.
    pub fn remove_node_everywhere(&mut self, id: u64) {
        self.by_value.retain(|_, bm| {
            bm.remove(id);
            !bm.is_empty()
        });
    }

    /// Candidate node ids carrying `value`, ascending. An absent value yields an empty `Vec`. The
    /// caller re-checks visibility + the exact predicate (a returned id may since have changed value
    /// — a harmless superset).
    ///
    /// This is a thin eager wrapper over [`Self::seek_eq_iter`], kept for callers/tests that want an
    /// owned `Vec`. A caller that re-checks ids one at a time should prefer [`Self::seek_eq_iter`] to
    /// avoid materializing a potentially multi-million-id flat `Vec` (the whole point of the compressed
    /// bitmap on a low-cardinality column).
    #[must_use]
    pub fn seek_eq(&self, value: &Value) -> Vec<u64> {
        self.seek_eq_iter(value)
            .map(Iterator::collect)
            .unwrap_or_default()
    }

    /// Streaming form of [`Self::seek_eq`]: a **lazy** ascending iterator over the candidate node ids
    /// carrying `value`, borrowing the value-bitmap in place — `None` if the value is absent or
    /// unindexable. The caller drives MVCC visibility + predicate re-check **per id**, exactly as the
    /// eager `seek_eq().into_iter()` did, but without ever collecting the ids into a flat `Vec` first.
    /// The ids are yielded in the same ascending order as [`Self::seek_eq`] (Roaring iterates
    /// ascending), so the candidate set is identical.
    #[must_use]
    pub fn seek_eq_iter(&self, value: &Value) -> Option<impl Iterator<Item = u64> + '_> {
        let key = keycodec::encode_single(value).ok()?;
        self.by_value.get(&key).map(RoaringTreemap::iter)
    }

    /// The raw [`RoaringTreemap`] of node ids carrying `value`, for an in-bitmap intersection across
    /// columns (the multi-predicate-AND fast path — see [`intersect`]). `None` if the value is absent
    /// or unindexable.
    #[must_use]
    pub fn bitmap_for(&self, value: &Value) -> Option<&RoaringTreemap> {
        let key = keycodec::encode_single(value).ok()?;
        self.by_value.get(&key)
    }

    /// The number of distinct values currently indexed (the column's live cardinality).
    #[must_use]
    pub fn distinct(&self) -> usize {
        self.by_value.len()
    }

    /// The total number of `(value, id)` memberships across all values (the indexed row count).
    #[must_use]
    pub fn total(&self) -> u64 {
        self.by_value.values().map(RoaringTreemap::len).sum()
    }

    /// The serialized size in bytes of all the column's bitmaps — the compressed posting footprint,
    /// used by the measurement harness to compare against the B+-tree postings.
    #[must_use]
    pub fn serialized_bytes(&self) -> u64 {
        self.by_value
            .values()
            .map(RoaringTreemap::serialized_size)
            .map(|s| s as u64)
            .sum()
    }
}

/// Intersects a set of value-bitmaps (one per conjoined equality predicate) into the candidate node
/// ids common to **all** of them, ascending — the multi-predicate-AND fast path (`n.a = x AND n.b =
/// y`). A `None` in `bitmaps` means that predicate's value is absent from its column, so the
/// conjunction is provably empty (an empty `Vec`). The id-set AND happens entirely inside Roaring (a
/// merge of sorted containers), never materializing the per-predicate candidate lists.
#[must_use]
pub fn intersect(bitmaps: &[Option<&RoaringTreemap>]) -> Vec<u64> {
    intersect_treemap(bitmaps).iter().collect()
}

/// Streaming form of [`intersect`]: returns the AND of the value-bitmaps as an owned
/// [`RoaringTreemap`] so the caller can iterate the candidates **lazily** (`.iter()`) and re-check
/// MVCC visibility id-by-id, instead of first collecting them into a flat `Vec<u64>` — for the
/// low-cardinality columns this index targets the conjunction can still be large, and the flat `Vec`
/// is exactly the allocation we want to avoid. The id-set AND happens entirely inside Roaring (a merge
/// of sorted containers), never materializing the per-predicate candidate lists. The yielded ids are
/// the same set, ascending, as [`intersect`].
#[must_use]
pub fn intersect_treemap(bitmaps: &[Option<&RoaringTreemap>]) -> RoaringTreemap {
    if bitmaps.is_empty() {
        return RoaringTreemap::new();
    }
    // Any absent value ⇒ the conjunction is empty.
    let mut present: Vec<&RoaringTreemap> = Vec::with_capacity(bitmaps.len());
    for b in bitmaps {
        match b {
            Some(bm) => present.push(bm),
            None => return RoaringTreemap::new(),
        }
    }
    // Intersect the smallest first to shrink the running set fastest (a standard AND ordering).
    present.sort_by_key(|bm| bm.len());
    let mut acc = present[0].clone();
    for bm in &present[1..] {
        acc &= *bm;
        if acc.is_empty() {
            break;
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_seek_remove_roundtrip() {
        let mut bm = BitmapIndex::new();
        bm.insert(&Value::Boolean(true), 1);
        bm.insert(&Value::Boolean(false), 2);
        bm.insert(&Value::Boolean(true), 3);
        assert_eq!(bm.seek_eq(&Value::Boolean(true)), vec![1, 3]);
        assert_eq!(bm.seek_eq(&Value::Boolean(false)), vec![2]);
        assert_eq!(bm.distinct(), 2);
        assert_eq!(bm.total(), 3);

        assert!(bm.remove(&Value::Boolean(true), 1));
        assert_eq!(bm.seek_eq(&Value::Boolean(true)), vec![3]);
        // Removing the last id of a value drops the value entirely.
        assert!(bm.remove(&Value::Boolean(false), 2));
        assert_eq!(bm.distinct(), 1);
        assert!(bm.seek_eq(&Value::Boolean(false)).is_empty());
    }

    #[test]
    fn null_is_absent_not_indexed() {
        let mut bm = BitmapIndex::new();
        bm.insert(&Value::Null, 1);
        assert_eq!(bm.distinct(), 0);
        assert!(bm.seek_eq(&Value::Null).is_empty());
    }

    #[test]
    fn remove_node_everywhere_clears_all_values() {
        let mut bm = BitmapIndex::new();
        bm.insert(&Value::String("a".into()), 7);
        bm.insert(&Value::String("b".into()), 7); // same node under two values (pre-reindex state)
        bm.insert(&Value::String("a".into()), 8);
        bm.remove_node_everywhere(7);
        assert_eq!(bm.seek_eq(&Value::String("a".into())), vec![8]);
        assert!(bm.seek_eq(&Value::String("b".into())).is_empty());
        assert_eq!(bm.distinct(), 1);
    }

    #[test]
    fn intersect_ands_value_bitmaps() {
        let mut a = BitmapIndex::new();
        let mut b = BitmapIndex::new();
        // column `a`: value X on {1,2,3,4}; column `b`: value Y on {2,4,6}
        for id in [1, 2, 3, 4] {
            a.insert(&Value::Integer(1), id);
        }
        for id in [2, 4, 6] {
            b.insert(&Value::Integer(2), id);
        }
        let got = intersect(&[
            a.bitmap_for(&Value::Integer(1)),
            b.bitmap_for(&Value::Integer(2)),
        ]);
        assert_eq!(got, vec![2, 4]);
    }

    #[test]
    fn intersect_with_absent_value_is_empty() {
        let mut a = BitmapIndex::new();
        a.insert(&Value::Integer(1), 1);
        // second predicate's value never indexed ⇒ empty conjunction.
        let got = intersect(&[a.bitmap_for(&Value::Integer(1)), None]);
        assert!(got.is_empty());
    }
}
