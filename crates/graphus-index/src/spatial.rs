//! Spatial indexing: a uniform **grid index** over indexed points for proximity and bounding-box
//! predicates (`04-technical-design.md` §6; `D-v1-index-types`; `rmp` task #73).
//!
//! A spatial index covers one node label and one point property. It accelerates two query shapes a
//! full scan handles only in O(n):
//!
//! - **proximity** — `distance(n.loc, $p) <= r` (points within radius `r` of a query point); and
//! - **bounding box** — `$min <= n.loc.x <= $max AND …` (points inside an axis-aligned box).
//!
//! This module is the **data-structure layer**, kept deliberately self-contained and pure so it is
//! unit-testable in isolation (no store, no WAL, no buffer pool) — exactly like the full-text
//! [`crate::fulltext`] index (`rmp` task #72). The transactional maintenance, MVCC re-check, and the
//! durability of the *catalog* are layered on top in `graphus-cypher` (`IndexSet`/`TxnCoordinator`)
//! and `graphus-storage` (the durable catalog): the grid itself is **ephemeral and rebuilt from the
//! store on open**, so — like the derived property index — it needs no separate crash-recovery path.
//!
//! # Why a uniform grid
//!
//! A uniform grid is the simplest correct spatial structure: it partitions the coordinate plane into
//! fixed-size square cells and buckets each indexed point by the cell it falls in. A range/proximity
//! query enumerates only the cells the query region overlaps, yielding a **candidate** set far
//! smaller than the whole index for a localized query, while being trivial to maintain incrementally
//! (insert/remove touch one cell). An R-tree or space-filling curve would pack denser, but the grid
//! is sufficient for v1 and its correctness is obvious — and correctness, not raw speed, is the
//! inviolable property here (the index must never change a query's result versus a full scan).
//!
//! # Candidates, not answers (the crate-wide contract)
//!
//! Every query method returns **candidate** node ids: it never filters by MVCC visibility, by current
//! label membership, or by the point's *current* coordinates (a bucket entry may be stale until an
//! update re-indexes the node). Crucially, a grid query is a **conservative over-approximation** even
//! geometrically — a proximity query returns every point in any cell the query circle *touches*,
//! including points in the cell's corners that are actually outside the radius. The caller therefore
//! re-checks every candidate's exact predicate against the transaction snapshot
//! (`distance(loc, p) <= r`), so returning a **superset** of the truly-matching ids is always
//! correct and a subset never is — identical to [`crate::kinds`] and [`crate::fulltext`].
//!
//! Only 2D CRSs are bucketed by the grid; a 3D point is indexed by its `(x, y)` projection (the third
//! coordinate is re-checked by the caller's exact predicate), and points of a CRS the index does not
//! cover are simply not inserted (so they fall back to a scan). The query side never returns a point
//! of a different CRS than the query point, because the grid is keyed per `(label, property)` and the
//! caller's exact `distance`/coordinate predicate rejects a cross-CRS candidate anyway.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use graphus_core::value::spatial::Point;

/// The default grid cell size, in coordinate units, when a caller passes `0.0` to [`SpatialIndex::new`].
///
/// `1.0` is a neutral default: for Cartesian data it is one coordinate unit; for WGS-84 it is one
/// degree (~111 km at the equator). The exact value is **not** load-bearing for correctness — only
/// for how many candidates a query enumerates — so it can be tuned later from measured plan quality
/// without changing any result. A query whose radius spans many cells still returns the correct
/// candidate superset; it just visits more cells.
pub const DEFAULT_CELL_SIZE: f64 = 1.0;

/// A grid cell coordinate: the integer `(col, row)` a point's `(x, y)` falls into.
type Cell = (i64, i64);

/// A uniform **grid index** over 2D-projected points: `cell -> sorted node ids`, plus a forward map
/// (`node -> its (cell, point)`) so an update/delete is O(1) in the number of cells (`rmp` task #73).
///
/// # Representation
///
/// - `cells: cell -> sorted, de-duplicated node ids in that cell`. Sorted so [`query_bbox`] /
///   [`query_within`] return candidates ascending (a deterministic order, like every other index
///   kind).
/// - `forward: node -> (cell, point)`. Without it, removing a node would require scanning every cell;
///   with it, a delete/update is O(1) in the cell count.
///
/// Both are [`BTreeMap`]/[`BTreeSet`]-backed so iteration is deterministic (reproducible tests and
/// the candidate-ordering contract).
///
/// [`query_bbox`]: SpatialIndex::query_bbox
/// [`query_within`]: SpatialIndex::query_within
#[derive(Debug, Clone)]
pub struct SpatialIndex {
    /// The side length of a grid cell in coordinate units (`> 0`).
    cell_size: f64,
    /// cell → sorted, de-duplicated node ids whose indexed point falls in that cell.
    cells: BTreeMap<Cell, Vec<u64>>,
    /// node → its current `(cell, indexed point)` (the forward index, for deletes/updates).
    forward: BTreeMap<u64, (Cell, Point)>,
}

impl SpatialIndex {
    /// An empty grid index with `cell_size` (or [`DEFAULT_CELL_SIZE`] when `cell_size <= 0.0` or
    /// non-finite).
    #[must_use]
    pub fn new(cell_size: f64) -> Self {
        let cell_size = if cell_size.is_finite() && cell_size > 0.0 {
            cell_size
        } else {
            DEFAULT_CELL_SIZE
        };
        Self {
            cell_size,
            cells: BTreeMap::new(),
            forward: BTreeMap::new(),
        }
    }

    /// The configured cell size in coordinate units.
    #[must_use]
    pub fn cell_size(&self) -> f64 {
        self.cell_size
    }

    /// Whether the index holds no points.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// The number of indexed points (distinct node ids currently present).
    #[must_use]
    pub fn len(&self) -> usize {
        self.forward.len()
    }

    /// The number of non-empty grid cells.
    #[must_use]
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// The grid cell a point's `(x, y)` projection falls into. A non-finite coordinate maps to cell
    /// `0` on that axis (the caller's exact predicate still rejects it; the bucket is just arbitrary).
    fn cell_of(&self, point: &Point) -> Cell {
        (self.axis_cell(point.x()), self.axis_cell(point.y()))
    }

    /// The cell index along one axis: `floor(coord / cell_size)`, clamped for non-finite input.
    fn axis_cell(&self, coord: f64) -> i64 {
        if !coord.is_finite() {
            return 0;
        }
        // `floor` then cast; coordinates far beyond i64 range saturate (an extreme point still buckets
        // *somewhere* deterministically, and the exact re-check is authoritative).
        let c = (coord / self.cell_size).floor();
        if c >= i64::MAX as f64 {
            i64::MAX
        } else if c <= i64::MIN as f64 {
            i64::MIN
        } else {
            c as i64
        }
    }

    /// Indexes (or **re-indexes**) `node` at `point`. Idempotent on the node: it first removes any
    /// existing entry (so an update after a coordinate change re-buckets the node), then inserts the
    /// node into its new cell's id list.
    pub fn index_point(&mut self, node: u64, point: Point) {
        self.remove(node);
        let cell = self.cell_of(&point);
        let list = self.cells.entry(cell).or_default();
        if let Err(pos) = list.binary_search(&node) {
            list.insert(pos, node);
        }
        self.forward.insert(node, (cell, point));
    }

    /// Removes `node` from the index entirely (its forward entry and the one cell it lives in),
    /// returning whether it was present. Idempotent: removing an absent node is a no-op.
    pub fn remove(&mut self, node: u64) -> bool {
        let Some((cell, _)) = self.forward.remove(&node) else {
            return false;
        };
        if let Some(list) = self.cells.get_mut(&cell) {
            if let Ok(pos) = list.binary_search(&node) {
                list.remove(pos);
            }
            if list.is_empty() {
                self.cells.remove(&cell);
            }
        }
        true
    }

    /// Drops every point, leaving an empty index (used by a full rebuild from the store).
    pub fn clear(&mut self) {
        self.cells.clear();
        self.forward.clear();
    }

    /// The candidate node ids whose indexed point may lie within the axis-aligned bounding box
    /// `[min_x, max_x] × [min_y, max_y]`, ascending and de-duplicated (`rmp` task #73).
    ///
    /// Returns every node in any cell the box overlaps — a geometric **superset** of the points
    /// actually inside the box (a cell on the box edge may hold points just outside it). The caller
    /// re-checks the exact coordinate predicate. An inverted box (`min > max` on either axis) matches
    /// nothing.
    #[must_use]
    pub fn query_bbox(&self, min_x: f64, max_x: f64, min_y: f64, max_y: f64) -> Vec<u64> {
        // A NaN bound, or an inverted box (min > max), matches nothing. We test `min > max`
        // explicitly (clearer than a negated `<=`) and reject any NaN bound up front — a NaN would
        // otherwise make `min > max` false and silently include everything.
        if min_x.is_nan()
            || max_x.is_nan()
            || min_y.is_nan()
            || max_y.is_nan()
            || min_x > max_x
            || min_y > max_y
        {
            return Vec::new();
        }
        let (cx0, cx1) = (self.axis_cell(min_x), self.axis_cell(max_x));
        let (cy0, cy1) = (self.axis_cell(min_y), self.axis_cell(max_y));
        let mut out: BTreeSet<u64> = BTreeSet::new();
        // Enumerate the overlapping cell rectangle. The cell *counts* are bounded by the query
        // region size / cell_size, so a localized query visits few cells.
        let mut cx = cx0;
        while cx <= cx1 {
            let mut cy = cy0;
            while cy <= cy1 {
                if let Some(list) = self.cells.get(&(cx, cy)) {
                    out.extend(list.iter().copied());
                }
                cy = match cy.checked_add(1) {
                    Some(n) => n,
                    None => break,
                };
            }
            cx = match cx.checked_add(1) {
                Some(n) => n,
                None => break,
            };
        }
        out.into_iter().collect()
    }

    /// The candidate node ids whose indexed point may lie within radius `radius` of `(center_x,
    /// center_y)`, ascending and de-duplicated (`rmp` task #73).
    ///
    /// Implemented as a [`query_bbox`](Self::query_bbox) over the circle's bounding square
    /// `[cx - r, cx + r] × [cy - r, cy + r]`: every point within the circle is within that square, so
    /// the bounding-box candidates are a **superset** of the in-circle points. The caller re-checks
    /// the exact `distance(loc, center) <= radius` predicate (which is also what excludes the square's
    /// corners and, for geographic CRSs, applies the great-circle metric the grid does not model). A
    /// negative or non-finite radius matches nothing.
    #[must_use]
    pub fn query_within(&self, center_x: f64, center_y: f64, radius: f64) -> Vec<u64> {
        // A non-finite radius (NaN/±inf) or a negative one matches nothing. `radius < 0.0` is false
        // for NaN, so the explicit finiteness guard covers the NaN case.
        if !radius.is_finite() || radius < 0.0 {
            return Vec::new();
        }
        self.query_bbox(
            center_x - radius,
            center_x + radius,
            center_y - radius,
            center_y + radius,
        )
    }

    /// All indexed node ids, ascending. The correct (if unselective) candidate set for a query the
    /// grid cannot bound, mirroring the property index's "all candidates" fallback.
    #[must_use]
    pub fn all_candidates(&self) -> Vec<u64> {
        self.forward.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_core::value::spatial::Crs;

    fn cart(x: f64, y: f64) -> Point {
        Point::new_2d(Crs::Cartesian, x, y)
    }

    #[test]
    fn insert_query_and_remove() {
        let mut idx = SpatialIndex::new(1.0);
        idx.index_point(10, cart(0.5, 0.5));
        idx.index_point(20, cart(5.5, 5.5));
        idx.index_point(30, cart(0.7, 0.2)); // same cell as 10
        assert_eq!(idx.len(), 3);

        // A bbox around the origin cell returns 10 and 30 (both in cell (0,0)), not 20.
        let mut got = idx.query_bbox(0.0, 0.9, 0.0, 0.9);
        got.sort_unstable();
        assert_eq!(got, vec![10, 30]);

        // A proximity query is a bbox over the circle's square: radius 1 around (5.5, 5.5) → only 20.
        assert_eq!(idx.query_within(5.5, 5.5, 1.0), vec![20]);

        // Remove 30; the origin cell still has 10.
        assert!(idx.remove(30));
        assert_eq!(idx.query_bbox(0.0, 0.9, 0.0, 0.9), vec![10]);
        // Idempotent remove.
        assert!(!idx.remove(30));
    }

    #[test]
    fn query_returns_a_geometric_superset_caller_rechecks() {
        // A point in a cell corner is returned by a bbox/circle that overlaps the cell even when the
        // point is geometrically outside the exact region — the documented candidate (over-approx)
        // contract. Here (0.9, 0.9) is in cell (0,0); a circle of radius 0.2 around (0.0, 0.0) also
        // overlaps cell (0,0), so 10 is a candidate though its true distance (~1.27) exceeds 0.2.
        let mut idx = SpatialIndex::new(1.0);
        idx.index_point(10, cart(0.9, 0.9));
        let candidates = idx.query_within(0.0, 0.0, 0.2);
        assert_eq!(candidates, vec![10], "the grid returns a superset");
        // The caller's exact re-check (not the grid's job) would then exclude it:
        let exact = ((0.9_f64).hypot(0.9)) <= 0.2;
        assert!(
            !exact,
            "the exact predicate correctly excludes the corner point"
        );
    }

    #[test]
    fn reindex_rebuckets_on_coordinate_change() {
        let mut idx = SpatialIndex::new(1.0);
        idx.index_point(10, cart(0.5, 0.5)); // cell (0,0)
        idx.index_point(10, cart(9.5, 9.5)); // update → cell (9,9)
        assert_eq!(idx.len(), 1);
        // No longer near the origin.
        assert!(idx.query_bbox(0.0, 1.0, 0.0, 1.0).is_empty());
        // Found at the new location.
        assert_eq!(idx.query_bbox(9.0, 10.0, 9.0, 10.0), vec![10]);
    }

    #[test]
    fn inverted_box_and_bad_radius_match_nothing() {
        let mut idx = SpatialIndex::new(1.0);
        idx.index_point(10, cart(0.5, 0.5));
        assert!(idx.query_bbox(5.0, 1.0, 0.0, 1.0).is_empty()); // min_x > max_x
        assert!(idx.query_bbox(0.0, 1.0, f64::NAN, 1.0).is_empty()); // NaN bound
        assert!(idx.query_within(0.0, 0.0, -1.0).is_empty()); // negative radius
        assert!(idx.query_within(0.0, 0.0, f64::INFINITY).is_empty()); // non-finite radius
        assert!(idx.query_within(0.0, 0.0, f64::NAN).is_empty());
    }

    #[test]
    fn brute_force_oracle_agreement_over_a_grid_of_points() {
        // The headline correctness property: for many random query boxes, the index candidate set is
        // a SUPERSET of the brute-force exact in-box answer (never a subset). A subset would be a
        // wrong query result; a superset is corrected by the caller's re-check.
        let mut idx = SpatialIndex::new(2.5);
        let mut points: Vec<(u64, f64, f64)> = Vec::new();
        let mut id = 0u64;
        for gx in -10..=10 {
            for gy in -10..=10 {
                let (x, y) = (gx as f64 * 0.5 + 0.3, gy as f64 * 0.5 - 0.7);
                idx.index_point(id, cart(x, y));
                points.push((id, x, y));
                id += 1;
            }
        }
        // A deterministic spread of query boxes (no rng dependency).
        let boxes = [
            (-1.0, 1.0, -1.0, 1.0),
            (0.0, 3.0, 0.0, 3.0),
            (-5.0, -2.0, 2.0, 4.0),
            (-100.0, 100.0, -100.0, 100.0), // everything
            (2.20, 2.30, -2.0, -1.0),       // a thin slice
        ];
        for (minx, maxx, miny, maxy) in boxes {
            let candidates: BTreeSet<u64> =
                idx.query_bbox(minx, maxx, miny, maxy).into_iter().collect();
            let truth: BTreeSet<u64> = points
                .iter()
                .filter(|(_, x, y)| *x >= minx && *x <= maxx && *y >= miny && *y <= maxy)
                .map(|(i, _, _)| *i)
                .collect();
            // Superset: every truly-matching point is a candidate (the inviolable property).
            assert!(
                truth.is_subset(&candidates),
                "index missed a true match for box ({minx},{maxx},{miny},{maxy}): truth={truth:?} candidates={candidates:?}"
            );
        }
    }

    #[test]
    fn three_d_points_index_by_their_xy_projection() {
        let mut idx = SpatialIndex::new(1.0);
        idx.index_point(10, Point::new_3d(Crs::Cartesian3D, 0.5, 0.5, 100.0));
        // The z coordinate does not affect the (x,y) bucketing; the caller's exact predicate handles z.
        assert_eq!(idx.query_bbox(0.0, 1.0, 0.0, 1.0), vec![10]);
    }

    #[test]
    fn clear_and_default_cell_size() {
        let mut idx = SpatialIndex::new(0.0); // non-positive → default
        assert_eq!(idx.cell_size(), DEFAULT_CELL_SIZE);
        idx.index_point(1, cart(0.0, 0.0));
        idx.clear();
        assert!(idx.is_empty());
        assert_eq!(idx.cell_count(), 0);
        assert!(idx.query_within(0.0, 0.0, 10.0).is_empty());
    }
}
