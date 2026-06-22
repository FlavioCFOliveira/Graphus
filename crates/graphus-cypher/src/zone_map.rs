//! `ZoneMap` — a **derived, in-memory** per-zone min/max data-skipping sidecar (`rmp` task #331), the
//! BRIN / ClickHouse "data-skipping index" applied to the row store's node-id space.
//!
//! # What it does
//!
//! A non-indexed analytical predicate scan (`MATCH (n:Label) WHERE n.p <cmp> v`) otherwise reads
//! every in-use node of the label and re-checks the predicate per row. For a column whose values are
//! **clustered by node id** — the common append-only / time-series case, where node id ≈ insertion
//! order so a monotonic timestamp or sequence is sorted by id — a coarse per-zone `{min, max}` summary
//! lets the scan **skip whole zones** of ids whose `[min, max]` cannot contain a matching value:
//! ~99% of zones on a monotonic column, gracefully degrading to ~0% (a full scan) on an unclustered
//! one. The storage cost is one `{min, max, present_count}` triple per `ZONE_SIZE` ids (well under 1%).
//!
//! A **zone** is a fixed range of `ZONE_SIZE` consecutive node ids (`zone z = ids [z·Z, (z+1)·Z)`),
//! not a physical store page — this decouples the sidecar from the storage page layout while giving
//! the same id-clustering benefit (BRIN's `pages_per_range`).
//!
//! # Correctness: conservative, never wrongly skips
//!
//! The skip decision must never exclude a zone that could hold a match (a subset is never correct).
//! Two rules guarantee that:
//!
//! * **Widening-only maintenance.** A write extends the affected zone's `[min, max]` to include the
//!   new value; it never *shrinks* the interval (shrinking would need a full zone re-scan). An
//!   over-wide interval only causes the scan to skip *less* — never to wrongly skip. A rebuild (on
//!   declare / open) recomputes exact intervals.
//! * **Conservative comparison + MVCC unchanged.** A zone is kept whenever its `[min, max]` overlaps
//!   the predicate's value/range under the same Cypher ordering the executor uses; the per-row
//!   visibility + exact-predicate re-check above the scan is **untouched**, so the zone map only ever
//!   prunes provably-non-matching id ranges. An absent / stale zone map simply yields "scan all"
//!   (the full candidate set), which is always correct.

use std::collections::HashMap;

use graphus_core::Value;

/// The number of consecutive node ids per zone (BRIN `pages_per_range`). A power of two so the zone
/// of an id is a shift. 1024 ids/zone keeps the summary ~0.1% of a column while still skipping at a
/// useful granularity; tuning it trades summary size against skip precision.
pub const ZONE_SIZE: u64 = 1024;

/// One zone's value summary over the ids `[zone·ZONE_SIZE, (zone+1)·ZONE_SIZE)`.
#[derive(Clone, Debug)]
struct Zone {
    /// The minimum property value seen in this zone (by Cypher ordering), or `None` if the zone holds
    /// no present value of the property.
    min: Option<Value>,
    /// The maximum property value seen in this zone, or `None` if empty.
    max: Option<Value>,
    /// The count of ids in this zone with a present (non-null) value — lets a `count(n.p)` shortcut
    /// and signals an all-absent zone (skippable for any equality/range predicate).
    present_count: u64,
}

impl Zone {
    fn empty() -> Self {
        Self {
            min: None,
            max: None,
            present_count: 0,
        }
    }

    /// Widens this zone to include `value` (never shrinks — see the module soundness note).
    fn widen(&mut self, value: &Value) {
        self.present_count += 1;
        match &self.min {
            Some(m) if cmp_value(m, value) != std::cmp::Ordering::Greater => {}
            _ => self.min = Some(value.clone()),
        }
        match &self.max {
            Some(m) if cmp_value(m, value) != std::cmp::Ordering::Less => {}
            _ => self.max = Some(value.clone()),
        }
    }

    /// Whether this zone's `[min, max]` could contain a value equal to `target`. An empty zone (no
    /// present value) never matches.
    fn may_contain_eq(&self, target: &Value) -> bool {
        match (&self.min, &self.max) {
            (Some(min), Some(max)) => {
                cmp_value(min, target) != std::cmp::Ordering::Greater
                    && cmp_value(max, target) != std::cmp::Ordering::Less
            }
            _ => false,
        }
    }

    /// Whether this zone's `[min, max]` overlaps the closed range `[lo, hi]` (either bound optional).
    fn may_overlap_range(&self, lo: Option<&Value>, hi: Option<&Value>) -> bool {
        let (Some(min), Some(max)) = (&self.min, &self.max) else {
            return false;
        };
        // Disjoint iff zone.max < lo  OR  zone.min > hi.
        if let Some(lo) = lo {
            if cmp_value(max, lo) == std::cmp::Ordering::Less {
                return false;
            }
        }
        if let Some(hi) = hi {
            if cmp_value(min, hi) == std::cmp::Ordering::Greater {
                return false;
            }
        }
        true
    }
}

/// A derived per-`(label_token, prop_key)` zone-map over the node-id space (`rmp` #331). Owned by the
/// [`TxnCoordinator`](crate::coordinator::TxnCoordinator) alongside the other derived structures and
/// rebuilt on open; opt-in per column. Maintained by widening on write so its skip decision is always
/// conservative (it can only ever skip provably-non-matching id zones).
#[derive(Default)]
#[must_use]
pub struct ZoneMap {
    /// Declared columns; a column is summarized iff declared. `Vec` of zones per column, indexed by
    /// zone number (`id / ZONE_SIZE`); the vector grows as higher ids appear.
    columns: HashMap<(u32, u32), Vec<Zone>>,
    /// Count of zones the most recent skip query pruned (observability / measurement, `rmp` #331).
    zones_skipped: std::cell::Cell<u64>,
    /// Count of zones the most recent skip query kept (had to scan).
    zones_scanned: std::cell::Cell<u64>,
}

impl ZoneMap {
    /// An empty zone map with no declared columns.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares `(label_token, prop_key)` for zone summarization (idempotent). Population happens on
    /// the next [`rebuild_column`](Self::rebuild_column) / per-write [`record`](Self::record).
    pub fn declare(&mut self, label_token: u32, prop_key: u32) {
        self.columns.entry((label_token, prop_key)).or_default();
    }

    /// Whether `(label_token, prop_key)` is a declared (summarized) column.
    #[must_use]
    pub fn is_declared(&self, label_token: u32, prop_key: u32) -> bool {
        self.columns.contains_key(&(label_token, prop_key))
    }

    /// The declared `(label_token, prop_key)` columns (a rebuild re-summarizes exactly these).
    #[must_use]
    pub fn declared(&self) -> Vec<(u32, u32)> {
        let mut v: Vec<(u32, u32)> = self.columns.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Drops every summarized zone but keeps the declared column set, so a following rebuild
    /// re-summarizes exactly the declared columns (the zone-map analogue of `ColumnCache::clear`).
    pub fn clear(&mut self) {
        for zones in self.columns.values_mut() {
            zones.clear();
        }
    }

    /// Installs a freshly-scanned exact column summary for `(label_token, prop_key)` (called by the
    /// coordinator rebuild with `(node_id, value)` rows in any order). A no-op for an undeclared
    /// column. Builds zones widening-style, so the result is exact for the scanned rows.
    pub fn rebuild_column(
        &mut self,
        label_token: u32,
        prop_key: u32,
        rows: impl IntoIterator<Item = (u64, Value)>,
    ) {
        if !self.columns.contains_key(&(label_token, prop_key)) {
            return;
        }
        let mut zones: Vec<Zone> = Vec::new();
        for (id, value) in rows {
            let z = (id / ZONE_SIZE) as usize;
            while zones.len() <= z {
                zones.push(Zone::empty());
            }
            zones[z].widen(&value);
        }
        self.columns.insert((label_token, prop_key), zones);
    }

    /// Records (widens) node `id`'s current `value` for `(label_token, prop_key)` on a write, if the
    /// column is declared (else a no-op). Widening-only — never shrinks — so the skip decision stays
    /// conservative across overwrites/removals (a since-removed value leaves the interval over-wide,
    /// which only reduces skipping, never correctness).
    pub fn record(&mut self, label_token: u32, prop_key: u32, id: u64, value: &Value) {
        let Some(zones) = self.columns.get_mut(&(label_token, prop_key)) else {
            return;
        };
        let z = (id / ZONE_SIZE) as usize;
        if z >= zones.len() {
            while zones.len() <= z {
                zones.push(Zone::empty());
            }
        }
        zones[z].widen(value);
    }

    /// The candidate node-id ranges (`[lo, hi)` half-open) that an equality predicate `prop = target`
    /// could match: every zone whose `[min, max]` contains `target`. `None` if the column is not
    /// summarized (caller scans everything). Updates the skip counters. The caller still re-checks
    /// each candidate's visibility + exact value.
    #[must_use]
    pub fn candidate_ranges_eq(
        &self,
        label_token: u32,
        prop_key: u32,
        target: &Value,
    ) -> Option<Vec<(u64, u64)>> {
        let zones = self.columns.get(&(label_token, prop_key))?;
        Some(self.candidate_ranges(zones, |z| z.may_contain_eq(target)))
    }

    /// The candidate node-id ranges for a range predicate `lo <= prop <= hi` (either bound optional):
    /// every zone overlapping `[lo, hi]`. `None` if the column is not summarized.
    #[must_use]
    pub fn candidate_ranges_range(
        &self,
        label_token: u32,
        prop_key: u32,
        lo: Option<&Value>,
        hi: Option<&Value>,
    ) -> Option<Vec<(u64, u64)>> {
        let zones = self.columns.get(&(label_token, prop_key))?;
        Some(self.candidate_ranges(zones, |z| z.may_overlap_range(lo, hi)))
    }

    /// Collects the id ranges of zones passing `keep`, coalescing adjacent kept zones into one range,
    /// and updates the skip/scan counters.
    fn candidate_ranges(&self, zones: &[Zone], keep: impl Fn(&Zone) -> bool) -> Vec<(u64, u64)> {
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut skipped = 0u64;
        let mut scanned = 0u64;
        for (z, zone) in zones.iter().enumerate() {
            let lo = z as u64 * ZONE_SIZE;
            let hi = lo + ZONE_SIZE;
            if keep(zone) {
                scanned += 1;
                match ranges.last_mut() {
                    Some(last) if last.1 == lo => last.1 = hi, // coalesce adjacent kept zones
                    _ => ranges.push((lo, hi)),
                }
            } else {
                skipped += 1;
            }
        }
        self.zones_skipped.set(skipped);
        self.zones_scanned.set(scanned);
        ranges
    }

    /// Zones pruned by the most recent `candidate_ranges_*` call (`rmp` #331 measurement).
    #[must_use]
    pub fn zones_skipped(&self) -> u64 {
        self.zones_skipped.get()
    }

    /// Zones kept (scanned) by the most recent `candidate_ranges_*` call.
    #[must_use]
    pub fn zones_scanned(&self) -> u64 {
        self.zones_scanned.get()
    }

    /// The number of summarized zones for a column (diagnostics / tests).
    #[must_use]
    pub fn zone_count(&self, label_token: u32, prop_key: u32) -> Option<usize> {
        self.columns.get(&(label_token, prop_key)).map(Vec::len)
    }
}

/// Compares two [`Value`]s by the same total order the executor's ordering uses for scalars. Only the
/// orderable scalar classes (integers, floats, strings, booleans) participate in zone pruning; any
/// other / mixed class compares `Equal` so the zone is conservatively **kept** (never wrongly
/// skipped). Integers and floats are compared numerically across the type boundary (Cypher numeric
/// comparison), matching how an equality/range predicate evaluates.
fn cmp_value(a: &Value, b: &Value) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (Value::Integer(x), Value::Integer(y)) => x.cmp(y),
        (Value::Float(x), Value::Float(y)) => x.partial_cmp(y).unwrap_or(Ordering::Equal),
        (Value::Integer(x), Value::Float(y)) => {
            (*x as f64).partial_cmp(y).unwrap_or(Ordering::Equal)
        }
        (Value::Float(x), Value::Integer(y)) => {
            x.partial_cmp(&(*y as f64)).unwrap_or(Ordering::Equal)
        }
        (Value::String(x), Value::String(y)) => x.cmp(y),
        (Value::Boolean(x), Value::Boolean(y)) => x.cmp(y),
        // Mismatched / non-orderable classes: compare Equal so the zone is conservatively kept.
        _ => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int_rows(ids_vals: &[(u64, i64)]) -> Vec<(u64, Value)> {
        ids_vals
            .iter()
            .map(|&(id, v)| (id, Value::Integer(v)))
            .collect()
    }

    #[test]
    fn clustered_column_skips_non_matching_zones() {
        let mut zm = ZoneMap::new();
        zm.declare(1, 2);
        // Monotonic: id i carries value i (so zone z = ids [z*1024,(z+1)*1024) holds values in that range).
        let rows: Vec<(u64, Value)> = (0..4096u64)
            .map(|i| (i, Value::Integer(i as i64)))
            .collect();
        zm.rebuild_column(1, 2, rows);
        assert_eq!(zm.zone_count(1, 2), Some(4)); // ids 0..4096 -> 4 zones

        // Looking for value 2000 (in zone 1): zones 0,2,3 are pruned, only zone 1 kept.
        let ranges = zm.candidate_ranges_eq(1, 2, &Value::Integer(2000)).unwrap();
        assert_eq!(ranges, vec![(1024, 2048)]);
        assert_eq!(zm.zones_skipped(), 3);
        assert_eq!(zm.zones_scanned(), 1);
    }

    #[test]
    fn unclustered_column_keeps_all_zones() {
        let mut zm = ZoneMap::new();
        zm.declare(1, 2);
        // Every zone spans the whole value range (value = id % 4) -> no zone can be pruned for value 2.
        let rows: Vec<(u64, Value)> = (0..4096u64)
            .map(|i| (i, Value::Integer((i % 4) as i64)))
            .collect();
        zm.rebuild_column(1, 2, rows);
        let ranges = zm.candidate_ranges_eq(1, 2, &Value::Integer(2)).unwrap();
        // All 4 zones kept and coalesced into one range.
        assert_eq!(ranges, vec![(0, 4096)]);
        assert_eq!(zm.zones_skipped(), 0);
    }

    #[test]
    fn range_predicate_prunes_disjoint_zones() {
        let mut zm = ZoneMap::new();
        zm.declare(3, 4);
        zm.rebuild_column(3, 4, int_rows(&[(0, 0), (1, 5), (1100, 100), (1101, 200)]));
        // zone 0: [0,5], zone 1: [100,200]. Range [50,80] overlaps neither -> empty candidates.
        let ranges = zm
            .candidate_ranges_range(3, 4, Some(&Value::Integer(50)), Some(&Value::Integer(80)))
            .unwrap();
        assert!(ranges.is_empty());
        assert_eq!(zm.zones_skipped(), 2);
    }

    #[test]
    fn widening_keeps_skip_conservative_after_write() {
        let mut zm = ZoneMap::new();
        zm.declare(1, 2);
        zm.rebuild_column(1, 2, int_rows(&[(0, 10), (1, 20)])); // zone 0: [10,20]
        // A new write in zone 0 with value 9999 widens it; now 5000 falls in [10,9999] -> kept.
        zm.record(1, 2, 5, &Value::Integer(9999));
        let ranges = zm.candidate_ranges_eq(1, 2, &Value::Integer(5000)).unwrap();
        assert_eq!(ranges, vec![(0, 1024)]);
    }

    #[test]
    fn undeclared_column_yields_no_ranges() {
        let zm = ZoneMap::new();
        assert!(zm.candidate_ranges_eq(9, 9, &Value::Integer(1)).is_none());
    }
}
