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
//! # Correctness: conservative, never wrongly skips (`rmp` tasks #904, #958)
//!
//! This structure sits at the **conservative** read polarity of `04-technical-design.md` §5.3 and
//! [`graphus_storage::scan_polarity`]: it *excludes* id ranges, and the exclusion happens **before**
//! any per-row re-check can see them. Nothing rebuilds a zone map afterwards — there is no rebuild on
//! open and no rollback hook — so a range wrongly excluded is a row lost for the life of the process.
//! The obligation is therefore one-directional: **never narrow on state that is not proven.** Four
//! rules discharge it, and all four are load-bearing:
//!
//! * **Widening-only maintenance.** A write extends the affected zone's `[min, max]` to include the
//!   new value; it never *shrinks* the interval (shrinking would need a full zone re-scan). An
//!   over-wide interval only causes the scan to skip *less* — never to wrongly skip. This is why an
//!   uncommitted writer needs no removal hook: its value widens the zone, and a rollback leaves the
//!   zone merely over-wide.
//! * **A rebuild summarises the SUPERSET, not the current image.** [`ZoneMap::rebuild_column`] is fed
//!   every *version* of the property for every node that carries the label in the live-OR-retained
//!   sense (`TxnCoordinator::rebuild_zone_column`). Summarising the newest version alone would narrow
//!   a zone on an uncommitted overwrite a rollback then undoes, and would also drop the older
//!   committed version an existing reader's snapshot still resolves.
//! * **A partial summary is never installed.** A column that has not been summarised end-to-end —
//!   never rebuilt, or rebuilt over a scan that faulted — **declines**
//!   ([`candidate_ranges_eq`](ZoneMap::candidate_ranges_eq) and friends return [`None`], "scan
//!   everything"), because a summary built over an incomplete scan can
//!   exclude an id range it never looked at. Declining costs a full scan; pruning on a partial
//!   summary costs rows. `None` is the decline; `Some(vec![])` means "no zone can hold this value",
//!   which is an *answer*, and the two must never be confused (`rmp` #680/#738).
//! * **The per-row re-check is snapshot-correct, and lives above this module.** A zone map produces
//!   **candidates**, never rows: [`candidate_ranges_eq`](ZoneMap::candidate_ranges_eq) /
//!   [`candidate_ids_eq`](ZoneMap::candidate_ids_eq) hand an id superset to a seam that owns the
//!   reader's snapshot and the store's own commit oracle (`rmp` #1069 phase 3) —
//!   `RecordStoreGraph::zone_scan_eq`, which re-checks
//!   through `label_bitmap_at` + `is_visible_via` exactly as every index seek does (`rmp` #958). This
//!   module holds no snapshot and therefore decides nothing about visibility.
//!
//! # The maintenance invariant a caller must uphold
//!
//! `Some(candidates)` is only a correct answer while **every** write that can make a node match has
//! widened that node's zone. On the coordinated path that is `RecordStoreGraph::reindex_node`, which
//! runs on every node create, property write and label change. A write path that can create a match
//! **without** going through it must re-summarise the column (or abandon it with
//! [`abandon_column`](ZoneMap::abandon_column)); otherwise it leaves a zone narrower than the graph.

use std::collections::HashMap;

use graphus_core::{Value, cmp_int_float};

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

/// One declared column's summary: the per-zone intervals, plus whether they were ever built from a
/// **complete** scan.
///
/// The flag is the difference between "no zone can hold this value" and "this column cannot answer".
/// A freshly declared column, and one whose rebuild scan faulted part-way, hold zones that describe
/// only the ids the scan reached; pruning on those would exclude id ranges nobody looked at. Such a
/// column declines instead (`rmp` #958).
#[derive(Clone, Debug, Default)]
struct Column {
    /// The per-zone summaries, indexed by zone number (`id / ZONE_SIZE`); grows as higher ids appear.
    zones: Vec<Zone>,
    /// `true` once a complete scan has been summarised into `zones` (and kept true by the
    /// widening-only maintenance, which can only make the intervals safer).
    summarized: bool,
}

/// A derived per-`(label_token, prop_key)` zone-map over the node-id space (`rmp` #331). Owned by the
/// [`TxnCoordinator`](crate::coordinator::TxnCoordinator) alongside the other derived structures and
/// shared with the statement seam that consumes it; opt-in per column. Maintained by widening on write
/// so its skip decision is always conservative (it can only ever skip provably-non-matching id zones).
#[derive(Default)]
#[must_use]
pub struct ZoneMap {
    /// Declared columns; a column is summarized iff declared **and** completely scanned once.
    columns: HashMap<(u32, u32), Column>,
    /// Count of zones the most recent skip query pruned (observability / measurement, `rmp` #331).
    zones_skipped: std::sync::atomic::AtomicU64,
    /// Count of zones the most recent skip query kept (had to scan).
    zones_scanned: std::sync::atomic::AtomicU64,
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
    ///
    /// Every column is left **unsummarized**, so a query issued between the clear and the rebuild
    /// declines to a full scan instead of pruning against an empty summary — an empty summary would
    /// otherwise exclude every zone and return no rows at all (`rmp` #958).
    pub fn clear(&mut self) {
        for column in self.columns.values_mut() {
            column.zones.clear();
            column.summarized = false;
        }
    }

    /// Marks `(label_token, prop_key)` **unsummarized**, so it declines every skip query until a
    /// complete rebuild re-summarizes it (`rmp` #958).
    ///
    /// This is what a rebuild whose scan faulted must call. A pruning structure cannot represent
    /// "these ids are unknown to me": every id inside a summarized zone is decided by that zone's
    /// interval, and every id past the last summarized zone is excluded outright. So a summary built
    /// over an incomplete scan does not merely lose precision, it excludes id ranges nobody read.
    /// Declining is the only conservative answer, and it costs one full scan.
    pub fn abandon_column(&mut self, label_token: u32, prop_key: u32) {
        if let Some(column) = self.columns.get_mut(&(label_token, prop_key)) {
            column.zones.clear();
            column.summarized = false;
        }
    }

    /// Installs a freshly-scanned exact column summary for `(label_token, prop_key)` and marks the
    /// column summarized (called by the coordinator rebuild with `(node_id, value)` rows in any
    /// order). A no-op for an undeclared column. Builds zones widening-style, so the result is exact
    /// for the scanned rows.
    ///
    /// # `rows` must be the value SUPERSET, not the current image
    ///
    /// Every `(id, value)` pair widens its zone, so the caller must pass **every version** of the
    /// property for every node that carries the label in the live-OR-retained sense. Passing only the
    /// newest version of each node narrows the zone on two unproven grounds at once: an uncommitted
    /// overwrite that a rollback will undo, and an older committed version that a reader whose
    /// snapshot predates the overwrite still resolves (`rmp` #50 newest-**visible**-wins). Either one
    /// makes a committed row unreachable, permanently (`rmp` #904/#958).
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
        self.columns.insert(
            (label_token, prop_key),
            Column {
                zones,
                summarized: true,
            },
        );
    }

    /// Records (widens) node `id`'s current `value` for `(label_token, prop_key)` on a write, if the
    /// column is declared (else a no-op). Widening-only — never shrinks — so the skip decision stays
    /// conservative across overwrites/removals (a since-removed value leaves the interval over-wide,
    /// which only reduces skipping, never correctness).
    pub fn record(&mut self, label_token: u32, prop_key: u32, id: u64, value: &Value) {
        let Some(column) = self.columns.get_mut(&(label_token, prop_key)) else {
            return;
        };
        let z = (id / ZONE_SIZE) as usize;
        while column.zones.len() <= z {
            column.zones.push(Zone::empty());
        }
        column.zones[z].widen(value);
    }

    /// The **candidate** node-id ranges (`[lo, hi)` half-open) that an equality predicate
    /// `prop = target` could match: every zone whose `[min, max]` contains `target`. Updates the skip
    /// counters.
    ///
    /// [`None`] is a **decline** — the column is not declared, or has never been summarized from a
    /// complete scan — and means "scan everything"; it is never "nothing matches". `Some(ranges)` is a
    /// candidate superset over the node-id space, and the caller **must** re-check each candidate's
    /// visibility, label membership and exact value against its own snapshot before returning a row
    /// (`rmp` #958). An empty `Some` is a real answer: no summarized zone can hold the value.
    #[must_use]
    pub fn candidate_ranges_eq(
        &self,
        label_token: u32,
        prop_key: u32,
        target: &Value,
    ) -> Option<Vec<(u64, u64)>> {
        let column = self.summarized_column(label_token, prop_key)?;
        Some(self.candidate_ranges(&column.zones, |z| z.may_contain_eq(target)))
    }

    /// The candidate node-id ranges for a range predicate `lo <= prop <= hi` (either bound optional):
    /// every zone overlapping `[lo, hi]`. Same decline contract as
    /// [`candidate_ranges_eq`](Self::candidate_ranges_eq).
    #[must_use]
    pub fn candidate_ranges_range(
        &self,
        label_token: u32,
        prop_key: u32,
        lo: Option<&Value>,
        hi: Option<&Value>,
    ) -> Option<Vec<(u64, u64)>> {
        let column = self.summarized_column(label_token, prop_key)?;
        Some(self.candidate_ranges(&column.zones, |z| z.may_overlap_range(lo, hi)))
    }

    /// [`candidate_ranges_eq`](Self::candidate_ranges_eq) flattened into the **candidate node ids**
    /// themselves, clipped to the store's live id space `1..high_water` (id `0` is the reserved null
    /// pointer and `high_water` is one past the largest id ever allocated).
    ///
    /// The ids are candidates and nothing more: this module reads no record and holds no snapshot, so
    /// every one of them still has to survive the reader's visibility + label + value re-check. The
    /// decline contract of [`candidate_ranges_eq`](Self::candidate_ranges_eq) applies unchanged.
    #[must_use]
    pub fn candidate_ids_eq(
        &self,
        label_token: u32,
        prop_key: u32,
        target: &Value,
        high_water: u64,
    ) -> Option<Vec<u64>> {
        let ranges = self.candidate_ranges_eq(label_token, prop_key, target)?;
        let mut ids = Vec::new();
        for (lo, hi) in ranges {
            ids.extend(lo.max(1)..hi.min(high_water));
        }
        Some(ids)
    }

    /// The column's summary, or [`None`] when it is undeclared or not summarized from a complete scan.
    fn summarized_column(&self, label_token: u32, prop_key: u32) -> Option<&Column> {
        self.columns
            .get(&(label_token, prop_key))
            .filter(|c| c.summarized)
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
        self.zones_skipped
            .store(skipped, std::sync::atomic::Ordering::Relaxed);
        self.zones_scanned
            .store(scanned, std::sync::atomic::Ordering::Relaxed);
        ranges
    }

    /// Zones pruned by the most recent `candidate_ranges_*` call (`rmp` #331 measurement).
    #[must_use]
    pub fn zones_skipped(&self) -> u64 {
        self.zones_skipped
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Zones kept (scanned) by the most recent `candidate_ranges_*` call.
    #[must_use]
    pub fn zones_scanned(&self) -> u64 {
        self.zones_scanned
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The number of summarized zones for a column (diagnostics / tests).
    #[must_use]
    pub fn zone_count(&self, label_token: u32, prop_key: u32) -> Option<usize> {
        self.columns
            .get(&(label_token, prop_key))
            .map(|c| c.zones.len())
    }

    /// Whether `(label_token, prop_key)` has been summarized from a complete scan, and may therefore
    /// prune (diagnostics / tests).
    #[must_use]
    pub fn is_summarized(&self, label_token: u32, prop_key: u32) -> bool {
        self.summarized_column(label_token, prop_key).is_some()
    }
}

/// Compares two [`Value`]s by the same total order the executor's ordering uses for scalars. Only the
/// orderable scalar classes (integers, floats, strings, booleans) participate in zone pruning; any
/// other / mixed class compares `Equal` so the zone is conservatively **kept** (never wrongly
/// skipped). Integers and floats are compared numerically across the type boundary (Cypher numeric
/// comparison), matching how an equality/range predicate evaluates.
///
/// # Why the cross-type arm calls [`cmp_int_float`] (`rmp` task #894)
///
/// A zone map decides which id ranges may be **skipped**, so it is only sound while its notion of
/// "is this value inside `[min, max]`" is the same one the predicate itself uses. This comparator is
/// a second, independent implementation of Cypher numeric ordering (it must be: it needs the
/// conservative `Equal` fallback for mismatched classes, which the real ordering does not have), and
/// an independent implementation is exactly where the two can drift. Routing the mixed
/// `INTEGER`/`FLOAT` case through the same exact primitive `crate::ordering` uses removes that
/// possibility: a zone whose `max` is `Float(2^53.0)` is now correctly recognised as *not*
/// containing `Integer(2^53+1)`, in the same breath as the predicate says the two are different
/// numbers.
///
/// `NaN` (and any other pair without an order) still falls back to `Equal`, keeping the zone.
fn cmp_value(a: &Value, b: &Value) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (Value::Integer(x), Value::Integer(y)) => x.cmp(y),
        (Value::Float(x), Value::Float(y)) => x.partial_cmp(y).unwrap_or(Ordering::Equal),
        (Value::Integer(x), Value::Float(y)) => cmp_int_float(*x, *y).unwrap_or(Ordering::Equal),
        (Value::Float(x), Value::Integer(y)) => cmp_int_float(*y, *x)
            .map(Ordering::reverse)
            .unwrap_or(Ordering::Equal),
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

    /// `rmp` #958: a column that was declared but never summarized from a complete scan must
    /// **decline** (`None` = "scan everything"), not answer `Some([])` (= "nothing matches"). The
    /// distinction is the whole result set: pruning against an empty summary excludes every id.
    #[test]
    fn a_declared_but_unsummarized_column_declines_rather_than_pruning_everything() {
        let mut zm = ZoneMap::new();
        zm.declare(1, 2);
        assert_eq!(
            zm.candidate_ranges_eq(1, 2, &Value::Integer(7)),
            None,
            "an unsummarized column must decline to a full scan, never prune every zone",
        );
        assert_eq!(zm.candidate_ids_eq(1, 2, &Value::Integer(7), 4096), None);
        assert!(!zm.is_summarized(1, 2));
    }

    /// A rebuild whose scan faulted part-way must leave the column declining, not summarized over the
    /// prefix it managed to read (`rmp` #958).
    #[test]
    fn abandoning_a_column_makes_it_decline_again() {
        let mut zm = ZoneMap::new();
        zm.declare(1, 2);
        zm.rebuild_column(1, 2, int_rows(&[(0, 10), (1, 20)]));
        assert!(zm.is_summarized(1, 2));
        assert!(
            zm.candidate_ranges_eq(1, 2, &Value::Integer(5000))
                .is_some()
        );

        zm.abandon_column(1, 2);
        assert!(!zm.is_summarized(1, 2));
        assert_eq!(zm.candidate_ranges_eq(1, 2, &Value::Integer(15)), None);
        // Still declared, so a later complete rebuild re-summarizes it.
        assert!(zm.is_declared(1, 2));
        zm.rebuild_column(1, 2, int_rows(&[(0, 10), (1, 20)]));
        assert!(zm.is_summarized(1, 2));
    }

    /// `clear()` leaves every column declining until the rebuild that follows it lands.
    #[test]
    fn clear_leaves_columns_declining_until_they_are_rebuilt() {
        let mut zm = ZoneMap::new();
        zm.declare(1, 2);
        zm.rebuild_column(1, 2, int_rows(&[(0, 10)]));
        zm.clear();
        assert!(zm.is_declared(1, 2));
        assert!(!zm.is_summarized(1, 2));
        assert_eq!(zm.candidate_ranges_eq(1, 2, &Value::Integer(10)), None);
    }

    /// The flattened candidate ids honour the store's live id space: id `0` is the reserved null
    /// pointer and `high_water` is exclusive.
    #[test]
    fn candidate_ids_are_clipped_to_the_live_id_space() {
        let mut zm = ZoneMap::new();
        zm.declare(1, 2);
        // One zone (ids 0..1024) holding values 0..=3, so the equality keeps exactly that zone.
        zm.rebuild_column(1, 2, int_rows(&[(0, 0), (3, 3)]));
        let ids = zm.candidate_ids_eq(1, 2, &Value::Integer(3), 5).unwrap();
        assert_eq!(
            ids,
            vec![1, 2, 3, 4],
            "0 is reserved, high_water is exclusive"
        );
    }

    /// A summarized column that provably cannot hold the value answers `Some([])` — an answer, not a
    /// decline. Its caller returns no rows for it, which is why only a complete summary may say it.
    #[test]
    fn a_summarized_column_that_cannot_match_answers_with_an_empty_candidate_set() {
        let mut zm = ZoneMap::new();
        zm.declare(1, 2);
        zm.rebuild_column(1, 2, int_rows(&[(0, 10), (1, 20)]));
        assert_eq!(
            zm.candidate_ids_eq(1, 2, &Value::Integer(9_999), 4096),
            Some(Vec::new()),
        );
    }
}
