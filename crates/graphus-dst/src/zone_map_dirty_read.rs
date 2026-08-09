//! Focused deterministic reproducer for the **zone-map skip query re-checking its candidates with a
//! raw dirty read, in both directions** (`rmp` task #958) — the data-skipping member of the read-polarity
//! family whose index siblings are `rmp` #904 (label gate) and #766/#779 (value gate).
//!
//! ## The defect
//!
//! A zone map is a *pruning* structure: `candidate_ranges_eq` excludes whole id ranges, and only the
//! ids it kept ever reach a per-row re-check. `TxnCoordinator::zone_scan_eq` performed that re-check by
//! reading the **raw live** label word and `mvcc.in_use()`, and then returned **rows** — not candidates
//! — to its caller. Both halves are wrong, and together they are unrepairable:
//!
//! * `mvcc.in_use()` is true for a record whose creator has not committed, so a row an open writer had
//!   just created was returned to every reader: a **dirty read**, below READ COMMITTED.
//! * the label word is mutated **in place** (`05 §9`), so an open writer's `REMOVE n:L` hid a
//!   **committed** row from every reader: the same dirty read, in the opposite direction.
//! * and because rows were returned rather than candidates, nothing downstream re-checked either.
//!
//! The reason it could not be fixed where it stood is structural: `TxnCoordinator` holds no statement
//! snapshot, and `RecordStore::label_bitmap_at` cannot be called without the `(Snapshot,
//! CommitRegistry)` pair only a statement seam has. The fix moves the decision to that seam
//! (`RecordStoreGraph::zone_scan_eq`), leaves the zone map producing **candidates only**, and re-checks
//! them through the one lifted body every node equality seek already shares — so the zone-routed answer
//! and the row-path answer are the same set by construction.
//!
//! ## The second half: the rebuild that narrows a zone on unproven state
//!
//! [`run_zone_rebuild_across_an_open_overwrite`] covers the other way a zone map loses a committed row.
//! `rebuild_zone_column` summarised the **chain head** of each node's property chain. When that head
//! belonged to an open writer, the committed value underneath it was summarised nowhere, so the zone
//! narrowed below it — and a rollback restores the record but not the summary. Nothing rebuilds a zone
//! map (no rebuild on open, no rollback hook), so that row is pruned for the life of the process. The
//! fix summarises **every** version, exactly as an index refill indexes every version (`rmp` #766).
//!
//! ## Why the DST, and what a single-threaded DST reaches here
//!
//! Every anomaly needs one transaction to be **open** across another transaction's read, which a
//! ticket-valued single-threaded coordinator gives for free: the writer's `CREATE` / `REMOVE` / `SET`
//! sits uncommitted on the page while the reader's statement runs on the same thread. No fault
//! injection and no scheduler are needed — the interleaving IS the fault — and the run is bit-for-bit
//! reproducible over `MemBlockDevice` + `MemLogSink`.
//!
//! ## Non-vacuity, measured rather than assumed
//!
//! Two traps would let these scenarios pass over the unfixed engine, so both are reported as fields and
//! asserted:
//!
//! * the zone map must actually **serve** the column ([`ZoneDirtyReadReport::zone_map_served`]); a
//!   decline (`None`) routes to the exact scan, and the scenario would be comparing a scan with itself;
//! * it must actually **prune** ([`ZoneDirtyReadReport::zones_pruned`]); a summary that keeps every zone
//!   is a full candidate list, and the id range that carries the defect would never be excluded.

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::KeyValues;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// The coordinator type the reproducer drives.
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// A small buffer-pool capacity, so eviction + the WAL rule are exercised during the run.
const POOL_CAPACITY: usize = 64;
/// The summarized label and property.
const LABEL: &str = "Event";
const PROP: &str = "ts";
/// How many `:Event` nodes are seeded, `ts` monotonic in node id (the clustered case a zone map is for).
///
/// Not decoration: at 8000 nodes the column spans 8 zones of 1024 ids, so a single-value equality
/// prunes 7 of them and the scenario is measuring a real skip rather than a full candidate list.
const SEEDED: i64 = 8_000;
/// The value the OPEN writer creates. Outside the seeded range, so a committed match cannot exist.
const CREATED_TS: i64 = 99_999;
/// The committed value the OPEN writer hides by removing the node's label.
const HIDDEN_TS: i64 = 5_000;
/// The column's maximum, and therefore the one value whose omission measurably narrows a zone.
const MAX_TS: i64 = SEEDED - 1;

/// How the in-flight writer ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterEnding {
    /// The writer commits: its creation becomes visible and its removal takes effect.
    Commits,
    /// The writer rolls back: the graph returns to its committed state.
    RollsBack,
}

/// One `(zone-routed rows, row-path rows)` observation, both taken at the SAME snapshot. The row path
/// never consults the zone map, so it is literally the "zone maps disabled" answer and the two agreeing
/// is a real check.
pub type ZoneVsRow = (usize, usize);

/// What one run of [`run_zone_map_dirty_read`] observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneDirtyReadReport {
    /// The value the open writer CREATED, read by a concurrent reader while the writer is open. Must be
    /// `(0, 0)`: nobody may see an uncommitted creation.
    pub created_while_open: ZoneVsRow,
    /// The committed value the open writer hid with `REMOVE n:Event`, read by that same concurrent
    /// reader. Must be `(1, 1)`: an uncommitted removal hides nothing.
    pub hidden_while_open: ZoneVsRow,
    /// The created value again, after the writer's fate is sealed.
    pub created_after: ZoneVsRow,
    /// The hidden value again, after the writer's fate is sealed.
    pub hidden_after: ZoneVsRow,
    /// NON-VACUITY: the zone map served every skip query above (it never declined to the exact scan).
    pub zone_map_served: bool,
    /// NON-VACUITY: zones pruned by the last skip query. `0` means nothing was skipped and the
    /// "zone-routed" answer was a full candidate list.
    pub zones_pruned: u64,
}

impl ZoneDirtyReadReport {
    /// The `rmp` #958 invariant: at every snapshot, the zone-routed answer equals the row path.
    #[must_use]
    pub fn zone_agrees_with_row_path(&self) -> bool {
        self.created_while_open.0 == self.created_while_open.1
            && self.hidden_while_open.0 == self.hidden_while_open.1
            && self.created_after.0 == self.created_after.1
            && self.hidden_after.0 == self.hidden_after.1
    }
}

/// What one run of [`run_zone_rebuild_across_an_open_overwrite`] observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneRebuildReport {
    /// The column's maximum value, read after the rebuild and after the writer's fate is sealed. Must
    /// agree, and must be `(1, 1)` for a rolled-back writer and `(0, 0)` for a committed one.
    pub max_value: ZoneVsRow,
    /// NON-VACUITY: the zone map served the skip query.
    pub zone_map_served: bool,
    /// NON-VACUITY: zones pruned by that skip query.
    pub zones_pruned: u64,
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs `src` inside `txn` and reports how many rows it produced.
fn run_in(coord: &Coord, txn: TxnId, src: &str) -> usize {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(
        !graph.has_error(),
        "captured error: {:?}",
        graph.take_error()
    );
    rows.len()
}

/// Runs `src` in its own transaction and commits.
fn run_write(coord: &mut Coord, src: &str) {
    let txn = coord.begin_serializable();
    let _ = run_in(coord, txn, src);
    coord.commit(txn).expect("write commits");
}

/// The row-path (zone-maps-disabled) answer for `ts = value`, inside `txn`.
fn row_rows(coord: &Coord, txn: TxnId, value: i64) -> usize {
    run_in(
        coord,
        txn,
        &format!("MATCH (n:{LABEL}) WHERE n.{PROP} = {value} RETURN id(n) AS id"),
    )
}

/// The zone-map-routed answer for `ts = value`, inside `txn`. [`None`] is the seam DECLINING, which the
/// callers below report as a non-vacuity failure rather than silently treating as zero rows.
fn zone_rows(coord: &Coord, txn: TxnId, value: i64) -> Option<usize> {
    let graph = coord.statement(txn).expect("statement");
    let hits = graph.zone_scan_eq(LABEL, PROP, &Value::Integer(value), KeyValues::Discard)?;
    assert!(
        !graph.has_error(),
        "captured error: {:?}",
        graph.take_error()
    );
    Some(hits.matched.len())
}

/// `(zone-routed, row-path)` for `ts = value` at ONE snapshot, plus whether the seam served it.
fn zone_vs_row(coord: &Coord, txn: TxnId, value: i64, served: &mut bool) -> ZoneVsRow {
    let zone = match zone_rows(coord, txn, value) {
        Some(n) => n,
        None => {
            *served = false;
            0
        }
    };
    (zone, row_rows(coord, txn, value))
}

/// A coordinator over a fresh in-memory store, seeded with [`SEEDED`] `:Event` nodes whose `ts` is
/// monotonic in node id, all committed.
fn seeded_coordinator() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");
    let mut coord = TxnCoordinator::new(store);
    // Batched so the per-transaction undo footprint stays bounded.
    const BATCH: i64 = 2_000;
    let mut lo = 0;
    while lo < SEEDED {
        let hi = (lo + BATCH).min(SEEDED);
        run_write(
            &mut coord,
            &format!(
                "UNWIND range({lo}, {}) AS i CREATE (:{LABEL} {{{PROP}: i}})",
                hi - 1
            ),
        );
        lo = hi;
    }
    coord
}

/// The headline scenario: an OPEN writer that creates one matching row and hides another, observed by a
/// concurrent reader through the zone map and through the row path at the same snapshot, then again
/// after the writer's fate is sealed.
#[must_use]
pub fn run_zone_map_dirty_read(ending: WriterEnding) -> ZoneDirtyReadReport {
    let coord = seeded_coordinator();
    coord
        .declare_zone_map(LABEL, PROP)
        .expect("declare the zone map");

    // A writer that creates a matching row AND hides a committed one, and stays OPEN. Both writes
    // maintain the zone map (widening), so the affected zones are kept and the candidates really do
    // reach the re-check — the defect is in the re-check, not in the pruning.
    let writer = coord.begin_serializable();
    let _ = run_in(
        &coord,
        writer,
        &format!("CREATE (:{LABEL} {{{PROP}: {CREATED_TS}}})"),
    );
    let _ = run_in(
        &coord,
        writer,
        &format!("MATCH (n:{LABEL}) WHERE n.{PROP} = {HIDDEN_TS} REMOVE n:{LABEL}"),
    );

    // A concurrent reader, at its own snapshot, while the writer is still open.
    let mut zone_map_served = true;
    let reader = coord.begin_serializable();
    let created_while_open = zone_vs_row(&coord, reader, CREATED_TS, &mut zone_map_served);
    let hidden_while_open = zone_vs_row(&coord, reader, HIDDEN_TS, &mut zone_map_served);
    let _ = coord.rollback(reader);

    // Seal the writer's fate.
    match ending {
        WriterEnding::Commits => {
            coord.commit(writer).expect("writer commits");
        }
        WriterEnding::RollsBack => coord.rollback(writer).expect("writer rolls back"),
    }

    let after = coord.begin_serializable();
    let created_after = zone_vs_row(&coord, after, CREATED_TS, &mut zone_map_served);
    let hidden_after = zone_vs_row(&coord, after, HIDDEN_TS, &mut zone_map_served);
    let zones_pruned = coord.zone_map_zones_skipped();
    let _ = coord.rollback(after);

    ZoneDirtyReadReport {
        created_while_open,
        hidden_while_open,
        created_after,
        hidden_after,
        zone_map_served,
        zones_pruned,
    }
}

/// The rebuild half: the zone-map rebuild runs while a writer holds an uncommitted overwrite of the
/// column's maximum, and the writer's fate is then sealed. A rebuild that summarised the chain head
/// alone has narrowed the zone below the committed maximum, and nothing repairs it.
#[must_use]
pub fn run_zone_rebuild_across_an_open_overwrite(ending: WriterEnding) -> ZoneRebuildReport {
    let coord = seeded_coordinator();

    // An open writer moves the column's maximum out of its zone.
    let writer = coord.begin_serializable();
    let _ = run_in(
        &coord,
        writer,
        &format!("MATCH (n:{LABEL}) WHERE n.{PROP} = {MAX_TS} SET n.{PROP} = 0"),
    );

    // THE REBUILD, while that writer is open.
    coord
        .declare_zone_map(LABEL, PROP)
        .expect("declare the zone map");

    match ending {
        WriterEnding::Commits => {
            coord.commit(writer).expect("writer commits");
        }
        WriterEnding::RollsBack => coord.rollback(writer).expect("writer rolls back"),
    }

    let mut zone_map_served = true;
    let reader = coord.begin_serializable();
    let max_value = zone_vs_row(&coord, reader, MAX_TS, &mut zone_map_served);
    let zones_pruned = coord.zone_map_zones_skipped();
    let _ = coord.rollback(reader);

    ZoneRebuildReport {
        max_value,
        zone_map_served,
        zones_pruned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two non-vacuity instruments, asserted once per report so every test below is known to be
    /// measuring a zone map that both served and pruned.
    fn assert_not_vacuous(served: bool, pruned: u64, what: &str) {
        assert!(
            served,
            "non-vacuity: the zone map DECLINED every skip query in {what}, so the comparison is a \
             scan measured against itself",
        );
        assert!(
            pruned > 0,
            "non-vacuity: the zone map pruned no zone at all in {what}, so no id range was excluded \
             and the defect had nothing to hide behind",
        );
    }

    /// THE `rmp` #958 SHAPE, direction 1 (phantom) and direction 2 (hidden committed row), both while
    /// the writer is OPEN. Before the fix the zone-routed answer was `(1, 0)` for the creation — a row
    /// no snapshot could see — and `(0, 1)` for the removal — a committed row dropped because the live
    /// label word already had the bit cleared.
    #[test]
    fn an_open_writer_is_invisible_to_the_zone_routed_scan_958() {
        for ending in [WriterEnding::RollsBack, WriterEnding::Commits] {
            let r = run_zone_map_dirty_read(ending);
            assert_not_vacuous(r.zone_map_served, r.zones_pruned, "the dirty-read scenario");
            assert_eq!(
                r.created_while_open,
                (0, 0),
                "`rmp` #958: the zone-routed scan returned a row an UNCOMMITTED writer created — \
                 `mvcc.in_use()` is not a visibility predicate — {r:?}",
            );
            assert_eq!(
                r.hidden_while_open,
                (1, 1),
                "`rmp` #958: the zone-routed scan dropped a COMMITTED row because an uncommitted \
                 `REMOVE n:Event` had already cleared the in-place label word — {r:?}",
            );
            assert!(
                r.zone_agrees_with_row_path(),
                "the invariant, whole — {r:?}"
            );
        }
    }

    /// The opposite direction, which the fix must not break: once the writer COMMITS, its creation must
    /// appear and its removal must take effect. A re-check that simply ignored uncommitted state would
    /// pass the test above and fail this one.
    #[test]
    fn a_committed_writer_is_reflected_in_the_zone_routed_scan_958() {
        let r = run_zone_map_dirty_read(WriterEnding::Commits);
        assert_not_vacuous(r.zone_map_served, r.zones_pruned, "the committed arm");
        assert_eq!(
            r.created_after,
            (1, 1),
            "the committed creation must be visible to a later reader — {r:?}",
        );
        assert_eq!(
            r.hidden_after,
            (0, 0),
            "the committed label removal must take effect — {r:?}",
        );
    }

    /// And a ROLLED-BACK writer must leave the committed graph exactly as it was.
    #[test]
    fn a_rolled_back_writer_leaves_the_zone_routed_scan_unchanged_958() {
        let r = run_zone_map_dirty_read(WriterEnding::RollsBack);
        assert_not_vacuous(r.zone_map_served, r.zones_pruned, "the rolled-back arm");
        assert_eq!(
            r.created_after,
            (0, 0),
            "a rolled-back creation must not survive anywhere — {r:?}",
        );
        assert_eq!(
            r.hidden_after,
            (1, 1),
            "a rolled-back removal must leave the committed row findable — {r:?}",
        );
    }

    /// The rebuild half of `rmp` #958: summarising the property chain's HEAD narrows the zone on an
    /// uncommitted overwrite, and the rollback that follows restores the record but not the summary.
    #[test]
    fn a_rebuild_across_an_open_overwrite_keeps_the_committed_value_958() {
        let r = run_zone_rebuild_across_an_open_overwrite(WriterEnding::RollsBack);
        assert_not_vacuous(r.zone_map_served, r.zones_pruned, "the rebuild scenario");
        assert_eq!(
            r.max_value,
            (1, 1),
            "`rmp` #958: the rebuild summarised the UNCOMMITTED chain head, narrowing the zone below \
             the committed maximum. The rollback restored the record; nothing restores a zone map, so \
             the row was pruned before any re-check could run — {r:?}",
        );
    }

    /// The committed ending of the same rebuild: the value really is gone, and the zone-routed answer
    /// must say so rather than resurrecting it.
    #[test]
    fn a_rebuild_across_a_committed_overwrite_loses_the_old_value_958() {
        let r = run_zone_rebuild_across_an_open_overwrite(WriterEnding::Commits);
        assert!(
            r.zone_map_served,
            "non-vacuity: the zone map must have served the query — {r:?}",
        );
        assert_eq!(
            r.max_value,
            (0, 0),
            "a committed overwrite must remove the old value from both answers — {r:?}",
        );
    }

    #[test]
    fn reproduction_is_deterministic_958() {
        assert_eq!(
            run_zone_map_dirty_read(WriterEnding::RollsBack),
            run_zone_map_dirty_read(WriterEnding::RollsBack),
        );
        assert_eq!(
            run_zone_map_dirty_read(WriterEnding::Commits),
            run_zone_map_dirty_read(WriterEnding::Commits),
        );
        assert_eq!(
            run_zone_rebuild_across_an_open_overwrite(WriterEnding::RollsBack),
            run_zone_rebuild_across_an_open_overwrite(WriterEnding::RollsBack),
        );
    }
}
