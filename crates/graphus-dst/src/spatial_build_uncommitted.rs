//! Focused deterministic reproducer for a **spatial index build baking an UNCOMMITTED point over the
//! committed one** (`rmp` #779) — the spatial member of the `rmp` #766 family whose text sibling is
//! `rmp` #773 and whose full-text sibling is `rmp` #778.
//!
//! ## The defect
//!
//! The per-entity spatial build helpers collapsed a point property's version chain **newest-wins**.
//! When the newest version belonged to a still-open transaction, that dirty point was the only one
//! indexed and the COMMITTED point was indexed **nowhere**. A reader that began after the build then
//! sought the committed point and got zero rows, while the snapshot-correct store scan returned it —
//! silent loss of a committed row on the read path.
//!
//! The `rmp` #467 cross-snapshot freshness marker did not save it, and the reason is the whole point of
//! this scenario: `note_ft_spatial_mutator` iterates `registered_spatial()`, which is EMPTY before the
//! index exists, so a writer that **predates the index** is never recorded as a mutator and never
//! poisons the marker. Only a writer that starts *after* the index exists is covered.
//!
//! The fix makes the grid **multi-valued per entity**: the build unions every point version, so the
//! committed point stays a candidate, and the executor's residual `distance(...) <op> r` filter — which
//! re-reads each candidate's snapshot-visible point — drops the extras. A superset the caller trims is
//! always correct; a subset never is, because a re-check can REMOVE a candidate but never RESURRECT one.
//!
//! ## Why the DST, not only the coordinator tests
//!
//! The anomaly needs a statement-interleaved timeline — a seed committing a point; a writer moving it
//! and staying **open**; an index build draining *while that writer is open*; then a fresh reader — and
//! it must be observed on the **production build route driven Online**. Driven inline over the
//! deterministic `MemBlockDevice` + `MemLogSink` coordinator it is fully reproducible, and the crash
//! variant below then proves the same property across a real recovery.
//!
//! ## The crash variant proves the rebuild claim
//!
//! The grid is **ephemeral**: it is discarded on close and rebuilt from the recovered store on open, by
//! the same helpers this fix changed. So the reproducer also crashes after the writer's fate is sealed
//! and asserts that the reopened engine's rebuilt grid still answers correctly — for BOTH endings, a
//! committed writer (its point must be findable) and a rolled-back one (the original point must be).

use graphus_core::TxnId;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_storage::recovery::recover_device;
use graphus_wal::{LogSink, MemLogSink, WalManager};

/// The coordinator type the reproducer drives.
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// A small buffer-pool capacity, so eviction + the WAL rule are exercised during the run.
const POOL_CAPACITY: usize = 16;

/// The committed point, and the query that looks for it.
const AT_ORIGIN: &str =
    "MATCH (n:City) WHERE distance(n.loc, point({x: 0, y: 0})) <= 1 RETURN id(n) AS id";
/// The in-flight writer's point, and the query that looks for it.
const AT_FAR: &str =
    "MATCH (n:City) WHERE distance(n.loc, point({x: 100, y: 100})) <= 1 RETURN id(n) AS id";

/// How the in-flight writer ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterEnding {
    /// The writer commits after the build drained: ITS point becomes the committed one.
    Commits,
    /// The writer rolls back after the build drained: the ORIGINAL point stays committed.
    RollsBack,
}

/// One reproduction's observations. Each field is `(index-routed rows, forced-full-scan rows)` for one
/// query at one snapshot — the scan being the ground truth the index must agree with exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpatialBuildReport {
    /// The committed point, read after the build drained and the writer's fate was sealed.
    pub origin_after: (usize, usize),
    /// The writer's point, read after the build drained and the writer's fate was sealed.
    pub far_after: (usize, usize),
    /// The committed point, read after a crash + recovery + grid rebuild.
    pub origin_recovered: (usize, usize),
    /// The writer's point, read after a crash + recovery + grid rebuild.
    pub far_recovered: (usize, usize),
}

impl SpatialBuildReport {
    /// The `rmp` #779 invariant: the spatial seek returns EXACTLY what the snapshot-correct scan
    /// returns, for both queries, both before and after recovery. Any disagreement is either the #766
    /// loss (seek < scan) or a wrong row (seek > scan).
    #[must_use]
    pub fn seek_agrees_with_scan(&self) -> bool {
        self.origin_after.0 == self.origin_after.1
            && self.far_after.0 == self.far_after.1
            && self.origin_recovered.0 == self.origin_recovered.1
            && self.far_recovered.0 == self.far_recovered.1
    }
}

fn compile(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog)
}

fn run_plan(coord: &Coord, txn: TxnId, plan: &PhysicalPlan) -> usize {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
    cursor.collect_all().expect("collect").len()
}

fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let _ = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

/// `(index-routed rows, forced-full-scan rows)` for `query` at ONE freshly-begun snapshot.
fn seek_vs_scan(coord: &mut Coord, query: &str) -> (usize, usize) {
    let txn = coord.begin_serializable();
    let seek = run_plan(coord, txn, &compile(query, &coord.catalog()));
    let scan = run_plan(coord, txn, &compile(query, &IndexCatalog::empty()));
    coord.commit(txn).expect("read commits");
    (seek, scan)
}

/// Recovers a fresh coordinator from `store`'s device + WAL image — the crash + reopen the grid is
/// rebuilt by.
fn recover(store: &RecordStore<MemBlockDevice, MemLogSink>) -> Coord {
    // Replay only the DURABLE WAL prefix onto a blank device — a genuine crash, not a clean close: any
    // byte the sink had buffered but not synced is lost, exactly as it would be on power failure.
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    let recovered = RecordStore::open(device, wal, POOL_CAPACITY).expect("open store");
    TxnCoordinator::new(recovered)
}

/// Drives the interleaving for `ending` and returns the report.
///
/// Timeline: seed commits a `City` at the origin; a writer moves it to (100, 100) and stays **open**;
/// the point index is declared and its build is drained to `Online` **while that writer is open** (the
/// production route); the writer then commits or rolls back; both queries are observed; the engine is
/// then crashed, recovered, and both queries observed again against the rebuilt grid.
#[must_use]
pub fn run_spatial_build_uncommitted(ending: WriterEnding) -> SpatialBuildReport {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");
    let mut coord = TxnCoordinator::new(store);

    // Seed: a committed City at the origin.
    run_write(
        &mut coord,
        "CREATE (:City {name: 'a', loc: point({x: 0, y: 0})})",
    );

    // A writer moves it far away and stays OPEN. It PREDATES the index, which is exactly why the
    // #467 freshness marker never learns about it.
    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH (n:City) SET n.loc = point({x: 100, y: 100})",
            &IndexCatalog::empty(),
        ),
    );

    // THE PRODUCTION ROUTE, driven Online, while that writer is still open.
    coord
        .create_point_index("by_loc", "City", "loc", false)
        .expect("declare point index");
    while coord.advance_index_builds(usize::MAX) {}
    assert!(
        !coord.catalog().indexes().is_empty(),
        "non-vacuity: the build must have produced an index the planner routes to",
    );

    // Seal the writer's fate.
    match ending {
        WriterEnding::Commits => {
            coord.commit(writer).expect("writer commits");
        }
        WriterEnding::RollsBack => {
            coord.rollback(writer).expect("writer rolls back");
        }
    }

    let origin_after = seek_vs_scan(&mut coord, AT_ORIGIN);
    let far_after = seek_vs_scan(&mut coord, AT_FAR);

    // Crash + recovery: the grid is discarded and rebuilt from the recovered store.
    let store = coord.into_store();
    let mut coord2 = recover(&store);
    assert!(
        !coord2.catalog().indexes().is_empty(),
        "non-vacuity: the recovered engine must still route to the point index",
    );
    let origin_recovered = seek_vs_scan(&mut coord2, AT_ORIGIN);
    let far_recovered = seek_vs_scan(&mut coord2, AT_FAR);

    SpatialBuildReport {
        origin_after,
        far_after,
        origin_recovered,
        far_recovered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The headline `rmp` #779 property, for a writer that ROLLS BACK: the committed point at the
    /// origin must still be findable through the index. Before the fix the build had baked the
    /// uncommitted (100, 100) in as the node's only grid entry, so the seek returned 0 while the scan
    /// returned 1 — a committed row lost to every future reader, and lost permanently, because a
    /// re-check can remove a candidate but never resurrect one.
    #[test]
    fn a_rolled_back_writer_leaves_the_committed_point_findable_779() {
        let report = run_spatial_build_uncommitted(WriterEnding::RollsBack);
        assert_eq!(
            report.origin_after,
            (1, 1),
            "rmp #779: the committed point must be findable through the index, and the scan agrees: \
             {report:?}"
        );
        assert_eq!(
            report.far_after,
            (0, 0),
            "the rolled-back point must be findable by NEITHER path: {report:?}"
        );
        assert!(report.seek_agrees_with_scan(), "{report:?}");
    }

    /// The other reader, and the reason "index only the newest COMMITTED version" is not a fix: once
    /// the in-flight writer COMMITS, its point must be findable too. `commit` does not re-insert grid
    /// entries — they are made eagerly at write time — so a committed-only image would lose this row
    /// instead. Only the version union serves both readers.
    #[test]
    fn a_committed_writer_leaves_its_own_point_findable_779() {
        let report = run_spatial_build_uncommitted(WriterEnding::Commits);
        assert_eq!(
            report.far_after,
            (1, 1),
            "rmp #779: the writer's now-committed point must be findable: {report:?}"
        );
        assert_eq!(
            report.origin_after,
            (0, 0),
            "the superseded point must be findable by NEITHER path — if the seek returns it, the \
             residual distance filter is not re-checking and the multi-valued grid is unsound: \
             {report:?}"
        );
        assert!(report.seek_agrees_with_scan(), "{report:?}");
    }

    /// The grid is ephemeral and rebuilt from the recovered store by the same helpers this fix
    /// changed, so the property must survive a crash for BOTH endings.
    #[test]
    fn the_rebuilt_grid_after_recovery_still_agrees_with_the_scan_779() {
        for ending in [WriterEnding::Commits, WriterEnding::RollsBack] {
            let report = run_spatial_build_uncommitted(ending);
            assert!(
                report.seek_agrees_with_scan(),
                "{ending:?}: the rebuilt grid disagrees with the snapshot-correct scan: {report:?}"
            );
            // The recovered engine must see exactly the committed outcome, not the pre-crash one.
            let (expect_origin, expect_far) = match ending {
                WriterEnding::Commits => (0, 1),
                WriterEnding::RollsBack => (1, 0),
            };
            assert_eq!(
                report.origin_recovered.0, expect_origin,
                "{ending:?}: wrong committed state at the origin after recovery: {report:?}"
            );
            assert_eq!(
                report.far_recovered.0, expect_far,
                "{ending:?}: wrong committed state at (100,100) after recovery: {report:?}"
            );
        }
    }

    #[test]
    fn reproduction_is_deterministic() {
        assert_eq!(
            run_spatial_build_uncommitted(WriterEnding::RollsBack),
            run_spatial_build_uncommitted(WriterEnding::RollsBack)
        );
        assert_eq!(
            run_spatial_build_uncommitted(WriterEnding::Commits),
            run_spatial_build_uncommitted(WriterEnding::Commits)
        );
    }
}
