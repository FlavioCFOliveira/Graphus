//! **The measured cost of the candidate + re-verification access model** (`rmp` task #991).
//!
//! Every index access path in Graphus is a *candidate list plus a re-verification*: the derived,
//! MVCC-unaware index answers with a **superset** of the matching ids, and the read body re-reads each
//! candidate to test visibility and re-apply the predicate. `PROFILE`'s `dbHits` charges what an operator
//! **matched**, so on its own it cannot distinguish a seek that examined ten candidates from one that
//! examined a million to return the same ten rows — and the blanket `mark_all_live_nodes` predicate
//! footprint that every non-equality node seek registers (one SIREAD per live node, whatever the seek
//! returns) appeared nowhere at all.
//!
//! This suite pins the counters that close both gaps, and the **baseline** they read on a fixed fixture,
//! so every later change in the sprint has a number to be measured against. PostgreSQL's `EXPLAIN
//! ANALYZE` reports the same distinction as *"Rows Removed by Filter"*
//! (`src/backend/commands/explain.c`; counters in `src/include/executor/instrument.h`); the names here
//! are Graphus's own, because the measured quantity is Graphus's own (decision `D-query-prefixes`).
//!
//! Everything runs against the **real** persistent record store through a `TxnCoordinator` — the
//! coordinated path, the only one that owns a derived `IndexSet` and therefore the only one where an
//! index seek is genuinely served by an index. A `MemGraph` has no candidate model at all and would
//! prove nothing.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::plan_description::{PlanDescription, PlanNode};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// The baseline fixture size. Small enough to build in a unit test, large enough that a blanket
/// whole-store marker pass is an unmistakable multiple of the rows a selective seek returns.
const NODES: i64 = 40;

// =================================================================================================
// Harness
// =================================================================================================

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    TxnCoordinator::new(RecordStore::create(device, wal, 256, 1).expect("store"))
}

fn compile_with(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog).with_prefix(ast.prefix())
}

/// Runs `src` in its own committed transaction, returning the rows.
fn run(coord: &mut Coord, src: &str, catalog: &IndexCatalog) -> Vec<Row> {
    let plan = compile_with(src, catalog);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open");
        let rows = cursor.collect_all().expect("collect");
        assert!(
            graph.take_error().is_none(),
            "{src:?} captured a storage error"
        );
        rows
    };
    coord.commit(txn).expect("commit");
    rows
}

fn write(coord: &mut Coord, src: &str) {
    run(coord, src, &IndexCatalog::empty());
}

/// Runs `src` (which must carry the `PROFILE` prefix) and returns `(rows, plan description)`.
fn profile(coord: &mut Coord, src: &str, catalog: &IndexCatalog) -> (Vec<Row>, PlanDescription) {
    let plan = compile_with(src, catalog);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    let out = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open");
        let rows = cursor.collect_all().expect("collect");
        let d = PlanDescription::profile(cursor.profile().expect("a PROFILEd statement measures"));
        assert!(
            graph.take_error().is_none(),
            "{src:?} captured a storage error"
        );
        (rows, d)
    };
    coord.commit(txn).expect("commit");
    out
}

/// The first operator of `kind` in a rendered plan, which must exist.
fn op_of<'a>(p: &'a PlanDescription, kind: &str) -> &'a PlanNode {
    fn find<'a>(n: &'a PlanNode, kind: &str) -> Option<&'a PlanNode> {
        if n.operator_type == kind {
            return Some(n);
        }
        n.children.iter().find_map(|c| find(c, kind))
    }
    find(p.root(), kind)
        .unwrap_or_else(|| panic!("no {kind} operator in the plan; got {:?}", p.root()))
}

/// The integer value of `key` in an operator's `args`, or [`None`] when the key is **absent** — which,
/// on the store-backed seam every test here drives, means a measured zero (see `push_candidate_args`
/// in `plan_description` for why that reading needs the qualifier).
fn arg(node: &PlanNode, key: &str) -> Option<i64> {
    node.args
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| match v {
            Value::Integer(n) => *n,
            other => panic!("{key} is not an integer: {other:?}"),
        })
}

/// [`arg`], defaulting an absent (measured-zero) counter to `0`.
fn arg0(node: &PlanNode, key: &str) -> i64 {
    arg(node, key).unwrap_or(0)
}

/// One operator's complete measured record: the two counters `PROFILE` always had, plus the five
/// `rmp` #991 added. Compared as a whole so a baseline assertion names every number that moved.
#[derive(Debug, PartialEq, Eq)]
struct Counters {
    rows: u64,
    db_hits: u64,
    examined: i64,
    rejected_visibility: i64,
    rejected_filter: i64,
    read_markers: i64,
    predicate_markers: i64,
}

fn counters(node: &PlanNode) -> Counters {
    Counters {
        rows: node.rows.expect("a PROFILEd operator reports rows"),
        db_hits: node.db_hits.expect("a PROFILEd operator reports dbHits"),
        examined: arg0(node, "CandidatesExamined"),
        rejected_visibility: arg0(node, "CandidatesRejectedByVisibility"),
        rejected_filter: arg0(node, "CandidatesRejectedByFilter"),
        read_markers: arg0(node, "ReadMarkers"),
        predicate_markers: arg0(node, "PredicateMarkers"),
    }
}

/// The number of candidates that **survived** the re-verification: what the access path examined,
/// minus the two disjoint rejection reasons.
///
/// This counts *candidates*, **not** the operator's rows. The two are equal only when the operator
/// emits exactly one row per survivor — the common case, but not a guarantee. See
/// [`surviving_candidates_are_not_rows_991`], which measures both mechanisms that break it.
fn surviving_candidates(c: &Counters) -> i64 {
    c.examined - c.rejected_visibility - c.rejected_filter
}

/// Asserts the disjoint counters account for every candidate, against an **explicitly stated** number
/// of survivors — never against `rows`, which is a different quantity.
fn assert_survivors(c: &Counters, expected: i64) {
    assert_eq!(
        surviving_candidates(c),
        expected,
        "examined - rejected(visibility) - rejected(filter) must equal the surviving candidates: {c:?}"
    );
}

/// `NODES` `:Person` nodes (`name`, `age`) in a ring of `:KNOWS` edges, with `name` and `age` indexed.
fn fixture() -> (Coord, IndexCatalog) {
    let mut coord = fresh_coord();
    for i in 0..NODES {
        write(
            &mut coord,
            &format!("CREATE (:Person {{name: 'p{i}', age: {i}}})"),
        );
    }
    for i in 0..NODES {
        let j = (i + 1) % NODES;
        write(
            &mut coord,
            &format!(
                "MATCH (a:Person {{name: 'p{i}'}}), (b:Person {{name: 'p{j}'}}) CREATE (a)-[:KNOWS]->(b)"
            ),
        );
    }
    coord
        .create_node_property_index("Person", "name")
        .expect("name index");
    coord
        .create_node_property_index("Person", "age")
        .expect("age index");
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(10_000);
    }
    let catalog = coord.catalog();
    (coord, catalog)
}

// =================================================================================================
// 1. A seek reports the candidates it EXAMINED, distinct from the rows it returned
// =================================================================================================

/// **Acceptance criterion 1.** An equality seek over a candidate list that is genuinely a *superset*
/// returns one row after examining two candidates — and the plan now says so.
///
/// # Where the superset comes from (not contrived)
///
/// The index key codec is deliberately **not injective**: `keycodec::encode_integer` places every `i64`
/// on the `f64` magnitude line, so `2^54 + 3` and `2^54 + 5` share one key (`rmp` #894 settled that
/// these differences are observable, which is exactly why the seek re-reads and re-checks every
/// candidate instead of trusting the index). Two nodes therefore answer one seek, and one of them is
/// rejected by the value residual.
///
/// # Why this is not vacuous
///
/// Before `rmp` #991 the operator carried `Rows = 1` and `DbHits = 1` and **nothing else**: the second
/// candidate — read from the store, decoded, compared and thrown away — was invisible. `arg(...)`
/// returns `None` for `CandidatesExamined` against the pre-change engine, so the `expect` below panics;
/// and the `examined > rows` assertion is the substantive claim, not the mere presence of a key.
#[test]
fn a_seek_reports_candidates_examined_distinct_from_the_rows_it_returned_991() {
    let mut coord = fresh_coord();
    // Two integers that share one index key, plus an unrelated third node.
    let (a, b) = ((1i64 << 54) + 3, (1i64 << 54) + 5);
    write(&mut coord, &format!("CREATE (:T {{v: {a}}})"));
    write(&mut coord, &format!("CREATE (:T {{v: {b}}})"));
    write(&mut coord, "CREATE (:T {v: 1})");
    coord.create_node_property_index("T", "v").expect("v index");
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(10_000);
    }
    let catalog = coord.catalog();

    let (rows, plan) = profile(
        &mut coord,
        &format!("PROFILE MATCH (n:T {{v: {a}}}) RETURN n.v AS v"),
        &catalog,
    );
    assert_eq!(rows.len(), 1, "only one node really holds the seek value");

    let seek = op_of(&plan, "NodeIndexSeek");
    let c = counters(seek);
    let examined = arg(seek, "CandidatesExamined")
        .expect("a seek reports the candidates it examined (rmp #991)");
    assert_eq!(c.rows, 1);
    assert_eq!(
        c.db_hits, 1,
        "dbHits still charges only what the seek MATCHED"
    );
    assert_eq!(
        examined, 2,
        "the colliding key made the candidate list a superset: {c:?}"
    );
    assert!(
        examined > i64::try_from(c.rows).unwrap(),
        "the gap between examined and returned is exactly what dbHits could not show: {c:?}"
    );
    assert_eq!(
        c.rejected_filter, 1,
        "the rejected candidate is attributed to the value residual, not lost: {c:?}"
    );
    // One candidate survived, and this seek emits exactly one row for it.
    assert_survivors(&c, 1);
}

/// An **unselective** range seek — `age >= 0` matches every node — is the shape whose cost the sprint
/// most needs a number for. Its candidates and its markers are counted separately, and they differ by a
/// factor the row count alone never revealed.
#[test]
fn an_unselective_range_seek_reports_its_full_candidate_pass_991() {
    let (mut coord, catalog) = fixture();
    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person) WHERE n.age >= 0 RETURN n.age AS age",
        &catalog,
    );
    assert_eq!(rows.len(), NODES as usize, "the bound excludes nothing");

    let c = counters(op_of(&plan, "NodeIndexRangeSeek"));
    assert_eq!(c.examined, NODES, "every node is a candidate: {c:?}");
    assert!(
        c.read_markers > c.examined,
        "the seek emits strictly more SIREAD markers ({}) than the candidates it examined ({}) — \
         the blanket predicate footprint, invisible until now: {c:?}",
        c.read_markers,
        c.examined
    );
    assert_survivors(&c, NODES);
}

// =================================================================================================
// 2. The SIREAD markers an operator emitted are counted and visible
// =================================================================================================

/// **Acceptance criterion 2**, and the headline finding this task exists to expose: a node RANGE seek
/// registers the blanket `mark_all_live_nodes` predicate footprint — **one SIREAD marker per live node**
/// — however few rows it returns. That whole-store pass never appeared in any counter.
///
/// # Why this is not vacuous
///
/// `ReadMarkers` did not exist before `rmp` #991, so `arg(...)` returns `None` and the `expect` panics
/// against the pre-change engine. The magnitude is the real assertion: a seek that returns **2** rows
/// must be shown to have marked all **40** live nodes.
#[test]
fn a_range_seek_reports_the_blanket_read_markers_it_emitted_991() {
    let (mut coord, catalog) = fixture();
    let (rows, plan) = profile(
        &mut coord,
        &format!(
            "PROFILE MATCH (n:Person) WHERE n.age >= {} RETURN n.age AS age",
            NODES - 2
        ),
        &catalog,
    );
    assert_eq!(rows.len(), 2, "only two nodes satisfy the bound");

    let seek = op_of(&plan, "NodeIndexRangeSeek");
    let markers = arg(seek, "ReadMarkers")
        .expect("an operator reports the SIREAD markers it emitted (rmp #991)");
    let c = counters(seek);
    assert!(
        markers >= NODES,
        "the range seek marks every live node ({NODES}) whatever it returns, but reported \
         only {markers} markers: {c:?}"
    );
    assert!(
        markers > 10 * i64::try_from(c.rows).unwrap(),
        "two rows cost a {markers}-marker whole-store pass — the cost this counter exists \
         to make visible: {c:?}"
    );
    assert_eq!(
        arg(seek, "PredicateMarkers"),
        Some(1),
        "and the one coarse Label predicate marker that pairs with it: {c:?}"
    );
}

/// The **equality** seek is the deliberate contrast (`rmp` #316 removed its blanket marker, because it
/// manufactured an rw-edge with every concurrent node writer and drove a measured abort storm): it must
/// NOT show a whole-store marker pass. The two tests together are what makes `ReadMarkers` a
/// *diagnostic* rather than a constant.
#[test]
fn an_equality_seek_shows_no_blanket_marker_pass_991() {
    let (mut coord, catalog) = fixture();
    let (_, eq_plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person {name: 'p7'}) RETURN n.name AS name",
        &catalog,
    );
    let eq = counters(op_of(&eq_plan, "NodeIndexSeek"));

    let (_, range_plan) = profile(
        &mut coord,
        &format!(
            "PROFILE MATCH (n:Person) WHERE n.age >= {} RETURN n.age AS age",
            NODES - 2
        ),
        &catalog,
    );
    let range = counters(op_of(&range_plan, "NodeIndexRangeSeek"));

    assert!(
        eq.read_markers < NODES,
        "the equality seek must not mark every live node (rmp #316): {eq:?}"
    );
    assert!(
        range.read_markers > 10 * eq.read_markers,
        "the range seek's blanket footprint must be measurably heavier than the equality \
         seek's precise one — range {range:?} vs eq {eq:?}"
    );
}

// =================================================================================================
// 3. The recorded baseline (acceptance criterion 3)
// =================================================================================================

/// **Acceptance criterion 3** — the recorded baseline, as executable assertions rather than prose, for
/// the four access paths this sprint will change: a selective equality seek, an unselective range seek,
/// a label scan and an untyped traversal.
///
/// Every number below was **measured** on this fixture (`NODES` = 40 `:Person` nodes in a `:KNOWS` ring,
/// `name` and `age` indexed, coordinated path, real record store, statements run inline). A later task
/// that makes any of these paths cheaper — or accidentally dearer — fails here and names the number it
/// moved. That is the point: the project decides empirically, and this is the "before".
///
/// Read the marker columns first; they are where the surprises are:
///
/// | path | rows | dbHits | examined | readMarkers |
/// | ---- | ---: | -----: | -------: | ----------: |
/// | selective equality seek | 1 | 1 | 1 | **2** |
/// | unselective range seek | 40 | 40 | 40 | **120** |
/// | label scan | 40 | 40 | 40 | **80** |
/// | untyped traversal (one anchor) | 1 | 1 | 2 | 2 |
///
/// The label scan marks every node **twice** (the blanket `mark_all_live_nodes` pass, then the
/// per-candidate marker of the re-check that follows it), and the unselective range seek **three**
/// times (blanket pass, candidate re-check, and the freshness re-read of each survivor's property).
#[test]
fn the_recorded_baseline_for_the_four_access_paths_991() {
    let (mut coord, catalog) = fixture();

    // ---- 1. selective equality seek: one row, precise footprint ---------------------------------
    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person {name: 'p7'}) RETURN n.name AS name",
        &catalog,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(
        counters(op_of(&plan, "NodeIndexSeek")),
        Counters {
            rows: 1,
            db_hits: 1,
            examined: 1,
            rejected_visibility: 0,
            rejected_filter: 0,
            read_markers: 2,
            predicate_markers: 1,
        },
        "BASELINE (rmp #991) — selective equality seek"
    );

    // ---- 2. unselective range seek: every node examined, marked three times ----------------------
    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person) WHERE n.age >= 0 RETURN n.age AS age",
        &catalog,
    );
    assert_eq!(rows.len(), NODES as usize);
    assert_eq!(
        counters(op_of(&plan, "NodeIndexRangeSeek")),
        Counters {
            rows: 40,
            db_hits: 40,
            examined: 40,
            rejected_visibility: 0,
            rejected_filter: 0,
            read_markers: 120,
            predicate_markers: 1,
        },
        "BASELINE (rmp #991) — unselective range seek: 3 markers per row"
    );

    // ---- 3. label scan ---------------------------------------------------------------------------
    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person) RETURN n.name AS name",
        &catalog,
    );
    assert_eq!(rows.len(), NODES as usize);
    assert_eq!(
        counters(op_of(&plan, "TokenLookupScan")),
        Counters {
            rows: 40,
            db_hits: 40,
            examined: 40,
            rejected_visibility: 0,
            rejected_filter: 0,
            read_markers: 80,
            predicate_markers: 1,
        },
        "BASELINE (rmp #991) — label scan: every node marked twice"
    );

    // ---- 4. untyped traversal ---------------------------------------------------------------------
    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (a:Person {name: 'p7'})-[]->(b) RETURN b.name AS name",
        &catalog,
    );
    assert_eq!(rows.len(), 1, "the ring gives p7 exactly one out-edge");
    assert_eq!(
        counters(op_of(&plan, "ExpandAll")),
        Counters {
            rows: 1,
            db_hits: 1,
            examined: 2,
            rejected_visibility: 0,
            rejected_filter: 1,
            read_markers: 2,
            predicate_markers: 1,
        },
        "BASELINE (rmp #991) — untyped traversal: both incident edges read, one rejected by \
         the traversal direction"
    );
}

// =================================================================================================
// 5. Omitted counters stay omitted, and are never fabricated (acceptance criterion 5)
// =================================================================================================

/// **Acceptance criterion 5.** The counters Graphus does not measure are still absent; the new counters
/// appear only where they were really measured (a zero is omitted, never padded in); and an `EXPLAIN` —
/// which executes nothing — reports none of them at all.
#[test]
fn omitted_counters_stay_omitted_and_zero_is_not_padded_991() {
    const CANDIDATE_KEYS: [&str; 5] = [
        "CandidatesExamined",
        "CandidatesRejectedByVisibility",
        "CandidatesRejectedByFilter",
        "ReadMarkers",
        "PredicateMarkers",
    ];
    let (mut coord, catalog) = fixture();

    // ---- a PROFILE -------------------------------------------------------------------------------
    let (_, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person {name: 'p7'}) RETURN n.name AS name",
        &catalog,
    );
    let mut nodes = vec![plan.root()];
    let mut seen_examined = false;
    while let Some(node) = nodes.pop() {
        nodes.extend(node.children.iter());
        for unmeasured in [
            "pageCacheHits",
            "pageCacheMisses",
            "pageCacheHitRatio",
            "time",
        ] {
            assert!(
                arg(node, unmeasured).is_none(),
                "{unmeasured} is not measured and must never be reported ({})",
                node.operator_type
            );
        }
        // A counter that IS present must be non-zero: absence is the measured zero, so a zero-valued
        // key would be padding the plan with nothing.
        for measured in CANDIDATE_KEYS {
            if let Some(n) = arg(node, measured) {
                assert!(
                    n != 0,
                    "{measured} is emitted only when non-zero ({})",
                    node.operator_type
                );
            }
        }
        seen_examined |= arg(node, "CandidatesExamined").is_some();
        // The operator that emits no candidate counter is exactly one that examines no candidate.
        if node.operator_type == "Projection" {
            assert!(
                arg(node, "CandidatesExamined").is_none(),
                "a Projection examines no candidate, so the counter is omitted, not zero-filled"
            );
        }
    }
    assert!(
        seen_examined,
        "at least one operator of a store-backed PROFILE must report examined candidates"
    );

    // ---- an EXPLAIN ------------------------------------------------------------------------------
    let explained = PlanDescription::explain(&compile_with(
        "EXPLAIN MATCH (n:Person {name: 'p7'}) RETURN n.name AS name",
        &catalog,
    ));
    let mut nodes = vec![explained.root()];
    while let Some(node) = nodes.pop() {
        nodes.extend(node.children.iter());
        assert!(node.rows.is_none() && node.db_hits.is_none());
        for measured in CANDIDATE_KEYS {
            assert!(
                arg(node, measured).is_none(),
                "an EXPLAIN runs nothing, so it measures nothing and reports no {measured}"
            );
        }
    }
}

// =================================================================================================
// Attribution, neutrality, and the visibility bucket
// =================================================================================================

/// The counters are attributed to the operator that made the storage call, not smeared over the plan —
/// the same containment rule `dbHits` follows. A seek feeding a traversal is the smallest shape that can
/// tell the difference.
#[test]
fn candidate_counts_land_on_the_operator_that_examined_them_991() {
    let (mut coord, catalog) = fixture();
    let (_, plan) = profile(
        &mut coord,
        "PROFILE MATCH (a:Person {name: 'p7'})-[]->(b) RETURN b.name AS name",
        &catalog,
    );
    let seek = counters(op_of(&plan, "NodeIndexSeek"));
    let expand = counters(op_of(&plan, "ExpandAll"));
    assert_eq!(
        seek.examined, 1,
        "the anchor seek examined its own single candidate: {seek:?}"
    );
    assert_eq!(
        expand.examined, 2,
        "the traversal examined the anchor's two incident edges, and they are NOT charged to \
         the seek beneath it: {expand:?}"
    );
    assert_eq!(
        arg0(op_of(&plan, "Projection"), "CandidatesExamined"),
        0,
        "the root projection reads properties, but examines no candidate of its own"
    );
}

/// Instrumentation must be observationally neutral: the same statement with and without the `PROFILE`
/// prefix produces the identical bag.
#[test]
fn profiling_the_candidates_does_not_change_the_result_991() {
    let (mut coord, catalog) = fixture();
    for query in [
        "MATCH (n:Person {name: 'p7'}) RETURN n.name AS name",
        "MATCH (n:Person) WHERE n.age >= 0 RETURN n.age AS age",
        "MATCH (n:Person) RETURN n.name AS name",
        "MATCH (a:Person {name: 'p7'})-[]->(b) RETURN b.name AS name",
    ] {
        let plain = run(&mut coord, query, &catalog);
        let (profiled, _) = profile(&mut coord, &format!("PROFILE {query}"), &catalog);
        assert_eq!(
            plain.len(),
            profiled.len(),
            "PROFILE changed the row count of {query:?}"
        );
        for (a, b) in plain.iter().zip(profiled.iter()) {
            assert_eq!(
                format!("{a:?}"),
                format!("{b:?}"),
                "PROFILE changed a row of {query:?}"
            );
        }
    }
}

/// A candidate the incidence chain still threads but whose version this snapshot cannot see is counted
/// as **rejected by visibility**, not silently dropped — the distinction the `Option`-shaped read seams
/// used to collapse, and the reason `rel_data` now delegates to a discriminated `rel_candidate`.
#[test]
fn a_deleted_candidate_is_counted_as_rejected_by_visibility_991() {
    let (mut coord, catalog) = fixture();
    // Delete p7's outgoing ring edge. The incidence chain threads the tombstone until GC, so a
    // later traversal still reads it and must reject it on visibility.
    write(
        &mut coord,
        "MATCH (:Person {name: 'p7'})-[r]->(:Person {name: 'p8'}) DELETE r",
    );
    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (a:Person {name: 'p7'})-[]-(b) RETURN b.name AS name",
        &catalog,
    );
    let expand = counters(op_of(&plan, "ExpandAll"));
    assert_eq!(rows.len(), 1, "only the incoming edge survives");
    assert_eq!(
        expand.rejected_visibility, 1,
        "the deleted edge is still examined, and is reported as a visibility rejection rather \
         than as an absence: {expand:?}"
    );
    assert_survivors(&expand, 1);
}

/// **Surviving candidates are not rows** — the reason every claim about the disjoint counters is
/// phrased over *candidates* and never over the operator's row count.
///
/// Both mechanisms below are measured, not argued. Each one is why the wire contract in
/// `specification/06-bolt-and-error-shapes.md` §3.1 says "survived the re-verification" rather than
/// "survived into the operator's rows".
///
/// # Why this is not vacuous
///
/// It fails against the wording it replaces: assert the identity over `rows` and the first case below
/// panics with `2 != 1`. It is also the test that would have caught the original over-claim, which the
/// four-path baseline fixture happened not to contain.
#[test]
fn surviving_candidates_are_not_rows_991() {
    // ---- (i) de-duplication: one id examined twice, surviving twice, yielding ONE row -----------
    //
    // The derived index only ever INSERTS on reindex, so updating an indexed property leaves the old
    // entry in the tree beside the new one. A range covering both keys therefore names the same id
    // twice, and the seek's own `dedup` collapses the two survivors into one row.
    let mut coord = fresh_coord();
    write(&mut coord, "CREATE (:T {v: 1})");
    coord.create_node_property_index("T", "v").expect("v index");
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(10_000);
    }
    let catalog = coord.catalog();
    write(&mut coord, "MATCH (n:T) SET n.v = 2");

    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:T) WHERE n.v >= 1 AND n.v <= 2 RETURN n.v AS v",
        &catalog,
    );
    assert_eq!(rows.len(), 1, "there is only one node");
    let seek = counters(op_of(&plan, "NodeIndexRangeSeek"));
    assert_eq!(
        seek.examined, 2,
        "the stale and the live index entry both name the id, so it is examined twice: {seek:?}"
    );
    assert_eq!(
        surviving_candidates(&seek),
        2,
        "and both survive the re-verification — the node's current value satisfies the range \
         under either entry: {seek:?}"
    );
    assert_eq!(
        seek.rows, 1,
        "…yet the operator emits ONE row, because the seek de-duplicates. THIS is why the \
         identity is over candidates and not over rows: {seek:?}"
    );

    // ---- (ii) one surviving candidate, reported on both of its sides ---------------------------
    //
    // A self-loop under an undirected pattern is a single relationship candidate that the seam
    // reports twice (once as the outgoing side, once as the incoming side) — visible as `dbHits = 2`
    // against `CandidatesExamined = 1`. The executor's relationship-isomorphism de-duplication then
    // brings the row count back to one, so here the two mechanisms happen to cancel; the seam-level
    // asymmetry is real either way and is what the wording must not deny.
    let mut coord = fresh_coord();
    write(&mut coord, "CREATE (:L {n: 1})");
    write(&mut coord, "MATCH (a:L) CREATE (a)-[:R]->(a)");
    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (a:L)-[]-(b) RETURN b.n AS n",
        &IndexCatalog::empty(),
    );
    assert_eq!(rows.len(), 1);
    let expand = counters(op_of(&plan, "ExpandAll"));
    assert_eq!(
        expand.examined, 1,
        "one incident relationship candidate: {expand:?}"
    );
    assert_eq!(surviving_candidates(&expand), 1);
    assert_eq!(
        expand.db_hits, 2,
        "…which the seam reported on BOTH of its sides — two records charged for one \
         surviving candidate: {expand:?}"
    );
}

/// Pins the two measured figures published outside the test suite — `docs/cypher.md` and
/// `graphus-bench/RESULTS.md` §11.1 — so a silent drift fails here and names the number it moved,
/// exactly as the four-path baseline does.
#[test]
fn the_published_documentation_figures_are_pinned_991() {
    let (mut coord, catalog) = fixture();

    // `docs/cypher.md` and RESULTS.md §11.1: the selective range seek.
    let (rows, plan) = profile(
        &mut coord,
        &format!(
            "PROFILE MATCH (n:Person) WHERE n.age >= {} RETURN n.age AS age",
            NODES - 2
        ),
        &catalog,
    );
    assert_eq!(rows.len(), 2);
    assert_eq!(
        counters(op_of(&plan, "NodeIndexRangeSeek")),
        Counters {
            rows: 2,
            db_hits: 2,
            examined: 2,
            rejected_visibility: 0,
            rejected_filter: 0,
            read_markers: 44,
            predicate_markers: 1,
        },
        "PUBLISHED (docs/cypher.md, RESULTS.md §11.1) — `n.age >= 38`: 2 rows cost a 44-marker pass"
    );

    // RESULTS.md §11.1: the text seek, whose residual predicate stays in a Filter above it.
    let (rows, plan) = profile(
        &mut coord,
        "PROFILE MATCH (n:Person) WHERE n.name STARTS WITH 'p1' RETURN n.name AS name",
        &catalog,
    );
    assert_eq!(rows.len(), 11);
    assert_eq!(
        counters(op_of(&plan, "NodeIndexStartsWithSeek")),
        Counters {
            rows: 11,
            db_hits: 11,
            examined: 11,
            rejected_visibility: 0,
            rejected_filter: 0,
            read_markers: 62,
            predicate_markers: 1,
        },
        "PUBLISHED (RESULTS.md §11.1) — `STARTS WITH 'p1'`: 11 rows cost a 62-marker pass"
    );
}
