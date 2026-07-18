//! An index build must never let an UNCOMMITTED write hide a COMMITTED row (`rmp` task #766).
//!
//! The per-entity index helpers used to collapse a property's version chain **newest-wins**. When the
//! newest version belonged to a still-open transaction, that dirty value was the only one indexed and
//! the committed value was indexed nowhere — so a reader that started AFTER the build (precisely the
//! reader the `rmp` #765 watermark declares safe to serve) sought the committed value and got nothing,
//! while the snapshot-correct store scan returned it. The row stayed lost even after the writer rolled
//! back, because a seek's re-check can REMOVE a candidate but never RESURRECT one.
//!
//! The fix indexes **every version** in the chain, making the tree a candidate SUPERSET: extra entries
//! are false positives the re-check drops. Reading the newest *committed* version instead was measured
//! and rejected — it merely moves the victim, because `commit` does not re-insert index entries (they
//! are made eagerly at write time), so the writer's own value would be missing once it committed. Both
//! readers are pinned below.
//!
//! Each test compares the index-routed query against the SAME query at the SAME snapshot with an empty
//! catalog (a forced full scan) — the ground truth — so a test can only pass by the two agreeing.

use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::GraphAccess;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_cypher::{Analyzer, ConstraintKind};
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    TxnCoordinator::new(RecordStore::create(device, wal, 64, 1).expect("create store"))
}

fn compile(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog)
}

fn run_plan(coord: &Coord, txn: graphus_core::TxnId, plan: &PhysicalPlan) -> Vec<Row> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
    cursor.collect_all().expect("collect")
}

fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let _ = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

/// The index-routed row count and the forced-full-scan row count for `query`, at ONE shared snapshot.
fn seek_vs_scan(coord: &Coord, txn: graphus_core::TxnId, query: &str) -> (usize, usize) {
    let seek = run_plan(coord, txn, &compile(query, &coord.catalog())).len();
    let scan = run_plan(coord, txn, &compile(query, &IndexCatalog::empty())).len();
    (seek, scan)
}

const FIND_COMMITTED: &str = "MATCH (n:Person) WHERE n.email = 'a@x.io' RETURN n.email AS a";
const FIND_UNCOMMITTED: &str = "MATCH (n:Person) WHERE n.email = 'zz@x.io' RETURN n.email AS a";

/// THE PRODUCTION ROUTE (`rmp` task #766). A server `CREATE INDEX` does **not** call the synchronous
/// `create_node_property_index` (which has no server caller); it declares the index and lets the engine
/// drive `advance_index_builds` between subsequent commands. That build has no read snapshot at all —
/// `PendingIndexBuild::snapshot` is a `Vec<u64>` of node ids, not a timestamp — and it never calls
/// `IndexSet::clear`, so it is populating a FRESH tree straight from the raw chain. Before the fix it
/// indexed only the uncommitted head, and the committed row was lost to every future reader.
#[test]
fn online_build_while_writer_open_keeps_committed_row_findable() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");

    // An OPEN, UNCOMMITTED writer moves the node off its committed value.
    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH (n:Person) SET n.email = 'zz@x.io'",
            &IndexCatalog::empty(),
        ),
    );

    // The production route: declare the index on the property under uncommitted mutation, then let the
    // engine drain the build exactly as it does between commands.
    coord
        .begin_online_node_property_index("Person", "email")
        .expect("declare online index");
    while coord.advance_index_builds(usize::MAX) {}

    // NON-VACUITY: the build must have actually produced an index the planner will route to. Without
    // this the assertions below would pass trivially on a plan that never touches an index.
    assert!(
        !coord.catalog().indexes().is_empty(),
        "vacuous: no index in the planner's catalog, so the seek below is not an index seek",
    );

    let reader = coord.begin_serializable();
    let (seek, scan) = seek_vs_scan(&coord, reader, FIND_COMMITTED);
    assert_eq!(
        scan, 1,
        "ground truth broken: the committed row must be visible to the full scan",
    );
    assert_eq!(
        seek, scan,
        "the online build indexed the UNCOMMITTED value and lost the committed row: \
         index seek returned {seek}, the snapshot-correct scan returned {scan}",
    );
}

/// The same defect on the synchronous rebuild route (`create_node_property_index` → `rebuild_index`),
/// where an UNRELATED `CREATE INDEX` additionally wipes the trees via `IndexSet::clear` first.
#[test]
fn unrelated_rebuild_while_writer_open_keeps_committed_row_findable() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");
    coord
        .create_node_property_index("Person", "email")
        .expect("create index");

    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH (n:Person) SET n.email = 'zz@x.io'",
            &IndexCatalog::empty(),
        ),
    );

    // An unrelated index DDL rebuilds every tree while the writer is still open.
    coord
        .create_node_property_index("Person", "unrelated")
        .expect("unrelated create index");

    let reader = coord.begin_serializable();
    let (seek, scan) = seek_vs_scan(&coord, reader, FIND_COMMITTED);
    assert_eq!(
        scan, 1,
        "ground truth broken: committed row must be visible"
    );
    assert_eq!(
        seek, scan,
        "the rebuild indexed the UNCOMMITTED value and lost the committed row: \
         index seek returned {seek}, the snapshot-correct scan returned {scan}",
    );
}

/// The other reader, and the reason indexing only the newest COMMITTED version is not a fix: once the
/// in-flight writer commits, its value must still be findable. `commit` does not re-insert index
/// entries — they are made eagerly at write time and `clear` destroyed them — so a committed-only image
/// would lose this row instead. Indexing every version serves both readers.
#[test]
fn rebuild_then_writer_commits_keeps_the_new_value_findable() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");
    coord
        .create_node_property_index("Person", "email")
        .expect("create index");

    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH (n:Person) SET n.email = 'zz@x.io'",
            &IndexCatalog::empty(),
        ),
    );
    coord
        .create_node_property_index("Person", "unrelated")
        .expect("unrelated create index");

    // The writer now COMMITS: its value is committed state and must be findable by a fresh reader.
    coord.commit(writer).expect("writer commits");

    let reader = coord.begin_serializable();
    let (seek, scan) = seek_vs_scan(&coord, reader, FIND_UNCOMMITTED);
    assert_eq!(
        scan, 1,
        "ground truth broken: committed new value must be visible"
    );
    assert_eq!(
        seek, scan,
        "the rebuild dropped the in-flight writer's value, and its commit did not restore it: \
         index seek returned {seek}, the snapshot-correct scan returned {scan}",
    );
}

/// A rolled-back writer must leave the committed value findable: the refill must not have baked the
/// dirty value in as the node's only indexed entry.
#[test]
fn rebuild_then_writer_rolls_back_keeps_committed_row_findable() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");
    coord
        .create_node_property_index("Person", "email")
        .expect("create index");

    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH (n:Person) SET n.email = 'zz@x.io'",
            &IndexCatalog::empty(),
        ),
    );
    coord
        .create_node_property_index("Person", "unrelated")
        .expect("unrelated create index");
    coord.rollback(writer).expect("writer rolls back");

    let reader = coord.begin_serializable();
    let (seek, scan) = seek_vs_scan(&coord, reader, FIND_COMMITTED);
    assert_eq!(
        scan, 1,
        "ground truth broken: committed row must be visible"
    );
    assert_eq!(
        seek, scan,
        "after the writer rolled back, the index still hides the committed row: \
         index seek returned {seek}, the snapshot-correct scan returned {scan}",
    );
}

/// Runs `src` in the already-open `txn` and returns the captured statement-level error, which is how a
/// write-time constraint violation surfaces (the constraint subsystem's captured-error channel) — NOT
/// via `commit`'s `Result`.
fn run_stmt_err(
    coord: &Coord,
    txn: graphus_core::TxnId,
    src: &str,
) -> Option<graphus_core::error::GraphusError> {
    let plan = compile(src, &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        let _ = cursor.collect_all().expect("collect");
    }
    graph.take_error()
}

/// THE IN-FLIGHT-WRITER COUNTEREXAMPLE (`rmp` task #766). This is the test that rejects the
/// "one tuple per distinct version TIMESTAMP" construction, which looks right and is not.
///
/// An in-flight writer's own uncommitted version carries no commit timestamp, so a construction keyed
/// only on committed timestamps never emits the tuple that writer holds. Once the writer commits, that
/// tuple is committed state indexed NOWHERE — `commit` does not re-insert index entries and the rebuild
/// destroyed the eager one — so the NODE KEY duplicate check for it finds no candidate and lets a real
/// duplicate through: a silent constraint violation, strictly worse than the row loss #766 set out to
/// fix. The fix gives each in-flight writer its own view (`composite_candidate_tuples`).
#[test]
fn node_key_duplicate_rejected_after_rebuild_during_in_flight_writer() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {a: 1, b: 1})");
    coord
        .create_constraint_general("pk", "Person", &["a", "b"], ConstraintKind::NodeKey, None)
        .expect("declare NODE KEY (a,b)");

    // CONTROL / NON-VACUITY: the NODE KEY must reject a duplicate of the UNTOUCHED tuple (1,1). Without
    // this the main assertion could pass simply because the constraint never fires in this harness.
    let control = coord.begin_serializable();
    let control_err = run_stmt_err(&coord, control, "CREATE (:Person {a: 1, b: 1})");
    assert!(
        control_err.is_some(),
        "control failed: NODE KEY did not reject a plain duplicate (1,1), so this test cannot \
         detect the defect it targets",
    );
    coord.rollback(control).expect("control rolls back");

    // An OPEN, UNCOMMITTED writer moves the node to the tuple (2,1). Only IT can see that tuple.
    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile("MATCH (n:Person) SET n.a = 2", &IndexCatalog::empty()),
    );

    // An unrelated index DDL rebuilds every tree while the writer is still open.
    coord
        .create_node_property_index("Person", "unrelated")
        .expect("unrelated create index");

    // The writer COMMITS: (2,1) is now committed state and must be a NODE KEY duplicate.
    coord.commit(writer).expect("writer commits");

    // Ground truth: the committed tuple really is (2,1).
    let probe = coord.begin_serializable();
    let live = run_plan(
        &coord,
        probe,
        &compile(
            "MATCH (n:Person) WHERE n.a = 2 AND n.b = 1 RETURN n.a AS a",
            &IndexCatalog::empty(),
        ),
    )
    .len();
    assert_eq!(
        live, 1,
        "ground truth broken: the committed tuple must be (2,1)"
    );

    // A second writer attempts the SAME tuple. The NODE KEY must REJECT it.
    let dup = coord.begin_serializable();
    let err = run_stmt_err(&coord, dup, "CREATE (:Person {a: 2, b: 1})");
    assert!(
        err.is_some(),
        "NODE KEY admitted a COMMITTED DUPLICATE (2,1): the rebuild dropped the in-flight writer's \
         tuple, so the duplicate check found no candidate",
    );
}

/// The full-text index must NOT return a node whose CURRENT text does not match (`rmp` tasks #766 /
/// #773). `fulltext_query` re-checks a candidate's visibility and current label — never its terms — so
/// a document built from several versions' text returns a WRONG ROW.
///
/// The build MUST be driven to `Online`: `create_fulltext_index` registers `Populating`, and a
/// `Populating` full-text index declines to the exact scan fallback, so the index under test is never
/// consulted and the probe cannot fail. That vacuity is exactly how this defect reached a green suite.
#[test]
fn fulltext_online_does_not_match_a_superseded_version() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Doc {title: 'quantum physics'})");
    // The node's CURRENT committed title is 'classical mechanics'; 'quantum physics' is a stale version
    // still present in the chain.
    run_write(
        &mut coord,
        "MATCH (n:Doc) SET n.title = 'classical mechanics'",
    );

    coord
        .create_fulltext_index(
            "docs",
            &["Doc".to_owned()],
            &["title".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("declare fulltext index");
    // Drive the build to Online — a Populating index proves nothing.
    while coord.advance_index_builds(usize::MAX) {}

    let reader = coord.begin_serializable();
    let graph = coord.statement(reader).expect("statement");
    // NON-VACUITY: the index must actually answer (Online + fresh), i.e. the CURRENT term is found.
    let current = graph.fulltext_query("docs", "classical");
    assert_eq!(
        current.as_ref().map(Vec::len),
        Some(1),
        "vacuous: the fulltext index did not serve the CURRENT term, so it is not Online/consulted \
         and the stale-term assertion below would pass trivially. got {current:?}",
    );
    // The stale version's term must NOT match: fulltext cannot re-check terms.
    let stale = graph.fulltext_query("docs", "quantum");
    assert_eq!(
        stale.as_ref().map(Vec::len),
        Some(0),
        "the fulltext index returned a WRONG ROW: 'quantum' matched a node whose current title is \
         'classical mechanics'. got {stale:?}",
    );
}

/// The composite refill must not regress to the CARTESIAN PRODUCT (`rmp` tasks #766 / #774).
///
/// What this gate does and does not catch, stated plainly so nobody mistakes it for more than it is:
///
/// - It CATCHES a regression to the cartesian product across per-key version lists, `O((V+1)^k)`. That
///   construction is correct but unaffordable: measured at 269.9 ms for V=16 on this exact scenario,
///   where the linear sweep now rebuilds the whole node in ~3 ms at V=64.
/// - It does NOT catch a regression from the linear sweep back to the pre-#774 `O(k*V^2)` construction:
///   an absolute wall-time bound at a single V cannot separate quadratic from linear when the quadratic
///   is still only a small fraction of the rebuild's linear store/insert floor (at V=64 both are a few
///   ms). That shape is guarded, load-invariantly, by the `construction_scales_sub_quadratically` unit
///   test in `graphus-cypher`'s coordinator, which times the construction alone at 256 vs 1024 versions.
///
/// Chains are NOT pruned in practice (`RecordStore::gc` has no production trigger, `rmp` #305), so V is
/// bounded by nothing and this path is worth a gate even though it only guards the outer bound.
#[test]
fn composite_rebuild_does_not_regress_to_cartesian_product() {
    fn rebuild_micros(updates: usize) -> u128 {
        let mut coord = fresh_coord();
        run_write(&mut coord, "CREATE (:Person {a: 0, b: 0, c: 0})");
        coord
            .create_constraint_general(
                "pk",
                "Person",
                &["a", "b", "c"],
                ConstraintKind::NodeKey,
                None,
            )
            .expect("declare 3-key NODE KEY");
        for i in 1..=updates {
            run_write(
                &mut coord,
                &format!("MATCH (n:Person) SET n.a = {i}, n.b = {i}, n.c = {i}"),
            );
        }
        let started = std::time::Instant::now();
        coord
            .create_node_property_index("Person", &format!("probe{updates}"))
            .expect("unrelated DDL drives the rebuild");
        started.elapsed().as_micros()
    }

    // At V=64 the linear sweep rebuilds the whole node in ~3 ms; a 3-key cartesian product over ~65
    // versions per key would emit ~275_000 tuples and is orders of magnitude beyond this. The bound is
    // tightened to 20 ms (from 60 ms, now the construction no longer carries a quadratic term): ~6x over
    // the measured ~3 ms so it does not flap on a loaded machine, yet ~13x below where a product
    // regression lands (269_900us at only V=16, far worse at V=64).
    let at64 = rebuild_micros(64);
    assert!(
        at64 < 20_000,
        "composite rebuild cost regressed toward the cartesian product: V=64 took {at64}us \
         (linear sweep measures ~3_000us; the product cost 269_900us at only V=16)",
    );
}

/// A text (trigram) index built while a writer holds an uncommitted overwrite must not lose the
/// committed row (`rmp` tasks #766 / #773). The trigram tree keeps ONE trigram set per node, so the
/// build used to collapse the property chain newest-wins; when the newest version belonged to a
/// still-open transaction, the tree held only the uncommitted value's trigrams and a fresh reader
/// sought the committed value and got nothing — the #766 loss, which reproduced on this tree.
///
/// The fix unions every version's trigrams (build-path `merge_text_value`), making the tree a candidate
/// SUPERSET; the executor's residual `CONTAINS` filter drops the extras. This is exactly the
/// node-property fix, and it is SOUND here (unlike full-text) because the text consumer DOES re-check
/// the string predicate (the residual above `NodeTextIndexSeek`).
///
/// The build MUST be driven so the text index is `Online`: `create_text_index` fills synchronously and
/// promotes to `Online`, and the reader's snapshot post-dates the build's freshness marker, so the seek
/// is genuinely routed to the trigram index. The `seek == 0` before the fix (vs `scan == 1`) proves the
/// index was consulted and lost the row — a declining index would have scanned and returned 1.
#[test]
fn text_online_build_while_writer_open_keeps_committed_row_findable() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Doc {title: 'classical mechanics'})");

    // An OPEN, UNCOMMITTED writer moves the node off its committed value. The property is NOT yet
    // text-indexed, so this writer is invisible to the #467 freshness marker (the marker only tracks
    // writers that mutate an already-registered index) — which is why the build below can bake its
    // uncommitted value and a later reader still trusts the index.
    let _writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        _writer,
        &compile(
            "MATCH (n:Doc) SET n.title = 'quantum physics'",
            &IndexCatalog::empty(),
        ),
    );

    coord
        .create_text_index("t", "Doc", "title", false)
        .expect("create text index");
    while coord.advance_index_builds(usize::MAX) {}

    // NON-VACUITY: the compiled query must actually route to the trigram index, or the seek below is a
    // disguised scan that cannot exhibit the loss.
    let reader = coord.begin_serializable();
    let seek_plan = compile(
        "MATCH (n:Doc) WHERE n.title CONTAINS 'classical' RETURN n",
        &coord.catalog(),
    );
    assert!(
        format!("{seek_plan:?}").contains("NodeTextIndexSeek"),
        "vacuous: the plan does not route to the text index, so the seek is a disguised scan",
    );

    let (seek, scan) = seek_vs_scan(
        &coord,
        reader,
        "MATCH (n:Doc) WHERE n.title CONTAINS 'classical' RETURN n",
    );
    assert_eq!(
        scan, 1,
        "ground truth broken: the committed row must be visible to the full scan",
    );
    assert_eq!(
        seek, scan,
        "the text build indexed only the UNCOMMITTED value and lost the committed row: \
         index seek returned {seek}, the snapshot-correct scan returned {scan}",
    );
}

/// The text union must not surface a value the reader's snapshot does not hold (`rmp` task #773) — the
/// property that makes the SUPERSET sound and distinguishes text (reason 1) from full-text (reason 2).
///
/// A node with committed history `'quantum physics'` → `'classical mechanics'` is built into a trigram
/// index that (post-#773) holds BOTH versions' trigrams. A `CONTAINS 'quantum'` seek returns the node
/// as a candidate, but the executor's residual re-reads the snapshot-visible value (`'classical
/// mechanics'`) and drops it — so the union never returns a wrong row, exactly where the same union over
/// full-text returned one (full-text has no term re-check). The `CONTAINS 'classical'` control confirms
/// the index is `Online` and consulted (not a vacuous scan).
#[test]
fn text_union_does_not_surface_a_superseded_committed_version() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Doc {title: 'quantum physics'})");
    run_write(
        &mut coord,
        "MATCH (n:Doc) SET n.title = 'classical mechanics'",
    );

    coord
        .create_text_index("t", "Doc", "title", false)
        .expect("create text index");
    while coord.advance_index_builds(usize::MAX) {}

    let reader = coord.begin_serializable();

    // TEETH: the trigram tree really did UNION the stale version — the raw index seek (which re-checks
    // visibility + label but NOT the string predicate) returns the node as a candidate for 'quantum'.
    // Only the residual can be what removes it below, so this test genuinely guards the residual and
    // would fail if either the union stopped unioning (candidate absent) or the residual regressed
    // (wrong row surfaced).
    {
        let graph = coord.statement(reader).expect("statement");
        let raw = graph.index_seek_text(
            "Doc",
            "title",
            graphus_cypher::physical::TextSeekOp::Contains,
            "quantum",
        );
        assert_eq!(
            raw.as_ref().map(Vec::len),
            Some(1),
            "the union did not carry the superseded version's trigrams (raw candidate = {raw:?})",
        );
    }

    // NON-VACUITY control: the CURRENT term is served by the index (proves Online + consulted).
    let (seek_c, scan_c) = seek_vs_scan(
        &coord,
        reader,
        "MATCH (n:Doc) WHERE n.title CONTAINS 'classical' RETURN n",
    );
    assert_eq!(
        scan_c, 1,
        "ground truth: current value contains 'classical'"
    );
    assert_eq!(
        seek_c, scan_c,
        "the text index did not serve the current term"
    );

    // The stale committed term must NOT match: the residual drops the union's false positive.
    let (seek_q, scan_q) = seek_vs_scan(
        &coord,
        reader,
        "MATCH (n:Doc) WHERE n.title CONTAINS 'quantum' RETURN n",
    );
    assert_eq!(
        scan_q, 0,
        "ground truth: the current committed value is 'classical mechanics'",
    );
    assert_eq!(
        seek_q, scan_q,
        "the text union returned a WRONG ROW: a superseded version's term 'quantum' matched a node \
         whose current title is 'classical mechanics' (seek {seek_q}, scan {scan_q})",
    );
}
