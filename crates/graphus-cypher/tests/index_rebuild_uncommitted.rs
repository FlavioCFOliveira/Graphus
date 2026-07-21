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

use std::collections::HashMap;

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

/// The `IndexState` of the full-text index named `name`, from the coordinator's listing surface.
fn ft_state(coord: &Coord, name: &str) -> Option<graphus_storage::IndexState> {
    coord
        .list_fulltext_indexes()
        .into_iter()
        .find(|(n, ..)| n == name)
        .map(|(_, _, _, _, _, state)| state)
}

/// NODE FULL-TEXT, the #766 window (`rmp` task #778). A full-text index built while a writer holds an
/// uncommitted overwrite of a covered property used to bake that DIRTY value newest-wins: the committed
/// value was then indexed NOWHERE (loss) and the uncommitted term was returned (wrong row).
///
/// Full-text cannot be repaired the way `rmp` #773 repaired the trigram tree. A version UNION is sound
/// for text because the executor's residual `CONTAINS` re-checks the string predicate and drops the
/// extras; `fulltext_query` re-checks a candidate's visibility and current LABEL and nothing else — it
/// never re-checks the TERMS — so a union's extra terms are not false positives a consumer drops, they
/// are wrong answers. The fix is therefore option (b): a build that observes an in-flight writer holding
/// the newest covered version must NOT promote the index `Online`; it stays `Populating` and every
/// reader declines to the snapshot-correct scan, which returns exactly these two answers.
#[test]
fn fulltext_online_build_while_writer_open_keeps_committed_row_findable() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Doc {title: 'classical mechanics'})");

    // An OPEN, UNCOMMITTED writer moves the node off its committed value. The property is not yet
    // full-text-indexed, so this writer is invisible to the #467 freshness marker (`note_ft_spatial_
    // mutator` only records writers that mutated an ALREADY-REGISTERED index) — which is why the build
    // below can bake its uncommitted value and a later reader still trusts the index.
    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH (n:Doc) SET n.title = 'quantum physics'",
            &IndexCatalog::empty(),
        ),
    );

    // THE PRODUCTION ROUTE: declare the index, then let the engine drain the build exactly as it does
    // between commands (`LocalEngine::drain_index_builds`).
    coord
        .create_fulltext_index(
            "docs",
            &["Doc".to_owned()],
            &["title".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("declare fulltext index");
    while coord.advance_index_builds(usize::MAX) {}

    {
        let reader = coord.begin_serializable();
        let graph = coord.statement(reader).expect("statement");

        // Both halves of the defect are observed BEFORE either is asserted, so one failure reports the
        // whole picture: (a) the committed value is LOST, and (b) the uncommitted term is a WRONG ROW.
        let committed = graph.fulltext_query("docs", "classical");
        let uncommitted = graph.fulltext_query("docs", "quantum");
        assert_eq!(
            (
                committed.as_ref().map(Vec::len),
                uncommitted.as_ref().map(Vec::len)
            ),
            (Some(1), Some(0)),
            "the full-text build baked the in-flight writer's UNCOMMITTED value:\n  \
             (a) LOSS      queryNodes('classical') = {committed:?} — the node's committed title is \
             'classical mechanics', so this must find it\n  \
             (b) WRONG ROW queryNodes('quantum')   = {uncommitted:?} — 'quantum physics' is an \
             UNCOMMITTED writer's value that no reader may see, and `fulltext_query` has no term \
             re-check to drop it",
        );
    }

    // THE MECHANISM (option (b), poison-on-build): while the conflict is live the index must not be
    // `Online`, because an `Online` full-text index is consulted directly and cannot be repaired by a
    // re-check. Staying `Populating` is what routes the two probes above to the exact scan.
    assert_eq!(
        ft_state(&coord, "docs"),
        Some(graphus_storage::IndexState::Populating),
        "a full-text index built over an in-flight writer's uncommitted value must not be promoted \
         Online — an Online index is trusted and its terms are never re-checked",
    );

    // THE RESURRECTION PATH: once the writer resolves, the conflict is gone and the index must promote
    // and serve. Without this the fix would be a permanent poison — strictly worse than the defect.
    coord.rollback(writer).expect("writer rolls back");
    let _ = coord.retry_poisoned_index_builds();
    while coord.advance_index_builds(usize::MAX) {}
    assert_eq!(
        ft_state(&coord, "docs"),
        Some(graphus_storage::IndexState::Online),
        "the conflicted build was never resurrected after the writer resolved: the index is stuck \
         Populating for the life of the process",
    );

    let reader = coord.begin_serializable();
    let graph = coord.statement(reader).expect("statement");
    let committed = graph.fulltext_query("docs", "classical");
    assert_eq!(
        committed.as_ref().map(Vec::len),
        Some(1),
        "after resurrection the Online index must serve the committed value. got {committed:?}",
    );
    let rolled_back = graph.fulltext_query("docs", "quantum");
    assert_eq!(
        rolled_back.as_ref().map(Vec::len),
        Some(0),
        "after resurrection the rolled-back writer's term must not be indexed. got {rolled_back:?}",
    );
}

/// RELATIONSHIP FULL-TEXT, the same window (`rmp` task #778) — the twin of
/// [`fulltext_online_build_while_writer_open_keeps_committed_row_findable`]. `fulltext_query_rel`
/// re-checks a candidate's visibility and current TYPE and nothing else, so it has exactly the node
/// path's blind spot on terms.
///
/// The relationship index is built SYNCHRONOUSLY (`create_fulltext_rel_index` registers `Online` and
/// calls `rebuild_index`), so the conflict must be detected inside that synchronous build and demote the
/// index — a different driver from the node path's chunked `advance_fulltext_build`, which is why both
/// twins are pinned.
#[test]
fn fulltext_rel_online_build_while_writer_open_keeps_committed_row_findable() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P {n: 1})-[:KNOWS {note: 'classical mechanics'}]->(:P {n: 2})",
    );

    // An OPEN, UNCOMMITTED writer moves the relationship off its committed value.
    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH ()-[r:KNOWS]->() SET r.note = 'quantum physics'",
            &IndexCatalog::empty(),
        ),
    );

    coord
        .create_fulltext_rel_index(
            "rels",
            &["KNOWS".to_owned()],
            &["note".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("declare relationship fulltext index");
    while coord.advance_index_builds(usize::MAX) {}

    {
        let reader = coord.begin_serializable();
        let graph = coord.statement(reader).expect("statement");

        // Both halves observed before either is asserted — see the node twin.
        let committed = graph.fulltext_query_rel("rels", "classical");
        let uncommitted = graph.fulltext_query_rel("rels", "quantum");
        assert_eq!(
            (
                committed.as_ref().map(Vec::len),
                uncommitted.as_ref().map(Vec::len)
            ),
            (Some(1), Some(0)),
            "the relationship full-text build baked the in-flight writer's UNCOMMITTED value:\n  \
             (a) LOSS      queryRelationships('classical') = {committed:?} — the relationship's \
             committed note is 'classical mechanics', so this must find it\n  \
             (b) WRONG ROW queryRelationships('quantum')   = {uncommitted:?} — 'quantum physics' is \
             an UNCOMMITTED writer's value that no reader may see, and `fulltext_query_rel` has no \
             term re-check to drop it",
        );
    }

    // THE MECHANISM.
    assert_eq!(
        ft_state(&coord, "rels"),
        Some(graphus_storage::IndexState::Populating),
        "a relationship full-text index built over an in-flight writer's uncommitted value must not \
         be left Online — an Online index is trusted and its terms are never re-checked",
    );

    // THE RESURRECTION PATH.
    coord.rollback(writer).expect("writer rolls back");
    let _ = coord.retry_poisoned_index_builds();
    while coord.advance_index_builds(usize::MAX) {}
    assert_eq!(
        ft_state(&coord, "rels"),
        Some(graphus_storage::IndexState::Online),
        "the conflicted relationship build was never resurrected after the writer resolved: the \
         index is stuck Populating for the life of the process",
    );

    let reader = coord.begin_serializable();
    let graph = coord.statement(reader).expect("statement");
    let committed = graph.fulltext_query_rel("rels", "classical");
    assert_eq!(
        committed.as_ref().map(Vec::len),
        Some(1),
        "after resurrection the Online index must serve the committed value. got {committed:?}",
    );
    let rolled_back = graph.fulltext_query_rel("rels", "quantum");
    assert_eq!(
        rolled_back.as_ref().map(Vec::len),
        Some(0),
        "after resurrection the rolled-back writer's term must not be indexed. got {rolled_back:?}",
    );
}

/// TWO conflict records, TWO owners — the cross-talk regression (`rmp` task #778).
///
/// The #778 conflict signal has two independent producers: the whole-set `rebuild_index`, which demotes
/// the full-text indexes it holed, and the chunked node build, which parks itself. Both originally read
/// and cleared ONE slot on the shared `IndexSet`, and the chunked build clears that slot on **every
/// chunk**. So a node build running after a rebuild had demoted an index wiped the rebuild's record of
/// which writers to wait for — and with the trigger gone, nothing ever re-drove that rebuild. The
/// demoted index stayed `Populating` for the life of the process: answers still correct (every reader is
/// on the exact scan) but permanently unaccelerated, with no path back to `Online`.
///
/// This drives exactly that interleaving: an `Online` index is demoted by a rebuild, a SECOND index's
/// build then runs its chunks, and after the blocking writer resolves BOTH must reach `Online`.
#[test]
fn a_second_fulltext_build_does_not_strand_an_index_demoted_by_a_rebuild() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Doc {title: 'classical mechanics'})");

    // Index A, built cleanly to Online with no writer in flight.
    coord
        .create_fulltext_index(
            "a",
            &["Doc".to_owned()],
            &["title".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("declare fulltext index a");
    while coord.advance_index_builds(usize::MAX) {}
    assert_eq!(
        ft_state(&coord, "a"),
        Some(graphus_storage::IndexState::Online),
        "setup: index a must start Online, or the demotion below proves nothing",
    );

    // A writer takes the covered property uncommitted...
    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH (n:Doc) SET n.title = 'quantum physics'",
            &IndexCatalog::empty(),
        ),
    );
    // ...and an UNRELATED DDL drives a whole-set `rebuild_index`, which holes index a and demotes it.
    coord
        .create_node_property_index("Doc", "probe")
        .expect("unrelated DDL drives the rebuild");
    assert_eq!(
        ft_state(&coord, "a"),
        Some(graphus_storage::IndexState::Populating),
        "setup: the rebuild must have demoted index a for this to test the stranding",
    );

    // THE CROSS-TALK: a second index's chunked build now runs and clears the shared per-chunk conflict
    // channel. With one shared slot this erased index a's resurrection trigger.
    coord
        .create_fulltext_index(
            "b",
            &["Doc".to_owned()],
            &["title".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("declare fulltext index b");
    while coord.advance_index_builds(usize::MAX) {}

    // The writer resolves: every conflict is now settled, so BOTH indexes must come back.
    coord.rollback(writer).expect("writer rolls back");
    while coord.advance_index_builds(usize::MAX) {}

    assert_eq!(
        ft_state(&coord, "a"),
        Some(graphus_storage::IndexState::Online),
        "index a was STRANDED Populating: the second build's chunk cleared the rebuild's record of \
         the blocking writer, so the repair was never re-driven",
    );
    assert_eq!(
        ft_state(&coord, "b"),
        Some(graphus_storage::IndexState::Online),
        "index b never completed after its blocking writer resolved",
    );

    // Both must serve the committed value, and neither the rolled-back term.
    let reader = coord.begin_serializable();
    let graph = coord.statement(reader).expect("statement");
    for name in ["a", "b"] {
        assert_eq!(
            graph
                .fulltext_query(name, "classical")
                .as_ref()
                .map(Vec::len),
            Some(1),
            "index {name} does not serve the committed value after resurrection",
        );
        assert_eq!(
            graph.fulltext_query(name, "quantum").as_ref().map(Vec::len),
            Some(0),
            "index {name} returned the rolled-back writer's term after resurrection",
        );
    }
}

/// A chunked build must not promote `Online` over a hole the WHOLE-SET rebuild left (`rmp` task #778).
///
/// The conflict gate originally consulted only the build's OWN record of entities it skipped. But an
/// unrelated `CREATE INDEX` / `CREATE CONSTRAINT` between two chunks runs `rebuild_index`, which calls
/// `IndexSet::clear` — emptying this index's tree and refilling it from the store, MINUS any entity an
/// in-flight writer holds. `clear` does not bump `wipe_generation` (only `fail_closed` does), so the
/// build sees no epoch change, does not re-snapshot, and simply resumes at its cursor. An entity skipped
/// BEFORE that cursor is therefore never revisited: the remaining chunks are clean, the build's own
/// record stays empty, and it promotes the index `Online` with the committed row missing — while
/// `bump_ft_spatial_marker_after_build` has already raised the #467 freshness marker so readers trust it.
///
/// That is the #766 loss re-entering through the promotion door, which is why the gate must consult the
/// shared demotion record too. Driven with a chunk budget of 1 so the DDL lands mid-build, after the
/// conflicted node has been passed.
#[test]
fn a_chunked_build_does_not_promote_over_a_hole_left_by_a_rebuild() {
    let mut coord = fresh_coord();
    // Several docs so the build takes several chunks; only the FIRST is put under uncommitted mutation,
    // so the rebuild's hole lands strictly before the cursor once the build has moved past it.
    run_write(&mut coord, "CREATE (:Doc {title: 'classical mechanics'})");
    for i in 0..6 {
        run_write(
            &mut coord,
            &format!("CREATE (:Doc {{title: 'filler {i}'}})"),
        );
    }

    coord
        .create_fulltext_index(
            "docs",
            &["Doc".to_owned()],
            &["title".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("declare fulltext index");

    // Advance ONE node: the build passes the first Doc and its cursor moves beyond it.
    coord.advance_index_builds(1);

    // NOW a writer takes the first Doc's covered property uncommitted, and an unrelated DDL runs the
    // whole-set rebuild — which wipes and refills the tree, skipping that node.
    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH (n:Doc) WHERE n.title = 'classical mechanics' SET n.title = 'quantum physics'",
            &IndexCatalog::empty(),
        ),
    );
    coord
        .create_node_property_index("Doc", "probe")
        .expect("unrelated DDL drives the rebuild");

    // Finish the build. Its remaining chunks are clean, so only the SHARED demotion record can stop it.
    while coord.advance_index_builds(usize::MAX) {}

    assert_eq!(
        ft_state(&coord, "docs"),
        Some(graphus_storage::IndexState::Populating),
        "the build promoted the index Online while the whole-set rebuild's hole was still outstanding",
    );

    // The committed row must still be findable, and the uncommitted term must not be.
    {
        let reader = coord.begin_serializable();
        let graph = coord.statement(reader).expect("statement");
        let committed = graph.fulltext_query("docs", "classical");
        let uncommitted = graph.fulltext_query("docs", "quantum");
        assert_eq!(
            (
                committed.as_ref().map(Vec::len),
                uncommitted.as_ref().map(Vec::len)
            ),
            (Some(1), Some(0)),
            "the index was published over a hole: committed 'classical' = {committed:?} (must be 1), \
             uncommitted 'quantum' = {uncommitted:?} (must be 0)",
        );
    }

    // And it must still resurrect once the writer resolves.
    coord.rollback(writer).expect("writer rolls back");
    while coord.advance_index_builds(usize::MAX) {}
    assert_eq!(
        ft_state(&coord, "docs"),
        Some(graphus_storage::IndexState::Online),
        "the build never resurrected after the writer resolved",
    );
    let reader = coord.begin_serializable();
    let graph = coord.statement(reader).expect("statement");
    assert_eq!(
        graph
            .fulltext_query("docs", "classical")
            .as_ref()
            .map(Vec::len),
        Some(1),
        "after resurrection the committed row must be findable through the Online index",
    );
}

/// The REMOVAL half of the uncommitted-version window (`rmp` task #778).
///
/// `SET n.p = …` and `REMOVE n.p` reach the store differently: a SET PREPENDS a new version, so the
/// writer's dirty value is the chain head and its `created_ts` names the writer; a REMOVE tombstones
/// **in place without prepending**, so the head is still the committed record and only its `expired_ts`
/// names the writer. A conflict gate that inspects `created_ts` alone therefore sees a perfectly ordinary
/// committed version and bakes it.
///
/// During the window that is harmless — the removal is invisible, so the baked value is the right answer.
/// The damage lands at COMMIT: the index still carries a term the entity no longer has, and full-text
/// re-checks visibility and label but never terms, so no reader can drop it.
#[test]
fn fulltext_build_parks_on_an_uncommitted_property_removal() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Doc {title: 'alpha beta'})");

    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile("MATCH (n:Doc) REMOVE n.title", &IndexCatalog::empty()),
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
    while coord.advance_index_builds(usize::MAX) {}

    // The removal is UNCOMMITTED, so a reader must still match the term.
    {
        let reader = coord.begin_serializable();
        let graph = coord.statement(reader).expect("statement");
        assert_eq!(
            graph.fulltext_query("docs", "alpha").as_ref().map(Vec::len),
            Some(1),
            "an uncommitted removal must not hide the committed value",
        );
    }
    assert_eq!(
        ft_state(&coord, "docs"),
        Some(graphus_storage::IndexState::Populating),
        "the build must park on an in-flight REMOVE exactly as it parks on an in-flight SET — the \
         `expired_ts` stamp is the only thing that names the writer",
    );

    // On COMMIT the term must disappear. This is the assertion that fails when only `created_ts` is
    // inspected: the doomed value was baked, and nothing re-checks terms.
    coord.commit(writer).expect("removal commits");
    while coord.advance_index_builds(usize::MAX) {}
    let reader = coord.begin_serializable();
    let graph = coord.statement(reader).expect("statement");
    let stale = graph.fulltext_query("docs", "alpha");
    assert_eq!(
        stale.as_ref().map(Vec::len),
        Some(0),
        "the index still matches 'alpha' after the property was REMOVED and committed. got {stale:?}",
    );
}

/// A COMMITTED removal must not stay indexed (`rmp` task #778 audit). Independent of concurrency.
///
/// `node_properties` returns every `in_use` record, and an MVCC tombstone keeps its slot until GC
/// reclaims it — which has no automatic trigger (`rmp` #305). The build collapsed the chain newest-wins
/// without consulting `expired_ts`, so a removed property's value stayed indexable for as long as the
/// tombstone survived: `REMOVE n.title`, commit, then ANY rebuild re-baked the removed term.
#[test]
fn fulltext_build_does_not_index_a_committed_removal() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Doc {title: 'alpha beta'})");
    run_write(&mut coord, "MATCH (n:Doc) REMOVE n.title");

    coord
        .create_fulltext_index(
            "docs",
            &["Doc".to_owned()],
            &["title".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("declare fulltext index");
    while coord.advance_index_builds(usize::MAX) {}

    let reader = coord.begin_serializable();
    let graph = coord.statement(reader).expect("statement");
    let stale = graph.fulltext_query("docs", "alpha");
    assert_eq!(
        stale.as_ref().map(Vec::len),
        Some(0),
        "the build indexed a COMMITTED-REMOVED property: 'alpha' still matches a node with no title \
         at all. got {stale:?}",
    );
}

/// Newest-wins must settle a key whatever the newest version's TYPE (`rmp` task #778 audit).
///
/// The dedup guard keyed off the accumulated STRING list, so it only tripped once a string had been
/// pushed for that key. When the newest version was a non-string it contributed nothing, the guard never
/// tripped, and the loop walked on to index an OLDER string version of the same key — resurrecting a
/// superseded term. Independent of concurrency.
#[test]
fn fulltext_build_does_not_index_a_string_shadowed_by_a_non_string() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Doc {title: 'alpha beta'})");
    run_write(&mut coord, "MATCH (n:Doc) SET n.title = 42");

    coord
        .create_fulltext_index(
            "docs",
            &["Doc".to_owned()],
            &["title".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("declare fulltext index");
    while coord.advance_index_builds(usize::MAX) {}

    let reader = coord.begin_serializable();
    let graph = coord.statement(reader).expect("statement");
    let stale = graph.fulltext_query("docs", "alpha");
    assert_eq!(
        stale.as_ref().map(Vec::len),
        Some(0),
        "a superseded STRING version was indexed because the newest version is an integer: \
         'alpha' still matches a node whose title is 42. got {stale:?}",
    );
}

// =================================================================================================
// SPATIAL (point) grids — `rmp` task #779
// =================================================================================================

/// A node proximity query near the origin; the committed point is at the origin.
const NEAR_ORIGIN: &str =
    "MATCH (n:City) WHERE distance(n.loc, point({x: 0, y: 0})) <= 1 RETURN id(n) AS id";

#[test]
fn spatial_online_build_while_writer_open_keeps_committed_point_findable() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:City {name: 'a', loc: point({x: 0, y: 0})})",
    );

    // An OPEN, UNCOMMITTED writer moves the point far away.
    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH (n:City) SET n.loc = point({x: 100, y: 100})",
            &IndexCatalog::empty(),
        ),
    );

    // THE PRODUCTION ROUTE, driven ONLINE.
    coord
        .create_point_index("by_loc", "City", "loc", false)
        .expect("declare point index");
    while coord.advance_index_builds(usize::MAX) {}

    assert!(
        !coord.catalog().indexes().is_empty(),
        "vacuous: no index in the planner's catalog",
    );

    let reader = coord.begin_serializable();
    let (seek, scan) = seek_vs_scan(&coord, reader, NEAR_ORIGIN);
    assert_eq!(scan, 1, "ground truth broken: committed point must be seen");
    assert_eq!(
        seek, scan,
        "the spatial build indexed the UNCOMMITTED point and lost the committed one: \
         index seek returned {seek}, the snapshot-correct scan returned {scan}",
    );
}

/// A relationship proximity query near the origin.
const REL_NEAR_ORIGIN: &str = "MATCH (a)-[r:VISITED]->(b) \
     WHERE distance(r.at, point({x: 0, y: 0})) <= 1 RETURN id(r) AS id";

/// A node proximity query near (100, 100) — where an in-flight writer's point lands.
const NEAR_FAR_100: &str =
    "MATCH (n:City) WHERE distance(n.loc, point({x: 100, y: 100})) <= 1 RETURN id(n) AS id";

#[test]
fn spatial_rel_build_while_writer_open_keeps_committed_point_findable() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {name: 'p1'}), (:P {name: 'p2'})");
    run_write(
        &mut coord,
        "MATCH (a:P {name: 'p1'}), (b:P {name: 'p2'}) \
         CREATE (a)-[:VISITED {at: point({x: 0, y: 0})}]->(b)",
    );

    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH ()-[r:VISITED]->() SET r.at = point({x: 100, y: 100})",
            &IndexCatalog::empty(),
        ),
    );

    coord
        .create_point_rel_index("rel_at", "VISITED", "at", false)
        .expect("declare rel point index");
    while coord.advance_index_builds(usize::MAX) {}

    assert!(
        !coord.catalog().indexes().is_empty(),
        "vacuous: no index in the planner's catalog",
    );

    let reader = coord.begin_serializable();
    let (seek, scan) = seek_vs_scan(&coord, reader, REL_NEAR_ORIGIN);
    assert_eq!(scan, 1, "ground truth broken: committed point must be seen");
    assert_eq!(
        seek, scan,
        "the rel spatial build indexed the UNCOMMITTED point and lost the committed one: \
         index seek returned {seek}, the snapshot-correct scan returned {scan}",
    );
}

/// THE LOAD-BEARING INVARIANT (`rmp` task #779). The multi-valued grid is only safe because the
/// executor keeps a residual `distance(...)` filter above the spatial seek that re-reads each
/// candidate's SNAPSHOT-VISIBLE point. If that residual is ever dropped — an "optimisation" that would
/// look free, since the grid seems to answer the predicate already — the union stops being a superset
/// the caller trims and starts being WRONG ROWS.
///
/// So this pins the invariant instead of trusting it (`rmp` #734's lesson: a correctness argument that
/// rests on an invariant maintained elsewhere must fail loudly when that invariant breaks). It asserts
/// BOTH halves, which is what makes it non-vacuous:
///
/// 1. the raw grid really does offer the far candidate (so the residual has something to drop); and
/// 2. the full query returns no row (so the residual dropped it).
///
/// Assertion 1 alone would pass on a grid that lost the entry; assertion 2 alone would pass on a plan
/// that never consulted the index.
#[test]
fn spatial_residual_filter_rechecks_the_snapshot_visible_point_779() {
    let mut coord = fresh_coord();
    // Committed at the origin; a LATER COMMITTED version moves it far away. The build unions both, so
    // the grid offers this node as a candidate near the origin — where it no longer is.
    run_write(
        &mut coord,
        "CREATE (:City {name: 'a', loc: point({x: 0, y: 0})})",
    );
    run_write(
        &mut coord,
        "MATCH (n:City) SET n.loc = point({x: 100, y: 100})",
    );
    coord
        .create_point_index("by_loc", "City", "loc", false)
        .expect("declare point index");
    while coord.advance_index_builds(usize::MAX) {}

    let reader = coord.begin_serializable();
    // (1) The grid DOES offer the stale candidate near the origin.
    let candidates = {
        let graph = coord.statement(reader).expect("statement");
        graph.index_seek_spatial("City", "loc", 0.0, 0.0, 1.0)
    };
    assert_eq!(
        candidates.as_ref().map(Vec::len),
        Some(1),
        "vacuous: the grid did not offer the superseded version as a candidate, so the residual \
         re-check below is not being exercised. got {candidates:?}",
    );
    // (2) …and the query returns NO row, because the residual re-read the visible point (100, 100).
    let (seek, scan) = seek_vs_scan(&coord, reader, NEAR_ORIGIN);
    assert_eq!(scan, 0, "ground truth: the node is no longer at the origin");
    assert_eq!(
        seek, 0,
        "the residual distance filter did NOT re-check: the spatial seek returned a WRONG ROW for a \
         node whose visible point is (100, 100). The multi-valued grid (rmp #779) is unsound without \
         this re-check.",
    );
}

/// The relationship twin of the invariant above (`rmp` task #779).
#[test]
fn spatial_rel_residual_filter_rechecks_the_snapshot_visible_point_779() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {name: 'p1'}), (:P {name: 'p2'})");
    run_write(
        &mut coord,
        "MATCH (a:P {name: 'p1'}), (b:P {name: 'p2'}) \
         CREATE (a)-[:VISITED {at: point({x: 0, y: 0})}]->(b)",
    );
    run_write(
        &mut coord,
        "MATCH ()-[r:VISITED]->() SET r.at = point({x: 100, y: 100})",
    );
    coord
        .create_point_rel_index("rel_at", "VISITED", "at", false)
        .expect("declare rel point index");
    while coord.advance_index_builds(usize::MAX) {}

    let reader = coord.begin_serializable();
    let candidates = {
        let graph = coord.statement(reader).expect("statement");
        graph.index_seek_spatial_rel("VISITED", "at", 0.0, 0.0, 1.0)
    };
    assert_eq!(
        candidates.as_ref().map(Vec::len),
        Some(1),
        "vacuous: the rel grid did not offer the superseded version as a candidate. got {candidates:?}",
    );
    let (seek, scan) = seek_vs_scan(&coord, reader, REL_NEAR_ORIGIN);
    assert_eq!(scan, 0, "ground truth: the rel is no longer at the origin");
    assert_eq!(
        seek, 0,
        "the residual distance filter did NOT re-check: the rel spatial seek returned a WRONG ROW.",
    );
}

/// The synchronous rebuild route (an UNRELATED index DDL wipes every tree via `IndexSet::clear` and
/// refills while the writer is still open) must also keep the committed point findable (`rmp` #779).
///
/// HONEST SCOPE: this test **passed before the fix** — it is not a #779 regression test. Here the
/// spatial index exists BEFORE the writer opens, so `note_ft_spatial_mutator` (which iterates
/// `registered_spatial()`) does record the writer, the #467 freshness marker is poisoned, and the reader
/// declines to the snapshot-correct scan. That is precisely the case #779 is NOT about: the defect is
/// the writer that PREDATES the index, whom the marker never sees. It is kept as the complementary
/// guard — it fails if the marker path itself ever regresses, which the multi-value union must not be
/// allowed to mask.
#[test]
fn spatial_unrelated_rebuild_while_writer_open_keeps_committed_point_findable() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:City {name: 'a', loc: point({x: 0, y: 0})})",
    );
    coord
        .create_point_index("by_loc", "City", "loc", false)
        .expect("create point index");
    while coord.advance_index_builds(usize::MAX) {}

    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH (n:City) SET n.loc = point({x: 100, y: 100})",
            &IndexCatalog::empty(),
        ),
    );

    // An unrelated index DDL rebuilds every tree while the writer is still open.
    coord
        .create_node_property_index("City", "name")
        .expect("unrelated create index");

    let reader = coord.begin_serializable();
    let (seek, scan) = seek_vs_scan(&coord, reader, NEAR_ORIGIN);
    assert_eq!(scan, 1, "ground truth broken: committed point must be seen");
    assert_eq!(
        seek, scan,
        "the rebuild indexed the UNCOMMITTED point and lost the committed one: \
         index seek returned {seek}, the snapshot-correct scan returned {scan}",
    );
}

/// The OTHER reader, and the reason indexing only the newest COMMITTED version is not a fix: once the
/// in-flight writer commits, ITS point must be findable too. `commit` does not re-insert grid entries
/// — they are made eagerly at write time and the rebuild destroyed them — so a committed-only image
/// would lose this row instead. Unioning every version serves both readers (`rmp` #779).
///
/// HONEST SCOPE: this test **passed before the fix** — the pre-fix newest-wins build happened to bake
/// exactly this reader's point in (that WAS the defect, seen from the other side). It is not a
/// regression test for #779; it is the counterexample that rejects the WRONG fix. "Index only the
/// newest COMMITTED version" repairs the two tests above and breaks this one, so it must stay green
/// alongside them, and only the union keeps all three.
#[test]
fn spatial_rebuild_then_writer_commits_keeps_the_new_point_findable() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:City {name: 'a', loc: point({x: 0, y: 0})})",
    );
    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH (n:City) SET n.loc = point({x: 100, y: 100})",
            &IndexCatalog::empty(),
        ),
    );
    coord
        .create_point_index("by_loc", "City", "loc", false)
        .expect("declare point index");
    while coord.advance_index_builds(usize::MAX) {}
    coord.commit(writer).expect("writer commits");

    let reader = coord.begin_serializable();
    let (seek, scan) = seek_vs_scan(&coord, reader, NEAR_FAR_100);
    assert_eq!(
        scan, 1,
        "ground truth: the committed point is now (100,100)"
    );
    assert_eq!(
        seek, scan,
        "after the writer committed, its point is findable nowhere: \
         index seek returned {seek}, the snapshot-correct scan returned {scan}",
    );
}

/// A rolled-back writer must leave the committed point findable: the refill must not have baked the
/// dirty point in as the node's only grid entry (`rmp` #779).
#[test]
fn spatial_rebuild_then_writer_rolls_back_keeps_committed_point_findable() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:City {name: 'a', loc: point({x: 0, y: 0})})",
    );
    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "MATCH (n:City) SET n.loc = point({x: 100, y: 100})",
            &IndexCatalog::empty(),
        ),
    );
    coord
        .create_point_index("by_loc", "City", "loc", false)
        .expect("declare point index");
    while coord.advance_index_builds(usize::MAX) {}
    coord.rollback(writer).expect("writer rolls back");

    let reader = coord.begin_serializable();
    let (seek, scan) = seek_vs_scan(&coord, reader, NEAR_ORIGIN);
    assert_eq!(scan, 1, "ground truth broken: committed point must be seen");
    assert_eq!(
        seek, scan,
        "after the writer rolled back, the committed point is findable nowhere: \
         index seek returned {seek}, the snapshot-correct scan returned {scan}",
    );
}

// =================================================================================================
// VECTOR (HNSW) graphs — `rmp` task #780
//
// Vector is the one index kind with no approximate fallback, so the #766 window here is not a missing
// row but a WRONG ONE: the build bakes an active writer's uncommitted embedding, the committed one is
// indexed nowhere, and a FRESH auto-commit reader's k=1 returns the wrong entity — with a `score`
// computed from a vector that reader's snapshot cannot see.
//
// Every assertion below is ABSOLUTE (the exact expected name and score), never seek-vs-scan agreement:
// in `rmp` #767 an equivalence test survived mutation because both seams were wrong identically.
// =================================================================================================

use graphus_core::Value as CoreValue;
use graphus_storage::{VectorEntity, VectorSimilarity};

/// `x` is the exact query direction (cosine 1.0 -> score 1.0); `y` is a runner-up at cosine 0.9
/// (score 0.95). Both are unit vectors, so the scores are exact, not approximate.
const V_QUERY: [f32; 3] = [1.0, 0.0, 0.0];

fn vec_lit(v: &[f32]) -> String {
    let elems: Vec<String> = v.iter().map(|x| format!("{x:?}")).collect();
    format!("[{}]", elems.join(", "))
}

fn pid_map(coord: &Coord, txn: graphus_core::TxnId, pattern: &str) -> HashMap<u64, String> {
    run_plan(coord, txn, &compile(pattern, &IndexCatalog::empty()))
        .iter()
        .map(|r| {
            let pid = match r.value("pid") {
                CoreValue::Integer(i) => i as u64,
                other => panic!("pid must be an integer, got {other:?}"),
            };
            let name = match r.value("name") {
                CoreValue::String(s) => s,
                other => panic!("name must be a string, got {other:?}"),
            };
            (pid, name)
        })
        .collect()
}

/// `(name, score)` rows from `db.index.vector.queryNodes`, in the procedure's own order.
fn knn_nodes(coord: &Coord, txn: graphus_core::TxnId, k: usize) -> Vec<(String, f64)> {
    let map = pid_map(
        coord,
        txn,
        "MATCH (n:Doc) RETURN id(n) AS pid, n.name AS name",
    );
    let src = format!(
        "CALL db.index.vector.queryNodes('doc_vec', {k}, {}) YIELD node, score \
         RETURN id(node) AS pid, score",
        vec_lit(&V_QUERY)
    );
    knn_rows(coord, txn, &src, &map)
}

/// `(name, score)` rows from `db.index.vector.queryRelationships`.
fn knn_rels(coord: &Coord, txn: graphus_core::TxnId, k: usize) -> Vec<(String, f64)> {
    let map = pid_map(
        coord,
        txn,
        "MATCH ()-[r:SIMILAR]->() RETURN id(r) AS pid, r.name AS name",
    );
    let src = format!(
        "CALL db.index.vector.queryRelationships('rel_vec', {k}, {}) YIELD relationship, score \
         RETURN id(relationship) AS pid, score",
        vec_lit(&V_QUERY)
    );
    knn_rows(coord, txn, &src, &map)
}

fn knn_rows(
    coord: &Coord,
    txn: graphus_core::TxnId,
    src: &str,
    map: &HashMap<u64, String>,
) -> Vec<(String, f64)> {
    run_plan(coord, txn, &compile(src, &IndexCatalog::empty()))
        .iter()
        .map(|r| {
            let pid = match r.value("pid") {
                CoreValue::Integer(i) => i as u64,
                other => panic!("pid must be an integer, got {other:?}"),
            };
            let score = match r.value("score") {
                CoreValue::Float(f) => f,
                other => panic!("score must be a float, got {other:?}"),
            };
            (
                map.get(&pid).cloned().unwrap_or_else(|| format!("<{pid}>")),
                score,
            )
        })
        .collect()
}

/// The number of decoy embeddings seeded around the query direction.
///
/// THE LOAD-BEARING TEST PARAMETER (`rmp` #780 vacuity audit). With a corpus of 2 and `k = 1`, the
/// over-fetch of `2k` returns EVERY entity, so the k-NN never makes a selection and `rescore_candidates`
/// alone determines the answer — which made an earlier version of these tests pass with the entire build
/// gate deleted. Mutation-tested: with the gate removed, the corpus below fails them.
///
/// Each decoy sits at angle `0.30 + i*0.001` rad from the query, i.e. cosine ~0.955 — strictly NEARER
/// the query than `x`'s dirty `[0,0,1]` (cosine 0) and strictly FARTHER than `x`'s committed `[1,0,0]`
/// (cosine 1.0). So `x` must win, but only if the graph OFFERS it, which is exactly what the build gate
/// decides.
const DISTRACTORS: usize = 200;

fn seed_distractors(coord: &mut Coord) {
    for i in 0..DISTRACTORS {
        let t = 0.30 + (i as f32) * 0.001;
        run_write(
            coord,
            &format!(
                "CREATE (:Doc {{name: 'd{i}', embedding: [{:?}, {:?}, 0.0]}})",
                t.cos(),
                t.sin()
            ),
        );
    }
}

fn seed_rel_distractors(coord: &mut Coord) {
    for i in 0..DISTRACTORS {
        let t = 0.30 + (i as f32) * 0.001;
        run_write(
            coord,
            &format!(
                "MATCH (a:P {{n: 'p1'}}), (b:P {{n: 'p3'}}) \
                 CREATE (a)-[:SIMILAR {{name: 'd{i}', vec: [{:?}, {:?}, 0.0]}}]->(b)",
                t.cos(),
                t.sin()
            ),
        );
    }
}

fn declare_node_vector(coord: &mut Coord) {
    coord
        .begin_online_vector_index_named(
            Some("doc_vec"),
            VectorEntity::Node,
            "Doc",
            "embedding",
            3,
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect("create node vector index");
}

fn seed_docs(coord: &mut Coord) {
    run_write(
        coord,
        "CREATE (:Doc {name: 'x', embedding: [1.0, 0.0, 0.0]})",
    );
    run_write(
        coord,
        "CREATE (:Doc {name: 'y', embedding: [0.9, 0.4358899, 0.0]})",
    );
}

/// Seeds, opens an uncommitted writer that moves `x` orthogonal to the query, then runs THE PRODUCTION
/// BUILD ROUTE (`begin_online_vector_index_named` — what the server's `CREATE VECTOR INDEX` calls).
fn seed_and_build_under_open_writer(coord: &mut Coord) -> graphus_core::TxnId {
    seed_docs(coord);
    seed_distractors(coord);
    let writer = coord.begin_serializable();
    let _ = run_plan(
        coord,
        writer,
        &compile(
            "MATCH (n:Doc {name: 'x'}) SET n.embedding = [0.0, 0.0, 1.0]",
            &IndexCatalog::empty(),
        ),
    );
    declare_node_vector(coord);
    writer
}

#[test]
fn vector_build_while_writer_open_returns_the_committed_nearest_neighbour() {
    let mut coord = fresh_coord();
    let _writer = seed_and_build_under_open_writer(&mut coord);

    // Non-vacuity: the index really is declared and really is Online. A NotOnline index ERRORS rather
    // than mis-ranking, so a green test could otherwise be the #733 gate firing instead of this fix.
    let listings = coord.list_vector_index_listings();
    assert_eq!(listings.len(), 1, "vacuous: no vector index declared");
    assert_eq!(
        format!("{:?}", listings[0].state),
        "Online",
        "vacuous: the index is not Online, so this exercises the #733 gate, not #780",
    );

    let reader = coord.begin_serializable();
    let got = knn_nodes(&coord, reader, 1);
    assert_eq!(
        got,
        vec![("x".to_owned(), 1.0)],
        "k=1 must return the COMMITTED nearest neighbour x at its snapshot-visible score 1.0; \
         the uncommitted [0,0,1] must not rank y first",
    );
}

#[test]
fn vector_rel_build_while_writer_open_returns_the_committed_nearest_neighbour() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P {n: 'p1'}), (:P {n: 'p2'}), (:P {n: 'p3'})",
    );
    run_write(
        &mut coord,
        "MATCH (a:P {n: 'p1'}), (b:P {n: 'p2'}) \
         CREATE (a)-[:SIMILAR {name: 'x', vec: [1.0, 0.0, 0.0]}]->(b)",
    );
    run_write(
        &mut coord,
        "MATCH (a:P {n: 'p2'}), (b:P {n: 'p3'}) \
         CREATE (a)-[:SIMILAR {name: 'y', vec: [0.9, 0.4358899, 0.0]}]->(b)",
    );
    seed_rel_distractors(&mut coord);
    let _writer = {
        let w = coord.begin_serializable();
        let _ = run_plan(
            &coord,
            w,
            &compile(
                "MATCH ()-[r:SIMILAR {name: 'x'}]->() SET r.vec = [0.0, 0.0, 1.0]",
                &IndexCatalog::empty(),
            ),
        );
        w
    };
    coord
        .begin_online_vector_index_named(
            Some("rel_vec"),
            VectorEntity::Relationship,
            "SIMILAR",
            "vec",
            3,
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect("create rel vector index");

    let listings = coord.list_vector_index_listings();
    assert_eq!(listings.len(), 1, "vacuous: no vector index declared");
    assert_eq!(
        format!("{:?}", listings[0].state),
        "Online",
        "vacuous: the index is not Online",
    );

    let reader = coord.begin_serializable();
    let got = knn_rels(&coord, reader, 1);
    assert_eq!(
        got,
        vec![("x".to_owned(), 1.0)],
        "rel k=1 must return the COMMITTED nearest relationship x at score 1.0",
    );
}

/// The wrong answer used to SURVIVE the writer's rollback for the life of the process (only a reopen
/// healed it, the graph being ephemeral). The re-fill driver must repair it once the writer resolves.
#[test]
fn vector_index_is_refilled_after_the_blocking_writer_rolls_back() {
    let mut coord = fresh_coord();
    let writer = seed_and_build_under_open_writer(&mut coord);
    coord.rollback(writer).expect("writer rolls back");
    // The repair runs on the command path, exactly where a real engine would drive it.
    while coord.advance_index_builds(usize::MAX) {}

    let reader = coord.begin_serializable();
    assert_eq!(
        knn_nodes(&coord, reader, 1),
        vec![("x".to_owned(), 1.0)],
        "after the blocking writer rolled back, the graph must be re-filled from committed state",
    );
}

/// Same, for a writer that COMMITS: the newly committed embedding must be the one indexed.
///
/// NOT a regression test, and it says so rather than being claimed as one: this test **passes before
/// the fix too**, because a committed writer's value IS the committed truth, so the graph that baked it
/// early was accidentally right. It is kept as the counterexample that rejects the tempting "just index
/// the newest COMMITTED version" repair — that would leave the writer's own value unindexed once it
/// committed, since `commit` re-inserts no index entries (they are made eagerly at write time).
#[test]
fn vector_index_is_refilled_after_the_blocking_writer_commits() {
    let mut coord = fresh_coord();
    let writer = seed_and_build_under_open_writer(&mut coord);
    coord.commit(writer).expect("writer commits");
    while coord.advance_index_builds(usize::MAX) {}

    let reader = coord.begin_serializable();
    // x is now committed at [0,0,1] (cosine 0 -> score 0.5), so the nearest DISTRACTOR wins: d0 sits at
    // cosine ~0.955 (score ~0.9777), ahead of y at 0.95.
    assert_eq!(
        knn_nodes(&coord, reader, 1),
        vec![("d0".to_owned(), 0.977_668_285_369_873)],
        "after the writer committed, its embedding IS the committed truth and d0 is nearest",
    );
}

/// THE DIRTY-READ SCORE CHANNEL (`rmp` task #780). Independent of #766 and reproducible with no build
/// conflict at all: an older reader must be scored against the embedding ITS snapshot sees, never the
/// newer committed one the graph holds.
#[test]
fn vector_score_is_recomputed_from_the_snapshot_visible_embedding() {
    let mut coord = fresh_coord();
    seed_docs(&mut coord);
    seed_distractors(&mut coord);
    declare_node_vector(&mut coord);

    // An older reader pins the snapshot where x = [1,0,0] (score 1.0).
    let reader = coord.begin_serializable();
    // A LATER, COMMITTED write moves x to cosine 0.98 (score 0.99). Deliberately a SMALL move: x stays
    // comfortably ahead of the distractors (~0.9777), so it is still OFFERED by the graph and this test
    // isolates the SCORE channel. The separate window where a large move pushes an entity OUT of the
    // candidate set is `rmp` #794, documented at `record_graph.rs::vector_query_nodes`.
    run_write(
        &mut coord,
        "MATCH (n:Doc {name: 'x'}) SET n.embedding = [0.98, 0.19899, 0.0]",
    );

    let got = knn_nodes(&coord, reader, 2);
    let x_score = got
        .iter()
        .find(|(n, _)| n == "x")
        .map(|(_, s)| *s)
        .expect("x must still be visible to this older reader");
    assert!(
        (x_score - 1.0).abs() < 1e-6,
        "x must be scored 1.0 from the embedding THIS snapshot sees ([1,0,0]); \
         got {x_score}, which is derived from the newer committed [0.98, 0.19899, 0] (score 0.99) \
         that this reader cannot observe",
    );
}

/// The relationship twin of the dirty-read score channel.
#[test]
fn vector_rel_score_is_recomputed_from_the_snapshot_visible_embedding() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {n: 'p1'}), (:P {n: 'p2'})");
    run_write(
        &mut coord,
        "MATCH (a:P {n: 'p1'}), (b:P {n: 'p2'}) \
         CREATE (a)-[:SIMILAR {name: 'x', vec: [1.0, 0.0, 0.0]}]->(b)",
    );
    run_write(&mut coord, "CREATE (:P {n: 'p3'})");
    seed_rel_distractors(&mut coord);
    coord
        .begin_online_vector_index_named(
            Some("rel_vec"),
            VectorEntity::Relationship,
            "SIMILAR",
            "vec",
            3,
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect("create rel vector index");

    let reader = coord.begin_serializable();
    // A SMALL later move (cosine 0.98), for the reason the node twin documents.
    run_write(
        &mut coord,
        "MATCH ()-[r:SIMILAR {name: 'x'}]->() SET r.vec = [0.98, 0.19899, 0.0]",
    );

    let got = knn_rels(&coord, reader, 2);
    let x_score = got
        .iter()
        .find(|(n, _)| n == "x")
        .map(|(_, s)| *s)
        .expect("x must still be visible to this older reader");
    assert!(
        (x_score - 1.0).abs() < 1e-6,
        "rel x must be scored 1.0 from the embedding THIS snapshot sees; got {x_score}",
    );
}

/// SILENT k-UNDERFILL (`rmp` #795). `k` went straight to the HNSW and the per-candidate re-check then
/// filtered the hits with no back-fill, so `queryNodes(k)` returned fewer than `k` rows even when `k`
/// valid neighbours existed.
#[test]
fn vector_knn_does_not_underfill_k_when_candidates_are_filtered() {
    let mut coord = fresh_coord();
    for (n, e) in [
        ("a", "[0.9, 0.4358899, 0.0]"),
        ("b", "[0.0, 1.0, 0.0]"),
        ("c", "[0.0, 0.0, 1.0]"),
    ] {
        run_write(
            &mut coord,
            &format!("CREATE (:Doc {{name: '{n}', embedding: {e}}})"),
        );
    }
    declare_node_vector(&mut coord);

    // An OLDER reader opens before a nearer node exists.
    let reader = coord.begin_serializable();
    run_write(
        &mut coord,
        "CREATE (:Doc {name: 'e', embedding: [1.0, 0.0, 0.0]})",
    );

    // The reader has exactly three visible neighbours: a, b, c.
    let got = knn_nodes(&coord, reader, 3);
    let names: Vec<String> = got.iter().map(|(n, _)| n.clone()).collect();
    assert_eq!(
        names,
        vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
        "k=3 must return all three visible neighbours; the invisible nearer node must not consume a slot",
    );
}

// -------------------------------------------------------------------------------------------------
// `rmp` #780 REPAIR — engine-STATE tests.
//
// These exist because every other #780 test asserts the query ANSWER, and the exact brute-force scan
// a blocked index declines to returns the SAME answer a repaired index does. That made the whole
// repair driver invisible: with `retry_conflicted_vector_builds` stubbed to `return false`, all of
// them stayed green (mutation-proven during the #780 audit). A test for a repair whose remedy is
// "degrade to a correct slower path" MUST therefore assert the engine's STATE — that the fast path is
// re-armed — never the rows.
// -------------------------------------------------------------------------------------------------

/// The re-fill driver must actually return the index to the ANN fast path.
///
/// FAILS with `retry_conflicted_vector_builds` disabled (verified by stubbing it to `return false`),
/// which is precisely what `vector_index_is_refilled_after_the_blocking_writer_rolls_back` above
/// cannot detect.
#[test]
fn vector_index_returns_to_the_fast_path_after_the_blocking_writer_resolves() {
    let mut coord = fresh_coord();
    let writer = seed_and_build_under_open_writer(&mut coord);

    // Non-vacuity: the gate really fired, so there is a degradation for the repair to undo.
    assert_eq!(
        coord.blocked_vector_indexes(),
        1,
        "vacuous: the build gate did not block the index, so this test proves nothing about repair",
    );
    assert_eq!(
        coord.vector_index_conflict_events(),
        1,
        "the blocked-state entry must be counted exactly once, for the operator-facing metric",
    );

    coord.rollback(writer).expect("writer rolls back");
    // Resolution ALONE is not the repair: the skipped entity is still missing from the graph, and a
    // k-NN can drop a candidate but never resurrect one.
    assert_eq!(
        coord.blocked_vector_indexes(),
        1,
        "the writer merely resolving must NOT re-arm the fast path — the graph is still holed",
    );

    // The command path, where a real engine drives the repair.
    while coord.advance_index_builds(usize::MAX) {}

    assert_eq!(
        coord.blocked_vector_indexes(),
        0,
        "after every blocking writer resolved, the re-fill must rebuild the graph and put the index \
         back on the ANN fast path; still blocked means every k-NN keeps paying an O(entities x dim) \
         exact scan forever, silently, while SHOW INDEXES reports ONLINE",
    );
    // The counter is monotonic: a repair does not un-count the degradation that happened.
    assert_eq!(
        coord.vector_index_conflict_events(),
        1,
        "the entry counter is cumulative and must not be reset by the repair",
    );
}

/// A whole-set rebuild re-derives every graph from a fresh store scan, so it must not carry a blocker
/// across — `IndexSet::clear` drops the #778 full-text blockers for exactly this reason.
///
/// FAILS without the `clear()` fix: the stale blocker survives, and the freshly and CORRECTLY rebuilt
/// graph is left declining to the exact scan (plus a redundant O(store) wipe + re-fill on the next
/// drain to undo it).
#[test]
fn a_whole_set_rebuild_does_not_strand_a_resolved_vector_blocker() {
    let mut coord = fresh_coord();
    let writer = seed_and_build_under_open_writer(&mut coord);
    assert_eq!(
        coord.blocked_vector_indexes(),
        1,
        "vacuous: the build gate did not block the index",
    );
    // The blocking writer resolves FIRST, so the rebuild's own pass cannot see any conflict at all —
    // any blocker still standing afterwards is therefore pure residue from the previous pass.
    coord.rollback(writer).expect("writer rolls back");

    // An unrelated index DDL, which drives `rebuild_index` (clear + re-register + re-fill from the
    // committed store) synchronously — the ordinary way a rebuild happens in a running engine.
    coord
        .create_node_property_index("Doc", "name")
        .expect("declare an unrelated index");

    assert_eq!(
        coord.blocked_vector_indexes(),
        0,
        "a whole-set rebuild from a conflict-free store must leave NO vector blocker behind; a \
         surviving one strands a correctly-rebuilt graph on the exact brute-force scan",
    );
}

// -------------------------------------------------------------------------------------------------
// `rmp` #802 — the re-fill throttle must DRAIN at full quiescence, not merely halve.
//
// The vector-conflict re-fill backoff is a coordinator-GLOBAL throttle shared by every vector index:
// one index's overlapping-writer storm inflates it, and it is spent as `skip` on the FIRST re-conflict
// of the NEXT index to block. Halving on a repair decays it over ~log2(backoff) later repairs, so the
// inflated throttle OUTLIVES the storm that armed it and makes a fresh, singly-conflicted index decline
// to the exact brute-force scan for `backoff` further commands — silently, while `SHOW INDEXES` reports
// ONLINE. The fix drains the backoff to its floor the moment the WHOLE vector blocker set is empty.
// -------------------------------------------------------------------------------------------------

/// Declare an ONLINE node vector index named `name` over `Doc.prop` (the production `CREATE VECTOR
/// INDEX` route).
fn declare_doc_vector(coord: &mut Coord, name: &str, prop: &str) {
    coord
        .begin_online_vector_index_named(
            Some(name),
            VectorEntity::Node,
            "Doc",
            prop,
            3,
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect("create node vector index");
}

/// Open (and leave open) a writer that moves `Doc {name: node}`'s `prop` off its committed value.
fn open_vec_blocker(coord: &mut Coord, node: &str, prop: &str) -> graphus_core::TxnId {
    let w = coord.begin_serializable();
    let _ = run_plan(
        coord,
        w,
        &compile(
            &format!("MATCH (n:Doc {{name: '{node}'}}) SET n.{prop} = [0.0, 0.0, 1.0]"),
            &IndexCatalog::empty(),
        ),
    );
    w
}

/// Drive ONE re-conflict of the already-blocked vector index on `prop`, which takes the `else`
/// (doubling) branch of the re-fill throttle: resolve the current blocker `w`, open the next blocker on
/// the OTHER node (distinct node ⇒ no write-write abort), then drain command passes until the re-fill
/// re-conflicts (one `vector_index_conflict_events` increment). Returns the new OPEN blocker.
fn overlap_double_vec(
    coord: &mut Coord,
    w: graphus_core::TxnId,
    prop: &str,
    next_node: &str,
) -> graphus_core::TxnId {
    let w_next = open_vec_blocker(coord, next_node, prop);
    coord.rollback(w).expect("resolve current blocker");
    let base = coord.vector_index_conflict_events();
    let mut guard = 0u64;
    loop {
        coord.advance_index_builds(usize::MAX);
        guard += 1;
        if coord.vector_index_conflict_events() > base {
            break;
        }
        assert!(
            guard <= 5_000_000,
            "{prop}: the re-fill never re-conflicted"
        );
    }
    w_next
}

/// Full quiescence: resolve `w`, then count command passes until the fast path is re-armed (the index
/// is no longer declining to the exact scan). This IS the "commands still served by the exact scan"
/// recovery bound.
fn quiesce_vec_and_count(coord: &mut Coord, w: graphus_core::TxnId) -> u64 {
    coord.rollback(w).expect("resolve last blocker");
    let mut passes = 0u64;
    while coord.blocked_vector_indexes() > 0 {
        coord.advance_index_builds(usize::MAX);
        passes += 1;
        assert!(
            passes <= 5_000_000,
            "the index never returned to the fast path"
        );
    }
    passes
}

/// The recovery bound: after a storm on one index has fully quiesced, an UNRELATED index that blocks
/// later with a single transient conflict must return to the ANN fast path PROMPTLY — it must not
/// inherit the storm's inflated throttle.
///
/// FAILS (RED) with the `rmp` #802 drain reverted (the `repaired` branch halving unconditionally): the
/// shared backoff peaks during storm A, A quiesces to backoff/2, and index B — built long after, with
/// ONE re-conflict — then inherits it and stays on the exact scan for hundreds of commands. MEASURED:
/// B pays 513 commands without the drain versus 3 with it (storm A peaked the shared backoff at 512).
///
/// The assertion is a STATE bound (`blocked_vector_indexes` passes), never a query answer: the exact
/// scan a blocked index declines to returns the SAME rows a repaired index does, so a rows-based test
/// cannot see the residue at all (`rmp` #780 audit, above).
#[test]
fn vector_conflict_backoff_drains_at_full_quiescence() {
    let mut coord = fresh_coord();
    // Two covered properties on the same label, each with its OWN vector index. The throttle they share
    // is coordinator-global, which is the whole point.
    run_write(
        &mut coord,
        "CREATE (:Doc {name: 'x', embedding: [1.0, 0.0, 0.0], emb2: [1.0, 0.0, 0.0]})",
    );
    run_write(
        &mut coord,
        "CREATE (:Doc {name: 'y', embedding: [0.9, 0.4358899, 0.0], emb2: [0.9, 0.4358899, 0.0]})",
    );

    // ---- STORM on index A: build under an open writer, then 20 overlapping re-conflicts that inflate
    // the shared backoff geometrically (1 → 2 → 4 → … → 512). An EVEN round count ends the storm on a
    // drained-skip round, so A quiesces through the pure vector-conflict re-fill (the path #802 fixes)
    // rather than the #803 poison-rebuild path (which clears the blocker WITHOUT touching this throttle,
    // and would leave B's inheritance ambiguous).
    let mut w = open_vec_blocker(&mut coord, "x", "embedding");
    declare_doc_vector(&mut coord, "vec_a", "embedding");
    for round in 0..20u32 {
        let next = if round % 2 == 0 { "y" } else { "x" };
        w = overlap_double_vec(&mut coord, w, "embedding", next);
    }
    // NON-VACUITY: the storm genuinely churned. Each re-conflict is one `vector_conflict_events` edge,
    // and (under a drained skip) one doubling of the shared backoff — so a high count is direct evidence
    // the throttle was driven far above its floor and there is a real inflation for B to inherit.
    let storm_events = coord.vector_index_conflict_events();
    assert!(
        storm_events >= 15,
        "vacuous: the storm produced only {storm_events} re-conflicts, so it did not inflate the \
         shared backoff and B below has nothing to inherit",
    );

    // A quiesces. Its OWN recovery still pays the inherent throttle cost it armed — the fix neither does
    // nor must shorten the storm's own tail; #802 is only about the backoff OUTLIVING the storm.
    let residue_a = quiesce_vec_and_count(&mut coord, w);
    assert_eq!(
        coord.blocked_vector_indexes(),
        0,
        "vacuous: storm A never blocked, so there was no inflated throttle to drain",
    );

    // ---- Index B: a DIFFERENT index, built long after the storm ended, with a SINGLE transient
    // re-conflict. It must NOT inherit storm A's throttle: B's own one re-conflict justifies at most a
    // ~3-command window, nothing more.
    let mut wb = open_vec_blocker(&mut coord, "x", "emb2");
    declare_doc_vector(&mut coord, "vec_b", "emb2");
    assert_eq!(
        coord.blocked_vector_indexes(),
        1,
        "vacuous: index B's build did not block, so its recovery exercises nothing",
    );
    wb = overlap_double_vec(&mut coord, wb, "emb2", "y");
    let residue_b = quiesce_vec_and_count(&mut coord, wb);

    // THE BOUND. With the drain (fix) B recovers in 3 command passes; without it B inherits the storm's
    // half-decayed backoff (256 after a 512 peak) and pays 513 — the residue outliving its cause.
    assert!(
        residue_b <= 5,
        "index B — unrelated to storm A, with a single transient conflict — took {residue_b} \
         commands to return to the ANN fast path (its own re-conflict justifies at most ~3). It \
         inherited storm A's inflated backoff (A itself needed {residue_a} and churned \
         {storm_events} re-conflicts); the re-fill throttle did not drain at full quiescence, so a \
         fresh index declines to the O(entities x dim) exact scan long after the storm that armed the \
         throttle is gone (`rmp` #802).",
    );
}
