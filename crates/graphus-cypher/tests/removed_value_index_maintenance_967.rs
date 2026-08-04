//! A **committed removal** — of a property or of a label — must leave every derived index agreeing
//! with the store (`rmp` task #967).
//!
//! # The two independent defects these tests pin
//!
//! Derived indexes come in two shapes, and the difference is the whole subject of this file:
//!
//! * **candidate + re-check** (property, composite) — the seek re-reads each candidate's current
//!   value at the reader's snapshot, so a stale entry is dropped and only a *missing* entry is fatal;
//! * **wholesale** (full text, vector, spatial, bitmap) — the structure holds one value per entity
//!   and its consumer does **not** re-check that value, so a stale entry is a wrong answer.
//!
//! **Defect 1 — the removal paths ran no wholesale maintenance at all.** `REMOVE n.p`,
//! `SET n.p = null`, `REMOVE n:Label`, `REMOVE r.p`, `SET r.p = null` and `SET n = {}` / `SET r = {}`
//! each carried a comment saying no re-index was needed because "dropping a key never adds a
//! candidate, and the seek re-checks the store so a stale candidate is filtered out". That is exactly
//! true of the first shape and exactly false of the second — which is why the *bitmap* column, being
//! membership-exact, already had a hook there (`reindex_node_bitmaps`) while full text, vector and
//! spatial had none. So a committed `REMOVE n.title` left the full-text index returning the node for
//! the removed text, until some *later, unrelated* write on the same entity happened to re-index it.
//!
//! **Defect 2 — `reindex_rel` then re-baked the removed value anyway.** Since #967 a property
//! overwrite is written **in place** and the superseded value descends onto the entity's undo chain,
//! which renamed the polarity of every raw property read:
//!
//! * `SupersetProperties::candidates()` (what the decoded `superset_scan_*_property_values` yields)
//!   is the **superset** — the live cells, with the EMPTY cell a `REMOVE` leaves behind skipped,
//!   followed by every retained historical value;
//! * `decision_scan_*_properties` is the **decision** read — the value each key holds at a snapshot,
//!   and the only read that resolves a removal to "absent".
//!
//! `reindex_rel` folded "first occurrence per key wins" over the superset, so for a removed key the
//! first surviving candidate was the **pre-removal value**. The node twin `reindex_node` was already
//! correct (it resolves through `read_node_props`, i.e. `decision_scan_node_properties`).
//!
//! The two defects are independent and neither fix alone is sufficient: with only defect 1 fixed, the
//! removal re-indexes and immediately re-bakes the old value; with only defect 2 fixed, the removal
//! re-indexes nothing and the index stays stale until an unrelated later write. Reverting either fix
//! fails the tests below.
//!
//! # What each shape costs when it is wrong
//!
//! * **full text** — `fulltext_query` / `fulltext_query_rel` re-check a hit's visibility and current
//!   label/type, never its **terms**, so a removed value is returned as a **wrong row**.
//! * **vector** — the `db.index.vector.*` procedures *do* re-score every candidate against its
//!   snapshot-visible embedding (`rescore_candidates` → `GraphAccess::{node,rel}_property`), so a
//!   phantom is never a wrong row. It is still a **candidate**, and only `2k` are over-fetched before
//!   that re-score runs, so enough phantoms crowd the genuine neighbour out and the query returns
//!   **nothing** where it owed a row — silent row LOSS.
//! * **spatial** — the grid takes the same phantom, but it is not observable today: the planner keeps
//!   the exact `distance(...)` predicate as a residual `Filter` above the seek, and that residual
//!   reads the property at the reader's snapshot. There is also no `k` to starve. The spatial test
//!   below therefore pins the *masking mechanism* rather than pretending to witness a defect it
//!   cannot reach, and fails the day the residual is elided.
//!
//! # Two ways these tests could pass for the wrong reason
//!
//! **The index never came `Online`.** A node index is built **incrementally**: `create_fulltext_index`
//! and `begin_online_vector_index_named` leave it `Populating`, and while it is not `Online` every
//! query declines to the exact scan fallback — which returns the right answer whatever the index
//! holds, hiding the defect completely. This was not hypothetical: the first draft of the node
//! full-text test passed against the unfixed engine for exactly this reason. Every node test therefore
//! calls `finish_index_builds`.
//!
//! **The consumer re-checks the axis being tested.** Both the label and the value axes *are* re-checked
//! at row level by every consumer, so no assertion here can rest on "the index holds a stale entry" —
//! it must rest on a consequence that survives the re-check: a term (which nothing re-checks) or a
//! crowded-out `k` (which the re-check causes rather than cures). A label-loss test asserted against
//! full text passes with the fix reverted, and was rewritten for that reason.
//!
//! Neither hazard is caught by reading the test. Both were caught by reverting each fix by patch and
//! confirming the assertion actually fails.

use std::collections::HashMap;

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_index::fulltext::Analyzer;
use graphus_io::MemBlockDevice;
use graphus_storage::{RecordStore, VectorEntity, VectorSimilarity};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness (mirrors tests/vector_procedures.rs + tests/spatial_coordinator.rs)
// =================================================================================================

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 64, 1).expect("create store");
    TxnCoordinator::new(store)
}

fn compile(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog)
}

fn run_plan(coord: &Coord, txn: TxnId, plan: &PhysicalPlan) -> Vec<Row> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(
        !graph.has_error(),
        "statement captured an error: {:?}",
        graph.take_error()
    );
    rows
}

/// Runs a write statement (planned without any index) and commits it.
fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let _rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

/// Runs a read statement over `catalog` in a fresh auto-commit transaction.
fn read_rows(coord: &mut Coord, catalog: &IndexCatalog, src: &str) -> Vec<Row> {
    let plan = compile(src, catalog);
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    rows
}

/// The `tag` values of the rows a `RETURN … AS tag` read produced, sorted.
fn tags(rows: &[Row]) -> Vec<String> {
    let mut out: Vec<String> = rows
        .iter()
        .map(|r| match r.value("tag") {
            Value::String(s) => s,
            other => panic!("expected a string tag, got {other:?}"),
        })
        .collect();
    out.sort();
    out
}

/// Drives every pending incremental index build to completion.
///
/// Load-bearing for the NODE tests: a node full-text index is created `Populating`, and while it is
/// not `Online` every query declines to the exact scan fallback, which returns the right answer and
/// hides the defect completely. Without this the node tests pass for the wrong reason.
fn finish_index_builds(coord: &mut Coord) {
    let mut iters = 0;
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(64);
        iters += 1;
        assert!(
            iters < 100_000,
            "the incremental index builds must terminate"
        );
    }
}

// =================================================================================================
// Full text — relationships
// =================================================================================================

/// A relationship full-text index must not return a relationship whose covered text was **removed**
/// in a committed transaction.
///
/// `fulltext_query_rel` re-checks a candidate's visibility and type but never its terms, so a term
/// re-baked from the undo chain is a wrong row nothing downstream can drop.
#[test]
fn a_removed_relationship_string_is_not_rebaked_into_the_fulltext_index() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P {name: 'a'}), (:P {name: 'b'}), (:P {name: 'c'})",
    );
    run_write(
        &mut coord,
        "MATCH (a:P {name: 'a'}), (b:P {name: 'b'}) \
         CREATE (a)-[:CITES {note: 'investigadores citam prova', tag: 'doomed'}]->(b)",
    );
    run_write(
        &mut coord,
        "MATCH (a:P {name: 'a'}), (c:P {name: 'c'}) \
         CREATE (a)-[:CITES {note: 'investigadores citam outra prova', tag: 'kept'}]->(c)",
    );
    coord
        .create_fulltext_rel_index(
            "cites_ft",
            &["CITES".to_owned()],
            &["note".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("create rel fulltext index");

    let query = "CALL db.index.fulltext.queryRelationships('cites_ft', 'investigadores') \
                 YIELD relationship AS r RETURN r.tag AS tag";
    let empty = IndexCatalog::empty();

    // Baseline: both relationships carry the covered text, so both are hits. Without this the test
    // could pass by never having indexed anything at all.
    assert_eq!(
        tags(&read_rows(&mut coord, &empty, query)),
        vec!["doomed".to_owned(), "kept".to_owned()],
        "baseline: both relationships carry the covered text"
    );

    // THE REMOVAL. `REMOVE r.note` itself ends in `reindex_rel`, so the re-bake — if any — happens
    // here, before any other statement runs.
    run_write(
        &mut coord,
        "MATCH ()-[r:CITES]->() WHERE r.tag = 'doomed' REMOVE r.note",
    );
    assert_eq!(
        tags(&read_rows(&mut coord, &empty, query)),
        vec!["kept".to_owned()],
        "after a committed `REMOVE r.note`, the relationship must not be a full-text hit. Two \
         independent defects each produce this failure: the removal path running no wholesale index \
         maintenance at all (defect 1), and `reindex_rel` re-baking the pre-removal value off the \
         candidate superset (defect 2). `fulltext_query_rel` re-checks visibility and type but NEVER \
         the terms, so either one is a committed-removed value returned as a row (`rmp` #967)"
    );

    // AND AGAIN, through an unrelated key: any later write on the relationship re-runs the wholesale
    // re-index, so a fix that only special-cases the removing statement still fails here.
    run_write(
        &mut coord,
        "MATCH ()-[r:CITES]->() WHERE r.tag = 'doomed' SET r.weight = 7",
    );
    assert_eq!(
        tags(&read_rows(&mut coord, &empty, query)),
        vec!["kept".to_owned()],
        "a later `SET` on an UNRELATED key must not resurrect the removed text either"
    );

    // Ground truth from the exact scan path: the property really is gone.
    let truth = read_rows(
        &mut coord,
        &empty,
        "MATCH ()-[r:CITES]->() WHERE r.note IS NOT NULL RETURN r.tag AS tag",
    );
    assert_eq!(
        tags(&truth),
        vec!["kept".to_owned()],
        "the exact scan path agrees: only the surviving relationship holds `note`"
    );
}

// =================================================================================================
// Vector (HNSW)
// =================================================================================================

/// A relationship whose covered embedding was **removed** must leave the ANN graph, not be
/// re-inserted at the value it used to hold.
///
/// The procedure re-scores every candidate against its snapshot-visible embedding
/// (`rescore_candidates` → `GraphAccess::rel_property`), so a phantom never becomes a wrong row. What
/// it becomes is a **candidate**, and the procedure over-fetches only `2k` candidates before that
/// re-score runs. Two phantoms nearer to the query than the genuine neighbour therefore consume the
/// whole `k = 1` over-fetch budget, both get dropped by the re-score, and the query returns **no
/// rows** where it owed one — silent row loss.
#[test]
fn a_removed_relationship_embedding_does_not_starve_the_vector_query() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {name: 'a'}), (:P {name: 'b'})");
    // Two relationships whose embeddings sit almost exactly on the query vector, and one that sits
    // diametrically opposite it. The first two are the ones whose embedding is removed.
    for (embedding, tag) in [
        ("[1.0, 0.0]", "doomed_1"),
        ("[0.99, 0.1]", "doomed_2"),
        ("[-1.0, 0.0]", "kept"),
    ] {
        run_write(
            &mut coord,
            &format!(
                "MATCH (a:P {{name: 'a'}}), (b:P {{name: 'b'}}) \
                 CREATE (a)-[:SIM {{embedding: {embedding}, tag: '{tag}'}}]->(b)"
            ),
        );
    }
    coord
        .begin_online_vector_index_named(
            Some("sim_vec"),
            VectorEntity::Relationship,
            "SIM",
            "embedding",
            2,
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect("create rel vector index");

    let empty = IndexCatalog::empty();
    // The vector procedure yields physical ids, so map id -> tag once and assert on the stable tag.
    let id_to_tag: HashMap<i64, String> = read_rows(
        &mut coord,
        &empty,
        "MATCH ()-[r:SIM]->() RETURN id(r) AS id, r.tag AS tag",
    )
    .iter()
    .map(|r| match (r.value("id"), r.value("tag")) {
        (Value::Integer(id), Value::String(tag)) => (id, tag),
        other => panic!("expected (id, tag), got {other:?}"),
    })
    .collect();

    // `k = 1` — the over-fetch budget is `2k = 2`, exactly the number of phantoms below.
    let query = "CALL db.index.vector.queryRelationships('sim_vec', 1, [1.0, 0.0]) \
                 YIELD relationship AS r RETURN id(r) AS id";
    let hit_tags = |coord: &mut Coord| -> Vec<String> {
        let mut out: Vec<String> = read_rows(coord, &IndexCatalog::empty(), query)
            .iter()
            .map(|r| match r.value("id") {
                Value::Integer(id) => id_to_tag.get(&id).cloned().expect("known relationship"),
                other => panic!("expected an integer id, got {other:?}"),
            })
            .collect();
        out.sort();
        out
    };

    assert_eq!(
        hit_tags(&mut coord),
        vec!["doomed_1".to_owned()],
        "baseline: the nearest embedding wins, so the index really is answering this query"
    );

    for tag in ["doomed_1", "doomed_2"] {
        run_write(
            &mut coord,
            &format!("MATCH ()-[r:SIM]->() WHERE r.tag = '{tag}' REMOVE r.embedding"),
        );
    }
    assert_eq!(
        hit_tags(&mut coord),
        vec!["kept".to_owned()],
        "after two committed `REMOVE r.embedding` the ANN graph must hold ONE entry, so the surviving \
         relationship is the answer. Re-inserting each removed embedding from the undo chain instead \
         leaves two phantoms nearer to the query, they consume the whole `2k` over-fetch budget, the \
         re-score drops both, and the query LOSES a row it owed (`rmp` #967)"
    );

    run_write(
        &mut coord,
        "MATCH ()-[r:SIM]->() WHERE r.tag = 'doomed_1' SET r.weight = 7",
    );
    assert_eq!(
        hit_tags(&mut coord),
        vec!["kept".to_owned()],
        "a later `SET` on an UNRELATED key must not resurrect the removed embedding either"
    );
}

// =================================================================================================
// Spatial (grid)
// =================================================================================================

/// Whether `plan` routes through the relationship spatial seek (rather than a scan + filter).
///
/// Read off the plan's own rendering rather than off a hand-written child walk: a walk with a `_ =>`
/// arm silently reports `false` for any operator shape it forgot, which would make the assertion
/// below fail open rather than closed.
fn plan_uses_rel_spatial_seek(plan: &PhysicalPlan) -> bool {
    format!("{plan}").contains("RelSpatialIndexSeek")
}

/// The relationship spatial grid is keyed by relationship id and holds ONE point per relationship, so
/// a removal must remove the entry rather than re-insert the point the relationship used to hold.
///
/// Unlike full text and vector, the seek's answer is made exact by the `distance(...)` residual the
/// executor keeps above it, which reads the property at the reader's snapshot. This test therefore
/// asserts the property that actually matters and would survive the residual being elided: the seek
/// path and the scan path return the **same** set, and neither returns the removed relationship.
#[test]
fn a_removed_relationship_point_leaves_the_spatial_seek_equal_to_the_scan() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {name: 'a'}), (:P {name: 'b'})");
    run_write(
        &mut coord,
        "MATCH (a:P {name: 'a'}), (b:P {name: 'b'}) \
         CREATE (a)-[:VISITED {at: point({x: 0, y: 0}), tag: 'doomed'}]->(b)",
    );
    run_write(
        &mut coord,
        "MATCH (a:P {name: 'a'}), (b:P {name: 'b'}) \
         CREATE (a)-[:VISITED {at: point({x: 1, y: 0}), tag: 'kept'}]->(b)",
    );
    coord
        .create_point_rel_index("visited_at", "VISITED", "at", false)
        .expect("create rel point index");

    let query = "MATCH (a)-[r:VISITED]->(b) \
                 WHERE distance(r.at, point({x: 0, y: 0})) <= 5 \
                 RETURN r.tag AS tag";
    let empty = IndexCatalog::empty();
    let indexed = coord.catalog();
    let plan = compile(query, &indexed);
    assert!(
        plan_uses_rel_spatial_seek(&plan),
        "the indexed plan must actually route through the relationship spatial seek, else this test \
         compares the scan path against itself:\n{plan}"
    );
    // THE MASKING MECHANISM, pinned. The grid takes the same phantom the full-text and vector indexes
    // take; what stops it becoming a row is that the planner keeps the exact `distance(...)` predicate
    // as a residual above the seek, and that residual reads the property at the reader's snapshot.
    // Elide the residual and the phantom becomes a row, so it is asserted rather than assumed.
    assert!(
        format!("{plan}").contains("Filter"),
        "the relationship spatial seek must keep the exact `distance(...)` predicate as a residual \
         `Filter` above it — the grid is a CANDIDATE source, and the residual is the only thing that \
         re-checks the point at the reader's snapshot:\n{plan}"
    );

    assert_eq!(
        tags(&read_rows(&mut coord, &indexed, query)),
        vec!["doomed".to_owned(), "kept".to_owned()],
        "baseline: both points are within the radius"
    );

    run_write(
        &mut coord,
        "MATCH ()-[r:VISITED]->() WHERE r.tag = 'doomed' REMOVE r.at",
    );
    let indexed = coord.catalog();
    let seek = tags(&read_rows(&mut coord, &indexed, query));
    let scan = tags(&read_rows(&mut coord, &empty, query));
    assert_eq!(
        seek, scan,
        "the relationship spatial seek must return exactly what the scan returns after a committed \
         `REMOVE r.at`"
    );
    assert_eq!(
        seek,
        vec!["kept".to_owned()],
        "the relationship whose point was removed must not be within any radius"
    );
}

// =================================================================================================
// Full text — nodes (the pre-existing half of the defect: the removal paths re-indexed nothing)
// =================================================================================================

/// Seeds two `:Doc` nodes and an **`Online`** node full-text index over `Doc.title`.
///
/// Returns the query that reads it. The build is driven to completion because a `Populating` index
/// declines every query to the exact scan, which would make each assertion below vacuous.
fn seed_node_fulltext(coord: &mut Coord) -> &'static str {
    run_write(
        coord,
        "CREATE (:Doc {title: 'investigadores citam prova', tag: 'doomed'}), \
                (:Doc {title: 'investigadores citam outra', tag: 'kept'})",
    );
    coord
        .create_fulltext_index(
            "doc_ft",
            &["Doc".to_owned()],
            &["title".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("create node fulltext index");
    finish_index_builds(coord);
    "CALL db.index.fulltext.queryNodes('doc_ft', 'investigadores') \
     YIELD node AS n RETURN n.tag AS tag"
}

/// `REMOVE n.title` and `SET n.title = null` are the same removal spelled two ways, and both must
/// take the node out of the node full-text index **on the removing statement**.
///
/// Neither path ran any wholesale index maintenance: `remove_node_property` and the null branch of
/// `set_node_property` both called `reindex_node_bitmaps`, which maintains the bitmap column and
/// nothing else, on the premise that "the other index kinds tolerate the stale entry".
#[test]
fn a_removed_node_string_leaves_the_fulltext_index_on_the_removing_statement() {
    let mut coord = fresh_coord();
    let query = seed_node_fulltext(&mut coord);
    let empty = IndexCatalog::empty();

    assert_eq!(
        tags(&read_rows(&mut coord, &empty, query)),
        vec!["doomed".to_owned(), "kept".to_owned()],
        "baseline: both nodes carry the covered text"
    );

    run_write(&mut coord, "MATCH (n:Doc {tag: 'doomed'}) REMOVE n.title");
    assert_eq!(
        tags(&read_rows(&mut coord, &empty, query)),
        vec!["kept".to_owned()],
        "`REMOVE n.title` must drop the node from the full-text index immediately, not leave it \
         matching until some later unrelated write happens to re-index it: `fulltext_query` \
         re-checks a hit's visibility and current label but NEVER its terms"
    );

    run_write(&mut coord, "MATCH (n:Doc {tag: 'kept'}) SET n.title = null");
    assert!(
        tags(&read_rows(&mut coord, &empty, query)).is_empty(),
        "`SET n.title = null` is the same removal spelled differently and must behave identically"
    );
}

/// A node that loses the covered **label** must leave the derived indexes too — the index covers
/// `(label, property)`, so a node that no longer carries the label is no longer covered.
///
/// `remove_labels` had the same hole as the property removals and for the same stated reason. The
/// **label** axis, unlike the value axis, *is* re-checked at row level by every consumer
/// (`fulltext_query` → `filter_any_label_candidates`, and both vector procedures re-check
/// `node_labels` inside `rescore_candidates`), so a stale entry is never a wrong row. Asserting on
/// full text here would therefore have been vacuous — it passes with the fix reverted, because the
/// row-level label re-check catches it either way, and this test was written that way first.
///
/// What a stale entry *is* is a **candidate**, and the vector procedure over-fetches only `2k` of them
/// before that re-check runs. Two nodes that lost the label, sitting nearer the query than the one
/// that kept it, therefore consume the whole `k = 1` budget and the query returns nothing.
#[test]
fn a_node_that_loses_the_covered_label_does_not_starve_the_vector_query() {
    let mut coord = fresh_coord();
    for (embedding, tag) in [
        ("[1.0, 0.0]", "doomed_1"),
        ("[0.99, 0.1]", "doomed_2"),
        ("[-1.0, 0.0]", "kept"),
    ] {
        run_write(
            &mut coord,
            &format!("CREATE (:Doc {{embedding: {embedding}, tag: '{tag}'}})"),
        );
    }
    coord
        .begin_online_vector_index_named(
            Some("doc_vec"),
            VectorEntity::Node,
            "Doc",
            "embedding",
            2,
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect("create node vector index");
    finish_index_builds(&mut coord);

    let empty = IndexCatalog::empty();
    let query = "CALL db.index.vector.queryNodes('doc_vec', 1, [1.0, 0.0]) \
                 YIELD node AS n RETURN n.tag AS tag";
    assert_eq!(
        tags(&read_rows(&mut coord, &empty, query)),
        vec!["doomed_1".to_owned()],
        "baseline: the nearest embedding wins, so the index really is answering this query"
    );

    for tag in ["doomed_1", "doomed_2"] {
        run_write(
            &mut coord,
            &format!("MATCH (n:Doc {{tag: '{tag}'}}) REMOVE n:Doc"),
        );
    }
    assert_eq!(
        tags(&read_rows(&mut coord, &empty, query)),
        vec!["kept".to_owned()],
        "`REMOVE n:Doc` takes a node out of the index's coverage, so it must leave the ANN graph. \
         Leaving it there keeps two nearer phantoms as candidates, they consume the whole `2k` \
         over-fetch budget, the row-level label re-check drops both, and the query LOSES a row"
    );
}

/// `SET n = {}` / `SET r = {}` clear every property without re-setting one, so the per-key
/// `set_*_property` loop runs zero times and the wholesale maintenance it would have carried never
/// happens. The whole-map replace therefore needs its own re-index.
#[test]
fn clearing_every_property_with_an_empty_map_leaves_the_fulltext_indexes() {
    let mut coord = fresh_coord();
    let node_query = seed_node_fulltext(&mut coord);
    let empty = IndexCatalog::empty();

    run_write(&mut coord, "MATCH (n:Doc {tag: 'doomed'}) SET n = {}");
    assert_eq!(
        tags(&read_rows(&mut coord, &empty, node_query)),
        vec!["kept".to_owned()],
        "`SET n = {{}}` cleared the covered text, so the node must leave the node full-text index"
    );

    // The relationship twin, in the same store.
    run_write(
        &mut coord,
        "MATCH (a:Doc {tag: 'kept'}) CREATE (a)-[:CITES {note: 'investigadores', tag: 'r'}]->(a)",
    );
    coord
        .create_fulltext_rel_index(
            "cites_ft",
            &["CITES".to_owned()],
            &["note".to_owned()],
            Analyzer::Standard,
            false,
        )
        .expect("create rel fulltext index");
    finish_index_builds(&mut coord);
    let rel_query = "CALL db.index.fulltext.queryRelationships('cites_ft', 'investigadores') \
                     YIELD relationship AS r RETURN r.tag AS tag";
    assert_eq!(
        tags(&read_rows(&mut coord, &empty, rel_query)),
        vec!["r".to_owned()],
        "baseline: the relationship carries the covered text"
    );

    run_write(&mut coord, "MATCH ()-[r:CITES]->() SET r = {}");
    assert!(
        tags(&read_rows(&mut coord, &empty, rel_query)).is_empty(),
        "`SET r = {{}}` cleared the covered text, so the relationship must leave the relationship \
         full-text index"
    );
}
