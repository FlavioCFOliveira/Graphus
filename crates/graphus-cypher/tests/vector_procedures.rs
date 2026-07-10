//! Vector (HNSW) index **query surface** end-to-end (`rmp` task #671, part D): the
//! `db.index.vector.queryNodes` / `db.index.vector.queryRelationships` procedures and the
//! `vector.similarity.cosine` / `vector.similarity.euclidean` functions, driven through the whole
//! query path — lex → parse → analyze → plan → bind → execute — over a real [`TxnCoordinator`] (the
//! store-backed backend that holds the live HNSW graph + MVCC).
//!
//! The harness mirrors `tests/vector_index.rs`: a `TxnCoordinator` over an in-memory store, `run_write`
//! to seed embeddings and declare the index via `begin_online_vector_index_named`, and a read helper
//! that runs a `CALL … YIELD …` statement on a coordinator `statement()` (a `RecordStoreGraph`).
//!
//! The vector index returns **physical** ids (`id(n)` / `id(r)`), so each test builds a
//! `physical id → tag` map from a `RETURN id(n) …` read and asserts on the stable `name`/`tag` rather
//! than on the store-assigned physical id order.

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
use graphus_io::MemBlockDevice;
use graphus_storage::{RecordStore, VectorEntity, VectorSimilarity};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness
// =================================================================================================

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 64, 1).expect("create store");
    TxnCoordinator::new(store)
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs a write statement and **commits** it, asserting it succeeded with no captured error.
fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src);
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let captured = {
        let mut graph = coord.statement(txn).expect("statement");
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            let _rows: Vec<Row> = cursor.collect_all().expect("collect");
        }
        graph.take_error()
    };
    assert!(
        captured.is_none(),
        "write {src:?} must succeed: {captured:?}"
    );
    coord.commit(txn).expect("write commits");
}

/// Runs a read statement on `txn` (an already-open transaction), returning its runtime rows. Does not
/// commit — the caller controls the transaction lifecycle (so MVCC-snapshot tests can pin a snapshot).
fn read_rows_on(coord: &mut Coord, txn: TxnId, src: &str) -> Vec<Row> {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
    cursor.collect_all().expect("collect")
}

/// Runs a read statement in a fresh auto-commit transaction, returning its runtime rows.
fn read_rows(coord: &mut Coord, src: &str) -> Vec<Row> {
    let txn = coord.begin_serializable();
    let rows = read_rows_on(coord, txn, src);
    coord.commit(txn).expect("read commits");
    rows
}

/// Runs a read statement expected to fail at execution, returning the rendered error string.
fn read_err(coord: &mut Coord, src: &str) -> String {
    let plan = compile(src);
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let err = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        match cursor.collect_all() {
            Ok(_) => panic!("expected {src:?} to fail, but it produced rows"),
            Err(e) => format!("{e}"),
        }
    };
    let _ = coord.rollback(txn);
    err
}

/// The `physical id → name` map for every `:Doc` node — the bridge from vector-index physical ids to
/// the test's stable `name` tags.
fn doc_pid_to_name(coord: &mut Coord) -> HashMap<u64, String> {
    read_rows(coord, "MATCH (n:Doc) RETURN id(n) AS pid, n.name AS name")
        .iter()
        .map(|r| pid_name(r, "name"))
        .collect()
}

fn pid_name(r: &Row, tag_col: &str) -> (u64, String) {
    let pid = match r.value("pid") {
        Value::Integer(i) => i as u64,
        other => panic!("id() must be an integer, got {other:?}"),
    };
    let name = match r.value(tag_col) {
        Value::String(s) => s,
        other => panic!("{tag_col} must be a string, got {other:?}"),
    };
    (pid, name)
}

/// Formats an `f32` vector as a Cypher list literal (`{:?}` keeps a decimal point so each element
/// lexes as a Float, never an Integer).
fn vec_lit(v: &[f32]) -> String {
    let elems: Vec<String> = v.iter().map(|x| format!("{x:?}")).collect();
    format!("[{}]", elems.join(", "))
}

/// Seeds three well-separated 3-D embeddings so the nearest neighbour of a query is unambiguous, then
/// declares a cosine node vector index over `(Doc, embedding)`.
fn seed_docs_and_index(coord: &mut Coord) {
    run_write(
        coord,
        "CREATE (:Doc {name: 'x', embedding: [1.0, 0.0, 0.0]})",
    );
    run_write(
        coord,
        "CREATE (:Doc {name: 'y', embedding: [0.0, 1.0, 0.0]})",
    );
    run_write(
        coord,
        "CREATE (:Doc {name: 'z', embedding: [0.0, 0.0, 1.0]})",
    );
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

/// Runs `db.index.vector.queryNodes` and returns `(name, score)` rows in the procedure's order.
fn query_nodes(coord: &mut Coord, index: &str, query: &[f32], k: usize) -> Vec<(String, f64)> {
    let pid_to_name = doc_pid_to_name(coord);
    let src = format!(
        "CALL db.index.vector.queryNodes('{index}', {k}, {}) YIELD node, score \
         RETURN id(node) AS pid, score",
        vec_lit(query)
    );
    read_rows(coord, &src)
        .iter()
        .map(|r| {
            let pid = match r.value("pid") {
                Value::Integer(i) => i as u64,
                other => panic!("id(node) must be an integer, got {other:?}"),
            };
            let score = match r.value("score") {
                Value::Float(f) => f,
                other => panic!("score must be a float, got {other:?}"),
            };
            (
                pid_to_name
                    .get(&pid)
                    .cloned()
                    .unwrap_or_else(|| format!("<pid {pid}>")),
                score,
            )
        })
        .collect()
}

/// The single FLOAT a `RETURN <expr>` statement yields.
fn scalar_float(coord: &mut Coord, expr: &str) -> f64 {
    let rows = read_rows(coord, &format!("RETURN {expr} AS s"));
    assert_eq!(rows.len(), 1, "expected one row for {expr:?}");
    match rows[0].value("s") {
        Value::Float(f) => f,
        other => panic!("{expr} must be a float, got {other:?}"),
    }
}

// =================================================================================================
// db.index.vector.queryNodes
// =================================================================================================

#[test]
fn query_nodes_returns_k_nearest_by_descending_score() {
    let mut coord = fresh_coord();
    seed_docs_and_index(&mut coord);

    // A query closest to 'x' (cos to x ≈ 0.894, to y ≈ 0.447, to z = 0). k = 3 returns all three,
    // nearest first, with scores strictly descending.
    let hits = query_nodes(&mut coord, "doc_vec", &[2.0, 1.0, 0.0], 3);
    let names: Vec<&str> = hits.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["x", "y", "z"], "nearest-first order");
    assert!(
        hits[0].1 >= hits[1].1 && hits[1].1 >= hits[2].1,
        "scores must be descending: {hits:?}"
    );
    // The nearest is 'x' with the highest score; the self-similarity of a colinear-with-x query is 1.0
    // only for an exact match, so just assert x outranks the rest.
    assert!(hits[0].1 > hits[2].1, "x must strictly outrank z: {hits:?}");

    // k = 1 returns only the single nearest.
    let top1 = query_nodes(&mut coord, "doc_vec", &[0.1, 0.95, 0.05], 1);
    assert_eq!(top1.len(), 1);
    assert_eq!(top1[0].0, "y", "the nearest neighbour of ~[0,1,0] is 'y'");

    // An exact match scores exactly 1.0 (cosine self-similarity).
    let exact = query_nodes(&mut coord, "doc_vec", &[1.0, 0.0, 0.0], 1);
    assert_eq!(exact[0].0, "x");
    assert!(
        (exact[0].1 - 1.0).abs() < 1e-6,
        "cosine self-score is 1.0, got {}",
        exact[0].1
    );
}

#[test]
fn query_nodes_excludes_a_deleted_node_mvcc() {
    let mut coord = fresh_coord();
    seed_docs_and_index(&mut coord);

    // Delete the node that a query near [1,0,0] would rank first, and commit.
    run_write(&mut coord, "MATCH (n:Doc {name: 'x'}) DELETE n");

    // A query near the deleted 'x' must never return it — it is gone from the index (maintenance) AND
    // dropped by the procedure's per-candidate MVCC re-check.
    let hits = query_nodes(&mut coord, "doc_vec", &[1.0, 0.0, 0.0], 3);
    let names: Vec<&str> = hits.iter().map(|(n, _)| n.as_str()).collect();
    assert!(
        !names.contains(&"x"),
        "deleted node must be excluded: {hits:?}"
    );
    assert_eq!(names.len(), 2, "the two survivors remain: {hits:?}");
}

#[test]
fn query_nodes_re_check_drops_a_candidate_invisible_to_the_reader_snapshot() {
    let mut coord = fresh_coord();
    seed_docs_and_index(&mut coord);

    // Pin a reader snapshot BEFORE a newer node is created.
    let reader = coord.begin_serializable();
    // Materialise the reader's pid→name map at its snapshot (the newer node will not be in it).
    let pid_to_name: HashMap<u64, String> = read_rows_on(
        &mut coord,
        reader,
        "MATCH (n:Doc) RETURN id(n) AS pid, n.name AS name",
    )
    .iter()
    .map(|r| pid_name(r, "name"))
    .collect();

    // A concurrent writer inserts a node nearest to the query and commits — the shared HNSW now holds
    // it, but the reader's older snapshot cannot see it.
    run_write(
        &mut coord,
        "CREATE (:Doc {name: 'newer', embedding: [1.0, 0.0, 0.0]})",
    );

    // The reader runs the k-NN on its OLD snapshot: the HNSW returns 'newer' as the nearest candidate,
    // but the per-candidate re-check (`node_exists` on the reader's snapshot) drops it. k = 4 requests
    // more candidates than there are visible docs, so the drop leaves exactly the 3 visible ones (with
    // a smaller k the invisible hit would instead push a visible doc past the k cutoff — Neo4j parity).
    let src = "CALL db.index.vector.queryNodes('doc_vec', 4, [1.0, 0.0, 0.0]) YIELD node, score \
               RETURN id(node) AS pid, score";
    let names: Vec<String> = read_rows_on(&mut coord, reader, src)
        .iter()
        .map(|r| {
            let pid = match r.value("pid") {
                Value::Integer(i) => i as u64,
                other => panic!("id(node) must be an integer, got {other:?}"),
            };
            pid_to_name
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| "<invisible>".to_owned())
        })
        .collect();
    let _ = coord.rollback(reader);

    assert!(
        !names.iter().any(|n| n == "newer" || n == "<invisible>"),
        "a candidate invisible to the reader snapshot must be dropped: {names:?}"
    );
    assert_eq!(
        names.len(),
        3,
        "the three snapshot-visible docs remain: {names:?}"
    );
}

#[test]
fn query_nodes_errors_clearly() {
    let mut coord = fresh_coord();
    seed_docs_and_index(&mut coord);

    // Also declare a relationship vector index of a known name for the wrong-kind check.
    run_write(
        &mut coord,
        "CREATE (:P {name: 'a'})-[:SIM {embedding: [1.0, 0.0]}]->(:P {name: 'b'})",
    );
    coord
        .begin_online_vector_index_named(
            Some("rel_vec"),
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

    // Unknown index.
    let e = read_err(
        &mut coord,
        "CALL db.index.vector.queryNodes('missing', 3, [1.0, 0.0, 0.0]) YIELD node RETURN node",
    );
    assert!(
        e.contains("no node vector index named \"missing\""),
        "unknown index: {e}"
    );

    // Wrong kind: a relationship vector index queried through queryNodes.
    let e = read_err(
        &mut coord,
        "CALL db.index.vector.queryNodes('rel_vec', 3, [1.0, 0.0]) YIELD node RETURN node",
    );
    assert!(
        e.contains("relationship vector index") && e.contains("queryRelationships"),
        "wrong kind: {e}"
    );

    // Dimension mismatch: the index is 3-D, the query is 2-D.
    let e = read_err(
        &mut coord,
        "CALL db.index.vector.queryNodes('doc_vec', 3, [1.0, 0.0]) YIELD node RETURN node",
    );
    assert!(
        e.contains("dimension 2") && e.contains("expects 3"),
        "dimension mismatch: {e}"
    );

    // Non-finite query element (NaN via 0.0/0.0).
    let e = read_err(
        &mut coord,
        "CALL db.index.vector.queryNodes('doc_vec', 3, [1.0, 0.0, 0.0/0.0]) YIELD node RETURN node",
    );
    assert!(e.contains("NaN or infinite"), "non-finite query: {e}");

    // Non-positive k.
    let e = read_err(
        &mut coord,
        "CALL db.index.vector.queryNodes('doc_vec', 0, [1.0, 0.0, 0.0]) YIELD node RETURN node",
    );
    assert!(e.contains("positive integer"), "non-positive k: {e}");
}

// =================================================================================================
// db.index.vector.queryRelationships
// =================================================================================================

#[test]
fn query_relationships_returns_k_nearest_by_descending_score() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P)-[:SIM {tag: 'r_x', embedding: [1.0, 0.0]}]->(:P)",
    );
    run_write(
        &mut coord,
        "CREATE (:P)-[:SIM {tag: 'r_y', embedding: [0.0, 1.0]}]->(:P)",
    );
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

    let rid_to_tag: HashMap<u64, String> = read_rows(
        &mut coord,
        "MATCH ()-[r:SIM]->() RETURN id(r) AS pid, r.tag AS tag",
    )
    .iter()
    .map(|r| pid_name(r, "tag"))
    .collect();

    let hits: Vec<(String, f64)> = read_rows(
        &mut coord,
        "CALL db.index.vector.queryRelationships('sim_vec', 2, [1.0, 0.0]) \
         YIELD relationship, score RETURN id(relationship) AS pid, score",
    )
    .iter()
    .map(|r| {
        let pid = match r.value("pid") {
            Value::Integer(i) => i as u64,
            other => panic!("id(relationship) must be an integer, got {other:?}"),
        };
        let score = match r.value("score") {
            Value::Float(f) => f,
            other => panic!("score must be a float, got {other:?}"),
        };
        (rid_to_tag.get(&pid).cloned().unwrap(), score)
    })
    .collect();

    let tags: Vec<&str> = hits.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(tags, vec!["r_x", "r_y"], "nearest-first order");
    assert!(hits[0].1 >= hits[1].1, "descending scores: {hits:?}");
    assert!(
        (hits[0].1 - 1.0).abs() < 1e-6,
        "r_x is an exact match: {hits:?}"
    );
}

#[test]
fn query_relationships_wrong_kind_errors() {
    let mut coord = fresh_coord();
    seed_docs_and_index(&mut coord); // declares the NODE index 'doc_vec'
    let e = read_err(
        &mut coord,
        "CALL db.index.vector.queryRelationships('doc_vec', 3, [1.0, 0.0, 0.0]) \
         YIELD relationship RETURN relationship",
    );
    assert!(
        e.contains("node vector index") && e.contains("queryNodes"),
        "wrong kind: {e}"
    );
}

// =================================================================================================
// vector.similarity.cosine / vector.similarity.euclidean
// =================================================================================================

#[test]
fn similarity_functions_compute_normalized_scores() {
    let mut coord = fresh_coord();

    // Cosine: identical → 1.0; orthogonal → 0.5; opposite → 0.0.
    assert!(
        (scalar_float(
            &mut coord,
            "vector.similarity.cosine([1.0, 2.0], [1.0, 2.0]) "
        ) - 1.0)
            .abs()
            < 1e-6
    );
    assert!(
        (scalar_float(
            &mut coord,
            "vector.similarity.cosine([1.0, 0.0], [0.0, 1.0])"
        ) - 0.5)
            .abs()
            < 1e-6
    );
    assert!(
        scalar_float(
            &mut coord,
            "vector.similarity.cosine([1.0, 0.0], [-1.0, 0.0])"
        )
        .abs()
            < 1e-6
    );
    // Integer elements widen to float (magnitude-independent cosine).
    assert!(
        (scalar_float(&mut coord, "vector.similarity.cosine([3, 4], [6, 8])") - 1.0).abs() < 1e-6
    );

    // Euclidean: squared distance 4 → 1/(1+4) = 0.2; distance 0 → 1.0.
    assert!(
        (scalar_float(&mut coord, "vector.similarity.euclidean([0.0], [2.0]) ") - 0.2).abs() < 1e-6
    );
    assert!(
        (scalar_float(
            &mut coord,
            "vector.similarity.euclidean([1.0, 2.0], [1.0, 2.0])"
        ) - 1.0)
            .abs()
            < 1e-6
    );
}

#[test]
fn similarity_functions_error_and_null_propagate() {
    let mut coord = fresh_coord();

    // A dimension mismatch is a runtime error.
    let e = read_err(
        &mut coord,
        "RETURN vector.similarity.cosine([1.0, 0.0, 0.0], [1.0, 0.0]) AS s",
    );
    assert!(e.contains("same dimension"), "dimension mismatch: {e}");

    // A null operand propagates to null.
    let rows = read_rows(
        &mut coord,
        "RETURN vector.similarity.euclidean(null, [1.0]) AS s",
    );
    assert!(matches!(rows[0].value("s"), Value::Null), "null propagates");
}
