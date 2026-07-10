//! Vector (HNSW) index end-to-end at the coordinator layer (`rmp` task #669, part B): the durable
//! catalog + synchronous online build, per-write maintenance, the `k`-NN seek through the
//! [`IndexSet`], crash recovery (rebuild-on-open), and `IF NOT EXISTS` / `DROP` idempotency.
//!
//! The DDL surface (`CREATE VECTOR INDEX …`) and the query planner seek are `rmp` #671 (parts C/D), so
//! these tests drive the coordinator API directly:
//! [`TxnCoordinator::begin_online_vector_index_named`] to declare, `run_write` to seed embeddings, and
//! [`TxnCoordinator::vector_query_nodes`] / [`vector_query_rels`] to run the ANN seek. The harness
//! mirrors `tests/text_index.rs`: a `TxnCoordinator` over an in-memory store with a `run_write` commit
//! probe and the `recover_no_force` deterministic reopen.
//!
//! The vector index returns **physical** ids (`id(n)` / `id(r)`), so each test builds a
//! `physical id → name` map from a `RETURN id(n) …` read and asserts on the stable `name` tag rather
//! than on the store-assigned physical id order.

use std::collections::HashMap;

use graphus_core::Value;
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
use graphus_index::DEFAULT_EF_SEARCH;
use graphus_io::MemBlockDevice;
use graphus_storage::{IndexState, RecordStore, VectorEntity, VectorSimilarity};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness
// =================================================================================================

fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

fn fresh_coord() -> Coord {
    TxnCoordinator::new(fresh_store())
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
        let _rows: Vec<Row> = {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect")
        };
        graph.take_error()
    };
    assert!(
        captured.is_none(),
        "write {src:?} must succeed: {captured:?}"
    );
    coord.commit(txn).expect("write commits");
}

/// Reads every `:Doc` node's `(physical id, name)` and returns the `physical id → name` map — the
/// bridge from the vector index's physical ids back to the test's stable `name` tags.
fn node_pid_to_name(coord: &mut Coord, label: &str) -> HashMap<u64, String> {
    let src = format!("MATCH (n:{label}) RETURN id(n) AS pid, n.name AS name");
    let plan = compile(&src);
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    coord.commit(txn).expect("read commits");
    rows.iter()
        .map(|r| {
            let pid = match r.value("pid") {
                Value::Integer(i) => i as u64,
                other => panic!("id(n) must be an integer, got {other:?}"),
            };
            let name = match r.value("name") {
                Value::String(s) => s,
                other => panic!("n.name must be a string, got {other:?}"),
            };
            (pid, name)
        })
        .collect()
}

/// The `k` nearest `:Doc` node **names** to `query` in the vector index over `(label, property)`,
/// nearest first — mapping the physical ids the seek returns back through `pid_to_name`.
fn nearest_node_names(
    coord: &mut Coord,
    label: &str,
    property: &str,
    query: &[f32],
    k: usize,
) -> Vec<String> {
    let pid_to_name = node_pid_to_name(coord, label);
    let hits = coord
        .vector_query_nodes(label, property, query, k, DEFAULT_EF_SEARCH)
        .expect("a vector index over (label, property) is registered")
        .expect("the query dimension matches the index");
    hits.into_iter()
        .map(|(pid, _score)| {
            pid_to_name
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| format!("<unknown pid {pid}>"))
        })
        .collect()
}

/// Deterministically reopens `store` from its durable WAL prefix (the recovery probe).
fn recover_no_force(store: &Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

/// Seeds three well-separated 3-D unit embeddings so the nearest neighbour of a query is unambiguous.
fn seed_docs(coord: &mut Coord) {
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
}

// =================================================================================================
// Tests
// =================================================================================================

#[test]
fn vector_index_is_durable_listed_idempotent_queryable_and_survives_reopen() {
    let mut coord = fresh_coord();
    seed_docs(&mut coord);

    // Declare a cosine vector index over the existing data (synchronous, always Online).
    let created = coord
        .begin_online_vector_index_named(
            Some("vec_doc_embedding"),
            VectorEntity::Node,
            "Doc",
            "embedding",
            3,
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect("create vector index");
    assert!(created, "a fresh create mutates");

    // SHOW-source surface: (name, label, property, Online).
    assert_eq!(
        coord.list_vector_indexes(),
        vec![(
            "vec_doc_embedding".to_owned(),
            "Doc".to_owned(),
            "embedding".to_owned(),
            IndexState::Online,
        )],
        "the vector index is Online and covers (Doc, embedding)"
    );

    // The synchronous build indexed the seed nodes: a query near 'x' returns 'x' first.
    assert_eq!(
        nearest_node_names(&mut coord, "Doc", "embedding", &[0.9, 0.1, 0.0], 1),
        vec!["x".to_owned()],
        "the nearest neighbour of ~[1,0,0] is 'x'"
    );
    // k = 3 returns all three, nearest first (query is closest to 'y').
    assert_eq!(
        nearest_node_names(&mut coord, "Doc", "embedding", &[0.1, 0.95, 0.05], 3)[0],
        "y",
        "the nearest neighbour of ~[0,1,0] is 'y'"
    );

    // IF NOT EXISTS equivalence: a re-declare of the same (label, property) errors without the flag…
    let err = coord
        .begin_online_vector_index_named(
            Some("other_name"),
            VectorEntity::Node,
            "Doc",
            "embedding",
            3,
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect_err("an equivalent vector index without IF NOT EXISTS errors");
    assert!(err.to_string().contains("equivalent index"), "{err:?}");
    // …and is an idempotent no-op with it (a different name over the same schema).
    assert!(
        !coord
            .begin_online_vector_index_named(
                Some("other_name"),
                VectorEntity::Node,
                "Doc",
                "embedding",
                3,
                VectorSimilarity::Cosine,
                16,
                200,
                true,
            )
            .expect("IF NOT EXISTS is a clean no-op"),
        "IF NOT EXISTS on an equivalent vector index does not mutate"
    );

    // A name collision with a DIFFERENT catalog errors: reuse the vector name for a range index.
    let err = coord
        .begin_online_node_property_index_named(Some("vec_doc_embedding"), "Doc", "title", false)
        .expect_err("a cross-catalog name collision errors");
    assert!(err.to_string().contains("named"), "{err:?}");

    // Crash + reopen: the durable catalog reload re-registers and rebuilds the HNSW graph from the store.
    let store = coord.into_store();
    assert_eq!(
        store.vector_indexes().len(),
        1,
        "the vector registration survives the reopen (durable catalog)"
    );
    let reopened = recover_no_force(&store);
    let mut coord2 = TxnCoordinator::new(reopened);
    assert_eq!(
        coord2.list_vector_indexes(),
        vec![(
            "vec_doc_embedding".to_owned(),
            "Doc".to_owned(),
            "embedding".to_owned(),
            IndexState::Online,
        )],
        "the vector index is fully recovered Online after reopen"
    );

    // The rebuilt index still serves the seek…
    assert_eq!(
        nearest_node_names(&mut coord2, "Doc", "embedding", &[0.0, 0.05, 0.95], 1),
        vec!["z".to_owned()],
        "the rebuilt index still finds 'z' nearest to ~[0,0,1]"
    );
    // …and a post-recovery write is maintained by the rebuilt index (a near-duplicate of 'x').
    run_write(
        &mut coord2,
        "CREATE (:Doc {name: 'x2', embedding: [0.99, 0.01, 0.0]})",
    );
    let top2 = nearest_node_names(&mut coord2, "Doc", "embedding", &[1.0, 0.0, 0.0], 2);
    assert!(
        top2.contains(&"x".to_owned()) && top2.contains(&"x2".to_owned()),
        "the post-recovery write is maintained by the rebuilt vector index: {top2:?}"
    );
}

#[test]
fn malformed_embeddings_are_skipped_not_errored() {
    let mut coord = fresh_coord();
    // Good embeddings, plus rows the index must skip: wrong length, non-list, and absent property.
    run_write(
        &mut coord,
        "CREATE (:Doc {name: 'ok1', embedding: [1.0, 0.0, 0.0]})",
    );
    run_write(
        &mut coord,
        "CREATE (:Doc {name: 'ok2', embedding: [0.0, 1.0, 0.0]})",
    );
    run_write(
        &mut coord,
        "CREATE (:Doc {name: 'short', embedding: [1.0, 0.0]})", // wrong length (dim 3 expected)
    );
    run_write(
        &mut coord,
        "CREATE (:Doc {name: 'scalar', embedding: 42})", // not a list
    );
    run_write(&mut coord, "CREATE (:Doc {name: 'absent'})"); // no embedding at all

    // Declaring over the mixed data must NOT error; the malformed rows are simply not indexed.
    let created = coord
        .begin_online_vector_index_named(
            None, // auto-name → vector_index_Doc_embedding
            VectorEntity::Node,
            "Doc",
            "embedding",
            3,
            VectorSimilarity::Euclidean,
            16,
            200,
            false,
        )
        .expect("create over mixed data does not error");
    assert!(created);
    assert_eq!(
        coord.list_vector_indexes()[0].0,
        "vector_index_Doc_embedding",
        "the omitted name is auto-generated deterministically"
    );

    // Only the two well-formed embeddings are candidates; a k = 5 query returns exactly them.
    let names = nearest_node_names(&mut coord, "Doc", "embedding", &[1.0, 0.0, 0.0], 5);
    assert_eq!(
        names.len(),
        2,
        "only the two valid embeddings are indexed: {names:?}"
    );
    assert!(names.contains(&"ok1".to_owned()) && names.contains(&"ok2".to_owned()));
    assert_eq!(names[0], "ok1", "'ok1' is nearest to [1,0,0]");

    // A post-declare write with a good embedding is indexed; a malformed one stays out.
    run_write(
        &mut coord,
        "CREATE (:Doc {name: 'ok3', embedding: [0.0, 0.0, 1.0]})",
    );
    run_write(
        &mut coord,
        "CREATE (:Doc {name: 'bad', embedding: ['a', 'b', 'c']})", // list of non-numbers
    );
    let names = nearest_node_names(&mut coord, "Doc", "embedding", &[0.0, 0.0, 1.0], 5);
    assert_eq!(names.len(), 3, "ok3 joins; 'bad' is skipped: {names:?}");
    assert!(names.contains(&"ok3".to_owned()));
    assert!(!names.contains(&"bad".to_owned()));
}

#[test]
fn drop_vector_index_removes_it_and_ddl_is_idempotent() {
    let mut coord = fresh_coord();
    seed_docs(&mut coord);
    coord
        .begin_online_vector_index_named(
            Some("vec_doc_embedding"),
            VectorEntity::Node,
            "Doc",
            "embedding",
            3,
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect("create vector index");
    assert_eq!(coord.list_vector_indexes().len(), 1);

    // DROP removes it (durable + in-memory); the seek no longer finds an index.
    assert!(
        coord
            .drop_vector_index("vec_doc_embedding", false)
            .expect("drop"),
        "dropping an existing index mutates"
    );
    assert!(coord.list_vector_indexes().is_empty());
    assert!(
        coord
            .vector_query_nodes("Doc", "embedding", &[1.0, 0.0, 0.0], 1, DEFAULT_EF_SEARCH)
            .is_none(),
        "after DROP no vector index answers the seek"
    );

    // A second DROP of the now-missing index errors without IF EXISTS and is a no-op with it.
    assert!(
        coord.drop_vector_index("vec_doc_embedding", false).is_err(),
        "dropping a missing index without IF EXISTS errors"
    );
    assert!(
        !coord
            .drop_vector_index("vec_doc_embedding", true)
            .expect("IF EXISTS is a clean no-op"),
        "dropping a missing index with IF EXISTS does not mutate"
    );
}

#[test]
fn zero_dimension_is_rejected() {
    let mut coord = fresh_coord();
    let err = coord
        .begin_online_vector_index_named(
            Some("bad_dim"),
            VectorEntity::Node,
            "Doc",
            "embedding",
            0, // meaningless
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect_err("a zero-dimension vector index is rejected");
    assert!(err.to_string().contains("greater than zero"), "{err:?}");
    assert!(
        coord.list_vector_indexes().is_empty(),
        "the rejected index is left undeclared"
    );
}

#[test]
fn relationship_vector_index_end_to_end() {
    let mut coord = fresh_coord();
    // A tiny graph of :SIMILAR relationships each carrying an embedding.
    run_write(
        &mut coord,
        "CREATE (:P {name: 'a'})-[:SIMILAR {name: 'r1', vec: [1.0, 0.0, 0.0]}]->(:P {name: 'b'})",
    );
    run_write(
        &mut coord,
        "CREATE (:P {name: 'c'})-[:SIMILAR {name: 'r2', vec: [0.0, 1.0, 0.0]}]->(:P {name: 'd'})",
    );

    let created = coord
        .begin_online_vector_index_named(
            Some("vec_similar"),
            VectorEntity::Relationship,
            "SIMILAR",
            "vec",
            3,
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect("create relationship vector index");
    assert!(created);
    assert_eq!(
        coord.list_vector_rel_indexes(),
        vec![(
            "vec_similar".to_owned(),
            "SIMILAR".to_owned(),
            "vec".to_owned(),
            IndexState::Online,
        )],
        "the relationship vector index is Online over (SIMILAR, vec)"
    );
    // A node vector index over the same numeric tokens must NOT be conflated (separate maps + entity).
    assert!(
        coord.list_vector_indexes().is_empty(),
        "the relationship index is not listed as a node index"
    );

    // Map r-name → physical rel id, then run the rel k-NN seek.
    let rid_to_name: HashMap<u64, String> = {
        let plan = compile("MATCH ()-[r:SIMILAR]->() RETURN id(r) AS rid, r.name AS name");
        let txn = coord.begin_serializable();
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let rows = {
            let mut graph = coord.statement(txn).expect("statement");
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect")
        };
        coord.commit(txn).expect("read commits");
        rows.iter()
            .map(|r| {
                let rid = match r.value("rid") {
                    Value::Integer(i) => i as u64,
                    other => panic!("id(r) must be an integer, got {other:?}"),
                };
                let name = match r.value("name") {
                    Value::String(s) => s,
                    other => panic!("r.name must be a string, got {other:?}"),
                };
                (rid, name)
            })
            .collect()
    };

    let hits = coord
        .vector_query_rels("SIMILAR", "vec", &[0.9, 0.1, 0.0], 1, DEFAULT_EF_SEARCH)
        .expect("a relationship vector index is registered")
        .expect("query dimension matches");
    let nearest = rid_to_name
        .get(&hits[0].0)
        .cloned()
        .expect("the hit maps back to a known relationship");
    assert_eq!(nearest, "r1", "the nearest relationship to ~[1,0,0] is r1");

    // Reopen: the relationship vector index rebuilds from the store and still serves the seek, and a
    // post-recovery relationship write is maintained.
    let store = coord.into_store();
    let reopened = recover_no_force(&store);
    let coord2 = TxnCoordinator::new(reopened);
    assert_eq!(coord2.list_vector_rel_indexes().len(), 1);
    let hits = coord2
        .vector_query_rels("SIMILAR", "vec", &[0.0, 0.9, 0.1], 1, DEFAULT_EF_SEARCH)
        .expect("registered after reopen")
        .expect("dimension matches");
    assert_eq!(
        hits.len(),
        1,
        "the rebuilt relationship vector index answers the seek with k = 1"
    );
}

#[test]
fn catalog_surfaces_online_vector_indexes() {
    // The #659 trap: `catalog()` must surface the Online vector index so the planner (#671) can see it.
    let mut coord = fresh_coord();
    seed_docs(&mut coord);
    assert!(
        !coord
            .catalog()
            .indexes()
            .iter()
            .any(|d| d.kind.tag() == "vector"),
        "no vector index yet"
    );
    coord
        .begin_online_vector_index_named(
            Some("vec_doc_embedding"),
            VectorEntity::Node,
            "Doc",
            "embedding",
            3,
            VectorSimilarity::Cosine,
            16,
            200,
            false,
        )
        .expect("create vector index");
    let catalog = coord.catalog();
    let descriptor = catalog
        .indexes()
        .iter()
        .find(|d| d.kind.tag() == "vector")
        .expect("the Online vector index is surfaced in the planner catalog");
    assert_eq!(descriptor.target.as_label(), Some("Doc"));
    assert_eq!(descriptor.properties, vec!["embedding".to_owned()]);

    // After DROP the catalog no longer surfaces it.
    coord.drop_vector_index("vec_doc_embedding", false).unwrap();
    assert!(
        !coord
            .catalog()
            .indexes()
            .iter()
            .any(|d| d.kind.tag() == "vector"),
        "after DROP the vector index is no longer surfaced"
    );
}
