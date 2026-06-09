//! End-to-end tests for [`RecordStoreGraph`] — the Cypher executor running over the **real**
//! persistent record store (`04-technical-design.md` §2, §7.4; `rmp` task #38).
//!
//! These tests run the full pipeline (`parse → semantic analysis → physical plan → execute`) against
//! a [`RecordStoreGraph`] wrapping a real [`graphus_storage::RecordStore`] over an in-memory DST
//! device + log. They prove the achievable subset (#38 + #42): MATCH / traversal / inline scalar
//! property filter / aggregation / `CREATE`/`SET`/`DELETE`, **node labels** (`CREATE (:L)`, `n:L`
//! predicates, `labels(n)`, label scans, `SET`/`REMOVE` label — `rmp` task #42), the
//! same-query-both-backends equivalence against the reference [`MemGraph`], crash-recovery
//! durability (including labels), and that every #39 deferral is signalled by a captured error
//! rather than a wrong answer.
//!
//! Property values here are restricted to the **inline scalar** classes (`Integer`/`Float`/
//! `Boolean`) the store can encode in this build; string/list/map/temporal property values are
//! deferred to #39 and are exercised here only to prove they signal an error. Node labels use the
//! inline label bitmap (`05 §9`); a label needing token id `≥ 63` (a 64th distinct label) is the
//! documented overflow deferral (#39's token-list block) and is exercised to prove it errors.

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::MemGraph;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::record_graph::RecordStoreGraph;
use graphus_cypher::runtime::{Row, RowValue, row_bindings};
use graphus_cypher::semantics::analyze;
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_storage::RecordStore;
use graphus_storage::recovery::recover_device;
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness
// =================================================================================================

/// A fresh, empty record store over an in-memory DST device + log.
fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

/// Compiles `src` and runs it over `store` inside one transaction `txn`, asserting **no** deferred
/// error was captured, committing, and returning `(rows, store)`.
///
/// This is the production path the orchestration layer will use: wrap the store, execute, check the
/// captured-error cell, then commit (or roll back on error).
fn run_commit(src: &str, store: Store, txn: u64) -> (Vec<Row>, Store) {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = RecordStoreGraph::begin(store, TxnId(txn));
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect rows")
    };
    assert!(
        !graph.has_error(),
        "unexpected captured error: {:?}",
        graph.take_error()
    );
    let store = graph.commit().expect("commit");
    (rows, store)
}

/// Compiles `src` to a physical plan against the empty index catalog.
fn compile(src: &str) -> graphus_cypher::physical::PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs `src` over `store` and returns only the captured deferred/storage error (rolling the
/// transaction back). Panics if no error was captured.
fn run_expect_error(src: &str, store: Store, txn: u64) -> graphus_core::error::GraphusError {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = RecordStoreGraph::begin(store, TxnId(txn));
    {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        let _ = cursor.collect_all();
    }
    let err = graph
        .take_error()
        .expect("expected a captured deferred/storage error");
    let _ = txn;
    graph.rollback().expect("rollback");
    err
}

fn i(n: i64) -> Value {
    Value::Integer(n)
}

/// Extracts a single named column from rows as a `Vec<Value>` (property-valued columns).
fn col(rows: &[Row], name: &str) -> Vec<Value> {
    rows.iter().map(|r| r.value(name)).collect()
}

/// Seeds a small inline-scalar graph via Cypher `CREATE` over the real store and commits it:
/// three nodes with an integer `n` property, chained `a -[:LINK]-> b -[:LINK]-> c`.
///
/// Returns the store positioned after the seed commit. Labels and **relationship properties** are
/// omitted — both are #39 (the store has no label-set nor relationship-property API yet).
fn seed_chain() -> Store {
    let store = fresh_store();
    // A single connected path pattern so the executor threads the relationships through the *same*
    // newly-created nodes (a comma-separated form re-mentioning `(a)` would create fresh anonymous
    // nodes — a CREATE-variable-reuse quirk shared by both backends, out of scope for #38).
    let src = "CREATE (a {n: 1})-[:LINK]->(b {n: 2})-[:LINK]->(c {n: 3})";
    let (_rows, store) = run_commit(src, store, 1);
    store
}

// =================================================================================================
// CREATE + MATCH + property read over the real store
// =================================================================================================

#[test]
fn create_then_match_all_nodes_over_real_store() {
    let store = fresh_store();
    let (created, store) = run_commit("CREATE (a {n: 1}), (b {n: 2}) RETURN a.n AS x", store, 1);
    // CREATE ... RETURN yields one row per driving row (one here): a.n.
    assert_eq!(col(&created, "x"), vec![i(1)]);

    // A fresh transaction sees the committed nodes.
    let (rows, _store) = run_commit("MATCH (n) RETURN n.n AS v", store, 2);
    let mut vs = col(&rows, "v");
    vs.sort_by_key(|v| match v {
        Value::Integer(k) => *k,
        _ => i64::MAX,
    });
    assert_eq!(vs, vec![i(1), i(2)]);
}

#[test]
fn inline_scalar_properties_round_trip_through_storage() {
    let store = fresh_store();
    let src = "CREATE (n {i: 42, f: 1.5, b: true}) RETURN n.i AS i, n.f AS f, n.b AS b";
    let (rows, store) = run_commit(src, store, 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("i"), Value::Integer(42));
    assert_eq!(rows[0].value("f"), Value::Float(1.5));
    assert_eq!(rows[0].value("b"), Value::Boolean(true));

    // The values survive a re-read in a new transaction (they are really persisted).
    let (rows, _store) = run_commit("MATCH (n) RETURN n.i AS i, n.f AS f, n.b AS b", store, 2);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("i"), Value::Integer(42));
    assert_eq!(rows[0].value("f"), Value::Float(1.5));
    assert_eq!(rows[0].value("b"), Value::Boolean(true));
}

// =================================================================================================
// Traversal (expand) over the real index-free adjacency
// =================================================================================================

#[test]
fn directed_traversal_with_type_filter() {
    let store = seed_chain();
    // a -> b: the only LINK out of the node with n = 1 reaches the node with n = 2.
    let (rows, _store) = run_commit(
        "MATCH (a)-[:LINK]->(b) WHERE a.n = 1 RETURN b.n AS bn",
        store,
        2,
    );
    assert_eq!(col(&rows, "bn"), vec![i(2)]);
}

#[test]
fn traversal_relationship_property_is_deferred_but_structure_works() {
    let store = seed_chain();
    // The traversal itself (structure + endpoints) works; we read endpoint *node* properties, not
    // the relationship property (which is #39).
    let (rows, _store) = run_commit(
        "MATCH (a)-[:LINK]->(b) RETURN a.n AS an, b.n AS bn",
        store,
        2,
    );
    let mut pairs: Vec<(i64, i64)> = rows
        .iter()
        .map(|r| {
            let Value::Integer(a) = r.value("an") else {
                panic!("an not int")
            };
            let Value::Integer(b) = r.value("bn") else {
                panic!("bn not int")
            };
            (a, b)
        })
        .collect();
    pairs.sort_unstable();
    assert_eq!(pairs, vec![(1, 2), (2, 3)]);
}

// =================================================================================================
// Filter / ORDER BY / LIMIT / aggregation over inline scalar properties
// =================================================================================================

#[test]
fn filter_order_limit_over_real_store() {
    let store = fresh_store();
    let (_r, store) = run_commit("CREATE ({n: 5}), ({n: 1}), ({n: 9}), ({n: 3})", store, 1);
    let (rows, _store) = run_commit(
        "MATCH (x) WHERE x.n > 2 RETURN x.n AS n ORDER BY n DESC LIMIT 2",
        store,
        2,
    );
    assert_eq!(col(&rows, "n"), vec![i(9), i(5)]);
}

#[test]
fn aggregation_over_real_store() {
    let store = fresh_store();
    let (_r, store) = run_commit("CREATE ({n: 10}), ({n: 20}), ({n: 30})", store, 1);
    let (rows, _store) = run_commit(
        "MATCH (x) RETURN count(*) AS c, sum(x.n) AS s, avg(x.n) AS a, min(x.n) AS mn, max(x.n) AS mx",
        store,
        2,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("c"), i(3));
    assert_eq!(rows[0].value("s"), i(60));
    assert_eq!(rows[0].value("a"), Value::Float(20.0));
    assert_eq!(rows[0].value("mn"), i(10));
    assert_eq!(rows[0].value("mx"), i(30));
}

// =================================================================================================
// SET + DELETE over the real store
// =================================================================================================

#[test]
fn set_inline_property_then_read_back() {
    let store = fresh_store();
    let (_r, store) = run_commit("CREATE ({n: 1})", store, 1);
    let (_r, store) = run_commit("MATCH (x) SET x.n = 99", store, 2);
    let (rows, _store) = run_commit("MATCH (x) RETURN x.n AS n", store, 3);
    // Newest-wins: the SET added a newer property record that shadows the original.
    assert_eq!(col(&rows, "n"), vec![i(99)]);
}

#[test]
fn detach_delete_removes_node_and_edges() {
    let store = seed_chain();
    // Detach-delete the middle node (n = 2): its two LINK edges go with it.
    let (_r, store) = run_commit("MATCH (b) WHERE b.n = 2 DETACH DELETE b", store, 2);
    let (rows, store) = run_commit("MATCH (n) RETURN n.n AS v", store, 3);
    let mut vs = col(&rows, "v");
    vs.sort_by_key(|v| match v {
        Value::Integer(k) => *k,
        _ => i64::MAX,
    });
    assert_eq!(vs, vec![i(1), i(3)]);
    // No edge remains (both LINKs were incident to the deleted node).
    let (edges, _store) = run_commit("MATCH ()-[r]->() RETURN r", store, 4);
    assert!(edges.is_empty(), "all edges should be gone, got {edges:?}");
}

// =================================================================================================
// Same query, both backends — RecordStoreGraph matches the MemGraph reference
// =================================================================================================

/// Runs `src` over a `MemGraph` seeded by `seed_mem` and returns the rows as order-independent
/// binding maps (so the comparison ignores row order, which the two backends may differ on).
fn rows_over_mem(
    src: &str,
    seed_mem: impl FnOnce(&mut MemGraph),
) -> Vec<std::collections::BTreeMap<String, RowValue>> {
    let mut g = MemGraph::new();
    seed_mem(&mut g);
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let rows = execute(&plan, &bound, &mut g)
        .expect("open")
        .collect_all()
        .expect("rows");
    rows.iter().map(row_bindings).collect()
}

#[test]
fn same_query_matches_memgraph_reference() {
    // A label-free query exercising scan + filter + traversal + projection over inline scalars.
    let query = "MATCH (a)-[:LINK]->(b) WHERE a.n < b.n RETURN a.n AS an, b.n AS bn";

    // Reference backend: build the identical graph directly in MemGraph (label-free, inline props).
    let mem = rows_over_mem(query, |g| {
        let a = g.add_node([] as [&str; 0], [("n", i(1))]);
        let b = g.add_node([] as [&str; 0], [("n", i(2))]);
        let c = g.add_node([] as [&str; 0], [("n", i(3))]);
        g.add_rel("LINK", a, b, [] as [(&str, Value); 0]);
        g.add_rel("LINK", b, c, [] as [(&str, Value); 0]);
    });

    // Real backend: the same graph seeded via Cypher CREATE over the record store.
    let store = seed_chain();
    let (rows, _store) = run_commit(query, store, 2);
    let real: Vec<_> = rows.iter().map(row_bindings).collect();

    // Order-independent multiset comparison (sort each side by a stable key).
    let key = |m: &std::collections::BTreeMap<String, RowValue>| {
        let an = m.get("an").and_then(RowValue::as_value).cloned();
        let bn = m.get("bn").and_then(RowValue::as_value).cloned();
        format!("{an:?}|{bn:?}")
    };
    let mut mem_sorted = mem.clone();
    mem_sorted.sort_by_key(key);
    let mut real_sorted = real.clone();
    real_sorted.sort_by_key(key);

    assert_eq!(
        real_sorted, mem_sorted,
        "RecordStoreGraph must produce the same rows as the MemGraph reference"
    );
    // Sanity: the query actually returns rows (1->2 and 2->3).
    assert_eq!(real_sorted.len(), 2);
}

// =================================================================================================
// Node labels over the real store (`rmp` task #42)
// =================================================================================================

/// Extracts a single named column as a `Vec<RowValue>` (for non-property columns like `labels(n)`).
fn col_row(rows: &[Row], name: &str) -> Vec<RowValue> {
    rows.iter()
        .map(|r| row_bindings(r).get(name).cloned().expect("column present"))
        .collect()
}

#[test]
fn create_labelled_node_then_match_by_label() {
    let store = fresh_store();
    let (_r, store) = run_commit("CREATE (:Person {n: 1})", store, 1);
    // A label-free node so the scan must discriminate.
    let (_r, store) = run_commit("CREATE ({n: 2})", store, 2);

    let (rows, store) = run_commit("MATCH (n:Person) RETURN n.n AS v", store, 3);
    assert_eq!(col(&rows, "v"), vec![i(1)], "only the :Person node matches");

    // A node without the label is not returned by the label scan.
    let (rows, _store) = run_commit("MATCH (n:NoSuch) RETURN n.n AS v", store, 4);
    assert!(rows.is_empty(), "an uninterned label matches nothing");
}

#[test]
fn multi_label_node_matches_each_label_and_conjunctions() {
    let store = fresh_store();
    let (_r, store) = run_commit("CREATE (n:A:B {n: 1})", store, 1);

    // MATCH (n:A) and MATCH (n:B) both find it.
    let (ra, store) = run_commit("MATCH (n:A) RETURN n.n AS v", store, 2);
    assert_eq!(col(&ra, "v"), vec![i(1)]);
    let (rb, store) = run_commit("MATCH (n:B) RETURN n.n AS v", store, 3);
    assert_eq!(col(&rb, "v"), vec![i(1)]);

    // n:A AND n:B is true; n:A AND n:C is false (no :C label).
    let (rab, store) = run_commit("MATCH (n:A) WHERE n:B RETURN n.n AS v", store, 4);
    assert_eq!(col(&rab, "v"), vec![i(1)]);
    let (rac, store) = run_commit("MATCH (n:A) WHERE n:C RETURN n.n AS v", store, 5);
    assert!(rac.is_empty(), "n:A AND n:C must be false");

    // labels(n) returns both names (the executor's labels() maps token ids back to names).
    let (rl, _store) = run_commit("MATCH (n:A) RETURN labels(n) AS ls", store, 6);
    assert_eq!(
        col_row(&rl, "ls"),
        vec![RowValue::Value(Value::List(vec![
            Value::String("A".to_owned()),
            Value::String("B".to_owned()),
        ]))],
        "labels(n) returns the node's label names"
    );
}

#[test]
fn set_label_adds_it_and_remove_label_clears_it() {
    let store = fresh_store();
    let (_r, store) = run_commit("CREATE (:A {n: 1})", store, 1);

    // SET n:NewLabel adds it; a later MATCH finds it.
    let (_r, store) = run_commit("MATCH (n:A) SET n:NewLabel", store, 2);
    let (rows, store) = run_commit("MATCH (n:NewLabel) RETURN n.n AS v", store, 3);
    assert_eq!(col(&rows, "v"), vec![i(1)]);

    // REMOVE n:A removes it; a later MATCH (n:A) no longer finds it, but :NewLabel still does.
    let (_r, store) = run_commit("MATCH (n:NewLabel) REMOVE n:A", store, 4);
    let (gone, store) = run_commit("MATCH (n:A) RETURN n.n AS v", store, 5);
    assert!(gone.is_empty(), "REMOVE n:A must clear the :A label");
    let (still, _store) = run_commit("MATCH (n:NewLabel) RETURN n.n AS v", store, 6);
    assert_eq!(col(&still, "v"), vec![i(1)], ":NewLabel must remain");
}

#[test]
fn labelled_query_matches_memgraph_reference() {
    // Both-backends-identical for a labelled query: scan by label + conjunction + labels().
    let query = "MATCH (n:Person) WHERE n:Admin RETURN n.n AS v, labels(n) AS ls";

    let mem = rows_over_mem(query, |g| {
        g.add_node(["Person", "Admin"], [("n", i(1))]);
        g.add_node(["Person"], [("n", i(2))]); // not :Admin
        g.add_node(["Admin"], [("n", i(3))]); // not :Person
    });

    let store = fresh_store();
    let (_r, store) = run_commit("CREATE (:Person:Admin {n: 1})", store, 1);
    let (_r, store) = run_commit("CREATE (:Person {n: 2})", store, 2);
    let (_r, store) = run_commit("CREATE (:Admin {n: 3})", store, 3);
    let (rows, _store) = run_commit(query, store, 4);
    let real: Vec<_> = rows.iter().map(row_bindings).collect();

    assert_eq!(
        real, mem,
        "labelled query must match the MemGraph reference"
    );
    assert_eq!(real.len(), 1, "only the :Person:Admin node matches");
}

#[test]
fn overflow_label_is_a_documented_deferred_error() {
    // Force a label whose Label-namespace token id is >= 63: intern 63 distinct labels (ids 0..=62)
    // on a node, then a 64th distinct label (id 63) overflows the inline bitmap (#39's token-list
    // block). It must be a captured, documented error — not a wrong answer or a panic.
    let store = fresh_store();
    // Create one node carrying labels L0..L62 (63 labels = token ids 0..=62, all inline).
    let inline: String = (0..63)
        .map(|k| format!(":L{k}"))
        .collect::<Vec<_>>()
        .join("");
    let (_r, store) = run_commit(&format!("CREATE (n{inline} {{n: 1}})"), store, 1);
    // Sanity: those 63 labels are all readable.
    let (rows, store) = run_commit("MATCH (n:L0) WHERE n:L62 RETURN labels(n) AS ls", store, 2);
    assert_eq!(rows.len(), 1);

    // The 64th distinct label (L63 -> token id 63) overflows.
    let err = run_expect_error("MATCH (n:L0) SET n:L63", store, 3);
    let msg = err.to_string();
    assert!(
        msg.contains("#39") && msg.contains("overflow"),
        "overflowing label must signal the documented deferred error, got: {msg}"
    );
}

#[test]
fn committed_labels_survive_a_no_force_crash() {
    // Create + commit a labelled node via Cypher, crash, recover, and MATCH by label still finds it.
    let store = fresh_store();
    let (_r, store) = run_commit("CREATE (:Person:Admin {n: 7})", store, 1);

    let recovered = recover_no_force(&store);
    let (rows, store) = run_commit("MATCH (n:Person) RETURN n.n AS v", recovered, 100);
    assert_eq!(col(&rows, "v"), vec![i(7)], "label survives recovery");

    // labels() still returns both names after recovery.
    let (rl, _store) = run_commit("MATCH (n:Admin) RETURN labels(n) AS ls", store, 101);
    assert_eq!(
        col_row(&rl, "ls"),
        vec![RowValue::Value(Value::List(vec![
            Value::String("Admin".to_owned()),
            Value::String("Person".to_owned()),
        ]))]
    );
}

// =================================================================================================
// Crash recovery: committed-via-Cypher data survives; uncommitted does not
// =================================================================================================

/// The durable WAL bytes of a store (its group-committed log prefix).
fn durable_log(store: &Store) -> Vec<u8> {
    store.with_wal(|w| w.sink().durable_bytes().to_vec())
}

/// Recovers a *no-force* crash: replay the durable WAL onto a fresh empty device, then open.
fn recover_no_force(store: &Store) -> Store {
    let log = durable_log(store);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");

    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

/// Recovers a *steal* crash: flush the store's (committed + uncommitted) dirty pages to a disk
/// image, then replay the WAL over it so uncommitted work is rolled back.
fn recover_steal(store: &mut Store) -> Store {
    store.flush().expect("flush (steal)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    {
        let mut staged: Vec<(u64, Box<Page>)> = Vec::new();
        for p in &pages {
            staged.push((p.0, store.read_device_page(*p).expect("read device page")));
        }
        for (idx, bytes) in staged {
            device
                .write_page(graphus_core::PageId(idx), &bytes)
                .expect("stage page");
        }
        device.sync_all().expect("persist disk image");
    }
    let log = durable_log(store);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

#[test]
fn committed_cypher_writes_survive_a_no_force_crash() {
    // Create + commit a graph via Cypher.
    let store = seed_chain();

    // Crash (device + log) and recover from the WAL alone.
    let recovered = recover_no_force(&store);

    // A MATCH after recovery returns the committed data.
    let (rows, _store) = run_commit("MATCH (n) RETURN n.n AS v", recovered, 100);
    let mut vs = col(&rows, "v");
    vs.sort_by_key(|v| match v {
        Value::Integer(k) => *k,
        _ => i64::MAX,
    });
    assert_eq!(vs, vec![i(1), i(2), i(3)]);

    // The committed edges survived too.
    let store2 = seed_chain();
    let recovered2 = recover_no_force(&store2);
    let (edges, _store) = run_commit(
        "MATCH (a)-[:LINK]->(b) RETURN a.n AS an, b.n AS bn",
        recovered2,
        101,
    );
    assert_eq!(edges.len(), 2, "both committed LINK edges survive recovery");
}

#[test]
fn uncommitted_cypher_writes_do_not_survive_a_crash() {
    // Committed baseline: one node n = 1.
    let store = fresh_store();
    let (_r, mut store) = run_commit("CREATE ({n: 1})", store, 1);

    // A second transaction creates a node but is NOT committed; harden its tail so the crash log
    // carries it (forcing undo to run), then crash with steal (its dirty pages on disk).
    {
        let plan = compile("CREATE ({n: 2})");
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let mut graph = RecordStoreGraph::begin(store, TxnId(2));
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open");
            let _ = cursor.collect_all().expect("rows");
        }
        assert!(!graph.has_error());
        // Reclaim the store WITHOUT committing txn 2 (it is a loser). Harden its WAL tail so the
        // crash log carries its records, forcing recovery's undo to roll it back.
        store = graph.into_store();
        store.with_wal(graphus_wal::WalManager::flush);
    }

    let recovered = recover_steal(&mut store);
    let (rows, _store) = run_commit("MATCH (n) RETURN n.n AS v", recovered, 100);
    // Only the committed node survives; the uncommitted one is rolled back by recovery's undo.
    assert_eq!(col(&rows, "v"), vec![i(1)]);
}

// =================================================================================================
// Deferred-to-#39 surfaces signal an error, never a wrong answer
// =================================================================================================

#[test]
fn string_property_value_is_a_deferred_error() {
    let store = fresh_store();
    let err = run_expect_error("CREATE (n {name: 'Ada'})", store, 1);
    let msg = err.to_string();
    assert!(
        msg.contains("strings") || msg.contains("overflow") || msg.contains("#39"),
        "string property must signal the deferred-overflow error, got: {msg}"
    );
}

#[test]
fn list_property_value_is_a_deferred_error() {
    let store = fresh_store();
    let err = run_expect_error("CREATE (n {tags: [1, 2, 3]})", store, 1);
    assert!(
        err.to_string().contains("#39") || err.to_string().contains("overflow"),
        "list property must signal a deferred error, got: {err}"
    );
}

#[test]
fn set_property_to_null_removal_is_a_deferred_error() {
    let store = fresh_store();
    let (_r, store) = run_commit("CREATE ({n: 1})", store, 1);
    let err = run_expect_error("MATCH (x) SET x.n = null", store, 2);
    assert!(
        err.to_string().contains("#39"),
        "property removal must signal a deferred error, got: {err}"
    );
}
