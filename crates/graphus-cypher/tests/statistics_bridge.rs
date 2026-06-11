//! End-to-end tests for the **storage statistics bridge** (`rmp` task #81, Stage 3b): the real
//! [`RecordStoreGraph`] surfaces the store's durable catalogue counts and per-indexed-property
//! equi-depth histograms to the cardinality estimator through the [`Statistics`] seam, and offers an
//! on-demand `ANALYZE` recompute path
//! ([`RecordStoreGraph::recompute_property_histogram`](graphus_cypher::record_graph::RecordStoreGraph::recompute_property_histogram)).
//!
//! The tests prove, over a real WAL-logged store (an in-memory DST device + log):
//!
//! * **Counts bridge** — `total_nodes` / `nodes_with_label` / `total_relationships` /
//!   `relationships_with_type` match a known seeded distribution, sourced from the durable catalogue
//!   counts (`rmp` tasks #79/#82), not a snapshot scan.
//! * **Histogram selectivity, end-to-end** — after `ANALYZE`, planning `MATCH (n:Person) WHERE
//!   n.age = K` / `>= K` **with stats** yields an estimate that tracks the true filtered count and is
//!   clearly different from the no-stats constant fallback, proving the histogram path fired through
//!   [`plan_physical_with_stats`].
//! * **Persistence** — the histogram survives a crash + WAL recovery; a fresh
//!   [`RecordStoreGraph`] over the recovered store still produces an informed estimate.
//! * **Fallback** — a property never `ANALYZE`d returns `None` from the seam, so the planner uses the
//!   constant fallback (the estimate equals the no-stats estimate for that predicate).

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::GraphAccess;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical, plan_physical_with_stats};
use graphus_cypher::record_graph::RecordStoreGraph;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
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

/// Compiles `src` to a physical plan against the empty index catalog (no index seeks; the statistics
/// path under test is orthogonal to index selection).
fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Lowers `src` to a **logical** plan (the cardinality estimator's input).
fn lower_query(src: &str) -> graphus_cypher::logical::LogicalOp {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    lower(&validated)
}

/// Compiles `src` and runs it over `store` inside transaction `txn`, asserting no captured error,
/// committing, and returning `(rows, store)`. The production write/read path.
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

/// The durable WAL bytes of a store (its group-committed log prefix).
fn durable_log(store: &Store) -> Vec<u8> {
    store.with_wal(|w| w.sink().durable_bytes().to_vec())
}

/// Recovers a *no-force* crash: replay the durable WAL onto a fresh empty device, then open. Mirrors
/// `tests/record_store_graph.rs::recover_no_force`.
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

/// Seeds the canonical distribution and commits it: 100 `:Person` with `age` spread over `0..100`
/// (every value distinct), 10 `:Company`, and 9 `:KNOWS` Person→Person relationships. Returns the
/// store positioned after the seed commit.
///
/// The nodes are created one statement at a time so the durable per-label / grand-total counts and
/// the `age` values are exactly known to the assertions below. (`UNWIND range(...)` would be denser,
/// but per-statement `CREATE` keeps the seed transparent and is plenty fast for 100 rows.)
fn seed_known_distribution() -> Store {
    let mut store = fresh_store();
    let mut txn = 1u64;
    for age in 0..100 {
        let src = format!("CREATE (:Person {{age: {age}}})");
        let (_r, s) = run_commit(&src, store, txn);
        store = s;
        txn += 1;
    }
    for _ in 0..10 {
        let (_r, s) = run_commit("CREATE (:Company {name: 'X'})", store, txn);
        store = s;
        txn += 1;
    }
    // 9 KNOWS edges among the persons (the exact endpoints are irrelevant; only the per-type count
    // is asserted). Match two persons and connect them, capping at one edge per statement.
    for k in 0..9 {
        let a = k;
        let b = k + 1;
        let src = format!(
            "MATCH (a:Person {{age: {a}}}), (b:Person {{age: {b}}}) CREATE (a)-[:KNOWS]->(b)"
        );
        let (_r, s) = run_commit(&src, store, txn);
        store = s;
        txn += 1;
    }
    store
}

// =================================================================================================
// 1. Counts bridge: total / per-label / per-type from the durable catalogue
// =================================================================================================

#[test]
fn statistics_is_present_and_counts_match_known_distribution() {
    let store = seed_known_distribution();
    let graph = RecordStoreGraph::begin(store, TxnId(1000));

    let stats = graph
        .statistics()
        .expect("the real store-backed graph always surfaces statistics");

    assert_eq!(stats.total_nodes(), 110, "100 Person + 10 Company");
    assert_eq!(stats.nodes_with_label("Person"), Some(100));
    assert_eq!(stats.nodes_with_label("Company"), Some(10));
    assert_eq!(stats.total_relationships(), 9, "9 KNOWS edges");
    assert_eq!(stats.relationships_with_type("KNOWS"), Some(9));

    // A label / type that no node carries is an EXACT Some(0) (the backend tracks per-label counts),
    // never the None "unknown" sentinel.
    assert_eq!(stats.nodes_with_label("Ghost"), Some(0));
    assert_eq!(stats.relationships_with_type("NOPE"), Some(0));

    let _ = graph.rollback().expect("read-only rollback");
}

// =================================================================================================
// 2. ANALYZE recompute + histogram selectivity end-to-end
// =================================================================================================

/// Recomputes the `(Person, age)` histogram over `store` and commits, returning the store.
fn analyze_person_age(store: Store, txn: u64) -> Store {
    let graph = RecordStoreGraph::begin(store, TxnId(txn));
    graph
        .recompute_property_histogram("Person", "age")
        .expect("ANALYZE Person.age");
    assert!(!graph.has_error(), "no error during recompute");
    graph.commit().expect("commit ANALYZE")
}

#[test]
fn analyze_then_equality_estimate_tracks_true_count_and_beats_fallback() {
    let store = seed_known_distribution();
    let store = analyze_person_age(store, 2000);

    // A fresh read transaction sees the committed histogram.
    let graph = RecordStoreGraph::begin(store, TxnId(2001));
    let stats = graph.statistics();

    // The histogram now exists for (Person, age): 100 distinct values.
    assert_eq!(
        stats
            .expect("stats")
            .distinct_label_property_values("Person", "age"),
        Some(100),
        "100 distinct ages were analyzed"
    );

    // WHERE p.age = 42 — every age distinct, true count is exactly 1.
    let logical = lower_query("MATCH (p:Person) WHERE p.age = 42 RETURN p");
    let with_stats = plan_physical_with_stats(&logical, &IndexCatalog::empty(), stats);
    let no_stats = plan_physical(&logical, &IndexCatalog::empty());

    let est = with_stats.estimated_rows();
    // The histogram equality estimate tracks the true count of ~1 (all-distinct values).
    assert!(
        (0.5..=2.0).contains(&est),
        "histogram equality estimate {est} should track the true count of 1"
    );
    // … and is clearly different from the no-stats constant fallback (the histogram path fired).
    let fallback = no_stats.estimated_rows();
    assert!(
        (est - fallback).abs() > 1.0,
        "histogram estimate {est} must differ from the constant fallback {fallback}"
    );

    assert!(!graph.has_error(), "no error reading the histogram");
    let _ = graph.rollback();
}

#[test]
fn analyze_then_range_estimate_tracks_true_filtered_count() {
    let store = seed_known_distribution();
    let store = analyze_person_age(store, 2100);

    let graph = RecordStoreGraph::begin(store, TxnId(2101));
    let stats = graph.statistics();

    // WHERE p.age >= 50 — true count is 50 (ages 50..100).
    let logical = lower_query("MATCH (p:Person) WHERE p.age >= 50 RETURN p");
    let with_stats = plan_physical_with_stats(&logical, &IndexCatalog::empty(), stats);
    let no_stats = plan_physical(&logical, &IndexCatalog::empty());

    let est = with_stats.estimated_rows();
    // The equi-depth range estimate is within ~one bucket depth of the true 50; allow a generous
    // band, matching the in-memory histogram test's tolerance.
    assert!(
        (35.0..=65.0).contains(&est),
        "range estimate {est} should track the true filtered count of 50"
    );
    // The no-stats fallback for a single-property filter over a label scan is
    // (DEFAULT_TOTAL_NODES * DEFAULT_LABEL_SELECTIVITY) * DEFAULT_PREDICATE_SELECTIVITY = 1000*0.1*0.3
    // = 30, distinct from the histogram's ~50.
    let fallback = no_stats.estimated_rows();
    assert!(
        (est - fallback).abs() > 5.0,
        "range estimate {est} must differ from the constant fallback {fallback}"
    );

    assert!(!graph.has_error());
    let _ = graph.rollback();
}

// =================================================================================================
// 3. Persistence: the histogram survives a crash + WAL recovery
// =================================================================================================

#[test]
fn analyzed_histogram_survives_crash_recovery() {
    let store = seed_known_distribution();
    let store = analyze_person_age(store, 2200);

    // Crash (device + log) and recover from the WAL alone.
    let recovered = recover_no_force(&store);

    // A fresh graph over the recovered store still has the histogram (the durable statistics
    // catalogue was checkpointed at the ANALYZE commit).
    let graph = RecordStoreGraph::begin(recovered, TxnId(2201));
    let stats = graph.statistics().expect("stats after recovery");

    assert_eq!(
        stats.distinct_label_property_values("Person", "age"),
        Some(100),
        "the analyzed histogram survived recovery"
    );

    // And the selectivity is still informed end-to-end.
    let logical = lower_query("MATCH (p:Person) WHERE p.age = 42 RETURN p");
    let with_stats = plan_physical_with_stats(&logical, &IndexCatalog::empty(), Some(stats));
    let est = with_stats.estimated_rows();
    assert!(
        (0.5..=2.0).contains(&est),
        "post-recovery equality estimate {est} still tracks the true count of 1"
    );

    assert!(!graph.has_error());
    let _ = graph.rollback();
}

// =================================================================================================
// 4. Fallback: a property never ANALYZEd has no histogram -> the constant fallback
// =================================================================================================

#[test]
fn property_without_histogram_falls_back_to_the_constant() {
    let store = seed_known_distribution();
    // NOTE: no ANALYZE here. Person.age has no stored histogram.
    let graph = RecordStoreGraph::begin(store, TxnId(2300));
    let stats = graph.statistics().expect("stats");

    // The seam returns None for an un-analyzed property (eq, range, distinct alike).
    assert_eq!(
        stats.estimate_nodes_label_property_eq("Person", "age", &Value::Integer(42)),
        None,
        "no histogram -> None (fall back)"
    );
    assert_eq!(
        stats.estimate_nodes_label_property_range(
            "Person",
            "age",
            Some(&Value::Integer(50)),
            true,
            None,
            true
        ),
        None
    );
    assert_eq!(
        stats.distinct_label_property_values("Person", "age"),
        None,
        "no histogram -> None distinct"
    );

    // End-to-end, the plan's estimate equals the no-stats fallback for that predicate (the estimator
    // could not improve on the constant). Counts still differ from no-stats (the label count is
    // known), so we compare the *with-known-counts* estimate against the same query estimated with a
    // stats source that knows the counts but has no histogram — which is exactly `stats` here.
    let logical = lower_query("MATCH (p:Person) WHERE p.age = 42 RETURN p");
    let with_stats = plan_physical_with_stats(&logical, &IndexCatalog::empty(), Some(stats));
    // Person count is the exact 100 (counts bridge works even without a histogram); the filter then
    // applies the constant DEFAULT_PREDICATE_SELECTIVITY = 0.3 -> 30.
    let est = with_stats.estimated_rows();
    assert!(
        (est - 30.0).abs() < 1e-9,
        "without a histogram the filter uses the 0.3 constant over the exact label count: {est}"
    );

    assert!(!graph.has_error());
    let _ = graph.rollback();
}

// =================================================================================================
// 5. Re-analyze clears a now-empty column; absent label/property never panics
// =================================================================================================

#[test]
fn analyze_empty_column_clears_any_stale_histogram() {
    // A label with no index-encodable values for the requested property -> the recompute removes any
    // stale histogram (here there was none) and leaves the seam at the None fallback.
    let store = seed_known_distribution();
    let graph = RecordStoreGraph::begin(store, TxnId(2400));
    // Person carries `age`, but no Person carries `nickname`, so the recompute finds no values.
    graph
        .recompute_property_histogram("Person", "nickname")
        .expect("recompute over an empty column is Ok");
    assert!(!graph.has_error());
    let store = graph.commit().expect("commit");

    let graph = RecordStoreGraph::begin(store, TxnId(2401));
    let stats = graph.statistics().expect("stats");
    assert_eq!(
        stats.distinct_label_property_values("Person", "nickname"),
        None,
        "no histogram was stored for an all-empty column"
    );
    let _ = graph.rollback();
}

#[test]
fn analyze_unknown_label_is_ok_and_stores_nothing() {
    // ANALYZE over a label that no node carries scans zero nodes -> empty -> no histogram, no error,
    // no panic (the token-resolution avoids minting tokens just to clear).
    let store = seed_known_distribution();
    let graph = RecordStoreGraph::begin(store, TxnId(2500));
    graph
        .recompute_property_histogram("Ghost", "age")
        .expect("recompute over an unknown label is Ok");
    assert!(!graph.has_error());
    let store = graph.commit().expect("commit");

    let graph = RecordStoreGraph::begin(store, TxnId(2501));
    assert_eq!(
        graph
            .statistics()
            .expect("stats")
            .distinct_label_property_values("Ghost", "age"),
        None
    );
    let _ = graph.rollback();
}
