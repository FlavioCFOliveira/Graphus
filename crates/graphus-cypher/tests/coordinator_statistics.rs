//! End-to-end tests for the **coordinator-level statistics seam** (`rmp` task #82):
//! [`TxnCoordinator::statistics`] surfaces the store's durable catalogue counts (`rmp` task #79) and
//! per-indexed-property equi-depth histograms (`rmp` task #81) to the planner
//! ([`plan_physical_with_stats`]) at compile time — the seam the production compile paths (server,
//! TCK runner, LDBC bench driver) use to activate the cost-based optimiser (`rmp` task #65).
//!
//! The tests prove, over a real WAL-logged store driven **through the coordinator** (the production
//! transaction path, unlike `statistics_bridge.rs` which drives `RecordStoreGraph::begin` directly):
//!
//! * **Counts** — `total_nodes` / `nodes_with_label` / `total_relationships` /
//!   `relationships_with_type` report the exact seeded distribution; a never-interned label/type is
//!   an exact `Some(0)`, and an un-`ANALYZE`d property is the `None` fallback.
//! * **Histogram parity** — after an `ANALYZE` through a statement seam, the coordinator seam's
//!   histogram answers (distinct / eq / range) are identical to the per-statement
//!   [`RecordStoreGraph`](graphus_cypher::record_graph::RecordStoreGraph) seam's over the same
//!   store — including while that statement seam is **live** (both borrow the shared store briefly
//!   per call, never overlapping).
//! * **Open-transaction safety** — every statistics call answers between `begin` and `commit`
//!   (the server compiles inside an open transaction), with no `RefCell` borrow conflict.
//! * **Planner consumption** — `plan_physical_with_stats(.., Some(&coord.statistics()))` yields a
//!   stats-informed `estimated_rows` (the exact label count for a bare label scan; a histogram-
//!   tracked estimate for an analyzed predicate), proving the seam feeds the planner end-to-end at
//!   the production compile boundary.

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::GraphAccess;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical, plan_physical_with_stats};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_cypher::statistics::Statistics;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness (the coordinator-driven statement pattern of `crash_concurrency.rs`)
// =================================================================================================

/// A fresh coordinator over a fresh, empty record store on an in-memory DST device + log.
fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 64, 1).expect("create store");
    TxnCoordinator::new(store)
}

/// Compiles `src` to a physical plan against the empty index catalog (statement driving only; the
/// statistics path under test is orthogonal to index selection).
fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Lowers `src` to a **logical** plan (the input `plan_physical_with_stats` estimates over).
fn lower_query(src: &str) -> graphus_cypher::logical::LogicalOp {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    lower(&validated)
}

/// Runs one statement of `txn` over the coordinator; the per-statement seam is dropped before
/// returning, so the transaction stays open without borrowing the store.
fn run_stmt(coord: &Coord, txn: TxnId, src: &str) -> Vec<Row> {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(
        !graph.has_error(),
        "unexpected captured error: {:?}",
        graph.take_error()
    );
    rows
}

/// Runs `src` in its own committed serializable transaction (the auto-commit shape).
fn exec_commit(coord: &mut Coord, src: &str) {
    let txn = coord.begin_serializable();
    let _ = run_stmt(coord, txn, src);
    coord.commit(txn).expect("commit");
}

/// Seeds the canonical distribution of `statistics_bridge.rs` — 100 `:Person` with `age` spread over
/// `0..100` (every value distinct), 10 `:Company`, 9 `:KNOWS` edges — through the coordinator, so
/// the durable catalogue counts are exactly known to the assertions below.
fn seed_known_distribution(coord: &mut Coord) {
    for age in 0..100 {
        exec_commit(coord, &format!("CREATE (:Person {{age: {age}}})"));
    }
    for _ in 0..10 {
        exec_commit(coord, "CREATE (:Company {name: 'X'})");
    }
    for k in 0..9 {
        exec_commit(
            coord,
            &format!(
                "MATCH (a:Person {{age: {k}}}), (b:Person {{age: {}}}) CREATE (a)-[:KNOWS]->(b)",
                k + 1
            ),
        );
    }
}

/// `ANALYZE (Person, age)` through a statement seam and commit — the on-demand recompute path the
/// coordinator's histogram answers are sourced from (`rmp` task #81).
fn analyze_person_age(coord: &mut Coord) {
    let txn = coord.begin_serializable();
    {
        let graph = coord.statement(txn).expect("statement");
        graph
            .recompute_property_histogram("Person", "age")
            .expect("ANALYZE Person.age");
        assert!(!graph.has_error(), "no error during recompute");
    }
    coord.commit(txn).expect("commit ANALYZE");
}

// =================================================================================================
// 1. Counts: the coordinator seam reports the exact durable catalogue
// =================================================================================================

#[test]
fn coordinator_statistics_counts_match_known_distribution() {
    let mut coord = fresh_coord();
    seed_known_distribution(&mut coord);

    let stats = coord.statistics();

    assert_eq!(stats.total_nodes(), 110, "100 Person + 10 Company");
    assert_eq!(stats.nodes_with_label("Person"), Some(100));
    assert_eq!(stats.nodes_with_label("Company"), Some(10));
    assert_eq!(stats.total_relationships(), 9, "9 KNOWS edges");
    assert_eq!(stats.relationships_with_type("KNOWS"), Some(9));

    // A label / type that no node carries is an EXACT Some(0) (the backend tracks per-label counts),
    // never the None "unknown" sentinel — identical to the statement seam's contract.
    assert_eq!(stats.nodes_with_label("Ghost"), Some(0));
    assert_eq!(stats.relationships_with_type("NOPE"), Some(0));

    // No ANALYZE has run: every histogram method is the None "fall back" sentinel.
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
    assert_eq!(stats.distinct_label_property_values("Person", "age"), None);
}

// =================================================================================================
// 2. Histogram parity: the coordinator seam equals the live statement seam
// =================================================================================================

#[test]
fn coordinator_histograms_match_the_statement_seam_after_analyze() {
    let mut coord = fresh_coord();
    seed_known_distribution(&mut coord);
    analyze_person_age(&mut coord);

    let stats = coord.statistics();

    // The committed histogram answers through the coordinator seam: 100 distinct ages.
    assert_eq!(
        stats.distinct_label_property_values("Person", "age"),
        Some(100)
    );
    let eq = stats
        .estimate_nodes_label_property_eq("Person", "age", &Value::Integer(42))
        .expect("eq estimate from the stored histogram");
    assert!(
        (0.5..=2.0).contains(&eq),
        "equality estimate {eq} tracks the true count of 1 (all ages distinct)"
    );
    let range = stats
        .estimate_nodes_label_property_range(
            "Person",
            "age",
            Some(&Value::Integer(50)),
            true,
            None,
            true,
        )
        .expect("range estimate from the stored histogram");
    assert!(
        (35.0..=65.0).contains(&range),
        "range estimate {range} tracks the true filtered count of 50"
    );

    // Parity with the per-statement seam over the same store — asserted while that seam is LIVE:
    // both implementations read the same shared catalogue through per-call borrows that never
    // overlap, so the answers are identical (both decode the same stored histogram bytes).
    let txn = coord.begin_serializable();
    {
        let graph = coord.statement(txn).expect("statement");
        let seam = graph.statistics().expect("the statement seam has stats");
        assert_eq!(seam.total_nodes(), stats.total_nodes());
        assert_eq!(
            seam.nodes_with_label("Person"),
            stats.nodes_with_label("Person")
        );
        assert_eq!(
            seam.relationships_with_type("KNOWS"),
            stats.relationships_with_type("KNOWS")
        );
        assert_eq!(
            seam.distinct_label_property_values("Person", "age"),
            stats.distinct_label_property_values("Person", "age")
        );
        assert_eq!(
            seam.estimate_nodes_label_property_eq("Person", "age", &Value::Integer(42)),
            Some(eq),
            "both seams decode the same stored histogram"
        );
        assert!(!graph.has_error());
    }
    coord.rollback(txn).expect("read-only rollback");
}

// =================================================================================================
// 3. Open-transaction safety: statistics answer between begin and commit
// =================================================================================================

#[test]
fn statistics_answer_while_a_transaction_is_open() {
    let mut coord = fresh_coord();
    seed_known_distribution(&mut coord);
    analyze_person_age(&mut coord);

    // The realistic compile-time condition: the server compiles between `begin` and the statement's
    // execution, so a transaction is open but no store borrow is live. Every statistics call must
    // answer with its own brief borrow — no `RefCell` conflict, no panic.
    let txn = coord.begin_serializable();
    let stats = coord.statistics();
    assert_eq!(stats.total_nodes(), 110);
    assert_eq!(stats.nodes_with_label("Person"), Some(100));
    assert_eq!(stats.total_relationships(), 9);
    assert_eq!(
        stats.distinct_label_property_values("Person", "age"),
        Some(100)
    );

    // Stronger than the server needs: even with a live statement seam in scope (it, too, borrows
    // only per call), the statistics seam still answers without overlap.
    {
        let graph = coord.statement(txn).expect("statement");
        assert_eq!(stats.nodes_with_label("Company"), Some(10));
        assert!(
            stats
                .estimate_nodes_label_property_eq("Person", "age", &Value::Integer(1))
                .is_some()
        );
        assert!(!graph.has_error());
    }
    coord.commit(txn).expect("commit");
}

// =================================================================================================
// 4. Planner consumption: the seam feeds plan_physical_with_stats end-to-end
// =================================================================================================

#[test]
fn planner_consumes_coordinator_statistics_end_to_end() {
    let mut coord = fresh_coord();
    seed_known_distribution(&mut coord);

    // A bare label scan: with the coordinator's statistics the root estimate is the EXACT label
    // count (10 :Company nodes) — the production compile sites pass exactly this `Some(&stats)`.
    // (:Company, not :Person, because the no-stats fallback DEFAULT_TOTAL_NODES *
    // DEFAULT_LABEL_SELECTIVITY = 1000 * 0.1 happens to also be 100 — the :Person assertion would
    // pass vacuously.)
    let logical = lower_query("MATCH (c:Company) RETURN c");
    let stats = coord.statistics();
    let with_stats = plan_physical_with_stats(&logical, &coord.catalog(), Some(&stats));
    let est = with_stats.estimated_rows();
    assert!(
        (est - 10.0).abs() < 1e-9,
        "stats-informed label-scan estimate is the exact count: {est}"
    );
    let fallback = plan_physical(&logical, &coord.catalog()).estimated_rows();
    assert!(
        (est - fallback).abs() > 1.0,
        "stats estimate {est} must differ from the constant fallback {fallback}"
    );

    // After ANALYZE, a histogram-backed predicate flows through the same boundary: the estimate
    // tracks the true count of 1 (all ages distinct), as in `statistics_bridge.rs`.
    analyze_person_age(&mut coord);
    let logical = lower_query("MATCH (p:Person) WHERE p.age = 42 RETURN p");
    let stats = coord.statistics();
    let with_stats = plan_physical_with_stats(&logical, &coord.catalog(), Some(&stats));
    let est = with_stats.estimated_rows();
    assert!(
        (0.5..=2.0).contains(&est),
        "histogram-backed estimate {est} tracks the true count of 1 through the coordinator seam"
    );
}
