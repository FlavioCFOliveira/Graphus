//! Regression guard for rmp #569: a **parameterized** equality point-lookup
//! `MATCH (n:L {k:$p})` must plan as a [`NodeIndexSeek`] (O(log n)) whenever a usable `:L(k)`
//! index exists — never revert to the O(label) [`NodeLabelScanEq`] scan.
//!
//! The #569 investigation suspected the cost-based optimiser reverted a `$param` equality seek to a
//! full label scan (the spike measured an online-index lookup scaling ~O(label)). Empirical probing
//! proved the seek is in fact chosen and executes sub-linearly; this test **pins** that outcome so a
//! future cost-model change cannot silently regress the ubiquitous OLTP point-lookup back to a scan.
//!
//! Coverage matrix (all four combinations plus the no-statistics / rule-based path):
//! - value shape: **`$param`** (`{k:$p}`) AND **literal** (`{k:42}`);
//! - index build: **offline** (`create_node_property_index`) AND **online**
//!   (`begin_online_node_property_index` + drive to `Online`);
//! - planner mode: cost-based (`Some(&coordinator.statistics())`, the production seam) AND rule-based
//!   (`None`).
//!
//! The harness mirrors `tests/online_index_build.rs` / `tests/coordinator_statistics.rs`: a
//! `TxnCoordinator` over an in-memory store, planned through the exact production seams
//! (`coordinator.catalog()` + `coordinator.statistics()` → `plan_physical_with_stats`).

use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, plan_physical, plan_physical_with_stats};
use graphus_cypher::semantics::analyze;
use graphus_cypher::statistics::Statistics;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 64, 1).expect("create store");
    TxnCoordinator::new(store)
}

fn lower_query(src: &str) -> graphus_cypher::logical::LogicalOp {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    lower(&validated)
}

/// Seeds `n` `(:Account {id})` nodes with distinct ids `0..n` in one committed transaction.
fn seed_accounts(coord: &mut Coord, n: i64) {
    let src = format!(
        "UNWIND range(0, {}) AS i CREATE (:Account {{id: i}})",
        n - 1
    );
    let plan = plan_physical(&lower_query(&src), &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("cursor");
        cursor.collect_all().expect("collect");
        assert!(!graph.has_error(), "seed error: {:?}", graph.take_error());
    }
    coord.commit(txn).expect("commit seed");
}

fn drive_build_to_online(coord: &mut Coord) {
    let mut it = 0;
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(64);
        it += 1;
        assert!(it < 100_000, "build must terminate");
    }
}

/// The leaf access-path operator the plan reads through (walks down single-input operators).
fn access_path(plan: &PhysicalPlan) -> &'static str {
    fn walk(op: &PhysicalOp) -> &'static str {
        match op {
            PhysicalOp::NodeIndexSeek { .. } => "NodeIndexSeek",
            PhysicalOp::NodeIndexRangeSeek { .. } => "NodeIndexRangeSeek",
            PhysicalOp::NodeLabelScanEq { .. } => "NodeLabelScanEq",
            PhysicalOp::NodeByLabelScan { .. } => "NodeByLabelScan",
            PhysicalOp::TokenLookupScan { .. } => "TokenLookupScan",
            PhysicalOp::AllNodesScan { .. } => "AllNodesScan",
            PhysicalOp::Filter { input, .. }
            | PhysicalOp::Projection { input, .. }
            | PhysicalOp::Limit { input, .. }
            | PhysicalOp::Skip { input, .. }
            | PhysicalOp::Aggregation { input, .. } => walk(input),
            _ => "other",
        }
    }
    walk(&plan.root)
}

/// Asserts both the `$param` and the literal equality point-lookup plan as a `NodeIndexSeek` against
/// `coord`'s live catalog + statistics, in BOTH the cost-based (`Some(stats)`) and rule-based (`None`)
/// planner modes. `ctx` names the index-build variant for a legible failure message.
fn assert_point_lookup_seeks(coord: &Coord, ctx: &str) {
    let catalog = coord.catalog();
    let stats = coord.statistics();

    let param = lower_query("MATCH (a:Account {id:$x}) RETURN a");
    let literal = lower_query("MATCH (a:Account {id:42}) RETURN a");

    for (shape, logical) in [("$param", &param), ("literal", &literal)] {
        // Cost-based (production seam): stats present.
        let cost_based = plan_physical_with_stats(logical, &catalog, Some(&stats));
        assert_eq!(
            access_path(&cost_based),
            "NodeIndexSeek",
            "[{ctx}] cost-based plan for a {shape} point lookup must be a NodeIndexSeek, got a scan"
        );
        // Rule-based (no stats): the seek must be chosen with no cost model at all.
        let rule_based = plan_physical_with_stats(logical, &catalog, None);
        assert_eq!(
            access_path(&rule_based),
            "NodeIndexSeek",
            "[{ctx}] rule-based plan for a {shape} point lookup must be a NodeIndexSeek, got a scan"
        );
    }

    // Cross-check the statistics the two shapes actually plan on.
    //
    // This assertion used to read `.is_none()`, on the premise that "production has no histogram …
    // (no ANALYZE runs there)". That premise was true when `rmp` #569 wrote it and is **false** since
    // `rmp` #572: `CREATE INDEX` now seeds the index's histogram, so a declared index is born with
    // real statistics. Inverted here rather than deleted, because the seeding is exactly what a
    // regression would silently undo.
    assert!(
        stats
            .estimate_nodes_label_property_eq("Account", "id", &graphus_core::Value::Integer(42))
            .is_some(),
        "[{ctx}] since `rmp` #572 a declared index is born with a histogram (CREATE INDEX seeds it)"
    );

    // The property that matters is unchanged and is asserted above for BOTH shapes: the point lookup
    // is a `NodeIndexSeek` cost-based AND rule-based. The rule-based case (`None` stats) is the one
    // that proves the seek does not *depend* on the histogram — which is what keeps a `$param` lookup
    // a seek, since a parameter's value is unknown at plan time and can never be placed in a
    // histogram bucket. `param_equality_seek_cost_beats_label_scan_eq` pins that cost ordering.
}

#[test]
fn offline_index_param_point_lookup_is_a_seek() {
    let mut coord = fresh_coord();
    seed_accounts(&mut coord, 1_000);
    coord
        .create_node_property_index("Account", "id")
        .expect("offline index");
    assert_point_lookup_seeks(&coord, "offline");
}

#[test]
fn online_index_param_point_lookup_is_a_seek() {
    let mut coord = fresh_coord();
    seed_accounts(&mut coord, 1_000);
    coord
        .begin_online_node_property_index("Account", "id")
        .expect("begin online index");
    drive_build_to_online(&mut coord);
    // Sanity: the online build promoted to Online (else the catalog would withhold the index).
    assert!(!coord.has_pending_index_builds(), "online build finished");
    assert_point_lookup_seeks(&coord, "online");
}

/// The seek estimate must beat the `NodeLabelScanEq` estimate for the parameter case at any label
/// size above the tiny-label crossover — the property that keeps the point-lookup a seek. This locks
/// the cost *ordering* (not just the current planner output) so a constant change that broke it would
/// fail here with a clear message.
#[test]
fn param_equality_seek_cost_beats_label_scan_eq() {
    use graphus_cypher::ast::{Expr, ExprKind, Label};
    use graphus_cypher::catalog::IndexId;
    use graphus_cypher::cost::estimate_cost;
    use graphus_cypher::lexer::Span;
    use graphus_cypher::logical::Var;

    let mut coord = fresh_coord();
    seed_accounts(&mut coord, 1_000);
    coord
        .create_node_property_index("Account", "id")
        .expect("offline index");
    let stats = coord.statistics();

    let span = Span::new(0, 0);
    let account = Label {
        name: "Account".to_owned(),
        span,
    };
    // A parameter seek value (the `literal_value` histogram probe returns None for a parameter, so the
    // cost model uses the constant-selectivity fallback — the production path).
    let param_value = Expr::new(ExprKind::Parameter("x".to_owned()), span);

    let seek = PhysicalOp::NodeIndexSeek {
        variable: Var::named("a"),
        label: account.clone(),
        property: "id".to_owned(),
        value: param_value.clone(),
        ordered: false,
        cached_property: false,
        index: IndexId(0),
    };
    let scan_eq = PhysicalOp::NodeLabelScanEq {
        variable: Var::named("a"),
        label: account,
        property: "id".to_owned(),
        value: param_value,
    };

    let seek_cost = estimate_cost(&seek, Some(&stats)).cost;
    let scan_cost = estimate_cost(&scan_eq, Some(&stats)).cost;
    assert!(
        seek_cost < scan_cost,
        "a $param equality seek ({seek_cost}) must cost less than NodeLabelScanEq ({scan_cost}) \
         over a 1000-node label"
    );
}
