//! Regression for the **bounded join-order planner** (`rmp` task #482, confidence-to-100).
//!
//! The cost-based optimiser reorders a reorderable join region by a System-R dynamic program, which
//! is super-exponential in the operand count. A query with *many* comma-separated patterns could make
//! PLANNING ITSELF expensive (a plan-time CPU/memory DoS). Above `MAX_JOIN_REGION_OPERANDS` the
//! optimiser now falls back to a polynomial **greedy** join order — a correct, connectivity-respecting,
//! **bag-identical** order (only the plan *shape* is heuristic, never the result).
//!
//! This pins two properties:
//!   1. **Bounded plan time** — a query with far more operands than the cap plans well within a
//!      generous wall-clock ceiling (the greedy path, not the exponential DP).
//!   2. **Bag-identical** — the greedy plan executes to the exact same result multiset as the
//!      rule-based plan (correctness is preserved; this is the TCK-safety argument).

use std::time::Instant;

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, MemGraph};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::logical::LogicalOp;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical, plan_physical_with_stats};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;

fn logical(src: &str) -> LogicalOp {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    lower(&validated)
}

fn run_plan(plan: &PhysicalPlan, graph: &mut MemGraph) -> Vec<Row> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    execute(plan, &bound, graph)
        .expect("open cursor")
        .collect_all()
        .expect("rows")
}

/// A canonical, order-independent multiset of result rows.
fn bag(rows: &[Row]) -> Vec<Vec<String>> {
    let mut keys: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            let mut pairs: Vec<String> = row
                .columns()
                .iter()
                .zip(row.values().iter())
                .map(|(c, v)| format!("{c}={v:?}"))
                .collect();
            pairs.sort();
            pairs
        })
        .collect();
    keys.sort();
    keys
}

/// `n` labels `L0..L{n-1}`, each with `per` nodes carrying a join key `k = 0..per`.
fn many_label_graph(n: usize, per: usize) -> MemGraph {
    let mut g = MemGraph::new();
    for li in 0..n {
        let label = format!("L{li}");
        for k in 0..per {
            g.add_node([label.as_str()], [("k", Value::Integer(k as i64))]);
        }
    }
    g
}

/// `MATCH (v0:L0),(v1:L1),...,(v{n-1}:L{n-1}) WHERE v0.k=v1.k AND v1.k=v2.k ... RETURN v0.k AS k` —
/// `n` reorderable join operands joined into one connected region by an equality chain on `k`.
fn many_pattern_query(n: usize) -> String {
    let patterns: Vec<String> = (0..n).map(|i| format!("(v{i}:L{i})")).collect();
    let joins: Vec<String> = (0..n - 1)
        .map(|i| format!("v{i}.k = v{}.k", i + 1))
        .collect();
    format!(
        "MATCH {} WHERE {} RETURN v0.k AS k",
        patterns.join(", "),
        joins.join(" AND ")
    )
}

#[test]
fn many_join_operands_plan_in_bounded_time_via_greedy_fallback() {
    // Far above MAX_JOIN_REGION_OPERANDS (8): the exponential DP would blow up; the greedy fallback
    // must plan in bounded time.
    let n = 28;
    let gs = many_label_graph(n, 2);
    let catalog = IndexCatalog::empty();
    let log = logical(&many_pattern_query(n));

    // PLAN time only: a 28-way exponential DP would not return in any reasonable time; the greedy
    // fallback must. We deliberately do NOT execute a 28-way join (its result/intermediate size is
    // irrelevant to this property and could be large); plan-time boundedness is the property under
    // test. Correctness (bag-identity) is pinned by the n=12 test below.
    let start = Instant::now();
    let plan = plan_physical_with_stats(&log, &catalog, gs.statistics());
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 5,
        "planning {n} join operands must be bounded by the greedy fallback, took {elapsed:?}"
    );
    // The plan is well-formed (non-empty, no planner panic).
    assert!(
        !format!("{plan:?}").is_empty(),
        "the greedy fallback must yield a well-formed plan for {n} operands"
    );
}

#[test]
fn greedy_plan_is_bag_identical_to_the_rule_based_plan() {
    // Above the cap (greedy), but small enough to execute cheaply.
    let n = 12;
    let catalog = IndexCatalog::empty();
    let log = logical(&many_pattern_query(n));

    let gs = many_label_graph(n, 2);
    let greedy = plan_physical_with_stats(&log, &catalog, gs.statistics());
    let rule = plan_physical(&log, &catalog);

    let mut g_rule = many_label_graph(n, 2);
    let mut g_greedy = many_label_graph(n, 2);
    assert_eq!(
        bag(&run_plan(&rule, &mut g_rule)),
        bag(&run_plan(&greedy, &mut g_greedy)),
        "the greedy join order must produce the identical result bag as the rule-based plan"
    );
}
