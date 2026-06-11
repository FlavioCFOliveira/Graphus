//! End-to-end tests for the **cost-based optimiser** (`rmp` task #65): with graph statistics
//! supplied, [`plan_physical_with_stats`] selects a measurably cheaper physical plan than the
//! rule-based [`plan_physical`] — reordering independent joins, choosing the hash-join build side, and
//! picking index seek vs scan by cost — while preserving the exact result **bag**.
//!
//! The suite proves, over deterministic [`MemGraph`] statistics (which serve exact counts and exact
//! equi-depth histograms, exercising the very seam the storage backend uses):
//!
//! * **Cheaper-and-different** — a multi-component query is reshaped under skewed statistics into a
//!   tree the [cost model](graphus_cypher::cost) scores **strictly cheaper** than the rule-based one
//!   (the headline acceptance criterion), with a structural witness (the join order changed).
//! * **Determinism** — planning the same query + statistics twice yields equal plans.
//! * **Fallback** — with `stats = None`, the with-stats entry point is byte-for-byte the rule-based
//!   plan.
//! * **Seek-vs-scan** — a selective predicate keeps (or wins back) the index seek and records its
//!   index dependency; a non-selective predicate (the histogram says it matches ~all rows) reverts to
//!   a label scan and drops the dependency.
//! * **Result-bag equivalence** — executing the rule-based and cost-based plans over the same graph
//!   yields identical result multisets. This is the key TCK-safety proof: only the plan *shape*
//!   changed.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::cost::estimate_cost;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, MemGraph};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::logical::LogicalOp;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, plan_physical, plan_physical_with_stats};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;

// =================================================================================================
// Harness
// =================================================================================================

/// Lowers `src` to a logical plan (the planner's input).
fn logical(src: &str) -> LogicalOp {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    lower(&validated)
}

/// Executes a compiled plan over `graph` and returns the rows.
fn run_plan(plan: &PhysicalPlan, graph: &mut MemGraph) -> Vec<Row> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    execute(plan, &bound, graph)
        .expect("open cursor")
        .collect_all()
        .expect("rows")
}

/// A canonical, order-independent key for a result row: its `(column, value)` pairs sorted by column
/// name and rendered with `Debug`. Two runs over the same fresh `MemGraph` mint node ids
/// deterministically, so equal bags render to equal multisets of keys.
fn row_key(row: &Row) -> Vec<String> {
    let mut pairs: Vec<String> = row
        .columns()
        .iter()
        .zip(row.values().iter())
        .map(|(c, v)| format!("{c}={v:?}"))
        .collect();
    pairs.sort();
    pairs
}

/// The sorted multiset of row keys — comparing two of these compares result **bags** (multiplicity
/// included), independent of emission order.
fn bag(rows: &[Row]) -> Vec<Vec<String>> {
    let mut keys: Vec<Vec<String>> = rows.iter().map(row_key).collect();
    keys.sort();
    keys
}

/// 1000 `:Person` (every `k` distinct), 3 `:Company` and 3 `:Car`. Deliberately skewed so a join
/// reorder is unambiguously cheaper.
fn skewed_graph() -> MemGraph {
    let mut g = MemGraph::new();
    for i in 0..1000 {
        g.add_node(["Person"], [("k", Value::Integer(i))]);
    }
    for i in 0..3 {
        g.add_node(
            ["Company"],
            [("k", Value::Integer(i)), ("j", Value::Integer(i))],
        );
    }
    for i in 0..3 {
        g.add_node(["Car"], [("j", Value::Integer(i))]);
    }
    g
}

// =================================================================================================
// 1. Cheaper-and-different: a multi-component query is reshaped under skewed statistics
// =================================================================================================

#[test]
fn cost_based_plan_is_cheaper_and_structurally_different() {
    let g = skewed_graph();
    let stats = g.statistics();
    let catalog = IndexCatalog::empty();
    let log = logical(
        "MATCH (a:Person), (b:Company), (c:Car) WHERE a.k = b.k AND b.j = c.j RETURN a, b, c",
    );

    let rule = plan_physical(&log, &catalog);
    let cost = plan_physical_with_stats(&log, &catalog, stats);

    // Structural: the tree changed (the join order was reordered).
    assert_ne!(
        rule.root, cost.root,
        "the cost-based tree must differ:\nrule:\n{rule}\ncost:\n{cost}"
    );

    // Cost model: the cost-based plan is strictly cheaper (measured by `estimate_cost`).
    let rule_cost = estimate_cost(&rule.root, stats).cost;
    let cost_cost = estimate_cost(&cost.root, stats).cost;
    assert!(
        cost_cost < rule_cost,
        "cost-based plan ({cost_cost}) must be cheaper than rule-based ({rule_cost})"
    );

    // The two relations joined first should be the small ones (Company, Car) — the innermost join must
    // not multiply the 1000-row Person relation. The innermost (deepest-left) join's operands are the
    // small relations.
    let innermost = innermost_join(&cost.root).expect("a join is present");
    let cols = join_operand_labels(innermost);
    assert!(
        cols.iter().all(|l| l != "Person"),
        "the innermost join must combine the two small relations, not Person; got {cols:?}"
    );
}

// =================================================================================================
// 2. Determinism: same query + stats -> identical plan
// =================================================================================================

#[test]
fn planning_is_deterministic_for_fixed_statistics() {
    let g = skewed_graph();
    let stats = g.statistics();
    let catalog = IndexCatalog::empty();
    let log = logical(
        "MATCH (a:Person), (b:Company), (c:Car) WHERE a.k = b.k AND b.j = c.j RETURN a, b, c",
    );

    let first = plan_physical_with_stats(&log, &catalog, stats);
    let second = plan_physical_with_stats(&log, &catalog, stats);
    assert_eq!(
        first, second,
        "planning must be deterministic for fixed stats"
    );
}

// =================================================================================================
// 3. Fallback: stats = None reproduces the rule-based plan byte-for-byte
// =================================================================================================

#[test]
fn no_stats_falls_back_to_the_rule_based_plan() {
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "age")
        .build();
    for src in [
        "MATCH (a:Person), (b:Company), (c:Car) WHERE a.k = b.k AND b.j = c.j RETURN a, b, c",
        "MATCH (n:Person) WHERE n.age = 30 RETURN n",
        "MATCH (n:Person) WHERE n.age > 18 RETURN n",
    ] {
        let log = logical(src);
        let rule = plan_physical(&log, &catalog);
        let none = plan_physical_with_stats(&log, &catalog, None);
        assert_eq!(
            rule, none,
            "stats=None must equal plan_physical for `{src}`"
        );
    }
}

// =================================================================================================
// 4. Seek-vs-scan: selective -> seek (dep recorded); non-selective -> scan (no dep)
// =================================================================================================

#[test]
fn selective_predicate_keeps_the_index_seek() {
    // 1000 distinct ages: `age = 42` matches exactly 1 row, so the seek is far cheaper than scanning
    // the whole label — the cost-based planner keeps the seek and records its index dependency.
    let mut g = MemGraph::new();
    for i in 0..1000 {
        g.add_node(["Person"], [("age", Value::Integer(i))]);
    }
    let stats = g.statistics();
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "age")
        .build();
    let log = logical("MATCH (n:Person) WHERE n.age = 42 RETURN n");

    let plan = plan_physical_with_stats(&log, &catalog, stats);
    assert!(
        plan.to_string().contains("NodeIndexSeek"),
        "a selective equality must keep the seek:\n{plan}"
    );
    assert_eq!(
        plan.index_dependencies().count(),
        1,
        "the kept seek must record its index dependency"
    );
}

#[test]
fn non_selective_predicate_reverts_the_seek_to_a_scan() {
    // Every Person has the SAME age (50): `age >= 0` (and `age = 50`) matches ~all rows, so a seek that
    // streams nearly the whole label is no cheaper than a plain scan — the cost-based planner reverts
    // to a NodeByLabelScan + Filter and drops the index dependency.
    let mut g = MemGraph::new();
    for _ in 0..1000 {
        g.add_node(["Person"], [("age", Value::Integer(50))]);
    }
    let stats = g.statistics();
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "age")
        .build();

    // A range that the histogram says matches the entire label.
    let log = logical("MATCH (n:Person) WHERE n.age >= 0 RETURN n");
    let rule = plan_physical(&log, &catalog);
    let cost = plan_physical_with_stats(&log, &catalog, stats);

    // The rule-based planner used the seek; the cost-based one reverted to a scan.
    assert!(
        rule.to_string().contains("NodeIndexRangeSeek"),
        "rule-based planner uses the seek:\n{rule}"
    );
    assert!(
        cost.to_string().contains("NodeByLabelScan") && !cost.to_string().contains("Seek"),
        "non-selective predicate must revert to a scan:\n{cost}"
    );
    // The dropped seek's index dependency must NOT be recorded.
    assert_eq!(
        cost.index_dependencies().count(),
        0,
        "a plan that dropped the seek must not record the index dependency"
    );
    // And the revert is genuinely cheaper (or equal — it is chosen only when strictly cheaper).
    assert!(estimate_cost(&cost.root, stats).cost <= estimate_cost(&rule.root, stats).cost);
}

// =================================================================================================
// 5. Result-bag equivalence: the rule-based and cost-based plans return identical multisets
// =================================================================================================

#[test]
fn rule_based_and_cost_based_plans_return_identical_bags() {
    let catalog = IndexCatalog::empty();
    let src = "MATCH (a:Person), (b:Company), (c:Car) WHERE a.k = b.k AND b.j = c.j RETURN a, b, c";
    let log = logical(src);

    // Build the two plans against one graph's statistics …
    let stats_graph = skewed_graph();
    let rule = plan_physical(&log, &catalog);
    let cost = plan_physical_with_stats(&log, &catalog, stats_graph.statistics());
    assert_ne!(
        rule.root, cost.root,
        "the plans must actually differ for this to prove anything"
    );

    // … then execute each over a freshly seeded (identical) graph and compare result bags.
    let mut g_rule = skewed_graph();
    let mut g_cost = skewed_graph();
    let rule_rows = run_plan(&rule, &mut g_rule);
    let cost_rows = run_plan(&cost, &mut g_cost);

    assert_eq!(
        rule_rows.len(),
        cost_rows.len(),
        "row counts must match (rule={}, cost={})",
        rule_rows.len(),
        cost_rows.len()
    );
    assert_eq!(
        bag(&rule_rows),
        bag(&cost_rows),
        "the reordered plan must return the identical result bag"
    );
    // Sanity: the equi-join produced the 3 matching (a,b,c) triples (k and j both 0,1,2 across the
    // 3 Company / 3 Car; each Person.k in 0..3 matches one Company).
    assert_eq!(rule_rows.len(), 3, "expected 3 matching rows");
}

#[test]
fn seek_revert_preserves_the_result_bag() {
    // The seek-vs-scan revert must also be bag-preserving: a non-selective range over a uniform column
    // returns the same rows whether realised as a seek or a scan+filter.
    let mut seed = MemGraph::new();
    for age in 0..20 {
        // 5 copies of each age 0..20 -> 100 Person; `age >= 10` matches exactly 50.
        for _ in 0..5 {
            seed.add_node(["Person"], [("age", Value::Integer(age))]);
        }
    }
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "age")
        .build();
    let log = logical("MATCH (n:Person) WHERE n.age >= 10 RETURN n.age AS age");

    let rule = plan_physical(&log, &catalog);
    let cost = plan_physical_with_stats(&log, &catalog, seed.statistics());

    let mut g_rule = MemGraph::new();
    let mut g_cost = MemGraph::new();
    for age in 0..20 {
        for _ in 0..5 {
            g_rule.add_node(["Person"], [("age", Value::Integer(age))]);
            g_cost.add_node(["Person"], [("age", Value::Integer(age))]);
        }
    }
    let rule_rows = run_plan(&rule, &mut g_rule);
    let cost_rows = run_plan(&cost, &mut g_cost);
    assert_eq!(rule_rows.len(), 50, "age >= 10 matches 50 of 100");
    assert_eq!(
        bag(&rule_rows),
        bag(&cost_rows),
        "seek-vs-scan choice must preserve the result bag"
    );
}

// =================================================================================================
// Structural helpers
// =================================================================================================

/// Finds the deepest-left join in a tree (the innermost join of a left-deep chain). For a left-deep
/// `((X ⋈ Y) ⋈ Z)` this is `X ⋈ Y`.
fn innermost_join(op: &PhysicalOp) -> Option<&PhysicalOp> {
    fn descend<'a>(op: &'a PhysicalOp, found: &mut Option<&'a PhysicalOp>) {
        match op {
            PhysicalOp::HashJoin { left, right, .. }
            | PhysicalOp::NestedLoopJoin { left, right } => {
                *found = Some(op);
                // Recurse into both sides; the deepest join wins (left-deep -> the left chain).
                descend(left, found);
                descend(right, found);
            }
            PhysicalOp::Filter { input, .. }
            | PhysicalOp::Projection { input, .. }
            | PhysicalOp::Aggregation { input, .. }
            | PhysicalOp::Sort { input, .. }
            | PhysicalOp::TopN { input, .. }
            | PhysicalOp::Skip { input, .. }
            | PhysicalOp::Limit { input, .. }
            | PhysicalOp::Eager { input }
            | PhysicalOp::Unwind { input, .. }
            | PhysicalOp::LoadCsv { input, .. }
            | PhysicalOp::ExpandAll { input, .. }
            | PhysicalOp::ExpandInto { input, .. }
            | PhysicalOp::NamedPath { input, .. }
            | PhysicalOp::Optional { input, .. } => descend(input, found),
            _ => {}
        }
    }
    // Walk the deepest join: keep descending the left chain until no nested join remains.
    let mut top = None;
    descend(op, &mut top);
    let mut current = top?;
    loop {
        let next = match current {
            PhysicalOp::HashJoin { left, .. } | PhysicalOp::NestedLoopJoin { left, .. } => {
                match left.as_ref() {
                    j @ (PhysicalOp::HashJoin { .. } | PhysicalOp::NestedLoopJoin { .. }) => j,
                    _ => return Some(current),
                }
            }
            _ => return Some(current),
        };
        current = next;
    }
}

/// The label names of the scan operands directly under a join (for a 2-scan join, both labels).
fn join_operand_labels(join: &PhysicalOp) -> Vec<String> {
    fn label_of(op: &PhysicalOp) -> Option<String> {
        match op {
            PhysicalOp::NodeByLabelScan { label, .. }
            | PhysicalOp::TokenLookupScan { label, .. }
            | PhysicalOp::NodeIndexSeek { label, .. }
            | PhysicalOp::NodeIndexRangeSeek { label, .. } => Some(label.name.clone()),
            _ => None,
        }
    }
    match join {
        PhysicalOp::HashJoin { left, right, .. } | PhysicalOp::NestedLoopJoin { left, right } => {
            [label_of(left), label_of(right)]
                .into_iter()
                .flatten()
                .collect()
        }
        _ => Vec::new(),
    }
}
