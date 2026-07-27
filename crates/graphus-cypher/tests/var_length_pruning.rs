//! Variable-length expansion: distinct-end-node pruning and endpoint-predicate pushdown
//! (`rmp` task #870).
//!
//! Two rewrites are pinned here, and the same thing is asked of both: **does the plan still return the
//! identical bag?** Every behavioural test below is therefore an A/B between two spellings of one
//! question — one the rewrite fires on, one it provably declines — rather than a comparison against a
//! hand-written expected value. A hand-written expectation only proves that the rewritten plan agrees
//! with whoever wrote the test down; an A/B proves it agrees with the plan it replaced.
//!
//! Each A/B additionally asserts the operator names on **both** sides, so a test cannot pass by the
//! rewrite silently not firing. Removing either rewrite fails the `VarLengthExpandPruning` /
//! `WHERE`-in-details assertions immediately; weakening a gate fails the decline assertions.
//!
//! The deliberate declines are load-bearing, not leftovers:
//!
//! * a consumed relationship list or a named path (the pruning walk represents no single trail);
//! * a multiplicity-sensitive aggregate (`count(v)`, `collect(v)`);
//! * a lower bound of 2 or more — [`a_lower_bound_of_two_declines_and_the_answer_proves_why`]
//!   builds the graph on which pruning would drop a real answer, so the gate is shown to be
//!   *necessary*, not merely present.

use std::collections::BTreeMap;

use graphus_core::Value;
use graphus_cypher::ast::QueryPrefix;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::MemGraph;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::plan_description::{PlanDescription, PlanNode};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;

// =================================================================================================
// Harness
// =================================================================================================

fn catalog() -> IndexCatalog {
    IndexCatalog::builder()
        .with_label_property("N", "id")
        .build()
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &catalog()).with_prefix(ast.prefix())
}

/// Runs `src` over `graph`, returning its rows and — for a prefixed statement — the plan description.
fn run(src: &str, graph: &mut MemGraph) -> (Vec<Row>, Option<PlanDescription>) {
    let plan = compile(src);
    let params = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut cursor = execute(&plan, &params, graph).expect("open");
    let rows = cursor.collect_all().expect("drain");
    let description = match plan.prefix() {
        Some(QueryPrefix::Profile) => Some(PlanDescription::profile(
            cursor
                .profile()
                .expect("a PROFILEd statement has a recorder"),
        )),
        Some(QueryPrefix::Explain) => Some(PlanDescription::explain(&plan)),
        None => None,
    };
    (rows, description)
}

/// The rows of `src` as an order-insensitive multiset of stringified tuples.
fn bag(src: &str, graph: &mut MemGraph) -> Vec<String> {
    let mut out: Vec<String> = run(src, graph)
        .0
        .iter()
        .map(|r| format!("{:?}", r.values()))
        .collect();
    out.sort();
    out
}

/// The rows of `src` in **encounter order**, stringified — for the properties (`collect`, `DISTINCT`
/// projection order) where the list a query returns is itself ordered.
fn ordered(src: &str, graph: &mut MemGraph) -> Vec<String> {
    run(src, graph)
        .0
        .iter()
        .map(|r| format!("{:?}", r.values()))
        .collect()
}

fn walk<'p>(node: &'p PlanNode, out: &mut Vec<&'p PlanNode>) {
    out.push(node);
    for c in &node.children {
        walk(c, out);
    }
}

fn nodes(plan: &PlanDescription) -> Vec<&PlanNode> {
    let mut out = Vec::new();
    walk(plan.root(), &mut out);
    out
}

/// The `Details` line of the first operator of type `kind`.
fn details_of(plan: &PlanDescription, kind: &str) -> String {
    nodes(plan)
        .into_iter()
        .find(|n| n.operator_type == kind)
        .map(|n| match n.args.iter().find(|(k, _)| k == "Details") {
            Some((_, Value::String(s))) => s.clone(),
            other => panic!("operator {kind} has no Details arg: {other:?}"),
        })
        .unwrap_or_else(|| panic!("no {kind} operator in plan:\n{plan:?}"))
}

/// The measured `dbHits` of the first operator of type `kind`.
fn db_hits_of(plan: &PlanDescription, kind: &str) -> u64 {
    nodes(plan)
        .into_iter()
        .find(|n| n.operator_type == kind)
        .and_then(|n| n.db_hits)
        .unwrap_or_else(|| panic!("no measured {kind} operator in plan:\n{plan:?}"))
}

fn operators(plan: &PlanDescription) -> Vec<String> {
    nodes(plan)
        .into_iter()
        .map(|n| n.operator_type.to_owned())
        .collect()
}

// =================================================================================================
// Graph builders
// =================================================================================================

/// `n` `:N` nodes with `id` 0..n and the edges `pairs` (`:E` unless a type is given), so a test can
/// state a graph as a literal adjacency list.
fn graph_of(n: i64, pairs: &[(usize, usize)]) -> MemGraph {
    let mut g = MemGraph::new();
    let ids: Vec<_> = (0..n)
        .map(|i| g.add_node(["N"], [("id", Value::Integer(i))]))
        .collect();
    for &(a, b) in pairs {
        g.add_rel("E", ids[a], ids[b], [] as [(&str, Value); 0]);
    }
    g
}

/// A deterministic 32-bit xorshift, so the randomised differential battery is reproducible from its
/// seed and a failure can be replayed exactly.
struct Rng(u32);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() as usize) % n
    }
}

/// A random directed multigraph on `n` `:N` nodes with `edges` edges (self-loops and parallel edges
/// included — both are exactly the shapes trail semantics make interesting).
fn random_graph(rng: &mut Rng, n: usize, edges: usize) -> MemGraph {
    let mut pairs = Vec::with_capacity(edges);
    for _ in 0..edges {
        pairs.push((rng.below(n), rng.below(n)));
    }
    graph_of(i64::try_from(n).expect("test graph fits in i64"), &pairs)
}

// =================================================================================================
// 1. Which shapes plan the pruning expansion, and which decline
// =================================================================================================

#[test]
fn a_plan_that_consumes_only_the_distinct_end_node_plans_the_pruning_expansion() {
    for src in [
        // A global aggregation emits one row, so no order exists above it to be disturbed.
        "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN count(DISTINCT v)",
        // A DISTINCT projection qualifies when it is the plan ROOT: its rows go straight to the
        // client, and a Cypher result without ORDER BY has no defined row order.
        "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN DISTINCT v",
        "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN DISTINCT v.id",
        // A grouped aggregation qualifies at the root, on the same reasoning.
        "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN v.id, count(DISTINCT v)",
        // A global aggregation qualifies even when it is NOT the root — one row has no order.
        "MATCH (u:N {id: 0})-[:E*1..3]->(v) WITH count(DISTINCT v) AS c RETURN c + 1",
        // An unbounded upper bound is not a special case for the walk.
        "MATCH (u:N {id: 0})-[:E*1..]->(v) RETURN count(DISTINCT v)",
        // Neither is a zero lower bound (which admits the anchor at depth 0).
        "MATCH (u:N {id: 0})-[:E*0..3]->(v) RETURN count(DISTINCT v)",
        // …nor an undirected or reversed arrow.
        "MATCH (u:N {id: 0})-[:E*1..3]-(v) RETURN count(DISTINCT v)",
        "MATCH (u:N {id: 0})<-[:E*1..3]-(v) RETURN count(DISTINCT v)",
    ] {
        let rendered = compile(src).to_string();
        assert!(
            rendered.contains("VarLengthExpandPruning"),
            "{src} must plan the pruning expansion, got:\n{rendered}"
        );
    }
}

#[test]
fn a_consumed_relationship_list_or_named_path_declines_the_pruning_expansion() {
    for (src, why) in [
        (
            "MATCH (u:N {id: 0})-[r:E*1..3]->(v) RETURN DISTINCT v, r",
            "the relationship list is projected",
        ),
        (
            "MATCH (u:N {id: 0})-[r:E*1..3]->(v) RETURN DISTINCT size(r)",
            "the relationship list is read by a projected expression",
        ),
        (
            "MATCH (u:N {id: 0})-[r:E*1..3]->(v) WHERE size(r) > 1 RETURN DISTINCT v",
            "the relationship list is read by a Filter between consumer and expansion",
        ),
        (
            "MATCH p = (u:N {id: 0})-[:E*1..3]->(v) RETURN DISTINCT v",
            "a named path binds the trail",
        ),
        (
            "MATCH (u:N {id: 0})-[r:E*1..3]->(v) RETURN count(DISTINCT r)",
            "the aggregate is over the relationship list itself",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN count(v)",
            "count(v) is multiplicity-sensitive",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN count(*)",
            "count(*) is multiplicity-sensitive",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN collect(v)",
            "collect(v) is multiplicity-sensitive",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN count(DISTINCT v), count(v)",
            "one multiplicity-sensitive aggregate disqualifies the whole aggregation",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN v",
            "no distinctness at all",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*2..3]->(v) RETURN count(DISTINCT v)",
            "a lower bound above 1 makes emission depend on the exact depth",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v)-[:E]->(w) RETURN count(DISTINCT w)",
            "a further hop sits between the expansion and the consumer",
        ),
        (
            "MATCH (u:N {id: 0})-[:E]->(v) RETURN count(DISTINCT v)",
            "a fixed-length hop has no trails to collapse",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN collect(DISTINCT v)",
            "collect folds rows into a list, whose order is part of the row",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN sum(DISTINCT v.id)",
            "a float/saturating sum is order-dependent at the last bit",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN min(v.id)",
            "a fold that names a representative is only order-immune if the comparator is; \
             conservatively declined",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN max(DISTINCT v.id)",
            "same as min",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) WITH DISTINCT v RETURN collect(v.id)",
            "a collect ABOVE a DISTINCT projection observes the row order it emits",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) WITH DISTINCT v RETURN v",
            "a non-root DISTINCT projection cannot know what observes its row order",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN DISTINCT v.id LIMIT 2",
            "a LIMIT over an unordered result turns row order into a row SELECTION",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) WITH v.id AS i, count(DISTINCT v) AS c \
             RETURN collect(i)",
            "a collect above a GROUPED aggregation observes the group order",
        ),
    ] {
        let rendered = compile(src).to_string();
        assert!(
            !rendered.contains("VarLengthExpandPruning"),
            "{src} must decline the pruning expansion ({why}), got:\n{rendered}"
        );
    }
}

#[test]
fn an_endpoint_predicate_moves_into_the_expansion_and_a_wider_one_does_not() {
    // Confined to the far endpoint, and pure: the whole `Filter` is absorbed.
    let pushed = compile("MATCH (u:N {id: 0})-[:E*1..2]->(v) WHERE v.id = 3 RETURN v").to_string();
    assert!(
        pushed.contains("WHERE (v.id = 3)"),
        "the endpoint predicate must sit inside the expansion, got:\n{pushed}"
    );
    assert!(
        !pushed.contains("Filter"),
        "a fully pushed predicate leaves no residual Filter, got:\n{pushed}"
    );

    // Reads the anchor as well: it cannot be decided from the candidate end node alone.
    let correlated =
        compile("MATCH (u:N {id: 0})-[:E*1..2]->(v) WHERE v.id = u.id RETURN v").to_string();
    assert!(
        correlated.contains("Filter((v.id = u.id))"),
        "a predicate reading the anchor stays above the expansion, got:\n{correlated}"
    );

    // Not pure per row (a function call could be non-deterministic): declines.
    let impure = compile("MATCH (u:N {id: 0})-[:E*1..2]->(v) WHERE toUpper(v.tag) = 'X' RETURN v")
        .to_string();
    assert!(
        impure.contains("Filter"),
        "an impure predicate stays above the expansion, got:\n{impure}"
    );

    // A fixed-length hop is not rewritten: its predicates are already ordinary filters.
    let fixed = compile("MATCH (u:N {id: 0})-[:E]->(v) WHERE v.id = 3 RETURN v").to_string();
    assert!(
        fixed.contains("Filter((v.id = 3))"),
        "a fixed-length hop keeps its Filter, got:\n{fixed}"
    );
}

#[test]
fn a_filter_is_pushed_whole_or_not_at_all() {
    // `size(...)` is a function call, so it is not certified pure. Whichever side of the `AND` it sits
    // on, the WHOLE `Filter` stays put: splitting it would reorder the two conjuncts against each
    // other, and `AND` short-circuits on FALSE only.
    for src in [
        "MATCH (u:N {id: 0})-[:E*1..2]->(v) WHERE size([v]) = 1 AND v.id = 3 RETURN v",
        "MATCH (u:N {id: 0})-[:E*1..2]->(v) WHERE v.id = 3 AND size([v]) = 1 RETURN v",
    ] {
        let rendered = compile(src).to_string();
        assert!(
            !rendered.contains("WHERE") && rendered.contains("Filter"),
            "a partly-qualifying Filter must not be split, got:\n{rendered}"
        );
    }

    // Both conjuncts qualify: the whole Filter moves and disappears.
    let whole = compile("MATCH (u:N {id: 0})-[:E*1..2]->(v) WHERE v.id = 3 AND v.id > 0 RETURN v")
        .to_string();
    assert!(
        whole.contains("WHERE ((v.id = 3) AND (v.id > 0))") && !whole.contains("Filter"),
        "a fully-qualifying Filter moves whole, got:\n{whole}"
    );
}

#[test]
fn splitting_a_filter_would_lose_an_error_so_the_filter_is_not_split() {
    // The concrete reason gate 3 is all-or-nothing. `v.a` is absent (so `v.a = 1` is NULL) and
    // `v.z = 0`. `AND` short-circuits on FALSE only, so the plain plan evaluates the right-hand side on
    // the NULL rows and raises. Pushing `v.a = 1` alone would drop those rows inside the walk and the
    // division would never happen — the query would quietly return no rows instead of failing.
    let mut g = MemGraph::new();
    let a = g.add_node(["N"], [("id", Value::Integer(0)), ("k", Value::Integer(1))]);
    let b = g.add_node(["N"], [("id", Value::Integer(1)), ("z", Value::Integer(0))]);
    g.add_rel("E", a, b, [] as [(&str, Value); 0]);

    let src = "MATCH (u:N {id: 0})-[:E*1..2]->(v) WHERE v.a = 1 AND u.k / v.z > 0 RETURN v.id";
    let rendered = compile(src).to_string();
    assert!(
        !rendered.contains("WHERE") && rendered.contains("Filter"),
        "the Filter reads the anchor as well, so nothing may be pushed, got:\n{rendered}"
    );

    let plan = compile(src);
    let params = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let outcome = execute(&plan, &params, &mut g).expect("open").collect_all();
    assert!(
        outcome.is_err(),
        "the division by zero must still surface, got {outcome:?}"
    );
}

#[test]
fn a_non_boolean_endpoint_predicate_raises_exactly_as_a_filter_would() {
    // Cypher's `WHERE` is three-valued over booleans; a non-boolean, non-null value is a type error,
    // NOT a false. The pushed predicate goes through the same `predicate_truth` the `Filter` uses, so
    // the error surfaces whether or not the pushdown fired.
    let mut g = MemGraph::new();
    let a = g.add_node(["N"], [("id", Value::Integer(0))]);
    let b = g.add_node(
        ["N"],
        [
            ("id", Value::Integer(1)),
            ("flag", Value::String("yes".to_owned())),
        ],
    );
    g.add_rel("E", a, b, [] as [(&str, Value); 0]);

    let pushed = "MATCH (u:N {id: 0})-[:E*1..2]->(v) WHERE v.flag RETURN v.id";
    let above = "MATCH (u:N {id: 0})-[:E*1..2]->(v) WHERE size([v]) = 1 AND v.flag RETURN v.id";
    assert!(
        compile(pushed).to_string().contains("WHERE v.flag"),
        "non-vacuity: the predicate must really be inside the expansion"
    );
    assert!(
        !compile(above).to_string().contains("WHERE"),
        "non-vacuity: the control must really keep the predicate above"
    );

    for src in [pushed, above] {
        let plan = compile(src);
        let params = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let outcome = execute(&plan, &params, &mut g).expect("open").collect_all();
        assert!(
            outcome.is_err(),
            "{src}: a non-boolean WHERE is a type error, not a dropped row, got {outcome:?}"
        );
    }
}

// =================================================================================================
// 2. The bag is unchanged — A/B against a spelling the rewrite declines
// =================================================================================================

/// The A/B pair for the pruning walk: `MATCH p = …` binds a named path, which the rewrite declines,
/// and `p` is not returned — so the two queries are the same question, planned two ways.
const PRUNED: &str = "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN DISTINCT v.id";
const PLAIN: &str = "MATCH p = (u:N {id: 0})-[:E*1..3]->(v) RETURN DISTINCT v.id";

#[test]
fn the_pruning_walk_returns_the_same_distinct_end_nodes_as_the_trail_walk() {
    // A graph chosen to exercise every case the soundness argument has to handle: a cycle back to the
    // anchor, a node reachable at two different depths, a self-loop, parallel edges, and a node whose
    // only route is through a node the walk meets twice.
    let mut g = graph_of(
        7,
        &[
            (0, 1),
            (1, 2),
            (2, 3),
            (3, 0), // a 4-cycle through the anchor
            (0, 3), // …and a chord, so node 3 is reachable at depth 1 and at depth 3
            (2, 2), // a self-loop
            (1, 2), // a parallel edge
            (3, 4),
            (4, 5),
            (5, 6),
            (6, 4),
        ],
    );

    let (_, pruned_plan) = run(&format!("PROFILE {PRUNED}"), &mut g);
    let (_, plain_plan) = run(&format!("PROFILE {PLAIN}"), &mut g);
    let pruned_ops = operators(&pruned_plan.expect("profile"));
    let plain_ops = operators(&plain_plan.expect("profile"));
    assert!(
        pruned_ops.iter().any(|o| o == "VarLengthExpandPruning"),
        "non-vacuity: side A must really run the pruning walk, got {pruned_ops:?}"
    );
    assert!(
        plain_ops.iter().any(|o| o == "ExpandAll")
            && !plain_ops.iter().any(|o| o == "VarLengthExpandPruning"),
        "non-vacuity: side B must really run the plain trail walk, got {plain_ops:?}"
    );

    assert_eq!(
        bag(PRUNED, &mut g),
        bag(PLAIN, &mut g),
        "the pruning walk changed the answer"
    );
    // …and the answer is not the empty set, which would make the comparison vacuous.
    assert!(!bag(PRUNED, &mut g).is_empty());
}

#[test]
fn the_anchor_is_still_reported_when_a_cycle_returns_to_it() {
    // The case the `min <= 1` argument turns on: the anchor is expanded at depth 0 and never
    // re-expanded, so it can only be *reached* again from some other node — and it must be, whenever a
    // closed trail of an admitted length exists. Each shape pairs a graph with a bound that admits its
    // cycle: a self-loop, a two-cycle over two distinct edges, a triangle, and a four-cycle whose two
    // anchor-incident edges are the ones the argument's hard case is about.
    for (pairs, range) in [
        (vec![(0, 0)], "*1..1"),
        (vec![(0, 1), (1, 0)], "*1..2"),
        (vec![(0, 1), (1, 2), (2, 0)], "*1..3"),
        (vec![(0, 1), (1, 2), (2, 3), (3, 0)], "*1..4"),
        (vec![(0, 1), (1, 2), (2, 3), (3, 0), (0, 3)], "*1..4"),
    ] {
        let mut g = graph_of(4.max(pairs.len() as i64), &pairs);
        let pruned = format!("MATCH (u:N {{id: 0}})-[:E{range}]->(v) RETURN DISTINCT v.id");
        let plain = format!("MATCH p = (u:N {{id: 0}})-[:E{range}]->(v) RETURN DISTINCT v.id");
        assert!(
            compile(&pruned)
                .to_string()
                .contains("VarLengthExpandPruning"),
            "non-vacuity: {pruned}"
        );
        let a = bag(&pruned, &mut g);
        assert_eq!(a, bag(&plain, &mut g), "graph {pairs:?} {range}");
        assert!(
            a.iter().any(|r| r.contains("Integer(0)")),
            "graph {pairs:?} {range}: the anchor is reachable from itself and must be reported, got {a:?}"
        );
    }

    // And it is NOT reported when the only cycle is longer than the bound — the emission is real, not
    // an artefact of the anchor being trivially present.
    let mut g = graph_of(4, &[(0, 1), (1, 2), (2, 3), (3, 0)]);
    let short = bag(PRUNED, &mut g);
    assert_eq!(short, bag(PLAIN, &mut g));
    assert!(
        !short.iter().any(|r| r.contains("Integer(0)")),
        "the four-cycle does not close within three hops, got {short:?}"
    );
}

#[test]
fn the_pruning_walk_does_not_preserve_encounter_order_which_is_why_collect_declines() {
    // The measured counterexample behind gate 4's whitelist, pinned so the reasoning cannot be
    // quietly re-litigated. Anchor `0` reaches `5`; `5` carries a self-loop and edges to `2` and `4`;
    // `2` reaches `1`. Within three hops the plain walk goes round the self-loop and meets `4` before
    // `1`; the pruning walk declines to re-expand `5` and meets `1` first.
    //
    // The *set* is identical, which is all the rewrite promises. The *order* is not — so an aggregate
    // that folds rows into a list would put a different value in the row, and `collect(DISTINCT …)`
    // is therefore refused.
    let mut g = graph_of(6, &[(0, 5), (5, 5), (5, 2), (5, 4), (2, 1)]);

    assert_eq!(
        ordered(PRUNED, &mut g),
        vec![
            "[Value(Integer(5))]",
            "[Value(Integer(2))]",
            "[Value(Integer(1))]",
            "[Value(Integer(4))]",
        ],
        "the pruning walk's encounter order"
    );
    assert_eq!(
        ordered(PLAIN, &mut g),
        vec![
            "[Value(Integer(5))]",
            "[Value(Integer(2))]",
            "[Value(Integer(4))]",
            "[Value(Integer(1))]",
        ],
        "the plain walk's encounter order"
    );
    // Same rows, different order: the multiset guarantee holds, an order guarantee would not.
    assert_eq!(bag(PRUNED, &mut g), bag(PLAIN, &mut g));

    // Which is exactly why an order-dependent fold declines the rewrite …
    for src in [
        "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN collect(DISTINCT v)",
        "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN sum(DISTINCT v.id)",
        "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN avg(DISTINCT v.id)",
        "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN min(v.id)",
        "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN max(v.id), count(DISTINCT v)",
    ] {
        let rendered = compile(src).to_string();
        assert!(
            !rendered.contains("VarLengthExpandPruning"),
            "{src} folds rows in order and must decline, got:\n{rendered}"
        );
    }
    // … while a count of a set is admitted: an integer names no element, so it cannot name the wrong
    // one.
    let counted =
        compile("MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN count(DISTINCT v)").to_string();
    assert!(
        counted.contains("VarLengthExpandPruning"),
        "got:\n{counted}"
    );
}

#[test]
fn min_and_max_are_declined_even_though_they_are_currently_order_stable() {
    // `min`/`max` replace only on a STRICT comparison, so among values that compare `Equal` the first
    // encountered wins. Whether that can be observed depends on the value comparator, not on the fold.
    // Measured here so the claim is a fact and not a worry: today `min`/`max` are order-stable across
    // `1` / `1.0`, while `collect(DISTINCT …)` is not.
    let stable_min = ordered("UNWIND [1, 1.0] AS x RETURN min(x)", &mut MemGraph::new());
    assert_eq!(
        stable_min,
        ordered("UNWIND [1.0, 1] AS x RETURN min(x)", &mut MemGraph::new()),
        "min is order-stable across representations that compare equal"
    );
    assert_ne!(
        ordered(
            "UNWIND [1, 1.0] AS x RETURN collect(DISTINCT x)",
            &mut MemGraph::new()
        ),
        ordered(
            "UNWIND [1.0, 1] AS x RETURN collect(DISTINCT x)",
            &mut MemGraph::new()
        ),
        "collect(DISTINCT) keeps the first representative, so it IS order-sensitive"
    );

    // They are declined anyway. `count(DISTINCT …)` is safe by the shape of the fold — it returns a
    // size, so there is no representative to pick — whereas `min`/`max` are safe only for as long as
    // the comparator stays a strict total order. The gate keeps its guarantee local.
    for src in [
        "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN min(v.id)",
        "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN max(v.id)",
    ] {
        let rendered = compile(src).to_string();
        assert!(
            !rendered.contains("VarLengthExpandPruning"),
            "{src} must decline, got:\n{rendered}"
        );
    }
}

#[test]
fn an_order_immune_aggregate_returns_the_same_value_under_pruning() {
    let mut rng = Rng(0x9E37_79B9);
    let pairs = [
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN count(DISTINCT v.id)",
            "MATCH p = (u:N {id: 0})-[:E*1..3]->(v) RETURN count(DISTINCT v.id)",
        ),
        (
            "MATCH (u:N {id: 0})-[:E*1..3]->(v) RETURN v.id, count(DISTINCT v)",
            "MATCH p = (u:N {id: 0})-[:E*1..3]->(v) RETURN v.id, count(DISTINCT v)",
        ),
    ];
    for (pruned, plain) in pairs {
        assert!(
            compile(pruned)
                .to_string()
                .contains("VarLengthExpandPruning"),
            "non-vacuity: {pruned}"
        );
        assert!(
            !compile(plain)
                .to_string()
                .contains("VarLengthExpandPruning"),
            "non-vacuity: {plain}"
        );
    }
    for case in 0..40 {
        let mut g = random_graph(&mut rng, 8, 14);
        for (pruned, plain) in pairs {
            // Bags, not sequences: a ROOT consumer's row order is not part of the contract, and
            // pruning does change it (see
            // `the_pruning_walk_does_not_preserve_encounter_order_which_is_why_collect_declines`).
            assert_eq!(
                bag(pruned, &mut g),
                bag(plain, &mut g),
                "case {case}: {pruned}"
            );
        }
    }
}

#[test]
fn two_parallel_self_loops_on_the_anchor_are_the_minimal_lower_bound_witness() {
    // The smallest graph on which pruning at `min >= 2` loses a real answer, found by exhaustive
    // differential search. Two parallel self-loops on the anchor and `*2..2`: the trail "loop A then
    // loop B" is edge-distinct and reaches the anchor at depth 2, so the anchor IS an answer. A
    // pruning walk expands the anchor at depth 0, meets it again at depth 1 (below `min`, so nothing
    // is emitted), and then refuses to expand it a second time — never reaching depth 2 at all.
    //
    // It is also the case that most cleanly separates the two memos: emission and expansion are
    // different questions, and at `min >= 2` the expansion memo starts deciding emission.
    let mut g = MemGraph::new();
    let a = g.add_node(["N"], [("id", Value::Integer(0))]);
    g.add_rel("E", a, a, [] as [(&str, Value); 0]);
    g.add_rel("E", a, a, [] as [(&str, Value); 0]);

    let src = "MATCH (u:N {id: 0})-[:E*2..2]->(v) RETURN DISTINCT v.id";
    let rendered = compile(src).to_string();
    assert!(
        !rendered.contains("VarLengthExpandPruning"),
        "a lower bound of 2 must decline, got:\n{rendered}"
    );
    assert_eq!(
        bag(src, &mut g),
        vec!["[Value(Integer(0))]"],
        "the anchor is reachable by an edge-distinct trail of exactly two hops"
    );

    // The same graph one hop lower DOES prune, and still reports the anchor — so the decline above is
    // the lower bound talking, not the graph being degenerate.
    let low = "MATCH (u:N {id: 0})-[:E*1..2]->(v) RETURN DISTINCT v.id";
    assert!(
        compile(low).to_string().contains("VarLengthExpandPruning"),
        "non-vacuity: the `*1..2` spelling must really prune"
    );
    assert_eq!(bag(low, &mut g), vec!["[Value(Integer(0))]"]);
}

#[test]
fn a_randomised_differential_battery_finds_no_disagreement() {
    // The defence against "an optimisation changes the answer": many random multigraphs (self-loops
    // and parallel edges included) across every range/direction shape the rewrite admits, each
    // compared against the spelling that declines it.
    let shapes = [
        ("*1..1", "->"),
        ("*1..2", "->"),
        ("*1..3", "->"),
        ("*1..4", "->"),
        ("*0..3", "->"),
        ("*1..", "->"),
        ("*", "->"),
        ("*1..3", "-"),
        ("*0..2", "-"),
    ];
    let mut rng = Rng(0x1234_5678);
    let mut compared = 0usize;
    let mut non_empty = 0usize;
    for case in 0..60 {
        let n = 3 + rng.below(7);
        let e = 1 + rng.below(3 * n);
        let mut g = random_graph(&mut rng, n, e);
        for (range, arrow) in shapes {
            let tail = if arrow == "->" { "->(v)" } else { "-(v)" };
            let pruned = format!("MATCH (u:N {{id: 0}})-[:E{range}]{tail} RETURN DISTINCT v.id");
            let plain = format!("MATCH p = (u:N {{id: 0}})-[:E{range}]{tail} RETURN DISTINCT v.id");
            assert!(
                compile(&pruned)
                    .to_string()
                    .contains("VarLengthExpandPruning"),
                "non-vacuity: {pruned} must plan the pruning walk"
            );
            assert!(
                !compile(&plain)
                    .to_string()
                    .contains("VarLengthExpandPruning"),
                "non-vacuity: {plain} must decline the pruning walk"
            );
            let a = bag(&pruned, &mut g);
            let b = bag(&plain, &mut g);
            assert_eq!(a, b, "case {case} shape {range}{arrow}: n={n} e={e}");
            compared += 1;
            if !a.is_empty() {
                non_empty += 1;
            }
        }
    }
    assert_eq!(compared, 60 * shapes.len());
    assert!(
        non_empty * 4 > compared,
        "non-vacuity: most comparisons must have found rows, got {non_empty}/{compared}"
    );
}

#[test]
fn a_lower_bound_of_two_declines_and_the_answer_proves_why() {
    // The graph that makes the `min <= 1` gate necessary rather than merely conservative. With
    // `*3..3` the only trail to node 3 is 0->1->2->3, but node 2 is also a *direct* neighbour of the
    // anchor. A pruning walk would expand node 2 at depth 1, reach node 3 at depth 2 — below `min`,
    // so nothing is emitted — and then refuse to expand node 2 again at depth 2, losing the depth-3
    // arrival entirely.
    let mut g = graph_of(4, &[(0, 1), (1, 2), (0, 2), (2, 3)]);
    let src = "MATCH (u:N {id: 0})-[:E*3..3]->(v) RETURN DISTINCT v.id";
    let rendered = compile(src).to_string();
    assert!(
        !rendered.contains("VarLengthExpandPruning"),
        "a lower bound of 2 or more must decline, got:\n{rendered}"
    );
    let rows = bag(src, &mut g);
    assert_eq!(
        rows.len(),
        1,
        "node 3 is reachable in exactly three hops and must be reported, got {rows:?}"
    );
    assert!(rows[0].contains("Integer(3)"), "{rows:?}");
}

// =================================================================================================
// 3. The pushed endpoint predicate
// =================================================================================================

#[test]
fn the_pushed_endpoint_predicate_returns_the_same_rows() {
    // A/B for the pushdown. `size([v]) = 1` is always true and always a function call, so putting it
    // first stops the leading run and nothing is pushed — same question, planned two ways.
    const PUSHED: &str = "MATCH (u:N {id: 0})-[:E*1..3]->(v) WHERE v.id = 3 RETURN v.id";
    const ABOVE: &str =
        "MATCH (u:N {id: 0})-[:E*1..3]->(v) WHERE size([v]) = 1 AND v.id = 3 RETURN v.id";

    assert!(
        compile(PUSHED).to_string().contains("WHERE (v.id = 3)"),
        "non-vacuity: side A must really carry the predicate inside the expansion"
    );
    let above = compile(ABOVE).to_string();
    assert!(
        !above.contains("WHERE") && above.contains("Filter"),
        "non-vacuity: side B must really keep the predicate above the expansion, got:\n{above}"
    );

    let mut rng = Rng(0x0BAD_F00D);
    let mut found = 0usize;
    for case in 0..40 {
        let mut g = random_graph(&mut rng, 6, 12);
        let a = bag(PUSHED, &mut g);
        assert_eq!(a, bag(ABOVE, &mut g), "case {case}");
        found += usize::from(!a.is_empty());
    }
    assert!(
        found > 0,
        "non-vacuity: some case must actually have matched node 3"
    );
}

#[test]
fn the_pushed_predicate_filters_emission_and_never_the_walk() {
    // A chain 0 -> 1 -> 2 where only node 2 satisfies the predicate. Node 1 fails it, and if the
    // predicate pruned the *walk* rather than the emission, node 2 would become unreachable. It must
    // still be found.
    let mut g = graph_of(3, &[(0, 1), (1, 2)]);
    let src = "MATCH (u:N {id: 0})-[:E*1..2]->(v) WHERE v.id = 2 RETURN v.id";
    assert!(
        compile(src).to_string().contains("WHERE (v.id = 2)"),
        "non-vacuity: the predicate must be inside the expansion"
    );
    let rows = bag(src, &mut g);
    assert_eq!(
        rows.len(),
        1,
        "node 2 lies beyond a node that fails the predicate and must still be reached, got {rows:?}"
    );
}

#[test]
fn a_null_valued_endpoint_predicate_drops_the_row_exactly_as_a_filter_would() {
    // Three-valued logic: `v.missing = 1` is NULL, not FALSE, and the `Filter` this predicate was
    // moved out of keeps rows on TRUE only.
    let mut g = graph_of(3, &[(0, 1), (1, 2)]);
    let pushed = "MATCH (u:N {id: 0})-[:E*1..2]->(v) WHERE v.missing = 1 RETURN v.id";
    let above =
        "MATCH (u:N {id: 0})-[:E*1..2]->(v) WHERE size([v]) = 1 AND v.missing = 1 RETURN v.id";
    assert!(compile(pushed).to_string().contains("WHERE"));
    assert!(!compile(above).to_string().contains("WHERE"));
    assert_eq!(bag(pushed, &mut g), bag(above, &mut g));
    assert!(
        bag(pushed, &mut g).is_empty(),
        "a NULL predicate keeps no row"
    );
}

// =================================================================================================
// 4. The pruning walk really does less work
// =================================================================================================

#[test]
fn the_pruning_walk_reads_strictly_fewer_db_hits_and_the_gap_widens_with_the_hop_bound() {
    // A complete digraph, where the number of trails grows with the hop bound while the number of
    // reachable nodes does not. Measuring at two bounds says something about the asymptotics rather
    // than pinning one machine-specific number: the saving must not merely exist, it must *grow*.
    let n = 8usize;
    let mut pairs = Vec::new();
    for a in 0..n {
        for b in 0..n {
            if a != b {
                pairs.push((a, b));
            }
        }
    }

    let mut ratios = Vec::new();
    for hops in [2u32, 3, 4, 5] {
        let mut g = graph_of(i64::try_from(n).expect("fits"), &pairs);
        let pruned_src =
            format!("PROFILE MATCH (u:N {{id: 0}})-[:E*1..{hops}]->(v) RETURN DISTINCT v.id");
        let plain_src =
            format!("PROFILE MATCH p = (u:N {{id: 0}})-[:E*1..{hops}]->(v) RETURN DISTINCT v.id");

        let (pruned_rows, pruned_plan) = run(&pruned_src, &mut g);
        let (plain_rows, plain_plan) = run(&plain_src, &mut g);
        let pruned_plan = pruned_plan.expect("profile");
        let plain_plan = plain_plan.expect("profile");

        // Same answer …
        let mut a: Vec<_> = pruned_rows
            .iter()
            .map(|r| format!("{:?}", r.values()))
            .collect();
        let mut b: Vec<_> = plain_rows
            .iter()
            .map(|r| format!("{:?}", r.values()))
            .collect();
        a.sort();
        b.sort();
        assert_eq!(a, b, "{hops} hops");
        // Every node is reachable, the anchor included: `0 -> k -> 0` is a two-edge trail.
        assert_eq!(a.len(), n, "{hops} hops: every node is reachable");

        let pruned_hits = db_hits_of(&pruned_plan, "VarLengthExpandPruning");
        let plain_hits = db_hits_of(&plain_plan, "ExpandAll");
        println!("{hops} hops: pruning={pruned_hits} plain={plain_hits}");
        // Never worse, at any bound. At two hops there is nothing to cut — the frontier is expanded
        // once and the second level is already the leaf — so the two agree exactly, which is itself
        // the statement that pruning costs nothing where it cannot help.
        assert!(
            pruned_hits <= plain_hits,
            "{hops} hops: pruning must never read more: pruning={pruned_hits} plain={plain_hits}"
        );
        if hops >= 3 {
            assert!(
                pruned_hits < plain_hits,
                "{hops} hops: pruning={pruned_hits} plain={plain_hits}"
            );
            ratios.push(
                (f64::from(u32::try_from(plain_hits).expect("fits")))
                    / (f64::from(u32::try_from(pruned_hits).expect("fits"))),
            );
        }
    }

    // The saving is asymptotic, not a constant factor: each added hop multiplies the number of trails
    // while leaving the number of reachable nodes alone.
    assert!(
        ratios.windows(2).all(|w| w[1] > w[0]),
        "the advantage must widen with the hop bound, got {ratios:?}"
    );
}

#[test]
fn the_pruning_detail_line_names_the_walk_and_binds_no_relationship() {
    let mut g = graph_of(3, &[(0, 1), (1, 2)]);
    let (_, plan) = run(&format!("PROFILE {PRUNED}"), &mut g);
    let plan = plan.expect("profile");
    let details = details_of(&plan, "VarLengthExpandPruning");
    assert_eq!(details, "VarLengthExpandPruning(u)-[:E*1..3]->(v)");
    // The operator binds no relationship list, and says so.
    let node = nodes(&plan)
        .into_iter()
        .find(|n| n.operator_type == "VarLengthExpandPruning")
        .expect("operator");
    assert!(
        node.identifiers.iter().any(|i| i == "v"),
        "the far endpoint is bound: {:?}",
        node.identifiers
    );
    assert_eq!(
        node.identifiers.len(),
        2,
        "only the anchor and the far endpoint are bound, got {:?}",
        node.identifiers
    );
}

// =================================================================================================
// 5. Regression: a `$param` inside a variable-length hop's inline property map
// =================================================================================================

#[test]
fn a_parameter_inside_a_var_length_inline_property_map_binds() {
    // A fixed-length hop lowers its inline property map to an ordinary `Filter`, whose parameters the
    // binder collects. A variable-length hop keeps the map ON the operator, and the binder did not
    // walk it — so `BoundParameters` did not carry `$p`, the comparison went NULL, every relationship
    // was rejected and the query returned **zero rows** while the fixed-length spelling of the same
    // question returned the match.
    let mut g = MemGraph::new();
    let a = g.add_node(["N"], [("id", Value::Integer(0))]);
    let b = g.add_node(["N"], [("id", Value::Integer(1))]);
    g.add_rel("T", a, b, [("k", Value::Integer(7))]);

    for src in [
        "MATCH (a:N {id: 0})-[r:T*1..3 {k: $p}]->(b) RETURN b.id",
        "MATCH (a:N {id: 0})-[r:T {k: $p}]->(b) RETURN b.id",
    ] {
        let plan = compile(src);
        let mut params = Parameters::new();
        params.insert("p", Value::Integer(7));
        let bound = bind_parameters(&plan, &params).expect("bind");
        assert_eq!(
            bound.get("p"),
            Some(&Value::Integer(7)),
            "{src}: the plan must declare the parameter it evaluates"
        );
        let rows = execute(&plan, &bound, &mut g)
            .expect("open")
            .collect_all()
            .expect("drain");
        assert_eq!(rows.len(), 1, "{src}: the matching relationship is found");
    }

    // A parameter the plan does not supply is still a bind-time error, not a silent empty result.
    let plan = compile("MATCH (a:N)-[r:T*1..3 {k: $p}]->(b) RETURN b");
    assert!(
        bind_parameters(&plan, &Parameters::new()).is_err(),
        "a missing parameter inside a var-length property map must be reported"
    );
}

#[test]
fn a_var_length_inline_property_map_is_visible_in_the_plan() {
    // The predicate really runs inside the expansion, so a plan description that omitted it would
    // understate the operator's work and make two differently-filtered queries look identical.
    let with_props = compile("MATCH (a:N {id: 0})-[r:T*1..3 {k: 7}]->(b) RETURN b").to_string();
    let without = compile("MATCH (a:N {id: 0})-[r:T*1..3]->(b) RETURN b").to_string();
    assert!(with_props.contains("{k: 7}"), "got:\n{with_props}");
    assert_ne!(with_props, without);
}

// =================================================================================================
// 6. The rewrites compose
// =================================================================================================

#[test]
fn a_pushed_predicate_and_a_pruning_walk_compose_without_changing_the_answer() {
    let mut rng = Rng(0xC0FF_EE01);
    let pruned_pushed = "MATCH (u:N {id: 0})-[:E*1..3]->(v) WHERE v.id > 2 RETURN DISTINCT v.id";
    let neither = "MATCH p = (u:N {id: 0})-[:E*1..3]->(v) WHERE size([v]) = 1 AND v.id > 2 RETURN DISTINCT v.id";

    let rendered = compile(pruned_pushed).to_string();
    assert!(
        rendered.contains("VarLengthExpandPruning") && rendered.contains("WHERE (v.id > 2)"),
        "non-vacuity: both rewrites must fire on side A, got:\n{rendered}"
    );
    let control = compile(neither).to_string();
    assert!(
        !control.contains("VarLengthExpandPruning") && !control.contains("WHERE"),
        "non-vacuity: neither rewrite may fire on side B, got:\n{control}"
    );

    let mut found = 0usize;
    for case in 0..40 {
        let mut g = random_graph(&mut rng, 7, 13);
        let a = bag(pruned_pushed, &mut g);
        assert_eq!(a, bag(neither, &mut g), "case {case}");
        found += usize::from(!a.is_empty());
    }
    assert!(found > 0, "non-vacuity: some case must have matched");
}

#[test]
fn a_grouped_distinct_aggregation_prunes_per_group_without_changing_the_answer() {
    // Several driving rows and a group key, so the "pruning is per driving row" claim is exercised
    // rather than assumed.
    let mut rng = Rng(0x5EED_1234);
    let pruned = "MATCH (u:N)-[:E*1..2]->(v) RETURN u.id, count(DISTINCT v.id)";
    let plain = "MATCH p = (u:N)-[:E*1..2]->(v) RETURN u.id, count(DISTINCT v.id)";
    assert!(
        compile(pruned)
            .to_string()
            .contains("VarLengthExpandPruning")
    );
    assert!(
        !compile(plain)
            .to_string()
            .contains("VarLengthExpandPruning")
    );

    for case in 0..30 {
        let mut g = random_graph(&mut rng, 6, 11);
        let mut a: BTreeMap<String, String> = BTreeMap::new();
        for row in run(pruned, &mut g).0 {
            a.insert(
                format!("{:?}", row.values()[0]),
                format!("{:?}", row.values()[1]),
            );
        }
        let mut b: BTreeMap<String, String> = BTreeMap::new();
        for row in run(plain, &mut g).0 {
            b.insert(
                format!("{:?}", row.values()[0]),
                format!("{:?}", row.values()[1]),
            );
        }
        assert_eq!(a, b, "case {case}");
    }
}
