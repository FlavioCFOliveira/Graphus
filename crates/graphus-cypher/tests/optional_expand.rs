//! **`OptionalExpand`: a one-hop `OPTIONAL MATCH` as one operator** (`rmp` task #882).
//!
//! Every `OPTIONAL MATCH` used to lower to `Apply(left, Optional(rhs))` and thence to a correlated
//! `NestedLoopJoin`: for **each** driving row the executor built a whole right branch — an `Argument`
//! row, an expand, one `Filter` per inside-`WHERE` predicate and the `Optional` wrapper — drained it,
//! merged every produced row back into the driving row, and tore it down again, all to discover at
//! most one neighbourhood. `PhysicalOp::OptionalExpand` does it in one operator.
//!
//! # What decides whether the rewrite is legal
//!
//! Not performance — **`OPTIONAL MATCH` semantics**. A driving row must survive with nulls *when and
//! only when* the right side yields nothing; a `WHERE` **inside** the `OPTIONAL MATCH` can null a row
//! out while a `WHERE` **after** it removes the row; relationship isomorphism still applies; and the
//! null set is the lowerer's, not a re-derivation. These tests hold each of those down.
//!
//! # How the comparison is made non-vacuous
//!
//! Almost every test below runs the query **twice**: once through the planner's plan (which must
//! contain the fused operator — asserted) and once through
//! [`PhysicalOp::fallback_plan`](graphus_cypher::physical::PhysicalOp::fallback_plan), which
//! reconstructs the exact `NestedLoopJoin`/`Optional` tree the planner produced **before** this task.
//! That reconstruction is not taken on trust: [`the_fallback_plan_is_the_pre_882_planner_output`]
//! pins it against plan text captured from the pre-change planner and recorded verbatim in this file.
//! So "the bags agree" means the new operator agrees with the code it replaced, executed here, not
//! with an expectation re-derived by the test author.

use graphus_core::Value;
use graphus_cypher::authorized_graph::{AuthorizedGraph, PrivilegeOracle};
use graphus_cypher::binding::{BindError, Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{
    ExpandDirection, GraphAccess, Incident, MemGraph, NodeId, RelData, RelId,
};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use std::cell::RefCell;

// =================================================================================================
// Harness
// =================================================================================================

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let validated = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    // The `EXPLAIN` / `PROFILE` prefix rides on the compiled plan and is what turns on the runtime
    // recorder, so it is carried here rather than in a second, prefix-only helper.
    plan_physical(&lower(&validated), &IndexCatalog::empty()).with_prefix(ast.prefix())
}

/// The same plan with **every** [`PhysicalOp::OptionalExpand`] replaced by the
/// `NestedLoopJoin`/`Optional` subtree it fused — i.e. the plan the planner produced before #882.
///
/// Bottom-up: children are un-fused first, so a nested fusion is recovered too.
fn unfused(plan: &PhysicalPlan) -> PhysicalPlan {
    fn go(mut op: PhysicalOp) -> PhysicalOp {
        for child in op.children_mut() {
            let taken = std::mem::replace(child, PhysicalOp::Empty);
            *child = go(taken);
        }
        op.fallback_plan().unwrap_or(op)
    }
    let mut out = plan.clone();
    out.root = go(plan.root.clone());
    out
}

/// Whether the plan text names the fused operator anywhere (either strategy).
fn is_fused(plan: &PhysicalPlan) -> bool {
    let text = plan.root.to_string();
    text.contains("OptionalExpandAll") || text.contains("OptionalExpandInto")
}

/// The corpus, built to make every acceptance case land on a **different** driving row, so a single
/// query exercises all of them at once and no case can be silently absent.
///
/// | node | what it contributes                                                            |
/// |------|--------------------------------------------------------------------------------|
/// | `a0` | **no** relationship at all — the null-row case                                  |
/// | `a1` | exactly one outgoing `T`                                                        |
/// | `a2` | **three** outgoing `T`, one of whose targets fails `b.x = 1` — several matches, and the `WHERE`-inside-vs-after case |
/// | `a3` | a `T` **self-loop** — bound once by an undirected hop, not twice                |
/// | `a4` | `T` to `a5` **twice** (multigraph) *and* a `T` back from `a5` — an undirected hop from `a4` binds three relationships, two of them the same pair in both orientations |
/// | `a6` | only an **incoming** `T` — `->` finds nothing here, `<-` finds one              |
/// | `a7` | only a `U` — a **typed** `:T` hop finds nothing, an **untyped** hop finds one   |
fn corpus() -> MemGraph {
    let mut g = MemGraph::new();
    let p = |g: &mut MemGraph, name: &str, x: i64| {
        g.add_node(
            ["P"],
            [
                ("name", Value::String(name.to_owned())),
                ("x", Value::Integer(x)),
            ],
        )
    };
    let _a0 = p(&mut g, "a0", 0);
    let a1 = p(&mut g, "a1", 1);
    let a2 = p(&mut g, "a2", 2);
    let a3 = p(&mut g, "a3", 3);
    let a4 = p(&mut g, "a4", 4);
    let a5 = p(&mut g, "a5", 5);
    let a6 = p(&mut g, "a6", 6);
    let a7 = p(&mut g, "a7", 7);
    let q1 = g.add_node(["Q"], [("x", Value::Integer(1))]);
    let q2a = g.add_node(["Q"], [("x", Value::Integer(1))]);
    let q2b = g.add_node(["Q"], [("x", Value::Integer(1))]);
    let q2c = g.add_node(["R"], [("x", Value::Integer(9))]);

    g.add_rel("T", a1, q1, [("w", Value::Integer(1))]);
    g.add_rel("T", a2, q2a, [("w", Value::Integer(1))]);
    g.add_rel("T", a2, q2b, [("w", Value::Integer(2))]);
    g.add_rel("T", a2, q2c, [("w", Value::Integer(3))]);
    g.add_rel("T", a3, a3, [("w", Value::Integer(4))]);
    g.add_rel("T", a4, a5, [("w", Value::Integer(5))]);
    g.add_rel("T", a4, a5, [("w", Value::Integer(6))]);
    g.add_rel("T", a5, a4, [("w", Value::Integer(7))]);
    g.add_rel("T", q1, a6, [("w", Value::Integer(9))]); // a6 has ONLY an incoming T
    g.add_rel("U", a7, q1, [("w", Value::Integer(8))]);
    g
}

fn render(row: &Row, columns: &[&str]) -> String {
    columns
        .iter()
        .map(|c| format!("{:?}", row.value(c)))
        .collect::<Vec<_>>()
        .join("|")
}

/// Runs `plan` over a fresh corpus and returns the rows **in emission order**, rendered.
///
/// Order is kept (not sorted) deliberately: the fused operator claims to reproduce the replaced
/// plan's rows *and their order*, which is a strictly stronger claim than bag equality and is what
/// makes a downstream `SKIP`/`LIMIT` without `ORDER BY` behave identically.
fn rows_of(plan: &PhysicalPlan, columns: &[&str], params: &Parameters) -> Vec<String> {
    let bound = bind_parameters(plan, params).expect("bind");
    let mut g = corpus();
    let mut cursor = execute(plan, &bound, &mut g).expect("open cursor");
    cursor
        .collect_all()
        .expect("collect")
        .iter()
        .map(|r| render(r, columns))
        .collect()
}

/// The load-bearing comparison: the fused plan and the plan it replaced produce the **same rows in
/// the same order**, and the query is not trivially empty.
fn assert_fused_matches_fallback(src: &str, columns: &[&str]) -> Vec<String> {
    assert_fused_matches_fallback_with(src, columns, &Parameters::new())
}

fn assert_fused_matches_fallback_with(
    src: &str,
    columns: &[&str],
    params: &Parameters,
) -> Vec<String> {
    let fused = compile(src);
    assert!(
        is_fused(&fused),
        "`{src}` must plan as OptionalExpand, else this comparison is vacuous:\n{}",
        fused.root
    );
    let reference = unfused(&fused);
    assert!(
        !is_fused(&reference),
        "the reference plan must NOT contain the fused operator:\n{}",
        reference.root
    );
    assert!(
        reference.root.to_string().contains("NestedLoopJoin")
            && reference.root.to_string().contains("Optional(nulls="),
        "the reference must be the Apply/Optional plan:\n{}",
        reference.root
    );
    let got = rows_of(&fused, columns, params);
    let want = rows_of(&reference, columns, params);
    assert!(
        !want.is_empty(),
        "the corpus must produce rows for `{src}`, else the comparison is vacuous"
    );
    assert_eq!(
        got, want,
        "OptionalExpand changed the result for `{src}`\n  fused:\n{}\n  reference:\n{}",
        fused.root, reference.root
    );
    got
}

/// Runs a query that must **decline** the fusion, asserting the decline and returning its rows.
///
/// The rows are returned so every decline test can also check the *answer* — a decline that produced
/// the wrong result would otherwise pass unnoticed.
fn assert_declines(src: &str, columns: &[&str]) -> Vec<String> {
    let plan = compile(src);
    assert!(
        !is_fused(&plan),
        "`{src}` must NOT fuse — the operator cannot express it:\n{}",
        plan.root
    );
    assert!(
        plan.root.to_string().contains("Optional(nulls="),
        "`{src}` must keep the Optional fallback shape:\n{}",
        plan.root
    );
    rows_of(&plan, columns, &Parameters::new())
}

// =================================================================================================
// 1. The operator is planned, and the reference it is compared against is the real pre-#882 plan
// =================================================================================================

/// Acceptance criterion 1, first half: the shape is recognised, on the plan.
#[test]
fn a_one_hop_optional_match_plans_as_a_single_optional_expand() {
    for (src, expected_type) in [
        (
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a, r, b",
            "OptionalExpandAll",
        ),
        (
            "MATCH (a:P) OPTIONAL MATCH (a)-[r]->(b) RETURN a, r, b",
            "OptionalExpandAll",
        ),
        (
            "MATCH (a:P) OPTIONAL MATCH (a)<-[r:T]-(b) RETURN a, r, b",
            "OptionalExpandAll",
        ),
        (
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]-(b) RETURN a, r, b",
            "OptionalExpandAll",
        ),
        (
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b:Q) WHERE b.x = 1 RETURN a, r, b",
            "OptionalExpandAll",
        ),
        (
            "MATCH (a:P), (b:Q) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a, b, r",
            "OptionalExpandInto",
        ),
    ] {
        let plan = compile(src);
        let found = find_optional_expand(&plan.root)
            .unwrap_or_else(|| panic!("no OptionalExpand for `{src}`:\n{}", plan.root));
        assert_eq!(
            found.operator_type(),
            expected_type,
            "wrong expand strategy for `{src}`:\n{}",
            plan.root
        );
        // The sub-plan is gone, not merely renamed. The `Optional` wrapper and the `Argument` leaf
        // must have disappeared outright; the join count must have gone DOWN by exactly one (an
        // expand-into's driving side is itself a cartesian `NestedLoopJoin` — `MATCH (a:P), (b:Q)` —
        // which this rewrite neither owns nor removes, so "no join anywhere" would be the wrong bar).
        let text = plan.root.to_string();
        for gone in ["Optional(nulls=", "Argument("] {
            assert!(
                !text.contains(gone),
                "`{src}` still plans a `{gone}` — the sub-plan was not removed:\n{text}"
            );
        }
        let joins = |t: &str| t.matches("NestedLoopJoin").count();
        assert_eq!(
            joins(&text) + 1,
            joins(&unfused(&plan).root.to_string()),
            "`{src}` must remove exactly one correlated join:\n{text}"
        );
    }
}

fn find_optional_expand(op: &PhysicalOp) -> Option<&PhysicalOp> {
    if matches!(op, PhysicalOp::OptionalExpand { .. }) {
        return Some(op);
    }
    op.children().into_iter().find_map(find_optional_expand)
}

/// The reference plan every equality test below is measured against **is** the plan the planner
/// produced before #882.
///
/// The expected strings were **measured**, not written: each was dumped from `plan_physical(...).root`
/// for that exact query with the fusion pass disabled — i.e. from the planner as it stood at commit
/// `64e9602`, this task's parent — and pinned here verbatim.
///
/// Without this test the whole file could be self-consistent and still wrong: `fallback_plan` could
/// reconstruct *some* Apply/Optional plan that the fused operator happens to agree with. That is not
/// hypothetical — the fifth case below caught exactly that during development.
#[test]
fn the_fallback_plan_is_the_pre_882_planner_output() {
    for (src, expected) in [
        (
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a, r, b",
            "Projection(a AS a, r AS r, b AS b)\n  \
             NestedLoopJoin\n    \
             NodeByLabelScan(a:P)\n    \
             Optional(nulls=[r, b])\n      \
             ExpandAll(a)-[r:T]->(b)\n        \
             Argument(a)\n",
        ),
        (
            "MATCH (a:P) OPTIONAL MATCH (a)-[r]->(b) RETURN a, r, b",
            "Projection(a AS a, r AS r, b AS b)\n  \
             NestedLoopJoin\n    \
             NodeByLabelScan(a:P)\n    \
             Optional(nulls=[r, b])\n      \
             ExpandAll(a)-[r]->(b)\n        \
             Argument(a)\n",
        ),
        (
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]-(b) RETURN a, r, b",
            "Projection(a AS a, r AS r, b AS b)\n  \
             NestedLoopJoin\n    \
             NodeByLabelScan(a:P)\n    \
             Optional(nulls=[r, b])\n      \
             ExpandAll(a)-[r:T]-(b)\n        \
             Argument(a)\n",
        ),
        (
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WHERE b.x = 1 RETURN a, r, b",
            "Projection(a AS a, r AS r, b AS b)\n  \
             NestedLoopJoin\n    \
             NodeByLabelScan(a:P)\n    \
             Optional(nulls=[r, b])\n      \
             Filter((b.x = 1))\n        \
             ExpandAll(a)-[r:T]->(b)\n          \
             Argument(a)\n",
        ),
        // Two inline predicates, ONE `Filter`: the predicate-pushdown pass (`rmp` #857) merges
        // adjacent filters, and the fusion runs after it, so what it absorbs — and what this
        // reconstruction rebuilds — is the merged conjunction the finished plan really carried. An
        // earlier draft of this task fused before that pass and reconstructed two stacked `Filter`s;
        // the reference below is what caught it.
        (
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b:Q) WHERE b.x = 1 RETURN a, r, b",
            "Projection(a AS a, r AS r, b AS b)\n  \
             NestedLoopJoin\n    \
             NodeByLabelScan(a:P)\n    \
             Optional(nulls=[r, b])\n      \
             Filter((b:Q AND (b.x = 1)))\n        \
             ExpandAll(a)-[r:T]->(b)\n          \
             Argument(a)\n",
        ),
        (
            "MATCH (a:P), (b:Q) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a, b, r",
            "Projection(a AS a, b AS b, r AS r)\n  \
             NestedLoopJoin\n    \
             NestedLoopJoin\n      \
             NodeByLabelScan(a:P)\n      \
             NodeByLabelScan(b:Q)\n    \
             Optional(nulls=[r])\n      \
             ExpandInto(a)-[r:T]->(b)\n        \
             Argument(a, b)\n",
        ),
    ] {
        let fused = compile(src);
        assert!(is_fused(&fused), "`{src}` must fuse:\n{}", fused.root);
        assert_eq!(
            unfused(&fused).root.to_string(),
            expected,
            "the reconstruction is not the pre-#882 plan for `{src}`"
        );
    }
}

/// The fused operator and the plan it replaces declare the **same identifiers** (the `EXPLAIN` /
/// `PROFILE` `identifiers` list) — the check on the bound-variable walk, which had to reproduce the
/// join's left-then-right, Argument-then-expand-then-nulls order rather than a shorter one.
#[test]
fn the_fused_operator_declares_the_same_identifiers_as_the_plan_it_replaces() {
    for src in [
        "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a, r, b",
        "MATCH (a:P), (b:Q) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a, b, r",
        "MATCH (a:P)-[r1:T]->(x) OPTIONAL MATCH (x)-[r2:T]->(c) RETURN a, c",
    ] {
        let fused = compile(src);
        let reference = unfused(&fused);
        let fused_op = find_optional_expand(&fused.root).expect("fused");
        // The replaced subtree is the reference plan's corresponding `NestedLoopJoin`.
        let join = find_by_type(&reference.root, "NestedLoopJoin").expect("reference join");
        assert_eq!(
            fused_op.identifiers(),
            join.identifiers(),
            "identifiers diverge for `{src}`"
        );
    }
}

fn find_by_type<'a>(op: &'a PhysicalOp, ty: &str) -> Option<&'a PhysicalOp> {
    if op.operator_type() == ty {
        return Some(op);
    }
    op.children().into_iter().find_map(|c| find_by_type(c, ty))
}

// =================================================================================================
// 2. Bag equality against the plan it replaces (acceptance criterion 2)
// =================================================================================================

/// The acceptance corpus, one query per named case, each compared row-for-row against the
/// pre-#882 plan over the same graph.
#[test]
fn every_acceptance_case_matches_the_plan_it_replaces() {
    let cases: &[(&str, &str, &[&str])] = &[
        (
            "typed, left-to-right",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a.name AS a, r.w AS w, b.x AS x",
            &["a", "w", "x"],
        ),
        (
            "untyped",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r]->(b) RETURN a.name AS a, r.w AS w, b.x AS x",
            &["a", "w", "x"],
        ),
        (
            "right-to-left (the other direction)",
            "MATCH (a:P) OPTIONAL MATCH (a)<-[r:T]-(b) RETURN a.name AS a, r.w AS w, b.x AS x",
            &["a", "w", "x"],
        ),
        (
            "undirected — both orientations, self-loop once",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]-(b) RETURN a.name AS a, r.w AS w, b.x AS x",
            &["a", "w", "x"],
        ),
        (
            "WHERE inside the OPTIONAL MATCH",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WHERE b.x = 1 \
             RETURN a.name AS a, r.w AS w, b.x AS x",
            &["a", "w", "x"],
        ),
        (
            "WHERE after the OPTIONAL MATCH",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WITH * WHERE b.x = 1 \
             RETURN a.name AS a, r.w AS w, b.x AS x",
            &["a", "w", "x"],
        ),
        (
            "inline label on the far endpoint",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b:Q) RETURN a.name AS a, r.w AS w, b.x AS x",
            &["a", "w", "x"],
        ),
        (
            "inline relationship property map",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T {w: 1}]->(b) RETURN a.name AS a, r.w AS w, b.x AS x",
            &["a", "w", "x"],
        ),
        (
            "predicate correlating the far endpoint with the anchor",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WHERE b.x > a.x \
             RETURN a.name AS a, r.w AS w, b.x AS x",
            &["a", "w", "x"],
        ),
        (
            "expand-into: both endpoints already bound",
            "MATCH (a:P), (b:Q) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a.name AS a, b.x AS x, r.w AS w",
            &["a", "x", "w"],
        ),
        (
            "a relationship bound by an EARLIER clause, reused here",
            "MATCH (a:P)-[r:T]->(m) OPTIONAL MATCH (a)-[r]->(b) \
             RETURN a.name AS a, r.w AS w, b.x AS x",
            &["a", "w", "x"],
        ),
        (
            "the optional hop follows a required hop (driving row carries r1)",
            "MATCH (a:P)-[r1:T]->(m) OPTIONAL MATCH (m)-[r2:T]->(c) \
             RETURN a.name AS a, r1.w AS w1, r2.w AS w2, c.x AS x",
            &["a", "w1", "w2", "x"],
        ),
        (
            "aggregation above the operator",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a.name AS a, count(b) AS n",
            &["a", "n"],
        ),
        (
            "ORDER BY / SKIP / LIMIT above the operator (row order is load-bearing)",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a.name AS a, b.x AS x \
             ORDER BY a.name, b.x SKIP 1 LIMIT 6",
            &["a", "x"],
        ),
    ];
    for (name, src, columns) in cases {
        let rows = assert_fused_matches_fallback(src, columns);
        assert!(!rows.is_empty(), "case `{name}` produced no rows");
    }
}

// =================================================================================================
// 3. The semantics, asserted directly (not only "the same as the old plan")
// =================================================================================================

/// A driving row with **no** match keeps its row, with the introduced variables null — **once**.
#[test]
fn a_driving_row_with_no_match_emits_its_null_row_exactly_once() {
    // `a0` has no relationship at all; `a7` has only a `U`, so a `:T` hop finds nothing for it either.
    let rows = assert_fused_matches_fallback(
        "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a.name AS a, b.x AS x",
        &["a", "x"],
    );
    for driver in ["a0", "a7"] {
        let nulls: Vec<&String> = rows
            .iter()
            .filter(|r| r.starts_with(&format!("String(\"{driver}\")|")))
            .collect();
        assert_eq!(
            nulls.len(),
            1,
            "`{driver}` must contribute exactly one row, got {nulls:?}"
        );
        assert!(
            nulls[0].ends_with("|Null"),
            "`{driver}`'s row must be null-filled, got {:?}",
            nulls[0]
        );
    }
}

/// A driving row with **several** matches emits them all and **no** null row beside them.
#[test]
fn a_driving_row_with_several_matches_emits_no_null_row_beside_them() {
    let rows = assert_fused_matches_fallback(
        "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a.name AS a, r.w AS w",
        &["a", "w"],
    );
    let a2: Vec<&String> = rows
        .iter()
        .filter(|r| r.starts_with("String(\"a2\")|"))
        .collect();
    assert_eq!(a2.len(), 3, "`a2` has three outgoing T, got {a2:?}");
    assert!(
        a2.iter().all(|r| !r.ends_with("|Null")),
        "a matched driving row must not also emit a null row: {a2:?}"
    );
}

/// **TRAP 1.** An undirected hop surfaces each non-self relationship **twice** (once per orientation)
/// and a self-loop **once** (`rmp` #867). The fused operator must reproduce that full multiset, and
/// must emit the null row only when the multiset is empty.
#[test]
fn an_undirected_hop_keeps_both_orientations_and_binds_a_self_loop_once() {
    let rows = assert_fused_matches_fallback(
        "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]-(b) RETURN a.name AS a, r.w AS w",
        &["a", "w"],
    );
    let count = |driver: &str| {
        rows.iter()
            .filter(|r| r.starts_with(&format!("String(\"{driver}\")|")))
            .count()
    };
    // `a3` has ONE self-loop: one row, not two.
    assert_eq!(
        count("a3"),
        1,
        "a self-loop is bound once by an undirected hop"
    );
    // `a4`: two parallel a4->a5 plus one a5->a4 — three distinct relationships, each incident once.
    assert_eq!(count("a4"), 3, "rows for a4: {rows:?}");
    // `a5` sees the same three from the other side.
    assert_eq!(count("a5"), 3, "rows for a5: {rows:?}");
    // And the driving rows that match nothing still appear exactly once.
    assert_eq!(count("a0"), 1);
}

/// **TRAP 2.** `WHERE` **inside** the `OPTIONAL MATCH` belongs to the optional part: a driving row
/// whose only neighbours fail it survives **with nulls**. `WHERE` **after** it filters the result and
/// removes that row. These are different queries and must stay different.
#[test]
fn where_inside_the_optional_match_nulls_a_row_where_where_after_removes_it() {
    let columns = &["a", "x"];
    // Inside: `a2`'s third neighbour (x = 9) fails, its other two pass; `a1`'s single neighbour
    // passes; `a4`/`a5`'s neighbours have x = 4/5 and all fail -> those drivers survive with nulls.
    let inside = assert_fused_matches_fallback(
        "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WHERE b.x = 1 RETURN a.name AS a, b.x AS x",
        columns,
    );
    let after = assert_fused_matches_fallback(
        "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WITH * WHERE b.x = 1 \
         RETURN a.name AS a, b.x AS x",
        columns,
    );
    let has_null_row_for = |rows: &[String], driver: &str| {
        rows.iter()
            .any(|r| r == &format!("String(\"{driver}\")|Null"))
    };
    // `a4` has T neighbours, but none satisfies `b.x = 1`.
    assert!(
        has_null_row_for(&inside, "a4"),
        "a WHERE inside the OPTIONAL MATCH must null the row out, not remove it: {inside:?}"
    );
    assert!(
        !has_null_row_for(&after, "a4"),
        "a WHERE after the OPTIONAL MATCH must REMOVE the row: {after:?}"
    );
    assert_ne!(
        inside, after,
        "inside-WHERE and after-WHERE must not collapse to the same query"
    );
    // The plans differ in exactly the documented way: inside, the predicate is absorbed by the
    // operator; after, it is a `Filter` sitting above it.
    let inside_plan = compile(
        "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WHERE b.x = 1 RETURN a.name AS a, b.x AS x",
    );
    let after_plan = compile(
        "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WITH * WHERE b.x = 1 \
         RETURN a.name AS a, b.x AS x",
    );
    assert!(
        inside_plan.root.to_string().contains("WHERE (b.x = 1)"),
        "the inside predicate must be absorbed:\n{}",
        inside_plan.root
    );
    assert!(
        after_plan.root.to_string().contains("Filter((b.x = 1))")
            && !after_plan.root.to_string().contains("WHERE (b.x = 1)"),
        "the after predicate must stay a Filter above the operator:\n{}",
        after_plan.root
    );
}

/// **TRAP 3.** Relationship isomorphism forbids traversing the same relationship twice **within one
/// pattern**, and does **not** cross a clause boundary. Both halves are checked here, and both are
/// checked against the plan they replace so the answer cannot drift either way.
#[test]
fn relationship_isomorphism_is_preserved_across_the_rewrite() {
    // (a) WITHIN one OPTIONAL MATCH: a two-hop pattern carries a `prior_rels` obligation. The
    //     operator has nowhere to put it, so the shape declines — and still answers correctly
    //     (`r1` and `r2` are never the same relationship).
    let two_hop = assert_declines(
        "MATCH (a:P) OPTIONAL MATCH (a)-[r1:T]-(b)-[r2:T]-(c) RETURN r1.w AS w1, r2.w AS w2",
        &["w1", "w2"],
    );
    assert!(
        two_hop.iter().any(|r| !r.ends_with("|Null")),
        "the two-hop case must actually match something: {two_hop:?}"
    );
    let mut matched_pairs = 0;
    for row in &two_hop {
        // A driving row that matched nothing contributes `Null|Null`; isomorphism has nothing to say
        // about it, and comparing the two nulls would fail for the wrong reason.
        if row.contains("Null") {
            continue;
        }
        matched_pairs += 1;
        let (w1, w2) = row.split_once('|').expect("two columns");
        assert_ne!(
            w1, w2,
            "relationship isomorphism violated within one pattern: {row}"
        );
    }
    assert!(
        matched_pairs > 0,
        "the two-hop case must produce real pairs, else the isomorphism check is vacuous"
    );
    // (b) ACROSS a clause boundary: reuse is legal, so the fused operator must NOT filter it out.
    //     `a4` reaches `a5` on two parallel relationships, so the required hop and the optional hop
    //     can legitimately bind the same relationship.
    let across = assert_fused_matches_fallback(
        "MATCH (a:P)-[r1:T]->(m) OPTIONAL MATCH (a)-[r2:T]->(m) \
         RETURN a.name AS a, r1.w AS w1, r2.w AS w2",
        &["a", "w1", "w2"],
    );
    assert!(
        across
            .iter()
            .any(|r| r.split('|').nth(1) == r.split('|').nth(2)),
        "reuse across a clause boundary is legal and must survive: {across:?}"
    );
}

// =================================================================================================
// 4. Declines (acceptance criterion 3) — each shown to fall back AND to answer correctly
// =================================================================================================

#[test]
fn shapes_the_operator_cannot_express_keep_the_fallback_plan() {
    let cases: &[(&str, &str, &[&str])] = &[
        (
            "two hops: the right side is not a single expand",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r1:T]->(b)-[r2:T]->(c) RETURN a.name AS a, c.x AS x",
            &["a", "x"],
        ),
        (
            "variable length: binds a relationship LIST, not one hop",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T*1..2]->(b) RETURN a.name AS a, b.x AS x",
            &["a", "x"],
        ),
        (
            "named path: introduces a variable the expand does not bind",
            "MATCH (a:P) OPTIONAL MATCH p = (a)-[r:T]->(b) RETURN a.name AS a, length(p) AS l",
            &["a", "l"],
        ),
        (
            "a second, disconnected component inside the OPTIONAL MATCH",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b), (c:Q) RETURN a.name AS a, c.x AS x",
            &["a", "x"],
        ),
        (
            "the anchor is NOT bound by the driving row: a fresh scan, not an Argument",
            "MATCH (a:P) OPTIONAL MATCH (b:Q)-[r:T]->(c) RETURN a.name AS a, c.x AS x",
            &["a", "x"],
        ),
        (
            "a LEADING optional match: nothing is bound to expand from",
            "OPTIONAL MATCH (a:P)-[r:T]->(b) RETURN a.name AS a, b.x AS x",
            &["a", "x"],
        ),
        (
            "an EXISTS subquery predicate: opens its own scope and reads the graph",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WHERE EXISTS { MATCH (b)-[:T]->() } \
             RETURN a.name AS a, b.x AS x",
            &["a", "x"],
        ),
        (
            "a COUNT subquery predicate",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WHERE COUNT { MATCH (b)-[:T]->() } > 0 \
             RETURN a.name AS a, b.x AS x",
            &["a", "x"],
        ),
        (
            "a pattern comprehension predicate",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WHERE size([(b)-[:T]->(z) | z.x]) > 0 \
             RETURN a.name AS a, b.x AS x",
            &["a", "x"],
        ),
        (
            "a list comprehension predicate: binds its own element variable",
            "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WHERE size([q IN [1, 2] WHERE q > b.x]) > 0 \
             RETURN a.name AS a, b.x AS x",
            &["a", "x"],
        ),
        (
            "a predicate over a driving-row column OUTSIDE the pattern",
            "MATCH (a:P) WITH a, 1 AS lim OPTIONAL MATCH (a)-[r:T]->(b) WHERE b.x = lim \
             RETURN a.name AS a, b.x AS x",
            &["a", "x"],
        ),
    ];
    for (name, src, columns) in cases {
        let rows = assert_declines(src, columns);
        assert!(!rows.is_empty(), "decline case `{name}` produced no rows");
    }
}

/// The declined **predicate** shapes still have to be *right*, and the boundary has to be a real one:
/// the same query with the predicate written over the pattern's own variables **does** fuse and
/// returns the same answer.
#[test]
fn the_predicate_boundary_is_real_on_both_sides() {
    // Left of the boundary: `lim` is a driving-row column outside the pattern -> declines.
    let declined = assert_declines(
        "MATCH (a:P) WITH a, 1 AS lim OPTIONAL MATCH (a)-[r:T]->(b) WHERE b.x = lim \
         RETURN a.name AS a, b.x AS x",
        &["a", "x"],
    );
    // Right of it: the same predicate written as a literal is confined to the pattern -> fuses.
    let fused = assert_fused_matches_fallback(
        "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WHERE b.x = 1 RETURN a.name AS a, b.x AS x",
        &["a", "x"],
    );
    assert_eq!(
        declined, fused,
        "the two spellings are the same query; only the plan may differ"
    );
    // And the declined spelling really does null rather than drop — a decline must not quietly change
    // the optional semantics either.
    assert!(
        declined.iter().any(|r| r.ends_with("|Null")),
        "the declined spelling still nulls unmatched drivers: {declined:?}"
    );
}

/// The `prior_rels` gate is not reachable from any query the lowerer produces today (a one-hop
/// optional pattern is always its pattern's first relationship), so it is exercised where it can be:
/// against a hand-built operator, in a crate-internal unit test. This test records **why** the
/// query-level version is absent, so a later reader does not conclude the gate is untested.
#[test]
fn the_prior_rels_gate_is_covered_by_a_unit_test_not_a_query() {
    // A one-hop OPTIONAL MATCH cannot carry a prior relationship of its own pattern: every shape that
    // could is multi-link, and every multi-link shape declines for the single-expand reason first.
    for src in [
        "MATCH (a:P) OPTIONAL MATCH (a)-[r1:T]->(b)-[r2:T]->(c) RETURN a.name AS a",
        "MATCH (a:P) OPTIONAL MATCH (a)-[r1:T]->(b), (a)-[r2:T]->(c) RETURN a.name AS a",
    ] {
        let plan = compile(src);
        assert!(
            !is_fused(&plan),
            "a multi-relationship optional pattern must decline:\n{}",
            plan.root
        );
    }
    // The gate itself is asserted in `physical.rs`'s
    // `a_prior_relationship_obligation_declines_the_fusion`.
}

// =================================================================================================
// 5. TRAP 5 — the read footprint does not narrow, and RBAC composes
// =================================================================================================

/// A [`GraphAccess`] decorator that records **every** read seam call, in order, forwarding verbatim.
///
/// The point is not a count but the whole ordered trace: a footprint that narrowed (a read the fused
/// operator no longer performs) is a phantom under SSI, and a trace comparison catches it whatever
/// its shape — a missing `expand`, a missing property read behind an absorbed predicate, a label
/// check the operator skipped.
struct RecordingGraph<'a> {
    inner: &'a mut MemGraph,
    trace: RefCell<Vec<String>>,
}

impl<'a> RecordingGraph<'a> {
    fn new(inner: &'a mut MemGraph) -> Self {
        Self {
            inner,
            trace: RefCell::new(Vec::new()),
        }
    }
    fn note(&self, what: String) {
        self.trace.borrow_mut().push(what);
    }
}

impl GraphAccess for RecordingGraph<'_> {
    fn scan_nodes(&self) -> Vec<NodeId> {
        self.note("scan_nodes".to_owned());
        self.inner.scan_nodes()
    }
    fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
        self.note(format!("scan_nodes_by_label({label})"));
        self.inner.scan_nodes_by_label(label)
    }
    fn expand(&self, node: NodeId, direction: ExpandDirection, types: &[String]) -> Vec<Incident> {
        self.note(format!("expand({node:?}, {direction:?}, {types:?})"));
        self.inner.expand(node, direction, types)
    }
    fn node_exists(&self, node: NodeId) -> bool {
        self.note(format!("node_exists({node:?})"));
        self.inner.node_exists(node)
    }
    fn rel_exists(&self, rel: RelId) -> bool {
        self.note(format!("rel_exists({rel:?})"));
        self.inner.rel_exists(rel)
    }
    fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
        self.note(format!("node_labels({node:?})"));
        self.inner.node_labels(node)
    }
    fn rel_data(&self, rel: RelId) -> Option<RelData> {
        self.note(format!("rel_data({rel:?})"));
        self.inner.rel_data(rel)
    }
    fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
        self.note(format!("node_property({node:?}, {key})"));
        self.inner.node_property(node, key)
    }
    fn rel_property(&self, rel: RelId, key: &str) -> Option<Value> {
        self.note(format!("rel_property({rel:?}, {key})"));
        self.inner.rel_property(rel, key)
    }
    fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
        self.note(format!("node_properties({node:?})"));
        self.inner.node_properties(node)
    }
    fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
        self.note(format!("rel_properties({rel:?})"));
        self.inner.rel_properties(rel)
    }
    fn incident_rels(&self, node: NodeId) -> Vec<RelId> {
        self.note(format!("incident_rels({node:?})"));
        self.inner.incident_rels(node)
    }
    // ---- writes: forwarded, never exercised by these read-only tests -------------------------
    fn create_node(&mut self, labels: &[String], properties: &[(String, Value)]) -> NodeId {
        self.inner.create_node(labels, properties)
    }
    fn create_rel(
        &mut self,
        rel_type: &str,
        start: NodeId,
        end: NodeId,
        properties: &[(String, Value)],
    ) -> RelId {
        self.inner.create_rel(rel_type, start, end, properties)
    }
    fn set_node_property(&mut self, node: NodeId, key: &str, value: Value) {
        self.inner.set_node_property(node, key, value);
    }
    fn set_rel_property(&mut self, rel: RelId, key: &str, value: Value) {
        self.inner.set_rel_property(rel, key, value);
    }
    fn add_labels(&mut self, node: NodeId, labels: &[String]) {
        self.inner.add_labels(node, labels);
    }
    fn remove_labels(&mut self, node: NodeId, labels: &[String]) {
        self.inner.remove_labels(node, labels);
    }
    fn remove_node_property(&mut self, node: NodeId, key: &str) {
        self.inner.remove_node_property(node, key);
    }
    fn remove_rel_property(&mut self, rel: RelId, key: &str) {
        self.inner.remove_rel_property(rel, key);
    }
    fn replace_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        self.inner.replace_node_properties(node, properties);
    }
    fn merge_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        self.inner.merge_node_properties(node, properties);
    }
    fn replace_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
        self.inner.replace_rel_properties(rel, properties);
    }
    fn merge_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
        self.inner.merge_rel_properties(rel, properties);
    }
    fn delete_rel(&mut self, rel: RelId) {
        self.inner.delete_rel(rel);
    }
    fn delete_node(&mut self, node: NodeId) {
        self.inner.delete_node(node);
    }
}

fn read_trace(plan: &PhysicalPlan) -> Vec<String> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut g = corpus();
    let mut recorder = RecordingGraph::new(&mut g);
    {
        let mut cursor = execute(plan, &bound, &mut recorder).expect("open");
        cursor.collect_all().expect("collect");
    }
    recorder.trace.into_inner()
}

/// **TRAP 5.** The fused operator's read footprint is not narrower than the plan it replaces. It is
/// in fact *identical*, which is the strongest form of the claim and the one the design intends: the
/// operator calls the very same seams, on the very same entities, in the very same order.
#[test]
fn the_read_footprint_is_identical_to_the_plan_it_replaces() {
    for src in [
        "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a.name AS a, b.x AS x",
        "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]-(b) RETURN a.name AS a, b.x AS x",
        "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b:Q) WHERE b.x = 1 RETURN a.name AS a, b.x AS x",
        "MATCH (a:P), (b:Q) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a.name AS a, r.w AS w",
    ] {
        let fused = compile(src);
        assert!(is_fused(&fused), "`{src}` must fuse");
        let reference = unfused(&fused);
        let got = read_trace(&fused);
        let want = read_trace(&reference);
        assert!(
            !want.is_empty(),
            "the reference must actually read the graph for `{src}`"
        );
        assert_eq!(
            got, want,
            "the read footprint changed for `{src}` — a narrower footprint is an SSI phantom"
        );
    }
}

/// A principal that cannot traverse `:Q` sees the same rows through the fused operator as through the
/// plan it replaces: RBAC composes at the seam, and the fusion did not move any read out from under
/// the decorator.
#[test]
fn rbac_composes_identically_over_the_fused_operator() {
    struct DenyQ {
        unrestricted: bool,
    }
    impl PrivilegeOracle for DenyQ {
        fn is_unrestricted(&self) -> bool {
            self.unrestricted
        }
        fn can_traverse_label(&self, label: &str) -> bool {
            self.unrestricted || label != "Q"
        }
        fn can_read_property(&self, label: &str, _property: &str) -> bool {
            self.unrestricted || label != "Q"
        }
        fn can_traverse_rel_type(&self, _rel_type: &str) -> bool {
            true
        }
        fn can_read_rel_property(&self, _rel_type: &str, _property: &str) -> bool {
            true
        }
        fn can_write_label(&self, _label: &str) -> bool {
            true
        }
        fn can_write_rel_type(&self, _rel_type: &str) -> bool {
            true
        }
        fn can_write_property(&self, _label: &str, _property: &str) -> bool {
            true
        }
        fn can_write_rel_property(&self, _rel_type: &str, _property: &str) -> bool {
            true
        }
        fn is_denied_traverse_label(&self, _label: &str) -> bool {
            false
        }
        fn is_denied_read_property(&self, _label: &str, _property: &str) -> bool {
            false
        }
        fn is_denied_write_label(&self, _label: &str) -> bool {
            false
        }
        fn is_denied_write_property(&self, _label: &str, _property: &str) -> bool {
            false
        }
    }

    fn run_authorized(plan: &PhysicalPlan, restricted: bool, columns: &[&str]) -> Vec<String> {
        let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
        let mut g = corpus();
        let mut authz = AuthorizedGraph::new(
            &mut g,
            DenyQ {
                unrestricted: !restricted,
            },
        );
        let mut cursor = execute(plan, &bound, &mut authz).expect("open");
        cursor
            .collect_all()
            .expect("collect")
            .iter()
            .map(|r| render(r, columns))
            .collect()
    }

    let src = "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) RETURN a.name AS a, b.x AS x";
    let columns = &["a", "x"];
    let fused = compile(src);
    assert!(is_fused(&fused), "`{src}` must fuse");
    let reference = unfused(&fused);

    let restricted_fused = run_authorized(&fused, true, columns);
    let restricted_reference = run_authorized(&reference, true, columns);
    assert_eq!(
        restricted_fused, restricted_reference,
        "RBAC must compose identically over the fused operator"
    );

    // Non-vacuity: the restriction must actually bite, or this proves nothing.
    let open_fused = run_authorized(&fused, false, columns);
    assert_eq!(
        open_fused,
        run_authorized(&reference, false, columns),
        "the unrestricted principal must also agree"
    );
    assert_ne!(
        restricted_fused, open_fused,
        "the `:Q` restriction must change the result, else the RBAC comparison is vacuous"
    );
}

/// `EXPLAIN` and `PROFILE` describe the operator honestly: it appears under its own operator type,
/// with the identifiers it binds, and — under `PROFILE` — with real row and `dbHits` counters. A
/// plan a client cannot see is a plan a client cannot debug, and the `dbHits` are the check that the
/// operator did not quietly stop charging for the reads it performs.
#[test]
fn explain_and_profile_describe_the_fused_operator() {
    use graphus_cypher::plan_description::{PlanDescription, PlanNode};

    fn find<'a>(node: &'a PlanNode, ty: &str) -> Option<&'a PlanNode> {
        if node.operator_type == ty {
            return Some(node);
        }
        node.children.iter().find_map(|c| find(c, ty))
    }

    let src =
        "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WHERE b.x = 1 RETURN a.name AS a, b.x AS x";
    let plan = compile(src);
    assert!(is_fused(&plan), "`{src}` must fuse:\n{}", plan.root);

    // EXPLAIN: the operator is named, its identifiers are the ones it binds, and the absorbed
    // predicate is visible in the rendering (it is no longer a `Filter` a reader could see).
    let explained = PlanDescription::explain(&plan);
    let node = find(explained.root(), "OptionalExpandAll")
        .expect("the fused operator must appear in the plan description");
    assert!(
        node.identifiers.contains(&"a".to_owned())
            && node.identifiers.contains(&"r".to_owned())
            && node.identifiers.contains(&"b".to_owned()),
        "identifiers: {:?}",
        node.identifiers
    );
    assert!(
        plan.root.to_string().contains("WHERE (b.x = 1)"),
        "the absorbed predicate must stay visible:\n{}",
        plan.root
    );

    // PROFILE: real counters, and they are the same ones the plan it replaces reports.
    let profiled = |plan: &PhysicalPlan, ty: &str| -> (u64, u64) {
        let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
        let mut g = corpus();
        let mut cursor = execute(plan, &bound, &mut g).expect("open profiled");
        cursor.collect_all().expect("collect");
        let desc =
            PlanDescription::profile(cursor.profile().expect("a PROFILEd plan has a recorder"));
        let node = find(desc.root(), ty).unwrap_or_else(|| panic!("no `{ty}` in the profile"));
        (node.rows.expect("rows"), node.db_hits.expect("dbHits"))
    };
    let profile_plan = compile(&format!("PROFILE {src}"));
    let (fused_rows, fused_hits) = profiled(&profile_plan, "OptionalExpandAll");
    // The replaced subtree reports its rows on the `Optional` that guaranteed them, and its reads are
    // spread over the join's right branch; the join's own row count is the comparable number.
    let (join_rows, _) = profiled(&unfused(&profile_plan), "NestedLoopJoin");
    assert_eq!(
        fused_rows, join_rows,
        "the fused operator must emit exactly the rows the join it replaces emitted"
    );
    assert!(
        fused_hits > 0,
        "the operator must charge for the reads it performs, or PROFILE lies about the access path"
    );
}

// =================================================================================================
// 6. Parameters absorbed with the predicates
// =================================================================================================

/// A `$param` inside the `OPTIONAL MATCH`'s `WHERE` is absorbed into the operator, so the parameter
/// walk must find it there. If it did not, `bind_parameters` would neither require nor bind the
/// parameter — the query would silently run with it unbound.
#[test]
fn a_parameter_inside_the_absorbed_predicate_is_still_bound() {
    let src = "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) WHERE b.x = $want \
               RETURN a.name AS a, b.x AS x";
    let plan = compile(src);
    assert!(is_fused(&plan), "`{src}` must fuse:\n{}", plan.root);

    // 1. Omitting it is an error — the operator declared the expectation.
    match bind_parameters(&plan, &Parameters::new()) {
        Err(BindError::MissingParameter { name }) => assert_eq!(name, "want"),
        other => panic!("an absorbed `$want` must still be required, got {other:?}"),
    }

    // 2. Supplying it produces exactly the rows the plan it replaces produces.
    let mut params = Parameters::new();
    params.insert("want".to_owned(), Value::Integer(1));
    assert_fused_matches_fallback_with(src, &["a", "x"], &params);
}

// =================================================================================================
// 7. Acceptance criterion 1, second half: measurably faster
// =================================================================================================

/// Times the fused plan against the plan it replaces over the **real record store**, and prints the
/// speedup.
///
/// The store, not `MemGraph`, is the load-bearing choice: `MemGraph::expand` scans *every*
/// relationship on every call, so on any graph large enough to time it the traversal dwarfs
/// everything else and the measurement says nothing about the operator. `RecordStoreGraph` walks the
/// incidence chain — `O(degree)` per anchor, as production does — so what is left to measure is the
/// per-driving-row machinery this task removes: rebuilding the right branch (allocating an operator
/// tree, projecting an `Argument` row, and re-resolving the relationship-type names the `rmp` #371
/// hoist was supposed to lift out of the row loop), and one full `merge_rows` row clone per output
/// row.
///
/// The assertion is only that the fused plan is not slower; a wall-clock ratio on a shared machine is
/// not a reproducible constant. The number itself is printed (`--nocapture`) and recorded in the task
/// summary.
#[test]
fn the_fused_plan_is_faster_than_the_plan_it_replaces() {
    use graphus_cypher::coordinator::TxnCoordinator;
    use graphus_io::MemBlockDevice;
    use graphus_storage::RecordStore;
    use graphus_wal::{MemLogSink, WalManager};
    use std::time::Instant;

    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: RecordStore<MemBlockDevice, MemLogSink> =
        RecordStore::create(device, wal, 4096, 1).expect("create store");
    let mut coord = TxnCoordinator::new(store);

    // 20 000 driving rows; four in five have three `:T` neighbours, one in five has none — so the
    // null path is exercised alongside the match path, in the proportion a real left-outer join sees.
    let seed = "UNWIND range(0, 19999) AS i \
                CREATE (a:P {x: i}) \
                WITH a, a.x AS i WHERE i % 5 <> 0 \
                UNWIND range(0, 2) AS k \
                CREATE (a)-[:T {w: k}]->(:Q {x: i + k})";
    let plan = compile(seed);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open seed");
        cursor.collect_all().expect("seed");
        assert!(graph.take_error().is_none(), "seed captured an error");
    }
    coord.commit(txn).expect("commit seed");

    let src = "MATCH (a:P) OPTIONAL MATCH (a)-[r:T]->(b) RETURN count(b) AS n";
    let fused = compile(src);
    assert!(is_fused(&fused), "`{src}` must fuse:\n{}", fused.root);
    let reference = unfused(&fused);

    let run = |coord: &mut TxnCoordinator<MemBlockDevice, MemLogSink>, plan: &PhysicalPlan| {
        let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
        let txn = coord.begin_serializable();
        let out = {
            let mut graph = coord.statement(txn).expect("statement");
            let rows = {
                let mut cursor = execute(plan, &bound, &mut graph).expect("open");
                cursor.collect_all().expect("collect")
            };
            assert!(graph.take_error().is_none(), "captured an error");
            rows.iter().map(|r| render(r, &["n"])).collect::<Vec<_>>()
        };
        let _ = coord.rollback(txn);
        out
    };

    // Warm both paths, and check they agree before timing anything: a timing comparison between two
    // plans that compute different things measures nothing.
    let warm_fused = run(&mut coord, &fused);
    assert_eq!(
        warm_fused,
        run(&mut coord, &reference),
        "the two plans must agree"
    );
    assert_eq!(
        warm_fused,
        vec!["Integer(48000)".to_owned()],
        "the benchmark must actually expand 48000 relationships"
    );

    const REPS: u32 = 3;
    let mut fused_ns = u128::MAX;
    let mut reference_ns = u128::MAX;
    for _ in 0..REPS {
        let t = Instant::now();
        let _ = run(&mut coord, &reference);
        reference_ns = reference_ns.min(t.elapsed().as_nanos());
        let t = Instant::now();
        let _ = run(&mut coord, &fused);
        fused_ns = fused_ns.min(t.elapsed().as_nanos());
    }
    let speedup = reference_ns as f64 / fused_ns as f64;
    println!(
        "rmp #882 OptionalExpand: 20000 driving rows, 48000 expansions, best of {REPS} -- \
         Apply/Optional {:.1} ms, OptionalExpand {:.1} ms, speedup {speedup:.2}x",
        reference_ns as f64 / 1e6,
        fused_ns as f64 / 1e6,
    );
    assert!(
        speedup > 1.0,
        "the fused plan must not be slower than the plan it replaces (got {speedup:.2}x)"
    );
}
