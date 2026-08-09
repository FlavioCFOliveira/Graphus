//! **Semi-join operators for `EXISTS` / `NOT EXISTS` subqueries** (`rmp` task #869).
//!
//! `WHERE EXISTS { … }` planned as `Filter(EXISTS{...})` — one opaque predicate over a scan. The
//! subquery could not be costed, could not drive the leaf access-path choice and could not
//! short-circuit; worse, the *pattern* form never reached the planner at all, so
//! `EXISTS { (u:USER {uidn: 1}) }` scanned the whole `USER` label per outer row even with an ONLINE
//! index on `USER.uidn`. `PhysicalOp::SemiApply` makes the subquery an ordinary correlated branch,
//! planned against the real `IndexCatalog`, and stops it at its first row.
//!
//! # How the comparison is made non-vacuous
//!
//! Almost every test below runs the query **twice**: once through the planner's plan (which must
//! contain the semi-join — asserted) and once through the plan reconstructed by
//! [`PhysicalOp::fallback_plan`](graphus_cypher::physical::PhysicalOp::fallback_plan), which rebuilds
//! the exact `Filter`-over-opaque-`EXISTS` the planner produced **before** this task — and which
//! therefore executes the pre-#869 expression-evaluator path. That reconstruction is not taken on
//! trust: [`the_unrewritten_plan_is_the_pre_869_planner_output`] pins it against plan text captured
//! from the pre-change planner (at `0af3422`) and recorded verbatim in this file. So "the bags agree"
//! means the new operator agrees with the code it replaced, executed here, and not with an
//! expectation re-derived by the test author.

use graphus_core::Value;
use graphus_cypher::authorized_graph::{AuthorizedGraph, PrivilegeOracle};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{
    ExpandDirection, GraphAccess, Incident, MemGraph, NodeId, RelData, RelId,
};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, plan_physical};
use graphus_cypher::plan_description::{PlanDescription, PlanNode};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;

// =================================================================================================
// Harness
// =================================================================================================

fn compile_with(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let validated = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    plan_physical(&lower(&validated), catalog).with_prefix(ast.prefix())
}

fn compile(src: &str) -> PhysicalPlan {
    compile_with(src, &IndexCatalog::empty())
}

/// The same plan with **every** [`PhysicalOp::SemiApply`] replaced by the `Filter` it consumed — i.e.
/// the plan the planner produced before #869, which executes the opaque-predicate path.
///
/// Bottom-up, so a nested semi-join (an `EXISTS` inside an `EXISTS`) is recovered too.
fn unrewritten(plan: &PhysicalPlan) -> PhysicalPlan {
    fn go(mut op: PhysicalOp) -> PhysicalOp {
        for child in op.children_mut() {
            let taken = std::mem::replace(child, PhysicalOp::Empty);
            *child = go(taken);
        }
        match op {
            // Only the semi-join is un-rewritten here: `fallback_plan` also answers for #882's
            // `OptionalExpand`, and un-fusing that too would compare against a plan neither task
            // produced.
            PhysicalOp::SemiApply { .. } => op.fallback_plan().expect("SemiApply has an inverse"),
            other => other,
        }
    }
    let mut out = plan.clone();
    out.root = go(plan.root.clone());
    out
}

fn is_rewritten(plan: &PhysicalPlan) -> bool {
    let text = plan.root.to_string();
    text.contains("SemiApply") || text.contains("AntiSemiApply")
}

/// The corpus, built so each driving node lands on a **different** acceptance case, and so that the
/// structures three-valued logic and relationship isomorphism turn on are all present at once.
///
/// | node | what it contributes                                                                  |
/// |------|--------------------------------------------------------------------------------------|
/// | `a0` | no relationship at all — `EXISTS` false, `NOT EXISTS` true                            |
/// | `a1` | exactly one outgoing `T` to a `:Q`                                                    |
/// | `a2` | **three** outgoing `T`, only one to a `:Q` — the short-circuit case (one is enough)   |
/// | `a3` | a `T` **self-loop**                                                                   |
/// | `a4` | two **parallel** `T` to `a5`, plus a `T` back from `a5`                               |
/// | `a5` | reached only by `a4` — has one outgoing `T`                                           |
/// | `a6` | only an **incoming** `T`, so `->` finds nothing and `<-` finds one                    |
/// | `a7` | only a `U`, so a typed `:T` hop finds nothing                                         |
/// | `a8` | `k` is **missing** — a predicate over it is `NULL`, never `FALSE`                     |
fn corpus() -> MemGraph {
    let mut g = MemGraph::new();
    let p = |g: &mut MemGraph, name: &str, k: Option<i64>| {
        let mut props = vec![("n", Value::String(name.to_owned()))];
        if let Some(k) = k {
            props.push(("k", Value::Integer(k)));
        }
        g.add_node(["P"], props)
    };
    let a0 = p(&mut g, "a0", Some(0));
    let a1 = p(&mut g, "a1", Some(1));
    let a2 = p(&mut g, "a2", Some(2));
    let a3 = p(&mut g, "a3", Some(3));
    let a4 = p(&mut g, "a4", Some(4));
    let a5 = p(&mut g, "a5", Some(5));
    let a6 = p(&mut g, "a6", Some(6));
    let a7 = p(&mut g, "a7", Some(7));
    let _a8 = p(&mut g, "a8", None);
    let q1 = g.add_node(
        ["Q"],
        [("n", Value::String("q1".into())), ("k", Value::Integer(1))],
    );
    let r1 = g.add_node(
        ["R"],
        [("n", Value::String("r1".into())), ("k", Value::Integer(9))],
    );

    let _ = a0;
    g.add_rel("T", a1, q1, [("w", Value::Integer(1))]);
    g.add_rel("T", a2, q1, [("w", Value::Integer(2))]);
    g.add_rel("T", a2, r1, [("w", Value::Integer(3))]);
    g.add_rel("T", a2, a7, [("w", Value::Integer(4))]);
    g.add_rel("T", a3, a3, [("w", Value::Integer(5))]);
    g.add_rel("T", a4, a5, [("w", Value::Integer(6))]);
    g.add_rel("T", a4, a5, [("w", Value::Integer(7))]);
    g.add_rel("T", a5, a4, [("w", Value::Integer(8))]);
    g.add_rel("T", r1, a6, [("w", Value::Integer(9))]); // a6 has ONLY an incoming T
    g.add_rel("U", a7, q1, [("w", Value::Integer(10))]);
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
/// Order is kept (not sorted) deliberately: the operator claims to reproduce the replaced plan's rows
/// *and their order*, which is strictly stronger than bag equality and is what makes a downstream
/// `SKIP`/`LIMIT` without `ORDER BY` behave identically.
fn rows_of(plan: &PhysicalPlan, columns: &[&str]) -> Vec<String> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut g = corpus();
    let mut cursor = execute(plan, &bound, &mut g).expect("open cursor");
    cursor
        .collect_all()
        .expect("collect")
        .iter()
        .map(|r| render(r, columns))
        .collect()
}

/// The load-bearing comparison: the rewritten plan and the plan it replaced produce the **same rows
/// in the same order**, and the query is not trivially empty.
fn assert_matches_unrewritten(src: &str, columns: &[&str]) -> Vec<String> {
    let rewritten = compile(src);
    assert!(
        is_rewritten(&rewritten),
        "`{src}` must plan as a semi-join, else this comparison is vacuous:\n{}",
        rewritten.root
    );
    let reference = unrewritten(&rewritten);
    assert!(
        !is_rewritten(&reference),
        "the reference plan must NOT contain the semi-join:\n{}",
        reference.root
    );
    assert!(
        reference.root.to_string().contains("EXISTS{...}"),
        "the reference must be the opaque-predicate plan:\n{}",
        reference.root
    );
    let got = rows_of(&rewritten, columns);
    let want = rows_of(&reference, columns);
    assert!(
        !want.is_empty(),
        "the corpus must produce rows for `{src}`, else the comparison is vacuous"
    );
    assert_eq!(
        got, want,
        "the semi-join changed the result for `{src}`\n  rewritten:\n{}\n  reference:\n{}",
        rewritten.root, reference.root
    );
    got
}

/// Runs a query that must **decline** the rewrite, asserting the decline and returning its rows.
///
/// The rows are returned so every decline test also checks the *answer* — a decline that produced the
/// wrong result would otherwise pass unnoticed.
fn assert_declines(src: &str, columns: &[&str], fallback_marker: &str) -> Vec<String> {
    let plan = compile(src);
    assert!(
        !is_rewritten(&plan),
        "`{src}` must NOT be rewritten — the operator cannot express it:\n{}",
        plan.root
    );
    assert!(
        plan.root.to_string().contains(fallback_marker),
        "`{src}` must keep the opaque-predicate fallback (`{fallback_marker}`):\n{}",
        plan.root
    );
    rows_of(&plan, columns)
}

fn find<'p>(n: &'p PlanNode, want: &str) -> Option<&'p PlanNode> {
    if n.operator_type == want {
        return Some(n);
    }
    n.children.iter().find_map(|c| find(c, want))
}

// =================================================================================================
// 1. The operator is planned, and the reference it is compared against is the real pre-#869 plan
// =================================================================================================

/// Acceptance criterion, first half: both spellings and both subquery forms are recognised, and the
/// inner pattern is visible in the plan rather than being an opaque `EXISTS{...}` token.
#[test]
fn a_where_exists_conjunct_plans_as_a_semi_join() {
    for (src, expected) in [
        (
            "MATCH (u:P) WHERE EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n",
            "SemiApply",
        ),
        (
            "MATCH (u:P) WHERE NOT EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n",
            "AntiSemiApply",
        ),
        (
            "MATCH (u:P) WHERE EXISTS { MATCH (u)-[:T]->(:Q) RETURN 1 } RETURN u.n AS n",
            "SemiApply",
        ),
        (
            "MATCH (u:P) WHERE NOT EXISTS { MATCH (u)-[:T]->(:Q) RETURN 1 } RETURN u.n AS n",
            "AntiSemiApply",
        ),
        // A bare pattern predicate desugars to the same AST node and takes the same path.
        (
            "MATCH (u:P) WHERE (u)-[:T]->() RETURN u.n AS n",
            "SemiApply",
        ),
    ] {
        let plan = compile(src);
        let text = plan.root.to_string();
        assert!(
            text.contains(expected),
            "`{src}` must plan as {expected}:\n{text}"
        );
        assert!(
            !text.contains("EXISTS{...}"),
            "`{src}` must not keep the opaque predicate:\n{text}"
        );
        // The subquery's own access path is now an operator a reader can see.
        assert!(
            text.contains("ExpandAll") || text.contains("ExpandInto"),
            "`{src}` must show the inner pattern's expand:\n{text}"
        );
        assert!(
            text.contains("Argument("),
            "`{src}`'s inner branch must be correlated through an Argument leaf:\n{text}"
        );
    }
}

/// The reference plan every equivalence test compares against is the **real** pre-#869 planner
/// output, not a hand-written approximation.
///
/// The expected strings were captured by running `plan_physical` at `0af3422` — the commit before
/// this task — and are recorded here verbatim. If `fallback_plan` ever stopped being an exact
/// inverse, this test is what notices.
#[test]
fn the_unrewritten_plan_is_the_pre_869_planner_output() {
    for (src, expected) in [
        (
            "MATCH (u:P) WHERE EXISTS { (u)-[:T]->(:P) } RETURN count(*)",
            "Aggregation(keys=[], aggs=[count(*) AS count(*)])\n  Filter(EXISTS{...})\n    NodeByLabelScan(u:P)\n",
        ),
        (
            "MATCH (u:P) WHERE NOT EXISTS { (u)-[:T]->(:P) } RETURN count(*)",
            "Aggregation(keys=[], aggs=[count(*) AS count(*)])\n  Filter(NOT EXISTS{...})\n    NodeByLabelScan(u:P)\n",
        ),
        (
            "MATCH (u:P) WHERE EXISTS { MATCH (u)-[:T]->(:P) RETURN 1 } RETURN count(*)",
            "Aggregation(keys=[], aggs=[count(*) AS count(*)])\n  Filter(EXISTS{...})\n    NodeByLabelScan(u:P)\n",
        ),
        (
            "MATCH (u:P) WHERE u.n = 'a' AND EXISTS { (u)-[:T]->(:P) } RETURN count(*)",
            "Aggregation(keys=[], aggs=[count(*) AS count(*)])\n  Filter(EXISTS{...})\n    NodeLabelScanEq(u:P n = 'a')\n",
        ),
        (
            "MATCH (u:P) WHERE EXISTS { (u)-[:T]->(:P) } AND u.n = 'a' RETURN count(*)",
            "Aggregation(keys=[], aggs=[count(*) AS count(*)])\n  Filter(EXISTS{...})\n    NodeLabelScanEq(u:P n = 'a')\n",
        ),
        (
            "MATCH (u:P) WITH u WHERE EXISTS { (u)-[:T]->(:P) } RETURN count(*)",
            "Aggregation(keys=[], aggs=[count(*) AS count(*)])\n  Projection(u AS u)\n    Filter(EXISTS{...})\n      NodeByLabelScan(u:P)\n",
        ),
    ] {
        let rewritten = compile(src);
        assert!(
            is_rewritten(&rewritten),
            "`{src}` must be rewritten, else this pin proves nothing:\n{}",
            rewritten.root
        );
        assert_eq!(
            unrewritten(&rewritten).root.to_string(),
            expected,
            "un-rewriting `{src}` must reproduce the pre-#869 planner output"
        );
    }
}

// =================================================================================================
// 2. Bag equivalence with the plan it replaced, over the corpus
// =================================================================================================

/// The corpus is chosen so each shape lands on several different driving rows at once — a self-loop,
/// parallel edges, an incoming-only node, a typed-hop miss and a node with a missing property.
#[test]
fn the_semi_join_returns_exactly_what_the_opaque_predicate_returned() {
    for src in [
        "MATCH (u:P) WHERE EXISTS { (u)-[:T]->() } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (u)<-[:T]-() } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (u)-[:T]-() } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (u)-[r:T]->(v) WHERE v.k = 1 } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (u)-[:T {w: 5}]->() } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (u)-[:T]->({n: 'q1'}) } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (u)-[:T]->()-[:T]->() } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (u)-[:T*1..2]->() } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { p = (u)-[:T]->() } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (:R)-[:T]->() } RETURN u.n AS n",
        "MATCH (u:P) WHERE NOT EXISTS { (u)-[:T]->() } RETURN u.n AS n",
        "MATCH (u:P) WHERE NOT EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { MATCH (u)-[:T]->(v) RETURN v } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { MATCH (u)-[:T]->(v) WHERE v.k = 1 RETURN v } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { MATCH (u)-[:T]->(v) RETURN v LIMIT 1 } RETURN u.n AS n",
        // An aggregating inner RETURN yields one row even for an empty match, so EXISTS is always
        // true — a shape whose answer would be wrong if the branch were treated as "the pattern".
        "MATCH (u:P) WHERE EXISTS { MATCH (u)-[:T]->(v:NOSUCH) RETURN count(*) } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { MATCH (u)-[:T]->(v) WITH v WHERE v.k = 1 RETURN v } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { MATCH (u)-[:T]->(v) RETURN v UNION MATCH (u)-[:U]->(v) RETURN v } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { MATCH (u)-[:T]->(v) RETURN v ORDER BY v.k SKIP 1 } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (u)-[:T]->() } AND NOT EXISTS { (u)-[:U]->() } RETURN u.n AS n",
        "MATCH (u:P) WHERE NOT EXISTS { (u)-[:U]->() } AND EXISTS { (u)-[:T]->() } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (u)-[:T]->(v) WHERE EXISTS { (v)-[:T]->() } } RETURN u.n AS n",
        "MATCH (u:P) WHERE (u)-[:T]->() RETURN u.n AS n",
        "MATCH (u:P)-[:T]->(v) WHERE EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n, v.n AS m",
        "MATCH (u:P) WITH u WHERE EXISTS { (u)-[:T]->() } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (u)-[:T]->() } RETURN u.n AS n ORDER BY n DESC",
        "MATCH (u:P) WHERE EXISTS { (u)-[:T]->() } RETURN count(*) AS n",
        // Comma-separated parts, where relationship isomorphism spans the whole subquery pattern.
        "MATCH (u:P) WHERE EXISTS { (u)-[r1:T]->(), (u)-[r2:T]->() } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (u)-[r1:T]->(m), (m)-[r2:T]->(u) } RETURN u.n AS n",
    ] {
        let columns: Vec<&str> = if src.contains("AS m") {
            vec!["n", "m"]
        } else {
            vec!["n"]
        };
        assert_matches_unrewritten(src, &columns);
    }
}

/// The corpus must actually discriminate: an `EXISTS` that no driving row satisfies and one that
/// every driving row satisfies would both pass a naive comparison. These pin the exact answers.
#[test]
fn the_corpus_answers_are_the_hand_derived_ones() {
    // a1..a5 have an outgoing T (a5 -> a4); a0, a6, a7, a8 do not.
    assert_eq!(
        assert_matches_unrewritten(
            "MATCH (u:P) WHERE EXISTS { (u)-[:T]->() } RETURN u.n AS n",
            &["n"]
        ),
        vec![
            "String(\"a1\")",
            "String(\"a2\")",
            "String(\"a3\")",
            "String(\"a4\")",
            "String(\"a5\")",
        ]
    );
    // The exact complement — nothing is lost and nothing is counted twice.
    assert_eq!(
        assert_matches_unrewritten(
            "MATCH (u:P) WHERE NOT EXISTS { (u)-[:T]->() } RETURN u.n AS n",
            &["n"]
        ),
        vec![
            "String(\"a0\")",
            "String(\"a6\")",
            "String(\"a7\")",
            "String(\"a8\")",
        ]
    );
    // Only a1 and a2 reach a :Q.
    assert_eq!(
        assert_matches_unrewritten(
            "MATCH (u:P) WHERE EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n",
            &["n"]
        ),
        vec!["String(\"a1\")", "String(\"a2\")"]
    );
}

/// `EXISTS` is two-valued, so `SemiApply` and `AntiSemiApply` **partition** the driving rows: every
/// row is kept by exactly one of them. That is the property `anti: bool` rests on, and it is the
/// reason an anti-semi-join is a legal negation *here* even though it is not one in general.
#[test]
fn semi_and_anti_partition_the_driving_rows() {
    for body in [
        "(u)-[:T]->()",
        "(u)-[:T]->(:Q)",
        "(u)-[r:T]->(v) WHERE v.k > 100",
        // The inner predicate is NULL for every candidate: still FALSE overall, never NULL.
        "(u)-[r:T]->(v) WHERE v.missing = 1",
        "(u)-[:NOSUCHTYPE]->()",
    ] {
        let semi = rows_of(
            &compile(&format!(
                "MATCH (u:P) WHERE EXISTS {{ {body} }} RETURN u.n AS n"
            )),
            &["n"],
        );
        let anti = rows_of(
            &compile(&format!(
                "MATCH (u:P) WHERE NOT EXISTS {{ {body} }} RETURN u.n AS n"
            )),
            &["n"],
        );
        let all = rows_of(&compile("MATCH (u:P) RETURN u.n AS n"), &["n"]);
        assert_eq!(
            semi.len() + anti.len(),
            all.len(),
            "`{body}`: semi ({semi:?}) and anti ({anti:?}) must partition {all:?}"
        );
        for row in &semi {
            assert!(!anti.contains(row), "`{body}`: {row} kept by both sides");
        }
        let mut union: Vec<&String> = semi.iter().chain(anti.iter()).collect();
        union.sort();
        let mut want: Vec<&String> = all.iter().collect();
        want.sort();
        assert_eq!(union, want, "`{body}`: the union must be every driving row");
    }
}

/// A subquery-local variable must never escape into the outer scope: the semi-join emits its driving
/// row unchanged. `RETURN *` is the sharpest way to ask.
#[test]
fn the_inner_branch_binds_nothing_in_the_outer_scope() {
    let plan = compile("MATCH (u:P) WHERE EXISTS { (u)-[r:T]->(v) } RETURN *");
    assert!(is_rewritten(&plan));
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut g = corpus();
    let rows = execute(&plan, &bound, &mut g)
        .expect("open")
        .collect_all()
        .expect("collect");
    assert!(!rows.is_empty(), "the corpus must produce rows");
    for row in &rows {
        assert_eq!(
            row.columns(),
            &["u".to_owned()],
            "only the driving column may survive a semi-join"
        );
    }
    // The operator's own identifier list says the same thing, which is what a client reads back.
    let semi = find(
        PlanDescription::explain(&compile(
            "EXPLAIN MATCH (u:P) WHERE EXISTS { (u)-[r:T]->(v) } RETURN *",
        ))
        .root(),
        "SemiApply",
    )
    .expect("the plan contains a SemiApply")
    .clone();
    assert_eq!(semi.identifiers, vec!["u".to_owned()]);
}

/// The previous test observes the row a `RETURN *` produced, which a `Projection` had already narrowed
/// to the plan's declared columns — so it cannot tell a semi-join that *merges* the inner row from one
/// that does not. This one observes the **operator's own output**, by executing a plan whose root IS
/// the semi-join, and pins both halves of the contract at once: the row it emits, and the columns the
/// cursor declares for it.
#[test]
fn the_operator_itself_emits_the_driving_row_unchanged() {
    let full = compile("MATCH (u:P)-[e:T]->(w) WHERE EXISTS { (u)-[:T]->(v) } RETURN u");
    assert!(is_rewritten(&full));
    // Strip everything above the semi-join, so nothing downstream can narrow or rename its output.
    fn find_semi(op: &PhysicalOp) -> Option<&PhysicalOp> {
        if matches!(op, PhysicalOp::SemiApply { .. }) {
            return Some(op);
        }
        op.children().into_iter().find_map(find_semi)
    }
    let mut bare = full.clone();
    bare.root = find_semi(&full.root)
        .expect("the plan contains a SemiApply")
        .clone();

    let bound = bind_parameters(&bare, &Parameters::new()).expect("bind");
    let mut g = corpus();
    let mut cursor = execute(&bare, &bound, &mut g).expect("open");
    let declared = cursor.columns().to_vec();
    let rows = cursor.collect_all().expect("collect");

    assert!(!rows.is_empty(), "the corpus must drive the operator");
    // The driving relation binds `u`, `e` and `w`; the subquery binds `v`, which must appear in
    // neither the declared columns nor any emitted row.
    assert_eq!(
        declared,
        vec!["u".to_owned(), "e".to_owned(), "w".to_owned()],
        "the cursor must declare the driving columns and only those"
    );
    for row in &rows {
        assert_eq!(
            row.columns(),
            &["u".to_owned(), "e".to_owned(), "w".to_owned()],
            "the emitted row must be the driving row, with nothing merged in from the branch"
        );
    }
}

// =================================================================================================
// 3. Acceptance criterion: an indexed predicate inside the subquery becomes a seek
// =================================================================================================

/// The headline acceptance criterion. `EXISTS { (u:P {k: 1}) }` used to scan the whole `:P` label per
/// outer row — the interpreter had no access to the catalogue at all. With the subquery planned as an
/// ordinary branch against the **real** catalogue, it seeks.
#[test]
fn an_indexed_predicate_inside_exists_plans_a_seek() {
    let catalog = IndexCatalog::builder()
        .with_label_property("P", "k")
        .build();
    for src in [
        "MATCH (v:Q) WHERE EXISTS { (u:P {k: 1})-[:T]->(v) } RETURN count(*)",
        "MATCH (v:Q) WHERE EXISTS { MATCH (u:P {k: 1})-[:T]->(v) RETURN 1 } RETURN count(*)",
        "MATCH (v:Q) WHERE EXISTS { (u:P)-[:T]->(v) WHERE u.k = 1 } RETURN count(*)",
    ] {
        let text = compile_with(src, &catalog).root.to_string();
        assert!(
            text.contains("NodeIndexSeek(u:P k = 1"),
            "`{src}` must seek the index inside the subquery:\n{text}"
        );
        // …and the same query with no index declared must NOT, or the assertion above would pass for
        // a reason unrelated to the catalogue reaching the subquery.
        let unindexed = compile(src).root.to_string();
        assert!(
            !unindexed.contains("NodeIndexSeek"),
            "`{src}` without a catalogue must not seek:\n{unindexed}"
        );
    }
}

/// The index a subquery seek depends on must be recorded as a plan dependency, or dropping that index
/// would leave a cached plan pointing at a structure that no longer exists.
#[test]
fn an_index_used_only_inside_a_subquery_is_recorded_as_a_dependency() {
    let catalog = IndexCatalog::builder()
        .with_label_property("P", "k")
        .build();
    let plan = compile_with(
        "MATCH (v:Q) WHERE EXISTS { (u:P {k: 1})-[:T]->(v) } RETURN count(*)",
        &catalog,
    );
    assert!(
        plan.root.to_string().contains("NodeIndexSeek"),
        "the seek must be planned, else this test is vacuous"
    );
    assert!(
        plan.index_dependencies().count() > 0,
        "the subquery's index must be a dependency of the whole plan"
    );

    // The cost-based path does not reuse the dependencies gathered during lowering — it RECOMPUTES
    // them from the final tree (`collect_index_dependencies`). That is a second, independent place the
    // subquery's index must be visible, and it is only exercised when statistics are supplied.
    struct Stats;
    impl graphus_cypher::statistics::Statistics for Stats {
        fn total_nodes(&self) -> u64 {
            1000
        }
        fn nodes_with_label(&self, _label: &str) -> Option<u64> {
            Some(500)
        }
        fn total_relationships(&self) -> u64 {
            1000
        }
        fn relationships_with_type(&self, _rel_type: &str) -> Option<u64> {
            Some(500)
        }
    }
    let toks = tokenize("MATCH (v:Q) WHERE EXISTS { (u:P {k: 1})-[:T]->(v) } RETURN count(*)")
        .expect("lex");
    let ast = parse_tokens(
        &toks,
        "MATCH (v:Q) WHERE EXISTS { (u:P {k: 1})-[:T]->(v) } RETURN count(*)",
    )
    .expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let costed = graphus_cypher::physical::plan_physical_with_stats(
        &lower(&validated),
        &catalog,
        Some(&Stats),
    );
    assert!(
        costed.root.to_string().contains("NodeIndexSeek"),
        "the costed plan must keep the subquery seek, else this is vacuous:\n{}",
        costed.root
    );
    assert!(
        costed.index_dependencies().count() > 0,
        "the dependencies recomputed from the final tree must include the subquery's index"
    );
}

/// A `$param` referenced **only inside** the subquery must still be declared by the plan, or binding
/// would silently accept a statement that is missing it.
#[test]
fn a_parameter_used_only_inside_a_subquery_is_still_required() {
    let plan = compile("MATCH (u:P) WHERE EXISTS { (u)-[:T]->({n: $want}) } RETURN u.n AS n");
    assert!(is_rewritten(&plan));
    assert!(
        bind_parameters(&plan, &Parameters::new()).is_err(),
        "a missing $want must be rejected, not defaulted"
    );
    let mut params = Parameters::new();
    params.insert("want", Value::String("q1".into()));
    let bound = bind_parameters(&plan, &params).expect("bind with the parameter supplied");
    let mut g = corpus();
    let rows = execute(&plan, &bound, &mut g)
        .expect("open")
        .collect_all()
        .expect("collect");
    assert_eq!(rows.len(), 2, "a1 and a2 point at q1");
}

// =================================================================================================
// 4. The short-circuit, measured
// =================================================================================================

/// Acceptance criterion: the right branch stops at the **first** row.
///
/// `a2` has three outgoing `:T`. A semi-join that drained its branch would expand all three; one that
/// stops at the first expands one. `dbHits` on the inner expand is what tells them apart — and it is
/// measured, not asserted: the same query with the rewrite un-done (the pre-#869 opaque predicate)
/// gives the number to beat.
#[test]
fn the_inner_branch_stops_at_the_first_row() {
    let src = "PROFILE MATCH (u:P) WHERE EXISTS { (u)-[r:T]->(v) } RETURN u.n AS n";
    let plan = compile(src);
    assert!(is_rewritten(&plan), "the rewrite must fire:\n{}", plan.root);

    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut g = corpus();
    let mut cursor = execute(&plan, &bound, &mut g).expect("open");
    let rows = cursor.collect_all().expect("drain").len();
    let description = PlanDescription::profile(cursor.profile().expect("a PROFILEd statement"));

    // a1..a5 match; a0, a6, a7, a8 do not.
    assert_eq!(rows, 5);
    let expand = find(description.root(), "ExpandAll").expect("the inner expand is in the plan");
    // Five driving rows match and each is settled by ONE expansion; the four that do not match walk
    // their (empty or wrong-direction) incidence list once. The bound the criterion states is "one per
    // outer row that matches" — anything above 9 total rows out of the expand would mean the branch
    // was drained rather than stopped.
    assert_eq!(
        expand.rows,
        Some(5),
        "the inner expand may emit at most one row per matching driving row, got {:?}",
        expand.rows
    );
}

/// The same measurement stated as a comparison: draining `a2`'s three relationships instead of
/// stopping at the first is exactly what the pre-#869 path did, and the semi-join must read strictly
/// less. Run over a graph where one node has many neighbours so the difference cannot be noise.
#[test]
fn the_short_circuit_reads_strictly_less_than_the_opaque_predicate_did() {
    fn hits(plan: &PhysicalPlan, g: &mut MemGraph) -> u64 {
        fn walk(n: &PlanNode) -> u64 {
            n.db_hits.unwrap_or(0) + n.children.iter().map(walk).sum::<u64>()
        }
        let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
        let mut cursor = execute(plan, &bound, g).expect("open");
        let _ = cursor.collect_all().expect("drain");
        walk(PlanDescription::profile(cursor.profile().expect("recorder")).root())
    }

    // One hub with 50 outgoing :T — the first is enough to settle EXISTS.
    let build = || {
        let mut g = MemGraph::new();
        let hub = g.add_node(["P"], [("n", Value::String("hub".into()))]);
        for i in 0..50 {
            let t = g.add_node(["Q"], [("n", Value::String(format!("q{i}")))]);
            g.add_rel("T", hub, t, [("w", Value::Integer(i))]);
        }
        g
    };

    let src = "PROFILE MATCH (u:P) WHERE EXISTS { (u)-[r:T]->(v) } RETURN u.n AS n";
    let rewritten = compile(src);
    assert!(is_rewritten(&rewritten));
    let reference = unrewritten(&rewritten);
    assert!(!is_rewritten(&reference));

    let fast = hits(&rewritten, &mut build());
    let slow = hits(&reference, &mut build());
    assert!(
        fast < slow,
        "the short-circuiting branch must read less than the drained one: {fast} vs {slow}"
    );
}

/// TRAP 4 (`rmp` #755 is the live precedent): what `EXPLAIN` shows must be what ran. The inner
/// branch's operators appear in the plan description **and** carry measured `PROFILE` counters, so a
/// reader cannot be shown an access path that was never attributed any work.
#[test]
fn the_inner_branch_is_both_shown_and_measured() {
    let plan = compile("PROFILE MATCH (u:P) WHERE EXISTS { (u)-[r:T]->(v) } RETURN u.n AS n");
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut g = corpus();
    let mut cursor = execute(&plan, &bound, &mut g).expect("open");
    let _ = cursor.collect_all().expect("drain");
    let description = PlanDescription::profile(cursor.profile().expect("recorder"));

    let semi = find(description.root(), "SemiApply").expect("SemiApply is in the description");
    assert_eq!(
        semi.children.len(),
        2,
        "the description must show BOTH the driving relation and the subquery branch"
    );
    let expand = find(description.root(), "ExpandAll").expect("the inner expand is shown");
    assert!(
        expand.db_hits.is_some_and(|h| h > 0),
        "the operator EXPLAIN shows must be attributed the work it did, got {:?}",
        expand.db_hits
    );
    // The rebuilt-per-row template accumulates into ONE plan operator, not one per driving row.
    let mut count = 0;
    fn tally(n: &PlanNode, want: &str, count: &mut usize) {
        if n.operator_type == want {
            *count += 1;
        }
        for c in &n.children {
            tally(c, want, count);
        }
    }
    tally(description.root(), "ExpandAll", &mut count);
    assert_eq!(count, 1, "the per-row rebuilds must share one plan node");
}

// =================================================================================================
// 4b. The acceptance criterion, measured against the real store
// =================================================================================================

/// The acceptance criterion's headline shape, over the **real** storage seam.
///
/// `MemGraph` has no index structure — it declines every seek and the executor silently falls back to
/// a scan — so a `dbHits` saving can only be demonstrated against `TxnCoordinator` over a
/// `RecordStore`, where the index the coordinator maintains genuinely serves the seek.
///
/// The number this pins is the one the task is about: with an ONLINE index on `USER.uidn` and a
/// **single** outer row, `EXISTS { (u:USER {uidn: 1}) }` used to read the whole `USER` label, because
/// the pattern form never reached the planner and its interpreter scans. It now reads a small,
/// bounded fraction of it.
#[test]
fn exists_with_an_indexed_inner_predicate_reads_a_fraction_of_the_label() {
    use graphus_cypher::coordinator::TxnCoordinator;
    use graphus_io::MemBlockDevice;
    use graphus_storage::RecordStore;
    use graphus_wal::{MemLogSink, WalManager};

    const USERS: i64 = 400;

    fn total_db_hits(p: &PlanDescription) -> u64 {
        fn walk(n: &PlanNode) -> u64 {
            n.db_hits.unwrap_or(0) + n.children.iter().map(walk).sum::<u64>()
        }
        walk(p.root())
    }

    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    let store = RecordStore::create(device, wal, 64, 1).expect("store");
    let mut coord = TxnCoordinator::new(store);

    // One MARKER node — the single outer row the acceptance criterion measures — and `USERS` users.
    let seed = format!(
        "CREATE (:MARKER) WITH 1 AS _ UNWIND range(0, {}) AS i CREATE (:USER {{uidn: i}})",
        USERS - 1
    );
    let plan = compile(&seed);
    let params = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    {
        let mut graph = coord.statement(txn).expect("statement");
        execute(&plan, &params, &mut graph)
            .expect("open")
            .collect_all()
            .expect("drain");
    }
    coord.commit(txn).expect("commit");
    coord
        .create_node_property_index("USER", "uidn")
        .expect("index");

    let query = "PROFILE MATCH (m:MARKER) WHERE EXISTS { (u:USER {uidn: 1}) } RETURN count(*) AS c";
    let run_it = |coord: &TxnCoordinator<MemBlockDevice, MemLogSink>, catalog: &IndexCatalog| {
        let plan = compile_with(query, catalog);
        let params = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let txn = coord.begin_serializable();
        let (rows, description, text) = {
            let mut graph = coord.statement(txn).expect("statement");
            let mut cursor = execute(&plan, &params, &mut graph).expect("open");
            let rows = cursor.collect_all().expect("drain");
            let description = PlanDescription::profile(cursor.profile().expect("recorder"));
            (rows, description, plan.root.to_string())
        };
        coord.commit(txn).expect("commit");
        (rows, description, text)
    };

    let catalog = coord.catalog();
    let (seek_rows, seek, seek_text) = run_it(&mut coord, &catalog);
    let (scan_rows, scan, scan_text) = run_it(&mut coord, &IndexCatalog::empty());

    assert!(
        seek_text.contains("SemiApply") && seek_text.contains("NodeIndexSeek(u:USER uidn = 1"),
        "the subquery must seek the real index:\n{seek_text}"
    );
    assert!(
        !scan_text.contains("NodeIndexSeek"),
        "the control must not seek:\n{scan_text}"
    );
    // Same answer, both ways — the saving must not come from reading less than the query needs.
    assert_eq!(seek_rows.len(), 1);
    assert_eq!(seek_rows[0].value("c"), scan_rows[0].value("c"));
    assert_eq!(
        format!("{:?}", seek_rows[0].value("c")),
        "Integer(1)",
        "the one MARKER row survives, because user 1 exists"
    );

    let seek_hits = total_db_hits(&seek);
    let scan_hits = total_db_hits(&scan);
    assert!(
        scan_hits >= USERS as u64,
        "the control must really read the label ({scan_hits} hits over {USERS} users)"
    );
    assert!(
        seek_hits * 10 < scan_hits,
        "the indexed subquery must read a small fraction of the label: seek={seek_hits} scan={scan_hits}"
    );
    eprintln!(
        "rmp #869 measured: seek dbHits={seek_hits}, scan dbHits={scan_hits} over {USERS} users"
    );
}

// =================================================================================================
// 5. Declines — every shape the rewrite refuses, with the answer it still returns
// =================================================================================================

/// TRAP 1. A semi-join answers "keep this row or not"; it cannot hand a boolean back to a surrounding
/// expression. Each of these needs a different operator (Neo4j's `SelectOrSemiApply` / `LetSemiApply`
/// family), so each is declined and keeps the opaque predicate.
#[test]
fn an_exists_that_is_not_a_top_level_conjunct_declines() {
    // Inside an OR: `a OR EXISTS {…}` is not a semi-join, and negating into one would be wrong.
    assert_eq!(
        assert_declines(
            "MATCH (u:P) WHERE u.n = 'a0' OR EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n",
            &["n"],
            "EXISTS{...}"
        ),
        vec!["String(\"a0\")", "String(\"a1\")", "String(\"a2\")"]
    );
    // Inside a CASE.
    assert_eq!(
        assert_declines(
            "MATCH (u:P) WHERE CASE WHEN EXISTS { (u)-[:T]->(:Q) } THEN true ELSE false END RETURN u.n AS n",
            &["n"],
            "Filter(CASE(...))"
        ),
        vec!["String(\"a1\")", "String(\"a2\")"]
    );
    // Inside a function argument.
    assert_declines(
        "MATCH (u:P) WHERE coalesce(EXISTS { (u)-[:T]->(:Q) }, false) RETURN u.n AS n",
        &["n"],
        "EXISTS{...}",
    );
    // A double negation is left alone rather than folded.
    assert_eq!(
        assert_declines(
            "MATCH (u:P) WHERE NOT NOT EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n",
            &["n"],
            "Filter(NOT NOT EXISTS{...})"
        ),
        vec!["String(\"a1\")", "String(\"a2\")"]
    );
}

/// A **projection** position is not a filter at all — the boolean is the answer, not a decision.
#[test]
fn an_exists_in_a_projection_declines() {
    let plan = compile("MATCH (u:P) RETURN u.n AS n, EXISTS { (u)-[:T]->(:Q) } AS e");
    assert!(
        !is_rewritten(&plan),
        "a projected EXISTS has no row to drop:\n{}",
        plan.root
    );
    let rows = rows_of(&plan, &["n", "e"]);
    assert_eq!(rows.len(), 9);
    assert_eq!(rows[1], "String(\"a1\")|Boolean(true)");
    assert_eq!(rows[0], "String(\"a0\")|Boolean(false)");
}

/// A **non-leading** conjunct declines, because moving it below a preceding conjunct would stop that
/// conjunct's `NULL` rows from reaching it — changing which expressions are evaluated, and so which
/// errors are raised. An `Aggregation` is used to pin the conjunct in place: the pushdown pass (`rmp`
/// #857) cannot move a conjunct across it, so the conjunction really does reach this pass intact.
#[test]
fn a_non_leading_exists_conjunct_declines() {
    let src = "MATCH (u:P) WITH u, count(*) AS c WHERE c > 0 AND EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n";
    let plan = compile(src);
    assert!(
        plan.root
            .to_string()
            .contains("Filter(((c > 0) AND EXISTS{...}))"),
        "the conjunction must reach this pass intact, else the decline is untested:\n{}",
        plan.root
    );
    assert_eq!(
        assert_declines(src, &["n"], "EXISTS{...}"),
        vec!["String(\"a1\")", "String(\"a2\")"]
    );
    // The same predicate with the EXISTS written FIRST is accepted and gives the same answer — which
    // is what makes the decline a deliberate restriction rather than an inability.
    let leading = "MATCH (u:P) WITH u, count(*) AS c WHERE EXISTS { (u)-[:T]->(:Q) } AND c > 0 RETURN u.n AS n";
    let plan = compile(leading);
    assert!(
        is_rewritten(&plan),
        "a leading conjunct is accepted:\n{}",
        plan.root
    );
    assert_eq!(
        rows_of(&plan, &["n"]),
        vec!["String(\"a1\")", "String(\"a2\")"]
    );
}

/// The conjuncts the leading run does NOT consume must survive, in their original order, as a `Filter`
/// above the chain. The residual has to be one the pushdown cannot move and that actually *selects* —
/// otherwise dropping it entirely would leave the answer unchanged and this would prove nothing. An
/// `Aggregation` pins it in place (`rmp` #857 cannot cross one) and `u.n = 'a1'` cuts two rows to one.
#[test]
fn a_residual_conjunct_after_the_leading_run_is_preserved() {
    let src = "MATCH (u:P) WITH u, count(*) AS c WHERE EXISTS { (u)-[:T]->(:Q) } AND u.n = 'a1' RETURN u.n AS n";
    let plan = compile(src);
    assert!(is_rewritten(&plan), "the EXISTS is leading:\n{}", plan.root);
    assert!(
        plan.root.to_string().contains("Filter((u.n = 'a1'))"),
        "the residual must remain as a Filter above the semi-join:\n{}",
        plan.root
    );
    // Without the residual the answer would be a1 AND a2; with it, a1 alone.
    assert_eq!(rows_of(&plan, &["n"]), vec!["String(\"a1\")"]);
    let without =
        "MATCH (u:P) WITH u, count(*) AS c WHERE EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n";
    assert_eq!(
        rows_of(&compile(without), &["n"]),
        vec!["String(\"a1\")", "String(\"a2\")"],
        "the control must show the residual really removes a row"
    );
    // Two residuals, so the left-to-right re-join is exercised rather than a single-element reduce.
    let two = "MATCH (u:P) WITH u, count(*) AS c WHERE EXISTS { (u)-[:T]->(:Q) } AND u.n <> 'a1' AND u.k = 2 RETURN u.n AS n";
    let plan = compile(two);
    assert!(is_rewritten(&plan));
    assert!(
        plan.root
            .to_string()
            .contains("Filter(((u.n <> 'a1') AND (u.k = 2)))"),
        "both residuals, in source order:\n{}",
        plan.root
    );
    assert_eq!(rows_of(&plan, &["n"]), vec!["String(\"a2\")"]);
}

/// In practice the restriction above costs little, because `rmp` #857's pushdown runs first and
/// separates the conjuncts — so the ordinary spelling `WHERE p AND EXISTS {…}` still gets the
/// operator. Pinned, because this interaction is load-bearing and invisible from either pass alone.
#[test]
fn the_pushdown_makes_the_ordinary_and_spelling_rewritable() {
    for src in [
        "MATCH (u:P) WHERE u.n = 'a1' AND EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n",
        "MATCH (u:P) WHERE EXISTS { (u)-[:T]->(:Q) } AND u.n = 'a1' RETURN u.n AS n",
        "MATCH (u:P) WHERE size(keys(u)) > 1 AND EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n",
    ] {
        let plan = compile(src);
        assert!(
            is_rewritten(&plan),
            "`{src}` should still reach the operator after the pushdown:\n{}",
            plan.root
        );
    }
}

// =================================================================================================
// 6. TRAP 3 — the read footprint, and RBAC
// =================================================================================================

/// A [`GraphAccess`] decorator that records **every** read seam call, in order, forwarding verbatim.
///
/// The point is the whole ordered trace, not a count: under SSI a read that no longer happens is a
/// marker that no longer exists, and a trace comparison catches that whatever shape it takes.
struct RecordingGraph<'a> {
    inner: &'a mut MemGraph,
    trace: std::cell::RefCell<Vec<String>>,
}

impl<'a> RecordingGraph<'a> {
    fn new(inner: &'a mut MemGraph) -> Self {
        Self {
            inner,
            trace: std::cell::RefCell::new(Vec::new()),
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

/// **TRAP 3, and the one place this task genuinely narrows a read footprint — stated, not hidden.**
///
/// The acceptance criteria require the right branch to short-circuit, and short-circuiting means a
/// candidate the drained plan examined is no longer examined. Under SSI a read that no longer happens
/// is an rw-marker that no longer exists, so this needs an argument. It is the standard one for
/// existential quantification, and it holds on **both** sides of the operator:
///
/// > A verdict is reached either by finding a **witness** or by exhausting the branch.
/// >
/// > * **No witness** — the branch was drained, so nothing was skipped and the footprint is the
/// >   drained plan's, including the relationship-pattern predicate marker that guards the
/// >   absent-edge phantom. This is the case for every row a `SemiApply` **drops** and every row an
/// >   `AntiSemiApply` **keeps**.
/// > * **A witness** — every read that established it still happened and is still marked: the
/// >   expansion that found it, and the property/label reads by which each earlier candidate was
/// >   rejected. Only reads *after* the witness are skipped, and no change to those entities can flip
/// >   the verdict — removing them leaves the witness intact, adding more only reinforces it. A change
/// >   that could flip the verdict must destroy the witness, and the witness is marked.
///
/// So the invariant is not "the footprint never narrows" but the sharper one this test pins: **the
/// justification for every verdict is fully marked**, and the only reads dropped are ones that
/// follow a marked witness. The earlier, weaker claim "anti never narrows" is FALSE and was corrected
/// here: an `AntiSemiApply` short-circuits too, on the rows it drops.
///
/// One further class of call legitimately disappears everywhere and is excluded below: `rel_data(r)`.
/// The interpreter re-reads each relationship record it was handed; the executor's `ExpandAll` does
/// not, because `expand` already returned the id and the far endpoint. That is not a narrower SSI
/// footprint — `RecordStoreGraph::expand` "SIREAD-mark[s] + visibility-filter[s] each edge" and
/// registers the relationship-pattern predicate marker before returning, so every relationship a
/// `rel_data` would have marked is already marked by the `expand` that produced it. Nor is it a
/// difference this task introduces: a top-level `MATCH (u)-[r:T]->(v)` has always run `ExpandAll`.
#[test]
fn a_verdict_reached_without_a_witness_keeps_the_whole_footprint() {
    // `a7` has one `:U` and no `:T` at all, so neither spelling can find a witness: both verdicts are
    // reached by exhausting the branch, and both footprints must be the drained plan's.
    for src in [
        "MATCH (u:P) WHERE u.n = 'a7' AND EXISTS { (u)-[r:T]->(v) } RETURN u.n AS n",
        "MATCH (u:P) WHERE u.n = 'a7' AND NOT EXISTS { (u)-[r:T]->(v) } RETURN u.n AS n",
        // `a1` has exactly one `:T`, to a `:Q` — so a `:R` target is never found and the branch is
        // exhausted after examining that one candidate's labels.
        "MATCH (u:P) WHERE u.n = 'a1' AND NOT EXISTS { (u)-[r:T]->(v:R) } RETURN u.n AS n",
        "MATCH (u:P) WHERE u.n = 'a1' AND EXISTS { (u)-[r:T]->(v:R) } RETURN u.n AS n",
    ] {
        let rewritten = compile(src);
        assert!(is_rewritten(&rewritten), "`{src}` must be rewritten");
        let got = read_trace(&rewritten);
        let want = read_trace(&unrewritten(&rewritten));
        assert!(
            want.iter().any(|r| r.starts_with("expand(")),
            "the reference must expand for `{src}`, else this proves nothing: {want:?}"
        );
        let missing: Vec<&String> = want
            .iter()
            .filter(|r| !r.starts_with("rel_data(") && !got.contains(r))
            .collect();
        assert!(
            missing.is_empty(),
            "`{src}` reached its verdict WITHOUT a witness, so nothing may be skipped — \
             these reads vanished and each is a potential SSI phantom: {missing:?}"
        );
    }
}

/// The mirror of the test above: where a witness *is* found the footprint really does narrow — on
/// both sides — and the expansion that produced the witness is still in it. Without this the
/// short-circuit could be absent and the argument above would be about a case that never happens.
#[test]
fn a_verdict_reached_by_a_witness_narrows_but_keeps_the_witness_marked() {
    for src in [
        // `a2` has three `:T`, the first of which reaches a `:Q` — a witness, so the other two are
        // never examined.
        "MATCH (u:P) WHERE u.n = 'a2' AND EXISTS { (u)-[r:T]->(v:Q) } RETURN u.n AS n",
        // The anti spelling drops `a2` on the same witness, and skips the same reads.
        "MATCH (u:P) WHERE u.n = 'a2' AND NOT EXISTS { (u)-[r:T]->(v:Q) } RETURN u.n AS n",
    ] {
        let rewritten = compile(src);
        assert!(is_rewritten(&rewritten));
        let got = read_trace(&rewritten);
        let want = read_trace(&unrewritten(&rewritten));
        assert!(
            got.len() < want.len(),
            "`{src}`: a witness exists, so the branch must stop early: {got:?} vs {want:?}"
        );
        assert!(
            got.iter().any(|r| r.starts_with("expand(")),
            "`{src}`: the expansion that found the witness must still be marked: {got:?}"
        );
    }
}

/// RBAC composes at the seam, exactly as it does for the plan the operator replaced: a principal that
/// cannot traverse `:Q` gets the same rows either way. The restriction is asserted to actually bite,
/// so an "identical" result cannot be identical-because-nothing-was-restricted.
#[test]
fn rbac_composes_identically_over_the_semi_join() {
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

    let restricted_rows = |plan: &PhysicalPlan, unrestricted: bool| {
        let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
        let mut g = corpus();
        let mut authorized = AuthorizedGraph::new(&mut g, DenyQ { unrestricted });
        let mut cursor = execute(plan, &bound, &mut authorized).expect("open");
        cursor
            .collect_all()
            .expect("collect")
            .iter()
            .map(|r| render(r, &["n"]))
            .collect::<Vec<_>>()
    };

    let src = "MATCH (u:P) WHERE EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n";
    let rewritten = compile(src);
    assert!(is_rewritten(&rewritten));
    let reference = unrewritten(&rewritten);

    let open = restricted_rows(&rewritten, true);
    let denied = restricted_rows(&rewritten, false);
    assert_ne!(
        open, denied,
        "the restriction must actually bite, else this test compares nothing"
    );
    assert_eq!(
        denied,
        restricted_rows(&reference, false),
        "RBAC must compose over the semi-join exactly as over the predicate it replaced"
    );
    assert!(
        denied.is_empty(),
        "with :Q untraversable no driving row can reach one, got {denied:?}"
    );
}

// =================================================================================================
// 6b. Contexts the operator must survive, not just the ones it was designed for
// =================================================================================================

/// A driving row whose anchor is `NULL` — the row an `OPTIONAL MATCH` leaves behind. The subquery
/// must evaluate to `FALSE` (never `NULL`, never an error), exactly as the predicate it replaced did.
#[test]
fn a_null_anchor_makes_the_subquery_false_on_both_sides() {
    for (src, expect) in [
        (
            "OPTIONAL MATCH (u:NOSUCHLABEL) WITH u WHERE EXISTS { (u)-[:T]->() } RETURN count(*) AS n",
            "Integer(0)",
        ),
        (
            "OPTIONAL MATCH (u:NOSUCHLABEL) WITH u WHERE NOT EXISTS { (u)-[:T]->() } RETURN count(*) AS n",
            "Integer(1)",
        ),
    ] {
        let rewritten = compile(src);
        assert!(
            is_rewritten(&rewritten),
            "`{src}` must be rewritten:\n{}",
            rewritten.root
        );
        let got = rows_of(&rewritten, &["n"]);
        assert_eq!(got, vec![expect.to_owned()], "`{src}`");
        assert_eq!(
            got,
            rows_of(&unrewritten(&rewritten), &["n"]),
            "`{src}` must agree with the predicate it replaced"
        );
    }
}

/// The rewrite must survive a **writing** statement: the `EXISTS` decides which rows are written, and
/// the read-write `Eager` barrier that protects the write must still be there.
#[test]
fn the_rewrite_composes_with_a_writing_clause() {
    let src = "MATCH (u:P) WHERE EXISTS { (u)-[:T]->(:Q) } SET u.marked = true RETURN u.n AS n";
    let rewritten = compile(src);
    assert!(is_rewritten(&rewritten), "`{src}`:\n{}", rewritten.root);
    let got = rows_of(&rewritten, &["n"]);
    assert_eq!(got, vec!["String(\"a1\")", "String(\"a2\")"]);
    assert_eq!(got, rows_of(&unrewritten(&rewritten), &["n"]));

    // And the write really happened, on exactly those rows.
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut g = corpus();
    {
        let mut cursor = execute(&plan, &bound, &mut g).expect("open");
        cursor.collect_all().expect("collect");
    }
    let check = compile("MATCH (u:P) WHERE u.marked = true RETURN u.n AS n");
    let bound = bind_parameters(&check, &Parameters::new()).expect("bind");
    let marked: Vec<String> = execute(&check, &bound, &mut g)
        .expect("open")
        .collect_all()
        .expect("collect")
        .iter()
        .map(|r| render(r, &["n"]))
        .collect();
    assert_eq!(marked, vec!["String(\"a1\")", "String(\"a2\")"]);
}

/// The subquery may name a variable an EARLIER clause bound, not just the pattern's own anchor —
/// which is what makes the correlation set "everything the driving relation binds" rather than "the
/// anchor". A synthetic (anonymous) binding must NOT be carried, because the subquery is lowered by a
/// fresh planner whose generated names restart at zero and would collide.
#[test]
fn the_subquery_correlates_on_every_named_driving_column() {
    let src = "MATCH (u:P)-[:T]->(w) WHERE EXISTS { (u)-[:T]->(w) } RETURN u.n AS n, w.n AS m";
    let rewritten = compile(src);
    assert!(is_rewritten(&rewritten));
    let text = rewritten.root.to_string();
    assert!(
        text.contains("Argument(u, w)"),
        "both named columns must be carried:\n{text}"
    );
    assert!(
        !text.contains("anon_")
            || !text
                .split("Argument(")
                .nth(1)
                .unwrap_or("")
                .starts_with("  anon"),
        "a synthetic name must never be an argument:\n{text}"
    );
    assert_matches_unrewritten(src, &["n", "m"]);
}

/// Cross-clause reuse of a relationship variable stays legal (relationship isomorphism is per
/// `MATCH`, not per statement), and the subquery's own pattern is isomorphic within itself.
#[test]
fn relationship_isomorphism_is_scoped_to_the_subquery_pattern() {
    // The outer `r` and the subquery's hop may be the same relationship: different clauses.
    assert_matches_unrewritten(
        "MATCH (u:P)-[r:T]->(w) WHERE EXISTS { (u)-[:T]->(w) } RETURN u.n AS n",
        &["n"],
    );
    // Two hops INSIDE the subquery may not reuse one relationship, which is why `a3`'s self-loop does
    // not satisfy a there-and-back pattern.
    let rows = rows_of(
        &compile("MATCH (u:P) WHERE EXISTS { (u)-[r1:T]->(m), (m)-[r2:T]->(u) } RETURN u.n AS n"),
        &["n"],
    );
    assert!(
        !rows.contains(&"String(\"a3\")".to_owned()),
        "a3's single self-loop cannot fill both hops: {rows:?}"
    );
    assert_eq!(
        rows,
        vec!["String(\"a4\")", "String(\"a5\")"],
        "only the a4/a5 pair has two distinct relationships both ways"
    );
}

// =================================================================================================
// 6c. The cost model can now see the subquery
// =================================================================================================

/// Before this task the same shape was a `Filter` over an opaque `EXISTS{…}` predicate: the model
/// charged ONE `COST_ROW_FILTER` for a whole correlated sub-plan and had no selectivity to apply. Both
/// numbers now come from the branch that actually runs — which is the point of making the subquery an
/// operator rather than an expression, and is a *decision* defect no result assertion would catch.
#[test]
fn the_cost_model_reflects_the_branch_and_the_short_circuit() {
    use graphus_cypher::cost::estimate_cost;

    let semi = compile("MATCH (u:P) WHERE EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n");
    let anti = compile("MATCH (u:P) WHERE NOT EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n");
    assert!(is_rewritten(&semi) && is_rewritten(&anti));

    fn semi_node(op: &PhysicalOp) -> &PhysicalOp {
        if matches!(op, PhysicalOp::SemiApply { .. }) {
            return op;
        }
        op.children()
            .into_iter()
            .find_map(|c| {
                let found = semi_node(c);
                matches!(found, PhysicalOp::SemiApply { .. }).then_some(found)
            })
            .unwrap_or(op)
    }

    let s = estimate_cost(semi_node(&semi.root), None);
    let a = estimate_cost(semi_node(&anti.root), None);
    let PhysicalOp::SemiApply { input, inner, .. } = semi_node(&semi.root) else {
        panic!("the semi-join must be found");
    };
    let driving = estimate_cost(input, None);
    let _ = inner;

    // Cardinality: a semi-join emits a FRACTION of its driving rows, and the anti emits the rest. The
    // two must sum to the driving cardinality, which is the model's statement of "EXISTS is
    // two-valued" — the same property the executor rests on.
    assert!(
        s.rows < driving.rows,
        "a semi-join must estimate fewer rows than it is driven by: {} vs {}",
        s.rows,
        driving.rows
    );
    assert!(
        (s.rows + a.rows - driving.rows).abs() < 1e-6,
        "semi ({}) + anti ({}) must be the driving cardinality ({})",
        s.rows,
        a.rows,
        driving.rows
    );
    assert!(
        s.cost > driving.cost,
        "the branch is not free: {} vs {}",
        s.cost,
        driving.cost
    );

    // Cost: the branch is charged per driving row, but bounded BELOW the drained branch — because the
    // executor stops at the first row. The saving is proportional to how OFTEN a witness is found, so
    // it must be measured on a branch the model expects to yield MANY rows. A one-hop expand is not
    // that branch without statistics — the default degree is 1, so stopping at the first of one row
    // saves exactly nothing and the model says so, correctly. A branch with an independent component
    // is: its estimate is the label cardinality. (For a highly selective branch the model likewise
    // predicts almost no saving, because a verdict reached without a witness drains. Neither is a
    // defect; both are the short-circuit being modelled honestly rather than assumed.)
    let likely = compile("MATCH (u:P) WHERE EXISTS { (u)-[:T]->(), (x:Q) } RETURN u.n AS n");
    assert!(is_rewritten(&likely));
    let PhysicalOp::SemiApply { input, inner, .. } = semi_node(&likely.root) else {
        panic!("the semi-join must be found");
    };
    let l = estimate_cost(semi_node(&likely.root), None);
    let l_driving = estimate_cost(input, None);
    let l_branch = estimate_cost(inner, None);
    assert!(
        l_branch.rows >= 1.0,
        "this branch must be one the model expects to match, else the saving is not testable: {}",
        l_branch.rows
    );
    let drained = l_driving.cost + l_driving.rows * l_branch.cost;
    assert!(
        l.cost < drained,
        "the short-circuit must be cheaper than draining the branch: {} vs {}",
        l.cost,
        drained
    );
}

// =================================================================================================
// 7. Non-vacuity: with the rewrite absent, these tests fail
// =================================================================================================

/// A guard, labelled as such: it passes with or without the rewrite. It exists so that a future
/// change that makes the *reference* path disagree with the operator is caught here rather than in a
/// user's result set.
#[test]
fn guard_the_reference_path_still_answers_correctly() {
    let plan = unrewritten(&compile(
        "MATCH (u:P) WHERE EXISTS { (u)-[:T]->(:Q) } RETURN u.n AS n",
    ));
    assert_eq!(
        rows_of(&plan, &["n"]),
        vec!["String(\"a1\")", "String(\"a2\")"]
    );
}
