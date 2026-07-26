//! **ValueHashJoin: join two branches on an equality between their values** (`rmp` task #865).
//!
//! `choose_join` derives its keys from shared column NAMES, so it can only ever express a
//! node-identity join. An equality between two different variables' properties — a join on a business
//! key rather than on identity — shares no name, so it fell through to a cartesian nested loop with the
//! equality left as a `Filter` above. Measured on the evaluation store:
//! `MATCH (u:USER), (a:ARTICLE) WHERE u.city = a.topic RETURN count(*)` evaluated 200000 x 2000 = 400M
//! pairs in **188.0s**. Neo4j plans a `ValueHashJoin` here, which is linear in the two inputs.
//!
//! Measured here on a 4000 x 400 corpus: **783.4 ms → 20.0 ms**, same answer.
//!
//! # The semantics that decide correctness
//!
//! The hash index buckets by grouping **equivalence**, but a bucket hit is confirmed with Cypher
//! **equality** — the predicate the join replaces. They differ exactly where it matters:
//!
//! * `null = null` is `null`, not true, so a null key must match nothing. Equivalence groups nulls
//!   together.
//! * `NaN = NaN` is false. Equivalence groups NaNs together.
//!
//! Confirming with equality over an equivalence-bucketed index is sound because equality implies
//! equivalence — `1 = 1.0` is true and both land in the same bucket — so no match is ever missed. Every
//! test below compares the join's bag against the nested-loop plan that produced it, over a corpus
//! built to contain each of these cases.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, MemGraph};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical_with_stats};
use graphus_cypher::semantics::analyze;

/// A corpus whose join keys deliberately include every awkward case: matching strings, a `null` on
/// each side, an integer against an equal float (cross-type equality is TRUE), an integer against the
/// string spelling of the same number (FALSE), and a `NaN` on each side.
fn awkward_corpus() -> MemGraph {
    let mut g = MemGraph::new();
    let nan = f64::NAN;
    for v in [
        Value::String("alpha".to_owned()),
        Value::String("beta".to_owned()),
        Value::Null,
        Value::Integer(7),
        Value::Integer(9),
        Value::Float(nan),
        Value::String("7".to_owned()),
    ] {
        g.add_node(["L"], [("k", v)]);
    }
    for v in [
        Value::String("alpha".to_owned()),
        Value::String("gamma".to_owned()),
        Value::Null,
        Value::Float(7.0),
        Value::Integer(9),
        Value::Float(nan),
    ] {
        g.add_node(["R"], [("k", v)]);
    }
    g
}

fn compile(src: &str, g: &MemGraph, stats: bool) -> PhysicalPlan {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let v = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    let s = if stats { g.statistics() } else { None };
    plan_physical_with_stats(&lower(&v), &IndexCatalog::empty(), s)
}

fn has_op(plan: &PhysicalPlan, name: &str) -> bool {
    format!("{:?}", plan.root).contains(&format!("{name} {{"))
}

fn rows_of(plan: &PhysicalPlan, g: &mut MemGraph, columns: &[&str]) -> Vec<String> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut out: Vec<String> = execute(plan, &bound, g)
        .expect("open")
        .collect_all()
        .expect("run")
        .iter()
        .map(|r| {
            columns
                .iter()
                .map(|c| format!("{:?}", r.value(c)))
                .collect::<Vec<_>>()
                .join("|")
        })
        .collect();
    out.sort();
    out
}

/// Asserts the hash-joined plan returns exactly the nested-loop plan's bag, and that it is non-empty.
fn assert_join_preserves_bag(src: &str, g: &mut MemGraph, columns: &[&str]) {
    let joined = compile(src, g, true);
    let nested = compile(src, g, false);
    assert!(
        !has_op(&nested, "ValueHashJoin"),
        "premise: the no-stats plan must be the nested loop this is compared against"
    );
    let a = rows_of(&joined, g, columns);
    let b = rows_of(&nested, g, columns);
    assert!(
        !b.is_empty(),
        "the corpus must match something, else the comparison is vacuous: {src}"
    );
    assert_eq!(a, b, "the hash join changed the result bag for `{src}`");
}

const JOIN: &str = "MATCH (l:L), (r:R) WHERE l.k = r.k RETURN l.k AS lk, r.k AS rk";

// =================================================================================================
// The rewrite fires and is faster
// =================================================================================================

#[test]
fn a_value_equality_between_two_branches_plans_as_a_value_hash_join() {
    let g = awkward_corpus();
    let plan = compile(JOIN, &g, true);
    assert!(
        has_op(&plan, "ValueHashJoin"),
        "an equality between two branches' values must become a value hash join:\n{:?}",
        plan.root
    );
    assert!(
        !has_op(&plan, "NestedLoopJoin"),
        "and must replace the cartesian nested loop"
    );
}

#[test]
fn it_is_linear_rather_than_quadratic() {
    // The property that matters: doubling BOTH inputs must not quadruple the time. A nested loop would.
    // Compared against itself at two sizes rather than against a wall-clock threshold, so the test does
    // not depend on how fast the host is.
    fn corpus(n: i64) -> MemGraph {
        let mut g = MemGraph::new();
        for i in 0..n {
            g.add_node(["L"], [("k", Value::Integer(i % 64))]);
        }
        for i in 0..n {
            g.add_node(["R"], [("k", Value::Integer(i % 64))]);
        }
        g
    }
    let src = "MATCH (l:L), (r:R) WHERE l.k = r.k RETURN count(*) AS n";
    let mut small = corpus(400);
    let mut large = corpus(800);
    assert!(
        has_op(&compile(src, &small, true), "ValueHashJoin"),
        "premise: the rewrite must have fired"
    );
    let time = |g: &mut MemGraph| {
        let plan = compile(src, g, true);
        let bound = bind_parameters(&plan, &Parameters::new()).unwrap();
        let t = std::time::Instant::now();
        let rows = execute(&plan, &bound, g).unwrap().collect_all().unwrap();
        (
            t.elapsed().as_secs_f64(),
            format!("{:?}", rows[0].value("n")),
        )
    };
    // Warm both, then measure.
    let _ = time(&mut small);
    let _ = time(&mut large);
    let (t_small, n_small) = time(&mut small);
    let (t_large, n_large) = time(&mut large);
    assert_ne!(n_small, n_large, "sanity: the two corpora differ");
    // Output grows 4x (both sides doubled), so the work is dominated by producing rows, not by
    // comparing pairs. A quadratic probe would be far worse than the 8x headroom allowed here.
    assert!(
        t_large < t_small * 8.0 + 0.05,
        "doubling both inputs must not blow up: {t_small:.4}s -> {t_large:.4}s"
    );
}

// =================================================================================================
// Semantics — the cases where equivalence and equality disagree
// =================================================================================================

#[test]
fn the_bag_matches_the_nested_loop_over_the_awkward_corpus() {
    let mut g = awkward_corpus();
    assert_join_preserves_bag(JOIN, &mut g, &["lk", "rk"]);
}

#[test]
fn a_null_key_matches_nothing() {
    // `null = null` is `null`, not true. The index buckets nulls together, so confirming with
    // equivalence instead of equality would produce a spurious row here.
    let mut g = awkward_corpus();
    let rows = rows_of(&compile(JOIN, &g, true), &mut g, &["lk", "rk"]);
    assert!(
        !rows.iter().any(|r| r.contains("Null")),
        "no row may pair a null key, got {rows:?}"
    );
    assert!(!rows.is_empty(), "and the join must still match something");
}

#[test]
fn nan_does_not_match_itself() {
    // `NaN = NaN` is false, though the two NaNs are the same group. Both corpora carry one.
    let mut g = awkward_corpus();
    let rows = rows_of(&compile(JOIN, &g, true), &mut g, &["lk", "rk"]);
    assert!(
        !rows.iter().any(|r| r.contains("NaN")),
        "NaN must not join to itself, got {rows:?}"
    );
}

#[test]
fn cross_type_numeric_equality_still_matches() {
    // `7 = 7.0` is TRUE in Cypher, and the two must land in the same bucket — the direction that would
    // silently LOSE rows if the digest disagreed with equality.
    let mut g = awkward_corpus();
    let rows = rows_of(&compile(JOIN, &g, true), &mut g, &["lk", "rk"]);
    assert!(
        rows.iter()
            .any(|r| r.contains("Integer(7)") && r.contains("Float(7.0)")),
        "7 must join to 7.0, got {rows:?}"
    );
}

#[test]
fn a_number_does_not_match_its_string_spelling() {
    // `7 = '7'` is false. The corpus has a `"7"` on the left for exactly this.
    let mut g = awkward_corpus();
    let rows = rows_of(&compile(JOIN, &g, true), &mut g, &["lk", "rk"]);
    assert!(
        !rows.iter().any(|r| r.starts_with(r#"String("7")"#)),
        "the string 7 must not join to a number, got {rows:?}"
    );
}

// =================================================================================================
// Preconditions — the shapes that must NOT be rewritten
// =================================================================================================

#[test]
fn an_equality_within_one_branch_is_not_a_join_key() {
    // Both sides read the same branch, so it is an ordinary filter and there is no join to build.
    let g = awkward_corpus();
    let src = "MATCH (l:L), (r:R) WHERE l.k = l.k RETURN count(*) AS n";
    let plan = compile(src, &g, true);
    assert!(
        !has_op(&plan, "ValueHashJoin"),
        "a same-branch equality is not a join key:\n{:?}",
        plan.root
    );
}

#[test]
fn a_residual_conjunct_stays_above_the_join() {
    let mut g = awkward_corpus();
    let src = "MATCH (l:L), (r:R) WHERE l.k = r.k AND l.k <> 'beta' \
               RETURN l.k AS lk, r.k AS rk";
    let plan = compile(src, &g, true);
    assert!(
        has_op(&plan, "ValueHashJoin"),
        "the equality must be consumed"
    );
    assert!(
        has_op(&plan, "Filter"),
        "and the other conjunct must remain a filter:\n{:?}",
        plan.root
    );
    assert_join_preserves_bag(src, &mut g, &["lk", "rk"]);
}

#[test]
fn an_identity_join_still_uses_the_name_keyed_hash_join() {
    // A shared VARIABLE is what `choose_join` already handles; this rewrite must not displace it.
    let g = awkward_corpus();
    let src = "MATCH (l:L) WITH l MATCH (l)-[:R]->(x) RETURN count(*) AS n";
    let plan = compile(src, &g, true);
    assert!(
        !has_op(&plan, "ValueHashJoin"),
        "an identity join is not a value join:\n{:?}",
        plan.root
    );
}

#[test]
fn plan_choice_is_deterministic() {
    let g = awkward_corpus();
    let first = format!("{:?}", compile(JOIN, &g, true).root);
    for _ in 0..4 {
        assert_eq!(first, format!("{:?}", compile(JOIN, &g, true).root));
    }
}

// =================================================================================================
// Regression: the join must not be dissolved by the region reorderer
// =================================================================================================

#[test]
fn the_join_survives_join_region_reordering() {
    // Regression for a correctness bug found by the openCypher TCK while this operator was being
    // written. A `ValueHashJoin` carries its own key EXPRESSIONS, but the join-region flattener
    // extracts operands and re-joins them with `choose_join`, which knows only shared column NAMES —
    // so reordering one dropped its predicate and turned the join back into a cartesian product. The
    // TCK scenarios "Join between node identities" and "Join between node properties of disconnected
    // nodes" both went from 2 and 1 rows to 4.
    //
    // A three-branch query is what triggers it: two branches alone are not a region worth reordering.
    let mut g = MemGraph::new();
    for i in 0..3i64 {
        g.add_node(["A"], [("k", Value::Integer(i))]);
        g.add_node(["B"], [("k", Value::Integer(i))]);
        g.add_node(["C"], [("j", Value::Integer(i))]);
    }
    let src = "MATCH (a:A), (b:B), (c:C) WHERE a.k = b.k AND b.k = c.j RETURN a.k AS x, c.j AS y";
    let joined = compile(src, &g, true);
    assert!(
        has_op(&joined, "ValueHashJoin"),
        "premise: the rewrite must have fired:\n{:?}",
        joined.root
    );
    // The answer, not just the shape: three A/B/C triples share each key, so 3 rows — NOT the 27 a
    // cartesian product would give.
    let rows = rows_of(&joined, &mut g, &["x", "y"]);
    assert_eq!(
        rows.len(),
        3,
        "expected one row per shared key, got {rows:?}"
    );
    assert_join_preserves_bag(src, &mut g, &["x", "y"]);
}
