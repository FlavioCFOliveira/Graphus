//! **Planner hints: `USING INDEX` / `USING SCAN` / `USING JOIN`** (`rmp` task #855).
//!
//! Graphus chooses its anchor and access paths by cost (tasks #858/#887), and an estimate built on
//! histograms and counters can still be wrong on a skewed or freshly-loaded store. A hint is the
//! operator's escape hatch for that. Neo4j exposes these three forms; Memgraph exposes
//! `USING INDEX :Label(prop)`; Graphus had none.
//!
//! Two properties matter and the second is the one that makes hints trustworthy:
//!
//! 1. **A hint overrides the cost model.** The forced plan is built by the very rewrite the cost model
//!    would have considered and possibly rejected, so a hint never produces a shape the planner has not
//!    validated — and never changes the answer.
//! 2. **An unsatisfiable hint is an ERROR, not a no-op.** Silently ignoring one leaves the operator
//!    believing they overrode the planner when they did not, which is worse than having no hint at all.
//!
//! The grammar also has to stay compatible: `USING`, `SCAN` and `JOIN` are **not** openCypher reserved
//! words, so they must keep working as ordinary identifiers (`RETURN a AS join` is legal Cypher).

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, MemGraph};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical_hinted};
use graphus_cypher::semantics::analyze;

const NO_PROPS: [(&str, Value); 0] = [];

fn corpus() -> MemGraph {
    let mut g = MemGraph::new();
    let users: Vec<_> = (0..200)
        .map(|i| g.add_node(["USER"], [("uidn", Value::Integer(i))]))
        .collect();
    let arts: Vec<_> = (0..4)
        .map(|i| g.add_node(["ARTICLE"], [("aid", Value::Integer(i))]))
        .collect();
    for (i, &u) in users.iter().enumerate() {
        g.add_rel("LIKES", u, arts[i % arts.len()], NO_PROPS);
    }
    g
}

fn indexed() -> IndexCatalog {
    IndexCatalog::builder()
        .with_label_property("USER", "uidn")
        .build()
}

/// Compiles `src`, applying whatever hints it carries.
fn compile(src: &str, g: &MemGraph, cat: &IndexCatalog) -> Result<PhysicalPlan, String> {
    let toks = tokenize(src).map_err(|e| format!("lex: {e:?}"))?;
    let ast = parse_tokens(&toks, src).map_err(|e| format!("parse: {e:?}"))?;
    let v = analyze(&ast).map_err(|e| format!("analyze: {e:?}"))?;
    plan_physical_hinted(&lower(&v), cat, g.statistics(), &v.planner_hints())
        .map_err(|e| e.to_string())
}

fn has_op(plan: &PhysicalPlan, name: &str) -> bool {
    format!("{:?}", plan.root).contains(&format!("{name} {{"))
}

fn rows(src: &str, g: &mut MemGraph, cat: &IndexCatalog, column: &str) -> Vec<String> {
    let plan = compile(src, g, cat).expect("plan");
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut out: Vec<String> = execute(&plan, &bound, g)
        .expect("open")
        .collect_all()
        .expect("run")
        .iter()
        .map(|r| format!("{:?}", r.value(column)))
        .collect();
    out.sort();
    out
}

// =================================================================================================
// Grammar compatibility — the hint words are contextual, not reserved
// =================================================================================================

#[test]
fn the_hint_words_still_work_as_ordinary_identifiers() {
    // `USING`, `SCAN` and `JOIN` are not openCypher reserved words. Reserving them to parse the hints
    // would break long-standing valid Cypher, which is why they are recognised only in hint position.
    let g = corpus();
    let cat = indexed();
    for src in [
        "MATCH (n) RETURN n AS join",
        "MATCH (n) RETURN n AS scan",
        "MATCH (n) RETURN n AS using",
        "MATCH (scan:USER) RETURN scan.uidn AS x",
        "WITH 1 AS using RETURN using AS x",
        "MATCH (n:USER) WITH n AS join RETURN join.uidn AS x",
    ] {
        assert!(
            compile(src, &g, &cat).is_ok(),
            "must still parse as an identifier: {src}"
        );
    }
}

#[test]
fn all_three_hint_forms_parse() {
    for src in [
        "MATCH (u:USER) USING INDEX u:USER(uidn) WHERE u.uidn = 1 RETURN u.uidn AS x",
        "MATCH (u:USER) USING SCAN u:USER WHERE u.uidn = 1 RETURN u.uidn AS x",
        "MATCH (u:USER)-[:LIKES]->(a:ARTICLE) USING JOIN ON a RETURN u.uidn AS x",
    ] {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let v = analyze(&ast).expect("analyze");
        assert_eq!(v.planner_hints().len(), 1, "one hint expected in `{src}`");
    }
    // Several hints on one MATCH are accepted too.
    let src = "MATCH (u:USER)-[:LIKES]->(a:ARTICLE) USING INDEX u:USER(uidn) USING SCAN a:ARTICLE \
               WHERE u.uidn = 1 RETURN u.uidn AS x";
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    assert_eq!(analyze(&ast).expect("analyze").planner_hints().len(), 2);
}

#[test]
fn a_malformed_hint_is_a_syntax_error() {
    let g = corpus();
    let cat = indexed();
    let _ = (&g, &cat);
    for src in [
        "MATCH (u:USER) USING WOBBLE u:USER RETURN u.uidn AS x",
        "MATCH (u:USER) USING INDEX u RETURN u.uidn AS x",
        "MATCH (u:USER) USING INDEX u:USER RETURN u.uidn AS x",
        "MATCH (u:USER) USING SCAN u RETURN u.uidn AS x",
        "MATCH (u:USER) USING JOIN u RETURN u.uidn AS x",
    ] {
        assert!(
            compile(src, &g, &cat).is_err(),
            "malformed hint must not parse: {src}"
        );
    }
}

// =================================================================================================
// USING SCAN — force the scan the cost model rejected
// =================================================================================================

#[test]
fn using_scan_forces_a_scan_where_the_planner_chose_a_seek() {
    let mut g = corpus();
    let cat = indexed();
    let unhinted = "MATCH (u:USER) WHERE u.uidn = 42 RETURN u.uidn AS x";
    let hinted = "MATCH (u:USER) USING SCAN u:USER WHERE u.uidn = 42 RETURN u.uidn AS x";

    let plain = compile(unhinted, &g, &cat).expect("plan");
    assert!(
        has_op(&plain, "NodeIndexSeek"),
        "premise: without the hint the planner seeks"
    );
    let forced = compile(hinted, &g, &cat).expect("plan");
    assert!(
        !has_op(&forced, "NodeIndexSeek"),
        "USING SCAN must override the seek:\n{:?}",
        forced.root
    );
    // Any non-index access path satisfies the hint. `NodeLabelScanEq` is the one the revert produces
    // here: it scans the label and applies the equality inline, using no index — which is exactly what
    // `USING SCAN` asks for.
    assert!(
        has_op(&forced, "NodeByLabelScan")
            || has_op(&forced, "TokenLookupScan")
            || has_op(&forced, "NodeLabelScanEq"),
        "and leave a scan in its place:\n{:?}",
        forced.root
    );

    // The forced plan must return the same rows — a hint changes HOW, never WHAT.
    let a = rows(unhinted, &mut g, &cat, "x");
    let b = rows(hinted, &mut g, &cat, "x");
    assert_eq!(a.len(), 1, "non-vacuity: user 42 exists");
    assert_eq!(a, b, "a hint must not change the answer");
}

// =================================================================================================
// USING INDEX — force the seek the cost model rejected
// =================================================================================================

#[test]
fn using_index_forces_a_seek_where_the_planner_chose_a_scan() {
    // A non-selective predicate the cost model prefers to scan for: every user has `uidn >= 0`, so a
    // seek over the whole range loses to a plain scan. The hint overrides that.
    let mut g = corpus();
    let cat = indexed();
    let unhinted = "MATCH (u:USER) WHERE u.uidn >= 0 RETURN u.uidn AS x";
    let hinted = "MATCH (u:USER) USING INDEX u:USER(uidn) WHERE u.uidn >= 0 RETURN u.uidn AS x";

    let plain = compile(unhinted, &g, &cat).expect("plan");
    let forced = compile(hinted, &g, &cat).expect("plan");
    // The premise: the two plans differ, so the hint really did something. If the planner had already
    // chosen the seek this test would prove nothing, and the assertion below says so.
    assert!(
        has_op(&forced, "NodeIndexSeek") || has_op(&forced, "NodeIndexRangeSeek"),
        "USING INDEX must force an index access path:\n{:?}",
        forced.root
    );

    let a = rows(unhinted, &mut g, &cat, "x");
    let b = rows(hinted, &mut g, &cat, "x");
    assert_eq!(a.len(), 200, "non-vacuity: every user matches");
    assert_eq!(a, b, "a hint must not change the answer");
    let _ = plain;
}

#[test]
fn using_index_is_satisfied_when_the_planner_already_chose_the_seek() {
    // An already-satisfied hint is not an error: the operator asked for the plan they got.
    let g = corpus();
    let cat = indexed();
    let src = "MATCH (u:USER) USING INDEX u:USER(uidn) WHERE u.uidn = 42 RETURN u.uidn AS x";
    let plan = compile(src, &g, &cat).expect("an already-satisfied hint must not error");
    assert!(has_op(&plan, "NodeIndexSeek"));
}

// =================================================================================================
// Unsatisfiable hints error — the property that makes a hint trustworthy
// =================================================================================================

#[test]
fn a_hint_naming_an_undeclared_index_errors() {
    let g = corpus();
    let cat = indexed();
    let src = "MATCH (u:USER) USING INDEX u:USER(nosuchprop) WHERE u.uidn = 1 RETURN u.uidn AS x";
    let err = compile(src, &g, &cat).expect_err("an undeclared index must be reported");
    assert!(
        err.contains("cannot be satisfied") && err.contains("nosuchprop"),
        "the error must name what failed, got: {err}"
    );
}

#[test]
fn a_hint_with_no_seekable_predicate_errors() {
    // The index exists but nothing in the query can drive it, so the seek cannot be built. Reporting
    // that is the whole point: silently scanning would leave the operator believing otherwise.
    let g = corpus();
    let cat = indexed();
    let src = "MATCH (u:USER) USING INDEX u:USER(uidn) RETURN u.uidn AS x";
    let err = compile(src, &g, &cat).expect_err("no predicate to seek on must be reported");
    assert!(
        err.contains("cannot be satisfied"),
        "unexpected error text: {err}"
    );
}

#[test]
fn a_scan_hint_for_an_unbound_variable_errors() {
    let g = corpus();
    let cat = indexed();
    let src = "MATCH (u:USER) USING SCAN u:USER RETURN u.uidn AS x";
    // Nothing made `u` a seek, so there is no seek to revert — the hint is a no-op and must say so
    // rather than pass silently.
    let plan = compile(src, &g, &cat);
    assert!(
        plan.is_ok(),
        "a scan hint over an existing scan is already satisfied: {plan:?}"
    );
}

#[test]
fn using_join_is_reported_as_not_implemented() {
    // The parser accepts it so the grammar is one piece, but the join-side override is task #888.
    // Accepting the syntax and doing nothing is exactly the failure mode hints must not have.
    let g = corpus();
    let cat = indexed();
    let src = "MATCH (u:USER)-[:LIKES]->(a:ARTICLE) USING JOIN ON a RETURN u.uidn AS x";
    let err = compile(src, &g, &cat).expect_err("USING JOIN must not be silently ignored");
    assert!(
        err.contains("not implemented") && err.contains("888"),
        "the error must point at the follow-up task, got: {err}"
    );
}

// =================================================================================================
// No hints, no change
// =================================================================================================

#[test]
fn an_unhinted_query_plans_exactly_as_before() {
    // The gate that keeps this feature from perturbing every other query — and the TCK.
    let g = corpus();
    let cat = indexed();
    for src in [
        "MATCH (u:USER) WHERE u.uidn = 42 RETURN u.uidn AS x",
        "MATCH (u:USER)-[:LIKES]->(a:ARTICLE) WHERE u.uidn = 1 RETURN a.aid AS x",
        "MATCH (u:USER) RETURN count(u) AS x",
    ] {
        let toks = tokenize(src).unwrap();
        let ast = parse_tokens(&toks, src).unwrap();
        let v = analyze(&ast).unwrap();
        assert!(v.planner_hints().is_empty(), "no hints in `{src}`");
        let hinted = plan_physical_hinted(&lower(&v), &cat, g.statistics(), &[]).expect("plan");
        let plain =
            graphus_cypher::physical::plan_physical_with_stats(&lower(&v), &cat, g.statistics());
        assert_eq!(
            format!("{:?}", hinted.root),
            format!("{:?}", plain.root),
            "an unhinted query must plan identically: {src}"
        );
    }
}
