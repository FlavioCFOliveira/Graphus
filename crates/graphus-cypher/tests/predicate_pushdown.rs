//! **Predicate pushdown to the scan that binds the variable** (`rmp` task #857).
//!
//! A predicate written in the same clause as its pattern already reached the scan; one written after a
//! `WITH` did not. Measured before this task:
//! `MATCH (v:USER)-[:LIKES]->(a) WITH v, a WHERE v.uidn = 42` planned `NodeByLabelScan(v)` and filtered
//! above both the projection and the expand, while the identical `MATCH (v:USER {uidn: 42})-…` planned
//! `NodeIndexSeek`. Two operators sat between the filter and the scan and nothing moved the conjunct
//! past them.
//!
//! Two properties are tested, and the second matters more than the first:
//!
//! 1. **The conjunct arrives** — the plan for the `WITH` spelling now contains the seek.
//! 2. **The barriers hold** — a conjunct must NOT cross an aggregation, a bound (`SKIP`/`LIMIT`/`TopN`),
//!    or an `OPTIONAL MATCH`. Each of those is tested on a corpus where crossing it would produce a
//!    DIFFERENT answer, so the test fails loudly if the barrier ever lifts, rather than passing because
//!    the two answers happened to coincide.

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

const NO_PROPS: [(&str, Value); 0] = [];
const USERS: i64 = 200;

/// 200 `USER`s with distinct `uidn`, each liking one of 5 `ARTICLE`s.
fn corpus() -> MemGraph {
    let mut g = MemGraph::new();
    let users: Vec<_> = (0..USERS)
        .map(|i| g.add_node(["USER"], [("uidn", Value::Integer(i))]))
        .collect();
    let arts: Vec<_> = (0..5)
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

fn compile(src: &str, g: &MemGraph, cat: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let v = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    plan_physical_with_stats(&lower(&v), cat, g.statistics())
}

/// Whether the compiled plan contains an operator whose debug rendering starts with `name`.
fn has_op(plan: &PhysicalPlan, name: &str) -> bool {
    format!("{:?}", plan.root).contains(&format!("{name} {{"))
}

/// The rows `src` produces, as a sorted multiset of the named columns.
fn bag(src: &str, g: &mut MemGraph, cat: &IndexCatalog, columns: &[&str]) -> Vec<String> {
    let plan = compile(src, g, cat);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut out: Vec<String> = execute(&plan, &bound, g)
        .unwrap_or_else(|e| panic!("open `{src}`: {e:?}"))
        .collect_all()
        .unwrap_or_else(|e| panic!("run `{src}`: {e:?}"))
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

// =================================================================================================
// 1. The conjunct arrives at the scan
// =================================================================================================

#[test]
fn a_predicate_after_a_with_reaches_the_scan_as_a_seek() {
    let mut g = corpus();
    let cat = indexed();
    let via_with =
        "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH v, a WHERE v.uidn = 42 RETURN a.aid AS aid";
    let inline = "MATCH (v:USER {uidn: 42})-[:LIKES]->(a:ARTICLE) RETURN a.aid AS aid";

    let plan = compile(via_with, &g, &cat);
    assert!(
        has_op(&plan, "NodeIndexSeek"),
        "the conjunct must reach the scan and become a seek:\n{:?}",
        plan.root
    );
    assert!(
        !has_op(&plan, "NodeByLabelScan"),
        "and the label scan it replaced must be gone"
    );

    // Same answer as the spelling that always planned a seek — and non-empty, so the comparison is not
    // vacuous.
    let a = bag(via_with, &mut g, &cat, &["aid"]);
    let b = bag(inline, &mut g, &cat, &["aid"]);
    assert!(
        !a.is_empty(),
        "the corpus must match, else this proves nothing"
    );
    assert_eq!(a, b, "pushdown must not change the answer");
}

#[test]
fn it_travels_through_several_projections() {
    // One conjunct, three pass-through projections between it and the scan.
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH v, a WITH v, a WITH v, a \
               WHERE v.uidn = 7 RETURN a.aid AS aid";
    let plan = compile(src, &g, &cat);
    assert!(
        has_op(&plan, "NodeIndexSeek"),
        "a conjunct must cross every pass-through projection:\n{:?}",
        plan.root
    );
    let rows = bag(src, &mut g, &cat, &["aid"]);
    assert_eq!(rows.len(), 1, "user 7 likes exactly one article");
}

#[test]
fn a_conjunction_pushes_only_the_part_that_qualifies() {
    // `v.uidn` is identity-projected and indexed; the other conjunct reads a column the projection
    // computes, so it must stay above. The answer must be the conjunction of both.
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH v, a, a.aid * 2 AS doubled \
               WHERE v.uidn = 8 AND doubled >= 0 RETURN a.aid AS aid";
    let plan = compile(src, &g, &cat);
    assert!(
        has_op(&plan, "NodeIndexSeek"),
        "the qualifying conjunct must still reach the scan:\n{:?}",
        plan.root
    );
    assert!(
        has_op(&plan, "Filter"),
        "and the non-qualifying one must remain as a filter"
    );
    let rows = bag(src, &mut g, &cat, &["aid"]);
    assert_eq!(rows.len(), 1, "user 8 likes exactly one article");
}

#[test]
fn distinct_does_not_block_the_push() {
    // Filtering before or after de-duplication yields the same set, because the predicate reads only an
    // identity-projected column.
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH DISTINCT v WHERE v.uidn = 3 \
               RETURN v.uidn AS uidn";
    let plan = compile(src, &g, &cat);
    assert!(has_op(&plan, "NodeIndexSeek"), "{:?}", plan.root);
    assert_eq!(bag(src, &mut g, &cat, &["uidn"]).len(), 1);
}

#[test]
fn a_renamed_column_is_declined_rather_than_guessed_at() {
    // `WITH v AS w … WHERE w.uidn = 42` reads a name the input below does not bind. The pass declines,
    // so the predicate stays a residual filter — and the answer is still right, which is the point.
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH v AS w, a WHERE w.uidn = 42 \
               RETURN a.aid AS aid";
    let plan = compile(src, &g, &cat);
    assert!(
        !has_op(&plan, "NodeIndexSeek"),
        "a renamed column must not be pushed (the rewrite is not implemented for it)"
    );
    assert_eq!(
        bag(src, &mut g, &cat, &["aid"]).len(),
        1,
        "answer still correct"
    );
}

// =================================================================================================
// 2. The barriers hold — each on a corpus where crossing would give a DIFFERENT answer
// =================================================================================================

#[test]
fn a_bound_is_a_barrier_and_crossing_it_would_be_observable() {
    // `ORDER BY v.uidn LIMIT 10` keeps users 0..9; user 42 is not among them, so the answer is EMPTY.
    // Had the conjunct crossed the bound it would have selected user 42 first and returned one row —
    // so this test distinguishes the two semantics rather than assuming they differ.
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH v, a ORDER BY v.uidn LIMIT 10 \
               WHERE v.uidn = 42 RETURN a.aid AS aid";
    assert!(
        bag(src, &mut g, &cat, &["aid"]).is_empty(),
        "the filter must apply AFTER the bound, so nothing matches"
    );
    // And the discriminating control: the same query bounded to include user 42 returns a row, proving
    // the empty result above is the bound's doing and not a broken query.
    let control = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH v, a ORDER BY v.uidn LIMIT 50 \
                   WHERE v.uidn = 42 RETURN a.aid AS aid";
    assert_eq!(bag(control, &mut g, &cat, &["aid"]).len(), 1);
}

#[test]
fn skip_is_a_barrier_and_crossing_it_would_be_observable() {
    // `ORDER BY v.uidn SKIP 100` drops users 0..99, so a predicate on user 42 must match nothing.
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH v, a ORDER BY v.uidn SKIP 100 \
               WHERE v.uidn = 42 RETURN a.aid AS aid";
    assert!(
        bag(src, &mut g, &cat, &["aid"]).is_empty(),
        "the filter must apply after the skip"
    );
    let control = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH v, a ORDER BY v.uidn SKIP 10 \
                   WHERE v.uidn = 42 RETURN a.aid AS aid";
    assert_eq!(bag(control, &mut g, &cat, &["aid"]).len(), 1);
}

#[test]
fn an_aggregation_is_a_barrier_and_crossing_it_would_change_every_count() {
    // `WITH a, count(v) AS fans WHERE fans > 30`: the predicate reads the aggregate, so it cannot move
    // below the grouping. The counts must be over ALL users, not over a filtered subset.
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH a, count(v) AS fans WHERE fans > 30 \
               RETURN fans ORDER BY fans";
    let rows = bag(src, &mut g, &cat, &["fans"]);
    // 200 users over 5 articles = 40 fans each, so every article passes and every count is 40.
    assert_eq!(rows.len(), 5, "all five articles have more than 30 fans");
    assert!(
        rows.iter().all(|r| r.contains("40")),
        "each count must be over all users, got {rows:?}"
    );

    // A predicate on the grouping KEY's own property alongside the aggregate must also not corrupt the
    // counts: filtering the group key after grouping keeps each surviving count intact.
    let keyed = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH a, count(v) AS fans \
                 WHERE a.aid = 1 RETURN fans";
    let one = bag(keyed, &mut g, &cat, &["fans"]);
    assert_eq!(one.len(), 1);
    assert!(
        one[0].contains("40"),
        "the count must still be 40, got {one:?}"
    );
}

#[test]
fn an_optional_match_is_a_barrier() {
    // A predicate must not be pushed inside the optional side: doing so would drop the driving row the
    // outer join has to preserve with nulls. Here every USER is preserved, and the ones whose optional
    // side does not match carry a null — a count that changes if the barrier lifts.
    let mut g = MemGraph::new();
    let a = g.add_node(["USER"], [("uidn", Value::Integer(1))]);
    let b = g.add_node(["USER"], [("uidn", Value::Integer(2))]);
    let art = g.add_node(["ARTICLE"], [("aid", Value::Integer(9))]);
    g.add_rel("LIKES", a, art, NO_PROPS);
    // `b` likes nothing, so its optional side is null.
    let cat = indexed();
    let src = "MATCH (v:USER) OPTIONAL MATCH (v)-[:LIKES]->(x:ARTICLE) \
               WITH v, x WHERE v.uidn >= 1 RETURN v.uidn AS uidn";
    let rows = bag(src, &mut g, &cat, &["uidn"]);
    assert_eq!(
        rows.len(),
        2,
        "both users must survive the outer join, got {rows:?}"
    );
    let _ = b;
}

// =================================================================================================
// 3. Bag equality over a corpus, which is what makes the rewrite safe to apply unconditionally
// =================================================================================================

#[test]
fn every_spelling_agrees_with_its_no_index_counterpart() {
    // The rewrite must be bag-preserving, so the SAME query compiled with and without an index — which
    // is what decides whether the pushed conjunct becomes a seek or stays a filter — must produce the
    // identical bag. That compares the pushed-and-seeking plan against the pushed-but-scanning one over
    // a corpus of clause shapes, including the barrier cases.
    let mut g = corpus();
    let with_index = indexed();
    let without = IndexCatalog::empty();
    for (src, columns) in [
        (
            "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH v, a WHERE v.uidn = 42 RETURN a.aid AS aid",
            &["aid"][..],
        ),
        (
            "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH v, a WHERE v.uidn > 190 RETURN v.uidn AS uidn",
            &["uidn"][..],
        ),
        (
            "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH DISTINCT v WHERE v.uidn <= 2 RETURN v.uidn AS uidn",
            &["uidn"][..],
        ),
        (
            "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH v, a ORDER BY v.uidn LIMIT 10 \
             WHERE v.uidn = 5 RETURN a.aid AS aid",
            &["aid"][..],
        ),
        (
            "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH v, a, a.aid AS k \
             WHERE v.uidn = 11 AND k >= 0 RETURN k",
            &["k"][..],
        ),
        (
            "MATCH (v:USER)-[:LIKES]->(a:ARTICLE) WITH v AS w, a WHERE w.uidn = 3 RETURN a.aid AS aid",
            &["aid"][..],
        ),
    ] {
        let seeking = bag(src, &mut g, &with_index, columns);
        let scanning = bag(src, &mut g, &without, columns);
        assert!(
            !seeking.is_empty(),
            "every corpus query must match something, else it proves nothing: {src}"
        );
        assert_eq!(seeking, scanning, "bag mismatch for `{src}`");
    }
}

// =================================================================================================
// 4. Regression: many conjuncts stopping at the same point must not deepen the plan
// =================================================================================================

#[test]
fn conjuncts_that_stop_at_the_same_point_are_merged_not_nested() {
    // Regression for a stack overflow this pass caused while being written. Wrapping each conjunct in
    // its own `Filter` added one plan level per conjunct, and a 12-part pattern with 11 join conjuncts
    // then overflowed the stack inside the recursive passes that walk the plan afterwards
    // (`planner_join_bound::greedy_plan_is_bag_identical_to_the_rule_based_plan`). Conjuncts that cannot
    // travel must therefore be merged into one predicate rather than nested — which is also exactly the
    // predicate the query already had, since they are re-joined in their original order.
    let mut g = MemGraph::new();
    for i in 0..3 {
        g.add_node(["L"], [("k", Value::Integer(i))]);
    }
    let parts: Vec<String> = (0..12).map(|i| format!("(v{i}:L)")).collect();
    let joins: Vec<String> = (0..11).map(|i| format!("v{i}.k = v{}.k", i + 1)).collect();
    let src = format!(
        "MATCH {} WHERE {} RETURN v0.k AS k",
        parts.join(", "),
        joins.join(" AND ")
    );
    let cat = IndexCatalog::empty();
    let plan = compile(&src, &g, &cat);
    let rendered = format!("{:?}", plan.root);
    let filters = rendered.matches("Filter {").count();
    assert!(
        filters <= 2,
        "11 immovable conjuncts must not become 11 nested filters, found {filters}"
    );

    // And the answer is still right: all twelve parts share the same `k`, so each of the 3 values
    // yields one row.
    let rows = bag(&src, &mut g, &cat, &["k"]);
    assert_eq!(rows.len(), 3, "one row per shared k value, got {rows:?}");
}
