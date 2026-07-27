//! **Splitting a pattern at a shared node into two hash-joined halves** (`rmp` task #880).
//!
//! A single pipeline walks a pattern left-to-right from one anchor, so a pattern selective at BOTH
//! ends and unselective in the middle has to materialise the whole middle: it walks out from one
//! anchor through the wide part and only discovers the other end at the far side. Cutting the pattern
//! at a middle node lets each end pay only its own fan-out, with a
//! [`HashJoin`](graphus_cypher::physical::PhysicalOp::HashJoin) meeting them on the shared node — the
//! shape Neo4j's IDP solver plans as two `Expand` pipelines under a `NodeHashJoin`.
//!
//! **The trap this suite exists for.** Relationship isomorphism spans the whole `MATCH`, but two
//! independently planned halves have no link between their traversed relationships, so a cut can
//! produce rows the single pipeline rejects. The planner restores it as an explicit `<>` guard per
//! cross pair; [`the_isomorphism_guard_is_load_bearing`] proves the guard is not decoration by
//! stripping it from a real planned tree and showing the answer changes.
//!
//! Every correctness test compares the **bag** the cut plan produces against the bag the un-optimised
//! (statistics-free) plan produces, never against a hand-written expectation — the discipline the
//! "an optimisation changes the answer" defect class demands.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, MemGraph};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, plan_physical_with_stats};
use graphus_cypher::semantics::analyze;

const NO_PROPS: [(&str, Value); 0] = [];

// =================================================================================================
// Corpus
// =================================================================================================

/// A store shaped like the case the task exists for: a handful of `TOPIC` hubs every `PERSON`
/// follows, so `FOLLOWS` fans out enormously from a topic and barely at all from a person, and many
/// `CITY` nodes so an anchor on a city is selective.
///
/// Two deliberate irregularities, both load-bearing for tests below:
///
/// * person 0 follows topic 0 **twice** (parallel edges). Without that, two halves that meet on a
///   topic could never bind the same `FOLLOWS`, and the isomorphism test would be vacuous.
/// * every person lives in exactly one city and follows exactly two topics, so a pattern that walks
///   out and back has something to match.
fn corpus() -> MemGraph {
    let mut g = MemGraph::new();
    let topics: Vec<_> = (0..4)
        .map(|i| g.add_node(["TOPIC"], [("tid", Value::Integer(i))]))
        .collect();
    let cities: Vec<_> = (0..50)
        .map(|i| g.add_node(["CITY"], [("cname", Value::Integer(i))]))
        .collect();
    let people: Vec<_> = (0..600i64)
        .map(|i| g.add_node(["PERSON"], [("pid", Value::Integer(i))]))
        .collect();
    for (i, &p) in people.iter().enumerate() {
        g.add_rel("FOLLOWS", p, topics[i % 4], NO_PROPS);
        g.add_rel("FOLLOWS", p, topics[(i + 1) % 4], NO_PROPS);
        g.add_rel("LIVES_IN", p, cities[i % 50], NO_PROPS);
    }
    // The parallel edge. Person 0 now follows topic 0 twice.
    g.add_rel("FOLLOWS", people[0], topics[0], NO_PROPS);
    g
}

fn indexed() -> IndexCatalog {
    IndexCatalog::builder()
        .with_label_property("CITY", "cname")
        .with_label_property("PERSON", "pid")
        .build()
}

// =================================================================================================
// Harness
// =================================================================================================

fn compile(src: &str, g: &MemGraph, cat: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let v = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    plan_physical_with_stats(&lower(&v), cat, g.statistics())
}

/// The statistics-free plan: no cost-based rewrite runs at all, so this is the reference every bag
/// comparison below is made against.
fn compile_rule_based(src: &str, cat: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).unwrap();
    let ast = parse_tokens(&toks, src).unwrap();
    let v = analyze(&ast).unwrap();
    plan_physical_with_stats(&lower(&v), cat, None)
}

fn rows_of(plan: &PhysicalPlan, g: &mut MemGraph, columns: &[&str]) -> Vec<String> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut out: Vec<String> = execute(plan, &bound, g)
        .unwrap_or_else(|e| panic!("open: {e:?}"))
        .collect_all()
        .unwrap_or_else(|e| panic!("run: {e:?}"))
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

/// Renders the plan tree as the planner's own `Display`, which is what the operator-name assertions
/// below match on.
fn rendered(plan: &PhysicalPlan) -> String {
    plan.root.to_string()
}

/// The load-bearing check of the whole task: the cost-based plan must produce exactly the bag the
/// statistics-free plan produces, and that bag must be non-empty.
///
/// # Why the plan shape is asserted too
///
/// Comparing the two bags proves nothing on its own. When the cut **declines**, the cost-based plan and
/// the statistics-free plan can be the same tree, and the comparison passes because it is comparing a
/// plan with itself — the query never exercised the rewrite under test. Every caller of this helper
/// intends to exercise a cut, so the presence of a `HashJoin` is checked here, once, rather than
/// remembered at each call site. A query that is meant to DECLINE uses
/// [`assert_declines_and_preserves_bag`] instead, which states that intent explicitly and pairs it with
/// a positive control.
fn assert_cut_preserves_bag(src: &str, g: &mut MemGraph, cat: &IndexCatalog, columns: &[&str]) {
    let plan = compile(src, g, cat);
    assert!(
        rendered(&plan).contains("HashJoin"),
        "non-vacuity: this query must really be cut, else the bag comparison compares a plan with \
         itself:\n{src}\n{}",
        plan.root
    );
    let optimised = rows_of(&plan, g, columns);
    let reference = rows_of(&compile_rule_based(src, cat), g, columns);
    assert!(
        !reference.is_empty(),
        "the corpus query must match something, else the comparison is vacuous: {src}"
    );
    assert_eq!(
        optimised, reference,
        "the cut changed the result bag for `{src}`"
    );
}

/// The mirror of [`assert_cut_preserves_bag`] for a query the planner must **refuse** to cut: the plan
/// must carry no `HashJoin`, and the bag must still be right and non-empty.
///
/// A negative assertion is worthless without a positive control, so the caller supplies `control` — a
/// query differing only in the feature that forces the decline. The control MUST be cut; if it is not,
/// the decline being asserted is some unrelated decline (no access path, an unlabelled node) and the
/// test proves nothing about the feature it names.
fn assert_declines_and_preserves_bag(
    src: &str,
    control: &str,
    g: &mut MemGraph,
    cat: &IndexCatalog,
    columns: &[&str],
) {
    let control_plan = compile(control, g, cat);
    assert!(
        rendered(&control_plan).contains("HashJoin"),
        "the positive control must be cut, else the decline below is not attributable to the feature \
         under test:\n{control}\n{}",
        control_plan.root
    );
    let plan = compile(src, g, cat);
    assert!(
        !rendered(&plan).contains("HashJoin"),
        "this pattern must NOT be cut:\n{src}\n{}",
        plan.root
    );
    let optimised = rows_of(&plan, g, columns);
    let reference = rows_of(&compile_rule_based(src, cat), g, columns);
    assert!(
        !reference.is_empty(),
        "the corpus query must match something, else the comparison is vacuous: {src}"
    );
    assert_eq!(
        optimised, reference,
        "the declined plan changed the result bag for `{src}`"
    );
}

// =================================================================================================
// (1) The measured case: two pipelines and a hash join
// =================================================================================================

/// Selective at both ends (two indexed cities), unselective in the middle (a topic every person
/// follows). Written from the middle outwards as two comma parts, which is what leaves the wide node
/// as the rule-based anchor.
const BOTH_ENDS: &str = "MATCH (t:TOPIC)<-[:FOLLOWS]-(p1:PERSON)-[:LIVES_IN]->(c1:CITY), \
                                (t)<-[:FOLLOWS]-(p2:PERSON)-[:LIVES_IN]->(c2:CITY) \
                         WHERE c1.cname = 3 AND c2.cname = 7 \
                         RETURN p1.pid AS a, p2.pid AS b ORDER BY a, b";

#[test]
fn a_pattern_selective_at_both_ends_plans_two_pipelines_and_a_hash_join() {
    let g = corpus();
    let plan = compile(BOTH_ENDS, &g, &indexed());
    let text = rendered(&plan);
    assert!(
        text.contains("HashJoin(on=[t])"),
        "the pattern must be cut at the wide middle node:\n{text}"
    );
    assert_eq!(
        text.matches("NodeIndexSeek").count(),
        2,
        "each half must be anchored on its own selective end:\n{text}"
    );
    // The single pipeline is gone: no expand may sit between the join and the rest of the plan on a
    // path that re-walks the middle.
    assert_eq!(
        text.matches("NodeByLabelScan").count(),
        0,
        "neither half may fall back to a full label scan on this corpus:\n{text}"
    );
}

#[test]
fn the_cut_plan_returns_the_rule_based_bag() {
    let mut g = corpus();
    assert_cut_preserves_bag(BOTH_ENDS, &mut g, &indexed(), &["a", "b"]);
}

#[test]
fn the_cut_really_is_reached_only_with_statistics() {
    // The decline path: with no statistics no cost-based rewrite runs, so the plan must be the
    // rule-based pipeline — untouched, not a partial answer.
    let text = compile_rule_based(BOTH_ENDS, &indexed()).root.to_string();
    assert!(
        !text.contains("HashJoin"),
        "a statistics-free plan must keep its pipeline:\n{text}"
    );
}

// =================================================================================================
// (2) Relationship isomorphism across the join
// =================================================================================================

/// [`BOTH_ENDS`] with both ends pinned to the **same** city, so the two halves may bind the same
/// person — and therefore the same `FOLLOWS` and the same `LIVES_IN`. This is the pattern the module
/// note calls reachable rather than theoretical: without the guard the cut emits rows in which one
/// edge is walked by both halves.
///
/// City 0 is chosen because person 0 lives there and follows topic 0 **twice**, so the trap is
/// exercised through parallel edges as well as through a repeated single edge.
const SHARED_RELATIONSHIP: &str = "MATCH (t:TOPIC)<-[r1:FOLLOWS]-(p1:PERSON)-[l1:LIVES_IN]->(c1:CITY), \
                                          (t)<-[r2:FOLLOWS]-(p2:PERSON)-[l2:LIVES_IN]->(c2:CITY) \
                                   WHERE c1.cname = 0 AND c2.cname = 0 \
                                   RETURN p1.pid AS x, p2.pid AS y ORDER BY x, y";

#[test]
fn halves_that_can_share_a_relationship_still_return_the_rule_based_bag() {
    let mut g = corpus();
    assert_cut_preserves_bag(SHARED_RELATIONSHIP, &mut g, &indexed(), &["x", "y"]);
}

/// Removes the `Filter` sitting directly above the plan's `HashJoin`, returning the tree without it.
///
/// Used only to prove the guard matters: it reconstructs, from a really planned tree, the plan the
/// cut WOULD have produced had the isomorphism repair been left out.
fn strip_filter_above_hash_join(op: PhysicalOp) -> (PhysicalOp, bool) {
    if let PhysicalOp::Filter { input, predicate } = op {
        if matches!(input.as_ref(), PhysicalOp::HashJoin { .. }) {
            return (*input, true);
        }
        let (inner, stripped) = strip_filter_above_hash_join(*input);
        return (
            PhysicalOp::Filter {
                input: Box::new(inner),
                predicate,
            },
            stripped,
        );
    }
    match op {
        PhysicalOp::Projection {
            input,
            items,
            distinct,
        } => {
            let (inner, stripped) = strip_filter_above_hash_join(*input);
            (
                PhysicalOp::Projection {
                    input: Box::new(inner),
                    items,
                    distinct,
                },
                stripped,
            )
        }
        PhysicalOp::Sort { input, keys } => {
            let (inner, stripped) = strip_filter_above_hash_join(*input);
            (
                PhysicalOp::Sort {
                    input: Box::new(inner),
                    keys,
                },
                stripped,
            )
        }
        other => (other, false),
    }
}

#[test]
fn the_isomorphism_guard_is_load_bearing() {
    // Non-vacuity, demonstrated rather than asserted. The planned tree carries an `r1 <> r2` guard
    // above its hash join; strip that one operator and the SAME plan answers differently. That is the
    // proof the guard is what keeps the cut sound — and the proof this test would fail if the repair
    // were removed from the planner.
    let mut g = corpus();
    let cat = indexed();
    let plan = compile(SHARED_RELATIONSHIP, &g, &cat);
    let text = rendered(&plan);
    assert!(
        text.contains("HashJoin"),
        "premise: this pattern must really be cut, else the test proves nothing:\n{text}"
    );
    assert!(
        text.contains("r1 <> r2") || text.contains("r2 <> r1"),
        "the cut must re-impose relationship isomorphism across the join:\n{text}"
    );

    let guarded = rows_of(&plan, &mut g, &["x", "y"]);
    let reference = rows_of(
        &compile_rule_based(SHARED_RELATIONSHIP, &cat),
        &mut g,
        &["x", "y"],
    );
    assert!(!reference.is_empty(), "non-vacuity: the pattern must match");
    assert_eq!(
        guarded, reference,
        "the guarded cut must agree with the reference"
    );

    let mut unguarded = compile(SHARED_RELATIONSHIP, &g, &cat);
    let (root, stripped) = strip_filter_above_hash_join(unguarded.root);
    assert!(stripped, "the guard `Filter` must have been found to strip");
    unguarded.root = root;
    let without = rows_of(&unguarded, &mut g, &["x", "y"]);
    assert!(
        without.len() > guarded.len(),
        "without the guard the cut must produce rows the pipeline rejects — it produced {} against \
         {}, so this corpus does not exercise the trap and the test is vacuous",
        without.len(),
        guarded.len()
    );
}

// =================================================================================================
// (3) The corpus of shapes that decide legality
// =================================================================================================

/// Counts the relationship-isomorphism guards the plan carries — one `a <> b` per cross pair the
/// type-disjointness proof could not eliminate.
fn guard_count(plan: &PhysicalPlan) -> usize {
    rendered(plan).matches(" <> ").count()
}

#[test]
fn every_cross_pair_of_one_repeated_type_carries_a_guard() {
    // Four hops, every one of them `FOLLOWS`, cut two-and-two — so all FOUR cross pairs are between
    // hops of the same type and none can be eliminated by the type-disjointness proof. This is the
    // suite's coverage of the fully-guarded case, so the guard COUNT is asserted, not just the bag: a
    // guard silently dropped from one pair would still leave a plan that looks cut.
    //
    // Person 0 has three `FOLLOWS` (topic 0 twice, topic 1 once) and person 4 has two, which is what
    // makes a four-distinct-relationship pattern satisfiable at all.
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (t:TOPIC)<-[:FOLLOWS]-(p1:PERSON)-[:FOLLOWS]->(t2:TOPIC), \
                      (t)<-[:FOLLOWS]-(p2:PERSON)-[:FOLLOWS]->(t3:TOPIC) \
               WHERE p1.pid = 0 AND p2.pid = 4 RETURN t.tid AS x ORDER BY x";
    assert_eq!(
        guard_count(&compile(src, &g, &cat)),
        4,
        "all four cross pairs share the `FOLLOWS` type, so all four must be guarded:\n{}",
        compile(src, &g, &cat).root
    );
    assert_cut_preserves_bag(src, &mut g, &cat, &["x"]);
}

#[test]
fn a_provably_disjoint_cross_pair_is_left_unguarded() {
    // The other side of the same coin. `BOTH_ENDS` cuts two `FOLLOWS`/`LIVES_IN` halves, so of its four
    // cross pairs two pit `FOLLOWS` against `LIVES_IN` — a relationship carries exactly one type, so
    // those two can never denote the same edge and need no guard. Exactly two guards must remain.
    //
    // Pinning the count is what makes the optimisation honest in both directions: three or four guards
    // would mean the proof stopped firing, and one would mean a same-type pair had been dropped.
    let mut g = corpus();
    let cat = indexed();
    assert_eq!(
        guard_count(&compile(BOTH_ENDS, &g, &cat)),
        2,
        "the two same-type cross pairs must be guarded and the two disjoint-type ones must not:\n{}",
        compile(BOTH_ENDS, &g, &cat).root
    );
    assert_cut_preserves_bag(BOTH_ENDS, &mut g, &cat, &["a", "b"]);
}

/// [`BOTH_ENDS`] with one hop made variable-length. Identical in every other respect, which is what
/// makes it a controlled experiment: the only thing that can explain a decline is the range.
const VAR_LENGTH_VARIANTS: &[&str] = &[
    "MATCH (t:TOPIC)<-[:FOLLOWS]-(p1:PERSON)-[:LIVES_IN*1..1]->(c1:CITY), \
            (t)<-[:FOLLOWS]-(p2:PERSON)-[:LIVES_IN]->(c2:CITY) \
     WHERE c1.cname = 3 AND c2.cname = 7 RETURN p1.pid AS a, p2.pid AS b ORDER BY a, b",
    "MATCH (t:TOPIC)<-[:FOLLOWS*1..2]-(p1:PERSON)-[:LIVES_IN]->(c1:CITY), \
            (t)<-[:FOLLOWS]-(p2:PERSON)-[:LIVES_IN]->(c2:CITY) \
     WHERE c1.cname = 3 AND c2.cname = 7 RETURN p1.pid AS a, p2.pid AS b ORDER BY a, b",
];

#[test]
fn a_var_length_hop_is_declined_and_the_bag_is_unchanged() {
    // A variable-length hop binds a LIST of relationships, so disjointness across a join would need
    // list-vs-list and list-vs-scalar cases the guard cannot express. `recognise_expand_chain` refuses
    // such a pattern outright, which is why those cases are unreachable rather than unhandled — and
    // this pins that the refusal leaves a correct plan rather than a partial one.
    //
    // Each variant is `BOTH_ENDS` with exactly one hop made variable-length, and `BOTH_ENDS` itself is
    // the positive control. Without that control a decline could just as well mean "no access path" or
    // "an unlabelled node", and the test would prove nothing about variable length at all — note that
    // `*1..1` traverses precisely one hop, so even the degenerate range must decline.
    let mut g = corpus();
    let cat = indexed();
    for src in VAR_LENGTH_VARIANTS {
        assert_declines_and_preserves_bag(src, BOTH_ENDS, &mut g, &cat, &["a", "b"]);
    }
}

#[test]
fn a_predicate_spanning_both_halves_preserves_the_bag() {
    // A conjunct that reads a variable from each half cannot be pushed into either; it must stay above
    // the join. If it were handed to one half it would test an unbound column and silently drop rows.
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (t:TOPIC)<-[:FOLLOWS]-(p1:PERSON)-[:LIVES_IN]->(c1:CITY), \
                      (t)<-[:FOLLOWS]-(p2:PERSON)-[:LIVES_IN]->(c2:CITY) \
               WHERE c1.cname = 3 AND c2.cname = 7 AND p1.pid < p2.pid \
               RETURN p1.pid AS a, p2.pid AS b ORDER BY a, b";
    // The spanning conjunct must survive into the plan, above the join — if the placement logic had
    // dropped it the bag comparison below would still pass whenever the predicate happens to select
    // everything, so its presence is asserted directly.
    let text = rendered(&compile(src, &g, &cat));
    assert!(
        text.contains("p1.pid < p2.pid"),
        "the spanning conjunct must be re-applied above the join:\n{text}"
    );
    assert_cut_preserves_bag(src, &mut g, &cat, &["a", "b"]);
}

#[test]
fn the_written_anchors_own_seek_is_offered_as_a_candidate() {
    // The regression this pins. The chain search runs top-down, BEFORE the children are optimised, so
    // its baseline is the raw subtree — whose bottom `recognise_expand_chain` requires to be a plain
    // scan. Every other candidate is built by `candidate_anchored_at`, which DOES build an index seek.
    // Enumerating only `k >= 1` therefore raced "written anchor, scanned" against "every other anchor,
    // seeked", and the written anchor could lose on the strength of a seek it was never offered.
    //
    // Measured before the repair, on this corpus with an index on `PERSON.pid` only: the plan bottomed
    // out in `AllNodesScan(a)` under `Filter(a:PERSON AND a.pid = 5)`. With `k = 0` enumerated it
    // bottoms out in `NodeIndexSeek(a:PERSON pid = 5)`.
    //
    // The anchor is written WITHOUT its label in the pattern, which is what keeps the rule-based
    // lowering from consuming the predicate into a seek by itself — otherwise the recogniser would see
    // a seek at the bottom, decline, and the case could not arise.
    let mut g = corpus();
    let cat = indexed();
    for src in [
        "MATCH (a)-[:FOLLOWS]->(t:TOPIC)<-[:FOLLOWS]-(b:PERSON) \
         WHERE a:PERSON AND a.pid = 5 RETURN b.pid AS a, b.pid AS b ORDER BY a, b",
        "MATCH (a)-[:LIVES_IN]->(c:CITY)<-[:LIVES_IN]-(b:PERSON) \
         WHERE a:PERSON AND a.pid = 5 RETURN b.pid AS a, b.pid AS b ORDER BY a, b",
        "MATCH (a)-[:FOLLOWS]->(t:TOPIC)<-[:FOLLOWS]-(b:PERSON)-[:LIVES_IN]->(c:CITY) \
         WHERE a:PERSON AND a.pid = 5 RETURN c.cname AS a, c.cname AS b ORDER BY a, b",
    ] {
        let plan = compile(src, &g, &cat);
        let text = rendered(&plan);
        assert!(
            text.contains("NodeIndexSeek(a:PERSON pid = 5"),
            "the written anchor's own seek must be among the candidates:\n{src}\n{text}"
        );
        assert!(
            !text.contains("AllNodesScan"),
            "and it must beat scanning every node:\n{src}\n{text}"
        );
        // The whole point is that it is a better plan, not merely a different one — so the answer must
        // still be the reference answer.
        let optimised = rows_of(&plan, &mut g, &["a", "b"]);
        let reference = rows_of(&compile_rule_based(src, &cat), &mut g, &["a", "b"]);
        assert!(!reference.is_empty(), "non-vacuity: `{src}` must match");
        assert_eq!(optimised, reference, "the bag changed for `{src}`");
    }
}

#[test]
fn a_cut_needs_no_index_and_still_preserves_the_bag() {
    // Measured, and not what the first version of this test assumed. With an EMPTY catalogue the
    // pattern is still cut: each half falls back to a label scan, and two scans plus a hash join beat
    // one scan plus the whole middle fan-out. The rewrite is therefore not index-gated — which makes
    // this the case that exercises `best_anchoring`'s scan fallback rather than its seek path.
    let mut g = corpus();
    let empty = IndexCatalog::empty();
    assert_cut_preserves_bag(BOTH_ENDS, &mut g, &empty, &["a", "b"]);
}

// =================================================================================================
// (4) Determinism and bounded planning
// =================================================================================================

#[test]
fn plan_choice_is_deterministic_for_fixed_statistics() {
    let g = corpus();
    let cat = indexed();
    let first = rendered(&compile(BOTH_ENDS, &g, &cat));
    for _ in 0..8 {
        assert_eq!(
            first,
            rendered(&compile(BOTH_ENDS, &g, &cat)),
            "the chosen cut must be stable for fixed statistics"
        );
    }
}

/// A `MATCH` of `hops` `FOLLOWS` links whose only selective predicate sits on the **last** node.
///
/// The placement is load-bearing. `recognise_expand_chain` requires a plain scan at the bottom of the
/// chain, so putting the predicate on `n0` turns the anchor into an index seek and the recogniser
/// declines the whole pattern — the search under test would never run and every assertion over it
/// would be vacuous. On the last node the written anchor stays a label scan and the chain is really
/// searched.
fn long_pattern(hops: usize) -> String {
    let mut src = String::from("MATCH (n0:PERSON)");
    for i in 1..=hops {
        let label = if i % 2 == 1 { "TOPIC" } else { "PERSON" };
        src.push_str(&format!("<-[:FOLLOWS]-(n{i}:{label})"));
    }
    let property = if hops % 2 == 0 { "pid" } else { "tid" };
    src.push_str(&format!(
        " WHERE n{hops}.{property} = 1 RETURN count(*) AS c"
    ));
    src
}

#[test]
fn the_long_pattern_probe_really_exercises_the_search() {
    // Non-vacuity for every long-pattern claim, here and in the counted bound test in `physical.rs`:
    // this shape must be one the recogniser ACCEPTS. If it declined, the counter would read zero at
    // every size, the plateau would hold trivially, and the test below would be watching a plan the
    // search never touched.
    //
    // The observable is that the search CHANGED the plan — not that it produced any particular shape.
    // On this corpus the cost model re-anchors onto the four-node `TOPIC` scan rather than onto the
    // indexed `PERSON` at the far end, because walking four hub hops out of one person costs more than
    // scanning four topics; asserting on a seek would pin the cost model's answer instead of the fact
    // that it was asked.
    let g = corpus();
    let cat = indexed();
    for hops in [4usize, 12] {
        let src = long_pattern(hops);
        let optimised = rendered(&compile(&src, &g, &cat));
        let reference = compile_rule_based(&src, &cat).root.to_string();
        assert_ne!(
            optimised, reference,
            "the chain search must really engage with the {hops}-hop probe pattern, else the bound \
             below measures a decline:\n{optimised}"
        );
    }
}

#[test]
fn a_long_pattern_still_plans_and_a_modest_one_still_answers() {
    // The BOUND on the cut search is pinned by counting, not timing, in
    // `physical::tests::the_cut_search_stops_growing_past_the_pattern_size_bound` — a wall-clock
    // assertion in a debug build measures the machine as much as the code, and the counter is a
    // deterministic property of the planner. What is left for this level is the end-to-end statement
    // the counter cannot make.
    //
    // Split in two on purpose. A long pattern is checked for PLANNING only: executing a twelve-hop
    // walk out of every `PERSON` over a corpus with four hub topics enumerates a combinatorial number
    // of paths, so running it would measure nothing but patience. The ANSWER is checked on a pattern
    // long enough to be re-anchored and cut but small enough to execute.
    let mut g = corpus();
    let cat = indexed();
    for hops in [12usize, 24, 36] {
        let plan = compile(&long_pattern(hops), &g, &cat);
        assert!(
            rendered(&plan).contains("ExpandAll"),
            "a {hops}-hop pattern must still plan and still expand"
        );
    }
    let src = long_pattern(3);
    let optimised = rows_of(&compile(&src, &g, &cat), &mut g, &["c"]);
    let reference = rows_of(&compile_rule_based(&src, &cat), &mut g, &["c"]);
    assert_eq!(
        optimised, reference,
        "the long-pattern shape's answer changed under optimisation: {src}"
    );
}
