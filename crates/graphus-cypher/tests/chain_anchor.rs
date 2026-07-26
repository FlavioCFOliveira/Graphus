//! **Cost-based anchor selection over a multi-hop chain** (`rmp` task #858).
//!
//! The rule-based anchor is whichever node was written first, so the same pattern written two ways
//! costs wildly differently. Measured on the evaluation store (200k USER / 2k ARTICLE / 3M LIKES):
//! `MATCH (u:USER {uidn:42})-[:LIKES]->(a:ARTICLE)<-[:LIKES]-(v:USER)` ran in **0.019s**, and the same
//! pattern written v-first with `WHERE u.uidn = 42` ran in **125.697s** — a 6600x gap decided purely by
//! spelling. The existing expand-direction reversal (`rmp` #366) re-anchors a SINGLE hop; this
//! generalises it to a chain.
//!
//! Correctness first: re-anchoring changes the traversal order, so every test here checks the result
//! **bag**, not just the plan shape. A directed edge is the same relationship whichever endpoint
//! enumerates it, so the two plans must agree exactly — and where they could not be made to agree
//! (a var-length hop, a cycle, an isomorphism constraint from outside the chain) the pass must decline
//! rather than reorder.

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

/// The evaluation store's shape in miniature: many `USER`s, few `ARTICLE`s, so `LIKES` fans out hugely
/// from an article and barely at all from a user — the asymmetry that makes anchor choice decisive.
///
/// Each user likes exactly **two** distinct articles, so a chain that traverses two different `LIKES`
/// out of the same user has something to match. With one like each, relationship isomorphism would make
/// every such pattern empty and every comparison over it vacuous.
fn corpus() -> MemGraph {
    let mut g = MemGraph::new();
    let users: Vec<_> = (0..400)
        .map(|i| g.add_node(["USER"], [("uidn", Value::Integer(i))]))
        .collect();
    let arts: Vec<_> = (0..4)
        .map(|i| g.add_node(["ARTICLE"], [("aid", Value::Integer(i))]))
        .collect();
    for (i, &u) in users.iter().enumerate() {
        g.add_rel("LIKES", u, arts[i % arts.len()], NO_PROPS);
        g.add_rel("LIKES", u, arts[(i + 1) % arts.len()], NO_PROPS);
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

fn has_op(plan: &PhysicalPlan, name: &str) -> bool {
    format!("{:?}", plan.root).contains(&format!("{name} {{"))
}

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

/// Runs `src` with statistics (so the cost-based passes fire) and without (the rule-based plan), and
/// asserts the two bags match and are non-empty.
///
/// This is the load-bearing check of the whole task: the no-stats plan is the reference the rewrite
/// must preserve, and comparing against it catches a re-anchoring that changes the answer.
fn assert_reanchor_preserves_bag(
    src: &str,
    g: &mut MemGraph,
    cat: &IndexCatalog,
    columns: &[&str],
) {
    let with_stats = bag(src, g, cat, columns);
    // The no-stats path runs no cost-based rewrite at all, so it is the rule-based reference.
    let toks = tokenize(src).unwrap();
    let ast = parse_tokens(&toks, src).unwrap();
    let v = analyze(&ast).unwrap();
    let rule = plan_physical_with_stats(&lower(&v), cat, None);
    let bound = bind_parameters(&rule, &Parameters::new()).expect("bind");
    let mut reference: Vec<String> = execute(&rule, &bound, g)
        .unwrap_or_else(|e| panic!("open reference `{src}`: {e:?}"))
        .collect_all()
        .unwrap_or_else(|e| panic!("run reference `{src}`: {e:?}"))
        .iter()
        .map(|r| {
            columns
                .iter()
                .map(|c| format!("{:?}", r.value(c)))
                .collect::<Vec<_>>()
                .join("|")
        })
        .collect();
    reference.sort();
    assert!(
        !reference.is_empty(),
        "the corpus query must match something, else the comparison is vacuous: {src}"
    );
    assert_eq!(
        with_stats, reference,
        "re-anchoring changed the result bag for `{src}`"
    );
}

// =================================================================================================
// The measured case
// =================================================================================================

const SEEK_FIRST: &str = "MATCH (u:USER)-[:LIKES]->(a:ARTICLE)<-[:LIKES]-(v:USER) WHERE u.uidn = 42 \
     RETURN v.uidn AS other ORDER BY other";
const V_FIRST: &str = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE)<-[:LIKES]-(u:USER) WHERE u.uidn = 42 \
     RETURN v.uidn AS other ORDER BY other";

#[test]
fn both_spellings_of_the_measured_pattern_anchor_on_the_indexed_node() {
    let g = corpus();
    let cat = indexed();
    for src in [SEEK_FIRST, V_FIRST] {
        let plan = compile(src, &g, &cat);
        assert!(
            has_op(&plan, "NodeIndexSeek"),
            "spelling must anchor on the indexed node, not on whichever was written first:\n{src}\n{:?}",
            plan.root
        );
    }
    // And the spelling that used to scan no longer does.
    assert!(
        !has_op(&compile(V_FIRST, &g, &cat), "NodeByLabelScan"),
        "the v-first spelling must no longer anchor on a full label scan"
    );
}

#[test]
fn the_two_spellings_return_the_same_rows() {
    // Non-vacuous by construction: user 42 shares its article with 99 others in this corpus.
    let mut g = corpus();
    let cat = indexed();
    let a = bag(SEEK_FIRST, &mut g, &cat, &["other"]);
    let b = bag(V_FIRST, &mut g, &cat, &["other"]);
    assert!(
        a.len() > 50,
        "expected a real fan-out, got {} rows",
        a.len()
    );
    assert_eq!(a, b, "the two spellings describe the same pattern");
}

#[test]
fn re_anchoring_preserves_the_rule_based_bag() {
    let mut g = corpus();
    let cat = indexed();
    assert_reanchor_preserves_bag(V_FIRST, &mut g, &cat, &["other"]);
    assert_reanchor_preserves_bag(SEEK_FIRST, &mut g, &cat, &["other"]);
}

// =================================================================================================
// Bag equality across the shapes that decide legality
// =================================================================================================

#[test]
fn mixed_direction_chains_preserve_the_bag() {
    // Every hop reversed on re-anchoring must enumerate the same directed edges. A chain whose hops
    // point different ways is where a sign error would show.
    let mut g = corpus();
    let cat = indexed();
    for src in [
        "MATCH (v:USER)-[:LIKES]->(a:ARTICLE)<-[:LIKES]-(u:USER) WHERE u.uidn = 3 \
         RETURN v.uidn AS x ORDER BY x",
        "MATCH (a:ARTICLE)<-[:LIKES]-(v:USER) WHERE v.uidn = 3 RETURN a.aid AS x ORDER BY x",
        "MATCH (a:ARTICLE)<-[:LIKES]-(v:USER)-[:LIKES]->(b:ARTICLE) WHERE v.uidn = 3 \
         RETURN b.aid AS x ORDER BY x",
    ] {
        assert_reanchor_preserves_bag(src, &mut g, &cat, &["x"]);
    }
}

#[test]
fn relationship_isomorphism_survives_re_anchoring() {
    // The trap. Both hops have the SAME type, so the same relationship could be traversed twice unless
    // the isomorphism set is re-derived for the new order. If it were dropped, the v-first spelling
    // would gain rows where `v == u` walked one edge in both directions.
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE)<-[:LIKES]-(u:USER) WHERE u.uidn = 5 \
               RETURN v.uidn AS x ORDER BY x";
    assert_reanchor_preserves_bag(src, &mut g, &cat, &["x"]);
    // Specifically: user 5 must NOT appear as its own neighbour. Reaching itself would need two
    // DISTINCT likes from user 5 to the same article, which the corpus does not contain — so any
    // occurrence of 5 here is an isomorphism constraint that was dropped when the order changed.
    let rows = bag(src, &mut g, &cat, &["x"]);
    assert!(
        !rows.iter().any(|r| r == "Integer(5)"),
        "isomorphism must exclude the anchor reaching itself through the edge it already used"
    );
    assert!(!rows.is_empty(), "and the pattern must still match");
}

#[test]
fn a_var_length_hop_is_declined() {
    // A variable-length hop's reversal is not proven to enumerate the same paths, so the chain must not
    // be re-anchored at all. The answer must still be right, which is what this asserts.
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (v:USER)-[:LIKES*1..2]->(a)<-[:LIKES]-(u:USER) WHERE u.uidn = 6 \
               RETURN v.uidn AS x ORDER BY x";
    assert_reanchor_preserves_bag(src, &mut g, &cat, &["x"]);
}

#[test]
fn a_predicate_on_the_middle_node_still_yields_the_right_rows() {
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE)<-[:LIKES]-(u:USER) \
               WHERE a.aid = 1 AND u.uidn = 9 RETURN v.uidn AS x ORDER BY x";
    assert_reanchor_preserves_bag(src, &mut g, &cat, &["x"]);
}

#[test]
fn an_unindexed_chain_is_unchanged() {
    // With nothing seekable anywhere, no candidate can beat the rule-based plan, so the plan must be
    // the rule-based one — the gate that keeps this rewrite from perturbing queries it cannot help.
    let mut g = corpus();
    let empty = IndexCatalog::empty();
    let src = "MATCH (v:USER)-[:LIKES]->(a:ARTICLE)<-[:LIKES]-(u:USER) WHERE u.uidn = 11 \
               RETURN v.uidn AS x ORDER BY x";
    assert_reanchor_preserves_bag(src, &mut g, &empty, &["x"]);
}

#[test]
fn plan_choice_is_deterministic_for_fixed_statistics() {
    let g = corpus();
    let cat = indexed();
    let first = format!("{:?}", compile(V_FIRST, &g, &cat).root);
    for _ in 0..4 {
        assert_eq!(
            first,
            format!("{:?}", compile(V_FIRST, &g, &cat).root),
            "the chosen anchor must be stable for fixed statistics"
        );
    }
}

#[test]
fn planning_stays_bounded_on_a_long_chain() {
    // The enumeration is linear in the chain length (one candidate per node), not factorial. A ten-hop
    // chain must therefore plan promptly; a factorial search would not return.
    let g = corpus();
    let cat = indexed();
    let mut src = String::from("MATCH (n0:USER)");
    for i in 1..=10 {
        let label = if i % 2 == 1 { "ARTICLE" } else { "USER" };
        src.push_str(&format!("-[:LIKES]->(n{i}:{label})"));
    }
    src.push_str(" WHERE n0.uidn = 1 RETURN count(*) AS c");
    let start = std::time::Instant::now();
    let plan = compile(&src, &g, &cat);
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 5,
        "planning a 10-hop chain took {elapsed:?}"
    );
    assert!(has_op(&plan, "ExpandAll"), "sanity: the plan must expand");
}
