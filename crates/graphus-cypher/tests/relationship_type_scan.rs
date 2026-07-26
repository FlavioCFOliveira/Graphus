//! **Relationship-type scan for type-only patterns** (`rmp` task #867).
//!
//! `MATCH ()-[r:LIKES]->()` constrains no node, yet the lowerer always anchored on the pattern's
//! leading node: it scanned every node and expanded each one's incidences to reach relationships the
//! relationship store already holds contiguously. Measured on a 200k-node / 2M-`LIKES` store the query
//! `MATCH ()-[r:LIKES]->() RETURN count(r)` took **1.859 s** that way. Neo4j plans a
//! `DirectedRelationshipTypeScan` here. `LogicalOp::AllRelationshipsScan` existed — physical form, cost
//! arm, cardinality arm, `Display`, ~15 match sites — but **nothing ever constructed it**: the operator
//! was dead code reachable only from three unit tests.
//!
//! # What these tests hold down
//!
//! 1. **The lowerer emits it from a real query.** The operator can never silently return to dead code
//!    ([`the_lowerer_emits_all_relationships_scan_for_a_type_only_pattern`]).
//! 2. **The result bag is unchanged.** Every rewrite is compared against the *reference* lowering — the
//!    same pattern written with **named** endpoints, which declines the rewrite by construction and so
//!    still lowers to `AllNodesScan` + `ExpandAll`. Comparing `count`, the relationship-identity bag,
//!    and (through a named path) the **endpoint bindings in order** makes the comparison total: an
//!    undirected pattern's two orientations and a self-loop's single row are all distinguished.
//! 3. **Every declined precondition really declines**, and still answers correctly.
//! 4. **The relationship index seeks did not regress.** `try_rel_index_seek` used to pattern-match
//!    `Expand`-over-`AllNodesScan`; the shape it fires on now exists in two spellings and it must
//!    recognise both, or `MATCH ()-[r:T {p: 1}]->()` would have silently reverted from a `RelIndexSeek`
//!    to a full type scan + filter.
//! 5. **The store-scan access path agrees with the node-walk**, over the real `RecordStoreGraph`
//!    (`TxnCoordinator`), where `GraphAccess::scan_rels_by_type` actually serves the enumeration.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, MemGraph, NodeId};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::logical::LogicalOp;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical, plan_physical_with_stats};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

// =================================================================================================
// Harness
// =================================================================================================

/// A corpus with **every** shape the direction rule has to distinguish: plain edges in both
/// orientations between distinct nodes, a **self-loop** (bound once by an undirected pattern, not
/// twice), parallel edges of the same type between the same pair (Graphus is a multigraph), and a
/// second relationship type so a typed scan has something to exclude.
fn corpus() -> MemGraph {
    let mut g = MemGraph::new();
    let n: Vec<NodeId> = (0..6)
        .map(|i| g.add_node(["P"], [("k", Value::Integer(i))]))
        .collect();
    // Plain edges, a couple of them parallel between the same pair.
    g.add_rel("LIKES", n[0], n[1], [("w", Value::Integer(1))]);
    g.add_rel("LIKES", n[0], n[1], [("w", Value::Integer(2))]);
    g.add_rel("LIKES", n[1], n[2], [("w", Value::Integer(3))]);
    g.add_rel("LIKES", n[3], n[0], [("w", Value::Integer(4))]);
    // A self-loop: an undirected pattern binds it ONCE, a non-self edge TWICE.
    g.add_rel("LIKES", n[4], n[4], [("w", Value::Integer(5))]);
    // A second type, plus a node (n[5]) with no LIKES at all.
    g.add_rel("FOLLOWS", n[2], n[3], [("w", Value::Integer(6))]);
    g.add_rel("FOLLOWS", n[5], n[0], [("w", Value::Integer(7))]);
    g
}

fn logical(src: &str) -> LogicalOp {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let validated = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    lower(&validated)
}

fn compile(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    plan_physical(&logical(src), catalog)
}

/// Whether the **logical** plan contains an `AllRelationshipsScan` leaf anywhere.
fn logical_has_rel_scan(op: &LogicalOp) -> bool {
    if matches!(op, LogicalOp::AllRelationshipsScan { .. }) {
        return true;
    }
    // `Display` renders the whole tree, so a textual probe covers every nesting without a 40-arm walk.
    // The operator name is not a substring of any other operator's name.
    op.to_string().contains("AllRelationshipsScan")
}

fn plan_text(src: &str, catalog: &IndexCatalog) -> String {
    compile(src, catalog).root.to_string()
}

/// Runs `src` over `g` and returns the rows, each rendered as a `|`-joined tuple of `columns`.
///
/// The rendering is stringly on purpose: it captures whatever the projection produced (integers, node
/// ids, lists of ids) without the test having to destructure per column, and it sorts, so the
/// comparison is a **bag** comparison exactly as openCypher specifies for a pattern with no `ORDER BY`.
fn bag(src: &str, g: &mut MemGraph, catalog: &IndexCatalog, columns: &[&str]) -> Vec<String> {
    let plan = compile(src, catalog);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut out: Vec<String> = execute(&plan, &bound, g)
        .unwrap_or_else(|e| panic!("open `{src}`: {e:?}"))
        .collect_all()
        .unwrap_or_else(|e| panic!("run `{src}`: {e:?}"))
        .iter()
        .map(|r| render(r, columns))
        .collect();
    out.sort();
    out
}

fn render(row: &Row, columns: &[&str]) -> String {
    columns
        .iter()
        .map(|c| format!("{:?}", row.value(c)))
        .collect::<Vec<_>>()
        .join("|")
}

/// The load-bearing comparison of the whole task: `rewritten` (which MUST lower to an
/// `AllRelationshipsScan`) and `reference` (which MUST NOT) return the **same non-empty bag**.
///
/// The two sources are the same pattern written with anonymous vs. named endpoints, so `reference` is
/// literally the lowering this task replaces — not a re-derivation of the expected answer.
fn assert_same_bag_as_reference(rewritten: &str, reference: &str, columns: &[&str]) {
    let rewritten_plan = logical(rewritten);
    let reference_plan = logical(reference);
    assert!(
        logical_has_rel_scan(&rewritten_plan),
        "`{rewritten}` must lower to a relationship-type scan, else this comparison is vacuous:\n{rewritten_plan}"
    );
    assert!(
        !logical_has_rel_scan(&reference_plan),
        "`{reference}` must keep the scan + expand reference lowering, else there is nothing to compare against:\n{reference_plan}"
    );

    let catalog = IndexCatalog::empty();
    let mut g = corpus();
    let got = bag(rewritten, &mut g, &catalog, columns);
    let mut g = corpus();
    let want = bag(reference, &mut g, &catalog, columns);
    assert!(
        !want.is_empty(),
        "the corpus must match something, else the comparison is vacuous: `{reference}`"
    );
    assert_eq!(
        got, want,
        "the relationship-type scan changed the result bag\n  rewritten: {rewritten}\n  reference: {reference}"
    );
}

// =================================================================================================
// 1. The lowerer constructs the operator (acceptance criterion 3: never dead code again)
// =================================================================================================

#[test]
fn the_lowerer_emits_all_relationships_scan_for_a_type_only_pattern() {
    // The measured query of `rmp` #867. Asserting on the LOGICAL plan is what makes this a guard
    // against the operator lapsing back into dead code: a physical-plan assertion could in principle be
    // satisfied by some other construction site, but only `lower` produces the logical operator.
    let plan = logical("MATCH ()-[r:LIKES]->() RETURN count(r) AS c");
    let leaf = find_rel_scan(&plan).unwrap_or_else(|| panic!("no AllRelationshipsScan in\n{plan}"));
    let LogicalOp::AllRelationshipsScan {
        relationship,
        from,
        to,
        direction,
        types,
    } = leaf
    else {
        unreachable!("find_rel_scan only returns that variant")
    };
    assert_eq!(relationship.name, "r");
    assert_ne!(
        from.name, to.name,
        "the two endpoints must be distinct variables, or a self-loop pattern would bind one twice"
    );
    assert_eq!(*direction, graphus_cypher::ast::RelDirection::LeftToRight);
    assert_eq!(
        types.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["LIKES"]
    );
}

/// The first `AllRelationshipsScan` in `op`, found by walking the pattern spine the lowerer builds.
fn find_rel_scan(op: &LogicalOp) -> Option<&LogicalOp> {
    match op {
        LogicalOp::AllRelationshipsScan { .. } => Some(op),
        LogicalOp::Filter { input, .. }
        | LogicalOp::Projection { input, .. }
        | LogicalOp::Aggregation { input, .. }
        | LogicalOp::NamedPath { input, .. }
        | LogicalOp::Optional { input, .. }
        | LogicalOp::Expand { input, .. } => find_rel_scan(input),
        LogicalOp::Apply { left, right } => find_rel_scan(left).or_else(|| find_rel_scan(right)),
        _ => None,
    }
}

#[test]
fn the_physical_plan_is_a_relationship_scan_not_a_node_scan_plus_expand() {
    // Acceptance criterion 1. The whole `AllNodesScan` + `ExpandAll` subtree is gone, not merely
    // supplemented.
    let rendered = plan_text(
        "MATCH ()-[r:LIKES]->() RETURN count(r) AS c",
        &IndexCatalog::empty(),
    );
    assert!(rendered.contains("AllRelationshipsScan"), "{rendered}");
    assert!(!rendered.contains("AllNodesScan"), "{rendered}");
    assert!(!rendered.contains("ExpandAll"), "{rendered}");
}

// =================================================================================================
// 2. Bag equivalence against the reference lowering (acceptance criterion 2)
// =================================================================================================

#[test]
fn directed_pattern_matches_the_reference_bag() {
    assert_same_bag_as_reference(
        "MATCH ()-[r:LIKES]->() RETURN count(r) AS c",
        "MATCH (a)-[r:LIKES]->(b) RETURN count(r) AS c",
        &["c"],
    );
    assert_same_bag_as_reference(
        "MATCH ()-[r:LIKES]->() RETURN id(r) AS rid",
        "MATCH (a)-[r:LIKES]->(b) RETURN id(r) AS rid",
        &["rid"],
    );
}

#[test]
fn reverse_arrow_pattern_matches_the_reference_bag() {
    // `<-` binds `from` to the relationship's END and `to` to its START; the named path below is what
    // proves the *binding*, not merely the relationship set.
    assert_same_bag_as_reference(
        "MATCH ()<-[r:LIKES]-() RETURN count(r) AS c",
        "MATCH (a)<-[r:LIKES]-(b) RETURN count(r) AS c",
        &["c"],
    );
}

#[test]
fn undirected_pattern_matches_the_reference_bag() {
    // The trap this task had to fix: the operator used to bind ONE canonical orientation per
    // relationship, while the scan path it replaces surfaces each **non-self** relationship twice (once
    // from each endpoint) and a self-loop once. `count(r)` would silently have halved.
    assert_same_bag_as_reference(
        "MATCH ()-[r:LIKES]-() RETURN count(r) AS c",
        "MATCH (a)-[r:LIKES]-(b) RETURN count(r) AS c",
        &["c"],
    );
    assert_same_bag_as_reference(
        "MATCH ()-[r:LIKES]-() RETURN id(r) AS rid",
        "MATCH (a)-[r:LIKES]-(b) RETURN id(r) AS rid",
        &["rid"],
    );
}

#[test]
fn undirected_count_is_two_per_non_self_edge_and_one_per_self_loop() {
    // The same rule stated as an absolute, so a *symmetric* regression in both paths (which the
    // reference comparison above could not catch) still fails. The corpus has 4 non-self `LIKES` and 1
    // self-loop: 4*2 + 1 = 9.
    let mut g = corpus();
    let rows = bag(
        "MATCH ()-[r:LIKES]-() RETURN count(r) AS c",
        &mut g,
        &IndexCatalog::empty(),
        &["c"],
    );
    assert_eq!(rows, vec!["Integer(9)".to_owned()]);
    // The directed spelling counts each relationship exactly once.
    let mut g = corpus();
    let rows = bag(
        "MATCH ()-[r:LIKES]->() RETURN count(r) AS c",
        &mut g,
        &IndexCatalog::empty(),
        &["c"],
    );
    assert_eq!(rows, vec!["Integer(5)".to_owned()]);
}

#[test]
fn endpoint_bindings_match_the_reference_in_order() {
    // A named path exposes the operator's `from`/`to` bindings — `nodes(p)` is `[from, to]` — which is
    // otherwise unobservable for anonymous endpoints. This is what makes the bag comparison **total**:
    // it distinguishes the two orientations of an undirected match and the direction of a `<-` pattern,
    // not just which relationships were found.
    for (rewritten, reference) in [
        (
            "MATCH p = ()-[r:LIKES]->() RETURN id(r) AS rid, [n IN nodes(p) | id(n)] AS ns",
            "MATCH p = (a)-[r:LIKES]->(b) RETURN id(r) AS rid, [n IN nodes(p) | id(n)] AS ns",
        ),
        (
            "MATCH p = ()<-[r:LIKES]-() RETURN id(r) AS rid, [n IN nodes(p) | id(n)] AS ns",
            "MATCH p = (a)<-[r:LIKES]-(b) RETURN id(r) AS rid, [n IN nodes(p) | id(n)] AS ns",
        ),
        (
            "MATCH p = ()-[r:LIKES]-() RETURN id(r) AS rid, [n IN nodes(p) | id(n)] AS ns",
            "MATCH p = (a)-[r:LIKES]-(b) RETURN id(r) AS rid, [n IN nodes(p) | id(n)] AS ns",
        ),
    ] {
        assert_same_bag_as_reference(rewritten, reference, &["rid", "ns"]);
    }
}

#[test]
fn multi_type_pattern_matches_the_reference_bag() {
    assert_same_bag_as_reference(
        "MATCH ()-[r:LIKES|FOLLOWS]->() RETURN id(r) AS rid",
        "MATCH (a)-[r:LIKES|FOLLOWS]->(b) RETURN id(r) AS rid",
        &["rid"],
    );
    assert_same_bag_as_reference(
        "MATCH ()-[r:LIKES|FOLLOWS]-() RETURN count(r) AS c",
        "MATCH (a)-[r:LIKES|FOLLOWS]-(b) RETURN count(r) AS c",
        &["c"],
    );
}

#[test]
fn untyped_pattern_matches_the_reference_bag() {
    // An empty type list means "any type" — the operator supports it and the lowerer emits it, so the
    // untyped spelling must agree too.
    assert_same_bag_as_reference(
        "MATCH ()-[r]->() RETURN id(r) AS rid",
        "MATCH (a)-[r]->(b) RETURN id(r) AS rid",
        &["rid"],
    );
    assert_same_bag_as_reference(
        "MATCH ()-[r]-() RETURN count(r) AS c",
        "MATCH (a)-[r]-(b) RETURN count(r) AS c",
        &["c"],
    );
}

#[test]
fn inline_relationship_properties_still_filter() {
    // The link's inline property map is a post-`Filter` on the single relationship binding, exactly as
    // on the `Expand` path.
    assert_same_bag_as_reference(
        "MATCH ()-[r:LIKES {w: 3}]->() RETURN id(r) AS rid",
        "MATCH (a)-[r:LIKES {w: 3}]->(b) RETURN id(r) AS rid",
        &["rid"],
    );
}

#[test]
fn a_general_type_expression_still_filters() {
    // `:!FOLLOWS` cannot be reduced to the disjunctive `types` fast path, so the scan enumerates every
    // type and a `HasLabels` filter enforces the predicate — the same split the `Expand` path uses.
    assert_same_bag_as_reference(
        "MATCH ()-[r:!FOLLOWS]->() RETURN id(r) AS rid",
        "MATCH (a)-[r:!FOLLOWS]->(b) RETURN id(r) AS rid",
        &["rid"],
    );
}

#[test]
fn a_where_predicate_on_the_relationship_still_filters() {
    assert_same_bag_as_reference(
        "MATCH ()-[r:LIKES]->() WHERE r.w > 2 RETURN id(r) AS rid",
        "MATCH (a)-[r:LIKES]->(b) WHERE r.w > 2 RETURN id(r) AS rid",
        &["rid"],
    );
}

#[test]
fn a_leading_optional_match_keeps_its_null_row() {
    // `OPTIONAL MATCH` over the rewritten leaf must keep the `Apply`/`Optional` null semantics: a
    // pattern matching nothing yields exactly one all-null row, not zero rows.
    let mut g = corpus();
    let rows = bag(
        "OPTIONAL MATCH ()-[r:NOSUCHTYPE]->() RETURN r AS r",
        &mut g,
        &IndexCatalog::empty(),
        &["r"],
    );
    assert_eq!(rows, vec!["Null".to_owned()], "one null row, not zero rows");
    // And with a prior clause, one null row per driving row.
    let mut g = corpus();
    let rows = bag(
        "UNWIND [1, 2] AS x OPTIONAL MATCH ()-[r:NOSUCHTYPE]->() RETURN x AS x, r AS r",
        &mut g,
        &IndexCatalog::empty(),
        &["x", "r"],
    );
    assert_eq!(rows, vec!["Integer(1)|Null", "Integer(2)|Null"]);
}

#[test]
fn a_correlated_optional_match_matches_the_reference_bag() {
    assert_same_bag_as_reference(
        "UNWIND [1, 2] AS x OPTIONAL MATCH ()-[r:LIKES]->() RETURN x AS x, id(r) AS rid",
        "UNWIND [1, 2] AS x OPTIONAL MATCH (a)-[r:LIKES]->(b) RETURN x AS x, id(r) AS rid",
        &["x", "rid"],
    );
}

#[test]
fn a_second_disconnected_component_matches_the_reference_bag() {
    // With a prior plan the rewritten leaf joins by the same uncorrelated `Apply` the fresh-scan path
    // uses, so a cartesian pattern must still be a cartesian product.
    assert_same_bag_as_reference(
        "MATCH (n:P) MATCH ()-[r:LIKES]->() RETURN n.k AS k, id(r) AS rid",
        "MATCH (n:P) MATCH (a)-[r:LIKES]->(b) RETURN n.k AS k, id(r) AS rid",
        &["k", "rid"],
    );
}

#[test]
fn the_cost_based_path_agrees_with_the_rule_based_path() {
    // With statistics the cost-based passes run; none of them may change the bag of a plan rooted at a
    // relationship-type scan.
    for src in [
        "MATCH ()-[r:LIKES]->() RETURN count(r) AS c",
        "MATCH ()-[r:LIKES]-() RETURN count(r) AS c",
        "MATCH ()-[r]-() RETURN count(r) AS c",
    ] {
        let mut g = corpus();
        let rule = bag(src, &mut g, &IndexCatalog::empty(), &["c"]);

        let mut g = corpus();
        let plan = plan_physical_with_stats(&logical(src), &IndexCatalog::empty(), g.statistics());
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let mut costed: Vec<String> = execute(&plan, &bound, &mut g)
            .expect("open")
            .collect_all()
            .expect("run")
            .iter()
            .map(|r| render(r, &["c"]))
            .collect();
        costed.sort();
        assert_eq!(rule, costed, "cost-based planning changed the bag: {src}");
    }
}

// =================================================================================================
// 3. Declined preconditions — each one keeps the reference lowering AND the right answer
// =================================================================================================

#[test]
fn declined_shapes_keep_the_scan_and_expand_lowering() {
    for src in [
        // Variable length: `r` binds a LIST built by walking, which no single-relationship
        // enumeration produces.
        "MATCH ()-[r:LIKES*1..2]->() RETURN count(r) AS c",
        // More than one chain link: a traversal needs an anchor.
        "MATCH ()-[r:LIKES]->()-[q:LIKES]->() RETURN count(r) AS c",
        // A named leading node: it has (and may need) its own access path.
        "MATCH (a)-[r:LIKES]->() RETURN count(r) AS c",
        // A named far endpoint.
        "MATCH ()-[r:LIKES]->(b) RETURN count(r) AS c",
        // A labelled endpoint: a label scan is a real access path this rewrite would throw away.
        "MATCH (:P)-[r:LIKES]->() RETURN count(r) AS c",
        "MATCH ()-[r:LIKES]->(:P) RETURN count(r) AS c",
        // An endpoint label EXPRESSION, and an endpoint inline property map.
        "MATCH ()-[r:LIKES]->(:P|Q) RETURN count(r) AS c",
        "MATCH ({k: 1})-[r:LIKES]->() RETURN count(r) AS c",
        "MATCH ()-[r:LIKES]->({k: 1}) RETURN count(r) AS c",
        // A quantified path pattern binds group lists, not one relationship.
        "MATCH () (()-[r:LIKES]->()){1,2} () RETURN count(r) AS c",
        // `shortestPath` is a different operator entirely.
        "MATCH (a:P), (b:P), p = shortestPath((a)-[:LIKES*]-(b)) RETURN count(p) AS c",
    ] {
        let plan = logical(src);
        assert!(
            !logical_has_rel_scan(&plan),
            "`{src}` must decline the relationship-type scan:\n{plan}"
        );
    }
}

#[test]
fn a_second_relationship_of_the_same_match_declines_and_stays_isomorphic() {
    // `AllRelationshipsScan` has no `prior_rels` field, so it cannot exclude a relationship an earlier
    // link of the same pattern already bound. The FIRST part may be rewritten; the second MUST NOT be,
    // or Cypher relationship isomorphism would silently be lost.
    let src = "MATCH ()-[r:LIKES]->(), ()-[q:LIKES]->() RETURN id(r) AS rid, id(q) AS qid";
    let plan = logical(src);
    let rendered = plan.to_string();
    assert_eq!(
        rendered.matches("AllRelationshipsScan").count(),
        1,
        "exactly the first part may be rewritten:\n{rendered}"
    );
    assert!(
        rendered.contains("Expand"),
        "the second part must stay an expand so `prior_rels` can exclude `r`:\n{rendered}"
    );

    // And the answer is still isomorphic: 5 LIKES, each paired with the 4 others, never itself.
    let mut g = corpus();
    let rows = bag(src, &mut g, &IndexCatalog::empty(), &["rid", "qid"]);
    assert_eq!(rows.len(), 20, "5 * 4 ordered pairs of distinct LIKES");
    assert!(
        rows.iter().all(|r| {
            let (a, b) = r.split_once('|').expect("two columns");
            a != b
        }),
        "no row may bind the same relationship to both variables: {rows:?}"
    );
}

#[test]
fn a_self_referencing_pattern_still_checks_the_connection() {
    // `MATCH (a)-[r:T]->(a)` names both endpoints with the SAME variable, so it must keep the
    // `ExpandInto` connection check. Rewriting it would bind `a` twice on one row and silently drop the
    // `start == end` constraint — which is exactly why both endpoints must be anonymous.
    let plan = logical("MATCH (a)-[r:LIKES]->(a) RETURN id(r) AS rid");
    assert!(!logical_has_rel_scan(&plan), "{plan}");
    let mut g = corpus();
    let rows = bag(
        "MATCH (a)-[r:LIKES]->(a) RETURN id(r) AS rid",
        &mut g,
        &IndexCatalog::empty(),
        &["rid"],
    );
    assert_eq!(rows.len(), 1, "only the self-loop matches: {rows:?}");
}

#[test]
fn a_self_referencing_pattern_is_not_served_by_a_relationship_seek() {
    // A **pre-existing** defect of the relationship seeks (`rmp` #659 / #666 / #680 / #664), found and
    // fixed while generalising their shape recogniser in `rmp` #867.
    //
    // A relationship seek materialises `from` and `to` as two independent columns out of the matched
    // relationship's record. When the pattern names BOTH endpoints with the same variable the second
    // binding overwrites the first and the `start == end` check disappears — so declaring an index
    // CHANGED THE ANSWER. Measured on this corpus before the fix:
    // `MATCH (a)-[r:LIKES]->(a) WHERE r.w = 5` returned 1 row with no index and 5 with one.
    let src = "MATCH (a)-[r:LIKES]->(a) WHERE r.w = 5 RETURN id(a) AS aid, id(r) AS rid";
    let catalog = rel_property_catalog();
    let rendered = plan_text(src, &catalog);
    assert!(
        !rendered.contains("RelIndexSeek"),
        "a self-referencing pattern must decline the seek:\n{rendered}"
    );
    assert!(rendered.contains("ExpandInto"), "{rendered}");

    let mut g = corpus();
    let indexed = bag(src, &mut g, &catalog, &["aid", "rid"]);
    let mut g = corpus();
    let scanned = bag(src, &mut g, &IndexCatalog::empty(), &["aid", "rid"]);
    assert_eq!(
        indexed.len(),
        1,
        "only the self-loop may match, index or not: {indexed:?}"
    );
    assert_eq!(
        indexed, scanned,
        "declaring a relationship index must not change the answer"
    );

    // The same guard for the other three relationship seek kinds, which share the recogniser.
    for (src, catalog) in [
        (
            "MATCH (a)-[r:LIKES]->(a) WHERE r.w >= 1 RETURN id(r) AS rid",
            rel_property_catalog(),
        ),
        (
            "MATCH (a)-[r:LIKES {w: 5, z: 1}]->(a) RETURN id(r) AS rid",
            IndexCatalog::builder()
                .with_rel_composite("LIKES", ["w", "z"])
                .build(),
        ),
        (
            "MATCH (a)-[r:VISITED]->(a) WHERE distance(r.at, point({x: 0, y: 0})) < 5 RETURN id(r) AS rid",
            IndexCatalog::builder()
                .with_rel_spatial("VISITED", "at")
                .build(),
        ),
    ] {
        let rendered = plan_text(src, &catalog);
        assert!(
            !rendered.contains("Seek"),
            "a self-referencing pattern must decline every relationship seek: {src}\n{rendered}"
        );
    }
}

// =================================================================================================
// 4. The relationship index seeks must not regress (the shape they fire on changed spelling)
// =================================================================================================

fn rel_property_catalog() -> IndexCatalog {
    IndexCatalog::builder()
        .with_rel_property("LIKES", "w")
        .build()
}

#[test]
fn the_named_endpoint_relationship_index_seek_still_fires() {
    // The pre-existing `rmp` #659 / #680 path, unchanged by this task — the non-regression bar the
    // task set explicitly.
    let catalog = rel_property_catalog();
    for src in [
        "MATCH (a)-[r:LIKES]->(b) WHERE r.w = 3 RETURN id(r) AS rid",
        "MATCH (a)-[r:LIKES {w: 3}]->(b) RETURN id(r) AS rid",
    ] {
        let rendered = plan_text(src, &catalog);
        assert!(rendered.contains("RelIndexSeek"), "{src}: {rendered}");
    }
    let rendered = plan_text(
        "MATCH (a)-[r:LIKES]->(b) WHERE r.w >= 3 RETURN id(r) AS rid",
        &catalog,
    );
    assert!(rendered.contains("RelIndexRangeSeek"), "{rendered}");
}

#[test]
fn the_anonymous_endpoint_relationship_index_seek_still_fires() {
    // The shape this task rewrote. Before the recogniser was generalised these lowered to a full type
    // scan + filter — a silent performance regression on the path `rmp` #659 / #666 / #680 built.
    let catalog = rel_property_catalog();
    for src in [
        "MATCH ()-[r:LIKES]->() WHERE r.w = 3 RETURN id(r) AS rid",
        "MATCH ()-[r:LIKES {w: 3}]->() RETURN id(r) AS rid",
        "MATCH ()-[r:LIKES {w: 3}]-() RETURN id(r) AS rid",
    ] {
        let rendered = plan_text(src, &catalog);
        assert!(rendered.contains("RelIndexSeek"), "{src}: {rendered}");
        assert!(
            !rendered.contains("AllRelationshipsScan"),
            "the seek replaces the whole scan: {src}: {rendered}"
        );
    }
    let rendered = plan_text(
        "MATCH ()-[r:LIKES]->() WHERE r.w >= 3 RETURN id(r) AS rid",
        &catalog,
    );
    assert!(rendered.contains("RelIndexRangeSeek"), "{rendered}");
}

#[test]
fn the_anonymous_endpoint_composite_relationship_seek_still_fires() {
    let catalog = IndexCatalog::builder()
        .with_rel_composite("LIKES", ["w", "z"])
        .build();
    let rendered = plan_text(
        "MATCH ()-[r:LIKES {w: 3, z: 1}]->() RETURN id(r) AS rid",
        &catalog,
    );
    assert!(rendered.contains("RelCompositeIndexSeek"), "{rendered}");
}

#[test]
fn the_anonymous_endpoint_relationship_spatial_seek_still_fires() {
    let catalog = IndexCatalog::builder()
        .with_rel_spatial("VISITED", "at")
        .build();
    let rendered = plan_text(
        "MATCH ()-[r:VISITED]-() WHERE distance(r.at, point({x: 0, y: 0})) < 5 RETURN r",
        &catalog,
    );
    assert!(rendered.contains("RelSpatialIndexSeek"), "{rendered}");
}

#[test]
fn the_seek_and_the_scan_return_the_same_bag() {
    // The seek is only sound if it reproduces the scan's rows exactly; with the anonymous-endpoint
    // shape now feeding it, re-prove that end to end (including the undirected two-orientation rule).
    for src in [
        "MATCH ()-[r:LIKES]->() WHERE r.w = 3 RETURN id(r) AS rid",
        "MATCH ()-[r:LIKES]-() WHERE r.w = 3 RETURN id(r) AS rid",
        "MATCH ()-[r:LIKES]->() WHERE r.w >= 3 RETURN id(r) AS rid",
    ] {
        let indexed = plan_text(src, &rel_property_catalog());
        assert!(
            indexed.contains("RelIndexSeek") || indexed.contains("RelIndexRangeSeek"),
            "{src}: {indexed}"
        );
        let mut g = corpus();
        let seek = bag(src, &mut g, &rel_property_catalog(), &["rid"]);
        let mut g = corpus();
        let scan = bag(src, &mut g, &IndexCatalog::empty(), &["rid"]);
        assert!(!scan.is_empty(), "vacuous comparison: {src}");
        assert_eq!(seek, scan, "seek and scan disagree: {src}");
    }
}

#[test]
fn the_reference_seam_declines_the_accelerator_so_the_fallback_is_what_ran() {
    // Every `MemGraph` assertion above therefore exercises the **node-walk fallback** inside
    // `all_rel_ids`, not the store scan — which is what makes this file cover both access paths (§5
    // below covers the store scan over the real `RecordStoreGraph`). Pinned explicitly so the claim
    // cannot quietly become false if `MemGraph` ever grows an override.
    let g = corpus();
    for types in [
        Vec::new(),
        vec!["LIKES".to_owned()],
        vec!["LIKES".to_owned(), "FOLLOWS".to_owned()],
    ] {
        assert!(
            g.scan_rels_by_type(&types).is_none(),
            "MemGraph must decline the accelerator: {types:?}"
        );
    }
}

// =================================================================================================
// 5. The store-scan access path over the real RecordStoreGraph
// =================================================================================================

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: RecordStore<MemBlockDevice, MemLogSink> =
        RecordStore::create(device, wal, 64, 1).expect("create store");
    TxnCoordinator::new(store)
}

/// Runs `src` in its own committed transaction over the coordinator, returning the rendered bag.
fn coord_bag(coord: &mut Coord, src: &str, columns: &[&str]) -> Vec<String> {
    let plan = compile(src, &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    let mut rows: Vec<String> = {
        let mut graph = coord.statement(txn).expect("statement");
        let out: Vec<Row> = {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect")
        };
        assert!(
            graph.take_error().is_none(),
            "`{src}` captured a deferred error"
        );
        out.iter().map(|r| render(r, columns)).collect()
    };
    coord.commit(txn).expect("commit");
    rows.sort();
    rows
}

fn coord_write(coord: &mut Coord, src: &str) {
    let plan = compile(src, &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect");
        assert!(graph.take_error().is_none(), "`{src}` captured an error");
    }
    coord.commit(txn).expect("commit");
}

/// The same corpus as [`corpus`], created through Cypher over the real store.
fn seed_coord(coord: &mut Coord) {
    coord_write(
        coord,
        "CREATE (a:P {k: 0}), (b:P {k: 1}), (c:P {k: 2}), (d:P {k: 3}), (e:P {k: 4}), (f:P {k: 5}),
                (a)-[:LIKES {w: 1}]->(b), (a)-[:LIKES {w: 2}]->(b), (b)-[:LIKES {w: 3}]->(c),
                (d)-[:LIKES {w: 4}]->(a), (e)-[:LIKES {w: 5}]->(e),
                (c)-[:FOLLOWS {w: 6}]->(d), (f)-[:FOLLOWS {w: 7}]->(a)",
    );
}

#[test]
fn the_store_scan_agrees_with_the_node_walk_over_the_record_store() {
    // Over a `RecordStoreGraph` the anonymous spelling is served by
    // `GraphAccess::scan_rels_by_type` (a direct relationship-store scan) while the named spelling
    // takes the `scan_nodes` + `expand` node-walk. The two access paths must return the same bag —
    // this is what covers the seam implementation, which `MemGraph` (which declines it) never exercises.
    let mut coord = fresh_coord();
    seed_coord(&mut coord);
    for (rewritten, reference, columns) in [
        (
            "MATCH ()-[r:LIKES]->() RETURN id(r) AS rid",
            "MATCH (a)-[r:LIKES]->(b) RETURN id(r) AS rid",
            &["rid"][..],
        ),
        (
            "MATCH ()-[r:LIKES]-() RETURN count(r) AS c",
            "MATCH (a)-[r:LIKES]-(b) RETURN count(r) AS c",
            &["c"][..],
        ),
        (
            "MATCH ()-[r]->() RETURN id(r) AS rid",
            "MATCH (a)-[r]->(b) RETURN id(r) AS rid",
            &["rid"][..],
        ),
        (
            "MATCH ()-[r:LIKES|FOLLOWS]->() RETURN id(r) AS rid",
            "MATCH (a)-[r:LIKES|FOLLOWS]->(b) RETURN id(r) AS rid",
            &["rid"][..],
        ),
        (
            "MATCH p = ()-[r:LIKES]-() RETURN id(r) AS rid, [n IN nodes(p) | id(n)] AS ns",
            "MATCH p = (a)-[r:LIKES]-(b) RETURN id(r) AS rid, [n IN nodes(p) | id(n)] AS ns",
            &["rid", "ns"][..],
        ),
    ] {
        let got = coord_bag(&mut coord, rewritten, columns);
        let want = coord_bag(&mut coord, reference, columns);
        assert!(!want.is_empty(), "vacuous comparison: {reference}");
        assert_eq!(got, want, "store scan vs node walk disagree: {rewritten}");
    }
}

#[test]
fn the_store_scan_honours_mvcc_visibility_and_a_type_that_does_not_exist() {
    let mut coord = fresh_coord();
    seed_coord(&mut coord);
    // A type no relationship carries yields nothing (and must not be confused with "any type").
    assert_eq!(
        coord_bag(
            &mut coord,
            "MATCH ()-[r:NOSUCH]->() RETURN count(r) AS c",
            &["c"]
        ),
        vec!["Integer(0)".to_owned()]
    );
    // A deleted relationship disappears from the scan.
    coord_write(&mut coord, "MATCH ()-[r:LIKES]->() WHERE r.w = 3 DELETE r");
    assert_eq!(
        coord_bag(
            &mut coord,
            "MATCH ()-[r:LIKES]->() RETURN count(r) AS c",
            &["c"]
        ),
        vec!["Integer(4)".to_owned()],
        "the deleted LIKES must not be enumerated"
    );
    assert_eq!(
        coord_bag(
            &mut coord,
            "MATCH (a)-[r:LIKES]->(b) RETURN count(r) AS c",
            &["c"]
        ),
        vec!["Integer(4)".to_owned()],
        "and the node-walk agrees"
    );
}

#[test]
fn an_uncommitted_write_is_visible_to_its_own_transaction_through_the_store_scan() {
    // The scan reads through the statement's own MVCC snapshot, so a relationship this transaction just
    // created is visible to a later statement of the same transaction — exactly as the node-walk is.
    let mut coord = fresh_coord();
    seed_coord(&mut coord);
    let txn = coord.begin_serializable();
    for (src, expected) in [
        ("CREATE (:P {k: 9})-[:LIKES {w: 9}]->(:P {k: 10})", None),
        (
            "MATCH ()-[r:LIKES]->() RETURN count(r) AS c",
            Some("Integer(6)"),
        ),
        (
            "MATCH (a)-[r:LIKES]->(b) RETURN count(r) AS c",
            Some("Integer(6)"),
        ),
    ] {
        let plan = compile(src, &IndexCatalog::empty());
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let mut graph = coord.statement(txn).expect("statement");
        let rows: Vec<Row> = {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect")
        };
        assert!(graph.take_error().is_none(), "`{src}` captured an error");
        if let Some(expected) = expected {
            assert_eq!(render(&rows[0], &["c"]), expected, "{src}");
        }
    }
    coord.commit(txn).expect("commit");
}

// =================================================================================================
// 6. RBAC: a restricted principal's QUERY falls back and returns RBAC-correct rows
// =================================================================================================
//
// The seam-level decline (`AuthorizedGraph::scan_rels_by_type` returning `None` for a restricted
// principal) is asserted in `authorized_graph`'s own unit tests, with a stub oracle. That is necessary
// but not sufficient: it proves the decorator declines, not that a **query** through the decorator
// falls back to the node-walk and applies RBAC to the rows it returns. That gap — enforcement asserted
// at the seam, never at the query — is precisely what let `rmp` #820 / #822 / #826 ship behind green
// CI, so CLAUDE.md's regression-prevention rule requires closing it here.
//
// Every case drives `execute` over a REAL `RecordStoreGraph` (a `TxnCoordinator` statement) wrapped in
// an `AuthorizedGraph`, and asserts the **anonymous-endpoint** spelling (which the planner lowers to
// `AllRelationshipsScan`, whose access path the decorator declines) returns exactly the same rows as
// the **named-endpoint** spelling (which lowers to `AllNodesScan` + `ExpandAll` and has always been
// RBAC-filtered). If the decline ever regressed, the anonymous spelling would return the raw,
// unfiltered store enumeration and the two would diverge.

use graphus_cypher::authorized_graph::{AuthorizedGraph, PrivilegeOracle};
use std::collections::BTreeSet;

/// A `PrivilegeOracle` driven by explicit allow-lists plus explicit deny-lists, so a test can express
/// a broad grant with a carved hole (the DENY-precedence shape) exactly as the server's
/// `EffectivePrivileges` resolves it.
#[derive(Default, Clone)]
struct Rbac {
    unrestricted: bool,
    traverse_labels: BTreeSet<String>,
    read_props: BTreeSet<(String, String)>,
    traverse_rel_types: BTreeSet<String>,
    read_rel_props: BTreeSet<(String, String)>,
    denied_traverse_labels: BTreeSet<String>,
    denied_read_props: BTreeSet<(String, String)>,
}

impl Rbac {
    /// Every grant, but still `is_unrestricted() == false` — the configuration that proves the
    /// **decline path itself** loses no rows (a restricted principal holding every privilege must see
    /// exactly what an unrestricted one sees).
    fn all_grants() -> Self {
        Self::default()
            .traverse("P")
            .traverse("Q")
            .traverse("Secret")
            .rel_type("LIKES")
            .rel_type("FOLLOWS")
            .read_prop("P", "k")
            .read_prop("Q", "k")
            .read_prop("Secret", "k")
            .read_rel_prop("LIKES", "w")
            .read_rel_prop("FOLLOWS", "w")
    }
    fn traverse(mut self, l: &str) -> Self {
        self.traverse_labels.insert(l.to_owned());
        self
    }
    fn rel_type(mut self, t: &str) -> Self {
        self.traverse_rel_types.insert(t.to_owned());
        self
    }
    fn read_prop(mut self, l: &str, p: &str) -> Self {
        self.read_props.insert((l.to_owned(), p.to_owned()));
        self
    }
    fn read_rel_prop(mut self, t: &str, p: &str) -> Self {
        self.read_rel_props.insert((t.to_owned(), p.to_owned()));
        self
    }
    fn deny_traverse(mut self, l: &str) -> Self {
        self.denied_traverse_labels.insert(l.to_owned());
        self
    }
    fn deny_read(mut self, l: &str, p: &str) -> Self {
        self.denied_read_props.insert((l.to_owned(), p.to_owned()));
        self
    }
    fn without_rel_type(mut self, t: &str) -> Self {
        self.traverse_rel_types.remove(t);
        self
    }
}

impl PrivilegeOracle for Rbac {
    fn is_unrestricted(&self) -> bool {
        self.unrestricted
    }
    fn can_traverse_label(&self, label: &str) -> bool {
        self.traverse_labels.contains(label)
    }
    fn can_read_property(&self, label: &str, property: &str) -> bool {
        self.read_props
            .contains(&(label.to_owned(), property.to_owned()))
    }
    fn can_traverse_rel_type(&self, rel_type: &str) -> bool {
        self.traverse_rel_types.contains(rel_type)
    }
    fn can_read_rel_property(&self, rel_type: &str, property: &str) -> bool {
        self.read_rel_props
            .contains(&(rel_type.to_owned(), property.to_owned()))
    }
    fn can_write_label(&self, _label: &str) -> bool {
        false
    }
    fn can_write_rel_type(&self, _rel_type: &str) -> bool {
        false
    }
    fn can_write_property(&self, _label: &str, _property: &str) -> bool {
        false
    }
    fn can_write_rel_property(&self, _rel_type: &str, _property: &str) -> bool {
        false
    }
    fn is_denied_traverse_label(&self, label: &str) -> bool {
        self.denied_traverse_labels.contains(label)
    }
    fn is_denied_read_property(&self, label: &str, property: &str) -> bool {
        self.denied_read_props
            .contains(&(label.to_owned(), property.to_owned()))
    }
    fn is_denied_write_label(&self, _label: &str) -> bool {
        false
    }
    fn is_denied_write_property(&self, _label: &str, _property: &str) -> bool {
        false
    }
}

/// Runs `src` in its own committed transaction over the coordinator, through an `AuthorizedGraph`
/// enforcing `oracle`, returning the rendered bag.
fn rbac_bag(coord: &mut Coord, oracle: Rbac, src: &str, columns: &[&str]) -> Vec<String> {
    let plan = compile(src, &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    let mut rows: Vec<String> = {
        let mut graph = coord.statement(txn).expect("statement");
        let out = {
            let mut authz = AuthorizedGraph::new(&mut graph, oracle);
            let rendered: Vec<String> = {
                let mut cursor = execute(&plan, &bound, &mut authz).expect("open cursor");
                cursor
                    .collect_all()
                    .expect("collect")
                    .iter()
                    .map(|r| render(r, columns))
                    .collect()
            };
            assert!(
                authz.take_auth_error().is_none(),
                "`{src}` raised an authorisation error"
            );
            rendered
        };
        assert!(
            graph.take_error().is_none(),
            "`{src}` captured a deferred error"
        );
        out
    };
    coord.commit(txn).expect("commit");
    rows.sort();
    rows
}

/// The RBAC corpus: a `:P`-only pair joined by `LIKES`, a **multi-label** `:P:Q` node (the DENY
/// precedence case — a deny on *either* of its labels must hide it), a `:Secret` node reachable only
/// through `LIKES`, and a `FOLLOWS` edge so a type-restricted principal has something to lose.
fn seed_rbac(coord: &mut Coord) {
    coord_write(
        coord,
        "CREATE (a:P {k: 0}), (b:P {k: 1}), (m:P:Q {k: 2}), (s:Secret {k: 3}),
                (a)-[:LIKES {w: 10}]->(b),
                (a)-[:LIKES {w: 20}]->(m),
                (a)-[:LIKES {w: 30}]->(s),
                (b)-[:FOLLOWS {w: 40}]->(a)",
    );
}

/// Every query shape the task's rewrite touches, as `(anonymous spelling, named spelling, columns)`.
///
/// The two spellings are semantically identical; only the **access path** differs — the anonymous one
/// lowers to `AllRelationshipsScan` (whose seam accelerator the decorator declines for a restricted
/// principal), the named one to `AllNodesScan` + `ExpandAll`.
const RBAC_SHAPES: [(&str, &str, &[&str]); 6] = [
    (
        "MATCH ()-[r:LIKES]->() RETURN id(r) AS rid",
        "MATCH (a)-[r:LIKES]->(b) RETURN id(r) AS rid",
        &["rid"],
    ),
    (
        "MATCH ()-[r]->() RETURN id(r) AS rid",
        "MATCH (a)-[r]->(b) RETURN id(r) AS rid",
        &["rid"],
    ),
    (
        "MATCH ()-[r:LIKES]-() RETURN id(r) AS rid",
        "MATCH (a)-[r:LIKES]-(b) RETURN id(r) AS rid",
        &["rid"],
    ),
    (
        "MATCH ()-[r:LIKES]->() RETURN count(r) AS c",
        "MATCH (a)-[r:LIKES]->(b) RETURN count(r) AS c",
        &["c"],
    ),
    (
        "MATCH p = ()-[r:LIKES]->() RETURN id(r) AS rid, [n IN nodes(p) | id(n)] AS ns",
        "MATCH p = (a)-[r:LIKES]->(b) RETURN id(r) AS rid, [n IN nodes(p) | id(n)] AS ns",
        &["rid", "ns"],
    ),
    (
        "MATCH ()-[r:LIKES]->() WHERE r.w > 10 RETURN id(r) AS rid",
        "MATCH (a)-[r:LIKES]->(b) WHERE r.w > 10 RETURN id(r) AS rid",
        &["rid"],
    ),
];

/// The four privilege configurations, as `(name, oracle, expected LIKES count)`.
fn rbac_configurations() -> Vec<(&'static str, Rbac, i64)> {
    vec![
        // 1. A plain grant list: `:Secret` is simply not granted, so the edge into it is filtered.
        (
            "grant-list (no :Secret grant)",
            Rbac::default()
                .traverse("P")
                .traverse("Q")
                .rel_type("LIKES")
                .rel_type("FOLLOWS")
                .read_rel_prop("LIKES", "w")
                .read_rel_prop("FOLLOWS", "w"),
            2,
        ),
        // 2. A BROAD grant with a DENY carved out of it, on a MULTI-LABEL node: `:P:Q` carries a
        //    granted label AND a denied one. DENY must win, hiding the node and the edge into it —
        //    the `rmp` #645 precedence rule, exercised through this access path.
        //    Two of the three LIKES survive: `a->b` (both `:P`) and `a->s` (`:Secret`, which
        //    `all_grants` DOES grant) — only the edge into `:P:Q` is lost. Which one is lost is pinned
        //    separately by `deny_precedence_hides_exactly_the_multi_label_nodes_edge`.
        (
            "deny-precedence on a multi-label node",
            Rbac::all_grants().deny_traverse("Q"),
            2,
        ),
        // 3. The relationship TYPE is not traversable: every `LIKES` edge disappears, endpoints intact.
        (
            "rel-type LIKES not traversable",
            Rbac::all_grants().without_rel_type("LIKES"),
            0,
        ),
        // 4. Every grant held, yet still restricted: the accelerator is declined and the node-walk
        //    serves, so the rows must be the FULL set. This is the configuration that would catch a
        //    decline that silently dropped rows.
        ("all grants, still restricted", Rbac::all_grants(), 3),
        // 5. A DENY on a node PROPERTY, not on traversal. The graded reversal (`rmp` #645): DENY READ
        //    hides the value and leaves the node — and therefore the relationship — visible. This is the
        //    over-filtering direction, and it is worth pinning separately: a decline that fell back to a
        //    node-walk which conflated "cannot read a property" with "cannot traverse" would silently
        //    lose rows, and every other configuration here would still pass.
        (
            "deny READ on a property (traversal intact)",
            Rbac::all_grants().deny_read("P", "k"),
            3,
        ),
    ]
}

#[test]
fn a_restricted_principal_sees_the_same_rows_from_both_spellings() {
    let mut coord = fresh_coord();
    seed_rbac(&mut coord);
    for (name, oracle, _) in rbac_configurations() {
        for (anonymous, named, columns) in RBAC_SHAPES {
            let got = rbac_bag(&mut coord, oracle.clone(), anonymous, columns);
            let want = rbac_bag(&mut coord, oracle.clone(), named, columns);
            assert_eq!(
                got, want,
                "[{name}] the anonymous-endpoint spelling returned different rows than the \
                 named-endpoint spelling — the RBAC decline regressed\n  anonymous: {anonymous}\n  \
                 named:     {named}"
            );
        }
    }
}

#[test]
fn a_restricted_principal_sees_the_rbac_correct_relationship_count() {
    // The absolute counterpart of the comparison above: a *symmetric* regression in both spellings
    // would satisfy that test and fail this one. The expected counts are derived by hand from the
    // corpus and each configuration's privileges.
    let mut coord = fresh_coord();
    seed_rbac(&mut coord);
    for (name, oracle, expected_likes) in rbac_configurations() {
        let rows = rbac_bag(
            &mut coord,
            oracle,
            "MATCH ()-[r:LIKES]->() RETURN count(r) AS c",
            &["c"],
        );
        assert_eq!(
            rows,
            vec![format!("Integer({expected_likes})")],
            "[{name}] wrong RBAC-filtered LIKES count"
        );
    }
}

#[test]
fn an_unrestricted_principal_sees_everything_through_the_decorator() {
    // The contrast that makes the restricted counts meaningful: with `is_unrestricted() == true` the
    // decorator is a pass-through, the seam accelerator is forwarded, and all three LIKES are returned.
    let mut coord = fresh_coord();
    seed_rbac(&mut coord);
    let unrestricted = Rbac {
        unrestricted: true,
        ..Rbac::default()
    };
    let rows = rbac_bag(
        &mut coord,
        unrestricted,
        "MATCH ()-[r:LIKES]->() RETURN count(r) AS c",
        &["c"],
    );
    assert_eq!(rows, vec!["Integer(3)".to_owned()]);
}

#[test]
fn deny_precedence_hides_exactly_the_multi_label_nodes_edge() {
    // The count alone cannot distinguish "the deny hid the right edge" from "the deny hid *an* edge":
    // the grant-list configuration also yields 2, for a different reason. Pin the identity.
    //
    // `:P:Q` carries a GRANTED label (`P`) and a DENIED one (`Q`). DENY must win (`rmp` #645), so the
    // node is untraversable and the `LIKES` edge into it must be exactly the one that disappears —
    // through the relationship-type-scan access path, which is what this file exists to hold down.
    let mut coord = fresh_coord();
    seed_rbac(&mut coord);
    let all = rbac_bag(
        &mut coord,
        Rbac::all_grants(),
        "MATCH ()-[r:LIKES]->() RETURN r.w AS w",
        &["w"],
    );
    let denied = rbac_bag(
        &mut coord,
        Rbac::all_grants().deny_traverse("Q"),
        "MATCH ()-[r:LIKES]->() RETURN r.w AS w",
        &["w"],
    );
    assert_eq!(
        all,
        vec!["Integer(10)", "Integer(20)", "Integer(30)"],
        "with every grant the principal sees all three LIKES"
    );
    assert_eq!(
        denied,
        vec!["Integer(10)", "Integer(30)"],
        "the DENY on `Q` must remove exactly the edge into the multi-label `:P:Q` node (w = 20)"
    );
}
