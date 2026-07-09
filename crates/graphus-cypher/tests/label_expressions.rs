//! End-to-end tests for **label expressions** (GPM / Neo4j 5.x): the `&` (AND), `|` (OR), `!`
//! (NOT), and `%` (wildcard) operators, with grouping `( … )`, on node-pattern labels, WHERE
//! label predicates, and relationship-type expressions.
//!
//! Each test runs the full `parse → semantics → plan → execute` pipeline over a seeded
//! [`MemGraph`], exactly like `executor.rs`, so it proves the whole stack — the new lexer tokens,
//! the label-expression grammar and its normalisation, the boolean evaluator, and the planner
//! wiring — end to end. Semantics is confirmed against Neo4j 5.x
//! (`expressions/predicates/label-expression-predicates`, and the openCypher `Graph5` feature).

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{MemGraph, NodeId};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;

// =================================================================================================
// Harness
// =================================================================================================

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

/// Runs `src` over `graph` and returns all result rows (empty catalog, no params).
fn run(src: &str, graph: &mut MemGraph) -> Vec<Row> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    execute(&plan, &bound, graph)
        .expect("open cursor")
        .collect_all()
        .expect("rows")
}

/// Compiles `src` only through semantic analysis, returning the classification error string (or a
/// panic if it unexpectedly succeeds). Used to assert that an illegal construct is rejected.
fn compile_err(src: &str) -> String {
    let toks = tokenize(src).expect("lex");
    let ast = match parse_tokens(&toks, src) {
        Ok(ast) => ast,
        Err(e) => return format!("{e:?}"),
    };
    match analyze(&ast) {
        Err(e) => format!("{e:?}"),
        Ok(_) => panic!("expected `{src}` to be rejected, but it compiled"),
    }
}

/// Collects the `id` string column of every row, sorted, for order-insensitive comparison.
fn ids(rows: &[Row]) -> Vec<String> {
    let mut out: Vec<String> = rows
        .iter()
        .map(|r| match r.value("id") {
            Value::String(s) => s,
            other => panic!("expected a string id, got {other:?}"),
        })
        .collect();
    out.sort();
    out
}

/// The `Graph5`-style label lattice: one node per subset of {A, B, C}, each tagged with an `id`
/// naming its labels (`ABC`, `AB`, …, `none` for the unlabelled node).
fn seed_labels() -> MemGraph {
    let mut g = MemGraph::new();
    g.add_node(["A", "B", "C"], [("id", s("ABC"))]);
    g.add_node(["A", "B"], [("id", s("AB"))]);
    g.add_node(["A", "C"], [("id", s("AC"))]);
    g.add_node(["B", "C"], [("id", s("BC"))]);
    g.add_node(["A"], [("id", s("A"))]);
    g.add_node(["B"], [("id", s("B"))]);
    g.add_node(["C"], [("id", s("C"))]);
    g.add_node([] as [&str; 0], [("id", s("none"))]);
    g
}

// =================================================================================================
// Node-pattern label expressions
// =================================================================================================

#[test]
fn single_label_pattern() {
    let mut g = seed_labels();
    let rows = run("MATCH (n:A) RETURN n.id AS id", &mut g);
    assert_eq!(ids(&rows), ["A", "AB", "ABC", "AC"]);
}

#[test]
fn legacy_colon_conjunction_pattern() {
    let mut g = seed_labels();
    let rows = run("MATCH (n:A:B) RETURN n.id AS id", &mut g);
    assert_eq!(ids(&rows), ["AB", "ABC"]);
}

#[test]
fn ampersand_conjunction_equals_legacy_colon() {
    let mut g = seed_labels();
    let rows = run("MATCH (n:A&B) RETURN n.id AS id", &mut g);
    // `:A&B` is exactly equivalent to the legacy `:A:B`.
    assert_eq!(ids(&rows), ["AB", "ABC"]);
}

#[test]
fn pipe_disjunction_pattern() {
    let mut g = seed_labels();
    let rows = run("MATCH (n:A|B) RETURN n.id AS id", &mut g);
    // Any node carrying A or B (or both).
    assert_eq!(ids(&rows), ["A", "AB", "ABC", "AC", "B", "BC"]);
}

#[test]
fn negation_pattern() {
    let mut g = seed_labels();
    let rows = run("MATCH (n:!A) RETURN n.id AS id", &mut g);
    // Every node NOT carrying A — including the unlabelled node.
    assert_eq!(ids(&rows), ["B", "BC", "C", "none"]);
}

#[test]
fn wildcard_pattern_matches_any_labelled_node() {
    let mut g = seed_labels();
    let rows = run("MATCH (n:%) RETURN n.id AS id", &mut g);
    // `%` matches every node with at least one label; the unlabelled node is excluded.
    assert_eq!(ids(&rows), ["A", "AB", "ABC", "AC", "B", "BC", "C"]);
}

#[test]
fn grouped_expression_pattern() {
    let mut g = seed_labels();
    // (A & B) | C  — precedence & grouping: A-and-B, plus anything with C.
    let rows = run("MATCH (n:(A&B)|C) RETURN n.id AS id", &mut g);
    assert_eq!(ids(&rows), ["AB", "ABC", "AC", "BC", "C"]);
}

#[test]
fn negation_binds_tighter_than_conjunction() {
    let mut g = seed_labels();
    // !A & B  ==  (!A) & B  — nodes with B but not A.
    let rows = run("MATCH (n:!A&B) RETURN n.id AS id", &mut g);
    assert_eq!(ids(&rows), ["B", "BC"]);
}

#[test]
fn conjunction_binds_tighter_than_disjunction() {
    let mut g = seed_labels();
    // A | B & C  ==  A | (B & C)
    let rows = run("MATCH (n:A|B&C) RETURN n.id AS id", &mut g);
    assert_eq!(ids(&rows), ["A", "AB", "ABC", "AC", "BC"]);
}

#[test]
fn double_negation_pattern() {
    let mut g = seed_labels();
    // !!A  ==  A
    let rows = run("MATCH (n:!!A) RETURN n.id AS id", &mut g);
    assert_eq!(ids(&rows), ["A", "AB", "ABC", "AC"]);
}

#[test]
fn expand_target_label_expression() {
    // A general label expression on an expand target (never label-scanned) still filters.
    let mut g = MemGraph::new();
    let a = g.add_node(["Root"], [("id", s("root"))]);
    let b = g.add_node(["X"], [("id", s("x"))]);
    let c = g.add_node(["Y"], [("id", s("y"))]);
    g.add_rel("R", a, b, [] as [(&str, Value); 0]);
    g.add_rel("R", a, c, [] as [(&str, Value); 0]);
    let rows = run("MATCH (:Root)-[:R]->(t:X|Y) RETURN t.id AS id", &mut g);
    assert_eq!(ids(&rows), ["x", "y"]);
    let rows = run("MATCH (:Root)-[:R]->(t:!X) RETURN t.id AS id", &mut g);
    assert_eq!(ids(&rows), ["y"]);
}

// =================================================================================================
// WHERE label predicates
// =================================================================================================

#[test]
fn where_single_label_boolean() {
    // Graph5 [1]: `a:B` as a returned boolean over every node.
    let mut g = seed_labels();
    let rows = run("MATCH (a) RETURN a.id AS id, a:B AS r", &mut g);
    let mut got: Vec<(String, bool)> = rows
        .iter()
        .map(|r| {
            let id = match r.value("id") {
                Value::String(s) => s,
                o => panic!("{o:?}"),
            };
            let b = matches!(r.value("r"), Value::Boolean(b) if b);
            (id, b)
        })
        .collect();
    got.sort();
    let has_b = |id: &str| matches!(id, "B" | "AB" | "BC" | "ABC");
    for (id, b) in got {
        assert_eq!(b, has_b(&id), "a:B for node {id}");
    }
}

#[test]
fn where_conjunction() {
    let mut g = seed_labels();
    let rows = run("MATCH (n) WHERE n:A&B RETURN n.id AS id", &mut g);
    assert_eq!(ids(&rows), ["AB", "ABC"]);
}

#[test]
fn where_disjunction() {
    let mut g = seed_labels();
    let rows = run("MATCH (n) WHERE n:A|B RETURN n.id AS id", &mut g);
    assert_eq!(ids(&rows), ["A", "AB", "ABC", "AC", "B", "BC"]);
}

#[test]
fn where_negation_and_grouping() {
    let mut g = seed_labels();
    // (A | B) & !C
    let rows = run("MATCH (n) WHERE n:(A|B)&!C RETURN n.id AS id", &mut g);
    assert_eq!(ids(&rows), ["A", "AB", "B"]);
}

#[test]
fn where_wildcard_excludes_unlabelled() {
    let mut g = seed_labels();
    let rows = run("MATCH (n) WHERE n:% RETURN n.id AS id", &mut g);
    assert_eq!(ids(&rows), ["A", "AB", "ABC", "AC", "B", "BC", "C"]);
}

#[test]
fn label_predicate_before_comprehension_pipe_is_not_swallowed() {
    // Regression guard for the `|` ambiguity: a label predicate in a list-comprehension WHERE must
    // not consume the comprehension's `|` projection separator. `x:A` is the filter; `|` separates
    // the projection `x.id`.
    let mut g = seed_labels();
    let rows = run(
        "MATCH (n) WITH collect(n) AS ns \
         RETURN [x IN ns WHERE x:A | x.id] AS picked",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    let Value::List(mut got) = rows[0].value("picked") else {
        panic!("expected a list");
    };
    got.sort_by_key(|v| format!("{v:?}"));
    assert_eq!(got, vec![s("A"), s("AB"), s("ABC"), s("AC")]);
}

#[test]
fn parenthesised_disjunction_inside_comprehension_where() {
    // A disjunctive label expression inside a comprehension WHERE works when parenthesised.
    let mut g = seed_labels();
    let rows = run(
        "MATCH (n) WITH collect(n) AS ns \
         RETURN [x IN ns WHERE (x:A|B) | x.id] AS picked",
        &mut g,
    );
    let Value::List(mut got) = rows[0].value("picked") else {
        panic!("expected a list");
    };
    got.sort_by_key(|v| format!("{v:?}"));
    assert_eq!(
        got,
        vec![s("A"), s("AB"), s("ABC"), s("AC"), s("B"), s("BC")]
    );
}

#[test]
fn where_negation_on_unlabelled_is_true() {
    // A node with no labels: `n:!A` is true, `n:%` is false (Neo4j 5.x).
    let mut g = MemGraph::new();
    g.add_node([] as [&str; 0], [("id", s("bare"))]);
    assert_eq!(
        ids(&run("MATCH (n) WHERE n:!A RETURN n.id AS id", &mut g)),
        ["bare"]
    );
    assert!(run("MATCH (n) WHERE n:% RETURN n.id AS id", &mut g).is_empty());
}

#[test]
fn where_label_and_boolean_combination() {
    // A label predicate composes with ordinary boolean operators.
    let mut g = seed_labels();
    let rows = run("MATCH (n) WHERE n:A AND NOT n:B RETURN n.id AS id", &mut g);
    assert_eq!(ids(&rows), ["A", "AC"]);
}

// =================================================================================================
// Relationship-type expressions
// =================================================================================================

/// A small typed-edge graph: one central node with an outgoing edge of each type, tagged by `id`.
fn seed_typed_edges() -> (MemGraph, NodeId) {
    let mut g = MemGraph::new();
    let hub = g.add_node(["Hub"], [("id", s("hub"))]);
    let t1 = g.add_node([] as [&str; 0], [("id", s("t1"))]);
    let t2 = g.add_node([] as [&str; 0], [("id", s("t2"))]);
    let t3 = g.add_node([] as [&str; 0], [("id", s("t3"))]);
    g.add_rel("T1", hub, t1, [] as [(&str, Value); 0]);
    g.add_rel("T2", hub, t2, [] as [(&str, Value); 0]);
    g.add_rel("T3", hub, t3, [] as [(&str, Value); 0]);
    (g, hub)
}

#[test]
fn rel_type_disjunction() {
    let (mut g, _) = seed_typed_edges();
    let rows = run("MATCH (:Hub)-[:T1|T2]->(t) RETURN t.id AS id", &mut g);
    assert_eq!(ids(&rows), ["t1", "t2"]);
}

#[test]
fn rel_type_negation() {
    let (mut g, _) = seed_typed_edges();
    let rows = run("MATCH (:Hub)-[r:!T1]->(t) RETURN t.id AS id", &mut g);
    assert_eq!(ids(&rows), ["t2", "t3"]);
}

#[test]
fn rel_type_wildcard_matches_any() {
    let (mut g, _) = seed_typed_edges();
    let rows = run("MATCH (:Hub)-[:%]->(t) RETURN t.id AS id", &mut g);
    assert_eq!(ids(&rows), ["t1", "t2", "t3"]);
}

#[test]
fn rel_type_conjunction_never_matches() {
    // A relationship has exactly one type, so `:T1&T2` can never match (Neo4j).
    let (mut g, _) = seed_typed_edges();
    let rows = run("MATCH (:Hub)-[:T1&T2]->(t) RETURN t.id AS id", &mut g);
    assert!(rows.is_empty());
}

#[test]
fn rel_type_grouped_expression() {
    let (mut g, _) = seed_typed_edges();
    // (T1 | T2) & !T2  ==  just T1
    let rows = run(
        "MATCH (:Hub)-[r:(T1|T2)&!T2]->(t) RETURN t.id AS id",
        &mut g,
    );
    assert_eq!(ids(&rows), ["t1"]);
}

#[test]
fn where_relationship_type_predicate() {
    // A label predicate on a relationship checks its single type.
    let (mut g, _) = seed_typed_edges();
    let rows = run(
        "MATCH (:Hub)-[r]->(t) WHERE r:T1|T3 RETURN t.id AS id",
        &mut g,
    );
    assert_eq!(ids(&rows), ["t1", "t3"]);
}

#[test]
fn legacy_pipe_colon_relationship_types() {
    // openCypher legacy `[:A|:B]` (optional colon after `|`) still parses.
    let (mut g, _) = seed_typed_edges();
    let rows = run("MATCH (:Hub)-[:T1|:T3]->(t) RETURN t.id AS id", &mut g);
    assert_eq!(ids(&rows), ["t1", "t3"]);
}

// =================================================================================================
// Null and three-valued logic
// =================================================================================================

#[test]
fn label_expression_on_null_is_null() {
    // Graph5 [5]: an OPTIONAL MATCH that binds nothing yields `null`, and a label predicate on
    // `null` is `null` (not false).
    let mut g = MemGraph::new();
    g.add_node(["Single"], [("id", s("s"))]);
    let rows = run(
        "MATCH (n:Single) OPTIONAL MATCH (n)-[r:TYPE]-(m) RETURN m:TYPE AS r",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("r"), Value::Null);
}

#[test]
fn negated_label_expression_on_null_is_null() {
    let mut g = MemGraph::new();
    g.add_node(["Single"], [("id", s("s"))]);
    let rows = run(
        "MATCH (n:Single) OPTIONAL MATCH (n)-[r:TYPE]-(m) RETURN m:!A|B AS r",
        &mut g,
    );
    assert_eq!(rows[0].value("r"), Value::Null);
}

// =================================================================================================
// Rejected constructs (compile-time)
// =================================================================================================

#[test]
fn label_expression_rejected_in_create() {
    assert!(compile_err("CREATE (n:A|B)").contains("LabelExpressionNotAllowed"));
    assert!(compile_err("CREATE (n:!A)").contains("LabelExpressionNotAllowed"));
    assert!(compile_err("CREATE (n:%)").contains("LabelExpressionNotAllowed"));
}

#[test]
fn label_expression_rejected_in_merge() {
    assert!(compile_err("MERGE (n:A|B)").contains("LabelExpressionNotAllowed"));
}

#[test]
fn general_type_expression_rejected_on_var_length() {
    // A general per-hop type expression on a variable-length relationship is not modelled.
    assert!(
        compile_err("MATCH (:Hub)-[:!T1*1..3]->(t) RETURN t").contains("LabelExpressionNotAllowed")
    );
    // A disjunction on a var-length hop still uses the fast path and is fine.
    let (mut g, _) = seed_typed_edges();
    let _ = run("MATCH (:Hub)-[:T1|T2*1..1]->(t) RETURN t.id AS id", &mut g);
}

#[test]
fn mixing_colon_and_operators_is_a_syntax_error() {
    // Neo4j forbids combining the legacy `:` conjunction with the `&`/`|`/`!`/`%` operators.
    assert!(compile_err("MATCH (n:A:B&C) RETURN n").contains("Expected"));
    assert!(compile_err("MATCH (n:A&B:C) RETURN n").contains("Expected"));
    assert!(compile_err("MATCH (n) WHERE n:A|B:C RETURN n").contains("Expected"));
}

#[test]
fn set_and_remove_still_take_concrete_labels_only() {
    // SET/REMOVE keep the colon-conjunction-only label list; a label expression there is a parse
    // error (the `&` cannot begin the property/label continuation).
    let mut g = MemGraph::new();
    g.add_node(["A"], [("id", s("x"))]);
    // Legacy multi-label SET still works.
    let _ = run("MATCH (n:A) SET n:B:C RETURN n.id AS id", &mut g);
    let rows = run("MATCH (n) WHERE n:A&B&C RETURN n.id AS id", &mut g);
    assert_eq!(ids(&rows), ["x"]);
}
