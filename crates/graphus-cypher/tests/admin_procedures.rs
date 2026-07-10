//! End-to-end tests for the Neo4j-compatible admin/introspection procedures (`rmp` task #639):
//! `dbms.components`, `db.awaitIndexes`, `db.resampleIndex`, `db.resampleOutdatedIndexes` and
//! `db.index.fulltext.queryRelationships`.
//!
//! These drive the **whole** query path — lex → parse → analyze → plan → bind → execute →
//! materialize — over the [`MemGraph`] reference backend, proving the registry wiring, the `YIELD`
//! binding and (crucially for `dbms.components`) that a `LIST<STRING>` output column egresses through
//! the executor as a materialized list. The registry-level unit tests in
//! `src/procedure_registry.rs` cover the handler bodies in isolation; this file proves the
//! executor + `YIELD` + materialization seam end-to-end, mirroring `tests/fulltext_index.rs`.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::MemGraph;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::result::MaterializedValue;
use graphus_cypher::semantics::analyze;

/// Compiles and runs `src` over `graph`, returning the materialized result rows (the shape the wire
/// seams consume).
fn run(src: &str, graph: &mut MemGraph) -> Vec<Vec<MaterializedValue>> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut cursor = execute(&plan, &bound, graph).expect("open cursor");
    let mut rows = Vec::new();
    while let Some(row) = cursor.next_materialized().expect("row") {
        rows.push(row);
    }
    rows
}

/// Compiles and runs `src`, expecting execution to fail; returns the rendered error string.
fn run_expect_err(src: &str, graph: &mut MemGraph) -> String {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut cursor = execute(&plan, &bound, graph).expect("open cursor");
    // The failure surfaces as the cursor is driven.
    match cursor.next_materialized() {
        Err(e) => format!("{e}"),
        Ok(_) => panic!("expected a runtime error, but the cursor produced a row"),
    }
}

#[test]
fn dbms_components_yields_name_versions_edition_end_to_end() {
    let mut g = MemGraph::new();
    let rows = run(
        "CALL dbms.components() YIELD name, versions, edition RETURN name, versions, edition",
        &mut g,
    );
    assert_eq!(rows.len(), 1, "dbms.components yields exactly one row");
    let row = &rows[0];

    // name = "Graphus"
    match &row[0] {
        MaterializedValue::Value(Value::String(s)) => assert_eq!(s, "Graphus"),
        other => panic!("expected name String, got {other:?}"),
    }
    // versions = LIST<STRING> of the workspace version — proves a list value egresses correctly.
    match &row[1] {
        MaterializedValue::Value(Value::List(items)) => {
            assert_eq!(
                items,
                &vec![Value::String(env!("CARGO_PKG_VERSION").into())]
            );
        }
        other => panic!("expected versions List, got {other:?}"),
    }
    // edition = "community"
    match &row[2] {
        MaterializedValue::Value(Value::String(s)) => assert_eq!(s, "community"),
        other => panic!("expected edition String, got {other:?}"),
    }
}

#[test]
fn void_admin_procedures_add_no_columns_end_to_end() {
    let mut g = MemGraph::new();
    // A VOID procedure is cardinality-preserving (openCypher `test.doNothing()` semantics): a
    // standalone call runs against the single seed row and passes it through, adding **no** columns.
    // So the result is exactly one row with zero columns — the procedure completed with no effect and
    // no yielded data.
    for src in [
        "CALL db.awaitIndexes(30)",
        "CALL db.resampleIndex('some_index')",
        "CALL db.resampleOutdatedIndexes()",
    ] {
        let rows = run(src, &mut g);
        assert_eq!(
            rows.len(),
            1,
            "`{src}` preserves the seed row's cardinality"
        );
        assert!(rows[0].is_empty(), "`{src}` yields no columns (VOID)");
    }
}

#[test]
fn void_admin_procedure_passes_driving_rows_through_unchanged() {
    // In-query, a void procedure adds no columns and passes each driving row through. `UNWIND`
    // provides three driving rows; `db.awaitIndexes` must not drop or duplicate any.
    let mut g = MemGraph::new();
    let rows = run(
        "UNWIND [1, 2, 3] AS x CALL db.awaitIndexes(1) RETURN x",
        &mut g,
    );
    let xs: Vec<i64> = rows
        .iter()
        .map(|r| match &r[0] {
            MaterializedValue::Value(Value::Integer(i)) => *i,
            other => panic!("expected integer x, got {other:?}"),
        })
        .collect();
    assert_eq!(xs, vec![1, 2, 3]);
}

#[test]
fn fulltext_query_relationships_yields_structural_relationships_end_to_end() {
    // `rmp` task #663: `queryRelationships` returns a structural RELATIONSHIP result column, driven
    // through the whole plan → execute → materialize seam.
    let mut g = MemGraph::new();
    let a = g.add_node(["N"], [] as [(&str, Value); 0]);
    let b = g.add_node(["N"], [] as [(&str, Value); 0]);
    let r = g.add_rel("KNOWS", a, b, [("note", s("graph database"))]);
    g.create_fulltext_rel_index(
        "rel_ix",
        ["KNOWS"],
        ["note"],
        graphus_cypher::Analyzer::Standard,
    );

    let rows = run(
        "CALL db.index.fulltext.queryRelationships('rel_ix', 'database') YIELD relationship, score \
         RETURN relationship, score",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    match &rows[0][0] {
        MaterializedValue::Relationship(rel) => {
            assert_eq!(rel.id, r.0);
            assert_eq!(rel.rel_type, "KNOWS");
            assert_eq!(rel.start, a.0);
            assert_eq!(rel.end, b.0);
        }
        other => panic!("expected a structural relationship, got {other:?}"),
    }
    match &rows[0][1] {
        MaterializedValue::Value(Value::Float(f)) => assert!(*f >= 1.0),
        other => panic!("expected a float score, got {other:?}"),
    }
}

#[test]
fn fulltext_query_relationships_unknown_index_is_a_clear_error() {
    // An unknown relationship-index name (or a *node* index name given here) is a clear error.
    let mut g = MemGraph::new();
    let err = run_expect_err(
        "CALL db.index.fulltext.queryRelationships('nope', 'query') YIELD relationship, score \
         RETURN relationship, score",
        &mut g,
    );
    assert!(
        err.contains("nope") && err.contains("relationship full-text index"),
        "error should name the missing relationship full-text index, got: {err}"
    );
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}
