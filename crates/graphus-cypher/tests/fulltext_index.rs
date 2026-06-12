//! End-to-end full-text index tests over the [`MemGraph`] reference backend (`rmp` task #72).
//!
//! These exercise the **whole** query path — `CALL db.index.fulltext.queryNodes(name, query)
//! YIELD node, score` compiled, executed, and **materialized** — and assert that `node` egresses as
//! a structural [`MaterializedValue::Node`] (rmp #96), that the analyzer's documented behaviour holds
//! (tokenization, lowercasing, stop-words), that updates and deletes are reflected, and that an
//! unknown index name is a clear error. The durable-restart / MVCC-snapshot proofs against the real
//! storage backend live in the `graphus-server` integration tests; here the reference backend proves
//! the executor + procedure + materialization wiring.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, MemGraph, NodeId};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::result::{MaterializedNode, MaterializedValue};
use graphus_cypher::semantics::analyze;
use graphus_index::fulltext::Analyzer;

/// Compiles and runs `src` over `graph`, returning the **materialized** result rows so a `node`
/// column is the structural node it egresses as (the path the wire seams consume).
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

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

/// The `name` property of a materialized node row's first column (a structural node), for assertions.
fn node_name(row: &[MaterializedValue]) -> String {
    match &row[0] {
        MaterializedValue::Node(MaterializedNode { properties, .. }) => properties
            .iter()
            .find(|(k, _)| k == "name")
            .map(|(_, v)| match v {
                Value::String(s) => s.clone(),
                other => format!("{other:?}"),
            })
            .unwrap_or_default(),
        other => panic!("expected a structural node in column 0, got {other:?}"),
    }
}

#[test]
fn query_nodes_returns_structural_nodes_for_tokenized_matches() {
    let mut g = MemGraph::new();
    let _ada = g.add_node(
        ["Article"],
        [("title", s("Graph databases are great")), ("name", s("a1"))],
    );
    let _bob = g.add_node(
        ["Article"],
        [("title", s("Relational databases")), ("name", s("a2"))],
    );
    let _eve = g.add_node(
        ["Article"],
        [("title", s("Graph theory basics")), ("name", s("a3"))],
    );
    let _x = g.add_node(["Other"], [("title", s("Graph stuff")), ("name", s("x"))]); // wrong label
    g.create_fulltext_index("articles", "Article", ["title"], Analyzer::Standard);

    // "databases" matches a1 + a2. The result `node` column is a STRUCTURAL node (rmp #96), so we can
    // read its properties back through materialization.
    let rows = run(
        "CALL db.index.fulltext.queryNodes('articles', 'databases') YIELD node, score RETURN node, score",
        &mut g,
    );
    let mut names: Vec<String> = rows.iter().map(|r| node_name(r)).collect();
    names.sort();
    assert_eq!(names, vec!["a1".to_owned(), "a2".to_owned()]);

    // The second column is the FLOAT score (best-effort overlap = 1 here).
    for row in &rows {
        match &row[1] {
            MaterializedValue::Value(Value::Float(f)) => assert!(*f >= 1.0),
            other => panic!("expected a float score, got {other:?}"),
        }
    }

    // "graph" matches a1 + a3 (NOT the Other-labelled node — the index covers Article only).
    let rows = run(
        "CALL db.index.fulltext.queryNodes('articles', 'GRAPH') YIELD node RETURN node",
        &mut g,
    );
    let mut names: Vec<String> = rows.iter().map(|r| node_name(r)).collect();
    names.sort();
    assert_eq!(names, vec!["a1".to_owned(), "a3".to_owned()]);
}

#[test]
fn analyzer_lowercases_and_drops_stop_words_at_query_time() {
    let mut g = MemGraph::new();
    g.add_node(
        ["Doc"],
        [("body", s("The Quick Brown Fox")), ("name", s("d1"))],
    );
    g.create_fulltext_index("docs", "Doc", ["body"], Analyzer::Standard);

    // Mixed-case query lowercases to match (analyzer applied identically at index + query time).
    let rows = run(
        "CALL db.index.fulltext.queryNodes('docs', 'BROWN') YIELD node RETURN node",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(node_name(&rows[0]), "d1");

    // A stop-word-only query ("the") matches nothing — "the" is removed at both index and query time.
    let rows = run(
        "CALL db.index.fulltext.queryNodes('docs', 'the') YIELD node RETURN node",
        &mut g,
    );
    assert!(rows.is_empty(), "a stop-word-only query must match nothing");
}

#[test]
fn updates_and_deletes_are_reflected() {
    let mut g = MemGraph::new();
    let n = g.add_node(["Post"], [("text", s("graph database")), ("name", s("p1"))]);
    g.create_fulltext_index("posts", "Post", ["text"], Analyzer::Standard);

    // Initially "database" matches.
    let rows = run(
        "CALL db.index.fulltext.queryNodes('posts', 'database') YIELD node RETURN node",
        &mut g,
    );
    assert_eq!(rows.len(), 1);

    // Update the text: it no longer mentions "database" (the reference impl re-analyzes live state).
    g.set_node_property(n, "text", s("graph theory"));
    let rows = run(
        "CALL db.index.fulltext.queryNodes('posts', 'database') YIELD node RETURN node",
        &mut g,
    );
    assert!(
        rows.is_empty(),
        "the updated node must no longer match the stale term"
    );
    let rows = run(
        "CALL db.index.fulltext.queryNodes('posts', 'theory') YIELD node RETURN node",
        &mut g,
    );
    assert_eq!(rows.len(), 1, "the updated node matches its new term");

    // Delete the node: it disappears from the results.
    g.delete_node(n);
    let rows = run(
        "CALL db.index.fulltext.queryNodes('posts', 'theory') YIELD node RETURN node",
        &mut g,
    );
    assert!(rows.is_empty(), "a deleted node must not match");
}

#[test]
fn keyword_analyzer_matches_the_whole_field_case_insensitively() {
    let mut g = MemGraph::new();
    g.add_node(
        ["Tag"],
        [("label", s("Machine Learning")), ("name", s("t1"))],
    );
    g.add_node(["Tag"], [("label", s("Machine")), ("name", s("t2"))]);
    g.create_fulltext_index("tags", "Tag", ["label"], Analyzer::Keyword);

    // Keyword analyzer: the whole field is one term, lowercased. "machine learning" matches t1 only.
    let rows = run(
        "CALL db.index.fulltext.queryNodes('tags', 'machine learning') YIELD node RETURN node",
        &mut g,
    );
    let names: Vec<String> = rows.iter().map(|r| node_name(r)).collect();
    assert_eq!(names, vec!["t1".to_owned()]);

    // A single word does NOT match the whole-field "machine learning" term (no tokenization).
    let rows = run(
        "CALL db.index.fulltext.queryNodes('tags', 'machine') YIELD node RETURN node",
        &mut g,
    );
    assert_eq!(
        rows.iter().map(|r| node_name(r)).collect::<Vec<_>>(),
        vec!["t2".to_owned()]
    );
}

#[test]
fn unknown_index_name_is_a_clear_error() {
    let mut g = MemGraph::new();
    g.add_node(["Article"], [("title", s("hello"))]);
    // No index declared; the procedure must error (not return empty results) so a typo is obvious.
    let src = "CALL db.index.fulltext.queryNodes('nope', 'hello') YIELD node RETURN node";
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut cursor = execute(&plan, &bound, &mut g).expect("open");
    // The failure surfaces when the procedure is invoked (on the first pull).
    let err = cursor
        .next_materialized()
        .expect_err("must fail on unknown index");
    let msg = format!("{err}");
    assert!(
        msg.contains("nope") && msg.to_lowercase().contains("full-text"),
        "error should name the missing index: {msg}"
    );
}

#[test]
fn multi_property_index_searches_all_covered_properties() {
    let mut g = MemGraph::new();
    g.add_node(
        ["Book"],
        [
            ("title", s("Rust")),
            ("summary", s("a systems language")),
            ("name", s("b1")),
        ],
    );
    g.add_node(
        ["Book"],
        [
            ("title", s("Cooking")),
            ("summary", s("rust-free recipes")),
            ("name", s("b2")),
        ],
    );
    g.create_fulltext_index("books", "Book", ["title", "summary"], Analyzer::Standard);

    // "rust" appears in b1.title and b2.summary -> both match (the index covers both properties).
    let rows = run(
        "CALL db.index.fulltext.queryNodes('books', 'rust') YIELD node RETURN node",
        &mut g,
    );
    let mut names: Vec<String> = rows.iter().map(|r| node_name(r)).collect();
    names.sort();
    assert_eq!(names, vec!["b1".to_owned(), "b2".to_owned()]);

    // "systems" only in b1.summary.
    let rows = run(
        "CALL db.index.fulltext.queryNodes('books', 'systems') YIELD node RETURN node",
        &mut g,
    );
    assert_eq!(
        rows.iter().map(|r| node_name(r)).collect::<Vec<_>>(),
        vec!["b1".to_owned()]
    );
}

/// A node never created is never matched (the reference backend's analogue of MVCC invisibility:
/// the procedure re-checks `node_exists`).
#[test]
fn nonexistent_candidate_is_filtered() {
    let mut g = MemGraph::new();
    let n = g.add_node(["A"], [("t", s("findme")), ("name", s("n1"))]);
    g.create_fulltext_index("ix", "A", ["t"], Analyzer::Standard);
    g.delete_node(n);
    // The id is gone; even though it was once indexed, `node_exists` re-check drops it.
    assert!(
        g.fulltext_query("ix", "findme")
            .map(|v| v.contains(&NodeId(n.0)))
            != Some(true)
    );
    let rows = run(
        "CALL db.index.fulltext.queryNodes('ix', 'findme') YIELD node RETURN node",
        &mut g,
    );
    assert!(rows.is_empty());
}
