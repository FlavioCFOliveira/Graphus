//! Hermetic cargo exercise of the `examples/knowledge-graph-rest` **schema** (`rmp` #674).
//!
//! Where `knowledge_graph_rest.rs` proves the discovery *semantics + REST serialization* over a
//! data-only load, this test proves the production-realistic **search schema** the example now
//! declares actually works end-to-end, hermetically (no Bolt, no REST, no python, no network): it
//! takes the DDL block `graphus-kg-gen`'s `to_cypher()` emits, drives it through the REAL engine via
//! the admin-DDL command path (`parse_admin_statement` → `LocalEngine::{index_ddl, constraint_ddl}`
//! — the exact seam the Bolt/REST admin surfaces submit after parsing `CREATE … INDEX` /
//! `CREATE CONSTRAINT`), loads the seeded graph **schema-first**, and asserts:
//!
//! - the new index & constraint kinds are declared and `Online` (`SHOW INDEXES` / `SHOW
//!   CONSTRAINTS`): a **FULLTEXT** node index over `Document.title`, the node `RANGE` index on
//!   `Document.year`, the four node `UNIQUE` id constraints, a node **property-type** constraint
//!   (`Document.year IS :: INTEGER`) and a node **existence** constraint (`Document.title IS NOT
//!   NULL`);
//! - the **FULLTEXT search path**: `CALL db.index.fulltext.queryNodes('document_fulltext', '<term>')`
//!   returns exactly the known reference documents for that term — including the *empirically-verified*
//!   analyzer behaviour that the standard analyzer does **not** stem (so `graph` matches only the
//!   "On Graph Storage" title, never the "Indexed Graphs" one, which tokenizes to `graphs`);
//! - **constraint enforcement**: a Document written with a non-integer `year` (property-type) and one
//!   written with a missing `title` (existence) are each rejected with the constraint-violation error
//!   class.
//!
//! Determining the substrate empirically (`rmp` #674 asked): `LocalEngine::run` does **not** accept
//! DDL strings (admin DDL is intercepted before the Cypher pipeline), but `LocalEngine` fully supports
//! admin DDL through its typed `index_ddl` / `constraint_ddl` methods **and** runs the built-in
//! full-text procedure `db.index.fulltext.queryNodes` through its normal query path — so the whole
//! exercise runs in-process against the real coordinator, no booted server required.

use std::sync::Arc;

use graphus_core::Value;
use graphus_cypher::{CONSTRAINT_VIOLATION_PREFIX, MaterializedValue};
use graphus_io::MemBlockDevice;
use graphus_kg_gen::{Dataset, Profile, generate};
use graphus_server::admin::{AdminParse, parse_admin_statement};
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{
    ConstraintCommand, ConstraintTypeFilter, IndexCommand, IndexDdlReply, IndexTypeFilter,
    LocalEngine,
};
use graphus_sim::SharedClock;
use graphus_wal::MemLogSink;

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

/// Builds an in-memory engine with a fixed clock — the deterministic, hermetic substrate.
fn engine() -> Eng {
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 1024).expect("in-memory engine")
}

/// Whether `stmt` is a schema-DDL statement (any `CREATE CONSTRAINT` or any `CREATE … INDEX` form,
/// including `CREATE FULLTEXT INDEX`). Mirrors the loader splitters in `discovery.py` and
/// `knowledge_graph_rest.rs`.
fn is_schema_ddl(stmt: &str) -> bool {
    stmt.starts_with("CREATE CONSTRAINT")
        || (stmt.starts_with("CREATE") && stmt.contains(" INDEX "))
}

/// Splits the generated Cypher script into individual statements (dropping `//` comment lines).
fn split_statements(script: &str) -> Vec<String> {
    script
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Generates the fast-profile dataset, then loads it **schema-first** through the real engine: every
/// `CREATE CONSTRAINT` / `CREATE … INDEX` runs through the admin-DDL command path (as the Bolt/REST
/// admin seams do), then the data CREATEs load inside a single write transaction. Returns the loaded
/// engine and the dataset (for deriving ground-truth expectations). Asserts the load succeeds — i.e.
/// **every seed value conforms to every constraint** (`rmp` #674 acceptance).
fn load_schema_first() -> (Eng, Dataset) {
    let dataset = generate(Profile::Fast.config(), Profile::Fast.name());
    let script = dataset.to_cypher();
    let statements = split_statements(&script);

    let (ddl, data): (Vec<String>, Vec<String>) =
        statements.into_iter().partition(|s| is_schema_ddl(s));

    // The full schema DDL block this example declares: 4 UNIQUE + property-type + existence + a RANGE
    // index + a FULLTEXT index = 8 statements.
    assert!(
        ddl.len() >= 8,
        "expected the full schema DDL block, got {} statements: {ddl:?}",
        ddl.len()
    );

    let mut eng = engine();

    // 1. Apply the schema DDL through the admin path (each an auto-commit control command).
    for stmt in &ddl {
        match parse_admin_statement(stmt) {
            AdminParse::Index(cmd) => {
                eng.index_ddl(cmd)
                    .unwrap_or_else(|e| panic!("index DDL failed: {stmt}\n  {e}"));
            }
            AdminParse::Constraint(cmd) => {
                eng.constraint_ddl(cmd)
                    .unwrap_or_else(|e| panic!("constraint DDL failed: {stmt}\n  {e}"));
            }
            other => panic!("schema statement did not parse as admin DDL: {stmt}\n  got {other:?}"),
        }
    }

    // 2. Load the data with the schema active — every write is constraint-checked and index-maintained
    //    (so the FULLTEXT index is populated incrementally as each Document CREATE lands).
    let ticket = eng.begin(AccessMode::Write).expect("begin load txn");
    for stmt in &data {
        let mut reply = eng
            .run(ticket, stmt, Vec::new(), false, None)
            .unwrap_or_else(|e| {
                panic!("load statement failed (data does not conform?): {stmt}\n  {e}")
            });
        while let Ok(Some(_)) = reply.rows.next() {}
    }
    eng.commit(ticket).expect("commit load txn");

    (eng, dataset)
}

/// `SHOW INDEXES` (full column set), as an [`IndexDdlReply`].
fn show_indexes(eng: &mut Eng) -> IndexDdlReply {
    eng.index_ddl(IndexCommand::ShowIndexes {
        filter: IndexTypeFilter::All,
        tail: None,
    })
    .expect("show indexes")
}

/// `SHOW CONSTRAINTS` (full column set), as an [`IndexDdlReply`].
fn show_constraints(eng: &mut Eng) -> IndexDdlReply {
    eng.constraint_ddl(ConstraintCommand::Show {
        filter: ConstraintTypeFilter::All,
        tail: None,
    })
    .expect("show constraints")
}

/// The 0-based column index of `name` in an [`IndexDdlReply`]'s field list.
fn col(reply: &IndexDdlReply, name: &str) -> usize {
    reply
        .fields
        .iter()
        .position(|f| f == name)
        .unwrap_or_else(|| panic!("a `{name}` column in {:?}", reply.fields))
}

/// Finds the single row whose `name` column equals `name`, or panics.
fn row_by_name<'a>(reply: &'a IndexDdlReply, name: &str) -> &'a [Value] {
    let name_c = col(reply, "name");
    reply
        .rows
        .iter()
        .find(|r| matches!(&r[name_c], Value::String(n) if n == name))
        .unwrap_or_else(|| panic!("a row named `{name}`"))
        .as_slice()
}

/// Runs an auto-commit write that MUST be rejected by a constraint, returning the violation message.
/// The violation surfaces either from `run` or mid-stream while draining — both are handled.
fn expect_rejected(eng: &mut Eng, stmt: &str) -> String {
    let ticket = eng
        .begin_auto_commit(AccessMode::Write)
        .expect("begin auto-commit");
    match eng.run(ticket, stmt, Vec::new(), true, None) {
        Err(e) => e.to_string(),
        Ok(mut reply) => loop {
            match reply.rows.next() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("statement was ACCEPTED but must be rejected: {stmt}"),
                Err(e) => break e.to_string(),
            }
        },
    }
}

/// Collects the single string column (e.g. a `node.id`) of a read query into a sorted, de-duplicated
/// set — the Document ids the full-text search returned.
fn collect_string_ids(eng: &mut Eng, query: &str) -> Vec<String> {
    let ticket = eng.begin(AccessMode::Read).expect("begin read txn");
    let mut reply = eng
        .run(ticket, query, Vec::new(), false, None)
        .expect("query runs");
    let mut ids = Vec::new();
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::String(s))) = row.first() {
            ids.push(s.clone());
        }
    }
    eng.commit(ticket).expect("commit read txn");
    ids.sort();
    ids.dedup();
    ids
}

/// Runs the full-text search procedure for `term` and returns the matching Document ids, sorted.
fn fulltext_search(eng: &mut Eng, term: &str) -> Vec<String> {
    collect_string_ids(
        eng,
        &format!(
            "CALL db.index.fulltext.queryNodes('document_fulltext', '{term}') YIELD node \
             RETURN node.id AS id"
        ),
    )
}

#[test]
fn schema_first_load_declares_new_index_and_constraint_kinds() {
    let (mut eng, _dataset) = load_schema_first();

    // ---- SHOW INDEXES: the new FULLTEXT title index + the node RANGE index, Online. ----
    let idx = show_indexes(&mut eng);
    let (type_c, entity_c, labels_c, props_c, state_c) = (
        col(&idx, "type"),
        col(&idx, "entityType"),
        col(&idx, "labelsOrTypes"),
        col(&idx, "properties"),
        col(&idx, "state"),
    );

    // FULLTEXT node index over Document.title — the headline knowledge-graph SEARCH feature.
    let ft = row_by_name(&idx, "document_fulltext");
    assert_eq!(
        ft[type_c],
        Value::String("FULLTEXT".to_owned()),
        "FULLTEXT is a distinct analyzer-tokenized index, not a RANGE/TEXT synonym"
    );
    assert_eq!(
        ft[entity_c],
        Value::String("NODE".to_owned()),
        "the document_fulltext index is a NODE index"
    );
    assert_eq!(
        ft[labels_c],
        Value::List(vec![Value::String("Document".to_owned())])
    );
    assert_eq!(
        ft[props_c],
        Value::List(vec![Value::String("title".to_owned())])
    );
    assert_eq!(
        ft[state_c],
        Value::String("ONLINE".to_owned()),
        "the FULLTEXT index must be Online after the schema-first load"
    );

    // The node RANGE index on Document.year is still present and Online.
    let range = row_by_name(&idx, "document_year_range");
    assert_eq!(range[type_c], Value::String("RANGE".to_owned()));
    assert_eq!(range[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        range[props_c],
        Value::List(vec![Value::String("year".to_owned())])
    );
    assert_eq!(range[state_c], Value::String("ONLINE".to_owned()));

    // ---- SHOW CONSTRAINTS: the 4 UNIQUE + property-type + existence. ----
    let cons = show_constraints(&mut eng);
    let (ctype_c, centity_c, cprops_c, cptype_c) = (
        col(&cons, "type"),
        col(&cons, "entityType"),
        col(&cons, "properties"),
        col(&cons, "propertyType"),
    );

    for name in [
        "author_id_unique",
        "document_id_unique",
        "concept_id_unique",
        "topic_id_unique",
    ] {
        let uniq = row_by_name(&cons, name);
        assert_eq!(
            uniq[ctype_c],
            Value::String("NODE_PROPERTY_UNIQUENESS".to_owned()),
            "{name}"
        );
        assert_eq!(uniq[centity_c], Value::String("NODE".to_owned()), "{name}");
    }

    // Node property-type constraint: Document.year IS :: INTEGER.
    let year_type = row_by_name(&cons, "document_year_integer");
    assert_eq!(
        year_type[ctype_c],
        Value::String("NODE_PROPERTY_TYPE".to_owned())
    );
    assert_eq!(year_type[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        year_type[cprops_c],
        Value::List(vec![Value::String("year".to_owned())])
    );
    assert_eq!(
        year_type[cptype_c],
        Value::String("INTEGER".to_owned()),
        "the declared node property type is INTEGER (year is an i64, never a FLOAT)"
    );

    // Node existence constraint: Document.title IS NOT NULL.
    let title_exists = row_by_name(&cons, "document_title_exists");
    assert_eq!(
        title_exists[ctype_c],
        Value::String("NODE_PROPERTY_EXISTENCE".to_owned())
    );
    assert_eq!(title_exists[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        title_exists[cprops_c],
        Value::List(vec![Value::String("title".to_owned())])
    );
}

#[test]
fn fulltext_index_returns_exactly_the_expected_reference_documents() {
    let (mut eng, _dataset) = load_schema_first();

    // The reference documents carry realistic titles (disjoint from the "Document <n>" background):
    //   ref-d-0 "On Graph Storage" | ref-d-1 "Traversal Methods" | ref-d-2 "Indexed Graphs".
    //
    // EMPIRICAL analyzer finding (asserted below): the `standard` analyzer tokenizes on
    // non-alphanumeric boundaries, lowercases, and drops stop-words, but does NOT stem. So:
    //   - "graph"    -> {ref-d-0}  (title token "graph"; "storage" is the other token; "on" is a
    //                               stop-word). It does NOT match ref-d-2, whose title tokenizes to
    //                               {"indexed", "graphs"} — "graphs" is a DISTINCT term from "graph".
    //   - "graphs"   -> {ref-d-2}  (proving the no-stemming behaviour, the contrast to "graph").
    //   - "storage"  -> {ref-d-0}
    //   - "traversal"-> {ref-d-1}
    // None of the "Document <n>" background titles contain any of these terms, so the answer set is
    // exactly the reference documents — the known, enumerable ground truth.

    assert_eq!(
        fulltext_search(&mut eng, "graph"),
        vec!["ref-d-0".to_owned()],
        "'graph' matches only 'On Graph Storage' (ref-d-0), never 'Indexed Graphs' (no stemming)"
    );
    assert_eq!(
        fulltext_search(&mut eng, "graphs"),
        vec!["ref-d-2".to_owned()],
        "'graphs' matches only 'Indexed Graphs' (ref-d-2) — the no-stemming contrast to 'graph'"
    );
    assert_eq!(
        fulltext_search(&mut eng, "storage"),
        vec!["ref-d-0".to_owned()],
        "'storage' matches only 'On Graph Storage' (ref-d-0)"
    );
    assert_eq!(
        fulltext_search(&mut eng, "traversal"),
        vec!["ref-d-1".to_owned()],
        "'traversal' matches only 'Traversal Methods' (ref-d-1)"
    );

    // A stop-word-only query matches nothing (the analyzer drops it entirely).
    assert!(
        fulltext_search(&mut eng, "on").is_empty(),
        "a stop-word-only query ('on') matches no document"
    );
}

#[test]
fn schema_enforces_node_constraints_with_negative_writes() {
    let (mut eng, dataset) = load_schema_first();

    let document_count = dataset.documents.len() + 3; // + the 3 reference documents

    // Node property-type: a Document with a non-integer `year` (a string) is rejected.
    let wrong_type = expect_rejected(
        &mut eng,
        "CREATE (:Document {id: 'bad-type', title: 'Bad Year', year: 'twenty-twenty'})",
    );
    assert!(
        wrong_type.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a non-integer Document.year must be a constraint violation, got: {wrong_type}"
    );

    // Node existence: a Document without a `title` is rejected.
    let missing = expect_rejected(
        &mut eng,
        "CREATE (:Document {id: 'bad-exists', year: 2020})",
    );
    assert!(
        missing.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a missing/null Document.title must be a constraint violation, got: {missing}"
    );

    // Node uniqueness: a duplicate Document.id (a reference doc) is rejected.
    let dup = expect_rejected(
        &mut eng,
        "CREATE (:Document {id: 'ref-d-0', title: 'Duplicate', year: 2020})",
    );
    assert!(
        dup.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a duplicate Document.id must be a constraint violation, got: {dup}"
    );

    // The rejected writes all rolled back — the Document count is unchanged from the load.
    let count = {
        let ticket = eng.begin(AccessMode::Read).expect("begin read");
        let mut reply = eng
            .run(
                ticket,
                "MATCH (d:Document) RETURN count(d) AS c",
                Vec::new(),
                false,
                None,
            )
            .expect("count runs");
        let mut n = 0i64;
        while let Ok(Some(row)) = reply.rows.next() {
            if let Some(MaterializedValue::Value(Value::Integer(v))) = row.first() {
                n = *v;
            }
        }
        eng.commit(ticket).expect("commit read");
        n
    };
    assert_eq!(
        count, document_count as i64,
        "the three rejected writes created nothing"
    );
}
