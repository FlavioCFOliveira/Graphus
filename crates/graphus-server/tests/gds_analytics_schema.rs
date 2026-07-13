//! Hermetic cargo exercise of the `examples/gds-analytics` **schema** (`rmp` #679).
//!
//! Where `gds_analytics.rs` proves the graph-data-science *algorithm semantics* over a data-only load,
//! this test proves the production-realistic **schema** the example now declares actually works
//! end-to-end, hermetically (no Bolt, no Node, no network): it takes the DDL block `graphus-gds-gen`'s
//! `to_cypher()` emits, drives it through the REAL engine via the admin-DDL command path
//! (`parse_admin_statement` → `LocalEngine::{index_ddl, constraint_ddl}` — the exact seam the Bolt/REST
//! admin surfaces submit after parsing `CREATE INDEX` / `CREATE CONSTRAINT`), loads the seeded
//! influence network **schema-first**, and asserts:
//!
//! - the constraints are declared with the right kind/entity/type (`SHOW CONSTRAINTS`): a node
//!   `UNIQUE` on `Author.id`, a node property-type `STRING` on `Author.field_name`, and a node
//!   property-type `INTEGER` on `Author.h_index`;
//! - the indexes are declared and `Online` (`SHOW INDEXES`): a node `RANGE` index on `Author.field`
//!   and — the headline addition — a **relationship** `RANGE` index on `CITES.weight`;
//! - the **empirical planner utilisation** of the relationship `RANGE` index: Graphus serves an
//!   *equality* predicate on the citation weight from it (a `RelIndexSeek`) **and** a `>=` range
//!   predicate (a `RelIndexRangeSeek`, `rmp` #680) — asserted honestly on the real planner;
//! - **constraint enforcement**: an `Author` written with a non-string `field_name`, one with a
//!   non-integer `h_index`, and a duplicate `Author.id` are each rejected with the constraint-violation
//!   error class, and the rejected writes leave the loaded author count unchanged.
//!
//! Determining the substrate empirically (as `rmp` #673 established for the sibling fraud schema test):
//! `LocalEngine::run` does **not** accept DDL strings (admin DDL is intercepted before the Cypher
//! pipeline), but `LocalEngine` fully supports admin DDL through its typed `index_ddl` /
//! `constraint_ddl` methods — so the whole exercise runs in-process against the real coordinator, no
//! booted server required.
//!
//! IMPORTANT — the property names are the *actual* ones the influence-network model uses: the planted
//! community is an INTEGER `field` id and its human-readable label is a STRING `field_name`, so the
//! STRING property-type constraint sits on `field_name` (not on the integer `field`). The RANGE index
//! stays on the integer `field` id (the community filter/grouping access path).

use std::sync::Arc;

use graphus_core::Value;
use graphus_cypher::{
    CONSTRAINT_VIOLATION_PREFIX, IndexCatalog, MaterializedValue, PhysicalPlan, analyze, lower,
    parse_tokens, plan_physical, tokenize,
};
use graphus_gds_gen::{Dataset, Profile, generate};
use graphus_io::MemBlockDevice;
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
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 4096).expect("in-memory engine")
}

/// Whether `stmt` is a schema-DDL statement (any `CREATE CONSTRAINT` or any `CREATE … INDEX` form).
/// Kept byte-identical to the sibling `gds_analytics.rs` / `fraud_oltp_schema.rs` filter.
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
/// **every seed value conforms to every constraint** (`rmp` #679 acceptance).
fn load_schema_first() -> (Eng, Dataset) {
    let dataset = generate(Profile::Fast.config(), Profile::Fast.name());
    let script = dataset.to_cypher();
    let statements = split_statements(&script);

    let (ddl, data): (Vec<String>, Vec<String>) =
        statements.into_iter().partition(|s| is_schema_ddl(s));

    // The five schema statements this example declares: a UNIQUE, two `IS ::` property-type
    // constraints, a node RANGE index, and the relationship RANGE index.
    assert!(
        ddl.len() >= 5,
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

    // 2. Load the data with the schema active — every write is constraint-checked and index-maintained.
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

/// Compiles `src` into a physical plan against `catalog` (the real public planner pipeline — this is
/// the closest hermetic equivalent of `EXPLAIN`, since Graphus exposes no `EXPLAIN` query keyword).
fn plan(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let logical = lower(&validated);
    plan_physical(&logical, catalog)
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

/// Collects the single integer `id` column of a read query into a sorted, de-duplicated set.
fn collect_ids(eng: &mut Eng, query: &str) -> Vec<i64> {
    let ticket = eng.begin(AccessMode::Read).expect("begin read txn");
    let mut reply = eng
        .run(ticket, query, Vec::new(), false, None)
        .expect("query runs");
    let mut ids = Vec::new();
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
            ids.push(*n);
        }
    }
    eng.commit(ticket).expect("commit read txn");
    ids.sort_unstable();
    ids.dedup();
    ids
}

#[test]
fn schema_first_load_declares_constraints_and_indexes() {
    let (mut eng, _dataset) = load_schema_first();

    // ---- SHOW CONSTRAINTS: the node UNIQUE + the two node property-type constraints.
    let cons = show_constraints(&mut eng);
    let (ctype_c, centity_c, cprops_c, cptype_c) = (
        col(&cons, "type"),
        col(&cons, "entityType"),
        col(&cons, "properties"),
        col(&cons, "propertyType"),
    );

    let uniq = row_by_name(&cons, "author_id_unique");
    assert_eq!(
        uniq[ctype_c],
        Value::String("NODE_PROPERTY_UNIQUENESS".to_owned())
    );
    assert_eq!(uniq[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        uniq[cprops_c],
        Value::List(vec![Value::String("id".to_owned())])
    );

    // The STRING node property-type constraint — the campaign's first STRING property-type variant,
    // sitting on the *actual* string property `field_name` (the planted community label).
    let field_type = row_by_name(&cons, "author_field_name_string");
    assert_eq!(
        field_type[ctype_c],
        Value::String("NODE_PROPERTY_TYPE".to_owned())
    );
    assert_eq!(field_type[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        field_type[cprops_c],
        Value::List(vec![Value::String("field_name".to_owned())])
    );
    assert_eq!(
        field_type[cptype_c],
        Value::String("STRING".to_owned()),
        "the declared node property type of field_name is STRING"
    );

    // The INTEGER node property-type constraint on the h-index.
    let h_type = row_by_name(&cons, "author_h_index_integer");
    assert_eq!(
        h_type[ctype_c],
        Value::String("NODE_PROPERTY_TYPE".to_owned())
    );
    assert_eq!(h_type[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        h_type[cptype_c],
        Value::String("INTEGER".to_owned()),
        "the declared node property type of h_index is INTEGER (h_index is an i64)"
    );

    // ---- SHOW INDEXES: the node RANGE index on Author.field and the relationship RANGE index on
    //      CITES.weight, both Online.
    let idx = show_indexes(&mut eng);
    let (type_c, entity_c, labels_c, props_c, state_c) = (
        col(&idx, "type"),
        col(&idx, "entityType"),
        col(&idx, "labelsOrTypes"),
        col(&idx, "properties"),
        col(&idx, "state"),
    );

    let node_range = row_by_name(&idx, "author_field_range");
    assert_eq!(node_range[type_c], Value::String("RANGE".to_owned()));
    assert_eq!(node_range[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        node_range[labels_c],
        Value::List(vec![Value::String("Author".to_owned())])
    );
    assert_eq!(
        node_range[props_c],
        Value::List(vec![Value::String("field".to_owned())])
    );
    assert_eq!(node_range[state_c], Value::String("ONLINE".to_owned()));

    // The relationship RANGE index on CITES.weight — the headline addition (`rmp` #679).
    let rel_range = row_by_name(&idx, "cites_weight_range");
    assert_eq!(rel_range[type_c], Value::String("RANGE".to_owned()));
    assert_eq!(
        rel_range[entity_c],
        Value::String("RELATIONSHIP".to_owned()),
        "the CITES.weight index is a RELATIONSHIP index"
    );
    assert_eq!(
        rel_range[labels_c],
        Value::List(vec![Value::String("CITES".to_owned())])
    );
    assert_eq!(
        rel_range[props_c],
        Value::List(vec![Value::String("weight".to_owned())])
    );
    assert_eq!(
        rel_range[state_c],
        Value::String("ONLINE".to_owned()),
        "the relationship RANGE index must be Online after the schema-first load"
    );
}

#[test]
fn rel_range_index_serves_both_equality_and_range_predicates() {
    // The relationship RANGE index serves an EQUALITY predicate on the citation weight (a
    // `RelIndexSeek`, `rmp` #659) **and**, since `rmp` #680, a `>=` RANGE predicate (a
    // `RelIndexRangeSeek`) — the "influential citations" filter this example is built around, which used
    // to stay a full `ExpandAll` + `Filter` scan. Asserted on the real public planner against a catalog
    // that models exactly the schema's `cites_weight_range` index, then tied back to the engine: the
    // index is really Online, and an equality seek returns the seeded citations.
    let (mut eng, dataset) = load_schema_first();

    let catalog = IndexCatalog::builder()
        .with_rel_property("CITES", "weight")
        .build();

    // An equality predicate IS served by the relationship RANGE index.
    let eq_plan = plan(
        "MATCH ()-[c:CITES]->() WHERE c.weight = 5 RETURN c.weight",
        &catalog,
    );
    let eq_render = eq_plan.to_string();
    assert!(
        eq_render.contains("RelIndexSeek"),
        "an equality predicate must lower to a RelIndexSeek:\n{eq_render}"
    );
    assert_eq!(
        eq_plan.index_dependencies().count(),
        1,
        "the equality plan depends on exactly the relationship index:\n{eq_render}"
    );

    // ...and a `>=` RANGE predicate is served too (`rmp` #680), by the distinct `RelIndexRangeSeek`
    // operator, which REPLACES the `ExpandAll` scan subtree entirely.
    let ge_plan = plan(
        "MATCH ()-[c:CITES]->() WHERE c.weight >= 5 RETURN c.weight",
        &catalog,
    );
    let ge_render = ge_plan.to_string();
    assert!(
        ge_render.contains("RelIndexRangeSeek"),
        "a `>=` predicate must lower to a RelIndexRangeSeek:\n{ge_render}"
    );
    assert!(
        !ge_render.contains("ExpandAll"),
        "the seek replaces the ExpandAll scan subtree:\n{ge_render}"
    );
    assert_eq!(
        ge_plan.index_dependencies().count(),
        1,
        "the `>=` plan depends on exactly the relationship index:\n{ge_render}"
    );

    // Tie back to the engine: the relationship RANGE index really is Online, and — because a schema-
    // first-created index is maintained incrementally — an EQUALITY seek returns the seeded rows.
    {
        let idx = show_indexes(&mut eng);
        let state_c = col(&idx, "state");
        assert_eq!(
            row_by_name(&idx, "cites_weight_range")[state_c],
            Value::String("ONLINE".to_owned())
        );
    }

    // Pick a real intra-field (`:CITES`) citation weight (weights are drawn from `[1, 10]`).
    let cites_weight = dataset
        .citations
        .iter()
        .find(|c| c.intra)
        .map(|c| c.weight)
        .expect("the fast profile mints intra-field :CITES citations");
    let served = collect_ids(
        &mut eng,
        &format!(
            "MATCH (a:Author)-[c:CITES]->(:Author) WHERE c.weight = {cites_weight} RETURN a.id AS id"
        ),
    );
    assert!(
        !served.is_empty(),
        "the equality seek the rel index serves must return the seeded citation(s)"
    );

    // Cross-check the equality path against a ground-truth count derived from the dataset: the number
    // of DISTINCT citing authors that have at least one outgoing :CITES edge of this exact weight.
    let mut expected: Vec<i64> = dataset
        .citations
        .iter()
        .filter(|c| c.intra && c.weight == cites_weight)
        .map(|c| c.from)
        .collect();
    expected.sort_unstable();
    expected.dedup();
    assert_eq!(
        served, expected,
        "the equality seek must return exactly the citing authors with a :CITES edge of that weight"
    );
}

#[test]
fn schema_enforces_constraints_with_negative_writes() {
    let (mut eng, dataset) = load_schema_first();

    // An id well past every generated author + :Ref node, so the property-type negatives fail ONLY on
    // the type mismatch (never on uniqueness).
    let fresh_id = dataset.authors.len() as i64 + 1_000_000;

    // Node property-type (STRING): an Author with a non-string `field_name` is rejected.
    let bad_field = expect_rejected(
        &mut eng,
        &format!(
            "CREATE (:Author {{id: {fresh_id}, name: 'x', field: 0, field_name: 123, h_index: 5}})"
        ),
    );
    assert!(
        bad_field.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a non-string Author.field_name must be a constraint violation, got: {bad_field}"
    );

    // Node property-type (INTEGER): an Author with a non-integer `h_index` is rejected.
    let bad_h = expect_rejected(
        &mut eng,
        &format!(
            "CREATE (:Author {{id: {}, name: 'x', field: 0, field_name: 'graph-theory', h_index: 'high'}})",
            fresh_id + 1
        ),
    );
    assert!(
        bad_h.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a non-integer Author.h_index must be a constraint violation, got: {bad_h}"
    );

    // Node UNIQUE: a duplicate Author.id (0 exists by construction) is rejected.
    let dup = expect_rejected(
        &mut eng,
        "CREATE (:Author {id: 0, name: 'dup', field: 0, field_name: 'graph-theory', h_index: 5})",
    );
    assert!(
        dup.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a duplicate Author.id must be a constraint violation, got: {dup}"
    );

    // The rejected writes rolled back — the author count is unchanged from the load.
    let author_count = collect_ids(&mut eng, "MATCH (a:Author) RETURN count(a) AS id");
    assert_eq!(
        author_count,
        vec![dataset.authors.len() as i64],
        "the rejected writes created nothing"
    );
}
