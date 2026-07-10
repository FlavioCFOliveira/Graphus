//! Hermetic cargo exercise of the `examples/fraud-oltp` **schema** (`rmp` #673).
//!
//! Where `fraud_oltp_detection.rs` proves the detection *semantics* over a data-only load, this test
//! proves the production-realistic **schema** the example now declares actually works end-to-end,
//! hermetically (no Bolt, no Node, no network): it takes the DDL block `graphus-fraud-gen`'s
//! `to_cypher()` emits, drives it through the REAL engine via the admin-DDL command path
//! (`parse_admin_statement` → `LocalEngine::{index_ddl, constraint_ddl}` — the exact seam the Bolt/REST
//! admin surfaces submit after parsing `CREATE INDEX` / `CREATE CONSTRAINT`), loads the seeded graph
//! **schema-first**, and asserts:
//!
//! - the new index & constraint kinds are declared and `Online` (`SHOW INDEXES` / `SHOW CONSTRAINTS`):
//!   a relationship `RANGE` index on `TRANSFER.amount`, a `TEXT` index on `Customer.name`, the node
//!   `RANGE` indexes, a `NODE KEY`, a node `UNIQUE`, and the two relationship constraints;
//! - the **empirical planner utilisation** of the relationship `RANGE` index: Graphus serves an
//!   *equality* predicate on a relationship property from it (a `RelIndexSeek`) but **not** a `>=`
//!   range predicate (that stays a scan + filter) — asserted honestly on the real planner;
//! - **constraint enforcement**: a duplicate `Account.id`, a null-`amount` `TRANSFER`, and a
//!   non-integer `amount` `TRANSFER` are each rejected with the constraint-violation error class;
//! - the **TEXT** index path: `WHERE c.name CONTAINS '…'` returns exactly the expected customers.
//!
//! Determining the substrate empirically (`rmp` #673 asked): `LocalEngine::run` does **not** accept
//! DDL strings (admin DDL is intercepted before the Cypher pipeline), but `LocalEngine` fully supports
//! admin DDL through its typed `index_ddl` / `constraint_ddl` methods — so the whole exercise runs
//! in-process against the real coordinator, no booted server required.

use std::sync::Arc;

use graphus_core::Value;
use graphus_cypher::{
    CONSTRAINT_VIOLATION_PREFIX, IndexCatalog, MaterializedValue, PhysicalPlan, analyze, lower,
    parse_tokens, plan_physical, tokenize,
};
use graphus_fraud_gen::{Dataset, Profile, generate};
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

// The RING detection query, byte-identical to `data/detect.js` / `fraud_oltp_detection.rs`: the `>=`
// amount floor is exactly the relationship-property predicate the rel RANGE index would optimise.
const RING_QUERY: &str = "\
MATCH (a:Account)-[r1:TRANSFER]->(b:Account)-[r2:TRANSFER]->(c:Account)-[r3:TRANSFER]->(a)
WHERE r1.amount >= 9000 AND r2.amount >= 9000 AND r3.amount >= 9000
  AND a.id <> b.id AND b.id <> c.id AND a.id <> c.id
RETURN DISTINCT a.id AS id ORDER BY id";

/// Builds an in-memory engine with a fixed clock — the deterministic, hermetic substrate.
fn engine() -> Eng {
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 1024).expect("in-memory engine")
}

/// Whether `stmt` is a schema-DDL statement (any `CREATE CONSTRAINT` or any `CREATE … INDEX` form).
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
/// **every seed value conforms to every constraint** (`rmp` #673 acceptance).
fn load_schema_first() -> (Eng, Dataset) {
    let dataset = generate(Profile::Fast.config(), Profile::Fast.name());
    let script = dataset.to_cypher();
    let statements = split_statements(&script);

    let (ddl, data): (Vec<String>, Vec<String>) =
        statements.into_iter().partition(|s| is_schema_ddl(s));

    // At least the eight schema statements this example declares.
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
fn schema_first_load_declares_new_index_and_constraint_kinds() {
    let (mut eng, _dataset) = load_schema_first();

    // ---- SHOW INDEXES: the new relationship-RANGE + TEXT indexes and the node RANGE indexes, Online.
    let idx = show_indexes(&mut eng);
    let (type_c, entity_c, labels_c, props_c, state_c) = (
        col(&idx, "type"),
        col(&idx, "entityType"),
        col(&idx, "labelsOrTypes"),
        col(&idx, "properties"),
        col(&idx, "state"),
    );

    // Relationship RANGE index on TRANSFER.amount — the headline production optimisation.
    let rel_range = row_by_name(&idx, "transfer_amount_range");
    assert_eq!(rel_range[type_c], Value::String("RANGE".to_owned()));
    assert_eq!(
        rel_range[entity_c],
        Value::String("RELATIONSHIP".to_owned()),
        "the TRANSFER.amount index is a RELATIONSHIP index"
    );
    assert_eq!(
        rel_range[labels_c],
        Value::List(vec![Value::String("TRANSFER".to_owned())])
    );
    assert_eq!(
        rel_range[props_c],
        Value::List(vec![Value::String("amount".to_owned())])
    );
    assert_eq!(
        rel_range[state_c],
        Value::String("ONLINE".to_owned()),
        "the relationship RANGE index must be Online after the schema-first load"
    );

    // TEXT (trigram) index on Customer.name.
    let text = row_by_name(&idx, "customer_name_text");
    assert_eq!(
        text[type_c],
        Value::String("TEXT".to_owned()),
        "TEXT is a distinct native string index, not a RANGE synonym"
    );
    assert_eq!(text[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        text[props_c],
        Value::List(vec![Value::String("name".to_owned())])
    );
    assert_eq!(text[state_c], Value::String("ONLINE".to_owned()));

    // The two node RANGE indexes are still present and Online.
    for name in ["account_risk_score_range", "customer_country_range"] {
        let r = row_by_name(&idx, name);
        assert_eq!(r[type_c], Value::String("RANGE".to_owned()), "{name}");
        assert_eq!(r[entity_c], Value::String("NODE".to_owned()), "{name}");
        assert_eq!(r[state_c], Value::String("ONLINE".to_owned()), "{name}");
    }

    // ---- SHOW CONSTRAINTS: the NODE KEY, the node UNIQUE, and the two relationship constraints.
    let cons = show_constraints(&mut eng);
    let (ctype_c, centity_c, cprops_c, cptype_c) = (
        col(&cons, "type"),
        col(&cons, "entityType"),
        col(&cons, "properties"),
        col(&cons, "propertyType"),
    );

    let key = row_by_name(&cons, "account_id_key");
    assert_eq!(key[ctype_c], Value::String("NODE_KEY".to_owned()));
    assert_eq!(key[centity_c], Value::String("NODE".to_owned()));
    assert_eq!(
        key[cprops_c],
        Value::List(vec![Value::String("id".to_owned())])
    );

    let uniq = row_by_name(&cons, "customer_id_unique");
    assert_eq!(
        uniq[ctype_c],
        Value::String("NODE_PROPERTY_UNIQUENESS".to_owned())
    );

    let rel_exists = row_by_name(&cons, "transfer_amount_exists");
    assert_eq!(
        rel_exists[ctype_c],
        Value::String("RELATIONSHIP_PROPERTY_EXISTENCE".to_owned())
    );
    assert_eq!(
        rel_exists[centity_c],
        Value::String("RELATIONSHIP".to_owned())
    );

    let rel_type = row_by_name(&cons, "transfer_amount_integer");
    assert_eq!(
        rel_type[ctype_c],
        Value::String("RELATIONSHIP_PROPERTY_TYPE".to_owned())
    );
    assert_eq!(
        rel_type[centity_c],
        Value::String("RELATIONSHIP".to_owned())
    );
    assert_eq!(
        rel_type[cptype_c],
        Value::String("INTEGER".to_owned()),
        "the declared relationship property type is INTEGER (amount is an i64, never a FLOAT)"
    );
}

#[test]
fn rel_range_index_serves_equality_but_not_range_predicates() {
    // The honest empirical planner finding (`rmp` #673): Graphus's relationship RANGE index serves an
    // EQUALITY predicate on a relationship property (a `RelIndexSeek`) but NOT a `>=` range predicate
    // (which stays a full `ExpandAll` + `Filter` scan). We assert on the real public planner against a
    // catalog that models exactly the schema's `transfer_amount_range` index, then tie it back to the
    // engine: the index is really Online, and the `>=` detection query still returns the correct fraud.
    let (mut eng, dataset) = load_schema_first();

    let catalog = IndexCatalog::builder()
        .with_rel_property("TRANSFER", "amount")
        .build();

    // An equality predicate IS served by the relationship RANGE index.
    let eq_plan = plan(
        "MATCH ()-[t:TRANSFER]->() WHERE t.amount = 9000 RETURN t.amount",
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

    // A `>=` range predicate is NOT served — it stays a scan + filter (no index dependency).
    let ge_plan = plan(
        "MATCH ()-[t:TRANSFER]->() WHERE t.amount >= 9000 RETURN t.amount",
        &catalog,
    );
    let ge_render = ge_plan.to_string();
    assert!(
        !ge_render.contains("RelIndexSeek"),
        "a `>=` predicate is NOT served by the rel RANGE index (equality-only):\n{ge_render}"
    );
    assert!(
        ge_render.contains("Filter") && ge_render.contains("ExpandAll"),
        "the `>=` predicate is a scan + residual filter:\n{ge_render}"
    );
    assert_eq!(
        ge_plan.index_dependencies().count(),
        0,
        "the `>=` plan uses no index:\n{ge_render}"
    );

    // The actual RING detection query (all `>=`) likewise uses no relationship index.
    let ring_plan = plan(RING_QUERY, &catalog);
    assert_eq!(
        ring_plan.index_dependencies().count(),
        0,
        "the ring detection query uses no relationship index (its predicates are all `>=`)"
    );

    // Tie back to the engine: the relationship RANGE index really is Online, and — because a schema-
    // first-created index is maintained incrementally — an EQUALITY seek returns the seeded rows.
    {
        let idx = show_indexes(&mut eng);
        let state_c = col(&idx, "state");
        assert_eq!(
            row_by_name(&idx, "transfer_amount_range")[state_c],
            Value::String("ONLINE".to_owned())
        );
    }

    // Pick a real ring-edge amount (a planted `>= 9000` layering transfer exists by construction).
    let ring_amount = dataset
        .transfers
        .iter()
        .map(|t| t.amount)
        .find(|&a| a >= 9000)
        .expect("a ring/layering transfer with amount >= 9000 exists");
    let served = collect_ids(
        &mut eng,
        &format!(
            "MATCH (a:Account)-[t:TRANSFER]->(:Account) WHERE t.amount = {ring_amount} RETURN a.id AS id"
        ),
    );
    assert!(
        !served.is_empty(),
        "the equality seek the rel index serves must return the seeded transfer(s)"
    );

    // And the `>=` detection query — though scanned, not indexed — still finds exactly the planted rings.
    let ring_ids = collect_ids(&mut eng, RING_QUERY);
    let mut gt_rings: Vec<i64> = dataset
        .ground_truth
        .rings
        .iter()
        .flat_map(|r| r.accounts.clone())
        .collect();
    gt_rings.sort_unstable();
    gt_rings.dedup();
    assert_eq!(
        ring_ids, gt_rings,
        "the `>=` ring detection returns exactly the planted rings, indexed or not"
    );
}

#[test]
fn schema_enforces_constraints_with_negative_writes() {
    let (mut eng, dataset) = load_schema_first();

    // A conforming account id (0) exists; two conforming accounts (0, 1) exist to attach a rel to.
    assert!(dataset.accounts.len() > 2, "need at least two accounts");

    // NODE KEY (uniqueness half): a duplicate Account.id is rejected.
    let dup = expect_rejected(
        &mut eng,
        "CREATE (:Account {id: 0, holder: 0, balance: 1, risk_score: 1, opened_ts: 1, country: 'PT'})",
    );
    assert!(
        dup.contains(CONSTRAINT_VIOLATION_PREFIX),
        "duplicate Account.id must be a constraint violation, got: {dup}"
    );

    // Relationship existence: a TRANSFER without `amount` is rejected.
    let missing = expect_rejected(
        &mut eng,
        "MATCH (a:Account {id: 0}), (b:Account {id: 1}) CREATE (a)-[:TRANSFER {ts: 1, device: 1, ip: '10.0.0.1'}]->(b)",
    );
    assert!(
        missing.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a null/missing TRANSFER.amount must be a constraint violation, got: {missing}"
    );

    // Relationship property-type: a non-integer `amount` is rejected.
    let wrong_type = expect_rejected(
        &mut eng,
        "MATCH (a:Account {id: 0}), (b:Account {id: 1}) CREATE (a)-[:TRANSFER {amount: 'lots', ts: 1, device: 1, ip: '10.0.0.1'}]->(b)",
    );
    assert!(
        wrong_type.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a non-integer TRANSFER.amount must be a constraint violation, got: {wrong_type}"
    );

    // The rejected writes rolled back — the account/transfer counts are unchanged from the load.
    let account_count = collect_ids(&mut eng, "MATCH (a:Account) RETURN count(a) AS id");
    assert_eq!(
        account_count,
        vec![dataset.accounts.len() as i64],
        "the rejected duplicate created nothing"
    );
}

#[test]
fn text_index_contains_returns_expected_customers() {
    let (mut eng, dataset) = load_schema_first();

    // A substring that matches many customer names (`customer-1`, `customer-10…`, `customer-1xx`),
    // deriving the expected id set deterministically from the generated dataset — a real investigator
    // "find every holder whose name contains …" query the TEXT index accelerates.
    let substr = "customer-1";
    let mut expected: Vec<i64> = dataset
        .customers
        .iter()
        .filter(|c| c.name.contains(substr))
        .map(|c| c.id)
        .collect();
    expected.sort_unstable();
    expected.dedup();
    assert!(
        expected.len() > 1,
        "the substring must match multiple customers to exercise CONTAINS (not just equality)"
    );

    let got = collect_ids(
        &mut eng,
        &format!("MATCH (c:Customer) WHERE c.name CONTAINS '{substr}' RETURN c.id AS id"),
    );
    assert_eq!(
        got, expected,
        "CONTAINS over the TEXT-indexed customer name must return exactly the expected holders"
    );

    // A full-name CONTAINS resolves the single flagged holder for a known fraud (mule) account —
    // the "look up the flagged account holder by name" step.
    let mule = dataset.ground_truth.mules[0].mule;
    let full_name = format!("customer-{mule}");
    let flagged = collect_ids(
        &mut eng,
        &format!("MATCH (c:Customer) WHERE c.name CONTAINS '{full_name}' RETURN c.id AS id"),
    );
    assert!(
        flagged.contains(&mule),
        "the mule's holder (name {full_name}) must be found by CONTAINS"
    );
}
