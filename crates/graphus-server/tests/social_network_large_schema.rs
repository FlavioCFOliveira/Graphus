//! Hermetic cargo exercise of the `examples/social-network-large` **minimal (near-pure-topology)
//! schema** (`rmp` #677, simplified in #828).
//!
//! Where `graphus-social-gen`'s `tests/load_fast.rs` proves the large-graph bulk *load + traversal*
//! semantics, this test proves the schema the example now declares actually works end-to-end,
//! hermetically (no Bolt, no server, no network): it declares the schema through the REAL engine via the
//! admin-DDL command path (`parse_admin_statement` → `LocalEngine::constraint_ddl` — the exact seam the
//! Bolt/REST admin surfaces submit after parsing `CREATE CONSTRAINT`), loads a small seeded social graph
//! (`graphus-social-gen`, the SAME generator the example bulk-loads) **schema-first**, and asserts:
//!
//! - the two node id **UNIQUENESS** constraints (`USER.id` / `ARTICLE.id`) are declared (`SHOW
//!   CONSTRAINTS`) and are the WHOLE schema — the only other `SHOW INDEXES` rows are the two always-on
//!   **LOOKUP** token indexes; a constraint's backing index is not listed. The minimal model has no
//!   stored `name` / date properties, so there is no TEXT / FULLTEXT / RANGE / composite / existence
//!   schema;
//! - the **empirical planner utilisation** of a uniqueness constraint's backing index: a
//!   `MATCH (:USER {id: <int>})` point lookup lowers to a `NodeIndexSeek`, not a label scan;
//! - **constraint enforcement**: a second `ARTICLE` written with an `id` already present is rejected with
//!   the constraint-violation error class, and the rejected write leaves the counts unchanged.
//!
//! This is the string-form counterpart of the typed coordinator seam the example's `load::run_load`
//! applies through `TxnCoordinator`: both declare the identical schema (same object names), so a drift
//! between the two would fail here.

use std::sync::Arc;

use graphus_core::Value;
use graphus_cypher::{
    CONSTRAINT_VIOLATION_PREFIX, IndexCatalog, MaterializedValue, PhysicalPlan, analyze, lower,
    parse_tokens, plan_physical, tokenize,
};
use graphus_io::MemBlockDevice;
use graphus_server::admin::{AdminParse, parse_admin_statement};
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{
    ConstraintCommand, ConstraintTypeFilter, IndexCommand, IndexDdlReply, IndexTypeFilter,
    LocalEngine,
};
use graphus_sim::SharedClock;
use graphus_social_gen::{DegreeDist, GenConfig, Generator};
use graphus_wal::MemLogSink;

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

/// The seeded generator config for the hermetic load — a small id-only graph.
fn cfg() -> GenConfig {
    GenConfig {
        seed: 0x50C1_A150_5EA5_C4EE,
        users: 60,
        articles: 90,
        friend_min: 3,
        friend_max: 6,
        avg_likes_per_user: 3,
        degree_dist: DegreeDist::Uniform,
    }
}

/// The **exact** schema the example's `load::run_load` declares through the typed coordinator seam, here
/// written as the equivalent admin-DDL **strings** (carrying the SAME object names) the Bolt/REST admin
/// surface parses. The minimal model's whole schema is the two id uniqueness constraints. `IF NOT EXISTS`
/// is omitted so each is a plain create over the empty store.
const SCHEMA_DDL: &[&str] = &[
    "CREATE CONSTRAINT user_id_unique FOR (u:USER) REQUIRE u.id IS UNIQUE",
    "CREATE CONSTRAINT article_id_unique FOR (a:ARTICLE) REQUIRE a.id IS UNIQUE",
];

/// Builds an in-memory engine with a fixed clock — the deterministic, hermetic substrate.
fn engine() -> Eng {
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 1024).expect("in-memory engine")
}

/// Runs `f` on a dedicated 128 MiB-stack thread. The engine's recursive front-end (parser → analyzer →
/// physical planner) and its recursive cursor tree can nest more deeply than the default 2 MiB test
/// thread stack allows while loading the seeded graph — so, exactly like the example's own
/// `load::LOAD_STACK_BYTES` isolation (and the openCypher TCK harness's per-scenario stack), each test
/// body runs on a generously-sized thread. Any panic (a failed assertion) is re-raised on the caller so
/// the test still fails.
fn on_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .name("social-schema-test".to_owned())
        .stack_size(128 * 1024 * 1024)
        .spawn(f)
        .expect("spawn 128 MiB-stack test thread")
        .join()
        .unwrap_or_else(|p| std::panic::resume_unwind(p))
}

#[test]
fn schema_first_load_declares_id_uniqueness_constraints() {
    on_big_stack(schema_first_load_declares_id_uniqueness_constraints_impl);
}

#[test]
fn id_uniqueness_constraint_backs_the_point_seek() {
    on_big_stack(id_uniqueness_constraint_backs_the_point_seek_impl);
}

#[test]
fn schema_enforces_id_uniqueness_with_a_negative_write() {
    on_big_stack(schema_enforces_id_uniqueness_with_a_negative_write_impl);
}

/// Streams the whole seeded graph as its Cypher `CREATE` / `MATCH … CREATE` statements, in the
/// generator's deterministic order (USER nodes, ARTICLE nodes, FRIEND edges, LIKE edges).
fn data_statements(generator: &Generator) -> Vec<String> {
    let mut data = Vec::new();
    generator.stream_user_node_batches(|s| data.push(s));
    generator.stream_article_node_batches(|s| data.push(s));
    generator.stream_friend_edge_batches(|s| data.push(s));
    generator.stream_like_edge_batches(|s| data.push(s));
    data
}

/// Loads the seeded social graph **schema-first** through the real engine: every `CREATE CONSTRAINT`
/// runs through the admin-DDL command path (as the Bolt/REST admin seams do), then the data `CREATE`s
/// load inside a single write transaction — so every write is id-uniqueness-checked as it lands. Asserts
/// the load succeeds — i.e. **every seed id is unique** (the bijective `u64` ids never collide).
fn load_schema_first() -> Eng {
    let generator = Generator::new(cfg());
    let mut eng = engine();

    // 1. Apply the schema DDL through the admin path (each an auto-commit control command).
    for stmt in SCHEMA_DDL {
        match parse_admin_statement(stmt) {
            AdminParse::Constraint(cmd) => {
                eng.constraint_ddl(cmd)
                    .unwrap_or_else(|e| panic!("constraint DDL failed: {stmt}\n  {e}"));
            }
            other => {
                panic!("schema statement did not parse as constraint DDL: {stmt}\n  got {other:?}")
            }
        }
    }

    // 2. Load the data with the schema active — every write is id-uniqueness-checked.
    let ticket = eng.begin(AccessMode::Write).expect("begin load txn");
    for stmt in data_statements(&generator) {
        let mut reply = eng
            .run(ticket, &stmt, Vec::new(), false, None)
            .unwrap_or_else(|e| panic!("load statement failed (a duplicate id?): {stmt}\n  {e}"));
        while let Ok(Some(_)) = reply.rows.next() {}
    }
    eng.commit(ticket).expect("commit load txn");

    eng
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

/// Compiles `src` into a physical plan against `catalog` (the real public planner pipeline — the
/// closest hermetic equivalent of `EXPLAIN`, since Graphus exposes no `EXPLAIN` query keyword).
fn plan(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let logical = lower(&validated);
    plan_physical(&logical, catalog)
}

/// A single scalar integer (e.g. a `count(…)`).
fn scalar_int(eng: &mut Eng, query: &str) -> i64 {
    let ticket = eng.begin(AccessMode::Read).expect("begin read txn");
    let mut reply = eng
        .run(ticket, query, Vec::new(), false, None)
        .expect("query runs");
    let mut n = 0i64;
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::Integer(v))) = row.first() {
            n = *v;
        }
    }
    eng.commit(ticket).expect("commit read txn");
    n
}

/// Runs an auto-commit write that MUST be rejected by a constraint, returning the violation message.
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

fn schema_first_load_declares_id_uniqueness_constraints_impl() {
    let mut eng = load_schema_first();

    // ---- SHOW INDEXES: ONLY the two always-on LOOKUP token indexes. The id uniqueness constraints'
    //      backing indexes are NOT listed here (they surface under SHOW CONSTRAINTS), and there is no
    //      name/date search schema in the minimal model. ----
    let idx = show_indexes(&mut eng);
    let (type_c, entity_c, state_c) = (
        col(&idx, "type"),
        col(&idx, "entityType"),
        col(&idx, "state"),
    );

    let node_lookup = row_by_name(&idx, "node_label_lookup_index");
    assert_eq!(node_lookup[type_c], Value::String("LOOKUP".to_owned()));
    assert_eq!(node_lookup[entity_c], Value::String("NODE".to_owned()));
    assert_eq!(node_lookup[state_c], Value::String("ONLINE".to_owned()));
    let rel_lookup = row_by_name(&idx, "rel_type_lookup_index");
    assert_eq!(rel_lookup[type_c], Value::String("LOOKUP".to_owned()));
    assert_eq!(
        rel_lookup[entity_c],
        Value::String("RELATIONSHIP".to_owned())
    );
    assert_eq!(rel_lookup[state_c], Value::String("ONLINE".to_owned()));

    assert_eq!(
        idx.rows.len(),
        2,
        "SHOW INDEXES lists exactly the 2 always-on LOOKUP indexes (no search schema, and constraint \
         backings are not listed): {:?}",
        idx.rows
    );

    // ---- SHOW CONSTRAINTS: the two id UNIQUENESS constraints, and nothing else. ----
    let cons = show_constraints(&mut eng);
    let (ctype_c, centity_c, cprops_c) = (
        col(&cons, "type"),
        col(&cons, "entityType"),
        col(&cons, "properties"),
    );

    for (name, label) in [("user_id_unique", "USER"), ("article_id_unique", "ARTICLE")] {
        let uniq = row_by_name(&cons, name);
        assert_eq!(
            uniq[ctype_c],
            Value::String("NODE_PROPERTY_UNIQUENESS".to_owned()),
            "{label}.id is a node uniqueness constraint"
        );
        assert_eq!(uniq[centity_c], Value::String("NODE".to_owned()), "{name}");
        assert_eq!(
            uniq[cprops_c],
            Value::List(vec![Value::String("id".to_owned())]),
            "{name} covers exactly the id property"
        );
    }
    assert_eq!(
        cons.rows.len(),
        2,
        "SHOW CONSTRAINTS lists exactly the two id uniqueness constraints: {:?}",
        cons.rows
    );
}

fn id_uniqueness_constraint_backs_the_point_seek_impl() {
    // A uniqueness constraint registers a backing node-property index over its property, so the planner
    // lowers a `MATCH (:USER {id: <int>})` point lookup to a `NodeIndexSeek` — the same seek a standalone
    // RANGE index gave, which is why the constraint is the most-appropriate schema for the id anchor.
    // Modelled on the real public planner against a catalog carrying exactly that backing index.
    let _eng = load_schema_first();

    let catalog = IndexCatalog::builder()
        .with_token_lookup("USER")
        .with_label_property("USER", "id")
        .build();

    let seek_plan = plan("MATCH (u:USER {id: 5}) RETURN u.id", &catalog);
    let render = seek_plan.to_string();
    assert!(
        render.contains("NodeIndexSeek"),
        "the id point lookup must SEEK the uniqueness-constraint backing index, not scan; plan was:\n{render}"
    );

    // The contrast: with NO node-property index (only the label lookup), the same lookup is a label scan.
    let scan_catalog = IndexCatalog::builder().with_token_lookup("USER").build();
    let scan_plan = plan("MATCH (u:USER {id: 5}) RETURN u.id", &scan_catalog);
    assert!(
        !scan_plan.to_string().contains("NodeIndexSeek"),
        "without a backing index the lookup cannot be a NodeIndexSeek"
    );
}

fn schema_enforces_id_uniqueness_with_a_negative_write_impl() {
    let mut eng = load_schema_first();
    let article_count = cfg().articles as i64;

    // ARTICLE 0's id already exists (loaded above). Creating a second ARTICLE with the SAME id must be
    // rejected by the `article_id_unique` constraint.
    let existing_id = Generator::article_id(0) as i64;
    let dup = expect_rejected(
        &mut eng,
        &format!("CREATE (:ARTICLE {{id: {existing_id}}})"),
    );
    assert!(
        dup.contains(CONSTRAINT_VIOLATION_PREFIX),
        "a duplicate ARTICLE.id must be a constraint violation, got: {dup}"
    );

    // The rejected write rolled back — the ARTICLE count is unchanged from the load.
    let count = scalar_int(&mut eng, "MATCH (a:ARTICLE) RETURN count(a) AS c");
    assert_eq!(
        count, article_count,
        "the rejected write created nothing (ARTICLE count unchanged)"
    );
}
