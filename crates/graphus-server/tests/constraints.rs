//! End-to-end constraint tests over a **real booted server** (`rmp` task #99).
//!
//! Each test boots the server in-process over a fresh tempdir data root (UDS-only listener), seeds
//! nodes through the normal query path, declares constraints through the constraint-DDL command path
//! (the same [`ConstraintCommand`] the Bolt/REST admin seams submit after parsing
//! `CREATE CONSTRAINT …`), then exercises write-time enforcement and durability. This is the capstone
//! proof of the acceptance criteria against the real storage backend:
//!
//! - **uniqueness** is enforced on `CREATE`/`SET`/`MERGE` (a duplicate is rejected with the
//!   constraint-validation error class; a conforming write succeeds);
//! - **existence** (`NOT NULL`) is enforced (a `CREATE`/`SET` that omits or nulls the property is
//!   rejected);
//! - **creation-time validation** rejects a constraint over non-conforming existing data, succeeds
//!   over conforming data;
//! - `SHOW CONSTRAINTS` lists the declared constraints;
//! - the constraints **survive a full server restart** and still enforce;
//! - `DROP CONSTRAINT` removes enforcement.

use std::path::PathBuf;

use graphus_core::{GraphusError, Value};
use graphus_cypher::{CONSTRAINT_VIOLATION_PREFIX, MaterializedValue};
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::engine::{
    AccessMode, ConstraintCommand, ConstraintCreateKind, ConstraintEntity, ConstraintTypeFilter,
    CreateConstraint, EngineHandle, IndexDdlReply,
};
use graphus_server::{Server, ServerHandle};

struct TempStore {
    path: PathBuf,
}

impl TempStore {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        path.push(format!(
            "graphus-constraints-{tag}-{nanos}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn store_dir(&self) -> PathBuf {
        self.path.join("store")
    }

    fn uds_path(&self) -> PathBuf {
        self.path.join("graphus.sock")
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.store_dir(),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        bolt_server_agent: None,
        bolt_max_protocol_minor: None,
        rest_addr: None,
        uds_path: Some(temp.uds_path()),
        tls: TlsConfig::default(),
        admission: AdmissionConfig {
            max_concurrent_queries: 64,
            engine_queue_capacity: 256,
            result_buffer_capacity: 64,
            ..AdmissionConfig::default()
        },
        timing: TimingConfig {
            slow_query_threshold_ms: 1_000,
            shutdown_drain_deadline_ms: 5_000,
            ..TimingConfig::default()
        },
        jwt_secret: "constraints-itest-jwt-secret-uds-only!".to_owned(),
        auth: AuthBootstrap {
            admin_user: "alice".to_owned(),
            admin_password: "admin-pw8".to_owned(),
            admin_uid: None,
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: graphus_server::AuditConfig::default(),
        allow_insecure_network: false,
        bulk_import: graphus_server::config::BulkImportConfig::default(),
        metrics_scrape_token: None,
    }
}

async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config).start().await.expect("server boots")
}

/// Runs one auto-commit statement, returning its rows or the first runtime/compile error. A
/// constraint violation surfaces as a runtime error here (either before the first row, or as a
/// mid-stream terminal item — both are returned as `Err`).
async fn try_run(
    handle: &EngineHandle,
    query: &str,
) -> Result<Vec<Vec<MaterializedValue>>, GraphusError> {
    let ticket = handle
        .begin_auto_commit(AccessMode::Write)
        .await
        .expect("begin auto-commit");
    let reply = match handle
        .run(ticket, query.to_owned(), Vec::new(), true, None, None)
        .await
    {
        Ok(reply) => reply,
        Err(e) => return Err(e),
    };
    tokio::task::spawn_blocking(move || {
        let mut rx = reply.rows;
        let mut rows = Vec::new();
        loop {
            match rx.next() {
                Ok(Some(row)) => rows.push(row),
                Ok(None) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(rows)
    })
    .await
    .expect("drain")
}

/// Runs a statement that must succeed, returning its rows.
async fn run(handle: &EngineHandle, query: &str) -> Vec<Vec<MaterializedValue>> {
    try_run(handle, query)
        .await
        .unwrap_or_else(|e| panic!("query {query:?} must succeed, got: {e}"))
}

/// Asserts an error is a constraint violation. The constraint-validation error class is surfaced on
/// the Bolt wire as `Neo.ClientError.Schema.ConstraintValidationFailed`; at the engine boundary the
/// message carries the [`CONSTRAINT_VIOLATION_PREFIX`] sentinel that drives that classification.
fn assert_constraint_violation(e: &GraphusError) {
    let s = e.to_string();
    assert!(
        s.contains(CONSTRAINT_VIOLATION_PREFIX),
        "expected a constraint-violation error, got: {s}"
    );
}

/// The number of `Person` nodes currently visible.
async fn person_count(handle: &EngineHandle) -> i64 {
    let rows = run(handle, "MATCH (n:Person) RETURN count(n) AS c").await;
    match &rows[0][0] {
        MaterializedValue::Value(Value::Integer(i)) => *i,
        other => panic!("expected an integer count, got {other:?}"),
    }
}

/// Builds a node `CREATE CONSTRAINT` command (`rmp` #638 unified shape) with idempotency flags off.
fn node_create(
    name: &str,
    label: &str,
    properties: &[&str],
    kind: ConstraintCreateKind,
) -> ConstraintCommand {
    ConstraintCommand::Create(CreateConstraint {
        name: name.to_owned(),
        entity: ConstraintEntity::Node {
            label: label.to_owned(),
        },
        properties: properties.iter().map(|p| (*p).to_owned()).collect(),
        kind,
        if_not_exists: false,
        or_replace: false,
    })
}

/// Builds a **relationship** `CREATE CONSTRAINT` command (`rmp` #638 unified shape).
fn rel_create(
    name: &str,
    rel_type: &str,
    properties: &[&str],
    kind: ConstraintCreateKind,
) -> ConstraintCommand {
    ConstraintCommand::Create(CreateConstraint {
        name: name.to_owned(),
        entity: ConstraintEntity::Relationship {
            rel_type: rel_type.to_owned(),
        },
        properties: properties.iter().map(|p| (*p).to_owned()).collect(),
        kind,
        if_not_exists: false,
        or_replace: false,
    })
}

fn create_unique(name: &str, label: &str, property: &str) -> ConstraintCommand {
    node_create(name, label, &[property], ConstraintCreateKind::Unique)
}

fn create_existence(name: &str, label: &str, property: &str) -> ConstraintCommand {
    node_create(name, label, &[property], ConstraintCreateKind::Existence)
}

fn create_node_key(name: &str, label: &str, properties: &[&str]) -> ConstraintCommand {
    node_create(name, label, properties, ConstraintCreateKind::Key)
}

fn create_property_type(
    name: &str,
    label: &str,
    property: &str,
    declared_type: graphus_storage::ConstraintTypeDescriptor,
) -> ConstraintCommand {
    node_create(
        name,
        label,
        &[property],
        ConstraintCreateKind::PropertyType { declared_type },
    )
}

/// Runs `SHOW CONSTRAINTS` directly against the engine (bypassing the seam), so it yields the FULL
/// 10-column set (`id, name, type, entityType, labelsOrTypes, properties, ownedIndex, propertyType,
/// options, createStatement` — the `YIELD *` shape). A real client's bare `SHOW CONSTRAINTS` sees the
/// 8 default columns (the seam projects them); the tail translation is exercised over Bolt in
/// `db_admin_surface.rs`.
async fn show_constraints(handle: &EngineHandle) -> IndexDdlReply {
    handle
        .constraint_ddl(
            ConstraintCommand::Show {
                filter: ConstraintTypeFilter::All,
                tail: None,
            },
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("show constraints")
}

/// The same, but restricted to a constraint-kind filter (`rmp` #653).
async fn show_constraints_filtered(
    handle: &EngineHandle,
    filter: ConstraintTypeFilter,
) -> IndexDdlReply {
    handle
        .constraint_ddl(
            ConstraintCommand::Show { filter, tail: None },
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("show constraints (filtered)")
}

#[tokio::test]
async fn uniqueness_enforced_on_create_set_and_merge() {
    let temp = TempStore::new("uniqueness");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(&engine, "CREATE (:Person {email: 'a@x.com', name: 'A'})").await;
    engine
        .constraint_ddl(
            create_unique("uniq_email", "Person", "email"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create uniqueness constraint over conforming data");

    // A duplicate CREATE is rejected and creates nothing.
    let err = try_run(&engine, "CREATE (:Person {email: 'a@x.com', name: 'B'})")
        .await
        .expect_err("duplicate CREATE must be rejected");
    assert_constraint_violation(&err);
    assert_eq!(person_count(&engine).await, 1);

    // A conforming CREATE succeeds.
    run(&engine, "CREATE (:Person {email: 'b@x.com', name: 'B'})").await;
    assert_eq!(person_count(&engine).await, 2);

    // A SET that collides is rejected.
    let err = try_run(
        &engine,
        "MATCH (n:Person {email: 'b@x.com'}) SET n.email = 'a@x.com'",
    )
    .await
    .expect_err("SET to a duplicate must be rejected");
    assert_constraint_violation(&err);

    // A MERGE whose full pattern matches no node CREATEs a new one; if that new node's constrained
    // property collides, it is rejected. The pattern `{name: 'New', email: 'a@x.com'}` matches no
    // existing node (none has name 'New'), so MERGE CREATEs a node whose email duplicates 'A'.
    let err = try_run(&engine, "MERGE (:Person {name: 'New', email: 'a@x.com'})")
        .await
        .expect_err("MERGE creating a duplicate must be rejected");
    assert_constraint_violation(&err);

    // A MERGE whose pattern matches the existing node creates nothing, so it succeeds.
    run(&engine, "MERGE (:Person {email: 'a@x.com', name: 'A'})").await;
    assert_eq!(
        person_count(&engine).await,
        2,
        "MERGE matched, created nothing"
    );

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn existence_enforced_on_create_and_set() {
    let temp = TempStore::new("existence");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(&engine, "CREATE (:Person {name: 'A'})").await;
    engine
        .constraint_ddl(
            create_existence("name_exists", "Person", "name"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create existence constraint over conforming data");

    // A CREATE that omits the required property is rejected.
    let err = try_run(&engine, "CREATE (:Person {email: 'x'})")
        .await
        .expect_err("missing required property must be rejected");
    assert_constraint_violation(&err);

    // A CREATE that nulls the required property is rejected.
    let err = try_run(&engine, "CREATE (:Person {name: null})")
        .await
        .expect_err("null required property must be rejected");
    assert_constraint_violation(&err);

    // A SET that removes the required property is rejected.
    let err = try_run(&engine, "MATCH (n:Person {name: 'A'}) SET n.name = null")
        .await
        .expect_err("removing a required property must be rejected");
    assert_constraint_violation(&err);

    // A conforming CREATE succeeds.
    run(&engine, "CREATE (:Person {name: 'B'})").await;
    assert_eq!(person_count(&engine).await, 2);

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn creation_time_validation_rejects_nonconforming_data() {
    let temp = TempStore::new("createvalidate");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // Two Person nodes with the same email: a uniqueness constraint cannot be created.
    run(&engine, "CREATE (:Person {email: 'dup@x.com'})").await;
    run(&engine, "CREATE (:Person {email: 'dup@x.com'})").await;
    let err = engine
        .constraint_ddl(
            create_unique("uniq_email", "Person", "email"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect_err("uniqueness over duplicate data must be rejected");
    assert_constraint_violation(&err);
    // The failed creation declared nothing.
    assert_eq!(show_constraints(&engine).await.rows.len(), 0);

    // A Person without `name`: an existence constraint cannot be created.
    run(&engine, "CREATE (:Person {email: 'noname@x.com'})").await;
    let err = engine
        .constraint_ddl(
            create_existence("name_exists", "Person", "name"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect_err("existence over data missing the property must be rejected");
    assert_constraint_violation(&err);
    assert_eq!(show_constraints(&engine).await.rows.len(), 0);

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn show_constraints_lists_declared_constraints() {
    let temp = TempStore::new("show");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    engine
        .constraint_ddl(
            create_unique("uniq_email", "Person", "email"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create unique");
    engine
        .constraint_ddl(
            create_existence("name_exists", "Person", "name"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create existence");

    let reply = show_constraints(&engine).await;
    // The full 10-column YIELD-* shape (`rmp` #653), in order.
    assert_eq!(
        reply.fields,
        vec![
            "id".to_owned(),
            "name".to_owned(),
            "type".to_owned(),
            "entityType".to_owned(),
            "labelsOrTypes".to_owned(),
            "properties".to_owned(),
            "ownedIndex".to_owned(),
            "propertyType".to_owned(),
            "options".to_owned(),
            "createStatement".to_owned(),
        ]
    );
    assert_eq!(reply.rows.len(), 2);
    // Rows are ordered by name: name_exists, uniq_email.
    // Columns: [id, name, type, entityType, labelsOrTypes, properties, ownedIndex, propertyType, ...].
    assert_eq!(reply.rows[0][1], Value::String("name_exists".to_owned()));
    assert_eq!(
        reply.rows[0][2],
        Value::String("NODE_PROPERTY_EXISTENCE".to_owned())
    );
    assert_eq!(reply.rows[0][3], Value::String("NODE".to_owned()));
    assert_eq!(
        reply.rows[0][4],
        Value::List(vec![Value::String("Person".to_owned())]),
        "labelsOrTypes is a single-element list"
    );
    assert_eq!(
        reply.rows[0][5],
        Value::List(vec![Value::String("name".to_owned())]),
        "properties is a list"
    );
    assert_eq!(reply.rows[0][6], Value::Null, "existence owns no index");
    assert_eq!(reply.rows[1][1], Value::String("uniq_email".to_owned()));
    assert_eq!(
        reply.rows[1][2],
        Value::String("NODE_PROPERTY_UNIQUENESS".to_owned())
    );
    assert_eq!(
        reply.rows[1][6],
        Value::String("uniq_email".to_owned()),
        "a uniqueness constraint owns its backing index"
    );
    // `id` is a stable non-negative integer.
    assert!(matches!(reply.rows[0][0], Value::Integer(n) if n >= 0));

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn drop_constraint_removes_enforcement() {
    let temp = TempStore::new("drop");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(&engine, "CREATE (:Person {email: 'a@x.com'})").await;
    engine
        .constraint_ddl(
            create_unique("uniq_email", "Person", "email"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create constraint");
    try_run(&engine, "CREATE (:Person {email: 'a@x.com'})")
        .await
        .expect_err("enforced before drop");

    engine
        .constraint_ddl(
            ConstraintCommand::Drop {
                name: "uniq_email".to_owned(),
                if_exists: false,
            },
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("drop constraint");
    assert_eq!(show_constraints(&engine).await.rows.len(), 0);

    // After the drop the duplicate is allowed.
    run(&engine, "CREATE (:Person {email: 'a@x.com'})").await;
    assert_eq!(person_count(&engine).await, 2);

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn constraints_survive_a_full_server_restart() {
    let temp = TempStore::new("restart");
    let cfg = config(&temp);

    // Boot #1: seed, declare both kinds of constraint, confirm enforcement, then shut down cleanly.
    {
        let handle = boot(cfg.clone()).await;
        let engine = handle.engine.clone();
        run(&engine, "CREATE (:Person {email: 'a@x.com', name: 'A'})").await;
        engine
            .constraint_ddl(
                create_unique("uniq_email", "Person", "email"),
                None, /* principal: the test drives the engine directly */
            )
            .await
            .expect("create unique");
        engine
            .constraint_ddl(
                create_existence("name_exists", "Person", "name"),
                None, /* principal: the test drives the engine directly */
            )
            .await
            .expect("create existence");
        // Enforced before restart.
        try_run(&engine, "CREATE (:Person {email: 'a@x.com', name: 'B'})")
            .await
            .expect_err("uniqueness enforced before restart");
        handle.shutdown().await.expect("shutdown");
    }

    // Boot #2: the constraints must still be declared (durable catalog) and still enforce (a
    // uniqueness constraint's backing index is rebuilt from the recovered store) — the durability AC.
    let handle = boot(cfg).await;
    let engine = handle.engine.clone();

    assert_eq!(
        show_constraints(&engine).await.rows.len(),
        2,
        "both constraints must survive the restart"
    );

    // Uniqueness still enforces against the recovered data.
    let err = try_run(&engine, "CREATE (:Person {email: 'a@x.com', name: 'Dup'})")
        .await
        .expect_err("uniqueness must still enforce after restart");
    assert_constraint_violation(&err);

    // Existence still enforces.
    let err = try_run(&engine, "CREATE (:Person {email: 'z@x.com'})")
        .await
        .expect_err("existence must still enforce after restart");
    assert_constraint_violation(&err);

    // A fully-conforming CREATE still succeeds after restart.
    run(&engine, "CREATE (:Person {email: 'b@x.com', name: 'B'})").await;
    assert_eq!(person_count(&engine).await, 2);

    handle.shutdown().await.expect("shutdown");
}

// =================================================================================================
// NODE KEY — `rmp` task #100
// =================================================================================================

#[tokio::test]
async fn node_key_enforced_on_create_set_and_merge() {
    let temp = TempStore::new("nodekey");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(&engine, "CREATE (:Person {first: 'Ada', last: 'Lovelace'})").await;
    engine
        .constraint_ddl(
            create_node_key("person_key", "Person", &["first", "last"]),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create node key over conforming data");

    // A CREATE missing one key component is rejected (existence half).
    let err = try_run(&engine, "CREATE (:Person {first: 'Grace'})")
        .await
        .expect_err("missing key component must be rejected");
    assert_constraint_violation(&err);

    // A CREATE duplicating the full tuple is rejected (uniqueness half).
    let err = try_run(&engine, "CREATE (:Person {first: 'Ada', last: 'Lovelace'})")
        .await
        .expect_err("duplicate composite tuple must be rejected");
    assert_constraint_violation(&err);
    assert_eq!(person_count(&engine).await, 1);

    // A tuple differing in one component is allowed.
    run(&engine, "CREATE (:Person {first: 'Ada', last: 'Byron'})").await;
    assert_eq!(person_count(&engine).await, 2);

    // A MERGE that creates a colliding tuple is rejected.
    let err = try_run(
        &engine,
        "MERGE (:Person {first: 'Ada', last: 'Lovelace', note: 'x'})",
    )
    .await
    .expect_err("MERGE creating a duplicate tuple must be rejected");
    assert_constraint_violation(&err);

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn node_key_creation_time_validation() {
    let temp = TempStore::new("nodekeyvalidate");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // Two nodes share a composite tuple: the node key cannot be created.
    run(&engine, "CREATE (:Person {first: 'Ada', last: 'Lovelace'})").await;
    run(&engine, "CREATE (:Person {first: 'Ada', last: 'Lovelace'})").await;
    let err = engine
        .constraint_ddl(
            create_node_key("person_key", "Person", &["first", "last"]),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect_err("node key over duplicate tuples must be rejected");
    assert_constraint_violation(&err);
    assert_eq!(show_constraints(&engine).await.rows.len(), 0);

    // A node missing a component: the node key cannot be created.
    run(&engine, "CREATE (:Person {first: 'Solo'})").await;
    let err = engine
        .constraint_ddl(
            create_node_key("person_key2", "Person", &["first", "last"]),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect_err("node key over data missing a component must be rejected");
    assert_constraint_violation(&err);
    assert_eq!(show_constraints(&engine).await.rows.len(), 0);

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn node_key_survives_a_full_server_restart() {
    let temp = TempStore::new("nodekeyrestart");
    let cfg = config(&temp);

    {
        let handle = boot(cfg.clone()).await;
        let engine = handle.engine.clone();
        run(&engine, "CREATE (:Person {first: 'Ada', last: 'Lovelace'})").await;
        engine
            .constraint_ddl(
                create_node_key("person_key", "Person", &["first", "last"]),
                None, /* principal: the test drives the engine directly */
            )
            .await
            .expect("create node key");
        try_run(&engine, "CREATE (:Person {first: 'Ada', last: 'Lovelace'})")
            .await
            .expect_err("node key enforced before restart");
        handle.shutdown().await.expect("shutdown");
    }

    let handle = boot(cfg).await;
    let engine = handle.engine.clone();
    assert_eq!(
        show_constraints(&engine).await.rows.len(),
        1,
        "the node key must survive the restart"
    );

    // The duplicate tuple is still rejected (the backing composite index was rebuilt).
    let err = try_run(&engine, "CREATE (:Person {first: 'Ada', last: 'Lovelace'})")
        .await
        .expect_err("node key must still enforce after restart");
    assert_constraint_violation(&err);

    // A missing component is still rejected.
    let err = try_run(&engine, "CREATE (:Person {first: 'Lone'})")
        .await
        .expect_err("node-key existence must still enforce after restart");
    assert_constraint_violation(&err);

    // A distinct, complete tuple still succeeds.
    run(&engine, "CREATE (:Person {first: 'Grace', last: 'Hopper'})").await;
    assert_eq!(person_count(&engine).await, 2);

    handle.shutdown().await.expect("shutdown");
}

// =================================================================================================
// PROPERTY TYPE — `rmp` task #100
// =================================================================================================

#[tokio::test]
async fn property_type_enforced_on_create_and_set() {
    use graphus_storage::ConstraintTypeDescriptor as T;
    let temp = TempStore::new("proptype");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(&engine, "CREATE (:Person {age: 30})").await;
    engine
        .constraint_ddl(
            create_property_type("age_int", "Person", "age", T::Integer),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create property-type constraint over conforming data");

    // A STRING where INTEGER is required is rejected with the right class.
    let err = try_run(&engine, "CREATE (:Person {age: 'old'})")
        .await
        .expect_err("wrong type must be rejected");
    assert_constraint_violation(&err);

    // The correct type succeeds; an absent property succeeds (type does not imply existence).
    run(&engine, "CREATE (:Person {age: 25})").await;
    run(&engine, "CREATE (:Person {name: 'NoAge'})").await;
    assert_eq!(person_count(&engine).await, 3);

    // A SET storing the wrong type is rejected.
    let err = try_run(&engine, "MATCH (p:Person {age: 25}) SET p.age = 'nope'")
        .await
        .expect_err("SET to wrong type must be rejected");
    assert_constraint_violation(&err);

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn property_type_creation_time_validation_and_restart() {
    use graphus_storage::ConstraintTypeDescriptor as T;
    let temp = TempStore::new("proptyperestart");
    let cfg = config(&temp);

    {
        let handle = boot(cfg.clone()).await;
        let engine = handle.engine.clone();

        // Existing wrong-typed data: the constraint cannot be created.
        run(&engine, "CREATE (:Person {score: 'high'})").await;
        let err = engine
            .constraint_ddl(
                create_property_type("score_int", "Person", "score", T::Integer),
                None, /* principal: the test drives the engine directly */
            )
            .await
            .expect_err("property-type over wrong-typed data must be rejected");
        assert_constraint_violation(&err);
        assert_eq!(show_constraints(&engine).await.rows.len(), 0);

        // Overwrite with a conforming value, then declare the constraint.
        run(&engine, "MATCH (p:Person {score: 'high'}) SET p.score = 99").await;
        engine
            .constraint_ddl(
                create_property_type("score_int", "Person", "score", T::Integer),
                None, /* principal: the test drives the engine directly */
            )
            .await
            .expect("create over conforming data");
        handle.shutdown().await.expect("shutdown");
    }

    let handle = boot(cfg).await;
    let engine = handle.engine.clone();
    assert_eq!(show_constraints(&engine).await.rows.len(), 1);

    // The type rule still enforces after the restart.
    let err = try_run(&engine, "CREATE (:Person {score: 'bad'})")
        .await
        .expect_err("property-type must still enforce after restart");
    assert_constraint_violation(&err);
    run(&engine, "CREATE (:Person {score: 7})").await;

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn show_constraints_lists_all_four_kinds() {
    use graphus_storage::ConstraintTypeDescriptor as T;
    let temp = TempStore::new("showall");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    engine
        .constraint_ddl(
            create_unique("u", "Person", "email"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("unique");
    engine
        .constraint_ddl(
            create_existence("e", "Person", "name"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("existence");
    engine
        .constraint_ddl(
            create_node_key("k", "Person", &["first", "last"]),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("node key");
    engine
        .constraint_ddl(
            create_property_type("t", "Person", "age", T::Integer),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("property type");

    let reply = show_constraints(&engine).await;
    assert_eq!(reply.rows.len(), 4);
    // Rows are ordered by name: e, k, t, u. Columns:
    // [id, name, type, entityType, labelsOrTypes, properties, ownedIndex, propertyType, ...].
    assert_eq!(reply.rows[0][1], Value::String("e".to_owned()));
    assert_eq!(
        reply.rows[0][2],
        Value::String("NODE_PROPERTY_EXISTENCE".to_owned())
    );
    assert_eq!(reply.rows[1][1], Value::String("k".to_owned()));
    // A composite node key lists its whole property tuple as a list; type is NODE_KEY (no folded type).
    assert_eq!(
        reply.rows[1][5],
        Value::List(vec![
            Value::String("first".to_owned()),
            Value::String("last".to_owned()),
        ])
    );
    assert_eq!(reply.rows[1][2], Value::String("NODE_KEY".to_owned()));
    assert_eq!(
        reply.rows[1][6],
        Value::String("k".to_owned()),
        "a node key owns its backing index"
    );
    assert_eq!(reply.rows[2][1], Value::String("t".to_owned()));
    // The property type is NOT folded into `type`; it goes in the `propertyType` column.
    assert_eq!(
        reply.rows[2][2],
        Value::String("NODE_PROPERTY_TYPE".to_owned())
    );
    assert_eq!(
        reply.rows[2][7],
        Value::String("INTEGER".to_owned()),
        "propertyType column carries the declared type"
    );
    assert_eq!(reply.rows[3][1], Value::String("u".to_owned()));
    assert_eq!(
        reply.rows[3][2],
        Value::String("NODE_PROPERTY_UNIQUENESS".to_owned())
    );

    handle.shutdown().await.expect("graceful shutdown");
}

/// `rmp` #653: a `SHOW <filter> CONSTRAINTS` type filter returns only the matching kinds. Exercises the
/// engine's filtered rendering directly (the seam path is covered end-to-end over Bolt in
/// `db_admin_surface.rs`).
#[tokio::test]
async fn show_constraints_type_filter_selects_matching_kinds() {
    use graphus_storage::ConstraintTypeDescriptor as T;
    let temp = TempStore::new("show_filter");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    engine
        .constraint_ddl(
            create_unique("u", "Person", "email"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("unique");
    engine
        .constraint_ddl(
            create_node_key("k", "Person", &["first", "last"]),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("node key");
    engine
        .constraint_ddl(
            create_property_type("t", "Person", "age", T::Integer),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("property type");
    engine
        .constraint_ddl(
            rel_create("rk", "RATED", &["a", "b"], ConstraintCreateKind::Key),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("rel key");

    // ALL returns everything.
    assert_eq!(
        show_constraints_filtered(&engine, ConstraintTypeFilter::All)
            .await
            .rows
            .len(),
        4
    );
    // NODE KEY returns only the node key (name column is index 1).
    let node_keys = show_constraints_filtered(&engine, ConstraintTypeFilter::NodeKey).await;
    assert_eq!(node_keys.rows.len(), 1);
    assert_eq!(node_keys.rows[0][1], Value::String("k".to_owned()));
    // KEY returns both node and rel keys.
    assert_eq!(
        show_constraints_filtered(&engine, ConstraintTypeFilter::Key)
            .await
            .rows
            .len(),
        2
    );
    // PROPERTY TYPE returns only the property-type constraint.
    let types = show_constraints_filtered(&engine, ConstraintTypeFilter::PropertyType).await;
    assert_eq!(types.rows.len(), 1);
    assert_eq!(types.rows[0][1], Value::String("t".to_owned()));
    assert_eq!(types.rows[0][7], Value::String("INTEGER".to_owned()));
    // UNIQUENESS returns only the (node) uniqueness constraint here.
    let uniq = show_constraints_filtered(&engine, ConstraintTypeFilter::Unique).await;
    assert_eq!(uniq.rows.len(), 1);
    assert_eq!(uniq.rows[0][1], Value::String("u".to_owned()));

    handle.shutdown().await.expect("graceful shutdown");
}

/// `rmp` #638: `CREATE CONSTRAINT … IF NOT EXISTS` is an idempotent no-op when an equivalent
/// constraint already exists — by the same name **or** the same schema — reporting `mutated == false`;
/// creating a duplicate name **without** `IF NOT EXISTS` is an error.
#[tokio::test]
async fn create_constraint_if_not_exists_is_idempotent() {
    let temp = TempStore::new("ifnotexists");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // First create: mutates.
    let first = engine
        .constraint_ddl(
            create_unique("uniq_email", "Person", "email"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("first create");
    assert!(first.mutated, "the first create mutates the schema");

    // Same-name IF NOT EXISTS: no-op.
    let same_name = engine
        .constraint_ddl(
            ConstraintCommand::Create(CreateConstraint {
                name: "uniq_email".to_owned(),
                entity: ConstraintEntity::Node {
                    label: "Person".to_owned(),
                },
                properties: vec!["email".to_owned()],
                kind: ConstraintCreateKind::Unique,
                if_not_exists: true,
                or_replace: false,
            }),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("if-not-exists same name");
    assert!(!same_name.mutated, "an existing name is a no-op");

    // Equivalent schema under a DIFFERENT name, with IF NOT EXISTS: still a no-op.
    let same_schema = engine
        .constraint_ddl(
            ConstraintCommand::Create(CreateConstraint {
                name: "another_name".to_owned(),
                entity: ConstraintEntity::Node {
                    label: "Person".to_owned(),
                },
                properties: vec!["email".to_owned()],
                kind: ConstraintCreateKind::Unique,
                if_not_exists: true,
                or_replace: false,
            }),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("if-not-exists same schema");
    assert!(!same_schema.mutated, "an equivalent schema is a no-op");

    // Still exactly one constraint.
    assert_eq!(show_constraints(&engine).await.rows.len(), 1);

    // A duplicate name WITHOUT IF NOT EXISTS is an error.
    engine
        .constraint_ddl(
            create_unique("uniq_email", "Person", "email"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect_err("duplicate name without IF NOT EXISTS is rejected");

    handle.shutdown().await.expect("graceful shutdown");
}

/// `rmp` #638: `CREATE OR REPLACE CONSTRAINT` drops any same-named constraint and creates the new one,
/// replacing a rule of a different kind and re-establishing enforcement for the new one.
#[tokio::test]
async fn create_or_replace_constraint_drops_and_recreates() {
    let temp = TempStore::new("orreplace");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // Start with an existence constraint named `c`.
    engine
        .constraint_ddl(
            create_existence("c", "Person", "email"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create existence");
    // A node missing `email` is now rejected.
    try_run(&engine, "CREATE (:Person {name: 'no-email'})")
        .await
        .expect_err("existence enforced");

    // OR REPLACE the same name with a uniqueness rule.
    let replaced = engine
        .constraint_ddl(
            ConstraintCommand::Create(CreateConstraint {
                name: "c".to_owned(),
                entity: ConstraintEntity::Node {
                    label: "Person".to_owned(),
                },
                properties: vec!["email".to_owned()],
                kind: ConstraintCreateKind::Unique,
                if_not_exists: false,
                or_replace: true,
            }),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("or replace");
    assert!(replaced.mutated, "OR REPLACE mutates");

    // Exactly one constraint remains, and it is now the uniqueness rule.
    let reply = show_constraints(&engine).await;
    assert_eq!(reply.rows.len(), 1);
    assert_eq!(reply.rows[0][1], Value::String("c".to_owned()));
    assert_eq!(
        reply.rows[0][2],
        Value::String("NODE_PROPERTY_UNIQUENESS".to_owned())
    );

    // Existence is no longer enforced (a missing email is allowed) but uniqueness now is.
    run(&engine, "CREATE (:Person {name: 'no-email'})").await;
    run(&engine, "CREATE (:Person {email: 'a@x.com'})").await;
    try_run(&engine, "CREATE (:Person {email: 'a@x.com'})")
        .await
        .expect_err("uniqueness enforced after replace");

    handle.shutdown().await.expect("graceful shutdown");
}

/// `rmp` #638: a **relationship existence** constraint (`FOR ()-[r:KNOWS]-() REQUIRE r.since IS NOT
/// NULL`) is enforced on `CREATE` and on `SET r.since = null`.
#[tokio::test]
async fn relationship_existence_enforced_on_create_and_set() {
    let temp = TempStore::new("rel_existence");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(&engine, "CREATE (:Person {id: 1}), (:Person {id: 2})").await;
    engine
        .constraint_ddl(
            rel_create(
                "knows_since",
                "KNOWS",
                &["since"],
                ConstraintCreateKind::Existence,
            ),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create rel existence");

    // A relationship with `since` is allowed.
    run(
        &engine,
        "MATCH (a:Person {id: 1}), (b:Person {id: 2}) CREATE (a)-[:KNOWS {since: 2020}]->(b)",
    )
    .await;
    // A relationship without `since` is rejected.
    let err = try_run(
        &engine,
        "MATCH (a:Person {id: 1}), (b:Person {id: 2}) CREATE (a)-[:KNOWS]->(b)",
    )
    .await
    .expect_err("existence enforced on create");
    assert_constraint_violation(&err);

    // Removing `since` from an existing relationship is rejected.
    try_run(&engine, "MATCH ()-[r:KNOWS]->() SET r.since = null")
        .await
        .expect_err("existence enforced on set-null");

    handle.shutdown().await.expect("graceful shutdown");
}

/// `rmp` #638: a **relationship key** constraint (`FOR ()-[r:RATED]-() REQUIRE (r.user, r.movie) IS
/// RELATIONSHIP KEY`) enforces both the existence half (all covered properties present) and the
/// uniqueness half (the tuple is unique across relationships of the type), including at creation-time
/// validation against existing data.
#[tokio::test]
async fn relationship_key_enforced_and_creation_validation() {
    let temp = TempStore::new("rel_key");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(&engine, "CREATE (:U {id: 1}), (:M {id: 10})").await;
    engine
        .constraint_ddl(
            rel_create(
                "rated_key",
                "RATED",
                &["user", "movie"],
                ConstraintCreateKind::Key,
            ),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create rel key");

    // A complete tuple is allowed.
    run(
        &engine,
        "MATCH (u:U {id: 1}), (m:M {id: 10}) CREATE (u)-[:RATED {user: 1, movie: 10, stars: 5}]->(m)",
    )
    .await;
    // A missing covered property (existence half) is rejected.
    try_run(
        &engine,
        "MATCH (u:U {id: 1}), (m:M {id: 10}) CREATE (u)-[:RATED {user: 1}]->(m)",
    )
    .await
    .expect_err("rel-key existence half enforced");
    // A duplicate tuple (uniqueness half) is rejected.
    let err = try_run(
        &engine,
        "MATCH (u:U {id: 1}), (m:M {id: 10}) CREATE (u)-[:RATED {user: 1, movie: 10}]->(m)",
    )
    .await
    .expect_err("rel-key uniqueness half enforced");
    assert_constraint_violation(&err);

    // Creation-time validation: a fresh constraint over data that already violates it is rejected.
    run(
        &engine,
        "MATCH (u:U {id: 1}), (m:M {id: 10}) CREATE (u)-[:LINK {a: 1}]->(m), (u)-[:LINK {a: 1}]->(m)",
    )
    .await;
    engine
        .constraint_ddl(
            rel_create("link_unique", "LINK", &["a"], ConstraintCreateKind::Unique),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect_err("creation-time validation rejects duplicate rel values");

    handle.shutdown().await.expect("graceful shutdown");
}

/// `rmp` #638: relationship constraints are durable — they survive a full server restart (reloaded
/// from the durable catalog and enforced again) — and `SHOW CONSTRAINTS` reports `entityType`
/// `RELATIONSHIP`.
#[tokio::test]
async fn relationship_constraints_survive_restart_and_show_entity_type() {
    let temp = TempStore::new("rel_restart");
    let cfg = config(&temp);

    {
        let handle = boot(cfg.clone()).await;
        let engine = handle.engine.clone();
        run(&engine, "CREATE (:A {id: 1}), (:B {id: 2})").await;
        engine
            .constraint_ddl(
                rel_create("paid_ref", "PAID", &["ref"], ConstraintCreateKind::Unique),
                None, /* principal: the test drives the engine directly */
            )
            .await
            .expect("create rel unique");
        // A SHOW reports the relationship entityType and the 5.x rel-uniqueness type string.
        let reply = show_constraints(&engine).await;
        assert_eq!(reply.rows.len(), 1);
        assert_eq!(reply.rows[0][1], Value::String("paid_ref".to_owned()));
        assert_eq!(
            reply.rows[0][2],
            Value::String("RELATIONSHIP_PROPERTY_UNIQUENESS".to_owned())
        );
        assert_eq!(reply.rows[0][3], Value::String("RELATIONSHIP".to_owned()));
        assert_eq!(
            reply.rows[0][4],
            Value::List(vec![Value::String("PAID".to_owned())]),
            "labelsOrTypes carries the relationship type"
        );
        run(
            &engine,
            "MATCH (a:A {id: 1}), (b:B {id: 2}) CREATE (a)-[:PAID {ref: 'x'}]->(b)",
        )
        .await;
        handle.shutdown().await.expect("graceful shutdown");
    }

    // Restart: the relationship constraint is reloaded and still enforced.
    {
        let handle = boot(cfg).await;
        let engine = handle.engine.clone();
        assert_eq!(show_constraints(&engine).await.rows.len(), 1);
        try_run(
            &engine,
            "MATCH (a:A {id: 1}), (b:B {id: 2}) CREATE (a)-[:PAID {ref: 'x'}]->(b)",
        )
        .await
        .expect_err("rel uniqueness enforced after restart");
        handle.shutdown().await.expect("graceful shutdown");
    }
}

// =================================================================================================
// `rmp` #650 — `REMOVE n.p` / `REMOVE r.p` must enforce existence & key constraints (regression).
//
// Before the fix, `remove_node_property` / `remove_rel_property` bypassed constraint enforcement
// (unlike `SET … = null`), so a `REMOVE` could silently leave a record violating a `NOT NULL` /
// `KEY` constraint — a schema-integrity / ACID defect. These tests assert the `REMOVE` clause is
// now rejected and rolled back (the property remains present).
// =================================================================================================

/// The string value of `MATCH (n:Person {id:1}) RETURN n.<key>`, or `None` if absent/null.
async fn person_prop(handle: &EngineHandle, key: &str) -> Option<String> {
    let rows = run(
        handle,
        &format!("MATCH (n:Person {{id: 1}}) RETURN n.{key} AS v"),
    )
    .await;
    match &rows[0][0] {
        MaterializedValue::Value(Value::String(s)) => Some(s.clone()),
        MaterializedValue::Value(Value::Null) => None,
        other => panic!("unexpected value {other:?}"),
    }
}

#[tokio::test]
async fn remove_property_is_rejected_by_node_existence_constraint() {
    let temp = TempStore::new("remove_node_existence");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(&engine, "CREATE (:Person {id: 1, name: 'A'})").await;
    engine
        .constraint_ddl(
            create_existence("name_exists", "Person", "name"),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create existence constraint");

    // `REMOVE n.name` would leave a Person with no `name` — a NOT NULL violation.
    let err = try_run(&engine, "MATCH (n:Person {id: 1}) REMOVE n.name")
        .await
        .expect_err("REMOVE of a required property must be rejected");
    assert_constraint_violation(&err);
    // Rolled back: the property is still present.
    assert_eq!(person_prop(&engine, "name").await, Some("A".to_owned()));

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn remove_property_is_rejected_by_node_key_constraint() {
    let temp = TempStore::new("remove_node_key");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(
        &engine,
        "CREATE (:Person {id: 1, first: 'Ada', last: 'Byron'})",
    )
    .await;
    engine
        .constraint_ddl(
            create_node_key("person_key", "Person", &["first", "last"]),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create node-key constraint");

    // Removing either covered property makes the key tuple incomplete → rejected, and rolls back.
    let err = try_run(&engine, "MATCH (n:Person {id: 1}) REMOVE n.last")
        .await
        .expect_err("REMOVE of a key property must be rejected");
    assert_constraint_violation(&err);
    assert_eq!(person_prop(&engine, "last").await, Some("Byron".to_owned()));
    let err = try_run(&engine, "MATCH (n:Person {id: 1}) REMOVE n.first")
        .await
        .expect_err("REMOVE of a key property must be rejected");
    assert_constraint_violation(&err);
    assert_eq!(person_prop(&engine, "first").await, Some("Ada".to_owned()));

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn remove_property_is_rejected_by_relationship_existence_constraint() {
    let temp = TempStore::new("remove_rel_existence");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(&engine, "CREATE (:A {id: 1}), (:B {id: 2})").await;
    engine
        .constraint_ddl(
            rel_create(
                "since_exists",
                "KNOWS",
                &["since"],
                ConstraintCreateKind::Existence,
            ),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create rel existence constraint");
    run(
        &engine,
        "MATCH (a:A {id: 1}), (b:B {id: 2}) CREATE (a)-[:KNOWS {since: 2020}]->(b)",
    )
    .await;

    // `REMOVE r.since` would leave the relationship missing a required property → rejected.
    let err = try_run(&engine, "MATCH ()-[r:KNOWS]->() REMOVE r.since")
        .await
        .expect_err("REMOVE of a required rel property must be rejected");
    assert_constraint_violation(&err);
    // Rolled back: the relationship still carries `since`.
    let rows = run(&engine, "MATCH ()-[r:KNOWS]->() RETURN r.since AS v").await;
    assert_eq!(rows[0][0], MaterializedValue::Value(Value::Integer(2020)));

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn remove_property_is_rejected_by_relationship_key_constraint() {
    let temp = TempStore::new("remove_rel_key");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(&engine, "CREATE (:A {id: 1}), (:B {id: 2})").await;
    engine
        .constraint_ddl(
            rel_create("rated_key", "RATED", &["u", "m"], ConstraintCreateKind::Key),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("create rel-key constraint");
    run(
        &engine,
        "MATCH (a:A {id: 1}), (b:B {id: 2}) CREATE (a)-[:RATED {u: 1, m: 2}]->(b)",
    )
    .await;

    // Removing a covered key property makes the tuple incomplete → rejected.
    let err = try_run(&engine, "MATCH ()-[r:RATED]->() REMOVE r.u")
        .await
        .expect_err("REMOVE of a rel-key property must be rejected");
    assert_constraint_violation(&err);
    let rows = run(&engine, "MATCH ()-[r:RATED]->() RETURN r.u AS v").await;
    assert_eq!(rows[0][0], MaterializedValue::Value(Value::Integer(1)));

    handle.shutdown().await.expect("graceful shutdown");
}

// =================================================================================================
// `rmp` #652 — the full Neo4j-5.x property-type set for `IS :: <TYPE>` constraints: temporal,
// spatial (POINT), closed unions, and `LIST<X NOT NULL>`, enforced end-to-end against real values.
// =================================================================================================

#[tokio::test]
async fn property_type_constraint_temporal_point_union_and_list_enforced() {
    use graphus_storage::ConstraintTypeDescriptor as T;
    let temp = TempStore::new("proptype_full");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // --- DATE ---
    run(&engine, "CREATE (:D {id: 1, d: date('2020-01-01')})").await;
    engine
        .constraint_ddl(
            create_property_type("d_is_date", "D", "d", T::Date),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("DATE property-type constraint over conforming data");
    run(&engine, "CREATE (:D {id: 2, d: date('2021-06-01')})").await; // conforming
    run(&engine, "CREATE (:D {id: 3})").await; // absent property is allowed (type ≠ existence)
    let err = try_run(&engine, "CREATE (:D {id: 4, d: 5})")
        .await
        .expect_err("an INTEGER value violates a DATE type constraint");
    assert_constraint_violation(&err);

    // --- POINT ---
    engine
        .constraint_ddl(
            create_property_type("loc_is_point", "Loc", "p", T::Point),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("POINT property-type constraint");
    run(&engine, "CREATE (:Loc {id: 1, p: point({x: 1.0, y: 2.0})})").await;
    let err = try_run(&engine, "CREATE (:Loc {id: 2, p: 'here'})")
        .await
        .expect_err("a STRING value violates a POINT type constraint");
    assert_constraint_violation(&err);

    // --- Closed union INTEGER | STRING ---
    engine
        .constraint_ddl(
            create_property_type(
                "code_union",
                "Code",
                "c",
                T::Union(vec![T::Integer, T::String]),
            ),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("union property-type constraint");
    run(&engine, "CREATE (:Code {id: 1, c: 42})").await;
    run(&engine, "CREATE (:Code {id: 2, c: 'ABC'})").await;
    let err = try_run(&engine, "CREATE (:Code {id: 3, c: true})")
        .await
        .expect_err("a BOOLEAN value conforms to neither INTEGER nor STRING");
    assert_constraint_violation(&err);

    // --- LIST<INTEGER NOT NULL> ---
    engine
        .constraint_ddl(
            create_property_type("tags_list", "Tags", "t", T::List(Box::new(T::Integer))),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("list property-type constraint");
    run(&engine, "CREATE (:Tags {id: 1, t: [1, 2, 3]})").await;
    // A homogeneous list of the wrong element type (STRING) is storable but violates LIST<INTEGER>.
    let err = try_run(&engine, "CREATE (:Tags {id: 2, t: ['a', 'b']})")
        .await
        .expect_err("a STRING-element list violates LIST<INTEGER NOT NULL>");
    assert_constraint_violation(&err);

    handle.shutdown().await.expect("graceful shutdown");
}

// =================================================================================================
// `rmp` #651 — composite property uniqueness (node + relationship): the combined values of a tuple
// must be unique, with null-relaxation (a null in any covered property is never checked), enforced
// on CREATE/SET/MERGE and at creation time, and durable across restart.
// =================================================================================================

/// Builds a composite node `IS UNIQUE` command.
fn create_composite_unique(name: &str, label: &str, properties: &[&str]) -> ConstraintCommand {
    node_create(name, label, properties, ConstraintCreateKind::Unique)
}

#[tokio::test]
async fn composite_node_uniqueness_enforced_with_null_relaxation() {
    let temp = TempStore::new("composite_node_unique");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(
        &engine,
        "CREATE (:Person {id: 1, first: 'Ada', last: 'Byron'})",
    )
    .await;
    engine
        .constraint_ddl(
            create_composite_unique("uq_name", "Person", &["first", "last"]),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect("composite uniqueness over conforming data");

    // A different tuple (same first, different last) is allowed.
    run(
        &engine,
        "CREATE (:Person {id: 2, first: 'Ada', last: 'Lovelace'})",
    )
    .await;
    // A duplicate tuple is rejected.
    let err = try_run(
        &engine,
        "CREATE (:Person {id: 3, first: 'Ada', last: 'Byron'})",
    )
    .await
    .expect_err("duplicate composite tuple must be rejected");
    assert_constraint_violation(&err);

    // Null-relaxation: a node missing a covered property has an incomplete tuple → never collides,
    // so two such nodes both succeed (Cypher uniqueness treats null as never-equal).
    run(&engine, "CREATE (:Person {id: 4, first: 'Ada'})").await;
    run(&engine, "CREATE (:Person {id: 5, first: 'Ada'})").await;

    // A SET that completes a tuple into a duplicate is rejected.
    let err = try_run(&engine, "MATCH (n:Person {id: 2}) SET n.last = 'Byron'")
        .await
        .expect_err("SET into a duplicate composite tuple must be rejected");
    assert_constraint_violation(&err);

    // Creation-time validation over pre-existing duplicates rejects the constraint.
    run(&engine, "CREATE (:Dup {a: 1, b: 2})").await;
    run(&engine, "CREATE (:Dup {a: 1, b: 2})").await;
    let err = engine
        .constraint_ddl(
            create_composite_unique("dk", "Dup", &["a", "b"]),
            None, /* principal: the test drives the engine directly */
        )
        .await
        .expect_err("composite uniqueness over duplicate data must be rejected");
    assert_constraint_violation(&err);

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn composite_relationship_uniqueness_enforced_and_durable() {
    let temp = TempStore::new("composite_rel_unique");
    let cfg = config(&temp);

    {
        let handle = boot(cfg.clone()).await;
        let engine = handle.engine.clone();
        run(&engine, "CREATE (:A {id: 1}), (:B {id: 2})").await;
        engine
            .constraint_ddl(
                rel_create("rq_pair", "PAID", &["x", "y"], ConstraintCreateKind::Unique),
                None, /* principal: the test drives the engine directly */
            )
            .await
            .expect("composite rel uniqueness");
        run(
            &engine,
            "MATCH (a:A {id: 1}), (b:B {id: 2}) CREATE (a)-[:PAID {x: 1, y: 2}]->(b)",
        )
        .await;
        // A different tuple is allowed.
        run(
            &engine,
            "MATCH (a:A {id: 1}), (b:B {id: 2}) CREATE (a)-[:PAID {x: 1, y: 3}]->(b)",
        )
        .await;
        // The duplicate tuple is rejected.
        let err = try_run(
            &engine,
            "MATCH (a:A {id: 1}), (b:B {id: 2}) CREATE (a)-[:PAID {x: 1, y: 2}]->(b)",
        )
        .await
        .expect_err("duplicate composite rel tuple must be rejected");
        assert_constraint_violation(&err);
        // Null-relaxation: an incomplete tuple never collides.
        run(
            &engine,
            "MATCH (a:A {id: 1}), (b:B {id: 2}) CREATE (a)-[:PAID {x: 1}]->(b)",
        )
        .await;
        handle.shutdown().await.expect("graceful shutdown");
    }

    // Restart: the composite rel uniqueness constraint is reloaded and still enforced.
    {
        let handle = boot(cfg).await;
        let engine = handle.engine.clone();
        assert_eq!(show_constraints(&engine).await.rows.len(), 1);
        let err = try_run(
            &engine,
            "MATCH (a:A {id: 1}), (b:B {id: 2}) CREATE (a)-[:PAID {x: 1, y: 2}]->(b)",
        )
        .await
        .expect_err("composite rel uniqueness enforced after restart");
        assert_constraint_violation(&err);
        handle.shutdown().await.expect("graceful shutdown");
    }
}
