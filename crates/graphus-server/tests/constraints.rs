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
use graphus_server::engine::{AccessMode, ConstraintCommand, EngineHandle, IndexDdlReply};
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
        fsync_threads: 1,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        rest_addr: None,
        uds_path: Some(temp.uds_path()),
        tls: TlsConfig::default(),
        admission: AdmissionConfig {
            max_concurrent_queries: 64,
            engine_queue_capacity: 256,
            result_buffer_capacity: 64,
        },
        timing: TimingConfig {
            slow_query_threshold_ms: 1_000,
            shutdown_drain_deadline_ms: 5_000,
        },
        jwt_secret: "constraints-itest-jwt-secret-uds-only!".to_owned(),
        auth: AuthBootstrap {
            admin_user: "alice".to_owned(),
            admin_password: "pw".to_owned(),
            admin_uid: None,
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: graphus_server::AuditConfig::default(),
        allow_insecure_network: false,
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
        .run(ticket, query.to_owned(), Vec::new(), true, None)
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

fn create_unique(name: &str, label: &str, property: &str) -> ConstraintCommand {
    ConstraintCommand::CreateUnique {
        name: name.to_owned(),
        label: label.to_owned(),
        property: property.to_owned(),
    }
}

fn create_existence(name: &str, label: &str, property: &str) -> ConstraintCommand {
    ConstraintCommand::CreateExistence {
        name: name.to_owned(),
        label: label.to_owned(),
        property: property.to_owned(),
    }
}

async fn show_constraints(handle: &EngineHandle) -> IndexDdlReply {
    handle
        .constraint_ddl(ConstraintCommand::Show)
        .await
        .expect("show constraints")
}

#[tokio::test]
async fn uniqueness_enforced_on_create_set_and_merge() {
    let temp = TempStore::new("uniqueness");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(&engine, "CREATE (:Person {email: 'a@x.com', name: 'A'})").await;
    engine
        .constraint_ddl(create_unique("uniq_email", "Person", "email"))
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
        .constraint_ddl(create_existence("name_exists", "Person", "name"))
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
        .constraint_ddl(create_unique("uniq_email", "Person", "email"))
        .await
        .expect_err("uniqueness over duplicate data must be rejected");
    assert_constraint_violation(&err);
    // The failed creation declared nothing.
    assert_eq!(show_constraints(&engine).await.rows.len(), 0);

    // A Person without `name`: an existence constraint cannot be created.
    run(&engine, "CREATE (:Person {email: 'noname@x.com'})").await;
    let err = engine
        .constraint_ddl(create_existence("name_exists", "Person", "name"))
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
        .constraint_ddl(create_unique("uniq_email", "Person", "email"))
        .await
        .expect("create unique");
    engine
        .constraint_ddl(create_existence("name_exists", "Person", "name"))
        .await
        .expect("create existence");

    let reply = show_constraints(&engine).await;
    assert_eq!(
        reply.fields,
        vec![
            "name".to_owned(),
            "label".to_owned(),
            "property".to_owned(),
            "type".to_owned()
        ]
    );
    assert_eq!(reply.rows.len(), 2);
    // Rows are ordered by name: name_exists, uniq_email.
    assert_eq!(reply.rows[0][0], Value::String("name_exists".to_owned()));
    assert_eq!(
        reply.rows[0][3],
        Value::String("NODE_PROPERTY_EXISTENCE".to_owned())
    );
    assert_eq!(reply.rows[1][0], Value::String("uniq_email".to_owned()));
    assert_eq!(reply.rows[1][3], Value::String("UNIQUENESS".to_owned()));

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn drop_constraint_removes_enforcement() {
    let temp = TempStore::new("drop");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(&engine, "CREATE (:Person {email: 'a@x.com'})").await;
    engine
        .constraint_ddl(create_unique("uniq_email", "Person", "email"))
        .await
        .expect("create constraint");
    try_run(&engine, "CREATE (:Person {email: 'a@x.com'})")
        .await
        .expect_err("enforced before drop");

    engine
        .constraint_ddl(ConstraintCommand::Drop {
            name: "uniq_email".to_owned(),
        })
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
            .constraint_ddl(create_unique("uniq_email", "Person", "email"))
            .await
            .expect("create unique");
        engine
            .constraint_ddl(create_existence("name_exists", "Person", "name"))
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
