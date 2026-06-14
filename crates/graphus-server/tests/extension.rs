//! End-to-end test for the **compiled-in extension mechanism** over a real booted server (`rmp`
//! task #75).
//!
//! The engine registers its sample extensions at boot (`exec::install_extensions`): a scalar UDF
//! `ext.double(n)` and a UDP `ext.range(a, b) YIELD value`. This boots the server in-process over a
//! fresh tempdir data root (UDS-only listener) and proves both are callable through the engine's
//! `Run` path — the same path every Bolt/REST statement takes — so the extension wiring works
//! against the real storage backend, not just in unit tests.

use std::path::PathBuf;

use graphus_core::Value;
use graphus_cypher::MaterializedValue;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::engine::{AccessMode, EngineHandle};
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
            "graphus-extension-{tag}-{nanos}-{}",
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
        jwt_secret: "extension-itest-jwt-secret-uds-only!!".to_owned(),
        auth: AuthBootstrap {
            admin_user: "alice".to_owned(),
            admin_password: "admin-pw8".to_owned(),
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

/// Runs one auto-commit statement and returns its rows (each cell as a [`MaterializedValue`]).
async fn run(handle: &EngineHandle, query: &str) -> Vec<Vec<MaterializedValue>> {
    let ticket = handle
        .begin_auto_commit(AccessMode::Write)
        .await
        .expect("begin auto-commit");
    let reply = handle
        .run(ticket, query.to_owned(), Vec::new(), true, None)
        .await
        .expect("run");
    tokio::task::spawn_blocking(move || {
        let mut rx = reply.rows;
        let mut rows = Vec::new();
        loop {
            match rx.next() {
                Ok(Some(row)) => rows.push(row),
                Ok(None) => break,
                Err(e) => panic!("row stream error: {e}"),
            }
        }
        rows
    })
    .await
    .expect("drain")
}

/// The scalar value of a single-row single-column result, or panics on a different shape.
fn scalar(rows: &[Vec<MaterializedValue>]) -> &Value {
    assert_eq!(rows.len(), 1, "expected one row, got {}", rows.len());
    assert_eq!(rows[0].len(), 1, "expected one column");
    match &rows[0][0] {
        MaterializedValue::Value(v) => v,
        other => panic!("expected a scalar value, got {other:?}"),
    }
}

#[tokio::test]
async fn compiled_in_scalar_udf_runs_through_the_engine() {
    let temp = TempStore::new("udf");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // `ext.double` is registered at engine boot — callable through the normal Run path.
    let rows = run(&engine, "RETURN ext.double(21) AS v").await;
    assert_eq!(scalar(&rows), &Value::Integer(42));

    // It composes with built-ins.
    let rows = run(&engine, "RETURN ext.double(3) + abs(-4) AS v").await;
    assert_eq!(scalar(&rows), &Value::Integer(10));

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn compiled_in_udp_runs_through_the_engine() {
    let temp = TempStore::new("udp");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // `ext.range(1, 3) YIELD value` is registered at engine boot — yields rows 1, 2, 3.
    let rows = run(&engine, "CALL ext.range(1, 3) YIELD value RETURN value").await;
    let got: Vec<Value> = rows
        .iter()
        .map(|r| match &r[0] {
            MaterializedValue::Value(v) => v.clone(),
            other => panic!("expected scalar, got {other:?}"),
        })
        .collect();
    assert_eq!(
        got,
        vec![Value::Integer(1), Value::Integer(2), Value::Integer(3)]
    );

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn builtins_still_work_alongside_extensions() {
    // Regression: registering extensions does not disturb built-in resolution through the engine.
    let temp = TempStore::new("builtins");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    let rows = run(&engine, "RETURN abs(-5) AS a").await;
    assert_eq!(scalar(&rows), &Value::Integer(5));

    let rows = run(&engine, "RETURN size([1, 2, 3]) AS s").await;
    assert_eq!(scalar(&rows), &Value::Integer(3));

    handle.shutdown().await.expect("graceful shutdown");
}
