//! **Multi-tenant engine-degradation isolation gate** (`rmp` #414).
//!
//! Before #414 the engine-degraded flag lived on the single `Arc<Metrics>` shared by every
//! per-database engine, so the moment ONE database's engine caught a recovery double-panic
//! (`rmp` #409), the per-statement gate refused work on **every** database — a multi-tenant
//! isolation breach (one corrupt secondary database took the whole server down, violating the
//! `CLAUDE.md` guarantee that one corrupt secondary database can never take down the rest).
//!
//! This gate boots a real server with a default database plus a created secondary database `tenant_a`,
//! trips `tenant_a`'s recovery-degraded path (the #409 double-panic scenario, via the
//! `internal-test-udf` `ext.panic` seam + the `arm_recovery_fault` fault injector), and asserts:
//!
//! * `tenant_a` refuses further work with the clean engine-degraded error (its own gate fired);
//! * a query on the **default** database still **SUCCEEDS** (it was never touched by `tenant_a`'s
//!   degradation — the per-engine flag confined the refusal);
//! * the catalog's per-database readiness aggregation **distinguishes** them: `degraded_databases()`
//!   names `tenant_a`, while `default_database_degraded()` stays `false`.
//!
//! Gated on the opt-in `internal-test-udf` feature (which registers the `ext.panic` UDF + the
//! recovery-fault seam): run with `cargo test -p graphus-server --features internal-test-udf --test
//! multi_db_engine_isolation`.
#![cfg(feature = "internal-test-udf")]

use std::path::PathBuf;

use graphus_core::Value;
use graphus_cypher::MaterializedValue;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, EncryptionConfig, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::engine::{AccessMode, EngineHandle};
use graphus_server::{AuditConfig, Server, ServerHandle};

/// A unique temp directory for one test's data root (auto-removed on drop).
struct TempStore {
    path: PathBuf,
}

impl TempStore {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        path.push(format!(
            "graphus-degrade-iso-{tag}-{nanos}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A UDS-only config (no network listener ⇒ no TLS / JWT secret needed) over `temp`'s store dir.
fn config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.path.join("store"),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        rest_addr: None,
        uds_path: Some(temp.path.join("graphus.sock")),
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
        jwt_secret: "degrade-iso-itest-jwt-secret-uds!!!".to_owned(),
        auth: AuthBootstrap {
            admin_user: "alice".to_owned(),
            admin_password: "admin-pw8".to_owned(),
            admin_uid: None,
            users: Vec::new(),
        },
        encryption: EncryptionConfig::default(),
        audit: AuditConfig::default(),
        allow_insecure_network: false,
        metrics_scrape_token: None,
    }
}

async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

/// Runs one auto-commit WRITE statement and returns `Ok(rows)` on a clean commit or `Err(message)` if
/// the statement failed at the reply stage (e.g. a degraded engine's clean error). A WRITE auto-commit
/// runs **inline on the engine thread** (a Read would dispatch off-thread), which is what lets the
/// `ext.panic` statement reach the engine-thread recovery rollback the fault injector targets.
async fn run_write(handle: &EngineHandle, query: &str) -> Result<Vec<Vec<Value>>, String> {
    let ticket = handle
        .begin_auto_commit(AccessMode::Write)
        .await
        .map_err(|e| e.to_string())?;
    let reply = handle
        .run(ticket, query.to_owned(), Vec::new(), true, None)
        .await
        .map_err(|e| e.to_string())?;
    tokio::task::spawn_blocking(move || {
        let mut rx = reply.rows;
        let mut rows = Vec::new();
        loop {
            match rx.next() {
                Ok(Some(row)) => rows.push(
                    row.into_iter()
                        .map(|v| match v {
                            MaterializedValue::Value(val) => val,
                            other => Value::String(format!("{other:?}")),
                        })
                        .collect::<Vec<_>>(),
                ),
                Ok(None) => return Ok(rows),
                Err(e) => return Err(e.to_string()),
            }
        }
    })
    .await
    .expect("drain task joins")
}

/// `rmp` #414: tripping one database's recovery-degraded path must NOT disable the others.
#[tokio::test]
async fn one_degraded_database_does_not_disable_the_rest() {
    let temp = TempStore::new("isolation");
    let handle = boot(config(&temp)).await;
    let catalog = handle.catalog.clone();
    let default_db = handle.engine.clone();

    // A created secondary database `tenant_a` (its own independent engine + store).
    let tenant_a = catalog.create("tenant_a").await.expect("create tenant_a");

    // Both databases are healthy and serviceable to start.
    run_write(&default_db, "CREATE (:Probe {v: 1})")
        .await
        .expect("default db healthy seed commits");
    run_write(&tenant_a, "CREATE (:Probe {v: 1})")
        .await
        .expect("tenant_a healthy seed commits");
    assert!(
        catalog.degraded_databases().is_empty(),
        "no engine starts degraded"
    );
    assert!(!catalog.default_database_degraded());
    assert_eq!(catalog.failed_open_database_count(), 0);

    // Silence the deliberate panic's default hook so it does not spam the test log.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    // Arm the recovery fault so the rollback recovering tenant_a's next (panicking) statement ALSO
    // panics — the #409 recovery double-panic — and drive that panicking WRITE on tenant_a ONLY. The
    // fault static is process-global, but we consume it immediately on tenant_a and never arm it for
    // the default database, so only tenant_a's engine degrades.
    graphus_server::engine::arm_recovery_fault(1);
    let _ = run_write(
        &tenant_a,
        "MATCH (p:Probe) SET p.v = ext.panic(p.v) RETURN p.v",
    )
    .await;

    std::panic::set_hook(prev_hook);

    // tenant_a is now degraded and refuses further work with the clean engine-degraded error.
    let a_after = run_write(&tenant_a, "MATCH (p:Probe) RETURN count(p)").await;
    let a_msg = a_after.expect_err("tenant_a must refuse further work once degraded");
    assert!(
        a_msg.contains("engine degraded"),
        "tenant_a must serve the clean engine-degraded error, got: {a_msg}"
    );
    assert!(
        !a_msg.contains("engine unavailable"),
        "must NOT be engine_gone (a dead thread), got: {a_msg}"
    );

    // THE KEY ISOLATION ASSERTION (`rmp` #414): the DEFAULT database still SUCCEEDS — tenant_a's
    // degradation did not disable it. Before #414 this query would have been refused by the shared gate.
    let rows = run_write(&default_db, "MATCH (p:Probe) RETURN count(p)")
        .await
        .expect("the default database must still serve queries while tenant_a is degraded");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].first(), Some(&Value::Integer(1)));

    // Readiness DISTINGUISHES them (`rmp` #414): the per-database aggregation names the degraded
    // secondary (tenant_a) while the default database stays healthy.
    assert_eq!(
        catalog.degraded_databases(),
        vec!["tenant_a".to_owned()],
        "the degraded-database aggregation must name exactly tenant_a"
    );
    assert!(
        !catalog.default_database_degraded(),
        "the default database must NOT be flagged degraded — only tenant_a is"
    );

    handle.shutdown().await.expect("graceful shutdown");
}
