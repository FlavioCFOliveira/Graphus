//! End-to-end multi-database tests (decision `D-multi-db`, rmp #83): the crash-safe database
//! catalog + per-database engine runtime, driven through a **real booted server**.
//!
//! Each test boots the server in-process over a fresh tempdir data root (UDS-only listener: no
//! TLS, no network), then drives the per-database [`EngineHandle`]s directly — the same client API
//! the Bolt/REST seams submit through (the wire-level admin surface is rmp #84). Covered:
//!
//! - **Isolation**: two databases hold fully independent data (each is its own `RecordStore`).
//! - **Restart/recovery**: writes to both databases survive a full server shutdown + reboot
//!   (per-database WAL recovery), and the catalog lists both afterwards.
//! - **Backward compatibility**: a data dir laid out the old single-db way (`graphus.store` +
//!   `graphus.wal`, no `databases.toml`) boots with just the default database — and a server that
//!   never creates an additional database never writes the catalog file at all.
//! - **Lifecycle over a live server**: create → stop → start (data survives) → stop → drop
//!   (directory removed); drop-while-online rejected.

use std::path::PathBuf;
use std::sync::Arc;

use graphus_core::Value;
use graphus_cypher::MaterializedValue;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::engine::{AccessMode, EngineHandle};
use graphus_server::{DbState, Server, ServerHandle};

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
            "graphus-multidb-{tag}-{nanos}-{}",
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

/// A UDS-only config (no network listener ⇒ no TLS / JWT secret needed) over `temp`'s store dir.
fn multi_db_config(temp: &TempStore) -> ServerConfig {
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
        // No network listener is enabled, so the insecure default secret is fine (and unused).
        jwt_secret: "multidb-itest-jwt-secret-uds-only!!!".to_owned(),
        auth: AuthBootstrap {
            admin_user: "alice".to_owned(),
            admin_password: "admin-pw8".to_owned(),
            admin_uid: None,
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: graphus_server::AuditConfig::default(),
        allow_insecure_network: false,
        metrics_scrape_token: None,
    }
}

/// Boots a server from `config` and returns its handle once ready.
async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

/// Flattens each result-row cell to a scalar [`Value`] for the property-only assertion path, the
/// way the old server `project_value` did: a graph entity (which a bound-variable `CREATE`/`MATCH`
/// streams back even with no `RETURN`) collapses to its id, a path to the list of its element ids
/// in traversal order, and a structural list element-wise. These multi-db/scalar tests assert only
/// on scalars; the entity ids are inert here.
fn scalar_row(values: Vec<MaterializedValue>) -> Vec<Value> {
    values.into_iter().map(materialized_to_scalar).collect()
}

/// Flattens one [`MaterializedValue`] cell to a scalar [`Value`] (entity → id, path → list of
/// element ids in traversal order, list → element-wise).
#[expect(
    clippy::cast_possible_wrap,
    reason = "entity ids are well within i64; this mirrors the old project_value flattening"
)]
fn materialized_to_scalar(v: MaterializedValue) -> Value {
    match v {
        MaterializedValue::Value(val) => val,
        MaterializedValue::Node(n) => Value::Integer(n.id as i64),
        MaterializedValue::Relationship(r) => Value::Integer(r.id as i64),
        MaterializedValue::Path(p) => {
            let mut ids = Vec::with_capacity(p.steps.len() * 2 + 1);
            ids.push(Value::Integer(p.start.id as i64));
            for step in &p.steps {
                ids.push(Value::Integer(step.rel.id as i64));
                ids.push(Value::Integer(step.node.id as i64));
            }
            Value::List(ids)
        }
        MaterializedValue::List(items) => {
            Value::List(items.into_iter().map(materialized_to_scalar).collect())
        }
    }
}

/// Runs one auto-commit statement against `handle` and returns all result rows. The row stream is
/// drained on a blocking task (`RowReceiver::next` blocks by design — `04 §9.1`); draining it is
/// what commits the auto-commit transaction.
async fn run_query(handle: &EngineHandle, query: &str) -> Vec<Vec<Value>> {
    let ticket = handle
        .begin_auto_commit(AccessMode::Write)
        .await
        .expect("begin auto-commit");
    let reply = handle
        // `None` privileges: the test harness runs unrestricted (no RBAC enforcement, rmp #93).
        .run(ticket, query.to_owned(), Vec::new(), true, None)
        .await
        .expect("run statement");
    tokio::task::spawn_blocking(move || {
        let mut rx = reply.rows;
        let mut rows = Vec::new();
        loop {
            match rx.next() {
                Ok(Some(row)) => rows.push(scalar_row(row)),
                Ok(None) => break,
                Err(e) => panic!("row stream error: {e}"),
            }
        }
        rows
    })
    .await
    .expect("drain rows")
}

/// Runs a single-row, single-column integer query (e.g. a `count(...)`) and returns the integer.
async fn count(handle: &EngineHandle, query: &str) -> i64 {
    let rows = run_query(handle, query).await;
    assert_eq!(rows.len(), 1, "count query returns exactly one row");
    match rows[0].first() {
        Some(Value::Integer(n)) => *n,
        other => panic!("expected an integer count, got {other:?}"),
    }
}

// ------------------------------------------------------------------------------------------------
// Isolation: two databases are fully independent stores.
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn two_databases_hold_independent_data() {
    let temp = TempStore::new("isolation");
    let handle = boot(multi_db_config(&temp)).await;

    let analytics = handle
        .catalog
        .create("analytics")
        .await
        .expect("create second database");
    let default_db = handle.engine.clone();

    // Write a differently-labelled node into each database.
    run_query(&default_db, "CREATE (:DefaultOnly {marker: 1})").await;
    run_query(&analytics, "CREATE (:AnalyticsOnly {marker: 2})").await;

    // Each database sees its own data — and nothing of the other's.
    assert_eq!(
        count(&default_db, "MATCH (n:DefaultOnly) RETURN count(n)").await,
        1
    );
    assert_eq!(
        count(&default_db, "MATCH (n:AnalyticsOnly) RETURN count(n)").await,
        0
    );
    assert_eq!(
        count(&analytics, "MATCH (n:AnalyticsOnly) RETURN count(n)").await,
        1
    );
    assert_eq!(
        count(&analytics, "MATCH (n:DefaultOnly) RETURN count(n)").await,
        0
    );

    // The lookup registry serves both, case-insensitively.
    assert!(handle.catalog.handle("ANALYTICS").is_some());
    assert!(handle.catalog.handle("graphus").is_some());
    assert!(handle.catalog.handle("missing").is_none());

    handle.shutdown().await.expect("graceful shutdown");
}

// ------------------------------------------------------------------------------------------------
// Restart/recovery: both databases survive a full server restart (per-db WAL recovery).
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn both_databases_recover_after_restart() {
    let temp = TempStore::new("restart");
    let config = multi_db_config(&temp);

    // Boot #1: create the second database and write to both.
    {
        let handle = boot(config.clone()).await;
        let analytics = handle.catalog.create("analytics").await.expect("create");
        run_query(&handle.engine, "CREATE (:DefaultData {v: 1})").await;
        run_query(&analytics, "CREATE (:AnalyticsData {v: 2})").await;
        handle.shutdown().await.expect("graceful shutdown");
    }

    // The catalog file persisted the second database.
    assert!(temp.store_dir().join("databases.toml").exists());

    // Boot #2: the catalog lists both, both are online, and both recovered their data.
    let handle = boot(config).await;
    let infos = handle.catalog.list().await;
    assert_eq!(infos.len(), 2);
    assert!(infos[0].is_default);
    assert_eq!(infos[0].state, DbState::Online);
    assert_eq!(infos[1].name, "analytics");
    assert_eq!(infos[1].state, DbState::Online);
    assert_eq!(infos[1].error, None);

    let analytics = handle
        .catalog
        .handle("analytics")
        .expect("analytics is online after restart");
    assert_eq!(
        count(&handle.engine, "MATCH (n:DefaultData) RETURN count(n)").await,
        1
    );
    assert_eq!(
        count(&analytics, "MATCH (n:AnalyticsData) RETURN count(n)").await,
        1
    );
    // Isolation also holds after recovery.
    assert_eq!(
        count(&analytics, "MATCH (n:DefaultData) RETURN count(n)").await,
        0
    );

    handle.shutdown().await.expect("graceful shutdown");
}

// ------------------------------------------------------------------------------------------------
// Backward compatibility: the old single-db layout boots unchanged with just the default database.
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn old_single_database_layout_boots_unchanged() {
    let temp = TempStore::new("backcompat");
    let config = multi_db_config(&temp);

    // Boot #1 produces exactly the pre-multi-db layout: a server that never creates an additional
    // database never writes `databases.toml` (or a `databases/` dir).
    {
        let handle = boot(config.clone()).await;
        run_query(&handle.engine, "CREATE (:Legacy {v: 42})").await;
        handle.shutdown().await.expect("graceful shutdown");
    }
    assert!(temp.store_dir().join("graphus.store").exists());
    assert!(temp.store_dir().join("graphus.wal").exists());
    assert!(
        !temp.store_dir().join("databases.toml").exists(),
        "no catalog file in a single-db deployment (the old layout)"
    );
    assert!(
        !temp.store_dir().join("databases").exists(),
        "no databases/ dir in a single-db deployment"
    );

    // Boot #2 over that old layout: zero migration, the default database only, data intact.
    let handle = boot(config).await;
    let infos = handle.catalog.list().await;
    assert_eq!(infos.len(), 1, "just the default database");
    assert!(infos[0].is_default);
    assert_eq!(infos[0].state, DbState::Online);
    assert_eq!(
        count(&handle.engine, "MATCH (n:Legacy) RETURN count(n)").await,
        1
    );

    handle.shutdown().await.expect("graceful shutdown");
}

// ------------------------------------------------------------------------------------------------
// Lifecycle over a live server: create → stop → start (data survives) → stop → drop.
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn lifecycle_stop_start_preserves_data_and_drop_removes_it() {
    let temp = TempStore::new("lifecycle");
    let handle = boot(multi_db_config(&temp)).await;
    let catalog = Arc::clone(&handle.catalog);

    let scratch = catalog.create("scratch").await.expect("create");
    run_query(&scratch, "CREATE (:Kept {v: 7})").await;
    drop(scratch);

    // Stop: the handle disappears from the registry; the data dir stays.
    catalog.stop("scratch").await.expect("stop");
    assert!(catalog.handle("scratch").is_none());
    let dir = temp.store_dir().join("databases").join("scratch");
    assert!(dir.join("graphus.store").exists(), "stopped ≠ deleted");

    // Start: the store reopens (WAL recovery + verify) and the data is still there.
    let scratch = catalog.start("scratch").await.expect("start");
    assert_eq!(count(&scratch, "MATCH (n:Kept) RETURN count(n)").await, 1);
    drop(scratch);

    // Drop while online is rejected; stop first, then drop deletes the directory.
    assert!(catalog.drop_database("scratch").await.is_err());
    catalog.stop("scratch").await.expect("stop before drop");
    catalog.drop_database("scratch").await.expect("drop");
    assert!(!dir.exists(), "drop removes the database directory");
    assert_eq!(catalog.list().await.len(), 1, "only the default remains");

    handle.shutdown().await.expect("graceful shutdown");
}

// ------------------------------------------------------------------------------------------------
// Boot resilience: one failing secondary database never takes the server down (storage audit).
// ------------------------------------------------------------------------------------------------

/// Boot with a corrupt secondary store: the server must start, report the failed database (with
/// its error) via the catalog listing, and leave the durable desired state (`online`) untouched —
/// so a later boot, after repair, retries it.
#[tokio::test]
async fn boot_survives_a_corrupt_secondary_database() {
    let temp = TempStore::new("corrupt-secondary");
    let config = multi_db_config(&temp);

    // Boot #1: create the secondary, write to it, shut down cleanly.
    {
        let handle = boot(config.clone()).await;
        let flaky = handle.catalog.create("flaky").await.expect("create");
        run_query(&flaky, "CREATE (:Doomed {v: 1})").await;
        drop(flaky);
        handle.shutdown().await.expect("graceful shutdown");
    }

    // Corrupt the secondary's store file: garbage, not even a whole number of pages.
    let store = temp
        .store_dir()
        .join("databases")
        .join("flaky")
        .join("graphus.store");
    std::fs::write(&store, [0xFF_u8; 1000]).expect("corrupt the store");

    // Boot #2 must succeed: the default serves; flaky is reported failed, desired still online.
    let handle = boot(config).await;
    assert!(
        handle.catalog.handle("flaky").is_none(),
        "the corrupt database is not serving"
    );
    let infos = handle.catalog.list().await;
    let flaky = infos
        .iter()
        .find(|i| i.name == "flaky")
        .expect("the failed database is still listed");
    assert_eq!(flaky.state, DbState::Offline, "actual: not running");
    assert_eq!(
        flaky.desired,
        DbState::Online,
        "a boot failure never flips the durable intent"
    );
    assert!(
        flaky.error.is_some(),
        "the startup error is reported: {flaky:?}"
    );
    // `rmp` #430 GATE: a non-default database failing to open flips a degraded readiness SIGNAL, so an
    // orchestrator can tell a configured database is not serving (previously readiness stayed
    // unconditionally green, hiding the failure). The count is surfaced lock-free for `/health/ready`.
    assert_eq!(
        handle.catalog.failed_open_database_count(),
        1,
        "exactly one configured (non-default) database failed to open — the degraded signal is set"
    );
    // The default database is fully functional.
    assert_eq!(count(&handle.engine, "MATCH (n) RETURN count(n)").await, 0);

    // Reload-and-assert at the file level: the durable desired state still says online.
    let text =
        std::fs::read_to_string(temp.store_dir().join("databases.toml")).expect("catalog file");
    assert!(text.contains("name = \"flaky\""), "catalog file: {text}");
    assert!(text.contains("state = \"online\""), "catalog file: {text}");

    handle.shutdown().await.expect("graceful shutdown");
}

/// The crashed-create window: `databases.toml` claims a database `online` whose directory does
/// not exist (a crash right after create's persist, before the engine ever started). The next
/// boot simply creates a fresh empty store under that name (module docs of `dbcatalog`).
#[tokio::test]
async fn boot_creates_a_fresh_store_for_an_online_entry_without_a_directory() {
    let temp = TempStore::new("crashed-create");
    let config = multi_db_config(&temp);

    // Plant exactly what a crash between create's persist and its engine spawn leaves behind:
    // a valid catalog naming an online database, and no directory for it.
    std::fs::create_dir_all(temp.store_dir()).expect("store dir");
    std::fs::write(
        temp.store_dir().join("databases.toml"),
        "version = 1\n\n[[databases]]\nname = \"phantom\"\nstate = \"online\"\n",
    )
    .expect("plant catalog");
    assert!(!temp.store_dir().join("databases").exists());

    let handle = boot(config).await;
    let phantom = handle
        .catalog
        .handle("phantom")
        .expect("phantom comes online at boot");
    assert!(
        temp.store_dir()
            .join("databases")
            .join("phantom")
            .join("graphus.store")
            .exists(),
        "a fresh store was created under the claimed name"
    );
    assert_eq!(
        count(&phantom, "MATCH (n) RETURN count(n)").await,
        0,
        "fresh and empty"
    );
    drop(phantom);

    handle.shutdown().await.expect("graceful shutdown");
}

// ------------------------------------------------------------------------------------------------
// rmp #418: the server-wide active-transactions gauge is a SUM across databases, not last-writer-wins.
// ------------------------------------------------------------------------------------------------

/// `rmp` #418: before the fix each engine published its open-transaction count with a last-writer-wins
/// `store`, so under multi-DB the gauge reflected whichever engine published last — a finished txn on
/// DB `b` would clobber a still-open (leaked) txn on DB `a` back to zero, making the `rmp` #386 leak
/// oracle ("a return to zero proves no leak") unsound. With the additive gauge, an open txn on `a`
/// summed with a finished txn on `b` leaves the gauge `>= 1`.
#[tokio::test]
async fn active_txn_gauge_sums_across_databases() {
    let temp = TempStore::new("active-txn-sum");
    let server = boot(multi_db_config(&temp)).await;
    let metrics = server.metrics.clone();
    let db_a = server.engine.clone();
    let db_b = server
        .catalog
        .create("tenant_b")
        .await
        .expect("create tenant_b");

    // Leak an OPEN explicit transaction on DB `a` (begun, never committed/rolled back). DB `a`'s
    // engine publishes its count (+1) additively into the server-wide gauge.
    let leaked = db_a
        .begin(AccessMode::Write)
        .await
        .expect("begin a leaked transaction on db a");

    // Run + finish a full auto-commit transaction on DB `b`. Pre-#418 its engine's final publish of
    // `active_count == 0` would `store(0)` over the shared gauge, masking `a`'s open txn.
    run_query(&db_b, "CREATE (:OnB {x: 1})").await;

    // THE KEY ASSERTION (`rmp` #418): the gauge reflects the SUM — `a`'s one open txn survives `b`'s
    // publish. (It is exactly 1 here: `b` finished and retracted its contribution; `a` still holds one.)
    assert!(
        metrics.active_txns() >= 1,
        "the active-transaction gauge must SUM across databases (a's open txn must survive b's finish), \
         got {}",
        metrics.active_txns()
    );

    // Close the leaked txn; the gauge then returns to zero (no real leak), proving the additive
    // bookkeeping balances.
    db_a.rollback(leaked)
        .await
        .expect("rollback the leaked txn");
    // The rollback reply is sent after the engine republishes its count, so the gauge is settled.
    assert_eq!(
        metrics.active_txns(),
        0,
        "once a's txn is rolled back the server-wide gauge nets to zero"
    );

    server.shutdown().await.expect("graceful shutdown");
}

// ------------------------------------------------------------------------------------------------
// rmp #427: a stale EngineHandle held across stop → drop → recreate can never touch the new store.
// ------------------------------------------------------------------------------------------------

/// `rmp` #427: `DatabaseCatalog::handle` hands out a cloned `EngineHandle` without the admin lock, so a
/// caller could hold one across a `stop` + `drop` + re-`create` of the same name. `stop_engine`
/// **unpublishes the lookup handle, then drains + joins** the engine before the directory is reused, so
/// the stale handle's command channel is already closed by the time a new store exists under the name.
/// This pins that join-before-remove isolation: a stale handle errors cleanly (`engine_gone`) and never
/// reaches the freshly-created store (proven by the new store staying empty + a fresh handle seeing the
/// new data only).
#[tokio::test]
async fn stale_handle_after_drop_recreate_cannot_touch_new_store() {
    let temp = TempStore::new("stale-handle");
    let handle = boot(multi_db_config(&temp)).await;

    // Create `reused`, write a node, capture a STALE handle clone, then take it fully offline.
    let _ = handle
        .catalog
        .create("reused")
        .await
        .expect("create reused");
    let stale = handle
        .catalog
        .handle("reused")
        .expect("handle while online");
    run_query(&stale, "CREATE (:Gen1 {v: 1})").await;
    assert_eq!(count(&stale, "MATCH (n) RETURN count(n)").await, 1);

    handle.catalog.stop("reused").await.expect("stop reused");
    handle
        .catalog
        .drop_database("reused")
        .await
        .expect("drop reused");

    // Re-create the same name: a brand-new, empty store under the (reused) directory + a NEW engine.
    let fresh = handle
        .catalog
        .create("reused")
        .await
        .expect("recreate reused");
    assert_eq!(
        count(&fresh, "MATCH (n) RETURN count(n)").await,
        0,
        "the recreated store is fresh and empty (Gen1's data must not resurrect)"
    );

    // THE KEY ASSERTION (`rmp` #427): the STALE handle (from the dropped generation) is now wired to a
    // joined-and-gone engine thread. Using it errors cleanly — it never touches the new store.
    let stale_run = stale.begin_auto_commit(AccessMode::Write).await.and(Ok(()));
    assert!(
        stale_run.is_err(),
        "the stale handle must error (its engine was joined before the dir was reused), never touch \
         the new store"
    );

    // The new store is still empty: the stale handle's attempt left no trace on it.
    assert_eq!(
        count(&fresh, "MATCH (n) RETURN count(n)").await,
        0,
        "the freshly-created store is untouched by the stale handle"
    );

    handle.shutdown().await.expect("graceful shutdown");
}

// ------------------------------------------------------------------------------------------------
// rmp #423: secondary indexes are REBUILT from the store on open, never verified against a durable
// index image — so the empty index slice passed to `verify_on_open` cannot mask a divergence.
// ------------------------------------------------------------------------------------------------

/// `rmp` #423: `open_or_create_coordinator` calls `verify_on_open(&mut store, &[])` — an empty
/// index/base divergence slice. That is correct precisely because every Graphus secondary index is
/// **in-memory and rebuilt from the store on each open** (`TxnCoordinator::new`), never persisted as a
/// separate durable image that could diverge. This test pins that contract: a node-property index +
/// data created on one boot is fully functional after a shutdown + reopen (the index was rebuilt — an
/// indexed lookup returns the right rows), and no separate durable index file exists beside the store.
#[tokio::test]
async fn secondary_indexes_are_rebuilt_not_verified_on_open() {
    let temp = TempStore::new("index-rebuilt");
    let config = multi_db_config(&temp);

    // Boot #1: declare an index, seed indexed data, shut down cleanly (the index is in-memory only).
    {
        let handle = boot(config.clone()).await;
        // Index DDL is a control command (not a query): submit it via the engine's `index_ddl` seam.
        handle
            .engine
            .index_ddl(
                graphus_server::engine::command::IndexCommand::CreateNodePropertyIndex {
                    label: "Person".to_owned(),
                    property: "email".to_owned(),
                },
            )
            .await
            .expect("create node-property index");
        run_query(&handle.engine, "CREATE (:Person {email: 'a@x'})").await;
        run_query(&handle.engine, "CREATE (:Person {email: 'b@x'})").await;
        handle.shutdown().await.expect("graceful shutdown");
    }

    // No separate durable secondary-index file was written beside the default store: the index is
    // rebuilt from the store, so there is no persisted image to verify (or to diverge).
    let store_dir = temp.store_dir();
    for entry in std::fs::read_dir(&store_dir).expect("read store dir") {
        let name = entry.expect("dir entry").file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.contains("index") && !name.ends_with(".idx"),
            "no durable secondary-index image must exist (indexes are rebuilt on open), found {name:?}"
        );
    }

    // Boot #2 over the SAME store dir: opening runs `verify_on_open(&[])` then `TxnCoordinator::new`
    // rebuilds the index from the store. The index must be live — an indexed lookup returns the right
    // rows, proving it was reconstructed, not read from (a possibly-divergent) persisted image.
    {
        let handle = boot(config).await;
        assert_eq!(
            count(
                &handle.engine,
                "MATCH (p:Person) WHERE p.email = 'a@x' RETURN count(p)",
            )
            .await,
            1,
            "the index was rebuilt on open and the indexed lookup is correct"
        );
        assert_eq!(
            count(&handle.engine, "MATCH (p:Person) RETURN count(p)").await,
            2,
            "all rows survive the reopen"
        );
        handle.shutdown().await.expect("graceful shutdown");
    }
}
