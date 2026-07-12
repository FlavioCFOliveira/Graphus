//! End-to-end tests for the offline-import → adopt → serve path (`rmp` #681): a `graphus-bulk`
//! offline-imported store is made directly servable by `graphus-server`, and — when the import opted
//! into `--persist-id` — queryable by the original CSV `:ID`.
//!
//! The flow each test exercises is the genuine, user-reproducible one:
//!
//! 1. **Offline import** — an `<import>/graph.store` + `graph.wal/` is built with the `graphus-bulk`
//!    importer (the crate the binary drives), with the opt-in `--persist-id` so each node keeps its
//!    external `:ID` as a queryable string property.
//! 2. **Adopt** — the **real `graphus-server` binary** (`CARGO_BIN_EXE_graphus-server`) `adopt`
//!    subcommand relocates the store into the server's servable layout (a named database under
//!    `databases/<name>/` + a `databases.toml` entry, or the default database in the data root) and
//!    verifies it opens/recovers/verifies before registering it.
//! 3. **Serve** — the server is booted **in-process** over that data root (the established
//!    multi-database test harness) and the adopted data is queried, including **by original id**.
//! 4. **Durability** — a full shutdown + reboot re-serves the adopted database from its own WAL
//!    recovery, proving an adopted store is a first-class, crash-safe, ACID database.

use std::path::{Path, PathBuf};
use std::process::Command;

use graphus_bulk::BulkImporter;
use graphus_core::Value;
use graphus_cypher::MaterializedValue;
use graphus_io::FileBlockDevice;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::engine::{AccessMode, EngineHandle};
use graphus_server::{DbState, Server, ServerHandle};
use graphus_storage::RecordStore;
use graphus_wal::{FileLogSink, WalManager};

// ------------------------------------------------------------------------------------------------
// Temp dirs + a small deterministic dataset
// ------------------------------------------------------------------------------------------------

/// A unique temp directory (auto-removed on drop) holding one test's import dir + data root.
struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "graphus-adopt-{tag}-{nanos}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    /// The offline-import artifact directory (`graph.store` + `graph.wal/`).
    fn import_dir(&self) -> PathBuf {
        self.path.join("import")
    }

    /// The server data root the adopt lands into and the in-process server serves from.
    fn data_root(&self) -> PathBuf {
        self.path.join("data")
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The node CSV: a NAMED `:ID` column (`personId:ID`) so `--persist-id` records the external id as the
/// queryable string property `personId`.
const NODES_CSV: &str = "personId:ID,:LABEL,name:string,age:int\np1,Person,Alice,30\np2,Person,Bob,41\np3,Person,Cara,25\n";

/// The relationship CSV: joins on the same external ids.
const RELS_CSV: &str = ":START_ID,:END_ID,:TYPE,since:int\np1,p2,KNOWS,2015\np2,p3,KNOWS,2019\n";

/// Builds an offline import artifact at `import_dir` (a real file-backed `graph.store`/`graph.wal/`)
/// using the `graphus-bulk` importer with `--persist-id`. This is the exact code path the
/// `graphus-bulk import --persist-id` binary drives (the binary is a thin CLI over this crate); the
/// `CARGO_BIN_EXE_graphus-bulk` binary is not visible to `graphus-server`'s own test harness, so the
/// import is driven through the shared library while the ADOPT step under test runs the real binary.
fn offline_import_with_persist_id(import_dir: &Path) {
    std::fs::create_dir_all(import_dir).expect("create import dir");
    let device_file = import_dir.join(graphus_bulk::IMPORT_STORE_FILE_NAME);
    let wal_file = import_dir.join(graphus_bulk::IMPORT_WAL_DIR_NAME);

    let device = FileBlockDevice::open(&device_file).expect("open device");
    let wal = WalManager::create(FileLogSink::open(&wal_file).expect("open wal sink"))
        .expect("create wal");
    let store = RecordStore::create(device, wal, 256, 1).expect("create store");

    let mut importer = BulkImporter::new(store, 10_000, b',').with_persist_id(true);
    importer
        .import_nodes(NODES_CSV.as_bytes())
        .expect("import nodes");
    importer
        .import_relationships(RELS_CSV.as_bytes())
        .expect("import rels");
    let (mut store, _stats) = importer.finish();
    store.flush().expect("flush store");
    // Harden the import directory entries so the store/WAL files are findable (mirrors the CLI's
    // durable-create barrier).
    graphus_io::sync_dir(import_dir).expect("sync import dir");
}

// ------------------------------------------------------------------------------------------------
// The real `graphus-server adopt` binary
// ------------------------------------------------------------------------------------------------

/// Writes a minimal server config TOML pinning the data root + default database, so the adopt binary
/// and the in-process server agree on where the servable store lives.
fn write_config(root: &Path, data_root: &Path) -> PathBuf {
    let cfg = root.join("adopt-config.toml");
    let toml = format!(
        "store_path = {:?}\ndefault_database = \"graphus\"\n",
        data_root.to_string_lossy()
    );
    std::fs::write(&cfg, toml).expect("write config");
    cfg
}

/// Runs `graphus-server adopt <args…>` (the real binary) and asserts it succeeds, returning its
/// stdout for the caller to inspect. Panics with the captured stderr on failure.
fn run_adopt(args: &[&str]) -> String {
    let bin = env!("CARGO_BIN_EXE_graphus-server");
    let output = Command::new(bin)
        .arg("adopt")
        .args(args)
        .output()
        .expect("spawn graphus-server adopt");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "graphus-server adopt failed (status {:?})\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        output.status.code()
    );
    stdout
}

// ------------------------------------------------------------------------------------------------
// In-process server harness (mirrors the multi-database E2E)
// ------------------------------------------------------------------------------------------------

/// A UDS-only server config over `data_root` (no network listener ⇒ no TLS / usable JWT secret
/// needed). Matches the store_path the adopt binary was pointed at.
fn serve_config(root: &TempRoot) -> ServerConfig {
    ServerConfig {
        store_path: root.data_root(),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        bolt_server_agent: None,
        rest_addr: None,
        uds_path: Some(root.path.join("graphus.sock")),
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
        jwt_secret: "adopt-itest-jwt-secret-uds-only-32b!!".to_owned(),
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

/// Boots a server from `config` and returns its handle once ready.
async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

/// Flattens one materialized cell to a scalar [`Value`] (entity → id).
fn materialized_to_scalar(v: MaterializedValue) -> Value {
    match v {
        MaterializedValue::Value(val) => val,
        MaterializedValue::Node(n) => Value::Integer(n.id as i64),
        MaterializedValue::Relationship(r) => Value::Integer(r.id as i64),
        MaterializedValue::Path(_) | MaterializedValue::List(_) => Value::Null,
    }
}

/// Runs one auto-commit statement against `handle` and returns all result rows (scalarized).
async fn run_query(handle: &EngineHandle, query: &str) -> Vec<Vec<Value>> {
    let ticket = handle
        .begin_auto_commit(AccessMode::Write)
        .await
        .expect("begin auto-commit");
    let reply = handle
        .run(ticket, query.to_owned(), Vec::new(), true, None)
        .await
        .expect("run statement");
    tokio::task::spawn_blocking(move || {
        let mut rx = reply.rows;
        let mut rows = Vec::new();
        loop {
            match rx.next() {
                Ok(Some(row)) => rows.push(row.into_iter().map(materialized_to_scalar).collect()),
                Ok(None) => break,
                Err(e) => panic!("row stream error: {e}"),
            }
        }
        rows
    })
    .await
    .expect("drain rows")
}

/// Runs a single-row single-column integer query (a `count(...)`) and returns the integer.
async fn count(handle: &EngineHandle, query: &str) -> i64 {
    let rows = run_query(handle, query).await;
    assert_eq!(rows.len(), 1, "count query returns exactly one row");
    match rows[0].first() {
        Some(Value::Integer(n)) => *n,
        other => panic!("expected an integer count, got {other:?}"),
    }
}

/// Runs a single-row single-column string query and returns the string.
async fn scalar_string(handle: &EngineHandle, query: &str) -> String {
    let rows = run_query(handle, query).await;
    assert_eq!(rows.len(), 1, "expected exactly one row for {query:?}");
    match rows[0].first() {
        Some(Value::String(s)) => s.clone(),
        other => panic!("expected a string, got {other:?}"),
    }
}

// ------------------------------------------------------------------------------------------------
// Named-database adoption (databases/<name>/ + databases.toml) — the primary #681 story
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn adopt_named_database_then_serve_and_query_by_original_id() {
    let root = TempRoot::new("named");
    offline_import_with_persist_id(&root.import_dir());

    let cfg = write_config(&root.path, &root.data_root());
    run_adopt(&[
        "--from",
        &root.import_dir().to_string_lossy(),
        "--database",
        "socialnet",
        "--config",
        &cfg.to_string_lossy(),
    ]);

    // The adopt produced the server-servable layout: a catalog entry + the named database directory.
    assert!(
        root.data_root().join("databases.toml").exists(),
        "adopt registered the named database in the durable catalog"
    );
    assert!(
        root.data_root()
            .join("databases")
            .join("socialnet")
            .join("graphus.store")
            .exists(),
        "adopt laid the store into databases/socialnet/graphus.store"
    );

    // Boot the server over that data root: the adopted database is Online and serves.
    {
        let handle = boot(serve_config(&root)).await;
        let db = handle
            .catalog
            .handle("socialnet")
            .expect("adopted database is online after boot");

        assert_eq!(count(&db, "MATCH (n:Person) RETURN count(n)").await, 3);
        assert_eq!(
            count(&db, "MATCH ()-[r:KNOWS]->() RETURN count(r)").await,
            2
        );

        // The heart of #681: query a node by its ORIGINAL CSV :ID (persisted via --persist-id).
        assert_eq!(
            scalar_string(&db, "MATCH (p:Person {personId: 'p2'}) RETURN p.name").await,
            "Bob",
        );
        // The relationship join resolved against the same external ids.
        assert_eq!(
            scalar_string(
                &db,
                "MATCH (a:Person {personId: 'p1'})-[:KNOWS]->(b) RETURN b.personId"
            )
            .await,
            "p2",
        );
        handle.shutdown().await.expect("graceful shutdown");
    }

    // Durability: reboot re-serves the adopted database from its own WAL recovery — an adopted store
    // is a first-class, crash-safe, ACID database.
    {
        let handle = boot(serve_config(&root)).await;
        let infos = handle.catalog.list().await;
        let socialnet = infos
            .iter()
            .find(|i| i.name == "socialnet")
            .expect("socialnet listed after reboot");
        assert_eq!(socialnet.state, DbState::Online);
        assert_eq!(socialnet.error, None);

        let db = handle
            .catalog
            .handle("socialnet")
            .expect("adopted database online after reboot");
        assert_eq!(count(&db, "MATCH (n:Person) RETURN count(n)").await, 3);
        assert_eq!(
            scalar_string(&db, "MATCH (p:Person {personId: 'p3'}) RETURN p.name").await,
            "Cara",
        );
        handle.shutdown().await.expect("graceful shutdown");
    }
}

// ------------------------------------------------------------------------------------------------
// Default-database adoption (the store laid directly into the data root, no catalog)
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn adopt_default_database_then_serve_and_query_by_original_id() {
    let root = TempRoot::new("default");
    offline_import_with_persist_id(&root.import_dir());

    let cfg = write_config(&root.path, &root.data_root());
    // No --database ⇒ the config's default database ("graphus").
    run_adopt(&[
        "--from",
        &root.import_dir().to_string_lossy(),
        "--config",
        &cfg.to_string_lossy(),
    ]);

    // Adopted as the DEFAULT database: store laid directly into the data root, no catalog file.
    assert!(
        root.data_root().join("graphus.store").exists(),
        "adopt laid the store into the data root as the default database"
    );
    assert!(
        !root.data_root().join("databases.toml").exists(),
        "the default database is implicit — no catalog entry"
    );

    let handle = boot(serve_config(&root)).await;
    assert_eq!(
        count(&handle.engine, "MATCH (n:Person) RETURN count(n)").await,
        3
    );
    assert_eq!(
        scalar_string(
            &handle.engine,
            "MATCH (p:Person {personId: 'p1'}) RETURN p.name"
        )
        .await,
        "Alice",
    );
    handle.shutdown().await.expect("graceful shutdown");
}

// ------------------------------------------------------------------------------------------------
// Guard rails
// ------------------------------------------------------------------------------------------------

#[test]
fn adopt_rejects_a_missing_import_artifact() {
    let root = TempRoot::new("missing");
    std::fs::create_dir_all(root.import_dir()).expect("mkdir");
    let cfg = write_config(&root.path, &root.data_root());

    let bin = env!("CARGO_BIN_EXE_graphus-server");
    let output = Command::new(bin)
        .arg("adopt")
        .args([
            "--from",
            &root.import_dir().to_string_lossy(),
            "--config",
            &cfg.to_string_lossy(),
        ])
        .output()
        .expect("spawn adopt");
    assert!(
        !output.status.success(),
        "adopt must fail on an import directory with no graph.store"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("graph.store"),
        "the error names the missing store artifact: {stderr}"
    );
}
