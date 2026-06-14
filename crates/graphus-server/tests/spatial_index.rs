//! End-to-end spatial (point) index tests over a **real booted server** (`rmp` task #98).
//!
//! Each test boots the server in-process over a fresh tempdir data root (UDS-only listener), seeds
//! `City` nodes (each with a `loc` point property) through the normal query path, creates a point
//! index through the index-DDL command path (the same `IndexCommand` the Bolt/REST admin seams submit
//! after parsing `CREATE POINT INDEX …`), then runs proximity queries
//! `MATCH (n:City) WHERE distance(n.loc, point({x:..,y:..})) <= r RETURN n`. This is the capstone proof
//! of the acceptance criteria against the real storage backend:
//!
//! - a proximity query over the index returns the SAME nodes as a full scan (the overriding AC: the
//!   index never changes the answer, it only accelerates it — `db.index.spatial` does not exist, so we
//!   prove equivalence by running the query with and without the declared index and asserting equal
//!   results, plus the absolute correctness of the matched set);
//! - updates and deletes are reflected;
//! - results are MVCC-correct (each statement runs in its own committed transaction);
//! - the index **survives a full server restart** (the durable catalog + the rebuild-from-store).
//!
//! Mirrors `tests/fulltext_index.rs`.

use std::path::PathBuf;

use graphus_core::Value;
use graphus_cypher::MaterializedValue;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::engine::{AccessMode, EngineHandle, IndexCommand};
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
            "graphus-spatial-{tag}-{nanos}-{}",
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
        jwt_secret: "spatial-itest-jwt-secret-uds-only!!!".to_owned(),
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

/// Runs a proximity query over `City.loc` centred at `(cx, cy)` within `r` and returns the matched
/// nodes' `name` property values, sorted. The `n` column egresses as a structural node.
async fn proximity_names(handle: &EngineHandle, cx: f64, cy: f64, r: f64) -> Vec<String> {
    let q = format!(
        "MATCH (n:City) WHERE distance(n.loc, point({{x: {cx}, y: {cy}}})) <= {r} RETURN n"
    );
    let rows = run(handle, &q).await;
    let mut names: Vec<String> = rows
        .iter()
        .filter_map(|r| match r.first() {
            Some(MaterializedValue::Node(n)) => n
                .properties
                .iter()
                .find(|(k, _)| k == "name")
                .and_then(|(_, v)| match v {
                    Value::String(s) => Some(s.clone()),
                    _ => None,
                }),
            _ => None,
        })
        .collect();
    names.sort();
    names
}

fn create_by_loc_index() -> IndexCommand {
    IndexCommand::CreatePointIndex {
        name: "by_loc".to_owned(),
        label: "City".to_owned(),
        property: "loc".to_owned(),
    }
}

#[tokio::test]
async fn create_query_update_delete_over_a_real_server() {
    let temp = TempStore::new("crud");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // Seed: a near cluster, a mid node, a far node, and a wrong-label node.
    run(
        &engine,
        "CREATE (:City {loc: point({x: 0, y: 0}), name: 'a'})",
    )
    .await;
    run(
        &engine,
        "CREATE (:City {loc: point({x: 1, y: 1}), name: 'b'})",
    )
    .await;
    run(
        &engine,
        "CREATE (:City {loc: point({x: 3, y: 4}), name: 'c'})",
    )
    .await; // dist 5
    run(
        &engine,
        "CREATE (:City {loc: point({x: 100, y: 100}), name: 'd'})",
    )
    .await;
    run(
        &engine,
        "CREATE (:Town {loc: point({x: 0, y: 0}), name: 'wrong'})",
    )
    .await; // wrong label

    // Baseline (no index): the proximity result over a full scan.
    let scan_near = proximity_names(&engine, 0.0, 0.0, 2.0).await;
    assert_eq!(scan_near, vec!["a".to_owned(), "b".to_owned()]);

    // Create the index through the DDL command path; the online build completes before it returns.
    engine
        .index_ddl(create_by_loc_index())
        .await
        .expect("create point index");

    // The index path returns the SAME nodes as the full scan (the overriding AC).
    assert_eq!(proximity_names(&engine, 0.0, 0.0, 2.0).await, scan_near);
    // A wider radius admits c (dist 5) but never d (far) — still a City-only result.
    assert_eq!(
        proximity_names(&engine, 0.0, 0.0, 10.0).await,
        vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]
    );

    // Update is reflected: move 'a' far away — the near query loses it, a query at the new spot finds it.
    run(
        &engine,
        "MATCH (n:City {name: 'a'}) SET n.loc = point({x: 50, y: 50})",
    )
    .await;
    assert_eq!(
        proximity_names(&engine, 0.0, 0.0, 2.0).await,
        vec!["b".to_owned()]
    );
    assert_eq!(
        proximity_names(&engine, 50.0, 50.0, 1.0).await,
        vec!["a".to_owned()]
    );

    // Delete is reflected: 'b' disappears.
    run(&engine, "MATCH (n:City {name: 'b'}) DELETE n").await;
    assert!(proximity_names(&engine, 0.0, 0.0, 2.0).await.is_empty());

    // SHOW POINT INDEXES lists the index.
    let reply = engine
        .index_ddl(IndexCommand::ShowPointIndexes)
        .await
        .expect("show");
    assert_eq!(reply.rows.len(), 1);
    assert_eq!(reply.rows[0][0], Value::String("by_loc".to_owned()));
    assert_eq!(reply.rows[0][1], Value::String("City".to_owned()));
    assert_eq!(reply.rows[0][2], Value::String("loc".to_owned()));
    assert_eq!(reply.rows[0][3], Value::String("online".to_owned()));

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn index_survives_a_full_server_restart() {
    let temp = TempStore::new("restart");
    let cfg = config(&temp);

    // Boot #1: seed, create the index, confirm it works, then shut down cleanly.
    {
        let handle = boot(cfg.clone()).await;
        let engine = handle.engine.clone();
        run(
            &engine,
            "CREATE (:City {loc: point({x: 0, y: 0}), name: 'r1'})",
        )
        .await;
        run(
            &engine,
            "CREATE (:City {loc: point({x: 1, y: 0}), name: 'r2'})",
        )
        .await;
        run(
            &engine,
            "CREATE (:City {loc: point({x: 200, y: 200}), name: 'far'})",
        )
        .await;
        engine
            .index_ddl(create_by_loc_index())
            .await
            .expect("create");
        assert_eq!(
            proximity_names(&engine, 0.0, 0.0, 2.0).await,
            vec!["r1".to_owned(), "r2".to_owned()]
        );
        handle.shutdown().await.expect("shutdown");
    }

    // Boot #2: the index must still be declared (durable catalog) and return correct matches (grid
    // rebuilt from the recovered store) — the durability acceptance criterion.
    let handle = boot(cfg).await;
    let engine = handle.engine.clone();

    let reply = engine
        .index_ddl(IndexCommand::ShowPointIndexes)
        .await
        .expect("show after restart");
    assert_eq!(reply.rows.len(), 1, "the index must survive the restart");
    assert_eq!(reply.rows[0][3], Value::String("online".to_owned()));

    assert_eq!(
        proximity_names(&engine, 0.0, 0.0, 2.0).await,
        vec!["r1".to_owned(), "r2".to_owned()]
    );
    // The far node is correctly excluded from the near result and found at its own spot after
    // recovery (no over- or under-matching from the rebuilt grid).
    assert!(
        !proximity_names(&engine, 0.0, 0.0, 2.0)
            .await
            .contains(&"far".to_owned())
    );
    assert_eq!(
        proximity_names(&engine, 200.0, 200.0, 1.0).await,
        vec!["far".to_owned()]
    );

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn online_build_over_a_prepopulated_store() {
    let temp = TempStore::new("online");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // Seed many cities FIRST so the online build has work to do, then create the index.
    for n in 0..30 {
        run(
            &engine,
            &format!("CREATE (:City {{loc: point({{x: {n}, y: 0}}), name: 'c{n}'}})"),
        )
        .await;
    }
    // Baseline over a full scan (no index).
    let scan = proximity_names(&engine, 0.0, 0.0, 5.0).await;

    engine
        .index_ddl(create_by_loc_index())
        .await
        .expect("create (online build runs to completion)");

    // After the build the index path returns the identical set as the scan path.
    assert_eq!(proximity_names(&engine, 0.0, 0.0, 5.0).await, scan);
    assert!(!scan.is_empty());

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn drop_index_then_query_still_correct() {
    let temp = TempStore::new("drop");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();
    run(
        &engine,
        "CREATE (:City {loc: point({x: 0, y: 0}), name: 'd1'})",
    )
    .await;
    engine
        .index_ddl(create_by_loc_index())
        .await
        .expect("create");
    assert_eq!(
        proximity_names(&engine, 0.0, 0.0, 1.0).await,
        vec!["d1".to_owned()]
    );

    engine
        .index_ddl(IndexCommand::DropPointIndex {
            name: "by_loc".to_owned(),
        })
        .await
        .expect("drop");

    // Unlike a dropped full-text index (whose procedure call errors), a proximity query simply falls
    // back to a scan after the drop and stays correct.
    assert_eq!(
        proximity_names(&engine, 0.0, 0.0, 1.0).await,
        vec!["d1".to_owned()]
    );
    let reply = engine
        .index_ddl(IndexCommand::ShowPointIndexes)
        .await
        .expect("show");
    assert!(reply.rows.is_empty(), "the dropped index is gone");

    handle.shutdown().await.expect("shutdown");
}
