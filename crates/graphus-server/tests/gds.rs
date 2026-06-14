//! End-to-end tests for the **Graph Data Science (`gds.*`) procedure surface** over a real booted
//! server (`rmp` task #133).
//!
//! The engine registers the `gds.*` procedures at boot (`exec::install_extensions` →
//! `register_gds`), sharing one named-graph catalog for the engine's lifetime. These tests boot the
//! server in-process over a fresh tempdir data root (UDS-only listener), build a small graph with
//! Cypher, then drive `CALL gds.graph.project(...)` followed by the streaming algorithms through the
//! **same** `Run` path every Bolt/REST statement takes — so the GDS wiring is exercised against the
//! real storage backend (real records, real WAL, MVCC-consistent projection), not just unit tests.

use std::collections::BTreeMap;
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
        path.push(format!("graphus-gds-{tag}-{nanos}-{}", std::process::id()));
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
        jwt_secret: "gds-itest-jwt-secret-uds-only-pad!!".to_owned(),
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

/// Runs one auto-commit statement and returns its rows (each cell a [`MaterializedValue`]).
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

/// The scalar of a single cell as a plain [`Value`] (panics on a structural materialization).
fn val(cell: &MaterializedValue) -> Value {
    match cell {
        MaterializedValue::Value(v) => v.clone(),
        other => panic!("expected a scalar value, got {other:?}"),
    }
}

/// Builds a small undirected social graph: a triangle a-b-c plus a pendant d off a, all `:Person`
/// connected by `:KNOWS`. Returns nothing — the test reads ids back via the `id(n)` function.
async fn seed_social_graph(engine: &EngineHandle) {
    run(
        engine,
        "CREATE (a:Person {name:'a'}), (b:Person {name:'b'}), \
                (c:Person {name:'c'}), (d:Person {name:'d'}), \
                (a)-[:KNOWS]->(b), (b)-[:KNOWS]->(c), (c)-[:KNOWS]->(a), (a)-[:KNOWS]->(d)",
    )
    .await;
}

/// Maps each `:Person`'s name to its internal node id (via `id(n)`), so a test can assert on a node
/// by name rather than guessing the store's physical ids.
async fn name_to_id(engine: &EngineHandle) -> BTreeMap<String, i64> {
    let rows = run(
        engine,
        "MATCH (n:Person) RETURN n.name AS name, id(n) AS id ORDER BY name",
    )
    .await;
    let mut map = BTreeMap::new();
    for r in rows {
        let (Value::String(name), Value::Integer(id)) = (val(&r[0]), val(&r[1])) else {
            panic!("unexpected row shape");
        };
        map.insert(name, id);
    }
    map
}

#[tokio::test]
async fn gds_project_and_pagerank_stream_through_engine() {
    let temp = TempStore::new("pagerank");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    seed_social_graph(&engine).await;

    // Project a named graph from the live, committed store under the calling statement's snapshot.
    let rows = run(
        &engine,
        "CALL gds.graph.project('social', 'Person', 'KNOWS', {}) \
         YIELD graphName, nodeCount, relationshipCount \
         RETURN graphName, nodeCount, relationshipCount",
    )
    .await;
    assert_eq!(rows.len(), 1);
    assert_eq!(val(&rows[0][0]), Value::String("social".into()));
    assert_eq!(val(&rows[0][1]), Value::Integer(4)); // 4 :Person nodes
    assert_eq!(val(&rows[0][2]), Value::Integer(8)); // 4 :KNOWS, undirected -> 8 stored

    // PageRank streams one row per projected node, every score finite & positive.
    let rows = run(
        &engine,
        "CALL gds.pageRank.stream('social', {}) YIELD nodeId, score RETURN nodeId, score",
    )
    .await;
    assert_eq!(rows.len(), 4);
    for r in &rows {
        match val(&r[1]) {
            Value::Float(f) => assert!(f.is_finite() && f > 0.0, "score {f} must be finite positive"),
            other => panic!("expected float score, got {other:?}"),
        }
    }

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn gds_wcc_and_degree_stream_through_engine() {
    let temp = TempStore::new("wcc");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    seed_social_graph(&engine).await;
    let ids = name_to_id(&engine).await;

    run(
        &engine,
        "CALL gds.graph.project('g', 'Person', 'KNOWS', {}) YIELD graphName RETURN graphName",
    )
    .await;

    // WCC: the whole graph is one connected component.
    let rows = run(
        &engine,
        "CALL gds.wcc.stream('g', {}) YIELD nodeId, componentId RETURN nodeId, componentId",
    )
    .await;
    assert_eq!(rows.len(), 4);
    let comps: std::collections::BTreeSet<i64> = rows
        .iter()
        .map(|r| match val(&r[1]) {
            Value::Integer(c) => c,
            other => panic!("expected integer componentId, got {other:?}"),
        })
        .collect();
    assert_eq!(comps.len(), 1, "all four nodes share one component");

    // Degree: node 'a' touches b, c and d (degree 3); 'd' touches only a (degree 1).
    let rows = run(
        &engine,
        "CALL gds.degree.stream('g', {}) YIELD nodeId, score RETURN nodeId, score",
    )
    .await;
    let deg: BTreeMap<i64, f64> = rows
        .iter()
        .map(|r| {
            let (Value::Integer(id), Value::Float(s)) = (val(&r[0]), val(&r[1])) else {
                panic!("unexpected degree row");
            };
            (id, s)
        })
        .collect();
    assert_eq!(deg.get(&ids["a"]), Some(&3.0));
    assert_eq!(deg.get(&ids["d"]), Some(&1.0));

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn gds_dijkstra_stream_weighted_through_engine() {
    let temp = TempStore::new("dijkstra");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // a -1-> b -1-> c and a -5-> c (directed, weighted). Shortest a..c == 2 (via b).
    run(
        &engine,
        "CREATE (a:City {name:'a'}), (b:City {name:'b'}), (c:City {name:'c'}), \
                (a)-[:ROAD {w:1.0}]->(b), (b)-[:ROAD {w:1.0}]->(c), (a)-[:ROAD {w:5.0}]->(c)",
    )
    .await;
    let ids = {
        let rows = run(
            &engine,
            "MATCH (n:City) RETURN n.name AS name, id(n) AS id ORDER BY name",
        )
        .await;
        let mut m = BTreeMap::new();
        for r in rows {
            let (Value::String(n), Value::Integer(i)) = (val(&r[0]), val(&r[1])) else {
                panic!("row shape");
            };
            m.insert(n, i);
        }
        m
    };

    run(
        &engine,
        "CALL gds.graph.project('roads', 'City', 'ROAD', \
             {orientation:'NATURAL', relationshipWeightProperty:'w'}) \
         YIELD graphName RETURN graphName",
    )
    .await;

    let query = format!(
        "CALL gds.dijkstra.stream('roads', {{sourceNode: {}}}) \
         YIELD nodeId, distance RETURN nodeId, distance",
        ids["a"]
    );
    let rows = run(&engine, &query).await;
    let dist: BTreeMap<i64, f64> = rows
        .iter()
        .map(|r| {
            let (Value::Integer(id), Value::Float(d)) = (val(&r[0]), val(&r[1])) else {
                panic!("unexpected dijkstra row");
            };
            (id, d)
        })
        .collect();
    assert_eq!(dist.get(&ids["a"]), Some(&0.0));
    assert_eq!(dist.get(&ids["b"]), Some(&1.0));
    assert_eq!(dist.get(&ids["c"]), Some(&2.0)); // via b, never the direct weight-5 edge

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn gds_projection_is_a_consistent_snapshot() {
    // A projection taken under one statement's snapshot must NOT observe writes a *later* statement
    // makes — it is frozen at project time. We project a 2-node graph, then add a third node, and
    // assert the projected graph still reports 2 nodes (the snapshot it was built from).
    let temp = TempStore::new("snapshot");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    run(
        &engine,
        "CREATE (a:N {name:'a'}), (b:N {name:'b'}), (a)-[:R]->(b)",
    )
    .await;

    let rows = run(
        &engine,
        "CALL gds.graph.project('snap', 'N', 'R', {}) YIELD nodeCount RETURN nodeCount",
    )
    .await;
    assert_eq!(val(&rows[0][0]), Value::Integer(2));

    // A later committed write adds a node — the projection is unaffected.
    run(&engine, "CREATE (c:N {name:'c'})").await;

    let rows = run(
        &engine,
        "CALL gds.graph.list() YIELD graphName, nodeCount RETURN graphName, nodeCount",
    )
    .await;
    assert_eq!(rows.len(), 1);
    assert_eq!(val(&rows[0][0]), Value::String("snap".into()));
    assert_eq!(
        val(&rows[0][1]),
        Value::Integer(2),
        "the projection stays frozen at its snapshot (2 nodes), ignoring the later 3rd node"
    );

    // Re-projecting now sees all three nodes (the new statement's fresh snapshot).
    let rows = run(
        &engine,
        "CALL gds.graph.project('snap', 'N', 'R', {}) YIELD nodeCount RETURN nodeCount",
    )
    .await;
    assert_eq!(
        val(&rows[0][0]),
        Value::Integer(3),
        "a re-project under a fresh snapshot sees the 3rd node"
    );

    handle.shutdown().await.expect("graceful shutdown");
}
