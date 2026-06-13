//! End-to-end full-text index tests over a **real booted server** (`rmp` task #72).
//!
//! Each test boots the server in-process over a fresh tempdir data root (UDS-only listener), seeds
//! nodes through the normal query path, creates a full-text index through the index-DDL command path
//! (the same `IndexCommand` the Bolt/REST admin seams submit after parsing
//! `CREATE FULLTEXT INDEX …`), then queries it with `CALL db.index.fulltext.queryNodes(…)`. This is
//! the capstone proof of the acceptance criteria against the real storage backend:
//!
//! - a full-text index returns the correct matching nodes for tokenized queries on seeded data;
//! - updates and deletes are reflected;
//! - results are MVCC-correct (each statement runs in its own committed transaction);
//! - the index **survives a full server restart** (the durable catalog + the rebuild-from-store).

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
            "graphus-fulltext-{tag}-{nanos}-{}",
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
            ..AdmissionConfig::default()
        },
        timing: TimingConfig {
            slow_query_threshold_ms: 1_000,
            shutdown_drain_deadline_ms: 5_000,
            ..TimingConfig::default()
        },
        jwt_secret: "fulltext-itest-jwt-secret-uds-only!!!".to_owned(),
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

/// Queries the full-text index and returns the matching nodes' `name` property values, sorted. The
/// `node` column egresses as a structural node, so we read its materialized properties.
async fn query_names(handle: &EngineHandle, index: &str, search: &str) -> Vec<String> {
    let q =
        format!("CALL db.index.fulltext.queryNodes('{index}', '{search}') YIELD node RETURN node");
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

fn create_articles_index(props: &[&str], analyzer: &str) -> IndexCommand {
    IndexCommand::CreateFulltextIndex {
        name: "articles".to_owned(),
        label: "Article".to_owned(),
        properties: props.iter().map(|p| (*p).to_owned()).collect(),
        analyzer: analyzer.to_owned(),
    }
}

#[tokio::test]
async fn create_query_update_delete_over_a_real_server() {
    let temp = TempStore::new("crud");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // Seed.
    run(
        &engine,
        "CREATE (:Article {title: 'Graph databases are great', name: 'a1'})",
    )
    .await;
    run(
        &engine,
        "CREATE (:Article {title: 'Relational databases', name: 'a2'})",
    )
    .await;
    run(
        &engine,
        "CREATE (:Article {title: 'Graph theory basics', name: 'a3'})",
    )
    .await;
    run(&engine, "CREATE (:Other {title: 'Graph stuff', name: 'x'})").await; // wrong label

    // Create the index through the DDL command path, then wait for the online build to finish.
    engine
        .index_ddl(create_articles_index(&["title"], "standard"))
        .await
        .expect("create fulltext index");

    // The index returns the correct matching nodes for tokenized queries.
    assert_eq!(
        query_names(&engine, "articles", "databases").await,
        vec!["a1".to_owned(), "a2".to_owned()]
    );
    // "graph" matches a1 + a3 (NOT the Other-labelled node).
    assert_eq!(
        query_names(&engine, "articles", "graph").await,
        vec!["a1".to_owned(), "a3".to_owned()]
    );
    // A stop-word-only query matches nothing.
    assert!(query_names(&engine, "articles", "are the").await.is_empty());

    // Update is reflected: a1 no longer mentions "databases".
    run(
        &engine,
        "MATCH (n:Article {name: 'a1'}) SET n.title = 'Graph theory only'",
    )
    .await;
    assert_eq!(
        query_names(&engine, "articles", "databases").await,
        vec!["a2".to_owned()]
    );

    // Delete is reflected: a2 disappears.
    run(&engine, "MATCH (n:Article {name: 'a2'}) DELETE n").await;
    assert!(
        query_names(&engine, "articles", "databases")
            .await
            .is_empty()
    );

    // SHOW FULLTEXT INDEXES lists the index.
    let reply = engine
        .index_ddl(IndexCommand::ShowFulltextIndexes)
        .await
        .expect("show");
    assert_eq!(reply.rows.len(), 1);
    assert_eq!(reply.rows[0][0], Value::String("articles".to_owned()));

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
            "CREATE (:Article {title: 'graph database survives restart', name: 'r1'})",
        )
        .await;
        run(
            &engine,
            "CREATE (:Article {title: 'relational only', name: 'r2'})",
        )
        .await;
        engine
            .index_ddl(create_articles_index(&["title"], "standard"))
            .await
            .expect("create");
        assert_eq!(
            query_names(&engine, "articles", "survives").await,
            vec!["r1".to_owned()]
        );
        handle.shutdown().await.expect("shutdown");
    }

    // Boot #2: the index must still be declared (durable catalog) and return correct matches
    // (inverted index rebuilt from the recovered store) — the durability acceptance criterion.
    let handle = boot(cfg).await;
    let engine = handle.engine.clone();

    let reply = engine
        .index_ddl(IndexCommand::ShowFulltextIndexes)
        .await
        .expect("show after restart");
    assert_eq!(reply.rows.len(), 1, "the index must survive the restart");

    assert_eq!(
        query_names(&engine, "articles", "survives").await,
        vec!["r1".to_owned()]
    );
    assert_eq!(
        query_names(&engine, "articles", "database").await,
        vec!["r1".to_owned()]
    );
    assert_eq!(
        query_names(&engine, "articles", "relational").await,
        vec!["r2".to_owned()]
    );

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn unknown_analyzer_is_rejected() {
    let temp = TempStore::new("badanalyzer");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();
    let err = engine
        .index_ddl(create_articles_index(&["title"], "no-such-analyzer"))
        .await
        .expect_err("an unknown analyzer must be rejected");
    assert!(format!("{err}").to_lowercase().contains("analyzer"));
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn drop_index_then_query_errors() {
    let temp = TempStore::new("drop");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();
    run(&engine, "CREATE (:Article {title: 'graph', name: 'd1'})").await;
    engine
        .index_ddl(create_articles_index(&["title"], "standard"))
        .await
        .expect("create");
    assert_eq!(
        query_names(&engine, "articles", "graph").await,
        vec!["d1".to_owned()]
    );

    engine
        .index_ddl(IndexCommand::DropFulltextIndex {
            name: "articles".to_owned(),
        })
        .await
        .expect("drop");

    // Querying the dropped index must error (not return empty results).
    let ticket = engine
        .begin_auto_commit(AccessMode::Write)
        .await
        .expect("begin");
    let result = engine
        .run(
            ticket,
            "CALL db.index.fulltext.queryNodes('articles', 'graph') YIELD node RETURN node"
                .to_owned(),
            Vec::new(),
            true,
            None,
        )
        .await;
    // The error may surface at run() or while draining; either way the query must not succeed-empty.
    let errored = match result {
        Err(_) => true,
        Ok(reply) => tokio::task::spawn_blocking(move || {
            // The first pull either yields an error (the dropped-index failure) or a row/None
            // (which would be the bug we are guarding against).
            let mut rx = reply.rows;
            rx.next().is_err()
        })
        .await
        .expect("drain"),
    };
    assert!(errored, "querying a dropped full-text index must error");

    handle.shutdown().await.expect("shutdown");
}
