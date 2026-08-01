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
use graphus_server::engine::{AccessMode, EngineHandle, IndexCommand, IndexTypeFilter};
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
        jwt_secret: "fulltext-itest-jwt-secret-uds-only!!!".to_owned(),
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

/// Runs one auto-commit statement and returns its rows (each cell as a [`MaterializedValue`]).
async fn run(handle: &EngineHandle, query: &str) -> Vec<Vec<MaterializedValue>> {
    let ticket = handle
        .begin_auto_commit(AccessMode::Write)
        .await
        .expect("begin auto-commit");
    let reply = handle
        .run(ticket, query.to_owned(), Vec::new(), true, None, None)
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
        entity: graphus_cypher::FulltextEntity::Node,
        labels_or_types: vec!["Article".to_owned()],
        properties: props.iter().map(|p| (*p).to_owned()).collect(),
        analyzer: analyzer.to_owned(),
        if_not_exists: false,
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

    // SHOW FULLTEXT INDEXES lists the index (unified listing filtered to FULLTEXT, `rmp` #660). The
    // engine returns the full column set; `name` is column 1 (`id` is column 0).
    let reply = engine
        .index_ddl(IndexCommand::ShowIndexes {
            filter: IndexTypeFilter::Fulltext,
            tail: None,
        })
        .await
        .expect("show");
    assert_eq!(reply.rows.len(), 1);
    assert_eq!(reply.rows[0][1], Value::String("articles".to_owned()));
    assert_eq!(
        reply.rows[0][4],
        Value::String("FULLTEXT".to_owned()),
        "type"
    );

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
        .index_ddl(IndexCommand::ShowIndexes {
            filter: IndexTypeFilter::Fulltext,
            tail: None,
        })
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
            if_exists: false,
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

/// rmp #548 regression (production-readiness cert, Cypher-correctness dimension). A full-text
/// procedure whose result feeds an **expansion** — `CALL db.index.fulltext.queryNodes(...) YIELD node
/// MATCH (node)-[r]->(m) RETURN m` — plans as `Projection -> ExpandAll -> ProcedureCall`. The #543
/// off-thread-read gate mis-classified it as *not* calling a procedure (the old `op_calls_procedure`
/// did not recurse `ExpandAll`), dispatched it to the off-thread reader, where the full-text seam has
/// no scan fallback on the reader's owned read view and failed with a spurious "no such index" error.
/// After the exhaustive `calls_procedure()` fix the plan stays inline and serves the query correctly.
#[tokio::test]
async fn fulltext_procedure_feeding_an_expand_is_served_inline_not_misrouted() {
    let temp = TempStore::new("proc-expand");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // An Article that matches the full-text query, with an outgoing edge to a Ref node the query expands to.
    run(
        &engine,
        "CREATE (a:Article {title: 'graph databases', name: 'a1'})-[:CITES]->(:Ref {name: 'r1'})",
    )
    .await;
    engine
        .index_ddl(create_articles_index(&["title"], "standard"))
        .await
        .expect("create fulltext index");

    // The escape pattern: the ProcedureCall's `node` output drives an ExpandAll. Dispatched as an
    // auto-commit read, this is exactly the plan the #543 gate would have mis-routed off-thread.
    let rows = run(
        &engine,
        "CALL db.index.fulltext.queryNodes('articles', 'graph') YIELD node \
         MATCH (node)-[r]->(m) RETURN m",
    )
    .await;

    // It must return the expanded Ref node — NOT error with "no such index" and NOT be empty.
    let names: Vec<String> = rows
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
    assert_eq!(
        names,
        vec!["r1".to_owned()],
        "the full-text-procedure-feeding-expand query must run inline and return the expanded node"
    );

    handle.shutdown().await.expect("graceful shutdown");
}

// ================================================================================================
// Relationship + multi-label full-text indexes (`rmp` task #663)
// ================================================================================================

/// A `CREATE FULLTEXT INDEX` command over a **relationship** pattern (`rmp` #663).
fn create_rel_fulltext(name: &str, types: &[&str], props: &[&str]) -> IndexCommand {
    IndexCommand::CreateFulltextIndex {
        name: name.to_owned(),
        entity: graphus_cypher::FulltextEntity::Relationship,
        labels_or_types: types.iter().map(|t| (*t).to_owned()).collect(),
        properties: props.iter().map(|p| (*p).to_owned()).collect(),
        analyzer: "standard".to_owned(),
        if_not_exists: false,
    }
}

/// A **multi-label** node `CREATE FULLTEXT INDEX` command (`rmp` #663).
fn create_multi_label_fulltext(name: &str, labels: &[&str], props: &[&str]) -> IndexCommand {
    IndexCommand::CreateFulltextIndex {
        name: name.to_owned(),
        entity: graphus_cypher::FulltextEntity::Node,
        labels_or_types: labels.iter().map(|l| (*l).to_owned()).collect(),
        properties: props.iter().map(|p| (*p).to_owned()).collect(),
        analyzer: "standard".to_owned(),
        if_not_exists: false,
    }
}

/// Queries a relationship full-text index and returns the matching relationships' `note` property
/// values, sorted. The `relationship` column egresses as a structural relationship.
async fn query_rel_notes(handle: &EngineHandle, index: &str, search: &str) -> Vec<String> {
    let q = format!(
        "CALL db.index.fulltext.queryRelationships('{index}', '{search}') YIELD relationship \
         RETURN relationship"
    );
    let rows = run(handle, &q).await;
    let mut notes: Vec<String> = rows
        .iter()
        .filter_map(|r| match r.first() {
            Some(MaterializedValue::Relationship(rel)) => rel
                .properties
                .iter()
                .find(|(k, _)| k == "note")
                .and_then(|(_, v)| match v {
                    Value::String(s) => Some(s.clone()),
                    _ => None,
                }),
            _ => None,
        })
        .collect();
    notes.sort();
    notes
}

#[tokio::test]
async fn relationship_fulltext_query_over_a_real_server() {
    let temp = TempStore::new("rel-ft");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // Seed relationships carrying text.
    run(
        &engine,
        "CREATE (:P {name: 'a'})-[:KNOWS {note: 'graph databases are great'}]->(:P {name: 'b'})",
    )
    .await;
    run(
        &engine,
        "CREATE (:P {name: 'c'})-[:KNOWS {note: 'relational databases'}]->(:P {name: 'd'})",
    )
    .await;
    run(
        &engine,
        "CREATE (:P {name: 'e'})-[:LIKES {note: 'graph theory'}]->(:P {name: 'f'})",
    )
    .await; // wrong type

    engine
        .index_ddl(create_rel_fulltext("rel_notes", &["KNOWS"], &["note"]))
        .await
        .expect("create relationship fulltext index");

    // Tokenized query returns the matching KNOWS relationships (not the LIKES one).
    assert_eq!(
        query_rel_notes(&engine, "rel_notes", "databases").await,
        vec![
            "graph databases are great".to_owned(),
            "relational databases".to_owned()
        ]
    );
    // "graph" matches only the KNOWS relationship (the LIKES one is a different, uncovered type).
    assert_eq!(
        query_rel_notes(&engine, "rel_notes", "graph").await,
        vec!["graph databases are great".to_owned()]
    );

    // An update to a relationship property is reflected.
    run(
        &engine,
        "MATCH ()-[r:KNOWS {note: 'relational databases'}]->() SET r.note = 'graph only now'",
    )
    .await;
    assert_eq!(
        query_rel_notes(&engine, "rel_notes", "relational").await,
        Vec::<String>::new()
    );
    assert_eq!(
        query_rel_notes(&engine, "rel_notes", "graph").await,
        vec![
            "graph databases are great".to_owned(),
            "graph only now".to_owned()
        ]
    );

    // Querying an unknown relationship index name errors, not empty.
    let ticket = engine
        .begin_auto_commit(AccessMode::Write)
        .await
        .expect("begin");
    let result = engine
        .run(
            ticket,
            "CALL db.index.fulltext.queryRelationships('nope', 'graph') YIELD relationship \
             RETURN relationship"
                .to_owned(),
            Vec::new(),
            true,
            None,
            None,
        )
        .await;
    let errored = match result {
        Err(_) => true,
        Ok(reply) => tokio::task::spawn_blocking(move || {
            let mut rx = reply.rows;
            rx.next().is_err()
        })
        .await
        .expect("drain"),
    };
    assert!(errored, "querying an unknown relationship index must error");

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn multi_label_node_fulltext_matches_any_covered_label() {
    let temp = TempStore::new("multi-label");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    // Three nodes: an Article, a Blog, and an uncovered Note.
    run(
        &engine,
        "CREATE (:Article {title: 'graph databases', name: 'art'})",
    )
    .await;
    run(
        &engine,
        "CREATE (:Blog {title: 'graph theory', name: 'blog'})",
    )
    .await;
    run(
        &engine,
        "CREATE (:Note {title: 'graph stuff', name: 'note'})",
    )
    .await;

    // A single index over BOTH Article and Blog.
    engine
        .index_ddl(create_multi_label_fulltext(
            "posts",
            &["Article", "Blog"],
            &["title"],
        ))
        .await
        .expect("create multi-label fulltext index");

    // "graph" matches the Article AND the Blog (any covered label) — but NOT the uncovered Note.
    assert_eq!(
        query_names(&engine, "posts", "graph").await,
        vec!["art".to_owned(), "blog".to_owned()]
    );
    // A term unique to one covered label still matches through the shared index.
    assert_eq!(
        query_names(&engine, "posts", "theory").await,
        vec!["blog".to_owned()]
    );

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn show_indexes_reports_relationship_entity_and_multi_label_types() {
    let temp = TempStore::new("show-663");
    let handle = boot(config(&temp)).await;
    let engine = handle.engine.clone();

    engine
        .index_ddl(create_rel_fulltext(
            "rel_ft",
            &["KNOWS", "RATED"],
            &["note"],
        ))
        .await
        .expect("create rel fulltext");
    engine
        .index_ddl(create_multi_label_fulltext(
            "node_ft",
            &["Article", "Blog"],
            &["title"],
        ))
        .await
        .expect("create multi-label fulltext");

    let reply = engine
        .index_ddl(IndexCommand::ShowIndexes {
            filter: IndexTypeFilter::Fulltext,
            tail: None,
        })
        .await
        .expect("show");
    assert_eq!(reply.rows.len(), 2, "both full-text indexes are listed");

    // Columns: id(0), name(1), state(2), populationPercent(3), type(4), entityType(5),
    // labelsOrTypes(6), properties(7), ...
    for row in &reply.rows {
        let name = match &row[1] {
            Value::String(s) => s.clone(),
            other => panic!("name column: {other:?}"),
        };
        let entity_type = &row[5];
        let labels_or_types = match &row[6] {
            Value::List(items) => items
                .iter()
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    other => panic!("labelsOrTypes element: {other:?}"),
                })
                .collect::<Vec<_>>(),
            other => panic!("labelsOrTypes column: {other:?}"),
        };
        match name.as_str() {
            "rel_ft" => {
                assert_eq!(*entity_type, Value::String("RELATIONSHIP".to_owned()));
                assert_eq!(
                    labels_or_types,
                    vec!["KNOWS".to_owned(), "RATED".to_owned()]
                );
            }
            "node_ft" => {
                assert_eq!(*entity_type, Value::String("NODE".to_owned()));
                assert_eq!(
                    labels_or_types,
                    vec!["Article".to_owned(), "Blog".to_owned()]
                );
            }
            other => panic!("unexpected index name {other}"),
        }
    }

    handle.shutdown().await.expect("graceful shutdown");
}

#[tokio::test]
async fn relationship_and_multi_label_index_survive_restart() {
    let temp = TempStore::new("restart-663");
    let cfg = config(&temp);

    // Boot #1: seed, create a relationship index and a multi-label node index, confirm, shut down.
    {
        let handle = boot(cfg.clone()).await;
        let engine = handle.engine.clone();
        run(
            &engine,
            "CREATE (:Article {title: 'graph survives', name: 'art'})",
        )
        .await;
        run(
            &engine,
            "CREATE (:Blog {title: 'blog survives', name: 'blog'})",
        )
        .await;
        run(
            &engine,
            "CREATE (:P {name: 'x'})-[:KNOWS {note: 'graph edge survives'}]->(:P {name: 'y'})",
        )
        .await;
        engine
            .index_ddl(create_rel_fulltext("rel_notes", &["KNOWS"], &["note"]))
            .await
            .expect("create rel fulltext");
        engine
            .index_ddl(create_multi_label_fulltext(
                "posts",
                &["Article", "Blog"],
                &["title"],
            ))
            .await
            .expect("create multi-label fulltext");
        assert_eq!(
            query_rel_notes(&engine, "rel_notes", "survives").await,
            vec!["graph edge survives".to_owned()]
        );
        handle.shutdown().await.expect("shutdown");
    }

    // Boot #2: both indexes must survive (durable catalog incl. the extension block + rebuild).
    let handle = boot(cfg).await;
    let engine = handle.engine.clone();

    let reply = engine
        .index_ddl(IndexCommand::ShowIndexes {
            filter: IndexTypeFilter::Fulltext,
            tail: None,
        })
        .await
        .expect("show after restart");
    assert_eq!(reply.rows.len(), 2, "both indexes must survive the restart");

    // The relationship index still returns the matching edge (rebuilt rel inverted index).
    assert_eq!(
        query_rel_notes(&engine, "rel_notes", "graph").await,
        vec!["graph edge survives".to_owned()]
    );
    // The multi-label node index still matches across both covered labels.
    assert_eq!(
        query_names(&engine, "posts", "survives").await,
        vec!["art".to_owned(), "blog".to_owned()]
    );

    handle.shutdown().await.expect("shutdown");
}
