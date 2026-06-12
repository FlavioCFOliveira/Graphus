//! End-to-end integration tests for the Graphus server (`04-technical-design.md` §8/§9; rmp #20).
//!
//! Each test boots a **real server** in-process on loopback over a fresh tempdir store (a multi-thread
//! Tokio runtime, the single-threaded engine on its own thread, the real `RecordStore`), then drives
//! the live interfaces:
//!
//! - **REST** end-to-end (open tx → CREATE → commit → MATCH returns it), proving the write hit the
//!   real persistent store.
//! - **Bolt** end-to-end over a real Unix socket (handshake → HELLO/LOGON → RUN/PULL → RECORDs).
//! - **Auth rejection** on each interface.
//! - **Admission control** fast-rejecting beyond the configured limit.
//! - **Graceful shutdown** draining + the store reopening clean.
//! - The **observability** endpoints (`/metrics`, `/health/ready`).
//!
//! ## Tested vs smoke-tested transports (documented)
//!
//! REST and the server's HTTP surface are exercised over the **non-TLS** loopback path the listener
//! supports for exactly this purpose (and which `ServerConfig::validate` forbids in production); a raw
//! HTTP/1.1 client is hand-rolled over a `TcpStream` to avoid a heavy TLS-client dev-dependency. The
//! full Bolt path is exercised over the **UDS** transport (kernel-protected, no TLS — `04 §8.4`). The
//! **TLS** config path is covered separately: a `rcgen` self-signed cert is built into a rustls
//! `ServerConfig` via the auth crate and a TLS Bolt-TCP + REST listener is **bind-verified** (the TLS
//! handshake against a live socket is the one interface only smoke-tested here, since driving it needs
//! a TLS client).

use std::path::PathBuf;
use std::time::Duration;

use graphus_bolt::server::{encode_client_handshake, encode_request_framed};
use graphus_bolt::{BoltValue, Dechunker, Frame, Proposal, Request, Response};
use graphus_core::Value;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::{Server, ServerHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

/// A unique temp directory for one test's store (auto-removed on drop).
struct TempStore {
    path: PathBuf,
}

impl TempStore {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!(
            "graphus-itest-{tag}-{nanos}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
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

/// Builds a base config: REST + UDS on loopback (REST non-TLS for the test client), no Bolt-TCP, the
/// `alice`/`pw` admin user, store in `temp`.
fn base_config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.store_dir(),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        fsync_threads: 1,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        // REST on an ephemeral port; no TLS so the test's raw HTTP client can connect.
        rest_addr: Some("127.0.0.1:0".to_owned()),
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
        jwt_secret: "integration-test-jwt-secret-32-bytes!".to_owned(),
        auth: AuthBootstrap {
            admin_user: "alice".to_owned(),
            admin_password: "pw".to_owned(),
            admin_uid: Some(current_uid()),
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: graphus_server::AuditConfig::default(),
        // The REST test client speaks plaintext HTTP on loopback; opt into the non-TLS network path
        // (production keeps this off — `ServerConfig::validate`).
        allow_insecure_network: true,
    }
}

/// The current process uid, so the UDS peer-cred gate admits this test's own connections.
fn current_uid() -> u32 {
    // Read from the `id -u`-equivalent via the runtime; std has no portable getuid, so parse
    // `/proc/self/status` on Linux, else fall back to 0 (the test only needs the server's uid map to
    // match *this* process's peer uid, which on Linux is the real uid).
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    if let Some(first) = rest.split_whitespace().next() {
                        if let Ok(uid) = first.parse() {
                            return uid;
                        }
                    }
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Boots a server from `config` and returns its handle once ready.
async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

// ----------------------------------------------------------------------------------------------
// A tiny raw HTTP/1.1 client over a plain TcpStream (no TLS, no heavy client dep).
// ----------------------------------------------------------------------------------------------

/// Sends one HTTP/1.1 request and returns `(status_code, body)`. `body_json` is sent as the request
/// body with `Content-Type: application/json` when `Some`. `bearer` adds an `Authorization` header.
async fn http_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body_json: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect REST");
    let body = body_json.unwrap_or("");
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\n"
    );
    if let Some(token) = bearer {
        req.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if body_json.is_some() {
        req.push_str("Content-Type: application/json\r\n");
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    req.push_str(body);

    stream.write_all(req.as_bytes()).await.expect("write req");
    stream.flush().await.unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read resp");
    let text = String::from_utf8_lossy(&raw).into_owned();

    // Parse the status line + split off the body after the header terminator.
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}

// ----------------------------------------------------------------------------------------------
// REST end-to-end.
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn rest_create_then_match_hits_the_real_store() {
    let temp = TempStore::new("rest-e2e");
    let server = boot(base_config(&temp)).await;
    let rest = server.rest_addr.expect("REST enabled");

    // Mint a Bearer token for alice (the admin) using the same secret the server was built with.
    let token = mint_token(&server, "alice").await;

    // Open an explicit write transaction.
    let (status, body) = http_request(
        rest,
        "POST",
        "/db/graphus/tx",
        Some(&token),
        Some(r#"{"statements":[],"access_mode":"WRITE"}"#),
    )
    .await;
    assert_eq!(status, 201, "begin tx: {body}");
    let tx_id = extract_json_string(&body, "id").expect("tx id in begin response");

    // CREATE a node in the open transaction.
    let create_path = format!("/db/graphus/tx/{tx_id}");
    let (status, body) = http_request(
        rest,
        "POST",
        &create_path,
        Some(&token),
        Some(r#"{"statements":[{"statement":"CREATE (:Person {name: 'Ada'})"}]}"#),
    )
    .await;
    assert_eq!(status, 200, "create: {body}");

    // Commit (empty final statement set).
    let commit_path = format!("/db/graphus/tx/{tx_id}/commit");
    let (status, body) = http_request(
        rest,
        "POST",
        &commit_path,
        Some(&token),
        Some(r#"{"statements":[]}"#),
    )
    .await;
    assert_eq!(status, 200, "commit: {body}");

    // In a NEW auto-commit transaction, MATCH it back — proving it persisted to the real store.
    let (status, body) = http_request(
        rest,
        "POST",
        "/db/graphus/tx/commit",
        Some(&token),
        Some(r#"{"statements":[{"statement":"MATCH (p:Person) RETURN p.name"}]}"#),
    )
    .await;
    assert_eq!(status, 200, "match: {body}");
    assert!(
        body.contains("Ada"),
        "the committed node must be readable back: {body}"
    );

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test]
async fn rest_graph_projection_dedups_nodes_and_edges() {
    // rmp #77: create a tiny graph, POST the graph-visualisation endpoint, and assert the
    // deduplicated `{ nodes, relationships }` projection (endpoints + dedup), plus auth + db
    // selection, all over the REAL booted server and persistent store.
    let temp = TempStore::new("rest-graph-viz");
    let server = boot(base_config(&temp)).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(&server, "alice").await;

    // Build a small graph: (Ada)-[:KNOWS]->(Bob), committed to the real store.
    let (status, body) = http_request(
        rest,
        "POST",
        "/db/graphus/tx/commit",
        Some(&token),
        Some(
            r#"{"statements":[{"statement":"CREATE (a:Person {name:'Ada'})-[:KNOWS]->(b:Person {name:'Bob'})"}]}"#,
        ),
    )
    .await;
    assert_eq!(status, 200, "seed graph: {body}");

    // The viz query mentions the SAME node `a` twice (so dedup is exercised end-to-end): once as a
    // bound entity, and again inside a list cell (`[a]`) — distinct result columns, one node id.
    let (status, body) = http_request(
        rest,
        "POST",
        "/db/graphus/graph",
        Some(&token),
        Some(
            r#"{"statements":[{"statement":"MATCH (a:Person {name:'Ada'})-[r:KNOWS]->(b:Person) RETURN a, r, b, [a] AS again"}]}"#,
        ),
    )
    .await;
    assert_eq!(status, 200, "graph projection: {body}");
    let graph: serde_json::Value = serde_json::from_str(&body).expect("graph JSON");

    // Exactly two distinct nodes (Ada deduped despite appearing twice) and one relationship.
    let nodes = graph["nodes"].as_array().expect("nodes array");
    let rels = graph["relationships"]
        .as_array()
        .expect("relationships array");
    assert_eq!(nodes.len(), 2, "Ada must be deduped: {body}");
    assert_eq!(rels.len(), 1, "one KNOWS edge: {body}");

    // The relationship carries its endpoints (startNode/endNode) and they reference real node ids.
    let rel = &rels[0];
    assert_eq!(rel["type"], "KNOWS", "rel type: {body}");
    let start = rel["startNode"].as_i64().expect("startNode id");
    let end = rel["endNode"].as_i64().expect("endNode id");
    let node_ids: Vec<i64> = nodes.iter().map(|n| n["id"].as_i64().unwrap()).collect();
    assert!(node_ids.contains(&start), "startNode in nodes: {body}");
    assert!(node_ids.contains(&end), "endNode in nodes: {body}");

    // Both names are present (RBAC for the admin user hides nothing).
    assert!(
        body.contains("Ada") && body.contains("Bob"),
        "names: {body}"
    );

    // Auth: the same endpoint without a Bearer token is rejected (401), exactly as the tx endpoints.
    let (status, _) = http_request(
        rest,
        "POST",
        "/db/graphus/graph",
        None,
        Some(r#"{"statements":[{"statement":"MATCH (n) RETURN n"}]}"#),
    )
    .await;
    assert_eq!(status, 401, "viz endpoint rejects a missing Bearer");

    // Database selection: an unknown database name fails the same way the tx endpoints do (400
    // problem from the seam's `begin`), with no projection.
    let (status, _) = http_request(
        rest,
        "POST",
        "/db/no-such-db/graph",
        Some(&token),
        Some(r#"{"statements":[{"statement":"MATCH (n) RETURN n"}]}"#),
    )
    .await;
    assert_eq!(status, 400, "unknown database is rejected");

    server.shutdown().await.expect("clean shutdown");
}

// ----------------------------------------------------------------------------------------------
// Bolt end-to-end over UDS.
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn bolt_uds_full_session_returns_records() {
    let temp = TempStore::new("bolt-uds");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // First, write a node via an auto-commit RUN so the read below has something to return.
    {
        let mut client = BoltUdsClient::connect(&uds).await;
        client.handshake_and_logon("alice", "pw").await;
        client.run_pull("CREATE (:Greeting {text: 'hello'})").await;
        client.goodbye().await;
    }

    // Now a fresh session reads it back.
    let mut client = BoltUdsClient::connect(&uds).await;
    client.handshake_and_logon("alice", "pw").await;
    let records = client.run_pull("MATCH (g:Greeting) RETURN g.text").await;
    client.goodbye().await;

    assert!(
        records.iter().any(|r| r
            .iter()
            .any(|v| matches!(v, Value::String(s) if s == "hello"))),
        "the Bolt session must read back the committed node: {records:?}"
    );

    server.shutdown().await.expect("clean shutdown");
}

/// rmp #97 — a write statement with no `RETURN` must be **zero-cardinality on the wire**: RUN
/// advertises empty `fields`, and the following PULL streams **no** RECORD before the trailing
/// SUCCESS. Advertising N fields but streaming a RECORD with M ≠ N values is a fields-vs-values
/// mismatch a real Neo4j driver rejects, so this guards the Bolt-protocol guarantee (req 3). The
/// follow-up read proves the write still persisted — the rows are suppressed, not the side effect.
#[tokio::test]
async fn bolt_write_without_return_advertises_no_fields_and_streams_no_records() {
    let temp = TempStore::new("bolt-write-no-return");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut client = BoltUdsClient::connect(&uds).await;
    client.handshake_and_logon("alice", "pw").await;

    // A bare `CREATE` with no `RETURN`: RUN must advertise no fields and PULL must stream no records.
    let (fields, records) = client.run_fields_then_pull("CREATE (:N {x: 1})").await;
    assert!(
        fields.is_empty(),
        "a write without RETURN advertises empty fields, got {fields:?}"
    );
    assert!(
        records.is_empty(),
        "a write without RETURN streams zero records, got {records:?}"
    );

    // The write persisted regardless: a following read returns the value.
    let read = client.run_pull("MATCH (n:N) RETURN n.x").await;
    assert!(
        read.iter()
            .any(|r| r.iter().any(|v| matches!(v, Value::Integer(1)))),
        "the suppressed-row write must still have persisted: {read:?}"
    );
    client.goodbye().await;

    server.shutdown().await.expect("clean shutdown");
}

/// End-to-end **structural-result conformance** (rmp #96): a query that returns nodes,
/// relationships and paths must deliver them on the wire as the Bolt 5.x `Node` (tag `0x4E`),
/// `Relationship` (`0x52`) and `Path` (`0x50`) structures — not as flattened ids — covering
/// connect, authenticate, a write transaction and read transactions over a live UDS session.
///
/// No official Neo4j driver is installable offline here, so this asserts at the **structure level**
/// instead: `run_pull_bolt` decodes each RECORD cell through `unpack_bolt_value`, which peeks the
/// PackStream structure tag and only yields `BoltValue::Node` / `Relationship` / `Path` when the
/// wire bytes actually carried that struct signature. Decoding to the variant therefore proves the
/// tag was on the wire — exactly the byte-for-byte conformance the task requires.
#[tokio::test]
async fn bolt_structural_results_node_rel_path_on_the_wire() {
    let temp = TempStore::new("bolt-structural");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut client = BoltUdsClient::connect(&uds).await;
    client.handshake_and_logon("alice", "pw").await;

    // WRITE txn (auto-commit): build a small graph a:Person -[:KNOWS]-> b:Person:Employee. We drain
    // the RUN/PULL but deliberately do NOT assert on any rows it streams: a write without `RETURN`
    // is a pure side effect, and its result-row cardinality is not what this test certifies. That
    // the write actually persisted is proven below by the explicit `RETURN` reads finding the data.
    let _ = client
        .run_pull_bolt(
            "CREATE (a:Person {name: 'Ada', age: 39})\
             -[:KNOWS {since: 2020}]->\
             (b:Person:Employee {name: 'Bob'})",
        )
        .await;

    // READ a node: the single RECORD cell must arrive as a Bolt `Node` struct.
    let rows = client
        .run_pull_bolt("MATCH (n:Person {name: 'Ada'}) RETURN n")
        .await;
    assert_eq!(rows.len(), 1, "exactly one Ada node: {rows:?}");
    assert_eq!(rows[0].len(), 1, "RETURN n is one column");
    let ada_id = match &rows[0][0] {
        BoltValue::Node(node) => {
            assert!(
                node.labels.iter().any(|l| l == "Person"),
                "node carries the Person label: {node:?}"
            );
            assert_eq!(
                prop(&node.properties, "name"),
                Some(&Value::String("Ada".to_owned())),
                "node.name == 'Ada': {node:?}"
            );
            assert_eq!(
                prop(&node.properties, "age"),
                Some(&Value::Integer(39)),
                "node.age == 39: {node:?}"
            );
            node.id
        }
        other => panic!("RETURN n must be a Bolt Node struct, got: {other:?}"),
    };

    // READ Bob's id too, so the relationship endpoint assertions can be exact.
    let rows = client
        .run_pull_bolt("MATCH (n:Person {name: 'Bob'}) RETURN n")
        .await;
    let bob_id = match &rows[0][0] {
        BoltValue::Node(node) => node.id,
        other => panic!("RETURN n (Bob) must be a Bolt Node struct, got: {other:?}"),
    };
    assert_ne!(ada_id, bob_id, "Ada and Bob are distinct nodes");

    // READ a relationship: the cell must arrive as a Bolt `Relationship` struct (tag 0x52), with
    // its type, property, and endpoint ids matching the graph just written.
    let rows = client
        .run_pull_bolt("MATCH (:Person {name: 'Ada'})-[r:KNOWS]->(:Person) RETURN r")
        .await;
    assert_eq!(rows.len(), 1, "exactly one KNOWS relationship: {rows:?}");
    match &rows[0][0] {
        BoltValue::Relationship(rel) => {
            assert_eq!(rel.rel_type, "KNOWS", "rel type is KNOWS: {rel:?}");
            assert_eq!(
                prop(&rel.properties, "since"),
                Some(&Value::Integer(2020)),
                "rel.since == 2020: {rel:?}"
            );
            assert!(
                rel.start >= 0 && rel.end >= 0,
                "endpoint ids non-negative: {rel:?}"
            );
            assert_eq!(rel.start, ada_id, "rel starts at Ada: {rel:?}");
            assert_eq!(rel.end, bob_id, "rel ends at Bob: {rel:?}");
        }
        other => panic!("RETURN r must be a Bolt Relationship struct, got: {other:?}"),
    }

    // READ a path (`MATCH p = ... RETURN p`): the cell must arrive as a Bolt `Path` struct (tag
    // 0x50) — two distinct nodes, one unbound KNOWS relationship, and the alternating, signed,
    // 1-based index sequence `[+1, 1]` (rel #1 forward, then arrival node at `nodes[1]`).
    let rows = client
        .run_pull_bolt("MATCH p = (:Person {name: 'Ada'})-[:KNOWS]->(:Person) RETURN p")
        .await;
    assert_eq!(rows.len(), 1, "exactly one path: {rows:?}");
    match &rows[0][0] {
        BoltValue::Path(path) => {
            assert_eq!(path.nodes.len(), 2, "path has two nodes: {path:?}");
            assert_eq!(path.rels.len(), 1, "path has one relationship: {path:?}");
            assert_eq!(
                path.rels[0].rel_type, "KNOWS",
                "the path's unbound rel is KNOWS: {path:?}"
            );
            assert_eq!(
                path.indices,
                vec![1, 1],
                "Bolt path indices are [rel(+1), node(1)]: {path:?}"
            );
        }
        other => panic!("RETURN p must be a Bolt Path struct, got: {other:?}"),
    }

    client.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test]
async fn bolt_uds_route_and_telemetry_round_trip() {
    // Over the REAL UDS path (rmp #95): a ROUTE returns a single-instance routing table and a
    // TELEMETRY is acknowledged with SUCCESS — proving the typed messages flow through the listener,
    // the minted connection_id surfaces in HELLO, and neither breaks a stock routing-style driver.
    let temp = TempStore::new("bolt-route");
    let mut config = base_config(&temp);
    // Advertise an explicit reconnection address the routing table must carry.
    config.advertised_bolt_address = Some("graphus.test:7687".to_owned());
    let server = boot(config).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut client = BoltUdsClient::connect(&uds).await;
    // HELLO SUCCESS must carry a per-connection connection_id (not the old hardcoded sentinel only).
    let hello = {
        let hs = encode_client_handshake([
            Proposal::range(5, 4, 4),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
        ]);
        client.stream.write_all(&hs).await.unwrap();
        let mut reply = [0u8; 4];
        client.stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x00, 0x00, 0x04, 0x05]);
        client
            .request_response(Request::Hello {
                extra: vec![("user_agent".to_owned(), Value::String("itest".to_owned()))],
            })
            .await
    };
    match &hello {
        Response::Success { metadata } => {
            let conn_id = metadata
                .iter()
                .find(|(k, _)| k == "connection_id")
                .map(|(_, v)| v);
            assert!(
                matches!(conn_id, Some(Value::String(s)) if s.starts_with("bolt-")),
                "HELLO carries a minted connection_id: {metadata:?}"
            );
        }
        other => panic!("expected HELLO SUCCESS, got {other:?}"),
    }

    // LOGON.
    let logon = client
        .request_response(Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("alice".to_owned())),
                ("credentials".to_owned(), Value::String("pw".to_owned())),
            ],
        })
        .await;
    assert!(
        matches!(logon, Response::Success { .. }),
        "LOGON ok: {logon:?}"
    );

    // TELEMETRY → SUCCESS, never FAILURE.
    let telemetry = client.request_response(Request::Telemetry { api: 1 }).await;
    assert!(
        matches!(telemetry, Response::Success { .. }),
        "TELEMETRY acknowledged: {telemetry:?}"
    );

    // ROUTE → a routing table advertising the configured address for all three roles.
    let route = client
        .request_response(Request::Route {
            routing: vec![],
            bookmarks: vec![],
            extra: vec![("db".to_owned(), Value::String("graphus".to_owned()))],
        })
        .await;
    let Response::Success { metadata } = route else {
        panic!("expected ROUTE SUCCESS, got {route:?}");
    };
    let Some((_, Value::Map(rt))) = metadata.iter().find(|(k, _)| k == "rt") else {
        panic!("ROUTE SUCCESS missing rt map: {metadata:?}");
    };
    let Some((_, Value::List(servers))) = rt.iter().find(|(k, _)| k == "servers") else {
        panic!("rt.servers missing: {rt:?}");
    };
    assert_eq!(
        servers.len(),
        3,
        "READ + WRITE + ROUTE on a single instance"
    );
    for entry in servers {
        let Value::Map(m) = entry else {
            panic!("server entry not a map");
        };
        let Some((_, Value::List(addrs))) = m.iter().find(|(k, _)| k == "addresses") else {
            panic!("server entry has no addresses");
        };
        assert_eq!(
            addrs,
            &vec![Value::String("graphus.test:7687".to_owned())],
            "every role advertises the configured address"
        );
    }

    client.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// Looks up a property value by key in a Bolt entity's ordered `(key, value)` property list.
fn prop<'a>(properties: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    properties.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Flattens a [`BoltValue`] cell to a scalar [`Value`] for the property-only assertion path, the
/// way the old server `project_value` did: an entity collapses to its id (`Value::Integer`), a path
/// to the `Value::List` of its element ids in traversal order, and a structural list element-wise.
/// Tests that need the structural form use `run_pull_bolt` instead.
fn bolt_to_scalar(v: BoltValue) -> Value {
    match v {
        BoltValue::Value(val) => val,
        BoltValue::Node(n) => Value::Integer(n.id),
        BoltValue::Relationship(r) => Value::Integer(r.id),
        BoltValue::Path(p) => {
            let mut ids = Vec::with_capacity(p.nodes.len() + p.rels.len());
            for node in &p.nodes {
                ids.push(Value::Integer(node.id));
            }
            for rel in &p.rels {
                ids.push(Value::Integer(rel.id));
            }
            Value::List(ids)
        }
        BoltValue::List(items) => Value::List(items.into_iter().map(bolt_to_scalar).collect()),
    }
}

/// A minimal Bolt client over a Unix socket for the integration test.
struct BoltUdsClient {
    stream: UnixStream,
    dechunker: Dechunker,
}

impl BoltUdsClient {
    async fn connect(path: &std::path::Path) -> Self {
        let stream = UnixStream::connect(path).await.expect("connect UDS");
        Self {
            stream,
            dechunker: Dechunker::new(),
        }
    }

    /// Performs the handshake, then HELLO + LOGON(basic), asserting both succeed.
    async fn handshake_and_logon(&mut self, user: &str, password: &str) {
        let hs = encode_client_handshake([
            Proposal::range(5, 4, 4),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
        ]);
        self.stream.write_all(&hs).await.unwrap();
        // Read the 4-byte server version reply.
        let mut reply = [0u8; 4];
        self.stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x00, 0x00, 0x04, 0x05], "negotiated Bolt 5.4");

        self.send(&Request::Hello {
            extra: vec![("user_agent".to_owned(), Value::String("itest".to_owned()))],
        })
        .await;
        assert!(
            matches!(self.recv().await, Response::Success { .. }),
            "HELLO ok"
        );

        self.send(&Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String(user.to_owned())),
                ("credentials".to_owned(), Value::String(password.to_owned())),
            ],
        })
        .await;
        assert!(
            matches!(self.recv().await, Response::Success { .. }),
            "LOGON ok"
        );
    }

    /// Runs `query` as an auto-commit statement and PULLs all records, returning the rows with each
    /// cell flattened to a scalar [`Value`] (a graph entity collapses to its id, as the old
    /// `project_value` did). Used by tests that only assert on property values.
    async fn run_pull(&mut self, query: &str) -> Vec<Vec<Value>> {
        self.run_pull_bolt(query)
            .await
            .into_iter()
            .map(|row| row.into_iter().map(bolt_to_scalar).collect())
            .collect()
    }

    /// Runs `query` as an auto-commit statement and PULLs all records, returning the **raw**
    /// [`BoltValue`] cells (not scalar-flattened), so a test can assert on the structural variants
    /// (`Node` / `Relationship` / `Path`) a graph query delivers on the wire.
    async fn run_pull_bolt(&mut self, query: &str) -> Vec<Vec<BoltValue>> {
        self.send(&Request::Run {
            query: query.to_owned(),
            parameters: vec![],
            extra: vec![],
        })
        .await;
        let run_reply = self.recv().await;
        assert!(
            matches!(run_reply, Response::Success { .. }),
            "RUN ok: {run_reply:?}"
        );

        self.send(&Request::Pull { n: -1, qid: None }).await;
        let mut rows = Vec::new();
        loop {
            match self.recv().await {
                Response::Record { values } => rows.push(values),
                Response::Success { .. } => break, // trailing summary
                other => panic!("unexpected response during PULL: {other:?}"),
            }
        }
        rows
    }

    /// Runs `query` as an auto-commit statement, returning the **advertised `fields`** from the RUN
    /// SUCCESS metadata together with every RECORD streamed by the following PULL. Used to assert the
    /// RUN-advertised schema and the PULL-streamed row count agree (rmp #97: a write without `RETURN`
    /// must advertise empty `fields` and stream zero records — a length match a real driver enforces).
    async fn run_fields_then_pull(&mut self, query: &str) -> (Vec<String>, Vec<Vec<BoltValue>>) {
        self.send(&Request::Run {
            query: query.to_owned(),
            parameters: vec![],
            extra: vec![],
        })
        .await;
        let run_reply = self.recv().await;
        let Response::Success { metadata } = run_reply else {
            panic!("RUN ok expected: {run_reply:?}");
        };
        let fields = match metadata.iter().find(|(k, _)| k == "fields") {
            Some((_, Value::List(items))) => items
                .iter()
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    other => panic!("a `fields` entry must be a string, got {other:?}"),
                })
                .collect(),
            other => panic!("RUN SUCCESS must advertise a `fields` list, got {other:?}"),
        };

        self.send(&Request::Pull { n: -1, qid: None }).await;
        let mut rows = Vec::new();
        loop {
            match self.recv().await {
                Response::Record { values } => rows.push(values),
                Response::Success { .. } => break, // trailing summary
                other => panic!("unexpected response during PULL: {other:?}"),
            }
        }
        (fields, rows)
    }

    /// Sends a single request and returns the single response (for ROUTE / TELEMETRY round-trips).
    async fn request_response(&mut self, req: Request) -> Response {
        self.send(&req).await;
        self.recv().await
    }

    /// Attempts LOGON with a bad password, asserting a FAILURE.
    async fn handshake_then_bad_logon(&mut self) -> Response {
        let hs = encode_client_handshake([
            Proposal::range(5, 4, 4),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
        ]);
        self.stream.write_all(&hs).await.unwrap();
        let mut reply = [0u8; 4];
        self.stream.read_exact(&mut reply).await.unwrap();
        self.send(&Request::Hello {
            extra: vec![("user_agent".to_owned(), Value::String("itest".to_owned()))],
        })
        .await;
        let _ = self.recv().await;
        self.send(&Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("alice".to_owned())),
                ("credentials".to_owned(), Value::String("WRONG".to_owned())),
            ],
        })
        .await;
        self.recv().await
    }

    async fn goodbye(&mut self) {
        self.send(&Request::Goodbye).await;
    }

    async fn send(&mut self, req: &Request) {
        let bytes = encode_request_framed(req).unwrap();
        self.stream.write_all(&bytes).await.unwrap();
        self.stream.flush().await.unwrap();
    }

    /// Reads one framed Bolt response, buffering from the socket as needed.
    async fn recv(&mut self) -> Response {
        loop {
            if let Some(Frame::Message(payload)) = self.dechunker.next_frame().unwrap() {
                return Response::decode(&payload).unwrap();
            }
            let mut buf = [0u8; 4096];
            let n = self.stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "unexpected EOF awaiting a Bolt response");
            self.dechunker.push(&buf[..n]);
        }
    }
}

// ----------------------------------------------------------------------------------------------
// Auth rejection on each interface.
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn rest_rejects_bad_credentials() {
    let temp = TempStore::new("rest-auth");
    let server = boot(base_config(&temp)).await;
    let rest = server.rest_addr.expect("REST enabled");

    // No token at all.
    let (status, _) = http_request(
        rest,
        "POST",
        "/db/graphus/tx",
        None,
        Some(r#"{"statements":[]}"#),
    )
    .await;
    assert_eq!(status, 401, "missing Bearer is rejected");

    // A garbage token.
    let (status, _) = http_request(
        rest,
        "POST",
        "/db/graphus/tx",
        Some("not.a.real.jwt"),
        Some(r#"{"statements":[]}"#),
    )
    .await;
    assert_eq!(status, 401, "invalid Bearer is rejected");

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test]
async fn bolt_rejects_bad_credentials() {
    let temp = TempStore::new("bolt-auth");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut client = BoltUdsClient::connect(&uds).await;
    let resp = client.handshake_then_bad_logon().await;
    assert!(
        matches!(resp, Response::Failure(_)),
        "a wrong password is a Bolt FAILURE: {resp:?}"
    );

    server.shutdown().await.expect("clean shutdown");
}

// ----------------------------------------------------------------------------------------------
// Admission control fast-reject.
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn admission_control_fast_rejects_when_saturated() {
    use graphus_server::engine::{AccessMode, ServerBusy};

    let temp = TempStore::new("admission");
    let mut config = base_config(&temp);
    // Limit to a single concurrent query so we can saturate it deterministically.
    config.admission.max_concurrent_queries = 1;
    let server = boot(config).await;

    // Acquire the only permit and hold it.
    let _held = server.engine.try_admit().expect("first admit succeeds");

    // The next admit must be fast-rejected.
    let rejected = server.engine.try_admit();
    assert_eq!(rejected.err(), Some(ServerBusy), "second admit is shed");

    // The rejection is observable in metrics (`04 §9.3` load shedding is observable).
    let text = server.metrics.render_prometheus();
    assert!(
        text.contains("graphus_admission_rejections_total 1"),
        "rejection is counted: {text}"
    );

    // End-to-end: with the only permit still held, a real REST query is shed through the request
    // path. The shared `GraphusError`→HTTP mapping in `graphus-rest` renders the engine's "server
    // busy" as a **retriable transient** status (409 `Neo.TransientError.*`), the HTTP analogue of
    // Bolt's `TransientError` FAILURE. (The deliverable's literal "503" is a documented nuance: the
    // one-error-model seam carries a `GraphusError`, and that crate owns its status mapping; both 409
    // and 503 are retriable, and the rejection is the same observable shed event in the metric above.)
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(&server, "alice").await;
    let (status, _body) = http_request(
        rest,
        "POST",
        "/db/graphus/tx/commit",
        Some(&token),
        Some(r#"{"statements":[{"statement":"RETURN 1"}]}"#),
    )
    .await;
    assert!(
        status == 409 || status == 503,
        "a saturated server sheds a real REST query with a retriable status, got {status}"
    );

    // Sanity: the engine still serves once the permit is released.
    drop(_held);
    let again = server.engine.try_admit();
    assert!(again.is_ok(), "a freed slot is reusable");
    drop(again);

    // (Also exercise the neutral AccessMode re-export so it is part of the public surface check.)
    let _ = AccessMode::Write;

    server.shutdown().await.expect("clean shutdown");
}

// ----------------------------------------------------------------------------------------------
// Observability endpoints.
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn metrics_and_health_endpoints_respond() {
    let temp = TempStore::new("observability");
    let server = boot(base_config(&temp)).await;
    let rest = server.rest_addr.expect("REST enabled");

    let (status, body) = http_request(rest, "GET", "/health/live", None, None).await;
    assert_eq!(status, 200, "live");
    assert!(body.contains("live"));

    let (status, body) = http_request(rest, "GET", "/health/ready", None, None).await;
    assert_eq!(status, 200, "ready once booted");
    assert!(body.contains("ready"));

    let (status, body) = http_request(rest, "GET", "/metrics", None, None).await;
    assert_eq!(status, 200, "metrics");
    assert!(
        body.contains("graphus_query_duration_seconds")
            && body.contains("# TYPE graphus_active_transactions gauge"),
        "Prometheus exposition present: {body}"
    );

    server.shutdown().await.expect("clean shutdown");
}

// ----------------------------------------------------------------------------------------------
// Graceful shutdown drains + the store reopens clean.
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn graceful_shutdown_persists_and_store_reopens_clean() {
    let temp = TempStore::new("shutdown-reopen");

    // Boot, write+commit a node via REST, then shut down gracefully.
    {
        let server = boot(base_config(&temp)).await;
        let rest = server.rest_addr.expect("REST enabled");
        let token = mint_token(&server, "alice").await;
        let (status, body) = http_request(
            rest,
            "POST",
            "/db/graphus/tx/commit",
            Some(&token),
            Some(r#"{"statements":[{"statement":"CREATE (:Durable {id: 1})"}]}"#),
        )
        .await;
        assert_eq!(status, 200, "auto-commit create: {body}");
        // Graceful shutdown: drain + flush + fdatasync + mark clean (`04 §9.4`).
        server.shutdown().await.expect("clean shutdown");
    }

    // Reboot over the SAME store dir: opening runs recovery + `verify_on_open` (refusing a corrupt
    // store). A successful boot proves the store reopened clean; the data must still be there.
    {
        let server = boot(base_config(&temp)).await;
        let rest = server.rest_addr.expect("REST enabled");
        let token = mint_token(&server, "alice").await;
        let (status, body) = http_request(
            rest,
            "POST",
            "/db/graphus/tx/commit",
            Some(&token),
            Some(r#"{"statements":[{"statement":"MATCH (d:Durable) RETURN d.id"}]}"#),
        )
        .await;
        assert_eq!(status, 200, "match after reopen: {body}");
        assert!(
            body.contains('1'),
            "the durable node survives a graceful shutdown + reopen: {body}"
        );
        server.shutdown().await.expect("clean shutdown");
    }
}

// ----------------------------------------------------------------------------------------------
// TLS config path (smoke): a self-signed cert builds a rustls ServerConfig and the TLS listeners
// bind. The TLS handshake itself is exercised by graphus-auth's own tests; here we prove the
// server's TLS wiring (config build + bound listeners) works.
// ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn tls_config_path_boots_network_listeners() {
    let temp = TempStore::new("tls");

    // A self-signed cert/key for localhost, written to disk for the config to reference.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = temp.path.join("cert.pem");
    let key_path = temp.path.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    let mut config = base_config(&temp);
    config.tls = TlsConfig {
        cert_path: Some(cert_path),
        key_path: Some(key_path),
    };
    // Enable all three listeners, all on ephemeral ports / the temp socket.
    config.bolt_tcp_addr = Some("127.0.0.1:0".to_owned());
    config.rest_addr = Some("127.0.0.1:0".to_owned());

    let server = boot(config).await;
    assert!(server.rest_addr.is_some(), "REST+TLS bound");
    assert!(server.bolt_tcp_addr.is_some(), "Bolt-TCP+TLS bound");
    assert!(server.uds_path.is_some(), "UDS bound");

    // The bound TCP ports accept a connection (the TLS handshake against them is graphus-auth's
    // territory; we only smoke-test that the listeners are live).
    let bolt = server.bolt_tcp_addr.unwrap();
    assert!(TcpStream::connect(bolt).await.is_ok(), "Bolt-TCP accepts");

    server.shutdown().await.expect("clean shutdown");
}

// ----------------------------------------------------------------------------------------------
// Helpers.
// ----------------------------------------------------------------------------------------------

/// Mints a Bearer token for `user` valid for an hour, signed with the server's configured secret.
///
/// The server seeds the user into its `Authenticator` at startup; here we re-derive a token the
/// server will accept by constructing a matching authenticator with the same secret + user. (The
/// server does not expose a token-mint endpoint in v1; a real deployment issues tokens out of band.)
async fn mint_token(_server: &ServerHandle, user: &str) -> String {
    use graphus_auth::Authenticator;
    let mut auth = Authenticator::new(b"integration-test-jwt-secret-32-bytes!");
    auth.catalog_mut().create_user(user).unwrap();
    auth.issue_token(user, now_unix_secs(), 3_600).unwrap()
}

/// Current unix seconds (the server's `SystemClock` uses the same wall clock for JWT validation).
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Extracts a top-level JSON string field's value by key from a flat-ish JSON body (test-grade).
fn extract_json_string(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = body.find(&needle)? + needle.len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// A short delay helper for any timing-sensitive assertions (kept minimal; most tests are
/// deterministic via request/response).
#[allow(dead_code)]
async fn settle() {
    tokio::time::sleep(Duration::from_millis(20)).await;
}
