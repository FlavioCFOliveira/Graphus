//! `EXPLAIN` / `PROFILE` over the **real Bolt wire** (`rmp` task #752).
//!
//! Everything else in this feature can be (and is) unit-tested inside `graphus-cypher`. What only this
//! test can prove is the property the task exists for: **a client can inspect the plan of a query it
//! sent, and can therefore detect a planner regression from an index seek to a full scan.**
//!
//! It boots a real server (UDS listener), connects with the real synchronous Bolt client, and drives
//! everything — the seeding, the index DDL, the queries — over the socket. The assertions are on what
//! comes back in the `SUCCESS` metadata: the `plan` key (EXPLAIN) and the `profile` key (PROFILE), in the
//! Neo4j 5.x shape.
//!
//! Unix-only (it relies on UDS); elsewhere it compiles to nothing so `cargo test` stays green.

#![cfg(unix)]

use std::path::PathBuf;

use graphus_cli::client::BoltClient;
use graphus_core::Value;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::{Server, ServerHandle};

// =================================================================================================
// Harness: a real server on a real socket
// =================================================================================================

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
            "graphus-explain-{tag}-{nanos}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
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
        store_path: temp.path.join("store"),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        bolt_server_agent: None,
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
            slow_query_threshold_ms: 10_000,
            shutdown_drain_deadline_ms: 5_000,
            ..TimingConfig::default()
        },
        jwt_secret: "explain-profile-itest-jwt-secret-uds!".to_owned(),
        auth: AuthBootstrap {
            admin_user: "alice".to_owned(),
            admin_password: "admin-pw8".to_owned(),
            // The UDS listener refuses an unmapped uid at accept time (the `SO_PEERCRED` gate), so bind
            // the admin to this process's uid — the same thing every other UDS integration test does.
            admin_uid: Some(current_uid()),
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: graphus_server::AuditConfig::default(),
        allow_insecure_network: false,
        bulk_import: graphus_server::config::BulkImportConfig::default(),
        metrics_scrape_token: None,
    }
}

/// This process's uid, so the UDS peer-cred gate admits the test's own connections (the same approach
/// as the other UDS integration tests: read `/proc/self/status` on Linux, `id -u` elsewhere).
fn current_uid() -> u32 {
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
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0)
    }
}

async fn boot(temp: &TempStore) -> ServerHandle {
    Server::new(config(temp))
        .start()
        .await
        .expect("the server boots")
}

fn connect(temp: &TempStore) -> BoltClient<std::os::unix::net::UnixStream> {
    let mut client = BoltClient::connect_uds(&temp.uds_path()).expect("connect over UDS");
    client.login("alice", "admin-pw8").expect("login");
    client
}

// =================================================================================================
// Reading the plan out of the SUCCESS metadata (what a driver does)
// =================================================================================================

/// The plan a statement reported, and under which key.
struct WirePlan {
    key: String,
    root: Value,
}

fn wire_plan(summary: &[(String, Value)]) -> Option<WirePlan> {
    for key in ["profile", "plan"] {
        if let Some((_, v)) = summary.iter().find(|(k, _)| k == key) {
            return Some(WirePlan {
                key: key.to_owned(),
                root: v.clone(),
            });
        }
    }
    None
}

fn map_get<'v>(v: &'v Value, key: &str) -> Option<&'v Value> {
    match v {
        Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

/// Every `operatorType` in the plan, pre-order.
fn operators(node: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(Value::String(t)) = map_get(node, "operatorType") {
        out.push(t.clone());
    }
    if let Some(Value::List(children)) = map_get(node, "children") {
        for c in children {
            out.extend(operators(c));
        }
    }
    out
}

/// The sum of every operator's measured `dbHits`.
fn total_db_hits(node: &Value) -> i64 {
    let mine = match map_get(node, "dbHits") {
        Some(Value::Integer(n)) => *n,
        _ => 0,
    };
    let kids = match map_get(node, "children") {
        Some(Value::List(children)) => children.iter().map(total_db_hits).sum(),
        _ => 0,
    };
    mine + kids
}

// =================================================================================================
// The tests
// =================================================================================================

/// The headline acceptance criterion: **a regression from an index seek to a full scan is detectable
/// from a client**, over the wire, on a query whose results are identical either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seek_to_scan_regression_is_detectable_over_the_wire() {
    let temp = TempStore::new("regression");
    let server = boot(&temp).await;

    let rows = tokio::task::spawn_blocking(move || {
        let mut c = connect(&temp);

        // Seed 300 people, then declare the index the planner should use.
        c.run("UNWIND range(0, 299) AS i CREATE (:Person {email: 'u' + toString(i) + '@x.io'})")
            .expect("seed");
        c.run("CREATE INDEX person_email FOR (p:Person) ON (p.email)")
            .expect("create index");

        let query = "PROFILE MATCH (p:Person {email: 'u7@x.io'}) RETURN p.email AS email";

        // --- with the index -------------------------------------------------------------------
        let seek = c.run(query).expect("profiled seek");
        let seek_plan = wire_plan(&seek.summary).expect("a PROFILE reports a plan");
        assert_eq!(seek_plan.key, "profile", "a PROFILE uses the `profile` key");
        let seek_ops = operators(&seek_plan.root);
        assert_eq!(seek.records.len(), 1, "one person matches");

        // --- the regression: the index is dropped, the query is unchanged ----------------------
        c.run("DROP INDEX person_email").expect("drop index");
        let scan = c.run(query).expect("profiled scan");
        let scan_plan = wire_plan(&scan.summary).expect("a PROFILE reports a plan");
        let scan_ops = operators(&scan_plan.root);

        // The RESULT is identical — which is exactly why the plan is the only way to catch this.
        assert_eq!(scan.records, seek.records);

        (
            seek_ops,
            scan_ops,
            total_db_hits(&seek_plan.root),
            total_db_hits(&scan_plan.root),
        )
    })
    .await
    .expect("client thread");

    let (seek_ops, scan_ops, seek_hits, scan_hits) = rows;
    println!("seek plan: {seek_ops:?} dbHits={seek_hits}");
    println!("scan plan: {scan_ops:?} dbHits={scan_hits}");

    // THE assertion: the index-backed plan reports the seek operator, and the regressed plan does not.
    assert!(
        seek_ops.iter().any(|o| o == "NodeIndexSeek"),
        "the declared index must show up as a NodeIndexSeek: {seek_ops:?}"
    );
    assert!(
        !scan_ops.iter().any(|o| o == "NodeIndexSeek"),
        "with the index dropped the query must NOT report a seek: {scan_ops:?}"
    );
    assert!(
        scan_ops.iter().any(|o| o == "NodeLabelScanEq"),
        "the regressed query scans: {scan_ops:?}"
    );
    // The scan's measured cost is the whole label — not a guess, a count of records the seam read.
    assert!(
        scan_hits >= 300,
        "the scan read every one of the 300 seeded nodes: dbHits={scan_hits}"
    );

    let _ = server.shutdown().await;
}

/// `EXPLAIN` does not execute — proven over the wire, on a statement whose side effect would be visible.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explain_over_the_wire_returns_a_plan_and_creates_nothing() {
    let temp = TempStore::new("explain");
    let server = boot(&temp).await;

    tokio::task::spawn_blocking(move || {
        let mut c = connect(&temp);

        let explained = c
            .run("EXPLAIN CREATE (:Ghost {name: 'nobody'})")
            .expect("EXPLAIN runs");
        assert!(explained.records.is_empty(), "EXPLAIN returns zero records");
        let plan = wire_plan(&explained.summary).expect("EXPLAIN reports a plan");
        assert_eq!(
            plan.key, "plan",
            "an EXPLAIN uses the `plan` key, not `profile`"
        );
        assert!(operators(&plan.root).iter().any(|o| o == "Create"));
        // Nothing ran, so no runtime counter is reported (never a fabricated zero).
        assert!(map_get(&plan.root, "dbHits").is_none());
        assert!(map_get(&plan.root, "rows").is_none());

        // …and the node really was not created.
        let count = c
            .run("MATCH (g:Ghost) RETURN count(g) AS n")
            .expect("count");
        assert_eq!(
            count.records[0][0],
            Value::Integer(0),
            "EXPLAIN CREATE must create nothing"
        );

        // An EXPLAIN of a READ is dispatched to the off-thread reader pool (it is a structurally
        // read-only auto-commit statement), so this also proves the reader path reports the plan — and
        // that it, too, executes nothing.
        c.run("CREATE (:Ghost {name: 'real'})")
            .expect("seed a ghost");
        let read = c
            .run("EXPLAIN MATCH (g:Ghost) RETURN g.name AS name")
            .expect("EXPLAIN a read");
        assert!(
            read.records.is_empty(),
            "an EXPLAINed read returns no records even though rows exist"
        );
        assert_eq!(
            read.fields,
            vec!["name".to_owned()],
            "…but its columns are reported"
        );
        let read_plan = wire_plan(&read.summary).expect("the reader pool reports the plan too");
        assert_eq!(read_plan.key, "plan");
        assert!(operators(&read_plan.root).iter().any(|o| o == "Projection"));

        // An ordinary statement carries no plan at all.
        let plain = c.run("MATCH (g:Ghost) RETURN g").expect("plain");
        assert!(wire_plan(&plain.summary).is_none());
        assert_eq!(
            plain.records.len(),
            1,
            "the ghost really is there to be read"
        );

        // The prefix is not a reserved word: `explain` still works as an alias, over the wire.
        let alias = c.run("RETURN 1 AS explain").expect("alias");
        assert_eq!(alias.fields, vec!["explain".to_owned()]);
        assert!(wire_plan(&alias.summary).is_none());

        c.goodbye().expect("goodbye");
    })
    .await
    .expect("client thread");

    let _ = server.shutdown().await;
}

/// `PROFILE` returns the statement's rows AND a plan annotated with measured counters, in the Neo4j
/// 5.x wire shape a driver parses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn profile_over_the_wire_returns_rows_and_measured_counters() {
    let temp = TempStore::new("profile");
    let server = boot(&temp).await;

    tokio::task::spawn_blocking(move || {
        let mut c = connect(&temp);
        c.run("UNWIND range(0, 9) AS i CREATE (:Item {n: i})")
            .expect("seed");

        let r = c
            .run("PROFILE MATCH (i:Item) WHERE i.n >= 5 RETURN i.n AS n")
            .expect("profile");
        assert_eq!(
            r.records.len(),
            5,
            "PROFILE runs the query and returns rows"
        );

        let plan = wire_plan(&r.summary).expect("a plan");
        assert_eq!(plan.key, "profile");

        // The Neo4j 5.x plan-node shape, exactly.
        assert!(matches!(
            map_get(&plan.root, "operatorType"),
            Some(Value::String(_))
        ));
        assert!(matches!(map_get(&plan.root, "args"), Some(Value::Map(_))));
        assert!(
            map_get(&plan.root, "arguments").is_none(),
            "the wire key is `args`, never `arguments`"
        );
        assert!(matches!(
            map_get(&plan.root, "identifiers"),
            Some(Value::List(_))
        ));
        assert!(matches!(
            map_get(&plan.root, "children"),
            Some(Value::List(_))
        ));
        // The measured counters are top-level siblings, as Neo4j sends them.
        assert_eq!(
            map_get(&plan.root, "rows"),
            Some(&Value::Integer(5)),
            "the root emitted the 5 rows the client received"
        );
        assert!(matches!(
            map_get(&plan.root, "dbHits"),
            Some(Value::Integer(_))
        ));
        assert!(
            total_db_hits(&plan.root) >= 10,
            "the label scan read all 10 items: {}",
            total_db_hits(&plan.root)
        );

        // A leaf omits `children` entirely (it does not send an empty list) — as Neo4j does.
        let mut leaf = &plan.root;
        while let Some(Value::List(children)) = map_get(leaf, "children") {
            leaf = children.first().expect("a non-empty children list");
        }
        assert!(map_get(leaf, "children").is_none());

        // `PROFILE` really writes, too.
        let w = c
            .run("PROFILE CREATE (:Item {n: 99}) RETURN 1 AS ok")
            .expect("profiled write");
        let created = w
            .summary
            .iter()
            .find(|(k, _)| k == "stats")
            .and_then(|(_, v)| map_get(v, "nodes-created").cloned());
        assert_eq!(created, Some(Value::Integer(1)), "PROFILE really writes");
        let count = c.run("MATCH (i:Item) RETURN count(i) AS n").expect("count");
        assert_eq!(count.records[0][0], Value::Integer(11));

        c.goodbye().expect("goodbye");
    })
    .await
    .expect("client thread");

    let _ = server.shutdown().await;
}

/// **The finding `PROFILE` exposed (`rmp` #752), now pinned as its FIX (`rmp` #755).**
///
/// An auto-commit read is dispatched to the off-thread **reader pool** (`rmp` #336/#543). Its seam
/// (`ReadOnlyGraph`) used to implement **no** `index_seek_*` method: it declined every property-index
/// seek and the executor fell back — correctly, but expensively — to a full scan. So an indexed query
/// sent over the wire as a plain auto-commit read reported `NodeIndexSeek` in its plan (the planner
/// *did* choose the index) while its measured `dbHits` were those of a full scan. Measured, on the same
/// 300-node data:
///
/// | seam | operator | `dbHits` before #755 | after |
/// |------|----------|----------------------|-------|
/// | inline store seam (`RecordStoreGraph`) | `NodeIndexSeek` | **2** | 2 |
/// | inline store seam, index dropped | `NodeLabelScanEq` | 201 | 201 |
/// | **off-thread reader** (this test, over Bolt, 300 nodes) | `NodeIndexSeek` | **301** — the whole store | **a real seek** |
///
/// The plan was right; the *execution* did not use the index. It was never a correctness bug — the rows
/// are identical either way, which is exactly why it went unnoticed until `PROFILE` measured it.
///
/// `rmp` #755 (Slice S2) closes it: the engine thread pre-runs the plan's statically-knowable equality
/// seeks at dispatch and hands the reader the candidate ids, which the reader re-checks through the same
/// lifted body the inline seam uses. This test now pins the FIX with the threshold the finding itself
/// named — `seek_hits * 4 < scan_hits`, matching what the inline seam already achieved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_off_thread_reader_serves_the_index_seek_and_profile_measures_it() {
    let temp = TempStore::new("readerpool");
    let server = boot(&temp).await;

    let (seek_ops, seek_hits, scan_hits) = tokio::task::spawn_blocking(move || {
        let mut c = connect(&temp);
        c.run("UNWIND range(0, 299) AS i CREATE (:Person {email: 'u' + toString(i) + '@x.io'})")
            .expect("seed");
        c.run("CREATE INDEX person_email FOR (p:Person) ON (p.email)")
            .expect("index");

        let query = "PROFILE MATCH (p:Person {email: 'u7@x.io'}) RETURN p.email AS email";
        let seek = c.run(query).expect("indexed read");
        let seek_plan = wire_plan(&seek.summary).expect("plan");

        c.run("DROP INDEX person_email").expect("drop");
        let scan = c.run(query).expect("unindexed read");
        let scan_plan = wire_plan(&scan.summary).expect("plan");

        (
            operators(&seek_plan.root),
            total_db_hits(&seek_plan.root),
            total_db_hits(&scan_plan.root),
        )
    })
    .await
    .expect("client thread");

    assert!(
        seek_ops.iter().any(|o| o == "NodeIndexSeek"),
        "the planner DID pick the index: {seek_ops:?}"
    );
    assert!(
        seek_hits * 4 < scan_hits,
        "MEASURED FIX (rmp #755): an auto-commit read runs on the reader pool, which now SERVES the \
         index seek from the candidates captured at dispatch — so the indexed query must read a small \
         fraction of what the unindexed one reads (seek={seek_hits}, scan={scan_hits}). Before #755 \
         these were EQUAL (301 vs 301: the whole 300-node store) while the plan still said NodeIndexSeek."
    );

    let _ = server.shutdown().await;
}

/// **`rmp` #768 — the off-thread reader now serves a node RANGE seek, MEASURED.**
///
/// `rmp` #755 taught the reader pool only node-property **equality** seeks. Every other node-property
/// seek — RANGE (`<`/`<=`/`>`/`>=`), COMPOSITE, TEXT — still fell to the reader's `GraphAccess` default
/// (`None`) and full-scanned the label while the plan named the index. This pins the RANGE fix the way
/// the equality one is pinned: a `PROFILE`d auto-commit read over the wire (so it runs on the reader
/// pool) whose **measured `dbHits`** must be a small fraction of the same query's full scan. Asserting
/// the operator NAME is deliberately NOT enough — a `NodeIndexRangeSeek` in the plan is exactly what
/// shipped over a full scan.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_off_thread_reader_serves_a_range_seek_and_profile_measures_it() {
    let temp = TempStore::new("readerpool-range");
    let server = boot(&temp).await;

    let (seek_ops, seek_hits, scan_hits) = tokio::task::spawn_blocking(move || {
        let mut c = connect(&temp);
        // 300 items 0..=299; the seek `n >= 295` matches only the top 5.
        c.run("UNWIND range(0, 299) AS i CREATE (:Item {n: i})")
            .expect("seed");
        c.run("CREATE INDEX item_n FOR (x:Item) ON (x.n)")
            .expect("index");

        let query = "PROFILE MATCH (x:Item) WHERE x.n >= 295 RETURN x.n AS n";
        let seek = c.run(query).expect("indexed range read");
        let seek_plan = wire_plan(&seek.summary).expect("plan");
        assert_eq!(seek.records.len(), 5, "295..=299 match");

        c.run("DROP INDEX item_n").expect("drop");
        let scan = c.run(query).expect("unindexed range read");
        let scan_plan = wire_plan(&scan.summary).expect("plan");
        assert_eq!(scan.records.len(), 5, "the rows are identical either way");

        (
            operators(&seek_plan.root),
            total_db_hits(&seek_plan.root),
            total_db_hits(&scan_plan.root),
        )
    })
    .await
    .expect("client thread");

    assert!(
        seek_ops.iter().any(|o| o == "NodeIndexRangeSeek"),
        "the planner DID pick the range index: {seek_ops:?}"
    );
    assert!(
        seek_hits * 4 < scan_hits,
        "MEASURED FIX (rmp #768): the reader pool now SERVES the range seek from the candidates \
         captured at dispatch, so the indexed range must read a small fraction of the full scan \
         (seek={seek_hits}, scan={scan_hits}). Before #768 the off-thread reader declined every range \
         seek and read the whole label while the plan still said NodeIndexRangeSeek."
    );

    let _ = server.shutdown().await;
}

/// **`rmp` #768 — the off-thread reader now serves a node COMPOSITE (multi-property) seek, MEASURED.**
///
/// Same shape as the range test, for a two-property composite equality seek
/// (`{dept: …, team: …}`) backed by a composite `RANGE` index.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_off_thread_reader_serves_a_composite_seek_and_profile_measures_it() {
    let temp = TempStore::new("readerpool-composite");
    let server = boot(&temp).await;

    let (seek_ops, seek_hits, scan_hits) = tokio::task::spawn_blocking(move || {
        let mut c = connect(&temp);
        // Each employee has a UNIQUE (dept, team) pair, so the composite seek matches exactly one.
        c.run(
            "UNWIND range(0, 299) AS i \
             CREATE (:Emp {dept: 'D' + toString(i), team: 'T' + toString(i)})",
        )
        .expect("seed");
        c.run("CREATE INDEX emp_dept_team FOR (e:Emp) ON (e.dept, e.team)")
            .expect("composite index");

        let query = "PROFILE MATCH (e:Emp {dept: 'D7', team: 'T7'}) RETURN e.dept AS d";
        let seek = c.run(query).expect("indexed composite read");
        let seek_plan = wire_plan(&seek.summary).expect("plan");
        assert_eq!(seek.records.len(), 1, "one employee matches (D7, T7)");

        c.run("DROP INDEX emp_dept_team").expect("drop");
        let scan = c.run(query).expect("unindexed composite read");
        let scan_plan = wire_plan(&scan.summary).expect("plan");
        assert_eq!(
            scan.records, seek.records,
            "the rows are identical either way"
        );

        (
            operators(&seek_plan.root),
            total_db_hits(&seek_plan.root),
            total_db_hits(&scan_plan.root),
        )
    })
    .await
    .expect("client thread");

    assert!(
        seek_ops.iter().any(|o| o == "NodeCompositeIndexSeek"),
        "the planner DID pick the composite index: {seek_ops:?}"
    );
    assert!(
        seek_hits * 4 < scan_hits,
        "MEASURED FIX (rmp #768): the reader pool now SERVES the composite seek from the candidates \
         captured at dispatch (seek={seek_hits}, scan={scan_hits}). Before #768 the off-thread reader \
         declined it and read the whole label while the plan still said NodeCompositeIndexSeek."
    );

    let _ = server.shutdown().await;
}

/// **`rmp` #768 — the off-thread reader now serves a node TEXT (trigram) seek, MEASURED.**
///
/// This is the exact residual the `rmp` #746 index-seek gate reproduced on a live server:
/// `NodeTextIndexSeek` in the plan, a full-scan `dbHits` at runtime. A `CONTAINS` auto-commit read over
/// the wire must now measure a small fraction of its full scan.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_off_thread_reader_serves_a_text_seek_and_profile_measures_it() {
    let temp = TempStore::new("readerpool-text");
    let server = boot(&temp).await;

    let (seek_ops, seek_hits, scan_hits) = tokio::task::spawn_blocking(move || {
        let mut c = connect(&temp);
        // Bodies `doc0xyz`..`doc299xyz`; the 3-char needle `c7x` forms a trigram and matches only `doc7xyz`.
        c.run("UNWIND range(0, 299) AS i CREATE (:Doc {body: 'doc' + toString(i) + 'xyz'})")
            .expect("seed");
        c.run("CREATE TEXT INDEX doc_body FOR (d:Doc) ON (d.body)")
            .expect("text index");

        let query = "PROFILE MATCH (d:Doc) WHERE d.body CONTAINS 'c7x' RETURN d.body AS b";
        let seek = c.run(query).expect("indexed text read");
        let seek_plan = wire_plan(&seek.summary).expect("plan");
        assert_eq!(seek.records.len(), 1, "only doc7xyz contains 'c7x'");

        c.run("DROP INDEX doc_body").expect("drop");
        let scan = c.run(query).expect("unindexed text read");
        let scan_plan = wire_plan(&scan.summary).expect("plan");
        assert_eq!(
            scan.records, seek.records,
            "the rows are identical either way"
        );

        (
            operators(&seek_plan.root),
            total_db_hits(&seek_plan.root),
            total_db_hits(&scan_plan.root),
        )
    })
    .await
    .expect("client thread");

    assert!(
        seek_ops.iter().any(|o| o == "NodeTextIndexSeek"),
        "the planner DID pick the text index: {seek_ops:?}"
    );
    assert!(
        seek_hits * 4 < scan_hits,
        "MEASURED FIX (rmp #768, the #746 I9 residual): the reader pool now SERVES the trigram text \
         seek from the candidates captured at dispatch (seek={seek_hits}, scan={scan_hits}). Before \
         #768 the off-thread reader declined it and read the whole label while the plan still said \
         NodeTextIndexSeek — measured on the live server as text_seek_hits=801 == text_scan_hits=801."
    );

    let _ = server.shutdown().await;
}
