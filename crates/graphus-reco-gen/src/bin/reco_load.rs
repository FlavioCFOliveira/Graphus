//! `reco_load` — the network **bulk-import (Mode A) loader + schema DDL + correctness gate** for
//! `examples/product-recommendation`.
//!
//! It drives the deterministic recommendation graph (the CSV file set produced by `reco_gen`) into an
//! **already-running** `graphus-server` over the wire, using the ratified network bulk-import **Mode
//! A** happy path (`specification/08-network-bulk-import.md`, `rmp` #518/#519): create a fresh empty
//! database, stream the node files then the relationship files, `end` the session, then bring the
//! database online, declare the production-realistic **read-path schema**, and assert the graph shape,
//! the index-backed query paths, and constraint enforcement.
//!
//! # The schema it declares (`rmp` #676)
//!
//! Once the graph is online, the loader applies the shared [`graphus_reco_gen::schema::schema_ddl`]
//! block — a **`NODE KEY`** on `User.id` and a **`UNIQUE`** on `Product.id` (the identity constraints
//! whose backing indexes serve the `(:User {id})` / `(:Product {id})` anchor seeks every recommendation
//! query starts from), a **property-type** constraint `Product.price IS :: INTEGER`, a **`TEXT`** index
//! on `Product.name`, and a **`VECTOR`** (HNSW) index on `Product.embedding` — then waits for every
//! backing index to reach `online`, captures `SHOW INDEXES` / `SHOW CONSTRAINTS` as evidence, and
//! asserts three index-backed query paths against the known dataset: a **vector k-NN** "similar
//! products" seek (`db.index.vector.queryNodes` at a category centroid returns that category's
//! products), a **`TEXT` `CONTAINS`** search (finds a known product by a fragment of its name), and two
//! **constraint-enforcement negatives** (a duplicate `Product.id` and a non-integer `price` are both
//! rejected). Every recommendation query in the read battery must also return a well-formed result.
//!
//! # Wire protocol
//!
//! **REST-only**, plaintext loopback HTTP/1.1 over a blocking [`std::net::TcpStream`] — the server runs
//! with `allow_insecure_network = true` on `127.0.0.1`, so no TLS is involved. The exact recipe mirrors
//! `graphus-server`'s own `tests/bulk_import_endpoint.rs`:
//!
//! - `POST /auth/login` with `{"username","password"}` → a Bearer token (`rmp` #499), sent as
//!   `Authorization: Bearer <token>` on every subsequent call.
//! - `POST /db/{db}/tx/commit` with `{"statements":[{"statement":"…","parameters":{…}}]}` for Cypher
//!   and admin statements (`04 §8.2`).
//! - `POST /admin/db/{db}/bulk-import?phase=nodes` / `?phase=relationships` (`Content-Type: text/csv`,
//!   `Content-Length`-framed body) / `?end=true` (empty body) for the Mode A streaming upload.
//!
//! ## Error signalling (no `errors` array)
//!
//! Graphus's REST surface signals a failed statement with a non-2xx HTTP status and an RFC 9457
//! `application/problem+json` body — it has **no** Neo4j-style `{"results":…,"errors":[…]}` envelope.
//! So "the statement did not error" means: the response status is `200` **and** its body is a
//! well-formed `{"results":[…]}` envelope. A single-statement read is *streamed* as chunked
//! `application/json` whose bytes are identical to the buffered envelope; a runtime error mid-stream
//! aborts that body, so validating the JSON parses is what catches an in-band read failure (a
//! pre-first-byte compile error surfaces as the non-200 status directly). This loader decodes
//! `Transfer-Encoding: chunked` so the buffered and streamed paths parse uniformly.
//!
//! # Two transports
//!
//! - **REST bulk-import (Mode A)** — the default, driven by `--rest <host:port>` against a plaintext
//!   loopback dev server: the full modern flow above (bulk upload + VECTOR/TEXT/property-type schema +
//!   the index-backed query asserts).
//! - **Bolt attach (`--bolt <url>`, `rmp` #693)** — for an ALREADY-RUNNING, possibly remote instance
//!   (e.g. pi516) over Bolt-over-TCP + TLS (`bolt+ssc://` accepts a self-signed cert). Here the harness
//!   already carved out the isolated `--db`, so this loader does **not** create/drop it: it declares a
//!   **version-tolerant** minimal schema (best-effort range indexes on `User.id` / `Product.id` so the
//!   anchor seeks are index-backed; modern VECTOR/TEXT/property-type schema is skipped — an old server
//!   may not support it), streams the node + relationship rows in `UNWIND`-batched writes, and asserts
//!   the graph shape + that every recommendation family returns a well-formed result. The full modern
//!   schema is validated in REST/local mode against a current server.
//!
//! ## Exit contract
//!
//! On full success it prints exactly one machine-readable sentinel line to stdout —
//! `GRAPHUS_RECO_LOAD_OK users=<n> products=<n> friends=<n> purchased=<n>` — and exits `0`. Every
//! failure path prints `reco_load: <what failed>: <server status/body>` to stderr and exits non-zero;
//! a server-reported failure is surfaced, never turned into a panic.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_reco_gen::Generator;
use graphus_reco_gen::client::{BoltClient, BoltUrl};
use graphus_reco_gen::queries::READ_BATTERY;
use graphus_reco_gen::schema;
use serde_json::{Value as Json, json};

/// Bounds a hung connect without failing a healthy loopback (which resolves instantly).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Per-syscall read/write timeout. Generous on purpose: a large-profile `phase=…` upload streams
/// hundreds of MB and the server responds only after the whole file is durably ingested, so a short
/// timeout would spuriously fail a legitimate load — while this still bounds a truly wedged server.
const IO_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// How long to wait for both online index builds to reach `online`. The build advances by a bounded
/// chunk both on a ~2 ms idle background tick and after every engine command (each `SHOW INDEXES`
/// poll), so this is a wide safety margin, not the expected duration.
const INDEX_ONLINE_TIMEOUT: Duration = Duration::from_secs(60);
/// Delay between `SHOW INDEXES` polls while waiting for the builds to complete.
const INDEX_POLL_INTERVAL: Duration = Duration::from_millis(200);

fn main() -> ExitCode {
    let mut argv = std::env::args().skip(1).peekable();
    if argv.peek().is_some_and(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("reco_load: {e}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    // Bolt attach mode (`--bolt`) loads over Bolt-over-TCP+TLS into a harness-created isolated DB;
    // the default REST mode drives the network bulk-import (Mode A) happy path.
    let result = if args.bolt.is_some() {
        run_bolt(&args)
    } else {
        run(&args)
    };
    match result {
        Ok(()) => {
            // The single success sentinel the example's `run.sh` greps for.
            println!(
                "GRAPHUS_RECO_LOAD_OK users={} products={} friends={} purchased={}",
                args.expect_users, args.expect_products, args.expect_friends, args.expect_purchased
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("reco_load: {e}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "usage (REST bulk-import):\n\
    \x20 reco_load --rest <host:port> --default-db <name> --db <name> --data-dir <dir> \\\n\
    \x20           --user <name> --password <pw> \\\n\
    \x20           --expect-users <N> --expect-products <N> --expect-friends <N> --expect-purchased <N>\n\
usage (Bolt attach into a pre-created isolated DB, rmp #693):\n\
    \x20 reco_load --bolt <bolt+ssc://host:7687> --db <name> --data-dir <dir> \\\n\
    \x20           --user <name> --password <pw> \\\n\
    \x20           --expect-users <N> --expect-products <N> --expect-friends <N> --expect-purchased <N>\n\
Drives the reco graph into a running graphus-server (REST bulk-import Mode A, or Bolt UNWIND writes),\n\
declares the read-path indexes, and asserts the graph shape + that every recommendation query\n\
returns a well-formed result. Prints GRAPHUS_RECO_LOAD_OK on success.\n";

/// The fully-parsed command line. `--db`, `--data-dir`, `--user`, `--password` and the four
/// `--expect-*` counts are always required; exactly one transport is required — `--rest` (+
/// `--default-db`) for bulk-import Mode A, or `--bolt <url>` for the Bolt attach path.
struct Args {
    /// REST endpoint (`host:port`) for bulk-import Mode A; `None` in Bolt attach mode.
    rest: Option<String>,
    /// The server's default database (admin statements route through it); REST mode only.
    default_db: Option<String>,
    /// Bolt URL (`bolt[+s|+ssc]://host:port`) for the attach path; `None` in REST mode.
    bolt: Option<String>,
    db: String,
    data_dir: PathBuf,
    user: String,
    password: String,
    expect_users: u64,
    expect_products: u64,
    expect_friends: u64,
    expect_purchased: u64,
}

impl Args {
    /// Parses `--flag value` (and `--flag=value`) pairs. Common flags are mandatory; a missing or
    /// malformed one is a clear error (not a silent default). Exactly one of `--rest` / `--bolt`
    /// selects the transport.
    ///
    /// # Errors
    /// A human-readable message naming the missing/invalid flag or an ambiguous transport.
    fn parse(argv: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut map: HashMap<String, String> = HashMap::new();
        let mut it = argv;
        while let Some(arg) = it.next() {
            let Some(flag) = arg.strip_prefix("--") else {
                return Err(format!(
                    "unexpected argument {arg:?} (expected --flag value)"
                ));
            };
            if let Some((k, v)) = flag.split_once('=') {
                map.insert(k.to_owned(), v.to_owned());
            } else {
                let v = it
                    .next()
                    .ok_or_else(|| format!("missing value for --{flag}"))?;
                map.insert(flag.to_owned(), v);
            }
        }

        let text = |k: &str| {
            map.get(k)
                .cloned()
                .ok_or_else(|| format!("missing required --{k}"))
        };
        let count = |k: &str| -> Result<u64, String> {
            let v = map
                .get(k)
                .ok_or_else(|| format!("missing required --{k}"))?;
            v.parse::<u64>()
                .map_err(|_| format!("--{k} must be a non-negative integer, got {v:?}"))
        };

        let rest = map.get("rest").cloned();
        let bolt = map.get("bolt").cloned();
        match (&rest, &bolt) {
            (None, None) => return Err("one of --rest or --bolt is required".to_owned()),
            (Some(_), Some(_)) => {
                return Err(
                    "--rest and --bolt are mutually exclusive (pick one transport)".to_owned(),
                );
            }
            _ => {}
        }
        // `--default-db` is only meaningful (and required) for the REST bulk-import path.
        let default_db = if rest.is_some() {
            Some(text("default-db")?)
        } else {
            None
        };

        Ok(Self {
            rest,
            default_db,
            bolt,
            db: text("db")?,
            data_dir: PathBuf::from(text("data-dir")?),
            user: text("user")?,
            password: text("password")?,
            expect_users: count("expect-users")?,
            expect_products: count("expect-products")?,
            expect_friends: count("expect-friends")?,
            expect_purchased: count("expect-purchased")?,
        })
    }
}

/// Runs the whole load + assert pipeline. Returns `Ok(())` only when every step succeeded and every
/// assertion held; the `Err` string is the already-formatted `<what failed>: <server status/body>`.
fn run(args: &Args) -> Result<(), String> {
    let rest_addr = args
        .rest
        .as_deref()
        .ok_or("REST mode requires --rest <host:port>")?;
    let default_db = args
        .default_db
        .as_deref()
        .ok_or("REST mode requires --default-db <name>")?;

    // 1. Authenticate → Bearer token for every later call.
    let token = login(rest_addr, &args.user, &args.password)?;
    let rest = Rest {
        addr: rest_addr,
        token: &token,
    };

    // 2. Create the fresh, empty Mode A target database (admin statement runs against the default db).
    rest.statement(
        default_db,
        "CREATE DATABASE",
        &format!("CREATE DATABASE {}", args.db),
        None,
    )?;

    // 3. Streaming bulk upload (Mode A): node files, then relationship files, then end.
    //    Each file is read straight into a `Vec<u8>` (one read loop, no string concatenation) — fine
    //    for the example scale — and framed with its exact `Content-Length`.
    let users = read_csv(&args.data_dir, "users.csv")?;
    let products = read_csv(&args.data_dir, "products.csv")?;
    let friends = read_csv(&args.data_dir, "friends.csv")?;
    let purchased = read_csv(&args.data_dir, "purchased.csv")?;

    // Two `phase=nodes` calls share ONE Mode A session: the first begins the `Loading` session, the
    // second continues it (the server keys the session on the `Loading` database, not the call), so
    // both files land in the same on-engine id-map that the relationship phase then resolves against.
    rest.bulk_ok(
        "users.csv (phase=nodes)",
        &args.db,
        "phase=nodes",
        CSV,
        &users,
    )?;
    rest.bulk_ok(
        "products.csv (phase=nodes)",
        &args.db,
        "phase=nodes",
        CSV,
        &products,
    )?;
    rest.bulk_ok(
        "friends.csv (phase=relationships)",
        &args.db,
        "phase=relationships",
        CSV,
        &friends,
    )?;
    rest.bulk_ok(
        "purchased.csv (phase=relationships)",
        &args.db,
        "phase=relationships",
        CSV,
        &purchased,
    )?;

    // End the session and check the server's own final ingest tally against the expected shape.
    let end = rest.bulk(&args.db, "end=true", None, b"")?;
    if end.status != 200 {
        return Err(format!(
            "bulk end=true failed: HTTP {}: {}",
            end.status,
            clip_bytes(&end.body)
        ));
    }
    let end_json: Json = serde_json::from_slice(&end.body).map_err(|e| {
        format!(
            "bulk end=true returned a malformed stats body ({e}): {}",
            clip_bytes(&end.body)
        )
    })?;
    let end_nodes = json_u64(&end_json, "nodes").ok_or_else(|| {
        format!(
            "bulk end=true response missing numeric \"nodes\": {}",
            clip_bytes(&end.body)
        )
    })?;
    let end_rels = json_u64(&end_json, "relationships").ok_or_else(|| {
        format!(
            "bulk end=true response missing numeric \"relationships\": {}",
            clip_bytes(&end.body)
        )
    })?;
    let want_nodes = checked_add(
        args.expect_users,
        args.expect_products,
        "expect-users + expect-products",
    )?;
    let want_rels = checked_add(
        args.expect_friends,
        args.expect_purchased,
        "expect-friends + expect-purchased",
    )?;
    if end_nodes != want_nodes {
        return Err(format!(
            "bulk end=true node total mismatch: server ingested {end_nodes} nodes, expected \
             {want_nodes} (= {} users + {} products)",
            args.expect_users, args.expect_products
        ));
    }
    if end_rels != want_rels {
        return Err(format!(
            "bulk end=true relationship total mismatch: server ingested {end_rels} relationships, \
             expected {want_rels} (= {} friends + {} purchased)",
            args.expect_friends, args.expect_purchased
        ));
    }

    // 4. Mode A leaves the database Offline; bring it online explicitly.
    rest.statement(
        default_db,
        "START DATABASE",
        &format!("START DATABASE {}", args.db),
        None,
    )?;

    // 5. Declare the production-realistic read-path SCHEMA (`rmp` #676) — the shared DDL block the
    //    hermetic mirror also drives: identity constraints (a NODE KEY on User.id, a UNIQUE on
    //    Product.id) whose backing indexes serve the `(:User {id})` / `(:Product {id})` anchor seeks AND
    //    enforce catalogue identity, a `price IS :: INTEGER` property-type constraint, a TEXT index for
    //    name search, and a VECTOR (HNSW) index for the "similar products" ANN query.
    for stmt in graphus_reco_gen::schema::schema_ddl() {
        rest.statement(&args.db, &stmt, &stmt, None)?;
    }

    // 6. Poll SHOW INDEXES until every backing index reports `online` (each poll also advances any
    //    still-building index). Constraint-backed / TEXT / VECTOR indexes build synchronously, so this
    //    is a wide safety margin rather than the expected duration.
    wait_for_indexes(&rest, &args.db)?;

    // 7. Shape assertions.
    assert_count(
        &rest,
        &args.db,
        "MATCH (u:User) RETURN count(u)",
        "User node count",
        args.expect_users,
    )?;
    assert_count(
        &rest,
        &args.db,
        "MATCH (p:Product) RETURN count(p)",
        "Product node count",
        args.expect_products,
    )?;
    // Each undirected FRIEND is stored once but traversed from both ends by `-[r:FRIEND]-`, so the
    // count is 2× the emitted edge count (the social-network-large convention).
    let want_friend_traversals = checked_mul(args.expect_friends, 2, "expect-friends × 2")?;
    assert_count(
        &rest,
        &args.db,
        "MATCH ()-[r:FRIEND]-() RETURN count(r)",
        "FRIEND traversal count",
        want_friend_traversals,
    )?;
    assert_count(
        &rest,
        &args.db,
        "MATCH ()-[r:PURCHASED]->() RETURN count(r)",
        "PURCHASED edge count",
        args.expect_purchased,
    )?;

    // 8. Recommendation smoke: every family must return a well-formed, non-erroring result on a real
    //    sample user id. Surfaces any unsupported Cypher in the battery early.
    let sample_id = Generator::user_id(0);
    for spec in READ_BATTERY {
        let params = json!({ "id": sample_id });
        let what = format!("recommendation query family '{}'", spec.name);
        rest.statement(&args.db, &what, spec.cypher, Some(params))
            .map_err(|e| format!("{e} (family {:?} is not a well-formed result)", spec.name))?;
    }

    // 9. Schema evidence + the new index-backed query paths (`rmp` #676): dump SHOW INDEXES / SHOW
    //    CONSTRAINTS as human-readable evidence, then assert the VECTOR k-NN "similar products" seek and
    //    the TEXT `CONTAINS` search return the known dataset results.
    schema_evidence_and_query_asserts(&rest, &args.db)?;

    // 10. Constraint enforcement negatives: a duplicate `Product.id` (UNIQUE) and a non-integer `price`
    //     (property-type) must each be REJECTED by the server (a rolled-back, non-2xx write).
    assert_constraints_reject(&rest, &args.db)?;

    Ok(())
}

// ================================================================================================
// Bolt attach load (`--bolt`, rmp #693) — UNWIND-batched writes into a pre-created isolated DB
// ================================================================================================

/// Node rows per `UNWIND` write (one transaction/fsync per batch).
const NODE_BATCH: usize = 1000;
/// Relationship rows per `UNWIND` write (each row is a 2-seek MATCH + CREATE).
const EDGE_BATCH: usize = 500;
/// Per-read socket timeout for the attach loader: generous (a batch commit fsyncs on the server) but
/// still bounds a truly wedged connection.
const BOLT_IO_TIMEOUT: Duration = Duration::from_secs(300);

/// Loads the reco graph over Bolt-over-TCP+TLS into the harness-created isolated `--db`. Does NOT
/// create or drop the database (the shell harness owns its lifecycle). Declares a version-tolerant
/// minimal schema (best-effort range indexes on the anchor properties), streams the node then
/// relationship rows in `UNWIND` batches, and asserts the graph shape + that every recommendation
/// family returns a well-formed result.
///
/// # Errors
/// Any connect/login failure, a server `FAILURE` on a write, a shape mismatch, or a recommendation
/// family that does not return a well-formed result.
fn run_bolt(args: &Args) -> Result<(), String> {
    let url_str = args
        .bolt
        .as_deref()
        .ok_or("Bolt mode requires --bolt <url>")?;
    let url = BoltUrl::parse(url_str)?;
    let mut load = BoltLoad::connect(&url, &args.db, &args.user, &args.password)?;
    eprintln!(
        "reco_load: Bolt attach to {url} db={:?} (version-tolerant UNWIND load)",
        args.db
    );

    // 1. Version-tolerant read-path indexes on the anchor properties so `(:User {id})` /
    //    `(:Product {id})` seeks are index-backed (not scans) BEFORE the edge MATCH-by-id load. On an
    //    empty label the index is online immediately; a rejected/duplicate CREATE is tolerated (an
    //    older server may differ in DDL surface — the load still succeeds, only slower via a scan).
    load.best_effort_index("User", "id");
    load.best_effort_index("Product", "id");

    // 2. Stream nodes, then relationships, in UNWIND batches (parameterised — one plan per shape).
    let users = parse_users(&args.data_dir)?;
    let products = parse_products(&args.data_dir)?;
    let friends = parse_friends(&args.data_dir)?;
    let purchased = parse_purchased(&args.data_dir)?;

    for chunk in users.chunks(NODE_BATCH) {
        let rows: Vec<Value> = chunk
            .iter()
            .map(|(id, name, country)| {
                Value::Map(vec![
                    ("id".into(), Value::String(id.clone())),
                    ("name".into(), Value::String(name.clone())),
                    ("country".into(), Value::String(country.clone())),
                ])
            })
            .collect();
        load.write(
            "load User nodes",
            "UNWIND $rows AS row CREATE (:User {id: row.id, name: row.name, country: row.country})",
            vec![("rows".into(), Value::List(rows))],
        )?;
    }
    eprintln!("reco_load: loaded {} User nodes", users.len());

    for chunk in products.chunks(NODE_BATCH) {
        let rows: Vec<Value> = chunk
            .iter()
            .map(|(id, name, category, price)| {
                Value::Map(vec![
                    ("id".into(), Value::String(id.clone())),
                    ("name".into(), Value::String(name.clone())),
                    ("category".into(), Value::String(category.clone())),
                    ("price".into(), Value::Integer(*price)),
                ])
            })
            .collect();
        load.write(
            "load Product nodes",
            "UNWIND $rows AS row \
             CREATE (:Product {id: row.id, name: row.name, category: row.category, price: row.price})",
            vec![("rows".into(), Value::List(rows))],
        )?;
    }
    eprintln!("reco_load: loaded {} Product nodes", products.len());

    for chunk in friends.chunks(EDGE_BATCH) {
        let rows: Vec<Value> = chunk
            .iter()
            .map(|(a, b, since)| {
                Value::Map(vec![
                    ("a".into(), Value::String(a.clone())),
                    ("b".into(), Value::String(b.clone())),
                    ("since".into(), Value::Integer(*since)),
                ])
            })
            .collect();
        load.write(
            "load FRIEND edges",
            "UNWIND $rows AS row MATCH (a:User {id: row.a}), (b:User {id: row.b}) \
             CREATE (a)-[:FRIEND {since: row.since}]->(b)",
            vec![("rows".into(), Value::List(rows))],
        )?;
    }
    eprintln!("reco_load: loaded {} FRIEND edges", friends.len());

    for chunk in purchased.chunks(EDGE_BATCH) {
        let rows: Vec<Value> = chunk
            .iter()
            .map(|(u, p, ts, qty)| {
                Value::Map(vec![
                    ("u".into(), Value::String(u.clone())),
                    ("p".into(), Value::String(p.clone())),
                    ("ts".into(), Value::Integer(*ts)),
                    ("qty".into(), Value::Integer(*qty)),
                ])
            })
            .collect();
        load.write(
            "load PURCHASED edges",
            "UNWIND $rows AS row MATCH (u:User {id: row.u}), (p:Product {id: row.p}) \
             CREATE (u)-[:PURCHASED {ts: row.ts, qty: row.qty}]->(p)",
            vec![("rows".into(), Value::List(rows))],
        )?;
    }
    eprintln!("reco_load: loaded {} PURCHASED edges", purchased.len());

    // 3. Shape assertions (deterministic for a fixed seed + profile).
    load.assert_count(
        "MATCH (u:User) RETURN count(u)",
        "User node count",
        args.expect_users,
    )?;
    load.assert_count(
        "MATCH (p:Product) RETURN count(p)",
        "Product node count",
        args.expect_products,
    )?;
    load.assert_count(
        "MATCH ()-[r:PURCHASED]->() RETURN count(r)",
        "PURCHASED edge count",
        args.expect_purchased,
    )?;
    // FRIEND is stored once but traversed from both ends by `-[r:FRIEND]-`; tolerate either the
    // undirected double-count (2×) or a single count, so an older engine's traversal semantics do not
    // false-fail the load (both mean "every friendship is present").
    load.assert_count_either(
        "MATCH ()-[r:FRIEND]-() RETURN count(r)",
        "FRIEND traversal count",
        args.expect_friends.saturating_mul(2),
        args.expect_friends,
    )?;

    // 4. Recommendation smoke: every family must return a well-formed, non-erroring result on a real
    //    sample user id (surfaces any unsupported Cypher in the battery against this server version).
    let sample_id = Generator::user_id(0);
    for spec in READ_BATTERY {
        load.write(
            &format!("recommendation family '{}'", spec.name),
            spec.cypher,
            vec![("id".into(), Value::String(sample_id.clone()))],
        )?;
    }
    eprintln!(
        "reco_load: every recommendation family returned a well-formed result ({} families)",
        READ_BATTERY.len()
    );

    load.goodbye();
    Ok(())
}

/// A minimal authenticated Bolt session bound to one target database, for the attach load path.
struct BoltLoad {
    client: BoltClient,
    db: String,
}

impl BoltLoad {
    /// Connects + logs in over the Bolt URL.
    fn connect(url: &BoltUrl, db: &str, user: &str, password: &str) -> Result<Self, String> {
        let mut client = BoltClient::connect_bolt(url, BOLT_IO_TIMEOUT)
            .map_err(|e| format!("connecting to {url} failed: {e}"))?;
        client
            .login(user, password)
            .map_err(|e| format!("login as {user:?} on {url} failed: {e}"))?;
        Ok(Self {
            client,
            db: db.to_owned(),
        })
    }

    /// Runs one write/statement, discarding the rows; a server `FAILURE` is surfaced as an `Err`.
    fn write(
        &mut self,
        what: &str,
        cypher: &str,
        params: Vec<(String, Value)>,
    ) -> Result<(), String> {
        self.client
            .run(cypher, params, &self.db)
            .map(|_| ())
            .map_err(|e| format!("{what} failed: {e}"))
    }

    /// Best-effort index creation: a failure (already-exists, unsupported DDL surface) is noted, not
    /// fatal — the load still completes (anchor seeks fall back to a scan).
    fn best_effort_index(&mut self, label: &str, prop: &str) {
        let cypher = format!("CREATE INDEX FOR (n:{label}) ON (n.{prop})");
        if let Err(e) = self.client.run(&cypher, vec![], &self.db) {
            eprintln!(
                "reco_load: note: best-effort index on {label}.{prop} not created ({e}); \
                 anchor seeks may scan on this server"
            );
        } else {
            eprintln!("reco_load: created range index on {label}.{prop}");
        }
    }

    /// Runs a `RETURN count(...)` and returns the scalar.
    fn count(&mut self, cypher: &str) -> Result<u64, String> {
        let qr = self
            .client
            .run(cypher, vec![], &self.db)
            .map_err(|e| format!("count query {cypher:?} failed: {e}"))?;
        let got = qr
            .first_scalar()
            .ok_or_else(|| format!("count query {cypher:?} did not return a scalar integer"))?;
        u64::try_from(got)
            .map_err(|_| format!("count query {cypher:?} returned a negative count {got}"))
    }

    /// Asserts a count equals `expected`.
    fn assert_count(&mut self, cypher: &str, what: &str, expected: u64) -> Result<(), String> {
        let got = self.count(cypher)?;
        if got != expected {
            return Err(format!("{what}: expected {expected}, got {got}"));
        }
        eprintln!("reco_load: {what} = {got} (ok)");
        Ok(())
    }

    /// Asserts a count equals one of two accepted values (version-tolerant, e.g. undirected 2× vs 1×).
    fn assert_count_either(
        &mut self,
        cypher: &str,
        what: &str,
        expected_a: u64,
        expected_b: u64,
    ) -> Result<(), String> {
        let got = self.count(cypher)?;
        if got != expected_a && got != expected_b {
            return Err(format!(
                "{what}: expected {expected_a} or {expected_b}, got {got}"
            ));
        }
        eprintln!("reco_load: {what} = {got} (ok)");
        Ok(())
    }

    /// Sends `GOODBYE` (best-effort).
    fn goodbye(&mut self) {
        let _ = self.client.goodbye();
    }
}

/// Reads a CSV file and returns its non-empty data lines (the header row and any blank tail stripped),
/// each split on `,`. The reco generator never emits a comma/quote/newline inside a field, so a plain
/// split is exact.
fn read_data_rows(dir: &Path, name: &str) -> Result<Vec<Vec<String>>, String> {
    let bytes = read_csv(dir, name)?;
    let text = String::from_utf8(bytes).map_err(|e| format!("{name} is not UTF-8: {e}"))?;
    Ok(text
        .lines()
        .skip(1) // header
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split(',').map(str::to_owned).collect())
        .collect())
}

/// Parses one integer column of a CSV row, with a file/column-named error.
fn row_int(cells: &[String], col: usize, name: &str) -> Result<i64, String> {
    cells
        .get(col)
        .ok_or_else(|| format!("{name}: row has no column {col}"))?
        .trim()
        .parse::<i64>()
        .map_err(|e| format!("{name}: column {col} is not an integer: {e}"))
}

/// Parses one string column of a CSV row, with a file/column-named error.
fn row_str(cells: &[String], col: usize, name: &str) -> Result<String, String> {
    cells
        .get(col)
        .cloned()
        .ok_or_else(|| format!("{name}: row has no column {col}"))
}

/// `users.csv` → `(id, name, country)` (node CSV columns 2, 3, 4).
fn parse_users(dir: &Path) -> Result<Vec<(String, String, String)>, String> {
    read_data_rows(dir, "users.csv")?
        .into_iter()
        .map(|c| {
            Ok((
                row_str(&c, 2, "users.csv")?,
                row_str(&c, 3, "users.csv")?,
                row_str(&c, 4, "users.csv")?,
            ))
        })
        .collect()
}

/// `products.csv` → `(id, name, category, price)` (node CSV columns 2, 3, 4, 5; embedding skipped).
fn parse_products(dir: &Path) -> Result<Vec<(String, String, String, i64)>, String> {
    read_data_rows(dir, "products.csv")?
        .into_iter()
        .map(|c| {
            Ok((
                row_str(&c, 2, "products.csv")?,
                row_str(&c, 3, "products.csv")?,
                row_str(&c, 4, "products.csv")?,
                row_int(&c, 5, "products.csv")?,
            ))
        })
        .collect()
}

/// `friends.csv` → `(start_id, end_id, since)` (rel CSV columns 0, 1, 3).
fn parse_friends(dir: &Path) -> Result<Vec<(String, String, i64)>, String> {
    read_data_rows(dir, "friends.csv")?
        .into_iter()
        .map(|c| {
            Ok((
                row_str(&c, 0, "friends.csv")?,
                row_str(&c, 1, "friends.csv")?,
                row_int(&c, 3, "friends.csv")?,
            ))
        })
        .collect()
}

/// `purchased.csv` → `(user_id, product_id, ts, qty)` (rel CSV columns 0, 1, 3, 4).
fn parse_purchased(dir: &Path) -> Result<Vec<(String, String, i64, i64)>, String> {
    read_data_rows(dir, "purchased.csv")?
        .into_iter()
        .map(|c| {
            Ok((
                row_str(&c, 0, "purchased.csv")?,
                row_str(&c, 1, "purchased.csv")?,
                row_int(&c, 3, "purchased.csv")?,
                row_int(&c, 4, "purchased.csv")?,
            ))
        })
        .collect()
}

/// Captures `SHOW INDEXES` / `SHOW CONSTRAINTS` as human-readable evidence (printed between
/// `GRAPHUS_RECO_SCHEMA_BEGIN`/`_END` sentinels for the example's `run.sh` to persist) and asserts the
/// two new index-backed query paths against the known dataset:
///
/// * the **VECTOR k-NN** "similar products" seek — `db.index.vector.queryNodes` at category 0's centroid
///   returns products **all of category 0**, with descending, high scores (an index hit, not a scan);
/// * the **TEXT `CONTAINS`** search — a fragment of a known product's name resolves back to that product.
///
/// # Errors
/// Any statement failure, a malformed result shape, or an assertion that does not hold.
fn schema_evidence_and_query_asserts(rest: &Rest<'_>, db: &str) -> Result<(), String> {
    // --- Evidence: SHOW INDEXES / SHOW CONSTRAINTS (printed for run.sh to persist). ---
    let indexes = rest.statement(db, "SHOW INDEXES", "SHOW INDEXES", None)?;
    let constraints = rest.statement(db, "SHOW CONSTRAINTS", "SHOW CONSTRAINTS", None)?;
    let n_indexes = result_row_count(&indexes);
    let n_constraints = result_row_count(&constraints);
    eprintln!("GRAPHUS_RECO_SCHEMA_BEGIN");
    eprintln!("SHOW INDEXES ({n_indexes} rows):");
    for line in render_schema_rows(
        &indexes,
        &[
            "name",
            "type",
            "entityType",
            "labelsOrTypes",
            "properties",
            "state",
        ],
    ) {
        eprintln!("  {line}");
    }
    eprintln!("SHOW CONSTRAINTS ({n_constraints} rows):");
    for line in render_schema_rows(
        &constraints,
        &[
            "name",
            "type",
            "entityType",
            "labelsOrTypes",
            "properties",
            "propertyType",
        ],
    ) {
        eprintln!("  {line}");
    }
    eprintln!("GRAPHUS_RECO_SCHEMA_END");
    eprintln!("GRAPHUS_RECO_SCHEMA indexes={n_indexes} constraints={n_constraints}");

    // --- VECTOR k-NN "similar products": a seek at category 0's centroid returns category-0 products. ---
    let category = 0usize;
    let expected_category = Generator::category_name(category);
    let query_vec = Generator::category_centroid(category);
    let k = 5usize;
    let knn = rest.statement(
        db,
        "vector k-NN queryNodes",
        &format!(
            "CALL db.index.vector.queryNodes('{}', {k}, {}) YIELD node, score \
             RETURN node.category AS category, score",
            schema::PRODUCT_EMBEDDING_VECTOR,
            cypher_f32_list(&query_vec),
        ),
        None,
    )?;
    let rows = knn
        .pointer("/results/0/data")
        .and_then(Json::as_array)
        .ok_or_else(|| {
            format!(
                "vector k-NN: missing results[0].data: {}",
                clip_str(&knn.to_string())
            )
        })?;
    if rows.is_empty() {
        return Err("vector k-NN returned no products (the VECTOR index built empty?)".to_owned());
    }
    if rows.len() > k {
        return Err(format!(
            "vector k-NN returned {} rows, more than k={k}",
            rows.len()
        ));
    }
    let mut prev_score = f64::INFINITY;
    for row in rows {
        let cells = row
            .as_array()
            .ok_or_else(|| "vector k-NN: a data row is not an array".to_owned())?;
        let cat = jolt_str(&cells[0]).ok_or_else(|| {
            format!(
                "vector k-NN: category cell is not a Jolt string: {}",
                cells[0]
            )
        })?;
        if cat != expected_category {
            return Err(format!(
                "vector k-NN at category {category}'s centroid returned a '{cat}' product, expected all \
                 '{expected_category}' (the category clusters are not separated?)"
            ));
        }
        let score = jolt_float(&cells[1])
            .ok_or_else(|| format!("vector k-NN: score cell is not a Jolt float: {}", cells[1]))?;
        if score > prev_score {
            return Err(format!(
                "vector k-NN scores must be descending (nearest first), saw {score} after {prev_score}"
            ));
        }
        prev_score = score;
    }
    // The nearest neighbour of the exact centroid must be a strong cosine match.
    let top_score = jolt_float(&rows[0].as_array().expect("checked")[1]).expect("checked");
    if top_score < 0.9 {
        return Err(format!(
            "vector k-NN top score {top_score} is too low for a centroid query (index not used / clusters bad)"
        ));
    }

    // --- TEXT `CONTAINS`: a fragment of a known product's name resolves back to that product. ---
    let pid = Generator::product_id(0);
    let name_json = rest.statement(
        db,
        "product 0 name point-read",
        "MATCH (p:Product {id: $id}) RETURN p.name AS name",
        Some(json!({ "id": pid })),
    )?;
    let name = name_json
        .pointer("/results/0/data/0/0")
        .and_then(jolt_str)
        .ok_or_else(|| {
            format!(
                "product 0 name point-read returned no name: {}",
                clip_str(&name_json.to_string())
            )
        })?
        .to_owned();
    // The product name is `<noun> <adjective> [brand]`; the leading noun is a stable, comma-free
    // fragment guaranteed present. Search for it and require product 0 to be among the matches.
    let fragment = name.split(' ').next().unwrap_or(&name).to_owned();
    let contains = rest.statement(
        db,
        "TEXT CONTAINS search",
        "MATCH (p:Product) WHERE p.name CONTAINS $fragment RETURN p.id AS id",
        Some(json!({ "fragment": fragment })),
    )?;
    let match_rows = contains
        .pointer("/results/0/data")
        .and_then(Json::as_array)
        .ok_or_else(|| {
            format!(
                "TEXT CONTAINS: missing results[0].data: {}",
                clip_str(&contains.to_string())
            )
        })?;
    let found_pid = match_rows
        .iter()
        .filter_map(|row| row.as_array())
        .filter_map(|cells| cells.first())
        .any(|cell| jolt_str(cell) == Some(pid.as_str()));
    if !found_pid {
        return Err(format!(
            "TEXT CONTAINS '{fragment}' did not return product 0 (id {pid}), whose name is '{name}'"
        ));
    }

    Ok(())
}

/// Asserts the two constraint-enforcement negatives are REJECTED by the server (a rolled-back write, so
/// `rest.statement` returns an `Err`): a **duplicate `Product.id`** (violates the `UNIQUE` constraint)
/// and a **non-integer `price`** (violates the `IS :: INTEGER` property-type constraint).
///
/// # Errors
/// If either write is *accepted* (the constraint did not enforce), or the point-read of product 0's id
/// fails.
fn assert_constraints_reject(rest: &Rest<'_>, db: &str) -> Result<(), String> {
    let existing_pid = Generator::product_id(0);

    // Duplicate Product.id → UNIQUE violation.
    expect_rejected(
        rest,
        db,
        "duplicate Product.id (UNIQUE)",
        "CREATE (:Product {id: $id, name: 'dup', category: 'x', price: 100})",
        Some(json!({ "id": existing_pid })),
    )?;

    // Non-integer price → property-type violation. A fresh, unique (non-hex) id keeps the write's *only*
    // defect the float price, so the rejection is unambiguously the property-type constraint.
    expect_rejected(
        rest,
        db,
        "non-integer Product.price (IS :: INTEGER)",
        "CREATE (:Product {id: 'reco-neg-price-test', name: 'p', category: 'x', price: 9.99})",
        None,
    )?;

    Ok(())
}

/// Runs a write that MUST be rejected by a constraint: succeeds (`Ok`) only when the server *rejects* it
/// (`rest.statement` returns an `Err` — a constraint violation surfaces as a non-2xx problem+json).
///
/// # Errors
/// `<what> was ACCEPTED but must be rejected …` if the write succeeded.
fn expect_rejected(
    rest: &Rest<'_>,
    db: &str,
    what: &str,
    statement: &str,
    params: Option<Json>,
) -> Result<(), String> {
    match rest.statement(db, what, statement, params) {
        Ok(_) => Err(format!(
            "{what} was ACCEPTED but must be rejected by its constraint"
        )),
        Err(_) => Ok(()),
    }
}

/// Formats an `f32` slice as a Cypher list literal (`[1.0, 0.0, …]`). `{x:?}` keeps a decimal point so
/// each element lexes as a Cypher `Float`, never an `Integer` (the vector index's query dimension check
/// widens integers, but a decimal literal is unambiguous).
fn cypher_f32_list(v: &[f32]) -> String {
    let elems: Vec<String> = v.iter().map(|x| format!("{x:?}")).collect();
    format!("[{}]", elems.join(", "))
}

/// The number of data rows in a `{"results":[{"data":[…]}]}` envelope (`0` if absent).
fn result_row_count(json: &Json) -> usize {
    json.pointer("/results/0/data")
        .and_then(Json::as_array)
        .map_or(0, Vec::len)
}

/// Renders each row of a `SHOW INDEXES` / `SHOW CONSTRAINTS` result as a compact `col=value …` evidence
/// line, selecting `columns` by name (robust to the full column set). List cells render as `[a, b]`.
fn render_schema_rows(json: &Json, columns: &[&str]) -> Vec<String> {
    let Some(fields) = json.pointer("/results/0/fields").and_then(Json::as_array) else {
        return Vec::new();
    };
    let idx = |name: &str| fields.iter().position(|f| f.as_str() == Some(name));
    let Some(rows) = json.pointer("/results/0/data").and_then(Json::as_array) else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|row| row.as_array())
        .map(|cells| {
            let mut parts = Vec::new();
            for &col in columns {
                if let Some(i) = idx(col)
                    && let Some(cell) = cells.get(i)
                {
                    parts.push(format!("{col}={}", render_jolt_cell(cell)));
                }
            }
            parts.join(" ")
        })
        .collect()
}

/// Renders a single strict-Jolt cell for the evidence dump: a string/int payload, a `[a, b]` list, or a
/// compact JSON fallback.
fn render_jolt_cell(cell: &Json) -> String {
    if let Some(s) = jolt_str(cell) {
        return s.to_owned();
    }
    if let Some(i) = jolt_int(cell) {
        return i.to_string();
    }
    if let Some(items) = cell.as_array() {
        let inner: Vec<String> = items.iter().map(render_jolt_cell).collect();
        return format!("[{}]", inner.join(", "));
    }
    if cell.is_null() {
        return "null".to_owned();
    }
    cell.to_string()
}

/// The `Content-Type` for every CSV bulk-upload body.
const CSV: Option<&str> = Some("text/csv");

/// Reads one CSV file from `dir` fully into a byte buffer (a single read loop — never string
/// concatenation), for framing as one bulk-upload body.
///
/// # Errors
/// A message naming the file when it cannot be read.
fn read_csv(dir: &std::path::Path, name: &str) -> Result<Vec<u8>, String> {
    let path = dir.join(name);
    std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// A minimal, authenticated REST client bound to one server address + Bearer token.
struct Rest<'a> {
    addr: &'a str,
    token: &'a str,
}

impl Rest<'_> {
    /// Runs one Cypher/admin statement over `POST /db/{db}/tx/commit`, asserting a `200` with a
    /// well-formed `{"results":…}` body, and returns the parsed body. `what` names the operation for
    /// error messages; `params`, if present, becomes the statement's `parameters` object.
    ///
    /// # Errors
    /// `<what> failed: HTTP <status>: <body>` on a non-200, or `<what> returned a malformed/aborted
    /// result body` when a `200` body does not parse as JSON (an in-band streamed-read abort).
    fn statement(
        &self,
        db: &str,
        what: &str,
        statement: &str,
        params: Option<Json>,
    ) -> Result<Json, String> {
        let body = statement_body(statement, params);
        let resp = http_post(
            self.addr,
            &format!("/db/{db}/tx/commit"),
            Some(self.token),
            Some("application/json"),
            &body,
        )?;
        if resp.status != 200 {
            return Err(format!(
                "{what} failed: HTTP {}: {}",
                resp.status,
                clip_bytes(&resp.body)
            ));
        }
        let json: Json = serde_json::from_slice(&resp.body).map_err(|e| {
            format!(
                "{what} returned a 200 but a malformed/aborted result body ({e}): {}",
                clip_bytes(&resp.body)
            )
        })?;
        if json.get("results").and_then(Json::as_array).is_none() {
            return Err(format!(
                "{what} returned a 200 but no results envelope: {}",
                clip_bytes(&resp.body)
            ));
        }
        Ok(json)
    }

    /// One `POST /admin/db/{db}/bulk-import?{query}` call, returning the raw response (the caller
    /// decides how to interpret the status/body).
    ///
    /// # Errors
    /// Only on a transport failure; a non-200 HTTP status is returned as an [`HttpResponse`].
    fn bulk(
        &self,
        db: &str,
        query: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<HttpResponse, String> {
        http_post(
            self.addr,
            &format!("/admin/db/{db}/bulk-import?{query}"),
            Some(self.token),
            content_type,
            body,
        )
    }

    /// A bulk call that must return `200`, surfacing the server's status/body otherwise.
    ///
    /// # Errors
    /// `<what> failed: HTTP <status>: <body>` on any non-200 (or a transport failure).
    fn bulk_ok(
        &self,
        what: &str,
        db: &str,
        query: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<(), String> {
        let resp = self.bulk(db, query, content_type, body)?;
        if resp.status != 200 {
            return Err(format!(
                "bulk {what} failed: HTTP {}: {}",
                resp.status,
                clip_bytes(&resp.body)
            ));
        }
        Ok(())
    }
}

/// Authenticates via `POST /auth/login` and returns the Bearer token.
///
/// # Errors
/// A message with the server status/body on a failed login, or a missing `token` field.
fn login(addr: &str, user: &str, password: &str) -> Result<String, String> {
    let body = serde_json::to_vec(&json!({ "username": user, "password": password }))
        // INVARIANT: a Value built from string-keyed objects and string values always serializes.
        .expect("INVARIANT: login request Value is plain JSON");
    let resp = http_post(addr, "/auth/login", None, Some("application/json"), &body)?;
    if resp.status != 200 {
        return Err(format!(
            "login as {user:?} failed: HTTP {}: {}",
            resp.status,
            clip_bytes(&resp.body)
        ));
    }
    let json: Json = serde_json::from_slice(&resp.body).map_err(|e| {
        format!(
            "login response is not valid JSON ({e}): {}",
            clip_bytes(&resp.body)
        )
    })?;
    json.get("token")
        .and_then(Json::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            format!(
                "login response missing a string \"token\": {}",
                clip_bytes(&resp.body)
            )
        })
}

/// The `(label, property)` **durable** indexes awaited `online` after the schema DDL: the TEXT index
/// (Product.name) and the VECTOR index (Product.embedding). The identity constraints' backing indexes
/// (User.id NODE KEY, Product.id UNIQUE) drive the anchor seeks through the in-memory index set but are
/// surfaced under `SHOW CONSTRAINTS`, **not** `SHOW INDEXES` (which lists only durable index
/// declarations), so they are awaited via the constraint listing, not here.
const REQUIRED_INDEXES: &[(&str, &str)] = &[("Product", "name"), ("Product", "embedding")];

/// Polls `SHOW INDEXES` until every [`REQUIRED_INDEXES`] index reports `online` (case-insensitive), or
/// the [`INDEX_ONLINE_TIMEOUT`] elapses. Each poll is itself an engine command, which advances any
/// still-building online index.
///
/// # Errors
/// A message naming the still-pending indexes on timeout, or any statement failure.
fn wait_for_indexes(rest: &Rest<'_>, db: &str) -> Result<(), String> {
    let deadline = Instant::now() + INDEX_ONLINE_TIMEOUT;
    loop {
        let json = rest.statement(db, "SHOW INDEXES", "SHOW INDEXES", None)?;
        let mut pending = Vec::new();
        for &(label, property) in REQUIRED_INDEXES {
            if !index_is_online(&json, label, property)? {
                pending.push(format!("{label}({property})"));
            }
        }
        if pending.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "indexes did not reach `online` within {}s (pending: {}); last SHOW INDEXES: {}",
                INDEX_ONLINE_TIMEOUT.as_secs(),
                pending.join(", "),
                clip_str(&json.to_string())
            ));
        }
        std::thread::sleep(INDEX_POLL_INTERVAL);
    }
}

/// Whether the `SHOW INDEXES` result has a row covering `(label, property)` in state `online`. Columns
/// are resolved **by name** from `results[0].fields` (robust to the full unified column set — `rmp`
/// #660 made `SHOW INDEXES` a 12-column Neo4j listing, not a bare `[label, property, state]` triple).
/// `labelsOrTypes` and `properties` are strict-Jolt **list** cells (plain JSON arrays of `{"U":"…"}`);
/// a row matches when its label list contains `label` and its property list is exactly `[property]`.
/// Returns `false` (not an error) when no such row is present yet.
///
/// # Errors
/// When the response has no `results[0].fields` / `results[0].data`, or is missing the columns needed.
fn index_is_online(json: &Json, label: &str, property: &str) -> Result<bool, String> {
    let fields = json
        .pointer("/results/0/fields")
        .and_then(Json::as_array)
        .ok_or_else(|| {
            format!(
                "SHOW INDEXES: missing results[0].fields array: {}",
                clip_str(&json.to_string())
            )
        })?;
    let col = |name: &str| fields.iter().position(|f| f.as_str() == Some(name));
    let (Some(labels_c), Some(props_c), Some(state_c)) =
        (col("labelsOrTypes"), col("properties"), col("state"))
    else {
        return Err(format!(
            "SHOW INDEXES: missing labelsOrTypes/properties/state columns in fields {fields:?}"
        ));
    };
    let rows = json
        .pointer("/results/0/data")
        .and_then(Json::as_array)
        .ok_or_else(|| {
            format!(
                "SHOW INDEXES: missing results[0].data array: {}",
                clip_str(&json.to_string())
            )
        })?;
    let max_c = labels_c.max(props_c).max(state_c);
    for row in rows {
        let Some(cells) = row.as_array() else {
            continue;
        };
        if cells.len() <= max_c {
            continue;
        }
        if jolt_list_contains(&cells[labels_c], label) && jolt_list_is(&cells[props_c], property) {
            return Ok(jolt_str(&cells[state_c]).is_some_and(|s| s.eq_ignore_ascii_case("online")));
        }
    }
    Ok(false)
}

/// Whether a strict-Jolt **list** cell (a plain JSON array of `{"U":"…"}` strings) contains `s`.
fn jolt_list_contains(cell: &Json, s: &str) -> bool {
    cell.as_array()
        .is_some_and(|xs| xs.iter().any(|e| jolt_str(e) == Some(s)))
}

/// Whether a strict-Jolt **list** cell is exactly the single-element list `[s]`.
fn jolt_list_is(cell: &Json, s: &str) -> bool {
    cell.as_array()
        .is_some_and(|xs| xs.len() == 1 && jolt_str(&xs[0]) == Some(s))
}

/// Runs a `RETURN count(...)` statement and asserts the single scalar equals `expected`.
///
/// # Errors
/// The statement failure, a non-integer/negative count, or a mismatch (with both values).
fn assert_count(
    rest: &Rest<'_>,
    db: &str,
    statement: &str,
    what: &str,
    expected: u64,
) -> Result<(), String> {
    let json = rest.statement(db, what, statement, None)?;
    let cell = json.pointer("/results/0/data/0/0").ok_or_else(|| {
        format!(
            "{what}: missing results[0].data[0][0] scalar in {}",
            clip_str(&json.to_string())
        )
    })?;
    let got = jolt_int(cell)
        .ok_or_else(|| format!("{what}: cell {cell} is not a Jolt integer `{{\"Z\":\"…\"}}`"))?;
    let got = u64::try_from(got)
        .map_err(|_| format!("{what}: server returned a negative count {got}"))?;
    if got != expected {
        return Err(format!("{what}: expected {expected}, got {got}"));
    }
    Ok(())
}

/// Serialises one statement (+ optional parameters) into a `tx/commit` request body. Built through
/// `serde_json` so the Cypher text and parameters are always correctly escaped.
fn statement_body(statement: &str, params: Option<Json>) -> Vec<u8> {
    let stmt = match params {
        Some(p) => json!({ "statement": statement, "parameters": p }),
        None => json!({ "statement": statement }),
    };
    // INVARIANT: a Value built from string-keyed objects/strings always serializes.
    serde_json::to_vec(&json!({ "statements": [stmt] }))
        .expect("INVARIANT: statement request Value is plain JSON")
}

/// The string payload of a strict-Jolt string cell `{"U":"…"}`.
fn jolt_str(cell: &Json) -> Option<&str> {
    cell.get("U")?.as_str()
}

/// The i64 payload of a strict-Jolt integer cell `{"Z":"<decimal>"}` (the int53-safe string encoding).
fn jolt_int(cell: &Json) -> Option<i64> {
    cell.get("Z")?.as_str()?.parse().ok()
}

/// The f64 payload of a strict-Jolt float cell `{"R":"<decimal>"}` (the vector-score encoding).
fn jolt_float(cell: &Json) -> Option<f64> {
    cell.get("R")?.as_str()?.parse().ok()
}

/// A top-level plain-JSON `u64` field (the bulk-import stats body is plain JSON, not Jolt).
fn json_u64(json: &Json, key: &str) -> Option<u64> {
    json.get(key)?.as_u64()
}

/// `a + b`, erroring on overflow (defensive — the example's counts never approach `u64::MAX`).
fn checked_add(a: u64, b: u64, ctx: &str) -> Result<u64, String> {
    a.checked_add(b)
        .ok_or_else(|| format!("{ctx} overflows u64 ({a} + {b})"))
}

/// `a * b`, erroring on overflow.
fn checked_mul(a: u64, b: u64, ctx: &str) -> Result<u64, String> {
    a.checked_mul(b)
        .ok_or_else(|| format!("{ctx} overflows u64 ({a} × {b})"))
}

// ------------------------------------------------------------------------------------------------
// A tiny blocking HTTP/1.1 client (plaintext loopback only), Connection: close, read-to-EOF.
// ------------------------------------------------------------------------------------------------

/// A parsed HTTP response: the status code and the (de-chunked) body bytes.
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

/// Performs one `POST` and returns the parsed response. The body is framed with `Content-Length`;
/// the whole raw response is read to EOF (the server sends `Connection: close`) and, if the response
/// used `Transfer-Encoding: chunked` (single-statement reads stream this way), de-chunked so the
/// caller always sees the real body bytes.
///
/// # Errors
/// A transport-level failure (connect/resolve/write/read) or a malformed HTTP response. A non-2xx
/// status is *not* an error here — it is returned in [`HttpResponse::status`].
fn http_post(
    addr: &str,
    path: &str,
    bearer: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<HttpResponse, String> {
    let mut stream = connect(addr)?;

    let mut head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\n"
    );
    if let Some(token) = bearer {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));

    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(|e| format!("writing request to {addr}{path} failed: {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("reading response from {addr}{path} failed: {e}"))?;

    parse_response(&raw).map_err(|e| format!("malformed response from {addr}{path}: {e}"))
}

/// Opens a timeout-bounded TCP connection to `host:port` (first resolved address).
fn connect(addr: &str) -> Result<TcpStream, String> {
    let sock = addr
        .to_socket_addrs()
        .map_err(|e| format!("resolving {addr} failed: {e}"))?
        .next()
        .ok_or_else(|| format!("no socket address resolved for {addr}"))?;
    let stream = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT)
        .map_err(|e| format!("connecting to {addr} failed: {e}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|e| format!("setting socket timeouts for {addr} failed: {e}"))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Splits a raw HTTP/1.1 response into `(status, body)`, de-chunking a `Transfer-Encoding: chunked`
/// body. The body is everything after the header terminator, to EOF (`Connection: close`).
///
/// # Errors
/// When the header terminator or status code cannot be found, or a chunked body is malformed.
fn parse_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let sep = find_sub(raw, b"\r\n\r\n").ok_or("no header terminator (\\r\\n\\r\\n)")?;
    let head = &raw[..sep];
    let body = &raw[sep + 4..];

    let line_end = find_sub(head, b"\r\n").unwrap_or(head.len());
    let status_line =
        std::str::from_utf8(&head[..line_end]).map_err(|_| "status line is not UTF-8")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("no status code in status line {status_line:?}"))?;

    let mut chunked = false;
    for line in std::str::from_utf8(&head[line_end..])
        .unwrap_or("")
        .split("\r\n")
    {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("transfer-encoding")
            && v.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }

    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    Ok(HttpResponse { status, body })
}

/// Decodes a complete, in-memory HTTP/1.1 chunked body into its payload bytes, ignoring any trailer.
///
/// # Errors
/// When a chunk-size line is missing/invalid or a chunk is truncated.
fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    loop {
        let nl = find_sub(data, b"\r\n").ok_or("chunked body: missing chunk-size CRLF")?;
        let size_line = std::str::from_utf8(&data[..nl])
            .map_err(|_| "chunked body: chunk-size line is not UTF-8")?;
        // A chunk-size line may carry `;ext` extensions after the hex size.
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16)
            .map_err(|_| format!("chunked body: invalid chunk size {hex:?}"))?;
        data = &data[nl + 2..];
        if size == 0 {
            break; // last chunk; trailers (if any) are ignored
        }
        if data.len() < size {
            return Err("chunked body: truncated chunk data".to_owned());
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        // Skip the CRLF that terminates the chunk data.
        if data.starts_with(b"\r\n") {
            data = &data[2..];
        }
    }
    Ok(out)
}

/// Index of the first occurrence of `needle` in `hay`.
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A length-bounded, lossy rendering of a response body for an error message (responses are small,
/// but the guard keeps a pathological body from flooding stderr).
fn clip_bytes(body: &[u8]) -> String {
    clip_str(&String::from_utf8_lossy(body))
}

/// A length-bounded copy of `s` (never splitting a UTF-8 char), for error messages.
fn clip_str(s: &str) -> String {
    const MAX: usize = 2000;
    if s.len() <= MAX {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(MAX).collect();
    out.push_str("... (truncated)");
    out
}
