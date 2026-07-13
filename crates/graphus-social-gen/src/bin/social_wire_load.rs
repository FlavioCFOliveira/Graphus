//! `social_wire_load` — the **over-the-wire loader + schema DDL + correctness gate** for
//! `examples/social-network-large` (`rmp` #691).
//!
//! It drives the deterministic social graph (the CSV file set produced by `social_gen --format csv`)
//! into an **already-running / self-booted** `graphus-server` over the wire, closing the historical
//! `#681` disconnect where the offline bulk store was not server-openable so the wire demo was only a
//! 4-node toy. Two transports:
//!
//! - **REST bulk-import (Mode A)** — `--rest <host:port>` against a plaintext-loopback dev server
//!   (`allow_insecure_network = true`): `CREATE DATABASE` → stream the node files then the
//!   relationship files → `end=true` (asserting the server's own node/relationship tally) →
//!   `START DATABASE` → declare a version-tolerant read-path schema → shape + battery smoke asserts.
//!   The exact recipe mirrors `graphus-server`'s `tests/bulk_import_endpoint.rs` and the sibling
//!   `reco_load`/`bulk-etl` examples.
//! - **Bolt attach (`--bolt <url>`)** — Bolt-over-TCP + TLS against an ALREADY-RUNNING, possibly
//!   remote/older instance (`bolt+ssc://` accepts a self-signed cert). The harness already
//!   carved out the isolated `--db`, so this loader does NOT create/drop it: it declares best-effort
//!   anchor indexes, streams the node then relationship rows in `UNWIND`-batched writes, and asserts
//!   the graph shape + that every battery family returns a well-formed result. Version-tolerant: a
//!   rejected modern DDL (an older server) is noted, never fatal.
//!
//! # The graph CSV shape (`social_gen --format csv`)
//!
//! `neo4j-admin import`-flavoured: node files are `:ID,:LABEL,id:string,name:string,registered:long`
//! (the 24-hex id appears **twice** — the reserved `:ID` join key AND a stored `id` property the
//! traversals anchor on); relationship files are `:START_ID,:END_ID,:TYPE,<prop>:long`. The generator
//! never emits a comma / quote / newline inside a field, so a plain `split(',')` is exact for the Bolt
//! path's row parse.
//!
//! # Exit contract
//!
//! On full success it prints one machine-readable sentinel — `GRAPHUS_SOCIAL_LOAD_OK users=<n>
//! articles=<n> friends=<n> likes=<n>` — and exits `0`. Every failure prints `social_wire_load: <what
//! failed>: <server status/body>` to stderr and exits non-zero; a server `FAILURE` is surfaced, never
//! a panic.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_reco_gen::client::{BoltClient, BoltUrl};
use graphus_social_gen::{DegreeDist, EPOCH_S, GenConfig, Generator, REG_SPAN_S, battery};
use serde_json::{Value as Json, json};

/// Bounds a hung connect without failing a healthy loopback.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Per-syscall read/write timeout for the REST path. Generous: a bulk `phase=…` upload streams the
/// whole file and the server responds only after it is durably ingested.
const IO_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Per-read socket timeout for the Bolt attach loader (a batch commit fsyncs on the server).
const BOLT_IO_TIMEOUT: Duration = Duration::from_secs(300);
/// Node rows per `UNWIND` write on the Bolt path (one transaction/fsync per batch).
const NODE_BATCH: usize = 1000;
/// Relationship rows per `UNWIND` write (each row is a 2-seek MATCH + CREATE).
const EDGE_BATCH: usize = 500;
/// How long to wait for the online index builds to reach `online` (REST path).
const INDEX_ONLINE_TIMEOUT: Duration = Duration::from_secs(60);
/// Delay between `SHOW INDEXES` polls while waiting for the builds.
const INDEX_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// The `Content-Type` for every CSV bulk-upload body.
const CSV: Option<&str> = Some("text/csv");

fn main() -> ExitCode {
    let mut argv = std::env::args().skip(1).peekable();
    if argv.peek().is_some_and(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("social_wire_load: {e}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    let cfg = match args.gen_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("social_wire_load: {e}");
            return ExitCode::FAILURE;
        }
    };
    let summary = Generator::new(cfg.clone()).summary();

    let result = if args.bolt.is_some() {
        run_bolt(&args, &cfg, &summary)
    } else {
        run_rest(&args, &cfg, &summary)
    };
    match result {
        Ok(()) => {
            println!(
                "GRAPHUS_SOCIAL_LOAD_OK users={} articles={} friends={} likes={}",
                summary.users, summary.articles, summary.friend_edges, summary.like_edges
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("social_wire_load: {e}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "usage (REST bulk-import, Mode A):\n\
    \x20 social_wire_load --rest <host:port> --default-db <name> --db <name> --data-dir <dir> \\\n\
    \x20                  --user <name> --password <pw> --profile <fast|large|huge> [gen overrides]\n\
usage (Bolt attach into a pre-created isolated DB):\n\
    \x20 social_wire_load --bolt <bolt+ssc://host:7687> --db <name> --data-dir <dir> \\\n\
    \x20                  --user <name> --password <pw> --profile <fast|large|huge> [gen overrides]\n\
gen overrides (must MATCH the social_gen invocation that wrote --data-dir): --users --articles \\\n\
    \x20 --friend-min --friend-max --avg-likes --seed --degree-dist uniform|zipf --zipf-exponent N\n\
Loads the social graph into a running graphus-server (REST bulk-import Mode A, or Bolt UNWIND writes),\n\
declares a version-tolerant read-path schema, asserts the round-tripped shape, and smoke-tests every\n\
read-battery family. Prints GRAPHUS_SOCIAL_LOAD_OK on success.\n";

/// The parsed command line. Exactly one transport (`--rest` + `--default-db`, or `--bolt`) is
/// required; the generator flags reconstruct the identical deterministic config for expected counts
/// and the search-term ground truth.
struct Args {
    rest: Option<String>,
    default_db: Option<String>,
    bolt: Option<String>,
    db: String,
    data_dir: PathBuf,
    user: String,
    password: String,
    profile: String,
    users: Option<u64>,
    articles: Option<u64>,
    friend_min: Option<u64>,
    friend_max: Option<u64>,
    avg_likes: Option<u64>,
    seed: Option<u64>,
    degree_dist: Option<DegreeDist>,
}

impl Args {
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
        let opt_u64 = |k: &str| -> Result<Option<u64>, String> {
            map.get(k)
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| format!("--{k} must be a non-negative integer, got {v:?}"))
                })
                .transpose()
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
        let default_db = if rest.is_some() {
            Some(text("default-db")?)
        } else {
            None
        };
        let degree_dist = match map.get("degree-dist").map(String::as_str) {
            None | Some("uniform") => None,
            Some("zipf" | "powerlaw" | "power-law") => {
                let exponent = opt_u64("zipf-exponent")?.unwrap_or(2) as u32;
                Some(DegreeDist::PowerLaw { exponent })
            }
            Some(other) => return Err(format!("unknown --degree-dist {other:?} (uniform|zipf)")),
        };

        Ok(Self {
            rest,
            default_db,
            bolt,
            db: text("db")?,
            data_dir: PathBuf::from(text("data-dir")?),
            user: text("user")?,
            password: text("password")?,
            profile: map
                .get("profile")
                .cloned()
                .unwrap_or_else(|| "fast".to_owned()),
            users: opt_u64("users")?,
            articles: opt_u64("articles")?,
            friend_min: opt_u64("friend-min")?,
            friend_max: opt_u64("friend-max")?,
            avg_likes: opt_u64("avg-likes")?,
            seed: opt_u64("seed")?,
            degree_dist,
        })
    }

    /// Reconstructs the deterministic generator config from the CLI (the same resolution `social_gen`
    /// used), so the expected counts + search-term ground truth match the loaded CSV byte-for-byte.
    fn gen_config(&self) -> Result<GenConfig, String> {
        GenConfig::resolve(
            &self.profile,
            self.users,
            self.articles,
            self.friend_min,
            self.friend_max,
            self.avg_likes,
            self.seed,
            self.degree_dist,
        )
    }
}

// ================================================================================================
// REST bulk-import (Mode A)
// ================================================================================================

/// Runs the REST bulk-import Mode A load + schema + asserts. Returns `Ok(())` only when every step
/// succeeded and every assertion held.
fn run_rest(
    args: &Args,
    cfg: &GenConfig,
    summary: &graphus_social_gen::Summary,
) -> Result<(), String> {
    let rest_addr = args
        .rest
        .as_deref()
        .ok_or("REST mode requires --rest <host:port>")?;
    let default_db = args
        .default_db
        .as_deref()
        .ok_or("REST mode requires --default-db <name>")?;

    let token = login(rest_addr, &args.user, &args.password)?;
    let rest = Rest {
        addr: rest_addr,
        token: &token,
    };

    // 1. Create the fresh, empty Mode A target database (admin statement via the default db).
    rest.statement(
        default_db,
        "CREATE DATABASE",
        &format!("CREATE DATABASE {}", args.db),
        None,
    )?;

    // 2. Streaming bulk upload: node files, then relationship files, then end. Two `phase=nodes` calls
    //    share ONE Mode A session (keyed on the Loading database), so both node files land in the same
    //    on-engine id-map the relationship phase resolves against.
    let users = read_csv(&args.data_dir, "users.csv")?;
    let articles = read_csv(&args.data_dir, "articles.csv")?;
    let friends = read_csv(&args.data_dir, "friends.csv")?;
    let likes = read_csv(&args.data_dir, "likes.csv")?;
    rest.bulk_ok(
        "users.csv (phase=nodes)",
        &args.db,
        "phase=nodes",
        CSV,
        &users,
    )?;
    rest.bulk_ok(
        "articles.csv (phase=nodes)",
        &args.db,
        "phase=nodes",
        CSV,
        &articles,
    )?;
    rest.bulk_ok(
        "friends.csv (phase=relationships)",
        &args.db,
        "phase=relationships",
        CSV,
        &friends,
    )?;
    rest.bulk_ok(
        "likes.csv (phase=relationships)",
        &args.db,
        "phase=relationships",
        CSV,
        &likes,
    )?;

    // End the session and check the server's own final ingest tally against the deterministic shape.
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
            "bulk end=true missing numeric \"nodes\": {}",
            clip_bytes(&end.body)
        )
    })?;
    let end_rels = json_u64(&end_json, "relationships").ok_or_else(|| {
        format!(
            "bulk end=true missing numeric \"relationships\": {}",
            clip_bytes(&end.body)
        )
    })?;
    let want_nodes = summary.users + summary.articles;
    let want_rels = summary.friend_edges + summary.like_edges;
    if end_nodes != want_nodes {
        return Err(format!(
            "bulk end=true node total mismatch: server ingested {end_nodes} nodes, expected {want_nodes} \
             (= {} users + {} articles)",
            summary.users, summary.articles
        ));
    }
    if end_rels != want_rels {
        return Err(format!(
            "bulk end=true relationship total mismatch: server ingested {end_rels} relationships, expected \
             {want_rels} (= {} FRIEND + {} LIKE)",
            summary.friend_edges, summary.like_edges
        ));
    }
    eprintln!(
        "social_wire_load: bulk end=true ingested {end_nodes} nodes + {end_rels} relationships (ok)"
    );

    // 3. Mode A leaves the database Offline; bring it online.
    rest.statement(
        default_db,
        "START DATABASE",
        &format!("START DATABASE {}", args.db),
        None,
    )?;

    // 4. Declare the version-tolerant read-path schema (best-effort — an older server may reject the
    //    modern DDL; the anchor indexes matter, the rest is optimisation / extra query surface).
    let created_fulltext = declare_schema_rest(&rest, &args.db)?;

    // 5. Shape assertions (deterministic for a fixed seed + profile).
    assert_count_rest(
        &rest,
        &args.db,
        "MATCH (u:USER) RETURN count(u)",
        "USER node count",
        summary.users,
    )?;
    assert_count_rest(
        &rest,
        &args.db,
        "MATCH (a:ARTICLE) RETURN count(a)",
        "ARTICLE node count",
        summary.articles,
    )?;
    // Each undirected FRIEND is stored once but traversed from both ends by `-[r:FRIEND]-` (2×).
    assert_count_rest(
        &rest,
        &args.db,
        "MATCH ()-[r:FRIEND]-() RETURN count(r)",
        "FRIEND traversal count",
        summary.friend_edges * 2,
    )?;
    assert_count_rest(
        &rest,
        &args.db,
        "MATCH ()-[r:LIKE]->() RETURN count(r)",
        "LIKE edge count",
        summary.like_edges,
    )?;

    // 6. Battery smoke: every family must return a well-formed, non-erroring result. The FULLTEXT
    //    family is asserted only when its index was actually created (version-tolerant).
    smoke_battery_rest(&rest, &args.db, cfg, created_fulltext)?;

    Ok(())
}

/// Declares the read-path schema over REST, best-effort. Returns whether the FULLTEXT index was
/// created (so the caller knows whether to smoke-test that family). Every DDL statement failure is
/// noted, not fatal — an older server that rejects modern DDL still serves the traversals (via a
/// scan).
///
/// The wait for the builds to go `ONLINE`, in contrast, IS fatal when it times out (`rmp` task #733):
/// the battery that follows claims to measure INDEX-backed search, so a run that queried a still-
/// building index would report scan latencies (and, before #733 was fixed, a silently empty FULLTEXT
/// result) as if they were index-backed evidence.
fn declare_schema_rest(rest: &Rest<'_>, db: &str) -> Result<bool, String> {
    // Anchor indexes (UNNAMED — an older server rejects NAMED node indexes): the id seeks the whole
    // battery starts from. These SHOULD succeed even on an older server.
    for (label, prop) in [("USER", "id"), ("ARTICLE", "id")] {
        best_effort_rest(
            rest,
            db,
            &format!("CREATE INDEX FOR (n:{label}) ON (n.{prop})"),
            &format!("anchor index {label}.{prop}"),
        );
    }
    // TEXT index on ARTICLE.name (the CONTAINS search is served by a scan without it — optimisation).
    best_effort_rest(
        rest,
        db,
        "CREATE TEXT INDEX article_name_text FOR (a:ARTICLE) ON (a.name)",
        "TEXT index ARTICLE.name",
    );
    // FULLTEXT headline index — required by the `fulltext` battery family.
    let ft = best_effort_rest(
        rest,
        db,
        &format!(
            "CREATE FULLTEXT INDEX {} FOR (a:ARTICLE) ON EACH [a.name]",
            battery::FULLTEXT_INDEX
        ),
        "FULLTEXT index ARTICLE.name",
    );
    // Existence constraint on ARTICLE.name (extra realistic schema surface).
    best_effort_rest(
        rest,
        db,
        "CREATE CONSTRAINT article_name_exists FOR (a:ARTICLE) REQUIRE a.name IS NOT NULL",
        "existence constraint ARTICLE.name",
    );
    // Wait for the durable index builds to go ONLINE (a no-op against a server that does not report
    // an index `state`; fatal if they are still POPULATING when the timeout elapses).
    wait_for_indexes(rest, db)?;
    Ok(ft)
}

/// Runs one best-effort DDL statement, noting (not failing) on rejection. Returns `true` if it was
/// accepted.
fn best_effort_rest(rest: &Rest<'_>, db: &str, statement: &str, what: &str) -> bool {
    match rest.statement(db, what, statement, None) {
        Ok(_) => {
            eprintln!("social_wire_load: created {what}");
            true
        }
        Err(e) => {
            eprintln!(
                "social_wire_load: note: {what} not created ({e}); continuing (version-tolerant)"
            );
            false
        }
    }
}

/// Smoke-tests every battery family over REST on a real sample. The traversal + scan families must
/// return a well-formed result; the search families additionally assert the ground-truth hit count.
fn smoke_battery_rest(
    rest: &Rest<'_>,
    db: &str,
    cfg: &GenConfig,
    fulltext: bool,
) -> Result<(), String> {
    let u0 = Generator::user_id(0);
    let u1 = Generator::user_id(1);
    let (term, expected_hits) = Generator::dominant_headline_term_for(cfg.seed, cfg.articles);
    let since = EPOCH_S + REG_SPAN_S / 2;

    for fam in battery::ALL {
        if fam.name == "fulltext" && !fulltext {
            eprintln!(
                "social_wire_load: skipping fulltext smoke (FULLTEXT index unavailable on this server)"
            );
            continue;
        }
        let params = rest_params(fam.params, &u0, &u1, &term, since as i64);
        let json = rest
            .statement(
                db,
                &format!("battery family '{}'", fam.name),
                fam.cypher,
                params,
            )
            .map_err(|e| format!("{e} (family {:?} is not a well-formed result)", fam.name))?;
        // Ground-truth hit-count assertions for the search families (evidence the engine matched the
        // deterministic generator, not just "did not error").
        if fam.name == "text_contains" {
            let got = jolt_scalar_u64(&json).ok_or_else(|| {
                format!(
                    "text_contains returned no scalar: {}",
                    clip_str(&json.to_string())
                )
            })?;
            if got != expected_hits {
                return Err(format!(
                    "text_contains '{term}' hit count mismatch: server {got}, ground truth {expected_hits}"
                ));
            }
        }
        if fam.name == "fulltext" {
            let got = jolt_scalar_u64(&json).ok_or_else(|| {
                format!(
                    "fulltext returned no scalar: {}",
                    clip_str(&json.to_string())
                )
            })?;
            if got != expected_hits {
                return Err(format!(
                    "fulltext '{term}' hit count mismatch: server {got}, ground truth {expected_hits}"
                ));
            }
        }
    }
    eprintln!(
        "social_wire_load: every battery family returned a well-formed result; text search '{term}' = {expected_hits} articles (ground-truth match)"
    );
    Ok(())
}

/// Builds the REST (JSON) parameters for a battery family. `term` is lower-cased for the FULLTEXT
/// analyzer token (matching the in-process loader).
fn rest_params(kind: battery::Params, u0: &str, u1: &str, term: &str, since: i64) -> Option<Json> {
    match kind {
        battery::Params::None => None,
        battery::Params::User => Some(json!({ "u0": u0 })),
        battery::Params::UserPair => Some(json!({ "u0": u0, "u1": u1 })),
        battery::Params::Term => Some(json!({ "term": term })),
        battery::Params::FulltextTerm => Some(json!({ "term": term.to_lowercase() })),
        battery::Params::Recent => Some(json!({ "since": since })),
    }
}

// ================================================================================================
// Bolt attach load (`--bolt`) — UNWIND-batched writes into a pre-created isolated DB
// ================================================================================================

/// Loads the social graph over Bolt-over-TCP+TLS into the harness-created isolated `--db`. Does NOT
/// create or drop the database. Declares best-effort anchor indexes, streams the node then
/// relationship rows in `UNWIND` batches (parsed from the CSV), and asserts the shape + battery.
fn run_bolt(
    args: &Args,
    cfg: &GenConfig,
    summary: &graphus_social_gen::Summary,
) -> Result<(), String> {
    let url_str = args
        .bolt
        .as_deref()
        .ok_or("Bolt mode requires --bolt <url>")?;
    let url = BoltUrl::parse(url_str)?;
    let mut load = BoltLoad::connect(&url, &args.db, &args.user, &args.password)?;
    eprintln!(
        "social_wire_load: Bolt attach to {url} db={:?} (version-tolerant UNWIND load)",
        args.db
    );

    // 1. Best-effort anchor indexes so `(:USER {id})` / `(:ARTICLE {id})` seeks are index-backed
    //    BEFORE the edge MATCH-by-id load. On an empty label the index is online immediately.
    load.best_effort_index("USER", "id");
    load.best_effort_index("ARTICLE", "id");
    let fulltext = load.best_effort_fulltext();

    // 2. Stream nodes, then relationships, in UNWIND batches (parsed from the deterministic CSV; the
    //    generator never emits a comma/quote/newline in a field, so split(',') is exact).
    let users = parse_nodes(&args.data_dir, "users.csv")?;
    let articles = parse_nodes(&args.data_dir, "articles.csv")?;
    let friends = parse_edges(&args.data_dir, "friends.csv")?;
    let likes = parse_edges(&args.data_dir, "likes.csv")?;

    for chunk in users.chunks(NODE_BATCH) {
        let rows = node_rows(chunk);
        load.write(
            "load USER nodes",
            "UNWIND $rows AS row CREATE (:USER {id: row.id, name: row.name, registered: row.registered})",
            vec![("rows".into(), Value::List(rows))],
        )?;
    }
    eprintln!("social_wire_load: loaded {} USER nodes", users.len());
    for chunk in articles.chunks(NODE_BATCH) {
        let rows = node_rows(chunk);
        load.write(
            "load ARTICLE nodes",
            "UNWIND $rows AS row CREATE (:ARTICLE {id: row.id, name: row.name, registered: row.registered})",
            vec![("rows".into(), Value::List(rows))],
        )?;
    }
    eprintln!("social_wire_load: loaded {} ARTICLE nodes", articles.len());
    for chunk in friends.chunks(EDGE_BATCH) {
        let rows = edge_rows(chunk, "since");
        load.write(
            "load FRIEND edges",
            "UNWIND $rows AS row MATCH (a:USER {id: row.a}), (b:USER {id: row.b}) \
             CREATE (a)-[:FRIEND {since: row.prop}]->(b)",
            vec![("rows".into(), Value::List(rows))],
        )?;
    }
    eprintln!("social_wire_load: loaded {} FRIEND edges", friends.len());
    for chunk in likes.chunks(EDGE_BATCH) {
        let rows = edge_rows(chunk, "date");
        load.write(
            "load LIKE edges",
            "UNWIND $rows AS row MATCH (u:USER {id: row.a}), (a:ARTICLE {id: row.b}) \
             CREATE (u)-[:LIKE {date: row.prop}]->(a)",
            vec![("rows".into(), Value::List(rows))],
        )?;
    }
    eprintln!("social_wire_load: loaded {} LIKE edges", likes.len());

    // 3. Shape assertions (version-tolerant on the undirected FRIEND double-count).
    load.assert_count(
        "MATCH (u:USER) RETURN count(u)",
        "USER node count",
        summary.users,
    )?;
    load.assert_count(
        "MATCH (a:ARTICLE) RETURN count(a)",
        "ARTICLE node count",
        summary.articles,
    )?;
    load.assert_count(
        "MATCH ()-[r:LIKE]->() RETURN count(r)",
        "LIKE edge count",
        summary.like_edges,
    )?;
    load.assert_count_either(
        "MATCH ()-[r:FRIEND]-() RETURN count(r)",
        "FRIEND traversal count",
        summary.friend_edges.saturating_mul(2),
        summary.friend_edges,
    )?;

    // 4. Battery smoke: every family must return a well-formed result (fulltext only if created).
    let u0 = Generator::user_id(0);
    let u1 = Generator::user_id(1);
    let (term, _hits) = Generator::dominant_headline_term_for(cfg.seed, cfg.articles);
    let since = (EPOCH_S + REG_SPAN_S / 2) as i64;
    for fam in battery::ALL {
        if fam.name == "fulltext" && !fulltext {
            continue;
        }
        let params = bolt_params(fam.params, &u0, &u1, &term, since);
        load.write(
            &format!("battery family '{}'", fam.name),
            fam.cypher,
            params,
        )?;
    }
    eprintln!("social_wire_load: every battery family returned a well-formed result over Bolt");

    load.goodbye();
    Ok(())
}

/// Builds the Bolt (`Value`) parameters for a battery family.
fn bolt_params(
    kind: battery::Params,
    u0: &str,
    u1: &str,
    term: &str,
    since: i64,
) -> Vec<(String, Value)> {
    match kind {
        battery::Params::None => vec![],
        battery::Params::User => vec![("u0".into(), Value::String(u0.into()))],
        battery::Params::UserPair => {
            vec![
                ("u0".into(), Value::String(u0.into())),
                ("u1".into(), Value::String(u1.into())),
            ]
        }
        battery::Params::Term => vec![("term".into(), Value::String(term.into()))],
        battery::Params::FulltextTerm => vec![("term".into(), Value::String(term.to_lowercase()))],
        battery::Params::Recent => vec![("since".into(), Value::Integer(since))],
    }
}

/// A parsed node row: `(id, name, registered)`.
type NodeRow = (String, String, i64);
/// A parsed edge row: `(start_id, end_id, prop_value)`.
type EdgeRow = (String, String, i64);

/// Builds `UNWIND` `Value::Map` rows for a node chunk (`{id, name, registered}`).
fn node_rows(chunk: &[NodeRow]) -> Vec<Value> {
    chunk
        .iter()
        .map(|(id, name, reg)| {
            Value::Map(vec![
                ("id".into(), Value::String(id.clone())),
                ("name".into(), Value::String(name.clone())),
                ("registered".into(), Value::Integer(*reg)),
            ])
        })
        .collect()
}

/// Builds `UNWIND` `Value::Map` rows for an edge chunk (`{a, b, prop}`).
fn edge_rows(chunk: &[EdgeRow], _prop_name: &str) -> Vec<Value> {
    chunk
        .iter()
        .map(|(a, b, prop)| {
            Value::Map(vec![
                ("a".into(), Value::String(a.clone())),
                ("b".into(), Value::String(b.clone())),
                ("prop".into(), Value::Integer(*prop)),
            ])
        })
        .collect()
}

/// A minimal authenticated Bolt session bound to one target database.
struct BoltLoad {
    client: BoltClient,
    db: String,
}

impl BoltLoad {
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

    fn best_effort_index(&mut self, label: &str, prop: &str) {
        let cypher = format!("CREATE INDEX FOR (n:{label}) ON (n.{prop})");
        match self.client.run(&cypher, vec![], &self.db) {
            Ok(_) => eprintln!("social_wire_load: created anchor index {label}.{prop}"),
            Err(e) => eprintln!(
                "social_wire_load: note: anchor index {label}.{prop} not created ({e}); seeks may scan"
            ),
        }
    }

    /// Best-effort FULLTEXT headline index (an older server rejects it). Returns whether it succeeded.
    fn best_effort_fulltext(&mut self) -> bool {
        let cypher = format!(
            "CREATE FULLTEXT INDEX {} FOR (a:ARTICLE) ON EACH [a.name]",
            battery::FULLTEXT_INDEX
        );
        match self.client.run(&cypher, vec![], &self.db) {
            Ok(_) => {
                eprintln!("social_wire_load: created FULLTEXT headline index");
                true
            }
            Err(e) => {
                eprintln!(
                    "social_wire_load: note: FULLTEXT index not created ({e}); fulltext family skipped"
                );
                false
            }
        }
    }

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

    fn assert_count(&mut self, cypher: &str, what: &str, expected: u64) -> Result<(), String> {
        let got = self.count(cypher)?;
        if got != expected {
            return Err(format!("{what}: expected {expected}, got {got}"));
        }
        eprintln!("social_wire_load: {what} = {got} (ok)");
        Ok(())
    }

    fn assert_count_either(
        &mut self,
        cypher: &str,
        what: &str,
        a: u64,
        b: u64,
    ) -> Result<(), String> {
        let got = self.count(cypher)?;
        if got != a && got != b {
            return Err(format!("{what}: expected {a} or {b}, got {got}"));
        }
        eprintln!("social_wire_load: {what} = {got} (ok)");
        Ok(())
    }

    fn goodbye(&mut self) {
        let _ = self.client.goodbye();
    }
}

// ------------------------------------------------------------------------------------------------
// CSV parsing (Bolt path) — plain split(','); the generator emits no comma/quote/newline in a field.
// ------------------------------------------------------------------------------------------------

/// Reads the non-empty data rows of a CSV (header + blank tail stripped), each split on `,`.
fn read_data_rows(dir: &Path, name: &str) -> Result<Vec<Vec<String>>, String> {
    let bytes = read_csv(dir, name)?;
    let text = String::from_utf8(bytes).map_err(|e| format!("{name} is not UTF-8: {e}"))?;
    Ok(text
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split(',').map(str::to_owned).collect())
        .collect())
}

/// `users.csv` / `articles.csv` → `(id, name, registered)` (node columns 2 [stored id], 3, 4).
fn parse_nodes(dir: &Path, name: &str) -> Result<Vec<NodeRow>, String> {
    read_data_rows(dir, name)?
        .into_iter()
        .map(|c| {
            Ok((
                row_str(&c, 2, name)?,
                row_str(&c, 3, name)?,
                row_int(&c, 4, name)?,
            ))
        })
        .collect()
}

/// `friends.csv` / `likes.csv` → `(start_id, end_id, prop)` (rel columns 0, 1, 3).
fn parse_edges(dir: &Path, name: &str) -> Result<Vec<EdgeRow>, String> {
    read_data_rows(dir, name)?
        .into_iter()
        .map(|c| {
            Ok((
                row_str(&c, 0, name)?,
                row_str(&c, 1, name)?,
                row_int(&c, 3, name)?,
            ))
        })
        .collect()
}

fn row_str(cells: &[String], col: usize, name: &str) -> Result<String, String> {
    cells
        .get(col)
        .cloned()
        .ok_or_else(|| format!("{name}: row has no column {col}"))
}

fn row_int(cells: &[String], col: usize, name: &str) -> Result<i64, String> {
    cells
        .get(col)
        .ok_or_else(|| format!("{name}: row has no column {col}"))?
        .trim()
        .parse::<i64>()
        .map_err(|e| format!("{name}: column {col} is not an integer: {e}"))
}

// ------------------------------------------------------------------------------------------------
// REST client + tiny blocking HTTP/1.1 (plaintext loopback only)
// ------------------------------------------------------------------------------------------------

/// A minimal, authenticated REST client bound to one server address + Bearer token.
struct Rest<'a> {
    addr: &'a str,
    token: &'a str,
}

impl Rest<'_> {
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

/// Runs a `RETURN count(...)` over REST and asserts the single scalar equals `expected`.
fn assert_count_rest(
    rest: &Rest<'_>,
    db: &str,
    statement: &str,
    what: &str,
    expected: u64,
) -> Result<(), String> {
    let json = rest.statement(db, what, statement, None)?;
    let got = jolt_scalar_u64(&json).ok_or_else(|| {
        format!(
            "{what}: missing scalar count in {}",
            clip_str(&json.to_string())
        )
    })?;
    if got != expected {
        return Err(format!("{what}: expected {expected}, got {got}"));
    }
    eprintln!("social_wire_load: {what} = {got} (ok)");
    Ok(())
}

/// The `results[0].data[0][0]` scalar of a Jolt `count(...)` envelope as a `u64` (`{"Z":"…"}`).
fn jolt_scalar_u64(json: &Json) -> Option<u64> {
    let cell = json.pointer("/results/0/data/0/0")?;
    let z = cell.get("Z")?.as_str()?;
    z.parse::<i64>().ok().and_then(|v| u64::try_from(v).ok())
}

/// Polls `SHOW INDEXES` until every declared index reports a state other than `populating`, and
/// **fails** if they are still building when the timeout elapses (`rmp` task #733).
///
/// The state is read from the cell under the `state` FIELD, resolved by name against the result's
/// `fields` header — not by scanning the row for the first string cell. That earlier shortcut picked
/// up the row's `name` column (the first string in every row), which never equals `"populating"`, so
/// the gate passed instantly and the loader queried a still-building index: the silent-zero FULLTEXT
/// result of `rmp` #733 was measured through exactly that hole. A verification step that cannot fail
/// verifies nothing.
///
/// Version-tolerant: a server whose `SHOW INDEXES` lacks the `state` field (or rejects the statement
/// outright) reports nothing to wait on, and the poll returns `Ok` — the caller then relies on the
/// engine's own guarantee that a not-yet-`ONLINE` index is answered by a correct scan.
fn wait_for_indexes(rest: &Rest<'_>, db: &str) -> Result<(), String> {
    let deadline = Instant::now() + INDEX_ONLINE_TIMEOUT;
    loop {
        let Ok(json) = rest.statement(db, "SHOW INDEXES", "SHOW INDEXES", None) else {
            return Ok(());
        };
        // The position of the `state` column in this server's result header. Absent ⇒ nothing to wait
        // on (an older server), so the poll is a no-op rather than a spurious failure.
        let fields = json.pointer("/results/0/fields").and_then(Json::as_array);
        let Some(state_at) =
            fields.and_then(|fields| fields.iter().position(|f| f.as_str() == Some("state")))
        else {
            return Ok(());
        };
        let name_at =
            fields.and_then(|fields| fields.iter().position(|f| f.as_str() == Some("name")));
        let building: Vec<String> = json
            .pointer("/results/0/data")
            .and_then(Json::as_array)
            .map(|rows| {
                rows.iter()
                    .filter(|row| {
                        cell_str(row, Some(state_at))
                            .is_some_and(|s| s.eq_ignore_ascii_case("populating"))
                    })
                    .map(|row| cell_str(row, name_at).unwrap_or_else(|| "?".to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        if building.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "index build did not reach ONLINE within {}s: still POPULATING: {}",
                INDEX_ONLINE_TIMEOUT.as_secs(),
                building.join(", ")
            ));
        }
        std::thread::sleep(INDEX_POLL_INTERVAL);
    }
}

/// The string (Jolt `"U"`) cell of a `SHOW INDEXES` row at column `at`, resolved by the caller from
/// the result header — never by position guessed from the row itself.
fn cell_str(row: &Json, at: Option<usize>) -> Option<String> {
    row.as_array()?
        .get(at?)?
        .get("U")
        .and_then(Json::as_str)
        .map(ToOwned::to_owned)
}

fn login(addr: &str, user: &str, password: &str) -> Result<String, String> {
    let body = serde_json::to_vec(&json!({ "username": user, "password": password }))
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

fn statement_body(statement: &str, params: Option<Json>) -> Vec<u8> {
    let stmt = match params {
        Some(p) => json!({ "statement": statement, "parameters": p }),
        None => json!({ "statement": statement }),
    };
    serde_json::to_vec(&json!({ "statements": [stmt] }))
        .expect("INVARIANT: statement request Value is plain JSON")
}

fn read_csv(dir: &Path, name: &str) -> Result<Vec<u8>, String> {
    let path = dir.join(name);
    std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn json_u64(json: &Json, key: &str) -> Option<u64> {
    json.get(key)?.as_u64()
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

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

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    loop {
        let nl = find_sub(data, b"\r\n").ok_or("chunked body: missing chunk-size CRLF")?;
        let size_line = std::str::from_utf8(&data[..nl])
            .map_err(|_| "chunked body: chunk-size line is not UTF-8")?;
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16)
            .map_err(|_| format!("chunked body: invalid chunk size {hex:?}"))?;
        data = &data[nl + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size {
            return Err("chunked body: truncated chunk data".to_owned());
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        if data.starts_with(b"\r\n") {
            data = &data[2..];
        }
    }
    Ok(out)
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn clip_bytes(body: &[u8]) -> String {
    clip_str(&String::from_utf8_lossy(body))
}

fn clip_str(s: &str) -> String {
    const MAX: usize = 2000;
    if s.len() <= MAX {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(MAX).collect();
    out.push_str("... (truncated)");
    out
}
