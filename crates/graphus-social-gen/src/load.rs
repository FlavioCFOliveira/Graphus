//! The engine-driving **large-graph load + traversal** workload for `examples/social-network`,
//! ingesting a large deterministic graph through the **production bulk path** over an **on-disk**
//! store, then serving the openCypher **traversal/read** battery against it through the REAL engine.
//!
//! This module is the shared, library-level core that three consumers reuse so the engine-driving
//! logic lives in exactly one place:
//!
//! - the `social_load` binary (the demonstration + its own pass/fail assertions),
//! - the `social_evidence` binary (a later task — wraps a run with the harness's RSS sampler + a
//!   standardized [`EvidenceReport`](graphus_examples_harness::EvidenceReport)),
//! - the hermetic `tests/load_fast.rs` cargo test (the default-`cargo test` shape + read-query gate).
//!
//! # Why BULK for ingest and CYPHER for traversal (the empirical decision)
//!
//! The example's purpose is to evaluate Graphus on a **large** graph, so the ingest path must scale.
//! Two ingest strategies were considered, and the choice is justified by evidence:
//!
//! - **Per-edge Cypher `CREATE` is `O(E · N)` and does not reach large scale.** Creating an edge by id
//!   with `MATCH (a:USER {id: …}), (b:USER {id: …}) CREATE (a)-[:FRIEND]->(b)` costs one lookup per
//!   endpoint. The planner plan was dumped for *every* two-anchor shape tried — `MATCH (a {id}), (b
//!   {id})`, two separate `MATCH` clauses, `MATCH … WITH … MATCH`, and `MATCH (a),(b) WHERE a.id=… AND
//!   b.id=…` — and in all of them the rule-based planner index-seeks at most **one** anchor:
//!   `NodeIndexSeek(a) ⋈ {Filter over a TokenLookupScan/LabelScan of b}`. The *second* anchor's
//!   predicate sits above the join, where the index-selection rewrite (which only fires on a `Filter`
//!   directly over a `NodeByLabelScan`) cannot reach it. So even with the `:USER(id)` index present,
//!   per-edge ingest is `O(E · N)`, not `O(E · log N)`. **This is a `graphus-cypher` planner
//!   limitation (single-anchor index selection across a join); it is filed as an improvement** — and
//!   it is the reason this loader does *not* ingest via Cypher.
//!
//! - **The production bulk path (`graphus-bulk`'s [`BulkImporter`]) is `O(E)` and scales.** The
//!   importer writes directly through the low-level store API and resolves each relationship endpoint
//!   through an internal `external :ID → physical node id` **hash map** — O(1) per endpoint, **O(E)
//!   total** — independent of `N`. This is exactly the production initial-load fast path the
//!   `graphus-bulk` CLI and the `examples/bulk-etl` demonstration use. So this loader pivots ingest to
//!   it: stream the deterministic [`Generator`] as `neo4j-admin import`-flavoured CSV into the
//!   importer, node files (USER, ARTICLE) then relationship files (FRIEND, LIKE).
//!
//! - **Cypher stays the traversal/read path — that is where a large graph's query latency is
//!   measured.** After [`BulkImporter::finish`] hands the populated [`RecordStore`] back, this loader
//!   builds a [`TxnCoordinator`] over **that same store, in the same process, with no reopen**, builds
//!   the `:USER(id)` / `:ARTICLE(id)` property indexes so the point-lookup-anchored traversals seek,
//!   and runs the read-query battery (direct friends, friend-of-friend, mutual friends, top-liked
//!   articles, degree) over the production statement seam (`TxnCoordinator::statement` + `execute` —
//!   exactly what the server's `handle_run` drives per `RUN`), capturing each probe's latency.
//!
//! This is production-realistic: you **bulk-load** a big graph, declare its lookup indexes, then
//! **serve + query** it. The bulk importer interns every token (the `USER`/`ARTICLE` labels, the
//! `FRIEND`/`LIKE` types, the `id`/`name`/`registered`/`since`/`date` property keys) into the same
//! store, so the coordinator built over it resolves them for the read queries with no extra wiring
//! (asserted by reading the shape back from the engine and by `tests/load_fast.rs`).
//!
//! # Why this uses an ON-DISK store (not the in-memory DST device the iot example uses)
//!
//! The headline evidence of a *large-graph* demonstration is the **real bytes on disk**. So both the
//! bulk import and the read phases run over a [`FileBlockDevice`] (the page device file) + [`FileLogSink`]
//! (the segmented WAL directory) under a caller-supplied directory — the same on-disk layout the
//! `graphus-bulk` importer and the production server use. After the load is flushed + synced the
//! durable footprint is the real summed size of those files, and the logical-vs-physical amplification
//! is derived from the logical CSV byte count the importer consumed.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use graphus_bulk::{BulkImporter, DEFAULT_BATCH_SIZE};
use graphus_core::{TxnId, Value};
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::{
    IndexCatalog, Parameters, Row, RowValue, analyze, bind_parameters, execute, lower,
    parse_tokens, plan_physical, tokenize,
};
use graphus_io::FileBlockDevice;
use graphus_storage::RecordStore;
use graphus_txn::IsolationLevel;
use graphus_wal::{FileLogSink, WalManager};

use crate::{GenConfig, Generator};

/// The on-disk store type this loader drives.
type Store = RecordStore<FileBlockDevice, FileLogSink>;
/// The coordinator type this loader drives.
type Coord = TxnCoordinator<FileBlockDevice, FileLogSink>;

/// Buffer-pool frames for the load session. A larger pool than the iot churn loop's 256 because this
/// workload writes a much bigger graph and benefits from more resident pages during the bulk import
/// and the read battery's endpoint seeks. Still a fixed, modest cap so RAM stays bounded at any
/// profile.
const POOL_PAGES: usize = 4_096;

/// The element-id seed handed to [`RecordStore::create`] (the production default the server uses).
const ELEMENT_ID_SEED: u128 = 1;

/// Knobs for one load run.
#[derive(Debug, Clone)]
pub struct LoadOpts {
    /// Whether to create the `:USER(id)` / `:ARTICLE(id)` indexes after the bulk import and before the
    /// read battery. Always `true` in normal use (it is what makes the point-lookup-anchored
    /// traversals seek); exposed so a benchmark can measure the scan-only read cost if it wants the
    /// contrast.
    pub index_ids: bool,
}

impl Default for LoadOpts {
    fn default() -> Self {
        Self { index_ids: true }
    }
}

/// One read-query probe's measured result: its label, wall-clock latency in microseconds, the number
/// of rows it returned, and a single representative scalar (the first row's first integer value, or
/// `None` when the shape is non-scalar / empty) so the binary can show the answer without
/// re-running the query.
#[derive(Debug, Clone)]
pub struct QuerySample {
    /// A short identifier for the probe (`"friends"`, `"fof"`, `"mutual"`, `"top_liked"`,
    /// `"degree"`).
    pub name: String,
    /// The Cypher the probe ran (for the README / human inspection).
    pub query: String,
    /// Wall-clock latency of the probe in microseconds.
    pub latency_us: u64,
    /// Number of rows the probe returned.
    pub rows: u64,
    /// The first row's first integer value, if the result is scalar-shaped (e.g. a `count`).
    pub scalar: Option<i64>,
}

/// One load phase's timing + throughput.
#[derive(Debug, Clone, Copy)]
pub struct PhaseTiming {
    /// Wall-clock duration of the phase, in milliseconds.
    pub millis: u64,
    /// Items processed in the phase (nodes or edges, depending on the phase).
    pub items: u64,
}

impl PhaseTiming {
    /// Items per second over the phase (`0.0` for a zero-duration phase).
    #[must_use]
    pub fn per_sec(&self) -> f64 {
        if self.millis == 0 {
            0.0
        } else {
            self.items as f64 * 1000.0 / self.millis as f64
        }
    }
}

/// The full load-run outcome — the per-phase bulk-import timings + throughput, the durable on-disk
/// footprint and its logical-vs-physical amplification, the realised graph shape (read back from the
/// engine, not just predicted by the generator), and the read-query battery. Mirrors
/// `graphus-iot-gen`'s `ChurnOutcome` shape.
#[derive(Debug, Clone)]
pub struct LoadOutcome {
    /// The resolved generation config the run executed.
    pub cfg: GenConfig,
    /// Whether the id indexes were created before the read battery.
    pub indexed: bool,
    /// Timing + throughput of the bulk **node** import pass (USER + ARTICLE files), from the
    /// importer's [`ImportStats`](graphus_bulk::ImportStats) wall-clock plus this loader's own timing.
    pub nodes_phase: PhaseTiming,
    /// Timing + throughput of the bulk **relationship** import pass (FRIEND + LIKE files).
    pub rels_phase: PhaseTiming,
    /// Nodes ingested per second over the node pass, as reported by the importer's `ImportStats`.
    pub import_nodes_per_sec: f64,
    /// Relationships ingested per second over the relationship pass, as reported by `ImportStats`.
    pub import_rels_per_sec: f64,
    /// Total typed property assignments the importer made (across nodes and relationships).
    pub import_properties: u64,
    /// The uncompressed logical size, in bytes, of the loader-ready CSV the importer consumed (the
    /// honest denominator for the amplification figures).
    pub logical_csv_bytes: u64,
    /// Wall-clock duration of the two `CREATE INDEX` builds, in milliseconds (`0` when not indexed).
    pub index_build_millis: u64,
    /// Durable on-disk size of the page device file after the load (bytes).
    pub device_bytes: u64,
    /// Durable on-disk size of the WAL directory after the load (bytes, summed over its segments).
    pub wal_bytes: u64,
    /// `USER` node count read back from the engine after the load.
    pub user_count: u64,
    /// `ARTICLE` node count read back from the engine after the load.
    pub article_count: u64,
    /// `FRIEND` edge count read back from the engine after the load.
    pub friend_count: u64,
    /// `LIKE` edge count read back from the engine after the load.
    pub like_count: u64,
    /// The read-query battery's measured samples, in run order.
    pub queries: Vec<QuerySample>,
}

impl LoadOutcome {
    /// Total durable on-disk footprint = device file + WAL directory (bytes).
    #[must_use]
    pub fn footprint_bytes(&self) -> u64 {
        self.device_bytes + self.wal_bytes
    }

    /// Total nodes + edges loaded (the realised, read-back totals).
    #[must_use]
    pub fn total_elements(&self) -> u64 {
        self.user_count + self.article_count + self.friend_count + self.like_count
    }

    /// Space amplification = total durable on-disk bytes (device + WAL) / logical CSV bytes. The
    /// peak-footprint figure right after a bulk load (the WAL still holds the redo log; a later
    /// checkpoint truncates it). `0.0` when no logical bytes were consumed.
    #[must_use]
    pub fn space_amplification(&self) -> f64 {
        if self.logical_csv_bytes == 0 {
            0.0
        } else {
            self.footprint_bytes() as f64 / self.logical_csv_bytes as f64
        }
    }

    /// Steady-state space amplification = durable **store** image bytes / logical CSV bytes (the WAL,
    /// a transient redo log, excluded). What a checkpointed store occupies for the logical input.
    #[must_use]
    pub fn store_space_amplification(&self) -> f64 {
        if self.logical_csv_bytes == 0 {
            0.0
        } else {
            self.device_bytes as f64 / self.logical_csv_bytes as f64
        }
    }

    /// Looks up a measured query sample by its `name`.
    #[must_use]
    pub fn query(&self, name: &str) -> Option<&QuerySample> {
        self.queries.iter().find(|q| q.name == name)
    }
}

/// Creates a fresh on-disk store under `dir` (a `graph.store` page-device file + a `graph.wal`
/// segmented WAL directory), recovering nothing (the directory is created empty). Returns the store
/// (the bulk importer wants the `RecordStore` directly, not a coordinator). Mirrors the construction
/// in `graphus-server`'s `LocalEngine` and the `graphus-bulk` importer, but creating a *new* store.
///
/// # Errors
/// Returns a [`graphus_core::GraphusError`] if the device file, the WAL, or the store cannot be
/// created.
fn create_store(dir: &Path) -> Result<Store, graphus_core::GraphusError> {
    let device_file = dir.join("graph.store");
    let wal_dir = dir.join("graph.wal");
    let device = FileBlockDevice::open(&device_file)?;
    let wal = WalManager::create(
        FileLogSink::open(&wal_dir)
            .map_err(|e| graphus_core::GraphusError::Storage(format!("create wal: {e}")))?,
    )
    .map_err(|e| graphus_core::GraphusError::Storage(format!("create wal manager: {e}")))?;
    RecordStore::create(device, wal, POOL_PAGES, ELEMENT_ID_SEED)
}

/// Streams a generator CSV stream to a temp file under `dir`, **chunk by chunk** (peak resident
/// memory is one chunk — never the whole CSV), and returns the file path plus the total bytes written
/// (the logical size of that CSV). The `stream` closure pushes chunks to the supplied sink; this
/// writes each straight to the file as it arrives. Using a temp file (rather than holding the bytes)
/// is what keeps the `huge` profile's multi-gigabyte CSVs off the heap.
///
/// # Errors
/// Returns an [`std::io::Error`] if the file cannot be created or written.
fn write_csv_to_temp(
    dir: &Path,
    name: &str,
    stream: impl FnOnce(&mut dyn FnMut(Vec<u8>)),
) -> std::io::Result<(PathBuf, u64)> {
    let path = dir.join(name);
    let file = std::fs::File::create(&path)?;
    let mut writer = std::io::BufWriter::new(file);
    let mut bytes = 0u64;
    let mut err: Option<std::io::Error> = None;
    {
        let mut sink = |chunk: Vec<u8>| {
            if err.is_some() {
                return;
            }
            bytes += chunk.len() as u64;
            if let Err(e) = writer.write_all(&chunk) {
                err = Some(e);
            }
        };
        stream(&mut sink);
    }
    if let Some(e) = err {
        return Err(e);
    }
    writer.flush()?;
    Ok((path, bytes))
}

/// Opens a buffered reader over a CSV file the bulk import passes consume.
fn buf_read(path: &Path) -> std::io::Result<std::io::BufReader<std::fs::File>> {
    Ok(std::io::BufReader::new(std::fs::File::open(path)?))
}

/// Runs one Cypher statement to completion inside the already-open `txn` over the coordinator's
/// statement seam (the production code path), compiling against `catalog` so index-accelerated
/// strategies are picked. Returns the materialised rows. Panics if the statement captured an engine
/// error — every statement in this workload is well-formed by construction.
fn run_in_txn(coord: &Coord, txn: TxnId, catalog: &IndexCatalog, src: &str) -> Vec<Row> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    // Compile against the LIVE catalog (not `IndexCatalog::empty()`): with the `:USER(id)` /
    // `:ARTICLE(id)` indexes present, the anchor of every `MATCH (:USER {id: …})` becomes a
    // `NodeIndexSeek` so the read-query battery's point lookups seek.
    let plan = plan_physical(&lower(&validated), catalog);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(
        !graph.has_error(),
        "captured engine error running {src:?}: {:?}",
        graph.take_error()
    );
    rows
}

/// Reads a single scalar integer (a `count(...)`) from `src` in its own committed snapshot txn.
fn scalar_count(coord: &mut Coord, catalog: &IndexCatalog, src: &str) -> u64 {
    let txn = coord.begin(IsolationLevel::Snapshot);
    let rows = run_in_txn(coord, txn, catalog, src);
    coord.commit(txn).expect("commit count");
    match rows.first().and_then(|r| r.values().first()) {
        Some(RowValue::Value(Value::Integer(n))) => u64::try_from(*n).unwrap_or(0),
        other => panic!("unexpected count row for {src:?}: {other:?}"),
    }
}

/// Runs `src` in its own committed snapshot transaction and returns its rows + wall-clock latency.
fn timed_read(coord: &mut Coord, catalog: &IndexCatalog, src: &str) -> (Vec<Row>, u64) {
    let started = Instant::now();
    let txn = coord.begin(IsolationLevel::Snapshot);
    let rows = run_in_txn(coord, txn, catalog, src);
    coord.commit(txn).expect("commit read");
    let latency_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    (rows, latency_us)
}

/// Extracts the first row's first integer value, if the result is scalar-shaped.
fn first_scalar(rows: &[Row]) -> Option<i64> {
    match rows.first().and_then(|r| r.values().first()) {
        Some(RowValue::Value(Value::Integer(n))) => Some(*n),
        _ => None,
    }
}

/// The summed byte size of every regular file under `dir` (recursively). Used to total the WAL
/// directory's segment files. Returns `0` for a missing directory.
fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            total += dir_bytes(&entry.path());
        } else {
            total += meta.len();
        }
    }
    total
}

/// Runs the full large-graph **bulk load + read-query battery** against a fresh on-disk store under
/// `dir`, returning the structural + performance outcome.
///
/// The load proceeds in two bulk passes (driven straight from the deterministic [`Generator`] as
/// streamed CSV through [`BulkImporter`]): a **node** pass (USER then ARTICLE files) and a
/// **relationship** pass (FRIEND then LIKE files). After [`BulkImporter::finish`] hands the populated
/// store back, a [`TxnCoordinator`] is built over it (same process, no reopen), the `:USER(id)` /
/// `:ARTICLE(id)` indexes are built (when `opts.index_ids`), the store is flushed + synced and the
/// durable file sizes measured, the realised graph shape is read back from the engine, and the
/// read-query battery is run with per-query latencies.
///
/// `dir` must be an existing, writable directory the caller owns (a temp dir for tests, a chosen
/// path for an evidence run); this function creates `graph.store` + `graph.wal` and the streamed
/// CSV temp files inside it and never deletes them — the caller decides their lifetime.
///
/// # Panics
/// Panics if any statement captures an engine error (the read battery is well-formed by construction)
/// or if store creation / bulk import / flush fails — those would signal a real durability or engine
/// bug worth surfacing loudly in the example.
#[must_use]
pub fn run_load(cfg: &GenConfig, dir: &Path, opts: LoadOpts) -> LoadOutcome {
    let store = create_store(dir).expect("create on-disk store");
    let generator = Generator::new(cfg.clone());

    // --- Stream the four CSVs to temp files, chunk-by-chunk (peak memory: one chunk). -------------
    // The streams also report the realised edge totals (== the generator's friend/like edge counts).
    let (users_csv, users_bytes) =
        write_csv_to_temp(dir, "users.csv", |s| generator.stream_user_csv(s))
            .expect("write users.csv");
    let (articles_csv, articles_bytes) =
        write_csv_to_temp(dir, "articles.csv", |s| generator.stream_article_csv(s))
            .expect("write articles.csv");
    let mut friend_emitted = 0u64;
    let (friends_csv, friends_bytes) = write_csv_to_temp(dir, "friends.csv", |s| {
        friend_emitted = generator.stream_friend_csv(s);
    })
    .expect("write friends.csv");
    let mut like_emitted = 0u64;
    let (likes_csv, likes_bytes) = write_csv_to_temp(dir, "likes.csv", |s| {
        like_emitted = generator.stream_like_csv(s);
    })
    .expect("write likes.csv");
    let logical_csv_bytes = users_bytes + articles_bytes + friends_bytes + likes_bytes;

    // --- Bulk import: node pass (USER then ARTICLE), then relationship pass (FRIEND then LIKE). ---
    // The importer resolves each relationship endpoint through its internal external-id→internal-id
    // hash map (O(1) per endpoint ⇒ O(E) total) — the production initial-load fast path. It interns
    // every token (labels, rel types, prop keys) into the store, so the coordinator built below
    // resolves them for the read battery with no extra wiring.
    let mut importer = BulkImporter::new(store, DEFAULT_BATCH_SIZE, b',');

    let t = Instant::now();
    importer
        .import_nodes(buf_read(&users_csv).expect("open users.csv"))
        .expect("import USER nodes");
    importer
        .import_nodes(buf_read(&articles_csv).expect("open articles.csv"))
        .expect("import ARTICLE nodes");
    let node_wall_ms = t.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

    let t = Instant::now();
    importer
        .import_relationships(buf_read(&friends_csv).expect("open friends.csv"))
        .expect("import FRIEND edges");
    importer
        .import_relationships(buf_read(&likes_csv).expect("open likes.csv"))
        .expect("import LIKE edges");
    let rel_wall_ms = t.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

    let (store, stats) = importer.finish();

    let nodes_phase = PhaseTiming {
        millis: node_wall_ms,
        items: stats.nodes,
    };
    let rels_phase = PhaseTiming {
        millis: rel_wall_ms,
        items: stats.relationships,
    };

    // --- Build a coordinator over the SAME store (no reopen) for the index build + read battery. --
    let mut coord = TxnCoordinator::new(store);

    // --- Index build (schema op via the dedicated coordinator method, online over loaded data). ---
    // This is what makes the read battery's id-anchored point lookups seek instead of scan.
    let mut index_build_millis = 0u64;
    if opts.index_ids {
        let t = Instant::now();
        coord
            .create_node_property_index("USER", "id")
            .expect("create :USER(id) index");
        coord
            .create_node_property_index("ARTICLE", "id")
            .expect("create :ARTICLE(id) index");
        index_build_millis = t.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    }
    // The live catalog the read phases compile against: reflects the indexes just built so the planner
    // emits `NodeIndexSeek` for every id-keyed MATCH.
    let catalog = coord.catalog();

    // --- Flush + sync so the durable image on disk reflects every committed page, then measure. ---
    coord
        .with_store_mut(|s| s.flush())
        .expect("flush store after load");
    let device_file = dir.join("graph.store");
    let wal_dir = dir.join("graph.wal");
    let device_bytes = std::fs::metadata(&device_file)
        .map(|m| m.len())
        .unwrap_or(0);
    let wal_bytes = dir_bytes(&wal_dir);

    // --- Read back the realised shape from the engine (not just the generator's prediction). ------
    let user_count = scalar_count(&mut coord, &catalog, "MATCH (u:USER) RETURN count(u) AS c");
    let article_count = scalar_count(
        &mut coord,
        &catalog,
        "MATCH (a:ARTICLE) RETURN count(a) AS c",
    );
    let friend_count = scalar_count(
        &mut coord,
        &catalog,
        "MATCH ()-[r:FRIEND]-() RETURN count(r) AS c",
    ) / 2; // each undirected FRIEND is traversed from both ends.
    let like_count = scalar_count(
        &mut coord,
        &catalog,
        "MATCH ()-[r:LIKE]->() RETURN count(r) AS c",
    );

    // --- The read-query battery. ------------------------------------------------------------------
    let queries = run_query_battery(&mut coord, &catalog, &generator);

    LoadOutcome {
        cfg: cfg.clone(),
        indexed: opts.index_ids,
        nodes_phase,
        rels_phase,
        import_nodes_per_sec: stats.nodes_per_sec(),
        import_rels_per_sec: stats.rels_per_sec(),
        import_properties: stats.properties,
        logical_csv_bytes,
        index_build_millis,
        device_bytes,
        wal_bytes,
        user_count,
        article_count,
        friend_count,
        like_count,
        queries,
    }
}

/// Runs the five read-query probes against the loaded graph, returning a measured [`QuerySample`]
/// per probe. The probes exercise the traversal capabilities a social network actually uses:
///
/// 1. `friends`   — direct friends of a sample user (1-hop neighbourhood).
/// 2. `fof`       — friend-of-friend (2-hop) of a sample user, excluding the user itself.
/// 3. `mutual`    — mutual friends shared by two sample users.
/// 4. `top_liked` — the top-N most-liked articles (aggregation + `ORDER BY` + `LIMIT`).
/// 5. `degree`    — a sample user's friend count (degree).
fn run_query_battery(
    coord: &mut Coord,
    catalog: &IndexCatalog,
    generator: &Generator,
) -> Vec<QuerySample> {
    // Two stable sample users (the index seek makes these cheap regardless of graph size). User 0
    // and user 1 are guaranteed to exist for any non-empty population.
    let u0 = generator.sample_user_id(0);
    let u1 = generator.sample_user_id(1);

    let mut out = Vec::with_capacity(5);

    // 1) Direct friends.
    let q = format!(
        "MATCH (u:USER {{id: '{u0}'}})-[:FRIEND]-(f:USER) RETURN count(DISTINCT f) AS friends"
    );
    let (rows, latency_us) = timed_read(coord, catalog, &q);
    out.push(QuerySample {
        name: "friends".to_owned(),
        query: q,
        latency_us,
        rows: rows.len() as u64,
        scalar: first_scalar(&rows),
    });

    // 2) Friend-of-friend (2-hop), excluding the seed user itself (a friend reached via two hops is
    //    a 2-hop neighbour; we count the distinct set so direct friends reachable on a second path
    //    are not double-counted).
    let q = format!(
        "MATCH (u:USER {{id: '{u0}'}})-[:FRIEND]-(:USER)-[:FRIEND]-(fof:USER) \
         WHERE fof.id <> '{u0}' \
         RETURN count(DISTINCT fof) AS fof"
    );
    let (rows, latency_us) = timed_read(coord, catalog, &q);
    out.push(QuerySample {
        name: "fof".to_owned(),
        query: q,
        latency_us,
        rows: rows.len() as u64,
        scalar: first_scalar(&rows),
    });

    // 3) Mutual friends between two sample users.
    let q = format!(
        "MATCH (a:USER {{id: '{u0}'}})-[:FRIEND]-(m:USER)-[:FRIEND]-(b:USER {{id: '{u1}'}}) \
         RETURN count(DISTINCT m) AS mutual"
    );
    let (rows, latency_us) = timed_read(coord, catalog, &q);
    out.push(QuerySample {
        name: "mutual".to_owned(),
        query: q,
        latency_us,
        rows: rows.len() as u64,
        scalar: first_scalar(&rows),
    });

    // 4) Top-N most-liked articles (aggregation + ORDER BY + LIMIT).
    let q = "MATCH (:USER)-[:LIKE]->(a:ARTICLE) \
             RETURN a.name AS article, count(*) AS likes \
             ORDER BY likes DESC, article ASC LIMIT 5"
        .to_owned();
    let (rows, latency_us) = timed_read(coord, catalog, &q);
    out.push(QuerySample {
        name: "top_liked".to_owned(),
        query: q,
        latency_us,
        // Non-scalar shape: report the row count (the N returned) and the top article's like count.
        rows: rows.len() as u64,
        scalar: rows
            .first()
            .and_then(|r| r.values().get(1))
            .and_then(|v| match v {
                RowValue::Value(Value::Integer(n)) => Some(*n),
                _ => None,
            }),
    });

    // 5) Degree (a sample user's friend count).
    let q = format!("MATCH (u:USER {{id: '{u0}'}})-[:FRIEND]-(f:USER) RETURN count(f) AS degree");
    let (rows, latency_us) = timed_read(coord, catalog, &q);
    out.push(QuerySample {
        name: "degree".to_owned(),
        query: q,
        latency_us,
        rows: rows.len() as u64,
        scalar: first_scalar(&rows),
    });

    out
}

/// The worker-thread stack size for a load run (`128 MiB`), matching the openCypher TCK harness's
/// per-scenario stack. The engine's recursive front-end (parser → analyzer → physical planner) and
/// the recursive cursor tree can nest deeply for a read query; running the load on a generously-sized
/// thread is the same isolation the TCK runner and the server's engine thread use.
pub const LOAD_STACK_BYTES: usize = 128 * 1024 * 1024;

/// Runs [`run_load`] on a dedicated 128 MiB-stack thread (see [`LOAD_STACK_BYTES`]). This is the
/// entry point the binary and the cargo test use, so a deep recursion in the engine's front-end /
/// executor over a read query cannot overflow the default thread stack. The closure is pure with
/// respect to the caller (it owns its own store), so joining it back is straightforward.
///
/// # Panics
/// Propagates any panic from the load (re-raised on the calling thread) so a real engine/durability
/// bug still surfaces loudly, exactly as a direct [`run_load`] call would.
#[must_use]
pub fn run_load_isolated(cfg: &GenConfig, dir: &Path, opts: LoadOpts) -> LoadOutcome {
    let cfg = cfg.clone();
    let dir = dir.to_path_buf();
    std::thread::Builder::new()
        .name("social-load".to_owned())
        .stack_size(LOAD_STACK_BYTES)
        .spawn(move || run_load(&cfg, &dir, opts))
        .expect("spawn social-load thread")
        .join()
        .unwrap_or_else(|p| std::panic::resume_unwind(p))
}

/// Resolves a `dir` argument: if `Some`, use it (the caller owns its lifetime); if `None`, create a
/// fresh, unique temp directory under the system temp dir and return it. Used by the binary so a bare
/// `social_load` run is self-cleaning-free but isolated per invocation.
///
/// # Errors
/// Returns an [`std::io::Error`] if the temp directory cannot be created.
pub fn resolve_dir(dir: Option<PathBuf>) -> std::io::Result<PathBuf> {
    if let Some(d) = dir {
        std::fs::create_dir_all(&d)?;
        return Ok(d);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "graphus-social-load-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

/// Serialises the outcome to a compact JSON object (hand-rolled flat writer, dependency-light and
/// stable — mirrors `graphus-iot-gen`'s `samples_json`). This is the machine-readable result the
/// `social_load` binary emits on its sentinel line.
#[must_use]
pub fn outcome_json(out: &LoadOutcome) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(512 + out.queries.len() * 128);
    s.push('{');
    let _ = write!(s, "\"seed\":{},", out.cfg.seed);
    let _ = write!(s, "\"indexed\":{},", out.indexed);
    let _ = write!(s, "\"users\":{},", out.user_count);
    let _ = write!(s, "\"articles\":{},", out.article_count);
    let _ = write!(s, "\"friend_edges\":{},", out.friend_count);
    let _ = write!(s, "\"like_edges\":{},", out.like_count);
    let _ = write!(s, "\"properties\":{},", out.import_properties);
    let _ = write!(s, "\"logical_csv_bytes\":{},", out.logical_csv_bytes);
    let _ = write!(s, "\"device_bytes\":{},", out.device_bytes);
    let _ = write!(s, "\"wal_bytes\":{},", out.wal_bytes);
    let _ = write!(s, "\"footprint_bytes\":{},", out.footprint_bytes());
    let _ = write!(
        s,
        "\"space_amplification\":{:.3},",
        out.space_amplification()
    );
    let _ = write!(
        s,
        "\"store_space_amplification\":{:.3},",
        out.store_space_amplification()
    );
    let _ = write!(s, "\"index_build_millis\":{},", out.index_build_millis);
    let _ = write!(
        s,
        "\"nodes_ms\":{},\"nodes_per_sec\":{:.1},\"import_nodes_per_sec\":{:.1},",
        out.nodes_phase.millis,
        out.nodes_phase.per_sec(),
        out.import_nodes_per_sec
    );
    let _ = write!(
        s,
        "\"rels_ms\":{},\"rels_per_sec\":{:.1},\"import_rels_per_sec\":{:.1},",
        out.rels_phase.millis,
        out.rels_phase.per_sec(),
        out.import_rels_per_sec
    );
    s.push_str("\"queries\":[");
    for (i, q) in out.queries.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            "{{\"name\":\"{}\",\"latency_us\":{},\"rows\":{},\"scalar\":{}}}",
            q.name,
            q.latency_us,
            q.rows,
            q.scalar
                .map_or_else(|| "null".to_owned(), |n| n.to_string())
        );
    }
    s.push_str("]}");
    s
}
