//! `iot_wire` — the **FILE-BACKED, over-the-wire** IoT ingest + retention churn driver (`rmp` #694).
//!
//! This is where `examples/iot-timeseries`'s storage claims are actually earned. The in-process mirror
//! ([`graphus_iot_gen::churn`]) runs the real engine, but over an **in-memory** device and WAL: there is
//! no store file and no WAL file, so durable bytes, WAL/store amplification and fsync volume are
//! structurally unmeasurable there. This driver instead speaks **Bolt** to a real `graphus-server` —
//! with a real `FileBlockDevice` and a real segmented WAL on disk — and measures what is really written.
//!
//! # What it drives
//!
//! 1. **Schema first** (over the wire): a `NODE KEY` on `Sensor.id`, an existence + a property-type
//!    constraint on the reading (`ts IS :: ZONED DATETIME`), a `POINT` index on `Sensor.location`, a
//!    composite `RANGE` index on `Reading(sensor, seq)`, the single-property `RANGE` retention index on
//!    `Reading.seq`, and a `RANGE` index on the **temporal** `Reading.ts`. Each is attempted
//!    independently, so an older target that lacks an index kind degrades to a recorded skip instead of
//!    a hard failure.
//! 2. **Batched, concurrent ingest**: `--ingest-clients` independent Bolt connections, each owning a
//!    **disjoint slice of the sensor fleet** (`sensor % clients`), each ingesting `--batch N` readings
//!    per statement and per commit (`UNWIND $rows …`) — what a real gateway does. Sharding by sensor is
//!    what makes the concurrency conflict-free by construction: two readings from different sensors
//!    never touch the same node, so they never contend for the same relationship-chain head. Retriable
//!    transaction errors are retried (and counted, never hidden).
//! 3. **A `batch = 1` CONTROL segment** (`--batch1-ticks`, default 10) at the end of the churn, in the
//!    same steady state, on the same database: one Bolt round-trip and one commit per 32-byte reading.
//!    Its durable write volume is **measured**, not modelled — so the example's headline claim (that
//!    per-reading commits dominate the durability bill) is a comparison of two observations (`rmp` #745).
//! 4. **A concurrent READ mix** (`--reader-clients`, default 2) running DURING the churn: windowed
//!    composite-index reads, per-sensor aggregations and **temporal** `ts ∈ [t0, t1)` window reads, each
//!    result **gated against the generator's own stream** — not counted. An index that silently returns
//!    an empty set (`rmp` #738) fails the run here.
//! 5. **Retention**: one windowed `DETACH DELETE` per tick on the control connection, after the tick's
//!    ingest has fully drained (so it never races the writers it would otherwise conflict with).
//! 6. **The real reclamation trigger**: `CHECKPOINT DATABASE <db>` every `--checkpoint-every` ticks — a
//!    parsed admin statement (`rmp` #305), issued over the SAME Bolt connection as every other
//!    statement.
//!
//! # What it measures (and what it refuses to invent)
//!
//! Per tick it samples the live `:Reading` count over the wire and — when co-located with the server
//! (`--db-store-path`) — the REAL on-disk footprint, classified **by path** so the segmented WAL
//! (`graphus.wal/seg.<lsn>`: a DIRECTORY of files whose leaf names contain no "wal") is counted as WAL
//! and not silently folded into the store. It tracks the cumulative WAL bytes written (segments are
//! append-only, so the maximum length ever seen per segment path is what the engine wrote — the
//! residual on-disk WAL alone understates it badly once checkpoints start reclaiming), reads the
//! server's own CPU / peak RSS / kernel `write_bytes` from `/proc`, and records real latency percentiles
//! per statement family and per read family.
//!
//! In **attach (external)** mode none of that is accessible — the server is on another host — so every
//! such field is emitted as `null` (NOT as `0`) and the server-side evidence comes from `/metrics`.
//!
//! # Usage
//!
//! ```text
//! iot_wire --socket <path> | --bolt bolt[+ssc]://host:port
//!          --user U --password P --db <database> --samples <out.json>
//!          [--profile fast|reclaim|large|soak] [--sensors N] [--rate N] [--window N] [--ticks N] [--seed N]
//!          [--ingest-clients N] [--batch N] [--batch1-ticks N] [--reader-clients N]
//!          [--checkpoint-every N] [--payload-samples N]
//!          [--db-store-path <dir>] [--server-pid <pid>]
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_iot_gen::footprint::{self, StoreFootprint};
use graphus_iot_gen::wire_samples::{
    WIRE_SAMPLES_VERSION, WalAttribution, WireCheck, WireLatency, WireReaderFamily, WireReaders,
    WireSamples, WireSegment, WireStorage, WireTick, WireTransport,
};
use graphus_iot_gen::{GenConfig, Generator, ReadingRow, SITE_RADIUS, expected_window};
use graphus_reco_gen::bench::{
    ns_to_ms, parse_proc_io_bytes, parse_status_kb_bytes, percentile_ns,
};
use graphus_reco_gen::client::{BoltClient, BoltUrl, ClientError, QueryResult};

/// The Graphus page size — the unit the store's data image grows in. Mirrors `graphus_io::PAGE_SIZE`
/// (this binary is client-only and never links the engine, so the constant is restated, and a unit test
/// below pins it against the value the store actually produces).
const PAGE_SIZE: u64 = 8192;

/// How long a client waits for a server reply before giving up.
const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// How many times a retriable transaction error (an SSI or write-write conflict) is retried before the
/// run gives up on that statement. Sensor-sharded ingest should never conflict, so a non-zero retry
/// count is itself evidence worth reporting.
const MAX_RETRIES: u32 = 8;

/// How many failure messages a reader family keeps verbatim. Enough to diagnose without drowning the
/// report; the *counts* are complete either way.
const MAX_FAILURE_SAMPLES: usize = 5;

/// How often the dedicated [`WalSampler`] thread re-reads the WAL directory (`rmp` #745).
///
/// **This interval is load-bearing evidence, not a tuning knob.** The cumulative WAL volume is
/// reconstructed by keeping the maximum length ever observed per segment path — sound *only* if every
/// segment is observed at its final length before a checkpoint deletes it. Sampled once per TICK, that
/// premise broke: the `batch = 1` control writes over 1 MiB of WAL per tick against a store-proportional
/// seal size of exactly 1 MiB (`clamp(store, 1 MiB, 64 MiB)`), so a segment could be created, filled,
/// sealed AND reclaimed *between two consecutive samples* — never observed, or observed far below its
/// sealed length. The resulting under-count was ONE-SIDED (a per-path maximum over append-only files can
/// only ever be too small) and HOST-SPEED DEPENDENT (it is a function of write-rate over sample-rate), so
/// the published write amplification was neither correct nor reproducible.
///
/// At 2 ms the control's ~58 ms segment lifetime is sampled ~29 times, and the main segment's ~3.5 ticks
/// hundreds of times. The cost is one `read_dir` of a directory holding a handful of files, in the DRIVER
/// process — it does not touch the server's write path.
///
/// A faster sampler still does not *prove* nothing was missed, which is why it is not the whole fix:
/// [`WireSamples::instrument_gate`](graphus_iot_gen::wire_samples::WireSamples::instrument_gate) FAILS
/// the run if the reconstruction ever falls below the floor the run's own on-disk series forces on it.
///
/// `--wal-sample-ms` overrides it. That flag is the instrument's own CALIBRATION KNOB, and it is the
/// empirical answer to "is 2 ms actually fast enough?": sweep it, and the reconstructed WAL volume must
/// **PLATEAU**. If the figure is still climbing as the sampler speeds up, the sampler is still missing
/// segments and the volume is still an under-count. Measured on this host (`reclaim` profile):
///
/// ```text
///   16 ms -> 48.6 MB      still climbing: segments are being missed
///    8 ms -> 51.0 MB
///    4 ms -> 52.3 MB
///    2 ms -> 52.5 MB      <- the default
///    1 ms -> 52.5 MB      converged
/// ```
const DEFAULT_WAL_SAMPLE_MS: u64 = 2;

// ==================================================================================================
// The WAL instrument (`rmp` #745)
// ==================================================================================================

/// The cumulative WAL volume, reconstructed from a **dedicated high-frequency sampler thread**.
///
/// A WAL segment is append-only and is never truncated, so the maximum length ever seen for a segment
/// path is what the engine wrote into it before a checkpoint deleted it. Summing those maxima recovers
/// the total volume — provided nothing is born and dies between two samples. See
/// [`WAL_SAMPLE_INTERVAL`] for the defect this replaced, and why polling faster is necessary but not
/// sufficient (the gate is the sufficient half).
struct WalSampler {
    /// The store directory to walk.
    path: PathBuf,
    /// How often the background thread re-reads it.
    interval: Duration,
    /// segment path -> the MAXIMUM length ever observed for it. Monotone by construction.
    seen: Mutex<BTreeMap<PathBuf, u64>>,
    stop: AtomicBool,
}

impl WalSampler {
    fn new(path: PathBuf, interval_ms: u64) -> Self {
        Self {
            path,
            interval: Duration::from_millis(interval_ms.max(1)),
            seen: Mutex::new(BTreeMap::new()),
            stop: AtomicBool::new(false),
        }
    }

    /// Takes ONE observation of the WAL directory and folds it into the running maxima.
    ///
    /// Called both by the background thread and, synchronously, at every phase boundary — so a mark is
    /// always taken against a *fresh* observation rather than whatever the sampler last happened to see.
    fn sample(&self) {
        let segments = footprint::wal_segments(&self.path);
        let mut seen = self.lock();
        for (seg, len) in segments {
            let e = seen.entry(seg).or_insert(0);
            *e = (*e).max(len);
        }
    }

    /// The cumulative WAL bytes observed so far. Monotone non-decreasing.
    fn total(&self) -> u64 {
        self.lock().values().sum()
    }

    /// The sampler outlives any panic in the workload thread, and a poisoned mutex would then lose the
    /// entire measurement — so the guard is recovered rather than propagated. The map's invariant
    /// (per-path maxima) cannot be broken by a panic between the two statements that maintain it.
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<PathBuf, u64>> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Starts the sampler thread. It runs until [`stop`](WalSampler::stop) is set, which must not happen
/// until the LAST byte the run cares about has been written (that includes the post-churn functional
/// checks, whose rejected writes are real transactions that write real WAL).
fn spawn_wal_sampler(sampler: &Arc<WalSampler>) -> std::thread::JoinHandle<()> {
    let sampler = Arc::clone(sampler);
    std::thread::spawn(move || {
        while !sampler.stop.load(Ordering::Acquire) {
            sampler.sample();
            // Sleep in SLICES, re-checking `stop` between them, so shutdown never has to wait out a
            // whole interval. A single `sleep(interval)` here made the run's final `join` block for the
            // full period — harmless at the 2 ms default, and a hang at the long intervals the
            // calibration sweep uses. A shutdown latency that scales with a tuning knob is a bug.
            let mut left = sampler.interval;
            while !left.is_zero() && !sampler.stop.load(Ordering::Acquire) {
                let slice = left.min(Duration::from_millis(2));
                std::thread::sleep(slice);
                left -= slice;
            }
        }
        sampler.sample(); // a final observation, so nothing written just before the stop is missed
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("iot_wire: error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ==================================================================================================
// Transport + statement helpers
// ==================================================================================================

/// Where the driver connects.
#[derive(Debug, Clone)]
enum Target {
    Uds(PathBuf),
    Bolt(BoltUrl),
}

impl Target {
    fn transport(&self) -> WireTransport {
        match self {
            Self::Uds(_) => WireTransport::BoltUds,
            Self::Bolt(_) => WireTransport::BoltTcp,
        }
    }

    fn connect(&self, user: &str, password: &str) -> Result<BoltClient, String> {
        let mut c = match self {
            Self::Uds(p) => BoltClient::connect_uds(p, READ_TIMEOUT)
                .map_err(|e| format!("connect UDS {}: {e}", p.display()))?,
            Self::Bolt(u) => BoltClient::connect_bolt(u, READ_TIMEOUT)
                .map_err(|e| format!("connect {u}: {e}"))?,
        };
        c.login(user, password).map_err(|e| format!("login: {e}"))?;
        Ok(c)
    }
}

/// Whether a server failure is a **retriable** transaction conflict (SSI or write-write) rather than a
/// terminal error. Neo4j-compatible clients key off the `TransientError` classification and the
/// `Neo.TransientError.Transaction.*` code family, which Graphus reproduces.
fn is_retriable(err: &ClientError) -> bool {
    let text = err.to_string();
    let t = text.to_ascii_lowercase();
    t.contains("transienterror")
        || t.contains("serialization")
        || t.contains("serialisation")
        || t.contains("conflict")
        || t.contains("deadlock")
        || t.contains("outdated")
}

/// Runs one statement, retrying a retriable transaction conflict up to [`MAX_RETRIES`] times. Returns
/// the statement's latency, how many retries it cost, and the FULL result — including the server's
/// side-effect `stats`, which is the only authority on what a write statement actually wrote (`rmp`
/// #745; see [`ingest_rows`]).
fn run_retrying_full(
    client: &mut BoltClient,
    db: &str,
    query: &str,
    params: Vec<(String, Value)>,
) -> Result<(Duration, u32, QueryResult), String> {
    let mut retries = 0u32;
    loop {
        let started = Instant::now();
        match client.run(query, params.clone(), db) {
            Ok(r) => return Ok((started.elapsed(), retries, r)),
            Err(e) if is_retriable(&e) && retries < MAX_RETRIES => {
                retries += 1;
                std::thread::sleep(Duration::from_millis(2 * u64::from(retries)));
            }
            Err(e) => return Err(format!("{query}: {e}")),
        }
    }
}

/// [`run_retrying_full`] for the callers that only need the rows back.
fn run_retrying(
    client: &mut BoltClient,
    db: &str,
    query: &str,
    params: Vec<(String, Value)>,
) -> Result<(Duration, u32, Vec<Vec<Value>>), String> {
    let (lat, retries, result) = run_retrying_full(client, db, query, params)?;
    Ok((lat, retries, result.records))
}

/// Runs a scalar-shaped query (a single `count(...)` cell) and returns the integer.
fn scalar(client: &mut BoltClient, db: &str, query: &str) -> Result<i64, String> {
    let (_, _, rows) = run_retrying(client, db, query, Vec::new())?;
    match rows.first().and_then(|r| r.first()) {
        Some(Value::Integer(n)) => Ok(*n),
        other => Err(format!("{query}: expected a scalar integer, got {other:?}")),
    }
}

// ==================================================================================================
// Ingest: batched by default (a real gateway batches), with a measured batch=1 control segment
// ==================================================================================================

/// The **batched** ingest statement: one Bolt round-trip and ONE commit for `$rows` readings.
///
/// This is what a real IoT gateway sends — it buffers its devices' samples and flushes them together —
/// and it is the shape whose durability cost the example's headline number should describe. `$ts` is a
/// real PackStream `DateTime` inside the row map, so the temporal wire path is exercised on every batch.
const INGEST_CYPHER_BATCH: &str = "UNWIND $rows AS row \
     MATCH (s:Sensor {id: row.sensor}) \
     CREATE (s)-[:EMITTED]->(:Reading {sensor: row.sensor, seq: row.seq, ts: row.ts, value: row.value})";

/// The **per-reading** ingest statement — one Bolt round-trip and one commit per 32-byte reading.
///
/// The CONTROL. This was the example's only ingest shape, and it is what makes its write amplification
/// so spectacular: a commit is not acknowledged until its redo record is fsynced, so a 32-byte reading
/// drags a whole transaction's redo/undo imaging behind it. The run measures it deliberately, in the
/// same steady state as the batched segment, so the comparison is an observation and not a model.
const INGEST_CYPHER_SINGLE: &str = "MATCH (s:Sensor {id: $sid}) \
     CREATE (s)-[:EMITTED]->(:Reading {sensor: $sid, seq: $seq, ts: $ts, value: $value})";

/// The `$rows` parameter for [`INGEST_CYPHER_BATCH`]: a list of `{sensor, seq, ts, value}` maps, with
/// `ts` a real `DATETIME`.
fn batch_rows_param(rows: &[ReadingRow]) -> Value {
    Value::List(
        rows.iter()
            .map(|r| {
                Value::Map(vec![
                    (
                        "sensor".to_owned(),
                        Value::String(Generator::sensor_id(r.sensor)),
                    ),
                    ("seq".to_owned(), Value::Integer(r.seq as i64)),
                    ("ts".to_owned(), r.ts_value()),
                    ("value".to_owned(), Value::Integer(r.value as i64)),
                ])
            })
            .collect(),
    )
}

/// The parameters for [`INGEST_CYPHER_SINGLE`].
fn single_row_params(r: &ReadingRow) -> Vec<(String, Value)> {
    vec![
        (
            "sid".to_owned(),
            Value::String(Generator::sensor_id(r.sensor)),
        ),
        ("seq".to_owned(), Value::Integer(r.seq as i64)),
        ("ts".to_owned(), r.ts_value()),
        ("value".to_owned(), Value::Integer(r.value as i64)),
    ]
}

/// A batch of readings for one shard's connection to ingest at a given batch size, or the shutdown
/// sentinel.
enum ShardJob {
    Ingest { rows: Vec<ReadingRow>, batch: u64 },
    Stop,
}

/// What a shard reports back after one tick: the per-statement latencies it observed, the commits it
/// made, the readings the SERVER confirmed it created, the retries it paid, or the terminal error that
/// killed it.
struct ShardResult {
    latencies_ns: Vec<u64>,
    commits: u64,
    /// Readings the SERVER reported creating (`nodes-created`), NOT the rows the client sent (`rmp`
    /// #745). See [`ingest_rows`].
    readings_written: u64,
    /// The logical payload of exactly those readings — so the write-amplification denominator describes
    /// the same rows the numerator's WAL does.
    logical_bytes: u64,
    retries: u32,
    error: Option<String>,
}

/// A long-lived ingest worker: owns its own Bolt connection for the whole run (a fresh connection per
/// tick would measure connection setup, not ingest).
struct Shard {
    jobs: mpsc::Sender<ShardJob>,
    results: mpsc::Receiver<ShardResult>,
    join: std::thread::JoinHandle<()>,
}

fn spawn_shard(target: &Target, user: &str, password: &str, db: &str) -> Result<Shard, String> {
    let mut client = target.connect(user, password)?;
    let db = db.to_owned();
    let (job_tx, job_rx) = mpsc::channel::<ShardJob>();
    let (res_tx, res_rx) = mpsc::channel::<ShardResult>();
    let join = std::thread::spawn(move || {
        while let Ok(job) = job_rx.recv() {
            match job {
                ShardJob::Stop => break,
                ShardJob::Ingest { rows, batch } => {
                    let result = ingest_rows(&mut client, &db, &rows, batch);
                    if res_tx.send(result).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = client.goodbye();
    });
    Ok(Shard {
        jobs: job_tx,
        results: res_rx,
        join,
    })
}

/// Ingests `rows` in commits of `batch` readings each, recording one latency per STATEMENT (which is
/// also one per commit). `batch == 1` uses the per-reading statement — the control shape — rather than
/// a one-row `UNWIND`, so the control really is the shape it claims to be.
///
/// # It counts what the SERVER wrote (`rmp` #745)
///
/// The batched statement is `UNWIND $rows AS row MATCH (s:Sensor {id: row.sensor}) CREATE …`, and a row
/// whose `MATCH` finds no sensor is **silently dropped**: the statement still succeeds, and Cypher's
/// semantics say nothing was created for that row. A driver that counted the rows it SENT would then
/// inflate the write-amplification denominator with readings the server never stored — a measurement
/// defect that *looks like an efficiency win*, which is the most dangerous kind.
///
/// So the readings are counted from the SERVER's own `nodes-created` side-effect counter (the trailing
/// `PULL SUCCESS` `stats` map, `rmp` #509), and a disagreement with the batch size is a hard FAILURE, not
/// a silent adjustment: the workload is supposed to reference sensors that exist, so a dropped row means
/// the run is not driving the scenario it claims to be driving.
fn ingest_rows(client: &mut BoltClient, db: &str, rows: &[ReadingRow], batch: u64) -> ShardResult {
    let batch = batch.max(1) as usize;
    let mut latencies_ns = Vec::with_capacity(rows.len().div_ceil(batch));
    let mut commits = 0u64;
    let mut readings_written = 0u64;
    let mut logical_bytes = 0u64;
    let mut retries = 0u32;
    let mut error = None;

    for chunk in rows.chunks(batch) {
        let outcome = if batch == 1 {
            let r = &chunk[0];
            run_retrying_full(client, db, INGEST_CYPHER_SINGLE, single_row_params(r))
        } else {
            run_retrying_full(
                client,
                db,
                INGEST_CYPHER_BATCH,
                vec![("rows".to_owned(), batch_rows_param(chunk))],
            )
        };
        match outcome {
            Ok((lat, tries, result)) => {
                // THE SERVER'S OWN COUNT. `None` means the server reported no `stats` at all, which is
                // NOT the same as zero — it means this instrument cannot see what was written, and an
                // unverifiable denominator is exactly what this check exists to forbid.
                let created = match result.nodes_created() {
                    Some(n) if n == chunk.len() as i64 => n as u64,
                    Some(n) => {
                        error = Some(format!(
                            "the server created {n} :Reading node(s) for a {}-row ingest statement. A \
                             row whose MATCH (s:Sensor {{id: row.sensor}}) finds nothing is SILENTLY \
                             DROPPED by the UNWIND — the statement still succeeds — so the driver would \
                             go on counting {} readings it never stored, inflating the \
                             write-amplification denominator and deflating the ratio. The run is not \
                             driving the workload it claims to be driving",
                            chunk.len(),
                            chunk.len(),
                        ));
                        break;
                    }
                    None => {
                        error = Some(
                            "the server reported no `nodes-created` side-effect counter for an ingest \
                             statement, so the driver CANNOT verify that the readings it sent were the \
                             readings the server stored. Every per-element figure in this example \
                             divides by that count; an unverifiable denominator is not a measurement"
                                .to_owned(),
                        );
                        break;
                    }
                };
                readings_written += created;
                logical_bytes += chunk.iter().map(logical_reading_bytes).sum::<u64>();
                latencies_ns.push(lat.as_nanos() as u64);
                commits += 1;
                retries += tries;
            }
            Err(e) => {
                error = Some(e);
                break;
            }
        }
    }
    ShardResult {
        latencies_ns,
        commits,
        readings_written,
        logical_bytes,
        retries,
        error,
    }
}

// ==================================================================================================
// The concurrent READ mix, gated against the generator's ground truth (`rmp` #745)
// ==================================================================================================

/// The three read families the mix drives, round-robin. Each exercises a different index and is gated
/// against the generator's own stream — never merely counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    /// Leading `sensor` equality + a `seq` range: the composite `Reading(sensor, seq)` index.
    Windowed,
    /// The same window, aggregated: `count` / `min` / `max` / `sum` per sensor.
    Aggregate,
    /// A **temporal** window: `ts ∈ [t0, t1)` over the `Reading.ts` RANGE index (`rmp` #745).
    Temporal,
}

impl Family {
    const ALL: [Self; 3] = [Self::Windowed, Self::Aggregate, Self::Temporal];

    fn name(self) -> &'static str {
        match self {
            Self::Windowed => "windowed-composite",
            Self::Aggregate => "per-sensor-aggregate",
            Self::Temporal => "temporal-window",
        }
    }

    fn cypher(self) -> &'static str {
        match self {
            Self::Windowed => {
                "MATCH (r:Reading) WHERE r.sensor = $sid AND r.seq >= $lo AND r.seq < $hi \
                 RETURN r.sensor AS sensor, r.seq AS seq, r.ts AS ts, r.value AS value"
            }
            Self::Aggregate => {
                "MATCH (r:Reading) WHERE r.sensor = $sid AND r.seq >= $lo AND r.seq < $hi \
                 RETURN count(r) AS n, min(r.seq) AS lo, max(r.seq) AS hi, sum(r.value) AS total"
            }
            Self::Temporal => {
                "MATCH (r:Reading) WHERE r.ts >= $t0 AND r.ts < $t1 \
                 RETURN r.sensor AS sensor, r.seq AS seq, r.ts AS ts, r.value AS value"
            }
        }
    }
}

/// What the writers publish for the readers to reason about — the two moving frontiers of the live band.
///
/// The retention window slides *under* the readers, so a naive "the query must return exactly the
/// generated rows" gate would be flaky by construction. These two atomics make it sound instead, and the
/// ORDER in which they are published is the whole trick:
///
/// * [`ingested_through`](Self::ingested_through) is published **after** a tick's ingest has fully
///   drained, so a reader that loads it **before** issuing its query knows every reading below it was
///   *committed before the query started* — and is therefore in the query's snapshot.
/// * [`cutoff_upper`](Self::cutoff_upper) is published **before** the retention `DELETE` runs, so it is
///   an *upper bound* on what may have been deleted at any instant. A reader that loads it **after** its
///   query returned knows nothing at or above it can have been deleted while the query was in flight.
///
/// Publish them the other way round and the gate becomes a race: a delete that commits between the
/// query's snapshot and the reader's load of the atomic would make the reader demand rows the server has
/// correctly removed.
struct Progress {
    /// Every reading with `seq <` this has been COMMITTED (published after each tick's ingest barrier).
    ingested_through: AtomicU64,
    /// Nothing with `seq >=` this has been DELETED (published *before* each retention `DELETE`).
    cutoff_upper: AtomicU64,
    /// Set when the churn loop finishes; the readers drain and exit.
    stop: AtomicBool,
}

/// The immutable oracle + knobs every reader thread shares.
struct ReaderCtx {
    readings: Vec<ReadingRow>,
    progress: Progress,
    sensors: u64,
    rate: u64,
    window: u64,
}

/// One reader family's running tally inside a worker.
#[derive(Default)]
struct FamilyTally {
    queries: u64,
    exact_gated: u64,
    bounded_gated: u64,
    rows_returned: u64,
    rows_verified: u64,
    mismatches: u64,
    empty_but_expected: u64,
    latencies_ns: Vec<u64>,
    failures: Vec<String>,
}

impl FamilyTally {
    fn fail(&mut self, msg: String) {
        self.mismatches += 1;
        if self.failures.len() < MAX_FAILURE_SAMPLES {
            self.failures.push(msg);
        }
    }

    fn merge(&mut self, other: Self) {
        self.queries += other.queries;
        self.exact_gated += other.exact_gated;
        self.bounded_gated += other.bounded_gated;
        self.rows_returned += other.rows_returned;
        self.rows_verified += other.rows_verified;
        self.mismatches += other.mismatches;
        self.empty_but_expected += other.empty_but_expected;
        self.latencies_ns.extend(other.latencies_ns);
        for f in other.failures {
            if self.failures.len() < MAX_FAILURE_SAMPLES {
                self.failures.push(f);
            }
        }
    }
}

/// What one reader worker brings home.
#[derive(Default)]
struct ReaderResult {
    per_family: [FamilyTally; 3],
    errors: u64,
    error_samples: Vec<String>,
}

/// The `(sensor, seq, ts, value)` row shape both row-returning families use, checked field by field
/// against the generator's ground truth.
///
/// **Every** field is compared, and the timestamp is compared as a *temporal value* — not as an epoch
/// integer the client re-derived — so a server that lost the zone, shifted the offset, or truncated the
/// instant fails here. This is the check the example did not have: every read was a `count(…)`, so a
/// corrupted payload passed green (`rmp` #745).
fn check_payload_row(row: &[Value], expected: &ReadingRow) -> Result<(), String> {
    if row.len() < 4 {
        return Err(format!(
            "seq {}: expected 4 columns (sensor, seq, ts, value), got {} — {row:?}",
            expected.seq,
            row.len()
        ));
    }
    let want_sensor = Generator::sensor_id(expected.sensor);
    match &row[0] {
        Value::String(s) if *s == want_sensor => {}
        other => {
            return Err(format!(
                "seq {}: stored sensor={other:?}, generated sensor={want_sensor:?}",
                expected.seq
            ));
        }
    }
    match &row[1] {
        Value::Integer(n) if *n == expected.seq as i64 => {}
        other => {
            return Err(format!(
                "seq {}: stored seq={other:?}, generated seq={}",
                expected.seq, expected.seq
            ));
        }
    }
    let want_ts = expected.ts_value();
    if row[2] != want_ts {
        return Err(format!(
            "seq {}: stored ts={:?}, generated ts={want_ts:?} — the temporal did NOT round-trip",
            expected.seq, row[2]
        ));
    }
    match &row[3] {
        Value::Integer(n) if *n == expected.value as i64 => {}
        other => {
            return Err(format!(
                "seq {}: stored value={other:?}, generated value={}",
                expected.seq, expected.value
            ));
        }
    }
    Ok(())
}

/// The `seq` cell of a payload row (column 1).
fn row_seq(row: &[Value]) -> Option<u64> {
    match row.get(1) {
        Some(Value::Integer(n)) if *n >= 0 => Some(*n as u64),
        _ => None,
    }
}

/// Reads an integer-ish aggregate cell (`count` / `min` / `max` / `sum`); `sum` may legitimately come
/// back as a float, and a `min`/`max` over an empty set is `null`.
fn agg_int(row: &[Value], i: usize) -> Option<i64> {
    match row.get(i) {
        Some(Value::Integer(n)) => Some(*n),
        Some(Value::Float(f)) => Some(*f as i64),
        _ => None,
    }
}

/// Gates ONE row-returning query (the `windowed-composite` and `temporal-window` families) against the
/// generator's stream, using the two-sided bound that stays sound while retention slides underneath.
///
/// * `returned ⊆ generated[lo, hi)` — every row the server produced must be a row the generator produced,
///   with **every field** equal. A row that is not in the window at all, or whose payload differs, fails.
/// * `returned ⊇ generated[max(lo, cutoff_after), hi)` — every reading that was committed before the
///   query started (`hi <= ingested_through` at issue time) and that no retention `DELETE` could have
///   removed by the time the query returned (`seq >= cutoff_upper` after it) **must** be there. A missing
///   one is row loss.
///
/// When `lo >= cutoff_after` the two bounds coincide and the gate is an **exact set equality** — the
/// strongest form, and the one the reader gate demands a floor of.
fn gate_rows(
    tally: &mut FamilyTally,
    rows: &[Vec<Value>],
    expected: &[ReadingRow],
    lo: u64,
    cutoff_after: u64,
) {
    // The subset half: every returned row must be a generated row, field for field.
    let by_seq: BTreeMap<u64, &ReadingRow> = expected.iter().map(|r| (r.seq, r)).collect();
    for row in rows {
        tally.rows_returned += 1;
        let Some(seq) = row_seq(row) else {
            tally.fail(format!("a row with no readable `seq` column: {row:?}"));
            continue;
        };
        match by_seq.get(&seq) {
            None => tally.fail(format!(
                "the server returned seq {seq}, which the generator never emitted into this window \
                 (sensor/seq predicate violated, or a row from another sensor leaked in)"
            )),
            Some(want) => match check_payload_row(row, want) {
                Ok(()) => tally.rows_verified += 1,
                Err(e) => tally.fail(e),
            },
        }
    }

    // The superset half: everything provably still live must have come back.
    let returned: std::collections::BTreeSet<u64> =
        rows.iter().filter_map(|r| row_seq(r)).collect();
    let must_be_live: Vec<u64> = expected
        .iter()
        .filter(|r| r.seq >= cutoff_after)
        .map(|r| r.seq)
        .collect();
    let missing: Vec<u64> = must_be_live
        .iter()
        .copied()
        .filter(|s| !returned.contains(s))
        .collect();

    if !missing.is_empty() {
        if returned.is_empty() {
            // THE `rmp` #738 SIGNATURE: not "some rows are missing" but "the whole result is empty",
            // while rows provably existed. An index that returns Some(empty) instead of declining looks
            // exactly like this, and no count-only check can see it.
            tally.empty_but_expected += 1;
            if tally.failures.len() < MAX_FAILURE_SAMPLES {
                tally.failures.push(format!(
                    "EMPTY RESULT where {} row(s) provably existed (seq {:?}..): the query returned \
                     nothing while readings committed before it started, and deleted by nothing, were \
                     live — the signature of an index silently answering with an empty set (rmp #738)",
                    must_be_live.len(),
                    must_be_live.first(),
                ));
            }
        } else {
            tally.fail(format!(
                "{} provably-live reading(s) were NOT returned (first missing seq {:?}) — row loss",
                missing.len(),
                missing.first(),
            ));
        }
    }

    if lo >= cutoff_after {
        tally.exact_gated += 1;
    } else {
        tally.bounded_gated += 1;
    }
}

/// Gates ONE aggregation query. In the exact case (`lo >= cutoff_after`) every aggregate is compared to
/// the generator's own `count` / `min` / `max` / `sum`; when the window straddles the retention frontier
/// the aggregates are held to the sound band between "only the provably-live readings" and "every
/// generated reading in the window" — tight enough to catch a wrong answer, loose enough never to flake.
fn gate_aggregate(
    tally: &mut FamilyTally,
    rows: &[Vec<Value>],
    expected: &[ReadingRow],
    lo: u64,
    hi: u64,
    cutoff_after: u64,
) {
    let Some(row) = rows.first() else {
        tally.fail(
            "the aggregation returned NO row at all (an aggregate always yields one)".to_owned(),
        );
        return;
    };
    tally.rows_returned += 1;

    let live: Vec<&ReadingRow> = expected.iter().filter(|r| r.seq >= cutoff_after).collect();
    let (n_lo, n_hi) = (live.len() as i64, expected.len() as i64);
    let sum_lo: i64 = live.iter().map(|r| r.value as i64).sum();
    let sum_hi: i64 = expected.iter().map(|r| r.value as i64).sum();

    let Some(n) = agg_int(row, 0) else {
        tally.fail(format!("count(r) is not an integer: {:?}", row.first()));
        return;
    };
    if n < n_lo || n > n_hi {
        if n == 0 && n_lo > 0 {
            tally.empty_but_expected += 1;
            if tally.failures.len() < MAX_FAILURE_SAMPLES {
                tally.failures.push(format!(
                    "count(r) = 0 while {n_lo} reading(s) provably existed in seq [{lo}, {hi}) — the \
                     rmp #738 signature (an index answering with an empty set instead of declining)"
                ));
            }
        } else {
            tally.fail(format!(
                "count(r) = {n} is outside the sound band [{n_lo}, {n_hi}] for seq [{lo}, {hi})"
            ));
        }
        return;
    }
    tally.rows_verified += 1;

    // min / max must lie inside the requested window (an index that widened the range shows up here).
    if n > 0 {
        match (agg_int(row, 1), agg_int(row, 2)) {
            (Some(min), Some(max)) => {
                if min < lo as i64 || max >= hi as i64 || min > max {
                    tally.fail(format!(
                        "min/max seq = {min}/{max} escapes the requested window [{lo}, {hi})"
                    ));
                    return;
                }
                if lo >= cutoff_after {
                    // Exact: the aggregates must equal the generator's own, to the last unit.
                    let want_min = expected.first().map_or(0, |r| r.seq as i64);
                    let want_max = expected.last().map_or(0, |r| r.seq as i64);
                    if n != n_hi || min != want_min || max != want_max {
                        tally.fail(format!(
                            "exact window [{lo}, {hi}): count/min/max = {n}/{min}/{max}, generated \
                             {n_hi}/{want_min}/{want_max}"
                        ));
                        return;
                    }
                }
            }
            _ => {
                tally.fail(format!(
                    "min/max are not integers over a non-empty aggregate: {row:?}"
                ));
                return;
            }
        }
    }

    match agg_int(row, 3) {
        Some(total) if total >= sum_lo && total <= sum_hi => {
            if lo >= cutoff_after && total != sum_hi {
                tally.fail(format!(
                    "exact window [{lo}, {hi}): sum(r.value) = {total}, generated {sum_hi}"
                ));
                return;
            }
        }
        Some(total) => {
            tally.fail(format!(
                "sum(r.value) = {total} is outside the sound band [{sum_lo}, {sum_hi}] for seq \
                 [{lo}, {hi})"
            ));
            return;
        }
        None if n == 0 => {}
        None => {
            tally.fail(format!("sum(r.value) is not a number: {:?}", row.get(3)));
            return;
        }
    }

    if lo >= cutoff_after {
        tally.exact_gated += 1;
    } else {
        tally.bounded_gated += 1;
    }
}

/// Picks the `seq` window a reader will query, given the two published frontiers — or `None` when the
/// live band is not yet wide enough to carve a window out of (the run's first few ticks).
///
/// The window is anchored at the top of the committed frontier and is `window / 2` wide, which on the
/// default profile leaves ~2 ticks of retention headroom below it. That headroom is what makes the
/// EXACT gate the common case rather than the lucky one — but nothing depends on it: the returned
/// `(lo, hi)` is gated soundly either way, and the reader gate demands a *floor* of exact gates so a
/// profile that made them impossible would fail loudly instead of silently weakening.
fn pick_window(ingested_through: u64, cutoff: u64, window: u64, rate: u64) -> Option<(u64, u64)> {
    let hi = ingested_through;
    let span = (window / 2).max(rate);
    let lo = hi.checked_sub(span)?;
    // Keep the window clear of the retention frontier by one tick's worth of readings.
    let floor = cutoff.saturating_add(rate);
    let lo = lo.max(floor);
    (lo + rate <= hi).then_some((lo, hi))
}

/// One reader worker: its own Bolt connection, driving the three families round-robin against the live
/// database WHILE the writers churn, and gating every result against the generator's stream.
fn reader_worker(id: u64, mut client: BoltClient, db: &str, ctx: &Arc<ReaderCtx>) -> ReaderResult {
    let mut out = ReaderResult::default();
    let mut round = id; // stagger the families across workers

    while !ctx.progress.stop.load(Ordering::Acquire) {
        // Load the committed frontier BEFORE issuing the query: everything below it is in the query's
        // snapshot by construction.
        let ingested = ctx.progress.ingested_through.load(Ordering::Acquire);
        let cutoff_before = ctx.progress.cutoff_upper.load(Ordering::Acquire);
        let Some((lo, hi)) = pick_window(ingested, cutoff_before, ctx.window, ctx.rate) else {
            std::thread::sleep(Duration::from_millis(5));
            continue;
        };

        let family = Family::ALL[(round % 3) as usize];
        let sensor = (round / 3) % ctx.sensors.max(1);
        round = round.wrapping_add(1);

        let params: Vec<(String, Value)> = match family {
            Family::Windowed | Family::Aggregate => vec![
                (
                    "sid".to_owned(),
                    Value::String(Generator::sensor_id(sensor)),
                ),
                ("lo".to_owned(), Value::Integer(lo as i64)),
                ("hi".to_owned(), Value::Integer(hi as i64)),
            ],
            // The temporal window is the SAME window expressed as instants: `ts` is strictly increasing
            // in `seq`, so `[ts_of(lo), ts_of(hi))` selects exactly the readings of `[lo, hi)`. The
            // bounds go over the wire as real PackStream `DateTime`s.
            Family::Temporal => vec![
                ("t0".to_owned(), ts_param(Generator::ts_millis_of(lo))),
                ("t1".to_owned(), ts_param(Generator::ts_millis_of(hi))),
            ],
        };

        let started = Instant::now();
        let outcome = run_retrying(&mut client, db, family.cypher(), params);
        let elapsed = started.elapsed();

        // Load the deletion frontier AFTER the query returned: nothing at or above it can have been
        // deleted while the query was in flight.
        let cutoff_after = ctx.progress.cutoff_upper.load(Ordering::Acquire);

        let tally = &mut out.per_family[Family::ALL.iter().position(|f| *f == family).unwrap_or(0)];
        match outcome {
            Err(e) => {
                out.errors += 1;
                if out.error_samples.len() < MAX_FAILURE_SAMPLES {
                    out.error_samples.push(e);
                }
            }
            Ok((_, _, rows)) => {
                tally.queries += 1;
                tally.latencies_ns.push(elapsed.as_nanos() as u64);
                let sensor_filter = match family {
                    Family::Temporal => None, // the temporal window spans the whole fleet
                    _ => Some(sensor),
                };
                let expected = expected_window(&ctx.readings, sensor_filter, lo, hi);
                match family {
                    Family::Aggregate => {
                        gate_aggregate(tally, &rows, &expected, lo, hi, cutoff_after);
                    }
                    _ => gate_rows(tally, &rows, &expected, lo, cutoff_after),
                }
            }
        }
    }
    let _ = client.goodbye();
    out
}

/// An epoch-ms instant as the `DATETIME` Bolt parameter the temporal window read binds.
fn ts_param(ts_millis: u64) -> Value {
    ReadingRow {
        seq: 0,
        sensor: 0,
        ts_millis,
        value: 0,
    }
    .ts_value()
}

// ==================================================================================================
// The run
// ==================================================================================================

#[allow(clippy::too_many_lines)] // one linear driver: schema -> churn loop -> checks -> samples
fn run() -> Result<bool, String> {
    let args = Args::parse()?;
    let target = args.target()?;
    let db = args.db.clone();

    // THE WAL INSTRUMENT, STARTED BEFORE THE FIRST BYTE (`rmp` #745).
    //
    // It goes up before the schema DDL, not after: the run's TOTAL WAL volume must account for every byte
    // the engine wrote, and `wal_attribution` reconciles those buckets against it exactly. A sampler that
    // started later would leave the bootstrap's WAL unobserved, and the reconciliation would (correctly)
    // fail. The background thread then runs for the whole workload AND through the post-churn checks —
    // whose four deliberately-rejected writes are real transactions that write real WAL.
    let wal_sampler: Option<Arc<WalSampler>> = args
        .db_store_path
        .as_ref()
        .map(|p| Arc::new(WalSampler::new(p.clone(), args.wal_sample_ms)));
    let sampler_thread = wal_sampler.as_ref().map(spawn_wal_sampler);

    let mut control = target.connect(&args.user, &args.password)?;
    eprintln!(
        "iot_wire: connected ({}), database '{}', profile={} sensors={} rate={} window={} ticks={} \
         ingest_clients={} batch={} batch1_control_ticks={} reader_clients={} checkpoint_every={}",
        target.transport().label(),
        db,
        args.profile,
        args.cfg.sensors,
        args.cfg.rate,
        args.cfg.window,
        args.cfg.ticks,
        args.ingest_clients,
        args.batch,
        args.batch1_ticks,
        args.reader_clients,
        args.checkpoint_every,
    );

    // ---- Schema first: every ingest is constraint-checked and index-maintained from the first row. --
    let mut schema_applied = Vec::new();
    let mut schema_skipped = Vec::new();
    let generator = Generator::new(args.cfg.clone());
    for ddl in generator.schema_ddl() {
        match control.run(&ddl, Vec::new(), &db) {
            Ok(_) => schema_applied.push(ddl),
            Err(e) => {
                eprintln!("  schema SKIPPED (target rejected it): {ddl} -> {e}");
                schema_skipped.push(format!("{ddl} -> {e}"));
            }
        }
    }
    // Two indexes the workload's shape depends on: the retention RANGE index on `Reading.seq` (the
    // per-tick aged-out DELETE seeks it) and the temporal RANGE index on `Reading.ts` (the window read
    // this example exists to serve seeks it). Without either, the target cannot drive this scenario
    // honestly, and a "degraded to a scan" run would publish a durability cost for a workload nobody ran.
    for required in ["reading_seq", "reading_ts"] {
        if !schema_applied.iter().any(|d| d.contains(required)) {
            return Err(format!(
                "the target rejected the `{required}` index — this scenario cannot be driven honestly \
                 against it"
            ));
        }
    }

    // ---- The sensor fleet (created once; only readings churn). ----
    for stmt in generator.sensor_cypher() {
        run_retrying(&mut control, &db, &stmt, Vec::new())?;
    }

    // ---- Concurrent ingest shards, one persistent connection each. ----
    let clients = args.ingest_clients.max(1) as usize;
    let mut shards = Vec::with_capacity(clients);
    for _ in 0..clients {
        shards.push(spawn_shard(&target, &args.user, &args.password, &db)?);
    }

    // THE BATCH IS A CAP, AND THE REPORTED BATCH IS THE ONE THAT HAPPENED (`rmp` #745).
    //
    // `--batch N` is what a gateway's flush buffer holds: it commits *up to* N readings at once. Two
    // things stop that cap from being the number a commit actually carries, and BOTH are real:
    //
    //   * a tick is a barrier (the retention `DELETE` must never race the ingest it would conflict
    //     with), so a shard can only flush the readings that tick gave it — at most `rate / clients`;
    //   * the generator assigns readings to sensors from a seeded PRNG, so the shards' per-tick shares
    //     are not equal: one may get 22 readings and the other 28.
    //
    // So the driver keeps the cap (a commit never exceeds it) and REPORTS the mean readings per commit
    // it measured. Publishing the *requested* figure would label a 25-reading commit `batch=50` — a
    // field not carrying the quantity its name promises, which is exactly the evidence defect this task
    // exists to remove. (An earlier cut of this driver chunked at `min(cap, rate/clients)` instead, and
    // the trailing remainder chunks — 25 + 3 — dragged the mean to 17.1. The segment gate's
    // label-honesty rule caught it.)
    let rows_per_shard = args.cfg.rate.div_ceil(clients as u64).max(1);
    if args.batch > rows_per_shard {
        eprintln!(
            "  note: --batch {} is a CAP. A tick gives each shard ~{} readings (rate {} / {} ingest \
             clients) and the tick is a barrier, so a commit carries about that many. The evidence \
             reports the MEASURED mean readings per commit, not the cap.",
            args.batch, rows_per_shard, args.cfg.rate, clients,
        );
    }

    // ---- The churn loop. ----
    //
    // WARMUP — where the growth ramp ends and the plateau claim begins. Getting this right is what makes
    // the plateau assertion honest, so it is DERIVED, not tuned:
    //
    //   * `fill_ticks` — the window must first FILL. Until then nothing has aged out, nothing is deleted,
    //     and the store is simply growing because the data is growing. Nothing to reclaim.
    //   * `+ 2 x checkpoint_every` — and then reclamation must actually have HAPPENED, twice. The store
    //     plateaus because freed record slots go on a free list that later inserts REUSE; that needs (1) a
    //     checkpoint to free the slots the retention DELETE tombstoned, and (2) a further stretch of
    //     ingest to reuse them. One checkpoint is not enough: its freed slots have not been consumed yet,
    //     so the store is still extending. Two is.
    //
    // The in-memory mirror needs no such allowance because it GCs on EVERY tick; the wire run reclaims
    // only when a `CHECKPOINT DATABASE` (or the background cadence) says so, which is precisely the
    // realistic behaviour this driver exists to measure.
    let fill_ticks = args.cfg.window.div_ceil(args.cfg.rate.max(1)) + 1;
    let warmup_ticks = if args.checkpoint_every > 0 {
        fill_ticks + 2 * args.checkpoint_every
    } else {
        // `--checkpoint-every 0`: reclamation is left entirely to the background cadence, which fires on
        // WAL GROWTH (clamp(4 x store_bytes, 8 MiB, 256 MiB)), not on ticks — so its timing cannot be
        // derived from the workload shape at all. Concede that honestly and treat the first third of the
        // run as warmup rather than pretend to a boundary we cannot compute.
        (args.cfg.ticks / 3).max(fill_ticks)
    };
    if warmup_ticks * 2 > args.cfg.ticks {
        return Err(format!(
            "the run is too short to observe a plateau: warmup ends at tick {warmup_ticks} of only {} \
             ticks. Reclamation must have run (and its freed slots been reused) before a flat store means \
             anything. Raise --ticks, or lower --checkpoint-every.",
            args.cfg.ticks
        ));
    }

    // The batch=1 CONTROL segment is the LAST `--batch1-ticks` ticks: same server, same database, same
    // steady state, same retention + checkpoint cadence — only the ingest shape differs. Putting it at
    // the END (rather than at the start, during the growth ramp) is what makes the two segments
    // comparable: a control run while the window was still filling would be measuring a different
    // workload, not a different batch size.
    let control_start_tick = args.cfg.ticks.saturating_sub(args.batch1_ticks);
    if args.batch1_ticks > 0 && control_start_tick <= warmup_ticks {
        return Err(format!(
            "the batch=1 control segment ({} ticks) would start at tick {control_start_tick}, inside the \
             warmup ({warmup_ticks} ticks) — it must run in the STEADY STATE to be comparable with the \
             batched segment. Raise --ticks or lower --batch1-ticks.",
            args.batch1_ticks
        ));
    }

    let mut stream = Generator::new(args.cfg.clone());
    let mut series: Vec<WireTick> = Vec::with_capacity(args.cfg.ticks as usize);
    let mut insert_latencies_ns: Vec<u64> = Vec::new();
    // The batched SEGMENT's own ingest latencies: steady-state statements only, so its `n` matches the
    // ingest-commit count the segment publishes beside it (`insert_latencies_ns` stays the whole run's).
    let mut steady_latencies_ns: Vec<u64> = Vec::new();
    let mut control_latencies_ns: Vec<u64> = Vec::new();
    let mut delete_latencies_ns: Vec<u64> = Vec::new();
    let mut checkpoint_latencies_ns: Vec<u64> = Vec::new();
    // EVERY statement the run issued, in one vector (`rmp` #745).
    //
    // `throughput.operations` counts every statement — batched ingest, per-reading control ingest,
    // retention DELETEs and CHECKPOINTs — so `throughput.p50/p99/p999` must describe that SAME
    // population, or the fields in the block do not describe the same thing and a reader who divides one
    // by another gets a lie. They used to be the batched-ingest family alone (n = 230) sitting beside an
    // `operations` count of 924: percentiles describing ~25% of the operations they were published with,
    // silently excluding the control's 500 per-reading commits (p50 1.79 ms) and 136 deletes. The
    // per-family percentiles are NOT lost — each segment carries its own, and the DELETE and CHECKPOINT
    // families carry theirs — they are simply reported under names that say which family they describe.
    let mut all_statement_latencies_ns: Vec<u64> = Vec::new();
    // Observed WAL-disk reclamation: how many times the on-disk WAL physically shrank, and by how much.
    let mut wal_reclaim_events = 0u64;
    let mut wal_reclaimed_bytes = 0u64;
    let mut total_ingested = 0u64;
    let mut logical_ingested_bytes = 0u64;
    let mut retried_ops = 0u64;
    let mut checkpoints_issued = 0u64;
    let mut ingest_commits = 0u64;
    let mut server_peak_rss: Option<u64> = None;
    // The last retention cutoff applied — every surviving reading must have `seq >= last_cutoff`, which
    // is what proves the DELETE removed the OLD rows and not the wrong ones (rmp #745).
    let mut last_cutoff: u64 = 0;

    // Per-segment accounting (`rmp` #745): the batched main segment and the batch=1 control, each with
    // its OWN measured WAL delta and store growth — the batch=1 number is measured, never modelled.
    // BOTH are measured in STEADY STATE (see the `steady` mark in the churn loop): the growth ramp goes
    // into `warmup_seg`, which is counted in the run's totals but never in the compared segments.
    let mut seg = SegmentAcc::default();
    let mut control_seg = SegmentAcc::default();
    let mut warmup_seg = SegmentAcc::default();
    let mut boundary: Option<StorageMark> = None;
    // The storage counters at the instant the steady state begins — the batched segment's baseline.
    let mut steady: Option<StorageMark> = None;
    let mut steady_started: Option<Instant> = None;
    let mut boundary_elapsed: f64 = 0.0;

    // ---- The concurrent READ mix, live for the whole churn. ----
    let ctx = Arc::new(ReaderCtx {
        readings: generator.all_readings(),
        progress: Progress {
            ingested_through: AtomicU64::new(0),
            cutoff_upper: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        },
        sensors: args.cfg.sensors,
        rate: args.cfg.rate,
        window: args.cfg.window,
    });
    let mut reader_handles = Vec::new();
    for id in 0..args.reader_clients {
        let client = target.connect(&args.user, &args.password)?;
        let ctx = Arc::clone(&ctx);
        let db = db.clone();
        reader_handles.push(std::thread::spawn(move || {
            reader_worker(id, client, &db, &ctx)
        }));
    }

    let cpu_before = args.server_pid.and_then(proc_cpu_secs);
    let io_before = args.server_pid.and_then(proc_write_bytes);
    let workload_started = Instant::now();
    // THE BOOTSTRAP MARK: everything the engine wrote before the churn loop — creating the database,
    // applying the six schema DDL statements, and creating the sensor fleet. It is a real cost and it is
    // published by name (`wal_attribution.bootstrap_bytes`), not silently folded into a segment or left
    // as an unattributed remainder in the run total.
    let bootstrap_mark = wal_mark(&wal_sampler).unwrap_or(0);

    while let Some(t) = stream.tick() {
        let in_control = args.batch1_ticks > 0 && t.tick >= control_start_tick;
        let batch = if in_control { 1 } else { args.batch };

        // The batched segment is measured from the END OF WARMUP — not from tick 0.
        //
        // This is what makes the batch=N vs batch=1 comparison an experiment rather than an anecdote.
        // The batch=1 control runs in pure STEADY STATE: the store has plateaued, and every one of its
        // ticks also pays a retention DELETE. The growth ramp is a DIFFERENT REGIME — the data image is
        // still extending, and until the window first fills NOTHING has aged out, so not one DELETE has
        // run. Charging the batched segment with the ramp and the control with none of it would divide
        // two different workloads into each other and call the quotient "the cost of batching". The two
        // segments now differ in exactly ONE variable — the batch size — which is the only way the ratio
        // between them means what the example says it means.
        if !in_control && steady.is_none() && t.tick >= warmup_ticks {
            steady = wal_sampler.as_deref().map(mark_storage);
            steady_started = Some(Instant::now());
            seg.first_tick = t.tick;
        }

        // At the boundary, freeze the storage counters: everything after belongs to the control segment.
        if in_control && boundary.is_none() {
            boundary = wal_sampler.as_deref().map(mark_storage);
            boundary_elapsed = workload_started.elapsed().as_secs_f64();
            seg.secs = steady_started.map_or(0.0, |s| s.elapsed().as_secs_f64());
            control_seg.first_tick = t.tick;
        }
        let acc = if in_control {
            &mut control_seg
        } else if t.tick >= warmup_ticks {
            &mut seg
        } else {
            // The growth ramp. It is still driven, still ingested, and still counted in the run's
            // TOTALS — it is only excluded from the segment the comparison is made on.
            &mut warmup_seg
        };
        acc.ticks += 1;

        // ---- PHASE MARK: before ingest. --------------------------------------------------------------
        //
        // Four marks bracket the tick's three phases, so the WAL written by INGEST, by RETENTION and by
        // CHECKPOINT is each measured separately and exactly, rather than being lumped into one segment
        // total where the fixed per-tick cost quietly dilutes the batch comparison. Each mark forces a
        // fresh observation; the background sampler covers the gaps between them.
        let m_pre_ingest = wal_mark(&wal_sampler);

        // 1. Ingest this tick's readings, sharded by SENSOR across the concurrent connections. A shard
        //    only ever touches its own sensors, so no two shards contend for the same node.
        let mut per_shard: Vec<Vec<ReadingRow>> = vec![Vec::new(); clients];
        for r in &t.readings {
            per_shard[(r.sensor as usize) % clients].push(*r);
        }
        for (shard, rows) in shards.iter().zip(per_shard) {
            shard
                .jobs
                .send(ShardJob::Ingest { rows, batch })
                .map_err(|_| "an ingest shard died".to_owned())?;
        }
        // Barrier: every shard must finish this tick before the retention DELETE runs, so the DELETE
        // never races the CREATEs it would conflict with.
        for shard in &shards {
            let res = shard
                .results
                .recv()
                .map_err(|_| "an ingest shard died mid-tick".to_owned())?;
            if let Some(e) = res.error {
                return Err(format!("ingest failed: {e}"));
            }
            retried_ops += u64::from(res.retries);
            ingest_commits += res.commits;
            acc.commits += res.commits;
            acc.ingest_commits += res.commits;

            // COUNT WHAT THE SERVER WROTE, NOT WHAT THE CLIENT SENT (`rmp` #745).
            //
            // `readings` is the denominator of every per-element figure this example publishes — write
            // amplification above all — and it must be the number of readings the server actually
            // STORED. The batched `UNWIND $rows AS row MATCH (s:Sensor {id: row.sensor}) CREATE …`
            // silently DROPS any row whose `MATCH` finds nothing: the statement succeeds, and a driver
            // counting rows SENT would inflate the denominator and deflate the amplification — a
            // measurement defect that looks like an improvement. `ShardResult::readings_written` is the
            // SERVER's own `nodes-created` from the trailing PULL SUCCESS (`rmp` #509), and
            // `ingest_rows` fails the run outright if it ever disagrees with the batch size.
            total_ingested += res.readings_written;
            acc.readings += res.readings_written;
            let bytes = res.logical_bytes;
            logical_ingested_bytes += bytes;
            acc.logical_bytes += bytes;

            all_statement_latencies_ns.extend(res.latencies_ns.iter().copied());
            if in_control {
                control_latencies_ns.extend(res.latencies_ns);
            } else {
                // The batched SEGMENT's latency must cover exactly the statements the segment counts —
                // the steady-state ones. A warmup statement folded in here would report an `n` larger
                // than the segment's own ingest-commit count, and would mix the ramp's timings into a
                // percentile the report attributes to steady state.
                if t.tick >= warmup_ticks {
                    steady_latencies_ns.extend(res.latencies_ns.iter().copied());
                }
                insert_latencies_ns.extend(res.latencies_ns);
            }
        }
        // PUBLISH the committed frontier — AFTER the barrier, so a reader that reads it knows every
        // reading below `next_seq` is committed and therefore in its snapshot.
        ctx.progress
            .ingested_through
            .store(t.next_seq, Ordering::Release);

        // ---- PHASE MARK: ingest done, retention not yet run. -----------------------------------------
        let m_post_ingest = wal_mark(&wal_sampler);

        // 2. Retention: delete everything that aged out of the window (an index-backed seek on
        //    Reading.seq), on the control connection.
        if t.delete.is_some() {
            // PUBLISH the deletion frontier BEFORE the DELETE runs: it is an UPPER BOUND on what may
            // have been deleted at any instant, which is exactly what a reader needs to reason soundly
            // about a query that was in flight while this statement committed.
            ctx.progress
                .cutoff_upper
                .store(t.delete_cutoff, Ordering::Release);
            let (lat, tries, _) = run_retrying(
                &mut control,
                &db,
                "MATCH (r:Reading) WHERE r.seq < $cutoff DETACH DELETE r",
                vec![("cutoff".to_owned(), Value::Integer(t.delete_cutoff as i64))],
            )?;
            delete_latencies_ns.push(lat.as_nanos() as u64);
            all_statement_latencies_ns.push(lat.as_nanos() as u64);
            retried_ops += u64::from(tries);
            last_cutoff = t.delete_cutoff;
            acc.commits += 1; // the retention DELETE is a commit too
        }

        // ---- PHASE MARK: retention done, checkpoint not yet run. -------------------------------------
        let m_post_delete = wal_mark(&wal_sampler);

        // 3. The REAL reclamation trigger (`rmp` #305): the `CHECKPOINT DATABASE` admin statement, over
        //    the same wire. (`--checkpoint-every 0` relies on the background cadence alone.)
        let checkpointed = args.checkpoint_every > 0 && (t.tick + 1) % args.checkpoint_every == 0;
        if checkpointed {
            let started = Instant::now();
            control
                .run(&format!("CHECKPOINT DATABASE {db}"), Vec::new(), &db)
                .map_err(|e| format!("CHECKPOINT DATABASE {db}: {e}"))?;
            let lat = started.elapsed().as_nanos() as u64;
            checkpoint_latencies_ns.push(lat);
            all_statement_latencies_ns.push(lat);
            checkpoints_issued += 1;
        }

        // ---- PHASE MARK: the tick's write work is done. ----------------------------------------------
        let m_post_checkpoint = wal_mark(&wal_sampler);

        // Attribute the tick's WAL to the phase that wrote it. Saturating deltas of a MONOTONE counter,
        // so each term is a real, non-negative byte count.
        if let (Some(a), Some(b), Some(c), Some(d)) = (
            m_pre_ingest,
            m_post_ingest,
            m_post_delete,
            m_post_checkpoint,
        ) {
            acc.ingest_wal += b.saturating_sub(a);
            acc.retention_wal += c.saturating_sub(b);
            acc.checkpoint_wal += d.saturating_sub(c);
        }

        // 4. Sample: the live count over the wire, and (locally) the REAL on-disk footprint.
        let live = scalar(&mut control, &db, "MATCH (r:Reading) RETURN count(r) AS c")? as u64;
        let (store_data_bytes, store_bytes, wal_bytes) = match &args.db_store_path {
            Some(path) => {
                let fp = footprint::measure(path);
                (
                    Some(fp.data_bytes),
                    Some(fp.store_bytes()),
                    Some(fp.wal_bytes),
                )
            }
            None => (None, None, None),
        };
        if let Some(pid) = args.server_pid {
            if let Some(rss) = proc_rss_bytes(pid) {
                server_peak_rss = Some(server_peak_rss.map_or(rss, |p: u64| p.max(rss)));
            }
        }

        // A WAL that SHRANK since the previous tick is the one directly-observable proof that a sealed
        // segment was physically deleted and its disk returned. (The maintenance counters cannot show
        // this: they count reclaimed MVCC versions in the STORE, and they climb happily while the WAL
        // frees nothing at all — see `rmp` #706.)
        if let (Some(prev), Some(now)) = (series.last().and_then(|s| s.wal_bytes), wal_bytes) {
            if now < prev {
                wal_reclaim_events += 1;
                wal_reclaimed_bytes += prev - now;
            }
        }
        series.push(WireTick {
            tick: t.tick,
            total_ingested,
            live_readings: live,
            checkpointed,
            batch,
            store_data_bytes,
            store_bytes,
            wal_bytes,
        });
        if t.tick % 10 == 0
            || t.tick + 1 == args.cfg.ticks
            || (in_control && t.tick == control_start_tick)
        {
            eprintln!(
                "  tick {:4}  batch {:3}  ingested {:7}  live {:6}  store {:>10}  wal {:>10}{}",
                t.tick,
                batch,
                total_ingested,
                live,
                store_data_bytes.map_or("n/a".to_owned(), |b| format!("{b}B")),
                wal_bytes.map_or("n/a".to_owned(), |b| format!("{b}B")),
                if checkpointed { "  [CHECKPOINT]" } else { "" },
            );
        }
    }

    let workload = workload_started.elapsed();
    ctx.progress.stop.store(true, Ordering::Release);

    // ---- Shut the ingest shards down (their connections are done). ----
    for shard in &shards {
        let _ = shard.jobs.send(ShardJob::Stop);
    }
    for shard in shards {
        let _ = shard.join.join();
    }

    // ---- Collect the concurrent read mix. ----
    let readers = collect_readers(reader_handles, args.reader_clients, workload.as_secs_f64())?;
    if let Some(r) = &readers {
        eprintln!(
            "  readers: {} queries over {} client(s) — {} rows verified against ground truth, {} \
             mismatch(es), {} empty-but-expected, {} error(s)",
            r.total_queries(),
            r.clients,
            r.total_rows_verified(),
            r.families.iter().map(|f| f.mismatches).sum::<u64>(),
            r.families.iter().map(|f| f.empty_but_expected).sum::<u64>(),
            r.errors,
        );
    }

    // ---- Close the segments' storage accounting. ----
    let end_mark = wal_sampler.as_deref().map(mark_storage);
    // The batched segment's wall-clock runs from the START OF STEADY STATE (not from tick 0), so its
    // throughput describes the same regime its write amplification does. With no control segment it
    // simply runs to the end of the workload.
    if args.batch1_ticks == 0 {
        seg.secs = steady_started.map_or(workload.as_secs_f64(), |s| s.elapsed().as_secs_f64());
        boundary_elapsed = workload.as_secs_f64();
    }
    control_seg.secs = (workload.as_secs_f64() - boundary_elapsed).max(0.0);

    let segments = build_segments(
        &args,
        control_start_tick,
        &seg,
        &control_seg,
        // The batched segment's storage baseline is the STEADY mark, not the run's start mark: the
        // growth ramp's WAL and store growth belong to neither compared segment.
        steady,
        boundary,
        end_mark,
        &steady_latencies_ns,
        &control_latencies_ns,
    );

    // ---- Post-run functional checks over the SAME wire. ----
    let final_live = scalar(&mut control, &db, "MATCH (r:Reading) RETURN count(r) AS c")? as u64;
    let session = Session {
        target: &target,
        user: &args.user,
        password: &args.password,
        db: &db,
    };
    let mut payload_samples_verified = 0u64;
    let checks = wire_checks(
        &mut control,
        &session,
        &args,
        &ctx.readings,
        final_live,
        total_ingested,
        last_cutoff,
        &mut payload_samples_verified,
    )?;
    let checks_failed = checks.iter().filter(|c| !c.ok).count();

    // ---- The LAST WAL mark: after the post-churn functional checks. ----
    //
    // Those checks are not read-only. Four of them deliberately issue writes the schema must REJECT (a
    // duplicate `Sensor.id`, an INTEGER `ts`, a STRING `ts`, a `Reading` with no `value`) — and a
    // rejected write is a transaction that began and aborted, which is durable work. Their WAL is real,
    // and it is published by name (`wal_attribution.post_run_bytes`) rather than left as an unattributed
    // remainder in the run total (it used to be part of the 3.62 MB / 7.3% that did not reconcile).
    //
    // The instrument's work is done: nothing after this point writes WAL that the evidence counts. The
    // sampler takes one FINAL observation as it stops, so the total it reports covers the checks too.
    if let Some(s) = &wal_sampler {
        s.stop.store(true, Ordering::Release);
    }
    if let Some(h) = sampler_thread {
        let _ = h.join();
    }

    // ---- Storage evidence (local only). ----
    let wal_written_total = wal_sampler.as_ref().map_or(0, |s| s.total());
    let storage = args.db_store_path.as_ref().map(|path| {
        let fp: StoreFootprint = footprint::measure(path);
        let post_warmup: Vec<u64> = series
            .iter()
            .filter(|s| s.tick >= warmup_ticks)
            .filter_map(|s| s.store_data_bytes)
            .collect();
        let plateau_min = post_warmup.iter().copied().min().unwrap_or(fp.data_bytes);
        let plateau_max = post_warmup.iter().copied().max().unwrap_or(fp.data_bytes);
        // The PEAK on-disk WAL over the run — the honest worst case. The residual `fp.wal_bytes` alone
        // is misleading: the WAL sawtooths (reclamation frees disk in whole segment units), so the final
        // figure depends on where in the sawtooth the run happened to stop.
        let wal_peak = series
            .iter()
            .filter_map(|s| s.wal_bytes)
            .max()
            .unwrap_or(fp.wal_bytes)
            .max(fp.wal_bytes);
        // The TOTAL durable footprint band (store + WAL) over the post-warmup window — the disk the
        // database actually occupies. The store's own band plateaus; this one does not, and an example
        // that reported only the former would be telling the truth about a component in order to tell a
        // falsehood about the whole (`rmp` #713).
        let post_footprint: Vec<u64> = series
            .iter()
            .filter(|s| s.tick >= warmup_ticks)
            .filter_map(WireTick::durable_bytes)
            .collect();
        let footprint_final = fp.total_bytes();
        let footprint_min = post_footprint
            .iter()
            .copied()
            .min()
            .unwrap_or(footprint_final);
        let footprint_peak = post_footprint
            .iter()
            .copied()
            .max()
            .unwrap_or(footprint_final)
            .max(footprint_final);
        WireStorage {
            data_bytes: fp.data_bytes,
            dwb_bytes: fp.dwb_bytes,
            wal_bytes: fp.wal_bytes,
            wal_peak_bytes: wal_peak,
            other_bytes: fp.other_bytes,
            wal_written_bytes: wal_written_total,
            plateau_min_data_bytes: plateau_min,
            plateau_max_data_bytes: plateau_max,
            plateau_max_data_pages: plateau_max.div_ceil(PAGE_SIZE),
            footprint_min_bytes: footprint_min,
            footprint_peak_bytes: footprint_peak,
            footprint_final_bytes: footprint_final,
            wal_reclaim_events,
            wal_reclaimed_bytes,
            server_io_write_bytes: match (io_before, args.server_pid.and_then(proc_write_bytes)) {
                (Some(b), Some(a)) => Some(a.saturating_sub(b)),
                _ => None,
            },
        }
    });

    let server_cpu_secs = match (cpu_before, args.server_pid.and_then(proc_cpu_secs)) {
        (Some((ub, sb)), Some((ua, sa))) => Some(((ua - ub).max(0.0), (sa - sb).max(0.0))),
        _ => None,
    };

    // ---- EVERY WAL BYTE, ATTRIBUTED TO THE PHASE THAT WROTE IT (`rmp` #745). ----
    //
    // The five buckets partition the run's timeline end to end, so they sum to the total BY
    // CONSTRUCTION — and `WireSamples::instrument_gate` FAILS the run if they ever do not. That is the
    // point: the segments used to be published beside a run total they did not add up to (34.78 + 11.24
    // against 49.65 MB), and the 3.62 MB / 7.3% remainder was exactly where the accounting had lost
    // track. A remainder is not a rounding artefact; it is the shape a measurement defect makes.
    let wal_attribution = wal_sampler.as_ref().map(|_| {
        let steady_wal = steady.map_or(bootstrap_mark, |m| m.wal_written);
        let boundary_wal = boundary.map_or(end_mark.map_or(steady_wal, |m| m.wal_written), |m| {
            m.wal_written
        });
        let end_wal = end_mark.map_or(boundary_wal, |m| m.wal_written);
        WalAttribution {
            bootstrap_bytes: bootstrap_mark,
            warmup_bytes: steady_wal.saturating_sub(bootstrap_mark),
            main_bytes: boundary_wal.saturating_sub(steady_wal),
            control_bytes: end_wal.saturating_sub(boundary_wal),
            post_run_bytes: wal_written_total.saturating_sub(end_wal),
        }
    });
    if let Some(a) = &wal_attribution {
        eprintln!(
            "  WAL attribution: bootstrap {} + warmup {} + main {} + control {} + post-run checks {} = \
             {} B (measured cumulative: {} B){}",
            a.bootstrap_bytes,
            a.warmup_bytes,
            a.main_bytes,
            a.control_bytes,
            a.post_run_bytes,
            a.total(),
            wal_written_total,
            if a.total() == wal_written_total {
                " — RECONCILES"
            } else {
                " — DOES NOT RECONCILE (the gate will fail this run)"
            },
        );
    }

    let samples = WireSamples {
        version: WIRE_SAMPLES_VERSION,
        scenario: args.scenario.clone(),
        transport: target.transport(),
        database: db.clone(),
        local: args.db_store_path.is_some(),
        seed: args.cfg.seed,
        sensors: args.cfg.sensors,
        rate: args.cfg.rate,
        window: args.cfg.window,
        ticks: args.cfg.ticks,
        warmup_ticks,
        ingest_clients: clients as u64,
        checkpoint_every: args.checkpoint_every,
        batch: segments.first().map_or(args.batch, |seg| seg.batch),
        control_batch1_ticks: args.batch1_ticks,
        ticks_series: series,
        total_ingested,
        final_live_readings: final_live,
        checkpoints_issued,
        ingest_ops: ingest_commits,
        delete_ops: delete_latencies_ns.len() as u64,
        retried_ops,
        workload_secs: workload.as_secs_f64(),
        logical_ingested_bytes,
        segments,
        wal_attribution,
        readers,
        payload_samples_verified,
        storage,
        // The percentiles of EVERY statement — the same population `throughput.operations` counts, so
        // the two fields in that block describe the same thing (`rmp` #745). The per-family percentiles
        // live beside them under names that say which family they describe.
        statement_latency: latency(&all_statement_latencies_ns),
        insert_latency: latency(&insert_latencies_ns),
        delete_latency: latency(&delete_latencies_ns),
        checkpoint_latency: latency(&checkpoint_latencies_ns),
        server_cpu_secs,
        server_peak_rss_bytes: server_peak_rss,
        schema_applied,
        schema_skipped,
        checks,
    };

    let json = serde_json::to_string_pretty(&samples)
        .map_err(|e| format!("cannot serialize samples: {e}"))?;
    std::fs::write(&args.samples, json)
        .map_err(|e| format!("cannot write {}: {e}", args.samples.display()))?;
    let _ = control.goodbye();

    eprintln!(
        "iot_wire: {} readings ingested over {:.2}s ({:.0}/s) in {} commits, {} checkpoints issued, {} \
         retries; wrote {}",
        total_ingested,
        workload.as_secs_f64(),
        samples.ingest_per_sec().unwrap_or(0.0),
        ingest_commits,
        checkpoints_issued,
        retried_ops,
        args.samples.display(),
    );
    if checks_failed > 0 {
        eprintln!("iot_wire: {checks_failed} over-the-wire check(s) FAILED (see samples.json)");
        for c in samples.checks.iter().filter(|c| !c.ok) {
            eprintln!("  FAILED — {}: {}", c.name, c.detail);
        }
        return Ok(false);
    }
    println!("GRAPHUS_IOT_WIRE_OK");
    Ok(true)
}

/// Joins the reader workers and folds their tallies into one [`WireReaders`].
fn collect_readers(
    handles: Vec<std::thread::JoinHandle<ReaderResult>>,
    clients: u64,
    secs: f64,
) -> Result<Option<WireReaders>, String> {
    if handles.is_empty() {
        return Ok(None);
    }
    let mut merged: [FamilyTally; 3] = Default::default();
    let mut errors = 0u64;
    let mut error_samples: Vec<String> = Vec::new();
    for h in handles {
        let r = h
            .join()
            .map_err(|_| "a reader thread panicked — the read mix is not trustworthy".to_owned())?;
        errors += r.errors;
        for e in r.error_samples {
            if error_samples.len() < MAX_FAILURE_SAMPLES {
                error_samples.push(e);
            }
        }
        for (dst, src) in merged.iter_mut().zip(r.per_family) {
            dst.merge(src);
        }
    }
    let families = Family::ALL
        .iter()
        .zip(merged)
        .map(|(f, t)| WireReaderFamily {
            name: f.name().to_owned(),
            cypher: f.cypher().to_owned(),
            queries: t.queries,
            exact_gated: t.exact_gated,
            bounded_gated: t.bounded_gated,
            rows_returned: t.rows_returned,
            rows_verified: t.rows_verified,
            mismatches: t.mismatches,
            empty_but_expected: t.empty_but_expected,
            latency: latency(&t.latencies_ns),
            failure_samples: t.failures,
        })
        .collect();
    Ok(Some(WireReaders {
        clients,
        secs,
        errors,
        error_samples,
        families,
    }))
}

/// A running total for one measured ingest segment.
#[derive(Default)]
struct SegmentAcc {
    first_tick: u64,
    ticks: u64,
    readings: u64,
    /// Ingest statements + retention DELETEs — every transaction the segment committed.
    commits: u64,
    /// Just the ingest statements: the denominator of the MEASURED readings-per-commit.
    ingest_commits: u64,
    logical_bytes: u64,
    secs: f64,

    // ---- the WAL bill, split BY PHASE inside the tick (`rmp` #745) ----
    //
    // Both segments pay an identical fixed per-tick cost F — the retention `DETACH DELETE` and the
    // amortised `CHECKPOINT DATABASE` — that batching cannot touch. Left lumped into the segment's total
    // it sits in BOTH numerators of `(50·A₁ + F) / (2·A₂₅ + F)` and drags the ratio toward 1, where it
    // was then mistaken for "the WAL record format". Measured apart, it cancels from the comparison and
    // can be published for what it is.
    /// WAL the INGEST phase wrote: from the start of a tick's ingest to the drain of its barrier.
    ingest_wal: u64,
    /// WAL the retention `DETACH DELETE` wrote.
    retention_wal: u64,
    /// WAL the `CHECKPOINT DATABASE` wrote.
    checkpoint_wal: u64,
}

/// The durable-write counters at one instant: cumulative WAL volume + the data image's length.
#[derive(Debug, Clone, Copy)]
struct StorageMark {
    wal_written: u64,
    data_bytes: u64,
}

/// Takes a FRESH observation and returns the durable-write counters at this instant.
///
/// It forces a synchronous [`WalSampler::sample`] rather than reading whatever the background thread
/// last happened to see, so a phase boundary is marked against the WAL *as it is now*. The background
/// thread's job is to cover the gaps BETWEEN marks, where a segment could otherwise be born, sealed and
/// reclaimed unobserved.
fn mark_storage(sampler: &WalSampler) -> StorageMark {
    sampler.sample();
    StorageMark {
        wal_written: sampler.total(),
        data_bytes: footprint::measure(&sampler.path).data_bytes,
    }
}

/// The cumulative WAL volume at this instant, freshly observed. The phase-boundary primitive: a phase's
/// WAL cost is the difference of two of these.
fn wal_mark(sampler: &Option<Arc<WalSampler>>) -> Option<u64> {
    let s = sampler.as_ref()?;
    s.sample();
    Some(s.total())
}

/// Builds the measured [`WireSegment`]s from the two accumulators and the three storage marks.
#[allow(clippy::too_many_arguments)]
fn build_segments(
    args: &Args,
    control_start_tick: u64,
    main: &SegmentAcc,
    control: &SegmentAcc,
    start: Option<StorageMark>,
    boundary: Option<StorageMark>,
    end: Option<StorageMark>,
    main_latencies_ns: &[u64],
    control_latencies_ns: &[u64],
) -> Vec<WireSegment> {
    // The main segment ends where the control begins (or at the end of the run when there is no control).
    let main_end = boundary.or(end);
    // The reported batch is the one the run MEASURED — mean readings per ingest commit — not the `--batch`
    // cap that bounds it (`rmp` #745). A commit carrying 25 readings must not be labelled `batch=50`.
    let measured_batch = |readings: u64, commits: u64| -> u64 {
        if commits == 0 {
            return 1;
        }
        (readings as f64 / commits as f64).round() as u64
    };
    // The phase totals are only meaningful when the storage was measured at all (attach mode takes no
    // marks), so they travel with the same `Option` as the segment's WAL delta — never a fabricated 0.
    let measured = start.is_some() && main_end.is_some();
    let phase = |v: u64| measured.then_some(v);

    let main_batch = measured_batch(main.readings, main.ingest_commits);
    let mut out = vec![WireSegment {
        label: format!("batch={main_batch} (main)"),
        batch: main_batch,
        batch_cap: args.batch,
        // Where STEADY STATE began — not tick 0. The compared segments must be the same regime.
        first_tick: main.first_tick,
        next_tick: control_start_tick,
        readings: main.readings,
        commits: main.commits,
        ingest_commits: main.ingest_commits,
        logical_bytes: main.logical_bytes,
        wal_written_bytes: delta(start, main_end, |m| m.wal_written),
        ingest_wal_bytes: phase(main.ingest_wal),
        retention_wal_bytes: phase(main.retention_wal),
        checkpoint_wal_bytes: phase(main.checkpoint_wal),
        // The named remainder: WAL written between a tick's last phase mark and the next tick's first
        // (the per-tick live-count query, plus any background maintenance that fired in that gap). Small,
        // and NAMED — the phases must sum to the segment's total, and the gate proves they do.
        other_wal_bytes: delta(start, main_end, |m| m.wal_written).map(|total| {
            total.saturating_sub(main.ingest_wal + main.retention_wal + main.checkpoint_wal)
        }),
        ticks: main.ticks,
        store_growth_bytes: delta(start, main_end, |m| m.data_bytes),
        secs: main.secs,
        ingest_latency: latency(main_latencies_ns),
    }];
    if args.batch1_ticks > 0 && control.readings > 0 {
        let measured = boundary.is_some() && end.is_some();
        let phase = |v: u64| measured.then_some(v);
        out.push(WireSegment {
            label: "batch=1 (control)".to_owned(),
            batch: measured_batch(control.readings, control.ingest_commits),
            batch_cap: 1,
            first_tick: control.first_tick,
            next_tick: args.cfg.ticks,
            readings: control.readings,
            commits: control.commits,
            ingest_commits: control.ingest_commits,
            logical_bytes: control.logical_bytes,
            wal_written_bytes: delta(boundary, end, |m| m.wal_written),
            ingest_wal_bytes: phase(control.ingest_wal),
            retention_wal_bytes: phase(control.retention_wal),
            checkpoint_wal_bytes: phase(control.checkpoint_wal),
            other_wal_bytes: delta(boundary, end, |m| m.wal_written).map(|total| {
                total.saturating_sub(
                    control.ingest_wal + control.retention_wal + control.checkpoint_wal,
                )
            }),
            ticks: control.ticks,
            store_growth_bytes: delta(boundary, end, |m| m.data_bytes),
            secs: control.secs,
            ingest_latency: latency(control_latencies_ns),
        });
    }
    out
}

/// The saturating delta of one storage counter between two marks — `None` when either was not measured
/// (attach mode), never a fabricated `0`.
fn delta(
    from: Option<StorageMark>,
    to: Option<StorageMark>,
    f: impl Fn(&StorageMark) -> u64,
) -> Option<u64> {
    Some(f(&to?).saturating_sub(f(&from?)))
}

/// The logical payload of one reading, in bytes: its four property values (the `sensor` id string plus
/// three 8-byte values — `seq`, the `ts` instant, and `value`). Deliberately *logical* — no record
/// headers, no MVCC version, no index entry, no page slack. Those are exactly the overheads write
/// amplification exists to expose, so counting them in the denominator would flatter the ratio into
/// meaninglessness. (`ts` is now a temporal, but its payload is still one 64-bit instant: the epoch
/// seconds. Counting the zone/offset fields would inflate the denominator and flatter the ratio, so the
/// figure is unchanged and the two ingest shapes stay comparable with every earlier run.)
fn logical_reading_bytes(r: &ReadingRow) -> u64 {
    Generator::sensor_id(r.sensor).len() as u64 + 8 + 8 + 8
}

/// Real latency percentiles for one statement family, or `None` for an empty family (never a zeroed
/// struct that would read like a measurement — `rmp` #699).
fn latency(latencies_ns: &[u64]) -> Option<WireLatency> {
    if latencies_ns.is_empty() {
        return None;
    }
    let mut sorted = latencies_ns.to_vec();
    sorted.sort_unstable();
    Some(WireLatency {
        count: sorted.len() as u64,
        p50_ms: ns_to_ms(percentile_ns(&sorted, 500)),
        p99_ms: ns_to_ms(percentile_ns(&sorted, 990)),
        p999_ms: ns_to_ms(percentile_ns(&sorted, 999)),
    })
}

/// Everything needed to open a fresh Bolt session against the workload's database: the transport, the
/// credentials and the database name. Bundled because they always travel together (and because a
/// function taking six loose `&str`s is a bug waiting to happen).
struct Session<'a> {
    target: &'a Target,
    user: &'a str,
    password: &'a str,
    db: &'a str,
}

impl Session<'_> {
    fn connect(&self) -> Result<BoltClient, String> {
        self.target.connect(self.user, self.password)
    }
}

/// Runs a statement that is EXPECTED to be rejected, on a **fresh** Bolt session, and reports whether
/// the server refused it.
///
/// The fresh session is not incidental. Bolt (`§ Connection states`) puts a connection into `FAILED`
/// after a `FAILURE`, and every subsequent request is answered `IGNORED` until the client sends
/// `RESET` — so a negative check run on the control connection would poison it for everything after.
/// The shared `graphus-reco-gen` client exposes no `RESET`, so each negative check gets its own
/// short-lived connection. (That is also the more honest test: the constraint must reject the write on
/// any session, not only on one that has already seen a failure.)
fn expect_rejected(session: &Session<'_>, stmt: &str) -> Result<(bool, String), String> {
    let mut c = session.connect()?;
    let outcome = c.run(stmt, Vec::new(), session.db);
    let result = match &outcome {
        Err(e) => (true, format!("rejected: {e}")),
        Ok(_) => (
            false,
            "ACCEPTED — the constraint is NOT enforced".to_owned(),
        ),
    };
    // The session is in FAILED state on the expected path; just drop it (GOODBYE would be IGNORED).
    if outcome.is_ok() {
        let _ = c.goodbye();
    }
    Ok(result)
}

/// The post-run functional battery, driven over the same wire: the schema the driver declared must
/// actually be **enforced** and **usable**, not merely accepted — and what the server stored must be
/// what the generator produced, field for field.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn wire_checks(
    control: &mut BoltClient,
    session: &Session<'_>,
    args: &Args,
    readings: &[ReadingRow],
    final_live: u64,
    total_ingested: u64,
    last_cutoff: u64,
    payload_samples_verified: &mut u64,
) -> Result<Vec<WireCheck>, String> {
    let db = session.db;
    let cfg = &args.cfg;
    let mut checks = Vec::new();

    // 1. Steady state: the live count sits in [window, window + rate) — retention is holding the window.
    let lo = cfg.window;
    let hi = cfg.window + cfg.rate;
    checks.push(WireCheck {
        name: "steady-state live :Reading count in [window, window + rate)".to_owned(),
        ok: final_live >= lo && final_live < hi,
        detail: format!("live={final_live}, band=[{lo}, {hi}), total_ingested={total_ingested}"),
    });

    // 1b. Retention deleted the RIGHT rows. A cardinality band alone (check 1) passes even if the DELETE
    //     removed the NEWEST readings instead of the oldest — the count is identical. The retention
    //     predicate is `seq < cutoff`, so AFTER retention NOT ONE reading below the last cutoff may
    //     survive: `count(seq < last_cutoff)` must be 0. A non-zero count means the DELETE removed the
    //     wrong rows (the whole subject of this example) or removed nothing — either FAILS (rmp #745).
    if last_cutoff > 0 {
        let below = scalar(
            control,
            db,
            &format!("MATCH (r:Reading) WHERE r.seq < {last_cutoff} RETURN count(r) AS c"),
        )? as u64;
        checks.push(WireCheck {
            name: "retention removed the OLDEST readings (nothing below the last cutoff survives)"
                .to_owned(),
            ok: below == 0,
            detail: format!("readings with seq < last_cutoff({last_cutoff}) still live = {below}"),
        });
        // …and the survivors ARE the retained tail: the minimum live seq is at or above the cutoff.
        let min_seq = scalar(control, db, "MATCH (r:Reading) RETURN min(r.seq) AS c")?;
        checks.push(WireCheck {
            name: "the live seq window is the retained tail (min live seq >= last cutoff)"
                .to_owned(),
            ok: min_seq >= last_cutoff as i64,
            detail: format!("min_live_seq={min_seq}, last_cutoff={last_cutoff}"),
        });
    }

    // 1c. THE PAYLOAD READ-BACK (`rmp` #745). Every read in this example used to be a `count(…)`, so a
    //     corrupted, transposed or truncated property value passed GREEN. Here a deterministic sample of
    //     the SURVIVING readings is read back in full and compared, field by field, against the value the
    //     generator produced for that `seq` — including `ts`, compared as a real temporal, so a value the
    //     Bolt temporal path mangled fails here rather than being silently re-derived by the client.
    let (verified, attempted, payload_detail) = verify_payloads(
        control,
        db,
        readings,
        last_cutoff,
        cfg,
        args.payload_samples,
    )?;
    *payload_samples_verified = verified;
    checks.push(WireCheck {
        name: "surviving readings' payloads match the generator's ground truth EXACTLY (sensor, seq, ts, value)"
            .to_owned(),
        ok: attempted > 0 && verified == attempted && payload_detail.is_empty(),
        detail: if payload_detail.is_empty() {
            format!(
                "{verified} of {attempted} surviving readings read back over the wire ({}); every \
                 (sensor, seq, ts, value) field equals the generated one (ts compared as a DATETIME, \
                 not as an epoch integer)",
                if args.payload_samples == 0 {
                    "EVERY reading in the retained band"
                } else {
                    "a deterministic stride across the retained band"
                }
            )
        } else {
            format!("{verified} of {attempted} verified, then: {payload_detail}")
        },
    });

    // 1d. NO ORPHAN `:EMITTED` SURVIVES RETENTION. A `DETACH DELETE`d reading must take its incident
    //     relationship with it: a dangling edge is silent corruption that every `count(:Reading)` check
    //     in this example would have passed straight over. Three independent counts pin it:
    //       * every `:EMITTED` in the graph, from any node to any node;
    //       * every `:EMITTED` that actually runs Sensor -> Reading;
    //       * the distinct live readings reachable through one.
    //     All three must equal the live reading count: no edge left behind, and every live reading has
    //     exactly one incident `:EMITTED`.
    let edges_all = scalar(control, db, "MATCH ()-[e:EMITTED]->() RETURN count(e) AS c")? as u64;
    let edges_sr = scalar(
        control,
        db,
        "MATCH (:Sensor)-[e:EMITTED]->(:Reading) RETURN count(e) AS c",
    )? as u64;
    let readings_with_edge = scalar(
        control,
        db,
        "MATCH (:Sensor)-[:EMITTED]->(r:Reading) RETURN count(DISTINCT r) AS c",
    )? as u64;
    checks.push(WireCheck {
        name: "no orphan :EMITTED survives retention (edges == live readings, each with exactly one)"
            .to_owned(),
        ok: edges_all == final_live && edges_sr == final_live && readings_with_edge == final_live,
        detail: format!(
            ":EMITTED total={edges_all}, Sensor->Reading={edges_sr}, distinct live readings with an \
             incident edge={readings_with_edge}, live readings={final_live}"
        ),
    });

    // 2. POINT index: sensors within SITE_RADIUS of site 0's centre are EXACTLY the site-0 sensors —
    //    a known ground truth (the generator clusters the fleet on a 2x2 grid far wider than the radius).
    let near = scalar(
        control,
        db,
        &format!(
            "MATCH (s:Sensor) WHERE point.distance(s.location, point({{x: 0, y: 0}})) <= {SITE_RADIUS} \
             RETURN count(s) AS c"
        ),
    )?;
    let expected_site0 = cfg.sensors.div_ceil(4) as i64;
    checks.push(WireCheck {
        name: "POINT (spatial) proximity returns exactly site 0's sensors".to_owned(),
        ok: near == expected_site0,
        detail: format!("near_site0={near}, expected={expected_site0}"),
    });

    // 3. Composite RANGE index: the per-sensor windowed read (leading `sensor` equality + a `seq`
    //    range) must agree with the :EMITTED traversal — a self-validating cross-check, since a
    //    reading's `sensor` property equals its emitter's id by construction.
    let by_prop = scalar(
        control,
        db,
        "MATCH (r:Reading) WHERE r.sensor = 's-0' RETURN count(r) AS c",
    )?;
    let by_edge = scalar(
        control,
        db,
        "MATCH (:Sensor {id: 's-0'})-[:EMITTED]->(r:Reading) RETURN count(r) AS c",
    )?;
    checks.push(WireCheck {
        name: "composite windowed read agrees with the :EMITTED traversal".to_owned(),
        ok: by_prop == by_edge && by_prop > 0,
        detail: format!("by_property={by_prop}, by_traversal={by_edge}"),
    });

    // 3b. THE TEMPORAL WINDOW READ (`rmp` #745) — the query a time-series database exists to serve, over
    //     a REAL `DATETIME` property and its RANGE index, with its `[t0, t1)` bounds bound as real
    //     PackStream temporals. Gated against ground truth, not counted: `ts` is strictly increasing in
    //     `seq`, so the readings in `[ts_of(lo), ts_of(hi))` are EXACTLY those the generator emitted with
    //     `seq ∈ [lo, hi)` — an oracle the temporal path itself never touches. An empty result where rows
    //     exist is the `rmp` #738 signature and FAILS.
    let (t_lo, t_hi) = temporal_check_window(last_cutoff, cfg);
    let expected: Vec<ReadingRow> = expected_window(readings, None, t_lo, t_hi);
    let (_, _, rows) = run_retrying(
        control,
        db,
        "MATCH (r:Reading) WHERE r.ts >= $t0 AND r.ts < $t1 \
         RETURN r.sensor AS sensor, r.seq AS seq, r.ts AS ts, r.value AS value",
        vec![
            ("t0".to_owned(), ts_param(Generator::ts_millis_of(t_lo))),
            ("t1".to_owned(), ts_param(Generator::ts_millis_of(t_hi))),
        ],
    )?;
    let mut tally = FamilyTally::default();
    // The churn is over and nothing deletes any more, so `cutoff_after` is simply the last cutoff: the
    // gate is an EXACT set equality over a window entirely inside the retained band.
    gate_rows(&mut tally, &rows, &expected, t_lo, last_cutoff);
    checks.push(WireCheck {
        name: "temporal window read (ts IN [t0, t1), a real DATETIME range) returns EXACTLY the generated readings"
            .to_owned(),
        ok: tally.mismatches == 0
            && tally.empty_but_expected == 0
            && !expected.is_empty()
            && tally.rows_verified == expected.len() as u64,
        detail: format!(
            "seq window [{t_lo}, {t_hi}) = ts [{}, {}); expected {} readings, server returned {}, \
             verified {} field-by-field, {} mismatch(es), {} empty-but-expected{}",
            Generator::ts_millis_of(t_lo),
            Generator::ts_millis_of(t_hi),
            expected.len(),
            rows.len(),
            tally.rows_verified,
            tally.mismatches,
            tally.empty_but_expected,
            if tally.failures.is_empty() {
                String::new()
            } else {
                format!(" — {}", tally.failures.join("; "))
            }
        ),
    });

    // 4. NODE KEY enforcement: a duplicate Sensor.id must be REJECTED over the wire, and must leave the
    //    fleet untouched (a rejected write creates nothing — atomicity).
    let (dup_rejected, dup_detail) = expect_rejected(
        session,
        "CREATE (:Sensor {id: 's-0', kind: 'temperature', site: 0, location: point({x: 0, y: 0})})",
    )?;
    let sensors_now = scalar(control, db, "MATCH (s:Sensor) RETURN count(s) AS c")?;
    checks.push(WireCheck {
        name: "duplicate Sensor.id rejected (NODE KEY) and nothing created".to_owned(),
        ok: dup_rejected && sensors_now == cfg.sensors as i64,
        detail: format!(
            "{dup_detail}; sensors={sensors_now} (expected {})",
            cfg.sensors
        ),
    });

    // 5. Property-type constraint (`rmp` #745): `Reading.ts IS :: ZONED DATETIME`, so a bare epoch-ms
    //    INTEGER `ts` must now be REJECTED — the exact inverse of the old schema, which forbade the
    //    temporal and accepted the integer. This is what keeps the temporal type meaningful: without it,
    //    an ingest that silently degraded to integers would pass every other check in this file.
    let (int_ts_rejected, int_ts_detail) = expect_rejected(
        session,
        "MATCH (s:Sensor {id: 's-0'}) CREATE (s)-[:EMITTED]->(:Reading {sensor: 's-0', seq: -1, ts: 1704067200000, value: 1})",
    )?;
    checks.push(WireCheck {
        name:
            "an INTEGER Reading.ts is rejected (property-type constraint: ts IS :: ZONED DATETIME)"
                .to_owned(),
        ok: int_ts_rejected,
        detail: int_ts_detail,
    });

    // 5b. …and so is a string. (Two different wrong types, so the constraint is not merely rejecting
    //     one accidental shape.)
    let (str_ts_rejected, str_ts_detail) = expect_rejected(
        session,
        "MATCH (s:Sensor {id: 's-0'}) CREATE (s)-[:EMITTED]->(:Reading {sensor: 's-0', seq: -2, ts: 'noon', value: 1})",
    )?;
    checks.push(WireCheck {
        name: "a STRING Reading.ts is rejected (property-type constraint)".to_owned(),
        ok: str_ts_rejected,
        detail: str_ts_detail,
    });

    // 6. Existence constraint: a Reading with no `value` must be REJECTED. Its `ts` is a VALID temporal,
    //    so the rejection can only be the existence constraint.
    let (val_rejected, val_detail) = expect_rejected(
        session,
        "MATCH (s:Sensor {id: 's-0'}) CREATE (s)-[:EMITTED]->(:Reading {sensor: 's-0', seq: -3, ts: datetime({epochMillis: 1704067200000})})",
    )?;
    checks.push(WireCheck {
        name: "Reading without a `value` rejected (existence constraint)".to_owned(),
        ok: val_rejected,
        detail: val_detail,
    });

    // 6b. And the rejected writes really did create NOTHING: the live count is untouched (atomicity of
    //     a constraint-violating statement — a rejected write must leave no debris behind).
    let live_after_rejections =
        scalar(control, db, "MATCH (r:Reading) RETURN count(r) AS c")? as u64;
    checks.push(WireCheck {
        name: "the four rejected writes created nothing (atomicity)".to_owned(),
        ok: live_after_rejections == final_live,
        detail: format!("live before={final_live}, after the rejections={live_after_rejections}"),
    });

    // 7. The declared schema is visible to the operator (SHOW INDEXES / SHOW CONSTRAINTS).
    let (_, _, idx) = run_retrying(
        control,
        db,
        "SHOW INDEXES YIELD name, type, entityType, state RETURN name, type, entityType, state",
        Vec::new(),
    )?;
    let (_, _, cons) = run_retrying(
        control,
        db,
        "SHOW CONSTRAINTS YIELD name, type, entityType RETURN name, type, entityType",
        Vec::new(),
    )?;
    // Verify the declared schema BY NAME, BY TYPE, and — for indexes — that it is actually ONLINE. Not
    // merely that "at least 3" rows exist: a count-only check passed even if a #694 index were stuck
    // Populating (it is still a row). And name+state alone still passed if a RANGE index had been
    // silently created as some OTHER kind (`rmp` #745), which would quietly change every seek in the
    // workload into something else. SHOW INDEXES columns are (name, type, entityType, state); SHOW
    // CONSTRAINTS (name, type, entityType).
    let schema_gaps = declared_schema_gaps(&idx, &cons);
    checks.push(WireCheck {
        name: "every declared index/constraint is present by NAME and TYPE, and every index is ONLINE"
            .to_owned(),
        ok: schema_gaps.is_empty(),
        detail: if schema_gaps.is_empty() {
            format!(
                "{} indexes ONLINE with the declared type + {} constraints present with the declared \
                 type (by name)",
                EXPECTED_INDEXES.len(),
                EXPECTED_CONSTRAINTS.len()
            )
        } else {
            format!("schema gaps: {}", schema_gaps.join("; "))
        },
    });

    Ok(checks)
}

/// The `seq` window the post-run temporal check queries: a slice strictly inside the retained band, so
/// the gate is an exact set equality. The band is `[last_cutoff, total_readings)`; the window takes its
/// middle half, leaving room on both sides.
fn temporal_check_window(last_cutoff: u64, cfg: &GenConfig) -> (u64, u64) {
    let top = cfg.total_readings();
    let live_span = top.saturating_sub(last_cutoff);
    if live_span == 0 {
        return (last_cutoff, top);
    }
    let lo = last_cutoff + live_span / 4;
    let hi = top - live_span / 4;
    if lo < hi {
        (lo, hi)
    } else {
        (last_cutoff, top)
    }
}

/// Reads the SURVIVING readings back in full and compares every field against the generator's stream.
/// Returns `(verified, attempted, failure detail)` — the detail is empty on a clean run.
///
/// `wanted == 0` (the default) checks **EVERY** reading in the retained band, which is the strongest form
/// and costs one round-trip per surviving reading (200 on the default profile, ~0.05 s). A positive
/// `wanted` takes a deterministic evenly-spaced stride instead.
///
/// The exhaustive default is not gold-plating — it is scar tissue. The first cut of this check sampled 64
/// of the 200 surviving readings on a stride of 3; a deliberately corrupted `value` at `seq` 6900 fell
/// **between** two sampled seqs and the check passed, while the concurrent readers (which see far more
/// rows) caught it. A gate that finds a planted defect only 32% of the time is not a gate. A single
/// mismatched field is a failure; there is no tolerance to spend.
fn verify_payloads(
    control: &mut BoltClient,
    db: &str,
    readings: &[ReadingRow],
    last_cutoff: u64,
    cfg: &GenConfig,
    wanted: u64,
) -> Result<(u64, u64, String), String> {
    let top = cfg.total_readings().min(readings.len() as u64);
    let live_span = top.saturating_sub(last_cutoff);
    if live_span == 0 {
        return Ok((
            0,
            0,
            "no surviving readings to read back — the retention window is empty".to_owned(),
        ));
    }
    // `0` = every surviving reading (the default). Otherwise a deterministic stride over the band.
    let n = if wanted == 0 {
        live_span
    } else {
        wanted.min(live_span)
    };
    let stride = (live_span / n).max(1);

    let mut verified = 0u64;
    let mut attempted = 0u64;
    let mut failures: Vec<String> = Vec::new();
    for i in 0..n {
        let seq = last_cutoff + i * stride;
        if seq >= top {
            break;
        }
        attempted += 1;
        let expected = &readings[seq as usize];
        let (_, _, rows) = run_retrying(
            control,
            db,
            "MATCH (r:Reading) WHERE r.seq = $seq \
             RETURN r.sensor AS sensor, r.seq AS seq, r.ts AS ts, r.value AS value",
            vec![("seq".to_owned(), Value::Integer(seq as i64))],
        )?;
        match rows.len() {
            1 => match check_payload_row(&rows[0], expected) {
                Ok(()) => verified += 1,
                Err(e) => {
                    if failures.len() < MAX_FAILURE_SAMPLES {
                        failures.push(e);
                    }
                }
            },
            0 => {
                if failures.len() < MAX_FAILURE_SAMPLES {
                    failures.push(format!(
                        "seq {seq} is inside the retained band [{last_cutoff}, {top}) but the server \
                         returned NO row for it — a surviving reading vanished, or the seek returned an \
                         empty result (rmp #738)"
                    ));
                }
            }
            n => {
                if failures.len() < MAX_FAILURE_SAMPLES {
                    failures.push(format!(
                        "seq {seq} came back {n} times — `seq` is the retention key and must be unique \
                         per reading"
                    ));
                }
            }
        }
    }
    Ok((verified, attempted, failures.join("; ")))
}

/// The indexes `Generator::schema_ddl` declares, with the TYPE each must have (`rmp` #745). Kept beside
/// the gate that verifies them so the two cannot silently drift.
const EXPECTED_INDEXES: [(&str, &str); 4] = [
    ("sensor_location_point", "POINT"),
    ("reading_sensor_seq", "RANGE"),
    ("reading_seq", "RANGE"),
    ("reading_ts", "RANGE"),
];
/// The constraints `Generator::schema_ddl` declares, with the TYPE each must have.
const EXPECTED_CONSTRAINTS: [(&str, &str); 3] = [
    ("sensor_id_key", "NODE_KEY"),
    ("reading_value_exists", "NODE_PROPERTY_EXISTENCE"),
    ("reading_ts_datetime", "NODE_PROPERTY_TYPE"),
];

/// Verify the declared IoT schema against a `SHOW INDEXES` / `SHOW CONSTRAINTS` result: every declared
/// index must be present BY NAME, carry the declared TYPE, and be `ONLINE`; every declared constraint
/// must be present by name and carry the declared type. Returns one human-readable gap per violation
/// (empty ⇒ the schema is fully materialised, exactly as declared).
///
/// The type check is `rmp` #745's addition. A name+state gate passed a `RANGE` index that the engine had
/// silently created as some other kind — which would change every seek in the workload into something
/// else while the example carried on reporting the performance of an index it never built.
fn declared_schema_gaps(idx: &[Vec<Value>], cons: &[Vec<Value>]) -> Vec<String> {
    let cell = |row: &[Value], i: usize| -> String {
        match row.get(i) {
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        }
    };
    let mut gaps: Vec<String> = Vec::new();
    for (name, want_type) in EXPECTED_INDEXES {
        match idx.iter().find(|row| cell(row, 0) == name) {
            None => gaps.push(format!("index '{name}' ABSENT")),
            Some(row) => {
                let got_type = cell(row, 1);
                if !got_type.eq_ignore_ascii_case(want_type) {
                    gaps.push(format!(
                        "index '{name}' type='{got_type}' (declared {want_type}) — the index exists but \
                         is NOT the kind the workload seeks"
                    ));
                }
                let state = cell(row, 3);
                if !state.eq_ignore_ascii_case("online") {
                    gaps.push(format!("index '{name}' state='{state}' (not ONLINE)"));
                }
            }
        }
    }
    for (name, want_type) in EXPECTED_CONSTRAINTS {
        match cons.iter().find(|row| cell(row, 0) == name) {
            None => gaps.push(format!("constraint '{name}' ABSENT")),
            Some(row) => {
                let got_type = cell(row, 1);
                if !got_type.eq_ignore_ascii_case(want_type) {
                    gaps.push(format!(
                        "constraint '{name}' type='{got_type}' (declared {want_type})"
                    ));
                }
            }
        }
    }
    gaps
}

// ==================================================================================================
// /proc sampling of the SERVER process (local mode only)
// ==================================================================================================

/// The server's cumulative (user, system) CPU seconds from `/proc/<pid>/stat`.
fn proc_cpu_secs(pid: i64) -> Option<(f64, f64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (utime, stime) = graphus_reco_gen::bench::parse_stat_utime_stime(&stat)?;
    // USER_HZ is 100 on every Linux Graphus targets (x86_64 / aarch64); `sysconf(_SC_CLK_TCK)` would
    // need libc, and this is an evidence sampler, not a load-bearing path.
    const USER_HZ: f64 = 100.0;
    Some((utime as f64 / USER_HZ, stime as f64 / USER_HZ))
}

/// The server's current RSS in bytes from `/proc/<pid>/status`.
fn proc_rss_bytes(pid: i64) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_status_kb_bytes(&status, "VmRSS")
}

/// The server's cumulative `write_bytes` from `/proc/<pid>/io` — the kernel's account of the bytes this
/// process caused to be sent to the storage layer. An independent, engine-external cross-check on the
/// durable write volume.
fn proc_write_bytes(pid: i64) -> Option<u64> {
    let io = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
    parse_proc_io_bytes(&io, "write_bytes")
}

// ==================================================================================================
// CLI
// ==================================================================================================

struct Args {
    socket: Option<String>,
    bolt: Option<String>,
    user: String,
    password: String,
    db: String,
    profile: String,
    cfg: GenConfig,
    ingest_clients: u64,
    batch: u64,
    batch1_ticks: u64,
    reader_clients: u64,
    payload_samples: u64,
    checkpoint_every: u64,
    /// How often the WAL sampler thread re-reads the WAL directory, in ms. The instrument's CALIBRATION
    /// KNOB (`rmp` #745): sweep it and the reconstructed WAL volume must PLATEAU. See
    /// [`DEFAULT_WAL_SAMPLE_MS`].
    wal_sample_ms: u64,
    db_store_path: Option<PathBuf>,
    server_pid: Option<i64>,
    samples: PathBuf,
    scenario: String,
}

impl Args {
    fn target(&self) -> Result<Target, String> {
        match (&self.bolt, &self.socket) {
            (Some(url), None) => Ok(Target::Bolt(BoltUrl::parse(url)?)),
            (None, Some(path)) => Ok(Target::Uds(PathBuf::from(path))),
            (Some(_), Some(_)) => {
                Err("--socket and --bolt are mutually exclusive (pick one transport)".to_owned())
            }
            (None, None) => Err("one of --socket or --bolt is required".to_owned()),
        }
    }

    #[allow(clippy::too_many_lines)] // a flat flag table
    fn parse() -> Result<Self, String> {
        let mut socket = None;
        let mut bolt = None;
        let mut user = "graphus".to_owned();
        let mut password = "graphus-local".to_owned();
        let mut db = String::new();
        let mut profile = "fast".to_owned();
        let mut sensors = None;
        let mut rate = None;
        let mut window = None;
        let mut ticks = None;
        let mut seed = None;
        let mut ingest_clients = 2u64;
        // A real gateway BATCHES: it buffers its devices' samples and flushes them in one transaction.
        // 50 readings per commit is a modest, realistic default (`rmp` #745).
        let mut batch = 50u64;
        let mut batch1_ticks = 10u64;
        let mut reader_clients = 2u64;
        // 0 = EVERY surviving reading (see `verify_payloads`): a strided sample can miss a planted
        // defect, and a check that finds a corruption only some of the time is not a check.
        let mut payload_samples = 0u64;
        let mut checkpoint_every = 5u64;
        let mut wal_sample_ms = DEFAULT_WAL_SAMPLE_MS;
        let mut db_store_path = None;
        let mut server_pid = None;
        let mut samples = None;
        let mut scenario = "iot-timeseries".to_owned();

        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
            let num = |v: String, what: &str| -> Result<u64, String> {
                v.parse::<u64>()
                    .map_err(|_| format!("{what} expects a non-negative integer, got {v:?}"))
            };
            match flag.as_str() {
                "--socket" => socket = Some(value()?),
                "--bolt" => bolt = Some(value()?),
                "--user" => user = value()?,
                "--password" => password = value()?,
                "--db" => db = value()?,
                "--profile" => profile = value()?,
                "--sensors" => sensors = Some(num(value()?, "--sensors")?),
                "--rate" => rate = Some(num(value()?, "--rate")?),
                "--window" => window = Some(num(value()?, "--window")?),
                "--ticks" => ticks = Some(num(value()?, "--ticks")?),
                "--seed" => seed = Some(num(value()?, "--seed")?),
                "--ingest-clients" => ingest_clients = num(value()?, "--ingest-clients")?.max(1),
                "--batch" => batch = num(value()?, "--batch")?.max(1),
                "--batch1-ticks" => batch1_ticks = num(value()?, "--batch1-ticks")?,
                "--reader-clients" => reader_clients = num(value()?, "--reader-clients")?,
                "--payload-samples" => payload_samples = num(value()?, "--payload-samples")?,
                "--checkpoint-every" => checkpoint_every = num(value()?, "--checkpoint-every")?,
                "--wal-sample-ms" => wal_sample_ms = num(value()?, "--wal-sample-ms")?.max(1),
                "--db-store-path" => db_store_path = Some(PathBuf::from(value()?)),
                "--server-pid" => {
                    let v = value()?;
                    server_pid = Some(
                        v.parse::<i64>()
                            .map_err(|_| format!("--server-pid expects a pid, got {v:?}"))?,
                    );
                }
                "--samples" => samples = Some(PathBuf::from(value()?)),
                "--scenario" => scenario = value()?,
                "-h" | "--help" => {
                    eprintln!(
                        "usage: iot_wire (--socket <path> | --bolt <url>) --user U --password P \
                         --db <database> --samples <out.json> [--profile fast|reclaim|large|soak] \
                         [--sensors N] [--rate N] [--window N] [--ticks N] [--seed N] \
                         [--ingest-clients N] [--batch N] [--batch1-ticks N] [--reader-clients N] \
                         [--payload-samples N | 0 = every surviving reading] [--checkpoint-every N] \
                         [--wal-sample-ms N] [--db-store-path <dir>] [--server-pid <pid>] [--scenario <name>]"
                    );
                    std::process::exit(0);
                }
                other => return Err(format!("unknown flag {other:?}")),
            }
        }

        let mut cfg = GenConfig::from_profile(&profile);
        if let Some(v) = sensors {
            cfg.sensors = v.max(1);
        }
        if let Some(v) = rate {
            cfg.rate = v.max(1);
        }
        if let Some(v) = window {
            cfg.window = v.max(1);
        }
        if let Some(v) = ticks {
            cfg.ticks = v.max(1);
        }
        if let Some(v) = seed {
            cfg.seed = v;
        }
        if db.is_empty() {
            return Err("--db is required (the isolated database to run the churn in)".to_owned());
        }
        let samples = samples.ok_or("--samples <out.json> is required")?;

        Ok(Self {
            socket,
            bolt,
            user,
            password,
            db,
            profile,
            cfg,
            ingest_clients,
            batch,
            batch1_ticks,
            reader_clients,
            payload_samples,
            checkpoint_every,
            wal_sample_ms,
            db_store_path,
            server_pid,
            samples,
            scenario,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `SHOW INDEXES`-shaped row `(name, type, entityType, state)`.
    fn idx_row(name: &str, kind: &str, state: &str) -> Vec<Value> {
        vec![
            Value::String(name.to_owned()),
            Value::String(kind.to_owned()),
            Value::String("NODE".to_owned()),
            Value::String(state.to_owned()),
        ]
    }
    /// Build a `SHOW CONSTRAINTS`-shaped row `(name, type, entityType)`.
    fn cons_row(name: &str, kind: &str) -> Vec<Value> {
        vec![
            Value::String(name.to_owned()),
            Value::String(kind.to_owned()),
            Value::String("NODE".to_owned()),
        ]
    }
    fn all_online() -> (Vec<Vec<Value>>, Vec<Vec<Value>>) {
        (
            EXPECTED_INDEXES
                .iter()
                .map(|(n, k)| idx_row(n, k, "ONLINE"))
                .collect(),
            EXPECTED_CONSTRAINTS
                .iter()
                .map(|(n, k)| cons_row(n, k))
                .collect(),
        )
    }

    /// The schema gate (`rmp` #743, extended by #745) must FIRE — not silently pass — when the declared
    /// schema is not fully materialised, or is materialised as the WRONG KIND.
    #[test]
    fn declared_schema_gate_is_falsifiable() {
        // Healthy: every declared index ONLINE with its declared type + every constraint ⇒ no gaps.
        let (idx, cons) = all_online();
        assert!(declared_schema_gaps(&idx, &cons).is_empty());

        // A #694 index stuck Populating is STILL A ROW (count-only passed) — this must fail.
        let mut populating = idx.clone();
        populating[1][3] = Value::String("POPULATING".to_owned());
        let gaps = declared_schema_gaps(&populating, &cons);
        assert_eq!(gaps.len(), 1);
        assert!(gaps[0].contains("POPULATING"), "{gaps:?}");

        // `rmp` #745: a RANGE index silently created as some OTHER kind passes a name+state check, and
        // would quietly turn every seek in the workload into something else. The TYPE check catches it.
        let mut wrong_kind = idx.clone();
        wrong_kind[3][1] = Value::String("TEXT".to_owned()); // reading_ts as a TEXT index
        let gaps = declared_schema_gaps(&wrong_kind, &cons);
        assert!(
            gaps.iter()
                .any(|g| g.contains("reading_ts") && g.contains("NOT the kind")),
            "a RANGE index created as TEXT must fail: {gaps:?}"
        );

        // …and the same for a constraint: a property-type constraint downgraded to a bare existence one.
        let mut wrong_cons = cons.clone();
        wrong_cons[2][1] = Value::String("NODE_PROPERTY_EXISTENCE".to_owned());
        assert!(
            declared_schema_gaps(&idx, &wrong_cons)
                .iter()
                .any(|g| g.contains("reading_ts_datetime")),
            "a constraint of the wrong TYPE must fail"
        );

        // A missing index by name must fail (even though the row count could be topped up elsewhere).
        let missing_idx: Vec<Vec<Value>> = idx.iter().skip(1).cloned().collect();
        assert!(
            declared_schema_gaps(&missing_idx, &cons)
                .iter()
                .any(|g| g.contains("ABSENT"))
        );

        // A missing constraint by name must fail.
        let missing_cons: Vec<Vec<Value>> = cons.iter().skip(1).cloned().collect();
        assert!(
            declared_schema_gaps(&idx, &missing_cons)
                .iter()
                .any(|g| g.contains("ABSENT"))
        );

        // Case-insensitive ONLINE/type is accepted (defensive against renderer casing).
        let lower: Vec<Vec<Value>> = EXPECTED_INDEXES
            .iter()
            .map(|(n, k)| idx_row(n, &k.to_lowercase(), "Online"))
            .collect();
        assert!(declared_schema_gaps(&lower, &cons).is_empty());
    }

    /// The restated PAGE_SIZE must match the engine's. This binary is client-only (it never links
    /// `graphus-io`), so the constant is pinned here against the documented value — a divergence would
    /// silently misreport every page figure in the evidence report.
    #[test]
    fn page_size_matches_the_engine() {
        assert_eq!(PAGE_SIZE, 8192, "graphus_io::PAGE_SIZE");
    }

    /// A retriable SSI conflict must be told apart from a terminal error, or the driver would either
    /// hammer a doomed statement or give up on a perfectly retriable one.
    #[test]
    fn retriable_classification() {
        let transient = ClientError::Protocol(
            "Neo.TransientError.Transaction.Outdated: the transaction is outdated".to_owned(),
        );
        assert!(is_retriable(&transient));
        let terminal = ClientError::Protocol(
            "Neo.ClientError.Schema.ConstraintValidationFailed: duplicate key".to_owned(),
        );
        assert!(!is_retriable(&terminal));
    }

    /// The logical payload of a reading is its four property values — stable and independent of the
    /// engine's on-disk encoding (which is exactly what amplification measures against it).
    #[test]
    fn logical_reading_bytes_counts_only_the_payload() {
        let r = ReadingRow {
            seq: 7,
            sensor: 3,
            ts_millis: 1_704_067_207_000,
            value: 42,
        };
        // "s-3" (3 bytes) + seq (8) + ts (8) + value (8)
        assert_eq!(logical_reading_bytes(&r), 3 + 8 + 8 + 8);
    }

    /// An empty latency family is NOT MEASURED, and must be reported as absent — never as a struct of
    /// zeros that would read like a real p50 of 0 ms (`rmp` #699).
    #[test]
    fn an_empty_latency_family_is_absent_not_zero() {
        assert!(latency(&[]).is_none());
        let l = latency(&[1_000_000, 2_000_000, 3_000_000]).expect("a measured family");
        assert_eq!(l.count, 3);
        assert!(l.p50_ms > 0.0);
    }

    // ---- `rmp` #745: the reader window + the ground-truth gates ----------------------------------

    /// The reader's window must sit INSIDE the live band: above the retention frontier (or nothing it
    /// asks for is guaranteed to exist) and below the committed frontier (or it asks for rows nobody has
    /// written yet). Both bounds are what make the gate sound rather than flaky.
    #[test]
    fn the_reader_window_stays_inside_the_live_band() {
        // Steady state: 6 000 ingested, retention has deleted everything below 5 800, window 200.
        let (lo, hi) = pick_window(6_000, 5_800, 200, 50).expect("a window in steady state");
        assert!(hi == 6_000, "anchored at the committed frontier");
        assert!(
            lo >= 5_800 + 50,
            "clear of the retention frontier by a tick"
        );
        assert!(lo < hi);

        // Early in the run the live band is too thin to carve a window out of: better to skip than to
        // gate against rows that may or may not exist.
        assert_eq!(pick_window(20, 0, 200, 50), None);
        assert_eq!(pick_window(0, 0, 200, 50), None);
    }

    fn row(sensor: u64, seq: u64, value: u64) -> Vec<Value> {
        let r = ReadingRow {
            seq,
            sensor,
            ts_millis: Generator::ts_millis_of(seq),
            value,
        };
        vec![
            Value::String(Generator::sensor_id(sensor)),
            Value::Integer(seq as i64),
            r.ts_value(),
            Value::Integer(value as i64),
        ]
    }

    fn expect(sensor: u64, seq: u64, value: u64) -> ReadingRow {
        ReadingRow {
            seq,
            sensor,
            ts_millis: Generator::ts_millis_of(seq),
            value,
        }
    }

    /// The happy path: the server returned exactly the generated rows, so the gate is an EXACT set
    /// equality and finds nothing wrong. Without this, every test below could pass against a gate that
    /// simply always fails.
    #[test]
    fn the_row_gate_passes_a_correct_result() {
        let expected = vec![expect(1, 10, 100), expect(1, 11, 101)];
        let rows = vec![row(1, 10, 100), row(1, 11, 101)];
        let mut t = FamilyTally::default();
        gate_rows(&mut t, &rows, &expected, 10, 0);
        assert_eq!(t.mismatches, 0);
        assert_eq!(t.empty_but_expected, 0);
        assert_eq!(t.rows_verified, 2);
        assert_eq!(t.exact_gated, 1, "the window was clear of the frontier");
    }

    /// **THE `rmp` #738 SIGNATURE.** An index that answers with an EMPTY result instead of declining
    /// loses every row silently. A `count(…)`-shaped check cannot see it (0 is a well-formed count); the
    /// row gate must.
    #[test]
    fn the_row_gate_catches_an_empty_result_where_rows_existed() {
        let expected = vec![expect(1, 10, 100), expect(1, 11, 101)];
        let mut t = FamilyTally::default();
        gate_rows(&mut t, &[], &expected, 10, 0);
        assert_eq!(t.empty_but_expected, 1, "an empty result FAILS");
        assert!(t.failures[0].contains("rmp #738"));
    }

    /// A single corrupted field — a value, a sensor, or a mangled timestamp — must fail. This is the
    /// check the example did not have.
    #[test]
    fn the_row_gate_catches_a_corrupted_payload() {
        let expected = vec![expect(1, 10, 100)];

        let mut t = FamilyTally::default();
        gate_rows(&mut t, &[row(1, 10, 999)], &expected, 10, 0);
        assert_eq!(t.mismatches, 1, "a wrong `value` must fail");
        assert!(t.failures[0].contains("stored value"));

        let mut t = FamilyTally::default();
        gate_rows(&mut t, &[row(2, 10, 100)], &expected, 10, 0);
        assert_eq!(t.mismatches, 1, "a wrong `sensor` must fail");

        // A timestamp the wire mangled (here: shifted by an hour) must fail, and must be reported as a
        // TEMPORAL failure — not silently re-derived by the client into an integer that happens to match.
        let mut bad_ts = row(1, 10, 100);
        bad_ts[2] = ReadingRow {
            seq: 10,
            sensor: 1,
            ts_millis: Generator::ts_millis_of(10) + 3_600_000,
            value: 100,
        }
        .ts_value();
        let mut t = FamilyTally::default();
        gate_rows(&mut t, &[bad_ts], &expected, 10, 0);
        assert_eq!(t.mismatches, 1, "a shifted `ts` must fail");
        assert!(t.failures[0].contains("did NOT round-trip"));
    }

    /// A row the generator never produced (a leak from another sensor, or from outside the window) must
    /// fail — the subset half of the gate.
    #[test]
    fn the_row_gate_catches_a_row_that_was_never_generated() {
        let expected = vec![expect(1, 10, 100)];
        let mut t = FamilyTally::default();
        gate_rows(&mut t, &[row(1, 10, 100), row(1, 77, 7)], &expected, 10, 0);
        assert_eq!(t.mismatches, 1);
        assert!(t.failures[0].contains("never emitted into this window"));
    }

    /// **The gate must stay SOUND while retention slides underneath it.** A reading the retention DELETE
    /// legitimately removed mid-query must NOT be demanded back — otherwise the gate would be flaky, and
    /// a flaky gate gets disabled, which is how the defect returns.
    #[test]
    fn the_row_gate_does_not_demand_rows_retention_legitimately_deleted() {
        let expected = vec![expect(1, 10, 100), expect(1, 11, 101), expect(1, 12, 102)];
        // The retention frontier advanced past seq 11 while the query was in flight, so the server may
        // legitimately have dropped 10 and 11 — but 12 was provably live and MUST be there.
        let mut t = FamilyTally::default();
        gate_rows(&mut t, &[row(1, 12, 102)], &expected, 10, 12);
        assert_eq!(
            t.mismatches, 0,
            "a legitimately-deleted row is not row loss"
        );
        assert_eq!(t.empty_but_expected, 0);
        assert_eq!(t.bounded_gated, 1, "the window straddled the frontier");
        assert_eq!(t.exact_gated, 0);

        // …but dropping seq 12, which nothing could have deleted, IS row loss.
        let mut t = FamilyTally::default();
        gate_rows(&mut t, &[], &expected, 10, 12);
        assert_eq!(
            t.empty_but_expected, 1,
            "a provably-live reading must come back"
        );
    }

    /// The aggregation gate: exact when the window is clear of the frontier, and held to a sound band
    /// when it straddles it. A `count` of zero where rows existed is the #738 signature there too.
    #[test]
    fn the_aggregate_gate_is_exact_when_it_can_be_and_sound_when_it_cannot() {
        let expected = vec![expect(1, 10, 100), expect(1, 11, 101), expect(1, 12, 102)];
        let agg = |n: i64, lo: i64, hi: i64, total: i64| {
            vec![vec![
                Value::Integer(n),
                Value::Integer(lo),
                Value::Integer(hi),
                Value::Integer(total),
            ]]
        };

        // Exact + correct.
        let mut t = FamilyTally::default();
        gate_aggregate(&mut t, &agg(3, 10, 12, 303), &expected, 10, 13, 0);
        assert_eq!(t.mismatches, 0);
        assert_eq!(t.exact_gated, 1);

        // Exact + a wrong sum FAILS (the aggregation is gated, not merely counted).
        let mut t = FamilyTally::default();
        gate_aggregate(&mut t, &agg(3, 10, 12, 999), &expected, 10, 13, 0);
        assert_eq!(t.mismatches, 1);

        // Exact + a wrong count FAILS.
        let mut t = FamilyTally::default();
        gate_aggregate(&mut t, &agg(2, 10, 11, 201), &expected, 10, 13, 0);
        assert_eq!(t.mismatches, 1);

        // A count of ZERO where rows provably existed is the #738 signature.
        let mut t = FamilyTally::default();
        gate_aggregate(
            &mut t,
            &[vec![
                Value::Integer(0),
                Value::Null,
                Value::Null,
                Value::Null,
            ]],
            &expected,
            10,
            13,
            0,
        );
        assert_eq!(t.empty_but_expected, 1);

        // Straddling the frontier: retention may have taken 10 and 11, so a count of 1 (only seq 12) is
        // sound and must NOT fail.
        let mut t = FamilyTally::default();
        gate_aggregate(&mut t, &agg(1, 12, 12, 102), &expected, 10, 13, 12);
        assert_eq!(t.mismatches, 0);
        assert_eq!(t.bounded_gated, 1);

        // …but a count ABOVE what the generator ever produced is impossible however retention moved.
        let mut t = FamilyTally::default();
        gate_aggregate(&mut t, &agg(9, 10, 12, 303), &expected, 10, 13, 12);
        assert_eq!(t.mismatches, 1);

        // …and a min/max escaping the requested window means the index widened the range.
        let mut t = FamilyTally::default();
        gate_aggregate(&mut t, &agg(3, 5, 12, 303), &expected, 10, 13, 0);
        assert_eq!(t.mismatches, 1);
        assert!(t.failures[0].contains("escapes the requested window"));
    }

    /// The post-run temporal check window must land strictly inside the retained band, or its "exact"
    /// gate would be gating a window half of which retention had already removed.
    #[test]
    fn the_temporal_check_window_sits_inside_the_retained_band() {
        let cfg = GenConfig {
            seed: 1,
            sensors: 8,
            rate: 50,
            window: 200,
            ticks: 140,
        };
        let last_cutoff = 6_800; // 7 000 ingested, 200 retained
        let (lo, hi) = temporal_check_window(last_cutoff, &cfg);
        assert!(lo >= last_cutoff, "never below the retention cutoff");
        assert!(hi <= cfg.total_readings(), "never above what was ingested");
        assert!(
            lo < hi && hi - lo >= 50,
            "a usefully wide window: {lo}..{hi}"
        );
    }

    /// The batch parameter must carry a real PackStream temporal per row — not an epoch integer. A row
    /// map that lost its `ts` type would silently violate the property-type constraint on the server.
    #[test]
    fn the_batch_parameter_carries_a_real_temporal_per_row() {
        let rows = [expect(1, 10, 100), expect(2, 11, 101)];
        let Value::List(items) = batch_rows_param(&rows) else {
            panic!("$rows must be a list");
        };
        assert_eq!(items.len(), 2);
        let Value::Map(first) = &items[0] else {
            panic!("each row is a map");
        };
        assert_eq!(first.len(), 4);
        assert_eq!(first[0].0, "sensor");
        assert!(
            matches!(first[2].1, Value::ZonedDateTime(_)),
            "ts is a DATETIME, not an integer"
        );
        assert_eq!(first[3].1, Value::Integer(100));

        // …and the single-reading (control) parameters carry the identical temporal.
        let single = single_row_params(&rows[0]);
        assert_eq!(single[2].0, "ts");
        assert_eq!(single[2].1, rows[0].ts_value());
    }
}
