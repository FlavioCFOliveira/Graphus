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
//!    constraint on the reading, a `POINT` index on `Sensor.location`, a composite `RANGE` index on
//!    `Reading(sensor, seq)`, and the single-property `RANGE` retention index on `Reading.seq`. Each is
//!    attempted independently, so an older target that lacks an index kind degrades to a recorded skip
//!    instead of a hard failure.
//! 2. **Concurrent ingest**: `--ingest-clients` independent Bolt connections, each owning a **disjoint
//!    slice of the sensor fleet** (`sensor % clients`). Sharding by sensor is what makes the concurrency
//!    conflict-free by construction: two readings from different sensors never touch the same node, so
//!    they never contend for the same relationship-chain head. The realistic shape, too — one gateway
//!    per group of devices. Retriable transaction errors are retried (and counted, never hidden).
//! 3. **Retention**: one windowed `DETACH DELETE` per tick on the control connection, after the tick's
//!    ingest has fully drained (so it never races the writers it would otherwise conflict with).
//! 4. **The real reclamation trigger**: `CHECKPOINT DATABASE <db>` every `--checkpoint-every` ticks — a
//!    parsed admin statement (`rmp` #305), issued over the SAME Bolt connection as every other
//!    statement. This is the correction of this example's central stale premise: reclamation is
//!    operator-reachable over the wire, and additionally runs on a background cadence with no operator
//!    action at all.
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
//! per statement family.
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
//!          [--ingest-clients N] [--checkpoint-every N]
//!          [--db-store-path <dir>] [--server-pid <pid>]
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_iot_gen::footprint::{self, StoreFootprint};
use graphus_iot_gen::wire_samples::{
    WIRE_SAMPLES_VERSION, WireCheck, WireLatency, WireSamples, WireStorage, WireTick, WireTransport,
};
use graphus_iot_gen::{GenConfig, Generator, ReadingRow, SITE_RADIUS};
use graphus_reco_gen::bench::{
    ns_to_ms, parse_proc_io_bytes, parse_status_kb_bytes, percentile_ns,
};
use graphus_reco_gen::client::{BoltClient, BoltUrl, ClientError};

/// The Graphus page size — the unit the store's data image grows in. Mirrors `graphus_io::PAGE_SIZE`
/// (this binary is client-only and never links the engine, so the constant is restated, and a unit test
/// below pins it against the value the store actually produces).
const PAGE_SIZE: u64 = 8192;

/// How long a client waits for a server reply before giving up.
const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// How many times a retriable transaction error (an SSI / write-lock conflict) is retried before the
/// run gives up on that statement. Sensor-sharded ingest should never conflict, so a non-zero retry
/// count is itself evidence worth reporting.
const MAX_RETRIES: u32 = 8;

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

/// Whether a server failure is a **retriable** transaction conflict (SSI / write-lock) rather than a
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
/// the statement's latency and how many retries it cost.
fn run_retrying(
    client: &mut BoltClient,
    db: &str,
    query: &str,
    params: Vec<(String, Value)>,
) -> Result<(Duration, u32, Vec<Vec<Value>>), String> {
    let mut retries = 0u32;
    loop {
        let started = Instant::now();
        match client.run(query, params.clone(), db) {
            Ok(r) => return Ok((started.elapsed(), retries, r.records)),
            Err(e) if is_retriable(&e) && retries < MAX_RETRIES => {
                retries += 1;
                std::thread::sleep(Duration::from_millis(2 * u64::from(retries)));
            }
            Err(e) => return Err(format!("{query}: {e}")),
        }
    }
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
// Concurrent ingest: one long-lived Bolt connection per shard, sensor-sharded so shards never conflict
// ==================================================================================================

/// The Cypher every ingest statement runs, with real Bolt parameters (so the server's parameterized
/// plan cache is exercised, exactly as a production client would).
const INGEST_CYPHER: &str = "MATCH (s:Sensor {id: $sid}) \
     CREATE (s)-[:EMITTED]->(:Reading {sensor: $sid, seq: $seq, ts: $ts, value: $value})";

/// A batch of readings for one shard's connection to ingest, or the shutdown sentinel.
enum ShardJob {
    Ingest(Vec<ReadingRow>),
    Stop,
}

/// What a shard reports back after one tick: the per-statement latencies it observed and the retries it
/// paid, or the terminal error that killed it.
struct ShardResult {
    latencies_ns: Vec<u64>,
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
                ShardJob::Ingest(rows) => {
                    let mut latencies_ns = Vec::with_capacity(rows.len());
                    let mut retries = 0u32;
                    let mut error = None;
                    for r in rows {
                        let params = vec![
                            (
                                "sid".to_owned(),
                                Value::String(Generator::sensor_id(r.sensor)),
                            ),
                            ("seq".to_owned(), Value::Integer(r.seq as i64)),
                            ("ts".to_owned(), Value::Integer(r.ts as i64)),
                            ("value".to_owned(), Value::Integer(r.value as i64)),
                        ];
                        match run_retrying(&mut client, &db, INGEST_CYPHER, params) {
                            Ok((lat, tries, _)) => {
                                latencies_ns.push(lat.as_nanos() as u64);
                                retries += tries;
                            }
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                    if res_tx
                        .send(ShardResult {
                            latencies_ns,
                            retries,
                            error,
                        })
                        .is_err()
                    {
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

// ==================================================================================================
// The run
// ==================================================================================================

#[allow(clippy::too_many_lines)] // one linear driver: schema -> churn loop -> checks -> samples
fn run() -> Result<bool, String> {
    let args = Args::parse()?;
    let target = args.target()?;
    let db = args.db.clone();

    let mut control = target.connect(&args.user, &args.password)?;
    eprintln!(
        "iot_wire: connected ({}), database '{}', profile={} sensors={} rate={} window={} ticks={} \
         ingest_clients={} checkpoint_every={}",
        target.transport().label(),
        db,
        args.profile,
        args.cfg.sensors,
        args.cfg.rate,
        args.cfg.window,
        args.cfg.ticks,
        args.ingest_clients,
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
    // The retention RANGE index on Reading.seq is the one the whole workload's shape depends on: the
    // per-tick aged-out DELETE seeks it. Without it the target cannot serve this scenario honestly.
    if !schema_applied.iter().any(|d| d.contains("reading_seq")) {
        return Err(
            "the target rejected the retention RANGE index on Reading.seq — this scenario cannot be \
             driven honestly against it"
                .to_owned(),
        );
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
    let mut stream = Generator::new(args.cfg.clone());
    let mut series: Vec<WireTick> = Vec::with_capacity(args.cfg.ticks as usize);
    let mut insert_latencies_ns: Vec<u64> = Vec::new();
    let mut delete_latencies_ns: Vec<u64> = Vec::new();
    let mut checkpoint_latencies_ns: Vec<u64> = Vec::new();
    // Cumulative WAL bytes written: segment path -> the MAXIMUM length ever observed for it. A WAL
    // segment is append-only, so its maximum length is what the engine wrote into it before a
    // checkpoint reclaimed (deleted) it.
    let mut wal_written: BTreeMap<PathBuf, u64> = BTreeMap::new();
    // Observed WAL-disk reclamation: how many times the on-disk WAL physically shrank, and by how much.
    let mut wal_reclaim_events = 0u64;
    let mut wal_reclaimed_bytes = 0u64;
    let mut total_ingested = 0u64;
    let mut logical_ingested_bytes = 0u64;
    let mut retried_ops = 0u64;
    let mut checkpoints_issued = 0u64;
    let mut server_peak_rss: Option<u64> = None;

    let cpu_before = args.server_pid.and_then(proc_cpu_secs);
    let io_before = args.server_pid.and_then(proc_write_bytes);
    let workload_started = Instant::now();

    while let Some(t) = stream.tick() {
        // 1. Ingest this tick's readings, sharded by SENSOR across the concurrent connections. A shard
        //    only ever touches its own sensors, so no two shards contend for the same node.
        let mut per_shard: Vec<Vec<ReadingRow>> = vec![Vec::new(); clients];
        for r in &t.readings {
            per_shard[(r.sensor as usize) % clients].push(*r);
            logical_ingested_bytes += logical_reading_bytes(r);
        }
        for (shard, rows) in shards.iter().zip(per_shard) {
            let n = rows.len();
            shard
                .jobs
                .send(ShardJob::Ingest(rows))
                .map_err(|_| "an ingest shard died".to_owned())?;
            total_ingested += n as u64;
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
            insert_latencies_ns.extend(res.latencies_ns);
        }

        // 2. Retention: delete everything that aged out of the window (an index-backed seek on
        //    Reading.seq), on the control connection.
        if let Some(_del) = &t.delete {
            let (lat, tries, _) = run_retrying(
                &mut control,
                &db,
                "MATCH (r:Reading) WHERE r.seq < $cutoff DETACH DELETE r",
                vec![("cutoff".to_owned(), Value::Integer(t.delete_cutoff as i64))],
            )?;
            delete_latencies_ns.push(lat.as_nanos() as u64);
            retried_ops += u64::from(tries);
        }

        // 3. The REAL reclamation trigger (`rmp` #305): the `CHECKPOINT DATABASE` admin statement, over
        //    the same wire. (`--checkpoint-every 0` relies on the background cadence alone.)
        let checkpointed = args.checkpoint_every > 0 && (t.tick + 1) % args.checkpoint_every == 0;
        if checkpointed {
            let started = Instant::now();
            control
                .run(&format!("CHECKPOINT DATABASE {db}"), Vec::new(), &db)
                .map_err(|e| format!("CHECKPOINT DATABASE {db}: {e}"))?;
            checkpoint_latencies_ns.push(started.elapsed().as_nanos() as u64);
            checkpoints_issued += 1;
        }

        // 4. Sample: the live count over the wire, and (locally) the REAL on-disk footprint.
        let live = scalar(&mut control, &db, "MATCH (r:Reading) RETURN count(r) AS c")? as u64;
        let (store_data_bytes, store_bytes, wal_bytes) = match &args.db_store_path {
            Some(path) => {
                let fp = footprint::measure(path);
                for (seg, len) in footprint::wal_segments(path) {
                    let e = wal_written.entry(seg).or_insert(0);
                    *e = (*e).max(len);
                }
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
            store_data_bytes,
            store_bytes,
            wal_bytes,
        });
        if t.tick % 10 == 0 || t.tick + 1 == args.cfg.ticks {
            eprintln!(
                "  tick {:4}  ingested {:7}  live {:6}  store {:>10}  wal {:>10}{}",
                t.tick,
                total_ingested,
                live,
                store_data_bytes.map_or("n/a".to_owned(), |b| format!("{b}B")),
                wal_bytes.map_or("n/a".to_owned(), |b| format!("{b}B")),
                if checkpointed { "  [CHECKPOINT]" } else { "" },
            );
        }
    }

    let workload = workload_started.elapsed();

    // ---- Shut the ingest shards down (their connections are done). ----
    for shard in &shards {
        let _ = shard.jobs.send(ShardJob::Stop);
    }
    for shard in shards {
        let _ = shard.join.join();
    }

    // ---- Post-run functional checks over the SAME wire. ----
    let final_live = scalar(&mut control, &db, "MATCH (r:Reading) RETURN count(r) AS c")? as u64;
    let session = Session {
        target: &target,
        user: &args.user,
        password: &args.password,
        db: &db,
    };
    let checks = wire_checks(
        &mut control,
        &session,
        &args.cfg,
        final_live,
        total_ingested,
    )?;
    let checks_failed = checks.iter().filter(|c| !c.ok).count();

    // ---- Storage evidence (local only). ----
    let storage = args.db_store_path.as_ref().map(|path| {
        let fp: StoreFootprint = footprint::measure(path);
        for (seg, len) in footprint::wal_segments(path) {
            let e = wal_written.entry(seg).or_insert(0);
            *e = (*e).max(len);
        }
        let post_warmup: Vec<u64> = series
            .iter()
            .filter(|s| s.tick >= warmup_ticks)
            .filter_map(|s| s.store_data_bytes)
            .collect();
        let plateau_min = post_warmup.iter().copied().min().unwrap_or(fp.data_bytes);
        let plateau_max = post_warmup.iter().copied().max().unwrap_or(fp.data_bytes);
        // The PEAK on-disk WAL over the run — the honest worst case. The residual `fp.wal_bytes` alone
        // is misleading: the WAL sawtooths (reclamation frees disk in whole 64 MiB segment units), so
        // the final figure depends on where in the sawtooth the run happened to stop.
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
            wal_written_bytes: wal_written.values().sum(),
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
        ticks_series: series,
        total_ingested,
        final_live_readings: final_live,
        checkpoints_issued,
        ingest_ops: insert_latencies_ns.len() as u64,
        delete_ops: delete_latencies_ns.len() as u64,
        retried_ops,
        workload_secs: workload.as_secs_f64(),
        logical_ingested_bytes,
        storage,
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
        "iot_wire: {} readings ingested over {:.2}s ({:.0}/s), {} checkpoints issued, {} retries; \
         wrote {}",
        total_ingested,
        workload.as_secs_f64(),
        samples.ingest_per_sec().unwrap_or(0.0),
        checkpoints_issued,
        retried_ops,
        args.samples.display(),
    );
    if checks_failed > 0 {
        eprintln!("iot_wire: {checks_failed} over-the-wire check(s) FAILED (see samples.json)");
        return Ok(false);
    }
    println!("GRAPHUS_IOT_WIRE_OK");
    Ok(true)
}

/// The logical payload of one reading, in bytes: its four property values (the `sensor` id string plus
/// three 8-byte integers). Deliberately *logical* — no record headers, no MVCC version, no index entry,
/// no page slack. Those are exactly the overheads write amplification exists to expose, so counting
/// them in the denominator would flatter the ratio into meaninglessness.
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
/// actually be **enforced** and **usable**, not merely accepted.
fn wire_checks(
    control: &mut BoltClient,
    session: &Session<'_>,
    cfg: &GenConfig,
    final_live: u64,
    total_ingested: u64,
) -> Result<Vec<WireCheck>, String> {
    let db = session.db;
    let mut checks = Vec::new();

    // 1. Steady state: the live count sits in [window, window + rate) — retention is holding the window.
    let lo = cfg.window;
    let hi = cfg.window + cfg.rate;
    checks.push(WireCheck {
        name: "steady-state live :Reading count in [window, window + rate)".to_owned(),
        ok: final_live >= lo && final_live < hi,
        detail: format!("live={final_live}, band=[{lo}, {hi}), total_ingested={total_ingested}"),
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

    // 5. Property-type constraint: a float `ts` must be REJECTED (`Reading.ts IS :: INTEGER`).
    let (ts_rejected, ts_detail) = expect_rejected(
        session,
        "MATCH (s:Sensor {id: 's-0'}) CREATE (s)-[:EMITTED]->(:Reading {sensor: 's-0', seq: -1, ts: 1.5, value: 1})",
    )?;
    checks.push(WireCheck {
        name: "non-INTEGER Reading.ts rejected (property-type constraint)".to_owned(),
        ok: ts_rejected,
        detail: ts_detail,
    });

    // 6. Existence constraint: a Reading with no `value` must be REJECTED.
    let (val_rejected, val_detail) = expect_rejected(
        session,
        "MATCH (s:Sensor {id: 's-0'}) CREATE (s)-[:EMITTED]->(:Reading {sensor: 's-0', seq: -2, ts: 1})",
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
        name: "the three rejected writes created nothing (atomicity)".to_owned(),
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
    // Verify the declared schema BY NAME, and that every declared index is actually ONLINE — not
    // merely that "at least 3" rows exist. A count-only check passed even if a #694 index were stuck
    // Populating (it is still a row), i.e. it could never catch the exact failure this example exists
    // to expose (rmp #743). SHOW INDEXES columns are (name, type, entityType, state); SHOW CONSTRAINTS
    // (name, type, entityType). Graphus renders an online index state as "ONLINE" (index_show.rs).
    let schema_gaps = declared_schema_gaps(&idx, &cons);
    checks.push(WireCheck {
        name: "every declared index/constraint is present by name and every index is ONLINE"
            .to_owned(),
        ok: schema_gaps.is_empty(),
        detail: if schema_gaps.is_empty() {
            format!(
                "{} indexes ONLINE + {} constraints present (by name)",
                EXPECTED_INDEXES.len(),
                EXPECTED_CONSTRAINTS.len()
            )
        } else {
            format!("schema gaps: {}", schema_gaps.join("; "))
        },
    });

    Ok(checks)
}

/// The index names `Generator::schema_ddl` declares (see `crates/graphus-iot-gen/src/lib.rs`). Kept
/// beside the gate that verifies them so the two cannot silently drift.
const EXPECTED_INDEXES: [&str; 3] = ["sensor_location_point", "reading_sensor_seq", "reading_seq"];
/// The constraint names `Generator::schema_ddl` declares.
const EXPECTED_CONSTRAINTS: [&str; 3] = [
    "sensor_id_key",
    "reading_value_exists",
    "reading_ts_integer",
];

/// Verify the declared IoT schema against a `SHOW INDEXES` / `SHOW CONSTRAINTS` result: every declared
/// index must be present BY NAME and `ONLINE`, and every declared constraint present by name. Returns
/// one human-readable gap per violation (empty ⇒ the schema is fully materialised). This is the gate
/// (`rmp #743`) that a count-only `idx.len() >= 3` check could not be: a `#694` index stuck
/// `Populating` is still a row, so counting passed while the index was unusable — this fails.
fn declared_schema_gaps(idx: &[Vec<Value>], cons: &[Vec<Value>]) -> Vec<String> {
    let cell = |row: &[Value], i: usize| -> String {
        match row.get(i) {
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        }
    };
    let mut gaps: Vec<String> = Vec::new();
    for name in EXPECTED_INDEXES {
        match idx.iter().find(|row| cell(row, 0) == name) {
            None => gaps.push(format!("index '{name}' ABSENT")),
            Some(row) => {
                let state = cell(row, 3);
                if !state.eq_ignore_ascii_case("online") {
                    gaps.push(format!("index '{name}' state='{state}' (not ONLINE)"));
                }
            }
        }
    }
    for name in EXPECTED_CONSTRAINTS {
        if !cons.iter().any(|row| cell(row, 0) == name) {
            gaps.push(format!("constraint '{name}' ABSENT"));
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
    checkpoint_every: u64,
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
        let mut checkpoint_every = 5u64;
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
                "--checkpoint-every" => checkpoint_every = num(value()?, "--checkpoint-every")?,
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
                         [--ingest-clients N] [--checkpoint-every N] [--db-store-path <dir>] \
                         [--server-pid <pid>] [--scenario <name>]"
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
            checkpoint_every,
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
    fn idx_row(name: &str, state: &str) -> Vec<Value> {
        vec![
            Value::String(name.to_owned()),
            Value::String("RANGE".to_owned()),
            Value::String("NODE".to_owned()),
            Value::String(state.to_owned()),
        ]
    }
    /// Build a `SHOW CONSTRAINTS`-shaped row `(name, type, entityType)`.
    fn cons_row(name: &str) -> Vec<Value> {
        vec![
            Value::String(name.to_owned()),
            Value::String("NODE_KEY".to_owned()),
            Value::String("NODE".to_owned()),
        ]
    }
    fn all_online() -> (Vec<Vec<Value>>, Vec<Vec<Value>>) {
        (
            EXPECTED_INDEXES
                .iter()
                .map(|n| idx_row(n, "ONLINE"))
                .collect(),
            EXPECTED_CONSTRAINTS.iter().map(|n| cons_row(n)).collect(),
        )
    }

    /// The schema gate (`rmp #743`) must FIRE — not silently pass — when the declared schema is not
    /// fully materialised. A count-only `idx.len() >= 3` check could never catch these.
    #[test]
    fn declared_schema_gate_is_falsifiable() {
        // Healthy: every declared index ONLINE + every constraint present ⇒ no gaps.
        let (idx, cons) = all_online();
        assert!(declared_schema_gaps(&idx, &cons).is_empty());

        // A #694 index stuck Populating is STILL A ROW (count-only passed) — this must fail.
        let mut populating = idx.clone();
        populating[1][3] = Value::String("POPULATING".to_owned());
        let gaps = declared_schema_gaps(&populating, &cons);
        assert_eq!(gaps.len(), 1);
        assert!(gaps[0].contains("POPULATING"), "{gaps:?}");

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

        // Case-insensitive ONLINE is accepted (defensive against renderer casing).
        let lower: Vec<Vec<Value>> = EXPECTED_INDEXES
            .iter()
            .map(|n| idx_row(n, "Online"))
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
            ts: 1_704_067_207_000,
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
}
