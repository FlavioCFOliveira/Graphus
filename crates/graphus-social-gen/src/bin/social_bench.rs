//! `social_bench` — the **concurrent over-the-wire read driver**, the headline of the
//! `examples/social-network-large` performance evaluation (`rmp` #691).
//!
//! It drives **many simultaneous read-only Bolt connections** against an already-loaded social graph
//! and **exposes whether reads scale across CPU cores**. It sweeps a **concurrency ladder** — an
//! increasing number of simultaneous connections — and, for each rung:
//!
//! 1. spawns `C` worker OS threads, each owning its own [`BoltClient`] over its own connection, all
//!    released together by a start [`Barrier`], each looping a weighted mix of the read battery
//!    ([`graphus_social_gen::battery`]) against the target database until a shared op budget drains;
//! 2. optionally runs low-rate writer threads (a single-anchor `SET` touch) so readers contend with
//!    live writers under MVCC/SSI (the concurrent read/write mix);
//! 3. in LOCAL mode, samples the **co-located server process** via `/proc/<server-pid>`: total +
//!    per-thread CPU (from `stat`), peak/current RSS (`status`), IO bytes (`io`, if readable) — so the
//!    report shows **read scaling vs C** by sampling the SERVER, not this driver (the historical
//!    `~1-core` figure was a driver artifact of the in-process battery);
//! 4. aggregates client throughput + latency percentiles (overall and per family) and the server's
//!    core utilisation, busy-thread count, and peak RSS.
//!
//! Before the ladder it runs a **capability preflight** (one warm-up call per family): a family the
//! target cannot serve (e.g. `fulltext` on an older server without the FULLTEXT index) is dropped from
//! the mix and noted — so the same driver runs version-tolerantly against a modern local server (all
//! eight families) or an older remote one (the seven core families).
//!
//! # Two transports (mirrors `reco_bench`)
//!
//! - **Local (`--socket` + `--server-pid`)** — Bolt-over-UDS against a co-located server whose pid is
//!   known, so the full `/proc` per-thread scaling diagnosis is available.
//! - **Attach (`--bolt <url>`)** — Bolt-over-TCP + TLS against an ALREADY-RUNNING, possibly remote /
//!   older instance (e.g. pi516; `bolt+ssc://` accepts a self-signed cert). No co-located pid, so
//!   `/proc` sampling is off; the server-side channel is the target's `/metrics` scraped by `run.sh`
//!   and folded in by `measure_target`. The driver prints client-side stats sentinels
//!   `GRAPHUS_SOCIAL_BENCH_STATS` / `_RUNG` and writes no `report.json` of its own in attach mode.
//!
//! It is a **client-only** binary (`wire` feature): it never links the engine, so it can hammer a
//! server in another process or on another host.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_examples_harness::metrics::DiskFootprint;
use graphus_examples_harness::{
    CpuSection, DatasetScale, EvidenceCollector, MemorySection, RunMetadata, StorageSection,
};
use graphus_reco_gen::bench::{self, Pcts};
use graphus_reco_gen::client::{BoltClient, BoltUrl, ClientResult};
use graphus_social_gen::{EPOCH_S, Generator, REG_SPAN_S, SplitMix64, battery};

/// How often the background sampler polls `/proc/<pid>/status` for RSS, in milliseconds.
const SAMPLE_INTERVAL_MS: u64 = 50;
/// A thread counts as "busy" over a rung if it consumed more than this fraction of one core.
const BUSY_THREAD_FRACTION: f64 = 0.05;
/// The per-rung reader error-rate above which the run is broken (nonzero exit). Server `FAILURE`s and
/// transport faults count; zero-row results do NOT (they are successful reads).
const MAX_ERROR_RATE: f64 = 0.05;
/// The plateau band for the knee diagnosis / auto-extend.
const PLATEAU_BAND: f64 = 0.10;
/// Default per-client op floor: the effective per-rung budget is at least `clients × this`.
const DEFAULT_MIN_OPS_PER_CLIENT: u64 = 150;
/// Hard cap on the client count when `--auto-extend` keeps doubling.
const AUTO_EXTEND_MAX_CLIENTS: usize = 512;
/// Hard cap on the total rung count (explicit + auto-extended).
const MAX_TOTAL_RUNGS: usize = 24;

/// A cumulative `(utime, stime)` clock-ticks snapshot; `None` when the server process is not
/// observable via `/proc`.
type CpuTicks = Option<(u64, u64)>;

/// Where the driver connects.
#[derive(Clone)]
enum Target {
    /// Bolt-over-UDS (local, co-located server).
    Uds(PathBuf),
    /// Bolt-over-TCP(+TLS) (attach mode; `bolt+ssc://` = self-signed OK).
    Bolt(BoltUrl),
}

impl Target {
    fn connect(&self, read_timeout: Duration) -> ClientResult<BoltClient> {
        match self {
            Self::Uds(path) => BoltClient::connect_uds(path, read_timeout),
            Self::Bolt(url) => BoltClient::connect_bolt(url, read_timeout),
        }
    }
    fn is_external(&self) -> bool {
        matches!(self, Self::Bolt(_))
    }
    fn label(&self) -> String {
        match self {
            Self::Uds(p) => format!("uds:{}", p.display()),
            Self::Bolt(u) => u.to_string(),
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("social_bench: error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the whole ladder. `Ok(true)` = clean, `Ok(false)` = a rung breached [`MAX_ERROR_RATE`],
/// `Err` = fatal setup error.
fn run() -> Result<bool, String> {
    let args = Args::parse()?;
    let ladder = bench::parse_ladder(&args.ladder)?;
    let target = args.target()?;
    let external = target.is_external();

    let (term, _hits) = Generator::dominant_headline_term_for(args.seed, args.articles.max(1));
    let since = (EPOCH_S + REG_SPAN_S / 2) as i64;

    // Capability preflight: connect once, warm each family, keep only the families the target serves.
    let active = preflight_active_families(&target, &args, &term, since)?;
    if active.is_empty() {
        return Err(
            "no read-battery family could be served by the target (preflight failed for all)"
                .into(),
        );
    }

    let ctx = Arc::new(BenchCtx {
        target: target.clone(),
        user: args.user.clone(),
        password: args.password.clone(),
        db: args.db.clone(),
        read_timeout: Duration::from_millis(args.read_timeout_ms),
        users: args.users.max(1),
        articles: args.articles.max(1),
        term,
        since,
        ops_per_rung: args.ops_per_rung,
        min_ops_per_client: args.min_ops_per_client,
        write_every_ms: args.write_every_ms,
        writers: args.writers,
        target_rps: args.target_rps,
        seed: args.seed,
        active: active.clone(),
        bag: weighted_bag(&active),
    });

    let server_pid = args.server_pid.unwrap_or(-1);
    let proc_available = !external && read_total_cpu(server_pid).is_some();
    let clk_tck = clock_ticks_per_sec();
    if external {
        eprintln!(
            "social_bench: ATTACH mode ({}) — /proc sampling OFF; server-side evidence is the target's \
             /metrics (folded in by measure_target). Client throughput + latency are measured here.",
            target.label()
        );
    } else if !proc_available {
        eprintln!(
            "social_bench: /proc/{server_pid}/stat is not observable (non-Linux, or pid not owned/alive) \
             — server CPU/RSS/IO sampling DISABLED; throughput + latency evidence is still valid."
        );
    }

    let active_names: Vec<&str> = active.iter().map(|&i| battery::ALL[i].name).collect();
    eprintln!(
        "social_bench: target={} db={} pid={} ladder={:?} ops/rung={} min_ops/client={} users={} \
         articles={} write_every_ms={} writers={} target_rps={} auto_extend={} clk_tck={clk_tck} \
         proc_sampling={} mode={} active_families={:?}",
        target.label(),
        args.db,
        server_pid,
        ladder,
        args.ops_per_rung,
        args.min_ops_per_client,
        ctx.users,
        ctx.articles,
        args.write_every_ms,
        ctx.effective_writers(),
        args.target_rps,
        args.auto_extend,
        proc_available,
        if external { "external" } else { "local" },
        active_names,
    );

    let mut rungs: Vec<RungResult> = Vec::with_capacity(ladder.len());
    for (rung_ix, &clients) in ladder.iter().enumerate() {
        let result = drive_rung(&ctx, rung_ix, clients, server_pid, proc_available, clk_tck);
        print_rung_line(&result);
        rungs.push(result);
    }

    // Auto-extend past the tested ladder while throughput is still rising (so the knee is located).
    if args.auto_extend && !rungs.is_empty() {
        let mut rung_ix = ladder.len();
        loop {
            if rungs.len() >= MAX_TOTAL_RUNGS {
                eprintln!("social_bench: auto-extend stopped at the {MAX_TOTAL_RUNGS}-rung cap.");
                break;
            }
            let last = rungs.last().expect("non-empty");
            let prior_best = rungs[..rungs.len() - 1]
                .iter()
                .map(|r| r.ops_per_sec)
                .fold(0.0f64, f64::max);
            let gain = if prior_best > 0.0 {
                (last.ops_per_sec - prior_best) / prior_best
            } else {
                f64::INFINITY
            };
            if gain <= PLATEAU_BAND {
                eprintln!(
                    "social_bench: auto-extend stopped — throughput plateaued at clients={} ({:.1} ops/s, \
                     {:+.1}% vs prior best {:.1}).",
                    last.clients,
                    last.ops_per_sec,
                    gain * 100.0,
                    prior_best
                );
                break;
            }
            let next = last.clients.saturating_mul(2);
            if next > AUTO_EXTEND_MAX_CLIENTS {
                eprintln!(
                    "social_bench: auto-extend reached the clients={AUTO_EXTEND_MAX_CLIENTS} cap (still rising)."
                );
                break;
            }
            eprintln!("social_bench: auto-extend → clients={next} (throughput still rising)");
            let result = drive_rung(&ctx, rung_ix, next, server_pid, proc_available, clk_tck);
            print_rung_line(&result);
            rungs.push(result);
            rung_ix += 1;
        }
    }

    if rungs.is_empty() {
        return Err("empty ladder produced no rungs".into());
    }

    print_report(&ctx, &rungs, proc_available, external);
    print_client_stats_sentinels(&rungs, external);

    if external {
        eprintln!(
            "social_bench: attach mode — evidence report is emitted by measure_target (from the /metrics before/after delta)."
        );
    } else if let Some(dir) = &args.evidence_dir {
        write_evidence(dir, &args, &ctx, &rungs, proc_available)
            .map_err(|e| format!("failed to write evidence to {dir}: {e}"))?;
    }

    // Exit gate: any rung whose reader error rate breached the threshold marks a broken run.
    let mut ok = true;
    for r in &rungs {
        let attempts = r.ok_ops + r.err_ops;
        if attempts > 0 {
            let rate = r.err_ops as f64 / attempts as f64;
            if rate > MAX_ERROR_RATE {
                eprintln!(
                    "social_bench: FAIL rung clients={}: reader error rate {:.1}% ({} of {} ops) exceeds {:.0}%",
                    r.clients,
                    rate * 100.0,
                    r.err_ops,
                    attempts,
                    MAX_ERROR_RATE * 100.0
                );
                ok = false;
            }
        }
    }
    if ok {
        eprintln!(
            "social_bench: OK — every rung stayed under the {:.0}% reader-error threshold.",
            MAX_ERROR_RATE * 100.0
        );
    }
    Ok(ok)
}

// ============================================================================================
// Capability preflight + weighted mix
// ============================================================================================

/// Connects once, warms every battery family with one representative call, and returns the indices
/// (into [`battery::ALL`]) the target actually served. A family that errors (e.g. `fulltext` without a
/// FULLTEXT index on an older server) is dropped and noted — this is the version-tolerance seam AND
/// the required warm-up before the measured ladder.
fn preflight_active_families(
    target: &Target,
    args: &Args,
    term: &str,
    since: i64,
) -> Result<Vec<usize>, String> {
    let mut client = target
        .connect(Duration::from_millis(args.read_timeout_ms))
        .map_err(|e| format!("preflight connect failed: {e}"))?;
    client
        .login(&args.user, &args.password)
        .map_err(|e| format!("preflight login as {:?} failed: {e}", args.user))?;
    let u0 = Generator::user_id(0);
    let u1 = Generator::user_id(1 % args.users.max(1));
    let mut active = Vec::new();
    for (i, fam) in battery::ALL.iter().enumerate() {
        let params = op_params(fam.params, &u0, &u1, term, since);
        match client.run(fam.cypher, params, &args.db) {
            Ok(_) => active.push(i),
            Err(e) => eprintln!(
                "social_bench: preflight: dropping family '{}' — target rejected it ({e})",
                fam.name
            ),
        }
    }
    let _ = client.goodbye();
    Ok(active)
}

/// Builds the weighted pick "bag": each active family index repeated by its weight, so a uniform draw
/// over the bag realises the mix (cheap point reads more frequent than heavy scans/aggregations).
fn weighted_bag(active: &[usize]) -> Vec<usize> {
    let mut bag = Vec::new();
    for &i in active {
        let w = match battery::ALL[i].name {
            "friends" | "degree" => 4,            // cheap point-anchored 1-hop counts
            "fof" | "mutual" => 2,                // heavier multi-hop traversals
            "text_contains" | "like_recent" => 2, // property/range scans
            "top_liked" | "fulltext" => 1,        // whole-set aggregation / procedure
            _ => 1,
        };
        for _ in 0..w {
            bag.push(i);
        }
    }
    bag
}

/// Builds the per-op `Value` params for a family (anchors vary per op; `term`/`since` are fixed).
fn op_params(
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

// ============================================================================================
// Rung driver
// ============================================================================================

/// Immutable per-run configuration shared with every worker/writer thread.
struct BenchCtx {
    target: Target,
    user: String,
    password: String,
    db: String,
    read_timeout: Duration,
    users: u64,
    articles: u64,
    term: String,
    since: i64,
    ops_per_rung: u64,
    min_ops_per_client: u64,
    write_every_ms: u64,
    writers: usize,
    target_rps: f64,
    seed: u64,
    /// Indices (into [`battery::ALL`]) of the families the target serves.
    active: Vec<usize>,
    /// The weighted pick bag over `active`.
    bag: Vec<usize>,
}

impl BenchCtx {
    fn effective_budget(&self, clients: usize) -> u64 {
        self.ops_per_rung
            .max(self.min_ops_per_client.saturating_mul(clients as u64))
    }
    fn effective_writers(&self) -> usize {
        if self.write_every_ms == 0 {
            0
        } else {
            self.writers.max(1)
        }
    }
    fn arrival_interval(&self) -> Option<Duration> {
        if self.target_rps > 0.0 {
            Some(Duration::from_secs_f64(1.0 / self.target_rps))
        } else {
            None
        }
    }
}

/// One worker's accumulated per-family stats (indexed by position in [`battery::ALL`]).
struct WorkerStats {
    lat: Vec<Vec<u64>>,
    ok: Vec<u64>,
    err: Vec<u64>,
    connect_errors: u64,
}
impl WorkerStats {
    fn new(families: usize) -> Self {
        Self {
            lat: vec![Vec::new(); families],
            ok: vec![0; families],
            err: vec![0; families],
            connect_errors: 0,
        }
    }
}

/// The aggregated per-family result the report prints.
struct FamilyResult {
    name: &'static str,
    advanced: bool,
    ok: u64,
    err: u64,
    pcts: Pcts,
}

/// The fully-aggregated result of one ladder rung.
struct RungResult {
    clients: usize,
    ok_ops: u64,
    err_ops: u64,
    wall_secs: f64,
    ops_per_sec: f64,
    overall: Pcts,
    per_family: Vec<FamilyResult>,
    cpu_user_secs: f64,
    cpu_system_secs: f64,
    server_cores: f64,
    busy_threads: usize,
    busiest_core_frac: f64,
    peak_rss: u64,
    final_rss: u64,
    vm_hwm: u64,
    io_read_bytes: u64,
    io_available: bool,
    writes_ok: u64,
    writes_err: u64,
}

/// Drives a single rung of `clients` concurrent connections.
fn drive_rung(
    ctx: &Arc<BenchCtx>,
    rung_ix: usize,
    clients: usize,
    server_pid: i64,
    proc_available: bool,
    clk_tck: u64,
) -> RungResult {
    let families = battery::ALL.len();
    let issued = Arc::new(AtomicU64::new(0));
    let budget = ctx.effective_budget(clients);
    let origin: Arc<OnceLock<Instant>> = Arc::new(OnceLock::new());
    let barrier = Arc::new(Barrier::new(clients + 1));

    let sampler_stop = Arc::new(AtomicBool::new(false));
    let sampler = if proc_available {
        Some(spawn_rss_sampler(server_pid, Arc::clone(&sampler_stop)))
    } else {
        None
    };

    let effective_writers = ctx.effective_writers();
    let writer_stop = Arc::new(AtomicBool::new(false));
    let mut writer_handles: Vec<JoinHandle<(u64, u64)>> = Vec::with_capacity(effective_writers);
    for wi in 0..effective_writers {
        writer_handles.push(spawn_writer(
            Arc::clone(ctx),
            Arc::clone(&writer_stop),
            rung_ix,
            wi,
        ));
    }

    let mut handles: Vec<JoinHandle<WorkerStats>> = Vec::with_capacity(clients);
    for w in 0..clients {
        let ctx = Arc::clone(ctx);
        let issued = Arc::clone(&issued);
        let barrier = Arc::clone(&barrier);
        let origin = Arc::clone(&origin);
        let seed = ctx
            .seed
            .wrapping_add((rung_ix as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
            .wrapping_add((w as u64).wrapping_mul(0xD1B5_4A32_D192_ED03));
        handles.push(thread::spawn(move || {
            run_worker(&ctx, &issued, &barrier, &origin, families, seed, budget)
        }));
    }

    barrier.wait();
    let t0 = *origin.get_or_init(Instant::now);
    let cpu_start = if proc_available {
        read_total_cpu(server_pid)
    } else {
        None
    };
    let threads_start = if proc_available {
        snapshot_threads(server_pid)
    } else {
        BTreeMap::new()
    };
    let io_start = if proc_available {
        read_io_bytes(server_pid)
    } else {
        None
    };

    let mut merged = WorkerStats::new(families);
    let mut connect_errors = 0u64;
    for h in handles {
        match h.join() {
            Ok(ws) => {
                connect_errors += ws.connect_errors;
                for f in 0..families {
                    merged.ok[f] += ws.ok[f];
                    merged.err[f] += ws.err[f];
                    merged.lat[f].extend_from_slice(&ws.lat[f]);
                }
            }
            Err(_) => connect_errors += 1,
        }
    }
    let wall = t0.elapsed();

    let cpu_end = if proc_available {
        read_total_cpu(server_pid)
    } else {
        None
    };
    let threads_end = if proc_available {
        snapshot_threads(server_pid)
    } else {
        BTreeMap::new()
    };
    let io_end = if proc_available {
        read_io_bytes(server_pid)
    } else {
        None
    };

    writer_stop.store(true, Ordering::Relaxed);
    sampler_stop.store(true, Ordering::Relaxed);
    let (mut writes_ok, mut writes_err) = (0u64, 0u64);
    for h in writer_handles {
        let (o, e) = h.join().unwrap_or((0, 0));
        writes_ok += o;
        writes_err += e;
    }
    let (peak_rss, final_rss, vm_hwm) =
        sampler.map_or((0, 0, 0), |h| h.join().unwrap_or((0, 0, 0)));

    aggregate_rung(
        clients,
        wall,
        merged,
        connect_errors,
        clk_tck,
        RungSamples {
            cpu: (cpu_start, cpu_end),
            threads_start,
            threads_end,
            io: (io_start, io_end),
            rss: (peak_rss, final_rss, vm_hwm),
            writes: (writes_ok, writes_err),
        },
    )
}

/// One reader worker: connect + login, wait at the barrier, then loop the weighted mix until the
/// shared budget drains. Never panics.
fn run_worker(
    ctx: &BenchCtx,
    issued: &AtomicU64,
    barrier: &Barrier,
    origin: &OnceLock<Instant>,
    families: usize,
    seed: u64,
    budget: u64,
) -> WorkerStats {
    let mut stats = WorkerStats::new(families);
    let mut client = match ctx.target.connect(ctx.read_timeout) {
        Ok(c) => c,
        Err(_) => {
            stats.connect_errors = 1;
            barrier.wait();
            return stats;
        }
    };
    if client.login(&ctx.user, &ctx.password).is_err() {
        stats.connect_errors = 1;
        barrier.wait();
        return stats;
    }
    barrier.wait();
    let t0 = *origin.get_or_init(Instant::now);
    let interval = ctx.arrival_interval();
    let mut rng = SplitMix64::new(seed);
    let u0_pool = ctx.users;
    loop {
        let ticket = issued.fetch_add(1, Ordering::Relaxed);
        if ticket >= budget {
            break;
        }
        let scheduled =
            interval.map(|iv| t0 + iv.saturating_mul(u32::try_from(ticket).unwrap_or(u32::MAX)));
        if let Some(due) = scheduled {
            let now = Instant::now();
            if due > now {
                thread::sleep(due - now);
            }
        }
        // Weighted family pick over the ACTIVE set, with anchors spread across the keyspace.
        let fam_ix = ctx.bag[(rng.next_u64() as usize) % ctx.bag.len()];
        let fam = &battery::ALL[fam_ix];
        let u0 = Generator::user_id(rng.next_u64() % u0_pool);
        let u1 = Generator::user_id(rng.next_u64() % u0_pool);
        let params = op_params(fam.params, &u0, &u1, &ctx.term, ctx.since);
        let op_start = scheduled.unwrap_or_else(Instant::now);
        match client.run(fam.cypher, params, &ctx.db) {
            Ok(_) => {
                let ns = u64::try_from(op_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
                stats.lat[fam_ix].push(ns);
                stats.ok[fam_ix] += 1;
            }
            Err(_) => stats.err[fam_ix] += 1,
        }
    }
    let _ = client.goodbye();
    stats
}

/// Spawns one low-rate writer: a single-anchor `SET` touch of a user's `registered` timestamp — a
/// real write that contends with the readers under MVCC/SSI without a two-anchor scan. Returns
/// `(committed, failed)`.
fn spawn_writer(
    ctx: Arc<BenchCtx>,
    stop: Arc<AtomicBool>,
    rung_ix: usize,
    writer_ix: usize,
) -> JoinHandle<(u64, u64)> {
    thread::spawn(move || {
        let mut client = match ctx.target.connect(ctx.read_timeout) {
            Ok(c) => c,
            Err(_) => return (0, 1),
        };
        if client.login(&ctx.user, &ctx.password).is_err() {
            return (0, 1);
        }
        let mut rng = SplitMix64::new(
            ctx.seed
                .wrapping_add((rung_ix as u64).wrapping_mul(0xA076_1D64_78BD_642F))
                .wrapping_add((writer_ix as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F))
                ^ 0x5757_5252_0000_0001,
        );
        let mut ok = 0u64;
        let mut err = 0u64;
        let mut ts: i64 = EPOCH_S as i64;
        while !stop.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(ctx.write_every_ms));
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let uid = Generator::user_id(rng.next_u64() % ctx.users);
            ts = ts.wrapping_add(1);
            let params = vec![
                ("id".to_string(), Value::String(uid)),
                ("ts".to_string(), Value::Integer(ts)),
            ];
            match client.run(
                "MATCH (u:USER {id: $id}) SET u.registered = $ts",
                params,
                &ctx.db,
            ) {
                Ok(_) => ok += 1,
                Err(_) => err += 1,
            }
        }
        let _ = client.goodbye();
        (ok, err)
    })
}

/// The raw `/proc` + writer samples taken around a rung.
struct RungSamples {
    cpu: (CpuTicks, CpuTicks),
    threads_start: BTreeMap<u64, u64>,
    threads_end: BTreeMap<u64, u64>,
    io: (Option<u64>, Option<u64>),
    rss: (u64, u64, u64),
    writes: (u64, u64),
}

/// Folds the merged worker stats + `/proc` deltas into a [`RungResult`].
fn aggregate_rung(
    clients: usize,
    wall: Duration,
    mut merged: WorkerStats,
    connect_errors: u64,
    clk_tck: u64,
    samples: RungSamples,
) -> RungResult {
    let RungSamples {
        cpu,
        threads_start,
        threads_end,
        io,
        rss,
        writes,
    } = samples;
    let families = battery::ALL.len();
    let wall_secs = wall.as_secs_f64().max(f64::MIN_POSITIVE);

    let mut all_lat: Vec<u64> = Vec::new();
    let mut per_family = Vec::with_capacity(families);
    let mut ok_ops = 0u64;
    let mut err_ops = connect_errors;
    for f in 0..families {
        let spec = &battery::ALL[f];
        let mut lat = std::mem::take(&mut merged.lat[f]);
        lat.sort_unstable();
        all_lat.extend_from_slice(&lat);
        ok_ops += merged.ok[f];
        err_ops += merged.err[f];
        per_family.push(FamilyResult {
            name: spec.name,
            advanced: spec.advanced,
            ok: merged.ok[f],
            err: merged.err[f],
            pcts: bench::summarize(&lat),
        });
    }
    all_lat.sort_unstable();
    let overall = bench::summarize(&all_lat);
    let ops_per_sec = ok_ops as f64 / wall_secs;

    let (cpu_start, cpu_end) = cpu;
    let (cpu_user_secs, cpu_system_secs) = match (cpu_start, cpu_end) {
        (Some((u0, s0)), Some((u1, s1))) => (
            u1.saturating_sub(u0) as f64 / clk_tck as f64,
            s1.saturating_sub(s0) as f64 / clk_tck as f64,
        ),
        _ => (0.0, 0.0),
    };
    let server_cores = (cpu_user_secs + cpu_system_secs) / wall_secs;

    let mut busy_threads = 0usize;
    let mut busiest_core_frac = 0.0f64;
    for (tid, &end_ticks) in &threads_end {
        let start_ticks = threads_start.get(tid).copied().unwrap_or(end_ticks);
        let frac = end_ticks.saturating_sub(start_ticks) as f64 / clk_tck as f64 / wall_secs;
        if frac > BUSY_THREAD_FRACTION {
            busy_threads += 1;
        }
        busiest_core_frac = busiest_core_frac.max(frac);
    }

    let (io_start, io_end) = io;
    let (io_read_bytes, io_available) = match (io_start, io_end) {
        (Some(a), Some(b)) => (b.saturating_sub(a), true),
        _ => (0, false),
    };
    let (peak_rss, final_rss, vm_hwm) = rss;
    let (writes_ok, writes_err) = writes;

    RungResult {
        clients,
        ok_ops,
        err_ops,
        wall_secs,
        ops_per_sec,
        overall,
        per_family,
        cpu_user_secs,
        cpu_system_secs,
        server_cores,
        busy_threads,
        busiest_core_frac,
        peak_rss,
        final_rss,
        vm_hwm,
        io_read_bytes,
        io_available,
        writes_ok,
        writes_err,
    }
}

// ============================================================================================
// /proc sampling primitives (Linux) — thin wrappers over graphus_reco_gen::bench parsers
// ============================================================================================

fn clock_ticks_per_sec() -> u64 {
    std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(100)
}

fn read_total_cpu(pid: i64) -> CpuTicks {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    bench::parse_stat_utime_stime(&s)
}

fn read_io_bytes(pid: i64) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
    bench::parse_proc_io_bytes(&s, "read_bytes").or_else(|| bench::parse_proc_io_bytes(&s, "rchar"))
}

fn snapshot_threads(pid: i64) -> BTreeMap<u64, u64> {
    let mut map = BTreeMap::new();
    let task_dir = format!("/proc/{pid}/task");
    let Ok(entries) = std::fs::read_dir(&task_dir) else {
        return map;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(tid) = name.to_str().and_then(|s| s.parse::<u64>().ok()) else {
            continue;
        };
        if let Ok(s) = std::fs::read_to_string(format!("{task_dir}/{tid}/stat")) {
            if let Some((u, sy)) = bench::parse_stat_utime_stime(&s) {
                map.insert(tid, u.saturating_add(sy));
            }
        }
    }
    map
}

fn spawn_rss_sampler(pid: i64, stop: Arc<AtomicBool>) -> JoinHandle<(u64, u64, u64)> {
    fn sample(path: &str, max_rss: &mut u64, last_rss: &mut u64, hwm: &mut u64) {
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Some(rss) = bench::parse_status_kb_bytes(&s, "VmRSS") {
                *max_rss = (*max_rss).max(rss);
                *last_rss = rss;
            }
            if let Some(h) = bench::parse_status_kb_bytes(&s, "VmHWM") {
                *hwm = (*hwm).max(h);
            }
        }
    }
    thread::spawn(move || {
        let status_path = format!("/proc/{pid}/status");
        let (mut max_rss, mut last_rss, mut hwm) = (0u64, 0u64, 0u64);
        while !stop.load(Ordering::Relaxed) {
            sample(&status_path, &mut max_rss, &mut last_rss, &mut hwm);
            thread::sleep(Duration::from_millis(SAMPLE_INTERVAL_MS));
        }
        sample(&status_path, &mut max_rss, &mut last_rss, &mut hwm);
        (max_rss, last_rss, hwm)
    })
}

// ============================================================================================
// Reporting
// ============================================================================================

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn print_rung_line(r: &RungResult) {
    eprintln!(
        "  rung clients={:>4}: {:>9.1} ops/s | p50={:>7.3}ms p99={:>8.3}ms | cores={:>5.2} busy_thr={:>3} \
         busiest={:>4.2} | rss={:>6.1}MiB | ok={} err={} | writes ok={} err={}",
        r.clients,
        r.ops_per_sec,
        bench::ns_to_ms(r.overall.p50),
        bench::ns_to_ms(r.overall.p99),
        r.server_cores,
        r.busy_threads,
        r.busiest_core_frac,
        mib(r.peak_rss),
        r.ok_ops,
        r.err_ops,
        r.writes_ok,
        r.writes_err,
    );
}

fn print_report(ctx: &BenchCtx, rungs: &[RungResult], proc_available: bool, external: bool) {
    println!(
        "\n=== social_bench: concurrency ladder ({} active families) ===",
        ctx.active.len()
    );
    println!(
        "{:>8} | {:>10} | {:>9} | {:>9} | {:>7} | {:>6} | {:>12}",
        "clients", "ops/s", "p50 ms", "p99 ms", "cores", "busyth", "peak_rss_MiB"
    );
    println!("{}", "-".repeat(80));
    for r in rungs {
        println!(
            "{:>8} | {:>10.1} | {:>9.3} | {:>9.3} | {:>7.2} | {:>6} | {:>12.1}",
            r.clients,
            r.ops_per_sec,
            bench::ns_to_ms(r.overall.p50),
            bench::ns_to_ms(r.overall.p99),
            r.server_cores,
            r.busy_threads,
            mib(r.peak_rss),
        );
    }

    let top = top_rung(rungs);
    println!(
        "\n=== per-family latency @ top rung (clients={}) ===",
        top.clients
    );
    println!(
        "{:>14} | {:>4} | {:>8} | {:>8} | {:>9} | {:>9} | {:>9}",
        "family", "adv", "ok", "err", "p50 ms", "p99 ms", "max ms"
    );
    println!("{}", "-".repeat(84));
    for f in &top.per_family {
        if f.ok == 0 && f.err == 0 {
            continue; // an inactive family (dropped in preflight) — omit from the breakdown
        }
        println!(
            "{:>14} | {:>4} | {:>8} | {:>8} | {:>9.3} | {:>9.3} | {:>9.3}",
            f.name,
            if f.advanced { "yes" } else { "no" },
            f.ok,
            f.err,
            bench::ns_to_ms(f.pcts.p50),
            bench::ns_to_ms(f.pcts.p99),
            bench::ns_to_ms(f.pcts.max),
        );
    }

    println!("\n=== knee diagnosis ===");
    for line in diagnose_knee(rungs, proc_available, external) {
        println!("{line}");
    }
}

/// The client-side throughput-scaling verdict — the core-scaling signal available in attach mode.
fn client_side_scaling_verdict(rungs: &[RungResult]) -> Option<String> {
    let base = rungs.iter().find(|r| r.clients == 1)?;
    let best = best_rung(rungs);
    if base.ops_per_sec <= 0.0 {
        return None;
    }
    let ratio = best.ops_per_sec / base.ops_per_sec;
    let verdict = if best.clients > 1 && ratio >= 1.3 {
        format!(
            "CLIENT-SIDE VERDICT: reads SCALED with concurrency — peak {:.1} ops/s at clients={} is {:.2}× \
             the single-client {:.1} ops/s, so the server served reads across cores (the off-thread reader \
             pool #336/#543 is engaged). Confirm with the /metrics server_metrics delta.",
            best.ops_per_sec, best.clients, ratio, base.ops_per_sec
        )
    } else {
        format!(
            "CLIENT-SIDE VERDICT: reads did NOT scale with concurrency — peak {:.1} ops/s at clients={} is \
             only {:.2}× the single-client {:.1} ops/s, the single-thread-ceiling signature. Cross-check \
             the /metrics server_metrics delta.",
            best.ops_per_sec, best.clients, ratio, base.ops_per_sec
        )
    };
    Some(verdict)
}

fn top_rung(rungs: &[RungResult]) -> &RungResult {
    rungs
        .iter()
        .max_by_key(|r| r.clients)
        .expect("non-empty ladder")
}
fn best_rung(rungs: &[RungResult]) -> &RungResult {
    rungs
        .iter()
        .max_by(|a, b| a.ops_per_sec.total_cmp(&b.ops_per_sec))
        .expect("non-empty ladder")
}

fn diagnose_knee(rungs: &[RungResult], proc_available: bool, external: bool) -> Vec<String> {
    let mut out = Vec::new();
    let best = best_rung(rungs);
    let top = top_rung(rungs);

    out.push(format!(
        "Peak throughput {:.1} ops/s at clients={} (p50={:.3}ms p99={:.3}ms p99.9={:.3}ms).",
        best.ops_per_sec,
        best.clients,
        bench::ns_to_ms(best.overall.p50),
        bench::ns_to_ms(best.overall.p99),
        bench::ns_to_ms(best.overall.p999),
    ));

    if top.clients > best.clients {
        let gain = if best.ops_per_sec > 0.0 {
            (top.ops_per_sec - best.ops_per_sec) / best.ops_per_sec
        } else {
            0.0
        };
        if gain <= PLATEAU_BAND {
            out.push(format!(
                "THROUGHPUT PLATEAUED: raising clients {}→{} changed throughput by {:+.1}% (within the {:.0}% \
                 plateau band) while p99 went {:.3}ms→{:.3}ms. The saturation knee is at ~clients={}.",
                best.clients, top.clients, gain * 100.0, PLATEAU_BAND * 100.0,
                bench::ns_to_ms(best.overall.p99), bench::ns_to_ms(top.overall.p99), best.clients,
            ));
        } else {
            out.push(format!(
                "Throughput was STILL RISING at the top rung: clients {}→{} gained {:+.1}% (beyond the {:.0}% \
                 band); the knee is beyond the tested ladder — extend --ladder.",
                best.clients, top.clients, gain * 100.0, PLATEAU_BAND * 100.0,
            ));
        }
    } else {
        out.push(
            "The ladder's top rung is also its best; extend --ladder to observe the plateau."
                .into(),
        );
    }

    if external {
        out.push(
            "Server core scaling: measured via the target's /metrics before/after delta (see the report.json \
             server_metrics section), NOT /proc — this is a remote/attached instance.".into(),
        );
        if let Some(v) = client_side_scaling_verdict(rungs) {
            out.push(v);
        }
        return out;
    }
    if !proc_available {
        out.push(
            "Server core scaling: NOT MEASURED (/proc sampling unavailable). Re-run on Linux with a readable \
             --server-pid to expose the single-thread vs reader-pool signature.".into(),
        );
        return out;
    }

    out.push(format!(
        "At saturation (clients={}) the server used {:.2} cores across {} busy thread(s); the busiest single \
         thread ran at {:.2} of a core.",
        best.clients, best.server_cores, best.busy_threads, best.busiest_core_frac,
    ));
    let single_thread_ceiling = best.busy_threads <= 1
        || (best.busiest_core_frac >= 0.80 && (best.server_cores - best.busiest_core_frac) < 0.75);
    if single_thread_ceiling {
        out.push(format!(
            "VERDICT: reads hit a SINGLE-THREAD CEILING — one thread near-saturated ({:.2} core) while total \
             server core usage stayed at {:.2}. Throughput is bounded by one engine thread, not the machine's \
             cores (the read path the off-thread reader pool #336/#543 relieves).",
            best.busiest_core_frac, best.server_cores,
        ));
    } else {
        out.push(format!(
            "VERDICT: reads SCALED ACROSS CORES — {} threads were busy and total core usage reached {:.2}, well \
             above any single thread's {:.2}. The read path spread work across cores (the off-thread reader \
             pool #336/#543 is engaged).",
            best.busy_threads, best.server_cores, best.busiest_core_frac,
        ));
    }
    if top.io_available {
        out.push(format!("Server disk read IO at the top rung: {:.1} MiB over the rung (low ⇒ served from the buffer pool).", mib(top.io_read_bytes)));
    }
    out
}

/// Emits the machine-readable client-side stats sentinels `run.sh` forwards to `measure_target`.
fn print_client_stats_sentinels(rungs: &[RungResult], external: bool) {
    let best = best_rung(rungs);
    let (writes_ok, writes_err): (u64, u64) = rungs
        .iter()
        .fold((0, 0), |(o, e), r| (o + r.writes_ok, e + r.writes_err));
    let attempts = writes_ok + writes_err;
    let abort_rate = if attempts > 0 {
        writes_err as f64 / attempts as f64
    } else {
        0.0
    };
    let total_ops: u64 = rungs.iter().map(|r| r.ok_ops).sum();
    let total_secs: f64 = rungs.iter().map(|r| r.wall_secs).sum();
    println!(
        "GRAPHUS_SOCIAL_BENCH_STATS mode={} best_clients={} best_ops_per_sec={:.3} best_ops={} best_secs={:.6} \
         p50_ms={:.4} p99_ms={:.4} p999_ms={:.4} abort_rate={:.6} writers_ok={} writers_err={} total_ops={} total_secs={:.6}",
        if external { "external" } else { "local" },
        best.clients,
        best.ops_per_sec,
        best.ok_ops,
        best.wall_secs,
        bench::ns_to_ms(best.overall.p50),
        bench::ns_to_ms(best.overall.p99),
        bench::ns_to_ms(best.overall.p999),
        abort_rate,
        writes_ok,
        writes_err,
        total_ops,
        total_secs,
    );
    for r in rungs {
        println!(
            "GRAPHUS_SOCIAL_BENCH_RUNG clients={} ops_per_sec={:.3} p50_ms={:.4} p99_ms={:.4} p999_ms={:.4} \
             ok={} err={} secs={:.6} writes_ok={} writes_err={}",
            r.clients,
            r.ops_per_sec,
            bench::ns_to_ms(r.overall.p50),
            bench::ns_to_ms(r.overall.p99),
            bench::ns_to_ms(r.overall.p999),
            r.ok_ops,
            r.err_ops,
            r.wall_secs,
            r.writes_ok,
            r.writes_err,
        );
    }
}

// ============================================================================================
// Evidence (LOCAL only — attach mode's evidence is emitted by measure_target)
// ============================================================================================

/// Emits the standardized `EvidenceReport`, populated MANUALLY from the SERVER-process `/proc` samples
/// (the subject under measurement is the *server*, not this driver). LOCAL mode only.
fn write_evidence(
    dir: &str,
    args: &Args,
    ctx: &BenchCtx,
    rungs: &[RungResult],
    proc_available: bool,
) -> Result<(), String> {
    let best = best_rung(rungs);
    let top = top_rung(rungs);
    let nodes = args.users.saturating_add(args.articles);
    let relationships = args.friends.saturating_add(args.likes);

    let metadata = RunMetadata::new(
        args.scenario.clone(),
        "large social network: concurrent over-the-wire read scaling vs C (server-PID sampled)",
    )
    .with_dataset(DatasetScale::new(nodes, relationships));
    let mut collector = EvidenceCollector::new(metadata);

    let fp = args
        .store_path
        .as_deref()
        .map_or_else(StoreFootprint::default, du_store);
    let (store_bytes, wal_bytes) = (fp.store_bytes(), fp.wal_bytes);

    {
        let total_ops: u64 = rungs.iter().map(|r| r.ok_ops).sum();
        let total_errs: u64 = rungs.iter().map(|r| r.err_ops).sum();
        let active_names: Vec<&str> = ctx.active.iter().map(|&i| battery::ALL[i].name).collect();
        let w = &mut collector.metadata_mut().workload;
        w.insert(
            "connection".into(),
            "bolt (client, per-connection thread)".into(),
        );
        w.insert("scenario_db".into(), args.db.clone());
        w.insert("ladder".into(), args.ladder.clone());
        w.insert("ops_per_rung".into(), args.ops_per_rung.to_string());
        w.insert("rungs".into(), rungs.len().to_string());
        w.insert("seed".into(), args.seed.to_string());
        w.insert("write_every_ms".into(), args.write_every_ms.to_string());
        w.insert("proc_sampling".into(), proc_available.to_string());
        w.insert("active_families".into(), active_names.join(","));
        // The FOUR deterministic structural counts the baseline gate holds (STRING values).
        w.insert("user_count".into(), args.users.to_string());
        w.insert("article_count".into(), args.articles.to_string());
        w.insert("friend_count".into(), args.friends.to_string());
        w.insert("like_count".into(), args.likes.to_string());
        w.insert("node_count".into(), nodes.to_string());
        w.insert("relationship_count".into(), relationships.to_string());
        // Local server on-disk footprint (informational; N/A remotely).
        if args.store_path.is_some() {
            w.insert("store_bytes".into(), store_bytes.to_string());
            w.insert("wal_bytes".into(), wal_bytes.to_string());
        }
        // Headline results (machine-variant, informational).
        w.insert("best_clients".into(), best.clients.to_string());
        w.insert(
            "best_ops_per_sec".into(),
            format!("{:.1}", best.ops_per_sec),
        );
        w.insert(
            "best_p50_ms".into(),
            format!("{:.4}", bench::ns_to_ms(best.overall.p50)),
        );
        w.insert(
            "best_p99_ms".into(),
            format!("{:.4}", bench::ns_to_ms(best.overall.p99)),
        );
        w.insert(
            "best_server_cores".into(),
            format!("{:.3}", best.server_cores),
        );
        w.insert("best_busy_threads".into(), best.busy_threads.to_string());
        w.insert("total_read_ops".into(), total_ops.to_string());
        w.insert("total_read_errors".into(), total_errs.to_string());
    }

    collector.start();
    for r in rungs {
        collector.phase(
            format!("rung C={}", r.clients),
            Duration::from_secs_f64(r.wall_secs),
        );
    }
    // The workload ran BEFORE this report was built, so the collector could not bracket it: hand it
    // the measured ladder wall-time explicitly. Without this the report would time its own emission.
    let workload_secs: f64 = rungs.iter().map(|r| r.wall_secs).sum();
    collector.record_total_duration(Duration::from_secs_f64(workload_secs));
    collector.record_resources((
        CpuSection {
            user_secs: best.cpu_user_secs,
            system_secs: best.cpu_system_secs,
            mean_core_utilisation: best.server_cores,
        },
        MemorySection {
            peak_rss_bytes: best.peak_rss,
            final_rss_bytes: best.final_rss,
        },
    ));
    // The STORAGE vector: in local mode the server is co-located, so its real on-disk footprint is
    // readable. (Remotely there is no filesystem to walk and the section stays zeroed by contract.)
    if args.store_path.is_some() {
        *collector.storage_mut() = StorageSection::from_footprints(
            DiskFootprint::from_bytes(store_bytes),
            DiskFootprint::from_bytes(wal_bytes),
            // fsync proxy: every committed WAL byte is fsynced before the commit is acknowledged.
            wal_bytes,
        );
        // Space amplification of the durable image over the logical graph. `0` logical bytes leaves
        // the ratio at "not measured" rather than inventing one.
        collector.record_amplification(0, args.logical_bytes);
    }

    let total_ops: u64 = rungs.iter().map(|r| r.ok_ops).sum();
    let (writes_ok, writes_err): (u64, u64) = rungs
        .iter()
        .fold((0, 0), |(o, e), r| (o + r.writes_ok, e + r.writes_err));
    let writer_attempts = writes_ok + writes_err;
    let abort_rate = if writer_attempts > 0 {
        writes_err as f64 / writer_attempts as f64
    } else {
        0.0
    };
    {
        let t = collector.throughput_mut();
        t.operations = total_ops;
        t.ops_per_sec = best.ops_per_sec;
        t.p50_latency_ms = bench::ns_to_ms(best.overall.p50);
        t.p99_latency_ms = bench::ns_to_ms(best.overall.p99);
        t.p999_latency_ms = bench::ns_to_ms(best.overall.p999);
        t.abort_rate = abort_rate;
    }

    collector.note(format!(
        "OVER-THE-WIRE CONCURRENCY LADDER ({} rungs over {} against '{}'): the headline is whether SERVER-PID CPU \
         scales with C — reads spreading across cores (reader pool #336/#543) vs a single-thread ceiling. The \
         in-process battery this replaces measured the DRIVER, not the server (a ~1-core artifact).",
        rungs.len(), args.ladder, args.db,
    ));
    for r in rungs {
        collector.note(format!(
            "rung clients={}: {:.1} ops/s over {:.3}s ({} ok, {} err); p50={:.3}ms p90={:.3}ms p99={:.3}ms \
             p99.9={:.3}ms max={:.3}ms; server {:.2} cores across {} busy thread(s), busiest {:.2} core; peak RSS \
             {:.1}MiB (VmHWM {:.1}MiB){}{}",
            r.clients, r.ops_per_sec, r.wall_secs, r.ok_ops, r.err_ops,
            bench::ns_to_ms(r.overall.p50), bench::ns_to_ms(r.overall.p90), bench::ns_to_ms(r.overall.p99),
            bench::ns_to_ms(r.overall.p999), bench::ns_to_ms(r.overall.max), r.server_cores, r.busy_threads,
            r.busiest_core_frac, mib(r.peak_rss), mib(r.vm_hwm),
            if r.io_available { format!("; disk read IO {:.1}MiB", mib(r.io_read_bytes)) } else { String::new() },
            if r.writes_ok + r.writes_err > 0 { format!("; writer {} ok / {} conflict", r.writes_ok, r.writes_err) } else { String::new() },
        ));
    }
    for f in &top.per_family {
        if f.ok == 0 && f.err == 0 {
            continue;
        }
        collector.note(format!(
            "family {} ({}) @ clients={}: {} ok / {} err; p50={:.3}ms p99={:.3}ms max={:.3}ms",
            f.name,
            if f.advanced {
                "advanced traversal"
            } else {
                "point read"
            },
            top.clients,
            f.ok,
            f.err,
            bench::ns_to_ms(f.pcts.p50),
            bench::ns_to_ms(f.pcts.p99),
            bench::ns_to_ms(f.pcts.max),
        ));
    }
    for line in diagnose_knee(rungs, proc_available, false) {
        collector.note(format!("KNEE: {line}"));
    }
    if args.store_path.is_some() {
        collector.note(format!(
            "SERVER ON-DISK FOOTPRINT (local, co-located), measured directly from the server's store directory and \
             DECOMPOSED — a lumped total would blend bytes that scale with the graph with bytes that do not: \
             data image (graphus.store) {:.1}MiB | doublewrite buffers (graphus.dwb) {:.1}MiB | redo log \
             (graphus.wal/seg.<lsn>) {:.1}MiB | catalog/locks {:.1}MiB.",
            mib(fp.data_bytes), mib(fp.dwb_bytes), mib(fp.wal_bytes), mib(fp.other_bytes),
        ));
        if fp.data_bytes > 0 {
            collector.note(format!(
                "STORAGE EFFICIENCY: the redo log is {:.1}x the data image it protects ({:.1}MiB WAL vs {:.1}MiB \
                 data) — it is not checkpointed away over this run. The doublewrite buffers are a FIXED preallocation \
                 ({:.1}MiB total, one per database, independent of graph size), so on a small graph they dominate the \
                 footprint while on a large one they amortise to nothing.",
                fp.wal_bytes as f64 / fp.data_bytes as f64,
                mib(fp.wal_bytes), mib(fp.data_bytes), mib(fp.dwb_bytes),
            ));
        }
        if args.logical_bytes > 0 && fp.data_bytes > 0 {
            collector.note(format!(
                "SPACE AMPLIFICATION: the DATA image is {:.2}x the {:.1}MiB logical graph (the generator's CSV bytes) \
                 — this is the ratio that scales with the graph. Counting every durable byte (data + doublewrite + \
                 WAL = {:.1}MiB) the whole directory is {:.2}x logical, but that figure is dominated by the two \
                 constant-cost items above and must not be read as a per-byte storage cost.",
                fp.data_bytes as f64 / args.logical_bytes as f64, mib(args.logical_bytes),
                mib(store_bytes + wal_bytes),
                (store_bytes + wal_bytes) as f64 / args.logical_bytes as f64,
            ));
        }
    }
    if !proc_available {
        collector.note("SERVER /proc SAMPLING DISABLED (non-Linux or unreadable --server-pid): CPU/RSS/IO zeroed; throughput + latency still stand.");
    }

    let report = collector.finish();
    let evidence_dir = PathBuf::from(dir);
    match report.write_to(&evidence_dir) {
        Ok((json, md)) => {
            eprintln!(
                "social_bench: wrote {} and {}",
                json.display(),
                md.display()
            );
            Ok(())
        }
        Err(e) => Err(format!("{e}")),
    }
}

/// The server's real on-disk footprint, decomposed.
///
/// Reporting a single lumped total is misleading: it blends the graph's data image with a
/// FIXED-SIZE preallocated doublewrite buffer (paid once per database, regardless of graph size) and
/// an un-checkpointed redo log. Only the decomposition tells a reader which bytes scale with the
/// graph and which are constant overhead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct StoreFootprint {
    /// The data image (`graphus.store`) — the bytes that hold the graph itself.
    data_bytes: u64,
    /// The doublewrite buffers (`graphus.dwb`) — preallocated, fixed size, one per database.
    dwb_bytes: u64,
    /// The redo log (`graphus.wal/seg.<lsn>`).
    wal_bytes: u64,
    /// Catalog/lock/config leftovers (`databases.toml`, `security.toml`, `store.lock`, …).
    other_bytes: u64,
}

impl StoreFootprint {
    /// Everything that is not the redo log — the `StorageSection::store_bytes` contract.
    fn store_bytes(&self) -> u64 {
        self.data_bytes
            .saturating_add(self.dwb_bytes)
            .saturating_add(self.other_bytes)
    }
}

/// Best-effort recursive walk of the server store directory, decomposed into a [`StoreFootprint`].
///
/// Classification follows the **path**, not the leaf file name: the server's WAL is a *directory*
/// (`databases/<db>/graphus.wal/`) whose segments are named `seg.<lsn>` and carry no "wal" marker of
/// their own, so a name-only test silently counts every WAL byte as store — hiding the redo log
/// entirely. Returns a zeroed footprint if the path is unreadable.
fn du_store(path: &str) -> StoreFootprint {
    fn name_contains(p: &std::path::Path, needle: &str) -> bool {
        p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.to_ascii_lowercase().contains(needle))
    }
    fn walk(dir: &std::path::Path, in_wal: bool, fp: &mut StoreFootprint) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let wal_here = in_wal || name_contains(&p, "wal");
            if p.is_dir() {
                walk(&p, wal_here, fp);
            } else if let Ok(meta) = entry.metadata() {
                let len = meta.len();
                if wal_here {
                    fp.wal_bytes += len;
                } else if name_contains(&p, ".dwb") {
                    fp.dwb_bytes += len;
                } else if name_contains(&p, ".store") {
                    fp.data_bytes += len;
                } else {
                    fp.other_bytes += len;
                }
            }
        }
    }
    let mut fp = StoreFootprint::default();
    walk(std::path::Path::new(path), false, &mut fp);
    fp
}

// ============================================================================================
// CLI
// ============================================================================================

struct Args {
    socket: Option<String>,
    bolt: Option<String>,
    user: String,
    password: String,
    db: String,
    server_pid: Option<i64>,
    ladder: String,
    ops_per_rung: u64,
    min_ops_per_client: u64,
    users: u64,
    articles: u64,
    friends: u64,
    likes: u64,
    seed: u64,
    scenario: String,
    evidence_dir: Option<String>,
    store_path: Option<String>,
    /// Logical size of the loaded graph (the generator's CSV bytes), for the space-amplification
    /// ratio. `0` = not supplied, and the ratio stays at "not measured" rather than being invented.
    logical_bytes: u64,
    write_every_ms: u64,
    writers: usize,
    target_rps: f64,
    auto_extend: bool,
    read_timeout_ms: u64,
}

impl Args {
    fn target(&self) -> Result<Target, String> {
        match (&self.bolt, &self.socket) {
            (Some(url), None) => Ok(Target::Bolt(BoltUrl::parse(url)?)),
            (None, Some(path)) => Ok(Target::Uds(PathBuf::from(path))),
            (Some(_), Some(_)) => {
                Err("--socket and --bolt are mutually exclusive (pick one transport)".into())
            }
            (None, None) => Err("one of --socket or --bolt is required".into()),
        }
    }

    fn parse() -> Result<Self, String> {
        let mut socket = None;
        let mut bolt = None;
        let mut user = None;
        let mut password = None;
        let mut db = None;
        let mut server_pid = None;
        let mut ladder = None;
        let mut ops_per_rung = None;
        let mut min_ops_per_client = DEFAULT_MIN_OPS_PER_CLIENT;
        let mut users = None;
        let mut articles = None;
        let mut friends = None;
        let mut likes = None;
        let mut seed = 0x50C1_A150_600D_5EEDu64;
        let mut scenario = "social-network-large".to_string();
        let mut evidence_dir = None;
        let mut store_path = None;
        let mut logical_bytes = 0u64;
        let mut write_every_ms = 0u64;
        let mut writers = 1usize;
        let mut target_rps = 0.0f64;
        let mut auto_extend = false;
        let mut read_timeout_ms = 120_000u64;

        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
            match flag.as_str() {
                "--socket" => socket = Some(value()?),
                "--bolt" => bolt = Some(value()?),
                "--user" => user = Some(value()?),
                "--password" => password = Some(value()?),
                "--db" => db = Some(value()?),
                "--server-pid" => {
                    server_pid = Some(
                        value()?
                            .parse()
                            .map_err(|_| "--server-pid must be an integer".to_string())?,
                    )
                }
                "--ladder" => ladder = Some(value()?),
                "--ops-per-rung" => {
                    ops_per_rung =
                        Some(value()?.parse().map_err(|_| {
                            "--ops-per-rung must be a non-negative integer".to_string()
                        })?)
                }
                "--min-ops-per-client" => {
                    min_ops_per_client = parse_u64(&value()?, "--min-ops-per-client")?
                }
                "--users" => users = Some(parse_u64(&value()?, "--users")?),
                "--articles" => articles = Some(parse_u64(&value()?, "--articles")?),
                "--friends" => friends = Some(parse_u64(&value()?, "--friends")?),
                "--likes" => likes = Some(parse_u64(&value()?, "--likes")?),
                "--seed" => seed = parse_u64(&value()?, "--seed")?,
                "--scenario" => scenario = value()?,
                "--evidence-dir" => evidence_dir = Some(value()?),
                "--store-path" => store_path = Some(value()?),
                "--logical-bytes" => {
                    logical_bytes = value()?
                        .parse()
                        .map_err(|_| "bad --logical-bytes".to_string())?
                }
                "--write-every-ms" => write_every_ms = parse_u64(&value()?, "--write-every-ms")?,
                "--writers" => {
                    writers = usize::try_from(parse_u64(&value()?, "--writers")?)
                        .map_err(|_| "--writers is too large".to_string())?
                }
                "--target-rps" => {
                    let v = value()?;
                    target_rps = v.parse().map_err(|_| {
                        format!("--target-rps must be a non-negative number, got {v:?}")
                    })?;
                    if target_rps < 0.0 {
                        return Err("--target-rps must be >= 0".into());
                    }
                }
                "--auto-extend" => auto_extend = true,
                "--read-timeout-ms" => read_timeout_ms = parse_u64(&value()?, "--read-timeout-ms")?,
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown flag {other:?} (try --help)")),
            }
        }

        Ok(Self {
            socket,
            bolt,
            user: user.ok_or("--user is required")?,
            password: password.ok_or("--password is required")?,
            db: db.ok_or("--db is required")?,
            server_pid,
            ladder: ladder.ok_or("--ladder is required (e.g. 1,2,4,8)")?,
            ops_per_rung: ops_per_rung.ok_or("--ops-per-rung is required")?,
            min_ops_per_client,
            users: users.ok_or("--users is required")?,
            articles: articles.ok_or("--articles is required")?,
            friends: friends.ok_or("--friends is required")?,
            likes: likes.ok_or("--likes is required")?,
            seed,
            scenario,
            evidence_dir,
            store_path,
            logical_bytes,
            write_every_ms,
            writers,
            target_rps,
            auto_extend,
            read_timeout_ms: {
                if read_timeout_ms == 0 {
                    return Err("--read-timeout-ms must be > 0".into());
                }
                read_timeout_ms
            },
        })
    }
}

fn parse_u64(s: &str, flag: &str) -> Result<u64, String> {
    s.parse()
        .map_err(|_| format!("{flag} must be a non-negative integer, got {s:?}"))
}

fn print_usage() {
    eprintln!(
        "usage: social_bench (--socket <path> --server-pid <pid> | --bolt <bolt+ssc://host:7687>) \\\n\
         \x20   --user <name> --password <pw> --db <name> \\\n\
         \x20   --ladder <csv e.g. 1,2,4,8> --ops-per-rung <N> \\\n\
         \x20   --users <N> --articles <N> --friends <N> --likes <N> [--seed <u64>] \\\n\
         \x20   [--min-ops-per-client <N default 150>] [--scenario social-network-large] \\\n\
         \x20   [--evidence-dir <dir>] [--store-path <server store dir>] [--logical-bytes <N>] \\\n\
         \x20   [--write-every-ms <ms default 0>] [--writers <N default 1>] \\\n\
         \x20   [--target-rps <R default 0 = closed-loop>] [--auto-extend] [--read-timeout-ms <ms default 120000>]"
    );
}

#[cfg(test)]
mod tests {
    use super::du_store;

    /// The server's WAL is a DIRECTORY of `seg.<lsn>` files, so a classifier that only looks at the
    /// leaf file name counts every WAL byte as store — reporting `wal_bytes = 0` and hiding the redo
    /// log entirely. This pins the real on-disk layout, and the decomposition that keeps the
    /// fixed-cost doublewrite buffer from being mistaken for graph data (regression for both bugs).
    #[test]
    fn du_store_decomposes_the_real_server_layout() {
        let root = std::env::temp_dir().join(format!("gsocial-du-{}", std::process::id()));
        let db = root.join("databases").join("socialdb");
        let wal = db.join("graphus.wal");
        std::fs::create_dir_all(&wal).expect("layout");

        std::fs::write(db.join("graphus.store"), vec![0u8; 4096]).expect("data image");
        std::fs::write(db.join("graphus.dwb"), vec![0u8; 1024]).expect("doublewrite");
        std::fs::write(root.join("databases.toml"), vec![0u8; 64]).expect("catalog");
        // WAL segments: named `seg.<lsn>` — no "wal" in the leaf name, only in the parent directory.
        std::fs::write(wal.join("seg.00000000000000000008"), vec![0u8; 8192]).expect("seg8");
        std::fs::write(wal.join("seg.00000000000000000009"), vec![0u8; 256]).expect("seg9");

        let fp = du_store(root.to_str().expect("utf8"));
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(
            fp.wal_bytes,
            8192 + 256,
            "WAL segments must be counted as WAL, not store"
        );
        assert_eq!(
            fp.data_bytes, 4096,
            "only graphus.store holds the graph itself"
        );
        assert_eq!(
            fp.dwb_bytes, 1024,
            "the doublewrite buffer is fixed overhead, not graph data"
        );
        assert_eq!(fp.other_bytes, 64, "catalog bytes are neither data nor WAL");
        assert_eq!(
            fp.store_bytes(),
            4096 + 1024 + 64,
            "store_bytes = everything that is not WAL"
        );
    }
}
