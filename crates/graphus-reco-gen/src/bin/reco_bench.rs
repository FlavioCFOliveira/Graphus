//! `reco_bench` — the **concurrent UDS-Bolt read driver**, the heart of the
//! `examples/product-recommendation` performance evaluation (`rmp #541`).
//!
//! It drives **many simultaneous read-only Bolt-over-UDS connections** against an already-loaded
//! recommendation database (`recodb`) and **exposes the server's read-path bottleneck**. It sweeps a
//! **concurrency ladder** — an increasing number of simultaneous connections — and, for each rung:
//!
//! 1. spawns `C` worker OS threads, each owning its **own** [`BoltClient`] over its own UDS
//!    connection, all released together by a start [`Barrier`], each looping a **weighted mix** of
//!    the recommendation read battery ([`queries::READ_BATTERY`]) against `recodb` until a shared
//!    op budget is drained;
//! 2. optionally runs **one** low-rate writer thread issuing [`queries::WRITE_PURCHASE`] concurrently
//!    (the "poucas escritas"), so the readers contend with a live writer under MVCC/SSI;
//! 3. samples the **server process** via `/proc/<server-pid>` on a background thread: total + per-
//!    thread CPU (from `stat`), peak/current RSS (`status`), and IO bytes (`io`, if readable);
//! 4. aggregates client throughput + latency percentiles (overall and per family) and the server's
//!    core utilisation, busy-thread count, busiest-thread core fraction, and peak RSS.
//!
//! After the ladder it prints a human table, a per-family latency breakdown at the top rung, and a
//! **knee diagnosis**: where throughput saturated while p99 latency kept climbing, and how many
//! server cores/threads were busy at saturation — the empirical signature of the single engine thread
//! versus the off-thread reader pool (`#336`/`#527`). With `--evidence-dir` it emits the standardized
//! [`EvidenceReport`] (`report.json` + `report.md`) via [`graphus_examples_harness`], populated
//! **manually** from the server-process `/proc` samples (NOT the harness's own self-metering — the
//! subject under measurement is the *server*, not this driver).
//!
//! It is a **client-only** binary: it links `graphus-bolt` + `graphus-core` +
//! `graphus-examples-harness` and speaks the wire — it never links the engine, so it adds nothing to
//! the server build and can hammer a server in another process (or on another host, over the socket).
//!
//! # Usage
//!
//! ```text
//! reco_bench --socket <path> --user <name> --password <pw> --db <name> --server-pid <pid> \
//!            --ladder 1,2,4,8,16 --ops-per-rung <N> \
//!            --users <N> --products <N> --friends <N> --purchased <N> \
//!            [--scenario product-recommendations] [--evidence-dir <dir>] \
//!            [--write-every-ms <ms>] [--read-timeout-ms <ms>] [--seed <u64>]
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_examples_harness::{
    CpuSection, DatasetScale, EvidenceCollector, MemorySection, RunMetadata,
};
use graphus_reco_gen::bench::{self, Pcts};
use graphus_reco_gen::client::BoltClient;
use graphus_reco_gen::{EPOCH_S, Generator, SplitMix64, queries};

/// How often the background sampler polls `/proc/<pid>/status` for RSS, in milliseconds.
const SAMPLE_INTERVAL_MS: u64 = 50;

/// A thread counts as "busy" over a rung if it consumed more than this fraction of one core.
const BUSY_THREAD_FRACTION: f64 = 0.05;

/// The per-rung reader error-rate above which the run is considered broken (nonzero exit). Server
/// `FAILURE`s and transport faults count; **zero-row results do not** (they are successful reads).
const MAX_ERROR_RATE: f64 = 0.05;

/// The plateau band for the knee diagnosis: if the highest-concurrency rung's throughput is within
/// this fraction of the best rung's, throughput is treated as saturated (adding clients stopped
/// buying throughput).
const PLATEAU_BAND: f64 = 0.10;

/// A cumulative `(utime, stime)` clock-ticks snapshot from `/proc/<pid>/stat`; `None` when the
/// server process is not observable via `/proc` (e.g. non-Linux).
type CpuTicks = Option<(u64, u64)>;

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("reco_bench: error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the whole ladder. Returns `Ok(true)` on a clean run, `Ok(false)` if a rung's reader error
/// rate breached [`MAX_ERROR_RATE`], and `Err` on a fatal setup error.
fn run() -> Result<bool, String> {
    let args = Args::parse()?;

    let ladder = bench::parse_ladder(&args.ladder)?;
    let ctx = Arc::new(BenchCtx {
        socket: PathBuf::from(&args.socket),
        user: args.user.clone(),
        password: args.password.clone(),
        db: args.db.clone(),
        read_timeout: Duration::from_millis(args.read_timeout_ms),
        users: args.users.max(1),
        products: args.products.max(1),
        ops_per_rung: args.ops_per_rung,
        write_every_ms: args.write_every_ms,
        seed: args.seed,
    });

    // Is `/proc/<pid>` observable? On Linux it is; elsewhere (or for an unreadable pid) we skip the
    // server-resource sampling gracefully and note it — the throughput/latency evidence still stands.
    let proc_available = read_total_cpu(args.server_pid).is_some();
    let clk_tck = clock_ticks_per_sec();
    if !proc_available {
        eprintln!(
            "reco_bench: /proc/{}/stat is not observable (non-Linux, or pid not owned/alive) — \
             server CPU/RSS/IO sampling is DISABLED; throughput + latency evidence is still valid.",
            args.server_pid
        );
    }

    eprintln!(
        "reco_bench: socket={} db={} pid={} ladder={:?} ops/rung={} users={} products={} \
         write_every_ms={} clk_tck={clk_tck} proc_sampling={}",
        args.socket,
        args.db,
        args.server_pid,
        ladder,
        args.ops_per_rung,
        ctx.users,
        ctx.products,
        args.write_every_ms,
        proc_available,
    );

    let mut rungs: Vec<RungResult> = Vec::with_capacity(ladder.len());
    for (rung_ix, &clients) in ladder.iter().enumerate() {
        let result = drive_rung(
            &ctx,
            rung_ix,
            clients,
            args.server_pid,
            proc_available,
            clk_tck,
        );
        print_rung_line(&result);
        rungs.push(result);
    }

    if rungs.is_empty() {
        return Err("empty ladder produced no rungs".to_string());
    }

    print_report(&rungs, proc_available);

    if let Some(dir) = &args.evidence_dir {
        write_evidence(dir, &args, &ladder, &rungs, proc_available)
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
                    "reco_bench: FAIL rung clients={}: reader error rate {:.1}% ({} of {} ops) \
                     exceeds the {:.0}% threshold",
                    r.clients,
                    rate * 100.0,
                    r.err_ops,
                    attempts,
                    MAX_ERROR_RATE * 100.0,
                );
                ok = false;
            }
        }
    }
    if ok {
        eprintln!(
            "reco_bench: OK — every rung stayed under the {:.0}% reader-error threshold.",
            MAX_ERROR_RATE * 100.0
        );
    }
    Ok(ok)
}

// ============================================================================================
// Rung driver
// ============================================================================================

/// Immutable per-run configuration shared (via `Arc`) with every worker/writer thread.
struct BenchCtx {
    socket: PathBuf,
    user: String,
    password: String,
    db: String,
    read_timeout: Duration,
    users: u64,
    products: u64,
    ops_per_rung: u64,
    write_every_ms: u64,
    seed: u64,
}

/// One worker thread's accumulated per-family stats.
struct WorkerStats {
    /// Per family index: the nanosecond latencies of successful ops.
    lat: Vec<Vec<u64>>,
    /// Per family index: count of successful ops.
    ok: Vec<u64>,
    /// Per family index: count of errored ops (server `FAILURE` or transport fault).
    err: Vec<u64>,
    /// Connection/login failures for this worker (0 or 1) — a rung-level error, not a family one.
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
    // ---- server-process resources over the rung (all zero when proc sampling is disabled) --------
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
    // ---- writer ----------------------------------------------------------------------------------
    writes_ok: u64,
    writes_err: u64,
}

/// Drives a single rung of `clients` concurrent connections and returns its aggregated result.
fn drive_rung(
    ctx: &Arc<BenchCtx>,
    rung_ix: usize,
    clients: usize,
    server_pid: i64,
    proc_available: bool,
    clk_tck: u64,
) -> RungResult {
    let families = queries::READ_BATTERY.len();
    let issued = Arc::new(AtomicU64::new(0));
    // Barrier over the `clients` workers + this driver thread, so the measured window brackets the
    // load loop exactly (every worker connects + logs in, then waits; the driver waits too; when the
    // barrier releases the driver starts the clock and takes the CPU/IO/thread snapshot).
    let barrier = Arc::new(Barrier::new(clients + 1));

    // ---- background RSS sampler (peak/current VmRSS, peak VmHWM) --------------------------------
    let sampler_stop = Arc::new(AtomicBool::new(false));
    let sampler = if proc_available {
        Some(spawn_rss_sampler(server_pid, Arc::clone(&sampler_stop)))
    } else {
        None
    };

    // ---- optional low-rate writer ---------------------------------------------------------------
    let writer_stop = Arc::new(AtomicBool::new(false));
    let writer = if ctx.write_every_ms > 0 {
        Some(spawn_writer(
            Arc::clone(ctx),
            Arc::clone(&writer_stop),
            rung_ix,
        ))
    } else {
        None
    };

    // ---- reader workers -------------------------------------------------------------------------
    let mut handles: Vec<JoinHandle<WorkerStats>> = Vec::with_capacity(clients);
    for w in 0..clients {
        let ctx = Arc::clone(ctx);
        let issued = Arc::clone(&issued);
        let barrier = Arc::clone(&barrier);
        // A per-(rung,worker) seed so distinct connections hit distinct ids rather than all pounding
        // the same anchor (which would flatter the cache unrealistically).
        let seed = ctx
            .seed
            .wrapping_add((rung_ix as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
            .wrapping_add((w as u64).wrapping_mul(0xD1B5_4A32_D192_ED03));
        handles.push(thread::spawn(move || {
            run_worker(&ctx, &issued, &barrier, families, seed)
        }));
    }

    // The driver joins the barrier: when it releases, all workers are connected and about to loop.
    barrier.wait();
    let t0 = Instant::now();
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

    // Join the readers.
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
            Err(_) => {
                // A worker thread panicked (should never happen — the worker never unwraps on I/O);
                // count it as an error so the exit gate can react rather than silently dropping it.
                connect_errors += 1;
            }
        }
    }
    let wall = t0.elapsed();

    // End snapshots (taken right after the readers finished, before stopping the sampler/writer).
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

    // Stop and join the background threads.
    writer_stop.store(true, Ordering::Relaxed);
    sampler_stop.store(true, Ordering::Relaxed);
    let (writes_ok, writes_err) = writer.map_or((0, 0), |h| h.join().unwrap_or((0, 0)));
    let (peak_rss, final_rss, vm_hwm) =
        sampler.map_or((0, 0, 0), |h| h.join().unwrap_or((0, 0, 0)));

    let samples = RungSamples {
        cpu: (cpu_start, cpu_end),
        threads_start,
        threads_end,
        io: (io_start, io_end),
        rss: (peak_rss, final_rss, vm_hwm),
        writes: (writes_ok, writes_err),
    };
    aggregate_rung(clients, wall, merged, connect_errors, clk_tck, samples)
}

/// One reader worker: connect + login, wait at the barrier, then loop the weighted read mix until the
/// shared op budget is exhausted. Never panics; a connect/login failure is recorded and the worker
/// still joins the barrier so the rung cannot deadlock.
fn run_worker(
    ctx: &BenchCtx,
    issued: &AtomicU64,
    barrier: &Barrier,
    families: usize,
    seed: u64,
) -> WorkerStats {
    let mut stats = WorkerStats::new(families);

    let mut client = match BoltClient::connect_uds(&ctx.socket, ctx.read_timeout) {
        Ok(c) => c,
        Err(_) => {
            stats.connect_errors = 1;
            barrier.wait(); // MUST still release the barrier.
            return stats;
        }
    };
    if client.login(&ctx.user, &ctx.password).is_err() {
        stats.connect_errors = 1;
        barrier.wait();
        return stats;
    }

    // All workers ready — release together.
    barrier.wait();

    let mut rng = SplitMix64::new(seed);
    loop {
        let ticket = issued.fetch_add(1, Ordering::Relaxed);
        if ticket >= ctx.ops_per_rung {
            break;
        }
        let spec = queries::pick(rng.next_u64());
        let fam = bench::family_index(spec);
        let id = Generator::user_id(rng.next_u64() % ctx.users);
        let params = vec![("id".to_string(), Value::String(id))];
        match client.run(spec.cypher, params, &ctx.db) {
            Ok(qr) => {
                let ns = u64::try_from(qr.elapsed.as_nanos()).unwrap_or(u64::MAX);
                stats.lat[fam].push(ns);
                stats.ok[fam] += 1;
            }
            Err(_) => stats.err[fam] += 1,
        }
    }

    let _ = client.goodbye();
    stats
}

/// Spawns the single low-rate writer for a rung. It connects, then issues [`queries::WRITE_PURCHASE`]
/// every `write_every_ms` until stopped, counting committed writes and write-failures (SSI aborts /
/// conflicts) separately. Returns `(committed, failed)`.
fn spawn_writer(
    ctx: Arc<BenchCtx>,
    stop: Arc<AtomicBool>,
    rung_ix: usize,
) -> JoinHandle<(u64, u64)> {
    thread::spawn(move || {
        let mut client = match BoltClient::connect_uds(&ctx.socket, ctx.read_timeout) {
            Ok(c) => c,
            Err(_) => return (0, 1),
        };
        if client.login(&ctx.user, &ctx.password).is_err() {
            return (0, 1);
        }
        let mut rng = SplitMix64::new(
            ctx.seed
                .wrapping_add((rung_ix as u64).wrapping_mul(0xA076_1D64_78BD_642F))
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
            let pid = Generator::product_id(rng.next_u64() % ctx.products);
            ts = ts.wrapping_add(1);
            let params = vec![
                ("uid".to_string(), Value::String(uid)),
                ("pid".to_string(), Value::String(pid)),
                ("ts".to_string(), Value::Integer(ts)),
            ];
            match client.run(queries::WRITE_PURCHASE, params, &ctx.db) {
                Ok(_) => ok += 1,
                Err(_) => err += 1,
            }
        }
        let _ = client.goodbye();
        (ok, err)
    })
}

/// The raw `/proc` + writer samples taken around a rung, folded by [`aggregate_rung`]. Grouped into
/// one struct so the aggregation entry point stays within a sane argument count.
struct RungSamples {
    /// `(start, end)` cumulative `(utime, stime)` ticks of the whole server process.
    cpu: (CpuTicks, CpuTicks),
    /// Per-thread cumulative `(utime + stime)` ticks at rung start / end, keyed by tid.
    threads_start: BTreeMap<u64, u64>,
    threads_end: BTreeMap<u64, u64>,
    /// `(start, end)` `/proc/<pid>/io` read-bytes counter (`None` when unreadable).
    io: (Option<u64>, Option<u64>),
    /// `(peak_vm_rss, final_vm_rss, vm_hwm)` bytes from the RSS sampler.
    rss: (u64, u64, u64),
    /// `(committed, failed)` writer transactions over the rung.
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
    let families = queries::READ_BATTERY.len();
    let wall_secs = wall.as_secs_f64().max(f64::MIN_POSITIVE);

    // Per-family + overall percentiles.
    let mut all_lat: Vec<u64> = Vec::new();
    let mut per_family = Vec::with_capacity(families);
    let mut ok_ops = 0u64;
    let mut err_ops = connect_errors;
    for f in 0..families {
        let spec = &queries::READ_BATTERY[f];
        // Move this family's latency buffer out of `merged` (no clone), sort once, then fold it into
        // both the overall distribution and this family's own percentiles.
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

    // CPU over the rung.
    let (cpu_start, cpu_end) = cpu;
    let (cpu_user_secs, cpu_system_secs) = match (cpu_start, cpu_end) {
        (Some((u0, s0)), Some((u1, s1))) => {
            let du = u1.saturating_sub(u0) as f64 / clk_tck as f64;
            let ds = s1.saturating_sub(s0) as f64 / clk_tck as f64;
            (du, ds)
        }
        _ => (0.0, 0.0),
    };
    let server_cores = (cpu_user_secs + cpu_system_secs) / wall_secs;

    // Per-thread CPU: how many threads burned > BUSY_THREAD_FRACTION of a core, and the busiest one.
    let mut busy_threads = 0usize;
    let mut busiest_core_frac = 0.0f64;
    for (tid, &end_ticks) in &threads_end {
        let start_ticks = threads_start.get(tid).copied().unwrap_or(end_ticks);
        let delta = end_ticks.saturating_sub(start_ticks) as f64 / clk_tck as f64;
        let frac = delta / wall_secs;
        if frac > BUSY_THREAD_FRACTION {
            busy_threads += 1;
        }
        busiest_core_frac = busiest_core_frac.max(frac);
    }

    // IO delta (may be unavailable if /proc/<pid>/io is permission-restricted).
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
// /proc sampling primitives (Linux)
// ============================================================================================

/// Reads the ticks-per-second (`_SC_CLK_TCK`) once via `getconf CLK_TCK`, the ticks the `/proc`
/// `utime`/`stime` fields are denominated in. Defaults to `100` (the Linux near-universal value) if
/// `getconf` is absent or unparseable — no libc dependency.
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

/// Reads the server process's cumulative `(utime, stime)` in clock ticks from `/proc/<pid>/stat`.
fn read_total_cpu(pid: i64) -> CpuTicks {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    bench::parse_stat_utime_stime(&s)
}

/// Reads the server process's `read_bytes` (falling back to `rchar`) from `/proc/<pid>/io`. Returns
/// `None` if the file is unreadable (permission-restricted) or the counter is absent.
fn read_io_bytes(pid: i64) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
    bench::parse_proc_io_bytes(&s, "read_bytes").or_else(|| bench::parse_proc_io_bytes(&s, "rchar"))
}

/// Snapshots every thread's cumulative `(utime + stime)` ticks, keyed by tid, from
/// `/proc/<pid>/task/<tid>/stat`. Robust to threads appearing/disappearing between snapshots: the
/// aggregation joins on tid.
fn snapshot_threads(pid: i64) -> BTreeMap<u64, u64> {
    let mut map = BTreeMap::new();
    let task_dir = format!("/proc/{pid}/task");
    let Ok(entries) = std::fs::read_dir(&task_dir) else {
        return map;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(tid_str) = name.to_str() else {
            continue;
        };
        let Ok(tid) = tid_str.parse::<u64>() else {
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

/// Spawns the background RSS sampler. It polls `/proc/<pid>/status` every [`SAMPLE_INTERVAL_MS`]
/// until `stop` is set, tracking the max `VmRSS`, the last `VmRSS`, and the peak `VmHWM`. Returns
/// `(peak_vm_rss, final_vm_rss, vm_hwm)` in bytes.
fn spawn_rss_sampler(pid: i64, stop: Arc<AtomicBool>) -> JoinHandle<(u64, u64, u64)> {
    /// One `/proc/<pid>/status` sample, folding `VmRSS` (max + last) and `VmHWM` (peak).
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
        let mut max_rss = 0u64;
        let mut last_rss = 0u64;
        let mut hwm = 0u64;
        while !stop.load(Ordering::Relaxed) {
            sample(&status_path, &mut max_rss, &mut last_rss, &mut hwm);
            thread::sleep(Duration::from_millis(SAMPLE_INTERVAL_MS));
        }
        // One final sample so the end-of-rung RSS is captured even if the loop slept through it.
        sample(&status_path, &mut max_rss, &mut last_rss, &mut hwm);
        (max_rss, last_rss, hwm)
    })
}

// ============================================================================================
// Reporting
// ============================================================================================

/// Prints a one-line progress summary for a rung as it completes.
fn print_rung_line(r: &RungResult) {
    eprintln!(
        "  rung clients={:>4}: {:>9.1} ops/s | p50={:>7.3}ms p99={:>8.3}ms | \
         cores={:>5.2} busy_thr={:>3} busiest={:>4.2} | rss={:>6.1}MiB | ok={} err={} | writes ok={} err={}",
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

/// Prints the human summary table, the per-family breakdown at the top rung, and the knee diagnosis.
fn print_report(rungs: &[RungResult], proc_available: bool) {
    println!("\n=== reco_bench: concurrency ladder ===");
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

    // Per-family latency breakdown at the TOP rung (the highest-concurrency one).
    let top = top_rung(rungs);
    println!(
        "\n=== per-family latency @ top rung (clients={}) ===",
        top.clients
    );
    println!(
        "{:>12} | {:>4} | {:>8} | {:>8} | {:>9} | {:>9} | {:>9}",
        "family", "adv", "ok", "err", "p50 ms", "p99 ms", "max ms"
    );
    println!("{}", "-".repeat(80));
    for f in &top.per_family {
        println!(
            "{:>12} | {:>4} | {:>8} | {:>8} | {:>9.3} | {:>9.3} | {:>9.3}",
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
    for line in diagnose_knee(rungs, proc_available) {
        println!("{line}");
    }
}

/// The rung with the highest client count (ties resolved to the last such rung).
fn top_rung(rungs: &[RungResult]) -> &RungResult {
    rungs
        .iter()
        .max_by_key(|r| r.clients)
        .expect("INVARIANT: caller guarantees a non-empty ladder")
}

/// The rung with the highest throughput (the saturation point). Ties resolved to the first.
fn best_rung(rungs: &[RungResult]) -> &RungResult {
    rungs
        .iter()
        .max_by(|a, b| a.ops_per_sec.total_cmp(&b.ops_per_sec))
        .expect("INVARIANT: caller guarantees a non-empty ladder")
}

/// Produces the knee-diagnosis narrative: where throughput peaked, whether it plateaued while p99
/// climbed, and — the headline — how many server cores/threads were busy at saturation, i.e. whether
/// reads scaled across cores or hit a single-thread ceiling.
fn diagnose_knee(rungs: &[RungResult], proc_available: bool) -> Vec<String> {
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

    // Plateau: did the highest-concurrency rung fail to beat the best by more than PLATEAU_BAND while
    // its p99 latency rose? That is the classic saturation knee.
    if top.clients > best.clients {
        let gain = if best.ops_per_sec > 0.0 {
            (top.ops_per_sec - best.ops_per_sec) / best.ops_per_sec
        } else {
            0.0
        };
        let p99_rose = top.overall.p99 > best.overall.p99;
        if gain <= PLATEAU_BAND {
            out.push(format!(
                "THROUGHPUT PLATEAUED: raising clients {}→{} changed throughput by {:+.1}% (within \
                 the {:.0}% plateau band) while p99 latency went {:.3}ms→{:.3}ms ({}). Extra clients \
                 bought latency, not throughput — the saturation knee is at ~clients={}.",
                best.clients,
                top.clients,
                gain * 100.0,
                PLATEAU_BAND * 100.0,
                bench::ns_to_ms(best.overall.p99),
                bench::ns_to_ms(top.overall.p99),
                if p99_rose { "p99 rose" } else { "p99 did not rise" },
                best.clients,
            ));
        } else {
            out.push(format!(
                "Throughput was STILL RISING at the top rung: clients {}→{} gained {:+.1}% (beyond \
                 the {:.0}% plateau band); the knee is beyond the tested ladder — extend --ladder to \
                 find it.",
                best.clients,
                top.clients,
                gain * 100.0,
                PLATEAU_BAND * 100.0,
            ));
        }
    } else {
        out.push(
            "The ladder's top rung is also its best; extend --ladder to observe the plateau."
                .to_string(),
        );
    }

    if !proc_available {
        out.push(
            "Server core scaling: NOT MEASURED (/proc sampling was unavailable). Re-run on Linux \
             with a readable --server-pid to expose the single-engine-thread vs reader-pool signature."
                .to_string(),
        );
        return out;
    }

    // The headline: cores/threads busy at saturation.
    out.push(format!(
        "At saturation (clients={}) the server used {:.2} cores across {} busy thread(s); the busiest \
         single thread ran at {:.2} of a core.",
        best.clients, best.server_cores, best.busy_threads, best.busiest_core_frac,
    ));

    // Interpret: single-thread ceiling vs multi-core scaling.
    let single_thread_ceiling = best.busy_threads <= 1
        || (best.busiest_core_frac >= 0.80 && (best.server_cores - best.busiest_core_frac) < 0.75);
    if single_thread_ceiling {
        out.push(format!(
            "VERDICT: reads hit a SINGLE-THREAD CEILING — one thread near-saturated ({:.2} core) while \
             the server's total core usage stayed at {:.2}. Throughput is bounded by one engine thread, \
             not by the machine's cores; this is the single-writer/single-engine-thread read path the \
             off-thread reader pool (#336/#527) is meant to relieve.",
            best.busiest_core_frac, best.server_cores,
        ));
    } else {
        out.push(format!(
            "VERDICT: reads SCALED ACROSS CORES — {} threads were busy and total core usage reached \
             {:.2}, well above any single thread's {:.2}. The read path spread work across cores (the \
             off-thread reader pool #336/#527 is engaged).",
            best.busy_threads, best.server_cores, best.busiest_core_frac,
        ));
    }

    if top.io_available {
        out.push(format!(
            "Server disk read IO at the top rung: {:.1} MiB over the rung (reads are largely served \
             from the buffer pool when this stays low).",
            mib(top.io_read_bytes),
        ));
    } else {
        out.push(
            "Server disk read IO: /proc/<pid>/io was not readable (permission-restricted) — IO delta \
             unavailable."
                .to_string(),
        );
    }

    out
}

// ============================================================================================
// Evidence
// ============================================================================================

/// Emits the standardized [`EvidenceReport`] for the run, populated MANUALLY from the server-process
/// `/proc` samples (the harness's own self-metering is deliberately NOT used — the subject under
/// measurement is the *server* process, not this driver).
fn write_evidence(
    dir: &str,
    args: &Args,
    ladder: &[usize],
    rungs: &[RungResult],
    proc_available: bool,
) -> Result<(), String> {
    let best = best_rung(rungs);
    let top = top_rung(rungs);

    let nodes = args.users.saturating_add(args.products);
    let relationships = args.friends.saturating_add(args.purchased);

    let metadata = RunMetadata::new(
        args.scenario.clone(),
        "read-heavy product recommendations: concurrent read scaling",
    )
    .with_dataset(DatasetScale::new(nodes, relationships));
    let mut collector = EvidenceCollector::new(metadata);

    // Workload params: the ladder shape + the FOUR structural counts (STRING values — the baseline
    // gate reads these) + the headline throughput/latency figures.
    {
        let total_ops: u64 = rungs.iter().map(|r| r.ok_ops).sum();
        let total_errs: u64 = rungs.iter().map(|r| r.err_ops).sum();
        let w = &mut collector.metadata_mut().workload;
        w.insert(
            "connection".into(),
            "uds-bolt (client, per-connection thread)".into(),
        );
        w.insert("scenario_db".into(), args.db.clone());
        w.insert("ladder".into(), args.ladder.clone());
        w.insert("ops_per_rung".into(), args.ops_per_rung.to_string());
        w.insert("rungs".into(), ladder.len().to_string());
        w.insert("seed".into(), args.seed.to_string());
        w.insert("write_every_ms".into(), args.write_every_ms.to_string());
        w.insert("proc_sampling".into(), proc_available.to_string());
        // The FOUR deterministic structural counts the baseline gate holds (STRING values).
        w.insert("user_count".into(), args.users.to_string());
        w.insert("product_count".into(), args.products.to_string());
        w.insert("friend_count".into(), args.friends.to_string());
        w.insert("purchased_count".into(), args.purchased.to_string());
        w.insert("node_count".into(), nodes.to_string());
        w.insert("relationship_count".into(), relationships.to_string());
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
            "best_p999_ms".into(),
            format!("{:.4}", bench::ns_to_ms(best.overall.p999)),
        );
        w.insert(
            "best_server_cores".into(),
            format!("{:.3}", best.server_cores),
        );
        w.insert("best_busy_threads".into(), best.busy_threads.to_string());
        w.insert(
            "best_busiest_core_frac".into(),
            format!("{:.3}", best.busiest_core_frac),
        );
        w.insert("total_read_ops".into(), total_ops.to_string());
        w.insert("total_read_errors".into(), total_errs.to_string());
    }

    collector.start();

    // One phase per rung (wall-clock of the rung's load window).
    for r in rungs {
        collector.phase(
            format!("rung C={}", r.clients),
            Duration::from_secs_f64(r.wall_secs),
        );
    }

    // Resources (CPU + memory) from the BEST rung — measured on the SERVER process via /proc.
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

    // Throughput + latency (best rung overall) + writer abort rate.
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

    // Notes: a per-rung line, a per-family line at the top rung, and the knee diagnosis.
    collector.note(format!(
        "CONCURRENCY LADDER (read-heavy, {} rungs over {} against '{}'): the headline evidence is \
         where throughput SATURATES while latency explodes and only a subset of cores stay busy — the \
         single-engine-thread vs off-thread-reader-pool signature.",
        rungs.len(),
        args.ladder,
        args.db,
    ));
    for r in rungs {
        collector.note(format!(
            "rung clients={}: {:.1} ops/s over {:.3}s ({} ok, {} err); p50={:.3}ms p90={:.3}ms \
             p99={:.3}ms p99.9={:.3}ms max={:.3}ms; server {:.2} cores across {} busy thread(s), \
             busiest {:.2} core; peak RSS {:.1}MiB (VmHWM {:.1}MiB){}{}",
            r.clients,
            r.ops_per_sec,
            r.wall_secs,
            r.ok_ops,
            r.err_ops,
            bench::ns_to_ms(r.overall.p50),
            bench::ns_to_ms(r.overall.p90),
            bench::ns_to_ms(r.overall.p99),
            bench::ns_to_ms(r.overall.p999),
            bench::ns_to_ms(r.overall.max),
            r.server_cores,
            r.busy_threads,
            r.busiest_core_frac,
            mib(r.peak_rss),
            mib(r.vm_hwm),
            if r.io_available {
                format!("; disk read IO {:.1}MiB", mib(r.io_read_bytes))
            } else {
                String::new()
            },
            if r.writes_ok + r.writes_err > 0 {
                format!("; writer {} ok / {} conflict", r.writes_ok, r.writes_err)
            } else {
                String::new()
            },
        ));
    }
    for f in &top.per_family {
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
    for line in diagnose_knee(rungs, proc_available) {
        collector.note(format!("KNEE: {line}"));
    }
    if !proc_available {
        collector.note(
            "SERVER /proc SAMPLING DISABLED (non-Linux or unreadable --server-pid): CPU / RSS / IO \
             sections are zeroed; the throughput + latency evidence still stands."
                .to_string(),
        );
    }

    let report = collector.finish();
    let evidence_dir = PathBuf::from(dir);
    match report.write_to(&evidence_dir) {
        Ok((json, md)) => {
            eprintln!("reco_bench: wrote {} and {}", json.display(), md.display());
            Ok(())
        }
        Err(e) => Err(format!("{e}")),
    }
}

/// Bytes → mebibytes as an `f64`, for human display.
fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

// ============================================================================================
// CLI
// ============================================================================================

/// The parsed `reco_bench` command line.
struct Args {
    socket: String,
    user: String,
    password: String,
    db: String,
    server_pid: i64,
    ladder: String,
    ops_per_rung: u64,
    users: u64,
    products: u64,
    friends: u64,
    purchased: u64,
    scenario: String,
    evidence_dir: Option<String>,
    write_every_ms: u64,
    read_timeout_ms: u64,
    seed: u64,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut socket = None;
        let mut user = None;
        let mut password = None;
        let mut db = None;
        let mut server_pid = None;
        let mut ladder = None;
        let mut ops_per_rung = None;
        let mut users = None;
        let mut products = None;
        let mut friends = None;
        let mut purchased = None;
        let mut scenario = "product-recommendations".to_string();
        let mut evidence_dir = None;
        let mut write_every_ms = 0u64;
        let mut read_timeout_ms = 120_000u64;
        let mut seed = 0x5EC0_11EC_710Du64;

        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
            match flag.as_str() {
                "--socket" => socket = Some(value()?),
                "--user" => user = Some(value()?),
                "--password" => password = Some(value()?),
                "--db" => db = Some(value()?),
                "--server-pid" => {
                    server_pid = Some(
                        value()?
                            .parse()
                            .map_err(|_| "--server-pid must be an integer".to_string())?,
                    );
                }
                "--ladder" => ladder = Some(value()?),
                "--ops-per-rung" => {
                    ops_per_rung = Some(value()?.parse().map_err(|_| {
                        "--ops-per-rung must be a non-negative integer".to_string()
                    })?);
                }
                "--users" => users = Some(parse_u64(&value()?, "--users")?),
                "--products" => products = Some(parse_u64(&value()?, "--products")?),
                "--friends" => friends = Some(parse_u64(&value()?, "--friends")?),
                "--purchased" => purchased = Some(parse_u64(&value()?, "--purchased")?),
                "--scenario" => scenario = value()?,
                "--evidence-dir" => evidence_dir = Some(value()?),
                "--write-every-ms" => write_every_ms = parse_u64(&value()?, "--write-every-ms")?,
                "--read-timeout-ms" => read_timeout_ms = parse_u64(&value()?, "--read-timeout-ms")?,
                "--seed" => seed = parse_u64(&value()?, "--seed")?,
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown flag {other:?} (try --help)")),
            }
        }

        let socket = socket.ok_or("--socket is required")?;
        let user = user.ok_or("--user is required")?;
        let password = password.ok_or("--password is required")?;
        let db = db.ok_or("--db is required")?;
        let server_pid = server_pid.ok_or("--server-pid is required")?;
        let ladder = ladder.ok_or("--ladder is required (e.g. 1,2,4,8)")?;
        let ops_per_rung = ops_per_rung.ok_or("--ops-per-rung is required")?;
        let users = users.ok_or("--users is required")?;
        let products = products.ok_or("--products is required")?;
        let friends = friends.ok_or("--friends is required")?;
        let purchased = purchased.ok_or("--purchased is required")?;
        if read_timeout_ms == 0 {
            return Err("--read-timeout-ms must be > 0".to_string());
        }

        Ok(Self {
            socket,
            user,
            password,
            db,
            server_pid,
            ladder,
            ops_per_rung,
            users,
            products,
            friends,
            purchased,
            scenario,
            evidence_dir,
            write_every_ms,
            read_timeout_ms,
            seed,
        })
    }
}

/// Parses a `u64` CLI value with a flag-named error.
fn parse_u64(s: &str, flag: &str) -> Result<u64, String> {
    s.parse()
        .map_err(|_| format!("{flag} must be a non-negative integer, got {s:?}"))
}

/// Prints the usage banner.
fn print_usage() {
    eprintln!(
        "usage: reco_bench --socket <path> --user <name> --password <pw> --db <name> \
         --server-pid <pid> \\\n\
         \x20   --ladder <csv e.g. 1,2,4,8> --ops-per-rung <N> \\\n\
         \x20   --users <N> --products <N> --friends <N> --purchased <N> \\\n\
         \x20   [--scenario product-recommendations] [--evidence-dir <dir>] \\\n\
         \x20   [--write-every-ms <ms default 0>] [--read-timeout-ms <ms default 120000>] \\\n\
         \x20   [--seed <u64>]"
    );
}
