//! `reco_bench` — the **concurrent UDS-Bolt read driver**, the heart of the
//! `examples/product-recommendation` performance evaluation (`rmp #541`).
//!
//! It drives **many simultaneous Bolt connections** against an already-loaded recommendation database
//! (`recodb`) and **exposes the server's read-path bottleneck under a production-shaped MIX** — reads
//! served *while writes commit underneath*, which is the only workload that can exercise MVCC
//! snapshot-isolation reads, the off-thread reader pool, SSI, and the GC pins a long reader holds
//! (`rmp` #714). It sweeps a **concurrency ladder** and, for each rung, runs it **TWICE**:
//!
//! * arm `readonly` (the **CONTROL**) — writers off;
//! * arm `mixed` (the **TREATMENT**, and the default) — writers on.
//!
//! The delta between the two arms is *the cost of the mix*: the quantity a read-only ladder against a
//! frozen graph structurally cannot see. The control arm runs **first**, so it warms the buffer pool
//! for the mixed arm and the measured cost is a conservative **lower bound**.
//!
//! Within an arm each rung:
//!
//! 1. spawns `C` worker OS threads, each owning its **own** [`BoltClient`] over its own connection,
//!    all released together by a start [`Barrier`], each looping a **weighted mix** of the
//!    recommendation read battery ([`queries::READ_BATTERY`]) until a shared op budget is drained —
//!    and classifying every failure, because **an auto-commit read runs at Snapshot Isolation and can
//!    never abort** (invariant I1);
//! 2. in the `mixed` arm, runs `--writers` paced writer threads. Each iteration is ONE **business
//!    unit** driven through [`mix::run_managed_write`] — managed retry with bounded exponential
//!    backoff and jitter, exactly what `session.execute_write` does in every official driver. The
//!    write stream is realistic, not uniform: `--hot-write-fraction` of it is a **read-modify-write of
//!    a small trending product set**, which is what actually makes SSI (and hence the retry path)
//!    load-bearing;
//! 3. samples the **server process** via `/proc/<server-pid>` on a background thread: total + per-
//!    thread CPU (from `stat`), peak/current RSS (`status`), and IO bytes (`io`, if readable);
//! 4. aggregates client throughput + latency percentiles (overall and per family) and the server's
//!    core utilisation, busy-thread count, busiest-thread core fraction, and peak RSS.
//!
//! After the ladder a **slow-reader probe** (invariant I5) holds one deliberately heavy reader open
//! while the writers commit, proving a long reader's GC pin does not stall the write path (`rmp` #551).
//!
//! # Two layers of truth, never conflated (`rmp` #714, #715)
//!
//! The read vector and the write vector are **separate workloads** and are reported separately. The
//! `throughput.*` section is the READ vector of the mixed arm's best rung — one coherent set, whose
//! `abort_rate` is the **read** abort rate (a genuinely measured `0.0`: it is invariant I1). The
//! WRITE vector lives in the workload map (`engine_abort_rate`, `write_commit_rate`, …), split into
//! the ENGINE layer (attempts/aborts — the contention evidence) and the APPLICATION layer
//! (units/committed — the business outcome). Splicing them produced a report claiming that 5% of
//! 12 000 READS aborted: false, and impossible.
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
//! # Two transports (`rmp` #693)
//!
//! - **Local (`--socket`)** — Bolt-over-UDS against a co-located server whose pid is known, so the
//!   full `/proc/<pid>` per-thread knee diagnosis is available.
//! - **Attach (`--bolt <url>`)** — Bolt-over-TCP + TLS against an ALREADY-RUNNING, possibly remote
//!   instance (`bolt+ssc://` accepts a self-signed cert). There is no co-located pid, so
//!   the `/proc` sampling is skipped; the server-side channel is the target's Prometheus `/metrics`
//!   (scraped by the example's `run.sh` before/after and folded in by `measure_target`). The driver
//!   prints machine-readable client-side stats sentinels (`GRAPHUS_RECO_BENCH_STATS` / `_RUNG`) for
//!   `run.sh` to forward to `measure_target`, and writes no `report.json` of its own in attach mode.
//!
//! # Load-generation modes
//!
//! - **Closed-loop (default)** — each worker issues the next op as soon as the previous completes
//!   (a zero-think-time saturation probe; subject to coordinated omission near saturation).
//! - **Open-loop (`--target-rps R`)** — ops are dispatched on a fixed arrival schedule and latency is
//!   measured from each op's *scheduled* time, so a slow server shows up as growing latency rather
//!   than a throttled arrival rate (kills coordinated omission).
//!
//! A `--min-ops-per-client` floor keeps the per-family sample count from collapsing as the ladder
//! widens. `--writers 0` gives a **pure read ladder** (a legitimate isolation experiment) and
//! `--mix-baseline 0` skips the control arm.
//!
//! # Usage
//!
//! ```text
//! reco_bench (--socket <path> --server-pid <pid> | --bolt <bolt+ssc://host:7687>) \
//!            --user <name> --password <pw> --db <name> \
//!            --ladder 1,2,4,8,16 --ops-per-rung <N> \
//!            --users <N> --products <N> --friends <N> --purchased <N> \
//!            [--scenario product-recommendations] [--evidence-dir <dir>] \
//!            [--writers <N>] [--write-every-ms <ms>] [--hot-write-fraction <f>] [--hot-keys <N>] \
//!            [--mix-baseline 0|1] [--retry-budget-ms <ms>] [--probe-secs <s>] \
//!            [--min-ops-per-client <N>] [--target-rps <R>] [--auto-extend] \
//!            [--read-timeout-ms <ms>] [--seed <u64>]
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_examples_harness::{
    CpuSection, DatasetScale, EvidenceCollector, MemorySection, RunMetadata,
};
use graphus_reco_gen::bench::{self, Pcts};
use graphus_reco_gen::client::{BoltClient, BoltUrl, ClientResult};
use graphus_reco_gen::mix::{
    self, Arm, ErrorSample, READ_LIVENESS_FLOOR, ReadInvariant, RetryPolicy, WriteKind, WriteVector,
};
use graphus_reco_gen::{EPOCH_S, Generator, SplitMix64, queries};

/// How often the background sampler polls `/proc/<pid>/status` for RSS, in milliseconds.
const SAMPLE_INTERVAL_MS: u64 = 50;

// --- The production-shaped MIX defaults (`rmp` #714) ---------------------------------------------
// The run everyone actually executes MUST be the mix. A read-only default measured a FROZEN graph and
// could not expose a single one of the concurrency mechanisms the server is built around.

/// Default concurrent writer count (`--writers`). `0` = a pure read ladder.
const DEFAULT_WRITERS: usize = 2;
/// Default writer pacing (`--write-every-ms`): a steady, production-shaped trickle, not a storm.
const DEFAULT_WRITE_EVERY_MS: u64 = 20;
/// Default share of writes landing on the trending hot set (`--hot-write-fraction`).
const DEFAULT_HOT_WRITE_FRACTION: f64 = 0.25;
/// Default size of the trending hot set (`--hot-keys`) — small enough that concurrent
/// read-modify-writes genuinely collide, which is what makes SSI and the retry path load-bearing.
const DEFAULT_HOT_KEYS: u64 = 4;
/// Default per-unit managed-retry budget (`--retry-budget-ms`), the driver's `maxTransactionRetryTime`.
const DEFAULT_RETRY_BUDGET_MS: u64 = 15_000;
/// Default slow-reader probe window (`--probe-secs`) — modest and cheap, but long enough that a
/// writer stalled behind a long reader's GC pin would show up as zero commits.
const DEFAULT_PROBE_SECS: f64 = 3.0;
/// The read family the slow-reader probe repeats: the heaviest traversal in the battery.
const PROBE_FAMILY: &str = "r3_fof3";

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

/// Default per-client op floor (`--min-ops-per-client`): keeps the effective per-rung op budget at
/// least `clients × this`, so per-family sample counts do not collapse as the ladder widens. Chosen
/// so the committed `fast` ladder (≤ 8 clients) stays at its historical global budget (`8 × 150 <
/// 1500`), i.e. this only lifts the budget for wide rungs.
const DEFAULT_MIN_OPS_PER_CLIENT: u64 = 150;

/// Hard cap on the client count when `--auto-extend` keeps doubling past the tested ladder, so a
/// non-plateauing server cannot widen the sweep unboundedly.
const AUTO_EXTEND_MAX_CLIENTS: usize = 512;
/// Hard cap on the total number of rungs (explicit + auto-extended), bounding the run time.
const MAX_TOTAL_RUNGS: usize = 24;

/// Where the driver connects: a local Unix socket, or a Bolt-over-TCP(+TLS) URL for an attached
/// (possibly remote) instance. Each worker owns one connection built from this.
#[derive(Clone)]
enum Target {
    /// Bolt-over-UDS at a filesystem path (local, co-located server).
    Uds(PathBuf),
    /// Bolt-over-TCP(+TLS) at a parsed URL (attach mode; `bolt+ssc://` = self-signed OK).
    Bolt(BoltUrl),
}

impl Target {
    /// Opens one Bolt connection to the target (handshake done; caller still logs in).
    fn connect(&self, read_timeout: Duration) -> ClientResult<BoltClient> {
        match self {
            Self::Uds(path) => BoltClient::connect_uds(path, read_timeout),
            Self::Bolt(url) => BoltClient::connect_bolt(url, read_timeout),
        }
    }

    /// Whether this is the attach (external) transport.
    fn is_external(&self) -> bool {
        matches!(self, Self::Bolt(_))
    }

    /// A short human label for logs.
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
            eprintln!("reco_bench: error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the whole PAIRED ladder. Returns `Ok(true)` on a clean run, `Ok(false)` if a rung's reader
/// error rate breached [`MAX_ERROR_RATE`] or an invariant (I1–I5) was violated, and `Err` on a fatal
/// setup error.
fn run() -> Result<bool, String> {
    let args = Args::parse()?;

    let ladder = bench::parse_ladder(&args.ladder)?;
    let target = args.target()?;
    let external = target.is_external();
    let ctx = Arc::new(BenchCtx {
        target: target.clone(),
        user: args.user.clone(),
        password: args.password.clone(),
        db: args.db.clone(),
        read_timeout: Duration::from_millis(args.read_timeout_ms),
        users: args.users.max(1),
        products: args.products.max(1),
        ops_per_rung: args.ops_per_rung,
        min_ops_per_client: args.min_ops_per_client,
        write_every_ms: args.write_every_ms,
        writers: args.writers,
        hot_write_fraction: args.hot_write_fraction,
        hot_keys: args.hot_keys.max(1),
        retry: RetryPolicy {
            budget: Duration::from_millis(args.retry_budget_ms),
            ..RetryPolicy::default()
        },
        target_rps: args.target_rps,
        seed: args.seed,
    });

    // Server-process `/proc` sampling is only meaningful for a co-located pid (local mode). In attach
    // mode there is no local pid — the server-side channel is the target's `/metrics` (scraped by
    // run.sh + measure_target), so `/proc` sampling is deliberately OFF.
    let server_pid = args.server_pid.unwrap_or(-1);
    let proc_available = !external && read_total_cpu(server_pid).is_some();
    let clk_tck = clock_ticks_per_sec();
    if external {
        eprintln!(
            "reco_bench: ATTACH mode ({}) — /proc sampling OFF; server-side evidence is the target's \
             /metrics (folded in by measure_target). Client throughput + latency are measured here.",
            target.label()
        );
    } else if !proc_available {
        eprintln!(
            "reco_bench: /proc/{server_pid}/stat is not observable (non-Linux, or pid not \
             owned/alive) — server CPU/RSS/IO sampling is DISABLED; throughput + latency evidence is \
             still valid."
        );
    }

    let arms = ctx.arms(args.mix_baseline);
    eprintln!(
        "reco_bench: target={} db={} pid={} ladder={:?} arms={:?} ops/rung={} min_ops/client={} \
         writers={} write_every_ms={} hot_write_fraction={} hot_keys={} retry_budget_ms={} \
         target_rps={} auto_extend={} clk_tck={clk_tck} proc_sampling={} mode={}",
        target.label(),
        args.db,
        server_pid,
        ladder,
        arms.iter().map(|a| a.label()).collect::<Vec<_>>(),
        args.ops_per_rung,
        args.min_ops_per_client,
        ctx.effective_writers(),
        args.write_every_ms,
        args.hot_write_fraction,
        ctx.hot_keys,
        args.retry_budget_ms,
        args.target_rps,
        args.auto_extend,
        proc_available,
        if external { "external" } else { "local" },
    );

    // The PAIRED ladder: every rung is driven once per arm, control FIRST (so its cache warming makes
    // the measured cost of the mix a conservative lower bound). The reader seed is keyed to the LADDER
    // index, not to the arm, so both arms replay the SAME read stream against the SAME anchors — the
    // delta between them is the writers, and nothing else.
    let mut rungs: Vec<RungResult> = Vec::with_capacity(ladder.len() * arms.len());
    for (rung_ix, &clients) in ladder.iter().enumerate() {
        for &arm in &arms {
            let result = drive_rung(
                &ctx,
                rung_ix,
                clients,
                arm,
                server_pid,
                proc_available,
                clk_tck,
            );
            print_rung_line(&result);
            rungs.push(result);
        }
    }

    // Auto-extend: if throughput was still rising at the top rung, keep DOUBLING the client count
    // past the tested ladder until it plateaus or the caps are hit — so the knee is located even when
    // it lies beyond a fixed ladder. "Still rising" means the newest rung beat the best of the PRIOR
    // rungs by more than PLATEAU_BAND (comparing against the best-so-far *including* the newest rung
    // would read a still-climbing rung — which is itself the new best — as a plateau). The decision is
    // taken on the PRIMARY arm (the one the headline is drawn from); each extension still runs the
    // full pair, so the cost of the mix stays measured at every rung.
    if args.auto_extend && !rungs.is_empty() {
        let primary = primary_arm(&rungs);
        let mut rung_ix = ladder.len();
        loop {
            if rungs.len() >= MAX_TOTAL_RUNGS {
                eprintln!("reco_bench: auto-extend stopped at the {MAX_TOTAL_RUNGS}-rung cap.");
                break;
            }
            let series: Vec<&RungResult> = rungs.iter().filter(|r| r.arm == primary).collect();
            let Some(last) = series.last() else { break };
            // The best throughput among all PRIMARY rungs EXCEPT the newest one.
            let prior_best = series[..series.len() - 1]
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
                    "reco_bench: auto-extend stopped — throughput plateaued at clients={} \
                     ({:.1} ops/s, {:+.1}% vs the prior best {:.1} ops/s).",
                    last.clients,
                    last.ops_per_sec,
                    gain * 100.0,
                    prior_best,
                );
                break;
            }
            let next = last.clients.saturating_mul(2);
            if next > AUTO_EXTEND_MAX_CLIENTS {
                eprintln!(
                    "reco_bench: auto-extend reached the clients={AUTO_EXTEND_MAX_CLIENTS} cap \
                     (still rising)."
                );
                break;
            }
            eprintln!("reco_bench: auto-extend → clients={next} (throughput still rising)");
            for &arm in &arms {
                let result = drive_rung(
                    &ctx,
                    rung_ix,
                    next,
                    arm,
                    server_pid,
                    proc_available,
                    clk_tck,
                );
                print_rung_line(&result);
                rungs.push(result);
            }
            rung_ix += 1;
        }
    }

    if rungs.is_empty() {
        return Err("empty ladder produced no rungs".to_string());
    }

    // I5 — the SLOW-READER probe: hold one deliberately heavy reader open while the writers commit.
    // A long reader pins the GC watermark (`rmp` #551); if that pin could stall the write path, the
    // writers would commit NOTHING during this window. Only meaningful when there is a write workload.
    let probe = if ctx.effective_writers() > 0 {
        let p = run_slow_reader_probe(&ctx, args.probe_secs);
        print_probe_line(&p);
        Some(p)
    } else {
        eprintln!(
            "reco_bench: slow-reader probe SKIPPED (no writers: --writers 0 is a pure read ladder, \
             so there is no write path for a long reader to stall)."
        );
        None
    };

    print_report(&rungs, proc_available, external);

    // The invariants (I1–I5). Each prints its own PASS/FAIL line; any violation fails the process.
    let invariants = check_invariants(&rungs, probe.as_ref(), &ctx);
    let invariants_ok = print_invariants(&invariants);

    // Machine-readable client-side stats sentinels for run.sh to forward to measure_target (the ONLY
    // place server-side + client-side evidence is stitched together in attach mode). Printed in both
    // modes; run.sh consumes them only in external mode.
    print_client_stats_sentinels(&rungs, probe.as_ref(), external, invariants_ok);

    // Evidence: LOCAL writes the full self-metered report.json (server /proc CPU/RSS + knee). ATTACH
    // mode does NOT — its evidence is emitted by measure_target from the /metrics before/after delta.
    if external {
        eprintln!(
            "reco_bench: attach mode — evidence report is emitted by measure_target (from the \
             /metrics before/after delta), not written here."
        );
    } else if let Some(dir) = &args.evidence_dir {
        write_evidence(dir, &args, &ctx, &rungs, probe.as_ref(), proc_available)
            .map_err(|e| format!("failed to write evidence to {dir}: {e}"))?;
    }

    // Exit gate: any rung whose reader error rate breached the threshold marks a broken run.
    let mut ok = invariants_ok;
    for r in &rungs {
        let attempts = r.ok_ops + r.err_ops;
        if attempts > 0 {
            let rate = r.err_ops as f64 / attempts as f64;
            if rate > MAX_ERROR_RATE {
                eprintln!(
                    "reco_bench: FAIL rung clients={} arm={}: reader error rate {:.1}% ({} of {} \
                     ops) exceeds the {:.0}% threshold — the failures were: {}",
                    r.clients,
                    r.arm.label(),
                    rate * 100.0,
                    r.err_ops,
                    attempts,
                    MAX_ERROR_RATE * 100.0,
                    if r.read_errors.is_empty() {
                        "(no failure was captured — the errors are connect/login failures, see \
                         connect_errors)"
                            .to_string()
                    } else {
                        r.read_errors.summary()
                    },
                );
                ok = false;
            }
        }
    }
    if ok {
        eprintln!(
            "reco_bench: OK — every rung stayed under the {:.0}% reader-error threshold and every \
             invariant held.",
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
    target: Target,
    user: String,
    password: String,
    db: String,
    read_timeout: Duration,
    users: u64,
    products: u64,
    /// The requested global op budget per rung (`--ops-per-rung`).
    ops_per_rung: u64,
    /// Per-client op floor: the effective budget is at least `clients × this` (`--min-ops-per-client`).
    min_ops_per_client: u64,
    write_every_ms: u64,
    /// Requested concurrent writer count (`--writers`); `0` = a pure read ladder.
    writers: usize,
    /// Share of writes that land on the trending hot set (`--hot-write-fraction`).
    hot_write_fraction: f64,
    /// Size of the trending hot set (`--hot-keys`).
    hot_keys: u64,
    /// The managed-retry policy each business unit is driven under.
    retry: RetryPolicy,
    /// Fixed total arrival rate for open-loop mode (`--target-rps`); `0.0` = closed-loop.
    target_rps: f64,
    seed: u64,
}

impl BenchCtx {
    /// The effective per-rung op budget: the larger of the requested global budget and the per-client
    /// floor (`clients × min_ops_per_client`). This keeps per-family sample counts from collapsing as
    /// the ladder widens, without shrinking a rung below the requested global budget.
    fn effective_budget(&self, clients: usize) -> u64 {
        let floor = self.min_ops_per_client.saturating_mul(clients as u64);
        self.ops_per_rung.max(floor)
    }

    /// The number of concurrent writers actually spawned. Zero when writes are disabled — either by
    /// pacing (`--write-every-ms 0`) or explicitly (`--writers 0`, the pure-read-ladder isolation
    /// experiment).
    fn effective_writers(&self) -> usize {
        if self.write_every_ms == 0 {
            0
        } else {
            self.writers
        }
    }

    /// The arms every rung is driven under.
    ///
    /// * no write workload ⇒ the single `readonly` arm (a pure read ladder — still a legitimate
    ///   experiment, and it must keep working);
    /// * a write workload + `--mix-baseline 1` ⇒ the PAIR (`readonly` CONTROL, then `mixed`);
    /// * a write workload + `--mix-baseline 0` ⇒ the `mixed` arm alone (no cost-of-the-mix figure).
    fn arms(&self, mix_baseline: bool) -> Vec<Arm> {
        if self.effective_writers() == 0 {
            vec![Arm::Readonly]
        } else if mix_baseline {
            vec![Arm::Readonly, Arm::Mixed]
        } else {
            vec![Arm::Mixed]
        }
    }

    /// The uniform inter-arrival spacing for open-loop mode, or `None` in closed-loop mode.
    fn arrival_interval(&self) -> Option<Duration> {
        if self.target_rps > 0.0 {
            Some(Duration::from_secs_f64(1.0 / self.target_rps))
        } else {
            None
        }
    }

    /// The Cypher + parameters of one write **business unit**, drawn from this writer's own RNG.
    ///
    /// [`WriteKind::Common`] (the bulk) lands on a RANDOM `(user, product)` pair and hardly ever
    /// conflicts; [`WriteKind::Hot`] is a read-modify-write of one of the `hot_keys` trending products
    /// — the component that actually exercises SSI. Returns `(kind, cypher, params)`.
    fn write_unit(
        &self,
        rng: &mut SplitMix64,
        ts: i64,
    ) -> (WriteKind, &'static str, Vec<(String, Value)>) {
        match mix::pick_write_kind(rng.next_u64(), self.hot_write_fraction) {
            WriteKind::Hot => {
                let pid = Generator::product_id(rng.next_u64() % self.hot_keys.min(self.products));
                (
                    WriteKind::Hot,
                    queries::WRITE_PRODUCT_HOT,
                    vec![("id".to_string(), Value::String(pid))],
                )
            }
            WriteKind::Common => {
                let uid = Generator::user_id(rng.next_u64() % self.users);
                let pid = Generator::product_id(rng.next_u64() % self.products);
                (
                    WriteKind::Common,
                    queries::WRITE_PURCHASE,
                    vec![
                        ("uid".to_string(), Value::String(uid)),
                        ("pid".to_string(), Value::String(pid)),
                        ("ts".to_string(), Value::Integer(ts)),
                    ],
                )
            }
        }
    }
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
    /// The READ invariant (I1): an auto-commit read runs at SI and can NEVER abort. Before `rmp` #714
    /// every reader failure was lumped into `err`, so a serialization abort on the read path would
    /// have been silently averaged into an error rate and the run would have passed.
    reads: ReadInvariant,
    /// WHAT the failed reads actually failed with. An error RATE without the error is a number, not
    /// evidence — see [`ErrorSample`].
    read_errors: ErrorSample,
}

impl WorkerStats {
    fn new(families: usize) -> Self {
        Self {
            lat: vec![Vec::new(); families],
            ok: vec![0; families],
            err: vec![0; families],
            connect_errors: 0,
            reads: ReadInvariant::default(),
            read_errors: ErrorSample::default(),
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

/// The fully-aggregated result of one ladder rung — of ONE arm of it.
struct RungResult {
    /// Which arm this rung is: the `readonly` CONTROL or the `mixed` TREATMENT.
    arm: Arm,
    clients: usize,
    /// The read op budget this rung was asked to drain (`ok_ops + err_ops` must equal it — I3).
    budget: u64,
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
    // ---- the WRITE vector (engine + application layers) and the READ invariant -------------------
    /// The rung's write evidence. Empty (`attempted() == false`) on a `readonly` rung — and then every
    /// derived rate is `None`, never a fabricated `0.0`.
    write: WriteVector,
    /// The rung's read-abort observations (I1). MUST be empty.
    reads: ReadInvariant,
    /// The distinct failures the rung's reads hit (empty on a clean rung).
    read_errors: ErrorSample,
}

/// Drives a single rung of `clients` concurrent connections **in one arm** and returns its aggregated
/// result. Writers are spawned only in the [`Arm::Mixed`] arm — that is the whole point of the pair.
fn drive_rung(
    ctx: &Arc<BenchCtx>,
    rung_ix: usize,
    clients: usize,
    arm: Arm,
    server_pid: i64,
    proc_available: bool,
    clk_tck: u64,
) -> RungResult {
    let families = queries::READ_BATTERY.len();
    let issued = Arc::new(AtomicU64::new(0));
    let budget = ctx.effective_budget(clients);
    // A shared load-window origin, initialised (exactly once, race-free) by the first participant to
    // clear the barrier. It is both the measurement clock's `t0` and — in open-loop mode — the base
    // of the fixed arrival schedule every worker paces against.
    let origin: Arc<OnceLock<Instant>> = Arc::new(OnceLock::new());
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

    // ---- the concurrent writers — ONLY in the mixed arm (the treatment) --------------------------
    let effective_writers = match arm {
        Arm::Mixed => ctx.effective_writers(),
        Arm::Readonly => 0,
    };
    let writer_stop = Arc::new(AtomicBool::new(false));
    let mut writer_handles: Vec<JoinHandle<WriteVector>> = Vec::with_capacity(effective_writers);
    for wi in 0..effective_writers {
        writer_handles.push(spawn_writer(
            Arc::clone(ctx),
            Arc::clone(&writer_stop),
            rung_ix,
            wi,
        ));
    }

    // ---- reader workers -------------------------------------------------------------------------
    let mut handles: Vec<JoinHandle<WorkerStats>> = Vec::with_capacity(clients);
    for w in 0..clients {
        let ctx = Arc::clone(ctx);
        let issued = Arc::clone(&issued);
        let barrier = Arc::clone(&barrier);
        let origin = Arc::clone(&origin);
        // A per-(rung,worker) seed so distinct connections hit distinct ids rather than all pounding
        // the same anchor (which would flatter the cache unrealistically).
        let seed = ctx
            .seed
            .wrapping_add((rung_ix as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
            .wrapping_add((w as u64).wrapping_mul(0xD1B5_4A32_D192_ED03));
        handles.push(thread::spawn(move || {
            run_worker(&ctx, &issued, &barrier, &origin, families, seed, budget)
        }));
    }

    // The driver joins the barrier: when it releases, all workers are connected and about to loop.
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
                merged.reads.merge(ws.reads);
                merged.read_errors.merge(ws.read_errors);
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

    // Stop and join the background threads. Each writer hands back its OWN WriteVector, built from its
    // own per-unit locals; merging them can never manufacture an impossible rate (`rmp` #715).
    writer_stop.store(true, Ordering::Relaxed);
    sampler_stop.store(true, Ordering::Relaxed);
    let mut write = WriteVector::default();
    for h in writer_handles {
        write.merge(h.join().unwrap_or_default());
    }
    let (peak_rss, final_rss, vm_hwm) =
        sampler.map_or((0, 0, 0), |h| h.join().unwrap_or((0, 0, 0)));

    let samples = RungSamples {
        cpu: (cpu_start, cpu_end),
        threads_start,
        threads_end,
        io: (io_start, io_end),
        rss: (peak_rss, final_rss, vm_hwm),
        write,
    };
    aggregate_rung(
        arm,
        clients,
        budget,
        wall,
        merged,
        connect_errors,
        clk_tck,
        samples,
    )
}

/// One reader worker: connect + login, wait at the barrier, then loop the weighted read mix until the
/// shared op budget is exhausted. Never panics; a connect/login failure is recorded and the worker
/// still joins the barrier so the rung cannot deadlock.
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
    // The shared load-window origin (open-loop schedule base + the measurement clock).
    let t0 = *origin.get_or_init(Instant::now);
    let interval = ctx.arrival_interval();

    let mut rng = SplitMix64::new(seed);
    loop {
        let ticket = issued.fetch_add(1, Ordering::Relaxed);
        if ticket >= budget {
            break;
        }
        // Open-loop: op `ticket` is due at `t0 + ticket*interval`. Sleep until then and measure
        // latency from that SCHEDULED time (so a slow server surfaces as growing latency, not a
        // throttled arrival rate — coordinated-omission-free). Closed-loop: fire immediately and
        // measure the round-trip.
        let scheduled =
            interval.map(|iv| t0 + iv.saturating_mul(u32::try_from(ticket).unwrap_or(u32::MAX)));
        if let Some(due) = scheduled {
            let now = Instant::now();
            if due > now {
                thread::sleep(due - now);
            }
        }
        let spec = queries::pick(rng.next_u64());
        let fam = bench::family_index(spec);
        let id = Generator::user_id(rng.next_u64() % ctx.users);
        let params = vec![("id".to_string(), Value::String(id))];
        let op_start = scheduled.unwrap_or_else(Instant::now);
        match client.run(spec.cypher, params, &ctx.db) {
            Ok(_) => {
                let ns = u64::try_from(op_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
                stats.lat[fam].push(ns);
                stats.ok[fam] += 1;
            }
            Err(e) => {
                stats.err[fam] += 1;
                // I1: an auto-commit read runs at Snapshot Isolation. If it came back with a
                // serialization abort, the SI guarantee is broken — that is an INVARIANT VIOLATION,
                // not a statistic to be averaged into an error rate.
                stats.reads.record(&e);
                // …and whatever it was, RECORD WHAT IT WAS. A bare error rate cannot be acted on.
                stats.read_errors.record(&e);
            }
        }
    }

    let _ = client.goodbye();
    stats
}

/// Spawns one **paced, production-shaped writer** for a mixed rung.
///
/// It connects, then — every `write_every_ms` until stopped — drives ONE **business unit** through
/// [`mix::run_managed_write`]: managed retry with bounded exponential backoff and jitter, the same
/// contract `session.execute_write` gives an application. The unit is either the low-conflict
/// [`queries::WRITE_PURCHASE`] on a random `(user, product)` pair or — with probability
/// `hot_write_fraction` — a read-modify-write of one of the `hot_keys` trending products, which is
/// what makes SSI and the retry path load-bearing rather than dead code.
///
/// `writer_ix` salts the seed stream so concurrent writers do not replay the same key sequence.
/// Returns this writer's own [`WriteVector`], built from **per-unit locals** — never by differencing a
/// shared counter, which under concurrency lets another thread's increments leak in and can report an
/// impossible `abort_rate > 1` (`rmp` #715).
fn spawn_writer(
    ctx: Arc<BenchCtx>,
    stop: Arc<AtomicBool>,
    rung_ix: usize,
    writer_ix: usize,
) -> JoinHandle<WriteVector> {
    thread::spawn(move || {
        let mut v = WriteVector::default();
        let mut client = match ctx.target.connect(ctx.read_timeout) {
            Ok(c) => c,
            Err(e) => {
                v.other_errors += 1;
                eprintln!("reco_bench: writer {writer_ix} could not connect: {e}");
                return v;
            }
        };
        if let Err(e) = client.login(&ctx.user, &ctx.password) {
            v.other_errors += 1;
            eprintln!("reco_bench: writer {writer_ix} could not log in: {e}");
            return v;
        }
        let mut rng = SplitMix64::new(
            ctx.seed
                .wrapping_add((rung_ix as u64).wrapping_mul(0xA076_1D64_78BD_642F))
                .wrapping_add((writer_ix as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F))
                ^ 0x5757_5252_0000_0001,
        );
        let mut backoff_rng = SplitMix64::new(rng.next_u64());
        let mut ts: i64 = EPOCH_S as i64;
        while !stop.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(ctx.write_every_ms));
            if stop.load(Ordering::Relaxed) {
                break;
            }
            ts = ts.wrapping_add(1);
            let (_kind, cypher, params) = ctx.write_unit(&mut rng, ts);
            // The unit's OWN local outcome — the only thing folded into the shared vector.
            let outcome = mix::run_managed_write(&ctx.retry, &mut backoff_rng, || {
                client.run(cypher, params.clone(), &ctx.db).map(|_| ())
            });
            v.record(&outcome);
        }
        let _ = client.goodbye();
        v
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
    /// The rung's merged write vector (empty on a `readonly` rung).
    write: WriteVector,
}

/// Folds the merged worker stats + `/proc` deltas into a [`RungResult`].
#[allow(clippy::too_many_arguments)]
fn aggregate_rung(
    arm: Arm,
    clients: usize,
    budget: u64,
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
        write,
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

    RungResult {
        arm,
        clients,
        budget,
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
        write,
        reads: merged.reads,
        read_errors: merged.read_errors,
    }
}

// ============================================================================================
// I5 — the slow-reader probe (a long reader must not stall the writers)
// ============================================================================================

/// The outcome of the slow-reader probe: what a deliberately heavy, repeated reader cost, and — the
/// point of the exercise — what the writers managed to COMMIT while it was running.
struct ProbeResult {
    /// The heavy read family the probe hammered.
    family: &'static str,
    /// Heavy reads completed inside the window.
    reader_ops: u64,
    /// Heavy reads that errored inside the window.
    reader_errs: u64,
    /// The probe reader's read-abort observations (I1 applies here too).
    reads: ReadInvariant,
    /// The distinct failures the probe reader hit.
    read_errors: ErrorSample,
    /// The probe reader's latency distribution — this is what "slow" actually cost.
    reader_pcts: Pcts,
    /// What the writers did DURING the window (per-unit locals, merged).
    write: WriteVector,
    /// The probe window's wall time.
    wall_secs: f64,
}

/// Holds one deliberately **slow** reader open (repeating the heaviest traversal in the battery) while
/// the writers commit underneath it, and reports what each side achieved **inside that window**.
///
/// This is the GC-pin / long-reader path (`rmp` #551): a reader's MVCC snapshot pins the GC watermark
/// for as long as it lives. If that pin could stall the write path, the writers would commit *nothing*
/// while the heavy reader runs — and the ladder, whose reads are all short, would never notice.
fn run_slow_reader_probe(ctx: &Arc<BenchCtx>, probe_secs: f64) -> ProbeResult {
    let family = queries::READ_BATTERY
        .iter()
        .find(|q| q.name == PROBE_FAMILY)
        .or_else(|| queries::READ_BATTERY.last())
        .expect("INVARIANT: the read battery is non-empty (queries::tests)");

    let stop = Arc::new(AtomicBool::new(false));
    let writers = ctx.effective_writers();
    let mut writer_handles: Vec<JoinHandle<WriteVector>> = Vec::with_capacity(writers);
    for wi in 0..writers {
        // A distinct rung index keeps the probe's write stream from replaying the last rung's.
        writer_handles.push(spawn_writer(
            Arc::clone(ctx),
            Arc::clone(&stop),
            usize::MAX,
            wi,
        ));
    }

    let window = Duration::from_secs_f64(probe_secs.max(0.1));
    let started = Instant::now();
    let mut reader_ops = 0u64;
    let mut reader_errs = 0u64;
    let mut reads = ReadInvariant::default();
    let mut read_errors = ErrorSample::default();
    let mut lat: Vec<u64> = Vec::new();
    let mut rng = SplitMix64::new(ctx.seed ^ 0x510E_5EED_C0DE_1234);

    match ctx.target.connect(ctx.read_timeout) {
        Ok(mut client) => {
            if client.login(&ctx.user, &ctx.password).is_ok() {
                // At least one heavy read, then keep going until the window closes.
                loop {
                    let id = Generator::user_id(rng.next_u64() % ctx.users);
                    let params = vec![("id".to_string(), Value::String(id))];
                    let op = Instant::now();
                    match client.run(family.cypher, params, &ctx.db) {
                        Ok(_) => {
                            reader_ops += 1;
                            lat.push(u64::try_from(op.elapsed().as_nanos()).unwrap_or(u64::MAX));
                        }
                        Err(e) => {
                            reader_errs += 1;
                            reads.record(&e);
                            read_errors.record(&e);
                        }
                    }
                    if started.elapsed() >= window {
                        break;
                    }
                }
                let _ = client.goodbye();
            } else {
                reader_errs += 1;
            }
        }
        Err(_) => reader_errs += 1,
    }

    let wall_secs = started.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
    stop.store(true, Ordering::Relaxed);
    let mut write = WriteVector::default();
    for h in writer_handles {
        write.merge(h.join().unwrap_or_default());
    }
    lat.sort_unstable();

    ProbeResult {
        family: family.name,
        reader_ops,
        reader_errs,
        reads,
        read_errors,
        reader_pcts: bench::summarize(&lat),
        write,
        wall_secs,
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
    let writes = if r.write.attempted() {
        format!(
            " | writes {}/{} committed, {} engine aborts (rate {:.3}), {} retries",
            r.write.committed,
            r.write.units,
            r.write.aborts,
            r.write.engine_abort_rate().unwrap_or(0.0),
            r.write.retries,
        )
    } else {
        String::new()
    };
    eprintln!(
        "  rung clients={:>4} arm={:<8}: {:>9.1} ops/s | p50={:>7.3}ms p99={:>8.3}ms | \
         cores={:>5.2} busy_thr={:>3} busiest={:>4.2} | rss={:>6.1}MiB | ok={} err={}{}{}",
        r.clients,
        r.arm.label(),
        r.ops_per_sec,
        bench::ns_to_ms(r.overall.p50),
        bench::ns_to_ms(r.overall.p99),
        r.server_cores,
        r.busy_threads,
        r.busiest_core_frac,
        mib(r.peak_rss),
        r.ok_ops,
        r.err_ops,
        writes,
        // An error rate without the error is not evidence: say WHAT failed, right here.
        if r.read_errors.is_empty() {
            String::new()
        } else {
            format!(" | READ FAILURES {}", r.read_errors.summary())
        },
    );
}

/// Prints the slow-reader probe's one-line summary.
fn print_probe_line(p: &ProbeResult) {
    eprintln!(
        "  slow-reader probe ({} for {:.1}s): {} heavy reads (p50={:.1}ms max={:.1}ms, {} err) \
         WHILE writers committed {}/{} units ({} engine aborts){}",
        p.family,
        p.wall_secs,
        p.reader_ops,
        bench::ns_to_ms(p.reader_pcts.p50),
        bench::ns_to_ms(p.reader_pcts.max),
        p.reader_errs,
        p.write.committed,
        p.write.units,
        p.write.aborts,
        if p.read_errors.is_empty() {
            String::new()
        } else {
            format!(" | READ FAILURES {}", p.read_errors.summary())
        },
    );
}

/// The arm the headline is drawn from: `mixed` when there was a write workload (the production-shaped
/// default), otherwise `readonly` (the pure read ladder).
fn primary_arm(rungs: &[RungResult]) -> Arm {
    if rungs.iter().any(|r| r.arm == Arm::Mixed) {
        Arm::Mixed
    } else {
        Arm::Readonly
    }
}

/// The rungs of one arm, in ladder order.
fn arm_rungs(rungs: &[RungResult], arm: Arm) -> Vec<&RungResult> {
    rungs.iter().filter(|r| r.arm == arm).collect()
}

/// The `readonly` CONTROL rung paired with `mixed` rung `r` (same client count). `None` when the
/// control arm was skipped (`--mix-baseline 0`).
fn control_for<'a>(rungs: &'a [RungResult], r: &RungResult) -> Option<&'a RungResult> {
    rungs
        .iter()
        .find(|c| c.arm == Arm::Readonly && c.clients == r.clients)
}

/// Prints the human summary table, the cost-of-the-mix table, the per-family breakdown at the top
/// rung, and the knee diagnosis.
fn print_report(rungs: &[RungResult], proc_available: bool, external: bool) {
    println!("\n=== reco_bench: concurrency ladder (paired arms) ===");
    println!(
        "{:>8} | {:>8} | {:>10} | {:>9} | {:>9} | {:>7} | {:>6} | {:>12}",
        "clients", "arm", "ops/s", "p50 ms", "p99 ms", "cores", "busyth", "peak_rss_MiB"
    );
    println!("{}", "-".repeat(92));
    for r in rungs {
        println!(
            "{:>8} | {:>8} | {:>10.1} | {:>9.3} | {:>9.3} | {:>7.2} | {:>6} | {:>12.1}",
            r.clients,
            r.arm.label(),
            r.ops_per_sec,
            bench::ns_to_ms(r.overall.p50),
            bench::ns_to_ms(r.overall.p99),
            r.server_cores,
            r.busy_threads,
            mib(r.peak_rss),
        );
    }

    print_mix_cost_table(rungs);

    // Per-family latency breakdown at the TOP rung (the highest-concurrency one, PRIMARY arm).
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
    for line in diagnose_knee(rungs, proc_available, external) {
        println!("{line}");
    }
}

/// The client-side throughput-scaling verdict — the only core-scaling signal available in attach mode
/// (no `/proc`). Compares the best rung's throughput against the single-client rung: a materially
/// higher peak at more clients means the server served reads concurrently (the reader pool scaled
/// across cores); a flat curve means a one-core / single-thread ceiling. Returns `None` if there is
/// no single-client rung to anchor the comparison.
fn client_side_scaling_verdict(rungs: &[RungResult]) -> Option<String> {
    let base = rungs.iter().find(|r| r.clients == 1)?;
    let best = best_rung(rungs);
    if base.ops_per_sec <= 0.0 {
        return None;
    }
    let ratio = best.ops_per_sec / base.ops_per_sec;
    // A near-1× ratio (best barely beats one client) is the single-core signature; a clearly >1×
    // ratio is concurrent read scaling. 1.3× is a conservative threshold well outside run-to-run noise.
    let verdict = if best.clients > 1 && ratio >= 1.3 {
        format!(
            "CLIENT-SIDE VERDICT: reads SCALED with concurrency — peak {:.1} ops/s at clients={} is \
             {:.2}× the single-client {:.1} ops/s, so the server served reads across cores (the \
             off-thread reader pool #336/#543 is engaged). Confirm with the /metrics server_metrics \
             delta in the report.",
            best.ops_per_sec, best.clients, ratio, base.ops_per_sec
        )
    } else {
        format!(
            "CLIENT-SIDE VERDICT: reads did NOT scale with concurrency — peak {:.1} ops/s at \
             clients={} is only {:.2}× the single-client {:.1} ops/s, the single-thread-ceiling \
             signature. Cross-check the /metrics server_metrics delta.",
            best.ops_per_sec, best.clients, ratio, base.ops_per_sec
        )
    };
    Some(verdict)
}

/// The PRIMARY arm's rung with the highest client count (ties resolved to the last such rung).
///
/// Every headline is drawn from the **primary** arm — the `mixed` one when a write workload ran. A
/// max over BOTH arms would silently report the control (writers off) whenever the mix cost enough
/// throughput, which is exactly the fiction this task exists to kill.
fn top_rung(rungs: &[RungResult]) -> &RungResult {
    let primary = primary_arm(rungs);
    rungs
        .iter()
        .filter(|r| r.arm == primary)
        .max_by_key(|r| r.clients)
        .expect("INVARIANT: caller guarantees a non-empty ladder")
}

/// The PRIMARY arm's rung with the highest throughput (the saturation point). Ties resolved to the
/// first.
fn best_rung(rungs: &[RungResult]) -> &RungResult {
    let primary = primary_arm(rungs);
    rungs
        .iter()
        .filter(|r| r.arm == primary)
        .max_by(|a, b| a.ops_per_sec.total_cmp(&b.ops_per_sec))
        .expect("INVARIANT: caller guarantees a non-empty ladder")
}

/// The `readonly` CONTROL rung with the highest throughput, when a control arm ran.
fn best_control_rung(rungs: &[RungResult]) -> Option<&RungResult> {
    rungs
        .iter()
        .filter(|r| r.arm == Arm::Readonly)
        .max_by(|a, b| a.ops_per_sec.total_cmp(&b.ops_per_sec))
}

/// Prints THE COST OF THE MIX: for every rung, the control (writers off) against the treatment
/// (writers on), and the delta. This is the quantity nobody had ever measured here — a read-only
/// ladder against a frozen graph cannot produce it, and it is what a capacity planner actually needs.
fn print_mix_cost_table(rungs: &[RungResult]) {
    let mixed = arm_rungs(rungs, Arm::Mixed);
    if mixed.is_empty() {
        println!(
            "\n=== cost of the mix === NOT MEASURED: this run had no write workload (--writers 0), \
             so it is a pure read ladder against a FROZEN graph. It cannot say anything about how the \
             server behaves when reads are served while writes commit underneath."
        );
        return;
    }
    if mixed.iter().all(|r| control_for(rungs, r).is_none()) {
        println!(
            "\n=== cost of the mix === NOT MEASURED: the control arm was skipped \
             (--mix-baseline 0), so there is no writers-off reading to compare the mix against."
        );
        return;
    }
    println!("\n=== cost of the mix (control = writers OFF, mixed = writers ON) ===");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>9} | {:>11} | {:>11} | {:>10}",
        "clients", "control ops/s", "mixed ops/s", "delta", "ctl p50/p99", "mix p50/p99", "commits"
    );
    println!("{}", "-".repeat(96));
    for r in &mixed {
        let (ctl_ops, ctl_lat, delta) = match control_for(rungs, r) {
            Some(c) => (
                format!("{:.1}", c.ops_per_sec),
                format!(
                    "{:.1}/{:.1}",
                    bench::ns_to_ms(c.overall.p50),
                    bench::ns_to_ms(c.overall.p99)
                ),
                mix::mix_cost_pct(c.ops_per_sec, r.ops_per_sec)
                    .map_or_else(|| "n/a".to_string(), |p| format!("{p:+.1}%")),
            ),
            None => ("n/a".to_string(), "n/a".to_string(), "n/a".to_string()),
        };
        println!(
            "{:>8} | {:>12} | {:>12.1} | {:>9} | {:>11} | {:>11} | {:>10}",
            r.clients,
            ctl_ops,
            r.ops_per_sec,
            delta,
            ctl_lat,
            format!(
                "{:.1}/{:.1}",
                bench::ns_to_ms(r.overall.p50),
                bench::ns_to_ms(r.overall.p99)
            ),
            r.write.committed,
        );
    }
    println!(
        "NOTE: the control arm runs FIRST at every rung, so it warms the buffer pool for the mixed \
         arm. The cost of the mix reported here is therefore a conservative LOWER BOUND."
    );
}

// ============================================================================================
// The invariants (I1–I5)
// ============================================================================================

/// One invariant's verdict.
struct Invariant {
    id: &'static str,
    title: &'static str,
    ok: bool,
    detail: String,
}

/// Evaluates every invariant the mix makes checkable. A violation FAILS the run (non-zero exit): none
/// of these is a performance threshold, they are all statements that must simply be TRUE.
fn check_invariants(
    rungs: &[RungResult],
    probe: Option<&ProbeResult>,
    ctx: &BenchCtx,
) -> Vec<Invariant> {
    let mut out = Vec::new();
    let mixed = arm_rungs(rungs, Arm::Mixed);

    // ---- I1: an auto-commit READ runs at Snapshot Isolation and can NEVER abort -----------------
    let mut read_aborts = 0u64;
    let mut read_codes: Vec<String> = Vec::new();
    for r in rungs {
        read_aborts += r.reads.aborted;
        for c in &r.reads.codes {
            if !read_codes.contains(c) {
                read_codes.push(c.clone());
            }
        }
    }
    if let Some(p) = probe {
        read_aborts += p.reads.aborted;
        for c in &p.reads.codes {
            if !read_codes.contains(c) {
                read_codes.push(c.clone());
            }
        }
    }
    out.push(Invariant {
        id: "I1",
        title: "READS NEVER ABORT (auto-commit reads run at Snapshot Isolation)",
        ok: read_aborts == 0,
        detail: if read_aborts == 0 {
            "0 reads aborted across every rung and the slow-reader probe".to_string()
        } else {
            format!(
                "{read_aborts} READ(s) came back with a serialization abort ({read_codes:?}) — an \
                 auto-commit read must neither abort a writer nor be aborted by one"
            )
        },
    });

    // ---- I2: WRITERS MAKE PROGRESS (bounded retries, no livelock, not starved) -------------------
    if mixed.is_empty() {
        out.push(Invariant {
            id: "I2",
            title: "WRITERS MAKE PROGRESS",
            ok: true,
            detail: "N/A — no write workload (--writers 0): a pure read ladder".to_string(),
        });
    } else {
        let mut bad: Vec<String> = Vec::new();
        for r in &mixed {
            let w = &r.write;
            if w.committed == 0 {
                bad.push(format!(
                    "clients={}: writers committed NOTHING ({} units attempted) — starved by the \
                     readers",
                    r.clients, w.units
                ));
                continue;
            }
            if w.exhausted > 0 {
                bad.push(format!(
                    "clients={}: {} unit(s) exhausted the {}ms retry budget (a livelock signal)",
                    r.clients,
                    w.exhausted,
                    ctx.retry.budget.as_millis()
                ));
            }
            if w.commit_rate() != Some(1.0) {
                bad.push(format!(
                    "clients={}: application commit rate {:.4} < 1.0 ({} of {} units committed)",
                    r.clients,
                    w.commit_rate().unwrap_or(0.0),
                    w.committed,
                    w.units
                ));
            }
            if w.other_errors > 0 {
                bad.push(format!(
                    "clients={}: {} write(s) failed with a NON-contention error",
                    r.clients, w.other_errors
                ));
            }
        }
        let total: WriteVector = mixed.iter().fold(WriteVector::default(), |mut acc, r| {
            acc.merge(r.write.clone());
            acc
        });
        out.push(Invariant {
            id: "I2",
            title: "WRITERS MAKE PROGRESS (commit rate 1.0, 0 retry-budget exhaustions)",
            ok: bad.is_empty(),
            detail: if bad.is_empty() {
                format!(
                    "{}/{} business units committed across every mixed rung; engine abort rate {}; \
                     {:.4} retries/commit; worst unit retried {}×",
                    total.committed,
                    total.units,
                    total
                        .engine_abort_rate()
                        .map_or_else(|| "n/a".into(), |r| format!("{r:.6}")),
                    total.retries_per_commit().unwrap_or(0.0),
                    total.max_retries,
                )
            } else {
                bad.join("; ")
            },
        });
    }

    // ---- I3: READERS ARE NOT STARVED BY THE WRITERS ---------------------------------------------
    if mixed.is_empty() {
        out.push(Invariant {
            id: "I3",
            title: "READERS NOT STARVED BY WRITERS",
            ok: true,
            detail: "N/A — no write workload (--writers 0)".to_string(),
        });
    } else {
        let mut bad: Vec<String> = Vec::new();
        for r in &mixed {
            let attempted = r.ok_ops + r.err_ops;
            if attempted != r.budget {
                bad.push(format!(
                    "clients={}: the read budget did NOT drain ({attempted} of {} ops issued)",
                    r.clients, r.budget
                ));
            }
            if let Some(c) = control_for(rungs, r)
                && c.ops_per_sec > 0.0
                && r.ops_per_sec < c.ops_per_sec * READ_LIVENESS_FLOOR
            {
                bad.push(format!(
                    "clients={}: mixed throughput {:.1} ops/s COLLAPSED below {:.0}% of the control's \
                     {:.1} ops/s",
                    r.clients,
                    r.ops_per_sec,
                    READ_LIVENESS_FLOOR * 100.0,
                    c.ops_per_sec,
                ));
            }
        }
        out.push(Invariant {
            id: "I3",
            title: "READERS NOT STARVED BY WRITERS (full read budget drained; no collapse)",
            ok: bad.is_empty(),
            detail: if bad.is_empty() {
                format!(
                    "every mixed rung drained its full read budget and stayed above the {:.0}% \
                     liveness floor vs its control (a catastrophic-collapse guard, NOT a perf gate)",
                    READ_LIVENESS_FLOOR * 100.0
                )
            } else {
                bad.join("; ")
            },
        });
    }

    // ---- I4: the rmp #612 detector ---------------------------------------------------------------
    let poisoned: Vec<String> = rungs
        .iter()
        .flat_map(|r| r.write.nonretryable.iter().cloned())
        .chain(
            probe
                .iter()
                .flat_map(|p| p.write.nonretryable.iter().cloned()),
        )
        .collect();
    out.push(Invariant {
        id: "I4",
        title: "SERIALIZATION ABORTS ARE RETRYABLE (rmp #612 detector)",
        ok: poisoned.is_empty(),
        detail: if poisoned.is_empty() {
            // A detector that had nothing to classify has VERIFIED NOTHING, and must say so. Reporting
            // a bare "no abort was poisoned" when there was no abort at all is a green gate that
            // cannot fire — the exact failure mode this suite has been burned by before. At a
            // production-shaped write rate the engine abort rate is a measured ~0 (the writers are a
            // trickle and rarely collide), so on most runs this detector is ARMED but IDLE. To arm it
            // for real, raise the contention: more writers, tighter pacing, or fewer hot keys
            // (--writers / --write-every-ms / --hot-keys).
            let aborts: u64 = rungs.iter().map(|r| r.write.aborts).sum::<u64>()
                + probe.map_or(0, |p| p.write.aborts);
            if aborts == 0 {
                "NOT EXERCISED — this run produced ZERO serialization aborts, so the detector had \
                 nothing to classify. It is armed, not vacuous: a poisoned abort would fail the run. \
                 But nothing here VERIFIES rmp #612 today; raise the contention (--writers, \
                 --write-every-ms, --hot-keys) to actually exercise it."
                    .to_string()
            } else {
                format!(
                    "{aborts} serialization abort(s) occurred and NONE was dressed in a code an \
                     official driver refuses to retry"
                )
            }
        } else {
            format!(
                "rmp #612 REGRESSION — {} serialization abort(s) carried a NON-retryable code, which \
                 silently breaks managed-transaction retry (execute_write) for EVERY driver \
                 application: {:?}",
                poisoned.len(),
                &poisoned[..poisoned.len().min(3)]
            )
        },
    });

    // ---- I5: a long reader must not stall the writers (the GC pin, rmp #551) ---------------------
    match probe {
        None => out.push(Invariant {
            id: "I5",
            title: "SLOW READER DOES NOT STALL THE WRITERS",
            ok: true,
            detail: "N/A — no write workload (--writers 0)".to_string(),
        }),
        Some(p) => {
            let mut bad: Vec<String> = Vec::new();
            if p.reader_ops == 0 {
                bad.push(format!(
                    "the slow reader ({}) completed NO heavy read in the {:.1}s window ({} errors)",
                    p.family, p.wall_secs, p.reader_errs
                ));
            }
            if p.write.committed == 0 {
                bad.push(format!(
                    "the writers committed NOTHING while a long reader held its snapshot open ({} \
                     units attempted) — a long reader's GC pin is stalling the write path",
                    p.write.units
                ));
            }
            out.push(Invariant {
                id: "I5",
                title: "SLOW READER DOES NOT STALL THE WRITERS (the GC pin, rmp #551)",
                ok: bad.is_empty(),
                detail: if bad.is_empty() {
                    format!(
                        "{} heavy '{}' reads (p50 {:.1}ms, max {:.1}ms) ran for {:.1}s while the \
                         writers committed {} unit(s) underneath them",
                        p.reader_ops,
                        p.family,
                        bench::ns_to_ms(p.reader_pcts.p50),
                        bench::ns_to_ms(p.reader_pcts.max),
                        p.wall_secs,
                        p.write.committed,
                    )
                } else {
                    bad.join("; ")
                },
            });
        }
    }

    // ---- I6: the server never fails a read with an INTERNAL error (`rmp` #721) -------------------
    // `Neo.DatabaseError.*` is not a workload outcome, it is the server's OWN fault: a correct server
    // never returns one, for any workload, at any rate. So it must NOT be averaged into the reader
    // error rate and waved through under a 5% threshold — "the storage engine could not locate a
    // record" happening on 0.2% of reads is not a 0.2% problem, it is a BUG that happens to be rare.
    // The read-only ladder that used to be the default could never have caught this: it takes a
    // concurrent writer GROWING the store to produce it.
    let mut read_errors = ErrorSample::default();
    for r in rungs {
        read_errors.merge(r.read_errors.clone());
    }
    if let Some(p) = probe {
        read_errors.merge(p.read_errors.clone());
    }
    let internal_count = read_errors.internal_count();
    out.push(Invariant {
        id: "I6",
        title: "NO INTERNAL SERVER ERROR ON THE READ PATH (Neo.DatabaseError.*)",
        ok: internal_count == 0,
        detail: if internal_count == 0 {
            "no read failed with an internal server error, across every rung and the slow-reader probe"
                .to_string()
        } else {
            format!(
                "rmp #721 — {} read(s) failed with an INTERNAL server error: {}. This is the SERVER's \
                 own fault, not a workload outcome, and it appears ONLY while writers commit \
                 underneath the readers (the writers-off CONTROL arm of this very ladder is clean at \
                 every rung). Root cause: the off-thread reader's location oracle is a SNAPSHOT \
                 (MetaSnapshot's device_pages) while the record content it navigates is LIVE, so a \
                 reader can follow a pointer — advanced in place by a concurrently committed writer — \
                 into a store page allocated after its own snapshot, and is then unable to locate it.",
                internal_count,
                read_errors
                    .internal_errors()
                    .iter()
                    .map(|k| format!("{}×{} ({})", k.count, k.code, k.exemplar))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        },
    });

    out
}

/// Prints every invariant's PASS/FAIL line. Returns whether they all held.
fn print_invariants(invariants: &[Invariant]) -> bool {
    println!("\n=== invariants (a violation FAILS the run) ===");
    let mut ok = true;
    for i in invariants {
        println!(
            "{} {} — {}: {}",
            if i.ok { "PASS" } else { "FAIL" },
            i.id,
            i.title,
            i.detail
        );
        ok &= i.ok;
    }
    ok
}

/// Produces the knee-diagnosis narrative: where throughput peaked, whether it plateaued while p99
/// climbed, and — the headline — how many server cores/threads were busy at saturation, i.e. whether
/// reads scaled across cores or hit a single-thread ceiling.
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

    if external {
        // Attach mode: no /proc, so the server-side channel is /metrics (folded in by measure_target).
        // The client-side throughput-scaling curve is the core-scaling verdict available here.
        out.push(
            "Server core scaling: measured via the target's /metrics before/after delta (see the \
             report.json server_metrics section), NOT /proc — this is a remote/attached instance."
                .to_string(),
        );
        if let Some(v) = client_side_scaling_verdict(rungs) {
            out.push(v);
        }
        return out;
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

/// Renders an optional `f64` sentinel value: the measurement, or the literal `na`.
///
/// **NEVER** a `0.0` placeholder. `run.sh` skips an `na` token rather than forwarding a fabricated
/// zero into the report — which is exactly what it used to do for `abort_rate` on a run that had no
/// writers at all, publishing a conflict-free write workload that never ran (`rmp` #711/#714).
fn sf(v: Option<f64>, decimals: usize) -> String {
    v.map_or_else(|| "na".to_string(), |x| format!("{x:.decimals$}"))
}

/// Renders an optional `u64` sentinel value: the measurement, or the literal `na`.
fn su(v: Option<u64>) -> String {
    v.map_or_else(|| "na".to_string(), |x| x.to_string())
}

/// The READ abort rate of one rung. Reads run at Snapshot Isolation, so this is a genuinely MEASURED
/// `0.0` (invariant I1) — not a placeholder. `None` only when the rung issued no read at all.
fn read_abort_rate(r: &RungResult) -> Option<f64> {
    let attempted = r.ok_ops + r.err_ops;
    (attempted > 0).then(|| r.reads.aborted as f64 / attempted as f64)
}

/// The write vector of the PRIMARY arm (plus the probe), and the wall-time it accrued over.
fn primary_write_vector(rungs: &[RungResult], probe: Option<&ProbeResult>) -> (WriteVector, f64) {
    let primary = primary_arm(rungs);
    let mut write = WriteVector::default();
    let mut secs = 0.0f64;
    for r in rungs.iter().filter(|r| r.arm == primary) {
        write.merge(r.write.clone());
        if r.write.attempted() {
            secs += r.wall_secs;
        }
    }
    if let Some(p) = probe {
        write.merge(p.write.clone());
        secs += p.wall_secs;
    }
    (write, secs)
}

/// Emits the machine-readable client-side stats sentinels the example's `run.sh` forwards to
/// `measure_target` in attach mode (the only place the client-side throughput/latency and the
/// server-side `/metrics` delta are stitched into one report). A `GRAPHUS_RECO_BENCH_STATS` headline
/// line (the PRIMARY arm's best rung) plus one `GRAPHUS_RECO_BENCH_RUNG` line per rung per arm (the
/// full paired scaling curve). Printed in both modes; `run.sh` only consumes them in external mode.
///
/// The headline carries **one coherent read vector**: `best_ops`, `best_ops_per_sec`, the percentiles
/// and `abort_rate` all describe the SAME transactions (the reads), and `abort_rate` is therefore the
/// READ abort rate — a genuinely measured `0.0`, because an auto-commit read runs at SI and cannot
/// abort (invariant I1). The WRITE layer travels in its own explicitly-named keys. Before `rmp` #714
/// the `abort_rate` on this line was the WRITERS' rate sitting beside the READ counts, so a reader
/// concluded that 5% of the reads had aborted: false, impossible, and believed.
///
/// There is deliberately **no `writes_ok` / `writes_err` pair** here. Under managed retry those two
/// count *different populations* — `writes_ok` would be committed BUSINESS UNITS while `writes_err`
/// would be engine ABORTS — so a unit that aborts twice and then commits lands in both, their sum is
/// not an attempt count, and `writes_err / (writes_ok + writes_err)` is neither the engine abort rate
/// nor an application failure rate. It is precisely the kind of plausible-looking ratio a reader would
/// compute and believe. Both layers are published unambiguously instead: `write_attempts` /
/// `write_aborts` / `engine_abort_rate` (ENGINE) and `write_units` / `write_committed` /
/// `write_commit_rate` / `write_exhausted` / `write_other_errors` (APPLICATION). This matters because
/// `run.sh` forwards each `…_RUNG` line VERBATIM into the attach-mode report's notes, so an ambiguous
/// key here does not merely mislead a terminal — it becomes published evidence.
fn print_client_stats_sentinels(
    rungs: &[RungResult],
    probe: Option<&ProbeResult>,
    external: bool,
    invariants_ok: bool,
) {
    let best = best_rung(rungs);
    let primary = primary_arm(rungs);
    let (write, write_secs) = primary_write_vector(rungs, probe);
    let attempted = write.attempted();
    let wp = write.pcts();

    let total_ops: u64 = rungs.iter().map(|r| r.ok_ops).sum();
    let total_secs: f64 = rungs.iter().map(|r| r.wall_secs).sum();
    let control_best = best_control_rung(rungs)
        .map(|c| c.ops_per_sec)
        .filter(|_| primary == Arm::Mixed);
    // The cost of the mix AT THE BEST RUNG: the mixed best rung against ITS OWN control rung.
    let mix_cost = control_for(rungs, best)
        .filter(|_| primary == Arm::Mixed)
        .and_then(|c| mix::mix_cost_pct(c.ops_per_sec, best.ops_per_sec));

    println!(
        "GRAPHUS_RECO_BENCH_STATS mode={} arm={} best_clients={} best_ops_per_sec={:.3} best_ops={} \
         best_secs={:.6} p50_ms={:.4} p99_ms={:.4} p999_ms={:.4} abort_rate={} read_abort_rate={} \
         total_ops={} total_secs={:.6} write_attempts={} \
         write_aborts={} engine_abort_rate={} write_units={} write_committed={} write_commit_rate={} \
         write_retries_per_commit={} write_max_retries={} write_exhausted={} write_other_errors={} \
         write_p50_ms={} \
         write_p99_ms={} write_p999_ms={} write_ops_per_sec={} control_best_ops_per_sec={} \
         mix_cost_read_ops_pct={} invariants_ok={}",
        if external { "external" } else { "local" },
        primary.label(),
        best.clients,
        best.ops_per_sec,
        best.ok_ops,
        best.wall_secs,
        bench::ns_to_ms(best.overall.p50),
        bench::ns_to_ms(best.overall.p99),
        bench::ns_to_ms(best.overall.p999),
        sf(read_abort_rate(best), 6),
        sf(read_abort_rate(best), 6),
        total_ops,
        total_secs,
        su(attempted.then_some(write.attempts)),
        su(attempted.then_some(write.aborts)),
        sf(write.engine_abort_rate(), 6),
        su(attempted.then_some(write.units)),
        su(attempted.then_some(write.committed)),
        sf(write.commit_rate(), 6),
        sf(write.retries_per_commit(), 4),
        su(attempted.then_some(u64::from(write.max_retries))),
        su(attempted.then_some(write.exhausted)),
        su(attempted.then_some(write.other_errors)),
        sf(wp.map(|p| bench::ns_to_ms(p.p50)), 4),
        sf(wp.map(|p| bench::ns_to_ms(p.p99)), 4),
        sf(wp.map(|p| bench::ns_to_ms(p.p999)), 4),
        sf(write.ops_per_sec(write_secs), 4),
        sf(control_best, 3),
        sf(mix_cost, 2),
        u8::from(invariants_ok),
    );

    for r in rungs {
        let w = &r.write;
        let a = w.attempted();
        let cost = control_for(rungs, r)
            .filter(|_| r.arm == Arm::Mixed)
            .and_then(|c| mix::mix_cost_pct(c.ops_per_sec, r.ops_per_sec));
        println!(
            "GRAPHUS_RECO_BENCH_RUNG clients={} arm={} ops_per_sec={:.3} p50_ms={:.4} p99_ms={:.4} \
             p999_ms={:.4} ok={} err={} secs={:.6} read_abort_rate={} \
             write_attempts={} write_aborts={} engine_abort_rate={} write_units={} \
             write_committed={} write_commit_rate={} write_exhausted={} write_other_errors={} \
             mix_cost_pct={}",
            r.clients,
            r.arm.label(),
            r.ops_per_sec,
            bench::ns_to_ms(r.overall.p50),
            bench::ns_to_ms(r.overall.p99),
            bench::ns_to_ms(r.overall.p999),
            r.ok_ops,
            r.err_ops,
            r.wall_secs,
            sf(read_abort_rate(r), 6),
            su(a.then_some(w.attempts)),
            su(a.then_some(w.aborts)),
            sf(w.engine_abort_rate(), 6),
            su(a.then_some(w.units)),
            su(a.then_some(w.committed)),
            sf(w.commit_rate(), 6),
            su(a.then_some(w.exhausted)),
            su(a.then_some(w.other_errors)),
            sf(cost, 2),
        );
    }
}

// ============================================================================================
// Evidence
// ============================================================================================

/// Emits the standardized [`EvidenceReport`] for the run, populated MANUALLY from the server-process
/// `/proc` samples (the harness's own self-metering is deliberately NOT used — the subject under
/// measurement is the *server* process, not this driver). LOCAL mode only — attach mode's evidence is
/// emitted by `measure_target` from the `/metrics` before/after delta.
fn write_evidence(
    dir: &str,
    args: &Args,
    ctx: &BenchCtx,
    rungs: &[RungResult],
    probe: Option<&ProbeResult>,
    proc_available: bool,
) -> Result<(), String> {
    let best = best_rung(rungs);
    let top = top_rung(rungs);
    let primary = primary_arm(rungs);
    let (write, write_secs) = primary_write_vector(rungs, probe);

    let nodes = args.users.saturating_add(args.products);
    let relationships = args.friends.saturating_add(args.purchased);

    let metadata = RunMetadata::new(
        args.scenario.clone(),
        "read-heavy product recommendations: concurrent read scaling under a production-shaped \
         read/write MIX (paired control vs mixed arms)",
    )
    .with_dataset(DatasetScale::new(nodes, relationships));
    let mut collector = EvidenceCollector::new(metadata);

    // Workload params: the ladder shape + the FOUR structural counts (STRING values — the baseline
    // gate reads these) + the headline throughput/latency figures + the WRITE vector (whose home is
    // HERE, never spliced into throughput.*).
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
        w.insert("rungs".into(), rungs.len().to_string());
        w.insert("seed".into(), args.seed.to_string());
        w.insert("proc_sampling".into(), proc_available.to_string());
        w.insert("headline_arm".into(), primary.label().into());

        // --- The WRITE workload's SHAPE (what the writers were asked to do) ------------------------
        w.insert("writers".into(), ctx.effective_writers().to_string());
        w.insert("write_every_ms".into(), args.write_every_ms.to_string());
        if ctx.effective_writers() > 0 {
            w.insert("writer_mode".into(), "managed-retry".into());
            w.insert(
                "hot_write_fraction".into(),
                format!("{:.4}", args.hot_write_fraction),
            );
            w.insert("hot_keys".into(), ctx.hot_keys.to_string());
            w.insert(
                "write_retry_budget_ms".into(),
                args.retry_budget_ms.to_string(),
            );
        }

        // --- The WRITE vector: ENGINE layer, then APPLICATION layer. Every metric an Option: an
        //     unmeasured one is OMITTED, never zero-filled (`rmp` #711). -----------------------------
        if write.attempted() {
            w.insert("engine_txn_attempts".into(), write.attempts.to_string());
            w.insert("engine_txn_aborts".into(), write.aborts.to_string());
            if let Some(r) = write.engine_abort_rate() {
                w.insert("engine_abort_rate".into(), format!("{r:.6}"));
            }
            w.insert("write_units".into(), write.units.to_string());
            w.insert("write_committed".into(), write.committed.to_string());
            if let Some(r) = write.commit_rate() {
                w.insert("write_commit_rate".into(), format!("{r:.6}"));
            }
            if let Some(r) = write.retries_per_commit() {
                w.insert("write_retries_per_commit".into(), format!("{r:.4}"));
            }
            w.insert("write_max_retries".into(), write.max_retries.to_string());
            w.insert(
                "write_retry_budget_exhausted".into(),
                write.exhausted.to_string(),
            );
            if let Some(p) = write.pcts() {
                w.insert(
                    "write_p50_ms".into(),
                    format!("{:.4}", bench::ns_to_ms(p.p50)),
                );
                w.insert(
                    "write_p99_ms".into(),
                    format!("{:.4}", bench::ns_to_ms(p.p99)),
                );
                w.insert(
                    "write_p999_ms".into(),
                    format!("{:.4}", bench::ns_to_ms(p.p999)),
                );
            }
            if let Some(ops) = write.ops_per_sec(write_secs) {
                w.insert("write_ops_per_sec".into(), format!("{ops:.4}"));
            }
        }

        // --- THE COST OF THE MIX (the novel quantity) ----------------------------------------------
        if let Some(c) = best_control_rung(rungs).filter(|_| primary == Arm::Mixed) {
            w.insert(
                "control_best_ops_per_sec".into(),
                format!("{:.1}", c.ops_per_sec),
            );
            w.insert(
                "mixed_best_ops_per_sec".into(),
                format!("{:.1}", best.ops_per_sec),
            );
            if let Some(pct) = control_for(rungs, best)
                .and_then(|ctl| mix::mix_cost_pct(ctl.ops_per_sec, best.ops_per_sec))
            {
                w.insert("mix_cost_read_ops_pct".into(), format!("{pct:.2}"));
            }
        }
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

    // One phase per rung PER ARM (wall-clock of that arm's load window), plus the slow-reader probe.
    for r in rungs {
        collector.phase(
            format!("rung C={} ({})", r.clients, r.arm.label()),
            Duration::from_secs_f64(r.wall_secs),
        );
    }
    if let Some(p) = probe {
        collector.phase(
            "slow-reader probe".to_string(),
            Duration::from_secs_f64(p.wall_secs),
        );
    }

    // total_millis = the WORKLOAD's wall-time (rmp #699). The whole ladder ran before this report was
    // built, so the collector could not bracket it: an unbracketed start()/finish() timed only the
    // report's own emission (the committed baseline read `total_millis: 0.027` — 27 MICROseconds for
    // a 65-second ladder). The rungs (both arms) and the probe are driven back to back, so their
    // summed wall-time IS the run.
    let ladder_wall: f64 =
        rungs.iter().map(|r| r.wall_secs).sum::<f64>() + probe.map_or(0.0, |p| p.wall_secs);
    collector.record_total_duration(Duration::from_secs_f64(ladder_wall));

    // Resources (CPU + memory) from the BEST rung — measured on the SERVER process via /proc.
    collector.record_resources((
        CpuSection {
            user_secs: Some(best.cpu_user_secs),
            system_secs: Some(best.cpu_system_secs),
            mean_core_utilisation: Some(best.server_cores),
        },
        MemorySection {
            peak_rss_bytes: (best.peak_rss > 0).then_some(best.peak_rss),
            final_rss_bytes: (best.final_rss > 0).then_some(best.final_rss),
        },
    ));

    // throughput.* = the READ vector of the PRIMARY (mixed) arm's BEST rung — ONE coherent set of
    // transactions. `operations`, `ops_per_sec`, the percentiles and `abort_rate` all describe the
    // SAME reads. `abort_rate` is therefore the READ abort rate: a genuinely MEASURED 0.0, because an
    // auto-commit read runs at Snapshot Isolation and cannot abort (invariant I1). The WRITE layer's
    // abort rate is `engine_abort_rate` in the workload map, and the two are never merged (`rmp` #714,
    // #715). This section used to carry the whole ladder's op COUNT beside the best rung's RATE beside
    // the WRITERS' abort rate: three different populations in one row.
    {
        let t = collector.throughput_mut();
        t.operations = Some(best.ok_ops);
        t.ops_per_sec = Some(best.ops_per_sec);
        t.p50_latency_ms = Some(bench::ns_to_ms(best.overall.p50));
        t.p99_latency_ms = Some(bench::ns_to_ms(best.overall.p99));
        t.p999_latency_ms = Some(bench::ns_to_ms(best.overall.p999));
        t.abort_rate = read_abort_rate(best);
    }

    // Notes: a per-rung line, a per-family line at the top rung, and the knee diagnosis.
    collector.note(format!(
        "CONCURRENCY LADDER (read-heavy MIX, {} rungs × {} arm(s) over {} against '{}'): the headline \
         evidence is where throughput SATURATES while latency explodes and only a subset of cores stay \
         busy — the single-engine-thread vs off-thread-reader-pool signature — measured under a \
         PRODUCTION-SHAPED MIX (reads served while writes commit underneath), not against a frozen \
         graph.",
        rungs.len(),
        if primary == Arm::Mixed { 2 } else { 1 },
        args.ladder,
        args.db,
    ));
    collector.note(format!(
        "TWO LAYERS OF TRUTH, never conflated (rmp #714, #715). READ: throughput.* is ONE coherent \
         set — the {} reads of the best '{}' rung (C={}), at {:.1} ops/s, and throughput.abort_rate = \
         {} is the READ abort rate. It is a MEASURED zero, not a placeholder: a standalone auto-commit \
         read runs at SNAPSHOT ISOLATION (rmp #543/#545), so it can neither abort a writer nor be \
         aborted by one — that is invariant I1, and the run FAILS if a read ever aborts. WRITE: the \
         writers' evidence lives in the workload map and is split in two. ENGINE: {} of {} transaction \
         attempts were aborted by SSI (engine_abort_rate {}). APPLICATION: {} of {} business units \
         COMMITTED (write_commit_rate {}), at {} retries per commit, {} exhausting their retry budget. \
         A high engine abort rate WITH a full application commit rate is a HEALTHY system under \
         contention: the application-visible cost of contention is LATENCY (see write_p99_ms, which is \
         RETRY-INCLUSIVE), not lost work.",
        best.ok_ops,
        primary.label(),
        best.clients,
        best.ops_per_sec,
        read_abort_rate(best).map_or_else(|| "n/a".into(), |r| format!("{r:.6}")),
        write.aborts,
        write.attempts,
        write
            .engine_abort_rate()
            .map_or_else(|| "n/a (no write workload ran)".into(), |r| format!("{r:.6}")),
        write.committed,
        write.units,
        write
            .commit_rate()
            .map_or_else(|| "n/a".into(), |r| format!("{r:.6}")),
        write
            .retries_per_commit()
            .map_or_else(|| "n/a".into(), |r| format!("{r:.4}")),
        write.exhausted,
    ));
    collector.note(mix_cost_note(rungs, best, primary));
    collector.note(format!(
        "THE WRITE STREAM is production-shaped, not a storm: {} writer(s) paced at one business unit \
         every {}ms, each driven through MANAGED RETRY (bounded exponential backoff + jitter — what \
         session.execute_write does in every official driver). {:.0}% of the units are a \
         read-modify-write of one of {} TRENDING products (`SET p.hot = coalesce(p.hot,0)+1`); the \
         rest CREATE a PURCHASED edge on a random (user, product) pair. The hot component is what \
         makes SSI — and therefore the retry path — LOAD-BEARING: a purely random write stream conflicts \
         with nobody, aborts nothing, and leaves the retry path as dead code and the bounded-retries \
         invariant vacuous.",
        ctx.effective_writers(),
        args.write_every_ms,
        args.hot_write_fraction * 100.0,
        ctx.hot_keys,
    ));
    if let Some(p) = probe {
        collector.note(format!(
            "SLOW-READER PROBE (invariant I5, the GC pin — rmp #551): while {} heavy '{}' traversals \
             (p50 {:.1}ms, max {:.1}ms) held their MVCC snapshots open for {:.1}s, the writers \
             committed {} of {} business units underneath them ({} engine aborts). A long reader pins \
             the GC watermark; if that pin could stall the write path, this window would show ZERO \
             commits — and the ladder, whose reads are all short, would never have noticed.",
            p.reader_ops,
            p.family,
            bench::ns_to_ms(p.reader_pcts.p50),
            bench::ns_to_ms(p.reader_pcts.max),
            p.wall_secs,
            p.write.committed,
            p.write.units,
            p.write.aborts,
        ));
    }
    for r in rungs {
        collector.note(format!(
            "rung clients={} arm={}: {:.1} ops/s over {:.3}s ({} ok, {} err, {} read aborts); \
             p50={:.3}ms p90={:.3}ms p99={:.3}ms p99.9={:.3}ms max={:.3}ms; server {:.2} cores across \
             {} busy thread(s), busiest {:.2} core; peak RSS {:.1}MiB (VmHWM {:.1}MiB){}{}{}{}",
            r.clients,
            r.arm.label(),
            r.ops_per_sec,
            r.wall_secs,
            r.ok_ops,
            r.err_ops,
            r.reads.aborted,
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
            if r.read_errors.is_empty() {
                String::new()
            } else {
                format!("; READ FAILURES {}", r.read_errors.summary())
            },
            if r.write.attempted() {
                format!(
                    "; WRITES {}/{} units committed, {} of {} engine attempts aborted (rate {}), {} \
                     retries, {} exhausted",
                    r.write.committed,
                    r.write.units,
                    r.write.aborts,
                    r.write.attempts,
                    r.write
                        .engine_abort_rate()
                        .map_or_else(|| "n/a".into(), |x| format!("{x:.4}")),
                    r.write.retries,
                    r.write.exhausted,
                )
            } else {
                String::new()
            },
            match control_for(rungs, r).filter(|_| r.arm == Arm::Mixed) {
                Some(c) => format!(
                    "; COST OF THE MIX {} vs its control's {:.1} ops/s",
                    mix::mix_cost_pct(c.ops_per_sec, r.ops_per_sec)
                        .map_or_else(|| "n/a".into(), |p| format!("{p:+.1}%")),
                    c.ops_per_sec,
                ),
                None => String::new(),
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
    // --- Storage: the recommendation database's REAL on-disk footprint (rmp #699). This section used
    // to be left ENTIRELY at zero — store_bytes, wal_bytes, both amplification ratios — even though a
    // real store sat on disk for the whole ladder, so the report asserted the run had no durable
    // footprint at all. The WAL is a DIRECTORY of segment files (`graphus.wal/seg.<lsn>`): it is
    // measured by PATH, because a meter keying off the leaf file name would fold every WAL byte into
    // the store and report `wal_bytes: 0`, hiding the redo log completely.
    match (&args.store, &args.wal) {
        (Some(store), Some(wal)) => {
            collector
                .record_storage(store, wal, None)
                .map_err(|e| format!("cannot measure the store/WAL footprint: {e}"))?;
            // Amplification against the REAL logical dataset (the generator's CSV bytes). Absent that
            // figure the ratios are simply OMITTED rather than computed against an invented
            // per-element size.
            if args.logical_bytes > 0 {
                collector.record_amplification(args.logical_bytes, args.logical_bytes);
            }
            // Per-element durable cost (`rmp #711`, `#715`): a per-element cost is only honest if its
            // two inputs describe the SAME graph. `metadata.dataset` is the GENERATOR's seed counts —
            // but the mix's COMMON writes CREATE extra PURCHASED edges into this very store, so once
            // the writers have committed anything, the store no longer holds the graph those counts
            // describe. Dividing the measured image by them would be real arithmetic over a graph that
            // is not there: a figure wrong in a way no reader could see. Absent is the honest state
            // (exactly what fraud-oltp does for the same reason).
            let mixed_wrote = write.committed > 0;
            if mixed_wrote {
                collector.note(format!(
                    "storage.bytes_per_node / bytes_per_relationship are deliberately ABSENT \
                     (rmp #711/#714): the dataset counts are the GENERATOR's seed graph, while the \
                     mixed arm COMMITTED {} business unit(s) into this same store — most of them a \
                     CREATE of a new PURCHASED edge. The store therefore no longer holds the graph \
                     those counts describe, and a per-element cost computed from them would be real \
                     arithmetic over the wrong graph.",
                    write.committed,
                ));
            } else {
                collector.record_per_element_costs();
            }
            let s = collector.storage_mut();
            let (store_bytes, wal_bytes) = (
                s.store_bytes.unwrap_or_default(),
                s.wal_bytes.unwrap_or_default(),
            );
            collector.note(format!(
                "storage.* is the REAL on-disk footprint of the '{}' database after the ladder: a {} \
                 B store image plus a {} B WAL DIRECTORY of segment files (walked by PATH). The \
                 amplification ratios are those durable bytes over the generator's {} B logical CSV{}.",
                args.db,
                store_bytes,
                wal_bytes,
                args.logical_bytes,
                if mixed_wrote {
                    " — and they now include the durable cost of the writes the mix committed, so they \
                     are an UPPER bound on the load's own amplification"
                } else {
                    ", and storage.bytes_per_node / bytes_per_relationship amortise that store image \
                     over the loaded graph"
                },
            ));
        }
        _ => {
            collector.note(
                "storage.* is ABSENT = NOT MEASURED: no --store/--wal path was supplied (attach mode \
                 has no local store to walk). It is not a claim that the run wrote nothing — the \
                 schema omits an unmeasured vector rather than zero-filling it (rmp #711)."
                    .to_string(),
            );
        }
    }

    for line in diagnose_knee(rungs, proc_available, false) {
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

/// The **COST OF THE MIX** note, written for a human reader: what serving reads *while writes commit*
/// actually costs, rung by rung — the quantity a read-only ladder against a frozen graph structurally
/// cannot produce.
fn mix_cost_note(rungs: &[RungResult], best: &RungResult, primary: Arm) -> String {
    if primary != Arm::Mixed {
        return "THE COST OF THE MIX: NOT MEASURED — this run had no write workload (--writers 0), so \
                it is a pure read ladder against a FROZEN graph. It is a legitimate isolation \
                experiment, but it says nothing about how the server behaves when reads are served \
                while writes commit underneath, which is every production graph workload."
            .to_string();
    }
    let per_rung: Vec<String> = arm_rungs(rungs, Arm::Mixed)
        .iter()
        .map(|r| match control_for(rungs, r) {
            Some(c) => format!(
                "C={}: {:.1} → {:.1} ops/s ({}), p99 {:.1} → {:.1} ms",
                r.clients,
                c.ops_per_sec,
                r.ops_per_sec,
                mix::mix_cost_pct(c.ops_per_sec, r.ops_per_sec)
                    .map_or_else(|| "n/a".into(), |p| format!("{p:+.1}%")),
                bench::ns_to_ms(c.overall.p99),
                bench::ns_to_ms(r.overall.p99),
            ),
            None => format!(
                "C={}: {:.1} ops/s (no control arm)",
                r.clients, r.ops_per_sec
            ),
        })
        .collect();
    if per_rung.is_empty() || arm_rungs(rungs, Arm::Readonly).is_empty() {
        return "THE COST OF THE MIX: NOT MEASURED — the control arm was skipped (--mix-baseline 0), \
                so the mixed arm has nothing to be compared against."
            .to_string();
    }
    let headline = control_for(rungs, best)
        .and_then(|c| mix::mix_cost_pct(c.ops_per_sec, best.ops_per_sec))
        .map_or_else(
            || "n/a".to_string(),
            |p| format!("{p:+.1}% at the best rung (C={})", best.clients),
        );
    format!(
        "THE COST OF THE MIX (rmp #714). Every rung was run TWICE, back to back, same concurrency, \
         same op budget, same graph: once with the writers OFF (the control) and once with them ON \
         (the treatment — the production-shaped default this report headlines). What the mix costs the \
         READ path: {headline}. Rung by rung: {}. The control arm runs FIRST at every rung, so it \
         warms the buffer pool for the mixed arm — the cost reported here is therefore a conservative \
         LOWER BOUND. This is the number a capacity planner needs and that a read-only ladder against \
         a frozen graph can never produce.",
        per_rung.join(" | "),
    )
}

// ============================================================================================
// CLI
// ============================================================================================

/// The parsed `reco_bench` command line.
struct Args {
    /// Bolt-over-UDS socket path (local mode). Mutually exclusive with `bolt`.
    socket: Option<String>,
    /// Bolt-over-TCP(+TLS) URL (attach mode). Mutually exclusive with `socket`.
    bolt: Option<String>,
    user: String,
    password: String,
    db: String,
    /// Co-located server pid for `/proc` sampling (local mode only; ignored in attach mode).
    server_pid: Option<i64>,
    ladder: String,
    ops_per_rung: u64,
    min_ops_per_client: u64,
    users: u64,
    products: u64,
    friends: u64,
    purchased: u64,
    scenario: String,
    evidence_dir: Option<String>,
    /// The co-located database's store image (`.../databases/<db>/graphus.store`), for the REAL
    /// on-disk storage evidence. `None` (attach mode) ⇒ the storage section stays honestly zero.
    store: Option<String>,
    /// The co-located database's WAL **directory** (`.../databases/<db>/graphus.wal`, which holds the
    /// `seg.<lsn>` segment files). Measured by PATH, not by leaf file name.
    wal: Option<String>,
    /// Logical size of the loaded graph (the generator's CSV bytes), for the amplification ratios.
    /// `0` = not supplied, and the ratios stay at "not measured" rather than being invented.
    logical_bytes: u64,
    write_every_ms: u64,
    writers: usize,
    /// Share of writes landing on the trending hot set (`--hot-write-fraction`).
    hot_write_fraction: f64,
    /// Size of the trending hot set (`--hot-keys`).
    hot_keys: u64,
    /// Per-unit managed-retry budget in ms (`--retry-budget-ms`).
    retry_budget_ms: u64,
    /// Run the `readonly` CONTROL arm alongside the `mixed` arm (`--mix-baseline`).
    mix_baseline: bool,
    /// Slow-reader probe window in seconds (`--probe-secs`).
    probe_secs: f64,
    target_rps: f64,
    auto_extend: bool,
    read_timeout_ms: u64,
    seed: u64,
}

impl Args {
    /// The [`Target`] the ladder connects to: `--bolt <url>` (attach) or `--socket <path>` (local).
    /// Exactly one must be given.
    fn target(&self) -> Result<Target, String> {
        match (&self.bolt, &self.socket) {
            (Some(url), None) => Ok(Target::Bolt(BoltUrl::parse(url)?)),
            (None, Some(path)) => Ok(Target::Uds(PathBuf::from(path))),
            (Some(_), Some(_)) => {
                Err("--socket and --bolt are mutually exclusive (pick one transport)".to_string())
            }
            (None, None) => Err("one of --socket or --bolt is required".to_string()),
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
        let mut products = None;
        let mut friends = None;
        let mut purchased = None;
        let mut scenario = "product-recommendations".to_string();
        let mut evidence_dir = None;
        let mut store = None;
        let mut wal = None;
        let mut logical_bytes = 0u64;
        // The production-shaped MIX is the DEFAULT (rmp #714): the run everyone executes must be the
        // mix, not a read-only ladder against a frozen graph.
        let mut write_every_ms = DEFAULT_WRITE_EVERY_MS;
        let mut writers = DEFAULT_WRITERS;
        let mut hot_write_fraction = DEFAULT_HOT_WRITE_FRACTION;
        let mut hot_keys = DEFAULT_HOT_KEYS;
        let mut retry_budget_ms = DEFAULT_RETRY_BUDGET_MS;
        let mut mix_baseline = true;
        let mut probe_secs = DEFAULT_PROBE_SECS;
        let mut target_rps = 0.0f64;
        let mut auto_extend = false;
        let mut read_timeout_ms = 120_000u64;
        let mut seed = 0x5EC0_11EC_710Du64;

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
                    );
                }
                "--ladder" => ladder = Some(value()?),
                "--ops-per-rung" => {
                    ops_per_rung = Some(value()?.parse().map_err(|_| {
                        "--ops-per-rung must be a non-negative integer".to_string()
                    })?);
                }
                "--min-ops-per-client" => {
                    min_ops_per_client = parse_u64(&value()?, "--min-ops-per-client")?;
                }
                "--users" => users = Some(parse_u64(&value()?, "--users")?),
                "--products" => products = Some(parse_u64(&value()?, "--products")?),
                "--friends" => friends = Some(parse_u64(&value()?, "--friends")?),
                "--purchased" => purchased = Some(parse_u64(&value()?, "--purchased")?),
                "--scenario" => scenario = value()?,
                "--evidence-dir" => evidence_dir = Some(value()?),
                "--write-every-ms" => write_every_ms = parse_u64(&value()?, "--write-every-ms")?,
                "--writers" => {
                    writers = usize::try_from(parse_u64(&value()?, "--writers")?)
                        .map_err(|_| "--writers is too large".to_string())?;
                }
                "--hot-write-fraction" => {
                    let v = value()?;
                    hot_write_fraction = v
                        .parse()
                        .map_err(|_| format!("--hot-write-fraction must be a number, got {v:?}"))?;
                    if !(0.0..=1.0).contains(&hot_write_fraction) {
                        return Err("--hot-write-fraction must be in [0, 1]".to_string());
                    }
                }
                "--hot-keys" => hot_keys = parse_u64(&value()?, "--hot-keys")?.max(1),
                "--retry-budget-ms" => {
                    retry_budget_ms = parse_u64(&value()?, "--retry-budget-ms")?.max(1);
                }
                "--mix-baseline" => mix_baseline = parse_u64(&value()?, "--mix-baseline")? != 0,
                "--probe-secs" => {
                    let v = value()?;
                    probe_secs = v
                        .parse()
                        .map_err(|_| format!("--probe-secs must be a number, got {v:?}"))?;
                    if probe_secs < 0.0 {
                        return Err("--probe-secs must be >= 0".to_string());
                    }
                }
                "--target-rps" => {
                    let v = value()?;
                    target_rps = v.parse().map_err(|_| {
                        format!("--target-rps must be a non-negative number, got {v:?}")
                    })?;
                    if target_rps < 0.0 {
                        return Err("--target-rps must be >= 0".to_string());
                    }
                }
                "--store" => store = Some(value()?),
                "--wal" => wal = Some(value()?),
                "--logical-bytes" => logical_bytes = parse_u64(&value()?, "--logical-bytes")?,
                "--auto-extend" => auto_extend = true,
                "--read-timeout-ms" => read_timeout_ms = parse_u64(&value()?, "--read-timeout-ms")?,
                "--seed" => seed = parse_u64(&value()?, "--seed")?,
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown flag {other:?} (try --help)")),
            }
        }

        let user = user.ok_or("--user is required")?;
        let password = password.ok_or("--password is required")?;
        let db = db.ok_or("--db is required")?;
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
            bolt,
            user,
            password,
            db,
            server_pid,
            store,
            wal,
            logical_bytes,
            ladder,
            ops_per_rung,
            min_ops_per_client,
            users,
            products,
            friends,
            purchased,
            scenario,
            evidence_dir,
            write_every_ms,
            writers,
            hot_write_fraction,
            hot_keys,
            retry_budget_ms,
            mix_baseline,
            probe_secs,
            target_rps,
            auto_extend,
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
        "usage: reco_bench (--socket <path> --server-pid <pid> | --bolt <bolt+ssc://host:7687>) \\\n\
         \x20   --user <name> --password <pw> --db <name> \\\n\
         \x20   --ladder <csv e.g. 1,2,4,8> --ops-per-rung <N> \\\n\
         \x20   --users <N> --products <N> --friends <N> --purchased <N> \\\n\
         \x20   [--min-ops-per-client <N default 150>] [--scenario product-recommendations] \\\n\
         \x20   [--evidence-dir <dir>] \\\n\
         \x20   [--writers <N default 2>] [--write-every-ms <ms default 20>] \\\n\
         \x20   [--hot-write-fraction <f default 0.25>] [--hot-keys <N default 4>] \\\n\
         \x20   [--mix-baseline <0|1 default 1>] [--retry-budget-ms <ms default 15000>] \\\n\
         \x20   [--probe-secs <s default 3>] \\\n\
         \x20   [--store <graphus.store>] [--wal <graphus.wal dir>] [--logical-bytes <N>] \\\n\
         \x20   [--target-rps <R default 0 = closed-loop>] [--auto-extend] \\\n\
         \x20   [--read-timeout-ms <ms default 120000>] [--seed <u64>]"
    );
}
