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

use std::collections::{BTreeMap, HashMap};
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
use graphus_reco_gen::client::{BoltClient, BoltUrl, ClientError, ClientResult, QueryResult};
use graphus_reco_gen::mix::{
    self, Arm, ErrorSample, READ_LIVENESS_FLOOR, ReadInvariant, RetryPolicy, WriteKind, WriteVector,
};
use graphus_reco_gen::queries::FamilyKind;
use graphus_reco_gen::{EMBED_DIM, EPOCH_S, GenConfig, Generator, SplitMix64, queries, schema};

/// The number of nearest neighbours the ANN "similar products" family requests (`db.index.vector.
/// queryNodes`'s `$k`). Small — a real "you might also like" strip shows a handful.
const ANN_K: usize = 5;

/// The absolute dbHits envelope the index proof holds the VECTOR ANN read to.
///
/// An HNSW seek reads `O(ef_search)`, **NOT** `O(k)`: `query_knn` searches the base layer with
/// `ef_search.max(k)`, so every `k` below the default `ef_search` traverses exactly the same graph and
/// simply keeps more of what the search already materialised (`graphus_index::DEFAULT_EF_SEARCH` = 100;
/// see the same reasoning spelled out at `graphus-cypher`'s `seek_vector_knn` call site: "past a point
/// the binding constraint is `ef_search`, not k'"). A `k`-scaled bound is therefore wrong *by
/// construction* — MEASURED: `k = 5` reads 50 dbHits, which a `k × 8 = 40` bound rejected as a
/// "brute-force scan" even though the same read is 16× cheaper than the 800-dbHit full catalogue scan.
///
/// `2 × DEFAULT_EF_SEARCH` leaves margin for the over-fetch (`k' = 2k`) and the per-candidate MVCC/RBAC
/// re-checks while staying flat as the catalogue grows — which is the property that actually
/// distinguishes an HNSW seek from a brute-force scan. The ratio test against the measured full scan
/// remains the primary gate; this is the shape check beside it.
const ANN_EF_ENVELOPE: i64 = 200;

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

// --- I7: reads return correct results (the read-result oracle, `rmp` #744) -----------------------

/// The generation seed every `reco_gen` profile pins (`GenConfig::{tiny,fast,large,huge}`), and thus
/// the seed the loaded graph's `User.name` / `User.country` were built from. `reco_gen` exposes no seed
/// knob, so this is the seed of every graph the example loads; `--gen-seed` overrides it for a graph
/// hand-loaded with a different seed.
const RECO_GEN_SEED: u64 = 0x05EC_011E_C710_0001;

/// The `LIMIT` the `s_purchases` family caps its result at (kept in step with [`queries::READ_BATTERY`]).
const S_PURCHASES_LIMIT: usize = 50;

/// The default read-result verification sampling fraction (`--verify-fraction`): a small but NON-ZERO
/// value so invariant I7 runs by default. Roughly one read in `ceil(1/f)` per worker is checked against
/// ground truth, so the verification cost stays a bounded fraction of the workload.
const DEFAULT_VERIFY_FRACTION: f64 = 0.05;

/// How many mismatch exemplars I7 keeps for the report (bounded so a pathological run cannot flood it).
const MAX_VERIFY_SAMPLES: usize = 8;

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

    // I7 (`rmp` #744): build the ground-truth oracle ONCE. A `--gen-profile` reconstructs the exact
    // generation config (unlocking the s_degree check, and — with writers off — the exact s_purchases
    // set); without it, s_user (from the pinned generation seed) and the s_purchases well-formedness
    // check still run. The graph is "static" (safe for the exact purchased-set check) iff no writer runs.
    let gen_cfg = match &args.gen_profile {
        Some(name) => Some(GenConfig::profile(name).ok_or_else(|| {
            format!("unknown --gen-profile {name:?} (expected one of tiny|fast|large|huge)")
        })?),
        None => None,
    };
    let gen_seed = gen_cfg.as_ref().map_or(args.gen_seed, |c| c.seed);
    let graph_static = args.writers == 0 || args.write_every_ms == 0;
    let users = args.users.max(1);
    let products = args.products.max(1);
    let oracle = ReadOracle::build(gen_seed, users, products, gen_cfg.as_ref(), graph_static);

    // Capability preflight for the two index-backed families (`rmp` #746): the LOCAL (REST bulk-import)
    // path declares the full VECTOR + TEXT schema, so both are served; the ATTACH path declares only a
    // version-tolerant minimal schema (an older server may lack the VECTOR/TEXT DDL), so a family whose
    // warm-up errors is DROPPED from the mix and its index proof reported SKIPPED — never a false
    // failure against a server that legitimately does not have the index.
    let (ann_active, text_active) = preflight_index_families(
        &target,
        &args.user,
        &args.password,
        &args.db,
        &oracle,
        Duration::from_millis(args.read_timeout_ms),
    );
    let active_bag = build_active_bag(ann_active, text_active);

    let ctx = Arc::new(BenchCtx {
        target: target.clone(),
        user: args.user.clone(),
        password: args.password.clone(),
        db: args.db.clone(),
        read_timeout: Duration::from_millis(args.read_timeout_ms),
        users,
        products,
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
        verify_fraction: args.verify_fraction,
        oracle,
        active_bag,
        ann_active,
        text_active,
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

    // The invariants (I1–I7). Each prints its own PASS/FAIL line; any violation fails the process.
    let mut invariants = check_invariants(&rungs, probe.as_ref(), &ctx);
    // I8/I9 (`rmp` #746): PROVE the declared VECTOR + TEXT indexes are genuinely USED at runtime — over
    // the wire, under load, with PROFILE-measured dbHits — so the plan naming an index it then scans
    // (`rmp` #755) FAILS the run instead of passing behind a green tick.
    invariants.extend(prove_index_seeks(&ctx));
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
    /// Read-result verification sampling fraction (`--verify-fraction`); `0.0` disables I7.
    verify_fraction: f64,
    /// The ground-truth oracle I7 checks sampled reads against (`rmp` #744).
    oracle: ReadOracle,
    /// The weighted pick bag (`rmp` #746): each ACTIVE read-battery family's index repeated by its
    /// weight. The two index-backed families are present only when the target serves them (see the
    /// capability preflight); a uniform draw over this bag therefore reproduces the relative family
    /// weights among the families that are actually available.
    active_bag: Vec<usize>,
    /// Whether the VECTOR ANN family (`p_ann`) is served by the target (preflight result).
    ann_active: bool,
    /// Whether the TEXT `CONTAINS` family (`p_search`) is served by the target (preflight result).
    text_active: bool,
}

impl BenchCtx {
    /// Verify roughly every `ceil(1/verify_fraction)`-th read op per worker, or `0` when verification
    /// is disabled (`--verify-fraction 0`). A per-worker counter modulo this value picks the sampled
    /// ops, so the sampling is deterministic and its cost is a bounded fraction of the workload.
    fn verify_every(&self) -> u64 {
        if self.verify_fraction > 0.0 {
            (1.0 / self.verify_fraction).ceil() as u64
        } else {
            0
        }
    }

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
    /// I7 (`rmp` #744): sampled reads whose rows matched the generator's ground truth.
    verify_ok: u64,
    /// I7: sampled reads whose rows DIVERGED from ground truth (any one FAILS the run).
    verify_mismatch: u64,
    /// I7: sampled reads on a family the oracle does not reconstruct (not counted either way).
    verify_skipped: u64,
    /// A bounded sample of mismatch descriptions for the report.
    verify_samples: Vec<String>,
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
            verify_ok: 0,
            verify_mismatch: 0,
            verify_skipped: 0,
            verify_samples: Vec::new(),
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
    /// I7: sampled reads verified CORRECT against the generator's ground truth (`rmp` #744).
    verify_ok: u64,
    /// I7: sampled reads that returned WRONG rows (any one FAILS the run).
    verify_mismatch: u64,
    /// I7: sampled reads on a non-reconstructed family (informational).
    verify_skipped: u64,
    /// A bounded sample of the rung's mismatch descriptions.
    verify_samples: Vec<String>,
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
                merged.verify_ok += ws.verify_ok;
                merged.verify_mismatch += ws.verify_mismatch;
                merged.verify_skipped += ws.verify_skipped;
                for s in ws.verify_samples {
                    if merged.verify_samples.len() < MAX_VERIFY_SAMPLES {
                        merged.verify_samples.push(s);
                    }
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

    // I7 (`rmp` #744): a deterministic per-worker sampler. `read_ix` counts this worker's read ops; one
    // in `verify_every` of them is checked against the ground-truth oracle, so verification is a bounded
    // fraction of the load and does not materially distort throughput/latency.
    let verify_every = ctx.verify_every();
    let mut read_ix: u64 = 0;

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
        // Draw a family from the ACTIVE bag (`rmp` #746): the index-backed families are present only
        // when the target serves them, so an attach run against an older server without the VECTOR/TEXT
        // schema never picks a family it cannot serve.
        let fam = ctx.active_bag[(rng.next_u64() as usize) % ctx.active_bag.len()];
        let spec = &queries::READ_BATTERY[fam];
        // Build this op's parameters + verification anchor, and choose the dispatch path that actually
        // hits its declared index at runtime (`rmp` #746/#755) — auto-commit for the traversal and the
        // (inline-HNSW) ANN families, an explicit read transaction for the TEXT `CONTAINS` seek.
        let op = build_read_op(spec, &mut rng, &ctx.oracle, ctx.users);
        // I7 verification: sample the UserAnchored families (5% by default); ALWAYS verify the two
        // index-backed families (their correctness IS the exercise, and the check is O(rows) cheap).
        let sample = matches!(spec.kind, FamilyKind::VectorAnn | FamilyKind::TextContains)
            || (verify_every != 0 && read_ix % verify_every == 0);
        read_ix += 1;
        let op_start = scheduled.unwrap_or_else(Instant::now);
        let outcome = match spec.kind {
            // The TEXT search MUST run inside an explicit read transaction to seek NodeTextIndexSeek;
            // — the realistic `session.executeRead` shape (see `read_in_read_txn` on why this is no
            // longer what makes the seek happen).
            FamilyKind::TextContains => {
                read_in_read_txn(&mut client, spec.cypher, op.params.clone(), &ctx.db)
            }
            // UserAnchored + the (not-reader-safe, inline) ANN procedure hit their path auto-commit.
            _ => client.run(spec.cypher, op.params.clone(), &ctx.db),
        };
        match outcome {
            Ok(result) => {
                // Latency is stamped FIRST, so the verification never inflates it.
                let ns = u64::try_from(op_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
                stats.lat[fam].push(ns);
                stats.ok[fam] += 1;
                if sample {
                    match verify_read_op(spec, &result, &ctx.oracle, &op) {
                        ReadCheck::Verified => stats.verify_ok += 1,
                        ReadCheck::Skipped => stats.verify_skipped += 1,
                        ReadCheck::Mismatch(detail) => {
                            stats.verify_mismatch += 1;
                            if stats.verify_samples.len() < MAX_VERIFY_SAMPLES {
                                stats.verify_samples.push(detail);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                stats.err[fam] += 1;
                // I1: a read runs read-only (auto-commit at Snapshot Isolation, or a read-only explicit
                // transaction whose SIREAD-only footprint can never make it an SSI pivot — proven 0
                // aborts under a hot-write storm, `rmp` #746). A serialization abort here is therefore an
                // INVARIANT VIOLATION, not a statistic to be averaged into an error rate.
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

    let verify_ok = merged.verify_ok;
    let verify_mismatch = merged.verify_mismatch;
    let verify_skipped = merged.verify_skipped;
    let verify_samples = std::mem::take(&mut merged.verify_samples);

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
        verify_ok,
        verify_mismatch,
        verify_skipped,
        verify_samples,
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

// ============================================================================================
// I8 / I9 — the index-seek PROOF (the declared VECTOR + TEXT indexes are USED at runtime, rmp #746)
// ============================================================================================

/// A profiled read: the plan's operators and its **measured** total `dbHits` (`rmp` #752), plus the rows
/// (for a ground-truth check).
struct ProfiledRead {
    ops: Vec<String>,
    db_hits: i64,
    result: QueryResult,
}

/// Reads back a `PROFILE`d reply's measured plan (whatever dispatch path produced it).
///
/// # Errors
/// When the transport/statement failed, the reply carried no plan (a missing `PROFILE` prefix), or the
/// plan reported no measured `dbHits`.
fn profiled(result: ClientResult<QueryResult>) -> Result<ProfiledRead, String> {
    let result = result.map_err(|e| e.to_string())?;
    let plan = result.plan.as_ref().ok_or_else(|| {
        "the reply carried no PROFILE plan (did the query keep its PROFILE prefix?)".to_string()
    })?;
    let ops = plan.operators();
    let db_hits = plan
        .total_db_hits()
        .ok_or_else(|| "the PROFILE plan reported no measured dbHits".to_string())?;
    Ok(ProfiledRead {
        ops,
        db_hits,
        result,
    })
}

/// An index proof that could not even run (connect/login/statement fault): a hard FAIL.
fn proof_error(id: &'static str, title: &'static str, msg: &str) -> Invariant {
    Invariant {
        id,
        title,
        ok: false,
        detail: msg.to_string(),
    }
}

/// An index proof skipped because the family is not served (attach/older server): an informational PASS.
fn proof_skipped(id: &'static str, title: &'static str, why: &str) -> Invariant {
    Invariant {
        id,
        title,
        ok: true,
        detail: format!("SKIPPED — {why}"),
    }
}

/// PROVES, over the wire and UNDER LOAD, that the two declared index-backed families genuinely USE their
/// index at runtime — not merely that the planner named it (`rmp` #746/#755). Each query is PROFILEd on
/// the dispatch path the mix uses, its real `dbHits` measured, and compared against a full scan while the
/// same paced writers commit underneath. Returns the two invariants (I8, I9) and prints a
/// `GRAPHUS_RECO_INDEX_PROOF` sentinel carrying the measured numbers.
fn prove_index_seeks(ctx: &Arc<BenchCtx>) -> Vec<Invariant> {
    const T8: &str = "VECTOR ANN retrieval genuinely uses the HNSW index at runtime (I8)";
    const T9: &str = "TEXT CONTAINS genuinely SEEKS the trigram index, not the rmp #755 scan (I9)";

    let mut client = match ctx.target.connect(ctx.read_timeout) {
        Ok(c) => c,
        Err(e) => {
            let m = format!("index-proof connect failed: {e}");
            return vec![proof_error("I8", T8, &m), proof_error("I9", T9, &m)];
        }
    };
    if client.login(&ctx.user, &ctx.password).is_err() {
        return vec![
            proof_error("I8", T8, "index-proof login failed"),
            proof_error("I9", T9, "index-proof login failed"),
        ];
    }

    // Run the proof UNDER LOAD: the same paced writers the mix uses commit underneath the profiled
    // reads, so the seeks are certified WHILE writes are landing (not on a frozen graph). `usize::MAX-1`
    // keeps this window's write stream from replaying any ladder rung's.
    let stop = Arc::new(AtomicBool::new(false));
    let mut writer_handles: Vec<JoinHandle<WriteVector>> = Vec::new();
    for wi in 0..ctx.effective_writers() {
        writer_handles.push(spawn_writer(
            Arc::clone(ctx),
            Arc::clone(&stop),
            usize::MAX - 1,
            wi,
        ));
    }

    let (i8, v_sentinel) = prove_vector(&mut client, ctx, T8);
    let (i9, t_sentinel) = prove_text(&mut client, ctx, T9);

    stop.store(true, Ordering::Relaxed);
    for h in writer_handles {
        let _ = h.join();
    }
    let _ = client.goodbye();

    println!("GRAPHUS_RECO_INDEX_PROOF {v_sentinel} {t_sentinel}");
    vec![i8, i9]
}

/// The I8 proof: the VECTOR ANN family runs inline (`ProcedureCall`), reads O(k) not O(store), and
/// returns the queried category's products. Returns `(invariant, sentinel_fragment)`.
fn prove_vector(
    client: &mut BoltClient,
    ctx: &BenchCtx,
    title: &'static str,
) -> (Invariant, String) {
    if !ctx.ann_active {
        return (
            proof_skipped(
                "I8",
                title,
                "the VECTOR ANN family is not served by this target",
            ),
            "vector=skipped".to_string(),
        );
    }
    let category = ctx.oracle.ann_categories.first().copied().unwrap_or(0);
    let ann_spec = queries::READ_BATTERY
        .iter()
        .find(|q| q.kind == FamilyKind::VectorAnn)
        .expect("INVARIANT: the battery has one VECTOR ANN family");
    let query_vector: Vec<Value> = Generator::category_centroid(category)
        .iter()
        .map(|x| Value::Float(f64::from(*x)))
        .collect();
    let ann_params = vec![
        (
            "indexName".to_string(),
            Value::String(schema::PRODUCT_EMBEDDING_VECTOR.to_string()),
        ),
        ("k".to_string(), Value::Integer(ANN_K as i64)),
        ("queryVector".to_string(), Value::List(query_vector)),
    ];
    let ann =
        match profiled(client.run(&format!("PROFILE {}", ann_spec.cypher), ann_params, &ctx.db)) {
            Ok(p) => p,
            Err(e) => {
                return (
                    proof_error("I8", title, &format!("ANN PROFILE failed: {e}")),
                    "vector=error".to_string(),
                );
            }
        };
    // A forced full Product scan: no index serves `p.category <> ''`, so it reads every product.
    let scan = match profiled(client.run(
        "PROFILE MATCH (p:Product) WHERE p.category <> $x RETURN count(p) AS n",
        vec![("x".to_string(), Value::String(String::new()))],
        &ctx.db,
    )) {
        Ok(p) => p,
        Err(e) => {
            return (
                proof_error("I8", title, &format!("scan-reference PROFILE failed: {e}")),
                "vector=error".to_string(),
            );
        }
    };

    let op_present = ann.ops.iter().any(|o| o == "ProcedureCall");
    let ground_truth = verify_ann(&ann.result, &ctx.oracle, category);
    let sentinel = format!(
        "vector_op={} vector_hits={} scan_hits={} vector_k={ANN_K}",
        if op_present {
            "ProcedureCall"
        } else {
            "MISSING"
        },
        ann.db_hits,
        scan.db_hits
    );
    // Genuine HNSW seek: the ProcedureCall is present, the neighbours are correct, and the dbHits are
    // k-scale AND a fraction of a full scan (a brute-force scan-then-top-k would read the whole store).
    let fail: Option<String> = if !op_present {
        Some(format!(
            "the ANN plan has no ProcedureCall calling the vector index: {:?}",
            ann.ops
        ))
    } else if let ReadCheck::Mismatch(m) = &ground_truth {
        Some(format!("ANN ground truth failed: {m}"))
    } else if ann.db_hits >= scan.db_hits {
        Some(format!(
            "the ANN read as much of the store as a full scan: ann={} scan={}",
            ann.db_hits, scan.db_hits
        ))
    } else if ann.db_hits > ANN_EF_ENVELOPE {
        Some(format!(
            "the ANN dbHits {} exceed the HNSW candidate-list envelope ({ANN_EF_ENVELOPE}) — the read \
             is growing with the store, i.e. a brute-force scan rather than an HNSW seek",
            ann.db_hits
        ))
    } else {
        None
    };
    let inv = match fail {
        None => Invariant {
            id: "I8",
            title,
            ok: true,
            detail: format!(
                "ProcedureCall + HNSW seek: ann dbHits={} (k={ANN_K}, envelope {ANN_EF_ENVELOPE}) vs a \
                 {}-dbHit full Product scan; \
                 every neighbour is category '{}' with a strong score",
                ann.db_hits,
                scan.db_hits,
                Generator::category_name(category)
            ),
        },
        Some(m) => Invariant {
            id: "I8",
            title,
            ok: false,
            detail: m,
        },
    };
    (inv, sentinel)
}

/// The I9 proof: the TEXT `CONTAINS` search SEEKS `NodeTextIndexSeek` in an explicit transaction and
/// reads a small fraction of a forced index-free full `Product` label scan.
/// Returns `(invariant, sentinel_fragment)`.
fn prove_text(client: &mut BoltClient, ctx: &BenchCtx, title: &'static str) -> (Invariant, String) {
    if !ctx.text_active {
        return (
            proof_skipped(
                "I9",
                title,
                "the TEXT CONTAINS family is not served by this target",
            ),
            "text=skipped".to_string(),
        );
    }
    let text_spec = queries::READ_BATTERY
        .iter()
        .find(|q| q.kind == FamilyKind::TextContains)
        .expect("INVARIANT: the battery has one TEXT search family");
    let product_ix = 0u64;
    let params = vec![(
        "fragment".to_string(),
        Value::String(product_search_fragment(ctx.oracle.gen_seed, product_ix)),
    )];
    let profiled_q = format!("PROFILE {}", text_spec.cypher);
    // Explicit read transaction: seeks NodeTextIndexSeek (inline on the engine thread).
    let seek = match profiled(read_in_read_txn(client, &profiled_q, params, &ctx.db)) {
        Ok(p) => p,
        Err(e) => {
            return (
                proof_error("I9", title, &format!("TEXT seek PROFILE failed: {e}")),
                "text=error".to_string(),
            );
        }
    };
    // The STORE-SCALE reference: a forced full `Product` label scan that no index serves.
    //
    // Deliberately NOT "the same query auto-committed". That contrast was written against `rmp` #755
    // (the off-thread reader pool declining an index seek to a full scan), but #768 gave the pool node
    // TEXT-seek parity, so the auto-commit path now seeks exactly as an explicit transaction does —
    // measured on an isolated server as 23 dbHits either way. A gate whose PASS condition requires a
    // known defect to still be present INVERTS the moment the defect is fixed: it reports FAIL on an
    // improvement. Comparing against a real index-free scan measures the property actually claimed —
    // the seek reads a handful of products, not the catalogue — and holds however the read is
    // dispatched.
    let scan = match profiled(client.run(
        "PROFILE MATCH (p:Product) WHERE p.category <> $x RETURN count(p) AS n",
        vec![("x".to_string(), Value::String(String::new()))],
        &ctx.db,
    )) {
        Ok(p) => p,
        Err(e) => {
            return (
                proof_error(
                    "I9",
                    title,
                    &format!("TEXT scan-contrast PROFILE failed: {e}"),
                ),
                "text=error".to_string(),
            );
        }
    };

    let op_present = seek.ops.iter().any(|o| o == "NodeTextIndexSeek");
    let ground_truth = verify_text(&seek.result, &ctx.oracle, product_ix);
    let sentinel = format!(
        "text_op={} text_seek_hits={} text_scan_hits={}",
        if op_present {
            "NodeTextIndexSeek"
        } else {
            "MISSING"
        },
        seek.db_hits,
        scan.db_hits
    );
    let fail: Option<String> =
        if let Err(m) = bench::index_seek_verdict(op_present, seek.db_hits, scan.db_hits, 4) {
            Some(m)
        } else if let ReadCheck::Mismatch(m) = &ground_truth {
            Some(format!("TEXT ground truth failed: {m}"))
        } else {
            None
        };
    let inv = match fail {
        None => Invariant {
            id: "I9",
            title,
            ok: true,
            detail: format!(
                "NodeTextIndexSeek: trigram seek dbHits={} vs a {}-dbHit forced full Product scan — a \
                 genuine seek reading a handful of products, not a plan that names an index it then \
                 scans",
                seek.db_hits, scan.db_hits
            ),
        },
        Some(m) => Invariant {
            id: "I9",
            title,
            ok: false,
            detail: m,
        },
    };
    (inv, sentinel)
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

    // ---- I7: READS RETURN CORRECT RESULTS (recomputed from the generator, `rmp` #744) ------------
    // The reads are no longer pulled-and-discarded: a deterministic sample of them is checked against
    // ground truth recomputed from the same generator that built the loaded graph. A single WRONG,
    // MISSING, or MIS-ORDERED row FAILS the run; a verifier that verified NOTHING (fraction > 0 but no
    // sampled read landed on a reconstructed family) also FAILS — measure it or omit it.
    let verify_ok: u64 = rungs.iter().map(|r| r.verify_ok).sum();
    let verify_mismatch: u64 = rungs.iter().map(|r| r.verify_mismatch).sum();
    let verify_skipped: u64 = rungs.iter().map(|r| r.verify_skipped).sum();
    let mut samples: Vec<String> = Vec::new();
    for r in rungs {
        for s in &r.verify_samples {
            if samples.len() < MAX_VERIFY_SAMPLES {
                samples.push(s.clone());
            }
        }
    }
    let families = {
        let mut fams = vec!["s_user(name+country)"];
        if ctx.oracle.degree.is_some() {
            fams.push("s_degree");
        }
        fams.push(if ctx.oracle.purchases.is_some() {
            "s_purchases(exact set)"
        } else {
            "s_purchases(well-formed)"
        });
        fams.join(", ")
    };
    let (i7_ok, i7_detail) = if ctx.verify_fraction <= 0.0 {
        (
            true,
            "N/A — read-result verification is disabled (--verify-fraction 0)".to_string(),
        )
    } else if verify_mismatch > 0 {
        (
            false,
            format!(
                "{verify_mismatch} sampled read(s) returned WRONG results (of {} checked) — the server \
                 served incorrect rows, which a pull-and-discard driver would have passed green: {}",
                verify_ok + verify_mismatch,
                samples.join(" | ")
            ),
        )
    } else if verify_ok == 0 {
        (
            false,
            "--verify-fraction > 0 but NOT ONE sampled read was checked against ground truth — the \
             verifier is VACUOUS (measure it or omit it). Expected the read battery to include a \
             reconstructed family (s_user is always reconstructible here)."
                .to_string(),
        )
    } else {
        (
            true,
            format!(
                "{verify_ok} sampled read(s) returned CORRECT results (verified families: {families}; \
                 {verify_skipped} sampled read(s) fell on non-reconstructed families and were skipped). \
                 The FoF / collaborative-filtering families are not reconstructed here. Pass \
                 --gen-profile to also verify s_degree, and add --writers 0 to verify the exact \
                 s_purchases set."
            ),
        )
    };
    out.push(Invariant {
        id: "I7",
        title: "READS RETURN CORRECT RESULTS (recomputed from the generator, rmp #744)",
        ok: i7_ok,
        detail: i7_detail,
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
// I7 — reads return correct results (the read-result oracle, `rmp` #744)
// ============================================================================================

/// Ground truth recomputed from the deterministic generator, used to check that the server returns
/// CORRECT rows for a **sampled** read — so a server that serves WRONG, MISSING, or MIS-ORDERED rows can
/// no longer pass a green run whose reads were pulled and discarded (`rmp` #744). Built **once** at
/// startup; verification is then O(returned rows) per sampled op.
///
/// Which families are checked, and why not all:
/// * `s_user` (`RETURN u.name, u.country`) — always, from [`RECO_GEN_SEED`]. Stable under the write
///   workload (no writer touches `User.name`/`country`).
/// * `s_degree` (`RETURN count(f)`) — only with a `--gen-profile` (needs the reconstructed friend
///   graph). Stable under the write workload (the writers add `PURCHASED`/`hot`, never `FRIEND`).
/// * `s_purchases` (`RETURN p.id … LIMIT 50`) — the LIMIT-respecting, real-product well-formedness check
///   always; the exact set+cardinality check only when the graph is **static** (`--writers 0`), because
///   `WRITE_PURCHASE` adds `PURCHASED` edges (and the multigraph permits duplicates), which would make a
///   loaded-graph purchased oracle stale.
/// * `r1`–`r4` (the FoF / collaborative-filtering aggregations) — deliberately not reconstructed.
struct ReadOracle {
    /// The generation seed the loaded `User.name`/`User.country` were built from.
    gen_seed: u64,
    /// Number of users in the loaded graph (bounds the anchor index).
    users: u64,
    /// Every valid `Product` id (24-hex → `u128`) mapped to its product index. Lets `s_purchases` reject
    /// a returned id that is not a real product, and (when sound) test set membership. Small (`products`
    /// entries), so it is always built.
    product_index: HashMap<u128, u32>,
    /// Per-user undirected `FRIEND` degree — `Some` only when a `--gen-profile` reconstructs the graph.
    degree: Option<Vec<u64>>,
    /// Per-user SORTED distinct purchased product indices — `Some` only when the graph is static (no
    /// writers) AND a `--gen-profile` is given (the write workload otherwise mutates the purchased set).
    purchases: Option<Vec<Vec<u32>>>,
    /// The category index (`0..EMBED_DIM`) of every product, by product index — a pure function of the
    /// generation seed (`Generator::product_category_index`). The ANN ground-truth: a returned node id
    /// maps to a product whose category must equal the queried centroid's category.
    product_category: Vec<usize>,
    /// The category indices that have **at least [`ANN_K`] products**, so a k-NN query at their centroid
    /// returns a full k of that category (all same-category ⇒ the ground-truth check is exact). The ANN
    /// family draws its query category only from here. Falls back to all categories if none qualifies
    /// (a degenerate tiny catalogue), keeping the family runnable.
    ann_categories: Vec<usize>,
}

impl ReadOracle {
    /// Builds the oracle once. `cfg` is the reconstructed generation config (`Some` iff `--gen-profile`
    /// was given); `graph_static` is whether the run mutates the graph (`false` ⇒ writers are active, so
    /// the exact `s_purchases` set is not reconstructed).
    fn build(
        gen_seed: u64,
        users: u64,
        products: u64,
        cfg: Option<&GenConfig>,
        graph_static: bool,
    ) -> Self {
        // Product id → index (always; `products` is small — thousands, not millions).
        let mut product_index = HashMap::with_capacity(products as usize);
        for k in 0..products {
            if let Ok(key) = u128::from_str_radix(&Generator::product_id(k), 16) {
                product_index.insert(key, k as u32);
            }
        }
        // Per-product category + which categories have >= ANN_K products (the ANN query categories).
        // Category is a pure function of (gen_seed, product index), independent of the write workload.
        let product_category: Vec<usize> = (0..products)
            .map(|i| Generator::product_category_index(gen_seed, i))
            .collect();
        let mut per_category = [0usize; EMBED_DIM];
        for &c in &product_category {
            if c < EMBED_DIM {
                per_category[c] += 1;
            }
        }
        let mut ann_categories: Vec<usize> = (0..EMBED_DIM)
            .filter(|&c| per_category[c] >= ANN_K)
            .collect();
        if ann_categories.is_empty() {
            // Degenerate tiny catalogue: no category has k products. Query every category anyway (the
            // ground-truth check tolerates fewer than k rows), so the family still runs.
            ann_categories = (0..EMBED_DIM).collect();
        }
        let (degree, purchases) = match cfg {
            None => (None, None),
            Some(cfg) => {
                let generator = Generator::new(cfg.clone());
                // The exact purchased-set check is SOUND only when no writer ever adds a PURCHASED edge.
                let purchases = graph_static.then(|| {
                    generator
                        .purchases_by_user()
                        .into_iter()
                        .map(|ps| {
                            let mut v: Vec<u32> = ps.into_iter().map(|p| p as u32).collect();
                            v.sort_unstable();
                            v
                        })
                        .collect()
                });
                (Some(generator.friend_degrees()), purchases)
            }
        };
        Self {
            gen_seed,
            users,
            product_index,
            degree,
            purchases,
            product_category,
            ann_categories,
        }
    }

    /// Picks a query **category** for one ANN op from the well-populated set, by a uniform draw. The
    /// draw is the caller's RNG value reduced modulo the eligible-category count, so distinct ops spread
    /// across categories deterministically.
    fn ann_category(&self, draw: u64) -> usize {
        let n = self.ann_categories.len().max(1) as u64;
        self.ann_categories[(draw % n) as usize]
    }

    /// The generated category of the product whose 24-hex id is `id`, or `None` if `id` is not a real
    /// product (the ANN must never return a phantom node). Used by the ANN ground-truth check.
    fn category_of_product_id(&self, id: &str) -> Option<usize> {
        let key = u128::from_str_radix(id, 16).ok()?;
        let ix = *self.product_index.get(&key)? as usize;
        self.product_category.get(ix).copied()
    }

    /// The number of products in the loaded catalogue (bounds the TEXT search's anchor product index).
    fn products(&self) -> u64 {
        self.product_category.len() as u64
    }
}

/// One read op's parameters + the ground-truth ANCHOR the verifier checks the reply against. Built on
/// the worker thread from the family's [`FamilyKind`], so a family's parameter shape, dispatch path, and
/// verification all stay in one place (`rmp` #746).
struct ReadOp {
    /// The `$`-parameters for this op, already the shape the family's Cypher binds.
    params: Vec<(String, Value)>,
    /// What the verifier checks the reply against.
    anchor: OpAnchor,
}

/// The family-specific verification anchor for one read op.
enum OpAnchor {
    /// A `(:User {id})` anchor: the user index the op drew.
    User(u64),
    /// A VECTOR ANN query at `category`'s centroid: every returned node must be that category.
    Ann { category: usize },
    /// A TEXT `CONTAINS` search whose fragment is product `product_ix`'s unique reference code
    /// (`REF-…`, carried inside its name): that product's id must appear in the reply.
    Text { product_ix: u64 },
}

/// Builds one read op — its parameters and its verification anchor — for `spec`, drawing anchors from
/// `rng`. Each [`FamilyKind`] binds exactly the parameters its Cypher expects (`rmp` #746): the ANN's
/// `$queryVector` is a real `LIST<FLOAT>` category centroid, never a string-formatted literal.
fn build_read_op(
    spec: &queries::QuerySpec,
    rng: &mut SplitMix64,
    oracle: &ReadOracle,
    users: u64,
) -> ReadOp {
    match spec.kind {
        FamilyKind::UserAnchored => {
            let uidx = rng.next_u64() % users.max(1);
            ReadOp {
                params: vec![("id".to_string(), Value::String(Generator::user_id(uidx)))],
                anchor: OpAnchor::User(uidx),
            }
        }
        FamilyKind::VectorAnn => {
            let category = oracle.ann_category(rng.next_u64());
            // The query vector is the category CENTROID, passed as a real LIST<FLOAT> Bolt parameter.
            let query_vector: Vec<Value> = Generator::category_centroid(category)
                .iter()
                .map(|x| Value::Float(f64::from(*x)))
                .collect();
            ReadOp {
                params: vec![
                    (
                        "indexName".to_string(),
                        Value::String(schema::PRODUCT_EMBEDDING_VECTOR.to_string()),
                    ),
                    ("k".to_string(), Value::Integer(ANN_K as i64)),
                    ("queryVector".to_string(), Value::List(query_vector)),
                ],
                anchor: OpAnchor::Ann { category },
            }
        }
        FamilyKind::TextContains => {
            let product_ix = rng.next_u64() % oracle.products().max(1);
            ReadOp {
                params: vec![(
                    "fragment".to_string(),
                    Value::String(product_search_fragment(oracle.gen_seed, product_ix)),
                )],
                anchor: OpAnchor::Text { product_ix },
            }
        }
    }
}

/// A **selective** `CONTAINS` search fragment for product `i` — its unique **reference code**
/// (`REF-…`, [`Generator::product_model_code`]), a real "find this product by its model/SKU" search.
///
/// The reference code rather than a bare noun is used deliberately: the generator assembles names from
/// small shared pools (25 nouns, 15 adjectives, 10 brands), so every *trigram* of a natural-language
/// fragment appears across a large fraction of the catalogue and a `CONTAINS '<noun>'` seek is NOT
/// selective — its trigram candidate set is nearly the whole store, so it reads as much as a full scan
/// (measured 801 ≈ 801 dbHits) and the index-proof gate cannot tell a genuine seek from the `rmp` #755
/// decline. The reference code's trigrams are rare (they derive from the product's unique id), so its
/// seek reads a handful of products — a genuine, index-serviceable search. It is comma-free and, by
/// construction, present in product `i`'s own `name`, so the ground-truth check is exact. It does not
/// depend on the generation seed (the id is a pure function of the index), but the parameter is kept for
/// call-site symmetry with the other fragment builders.
fn product_search_fragment(_gen_seed: u64, i: u64) -> String {
    Generator::product_model_code(i)
}

/// Warms the two index-backed families once to learn whether the target actually serves them (`rmp`
/// #746). Returns `(ann_active, text_active)`.
///
/// The LOCAL (REST bulk-import) path declares the full VECTOR + TEXT schema, so both warm-ups succeed;
/// the ATTACH path declares only a version-tolerant minimal schema (an older server may lack the
/// VECTOR/TEXT DDL), so a family whose warm-up ERRORS is dropped from the mix and its index proof
/// reported SKIPPED — a server that legitimately has no such index must not fail the run. `UserAnchored`
/// families are always active. A connect/login failure drops both (the ladder's own connect gate then
/// surfaces the real fault).
fn preflight_index_families(
    target: &Target,
    user: &str,
    password: &str,
    db: &str,
    oracle: &ReadOracle,
    read_timeout: Duration,
) -> (bool, bool) {
    let mut client = match target.connect(read_timeout) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "reco_bench: index-family preflight: connect failed ({e}); dropping ANN + TEXT families"
            );
            return (false, false);
        }
    };
    if client.login(user, password).is_err() {
        eprintln!("reco_bench: index-family preflight: login failed; dropping ANN + TEXT families");
        return (false, false);
    }
    let mut rng = SplitMix64::new(0x0A22_15EE_C0DE_0746 ^ oracle.gen_seed);
    let ann_spec = queries::READ_BATTERY
        .iter()
        .find(|q| q.kind == FamilyKind::VectorAnn)
        .expect("INVARIANT: the read battery has one VECTOR ANN family");
    let ann_op = build_read_op(ann_spec, &mut rng, oracle, oracle.users);
    let ann_active = client.run(ann_spec.cypher, ann_op.params, db).is_ok();
    let text_spec = queries::READ_BATTERY
        .iter()
        .find(|q| q.kind == FamilyKind::TextContains)
        .expect("INVARIANT: the read battery has one TEXT search family");
    let text_op = build_read_op(text_spec, &mut rng, oracle, oracle.users);
    let text_active = read_in_read_txn(&mut client, text_spec.cypher, text_op.params, db).is_ok();
    if !ann_active {
        eprintln!(
            "reco_bench: index-family preflight: the VECTOR ANN family (db.index.vector.queryNodes) is \
             not served — dropping p_ann and skipping its index proof (I8)."
        );
    }
    if !text_active {
        eprintln!(
            "reco_bench: index-family preflight: the TEXT CONTAINS family is not served — dropping \
             p_search and skipping its index proof (I9)."
        );
    }
    let _ = client.goodbye();
    (ann_active, text_active)
}

/// Builds the weighted pick bag over the ACTIVE families (`rmp` #746): each family's index repeated by
/// its weight, dropping the two index-backed families when the preflight found the target does not serve
/// them. `UserAnchored` families are always included, so the bag is never empty.
fn build_active_bag(ann_active: bool, text_active: bool) -> Vec<usize> {
    let mut bag = Vec::new();
    for (i, spec) in queries::READ_BATTERY.iter().enumerate() {
        let active = match spec.kind {
            FamilyKind::UserAnchored => true,
            FamilyKind::VectorAnn => ann_active,
            FamilyKind::TextContains => text_active,
        };
        if active {
            for _ in 0..spec.weight {
                bag.push(i);
            }
        }
    }
    bag
}

/// Runs `cypher` inside an **explicit read transaction** (`BEGIN` → `RUN` → `COMMIT`) — the path that
/// makes an index-backed read really SEEK its index (`rmp` #746/#755). An auto-commit read is dispatched
/// to the off-thread reader pool. NOTE: the pool no longer declines index seeks for the kinds these
/// examples exercise (`rmp` #768 node TEXT, #769 relationship), so this is the realistic production
/// shape rather than a correctness requirement — MEASURED as identical dbHits either way. This is also the production `session.executeRead` shape.
/// On any server `FAILURE` the connection is `RESET` back to `READY`, so one failed read cannot poison it.
fn read_in_read_txn(
    client: &mut BoltClient,
    cypher: &str,
    params: Vec<(String, Value)>,
    db: &str,
) -> ClientResult<QueryResult> {
    let reset_on_failure = |client: &mut BoltClient, e: ClientError| -> ClientError {
        if matches!(e, ClientError::Failure(_)) {
            let _ = client.reset();
        }
        e
    };
    if let Err(e) = client.begin(db) {
        return Err(reset_on_failure(client, e));
    }
    match client.run_in_txn(cypher, params) {
        Ok(qr) => match client.commit() {
            Ok(()) => Ok(qr),
            Err(e) => Err(reset_on_failure(client, e)),
        },
        Err(e) => Err(reset_on_failure(client, e)),
    }
}

/// Routes one sampled reply to the verifier for its family kind (`rmp` #746). The `UserAnchored`
/// families keep their existing per-name verifier (`s_user` / `s_degree` / `s_purchases`); the two
/// index-backed families get their own ground-truth checks.
fn verify_read_op(
    spec: &queries::QuerySpec,
    result: &QueryResult,
    oracle: &ReadOracle,
    op: &ReadOp,
) -> ReadCheck {
    match op.anchor {
        OpAnchor::User(uidx) => verify_reco_read(spec.name, result, oracle, uidx),
        OpAnchor::Ann { category } => verify_ann(result, oracle, category),
        OpAnchor::Text { product_ix } => verify_text(result, oracle, product_ix),
    }
}

/// The verdict of checking one sampled read reply against the [`ReadOracle`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReadCheck {
    /// Checked against ground truth and CORRECT.
    Verified,
    /// This family is not deterministically reconstructed, or the oracle lacks the data: not counted.
    Skipped,
    /// Checked and WRONG — the string describes the divergence for the report.
    Mismatch(String),
}

/// Checks one sampled read reply against ground truth. **Pure** — no I/O, no clock — so it is
/// unit-testable (see the `tests` module) and adds nothing to the latency measured around it. `uidx`
/// is the anchor user index the worker drew. Only the deterministic structural families are checked.
fn verify_reco_read(
    family: &str,
    result: &QueryResult,
    oracle: &ReadOracle,
    uidx: u64,
) -> ReadCheck {
    match family {
        "s_user" => verify_s_user(result, oracle, uidx),
        "s_degree" => verify_s_degree(result, oracle, uidx),
        "s_purchases" => verify_s_purchases(result, oracle, uidx),
        _ => ReadCheck::Skipped,
    }
}

/// `p_ann`: the VECTOR (HNSW) k-NN ground truth (`rmp` #746). A query at category `category`'s CENTROID
/// must return only that category's products (the generator clusters each embedding one-hot on its
/// category axis), in DESCENDING normalized similarity, and the nearest must be a strong cosine match
/// (`>= 0.9`). Every returned node id must map to a **real** product whose GENERATED category is
/// `category` — so a server cannot pass by echoing the right category string on the wrong (or a phantom)
/// node. This is what makes the ANN falsifiable: a query at the WRONG centroid returns the wrong
/// category and FAILS here.
fn verify_ann(result: &QueryResult, oracle: &ReadOracle, category: usize) -> ReadCheck {
    if result.records.is_empty() {
        return ReadCheck::Mismatch(format!(
            "p_ann(cat {category}): the VECTOR index returned no products (built empty / declined?)"
        ));
    }
    if result.records.len() > ANN_K {
        return ReadCheck::Mismatch(format!(
            "p_ann(cat {category}): returned {} rows, more than k={ANN_K}",
            result.records.len()
        ));
    }
    let expected_name = Generator::category_name(category);
    let mut prev_score = f64::INFINITY;
    let mut top_score: Option<f64> = None;
    for row in 0..result.records.len() {
        let got_cat = match field_in_row(result, "category", row) {
            Some(Value::String(s)) => s.as_str(),
            other => {
                return ReadCheck::Mismatch(format!(
                    "p_ann(cat {category}): row {row} category cell is {other:?}, expected a string"
                ));
            }
        };
        if got_cat != expected_name {
            return ReadCheck::Mismatch(format!(
                "p_ann at category {category}'s centroid returned a '{got_cat}' product, expected all \
                 '{expected_name}' (clusters not separated / query vector wrong)"
            ));
        }
        let id = match field_in_row(result, "id", row) {
            Some(Value::String(s)) => s.clone(),
            other => {
                return ReadCheck::Mismatch(format!("p_ann: row {row} id cell is {other:?}"));
            }
        };
        match oracle.category_of_product_id(&id) {
            Some(c) if c == category => {}
            Some(c) => {
                return ReadCheck::Mismatch(format!(
                    "p_ann(cat {category}): node {id} is generated category {c}, not {category}"
                ));
            }
            None => {
                return ReadCheck::Mismatch(format!(
                    "p_ann: node {id} is not a real product (a phantom result)"
                ));
            }
        }
        let score = match field_in_row(result, "score", row) {
            Some(Value::Float(f)) => *f,
            Some(Value::Integer(n)) => *n as f64,
            other => {
                return ReadCheck::Mismatch(format!("p_ann: row {row} score cell is {other:?}"));
            }
        };
        // Scores must be non-increasing (nearest first); a tiny epsilon absorbs float noise.
        if score > prev_score + 1e-9 {
            return ReadCheck::Mismatch(format!(
                "p_ann: scores must be descending (nearest first), saw {score} after {prev_score}"
            ));
        }
        prev_score = score;
        top_score.get_or_insert(score);
    }
    if let Some(top) = top_score
        && top < 0.9
    {
        return ReadCheck::Mismatch(format!(
            "p_ann(cat {category}): top score {top} too low for a centroid query (index not used?)"
        ));
    }
    ReadCheck::Verified
}

/// `p_search`: the TEXT (trigram) `CONTAINS` ground truth (`rmp` #746). Searching a product's OWN unique
/// reference code (`REF-…`, [`product_search_fragment`]) must return that product's id among the matches
/// — a trigram index that silently dropped it (or returned an empty result, `rmp` #738) FAILS here.
/// Every returned id must be a real product.
fn verify_text(result: &QueryResult, oracle: &ReadOracle, product_ix: u64) -> ReadCheck {
    let expected_id = Generator::product_id(product_ix);
    let mut found = false;
    for row in 0..result.records.len() {
        let id = match field_in_row(result, "id", row) {
            Some(Value::String(s)) => s.clone(),
            other => {
                return ReadCheck::Mismatch(format!("p_search: row {row} id cell is {other:?}"));
            }
        };
        if oracle.category_of_product_id(&id).is_none() {
            return ReadCheck::Mismatch(format!(
                "p_search: returned id {id} is not a real product"
            ));
        }
        if id == expected_id {
            found = true;
        }
    }
    if found {
        ReadCheck::Verified
    } else {
        ReadCheck::Mismatch(format!(
            "p_search(product {product_ix}): a search for its own reference code did not return its id \
             {expected_id} ({} match rows)",
            result.records.len()
        ))
    }
}

/// The value of column `name` in row `row` of `result`, by field name (robust to column reordering).
fn field_in_row<'a>(result: &'a QueryResult, name: &str, row: usize) -> Option<&'a Value> {
    let col = result.fields.iter().position(|f| f == name)?;
    result.records.get(row)?.get(col)
}

/// The `String` value of column `name` in the first row, if present and a string.
fn string_field(result: &QueryResult, name: &str) -> Option<String> {
    match field_in_row(result, name, 0) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// `s_user`: `MATCH (u:User {id: $id}) RETURN u.name AS name, u.country AS country` — exactly one row
/// whose `name`/`country` equal the generator's ground truth.
fn verify_s_user(result: &QueryResult, oracle: &ReadOracle, uidx: u64) -> ReadCheck {
    if uidx >= oracle.users {
        return ReadCheck::Skipped;
    }
    if result.records.len() != 1 {
        return ReadCheck::Mismatch(format!(
            "s_user(u{uidx}): expected exactly 1 row for a unique :User(id), got {}",
            result.records.len()
        ));
    }
    let expected_name = Generator::user_name(oracle.gen_seed, uidx);
    let expected_country = Generator::user_country(oracle.gen_seed, uidx);
    let got_name = string_field(result, "name");
    let got_country = string_field(result, "country");
    if got_name.as_deref() == Some(expected_name.as_str())
        && got_country.as_deref() == Some(expected_country)
    {
        ReadCheck::Verified
    } else {
        ReadCheck::Mismatch(format!(
            "s_user(u{uidx}): expected (name={expected_name:?}, country={expected_country:?}), \
             got (name={got_name:?}, country={got_country:?})"
        ))
    }
}

/// `s_degree`: `RETURN count(f) AS degree` — a single scalar row equal to the user's undirected
/// `FRIEND` degree. Skipped when no `--gen-profile` reconstructed the friend graph.
fn verify_s_degree(result: &QueryResult, oracle: &ReadOracle, uidx: u64) -> ReadCheck {
    let Some(degree) = &oracle.degree else {
        return ReadCheck::Skipped;
    };
    let Some(&expected) = degree.get(uidx as usize) else {
        return ReadCheck::Skipped;
    };
    let got = match (
        result.records.len(),
        result.records.first().and_then(|r| r.first()),
    ) {
        (1, Some(Value::Integer(n))) => *n,
        _ => {
            return ReadCheck::Mismatch(format!(
                "s_degree(u{uidx}): expected a single integer row, got fields={:?} rows={}",
                result.fields,
                result.records.len()
            ));
        }
    };
    if i128::from(got) == i128::from(expected) {
        ReadCheck::Verified
    } else {
        ReadCheck::Mismatch(format!("s_degree(u{uidx}): expected {expected}, got {got}"))
    }
}

/// `s_purchases`: `RETURN p.id AS id, p.name AS name LIMIT 50`. Always sound: the LIMIT is respected and
/// every returned id is a real product. Exact set + cardinality only when the graph is static (writers
/// off) — see [`ReadOracle`].
fn verify_s_purchases(result: &QueryResult, oracle: &ReadOracle, uidx: u64) -> ReadCheck {
    if result.records.len() > S_PURCHASES_LIMIT {
        return ReadCheck::Mismatch(format!(
            "s_purchases(u{uidx}): returned {} rows, exceeding LIMIT {S_PURCHASES_LIMIT}",
            result.records.len()
        ));
    }
    let mut returned: Vec<u32> = Vec::with_capacity(result.records.len());
    for row_ix in 0..result.records.len() {
        let Some(Value::String(pid)) = field_in_row(result, "id", row_ix) else {
            return ReadCheck::Mismatch(format!(
                "s_purchases(u{uidx}): row {row_ix} has no string `id` column (fields={:?})",
                result.fields
            ));
        };
        let Ok(key) = u128::from_str_radix(pid, 16) else {
            return ReadCheck::Mismatch(format!(
                "s_purchases(u{uidx}): returned id {pid:?} is not a 24-hex product id"
            ));
        };
        let Some(&p_ix) = oracle.product_index.get(&key) else {
            return ReadCheck::Mismatch(format!(
                "s_purchases(u{uidx}): returned id {pid:?} is not a known Product"
            ));
        };
        returned.push(p_ix);
    }
    // Exact set + cardinality — sound only for a static graph (`purchases` is `Some`).
    if let Some(purchases) = &oracle.purchases {
        let Some(expected) = purchases.get(uidx as usize) else {
            return ReadCheck::Skipped;
        };
        let expected_count = expected.len().min(S_PURCHASES_LIMIT);
        if result.records.len() != expected_count {
            return ReadCheck::Mismatch(format!(
                "s_purchases(u{uidx}): returned {} rows, expected min(50, {}) = {expected_count}",
                result.records.len(),
                expected.len()
            ));
        }
        for p_ix in &returned {
            if expected.binary_search(p_ix).is_err() {
                return ReadCheck::Mismatch(format!(
                    "s_purchases(u{uidx}): returned product index {p_ix}, which the user never purchased"
                ));
            }
        }
    }
    ReadCheck::Verified
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
    /// I7 read-result verification sampling fraction (`--verify-fraction`, default
    /// [`DEFAULT_VERIFY_FRACTION`]); `0` disables verification.
    verify_fraction: f64,
    /// The generation profile to reconstruct the ground-truth oracle from (`--gen-profile`), unlocking
    /// the `s_degree` check (and, with `--writers 0`, the exact `s_purchases` set). `None` ⇒ only the
    /// generation-seed-based `s_user` and `s_purchases` well-formedness checks run.
    gen_profile: Option<String>,
    /// The generation seed for the `s_user` name/country check (`--gen-seed`, default
    /// [`RECO_GEN_SEED`], the seed every `reco_gen` profile pins). Ignored when `--gen-profile` is set
    /// (the profile's own seed is used).
    gen_seed: u64,
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
        let mut verify_fraction = DEFAULT_VERIFY_FRACTION;
        let mut gen_profile = None;
        let mut gen_seed = RECO_GEN_SEED;

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
                "--verify-fraction" => {
                    let v = value()?;
                    verify_fraction = v
                        .parse()
                        .map_err(|_| format!("--verify-fraction must be a number, got {v:?}"))?;
                    if !(0.0..=1.0).contains(&verify_fraction) {
                        return Err("--verify-fraction must be in [0, 1]".to_string());
                    }
                }
                "--gen-profile" => gen_profile = Some(value()?),
                "--gen-seed" => gen_seed = parse_u64(&value()?, "--gen-seed")?,
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
            verify_fraction,
            gen_profile,
            gen_seed,
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
         \x20   [--verify-fraction <f default 0.05, 0 disables I7>] \\\n\
         \x20   [--gen-profile <tiny|fast|large|huge, unlocks s_degree/exact s_purchases>] \\\n\
         \x20   [--gen-seed <u64 default = the reco_gen profile seed>] \\\n\
         \x20   [--read-timeout-ms <ms default 120000>] [--seed <u64>]"
    );
}

// ============================================================================================
// I7 read-result verifier — falsifiability tests (`rmp` #744)
// ============================================================================================
//
// These pin the whole point of I7: a CORRECT reply verifies, and a WRONG one (a divergent value, a
// missing row, an over-LIMIT result, a phantom product) is reported as a MISMATCH — which is exactly
// what a pull-and-discard reader could not tell apart. The oracle is recomputed from the same
// generator the loaded graph is built from, so the tests never assert a hand-picked answer.
#[cfg(test)]
mod tests {
    use super::*;

    /// Assembles a [`QueryResult`] for a family's `(fields, rows)` shape.
    fn qr(fields: &[&str], rows: Vec<Vec<Value>>) -> QueryResult {
        QueryResult {
            fields: fields.iter().map(|s| (*s).to_string()).collect(),
            records: rows,
            elapsed: Duration::ZERO,
            ..QueryResult::default()
        }
    }

    /// A small, fully-reconstructible generation config (the pinned generation seed).
    fn small_cfg() -> GenConfig {
        GenConfig {
            seed: RECO_GEN_SEED,
            users: 200,
            products: 40,
            friend_min: 3,
            friend_max: 10,
            avg_purchases_per_user: 4,
            popularity_skew: 3,
        }
    }

    #[test]
    fn i7_s_user_verifies_the_truth_and_flags_a_wrong_name() {
        let oracle = ReadOracle::build(RECO_GEN_SEED, 200, 40, None, true);
        let uidx = 7u64;
        let name = Generator::user_name(RECO_GEN_SEED, uidx);
        let country = Generator::user_country(RECO_GEN_SEED, uidx).to_string();

        let good = qr(
            &["name", "country"],
            vec![vec![
                Value::String(name.clone()),
                Value::String(country.clone()),
            ]],
        );
        assert_eq!(
            verify_reco_read("s_user", &good, &oracle, uidx),
            ReadCheck::Verified
        );

        // A server that returned the WRONG name must be caught.
        let wrong_name = qr(
            &["name", "country"],
            vec![vec![
                Value::String("Impostor Silva".to_string()),
                Value::String(country),
            ]],
        );
        assert!(matches!(
            verify_reco_read("s_user", &wrong_name, &oracle, uidx),
            ReadCheck::Mismatch(_)
        ));

        // A MISSING row (the server dropped the user) is a mismatch too.
        let empty = qr(&["name", "country"], vec![]);
        assert!(matches!(
            verify_reco_read("s_user", &empty, &oracle, uidx),
            ReadCheck::Mismatch(_)
        ));
    }

    #[test]
    fn i7_s_degree_verifies_the_count_and_flags_an_off_by_one() {
        let cfg = small_cfg();
        let oracle = ReadOracle::build(cfg.seed, cfg.users, cfg.products, Some(&cfg), true);
        let degrees = Generator::new(cfg).friend_degrees();
        let uidx = 5u64;
        let expected = i64::try_from(degrees[uidx as usize]).unwrap();

        let good = qr(&["degree"], vec![vec![Value::Integer(expected)]]);
        assert_eq!(
            verify_reco_read("s_degree", &good, &oracle, uidx),
            ReadCheck::Verified
        );

        let off_by_one = qr(&["degree"], vec![vec![Value::Integer(expected + 1)]]);
        assert!(matches!(
            verify_reco_read("s_degree", &off_by_one, &oracle, uidx),
            ReadCheck::Mismatch(_)
        ));

        // Without a --gen-profile the friend graph is not reconstructed: SKIP, never a false mismatch.
        let no_profile = ReadOracle::build(RECO_GEN_SEED, 200, 40, None, true);
        assert_eq!(
            verify_reco_read("s_degree", &good, &no_profile, uidx),
            ReadCheck::Skipped
        );
    }

    #[test]
    fn i7_s_purchases_verifies_the_set_and_flags_wrong_over_limit_and_phantom() {
        let cfg = small_cfg();
        // A static graph (writers off) ⇒ the exact purchased-set oracle is built.
        let oracle = ReadOracle::build(cfg.seed, cfg.users, cfg.products, Some(&cfg), true);
        let purchases = Generator::new(cfg.clone()).purchases_by_user();
        let uidx = (0..cfg.users)
            .find(|&u| {
                let n = purchases[u as usize].len();
                n > 0 && n <= S_PURCHASES_LIMIT
            })
            .expect("some user bought a verifiable (non-empty, <=50) set");
        let bought = &purchases[uidx as usize];

        let good = qr(
            &["id", "name"],
            bought
                .iter()
                .map(|&p| {
                    vec![
                        Value::String(Generator::product_id(p)),
                        Value::String(format!("Product {p}")),
                    ]
                })
                .collect(),
        );
        assert_eq!(
            verify_reco_read("s_purchases", &good, &oracle, uidx),
            ReadCheck::Verified
        );

        // A product the user never bought (added → wrong set + wrong cardinality) is caught.
        let not_bought = (0..cfg.products)
            .find(|p| !bought.contains(p))
            .expect("some product went unbought");
        let mut wrong_rows = good.records.clone();
        wrong_rows.push(vec![
            Value::String(Generator::product_id(not_bought)),
            Value::String("Phantom".to_string()),
        ]);
        assert!(matches!(
            verify_reco_read(
                "s_purchases",
                &qr(&["id", "name"], wrong_rows),
                &oracle,
                uidx
            ),
            ReadCheck::Mismatch(_)
        ));

        // The always-sound checks (no --gen-profile, writers on): a non-product id, and a result that
        // ignores the LIMIT, are both mismatches.
        let well_formed = ReadOracle::build(RECO_GEN_SEED, 200, 40, None, false);
        let phantom = qr(
            &["id", "name"],
            vec![vec![
                Value::String("ffffffffffffffffffffffff".to_string()),
                Value::String("Not A Product".to_string()),
            ]],
        );
        assert!(matches!(
            verify_reco_read("s_purchases", &phantom, &well_formed, 3),
            ReadCheck::Mismatch(_)
        ));

        let over_limit = qr(
            &["id", "name"],
            (0..=(S_PURCHASES_LIMIT as u64))
                .map(|p| {
                    vec![
                        Value::String(Generator::product_id(p % 40)),
                        Value::String("x".to_string()),
                    ]
                })
                .collect(),
        );
        assert!(matches!(
            verify_reco_read("s_purchases", &over_limit, &well_formed, 3),
            ReadCheck::Mismatch(_)
        ));
    }

    #[test]
    fn i7_unreconstructed_families_are_skipped_not_failed() {
        let oracle = ReadOracle::build(RECO_GEN_SEED, 200, 40, None, true);
        // r3_fof3 (and the other FoF/collaborative families) are not reconstructed: never a mismatch.
        let fof = qr(
            &["product", "reach"],
            vec![vec![
                Value::String("deadbeef".to_string()),
                Value::Integer(9),
            ]],
        );
        assert_eq!(
            verify_reco_read("r3_fof3", &fof, &oracle, 1),
            ReadCheck::Skipped
        );
    }

    // --- The index-backed families (`rmp` #746): parameter shape + falsifiable ground truth ---------

    /// The two new families bind exactly their kind's parameters, and the ANN query vector is a REAL
    /// `LIST<FLOAT>` Bolt parameter of the embedding dimension — never a string-formatted literal (the
    /// acceptance criterion).
    #[test]
    fn build_read_op_binds_kind_params_and_a_real_vector() {
        let cfg = small_cfg();
        let oracle = ReadOracle::build(cfg.seed, cfg.users, cfg.products, Some(&cfg), true);
        let mut rng = SplitMix64::new(1);
        for spec in queries::READ_BATTERY {
            let op = build_read_op(spec, &mut rng, &oracle, cfg.users);
            let keys: Vec<&str> = op.params.iter().map(|(k, _)| k.as_str()).collect();
            match spec.kind {
                FamilyKind::UserAnchored => assert_eq!(keys, ["id"], "{}", spec.name),
                FamilyKind::VectorAnn => {
                    assert_eq!(keys, ["indexName", "k", "queryVector"], "{}", spec.name);
                    let (_, qv) = op
                        .params
                        .iter()
                        .find(|(k, _)| k == "queryVector")
                        .expect("queryVector param");
                    match qv {
                        Value::List(v) => {
                            assert_eq!(v.len(), EMBED_DIM, "the query vector is EMBED_DIM long");
                            assert!(
                                v.iter().all(|x| matches!(x, Value::Float(_))),
                                "the query vector is a real LIST<FLOAT>, not a string literal"
                            );
                        }
                        other => panic!("queryVector must be a List<Float>, got {other:?}"),
                    }
                }
                FamilyKind::TextContains => assert_eq!(keys, ["fragment"], "{}", spec.name),
            }
        }
    }

    /// `verify_ann` accepts a genuine category cluster and FLAGS a wrong-centroid / low-score / phantom
    /// reply — so a query at the wrong centroid, or a scan-then-topk regression, fails the run.
    #[test]
    fn ann_verifies_a_cluster_and_flags_a_wrong_centroid() {
        let cfg = small_cfg();
        let oracle = ReadOracle::build(cfg.seed, cfg.users, cfg.products, Some(&cfg), true);
        let c = *oracle.ann_categories.first().expect("a populated category");
        let cat = Generator::category_name(c);
        let members: Vec<u64> = (0..cfg.products)
            .filter(|&i| Generator::product_category_index(cfg.seed, i) == c)
            .take(ANN_K.min(3))
            .collect();
        assert!(!members.is_empty());
        let good = qr(
            &["id", "category", "score"],
            members
                .iter()
                .enumerate()
                .map(|(k, &i)| {
                    vec![
                        Value::String(Generator::product_id(i)),
                        Value::String(cat.to_string()),
                        Value::Float(0.99 - 0.01 * k as f64),
                    ]
                })
                .collect(),
        );
        assert_eq!(verify_ann(&good, &oracle, c), ReadCheck::Verified);

        // Wrong centroid: a product of a DIFFERENT category is returned for category `c`.
        let other_c = (c + 1) % EMBED_DIM;
        let other = (0..cfg.products)
            .find(|&i| Generator::product_category_index(cfg.seed, i) == other_c)
            .expect("another category has a product");
        let wrong = qr(
            &["id", "category", "score"],
            vec![vec![
                Value::String(Generator::product_id(other)),
                Value::String(Generator::category_name(other_c).to_string()),
                Value::Float(0.99),
            ]],
        );
        assert!(matches!(
            verify_ann(&wrong, &oracle, c),
            ReadCheck::Mismatch(_)
        ));

        // A weak top score (the centroid's nearest neighbour must be a strong match).
        let weak = qr(
            &["id", "category", "score"],
            vec![vec![
                Value::String(Generator::product_id(members[0])),
                Value::String(cat.to_string()),
                Value::Float(0.5),
            ]],
        );
        assert!(matches!(
            verify_ann(&weak, &oracle, c),
            ReadCheck::Mismatch(_)
        ));

        // A phantom node (id echoing the right category but not a real product).
        let phantom = qr(
            &["id", "category", "score"],
            vec![vec![
                Value::String("f".repeat(24)),
                Value::String(cat.to_string()),
                Value::Float(0.99),
            ]],
        );
        assert!(matches!(
            verify_ann(&phantom, &oracle, c),
            ReadCheck::Mismatch(_)
        ));

        // Empty result (index built empty / declined).
        let empty = qr(&["id", "category", "score"], vec![]);
        assert!(matches!(
            verify_ann(&empty, &oracle, c),
            ReadCheck::Mismatch(_)
        ));
    }

    /// `verify_text` requires the searched product's own id to be returned, and FLAGS a silent drop
    /// (`rmp` #738) or a phantom id.
    #[test]
    fn text_verifies_the_product_is_found_and_flags_a_miss() {
        let cfg = small_cfg();
        let oracle = ReadOracle::build(cfg.seed, cfg.users, cfg.products, Some(&cfg), true);
        let pix = 3u64;
        let pid = Generator::product_id(pix);
        let good = qr(
            &["id"],
            vec![
                vec![Value::String(Generator::product_id(1))],
                vec![Value::String(pid.clone())],
            ],
        );
        assert_eq!(verify_text(&good, &oracle, pix), ReadCheck::Verified);

        // The index silently dropped the product (its own search term did not return it).
        let missing = qr(&["id"], vec![vec![Value::String(Generator::product_id(1))]]);
        assert!(matches!(
            verify_text(&missing, &oracle, pix),
            ReadCheck::Mismatch(_)
        ));

        // A phantom (non-product) id in the result.
        let phantom = qr(&["id"], vec![vec![Value::String("f".repeat(24))]]);
        assert!(matches!(
            verify_text(&phantom, &oracle, pix),
            ReadCheck::Mismatch(_)
        ));
    }

    /// The ANN query categories are only ever drawn from well-populated categories (≥ [`ANN_K`]
    /// products), so an all-`k`-match ground-truth check is exact.
    #[test]
    fn ann_categories_are_well_populated() {
        let cfg = small_cfg();
        let oracle = ReadOracle::build(cfg.seed, cfg.users, cfg.products, Some(&cfg), true);
        for &c in &oracle.ann_categories {
            let count = (0..cfg.products)
                .filter(|&i| Generator::product_category_index(cfg.seed, i) == c)
                .count();
            // Either a genuinely well-populated category, or the whole-set fallback for a tiny catalogue.
            assert!(count >= ANN_K || oracle.ann_categories.len() == EMBED_DIM);
        }
    }
}
