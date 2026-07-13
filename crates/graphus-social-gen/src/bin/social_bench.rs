//! `social_bench` — the **concurrent over-the-wire read driver**, the headline of the
//! `examples/social-network-large` performance evaluation (`rmp` #691).
//!
//! It drives **many simultaneous Bolt connections** against an already-loaded social graph and
//! **exposes whether reads scale across CPU cores under a production-shaped read/write MIX** — reads
//! served *while writes commit underneath*, which is the only workload that can exercise MVCC
//! snapshot-isolation reads, the off-thread reader pool, SSI, and the GC pins a long reader holds
//! (`rmp` #714). It sweeps a **concurrency ladder** and, for each rung, runs it **TWICE**: arm
//! `readonly` (the CONTROL — writers off) and arm `mixed` (the TREATMENT, and the default — writers
//! on). The delta between the two is *the cost of the mix*, which a read-only ladder against a frozen
//! graph structurally cannot see. The control runs FIRST, warming the buffer pool for the mixed arm,
//! so the measured cost is a conservative LOWER bound. Within an arm each rung:
//!
//! 1. spawns `C` worker OS threads, each owning its own [`BoltClient`] over its own connection, all
//!    released together by a start [`Barrier`], each looping a weighted mix of the read battery
//!    ([`graphus_social_gen::battery`]) until a shared op budget drains — and classifying every
//!    failure, because an auto-commit read runs at Snapshot Isolation and can never abort (I1);
//! 2. in the `mixed` arm, runs `--writers` paced writer threads. Each iteration is ONE business unit
//!    driven through [`mix::run_managed_write`] — managed retry with bounded exponential backoff and
//!    jitter, what `session.execute_write` does in every official driver. The write stream is
//!    realistic: `--hot-write-fraction` of it is a read-modify-write of a small trending article set,
//!    which is what makes SSI (and hence the retry path) load-bearing;
//! 3. in LOCAL mode, samples the **co-located server process** via `/proc/<server-pid>`: total +
//!    per-thread CPU (from `stat`), peak/current RSS (`status`), IO bytes (`io`, if readable) — so the
//!    report shows **read scaling vs C** by sampling the SERVER, not this driver (the historical
//!    `~1-core` figure was a driver artifact of the in-process battery);
//! 4. aggregates client throughput + latency percentiles (overall and per family) and the server's
//!    core utilisation, busy-thread count, and peak RSS.
//!
//! After the ladder a **slow-reader probe** (I5) holds one heavy reader open while the writers commit,
//! proving a long reader's GC pin does not stall the write path (`rmp` #551). The read vector and the
//! write vector are reported **separately** (`rmp` #714/#715): `throughput.*` is the READ vector of
//! the mixed arm's best rung (its `abort_rate` a measured `0.0` — invariant I1), and the WRITE vector
//! lives in the workload map, split into the ENGINE layer (attempts/aborts) and the APPLICATION layer
//! (units/committed).
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
//! - **Attach (`--bolt <url>`)** — Bolt-over-TCP + TLS against an ALREADY-RUNNING, possibly remote / older instance (`bolt+ssc://` accepts a self-signed cert). No co-located pid, so
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
use graphus_reco_gen::client::{BoltClient, BoltUrl, ClientResult, QueryResult};
use graphus_reco_gen::mix::{
    self, Arm, ErrorSample, READ_LIVENESS_FLOOR, ReadInvariant, RetryPolicy, WriteKind, WriteVector,
};
// The managed-retry backoff draws from the mix seam's OWN PRNG type (`graphus_reco_gen::SplitMix64`).
// Each generator crate defines its own SplitMix64, and they are distinct types even though the
// algorithm is identical — aliasing keeps that explicit instead of letting a reader assume the
// workload RNG below and the backoff RNG are interchangeable.
use graphus_reco_gen::SplitMix64 as BackoffRng;
use graphus_social_gen::{
    DegreeDist, EPOCH_S, GenConfig, Generator, REG_SPAN_S, SplitMix64, battery,
};

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

/// The default read-result verification sampling fraction (`--verify-fraction`, `rmp` #744): a small
/// but NON-ZERO value so invariant I7 runs by default. Roughly one read in `ceil(1/f)` per worker is
/// checked against ground truth, so verification is a bounded fraction of the workload.
const DEFAULT_VERIFY_FRACTION: f64 = 0.05;

/// How many mismatch exemplars I7 keeps for the report (bounded so a pathological run cannot flood it).
const MAX_VERIFY_SAMPLES: usize = 8;

// --- The production-shaped MIX defaults (`rmp` #714). The run everyone executes MUST be the mix; a
// read-only default measured a FROZEN graph and could not expose one concurrency mechanism. ---------

/// Default concurrent writer count (`--writers`). `0` = a pure read ladder.
const DEFAULT_WRITERS: usize = 2;
/// Default writer pacing (`--write-every-ms`): a steady, production-shaped trickle, not a storm.
const DEFAULT_WRITE_EVERY_MS: u64 = 20;
/// Default share of writes landing on the trending hot set (`--hot-write-fraction`).
const DEFAULT_HOT_WRITE_FRACTION: f64 = 0.25;
/// Default size of the trending hot set (`--hot-keys`).
const DEFAULT_HOT_KEYS: u64 = 4;
/// Default per-unit managed-retry budget (`--retry-budget-ms`).
const DEFAULT_RETRY_BUDGET_MS: u64 = 15_000;
/// Default slow-reader probe window in seconds (`--probe-secs`).
const DEFAULT_PROBE_SECS: f64 = 3.0;
/// The battery family the slow-reader probe repeats: the heaviest whole-set aggregation available.
const PROBE_FAMILY: &str = "top_liked";

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

    // I7 (`rmp` #744): reconstruct the FRIEND ground-truth oracle ONCE, but only when a --gen-profile
    // resolves the SAME GenConfig the loader used AND a structural cross-check confirms it reproduced
    // the loaded edge count. A wrongly-reconstructed oracle must never FALSE-FAIL a correct server, so
    // any doubt leaves the oracle None and I7 reports N/A.
    let oracle = build_read_oracle(&args);

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
        verify_fraction: args.verify_fraction,
        oracle,
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
    let arms = ctx.arms(args.mix_baseline);
    eprintln!(
        "social_bench: target={} db={} pid={} ladder={:?} arms={:?} ops/rung={} min_ops/client={} \
         users={} articles={} writers={} write_every_ms={} hot_write_fraction={} hot_keys={} \
         retry_budget_ms={} target_rps={} auto_extend={} clk_tck={clk_tck} proc_sampling={} mode={} \
         active_families={:?}",
        target.label(),
        args.db,
        server_pid,
        ladder,
        arms.iter().map(|a| a.label()).collect::<Vec<_>>(),
        args.ops_per_rung,
        args.min_ops_per_client,
        ctx.users,
        ctx.articles,
        ctx.effective_writers(),
        args.write_every_ms,
        args.hot_write_fraction,
        ctx.hot_keys,
        args.retry_budget_ms,
        args.target_rps,
        args.auto_extend,
        proc_available,
        if external { "external" } else { "local" },
        active_names,
    );

    // The PAIRED ladder: every rung is driven once per arm, control FIRST (its cache warming makes the
    // measured cost of the mix a conservative lower bound). The reader seed is keyed to the LADDER
    // index, not the arm, so both arms replay the SAME read stream — the delta is the writers, nothing
    // else.
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

    // Auto-extend past the tested ladder while throughput is still rising (so the knee is located).
    // The decision is taken on the PRIMARY arm; each extension still runs the full pair.
    if args.auto_extend && !rungs.is_empty() {
        let primary = primary_arm(&rungs);
        let mut rung_ix = ladder.len();
        loop {
            if rungs.len() >= MAX_TOTAL_RUNGS {
                eprintln!("social_bench: auto-extend stopped at the {MAX_TOTAL_RUNGS}-rung cap.");
                break;
            }
            let series: Vec<&RungResult> = rungs.iter().filter(|r| r.arm == primary).collect();
            let Some(last) = series.last() else { break };
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
        return Err("empty ladder produced no rungs".into());
    }

    // I5 — the SLOW-READER probe (a long reader's GC pin must not stall the writers, rmp #551).
    let probe = if ctx.effective_writers() > 0 {
        let p = run_slow_reader_probe(&ctx, args.probe_secs);
        print_probe_line(&p);
        Some(p)
    } else {
        eprintln!(
            "social_bench: slow-reader probe SKIPPED (no writers: --writers 0 is a pure read ladder)."
        );
        None
    };

    print_report(&ctx, &rungs, proc_available, external);
    let invariants = check_invariants(&rungs, probe.as_ref(), &ctx);
    let invariants_ok = print_invariants(&invariants);
    print_client_stats_sentinels(&rungs, probe.as_ref(), external, invariants_ok);

    if external {
        eprintln!(
            "social_bench: attach mode — evidence report is emitted by measure_target (from the /metrics before/after delta)."
        );
    } else if let Some(dir) = &args.evidence_dir {
        write_evidence(dir, &args, &ctx, &rungs, probe.as_ref(), proc_available)
            .map_err(|e| format!("failed to write evidence to {dir}: {e}"))?;
    }

    // Exit gate: a breached reader error rate OR a violated invariant marks a broken run.
    let mut ok = invariants_ok;
    for r in &rungs {
        let attempts = r.ok_ops + r.err_ops;
        if attempts > 0 {
            let rate = r.err_ops as f64 / attempts as f64;
            if rate > MAX_ERROR_RATE {
                eprintln!(
                    "social_bench: FAIL rung clients={} arm={}: reader error rate {:.1}% ({} of {} \
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
            "social_bench: OK — every rung stayed under the {:.0}% reader-error threshold and every \
             invariant held.",
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
    /// Requested concurrent writer count (`--writers`); `0` = a pure read ladder.
    writers: usize,
    /// Share of writes that land on the trending hot set (`--hot-write-fraction`).
    hot_write_fraction: f64,
    /// Size of the trending hot set (`--hot-keys`).
    hot_keys: u64,
    /// The managed-retry policy each business unit is driven under.
    retry: RetryPolicy,
    target_rps: f64,
    seed: u64,
    /// Indices (into [`battery::ALL`]) of the families the target serves.
    active: Vec<usize>,
    /// The weighted pick bag over `active`.
    bag: Vec<usize>,
    /// Read-result verification sampling fraction (`--verify-fraction`); `0.0` disables I7.
    verify_fraction: f64,
    /// The ground-truth oracle I7 checks sampled reads against (`Some` only with a `--gen-profile`).
    oracle: Option<SocialReadOracle>,
}

impl BenchCtx {
    /// Verify roughly every `ceil(1/verify_fraction)`-th read op per worker, or `0` when verification
    /// is disabled or has no oracle. A per-worker counter modulo this value picks the sampled ops, so
    /// the sampling is deterministic and its cost is a bounded fraction of the workload.
    fn verify_every(&self) -> u64 {
        if self.verify_fraction > 0.0 && self.oracle.is_some() {
            (1.0 / self.verify_fraction).ceil() as u64
        } else {
            0
        }
    }

    /// The effective per-rung op budget: the larger of the requested global budget and the per-client
    /// floor (`clients × min_ops_per_client`), so per-family sample counts do not collapse as the
    /// ladder widens.
    fn effective_budget(&self, clients: usize) -> u64 {
        self.ops_per_rung
            .max(self.min_ops_per_client.saturating_mul(clients as u64))
    }

    /// The number of concurrent writers actually spawned. Zero when writes are disabled — either by
    /// pacing (`--write-every-ms 0`) or explicitly (`--writers 0`, the pure-read-ladder isolation
    /// experiment).
    ///
    /// `--writers 0` is the documented OFF switch, so it MUST yield zero writers. The previous
    /// `self.writers.max(1)` silently floored it back to one, which made the read-only baseline
    /// unreachable: the "writers off" run still had a writer committing underneath it.
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
    /// [`WriteKind::Common`] (the bulk) touches a RANDOM user's `registered` timestamp and hardly ever
    /// conflicts; [`WriteKind::Hot`] is a read-modify-write of one of the `hot_keys` trending articles
    /// (`SET a.hot = coalesce(a.hot, 0) + 1`) — the component that actually exercises SSI, because two
    /// concurrent read-modify-writes of the same node are precisely the rw-antidependency cycle SSI
    /// exists to break. Returns `(kind, cypher, params)`.
    fn write_unit(
        &self,
        rng: &mut SplitMix64,
        ts: i64,
    ) -> (WriteKind, &'static str, Vec<(String, Value)>) {
        match mix::pick_write_kind(rng.next_u64(), self.hot_write_fraction) {
            WriteKind::Hot => {
                let aid = Generator::article_id(rng.next_u64() % self.hot_keys.min(self.articles));
                (
                    WriteKind::Hot,
                    battery::WRITE_ARTICLE_HOT,
                    vec![("id".to_string(), Value::String(aid))],
                )
            }
            WriteKind::Common => {
                let uid = Generator::user_id(rng.next_u64() % self.users);
                (
                    WriteKind::Common,
                    battery::WRITE_USER_TOUCH,
                    vec![
                        ("id".to_string(), Value::String(uid)),
                        ("ts".to_string(), Value::Integer(ts)),
                    ],
                )
            }
        }
    }
}

/// One worker's accumulated per-family stats (indexed by position in [`battery::ALL`]).
struct WorkerStats {
    lat: Vec<Vec<u64>>,
    ok: Vec<u64>,
    err: Vec<u64>,
    connect_errors: u64,
    /// The READ invariant (I1): an auto-commit read runs at Snapshot Isolation and can NEVER abort.
    /// Before `rmp` #714 every reader failure was lumped into `err`, so a serialization abort on the
    /// read path would have been silently averaged into an error rate and the run would have passed.
    reads: ReadInvariant,
    /// WHAT the failed reads actually failed with. An error RATE without the error is a number, not
    /// evidence — see [`ErrorSample`].
    read_errors: ErrorSample,
    /// I7 (`rmp` #744): sampled reads whose count matched the generator's ground truth.
    verify_ok: u64,
    /// I7: sampled reads whose count DIVERGED from ground truth (any one FAILS the run).
    verify_mismatch: u64,
    /// I7: sampled reads on a non-reconstructed family / degenerate anchors (not counted either way).
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
    /// I7: sampled reads that returned WRONG counts (any one FAILS the run).
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
            // A worker thread panicked (it never unwraps on I/O, so this should not happen); count it
            // as an error so the exit gate reacts rather than silently dropping it.
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

    aggregate_rung(
        arm,
        clients,
        budget,
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
            write,
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
    // I7 (`rmp` #744): a deterministic per-worker sampler. `read_ix` counts this worker's read ops; one
    // in `verify_every` of them is checked against the ground-truth oracle, so verification is a bounded
    // fraction of the load and does not materially distort throughput/latency.
    let verify_every = ctx.verify_every();
    let mut read_ix: u64 = 0;
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
        let u0_idx = rng.next_u64() % u0_pool;
        let u1_idx = rng.next_u64() % u0_pool;
        let u0 = Generator::user_id(u0_idx);
        let u1 = Generator::user_id(u1_idx);
        let params = op_params(fam.params, &u0, &u1, &ctx.term, ctx.since);
        // Sample this op for I7 verification (before the round-trip, so the decision is deterministic).
        let sample = verify_every != 0 && read_ix % verify_every == 0;
        read_ix += 1;
        let op_start = scheduled.unwrap_or_else(Instant::now);
        match client.run(fam.cypher, params, &ctx.db) {
            Ok(result) => {
                // Latency is stamped FIRST, so the (sampled-only) verification never inflates it.
                let ns = u64::try_from(op_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
                stats.lat[fam_ix].push(ns);
                stats.ok[fam_ix] += 1;
                if sample && let Some(oracle) = &ctx.oracle {
                    match verify_social_read(fam.name, &result, oracle, u0_idx, u1_idx) {
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
                stats.err[fam_ix] += 1;
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
/// [`battery::WRITE_USER_TOUCH`] on a random user or — with probability `hot_write_fraction` — a
/// read-modify-write of one of the `hot_keys` trending articles ([`battery::WRITE_ARTICLE_HOT`]),
/// which is what makes SSI and the retry path load-bearing rather than dead code.
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
                eprintln!("social_bench: writer {writer_ix} could not connect: {e}");
                return v;
            }
        };
        if let Err(e) = client.login(&ctx.user, &ctx.password) {
            v.other_errors += 1;
            eprintln!("social_bench: writer {writer_ix} could not log in: {e}");
            return v;
        }
        let mut rng = SplitMix64::new(
            ctx.seed
                .wrapping_add((rung_ix as u64).wrapping_mul(0xA076_1D64_78BD_642F))
                .wrapping_add((writer_ix as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F))
                ^ 0x5757_5252_0000_0001,
        );
        let mut backoff_rng = BackoffRng::new(rng.next_u64());
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

/// The raw `/proc` + writer samples taken around a rung.
struct RungSamples {
    cpu: (CpuTicks, CpuTicks),
    threads_start: BTreeMap<u64, u64>,
    threads_end: BTreeMap<u64, u64>,
    io: (Option<u64>, Option<u64>),
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
        verify_ok: merged.verify_ok,
        verify_mismatch: merged.verify_mismatch,
        verify_skipped: merged.verify_skipped,
        verify_samples: std::mem::take(&mut merged.verify_samples),
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

/// Holds one deliberately **slow** reader open (repeating the heaviest family the target serves) while
/// the writers commit underneath it, and reports what each side achieved **inside that window**.
///
/// This is the GC-pin / long-reader path (`rmp` #551): a reader's MVCC snapshot pins the GC watermark
/// for as long as it lives. If that pin could stall the write path, the writers would commit *nothing*
/// while the heavy reader runs — and the ladder, whose reads are mostly short, would never notice.
///
/// The probe family is drawn from the **ACTIVE** set (the families the capability preflight proved the
/// target can serve): [`PROBE_FAMILY`] when it survived the preflight, otherwise the last active
/// family. Picking it from [`battery::ALL`] instead would let the probe hammer a family the target
/// rejects — every op an error, and the invariant it exists to check silently unmeasurable.
fn run_slow_reader_probe(ctx: &Arc<BenchCtx>, probe_secs: f64) -> ProbeResult {
    let fam_ix = ctx
        .active
        .iter()
        .copied()
        .find(|&i| battery::ALL[i].name == PROBE_FAMILY)
        .or_else(|| ctx.active.last().copied())
        .expect("INVARIANT: run() rejects an empty active family set before building the BenchCtx");
    let family = &battery::ALL[fam_ix];

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
                    let u0 = Generator::user_id(rng.next_u64() % ctx.users);
                    let u1 = Generator::user_id(rng.next_u64() % ctx.users);
                    let params = op_params(family.params, &u0, &u1, &ctx.term, ctx.since);
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

fn print_report(ctx: &BenchCtx, rungs: &[RungResult], proc_available: bool, external: bool) {
    println!(
        "\n=== social_bench: concurrency ladder, paired arms ({} active families) ===",
        ctx.active.len()
    );
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

/// The PRIMARY arm's rung with the highest client count (ties resolved to the last such rung).
///
/// Every headline is drawn from the **primary** arm — the `mixed` one when a write workload ran. A max
/// over BOTH arms would silently report the control (writers off) whenever the mix cost enough
/// throughput, which is exactly the fiction this task exists to kill.
fn top_rung(rungs: &[RungResult]) -> &RungResult {
    let primary = primary_arm(rungs);
    rungs
        .iter()
        .filter(|r| r.arm == primary)
        .max_by_key(|r| r.clients)
        .expect("INVARIANT: caller guarantees a non-empty ladder")
}

/// The PRIMARY arm's rung with the highest throughput (the saturation point).
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
/// (writers on), and the delta. This is the quantity a read-only ladder against a frozen graph cannot
/// produce, and it is what a capacity planner actually needs.
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
    // A scaling verdict needs a CONCURRENCY SWEEP to stand on. With a single-client ladder there is
    // nothing to spread, so a low busy-thread count says nothing about the server's ability to scale —
    // asserting a ceiling from it would be an artifact of the ladder, not a property of the server.
    // (This is the same class of mistake as the in-process battery that measured the driver.)
    if best.clients <= 1 {
        out.push(
            "VERDICT: NOT ASSESSABLE — this ladder never ran more than one concurrent client, so there was no \
             concurrency to spread across cores. Read scaling can only be judged by sweeping C (run the default \
             ladder, e.g. SOCIAL_LADDER=1,2,4,8). The single-client figures above are a latency baseline, not a \
             scaling result."
                .into(),
        );
        return out;
    }
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
                    "clients={}: mixed throughput {:.1} ops/s COLLAPSED below {:.0}% of the \
                     control's {:.1} ops/s",
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
    // The reads are no longer pulled-and-discarded: a deterministic sample of the degree / friends /
    // mutual families is checked against ground truth recomputed from the SAME generator that built the
    // loaded graph (the friend graph is never mutated by the writers, which only SET scalars). A single
    // WRONG count FAILS the run; a verifier that verified NOTHING while armed also FAILS. The oracle is
    // present ONLY when a --gen-profile reconstruction passed its structural cross-check, so I7 is N/A
    // (never a false fail) when the ground truth could not be reconstructed.
    let verify_ok: u64 = rungs.iter().map(|r| r.verify_ok).sum();
    let verify_mismatch: u64 = rungs.iter().map(|r| r.verify_mismatch).sum();
    let verify_skipped: u64 = rungs.iter().map(|r| r.verify_skipped).sum();
    let mut vsamples: Vec<String> = Vec::new();
    for r in rungs {
        for s in &r.verify_samples {
            if vsamples.len() < MAX_VERIFY_SAMPLES {
                vsamples.push(s.clone());
            }
        }
    }
    let (i7_ok, i7_detail) = if ctx.verify_fraction <= 0.0 || ctx.oracle.is_none() {
        (
            true,
            "N/A — read-result verification is disabled (--verify-fraction 0) or the generation config \
             could not be reconstructed (pass --gen-profile + the FRIEND-degree flags the loader used \
             to arm I7). NOT a pass over correctness — verification simply did not run."
                .to_string(),
        )
    } else if verify_mismatch > 0 {
        (
            false,
            format!(
                "{verify_mismatch} sampled read(s) returned WRONG counts (of {} checked) — the server \
                 served incorrect rows, which a pull-and-discard driver would have passed green: {}",
                verify_ok + verify_mismatch,
                vsamples.join(" | ")
            ),
        )
    } else if verify_ok == 0 {
        (
            false,
            "--verify-fraction > 0 and the oracle reconstructed, but NOT ONE sampled read landed on a \
             reconstructed family (degree / friends / mutual) — the verifier is VACUOUS (measure it or \
             omit it). Expected the read battery to sample those families."
                .to_string(),
        )
    } else {
        (
            true,
            format!(
                "{verify_ok} sampled read(s) returned CORRECT results (degree / friends / mutual \
                 recomputed from the generator; {verify_skipped} sampled read(s) fell on \
                 non-reconstructed families / degenerate anchors and were skipped). The FoF / \
                 top-liked / text / fulltext families are not reconstructed here."
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
/// server-side `/metrics` delta are stitched into one report). A `GRAPHUS_SOCIAL_BENCH_STATS` headline
/// line (the PRIMARY arm's best rung) plus one `GRAPHUS_SOCIAL_BENCH_RUNG` line per rung per arm (the
/// full paired scaling curve). Printed in both modes; `run.sh` only consumes them in external mode.
///
/// The headline carries **one coherent read vector**: `best_ops`, `best_ops_per_sec`, the percentiles
/// and `abort_rate` all describe the SAME transactions (the reads), so `abort_rate` is the READ abort
/// rate — a genuinely measured `0.0`, because an auto-commit read runs at SI and cannot abort
/// (invariant I1). The WRITE layer travels in its own explicitly-named keys. Before `rmp` #714 the
/// `abort_rate` on this line was the WRITERS' failure rate sitting beside the READ counts, so a reader
/// concluded that some fraction of the READS had aborted: false, impossible, and believed.
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
        "GRAPHUS_SOCIAL_BENCH_STATS mode={} arm={} best_clients={} best_ops_per_sec={:.3} \
         best_ops={} best_secs={:.6} p50_ms={:.4} p99_ms={:.4} p999_ms={:.4} abort_rate={} \
         read_abort_rate={} total_ops={} total_secs={:.6} \
         write_attempts={} write_aborts={} engine_abort_rate={} write_units={} write_committed={} \
         write_commit_rate={} write_retries_per_commit={} write_max_retries={} write_exhausted={} \
         write_other_errors={} \
         write_p50_ms={} write_p99_ms={} write_p999_ms={} write_ops_per_sec={} \
         control_best_ops_per_sec={} mix_cost_read_ops_pct={} invariants_ok={}",
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
            "GRAPHUS_SOCIAL_BENCH_RUNG clients={} arm={} ops_per_sec={:.3} p50_ms={:.4} \
             p99_ms={:.4} p999_ms={:.4} ok={} err={} secs={:.6} read_abort_rate={} \
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
// Evidence (LOCAL only — attach mode's evidence is emitted by measure_target)
// ============================================================================================

/// Emits the standardized `EvidenceReport`, populated MANUALLY from the SERVER-process `/proc` samples
/// (the subject under measurement is the *server*, not this driver). LOCAL mode only — attach mode's
/// evidence is emitted by `measure_target` from the `/metrics` before/after delta.
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
    let nodes = args.users.saturating_add(args.articles);
    let relationships = args.friends.saturating_add(args.likes);

    let metadata = RunMetadata::new(
        args.scenario.clone(),
        "large social network: concurrent read scaling under a production-shaped read/write MIX \
         (paired control vs mixed arms, server-PID sampled)",
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
        w.insert("proc_sampling".into(), proc_available.to_string());
        w.insert("active_families".into(), active_names.join(","));
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
        w.insert("article_count".into(), args.articles.to_string());
        w.insert("friend_count".into(), args.friends.to_string());
        w.insert("like_count".into(), args.likes.to_string());
        w.insert("node_count".into(), nodes.to_string());
        w.insert("relationship_count".into(), relationships.to_string());
        // Local server on-disk footprint (informational; N/A remotely).
        if args.store_path.is_some() {
            w.insert("store_bytes".into(), store_bytes.to_string());
            w.insert("wal_bytes".into(), wal_bytes.to_string());
            // The cumulative redo written vs. the WAL retained on disk — proves the redo log is
            // recycled, not accumulated (`rmp` #702). `wal_cumulative_bytes` is derived from the
            // highest `seg.<lsn>` frontier and so survives the reclaimed prefix's deletion.
            w.insert(
                "wal_cumulative_bytes".into(),
                fp.wal_cumulative_bytes.max(wal_bytes).to_string(),
            );
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
    // total_millis = the WORKLOAD's wall-time (`rmp` #699). The whole ladder ran BEFORE this report was
    // built, so an unbracketed start()/finish() would time only the report's own emission. The rungs
    // (both arms) and the probe run back to back, so their summed wall-time IS the run.
    let workload_secs: f64 =
        rungs.iter().map(|r| r.wall_secs).sum::<f64>() + probe.map_or(0.0, |p| p.wall_secs);
    collector.record_total_duration(Duration::from_secs_f64(workload_secs));
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
    // The STORAGE vector: in local mode the server is co-located, so its real on-disk footprint is
    // readable. (Remotely there is no filesystem to walk, and the section is ABSENT by contract —
    // never zero-filled, which would claim a measured empty store: `rmp #711`.)
    if args.store_path.is_some() {
        *collector.storage_mut() = StorageSection::from_footprints(
            Some(DiskFootprint::from_bytes(store_bytes)),
            Some(DiskFootprint::from_bytes(wal_bytes)),
            // fsync proxy: every committed WAL byte is fsynced before the commit is acknowledged.
            Some(wal_bytes),
        );
        // Space amplification of the durable image over the logical graph. `0` logical bytes omits the
        // ratio rather than inventing one.
        collector.record_amplification(0, args.logical_bytes);
        // Per-element durable cost (`rmp #711`, `#714`): the measured store image amortised over the
        // graph it holds. It stays UNCONDITIONAL here — unlike `product-recommendations`, whose mix
        // CREATEs new edges and therefore invalidates the dataset counts once the writers commit —
        // because BOTH of this scenario's write shapes are property `SET`s (`u.registered`, `a.hot`)
        // on nodes that already exist. They mutate values, never the element population, so the node
        // and relationship counts in `metadata.dataset` still describe exactly the graph this store
        // holds and the division remains honest arithmetic over the right graph.
        collector.record_per_element_costs();
    }

    // throughput.* = the READ vector of the PRIMARY (mixed) arm's BEST rung — ONE coherent set of
    // transactions. `operations`, `ops_per_sec`, the percentiles and `abort_rate` all describe the SAME
    // reads. `abort_rate` is therefore the READ abort rate: a genuinely MEASURED 0.0, because an
    // auto-commit read runs at Snapshot Isolation and cannot abort (invariant I1). The WRITE layer's
    // abort rate is `engine_abort_rate` in the workload map, and the two are never merged (`rmp` #714,
    // #715). This section used to carry the whole ladder's op COUNT beside the best rung's RATE beside
    // the WRITERS' failure rate: three different populations spliced into one row.
    {
        let t = collector.throughput_mut();
        t.operations = Some(best.ok_ops);
        t.ops_per_sec = Some(best.ops_per_sec);
        t.p50_latency_ms = Some(bench::ns_to_ms(best.overall.p50));
        t.p99_latency_ms = Some(bench::ns_to_ms(best.overall.p99));
        t.p999_latency_ms = Some(bench::ns_to_ms(best.overall.p999));
        t.abort_rate = read_abort_rate(best);
    }

    collector.note(format!(
        "OVER-THE-WIRE CONCURRENCY LADDER ({} rungs × {} arm(s) over {} against '{}'): the headline is \
         whether SERVER-PID CPU scales with C — reads spreading across cores (reader pool #336/#543) vs \
         a single-thread ceiling — measured under a PRODUCTION-SHAPED MIX (reads served while writes \
         commit underneath), not against a frozen graph. The in-process battery this replaces measured \
         the DRIVER, not the server (a ~1-core artifact).",
        rungs.len(),
        if primary == Arm::Mixed { 2 } else { 1 },
        args.ladder,
        args.db,
    ));
    collector.note(format!(
        "TWO LAYERS OF TRUTH, never conflated (rmp #714, #715). READ: throughput.* is ONE coherent set \
         — the {} reads of the best '{}' rung (C={}), at {:.1} ops/s, and throughput.abort_rate = {} is \
         the READ abort rate. It is a MEASURED zero, not a placeholder: a standalone auto-commit read \
         runs at SNAPSHOT ISOLATION (rmp #543/#545), so it can neither abort a writer nor be aborted by \
         one — that is invariant I1, and the run FAILS if a read ever aborts. WRITE: the writers' \
         evidence lives in the workload map and is split in two. ENGINE: {} of {} transaction attempts \
         were aborted by SSI (engine_abort_rate {}). APPLICATION: {} of {} business units COMMITTED \
         (write_commit_rate {}), at {} retries per commit, {} exhausting their retry budget. A high \
         engine abort rate WITH a full application commit rate is a HEALTHY system under contention: \
         the application-visible cost of contention is LATENCY (see write_p99_ms, which is \
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
         read-modify-write of one of {} TRENDING articles (`SET a.hot = coalesce(a.hot,0)+1`); the rest \
         touch a random user's `registered` timestamp. The hot component is what makes SSI — and \
         therefore the retry path — LOAD-BEARING: a purely random write stream conflicts with nobody, \
         aborts nothing, and leaves the retry path as dead code and the bounded-retries invariant \
         vacuous.",
        ctx.effective_writers(),
        args.write_every_ms,
        args.hot_write_fraction * 100.0,
        ctx.hot_keys,
    ));
    if let Some(p) = probe {
        collector.note(format!(
            "SLOW-READER PROBE (invariant I5, the GC pin — rmp #551): while {} heavy '{}' reads (p50 \
             {:.1}ms, max {:.1}ms) held their MVCC snapshots open for {:.1}s, the writers committed {} \
             of {} business units underneath them ({} engine aborts). A long reader pins the GC \
             watermark; if that pin could stall the write path, this window would show ZERO commits — \
             and the ladder, whose reads are mostly short, would never have noticed.",
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
        // Why the per-element cost SURVIVES the mix here (and not in `product-recommendations`, whose
        // mix CREATEs new PURCHASED edges and therefore has to OMIT this figure): a per-element cost is
        // only honest when its two inputs describe the SAME graph, and BOTH of this scenario's write
        // shapes are property SETs on nodes that already exist. They change VALUES, never the element
        // population — so `metadata.dataset` still describes exactly the graph the measured image holds.
        collector.note(if write.committed > 0 {
            format!(
                "storage.bytes_per_node / bytes_per_relationship are PRESENT and honest even though \
                 the mix COMMITTED {} business unit(s) into this same store (rmp #711/#714). Both \
                 write shapes are property SETs on EXISTING nodes (`u.registered` on a random user, \
                 `a.hot` on a trending article): they mutate values, they never create or delete an \
                 element. The node/relationship counts therefore still describe exactly the graph this \
                 store holds, and the division stays real arithmetic over the right graph. The figure \
                 does now include the durable cost of the `hot` property the mix added to the {} \
                 trending article(s) — a genuine, measured part of this store's footprint.",
                write.committed, ctx.hot_keys,
            )
        } else {
            "storage.bytes_per_node / bytes_per_relationship amortise the measured store image over \
             the loaded graph: no write workload committed, so the store holds exactly the graph the \
             generator's node/relationship counts describe."
                .to_string()
        });
        collector.note(format!(
            "SERVER ON-DISK FOOTPRINT (local, co-located), measured directly from the server's store directory and \
             DECOMPOSED — a lumped total would blend bytes that scale with the graph with bytes that do not: \
             data image (graphus.store) {:.1}MiB | doublewrite buffers (graphus.dwb) {:.1}MiB | redo log \
             (graphus.wal/seg.<lsn>) {:.1}MiB | catalog/locks {:.1}MiB.",
            mib(fp.data_bytes), mib(fp.dwb_bytes), mib(fp.wal_bytes), mib(fp.other_bytes),
        ));
        if fp.data_bytes > 0 {
            // `wal_cumulative_bytes` is the highest `seg.<lsn>` frontier — every redo byte the log has
            // appended over the run, still recoverable after the reclaimed prefix segments were deleted.
            // `wal_bytes` is what is RETAINED on disk now. Their gap is exactly the WAL that was recycled.
            let cumulative = fp.wal_cumulative_bytes.max(fp.wal_bytes);
            let reclaimed = cumulative.saturating_sub(fp.wal_bytes);
            let reclaimed_pct = if cumulative > 0 {
                100.0 * reclaimed as f64 / cumulative as f64
            } else {
                0.0
            };
            collector.note(format!(
                "STORAGE EFFICIENCY: the redo log RETAINS {:.1}MiB on disk = {:.1}x the {:.1}MiB data image it \
                 protects, having WRITTEN {:.1}MiB of cumulative redo over the run — so {:.1}MiB ({:.0}%) was \
                 RECYCLED, not accumulated. The Mode A bulk-load's redo is reclaimed at load end (`rmp` #579) and \
                 the WAL segment target is sized to the store (`rmp` #706), so sealed segments below the checkpoint \
                 floor are freed instead of retained; what remains is the recent redo tail, not the whole log \
                 (before those fixes the same workload held ~9.3x and grew monotonically, `rmp` #702). The \
                 doublewrite buffers are a FIXED preallocation ({:.1}MiB total, one per database, independent of \
                 graph size), so on a small graph they dominate the footprint while on a large one they amortise to \
                 nothing.",
                mib(fp.wal_bytes),
                fp.wal_bytes as f64 / fp.data_bytes as f64,
                mib(fp.data_bytes),
                mib(cumulative),
                mib(reclaimed),
                reclaimed_pct,
                mib(fp.dwb_bytes),
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
    /// The redo log (`graphus.wal/seg.<lsn>`) currently ON DISK — i.e. after reclamation.
    wal_bytes: u64,
    /// The CUMULATIVE redo the WAL has written over the run — the highest durable LSN, recovered
    /// from the highest `seg.<lsn>` base offset plus that segment's size (`rmp` #702). A segment name
    /// IS its base byte-offset in the logical log, and reclamation only ever *deletes* whole sealed
    /// segments below the checkpoint floor — it never rewrites the frontier — so the last segment's
    /// `(base_lsn + size)` still equals every byte the log has ever appended, even after the prefix
    /// was freed. This lets the report *prove* WAL recycling from its own on-disk state: `wal_bytes`
    /// (retained) far below `wal_cumulative_bytes` (written) means the redo log is recycled, not
    /// accumulated. Equal values mean nothing was reclaimed (a workload below the seal threshold).
    wal_cumulative_bytes: u64,
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
    // The cumulative-redo frontier: `seg.<lsn>` names the segment's base byte-offset in the logical
    // log, so `base_lsn + size` of the *highest* segment is the total redo the WAL has ever appended,
    // recoverable even after the reclaimed prefix segments were deleted (`rmp` #702).
    fn segment_frontier(p: &std::path::Path) -> Option<u64> {
        let name = p.file_name()?.to_str()?;
        let lsn = name.strip_prefix("seg.")?;
        lsn.parse::<u64>().ok()
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
                    if let Some(base_lsn) = segment_frontier(&p) {
                        fp.wal_cumulative_bytes = fp.wal_cumulative_bytes.max(base_lsn + len);
                    }
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
/// CORRECT rows for a **sampled** read — so a server that serves WRONG, MISSING, or MIS-ORDERED counts
/// can no longer pass a green run whose reads were pulled and discarded (`rmp` #744). Built **once** at
/// startup, only when a `--gen-profile` reconstructs the exact generation config.
///
/// Three families are checked, all recomputed from the `FRIEND` graph, which the example's write
/// workload never mutates (the writers only `SET` scalar properties), so the oracle stays valid for the
/// whole run:
/// * `degree` (`RETURN count(f)`) — the user's multi-edge `FRIEND` incidence count.
/// * `friends` (`RETURN count(DISTINCT f)`) — the user's distinct-neighbour count.
/// * `mutual` (`RETURN count(DISTINCT m)`) — `|neighbours(u0) ∩ neighbours(u1)|`, skipped when
///   `u0 == u1` (Cypher relationship-uniqueness makes that degenerate case depend on multi-edges).
///
/// `fof` / `top_liked` / `text_contains` / `like_recent` / `fulltext` are deliberately not
/// reconstructed (2-hop closures, global aggregations, and substring/full-text scans).
struct SocialReadOracle {
    /// Number of users in the loaded graph (bounds the anchor index).
    users: u64,
    /// Per-user multi-edge `FRIEND` incidence count (the `degree` answer).
    degree: Vec<u64>,
    /// Per-user SORTED distinct neighbour set (its length is `friends`; pairwise intersection is
    /// `mutual`).
    neighbours: Vec<Vec<u64>>,
}

impl SocialReadOracle {
    /// Builds the oracle from a reconstructed generation config (`--gen-profile` + overrides + the
    /// generation `--seed`).
    fn build(cfg: &GenConfig) -> Self {
        let (degree, neighbours) = Generator::new(cfg.clone()).friend_adjacency();
        Self {
            users: cfg.users,
            degree,
            neighbours,
        }
    }

    /// `|neighbours(a) ∩ neighbours(b)|` — the mutual-friends ground truth (both neighbour sets are
    /// sorted, so this is a linear merge). `None` when either anchor is out of range.
    fn mutual(&self, a: u64, b: u64) -> Option<u64> {
        let na = self.neighbours.get(a as usize)?;
        let nb = self.neighbours.get(b as usize)?;
        Some(sorted_intersection_len(na, nb))
    }
}

/// Reconstruct the FRIEND ground-truth oracle for I7 (`rmp` #744) — or decline to `None` (I7 N/A).
///
/// Requires a `--gen-profile`; without it the FRIEND-degree config cannot be reconstructed (unlike
/// reco's `s_user`, EVERY social family the oracle checks needs the friend graph), so I7 is N/A. When a
/// profile is given, the SAME `GenConfig` the loader resolved is rebuilt from the profile + the
/// FRIEND-degree overrides the loader was passed, then **structurally cross-checked**: the reconstructed
/// undirected incidence total (`Σ degree = 2 × edges`) must equal `2 × --friends` (the loaded edge
/// count). A mismatch means the profile/band we resolved is NOT the graph on the server — so the oracle
/// is DECLINED rather than risk false-failing a correct server with a wrong ground truth.
fn build_read_oracle(args: &Args) -> Option<SocialReadOracle> {
    let profile = args.gen_profile.as_ref()?;
    let cfg = GenConfig::resolve(
        profile,
        Some(args.users.max(1)),
        Some(args.articles.max(1)),
        args.friend_min,
        args.friend_max,
        args.avg_likes,
        Some(args.seed),
        args.degree_dist,
    )
    .ok()?;
    let oracle = SocialReadOracle::build(&cfg);
    let incidences: u64 = oracle.degree.iter().sum();
    if args.friends > 0 && incidences == 2 * args.friends {
        Some(oracle)
    } else {
        eprintln!(
            "social_bench: I7 oracle DECLINED — reconstructed FRIEND incidences {incidences} != \
             2×{} loaded edges; the --gen-profile/band did not reproduce the loaded graph, so \
             read-result verification is N/A (not a failure).",
            args.friends
        );
        None
    }
}

/// The number of elements common to two ascending-sorted, de-duplicated slices (a linear merge).
fn sorted_intersection_len(a: &[u64], b: &[u64]) -> u64 {
    let (mut i, mut j, mut count) = (0usize, 0usize, 0u64);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                count += 1;
                i += 1;
                j += 1;
            }
        }
    }
    count
}

/// The verdict of checking one sampled read reply against the [`SocialReadOracle`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReadCheck {
    /// Checked against ground truth and CORRECT.
    Verified,
    /// This family is not deterministically reconstructed (or the anchors are out of range / degenerate).
    Skipped,
    /// Checked and WRONG — the string describes the divergence for the report.
    Mismatch(String),
}

/// Checks one sampled read reply against ground truth. **Pure** — no I/O, no clock — so it is
/// unit-testable (see the `tests` module) and adds nothing to the latency measured around it. `u0`/`u1`
/// are the anchor user indices the worker drew (`u1` matters only for `mutual`).
fn verify_social_read(
    family: &str,
    result: &QueryResult,
    oracle: &SocialReadOracle,
    u0: u64,
    u1: u64,
) -> ReadCheck {
    match family {
        "degree" => scalar_check(
            result,
            &format!("degree(u{u0})"),
            oracle.degree.get(u0 as usize).copied(),
        ),
        "friends" => scalar_check(
            result,
            &format!("friends(u{u0})"),
            oracle
                .neighbours
                .get(u0 as usize)
                .map(|n| n.len() as u64)
                .filter(|_| u0 < oracle.users),
        ),
        "mutual" => {
            // The degenerate u0 == u1 case is not soundly reconstructible (Cypher relationship
            // uniqueness makes it depend on multi-edges), so skip it rather than risk a false mismatch.
            if u0 == u1 {
                return ReadCheck::Skipped;
            }
            scalar_check(
                result,
                &format!("mutual(u{u0},u{u1})"),
                oracle.mutual(u0, u1),
            )
        }
        _ => ReadCheck::Skipped,
    }
}

/// Checks a single-scalar-row `RETURN count(...) AS x` reply against `expected` (a count). `None`
/// expected ⇒ [`ReadCheck::Skipped`] (anchor out of range).
fn scalar_check(result: &QueryResult, label: &str, expected: Option<u64>) -> ReadCheck {
    let Some(expected) = expected else {
        return ReadCheck::Skipped;
    };
    let got = match (
        result.records.len(),
        result.records.first().and_then(|r| r.first()),
    ) {
        (1, Some(Value::Integer(n))) => *n,
        _ => {
            return ReadCheck::Mismatch(format!(
                "{label}: expected a single integer row, got fields={:?} rows={}",
                result.fields,
                result.records.len()
            ));
        }
    };
    if i128::from(got) == i128::from(expected) {
        ReadCheck::Verified
    } else {
        ReadCheck::Mismatch(format!("{label}: expected {expected}, got {got}"))
    }
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
    /// Concurrent writer count (`--writers`); `0` = a pure read ladder (writers OFF).
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
    /// I7 (`rmp` #744): read-result verification sampling fraction (`--verify-fraction`); `0.0`
    /// disables it. Non-zero AND a reconstructable generation config are BOTH required to arm I7.
    verify_fraction: f64,
    /// I7: the generation profile (`--gen-profile fast|large|huge`) the loaded graph was built from —
    /// needed to reconstruct the exact `FRIEND` ground truth. Absent ⇒ I7 is N/A (never a false fail).
    gen_profile: Option<String>,
    /// I7: `FRIEND`-degree band + distribution overrides the loader applied (`--friend-min`,
    /// `--friend-max`, `--avg-likes`, `--degree-dist`), so the oracle resolves the SAME `GenConfig`.
    friend_min: Option<u64>,
    friend_max: Option<u64>,
    avg_likes: Option<u64>,
    degree_dist: Option<DegreeDist>,
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
        // The production-shaped MIX is the DEFAULT (`rmp` #714): the run everyone executes must be the
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
        // I7 (`rmp` #744): verification is armed by default, but only actually runs when a --gen-profile
        // (plus any FRIEND-degree overrides the loader used) lets the oracle reconstruct the graph.
        let mut verify_fraction = DEFAULT_VERIFY_FRACTION;
        let mut gen_profile: Option<String> = None;
        let mut friend_min: Option<u64> = None;
        let mut friend_max: Option<u64> = None;
        let mut avg_likes: Option<u64> = None;
        let mut degree_dist: Option<DegreeDist> = None;
        let mut zipf_exponent: u32 = 2;

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
                "--hot-write-fraction" => {
                    let v = value()?;
                    hot_write_fraction = v
                        .parse()
                        .map_err(|_| format!("--hot-write-fraction must be a number, got {v:?}"))?;
                    if !(0.0..=1.0).contains(&hot_write_fraction) {
                        return Err("--hot-write-fraction must be in [0, 1]".into());
                    }
                }
                "--hot-keys" => hot_keys = parse_u64(&value()?, "--hot-keys")?.max(1),
                "--retry-budget-ms" => {
                    retry_budget_ms = parse_u64(&value()?, "--retry-budget-ms")?.max(1)
                }
                "--mix-baseline" => mix_baseline = parse_u64(&value()?, "--mix-baseline")? != 0,
                "--probe-secs" => {
                    let v = value()?;
                    probe_secs = v
                        .parse()
                        .map_err(|_| format!("--probe-secs must be a number, got {v:?}"))?;
                    if probe_secs < 0.0 {
                        return Err("--probe-secs must be >= 0".into());
                    }
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
                // I7 (`rmp` #744) — read-result verification + the generation config to reconstruct the
                // ground truth from. The band/dist flags mirror the loader's (social_wire_load) so the
                // oracle resolves the SAME GenConfig the graph was built with.
                "--verify-fraction" => {
                    let v = value()?;
                    verify_fraction = v.parse().map_err(|_| {
                        format!("--verify-fraction must be a number in [0,1], got {v:?}")
                    })?;
                    if !(0.0..=1.0).contains(&verify_fraction) {
                        return Err("--verify-fraction must be in [0, 1]".into());
                    }
                }
                "--gen-profile" => gen_profile = Some(value()?),
                "--friend-min" => friend_min = Some(parse_u64(&value()?, "--friend-min")?),
                "--friend-max" => friend_max = Some(parse_u64(&value()?, "--friend-max")?),
                "--avg-likes" => avg_likes = Some(parse_u64(&value()?, "--avg-likes")?),
                "--degree-dist" => {
                    degree_dist = Some(match value()?.as_str() {
                        "uniform" => DegreeDist::Uniform,
                        "zipf" | "powerlaw" | "power-law" => DegreeDist::PowerLaw {
                            exponent: zipf_exponent,
                        },
                        other => {
                            return Err(format!("unknown --degree-dist {other:?} (uniform|zipf)"));
                        }
                    });
                }
                "--zipf-exponent" => {
                    zipf_exponent = u32::try_from(parse_u64(&value()?, "--zipf-exponent")?)
                        .map_err(|_| "--zipf-exponent too large".to_string())?;
                    // If --degree-dist zipf was already parsed, refresh its exponent.
                    if let Some(DegreeDist::PowerLaw { .. }) = degree_dist {
                        degree_dist = Some(DegreeDist::PowerLaw {
                            exponent: zipf_exponent,
                        });
                    }
                }
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
            hot_write_fraction,
            hot_keys,
            retry_budget_ms,
            mix_baseline,
            probe_secs,
            target_rps,
            auto_extend,
            verify_fraction,
            gen_profile,
            friend_min,
            friend_max,
            avg_likes,
            degree_dist,
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
         \x20   [--writers <N default 2, 0 = pure read ladder>] [--write-every-ms <ms default 20>] \\\n\
         \x20   [--hot-write-fraction <f default 0.25>] [--hot-keys <N default 4>] \\\n\
         \x20   [--mix-baseline <0|1 default 1>] [--retry-budget-ms <ms default 15000>] \\\n\
         \x20   [--probe-secs <s default 3>] \\\n\
         \x20   [--target-rps <R default 0 = closed-loop>] [--auto-extend] [--read-timeout-ms <ms default 120000>]"
    );
}

#[cfg(test)]
mod tests {
    use super::{
        Arm, BenchCtx, ErrorSample, Pcts, ReadCheck, ReadInvariant, RetryPolicy, RungResult,
        SocialReadOracle, Target, WriteKind, WriteVector, diagnose_knee, du_store, primary_arm,
        top_rung, verify_social_read,
    };
    use graphus_core::Value;
    use graphus_reco_gen::client::QueryResult;
    use graphus_reco_gen::mix::UnitOutcome;
    use graphus_social_gen::{SplitMix64, battery};
    use std::path::PathBuf;
    use std::time::Duration;

    /// A rung fixture: everything not named is the neutral, "not measured" value.
    fn rung(arm: Arm, clients: usize, ops_per_sec: f64) -> RungResult {
        RungResult {
            arm,
            clients,
            budget: 1500,
            ok_ops: 1500,
            err_ops: 0,
            wall_secs: 7.0,
            ops_per_sec,
            overall: Pcts::default(),
            per_family: Vec::new(),
            cpu_user_secs: 4.5,
            cpu_system_secs: 0.1,
            // The signature that used to trip the false verdict: one thread above the busy threshold.
            server_cores: 0.66,
            busy_threads: 1,
            busiest_core_frac: 0.05,
            peak_rss: 0,
            final_rss: 0,
            vm_hwm: 0,
            io_read_bytes: 0,
            io_available: false,
            write: WriteVector::default(),
            reads: ReadInvariant::default(),
            read_errors: ErrorSample::default(),
            verify_ok: 0,
            verify_mismatch: 0,
            verify_skipped: 0,
            verify_samples: Vec::new(),
        }
    }

    /// A context fixture with the mix knobs the tests below exercise.
    fn ctx(writers: usize, write_every_ms: u64, hot_write_fraction: f64) -> BenchCtx {
        BenchCtx {
            target: Target::Uds(PathBuf::from("/nonexistent.sock")),
            user: "u".into(),
            password: "p".into(),
            db: "socialdb".into(),
            read_timeout: Duration::from_millis(1000),
            users: 1000,
            articles: 100,
            term: "term".into(),
            since: 0,
            verify_fraction: 0.0,
            oracle: None,
            ops_per_rung: 1500,
            min_ops_per_client: 150,
            write_every_ms,
            writers,
            hot_write_fraction,
            hot_keys: 4,
            retry: RetryPolicy::default(),
            target_rps: 0.0,
            seed: 7,
            active: vec![0],
            bag: vec![0],
        }
    }

    /// A single-integer-row `RETURN count(...)` reply.
    fn qr(rows: Vec<Vec<Value>>) -> QueryResult {
        QueryResult {
            fields: vec!["c".to_string()],
            records: rows,
            elapsed: Duration::from_millis(0),
        }
    }

    /// I7 (`rmp` #744) MUST FIRE on a wrong count and stay quiet on the right one — otherwise the
    /// pull-and-discard read loop it replaced could pass a server that served incorrect rows.
    #[test]
    fn i7_social_verifies_degree_friends_mutual_and_flags_wrong_counts() {
        // A hand-built oracle: user 0 ~ {1,2}, user 1 ~ {0}, user 2 ~ {0,1,2} (neighbours sorted+deduped).
        let oracle = SocialReadOracle {
            users: 3,
            degree: vec![2, 1, 3],
            neighbours: vec![vec![1, 2], vec![0], vec![0, 1, 2]],
        };
        let check = |fam: &str, n: i64, u0: u64, u1: u64| {
            verify_social_read(fam, &qr(vec![vec![Value::Integer(n)]]), &oracle, u0, u1)
        };

        // degree(u0) — the multi-edge incidence count.
        assert_eq!(check("degree", 2, 0, 0), ReadCheck::Verified);
        assert!(matches!(check("degree", 9, 0, 0), ReadCheck::Mismatch(_)));
        // friends(u0) — the DISTINCT-neighbour count.
        assert_eq!(check("friends", 3, 2, 0), ReadCheck::Verified);
        assert!(matches!(check("friends", 2, 2, 0), ReadCheck::Mismatch(_)));
        // mutual(u0,u1) — |neighbours(u0) ∩ neighbours(u1)| = |{1,2} ∩ {0,1,2}| = 2.
        assert_eq!(check("mutual", 2, 0, 2), ReadCheck::Verified);
        assert!(matches!(check("mutual", 0, 0, 2), ReadCheck::Mismatch(_)));
        // The degenerate u0 == u1 mutual is SKIPPED (not a false mismatch).
        assert_eq!(check("mutual", 0, 1, 1), ReadCheck::Skipped);
        // A family the oracle does not reconstruct is SKIPPED, never failed.
        assert_eq!(check("fof", 5, 0, 1), ReadCheck::Skipped);
        // A malformed reply (a dropped row) is a mismatch, not a silent pass.
        assert!(matches!(
            verify_social_read("degree", &qr(vec![]), &oracle, 0, 0),
            ReadCheck::Mismatch(_)
        ));
    }

    /// `--writers 0` is the DOCUMENTED off switch for the read-only baseline. Flooring it back to one
    /// (`self.writers.max(1)`) made that baseline unreachable: the "writers off" run still had a
    /// writer committing underneath it, so the control arm was not a control at all.
    #[test]
    fn writers_zero_really_means_zero_writers() {
        assert_eq!(ctx(0, 20, 0.25).effective_writers(), 0, "--writers 0 = OFF");
        assert_eq!(
            ctx(2, 0, 0.25).effective_writers(),
            0,
            "--write-every-ms 0 also disables the write workload"
        );
        assert_eq!(ctx(2, 20, 0.25).effective_writers(), 2, "the mix default");
    }

    /// With no write workload the ladder is the single `readonly` arm; with one it is the PAIR
    /// (control first, then treatment) unless the baseline is explicitly skipped.
    #[test]
    fn arms_pair_the_control_with_the_treatment() {
        assert_eq!(ctx(0, 20, 0.25).arms(true), vec![Arm::Readonly]);
        assert_eq!(
            ctx(2, 20, 0.25).arms(true),
            vec![Arm::Readonly, Arm::Mixed],
            "the control must run FIRST (it warms the pool ⇒ a conservative cost of the mix)"
        );
        assert_eq!(ctx(2, 20, 0.25).arms(false), vec![Arm::Mixed]);
    }

    /// Both write shapes are property SETs on an EXISTING node: the common one touches a random user,
    /// the hot one read-modify-writes a trending article. The hot shape is the only one that makes SSI
    /// (and therefore the retry path) load-bearing — a purely random stream conflicts with nobody.
    #[test]
    fn the_write_unit_draws_both_shapes_and_confines_the_hot_one_to_the_trending_set() {
        let c = ctx(2, 20, 0.5);
        let mut rng = SplitMix64::new(1);
        let (mut hot, mut common) = (0u32, 0u32);
        for i in 0..500 {
            let (kind, cypher, params) = c.write_unit(&mut rng, i);
            match kind {
                WriteKind::Hot => {
                    hot += 1;
                    assert_eq!(cypher, battery::WRITE_ARTICLE_HOT);
                    assert_eq!(params.len(), 1, "the hot write is anchored by $id alone");
                    assert_eq!(params[0].0, "id");
                }
                WriteKind::Common => {
                    common += 1;
                    assert_eq!(cypher, battery::WRITE_USER_TOUCH);
                    assert_eq!(params.len(), 2, "the common write carries $id and $ts");
                    assert_eq!(params[0].0, "id");
                    assert_eq!(params[1].0, "ts");
                }
            }
        }
        assert!(
            hot > 0 && common > 0,
            "both shapes must occur ({hot} hot, {common} common)"
        );
    }

    /// Every headline is drawn from the PRIMARY arm. A max over BOTH arms would silently report the
    /// control (writers off) whenever the mix cost enough throughput — republishing the frozen-graph
    /// fiction this task exists to kill.
    #[test]
    fn the_headline_is_drawn_from_the_mixed_arm_even_when_the_control_is_faster() {
        let rungs = vec![
            rung(Arm::Readonly, 8, 409.4),
            rung(Arm::Mixed, 8, 313.1), // the mix costs throughput — but it is still the headline
        ];
        assert_eq!(primary_arm(&rungs), Arm::Mixed);
        assert_eq!(
            top_rung(&rungs).ops_per_sec,
            313.1,
            "the top rung must be the MIXED one, not the faster control"
        );
    }

    /// A `readonly` rung has NO write vector, so every derived write rate must be ABSENT — a `0.0`
    /// there would publish a conflict-free write workload that never ran (`rmp` #711).
    #[test]
    fn an_unattempted_write_vector_reports_no_rate_at_all() {
        let r = rung(Arm::Readonly, 4, 200.0);
        assert!(!r.write.attempted());
        assert_eq!(r.write.engine_abort_rate(), None, "absent != zero");
        assert_eq!(r.write.commit_rate(), None);
        assert_eq!(super::read_abort_rate(&r), Some(0.0), "a MEASURED zero: I1");

        let mut mixed = rung(Arm::Mixed, 4, 180.0);
        mixed.write.record(&UnitOutcome {
            committed: true,
            attempts: 2,
            aborts: 1,
            latency_ns: 1_000_000,
            ..UnitOutcome::default()
        });
        assert_eq!(mixed.write.engine_abort_rate(), Some(0.5));
        assert_eq!(mixed.write.commit_rate(), Some(1.0));
    }

    /// The server's WAL is a DIRECTORY of `seg.<lsn>` files, so a classifier that only looks at the
    /// leaf file name counts every WAL byte as store — reporting `wal_bytes = 0` and hiding the redo
    /// log entirely. This pins the real on-disk layout, and the decomposition that keeps the
    /// fixed-cost doublewrite buffer from being mistaken for graph data (regression for both bugs).
    /// A scaling verdict needs a concurrency sweep. With a single-client ladder there is nothing to
    /// spread across cores, so the low busy-thread count must NOT be reported as a single-thread
    /// ceiling — that would be an artifact of the ladder masquerading as a property of the server.
    #[test]
    fn single_client_ladder_refuses_to_draw_a_scaling_verdict() {
        let lines = diagnose_knee(&[rung(Arm::Readonly, 1, 212.6)], true, false).join(" ");
        assert!(
            lines.contains("NOT ASSESSABLE"),
            "a one-rung ladder must decline to judge scaling, got: {lines}"
        );
        assert!(
            !lines.contains("SINGLE-THREAD CEILING"),
            "must not assert a ceiling it cannot measure, got: {lines}"
        );
    }

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
        // The cumulative-redo frontier is `max(base_lsn + size)` over the segments (`rmp` #702):
        // max(8 + 8192, 9 + 256) = 8200 — the higher of the two segment end-offsets.
        assert_eq!(
            fp.wal_cumulative_bytes,
            8 + 8192,
            "wal_cumulative_bytes = the highest seg.<lsn> frontier (base_lsn + size)"
        );
    }

    /// `rmp` #702: the redo-log RECYCLING that `rmp` #706/#579 deliver must be *provable from the
    /// evidence itself*. After the reclaimed prefix segments are deleted, only a tail segment remains
    /// on disk, but its `seg.<lsn>` name still encodes its base byte-offset — so `du_store` recovers the
    /// full cumulative redo the log ever wrote and the report can show `retained ≪ written`. This test
    /// pins that: a store whose WAL wrote 12 MiB of redo but had its 10 MiB prefix reclaimed must report
    /// 2 MiB retained and 12 MiB cumulative (a 10 MiB, 83% reclaim), never a lie in either direction.
    #[test]
    fn du_store_cumulative_redo_proves_wal_reclamation() {
        let root = std::env::temp_dir().join(format!("gsocial-du-reclaim-{}", std::process::id()));
        let wal = root.join("databases").join("socialdb").join("graphus.wal");
        std::fs::create_dir_all(&wal).expect("layout");

        // A reclaimed WAL: the 10 MiB prefix (seg.0 .. seg.10485760) was freed on a checkpoint; only
        // the tail segment — based at LSN 10 MiB, 2 MiB long — remains. Contiguous, non-overlapping.
        const TEN_MIB: u64 = 10 * 1024 * 1024;
        const TWO_MIB: usize = 2 * 1024 * 1024;
        std::fs::write(wal.join(format!("seg.{TEN_MIB:020}")), vec![0u8; TWO_MIB])
            .expect("tail seg");

        let fp = du_store(root.to_str().expect("utf8"));
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(
            fp.wal_bytes, TWO_MIB as u64,
            "only the un-reclaimed tail segment is retained on disk"
        );
        assert_eq!(
            fp.wal_cumulative_bytes,
            TEN_MIB + TWO_MIB as u64,
            "the tail segment's base LSN recovers the full 12 MiB of redo ever written"
        );
        let reclaimed = fp.wal_cumulative_bytes - fp.wal_bytes;
        assert_eq!(
            reclaimed, TEN_MIB,
            "10 MiB of superseded redo was recycled, not accumulated (rmp #706/#579)"
        );
        assert!(
            fp.wal_cumulative_bytes > fp.wal_bytes,
            "a reclaimed WAL must report written > retained, or the report cannot prove recycling"
        );
    }
}
