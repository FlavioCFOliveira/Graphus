//! `vopr_fuzz` — the **continuous, time-budgeted, multi-core VOPR soak fuzzer** (rmp #243).
//!
//! The VOPR core ([`crate::vopr`]) makes one run a **pure function of its [`VoprConfig`]** (which
//! carries the master seed): same mode + same config ⇒ identical `trace_hash` + `state_hash` and an
//! identical pass/fail verdict, single-threaded, with no wall-clock or shared mutable state leaking into
//! the run. This module turns that property into a *hyper-speed soak*: it sweeps a contiguous range of
//! seeds — optionally for a wall-clock budget, optionally across every CPU core — maximising seeds
//! explored per second, and surfaces the first (or every) failing seed with its #242 replay artifact.
//!
//! # Why the parallel sweep stays deterministic
//!
//! A seed's **verdict** (`failed` + `trace_hash` + `state_hash`) is decided *only* by `(mode, config,
//! predicate)`; nothing in a run observes the wall clock, the thread id, or any other run's state (each
//! worker builds its **own** engine). So which worker happens to run a given seed cannot change that
//! seed's verdict. Workers pull disjoint seeds from a single shared atomic counter (so each seed runs
//! **exactly once**), accumulate their verdicts locally, and the orchestrator merges and **sorts by
//! seed** before reporting. The result is provably identical to a serial sweep over the same range:
//! same seed set, same per-seed verdict, same sorted order — independent of thread timing. The
//! [`parallel_sweep_equals_serial`](#tests) acceptance test pins exactly this.
//!
//! # Where wall-clock is allowed
//!
//! Wall-clock ([`std::time::Instant`]) appears **only** in the orchestrator: to decide when the time
//! budget `T` has expired and to measure throughput (seeds/sec, ops/sec). It never enters a per-seed
//! run — the seed→verdict function is still pure. A run already in flight when the deadline passes is
//! always allowed to finish (a seed is the atomic unit of work), so a verdict is never half-computed.
//!
//! # The fuzz loop
//!
//! [`fuzz`] enumerates seeds from `start_seed` upward and runs each under the chosen [`ReplayMode`]
//! (optionally swarmed — rmp #241) until either (a) the wall-clock budget expires, (b) the optional
//! `max_seeds` cap is reached, or (c) `stop_on_failure` and a failure was found. Failing seeds are
//! collected (each with a #242 [`ReplayArtifact`] for one-command reproduction). The [`FuzzReport`]
//! carries the throughput metrics — **seeds/sec** (the hyper-speed metric), **ops/sec**, and the total
//! **simulated time advanced** — plus the sorted failing-seed set.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::vopr::{VoprConfig, VoprReport, run, run_liveness, run_safety};
use crate::vopr_repro::{ARTIFACT_VERSION, ReplayArtifact, ReplayMode};

/// An overridable failure predicate for the fuzzer (rmp #243): given the candidate **config** and the
/// [`VoprReport`] of a run of that config, decide whether the seed is a failure. The default
/// ([`fuzz`]/[`sweep_range`] passed `None`) is the mode's **real** verdict; tests inject a closure to
/// *plant* a synthetic failure (e.g. "seed == K fails") without needing a real engine bug.
///
/// It must be `Send + Sync` so the same predicate can be shared, by reference, across every worker
/// thread of a parallel sweep. The closure is pure (a function of its arguments), so sharing it across
/// threads keeps each seed's verdict independent of which worker ran it.
pub type FuzzPredicate<'a> = dyn Fn(&VoprConfig, &VoprReport) -> bool + Send + Sync + 'a;

/// The deterministic verdict of running **one** seed under one mode (rmp #243): the pure, thread- and
/// order-independent unit a sweep aggregates.
///
/// Every field is a pure function of `(mode, config, predicate)` — no wall-clock, no thread id, no
/// other run's state — so the verdict for a seed is identical no matter which worker computed it. This
/// is what makes the parallel sweep's verdict set provably equal to the serial sweep's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedVerdict {
    /// The seed this verdict is for.
    pub seed: u64,
    /// Whether the run was a failure under the active predicate (the mode's real verdict by default).
    pub failed: bool,
    /// The canonical event-trace hash — the byte-identity digest the parallel/serial equality test pins.
    pub trace_hash: u64,
    /// The final graph-state hash.
    pub state_hash: u64,
    /// Operations the run dispatched (`ok + err`), summed into the sweep's ops/sec.
    pub ops: u64,
    /// Logical (simulated) time advanced by the run, summed into the sweep's total simulated time.
    pub sim_time: u64,
    /// A one-line, human-readable failure summary (empty when the seed did not fail).
    pub summary: String,
}

impl SeedVerdict {
    /// Builds an [`Ord`]-stable sort key so a merged set of verdicts is ordered purely by seed — making
    /// the aggregation independent of the order workers produced verdicts in.
    fn sort_key(&self) -> u64 {
        self.seed
    }
}

/// Runs a single seed under `mode` (optionally swarmed) and classifies it into a [`SeedVerdict`] using
/// `predicate` (the mode's real verdict when `None`). Pure: a function of its inputs only.
///
/// The config for the seed is the mode's natural preset ([`VoprConfig::for_seed`] /
/// [`VoprConfig::safety`] / [`VoprConfig::liveness`]), or the fully seed-derived swarm config
/// ([`VoprConfig::swarm`], rmp #241) when `swarm` is set.
#[must_use]
pub fn verdict_for_seed(
    mode: ReplayMode,
    seed: u64,
    swarm: bool,
    predicate: Option<&FuzzPredicate<'_>>,
) -> SeedVerdict {
    let config = config_for(mode, seed, swarm);
    let (report, real_failed, real_summary) = run_mode(mode, config);

    // The predicate decides the verdict; without one we use the mode's real verdict. A planted
    // predicate that flips a clean run to "failed" carries a synthetic summary so the artifact still has
    // a human triage line.
    let failed = match predicate {
        Some(pred) => pred(&config, &report),
        None => real_failed,
    };
    let summary = if failed {
        if real_failed {
            real_summary
        } else {
            format!("{}: planted failure (predicate)", mode.name())
        }
    } else {
        String::new()
    };

    SeedVerdict {
        seed,
        failed,
        trace_hash: report.trace_hash,
        state_hash: report.state_hash,
        ops: (report.ok_ops + report.err_ops) as u64,
        sim_time: report.end_time,
        summary,
    }
}

/// The mode's natural config for `seed` (swarmed when requested).
fn config_for(mode: ReplayMode, seed: u64, swarm: bool) -> VoprConfig {
    if swarm {
        // Swarm derives the *whole* environment from the seed (rmp #241); the mode is still the runner
        // that config executes under.
        return VoprConfig::swarm(seed);
    }
    match mode {
        ReplayMode::Standard => VoprConfig::for_seed(seed),
        ReplayMode::Safety => VoprConfig::safety(seed),
        ReplayMode::Liveness => VoprConfig::liveness(seed),
    }
}

/// Runs `mode` + `config` and returns `(report, real_failed, summary)` — the mode's **real** verdict.
/// Mirrors `vopr_repro::run_mode_verdict` (kept private there) so the fuzzer needs no cross-module seam.
fn run_mode(mode: ReplayMode, config: VoprConfig) -> (VoprReport, bool, String) {
    match mode {
        ReplayMode::Standard => {
            let report = run(config);
            let failed = report.oracle.is_some();
            let summary = match &report.oracle {
                Some(err) => format!("standard: reference-model divergence: {err:?}"),
                None => "standard: no failure".to_owned(),
            };
            (report, failed, summary)
        }
        ReplayMode::Safety => {
            let r = run_safety(config);
            let failed = !r.safe;
            let summary = if r.safe {
                "safety: no failure".to_owned()
            } else {
                let props: Vec<&str> = r.violations.iter().map(|v| v.property.name()).collect();
                format!("safety: violated {props:?}")
            };
            (r.run, failed, summary)
        }
        ReplayMode::Liveness => {
            let r = run_liveness(config);
            let failed = !r.live;
            let summary = if r.live {
                "liveness: no failure".to_owned()
            } else {
                let kinds: Vec<&str> = r.failures.iter().map(|f| f.name()).collect();
                format!("liveness: failed {kinds:?}")
            };
            (r.run, failed, summary)
        }
    }
}

/// How the sweep enumerates and bounds the seed range it explores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepRange {
    /// The first seed to run (inclusive).
    pub start: u64,
    /// One past the last seed to run (exclusive). `start..end` is the seed range.
    pub end: u64,
}

impl SweepRange {
    /// A range of exactly `count` seeds from `start` (saturating at `u64::MAX`).
    #[must_use]
    pub fn count(start: u64, count: u64) -> Self {
        Self {
            start,
            end: start.saturating_add(count),
        }
    }

    /// The number of seeds in the range.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the range is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

/// Runs a **fixed seed range** under `mode` across `jobs` worker threads and returns the per-seed
/// verdicts **sorted by seed** (rmp #243).
///
/// This is the deterministic core both [`fuzz`] and the parallel/serial equality test build on. Each
/// seed in `range` runs **exactly once** (workers pull disjoint seeds from a shared atomic counter) and
/// its verdict is a pure function of `(mode, config, predicate)`, so the returned set — sorted by seed —
/// is **identical to a serial sweep** over the same range regardless of thread timing or `jobs`.
///
/// `jobs` is clamped to `1..=range.len()`; `jobs == 1` is an in-thread serial sweep (no thread spawn).
/// `predicate` overrides the verdict (the mode's real verdict when `None`).
#[must_use]
pub fn sweep_range(
    mode: ReplayMode,
    range: SweepRange,
    swarm: bool,
    jobs: usize,
    predicate: Option<&FuzzPredicate<'_>>,
) -> Vec<SeedVerdict> {
    if range.is_empty() {
        return Vec::new();
    }

    let span = range.len();
    // Never spawn more workers than there are seeds, and always at least one.
    let workers = jobs.max(1).min(span as usize);

    // Serial fast path: no thread spawn, no shared state — the reference behaviour the parallel path
    // must match.
    if workers == 1 {
        let mut verdicts: Vec<SeedVerdict> = (range.start..range.end)
            .map(|seed| verdict_for_seed(mode, seed, swarm, predicate))
            .collect();
        verdicts.sort_by_key(SeedVerdict::sort_key);
        return verdicts;
    }

    // Shared, monotonically-increasing next-seed cursor: each worker claims the next unclaimed seed with
    // a single atomic fetch-add, so the seeds partition disjointly across workers with no coordination
    // and every seed runs exactly once.
    let next = AtomicU64::new(range.start);
    let end = range.end;
    // Each worker accumulates its own verdicts locally, then pushes the batch once under a short-lived
    // lock — the lock guards the *merge*, never a per-seed run, so workers never contend during work.
    let collected: Mutex<Vec<SeedVerdict>> = Mutex::new(Vec::with_capacity(span as usize));

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let next = &next;
            let collected = &collected;
            scope.spawn(move || {
                let mut local: Vec<SeedVerdict> = Vec::new();
                loop {
                    let seed = next.fetch_add(1, Ordering::Relaxed);
                    if seed >= end {
                        break;
                    }
                    local.push(verdict_for_seed(mode, seed, swarm, predicate));
                }
                if !local.is_empty() {
                    collected.lock().expect("sweep merge lock").extend(local);
                }
            });
        }
    });

    let mut verdicts = collected.into_inner().expect("sweep merge lock");
    // Order-independent aggregation: sort by seed so the output is stable regardless of which worker
    // produced which verdict or in what order.
    verdicts.sort_by_key(SeedVerdict::sort_key);
    verdicts
}

/// How a [`FuzzRun`] decides when to stop a continuous sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuzzBudget {
    /// The wall-clock budget. The sweep keeps launching seeds until this elapses; a seed already in
    /// flight at expiry finishes (a seed is the atomic unit of work). `None` ⇒ no time budget (bounded
    /// only by `max_seeds` / the seed space).
    pub duration: Option<Duration>,
    /// An optional hard cap on the number of seeds to run, so a test can take a deterministic,
    /// wall-clock-free path (run exactly N seeds). `None` ⇒ no seed cap.
    pub max_seeds: Option<u64>,
}

impl FuzzBudget {
    /// A pure **seed-count** budget: run exactly `n` seeds with no time limit (the deterministic,
    /// wall-clock-free path a test uses).
    #[must_use]
    pub fn seeds(n: u64) -> Self {
        Self {
            duration: None,
            max_seeds: Some(n),
        }
    }

    /// A **time** budget: keep sweeping for `duration` wall-clock (no seed cap).
    #[must_use]
    pub fn for_duration(duration: Duration) -> Self {
        Self {
            duration: Some(duration),
            max_seeds: None,
        }
    }
}

/// The full configuration of one continuous fuzz soak (rmp #243).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuzzRun {
    /// Which runner each seed executes under.
    pub mode: ReplayMode,
    /// The first seed to enumerate (the sweep runs `start_seed`, `start_seed + 1`, …).
    pub start_seed: u64,
    /// Whether each seed swarms its full environment (rmp #241).
    pub swarm: bool,
    /// Worker-thread count (clamped to `>= 1`). [`available_jobs`] picks the machine default.
    pub jobs: usize,
    /// When to stop (time and/or seed-count budget).
    pub budget: FuzzBudget,
    /// `true` ⇒ stop at the first failing seed; `false` ⇒ keep collecting every failing seed until the
    /// budget expires.
    pub stop_on_failure: bool,
}

impl FuzzRun {
    /// A continuous, time-budgeted soak in `mode` from `start_seed` across `jobs` workers.
    #[must_use]
    pub fn new(mode: ReplayMode, start_seed: u64, jobs: usize, budget: FuzzBudget) -> Self {
        Self {
            mode,
            start_seed,
            swarm: false,
            jobs: jobs.max(1),
            budget,
            stop_on_failure: false,
        }
    }
}

/// The machine's default worker count: [`std::thread::available_parallelism`], or `1` if it cannot be
/// queried (a conservative, always-valid fallback).
#[must_use]
pub fn available_jobs() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
}

/// A failing seed surfaced by the fuzzer, paired with its #242 replay artifact for one-command
/// reproduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzFailure {
    /// The failing seed.
    pub seed: u64,
    /// A one-line, human-readable summary of why it failed.
    pub summary: String,
    /// A self-contained #242 reproducer artifact (mode + full config + the run's canonical hashes), so
    /// the failure replays byte-identically via `vopr-repro --replay`.
    pub artifact: ReplayArtifact,
}

/// The deterministic-up-to-throughput outcome of one continuous fuzz soak (rmp #243).
///
/// The **verdict set** (`seeds_run`, `failures`) is a pure function of the seed range explored, so two
/// soaks that happen to cover the same range produce the same failures in the same (seed-sorted) order.
/// The **throughput metrics** (`elapsed`, `seeds_per_sec`, `ops_per_sec`) depend on wall-clock and so
/// vary run to run — they are the hyper-speed report, not part of the determinism contract.
#[derive(Debug, Clone, PartialEq)]
pub struct FuzzReport {
    /// Which runner the soak used.
    pub mode: ReplayMode,
    /// The first seed enumerated.
    pub start_seed: u64,
    /// One past the last seed enumerated — so `start_seed..end_seed` is exactly the range explored.
    pub end_seed: u64,
    /// Total seeds run (`= end_seed - start_seed`).
    pub seeds_run: u64,
    /// Worker-thread count the soak used.
    pub jobs: usize,
    /// Failing seeds, **sorted by seed**, each with its replay artifact. Empty ⇒ the soak found no
    /// failure in the range.
    pub failures: Vec<FuzzFailure>,
    /// Total operations dispatched across every seed (the ops/sec numerator).
    pub total_ops: u64,
    /// Total logical (simulated) time advanced across every seed — the hyper-speed "simulated time" the
    /// soak compressed into `elapsed` wall-clock.
    pub total_sim_time: u64,
    /// Wall-clock the soak took (orchestrator-measured — the only wall-clock in the pipeline).
    pub elapsed: Duration,
    /// **Seeds per second** — the hyper-speed metric (`seeds_run / elapsed`).
    pub seeds_per_sec: f64,
    /// **Operations per second** (`total_ops / elapsed`).
    pub ops_per_sec: f64,
    /// Whether the soak stopped early on the first failure (`stop_on_failure`).
    pub stopped_on_failure: bool,
}

/// Runs a continuous, time-budgeted, multi-core fuzz soak (rmp #243) and returns its [`FuzzReport`].
///
/// The soak enumerates seeds from `cfg.start_seed` upward in **batches** (one batch ≈ one seed per
/// worker), running each batch through the deterministic [`sweep_range`]. After each batch it checks the
/// stop conditions — the wall-clock budget, the optional `max_seeds` cap, or (when `stop_on_failure`) a
/// failure found — and stops launching once any trips. A seed already running when the deadline passes
/// finishes (a seed is atomic), so a verdict is never half-computed. The wall clock is read **only**
/// here, in the orchestrator, to bound the soak and measure throughput — never inside a run.
///
/// `predicate` overrides the per-seed verdict (the mode's real verdict when `None`); a test plants a
/// synthetic failure (e.g. "seed == K fails") to exercise the failure path without a real engine bug.
#[must_use]
pub fn fuzz(cfg: FuzzRun, predicate: Option<&FuzzPredicate<'_>>) -> FuzzReport {
    let jobs = cfg.jobs.max(1);
    let deadline = cfg.budget.duration.map(|d| Instant::now() + d);
    let started = Instant::now();

    // The batch size: one seed per worker per batch keeps the wall-clock check frequent (so the time
    // budget is honoured tightly) while still amortising thread-spawn over `jobs` seeds. At least one.
    let batch = jobs.max(1) as u64;

    let mut all_verdicts: Vec<SeedVerdict> = Vec::new();
    let mut found_failure = false;
    let mut next_seed = cfg.start_seed;
    let mut seeds_run: u64 = 0;

    loop {
        // Stop conditions checked *before* launching the next batch (the wall-clock read lives only
        // here). A run already in the current/previous batch always completed — a seed is atomic.
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                break;
            }
        }
        if let Some(max) = cfg.budget.max_seeds {
            if seeds_run >= max {
                break;
            }
        }
        if cfg.stop_on_failure && found_failure {
            break;
        }

        // Size this batch, honouring a `max_seeds` cap and the seed-space ceiling.
        let mut this_batch = batch;
        if let Some(max) = cfg.budget.max_seeds {
            this_batch = this_batch.min(max - seeds_run);
        }
        let range_end = next_seed.saturating_add(this_batch);
        if range_end <= next_seed {
            break; // seed space exhausted
        }
        let range = SweepRange {
            start: next_seed,
            end: range_end,
        };

        let verdicts = sweep_range(cfg.mode, range, cfg.swarm, jobs, predicate);
        if verdicts.iter().any(|v| v.failed) {
            found_failure = true;
        }
        seeds_run = seeds_run.saturating_add(range.len());
        next_seed = range_end;
        all_verdicts.extend(verdicts);
    }

    let elapsed = started.elapsed();

    // Order-independent aggregation: sort the merged verdicts by seed so the report is stable regardless
    // of batch/thread timing.
    all_verdicts.sort_by_key(SeedVerdict::sort_key);

    let total_ops: u64 = all_verdicts.iter().map(|v| v.ops).sum();
    let total_sim_time: u64 = all_verdicts.iter().map(|v| v.sim_time).sum();

    // Build a replay artifact for each failing seed (sorted by seed already). When `stop_on_failure`, we
    // surface only the first failing seed; otherwise every collected failure.
    let mut failures: Vec<FuzzFailure> = Vec::new();
    for v in all_verdicts.iter().filter(|v| v.failed) {
        let config = config_for(cfg.mode, v.seed, cfg.swarm);
        failures.push(FuzzFailure {
            seed: v.seed,
            summary: v.summary.clone(),
            artifact: ReplayArtifact {
                version: ARTIFACT_VERSION,
                mode: cfg.mode,
                config,
                expected_trace_hash: v.trace_hash,
                expected_state_hash: v.state_hash,
                failure_summary: v.summary.clone(),
            },
        });
        if cfg.stop_on_failure {
            break;
        }
    }

    let secs = elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    FuzzReport {
        mode: cfg.mode,
        start_seed: cfg.start_seed,
        end_seed: next_seed,
        seeds_run,
        jobs,
        failures,
        total_ops,
        total_sim_time,
        elapsed,
        seeds_per_sec: seeds_run as f64 / secs,
        ops_per_sec: total_ops as f64 / secs,
        stopped_on_failure: cfg.stop_on_failure && found_failure,
    }
}

/// Renders a clean, multi-line summary of a [`FuzzReport`] (rmp #243) for the CLI: the throughput
/// metrics (seeds/sec, ops/sec, simulated time) and every failing seed with its one-line reproduction.
#[must_use]
pub fn summarize_fuzz(r: &FuzzReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "vopr-fuzz mode={} seeds={}..{} ({} run) jobs={} elapsed={:.3}s\n",
        r.mode.name(),
        r.start_seed,
        r.end_seed,
        r.seeds_run,
        r.jobs,
        r.elapsed.as_secs_f64(),
    ));
    out.push_str(&format!(
        "vopr-fuzz throughput: {:.1} seeds/sec, {:.0} ops/sec, sim_time_advanced={} (total ops={})\n",
        r.seeds_per_sec, r.ops_per_sec, r.total_sim_time, r.total_ops,
    ));
    if r.failures.is_empty() {
        out.push_str("vopr-fuzz: no failing seed found\n");
    } else {
        out.push_str(&format!(
            "vopr-fuzz: {} failing seed(s){}\n",
            r.failures.len(),
            if r.stopped_on_failure {
                " (stopped on first)"
            } else {
                ""
            },
        ));
        for f in &r.failures {
            out.push_str(&format!(
                "vopr-fuzz: FAIL seed={} {} — reproduce: vopr {} --seed {} --seeds 1\n",
                f.seed,
                f.summary,
                f.artifact.mode.name(),
                f.seed,
            ));
        }
    }
    out
}

/// Drives the `vopr fuzz` subcommand (rmp #243). Returns `(summary, exit_code)` where a non-zero exit
/// code signals at least one failing seed (or a usage error).
///
/// # CLI
///
/// ```text
/// graphus-dst vopr fuzz [flags]
///   --secs <T>            Wall-clock budget in seconds (continuous soak). Mutually informative with
///                        --max-seeds; with neither, defaults to --max-seeds 1 (a single seed).
///   --max-seeds <N>      Hard cap on seeds to run (a deterministic, wall-clock-free path).
///   --mode <m>           standard | safety | liveness (default: standard).
///   --swarm              Swarm each seed's full environment (rmp #241).
///   --jobs <N>           Worker threads (default: available parallelism).
///   --start-seed <S>     First seed to enumerate (default: 1).
///   --stop-on-failure    Halt at the first failing seed (default: keep going).
///   --keep-going         Collect every failing seed until the budget expires (the default).
///   --write-artifacts <dir>
///                        Write each failing seed's #242 replay artifact JSON into <dir>.
/// ```
#[must_use]
pub fn run_fuzz_cli<I: IntoIterator<Item = String>>(args: I) -> (String, u32) {
    let mut secs: Option<f64> = None;
    let mut max_seeds: Option<u64> = None;
    let mut mode = ReplayMode::Standard;
    let mut swarm = false;
    let mut jobs: Option<usize> = None;
    let mut start_seed: u64 = 1;
    let mut stop_on_failure = false;
    let mut artifact_dir: Option<String> = None;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        // Valueless flags first.
        match arg.as_str() {
            "--swarm" => {
                swarm = true;
                continue;
            }
            "--stop-on-failure" => {
                stop_on_failure = true;
                continue;
            }
            "--keep-going" => {
                stop_on_failure = false;
                continue;
            }
            _ => {}
        }
        let mut next_val = |label: &str| -> Result<String, String> {
            it.next()
                .ok_or_else(|| format!("flag {label} needs a value"))
        };
        let parsed: Result<(), String> = match arg.as_str() {
            "--secs" => next_val("--secs").and_then(|v| {
                v.parse::<f64>()
                    .map_err(|_| "flag --secs needs a number".to_owned())
                    .and_then(|s| {
                        if s.is_finite() && s >= 0.0 {
                            secs = Some(s);
                            Ok(())
                        } else {
                            Err("flag --secs needs a non-negative, finite number".to_owned())
                        }
                    })
            }),
            "--max-seeds" => next_val("--max-seeds").and_then(|v| {
                v.parse::<u64>()
                    .map(|n| max_seeds = Some(n.max(1)))
                    .map_err(|_| "flag --max-seeds needs an integer".to_owned())
            }),
            "--mode" => next_val("--mode").and_then(|v| ReplayMode::parse(&v).map(|m| mode = m)),
            "--jobs" => next_val("--jobs").and_then(|v| {
                v.parse::<usize>()
                    .map(|n| jobs = Some(n.max(1)))
                    .map_err(|_| "flag --jobs needs a positive integer".to_owned())
            }),
            "--start-seed" => next_val("--start-seed").and_then(|v| {
                v.parse::<u64>()
                    .map(|s| start_seed = s)
                    .map_err(|_| "flag --start-seed needs an integer".to_owned())
            }),
            "--write-artifacts" => next_val("--write-artifacts").map(|v| artifact_dir = Some(v)),
            other => Err(format!("unknown flag {other}")),
        };
        if let Err(e) = parsed {
            return (format!("error: {e}\n"), 1);
        }
    }

    // Resolve the budget. A time budget and a seed cap may coexist (whichever trips first stops the
    // soak); with neither, default to a single seed so the command always terminates promptly.
    let budget = FuzzBudget {
        duration: secs.map(Duration::from_secs_f64),
        max_seeds: if secs.is_none() && max_seeds.is_none() {
            Some(1)
        } else {
            max_seeds
        },
    };

    let cfg = FuzzRun {
        mode,
        start_seed,
        swarm,
        jobs: jobs.unwrap_or_else(available_jobs),
        budget,
        stop_on_failure,
    };

    let report = fuzz(cfg, None);
    let mut out = summarize_fuzz(&report);

    // Optionally persist each failure's artifact for `vopr-repro --replay`.
    if let Some(dir) = artifact_dir {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            out.push_str(&format!("error: create artifact dir {dir}: {e}\n"));
            return (out, 1);
        }
        for f in &report.failures {
            let path = std::path::Path::new(&dir).join(format!("vopr-fuzz-{}.json", f.seed));
            match crate::vopr_repro::write_artifact(&path, &f.artifact) {
                Ok(()) => out.push_str(&format!("vopr-fuzz: wrote artifact {}\n", path.display())),
                Err(e) => {
                    out.push_str(&format!("error: {e}\n"));
                    return (out, 1);
                }
            }
        }
    }

    let failures = report.failures.len() as u32;
    (out, failures)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Acceptance — the parallel sweep's verdicts equal the serial sweep's.** A parallel sweep over a
    /// fixed seed range (many workers) must yield the *exact same* per-seed verdict set as a serial sweep
    /// over the same range: identical seeds, identical `failed` bits, identical `trace_hash` /
    /// `state_hash` per seed. This is the key determinism guarantee — a seed's verdict is independent of
    /// which worker ran it, and the seed-sorted aggregation makes the output order stable.
    #[test]
    fn parallel_sweep_equals_serial() {
        let range = SweepRange::count(1000, 16);

        // Serial reference (jobs == 1: in-thread, no spawn).
        let serial = sweep_range(ReplayMode::Standard, range, false, 1, None);
        // Parallel sweep across many workers.
        let parallel = sweep_range(ReplayMode::Standard, range, false, 8, None);

        assert_eq!(
            serial, parallel,
            "the parallel sweep must produce the identical seed-sorted verdict set as the serial sweep"
        );

        // Re-running the parallel sweep is itself deterministic.
        let parallel2 = sweep_range(ReplayMode::Standard, range, false, 4, None);
        assert_eq!(parallel, parallel2, "the parallel sweep is reproducible");

        // Every seed in the range appears exactly once, in sorted order.
        let seeds: Vec<u64> = parallel.iter().map(|v| v.seed).collect();
        let expected: Vec<u64> = (range.start..range.end).collect();
        assert_eq!(
            seeds, expected,
            "every seed runs exactly once, sorted by seed"
        );
    }

    /// The parallel/serial equality holds under a **planted predicate** too: the synthetic verdict is a
    /// pure function of the config, so it partitions the same way no matter which worker evaluates it.
    #[test]
    fn parallel_sweep_equals_serial_with_predicate() {
        let range = SweepRange::count(500, 20);
        let pred = |c: &VoprConfig, _r: &VoprReport| c.seed % 7 == 0;

        let serial = sweep_range(ReplayMode::Standard, range, false, 1, Some(&pred));
        let parallel = sweep_range(ReplayMode::Standard, range, false, 8, Some(&pred));
        assert_eq!(serial, parallel);

        // The planted failures are exactly the multiples of 7 in range.
        let failed: Vec<u64> = parallel
            .iter()
            .filter(|v| v.failed)
            .map(|v| v.seed)
            .collect();
        let expected: Vec<u64> = (range.start..range.end).filter(|s| s % 7 == 0).collect();
        assert_eq!(
            failed, expected,
            "planted failures partition deterministically"
        );
    }

    /// **Acceptance — the time-budgeted soak runs and reports throughput.** A tiny wall-clock budget must
    /// still run at least one seed and populate the hyper-speed metrics (seeds/sec, ops/sec, simulated
    /// time advanced). The budget is sub-second so CI stays fast.
    #[test]
    fn time_budgeted_fuzz_runs_and_reports() {
        let cfg = FuzzRun::new(
            ReplayMode::Standard,
            1,
            2,
            FuzzBudget::for_duration(Duration::from_millis(200)),
        );
        let report = fuzz(cfg, None);

        assert!(report.seeds_run >= 1, "the soak ran at least one seed");
        assert_eq!(
            report.seeds_run,
            report.end_seed - report.start_seed,
            "seeds_run equals the enumerated range"
        );
        assert!(
            report.seeds_per_sec > 0.0,
            "seeds/sec is reported (hyper-speed metric)"
        );
        assert!(report.ops_per_sec > 0.0, "ops/sec is reported");
        assert!(
            report.total_sim_time > 0,
            "simulated time advanced is reported"
        );
        // The summary carries the metrics.
        let summary = summarize_fuzz(&report);
        assert!(summary.contains("seeds/sec"), "{summary}");
        assert!(summary.contains("sim_time_advanced"), "{summary}");
    }

    /// The **seed-count budget** is the deterministic, wall-clock-free path: exactly N seeds run.
    #[test]
    fn seed_count_budget_runs_exactly_n() {
        let cfg = FuzzRun::new(ReplayMode::Standard, 50, 4, FuzzBudget::seeds(12));
        let report = fuzz(cfg, None);
        assert_eq!(report.seeds_run, 12, "exactly the capped seed count ran");
        assert_eq!(report.start_seed, 50);
        assert_eq!(report.end_seed, 62);
    }

    /// **Acceptance — a planted failing seed is found and surfaced with a replay artifact that
    /// reproduces.** The real engine has no failing seed, so we plant "seed == K fails" via the
    /// overridable predicate. The fuzzer must find seed K, emit a #242 [`ReplayArtifact`], and that
    /// artifact must replay byte-identically to a failure.
    #[test]
    fn planted_failing_seed_is_found_with_replaying_artifact() {
        const K: u64 = 77;
        let pred = |c: &VoprConfig, _r: &VoprReport| c.seed == K;

        let cfg = FuzzRun {
            stop_on_failure: false,
            ..FuzzRun::new(ReplayMode::Standard, 70, 4, FuzzBudget::seeds(20))
        };
        let report = fuzz(cfg, Some(&pred));

        // Exactly seed K is surfaced as a failure.
        assert_eq!(report.failures.len(), 1, "exactly the planted seed failed");
        let failure = &report.failures[0];
        assert_eq!(failure.seed, K);
        assert!(
            failure.summary.contains("planted"),
            "the synthetic summary is carried: {}",
            failure.summary
        );

        // The artifact's recorded hashes match a fresh run of the seed's config (byte-identity), and the
        // config round-trips through the same seed.
        let fresh = run(failure.artifact.config);
        assert_eq!(failure.artifact.expected_trace_hash, fresh.trace_hash);
        assert_eq!(failure.artifact.expected_state_hash, fresh.state_hash);
        assert_eq!(failure.artifact.config.seed, K);

        // Replaying the artifact under the *same planted predicate* reproduces the failure: same hashes,
        // still failing. (The plain `vopr_repro::replay_artifact` uses the real verdict, which is clean
        // here — so we assert the predicate-based reproduction directly, mirroring the planted notion.)
        let replay = config_for(failure.artifact.mode, K, false);
        let rerun = run(replay);
        assert_eq!(rerun.trace_hash, failure.artifact.expected_trace_hash);
        assert!(pred(&replay, &rerun), "the artifact replays to the failure");
    }

    /// `stop_on_failure` halts at the first failing seed rather than collecting the whole range.
    #[test]
    fn stop_on_failure_halts_early() {
        // Plant "every seed >= 5 fails"; with stop_on_failure the soak surfaces only the first.
        let pred = |c: &VoprConfig, _r: &VoprReport| c.seed >= 5;
        let cfg = FuzzRun {
            stop_on_failure: true,
            ..FuzzRun::new(ReplayMode::Standard, 1, 1, FuzzBudget::seeds(100))
        };
        let report = fuzz(cfg, Some(&pred));
        assert!(report.stopped_on_failure, "the soak stopped on a failure");
        // Only the first failing seed is surfaced.
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].seed, 5, "the first failing seed (>=5)");
    }

    /// The CLI runs a deterministic, wall-clock-free seed-count soak and reports clean.
    #[test]
    fn cli_runs_a_seed_count_soak() {
        let (out, failures) = run_fuzz_cli(
            [
                "--max-seeds",
                "8",
                "--mode",
                "standard",
                "--jobs",
                "2",
                "--start-seed",
                "1",
            ]
            .iter()
            .map(|s| (*s).to_owned()),
        );
        assert_eq!(failures, 0, "no real engine failure: {out}");
        assert!(out.contains("8 run"), "{out}");
        assert!(out.contains("seeds/sec"), "{out}");
        assert!(out.contains("no failing seed found"), "{out}");
    }

    #[test]
    fn cli_rejects_unknown_flag() {
        let (out, code) = run_fuzz_cli(["--nope".to_owned()]);
        assert_eq!(code, 1);
        assert!(out.starts_with("error:"), "{out}");
    }

    #[test]
    fn cli_rejects_bad_mode() {
        let (out, code) = run_fuzz_cli([
            "--mode".to_owned(),
            "wat".to_owned(),
            "--max-seeds".to_owned(),
            "1".to_owned(),
        ]);
        assert_eq!(code, 1);
        assert!(out.contains("unknown mode"), "{out}");
    }
}
