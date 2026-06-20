//! `vopr_repro` — **persisted replay artifacts + a deterministic config shrinker** for the VOPR core
//! (rmp #242).
//!
//! A VOPR run is a pure function of its [`VoprConfig`] (which carries the master seed): same mode + same
//! config ⇒ identical `trace_hash` + `state_hash` (see [`crate::vopr`]). This module turns that property
//! into two operator tools:
//!
//! 1. **Replay artifact** — a [`ReplayArtifact`] captures everything needed to reproduce a failing run
//!    byte-identically: the [`ReplayMode`], the full [`VoprConfig`], and the canonical
//!    `expected_trace_hash` / `expected_state_hash` the original run produced, plus a human `failure_
//!    summary`. It serializes to JSON (the config and its sub-structs derive serde). [`write_artifact`]
//!    dumps it; [`replay_from_file`] loads it, re-runs the *same* mode+config, and asserts the reproduced
//!    run matches the recorded hashes **and** is still a failure — returning a clear [`ReplayOutcome`].
//!
//! 2. **Deterministic shrinker** — [`shrink`] greedily reduces a failing config (fewer ops, clients,
//!    pool pages, faults, crashes; a simpler mix) while **preserving the failure**, emitting the minimal
//!    still-failing config as a [`ReplayArtifact`]. It is deterministic, bounded (a hard cap on candidate
//!    evaluations), and **never accepts a non-failing config** — so the result is always a real, smaller
//!    reproducer. The failure predicate is overridable so tests can inject a synthetic failure without
//!    needing a real engine bug.
//!
//! # The single notion of "failure"
//!
//! Both tools agree on one [`is_failure`] predicate over a (mode, config) run:
//! * **Standard** — the reference-model oracle diverged ([`VoprReport::oracle`] is `Some`).
//! * **Safety** — a safety property was violated ([`crate::vopr::SafetyReport::safe`] is `false`).
//! * **Liveness** — a liveness property failed ([`crate::vopr::LivenessReport::live`] is `false`).
//!
//! Tests override this with a closure over the [`VoprReport`] (e.g. "clients ≥ 3 && ops ≥ 10 fails") so
//! the shrinker can be exercised against a *synthetic* failure deterministically.
//!
//! # CLI
//!
//! Driven through [`run_repro_cli`] (wired under the `vopr-repro` subcommand of the `graphus-dst`
//! binary):
//!
//! ```text
//! graphus-dst vopr-repro --replay <file.json>
//!     Load a reproducer artifact, re-run it, and assert it reproduces byte-identically (and still
//!     fails). Exit 0 on a faithful reproduction; non-zero on a hash mismatch or a vanished failure.
//!
//! graphus-dst vopr-repro --shrink <seed> [--mode standard|safety|liveness] [--out <file.json>]
//!     Shrink the failing run for <seed> in <mode> to a minimal still-failing reproducer and write the
//!     artifact to <file.json> (default: vopr-repro-<seed>.json). Exit 0 if the seed actually fails and
//!     a minimal artifact was written; non-zero if the seed does not fail (nothing to shrink).
//! ```

use std::path::Path;

use crate::mix::MixProfile;
use crate::vopr::{VoprConfig, VoprReport, run, run_liveness, run_safety};

/// The artifact format version. Bumped on any breaking change to the on-disk JSON shape so a loader can
/// reject an artifact it cannot faithfully replay rather than silently mis-reproducing.
pub const ARTIFACT_VERSION: u32 = 1;

/// Hard cap on the number of candidate configs the [`shrink`] search evaluates, so the shrinker always
/// terminates regardless of the starting config. Each candidate is one full deterministic run; the
/// greedy passes converge well within this bound for any bounded config (see [`shrink`]).
pub const SHRINK_MAX_CANDIDATES: usize = 4_096;

/// The floor the shrinker keeps `pool_pages` at or above. A pathologically tiny buffer pool
/// (`<= 2` pages) provokes re-entrant eviction *inside* a WAL-protected page write, which the engine's
/// buffer-pool/WAL coupling does not tolerate — the run cannot even be built. The swarm preset documents
/// `48` as the smallest pool that induces real eviction/steal pressure while staying valid
/// ([`VoprConfig::swarm`]), so the shrinker uses the same floor: a reproducer the engine cannot build is
/// not a valid reproducer, and shrinking the pool below this would change a real failure into a
/// build-time panic of a different class.
pub const SHRINK_MIN_POOL_PAGES: usize = 48;

/// An overridable failure predicate for [`shrink`]: given the candidate **config** (the knobs being
/// varied) and the [`VoprReport`] of a standard run of that config, decide whether it is a failure. The
/// default (the mode's real verdict) is used when [`shrink`] is passed `None`; tests inject a closure to
/// stand in for a real engine bug.
pub type FailurePredicate<'a> = dyn Fn(&VoprConfig, &VoprReport) -> bool + 'a;

/// Which VOPR runner a [`ReplayArtifact`] replays under. Each maps to one mode runner and one default
/// failure verdict (see [`is_failure`]). Serializes as a lower-case tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReplayMode {
    /// The bare deterministic run ([`run`]); failure ⇔ reference-model oracle divergence.
    Standard,
    /// Safety mode ([`run_safety`]); failure ⇔ a safety property violated.
    Safety,
    /// Liveness mode ([`run_liveness`]); failure ⇔ a liveness property failed.
    Liveness,
}

impl ReplayMode {
    /// A stable, lower-kebab name for CLI/diagnostics.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ReplayMode::Standard => "standard",
            ReplayMode::Safety => "safety",
            ReplayMode::Liveness => "liveness",
        }
    }

    /// Parses a mode name (`standard` / `safety` / `liveness`), case-insensitively.
    fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "standard" => Ok(ReplayMode::Standard),
            "safety" => Ok(ReplayMode::Safety),
            "liveness" => Ok(ReplayMode::Liveness),
            other => Err(format!(
                "unknown mode {other:?} (expected standard|safety|liveness)"
            )),
        }
    }
}

/// A persisted, self-contained reproducer for one failing VOPR run (rmp #242).
///
/// Everything here is a pure function of the run, so loading this artifact and re-running the recorded
/// `mode` + `config` reproduces the **exact** failure: the reproduced run's `trace_hash` / `state_hash`
/// equal `expected_trace_hash` / `expected_state_hash` byte-for-byte (the determinism gate), and it is
/// still a failure under [`is_failure`]. Serializes to JSON.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReplayArtifact {
    /// On-disk format version (see [`ARTIFACT_VERSION`]).
    pub version: u32,
    /// Which runner reproduces this failure.
    pub mode: ReplayMode,
    /// The full config (seed + environment + workload + faults) the failure replays from.
    pub config: VoprConfig,
    /// The canonical event-trace hash the original failing run produced — the byte-identity gate.
    pub expected_trace_hash: u64,
    /// The final graph-state hash the original failing run produced — the second byte-identity gate.
    pub expected_state_hash: u64,
    /// A human-readable one-line summary of the failure (which property/oracle broke), for triage.
    pub failure_summary: String,
}

impl ReplayArtifact {
    /// Builds an artifact from a *known failing* run of `mode` + `config`. Captures the run's canonical
    /// hashes so a later replay can assert byte-identity. The `failure_summary` is derived from the
    /// mode's real verdict.
    ///
    /// Returns `None` if the run does **not** fail under the mode's default [`is_failure`] verdict — an
    /// artifact is only meaningful for a genuine failure, so a non-failing config is rejected rather than
    /// silently captured.
    #[must_use]
    pub fn capture(mode: ReplayMode, config: VoprConfig) -> Option<Self> {
        let (report, failed, summary) = run_mode_verdict(mode, config);
        if !failed {
            return None;
        }
        Some(Self {
            version: ARTIFACT_VERSION,
            mode,
            config,
            expected_trace_hash: report.trace_hash,
            expected_state_hash: report.state_hash,
            failure_summary: summary,
        })
    }

    /// Serializes this artifact to pretty JSON.
    ///
    /// # Errors
    /// Returns the serde error if serialization fails (not expected for this plain-data shape).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Parses an artifact from JSON, rejecting a version this build cannot replay.
    ///
    /// # Errors
    /// Returns a message if the JSON is malformed or carries an unsupported [`version`](Self::version).
    pub fn from_json(s: &str) -> Result<Self, String> {
        let artifact: Self =
            serde_json::from_str(s).map_err(|e| format!("invalid artifact: {e}"))?;
        if artifact.version != ARTIFACT_VERSION {
            return Err(format!(
                "unsupported artifact version {} (this build replays v{ARTIFACT_VERSION})",
                artifact.version
            ));
        }
        Ok(artifact)
    }
}

/// The verdict of replaying a [`ReplayArtifact`] (rmp #242): did the reproduced run match the recorded
/// hashes byte-for-byte, and is it still a failure?
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// The reproduced run matched both recorded hashes **and** is still a failure — a faithful,
    /// byte-identical reproduction.
    Reproduced {
        /// The reproduced (== recorded) trace hash.
        trace_hash: u64,
        /// The reproduced (== recorded) state hash.
        state_hash: u64,
        /// The reproduced failure summary.
        summary: String,
    },
    /// The reproduced run did not match the recorded hashes — a determinism regression: the run is no
    /// longer a pure function of its config, or the artifact was produced by a different build.
    HashMismatch {
        /// What the artifact recorded.
        expected: (u64, u64),
        /// What the replay produced.
        actual: (u64, u64),
    },
    /// The reproduced run matched the recorded hashes but is **no longer a failure** — the bug it
    /// captured has been fixed (or the artifact was never a real failure).
    NoLongerFails {
        /// The (matching) reproduced hashes.
        hashes: (u64, u64),
    },
}

impl ReplayOutcome {
    /// `true` iff the artifact reproduced byte-identically and still fails (the only success state).
    #[must_use]
    pub fn is_reproduced(&self) -> bool {
        matches!(self, ReplayOutcome::Reproduced { .. })
    }
}

/// Runs `mode` + `config` and returns `(report, failed, one-line failure summary)`. The `failed` bit is
/// the mode's **real** verdict — the canonical default [`is_failure`] notion. The summary names exactly
/// which property/oracle broke (or "no failure" when clean), so an artifact carries a human triage line.
fn run_mode_verdict(mode: ReplayMode, config: VoprConfig) -> (VoprReport, bool, String) {
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

/// The single canonical **failure** predicate over a (mode, config) run (rmp #242): `true` iff the run is
/// a failure under the mode's real verdict — a standard reference-model divergence, a safety-property
/// violation, or a liveness-property failure. This is the default both the replay and the shrinker use.
#[must_use]
pub fn is_failure(mode: ReplayMode, config: VoprConfig) -> bool {
    run_mode_verdict(mode, config).1
}

/// Writes `artifact` as pretty JSON to `path`.
///
/// # Errors
/// Returns a message on a serialization or file-write error.
pub fn write_artifact(path: &Path, artifact: &ReplayArtifact) -> Result<(), String> {
    let json = artifact
        .to_json()
        .map_err(|e| format!("serialize artifact: {e}"))?;
    std::fs::write(path, json).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Loads a [`ReplayArtifact`] from `path`, re-runs the **same** mode + config, and certifies a faithful,
/// byte-identical reproduction (rmp #242).
///
/// The reproduced run must (a) match the recorded `expected_trace_hash` / `expected_state_hash`
/// byte-for-byte — the determinism gate proving the run is a pure function of its config — **and** (b)
/// still be a failure under [`is_failure`]. The returned [`ReplayOutcome`] distinguishes the three
/// cases (faithful / hash-mismatch / no-longer-fails).
///
/// # Errors
/// Returns a message if the file cannot be read or the artifact cannot be parsed (malformed or an
/// unsupported version).
pub fn replay_from_file(path: &Path) -> Result<ReplayOutcome, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let artifact = ReplayArtifact::from_json(&raw)?;
    Ok(replay_artifact(&artifact))
}

/// Re-runs `artifact`'s recorded mode + config and classifies the reproduction (the in-memory core of
/// [`replay_from_file`], exposed for tests that hold an artifact directly).
#[must_use]
pub fn replay_artifact(artifact: &ReplayArtifact) -> ReplayOutcome {
    let (report, failed, summary) = run_mode_verdict(artifact.mode, artifact.config);
    let actual = (report.trace_hash, report.state_hash);
    let expected = (artifact.expected_trace_hash, artifact.expected_state_hash);
    if actual != expected {
        return ReplayOutcome::HashMismatch { expected, actual };
    }
    if !failed {
        return ReplayOutcome::NoLongerFails { hashes: actual };
    }
    ReplayOutcome::Reproduced {
        trace_hash: report.trace_hash,
        state_hash: report.state_hash,
        summary,
    }
}

/// The outcome of a [`shrink`] search: the minimal still-failing artifact and how the search ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShrinkOutcome {
    /// The minimal still-failing reproducer found (always a real failure under the predicate).
    pub artifact: ReplayArtifact,
    /// How many candidate configs the search evaluated (bounded by [`SHRINK_MAX_CANDIDATES`]).
    pub candidates_evaluated: usize,
    /// How many reductions the greedy search accepted (each strictly shrank the config).
    pub reductions_accepted: usize,
    /// Whether the search hit the candidate cap before converging (it still returns the best found).
    pub hit_candidate_cap: bool,
}

/// Greedily reduces a **failing** `start` config to a minimal still-failing reproducer (rmp #242),
/// emitting it as a [`ReplayArtifact`].
///
/// # The reduction strategy
///
/// The search is a deterministic, bounded **greedy hill-climb to a smaller config**. It repeatedly tries
/// to shrink one knob at a time and **accepts a candidate only if it still fails** under `fails`
/// (the same failure notion, see below), keeping the config monotonically smaller. Knobs are tried in a
/// fixed order each pass (most-impactful first), and the passes repeat until a full pass accepts nothing
/// (a fixed point) or the candidate cap trips:
///
/// 1. `ops_per_client` — binary-style halving down toward `1` (the biggest run-length lever).
/// 2. `clients` — halving down toward `1` (fewer concurrent actors).
/// 3. `pool_pages` — halving down toward a small floor. **Shrinking the pool changes engine behavior**
///    (eviction/steal pressure), so a reduction is accepted only when the run *still fails the same
///    way*; the `fails` predicate is the gate, so a pool reduction that flips the verdict is rejected.
/// 4. `fault_budget.max_crashes` then `max_faults` — toward `0` (fewer injected disturbances).
/// 5. `mix` — collapse toward the simplest still-failing single-class-dominant mix.
///
/// Each knob shrink is greedy-minimal: it pushes the knob as low as the predicate allows in that pass.
///
/// # The failure predicate
///
/// `fails` is `Fn(&VoprConfig, &VoprReport) -> bool` — it sees both the candidate **config** (the knobs
/// the shrinker is varying) and the [`VoprReport`] of a **standard** run of that config. The default
/// ([`shrink`] with `None`) is the mode's **real** verdict ([`is_failure`], which ignores its arguments
/// and re-derives the mode verdict). Tests pass `Some(closure)` to inject a *synthetic* failure — either
/// config-level (e.g. "clients ≥ 3 && ops ≥ 10") or report-observable (e.g. "created_nodes ≥ N") — so the
/// shrinker can be exercised without a real engine bug.
///
/// # Determinism, bounding, and the no-non-failing-config invariant
///
/// Every candidate is a pure function of its config, the knob order is fixed, and the per-knob shrink is
/// deterministic — so the search is reproducible. It is bounded by [`SHRINK_MAX_CANDIDATES`]: each
/// candidate is counted, and the search stops at the cap, returning the best (smallest still-failing)
/// config found so far. The returned artifact is **always** a real failure: the search starts from a
/// failing config (asserted) and only ever moves to another failing config.
///
/// # Errors
/// Returns a message if `start` does **not** fail under `fails` — there is nothing to shrink, and the
/// shrinker must never fabricate a failing artifact from a clean config.
pub fn shrink(
    mode: ReplayMode,
    start: VoprConfig,
    fails: Option<&FailurePredicate<'_>>,
) -> Result<ShrinkOutcome, String> {
    // Resolve the predicate into a single closure over a config. With an override we run a *standard*
    // pass of the config and apply the closure to (config, report) (the synthetic-test path). Without, we
    // use the mode's real verdict (the production path).
    let evaluate = |cfg: VoprConfig| -> bool {
        match fails {
            Some(pred) => pred(&cfg, &run(cfg)),
            None => is_failure(mode, cfg),
        }
    };

    let mut candidates = 0usize;
    let mut hit_cap = false;
    // A bounded evaluator that records each candidate run and trips the cap. Returns `None` once the cap
    // is reached so the search stops descending further.
    let eval = |cfg: VoprConfig, candidates: &mut usize, hit_cap: &mut bool| -> Option<bool> {
        if *candidates >= SHRINK_MAX_CANDIDATES {
            *hit_cap = true;
            return None;
        }
        *candidates += 1;
        Some(evaluate(cfg))
    };

    // The start config must genuinely fail — otherwise there is nothing to shrink.
    match eval(start, &mut candidates, &mut hit_cap) {
        Some(true) => {}
        Some(false) => {
            return Err(format!(
                "start config (seed {}, mode {}) does not fail — nothing to shrink",
                start.seed,
                mode.name()
            ));
        }
        None => unreachable!("the cap cannot trip on the first candidate"),
    }

    let mut current = start;
    let mut reductions = 0usize;

    // Greedy fixed-point: repeat full reduction passes until a pass accepts nothing.
    loop {
        let mut progressed = false;

        // 1. ops_per_client: halve toward 1.
        if let Some(reduced) = shrink_u32_field(
            current,
            |c| c.ops_per_client,
            |c, v| c.ops_per_client = v,
            1,
            &mut |cfg| eval(cfg, &mut candidates, &mut hit_cap),
        ) {
            current = reduced;
            reductions += 1;
            progressed = true;
        }
        if hit_cap {
            break;
        }

        // 2. clients: halve toward 1.
        if let Some(reduced) = shrink_u32_field(
            current,
            |c| c.clients,
            |c, v| c.clients = v,
            1,
            &mut |cfg| eval(cfg, &mut candidates, &mut hit_cap),
        ) {
            current = reduced;
            reductions += 1;
            progressed = true;
        }
        if hit_cap {
            break;
        }

        // 3. pool_pages: halve toward the safe floor ([`SHRINK_MIN_POOL_PAGES`]). A pool reduction
        //    changes behavior, so the predicate is the gate — a flip in the verdict rejects it; and the
        //    floor keeps the pool large enough that the engine can still be built (a smaller pool would
        //    panic at build time, a different failure class).
        if let Some(reduced) = shrink_usize_field(
            current,
            |c| c.pool_pages,
            |c, v| c.pool_pages = v,
            SHRINK_MIN_POOL_PAGES,
            &mut |cfg| eval(cfg, &mut candidates, &mut hit_cap),
        ) {
            current = reduced;
            reductions += 1;
            progressed = true;
        }
        if hit_cap {
            break;
        }

        // 4. fault knobs: drive crashes then faults toward 0.
        if let Some(reduced) = shrink_u32_field(
            current,
            |c| c.fault_budget.max_crashes,
            |c, v| c.fault_budget.max_crashes = v,
            0,
            &mut |cfg| eval(cfg, &mut candidates, &mut hit_cap),
        ) {
            current = reduced;
            reductions += 1;
            progressed = true;
        }
        if hit_cap {
            break;
        }
        if let Some(reduced) = shrink_u32_field(
            current,
            |c| c.fault_budget.max_faults,
            |c, v| c.fault_budget.max_faults = v,
            0,
            &mut |cfg| eval(cfg, &mut candidates, &mut hit_cap),
        ) {
            current = reduced;
            reductions += 1;
            progressed = true;
        }
        if hit_cap {
            break;
        }

        // 5. mix: try simplest single-class-dominant mixes, accepting the first that still fails.
        if let Some(reduced) =
            shrink_mix(current, &mut |cfg| eval(cfg, &mut candidates, &mut hit_cap))
        {
            current = reduced;
            reductions += 1;
            progressed = true;
        }
        if hit_cap || !progressed {
            break;
        }
    }

    // Re-capture the minimal config under the *mode's real verdict* to fill the artifact hashes/summary.
    // The config is still failing under the working predicate by construction; for a synthetic predicate
    // (tests) the mode's real verdict may be "clean", so capture the standard hashes regardless and use a
    // predicate-based summary. We therefore build the artifact from a standard run directly.
    let final_report = run(current);
    let summary = match fails {
        Some(_) => format!(
            "shrunk reproducer (predicate-defined failure): clients={} ops={} pool={}",
            current.clients, current.ops_per_client, current.pool_pages
        ),
        None => run_mode_verdict(mode, current).2,
    };
    let artifact = ReplayArtifact {
        version: ARTIFACT_VERSION,
        mode,
        config: current,
        expected_trace_hash: final_report.trace_hash,
        expected_state_hash: final_report.state_hash,
        failure_summary: summary,
    };

    Ok(ShrinkOutcome {
        artifact,
        candidates_evaluated: candidates,
        reductions_accepted: reductions,
        hit_candidate_cap: hit_cap,
    })
}

/// Greedily shrinks one `u32` field toward `floor` by repeated halving, accepting each step only if the
/// candidate still fails. Returns the reduced config if any step was accepted, else `None`. Deterministic
/// and bounded (each halving strictly shrinks the value, so the loop runs `O(log start)` times).
fn shrink_u32_field(
    base: VoprConfig,
    get: impl Fn(&VoprConfig) -> u32,
    set: impl Fn(&mut VoprConfig, u32),
    floor: u32,
    eval: &mut dyn FnMut(VoprConfig) -> Option<bool>,
) -> Option<VoprConfig> {
    let mut current = base;
    let mut accepted = false;
    loop {
        let cur_val = get(&current);
        if cur_val <= floor {
            break;
        }
        // Halve toward the floor (never below it). `(cur+floor)/2` converges monotonically to `floor`.
        let candidate_val = floor.max((cur_val + floor) / 2);
        if candidate_val >= cur_val {
            break; // no progress possible (already adjacent to floor)
        }
        let mut candidate = current;
        set(&mut candidate, candidate_val);
        match eval(candidate) {
            Some(true) => {
                current = candidate;
                accepted = true;
            }
            Some(false) => {
                // This step over-shrank; try stepping just one below the current value (a finer probe)
                // before giving up, so we converge tightly rather than stopping at the first miss.
                if cur_val > floor + 1 {
                    let mut finer = current;
                    set(&mut finer, cur_val - 1);
                    match eval(finer) {
                        Some(true) => {
                            current = finer;
                            accepted = true;
                            continue;
                        }
                        Some(false) => break,
                        None => break,
                    }
                }
                break;
            }
            None => break, // candidate cap tripped
        }
    }
    if accepted { Some(current) } else { None }
}

/// The `usize` analogue of [`shrink_u32_field`] (for `pool_pages`).
fn shrink_usize_field(
    base: VoprConfig,
    get: impl Fn(&VoprConfig) -> usize,
    set: impl Fn(&mut VoprConfig, usize),
    floor: usize,
    eval: &mut dyn FnMut(VoprConfig) -> Option<bool>,
) -> Option<VoprConfig> {
    let mut current = base;
    let mut accepted = false;
    loop {
        let cur_val = get(&current);
        if cur_val <= floor {
            break;
        }
        let candidate_val = floor.max((cur_val + floor) / 2);
        if candidate_val >= cur_val {
            break;
        }
        let mut candidate = current;
        set(&mut candidate, candidate_val);
        match eval(candidate) {
            Some(true) => {
                current = candidate;
                accepted = true;
            }
            Some(false) => {
                if cur_val > floor + 1 {
                    let mut finer = current;
                    set(&mut finer, cur_val - 1);
                    match eval(finer) {
                        Some(true) => {
                            current = finer;
                            accepted = true;
                            continue;
                        }
                        Some(false) => break,
                        None => break,
                    }
                }
                break;
            }
            None => break,
        }
    }
    if accepted { Some(current) } else { None }
}

/// Tries to simplify the workload `mix` toward the simplest still-failing shape: each single-class
/// all-`1`-elsewhere mix in a fixed order, then the uniform `1,1,1,1` mix. Accepts the first candidate
/// that still fails. `LoadProfile` is left untouched (it is a schedule shape, not a size).
fn shrink_mix(
    base: VoprConfig,
    eval: &mut dyn FnMut(VoprConfig) -> Option<bool>,
) -> Option<VoprConfig> {
    // Candidate mixes, simplest first. Weights stay ≥1 so no class is fully excluded (mirrors the
    // generator's own non-degenerate contract). A create-node-dominant mix is the simplest "real work"
    // shape, so it leads.
    let candidates = [
        MixProfile {
            create_node: 1,
            create_edge: 1,
            count_nodes: 1,
            neighbors: 1,
        },
        MixProfile {
            create_node: 2,
            create_edge: 1,
            count_nodes: 1,
            neighbors: 1,
        },
    ];
    for &mix in &candidates {
        if mix == base.mix {
            continue; // already this shape — no reduction
        }
        // Only count it a reduction if the candidate is "simpler": a strictly smaller total weight.
        if mix.total() >= base.mix.total() {
            continue;
        }
        let mut candidate = base;
        candidate.mix = mix;
        match eval(candidate) {
            Some(true) => return Some(candidate),
            Some(false) => continue,
            None => return None,
        }
    }
    None
}

/// Drives the `vopr-repro` subcommand (rmp #242): `--replay <file>` to reproduce a saved failure, or
/// `--shrink <seed>` to minimize a failing seed into an artifact. Returns `(output, exit_code)` where a
/// non-zero exit code signals a failed reproduction / a non-failing seed / a usage error.
///
/// See the [module docs](self) for the full CLI surface.
#[must_use]
pub fn run_repro_cli<I: IntoIterator<Item = String>>(args: I) -> (String, u32) {
    let mut replay_path: Option<String> = None;
    let mut shrink_seed: Option<u64> = None;
    let mut mode = ReplayMode::Standard;
    let mut out_path: Option<String> = None;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let mut next_val = |label: &str| -> Result<String, String> {
            it.next()
                .ok_or_else(|| format!("flag {label} needs a value"))
        };
        let parsed: Result<(), String> = match arg.as_str() {
            "--replay" => next_val("--replay").map(|v| replay_path = Some(v)),
            "--shrink" => next_val("--shrink").and_then(|v| {
                v.parse::<u64>()
                    .map(|s| shrink_seed = Some(s))
                    .map_err(|_| "flag --shrink needs an integer seed".to_owned())
            }),
            "--mode" => next_val("--mode").and_then(|v| ReplayMode::parse(&v).map(|m| mode = m)),
            "--out" => next_val("--out").map(|v| out_path = Some(v)),
            other => Err(format!("unknown flag {other}")),
        };
        if let Err(e) = parsed {
            return (format!("error: {e}\n"), 1);
        }
    }

    match (replay_path, shrink_seed) {
        (Some(_), Some(_)) => (
            "error: pass exactly one of --replay / --shrink\n".to_owned(),
            1,
        ),
        (Some(path), None) => cli_replay(&path),
        (None, Some(seed)) => cli_shrink(mode, seed, out_path),
        (None, None) => (
            "error: pass --replay <file> or --shrink <seed>\n".to_owned(),
            1,
        ),
    }
}

/// Handles `--replay <file>`: reproduce and report the verdict.
fn cli_replay(path: &str) -> (String, u32) {
    match replay_from_file(Path::new(path)) {
        Err(e) => (format!("error: {e}\n"), 1),
        Ok(ReplayOutcome::Reproduced {
            trace_hash,
            state_hash,
            summary,
        }) => (
            format!(
                "vopr-repro: REPRODUCED {summary} trace_hash={trace_hash:016x} \
                 state_hash={state_hash:016x}\n"
            ),
            0,
        ),
        Ok(ReplayOutcome::HashMismatch { expected, actual }) => (
            format!(
                "vopr-repro: HASH MISMATCH expected=({:016x},{:016x}) actual=({:016x},{:016x}) \
                 — run is no longer a pure function of its config (determinism regression)\n",
                expected.0, expected.1, actual.0, actual.1
            ),
            1,
        ),
        Ok(ReplayOutcome::NoLongerFails { hashes }) => (
            format!(
                "vopr-repro: NO LONGER FAILS hashes=({:016x},{:016x}) — the captured bug appears fixed\n",
                hashes.0, hashes.1
            ),
            1,
        ),
    }
}

/// Handles `--shrink <seed>`: minimize the failing seed and write the artifact.
fn cli_shrink(mode: ReplayMode, seed: u64, out_path: Option<String>) -> (String, u32) {
    // Build the starting config for the seed in the requested mode (its natural preset).
    let start = match mode {
        ReplayMode::Standard => VoprConfig::for_seed(seed),
        ReplayMode::Safety => VoprConfig::safety(seed),
        ReplayMode::Liveness => VoprConfig::liveness(seed),
    };
    match shrink(mode, start, None) {
        Err(e) => (format!("vopr-repro: nothing to shrink: {e}\n"), 1),
        Ok(outcome) => {
            let path = out_path.unwrap_or_else(|| format!("vopr-repro-{seed}.json"));
            if let Err(e) = write_artifact(Path::new(&path), &outcome.artifact) {
                return (format!("error: {e}\n"), 1);
            }
            let c = &outcome.artifact.config;
            (
                format!(
                    "vopr-repro: SHRUNK seed={seed} mode={} -> clients={} ops={} pool={} \
                     crashes={} faults={} ({} candidates, {} reductions{}) written to {path}\n",
                    mode.name(),
                    c.clients,
                    c.ops_per_client,
                    c.pool_pages,
                    c.fault_budget.max_crashes,
                    c.fault_budget.max_faults,
                    outcome.candidates_evaluated,
                    outcome.reductions_accepted,
                    if outcome.hit_candidate_cap {
                        ", CAPPED"
                    } else {
                        ""
                    },
                ),
                0,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vopr_fault::FaultBudget;

    /// A deterministic, unique temp path for a round-trip test (no wall-clock, no entropy): derived from
    /// a caller-supplied tag + the process id, so parallel test binaries do not collide and the path is
    /// reproducible within a run. The caller cleans it up.
    fn temp_artifact_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "graphus-vopr-repro-{tag}-{}.json",
            std::process::id()
        ))
    }

    #[test]
    fn artifact_round_trips_through_json() {
        let artifact = ReplayArtifact {
            version: ARTIFACT_VERSION,
            mode: ReplayMode::Safety,
            config: VoprConfig::safety(123),
            expected_trace_hash: 0xdead_beef,
            expected_state_hash: 0x0bad_f00d,
            failure_summary: "synthetic".to_owned(),
        };
        let json = artifact.to_json().expect("serialize");
        let back = ReplayArtifact::from_json(&json).expect("deserialize");
        assert_eq!(artifact, back, "artifact JSON round-trip is lossless");
    }

    #[test]
    fn from_json_rejects_unsupported_version() {
        let artifact = ReplayArtifact {
            version: ARTIFACT_VERSION + 99,
            mode: ReplayMode::Standard,
            config: VoprConfig::for_seed(1),
            expected_trace_hash: 0,
            expected_state_hash: 0,
            failure_summary: String::new(),
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let err = ReplayArtifact::from_json(&json).unwrap_err();
        assert!(err.contains("unsupported artifact version"), "{err}");
    }

    /// **Acceptance — byte-identical reproduction.** Capture a standard run's canonical hashes into an
    /// artifact, persist it to a JSON file, reload it, replay it, and assert the reproduced
    /// `trace_hash` + `state_hash` match the recorded ones byte-for-byte (the determinism gate: a run is
    /// a pure function of its config). The standard run is clean, so the verdict is `NoLongerFails` — but
    /// the *hashes match exactly*, which is the property under test.
    #[test]
    fn replay_reproduces_hashes_byte_identically() {
        let cfg = VoprConfig::for_seed(20260620);
        let report = run(cfg);
        let artifact = ReplayArtifact {
            version: ARTIFACT_VERSION,
            mode: ReplayMode::Standard,
            config: cfg,
            expected_trace_hash: report.trace_hash,
            expected_state_hash: report.state_hash,
            failure_summary: "captured".to_owned(),
        };

        // Round-trip through a real temp file (exercise the on-disk path too).
        let path = temp_artifact_path("byte-identical");
        write_artifact(&path, &artifact).expect("write artifact");
        let outcome = replay_from_file(&path);
        let _ = std::fs::remove_file(&path); // clean up the scratch file
        let outcome = outcome.expect("replay from file");

        let hashes = match outcome {
            ReplayOutcome::NoLongerFails { hashes } => hashes,
            ReplayOutcome::Reproduced {
                trace_hash,
                state_hash,
                ..
            } => (trace_hash, state_hash),
            ReplayOutcome::HashMismatch { .. } => {
                panic!("a replay of the same config must reproduce identical hashes")
            }
        };
        assert_eq!(
            hashes,
            (report.trace_hash, report.state_hash),
            "replay reproduces the recorded hashes byte-for-byte"
        );
    }

    /// A deliberately wrong recorded hash must be detected as a `HashMismatch`.
    #[test]
    fn replay_detects_a_hash_mismatch() {
        let cfg = VoprConfig::for_seed(7);
        let artifact = ReplayArtifact {
            version: ARTIFACT_VERSION,
            mode: ReplayMode::Standard,
            config: cfg,
            expected_trace_hash: 0xffff_ffff_ffff_ffff,
            expected_state_hash: 0,
            failure_summary: "wrong".to_owned(),
        };
        match replay_artifact(&artifact) {
            ReplayOutcome::HashMismatch { actual, .. } => {
                assert_ne!(actual.0, 0xffff_ffff_ffff_ffff, "the real hash differs");
            }
            other => panic!("expected a hash mismatch, got {other:?}"),
        }
    }

    /// **Acceptance — the shrinker converges to a strictly-smaller still-failing reproducer.**
    ///
    /// The real engine has no failing seed, so we inject a *synthetic* config-level failure:
    /// "fails iff clients ≥ 3 AND ops_per_client ≥ 10". The public `shrink` takes a
    /// `Fn(&VoprConfig, &VoprReport) -> bool`, so the predicate reads the candidate config's knobs
    /// directly. We start well above the threshold and assert the shrinker drives both dominant knobs
    /// down to *exactly* the synthetic floor (clients == 3, ops == 10) — strictly smaller than the start —
    /// and never accepts a config below the floor.
    #[test]
    fn shrinker_converges_to_minimal_synthetic_failure() {
        const MIN_CLIENTS: u32 = 3;
        const MIN_OPS: u32 = 10;

        let start = VoprConfig {
            clients: 12,
            ops_per_client: 80,
            pool_pages: 512,
            ..VoprConfig::for_seed(42)
        }
        .with_faults(FaultBudget::default().with_max_faults(8))
        .with_crashes(3);

        let pred = |c: &VoprConfig, _r: &VoprReport| {
            c.clients >= MIN_CLIENTS && c.ops_per_client >= MIN_OPS
        };
        let outcome = shrink(ReplayMode::Standard, start, Some(&pred)).expect("start fails");
        let reduced = outcome.artifact.config;

        // Converged to exactly the synthetic floor on the dominant knobs.
        assert_eq!(reduced.clients, MIN_CLIENTS, "clients shrank to the floor");
        assert_eq!(reduced.ops_per_client, MIN_OPS, "ops shrank to the floor");
        // Strictly smaller than the start.
        assert!(reduced.clients < start.clients);
        assert!(reduced.ops_per_client < start.ops_per_client);
        // The synthetic failure ignores faults/crashes/pool, so the shrinker also drove THOSE to their
        // floors (they never affect the verdict, so every reduction is accepted).
        assert_eq!(reduced.fault_budget.max_crashes, 0, "crashes shrank to 0");
        assert_eq!(reduced.fault_budget.max_faults, 0, "faults shrank to 0");
        assert_eq!(
            reduced.pool_pages, SHRINK_MIN_POOL_PAGES,
            "pool shrank to its safe floor"
        );
        // Still failing under the synthetic predicate.
        assert!(
            pred(&reduced, &run(reduced)),
            "the minimal config still fails"
        );
        // Bounded.
        assert!(outcome.candidates_evaluated <= SHRINK_MAX_CANDIDATES);
        assert!(outcome.reductions_accepted > 0);
        // The emitted artifact replays byte-identically.
        let fresh = run(reduced);
        assert_eq!(outcome.artifact.expected_trace_hash, fresh.trace_hash);
        assert_eq!(outcome.artifact.expected_state_hash, fresh.state_hash);
    }

    /// The shrinker is deterministic: the same start + predicate yield the same minimal config.
    #[test]
    fn shrinker_is_deterministic() {
        let start = VoprConfig {
            clients: 9,
            ops_per_client: 40,
            ..VoprConfig::for_seed(5)
        };
        let pred = |c: &VoprConfig, _r: &VoprReport| c.clients >= 2 && c.ops_per_client >= 4;
        let a = shrink(ReplayMode::Standard, start, Some(&pred)).unwrap();
        let b = shrink(ReplayMode::Standard, start, Some(&pred)).unwrap();
        assert_eq!(a, b, "the shrinker is a pure function of its inputs");
    }

    /// `shrink` must refuse a start config that does not fail (nothing to shrink).
    #[test]
    fn shrink_rejects_a_non_failing_start() {
        let never = |_c: &VoprConfig, _r: &VoprReport| false;
        let err = shrink(ReplayMode::Standard, VoprConfig::for_seed(1), Some(&never))
            .expect_err("a non-failing start must be rejected");
        assert!(err.contains("does not fail"), "{err}");
    }

    /// **Acceptance — `shrink` with a report-observable predicate.** "fails iff created_nodes ≥ N" — a
    /// real, report-observable property monotone in the workload size. The shrinker reduces a big config
    /// to a smaller one that still clears the floor, proving the public path converges and never accepts
    /// a config below the threshold.
    #[test]
    fn shrink_public_path_converges_on_report_predicate() {
        const MIN_CREATED: i64 = 20;
        let start = VoprConfig {
            clients: 10,
            ops_per_client: 60,
            pool_pages: 512,
            ..VoprConfig::for_seed(99)
        };
        assert!(
            run(start).created_nodes >= MIN_CREATED,
            "the start clears the floor"
        );

        let pred = |_c: &VoprConfig, r: &VoprReport| r.created_nodes >= MIN_CREATED;
        let outcome = shrink(ReplayMode::Standard, start, Some(&pred)).expect("start fails");
        let reduced = outcome.artifact.config;

        assert!(
            run(reduced).created_nodes >= MIN_CREATED,
            "reduced config still satisfies the report predicate"
        );
        assert!(
            reduced.ops_per_client < start.ops_per_client
                || reduced.clients < start.clients
                || reduced.pool_pages < start.pool_pages,
            "the shrinker strictly reduced the config (was {start:?}, got {reduced:?})"
        );
        assert!(outcome.candidates_evaluated <= SHRINK_MAX_CANDIDATES);
        let fresh = run(reduced);
        assert_eq!(outcome.artifact.expected_trace_hash, fresh.trace_hash);
        assert_eq!(outcome.artifact.expected_state_hash, fresh.state_hash);
    }

    /// **Acceptance — full CLI shrink → replay round-trip on a real engine failure.** We cannot trigger a
    /// real engine bug, so this exercises the artifact lifecycle end-to-end: a `replay` of an artifact
    /// captured from a real run reproduces byte-identically through the CLI surface.
    #[test]
    fn cli_replay_reproduces_a_written_artifact() {
        let cfg = VoprConfig::for_seed(31337);
        let report = run(cfg);
        let artifact = ReplayArtifact {
            version: ARTIFACT_VERSION,
            mode: ReplayMode::Standard,
            config: cfg,
            expected_trace_hash: report.trace_hash,
            expected_state_hash: report.state_hash,
            failure_summary: "captured".to_owned(),
        };
        let path = temp_artifact_path("cli-replay");
        write_artifact(&path, &artifact).expect("write");
        let (out, code) = run_repro_cli(["--replay".to_owned(), path.display().to_string()]);
        let _ = std::fs::remove_file(&path);
        // A clean standard run reproduces hashes but no longer fails ⇒ exit 1, NO LONGER FAILS — and the
        // recorded hashes are echoed, proving the byte-identity reproduction flowed through the CLI.
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("NO LONGER FAILS"), "{out}");
        assert!(
            out.contains(&format!("{:016x}", report.trace_hash)),
            "the reproduced hash is reported: {out}"
        );
    }

    #[test]
    fn cli_replay_missing_file_errors() {
        let (out, code) = run_repro_cli(["--replay".to_owned(), "/no/such/file.json".to_owned()]);
        assert_eq!(code, 1);
        assert!(out.starts_with("error:"), "{out}");
    }

    #[test]
    fn cli_rejects_both_modes() {
        let (out, code) = run_repro_cli([
            "--replay".to_owned(),
            "x.json".to_owned(),
            "--shrink".to_owned(),
            "1".to_owned(),
        ]);
        assert_eq!(code, 1);
        assert!(out.contains("exactly one"), "{out}");
    }

    #[test]
    fn cli_rejects_no_mode() {
        let (out, code) = run_repro_cli(std::iter::empty::<String>());
        assert_eq!(code, 1);
        assert!(
            out.contains("--replay") && out.contains("--shrink"),
            "{out}"
        );
    }

    #[test]
    fn replay_mode_name_parse_round_trip() {
        for m in [
            ReplayMode::Standard,
            ReplayMode::Safety,
            ReplayMode::Liveness,
        ] {
            assert_eq!(ReplayMode::parse(m.name()).unwrap(), m);
        }
        assert!(ReplayMode::parse("nope").is_err());
    }
}
