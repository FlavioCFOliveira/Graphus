//! The **read/write mix** seam shared by every over-the-wire example driver (`rmp` #714).
//!
//! A production graph workload is a **MIX**: reads are served *while writes commit underneath*.
//! Graphus's entire concurrency story — MVCC snapshot-isolation auto-commit reads that neither abort
//! writers nor are aborted by them, the off-thread reader pool (`#336`/`#543`), SSI for writers
//! (`#171`), GC pins held by long readers (`#551`) — exists precisely to make that mix work. A
//! **read-only ladder against a frozen graph cannot expose any of it**. This module is the machinery
//! that lets a driver run the mix, retry like a real driver, and report the result **honestly**.
//!
//! # Two layers of truth, never conflated
//!
//! The single most damaging evidence defect in a concurrent workload is splicing the read vector and
//! the write vector into one section — `operations: 12000, abort_rate: 0.05` reads as *"5% of the
//! 12000 READS aborted"*, which is not merely false but **impossible** (an auto-commit read runs at
//! Snapshot Isolation: it cannot abort). So the two layers are kept apart, structurally:
//!
//! | Layer | What it counts | Where it lives |
//! |---|---|---|
//! | **ENGINE** | transaction *attempts* and *aborts* the engine actually saw — the contention evidence | [`WriteVector::attempts`] / [`WriteVector::aborts`] / [`WriteVector::engine_abort_rate`] |
//! | **APPLICATION** | *business units* driven to commit through managed retry — the outcome the user sees | [`WriteVector::units`] / [`WriteVector::committed`] / [`WriteVector::commit_rate`] |
//! | **READ** | the read ladder's throughput/latency, and the invariant that it **never aborts** | the driver's own read stats + [`ReadInvariant`] |
//!
//! A high engine abort rate **with** a full application commit rate is a *healthy* system under
//! contention: the application-visible cost of contention is **latency** (see the retry-inclusive
//! [`WriteVector::pcts`]), not lost work.
//!
//! # The instrumentation rule (a real bug, `rmp` #715)
//!
//! Per-unit retry counts MUST be accumulated in a **per-unit local** owned by that unit's own closure
//! ([`UnitOutcome`]), then folded into the shared vector afterwards ([`WriteVector::record`]).
//! Differencing a *shared* counter around a unit is wrong under concurrency: other threads' increments
//! leak into the difference and the report can print an impossible `abort_rate > 1`. Every API here is
//! shaped so the correct thing is the easy thing — [`run_managed_write`] hands back a local, and the
//! only way into a [`WriteVector`] is to `record` one.

#![forbid(unsafe_code)]

use std::thread;
use std::time::{Duration, Instant};

use crate::SplitMix64;
use crate::bench::{Pcts, summarize};
use crate::client::ClientError;

// ================================================================================================
// Abort classification (the `rmp` #612 detector)
// ================================================================================================

/// The retryable error family every official Neo4j driver retries in a managed transaction.
pub const TRANSIENT_CODE_PREFIX: &str = "Neo.TransientError.";

/// The error-code **titles** an official driver rewrites *out of* the retryable family.
///
/// The Neo4j drivers carry an `ERROR_REWRITE_MAP` that turns `Neo.TransientError.Transaction.Terminated`
/// and `…LockClientStopped` into a **non-retryable** `Neo.ClientError.*`. A server that dresses its
/// serialization abort in one of these titles silently breaks managed-transaction retry
/// (`session.execute_write`) for **every** driver application — which is exactly what `rmp` #612 was.
/// Graphus emits `Neo.TransientError.Transaction.Outdated` for that reason.
pub const DRIVER_POISON_TITLES: &[&str] = &[".Terminated", ".LockClientStopped"];

/// Is this failure an engine **serialization / SSI abort**?
///
/// Deliberately **BROAD** on the code family (any `Neo.TransientError.*`), so a regression that
/// re-dresses the abort in another transient title is still *classified* as one — and can then be
/// judged non-retryable by [`is_retryable_abort`] instead of silently sliding into the "some other
/// error" bucket where nobody would ever look at it (`rmp` #612).
#[must_use]
pub fn is_serialization_abort(e: &ClientError) -> bool {
    matches!(e, ClientError::Failure(f) if f.code.starts_with(TRANSIENT_CODE_PREFIX))
}

/// Is `code` a driver **poison title** — a code an official driver refuses to retry?
#[must_use]
pub fn is_driver_poison_title(code: &str) -> bool {
    DRIVER_POISON_TITLES.iter().any(|t| code.ends_with(t))
}

/// Would a real driver **retry** this failure in a managed transaction?
///
/// `true` only for a serialization abort that does **not** wear a poison title. This is the classifier
/// [`run_managed_write`] consults, and it mirrors what the official drivers do — so if Graphus ever
/// re-breaks `rmp` #612, this returns `false` for a genuine serialization abort and the run FAILS.
#[must_use]
pub fn is_retryable_abort(e: &ClientError) -> bool {
    match e {
        ClientError::Failure(f) => {
            f.code.starts_with(TRANSIENT_CODE_PREFIX) && !is_driver_poison_title(&f.code)
        }
        _ => false,
    }
}

/// Does this failure **describe** a serialization conflict, whatever code it happens to wear?
///
/// This is the semantic half of the `rmp` #612 detector: it recognises the abort by what the engine
/// *says* (its message) and by the poison titles, independently of the code family. A failure that
/// `looks_like_serialization_conflict` but that [`is_retryable_abort`] refuses is a **regression**:
/// the engine aborted for serializability but dressed it so no driver will ever retry it.
///
/// The message markers are the engine's own wording (`graphus-txn`: *"serialization failure: …
/// (SSI dangerous structure); retry"*) and are kept **narrow** on purpose — a constraint violation or
/// a syntax error must never be mistaken for a serialization abort.
#[must_use]
pub fn looks_like_serialization_conflict(e: &ClientError) -> bool {
    let ClientError::Failure(f) = e else {
        return false;
    };
    if is_serialization_abort(e) || is_driver_poison_title(&f.code) {
        return true;
    }
    let m = f.message.to_ascii_lowercase();
    m.contains("serializ")
        || m.contains("dangerous structure")
        || m.contains("write-write conflict")
}

// ================================================================================================
// Managed retry (what every official driver does)
// ================================================================================================

/// The application's declared retry budget and backoff shape for one business unit.
///
/// This models `session.execute_write` / `executeWrite`: on a retryable serialization abort the unit
/// is re-attempted with **bounded exponential backoff plus full jitter** until it commits or the
/// budget elapses. The jitter matters: without it, the writers that just conflicted all wake together
/// and conflict again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total wall-clock budget for one unit, across every attempt (the driver's
    /// `maxTransactionRetryTime`). Exceeding it is a **retry-budget exhaustion**, not a crash.
    pub budget: Duration,
    /// The first backoff delay; each subsequent retry doubles it (capped at `max_delay`).
    pub base_delay: Duration,
    /// The ceiling on a single backoff delay.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    /// The production-shaped default: a 15 s budget, 5 ms base, 250 ms ceiling.
    fn default() -> Self {
        Self {
            budget: Duration::from_secs(15),
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(250),
        }
    }
}

/// The outcome of **one** unit of business work driven to commit (or to budget exhaustion).
///
/// This is the **per-unit local** the instrumentation rule demands: it is owned by the unit's own
/// closure and folded into the shared [`WriteVector`] only afterwards, so no other thread's
/// increments can leak into it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitOutcome {
    /// Did the business unit ultimately COMMIT?
    pub committed: bool,
    /// Engine transaction attempts this unit cost (always ≥ 1).
    pub attempts: u32,
    /// Engine aborts this unit suffered (serialization conflicts).
    pub aborts: u32,
    /// Did the unit exhaust its retry budget without committing (a livelock signal)?
    pub exhausted: bool,
    /// **Retry-inclusive** latency: from the first attempt's start to the commit (or to giving up).
    /// This is the only latency a user of the application actually experiences.
    pub latency_ns: u64,
    /// A serialization abort the classifier **refused to retry** — the `rmp` #612 regression signal.
    pub nonretryable: Option<String>,
    /// A failure that was not a serialization abort at all (a syntax error, a constraint violation, a
    /// transport fault). Not contention: a genuine error to surface.
    pub other_error: Option<String>,
}

impl UnitOutcome {
    /// Retries this unit cost (`attempts - 1`).
    #[must_use]
    pub fn retries(&self) -> u32 {
        self.attempts.saturating_sub(1)
    }
}

/// Drives **one** business unit to commit through **managed retry** — exactly what an official driver
/// does inside `execute_write`.
///
/// `attempt` performs one engine transaction (for an auto-commit statement, one `RUN`); it is
/// re-invoked from scratch on each retry, so it must rebuild whatever state it needs. Returns the
/// unit's **local** [`UnitOutcome`]; the caller folds it into a [`WriteVector`] with
/// [`WriteVector::record`].
///
/// Classification:
/// * a **retryable** serialization abort ⇒ counted, backed off (exponential + full jitter), retried
///   until the budget elapses (then `exhausted`);
/// * a serialization abort the classifier **refuses** (a poison title) ⇒ counted, `nonretryable` set,
///   **not** retried — this is the `rmp` #612 detector and the caller MUST fail the run on it;
/// * anything else ⇒ `other_error`, not retried.
pub fn run_managed_write<F>(
    policy: &RetryPolicy,
    rng: &mut SplitMix64,
    mut attempt: F,
) -> UnitOutcome
where
    F: FnMut() -> Result<(), ClientError>,
{
    let started = Instant::now();
    let mut out = UnitOutcome::default();
    loop {
        out.attempts = out.attempts.saturating_add(1);
        match attempt() {
            Ok(()) => {
                out.committed = true;
                break;
            }
            Err(e) if is_retryable_abort(&e) => {
                out.aborts = out.aborts.saturating_add(1);
                let elapsed = started.elapsed();
                let Some(remaining) = policy.budget.checked_sub(elapsed) else {
                    out.exhausted = true;
                    break;
                };
                if remaining.is_zero() {
                    out.exhausted = true;
                    break;
                }
                let delay = backoff_delay(policy, out.aborts, rng).min(remaining);
                if !delay.is_zero() {
                    thread::sleep(delay);
                }
            }
            Err(e) if looks_like_serialization_conflict(&e) => {
                // The engine aborted for SERIALIZABILITY but dressed it in a code no driver retries.
                // Retrying it here would HIDE the very defect the example exists to catch (rmp #612).
                out.aborts = out.aborts.saturating_add(1);
                out.nonretryable = Some(e.to_string());
                break;
            }
            Err(e) => {
                out.other_error = Some(e.to_string());
                break;
            }
        }
    }
    out.latency_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    out
}

/// The backoff for the `nth` abort (1-based): `base * 2^(n-1)`, capped at `max_delay`, then **full
/// jitter** (uniform in `[0, capped]`) so conflicting writers do not wake in lockstep.
fn backoff_delay(policy: &RetryPolicy, nth_abort: u32, rng: &mut SplitMix64) -> Duration {
    let base = u64::try_from(policy.base_delay.as_nanos()).unwrap_or(u64::MAX);
    let ceil = u64::try_from(policy.max_delay.as_nanos()).unwrap_or(u64::MAX);
    if base == 0 || ceil == 0 {
        return Duration::ZERO;
    }
    // `1 << shift` with shift < 63 can never overflow; the saturating_mul + min then clamp to `ceil`.
    let shift = nth_abort.saturating_sub(1).min(32);
    let window = base.saturating_mul(1u64 << shift).min(ceil).max(1);
    Duration::from_nanos(rng.next_u64() % (window + 1))
}

// ================================================================================================
// The WRITE vector — the two layers, side by side but never merged
// ================================================================================================

/// The aggregated **write** evidence of a workload: the ENGINE layer (contention) and the APPLICATION
/// layer (business outcome), kept as separate fields so no report can accidentally splice them.
///
/// Every derived figure is an [`Option`]: with **no attempts there is no rate**, and a `0.0` there
/// would claim a conflict-free write workload that never ran (`rmp` #711 — measure it or omit it).
#[derive(Debug, Clone, Default)]
pub struct WriteVector {
    // ---- ENGINE layer -------------------------------------------------------------------------
    /// Engine transaction attempts (every `RUN` of the write, including every retry).
    pub attempts: u64,
    /// Engine transaction aborts (serialization conflicts the engine raised).
    pub aborts: u64,
    // ---- APPLICATION layer --------------------------------------------------------------------
    /// Business units the application asked for.
    pub units: u64,
    /// Business units that COMMITTED.
    pub committed: u64,
    /// Business units that exhausted their retry budget without committing.
    pub exhausted: u64,
    /// Total retries spent across every unit.
    pub retries: u64,
    /// The worst single unit's retry count.
    pub max_retries: u32,
    /// **Retry-inclusive** per-unit latencies, in nanoseconds (unsorted).
    pub lat_ns: Vec<u64>,
    /// Serialization aborts the classifier refused to retry (`rmp` #612). Non-empty ⇒ FAIL the run.
    pub nonretryable: Vec<String>,
    /// Failures that were not serialization aborts at all.
    pub other_errors: u64,
}

impl WriteVector {
    /// Folds one unit's **local** outcome in. The only way to grow a [`WriteVector`] — see the
    /// instrumentation rule in the [module docs](self).
    pub fn record(&mut self, o: &UnitOutcome) {
        self.units = self.units.saturating_add(1);
        self.attempts = self.attempts.saturating_add(u64::from(o.attempts));
        self.aborts = self.aborts.saturating_add(u64::from(o.aborts));
        self.retries = self.retries.saturating_add(u64::from(o.retries()));
        self.max_retries = self.max_retries.max(o.retries());
        if o.committed {
            self.committed = self.committed.saturating_add(1);
            self.lat_ns.push(o.latency_ns);
        }
        if o.exhausted {
            self.exhausted = self.exhausted.saturating_add(1);
        }
        if let Some(nr) = &o.nonretryable {
            self.nonretryable.push(nr.clone());
        }
        if o.other_error.is_some() {
            self.other_errors = self.other_errors.saturating_add(1);
        }
    }

    /// Merges another vector's totals into this one (e.g. one writer thread's into the rung's).
    pub fn merge(&mut self, other: Self) {
        self.attempts = self.attempts.saturating_add(other.attempts);
        self.aborts = self.aborts.saturating_add(other.aborts);
        self.units = self.units.saturating_add(other.units);
        self.committed = self.committed.saturating_add(other.committed);
        self.exhausted = self.exhausted.saturating_add(other.exhausted);
        self.retries = self.retries.saturating_add(other.retries);
        self.max_retries = self.max_retries.max(other.max_retries);
        self.lat_ns.extend_from_slice(&other.lat_ns);
        self.nonretryable.extend(other.nonretryable);
        self.other_errors = self.other_errors.saturating_add(other.other_errors);
    }

    /// Did a write workload run at all? (`false` ⇒ every derived metric below is `None`.)
    #[must_use]
    pub fn attempted(&self) -> bool {
        self.attempts > 0
    }

    /// The **ENGINE** abort rate: `aborts / attempts`. `None` when nothing was attempted — never a
    /// fabricated `0.0`.
    #[must_use]
    pub fn engine_abort_rate(&self) -> Option<f64> {
        (self.attempts > 0).then(|| self.aborts as f64 / self.attempts as f64)
    }

    /// The **APPLICATION** commit rate: `committed / units`. `None` when no unit was requested.
    #[must_use]
    pub fn commit_rate(&self) -> Option<f64> {
        (self.units > 0).then(|| self.committed as f64 / self.units as f64)
    }

    /// Retries spent per committed unit — the price contention charged the application. `None` when
    /// nothing committed.
    #[must_use]
    pub fn retries_per_commit(&self) -> Option<f64> {
        (self.committed > 0).then(|| self.retries as f64 / self.committed as f64)
    }

    /// Committed business units per second over a `wall_secs` window. `None` when nothing committed.
    #[must_use]
    pub fn ops_per_sec(&self, wall_secs: f64) -> Option<f64> {
        (self.committed > 0 && wall_secs > 0.0).then(|| self.committed as f64 / wall_secs)
    }

    /// The **retry-inclusive** per-unit latency percentiles. `None` when nothing committed.
    #[must_use]
    pub fn pcts(&self) -> Option<Pcts> {
        if self.lat_ns.is_empty() {
            return None;
        }
        let mut lat = self.lat_ns.clone();
        lat.sort_unstable();
        Some(summarize(&lat))
    }
}

// ================================================================================================
// The error SAMPLE — an error rate without the error is not evidence
// ================================================================================================

/// A bounded, de-duplicated sample of the distinct failures a workload actually hit.
///
/// A driver that reports *"reader error rate 73%"* and nothing else has produced a number, not
/// evidence: nobody can tell a server defect from a malformed query from a dropped connection, and the
/// only way to find out is to re-run the whole ladder by hand with a debugger attached. That is
/// precisely what happened the first time the mix was switched on (`rmp` #714) — a 54–73% reader error
/// rate appeared in the mixed arm and the report could not say what it *was*.
///
/// So every failure is classified by its **code** (a Bolt `FAILURE`'s code, or `io`/`protocol` for a
/// transport fault), counted, and kept with **one exemplar message**. Bounded at
/// [`MAX_DISTINCT_ERRORS`] distinct codes so a pathological run cannot exhaust memory; everything past
/// the cap is still COUNTED (in `overflow`), never silently dropped.
#[derive(Debug, Clone, Default)]
pub struct ErrorSample {
    /// Every failure recorded, including those past the distinct-code cap.
    pub total: u64,
    /// The distinct codes seen, each with its count and one exemplar message.
    pub distinct: Vec<ErrorKind>,
    /// Failures whose code did not fit the distinct cap (counted, not identified).
    pub overflow: u64,
}

/// One distinct failure code, its frequency, and an exemplar of its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorKind {
    /// The Bolt `FAILURE` code, or `io` / `protocol` for a transport-level fault.
    pub code: String,
    /// One exemplar message for this code (the first one seen).
    pub exemplar: String,
    /// How many failures carried this code.
    pub count: u64,
}

/// The Neo4j status-code family reserved for **the server's own faults** — a bug, not a workload
/// outcome.
///
/// `Neo.ClientError.*` is the client's fault (bad syntax, a violated constraint, no permission).
/// `Neo.TransientError.*` is contention (retry it). `Neo.DatabaseError.*` is **neither**: it means the
/// database hit an internal error it has no contract for. A correct server never returns one, at any
/// rate, for any workload — so it can never be averaged into an "error rate" and waved through under a
/// threshold. See [`ErrorSample::internal_errors`] and invariant I6.
pub const INTERNAL_CODE_PREFIX: &str = "Neo.DatabaseError.";

/// How many distinct error codes an [`ErrorSample`] identifies before it starts counting overflow.
const MAX_DISTINCT_ERRORS: usize = 8;

/// How much of an exemplar message is kept (a Bolt failure message is unbounded; a report line is not).
const MAX_EXEMPLAR_CHARS: usize = 200;

impl ErrorSample {
    /// Records one failure, folding it into its code's bucket.
    pub fn record(&mut self, e: &ClientError) {
        self.total = self.total.saturating_add(1);
        let (code, message) = match e {
            ClientError::Failure(f) => (f.code.clone(), f.message.clone()),
            ClientError::Io(io) => ("io".to_string(), io.to_string()),
            ClientError::Protocol(m) => ("protocol".to_string(), m.clone()),
        };
        if let Some(k) = self.distinct.iter_mut().find(|k| k.code == code) {
            k.count = k.count.saturating_add(1);
            return;
        }
        if self.distinct.len() < MAX_DISTINCT_ERRORS {
            self.distinct.push(ErrorKind {
                code,
                exemplar: truncate(&message, MAX_EXEMPLAR_CHARS),
                count: 1,
            });
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
    }

    /// Merges another sample in, preserving counts across the cap.
    pub fn merge(&mut self, other: Self) {
        self.total = self.total.saturating_add(other.total);
        self.overflow = self.overflow.saturating_add(other.overflow);
        for k in other.distinct {
            if let Some(mine) = self.distinct.iter_mut().find(|m| m.code == k.code) {
                mine.count = mine.count.saturating_add(k.count);
            } else if self.distinct.len() < MAX_DISTINCT_ERRORS {
                self.distinct.push(k);
            } else {
                self.overflow = self.overflow.saturating_add(k.count);
            }
        }
    }

    /// Did anything fail?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// The failures that were the **server's own fault** (`Neo.DatabaseError.*`) — see
    /// [`INTERNAL_CODE_PREFIX`]. These back invariant I6, and a single one FAILS a run.
    #[must_use]
    pub fn internal_errors(&self) -> Vec<&ErrorKind> {
        self.distinct
            .iter()
            .filter(|k| k.code.starts_with(INTERNAL_CODE_PREFIX))
            .collect()
    }

    /// How many failures were internal server errors.
    #[must_use]
    pub fn internal_count(&self) -> u64 {
        self.internal_errors().iter().map(|k| k.count).sum()
    }

    /// A one-line, human-readable summary — the distinct codes ordered by frequency, most frequent
    /// first, each with its count and exemplar. Empty string when nothing failed.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.is_empty() {
            return String::new();
        }
        let mut kinds = self.distinct.clone();
        kinds.sort_by_key(|k| std::cmp::Reverse(k.count));
        let mut parts: Vec<String> = kinds
            .iter()
            .map(|k| format!("{}×{} ({})", k.count, k.code, k.exemplar))
            .collect();
        if self.overflow > 0 {
            parts.push(format!(
                "{} further error(s) past the distinct-code cap",
                self.overflow
            ));
        }
        parts.join("; ")
    }
}

/// Truncates `s` to at most `max` characters, on a char boundary, appending an ellipsis when cut.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max).collect();
    format!("{cut}…")
}

// ================================================================================================
// The READ invariant — an auto-commit read runs at SI and can NEVER abort
// ================================================================================================

/// The read layer's **invariant**: a standalone auto-commit read runs at **Snapshot Isolation**
/// (`rmp` #543/#545), so it neither aborts a writer nor is aborted by one. Any read whose failure code
/// is a serialization abort is therefore an **invariant violation**, not a statistic.
///
/// Before `rmp` #714 every reader error was lumped into one per-family counter, so this was not even
/// *observable*: a serialization abort on the read path would have been silently averaged into an
/// "error rate" and passed the run.
#[derive(Debug, Clone, Default)]
pub struct ReadInvariant {
    /// Reads that failed with a serialization/transient abort code. MUST be zero.
    pub aborted: u64,
    /// The distinct codes observed (capped — this is a violation report, not a histogram).
    pub codes: Vec<String>,
}

/// How many distinct violating codes [`ReadInvariant`] keeps before it stops collecting.
const MAX_READ_ABORT_CODES: usize = 8;

impl ReadInvariant {
    /// Classifies one read failure. Only a serialization abort counts — a transport fault or a syntax
    /// error is a plain error, handled by the driver's existing error-rate gate.
    pub fn record(&mut self, e: &ClientError) {
        if !looks_like_serialization_conflict(e) {
            return;
        }
        self.aborted = self.aborted.saturating_add(1);
        let code = match e {
            ClientError::Failure(f) => f.code.clone(),
            other => other.to_string(),
        };
        if self.codes.len() < MAX_READ_ABORT_CODES && !self.codes.contains(&code) {
            self.codes.push(code);
        }
    }

    /// Merges another reader's observations in.
    pub fn merge(&mut self, other: Self) {
        self.aborted = self.aborted.saturating_add(other.aborted);
        for c in other.codes {
            if self.codes.len() < MAX_READ_ABORT_CODES && !self.codes.contains(&c) {
                self.codes.push(c);
            }
        }
    }

    /// Does the invariant hold?
    #[must_use]
    pub fn ok(&self) -> bool {
        self.aborted == 0
    }
}

// ================================================================================================
// The paired arms — measuring what the MIX costs
// ================================================================================================

/// Which arm of the **paired** ladder a rung belongs to.
///
/// Each rung is run twice, back to back, at the same concurrency and the same op budget against the
/// same graph: [`Arm::Readonly`] (the CONTROL — writers off) and then [`Arm::Mixed`] (the TREATMENT —
/// writers on). The delta between them is *the cost of the mix*, which no read-only ladder can see.
///
/// The control runs FIRST on purpose: it warms the buffer pool for the mixed arm, so the measured cost
/// of the mix is a conservative **lower bound**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm {
    /// Writers OFF — the control.
    Readonly,
    /// Writers ON — the treatment, and the production-shaped default.
    Mixed,
}

impl Arm {
    /// The stable report/sentinel label (`readonly` / `mixed`).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Readonly => "readonly",
            Self::Mixed => "mixed",
        }
    }
}

/// The cost of the mix at one rung, as a **percentage change** in read throughput
/// (`(mixed - control) / control * 100`; negative = the mix cost throughput). `None` when there is no
/// control arm to compare against.
#[must_use]
pub fn mix_cost_pct(control_ops_per_sec: f64, mixed_ops_per_sec: f64) -> Option<f64> {
    (control_ops_per_sec > 0.0)
        .then(|| (mixed_ops_per_sec - control_ops_per_sec) / control_ops_per_sec * 100.0)
}

/// The **liveness floor** for the "readers are not starved by writers" invariant: a mixed rung must
/// keep at least this fraction of its control rung's throughput.
///
/// Deliberately **generous**. This is a catastrophic-collapse guard (a livelock, a writer that locks
/// out every reader), NOT a performance gate: a tight relative gate over a scheduling-variant quantity
/// is a flake generator, not a regression detector.
pub const READ_LIVENESS_FLOOR: f64 = 0.10;

// ================================================================================================
// The writer's workload shape
// ================================================================================================

/// Which of the two write shapes a writer iteration issues.
///
/// A production write stream is not uniform. Most writes touch a **random** key and essentially never
/// conflict; a minority pile onto a small **trending** set (the article everyone is liking right now,
/// the product everyone is buying), where two concurrent read-modify-writes of the *same* node are
/// exactly the rw-antidependency SSI exists to catch.
///
/// # What this actually measures (do not over-claim it)
///
/// The hot component exists so that SSI *can* fire. Whether it *does* is a matter of arithmetic, and
/// at the **production-shaped default** it does not: 2 writers paced one unit every 20 ms, each unit
/// committing in ~2.3 ms, simply do not overlap on the same key often enough — the measured engine
/// abort rate of the default `rmp` #714 run is **~0** (0 aborts in 1735 attempts on a 16-core host).
/// That is the honest result for a trickle, and it is reported as such: a *measured* zero, not a
/// claim that SSI was stressed and found robust.
///
/// So the retry path and the `rmp` #612 detector ([`is_retryable_abort`]) are **armed but idle** on a
/// default run — invariant I4 says exactly that rather than implying it verified something. To arm
/// them for real, raise the contention: more writers, tighter pacing, or fewer hot keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteKind {
    /// The bulk of the stream: a low-conflict write on a RANDOM key.
    Common,
    /// The minority: a read-modify-write on a SMALL trending set — the SSI-exercising component.
    Hot,
}

/// Resolution of the hot/common draw. `10_000` ⇒ a hot fraction is honoured to 0.01%.
const HOT_DRAW_SCALE: u64 = 10_000;

/// Picks the write shape for one iteration: [`WriteKind::Hot`] with probability `hot_fraction`
/// (clamped to `[0, 1]`), else [`WriteKind::Common`]. `draw` is any value from the writer's own
/// deterministic RNG.
#[must_use]
pub fn pick_write_kind(draw: u64, hot_fraction: f64) -> WriteKind {
    let f = hot_fraction.clamp(0.0, 1.0);
    // Integer comparison against a scaled threshold: no float rounding decides the branch.
    let threshold = (f * HOT_DRAW_SCALE as f64).round() as u64;
    if draw % HOT_DRAW_SCALE < threshold {
        WriteKind::Hot
    } else {
        WriteKind::Common
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_bolt::Failure;

    fn failure(code: &str, message: &str) -> ClientError {
        ClientError::Failure(Failure::new(code.to_owned(), message.to_owned()))
    }

    #[test]
    fn the_real_ssi_abort_is_classified_and_retried() {
        let e = failure(
            "Neo.TransientError.Transaction.Outdated",
            "serialization failure: transaction 7 aborted to preserve serializability \
             (SSI dangerous structure); retry",
        );
        assert!(is_serialization_abort(&e));
        assert!(is_retryable_abort(&e));
        assert!(looks_like_serialization_conflict(&e));
    }

    #[test]
    fn poison_titles_are_the_612_regression_and_are_never_retried() {
        // rmp #612: the SSI abort dressed in a title every official driver EXCLUDES from retry.
        for code in [
            "Neo.TransientError.Transaction.Terminated",
            "Neo.ClientError.Transaction.Terminated",
            "Neo.TransientError.Transaction.LockClientStopped",
        ] {
            let e = failure(code, "serialization failure; retry");
            assert!(
                looks_like_serialization_conflict(&e),
                "{code} must still be RECOGNISED as a serialization abort"
            );
            assert!(
                !is_retryable_abort(&e),
                "{code} is a driver poison title and must NOT be retried"
            );
        }
    }

    #[test]
    fn a_serialization_abort_in_a_foreign_code_family_is_still_detected() {
        // The engine aborted for serializability but classified it as a plain ClientError: no driver
        // would retry it. The message gives it away — and that is the whole point of the detector.
        let e = failure(
            "Neo.ClientError.Statement.ArgumentError",
            "serialization failure: transaction 3 aborted (SSI dangerous structure)",
        );
        assert!(!is_serialization_abort(&e));
        assert!(!is_retryable_abort(&e));
        assert!(looks_like_serialization_conflict(&e));
    }

    #[test]
    fn ordinary_errors_are_not_mistaken_for_contention() {
        for (code, msg) in [
            ("Neo.ClientError.Statement.SyntaxError", "invalid input 'X'"),
            (
                "Neo.ClientError.Schema.ConstraintValidationFailed",
                "Node(3) already exists with label `User` and property `id`",
            ),
            ("Neo.ClientError.Security.Unauthorized", "access denied"),
        ] {
            let e = failure(code, msg);
            assert!(!is_serialization_abort(&e), "{code}");
            assert!(!is_retryable_abort(&e), "{code}");
            assert!(
                !looks_like_serialization_conflict(&e),
                "{code} must not be mistaken for a serialization abort"
            );
        }
        // A transport fault is not contention either.
        let io = ClientError::Protocol("unexpected message".into());
        assert!(!looks_like_serialization_conflict(&io));
    }

    /// The retry loop is the heart of the production-shaped client: N aborts then a commit must be
    /// reported as ONE committed unit that cost N+1 engine attempts and N retries.
    #[test]
    fn managed_write_retries_until_it_commits() {
        let policy = RetryPolicy {
            budget: Duration::from_secs(5),
            base_delay: Duration::ZERO, // no sleeping in a unit test
            max_delay: Duration::ZERO,
        };
        let mut rng = SplitMix64::new(1);
        let mut left = 3u32;
        let out = run_managed_write(&policy, &mut rng, || {
            if left > 0 {
                left -= 1;
                Err(failure(
                    "Neo.TransientError.Transaction.Outdated",
                    "serialization failure; retry",
                ))
            } else {
                Ok(())
            }
        });
        assert!(out.committed);
        assert_eq!(out.attempts, 4, "3 aborted attempts + the committing one");
        assert_eq!(out.aborts, 3);
        assert_eq!(out.retries(), 3);
        assert!(!out.exhausted);
        assert!(out.nonretryable.is_none() && out.other_error.is_none());
    }

    #[test]
    fn managed_write_exhausts_its_budget_rather_than_looping_forever() {
        let policy = RetryPolicy {
            budget: Duration::from_millis(20),
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(2),
        };
        let mut rng = SplitMix64::new(2);
        let out = run_managed_write(&policy, &mut rng, || {
            Err(failure(
                "Neo.TransientError.Transaction.Outdated",
                "serialization failure; retry",
            ))
        });
        assert!(!out.committed);
        assert!(
            out.exhausted,
            "a never-committing unit must exhaust, not hang"
        );
        assert!(out.attempts >= 1 && out.aborts >= 1);
        assert!(out.nonretryable.is_none());
    }

    #[test]
    fn managed_write_refuses_to_retry_a_poisoned_abort_and_flags_it() {
        let policy = RetryPolicy {
            budget: Duration::from_secs(5),
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        };
        let mut rng = SplitMix64::new(3);
        let mut calls = 0u32;
        let out = run_managed_write(&policy, &mut rng, || {
            calls += 1;
            Err(failure(
                "Neo.TransientError.Transaction.Terminated",
                "serialization failure; retry",
            ))
        });
        assert_eq!(calls, 1, "a poisoned abort must NOT be retried (rmp #612)");
        assert!(!out.committed);
        assert_eq!(out.aborts, 1);
        assert!(
            out.nonretryable.is_some(),
            "the #612 detector must flag it so the run FAILS"
        );
    }

    #[test]
    fn managed_write_does_not_retry_an_ordinary_error() {
        let policy = RetryPolicy::default();
        let mut rng = SplitMix64::new(4);
        let mut calls = 0u32;
        let out = run_managed_write(&policy, &mut rng, || {
            calls += 1;
            Err(failure(
                "Neo.ClientError.Statement.SyntaxError",
                "bad query",
            ))
        });
        assert_eq!(calls, 1);
        assert!(!out.committed && out.aborts == 0);
        assert!(out.other_error.is_some() && out.nonretryable.is_none());
    }

    /// The `rmp` #715 instrumentation rule, pinned: a vector built from PER-UNIT LOCALS can never
    /// report an impossible rate, however the units interleave. (Differencing a shared counter around
    /// each unit is what produced an `abort_rate > 1` in the field.)
    #[test]
    fn write_vector_folds_per_unit_locals_into_coherent_two_layer_evidence() {
        let mut v = WriteVector::default();
        assert_eq!(
            v.engine_abort_rate(),
            None,
            "no attempts ⇒ NO rate, not 0.0"
        );
        assert_eq!(v.commit_rate(), None);
        assert_eq!(v.retries_per_commit(), None);
        assert_eq!(v.pcts(), None);
        assert!(!v.attempted());

        // Unit A: committed first try. Unit B: two aborts then committed. Unit C: exhausted.
        v.record(&UnitOutcome {
            committed: true,
            attempts: 1,
            aborts: 0,
            latency_ns: 1_000_000,
            ..UnitOutcome::default()
        });
        v.record(&UnitOutcome {
            committed: true,
            attempts: 3,
            aborts: 2,
            latency_ns: 9_000_000,
            ..UnitOutcome::default()
        });
        v.record(&UnitOutcome {
            committed: false,
            attempts: 4,
            aborts: 4,
            exhausted: true,
            latency_ns: 20_000_000,
            ..UnitOutcome::default()
        });

        assert_eq!(v.units, 3);
        assert_eq!(v.attempts, 8);
        assert_eq!(v.aborts, 6);
        assert_eq!(v.committed, 2);
        assert_eq!(v.exhausted, 1);
        assert_eq!(v.retries, 5, "retries: unit A 0 + unit B 2 + unit C 3");
        assert_eq!(v.max_retries, 3);
        let rate = v.engine_abort_rate().expect("attempted");
        assert!(
            (0.0..=1.0).contains(&rate),
            "an abort rate above 1 is impossible: {rate}"
        );
        assert!((rate - 6.0 / 8.0).abs() < 1e-12);
        assert!((v.commit_rate().expect("units") - 2.0 / 3.0).abs() < 1e-12);
        assert!((v.retries_per_commit().expect("committed") - 2.5).abs() < 1e-12);
        // Only COMMITTED units contribute a latency (an exhausted unit has no commit latency).
        assert_eq!(v.pcts().expect("commits").max, 9_000_000);
        assert_eq!(v.ops_per_sec(2.0), Some(1.0));
    }

    #[test]
    fn write_vectors_merge_without_losing_a_layer() {
        let mut a = WriteVector::default();
        a.record(&UnitOutcome {
            committed: true,
            attempts: 2,
            aborts: 1,
            latency_ns: 5,
            ..UnitOutcome::default()
        });
        let mut b = WriteVector::default();
        b.record(&UnitOutcome {
            committed: true,
            attempts: 4,
            aborts: 3,
            latency_ns: 7,
            ..UnitOutcome::default()
        });
        b.nonretryable
            .push("Neo.ClientError.Transaction.Terminated: …".into());
        a.merge(b);
        assert_eq!((a.units, a.attempts, a.aborts, a.committed), (2, 6, 4, 2));
        assert_eq!(a.max_retries, 3);
        assert_eq!(a.lat_ns.len(), 2);
        assert_eq!(
            a.nonretryable.len(),
            1,
            "a #612 flag must survive the merge"
        );
    }

    #[test]
    fn read_invariant_only_counts_serialization_aborts() {
        let mut r = ReadInvariant::default();
        assert!(r.ok());
        r.record(&failure("Neo.ClientError.Statement.SyntaxError", "bad"));
        assert!(r.ok(), "a syntax error is not an SI violation");
        r.record(&failure(
            "Neo.TransientError.Transaction.Outdated",
            "serialization failure; retry",
        ));
        assert!(!r.ok(), "an aborted READ violates Snapshot Isolation");
        assert_eq!(r.aborted, 1);
        assert_eq!(r.codes, vec!["Neo.TransientError.Transaction.Outdated"]);

        let mut other = ReadInvariant::default();
        other.record(&failure(
            "Neo.TransientError.Transaction.Outdated",
            "serialization failure",
        ));
        r.merge(other);
        assert_eq!(r.aborted, 2);
        assert_eq!(r.codes.len(), 1, "the code list is a set, not a histogram");
    }

    #[test]
    fn hot_fraction_is_honoured_and_its_extremes_are_exact() {
        let mut rng = SplitMix64::new(0xDEAD_BEEF);
        let n = 200_000;
        let mut hot = 0u64;
        for _ in 0..n {
            if pick_write_kind(rng.next_u64(), 0.25) == WriteKind::Hot {
                hot += 1;
            }
        }
        let f = hot as f64 / n as f64;
        assert!((f - 0.25).abs() < 0.01, "hot fraction {f} is not ~0.25");

        // The extremes must be exact, not merely likely: 0 ⇒ never hot, 1 ⇒ always hot.
        for _ in 0..1000 {
            let d = rng.next_u64();
            assert_eq!(pick_write_kind(d, 0.0), WriteKind::Common);
            assert_eq!(pick_write_kind(d, 1.0), WriteKind::Hot);
            // Out-of-range fractions clamp rather than misbehave.
            assert_eq!(pick_write_kind(d, -1.0), WriteKind::Common);
            assert_eq!(pick_write_kind(d, 2.0), WriteKind::Hot);
        }
    }

    #[test]
    fn mix_cost_is_a_percentage_delta_and_declines_without_a_control() {
        // 409.4 -> 313.1 ops/s is the measured cost of the mix at C=8 (rmp #714).
        let pct = mix_cost_pct(409.4, 313.1).expect("a control arm");
        assert!((pct - (-23.52)).abs() < 0.1, "got {pct}");
        assert_eq!(
            mix_cost_pct(0.0, 313.1),
            None,
            "no control ⇒ no cost figure"
        );
    }

    #[test]
    fn arm_labels_are_the_sentinel_contract() {
        assert_eq!(Arm::Readonly.label(), "readonly");
        assert_eq!(Arm::Mixed.label(), "mixed");
    }

    /// An error RATE without the error is a number, not evidence. The sampler must name the failure,
    /// count it, and keep an exemplar — that is what turned a bare "95% reader error rate" into the
    /// located root cause of `rmp` #721.
    #[test]
    fn error_sample_names_counts_and_exemplifies_every_distinct_failure() {
        let mut s = ErrorSample::default();
        assert!(s.is_empty());
        assert_eq!(s.summary(), "");

        for _ in 0..3 {
            s.record(&failure(
                "Neo.DatabaseError.General.UnknownError",
                "Prop store page 321 not allocated",
            ));
        }
        s.record(&ClientError::Protocol(
            "unexpected response to RUN: Ignored".into(),
        ));

        assert_eq!(s.total, 4);
        assert_eq!(s.distinct.len(), 2);
        let sum = s.summary();
        assert!(
            sum.contains("3×Neo.DatabaseError.General.UnknownError"),
            "{sum}"
        );
        assert!(sum.contains("Prop store page 321 not allocated"), "{sum}");
        assert!(sum.contains("1×protocol"), "{sum}");
        // Most frequent first — a reader scanning the line sees the dominant failure immediately.
        assert!(sum.find("Neo.DatabaseError").unwrap() < sum.find("protocol").unwrap());
    }

    /// I6: `Neo.DatabaseError.*` is the server's OWN fault. A client error or a transient abort is
    /// not, and must never be mistaken for one (that would make I6 fire on a workload outcome).
    #[test]
    fn only_a_database_error_counts_as_an_internal_server_fault() {
        let mut s = ErrorSample::default();
        s.record(&failure(
            "Neo.DatabaseError.General.UnknownError",
            "Rel store page 388 not allocated",
        ));
        s.record(&failure(
            "Neo.DatabaseError.Statement.ExecutionFailed",
            "internal",
        ));
        // NOT internal faults: the client's fault, and contention.
        s.record(&failure("Neo.ClientError.Statement.SyntaxError", "bad"));
        s.record(&failure(
            "Neo.TransientError.Transaction.Outdated",
            "serialization failure; retry",
        ));
        s.record(&ClientError::Protocol("Ignored".into()));

        assert_eq!(
            s.internal_count(),
            2,
            "only the two Neo.DatabaseError.* failures"
        );
        let codes: Vec<&str> = s
            .internal_errors()
            .iter()
            .map(|k| k.code.as_str())
            .collect();
        assert_eq!(
            codes,
            vec![
                "Neo.DatabaseError.General.UnknownError",
                "Neo.DatabaseError.Statement.ExecutionFailed"
            ]
        );

        let clean = ErrorSample::default();
        assert_eq!(clean.internal_count(), 0);
        assert!(clean.internal_errors().is_empty());
    }

    /// The distinct-code cap must BOUND memory without LOSING counts: everything past the cap is still
    /// counted in `overflow`, never silently dropped.
    #[test]
    fn the_distinct_cap_bounds_memory_without_losing_a_single_error() {
        let mut s = ErrorSample::default();
        for i in 0..(MAX_DISTINCT_ERRORS + 5) {
            s.record(&failure(&format!("Neo.ClientError.Code{i}"), "m"));
        }
        assert_eq!(s.total, (MAX_DISTINCT_ERRORS + 5) as u64);
        assert_eq!(s.distinct.len(), MAX_DISTINCT_ERRORS);
        assert_eq!(s.overflow, 5, "the 5 past the cap are COUNTED, not dropped");
        assert!(
            s.summary()
                .contains("5 further error(s) past the distinct-code cap")
        );
    }

    #[test]
    fn error_samples_merge_and_preserve_counts_across_the_cap() {
        let mut a = ErrorSample::default();
        a.record(&failure("Neo.DatabaseError.General.UnknownError", "page 1"));
        let mut b = ErrorSample::default();
        b.record(&failure("Neo.DatabaseError.General.UnknownError", "page 2"));
        b.record(&failure("Neo.ClientError.Statement.SyntaxError", "bad"));
        a.merge(b);
        assert_eq!(a.total, 3);
        assert_eq!(a.distinct.len(), 2, "the same code folds into one bucket");
        assert_eq!(a.internal_count(), 2);
    }

    /// A Bolt failure message is unbounded; a report line is not.
    #[test]
    fn a_pathological_exemplar_is_truncated_on_a_char_boundary() {
        let mut s = ErrorSample::default();
        let long = "é".repeat(MAX_EXEMPLAR_CHARS * 2);
        s.record(&failure("Neo.ClientError.Statement.SyntaxError", &long));
        let ex = &s.distinct[0].exemplar;
        assert_eq!(
            ex.chars().count(),
            MAX_EXEMPLAR_CHARS + 1,
            "truncated + ellipsis"
        );
        assert!(ex.ends_with('…'));
    }
}
