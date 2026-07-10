//! `graphus-examples-harness` — the shared evidence-collection scaffold for Graphus's `examples/*`.
//!
//! Every demonstrative example under `examples/*` must, per the project's `Examples` rule, collect
//! **explicit evidence across all performance vectors — memory, CPU, and storage**. Rather than have
//! each example reinvent that machinery, they all consume this small, dev-only library:
//!
//! 1. construct an [`EvidenceCollector`] with the run's metadata,
//! 2. call [`EvidenceCollector::start`] before exercising the server,
//! 3. record phase timings / metrics into the typed sections as the scenario runs,
//! 4. call [`EvidenceCollector::finish`] when done, and
//! 5. call [`EvidenceReport::write_to`] to emit a machine-readable `report.json` plus a
//!    human-readable `report.md` into the example's git-ignored `evidence/` directory.
//!
//! ## The evidence schema (stable, versioned)
//!
//! [`EvidenceReport`] is a **stable, versioned schema** that `examples/*` (`rmp #27`–`#33`) and
//! external tooling can rely on. Every field is `serde` Serialize/Deserialize with a fixed
//! **snake_case** wire name; the top level carries an integer [`EvidenceReport::version`]
//! ([`SCHEMA_VERSION`]) so consumers can detect format changes. The schema is documented field by
//! field on each section type below, and mirrored in `examples/README.md`.
//!
//! The sections are:
//!
//! | Section | Captures |
//! |---------|----------|
//! | [`RunMetadata`]     | scenario id, dataset scale, workload params, description |
//! | [`HostInfo`]        | os, arch, cpu cores, hostname, rustc version, timestamp |
//! | [`CpuSection`]      | user / system CPU seconds, mean core utilisation |
//! | [`MemorySection`]   | peak / final RSS bytes |
//! | [`StorageSection`]  | store / WAL bytes + pages, bytes fsynced, write-amp, space-amp |
//! | [`ThroughputSection`] | operations, ops/sec, p50 / p99 / p999 latency (ms) |
//! | [`ServerMetricsSection`] | server-side `/metrics` deltas: committed/aborted txns, abort rate, slow queries, panic/force-detach counters, SSI gauge, query-duration histogram |
//!
//! Every report also carries a top-level [`EvidenceReport::measurement_mode`]
//! ([`MeasurementMode`]) recording whether the evidence was collected against a **local** server
//! (this host, with `/proc` + store-file access) or an **external** one (a remote instance, where
//! only the `/metrics` endpoint is reachable).
//!
//! ## Baseline-diff regression detection
//!
//! [`EvidenceReport::compare_to_baseline`] diffs a run against a committed baseline report and flags
//! a **regression** when any key metric degrades beyond a configurable threshold (default 10%).
//! Load a baseline from disk with [`EvidenceReport::load`].
//!
//! ## Why this is a separate leaf crate
//!
//! It is depended upon by NOTHING in the production build (notably **not** `graphus-server`), so it
//! adds zero overhead to the shipped binary — exactly the role `graphus-bench` plays for benchmarks.
//!
//! ## Scaffold, not the metering itself
//!
//! This crate establishes the **typed seams** every example collects evidence through, and a minimal
//! working report writer so the smoke example produces real output today. The actual metering is
//! filled in by follow-up tasks:
//!
//! - **`rmp #246`** — CPU & memory metering ([`CpuSection`], [`MemorySection`]): `getrusage`,
//!   peak RSS, `/proc` sampling.
//! - **`rmp #247`** — storage metering + throughput/latency collectors ([`StorageSection`],
//!   [`ThroughputSection`]).
//! - **`rmp #248`** — the standardized evidence-report emitter (richer JSON + Markdown), the stable
//!   versioned schema, host/env auto-detection, and the baseline-diff regression helper. **(this
//!   crate, now complete).**
//!
//! The API is deliberately allocation-light and side-effect-free until [`EvidenceReport::write_to`],
//! making it usable from DST-driven (deterministic) scenarios. Only [`HostInfo`]'s timestamp and the
//! environmental fields are wall-clock / platform derived — by design, since they are *report
//! metadata*; every measured metric value comes from injected meters.

//! ## `unsafe` policy
//!
//! The crate is `unsafe`-free except for the [`resource`] metering module, which makes a handful of
//! `getrusage`/`sysconf` libc calls — each confined to a tiny helper with a `// SAFETY:` rationale.
//! We therefore use `deny(unsafe_op_in_unsafe_fn)` (every `unsafe` op must sit in an explicit
//! `unsafe` block) instead of a blanket `forbid(unsafe_code)`; the rest of the crate uses no
//! `unsafe`.
#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub mod diff;
pub mod host;
pub mod metrics;
pub mod resource;
pub mod scrape;

pub use diff::{ComparisonReport, MetricDelta, RegressionThresholds};
pub use host::HostInfo;
pub use metrics::{DiskFootprint, LatencyCollector, PAGE_SIZE, StorageMeter, ThroughputCounter};
pub use resource::{
    CpuMeter, CpuTimes, ResourceMeter, RssSample, RssSampler, Target, cumulative_cpu_times,
    current_rss_bytes,
};
pub use scrape::{Bucket, Histogram, MetricsSnapshot};

/// Current evidence-schema version.
///
/// Bump this whenever the on-disk shape of [`EvidenceReport`] changes in a way consumers must notice.
/// It is serialized as the top-level `version` field of every `report.json`, so external tooling and
/// the baseline-diff helper can detect format drift. Reports are deserialized leniently (every added
/// section defaults via `#[serde(default)]`), so an *older-but-compatible* report still loads.
///
/// - `1` — the original scaffold: metadata, host, CPU, memory, storage, throughput.
/// - `2` — adds the top-level [`measurement_mode`](EvidenceReport::measurement_mode)
///   ([`MeasurementMode`]) and the optional server-side [`ServerMetricsSection`]
///   ([`server_metrics`](EvidenceReport::server_metrics)) scraped from `/metrics` (`rmp #684`). Both
///   are additive `#[serde(default)]` fields, so a v1 `report.json` still deserializes.
pub const SCHEMA_VERSION: u32 = 2;

/// The size of the dataset an example exercised.
///
/// A small typed struct rather than a free map so the two figures every scenario reports — node and
/// relationship counts — have stable, comparable wire names, plus an optional `scale_factor` for
/// scenarios parameterised by an LDBC-style scale knob.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DatasetScale {
    /// Number of nodes the run loaded / operated over.
    pub nodes: u64,
    /// Number of relationships the run loaded / operated over.
    pub relationships: u64,
    /// Optional scenario scale factor (e.g. an LDBC SF). `None` when the scenario is not scaled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale_factor: Option<f64>,
}

impl DatasetScale {
    /// A dataset with the given node and relationship counts and no scale factor.
    #[must_use]
    pub fn new(nodes: u64, relationships: u64) -> Self {
        Self {
            nodes,
            relationships,
            scale_factor: None,
        }
    }

    /// Sets the scale factor (builder style).
    #[must_use]
    pub fn with_scale_factor(mut self, sf: f64) -> Self {
        self.scale_factor = Some(sf);
        self
    }
}

/// Identifying metadata for a single example run.
///
/// Captured once, at construction time, and echoed verbatim into both emitted reports so a piece of
/// evidence is always traceable back to *which scenario produced it, over what dataset, with which
/// knobs*. The host/environment is captured separately in [`HostInfo`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetadata {
    /// Stable scenario key for the example, e.g. `"fraud-oltp"` or `"social-network-uds"`. This is
    /// the join key the baseline-diff helper uses, so it MUST be stable across runs of the same
    /// scenario.
    pub scenario: String,
    /// A one-line human description of what the run demonstrates.
    pub description: String,
    /// The dataset the run exercised (node / relationship counts, optional scale factor).
    #[serde(default)]
    pub dataset: DatasetScale,
    /// The run's tunable knobs — clients, ops, duration, batch size, … — as a stable, ordered
    /// key→value map. A [`BTreeMap`] so JSON key order is deterministic across runs.
    #[serde(default)]
    pub workload: BTreeMap<String, String>,
    /// Wall-clock start time as a Unix timestamp in seconds. `0` until [`EvidenceCollector::start`].
    pub started_unix_secs: u64,
}

impl RunMetadata {
    /// Creates metadata for an example run keyed by its stable `scenario` id, with an empty dataset
    /// and no workload params. Add those with [`with_dataset`](Self::with_dataset) /
    /// [`workload_param`](Self::workload_param).
    pub fn new(scenario: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            scenario: scenario.into(),
            description: description.into(),
            dataset: DatasetScale::default(),
            workload: BTreeMap::new(),
            started_unix_secs: 0,
        }
    }

    /// Sets the dataset scale (builder style).
    #[must_use]
    pub fn with_dataset(mut self, dataset: DatasetScale) -> Self {
        self.dataset = dataset;
        self
    }

    /// Records one workload knob, e.g. `("clients", "16")` (builder style). Repeatable.
    #[must_use]
    pub fn workload_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.workload.insert(key.into(), value.into());
        self
    }
}

/// CPU-usage evidence for the run.
///
/// **Seam — filled in by `rmp #246`** (`getrusage(RUSAGE_SELF/RUSAGE_CHILDREN)`, `/proc/<pid>/stat`
/// sampling). Fields are present so example code can already reference the shape; they stay zeroed
/// until the metering lands.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuSection {
    /// User-mode CPU time consumed by the server process(es), in seconds.
    pub user_secs: f64,
    /// Kernel-mode CPU time consumed by the server process(es), in seconds.
    pub system_secs: f64,
    /// Mean CPU utilisation over the run as a fraction of one core (1.0 == one core saturated).
    pub mean_core_utilisation: f64,
}

/// Memory-usage evidence for the run.
///
/// **Seam — filled in by `rmp #246`** (peak RSS via `getrusage`/`/proc/<pid>/status`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemorySection {
    /// Peak resident set size of the server process, in bytes.
    pub peak_rss_bytes: u64,
    /// Resident set size sampled at the end of the run, in bytes.
    pub final_rss_bytes: u64,
}

/// Storage-footprint evidence for the run, including the classic amplification ratios.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageSection {
    /// Total on-disk size of the data store after the run, in bytes.
    pub store_bytes: u64,
    /// Total on-disk size of the write-ahead log after the run, in bytes.
    pub wal_bytes: u64,
    /// Equivalent whole-page count of the data store (`ceil(store_bytes / PAGE_SIZE)`).
    #[serde(default)]
    pub store_pages: u64,
    /// Equivalent whole-page count of the WAL (`ceil(wal_bytes / PAGE_SIZE)`).
    #[serde(default)]
    pub wal_pages: u64,
    /// Bytes physically `fsync`ed to durable media during the run, if measured.
    pub bytes_fsynced: u64,
    /// **Write amplification**: physical bytes written / logical bytes written. `0.0` when not
    /// measured (no logical figure supplied). `1.0` is ideal; `> 1.0` quantifies durability I/O
    /// overhead.
    #[serde(default)]
    pub write_amplification: f64,
    /// **Space amplification**: total on-disk bytes / logical graph size. `0.0` when not measured.
    /// `1.0` means the on-disk form equals the logical data size; `> 1.0` captures padding/slack.
    #[serde(default)]
    pub space_amplification: f64,
}

/// Throughput / latency evidence for the run.
///
/// **Seam — filled in by `rmp #247`** (operation counters + latency histograms).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThroughputSection {
    /// Total number of operations (queries / writes) executed during the run.
    pub operations: u64,
    /// Mean throughput in operations per second across the run.
    pub ops_per_sec: f64,
    /// 50th-percentile per-operation latency, in milliseconds.
    pub p50_latency_ms: f64,
    /// 99th-percentile per-operation latency, in milliseconds.
    pub p99_latency_ms: f64,
    /// 99.9th-percentile per-operation latency, in milliseconds.
    pub p999_latency_ms: f64,
    /// Transaction **abort / conflict rate** over the run, in `[0.0, 1.0]`: the fraction of
    /// concurrent write transactions the engine aborted (e.g. under Serializable Snapshot Isolation)
    /// rather than committed. `0.0` means "no aborts observed (or not a concurrent workload)".
    ///
    /// Additive field (`rmp #253`): older reports that predate it deserialize with `0.0` via
    /// `#[serde(default)]`, so the schema stays compatible at [`SCHEMA_VERSION`] `1`.
    #[serde(default)]
    pub abort_rate: f64,
}

/// Where a run's evidence was collected from — the top-level `measurement_mode` (`rmp #684`).
///
/// A **local** run boots (or shares a host with) the `graphus-server` it measures, so it can read
/// `/proc`, `getrusage`, and the on-disk store/WAL directly (the [`resource`]/[`metrics`] meters).
/// An **external** run targets a *remote* instance where those are inaccessible: its only server-side
/// evidence is the Prometheus `/metrics` endpoint, captured into the [`ServerMetricsSection`].
///
/// Serialized lowercase (`"local"` / `"external"`). Defaults to [`Local`](Self::Local) so a v1
/// report — which predates the field — deserializes to the historically-correct mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MeasurementMode {
    /// The server was measured on this host (full `/proc` + store-file access).
    #[default]
    Local,
    /// The server was measured over the network via `/metrics` only (no `/proc` / store access).
    External,
}

/// Server-side evidence scraped from the Prometheus `/metrics` endpoint, as **before → after**
/// deltas over the example's workload window (`rmp #684`).
///
/// This is the evidence the reliability/perf audits flagged as the single biggest gap: it is visible
/// **both** for a local server and for a remote instance where `/proc` and the store files cannot be
/// read. The db-scoped figures (committed/aborted/slow/query-duration) are attributed to a target
/// [`database`](Self::database) when Graphus exposes the per-database `graphus_db_*` family
/// (`rmp #463`); otherwise they fall back to the server-wide aggregate and [`scope_note`](Self::scope_note)
/// records the fallback. The process-wide reliability signals (panic/force-detach counters, the SSI
/// gauge) are always server-global.
///
/// Build it from two [`MetricsSnapshot`]s with [`from_snapshots`](Self::from_snapshots).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerMetricsSection {
    /// The database the db-scoped deltas are attributed to, or `None` when no per-database series
    /// existed and the figures are a server-wide aggregate (see [`scope_note`](Self::scope_note)).
    #[serde(default)]
    pub database: Option<String>,
    /// Transactions committed during the window (`transactions_committed_total` delta).
    #[serde(default)]
    pub transactions_committed: u64,
    /// Transactions aborted / rolled back during the window (`transactions_aborted_total` delta).
    #[serde(default)]
    pub transactions_aborted: u64,
    /// Abort / conflict rate over the window: `aborted / (committed + aborted)`, or `0.0` when the
    /// window committed and aborted nothing.
    #[serde(default)]
    pub abort_rate: f64,
    /// Queries exceeding the slow-query threshold during the window (`slow_queries_total` delta).
    #[serde(default)]
    pub slow_queries: u64,
    /// Statements caught panicking at the engine boundary during the window
    /// (`statement_panics_total` delta). On a healthy server this MUST be `0`.
    #[serde(default)]
    pub statement_panics: u64,
    /// Statement-recovery double-panics during the window (`engine_recovery_panics_total` delta).
    /// MUST be `0`.
    #[serde(default)]
    pub engine_recovery_panics: u64,
    /// Wedged engines force-detached during the window (`engine_force_detached_total` delta). MUST
    /// be `0`.
    #[serde(default)]
    pub engine_force_detached: u64,
    /// Force-detached zombies still believed to hold their store-open lock at the end of the run
    /// (`engine_force_detached_active` gauge). MUST be `0`.
    #[serde(default)]
    pub engine_force_detached_active: u64,
    /// Retained SSI conflict records **before** the workload (`ssi_tracked_transactions` gauge).
    #[serde(default)]
    pub ssi_tracked_before: u64,
    /// Retained SSI conflict records **after** the workload. A large residual after a quiescent
    /// window can signal a long-lived reader pinning the GC watermark (`rmp #591`).
    #[serde(default)]
    pub ssi_tracked_after: u64,
    /// Queries recorded in the query-duration histogram during the window (`_count` delta).
    #[serde(default)]
    pub query_count: u64,
    /// Mean query duration over the window, in **milliseconds** (`_sum` delta / `_count` delta).
    #[serde(default)]
    pub query_duration_mean_ms: f64,
    /// Approximate p50 query duration over the window, in **milliseconds**, from the histogram bucket
    /// deltas (Prometheus `histogram_quantile` interpolation).
    #[serde(default)]
    pub query_duration_p50_ms: f64,
    /// Approximate p99 query duration over the window, in **milliseconds**, from the histogram bucket
    /// deltas.
    #[serde(default)]
    pub query_duration_p99_ms: f64,
    /// A caveat recording any scope fallback (e.g. that no per-database series existed for the
    /// requested database, so the db-scoped figures are a server-wide aggregate). Empty when the
    /// per-database series were used directly.
    #[serde(default)]
    pub scope_note: String,
}

impl ServerMetricsSection {
    // -- Global series names ---------------------------------------------------------------------
    const COMMITTED: &'static str = "graphus_transactions_committed_total";
    const ABORTED: &'static str = "graphus_transactions_aborted_total";
    const SLOW: &'static str = "graphus_slow_queries_total";
    const QUERY_DURATION: &'static str = "graphus_query_duration_seconds";
    const STATEMENT_PANICS: &'static str = "graphus_statement_panics_total";
    const RECOVERY_PANICS: &'static str = "graphus_engine_recovery_panics_total";
    const FORCE_DETACHED: &'static str = "graphus_engine_force_detached_total";
    const FORCE_DETACHED_ACTIVE: &'static str = "graphus_engine_force_detached_active";
    const SSI_TRACKED: &'static str = "graphus_ssi_tracked_transactions";
    // -- Per-database series names ---------------------------------------------------------------
    const DB_COMMITTED: &'static str = "graphus_db_transactions_committed_total";
    const DB_ABORTED: &'static str = "graphus_db_transactions_aborted_total";
    const DB_SLOW: &'static str = "graphus_db_slow_queries_total";
    const DB_QUERY_DURATION: &'static str = "graphus_db_query_duration_seconds";

    /// Computes the server-side evidence as before → after deltas, attributed to `database`.
    ///
    /// The db-scoped figures (committed/aborted/slow/query-duration) use the per-database
    /// `graphus_db_*` series when `after` carries them for `database`; otherwise they fall back to the
    /// server-wide aggregate and [`scope_note`](Self::scope_note) records the fallback. The
    /// process-wide reliability signals are always taken from the global series. Counter deltas are
    /// clamped at `0` (Prometheus counters only increase); the SSI figures are the absolute gauge
    /// before and after.
    ///
    /// # Examples
    ///
    /// ```
    /// use graphus_examples_harness::{scrape, ServerMetricsSection};
    ///
    /// let before = scrape::parse("graphus_transactions_committed_total 10\n");
    /// let after = scrape::parse("graphus_transactions_committed_total 25\n");
    /// let section = ServerMetricsSection::from_snapshots(&before, &after, "graphus");
    /// assert_eq!(section.transactions_committed, 15);
    /// ```
    #[must_use]
    pub fn from_snapshots(
        before: &MetricsSnapshot,
        after: &MetricsSnapshot,
        database: &str,
    ) -> Self {
        let per_db = after.has_database(database);

        // db-scoped figures: per-database when available, else the server-wide aggregate.
        let (committed, aborted, slow, before_hist, after_hist, db_field, scope_note) = if per_db {
            (
                delta_u64(
                    before.db_scalar(database, Self::DB_COMMITTED),
                    after.db_scalar(database, Self::DB_COMMITTED),
                ),
                delta_u64(
                    before.db_scalar(database, Self::DB_ABORTED),
                    after.db_scalar(database, Self::DB_ABORTED),
                ),
                delta_u64(
                    before.db_scalar(database, Self::DB_SLOW),
                    after.db_scalar(database, Self::DB_SLOW),
                ),
                before.db_histogram(database, Self::DB_QUERY_DURATION),
                after.db_histogram(database, Self::DB_QUERY_DURATION),
                Some(database.to_string()),
                String::new(),
            )
        } else {
            (
                delta_u64(
                    before.scalar(Self::COMMITTED),
                    after.scalar(Self::COMMITTED),
                ),
                delta_u64(before.scalar(Self::ABORTED), after.scalar(Self::ABORTED)),
                delta_u64(before.scalar(Self::SLOW), after.scalar(Self::SLOW)),
                before.histogram(Self::QUERY_DURATION),
                after.histogram(Self::QUERY_DURATION),
                None,
                format!(
                    "no per-database series for {database:?}; committed/aborted/slow_queries/\
                     query_duration are server-wide aggregates across all databases"
                ),
            )
        };

        let total = committed + aborted;
        let abort_rate = if total > 0 {
            aborted as f64 / total as f64
        } else {
            0.0
        };

        // Query-duration histogram delta → count, mean, and interpolated percentiles (ms).
        let (query_count, mean_ms, p50_ms, p99_ms) = match after_hist {
            Some(after_h) => {
                let delta = after_h.delta(before_hist);
                let count = delta.count.max(0.0).round() as u64;
                let mean_ms = if delta.count > 0.0 {
                    delta.sum / delta.count * 1_000.0
                } else {
                    0.0
                };
                (
                    count,
                    mean_ms,
                    delta.quantile(0.50) * 1_000.0,
                    delta.quantile(0.99) * 1_000.0,
                )
            }
            None => (0, 0.0, 0.0, 0.0),
        };

        Self {
            database: db_field,
            transactions_committed: committed,
            transactions_aborted: aborted,
            abort_rate,
            slow_queries: slow,
            // Process-wide reliability signals are always global (no per-database breakdown exists).
            statement_panics: delta_u64(
                before.scalar(Self::STATEMENT_PANICS),
                after.scalar(Self::STATEMENT_PANICS),
            ),
            engine_recovery_panics: delta_u64(
                before.scalar(Self::RECOVERY_PANICS),
                after.scalar(Self::RECOVERY_PANICS),
            ),
            engine_force_detached: delta_u64(
                before.scalar(Self::FORCE_DETACHED),
                after.scalar(Self::FORCE_DETACHED),
            ),
            engine_force_detached_active: gauge_u64(after.scalar(Self::FORCE_DETACHED_ACTIVE)),
            ssi_tracked_before: gauge_u64(before.scalar(Self::SSI_TRACKED)),
            ssi_tracked_after: gauge_u64(after.scalar(Self::SSI_TRACKED)),
            query_count,
            query_duration_mean_ms: mean_ms,
            query_duration_p50_ms: p50_ms,
            query_duration_p99_ms: p99_ms,
            scope_note,
        }
    }
}

/// A non-negative counter delta `after - before` (treating an absent series as `0`), rounded to a
/// `u64`. Clamped at `0` because Prometheus counters only increase and a scrape gap must not underflow.
fn delta_u64(before: Option<f64>, after: Option<f64>) -> u64 {
    let before = before.unwrap_or(0.0);
    let after = after.unwrap_or(0.0);
    (after - before).max(0.0).round() as u64
}

/// The absolute value of a gauge series (absent ⇒ `0`), rounded to a `u64`.
fn gauge_u64(value: Option<f64>) -> u64 {
    value.unwrap_or(0.0).max(0.0).round() as u64
}

/// A single named phase of the scenario together with its measured wall-clock duration.
///
/// Phase timing is the one metric the scaffold records itself today (via
/// [`EvidenceCollector::phase`]); the richer per-phase resource attribution is `rmp #246`/`#247`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseTiming {
    /// Human label for the phase, e.g. `"insert social graph"`.
    pub name: String,
    /// Wall-clock duration of the phase, in milliseconds.
    pub millis: f64,
}

/// The complete, serializable evidence produced by one example run — the **stable, versioned
/// schema** documented at the crate root.
///
/// Emitted as `report.json` (machine-readable) and `report.md` (human-readable) by
/// [`EvidenceReport::write_to`]. The leading [`version`](Self::version) field
/// ([`SCHEMA_VERSION`]) lets consumers detect format drift; every section deserializes leniently
/// (`#[serde(default)]`) so an older-but-compatible report still loads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReport {
    /// Evidence-schema version ([`SCHEMA_VERSION`]). The first field so it is easy to grep/parse.
    pub version: u32,
    /// Identifying metadata for the run (scenario, dataset, workload).
    pub metadata: RunMetadata,
    /// Host / environment the run executed on (os, arch, cpu cores, hostname, rustc, timestamp).
    #[serde(default)]
    pub host: HostInfo,
    /// Total wall-clock duration of the run between `start()` and `finish()`, in milliseconds.
    pub total_millis: f64,
    /// Per-phase wall-clock timings, in the order phases were recorded.
    pub phases: Vec<PhaseTiming>,
    /// CPU evidence.
    pub cpu: CpuSection,
    /// Peak / final memory (RSS) evidence.
    pub memory: MemorySection,
    /// Storage footprint + amplification evidence.
    pub storage: StorageSection,
    /// Throughput + latency-percentile evidence.
    pub throughput: ThroughputSection,
    /// Where this run's server-side evidence was collected from — **local** (this host) or
    /// **external** (a remote instance via `/metrics` only). Additive field (`rmp #684`,
    /// [`SCHEMA_VERSION`] `2`); a v1 report defaults it to [`MeasurementMode::Local`].
    #[serde(default)]
    pub measurement_mode: MeasurementMode,
    /// Server-side `/metrics` evidence (before → after deltas), when the example scraped it.
    /// Additive field (`rmp #684`, [`SCHEMA_VERSION`] `2`); absent in v1 reports and omitted from the
    /// JSON when not collected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_metrics: Option<ServerMetricsSection>,
    /// Free-form notes carried into the report (scenario-specific observations, proxy caveats, …).
    #[serde(default)]
    pub notes: Vec<String>,
}

impl EvidenceReport {
    /// File name of the machine-readable report written into the evidence directory.
    pub const JSON_FILE: &'static str = "report.json";
    /// File name of the human-readable report written into the evidence directory.
    pub const MARKDOWN_FILE: &'static str = "report.md";

    /// Writes both reports (`report.json` + `report.md`) into `dir`, creating it if needed.
    ///
    /// Returns the paths of the two files written, in `(json, markdown)` order.
    ///
    /// # Errors
    ///
    /// Returns any I/O error from creating the directory or writing either file, and propagates a
    /// `serde_json` serialization error (surfaced as [`io::ErrorKind::InvalidData`]).
    pub fn write_to(&self, dir: impl AsRef<Path>) -> io::Result<(PathBuf, PathBuf)> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;

        let json_path = dir.join(Self::JSON_FILE);
        std::fs::write(&json_path, self.to_json()?)?;

        let md_path = dir.join(Self::MARKDOWN_FILE);
        std::fs::write(&md_path, self.to_markdown())?;

        Ok((json_path, md_path))
    }

    /// Serializes the report to pretty-printed JSON with stable (struct-declaration) key order.
    ///
    /// # Errors
    ///
    /// Propagates a `serde_json` serialization error as [`io::ErrorKind::InvalidData`].
    pub fn to_json(&self) -> io::Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Loads an [`EvidenceReport`] from a `report.json` file on disk (e.g. a committed baseline).
    ///
    /// # Errors
    ///
    /// Returns any I/O error from reading the file, and a `serde_json` parse error (surfaced as
    /// [`io::ErrorKind::InvalidData`]) if the contents are not a valid report.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Compares this run against `baseline`, flagging a regression when any key metric degrades
    /// beyond `thresholds`. See [`diff`] for the rule and the metrics covered.
    #[must_use]
    pub fn compare_to_baseline(
        &self,
        baseline: &EvidenceReport,
        thresholds: &RegressionThresholds,
    ) -> ComparisonReport {
        diff::compare(baseline, self, thresholds)
    }

    /// Renders the human-readable Markdown report: a header (scenario, dataset, host), the workload
    /// knobs, phase timings, and one table per performance vector (CPU / memory / storage+amp /
    /// throughput+latency).
    fn to_markdown(&self) -> String {
        use std::fmt::Write as _;

        let m = &self.metadata;
        let h = &self.host;
        let mut s = String::with_capacity(2048);

        let _ = writeln!(s, "# Evidence — {}", m.scenario);
        let _ = writeln!(s);
        let _ = writeln!(s, "_{}_", m.description);
        let _ = writeln!(s);
        let _ = writeln!(s, "- Schema version: `{}`", self.version);
        let _ = writeln!(
            s,
            "- Measurement mode: `{}`",
            match self.measurement_mode {
                MeasurementMode::Local => "local",
                MeasurementMode::External => "external",
            }
        );
        let _ = writeln!(
            s,
            "- Dataset: `{}` nodes, `{}` relationships{}",
            m.dataset.nodes,
            m.dataset.relationships,
            match m.dataset.scale_factor {
                Some(sf) => format!(" (scale factor `{sf}`)"),
                None => String::new(),
            }
        );
        let _ = writeln!(
            s,
            "- Host: `{}` on `{}/{}`, `{}` cores",
            h.hostname, h.os, h.arch, h.cpu_cores
        );
        let _ = writeln!(s, "- Toolchain: `{}`", h.rustc_version);
        let _ = writeln!(s, "- Timestamp (unix): `{}`", h.timestamp_unix_secs);
        let _ = writeln!(s, "- Total wall-clock: `{:.3} ms`", self.total_millis);
        let _ = writeln!(s);

        if !m.workload.is_empty() {
            let _ = writeln!(s, "## Workload");
            let _ = writeln!(s);
            let _ = writeln!(s, "| Knob | Value |");
            let _ = writeln!(s, "|------|-------|");
            for (k, v) in &m.workload {
                let _ = writeln!(s, "| {k} | {v} |");
            }
            let _ = writeln!(s);
        }

        let _ = writeln!(s, "## Phase timings");
        let _ = writeln!(s);
        let _ = writeln!(s, "| Phase | Duration (ms) |");
        let _ = writeln!(s, "|-------|---------------|");
        for p in &self.phases {
            let _ = writeln!(s, "| {} | {:.3} |", p.name, p.millis);
        }
        let _ = writeln!(s);

        let _ = writeln!(s, "## CPU");
        let _ = writeln!(s);
        let _ = writeln!(s, "| Metric | Value |");
        let _ = writeln!(s, "|--------|-------|");
        let _ = writeln!(s, "| user (s) | {:.3} |", self.cpu.user_secs);
        let _ = writeln!(s, "| system (s) | {:.3} |", self.cpu.system_secs);
        let _ = writeln!(
            s,
            "| mean core utilisation | {:.3} |",
            self.cpu.mean_core_utilisation
        );
        let _ = writeln!(s);

        let _ = writeln!(s, "## Memory");
        let _ = writeln!(s);
        let _ = writeln!(s, "| Metric | Value |");
        let _ = writeln!(s, "|--------|-------|");
        let _ = writeln!(s, "| peak RSS (bytes) | {} |", self.memory.peak_rss_bytes);
        let _ = writeln!(s, "| final RSS (bytes) | {} |", self.memory.final_rss_bytes);
        let _ = writeln!(s);

        let _ = writeln!(s, "## Storage");
        let _ = writeln!(s);
        let _ = writeln!(s, "| Metric | Value |");
        let _ = writeln!(s, "|--------|-------|");
        let _ = writeln!(s, "| store (bytes) | {} |", self.storage.store_bytes);
        let _ = writeln!(s, "| store (pages) | {} |", self.storage.store_pages);
        let _ = writeln!(s, "| WAL (bytes) | {} |", self.storage.wal_bytes);
        let _ = writeln!(s, "| WAL (pages) | {} |", self.storage.wal_pages);
        let _ = writeln!(s, "| fsynced (bytes) | {} |", self.storage.bytes_fsynced);
        let _ = writeln!(
            s,
            "| write amplification | {:.3} |",
            self.storage.write_amplification
        );
        let _ = writeln!(
            s,
            "| space amplification | {:.3} |",
            self.storage.space_amplification
        );
        let _ = writeln!(s);

        let _ = writeln!(s, "## Throughput & latency");
        let _ = writeln!(s);
        let _ = writeln!(s, "| Metric | Value |");
        let _ = writeln!(s, "|--------|-------|");
        let _ = writeln!(s, "| operations | {} |", self.throughput.operations);
        let _ = writeln!(s, "| ops/sec | {:.3} |", self.throughput.ops_per_sec);
        let _ = writeln!(
            s,
            "| p50 latency (ms) | {:.3} |",
            self.throughput.p50_latency_ms
        );
        let _ = writeln!(
            s,
            "| p99 latency (ms) | {:.3} |",
            self.throughput.p99_latency_ms
        );
        let _ = writeln!(
            s,
            "| p999 latency (ms) | {:.3} |",
            self.throughput.p999_latency_ms
        );
        let _ = writeln!(
            s,
            "| abort / conflict rate | {:.3} |",
            self.throughput.abort_rate
        );
        let _ = writeln!(s);

        if let Some(sm) = &self.server_metrics {
            let _ = writeln!(s, "## Server metrics (/metrics deltas)");
            let _ = writeln!(s);
            let _ = writeln!(
                s,
                "- Scope: {}",
                match &sm.database {
                    Some(db) => format!("database `{db}`"),
                    None => "server-wide aggregate".to_string(),
                }
            );
            if !sm.scope_note.is_empty() {
                let _ = writeln!(s, "- Note: {}", sm.scope_note);
            }
            let _ = writeln!(s);
            let _ = writeln!(s, "| Metric | Value |");
            let _ = writeln!(s, "|--------|-------|");
            let _ = writeln!(
                s,
                "| transactions committed | {} |",
                sm.transactions_committed
            );
            let _ = writeln!(s, "| transactions aborted | {} |", sm.transactions_aborted);
            let _ = writeln!(s, "| abort / conflict rate | {:.3} |", sm.abort_rate);
            let _ = writeln!(s, "| slow queries | {} |", sm.slow_queries);
            let _ = writeln!(s, "| statement panics | {} |", sm.statement_panics);
            let _ = writeln!(
                s,
                "| engine recovery panics | {} |",
                sm.engine_recovery_panics
            );
            let _ = writeln!(
                s,
                "| engine force-detached | {} |",
                sm.engine_force_detached
            );
            let _ = writeln!(
                s,
                "| engine force-detached (active) | {} |",
                sm.engine_force_detached_active
            );
            let _ = writeln!(s, "| SSI tracked (before) | {} |", sm.ssi_tracked_before);
            let _ = writeln!(s, "| SSI tracked (after) | {} |", sm.ssi_tracked_after);
            let _ = writeln!(s, "| query count | {} |", sm.query_count);
            let _ = writeln!(
                s,
                "| query duration mean (ms) | {:.3} |",
                sm.query_duration_mean_ms
            );
            let _ = writeln!(
                s,
                "| query duration p50 (ms) | {:.3} |",
                sm.query_duration_p50_ms
            );
            let _ = writeln!(
                s,
                "| query duration p99 (ms) | {:.3} |",
                sm.query_duration_p99_ms
            );
            let _ = writeln!(s);
        }

        if !self.notes.is_empty() {
            let _ = writeln!(s, "## Notes");
            let _ = writeln!(s);
            for n in &self.notes {
                let _ = writeln!(s, "- {n}");
            }
        }
        s
    }
}

/// Entry point that drives an example run and accumulates an [`EvidenceReport`].
///
/// Construct it with the run's [`RunMetadata`], bracket the scenario with [`start`] /
/// [`finish`], record phases with [`phase`], and populate the typed sections directly via the
/// `*_mut` accessors as the follow-up metering tasks come online.
///
/// [`start`]: EvidenceCollector::start
/// [`finish`]: EvidenceCollector::finish
/// [`phase`]: EvidenceCollector::phase
#[derive(Debug)]
pub struct EvidenceCollector {
    report: EvidenceReport,
    started: Option<Instant>,
}

impl EvidenceCollector {
    /// Creates a collector for a run described by `metadata`.
    ///
    /// No timing begins and no metric is sampled until [`start`](Self::start) is called.
    pub fn new(metadata: RunMetadata) -> Self {
        Self {
            report: EvidenceReport {
                version: SCHEMA_VERSION,
                metadata,
                host: HostInfo::detect(),
                total_millis: 0.0,
                phases: Vec::new(),
                cpu: CpuSection::default(),
                memory: MemorySection::default(),
                storage: StorageSection::default(),
                throughput: ThroughputSection::default(),
                measurement_mode: MeasurementMode::default(),
                server_metrics: None,
                notes: Vec::new(),
            },
            started: None,
        }
    }

    /// Marks the start of the run: records the wall-clock origin and stamps the start time.
    pub fn start(&mut self) {
        self.started = Some(Instant::now());
        self.report.metadata.started_unix_secs = unix_now_secs();
    }

    /// Mutable access to the run metadata, e.g. to set the dataset/workload after construction.
    pub fn metadata_mut(&mut self) -> &mut RunMetadata {
        &mut self.report.metadata
    }

    /// Records a completed phase with its measured `duration`.
    ///
    /// A convenience over computing `Instant::elapsed()` at the call site; example code typically
    /// snapshots an `Instant` before a phase and passes the elapsed `Duration` here.
    pub fn phase(&mut self, name: impl Into<String>, duration: Duration) {
        self.report.phases.push(PhaseTiming {
            name: name.into(),
            millis: duration.as_secs_f64() * 1_000.0,
        });
    }

    /// Mutable access to the CPU section, for `rmp #246` to populate.
    pub fn cpu_mut(&mut self) -> &mut CpuSection {
        &mut self.report.cpu
    }

    /// Mutable access to the memory section, for `rmp #246` to populate.
    pub fn memory_mut(&mut self) -> &mut MemorySection {
        &mut self.report.memory
    }

    /// Records the CPU + memory evidence produced by a finished [`ResourceMeter`].
    ///
    /// Brackets a workload with [`ResourceMeter::start`], sample RSS at chosen points, then pass the
    /// `(CpuSection, MemorySection)` from [`ResourceMeter::finish`] here to populate both seams.
    pub fn record_resources(&mut self, sections: (CpuSection, MemorySection)) {
        let (cpu, memory) = sections;
        self.report.cpu = cpu;
        self.report.memory = memory;
    }

    /// Records the on-disk storage evidence by measuring the example's store and WAL paths.
    ///
    /// `bytes_fsynced` honestly reports what the caller observed forced to durable media. When an
    /// example cannot instrument fsync directly, pass `None`: the measured WAL byte count is used as
    /// the faithful proxy (every committed WAL byte is fsynced before a commit is acknowledged), and
    /// a note records that this is a proxy rather than a directly-observed counter.
    ///
    /// # Errors
    ///
    /// Propagates any I/O error from walking the store or WAL path (a missing path is treated as a
    /// zero footprint, not an error).
    pub fn record_storage(
        &mut self,
        store_path: impl AsRef<Path>,
        wal_path: impl AsRef<Path>,
        bytes_fsynced: Option<u64>,
    ) -> io::Result<()> {
        let (store, wal) = StorageMeter::measure(store_path, wal_path)?;
        let fsynced = match bytes_fsynced {
            Some(b) => b,
            None => {
                self.report.notes.push(
                    "storage.bytes_fsynced is a proxy: the WAL on-disk byte count (every committed \
                     WAL byte is fsynced before commit acknowledgement), not a directly-observed \
                     fsync counter."
                        .to_string(),
                );
                wal.bytes
            }
        };
        self.report.storage = StorageSection::from_footprints(store, wal, fsynced);
        Ok(())
    }

    /// Records the storage amplification ratios from the logical figures the example tracked.
    ///
    /// Call **after** [`record_storage`](Self::record_storage): write amplification is derived from
    /// the measured physical store+WAL bytes against `logical_bytes_written`, and space amplification
    /// from the on-disk store+WAL total against `logical_graph_bytes`. Passing `0` for a logical
    /// figure leaves the corresponding ratio at `0.0` (meaning "not measured").
    pub fn record_amplification(&mut self, logical_bytes_written: u64, logical_graph_bytes: u64) {
        let physical = self
            .report
            .storage
            .store_bytes
            .saturating_add(self.report.storage.wal_bytes);
        self.report.storage.write_amplification =
            StorageMeter::write_amplification(physical, logical_bytes_written);
        self.report.storage.space_amplification =
            StorageMeter::space_amplification(physical, logical_graph_bytes);
    }

    /// Records the throughput + latency evidence from a finished
    /// [`metrics::ThroughputCounter`] and [`metrics::LatencyCollector`].
    ///
    /// Latency percentiles (p50/p99/p999) are emitted in milliseconds. The throughput window is the
    /// one the counter measured (call [`ThroughputCounter::stop`](metrics::ThroughputCounter::stop)
    /// first); for a deterministic injected window use
    /// [`record_throughput_over`](Self::record_throughput_over).
    pub fn record_throughput(
        &mut self,
        throughput: &metrics::ThroughputCounter,
        latency: &metrics::LatencyCollector,
    ) {
        self.report.throughput = ThroughputSection::from_collectors(throughput, latency);
    }

    /// Like [`record_throughput`](Self::record_throughput) but with an **injected** throughput
    /// `window` — the deterministic / DST-friendly path.
    pub fn record_throughput_over(
        &mut self,
        throughput: &metrics::ThroughputCounter,
        latency: &metrics::LatencyCollector,
        window: Duration,
    ) {
        self.report.throughput =
            ThroughputSection::from_collectors_over(throughput, latency, window);
    }

    /// Sets where this run's evidence was collected from ([`MeasurementMode::Local`] /
    /// [`External`](MeasurementMode::External)). Defaults to [`Local`](MeasurementMode::Local).
    pub fn set_measurement_mode(&mut self, mode: MeasurementMode) {
        self.report.measurement_mode = mode;
    }

    /// Records a pre-computed server-side [`ServerMetricsSection`] onto the report.
    pub fn record_server_metrics(&mut self, section: ServerMetricsSection) {
        self.report.server_metrics = Some(section);
    }

    /// Computes and records the server-side `/metrics` evidence from two [`MetricsSnapshot`]s (scraped
    /// before and after the workload), attributed to `database`. A convenience over
    /// [`ServerMetricsSection::from_snapshots`] + [`record_server_metrics`](Self::record_server_metrics).
    pub fn record_server_metrics_from(
        &mut self,
        before: &MetricsSnapshot,
        after: &MetricsSnapshot,
        database: &str,
    ) {
        self.report.server_metrics = Some(ServerMetricsSection::from_snapshots(
            before, after, database,
        ));
    }

    /// Mutable access to the storage section, for `rmp #247` to populate.
    pub fn storage_mut(&mut self) -> &mut StorageSection {
        &mut self.report.storage
    }

    /// Mutable access to the throughput section, for `rmp #247` to populate.
    pub fn throughput_mut(&mut self) -> &mut ThroughputSection {
        &mut self.report.throughput
    }

    /// Appends a free-form note to the report (e.g. a scenario-specific observation).
    pub fn note(&mut self, note: impl Into<String>) {
        self.report.notes.push(note.into());
    }

    /// Closes the run, finalising the total wall-clock duration, and yields the [`EvidenceReport`].
    ///
    /// If [`start`](Self::start) was never called, the total duration is left at zero.
    pub fn finish(mut self) -> EvidenceReport {
        if let Some(t0) = self.started {
            self.report.total_millis = t0.elapsed().as_secs_f64() * 1_000.0;
        }
        self.report
    }
}

/// Current Unix time in whole seconds, or `0` if the clock is before the epoch (never, in practice).
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata() -> RunMetadata {
        RunMetadata::new("smoke-evidence", "scaffold smoke test")
            .with_dataset(DatasetScale::new(10, 20))
            .workload_param("clients", "4")
    }

    /// Builds a fully-populated report so the schema round-trip and emitter tests exercise every
    /// documented field rather than zeros.
    fn fully_populated_report() -> EvidenceReport {
        let mut c = EvidenceCollector::new(sample_metadata());
        c.start();
        c.phase("load", Duration::from_millis(5));
        c.phase("query", Duration::from_millis(10));
        *c.cpu_mut() = CpuSection {
            user_secs: 1.5,
            system_secs: 0.5,
            mean_core_utilisation: 0.8,
        };
        *c.memory_mut() = MemorySection {
            peak_rss_bytes: 256 * 1024 * 1024,
            final_rss_bytes: 200 * 1024 * 1024,
        };
        *c.storage_mut() = StorageSection {
            store_bytes: 81_920,
            wal_bytes: 16_384,
            store_pages: 10,
            wal_pages: 2,
            bytes_fsynced: 16_384,
            write_amplification: 1.2,
            space_amplification: 1.5,
        };
        *c.throughput_mut() = ThroughputSection {
            operations: 100_000,
            ops_per_sec: 50_000.0,
            p50_latency_ms: 0.2,
            p99_latency_ms: 1.1,
            p999_latency_ms: 3.4,
            abort_rate: 0.05,
        };
        c.set_measurement_mode(MeasurementMode::External);
        c.record_server_metrics(ServerMetricsSection {
            database: Some("graphus".to_string()),
            transactions_committed: 190,
            transactions_aborted: 5,
            abort_rate: 5.0 / 195.0,
            slow_queries: 0,
            statement_panics: 0,
            engine_recovery_panics: 0,
            engine_force_detached: 0,
            engine_force_detached_active: 0,
            ssi_tracked_before: 12,
            ssi_tracked_after: 190,
            query_count: 46,
            query_duration_mean_ms: 0.488,
            query_duration_p50_ms: 0.3,
            query_duration_p99_ms: 2.1,
            scope_note: String::new(),
        });
        c.note("fully populated for the schema test");
        c.finish()
    }

    #[test]
    fn collector_records_phases_and_total() {
        let mut c = EvidenceCollector::new(sample_metadata());
        c.start();
        c.phase("warmup", Duration::from_millis(5));
        c.phase("work", Duration::from_millis(10));
        let report = c.finish();

        assert_eq!(report.phases.len(), 2);
        assert_eq!(report.phases[0].name, "warmup");
        assert!((report.phases[1].millis - 10.0).abs() < 1e-6);
        // total is wall-clock between start/finish; non-negative and at least registers as elapsed.
        assert!(report.total_millis >= 0.0);
    }

    #[test]
    fn report_carries_schema_version_and_host() {
        let report = EvidenceCollector::new(sample_metadata()).finish();
        assert_eq!(report.version, SCHEMA_VERSION);
        // Host/env is auto-detected and non-empty on the supported platforms.
        assert!(!report.host.os.is_empty());
        assert!(!report.host.arch.is_empty());
        assert!(report.host.cpu_cores >= 1);
    }

    #[test]
    fn sections_default_to_zero() {
        let report = EvidenceCollector::new(sample_metadata()).finish();
        assert_eq!(report.cpu.user_secs, 0.0);
        assert_eq!(report.memory.peak_rss_bytes, 0);
        assert_eq!(report.storage.store_bytes, 0);
        assert_eq!(report.storage.write_amplification, 0.0);
        assert_eq!(report.throughput.operations, 0);
    }

    #[test]
    fn schema_round_trips_with_all_fields_present() {
        let report = fully_populated_report();
        // serialize -> deserialize must reproduce an EQUAL struct.
        let json = report.to_json().expect("serialize");
        let parsed: EvidenceReport = serde_json::from_str(&json).expect("deserialize");

        // Every documented section survives the round-trip with its values intact.
        assert_eq!(parsed.version, report.version);
        assert_eq!(parsed.metadata.scenario, report.metadata.scenario);
        assert_eq!(parsed.metadata.dataset, report.metadata.dataset);
        assert_eq!(parsed.metadata.workload, report.metadata.workload);
        assert_eq!(parsed.host, report.host);
        assert_eq!(parsed.cpu.user_secs, report.cpu.user_secs);
        assert_eq!(parsed.memory.peak_rss_bytes, report.memory.peak_rss_bytes);
        assert_eq!(parsed.storage.store_pages, report.storage.store_pages);
        assert_eq!(
            parsed.storage.write_amplification,
            report.storage.write_amplification
        );
        assert_eq!(parsed.throughput.ops_per_sec, report.throughput.ops_per_sec);
        // The v2 additions (`rmp #684`) survive the round-trip.
        assert_eq!(parsed.version, SCHEMA_VERSION);
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.measurement_mode, MeasurementMode::External);
        assert_eq!(parsed.server_metrics, report.server_metrics);
        let sm = parsed
            .server_metrics
            .as_ref()
            .expect("server_metrics present");
        assert_eq!(sm.database.as_deref(), Some("graphus"));
        assert_eq!(sm.transactions_committed, 190);
        assert_eq!(sm.statement_panics, 0);
        assert_eq!(sm.query_count, 46);

        // The documented top-level keys are all present in the JSON.
        for key in [
            "\"version\"",
            "\"metadata\"",
            "\"host\"",
            "\"cpu\"",
            "\"memory\"",
            "\"storage\"",
            "\"throughput\"",
            "\"measurement_mode\"",
            "\"server_metrics\"",
        ] {
            assert!(json.contains(key), "JSON must contain top-level {key}");
        }
        // Measurement mode serializes lowercase.
        assert!(json.contains("\"external\""));
    }

    #[test]
    fn older_compatible_report_still_loads() {
        // A genuine **v1** `report.json` — missing every field added after v1 (host, dataset,
        // workload, amplification, notes, AND the v2 `measurement_mode` + `server_metrics`) — must
        // still deserialize via `#[serde(default)]`. This is the versioned-but-lenient contract that
        // lets a v1 baseline load against the current (v2) schema.
        let v1 = r#"{
            "version": 1,
            "metadata": { "scenario": "legacy", "description": "old", "started_unix_secs": 1 },
            "total_millis": 1.0,
            "phases": [],
            "cpu": { "user_secs": 0.0, "system_secs": 0.0, "mean_core_utilisation": 0.0 },
            "memory": { "peak_rss_bytes": 0, "final_rss_bytes": 0 },
            "storage": { "store_bytes": 0, "wal_bytes": 0, "bytes_fsynced": 0 },
            "throughput": { "operations": 0, "ops_per_sec": 0.0,
                            "p50_latency_ms": 0.0, "p99_latency_ms": 0.0, "p999_latency_ms": 0.0 }
        }"#;
        let parsed: EvidenceReport = serde_json::from_str(v1).expect("lenient v1 deserialize");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.metadata.scenario, "legacy");
        assert_eq!(parsed.metadata.dataset, DatasetScale::default());
        assert!(parsed.metadata.workload.is_empty());
        assert_eq!(parsed.storage.store_pages, 0);
        assert_eq!(parsed.storage.write_amplification, 0.0);
        // The additive `abort_rate` (rmp #253) defaults to 0.0 when absent from an older report.
        assert_eq!(parsed.throughput.abort_rate, 0.0);
        // The v2 additions (rmp #684) default cleanly: mode is Local, and there is no server metrics.
        assert_eq!(parsed.measurement_mode, MeasurementMode::Local);
        assert!(parsed.server_metrics.is_none());
    }

    #[test]
    fn server_metrics_section_from_snapshots_computes_deltas() {
        // Two scrapes bracketing a workload window, with both per-database series and the global
        // reliability counters.
        let before = crate::scrape::parse(
            "graphus_transactions_committed_total 100\n\
             graphus_transactions_aborted_total 4\n\
             graphus_statement_panics_total 0\n\
             graphus_engine_force_detached_total 0\n\
             graphus_ssi_tracked_transactions 3\n\
             graphus_db_transactions_committed_total{database=\"graphus\"} 100\n\
             graphus_db_transactions_aborted_total{database=\"graphus\"} 4\n\
             graphus_db_slow_queries_total{database=\"graphus\"} 0\n\
             # TYPE graphus_db_query_duration_seconds histogram\n\
             graphus_db_query_duration_seconds_bucket{database=\"graphus\",le=\"0.001\"} 0\n\
             graphus_db_query_duration_seconds_bucket{database=\"graphus\",le=\"0.01\"} 0\n\
             graphus_db_query_duration_seconds_bucket{database=\"graphus\",le=\"+Inf\"} 0\n\
             graphus_db_query_duration_seconds_sum{database=\"graphus\"} 0.0\n\
             graphus_db_query_duration_seconds_count{database=\"graphus\"} 0\n",
        );
        let after = crate::scrape::parse(
            "graphus_transactions_committed_total 130\n\
             graphus_transactions_aborted_total 14\n\
             graphus_statement_panics_total 0\n\
             graphus_engine_force_detached_total 0\n\
             graphus_engine_force_detached_active 0\n\
             graphus_ssi_tracked_transactions 40\n\
             graphus_db_transactions_committed_total{database=\"graphus\"} 130\n\
             graphus_db_transactions_aborted_total{database=\"graphus\"} 14\n\
             graphus_db_slow_queries_total{database=\"graphus\"} 2\n\
             # TYPE graphus_db_query_duration_seconds histogram\n\
             graphus_db_query_duration_seconds_bucket{database=\"graphus\",le=\"0.001\"} 0\n\
             graphus_db_query_duration_seconds_bucket{database=\"graphus\",le=\"0.01\"} 10\n\
             graphus_db_query_duration_seconds_bucket{database=\"graphus\",le=\"+Inf\"} 10\n\
             graphus_db_query_duration_seconds_sum{database=\"graphus\"} 0.05\n\
             graphus_db_query_duration_seconds_count{database=\"graphus\"} 10\n",
        );

        let sm = ServerMetricsSection::from_snapshots(&before, &after, "graphus");
        assert_eq!(sm.database.as_deref(), Some("graphus"));
        assert!(sm.scope_note.is_empty(), "per-db series → no fallback note");
        // db-scoped deltas taken from the per-database series.
        assert_eq!(sm.transactions_committed, 30);
        assert_eq!(sm.transactions_aborted, 10);
        assert_eq!(sm.slow_queries, 2);
        // abort_rate = 10 / (30 + 10).
        assert!((sm.abort_rate - 0.25).abs() < 1e-12);
        // Global reliability signals stay zero on a healthy server.
        assert_eq!(sm.statement_panics, 0);
        assert_eq!(sm.engine_recovery_panics, 0);
        assert_eq!(sm.engine_force_detached, 0);
        assert_eq!(sm.engine_force_detached_active, 0);
        // SSI gauge captured before and after.
        assert_eq!(sm.ssi_tracked_before, 3);
        assert_eq!(sm.ssi_tracked_after, 40);
        // Query-duration histogram delta: 10 queries in (0.001, 0.01], sum 0.05s → mean 5ms.
        assert_eq!(sm.query_count, 10);
        assert!((sm.query_duration_mean_ms - 5.0).abs() < 1e-9);
        // p50 = 0.001 + 0.009 * (5/10) = 0.0055s = 5.5ms; p99 = 0.001 + 0.009*(9.9/10) = 9.91ms.
        assert!((sm.query_duration_p50_ms - 5.5).abs() < 1e-9);
        assert!((sm.query_duration_p99_ms - 9.91).abs() < 1e-9);
    }

    #[test]
    fn server_metrics_section_falls_back_to_aggregate_without_per_db_series() {
        // No `graphus_db_*` series: the section falls back to the server-wide counters and records
        // the fallback in `scope_note`, leaving `database` unset.
        let before = crate::scrape::parse("graphus_transactions_committed_total 10\n");
        let after = crate::scrape::parse("graphus_transactions_committed_total 25\n");
        let sm = ServerMetricsSection::from_snapshots(&before, &after, "graphus");
        assert_eq!(sm.database, None);
        assert!(sm.scope_note.contains("no per-database series"));
        assert_eq!(sm.transactions_committed, 15);
    }

    #[test]
    fn write_to_emits_report_json_and_markdown() {
        let dir = std::env::temp_dir().join(format!("graphus-harness-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let report = fully_populated_report();
        let (json_path, md_path) = report.write_to(&dir).expect("write evidence");

        // The canonical filenames are report.json / report.md.
        assert_eq!(json_path.file_name().unwrap(), "report.json");
        assert_eq!(md_path.file_name().unwrap(), "report.md");
        assert!(json_path.exists());
        assert!(md_path.exists());

        // The JSON round-trips, and the loader reads it back.
        let parsed = EvidenceReport::load(&json_path).expect("load report.json");
        assert_eq!(parsed.metadata.scenario, "smoke-evidence");
        assert_eq!(parsed.phases.len(), 2);

        let md = std::fs::read_to_string(&md_path).unwrap();
        assert!(md.contains("# Evidence — smoke-evidence"));
        assert!(md.contains("## CPU"));
        assert!(md.contains("## Storage"));
        assert!(md.contains("write amplification"));
        assert!(md.contains("## Throughput & latency"));
        // The v2 server-metrics table + measurement mode render (rmp #684).
        assert!(md.contains("- Measurement mode: `external`"));
        assert!(md.contains("## Server metrics (/metrics deltas)"));
        assert!(md.contains("| statement panics | 0 |"));
        assert!(md.contains("| transactions committed | 190 |"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
