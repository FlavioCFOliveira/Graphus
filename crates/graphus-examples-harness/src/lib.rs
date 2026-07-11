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
//! ## Measured, or absent — never a zero placeholder (`rmp #711`)
//!
//! Every metric in the four performance-vector sections is an **`Option`**, serialized with
//! `skip_serializing_if = "Option::is_none"`. A vector an example could not measure — the CPU/RSS of a
//! server it is only *attached* to, the on-disk footprint of a store it does not own, the per-operation
//! latency of a one-shot batch import — is therefore **absent from the JSON**, not written as `0.0`.
//!
//! This is the schema half of the project's evidence-honesty rule (`examples/README.md`): *measure it
//! or omit it — never a zero placeholder*. Before `rmp #711` the schema could not express "not
//! measured", so an unmeasured vector was emitted as an exact `0.0` that reads as a measurement —
//! `storage.bytes_per_node: 0.0` told every reader that a stored node costs nothing to keep. A gate
//! built on such a field compares `0.0` to `0.0` and can never fire, which is the same lie wearing a
//! green tick. The distinction the type now expresses is **"was it measured"**, not "is it zero": a
//! genuinely measured zero (an `abort_rate` of `0.0` in a write workload that suffered no conflict)
//! stays a real, present `0.0`.
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
/// - `3` — **every metric is `Option`** (`rmp #711`): a metric an example did not measure is now
///   **ABSENT** from the JSON instead of being written as a `0` / `0.0` placeholder that a reader
///   cannot tell apart from a real zero. See [`EvidenceReport::load`] for how a v1/v2 report's zero
///   placeholders are normalised on the way in.
pub const SCHEMA_VERSION: u32 = 3;

/// The schema version from which a metric an example did not measure is **absent** rather than zero.
const OPTIONAL_METRICS_SINCE: u32 = 3;

/// How an absent (= not measured) metric renders in the human-readable `report.md`. Deliberately a
/// phrase and not a number: a reader must never be shown a `0.000` for something nobody measured.
const NOT_MEASURED: &str = "not measured";

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
/// Populated from the [`resource`] meters (`getrusage`, `/proc/<pid>/stat`). Every field is an
/// `Option`: a run that could **not** meter a CPU (an external target, whose process is not on this
/// host) leaves them absent rather than reporting `0.0` seconds of work — see the crate docs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CpuSection {
    /// User-mode CPU time consumed by the server process(es), in seconds. Absent = not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_secs: Option<f64>,
    /// Kernel-mode CPU time consumed by the server process(es), in seconds. Absent = not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_secs: Option<f64>,
    /// Mean CPU utilisation over the run as a fraction of one core (1.0 == one core saturated).
    /// Absent = not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mean_core_utilisation: Option<f64>,
}

impl CpuSection {
    /// Total CPU seconds (user + system), or `None` when either half was not measured — the figure
    /// the baseline gate compares.
    #[must_use]
    pub fn total_secs(&self) -> Option<f64> {
        match (self.user_secs, self.system_secs) {
            (Some(u), Some(s)) => Some(u + s),
            _ => None,
        }
    }

    /// `true` when nothing at all was measured (the whole vector is N/A).
    #[must_use]
    pub fn is_unmeasured(&self) -> bool {
        self.user_secs.is_none()
            && self.system_secs.is_none()
            && self.mean_core_utilisation.is_none()
    }
}

/// Memory-usage evidence for the run.
///
/// Populated from the [`resource`] meters (peak RSS via `getrusage` / `/proc/<pid>/status`). Absent
/// fields mean **not measured** (e.g. an external target), never "zero bytes resident".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MemorySection {
    /// Peak resident set size of the server process, in bytes. Absent = not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_rss_bytes: Option<u64>,
    /// Resident set size sampled at the end of the run, in bytes. Absent = not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_rss_bytes: Option<u64>,
}

impl MemorySection {
    /// `true` when nothing at all was measured (the whole vector is N/A).
    #[must_use]
    pub fn is_unmeasured(&self) -> bool {
        self.peak_rss_bytes.is_none() && self.final_rss_bytes.is_none()
    }
}

/// Storage-footprint evidence for the run, including the classic amplification ratios and the
/// per-element durable costs.
///
/// Every field is an `Option` because every one of them is only *sometimes* measurable: an example
/// attached to a remote instance can read no store at all; an in-memory mirror has no WAL; a run that
/// tracks no logical byte count cannot form an amplification ratio; a run whose dataset scale is
/// unknown cannot form a per-element cost. **Absent means NOT MEASURED** — never "this graph costs
/// nothing to store".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StorageSection {
    /// Total on-disk size of the data store after the run, in bytes. Absent = not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_bytes: Option<u64>,
    /// Total on-disk size of the write-ahead log after the run, in bytes. Absent = not measured (the
    /// WAL is a *directory* of `seg.<lsn>` files; an in-memory mirror has none at all).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wal_bytes: Option<u64>,
    /// Equivalent whole-page count of the data store (`ceil(store_bytes / PAGE_SIZE)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_pages: Option<u64>,
    /// Equivalent whole-page count of the WAL (`ceil(wal_bytes / PAGE_SIZE)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wal_pages: Option<u64>,
    /// Bytes physically `fsync`ed to durable media during the run. Absent = not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_fsynced: Option<u64>,
    /// **Write amplification**: physical bytes written / logical bytes written. Absent when not
    /// measured (no logical figure supplied). `1.0` is ideal; `> 1.0` quantifies durability I/O
    /// overhead.
    ///
    /// This field carries an amplification RATIO and nothing else. An example that wants to report a
    /// per-element cost or a plateau ratio must use the dedicated fields below — smuggling a
    /// different quantity in here makes the reports incomparable and silently misleads any reader
    /// (or gate) that trusts the field name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_amplification: Option<f64>,
    /// **Space amplification**: total on-disk bytes / logical graph size. Absent when not measured.
    /// `1.0` means the on-disk form equals the logical data size; `> 1.0` captures padding/slack.
    ///
    /// A ratio, like [`write_amplification`](Self::write_amplification) — see the note there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_amplification: Option<f64>,
    /// **Durable bytes per stored node**: the measured durable **store image** divided by the number
    /// of nodes the run stored. A per-element COST, not a ratio — reported here rather than smuggled
    /// into an amplification field. Absent when the store footprint or the dataset scale was not
    /// measured; see [`EvidenceCollector::record_per_element_costs`].
    ///
    /// It amortises the **whole** store image (records + property blocks + token catalogs + free-list
    /// slack) over the node count, so it is *not* the size of one node record, and
    /// `bytes_per_node * nodes` does **not** decompose `store_bytes` — it and
    /// [`bytes_per_relationship`](Self::bytes_per_relationship) are two views of the same image. It is
    /// a deterministic, machine-independent footprint signal (it moves when the record layout, the
    /// slack, or the catalog growth moves), which is exactly what makes it worth gating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_per_node: Option<f64>,
    /// **Durable bytes per stored relationship** — the same amortisation of the measured store image
    /// over the relationship count. See [`bytes_per_node`](Self::bytes_per_node). Absent = not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_per_relationship: Option<f64>,
    /// For retention/GC workloads with a genuine **steady state**: the ratio of the store's largest
    /// post-warmup footprint to its smallest — how far the store grew beyond the plateau reclamation
    /// should hold it at. `1.0` = a flat plateau. Absent for every workload that has no steady state
    /// to observe (which is most of them); see [`EvidenceCollector::record_plateau_ratio`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plateau_ratio: Option<f64>,
}

impl StorageSection {
    /// `true` when nothing at all was measured (the whole vector is N/A).
    #[must_use]
    pub fn is_unmeasured(&self) -> bool {
        *self == Self::default()
    }
}

/// Throughput / latency evidence for the run.
///
/// Populated from the [`metrics`] collectors (operation counters + an exact latency sample), or from
/// the figures an example's own driver measured. Absent fields mean **not measured**: a one-shot
/// offline batch import has no per-operation request/response boundary to time, so its latency
/// percentiles are absent rather than `0.0` — a `0.0` would read as "instantaneous".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ThroughputSection {
    /// Total number of operations (queries / writes) executed during the run. Absent = not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<u64>,
    /// Mean throughput in operations per second across the run. Absent = not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ops_per_sec: Option<f64>,
    /// 50th-percentile per-operation latency, in milliseconds. Absent = not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p50_latency_ms: Option<f64>,
    /// 99th-percentile per-operation latency, in milliseconds. Absent = not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p99_latency_ms: Option<f64>,
    /// 99.9th-percentile per-operation latency, in milliseconds. Absent = not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p999_latency_ms: Option<f64>,
    /// Transaction **abort / conflict rate** over the run, in `[0.0, 1.0]`: the fraction of
    /// concurrent write transactions the engine aborted (e.g. under Serializable Snapshot Isolation)
    /// rather than committed.
    ///
    /// This is the one metric whose **zero is a real measurement**: a write workload that suffered no
    /// conflict genuinely has an abort rate of `0.0`, and that is worth reporting. It is therefore
    /// `Some(0.0)` when measured and `None` only when the run did not observe aborts at all (e.g. a
    /// pure read workload, or a driver that does not count them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort_rate: Option<f64>,
}

impl ThroughputSection {
    /// `true` when nothing at all was measured (the whole vector is N/A).
    #[must_use]
    pub fn is_unmeasured(&self) -> bool {
        *self == Self::default()
    }
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
    /// Queries recorded in the query-duration histogram during the window (`_count` delta). A real
    /// counter delta, so `0` here is measured: the window recorded no query in the histogram.
    #[serde(default)]
    pub query_count: u64,
    /// Mean query duration over the window, in **milliseconds** (`_sum` delta / `_count` delta).
    /// Absent when the window recorded no query (there is no mean of nothing) — never `0.0`, which
    /// would read as "every query was instantaneous".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_duration_mean_ms: Option<f64>,
    /// Approximate p50 query duration over the window, in **milliseconds**, from the histogram bucket
    /// deltas (Prometheus `histogram_quantile` interpolation). Absent = no query in the window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_duration_p50_ms: Option<f64>,
    /// Approximate p99 query duration over the window, in **milliseconds**, from the histogram bucket
    /// deltas. Absent = no query in the window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_duration_p99_ms: Option<f64>,
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

        // Query-duration histogram delta → count, mean, and interpolated percentiles (ms). With no
        // histogram (or an empty window) there is nothing to average: the three duration figures stay
        // ABSENT rather than becoming a `0.0` that reads as "instantaneous".
        let (query_count, mean_ms, p50_ms, p99_ms) = match after_hist {
            Some(after_h) => {
                let delta = after_h.delta(before_hist);
                let count = delta.count.max(0.0).round() as u64;
                if delta.count > 0.0 {
                    (
                        count,
                        Some(delta.sum / delta.count * 1_000.0),
                        Some(delta.quantile(0.50) * 1_000.0),
                        Some(delta.quantile(0.99) * 1_000.0),
                    )
                } else {
                    (count, None, None, None)
                }
            }
            None => (0, None, None, None),
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

/// A derived **ratio** — an amplification, a per-element durable cost, a plateau ratio — is evidence
/// only when it is finite and strictly positive.
///
/// None of them can legitimately be `0.0`: a stored element cannot occupy zero durable bytes, and a
/// real footprint cannot amplify a real workload by a factor of zero. A zero (or a `NaN` from a
/// division by an unmeasured denominator) therefore means **not measured**, and is recorded as
/// ABSENT rather than written into the report as a figure a reader would take for a measurement.
fn measured_ratio(v: f64) -> Option<f64> {
    (v.is_finite() && v > 0.0).then_some(v)
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
    /// A **v1 / v2** report (schema `< 3`) is normalised on the way in by
    /// [`normalize_legacy_zero_placeholders`](Self::normalize_legacy_zero_placeholders): those schemas
    /// had no way to say "not measured", so every unmeasured metric was written as a `0` / `0.0`
    /// placeholder. Loading it verbatim would let the baseline comparator treat that placeholder as a
    /// measurement — and gate a real candidate figure against it (a `0.0 → 1239.04` "+100% regression"
    /// against a number nobody ever measured).
    ///
    /// # Errors
    ///
    /// Returns any I/O error from reading the file, and a `serde_json` parse error (surfaced as
    /// [`io::ErrorKind::InvalidData`]) if the contents are not a valid report.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut report: Self = serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if report.version < OPTIONAL_METRICS_SINCE {
            report.normalize_legacy_zero_placeholders();
        }
        Ok(report)
    }

    /// Rewrites the **zero placeholders** of a pre-v3 report (see [`SCHEMA_VERSION`]) as what they
    /// always were: metrics that were **not measured**.
    ///
    /// Before schema `3` every metric was a bare `u64` / `f64`, so an example that could not measure a
    /// vector had no choice but to serialize a zero — `report.json` files from that era carry
    /// `bytes_per_node: 0.0`, `write_amplification: 0.0`, `store_bytes: 0`, `p50_latency_ms: 0.0` for
    /// vectors nothing ever metered. Every metric mapped here is one whose zero is **physically
    /// impossible for a real measurement**:
    ///
    /// * a live process cannot burn `0` CPU seconds or hold `0` bytes resident;
    /// * a stored graph cannot occupy `0` durable bytes, cost `0` bytes per node, or amplify by `0`;
    /// * a timed workload cannot run `0` operations at `0` ops/sec, and a completed operation cannot
    ///   take exactly `0.0 ms`.
    ///
    /// [`throughput.abort_rate`](ThroughputSection::abort_rate) is deliberately **excluded**: a write
    /// workload that suffered no conflict genuinely measures `0.0`, so treating that zero as "absent"
    /// would silently disarm a live regression gate.
    pub fn normalize_legacy_zero_placeholders(&mut self) {
        fn drop_zero_f64(v: &mut Option<f64>) {
            if v.is_some_and(|x| !(x.is_finite() && x > 0.0)) {
                *v = None;
            }
        }
        fn drop_zero_u64(v: &mut Option<u64>) {
            if v == &Some(0) {
                *v = None;
            }
        }

        let cpu = &mut self.cpu;
        drop_zero_f64(&mut cpu.user_secs);
        drop_zero_f64(&mut cpu.system_secs);
        drop_zero_f64(&mut cpu.mean_core_utilisation);

        let mem = &mut self.memory;
        drop_zero_u64(&mut mem.peak_rss_bytes);
        drop_zero_u64(&mut mem.final_rss_bytes);

        let st = &mut self.storage;
        drop_zero_u64(&mut st.store_bytes);
        drop_zero_u64(&mut st.wal_bytes);
        drop_zero_u64(&mut st.store_pages);
        drop_zero_u64(&mut st.wal_pages);
        drop_zero_u64(&mut st.bytes_fsynced);
        drop_zero_f64(&mut st.write_amplification);
        drop_zero_f64(&mut st.space_amplification);
        drop_zero_f64(&mut st.bytes_per_node);
        drop_zero_f64(&mut st.bytes_per_relationship);
        drop_zero_f64(&mut st.plateau_ratio);

        let tp = &mut self.throughput;
        drop_zero_u64(&mut tp.operations);
        drop_zero_f64(&mut tp.ops_per_sec);
        drop_zero_f64(&mut tp.p50_latency_ms);
        drop_zero_f64(&mut tp.p99_latency_ms);
        drop_zero_f64(&mut tp.p999_latency_ms);
        // `abort_rate` is NOT normalised: 0.0 is a real, measurable outcome (no conflicts).
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

        // An unmeasured metric renders as an explicit "not measured", never as a `0.000` a reader
        // would take for a result (`rmp #711` — the same rule the JSON enforces by omitting it).
        let f = |v: Option<f64>| v.map_or_else(|| NOT_MEASURED.to_string(), |x| format!("{x:.3}"));
        let u = |v: Option<u64>| v.map_or_else(|| NOT_MEASURED.to_string(), |x| x.to_string());

        let _ = writeln!(s, "## CPU");
        let _ = writeln!(s);
        let _ = writeln!(s, "| Metric | Value |");
        let _ = writeln!(s, "|--------|-------|");
        let _ = writeln!(s, "| user (s) | {} |", f(self.cpu.user_secs));
        let _ = writeln!(s, "| system (s) | {} |", f(self.cpu.system_secs));
        let _ = writeln!(
            s,
            "| mean core utilisation | {} |",
            f(self.cpu.mean_core_utilisation)
        );
        let _ = writeln!(s);

        let _ = writeln!(s, "## Memory");
        let _ = writeln!(s);
        let _ = writeln!(s, "| Metric | Value |");
        let _ = writeln!(s, "|--------|-------|");
        let _ = writeln!(
            s,
            "| peak RSS (bytes) | {} |",
            u(self.memory.peak_rss_bytes)
        );
        let _ = writeln!(
            s,
            "| final RSS (bytes) | {} |",
            u(self.memory.final_rss_bytes)
        );
        let _ = writeln!(s);

        let _ = writeln!(s, "## Storage");
        let _ = writeln!(s);
        let _ = writeln!(s, "| Metric | Value |");
        let _ = writeln!(s, "|--------|-------|");
        let _ = writeln!(s, "| store (bytes) | {} |", u(self.storage.store_bytes));
        let _ = writeln!(s, "| store (pages) | {} |", u(self.storage.store_pages));
        let _ = writeln!(s, "| WAL (bytes) | {} |", u(self.storage.wal_bytes));
        let _ = writeln!(s, "| WAL (pages) | {} |", u(self.storage.wal_pages));
        let _ = writeln!(s, "| fsynced (bytes) | {} |", u(self.storage.bytes_fsynced));
        let _ = writeln!(
            s,
            "| write amplification | {} |",
            f(self.storage.write_amplification)
        );
        let _ = writeln!(
            s,
            "| space amplification | {} |",
            f(self.storage.space_amplification)
        );
        let _ = writeln!(s, "| bytes per node | {} |", f(self.storage.bytes_per_node));
        let _ = writeln!(
            s,
            "| bytes per relationship | {} |",
            f(self.storage.bytes_per_relationship)
        );
        if let Some(p) = self.storage.plateau_ratio {
            let _ = writeln!(s, "| plateau ratio | {p:.3} |");
        }
        let _ = writeln!(s);

        let _ = writeln!(s, "## Throughput & latency");
        let _ = writeln!(s);
        let _ = writeln!(s, "| Metric | Value |");
        let _ = writeln!(s, "|--------|-------|");
        let _ = writeln!(s, "| operations | {} |", u(self.throughput.operations));
        let _ = writeln!(s, "| ops/sec | {} |", f(self.throughput.ops_per_sec));
        let _ = writeln!(
            s,
            "| p50 latency (ms) | {} |",
            f(self.throughput.p50_latency_ms)
        );
        let _ = writeln!(
            s,
            "| p99 latency (ms) | {} |",
            f(self.throughput.p99_latency_ms)
        );
        let _ = writeln!(
            s,
            "| p999 latency (ms) | {} |",
            f(self.throughput.p999_latency_ms)
        );
        let _ = writeln!(
            s,
            "| abort / conflict rate | {} |",
            f(self.throughput.abort_rate)
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
                "| query duration mean (ms) | {} |",
                f(sm.query_duration_mean_ms)
            );
            let _ = writeln!(
                s,
                "| query duration p50 (ms) | {} |",
                f(sm.query_duration_p50_ms)
            );
            let _ = writeln!(
                s,
                "| query duration p99 (ms) | {} |",
                f(sm.query_duration_p99_ms)
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
    /// Explicit workload duration, when the collector could not bracket the workload itself.
    total_override: Option<Duration>,
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
            total_override: None,
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
    /// A path that **does not exist** is not a zero footprint — it is a footprint that was **not
    /// measured**. Its figures are therefore left absent (and a note says so), rather than reporting
    /// `store_bytes: 0` for a store this run never had access to.
    ///
    /// # Errors
    ///
    /// Propagates any I/O error from walking the store or WAL path (a missing path is not an error —
    /// it is recorded as "not measured").
    pub fn record_storage(
        &mut self,
        store_path: impl AsRef<Path>,
        wal_path: impl AsRef<Path>,
        bytes_fsynced: Option<u64>,
    ) -> io::Result<()> {
        self.record_storage_at(store_path, wal_path, None, bytes_fsynced)
    }

    /// [`record_storage`](Self::record_storage), but with the WAL byte count supplied by the example
    /// instead of walked at emission time (`rmp` #712).
    ///
    /// # Why an override exists at all
    ///
    /// A **crash-recovery** example's load-bearing WAL figure is the redo log that existed **at the
    /// crash** — the bytes that carried the acknowledged commits and that recovery then replayed. By
    /// the time the report is emitted, the server has restarted, replayed, and begun checkpointing:
    /// walking the WAL directory *then* measures the post-recovery **residual**, which is a different
    /// quantity and a much smaller one. Reporting the residual under `wal_bytes` would tell the reader
    /// that a crash-recovery run's redo log cost a fraction of what it actually cost.
    ///
    /// So the example — which owns the store and measured the WAL *by path*, at the instant that
    /// matters, with the same walker — passes that measurement in. It is still a MEASUREMENT, taken at
    /// the only instant at which the quantity exists; it is not a fabrication, and the caller is
    /// obliged to state in a note which instant its figure describes.
    ///
    /// `wal_bytes = None` restores the emission-time walk (what every other example wants).
    ///
    /// # Errors
    ///
    /// Propagates any I/O error from walking the store or WAL path (a missing path is not an error —
    /// it is recorded as "not measured").
    pub fn record_storage_at(
        &mut self,
        store_path: impl AsRef<Path>,
        wal_path: impl AsRef<Path>,
        wal_bytes: Option<u64>,
        bytes_fsynced: Option<u64>,
    ) -> io::Result<()> {
        let store_path = store_path.as_ref();
        let wal_path = wal_path.as_ref();
        let store = StorageMeter::try_measure_path(store_path)?;
        // An example-supplied WAL byte count replaces the emission-time walk; the path is still
        // consulted, so a WAL that does not exist at all is still reported as "not measured".
        let walked = StorageMeter::try_measure_path(wal_path)?;
        let wal = match (wal_bytes, walked) {
            (Some(bytes), Some(_)) => Some(DiskFootprint::from_bytes(bytes)),
            (Some(_), None) | (None, None) => None,
            (None, Some(w)) => Some(w),
        };

        if store.is_none() {
            self.report.notes.push(format!(
                "storage.store_bytes / store_pages are NOT MEASURED (absent, not zero): the store \
                 path {} does not exist for this run.",
                store_path.display()
            ));
        }
        if wal.is_none() {
            self.report.notes.push(format!(
                "storage.wal_bytes / wal_pages are NOT MEASURED (absent, not zero): the WAL path {} \
                 does not exist for this run.",
                wal_path.display()
            ));
        }

        let fsynced = match (bytes_fsynced, wal) {
            (Some(b), _) => Some(b),
            (None, Some(wal)) => {
                self.report.notes.push(
                    "storage.bytes_fsynced is a proxy: the WAL on-disk byte count (every committed \
                     WAL byte is fsynced before commit acknowledgement), not a directly-observed \
                     fsync counter."
                        .to_string(),
                );
                Some(wal.bytes)
            }
            // No fsync counter AND no WAL to proxy it with: the figure was not measured.
            (None, None) => None,
        };
        self.report.storage = StorageSection::from_footprints(store, wal, fsynced);
        Ok(())
    }

    /// Records the storage amplification ratios from the logical figures the example tracked.
    ///
    /// Call **after** [`record_storage`](Self::record_storage): write amplification is derived from
    /// the measured physical store+WAL bytes against `logical_bytes_written`, and space amplification
    /// from the on-disk store+WAL total against `logical_graph_bytes`. Passing `0` for a logical
    /// figure (or calling this without a measured footprint) leaves the corresponding ratio **absent**
    /// — an unmeasurable ratio is omitted, never emitted as a `0.0` that reads like a measurement.
    pub fn record_amplification(&mut self, logical_bytes_written: u64, logical_graph_bytes: u64) {
        let s = &self.report.storage;
        // The physical figure needs at least one measured footprint; store or WAL alone is still an
        // honest lower bound, but with neither there is nothing to divide.
        let physical = match (s.store_bytes, s.wal_bytes) {
            (None, None) => return,
            (store, wal) => store.unwrap_or(0).saturating_add(wal.unwrap_or(0)),
        };
        self.report.storage.write_amplification =
            StorageMeter::write_amplification(physical, logical_bytes_written);
        self.report.storage.space_amplification =
            StorageMeter::space_amplification(physical, logical_graph_bytes);
    }

    /// Derives the **per-element durable costs** — `bytes_per_node` and `bytes_per_relationship` —
    /// from the MEASURED store image and the run's [`DatasetScale`].
    ///
    /// Call **after** [`record_storage`](Self::record_storage) and after the dataset scale is set
    /// (via [`RunMetadata::with_dataset`] or [`metadata_mut`](Self::metadata_mut)). Each figure is
    /// derived only when both of its inputs were measured:
    ///
    /// * no measured `store_bytes` (an external target; a store this run cannot read) ⇒ **both absent**;
    /// * a dataset scale of `0` nodes (or `0` relationships) ⇒ **that** figure absent.
    ///
    /// The denominator is the durable **store image** and not `store + WAL`: the WAL is a transient
    /// redo log that a checkpoint reclaims, so folding it in would make the "cost of keeping a node"
    /// depend on how recently the server checkpointed. See [`StorageSection::bytes_per_node`] for what
    /// the figure does and does not decompose.
    ///
    /// # Caller obligation
    ///
    /// The store path measured and the dataset scale recorded MUST describe **the same graph**. An
    /// example that meters one tenant's store while counting every tenant's nodes would produce a
    /// number that is real arithmetic over mismatched inputs — the exact class of subtly-wrong
    /// evidence this schema exists to prevent. When that cannot be attested, do not call this.
    pub fn record_per_element_costs(&mut self) {
        let dataset = self.report.metadata.dataset.clone();
        self.record_per_element_costs_for(dataset.nodes, dataset.relationships);
    }

    /// Like [`record_per_element_costs`](Self::record_per_element_costs) but against an **explicit**
    /// element count, for the example whose [`DatasetScale`] describes a *different* graph from the
    /// one in the measured store.
    ///
    /// `gds-analytics` is exactly that case: its gated `dataset` is the hermetic CSR-projection sweep
    /// (which has no store at all), while the store it meters holds the loaded influence network. It
    /// must therefore divide by the network's counts, not the sweep's — dividing the store image by a
    /// graph that was never in it would yield a number that is arithmetically real and semantically
    /// meaningless.
    pub fn record_per_element_costs_for(&mut self, nodes: u64, relationships: u64) {
        let Some(store_bytes) = self.report.storage.store_bytes else {
            return;
        };
        let store_bytes = store_bytes as f64;
        if nodes > 0 {
            self.report.storage.bytes_per_node = measured_ratio(store_bytes / nodes as f64);
        }
        if relationships > 0 {
            self.report.storage.bytes_per_relationship =
                measured_ratio(store_bytes / relationships as f64);
        }
    }

    /// Records the **retention plateau ratio** for a workload that reaches a genuine steady state:
    /// the largest post-warmup footprint over the smallest (`1.0` = a perfectly flat plateau).
    ///
    /// This belongs to retention / GC workloads only (`iot-timeseries` is the one that has one). An
    /// example with no steady state to observe must simply not call this, leaving the field absent —
    /// emitting `1.0` (or `0.0`) for a workload that never plateaued would invent a property the run
    /// never demonstrated.
    ///
    /// A non-finite or non-positive `ratio` is rejected as "not measured" (a malformed figure must
    /// never become evidence).
    pub fn record_plateau_ratio(&mut self, ratio: f64) {
        self.report.storage.plateau_ratio = measured_ratio(ratio);
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

    /// Records the run's total wall-clock duration **explicitly**, overriding the
    /// [`start`](Self::start)-to-[`finish`](Self::finish) interval.
    ///
    /// Use this whenever the collector cannot bracket the workload itself — e.g. an example that
    /// measures its phases first and only builds the report afterwards. Without it such a report
    /// would show the *report-building* time as `total_millis`, which is not the workload's duration.
    pub fn record_total_duration(&mut self, total: Duration) {
        self.total_override = Some(total);
    }

    /// Resolves `total_millis` for a driver that ran its workload **before** the report was built
    /// (`rmp #699`) — the shape every `*_evidence` / `measure_*` emitter has.
    ///
    /// Such an emitter cannot bracket the workload with [`start`](Self::start) /
    /// [`finish`](Self::finish): that interval would time the report's own *emission* (a few
    /// hundredths of a millisecond), which is not the run's duration and reads as if it were
    /// measured. The honest resolution order is:
    ///
    /// 1. `total_millis` — the wall-time the example measured around its workload (preferred);
    /// 2. `workload_secs` — the timed throughput window, when that is all the driver tracked;
    /// 3. neither — `total_millis` stays at `0.0` (**not measured**) and a note says so, rather than
    ///    silently reporting the emitter's own runtime.
    ///
    /// Non-finite or negative inputs are rejected as "not supplied" (a malformed figure must never
    /// become evidence).
    pub fn record_total_duration_from(
        &mut self,
        total_millis: Option<f64>,
        workload_secs: Option<f64>,
    ) {
        let sane = |v: f64| v.is_finite() && v >= 0.0;
        if let Some(ms) = total_millis.filter(|v| sane(*v)) {
            self.record_total_duration(Duration::from_secs_f64(ms / 1_000.0));
            return;
        }
        if let Some(secs) = workload_secs.filter(|v| sane(*v) && *v > 0.0) {
            self.record_total_duration(Duration::from_secs_f64(secs));
            self.note(
                "total_millis is the measured WORKLOAD window (--workload-secs): the driver did not \
                 supply an explicit --total-millis. It is NOT this emitter's own runtime."
                    .to_string(),
            );
            return;
        }
        self.record_total_duration(Duration::ZERO);
        self.note(
            "total_millis = 0.0 means NOT MEASURED: the driver supplied neither --total-millis nor \
             --workload-secs. (It is deliberately not the report emitter's own runtime, which is \
             what an unbracketed start()/finish() would have timed.)"
                .to_string(),
        );
    }

    /// Closes the run, finalising the total wall-clock duration, and yields the [`EvidenceReport`].
    ///
    /// The total is the duration passed to [`record_total_duration`](Self::record_total_duration)
    /// when one was given, otherwise the [`start`](Self::start)-to-now interval. If neither was
    /// supplied, the total duration is left at zero.
    pub fn finish(mut self) -> EvidenceReport {
        if let Some(total) = self.total_override {
            self.report.total_millis = total.as_secs_f64() * 1_000.0;
        } else if let Some(t0) = self.started {
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
            user_secs: Some(1.5),
            system_secs: Some(0.5),
            mean_core_utilisation: Some(0.8),
        };
        *c.memory_mut() = MemorySection {
            peak_rss_bytes: Some(256 * 1024 * 1024),
            final_rss_bytes: Some(200 * 1024 * 1024),
        };
        *c.storage_mut() = StorageSection {
            store_bytes: Some(81_920),
            wal_bytes: Some(16_384),
            store_pages: Some(10),
            wal_pages: Some(2),
            bytes_fsynced: Some(16_384),
            write_amplification: Some(1.2),
            space_amplification: Some(1.5),
            bytes_per_node: Some(8_192.0),
            bytes_per_relationship: Some(4_096.0),
            plateau_ratio: Some(1.02),
        };
        *c.throughput_mut() = ThroughputSection {
            operations: Some(100_000),
            ops_per_sec: Some(50_000.0),
            p50_latency_ms: Some(0.2),
            p99_latency_ms: Some(1.1),
            p999_latency_ms: Some(3.4),
            abort_rate: Some(0.05),
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
            query_duration_mean_ms: Some(0.488),
            query_duration_p50_ms: Some(0.3),
            query_duration_p99_ms: Some(2.1),
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

    /// Regression (`rmp #699`): an emitter that builds its report AFTER the workload must report the
    /// WORKLOAD's wall-time, never the report's own emission time. Every `*_evidence` / `measure_*`
    /// driver has this shape, and before the fix each one emitted `total_millis ≈ 0.03` — a figure
    /// that looks measured but times only the serialization of the report.
    #[test]
    fn explicit_total_duration_wins_over_the_emitters_own_runtime() {
        let mut c = EvidenceCollector::new(sample_metadata());
        c.start();
        c.record_total_duration_from(Some(18_298.72), Some(1.0));
        let report = c.finish();
        // The explicit workload wall-time, NOT the sub-millisecond start()-to-finish() interval.
        assert!((report.total_millis - 18_298.72).abs() < 1e-6);
    }

    /// Regression (`rmp #699`): with no explicit total, the timed throughput window is the honest
    /// fallback — still the workload's duration, not the emitter's.
    #[test]
    fn total_duration_falls_back_to_the_measured_workload_window() {
        let mut c = EvidenceCollector::new(sample_metadata());
        c.start();
        c.record_total_duration_from(None, Some(4.5));
        let report = c.finish();
        assert!((report.total_millis - 4_500.0).abs() < 1e-6);
        assert!(
            report.notes.iter().any(|n| n.contains("--workload-secs")),
            "the fallback must be disclosed in a note, got {:?}",
            report.notes
        );
    }

    /// Regression (`rmp #699`): when the driver measured NOTHING, `total_millis` must be an honest
    /// 0.0 ("not measured") with a note — never the emitter's own near-zero runtime, which would read
    /// as a real measurement.
    #[test]
    fn total_duration_is_zero_and_disclosed_when_unmeasured() {
        let mut c = EvidenceCollector::new(sample_metadata());
        c.start();
        std::thread::sleep(Duration::from_millis(2));
        c.record_total_duration_from(None, None);
        let report = c.finish();
        assert_eq!(report.total_millis, 0.0);
        assert!(
            report.notes.iter().any(|n| n.contains("NOT MEASURED")),
            "an unmeasured total must say so, got {:?}",
            report.notes
        );
    }

    /// A malformed figure (NaN / negative) must never become evidence: it is treated as "not
    /// supplied" and falls through to the next honest source.
    #[test]
    fn total_duration_rejects_non_finite_and_negative_inputs() {
        let mut c = EvidenceCollector::new(sample_metadata());
        c.start();
        c.record_total_duration_from(Some(f64::NAN), Some(2.0));
        assert!((c.finish().total_millis - 2_000.0).abs() < 1e-6);

        let mut c = EvidenceCollector::new(sample_metadata());
        c.start();
        c.record_total_duration_from(Some(-5.0), None);
        assert_eq!(c.finish().total_millis, 0.0);
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

    /// **Regression (`rmp #711`).** A collector nobody fed measures nothing, and a report of nothing
    /// must SAY nothing — every metric absent, and NOT ONE `0` / `0.0` in the emitted JSON that a
    /// reader could take for a measurement.
    #[test]
    fn unmeasured_sections_are_absent_not_zero() {
        let report = EvidenceCollector::new(sample_metadata()).finish();
        assert!(report.cpu.is_unmeasured());
        assert!(report.memory.is_unmeasured());
        assert!(report.storage.is_unmeasured());
        assert!(report.throughput.is_unmeasured());

        let json = report.to_json().expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        for section in ["cpu", "memory", "storage", "throughput"] {
            let obj = v[section].as_object().expect("section object");
            assert!(
                obj.is_empty(),
                "an unmeasured `{section}` vector must serialize EMPTY (no zero placeholders), got \
                 {obj:?}"
            );
        }
        // The three fields this task exists for are simply not there.
        for dead in ["bytes_per_node", "bytes_per_relationship", "plateau_ratio"] {
            assert!(
                !json.contains(dead),
                "an unmeasured `{dead}` must be ABSENT from the JSON, not emitted as 0.0"
            );
        }
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
        assert_eq!(parsed.cpu, report.cpu);
        assert_eq!(parsed.memory, report.memory);
        assert_eq!(parsed.storage, report.storage);
        assert_eq!(parsed.throughput, report.throughput);
        // The per-element costs + plateau ratio (`rmp #711`) round-trip as real, present figures.
        assert_eq!(parsed.storage.bytes_per_node, Some(8_192.0));
        assert_eq!(parsed.storage.bytes_per_relationship, Some(4_096.0));
        assert_eq!(parsed.storage.plateau_ratio, Some(1.02));
        // The v2 additions (`rmp #684`) survive the round-trip.
        assert_eq!(parsed.version, SCHEMA_VERSION);
        assert_eq!(parsed.version, 3);
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
        assert_eq!(parsed.storage.store_pages, None);
        assert_eq!(parsed.storage.write_amplification, None);
        // The additive `abort_rate` (rmp #253) is absent from an older report.
        assert_eq!(parsed.throughput.abort_rate, None);
        // The v2 additions (rmp #684) default cleanly: mode is Local, and there is no server metrics.
        assert_eq!(parsed.measurement_mode, MeasurementMode::Local);
        assert!(parsed.server_metrics.is_none());
    }

    /// **Regression (`rmp #711`).** A committed **pre-v3 baseline** carries the zero placeholders the
    /// old schema forced on it (`bytes_per_node: 0.0` for a figure nobody ever measured). Loading it
    /// verbatim would arm the comparator with a fake measurement and turn the first honest candidate
    /// figure into a phantom "+100% regression". [`EvidenceReport::load`] normalises those zeros back
    /// into "not measured" — which is what they always were.
    #[test]
    fn a_pre_v3_baselines_zero_placeholders_load_as_not_measured() {
        let dir = std::env::temp_dir().join(format!("graphus-harness-v2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("baseline.json");
        // A v2 baseline exactly as `examples/fraud-oltp/baseline.json` was committed.
        std::fs::write(
            &path,
            r#"{
              "version": 2,
              "metadata": { "scenario": "fraud-oltp", "description": "b", "started_unix_secs": 1,
                            "dataset": { "nodes": 310, "relationships": 588 } },
              "total_millis": 7656.0,
              "phases": [],
              "cpu": { "user_secs": 1.91, "system_secs": 0.74, "mean_core_utilisation": 0.294 },
              "memory": { "peak_rss_bytes": 373026816, "final_rss_bytes": 373026816 },
              "storage": { "store_bytes": 442368, "wal_bytes": 3982455, "store_pages": 54,
                           "wal_pages": 487, "bytes_fsynced": 3982455,
                           "write_amplification": 39.35, "space_amplification": 39.35,
                           "bytes_per_node": 0.0, "bytes_per_relationship": 0.0,
                           "plateau_ratio": 0.0 },
              "throughput": { "operations": 914, "ops_per_sec": 210.36, "p50_latency_ms": 3.984,
                              "p99_latency_ms": 14.652, "p999_latency_ms": 16.656,
                              "abort_rate": 0.951852 }
            }"#,
        )
        .expect("write baseline");

        let baseline =
            EvidenceReport::load(&path).expect("a committed v2 baseline must still parse");

        // The dead placeholders are gone — they were never measurements.
        assert_eq!(baseline.storage.bytes_per_node, None);
        assert_eq!(baseline.storage.bytes_per_relationship, None);
        assert_eq!(baseline.storage.plateau_ratio, None);
        // …while every figure that WAS measured survives untouched.
        assert_eq!(baseline.storage.store_bytes, Some(442_368));
        assert_eq!(baseline.storage.write_amplification, Some(39.35));
        assert_eq!(baseline.cpu.user_secs, Some(1.91));
        assert_eq!(baseline.throughput.operations, Some(914));
        // …including a legitimately-measured non-zero abort rate.
        assert_eq!(baseline.throughput.abort_rate, Some(0.951852));

        // And the comparator does NOT invent a regression when the candidate finally measures the cost.
        let mut candidate = baseline.clone();
        candidate.version = SCHEMA_VERSION;
        candidate.storage.bytes_per_node = Some(1_427.0);
        let cmp = candidate.compare_to_baseline(&baseline, &RegressionThresholds::uniform(0.15));
        assert!(
            !cmp.regressed,
            "a newly-measured cost against an unmeasured baseline is not a regression: {}",
            cmp.summary()
        );
        assert!(
            cmp.skipped
                .iter()
                .any(|s| s.metric == "storage.bytes_per_node"),
            "…it is a SKIPPED gate, and must be reported as one: {}",
            cmp.summary()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A **measured** zero survives the legacy normalisation: `abort_rate: 0.0` in a write workload
    /// that suffered no conflict is a real result, and disarming that gate would hide real contention
    /// appearing later.
    #[test]
    fn a_legacy_measured_zero_abort_rate_is_kept() {
        let mut report = EvidenceCollector::new(sample_metadata()).finish();
        report.version = 2;
        report.throughput.abort_rate = Some(0.0);
        report.throughput.operations = Some(0);
        report.normalize_legacy_zero_placeholders();
        assert_eq!(
            report.throughput.abort_rate,
            Some(0.0),
            "a measured zero abort rate is evidence, not a placeholder"
        );
        assert_eq!(
            report.throughput.operations, None,
            "a zero operation count IS a placeholder — no workload ran zero operations"
        );
    }

    // -- The WAL a crash left behind (`rmp #712`) -------------------------------------------------

    /// **Regression (`rmp` #712).** A crash-recovery example's load-bearing WAL is the redo log that
    /// existed **at the crash**. By emission time the server has restarted, replayed it and begun
    /// checkpointing, so walking the WAL directory *then* measures the post-recovery **residual** — a
    /// different, far smaller quantity. Reporting the residual under `wal_bytes` tells the reader that
    /// a crashed store's redo log cost almost nothing, which is exactly the class of subtly-wrong
    /// evidence the honesty rules exist to prevent.
    ///
    /// [`EvidenceCollector::record_storage_at`] lets the example supply the figure it measured at the
    /// instant the quantity existed; the page count is derived from THAT, and `bytes_fsynced` follows
    /// it rather than the residual.
    #[test]
    fn a_supplied_wal_byte_count_overrides_the_emission_time_walk() {
        let dir = temp_store_with_bytes("crash-wal", 8_192);
        // The WAL as it looks AFTER recovery: a small residual (one reclaimed segment).
        std::fs::write(
            dir.join("graphus.wal").join("seg.0000000042"),
            vec![0u8; 4_096],
        )
        .expect("residual segment");

        let mut c = EvidenceCollector::new(RunMetadata::new("unit", "crash-time WAL"));
        c.start();
        c.record_storage_at(
            dir.join("graphus.store"),
            dir.join("graphus.wal"),
            Some(1_254_181), // what the example measured, by path, AT THE CRASH
            Some(1_254_181),
        )
        .expect("measure");
        let report = c.finish();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            report.storage.wal_bytes,
            Some(1_254_181),
            "the redo log the crash left behind is the WAL this run wrote — NOT the 4 KiB residual \
             that happens to be on disk once recovery has replayed and checkpointed it away"
        );
        assert_eq!(
            report.storage.wal_pages,
            Some(1_254_181u64.div_ceil(PAGE_SIZE)),
            "the page count must follow the supplied byte count, not the walked residual"
        );
        assert_eq!(report.storage.bytes_fsynced, Some(1_254_181));
        assert_eq!(
            report.storage.store_bytes,
            Some(8_192),
            "the store image is still walked at emission time (it is the image AFTER replay)"
        );
    }

    /// The override never *invents* a WAL: if the WAL path does not exist at all, the vector stays
    /// NOT MEASURED (absent), exactly as it does without the override. A figure supplied for a WAL
    /// this run never had would be a fabrication, and schema v3 exists to make that impossible.
    #[test]
    fn a_supplied_wal_byte_count_cannot_conjure_a_wal_that_does_not_exist() {
        let dir = temp_store_with_bytes("no-wal", 8_192);
        let _ = std::fs::remove_dir_all(dir.join("graphus.wal"));

        let mut c = EvidenceCollector::new(RunMetadata::new("unit", "absent WAL"));
        c.start();
        c.record_storage_at(
            dir.join("graphus.store"),
            dir.join("graphus.wal"),
            Some(999_999),
            None,
        )
        .expect("measure");
        let report = c.finish();
        let storage_json = serde_json::to_string(&report.storage).expect("serialize");
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(report.storage.wal_bytes, None);
        assert_eq!(report.storage.wal_pages, None);
        assert_eq!(
            report.storage.bytes_fsynced, None,
            "with no WAL there is nothing to proxy the fsynced bytes with either"
        );
        assert!(
            !storage_json.contains("wal_bytes"),
            "a WAL that does not exist is NOT MEASURED — absent from the storage section, never a \
             supplied number: {storage_json}"
        );
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("NOT MEASURED") && n.contains("wal_bytes")),
            "and the report must SAY why the vector is absent"
        );
    }

    // -- Per-element durable costs (`rmp #711`) --------------------------------------------------

    /// **Regression (`rmp #711`).** With no dataset scale there is no denominator, so there is no
    /// per-element cost — and the report must therefore carry NONE, not a `0.0`.
    #[test]
    fn per_element_costs_are_absent_without_a_dataset_scale() {
        let dir = temp_store_with_bytes("no-scale", 8_192);
        let mut c = EvidenceCollector::new(RunMetadata::new("unit", "no dataset scale"));
        c.start();
        c.record_storage(dir.join("graphus.store"), dir.join("graphus.wal"), None)
            .expect("measure");
        c.record_per_element_costs();
        let report = c.finish();

        assert_eq!(
            report.storage.store_bytes,
            Some(8_192),
            "the store IS measured"
        );
        assert_eq!(report.storage.bytes_per_node, None);
        assert_eq!(report.storage.bytes_per_relationship, None);

        let json = report.to_json().expect("serialize");
        assert!(
            !json.contains("bytes_per_node"),
            "an underivable per-element cost must be ABSENT from the JSON: {json}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With a measured store AND a dataset scale, the per-element cost is derived from both and
    /// serialized as the real figure — the durable store image amortised over each element count.
    #[test]
    fn per_element_costs_are_derived_from_the_measured_store_and_the_dataset() {
        let dir = temp_store_with_bytes("with-scale", 8_192);
        let metadata =
            RunMetadata::new("unit", "with dataset scale").with_dataset(DatasetScale::new(64, 256));
        let mut c = EvidenceCollector::new(metadata);
        c.start();
        c.record_storage(dir.join("graphus.store"), dir.join("graphus.wal"), None)
            .expect("measure");
        c.record_per_element_costs();
        let report = c.finish();

        // 8192 store bytes / 64 nodes = 128 B/node; / 256 rels = 32 B/rel. Derived from the MEASURED
        // store image — the WAL (a transient redo log a checkpoint reclaims) is deliberately excluded.
        assert_eq!(report.storage.bytes_per_node, Some(128.0));
        assert_eq!(report.storage.bytes_per_relationship, Some(32.0));

        let json = report.to_json().expect("serialize");
        assert!(json.contains("\"bytes_per_node\": 128.0"), "{json}");
        assert!(json.contains("\"bytes_per_relationship\": 32.0"), "{json}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An external target has no store to read: the storage vector is N/A, so the per-element costs
    /// MUST be absent even though the dataset scale is perfectly well known.
    #[test]
    fn per_element_costs_are_absent_when_the_store_was_not_measured() {
        let missing = std::env::temp_dir().join("graphus-harness-absent-store-xyz");
        let _ = std::fs::remove_dir_all(&missing);
        let metadata =
            RunMetadata::new("unit", "external target").with_dataset(DatasetScale::new(100, 200));
        let mut c = EvidenceCollector::new(metadata);
        c.start();
        c.record_storage(
            missing.join("graphus.store"),
            missing.join("graphus.wal"),
            None,
        )
        .expect("a missing path is not an error — it is 'not measured'");
        c.record_per_element_costs();
        c.record_amplification(1_000, 1_000);
        let report = c.finish();

        assert!(report.storage.is_unmeasured(), "nothing was measurable");
        assert_eq!(report.storage.store_bytes, None);
        assert_eq!(report.storage.bytes_per_node, None);
        assert_eq!(report.storage.write_amplification, None);
        assert!(
            report.notes.iter().any(|n| n.contains("NOT MEASURED")),
            "the absence must be disclosed: {:?}",
            report.notes
        );
    }

    /// The plateau ratio belongs only to a workload with a genuine steady state, and a malformed or
    /// non-positive figure is never accepted as one.
    #[test]
    fn plateau_ratio_is_opt_in_and_rejects_malformed_figures() {
        let c = EvidenceCollector::new(sample_metadata());
        assert_eq!(
            c.finish().storage.plateau_ratio,
            None,
            "opt-in: absent by default"
        );

        let mut c = EvidenceCollector::new(sample_metadata());
        c.record_plateau_ratio(1.0);
        assert_eq!(c.finish().storage.plateau_ratio, Some(1.0));

        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let mut c = EvidenceCollector::new(sample_metadata());
            c.record_plateau_ratio(bad);
            assert_eq!(
                c.finish().storage.plateau_ratio,
                None,
                "a malformed plateau ratio ({bad}) must never become evidence"
            );
        }
    }

    /// Builds a temp store layout (`graphus.store` file + `graphus.wal/` directory) of a known size.
    fn temp_store_with_bytes(tag: &str, bytes: usize) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "graphus-harness-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("graphus.wal")).expect("temp store");
        std::fs::write(dir.join("graphus.store"), vec![0u8; bytes]).expect("store image");
        dir
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
        assert!((sm.query_duration_mean_ms.expect("mean") - 5.0).abs() < 1e-9);
        // p50 = 0.001 + 0.009 * (5/10) = 0.0055s = 5.5ms; p99 = 0.001 + 0.009*(9.9/10) = 9.91ms.
        assert!((sm.query_duration_p50_ms.expect("p50") - 5.5).abs() < 1e-9);
        assert!((sm.query_duration_p99_ms.expect("p99") - 9.91).abs() < 1e-9);
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
