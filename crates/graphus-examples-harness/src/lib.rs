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

pub use diff::{ComparisonReport, MetricDelta, RegressionThresholds};
pub use host::HostInfo;
pub use metrics::{DiskFootprint, LatencyCollector, PAGE_SIZE, StorageMeter, ThroughputCounter};
pub use resource::{
    CpuMeter, CpuTimes, ResourceMeter, RssSample, RssSampler, Target, cumulative_cpu_times,
    current_rss_bytes,
};

/// Current evidence-schema version.
///
/// Bump this whenever the on-disk shape of [`EvidenceReport`] changes in a way consumers must notice.
/// It is serialized as the top-level `version` field of every `report.json`, so external tooling and
/// the baseline-diff helper can detect format drift. Reports are deserialized leniently (every added
/// section defaults via `#[serde(default)]`), so an *older-but-compatible* report still loads.
pub const SCHEMA_VERSION: u32 = 1;

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
        let _ = writeln!(s);

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
        };
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

        // The documented top-level keys are all present in the JSON.
        for key in [
            "\"version\"",
            "\"metadata\"",
            "\"host\"",
            "\"cpu\"",
            "\"memory\"",
            "\"storage\"",
            "\"throughput\"",
        ] {
            assert!(json.contains(key), "JSON must contain top-level {key}");
        }
    }

    #[test]
    fn older_compatible_report_still_loads() {
        // A minimal report missing every `#[serde(default)]` section (host, dataset, workload,
        // amplification, notes) must still deserialize — the versioned-but-lenient contract.
        let minimal = r#"{
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
        let parsed: EvidenceReport = serde_json::from_str(minimal).expect("lenient deserialize");
        assert_eq!(parsed.metadata.scenario, "legacy");
        assert_eq!(parsed.metadata.dataset, DatasetScale::default());
        assert!(parsed.metadata.workload.is_empty());
        assert_eq!(parsed.storage.store_pages, 0);
        assert_eq!(parsed.storage.write_amplification, 0.0);
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

        let _ = std::fs::remove_dir_all(&dir);
    }
}
