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
//! 5. call [`EvidenceReport::write_to`] to emit a machine-readable `evidence.json` plus a
//!    human-readable `evidence.md` into the example's git-ignored `evidence/` directory.
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
//! - **`rmp #248`** — the standardized evidence-report emitter (richer JSON + Markdown) and
//!   committed baselines.
//!
//! Until those land, the metric fields default to zero/empty and the emitted reports carry an
//! explicit `TODO(#246/#247/#248)` note, so the seams are visible and the smoke example still works.
//!
//! The API is deliberately allocation-light and side-effect-free until [`EvidenceReport::write_to`],
//! making it usable from DST-driven (deterministic) scenarios.

//! ## `unsafe` policy
//!
//! The crate is `unsafe`-free except for the [`resource`] metering module, which makes a handful of
//! `getrusage`/`sysconf` libc calls — each confined to a tiny helper with a `// SAFETY:` rationale.
//! We therefore use `deny(unsafe_op_in_unsafe_fn)` (every `unsafe` op must sit in an explicit
//! `unsafe` block) instead of a blanket `forbid(unsafe_code)`; the rest of the crate uses no
//! `unsafe`.
#![deny(unsafe_op_in_unsafe_fn)]

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub mod resource;

pub use resource::{CpuMeter, CpuTimes, ResourceMeter, RssSample, RssSampler, Target};

/// Identifying metadata for a single example run.
///
/// Captured once, at construction time, and echoed verbatim into both emitted reports so a piece of
/// evidence is always traceable back to *which example produced it, on what host, when*.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetadata {
    /// The example's directory name, e.g. `"social-network-uds"`. Used as the report title.
    pub example: String,
    /// A one-line human description of what the run demonstrates.
    pub description: String,
    /// Free-form host label (OS/arch). Filled richly by `rmp #246`; a caller-supplied hint for now.
    pub host: String,
    /// Wall-clock start time as a Unix timestamp in seconds. `0` until [`EvidenceCollector::start`].
    pub started_unix_secs: u64,
}

impl RunMetadata {
    /// Creates metadata for an example run. `host` may be a coarse hint (e.g. `"linux/x86_64"`);
    /// `rmp #246` will enrich it from the platform.
    pub fn new(
        example: impl Into<String>,
        description: impl Into<String>,
        host: impl Into<String>,
    ) -> Self {
        Self {
            example: example.into(),
            description: description.into(),
            host: host.into(),
            started_unix_secs: 0,
        }
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

/// Storage-footprint evidence for the run.
///
/// **Seam — filled in by `rmp #247`** (on-disk store + WAL sizing).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageSection {
    /// Total on-disk size of the data store after the run, in bytes.
    pub store_bytes: u64,
    /// Total on-disk size of the write-ahead log after the run, in bytes.
    pub wal_bytes: u64,
    /// Bytes physically `fsync`ed to durable media during the run, if measured.
    pub bytes_fsynced: u64,
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

/// The complete, serializable evidence produced by one example run.
///
/// Emitted as `evidence.json` (machine-readable) and `evidence.md` (human-readable) by
/// [`EvidenceReport::write_to`]. Each `*_section` is an independent seam owned by a follow-up task,
/// so they can be populated incrementally without changing this top-level shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReport {
    /// Identifying metadata for the run.
    pub metadata: RunMetadata,
    /// Total wall-clock duration of the run between `start()` and `finish()`, in milliseconds.
    pub total_millis: f64,
    /// Per-phase wall-clock timings, in the order phases were recorded.
    pub phases: Vec<PhaseTiming>,
    /// CPU evidence (`rmp #246`).
    pub cpu: CpuSection,
    /// Memory evidence (`rmp #246`).
    pub memory: MemorySection,
    /// Storage evidence (`rmp #247`).
    pub storage: StorageSection,
    /// Throughput/latency evidence (`rmp #247`).
    pub throughput: ThroughputSection,
    /// Notes carried into the report — including the standing `TODO` until the metering lands.
    pub notes: Vec<String>,
}

impl EvidenceReport {
    /// File name of the machine-readable report written into the evidence directory.
    pub const JSON_FILE: &'static str = "evidence.json";
    /// File name of the human-readable report written into the evidence directory.
    pub const MARKDOWN_FILE: &'static str = "evidence.md";

    /// Writes both reports (`evidence.json` + `evidence.md`) into `dir`, creating it if needed.
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
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(&json_path, json)?;

        let md_path = dir.join(Self::MARKDOWN_FILE);
        std::fs::write(&md_path, self.to_markdown())?;

        Ok((json_path, md_path))
    }

    /// Renders the human-readable Markdown summary.
    ///
    /// Intentionally minimal: a header, a phase-timing table, and a metrics table whose cells are
    /// the (currently zeroed) seam values. `rmp #248` will grow this into the standardized emitter.
    fn to_markdown(&self) -> String {
        use std::fmt::Write as _;

        let mut s = String::with_capacity(1024);
        let _ = writeln!(s, "# Evidence — {}", self.metadata.example);
        let _ = writeln!(s);
        let _ = writeln!(s, "_{}_", self.metadata.description);
        let _ = writeln!(s);
        let _ = writeln!(s, "- Host: `{}`", self.metadata.host);
        let _ = writeln!(s, "- Started (unix): `{}`", self.metadata.started_unix_secs);
        let _ = writeln!(s, "- Total wall-clock: `{:.3} ms`", self.total_millis);
        let _ = writeln!(s);

        let _ = writeln!(s, "## Phase timings");
        let _ = writeln!(s);
        let _ = writeln!(s, "| Phase | Duration (ms) |");
        let _ = writeln!(s, "|-------|---------------|");
        for p in &self.phases {
            let _ = writeln!(s, "| {} | {:.3} |", p.name, p.millis);
        }
        let _ = writeln!(s);

        let _ = writeln!(s, "## Performance vectors");
        let _ = writeln!(s);
        let _ = writeln!(s, "| Vector | Metric | Value |");
        let _ = writeln!(s, "|--------|--------|-------|");
        let _ = writeln!(s, "| CPU | user (s) | {:.3} |", self.cpu.user_secs);
        let _ = writeln!(s, "| CPU | system (s) | {:.3} |", self.cpu.system_secs);
        let _ = writeln!(
            s,
            "| CPU | mean core utilisation | {:.3} |",
            self.cpu.mean_core_utilisation
        );
        let _ = writeln!(
            s,
            "| Memory | peak RSS (bytes) | {} |",
            self.memory.peak_rss_bytes
        );
        let _ = writeln!(
            s,
            "| Memory | final RSS (bytes) | {} |",
            self.memory.final_rss_bytes
        );
        let _ = writeln!(
            s,
            "| Storage | store (bytes) | {} |",
            self.storage.store_bytes
        );
        let _ = writeln!(s, "| Storage | WAL (bytes) | {} |", self.storage.wal_bytes);
        let _ = writeln!(
            s,
            "| Throughput | operations | {} |",
            self.throughput.operations
        );
        let _ = writeln!(
            s,
            "| Throughput | ops/sec | {:.3} |",
            self.throughput.ops_per_sec
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
                metadata,
                total_millis: 0.0,
                phases: Vec::new(),
                cpu: CpuSection::default(),
                memory: MemorySection::default(),
                storage: StorageSection::default(),
                throughput: ThroughputSection::default(),
                notes: vec![
                    "Metric sections are scaffold placeholders. \
                     TODO(rmp #246): CPU + memory metering. \
                     TODO(rmp #247): storage + throughput/latency. \
                     TODO(rmp #248): standardized emitter + baselines."
                        .to_string(),
                ],
            },
            started: None,
        }
    }

    /// Marks the start of the run: records the wall-clock origin and stamps the start time.
    ///
    /// `rmp #246` will additionally snapshot the baseline `getrusage`/RSS here.
    pub fn start(&mut self) {
        self.started = Some(Instant::now());
        self.report.metadata.started_unix_secs = unix_now_secs();
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
        RunMetadata::new("smoke-evidence", "scaffold smoke test", "test-host")
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
    fn sections_default_to_zero_and_carry_todo_note() {
        let report = EvidenceCollector::new(sample_metadata()).finish();
        assert_eq!(report.cpu.user_secs, 0.0);
        assert_eq!(report.memory.peak_rss_bytes, 0);
        assert_eq!(report.storage.store_bytes, 0);
        assert_eq!(report.throughput.operations, 0);
        assert!(
            report.notes.iter().any(|n| n.contains("#246")),
            "the standing TODO seam note must be present"
        );
    }

    #[test]
    fn write_to_emits_json_and_markdown() {
        let dir = std::env::temp_dir().join(format!("graphus-harness-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut c = EvidenceCollector::new(sample_metadata());
        c.start();
        c.phase("only-phase", Duration::from_millis(3));
        let report = c.finish();
        let (json_path, md_path) = report.write_to(&dir).expect("write evidence");

        assert!(json_path.exists());
        assert!(md_path.exists());

        // The JSON round-trips back into an equivalent report.
        let json = std::fs::read_to_string(&json_path).unwrap();
        let parsed: EvidenceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.metadata.example, "smoke-evidence");
        assert_eq!(parsed.phases.len(), 1);

        let md = std::fs::read_to_string(&md_path).unwrap();
        assert!(md.contains("# Evidence — smoke-evidence"));
        assert!(md.contains("only-phase"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
