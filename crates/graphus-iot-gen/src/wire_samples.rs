//! The machine-readable result of one **file-backed over-the-wire** churn run — the contract between
//! the `iot_wire` driver (which writes it) and the hermetic `iot_wire_evidence` emitter/gate (which
//! reads it and folds it, together with the target's `/metrics` scrapes, into a standardized
//! [`EvidenceReport`](graphus_examples_harness::EvidenceReport)).
//!
//! # Evidence honesty (`rmp` #699)
//!
//! Every optional field here means **"not measured on this run"**, and is serialized as `null` rather
//! than as a `0` that would read like a measurement. That distinction is load-bearing:
//!
//! * In **local** mode the driver shares a host with the server, so it can read the real store
//!   directory and `/proc/<server-pid>` — the storage, CPU, RSS and kernel write-byte fields are all
//!   populated with real observations.
//! * In **external (attach)** mode the server is somewhere else: its store files and `/proc` are
//!   inaccessible by construction. Those fields stay `None`, the report omits them, and the
//!   server-side evidence comes exclusively from the target's Prometheus `/metrics`.
//!
//! A field is therefore never a placeholder. If it carries a number, that number was measured.

use serde::{Deserialize, Serialize};

/// The transport the run drove the workload over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WireTransport {
    /// Bolt over a Unix domain socket (a co-located server).
    BoltUds,
    /// Bolt over TCP, optionally TLS-wrapped (an attached local or remote instance).
    BoltTcp,
}

impl WireTransport {
    /// The `connection` label the evidence report records.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::BoltUds => "bolt-uds",
            Self::BoltTcp => "bolt-tcp",
        }
    }
}

/// One per-tick sample of the live workload and (locally) the REAL on-disk footprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireTick {
    /// 0-based tick index.
    pub tick: u64,
    /// Cumulative readings ingested up to and including this tick.
    pub total_ingested: u64,
    /// Live `:Reading` count after this tick's ingest + retention `DELETE` (read over the wire).
    pub live_readings: u64,
    /// Whether a `CHECKPOINT DATABASE` was issued at the end of this tick.
    pub checkpointed: bool,
    /// `graphus.store` — the data image length in bytes. `None` in external mode (no store access).
    pub store_data_bytes: Option<u64>,
    /// The segmented WAL's on-disk bytes. `None` in external mode.
    pub wal_bytes: Option<u64>,
}

/// The final, decomposed on-disk footprint plus the cumulative durable write volume (local only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireStorage {
    /// `graphus.store` — the data image (the graph itself), at the end of the run.
    pub data_bytes: u64,
    /// `graphus.dwb` — the doublewrite buffer: a FIXED preallocation per database, not graph data.
    pub dwb_bytes: u64,
    /// The segmented WAL's on-disk bytes at the end of the run (after the last checkpoint's reclaim).
    ///
    /// **Read this together with [`wal_peak_bytes`](Self::wal_peak_bytes).** The on-disk WAL does not
    /// plateau the way the store does — it *sawtooths*, because reclamation frees disk in whole SEGMENT
    /// units and a segment is only sealed at `DEFAULT_SEGMENT_TARGET_BYTES` (64 MiB). So the residual
    /// figure depends entirely on where in the sawtooth the run happened to stop, and on its own it
    /// flatters the WAL badly.
    pub wal_bytes: u64,
    /// The **peak** on-disk WAL observed across the run — the honest worst case, and the figure that
    /// actually sizes the disk a deployment must provision. See [`wal_bytes`](Self::wal_bytes).
    pub wal_peak_bytes: u64,
    /// Anything else in the database directory (catalog / key material).
    pub other_bytes: u64,
    /// **Cumulative** WAL bytes written over the whole run, not just what survives at the end.
    ///
    /// A WAL segment is append-only, so its final length is its maximum length; a checkpoint then
    /// *deletes* the segments below the reclaim floor. Summing the maximum observed length of every
    /// segment path ever seen therefore recovers the total volume the engine wrote, which the residual
    /// on-disk `wal_bytes` alone badly understates once reclamation starts. Sampled once per tick, so
    /// it is a lower bound if a segment were created and reclaimed entirely between two samples.
    pub wal_written_bytes: u64,
    /// Post-warmup minimum of `store_data_bytes` — the bottom of the plateau band.
    pub plateau_min_data_bytes: u64,
    /// Post-warmup maximum of `store_data_bytes` — the top of the plateau band.
    pub plateau_max_data_bytes: u64,
    /// The data image's page high-water (`plateau_max_data_bytes / PAGE_SIZE`).
    pub plateau_max_data_pages: u64,
    /// `write_bytes` from `/proc/<server-pid>/io` over the workload window: the kernel's own account of
    /// the bytes the SERVER process caused to be sent to the storage layer. An independent cross-check
    /// on `wal_written_bytes` + the store growth, from outside the engine. `None` if `/proc` is
    /// unavailable (non-Linux).
    pub server_io_write_bytes: Option<u64>,
}

/// Latency percentiles for one statement family, in milliseconds. Every field is a real measurement of
/// a non-empty sample; a family that never ran is represented by an absent [`WireLatency`], never by a
/// struct full of zeros.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WireLatency {
    /// Number of statements in the family (the sample size behind the percentiles).
    pub count: u64,
    /// 50th-percentile latency, ms.
    pub p50_ms: f64,
    /// 99th-percentile latency, ms.
    pub p99_ms: f64,
    /// 99.9th-percentile latency, ms.
    pub p999_ms: f64,
}

/// One functional check the driver ran over the wire (schema enforcement, index-backed reads, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireCheck {
    /// A short description of what was asserted.
    pub name: String,
    /// Whether it held.
    pub ok: bool,
    /// Human-readable observed value / failure detail.
    pub detail: String,
}

/// The whole run: configuration, per-tick series, storage, latency and the functional checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireSamples {
    /// Schema version of THIS file (bumped on any incompatible change).
    pub version: u32,
    /// The example that produced it (`iot-timeseries`).
    pub scenario: String,
    /// The transport the workload was driven over.
    pub transport: WireTransport,
    /// The isolated database the workload ran in.
    pub database: String,
    /// `true` when the driver shared a host with the server (store + `/proc` readable).
    pub local: bool,

    // ---- workload configuration ----
    /// The generator seed (the run is reproducible from it).
    pub seed: u64,
    /// Sensors in the fleet.
    pub sensors: u64,
    /// Readings ingested per tick.
    pub rate: u64,
    /// Retention window, in readings.
    pub window: u64,
    /// Ticks driven.
    pub ticks: u64,
    /// Ticks after which the steady state is asserted (the window has filled).
    pub warmup_ticks: u64,
    /// Concurrent ingest connections (each owns a disjoint set of sensors, so they never conflict).
    pub ingest_clients: u64,
    /// `CHECKPOINT DATABASE` was issued every this-many ticks (`0` = never; rely on the background
    /// cadence alone).
    pub checkpoint_every: u64,

    // ---- results ----
    /// The per-tick series.
    pub ticks_series: Vec<WireTick>,
    /// Total readings ingested over the run.
    pub total_ingested: u64,
    /// The live `:Reading` count at the end of the run.
    pub final_live_readings: u64,
    /// How many `CHECKPOINT DATABASE` statements the driver issued.
    pub checkpoints_issued: u64,
    /// Ingest statements executed.
    pub ingest_ops: u64,
    /// Retention `DETACH DELETE` statements executed.
    pub delete_ops: u64,
    /// Statements the server rejected with a retriable transaction error (SSI/lock conflict) and the
    /// driver retried. Real observation; `0` means none were observed, which for a sensor-sharded
    /// ingest is the expected, asserted outcome.
    pub retried_ops: u64,
    /// Wall-clock seconds of the CHURN LOOP — the workload window, not the process lifetime.
    pub workload_secs: f64,
    /// The logical payload the client asked the server to store, in bytes: for every ingested reading,
    /// its property values (`sensor` id string + `seq` + `ts` + `value`, the three integers at 8 bytes
    /// each). The denominator of write amplification. It is a *logical* figure by construction — it
    /// deliberately excludes record headers, MVCC versions, index entries and page slack, which are
    /// exactly the overheads amplification is meant to expose.
    pub logical_ingested_bytes: u64,

    /// Real on-disk storage evidence. `None` in external mode (the store lives on another host).
    pub storage: Option<WireStorage>,
    /// Real latency of the single-reading ingest statements.
    pub insert_latency: Option<WireLatency>,
    /// Real latency of the per-tick windowed retention `DETACH DELETE`.
    pub delete_latency: Option<WireLatency>,
    /// Real latency of the `CHECKPOINT DATABASE` operator statements.
    pub checkpoint_latency: Option<WireLatency>,
    /// The SERVER process's CPU time over the workload window (user, system) in seconds, from
    /// `/proc/<pid>/stat`. `None` in external mode / off Linux.
    pub server_cpu_secs: Option<(f64, f64)>,
    /// The SERVER process's peak RSS observed over the workload window, in bytes, from
    /// `/proc/<pid>/status`. `None` in external mode / off Linux.
    pub server_peak_rss_bytes: Option<u64>,

    /// Schema DDL the target accepted.
    pub schema_applied: Vec<String>,
    /// Schema DDL the target rejected (an older instance may lack a modern index kind) — recorded, not
    /// hidden.
    pub schema_skipped: Vec<String>,
    /// The functional checks driven over the wire.
    pub checks: Vec<WireCheck>,
}

/// The current schema version of [`WireSamples`].
pub const WIRE_SAMPLES_VERSION: u32 = 1;

impl WireSamples {
    /// Ingest throughput over the churn loop, in readings/second. `None` when the window is degenerate
    /// (a zero-length measurement cannot yield a rate).
    #[must_use]
    pub fn ingest_per_sec(&self) -> Option<f64> {
        (self.workload_secs > 0.0).then(|| self.total_ingested as f64 / self.workload_secs)
    }

    /// How many times the retention window the run ingested in total. The plateau is only meaningful
    /// when this is comfortably `> 1`.
    #[must_use]
    pub fn ingest_to_window(&self) -> f64 {
        self.total_ingested as f64 / self.window.max(1) as f64
    }

    /// The post-warmup **plateau ratio** of the data image: `plateau_max / plateau_min`. `1.0` means a
    /// perfectly flat footprint (every freed slot reused); a large value means growth. `None` when
    /// storage was not measured (external mode).
    #[must_use]
    pub fn plateau_ratio(&self) -> Option<f64> {
        self.storage
            .as_ref()
            .map(|s| s.plateau_max_data_bytes as f64 / s.plateau_min_data_bytes.max(1) as f64)
    }

    /// **Write amplification**: physical durable bytes written / logical bytes ingested.
    ///
    /// The numerator is `wal_written_bytes` (every byte the WAL ever carried, including the bytes later
    /// reclaimed) **plus** the final data image (the pages the checkpoints flushed home). It therefore
    /// counts the durable write volume the workload actually caused, not the residue that happens to
    /// survive on disk at the end. `None` when storage was not measured.
    #[must_use]
    pub fn write_amplification(&self) -> Option<f64> {
        let s = self.storage.as_ref()?;
        if self.logical_ingested_bytes == 0 {
            return None;
        }
        let physical = s.wal_written_bytes.saturating_add(s.data_bytes);
        Some(physical as f64 / self.logical_ingested_bytes as f64)
    }

    /// **Space amplification**: the final on-disk footprint (store + WAL) / the logical size of the
    /// data actually retained at steady state (`final_live_readings` readings' worth of payload).
    /// `None` when storage was not measured or nothing is retained.
    #[must_use]
    pub fn space_amplification(&self) -> Option<f64> {
        let s = self.storage.as_ref()?;
        if self.final_live_readings == 0 || self.total_ingested == 0 {
            return None;
        }
        let bytes_per_reading = self.logical_ingested_bytes as f64 / self.total_ingested as f64;
        let logical_live = bytes_per_reading * self.final_live_readings as f64;
        if logical_live <= 0.0 {
            return None;
        }
        let physical = s
            .data_bytes
            .saturating_add(s.dwb_bytes)
            .saturating_add(s.other_bytes)
            .saturating_add(s.wal_bytes);
        Some(physical as f64 / logical_live)
    }

    /// The **WAL/store ratio** at the end of the run: residual WAL bytes per byte of data image.
    ///
    /// Reported for completeness, but [`wal_to_store_ratio_peak`](Self::wal_to_store_ratio_peak) is the
    /// figure that matters: the on-disk WAL sawtooths (see [`WireStorage::wal_bytes`]), so this one
    /// depends on where in the sawtooth the run stopped. `None` when storage was not measured.
    #[must_use]
    pub fn wal_to_store_ratio(&self) -> Option<f64> {
        let s = self.storage.as_ref()?;
        (s.data_bytes > 0).then(|| s.wal_bytes as f64 / s.data_bytes as f64)
    }

    /// The **peak** WAL/store ratio over the run: the largest on-disk WAL observed, per byte of data
    /// image. This is the honest worst case — the ratio that sizes the disk a deployment must
    /// provision — and it is the number the WAL-amplification work (`rmp` #556) is really judged on.
    /// `None` when storage was not measured or no data image exists.
    #[must_use]
    pub fn wal_to_store_ratio_peak(&self) -> Option<f64> {
        let s = self.storage.as_ref()?;
        (s.data_bytes > 0).then(|| s.wal_peak_bytes as f64 / s.data_bytes as f64)
    }

    /// Whether the on-disk WAL **plateaued** the way the store did: its post-warmup band is bounded
    /// within `factor`. `None` when storage was not measured.
    ///
    /// On a small store this is expected to be `false`, and that is a REAL, reportable finding rather
    /// than a defect in the example — see the note the evidence report emits. The store plateaus because
    /// reclamation returns freed record slots to a free list that new inserts reuse; the WAL does not,
    /// because its disk is only freed in whole 64 MiB segment units.
    #[must_use]
    pub fn wal_plateaued(&self, factor: f64) -> Option<bool> {
        let s = self.storage.as_ref()?;
        let post: Vec<u64> = self
            .ticks_series
            .iter()
            .filter(|t| t.tick >= self.warmup_ticks)
            .filter_map(|t| t.wal_bytes)
            .collect();
        let (min, max) = (post.iter().copied().min()?, post.iter().copied().max()?);
        let _ = s;
        Some(max as f64 <= factor * min.max(1) as f64)
    }
}
