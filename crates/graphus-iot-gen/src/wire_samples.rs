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

/// The size at which the WAL seals its active segment and rolls to a new one
/// (`graphus_wal::sink::DEFAULT_SEGMENT_TARGET_BYTES`, `crates/graphus-wal/src/sink.rs`).
///
/// Replicated here as a plain constant rather than imported, so the wire driver and its gate keep
/// building with `--no-default-features --features wire` (client-only: no engine, no WAL crate). It is
/// load-bearing evidence, not a decoration: **WAL disk is reclaimed in whole segment units**, so until
/// a run has written this much WAL there is no sealed segment below the reclaim floor to delete, and
/// no WAL disk can be freed *however often* a checkpoint runs. A run shorter than this can therefore
/// neither observe reclamation nor claim it works — which is exactly why the wire run is sized to
/// cross it (`GenConfig::reclaim`, `rmp` #713 / #706).
pub const WAL_SEGMENT_TARGET_BYTES: u64 = 64 * 1024 * 1024;

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
    /// Everything durable that is NOT the redo log, at this tick: the data image **plus** the fixed
    /// doublewrite preallocation and the catalog. The non-WAL half of the durable footprint.
    /// `None` in external mode.
    pub store_bytes: Option<u64>,
    /// The segmented WAL's on-disk bytes. `None` in external mode.
    pub wal_bytes: Option<u64>,
}

impl WireTick {
    /// The **total durable on-disk footprint** at this tick: everything the database occupies on the
    /// filesystem, store *and* redo log.
    ///
    /// This is the figure that sizes the disk an operator must actually provision, and it is the one
    /// the example's headline claim must be judged against. The store alone plateaus beautifully; the
    /// total does not, because the WAL does not (`rmp` #706). Reporting only the store would make a
    /// true statement about a component and a false one about the database.
    #[must_use]
    pub fn durable_bytes(&self) -> Option<u64> {
        Some(self.store_bytes?.saturating_add(self.wal_bytes?))
    }
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

    // ---- the TOTAL durable footprint (store + WAL) — the figure that sizes a real disk ----
    /// Post-warmup **minimum** of the total durable footprint (store + WAL) — the bottom of the
    /// sawtooth, i.e. the moment just after a WAL segment was reclaimed.
    pub footprint_min_bytes: u64,
    /// Post-warmup **maximum** of the total durable footprint (store + WAL) — the top of the sawtooth,
    /// i.e. the moment just before a segment is sealed and freed. **This is the disk the deployment
    /// must actually provision**, and on a small store it is dominated entirely by the WAL.
    pub footprint_peak_bytes: u64,
    /// The total durable footprint at the END of the run. Like [`wal_bytes`](Self::wal_bytes), it
    /// depends on where in the WAL's sawtooth the run happened to stop, so it must never be quoted
    /// without [`footprint_peak_bytes`](Self::footprint_peak_bytes) beside it.
    pub footprint_final_bytes: u64,

    // ---- did WAL disk actually come back? ----
    /// How many times the on-disk WAL **shrank** between two consecutive ticks — i.e. how many times a
    /// sealed segment below the reclaim floor was physically deleted and its disk returned.
    ///
    /// This is the only direct, observable proof that WAL reclamation *happened*. The maintenance
    /// counters (`graphus_maintenance_versions_reclaimed_total`) climb happily while **zero** bytes of
    /// WAL disk are freed — they count reclaimed MVCC *versions* in the store, not WAL segments — so a
    /// green reclamation counter beside a monotonically-climbing WAL is not a contradiction, it is the
    /// defect (`rmp` #706). Counting the drops is what tells the two apart.
    pub wal_reclaim_events: u64,
    /// Total WAL bytes physically returned to the filesystem across those events.
    pub wal_reclaimed_bytes: u64,
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
///
/// v2 (`rmp` #713) adds the total-durable-footprint band (`footprint_*`) and the observed WAL
/// reclamation events (`wal_reclaim_events` / `wal_reclaimed_bytes`) to [`WireStorage`], and the
/// per-tick non-WAL store total to [`WireTick`]. This file is a private contract between `iot_wire` and
/// `iot_wire_evidence`, which `run.sh` always builds together, so the bump costs nothing.
pub const WIRE_SAMPLES_VERSION: u32 = 2;

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

    /// The post-warmup plateau ratio of the **TOTAL durable footprint** (store + WAL):
    /// `footprint_peak / footprint_min`.
    ///
    /// This is the honest counterpart to [`plateau_ratio`](Self::plateau_ratio), which measures only
    /// the store. The example's headline claim — "reclamation holds the footprint flat" — is *true of
    /// the store* (ratio 1.000) and *false of the database on disk*: the WAL sawtooths, so the total
    /// does too. Reporting only the store ratio would be a true statement about a component standing in
    /// for a false one about the whole (`rmp` #713). `None` when storage was not measured.
    #[must_use]
    pub fn durable_footprint_plateau_ratio(&self) -> Option<f64> {
        let s = self.storage.as_ref()?;
        Some(s.footprint_peak_bytes as f64 / s.footprint_min_bytes.max(1) as f64)
    }

    /// The **peak total durable footprint per byte of data image** — how many bytes of disk the
    /// database actually occupies, at its worst, for each byte of graph it holds.
    ///
    /// The single most useful resource-efficiency number this example produces, and a stable one: the
    /// peak is governed by the 64 MiB segment seal threshold, not by where the run stopped. `None` when
    /// storage was not measured or there is no data image to divide by.
    #[must_use]
    pub fn footprint_peak_over_store(&self) -> Option<f64> {
        let s = self.storage.as_ref()?;
        (s.data_bytes > 0).then(|| s.footprint_peak_bytes as f64 / s.data_bytes as f64)
    }

    /// Whether this run wrote enough WAL to **seal at least one segment** — i.e. whether it was long
    /// enough for WAL reclamation to be *possible* at all.
    ///
    /// Below [`WAL_SEGMENT_TARGET_BYTES`] no segment can have been sealed, so no WAL disk can have been
    /// freed, however many checkpoints ran. A run that has not crossed this line cannot certify
    /// reclamation — and a gate that demanded reclamation of such a run would be demanding the
    /// impossible, while a gate that stayed silent about it would be vacuous. The gate branches on this
    /// predicate and asserts something load-bearing either way. `None` when storage was not measured.
    #[must_use]
    pub fn sealed_a_segment(&self) -> Option<bool> {
        self.storage
            .as_ref()
            .map(|s| s.wal_written_bytes >= WAL_SEGMENT_TARGET_BYTES)
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

    /// The **storage half of the invariant gate** (`rmp` #713): everything that can be decided from the
    /// measured samples alone, with no `/metrics` and no network.
    ///
    /// It lives in the library rather than in `iot_wire_evidence` for one reason: **a gate nobody can
    /// test is a gate nobody can trust.** The defect this example is remediating is precisely a gate
    /// that could not fire — `bytes_per_node` compared `0.0` against `0.0` and printed PASS for months.
    /// Here the rules are a pure function of a value, so [the unit tests below](#tests) can hand it a
    /// run with a zeroed WAL and *prove* it fails. Returns one human-readable failure per violated rule;
    /// an empty vector means every storage invariant held.
    ///
    /// Returns no failures at all when `storage` is absent (attach mode): a gate must not punish a run
    /// for being unable to measure what is on another host — that is what `measurement_mode: external`
    /// and the absent fields already say.
    #[must_use]
    pub fn storage_gate(&self, g: &StorageGate) -> Vec<String> {
        let mut failures = Vec::new();
        let Some(st) = self.storage.as_ref() else {
            return failures;
        };

        // 1. THE STORE PLATEAU — the example's original claim, and it does hold.
        match self.plateau_ratio() {
            Some(r) if r <= g.plateau_factor => {}
            Some(r) => failures.push(format!(
                "the on-disk store did NOT plateau: the post-warmup data image spans [{}, {}]B, a \
                 ratio of {r:.3} (> {:.2}) — reclamation is not keeping up with the churn, so the \
                 footprint is growing without bound",
                st.plateau_min_data_bytes, st.plateau_max_data_bytes, g.plateau_factor
            )),
            None => failures.push("the store plateau could not be computed".to_owned()),
        }

        // 2. THE ANTI-ROT GATE. This example's whole subject is sustained write churn, so a report with
        //    NO write-durability evidence is not a passing run — it is a BROKEN run that looks like one.
        //    That is exactly how it rotted: the WAL is a DIRECTORY, a leaf-name classifier scored every
        //    segment as store, and the example published `wal_bytes: 0` / `bytes_fsynced: 0` /
        //    `write_amplification: 0` for months while asserting a green plateau over the top.
        let commits = self.ingest_ops.saturating_add(self.delete_ops);
        if commits > 0 {
            if st.wal_bytes == 0 && st.wal_written_bytes == 0 {
                failures.push(format!(
                    "{commits} write statements were committed, yet the measured WAL footprint is ZERO \
                     (wal_bytes=0, wal_written_bytes=0). A commit is not durable until its redo record \
                     is fsynced, so a real file-backed run CANNOT have committed {commits} writes and \
                     written no WAL. This is a MEASUREMENT defect, not a server that writes nothing — \
                     the classic cause is classifying the WAL by leaf file NAME (its segments are called \
                     `seg.<lsn>` and live inside a `graphus.wal/` DIRECTORY, so the name contains no \
                     'wal'), which scores every WAL byte as store"
                ));
            }
            if st.wal_written_bytes == 0 {
                failures.push(format!(
                    "bytes_fsynced would be 0 with {commits} commits — the cumulative WAL volume IS the \
                     durable-sync volume, and it cannot be zero while commits were acknowledged"
                ));
            }
            if self.logical_ingested_bytes == 0 {
                failures.push(
                    "logical_ingested_bytes is 0, so write_amplification cannot be computed and would \
                     be omitted — an ingest example MUST measure the payload it asked the server to \
                     store, or its amplification evidence is unfalsifiable"
                        .to_owned(),
                );
            }
        }

        // 3. WRITE AMPLIFICATION — a first-class, GATED signal, not a number buried in the notes.
        //    A CEILING, not a target: the figure is bad today, and an upper bound is the only honest way
        //    to gate a known-bad number. It cannot be satisfied by regressing, and it does not have to be
        //    relaxed to accept a fix.
        match self.write_amplification() {
            Some(w) if w > g.max_write_amplification => failures.push(format!(
                "WRITE AMPLIFICATION REGRESSED: {w:.1}x physical bytes per logical byte ingested \
                 (ceiling {:.0}x). The run wrote {} durable bytes ({} cumulative WAL + {} data image) \
                 to store {} logical bytes of readings. Raise the ceiling ONLY with evidence that the \
                 increase is intended",
                g.max_write_amplification,
                st.wal_written_bytes.saturating_add(st.data_bytes),
                st.wal_written_bytes,
                st.data_bytes,
                self.logical_ingested_bytes,
            )),
            Some(_) => {}
            None => failures.push(
                "write_amplification was NOT MEASURED on a file-backed run — the one number this \
                 example exists to publish is missing"
                    .to_owned(),
            ),
        }

        // 3b. THE ANTI-UNDER-COUNT FLOOR — every commit MUST have fsynced a redo record.
        //
        // The ceiling above only catches the engine getting worse. It cannot catch the INSTRUMENT
        // breaking, and a broken instrument is what this task is remediating. Under-count the WAL and
        // amplification *falls*, sailing under any ceiling and reading like a triumph. Nor is an
        // amplification floor enough: the data image alone is already ~1.2x the logical payload, so a
        // mis-measured WAL can still clear a 2x floor by coincidence.
        //
        // The sharp invariant is a physical one, and it does not care how big the store happens to be:
        // **a commit is not acknowledged until its redo record is durable** (ARIES write-ahead logging;
        // Mohan et al. 1992, §3). So N commits imply at least N redo records, and one `LogRecord` header
        // alone is ~53 bytes (`graphus-wal/src/record.rs`). A run reporting fewer than
        // `min_wal_bytes_per_commit` bytes of WAL per commit has therefore not discovered an
        // extraordinarily efficient engine — it has stopped counting bytes the engine is still writing.
        if commits > 0 && st.wal_written_bytes / commits < g.min_wal_bytes_per_commit {
            failures.push(format!(
                "WAL VOLUME IS PHYSICALLY IMPOSSIBLE: {} B of WAL across {commits} commits = {} B per \
                 commit (floor {} B). A commit is not durable — and is not acknowledged — until its redo \
                 record is fsynced, and one WAL record header alone is ~53 B. This is a MEASUREMENT \
                 defect, not an efficient engine: durable bytes are being written and NOT COUNTED. The \
                 classic cause is missing some or all of the WAL, which is a DIRECTORY of `seg.<lsn>` \
                 files whose leaf names contain no 'wal' — a name-based classifier scores them as store \
                 and this example then publishes `wal_bytes: 0` while asserting a green plateau",
                st.wal_written_bytes,
                st.wal_written_bytes / commits,
                g.min_wal_bytes_per_commit,
            ));
        }

        // 4. THE TOTAL DURABLE FOOTPRINT — the claim judged against the DATABASE, not one component of
        //    it. The store plateaus (rule 1). The database on disk does not, because the WAL does not.
        match self.footprint_peak_over_store() {
            Some(r) if r <= g.max_footprint_ratio => {}
            Some(r) => failures.push(format!(
                "TOTAL DURABLE FOOTPRINT REGRESSED: at its post-warmup peak the database occupied {} B \
                 on disk to hold a {} B data image — {r:.0}x (ceiling {:.0}x). The store plateaus; the \
                 database does not, because WAL disk is freed only in whole 64 MiB segments (rmp #706)",
                st.footprint_peak_bytes, st.data_bytes, g.max_footprint_ratio,
            )),
            None => failures.push(
                "the total durable footprint (store + WAL) could not be computed — the headline claim \
                 cannot be judged against the database, only against one of its components"
                    .to_owned(),
            ),
        }

        // 5. DID WAL DISK ACTUALLY COME BACK? A run long enough to seal a segment MUST show WAL disk
        //    physically returned. Note the asymmetry that keeps this monotone under a FIX: the "sealed"
        //    branch demands reclamation; the "too short to seal" branch demands nothing of it. So if
        //    #706 lands and segments become small, short runs start sealing and reclaiming too — and
        //    they pass. A gate that failed on an improvement would be worse than no gate at all.
        if self.sealed_a_segment() == Some(true) && st.wal_reclaim_events == 0 {
            failures.push(format!(
                "the run wrote {} B of WAL — past the {WAL_SEGMENT_TARGET_BYTES} B segment seal \
                 threshold, so at least one segment WAS sealed — yet the on-disk WAL never once shrank: \
                 NO WAL disk was ever reclaimed. Sealed segments below the reclaim floor are not being \
                 deleted",
                st.wal_written_bytes,
            ));
        }

        failures
    }
}

/// The ceilings and bounds [`WireSamples::storage_gate`] holds a run to.
///
/// Every figure is an **upper bound**, deliberately: the durability cost this example measures is bad
/// today (`rmp` #706 is open), and a bound is the only honest way to gate a known-bad number — it cannot
/// be satisfied by regressing, and it never has to be relaxed to accept a fix.
#[derive(Debug, Clone, Copy)]
pub struct StorageGate {
    /// How far the post-warmup STORE footprint may span (max/min) and still count as a plateau.
    pub plateau_factor: f64,
    /// Ceiling on physical durable bytes written per logical byte ingested.
    pub max_write_amplification: f64,
    /// **Floor** on WAL bytes written per commit — the anti-UNDER-count half of the gate, and the rule
    /// that makes the `wal_bytes: 0` rot un-publishable.
    ///
    /// A ceiling only catches the engine getting worse; it cannot catch the *instrument* breaking, since
    /// an under-counted WAL makes every amplification figure *fall*. This floor encodes the physics
    /// instead: a commit is not acknowledged until its redo record is fsynced, so N commits imply at
    /// least N redo records — and one `LogRecord` header alone is ~53 B. It is independent of store size,
    /// so (unlike an amplification floor) it cannot be satisfied by coincidence.
    pub min_wal_bytes_per_commit: u64,
    /// Ceiling on the peak total durable footprint (store + WAL) per byte of data image.
    pub max_footprint_ratio: f64,
}

impl Default for StorageGate {
    /// The bounds the example ships with. The ceilings sit just above the values measured on the
    /// `reclaim` profile (write amplification ~799x, peak footprint ~347x) — close enough to catch a
    /// regression, clear enough not to flap. The floor sits two orders of magnitude below the measured
    /// ~21 KB of WAL per commit, so it can only ever fire on a broken measurement, never on a real
    /// engine — however much #706 improves it.
    fn default() -> Self {
        Self {
            plateau_factor: 1.10,
            max_write_amplification: 1_000.0,
            min_wal_bytes_per_commit: 64,
            max_footprint_ratio: 450.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run shaped like the REAL `reclaim`-profile measurement (`rmp` #713): 7,000 readings ingested
    /// over 140 ticks into a flat 229,376 B data image, protected by 150,743,014 B of cumulative WAL
    /// that sealed and freed two 64 MiB segments on the way.
    ///
    /// Every test below starts from this healthy run and breaks exactly ONE thing, so a failing gate
    /// names the rule it caught rather than "something is wrong somewhere".
    fn healthy() -> WireSamples {
        let ticks_series = (0..140u64)
            .map(|tick| WireTick {
                tick,
                total_ingested: (tick + 1) * 50,
                live_readings: 200,
                checkpointed: (tick + 1) % 5 == 0,
                store_data_bytes: Some(229_376),
                store_bytes: Some(229_376 + 8_871_936 + 69_829),
                // A sawtooth: climbs, then drops back on the two segment reclaims.
                wal_bytes: Some(match tick {
                    0..=67 => 2_069_829 + tick * 1_000_000,
                    68..=127 => 2_069_829 + (tick - 68) * 1_100_000,
                    _ => 4_633_027 + (tick - 128) * 1_000_000,
                }),
            })
            .collect();
        WireSamples {
            version: WIRE_SAMPLES_VERSION,
            scenario: "iot-timeseries".to_owned(),
            transport: WireTransport::BoltUds,
            database: "iotdb".to_owned(),
            local: true,
            seed: 0xC0FF_EE15_600D_5EED,
            sensors: 8,
            rate: 50,
            window: 200,
            ticks: 140,
            warmup_ticks: 15,
            ingest_clients: 2,
            checkpoint_every: 5,
            ticks_series,
            total_ingested: 7_000,
            final_live_readings: 200,
            checkpoints_issued: 28,
            ingest_ops: 7_000,
            delete_ops: 135,
            retried_ops: 0,
            workload_secs: 9.4,
            logical_ingested_bytes: 189_000,
            storage: Some(WireStorage {
                data_bytes: 229_376,
                dwb_bytes: 8_871_936,
                wal_bytes: 16_505_196,
                wal_peak_bytes: 70_467_060,
                other_bytes: 69_829,
                wal_written_bytes: 150_743_014,
                plateau_min_data_bytes: 229_376,
                plateau_max_data_bytes: 229_376,
                plateau_max_data_pages: 28,
                footprint_min_bytes: 11_171_141,
                footprint_peak_bytes: 79_568_372,
                footprint_final_bytes: 25_676_337,
                wal_reclaim_events: 2,
                wal_reclaimed_bytes: 131_837_460,
                server_io_write_bytes: Some(188_534_784),
            }),
            insert_latency: None,
            delete_latency: None,
            checkpoint_latency: None,
            server_cpu_secs: None,
            server_peak_rss_bytes: None,
            schema_applied: Vec::new(),
            schema_skipped: Vec::new(),
            checks: Vec::new(),
        }
    }

    /// The real measurement passes its own gate. Without this, every test below could be satisfied by a
    /// gate that simply always fails.
    #[test]
    fn the_real_reclaim_profile_run_passes_the_gate() {
        let failures = healthy().storage_gate(&StorageGate::default());
        assert!(
            failures.is_empty(),
            "the measured reclaim-profile run must pass its own ceilings, got: {failures:#?}"
        );
    }

    /// **THE REGRESSION TEST THIS EXAMPLE EXISTS FOR** (`rmp` #713, acceptance criterion 3).
    ///
    /// The exact rot: the WAL is a *directory* of `seg.<lsn>` files, a leaf-name classifier scored every
    /// one of them as store, and the example published `wal_bytes: 0` / `bytes_fsynced: 0` /
    /// `write_amplification: 0` — for months — while asserting a green plateau over the top. A commit is
    /// not durable until its redo record is fsynced, so a file-backed run that committed 7,135 writes
    /// and wrote no WAL is not a measurement, it is a broken instrument. The gate MUST fail it.
    #[test]
    fn a_zero_wal_footprint_with_committed_writes_fails_the_gate() {
        let mut s = healthy();
        let st = s.storage.as_mut().expect("local run has storage");
        st.wal_bytes = 0;
        st.wal_written_bytes = 0;
        st.wal_peak_bytes = 0;
        st.wal_reclaim_events = 0;
        st.wal_reclaimed_bytes = 0;

        let failures = s.storage_gate(&StorageGate::default());
        assert!(
            failures.iter().any(|f| f.contains("WAL footprint is ZERO")),
            "a zeroed WAL alongside {} committed writes MUST fail the gate; got: {failures:#?}",
            s.ingest_ops + s.delete_ops,
        );
        assert!(
            failures
                .iter()
                .any(|f| f.contains("bytes_fsynced would be 0")),
            "a zero cumulative WAL means bytes_fsynced would be published as 0; got: {failures:#?}"
        );
        // …and the amplification FLOOR must fire too. This is the subtle half, and it is why the floor
        // exists at all: with the WAL zeroed, write_amplification computes to a healthy-looking 1.2x and
        // sails under any CEILING. A ceiling catches the engine getting worse; only a floor catches the
        // instrument breaking. The rot was never one bad field — it was a whole silent vector.
        assert!(
            failures
                .iter()
                .any(|f| f.contains("WAL VOLUME IS PHYSICALLY IMPOSSIBLE")),
            "a zeroed WAL collapses amplification to ~1.2x, which passes any CEILING — the per-commit \
             redo-record FLOOR must catch it; got: {failures:#?}"
        );
    }

    /// The under-count that a "is it exactly zero?" check cannot see: the WAL is measured, but only
    /// PARTIALLY (say one segment classified out of many). `wal_bytes != 0`, so the zero-check is happy;
    /// amplification quietly drops to a number that looks like a triumph. The FLOOR is what catches it.
    #[test]
    fn a_partially_counted_wal_fails_the_gate_even_though_it_is_not_zero() {
        let mut s = healthy();
        let st = s.storage.as_mut().expect("storage");
        st.wal_written_bytes = 150_743; // 0.1% of the truth — one mis-classified segment's worth
        st.wal_bytes = 150_743;
        st.wal_peak_bytes = 150_743;
        st.wal_reclaim_events = 0;
        st.wal_reclaimed_bytes = 0;

        let failures = s.storage_gate(&StorageGate::default());
        assert!(
            !failures.iter().any(|f| f.contains("WAL footprint is ZERO")),
            "the WAL is NOT zero here — that check cannot help, which is the whole point"
        );
        assert!(
            failures
                .iter()
                .any(|f| f.contains("WAL VOLUME IS PHYSICALLY IMPOSSIBLE")),
            "a 0.1%-counted WAL clears BOTH the amplification ceiling and a naive 2x amplification floor \
             (the data image alone is 1.2x the logical payload) — only the per-commit redo-record floor \
             catches it; got: {failures:#?}"
        );
    }

    /// The companion rot: the WAL is measured, but the LOGICAL payload is not — so `write_amplification`
    /// is `None`, silently omitted, and the run publishes no amplification at all while looking green.
    #[test]
    fn an_unmeasured_logical_payload_fails_the_gate() {
        let mut s = healthy();
        s.logical_ingested_bytes = 0;

        let failures = s.storage_gate(&StorageGate::default());
        assert!(
            failures
                .iter()
                .any(|f| f.contains("logical_ingested_bytes is 0")),
            "without a logical payload the amplification is unfalsifiable; got: {failures:#?}"
        );
        assert!(
            failures
                .iter()
                .any(|f| f.contains("write_amplification was NOT MEASURED")),
            "an omitted amplification must FAIL, not pass quietly; got: {failures:#?}"
        );
    }

    /// Write amplification is a CEILING, and the ceiling must actually bite.
    #[test]
    fn write_amplification_past_its_ceiling_fails_the_gate() {
        let mut s = healthy();
        // Double the WAL volume for the same logical payload: ~799x becomes ~1596x.
        s.storage.as_mut().expect("storage").wal_written_bytes = 301_486_028;

        let failures = s.storage_gate(&StorageGate::default());
        assert!(
            failures
                .iter()
                .any(|f| f.contains("WRITE AMPLIFICATION REGRESSED")),
            "a doubled WAL volume must trip the amplification ceiling; got: {failures:#?}"
        );
    }

    /// The total durable footprint (store + WAL) is gated against the DATABASE, not just the store — so
    /// a WAL that runs further ahead of its graph must fail even while the store's plateau stays a
    /// perfect 1.000. This is the check that stops a true statement about a component standing in for a
    /// false one about the whole.
    #[test]
    fn a_ballooning_total_footprint_fails_the_gate_even_when_the_store_plateaus() {
        let mut s = healthy();
        let st = s.storage.as_mut().expect("storage");
        st.footprint_peak_bytes = 229_376 * 600; // 600x the data image, past the 450x ceiling

        let failures = s.storage_gate(&StorageGate::default());
        assert_eq!(
            s.plateau_ratio(),
            Some(1.0),
            "the STORE still plateaus perfectly — that is exactly the trap"
        );
        assert!(
            failures
                .iter()
                .any(|f| f.contains("TOTAL DURABLE FOOTPRINT REGRESSED")),
            "a flat store must not excuse a database whose on-disk footprint ran away; got: {failures:#?}"
        );
    }

    /// A run that DID seal a segment but never got any WAL disk back is a reclamation failure, and is
    /// caught. (Today's engine passes this: it frees ~63 MiB per sealed segment.)
    #[test]
    fn sealing_a_segment_without_reclaiming_any_wal_disk_fails_the_gate() {
        let mut s = healthy();
        let st = s.storage.as_mut().expect("storage");
        st.wal_reclaim_events = 0;
        st.wal_reclaimed_bytes = 0;

        assert_eq!(
            s.sealed_a_segment(),
            Some(true),
            "150 MB of WAL is well past the 64 MiB seal threshold"
        );
        let failures = s.storage_gate(&StorageGate::default());
        assert!(
            failures
                .iter()
                .any(|f| f.contains("NO WAL disk was ever reclaimed")),
            "a sealed segment that is never freed must fail; got: {failures:#?}"
        );
    }

    /// The seal predicate keeps the gate MONOTONE UNDER A FIX. A run too short to seal a segment cannot
    /// reclaim WAL disk, and is not asked to — otherwise the gate would demand the impossible. Crucially
    /// it is the *sealed* branch that demands reclamation, so if `rmp` #706 lands and segments become
    /// small, short runs start sealing AND reclaiming, and still pass. A gate that failed on an
    /// improvement would be worse than no gate.
    #[test]
    fn a_run_too_short_to_seal_a_segment_is_not_asked_to_reclaim() {
        let mut s = healthy();
        let st = s.storage.as_mut().expect("storage");
        st.wal_written_bytes = 59_268_270; // the old `fast` profile: below the 64 MiB seal threshold
        st.wal_peak_bytes = 59_268_270;
        st.wal_bytes = 59_268_270;
        st.wal_reclaim_events = 0;
        st.wal_reclaimed_bytes = 0;

        assert_eq!(
            s.sealed_a_segment(),
            Some(false),
            "59 MB never reaches the 64 MiB seal threshold, so no segment can have been sealed"
        );
        let failures = s.storage_gate(&StorageGate::default());
        assert!(
            !failures
                .iter()
                .any(|f| f.contains("NO WAL disk was ever reclaimed")),
            "a run that could not possibly reclaim must not be failed for not reclaiming; got: {failures:#?}"
        );
    }

    /// Attach mode measures no storage at all, and a gate must not punish a run for being unable to see
    /// a filesystem on another host — `measurement_mode: external` plus the absent fields already say
    /// so. (The zero-placeholder rule is what keeps this honest: absent means NOT MEASURED.)
    #[test]
    fn attach_mode_measures_no_storage_and_is_not_gated_on_it() {
        let mut s = healthy();
        s.local = false;
        s.storage = None;

        assert!(
            s.storage_gate(&StorageGate::default()).is_empty(),
            "an attached run cannot measure the target's disk and must not be failed for it"
        );
    }

    /// The total durable footprint is store + WAL — both, and nothing invented. A tick that measured
    /// only one of them cannot report a total.
    #[test]
    fn the_durable_footprint_is_the_store_plus_the_wal() {
        let t = WireTick {
            tick: 0,
            total_ingested: 50,
            live_readings: 50,
            checkpointed: false,
            store_data_bytes: Some(229_376),
            store_bytes: Some(9_171_141),
            wal_bytes: Some(2_000_000),
        };
        assert_eq!(t.durable_bytes(), Some(11_171_141));

        let unmeasured = WireTick {
            wal_bytes: None,
            ..t
        };
        assert_eq!(
            unmeasured.durable_bytes(),
            None,
            "a footprint with an unmeasured half is NOT MEASURED, never a partial total"
        );
    }
}
