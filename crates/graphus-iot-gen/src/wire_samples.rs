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

/// The **maximum** size at which the WAL seals its active segment and rolls to a new one
/// (`graphus_wal::sink::DEFAULT_SEGMENT_TARGET_BYTES`, `crates/graphus-wal/src/sink.rs`).
///
/// Replicated here as a plain constant rather than imported, so the wire driver and its gate keep
/// building with `--no-default-features --features wire` (client-only: no engine, no WAL crate).
///
/// Since `rmp` #706 the seal size is **store-proportional** — `clamp(store_bytes, 1 MiB, 64 MiB)`
/// ([`graphus_wal::segment_target_for_store`]) — so a small database seals *small* segments and its WAL
/// disk actually comes back. This 64 MiB value is the CAP of that range. It is still load-bearing
/// evidence here as a **conservative** lower bound: **WAL disk is reclaimed in whole segment units**, so
/// a run that has written at least this much WAL has certainly sealed at least one segment (even at the
/// 64 MiB cap, and many more at the proportional size), so reclamation was *observable* — which is why
/// the wire run is sized to cross it ([`GenConfig::reclaim`], `rmp` #713 / #706). A run shorter than this
/// cannot be *certain* it sealed a segment, so the gate asks nothing of its reclamation (see
/// [`WireSamples::sealed_a_segment`]).
pub const WAL_SEGMENT_TARGET_BYTES: u64 = 64 * 1024 * 1024;

/// The **floor** of the store-proportional segment-seal band
/// (`graphus_wal::sink::WAL_SEGMENT_MIN_TARGET_BYTES`, `rmp` #706): a segment seals at
/// `clamp(store_bytes, 1 MiB, 64 MiB)`, so a small database seals **1 MiB** segments.
///
/// Replicated here as a plain constant for the same reason as [`WAL_SEGMENT_TARGET_BYTES`]: the wire
/// driver and its gate are client-only and never link the WAL crate.
///
/// This is what makes [`WireSamples::sealed_a_segment`] SHARP (`rmp` #745). It used to test the run's WAL
/// volume against the 64 MiB **cap**, which was a sound-but-blunt lower bound while ingest committed once
/// per reading and wrote ~143 MB of WAL. Batched ingest writes ~50 MB — still ~50 sealed segments for
/// this store, and 29 observed reclamations — but it falls *below the 64 MiB cap*, so the old predicate
/// would have answered "cannot certify a seal" and quietly excused the run from proving that WAL disk
/// came back at all. A gate that a 3.8x efficiency win turns vacuous is not a gate; the predicate now
/// asks the question the engine actually answers.
pub const WAL_SEGMENT_MIN_TARGET_BYTES: u64 = 1024 * 1024;

/// The size at which the WAL seals a segment for a store of `store_bytes` — `clamp(store, 1 MiB, 64 MiB)`
/// (`graphus_wal::segment_target_for_store`, `rmp` #706). Restated here (client-only build); pinned
/// against the engine's own rule by the unit tests.
#[must_use]
pub fn segment_target_for_store(store_bytes: u64) -> u64 {
    store_bytes.clamp(WAL_SEGMENT_MIN_TARGET_BYTES, WAL_SEGMENT_TARGET_BYTES)
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
    /// Readings per ingest statement (and per commit) during this tick — the **batch size** this tick
    /// ran under (`rmp` #745). The main churn runs at `--batch N`; the trailing control segment runs at
    /// `1`, so the per-reading durability cost of the two shapes can be measured on the same server, the
    /// same database and the same steady state.
    pub batch: u64,
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
    /// on-disk `wal_bytes` alone badly understates once reclamation starts.
    ///
    /// # The under-count this field used to carry, and what fixed it (`rmp` #745)
    ///
    /// The reconstruction above is only sound **if every segment is observed at its final length before
    /// it is deleted**. It used to be refreshed ONCE PER TICK, and that premise broke: the `batch = 1`
    /// control writes over 1 MiB of WAL per tick against a store-proportional seal size of exactly 1 MiB
    /// ([`segment_target_for_store`]), so a segment could be created, filled, sealed AND reclaimed
    /// *between two consecutive samples* — never observed, or observed far below its sealed length. The
    /// loss was ONE-SIDED (always an under-count, never an over-count: files are append-only and are
    /// never truncated, so a per-path maximum can only be too small) and HOST-SPEED DEPENDENT (it is a
    /// function of write-rate over sample-rate), which made the published write amplification neither
    /// correct nor reproducible.
    ///
    /// It is now sampled by a **dedicated high-frequency sampler thread** (every
    /// `WAL_SAMPLE_INTERVAL_MS`, `iot_wire`), live for the whole run, so no segment can live and die
    /// unobserved. Two gates keep it honest rather than merely hoping:
    /// [`wal_written_floor`](WireSamples::wal_written_floor) (the run's own on-disk series forces a
    /// lower bound on this figure — see [`WireSamples::instrument_gate`]) and the exact
    /// [`wal_attribution`](WireSamples::wal_attribution) reconciliation.
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

/// How the run's **cumulative WAL volume is attributed, byte for byte, to the phase that wrote it**
/// (`rmp` #745).
///
/// The two compared segments used to be published beside a run total they did not add up to: 34.78 MB
/// (main) + 11.24 MB (control) against a 49.65 MB run total left **3.62 MB (7.3%) unattributed** — the
/// warmup segment, which was measured into an accumulator and then never published, plus the WAL the
/// post-churn functional checks wrote. Evidence whose parts do not sum to its whole is evidence a reader
/// cannot check, and an unattributed remainder is exactly where a measurement defect hides.
///
/// Every byte now lands in exactly one of these buckets, and [`WireSamples::instrument_gate`] FAILS the
/// run if they do not sum to [`WireStorage::wal_written_bytes`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WalAttribution {
    /// Everything the engine wrote **before the churn loop began**: creating the database, applying the
    /// schema DDL (six indexes and constraints), and creating the sensor fleet.
    pub bootstrap_bytes: u64,
    /// The **growth ramp**: the ticks before the retention window has filled, where nothing has aged out
    /// yet and the store is still extending. Driven and counted in the run's totals, but excluded from
    /// both compared segments — charging the ramp to one of them and not the other would divide two
    /// different workloads into each other.
    pub warmup_bytes: u64,
    /// The **batched main segment**, in steady state.
    pub main_bytes: u64,
    /// The **`batch = 1` control segment**, in the same steady state.
    pub control_bytes: u64,
    /// The WAL written by the **post-churn functional checks** (the payload read-back's rejected writes:
    /// a duplicate `Sensor.id`, an INTEGER `ts`, a STRING `ts`, a `Reading` with no `value` — each a real
    /// transaction that begins and aborts, and an abort is durable work too).
    pub post_run_bytes: u64,
}

impl WalAttribution {
    /// The sum of every bucket — which MUST equal [`WireStorage::wal_written_bytes`].
    #[must_use]
    pub fn total(&self) -> u64 {
        self.bootstrap_bytes
            .saturating_add(self.warmup_bytes)
            .saturating_add(self.main_bytes)
            .saturating_add(self.control_bytes)
            .saturating_add(self.post_run_bytes)
    }
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

/// The durable write cost of one measured **ingest segment** (`rmp` #745).
///
/// The example's headline is that *per-reading commits* dominate the durability bill, so the run
/// measures **both** shapes — a `batch = N` main segment and a short `batch = 1` control segment — on the
/// same server, the same database and the same steady state, and reports the two write amplifications
/// side by side. The batch-1 figure is **measured**, never derived by arithmetic from the batched one:
/// the whole claim is about what the engine actually writes, and an arithmetic estimate would be a
/// model of the engine dressed up as an observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireSegment {
    /// Human-readable label (`"batch=50 (main)"` / `"batch=1 (control)"`).
    pub label: String,
    /// Readings per ingest statement — and therefore per commit — in this segment, **as measured**: the
    /// segment's readings over its ingest commits, rounded. It is NOT the `--batch` knob (that is
    /// [`batch_cap`](Self::batch_cap)), because a commit that carried 25 readings must not be labelled
    /// `batch=50`. [`readings_per_commit`](Self::readings_per_commit) re-derives the un-rounded figure so
    /// the label can be checked against the run that produced it.
    pub batch: u64,
    /// The `--batch` knob: the CAP on how many readings one commit may carry (a gateway's flush buffer).
    /// A commit can carry fewer — a tick is a barrier and the shards' per-tick shares are uneven — but
    /// never more, which the segment gate checks.
    pub batch_cap: u64,
    /// First tick of the segment (inclusive).
    pub first_tick: u64,
    /// One past the last tick of the segment (exclusive).
    pub next_tick: u64,
    /// Readings ingested in this segment.
    pub readings: u64,
    /// **Commits** in this segment: the ingest statements (each its own auto-commit transaction) plus
    /// the per-tick retention `DETACH DELETE`s. The denominator of "WAL bytes per commit".
    pub commits: u64,
    /// Just the **ingest** statements (each one commit) — the denominator of "readings per commit".
    pub ingest_commits: u64,
    /// The logical payload the client asked the server to store in this segment (the same per-reading
    /// figure the whole-run `logical_ingested_bytes` sums).
    pub logical_bytes: u64,
    /// Cumulative WAL bytes the engine wrote **during** this segment (the segment's delta of the
    /// run-wide cumulative WAL volume). `None` in attach mode (no store access).
    ///
    /// This is the WHOLE segment's bill: its ingest **plus** the fixed per-tick cost every tick pays
    /// regardless of batch size. See [`ingest_wal_bytes`](Self::ingest_wal_bytes).
    pub wal_written_bytes: Option<u64>,

    // ---- the WAL bill, decomposed BY PHASE (`rmp` #745) ----
    //
    // Both segments carry an identical per-tick FIXED cost that batching cannot touch: the retention
    // `DETACH DELETE` of a tick's worth of aged-out readings, and the amortised `CHECKPOINT DATABASE`.
    // Writing the comparison as `(50·A1 + F) / (2·A25 + F)` makes the problem obvious — F appears in BOTH
    // numerators and DILUTES the ratio, so the whole-segment saving is a FLOOR on the ingest saving, and
    // the residual is NOT "the WAL format": it contains F, which is neither the format nor the commit
    // rate. The driver therefore takes a WAL mark at each PHASE BOUNDARY INSIDE the tick — before
    // ingest, after ingest, after the DELETE, after the CHECKPOINT — so each term is measured separately
    // and exactly, and the headline comparison can be made on the ingest term alone, where F cancels by
    // construction.
    /// WAL written by this segment's **INGEST** phase alone: the window from the start of a tick's ingest
    /// to the drain of its barrier, summed over the segment's ticks. This is the term batching acts on,
    /// and the only sound basis for the batch = 1 vs batch = N comparison. `None` in attach mode.
    pub ingest_wal_bytes: Option<u64>,
    /// WAL written by this segment's per-tick **retention `DETACH DELETE`** — a fixed cost paid
    /// regardless of the ingest batch size. `None` in attach mode.
    pub retention_wal_bytes: Option<u64>,
    /// WAL written by this segment's **`CHECKPOINT DATABASE`** statements — a fixed cost paid regardless
    /// of the ingest batch size. `None` in attach mode.
    pub checkpoint_wal_bytes: Option<u64>,
    /// WAL written **BETWEEN the phases** — after a tick's checkpoint mark and before the next tick's
    /// pre-ingest mark (the per-tick live-count query, and any background maintenance pass that fired in
    /// that gap).
    ///
    /// Small (~0.5% of a segment), and named rather than left as a silent residual — because the three
    /// phases above plus this one MUST sum to [`wal_written_bytes`](Self::wal_written_bytes), and
    /// [`WireSamples::instrument_gate`] fails the run if they do not. An unaccounted remainder inside a
    /// segment is the same defect, one level down, as the unattributed 7.3% that used to sit between the
    /// segments and the run total: it is where a measurement error hides. `None` in attach mode.
    pub other_wal_bytes: Option<u64>,
    /// Ticks this segment ran (`next_tick - first_tick`), the denominator of the per-tick fixed cost.
    pub ticks: u64,

    /// Growth of the durable data image across this segment, saturating at `0` — at steady state the
    /// store plateaus, so this is usually zero and the WAL is the whole durable bill. `None` in attach
    /// mode.
    pub store_growth_bytes: Option<u64>,
    /// Wall-clock seconds the segment took.
    pub secs: f64,
    /// Real latency of this segment's ingest **statements** (one statement = `batch` readings).
    pub ingest_latency: Option<WireLatency>,
}

impl WireSegment {
    /// **Write amplification of this segment**: physical durable bytes written (its WAL volume plus any
    /// growth of the data image) per logical byte ingested. `None` when the storage was not measured
    /// (attach mode) or the segment ingested nothing.
    ///
    /// This is the WHOLE-SEGMENT figure, and it includes the fixed per-tick retention + checkpoint cost
    /// ([`fixed_wal_per_tick`](Self::fixed_wal_per_tick)) that batching cannot touch. For the batch = 1
    /// vs batch = N comparison use [`ingest_write_amplification`](Self::ingest_write_amplification),
    /// where that fixed term cancels by construction. Both are reported.
    #[must_use]
    pub fn write_amplification(&self) -> Option<f64> {
        let wal = self.wal_written_bytes?;
        if self.logical_bytes == 0 {
            return None;
        }
        let physical = wal.saturating_add(self.store_growth_bytes.unwrap_or(0));
        Some(physical as f64 / self.logical_bytes as f64)
    }

    /// **INGEST-ONLY write amplification** — the sound basis for comparing two ingest shapes (`rmp` #745).
    ///
    /// Physical durable bytes written *by the ingest itself* (the WAL of the ingest phase, plus any
    /// growth of the data image, which ingest is what causes) per logical byte ingested. The per-tick
    /// retention `DELETE` and `CHECKPOINT` — identical in both segments, and untouchable by batching —
    /// are excluded, so a ratio of two of these figures measures the batch size and nothing else.
    ///
    /// `None` when the phase marks were not taken (attach mode) or the segment ingested nothing.
    #[must_use]
    pub fn ingest_write_amplification(&self) -> Option<f64> {
        let wal = self.ingest_wal_bytes?;
        if self.logical_bytes == 0 {
            return None;
        }
        let physical = wal.saturating_add(self.store_growth_bytes.unwrap_or(0));
        Some(physical as f64 / self.logical_bytes as f64)
    }

    /// WAL bytes the ingest phase wrote per **reading** — the per-element durability cost of the ingest
    /// shape, with the fixed per-tick overhead excluded. `None` when unmeasured.
    #[must_use]
    pub fn ingest_wal_per_reading(&self) -> Option<f64> {
        let wal = self.ingest_wal_bytes?;
        (self.readings > 0).then(|| wal as f64 / self.readings as f64)
    }

    /// **F — the fixed WAL cost of one tick**, in bytes: the retention `DETACH DELETE` plus the amortised
    /// `CHECKPOINT DATABASE`, paid *regardless of the ingest batch size*.
    ///
    /// Published as its own named line rather than left to dilute the batch comparison. `None` when the
    /// phase marks were not taken (attach mode) or the segment ran no tick.
    #[must_use]
    pub fn fixed_wal_per_tick(&self) -> Option<f64> {
        let fixed = self
            .retention_wal_bytes?
            .saturating_add(self.checkpoint_wal_bytes?);
        (self.ticks > 0).then(|| fixed as f64 / self.ticks as f64)
    }

    /// The share of this segment's whole WAL bill that is the fixed per-tick cost F — the fraction of the
    /// segment's durability that batching *cannot* touch. `None` when unmeasured.
    #[must_use]
    pub fn fixed_wal_share(&self) -> Option<f64> {
        let total = self.wal_written_bytes?;
        let fixed = self
            .retention_wal_bytes?
            .saturating_add(self.checkpoint_wal_bytes?);
        (total > 0).then(|| fixed as f64 / total as f64)
    }

    /// WAL bytes written per commit in this segment — the figure batching actually moves (a commit's
    /// redo/undo overhead is paid once per *transaction*, not once per reading). `None` when unmeasured.
    #[must_use]
    pub fn wal_bytes_per_commit(&self) -> Option<f64> {
        let wal = self.wal_written_bytes?;
        (self.commits > 0).then(|| wal as f64 / self.commits as f64)
    }

    /// WAL bytes written per **reading** — the per-element durability cost, and the number the two
    /// segments are really being compared on. `None` when unmeasured.
    #[must_use]
    pub fn wal_bytes_per_reading(&self) -> Option<f64> {
        let wal = self.wal_written_bytes?;
        (self.readings > 0).then(|| wal as f64 / self.readings as f64)
    }

    /// The **measured** readings per ingest commit — re-derived from the run rather than taken from the
    /// CLI knob, so a segment whose label claims one batch size while its commits carried another is
    /// caught rather than published. `None` when the segment made no ingest commit.
    #[must_use]
    pub fn readings_per_commit(&self) -> Option<f64> {
        (self.ingest_commits > 0).then(|| self.readings as f64 / self.ingest_commits as f64)
    }

    /// Readings ingested per second in this segment.
    #[must_use]
    pub fn readings_per_sec(&self) -> Option<f64> {
        (self.secs > 0.0).then(|| self.readings as f64 / self.secs)
    }
}

/// One **reader family**'s gated results: what the concurrent read mix asked for, and whether the server
/// answered with exactly the rows the generator's own stream says must be there (`rmp` #745).
///
/// Every read is checked against ground truth, never merely counted. The two failure counters are the
/// point of the whole family:
///
/// * `mismatches` — the server returned a row the generator never produced, a row whose stored payload
///   differs from the generated one, or dropped a row that was provably live.
/// * `empty_but_expected` — the query returned **nothing** where rows provably existed. That is the exact
///   signature of `rmp` #738 (an index that silently answers with an empty set instead of declining), and
///   it is invisible to any check that only counts rows or compares two results the same broken index
///   produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireReaderFamily {
    /// The family's name (`windowed-composite` / `per-sensor-aggregate` / `temporal-window`).
    pub name: String,
    /// The Cypher shape it drives (recorded verbatim so the report says what was actually run).
    pub cypher: String,
    /// Queries executed.
    pub queries: u64,
    /// Queries whose window lay **strictly inside** the retained band for the whole of the query, so the
    /// result was gated as an **exact set equality** against the generator's stream.
    pub exact_gated: u64,
    /// Queries whose window straddled the moving retention frontier, so the result was gated with the
    /// sound two-sided bound instead (`returned ⊆ generated` and `returned ⊇ provably-still-live`).
    /// Concurrency makes this unavoidable; a run that could ONLY produce these would be weakly gated,
    /// which is why the gate demands a floor of `exact_gated`.
    pub bounded_gated: u64,
    /// Rows the family's queries returned in total.
    pub rows_returned: u64,
    /// Rows whose stored payload was compared, field by field, against the generator's ground truth.
    pub rows_verified: u64,
    /// Ground-truth violations (see the type docs).
    pub mismatches: u64,
    /// Queries that returned an empty result where rows provably existed (the `rmp` #738 signature).
    pub empty_but_expected: u64,
    /// Real latency of this family's queries.
    pub latency: Option<WireLatency>,
    /// The first few failures, in full, so a red run says what went wrong without a re-run.
    pub failure_samples: Vec<String>,
}

/// The concurrent read mix that ran **during** the churn (`rmp` #745).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireReaders {
    /// Independent Bolt connections issuing reads while the writers churned.
    pub clients: u64,
    /// Wall-clock seconds the reader pool was live (it starts and stops with the churn loop).
    pub secs: f64,
    /// Terminal (non-retriable) errors the readers hit. MUST be zero: a read of a live database under
    /// concurrent churn is not allowed to fail.
    pub errors: u64,
    /// The first few error messages, verbatim.
    pub error_samples: Vec<String>,
    /// One entry per read family.
    pub families: Vec<WireReaderFamily>,
}

impl WireReaders {
    /// Total queries the mix executed.
    #[must_use]
    pub fn total_queries(&self) -> u64 {
        self.families.iter().map(|f| f.queries).sum()
    }

    /// Total ground-truth violations across every family (`0` on a healthy run).
    #[must_use]
    pub fn total_mismatches(&self) -> u64 {
        self.families
            .iter()
            .map(|f| f.mismatches + f.empty_but_expected)
            .sum()
    }

    /// Total rows whose payload was verified against the generator's stream.
    #[must_use]
    pub fn total_rows_verified(&self) -> u64 {
        self.families.iter().map(|f| f.rows_verified).sum()
    }

    /// Read throughput over the churn window, in queries/second.
    #[must_use]
    pub fn queries_per_sec(&self) -> Option<f64> {
        (self.secs > 0.0).then(|| self.total_queries() as f64 / self.secs)
    }
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
    /// Readings per ingest statement (and per commit) in the MAIN segment — a real gateway batches
    /// (`rmp` #745).
    ///
    /// This is the **MEASURED** mean readings per ingest commit, not the `--batch` knob (which is a
    /// *cap*, [`WireSegment::batch_cap`]). Two real things keep a commit below the cap: a tick is a
    /// barrier (the retention `DELETE` must never race the ingest it would conflict with), so a shard can
    /// only flush what that tick gave it (~`rate / ingest-clients`); and the seeded generator's
    /// sensor assignment makes the shards' per-tick shares uneven. Publishing the requested figure would
    /// label a commit of 25 readings `batch=50` — a field not carrying the quantity its name promises,
    /// which the segment gate now refuses.
    pub batch: u64,
    /// Ticks of the trailing `batch = 1` CONTROL segment, measured separately so the per-reading
    /// durability cost of the two ingest shapes can be compared honestly.
    pub control_batch1_ticks: u64,

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

    /// The measured ingest segments — the `batch = N` main run and the `batch = 1` control — each with
    /// its own **measured** write amplification (`rmp` #745).
    pub segments: Vec<WireSegment>,
    /// Every cumulative WAL byte the run wrote, attributed to the phase that wrote it. Its buckets MUST
    /// sum to `storage.wal_written_bytes`, and [`instrument_gate`](Self::instrument_gate) fails the run
    /// if they do not. `None` in attach mode (no store access). See [`WalAttribution`].
    pub wal_attribution: Option<WalAttribution>,
    /// The concurrent read mix that ran DURING the churn, gated against the generator's ground truth.
    /// `None` when `--reader-clients 0` disabled it (which the gate then reports as a weakened run).
    pub readers: Option<WireReaders>,
    /// Surviving readings whose full payload (`sensor`, `seq`, `ts`, `value`) was read back over the wire
    /// after the churn and compared, field by field, against the generator's ground truth.
    pub payload_samples_verified: u64,

    /// Real on-disk storage evidence. `None` in external mode (the store lives on another host).
    pub storage: Option<WireStorage>,

    /// Real latency of **every statement the run issued** — batched ingest, per-reading control ingest,
    /// retention `DETACH DELETE` and `CHECKPOINT DATABASE` alike (`rmp` #745).
    ///
    /// This is the population [`statement_ops`](Self::statement_ops) counts, and therefore the ONLY
    /// population whose percentiles may be published in the report's `throughput` block beside
    /// `operations` and `ops_per_sec`. The block used to carry the batched-ingest family's percentiles
    /// (n = 230) beside an `operations` count of 924 — percentiles describing ~25% of the operations they
    /// were published with, silently omitting the control's 500 per-reading commits (a p50 of 1.79 ms
    /// against the batched 7.18 ms) and 136 retention deletes. Same defect family as the `ops_per_sec`
    /// bug: the fields in one block did not describe the same thing, so a reader who related them was
    /// misled.
    ///
    /// The per-family percentiles are NOT lost — [`insert_latency`](Self::insert_latency),
    /// [`delete_latency`](Self::delete_latency), [`checkpoint_latency`](Self::checkpoint_latency) and
    /// each segment's own [`WireSegment::ingest_latency`] all survive, under names that say which family
    /// they describe.
    pub statement_latency: Option<WireLatency>,
    /// Real latency of the MAIN segment's ingest statements (each carrying [`batch`](Self::batch)
    /// readings). A FAMILY figure: see [`statement_latency`](Self::statement_latency) for the one the
    /// `throughput` block carries.
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
/// per-tick non-WAL store total to [`WireTick`].
///
/// v3 (`rmp` #745) adds the measured ingest [`segments`](WireSamples::segments) (batch = N vs the
/// batch = 1 control, each with its own measured write amplification), the concurrent, ground-truth-gated
/// read mix ([`readers`](WireSamples::readers)), and the post-churn payload read-back count. This file is
/// a private contract between `iot_wire` and `iot_wire_evidence`, which `run.sh` always builds together,
/// so the bump costs nothing.
pub const WIRE_SAMPLES_VERSION: u32 = 3;

// ==================================================================================================
// THE DECISIVE GATE: the driver's polled WAL reconstruction, cross-checked against the ENGINE'S OWN
// exact counter (`rmp` #745).
//
// It lives HERE, as a pure function, and not in the binary — for the same reason every other rule in
// this file does: a gate nobody can test is a gate nobody can trust. This one earns that place more
// than any of them. The polled reconstruction is a LOWER BOUND by construction (a WAL segment born,
// sealed and reclaimed between two samples is never observed at its sealed length), and every OTHER
// rule in this file checks the reconstruction against ITSELF — so every other rule stayed green while
// the instrument under-counted the control segment by 17%. Only a source the driver does not produce
// can catch that, and this is it. It was therefore the one rule that had to be provably falsifiable,
// and the one rule that was living, untested, in the binary.
// ==================================================================================================

/// How far the driver's polled WAL reconstruction may drift from the engine's exact counter.
///
/// Not zero, and the reason is physical rather than a fudge: the two are read at different instants
/// (the `/metrics` scrapes bracket the driver's own run, so they include a little WAL the driver's
/// window does not), and a scrape taken mid-harden trails the true offset by at most one in-flight
/// commit batch. 3% absorbs that and nothing else — the defect it exists to catch under-counted the
/// control segment by **17.2%**, and the run as a whole by **5.5%**.
pub const WAL_RECONSTRUCTION_TOLERANCE: f64 = 0.03;

/// The verdict of cross-checking the polled reconstruction against the engine's exact WAL counter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WalCrossCheck {
    /// The two agree within [`WAL_RECONSTRUCTION_TOLERANCE`]. Carries the signed drift.
    Agrees { drift: f64 },
    /// They DISAGREE: the reconstruction cannot be trusted, and every amplification figure derived
    /// from it is wrong in the flattering direction.
    Drifted {
        reconstructed: u64,
        exact: u64,
        drift: f64,
    },
    /// The target does not publish the counter, so the reconstruction is **UNVERIFIED** — which is not
    /// the same as correct, and must never be reported as a pass.
    CounterAbsent,
    /// Storage was not measured at all (attach mode): there is nothing to cross-check.
    NotApplicable,
}

impl WalCrossCheck {
    /// Cross-checks the reconstruction against the engine's exact counter.
    ///
    /// `exact` is the delta of `graphus_db_wal_bytes_written_total` across the workload window;
    /// `reconstructed` is what the driver's polling summed. An `exact` of `0` means the counter was
    /// present but the window recorded nothing — treated as ABSENT rather than as agreement, since a
    /// zero cannot corroborate anything.
    #[must_use]
    pub fn evaluate(exact: Option<u64>, reconstructed: Option<u64>) -> Self {
        match (exact, reconstructed) {
            (_, None) => Self::NotApplicable,
            (None, Some(_)) | (Some(0), Some(_)) => Self::CounterAbsent,
            (Some(exact), Some(reconstructed)) => {
                let drift = (reconstructed as f64 - exact as f64) / exact as f64;
                if drift.abs() > WAL_RECONSTRUCTION_TOLERANCE {
                    Self::Drifted {
                        reconstructed,
                        exact,
                        drift,
                    }
                } else {
                    Self::Agrees { drift }
                }
            }
        }
    }

    /// The failure this verdict raises, or `None` when the instrument is corroborated (or when there
    /// was no storage to corroborate). Both [`Drifted`](Self::Drifted) and
    /// [`CounterAbsent`](Self::CounterAbsent) FAIL: an unverifiable instrument is not a passing one.
    #[must_use]
    pub fn failure(&self, database: &str, counter: &str) -> Option<String> {
        match *self {
            Self::Agrees { .. } | Self::NotApplicable => None,
            Self::Drifted {
                reconstructed,
                exact,
                drift,
            } => Some(format!(
                "THE WAL INSTRUMENT DISAGREES WITH THE ENGINE: the driver reconstructed {reconstructed} B \
                 of cumulative WAL by polling the WAL directory, but the engine's own exact counter \
                 ({counter}, a monotone durable byte offset that reclamation never rewinds) says the \
                 workload window wrote {exact} B — a drift of {:.1}% (limit {:.0}%). The reconstruction is \
                 only sound if every segment is observed at its final length before a checkpoint deletes \
                 it; when it under-counts, write amplification FALLS and sails under every ceiling in this \
                 report while reading like a triumph. Trust the counter, and fix the sampler",
                100.0 * drift,
                100.0 * WAL_RECONSTRUCTION_TOLERANCE,
            )),
            Self::CounterAbsent => Some(format!(
                "the target does not publish {counter}{{database=\"{database}\"}}, so the driver's polled \
                 WAL reconstruction could NOT be cross-checked against the engine's exact counter. The \
                 reconstruction is inherently a LOWER BOUND (a segment born and reclaimed between two \
                 samples is never seen), and without the counter nothing here can tell a correct \
                 reconstruction from an under-counting one. Run against a server built from this tree"
            )),
        }
    }
}

impl WireSamples {
    /// Ingest throughput over the churn loop, in **readings**/second — the DOMAIN rate.
    ///
    /// This is NOT the report's `throughput.ops_per_sec`: see [`Self::statement_ops`] and
    /// [`Self::statement_ops_per_sec`]. With `--batch` the two differ by the batch factor, and
    /// conflating them would put a readings/s figure in a field whose name (and whose sibling
    /// `operations` count) promise statements. `None` when the window is degenerate (a zero-length
    /// measurement cannot yield a rate).
    #[must_use]
    pub fn ingest_per_sec(&self) -> Option<f64> {
        (self.workload_secs > 0.0).then(|| self.total_ingested as f64 / self.workload_secs)
    }

    /// The run's **operation** count, where an operation is one STATEMENT the driver issued: an
    /// ingest commit, a windowed retention `DETACH DELETE`, or a `CHECKPOINT DATABASE`.
    ///
    /// This is the unit the shared report schema's `throughput.operations` is defined in, and the unit
    /// its latency percentiles are measured in — so [`Self::statement_ops_per_sec`] is derived from it
    /// and the two stay dividable into one another.
    #[must_use]
    pub fn statement_ops(&self) -> u64 {
        self.ingest_ops
            .saturating_add(self.delete_ops)
            .saturating_add(self.checkpoints_issued)
    }

    /// The run's throughput in **statements**/second — the quantity `throughput.ops_per_sec` promises.
    ///
    /// `ops_per_sec == operations / elapsed` is an invariant a reader is entitled to assume, and it is
    /// pinned by a test. Before `--batch`, ingest was one statement per reading so a readings/s rate
    /// here was numerically identical and the error was invisible; batching separates them by ~25x.
    /// `None` when nothing ran, or over a degenerate window.
    #[must_use]
    pub fn statement_ops_per_sec(&self) -> Option<f64> {
        let ops = self.statement_ops();
        (self.workload_secs > 0.0 && ops > 0).then(|| ops as f64 / self.workload_secs)
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

    /// The logical size of the data actually retained at steady state: `final_live_readings` readings'
    /// worth of payload. The denominator of [`space_amplification`](Self::space_amplification).
    #[must_use]
    pub fn logical_live_bytes(&self) -> Option<f64> {
        if self.final_live_readings == 0 || self.total_ingested == 0 {
            return None;
        }
        let bytes_per_reading = self.logical_ingested_bytes as f64 / self.total_ingested as f64;
        let live = bytes_per_reading * self.final_live_readings as f64;
        (live > 0.0).then_some(live)
    }

    /// The **fixed preallocation**: the doublewrite buffer plus the catalog. Constant per database, and
    /// it does NOT scale with the graph — so it is reported by name and kept OUT of every amplification
    /// ratio (`examples/README.md` evidence-honesty rule 5).
    #[must_use]
    pub fn fixed_preallocation_bytes(&self) -> Option<u64> {
        let s = self.storage.as_ref()?;
        Some(s.dwb_bytes.saturating_add(s.other_bytes))
    }

    /// **Space amplification**: the durable bytes that SCALE WITH THE GRAPH (the data image + the
    /// residual WAL) per logical byte of data actually retained at steady state.
    ///
    /// # Why the doublewrite buffer is NOT in the numerator (`rmp` #745)
    ///
    /// It used to be, and the result was the lumped-footprint ratio `examples/README.md` evidence-honesty
    /// rule 5 explicitly FORBIDS: **96% of the published 1703x was the FIXED 8.87 MB doublewrite
    /// preallocation**, divided by 5,400 B of live logical data. That number moved with the *size of a
    /// constant*, not with anything the engine did to the graph — it would have read 1703x for a database
    /// holding one reading or a million, and a real regression in the bytes that DO scale would have been
    /// invisible underneath it. "A lumped total blends the data image (which scales with the graph) with
    /// a fixed-size doublewrite preallocation (which does not), producing ratios that look alarming and
    /// mean nothing."
    ///
    /// The fixed half is not hidden — it is published under its own name
    /// ([`fixed_preallocation_bytes`](Self::fixed_preallocation_bytes)), where it says what it is: a
    /// constant. This ratio now carries only the bytes a reader can act on.
    ///
    /// `None` when storage was not measured or nothing is retained.
    #[must_use]
    pub fn space_amplification(&self) -> Option<f64> {
        let s = self.storage.as_ref()?;
        let logical_live = self.logical_live_bytes()?;
        let scaling = s.data_bytes.saturating_add(s.wal_bytes);
        Some(scaling as f64 / logical_live)
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

    /// The **peak total durable footprint per byte of data image** — how many bytes of disk the database
    /// occupies, at its worst, for each byte of graph it holds.
    ///
    /// # READ THIS RATIO WITH ITS DECOMPOSITION, OR NOT AT ALL (`rmp` #745)
    ///
    /// It is a **lumped** figure, and on a small store it is dominated by a CONSTANT: of the measured
    /// 14.73 MB peak, **8.87 MB (60%) is the FIXED doublewrite preallocation**, which does not scale with
    /// the graph and cannot regress. So this number is *not* a measure of WAL behaviour, and its gate
    /// (`max_footprint_ratio`) mostly measures doublewrite-over-store. It is kept because it is the disk
    /// an operator must genuinely provision — a real question — but the quantity that actually *moves*
    /// when the engine changes is the graph-scaling part, and that is
    /// [`wal_to_store_ratio_peak`](Self::wal_to_store_ratio_peak), which carries its own, sharper ceiling.
    ///
    /// The peak is governed by the **store-proportional** segment seal size,
    /// `clamp(store_bytes, 1 MiB, 64 MiB)` ([`segment_target_for_store`], `rmp` #706) — NOT by the 64 MiB
    /// cap, which this doc claimed until `rmp` #745 corrected it, and not by where the run stopped.
    ///
    /// `None` when storage was not measured or there is no data image to divide by.
    #[must_use]
    pub fn footprint_peak_over_store(&self) -> Option<f64> {
        let s = self.storage.as_ref()?;
        (s.data_bytes > 0).then(|| s.footprint_peak_bytes as f64 / s.data_bytes as f64)
    }

    /// The share of the peak durable footprint that is the FIXED doublewrite preallocation + catalog —
    /// the constant that [`footprint_peak_over_store`](Self::footprint_peak_over_store) is mostly made of
    /// on a small store, stated out loud so the ratio cannot be misread. `None` when unmeasured.
    #[must_use]
    pub fn footprint_peak_fixed_share(&self) -> Option<f64> {
        let s = self.storage.as_ref()?;
        let fixed = self.fixed_preallocation_bytes()?;
        (s.footprint_peak_bytes > 0).then(|| fixed as f64 / s.footprint_peak_bytes as f64)
    }

    /// The size at which THIS run's WAL seals a segment: `clamp(data_bytes, 1 MiB, 64 MiB)` (`rmp` #706).
    /// `None` when storage was not measured.
    #[must_use]
    pub fn segment_seal_bytes(&self) -> Option<u64> {
        self.storage
            .as_ref()
            .map(|s| segment_target_for_store(s.data_bytes))
    }

    /// Whether this run wrote enough WAL to **seal at least one segment** — i.e. whether it was long
    /// enough for WAL reclamation to be *possible* at all.
    ///
    /// Below the seal size no segment can have been sealed, so no WAL disk can have been freed, however
    /// many checkpoints ran. A run that has not crossed that line cannot certify reclamation — and a gate
    /// that demanded reclamation of such a run would be demanding the impossible, while a gate that
    /// stayed silent about it would be vacuous. The gate branches on this predicate and asserts something
    /// load-bearing either way.
    ///
    /// The threshold is the **store-proportional** seal size ([`segment_target_for_store`]), not the
    /// 64 MiB cap (`rmp` #745). Testing against the cap was a sound-but-blunt bound while ingest wrote
    /// ~143 MB of WAL; batching cut that to ~50 MB — which still seals ~50 of this store's 1 MiB segments
    /// and reclaims 29 of them — but falls *under the cap*, so the blunt predicate would have gone
    /// `false` and excused the run from proving WAL disk ever came back. `None` when storage was not
    /// measured.
    #[must_use]
    pub fn sealed_a_segment(&self) -> Option<bool> {
        let s = self.storage.as_ref()?;
        Some(s.wal_written_bytes >= segment_target_for_store(s.data_bytes))
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

    /// The MAIN (batched) ingest segment, if the run measured one.
    #[must_use]
    pub fn main_segment(&self) -> Option<&WireSegment> {
        self.segments.iter().find(|s| s.batch > 1)
    }

    /// The `batch = 1` CONTROL segment, if the run measured one.
    #[must_use]
    pub fn control_segment(&self) -> Option<&WireSegment> {
        self.segments.iter().find(|s| s.batch == 1)
    }

    /// How much cheaper — in physical durable bytes per logical byte — the batched ingest is than the
    /// per-reading one, over the WHOLE segment. `2.0` means batching halved the durability bill. `None`
    /// unless BOTH segments were measured (never derived from one of them, `rmp` #745).
    ///
    /// **This is a FLOOR on the ingest saving, not the ingest saving.** Both segments pay an identical
    /// fixed per-tick cost F (the retention `DELETE` + the amortised `CHECKPOINT`) that batching cannot
    /// touch, and F sits in BOTH numerators of `(50·A₁ + F) / (2·A₂₅ + F)`, dragging the ratio toward 1.
    /// The headline comparison is therefore made on
    /// [`batching_ingest_write_amp_saving`](Self::batching_ingest_write_amp_saving), where F cancels by
    /// construction; this figure is published beside it, clearly labelled, because it is what a
    /// deployment running this exact retention cadence actually pays.
    #[must_use]
    pub fn batching_write_amp_saving(&self) -> Option<f64> {
        let single = self.control_segment()?.write_amplification()?;
        let batched = self.main_segment()?.write_amplification()?;
        (batched > 0.0).then_some(single / batched)
    }

    /// **THE HEADLINE COMPARISON** (`rmp` #745): how much cheaper the batched ingest is than the
    /// per-reading one, measured on the INGEST PHASE ALONE.
    ///
    /// This is the sound experiment. The two segments differ in exactly one variable — the batch size —
    /// and the fixed per-tick cost F that both of them pay (and that batching cannot touch) is EXCLUDED
    /// from both, rather than being left to dilute the ratio toward 1 and then be mistaken for "the WAL
    /// format". `None` unless BOTH segments' phase marks were taken.
    #[must_use]
    pub fn batching_ingest_write_amp_saving(&self) -> Option<f64> {
        let single = self.control_segment()?.ingest_write_amplification()?;
        let batched = self.main_segment()?.ingest_write_amplification()?;
        (batched > 0.0).then_some(single / batched)
    }

    /// The **upper end of the headline band** — and the reason the headline IS a band (`rmp` #745).
    ///
    /// The phase marks attribute WAL to the phase that was running when it was written. That is exact
    /// for everything the DRIVER issues, but the engine also runs a BACKGROUND maintenance pass on its
    /// own WAL-growth cadence, and its bytes land in whichever phase happened to be running. Those bytes
    /// are checkpoint work, not ingest work, so wherever they land inside INGEST they inflate the ingest
    /// figure — and they inflate the SMALLER (batched) one relatively more, dragging the measured saving
    /// DOWN. [`batching_ingest_write_amp_saving`](Self::batching_ingest_write_amp_saving) is therefore a
    /// FLOOR, not a point.
    ///
    /// This bounds the other end, using only measured quantities: the run knows how many background
    /// passes fired (`maintenance_checkpoints` delta MINUS the checkpoints the driver issued) and what a
    /// checkpoint costs (the measured CHECKPOINT phase / the checkpoints issued). Charging EVERY
    /// background pass to the ingest phase — the worst case for the saving — and removing it gives the
    /// upper end. The truth is inside the band; the run publishes both ends and claims neither as a point.
    ///
    /// `background_passes` is the engine's own maintenance-checkpoint count MINUS the checkpoints the
    /// driver issued (the caller reads it from `/metrics`, which is where that counter lives).
    ///
    /// `None` when the phases were not measured, or when no background pass fired at all (in which case
    /// the floor IS the value, and there is no band to publish).
    #[must_use]
    pub fn batching_ingest_write_amp_saving_upper(&self, background_passes: u64) -> Option<f64> {
        let background = background_passes;
        if background == 0 {
            return None;
        }
        // What one checkpoint costs, measured: the whole run's checkpoint-phase WAL over the checkpoints
        // the driver actually issued.
        let ckpt_wal: u64 = self
            .segments
            .iter()
            .filter_map(|s| s.checkpoint_wal_bytes)
            .sum();
        if self.checkpoints_issued == 0 || ckpt_wal == 0 {
            return None;
        }
        let per_checkpoint = ckpt_wal as f64 / self.checkpoints_issued as f64;

        let main = self.main_segment()?;
        let control = self.control_segment()?;
        let m_ing = main.ingest_wal_bytes? as f64;
        let c_ing = control.ingest_wal_bytes? as f64;
        if main.logical_bytes == 0 || control.logical_bytes == 0 {
            return None;
        }

        // HOW THE PASSES ARE ALLOCATED, AND WHY IT MATTERS.
        //
        // The background cadence fires on WAL GROWTH, so a segment attracts background passes in
        // proportion to the WAL IT WROTE — not in proportion to its ingest phase. Each segment then loses
        // an ABSOLUTE number of bytes (its share of the passes x what a checkpoint costs), which is what
        // makes this bound informative at all: the two segments lose DIFFERENT FRACTIONS of their ingest
        // (the batched segment's ingest is larger and its share of the passes larger still), so the ratio
        // MOVES.
        //
        // Splitting the smear in proportion to each segment's INGEST would remove the same fraction from
        // both and leave the ratio algebraically unchanged — a "band" whose ends are equal by
        // construction, which is a bound that bounds nothing. (It is the mistake this comment exists to
        // stop anyone making again, including me: the first version of this function did exactly that and
        // published `7.9x - 7.9x`.)
        let m_wal = main.wal_written_bytes? as f64;
        let c_wal = control.wal_written_bytes? as f64;
        let run_wal = m_wal + c_wal;
        if run_wal <= 0.0 {
            return None;
        }
        let m_passes = background as f64 * (m_wal / run_wal);
        let c_passes = background as f64 * (c_wal / run_wal);

        let m_clean = (m_ing - m_passes * per_checkpoint).max(1.0);
        let c_clean = (c_ing - c_passes * per_checkpoint).max(1.0);

        let batched = m_clean / main.logical_bytes as f64;
        let single = c_clean / control.logical_bytes as f64;
        (batched > 0.0).then_some(single / batched)
    }

    /// **The lower bound the run's own on-disk WAL series forces on
    /// [`WireStorage::wal_written_bytes`]** — the self-check that makes a broken WAL instrument fail the
    /// run instead of publishing a floor as if it were a measurement (`rmp` #745).
    ///
    /// The physics, and it admits no exception:
    ///
    /// ```text
    /// on_disk(t) = on_disk(t-1) + written(t) - reclaimed(t),   reclaimed(t) >= 0
    ///   =>  written(t) >= on_disk(t) - on_disk(t-1)
    ///   =>  Σ written  >= Σ max(0, on_disk(t) - on_disk(t-1))
    /// ```
    ///
    /// Every byte the on-disk WAL *grew* by is a byte the engine certainly wrote. Reclamation can only
    /// ever make the on-disk figure SMALLER, so the sum of the positive deltas is a hard floor under the
    /// cumulative volume — one derived from a *different* observation (the per-tick residual) than the
    /// reconstruction it checks (the per-path maxima). A reconstruction that lands BELOW it has lost
    /// bytes the engine demonstrably wrote, and is not a measurement.
    ///
    /// It cannot false-positive: the inequality is forced, so a healthy instrument always clears it.
    /// `ticks` outside `[first, next)` are ignored, which is what makes the same rule usable per-segment
    /// (where it is far sharper than run-wide — a segment's own window has nowhere to hide a loss).
    #[must_use]
    pub fn wal_written_floor(&self, first_tick: u64, next_tick: u64) -> Option<u64> {
        let mut floor = 0u64;
        let mut any = false;
        for w in self.ticks_series.windows(2) {
            let (prev, cur) = (&w[0], &w[1]);
            if cur.tick < first_tick || cur.tick >= next_tick {
                continue;
            }
            let (Some(a), Some(b)) = (prev.wal_bytes, cur.wal_bytes) else {
                continue;
            };
            any = true;
            floor = floor.saturating_add(b.saturating_sub(a));
        }
        any.then_some(floor)
    }

    /// The run-wide WAL floor: [`wal_written_floor`](Self::wal_written_floor) over every tick.
    #[must_use]
    pub fn run_wal_written_floor(&self) -> Option<u64> {
        self.wal_written_floor(0, u64::MAX)
    }

    /// The **fixed per-tick WAL cost F** the run measured — the retention `DELETE` plus the amortised
    /// `CHECKPOINT DATABASE`, paid every tick regardless of the ingest batch size. Taken from the main
    /// segment (both segments measure it, and both must agree — see [`Self::instrument_gate`]).
    #[must_use]
    pub fn fixed_wal_per_tick(&self) -> Option<f64> {
        self.main_segment()?.fixed_wal_per_tick()
    }

    /// **THE INSTRUMENT'S OWN GATE** (`rmp` #745) — the rule that makes a broken WAL instrument FAIL the
    /// run rather than quietly publish an under-count as if it were a measurement.
    ///
    /// This exists because the instrument *was* broken and nothing caught it. `wal_written_bytes` is
    /// reconstructed by polling the WAL directory and keeping the maximum length seen per segment path.
    /// That is only sound if every segment is observed at its final length before a checkpoint deletes
    /// it — and at one sample per tick it was not: the `batch = 1` control wrote >1 MiB of WAL per tick
    /// against a 1 MiB segment seal, so segments were born, sealed and reclaimed *between samples*. The
    /// published 832.8x write amplification was therefore a FLOOR, one-sided and host-speed dependent,
    /// wearing the clothes of a measurement.
    ///
    /// Note what the pre-existing `min_wal_bytes_per_commit` floor could and could not do: it catches a
    /// *grossly* broken instrument (a zeroed or 0.1%-counted WAL), but at 64 B/commit it sits ~0.5% below
    /// the real volume, so it could never have fired on a 20% under-count. The two rules below are the
    /// sharp ones, and they are sharp because they check the reconstruction against evidence it does not
    /// itself produce:
    ///
    /// 1. **The series floor.** The run's own per-tick on-disk WAL series forces a hard lower bound on
    ///    the cumulative volume ([`wal_written_floor`](Self::wal_written_floor)) — applied run-wide AND
    ///    per segment, because a segment's own window is where a loss shows up sharply and where it can
    ///    least be averaged away.
    /// 2. **The attribution reconciliation.** Every WAL byte must be attributed to exactly one named
    ///    phase (bootstrap / warmup / main / control / post-run), and those buckets must SUM to the run
    ///    total. An unattributed remainder is not a rounding artefact — it is a byte the accounting lost
    ///    track of, and it is precisely where a measurement defect hides. (This run used to leave 7.3% of
    ///    its WAL unattributed and publish the segments beside a total they did not add up to.)
    ///
    /// Returns no failures when `storage` is absent (attach mode): there is no store to instrument.
    #[must_use]
    pub fn instrument_gate(&self) -> Vec<String> {
        let mut failures = Vec::new();
        let Some(st) = self.storage.as_ref() else {
            return failures;
        };

        // 1a. The RUN-WIDE series floor.
        if let Some(floor) = self.run_wal_written_floor() {
            if st.wal_written_bytes < floor {
                failures.push(format!(
                    "THE WAL INSTRUMENT LOST BYTES: it reconstructed {} B of cumulative WAL, but the \
                     run's OWN on-disk WAL series proves at least {floor} B were written (the sum of \
                     every tick-to-tick GROWTH of the on-disk WAL — and reclamation can only ever make \
                     that figure smaller, never larger, so every one of those bytes was certainly \
                     written). A reconstruction below its own floor is not a measurement: a WAL segment \
                     was created, filled, sealed and RECLAIMED between two samples, so it was never \
                     observed at its sealed length. Sample the WAL directory faster (see \
                     WAL_SAMPLE_INTERVAL_MS in iot_wire), or read the engine's exact counter",
                    st.wal_written_bytes,
                ));
            }
        }

        // 1b. The PER-SEGMENT series floor — the sharp one. A run-wide sum can average a loss away
        //     against a segment that happened to over-observe; a segment's own window cannot.
        for seg in &self.segments {
            let (Some(measured), Some(floor)) = (
                seg.wal_written_bytes,
                self.wal_written_floor(seg.first_tick, seg.next_tick),
            ) else {
                continue;
            };
            if measured < floor {
                failures.push(format!(
                    "THE WAL INSTRUMENT LOST BYTES IN THE '{}' SEGMENT: it measured {measured} B of WAL \
                     across ticks [{}, {}), but that segment's own on-disk WAL series proves at least \
                     {floor} B were written there. Its write amplification is therefore an UNDER-COUNT, \
                     and an under-counted WAL makes amplification FALL — it sails under every ceiling and \
                     reads like a triumph",
                    seg.label, seg.first_tick, seg.next_tick,
                ));
            }
        }

        // 2a. EACH SEGMENT'S PHASES MUST RECONCILE against that segment's own WAL total. Same rule as
        //     the run-level attribution below, one level down — and it exists because the residual is
        //     exactly where an error hides. (The inter-phase gap is real and small; it is NAMED, not
        //     swept into whichever phase happens to be adjacent.)
        for seg in &self.segments {
            let (Some(total), Some(i), Some(r), Some(c), Some(o)) = (
                seg.wal_written_bytes,
                seg.ingest_wal_bytes,
                seg.retention_wal_bytes,
                seg.checkpoint_wal_bytes,
                seg.other_wal_bytes,
            ) else {
                continue;
            };
            let summed = i.saturating_add(r).saturating_add(c).saturating_add(o);
            if summed != total {
                failures.push(format!(
                    "THE '{}' SEGMENT'S PHASES DO NOT RECONCILE: ingest {i} + retention {r} + checkpoint \
                     {c} + between-phase {o} = {summed} B, but the segment measured {total} B of WAL. \
                     Every byte of a segment must belong to one of its phases; a remainder means the \
                     phase marks are not bracketing the work they claim to bracket, and the INGEST-ONLY \
                     write amplification — this example's headline — is derived from exactly those marks",
                    seg.label,
                ));
            }
        }

        // 2b. THE RUN-LEVEL ATTRIBUTION MUST RECONCILE, exactly. Not "approximately": these are byte
        //     counters read from the same monotone map at phase boundaries, so they add up or the
        //     accounting is wrong.
        match &self.wal_attribution {
            None => failures.push(
                "the run measured a WAL volume but attributed none of it to a phase — the segments would \
                 then be published beside a run total they do not add up to, and an unattributed \
                 remainder is exactly where a measurement defect hides"
                    .to_owned(),
            ),
            Some(a) if a.total() != st.wal_written_bytes => failures.push(format!(
                "THE WAL ATTRIBUTION DOES NOT RECONCILE: the phases account for {} B (bootstrap {} + \
                 warmup {} + main {} + control {} + post-run {}) but the run measured {} B of cumulative \
                 WAL — {} B are unattributed. Every WAL byte must belong to exactly one phase; a \
                 remainder means the accounting lost track of bytes the engine wrote",
                a.total(),
                a.bootstrap_bytes,
                a.warmup_bytes,
                a.main_bytes,
                a.control_bytes,
                a.post_run_bytes,
                st.wal_written_bytes,
                (a.total() as i64 - st.wal_written_bytes as i64).abs(),
            )),
            Some(_) => {}
        }

        failures
    }

    /// The **ingest-shape half of the gate** (`rmp` #745): the batch = 1 control and the batch = N main
    /// segment must BOTH be measured, and batching must actually pay.
    ///
    /// The example's headline finding is that a commit per 32-byte reading dominates the durability
    /// bill. That claim is only earned if BOTH numbers are measured on the same server; and it is only
    /// still true if the batched segment really does write less per logical byte. A run where batching
    /// made no difference is not a run to wave through — it is a finding.
    ///
    /// Returns no failures when `storage` is absent (attach mode) — the amplification cannot be measured
    /// on another host's disk — nor when the control segment was disabled (`--batch1-ticks 0`), which the
    /// report states explicitly rather than pretending to a comparison it did not make.
    #[must_use]
    pub fn segment_gate(&self, g: &StorageGate) -> Vec<String> {
        let mut failures = Vec::new();
        if self.storage.is_none() {
            return failures;
        }
        let Some(main) = self.main_segment() else {
            failures.push(
                "no batched ingest segment was measured — the run ingested nothing, or the batch \
                 accounting is broken"
                    .to_owned(),
            );
            return failures;
        };

        // THE LABEL MUST BE TRUE. A segment that calls itself `batch=50` while its commits carried 25
        // readings is publishing a figure that does not carry the quantity its name promises — and every
        // per-commit number derived from it would inherit the lie. So the declared batch must be the one
        // the run MEASURED (readings / ingest commits, to within rounding), and no commit may have
        // exceeded the cap the client asked for.
        for seg in &self.segments {
            if let Some(measured) = seg.readings_per_commit() {
                if (measured - seg.batch as f64).abs() > 0.5 {
                    failures.push(format!(
                        "the '{}' segment claims {} readings per commit, but its {} ingest commits \
                         actually carried {measured:.2} — the label does not describe the run, so every \
                         per-commit figure derived from it is misattributed",
                        seg.label, seg.batch, seg.ingest_commits,
                    ));
                }
                if measured > seg.batch_cap as f64 + 0.5 {
                    failures.push(format!(
                        "the '{}' segment committed {measured:.2} readings per commit, ABOVE the {} the \
                         client's flush buffer was capped at — the ingest is not doing what the run says \
                         it is doing",
                        seg.label, seg.batch_cap,
                    ));
                }
            }
        }

        match main.write_amplification() {
            None => failures.push(format!(
                "the batched segment '{}' has NO measured write amplification on a file-backed run — \
                 the headline durability figure of this example is missing",
                main.label
            )),
            Some(w) if w > g.max_batched_write_amplification => failures.push(format!(
                "BATCHED WRITE AMPLIFICATION REGRESSED: the '{}' segment wrote {w:.1}x physical bytes \
                 per logical byte (ceiling {:.0}x). It wrote {} B of WAL over {} commits ({} readings) \
                 to store {} logical bytes. Raise the ceiling ONLY with evidence that the increase is \
                 intended",
                main.label,
                g.max_batched_write_amplification,
                main.wal_written_bytes.unwrap_or(0),
                main.commits,
                main.readings,
                main.logical_bytes,
            )),
            Some(_) => {}
        }

        if self.control_batch1_ticks == 0 {
            return failures; // the comparison was deliberately not run; the report says so.
        }
        let Some(control) = self.control_segment() else {
            failures.push(format!(
                "the run asked for a {}-tick batch=1 CONTROL segment but none was measured — the \
                 batch=1 write amplification would then be MISSING, and this example's whole finding is \
                 the comparison between the two",
                self.control_batch1_ticks
            ));
            return failures;
        };
        let (Some(single), Some(batched)) =
            (control.write_amplification(), main.write_amplification())
        else {
            failures.push(
                "the batch=1 control segment measured no write amplification — the comparison this \
                 example exists to publish cannot be made"
                    .to_owned(),
            );
            return failures;
        };
        if control.readings == 0 || control.commits == 0 {
            failures.push(
                "the batch=1 control segment ingested nothing — a control that runs no workload \
                 measures no workload"
                    .to_owned(),
            );
        }
        if single <= batched {
            failures.push(format!(
                "BATCHING DID NOT PAY: per-reading commits wrote {single:.1}x physical bytes per \
                 logical byte and the {}-reading batches wrote {batched:.1}x — batching is supposed to \
                 amortise the per-commit redo/undo overhead, so this is a FINDING, not a pass",
                main.batch,
            ));
        }

        // THE HEADLINE COMPARISON IS THE INGEST-ONLY ONE, so it is the one that must be gated (`rmp`
        // #745). The whole-segment ratio above is diluted by the fixed per-tick cost F, which BOTH
        // segments pay and batching cannot touch — so it is a FLOOR, and gating only a floor would let
        // the sound experiment go ungated.
        match (
            control.ingest_write_amplification(),
            main.ingest_write_amplification(),
        ) {
            (Some(single_i), Some(batched_i)) => {
                if single_i <= batched_i {
                    failures.push(format!(
                        "BATCHING DID NOT PAY ON THE INGEST ITSELF: per-reading commits wrote \
                         {single_i:.1}x physical bytes per logical byte of INGEST and the {}-reading \
                         batches wrote {batched_i:.1}x. This is the comparison with the fixed per-tick \
                         retention+checkpoint cost excluded, so it isolates the batch size — and it says \
                         batching bought nothing. That is a FINDING, not a pass",
                        main.batch,
                    ));
                }
            }
            _ => failures.push(
                "the INGEST-ONLY write amplification was not measured for both segments — the run then \
                 publishes only the whole-segment ratio, which is DILUTED by the fixed per-tick \
                 retention + checkpoint cost that batching cannot touch and that appears in BOTH \
                 numerators. Without the phase marks, the example cannot tell the batch size apart from \
                 the retention cadence, and its headline saving is a floor of unknown tightness"
                    .to_owned(),
            ),
        }

        // F IS A PROPERTY OF THE TICK, NOT OF THE BATCH SIZE — so the two segments must MEASURE it the
        // same. They run the identical retention DELETE and the identical checkpoint cadence, so a large
        // divergence means the phase marks are attributing WAL to the wrong phase, and every ingest-only
        // figure derived from them would inherit the error.
        if let (Some(f_main), Some(f_control)) =
            (main.fixed_wal_per_tick(), control.fixed_wal_per_tick())
        {
            let (lo, hi) = (f_main.min(f_control), f_main.max(f_control));
            if lo > 0.0 && hi > 3.0 * lo {
                failures.push(format!(
                    "THE FIXED PER-TICK COST DISAGREES BETWEEN THE SEGMENTS: the main segment measured \
                     {f_main:.0} B/tick of retention+checkpoint WAL and the control {f_control:.0} B/tick \
                     — but both run the SAME retention DELETE and the SAME checkpoint cadence, so this is \
                     a property of the tick and cannot depend on the batch size. The phase marks are \
                     attributing WAL to the wrong phase, and the ingest-only amplification inherits the \
                     error"
                ));
            }
        }
        failures
    }

    /// The **read half of the gate** (`rmp` #745): the concurrent read mix must have run, must have been
    /// gated against ground truth, and must not have found a single wrong row.
    ///
    /// Before #745 the example's read mix was `~0%` — every read was a `count(…)` — so a corrupted
    /// payload passed green and `rmp` #738 (an index silently answering with an EMPTY result instead of
    /// declining) could not have been caught here at all. The rules below are what make that impossible:
    /// each family must have run a floor of queries, must have gated a floor of them as **exact** set
    /// equalities (a run that only ever managed the weaker straddle bound proves much less), must have
    /// returned rows, and must have zero mismatches and zero empty-but-expected results.
    #[must_use]
    pub fn reader_gate(&self, g: &ReaderGate) -> Vec<String> {
        let mut failures = Vec::new();
        let Some(r) = self.readers.as_ref() else {
            failures.push(
                "NO CONCURRENT READ MIX RAN (--reader-clients 0). This example then measures a \
                 write-only workload and asserts nothing about what the server READS BACK under churn — \
                 which is how a corrupted payload, or an index silently returning an empty result \
                 (rmp #738), passes green"
                    .to_owned(),
            );
            return failures;
        };
        if r.errors > 0 {
            failures.push(format!(
                "the concurrent readers hit {} terminal error(s) — a read of a live database under \
                 churn must not fail: {}",
                r.errors,
                r.error_samples.join(" | "),
            ));
        }
        if r.families.is_empty() {
            failures.push("the reader mix ran no query families at all".to_owned());
        }
        for f in &r.families {
            if f.queries < g.min_queries_per_family {
                failures.push(format!(
                    "reader family '{}' ran only {} queries (floor {}) — too few for its gate to mean \
                     anything",
                    f.name, f.queries, g.min_queries_per_family,
                ));
            }
            if f.exact_gated < g.min_exact_gated_per_family {
                failures.push(format!(
                    "reader family '{}' gated only {} queries as EXACT set equalities (floor {}) — the \
                     rest fell back to the weaker straddle bound, so the family is barely gated. Widen \
                     the retention window, or slow the reader down relative to the churn",
                    f.name, f.exact_gated, g.min_exact_gated_per_family,
                ));
            }
            if f.rows_returned == 0 && f.queries > 0 {
                failures.push(format!(
                    "reader family '{}' returned ZERO rows across {} queries — an index that silently \
                     answers with an empty result set (rmp #738) looks exactly like this",
                    f.name, f.queries,
                ));
            }
            if f.mismatches > 0 {
                failures.push(format!(
                    "reader family '{}' returned {} row(s) that DISAGREE with the generator's ground \
                     truth: {}",
                    f.name,
                    f.mismatches,
                    f.failure_samples.join(" | "),
                ));
            }
            if f.empty_but_expected > 0 {
                failures.push(format!(
                    "reader family '{}' returned an EMPTY result {} time(s) where rows PROVABLY existed \
                     — this is the exact signature of rmp #738 (an index returning Some(empty) instead \
                     of declining), and it is a silent, total row-loss defect: {}",
                    f.name,
                    f.empty_but_expected,
                    f.failure_samples.join(" | "),
                ));
            }
        }
        if r.total_rows_verified() < g.min_rows_verified {
            failures.push(format!(
                "the reader mix verified only {} row payloads against ground truth (floor {}) — a read \
                 gate that inspects no rows is a row counter",
                r.total_rows_verified(),
                g.min_rows_verified,
            ));
        }
        failures
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
        // The sharp invariant is a physical one, and it does not care how big the store happens to be.
        // TWO physics, added together (`rmp` #745 strengthened this):
        //
        //   (a) **a commit is not acknowledged until its redo record is durable** (ARIES write-ahead
        //       logging; Mohan et al. 1992, §3). So N commits imply at least N redo records, and one
        //       `LogRecord` header alone is ~53 bytes (`graphus-wal/src/record.rs`).
        //   (b) **every logical byte the client asked the server to store must appear in the redo at
        //       least once** — that is what makes the commit replayable.
        //
        // The per-commit half ALONE was enough while ingest was one commit per reading (7 000 commits,
        // so a 0.1%-counted WAL fell below it). Batching collapses the commit count by ~50x, which would
        // have quietly weakened the floor by the same factor — so the logical payload is now added to it.
        // A run under this floor has not discovered an extraordinarily efficient engine; it has stopped
        // counting bytes the engine is still writing.
        let wal_floor = commits
            .saturating_mul(g.min_wal_bytes_per_commit)
            .saturating_add(self.logical_ingested_bytes);
        if commits > 0 && st.wal_written_bytes < wal_floor {
            failures.push(format!(
                "WAL VOLUME IS PHYSICALLY IMPOSSIBLE: {} B of WAL across {commits} commits carrying {} \
                 logical bytes — below the physical floor of {wal_floor} B ({commits} redo records x {} B \
                 of header, PLUS the logical payload every one of them must carry to be replayable). A \
                 commit is not durable — and is not acknowledged — until its redo record is fsynced. This \
                 is a MEASUREMENT defect, not an efficient engine: durable bytes are being written and \
                 NOT COUNTED. The classic cause is missing some or all of the WAL, which is a DIRECTORY \
                 of `seg.<lsn>` files whose leaf names contain no 'wal' — a name-based classifier scores \
                 them as store and this example then publishes `wal_bytes: 0` while asserting a green \
                 plateau",
                st.wal_written_bytes,
                self.logical_ingested_bytes,
                g.min_wal_bytes_per_commit,
            ));
        }

        // 4. THE TOTAL DURABLE FOOTPRINT — the claim judged against the DATABASE, not one component of
        //    it. The store plateaus (rule 1). The database on disk does not, because the WAL does not.
        //
        //    This is a LUMPED ratio and it is gated as one, deliberately and with its eyes open: it
        //    bounds the disk an operator must provision, which is a real question. But ~60% of it is the
        //    FIXED doublewrite preallocation, which cannot regress — so it is a COARSE bound, and rule 4b
        //    below carries the sharp one over the bytes that actually scale with the graph (`rmp` #745).
        match self.footprint_peak_over_store() {
            Some(r) if r <= g.max_footprint_ratio => {}
            Some(r) => failures.push(format!(
                "TOTAL DURABLE FOOTPRINT REGRESSED: at its post-warmup peak the database occupied {} B \
                 on disk to hold a {} B data image — {r:.0}x (ceiling {:.0}x). Of that peak, {} B is the \
                 FIXED doublewrite preallocation + catalog (it does not scale with the graph), so check \
                 the WAL peak first: {} B",
                st.footprint_peak_bytes,
                st.data_bytes,
                g.max_footprint_ratio,
                self.fixed_preallocation_bytes().unwrap_or(0),
                st.wal_peak_bytes,
            )),
            None => failures.push(
                "the total durable footprint (store + WAL) could not be computed — the headline claim \
                 cannot be judged against the database, only against one of its components"
                    .to_owned(),
            ),
        }

        // 4b. THE GRAPH-SCALING HALF OF THE FOOTPRINT, gated sharply (`rmp` #745). The peak WAL per byte
        //     of data image is the part of the durable footprint that the ENGINE controls and that a
        //     regression actually moves — a revert of the store-proportional segment seal (#706) blows
        //     this up while the lumped ratio above barely twitches, because a constant dominates it.
        match self.wal_to_store_ratio_peak() {
            Some(r) if r <= g.max_wal_to_store_peak => {}
            Some(r) => failures.push(format!(
                "PEAK WAL / STORE REGRESSED: the on-disk WAL peaked at {} B against a {} B data image — \
                 {r:.1}x (ceiling {:.0}x). This is the half of the durable footprint that SCALES with the \
                 graph, so unlike the lumped footprint ratio it is not cushioned by the fixed doublewrite \
                 preallocation. A revert of the store-proportional segment seal (rmp #706) lands here",
                st.wal_peak_bytes, st.data_bytes, g.max_wal_to_store_peak,
            )),
            None => failures.push(
                "the peak WAL/store ratio could not be computed — the graph-scaling half of the durable \
                 footprint is then ungated"
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
                "the run wrote {} B of WAL — past the {} B segment seal threshold for a {} B store \
                 (clamp(store, 1 MiB, 64 MiB), rmp #706), so at least one segment WAS sealed — yet the \
                 on-disk WAL never once shrank: NO WAL disk was ever reclaimed. Sealed segments below \
                 the reclaim floor are not being deleted",
                st.wal_written_bytes,
                segment_target_for_store(st.data_bytes),
                st.data_bytes,
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
    ///
    /// The gate applies it as `commits × this + logical_ingested_bytes` (`rmp` #745): batching cut the
    /// commit count by ~50x, and a floor that scaled only with commits would have been weakened by the
    /// same factor. Every logical byte must also appear in the redo at least once for the commit to be
    /// replayable, so adding the payload keeps the floor as sharp under batched ingest as it was under
    /// per-reading ingest.
    /// **What this floor can and CANNOT do** (`rmp` #745). It catches a *grossly* broken instrument — a
    /// zeroed WAL, or one segment counted out of fifty — and the unit tests prove it fires on both. It
    /// CANNOT catch a moderate under-count: at 64 B/commit it sits ~0.5% below the real WAL volume, so a
    /// sampler that lost 20% of the bytes sailed straight over it. That defect is caught by
    /// [`WireSamples::instrument_gate`], which checks the reconstruction against evidence the
    /// reconstruction does not itself produce (the run's own on-disk WAL series, and an exact
    /// phase-by-phase attribution). This floor is kept as the coarse backstop, not mistaken for the sharp
    /// one.
    pub min_wal_bytes_per_commit: u64,
    /// Ceiling on the peak total durable footprint (store + WAL) per byte of data image. A COARSE bound:
    /// most of it is the fixed doublewrite preallocation. See [`Self::max_wal_to_store_peak`].
    pub max_footprint_ratio: f64,
    /// Ceiling on the **peak on-disk WAL per byte of data image** — the graph-scaling half of the durable
    /// footprint, and the half a real regression moves (`rmp` #745). Sharper than
    /// [`max_footprint_ratio`](Self::max_footprint_ratio), which a fixed 8.87 MB preallocation dominates.
    pub max_wal_to_store_peak: f64,
    /// Ceiling on the **batched** segment's write amplification (`rmp` #745).
    ///
    /// Kept separate from [`max_write_amplification`](Self::max_write_amplification), which bounds the
    /// WHOLE run (batched main + the per-reading control, whose commits are ~50x more expensive per
    /// reading and dominate the mixed figure). A single ceiling over the mix would be slack enough to
    /// hide a real regression in the shape that actually matters — the one a production gateway uses.
    pub max_batched_write_amplification: f64,
}

/// The floors [`WireSamples::reader_gate`] holds the concurrent read mix to (`rmp` #745).
///
/// Every figure is a **lower bound**, deliberately: the failure this gate exists to prevent is a read
/// mix that *looks* green because it barely ran, or because it only ever gated the weak straddle bound.
/// A floor cannot be satisfied by doing less.
#[derive(Debug, Clone, Copy)]
pub struct ReaderGate {
    /// Minimum queries each family must have executed.
    pub min_queries_per_family: u64,
    /// Minimum queries each family must have gated as an **exact** set equality against ground truth.
    pub min_exact_gated_per_family: u64,
    /// Minimum row payloads the whole mix must have verified field-by-field against ground truth.
    pub min_rows_verified: u64,
}

impl Default for ReaderGate {
    /// The floors the example ships with, sized well below what the default `reclaim` profile actually
    /// achieves (thousands of queries, hundreds of thousands of verified rows) so they can only fire on
    /// a read mix that has genuinely stopped working — never on ordinary scheduling jitter.
    fn default() -> Self {
        Self {
            min_queries_per_family: 20,
            min_exact_gated_per_family: 10,
            min_rows_verified: 500,
        }
    }
}

impl Default for StorageGate {
    /// The bounds the example ships with — **every one of them calibrated against a measurement**, not
    /// against a hope.
    ///
    /// # The measurements MOVED in `rmp` #745, and the ceilings did NOT have to (read this before touching them)
    ///
    /// The WAL instrument was **UNDER-COUNTING**. It reconstructed the cumulative WAL volume by polling
    /// the WAL directory once per tick — at the END of the tick, *after* the checkpoint had already
    /// deleted the segments that tick's ingest created — and kept the maximum length ever seen per
    /// segment path. Segments were therefore born, sealed and RECLAIMED between two observations and
    /// were never seen at their sealed length. The loss was one-sided (an under-count, always) and
    /// host-speed dependent, which made the published figures neither correct nor reproducible.
    ///
    /// Fixing the instrument makes every WAL figure **LARGER**, and a larger figure against an unchanged
    /// ceiling is the shape of a regression — so it must be said plainly what happened here: **the engine
    /// did not get worse; the instrument got honest.** Measured against the engine's own exact counter
    /// (`graphus_db_wal_bytes_written_total`, `rmp` #745), the old instrument was short by **5.5% over
    /// the run and 17% in the `batch = 1` control segment**; the fixed one agrees with the engine to
    /// **+0.00%**.
    ///
    /// **And the ceilings still hold, unchanged.** Whole-run write amplification measures **279x**
    /// against the `350x` bound (it was 264x under the broken instrument); the batched segment measures
    /// **230x** against `300x`. The corrected numbers fit the headroom that was already there, so nothing
    /// was raised to accommodate them — which is the outcome one WANTS, because a raised ceiling and a
    /// corrected instrument look identical in a diff and only one of them is honest. Every bound below is
    /// still comfortably under the **~974x** a genuine regression to per-reading commits produces — and
    /// that figure is not hypothetical: the control segment measures exactly that regression, in the same
    /// run, as its own upper witness.
    ///
    /// `rmp` #745 adds [`max_wal_to_store_peak`](StorageGate::max_wal_to_store_peak): the sharp companion
    /// to [`max_footprint_ratio`](StorageGate::max_footprint_ratio), which is LUMPED — ~60% of it is a
    /// fixed 8.87 MB doublewrite preallocation that cannot regress, so it is coarse by construction. The
    /// peak WAL/store ratio measures **20x**; the bound is `40x`, and a revert of the store-proportional
    /// segment seal (`rmp` #706) would put it at **~241x** (64 MiB over a 278 KB store). It bites.
    ///
    /// The per-commit WAL floor is a COARSE backstop against a grossly broken instrument, and it could
    /// never have caught the 5.5% under-count above (it sits ~0.5% below the real volume). The sharp
    /// instrument check is [`WireSamples::instrument_gate`], plus the cross-check against the engine's
    /// exact counter in `iot_wire_evidence`.
    fn default() -> Self {
        Self {
            plateau_factor: 1.10,
            max_write_amplification: 350.0,
            min_wal_bytes_per_commit: 64,
            max_footprint_ratio: 120.0,
            max_batched_write_amplification: 300.0,
            max_wal_to_store_peak: 40.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The REAL `reclaim`-profile measurement** (`rmp` #745, captured from a green local run on this
    /// host **after the WAL instrument was fixed**): 7 000 readings over 140 ticks — 5 750 of them in the
    /// steady-state 25-reading batched segment, then 500 in a `batch = 1` control segment — into a flat
    /// 278 528 B data image, protected by **52 511 252 B** of cumulative WAL that sawtooths in a tight
    /// band (peak ~5.6 MiB) and is reclaimed 29 times on the way.
    ///
    /// The WAL figures here are **not** the ones this fixture used to carry. The old instrument polled the
    /// WAL directory once per tick, at the END of the tick — after the checkpoint had already deleted the
    /// segments that tick created — and reported 49 632 910 B. Cross-checked against the engine's own
    /// exact counter (`graphus_db_wal_bytes_written_total`, `rmp` #745) the fixed instrument agrees to
    /// **+0.00%**, and the old one was short by 5.5% run-wide and **17% in the control segment**. The
    /// engine did not change; the measurement did.
    ///
    /// Every test below starts from this healthy run and breaks exactly ONE thing, so a failing gate
    /// names the rule it caught rather than "something is wrong somewhere". Because the fixture IS the
    /// measurement, the ceilings in [`StorageGate::default`] are calibrated against a run that really
    /// happened rather than a number somebody hoped for.
    fn healthy() -> WireSamples {
        // The non-WAL durable half: the data image + the fixed doublewrite preallocation. (The catalog
        // lives above the database's own directory, so the measured `other_bytes` is 0 here.)
        const STORE: u64 = 278_528 + 8_871_936;
        // THE REAL on-disk WAL series, tick by tick, from the green run (`rmp` #745). It used to be a
        // synthetic sawtooth — and the moment `instrument_gate` began checking the reconstruction
        // against the series, the synthetic one FAILED: its invented growth implied 154 MB of WAL
        // against a 52.5 MB total. A fixture that cannot satisfy the physics the gate encodes is not a
        // fixture, it is a wish. This is the measurement.
        //
        // It sawtooths tightly — climbing as the churn writes, dropping on each checkpoint's reclaim of
        // the sealed store-proportional segments below the floor (#706) — and peaks at ~5.6 MiB.
        #[rustfmt::skip]
        const WAL_ON_DISK: [u64; 140] = [
        153295, 271012, 388841, 506782, 837826, 970054, 1098524, 1227300, 1356252, 1031376,
        1240978, 1431252, 1601686, 1753944, 1406029, 1615631, 1805649, 1976851, 2128085, 1537796,
        1747654, 1937928, 2109386, 2262412, 1541508, 1750982, 1941768, 2113610, 2265740, 1540228,
        260458, 450860, 622062, 773680, 1589418, 1799020, 1989038, 2160496, 2312754, 1539332,
        1749190, 1939464, 2110154, 2261644, 1538820, 1749062, 1939080, 2110026, 2262156, 1539972,
        1750342, 1940488, 2111178, 2262924, 1539460, 1749446, 1940104, 2111306, 2263820, 34284,
        243374, 433520, 604338, 756980, 1572718, 1782832, 1973362, 2144820, 2296310, 1539716,
        1749062, 1939208, 2110794, 2262156, 1538948, 1749318, 1939592, 2110922, 2262924, 1539972,
        1749958, 1939976, 2111306, 2263436, 1539588, 1748806, 1938824, 2109002, 1195102, 504562,
        713908, 903414, 1074744, 1226234, 991024, 1201010, 1391284, 1562486, 1714488, 1361709,
        1571183, 1761585, 1932019, 2083893, 1538308, 1747654, 1938568, 2109386, 2261260, 1538180,
        1747782, 1937672, 2109002, 2260492, 1538308, 376760, 586234, 776636, 947838, 588054,
        797784, 988442, 1159004, 1311262, 989800, 1199402, 1389292, 1561006, 1713008, 1363820,
        3053102, 4415984, 1209880, 2572762, 764826, 2454108, 3816990, 4853472, 5563554, 34284,
        ];
        let ticks_series = (0..140u64)
            .map(|tick| WireTick {
                tick,
                total_ingested: (tick + 1) * 50,
                live_readings: 200,
                checkpointed: (tick + 1) % 5 == 0,
                batch: if tick < 130 { 25 } else { 1 },
                store_data_bytes: Some(278_528),
                store_bytes: Some(STORE),
                wal_bytes: Some(WAL_ON_DISK[tick as usize]),
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
            // The EFFECTIVE batch: a tick is a barrier and its 50 readings are sharded across 2 ingest
            // connections, so a commit carries at most rate / clients = 25 of them.
            batch: 25,
            control_batch1_ticks: 10,
            ticks_series,
            total_ingested: 7_000,
            final_live_readings: 200,
            checkpoints_issued: 28,
            // 130 batched ticks x 2 statements/tick (2 shards) + 500 single-reading control statements.
            ingest_ops: 260 + 500,
            delete_ops: 135,
            retried_ops: 0,
            workload_secs: 2.54,
            logical_ingested_bytes: 189_000,
            segments: vec![
                WireSegment {
                    label: "batch=25 (main)".to_owned(),
                    batch: 25,
                    batch_cap: 50,
                    first_tick: 15,
                    next_tick: 130,
                    readings: 5_750,
                    commits: 345,
                    ingest_commits: 230,
                    logical_bytes: 155_250,
                    wal_written_bytes: Some(35_731_555),
                    // The phase split. THE FINDING: the fixed per-tick cost F (retention + checkpoint) is
                    // 52% of this segment's whole WAL bill — batching cannot touch a byte of it, and it
                    // sits in BOTH segments' numerators, which is what dragged the published "batching is
                    // worth 3.7x" down from the 7.9x the ingest itself actually shows.
                    ingest_wal_bytes: Some(17_070_242),
                    retention_wal_bytes: Some(3_275_518),
                    checkpoint_wal_bytes: Some(15_218_389),
                    other_wal_bytes: Some(167_406),
                    ticks: 115,
                    store_growth_bytes: Some(0),
                    secs: 1.9,
                    ingest_latency: None,
                },
                WireSegment {
                    label: "batch=1 (control)".to_owned(),
                    batch: 1,
                    batch_cap: 1,
                    first_tick: 130,
                    next_tick: 140,
                    readings: 500,
                    commits: 510,
                    ingest_commits: 500,
                    logical_bytes: 13_500,
                    wal_written_bytes: Some(13_155_972),
                    ingest_wal_bytes: Some(11_753_666),
                    retention_wal_bytes: Some(273_720),
                    checkpoint_wal_bytes: Some(1_114_790),
                    other_wal_bytes: Some(13_796),
                    ticks: 10,
                    store_growth_bytes: Some(0),
                    secs: 0.64,
                    ingest_latency: None,
                },
            ],
            wal_attribution: Some(WalAttribution {
                bootstrap_bytes: 37_394,
                warmup_bytes: 3_571_898,
                main_bytes: 35_731_555,
                control_bytes: 13_155_972,
                post_run_bytes: 14_433,
            }),
            readers: Some(WireReaders {
                clients: 2,
                secs: 2.54,
                errors: 0,
                error_samples: Vec::new(),
                families: vec![
                    reader_family("windowed-composite", 455, 455, 5_721),
                    reader_family("per-sensor-aggregate", 456, 456, 456),
                    reader_family("temporal-window", 454, 454, 45_400),
                ],
            }),
            payload_samples_verified: 64,
            statement_latency: Some(WireLatency {
                count: 923,
                p50_ms: 2.61,
                p99_ms: 8.27,
                p999_ms: 8.39,
            }),
            storage: Some(WireStorage {
                data_bytes: 278_528,
                dwb_bytes: 8_871_936,
                wal_bytes: 48_717,
                wal_peak_bytes: 5_563_554,
                other_bytes: 0,
                wal_written_bytes: 52_511_252,
                plateau_min_data_bytes: 278_528,
                plateau_max_data_bytes: 278_528,
                plateau_max_data_pages: 34,
                footprint_min_bytes: 9_184_748,
                footprint_peak_bytes: 14_714_018, // ~53x the graph — but 60% of it is the FIXED dwb
                footprint_final_bytes: 9_184_748,
                wal_reclaim_events: 29,
                wal_reclaimed_bytes: 29_005_868,
                server_io_write_bytes: Some(62_390_272),
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

    /// A healthy reader family: every query gated, no mismatch, rows returned and verified.
    fn reader_family(name: &str, queries: u64, exact: u64, rows: u64) -> WireReaderFamily {
        WireReaderFamily {
            name: name.to_owned(),
            cypher: "…".to_owned(),
            queries,
            exact_gated: exact,
            bounded_gated: queries - exact,
            rows_returned: rows.max(queries), // an aggregate family returns one row per query
            rows_verified: rows,
            mismatches: 0,
            empty_but_expected: 0,
            latency: None,
            failure_samples: Vec::new(),
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
        st.wal_written_bytes = 49_632; // 0.1% of the truth — one mis-classified segment's worth
        st.wal_bytes = 49_632;
        st.wal_peak_bytes = 49_632;
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

    /// Write amplification is a CEILING, and the ceiling must actually bite. The regression it exists to
    /// catch is a revert to a COMMIT PER READING, which the measured control segment shows costs ~831x —
    /// so doubling the WAL volume (264x -> ~528x) must be caught well before that.
    #[test]
    fn write_amplification_past_its_ceiling_fails_the_gate() {
        let mut s = healthy();
        s.storage.as_mut().expect("storage").wal_written_bytes = 99_265_820;

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
        st.footprint_peak_bytes = 229_376 * 600; // 600x the data image, past the 120x ceiling

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
            "49.6 MB of WAL is ~50x the 1 MiB seal size of a 278 KB store, so segments WERE sealed"
        );
        let failures = s.storage_gate(&StorageGate::default());
        assert!(
            failures
                .iter()
                .any(|f| f.contains("NO WAL disk was ever reclaimed")),
            "a sealed segment that is never freed must fail; got: {failures:#?}"
        );
    }

    /// **The seal predicate must ask the question the ENGINE answers** (`rmp` #745).
    ///
    /// A segment seals at `clamp(store_bytes, 1 MiB, 64 MiB)` (`rmp` #706), so for this 278 KB store it
    /// seals at the 1 MiB floor. Testing the run's WAL volume against the 64 MiB **cap** instead was a
    /// sound-but-blunt lower bound while per-reading commits wrote ~143 MB of WAL — but batching cut that
    /// to ~50 MB, which still seals ~50 segments and reclaims 29 of them, yet falls UNDER the cap. The
    /// blunt predicate would then have answered "cannot certify a seal" and excused the run from proving
    /// WAL disk ever came back: a 3.8x efficiency win would have silently switched the gate off.
    #[test]
    fn the_seal_predicate_uses_the_store_proportional_size_not_the_64_mib_cap() {
        let s = healthy();
        assert_eq!(
            s.segment_seal_bytes(),
            Some(WAL_SEGMENT_MIN_TARGET_BYTES),
            "a 278 KB store seals at the 1 MiB floor of the proportional band"
        );
        assert!(
            s.storage.as_ref().expect("storage").wal_written_bytes < WAL_SEGMENT_TARGET_BYTES,
            "the REAL batched run writes LESS than the 64 MiB cap — which is exactly why testing \
             against the cap would go vacuous"
        );
        assert_eq!(
            s.sealed_a_segment(),
            Some(true),
            "…and yet it certainly sealed segments, so the gate must still demand reclamation"
        );
        // The clamp is the engine's: a large store keeps the 64 MiB cap, a tiny one the 1 MiB floor.
        assert_eq!(segment_target_for_store(0), WAL_SEGMENT_MIN_TARGET_BYTES);
        assert_eq!(
            segment_target_for_store(8 * 1024 * 1024),
            8 * 1024 * 1024,
            "inside the band the seal size IS the store size"
        );
        assert_eq!(
            segment_target_for_store(u64::MAX),
            WAL_SEGMENT_TARGET_BYTES,
            "clamped at the 64 MiB cap"
        );
    }

    /// The seal predicate keeps the gate MONOTONE UNDER A FIX. A run too short to seal a segment cannot
    /// reclaim WAL disk, and is not asked to — otherwise the gate would demand the impossible. Crucially
    /// it is the *sealed* branch that demands reclamation, so a run that gets MORE efficient still seals,
    /// still reclaims, and still passes. A gate that failed on an improvement would be worse than no gate.
    #[test]
    fn a_run_too_short_to_seal_a_segment_is_not_asked_to_reclaim() {
        let mut s = healthy();
        let st = s.storage.as_mut().expect("storage");
        st.wal_written_bytes = 900_000; // below the 1 MiB seal size of this store
        st.wal_peak_bytes = 900_000;
        st.wal_bytes = 900_000;
        st.wal_reclaim_events = 0;
        st.wal_reclaimed_bytes = 0;
        // Keep the per-commit floor satisfiable so THIS rule is the only one under test.
        s.ingest_ops = 5;
        s.delete_ops = 0;
        s.logical_ingested_bytes = 500;

        assert_eq!(
            s.sealed_a_segment(),
            Some(false),
            "900 KB never reaches the 1 MiB seal size, so no segment can have been sealed"
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

    // ==============================================================================================
    // `rmp` #745 — the READ gate and the INGEST-SHAPE gate. Every rule is proven to FIRE on the defect
    // it names: a gate that cannot go red is decoration.
    // ==============================================================================================

    /// The healthy run passes both new gates. Without this, every test below could be satisfied by a
    /// gate that simply always fails.
    #[test]
    fn the_healthy_run_passes_the_reader_and_segment_gates() {
        let s = healthy();
        assert!(
            s.reader_gate(&ReaderGate::default()).is_empty(),
            "{:#?}",
            s.reader_gate(&ReaderGate::default())
        );
        assert!(
            s.segment_gate(&StorageGate::default()).is_empty(),
            "{:#?}",
            s.segment_gate(&StorageGate::default())
        );
    }

    /// **THE `rmp` #738 SIGNATURE.** An index that answers a windowed query with an EMPTY result set
    /// instead of declining loses every row, silently — and no `count(…)`-shaped check can see it,
    /// because the count it returns (0) is a perfectly well-formed number. The read gate MUST fail it.
    #[test]
    fn an_empty_result_where_rows_provably_existed_fails_the_reader_gate() {
        let mut s = healthy();
        let readers = s.readers.as_mut().expect("readers");
        readers.families[0].empty_but_expected = 3;
        readers.families[0].failure_samples =
            vec!["sensor s-3 seq [6100, 6200): expected 12 rows, got 0".to_owned()];

        let failures = s.reader_gate(&ReaderGate::default());
        assert!(
            failures.iter().any(|f| f.contains("rmp #738")),
            "an empty-but-expected result must fail the read gate; got: {failures:#?}"
        );
    }

    /// A stored payload that disagrees with the generator's ground truth — a corrupted or transposed
    /// property value — must fail. Before #745 every read was a `count(…)`, so it did not.
    #[test]
    fn a_payload_that_disagrees_with_ground_truth_fails_the_reader_gate() {
        let mut s = healthy();
        let readers = s.readers.as_mut().expect("readers");
        readers.families[2].mismatches = 1;
        readers.families[2].failure_samples =
            vec!["seq 6142: stored value=17, generated value=842".to_owned()];

        let failures = s.reader_gate(&ReaderGate::default());
        assert!(
            failures
                .iter()
                .any(|f| f.contains("DISAGREE with the generator's ground truth")),
            "a corrupted payload must fail the read gate; got: {failures:#?}"
        );
    }

    /// A read mix that barely ran, or that never once managed an EXACT gate, is weakly gated — and a
    /// weakly-gated read mix is how a defect hides. The floors must fire.
    #[test]
    fn a_barely_exercised_reader_mix_fails_the_reader_gate() {
        let mut s = healthy();
        let readers = s.readers.as_mut().expect("readers");
        readers.families[0].queries = 3;
        readers.families[0].exact_gated = 0;
        readers.families[0].bounded_gated = 3;

        let failures = s.reader_gate(&ReaderGate::default());
        assert!(
            failures.iter().any(|f| f.contains("floor 20")),
            "a family that ran 3 queries must fail its query floor; got: {failures:#?}"
        );
        assert!(
            failures.iter().any(|f| f.contains("EXACT set equalities")),
            "a family that never gated an exact equality must fail; got: {failures:#?}"
        );

        // …and a mix that verified no row payloads at all is a row counter, not a gate.
        let mut none_verified = healthy();
        for f in &mut none_verified.readers.as_mut().expect("readers").families {
            f.rows_verified = 0;
        }
        assert!(
            none_verified
                .reader_gate(&ReaderGate::default())
                .iter()
                .any(|f| f.contains("verified only 0 row payloads")),
            "a mix that inspects no rows must fail"
        );
    }

    /// **The read mix is not optional.** A run with no readers at all measures a write-only workload —
    /// which is exactly the state `rmp` #745 found this example in (~0% reads) — and must not pass
    /// quietly.
    #[test]
    fn a_run_with_no_reader_mix_fails_the_reader_gate() {
        let mut s = healthy();
        s.readers = None;
        let failures = s.reader_gate(&ReaderGate::default());
        assert!(
            failures
                .iter()
                .any(|f| f.contains("NO CONCURRENT READ MIX RAN")),
            "a write-only run must fail the read gate; got: {failures:#?}"
        );
    }

    /// A reader that hit a terminal server error did not "run 400 queries"; it ran 400 queries and a
    /// bug. Errors must fail the run, never be averaged away.
    #[test]
    fn a_reader_error_fails_the_reader_gate() {
        let mut s = healthy();
        let readers = s.readers.as_mut().expect("readers");
        readers.errors = 1;
        readers.error_samples = vec!["Neo.ClientError.Statement.TypeError: …".to_owned()];
        assert!(
            s.reader_gate(&ReaderGate::default())
                .iter()
                .any(|f| f.contains("terminal error")),
            "a reader error must fail the run"
        );
    }

    /// **A segment's label must describe the run that produced it** — and this rule caught a real defect
    /// while it was being written.
    ///
    /// The driver first chunked each shard's per-tick rows at `min(--batch, rate/clients)`. The generator
    /// assigns readings to sensors from a seeded PRNG, so the shards' shares are uneven (22 / 28, not
    /// 25 / 25) — and a 28-row shard chunked at 25 committed 25 + a remainder of 3. The mean readings per
    /// commit fell to **17.1** while the segment cheerfully called itself `batch=25`, and every
    /// per-commit figure derived from it would have been misattributed. The gate failed the run; the
    /// driver now treats `--batch` as a CAP and reports the batch it MEASURED.
    #[test]
    fn a_segment_whose_label_does_not_match_its_commits_fails_the_segment_gate() {
        let mut s = healthy();
        let main = s
            .segments
            .iter_mut()
            .find(|seg| seg.batch > 1)
            .expect("main");
        main.ingest_commits = 336; // the remainder-chunk bug: 5 750 readings over 336 commits = 17.1
        assert!(
            (main.readings_per_commit().expect("measured") - 17.1).abs() < 0.1,
            "the fixture reproduces the real mis-measurement"
        );

        let failures = s.segment_gate(&StorageGate::default());
        assert!(
            failures
                .iter()
                .any(|f| f.contains("the label does not describe the run")),
            "a segment claiming 25 readings/commit while committing 17.1 must FAIL; got: {failures:#?}"
        );

        // And the other direction: a commit that carried MORE than the client's flush cap means the
        // ingest is not doing what the run says it is doing.
        let mut s = healthy();
        let main = s
            .segments
            .iter_mut()
            .find(|seg| seg.batch > 1)
            .expect("main");
        main.batch_cap = 10;
        assert!(
            s.segment_gate(&StorageGate::default())
                .iter()
                .any(|f| f.contains("ABOVE the 10 the client's flush buffer was capped at")),
            "a commit above the cap must fail"
        );
    }

    /// **The batch=1 control is the whole comparison.** A run that publishes only the batched figure
    /// cannot claim that per-reading commits dominate the durability bill — it has not measured them.
    #[test]
    fn a_missing_batch1_control_segment_fails_the_segment_gate() {
        let mut s = healthy();
        s.segments.retain(|seg| seg.batch != 1);
        let failures = s.segment_gate(&StorageGate::default());
        assert!(
            failures.iter().any(|f| f.contains("CONTROL segment")),
            "a missing control segment must fail; got: {failures:#?}"
        );
    }

    /// If batching stopped paying, that is a FINDING about the engine, not a run to wave through.
    #[test]
    fn batching_that_does_not_pay_fails_the_segment_gate() {
        let mut s = healthy();
        // Make the batched segment as expensive per logical byte as the per-reading control.
        let control_amp = s
            .control_segment()
            .and_then(WireSegment::write_amplification)
            .expect("a measured control");
        let main = s
            .segments
            .iter_mut()
            .find(|seg| seg.batch > 1)
            .expect("main");
        main.wal_written_bytes = Some((control_amp * main.logical_bytes as f64) as u64);

        let failures = s.segment_gate(&StorageGate::default());
        assert!(
            failures.iter().any(|f| f.contains("BATCHING DID NOT PAY")),
            "a batched segment no cheaper than the per-reading one must fail; got: {failures:#?}"
        );
    }

    /// The batched segment carries its own CEILING, tighter than the whole-run one (which is diluted by
    /// the deliberately-expensive per-reading control). A regression in the shape a production gateway
    /// actually uses must be caught by it.
    #[test]
    fn a_regressed_batched_write_amplification_fails_the_segment_gate() {
        let mut s = healthy();
        let main = s
            .segments
            .iter_mut()
            .find(|seg| seg.batch > 1)
            .expect("main");
        main.wal_written_bytes = Some(main.wal_written_bytes.expect("measured") * 8);

        let failures = s.segment_gate(&StorageGate::default());
        assert!(
            failures
                .iter()
                .any(|f| f.contains("BATCHED WRITE AMPLIFICATION REGRESSED")),
            "an 8x WAL blow-up in the batched segment must trip its ceiling; got: {failures:#?}"
        );
    }

    /// Attach mode measures no disk, so the ingest-shape gate — which is entirely about durable bytes —
    /// must ask nothing of it. (The read gate still applies: reads work over any wire.)
    #[test]
    fn attach_mode_is_not_gated_on_segment_amplification() {
        let mut s = healthy();
        s.local = false;
        s.storage = None;
        assert!(s.segment_gate(&StorageGate::default()).is_empty());
        assert!(
            s.reader_gate(&ReaderGate::default()).is_empty(),
            "reads ARE measurable over an attached wire, so they stay gated"
        );
    }

    /// The two segments' amplifications are computed independently from their own measured WAL deltas —
    /// the batch=1 number is never inferred from the batched one by arithmetic.
    ///
    /// # The numbers this pins, and the story they REPLACE (`rmp` #745)
    ///
    /// The example used to publish "batching is worth 3.7x, and the residual 224x is the WAL record
    /// FORMAT — a commit's redo is dominated by the PAGE IMAGES of every page it dirtied". **Every clause
    /// of that was false**, and this test is where the truth is pinned:
    ///
    /// * The engine writes **byte-range patches**, not page images (`paging::encode_patch`);
    ///   `RecordType::FullPageImage` is emitted nowhere. `crates/graphus-cypher/tests/wal_amplification.rs`
    ///   decodes the durable log of this exact ingest shape and measures a mean page-changing record of
    ///   **197 B against an 8 192 B page** — a whole commit costs less than ONE image of any single one of
    ///   the 5.7 distinct pages it dirties.
    /// * The "3.7x" was not the batching saving at all. It was the batching saving **diluted by a fixed
    ///   per-tick cost F** — the retention `DELETE` and the `CHECKPOINT` — which is **52% of the main
    ///   segment's WAL bill**, is paid regardless of batch size, and sits in BOTH numerators. Measured on
    ///   the ingest phase alone, where F cancels, batching is worth **7.9x**.
    ///
    /// So the residual was never "the format". It was more than half retention and checkpoint, and the
    /// rest is the irreducible cost of durably recording a graph write plus one catalog re-image per
    /// commit. A story that is not measured will fill the gap left by a measurement that was not taken.
    #[test]
    fn each_segment_measures_its_own_write_amplification() {
        let s = healthy();
        let main = s.main_segment().expect("main");
        let control = s.control_segment().expect("control");

        // WHOLE-SEGMENT (retention + checkpoint included): the bill a deployment on this cadence pays.
        let m = main.write_amplification().expect("measured");
        let c = control.write_amplification().expect("measured");
        assert!((225.0..235.0).contains(&m), "batched, whole segment: {m}");
        assert!(
            (970.0..980.0).contains(&c),
            "per-reading, whole segment: {c}"
        );
        let whole = s.batching_write_amp_saving().expect("both measured");
        assert!(
            (4.0..4.5).contains(&whole),
            "the WHOLE-SEGMENT saving is {whole:.1}x — and it is a FLOOR, not the batching saving: the \
             fixed per-tick cost F is in both numerators"
        );

        // INGEST-ONLY (F excluded) — THE HEADLINE, and the sound experiment: the two segments then
        // differ in exactly one variable, the batch size.
        let mi = main.ingest_write_amplification().expect("measured");
        let ci = control.ingest_write_amplification().expect("measured");
        assert!((105.0..115.0).contains(&mi), "batched, ingest only: {mi}");
        assert!(
            (865.0..880.0).contains(&ci),
            "per-reading, ingest only: {ci}"
        );
        let ingest = s.batching_ingest_write_amp_saving().expect("both measured");
        assert!(
            (7.5..8.5).contains(&ingest),
            "batching is worth {ingest:.1}x on the ingest itself"
        );
        assert!(
            ingest > whole,
            "the ingest-only saving ({ingest:.1}x) MUST exceed the whole-segment one ({whole:.1}x): the \
             fixed per-tick cost F appears in both numerators of (50·A₁ + F) / (2·A₂₅ + F) and can only \
             ever drag the ratio toward 1. If this ever inverts, the phase marks are wrong"
        );

        // F IS THE BURIED TERM. It is more than half the batched segment's durable bill, and the example
        // used to attribute all of it to "the WAL format".
        let share = main.fixed_wal_share().expect("measured");
        assert!(
            share > 0.4,
            "the fixed per-tick retention+checkpoint cost is {:.0}% of the batched segment's WAL — this \
             is the term the 'page image' story was covering for",
            100.0 * share
        );

        // The measured readings-per-commit must equal the declared batch, or the label lies.
        assert!((main.readings_per_commit().expect("measured") - 25.0).abs() < 0.01);
        assert!((control.readings_per_commit().expect("measured") - 1.0).abs() < 0.01);

        // A control segment with no measured storage yields no saving — never a fabricated one.
        let mut attached = s.clone();
        for seg in &mut attached.segments {
            seg.wal_written_bytes = None;
            seg.ingest_wal_bytes = None;
        }
        assert_eq!(attached.batching_write_amp_saving(), None);
        assert_eq!(attached.batching_ingest_write_amp_saving(), None);
    }

    // ==============================================================================================
    // `rmp` #745 — THE INSTRUMENT'S OWN GATE. Every rule is proven to FIRE on the defect it names, and
    // proven NOT to fire on the healthy run. This is the gate that did not exist, which is why a 5.5%
    // run-wide (17% in the control segment) WAL under-count shipped and published a floor as a
    // measurement for months.
    // ==============================================================================================

    /// The real, corrected run passes its own instrument gate. Without this, every test below could be
    /// satisfied by a gate that simply always fails.
    #[test]
    fn the_corrected_run_passes_the_instrument_gate() {
        let failures = healthy().instrument_gate();
        assert!(
            failures.is_empty(),
            "the measured run must pass its own instrument gate, got: {failures:#?}"
        );
    }

    /// **THE DEFECT, REPRODUCED.** The WAL instrument polled the directory once per tick, at the END of
    /// the tick — after the checkpoint had already deleted the segments that tick's ingest created — so
    /// segments were born, sealed and reclaimed unobserved. The reconstruction came back BELOW what the
    /// run's own on-disk series proves was written, and nothing noticed.
    ///
    /// The floor is forced by physics and cannot false-positive: since
    /// `on_disk(t) = on_disk(t-1) + written(t) - reclaimed(t)` with `reclaimed(t) >= 0`, every byte the
    /// on-disk WAL GREW by is a byte the engine certainly wrote.
    #[test]
    fn an_under_counted_wal_fails_the_instrument_gate() {
        let mut s = healthy();
        let floor = s
            .run_wal_written_floor()
            .expect("the series forces a floor");
        // Under-count the run to just below its own proven floor — the shape of the real defect, which
        // no CEILING can catch (an under-counted WAL makes amplification FALL).
        let st = s.storage.as_mut().expect("storage");
        st.wal_written_bytes = floor - 1;
        // Keep the attribution consistent, so THIS rule is the only one under test.
        let a = s.wal_attribution.as_mut().expect("attribution");
        *a = WalAttribution {
            bootstrap_bytes: floor - 1,
            warmup_bytes: 0,
            main_bytes: 0,
            control_bytes: 0,
            post_run_bytes: 0,
        };
        for seg in &mut s.segments {
            seg.wal_written_bytes = None;
        }

        let failures = s.instrument_gate();
        assert!(
            failures
                .iter()
                .any(|f| f.contains("THE WAL INSTRUMENT LOST BYTES")),
            "a reconstruction below the floor its own on-disk series forces MUST fail; got: {failures:#?}"
        );
    }

    /// The per-SEGMENT floor is the sharp one, and it is where the real defect actually showed: the
    /// `batch = 1` control writes >1 MiB of WAL per tick against a 1 MiB segment seal, so it was the
    /// segment losing segments between samples — and it under-counted by **17%** while the run as a whole
    /// was only 5.5% short. A run-wide sum can average a loss away; a segment's own window cannot.
    #[test]
    fn an_under_counted_segment_fails_the_instrument_gate_even_when_the_run_total_looks_fine() {
        let mut s = healthy();
        let control_floor = {
            let c = s.control_segment().expect("control");
            s.wal_written_floor(c.first_tick, c.next_tick)
                .expect("the control's own series forces a floor")
        };
        assert!(
            control_floor > 0,
            "the control segment's ticks must actually show WAL growth, or this test proves nothing"
        );
        // The RUN total stays exactly as measured — only the control segment under-counts. The run-wide
        // rule therefore stays silent, and the per-segment rule must still fire.
        let c = s
            .segments
            .iter_mut()
            .find(|seg| seg.batch == 1)
            .expect("control");
        c.wal_written_bytes = Some(control_floor - 1);
        c.ingest_wal_bytes = None; // (the phase reconciliation is a different rule)
        c.other_wal_bytes = None;

        let failures = s.instrument_gate();
        assert!(
            failures
                .iter()
                .any(|f| f.contains("LOST BYTES IN THE 'batch=1 (control)' SEGMENT")),
            "a segment under-counting against its own on-disk series MUST fail; got: {failures:#?}"
        );
        assert!(
            !failures
                .iter()
                .any(|f| f.contains("THE WAL INSTRUMENT LOST BYTES:")),
            "the RUN-wide rule must stay silent here — that is exactly why the per-segment rule exists"
        );
    }

    /// **THE UNATTRIBUTED REMAINDER.** The segments used to be published beside a run total they did not
    /// add up to: 34.78 + 11.24 MB against 49.65 MB, leaving 3.62 MB (7.3%) belonging to nothing. A
    /// remainder is not a rounding artefact — it is where a measurement defect hides, and it must fail.
    #[test]
    fn an_unreconciled_wal_attribution_fails_the_instrument_gate() {
        let mut s = healthy();
        s.wal_attribution
            .as_mut()
            .expect("attribution")
            .warmup_bytes = 0; // 3.57 MB now belongs to nothing

        let failures = s.instrument_gate();
        assert!(
            failures
                .iter()
                .any(|f| f.contains("THE WAL ATTRIBUTION DOES NOT RECONCILE")),
            "an unattributed WAL remainder MUST fail; got: {failures:#?}"
        );

        // …and an attribution that is missing ENTIRELY is not a pass either.
        let mut none = healthy();
        none.wal_attribution = None;
        assert!(
            none.instrument_gate()
                .iter()
                .any(|f| f.contains("attributed none of it")),
            "a run with no attribution at all must fail"
        );
    }

    /// The same rule, one level down: a SEGMENT's phases must sum to that segment's own WAL total. The
    /// ingest-only write amplification — the example's headline — is derived from exactly these marks, so
    /// a phase mark that does not bracket the work it claims to bracket corrupts the headline silently.
    #[test]
    fn a_segments_phases_that_do_not_sum_to_its_total_fail_the_instrument_gate() {
        let mut s = healthy();
        let main = s
            .segments
            .iter_mut()
            .find(|seg| seg.batch > 1)
            .expect("main");
        // Drop the checkpoint phase on the floor: the segment's bytes no longer add up.
        main.checkpoint_wal_bytes = Some(0);

        let failures = s.instrument_gate();
        assert!(
            failures
                .iter()
                .any(|f| f.contains("PHASES DO NOT RECONCILE")),
            "a segment whose phases do not sum to its measured WAL MUST fail; got: {failures:#?}"
        );
    }

    /// **The fixed per-tick cost F is a property of the TICK, not of the batch size**, so the two segments
    /// must measure it the same — they run the identical retention DELETE and the identical checkpoint
    /// cadence. A large divergence means the phase marks are attributing WAL to the wrong phase, and every
    /// ingest-only figure inherits the error.
    #[test]
    fn a_fixed_per_tick_cost_that_disagrees_between_segments_fails_the_segment_gate() {
        let mut s = healthy();
        let control = s
            .segments
            .iter_mut()
            .find(|seg| seg.batch == 1)
            .expect("control");
        // Push the control's F an order of magnitude away from the main's, keeping its total intact so
        // only THIS rule is under test.
        let total = control.wal_written_bytes.expect("measured");
        control.retention_wal_bytes = Some(10);
        control.checkpoint_wal_bytes = Some(10);
        control.ingest_wal_bytes = Some(total - 20);
        control.other_wal_bytes = Some(0);

        let failures = s.segment_gate(&StorageGate::default());
        assert!(
            failures
                .iter()
                .any(|f| f.contains("THE FIXED PER-TICK COST DISAGREES BETWEEN THE SEGMENTS")),
            "a per-tick cost that depends on the batch size is impossible; got: {failures:#?}"
        );
    }

    /// A run with NO phase marks cannot make the ingest-only comparison at all — so it must not pass
    /// quietly with only the DILUTED whole-segment ratio, which is what the example published as if it
    /// were the batching saving.
    #[test]
    fn a_run_without_phase_marks_fails_the_segment_gate() {
        let mut s = healthy();
        for seg in &mut s.segments {
            seg.ingest_wal_bytes = None;
            seg.retention_wal_bytes = None;
            seg.checkpoint_wal_bytes = None;
            seg.other_wal_bytes = None;
        }
        let failures = s.segment_gate(&StorageGate::default());
        assert!(
            failures
                .iter()
                .any(|f| f.contains("INGEST-ONLY write amplification was not measured")),
            "without the phase marks the headline saving is a floor of unknown tightness, and the run \
             must say so rather than publish the diluted ratio as the finding; got: {failures:#?}"
        );
    }

    /// The graph-scaling half of the durable footprint carries its own, SHARP ceiling — because the
    /// lumped one is ~60% a fixed doublewrite preallocation that cannot regress. A revert of the
    /// store-proportional segment seal (`rmp` #706) puts the WAL peak at 64 MiB over a 278 KB store
    /// (~241x); the lumped ratio barely twitches, and this rule catches it.
    #[test]
    fn a_wal_peak_that_runs_away_from_its_store_fails_the_gate() {
        let mut s = healthy();
        let st = s.storage.as_mut().expect("storage");
        st.wal_peak_bytes = 64 * 1024 * 1024; // the pre-#706 fixed 64 MiB seal

        let failures = s.storage_gate(&StorageGate::default());
        assert!(
            failures
                .iter()
                .any(|f| f.contains("PEAK WAL / STORE REGRESSED")),
            "a 64 MiB WAL over a 278 KB store must fail the graph-scaling ceiling; got: {failures:#?}"
        );
    }

    /// **The lumped footprint ratio is mostly a CONSTANT, and the report must not pretend otherwise.**
    /// Of the measured 14.71 MB peak, 8.87 MB is the fixed doublewrite preallocation — it does not scale
    /// with the graph and it cannot regress. `space_amplification` used to divide that constant by the
    /// live data and publish `1703x`, which is the lumped-footprint ratio `examples/README.md`
    /// evidence-honesty rule 5 explicitly forbids.
    #[test]
    fn the_amplification_ratios_exclude_the_fixed_preallocation() {
        let s = healthy();

        // The fixed half is ~60% of the peak footprint — so a ratio built on the peak is a ratio built
        // mostly on a constant.
        let share = s.footprint_peak_fixed_share().expect("measured");
        assert!(
            (0.55..0.65).contains(&share),
            "the fixed preallocation is {:.0}% of the peak durable footprint",
            100.0 * share
        );

        // space_amplification now carries ONLY the bytes that scale with the graph (data image + WAL).
        let sa = s.space_amplification().expect("measured");
        let live = s.logical_live_bytes().expect("measured");
        let want = (278_528.0 + 48_717.0) / live;
        assert!(
            (sa - want).abs() < 0.01,
            "space_amplification must be (data + WAL) / live logical, got {sa}, want {want}"
        );
        assert!(
            sa < 100.0,
            "the honest, graph-scaling ratio is ~61x. The old lumped one read 1703x — 96% of it the \
             FIXED doublewrite preallocation, a number that would have read the same for a database \
             holding one reading or a million"
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
            batch: 50,
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

    /// `throughput.ops_per_sec` MUST be `throughput.operations / elapsed`. Both fields describe
    /// OPERATIONS (statements), so a reader is entitled to divide one by the other and get the third.
    ///
    /// The report used to fill `ops_per_sec` with the READINGS/s rate. While ingest was one statement
    /// per reading the two were numerically identical and the error was invisible; `--batch` separates
    /// them by the batch factor (a 7 000-reading run over 924 statements reported 2 838 "ops/s" beside
    /// an `operations` count that divides out to 374). That is the "every field carries the quantity
    /// its name promises" rule, and this test is what stops it coming back.
    #[test]
    fn ops_per_sec_is_the_statement_rate_and_divides_out_of_operations() {
        let s = healthy();

        let ops = s.statement_ops();
        assert_eq!(
            ops,
            s.ingest_ops + s.delete_ops + s.checkpoints_issued,
            "an operation is one STATEMENT: an ingest commit, a retention DELETE, or a CHECKPOINT"
        );

        let rate = s
            .statement_ops_per_sec()
            .expect("a measured statement rate");
        let divided = ops as f64 / s.workload_secs;
        assert!(
            (rate - divided).abs() < 1e-9,
            "ops_per_sec ({rate}) must equal operations / elapsed ({divided})"
        );

        // And it is NOT the readings/s rate: under batching they differ by the batch factor, so a
        // report that confused the two would be off by ~25x. Both are worth having — under names that
        // say which is which.
        let readings = s.ingest_per_sec().expect("a measured reading rate");
        assert!(
            readings > rate * 5.0,
            "the DOMAIN rate ({readings} readings/s) and the STATEMENT rate ({rate} ops/s) are \
             different quantities under batching — they must not be interchangeable"
        );

        // A degenerate window measures nothing, and reports nothing (never a 0.0 that reads like a
        // real observation of an idle server).
        let stopped = WireSamples {
            workload_secs: 0.0,
            ..healthy()
        };
        assert_eq!(stopped.statement_ops_per_sec(), None);
        assert_eq!(stopped.ingest_per_sec(), None);
    }

    // ==============================================================================================
    // THE DECISIVE GATE, PROVED TO FIRE (`rmp` #745).
    //
    // The storage audit's closing finding: the exact-counter cross-check was the ONLY rule capable of
    // catching the real defect (every other rule checks the reconstruction against itself, and every
    // other rule stayed green while the instrument under-counted by 17%) — and it was the one rule
    // living untested in the binary. These tests are what make it trustworthy: they replay the REAL
    // historical numbers and prove the gate goes red on them.
    // ==============================================================================================

    /// The exact figures from the run that shipped the defect: the old, once-per-tick instrument
    /// reconstructed 49,628,302 B while the engine had really written 52,515,999 B. The gate MUST fire.
    #[test]
    fn the_cross_check_fires_on_the_real_historical_undercount() {
        const BROKEN: u64 = 49_628_302;
        const EXACT: u64 = 52_515_999;

        let v = WalCrossCheck::evaluate(Some(EXACT), Some(BROKEN));
        let WalCrossCheck::Drifted { drift, .. } = v else {
            panic!("the gate MUST fire on the under-count that actually shipped; got {v:?}");
        };
        assert!(drift < 0.0, "an under-count drifts NEGATIVE, got {drift}");
        assert!(
            (drift.abs() - 0.055).abs() < 0.005,
            "the historical under-count was ~5.5% run-wide, got {:.1}%",
            100.0 * drift.abs()
        );
        let msg = v
            .failure("db", "graphus_db_wal_bytes_written_total")
            .expect("a Drifted verdict must raise a failure");
        assert!(msg.contains("DISAGREES WITH THE ENGINE"), "{msg}");

        // And the FIXED instrument, on the same run, must NOT fire: a gate that fails on a correct
        // measurement is worse than no gate.
        let fixed = WalCrossCheck::evaluate(Some(EXACT), Some(52_516_628));
        assert!(
            matches!(fixed, WalCrossCheck::Agrees { .. }),
            "the corrected reconstruction agrees to +0.00% and must PASS; got {fixed:?}"
        );
    }

    /// An instrument that cannot be corroborated is NOT a passing instrument. A target that does not
    /// publish the exact counter must FAIL the run, not silently skip the only rule that can catch an
    /// under-count. (A present-but-zero counter is treated the same: a zero corroborates nothing.)
    #[test]
    fn the_cross_check_fires_when_the_engine_counter_is_absent() {
        for exact in [None, Some(0)] {
            let v = WalCrossCheck::evaluate(exact, Some(52_516_628));
            assert_eq!(
                v,
                WalCrossCheck::CounterAbsent,
                "an absent (or zero) counter leaves the reconstruction UNVERIFIED, not correct"
            );
            let msg = v
                .failure("iotdb", "graphus_db_wal_bytes_written_total")
                .expect("an unverifiable instrument must FAIL");
            assert!(msg.contains("could NOT be cross-checked"), "{msg}");
            assert!(
                msg.contains("iotdb"),
                "the failure names the database: {msg}"
            );
        }

        // Attach mode measures no storage at all, so there is nothing to cross-check — and that is a
        // genuine N/A, not a failure.
        let na = WalCrossCheck::evaluate(Some(52_515_999), None);
        assert_eq!(na, WalCrossCheck::NotApplicable);
        assert!(
            na.failure("db", "c").is_none(),
            "attach mode has no storage to corroborate; it must not fail on that"
        );
    }

    /// The tolerance is a boundary, and both sides of it are load-bearing: the physical scrape skew it
    /// exists to absorb must PASS, and an over-count must fail exactly as an under-count does (a
    /// reconstruction that exceeds the engine's own figure is also a broken instrument).
    #[test]
    fn the_cross_check_tolerance_is_a_two_sided_boundary() {
        const EXACT: u64 = 10_000_000;

        // Inside the band (either sign): the physical skew between two scrapes. Passes.
        for recon in [9_800_000, 10_200_000] {
            assert!(
                matches!(
                    WalCrossCheck::evaluate(Some(EXACT), Some(recon)),
                    WalCrossCheck::Agrees { .. }
                ),
                "{recon} is within the {:.0}% band and must pass",
                100.0 * WAL_RECONSTRUCTION_TOLERANCE
            );
        }
        // Outside it, on BOTH sides. Both fail.
        for recon in [9_600_000, 10_400_000] {
            assert!(
                matches!(
                    WalCrossCheck::evaluate(Some(EXACT), Some(recon)),
                    WalCrossCheck::Drifted { .. }
                ),
                "{recon} is outside the {:.0}% band and must FAIL",
                100.0 * WAL_RECONSTRUCTION_TOLERANCE
            );
        }
    }

    /// The headline is a BAND, and the band must bracket the truth in the right direction (`rmp` #745).
    ///
    /// Background maintenance passes are checkpoint work whose WAL lands in whichever phase was running.
    /// Landing in INGEST, they inflate it — and they inflate the SMALLER (batched) ingest figure
    /// relatively more, so they drag the measured saving DOWN. The ingest-only saving is therefore a
    /// FLOOR, and removing the smear can only move the saving UP. A band that could close the other way
    /// would be reporting the confound backwards.
    #[test]
    fn the_headline_band_brackets_the_floor_from_above() {
        let s = healthy();
        let floor = s
            .batching_ingest_write_amp_saving()
            .expect("both segments' phases are measured");

        // No background pass fired => there is no smear, so there is no band: the floor IS the value.
        assert_eq!(
            s.batching_ingest_write_amp_saving_upper(0),
            None,
            "with no background pass there is nothing to bound; publishing a band would invent one"
        );

        // With background passes, the ceiling must sit STRICTLY ABOVE the floor. A band whose ends are
        // equal is not a bound — and it is exactly what an allocation proportional to each segment's
        // INGEST produces, because it removes the same FRACTION from both and the ratio cancels. The
        // passes must be allocated by each segment's WAL (the cadence fires on WAL growth) and removed as
        // ABSOLUTE bytes, so the two segments lose different fractions and the ratio actually moves.
        for passes in [1u64, 6, 20] {
            let hi = s
                .batching_ingest_write_amp_saving_upper(passes)
                .expect("a measured band");
            assert!(
                hi > floor,
                "the band must be NON-DEGENERATE: removing checkpoint bytes from the ingest phase must \
                 RAISE the saving, but {passes} pass(es) gave a ceiling of {hi:.2}x against a floor of \
                 {floor:.2}x — an allocation that cancels out of the ratio bounds nothing"
            );
        }

        // And the band widens with the size of the confound — more stray checkpoint WAL, more doubt.
        let few = s.batching_ingest_write_amp_saving_upper(2).expect("band");
        let many = s.batching_ingest_write_amp_saving_upper(12).expect("band");
        assert!(
            many > few,
            "a larger confound must widen the band, not narrow it ({many:.2}x vs {few:.2}x)"
        );
    }
}
