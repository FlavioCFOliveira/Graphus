//! `iot_wire_evidence` — folds one **file-backed over-the-wire** churn run into a standardized,
//! schema-versioned [`EvidenceReport`], and GATES it on the headline invariants (`rmp` #694).
//!
//! It is hermetic: serde + the shared evidence harness, no engine, no Bolt, no network. It reads what
//! `iot_wire` measured (`samples.json`) together with the target's Prometheus `/metrics` scraped
//! **before** and **after** the workload window, and produces `report.json` + `report.md`.
//!
//! # The invariants it gates (`--assert`)
//!
//! > **The on-disk STORE plateaus while `graphus_maintenance_versions_reclaimed_total` climbs — and the
//! > durability that costs is MEASURED, BOUNDED, and reported for the DATABASE, not just the store.**
//!
//! The plateau half needs both of its own halves, since neither is sufficient alone: a flat store on its
//! own proves nothing (a workload that wrote nothing is also flat), and a climbing reclamation counter on
//! its own proves nothing (an engine could reclaim while the footprint still grows without bound).
//! Together they are the claim: under a *sustained* delete-old/insert-new churn that ingests many times
//! the retention window, the engine physically reclaims the tombstoned versions and **new inserts reuse
//! the freed space**, so the store stops growing.
//!
//! But the store is not the database. The gates added in `rmp` #713 exist because the store's plateau was
//! being published as if it settled the footprint question, while the WAL — 258x the store, and growing
//! monotonically — sat unexamined in a secondary report nothing read and nothing gated:
//!
//! * **Anti-rot** — if write statements were committed, `wal_bytes` / `bytes_fsynced` / the logical
//!   payload MUST be non-zero. A commit is not durable until its redo record is fsynced, so a real
//!   file-backed run cannot commit thousands of writes and report no WAL. A zero here is a *measurement*
//!   defect (classically: classifying the WAL by leaf file name — see [`graphus_iot_gen::footprint`]),
//!   and it now FAILS the run instead of publishing `write_amplification: 0`.
//! * **A per-commit WAL FLOOR** — the subtler half, and the one a ceiling can never supply. An
//!   under-counted WAL makes every amplification figure *fall*, so it sails under any ceiling and reads
//!   like a triumph. The floor encodes the physics instead: N commits imply at least N fsynced redo
//!   records, and one record header alone is ~53 B. It is independent of store size, so — unlike an
//!   amplification floor, which the ~1.2x data image can satisfy by coincidence — it cannot be fooled.
//! * **Write amplification** — measured, reported, and held under a CEILING. Not a target: the number is
//!   bad today, and an upper bound is the only honest way to gate a known-bad figure — it cannot be
//!   satisfied by regressing, and it need not be relaxed to accept a fix.
//! * **Total durable footprint** — the store + the WAL, banded across the run, with its own plateau ratio
//!   and its own ceiling. This is the disk an operator actually provisions.
//! * **WAL reclamation actually happened** — asserted whenever the run wrote enough WAL to seal a
//!   segment. The maintenance counters cannot stand in for this: they count MVCC versions freed in the
//!   *store* and climb happily while zero bytes of WAL disk come back.
//!
//! Every one of those rules is a pure function of the samples ([`WireSamples::storage_gate`]), and every
//! one is unit-tested to FIRE on the defect it names. A gate nobody can test is a gate nobody can trust:
//! the bug being remediated here is, precisely, a gate that could not fire.
//!
//! The gate also holds the server's reliability counters to zero (no statement panics, no engine
//! recovery panics, no force-detached engines) and requires the functional wire checks to have passed.
//!
//! # Evidence honesty (`rmp` #699)
//!
//! Nothing here is invented. A field the run could not measure — the storage family in attach mode, an
//! empty latency family — is left out of the report rather than filled with a zero that would read like
//! an observation, and `total_millis` carries the **workload wall-clock**, not the time it took to write
//! the report. The amplification fields carry amplification and nothing else: the plateau ratio, which
//! an earlier revision of this example smuggled into `write_amplification`, now lives in the workload
//! parameters under its own name.
//!
//! # Usage
//!
//! ```text
//! iot_wire_evidence --samples <samples.json> --evidence-dir <dir>
//!                   [--metrics-before <f.prom>] [--metrics-after <f.prom>]
//!                   [--plateau-factor 1.10] [--min-ingest-to-window 3.0]
//!                   [--max-write-amplification 1000] [--max-footprint-ratio 450] [--assert]
//! ```

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use graphus_examples_harness::{
    DatasetScale, EvidenceCollector, MeasurementMode, RunMetadata, ServerMetricsSection, scrape,
};
use graphus_iot_gen::wire_samples::{
    ReaderGate, StorageGate, WAL_RECONSTRUCTION_TOLERANCE, WalCrossCheck, WireSamples, WireSegment,
};

/// Prometheus series the reclamation proof reads directly (the harness's `ServerMetricsSection` covers
/// the transaction/reliability families, but not the maintenance family, so they are read here).
const CHECKPOINTS: &str = "graphus_maintenance_checkpoints_total";
const RECLAIMED: &str = "graphus_maintenance_versions_reclaimed_total";
const FROZEN: &str = "graphus_maintenance_stamps_frozen_total";
const MAINT_FAILURES: &str = "graphus_maintenance_failures_total";

/// **THE ENGINE'S OWN, EXACT WAL VOLUME** (`rmp` #745) — per database.
///
/// The driver's `wal_written_bytes` is a RECONSTRUCTION: poll the WAL directory, keep the maximum length
/// ever seen per segment path. It is inherently a lower bound, because a segment that is created, sealed
/// and reclaimed between two observations is never seen at its sealed length — and that is exactly the
/// defect `rmp` #745 is remediating (the run published a floor as if it were a measurement).
///
/// The engine does not have to guess. `LogSink::durable_len` is a MONOTONE absolute byte offset (== the
/// LSN) that reclamation never rewinds, so the delta of this counter across the workload window IS the
/// WAL volume the window wrote, exactly. Comparing the reconstruction against it is the one check that
/// can *prove* the instrument whole rather than merely fail to catch it lying — and it is why the
/// counter was added rather than the sampler simply being run faster and hoped about.
const WAL_WRITTEN: &str = "graphus_db_wal_bytes_written_total";

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("iot_wire_evidence: error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)] // one linear fold: samples + metrics -> report -> gate
fn run() -> Result<bool, String> {
    let args = Args::parse()?;

    let raw = std::fs::read_to_string(&args.samples)
        .map_err(|e| format!("cannot read {}: {e}", args.samples))?;
    let s: WireSamples = serde_json::from_str(&raw)
        .map_err(|e| format!("cannot parse {} as WireSamples: {e}", args.samples))?;

    // ---- The /metrics before -> after deltas (the server-side evidence channel). ----
    let before = args
        .metrics_before
        .as_deref()
        .map(read_metrics)
        .transpose()?;
    let after = args
        .metrics_after
        .as_deref()
        .map(read_metrics)
        .transpose()?;
    let maintenance = match (&before, &after) {
        (Some(b), Some(a)) => Some(Maintenance {
            checkpoints: counter_delta(b, a, CHECKPOINTS),
            reclaimed: counter_delta(b, a, RECLAIMED),
            frozen: counter_delta(b, a, FROZEN),
            failures: counter_delta(b, a, MAINT_FAILURES),
        }),
        _ => None,
    };
    // THE ENGINE'S EXACT WAL VOLUME for this database, over the workload window. See `WAL_WRITTEN`.
    let exact_wal = match (&before, &after) {
        (Some(b), Some(a)) => labelled_counter_delta(b, a, WAL_WRITTEN, &s.database),
        _ => None,
    };

    // ---- Assemble the standardized report. ----
    let mut collector = EvidenceCollector::new(
        RunMetadata::new(
            s.scenario.clone(),
            "IoT / time-series event graph, FILE-BACKED over the wire: sustained ingest of \
             time-stamped sensor readings under a sliding-window retention policy, driven over Bolt \
             against a real graphus-server (real FileBlockDevice + real segmented WAL). Proves the \
             durable on-disk store PLATEAUS under delete-old/insert-new churn while the server's \
             reclamation counters climb — reclaimed space demonstrably reused, not unbounded growth."
                .to_owned(),
        )
        .with_dataset(DatasetScale::new(
            s.final_live_readings + s.sensors,
            s.final_live_readings, // one :EMITTED per live reading at steady state
        )),
    );
    collector.start();
    collector.set_measurement_mode(if s.local {
        MeasurementMode::Local
    } else {
        MeasurementMode::External
    });

    {
        let w = &mut collector.metadata_mut().workload;
        w.insert("connection".into(), s.transport.label().into());
        w.insert("database".into(), s.database.clone());
        w.insert("seed".into(), s.seed.to_string());
        w.insert("sensors".into(), s.sensors.to_string());
        w.insert("rate".into(), s.rate.to_string());
        w.insert("window".into(), s.window.to_string());
        w.insert("ticks".into(), s.ticks.to_string());
        w.insert("warmup_ticks".into(), s.warmup_ticks.to_string());
        w.insert("ingest_clients".into(), s.ingest_clients.to_string());
        w.insert("checkpoint_every".into(), s.checkpoint_every.to_string());
        w.insert(
            "ingest_batch".into(),
            format!(
                "{} readings per statement and per commit — MEASURED (a real gateway batches; the \
                 --batch knob is a CAP on the flush buffer, and a tick barrier plus the uneven \
                 per-sensor sharding keep a commit at about rate/clients readings)",
                s.batch
            ),
        );
        w.insert("ingest_commits".into(), s.ingest_ops.to_string());
        w.insert(
            "checkpoints_issued".into(),
            s.checkpoints_issued.to_string(),
        );
        w.insert("total_ingested".into(), s.total_ingested.to_string());
        // The DOMAIN rate: readings/second. Deliberately NOT `throughput.ops_per_sec` — that field
        // carries statements/second (the unit its sibling `operations` and the latency percentiles are
        // in). Two different quantities, two different names, so neither can be mistaken for the other.
        if let Some(rate) = s.ingest_per_sec() {
            w.insert(
                "ingest_readings_per_sec".into(),
                format!(
                    "{rate:.0} readings/s ingested (the DOMAIN rate; throughput.ops_per_sec is the \
                     STATEMENT rate, and with --batch the two differ by the batch factor)"
                ),
            );
        }
        w.insert(
            "ingest_to_window".into(),
            format!("{:.2}", s.ingest_to_window()),
        );
        w.insert(
            "steady_state_live".into(),
            s.final_live_readings.to_string(),
        );
        w.insert("retried_ops".into(), s.retried_ops.to_string());
        w.insert(
            "logical_ingested_bytes".into(),
            s.logical_ingested_bytes.to_string(),
        );
        // The plateau ratio gets its OWN name. It is NOT an amplification, and the earlier revision of
        // this example that reported it as `storage.write_amplification` was misusing a standard field.
        if let Some(r) = s.plateau_ratio() {
            w.insert("store_plateau_ratio".into(), format!("{r:.4}"));
        }
        if let Some(st) = &s.storage {
            w.insert(
                "store_plateau_min_bytes".into(),
                st.plateau_min_data_bytes.to_string(),
            );
            w.insert(
                "store_plateau_max_bytes".into(),
                st.plateau_max_data_bytes.to_string(),
            );
            w.insert("wal_written_bytes".into(), st.wal_written_bytes.to_string());
            w.insert("wal_peak_bytes".into(), st.wal_peak_bytes.to_string());
            w.insert("wal_residual_bytes".into(), st.wal_bytes.to_string());
            w.insert(
                "wal_plateaued".into(),
                match s.wal_plateaued(1.5) {
                    Some(true) => "yes".to_owned(),
                    Some(false) => {
                        "NO — the WAL sawtooths in a TIGHT store-proportional band (rmp #706); see notes"
                            .to_owned()
                    }
                    None => "not measured".to_owned(),
                },
            );
            // ------------------------------------------------------------------------------------
            // THE TOTAL DURABLE FOOTPRINT — what the DATABASE costs on disk, not what one component
            // of it costs. `storage.plateau_ratio` reports the STORE's plateau (that is what the
            // schema defines it as), and the store's plateau is a genuine 1.000. Since `rmp` #706 the
            // WAL is store-proportional, so the TOTAL footprint sawtooths within a tight band too (this
            // run: ~1.56x, was ~7.1x while #706 was open) — close to, but not a perfect, plateau. Both
            // numbers, side by side, under names that say which is which (`rmp` #713 / #706).
            // ------------------------------------------------------------------------------------
            w.insert(
                "durable_footprint_peak_bytes".into(),
                st.footprint_peak_bytes.to_string(),
            );
            w.insert(
                "durable_footprint_min_bytes".into(),
                st.footprint_min_bytes.to_string(),
            );
            w.insert(
                "durable_footprint_final_bytes".into(),
                st.footprint_final_bytes.to_string(),
            );
            if let Some(r) = s.durable_footprint_plateau_ratio() {
                w.insert(
                    "durable_footprint_plateau_ratio".into(),
                    format!(
                        "{r:.2}{}",
                        if r <= 1.10 {
                            " (FLAT)"
                        } else {
                            " — the DATABASE sawtooths in a tight store-proportional band (rmp #706); see notes"
                        }
                    ),
                );
            }
            // THE LUMPED RATIO, DECOMPOSED WHERE IT IS QUOTED (`rmp` #745 / evidence-honesty rule 5).
            //
            // "53x the graph" reads like a statement about the WAL. It is not: ~60% of that peak is the
            // FIXED doublewrite preallocation, a constant that does not scale with the graph and cannot
            // regress. The ratio is kept — the disk an operator must provision is a real question — but
            // it is never quoted without the decomposition that says what it is made of, and the
            // graph-scaling half is published beside it under its own name, where a regression actually
            // shows up.
            if let Some(r) = s.footprint_peak_over_store() {
                w.insert(
                    "durable_footprint_peak_over_store".into(),
                    format!(
                        "{r:.0}x — but READ THE DECOMPOSITION: of the {} B peak, {} B ({:.0}%) is the \
                         FIXED doublewrite preallocation + catalog, which does NOT scale with the graph \
                         and cannot regress. This ratio is dominated by a constant on a small store and \
                         is NOT a measure of WAL behaviour. The graph-scaling half is \
                         wal_to_store_ratio_peak ({}), and that is what a segment-sizing regression moves",
                        st.footprint_peak_bytes,
                        s.fixed_preallocation_bytes().unwrap_or(0),
                        100.0 * s.footprint_peak_fixed_share().unwrap_or(0.0),
                        s.wal_to_store_ratio_peak()
                            .map_or("not measured".to_owned(), |x| format!("{x:.1}x")),
                    ),
                );
            }
            if let Some(fixed) = s.fixed_preallocation_bytes() {
                w.insert(
                    "fixed_preallocation_bytes".into(),
                    format!(
                        "{fixed} (the {} B doublewrite buffer + the {} B catalog). A CONSTANT per \
                         database: it does not scale with the graph, so it is kept OUT of \
                         storage.space_amplification — which used to be 96% this number, divided by the \
                         live data, and therefore moved with the size of a constant rather than with \
                         anything the engine did (evidence-honesty rule 5)",
                        st.dwb_bytes, st.other_bytes,
                    ),
                );
            }
            // Did WAL disk physically come back? The maintenance counters cannot answer this: they
            // count reclaimed MVCC versions in the STORE and climb happily while the WAL frees nothing.
            w.insert(
                "wal_reclaim_events".into(),
                match s.sealed_a_segment() {
                    Some(true) => format!(
                        "{} (freed {} B of WAL disk; the run wrote {} B, past the {} B segment seal size \
                         of a {} B store — clamp(store, 1 MiB, 64 MiB), rmp #706 — so reclamation was \
                         OBSERVABLE and was observed)",
                        st.wal_reclaim_events,
                        st.wal_reclaimed_bytes,
                        st.wal_written_bytes,
                        s.segment_seal_bytes().unwrap_or(0),
                        st.data_bytes,
                    ),
                    Some(false) => format!(
                        "{} — THE RUN WAS TOO SHORT TO SEAL A SEGMENT: it wrote only {} B of WAL, below \
                         the {} B seal size of a {} B store, so NO WAL disk could be freed however many \
                         checkpoints ran. Use the `reclaim` profile (the default) to observe the cycle",
                        st.wal_reclaim_events,
                        st.wal_written_bytes,
                        s.segment_seal_bytes().unwrap_or(0),
                        st.data_bytes,
                    ),
                    None => "not measured".to_owned(),
                },
            );
            w.insert(
                "doublewrite_bytes".into(),
                format!("{} (fixed preallocation, not graph data)", st.dwb_bytes),
            );
            if let Some(io) = st.server_io_write_bytes {
                w.insert("server_proc_io_write_bytes".into(), io.to_string());
            }
        }
        // BOTH ratios, and the peak first: the residual-at-exit ratio alone is a mirage (it depends on
        // where in the WAL's sawtooth the run stopped), and quoting only the flattering one would be
        // exactly the kind of dishonest evidence this example exists to eliminate.
        if let Some(r) = s.wal_to_store_ratio_peak() {
            w.insert("wal_to_store_ratio_peak".into(), format!("{r:.1}"));
        }
        if let Some(r) = s.wal_to_store_ratio() {
            w.insert("wal_to_store_ratio_residual".into(), format!("{r:.1}"));
        }
        // Explicit, machine-readable NOT-MEASURED markers (`rmp` #699). In attach mode the
        // `storage`/`cpu`/`memory` sections are unmeasured, so (since `rmp` #740) the report OMITS
        // them entirely — an absent section, never a present-but-empty `{}` and never a `0` that reads
        // like a measurement. These markers, plus `measurement_mode: external`, say out loud which
        // sections are absent and why.
        w.insert(
            "storage_measured".into(),
            if s.storage.is_some() {
                "yes".into()
            } else {
                "no — attach mode: the store files belong to the target; the storage section is ABSENT = NOT MEASURED".to_owned()
            },
        );
        w.insert(
            "server_cpu_measured".into(),
            if s.server_cpu_secs.is_some() {
                "yes".into()
            } else {
                "no — attach mode: /proc/<server-pid> is not readable; the cpu section is ABSENT = NOT MEASURED".to_owned()
            },
        );
        w.insert(
            "server_rss_measured".into(),
            if s.server_peak_rss_bytes.is_some() {
                "yes".into()
            } else {
                "no — attach mode: /proc/<server-pid> is not readable; the memory section is ABSENT = NOT MEASURED".to_owned()
            },
        );
        // ------------------------------------------------------------------------------------------
        // THE INGEST-SHAPE COMPARISON (`rmp` #745). The example's headline durability finding is that a
        // COMMIT PER 32-BYTE READING dominates the bill — so both shapes are MEASURED, on the same
        // server, the same database and the same steady state, and both figures are published side by
        // side. Neither is derived from the other by arithmetic: an estimate would be a model of the
        // engine wearing the clothes of an observation.
        // ------------------------------------------------------------------------------------------
        for seg in &s.segments {
            w.insert(
                format!("segment [{}]", seg.label),
                format!(
                    "ticks [{}, {}) — {} readings in {} commits, {} of them ingest carrying {} \
                     readings each (MEASURED; the --batch cap was {}), {} logical bytes{}{}{}{}",
                    seg.first_tick,
                    seg.next_tick,
                    seg.readings,
                    seg.commits,
                    seg.ingest_commits,
                    seg.readings_per_commit()
                        .map_or("?".to_owned(), |r| format!("{r:.2}")),
                    seg.batch_cap,
                    seg.logical_bytes,
                    // BOTH physical terms, always — because write amplification is (WAL + data-image
                    // growth) / logical, and printing only the WAL beside the ratio gives a reader two
                    // numbers that do not divide into the third. The batched segment spans the warmup,
                    // where the store still grows; the batch=1 control sits in steady state, where it
                    // does not. Naming the growth term is what lets anyone check the arithmetic — and
                    // what stops the difference between the two segments from hiding inside the ratio.
                    seg.wal_written_bytes.map_or(String::new(), |wal| {
                        let growth = seg.store_growth_bytes.unwrap_or(0);
                        if growth > 0 {
                            format!(
                                ", wrote {wal} B of WAL + {growth} B of data-image growth = {} B \
                                 physical",
                                wal.saturating_add(growth)
                            )
                        } else {
                            format!(", wrote {wal} B of WAL (the data image did not grow)")
                        }
                    }),
                    seg.write_amplification().map_or(String::new(), |a| format!(
                        " => WHOLE-SEGMENT WRITE AMPLIFICATION {a:.1}x"
                    )),
                    seg.wal_bytes_per_commit()
                        .map_or(String::new(), |b| format!(" ({b:.0} B of WAL per commit")),
                    seg.wal_bytes_per_reading()
                        .map_or(")".to_owned(), |b| format!(", {b:.0} B per READING)")),
                ),
            );
            // THE PHASE SPLIT (`rmp` #745). The whole-segment figure above lumps the ingest together
            // with the fixed per-tick retention + checkpoint cost that batching cannot touch. Both terms
            // are measured, at phase boundaries INSIDE the tick, so the ingest can be compared on its own.
            if let (Some(ingest), Some(retention), Some(checkpoint)) = (
                seg.ingest_wal_bytes,
                seg.retention_wal_bytes,
                seg.checkpoint_wal_bytes,
            ) {
                w.insert(
                    format!("segment [{}] WAL by phase", seg.label),
                    format!(
                        "INGEST {ingest} B{} | RETENTION DELETE {retention} B | CHECKPOINT {checkpoint} \
                         B — the last two are the FIXED per-tick cost F ({} B/tick over {} ticks), paid \
                         regardless of the batch size and identical in both segments{}",
                        seg.ingest_write_amplification().map_or(String::new(), |a| {
                            format!(
                                " => INGEST-ONLY WRITE AMPLIFICATION {a:.1}x{}",
                                seg.ingest_wal_per_reading()
                                    .map_or(String::new(), |b| format!(" ({b:.0} B per READING)"))
                            )
                        }),
                        seg.fixed_wal_per_tick()
                            .map_or("?".to_owned(), |f| format!("{f:.0}")),
                        seg.ticks,
                        seg.fixed_wal_share().map_or(String::new(), |x| format!(
                            ", i.e. {:.0}% of this segment's whole WAL bill",
                            100.0 * x
                        )),
                    ),
                );
            }
            if let Some(l) = seg.ingest_latency {
                w.insert(
                    format!("segment [{}] ingest statement latency_ms", seg.label),
                    format!(
                        "p50={:.2} p99={:.2} p999={:.2} (n={} statements of {} reading(s))",
                        l.p50_ms, l.p99_ms, l.p999_ms, l.count, seg.batch
                    ),
                );
            }
        }
        // ------------------------------------------------------------------------------------------
        // THE FIXED PER-TICK COST F (`rmp` #745) — published as its own named line, because it is
        // neither the WAL format nor the commit rate, and leaving it inside the batch comparison
        // silently dilutes it and then invites the residual to be blamed on the format.
        //
        // Every tick pays it regardless of batch size: the retention `DETACH DELETE` of a tick's worth
        // of aged-out readings, plus the amortised `CHECKPOINT DATABASE`. Written out, the whole-segment
        // comparison is `(50·A₁ + F) / (2·A₂₅ + F)` — F sits in BOTH numerators and drags the ratio
        // toward 1. So the whole-segment saving is a FLOOR on the ingest saving, and the headline is
        // made on the ingest phase alone, where F cancels.
        // ------------------------------------------------------------------------------------------
        if let Some(main) = s.main_segment() {
            if let (Some(f), Some(share)) = (main.fixed_wal_per_tick(), main.fixed_wal_share()) {
                w.insert(
                    "fixed_wal_per_tick".into(),
                    format!(
                        "{f:.0} B/tick of WAL is the RETENTION DELETE + the amortised CHECKPOINT — paid \
                         every tick REGARDLESS of the ingest batch size ({:.0}% of the main segment's \
                         whole WAL bill: {} B of retention + {} B of checkpoint over {} ticks). It is \
                         neither the WAL format nor the commit rate, and it appears in BOTH segments' \
                         numerators — so the whole-segment batching saving is DILUTED by it and is a \
                         FLOOR. The headline comparison is made on the ingest phase alone, where it \
                         cancels",
                        100.0 * share,
                        main.retention_wal_bytes.unwrap_or(0),
                        main.checkpoint_wal_bytes.unwrap_or(0),
                        main.ticks,
                    ),
                );
            }
        }
        // THE HEADLINE: the INGEST-ONLY saving — the sound experiment, with F excluded from both sides.
        if let Some(saving) = s.batching_ingest_write_amp_saving() {
            let (single, batched) = (
                s.control_segment()
                    .and_then(WireSegment::ingest_write_amplification),
                s.main_segment()
                    .and_then(WireSegment::ingest_write_amplification),
            );
            w.insert(
                "batching_ingest_write_amp_saving".into(),
                format!(
                    "{saving:.1}x (THE HEADLINE) — measured on the INGEST PHASE ALONE, so the fixed \
                     per-tick retention + checkpoint cost that BOTH segments pay is excluded and the two \
                     differ in exactly one variable: the batch size. Per-reading commits cost {} of \
                     ingest write amplification; {}-reading batches cost {}",
                    single.map_or("not measured".to_owned(), |x| format!("{x:.0}x")),
                    s.batch,
                    batched.map_or("not measured".to_owned(), |x| format!("{x:.0}x")),
                ),
            );
        }
        if let Some(saving) = s.batching_write_amp_saving() {
            w.insert(
                "batching_write_amp_saving_whole_segment".into(),
                // One decimal, deliberately: the precision is the comparison's whole point.
                format!(
                    "{saving:.1}x — the WHOLE-SEGMENT saving, retention and checkpoint included. This is \
                     a FLOOR on the ingest saving, not the ingest saving: the fixed per-tick cost F is in \
                     BOTH numerators of (50·A₁ + F) / (2·A₂₅ + F) and drags the ratio toward 1. Quote it \
                     as what a deployment running THIS retention cadence pays end to end; quote \
                     batching_ingest_write_amp_saving as what BATCHING is worth",
                ),
            );
        } else if s.control_batch1_ticks == 0 {
            w.insert(
                "batching_write_amp_saving_whole_segment".into(),
                "not measured — the batch=1 CONTROL segment was disabled (--batch1-ticks 0), so this \
                 run cannot compare the two ingest shapes"
                    .to_owned(),
            );
        }
        // ------------------------------------------------------------------------------------------
        // EVERY WAL BYTE, ATTRIBUTED (`rmp` #745). The segments used to be published beside a run total
        // they did not add up to — 34.78 + 11.24 against 49.65 MB, leaving 3.62 MB (7.3%) unattributed.
        // An unattributed remainder is not a rounding artefact; it is where a measurement defect hides.
        // ------------------------------------------------------------------------------------------
        if let Some(a) = &s.wal_attribution {
            w.insert(
                "wal_attribution".into(),
                format!(
                    "bootstrap (schema DDL + sensor fleet) {} B + warmup (the growth ramp, excluded from \
                     both compared segments) {} B + main {} B + control {} B + post-run checks (four \
                     deliberately-REJECTED writes — an abort is durable work too) {} B = {} B, and the \
                     run measured {} B of cumulative WAL. Every byte is attributed to exactly one phase, \
                     and the gate FAILS the run if they do not reconcile",
                    a.bootstrap_bytes,
                    a.warmup_bytes,
                    a.main_bytes,
                    a.control_bytes,
                    a.post_run_bytes,
                    a.total(),
                    s.storage.as_ref().map_or(0, |st| st.wal_written_bytes),
                ),
            );
        }
        // The instrument's own self-check, published so a reader can re-derive it (`rmp` #745).
        if let (Some(floor), Some(st)) = (s.run_wal_written_floor(), &s.storage) {
            w.insert(
                "wal_instrument_self_check".into(),
                format!(
                    "the run's own on-disk WAL series proves at least {floor} B were written (the sum of \
                     every tick-to-tick GROWTH of the on-disk WAL; reclamation can only ever shrink that \
                     figure, so each of those bytes was certainly written). The instrument reconstructed \
                     {} B. {} — a reconstruction BELOW its own floor would mean a segment was created, \
                     sealed and reclaimed between two samples and never observed, which is exactly the \
                     defect rmp #745 fixed by sampling the WAL directory from a dedicated 2 ms thread \
                     instead of once per tick",
                    st.wal_written_bytes,
                    if st.wal_written_bytes >= floor {
                        "PASS"
                    } else {
                        "FAIL: THE INSTRUMENT LOST BYTES"
                    },
                ),
            );
        }

        // ------------------------------------------------------------------------------------------
        // THE CONCURRENT READ MIX (`rmp` #745). Before this, the example's read mix was ~0% — every read
        // was a `count(…)` — so a corrupted payload passed green and an index silently answering with an
        // EMPTY result (`rmp` #738) could not have been caught here at all.
        // ------------------------------------------------------------------------------------------
        match &s.readers {
            Some(r) => {
                w.insert(
                    "reader_clients".into(),
                    format!(
                        "{} independent Bolt connections reading WHILE the writers churned",
                        r.clients
                    ),
                );
                w.insert(
                    "reader_throughput".into(),
                    r.queries_per_sec().map_or("not measured".to_owned(), |q| {
                        format!(
                            "{q:.0} gated queries/s ({} queries over {:.1}s)",
                            r.total_queries(),
                            r.secs
                        )
                    }),
                );
                w.insert(
                    "reader_rows_verified".into(),
                    format!(
                        "{} rows compared field-by-field (sensor, seq, ts, value) against the \
                         generator's own stream — {} mismatch(es), {} empty-but-expected result(s)",
                        r.total_rows_verified(),
                        r.families.iter().map(|f| f.mismatches).sum::<u64>(),
                        r.families.iter().map(|f| f.empty_but_expected).sum::<u64>(),
                    ),
                );
                w.insert("reader_errors".into(), r.errors.to_string());
                for f in &r.families {
                    w.insert(
                        format!("reader family [{}]", f.name),
                        format!(
                            "{} queries ({} gated as EXACT set equalities, {} against the sound \
                             straddle bound), {} rows returned, {} verified, {} mismatch(es), {} \
                             empty-but-expected{}",
                            f.queries,
                            f.exact_gated,
                            f.bounded_gated,
                            f.rows_returned,
                            f.rows_verified,
                            f.mismatches,
                            f.empty_but_expected,
                            if f.failure_samples.is_empty() {
                                String::new()
                            } else {
                                format!(" — FAILURES: {}", f.failure_samples.join("; "))
                            },
                        ),
                    );
                    if let Some(l) = f.latency {
                        w.insert(
                            format!("reader family [{}] latency_ms", f.name),
                            format!(
                                "p50={:.2} p99={:.2} p999={:.2} (n={})",
                                l.p50_ms, l.p99_ms, l.p999_ms, l.count
                            ),
                        );
                    }
                }
            }
            None => {
                w.insert(
                    "reader_clients".into(),
                    "0 — NO concurrent read mix ran. This run measures a WRITE-ONLY workload and \
                     asserts nothing about what the server reads back under churn"
                        .to_owned(),
                );
            }
        }
        w.insert(
            "payload_samples_verified".into(),
            format!(
                "{} surviving readings read back in full after the churn and compared field-by-field \
                 against the generator's ground truth (ts compared as a DATETIME, not re-derived)",
                s.payload_samples_verified
            ),
        );

        // The store + WAL time series, so the growth-then-plateau curve is inspectable.
        w.insert("store_series".into(), store_series(&s));
        w.insert("wal_series".into(), wal_series(&s));
        // THE EXACT COUNTER, beside the reconstruction (`rmp` #745). Publishing both, and their drift,
        // is what lets a reader verify the instrument rather than trust it.
        if let (Some(exact), Some(st)) = (exact_wal, &s.storage) {
            let drift = if exact > 0 {
                100.0 * (st.wal_written_bytes as f64 - exact as f64) / exact as f64
            } else {
                0.0
            };
            w.insert(
                "wal_written_bytes_exact".into(),
                format!(
                    "{exact} B — the ENGINE'S OWN exact figure ({WAL_WRITTEN}, a monotone durable byte \
                     offset that reclamation never rewinds), delta'd across the workload window. The \
                     driver's polled reconstruction says {} B: a drift of {drift:+.2}%. The \
                     reconstruction is a LOWER BOUND by construction (a WAL segment born, sealed and \
                     reclaimed between two samples is never observed at its sealed length), so this \
                     cross-check is the only thing that can prove it whole rather than merely fail to \
                     catch it lying — and the run FAILS if they drift more than {:.0}%",
                    st.wal_written_bytes,
                    100.0 * WAL_RECONSTRUCTION_TOLERANCE,
                ),
            );
        }
        if let Some(m) = &maintenance {
            // THE BACKGROUND-MAINTENANCE CONFOUND, DISCLOSED (`rmp` #745).
            //
            // The driver issues `CHECKPOINT DATABASE` explicitly, and brackets it with a phase mark so
            // its WAL is attributed to the CHECKPOINT phase. But the engine ALSO runs a background
            // maintenance cadence of its own, triggered by WAL growth (clamp(4 × store, 8 MiB, 256 MiB)
            // — here the 8 MiB floor), and it does not coordinate with the operator's explicit
            // checkpoints. Those passes fire asynchronously, so their WAL lands in whichever phase
            // happened to be running — usually the longest one, INGEST.
            //
            // This is a real confound on the ingest-only figure and it is stated, not buried: it is
            // precisely the class of unmeasured fixed cost that the false "page image" story existed to
            // paper over, and repeating that mistake in a new place would be the worst possible outcome
            // of this work.
            let background = m.checkpoints.saturating_sub(s.checkpoints_issued);
            w.insert(
                "background_maintenance_passes".into(),
                format!(
                    "{background} (the engine ran {} maintenance checkpoints while the driver issued \
                     {} explicitly). The background cadence fires on WAL GROWTH — clamp(4 × store_bytes, \
                     8 MiB, 256 MiB), i.e. the 8 MiB floor for this store — and it does NOT reset on an \
                     operator's explicit CHECKPOINT DATABASE, so the two triggers run independently. \
                     CAVEAT, STATED: a background pass fires asynchronously, so its WAL is attributed to \
                     whichever phase was running at the time — usually INGEST, the longest. The \
                     ingest-only write amplification therefore carries an upper bound of this much \
                     checkpoint WAL that is not ingest; the retention/checkpoint term F below is a LOWER \
                     bound on the true fixed cost for the same reason",
                    m.checkpoints, s.checkpoints_issued,
                ),
            );
            w.insert(
                "maintenance_checkpoints_delta".into(),
                m.checkpoints.to_string(),
            );
            // THE HEADLINE IS A BAND, NOT A POINT — and this is where the other end of it is computed,
            // beside the confound that creates it. The background passes above are checkpoint work whose
            // bytes land in whichever phase was running, so the ingest-only saving is a FLOOR. Charging
            // every one of them to the ingest phase bounds the other end. The truth is inside the band,
            // and the report claims neither end as the value.
            let background = m.checkpoints.saturating_sub(s.checkpoints_issued);
            if let (Some(lo), Some(hi)) = (
                s.batching_ingest_write_amp_saving(),
                s.batching_ingest_write_amp_saving_upper(background),
            ) {
                w.insert(
                    "batching_ingest_write_amp_saving_band".into(),
                    format!(
                        "{lo:.1}x – {hi:.1}x — THE HEADLINE, AS A BAND. {background} background \
                         maintenance pass(es) fired on the engine's own cadence, on top of the {} the \
                         driver issued, and a background pass's WAL lands in whichever phase happened to \
                         be running. Those bytes are CHECKPOINT work, not ingest work, so wherever they \
                         land inside INGEST they inflate it — and they inflate the smaller (batched) \
                         figure relatively more, dragging the measured saving DOWN. {lo:.1}x therefore \
                         charges every stray byte to batching's disadvantage (the FLOOR); {hi:.1}x removes \
                         all of it from the ingest phase, split between the segments in proportion to \
                         their ingest WAL (the CEILING). Eliminating the confound outright needs `rmp` \
                         #754 — an explicit CHECKPOINT DATABASE does not reset the background cadence, so \
                         these passes run with nothing left to reclaim",
                        s.checkpoints_issued,
                    ),
                );
            }
            w.insert(
                "maintenance_versions_reclaimed_delta".into(),
                m.reclaimed.to_string(),
            );
            w.insert(
                "maintenance_stamps_frozen_delta".into(),
                m.frozen.to_string(),
            );
        }
        if !s.schema_skipped.is_empty() {
            w.insert("schema_skipped".into(), s.schema_skipped.join(" | "));
        }
        for c in &s.checks {
            w.insert(
                format!("check: {}", c.name),
                format!("{} — {}", if c.ok { "PASS" } else { "FAIL" }, c.detail),
            );
        }
    }

    // total_millis is the WORKLOAD wall-clock (`rmp` #699) — not the time this emitter took to run.
    let workload = Duration::from_secs_f64(s.workload_secs);
    collector.record_total_duration(workload);
    collector.phase("churn", workload);

    // ---- Throughput + latency: measured, or omitted. ----
    //
    // `operations` and `ops_per_sec` MUST carry the SAME quantity, or the report lies to anyone who
    // divides one by the other. The shared schema defines both over OPERATIONS (statements), and the
    // latency percentiles below are per-STATEMENT too, so a statement is the unit here.
    //
    // This mattered the moment `--batch` landed. While ingest was one statement per reading the two
    // quantities coincided numerically, so filling `ops_per_sec` with READINGS/s was invisibly wrong.
    // Batching separates them by the batch factor (~25x), and a readings/s rate sitting in a field
    // named `ops_per_sec` beside an `operations` count of statements is exactly the kind of quietly
    // false evidence this suite exists to refuse. The domain rate (readings/s) is still the number a
    // reader of an INGEST example wants — so it is reported, under a name that says what it is.
    {
        let ops = s.statement_ops();
        let t = collector.throughput_mut();
        t.operations = (ops > 0).then_some(ops);
        t.ops_per_sec = s.statement_ops_per_sec();
        // THE PERCENTILES DESCRIBE THE SAME POPULATION `operations` COUNTS (`rmp` #745).
        //
        // They used to be the batched-INGEST family alone — n = 230 — published beside an `operations`
        // count of 924. So `throughput.p50` described about a quarter of `throughput.operations`,
        // silently excluding the control segment's 500 per-reading commits (whose p50 is 1.79 ms against
        // the batched 7.18 ms — a wildly different distribution) and 136 retention deletes. That is the
        // same defect family as the `ops_per_sec` bug fixed above: three fields in one block, not all
        // describing the same thing, so any relation a reader draws between them is false.
        //
        // The block now carries the statement-wide distribution. The per-FAMILY percentiles are not lost
        // — the two segments carry their own, and the DELETE and CHECKPOINT families carry theirs, each
        // under a name that says which family it is.
        if let Some(l) = s.statement_latency {
            t.p50_latency_ms = Some(l.p50_ms);
            t.p99_latency_ms = Some(l.p99_ms);
            t.p999_latency_ms = Some(l.p999_ms);
        }
        // Abort rate: the fraction of statements the engine made the client retry. A sensor-sharded
        // ingest is conflict-free by construction, so this is expected to be 0 — and that zero is a
        // REAL observation (the one metric whose measured value may legitimately be 0.0), not an
        // assumption and not a placeholder.
        let attempted = ops.saturating_add(s.retried_ops);
        if attempted > 0 {
            t.abort_rate = Some(s.retried_ops as f64 / attempted as f64);
        }
    }
    // The per-FAMILY percentiles, each under a name that says which family it describes. The `throughput`
    // block above carries the statement-wide distribution (the population `operations` counts); these say
    // how the families that make it up differ — which is the useful part, and the part that a single
    // blended percentile cannot show.
    if let Some(l) = s.insert_latency {
        let w = &mut collector.metadata_mut().workload;
        w.insert(
            "batched_ingest_latency_ms".into(),
            format!(
                "p50={:.2} p99={:.2} p999={:.2} (n={} statements, each carrying {} readings)",
                l.p50_ms, l.p99_ms, l.p999_ms, l.count, s.batch
            ),
        );
    }
    if let Some(l) = s.delete_latency {
        let w = &mut collector.metadata_mut().workload;
        w.insert(
            "retention_delete_latency_ms".into(),
            format!(
                "p50={:.2} p99={:.2} p999={:.2} (n={})",
                l.p50_ms, l.p99_ms, l.p999_ms, l.count
            ),
        );
    }
    if let Some(l) = s.statement_latency {
        let w = &mut collector.metadata_mut().workload;
        w.insert(
            "statement_latency_population".into(),
            format!(
                "throughput.p50/p99/p999 describe ALL {} statements the run issued (batched ingest + \
                 per-reading control ingest + retention DELETEs + CHECKPOINTs) — the SAME population \
                 throughput.operations counts, so the fields in that block are relatable to one another. \
                 The families differ sharply and are reported separately above; a single blended \
                 percentile is coherent, not informative",
                l.count
            ),
        );
    }
    if let Some(l) = s.checkpoint_latency {
        let w = &mut collector.metadata_mut().workload;
        w.insert(
            "checkpoint_database_latency_ms".into(),
            format!(
                "p50={:.2} p99={:.2} p999={:.2} (n={})",
                l.p50_ms, l.p99_ms, l.p999_ms, l.count
            ),
        );
    }

    // ---- Storage: the REAL durable bytes (local only). ----
    if let Some(st) = &s.storage {
        let storage = collector.storage_mut();
        // `store_bytes` is the DATA IMAGE — the graph itself. The doublewrite buffer is a fixed
        // preallocation per database and the catalog is constant overhead; folding them in here would
        // inflate the store and deflate every ratio derived from it. Both are reported by name in the
        // workload params instead.
        storage.store_bytes = Some(st.data_bytes);
        storage.store_pages = Some(st.data_bytes.div_ceil(8192));
        storage.wal_bytes = Some(st.wal_bytes);
        storage.wal_pages = Some(st.wal_bytes.div_ceil(8192));
        // `bytes_fsynced` CARRIES THE CUMULATIVE WAL VOLUME, AND THAT IS A PROXY — SAY SO (`rmp` #745).
        //
        // It is not an fsync-syscall byte counter, and it is a LOWER BOUND on the bytes this workload
        // caused to be fsynced: every WAL byte is fsynced before its commit is acknowledged (so the WAL
        // volume is certainly included), but a CHECKPOINT also fsyncs the store pages it flushes home and
        // the doublewrite buffer it stages them through, and none of that is in this figure. The
        // harness's shared schema has no field for "the WAL volume", so the documented
        // WAL-as-fsync-proxy convention is used — but a proxy that is not named as one is just a wrong
        // number. `server_proc_io_write_bytes` (below, from /proc) is the kernel's own account of the
        // TOTAL bytes the server sent to storage, and is the honest upper cross-check.
        storage.bytes_fsynced = Some(st.wal_written_bytes);
        if let Some(w) = s.write_amplification() {
            storage.write_amplification = Some(w);
        }
        if let Some(a) = s.space_amplification() {
            storage.space_amplification = Some(a);
        }
        // Per-element durable cost (`rmp #711`): the measured DATA IMAGE amortised over the graph that
        // image holds — `metadata.dataset` above is exactly the final live readings plus their sensors.
        collector.record_per_element_costs();
        // The durable store's retention PLATEAU, when the run observed one: this is a retention/GC
        // workload, so it is one of the two reports in the suite that legitimately carries the field.
        if let Some(ratio) = s.plateau_ratio() {
            collector.record_plateau_ratio(ratio);
        }
    }

    // ---- CPU / RAM of the SERVER process (local only). ----
    if let Some((user, system)) = s.server_cpu_secs {
        let cpu = collector.cpu_mut();
        cpu.user_secs = Some(user);
        cpu.system_secs = Some(system);
        // No workload window ⇒ nothing to divide by ⇒ the utilisation is absent, not `0.0` cores.
        cpu.mean_core_utilisation =
            (s.workload_secs > 0.0).then(|| (user + system) / s.workload_secs);
    }
    if let Some(rss) = s.server_peak_rss_bytes {
        let mem = collector.memory_mut();
        mem.peak_rss_bytes = Some(rss);
        mem.final_rss_bytes = Some(rss);
    }

    // ---- Server-side /metrics evidence (transactions + the reliability signals). ----
    let server = match (&before, &after) {
        (Some(b), Some(a)) => {
            let section = ServerMetricsSection::from_snapshots(b, a, &s.database);
            collector.record_server_metrics(section.clone());
            Some(section)
        }
        _ => None,
    };

    // ---- Notes: the claim, and every caveat, stated in full. ----
    add_notes(&mut collector, &s, maintenance.as_ref());

    // ---- The gate. ----
    let mut failures = Vec::new();
    gate(
        &args,
        &s,
        maintenance.as_ref(),
        exact_wal,
        server.as_ref(),
        &mut failures,
    );

    let report = collector.finish();
    let (json, md) = report
        .write_to(&args.evidence_dir)
        .map_err(|e| format!("cannot write evidence to {}: {e}", args.evidence_dir))?;
    println!("wrote {}", json.display());
    println!("wrote {}", md.display());

    print_summary(&s, maintenance.as_ref());

    if args.assert_invariants && !failures.is_empty() {
        for f in &failures {
            eprintln!("iot_wire_evidence: INVARIANT VIOLATED — {f}");
        }
        return Ok(false);
    }
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("iot_wire_evidence: (not gated) {f}");
        }
    }
    println!("GRAPHUS_IOT_WIRE_EVIDENCE_OK");
    Ok(true)
}

/// The maintenance-family deltas over the workload window.
struct Maintenance {
    checkpoints: u64,
    reclaimed: u64,
    frozen: u64,
    failures: u64,
}

/// The headline gate: the store PLATEAUS while reclamation CLIMBS, the run was long enough for that to
/// mean anything, the server stayed healthy, and every functional wire check held.
#[allow(clippy::too_many_arguments)]
fn gate(
    args: &Args,
    s: &WireSamples,
    maintenance: Option<&Maintenance>,
    exact_wal: Option<u64>,
    server: Option<&ServerMetricsSection>,
    failures: &mut Vec<String>,
) {
    // 1. The run must ingest many times the window, or a "plateau" is just a short run.
    if s.ingest_to_window() < args.min_ingest_to_window {
        failures.push(format!(
            "the run ingested only {:.1}× the retention window (need >= {:.1}×) — too short for the \
             plateau to mean anything",
            s.ingest_to_window(),
            args.min_ingest_to_window
        ));
    }

    // 2. Steady state: retention is actually holding the window.
    let lo = s.window;
    let hi = s.window + s.rate;
    if s.final_live_readings < lo || s.final_live_readings >= hi {
        failures.push(format!(
            "the live :Reading count ({}) is outside the steady-state band [{lo}, {hi}) — retention \
             is not holding the window",
            s.final_live_readings
        ));
    }

    // 3. THE STORAGE INVARIANTS — the store plateau, the anti-rot gate, the write-amplification and
    //    total-footprint ceilings, and "did WAL disk actually come back?".
    //
    //    They live in the LIBRARY (`WireSamples::storage_gate`), not here, for one reason: a gate nobody
    //    can test is a gate nobody can trust — and this example is remediating a gate that could not
    //    fire. As a pure function of the samples, it is unit-tested against a run with a zeroed WAL,
    //    which PROVES it fails. See `wire_samples::tests`.
    //
    //    In attach mode `storage` is absent and this returns nothing: a gate must not punish a run for
    //    being unable to measure what lives on another host.
    let storage_gate = StorageGate {
        plateau_factor: args.plateau_factor,
        max_write_amplification: args.max_write_amplification,
        max_footprint_ratio: args.max_footprint_ratio,
        max_batched_write_amplification: args.max_batched_write_amplification,
        ..StorageGate::default()
    };
    failures.extend(s.storage_gate(&storage_gate));

    // 3a-i. THE INSTRUMENT'S OWN GATE (`rmp` #745) — and it is FIRST among equals, because every number
    //       below it is only as good as the instrument that produced it.
    //
    //       The WAL volume is RECONSTRUCTED (poll the WAL directory, keep the maximum length seen per
    //       segment path), and that reconstruction was UNDER-COUNTING: sampled once per tick, a segment
    //       could be created, sealed and reclaimed between two samples and never be observed at its
    //       sealed length. An under-counted WAL makes write amplification FALL — it sails under every
    //       ceiling in this file and reads like a triumph. No gate here could see it, because every gate
    //       here was downstream of it.
    //
    //       So the instrument is now checked against evidence it does not itself produce: the run's OWN
    //       on-disk WAL series forces a hard lower bound on the cumulative volume (reclamation can only
    //       shrink the on-disk figure, so every byte it GREW by was certainly written), and every WAL
    //       byte must reconcile, exactly, against a named phase.
    failures.extend(s.instrument_gate());

    // 3a-ii. THE DECISIVE CHECK: the reconstruction against the ENGINE'S OWN EXACT COUNTER (`rmp` #745).
    //
    //        Every rule above tests the reconstruction against ITSELF (its own on-disk series, its own
    //        attribution). They are sound and they are sharp, but they are all downstream of the same
    //        polling instrument, and none of them can *prove* it whole — only fail to catch it lying.
    //
    //        `graphus_db_wal_bytes_written_total` is not a reconstruction. It is `LogSink::durable_len`:
    //        a monotone absolute byte offset that reclamation never rewinds, published by the engine
    //        that wrote the bytes. Its delta over the workload window IS the WAL volume, exactly. If the
    //        driver's polling reconstruction disagrees with it, the reconstruction is wrong — and THAT is
    //        the check that would have caught this defect on the day it shipped, instead of a storage
    //        audit catching it months later.
    //
    //        Absent (an older target that does not publish the series) => SKIPPED, not passed, and the
    //        report says so by name. A gate that silently vanishes is the failure this whole task exists
    //        to remove.
    let cross =
        WalCrossCheck::evaluate(exact_wal, s.storage.as_ref().map(|st| st.wal_written_bytes));
    if let Some(f) = cross.failure(&s.database, WAL_WRITTEN) {
        failures.push(f);
    }

    // 3b. THE INGEST SHAPE (`rmp` #745): both segments measured, and batching must actually pay — judged
    //     on the INGEST-ONLY amplification, where the fixed per-tick retention + checkpoint cost that
    //     both segments pay (and that batching cannot touch) cancels by construction.
    failures.extend(s.segment_gate(&storage_gate));

    // 3c. THE READ MIX (`rmp` #745): it must have run, must have been gated against the generator's own
    //     stream, and must not have found a single wrong row — nor an EMPTY result where rows provably
    //     existed, which is the exact signature of `rmp` #738. Like the storage gate, every rule is a
    //     pure function of the samples and is unit-tested to FIRE on the defect it names.
    failures.extend(s.reader_gate(&ReaderGate::default()));

    // 3d. THE PAYLOAD READ-BACK: a run that verified no payload has not verified the data at all. Every
    //     read in this example used to be a `count(…)`, so a corrupted payload passed green.
    if s.payload_samples_verified == 0 {
        failures.push(
            "NO surviving reading's payload was read back and compared against the generator's ground \
             truth. Every read would then be a count(…), and a corrupted, transposed or truncated \
             property value would pass this example GREEN"
                .to_owned(),
        );
    }

    // 4. RECLAMATION CLIMBED. Without this, a flat store proves nothing (a workload that wrote nothing
    //    is also flat).
    match maintenance {
        Some(m) => {
            if m.reclaimed == 0 {
                failures.push(format!(
                    "{RECLAIMED} did not move over the workload window — the store may be flat simply \
                     because nothing was reclaimed AND nothing grew; the plateau is only a reclamation \
                     proof if the engine demonstrably freed versions"
                ));
            }
            if s.checkpoint_every > 0 && m.checkpoints < s.checkpoints_issued {
                failures.push(format!(
                    "{CHECKPOINTS} advanced by {} but the driver issued {} CHECKPOINT DATABASE \
                     statements — the operator trigger is not being counted",
                    m.checkpoints, s.checkpoints_issued
                ));
            }
            if m.failures > 0 {
                failures.push(format!(
                    "{MAINT_FAILURES} advanced by {} — reclamation is FAILING on the target",
                    m.failures
                ));
            }
        }
        None => failures.push(
            "no /metrics scrapes were supplied, so reclamation could not be observed — the plateau is \
             unproven without them"
                .to_owned(),
        ),
    }

    // 5. The server stayed HEALTHY through the churn. A reclamation proof produced by a server that
    //    panicked its way through the workload, or that had an engine force-detached under it, is not
    //    evidence of anything. These MUST be zero on a healthy instance.
    if let Some(sm) = server {
        if sm.statement_panics > 0 {
            failures.push(format!(
                "the server caught {} statement panic(s) during the workload",
                sm.statement_panics
            ));
        }
        if sm.engine_recovery_panics > 0 {
            failures.push(format!(
                "the server hit {} engine-recovery panic(s) during the workload",
                sm.engine_recovery_panics
            ));
        }
        if sm.engine_force_detached > 0 || sm.engine_force_detached_active > 0 {
            failures.push(format!(
                "an engine was force-detached during the workload (total={}, still active={})",
                sm.engine_force_detached, sm.engine_force_detached_active
            ));
        }
    }

    // 6. Every functional check over the wire held.
    for c in &s.checks {
        if !c.ok {
            failures.push(format!("wire check FAILED — {}: {}", c.name, c.detail));
        }
    }
}

fn add_notes(collector: &mut EvidenceCollector, s: &WireSamples, m: Option<&Maintenance>) {
    match (&s.storage, m) {
        (Some(st), Some(m)) => collector.note(format!(
            "STORAGE RECLAMATION PLATEAU (the headline — FILE-BACKED, over the wire): over {} ticks the \
             workload ingested {} readings ({:.1}× the retention window of {}) into a REAL graphus-server \
             (real FileBlockDevice + real segmented WAL) over {}. The durable data image PLATEAUED — \
             post-warmup band [{}, {}]B, ratio {:.3}, page high-water {} pages — while the server's own \
             reclamation counters CLIMBED: {} += {}, {} += {} over the same window ({} CHECKPOINT DATABASE \
             statements issued). Both halves are needed: a flat store alone would also describe a workload \
             that wrote nothing, and a climbing counter alone would not rule out unbounded growth.",
            s.ticks,
            s.total_ingested,
            s.ingest_to_window(),
            s.window,
            s.transport.label(),
            st.plateau_min_data_bytes,
            st.plateau_max_data_bytes,
            s.plateau_ratio().unwrap_or(0.0),
            st.plateau_max_data_pages,
            RECLAIMED,
            m.reclaimed,
            CHECKPOINTS,
            m.checkpoints,
            s.checkpoints_issued,
        )),
        (None, Some(m)) => collector.note(format!(
            "ATTACH (EXTERNAL) MODE — READ THE ZEROS AS 'NOT MEASURED'. The server belongs to someone \
             else: its store files and its /proc are inaccessible BY CONSTRUCTION. The `storage`, `cpu` \
             and `memory` sections of this report are therefore NOT MEASUREMENTS. The schema cannot omit \
             them (their fields are not optional), so they serialize as 0; `measurement_mode: external` at \
             the top of the report is the flag that says so, and the workload params carry explicit \
             `storage_measured=no` / `server_cpu_measured=no` / `server_rss_measured=no` markers. Do not \
             quote a 0 from those sections as a result. What IS measured here: the client-side throughput \
             and latency (this driver observed them directly), and the server-side /metrics delta — {} += \
             {}, {} += {} over the workload window, from {} CHECKPOINT DATABASE statements issued over the \
             wire. Run the example LOCALLY for the on-disk plateau curve and the real durable bytes.",
            RECLAIMED, m.reclaimed, CHECKPOINTS, m.checkpoints, s.checkpoints_issued,
        )),
        _ => collector.note(
            "No /metrics scrapes were supplied for this run, so the server-side reclamation evidence is \
             ABSENT. The plateau claim is not proven without it."
                .to_owned(),
        ),
    }

    if let Some(st) = &s.storage {
        collector.note(format!(
            "DURABLE WRITE VOLUME (real, measured): the run wrote {} WAL bytes CUMULATIVELY (the sum of \
             the maximum length of every WAL segment ever seen — segments are append-only, and a \
             checkpoint DELETES those below the reclaim floor, so the {}B of WAL still on disk at the end \
             badly understates what was written). storage.bytes_fsynced carries that cumulative figure: \
             every WAL byte is fsynced before its commit is acknowledged, so it is the honest durable-sync \
             volume, not an fsync-syscall byte counter. write_amplification = (cumulative WAL + data \
             image) / {} logical bytes ingested. The doublewrite buffer ({}B) is a FIXED per-database \
             preallocation and is deliberately NOT counted as store data — lumping it in would inflate the \
             store and flatter every ratio.{}",
            st.wal_written_bytes,
            st.wal_bytes,
            s.logical_ingested_bytes,
            st.dwb_bytes,
            st.server_io_write_bytes.map_or(String::new(), |io| format!(
                " Independent cross-check from OUTSIDE the engine: the kernel accounted {io} write_bytes \
                 to the server process over the same window (/proc/<pid>/io)."
            )),
        ));

        // ------------------------------------------------------------------------------------------
        // The finding this example exists to surface. It is reported LOUDLY and is deliberately NOT
        // gated: the claim under test is that the STORE plateaus while reclamation climbs, and it does.
        // The WAL's behaviour is a separate, real, measured server inefficiency — and an example whose
        // job is evidence must not quietly round it away.
        // ------------------------------------------------------------------------------------------
        // ------------------------------------------------------------------------------------------
        // THE HEADLINE CAVEAT, stated where a reader cannot miss it. The example's claim —
        // "reclamation holds the footprint flat" — is TRUE of the store and FALSE of the database.
        // Quoting only the store's flat plateau would be a true sentence deployed to create a false
        // impression, which is precisely the failure mode the evidence-honesty rules exist to stop.
        // ------------------------------------------------------------------------------------------
        collector.note(format!(
            "FINDING — THE STORE PLATEAUS, AND SINCE rmp #706 THE DATABASE ON DISK VERY NEARLY DOES TOO. \
             Read this next to the green `plateau_ratio: {:.3}` above, which describes the STORE ALONE.\n\
             Measured on this run: the data image held FLAT at {} B across the whole post-warmup window, \
             and the TOTAL durable footprint (store + WAL) now sawtooths within a TIGHT band [{}, {}] B — \
             a plateau ratio of {} (down from ~7.1 while #706 was open), peaking at {} per byte of graph \
             (down from ~347x). The WAL is still most of the footprint, but it is now a small, bounded, \
             sawtoothing multiple of the store rather than an unbounded climb to 64 MiB.\n\
             WHAT rmp #706 FIXED: WAL disk is reclaimed in whole SEGMENT units, and the active segment is \
             never reclaimed — so nothing below the reclaim floor can be freed until a segment SEALS. The \
             seal size is now STORE-PROPORTIONAL, clamp(store_bytes, 1 MiB, 64 MiB) \
             (graphus_wal::segment_target_for_store), applied by the store at open and on every \
             checkpoint. For a store this size that is the 1 MiB floor, so the reclaiming maintenance \
             checkpoint — whose cadence #556 already made store-proportional — has small sealed segments \
             below the floor to delete on nearly every pass. Before #706 the seal size was a fixed 64 MiB, \
             so a small database's WAL climbed all the way to 64 MiB (hundreds of times its store) before \
             one byte came back; a large log still keeps 64 MiB segments (the cap), unchanged.\n\
             WRITE AMPLIFICATION IS A SEPARATE NUMBER, AND IT HAS THREE TERMS — NOT THE TWO THIS EXAMPLE \
             USED TO CLAIM. The ~{}x cumulative-WAL / logical-bytes figure is set by (1) how many COMMITS \
             the client makes, (2) a fixed per-TICK cost that batching cannot touch — the retention DELETE \
             and the CHECKPOINT — and (3) what a commit's records actually cost. #706 changed none of \
             them: it shrinks the RETAINED footprint on disk, not how many bytes each commit writes. rmp \
             #745 measured terms (1) and (2) apart for the first time, by running the SAME steady state at \
             batch=1 and at a batched ingest and taking a WAL mark at every phase boundary INSIDE the \
             tick: {}\n\
             AND HERE IS WHAT THAT CORRECTED. This example used to publish a 3.7x batching saving and \
             blame the whole residual on the WAL record FORMAT — 'a commit's redo is dominated by the PAGE \
             IMAGES of every page it dirtied, ~22 kB, roughly three 8 KiB pages'. THAT WAS FALSE, AND IT \
             WAS NEVER MEASURED. The engine emits BYTE-RANGE PATCHES (paging::encode_patch: two bytes of \
             offset plus only the changed bytes); RecordType::FullPageImage is emitted NOWHERE in the \
             engine, and the guard in crates/graphus-cypher/tests/wal_amplification.rs now decodes the \
             durable log of this exact ingest shape and measures it: a one-reading commit writes ~19 small \
             Update deltas averaging ~197 B — against an 8 192 B page — so a WHOLE COMMIT costs less than \
             ONE image of any single one of the ~5.7 distinct pages it dirties. 'Cutting the residual \
             would be a WAL-format change to row-level redo' was doubly false: the engine already IS \
             patch-level physiological redo.\n\
             The residual was not the format. Measured on this run, the fixed per-tick RETENTION + \
             CHECKPOINT cost is {} — more than half the batched segment's entire WAL bill — and it is paid \
             regardless of batch size. It sat inside the old comparison, in both numerators, dragging the \
             saving down; a story that was never measured then filled the gap the measurement left.\n\
             WHY THE RECLAMATION COUNTERS AGREE: graphus_maintenance_versions_reclaimed_total counts MVCC \
             versions freed inside the STORE (what keeps the store flat); the on-disk WAL physically \
             shrinking is the separate, direct proof that WAL disk came back. Both climb here.\n\
             OBSERVED THIS RUN: {}\n\
             GUARDED: the file-backed regression guard in crates/graphus-cypher/tests/wal_amplification.rs \
             now drives a REAL segmented FileLogSink and FAILS on a reverted (fixed-64-MiB) segment on a \
             small store (rmp #719) — the MemLogSink guard it replaced had no segments and was \
             structurally blind to this.",
            s.plateau_ratio().unwrap_or(f64::NAN),
            st.data_bytes,
            st.footprint_min_bytes,
            st.footprint_peak_bytes,
            s.durable_footprint_plateau_ratio()
                .map_or("not measured".to_owned(), |r| format!("{r:.2}")),
            s.footprint_peak_over_store()
                .map_or("not measured".to_owned(), |r| format!("{r:.0}x")),
            s.write_amplification()
                .map_or("not measured".to_owned(), |w| format!("{w:.0}")),
            // The ingest-shape comparison, straight from THIS RUN's two measured segments. These numbers
            // were once written into the sentence by hand — so the note would have gone on asserting
            // "batching is worth 3.8x" no matter what the run actually measured, including after a
            // regression. A finding that does not move with its measurement is not evidence.
            match (
                s.control_segment()
                    .and_then(WireSegment::ingest_write_amplification),
                s.main_segment()
                    .and_then(WireSegment::ingest_write_amplification),
                s.batching_ingest_write_amp_saving(),
                s.batching_write_amp_saving(),
            ) {
                (Some(single), Some(batched), Some(saving), Some(whole)) => format!(
                    "on the INGEST PHASE ALONE — the sound experiment, with the fixed per-tick cost \
                     excluded from both sides so the two segments differ in exactly one variable — \
                     per-reading commits cost ~{single:.0}x and batched commits (~{} readings/commit) \
                     ~{batched:.0}x, so BATCHING IS WORTH ~{saving:.1}x. Over the WHOLE segment, \
                     retention and checkpoint included, the saving is only ~{whole:.1}x — and THAT is the \
                     figure this example used to publish as the batching saving, without ever measuring \
                     the fixed cost that was diluting it.",
                    s.batch
                ),
                _ => "not measured on this run — the batch=1 control segment was disabled or the storage \
                      vectors were unavailable (attach mode), so the two ingest shapes cannot be compared."
                    .to_owned(),
            },
            s.fixed_wal_per_tick().map_or("not measured".to_owned(), |f| {
                format!(
                    "{f:.0} B/tick ({}% of the batched segment's WAL)",
                    s.main_segment()
                        .and_then(WireSegment::fixed_wal_share)
                        .map_or("?".to_owned(), |x| format!("{:.0}", 100.0 * x))
                )
            }),
            match s.sealed_a_segment() {
                Some(true) => format!(
                    "the run wrote {} B of WAL, ~{}x the {} B segment seal size of its {} B store, so it \
                     certainly sealed many segments — and the on-disk WAL was seen to SHRINK {} time(s), \
                     returning {} B of disk. The WAL sawtooths in a tight band and comes back on nearly \
                     every checkpoint.",
                    st.wal_written_bytes,
                    st.wal_written_bytes / s.segment_seal_bytes().unwrap_or(1).max(1),
                    s.segment_seal_bytes().unwrap_or(0),
                    st.data_bytes,
                    st.wal_reclaim_events,
                    st.wal_reclaimed_bytes,
                ),
                Some(false) => format!(
                    "this run wrote only {} B of WAL — below the {} B segment seal size of its {} B store \
                     — so no segment can have sealed and no WAL disk could come back; a longer run crosses \
                     it and shows the full store-proportional seal-and-free sawtooth.",
                    st.wal_written_bytes,
                    s.segment_seal_bytes().unwrap_or(0),
                    st.data_bytes,
                ),
                None => "not measured".to_owned(),
            },
        ));
    }

    collector.note(format!(
        "RECLAMATION IS OPERATOR-REACHABLE AND AUTOMATIC (rmp #305 — shipped; this example's earlier \
         claim to the contrary was STALE and is corrected). Two real triggers exist in the live server: \
         (1) `CHECKPOINT DATABASE <name>`, a parsed admin statement issued over Bolt/REST like any other \
         — this run issued {} of them over the wire; and (2) a background maintenance cadence that runs \
         the same reader-safe GC + sharp checkpoint automatically once the WAL grows by \
         clamp(4 × store_bytes, 8 MiB, 256 MiB) since the last pass, with no operator action at all. \
         Set --checkpoint-every 0 to lean on the cadence alone.",
        s.checkpoints_issued,
    ));

    collector.note(format!(
        "CONCURRENCY: ingest ran over {} concurrent Bolt connections, SHARDED BY SENSOR (a connection \
         only ever writes readings from its own sensors), so no two writers contend for the same node's \
         relationship chain — the realistic 'one gateway per group of devices' shape, and conflict-free \
         by construction. Observed retries under SSI: {} (abort_rate is that figure over all attempted \
         statements — a real observation, not an assumption). The per-tick retention DELETE runs on the \
         control connection AFTER the tick's ingest has fully drained, so it never races the writers.",
        s.ingest_clients, s.retried_ops,
    ));

    // ----------------------------------------------------------------------------------------------
    // THE INGEST SHAPE (`rmp` #745) — the durability finding, stated as a comparison of two MEASUREMENTS.
    // ----------------------------------------------------------------------------------------------
    if let (Some(main), Some(control)) = (s.main_segment(), s.control_segment()) {
        let amp = |a: Option<f64>| a.map_or("not measured".to_owned(), |x| format!("{x:.0}x"));
        collector.note(format!(
            "INGEST SHAPE — WHAT A COMMIT PER READING COSTS, AND WHAT BATCHING ACTUALLY BUYS (every \
             figure MEASURED, on the same server, the same database and the same steady state; none \
             derived from another).\n\
             \n\
             THE SOUND EXPERIMENT IS THE INGEST-ONLY ONE. Every tick pays a FIXED cost F that has nothing \
             to do with the batch size — the retention DETACH DELETE of a tick's worth of aged-out \
             readings, plus the amortised CHECKPOINT DATABASE. Written out, the whole-segment comparison \
             is (50·A₁ + F) / (2·A₂₅ + F): F sits in BOTH numerators and drags the ratio toward 1. So the \
             driver now takes a WAL mark at every PHASE BOUNDARY INSIDE the tick — before ingest, after \
             ingest, after the DELETE, after the CHECKPOINT — and the headline is made on the ingest term, \
             where F cancels by construction.\n\
             \n\
             * {} — {} readings in {} commits.\n\
               INGEST-ONLY: {} B of WAL => {} write amplification ({} B per reading).\n\
               Whole segment (retention + checkpoint included): {} B => {}.\n\
             * {} — {} readings in {} commits.\n\
               INGEST-ONLY: {} B of WAL => {} write amplification ({} B per reading).\n\
               Whole segment: {} B => {}.\n\
             * THE FIXED PER-TICK COST F: {}. Paid regardless of batch size.\n\
             \n\
             => BATCHING {} READINGS PER COMMIT IS WORTH {} ON THE INGEST ITSELF. Over the whole segment, \
             retention and checkpoint included, it is worth {} — and a deployment running THIS retention \
             cadence pays that. Both are reported, under names that say which is which.\n\
             \n\
             WHAT THIS CORRECTS. The example used to publish the whole-segment figure (~3.7x) AS the \
             batching saving, and blamed the entire residual on the WAL record format: 'a commit's redo is \
             dominated by the PAGE IMAGES of every page it dirtied (~22 kB, roughly three 8 KiB pages)'. \
             That mechanism was never measured, and it is FALSE. The engine writes BYTE-RANGE PATCHES \
             (paging::encode_patch), never page images — RecordType::FullPageImage is emitted nowhere in \
             the engine — and the decoding guard in crates/graphus-cypher/tests/wal_amplification.rs \
             measures a one-reading commit as ~19 small Update deltas averaging ~197 B against an 8 192 B \
             page: a whole commit costs LESS than one image of any single one of the ~5.7 distinct pages \
             it touches. (And the WAL file grows by EXACTLY what its records encode — 940 303 B of LSN \
             space against 940 303 B on disk: no padding, no alignment, no per-flush framing.)\n\
             \n\
             THE RESIDUAL IS NOT THE FORMAT, AND WHAT IT ACTUALLY IS HAD NEVER BEEN LOOKED FOR. More than \
             half of it is F. The rest is the PER-COMMIT CATALOG RE-IMAGE: every commit rewrites the \
             durable catalog (StoreMeta) in full, and StoreMeta::free_list carries every record id that \
             has been FREED BUT NOT YET REUSED — 8 B each, imaged in BOTH the redo and the undo, so every \
             commit pays ~16 B for every freed slot whether it touches it or not. This example IS a \
             retention workload — it deletes 50 aged-out readings every tick, forever — so its free list \
             is permanently populated. Measured on the identical single-reading commit, on the identical \
             store, before and after ONE retention purge: the catalog image goes from 2 202 B to 60 137 B \
             per commit, and the whole commit from 4 562 B to 62 493 B — a 13.7x blow-up, paid by every \
             commit until those slots are reused. It is also why batching is worth ~8x here but only 1.6x \
             on a store with no free list: the catalog image is paid ONCE PER COMMIT, so the more it \
             costs, the more a batch has to amortise.\n\
             \n\
             THAT IS A REAL, UNADDRESSED ENGINE COST: in a retention workload, write amplification scales \
             with the number of freed-but-unreused record slots, because the free list rides inside a \
             catalog image that every commit rewrites. Nothing amortises it today except batching.\n\
             \n\
             A mechanism that is asserted rather than measured will always be there to explain a number \
             nobody checked — and the page-image story was standing exactly where this finding was.",
            control.label,
            control.readings,
            control.commits,
            control.ingest_wal_bytes.unwrap_or(0),
            amp(control.ingest_write_amplification()),
            control
                .ingest_wal_per_reading()
                .map_or("?".to_owned(), |b| format!("{b:.0}")),
            control.wal_written_bytes.unwrap_or(0),
            amp(control.write_amplification()),
            main.label,
            main.readings,
            main.commits,
            main.ingest_wal_bytes.unwrap_or(0),
            amp(main.ingest_write_amplification()),
            main.ingest_wal_per_reading()
                .map_or("?".to_owned(), |b| format!("{b:.0}")),
            main.wal_written_bytes.unwrap_or(0),
            amp(main.write_amplification()),
            main.fixed_wal_per_tick().map_or("not measured".to_owned(), |f| format!(
                "{f:.0} B/tick — {} of the batched segment's ENTIRE WAL bill ({} B of retention + {} B of \
                 checkpoint over {} ticks)",
                main.fixed_wal_share()
                    .map_or("?".to_owned(), |x| format!("{:.0}%", 100.0 * x)),
                main.retention_wal_bytes.unwrap_or(0),
                main.checkpoint_wal_bytes.unwrap_or(0),
                main.ticks,
            )),
            main.batch,
            s.batching_ingest_write_amp_saving()
                .map_or("not measured".to_owned(), |x| format!("{x:.1}x FEWER PHYSICAL BYTES PER \
                     LOGICAL BYTE")),
            s.batching_write_amp_saving()
                .map_or("not measured".to_owned(), |x| format!("{x:.1}x")),
        ));
    }

    // ----------------------------------------------------------------------------------------------
    // THE READ MIX (`rmp` #745) — gated against ground truth, not counted.
    // ----------------------------------------------------------------------------------------------
    match &s.readers {
        Some(r) => collector.note(format!(
            "CONCURRENT READS, GATED AGAINST GROUND TRUTH: {} independent Bolt connections read the \
             database WHILE the writers churned it, driving {} queries ({}) across three families — a \
             windowed read on the COMPOSITE Reading(sensor, seq) index, a per-sensor aggregation, and a \
             TEMPORAL `ts IN [t0, t1)` window on the Reading.ts RANGE index (real PackStream DateTime \
             bounds). Every result was CHECKED, not counted: {} returned rows were compared field by \
             field (sensor, seq, ts, value) against the reading the seeded generator produced for that \
             `seq`, with the timestamp compared as a TEMPORAL value rather than an integer the client \
             re-derived. Observed: {} mismatch(es), {} empty-but-expected result(s), {} error(s).\n\
             SOUND UNDER CHURN: the retention window slides beneath the readers, so an exact-equality \
             gate would be flaky by construction. Instead the writers publish two frontiers — the \
             committed `seq` (AFTER each tick's ingest barrier) and an UPPER BOUND on the retention \
             cutoff (BEFORE each DELETE) — and each query is gated with `returned ⊆ generated` AND \
             `returned ⊇ provably-still-live`. When the window is clear of the retention frontier the \
             two coincide and the gate is an EXACT set equality; {} of the queries achieved that. An \
             EMPTY result where rows provably existed is failed loudly: that is the exact signature of \
             rmp #738 (an index answering with an empty set instead of declining), and no count-only \
             check can see it.",
            r.clients,
            r.total_queries(),
            r.queries_per_sec()
                .map_or("rate not measured".to_owned(), |q| format!("{q:.0} q/s")),
            r.total_rows_verified(),
            r.families.iter().map(|f| f.mismatches).sum::<u64>(),
            r.families.iter().map(|f| f.empty_but_expected).sum::<u64>(),
            r.errors,
            r.families.iter().map(|f| f.exact_gated).sum::<u64>(),
        )),
        None => collector.note(
            "NO CONCURRENT READ MIX RAN (--reader-clients 0). This report describes a WRITE-ONLY \
             workload: it says nothing about what the server reads back under churn, and a corrupted \
             payload — or an index silently returning an empty result (rmp #738) — would not have been \
             caught by it."
                .to_owned(),
        ),
    }

    collector.note(format!(
        "PAYLOAD READ-BACK: after the churn, {} SURVIVING readings were read back in full over the wire \
         and compared field by field against the value the seeded generator produced for that `seq` — \
         including `ts`, compared as a real `DATETIME`. Every read in this example used to be a \
         `count(…)`: a corrupted, transposed or truncated property value passed GREEN, and the \
         Bolt/PackStream temporal path was never exercised at all (the schema FORBADE a temporal `ts`, \
         `IS :: INTEGER`). `Reading.ts` is now a `ZONED DATETIME`, RANGE-indexed, and both the ingest \
         parameters and the window-read bounds travel the wire as real PackStream `DateTime` structs.",
        s.payload_samples_verified,
    ));
}

/// A one-line rendering of one measured ingest segment for the greppable FINDING line.
fn segment_line(seg: &WireSegment) -> String {
    format!(
        "{}: {} readings in {} commits => {} ({})",
        seg.label,
        seg.readings,
        seg.commits,
        seg.write_amplification()
            .map_or("NOT MEASURED".to_owned(), |a| format!("{a:.1}x write amp")),
        seg.wal_bytes_per_commit()
            .map_or("n/a".to_owned(), |b| format!("{b:.0} B WAL/commit")),
    )
}

fn print_summary(s: &WireSamples, m: Option<&Maintenance>) {
    // THE INGEST-SHAPE COMPARISON, on its own greppable line (`rmp` #745). This is the example's
    // headline finding, and `run.sh` prints it verbatim: the two write amplifications, both MEASURED.
    if !s.segments.is_empty() {
        eprintln!(
            "iot_wire_evidence: BATCHING {}{}",
            s.segments
                .iter()
                .map(segment_line)
                .collect::<Vec<_>>()
                .join(" | "),
            s.batching_write_amp_saving()
                .map_or(String::new(), |x| format!(
                    " | BATCHING SAVES {x:.0}x THE DURABLE WRITE VOLUME PER LOGICAL BYTE"
                )),
        );
    }
    // The concurrent read mix, gated — not counted.
    if let Some(r) = &s.readers {
        eprintln!(
            "iot_wire_evidence: READERS {} gated queries over {} client(s) ({}), {} rows verified \
             field-by-field vs ground truth, {} mismatch(es), {} empty-but-expected, {} error(s)",
            r.total_queries(),
            r.clients,
            r.queries_per_sec()
                .map_or("n/a".to_owned(), |q| format!("{q:.0} q/s")),
            r.total_rows_verified(),
            r.families.iter().map(|f| f.mismatches).sum::<u64>(),
            r.families.iter().map(|f| f.empty_but_expected).sum::<u64>(),
            r.errors,
        );
        for f in &r.families {
            eprintln!(
                "iot_wire_evidence:   family {:<22} {:>5} queries ({} exact / {} bounded), {:>6} rows, \
                 latency p50={} p99={}",
                f.name,
                f.queries,
                f.exact_gated,
                f.bounded_gated,
                f.rows_returned,
                f.latency
                    .map_or("n/a".to_owned(), |l| format!("{:.2}ms", l.p50_ms)),
                f.latency
                    .map_or("n/a".to_owned(), |l| format!("{:.2}ms", l.p99_ms)),
            );
        }
    }
    // A dedicated, greppable FINDING line, so `run.sh` can surface the durability cost verbatim rather
    // than fishing it out of a prose summary. The whole point of this example is that this number is
    // impossible to miss.
    if let Some(st) = &s.storage {
        eprintln!(
            "iot_wire_evidence: FINDING store={} B (PLATEAU ratio {:.3}) | durable_footprint peak={} B \
             min={} B ratio={} | peak_per_byte_of_graph={} | write_amplification={} | wal_written={} B \
             ({} B/commit) | wal_reclaim_events={} freeing {} B",
            st.data_bytes,
            s.plateau_ratio().unwrap_or(f64::NAN),
            st.footprint_peak_bytes,
            st.footprint_min_bytes,
            s.durable_footprint_plateau_ratio()
                .map_or("n/a".to_owned(), |r| format!("{r:.2}")),
            s.footprint_peak_over_store()
                .map_or("n/a".to_owned(), |r| format!("{r:.0}x")),
            s.write_amplification()
                .map_or("NOT MEASURED".to_owned(), |w| format!("{w:.1}x")),
            st.wal_written_bytes,
            st.wal_written_bytes
                .checked_div(s.ingest_ops.saturating_add(s.delete_ops))
                .unwrap_or(0),
            st.wal_reclaim_events,
            st.wal_reclaimed_bytes,
        );
    }
    eprint!(
        "iot_wire_evidence: {} ticks, {} ingested ({:.1}× window), steady live {}",
        s.ticks,
        s.total_ingested,
        s.ingest_to_window(),
        s.final_live_readings
    );
    if let Some(st) = &s.storage {
        eprint!(
            " | STORE plateau [{}, {}]B ratio {:.3} ({} pages) | WAL written {}B, peak {}B, residual \
             {}B, {} reclaim event(s) freeing {}B | DURABLE FOOTPRINT (store+WAL) [{}, {}]B ratio {}, \
             peak {} per byte of graph",
            st.plateau_min_data_bytes,
            st.plateau_max_data_bytes,
            s.plateau_ratio().unwrap_or(0.0),
            st.plateau_max_data_pages,
            st.wal_written_bytes,
            st.wal_peak_bytes,
            st.wal_bytes,
            st.wal_reclaim_events,
            st.wal_reclaimed_bytes,
            st.footprint_min_bytes,
            st.footprint_peak_bytes,
            s.durable_footprint_plateau_ratio()
                .map_or("n/a".to_owned(), |r| format!("{r:.1}")),
            s.footprint_peak_over_store()
                .map_or("n/a".to_owned(), |r| format!("{r:.0}x")),
        );
    }
    if let Some(m) = m {
        eprint!(
            " | reclaimed +{} frozen +{} checkpoints +{}",
            m.reclaimed, m.frozen, m.checkpoints
        );
    }
    eprintln!();
}

/// A compact `tick:store_data_bytes` series, or a note that it was not measured.
fn store_series(s: &WireSamples) -> String {
    series_of(s, |t| t.store_data_bytes)
}

/// A compact `tick:wal_bytes` series, or a note that it was not measured.
fn wal_series(s: &WireSamples) -> String {
    series_of(s, |t| t.wal_bytes)
}

fn series_of(
    s: &WireSamples,
    f: impl Fn(&graphus_iot_gen::wire_samples::WireTick) -> Option<u64>,
) -> String {
    let points: Vec<String> = s
        .ticks_series
        .iter()
        .filter_map(|t| f(t).map(|v| format!("{}:{v}", t.tick)))
        .collect();
    if points.is_empty() {
        "not measured (attach mode: the store is on another host)".to_owned()
    } else {
        points.join(" ")
    }
}

fn read_metrics(path: &str) -> Result<scrape::MetricsSnapshot, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read metrics {path}: {e}"))?;
    Ok(scrape::parse(&text))
}

/// The before → after delta of a Prometheus counter (clamped at 0: counters only increase, and a
/// restarted server would otherwise produce a nonsense negative).
fn counter_delta(
    before: &scrape::MetricsSnapshot,
    after: &scrape::MetricsSnapshot,
    name: &str,
) -> u64 {
    let b = before.scalar(name).unwrap_or(0.0);
    let a = after.scalar(name).unwrap_or(0.0);
    (a - b).max(0.0) as u64
}

/// The before → after delta of a **per-database** Prometheus counter (`name{database="db"}`).
///
/// `None` when the series is absent on EITHER side — which means the target does not publish it (an
/// older server), NOT that it wrote zero bytes. That distinction is the whole evidence-honesty rule:
/// absent is not zero, and a gate must skip what it cannot see rather than assert against a fabricated
/// `0` (which here would read as "the engine wrote no WAL at all" and fail every run against an older
/// instance).
fn labelled_counter_delta(
    before: &scrape::MetricsSnapshot,
    after: &scrape::MetricsSnapshot,
    name: &str,
    database: &str,
) -> Option<u64> {
    let b = before.db_scalar(database, name)?;
    let a = after.db_scalar(database, name)?;
    Some((a - b).max(0.0) as u64)
}

struct Args {
    samples: String,
    evidence_dir: String,
    metrics_before: Option<String>,
    metrics_after: Option<String>,
    plateau_factor: f64,
    min_ingest_to_window: f64,
    max_write_amplification: f64,
    max_batched_write_amplification: f64,
    max_footprint_ratio: f64,
    assert_invariants: bool,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut samples = String::new();
        let mut evidence_dir = String::new();
        let mut metrics_before = None;
        let mut metrics_after = None;
        let mut plateau_factor = 1.10;
        let mut min_ingest_to_window = 3.0;
        // Ceilings, not targets. Both figures are BAD today (`rmp` #706 is open), and these bounds sit
        // just above the measured values so the example FAILS if the WAL gets worse, while any genuine
        // improvement — a smaller segment target, a leaner redo record — passes freely. An upper bound
        // is the only kind of gate that can hold a known-bad number honestly: it cannot be satisfied by
        // regressing, and it does not have to be relaxed to accept a fix.
        let mut max_write_amplification = StorageGate::default().max_write_amplification;
        let mut max_batched_write_amplification =
            StorageGate::default().max_batched_write_amplification;
        let mut max_footprint_ratio = StorageGate::default().max_footprint_ratio;
        let mut assert_invariants = false;

        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
            match flag.as_str() {
                "--samples" => samples = value()?,
                "--evidence-dir" => evidence_dir = value()?,
                "--metrics-before" => metrics_before = Some(value()?),
                "--metrics-after" => metrics_after = Some(value()?),
                "--plateau-factor" => {
                    plateau_factor = value()?
                        .parse()
                        .map_err(|_| "--plateau-factor expects a float > 1.0".to_owned())?;
                }
                "--min-ingest-to-window" => {
                    min_ingest_to_window = value()?
                        .parse()
                        .map_err(|_| "--min-ingest-to-window expects a float".to_owned())?;
                }
                "--max-write-amplification" => {
                    max_write_amplification = value()?
                        .parse()
                        .map_err(|_| "--max-write-amplification expects a float".to_owned())?;
                }
                "--max-batched-write-amplification" => {
                    max_batched_write_amplification = value()?.parse().map_err(|_| {
                        "--max-batched-write-amplification expects a float".to_owned()
                    })?;
                }
                "--max-footprint-ratio" => {
                    max_footprint_ratio = value()?
                        .parse()
                        .map_err(|_| "--max-footprint-ratio expects a float".to_owned())?;
                }
                "--assert" => assert_invariants = true,
                "-h" | "--help" => {
                    eprintln!(
                        "usage: iot_wire_evidence --samples <samples.json> --evidence-dir <dir> \
                         [--metrics-before <f>] [--metrics-after <f>] [--plateau-factor 1.10] \
                         [--min-ingest-to-window 3.0] [--max-write-amplification N] \
                         [--max-batched-write-amplification N] [--max-footprint-ratio N] [--assert]"
                    );
                    std::process::exit(0);
                }
                other => return Err(format!("unknown flag {other:?}")),
            }
        }
        if samples.is_empty() {
            return Err("--samples is required".to_owned());
        }
        if evidence_dir.is_empty() {
            return Err("--evidence-dir is required".to_owned());
        }
        if plateau_factor <= 1.0 {
            return Err("--plateau-factor must be > 1.0".to_owned());
        }
        if max_write_amplification <= 0.0
            || max_footprint_ratio <= 0.0
            || max_batched_write_amplification <= 0.0
        {
            return Err("the amplification/footprint ceilings must be > 0".to_owned());
        }
        Ok(Self {
            samples,
            evidence_dir,
            metrics_before,
            metrics_after,
            plateau_factor,
            min_ingest_to_window,
            max_write_amplification,
            max_batched_write_amplification,
            max_footprint_ratio,
            assert_invariants,
        })
    }
}
