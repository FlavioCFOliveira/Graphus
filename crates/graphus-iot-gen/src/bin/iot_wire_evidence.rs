//! `iot_wire_evidence` — folds one **file-backed over-the-wire** churn run into a standardized,
//! schema-versioned [`EvidenceReport`], and GATES it on the headline invariants (`rmp` #694).
//!
//! It is hermetic: serde + the shared evidence harness, no engine, no Bolt, no network. It reads what
//! `iot_wire` measured (`samples.json`) together with the target's Prometheus `/metrics` scraped
//! **before** and **after** the workload window, and produces `report.json` + `report.md`.
//!
//! # The invariant it gates (`--assert`)
//!
//! > **The on-disk store PLATEAUS while `graphus_maintenance_versions_reclaimed_total` CLIMBS.**
//!
//! Both halves are load-bearing, and neither is sufficient alone:
//!
//! * A flat store on its own proves nothing — a workload that wrote nothing also has a flat store.
//! * A climbing reclamation counter on its own proves nothing — an engine could be reclaiming while the
//!   footprint still grows without bound.
//!
//! Together they are the claim: under a *sustained* delete-old/insert-new churn that ingests many times
//! the retention window, the engine physically reclaims the tombstoned versions and **new inserts reuse
//! the freed space**, so the durable footprint stops growing.
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
//!                   [--plateau-factor 1.10] [--min-ingest-to-window 3.0] [--assert]
//! ```

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use graphus_examples_harness::{
    DatasetScale, EvidenceCollector, MeasurementMode, RunMetadata, ServerMetricsSection, scrape,
};
use graphus_iot_gen::wire_samples::WireSamples;

/// Prometheus series the reclamation proof reads directly (the harness's `ServerMetricsSection` covers
/// the transaction/reliability families, but not the maintenance family, so they are read here).
const CHECKPOINTS: &str = "graphus_maintenance_checkpoints_total";
const RECLAIMED: &str = "graphus_maintenance_versions_reclaimed_total";
const FROZEN: &str = "graphus_maintenance_stamps_frozen_total";
const MAINT_FAILURES: &str = "graphus_maintenance_failures_total";

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
            "checkpoints_issued".into(),
            s.checkpoints_issued.to_string(),
        );
        w.insert("total_ingested".into(), s.total_ingested.to_string());
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
                        "NO — the WAL sawtooths (64 MiB segment-roll reclaim granularity); see notes"
                            .to_owned()
                    }
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
        // Explicit, machine-readable NOT-MEASURED markers (`rmp` #699). The `storage`/`cpu`/`memory`
        // sections have non-optional fields, so in attach mode they serialize as 0 — and a 0 that reads
        // like a measurement is exactly the failure mode this example was audited for. These markers, plus
        // `measurement_mode: external`, say out loud which sections carry nothing.
        w.insert(
            "storage_measured".into(),
            if s.storage.is_some() {
                "yes".into()
            } else {
                "no — attach mode: the store files belong to the target; the storage section is 0 = NOT MEASURED".to_owned()
            },
        );
        w.insert(
            "server_cpu_measured".into(),
            if s.server_cpu_secs.is_some() {
                "yes".into()
            } else {
                "no — attach mode: /proc/<server-pid> is not readable; the cpu section is 0 = NOT MEASURED".to_owned()
            },
        );
        w.insert(
            "server_rss_measured".into(),
            if s.server_peak_rss_bytes.is_some() {
                "yes".into()
            } else {
                "no — attach mode: /proc/<server-pid> is not readable; the memory section is 0 = NOT MEASURED".to_owned()
            },
        );
        // The store + WAL time series, so the growth-then-plateau curve is inspectable.
        w.insert("store_series".into(), store_series(&s));
        w.insert("wal_series".into(), wal_series(&s));
        if let Some(m) = &maintenance {
            w.insert(
                "maintenance_checkpoints_delta".into(),
                m.checkpoints.to_string(),
            );
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
    {
        let ops = s
            .ingest_ops
            .saturating_add(s.delete_ops)
            .saturating_add(s.checkpoints_issued);
        let t = collector.throughput_mut();
        t.operations = (ops > 0).then_some(ops);
        if let Some(rate) = s.ingest_per_sec() {
            t.ops_per_sec = Some(rate);
        }
        // The percentiles are the INGEST family (the workload's dominant statement). The windowed
        // retention DELETE is a structurally different statement, so it gets its own workload params
        // rather than being folded into the same percentile — averaging them would misreport both.
        if let Some(l) = s.insert_latency {
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
        // Every WAL byte is fsynced before its commit is acknowledged, so the CUMULATIVE WAL volume the
        // run wrote is the honest durable-sync volume. (The residual on-disk WAL would understate it
        // badly: the checkpoints deleted most of it.) This is the harness's documented WAL-as-fsync-proxy
        // convention, applied to the cumulative figure rather than the leftovers.
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
fn gate(
    args: &Args,
    s: &WireSamples,
    maintenance: Option<&Maintenance>,
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

    // 3. THE PLATEAU (local only — the store lives on this host).
    if let Some(st) = &s.storage {
        match s.plateau_ratio() {
            Some(r) if r <= args.plateau_factor => {}
            Some(r) => failures.push(format!(
                "the on-disk store did NOT plateau: the post-warmup data image spans [{}, {}]B, a \
                 ratio of {r:.3} (> {:.2}) — reclamation is not keeping up with the churn, so the \
                 footprint is growing without bound",
                st.plateau_min_data_bytes, st.plateau_max_data_bytes, args.plateau_factor
            )),
            None => failures.push("the store plateau could not be computed".to_owned()),
        }
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
        let wal_flat = s.wal_plateaued(1.5).unwrap_or(true);
        collector.note(format!(
            "FINDING — THE ON-DISK WAL DOES NOT PLATEAU (the store does; the WAL SAWTOOTHS). Measured on \
             this run: the data image held flat at {}B while the on-disk WAL climbed to a PEAK of {}B — a \
             peak WAL/store ratio of {}, against a residual-at-exit ratio of only {} (which is why the \
             residual figure alone must never be quoted: it depends purely on where in the sawtooth the \
             run stopped). Post-warmup WAL plateau within 1.5x: {}.\n\
             ROOT CAUSE (traced, not guessed): WAL disk is reclaimed in whole SEGMENT units, and the \
             active segment is only sealed at DEFAULT_SEGMENT_TARGET_BYTES = 64 MiB \
             (graphus-wal/src/sink.rs). The background maintenance cadence, meanwhile, is adaptive — it \
             fires every clamp(4 x store_bytes, 8 MiB, 256 MiB), i.e. every 8 MiB for a store this size \
             (rmp #556). So the reclaim FLOOR advances promptly and correctly, but for the first 64 MiB of \
             WAL there is no SEALED segment below it to delete, and no disk is freed at all. Once the \
             segment finally rolls, the whole 64 MiB is released at once — hence the sawtooth. The cadence \
             was made store-proportional; the reclaim GRANULARITY was not.\n\
             IMPACT: a database holding a few hundred rows still carries up to ~64 MiB of WAL on disk, \
             indefinitely. That is not a durability defect (nothing is lost, recovery is unaffected) but \
             it is a real footprint defect, and it scales per-database — acutely so on a small target like \
             a Raspberry Pi 5 hosting several small databases.\n\
             SUGGESTED DIRECTION: make the segment target adaptive in the same spirit as the cadence, e.g. \
             clamp(k x store_bytes, 1 MiB, 64 MiB), so reclaim granularity tracks the store it protects.",
            st.data_bytes,
            st.wal_peak_bytes,
            s.wal_to_store_ratio_peak()
                .map_or("not measured".to_owned(), |r| format!("{r:.0}x")),
            s.wal_to_store_ratio()
                .map_or("not measured".to_owned(), |r| format!("{r:.0}x")),
            if wal_flat { "yes" } else { "NO" },
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
}

fn print_summary(s: &WireSamples, m: Option<&Maintenance>) {
    eprint!(
        "iot_wire_evidence: {} ticks, {} ingested ({:.1}× window), steady live {}",
        s.ticks,
        s.total_ingested,
        s.ingest_to_window(),
        s.final_live_readings
    );
    if let Some(st) = &s.storage {
        eprint!(
            " | store plateau [{}, {}]B ratio {:.3} ({} pages) | WAL written {}B, peak {}B, residual \
             {}B, peak WAL/store {}",
            st.plateau_min_data_bytes,
            st.plateau_max_data_bytes,
            s.plateau_ratio().unwrap_or(0.0),
            st.plateau_max_data_pages,
            st.wal_written_bytes,
            st.wal_peak_bytes,
            st.wal_bytes,
            s.wal_to_store_ratio_peak()
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

struct Args {
    samples: String,
    evidence_dir: String,
    metrics_before: Option<String>,
    metrics_after: Option<String>,
    plateau_factor: f64,
    min_ingest_to_window: f64,
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
                "--assert" => assert_invariants = true,
                "-h" | "--help" => {
                    eprintln!(
                        "usage: iot_wire_evidence --samples <samples.json> --evidence-dir <dir> \
                         [--metrics-before <f>] [--metrics-after <f>] [--plateau-factor 1.10] \
                         [--min-ingest-to-window 3.0] [--assert]"
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
        Ok(Self {
            samples,
            evidence_dir,
            metrics_before,
            metrics_after,
            plateau_factor,
            min_ingest_to_window,
            assert_invariants,
        })
    }
}
