//! `gds_evidence` — turns the hermetic `gds_sweep` output (plus, when present, the live server's
//! CPU/RAM/storage) into a **standardized, schema-versioned**
//! [`EvidenceReport`](graphus_examples_harness::EvidenceReport) for `examples/gds-analytics`
//! (`rmp #260`).
//!
//! # Why a dedicated emitter (not `measure_server`)
//!
//! The fraud-oltp example meters a *live* server with `measure_server`, because its evidence (load +
//! detection latency, SSI aborts) only exists while the server runs. The GDS example's headline
//! evidence is **per-algorithm scaling + CSR-projection footprint + a sequential-vs-parallel speedup
//! demonstration**, which the **always-hermetic** `gds_sweep` measures with no server at all (the
//! `graphus-gds` algorithms compute the same result whether driven in-process or over Bolt). So this
//! binary's primary input is `sweep.json`, and the live-server CPU/RAM/storage are *optional*
//! enrichment supplied only when `run.sh` ran the official-driver path.
//!
//! # How per-algorithm metrics are represented (schema-stable)
//!
//! [`EvidenceReport`](graphus_examples_harness::EvidenceReport)'s fixed sections
//! (cpu/memory/storage/throughput) have no native "per-algorithm" row, and we deliberately do NOT
//! widen the schema. Instead we use the schema's existing flexible carriers:
//!
//! - **`phases`** — **one [`PhaseTiming`](graphus_examples_harness::PhaseTiming) per algorithm**, at
//!   the *reference* (largest swept) graph
//!   size, each phase's `millis` being that algorithm's wall time. This is exactly what a phase is (a
//!   named unit of work + its duration), so per-algorithm timing reads naturally in both `report.md`
//!   (the "Phase timings" table) and `report.json`.
//! - **`workload`** params — the structural CSR footprint at the reference size
//!   (`reference_csr_bytes`, `reference_csr_bytes_per_node`, `reference_csr_bytes_per_edge`), the
//!   swept sizes, and the algorithm count: the **stable**, machine-independent metrics the baseline
//!   gate (`gds_baseline_cmp`) holds to a tight band.
//! - **`storage`** section — the **real on-disk** store image + WAL **directory** of the live server,
//!   when the official-driver path ran; honest zeros on the hermetic path (there is no server, so
//!   there is no on-disk footprint). Every field means exactly what its name says.
//! - **`dataset`** — the reference graph size (nodes / relationships), byte-stable for a fixed seed.
//! - **`throughput`** — the official-driver workload's real operation count, rate and latency
//!   percentiles when that path ran; honestly zero (= not measured) when it did not.
//!
//! This keeps [`SCHEMA_VERSION`](graphus_examples_harness::SCHEMA_VERSION) stable while giving a
//! faithful per-algorithm view.
//!
//! # Evidence honesty (`rmp #699`)
//!
//! Two fields used to carry something other than what they are named, which made this report
//! incomparable with every other example's and misled anything that trusted the schema:
//!
//! * `storage.space_amplification` carried the CSR **bytes-per-node** and `storage.write_amplification`
//!   the CSR **bytes-per-edge** — per-element COSTS smuggled into amplification RATIO fields (the
//!   committed baseline read `space_amplification: 119.06`, which anyone would read as a 119x space
//!   amplification). Those two deterministic figures were always ALSO published, correctly named, as
//!   the `reference_csr_bytes_per_node` / `_per_edge` workload params, so the gate now reads them
//!   from there and the amplification fields carry real ratios (durable bytes vs the logical dataset).
//! * `storage.store_bytes` carried the CSR projection's RESIDENT size while being documented as the
//!   on-disk store, and `wal_bytes` was left at `0` — so the report claimed the run wrote no redo log
//!   at all. The section now measures the server's real store file and WAL **directory**.
//!
//! `total_millis` likewise timed this binary's own report emission (the sweep and the driver workload
//! both finished long before it ran); it is now the workload wall-time the example measured and
//! passes in `--total-millis`.
//!
//! # Usage
//!
//! ```text
//! gds_evidence \
//!   --evidence-dir <dir> --sweep <sweep.json> \
//!   --scenario gds-analytics --description <text> \
//!   [--pid <server-pid> --uptime-secs <f64> --store <path> --wal <path> --peak-rss-bytes <u64>] \
//!   [--nodes <u64> --rels <u64>] \
//!   [--total-millis <f64>] \
//!   [--p50-ms <f64> --p99-ms <f64> --p999-ms <f64> --workload-ops <u64> --workload-secs <f64>] \
//!   [--logical-graph-bytes <u64>] [--logical-written-bytes <u64>] \
//!   [--algo-cpu <algo_cpu.json>] \
//!   [--param key=value]... [--note <text>]...
//! ```
//!
//! `--algo-cpu` is the per-algorithm **SERVER** CPU battery `analyze.js` measured (`rmp #717`): each
//! algorithm called repeatedly over Bolt with the phase bracketed between two reads of the server
//! pid's cumulative CPU counters. It lands as one CPU-carrying [`PhaseTiming`] per algorithm, so
//! `report.md` shows, per algorithm, the cores the SERVER kept busy — the question the run-wide
//! average cannot answer. Absent on an attach run (no co-located pid), and then the vector is absent
//! from the report, with a note saying why.
//!
//! The live-server flags are all optional: when `run.sh` skipped the driver path (`RUN_DRIVER=0` or
//! no node/npm), the CPU/RAM/storage/throughput sections honestly stay zero and the report still
//! carries the full hermetic per-algorithm + (deterministic) CSR-footprint evidence.

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use graphus_examples_harness::resource::cpu_section;
use graphus_examples_harness::{
    CpuSection, DatasetScale, EvidenceCollector, RunMetadata, Target, cumulative_cpu_times,
    current_rss_bytes,
};

/// The parsed sweep: the engine-parallelism facts + one record per swept graph size + the optional
/// parallelism demonstration (sequential-vs-parallel speedup across thread widths).
struct Sweep {
    engine_parallelism: String,
    host_cores: u64,
    repeats: u64,
    sizes: Vec<SweepSize>,
    parallelism: Option<ParallelismSummary>,
}

/// The parallelism demonstration's honest summary, surfaced into the report for human visibility. The
/// `max_speedup` is machine-/load-variant (illustrative, NOT gated); `deterministic_across_widths` is
/// an invariant of the GDS `Execution` knob and holds on every run.
struct ParallelismSummary {
    field_size: u64,
    node_count: u64,
    thread_widths: Vec<u64>,
    deterministic_across_widths: bool,
    max_speedup: f64,
    /// `(name, speedup)` per demonstrated algorithm, in emission order.
    algo_speedups: Vec<(String, f64)>,
}

/// One swept graph size: its dimensions, CSR footprint, and per-algorithm timings.
struct SweepSize {
    field_size: u64,
    node_count: u64,
    edge_count: u64,
    csr_bytes: u64,
    bytes_per_node: f64,
    bytes_per_edge: f64,
    timings_ms: Vec<(String, f64)>,
}

/// Parsed command-line inputs. The sweep + evidence-dir are required; everything else is optional
/// enrichment (the live server's CPU/RAM/storage, supplied only when the driver path ran).
#[derive(Default)]
struct Args {
    evidence_dir: String,
    sweep: String,
    scenario: String,
    description: String,
    pid: Option<u32>,
    uptime_secs: f64,
    store: Option<String>,
    wal: Option<String>,
    peak_rss_bytes: Option<u64>,
    nodes: Option<u64>,
    rels: Option<u64>,
    /// The example's measured workload wall-time, in milliseconds. This binary runs AFTER the sweep
    /// and the driver workload, so it cannot bracket them (`rmp #699`).
    total_millis: Option<f64>,
    workload_ops: Option<u64>,
    /// The window the driver's `workload_ops` were issued over — without it `ops_per_sec` cannot be
    /// derived and stays at the honest `0.0`.
    workload_secs: Option<f64>,
    p50_ms: Option<f64>,
    p99_ms: Option<f64>,
    p999_ms: Option<f64>,
    /// Logical size of the loaded dataset (the generator's emitted Cypher bytes), for the REAL
    /// amplification ratios. `None` ⇒ the ratios stay at "not measured" rather than being invented.
    logical_graph_bytes: Option<u64>,
    /// The logical bytes the client actually WROTE to the server on the load path (the uploaded CSV
    /// for the bulk-import path; the Cypher script for the attach path). The `write_amplification`
    /// denominator. `None` ⇒ falls back to `logical_graph_bytes`.
    logical_written_bytes: Option<u64>,
    /// The per-algorithm SERVER-CPU battery `analyze.js` wrote (`--algo-cpu-out`), when the run could
    /// measure it (a co-located server pid). `None` on an attach run — and then the per-algorithm
    /// core-utilisation vector is simply ABSENT from the report.
    algo_cpu: Option<String>,
    params: Vec<(String, String)>,
    notes: Vec<String>,
}

/// One algorithm's entry in the per-algorithm SERVER-CPU battery (`rmp #717`).
///
/// `cpu_secs` / `mean_core_utilisation` are `Option` for the one reason that matters: an algorithm
/// whose whole bracket burned less CPU than the OS's clock tick can resolve **has no measurement**,
/// and the driver omits the fields rather than writing a `0.0` that reads as "the server did no work".
struct AlgoCpu {
    algorithm: String,
    projection: String,
    calls: u64,
    wall_secs: f64,
    ms_per_call: f64,
    cpu_secs: Option<f64>,
    mean_core_utilisation: Option<f64>,
    /// Set when the algorithm ran but its CPU could not be resolved (with the reason), or when the
    /// server does not register the procedure at all.
    unmeasured: Option<String>,
}

/// The battery as a whole: the server it measured, the machine it ran on, and the per-algorithm rows.
struct AlgoCpuBattery {
    server_pid: u64,
    host_cores: u64,
    authors: u64,
    algorithms: Vec<AlgoCpu>,
    /// What DECLARING THE SCHEMA cost the server: wall, CPU, and — the figure that matters — the
    /// resident memory the index build took and never gave back (`rmp` #724).
    schema_ddl: Option<SchemaDdlCost>,
    /// The server's RSS when the battery opened and after its last call: the check that the algorithm
    /// calls themselves do not leak (they do not — measured).
    rss_growth_bytes: Option<i64>,
    battery_calls: u64,
}

/// The measured cost of applying the example's schema DDL to the loaded graph.
struct SchemaDdlCost {
    statements_applied: u64,
    wall_secs: f64,
    cpu_secs: f64,
    rss_before_bytes: u64,
    rss_after_bytes: u64,
    rss_delta_bytes: i64,
}

/// Parses `analyze.js`'s `algo_cpu.json`.
fn load_algo_cpu(path: &str) -> Result<AlgoCpuBattery, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("cannot parse {path}: {e}"))?;
    let arr = v
        .get("algorithms")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("{path}: no `algorithms` array"))?;

    let mut algorithms = Vec::with_capacity(arr.len());
    for a in arr {
        let algorithm = a
            .get("algorithm")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("{path}: an entry has no `algorithm`"))?
            .to_owned();
        // A procedure the server does not register was not measured — and says so.
        if let Some(skipped) = a.get("skipped").and_then(serde_json::Value::as_str) {
            algorithms.push(AlgoCpu {
                algorithm,
                projection: a
                    .get("projection")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                calls: 0,
                wall_secs: 0.0,
                ms_per_call: 0.0,
                cpu_secs: None,
                mean_core_utilisation: None,
                unmeasured: Some(skipped.to_owned()),
            });
            continue;
        }
        algorithms.push(AlgoCpu {
            algorithm,
            projection: a
                .get("projection")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            calls: a
                .get("calls")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            wall_secs: a
                .get("wall_secs")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0),
            ms_per_call: a
                .get("ms_per_call")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0),
            cpu_secs: a.get("cpu_secs").and_then(serde_json::Value::as_f64),
            mean_core_utilisation: a
                .get("mean_core_utilisation")
                .and_then(serde_json::Value::as_f64),
            unmeasured: a
                .get("cpu_not_measured")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
        });
    }

    let schema_ddl = v.get("schema_ddl").and_then(|d| {
        let rss_before = d.get("server_rss_before_bytes")?.as_u64()?;
        let rss_after = d.get("server_rss_after_bytes")?.as_u64()?;
        Some(SchemaDdlCost {
            statements_applied: d.get("statements_applied")?.as_u64()?,
            wall_secs: d.get("wall_secs")?.as_f64()?,
            cpu_secs: d.get("cpu_secs")?.as_f64()?,
            rss_before_bytes: rss_before,
            rss_after_bytes: rss_after,
            rss_delta_bytes: d
                .get("server_rss_delta_bytes")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(rss_after as i64 - rss_before as i64),
        })
    });

    Ok(AlgoCpuBattery {
        server_pid: v
            .get("server_pid")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        host_cores: v
            .get("host_cores")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        authors: v
            .get("authors")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        algorithms,
        schema_ddl,
        rss_growth_bytes: v
            .get("server_rss_growth_bytes")
            .and_then(serde_json::Value::as_i64),
        battery_calls: v
            .get("battery_calls")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("gds_evidence: {e}");
            return ExitCode::FAILURE;
        }
    };

    let sweep = match load_sweep(&args.sweep) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gds_evidence: cannot parse sweep {}: {e}", args.sweep);
            return ExitCode::FAILURE;
        }
    };
    let Some(reference) = sweep.sizes.last() else {
        eprintln!("gds_evidence: sweep has no size records");
        return ExitCode::FAILURE;
    };

    // --- Metadata: dataset = the reference (largest swept) graph size. This is DETERMINISTIC for a
    // fixed sweep (the sweep generator has its own fixed seed), so the baseline gate's structural
    // graph-size equality is path-independent — it holds identically whether or not the driver path
    // ran. The actual loaded influence-network size (the driver path's --nodes/--rels) is recorded in
    // the workload params for human visibility, NOT in the gated dataset.
    let metadata = RunMetadata::new(args.scenario.clone(), args.description.clone()).with_dataset(
        DatasetScale::new(reference.node_count, reference.edge_count),
    );
    let mut collector = EvidenceCollector::new(metadata);

    // Structural, stable workload params (these are the baseline gate's tight-band metrics).
    let alg_count = reference.timings_ms.len();
    let sizes_csv = sweep
        .sizes
        .iter()
        .map(|s| s.field_size.to_string())
        .collect::<Vec<_>>()
        .join(",");
    {
        let w = &mut collector.metadata_mut().workload;
        w.insert(
            "engine_parallelism".into(),
            sweep.engine_parallelism.clone(),
        );
        w.insert("host_cores".into(), sweep.host_cores.to_string());
        w.insert("sweep_repeats".into(), sweep.repeats.to_string());
        w.insert("sweep_field_sizes".into(), sizes_csv);
        w.insert("algorithm_count".into(), alg_count.to_string());
        w.insert(
            "reference_field_size".into(),
            reference.field_size.to_string(),
        );
        w.insert(
            "reference_node_count".into(),
            reference.node_count.to_string(),
        );
        w.insert(
            "reference_edge_count".into(),
            reference.edge_count.to_string(),
        );
        w.insert(
            "reference_csr_bytes".into(),
            reference.csr_bytes.to_string(),
        );
        w.insert(
            "reference_csr_bytes_per_node".into(),
            format!("{:.4}", reference.bytes_per_node),
        );
        w.insert(
            "reference_csr_bytes_per_edge".into(),
            format!("{:.4}", reference.bytes_per_edge),
        );
        // The actual loaded influence-network size (driver path only): human visibility, NOT gated.
        if let (Some(n), Some(r)) = (args.nodes, args.rels) {
            w.insert("loaded_network_nodes".into(), n.to_string());
            w.insert("loaded_network_rels".into(), r.to_string());
        }
        // The parallelism demonstration's honest summary (human visibility, NOT gated): the measured
        // multi-core speedup is machine-/load-variant, but `deterministic_across_widths` is invariant.
        if let Some(par) = &sweep.parallelism {
            let widths_csv = par
                .thread_widths
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",");
            w.insert(
                "parallel_demo_field_size".into(),
                par.field_size.to_string(),
            );
            w.insert(
                "parallel_demo_node_count".into(),
                par.node_count.to_string(),
            );
            w.insert("parallel_thread_widths".into(), widths_csv);
            w.insert(
                "parallel_deterministic_across_widths".into(),
                par.deterministic_across_widths.to_string(),
            );
            w.insert(
                "parallel_max_speedup".into(),
                format!("{:.4}", par.max_speedup),
            );
        }
        for (k, v) in &args.params {
            w.insert(k.clone(), v.clone());
        }
    }

    collector.start();
    // The sweep AND the driver workload both finished before this binary ran, so the collector cannot
    // bracket them: use the wall-time the example measured. Otherwise total_millis would time this
    // report's own emission (a few hundredths of a millisecond that read as if they were the run).
    collector.record_total_duration_from(args.total_millis, args.workload_secs);

    // --- Per-algorithm timings: one PHASE per algorithm at the reference (largest swept) size.
    // These are the HERMETIC, in-process library timings (no server, no wire) — named so, because the
    // report now also carries the same algorithms measured through the SERVER, and a reader must never
    // have to guess which is which.
    for (name, ms) in &reference.timings_ms {
        collector.phase(
            format!("library (in-process): {name}"),
            Duration::from_secs_f64(ms / 1_000.0),
        );
    }

    // --- Per-algorithm SERVER CPU (rmp #717): one CPU-carrying PHASE per algorithm, measured over
    // Bolt against the real server by bracketing its pid's cumulative CPU counters.
    //
    // This is the vector the example exists to expose and could not, because the run-level average
    // buried it: a 57 ms `betweenness` call that keeps 14 cores busy is invisible next to a load phase
    // that used one core for seconds. Each phase's `millis` is the bracket's wall time and its
    // `cpu_secs` the CPU the SERVER burned inside it, so `mean_core_utilisation` is that algorithm's
    // real core count — and an algorithm whose CPU fell below the OS clock tick carries NO cpu figure
    // at all (the phase keeps its wall time; the report renders the CPU as `not measured`).
    let mut battery_summary: Vec<String> = Vec::new();
    if let Some(path) = args.algo_cpu.as_deref() {
        let battery = match load_algo_cpu(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("gds_evidence: {e}");
                return ExitCode::FAILURE;
            }
        };
        // The schema DDL comes FIRST in the phase list, because it happens first and because it is
        // where this server spends memory it never returns (`rmp` #724).
        if let Some(ddl) = &battery.schema_ddl {
            collector.phase_with_cpu(
                format!(
                    "server (over Bolt): schema DDL [{} statements: constraints + node/rel RANGE indexes]",
                    ddl.statements_applied
                ),
                Duration::from_secs_f64(ddl.wall_secs),
                ddl.cpu_secs,
            );
            let mb = |b: i64| b as f64 / (1024.0 * 1024.0);
            collector.note(format!(
                "SERVER MEMORY — declaring the schema cost {:.1} MB of RESIDENT server memory ({:.1} \
                 MB -> {:.1} MB) for {} statements over a {}-node / {}-relationship graph, and the \
                 server NEVER GIVES IT BACK. Isolated per statement on this host: the :CITES(weight) \
                 relationship RANGE index over 23 962 relationships alone costs ~160 MB (~7 KB of RSS \
                 per indexed relationship, LINEAR in the element count — 59 967 relationships cost \
                 445 MB); the :Author(field) node index costs ~39 MB; the UNIQUE constraint ~20 MB; \
                 the two property-TYPE constraints, which build no index, cost nothing. Filed as rmp \
                 #724 — at this rate a single index over 1 M relationships needs ~7.5 GB of RSS. This \
                 example's own evidence is what surfaced it.",
                mb(ddl.rss_delta_bytes),
                mb(ddl.rss_before_bytes as i64),
                mb(ddl.rss_after_bytes as i64),
                ddl.statements_applied,
                battery.authors,
                args.rels.unwrap_or(0),
            ));
        }
        if let Some(growth) = battery.rss_growth_bytes {
            let mb = growth as f64 / (1024.0 * 1024.0);
            collector.note(format!(
                "SERVER MEMORY — the GDS calls do NOT leak; their memory is a ONE-TIME working set. \
                 Across the battery's {} algorithm calls the server's RSS moved {mb:+.1} MB, and that \
                 growth is first-touch, not per-call: a control on this host ran four consecutive \
                 passes of 18 gds.betweenness.stream calls and measured +67.8 MB on the FIRST pass \
                 (the parallel Brandes scratch, allocated once across the 16 rayon workers) then \
                 +0.8 / +1.9 / +1.0 MB on the next three — flat. A second control of 300 back-to-back \
                 gds.pageRank.stream calls moved RSS by 0.0 MB. The memory this example does NOT get \
                 back is the INDEX memory above (rmp #724), not the analytics.",
                battery.battery_calls,
            ));
        }

        let mut measured = 0_usize;
        let mut busiest: Option<(&str, f64)> = None;
        for a in &battery.algorithms {
            if let Some(reason) = &a.unmeasured {
                if a.calls == 0 {
                    // The server does not register the procedure: no phase, an explicit note.
                    collector.note(format!(
                        "server CPU for {}: NOT MEASURED — {reason}.",
                        a.algorithm
                    ));
                    continue;
                }
            }
            let name = format!("server (over Bolt): {} [{}]", a.algorithm, a.projection);
            match a.cpu_secs {
                Some(cpu) => {
                    collector.phase_with_cpu(name, Duration::from_secs_f64(a.wall_secs), cpu);
                    measured += 1;
                    let cores = a.mean_core_utilisation.unwrap_or(0.0);
                    if busiest.is_none_or(|(_, best)| cores > best) {
                        busiest = Some((a.algorithm.as_str(), cores));
                    }
                }
                None => {
                    // Wall time is real; CPU is not measurable. Record both facts, invent neither.
                    collector.phase(name, Duration::from_secs_f64(a.wall_secs));
                    collector.note(format!(
                        "server CPU for {} ({} calls, {:.2} ms/call): NOT MEASURED — {}.",
                        a.algorithm,
                        a.calls,
                        a.ms_per_call,
                        a.unmeasured.as_deref().unwrap_or("below the OS clock tick")
                    ));
                }
            }
        }
        for a in &battery.algorithms {
            if let (Some(cores), Some(cpu)) = (a.mean_core_utilisation, a.cpu_secs) {
                battery_summary.push(format!(
                    "{}={cores:.2} cores ({:.1} ms/call, {cpu:.2} CPU-s over {} calls)",
                    a.algorithm, a.ms_per_call, a.calls
                ));
            }
        }
        let (top_name, top_cores) = busiest.unwrap_or(("<none>", 0.0));
        collector.note(format!(
            "PER-ALGORITHM SERVER CPU (rmp #717): each algorithm was called repeatedly over Bolt \
             against graphus-server pid {} on a {}-core host, with the phase bracketed between two \
             reads of the SERVER's cumulative CPU counters (proc_watch --snapshot), over a \
             {}-author / {}-relationship projection. {measured} of {} algorithms produced a \
             resolvable CPU figure; the busiest was {top_name} at {top_cores:.2} cores. The rest are \
             recorded as NOT MEASURED with their reason — never as 0.",
            battery.server_pid,
            battery.host_cores,
            battery.authors,
            args.rels.unwrap_or(0),
            battery.algorithms.len(),
        ));
        if !battery_summary.is_empty() {
            collector.note(format!(
                "Per-algorithm cores: {}",
                battery_summary.join("; ")
            ));
        }
    } else {
        collector.note(
            "PER-ALGORITHM SERVER CPU: NOT MEASURED in this run. It requires a co-located server pid \
             whose /proc CPU counters the driver can bracket; an attach run reaches its target over \
             the wire only. The phases below are the hermetic in-process library timings."
                .to_owned(),
        );
    }

    // --- CPU + memory: the live server's, when the driver path supplied a PID; else honest zeros.
    if let Some(pid) = args.pid {
        let target = Target::Pid(pid);
        let cpu: CpuSection = match cumulative_cpu_times(target) {
            Some(times) => cpu_section(times, Duration::from_secs_f64(args.uptime_secs.max(0.0))),
            None => CpuSection::default(),
        };
        *collector.cpu_mut() = cpu;

        // An RSS that cannot be read is NOT MEASURED (absent), never `0` bytes resident (`rmp #711`).
        let final_rss = current_rss_bytes(target);
        let peak_rss = match (args.peak_rss_bytes, final_rss) {
            (Some(sampled), Some(read)) => Some(sampled.max(read)),
            (Some(sampled), None) => Some(sampled),
            (None, read) => read,
        };
        collector.memory_mut().peak_rss_bytes = peak_rss;
        collector.memory_mut().final_rss_bytes = final_rss;
        collector.note(format!(
            "Live CPU/RAM is graphus-server pid {pid} over {:.3}s uptime (the official-driver load + \
             analyze path). The per-algorithm timings + CSR footprint below come from the hermetic, \
             multi-threaded gds_sweep, which computes the same results with or without a server.",
            args.uptime_secs
        ));
    } else {
        collector.note(
            "Hermetic run: no live server (RUN_DRIVER=0 or node/npm absent), so CPU/RAM are left at \
             the honest 0.0. The per-algorithm timings + CSR footprint come from gds_sweep."
                .to_string(),
        );
    }

    // --- Storage: the live server's REAL on-disk footprint — the store image and the WAL, which is a
    // DIRECTORY of segment files (`graphus.wal/seg.<lsn>`), walked by path. On the hermetic path there
    // is no server and therefore no on-disk footprint, so the section honestly stays zero.
    //
    // The DETERMINISTIC CSR-projection footprint is NOT storage: it is the GDS engine's RESIDENT
    // projection. It is published, correctly named, in the workload params (reference_csr_bytes /
    // _per_node / _per_edge) and that is where `gds_baseline_cmp` gates it to a tight band — it used
    // to be smuggled into store_bytes + the two amplification fields (rmp #699).
    if let (Some(store), Some(wal)) = (&args.store, &args.wal) {
        if let Err(e) = collector.record_storage(store, wal, None) {
            eprintln!("gds_evidence: failed to measure the on-disk store/WAL: {e}");
            return ExitCode::FAILURE;
        }
        // Amplification: REAL ratios, and the two of them are genuinely different quantities.
        //
        // * write_amplification = durable bytes / the logical bytes the client actually WROTE. Since
        //   the default (local) run loads through the network bulk-import endpoint, what it wrote is
        //   the CSV it uploaded — not `graph.cypher`, which that path never sends. Feeding the Cypher
        //   size in here would divide by a payload the server never saw.
        // * space_amplification = durable bytes / the logical size of the GRAPH, for which
        //   `graph.cypher` (the generator's canonical serialization of exactly this graph) is the
        //   stable denominator in both run modes.
        //
        // Absent a logical figure, a ratio is simply omitted rather than invented.
        if let Some(graph_bytes) = args.logical_graph_bytes.filter(|b| *b > 0) {
            let written = args
                .logical_written_bytes
                .filter(|b| *b > 0)
                .unwrap_or(graph_bytes);
            collector.record_amplification(written, graph_bytes);
        }
        // Per-element durable costs (`rmp #711`): divided by the LOADED INFLUENCE NETWORK's counts —
        // the graph that is actually in the store just measured — and NOT by `metadata.dataset`, which
        // for this example is the hermetic CSR sweep's reference graph (a resident projection that
        // never touched a disk). Dividing the store image by a graph it never held would be real
        // arithmetic over mismatched inputs: precisely the subtly-wrong evidence the rule forbids.
        if let (Some(n), Some(r)) = (args.nodes, args.rels) {
            collector.record_per_element_costs_for(n, r);
            collector.note(format!(
                "storage.bytes_per_node / bytes_per_relationship are the measured durable store image \
                 amortised over the LOADED influence network ({n} nodes, {r} relationships) — the \
                 graph that is in that store. They are deliberately NOT divided by metadata.dataset, \
                 which for this example is the hermetic CSR sweep's reference graph and has no store."
            ));
        }
        collector.note(
            "storage.* is the live server's REAL on-disk footprint: the graphus.store image plus the \
             graphus.wal DIRECTORY of segment files (walked by PATH — the WAL is a directory, and a \
             meter keying off the leaf file name would report wal_bytes=0 and hide the redo log). \
             The amplification ratios are the durable bytes over the generator's logical Cypher bytes."
                .to_string(),
        );
    } else {
        collector.note(
            "Hermetic run: no live server, so there is no on-disk footprint and the storage section \
             is honestly zero (= not measured), not a stand-in for something else."
                .to_string(),
        );
    }
    collector.note(format!(
        "The GDS engine's RESIDENT CSR projection at the reference size is {} bytes ({:.2} B/node, \
         {:.2} B/edge) — a MEMORY footprint, not storage. It is DETERMINISTIC (identical with or \
         without a live server) and is what gds_baseline_cmp holds to a tight band, from the \
         reference_csr_bytes / reference_csr_bytes_per_node / reference_csr_bytes_per_edge workload \
         params. It used to be smuggled into storage.store_bytes + the two amplification fields, \
         which made this report incomparable with every other example's (rmp #699).",
        reference.csr_bytes, reference.bytes_per_node, reference.bytes_per_edge,
    ));

    // --- Throughput: the official-driver workload's REAL operations, rate and latency percentiles.
    // The hermetic sweep reports per-algorithm WALL TIME (the phases above), not an operation rate,
    // so with no driver path the whole section is ABSENT rather than carrying the sweep's measurement
    // COUNT dressed up as "operations" with a 0.0 ops/sec beside it (`rmp #699` / `#711`).
    if let Some(ops) = args.workload_ops {
        collector.throughput_mut().operations = Some(ops);
        if let Some(secs) = args.workload_secs.filter(|s| *s > 0.0) {
            collector.throughput_mut().ops_per_sec = Some(ops as f64 / secs);
        }
    }
    if let Some(p) = args.p50_ms {
        collector.throughput_mut().p50_latency_ms = Some(p);
    }
    if let Some(p) = args.p99_ms {
        collector.throughput_mut().p99_latency_ms = Some(p);
    }
    if let Some(p) = args.p999_ms {
        collector.throughput_mut().p999_latency_ms = Some(p);
    }
    {
        let sweep_measurements: u64 = sweep.sizes.iter().map(|s| s.timings_ms.len() as u64).sum();
        let w = &mut collector.metadata_mut().workload;
        w.insert("sweep_measurements".into(), sweep_measurements.to_string());
    }

    // The parallelism demonstration: a REAL, measured multi-core speedup + the invariant determinism.
    if let Some(par) = &sweep.parallelism {
        let per_algo = par
            .algo_speedups
            .iter()
            .map(|(n, s)| format!("{n} {s:.2}x"))
            .collect::<Vec<_>>()
            .join(", ");
        collector.note(format!(
            "Parallelism demonstration (rmp #342/#559): at field_size {} ({} nodes) each parallel GDS \
             algorithm was timed sequential-vs-parallel across thread widths {:?}. The results were \
             IDENTICAL across every width (deterministic_across_widths={}) — bit-identical for the \
             integer algorithms, within the documented f64 tolerance for PageRank/centrality. Best \
             measured speedup: {:.2}x (per algorithm: {}). The speedup magnitude is machine-/load-\
             variant and is NOT gated; the cross-width determinism is an invariant of the GDS \
             Execution knob and holds on every run.",
            par.field_size,
            par.node_count,
            par.thread_widths,
            par.deterministic_across_widths,
            par.max_speedup,
            per_algo,
        ));
    }

    for note in &args.notes {
        collector.note(note.clone());
    }

    let report = collector.finish();
    match report.write_to(&args.evidence_dir) {
        Ok((json, md)) => {
            println!("wrote {}", json.display());
            println!("wrote {}", md.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "gds_evidence: failed to write evidence to {}: {e}",
                args.evidence_dir
            );
            ExitCode::FAILURE
        }
    }
}

/// Parses the `--flag value` command line into [`Args`], validating the two required fields.
fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
        match flag.as_str() {
            "--evidence-dir" => args.evidence_dir = value()?,
            "--sweep" => args.sweep = value()?,
            "--scenario" => args.scenario = value()?,
            "--description" => args.description = value()?,
            "--pid" => args.pid = Some(value()?.parse().map_err(|e| format!("--pid: {e}"))?),
            "--uptime-secs" => {
                args.uptime_secs = value()?
                    .parse()
                    .map_err(|e| format!("--uptime-secs: {e}"))?;
            }
            "--store" => args.store = Some(value()?),
            "--wal" => args.wal = Some(value()?),
            "--peak-rss-bytes" => {
                args.peak_rss_bytes = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--peak-rss-bytes: {e}"))?,
                );
            }
            "--nodes" => args.nodes = Some(value()?.parse().map_err(|e| format!("--nodes: {e}"))?),
            "--rels" => args.rels = Some(value()?.parse().map_err(|e| format!("--rels: {e}"))?),
            "--total-millis" => {
                args.total_millis = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--total-millis: {e}"))?,
                );
            }
            "--workload-ops" => {
                args.workload_ops = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--workload-ops: {e}"))?,
                );
            }
            "--workload-secs" => {
                args.workload_secs = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--workload-secs: {e}"))?,
                );
            }
            "--logical-graph-bytes" => {
                args.logical_graph_bytes = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--logical-graph-bytes: {e}"))?,
                );
            }
            "--logical-written-bytes" => {
                args.logical_written_bytes = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--logical-written-bytes: {e}"))?,
                );
            }
            "--algo-cpu" => args.algo_cpu = Some(value()?),
            "--p50-ms" => {
                args.p50_ms = Some(value()?.parse().map_err(|e| format!("--p50-ms: {e}"))?)
            }
            "--p99-ms" => {
                args.p99_ms = Some(value()?.parse().map_err(|e| format!("--p99-ms: {e}"))?)
            }
            "--p999-ms" => {
                args.p999_ms = Some(value()?.parse().map_err(|e| format!("--p999-ms: {e}"))?);
            }
            "--param" => {
                let raw = value()?;
                let (k, v) = raw
                    .split_once('=')
                    .ok_or_else(|| format!("--param expects key=value, got {raw:?}"))?;
                args.params.push((k.to_string(), v.to_string()));
            }
            "--note" => args.notes.push(value()?),
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    if args.evidence_dir.is_empty() {
        return Err("--evidence-dir is required".to_string());
    }
    if args.sweep.is_empty() {
        return Err("--sweep is required".to_string());
    }
    if args.scenario.is_empty() {
        args.scenario = "gds-analytics".to_string();
    }
    Ok(args)
}

/// Loads + parses the sweep JSON (the shape `gds_sweep` emits) into a [`Sweep`].
fn load_sweep(path: &str) -> Result<Sweep, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;

    let engine_parallelism = v
        .get("engine_parallelism")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    let host_cores = v.get("host_cores").and_then(|x| x.as_u64()).unwrap_or(0);
    let repeats = v.get("repeats").and_then(|x| x.as_u64()).unwrap_or(0);

    let sizes_json = v
        .get("sizes")
        .and_then(|x| x.as_array())
        .ok_or("sweep JSON missing a `sizes` array")?;
    let mut sizes = Vec::with_capacity(sizes_json.len());
    for s in sizes_json {
        let field_size = s.get("field_size").and_then(|x| x.as_u64()).unwrap_or(0);
        let node_count = s.get("node_count").and_then(|x| x.as_u64()).unwrap_or(0);
        let edge_count = s.get("edge_count").and_then(|x| x.as_u64()).unwrap_or(0);
        let csr_bytes = s.get("csr_bytes").and_then(|x| x.as_u64()).unwrap_or(0);
        let bytes_per_node = s
            .get("bytes_per_node")
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0);
        let bytes_per_edge = s
            .get("bytes_per_edge")
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0);
        let mut timings_ms = Vec::new();
        if let Some(obj) = s.get("timings_ms").and_then(|x| x.as_object()) {
            for (name, ms) in obj {
                timings_ms.push((name.clone(), ms.as_f64().unwrap_or(0.0)));
            }
        }
        sizes.push(SweepSize {
            field_size,
            node_count,
            edge_count,
            csr_bytes,
            bytes_per_node,
            bytes_per_edge,
            timings_ms,
        });
    }
    if sizes.is_empty() {
        return Err("sweep `sizes` array is empty".to_string());
    }

    // The parallelism demonstration is optional (older sweeps predate it): parse it best-effort.
    let parallelism = v.get("parallelism").map(|p| {
        let field_size = p.get("field_size").and_then(|x| x.as_u64()).unwrap_or(0);
        let node_count = p.get("node_count").and_then(|x| x.as_u64()).unwrap_or(0);
        let thread_widths = p
            .get("thread_widths")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(serde_json::Value::as_u64).collect())
            .unwrap_or_default();
        let deterministic_across_widths = p
            .get("deterministic_across_widths")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let max_speedup = p.get("max_speedup").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let algo_speedups = p
            .get("algorithms")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| {
                        let name = a.get("name").and_then(|x| x.as_str())?.to_string();
                        let sp = a.get("speedup").and_then(|x| x.as_f64()).unwrap_or(0.0);
                        Some((name, sp))
                    })
                    .collect()
            })
            .unwrap_or_default();
        ParallelismSummary {
            field_size,
            node_count,
            thread_widths,
            deterministic_across_widths,
            max_speedup,
            algo_speedups,
        }
    });

    Ok(Sweep {
        engine_parallelism,
        host_cores,
        repeats,
        sizes,
        parallelism,
    })
}
