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
//!   [--logical-graph-bytes <u64>] \
//!   [--param key=value]... [--note <text>]...
//! ```
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
    params: Vec<(String, String)>,
    notes: Vec<String>,
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
    for (name, ms) in &reference.timings_ms {
        collector.phase(name.clone(), Duration::from_secs_f64(ms / 1_000.0));
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
        // Amplification: REAL ratios — the durable bytes the load actually produced over the logical
        // dataset the generator emitted. Absent a logical figure they are simply omitted.
        if let Some(logical) = args.logical_graph_bytes.filter(|b| *b > 0) {
            collector.record_amplification(logical, logical);
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
