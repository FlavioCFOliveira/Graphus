//! `gds_evidence` — turns the hermetic `gds_sweep` output (plus, when present, the live server's
//! CPU/RAM/storage) into a **standardized, schema-versioned** [`EvidenceReport`] for
//! `examples/gds-analytics` (`rmp #260`).
//!
//! # Why a dedicated emitter (not `measure_server`)
//!
//! The fraud-oltp example meters a *live* server with `measure_server`, because its evidence (load +
//! detection latency, SSI aborts) only exists while the server runs. The GDS example's headline
//! evidence is **per-algorithm scaling + CSR-projection footprint**, which the **always-hermetic**
//! `gds_sweep` measures with no server at all (`graphus-gds` is single-threaded and runs the same
//! whether driven in-process or over Bolt). So this binary's primary input is `sweep.json`, and the
//! live-server CPU/RAM/storage are *optional* enrichment supplied only when `run.sh` ran the
//! official-driver path.
//!
//! # How per-algorithm metrics are represented (schema-stable)
//!
//! [`EvidenceReport`]'s fixed sections (cpu/memory/storage/throughput) have no native "per-algorithm"
//! row, and we deliberately do NOT widen the schema. Instead we use the schema's existing flexible
//! carriers:
//!
//! - **`phases`** — **one [`PhaseTiming`] per algorithm**, at the *reference* (largest swept) graph
//!   size, each phase's `millis` being that algorithm's wall time. This is exactly what a phase is (a
//!   named unit of work + its duration), so per-algorithm timing reads naturally in both `report.md`
//!   (the "Phase timings" table) and `report.json`.
//! - **`workload`** params — the structural CSR footprint at the reference size (`csr_bytes`,
//!   `bytes_per_node`, `bytes_per_edge`), the swept sizes, and the algorithm count: the **stable**
//!   metrics the baseline gate holds to a tight band.
//! - **`storage`** section — populated EXCLUSIVELY from the reference CSR footprint:
//!   `store_bytes` = `csr_bytes`, `space_amplification` = `bytes_per_node`, `write_amplification` =
//!   `bytes_per_edge`. The projection IS the GDS engine's resident "storage", and this footprint is
//!   DETERMINISTIC (identical with or without a live server), so the harness's `compare_to_baseline`
//!   gates it with its existing storage thresholds. The live server's PATH-dependent on-disk
//!   store/WAL footprint is recorded in the workload params (`server_store_bytes` / `server_wal_bytes`)
//!   for human visibility, NOT in the gated storage section.
//! - **`dataset`** — the reference graph size (nodes / relationships), byte-stable for a fixed seed.
//! - **`throughput.operations`** — the per-size × per-algorithm measurement count (how much work the
//!   sweep did), with `ops_per_sec` left at the honest `0.0` (the sweep reports per-algorithm time,
//!   not an aggregate ops/sec).
//!
//! This keeps [`SCHEMA_VERSION`] stable while giving a faithful per-algorithm view.
//!
//! # Usage
//!
//! ```text
//! gds_evidence \
//!   --evidence-dir <dir> --sweep <sweep.json> \
//!   --scenario gds-analytics --description <text> \
//!   [--pid <server-pid> --uptime-secs <f64> --store <path> --wal <path> --peak-rss-bytes <u64>] \
//!   [--nodes <u64> --rels <u64>] \
//!   [--p50-ms <f64> --p99-ms <f64> --p999-ms <f64> --workload-ops <u64>] \
//!   [--param key=value]... [--note <text>]...
//! ```
//!
//! The live-server flags are all optional: when `run.sh` skipped the driver path (`RUN_DRIVER=0` or
//! no node/npm), the CPU/RAM sections honestly stay zero and the report still carries the full
//! hermetic per-algorithm + (deterministic) CSR-footprint evidence. `--store`/`--wal` are read only
//! to record the live server's on-disk footprint as workload params (never into the gated storage
//! section).

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use graphus_examples_harness::resource::cpu_section;
use graphus_examples_harness::{
    CpuSection, DatasetScale, EvidenceCollector, RunMetadata, Target, cumulative_cpu_times,
    current_rss_bytes,
};

/// The parsed sweep: the engine-parallelism facts + one record per swept graph size.
struct Sweep {
    engine_parallelism: String,
    host_cores: u64,
    repeats: u64,
    sizes: Vec<SweepSize>,
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
    workload_ops: Option<u64>,
    p50_ms: Option<f64>,
    p99_ms: Option<f64>,
    p999_ms: Option<f64>,
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
        for (k, v) in &args.params {
            w.insert(k.clone(), v.clone());
        }
    }

    collector.start();

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
        collector.cpu_mut().user_secs = cpu.user_secs;
        collector.cpu_mut().system_secs = cpu.system_secs;
        collector.cpu_mut().mean_core_utilisation = cpu.mean_core_utilisation;

        let final_rss = current_rss_bytes(target).unwrap_or(0);
        let peak_rss = args.peak_rss_bytes.unwrap_or(0).max(final_rss);
        collector.memory_mut().peak_rss_bytes = peak_rss;
        collector.memory_mut().final_rss_bytes = final_rss;
        collector.note(format!(
            "Live CPU/RAM is graphus-server pid {pid} over {:.3}s uptime (the official-driver load + \
             analyze path). The per-algorithm timings + CSR footprint below come from the hermetic, \
             single-threaded gds_sweep, which runs identically with or without a server.",
            args.uptime_secs
        ));
    } else {
        collector.note(
            "Hermetic run: no live server (RUN_DRIVER=0 or node/npm absent), so CPU/RAM are left at \
             the honest 0.0. The per-algorithm timings + CSR footprint come from gds_sweep."
                .to_string(),
        );
    }

    // --- Storage: the GDS example's gated "storage" is the DETERMINISTIC CSR-projection footprint,
    // NOT the live server's on-disk store/WAL (which is path-dependent: huge under the driver path,
    // zero on the hermetic path — gating it would make the baseline flaky). So the storage section is
    // populated EXCLUSIVELY from the sweep's reference CSR footprint, keeping it identical with or
    // without a server:
    //   - store_bytes           = reference CSR total bytes (CsrGraph::memory_bytes)
    //   - space_amplification   = CSR bytes-per-node
    //   - write_amplification   = CSR bytes-per-edge
    // The live server's on-disk store/WAL footprint, when the driver path measured it, is recorded in
    // the workload params for human visibility (server_store_bytes / server_wal_bytes), NOT gated.
    collector.storage_mut().store_bytes = reference.csr_bytes;
    collector.storage_mut().space_amplification = reference.bytes_per_node;
    collector.storage_mut().write_amplification = reference.bytes_per_edge;
    if let (Some(store), Some(wal)) = (&args.store, &args.wal) {
        let store_bytes = dir_or_file_bytes(store);
        let wal_bytes = dir_or_file_bytes(wal);
        let w = &mut collector.metadata_mut().workload;
        w.insert("server_store_bytes".into(), store_bytes.to_string());
        w.insert("server_wal_bytes".into(), wal_bytes.to_string());
    }
    collector.note(
        "storage.store_bytes is the reference CSR-projection footprint (CsrGraph::memory_bytes at \
         the largest swept size); storage.space_amplification = CSR bytes-per-node and \
         storage.write_amplification = CSR bytes-per-edge. These DETERMINISTIC structural metrics are \
         what the baseline gate holds to a tight band — they are identical with or without a live \
         server. CPU/RAM/wall-time and the live server's on-disk store/WAL footprint (workload \
         params server_store_bytes / server_wal_bytes) are machine-/path-variant and are NOT gated."
            .to_string(),
    );

    // --- Throughput: the sweep's total per-size × per-algorithm measurement count is the honest
    // "operations" figure; ops/sec is left at 0.0 (the sweep reports per-algorithm time, not an
    // aggregate rate). The latency percentiles come from the driver path when it ran.
    let measurements = sweep.sizes.iter().map(|s| s.timings_ms.len() as u64).sum();
    collector.throughput_mut().operations = measurements;
    if let Some(ops) = args.workload_ops {
        collector.throughput_mut().operations = ops;
    }
    if let Some(p) = args.p50_ms {
        collector.throughput_mut().p50_latency_ms = p;
    }
    if let Some(p) = args.p99_ms {
        collector.throughput_mut().p99_latency_ms = p;
    }
    if let Some(p) = args.p999_ms {
        collector.throughput_mut().p999_latency_ms = p;
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
            "--workload-ops" => {
                args.workload_ops = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--workload-ops: {e}"))?,
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

/// Total byte size of a path: the file size for a regular file, or the recursive sum of the entries
/// for a directory (the WAL is a directory; the store is a file). Missing/unreadable ⇒ `0` (honest).
fn dir_or_file_bytes(path: &str) -> u64 {
    fn walk(p: &std::path::Path) -> u64 {
        let Ok(meta) = std::fs::symlink_metadata(p) else {
            return 0;
        };
        if meta.is_file() {
            return meta.len();
        }
        if meta.is_dir() {
            let Ok(entries) = std::fs::read_dir(p) else {
                return 0;
            };
            return entries.flatten().map(|e| walk(&e.path())).sum();
        }
        0
    }
    walk(std::path::Path::new(path))
}

/// Loads + parses the sweep JSON (the shape `gds_sweep` emits) into a [`Sweep`].
fn load_sweep(path: &str) -> Result<Sweep, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;

    let engine_parallelism = v
        .get("engine_parallelism")
        .and_then(|x| x.as_str())
        .unwrap_or("single-threaded")
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
    Ok(Sweep {
        engine_parallelism,
        host_cores,
        repeats,
        sizes,
    })
}
