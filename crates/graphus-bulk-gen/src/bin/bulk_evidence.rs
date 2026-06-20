//! `bulk_evidence` — turns a real offline bulk load into a **standardized, schema-versioned**
//! [`EvidenceReport`] for `examples/bulk-etl` (`rmp #267`).
//!
//! # What it measures (and how)
//!
//! The bulk-etl example is **OFFLINE** (no server, no Bolt driver): the headline evidence is the
//! ingest **throughput** + the **storage footprint / amplification** of a one-shot bulk load. This
//! binary captures both for one profile and folds them into the shared evidence schema:
//!
//! 1. **Ingest throughput** — it spawns the **real `graphus-bulk import` binary** (the exact path the
//!    example demonstrates) as a child process, brackets it with a wall clock, and measures the
//!    import's CPU + peak RAM by **polling the child's PID** ([`Target::Pid`]) while it runs. Over the
//!    measured import window it reports:
//!    - **elements/sec** = `(nodes + relationships) / import_secs` (the
//!      [`ThroughputCounter`](graphus_examples_harness::ThroughputCounter) `operations` are the loaded
//!      element count, `ops_per_sec` the element rate),
//!    - **MB/sec** = `logical_csv_bytes / import_secs` (recorded as a workload param `ingest_mb_per_sec`,
//!      the input-CSV byte rate the loader sustained).
//! 2. **Peak RAM during load** — the high-water RSS of the import child, sampled on a tight poll loop
//!    while it runs (and a final read just before it exits), into [`MemorySection::peak_rss_bytes`].
//! 3. **CPU time** — the child's cumulative user + system CPU seconds (read from its PID just before
//!    it exits), into [`CpuSection`], with `mean_core_utilisation = cpu_secs / import_secs`.
//! 4. **End-to-end time** — the import child's wall-clock window, recorded as the import phase timing
//!    and as the run's total wall-clock.
//! 5. **Storage footprint + amplification** — read from the `storage.json` that `bulk_storage` emitted
//!    for the SAME dataset (`store_bytes`/`wal_bytes` + pages, bytes-per-node/edge, store/total space
//!    amplification, write amplification), folded into the gated [`StorageSection`].
//!
//! # What the baseline gates (and why)
//!
//! For a fixed seed + profile the dataset — and therefore its store footprint — is **byte-stable**, so
//! those are the meaningful regression signals the committed baseline holds to a tight band:
//!
//! - **`dataset.nodes` / `dataset.relationships`** — exact (integer-stable).
//! - **`storage.store_bytes` / `store_pages`**, **`bytes_per_node`** (`storage.space_amplification`),
//!   **`bytes_per_edge`** (`storage.write_amplification`) — within a 15% band.
//!
//! The throughput / CPU / peak-RAM / wall-time figures are **machine-variant** and are recorded for
//! human visibility but NOT gated (see `bulk_baseline_cmp`).
//!
//! # Schema mapping (no schema widening)
//!
//! [`EvidenceReport`]'s fixed sections carry the bulk metrics through their existing fields:
//!
//! - **`storage`** — the durable footprint: `store_bytes`/`wal_bytes` + pages, plus
//!   `space_amplification = bytes_per_node` and `write_amplification = bytes_per_edge` (the gated,
//!   deterministic per-element costs). The honest store/total CSV-relative amplifications go into the
//!   workload params for human visibility.
//! - **`throughput`** — `operations = nodes + relationships`, `ops_per_sec` = elements/sec.
//! - **`cpu` / `memory`** — the import child's CPU + peak/final RSS.
//! - **`phases`** — one phase, `import`, with the import wall time.
//! - **`workload`** — the per-table counts, the `ingest_*` rates, the CSV-relative amplifications,
//!   and the content hash (lossless round-trip evidence).
//!
//! # Usage
//!
//! ```text
//! bulk_evidence \
//!   --evidence-dir <dir> --data-dir <dir-with-csvs-and-manifest> --storage <storage.json> \
//!   [--bulk-bin <graphus-bulk>] [--scenario bulk-etl] [--description <text>] \
//!   [--content-hash <hex>] [--param key=value]... [--note <text>]... [--work-dir <dir>]
//! ```
//!
//! Hermetic: it spawns only the offline `graphus-bulk` binary, under a private temp dir removed on
//! exit. Deterministic dataset; the gated metrics are byte-stable, the rest machine-variant.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use graphus_bulk_gen::Manifest;
use graphus_examples_harness::resource::cpu_section;
use graphus_examples_harness::{
    CpuSection, DatasetScale, EvidenceCollector, RunMetadata, Target, ThroughputCounter,
    cumulative_cpu_times, current_rss_bytes,
};

/// The node CSV file names, in load order (must match `bulk_gen`).
const NODE_FILES: [&str; 4] = ["persons.csv", "forums.csv", "posts.csv", "comments.csv"];
/// The relationship CSV file names, in load order (must match `bulk_gen`).
const REL_FILES: [&str; 6] = [
    "knows.csv",
    "has_member.csv",
    "container_of.csv",
    "has_creator.csv",
    "reply_of.csv",
    "likes.csv",
];

/// The on-disk footprint + amplification figures parsed from `bulk_storage`'s `storage.json`.
#[derive(Default)]
struct StorageJson {
    store_bytes: u64,
    store_pages: u64,
    wal_bytes: u64,
    wal_pages: u64,
    bytes_per_node: f64,
    bytes_per_edge: f64,
    store_space_amplification: f64,
    space_amplification: f64,
    write_amplification: f64,
}

/// Parsed command-line inputs.
#[derive(Default)]
struct Args {
    evidence_dir: String,
    data_dir: String,
    storage: String,
    bulk_bin: Option<String>,
    work_dir: Option<String>,
    scenario: String,
    description: String,
    content_hash: Option<String>,
    params: Vec<(String, String)>,
    notes: Vec<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bulk_evidence: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

    let data_dir = PathBuf::from(&args.data_dir);
    let manifest = read_manifest(&data_dir.join("manifest.json"))?;
    let storage = read_storage_json(Path::new(&args.storage))?;
    let bulk_bin = resolve_bulk_bin(args.bulk_bin.as_deref().map(PathBuf::from))?;

    // A private workspace for the timed import (removed on exit, even on early return).
    let work = match &args.work_dir {
        Some(w) => {
            let w = PathBuf::from(w);
            std::fs::create_dir_all(&w)
                .map_err(|e| format!("creating work-dir {}: {e}", w.display()))?;
            w
        }
        None => mkdtemp("graphus-bulk-evidence")?,
    };
    let _guard = scopeguard(&work);
    let store_dir = work.join("store");

    // ----- Run the REAL import as a child, metering its CPU/RAM/time. -----
    let timed = timed_import(&bulk_bin, &store_dir, &data_dir)?;
    if timed.counts.nodes != manifest.total_nodes
        || timed.counts.relationships != manifest.total_relationships
    {
        return Err(format!(
            "import counts ({} nodes, {} rels) disagree with manifest ({} nodes, {} rels)",
            timed.counts.nodes,
            timed.counts.relationships,
            manifest.total_nodes,
            manifest.total_relationships
        ));
    }

    let import_secs = timed.wall.as_secs_f64();
    let elements = manifest.total_nodes + manifest.total_relationships;
    // Element rate over the import window (elements/sec) and the input-CSV byte rate (MB/sec).
    let mut throughput = ThroughputCounter::new();
    throughput.add(elements);
    let elements_per_sec = throughput.ops_per_sec_over(timed.wall);
    let mb = manifest.logical_csv_bytes as f64 / (1024.0 * 1024.0);
    let mb_per_sec = if import_secs > 0.0 {
        mb / import_secs
    } else {
        0.0
    };

    // ----- Assemble the standardized report. -----
    let metadata = RunMetadata::new(args.scenario.clone(), args.description.clone()).with_dataset(
        DatasetScale::new(manifest.total_nodes, manifest.total_relationships),
    );
    let mut collector = EvidenceCollector::new(metadata);

    // Structural + descriptive workload params.
    {
        let w = &mut collector.metadata_mut().workload;
        w.insert("profile".into(), manifest.profile.clone());
        w.insert(
            "total_properties".into(),
            manifest.total_properties.to_string(),
        );
        w.insert(
            "logical_csv_bytes".into(),
            manifest.logical_csv_bytes.to_string(),
        );
        w.insert("imported_elements".into(), elements.to_string());
        w.insert(
            "ingest_elements_per_sec".into(),
            format!("{elements_per_sec:.1}"),
        );
        w.insert("ingest_mb_per_sec".into(), format!("{mb_per_sec:.4}"));
        w.insert("import_wall_secs".into(), format!("{import_secs:.4}"));
        // The honest CSV-relative amplifications (NOT gated — bytes_per_node/edge are the gated ones).
        w.insert(
            "store_space_amplification".into(),
            format!("{:.4}", storage.store_space_amplification),
        );
        w.insert(
            "total_space_amplification".into(),
            format!("{:.4}", storage.space_amplification),
        );
        w.insert(
            "csv_write_amplification".into(),
            format!("{:.4}", storage.write_amplification),
        );
        if let Some(h) = &args.content_hash {
            w.insert("content_hash".into(), h.clone());
        }
        for (label, count) in &manifest.nodes_by_label {
            w.insert(format!("nodes_{label}"), count.to_string());
        }
        for (ty, count) in &manifest.relationships_by_type {
            w.insert(format!("rels_{ty}"), count.to_string());
        }
        for (k, v) in &args.params {
            w.insert(k.clone(), v.clone());
        }
    }

    collector.start();
    collector.phase("import", timed.wall);

    // CPU + memory: the import child's, measured by PID while it ran.
    let cpu: CpuSection = cpu_section(
        graphus_examples_harness::CpuTimes {
            user_secs: timed.user_secs,
            system_secs: timed.system_secs,
        },
        timed.wall,
    );
    collector.cpu_mut().user_secs = cpu.user_secs;
    collector.cpu_mut().system_secs = cpu.system_secs;
    collector.cpu_mut().mean_core_utilisation = cpu.mean_core_utilisation;
    collector.memory_mut().peak_rss_bytes = timed.peak_rss_bytes;
    collector.memory_mut().final_rss_bytes = timed.final_rss_bytes;

    // Storage: the durable footprint from storage.json. The GATED per-element costs are encoded into
    // space_amplification (bytes-per-node) and write_amplification (bytes-per-edge); the raw
    // store/WAL bytes + pages are recorded faithfully.
    {
        let s = collector.storage_mut();
        s.store_bytes = storage.store_bytes;
        s.store_pages = storage.store_pages;
        s.wal_bytes = storage.wal_bytes;
        s.wal_pages = storage.wal_pages;
        // bytes_fsynced: the retained WAL byte count is the honest fsync proxy for an offline load
        // (every committed WAL byte is fsynced before the commit is acknowledged).
        s.bytes_fsynced = storage.wal_bytes;
        s.space_amplification = storage.bytes_per_node;
        s.write_amplification = storage.bytes_per_edge;
    }

    // Throughput: elements loaded over the import window; element rate. (Latency percentiles are not
    // meaningful for a one-shot batch load and stay 0.0.)
    collector.throughput_mut().operations = throughput.count();
    collector.throughput_mut().ops_per_sec = elements_per_sec;

    collector.note(format!(
        "Ingest throughput + CPU/RAM/time are the REAL `graphus-bulk import` child process (pid \
         metered by polling its /proc or ps) over a {import_secs:.4}s offline load of {elements} \
         elements ({:.1} elements/sec, {mb_per_sec:.3} MB/sec of input CSV). These are machine-variant \
         and are NOT gated.",
        elements_per_sec
    ));
    collector.note(
        "storage.store_bytes / store_pages / wal_bytes / wal_pages are the durable graph.store image \
         + retained graph.wal redo log measured for the SAME dataset (from bulk_storage's \
         storage.json). storage.space_amplification = on-disk STORE bytes-per-node and \
         storage.write_amplification = on-disk STORE bytes-per-edge — the DETERMINISTIC per-element \
         costs the baseline gate holds to a tight band. The CSV-relative amplifications \
         (store/total/write vs logical_csv_bytes) are in the workload params for human visibility."
            .to_string(),
    );
    if let Some(h) = &args.content_hash {
        collector.note(format!(
            "Round-trip is LOSSLESS: import -> dump -> re-import preserves the id-independent content \
             hash {h} (proven by bulk_roundtrip)."
        ));
    }
    for note in &args.notes {
        collector.note(note.clone());
    }

    eprintln!(
        "bulk_evidence: profile={} {} nodes + {} rels in {:.4}s => {:.1} elements/sec, {:.3} MB/sec; \
         peak_rss={} B; cpu={:.3}s user + {:.3}s sys; store={} B ({} pages), wal={} B ({} pages)",
        manifest.profile,
        manifest.total_nodes,
        manifest.total_relationships,
        import_secs,
        elements_per_sec,
        mb_per_sec,
        timed.peak_rss_bytes,
        timed.user_secs,
        timed.system_secs,
        storage.store_bytes,
        storage.store_pages,
        storage.wal_bytes,
        storage.wal_pages,
    );

    let report = collector.finish();
    match report.write_to(&args.evidence_dir) {
        Ok((json, md)) => {
            println!("wrote {}", json.display());
            println!("wrote {}", md.display());
            Ok(())
        }
        Err(e) => Err(format!(
            "failed to write evidence to {}: {e}",
            args.evidence_dir
        )),
    }
}

/// The metered result of one timed import.
struct TimedImport {
    counts: ImportCounts,
    wall: Duration,
    user_secs: f64,
    system_secs: f64,
    peak_rss_bytes: u64,
    final_rss_bytes: u64,
}

/// Parsed counts from a `graphus-bulk import` run.
struct ImportCounts {
    nodes: u64,
    relationships: u64,
}

/// Spawns `graphus-bulk import` as a child, polling its PID for peak RSS while it runs and reading its
/// cumulative CPU just before it exits, and brackets it with a wall clock.
fn timed_import(bulk_bin: &Path, store: &Path, data_dir: &Path) -> Result<TimedImport, String> {
    let mut cmd = Command::new(bulk_bin);
    cmd.arg("import").arg("--db").arg(store);
    for f in NODE_FILES {
        cmd.arg("--nodes").arg(data_dir.join(f));
    }
    for f in REL_FILES {
        cmd.arg("--relationships").arg(data_dir.join(f));
    }
    // Capture stdout (the counts line); let stderr stream through for visibility.
    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());

    let started = Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawning {} import: {e}", bulk_bin.display()))?;
    let pid = child.id();
    let target = Target::Pid(pid);

    // Poll the child's RSS + CPU on a tight loop while it runs. The dataset is small, so a short
    // sleep keeps the poll cheap while still catching the peak; the final reads below close the gap.
    let mut peak_rss = 0u64;
    let mut last_cpu = (0.0f64, 0.0f64);
    loop {
        if let Some(rss) = current_rss_bytes(target) {
            peak_rss = peak_rss.max(rss);
        }
        if let Some(t) = cumulative_cpu_times(target) {
            last_cpu = (t.user_secs, t.system_secs);
        }
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => return Err(format!("waiting on import child: {e}")),
        }
    }
    // A final read after the loop (cheap; the PID may already be reaped, in which case we keep the
    // last in-flight sample, which is the honest high-water mark we observed).
    let final_rss = current_rss_bytes(target).unwrap_or(0);
    peak_rss = peak_rss.max(final_rss);

    let output = child
        .wait_with_output()
        .map_err(|e| format!("collecting import output: {e}"))?;
    let wall = started.elapsed();
    if !output.status.success() {
        return Err(format!("graphus-bulk import failed ({})", output.status));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let counts = parse_import_counts(&stdout)?;

    Ok(TimedImport {
        counts,
        wall,
        user_secs: last_cpu.0,
        system_secs: last_cpu.1,
        peak_rss_bytes: peak_rss,
        final_rss_bytes: final_rss,
    })
}

/// Parses the importer's `imported N nodes, M relationships, ...` stdout line.
fn parse_import_counts(stdout: &str) -> Result<ImportCounts, String> {
    let line = stdout
        .lines()
        .find(|l| l.starts_with("imported "))
        .ok_or_else(|| format!("could not find 'imported' line:\n{stdout}"))?;
    let mut nodes = None;
    let mut relationships = None;
    let toks: Vec<&str> = line.split_whitespace().collect();
    for w in toks.windows(2) {
        if let Ok(n) = w[0].trim_end_matches(',').parse::<u64>() {
            match w[1].trim_end_matches(',') {
                "nodes" => nodes = Some(n),
                "relationships" => relationships = Some(n),
                _ => {}
            }
        }
    }
    Ok(ImportCounts {
        nodes: nodes.ok_or("missing node count in import output")?,
        relationships: relationships.ok_or("missing relationship count in import output")?,
    })
}

// ---- Argument parsing + small helpers ----

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
        match flag.as_str() {
            "--evidence-dir" => args.evidence_dir = value()?,
            "--data-dir" => args.data_dir = value()?,
            "--storage" => args.storage = value()?,
            "--bulk-bin" => args.bulk_bin = Some(value()?),
            "--work-dir" => args.work_dir = Some(value()?),
            "--scenario" => args.scenario = value()?,
            "--description" => args.description = value()?,
            "--content-hash" => args.content_hash = Some(value()?),
            "--param" => {
                let raw = value()?;
                let (k, v) = raw
                    .split_once('=')
                    .ok_or_else(|| format!("--param expects key=value, got {raw:?}"))?;
                args.params.push((k.to_string(), v.to_string()));
            }
            "--note" => args.notes.push(value()?),
            "-h" | "--help" => {
                eprintln!(
                    "usage: bulk_evidence --evidence-dir <dir> --data-dir <dir> --storage \
                     <storage.json> [--bulk-bin <graphus-bulk>] [--scenario bulk-etl] \
                     [--description <text>] [--content-hash <hex>] [--param k=v]... [--note <t>]... \
                     [--work-dir <dir>]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    if args.evidence_dir.is_empty() {
        return Err("--evidence-dir is required".to_string());
    }
    if args.data_dir.is_empty() {
        return Err("--data-dir is required (where bulk_gen wrote the CSVs)".to_string());
    }
    if args.storage.is_empty() {
        return Err("--storage is required (bulk_storage's storage.json)".to_string());
    }
    if args.scenario.is_empty() {
        args.scenario = "bulk-etl".to_string();
    }
    if args.description.is_empty() {
        args.description =
            "Offline high-throughput bulk ingest + ETL: import a deterministic LDBC-SNB-like social \
             network from CSV via the real graphus-bulk binary, characterise ingest throughput + the \
             on-disk store footprint / amplification, and prove a lossless import -> dump -> re-import \
             round-trip."
                .to_string();
    }
    Ok(args)
}

fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("reading manifest {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("parsing manifest {}: {e}", path.display()))
}

fn read_storage_json(path: &Path) -> Result<StorageJson, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("reading storage json {}: {e}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("parsing storage json {}: {e}", path.display()))?;
    let u = |k: &str| v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
    let f = |k: &str| v.get(k).and_then(serde_json::Value::as_f64).unwrap_or(0.0);
    Ok(StorageJson {
        store_bytes: u("store_bytes"),
        store_pages: u("store_pages"),
        wal_bytes: u("wal_bytes"),
        wal_pages: u("wal_pages"),
        bytes_per_node: f("bytes_per_node"),
        bytes_per_edge: f("bytes_per_edge"),
        store_space_amplification: f("store_space_amplification"),
        space_amplification: f("space_amplification"),
        write_amplification: f("write_amplification"),
    })
}

fn resolve_bulk_bin(explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        if p.exists() {
            return Ok(p);
        }
        return Err(format!("--bulk-bin {} does not exist", p.display()));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("graphus-bulk");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    Ok(PathBuf::from("graphus-bulk"))
}

fn mkdtemp(prefix: &str) -> Result<PathBuf, String> {
    let base = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let pid = std::process::id();
    for attempt in 0..1000u32 {
        let dir = base.join(format!("{prefix}-{pid}-{attempt}"));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("creating temp dir {}: {e}", dir.display())),
        }
    }
    Err("could not create a unique temp dir after 1000 attempts".to_owned())
}

fn scopeguard(dir: &Path) -> impl Drop {
    struct Guard(PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    Guard(dir.to_path_buf())
}
