//! `bulk_evidence` — turns a real offline bulk load into a **standardized, schema-versioned**
//! [`EvidenceReport`] for `examples/bulk-etl` (`rmp` #267, rescaled and extended by `rmp` #716).
//!
//! # What it measures (and how)
//!
//! ONE import, metered for everything. The driver spawns the **real `graphus-bulk import` binary**
//! (the exact path the example demonstrates) as a child process, and then measures the store **that
//! very child produced** — its footprint, and the cost of reopening it. Every figure therefore
//! describes the *same* store image, which is what makes a per-element cost honest at all (the
//! examples' evidence-honesty rule: a cost whose two inputs describe different graphs is real
//! arithmetic over mismatched inputs, and still a lie).
//!
//! 1. **Ingest throughput** — the import child bracketed by a wall clock:
//!    - **elements/sec** = `(nodes + relationships) / import_secs`,
//!    - **MB/sec** = `logical_csv_bytes / import_secs` (the input-CSV byte rate the loader sustained).
//! 2. **Peak RAM during load** — the high-water RSS of the import child, sampled on a tight poll loop.
//! 3. **CPU time** — the child's cumulative user + system CPU seconds.
//! 4. **Storage footprint + amplification** — measured directly off the store the child just wrote
//!    ([`graphus_bulk_gen::footprint`]): `store_bytes` / `wal_bytes` + pages, the per-element durable
//!    costs, the two space amplifications, and the **WAL residual** the load left behind.
//! 5. **The REOPEN cost** (`rmp` #716) — the second half of a bulk load, and the half nobody was
//!    measuring. A separate `bulk_reopen` child reopens that same store: WAL recovery
//!    (`recover_device`) + `RecordStore::open`, timed, with its own peak RSS. This is the path
//!    **`rmp` #576** measured at ~33 s and **`rmp` #579** blew up to ~25 GB of RSS, because a reopen
//!    reads the entire un-reclaimed WAL. An example that only times the import cannot see it.
//!
//! # What the baseline gates (and why)
//!
//! For a fixed seed + profile the dataset — and therefore its store footprint — is **byte-stable**, so
//! those are the meaningful regression signals the committed baseline holds to a tight band:
//! `dataset.nodes` / `dataset.relationships` (exact), and `storage.store_bytes` / `store_pages` /
//! `bytes_per_node` / `bytes_per_relationship` / the amplification ratios (15%).
//!
//! The throughput / CPU / peak-RAM / wall-time / reopen-seconds figures are **machine-variant**: they
//! are recorded for human visibility and asserted against loose invariants by `run.sh`, but not gated
//! to a tight band (see `bulk_baseline_cmp`).
//!
//! # Schema mapping — every figure in the field that MEANS it
//!
//! - **`storage`** — the durable footprint. The amplification fields carry REAL amplification ratios
//!   (durable bytes over the logical CSV); the per-element durable costs go in `bytes_per_node` /
//!   `bytes_per_relationship`, the fields named for them.
//! - **`throughput`** — `operations = nodes + relationships`, `ops_per_sec` = elements/sec. A one-shot
//!   offline import has **no per-operation request boundary**, so its latency percentiles are ABSENT
//!   rather than emitted as a `0.0` that reads as "instantaneous" (`rmp` #711). The per-batch ingest
//!   latency of this dataset IS measured — over the wire, where a request boundary exists — and lands
//!   in the example's `evidence/wire/report.json`.
//! - **`cpu` / `memory`** — the import child's CPU + peak RSS. Its `final_rss_bytes` is ABSENT: the
//!   child has exited by then, and an exited process has no resident set.
//! - **`phases`** — `import` and `reopen`, the two halves of a bulk load. `total_millis` is their sum:
//!   the whole measured workload, not the report's own emission time.
//!
//! # Usage
//!
//! ```text
//! bulk_evidence \
//!   --evidence-dir <dir> --data-dir <dir-with-csvs-and-manifest> \
//!   [--storage-out <storage.json>] [--keep-store <dir>] \
//!   [--bulk-bin <graphus-bulk>] [--reopen-bin <bulk_reopen>] [--scenario bulk-etl] \
//!   [--description <text>] [--content-hash <hex>] [--param key=value]... [--note <text>]...
//! ```
//!
//! Hermetic: it spawns only the offline `graphus-bulk` and `bulk_reopen` binaries, under a private
//! temp dir removed on exit (unless `--keep-store` hands the store to the caller, which the example
//! uses to probe the `rmp` #681 layout question without paying for a *third* import of the same data).

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use graphus_bulk_gen::Manifest;
use graphus_bulk_gen::footprint::{FootprintReport, measure_and_derive};
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

/// Parsed command-line inputs.
#[derive(Default)]
struct Args {
    evidence_dir: String,
    data_dir: String,
    storage_out: Option<String>,
    keep_store: Option<String>,
    bulk_bin: Option<String>,
    reopen_bin: Option<String>,
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
    let bulk_bin = resolve_sibling(args.bulk_bin.as_deref().map(PathBuf::from), "graphus-bulk")?;
    let reopen_bin = resolve_sibling(args.reopen_bin.as_deref().map(PathBuf::from), "bulk_reopen")?;

    // A private workspace for the timed import. Removed on exit UNLESS the caller asked to keep the
    // store (`--keep-store`), in which case the store it names is the caller's to inspect and remove.
    let work = match &args.work_dir {
        Some(w) => {
            let w = PathBuf::from(w);
            std::fs::create_dir_all(&w)
                .map_err(|e| format!("creating work-dir {}: {e}", w.display()))?;
            w
        }
        None => mkdtemp("graphus-bulk-evidence")?,
    };
    let keep = args.keep_store.is_some();
    let _guard = (!keep).then(|| scopeguard(&work));
    let store_dir = match &args.keep_store {
        Some(k) => PathBuf::from(k),
        None => work.join("store"),
    };

    // ===== 1. The REAL import, as a child, metered for CPU / RAM / wall time. =====
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

    // ===== 2. The footprint of THE STORE THAT CHILD JUST WROTE. =====
    // Measured here, over this exact image — not by a second driver that re-imports the same dataset
    // into a second store. That is what lets the per-element costs below be stated at all: the store
    // metered IS the store holding the nodes/relationships counted.
    let fp: FootprintReport = measure_and_derive(
        &store_dir,
        manifest.total_nodes,
        manifest.total_relationships,
        manifest.logical_csv_bytes,
    )?;

    // ===== 3. The REOPEN cost of that same store (rmp #716; the rmp #576/#579 path). =====
    let reopen = timed_reopen(
        &reopen_bin,
        &store_dir,
        manifest.total_nodes,
        manifest.total_relationships,
    )?;

    let import_secs = timed.wall.as_secs_f64();
    let reopen_secs = reopen.open_secs;
    let elements = manifest.total_nodes + manifest.total_relationships;
    let mut throughput = ThroughputCounter::new();
    throughput.add(elements);
    let elements_per_sec = throughput.ops_per_sec_over(timed.wall);
    let mb = manifest.logical_csv_bytes as f64 / (1024.0 * 1024.0);
    let mb_per_sec = if import_secs > 0.0 {
        mb / import_secs
    } else {
        0.0
    };
    // The headline ratio of `rmp` #716: what fraction of a fresh load's cost you pay AGAIN, every time
    // the store is opened. A value near (or above) 1.0 means the reopen is a second load.
    let reopen_over_import = if import_secs > 0.0 {
        reopen_secs / import_secs
    } else {
        0.0
    };

    // ===== 4. Assemble the standardized report. =====
    let metadata = RunMetadata::new(args.scenario.clone(), args.description.clone()).with_dataset(
        DatasetScale::new(manifest.total_nodes, manifest.total_relationships),
    );
    let mut collector = EvidenceCollector::new(metadata);

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
        // ---- The reopen vector (rmp #716). ----
        w.insert("reopen_wall_secs".into(), format!("{reopen_secs:.4}"));
        w.insert(
            "reopen_scan_secs".into(),
            format!("{:.4}", reopen.scan_secs),
        );
        w.insert(
            "reopen_over_import_ratio".into(),
            format!("{reopen_over_import:.4}"),
        );
        w.insert(
            "reopen_peak_rss_bytes".into(),
            reopen.peak_rss_bytes.to_string(),
        );
        // ---- The WAL residual the completed load left behind: what the reopen had to replay. ----
        w.insert(
            "wal_residual_bytes".into(),
            fp.footprint.wal_bytes.to_string(),
        );
        w.insert(
            "wal_to_store_ratio".into(),
            format!("{:.4}", fp.wal_to_store_ratio),
        );
        // ---- The honest CSV-relative amplifications + per-element costs (also in `storage`). ----
        w.insert(
            "store_space_amplification".into(),
            format!("{:.4}", fp.store_space_amplification),
        );
        w.insert(
            "total_space_amplification".into(),
            format!("{:.4}", fp.space_amplification),
        );
        w.insert(
            "csv_write_amplification".into(),
            format!("{:.4}", fp.write_amplification),
        );
        w.insert(
            "storage_bytes_per_node".into(),
            format!("{:.4}", fp.bytes_per_node),
        );
        w.insert(
            "storage_bytes_per_edge".into(),
            format!("{:.4}", fp.bytes_per_edge),
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
    collector.phase("reopen", Duration::from_secs_f64(reopen_secs));
    // The workload already ran (and was timed) before this report was built, so the collector could
    // not bracket it: hand it the real workload wall-time — BOTH halves of the bulk load, the import
    // and the reopen it obliges. Otherwise total_millis would time the report's own emission.
    collector.record_total_duration(timed.wall + Duration::from_secs_f64(reopen_secs));

    // CPU + memory: the import child's, measured by PID while it ran.
    let cpu: CpuSection = cpu_section(
        graphus_examples_harness::CpuTimes {
            user_secs: timed.user_secs,
            system_secs: timed.system_secs,
        },
        timed.wall,
    );
    *collector.cpu_mut() = cpu;
    collector.memory_mut().peak_rss_bytes =
        (timed.peak_rss_bytes > 0).then_some(timed.peak_rss_bytes);
    collector.memory_mut().final_rss_bytes = timed.final_rss_bytes;
    if timed.final_rss_bytes.is_none() {
        collector.note(
            "memory.final_rss_bytes is ABSENT = NOT MEASURED: the `graphus-bulk import` child had \
             already exited by the time the final read was taken, and an exited process has no \
             resident set. The PEAK RSS, sampled while it ran, IS the memory evidence for this \
             one-shot offline load. (rmp #711 — it used to be emitted as a bare `0`.)"
                .to_string(),
        );
    }

    // Storage: the durable footprint of the store the timed import produced. Every figure in the
    // field that MEANS it.
    {
        let s = collector.storage_mut();
        s.store_bytes = Some(fp.footprint.store_bytes);
        s.store_pages = Some(fp.footprint.store_pages);
        s.wal_bytes = Some(fp.footprint.wal_bytes);
        s.wal_pages = Some(fp.footprint.wal_pages);
        // bytes_fsynced: the retained WAL byte count is the honest fsync proxy for an offline load
        // (every committed WAL byte is fsynced before the commit is acknowledged).
        s.bytes_fsynced = Some(fp.footprint.wal_bytes);
        s.space_amplification = Some(fp.space_amplification);
        s.write_amplification = Some(fp.write_amplification);
        s.bytes_per_node = Some(fp.bytes_per_node);
        s.bytes_per_relationship = Some(fp.bytes_per_edge);
    }

    // Throughput: elements loaded over the import window. A one-shot batch load has no per-operation
    // latency to measure, so the percentiles are ABSENT (`rmp` #711/#716) — the per-batch ingest
    // latency of this same dataset IS measured over the wire, where a request boundary exists.
    collector.throughput_mut().operations = Some(throughput.count());
    collector.throughput_mut().ops_per_sec = Some(elements_per_sec);
    collector.note(
        "throughput.p50/p99/p999_latency_ms are ABSENT because this OFFLINE load HAS no per-operation \
         latency to measure: `graphus-bulk import` is a one-shot batch process with no \
         request/response boundary to time. The honest throughput figure for it is ops_per_sec \
         (elements/sec), which IS measured. The per-batch ingest LATENCY of this same dataset is \
         measured where a request boundary genuinely exists — over the wire, in the network \
         bulk-import step — and is reported in evidence/wire/report.json. (rmp #716: measure it, or \
         omit it and say why; never a 0.0 that reads as `instantaneous`.)"
            .to_string(),
    );

    collector.note(format!(
        "INGEST: the REAL `graphus-bulk import` child (pid-metered) loaded {elements} elements \
         ({} nodes + {} relationships, {} properties) from {:.2} MiB of CSV in {import_secs:.4}s — \
         {elements_per_sec:.1} elements/sec, {mb_per_sec:.3} MB/sec. Machine-variant; NOT gated.",
        manifest.total_nodes, manifest.total_relationships, manifest.total_properties, mb,
    ));
    collector.note(format!(
        "REOPEN COST (rmp #716) — the half of a bulk load nobody was measuring: reopening the store \
         this load produced took {reopen_secs:.4}s ({reopen_over_import:.2}x the {import_secs:.4}s \
         import itself), peaking at {} B RSS. That cost is the WAL: the completed load left a \
         {} B redo-log RESIDUAL behind ({:.2}x the {} B durable store it wrote), and a reopen must \
         replay all of it (recover_device + RecordStore::open). This is the rmp #576 path (a ~33s \
         reopen of a large store) and the rmp #579 path (a WAL blow-up on reopen), reproduced and \
         quantified at a scale the example can afford to run every time.",
        reopen.peak_rss_bytes,
        fp.footprint.wal_bytes,
        fp.wal_to_store_ratio,
        fp.footprint.store_bytes,
    ));
    collector.note(format!(
        "STORAGE: store_bytes / wal_bytes / the per-element costs / the amplifications are ALL \
         measured over the SAME store image the timed import above produced — one import, metered for \
         everything (rmp #716). The durable graph is {} B; each stored node costs {:.1} B and each \
         stored relationship {:.1} B of it (two VIEWS of one image — they do not sum to store_bytes). \
         Against {} B of logical CSV: the durable store amplifies {:.2}x, and store+WAL amplifies \
         {:.2}x (write_amplification), which is WAL-dominated and transient only if something \
         reclaims it.",
        fp.footprint.store_bytes,
        fp.bytes_per_node,
        fp.bytes_per_edge,
        fp.logical_csv_bytes,
        fp.store_space_amplification,
        fp.write_amplification,
    ));
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
         peak_rss={} B; cpu={:.3}s user + {:.3}s sys; store={} B ({} pages), wal={} B ({} pages, \
         {:.2}x the store); REOPEN={:.4}s ({:.2}x the import), reopen_peak_rss={} B",
        manifest.profile,
        manifest.total_nodes,
        manifest.total_relationships,
        import_secs,
        elements_per_sec,
        mb_per_sec,
        timed.peak_rss_bytes,
        timed.user_secs,
        timed.system_secs,
        fp.footprint.store_bytes,
        fp.footprint.store_pages,
        fp.footprint.wal_bytes,
        fp.footprint.wal_pages,
        fp.wal_to_store_ratio,
        reopen_secs,
        reopen_over_import,
        reopen.peak_rss_bytes,
    );

    // The machine-readable storage/reopen figures `run.sh` asserts on (stable field names).
    if let Some(path) = &args.storage_out {
        std::fs::write(path, render_storage_json(&fp, &reopen))
            .map_err(|e| format!("writing {path}: {e}"))?;
    }

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

/// Renders the measured footprint + reopen cost as machine-readable JSON (stable field names; parsed
/// and asserted on by `examples/bulk-etl/run.sh`).
fn render_storage_json(fp: &FootprintReport, reopen: &ReopenResult) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(1400);
    s.push_str("{\n");
    let _ = writeln!(s, "  \"nodes\": {},", fp.nodes);
    let _ = writeln!(s, "  \"relationships\": {},", fp.relationships);
    let _ = writeln!(s, "  \"logical_csv_bytes\": {},", fp.logical_csv_bytes);
    let _ = writeln!(s, "  \"store_bytes\": {},", fp.footprint.store_bytes);
    let _ = writeln!(s, "  \"store_pages\": {},", fp.footprint.store_pages);
    let _ = writeln!(s, "  \"wal_bytes\": {},", fp.footprint.wal_bytes);
    let _ = writeln!(s, "  \"wal_pages\": {},", fp.footprint.wal_pages);
    let _ = writeln!(s, "  \"total_bytes\": {},", fp.footprint.total_bytes());
    let _ = writeln!(s, "  \"bytes_per_node\": {:.4},", fp.bytes_per_node);
    let _ = writeln!(s, "  \"bytes_per_edge\": {:.4},", fp.bytes_per_edge);
    let _ = writeln!(
        s,
        "  \"store_space_amplification\": {:.4},",
        fp.store_space_amplification
    );
    let _ = writeln!(
        s,
        "  \"space_amplification\": {:.4},",
        fp.space_amplification
    );
    let _ = writeln!(
        s,
        "  \"write_amplification\": {:.4},",
        fp.write_amplification
    );
    let _ = writeln!(s, "  \"wal_to_store_ratio\": {:.4},", fp.wal_to_store_ratio);
    let _ = writeln!(s, "  \"reopen_secs\": {:.6},", reopen.open_secs);
    let _ = writeln!(s, "  \"reopen_scan_secs\": {:.6},", reopen.scan_secs);
    let _ = writeln!(s, "  \"reopen_peak_rss_bytes\": {},", reopen.peak_rss_bytes);
    s.push_str(
        "  \"note\": \"Every figure is measured over ONE store image: the store the timed \
         `graphus-bulk import` child produced. store_bytes is the durable graph.store image; \
         wal_bytes is the WAL RESIDUAL the completed load left behind (graph.wal is a DIRECTORY) — \
         exactly what a reopen must replay. bytes_per_node/edge are over the STORE image and are two \
         views of it, not a decomposition. store_space_amplification = store/logical (steady state); \
         space_amplification = write_amplification = (store+wal)/logical (the peak right after load, \
         WAL-dominated, and an honest LOWER bound on bytes written). reopen_secs is WAL recovery + \
         RecordStore::open on that same store (rmp #576/#579/#716).\"\n",
    );
    s.push_str("}\n");
    s
}

/// The metered result of one timed import.
struct TimedImport {
    counts: ImportCounts,
    wall: Duration,
    user_secs: f64,
    system_secs: f64,
    peak_rss_bytes: u64,
    /// The child's RSS at the very end of the import, or `None` when the process had already exited
    /// and no final read was possible — an exited process has no resident set, and a `0` there would
    /// read as a measurement (`rmp` #711).
    final_rss_bytes: Option<u64>,
}

/// Parsed counts from a `graphus-bulk import` run.
struct ImportCounts {
    nodes: u64,
    relationships: u64,
}

/// The measured cost of one store reopen, parsed from `bulk_reopen`'s stable stdout line.
struct ReopenResult {
    open_secs: f64,
    scan_secs: f64,
    peak_rss_bytes: u64,
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

    // Poll the child's RSS + CPU while it runs. The final reads below close the last-millisecond gap.
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
    // A final read after the loop. The import child has just EXITED, so this read almost always fails
    // — and an exited process has NO final RSS to report. That is "not measured", not "0 bytes
    // resident": the figure stays absent (`rmp` #711). The PEAK, sampled while the child was alive,
    // is the real memory evidence for a one-shot batch import.
    let final_rss = current_rss_bytes(target);
    peak_rss = peak_rss.max(final_rss.unwrap_or(0));

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

/// Runs the `bulk_reopen` driver against the store the import just produced, and parses its measured
/// reopen cost. `bulk_reopen` asserts the reopened store still holds the whole graph, so a reopen that
/// came back fast because it came back EMPTY fails here rather than being reported as a good number.
fn timed_reopen(
    reopen_bin: &Path,
    store: &Path,
    nodes: u64,
    rels: u64,
) -> Result<ReopenResult, String> {
    let out = Command::new(reopen_bin)
        .arg("--db")
        .arg(store)
        .arg("--expect-nodes")
        .arg(nodes.to_string())
        .arg("--expect-rels")
        .arg(rels.to_string())
        .output()
        .map_err(|e| format!("spawning {}: {e}", reopen_bin.display()))?;
    if !out.status.success() {
        return Err(format!(
            "bulk_reopen failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("GRAPHUS_BULK_REOPEN_OK"))
        .ok_or_else(|| format!("bulk_reopen produced no result line:\n{stdout}"))?;
    let kv = |key: &str| -> Option<&str> {
        line.split_whitespace()
            .find_map(|tok| tok.strip_prefix(&format!("{key}=")))
    };
    let open_secs = kv("open_secs")
        .ok_or("bulk_reopen: missing open_secs")?
        .parse::<f64>()
        .map_err(|e| format!("bulk_reopen: open_secs: {e}"))?;
    let scan_secs = kv("scan_secs")
        .ok_or("bulk_reopen: missing scan_secs")?
        .parse::<f64>()
        .map_err(|e| format!("bulk_reopen: scan_secs: {e}"))?;
    let peak_rss_bytes = kv("peak_rss_bytes")
        .ok_or("bulk_reopen: missing peak_rss_bytes")?
        .parse::<u64>()
        .map_err(|e| format!("bulk_reopen: peak_rss_bytes: {e}"))?;
    Ok(ReopenResult {
        open_secs,
        scan_secs,
        peak_rss_bytes,
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
            "--storage-out" => args.storage_out = Some(value()?),
            "--keep-store" => args.keep_store = Some(value()?),
            "--bulk-bin" => args.bulk_bin = Some(value()?),
            "--reopen-bin" => args.reopen_bin = Some(value()?),
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
                    "usage: bulk_evidence --evidence-dir <dir> --data-dir <dir> \
                     [--storage-out <storage.json>] [--keep-store <dir>] [--bulk-bin <graphus-bulk>] \
                     [--reopen-bin <bulk_reopen>] [--scenario bulk-etl] [--description <text>] \
                     [--content-hash <hex>] [--param k=v]... [--note <t>]... [--work-dir <dir>]"
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
    if args.scenario.is_empty() {
        args.scenario = "bulk-etl".to_string();
    }
    if args.description.is_empty() {
        args.description =
            "Offline high-throughput bulk ingest + ETL: import a deterministic LDBC-SNB-like social \
             network from CSV via the real graphus-bulk binary; measure the ingest throughput, the \
             on-disk store footprint / amplification / WAL residual, and the COST OF REOPENING the \
             loaded store; and prove a lossless import -> dump -> re-import round-trip."
                .to_string();
    }
    Ok(args)
}

fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("reading manifest {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("parsing manifest {}: {e}", path.display()))
}

/// Resolves a helper binary: the explicit path if given, else a sibling of our own executable (the
/// usual `target/<profile>/` colocation), else `name` on `PATH`.
fn resolve_sibling(explicit: Option<PathBuf>, name: &str) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        if p.exists() {
            return Ok(p);
        }
        return Err(format!("{} does not exist", p.display()));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    Ok(PathBuf::from(name))
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
