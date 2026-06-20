//! `bulk_storage` — measures the **on-disk storage footprint** of a bulk-loaded store and the
//! classic write/space **amplification** ratios, emitting machine-readable JSON for the evidence
//! report (mirrors how `gds_sweep` emits `sweep.json`).
//!
//! # What it measures (honestly)
//!
//! 1. Imports the generated social-network dataset into a **fresh** store with the real
//!    `graphus-bulk` binary (the same path the example demonstrates), capturing its reported
//!    node/relationship counts.
//! 2. Walks the store directory with the shared harness
//!    [`StorageMeter`](graphus_examples_harness::StorageMeter), splitting the footprint into the
//!    `graph.store` block-device file and the `graph.wal` segment directory: total **bytes** and
//!    whole-**page** counts for each.
//! 3. Derives, from the manifest's known logical sizes:
//!    - **bytes-per-node** = total on-disk store bytes / node count,
//!    - **bytes-per-edge** = total on-disk store bytes / relationship count,
//!    - **space amplification** = total on-disk bytes (store + WAL) / logical CSV bytes,
//!    - **write amplification** = physical bytes written to disk (store + WAL) / logical CSV bytes
//!      written. For an offline bulk load the dominant physical writes are the final store image plus
//!      the WAL the batched commits produced; using the resident on-disk sizes as the physical-bytes
//!      proxy is an **honest lower bound** (it does not count WAL bytes later truncated/recycled), and
//!      is documented as such in the emitted JSON `note`.
//!
//! The denominator (`logical_csv_bytes`) is the uncompressed size of the loader-ready CSV the dataset
//! occupies — a meaningful, reproducible logical-size baseline (it is the literal input the loader
//! consumed), not a hand-waved estimate.
//!
//! All file work happens under a private temp dir removed on exit. Hermetic (no server, no network),
//! deterministic dataset. Output JSON field names are stable so `run.sh` / the evidence report can
//! parse them.
//!
//! Usage:
//! ```text
//! bulk_storage --bulk-bin <graphus-bulk> --data-dir <dir-with-csvs-and-manifest> \
//!     [--out <storage.json>] [--work-dir <dir>]
//! ```

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use graphus_bulk_gen::Manifest;
use graphus_examples_harness::StorageMeter;

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

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bulk_storage: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut bulk_bin: Option<PathBuf> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut work_dir: Option<PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bulk-bin" => bulk_bin = Some(PathBuf::from(next(&mut args, "--bulk-bin")?)),
            "--data-dir" => data_dir = Some(PathBuf::from(next(&mut args, "--data-dir")?)),
            "--out" => out_path = Some(PathBuf::from(next(&mut args, "--out")?)),
            "--work-dir" => work_dir = Some(PathBuf::from(next(&mut args, "--work-dir")?)),
            "-h" | "--help" => {
                eprintln!(
                    "usage: bulk_storage --bulk-bin <graphus-bulk> --data-dir <dir> \
                     [--out <storage.json>] [--work-dir <dir>]"
                );
                return Ok(());
            }
            other => return Err(format!("unexpected argument '{other}'")),
        }
    }

    let data_dir = data_dir.ok_or("--data-dir is required (where bulk_gen wrote the CSVs)")?;
    let bulk_bin = resolve_bulk_bin(bulk_bin)?;
    let manifest = read_manifest(&data_dir.join("manifest.json"))?;

    let work = match work_dir {
        Some(w) => {
            std::fs::create_dir_all(&w)
                .map_err(|e| format!("creating work-dir {}: {e}", w.display()))?;
            w
        }
        None => mkdtemp("graphus-bulk-storage")?,
    };
    let _guard = scopeguard(&work);

    let store_dir = work.join("store");

    // ----- Import the dataset into a fresh store. -----
    let counts = run_import(&bulk_bin, &store_dir, &data_dir)?;
    if counts.nodes != manifest.total_nodes || counts.relationships != manifest.total_relationships
    {
        return Err(format!(
            "import counts ({} nodes, {} rels) disagree with manifest ({} nodes, {} rels)",
            counts.nodes, counts.relationships, manifest.total_nodes, manifest.total_relationships
        ));
    }

    // ----- Measure the on-disk footprint (store file + WAL directory). -----
    let store_file = store_dir.join("graph.store");
    let wal_dir = store_dir.join("graph.wal");
    let (store_fp, wal_fp) = StorageMeter::measure(&store_file, &wal_dir)
        .map_err(|e| format!("measuring store footprint: {e}"))?;

    let total_bytes = store_fp.bytes + wal_fp.bytes;
    let nodes = manifest.total_nodes.max(1);
    let rels = manifest.total_relationships.max(1);
    let logical = manifest.logical_csv_bytes;

    // Bytes-per-element are reported against the STORE image (the durable graph), not the WAL (a
    // transient redo log), which is the meaningful per-record on-disk cost.
    let bytes_per_node = store_fp.bytes as f64 / nodes as f64;
    let bytes_per_edge = store_fp.bytes as f64 / rels as f64;
    // Two space-amplification figures, both honest and useful:
    //  - store-only: the DURABLE graph image vs the logical input — the steady-state on-disk cost of
    //    the data (fixed-record padding, free-list slack, token catalogs). This is what a compacted /
    //    checkpointed store occupies.
    //  - total: store + the retained WAL redo log vs the logical input — the peak footprint right
    //    after a bulk load, before any WAL truncation/checkpoint. The WAL dominates here because the
    //    batched commits logged every page; it is transient, not steady-state.
    let store_space_amp = StorageMeter::space_amplification(store_fp.bytes, logical);
    let space_amp = StorageMeter::space_amplification(total_bytes, logical);
    // Write amplification uses the total physical bytes written (store + WAL) as an honest lower
    // bound on bytes that hit disk for `logical` bytes of input.
    let write_amp = StorageMeter::write_amplification(total_bytes, logical);

    let report = StorageReport {
        profile: manifest.profile.clone(),
        nodes: manifest.total_nodes,
        relationships: manifest.total_relationships,
        properties: manifest.total_properties,
        logical_csv_bytes: logical,
        store_bytes: store_fp.bytes,
        store_pages: store_fp.pages,
        wal_bytes: wal_fp.bytes,
        wal_pages: wal_fp.pages,
        total_bytes,
        bytes_per_node,
        bytes_per_edge,
        store_space_amplification: store_space_amp,
        space_amplification: space_amp,
        write_amplification: write_amp,
    };

    eprintln!(
        "bulk_storage: profile={} store={} B ({} pages) wal={} B ({} pages) \
         => {:.1} B/node, {:.1} B/edge, store_space_amp={:.2}x, total_space_amp={:.2}x, write_amp={:.2}x",
        report.profile,
        report.store_bytes,
        report.store_pages,
        report.wal_bytes,
        report.wal_pages,
        report.bytes_per_node,
        report.bytes_per_edge,
        report.store_space_amplification,
        report.space_amplification,
        report.write_amplification
    );

    let json = render_json(&report);
    match &out_path {
        Some(p) => {
            std::fs::write(p, &json).map_err(|e| format!("writing {}: {e}", p.display()))?;
            eprintln!("bulk_storage: wrote {}", p.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

/// The measured storage footprint + amplification report (stable JSON field names).
struct StorageReport {
    profile: String,
    nodes: u64,
    relationships: u64,
    properties: u64,
    logical_csv_bytes: u64,
    store_bytes: u64,
    store_pages: u64,
    wal_bytes: u64,
    wal_pages: u64,
    total_bytes: u64,
    bytes_per_node: f64,
    bytes_per_edge: f64,
    store_space_amplification: f64,
    space_amplification: f64,
    write_amplification: f64,
}

/// Renders the report as machine-readable JSON (hand-rolled; stable field names for `run.sh`).
fn render_json(r: &StorageReport) -> String {
    let mut s = String::with_capacity(1024);
    s.push_str("{\n");
    let _ = writeln!(s, "  \"profile\": \"{}\",", r.profile);
    let _ = writeln!(s, "  \"nodes\": {},", r.nodes);
    let _ = writeln!(s, "  \"relationships\": {},", r.relationships);
    let _ = writeln!(s, "  \"properties\": {},", r.properties);
    let _ = writeln!(s, "  \"logical_csv_bytes\": {},", r.logical_csv_bytes);
    let _ = writeln!(s, "  \"store_bytes\": {},", r.store_bytes);
    let _ = writeln!(s, "  \"store_pages\": {},", r.store_pages);
    let _ = writeln!(s, "  \"wal_bytes\": {},", r.wal_bytes);
    let _ = writeln!(s, "  \"wal_pages\": {},", r.wal_pages);
    let _ = writeln!(s, "  \"total_bytes\": {},", r.total_bytes);
    let _ = writeln!(s, "  \"bytes_per_node\": {:.4},", r.bytes_per_node);
    let _ = writeln!(s, "  \"bytes_per_edge\": {:.4},", r.bytes_per_edge);
    let _ = writeln!(
        s,
        "  \"store_space_amplification\": {:.4},",
        r.store_space_amplification
    );
    let _ = writeln!(
        s,
        "  \"space_amplification\": {:.4},",
        r.space_amplification
    );
    let _ = writeln!(
        s,
        "  \"write_amplification\": {:.4},",
        r.write_amplification
    );
    s.push_str(
        "  \"note\": \"store_bytes is the durable graph.store image; wal_bytes is the retained \
         graph.wal redo log. bytes_per_node/edge are over the STORE image. \
         store_space_amplification = store_bytes/logical_csv_bytes (the STEADY-STATE durable cost); \
         space_amplification = (store+wal)/logical_csv_bytes (the PEAK footprint right after load, \
         WAL-dominated and transient until checkpoint/truncation); write_amplification = \
         (store+wal)/logical_csv_bytes is an honest LOWER BOUND on bytes written (resident on-disk \
         bytes, not counting WAL bytes later truncated/recycled). PAGE_SIZE is the harness page \
         size.\"\n",
    );
    s.push_str("}\n");
    s
}

/// Parsed counts from a `graphus-bulk import` run.
struct ImportCounts {
    nodes: u64,
    relationships: u64,
}

fn run_import(bulk_bin: &Path, store: &Path, data_dir: &Path) -> Result<ImportCounts, String> {
    let mut cmd = Command::new(bulk_bin);
    cmd.arg("import").arg("--db").arg(store);
    for f in NODE_FILES {
        cmd.arg("--nodes").arg(data_dir.join(f));
    }
    for f in REL_FILES {
        cmd.arg("--relationships").arg(data_dir.join(f));
    }
    let out = cmd
        .output()
        .map_err(|e| format!("spawning {} import: {e}", bulk_bin.display()))?;
    if !out.status.success() {
        return Err(format!(
            "graphus-bulk import failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
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
        nodes: nodes.ok_or("missing node count")?,
        relationships: relationships.ok_or("missing relationship count")?,
    })
}

// ---- Shared small helpers (kept local to each binary to avoid a thin helper module). ----

fn next(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}

fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("reading manifest {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("parsing manifest {}: {e}", path.display()))
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
    Err("could not create a unique temp dir".to_owned())
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
