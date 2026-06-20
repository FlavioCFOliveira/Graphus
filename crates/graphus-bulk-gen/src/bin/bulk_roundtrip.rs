//! `bulk_roundtrip` — drives the **real `graphus-bulk` binary** through a lossless
//! `import -> dump -> re-import` round-trip and proves it.
//!
//! # What it does (and asserts)
//!
//! 1. Generates the deterministic social-network dataset (per-label node CSVs + per-type relationship
//!    CSVs + `manifest.json`) for the chosen profile.
//! 2. Runs `graphus-bulk import` into a **fresh** store A, parsing its reported counts and asserting
//!    they equal the manifest's known logical counts (nodes / relationships / properties).
//! 3. Re-opens store A and asserts it is internally consistent (the ACID gate) and that its
//!    node/relationship counts match the manifest. Computes its **id-independent content hash**.
//! 4. Runs `graphus-bulk dump` to export the whole graph to CSV, then `graphus-bulk import` of that
//!    dump into a second fresh store B.
//! 5. Re-opens store B, verifies consistency, and asserts its content hash **equals** store A's —
//!    conclusive proof the round-trip is lossless (same labels, types, property values, connectivity,
//!    independent of physical id assignment).
//!
//! All file work happens under a private temp dir that is removed on exit. The driver exits non-zero
//! the moment any assertion fails, so it doubles as an executable E2E test of the bulk path. It is
//! hermetic (no server, no network) and deterministic.
//!
//! Usage:
//! ```text
//! bulk_roundtrip --bulk-bin <path/to/graphus-bulk> --data-dir <dir-with-csvs-and-manifest> \
//!     [--work-dir <dir>]
//! ```
//! `--data-dir` is where `bulk_gen` wrote the CSVs + `manifest.json`. If `--bulk-bin` is omitted the
//! driver looks for `graphus-bulk` next to its own executable, then on `PATH`.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use graphus_bulk_gen::Manifest;
use graphus_bulk_gen::content_hash::{ContentHash, content_hash};
use graphus_bulk_gen::store_io::open_store;
use graphus_storage::check::verify_on_open;

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
            eprintln!("bulk_roundtrip: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut bulk_bin: Option<PathBuf> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut work_dir: Option<PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bulk-bin" => bulk_bin = Some(PathBuf::from(next(&mut args, "--bulk-bin")?)),
            "--data-dir" => data_dir = Some(PathBuf::from(next(&mut args, "--data-dir")?)),
            "--work-dir" => work_dir = Some(PathBuf::from(next(&mut args, "--work-dir")?)),
            "-h" | "--help" => {
                eprintln!(
                    "usage: bulk_roundtrip --bulk-bin <graphus-bulk> --data-dir <dir> \
                     [--work-dir <dir>]"
                );
                return Ok(());
            }
            other => return Err(format!("unexpected argument '{other}'")),
        }
    }

    let data_dir = data_dir.ok_or("--data-dir is required (where bulk_gen wrote the CSVs)")?;
    let bulk_bin = resolve_bulk_bin(bulk_bin)?;

    // Read the generator manifest (the assertion contract).
    let manifest = read_manifest(&data_dir.join("manifest.json"))?;
    eprintln!(
        "bulk_roundtrip: profile={} expects nodes={} relationships={} properties={}",
        manifest.profile,
        manifest.total_nodes,
        manifest.total_relationships,
        manifest.total_properties
    );

    // A private workspace (removed on exit, even on early return, via the guard).
    let work = match work_dir {
        Some(w) => {
            std::fs::create_dir_all(&w)
                .map_err(|e| format!("creating work-dir {}: {e}", w.display()))?;
            w
        }
        None => mkdtemp("graphus-bulk-etl")?,
    };
    let _guard = scopeguard(&work);

    let store_a = work.join("store-a");
    let dump_dir = work.join("dump");
    let store_b = work.join("store-b");
    std::fs::create_dir_all(&dump_dir)
        .map_err(|e| format!("creating dump dir {}: {e}", dump_dir.display()))?;

    // ----- Step 1: import the generated CSVs into store A. -----
    let stats_a = run_import(&bulk_bin, &store_a, &data_dir)?;
    assert_eq("import: node count", manifest.total_nodes, stats_a.nodes)?;
    assert_eq(
        "import: relationship count",
        manifest.total_relationships,
        stats_a.relationships,
    )?;
    assert_eq(
        "import: property count",
        manifest.total_properties,
        stats_a.properties,
    )?;

    // ----- Step 2: re-open store A, verify consistency, count, hash. -----
    let hash_a = inspect_store("store A", &store_a, &manifest)?;

    // ----- Step 3: dump store A to CSV. -----
    let nodes_out = dump_dir.join("nodes.csv");
    let rels_out = dump_dir.join("rels.csv");
    run_dump(&bulk_bin, &store_a, &nodes_out, &rels_out)?;
    assert_nonempty(&nodes_out)?;
    assert_nonempty(&rels_out)?;

    // ----- Step 4: re-import the dump into store B. -----
    let stats_b = run_import_files(&bulk_bin, &store_b, &[nodes_out], &[rels_out])?;
    assert_eq(
        "re-import: node count == original",
        manifest.total_nodes,
        stats_b.nodes,
    )?;
    assert_eq(
        "re-import: relationship count == original",
        manifest.total_relationships,
        stats_b.relationships,
    )?;
    // NOTE: the property COUNT is deliberately NOT asserted across the dump. `graphus-bulk dump`
    // unifies every property key across ALL node labels into ONE nodes file (one column per distinct
    // key), so a node is emitted with EMPTY cells for keys other labels carry. On re-import,
    // graphus-bulk's documented value semantics materialise an empty `string`/`string[]` cell as a
    // present empty-string / empty-list property (only non-string scalars treat empty as absent), so
    // the populated-property count after a heterogeneous-label dump is HIGHER than the original. This
    // is a property of the importer/dumper pair, not of the data. The lossless guarantee we assert is
    // the CONTENT HASH below, computed over a CANONICAL shape that is invariant to these
    // present-but-empty string/array properties (see `content_hash`).
    eprintln!(
        "  store B re-import reported {} properties (>= original {} — the dump unifies label \
         columns; empty string/array cells re-import as present-but-empty properties, which the \
         content hash canonicalises away)",
        stats_b.properties, manifest.total_properties
    );

    // ----- Step 5: re-open store B, verify consistency, hash, and compare. -----
    let hash_b = inspect_store("store B", &store_b, &manifest)?;

    if hash_a.hex != hash_b.hex {
        return Err(format!(
            "LOSSY ROUND-TRIP: content hash diverged\n  store A: {} ({} nodes, {} rels)\n  store B: {} ({} nodes, {} rels)",
            hash_a.hex,
            hash_a.nodes,
            hash_a.relationships,
            hash_b.hex,
            hash_b.nodes,
            hash_b.relationships
        ));
    }

    // Machine-readable result line for run.sh to parse / assert on.
    println!(
        "GRAPHUS_BULK_ROUNDTRIP_OK profile={} nodes={} relationships={} properties={} content_hash={}",
        manifest.profile, hash_a.nodes, hash_a.relationships, manifest.total_properties, hash_a.hex
    );
    eprintln!(
        "bulk_roundtrip: LOSSLESS — import -> dump -> re-import preserved {} nodes, {} relationships \
         and content hash {}",
        hash_a.nodes, hash_a.relationships, hash_a.hex
    );
    Ok(())
}

/// Parsed counts from a `graphus-bulk import` run's stdout.
struct ImportCounts {
    nodes: u64,
    relationships: u64,
    properties: u64,
}

/// Runs `graphus-bulk import --db <store> --nodes ... --relationships ...` for the generated dataset
/// directory (using the fixed [`NODE_FILES`] / [`REL_FILES`] order).
fn run_import(bulk_bin: &Path, store: &Path, data_dir: &Path) -> Result<ImportCounts, String> {
    let nodes: Vec<PathBuf> = NODE_FILES.iter().map(|f| data_dir.join(f)).collect();
    let rels: Vec<PathBuf> = REL_FILES.iter().map(|f| data_dir.join(f)).collect();
    run_import_files(bulk_bin, store, &nodes, &rels)
}

/// Runs `graphus-bulk import` for explicit node/relationship file lists.
fn run_import_files(
    bulk_bin: &Path,
    store: &Path,
    nodes: &[PathBuf],
    rels: &[PathBuf],
) -> Result<ImportCounts, String> {
    let mut cmd = Command::new(bulk_bin);
    cmd.arg("import").arg("--db").arg(store);
    for n in nodes {
        cmd.arg("--nodes").arg(n);
    }
    for r in rels {
        cmd.arg("--relationships").arg(r);
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
    parse_import_counts(&stdout)
}

/// Runs `graphus-bulk dump --db <store> --nodes-out <f> --relationships-out <f>`.
fn run_dump(
    bulk_bin: &Path,
    store: &Path,
    nodes_out: &Path,
    rels_out: &Path,
) -> Result<(), String> {
    let out = Command::new(bulk_bin)
        .arg("dump")
        .arg("--db")
        .arg(store)
        .arg("--nodes-out")
        .arg(nodes_out)
        .arg("--relationships-out")
        .arg(rels_out)
        .output()
        .map_err(|e| format!("spawning {} dump: {e}", bulk_bin.display()))?;
    if !out.status.success() {
        return Err(format!(
            "graphus-bulk dump failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Parses the importer's `imported N nodes, M relationships, P properties` stdout line.
fn parse_import_counts(stdout: &str) -> Result<ImportCounts, String> {
    // Line shape: "imported 4806 nodes, 64360 relationships, 47190 properties"
    let line = stdout
        .lines()
        .find(|l| l.starts_with("imported "))
        .ok_or_else(|| format!("could not find 'imported' line in import output:\n{stdout}"))?;
    let mut nodes = None;
    let mut relationships = None;
    let mut properties = None;
    let toks: Vec<&str> = line.split_whitespace().collect();
    for w in toks.windows(2) {
        let n: Result<u64, _> = w[0].trim_end_matches(',').parse();
        if let Ok(n) = n {
            match w[1].trim_end_matches(',') {
                "nodes" => nodes = Some(n),
                "relationships" => relationships = Some(n),
                "properties" => properties = Some(n),
                _ => {}
            }
        }
    }
    Ok(ImportCounts {
        nodes: nodes.ok_or("missing node count in import output")?,
        relationships: relationships.ok_or("missing relationship count in import output")?,
        properties: properties.ok_or("missing property count in import output")?,
    })
}

/// Re-opens a store dir, verifies it is internally consistent (the ACID gate), asserts its
/// node/relationship counts match the manifest, and returns its content hash.
fn inspect_store(name: &str, db: &Path, manifest: &Manifest) -> Result<ContentHash, String> {
    let mut store = open_store(db).map_err(|e| format!("{name}: opening store: {e}"))?;
    verify_on_open(&mut store, &[]).map_err(|e| format!("{name}: store inconsistent: {e}"))?;

    let nodes = store
        .scan_node_ids()
        .map_err(|e| format!("{name}: scan nodes: {e}"))?
        .len() as u64;
    let rels = store
        .scan_rel_ids()
        .map_err(|e| format!("{name}: scan rels: {e}"))?
        .len() as u64;
    assert_eq(
        &format!("{name}: stored node count"),
        manifest.total_nodes,
        nodes,
    )?;
    assert_eq(
        &format!("{name}: stored relationship count"),
        manifest.total_relationships,
        rels,
    )?;

    let hash = content_hash(&mut store);
    eprintln!(
        "  {name}: consistent, {} nodes, {} relationships, content_hash={}",
        hash.nodes, hash.relationships, hash.hex
    );
    Ok(hash)
}

// ---- Small helpers (arg parsing, manifest IO, temp dir, assertions). ----

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
    // Next to our own executable (the usual `target/<profile>/` colocation).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("graphus-bulk");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    // Fall back to PATH.
    Ok(PathBuf::from("graphus-bulk"))
}

fn assert_eq(what: &str, expected: u64, actual: u64) -> Result<(), String> {
    if expected == actual {
        Ok(())
    } else {
        Err(format!("{what}: expected {expected}, got {actual}"))
    }
}

fn assert_nonempty(path: &Path) -> Result<(), String> {
    let len = std::fs::metadata(path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .len();
    if len == 0 {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(())
}

/// Creates a unique temp dir under `$TMPDIR` (or `/tmp`). Deterministic-name-free (uses the pid +
/// a monotonic counter) — the round-trip is deterministic, but the scratch *location* need not be.
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

/// A tiny RAII guard that removes `dir` on drop (best-effort).
fn scopeguard(dir: &Path) -> impl Drop {
    struct Guard(PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    Guard(dir.to_path_buf())
}
