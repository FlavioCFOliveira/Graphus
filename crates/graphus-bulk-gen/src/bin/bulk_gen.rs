//! `bulk_gen` — the deterministic social-network CSV generator binary for `examples/bulk-etl`.
//!
//! Writes the loader-ready dataset into `--out-dir` for the chosen `--profile`:
//! - one node CSV per label (`persons.csv`, `forums.csv`, `posts.csv`, `comments.csv`),
//! - one relationship CSV per type (`knows.csv`, `has_member.csv`, `container_of.csv`,
//!   `has_creator.csv`, `reply_of.csv`, `likes.csv`),
//! - `manifest.json` — the known logical counts (nodes per label, rels per type, total properties,
//!   logical content bytes) the round-trip + footprint drivers assert against.
//!
//! Output is a pure function of `(profile)` (each profile pins its own seed), so re-running yields
//! byte-identical files. Hermetic: serde only, no engine, no network.
//!
//! Usage:
//! ```text
//! cargo run -p graphus-bulk-gen --bin bulk_gen -- --profile fast  --out-dir <dir>
//! cargo run -p graphus-bulk-gen --bin bulk_gen -- --profile large --out-dir <dir>
//! ```

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_bulk_gen::{Profile, generate};

fn main() -> ExitCode {
    let mut profile = Profile::Fast;
    let mut out_dir = PathBuf::from(".");

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => {
                let v = match args.next() {
                    Some(v) => v,
                    None => return fail("--profile requires a value (fast|large)"),
                };
                profile = match Profile::parse(&v) {
                    Ok(p) => p,
                    Err(e) => return fail(&e),
                };
            }
            "--out-dir" => {
                out_dir = match args.next() {
                    Some(v) => PathBuf::from(v),
                    None => return fail("--out-dir requires a value"),
                };
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: bulk_gen --profile <fast|large> --out-dir <dir>\n\
                     writes per-label node CSVs + per-type relationship CSVs + manifest.json"
                );
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unexpected argument '{other}'")),
        }
    }

    let cfg = profile.config();
    let dataset = generate(cfg, profile.name());

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        return fail(&format!("cannot create out-dir {}: {e}", out_dir.display()));
    }

    // Write every node + relationship CSV file.
    for nf in &dataset.node_files {
        let path = out_dir.join(&nf.name);
        if let Err(e) = std::fs::write(&path, &nf.csv) {
            return fail(&format!("cannot write {}: {e}", path.display()));
        }
    }
    for rf in &dataset.rel_files {
        let path = out_dir.join(&rf.name);
        if let Err(e) = std::fs::write(&path, &rf.csv) {
            return fail(&format!("cannot write {}: {e}", path.display()));
        }
    }

    // Write the manifest.
    let manifest_path = out_dir.join("manifest.json");
    let manifest_json = match dataset.manifest_json() {
        Ok(j) => j,
        Err(e) => return fail(&format!("manifest serialization failed: {e}")),
    };
    if let Err(e) = std::fs::write(&manifest_path, &manifest_json) {
        return fail(&format!("cannot write {}: {e}", manifest_path.display()));
    }

    // A `key=value` summary line, parsed by run.sh for dataset sizing (mirrors `gds_gen`).
    let m = &dataset.manifest;
    println!(
        "generated profile={} seed={:#018x} nodes={} relationships={} properties={} \
         logical_csv_bytes={} node_files={} rel_files={}",
        profile.name(),
        cfg.seed,
        m.total_nodes,
        m.total_relationships,
        m.total_properties,
        m.logical_csv_bytes,
        dataset.node_files.len(),
        dataset.rel_files.len(),
    );
    // Per-table breakdown (informative).
    for (label, count) in &m.nodes_by_label {
        println!("  nodes {label}={count}");
    }
    for (ty, count) in &m.relationships_by_type {
        println!("  rels {ty}={count}");
    }
    println!("wrote {}", manifest_path.display());

    ExitCode::SUCCESS
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("bulk_gen: error: {msg}");
    ExitCode::FAILURE
}
