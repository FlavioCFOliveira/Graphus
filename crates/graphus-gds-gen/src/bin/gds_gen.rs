//! `gds_gen` — the deterministic influence-network generator binary for `examples/gds-analytics`.
//!
//! Writes these artifacts into `--out-dir` for the chosen `--profile`:
//! - `graph.cypher` — the schema DDL + `:Author`/`:Ref` node and `:CITES`/`:LINKS` edge CREATE
//!   statements (one per line, `;`-terminated). This is the **slow** load path; the attach mode uses
//!   it against a server with no bulk-import endpoint.
//! - `schema.cypher` — the schema DDL block on its own, for the bulk-import path (which ingests raw
//!   CSV and applies the schema afterwards).
//! - `nodes.csv` / `relationships.csv` — the network **bulk-import (Mode A)** CSV artifacts
//!   (`specification/08-network-bulk-import.md`); the **fast** load path the default profile uses.
//! - `reference.json` — the analytically-known reference subgraph + its known algorithm outputs the
//!   workload asserts against.
//!
//! Output is a pure function of `(profile)` (each profile pins its own seed), so re-running yields
//! byte-identical files. Hermetic: serde only, no engine, no network.
//!
//! Usage:
//! ```text
//! cargo run -p graphus-gds-gen --bin gds_gen -- --profile fast     --out-dir <dir>
//! cargo run -p graphus-gds-gen --bin gds_gen -- --profile moderate --out-dir <dir>
//! cargo run -p graphus-gds-gen --bin gds_gen -- --profile large    --out-dir <dir>
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_gds_gen::{Profile, generate, schema_cypher};

fn main() -> ExitCode {
    let mut profile = Profile::Fast;
    let mut out_dir = PathBuf::from(".");

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => {
                let v = match args.next() {
                    Some(v) => v,
                    None => return fail("--profile requires a value (fast|moderate|large)"),
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
                    "usage: gds_gen --profile <fast|moderate|large> --out-dir <dir>\n\
                     writes graph.cypher + schema.cypher + nodes.csv + relationships.csv + \
                     reference.json"
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

    let cypher_path = out_dir.join("graph.cypher");
    let schema_path = out_dir.join("schema.cypher");
    let nodes_path = out_dir.join("nodes.csv");
    let rels_path = out_dir.join("relationships.csv");
    let ref_path = out_dir.join("reference.json");

    let ref_json = match dataset.reference_json() {
        Ok(j) => j,
        Err(e) => return fail(&format!("reference serialization failed: {e}")),
    };

    // Each artifact is written independently so a write failure names the exact file that failed.
    let files: [(&PathBuf, String); 5] = [
        (&cypher_path, dataset.to_cypher()),
        (&schema_path, schema_cypher()),
        (&nodes_path, dataset.authors_csv()),
        (&rels_path, dataset.relationships_csv()),
        (&ref_path, ref_json),
    ];
    for (path, contents) in &files {
        if let Err(e) = std::fs::write(path, contents) {
            return fail(&format!("cannot write {}: {e}", path.display()));
        }
    }

    // The summary line is parsed by run.sh (the `kv` helper) for the evidence dataset sizing.
    // node_count = authors + 6 reference nodes; rel_count = citations + 7 reference links.
    let node_count = dataset.authors.len() + dataset.reference.ref_ids.len();
    let rel_count = dataset.citations.len() + dataset.reference.links.len();
    println!(
        "generated profile={} seed={:#018x} authors={} fields={} citations={} \
         ref_nodes={} ref_links={} nodes={} rels={}",
        profile.name(),
        cfg.seed,
        dataset.authors.len(),
        cfg.community_count,
        dataset.citations.len(),
        dataset.reference.ref_ids.len(),
        dataset.reference.links.len(),
        node_count,
        rel_count,
    );
    for (path, _) in &files {
        println!("wrote {}", path.display());
    }

    ExitCode::SUCCESS
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("gds_gen: error: {msg}");
    ExitCode::FAILURE
}
