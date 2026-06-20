//! `kg_gen` — the deterministic knowledge-graph generator binary for
//! `examples/knowledge-graph-rest`.
//!
//! Writes two artifacts into `--out-dir` for the chosen `--profile`:
//! - `graph.cypher` — the schema DDL (UNIQUE id constraints + a `Document.year` index) plus the
//!   `:Topic`/`:Concept`/`:Author`/`:Document` node and `:AUTHORED`/`:ABOUT`/`:MENTIONS`/`:CITES`/
//!   `:RELATED_TO` edge statements (one per line, `;`-terminated), followed by the fixed reference
//!   subgraph,
//! - `reference.json` — the analytically-known reference subgraph + the hand-derived answers to the
//!   five discovery queries the REST workload asserts against the live server.
//!
//! Output is a pure function of `(profile)` (each profile pins its own seed), so re-running yields
//! byte-identical files. Hermetic: serde only, no engine, no network.
//!
//! Usage:
//! ```text
//! cargo run -p graphus-kg-gen --bin kg_gen -- --profile fast  --out-dir <dir>
//! cargo run -p graphus-kg-gen --bin kg_gen -- --profile large --out-dir <dir>
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_kg_gen::{Profile, generate};

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
                    "usage: kg_gen --profile <fast|large> --out-dir <dir>\n\
                     writes graph.cypher + reference.json"
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
    let ref_path = out_dir.join("reference.json");

    let ref_json = match dataset.reference_json() {
        Ok(j) => j,
        Err(e) => return fail(&format!("reference serialization failed: {e}")),
    };

    if let Err(e) = std::fs::write(&cypher_path, dataset.to_cypher()) {
        return fail(&format!("cannot write {}: {e}", cypher_path.display()));
    }
    if let Err(e) = std::fs::write(&ref_path, ref_json) {
        return fail(&format!("cannot write {}: {e}", ref_path.display()));
    }

    // The summary line is parsed by run.sh (the `kv` helper) for the evidence dataset sizing.
    let nodes = dataset.node_count();
    println!(
        "generated profile={} seed={:#018x} topics={} concepts={} authors={} documents={} nodes={}",
        profile.name(),
        cfg.seed,
        dataset.topics.len(),
        dataset.concepts.len(),
        dataset.authors.len(),
        dataset.documents.len(),
        nodes,
    );
    println!("wrote {}", cypher_path.display());
    println!("wrote {}", ref_path.display());

    ExitCode::SUCCESS
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("kg_gen: error: {msg}");
    ExitCode::FAILURE
}
