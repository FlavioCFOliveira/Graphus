//! `gds_gen` — the deterministic influence-network generator binary for `examples/gds-analytics`.
//!
//! Writes two artifacts into `--out-dir` for the chosen `--profile`:
//! - `graph.cypher` — the schema DDL + `:Author`/`:Ref` node and `:CITES`/`:LINKS` edge CREATE
//!   statements (one per line, `;`-terminated),
//! - `reference.json` — the analytically-known reference subgraph + its known algorithm outputs the
//!   workload asserts against.
//!
//! Output is a pure function of `(profile)` (each profile pins its own seed), so re-running yields
//! byte-identical files. Hermetic: serde only, no engine, no network.
//!
//! Usage:
//! ```text
//! cargo run -p graphus-gds-gen --bin gds_gen -- --profile fast  --out-dir <dir>
//! cargo run -p graphus-gds-gen --bin gds_gen -- --profile large --out-dir <dir>
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_gds_gen::{Profile, generate};

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
                    "usage: gds_gen --profile <fast|large> --out-dir <dir>\n\
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
    println!("wrote {}", cypher_path.display());
    println!("wrote {}", ref_path.display());

    ExitCode::SUCCESS
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("gds_gen: error: {msg}");
    ExitCode::FAILURE
}
