//! `gen` — the deterministic fraud-graph generator binary for `examples/fraud-oltp`.
//!
//! Writes two artifacts into `--out-dir` for the chosen `--profile`:
//! - `graph.cypher` — the schema DDL + node/edge CREATE statements (one per line, `;`-terminated),
//! - `ground_truth.json` — the enumerable planted-fraud set the detector asserts against.
//!
//! Output is a pure function of `(profile)` (each profile pins its own seed), so re-running yields
//! byte-identical files. Hermetic: serde only, no engine, no network.
//!
//! Usage:
//!   cargo run -p graphus-fraud-gen --bin gen -- --profile fast  --out-dir <dir>
//!   cargo run -p graphus-fraud-gen --bin gen -- --profile large --out-dir <dir>

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_fraud_gen::{Profile, generate};

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
                    "usage: gen --profile <fast|large> --out-dir <dir>\n\
                     writes graph.cypher + ground_truth.json"
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
    let gt_path = out_dir.join("ground_truth.json");

    let gt_json = match dataset.ground_truth_json() {
        Ok(j) => j,
        Err(e) => return fail(&format!("ground-truth serialization failed: {e}")),
    };

    if let Err(e) = std::fs::write(&cypher_path, dataset.to_cypher()) {
        return fail(&format!("cannot write {}: {e}", cypher_path.display()));
    }
    if let Err(e) = std::fs::write(&gt_path, gt_json) {
        return fail(&format!("cannot write {}: {e}", gt_path.display()));
    }

    println!(
        "generated profile={} seed={:#018x} accounts={} customers={} transfers={} \
         rings={} mules={} fraud_accounts={}",
        profile.name(),
        cfg.seed,
        dataset.accounts.len(),
        dataset.customers.len(),
        dataset.transfers.len(),
        dataset.ground_truth.rings.len(),
        dataset.ground_truth.mules.len(),
        dataset.ground_truth.fraud_accounts.len(),
    );
    println!("wrote {}", cypher_path.display());
    println!("wrote {}", gt_path.display());

    ExitCode::SUCCESS
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("gen: error: {msg}");
    ExitCode::FAILURE
}
