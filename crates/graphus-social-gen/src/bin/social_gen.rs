//! `social_gen` — the deterministic social-network graph generator binary for
//! `examples/social-network`.
//!
//! Writes one artifact into `--out-dir` for the chosen `--profile`:
//! - `graph.cypher` — the `USER` + `ARTICLE` nodes, then the `FRIEND` (undirected multigraph) and
//!   `LIKE` edges, all batched and `;`-terminated.
//!
//! Output is a pure function of the resolved [`GenConfig`] (each profile pins its own seed), so
//! re-running yields a byte-identical file — the determinism the example's performance claims are
//! pinned to. Hermetic: serde only, no engine, no network, CI-runnable.
//!
//! Usage:
//!   cargo run -p graphus-social-gen --bin social_gen -- --profile fast  --out-dir <dir>
//!   cargo run -p graphus-social-gen --bin social_gen -- --profile large --out-dir <dir>
//!   cargo run -p graphus-social-gen --bin social_gen -- --profile huge  --out-dir <dir>

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_social_gen::{GenConfig, Generator};

fn main() -> ExitCode {
    let mut profile = String::from("fast");
    let mut out_dir = PathBuf::from(".");

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => match args.next() {
                Some(v) => profile = v,
                None => return fail("--profile requires a value (fast|large|huge)"),
            },
            "--out-dir" => match args.next() {
                Some(v) => out_dir = PathBuf::from(v),
                None => return fail("--out-dir requires a value"),
            },
            "-h" | "--help" => {
                eprintln!(
                    "usage: social_gen --profile <fast|large|huge> --out-dir <dir>\n\
                     writes graph.cypher (USER + ARTICLE nodes, then FRIEND + LIKE edges)"
                );
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unexpected argument '{other}'")),
        }
    }

    let cfg: GenConfig = match GenConfig::profile(&profile) {
        Some(c) => c,
        None => {
            return fail(&format!(
                "unknown profile '{profile}' (expected fast|large|huge)"
            ));
        }
    };
    let generator = Generator::new(cfg);

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        return fail(&format!("cannot create out-dir {}: {e}", out_dir.display()));
    }
    let graph_path = out_dir.join("graph.cypher");
    if let Err(e) = std::fs::write(&graph_path, generator.emit_all()) {
        return fail(&format!("cannot write {}: {e}", graph_path.display()));
    }

    println!("{}", generator.summary_line());
    println!("wrote {}", graph_path.display());
    ExitCode::SUCCESS
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("social_gen: error: {msg}");
    ExitCode::FAILURE
}
