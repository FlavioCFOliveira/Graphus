//! `reco_gen` — the deterministic product-recommendation graph generator binary for
//! `examples/product-recommendation`.
//!
//! Writes the `neo4j-admin import`-flavoured CSV file set for the chosen `--profile` into `--out-dir`:
//! `users.csv`, `products.csv` (node files, `:ID`/`:LABEL` header), `friends.csv`, `purchased.csv`
//! (relationship files, `:START_ID`/`:END_ID`/`:TYPE` header) — the same file set the production
//! `graphus-bulk`/network bulk-import path (`specification/08-network-bulk-import.md`) consumes. Each
//! file is streamed straight to disk one chunk at a time (peak memory is one CSV chunk, not the whole
//! file), so this scales to the `huge` profile's hundreds of millions of relationship rows.
//!
//! Output is a pure function of the resolved [`GenConfig`] (each profile pins its own seed), so
//! re-running with the same flags yields byte-identical files — the determinism the example's
//! performance claims are pinned to. Hermetic: serde only, no engine, no network, CI-runnable.
//!
//! A one-line `key=value` summary is printed to stdout so a shell `run.sh` can parse the realised
//! dataset shape (node/edge counts, degree statistics).
//!
//! Usage:
//!   cargo run -p graphus-reco-gen --bin reco_gen -- --profile fast  --out-dir <dir>
//!   cargo run -p graphus-reco-gen --bin reco_gen -- --profile large --out-dir <dir>
//!   cargo run -p graphus-reco-gen --bin reco_gen -- --profile huge  --out-dir <dir>

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use graphus_reco_gen::{GenConfig, Generator};

fn main() -> ExitCode {
    let mut profile = String::from("fast");
    let mut out_dir = PathBuf::from(".");

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => match args.next() {
                Some(v) => profile = v,
                None => return fail("--profile requires a value (tiny|fast|large|huge)"),
            },
            "--out-dir" => match args.next() {
                Some(v) => out_dir = PathBuf::from(v),
                None => return fail("--out-dir requires a value"),
            },
            "-h" | "--help" => {
                eprintln!(
                    "usage: reco_gen --profile <tiny|fast|large|huge> --out-dir <dir>\n\
                     Writes users.csv, products.csv, friends.csv, purchased.csv (the neo4j-admin\n\
                     import / network bulk-import CSV shape) for the resolved profile, and prints a\n\
                     one-line key=value summary of the realised graph shape to stdout."
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
                "unknown profile '{profile}' (expected tiny|fast|large|huge)"
            ));
        }
    };

    let generator = Generator::new(cfg);

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        return fail(&format!("cannot create out-dir {}: {e}", out_dir.display()));
    }

    let written = [
        stream_to_file(&out_dir, "users.csv", |sink| {
            generator.stream_user_csv(sink)
        }),
        stream_to_file(&out_dir, "products.csv", |sink| {
            generator.stream_product_csv(sink)
        }),
        stream_to_file(&out_dir, "friends.csv", |sink| {
            generator.stream_friend_csv(sink);
        }),
        stream_to_file(&out_dir, "purchased.csv", |sink| {
            generator.stream_purchased_csv(sink);
        }),
    ];
    for w in &written {
        if let Err(e) = w {
            return fail(e);
        }
    }

    println!("{}", generator.summary_line());
    for name in ["users.csv", "products.csv", "friends.csv", "purchased.csv"] {
        println!("wrote {}", out_dir.join(name).display());
    }

    ExitCode::SUCCESS
}

/// Streams one CSV artifact to `dir/name` via `stream`, one chunk at a time (never materializing the
/// whole file in memory), so peak memory is a single CSV chunk regardless of the profile size.
fn stream_to_file(
    dir: &std::path::Path,
    name: &str,
    stream: impl FnOnce(&mut dyn FnMut(Vec<u8>)),
) -> Result<(), String> {
    let path = dir.join(name);
    let file = std::fs::File::create(&path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    let mut writer = std::io::BufWriter::new(file);
    let mut err: Option<std::io::Error> = None;
    {
        let mut sink = |chunk: Vec<u8>| {
            if err.is_some() {
                return;
            }
            if let Err(e) = writer.write_all(&chunk) {
                err = Some(e);
            }
        };
        stream(&mut sink);
    }
    if let Some(e) = err {
        return Err(format!("cannot write {}: {e}", path.display()));
    }
    writer
        .flush()
        .map_err(|e| format!("cannot flush {}: {e}", path.display()))
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("reco_gen: error: {msg}");
    ExitCode::FAILURE
}
