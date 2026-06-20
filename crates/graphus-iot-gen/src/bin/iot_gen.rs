//! `iot_gen` — the deterministic time-series IoT churn-stream generator binary for
//! `examples/iot-timeseries`.
//!
//! Writes one artifact into `--out-dir` for the chosen `--profile` (with an optional `--window`
//! override):
//! - `stream.cypher` — the schema + sensor-fleet bootstrap, then every tick's INSERT (new readings)
//!   and DELETE (aged-out readings), one statement per line, `;`-terminated.
//!
//! Output is a pure function of the resolved [`GenConfig`] (each profile pins its own seed), so
//! re-running yields a byte-identical file — the determinism the example's steady-state +
//! reclamation claims are pinned to. Hermetic: serde only, no engine, no network, CI-runnable.
//!
//! Usage:
//!   cargo run -p graphus-iot-gen --bin iot_gen -- --profile fast  --out-dir <dir>
//!   cargo run -p graphus-iot-gen --bin iot_gen -- --profile large --out-dir <dir>
//!   cargo run -p graphus-iot-gen --bin iot_gen -- --profile fast  --window 500 --out-dir <dir>

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_iot_gen::{GenConfig, Generator};

fn main() -> ExitCode {
    let mut profile = String::from("fast");
    let mut out_dir = PathBuf::from(".");
    let mut window_override: Option<u64> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => match args.next() {
                Some(v) => profile = v,
                None => return fail("--profile requires a value (fast|large)"),
            },
            "--out-dir" => match args.next() {
                Some(v) => out_dir = PathBuf::from(v),
                None => return fail("--out-dir requires a value"),
            },
            "--window" => match args.next().map(|v| v.parse::<u64>()) {
                Some(Ok(w)) if w > 0 => window_override = Some(w),
                _ => return fail("--window requires a positive integer (number of readings)"),
            },
            "-h" | "--help" => {
                eprintln!(
                    "usage: iot_gen --profile <fast|large> [--window <readings>] --out-dir <dir>\n\
                     writes stream.cypher (schema + per-tick INSERT/DELETE churn)"
                );
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unexpected argument '{other}'")),
        }
    }

    let mut cfg: GenConfig = GenConfig::from_profile(&profile);
    if let Some(w) = window_override {
        cfg.window = w;
    }
    let generator = Generator::new(cfg.clone());

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        return fail(&format!("cannot create out-dir {}: {e}", out_dir.display()));
    }
    let stream_path = out_dir.join("stream.cypher");
    if let Err(e) = std::fs::write(&stream_path, generator.emit_all()) {
        return fail(&format!("cannot write {}: {e}", stream_path.display()));
    }

    println!("{}", generator.summary_line());
    println!("wrote {}", stream_path.display());
    ExitCode::SUCCESS
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("iot_gen: error: {msg}");
    ExitCode::FAILURE
}
