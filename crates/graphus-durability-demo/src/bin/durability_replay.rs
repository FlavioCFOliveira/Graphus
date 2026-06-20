//! `durability_replay` — the **one-command replay round-trip** for the durability example (rmp #277).
//!
//! The real Graphus engine has NO failing seed, so this binary plants a *synthetic* failure via the
//! existing #242 `FailurePredicate` path (see [`graphus_durability_demo::planted`]), captures it into a
//! [`ReplayArtifact`], writes it to disk, and replays it to the IDENTICAL failure — proving the
//! reproducer tooling round-trips, hermetically, without needing a real engine bug.
//!
//! This mirrors `graphus-dst vopr-repro --replay <file>` exactly, except the failure notion is the
//! reconstructed planted predicate (a pure function of the recorded config) instead of the engine's
//! real verdict (which passes on the healthy engine). The artifact's hashes are the REAL run's canonical
//! trace/state hashes, so the byte-identity (determinism) gate is genuine.
//!
//! Usage:
//!
//! ```text
//! durability_replay --capture <FILE> [--seed <SEED>]   # plant a failure, write the reproducer
//! durability_replay --replay  <FILE>                   # reproduce it; assert IDENTICAL failure
//! ```
//!
//! Exit status is non-zero on a usage error, a capture/replay failure, or a non-faithful reproduction
//! (a hash mismatch or a vanished failure).
#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;

use graphus_dst::vopr_repro::write_artifact;
use graphus_dst::{ReplayArtifact, ReplayOutcome};
use graphus_durability_demo::planted;

enum Mode {
    Capture { path: String, seed: u64 },
    Replay { path: String },
}

fn parse_args() -> Result<Mode, String> {
    let mut capture: Option<String> = None;
    let mut replay: Option<String> = None;
    let mut seed = 7u64;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = |label: &str| -> Result<String, String> {
            it.next()
                .ok_or_else(|| format!("flag {label} needs a value"))
        };
        match arg.as_str() {
            "--capture" => capture = Some(val("--capture")?),
            "--replay" => replay = Some(val("--replay")?),
            "--seed" => {
                seed = val("--seed")?
                    .parse()
                    .map_err(|_| "--seed needs an integer")?
            }
            "-h" | "--help" => return Err(usage()),
            other => return Err(format!("unknown flag {other}\n\n{}", usage())),
        }
    }
    match (capture, replay) {
        (Some(_), Some(_)) => Err("pass exactly one of --capture / --replay".to_owned()),
        (Some(path), None) => Ok(Mode::Capture { path, seed }),
        (None, Some(path)) => Ok(Mode::Replay { path }),
        (None, None) => Err(format!(
            "pass --capture <FILE> or --replay <FILE>\n\n{}",
            usage()
        )),
    }
}

fn usage() -> String {
    "durability_replay — plant a synthetic failure + prove the one-command replay round-trip\n\n\
     USAGE:\n    \
     durability_replay --capture <FILE> [--seed SEED]   plant a failure and write the reproducer\n    \
     durability_replay --replay  <FILE>                 reproduce it and assert an IDENTICAL failure\n\n\
     The real engine has no failing seed, so the failure is SYNTHETIC (the #242 FailurePredicate path).\n"
        .to_owned()
}

fn do_capture(path: &str, seed: u64) -> ExitCode {
    let Some(artifact) = planted::capture(seed) else {
        eprintln!(
            "error: the planted predicate did not fire for seed {seed} (need clients>=3 && ops>=10)"
        );
        return ExitCode::FAILURE;
    };
    if let Err(e) = write_artifact(Path::new(path), &artifact) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    println!(
        "CAPTURED planted reproducer -> {path}\n  mode={} seed={} clients={} ops={}\n  \
         expected_trace_hash={:016x} expected_state_hash={:016x}\n  summary: {}",
        artifact.mode.name(),
        artifact.config.seed,
        artifact.config.clients,
        artifact.config.ops_per_client,
        artifact.expected_trace_hash,
        artifact.expected_state_hash,
        artifact.failure_summary,
    );
    println!(
        "\nreplay it with:\n  cargo run -p graphus-durability-demo --bin durability_replay -- --replay {path}"
    );
    ExitCode::SUCCESS
}

fn do_replay(path: &str) -> ExitCode {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let artifact = match ReplayArtifact::from_json(&raw) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    if !planted::is_planted(&artifact) {
        eprintln!(
            "error: {path} is not a planted reproducer (no planted tag). Use \
             `graphus-dst vopr-repro --replay` for engine-verdict artifacts."
        );
        return ExitCode::FAILURE;
    }

    match planted::replay(&artifact) {
        ReplayOutcome::Reproduced {
            trace_hash,
            state_hash,
            summary,
        } => {
            println!(
                "REPRODUCED (identical) trace_hash={trace_hash:016x} state_hash={state_hash:016x}\n  \
                 {summary}"
            );
            println!(
                "\nThe replay re-ran the recorded config and matched BOTH recorded hashes byte-for-byte \
                 (determinism), and the planted failure fired again — an IDENTICAL reproduction."
            );
            ExitCode::SUCCESS
        }
        ReplayOutcome::HashMismatch { expected, actual } => {
            eprintln!(
                "HASH MISMATCH expected=({:016x},{:016x}) actual=({:016x},{:016x}) — the run is no \
                 longer a pure function of its config (a determinism regression)",
                expected.0, expected.1, actual.0, actual.1
            );
            ExitCode::FAILURE
        }
        ReplayOutcome::NoLongerFails { hashes } => {
            eprintln!(
                "NO LONGER FAILS hashes=({:016x},{:016x}) — the planted predicate stopped firing",
                hashes.0, hashes.1
            );
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    match parse_args() {
        Ok(Mode::Capture { path, seed }) => do_capture(&path, seed),
        Ok(Mode::Replay { path }) => do_replay(&path),
        Err(msg) => {
            if msg.starts_with("durability_replay —") {
                println!("{msg}");
                ExitCode::SUCCESS
            } else {
                eprintln!("error: {msg}");
                ExitCode::FAILURE
            }
        }
    }
}
