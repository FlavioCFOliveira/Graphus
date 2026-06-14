//! `graphus-dst` binary — the thin CLI over the deterministic simulation harness
//! ([`graphus_dst`]).
//!
//! Runs seeded crash/fault scenarios against the Graphus storage/WAL/txn engine and prints a
//! deterministic summary. A non-zero exit status signals at least one failing seed, which the
//! summary lists for one-line reproduction (`--seed <N>`).
#![forbid(unsafe_code)]

use std::process::ExitCode;

use graphus_dst::{cli, vopr};

fn main() -> ExitCode {
    // The `vopr` subcommand drives the wire-level VOPR simulator core (rmp #162); everything else is
    // the storage/WAL/txn crash-fault harness. Detect it before the harness arg parser.
    let mut raw = std::env::args().skip(1).peekable();
    if raw.peek().map(String::as_str) == Some("vopr") {
        let (summary, failures) = vopr::run_cli(raw.skip(1));
        print!("{summary}");
        return if failures == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    // Skip the program name; parse the rest.
    let cfg = match cli::parse_args(std::env::args().skip(1)) {
        Ok(cfg) => cfg,
        Err(e) => {
            // `--help` is reported through the same channel; print to stdout for help, stderr for a
            // genuine parse error. Both carry the usage string, so distinguish by content.
            let msg = e.to_string();
            if msg.starts_with("graphus-dst —") {
                println!("{msg}");
                return ExitCode::SUCCESS;
            }
            eprintln!("error: {msg}");
            return ExitCode::FAILURE;
        }
    };

    let (summary, failures) = cli::run(cfg);
    print!("{summary}");

    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
