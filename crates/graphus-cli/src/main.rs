//! `graphus-cli` — an interactive Cypher shell and admin client for Graphus, over Bolt/UDS.
//!
//! Connects to a running Graphus server over a Unix domain socket (the default, kernel-protected
//! transport — `04 §8.4`), authenticates with the Bolt `basic` scheme, and then either runs a single
//! statement (`-c`) and exits or drops into an interactive REPL.
//!
//! ```text
//! graphus-cli --uds /run/graphus.sock --user alice            # interactive (prompts for password)
//! graphus-cli -c "MATCH (n) RETURN count(n)"                  # one-shot, non-interactive
//! GRAPHUS_PASSWORD=secret graphus-cli --user alice -c "RETURN 1"
//! ```
//!
//! The wire format is **not** reimplemented here: the client ([`client::BoltClient`]) drives the
//! symmetric Bolt 5.4 codec from `graphus-bolt` over the socket. See that module and [`repl`] for the
//! design.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use graphus_cli::client::{BoltClient, ClientError};
use graphus_cli::render::render_table;
use graphus_cli::repl::Repl;

/// The conventional default UDS path: Graphus's `ServerConfig` default `uds_path` is `graphus.sock`
/// (relative to the server's working directory). The CLI mirrors that default and lets `--uds`
/// override it for a server bound to an absolute path.
const DEFAULT_UDS_PATH: &str = "graphus.sock";

/// The environment variable consulted for the password when `--password` is omitted.
const PASSWORD_ENV: &str = "GRAPHUS_PASSWORD";

/// Interactive Cypher shell and admin client for the Graphus graph database (over Bolt/UDS).
#[derive(Debug, Parser)]
#[command(name = "graphus-cli", version, about)]
struct Args {
    /// Path to the server's Unix domain socket.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_UDS_PATH)]
    uds: PathBuf,

    /// The user to authenticate as (Bolt `basic` scheme).
    #[arg(long, short = 'u', value_name = "USER", default_value = "neo4j")]
    user: String,

    /// The password. If omitted, read from $GRAPHUS_PASSWORD, else prompted (never echoed).
    #[arg(long, short = 'p', value_name = "PASSWORD")]
    password: Option<String>,

    /// Run a single statement non-interactively, print its result, and exit.
    #[arg(short = 'c', long = "command", value_name = "CYPHER")]
    command: Option<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // One uniform, non-panicking error channel. Credentials never appear here (the client
            // never embeds them in an error).
            eprintln!("graphus-cli: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Resolves credentials, connects + logs in, then runs `-c` once or starts the REPL.
fn run(args: Args) -> Result<(), String> {
    let password = resolve_password(args.password)?;

    let mut client = BoltClient::connect_uds(&args.uds).map_err(|e| match e {
        ClientError::Io(io) => format!("cannot connect to {}: {io}", args.uds.display()),
        other => other.to_string(),
    })?;
    client
        .login(&args.user, &password)
        .map_err(|e| format!("login failed: {e}"))?;
    // The password is dropped here; it lives only as long as the single LOGON send needed it.
    drop(password);

    match args.command {
        // One-shot: run the statement, render it, send GOODBYE, exit with a status reflecting success.
        Some(statement) => run_once(client, &statement),
        // Interactive REPL.
        None => {
            let mut repl = Repl::new(client, args.uds);
            repl.run_interactive().map_err(|e| e.to_string())
        }
    }
}

/// Runs a single statement and renders it to stdout, then closes the session.
///
/// A query *failure* (syntax/runtime) is reported to stderr and surfaced as an `Err`, so `-c` has a
/// non-zero exit status that scripts and the integration test can assert on. A successful query
/// (even with zero rows) exits `Ok`.
fn run_once(
    mut client: BoltClient<std::os::unix::net::UnixStream>,
    statement: &str,
) -> Result<(), String> {
    let outcome = client.run(statement);
    let _ = client.goodbye();
    match outcome {
        Ok(result) => {
            let mut stdout = std::io::stdout().lock();
            // `render_table` already ends with a newline; write it directly.
            write!(stdout, "{}", render_table(&result)).map_err(|e| e.to_string())?;
            Ok(())
        }
        Err(ClientError::Failure(f)) => Err(format!("{}: {}", f.code, f.message)),
        Err(e) => Err(e.to_string()),
    }
}

/// Resolves the password from `--password`, else `$GRAPHUS_PASSWORD`, else a no-echo prompt.
///
/// The prompt is written to stderr (so `-c` output piped from stdout stays clean) and the typed
/// characters are never echoed (`rpassword`).
fn resolve_password(flag: Option<String>) -> Result<String, String> {
    if let Some(pw) = flag {
        return Ok(pw);
    }
    if let Ok(pw) = std::env::var(PASSWORD_ENV) {
        return Ok(pw);
    }
    rpassword::prompt_password("Password: ").map_err(|e| format!("could not read password: {e}"))
}

// A tiny compile-time smoke test that the binary's pieces are wired (`Action` is part of the public
// REPL surface the integration test drives). Keeps `cargo test -p graphus-cli` honest even before
// the integration test boots a server.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_parse_with_defaults() {
        let args = Args::try_parse_from(["graphus-cli"]).expect("defaults parse");
        assert_eq!(args.uds, PathBuf::from(DEFAULT_UDS_PATH));
        assert_eq!(args.user, "neo4j");
        assert!(args.password.is_none());
        assert!(args.command.is_none());
    }

    #[test]
    fn args_parse_command_and_overrides() {
        let args = Args::try_parse_from([
            "graphus-cli",
            "--uds",
            "/tmp/g.sock",
            "-u",
            "alice",
            "-c",
            "RETURN 1",
        ])
        .expect("explicit args parse");
        assert_eq!(args.uds, PathBuf::from("/tmp/g.sock"));
        assert_eq!(args.user, "alice");
        assert_eq!(args.command.as_deref(), Some("RETURN 1"));
    }

    #[test]
    fn password_flag_takes_precedence_over_env() {
        // The flag wins even if the env var is set; this test sets neither beyond the flag.
        assert_eq!(
            resolve_password(Some("flagpw".to_owned())).unwrap(),
            "flagpw"
        );
    }

    #[test]
    fn action_variants_exist() {
        // The REPL's decision type is part of the surface the integration test exercises.
        use graphus_cli::repl::Action;
        assert_ne!(Action::Continue, Action::Quit);
    }
}
