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
//! graphus-cli --user alice --password-file /run/secrets/pw -c "RETURN 1"   # secure non-interactive
//! ```
//!
//! Passwords are resolved in order: `--password-file` / `$GRAPHUS_PASSWORD` / interactive no-echo
//! prompt. The inline `--password` flag is still accepted for compatibility but is **discouraged**
//! (SEC-185): a process argument is visible to other local users (`ps`, `/proc/<pid>/cmdline`) and is
//! saved in shell history, so using it prints a warning to stderr.
//!
//! The wire format is **not** reimplemented here: the client ([`client::BoltClient`]) drives the
//! symmetric Bolt 5.4 codec from `graphus-bolt` over the socket. See that module and [`repl`] for the
//! design.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

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

    /// **Discouraged:** the password passed inline. A process argument is visible to every local
    /// user via `ps`/`/proc/<pid>/cmdline` and is saved in shell history (SEC-185, CWE-214/522).
    /// Prefer `--password-file`, `$GRAPHUS_PASSWORD`, or the interactive no-echo prompt. Using this
    /// flag prints a warning to stderr.
    #[arg(long, short = 'p', value_name = "PASSWORD")]
    password: Option<String>,

    /// Read the password from the first line of this file (secure non-interactive alternative to
    /// `--password`: the secret never appears in the process arguments). Mutually exclusive with
    /// `--password`.
    #[arg(long, value_name = "PATH", conflicts_with = "password")]
    password_file: Option<PathBuf>,

    /// Run a single statement non-interactively, print its result, and exit.
    #[arg(short = 'c', long = "command", value_name = "CYPHER")]
    command: Option<String>,

    /// An operator subcommand (backup / restore). When omitted, the CLI runs `-c` once or starts
    /// the interactive REPL (the default behaviour).
    #[command(subcommand)]
    subcommand: Option<Command>,
}

/// Operator subcommands (`rmp` task #149). Each builds the corresponding administrative statement
/// (`BACKUP DATABASE …` / `RESTORE DATABASE …`) and runs it over the authenticated Bolt session —
/// the server gates both behind the global `Admin` privilege, so an unauthorized user is refused.
#[derive(Debug, Subcommand)]
enum Command {
    /// Take an online, PITR-capable backup of a database and write it to a file.
    Backup {
        /// The database to back up.
        #[arg(long, value_name = "NAME", default_value = "graphus")]
        database: String,
        /// The destination file path for the backup artifact (on the **server's** filesystem).
        #[arg(long, value_name = "PATH")]
        to: String,
    },
    /// Restore a database from a backup file, optionally to a point in time. The database must be
    /// stopped first (`STOP DATABASE <name>`); the default database cannot be restored in place.
    Restore {
        /// The database to restore.
        #[arg(long, value_name = "NAME")]
        database: String,
        /// The source backup-artifact file path (on the **server's** filesystem).
        #[arg(long, value_name = "PATH")]
        from: String,
        /// Restore to a specific WAL LSN (point-in-time). Mutually exclusive with `--at-timestamp`.
        #[arg(long, value_name = "LSN", conflicts_with = "at_timestamp")]
        at_lsn: Option<u64>,
        /// Restore to a specific commit timestamp (point-in-time). Mutually exclusive with `--at-lsn`.
        #[arg(long, value_name = "TIMESTAMP")]
        at_timestamp: Option<u64>,
    },
}

impl Command {
    /// Renders the subcommand as the administrative statement the server recognises. Names/paths are
    /// backtick/quote-wrapped so unusual (but valid) names and paths are passed through verbatim.
    fn to_statement(&self) -> String {
        match self {
            Self::Backup { database, to } => {
                format!("BACKUP DATABASE `{database}` TO '{}'", escape_single(to))
            }
            Self::Restore {
                database,
                from,
                at_lsn,
                at_timestamp,
            } => {
                let at = match (at_lsn, at_timestamp) {
                    (Some(lsn), _) => format!(" AT LSN {lsn}"),
                    (None, Some(ts)) => format!(" AT TIMESTAMP {ts}"),
                    (None, None) => String::new(),
                };
                format!(
                    "RESTORE DATABASE `{database}` FROM '{}'{at}",
                    escape_single(from)
                )
            }
        }
    }
}

/// Escapes a single-quoted string literal for the admin grammar: `\` and `'` are backslash-escaped
/// (the admin lexer unescapes `\\` and `\'`), so a path containing a quote is passed through safely.
fn escape_single(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
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
    let password = resolve_password(args.password, args.password_file)?;

    let mut client = BoltClient::connect_uds(&args.uds).map_err(|e| match e {
        ClientError::Io(io) => format!("cannot connect to {}: {io}", args.uds.display()),
        other => other.to_string(),
    })?;
    client
        .login(&args.user, &password)
        .map_err(|e| format!("login failed: {e}"))?;
    // The password is dropped here; it lives only as long as the single LOGON send needed it.
    drop(password);

    // An operator subcommand (backup/restore) takes precedence: build its admin statement and run it
    // once. Otherwise fall back to `-c` (one-shot) or the interactive REPL.
    if let Some(subcommand) = args.subcommand {
        return run_once(client, &subcommand.to_statement());
    }

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

/// Where a password should be sourced from, in precedence order. Computed by [`password_source`] (a
/// pure, unit-testable function) and then materialised by [`resolve_password`].
#[derive(Debug, PartialEq, Eq)]
enum PasswordSource {
    /// The inline `--password` flag. **Discouraged** (SEC-185): visible in `ps`/`/proc`; a warning is
    /// emitted when this is used.
    Arg(String),
    /// The first line of the `--password-file`.
    File(PathBuf),
    /// The `$GRAPHUS_PASSWORD` environment variable.
    Env,
    /// An interactive no-echo prompt.
    Prompt,
}

/// Decides where the password comes from, given the resolved flags. Pure (no I/O), so the precedence
/// and the SEC-185 argv-discouragement are unit-testable. `--password` and `--password-file` are
/// mutually exclusive at the clap level, so at most one is `Some`.
fn password_source(flag: Option<String>, file: Option<PathBuf>) -> PasswordSource {
    if let Some(pw) = flag {
        return PasswordSource::Arg(pw);
    }
    if let Some(path) = file {
        return PasswordSource::File(path);
    }
    if std::env::var_os(PASSWORD_ENV).is_some() {
        return PasswordSource::Env;
    }
    PasswordSource::Prompt
}

/// Resolves the password from (in order) `--password`, `--password-file`, `$GRAPHUS_PASSWORD`, else a
/// no-echo prompt.
///
/// The prompt is written to stderr (so `-c` output piped from stdout stays clean) and the typed
/// characters are never echoed (`rpassword`).
///
/// # Security (SEC-185, CWE-214/522)
/// `--password` puts the secret in the process arguments — visible to any local user via `ps` /
/// `/proc/<pid>/cmdline` and saved in shell history. When it is used, a warning is printed to stderr
/// pointing at the safer alternatives. `--password-file` keeps the secret off the argument list; the
/// `$GRAPHUS_PASSWORD` env var is less exposed than argv but still readable via `/proc/<pid>/environ`,
/// so the interactive prompt remains the most protected path.
fn resolve_password(flag: Option<String>, file: Option<PathBuf>) -> Result<String, String> {
    match password_source(flag, file) {
        PasswordSource::Arg(pw) => {
            eprintln!(
                "graphus-cli: warning: passing --password on the command line is insecure (visible \
                 via `ps` and /proc, and saved in shell history). Prefer --password-file, \
                 $GRAPHUS_PASSWORD, or the interactive prompt."
            );
            Ok(pw)
        }
        PasswordSource::File(path) => read_password_file(&path),
        PasswordSource::Env => {
            std::env::var(PASSWORD_ENV).map_err(|e| format!("could not read ${PASSWORD_ENV}: {e}"))
        }
        PasswordSource::Prompt => rpassword::prompt_password("Password: ")
            .map_err(|e| format!("could not read password: {e}")),
    }
}

/// Reads a password from the first line of `path`, stripping a single trailing `\n`/`\r\n`. The rest
/// of the file is ignored so a trailing newline (as most editors add) does not become part of the
/// secret.
fn read_password_file(path: &std::path::Path) -> Result<String, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read password file {}: {e}", path.display()))?;
    let first = contents.lines().next().unwrap_or("");
    Ok(first.to_owned())
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
    fn password_flag_takes_precedence() {
        // The inline flag still wins (compat), but its source is `Arg` so a warning is emitted by
        // `resolve_password`.
        assert_eq!(
            resolve_password(Some("flagpw".to_owned()), None).unwrap(),
            "flagpw"
        );
    }

    // Regression: SEC-185 — the password must not be silently sourced from argv. `--password` is
    // still accepted for compatibility, but it resolves to the `Arg` source, which is exactly the
    // branch `resolve_password` warns about; the safer sources (`--password-file`, env, prompt) take
    // over the moment the flag is absent. This pins the precedence so a future refactor cannot make
    // argv the default path again.
    #[test]
    fn sec185_password_source_precedence_keeps_argv_explicit() {
        // The inline flag, when present, is the (discouraged, warned-about) `Arg` source — never a
        // silent default.
        assert_eq!(
            password_source(Some("pw".to_owned()), None),
            PasswordSource::Arg("pw".to_owned())
        );
        // With no flag, a `--password-file` is preferred (secret off the argument list).
        assert_eq!(
            password_source(None, Some(PathBuf::from("/run/secrets/pw"))),
            PasswordSource::File(PathBuf::from("/run/secrets/pw"))
        );
        // With neither flag nor file and no env var set, the interactive prompt is the fallback — the
        // password is never taken from argv implicitly.
        // SAFETY of test: the env var is process-global; ensure it is unset for this assertion.
        // (No other test in this module sets it.)
        unsafe {
            std::env::remove_var(PASSWORD_ENV);
        }
        assert_eq!(password_source(None, None), PasswordSource::Prompt);
    }

    #[test]
    fn password_file_is_read_and_trailing_newline_stripped() {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("graphus-cli-pwfile-{nanos}-{}", std::process::id()));
        std::fs::write(&path, "s3cr3t\n").unwrap();

        let pw = resolve_password(None, Some(path.clone())).unwrap();
        assert_eq!(
            pw, "s3cr3t",
            "the trailing newline must not be part of the secret"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn password_and_password_file_are_mutually_exclusive() {
        let parsed = Args::try_parse_from([
            "graphus-cli",
            "--password",
            "x",
            "--password-file",
            "/tmp/pw",
        ]);
        assert!(
            parsed.is_err(),
            "--password and --password-file must conflict at the clap level"
        );
    }

    #[test]
    fn backup_subcommand_builds_statement() {
        let args = Args::try_parse_from([
            "graphus-cli",
            "backup",
            "--database",
            "sales",
            "--to",
            "/backups/sales.gbk",
        ])
        .expect("backup args parse");
        let sub = args.subcommand.expect("subcommand present");
        assert_eq!(
            sub.to_statement(),
            "BACKUP DATABASE `sales` TO '/backups/sales.gbk'"
        );
    }

    #[test]
    fn restore_subcommand_builds_statement_with_pitr() {
        // Plain restore (whole chain).
        let args = Args::try_parse_from([
            "graphus-cli",
            "restore",
            "--database",
            "sales",
            "--from",
            "/b",
        ])
        .expect("restore args parse");
        assert_eq!(
            args.subcommand.unwrap().to_statement(),
            "RESTORE DATABASE `sales` FROM '/b'"
        );
        // PITR by LSN.
        let args = Args::try_parse_from([
            "graphus-cli",
            "restore",
            "--database",
            "sales",
            "--from",
            "/b",
            "--at-lsn",
            "4096",
        ])
        .expect("restore-lsn args parse");
        assert_eq!(
            args.subcommand.unwrap().to_statement(),
            "RESTORE DATABASE `sales` FROM '/b' AT LSN 4096"
        );
        // PITR by timestamp.
        let args = Args::try_parse_from([
            "graphus-cli",
            "restore",
            "--database",
            "sales",
            "--from",
            "/b",
            "--at-timestamp",
            "1700000000",
        ])
        .expect("restore-ts args parse");
        assert_eq!(
            args.subcommand.unwrap().to_statement(),
            "RESTORE DATABASE `sales` FROM '/b' AT TIMESTAMP 1700000000"
        );
    }

    #[test]
    fn restore_lsn_and_timestamp_are_mutually_exclusive() {
        let err = Args::try_parse_from([
            "graphus-cli",
            "restore",
            "--database",
            "sales",
            "--from",
            "/b",
            "--at-lsn",
            "1",
            "--at-timestamp",
            "2",
        ]);
        assert!(err.is_err(), "--at-lsn and --at-timestamp must conflict");
    }

    #[test]
    fn escape_single_quotes_and_backslashes() {
        assert_eq!(escape_single("a'b"), "a\\'b");
        assert_eq!(escape_single("a\\b"), "a\\\\b");
        assert_eq!(escape_single("/plain/path"), "/plain/path");
    }

    #[test]
    fn action_variants_exist() {
        // The REPL's decision type is part of the surface the integration test exercises.
        use graphus_cli::repl::Action;
        assert_ne!(Action::Continue, Action::Quit);
    }
}
