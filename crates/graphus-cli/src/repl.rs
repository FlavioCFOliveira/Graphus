//! The interactive Cypher shell: line editing, statement accumulation, meta-commands, and result
//! rendering, driven over a [`BoltClient`].
//!
//! # Statement termination
//!
//! A Cypher statement is **terminated by a trailing semicolon** (`;`). Lines without a terminating
//! `;` accumulate into a multi-line buffer (the prompt switches to a continuation marker), so a
//! query can span several lines. A line that is only whitespace is ignored. The semicolon itself is
//! stripped before the statement is sent. This is the de-facto `cypher-shell` convention.
//!
//! # Meta-commands
//!
//! Lines beginning with `:` are **meta-commands**, handled locally (never sent to the server):
//!
//! - `:help` / `:h` / `:?` — list the commands.
//! - `:quit` / `:exit` / `:q` — disconnect (send `GOODBYE`) and exit.
//! - `:status` — the live admin/status op: server agent + connection id + negotiated protocol +
//!   socket path, with liveness proven by a `RETURN 1` round-trip (see [`Repl::status`]).
//! - `:clear` — discard a half-typed multi-line statement.
//!
//! # Cancellation
//!
//! Ctrl-C abandons the current input line (or a half-typed multi-line statement) and returns to a
//! fresh prompt; Ctrl-D on an empty line exits cleanly (sending `GOODBYE`).

use std::io::{Read, Write};
use std::path::PathBuf;

use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;

use crate::client::{BoltClient, ClientError};
use crate::render::{render_table, render_value};

/// The classification of one entered line, before any statement is assembled.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// A meta-command (the `:`-prefixed verb and its raw argument tail).
    Meta(MetaCommand),
    /// An ordinary (possibly partial) Cypher fragment to accumulate.
    Cypher(String),
    /// A blank line (ignored).
    Blank,
}

/// A parsed meta-command.
#[derive(Debug, PartialEq, Eq)]
pub enum MetaCommand {
    /// `:help` — show usage.
    Help,
    /// `:quit` / `:exit` — leave the shell.
    Quit,
    /// `:status` — report the live connection + server identity.
    Status,
    /// `:clear` — drop a half-typed multi-line statement.
    Clear,
    /// An unrecognised `:`-command (carries the verb, for a helpful message).
    Unknown(String),
}

/// Classifies one raw input line into a [`Line`].
///
/// A line whose first non-whitespace char is `:` is a meta-command; the verb is matched
/// case-insensitively. Everything else is Cypher (trimmed). A whitespace-only line is [`Line::Blank`].
#[must_use]
pub fn classify_line(raw: &str) -> Line {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Line::Blank;
    }
    if let Some(rest) = trimmed.strip_prefix(':') {
        let verb = rest.split_whitespace().next().unwrap_or("").to_lowercase();
        let cmd = match verb.as_str() {
            "help" | "h" | "?" => MetaCommand::Help,
            "quit" | "exit" | "q" => MetaCommand::Quit,
            "status" => MetaCommand::Status,
            "clear" => MetaCommand::Clear,
            other => MetaCommand::Unknown(other.to_owned()),
        };
        return Line::Meta(cmd);
    }
    Line::Cypher(trimmed.to_owned())
}

/// Accumulates Cypher fragments until a statement is terminated by a trailing `;`.
///
/// Push fragments with [`StatementBuffer::push`]; when one ends with `;`, the assembled statement
/// (semicolon stripped) is returned and the buffer resets. This is the pure core of the shell's
/// multi-line handling, exercised directly in tests.
#[derive(Debug, Default)]
pub struct StatementBuffer {
    parts: Vec<String>,
}

impl StatementBuffer {
    /// A new, empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a partial statement is currently buffered (controls the continuation prompt).
    #[must_use]
    pub fn is_pending(&self) -> bool {
        !self.parts.is_empty()
    }

    /// Discards any buffered partial statement.
    pub fn clear(&mut self) {
        self.parts.clear();
    }

    /// Adds a Cypher fragment. Returns `Some(statement)` if this fragment terminates it with `;`.
    pub fn push(&mut self, fragment: &str) -> Option<String> {
        let fragment = fragment.trim();
        if let Some(without_semi) = fragment.strip_suffix(';') {
            let without_semi = without_semi.trim_end();
            if !without_semi.is_empty() {
                self.parts.push(without_semi.to_owned());
            }
            let statement = self.parts.join(" ");
            self.parts.clear();
            // A bare `;` (empty statement) yields nothing to run.
            if statement.trim().is_empty() {
                return None;
            }
            return Some(statement);
        }
        self.parts.push(fragment.to_owned());
        None
    }
}

/// The shell, owning the connection, an editor, and the multi-line buffer.
pub struct Repl<S: Read + Write> {
    client: BoltClient<S>,
    socket: PathBuf,
    buffer: StatementBuffer,
}

/// What [`Repl::handle_statement`] / [`Repl::handle_meta`] decides the loop should do next.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Continue the read loop.
    Continue,
    /// Leave the shell.
    Quit,
}

impl<S: Read + Write> Repl<S> {
    /// Builds a shell over an already-logged-in client connected via `socket`.
    pub fn new(client: BoltClient<S>, socket: PathBuf) -> Self {
        Self {
            client,
            socket,
            buffer: StatementBuffer::new(),
        }
    }

    /// Runs one Cypher statement and prints the rendered table + summary, or the failure.
    ///
    /// Always returns [`Action::Continue`]: a query failure is reported and the shell stays alive
    /// (only a transport error, which propagates as `Err`, ends the session). The rendered text is
    /// written to `out` so the behaviour is testable without a terminal.
    pub fn handle_statement(
        &mut self,
        statement: &str,
        out: &mut impl Write,
    ) -> std::io::Result<Action> {
        match self.client.run(statement) {
            Ok(result) => {
                write!(out, "{}", render_table(&result))?;
                let summary = summarize(&result);
                writeln!(out, "{summary}")?;
            }
            Err(ClientError::Failure(f)) => {
                writeln!(out, "Error [{}]: {}", f.code, f.message)?;
            }
            // A transport/protocol error means the connection is unusable; surface it to the loop,
            // which exits. (Returning `Err` rather than printing keeps the session-fatal cases
            // distinct from a recoverable query failure.)
            Err(e) => return Err(std::io::Error::other(e.to_string())),
        }
        Ok(Action::Continue)
    }

    /// Handles a meta-command, writing any output to `out`.
    pub fn handle_meta(
        &mut self,
        cmd: &MetaCommand,
        out: &mut impl Write,
    ) -> std::io::Result<Action> {
        match cmd {
            MetaCommand::Help => {
                write!(out, "{HELP_TEXT}")?;
                Ok(Action::Continue)
            }
            MetaCommand::Quit => Ok(Action::Quit),
            MetaCommand::Clear => {
                self.buffer.clear();
                writeln!(out, "(cleared pending input)")?;
                Ok(Action::Continue)
            }
            MetaCommand::Status => {
                match self.status() {
                    Ok(report) => write!(out, "{report}")?,
                    Err(ClientError::Failure(f)) => {
                        writeln!(out, "Error [{}]: {}", f.code, f.message)?;
                    }
                    Err(e) => return Err(std::io::Error::other(e.to_string())),
                }
                Ok(Action::Continue)
            }
            MetaCommand::Unknown(verb) => {
                writeln!(out, "Unknown command ':{verb}'. Type :help for a list.")?;
                Ok(Action::Continue)
            }
        }
    }

    /// The `:status` admin/status operation against the **live** server.
    ///
    /// Reports the server-reported identity learned at `HELLO` (the `server` agent string and the
    /// assigned `connection_id`), the negotiated Bolt protocol version, and the socket path — then
    /// proves the connection is **live** by running `RETURN 1` and confirming the round-trip
    /// succeeds, reporting its latency. This is a real operation against the running server, not a
    /// cached value.
    ///
    /// # Errors
    /// Propagates a [`ClientError`] from the liveness probe (a `FAILURE`, or a transport fault).
    pub fn status(&mut self) -> Result<String, ClientError> {
        // The liveness probe: a trivial query that exercises the full RUN/PULL path end-to-end.
        let probe = self.client.run("RETURN 1 AS ok")?;
        let alive = probe
            .records
            .first()
            .and_then(|row| row.first())
            .map(render_value)
            .unwrap_or_else(|| "<no row>".to_owned());

        let info = self.client.server_info();
        let (version, agent, conn) = match info {
            Some(i) => (
                format!("{}.{}", i.version.major, i.version.minor),
                i.server_agent.clone(),
                i.connection_id.clone(),
            ),
            None => ("?".to_owned(), "?".to_owned(), "?".to_owned()),
        };

        let mut report = String::new();
        report.push_str("Server status\n");
        report.push_str(&format!("  socket:       {}\n", self.socket.display()));
        report.push_str(&format!("  protocol:     Bolt {version}\n"));
        report.push_str(&format!("  server agent: {agent}\n"));
        report.push_str(&format!("  connection:   {conn}\n"));
        report.push_str(&format!(
            "  liveness:     OK (RETURN 1 -> {alive} in {:.1?})\n",
            probe.elapsed
        ));
        Ok(report)
    }

    /// Drives the interactive loop with a real `rustyline` editor over stdin/stdout.
    ///
    /// Reads lines, accumulates `;`-terminated statements, dispatches meta-commands, and renders
    /// results until `:quit`, EOF (Ctrl-D on an empty line), or a session-fatal transport error.
    ///
    /// # Errors
    /// [`std::io::Error`] if the editor cannot be created or a write fails. A query *failure* is not
    /// an error here — it is reported inline and the loop continues.
    pub fn run_interactive(&mut self) -> std::io::Result<()> {
        let mut editor = DefaultEditor::new().map_err(readline_to_io)?;
        let stdout = std::io::stdout();
        println!("Graphus interactive shell. Type :help for commands, :quit to exit.");
        if let Some(info) = self.client.server_info() {
            println!(
                "Connected to {} (Bolt {}.{}) at {}.",
                info.server_agent,
                info.version.major,
                info.version.minor,
                self.socket.display()
            );
        }

        loop {
            let prompt = if self.buffer.is_pending() {
                "    ...> "
            } else {
                "graphus> "
            };
            match editor.readline(prompt) {
                Ok(raw) => {
                    let _ = editor.add_history_entry(raw.as_str());
                    let mut out = stdout.lock();
                    if self.dispatch(&raw, &mut out)? == Action::Quit {
                        break;
                    }
                }
                // Ctrl-C: abandon the current (possibly multi-line) input and start fresh.
                Err(ReadlineError::Interrupted) => {
                    if self.buffer.is_pending() {
                        self.buffer.clear();
                        println!("(cancelled)");
                    }
                }
                // Ctrl-D on an empty line: clean exit.
                Err(ReadlineError::Eof) => break,
                Err(e) => return Err(readline_to_io(e)),
            }
        }

        let _ = self.client.goodbye();
        Ok(())
    }

    /// Classifies one raw line and routes it: meta-command, or accumulate-and-maybe-run a statement.
    ///
    /// Factored out of the editor loop so the full per-line behaviour (multi-line accumulation +
    /// dispatch) is testable over an in-memory client and an in-memory `out`.
    pub fn dispatch(&mut self, raw: &str, out: &mut impl Write) -> std::io::Result<Action> {
        match classify_line(raw) {
            Line::Blank => Ok(Action::Continue),
            Line::Meta(cmd) => self.handle_meta(&cmd, out),
            Line::Cypher(fragment) => {
                if let Some(statement) = self.buffer.push(&fragment) {
                    self.handle_statement(&statement, out)
                } else {
                    Ok(Action::Continue)
                }
            }
        }
    }

    /// Sends `GOODBYE` and consumes the shell (used by the non-interactive `-c` path on exit).
    pub fn goodbye(mut self) {
        let _ = self.client.goodbye();
    }

    /// Borrows the underlying client (for the `-c` single-query path).
    pub fn client_mut(&mut self) -> &mut BoltClient<S> {
        &mut self.client
    }
}

/// A one-line summary of a query result: row count and elapsed time.
fn summarize(result: &crate::client::QueryResult) -> String {
    let rows = result.row_count();
    let noun = if rows == 1 { "row" } else { "rows" };
    format!("{rows} {noun} in {:.1?}", result.elapsed)
}

/// Maps a `rustyline` error onto an `io::Error` for the shared error channel.
fn readline_to_io(e: ReadlineError) -> std::io::Error {
    std::io::Error::other(format!("line editor error: {e}"))
}

/// The `:help` text.
const HELP_TEXT: &str = "\
Commands:
  <cypher>;          Run a Cypher statement (terminate with a semicolon).
  :help, :h, :?      Show this help.
  :status            Show the live connection + server identity.
  :clear             Discard a half-typed multi-line statement.
  :quit, :exit, :q   Disconnect and exit.

Multi-line input: a statement without a trailing ';' continues on the next line.
Ctrl-C cancels the current line; Ctrl-D on an empty line exits.
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_meta_commands_case_insensitively() {
        assert_eq!(classify_line(":help"), Line::Meta(MetaCommand::Help));
        assert_eq!(classify_line("  :QUIT  "), Line::Meta(MetaCommand::Quit));
        assert_eq!(classify_line(":Status"), Line::Meta(MetaCommand::Status));
        assert_eq!(classify_line(":exit"), Line::Meta(MetaCommand::Quit));
        assert_eq!(classify_line(":clear"), Line::Meta(MetaCommand::Clear));
        assert_eq!(
            classify_line(":wat"),
            Line::Meta(MetaCommand::Unknown("wat".to_owned()))
        );
    }

    #[test]
    fn classify_blank_and_cypher() {
        assert_eq!(classify_line("   "), Line::Blank);
        assert_eq!(classify_line(""), Line::Blank);
        assert_eq!(
            classify_line("MATCH (n) RETURN n;"),
            Line::Cypher("MATCH (n) RETURN n;".to_owned())
        );
    }

    #[test]
    fn statement_buffer_single_line() {
        let mut b = StatementBuffer::new();
        assert_eq!(b.push("RETURN 1;"), Some("RETURN 1".to_owned()));
        assert!(!b.is_pending());
    }

    #[test]
    fn statement_buffer_multi_line_joins_until_semicolon() {
        let mut b = StatementBuffer::new();
        assert_eq!(b.push("MATCH (n)"), None);
        assert!(b.is_pending());
        assert_eq!(b.push("WHERE n.x = 1"), None);
        assert_eq!(
            b.push("RETURN n;"),
            Some("MATCH (n) WHERE n.x = 1 RETURN n".to_owned())
        );
        assert!(!b.is_pending());
    }

    #[test]
    fn statement_buffer_bare_semicolon_runs_nothing() {
        let mut b = StatementBuffer::new();
        assert_eq!(b.push(";"), None);
        assert!(!b.is_pending());
    }

    #[test]
    fn statement_buffer_clear_drops_pending() {
        let mut b = StatementBuffer::new();
        b.push("MATCH (n)");
        assert!(b.is_pending());
        b.clear();
        assert!(!b.is_pending());
    }

    #[test]
    fn help_text_lists_every_meta_command() {
        for needle in [":help", ":status", ":clear", ":quit", ":exit"] {
            assert!(HELP_TEXT.contains(needle), "help missing {needle}");
        }
    }
}
