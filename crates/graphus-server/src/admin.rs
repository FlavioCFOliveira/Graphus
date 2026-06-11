//! The server-side **administrative statement surface** (rmp #84, decision `D-multi-db`): a
//! strict, tokenizing matcher that recognises database-administration statements **before** Cypher
//! compilation, and the shared execution context both connectivity seams
//! ([`crate::engine::BoltEngineExecutor`], [`crate::engine::RestEngineAdapter`]) drive.
//!
//! The query engine (`graphus-cypher`) stays completely database-agnostic: it never sees an
//! administrative statement. Interception happens in `graphus-server`, on the raw query string,
//! uniformly for all three connection types (UDS-Bolt and TCP-Bolt share the Bolt seam; REST has
//! its own seam) — one grammar, one authorization rule, one catalog behind every wire.
//!
//! ## Recognised grammar
//!
//! Keywords are **case-insensitive**; surrounding whitespace is ignored; one optional trailing
//! `;` is tolerated. A `<name>` is either a bare word (letters, digits, `_`, `-`, `.`) or a
//! `` `backtick-quoted` `` name; either way it is then validated and normalized by the catalog's
//! name rule ([`crate::dbcatalog::normalize_db_name`] — `[a-z][a-z0-9_-]{0,62}`,
//! case-insensitive).
//!
//! ```text
//! CREATE DATABASE <name> [IF NOT EXISTS]
//! DROP   DATABASE <name> [IF EXISTS]
//! START  DATABASE <name>
//! STOP   DATABASE <name>
//! SHOW   DATABASES
//! SHOW   DATABASE <name>
//! ```
//!
//! The matcher claims a statement **only** when its first two tokens are exactly an admin verb
//! followed by the `DATABASE`/`DATABASES` keyword — so `CREATE (n:Database)` (second token `(`),
//! `MATCH … RETURN 'CREATE DATABASE x'` (first token `MATCH`), or `CREATE DATABASE_X` (second
//! token is not the keyword) all pass through to Cypher untouched. Once claimed, the remainder
//! must parse exactly; a malformed remainder is a clear admin-syntax error rather than a
//! confusing Cypher one (`CREATE DATABASE` is never valid Cypher, so nothing is stolen from the
//! language).
//!
//! ## Semantics
//!
//! - All admin statements (including `SHOW DATABASES`) require the same **global `Admin`
//!   privilege** as the `/admin/*` REST endpoints (`04 §8.4` deny-by-default; one privilege model
//!   for the whole admin surface). A non-admin principal gets a permission-denied error and **no
//!   side effects**.
//! - Admin statements are **not transactional**: they are rejected inside an explicit
//!   (client-managed) transaction. On the REST auto-commit shortcut they execute immediately,
//!   outside the surrounding engine transaction.
//! - `IF NOT EXISTS` / `IF EXISTS` turn the duplicate/missing cases into no-op successes
//!   (`CREATE DATABASE <default> IF NOT EXISTS` is also a no-op: the default always exists).
//! - `SHOW DATABASES` returns one row per database — `name`, `state` (`"online"`/`"offline"`,
//!   the **actual** state), `default` (bool), `error` (string or null) — exactly what
//!   [`DatabaseCatalog::list`] exposes. `SHOW DATABASE <name>` returns that database's row, or
//!   zero rows when no such database exists.
//! - `DROP` requires the database to be stopped first (the catalog enforces it; the error is
//!   surfaced verbatim). The default database can never be stopped or dropped.
//!
//! ## Why the context bridges to the runtime with a `std` channel
//!
//! [`DatabaseCatalog`]'s lifecycle API is `async` (its admin mutex must be await-aware), but both
//! seams are synchronous and run on blocking threads — the Bolt session on `spawn_blocking`, and
//! the REST handlers *inside* a `Handle::block_on` on a blocking thread (see
//! `crate::listeners::rest`). A nested `Handle::block_on` panics ("cannot block the current
//! thread from within a runtime"), so the bridge **spawns** the catalog future onto the runtime
//! and waits for its result over a `std::sync::mpsc` one-shot — whose `recv` has no
//! runtime-context guard and is safe on any thread. This is the same reply pattern the engine
//! command channel uses (`04 §9.1`).

use std::sync::Arc;

use graphus_auth::{Authenticator, Privilege};
use graphus_core::{GraphusError, Value};
use tokio::runtime::Handle;

use crate::dbcatalog::{CatalogError, DatabaseCatalog, DbState, normalize_db_name};
use crate::engine::EngineHandle;

// ------------------------------------------------------------------------------------------------
// Statement grammar
// ------------------------------------------------------------------------------------------------

/// A recognised administrative statement (see the module docs for the grammar).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminCommand {
    /// `CREATE DATABASE <name> [IF NOT EXISTS]`.
    CreateDatabase {
        /// The database name, as written (the catalog normalizes + validates it).
        name: String,
        /// Whether `IF NOT EXISTS` was present (an existing database becomes a no-op success).
        if_not_exists: bool,
    },
    /// `DROP DATABASE <name> [IF EXISTS]`.
    DropDatabase {
        /// The database name, as written.
        name: String,
        /// Whether `IF EXISTS` was present (a missing database becomes a no-op success).
        if_exists: bool,
    },
    /// `START DATABASE <name>`.
    StartDatabase {
        /// The database name, as written.
        name: String,
    },
    /// `STOP DATABASE <name>`.
    StopDatabase {
        /// The database name, as written.
        name: String,
    },
    /// `SHOW DATABASES`.
    ShowDatabases,
    /// `SHOW DATABASE <name>`.
    ShowDatabase {
        /// The database name, as written.
        name: String,
    },
}

/// The outcome of matching a query string against the administrative grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminParse {
    /// Not an administrative statement: hand the query to the Cypher engine untouched.
    NotAdmin,
    /// A well-formed administrative statement.
    Command(AdminCommand),
    /// The statement is unambiguously claimed by the admin grammar (its first two tokens are an
    /// admin verb + the `DATABASE`/`DATABASES` keyword) but the remainder is malformed; the
    /// payload is the syntax-error message. The seams surface it as a compile-time error — the
    /// claimed prefixes are never valid Cypher, so nothing is taken from the language.
    Invalid(String),
}

/// One lexical token of an administrative statement.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// A bare word: letters, digits, `_`, `-`, `.` (keywords and unquoted names).
    Word(String),
    /// A `` `backtick-quoted` `` name (taken verbatim, no keyword meaning).
    Quoted(String),
    /// Any other single character (`(`, `:`, `'`, …) — never part of the admin grammar, so its
    /// presence in a claimed statement is a syntax error and before claiming means "not admin".
    Symbol(char),
}

/// A lazy tokenizer over the statement text. Lazy on purpose: an unclaimed statement is regular
/// Cypher whose full lexical structure (string literals, escapes) is none of this module's
/// business — only the first two tokens are ever read before the statement is claimed.
struct Lexer<'a> {
    rest: std::str::Chars<'a>,
}

impl<'a> Lexer<'a> {
    fn new(text: &'a str) -> Self {
        Self { rest: text.chars() }
    }

    /// Produces the next token, `Ok(None)` at end of input, or `Err` for an unterminated
    /// backtick-quoted name.
    fn next_tok(&mut self) -> Result<Option<Tok>, String> {
        // Skip whitespace.
        let mut chars = self.rest.clone();
        let first = loop {
            match chars.next() {
                Some(c) if c.is_whitespace() => continue,
                Some(c) => break c,
                None => {
                    self.rest = chars;
                    return Ok(None);
                }
            }
        };

        if first == '`' {
            // Backtick-quoted name: verbatim until the closing backtick.
            let mut name = String::new();
            loop {
                match chars.next() {
                    Some('`') => break,
                    Some(c) => name.push(c),
                    None => return Err("unterminated `backtick-quoted` database name".to_owned()),
                }
            }
            self.rest = chars;
            return Ok(Some(Tok::Quoted(name)));
        }

        if is_word_char(first) {
            let mut word = String::new();
            word.push(first);
            // Peek-extend while the next char is a word char.
            loop {
                let mut peek = chars.clone();
                match peek.next() {
                    Some(c) if is_word_char(c) => {
                        word.push(c);
                        chars = peek;
                    }
                    _ => break,
                }
            }
            self.rest = chars;
            return Ok(Some(Tok::Word(word)));
        }

        self.rest = chars;
        Ok(Some(Tok::Symbol(first)))
    }
}

/// Whether `c` may appear in a bare word (keyword or unquoted name).
fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

/// Whether `tok` is the (case-insensitive) keyword `kw`.
fn is_keyword(tok: &Tok, kw: &str) -> bool {
    matches!(tok, Tok::Word(w) if w.eq_ignore_ascii_case(kw))
}

/// Matches `query` against the administrative grammar (module docs). Strict by construction: it
/// claims a statement only on the exact two-token admin prefix, and once claimed the remainder
/// must parse exactly.
#[must_use]
pub fn parse_admin_statement(query: &str) -> AdminParse {
    let mut lex = Lexer::new(query);

    // Token 1: the verb. Anything unreadable or non-word means "regular Cypher".
    let Ok(Some(first)) = lex.next_tok() else {
        return AdminParse::NotAdmin;
    };
    let verb = match &first {
        Tok::Word(w) => w.to_ascii_uppercase(),
        _ => return AdminParse::NotAdmin,
    };
    if !matches!(verb.as_str(), "CREATE" | "DROP" | "START" | "STOP" | "SHOW") {
        return AdminParse::NotAdmin;
    }

    // Token 2: the DATABASE / DATABASES keyword. (Reading it cannot legitimately fail for real
    // Cypher here — a backtick directly after these verbs is not valid Cypher either — but an
    // unterminated quote is still just "not ours" at this point.)
    let second = match lex.next_tok() {
        Ok(Some(t)) => t,
        _ => return AdminParse::NotAdmin,
    };
    let plural = is_keyword(&second, "DATABASES");
    if !plural && !is_keyword(&second, "DATABASE") {
        return AdminParse::NotAdmin;
    }
    if plural && verb != "SHOW" {
        // e.g. `CREATE DATABASES x` — claimed by shape, but only SHOW takes the plural.
        return AdminParse::Invalid(format!(
            "expected DATABASE after {verb} (DATABASES is only valid in SHOW DATABASES)"
        ));
    }

    // From here on the statement is CLAIMED: parse strictly, errors are admin syntax errors.
    match parse_claimed(&verb, plural, &mut lex) {
        Ok(cmd) => AdminParse::Command(cmd),
        Err(msg) => AdminParse::Invalid(msg),
    }
}

/// Parses the remainder of a claimed statement (`verb` + `DATABASE`/`DATABASES` already read).
fn parse_claimed(verb: &str, plural: bool, lex: &mut Lexer<'_>) -> Result<AdminCommand, String> {
    if plural {
        // SHOW DATABASES — nothing else allowed.
        expect_end(lex, "SHOW DATABASES")?;
        return Ok(AdminCommand::ShowDatabases);
    }

    // Every singular form takes a name next.
    let name = match lex.next_tok()? {
        Some(Tok::Word(w)) => w,
        Some(Tok::Quoted(q)) => q,
        Some(other) => {
            return Err(unexpected(
                &other,
                &format!("a database name after {verb} DATABASE"),
            ));
        }
        None => return Err(format!("expected a database name after {verb} DATABASE")),
    };

    match verb {
        "CREATE" => {
            let if_not_exists = parse_optional_if(lex, /* with_not */ true)?;
            expect_end(lex, "CREATE DATABASE")?;
            Ok(AdminCommand::CreateDatabase {
                name,
                if_not_exists,
            })
        }
        "DROP" => {
            let if_exists = parse_optional_if(lex, /* with_not */ false)?;
            expect_end(lex, "DROP DATABASE")?;
            Ok(AdminCommand::DropDatabase { name, if_exists })
        }
        "START" => {
            expect_end(lex, "START DATABASE")?;
            Ok(AdminCommand::StartDatabase { name })
        }
        "STOP" => {
            expect_end(lex, "STOP DATABASE")?;
            Ok(AdminCommand::StopDatabase { name })
        }
        "SHOW" => {
            expect_end(lex, "SHOW DATABASE")?;
            Ok(AdminCommand::ShowDatabase { name })
        }
        // `parse_admin_statement` only claims the five verbs above.
        other => Err(format!("unsupported administrative verb {other}")),
    }
}

/// Parses an optional `IF NOT EXISTS` (`with_not = true`, CREATE) or `IF EXISTS` (DROP) clause.
/// Returns whether the clause was present. A partial clause (`IF` without the rest) is an error.
fn parse_optional_if(lex: &mut Lexer<'_>, with_not: bool) -> Result<bool, String> {
    // Peek: only consume if the next token is IF.
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    match peek.next_tok()? {
        Some(t) if is_keyword(&t, "IF") => {
            lex.rest = peek.rest.clone();
        }
        _ => return Ok(false),
    }
    let expected = if with_not {
        "IF NOT EXISTS"
    } else {
        "IF EXISTS"
    };
    if with_not {
        match lex.next_tok()? {
            Some(t) if is_keyword(&t, "NOT") => {}
            _ => return Err(format!("expected {expected}")),
        }
    }
    match lex.next_tok()? {
        Some(t) if is_keyword(&t, "EXISTS") => Ok(true),
        _ => Err(format!("expected {expected}")),
    }
}

/// Asserts end of statement, tolerating one trailing `;`.
fn expect_end(lex: &mut Lexer<'_>, what: &str) -> Result<(), String> {
    match lex.next_tok()? {
        None => Ok(()),
        Some(Tok::Symbol(';')) => match lex.next_tok()? {
            None => Ok(()),
            Some(t) => Err(unexpected(&t, &format!("end of {what} statement"))),
        },
        Some(t) => Err(unexpected(&t, &format!("end of {what} statement"))),
    }
}

/// Renders an "unexpected token" syntax error.
fn unexpected(tok: &Tok, expected: &str) -> String {
    let got = match tok {
        Tok::Word(w) => format!("`{w}`"),
        Tok::Quoted(q) => format!("`{q}`"),
        Tok::Symbol(c) => format!("`{c}`"),
    };
    format!("unexpected {got}; expected {expected}")
}

// ------------------------------------------------------------------------------------------------
// Execution context
// ------------------------------------------------------------------------------------------------

/// A buffered administrative result, streamed back through each seam's normal result mechanism.
#[derive(Debug, Clone, PartialEq)]
pub struct AdminResult {
    /// The result column names (empty for the lifecycle commands).
    pub fields: Vec<String>,
    /// The result rows (e.g. one per database for `SHOW DATABASES`).
    pub rows: Vec<Vec<Value>>,
}

impl AdminResult {
    /// The empty result the lifecycle commands return.
    fn empty() -> Self {
        Self {
            fields: Vec::new(),
            rows: Vec::new(),
        }
    }
}

/// The shared multi-database context of one server: **database targeting** (session `db` →
/// [`EngineHandle`]) plus **administrative-statement execution** against the catalog, used by both
/// connectivity seams. Cheap to clone (three `Arc`-shaped fields + a runtime handle).
#[derive(Clone)]
pub struct AdminContext {
    /// The database catalog (naming + lifecycle + the running-engine registry).
    catalog: Arc<DatabaseCatalog>,
    /// The shared authenticator: admin statements are authorized against the same RBAC catalog as
    /// every other operation (`04 §8.4`).
    auth: Arc<Authenticator>,
    /// The server runtime, for bridging the catalog's async lifecycle API from the synchronous
    /// seams (module docs: why spawn + `std` channel, not `block_on`).
    runtime: Handle,
    /// The default database's engine handle — the fast path for sessions that never name a
    /// database, guaranteeing the single-db experience is byte-for-byte today's behaviour.
    default_handle: EngineHandle,
}

impl AdminContext {
    /// Builds the context. `default_handle` must be the default database's admission-limited
    /// handle (the one [`crate::dbcatalog::DatabaseCatalog::start_default`] returned).
    #[must_use]
    pub fn new(
        catalog: Arc<DatabaseCatalog>,
        auth: Arc<Authenticator>,
        runtime: Handle,
        default_handle: EngineHandle,
    ) -> Self {
        Self {
            catalog,
            auth,
            runtime,
            default_handle,
        }
    }

    /// The (normalized) default database's name.
    #[must_use]
    pub fn default_database(&self) -> &str {
        self.catalog.default_database()
    }

    /// Resolves a session's target database to its canonical name + engine handle.
    ///
    /// `None` (or an empty/whitespace name — Bolt drivers send `""` for the home database) is the
    /// configured default database, served from the captured handle without touching the catalog
    /// (the unchanged single-db fast path). A named database resolves through the catalog's
    /// concurrent lookup registry; the name matching the default also takes the fast path.
    ///
    /// # Errors
    /// [`GraphusError::Protocol`] when the name is invalid, unknown, offline, or failed — with a
    /// distinct, accurate message for each case (the failure path consults the catalog listing).
    pub fn resolve(&self, db: Option<&str>) -> Result<(String, EngineHandle), GraphusError> {
        let Some(raw) = db.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok((
                self.catalog.default_database().to_owned(),
                self.default_handle.clone(),
            ));
        };
        let name = normalize_db_name(raw).map_err(|e| GraphusError::Protocol(e.to_string()))?;
        if name == self.catalog.default_database() {
            return Ok((name, self.default_handle.clone()));
        }
        match self.catalog.handle(&name) {
            Some(handle) => Ok((name, handle)),
            None => Err(self.unavailable(&name)),
        }
    }

    /// Builds the precise "database not servable" error for `name` (already normalized): unknown
    /// vs. stopped vs. failed-to-start. Off the hot path — it takes the catalog's admin lock via
    /// the async bridge purely to produce an accurate message.
    fn unavailable(&self, name: &str) -> GraphusError {
        let listing = {
            let catalog = Arc::clone(&self.catalog);
            let name = name.to_owned();
            self.run_on_runtime(
                async move { catalog.list().await.into_iter().find(|i| i.name == name) },
            )
        };
        let message = match listing {
            Ok(Some(info)) => match info.error {
                Some(e) => format!("database {name:?} failed to start: {e}"),
                None => format!(
                    "database {name:?} is not currently online (start it with START DATABASE)"
                ),
            },
            Ok(None) => format!("database {name:?} does not exist"),
            // The bridge only fails at process shutdown; report the plain fact.
            Err(_) => format!("database {name:?} is not currently available"),
        };
        GraphusError::Protocol(message)
    }

    /// Executes an administrative command on behalf of `principal`.
    ///
    /// Authorization first (module docs): the principal must be authenticated and hold the global
    /// `Admin` privilege — the same gate as the `/admin/*` REST endpoints. Only then is the
    /// catalog touched, so a denied command has **no side effects**.
    ///
    /// # Errors
    /// [`GraphusError::Security`] when unauthenticated/unauthorized; [`GraphusError::Runtime`]
    /// for a client-fault catalog rejection (bad name, duplicate, unknown, not stopped, the
    /// default database); [`GraphusError::Storage`] for a server-side catalog/engine fault.
    pub fn execute(
        &self,
        principal: Option<&str>,
        cmd: &AdminCommand,
    ) -> Result<AdminResult, GraphusError> {
        let principal = principal.ok_or_else(|| {
            GraphusError::Security(
                "administrative commands require an authenticated principal".to_owned(),
            )
        })?;
        self.auth
            .require(principal, &Privilege::admin_database())
            .map_err(|_| {
                GraphusError::Security(format!(
                    "permission denied: administrative commands require the admin privilege \
                     (user {principal:?} does not hold it)"
                ))
            })?;

        match cmd {
            AdminCommand::CreateDatabase {
                name,
                if_not_exists,
            } => {
                let outcome = self.with_catalog(name, |catalog, name| async move {
                    catalog.create(&name).await.map(|_handle| ())
                })?;
                match outcome {
                    Ok(()) => Ok(AdminResult::empty()),
                    // IF NOT EXISTS: an existing database — including the implicit default,
                    // which always exists — is a no-op success.
                    Err(CatalogError::AlreadyExists(_) | CatalogError::DefaultDatabase { .. })
                        if *if_not_exists =>
                    {
                        Ok(AdminResult::empty())
                    }
                    Err(e) => Err(graphus_error_from_catalog(&e)),
                }
            }
            AdminCommand::DropDatabase { name, if_exists } => {
                let outcome = self.with_catalog(name, |catalog, name| async move {
                    catalog.drop_database(&name).await
                })?;
                match outcome {
                    Ok(()) => Ok(AdminResult::empty()),
                    Err(CatalogError::UnknownDatabase(_)) if *if_exists => Ok(AdminResult::empty()),
                    Err(e) => Err(graphus_error_from_catalog(&e)),
                }
            }
            AdminCommand::StartDatabase { name } => {
                let outcome = self.with_catalog(name, |catalog, name| async move {
                    catalog.start(&name).await.map(|_handle| ())
                })?;
                outcome
                    .map(|()| AdminResult::empty())
                    .map_err(|e| graphus_error_from_catalog(&e))
            }
            AdminCommand::StopDatabase { name } => {
                let outcome =
                    self.with_catalog(
                        name,
                        |catalog, name| async move { catalog.stop(&name).await },
                    )?;
                outcome
                    .map(|()| AdminResult::empty())
                    .map_err(|e| graphus_error_from_catalog(&e))
            }
            AdminCommand::ShowDatabases => {
                let infos = {
                    let catalog = Arc::clone(&self.catalog);
                    self.run_on_runtime(async move { catalog.list().await })?
                };
                Ok(show_result(infos))
            }
            AdminCommand::ShowDatabase { name } => {
                // An invalid name cannot match any catalog entry: zero rows, same as unknown.
                let wanted = normalize_db_name(name).ok();
                let infos = {
                    let catalog = Arc::clone(&self.catalog);
                    self.run_on_runtime(async move { catalog.list().await })?
                };
                let filtered = infos
                    .into_iter()
                    .filter(|i| Some(&i.name) == wanted.as_ref())
                    .collect();
                Ok(show_result(filtered))
            }
        }
    }

    /// Runs one catalog lifecycle operation (`op(catalog, name)`) on the runtime, returning the
    /// operation's own `Result` (so callers can pattern-match `CatalogError` for the
    /// `IF [NOT] EXISTS` no-op cases).
    ///
    /// # Errors
    /// The **outer** error is the bridge failing (process shutdown); the inner one is the
    /// catalog's verdict.
    fn with_catalog<F, Fut>(
        &self,
        name: &str,
        op: F,
    ) -> Result<Result<(), CatalogError>, GraphusError>
    where
        F: FnOnce(Arc<DatabaseCatalog>, String) -> Fut,
        Fut: Future<Output = Result<(), CatalogError>> + Send + 'static,
    {
        let fut = op(Arc::clone(&self.catalog), name.to_owned());
        self.run_on_runtime(fut)
    }

    /// Bridges an async catalog operation from a synchronous (blocking-thread) seam: spawn the
    /// future onto the runtime, wait for the result over a `std::sync::mpsc` one-shot.
    ///
    /// `Handle::block_on` is **not** usable here: the REST seam executes inside an outer
    /// `Handle::block_on` (see `crate::listeners::rest`) where a nested `block_on` panics. A
    /// `std` `recv` carries no runtime-context guard, so this works from any thread (module docs).
    ///
    /// # Errors
    /// [`GraphusError::Transaction`] if the runtime dropped the task (process shutdown) — the
    /// same retriable classification as a closed engine channel.
    fn run_on_runtime<T, Fut>(&self, fut: Fut) -> Result<T, GraphusError>
    where
        T: Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::sync_channel::<T>(1);
        self.runtime.spawn(async move {
            // The receiver may have given up (it never does today); sending is best-effort.
            let _ = tx.send(fut.await);
        });
        rx.recv().map_err(|_| {
            GraphusError::Transaction(
                "administrative task aborted (server shutting down)".to_owned(),
            )
        })
    }
}

impl std::fmt::Debug for AdminContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminContext")
            .field("default_database", &self.catalog.default_database())
            .finish_non_exhaustive()
    }
}

/// Builds the `SHOW DATABASE(S)` result from catalog listings: `name`, `state`
/// (`"online"`/`"offline"`, the actual state), `default` (bool), `error` (string/null).
fn show_result(infos: Vec<crate::dbcatalog::DbInfo>) -> AdminResult {
    let fields = vec![
        "name".to_owned(),
        "state".to_owned(),
        "default".to_owned(),
        "error".to_owned(),
    ];
    let rows = infos
        .into_iter()
        .map(|info| {
            vec![
                Value::String(info.name),
                Value::String(
                    match info.state {
                        DbState::Online => "online",
                        DbState::Offline => "offline",
                    }
                    .to_owned(),
                ),
                Value::Boolean(info.is_default),
                info.error.map_or(Value::Null, Value::String),
            ]
        })
        .collect();
    AdminResult { fields, rows }
}

/// Maps a [`CatalogError`] onto the engine error model with the client/server fault split the
/// wire renderers expect: client faults (bad name, duplicate, unknown, not stopped, the default
/// database) are [`GraphusError::Runtime`] (Bolt `Neo.ClientError.Statement.ArgumentError`,
/// HTTP 400); infrastructure faults are [`GraphusError::Storage`] (`Neo.DatabaseError.*`,
/// HTTP 500).
fn graphus_error_from_catalog(e: &CatalogError) -> GraphusError {
    match e {
        CatalogError::InvalidName(_)
        | CatalogError::AlreadyExists(_)
        | CatalogError::UnknownDatabase(_)
        | CatalogError::NotOffline(_)
        | CatalogError::DefaultDatabase { .. } => GraphusError::Runtime(e.to_string()),
        CatalogError::Io { .. }
        | CatalogError::Corrupt { .. }
        | CatalogError::Encode(_)
        | CatalogError::Engine(_) => GraphusError::Storage(e.to_string()),
    }
}

// ------------------------------------------------------------------------------------------------
// Tests (the grammar; the execution context is covered by the wire-level integration tests)
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(query: &str) -> AdminCommand {
        match parse_admin_statement(query) {
            AdminParse::Command(c) => c,
            other => panic!("expected a command for {query:?}, got {other:?}"),
        }
    }

    fn invalid(query: &str) -> String {
        match parse_admin_statement(query) {
            AdminParse::Invalid(m) => m,
            other => panic!("expected Invalid for {query:?}, got {other:?}"),
        }
    }

    fn not_admin(query: &str) {
        assert_eq!(
            parse_admin_statement(query),
            AdminParse::NotAdmin,
            "{query:?} must pass through to Cypher"
        );
    }

    #[test]
    fn create_database_with_and_without_if_not_exists() {
        assert_eq!(
            cmd("CREATE DATABASE sales"),
            AdminCommand::CreateDatabase {
                name: "sales".to_owned(),
                if_not_exists: false
            }
        );
        assert_eq!(
            cmd("  create   database   Sales   if not exists  "),
            AdminCommand::CreateDatabase {
                name: "Sales".to_owned(), // normalization is the catalog's job
                if_not_exists: true
            }
        );
    }

    #[test]
    fn drop_start_stop_show_forms() {
        assert_eq!(
            cmd("DROP DATABASE sales"),
            AdminCommand::DropDatabase {
                name: "sales".to_owned(),
                if_exists: false
            }
        );
        assert_eq!(
            cmd("drop DATABASE sales IF EXISTS;"),
            AdminCommand::DropDatabase {
                name: "sales".to_owned(),
                if_exists: true
            }
        );
        assert_eq!(
            cmd("START DATABASE sales"),
            AdminCommand::StartDatabase {
                name: "sales".to_owned()
            }
        );
        assert_eq!(
            cmd("stop database sales"),
            AdminCommand::StopDatabase {
                name: "sales".to_owned()
            }
        );
        assert_eq!(cmd("SHOW DATABASES"), AdminCommand::ShowDatabases);
        assert_eq!(cmd("show databases ;"), AdminCommand::ShowDatabases);
        assert_eq!(
            cmd("SHOW DATABASE sales"),
            AdminCommand::ShowDatabase {
                name: "sales".to_owned()
            }
        );
    }

    #[test]
    fn backtick_quoted_names_are_taken_verbatim() {
        assert_eq!(
            cmd("CREATE DATABASE `Sales-2026`"),
            AdminCommand::CreateDatabase {
                name: "Sales-2026".to_owned(),
                if_not_exists: false
            }
        );
        // Even a quoted keyword is a name, never a keyword.
        assert_eq!(
            cmd("DROP DATABASE `database`"),
            AdminCommand::DropDatabase {
                name: "database".to_owned(),
                if_exists: false
            }
        );
    }

    #[test]
    fn regular_cypher_is_never_swallowed() {
        // The classic traps: CREATE with a node labelled Database, queries merely containing
        // the words, prefixed identifiers, and string literals.
        not_admin("CREATE (n:Database)");
        not_admin("CREATE (n:Database {name: 'x'}) RETURN n");
        not_admin("MATCH (n) RETURN n");
        not_admin("RETURN 'CREATE DATABASE sales'");
        not_admin("CREATE DATABASE_X");
        not_admin("WITH 1 AS x CREATE (n) RETURN x");
        not_admin("CREATE\n(n)");
        not_admin("showdatabases");
        not_admin("SHOW INDEXES"); // SHOW of something else is not (yet) ours
        not_admin(""); // empty input
        not_admin("   "); // blank input
        not_admin("`create` database x"); // a quoted first token is not a keyword
    }

    #[test]
    fn claimed_but_malformed_is_a_syntax_error() {
        // Claimed by the two-token prefix; the remainder must parse exactly.
        invalid("CREATE DATABASE"); // missing name
        invalid("CREATE DATABASE sales extra");
        invalid("CREATE DATABASE sales IF EXISTS"); // CREATE takes IF NOT EXISTS
        invalid("CREATE DATABASE sales IF NOT"); // partial clause
        invalid("DROP DATABASE sales IF NOT EXISTS"); // DROP takes IF EXISTS
        invalid("DROP DATABASE"); // missing name
        invalid("START DATABASE sales now");
        invalid("STOP DATABASE (sales)");
        invalid("SHOW DATABASES extra");
        invalid("SHOW DATABASE"); // missing name
        invalid("CREATE DATABASES sales"); // plural only for SHOW
        invalid("CREATE DATABASE `unterminated");
    }

    #[test]
    fn trailing_semicolon_is_tolerated_once() {
        assert_eq!(
            cmd("CREATE DATABASE sales;"),
            AdminCommand::CreateDatabase {
                name: "sales".to_owned(),
                if_not_exists: false
            }
        );
        invalid("CREATE DATABASE sales;;");
    }
}
