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
//!
//! CREATE INDEX [<name>] [IF NOT EXISTS] FOR (<var>:<Label>) ON (<var>.<property>) [OPTIONS { … }]
//! CREATE INDEX [IF NOT EXISTS] ON :<Label>(<property>)     -- legacy form
//! DROP   INDEX <name> [IF EXISTS]                          -- drops an index of ANY kind by name
//! DROP   INDEX ON :<Label>(<property>)                     -- (and the FOR … ON … form)
//! DROP   INDEX FOR (<var>:<Label>) ON (<var>.<property>)
//! SHOW   INDEX[ES]                                         -- singular synonym accepted (rmp #661)
//!
//! CREATE POINT INDEX [<name>] [IF NOT EXISTS] FOR (<var>:<Label>) ON (<var>.<prop>) [OPTIONS { … }]
//! DROP   POINT INDEX <name> [IF EXISTS]
//! SHOW   POINT INDEX[ES]
//!
//! CREATE FULLTEXT INDEX <name> [IF NOT EXISTS] FOR (<var>:<Label>) ON EACH [<var>.<prop>, …]
//!                                                  [OPTIONS { analyzer: '<analyzer>' }]   -- rmp #72
//!                                                  [OPTIONS { indexConfig { … } }]        -- rmp #661
//! DROP   FULLTEXT INDEX <name> [IF EXISTS]
//! SHOW   FULLTEXT INDEX[ES]
//! ```
//!
//! The matcher claims a statement **only** when its first two tokens are exactly an admin verb
//! followed by the `DATABASE`/`DATABASES` keyword (the database surface) or the `INDEX`/`INDEXES`
//! keyword (the index surface, `rmp` task #91) — so `CREATE (n:Database)` (second token `(`),
//! `MATCH … RETURN 'CREATE DATABASE x'` (first token `MATCH`), `CREATE DATABASE_X` /
//! `CREATE INDEX_X` (second token is not the keyword), or `CREATE (n:Index)` (second token `(`)
//! all pass through to Cypher untouched. Once claimed, the remainder must parse exactly; a
//! malformed remainder is a clear admin-syntax error rather than a confusing Cypher one
//! (`CREATE DATABASE` / `CREATE INDEX` are never valid Cypher, so nothing is stolen from the
//! language).
//!
//! ## Database vs. index surfaces (`rmp` task #91)
//!
//! The two surfaces share the strict matcher but execute in different places. **Database** commands
//! act on the off-engine async [`DatabaseCatalog`] ([`AdminContext::execute`]). **Index** commands
//! act on the [`graphus_cypher::TxnCoordinator`]'s node-property index catalog, which lives on the
//! single-threaded engine — so they are returned as [`AdminParse::Index`] and the seams route them
//! to the target database's [`EngineHandle`] (after the same admin-privilege gate). `CREATE INDEX`
//! starts a **non-blocking** background build: it returns promptly and never stalls concurrent
//! queries.
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
//! - `SHOW DATABASES` returns one row per database — `name`, `state`
//!   (`"online"`/`"offline"`/`"loading"`, the **actual** state — `"loading"` is a Mode A network
//!   bulk-import session in progress, `rmp` #519), `default` (bool), `error` (string or null) —
//!   exactly what
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

use graphus_auth::{AuthError, Privilege};
use graphus_core::{GraphusError, Value};
use graphus_cypher::{FulltextEntity, SpatialEntity, VectorEntity, VectorSimilarity};
use tokio::runtime::Handle;

use crate::audit::{
    AuditClass, AuditEvent, AuditLog, AuditOutcome, AuditSource, admin_target_database,
    classify_admin, is_mutating_admin, redact_admin_detail,
};
use crate::config::ServerConfig;
use crate::dbcatalog::{CatalogError, DatabaseCatalog, DbState, normalize_db_name};
use crate::engine::{
    ConstraintCommand, ConstraintCreateKind, ConstraintEntity, ConstraintTypeFilter,
    CreateConstraint, EngineHandle, IndexCommand, IndexTypeFilter, NodePropertyIndexRef,
    RelPropertyIndexRef, RunSummary,
};
use crate::security::{SecurityCatalog, SecurityError};

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

    // ---- Security surface (rmp #92) ----
    /// `CREATE USER <name> [SET PASSWORD '<pw>'] [IF NOT EXISTS]`.
    CreateUser {
        /// The username.
        name: String,
        /// The plaintext password from the `SET PASSWORD '<pw>'` clause, if present. Hashed (never
        /// stored or logged in the clear) by the security catalog before persistence.
        password: Option<String>,
        /// Whether `IF NOT EXISTS` was present (an existing user becomes a no-op success).
        if_not_exists: bool,
    },
    /// `DROP USER <name> [IF EXISTS]`.
    DropUser {
        /// The username.
        name: String,
        /// Whether `IF EXISTS` was present (a missing user becomes a no-op success).
        if_exists: bool,
    },
    /// `CREATE ROLE <name> [IF NOT EXISTS]`.
    CreateRole {
        /// The role name.
        name: String,
        /// Whether `IF NOT EXISTS` was present.
        if_not_exists: bool,
    },
    /// `DROP ROLE <name> [IF EXISTS]`.
    DropRole {
        /// The role name.
        name: String,
        /// Whether `IF EXISTS` was present.
        if_exists: bool,
    },
    /// `GRANT ROLE <role> TO <user>`.
    GrantRole {
        /// The role to grant.
        role: String,
        /// The user to grant it to.
        user: String,
    },
    /// `REVOKE ROLE <role> FROM <user>`.
    RevokeRole {
        /// The role to revoke.
        role: String,
        /// The user to revoke it from.
        user: String,
    },
    /// `GRANT <action> ON <scope> TO <role>`.
    GrantPrivilege {
        /// The parsed action.
        action: PrivAction,
        /// The parsed scope.
        scope: PrivScope,
        /// The role to grant to.
        role: String,
    },
    /// `DENY <action> ON <scope> TO <role>` (`rmp` #645). Records an explicit deny that takes
    /// precedence over any grant of the same `(action, scope)` at authorization time.
    DenyPrivilege {
        /// The parsed action.
        action: PrivAction,
        /// The parsed scope.
        scope: PrivScope,
        /// The role to deny on.
        role: String,
    },
    /// `REVOKE [GRANT | DENY] <action> ON <scope> FROM <role>` (`rmp` #645). The `mode` selects which
    /// of the grant / deny of that `(action, scope)` to remove; plain `REVOKE` removes both.
    RevokePrivilege {
        /// The parsed action.
        action: PrivAction,
        /// The parsed scope.
        scope: PrivScope,
        /// The role to revoke from.
        role: String,
        /// Which access sense(s) to remove (`GRANT` / `DENY` / both).
        mode: RevokeMode,
    },
    /// `SHOW USERS`.
    ShowUsers,
    /// `SHOW ROLES`.
    ShowRoles,
    /// `SHOW PRIVILEGES`.
    ShowPrivileges,
    /// `ALTER USER <name> SET PASSWORD '<pw>'` (`rmp` #641). Sets a new password (re-hashed,
    /// credential epoch bumped) without dropping/recreating the user.
    AlterUserPassword {
        /// The username.
        name: String,
        /// The new plaintext password (hashed by the security catalog; never stored/logged in clear).
        password: String,
    },
    /// `ALTER USER <name> SET STATUS {ACTIVE|SUSPENDED}` (`rmp` #641). Suspends or reactivates the
    /// account without dropping it.
    AlterUserStatus {
        /// The username.
        name: String,
        /// `true` for `SUSPENDED`, `false` for `ACTIVE`.
        suspended: bool,
    },
    /// `RENAME USER <from> TO <to>` (`rmp` #641).
    RenameUser {
        /// The current username.
        from: String,
        /// The new username.
        to: String,
    },
    /// `RENAME ROLE <from> TO <to>` (`rmp` #641).
    RenameRole {
        /// The current role name.
        from: String,
        /// The new role name.
        to: String,
    },

    // ---- DBMS introspection surface (rmp #637) ----
    /// `SHOW FUNCTIONS` — the built-in Cypher function library (read-only).
    ShowFunctions,
    /// `SHOW PROCEDURES` — the registered procedures (`db.*` built-ins + the GDS surface; read-only).
    ShowProcedures,
    /// `SHOW SETTINGS` — the server's effective (post-auto-tune) configuration (read-only).
    ShowSettings,
    /// `SHOW TRANSACTIONS` — the live explicit (managed) transactions across the server (read-only).
    ShowTransactions,
    /// `TERMINATE TRANSACTIONS '<id>' [, '<id>' ...]` — mark the named live transaction(s) for
    /// termination (their next interaction aborts). One or more single-quoted transaction ids.
    TerminateTransactions {
        /// The transaction ids to terminate, as written (e.g. `"graphus-transaction-42"`).
        ids: Vec<String>,
    },

    // ---- Operator backup / restore surface (rmp #149) ----
    /// `BACKUP DATABASE <name> TO '<path>'` — capture an online backup chain artifact of `name`
    /// (PITR-capable) and write it to `path`.
    BackupDatabase {
        /// The database to back up (the catalog normalizes + validates it).
        name: String,
        /// The destination file path for the artifact.
        path: String,
    },
    /// `RESTORE DATABASE <name> FROM '<path>' [AT LSN <n> | AT TIMESTAMP <n>]` — restore `name` from
    /// the backup chain artifact at `path`, to `point` (whole chain / a WAL LSN / a commit
    /// timestamp). The database must be **stopped** first; the default database cannot be restored
    /// in place.
    RestoreDatabase {
        /// The database to restore.
        name: String,
        /// The source backup-artifact file path.
        path: String,
        /// The point to restore to (PITR).
        point: RestorePoint,
    },

    // ---- Operator maintenance surface (rmp #305) ----
    /// `CHECKPOINT DATABASE <name>` — drive a maintenance checkpoint of the online database `name`:
    /// a reader-safe GC pass (reclaim dead versions + freeze committed MVCC stamps, lowering the WAL
    /// reclaim floor) followed by a sharp checkpoint that flushes dirty pages home and physically
    /// reclaims the WAL prefix below the floor — releasing RAM, disk and version slots that otherwise
    /// only drain on the background cadence (`rmp` #305 / #313 / #315).
    CheckpointDatabase {
        /// The database to checkpoint (the catalog normalizes + validates it).
        name: String,
    },
}

/// The point a [`AdminCommand::RestoreDatabase`] should recover to (`rmp` task #149). Maps 1:1 onto
/// [`graphus_storage::RestoreTarget`]; kept separate so the admin grammar is decoupled from the
/// storage crate's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorePoint {
    /// The whole committed chain (every captured transaction). The default with no `AT` clause.
    Latest,
    /// A specific WAL LSN (byte offset): replay up to and including the record ending there.
    Lsn(u64),
    /// A commit timestamp: replay up to and including the last transaction committed at or before it.
    Timestamp(u64),
}

impl RestorePoint {
    /// Maps onto the storage crate's [`graphus_storage::RestoreTarget`].
    #[must_use]
    pub fn to_target(self) -> graphus_storage::RestoreTarget {
        match self {
            Self::Latest => graphus_storage::RestoreTarget::Latest,
            Self::Lsn(n) => graphus_storage::RestoreTarget::Lsn(graphus_core::Lsn(n)),
            Self::Timestamp(t) => {
                graphus_storage::RestoreTarget::Timestamp(graphus_core::Timestamp(t))
            }
        }
    }
}

/// Which access sense(s) a `REVOKE` removes (`rmp` #645). Neo4j's `REVOKE GRANT`/`REVOKE DENY` remove
/// exactly one; a plain `REVOKE` removes whichever exists ([`RevokeMode::Both`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeMode {
    /// Plain `REVOKE`: remove both the grant and the deny of the `(action, scope)`.
    Both,
    /// `REVOKE GRANT`: remove only the grant, leaving any deny in place.
    GrantOnly,
    /// `REVOKE DENY`: remove only the deny, leaving any grant in place.
    DenyOnly,
}

/// A grantable action in the `GRANT`/`REVOKE`/`DENY` grammar (mirrors [`graphus_auth::Action`] but
/// kept separate so the grammar is decoupled from the auth crate's `#[non_exhaustive]` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivAction {
    /// `TRAVERSE`.
    Traverse,
    /// `READ`.
    Read,
    /// `WRITE`.
    Write,
    /// `SCHEMA`.
    Schema,
    /// `ADMIN`.
    Admin,
}

impl PrivAction {
    /// Parses an action keyword (case-insensitive); `None` if it is not one of the five.
    fn from_keyword(word: &str) -> Option<Self> {
        match word.to_ascii_uppercase().as_str() {
            "TRAVERSE" => Some(Self::Traverse),
            "READ" => Some(Self::Read),
            "WRITE" => Some(Self::Write),
            "SCHEMA" => Some(Self::Schema),
            "ADMIN" => Some(Self::Admin),
            _ => None,
        }
    }

    /// Maps onto the auth crate's [`graphus_auth::Action`].
    #[must_use]
    pub fn to_action(self) -> graphus_auth::Action {
        match self {
            Self::Traverse => graphus_auth::Action::Traverse,
            Self::Read => graphus_auth::Action::Read,
            Self::Write => graphus_auth::Action::Write,
            Self::Schema => graphus_auth::Action::Schema,
            Self::Admin => graphus_auth::Action::Admin,
        }
    }
}

/// A grantable scope in the `GRANT`/`REVOKE` grammar. The accepted forms map 1:1 onto
/// [`graphus_auth::Resource`]: `DATABASE`, `GRAPH <db>`, `LABEL <db>.<label>`,
/// `RELATIONSHIP <db>.<rel_type>`, `PROPERTY <db>.<label>.<property>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivScope {
    /// `DATABASE` — the whole server (every database).
    Database,
    /// `GRAPH <db>` — a whole named database.
    Graph {
        /// The database name.
        db: String,
    },
    /// `LABEL <db>.<label>` — all nodes of one label in one database.
    Label {
        /// The database name.
        db: String,
        /// The node label.
        label: String,
    },
    /// `RELATIONSHIP <db>.<rel_type>` — all relationships of one type in one database.
    RelType {
        /// The database name.
        db: String,
        /// The relationship type.
        rel_type: String,
    },
    /// `PROPERTY <db>.<label>.<property>` — one property of one label's nodes in one database.
    Property {
        /// The database name.
        db: String,
        /// The node label.
        label: String,
        /// The property key.
        property: String,
    },
}

impl PrivScope {
    /// Maps onto the auth crate's [`graphus_auth::Resource`].
    #[must_use]
    pub fn to_resource(&self) -> graphus_auth::Resource {
        use graphus_auth::Resource;
        match self {
            Self::Database => Resource::Database,
            Self::Graph { db } => Resource::Graph(db.clone()),
            Self::Label { db, label } => Resource::Label {
                db: db.clone(),
                label: label.clone(),
            },
            Self::RelType { db, rel_type } => Resource::RelType {
                db: db.clone(),
                rel_type: rel_type.clone(),
            },
            Self::Property {
                db,
                label,
                property,
            } => Resource::Property {
                db: db.clone(),
                label: label.clone(),
                property: property.clone(),
            },
        }
    }
}

/// The outcome of matching a query string against the administrative grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminParse {
    /// Not an administrative statement: hand the query to the Cypher engine untouched.
    NotAdmin,
    /// A well-formed **database** administrative statement (executed on the off-engine catalog via
    /// [`AdminContext::execute`]).
    Command(AdminCommand),
    /// A well-formed **index** administrative statement (`rmp` task #91): `CREATE/DROP INDEX` or
    /// `SHOW INDEXES`. Executed on the [`graphus_cypher::TxnCoordinator`] via the target database's
    /// [`EngineHandle`] (not the off-engine catalog), because the index catalog lives on the engine.
    /// The seams route it after the same admin-privilege gate as the database commands.
    Index(IndexCommand),
    /// A well-formed **constraint** administrative statement (`rmp` task #99): `CREATE/DROP
    /// CONSTRAINT` or `SHOW CONSTRAINTS`. Like an index command it is executed on the
    /// [`graphus_cypher::TxnCoordinator`] via the target database's [`EngineHandle`] (the constraint
    /// catalog lives on the engine), after the same admin-privilege gate. The seams route it
    /// identically to [`Index`](Self::Index).
    Constraint(ConstraintCommand),
    /// The statement is unambiguously claimed by the admin grammar (its first two tokens are an
    /// admin verb + the `DATABASE`/`DATABASES`/`INDEX`/`INDEXES` keyword) but the remainder is
    /// malformed; the payload is the syntax-error message. The seams surface it as a compile-time
    /// error — the claimed prefixes are never valid Cypher, so nothing is taken from the language.
    Invalid(String),
}

/// One lexical token of an administrative statement.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// A bare word: letters, digits, `_`, `-`, `.` (keywords and unquoted names).
    Word(String),
    /// A `` `backtick-quoted` `` name (taken verbatim, no keyword meaning).
    Quoted(String),
    /// A `'single'`- or `"double"`-quoted string literal — used for the `SET PASSWORD '<pw>'`
    /// clause (the security surface). Taken verbatim, with `\\` and the matching quote escapable.
    Str(String),
    /// Any other single character (`(`, `:`, …) — never part of the admin grammar, so its presence
    /// in a claimed statement is a syntax error and before claiming means "not admin".
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

        if first == '\'' || first == '"' {
            // Quoted string literal (the `SET PASSWORD '<pw>'` clause). The closing delimiter is the
            // same quote; `\\` escapes a backslash and `\<quote>` escapes the delimiter, so a
            // password may contain the quote character.
            let quote = first;
            let mut s = String::new();
            loop {
                match chars.next() {
                    Some('\\') => match chars.next() {
                        Some(c) => s.push(c),
                        None => return Err("unterminated string literal".to_owned()),
                    },
                    Some(c) if c == quote => break,
                    Some(c) => s.push(c),
                    None => return Err("unterminated string literal".to_owned()),
                }
            }
            self.rest = chars;
            return Ok(Some(Tok::Str(s)));
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

    // GRANT / REVOKE / DENY are never valid Cypher statement starts, so they are CLAIMED on the first
    // token alone (the security surface, rmp #92 / #645). Their remainder must then parse exactly.
    if verb == "GRANT" || verb == "REVOKE" || verb == "DENY" {
        return match parse_grant_revoke(&verb, &mut lex) {
            Ok(cmd) => AdminParse::Command(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // BACKUP / RESTORE are never valid Cypher statement starts either, so they are CLAIMED on the
    // first token alone (the operator backup surface, rmp #149).
    if verb == "BACKUP" || verb == "RESTORE" {
        return match parse_backup_restore(&verb, &mut lex) {
            Ok(cmd) => AdminParse::Command(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // CHECKPOINT is never a valid Cypher statement start either, so it is CLAIMED on the first token
    // alone (the operator maintenance surface, rmp #305).
    if verb == "CHECKPOINT" {
        return match parse_checkpoint(&verb, &mut lex) {
            Ok(cmd) => AdminParse::Command(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // TERMINATE is never a valid Cypher statement start, so it is CLAIMED on the first token alone
    // (the transaction-management surface, rmp #637).
    if verb == "TERMINATE" {
        return match parse_terminate(&verb, &mut lex) {
            Ok(cmd) => AdminParse::Command(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // ALTER / RENAME are never valid Cypher statement starts either, so they are CLAIMED on the first
    // token alone (the security-DDL surface, rmp #641).
    if verb == "ALTER" {
        return match parse_alter_user(&verb, &mut lex) {
            Ok(cmd) => AdminParse::Command(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }
    if verb == "RENAME" {
        return match parse_rename(&verb, &mut lex) {
            Ok(cmd) => AdminParse::Command(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    if !matches!(verb.as_str(), "CREATE" | "DROP" | "START" | "STOP" | "SHOW") {
        return AdminParse::NotAdmin;
    }

    // Token 2: the surface keyword — DATABASE(S) (database surface), INDEX(ES) (index surface), or
    // USER(S)/ROLE(S)/PRIVILEGES (security surface). (Reading it cannot legitimately fail for real
    // Cypher here — a backtick directly after these verbs is not valid Cypher either — but an
    // unterminated quote is still just "not ours" at this point.)
    let mut second = match lex.next_tok() {
        Ok(Some(t)) => t,
        _ => return AdminParse::NotAdmin,
    };

    // --- `CREATE OR REPLACE CONSTRAINT …` prefix (`rmp` #638) ---
    // `OR` right after CREATE is never a valid Cypher statement start, so consuming the `OR REPLACE`
    // prefix here CLAIMS the statement. `OR REPLACE` is a **Graphus superset** of the Neo4j surface
    // (which offers only `IF NOT EXISTS` for schema DDL) and is supported for CONSTRAINT only.
    let mut or_replace = false;
    if verb == "CREATE" && is_keyword(&second, "OR") {
        match lex.next_tok() {
            Ok(Some(ref t)) if is_keyword(t, "REPLACE") => {}
            Ok(Some(other)) => {
                return AdminParse::Invalid(unexpected_generic(&other, "REPLACE after CREATE OR"));
            }
            _ => return AdminParse::Invalid("expected REPLACE after CREATE OR".to_owned()),
        }
        or_replace = true;
        second = match lex.next_tok() {
            Ok(Some(t)) => t,
            _ => {
                return AdminParse::Invalid(
                    "expected CONSTRAINT after CREATE OR REPLACE".to_owned(),
                );
            }
        };
        if !is_keyword(&second, "CONSTRAINT") {
            return AdminParse::Invalid(
                "OR REPLACE is only supported for CREATE OR REPLACE CONSTRAINT".to_owned(),
            );
        }
    }

    // --- Security surface (rmp #92): CREATE/DROP USER, CREATE/DROP ROLE, SHOW USERS/ROLES/PRIVILEGES ---
    if is_keyword(&second, "USER")
        || is_keyword(&second, "USERS")
        || is_keyword(&second, "ROLE")
        || is_keyword(&second, "ROLES")
        || is_keyword(&second, "PRIVILEGES")
    {
        return match parse_claimed_security(&verb, &second, &mut lex) {
            Ok(cmd) => AdminParse::Command(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // --- DBMS introspection surface (rmp #637): SHOW FUNCTIONS/PROCEDURES/SETTINGS/TRANSACTIONS ---
    // These plurals directly after a verb are never valid Cypher, so the statement is CLAIMED once
    // the verb + keyword is seen. Only `SHOW` takes them (nullary listings).
    if is_keyword(&second, "FUNCTIONS")
        || is_keyword(&second, "PROCEDURES")
        || is_keyword(&second, "SETTINGS")
        || is_keyword(&second, "TRANSACTIONS")
    {
        return match parse_claimed_introspection(&verb, &second, &mut lex) {
            Ok(cmd) => AdminParse::Command(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // --- Database surface ---
    if is_keyword(&second, "DATABASE") || is_keyword(&second, "DATABASES") {
        let plural = is_keyword(&second, "DATABASES");
        if plural && verb != "SHOW" {
            // e.g. `CREATE DATABASES x` — claimed by shape, but only SHOW takes the plural.
            return AdminParse::Invalid(format!(
                "expected DATABASE after {verb} (DATABASES is only valid in SHOW DATABASES)"
            ));
        }
        // From here on the statement is CLAIMED: parse strictly, errors are admin syntax errors.
        return match parse_claimed(&verb, plural, &mut lex) {
            Ok(cmd) => AdminParse::Command(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // --- Filtered SHOW INDEXES surface (`rmp` task #660): `SHOW <filter> INDEX[ES] [tail]` ---
    // The index type-filter words (RANGE / TEXT / POINT / LOOKUP / FULLTEXT / VECTOR / ALL) precede the
    // INDEXES keyword. RANGE/TEXT/LOOKUP/FULLTEXT/POINT are also CREATE/DROP leads (dispatched below for
    // those verbs); for SHOW they route here to the ONE unified listing. VECTOR (no CREATE/DROP path
    // yet) and the shared `ALL` lead are handled only here. `ALL` is also a constraint filter, so it is
    // disambiguated by the terminal keyword (INDEX[ES] vs CONSTRAINT[S]). This is placed before the
    // typed-index / constraint-filter dispatch so `SHOW <filter> INDEXES` never reaches those paths.
    if verb == "SHOW" && is_index_filter_lead(&second) && show_targets_indexes(&second, &lex) {
        return match parse_show_indexes_filtered(&second, &mut lex) {
            Ok(cmd) => AdminParse::Index(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // --- Typed search-performance index surface (`rmp` #638): RANGE / TEXT / LOOKUP INDEX … ---
    // `RANGE` / `TEXT` / `LOOKUP` directly after a verb are never valid Cypher, so the statement is
    // CLAIMED once the verb + kind keyword is seen (mirroring FULLTEXT/POINT). RANGE is a full synonym
    // of the node-property index; TEXT maps to it (served by the same B-tree); LOOKUP is declined
    // (Graphus maintains token lookup indexes implicitly). The SHOW forms are dispatched above.
    if is_keyword(&second, "RANGE") || is_keyword(&second, "TEXT") || is_keyword(&second, "LOOKUP")
    {
        return match parse_claimed_typed_index(&verb, &second, &mut lex) {
            Ok(cmd) => AdminParse::Index(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // --- Full-text index surface (`rmp` task #72): CREATE/DROP/SHOW FULLTEXT INDEX(ES) … ---
    // The third token must be INDEX/INDEXES; `FULLTEXT` alone is never valid Cypher, so the statement
    // is CLAIMED once the verb + FULLTEXT prefix is seen.
    if is_keyword(&second, "FULLTEXT") {
        return match parse_claimed_fulltext(&verb, &mut lex) {
            Ok(cmd) => AdminParse::Index(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // --- Spatial (point) index surface (`rmp` task #98): CREATE/DROP/SHOW POINT INDEX(ES) … ---
    // Like FULLTEXT, `POINT` alone is never a valid Cypher statement start, so the statement is
    // CLAIMED once the verb + POINT prefix is seen.
    if is_keyword(&second, "POINT") {
        return match parse_claimed_point(&verb, &mut lex) {
            Ok(cmd) => AdminParse::Index(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // --- Vector (HNSW) index surface (`rmp` task #671): CREATE/DROP VECTOR INDEX … ---
    // Like FULLTEXT/POINT, `VECTOR` directly after a verb is never valid Cypher, so the statement is
    // CLAIMED once the verb + VECTOR prefix is seen. `SHOW VECTOR INDEXES` is dispatched by the unified
    // SHOW-index-filter surface above (`rmp` #660), so only CREATE/DROP reach here.
    if is_keyword(&second, "VECTOR") {
        return match parse_claimed_vector(&verb, &mut lex) {
            Ok(cmd) => AdminParse::Index(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // --- Filtered SHOW CONSTRAINTS surface (`rmp` task #653): `SHOW <filter> CONSTRAINT[S] [tail]` ---
    // The filter words (ALL / NODE / REL[ATIONSHIP] / PROPERTY / UNIQUE[NESS] / EXIST[ENCE] / KEY /
    // TYPE) precede the CONSTRAINT keyword, so `second` here is a filter lead — never a valid Cypher
    // statement after `SHOW`. Only `SHOW` takes a constraint filter; CREATE/DROP never reach this.
    if verb == "SHOW" && is_constraint_filter_lead(&second) {
        return match parse_show_constraints_filtered(&second, &mut lex) {
            Ok(cmd) => AdminParse::Constraint(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // --- Constraint surface (`rmp` task #99): CREATE/DROP/SHOW CONSTRAINT(S) … ---
    // `CONSTRAINT`/`CONSTRAINTS` directly after a verb is never valid Cypher, so the statement is
    // CLAIMED once the verb + the keyword is seen (mirroring the INDEX surface).
    if is_keyword(&second, "CONSTRAINT") || is_keyword(&second, "CONSTRAINTS") {
        let plural = is_keyword(&second, "CONSTRAINTS");
        if plural && verb != "SHOW" {
            // e.g. `CREATE CONSTRAINTS …` — claimed by shape, but only SHOW takes the plural.
            return AdminParse::Invalid(format!(
                "expected CONSTRAINT after {verb} (CONSTRAINTS is only valid in SHOW CONSTRAINTS)"
            ));
        }
        return match parse_claimed_constraint(&verb, plural, or_replace, &mut lex) {
            Ok(cmd) => AdminParse::Constraint(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    // --- Index surface (`rmp` task #91) ---
    if is_keyword(&second, "INDEX") || is_keyword(&second, "INDEXES") {
        let plural = is_keyword(&second, "INDEXES");
        if plural && verb != "SHOW" {
            // e.g. `CREATE INDEXES …` — claimed by shape, but only SHOW takes the plural.
            return AdminParse::Invalid(format!(
                "expected INDEX after {verb} (INDEXES is only valid in SHOW INDEXES)"
            ));
        }
        // CLAIMED by the index surface: parse strictly. The `SHOW INDEX[ES]` singular/plural split is
        // handled inside; `CREATE/DROP INDEXES` was already rejected above.
        return match parse_claimed_index(&verb, &mut lex) {
            Ok(cmd) => AdminParse::Index(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    AdminParse::NotAdmin
}

/// Parses the remainder of a claimed **index** statement (`verb` + `INDEX`/`INDEXES` already read),
/// for the `CREATE`/`DROP` shapes and `SHOW INDEXES` (`rmp` tasks #91, #624):
///
/// ```text
/// CREATE INDEX [<name>] [IF NOT EXISTS] FOR (n:Label) ON (n.property)  -- openCypher 9 (named/anonymous)
/// CREATE INDEX [IF NOT EXISTS] ON :Label(property)                     -- legacy (anonymous)
/// DROP   INDEX <name> [IF EXISTS]                                      -- by name
/// DROP   INDEX FOR (n:Label) ON (n.property)                           -- by target
/// DROP   INDEX ON :Label(property)                                     -- by target (legacy)
/// SHOW   INDEXES
/// ```
///
/// A name/label/property is a bare word or a `` `backtick-quoted` `` name (so one colliding with a
/// keyword still works); a variable is any bare word (its actual text is irrelevant — both shapes are
/// single-variable). The optional index **name** (`rmp` task #624) is disambiguated from the `FOR`/`ON`
/// target keywords and the `IF` clause by look-ahead: the first token after `CREATE/DROP INDEX` is the
/// name **unless** it is the bare keyword `FOR`, `ON` or `IF` (a name that collides with one of those
/// must be back-ticked).
fn parse_claimed_index(verb: &str, lex: &mut Lexer<'_>) -> Result<IndexCommand, String> {
    match verb {
        // Both `SHOW INDEX` (singular, `rmp` #661) and `SHOW INDEXES` list the unified index set
        // (filter = All), plus an optional YIELD/WHERE tail (`rmp` #660). Neo4j accepts `INDEX[ES]`;
        // the singular behaves identically to the plural. The filtered forms (`SHOW <filter> INDEX[ES]`)
        // are dispatched earlier. The `CREATE/DROP INDEXES` plural is rejected before dispatch.
        "SHOW" => {
            let tail = capture_show_tail(lex, "SHOW INDEXES")?;
            Ok(IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::All,
                tail,
            })
        }
        "CREATE" => parse_create_index(lex),
        "DROP" => parse_drop_index(lex),
        // `parse_admin_statement` only routes CREATE/DROP/SHOW here; START/STOP never reach this.
        other => Err(format!("unsupported index verb {other}")),
    }
}

/// Parses a **typed** search-performance index statement (`rmp` #638) whose first two tokens are
/// `verb` (`CREATE`/`DROP`/`SHOW`) + the kind keyword `kind_kw` (`RANGE`/`TEXT`/`LOOKUP`); the third
/// token must be `INDEX`/`INDEXES`:
///
/// ```text
/// CREATE RANGE INDEX [<name>] [IF NOT EXISTS] FOR (n:Label) ON (n.property)   -- full node-property synonym
/// CREATE TEXT  INDEX [<name>] [IF NOT EXISTS] FOR (n:Label) ON (n.property)   -- distinct trigram string index
/// DROP   RANGE|TEXT INDEX <name> [IF EXISTS]
/// SHOW   RANGE|TEXT INDEXES
/// ```
///
/// - **RANGE** is a full synonym of the plain node-property index (`CREATE INDEX`): the create/drop/show
///   are delegated verbatim to [`parse_claimed_index`], so a range index is nameable, droppable and
///   listed under `SHOW INDEXES` (with `type` `RANGE`). The RANGE B-tree serves `=` (equality seek) and,
///   since `rmp` task #658, `STARTS WITH` (a bounded prefix range seek over `[prefix, successor)`).
/// - **TEXT** is a **distinct native trigram string index** (`rmp` task #662), NOT a synonym of RANGE:
///   it is the only index that serves `CONTAINS` / `ENDS WITH` (a substring/suffix is not a contiguous
///   key range) and is preferred over RANGE for `STARTS WITH` when present. Routed to
///   [`parse_claimed_text_tail`], producing `CreateTextIndex`/`DropTextIndex`, and listed under
///   `SHOW INDEXES` with `type` `TEXT`. A RANGE and a TEXT index may coexist on the same
///   `(label, property)` (they are different kinds).
/// - **LOOKUP** is **declined** with an informative message: Graphus maintains node-label and
///   relationship-type lookup indexes **implicitly** (always-on), so label/type scans are already
///   index-backed and no explicit LOOKUP index is required.
///
/// The relationship form (`FOR ()-[r:TYPE]-()`) of RANGE/TEXT is not yet supported (it needs a durable
/// relationship-property index); RANGE reports it via the delegated node-property target parser, and
/// TEXT covers a node property only (relationship TEXT is a follow-up).
fn parse_claimed_typed_index(
    verb: &str,
    kind_kw: &Tok,
    lex: &mut Lexer<'_>,
) -> Result<IndexCommand, String> {
    let kind = keyword_text(kind_kw); // "RANGE" / "TEXT" / "LOOKUP"
    // The next token must be INDEX (CREATE/DROP) or INDEXES (SHOW).
    let kw = lex
        .next_tok()?
        .ok_or_else(|| format!("expected INDEX or INDEXES after {verb} {kind}"))?;
    let plural = is_keyword(&kw, "INDEXES");
    if !is_keyword(&kw, "INDEX") && !plural {
        return Err(unexpected_generic(
            &kw,
            &format!("INDEX or INDEXES after {verb} {kind}"),
        ));
    }
    if plural && verb != "SHOW" {
        return Err(format!(
            "expected INDEX after {verb} {kind} (INDEXES is only valid in SHOW {kind} INDEXES)"
        ));
    }

    if is_keyword(kind_kw, "LOOKUP") {
        // Token lookup indexes are implicit and always-on in Graphus (`rmp` #638): label and
        // relationship-type scans are already index-backed, so there is nothing to create, drop or list.
        return Err(
            "LOOKUP index DDL is not supported: Graphus maintains node-label and relationship-type \
             lookup indexes implicitly (always-on), so label/type scans are already index-backed and \
             no explicit LOOKUP index is required"
                .to_owned(),
        );
    }

    // TEXT is a **distinct** native string index (`rmp` task #662) — NOT a synonym of RANGE — that
    // accelerates `CONTAINS` / `ENDS WITH` / `STARTS WITH`, which a forward-ordered B-tree cannot serve.
    // Route it to the dedicated text-index parser (which produces `CreateTextIndex`/`DropTextIndex`),
    // rather than the RANGE node-property parser. The `verb` + `INDEX` are already read, so the text
    // parser resumes from the (optional) name / `FOR` clause. (SHOW TEXT INDEX[ES] is dispatched earlier
    // through the unified `SHOW <filter> INDEXES` surface, so only CREATE/DROP reach here.)
    if is_keyword(kind_kw, "TEXT") {
        return parse_claimed_text_tail(verb, lex);
    }

    // RANGE: a full node-property synonym — the `verb` + `INDEX`/`INDEXES` are already read, so hand the
    // remainder to the existing node-property parser verbatim. (SHOW RANGE INDEX[ES] is dispatched
    // earlier through the unified `SHOW <filter> INDEXES` surface, so only CREATE/DROP with the singular
    // `INDEX` reach here.)
    parse_claimed_index(verb, lex)
}

/// Parses the remainder of a claimed **text (trigram)** index statement (`verb` + `TEXT` + `INDEX`
/// already read), for the two mutating shapes (`rmp` task #662):
///
/// ```text
/// CREATE TEXT INDEX [<name>] [IF NOT EXISTS] FOR (<var>:<Label>) ON (<var>.<property>) [OPTIONS { … }]
/// DROP   TEXT INDEX <name> [IF EXISTS]
/// ```
///
/// A text index is identified by **name** (Neo4j-compatible), covers **exactly one** node string
/// property, and — like the point index — accepts an optional trailing `OPTIONS { … }` that is parsed,
/// validated structurally, then accepted-and-ignored (Graphus's trigram index has no analyzer to
/// configure; the clause must nonetheless parse for Neo4j-DDL compatibility). `SHOW TEXT INDEXES` is
/// handled by the unified SHOW-index-filter surface, so only CREATE/DROP reach here. Mirrors
/// [`parse_claimed_point`].
fn parse_claimed_text_tail(verb: &str, lex: &mut Lexer<'_>) -> Result<IndexCommand, String> {
    match verb {
        "DROP" => {
            // A text-index DROP always names its target.
            let name = expect_name(lex, "a text index name", "TEXT")?;
            // `IF EXISTS` turns a missing index into a no-op success.
            let if_exists = parse_optional_if(lex, /* with_not */ false)?;
            expect_end(lex, "DROP TEXT INDEX")?;
            Ok(IndexCommand::DropTextIndex { name, if_exists })
        }
        "CREATE" => {
            // The name is OPTIONAL (Neo4j parity): a bare `FOR`/`IF` directly after INDEX means
            // "unnamed" → a deterministic auto-name derived from the covered schema. `IF NOT EXISTS`
            // follows the (optional) name, before the `FOR` clause (Neo4j position).
            let explicit_name = parse_optional_text_index_name(lex)?;
            let if_not_exists = parse_optional_if(lex, /* with_not */ true)?;
            let (label, property) = parse_text_create_tail(lex)?;
            let name = explicit_name.unwrap_or_else(|| auto_text_index_name(&label, &property));
            Ok(IndexCommand::CreateTextIndex {
                name,
                label,
                property,
                if_not_exists,
            })
        }
        // `parse_admin_statement` only routes CREATE/DROP/SHOW here; START/STOP never reach this.
        other => Err(format!("unsupported text index verb {other}")),
    }
}

/// Parses the OPTIONAL text-index name in `CREATE TEXT INDEX [name] …` (`rmp` task #662). Returns
/// [`None`] (consuming nothing) when the next token is a bare `FOR` or `IF` — i.e. the name was omitted
/// and a deterministic auto-name applies — otherwise consumes and returns the explicit name. A
/// backtick-quoted `` `FOR` `` / `` `IF` `` is still a name (only the bare keyword signals "unnamed").
/// Mirrors [`parse_optional_point_index_name`].
fn parse_optional_text_index_name(lex: &mut Lexer<'_>) -> Result<Option<String>, String> {
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    if let Some(Tok::Word(w)) = peek.next_tok()? {
        if w.eq_ignore_ascii_case("FOR") || w.eq_ignore_ascii_case("IF") {
            return Ok(None);
        }
    }
    Ok(Some(expect_name(lex, "a text index name", "TEXT")?))
}

/// A deterministic auto-name for an anonymous text index on `(label, property)` (`rmp` task #662),
/// `text_index_<label>_<property>` — so a repeated anonymous `CREATE TEXT INDEX … IF NOT EXISTS`
/// resolves to the same name (idempotent) and `SHOW INDEXES` reports a stable name. A cross-catalog
/// name collision is caught by the engine's global name-uniqueness check.
fn auto_text_index_name(label: &str, property: &str) -> String {
    format!("text_index_{label}_{property}")
}

/// Parses the `FOR (<var>:<Label>) ON (<var>.<property>) [OPTIONS { … }]` tail of a
/// `CREATE TEXT INDEX <name>` statement (`rmp` task #662). Returns `(label, property)`. Mirrors the
/// single-property point-index tail ([`parse_point_create_tail`]).
fn parse_text_create_tail(lex: &mut Lexer<'_>) -> Result<(String, String), String> {
    const VERB: &str = "TEXT";
    // FOR ( <var> : <Label> )
    expect_keyword(lex, "FOR", VERB)?;
    expect_symbol(lex, '(', VERB)?;
    let _var = expect_word(lex, "a variable", VERB)?;
    expect_symbol(lex, ':', VERB)?;
    let label = expect_name(lex, "a label", VERB)?;
    expect_symbol(lex, ')', VERB)?;
    // ON ( <var>.<property> )
    expect_keyword(lex, "ON", VERB)?;
    expect_symbol(lex, '(', VERB)?;
    let property = parse_property_ref(VERB, lex)?;
    expect_symbol(lex, ')', VERB)?;
    // Optional trailing `OPTIONS { … }`: parsed + validated structurally, then accepted-and-ignored
    // (Graphus's trigram index has no analyzer/provider config; the clause must parse for Neo4j-DDL
    // compatibility).
    parse_optional_index_options(lex)?;
    expect_end(lex, "CREATE TEXT INDEX")?;
    Ok((label, property))
}

/// The parsed target of an index DDL statement: a **node** label property (`FOR (n:Label) ON
/// (n.property)` / legacy `ON :Label(property)`) or a **relationship** type property
/// (`FOR ()-[r:TYPE]-() ON (r.property)`, `rmp` task #646). The entity selects the `IndexCommand`
/// variant (node vs relationship) so a single target parser serves both CREATE and DROP.
#[derive(Debug, Clone, PartialEq, Eq)]
enum IndexTarget {
    /// A node-property index target `(label, properties)` — one property for a single-property RANGE
    /// index, two or more for a composite (multi-property) RANGE index (`rmp` task #657). The property
    /// order is significant for a composite.
    Node {
        /// The covered node label.
        label: String,
        /// The covered property keys, in declared order (one or more).
        properties: Vec<String>,
    },
    /// A relationship-property index target `(rel_type, properties)` (`rmp` tasks #646 / #666) — one
    /// property for a single-property RANGE index, two or more for a composite (multi-property) RANGE
    /// index. The property order is significant for a composite.
    Rel {
        /// The covered relationship type.
        rel_type: String,
        /// The covered property keys, in declared order (one or more).
        properties: Vec<String>,
    },
}

/// Parses a `CREATE INDEX [<name>] [IF NOT EXISTS] <target>` tail (`rmp` tasks #624 / #646): an
/// optional name, an optional `IF NOT EXISTS`, then the `FOR … ON …` (node **or** relationship) or
/// legacy `ON :Label(property)` (node) target.
fn parse_create_index(lex: &mut Lexer<'_>) -> Result<IndexCommand, String> {
    let name = parse_optional_index_name(lex)?;
    let if_not_exists = parse_optional_if(lex, /* with_not */ true)?;
    let target = parse_index_target("CREATE", lex)?;
    // Optional trailing `OPTIONS { indexProvider: '…', indexConfig { … } }` (`rmp` task #661): parsed
    // and validated, then accepted-and-ignored (Graphus has a single built-in index provider), so a
    // Neo4j `CREATE INDEX … OPTIONS { … }` is accepted verbatim.
    parse_optional_index_options(lex)?;
    expect_end(lex, "CREATE INDEX")?;
    match target {
        IndexTarget::Node { label, properties } => Ok(IndexCommand::CreateNodePropertyIndex {
            name,
            label,
            properties,
            if_not_exists,
        }),
        IndexTarget::Rel {
            rel_type,
            properties,
        } => Ok(IndexCommand::CreateRelPropertyIndex {
            name,
            rel_type,
            properties,
            if_not_exists,
        }),
    }
}

/// Parses a `DROP INDEX …` tail (`rmp` tasks #624 / #646): the by-**target** shape (`FOR …`/`ON …`,
/// node or relationship) or the by-**name** shape (`<name> [IF EXISTS]`). A leading `FOR`/`ON` keyword
/// selects the target shape; anything else is read as the index name.
///
/// A by-**name** drop resolves to the [`IndexCommand::DropNodePropertyIndex`] `Named` form regardless
/// of the index kind: index names are globally unique across the node **and** relationship property
/// index catalogs, and the engine resolves the name against either (`rmp` task #646).
fn parse_drop_index(lex: &mut Lexer<'_>) -> Result<IndexCommand, String> {
    // Look ahead: a leading FOR/ON keyword is the by-target shape; otherwise it is a `DROP INDEX <name>`.
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    let by_target = matches!(
        peek.next_tok()?,
        Some(ref t) if is_keyword(t, "FOR") || is_keyword(t, "ON")
    );
    if by_target {
        let target = parse_index_target("DROP", lex)?;
        expect_end(lex, "DROP INDEX")?;
        return match target {
            IndexTarget::Node { label, properties } => Ok(IndexCommand::DropNodePropertyIndex {
                index: NodePropertyIndexRef::Target { label, properties },
                if_exists: false,
            }),
            IndexTarget::Rel {
                rel_type,
                properties,
            } => Ok(IndexCommand::DropRelPropertyIndex {
                index: RelPropertyIndexRef::Target {
                    rel_type,
                    properties,
                },
                if_exists: false,
            }),
        };
    }
    // By name: `DROP INDEX <name> [IF EXISTS]`. The engine resolves the name across the node + rel
    // property index catalogs (names are globally unique), so the node `Named` variant carries it.
    let name = expect_name(lex, "an index name or a FOR/ON target", "DROP")?;
    let if_exists = parse_optional_if(lex, /* with_not */ false)?;
    expect_end(lex, "DROP INDEX")?;
    Ok(IndexCommand::DropNodePropertyIndex {
        index: NodePropertyIndexRef::Named(name),
        if_exists,
    })
}

/// Parses the optional index **name** before a `CREATE INDEX` target (`rmp` task #624). Returns the
/// name if present, or [`None`] when the next token is the bare keyword `FOR`, `ON` or `IF` (which
/// starts the target or the `IF NOT EXISTS` clause), or when there is no token (the target parser then
/// produces the precise "expected FOR/ON" error). A back-ticked token is always a name — so an index
/// may be named `` `for` `` / `` `if` `` if quoted.
fn parse_optional_index_name(lex: &mut Lexer<'_>) -> Result<Option<String>, String> {
    // Peek without consuming.
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    match peek.next_tok()? {
        // A bare FOR/ON/IF keyword is NOT a name: it starts the target or the IF clause.
        Some(Tok::Word(w))
            if w.eq_ignore_ascii_case("FOR")
                || w.eq_ignore_ascii_case("ON")
                || w.eq_ignore_ascii_case("IF") =>
        {
            Ok(None)
        }
        // Any other bare word, or a back-ticked name, is the index name.
        Some(Tok::Word(_) | Tok::Quoted(_)) => {
            Ok(Some(expect_name(lex, "an index name", "CREATE")?))
        }
        // A symbol / string / end-of-input: no name — let the target parser produce the precise error.
        _ => Ok(None),
    }
}

/// Parses an index target `(label, property)` from either supported shape after `verb INDEX`:
///
/// - **openCypher 9:** `FOR (<var>:<Label>) ON (<var>.<property>)`
/// - **legacy:** `ON :<Label>(<property>)`
///
/// The leading keyword (`FOR` vs `ON`) disambiguates; anything else is a syntax error naming both
/// accepted shapes.
fn parse_index_target(verb: &str, lex: &mut Lexer<'_>) -> Result<IndexTarget, String> {
    match lex.next_tok()? {
        Some(t) if is_keyword(&t, "FOR") => parse_index_for_on(verb, lex),
        Some(t) if is_keyword(&t, "ON") => parse_index_legacy_on(verb, lex),
        Some(other) => Err(unexpected(
            &other,
            &format!(
                "FOR (n:Label) ON (n.property), FOR ()-[r:TYPE]-() ON (r.property) or \
                 ON :Label(property) after {verb} INDEX"
            ),
        )),
        None => Err(format!(
            "expected FOR (n:Label) ON (n.property), FOR ()-[r:TYPE]-() ON (r.property) or \
             ON :Label(property) after {verb} INDEX"
        )),
    }
}

/// Parses the openCypher-9 `FOR (<var>:<Label>) ON (<var>.<property>)` (node) **or**
/// `FOR ()-[<var>:<TYPE>]-() ON (<var>.<property>)` (relationship, `rmp` task #646) tail (the `FOR`
/// already consumed). The relationship form is detected by its leading empty node `()`.
///
/// # Tokenization note
///
/// The lexer treats `.` and `-` as word characters (so a hyphenated/dotted name is one token), so
/// `n.property` lexes as a **single** [`Tok::Word`] (`"n.property"`), not `n` `.` `property`. We
/// therefore read that one word and split it on the first `.` into `(variable, property)`. The
/// `(n:Label)` part, by contrast, splits naturally because `:` is a symbol. The lone dash of the
/// relationship pattern lexes as the single word `"-"` — [`expect_dash`] consumes it; only the
/// **undirected** form is accepted (a directed arrow `->`/`<-` is a syntax error, mirroring the
/// constraint surface).
fn parse_index_for_on(verb: &str, lex: &mut Lexer<'_>) -> Result<IndexTarget, String> {
    // FOR ( … — a relationship-property index pattern opens with an empty node `()`.
    expect_symbol(lex, '(', verb)?;
    if peek_symbol(lex, ')')? {
        // FOR ()-[ <var> : <TYPE> ]-() ON ( <var>.<property>[, …] )  (`rmp` task #646)
        expect_symbol(lex, ')', verb)?; // close the empty start node
        expect_dash(lex, verb)?;
        expect_symbol(lex, '[', verb)?;
        let _var = expect_word(lex, "a variable", verb)?;
        expect_symbol(lex, ':', verb)?;
        let rel_type = expect_name(lex, "a relationship type", verb)?;
        expect_symbol(lex, ']', verb)?;
        expect_dash(lex, verb)?;
        expect_symbol(lex, '(', verb)?;
        expect_symbol(lex, ')', verb)?;
        // ON ( <var>.<property>[, …] )
        expect_keyword(lex, "ON", verb)?;
        expect_symbol(lex, '(', verb)?;
        let properties = parse_on_property_list(verb, lex)?;
        expect_symbol(lex, ')', verb)?;
        // The optional trailing `OPTIONS { … }` and end-of-statement are validated by the caller
        // (`parse_create_index` / `parse_drop_index`), so this leaf can serve both verbs (`rmp` #661).
        // One property is a single-property RANGE index; two or more a composite (multi-property) RANGE
        // index over the ordered relationship-property tuple (`rmp` task #666, the durable rel-composite
        // backing store deferred by `rmp` #657 now exists).
        return Ok(IndexTarget::Rel {
            rel_type,
            properties,
        });
    }
    // FOR ( <var> : <Label> )
    let _var = expect_word(lex, "a variable", verb)?;
    expect_symbol(lex, ':', verb)?;
    let label = expect_name(lex, "a label", verb)?;
    expect_symbol(lex, ')', verb)?;
    // ON ( <var>.<a>[, <var>.<b>, …] ) — one property is a single-property RANGE index, two or more a
    // composite (multi-property) RANGE index over the ordered tuple (`rmp` task #657).
    expect_keyword(lex, "ON", verb)?;
    expect_symbol(lex, '(', verb)?;
    let properties = parse_on_property_list(verb, lex)?;
    expect_symbol(lex, ')', verb)?;
    // The optional trailing `OPTIONS { … }` and end-of-statement are validated by the caller.
    Ok(IndexTarget::Node { label, properties })
}

/// Parses a comma-separated `<var>.<a>[, <var>.<b>, …]` property list inside an openCypher `ON ( … )`
/// index clause (the opening `(` already consumed, the closing `)` left for the caller) (`rmp` task
/// #657). Returns the properties in declared order. Rejects a **duplicate** property in the list (an
/// index over `(a, a)` is degenerate) with a clear error; the list is always non-empty (the loop reads
/// at least one property, or the underlying [`parse_property_ref`] errors).
fn parse_on_property_list(verb: &str, lex: &mut Lexer<'_>) -> Result<Vec<String>, String> {
    let mut properties = Vec::new();
    loop {
        properties.push(parse_property_ref(verb, lex)?);
        if peek_symbol(lex, ',')? {
            expect_symbol(lex, ',', verb)?;
        } else {
            break;
        }
    }
    for (i, p) in properties.iter().enumerate() {
        if properties[..i].contains(p) {
            return Err(format!(
                "duplicate property `{p}` in the index property list ON ( … )"
            ));
        }
    }
    Ok(properties)
}

/// Parses the `<var>.<property>` reference inside an openCypher `ON ( … )` clause.
///
/// # Tokenization
///
/// `.` is a word character, so `n.age` lexes as the **single** word `"n.age"` and we split it on the
/// first `.`. But a **backtick-quoted** property keeps the dot outside the quotes — `n.`age`` lexes
/// as the word `"n."` (trailing dot) followed by the quoted token — so when the word ends in `.` we
/// take the following [`Tok::Quoted`] (or word) as the property. Either way the variable text is
/// discarded (single-variable shape).
fn parse_property_ref(verb: &str, lex: &mut Lexer<'_>) -> Result<String, String> {
    let head = expect_word(lex, "a `variable.property` reference", verb)?;
    match head.split_once('.') {
        // `var.prop` in one word — the common case. Reject an embedded second dot (`a.b.c`).
        Some((_var, prop)) if !prop.is_empty() && !prop.contains('.') => Ok(prop.to_owned()),
        // `var.` then a separate (quoted or bare) property token: a backtick-quoted property.
        Some((_var, "")) => expect_name(lex, "a property", verb),
        _ => Err(format!(
            "expected `variable.property` after {verb} INDEX FOR (n:Label) ON (got `{head}`)"
        )),
    }
}

/// Parses the remainder of a claimed **full-text** index statement (`verb` + `FULLTEXT` already
/// read), for the three shapes (`rmp` task #72):
///
/// ```text
/// CREATE FULLTEXT INDEX <name> FOR (<var>:<Label>) ON EACH [<var>.<prop>, …]
///                                                          [OPTIONS { analyzer: '<analyzer>' }]
/// DROP   FULLTEXT INDEX <name>
/// SHOW   FULLTEXT INDEXES
/// ```
///
/// A full-text index is identified by **name** (Neo4j-compatible), unlike a node-property index
/// (`(label, property)`). The `OPTIONS { analyzer: '<name>' }` clause is optional; the analyzer name
/// is validated by the engine (`standard` / `keyword`), `standard` by default. `ON EACH [ … ]` lists
/// one or more `<var>.<property>` references (the `<var>` text is irrelevant — single-variable shape).
fn parse_claimed_fulltext(verb: &str, lex: &mut Lexer<'_>) -> Result<IndexCommand, String> {
    // The next token must be INDEX (CREATE/DROP) or INDEXES (SHOW). `FULLTEXT` alone never reaches
    // Cypher, so a wrong follower is an admin syntax error.
    let kw = lex
        .next_tok()?
        .ok_or_else(|| format!("expected INDEX or INDEXES after {verb} FULLTEXT"))?;
    let plural = is_keyword(&kw, "INDEXES");
    if !is_keyword(&kw, "INDEX") && !plural {
        return Err(unexpected_generic(
            &kw,
            &format!("INDEX or INDEXES after {verb} FULLTEXT"),
        ));
    }

    // `SHOW FULLTEXT INDEXES` is dispatched by the unified SHOW-index-filter surface (`rmp` #660), so
    // only CREATE/DROP FULLTEXT reach here; the plural INDEXES form is therefore always an error.
    if plural {
        return Err(format!(
            "expected INDEX after {verb} FULLTEXT (SHOW FULLTEXT INDEXES is the only plural form)"
        ));
    }

    // Both CREATE and DROP take a name next (full-text index names are mandatory in Neo4j).
    let name = expect_name(lex, "a full-text index name", "FULLTEXT")?;

    match verb {
        "DROP" => {
            // `IF EXISTS` (`rmp` #661) turns a missing index into a no-op success.
            let if_exists = parse_optional_if(lex, /* with_not */ false)?;
            expect_end(lex, "DROP FULLTEXT INDEX")?;
            Ok(IndexCommand::DropFulltextIndex { name, if_exists })
        }
        "CREATE" => {
            // `IF NOT EXISTS` (`rmp` #661) sits between the name and the `FOR` clause (Neo4j position).
            let if_not_exists = parse_optional_if(lex, /* with_not */ true)?;
            let (entity, labels_or_types, properties, analyzer) = parse_fulltext_create_tail(lex)?;
            Ok(IndexCommand::CreateFulltextIndex {
                name,
                entity,
                labels_or_types,
                properties,
                analyzer,
                if_not_exists,
            })
        }
        // `parse_admin_statement` only routes CREATE/DROP/SHOW here; START/STOP never reach this.
        other => Err(format!("unsupported full-text index verb {other}")),
    }
}

/// Parses the `FOR <pattern> ON EACH [<var>.<prop>, …] [OPTIONS { analyzer: '<name>' }]` tail of a
/// `CREATE FULLTEXT INDEX <name>` statement (`rmp` tasks #72, #663). `<pattern>` is either a node
/// pattern `(<var>:<Label>[|<Label>…])` or an undirected relationship pattern
/// `()-[<var>:<Type>[|<Type>…]]-()`. Returns `(entity, labels_or_types, properties, analyzer_name)`;
/// the analyzer defaults to `"standard"` when no `OPTIONS` clause is present.
fn parse_fulltext_create_tail(
    lex: &mut Lexer<'_>,
) -> Result<(FulltextEntity, Vec<String>, Vec<String>, String), String> {
    const VERB: &str = "FULLTEXT";
    // FOR <node or relationship pattern>
    expect_keyword(lex, "FOR", VERB)?;
    let (entity, labels_or_types) = parse_fulltext_pattern(lex)?;
    // ON EACH [ <var>.<prop> , … ]
    expect_keyword(lex, "ON", VERB)?;
    expect_keyword(lex, "EACH", VERB)?;
    expect_symbol(lex, '[', VERB)?;
    let mut properties = Vec::new();
    properties.push(parse_property_ref(VERB, lex)?);
    while peek_symbol(lex, ',')? {
        expect_symbol(lex, ',', VERB)?;
        properties.push(parse_property_ref(VERB, lex)?);
    }
    expect_symbol(lex, ']', VERB)?;
    // Optional OPTIONS { analyzer: '<name>' }
    let analyzer = parse_optional_fulltext_options(lex)?.unwrap_or_else(|| "standard".to_owned());
    expect_end(lex, "CREATE FULLTEXT INDEX")?;
    Ok((entity, labels_or_types, properties, analyzer))
}

/// Parses a full-text index `FOR` pattern (`rmp` task #663): a node pattern `(<var>:<Label>[|<Label>…])`
/// or an undirected relationship pattern `()-[<var>:<Type>[|<Type>…]]-()`, returning the
/// [`FulltextEntity`] and the ordered, `|`-separated label/type list (one or more). Multi-label/-type
/// is Neo4j's `A|B` syntax; a directed relationship arrow (`->` / `<-`) is a syntax error (only the
/// undirected form is accepted, like the constraint surface).
fn parse_fulltext_pattern(lex: &mut Lexer<'_>) -> Result<(FulltextEntity, Vec<String>), String> {
    const VERB: &str = "FULLTEXT";
    expect_symbol(lex, '(', VERB)?;
    // A relationship pattern opens with an empty node `()`.
    if peek_symbol(lex, ')')? {
        // ()-[ <var> : <Type>[|<Type>…] ]-()
        expect_symbol(lex, ')', VERB)?; // close the empty start node
        expect_dash(lex, VERB)?;
        expect_symbol(lex, '[', VERB)?;
        let _var = expect_word(lex, "a variable", VERB)?;
        expect_symbol(lex, ':', VERB)?;
        let types = parse_fulltext_token_list(lex, "a relationship type")?;
        expect_symbol(lex, ']', VERB)?;
        expect_dash(lex, VERB)?;
        expect_symbol(lex, '(', VERB)?;
        expect_symbol(lex, ')', VERB)?;
        return Ok((FulltextEntity::Relationship, types));
    }
    // (<var> : <Label>[|<Label>…])
    let _var = expect_word(lex, "a variable", VERB)?;
    expect_symbol(lex, ':', VERB)?;
    let labels = parse_fulltext_token_list(lex, "a label")?;
    expect_symbol(lex, ')', VERB)?;
    Ok((FulltextEntity::Node, labels))
}

/// Parses a `|`-separated list of label / relationship-type names (`rmp` task #663), one or more, in
/// declared order. `what` names the token kind for error messages (`"a label"` / `"a relationship
/// type"`). Mirrors the constraint type-union `|` fold.
fn parse_fulltext_token_list(lex: &mut Lexer<'_>, what: &str) -> Result<Vec<String>, String> {
    const VERB: &str = "FULLTEXT";
    let mut tokens = vec![expect_name(lex, what, VERB)?];
    while peek_symbol(lex, '|')? {
        expect_symbol(lex, '|', VERB)?;
        tokens.push(expect_name(lex, what, VERB)?);
    }
    Ok(tokens)
}

/// Parses an optional full-text-index `OPTIONS { … }` clause (`rmp` tasks #72, #661), only consumed
/// when the next token is `OPTIONS`. Returns the analyzer name if one was specified. Two shapes are
/// accepted (in addition to `indexProvider`, accepted and ignored — Graphus has one built-in provider):
///
/// ```text
/// OPTIONS { analyzer: '<name>' }                                                    -- bare (rmp #72)
/// OPTIONS { indexConfig: { `fulltext.analyzer`: '<name>',
///                          `fulltext.eventually_consistent`: true } }               -- Neo4j (rmp #661)
/// ```
///
/// `fulltext.analyzer` maps to the analyzer; `fulltext.eventually_consistent` is accepted and ignored
/// (builds are synchronous). An unknown **top-level** option key is a clear error; unknown
/// `indexConfig` keys are accepted and ignored (matching the constraint OPTIONS leniency, `rmp` #654).
/// A malformed clause (unbalanced braces, missing colon, wrong value type) is a syntax error.
fn parse_optional_fulltext_options(lex: &mut Lexer<'_>) -> Result<Option<String>, String> {
    if !consume_options_keyword(lex)? {
        return Ok(None);
    }
    expect_options_symbol(lex, '{')?;
    let entries = parse_option_map_body(lex)?;
    let mut analyzer: Option<String> = None;
    for (key, value) in &entries {
        match key.to_ascii_lowercase().as_str() {
            "analyzer" => analyzer = Some(as_option_string(value, "analyzer")?),
            // Accepted for Neo4j-DDL compatibility (one built-in provider), then ignored.
            "indexprovider" => {
                let _ = as_option_string(value, "indexProvider")?;
            }
            "indexconfig" => {
                for (ckey, cval) in as_option_map(value, "indexConfig")? {
                    match ckey.to_ascii_lowercase().as_str() {
                        "fulltext.analyzer" => {
                            analyzer = Some(as_option_string(cval, "fulltext.analyzer")?);
                        }
                        // Accepted and ignored: builds are synchronous, so there is nothing to reflect.
                        "fulltext.eventually_consistent" => {}
                        // Any other indexConfig key is accepted and ignored (leniency, `rmp` #654).
                        _ => {}
                    }
                }
            }
            other => {
                return Err(format!(
                    "unknown full-text index OPTIONS key `{other}`; \
                     expected analyzer, indexProvider or indexConfig"
                ));
            }
        }
    }
    Ok(analyzer)
}

// ------------------------------------------------------------------------------------------------
// Index OPTIONS { … } clause (`rmp` task #661)
// ------------------------------------------------------------------------------------------------

/// One parsed value inside an index `OPTIONS { … }` map (`rmp` task #661): a quoted string, a bare
/// token (a number / `true` / `false` / identifier), a `[ … ]` list, or a nested `{ … }` map.
/// Recursive so a nested `indexConfig { … }` map and a spatial `[min, max]` list validate
/// structurally.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OptionValue {
    /// A `'single'`- / `"double"`-quoted (or `` `backtick` ``) string value.
    Str(String),
    /// A bare token: a number, `true` / `false`, or an identifier (the lexer keeps it as one word).
    Word(String),
    /// A `[ … ]` list of values (e.g. a spatial `[-100.0, -100.0]` bound).
    List(Vec<OptionValue>),
    /// A nested `{ … }` map (e.g. `indexConfig { … }`).
    Map(Vec<(String, OptionValue)>),
}

/// Consumes a leading `OPTIONS` keyword if present (peeking on a clone first), returning whether it
/// was consumed. Shared by every index-kind OPTIONS parser (`rmp` task #661).
fn consume_options_keyword(lex: &mut Lexer<'_>) -> Result<bool, String> {
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    match peek.next_tok()? {
        Some(t) if is_keyword(&t, "OPTIONS") => {
            lex.rest = peek.rest.clone();
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Consumes the next token, requiring it to be the single symbol `sym`, framing errors for the
/// `OPTIONS { … }` context (`rmp` task #661).
fn expect_options_symbol(lex: &mut Lexer<'_>, sym: char) -> Result<(), String> {
    match lex.next_tok()? {
        Some(Tok::Symbol(c)) if c == sym => Ok(()),
        Some(t) => Err(unexpected(
            &t,
            &format!("`{sym}` in an OPTIONS {{ … }} clause"),
        )),
        None => Err(format!("expected `{sym}` in an OPTIONS {{ … }} clause")),
    }
}

/// Reads an `OPTIONS`-map **key**: a bare word (e.g. `indexProvider`, or a dotted/dashed
/// `spatial.wgs-84.min` the lexer keeps whole), a `` `backtick-quoted` `` key, or a `'quoted'` string
/// key — matching how Neo4j spells `indexConfig` keys (`rmp` task #661).
fn expect_option_key(lex: &mut Lexer<'_>) -> Result<String, String> {
    match lex.next_tok()? {
        Some(Tok::Word(w)) => Ok(w),
        Some(Tok::Quoted(q)) => Ok(q),
        Some(Tok::Str(s)) => Ok(s),
        Some(t) => Err(unexpected(&t, "an option key in an OPTIONS { … } clause")),
        None => Err("expected an option key in an OPTIONS { … } clause".to_owned()),
    }
}

/// Parses one `OPTIONS`-map value — a string, a bare token, a `[ … ]` list, or a `{ … }` map —
/// consuming exactly it (`rmp` task #661). Structural validation only: the value's meaning is the
/// caller's concern.
fn parse_option_value(lex: &mut Lexer<'_>) -> Result<OptionValue, String> {
    match lex.next_tok()? {
        Some(Tok::Str(s)) => Ok(OptionValue::Str(s)),
        Some(Tok::Quoted(q)) => Ok(OptionValue::Str(q)),
        Some(Tok::Word(w)) => Ok(OptionValue::Word(w)),
        Some(Tok::Symbol('[')) => {
            let mut items = Vec::new();
            if !peek_symbol(lex, ']')? {
                loop {
                    items.push(parse_option_value(lex)?);
                    if peek_symbol(lex, ',')? {
                        expect_options_symbol(lex, ',')?;
                    } else {
                        break;
                    }
                }
            }
            expect_options_symbol(lex, ']')?;
            Ok(OptionValue::List(items))
        }
        Some(Tok::Symbol('{')) => Ok(OptionValue::Map(parse_option_map_body(lex)?)),
        Some(other) => Err(unexpected(&other, "a value in an OPTIONS { … } clause")),
        None => Err("expected a value in an OPTIONS { … } clause".to_owned()),
    }
}

/// Parses the body of an `OPTIONS` / `indexConfig` map — the `key: value [, …]` pairs after an
/// **already-consumed** opening `{`, consuming the closing `}` (`rmp` task #661). An empty `{}` is
/// allowed. Keys are read by [`expect_option_key`], values by [`parse_option_value`].
fn parse_option_map_body(lex: &mut Lexer<'_>) -> Result<Vec<(String, OptionValue)>, String> {
    let mut entries = Vec::new();
    if peek_symbol(lex, '}')? {
        expect_options_symbol(lex, '}')?;
        return Ok(entries);
    }
    loop {
        let key = expect_option_key(lex)?;
        expect_options_symbol(lex, ':')?;
        let value = parse_option_value(lex)?;
        entries.push((key, value));
        if peek_symbol(lex, ',')? {
            expect_options_symbol(lex, ',')?;
        } else {
            break;
        }
    }
    expect_options_symbol(lex, '}')?;
    Ok(entries)
}

/// Requires `value` to be a quoted string (`rmp` task #661); errors naming the `key` otherwise.
fn as_option_string(value: &OptionValue, key: &str) -> Result<String, String> {
    match value {
        OptionValue::Str(s) => Ok(s.clone()),
        _ => Err(format!("OPTIONS `{key}` expects a quoted string value")),
    }
}

/// Requires `value` to be a nested `{ … }` map (`rmp` task #661); errors naming the `key` otherwise.
fn as_option_map<'v>(
    value: &'v OptionValue,
    key: &str,
) -> Result<&'v [(String, OptionValue)], String> {
    match value {
        OptionValue::Map(m) => Ok(m),
        _ => Err(format!("OPTIONS `{key}` expects a `{{ … }}` map value")),
    }
}

/// Parses an optional `OPTIONS { indexProvider: '<str>', indexConfig { … } }` clause on a
/// `CREATE RANGE/TEXT/POINT INDEX` (`rmp` task #661), validating the Neo4j shape. The only recognised
/// **top-level** keys are `indexProvider` (a quoted string) and `indexConfig` (a `{ … }` map); an
/// unknown top-level key is a clear error. Graphus has a single built-in index provider and
/// synchronous builds, so the provider and config are accepted for Neo4j-DDL compatibility and — for
/// now — **not applied** (parse + validate; applying spatial/provider config is a follow-up). The
/// `indexConfig` entries are accepted leniently (their keys carried but not interpreted), matching the
/// constraint OPTIONS leniency (`rmp` #654). A malformed clause is a syntax error. No-op (returns
/// without consuming) when the next token is not `OPTIONS`.
fn parse_optional_index_options(lex: &mut Lexer<'_>) -> Result<(), String> {
    if !consume_options_keyword(lex)? {
        return Ok(());
    }
    expect_options_symbol(lex, '{')?;
    for (key, value) in parse_option_map_body(lex)? {
        match key.to_ascii_lowercase().as_str() {
            "indexprovider" => {
                let _ = as_option_string(&value, "indexProvider")?;
            }
            "indexconfig" => {
                // Validate it is a map; its entries (spatial bounds, text config, …) are accepted and
                // carried structurally but not applied (single built-in provider).
                let _ = as_option_map(&value, "indexConfig")?;
            }
            other => {
                return Err(format!(
                    "unknown index OPTIONS key `{other}`; expected indexProvider or indexConfig"
                ));
            }
        }
    }
    Ok(())
}

/// Parses the remainder of a claimed **spatial (point)** index statement (`verb` + `POINT` already
/// read), for the three shapes (`rmp` task #98):
///
/// ```text
/// CREATE POINT INDEX <name> FOR (<var>:<Label>) ON (<var>.<property>)
/// DROP   POINT INDEX <name>
/// SHOW   POINT INDEXES
/// ```
///
/// A spatial index is identified by **name** (Neo4j-compatible), like a full-text index. Unlike the
/// full-text `ON EACH [ … ]` list, a point index covers **exactly one** property, so the create tail
/// is the single-property `ON (<var>.<property>)` shape (and there is no analyzer / OPTIONS clause).
fn parse_claimed_point(verb: &str, lex: &mut Lexer<'_>) -> Result<IndexCommand, String> {
    // The next token must be INDEX (CREATE/DROP) or INDEXES (SHOW). `POINT` alone never reaches
    // Cypher, so a wrong follower is an admin syntax error.
    let kw = lex
        .next_tok()?
        .ok_or_else(|| format!("expected INDEX or INDEXES after {verb} POINT"))?;
    let plural = is_keyword(&kw, "INDEXES");
    if !is_keyword(&kw, "INDEX") && !plural {
        return Err(unexpected_generic(
            &kw,
            &format!("INDEX or INDEXES after {verb} POINT"),
        ));
    }

    // `SHOW POINT INDEXES` is dispatched by the unified SHOW-index-filter surface (`rmp` #660), so only
    // CREATE/DROP POINT reach here; the plural INDEXES form is therefore always an error.
    if plural {
        return Err(format!(
            "expected INDEX after {verb} POINT (SHOW POINT INDEXES is the only plural form)"
        ));
    }

    match verb {
        "DROP" => {
            // A point-index DROP always names its target.
            let name = expect_name(lex, "a point index name", "POINT")?;
            // `IF EXISTS` (`rmp` #661) turns a missing index into a no-op success.
            let if_exists = parse_optional_if(lex, /* with_not */ false)?;
            expect_end(lex, "DROP POINT INDEX")?;
            Ok(IndexCommand::DropPointIndex { name, if_exists })
        }
        "CREATE" => {
            // The name is OPTIONAL (`rmp` #661, Neo4j parity): a bare `FOR`/`IF` directly after INDEX
            // means "unnamed" → a deterministic auto-name derived from the covered schema. `IF NOT
            // EXISTS` follows the (optional) name, before the `FOR` clause (Neo4j position).
            let explicit_name = parse_optional_point_index_name(lex)?;
            let if_not_exists = parse_optional_if(lex, /* with_not */ true)?;
            let (entity, label, property) = parse_point_create_tail(lex)?;
            let name =
                explicit_name.unwrap_or_else(|| auto_point_index_name(entity, &label, &property));
            Ok(IndexCommand::CreatePointIndex {
                name,
                entity,
                label,
                property,
                if_not_exists,
            })
        }
        // `parse_admin_statement` only routes CREATE/DROP/SHOW here; START/STOP never reach this.
        other => Err(format!("unsupported point index verb {other}")),
    }
}

/// Parses the OPTIONAL point-index name in `CREATE POINT INDEX [name] …` (`rmp` #661). Returns [`None`]
/// (consuming nothing) when the next token is a bare `FOR` or `IF` — i.e. the name was omitted and a
/// deterministic auto-name applies — otherwise consumes and returns the explicit name. A backtick-quoted
/// `` `FOR` `` / `` `IF` `` is still a name (only the bare keyword signals "unnamed"). Mirrors
/// [`parse_optional_constraint_name`].
fn parse_optional_point_index_name(lex: &mut Lexer<'_>) -> Result<Option<String>, String> {
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    if let Some(Tok::Word(w)) = peek.next_tok()? {
        if w.eq_ignore_ascii_case("FOR") || w.eq_ignore_ascii_case("IF") {
            return Ok(None);
        }
    }
    Ok(Some(expect_name(lex, "a point index name", "POINT")?))
}

/// A deterministic auto-name for an anonymous point index on `(entity, label_or_type, property)`
/// (`rmp` tasks #661, #664), `point_index_<label>_<property>` for a node index and
/// `point_index_rel_<type>_<property>` for a relationship index (the `rel_` infix keeps a node and a
/// relationship point index over numerically-colliding tokens from auto-naming to the same string) — so
/// a repeated anonymous `CREATE POINT INDEX … IF NOT EXISTS` resolves to the same name (idempotent) and
/// `SHOW INDEXES` reports a stable name. A cross-catalog name collision is caught by the engine's global
/// name-uniqueness check.
fn auto_point_index_name(entity: SpatialEntity, label_or_type: &str, property: &str) -> String {
    if entity.is_relationship() {
        format!("point_index_rel_{label_or_type}_{property}")
    } else {
        format!("point_index_{label_or_type}_{property}")
    }
}

/// Parses the `FOR (<var>:<Label>) ON (<var>.<property>)` (node) or
/// `FOR ()-[<var>:<Type>]-() ON (<var>.<property>)` (relationship) tail of a `CREATE POINT INDEX <name>`
/// statement (`rmp` tasks #98, #664). Returns `(entity, label_or_type, property)`. Mirrors the
/// openCypher node-property `FOR … ON …` shape (a single property, single label/type), reusing
/// [`parse_property_ref`]. Like the full-text and constraint surfaces, only the **undirected**
/// relationship form is accepted (a directed `->` / `<-` arrow is a syntax error).
fn parse_point_create_tail(lex: &mut Lexer<'_>) -> Result<(SpatialEntity, String, String), String> {
    const VERB: &str = "POINT";
    // FOR <node or relationship pattern>
    expect_keyword(lex, "FOR", VERB)?;
    let (entity, label_or_type) = parse_point_pattern(lex)?;
    // ON ( <var>.<property> )
    expect_keyword(lex, "ON", VERB)?;
    expect_symbol(lex, '(', VERB)?;
    let property = parse_property_ref(VERB, lex)?;
    expect_symbol(lex, ')', VERB)?;
    // Optional trailing `OPTIONS { indexConfig: { 'spatial.cartesian.min': [ … ], … } }` (`rmp` #661):
    // parsed + validated structurally, then accepted-and-ignored (the spatial config is not yet applied
    // — a follow-up; the clause must nonetheless parse without error for Neo4j-DDL compatibility).
    parse_optional_index_options(lex)?;
    expect_end(lex, "CREATE POINT INDEX")?;
    Ok((entity, label_or_type, property))
}

/// Parses a point index `FOR` pattern (`rmp` task #664): a node pattern `(<var>:<Label>)` or an
/// undirected relationship pattern `()-[<var>:<Type>]-()`, returning the [`SpatialEntity`] and the
/// single covered label/type. Unlike the full-text pattern a point index covers a **single** label/type
/// (no `A|B` union). A directed relationship arrow (`->` / `<-`) is a syntax error (only the undirected
/// form is accepted, like the full-text / constraint surfaces). Mirrors [`parse_fulltext_pattern`].
fn parse_point_pattern(lex: &mut Lexer<'_>) -> Result<(SpatialEntity, String), String> {
    const VERB: &str = "POINT";
    expect_symbol(lex, '(', VERB)?;
    // A relationship pattern opens with an empty node `()`.
    if peek_symbol(lex, ')')? {
        // ()-[ <var> : <Type> ]-()
        expect_symbol(lex, ')', VERB)?; // close the empty start node
        expect_dash(lex, VERB)?;
        expect_symbol(lex, '[', VERB)?;
        let _var = expect_word(lex, "a variable", VERB)?;
        expect_symbol(lex, ':', VERB)?;
        let rel_type = expect_name(lex, "a relationship type", VERB)?;
        expect_symbol(lex, ']', VERB)?;
        expect_dash(lex, VERB)?;
        expect_symbol(lex, '(', VERB)?;
        expect_symbol(lex, ')', VERB)?;
        return Ok((SpatialEntity::Relationship, rel_type));
    }
    // (<var> : <Label>)
    let _var = expect_word(lex, "a variable", VERB)?;
    expect_symbol(lex, ':', VERB)?;
    let label = expect_name(lex, "a label", VERB)?;
    expect_symbol(lex, ')', VERB)?;
    Ok((SpatialEntity::Node, label))
}

// ------------------------------------------------------------------------------------------------
// Vector (HNSW) index surface (`rmp` task #671)
// ------------------------------------------------------------------------------------------------

/// The validated `indexConfig` of a `CREATE VECTOR INDEX … OPTIONS { indexConfig: { … } }` clause
/// (`rmp` task #671): the embedding [`dimensions`](Self::dimensions), the [`similarity`](Self::similarity)
/// metric and the HNSW [`m`](Self::m) / [`ef_construction`](Self::ef_construction) build parameters.
struct VectorOptions {
    dimensions: usize,
    similarity: VectorSimilarity,
    m: usize,
    ef_construction: usize,
}

/// The default HNSW `vector.hnsw.m` when omitted (`rmp` task #671, Neo4j parity).
const DEFAULT_VECTOR_M: usize = 16;
/// The default HNSW `vector.hnsw.ef_construction` when omitted (`rmp` task #671, Neo4j parity).
const DEFAULT_VECTOR_EF_CONSTRUCTION: usize = 100;
/// The maximum embedding dimension a vector index accepts (`rmp` task #671, Neo4j parity).
const MAX_VECTOR_DIMENSIONS: i64 = 4096;

/// Parses the remainder of a claimed **vector (HNSW)** index statement (`verb` + `VECTOR` already read),
/// for the two mutating shapes (`rmp` task #671):
///
/// ```text
/// CREATE VECTOR INDEX [<name>] [IF NOT EXISTS] FOR (<var>:<Label>) ON (<var>.<prop>)
///        OPTIONS { indexConfig: { `vector.dimensions`: <int>, `vector.similarity_function`: '<metric>' [, …] } }
/// CREATE VECTOR INDEX [<name>] [IF NOT EXISTS] FOR ()-[<var>:<Type>]-() ON (<var>.<prop>) OPTIONS { … }
/// DROP   VECTOR INDEX <name> [IF EXISTS]
/// ```
///
/// A vector index is identified by **name** (Neo4j-compatible), like the other named index kinds; the
/// name is optional on `CREATE` (a deterministic auto-name applies, `rmp` #669). `SHOW VECTOR INDEXES`
/// is dispatched earlier by the unified SHOW-index-filter surface (`rmp` #660), so the plural `INDEXES`
/// never reaches here.
fn parse_claimed_vector(verb: &str, lex: &mut Lexer<'_>) -> Result<IndexCommand, String> {
    // The next token must be INDEX (CREATE/DROP) or INDEXES (SHOW). `VECTOR` alone never reaches Cypher,
    // so a wrong follower is an admin syntax error.
    let kw = lex
        .next_tok()?
        .ok_or_else(|| format!("expected INDEX or INDEXES after {verb} VECTOR"))?;
    let plural = is_keyword(&kw, "INDEXES");
    if !is_keyword(&kw, "INDEX") && !plural {
        return Err(unexpected_generic(
            &kw,
            &format!("INDEX or INDEXES after {verb} VECTOR"),
        ));
    }
    // `SHOW VECTOR INDEXES` is dispatched by the unified SHOW-index-filter surface (`rmp` #660), so only
    // CREATE/DROP VECTOR reach here; the plural INDEXES form is therefore always an error.
    if plural {
        return Err(format!(
            "expected INDEX after {verb} VECTOR (SHOW VECTOR INDEXES is the only plural form)"
        ));
    }

    match verb {
        "DROP" => {
            // A vector-index DROP always names its target.
            let name = expect_name(lex, "a vector index name", "VECTOR")?;
            // `IF EXISTS` turns a missing index into a no-op success.
            let if_exists = parse_optional_if(lex, /* with_not */ false)?;
            expect_end(lex, "DROP VECTOR INDEX")?;
            Ok(IndexCommand::DropVectorIndex { name, if_exists })
        }
        "CREATE" => {
            // The name is OPTIONAL (`rmp` #669, Neo4j parity): a bare `FOR`/`IF` directly after INDEX
            // means "unnamed" → the coordinator derives a deterministic auto-name. `IF NOT EXISTS`
            // follows the (optional) name, before the `FOR` clause (Neo4j position).
            let name = parse_optional_vector_index_name(lex)?;
            let if_not_exists = parse_optional_if(lex, /* with_not */ true)?;
            let (entity, label_or_type, property, opts) = parse_vector_create_tail(lex)?;
            Ok(IndexCommand::CreateVectorIndex {
                name,
                entity,
                label_or_type,
                property,
                dimensions: opts.dimensions,
                similarity: opts.similarity,
                m: opts.m,
                ef_construction: opts.ef_construction,
                if_not_exists,
            })
        }
        // `parse_admin_statement` only routes CREATE/DROP/SHOW here; START/STOP never reach this.
        other => Err(format!("unsupported vector index verb {other}")),
    }
}

/// Parses the OPTIONAL vector-index name in `CREATE VECTOR INDEX [name] …` (`rmp` task #671). Returns
/// [`None`] (consuming nothing) when the next token is a bare `FOR` or `IF` — i.e. the name was omitted
/// and the coordinator auto-names — otherwise consumes and returns the explicit name. A backtick-quoted
/// `` `FOR` `` / `` `IF` `` is still a name. Mirrors [`parse_optional_point_index_name`].
fn parse_optional_vector_index_name(lex: &mut Lexer<'_>) -> Result<Option<String>, String> {
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    if let Some(Tok::Word(w)) = peek.next_tok()? {
        if w.eq_ignore_ascii_case("FOR") || w.eq_ignore_ascii_case("IF") {
            return Ok(None);
        }
    }
    Ok(Some(expect_name(lex, "a vector index name", "VECTOR")?))
}

/// Parses the `FOR (<var>:<Label>) ON (<var>.<property>) OPTIONS { … }` (node) or
/// `FOR ()-[<var>:<Type>]-() ON (<var>.<property>) OPTIONS { … }` (relationship) tail of a
/// `CREATE VECTOR INDEX <name>` statement (`rmp` task #671). Returns `(entity, label_or_type, property,
/// options)`. The `OPTIONS { indexConfig: { … } }` clause is **required** (the embedding dimensions and
/// similarity metric can only be given there, and both are mandatory). Only the **undirected**
/// relationship form is accepted (a directed `->` / `<-` arrow is a syntax error), like the other index
/// surfaces.
fn parse_vector_create_tail(
    lex: &mut Lexer<'_>,
) -> Result<(VectorEntity, String, String, VectorOptions), String> {
    const VERB: &str = "VECTOR";
    // FOR <node or relationship pattern>
    expect_keyword(lex, "FOR", VERB)?;
    let (entity, label_or_type) = parse_vector_pattern(lex)?;
    // ON ( <var>.<property> )
    expect_keyword(lex, "ON", VERB)?;
    expect_symbol(lex, '(', VERB)?;
    let property = parse_property_ref(VERB, lex)?;
    expect_symbol(lex, ')', VERB)?;
    // OPTIONS { indexConfig: { … } } — REQUIRED (carries the mandatory dimensions + similarity).
    let options = parse_vector_index_options(lex)?;
    expect_end(lex, "CREATE VECTOR INDEX")?;
    Ok((entity, label_or_type, property, options))
}

/// Parses a vector index `FOR` pattern (`rmp` task #671): a node pattern `(<var>:<Label>)` or an
/// undirected relationship pattern `()-[<var>:<Type>]-()`, returning the [`VectorEntity`] and the single
/// covered label/type. A directed relationship arrow (`->` / `<-`) is a syntax error. Mirrors
/// [`parse_point_pattern`].
fn parse_vector_pattern(lex: &mut Lexer<'_>) -> Result<(VectorEntity, String), String> {
    const VERB: &str = "VECTOR";
    expect_symbol(lex, '(', VERB)?;
    // A relationship pattern opens with an empty node `()`.
    if peek_symbol(lex, ')')? {
        // ()-[ <var> : <Type> ]-()
        expect_symbol(lex, ')', VERB)?; // close the empty start node
        expect_dash(lex, VERB)?;
        expect_symbol(lex, '[', VERB)?;
        let _var = expect_word(lex, "a variable", VERB)?;
        expect_symbol(lex, ':', VERB)?;
        let rel_type = expect_name(lex, "a relationship type", VERB)?;
        expect_symbol(lex, ']', VERB)?;
        expect_dash(lex, VERB)?;
        expect_symbol(lex, '(', VERB)?;
        expect_symbol(lex, ')', VERB)?;
        return Ok((VectorEntity::Relationship, rel_type));
    }
    // (<var> : <Label>)
    let _var = expect_word(lex, "a variable", VERB)?;
    expect_symbol(lex, ':', VERB)?;
    let label = expect_name(lex, "a label", VERB)?;
    expect_symbol(lex, ')', VERB)?;
    Ok((VectorEntity::Node, label))
}

/// Parses the **required** `OPTIONS { [indexProvider: '<str>',] indexConfig: { … } }` clause of a
/// `CREATE VECTOR INDEX` and validates the embedding shape (`rmp` task #671), reusing the shared
/// OPTIONS-map machinery (`rmp` #661).
///
/// The `indexConfig` map's recognised keys are:
/// - `` `vector.dimensions` `` — **required** integer, validated to `1..=4096`;
/// - `` `vector.similarity_function` `` — **required** string, `'cosine'` / `'euclidean'`
///   (case-insensitive);
/// - `` `vector.hnsw.m` `` — optional positive integer, default `16`;
/// - `` `vector.hnsw.ef_construction` `` — optional positive integer, default `100`.
///
/// A top-level `indexProvider` string is accepted and ignored (Graphus has a single built-in provider);
/// an unknown **top-level** OPTIONS key is a clear error (matching the range/text/point OPTIONS parser).
/// An unknown `indexConfig` key is **accepted and ignored** (Neo4j leniency, matching #661's lenient
/// treatment of `indexConfig` entries). A missing OPTIONS clause, a missing `indexConfig`, a missing
/// required key, an out-of-range dimension, an unknown similarity or a non-positive HNSW parameter are
/// each a clear, side-effect-free error.
fn parse_vector_index_options(lex: &mut Lexer<'_>) -> Result<VectorOptions, String> {
    if !consume_options_keyword(lex)? {
        return Err(
            "CREATE VECTOR INDEX requires an OPTIONS { indexConfig: { `vector.dimensions`: <int>, \
             `vector.similarity_function`: 'cosine'|'euclidean' } } clause"
                .to_owned(),
        );
    }
    expect_options_symbol(lex, '{')?;
    let mut index_config: Option<Vec<(String, OptionValue)>> = None;
    for (key, value) in parse_option_map_body(lex)? {
        match key.to_ascii_lowercase().as_str() {
            "indexprovider" => {
                let _ = as_option_string(&value, "indexProvider")?;
            }
            "indexconfig" => {
                index_config = Some(as_option_map(&value, "indexConfig")?.to_vec());
            }
            other => {
                return Err(format!(
                    "unknown vector index OPTIONS key `{other}`; expected indexProvider or indexConfig"
                ));
            }
        }
    }
    let config = index_config.ok_or_else(|| {
        "CREATE VECTOR INDEX requires an `indexConfig` map inside OPTIONS { … }".to_owned()
    })?;

    let mut dimensions: Option<i64> = None;
    let mut similarity: Option<VectorSimilarity> = None;
    let mut m: Option<usize> = None;
    let mut ef_construction: Option<usize> = None;
    for (key, value) in &config {
        match key.to_ascii_lowercase().as_str() {
            "vector.dimensions" => {
                dimensions = Some(as_option_integer(value, "vector.dimensions")?);
            }
            "vector.similarity_function" => {
                let name = as_option_string(value, "vector.similarity_function")?;
                similarity = Some(parse_vector_similarity(&name)?);
            }
            "vector.hnsw.m" => {
                m = Some(positive_hnsw_param(
                    as_option_integer(value, "vector.hnsw.m")?,
                    "vector.hnsw.m",
                )?);
            }
            "vector.hnsw.ef_construction" => {
                ef_construction = Some(positive_hnsw_param(
                    as_option_integer(value, "vector.hnsw.ef_construction")?,
                    "vector.hnsw.ef_construction",
                )?);
            }
            // Unknown `indexConfig` keys are accepted and ignored (Neo4j leniency, `rmp` #661).
            _ => {}
        }
    }

    let dimensions = dimensions.ok_or_else(|| {
        "CREATE VECTOR INDEX requires `vector.dimensions` in its indexConfig".to_owned()
    })?;
    if !(1..=MAX_VECTOR_DIMENSIONS).contains(&dimensions) {
        return Err(format!(
            "`vector.dimensions` must be between 1 and {MAX_VECTOR_DIMENSIONS}, got {dimensions}"
        ));
    }
    let similarity = similarity.ok_or_else(|| {
        "CREATE VECTOR INDEX requires `vector.similarity_function` in its indexConfig".to_owned()
    })?;
    Ok(VectorOptions {
        // The `1..=MAX_VECTOR_DIMENSIONS` range check guarantees a lossless `usize` cast.
        dimensions: dimensions as usize,
        similarity,
        m: m.unwrap_or(DEFAULT_VECTOR_M),
        ef_construction: ef_construction.unwrap_or(DEFAULT_VECTOR_EF_CONSTRUCTION),
    })
}

/// Validates an HNSW build parameter (`vector.hnsw.m` / `vector.hnsw.ef_construction`) is a positive
/// integer, returning it as a `usize` (`rmp` task #671). A non-positive value is a clear error.
fn positive_hnsw_param(value: i64, key: &str) -> Result<usize, String> {
    if value < 1 {
        return Err(format!("`{key}` must be a positive integer, got {value}"));
    }
    Ok(value as usize)
}

/// Maps a `vector.similarity_function` string to a [`VectorSimilarity`] (`rmp` task #671),
/// case-insensitively. `'cosine'` → [`Cosine`](VectorSimilarity::Cosine), `'euclidean'` →
/// [`Euclidean`](VectorSimilarity::Euclidean); anything else is a clear error.
fn parse_vector_similarity(name: &str) -> Result<VectorSimilarity, String> {
    match name.to_ascii_lowercase().as_str() {
        "cosine" => Ok(VectorSimilarity::Cosine),
        "euclidean" => Ok(VectorSimilarity::Euclidean),
        other => Err(format!(
            "unknown `vector.similarity_function` {other:?}; expected 'cosine' or 'euclidean'"
        )),
    }
}

/// Requires `value` to be a bare integer token (`rmp` task #671); errors naming the `key` otherwise.
/// A negative integer lexes as a single `-…` word, so it parses here and is range-checked by the caller.
fn as_option_integer(value: &OptionValue, key: &str) -> Result<i64, String> {
    match value {
        OptionValue::Word(w) => w
            .parse::<i64>()
            .map_err(|_| format!("OPTIONS `{key}` expects an integer value, got `{w}`")),
        _ => Err(format!("OPTIONS `{key}` expects an integer value")),
    }
}

/// Parses the remainder of a claimed **constraint** statement (`verb` + `CONSTRAINT`/`CONSTRAINTS`
/// already read; `or_replace` set when a `CREATE OR REPLACE` prefix was consumed), for the shapes
/// (`rmp` tasks #99, #100, #638):
///
/// ```text
/// CREATE [OR REPLACE] CONSTRAINT <name> [IF NOT EXISTS] FOR (<var>:<Label>) REQUIRE <var>.<prop> IS [NODE] UNIQUE
/// CREATE [OR REPLACE] CONSTRAINT <name> [IF NOT EXISTS] FOR (<var>:<Label>) REQUIRE <var>.<prop> IS NOT NULL
/// CREATE [OR REPLACE] CONSTRAINT <name> [IF NOT EXISTS] FOR (<var>:<Label>) REQUIRE (<var>.a, …) IS [NODE] KEY
/// CREATE [OR REPLACE] CONSTRAINT <name> [IF NOT EXISTS] FOR (<var>:<Label>) REQUIRE <var>.<prop> IS :: <TYPE>
/// DROP   CONSTRAINT <name> [IF EXISTS]
/// SHOW   CONSTRAINTS
/// ```
///
/// A constraint is identified by **name** (Neo4j-compatible), like a full-text / point index. The
/// `REQUIRE … IS …` tail distinguishes the kind; the `<var>` text is irrelevant (single-variable
/// shape, reusing [`parse_property_ref`]). `<TYPE>` is an openCypher type name — `INTEGER`, `FLOAT`,
/// `STRING`, `BOOLEAN`, or `LIST<…>` — parsed by [`parse_constraint_type`]. `IF NOT EXISTS` and
/// `OR REPLACE` are mutually exclusive (`rmp` #638). The relationship pattern (`FOR ()-[r:TYPE]-()`)
/// lands in a follow-up slice of `rmp` #638 (rejected with a clear message for now).
fn parse_claimed_constraint(
    verb: &str,
    plural: bool,
    or_replace: bool,
    lex: &mut Lexer<'_>,
) -> Result<ConstraintCommand, String> {
    if plural {
        // SHOW CONSTRAINTS — the unfiltered listing (filter = All), plus an optional YIELD/WHERE tail
        // (`rmp` #653). The filtered forms (`SHOW <filter> CONSTRAINT[S]`) are dispatched earlier.
        let tail = capture_show_tail(lex, "SHOW CONSTRAINTS")?;
        return Ok(ConstraintCommand::Show {
            filter: ConstraintTypeFilter::All,
            tail,
        });
    }
    if verb == "SHOW" {
        // `SHOW CONSTRAINT` (singular) is not a recognised form; only the plural `SHOW CONSTRAINTS`.
        return Err(
            "expected SHOW CONSTRAINTS (the singular SHOW CONSTRAINT is not supported)".to_owned(),
        );
    }

    match verb {
        "DROP" => {
            // `DROP CONSTRAINT <name>` always names its target.
            let name = expect_name(lex, "a constraint name", "CONSTRAINT")?;
            let if_exists = parse_optional_if(lex, /* with_not */ false)?;
            expect_end(lex, "DROP CONSTRAINT")?;
            Ok(ConstraintCommand::Drop { name, if_exists })
        }
        "CREATE" => {
            // The name is OPTIONAL (`rmp` #654): Neo4j auto-generates one when omitted, so a bare
            // `FOR`/`IF` directly after `CONSTRAINT` means "unnamed". `IF NOT EXISTS` follows the name
            // (Neo4j positions it there); `OR REPLACE` was consumed by the dispatcher before the
            // surface keyword. The two are mutually exclusive.
            let explicit_name = parse_optional_constraint_name(lex)?;
            let if_not_exists = parse_optional_if(lex, /* with_not */ true)?;
            if or_replace && if_not_exists {
                return Err(
                    "CREATE CONSTRAINT cannot combine OR REPLACE with IF NOT EXISTS".to_owned(),
                );
            }
            let (entity, properties, kind) = parse_constraint_create_tail(lex)?;
            // An omitted name is filled in with a deterministic auto-generated name derived from the
            // constraint's schema, so `IF NOT EXISTS` stays idempotent and `SHOW CONSTRAINTS` reports a
            // stable name (`rmp` #654).
            let name =
                explicit_name.unwrap_or_else(|| auto_constraint_name(&entity, &properties, &kind));
            Ok(ConstraintCommand::Create(CreateConstraint {
                name,
                entity,
                properties,
                kind,
                if_not_exists,
                or_replace,
            }))
        }
        // `parse_admin_statement` only routes CREATE/DROP/SHOW here; START/STOP never reach this.
        other => Err(format!("unsupported constraint verb {other}")),
    }
}

/// Whether `tok` is a leading word of a `SHOW INDEXES` **type filter** (`rmp` #660) — `ALL` / `RANGE` /
/// `TEXT` / `POINT` / `LOOKUP` / `FULLTEXT` / `VECTOR` — as opposed to the bare `INDEXES` keyword (which
/// routes through `parse_claimed_index`). Only meaningful right after `SHOW`.
fn is_index_filter_lead(tok: &Tok) -> bool {
    matches!(tok, Tok::Word(w) if matches!(
        w.to_ascii_uppercase().as_str(),
        "ALL" | "RANGE" | "TEXT" | "POINT" | "LOOKUP" | "FULLTEXT" | "VECTOR"
    ))
}

/// Whether a `SHOW <lead> …` statement targets INDEXES rather than constraints (`rmp` #660). Only the
/// shared `ALL` lead is ambiguous (it is both an index and a constraint filter); every other index
/// filter lead is unambiguously an index statement. For `ALL`, peek the terminal keyword: `INDEX[ES]`
/// selects the index surface, otherwise the statement defers to the constraint filter surface. The peek
/// is on a clone, so it does not consume from `lex`.
fn show_targets_indexes(lead: &Tok, lex: &Lexer<'_>) -> bool {
    if !is_keyword(lead, "ALL") {
        return true;
    }
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    matches!(peek.next_tok(), Ok(Some(t)) if is_keyword(&t, "INDEX") || is_keyword(&t, "INDEXES"))
}

/// Parses a filtered `SHOW <filter> INDEX[ES] [YIELD … | WHERE …]` (`rmp` #660, #661); `first` is the
/// already-read leading filter word. Either the plural `INDEXES` or the singular `INDEX` closes the
/// filter — Neo4j accepts `INDEX[ES]` and the singular behaves identically (`rmp` #661) — then the
/// optional tail is captured verbatim (`crate::engine::index_show` translates it).
fn parse_show_indexes_filtered(first: &Tok, lex: &mut Lexer<'_>) -> Result<IndexCommand, String> {
    let filter = index_type_filter_from_lead(first)?;
    // The INDEX / INDEXES keyword closes the filter.
    let kw = lex
        .next_tok()?
        .ok_or_else(|| "expected INDEX or INDEXES after the SHOW INDEXES filter".to_owned())?;
    if !is_keyword(&kw, "INDEXES") && !is_keyword(&kw, "INDEX") {
        return Err(unexpected_generic(
            &kw,
            "INDEX or INDEXES after the SHOW INDEXES filter",
        ));
    }
    let tail = capture_show_tail(lex, "SHOW INDEXES")?;
    Ok(IndexCommand::ShowIndexes { filter, tail })
}

/// Maps a `SHOW INDEXES` filter lead word to its [`IndexTypeFilter`] (`rmp` #660). Each index filter is
/// a single standalone word (unlike the multi-word `SHOW CONSTRAINTS` filters).
fn index_type_filter_from_lead(tok: &Tok) -> Result<IndexTypeFilter, String> {
    let w = match tok {
        Tok::Word(w) => w.to_ascii_uppercase(),
        other => return Err(unexpected_generic(other, "a SHOW INDEXES filter word")),
    };
    Ok(match w.as_str() {
        "ALL" => IndexTypeFilter::All,
        "RANGE" => IndexTypeFilter::Range,
        "TEXT" => IndexTypeFilter::Text,
        "POINT" => IndexTypeFilter::Point,
        "LOOKUP" => IndexTypeFilter::Lookup,
        "FULLTEXT" => IndexTypeFilter::Fulltext,
        "VECTOR" => IndexTypeFilter::Vector,
        other => return Err(format!("unexpected `{other}` in the SHOW INDEXES filter")),
    })
}

/// Whether `tok` is a leading word of a `SHOW CONSTRAINTS` **type filter** (`rmp` #653) — `ALL` /
/// `NODE` / `REL[ATIONSHIP]` / `PROPERTY` / `UNIQUE[NESS]` / `EXIST[ENCE]` / `KEY` / `TYPE` — as opposed
/// to the bare `CONSTRAINT`/`CONSTRAINTS` keyword (which routes through `parse_claimed_constraint`).
/// Only meaningful right after `SHOW`.
fn is_constraint_filter_lead(tok: &Tok) -> bool {
    matches!(tok, Tok::Word(w) if matches!(
        w.to_ascii_uppercase().as_str(),
        "ALL" | "NODE" | "REL" | "RELATIONSHIP" | "PROPERTY"
            | "UNIQUE" | "UNIQUENESS" | "EXIST" | "EXISTENCE" | "KEY" | "TYPE"
    ))
}

/// Parses a filtered `SHOW <filter> CONSTRAINT[S] [YIELD … | WHERE …]` (`rmp` #653); `first` is the
/// already-read leading filter word. Both the singular `CONSTRAINT` and the plural `CONSTRAINTS` are
/// accepted for the filtered forms (matching Neo4j's `CONSTRAINT[S]`), then the optional tail is
/// captured verbatim.
fn parse_show_constraints_filtered(
    first: &Tok,
    lex: &mut Lexer<'_>,
) -> Result<ConstraintCommand, String> {
    let filter = parse_constraint_type_filter(first, lex)?;
    // The CONSTRAINT / CONSTRAINTS keyword closes the filter.
    let kw = lex.next_tok()?.ok_or_else(|| {
        "expected CONSTRAINT or CONSTRAINTS after the SHOW CONSTRAINTS filter".to_owned()
    })?;
    if !is_keyword(&kw, "CONSTRAINT") && !is_keyword(&kw, "CONSTRAINTS") {
        return Err(unexpected_generic(
            &kw,
            "CONSTRAINT or CONSTRAINTS after the SHOW CONSTRAINTS filter",
        ));
    }
    let tail = capture_show_tail(lex, "SHOW CONSTRAINTS")?;
    Ok(ConstraintCommand::Show { filter, tail })
}

/// Parses the `SHOW CONSTRAINTS` type-filter words (`rmp` #653), leaving the lexer positioned at the
/// closing `CONSTRAINT[S]` keyword. `first` is the already-read leading word. The grammar is an optional
/// entity (`NODE` / `REL[ATIONSHIP]`), an optional `PROPERTY`, and a terminal category
/// (`UNIQUE[NESS]` / `EXIST[ENCE]` / `KEY` / `TYPE`); `ALL` is a standalone filter. `KEY` rejects a
/// preceding `PROPERTY` and `TYPE` requires one, matching Neo4j's forms.
fn parse_constraint_type_filter(
    first: &Tok,
    lex: &mut Lexer<'_>,
) -> Result<ConstraintTypeFilter, String> {
    #[derive(Clone, Copy)]
    enum Ent {
        Node,
        Rel,
    }
    let mut entity: Option<Ent> = None;
    let mut property = false;
    let mut cur = first.clone();
    loop {
        let w = match &cur {
            Tok::Word(w) => w.to_ascii_uppercase(),
            other => return Err(unexpected_generic(other, "a SHOW CONSTRAINTS filter word")),
        };
        match w.as_str() {
            // `ALL` is a standalone filter: it selects every kind and takes no further words.
            "ALL" => return Ok(ConstraintTypeFilter::All),
            "NODE" => {
                if entity.is_some() || property {
                    return Err("unexpected NODE in the SHOW CONSTRAINTS filter".to_owned());
                }
                entity = Some(Ent::Node);
            }
            "REL" | "RELATIONSHIP" => {
                if entity.is_some() || property {
                    return Err("unexpected RELATIONSHIP in the SHOW CONSTRAINTS filter".to_owned());
                }
                entity = Some(Ent::Rel);
            }
            "PROPERTY" => {
                if property {
                    return Err(
                        "unexpected repeated PROPERTY in the SHOW CONSTRAINTS filter".to_owned(),
                    );
                }
                property = true;
            }
            "UNIQUE" | "UNIQUENESS" => {
                return Ok(match entity {
                    None => ConstraintTypeFilter::Unique,
                    Some(Ent::Node) => ConstraintTypeFilter::NodeUnique,
                    Some(Ent::Rel) => ConstraintTypeFilter::RelUnique,
                });
            }
            "EXIST" | "EXISTENCE" => {
                return Ok(match entity {
                    None => ConstraintTypeFilter::Existence,
                    Some(Ent::Node) => ConstraintTypeFilter::NodeExistence,
                    Some(Ent::Rel) => ConstraintTypeFilter::RelExistence,
                });
            }
            "KEY" => {
                if property {
                    return Err(
                        "KEY constraints are not property constraints (drop PROPERTY before KEY)"
                            .to_owned(),
                    );
                }
                return Ok(match entity {
                    None => ConstraintTypeFilter::Key,
                    Some(Ent::Node) => ConstraintTypeFilter::NodeKey,
                    Some(Ent::Rel) => ConstraintTypeFilter::RelKey,
                });
            }
            "TYPE" => {
                if !property {
                    return Err(
                        "expected PROPERTY before TYPE in the SHOW CONSTRAINTS filter".to_owned(),
                    );
                }
                return Ok(match entity {
                    None => ConstraintTypeFilter::PropertyType,
                    Some(Ent::Node) => ConstraintTypeFilter::NodePropertyType,
                    Some(Ent::Rel) => ConstraintTypeFilter::RelPropertyType,
                });
            }
            // The CONSTRAINT keyword arrived before a terminal category — the filter is incomplete.
            "CONSTRAINT" | "CONSTRAINTS" => {
                return Err(
                    "expected a constraint category (UNIQUENESS, EXISTENCE, KEY or PROPERTY TYPE) \
                     in the SHOW CONSTRAINTS filter"
                        .to_owned(),
                );
            }
            other => {
                return Err(format!(
                    "unexpected `{other}` in the SHOW CONSTRAINTS filter"
                ));
            }
        }
        // A prefix (NODE / REL / PROPERTY) was consumed; read the next filter word. A terminal category
        // returns above, so reaching here means more filter words must follow before CONSTRAINT[S].
        cur = lex.next_tok()?.ok_or_else(|| {
            "expected a constraint category after the SHOW CONSTRAINTS filter prefix".to_owned()
        })?;
    }
}

/// Captures the optional `YIELD … | WHERE …` tail of a `SHOW <what>` listing statement (`rmp` #653 for
/// constraints, #660 for indexes), **without** consuming it from `lex` (so the raw text is preserved).
/// `what` is the statement label used in error messages (e.g. `"SHOW CONSTRAINTS"` / `"SHOW INDEXES"`).
/// Returns:
///
/// - [`None`] for the end of the statement (or a lone tolerated trailing `;`);
/// - `Some(raw)` — the raw tail text (a single trailing `;` stripped) — when it begins with `YIELD` or
///   `WHERE`;
/// - an error for anything else (so `SHOW CONSTRAINTS garbage` / `SHOW INDEXES garbage` stays a syntax
///   error).
///
/// The tail is handed to the seams verbatim, which translate `YIELD`/`WHERE`/`RETURN` into a Cypher
/// read query re-run over the rendered rows (`crate::engine::constraint_show` / `index_show`).
fn capture_show_tail(lex: &mut Lexer<'_>, what: &str) -> Result<Option<String>, String> {
    // Peek the first token of the tail on a clone so the raw capture below still sees the whole tail.
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    match peek.next_tok()? {
        None => Ok(None),
        // A lone trailing `;` is tolerated (as `expect_end` does); nothing may follow it.
        Some(Tok::Symbol(';')) => match peek.next_tok()? {
            None => Ok(None),
            Some(t) => Err(unexpected(&t, &format!("end of {what} statement"))),
        },
        Some(Tok::Word(w))
            if w.eq_ignore_ascii_case("YIELD") || w.eq_ignore_ascii_case("WHERE") =>
        {
            let raw = lex.rest.as_str().trim();
            let raw = match raw.strip_suffix(';') {
                Some(head) => head.trim_end(),
                None => raw,
            };
            Ok(Some(raw.to_owned()))
        }
        Some(other) => Err(unexpected(
            &other,
            &format!("YIELD or WHERE after {what}, or the end of the statement"),
        )),
    }
}

/// Parses the OPTIONAL constraint name in `CREATE CONSTRAINT [name] …` (`rmp` #654). Returns [`None`]
/// (consuming nothing) when the next token is a bare `FOR` or `IF` — i.e. the name was omitted and
/// Neo4j-style auto-naming applies; otherwise consumes and returns the explicit name. A backtick-quoted
/// `` `FOR` `` / `` `IF` `` is still a name (only the bare keyword signals "unnamed").
fn parse_optional_constraint_name(lex: &mut Lexer<'_>) -> Result<Option<String>, String> {
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    if let Some(Tok::Word(w)) = peek.next_tok()? {
        if w.eq_ignore_ascii_case("FOR") || w.eq_ignore_ascii_case("IF") {
            return Ok(None);
        }
    }
    Ok(Some(expect_name(lex, "a constraint name", "CONSTRAINT")?))
}

/// A deterministic auto-generated constraint name (`rmp` #654), Neo4j-style `constraint_<hex>`, derived
/// from the constraint's schema (entity kind + covered token + property tuple + kind). Deterministic so
/// that a repeated `CREATE CONSTRAINT … IF NOT EXISTS` (with no name) resolves to the same name and is
/// idempotent, and so a restart re-derives the same name. Uses a stable FNV-1a hash (independent of the
/// std hasher, which is not guaranteed stable across builds).
fn auto_constraint_name(
    entity: &ConstraintEntity,
    properties: &[String],
    kind: &ConstraintCreateKind,
) -> String {
    let (etype, token) = match entity {
        ConstraintEntity::Node { label } => ("node", label.as_str()),
        ConstraintEntity::Relationship { rel_type } => ("rel", rel_type.as_str()),
    };
    let kind_str = match kind {
        ConstraintCreateKind::Unique => "unique".to_owned(),
        ConstraintCreateKind::Existence => "exists".to_owned(),
        ConstraintCreateKind::Key => "key".to_owned(),
        ConstraintCreateKind::PropertyType { declared_type } => {
            format!(
                "type:{}",
                graphus_cypher::constraint::type_descriptor_name(declared_type)
            )
        }
    };
    let canonical = format!("{etype}|{token}|{}|{kind_str}", properties.join(","));
    // FNV-1a 64-bit — a small, stable, dependency-free hash.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in canonical.as_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("constraint_{h:016x}")
}

/// Parses the `FOR <entity> REQUIRE … IS …` tail of a `CREATE CONSTRAINT <name>` statement
/// (`rmp` tasks #99, #100, #638). Returns `(entity, properties, kind)`. Mirrors the openCypher
/// `FOR (n:Label) … (n.prop)` node-property shape, reusing [`parse_property_ref`].
///
/// The `REQUIRE` target is a single bare/parenthesised property (`UNIQUE` / `NOT NULL` / `:: TYPE`) or
/// a parenthesised composite tuple `(n.a, n.b, …)` (only valid with `KEY`). The clause after `IS`
/// selects the kind. A multi-property tuple with any kind other than `KEY` is rejected.
fn parse_constraint_create_tail(
    lex: &mut Lexer<'_>,
) -> Result<(ConstraintEntity, Vec<String>, ConstraintCreateKind), String> {
    const VERB: &str = "CONSTRAINT";
    // FOR <entity-pattern>
    expect_keyword(lex, "FOR", VERB)?;
    let entity = parse_constraint_entity(lex)?;
    // REQUIRE <var>.<property>  — Neo4j uses `REQUIRE`; `ASSERT` is the legacy spelling, also accepted.
    let req = lex
        .next_tok()?
        .ok_or_else(|| "expected REQUIRE in CONSTRAINT".to_owned())?;
    if !is_keyword(&req, "REQUIRE") && !is_keyword(&req, "ASSERT") {
        return Err(unexpected_generic(&req, "REQUIRE in CONSTRAINT"));
    }
    // The property target may be bare (`REQUIRE n.prop`), a parenthesised single property
    // (`REQUIRE (n.prop)`), or a parenthesised composite tuple (`REQUIRE (n.a, n.b, …)`). Read a
    // comma-separated property list; a single bare property is the common single-property case.
    let parenthesised = peek_symbol(lex, '(')?;
    let mut properties = Vec::new();
    if parenthesised {
        expect_symbol(lex, '(', VERB)?;
        loop {
            properties.push(parse_property_ref(VERB, lex)?);
            // A comma continues the tuple; a close-paren ends it.
            if peek_symbol(lex, ',')? {
                expect_symbol(lex, ',', VERB)?;
            } else {
                break;
            }
        }
        expect_symbol(lex, ')', VERB)?;
    } else {
        properties.push(parse_property_ref(VERB, lex)?);
    }
    // IS ( [NODE|REL[ATIONSHIP]] UNIQUE | NOT NULL | [NODE|REL[ATIONSHIP]] KEY | :: <TYPE> | TYPED <TYPE> )
    expect_keyword(lex, "IS", VERB)?;
    let kind = parse_constraint_is_clause(lex, entity.is_relationship())?;
    // Arity: a composite tuple is valid for KEY and for UNIQUE (`rmp` #651 — composite property
    // uniqueness); existence and property-type constraints cover exactly one property.
    if properties.len() != 1
        && matches!(
            kind,
            ConstraintCreateKind::Existence | ConstraintCreateKind::PropertyType { .. }
        )
    {
        return Err(match kind {
            ConstraintCreateKind::Existence => {
                "an existence constraint (IS NOT NULL) covers exactly one property".to_owned()
            }
            ConstraintCreateKind::PropertyType { .. } => {
                "a property-type constraint (IS :: <TYPE>) covers exactly one property".to_owned()
            }
            ConstraintCreateKind::Unique | ConstraintCreateKind::Key => {
                unreachable!("UNIQUE and KEY permit a composite tuple")
            }
        });
    }
    // An optional trailing `OPTIONS { … }` (`rmp` #654): Neo4j attaches a backing-index provider /
    // config here on uniqueness & key constraints. Graphus has a single built-in index provider, so
    // the clause is accepted (for Neo4j-DDL compatibility) and its content ignored.
    skip_optional_options(lex)?;
    expect_end(lex, "CREATE CONSTRAINT")?;
    Ok((entity, properties, kind))
}

/// Consumes an optional trailing `OPTIONS { … }` map clause (`rmp` #654), accepting any well-formed
/// brace-balanced content (nested maps included) and discarding it. A no-op when the next token is not
/// `OPTIONS`. Errors on an unterminated brace group.
fn skip_optional_options(lex: &mut Lexer<'_>) -> Result<(), String> {
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    if !matches!(peek.next_tok()?, Some(t) if is_keyword(&t, "OPTIONS")) {
        return Ok(()); // no OPTIONS clause
    }
    lex.next_tok()?; // consume OPTIONS
    expect_symbol(lex, '{', "CONSTRAINT")?;
    let mut depth = 1usize;
    loop {
        match lex.next_tok()? {
            Some(Tok::Symbol('{')) => depth += 1,
            Some(Tok::Symbol('}')) => {
                depth -= 1;
                if depth == 0 {
                    return Ok(());
                }
            }
            Some(_) => {}
            None => return Err("unterminated OPTIONS { … } in CREATE CONSTRAINT".to_owned()),
        }
    }
}

/// Parses the entity pattern after `FOR` in a `CREATE CONSTRAINT` (`rmp` #638): the node pattern
/// `(<var>:<Label>)` or the (undirected) relationship pattern `()-[<var>:<TYPE>]-()`. The relationship
/// pattern is detected by its leading empty node `()`.
///
/// # Tokenization note
///
/// The lexer treats `-` as a word character, so a lone dash between the empty node and the `[…]`
/// segment lexes as the single word `"-"` (a following `[`/`(` symbol breaks it); [`expect_dash`]
/// consumes exactly that. Only the **undirected** form is accepted (Neo4j's constraint surface); a
/// directed arrow (`->` / `<-`) is a syntax error.
fn parse_constraint_entity(lex: &mut Lexer<'_>) -> Result<ConstraintEntity, String> {
    const VERB: &str = "CONSTRAINT";
    expect_symbol(lex, '(', VERB)?;
    // A relationship constraint pattern opens with an empty node `()`.
    if peek_symbol(lex, ')')? {
        // ()-[ <var> : <TYPE> ]-()
        expect_symbol(lex, ')', VERB)?; // close the empty start node
        expect_dash(lex, VERB)?;
        expect_symbol(lex, '[', VERB)?;
        let _var = expect_word(lex, "a variable", VERB)?;
        expect_symbol(lex, ':', VERB)?;
        let rel_type = expect_name(lex, "a relationship type", VERB)?;
        expect_symbol(lex, ']', VERB)?;
        expect_dash(lex, VERB)?;
        expect_symbol(lex, '(', VERB)?;
        expect_symbol(lex, ')', VERB)?;
        return Ok(ConstraintEntity::Relationship { rel_type });
    }
    let _var = expect_word(lex, "a variable", VERB)?;
    expect_symbol(lex, ':', VERB)?;
    let label = expect_name(lex, "a label", VERB)?;
    expect_symbol(lex, ')', VERB)?;
    Ok(ConstraintEntity::Node { label })
}

/// Expects the lone dash token `-` (a [`Tok::Word`] because `-` is a lexer word character) that joins
/// the segments of a relationship pattern (`rmp` #638). A directed arrow lexes as `-` + `>` (or `<` +
/// `-`), so the following symbol check in [`parse_constraint_entity`] rejects the directed form.
fn expect_dash(lex: &mut Lexer<'_>, verb: &str) -> Result<(), String> {
    match lex.next_tok()? {
        Some(Tok::Word(w)) if w == "-" => Ok(()),
        Some(other) => Err(unexpected_generic(
            &other,
            &format!("`-` in the relationship pattern after {verb}"),
        )),
        None => Err(format!(
            "expected `-` in the relationship pattern after {verb}"
        )),
    }
}

/// Parses the clause after `IS` in a `REQUIRE … IS …` constraint tail (`rmp` tasks #100, #638),
/// returning the [`ConstraintCreateKind`]. Accepts:
///
/// - `:: <TYPE>` and `TYPED <TYPE>` → a property-type constraint;
/// - `UNIQUE` / `[NODE|REL[ATIONSHIP]] UNIQUE` → uniqueness;
/// - `KEY` / `[NODE|REL[ATIONSHIP]] KEY` → key;
/// - `NOT NULL` → existence.
///
/// An explicit `NODE` / `REL[ATIONSHIP]` qualifier must match the entity pattern (`is_rel`); a
/// mismatch (e.g. `IS RELATIONSHIP KEY` on a `FOR (n:Label)` pattern) is a clear error.
fn parse_constraint_is_clause(
    lex: &mut Lexer<'_>,
    is_rel: bool,
) -> Result<ConstraintCreateKind, String> {
    const VERB: &str = "CONSTRAINT";
    // `IS :: <TYPE>` — `::` is two adjacent `:` symbols.
    if peek_symbol(lex, ':')? {
        expect_symbol(lex, ':', VERB)?;
        expect_symbol(lex, ':', VERB)?;
        let declared_type = parse_constraint_type(lex)?;
        return Ok(ConstraintCreateKind::PropertyType { declared_type });
    }
    let next = lex.next_tok()?.ok_or_else(|| {
        "expected UNIQUE, NOT NULL, KEY, TYPED or :: <TYPE> after IS in CONSTRAINT".to_owned()
    })?;
    // `IS TYPED <TYPE>` — the alternative spelling of the property-type clause.
    if is_keyword(&next, "TYPED") {
        let declared_type = parse_constraint_type(lex)?;
        return Ok(ConstraintCreateKind::PropertyType { declared_type });
    }
    if is_keyword(&next, "UNIQUE") {
        return Ok(ConstraintCreateKind::Unique);
    }
    if is_keyword(&next, "KEY") {
        return Ok(ConstraintCreateKind::Key);
    }
    if is_keyword(&next, "NOT") {
        let null = lex
            .next_tok()?
            .ok_or_else(|| "expected NULL after NOT in CONSTRAINT".to_owned())?;
        if !is_keyword(&null, "NULL") {
            return Err(unexpected_generic(&null, "NULL after NOT in CONSTRAINT"));
        }
        return Ok(ConstraintCreateKind::Existence);
    }
    // Optional entity qualifier: NODE (node) or REL / RELATIONSHIP (relationship) before UNIQUE/KEY.
    let qualifier_is_rel = if is_keyword(&next, "NODE") {
        false
    } else if is_keyword(&next, "REL") || is_keyword(&next, "RELATIONSHIP") {
        true
    } else {
        return Err(unexpected_generic(
            &next,
            "UNIQUE, NOT NULL, KEY, a NODE/RELATIONSHIP qualifier, TYPED or :: <TYPE> after IS in CONSTRAINT",
        ));
    };
    if qualifier_is_rel != is_rel {
        return Err(format!(
            "the {} qualifier does not match the {} pattern in CONSTRAINT",
            if qualifier_is_rel {
                "RELATIONSHIP"
            } else {
                "NODE"
            },
            if is_rel {
                "relationship (FOR ()-[r:TYPE]-())"
            } else {
                "node (FOR (n:Label))"
            },
        ));
    }
    let kw = lex
        .next_tok()?
        .ok_or_else(|| "expected UNIQUE or KEY after the qualifier in CONSTRAINT".to_owned())?;
    if is_keyword(&kw, "UNIQUE") {
        Ok(ConstraintCreateKind::Unique)
    } else if is_keyword(&kw, "KEY") {
        Ok(ConstraintCreateKind::Key)
    } else {
        Err(unexpected_generic(
            &kw,
            "UNIQUE or KEY after the qualifier in CONSTRAINT",
        ))
    }
}

/// Parses a Neo4j property-type-constraint **type** for a `IS :: <TYPE>` clause (`rmp` tasks #100,
/// #652): the closed set of property types, a `LIST<X [NOT NULL]>` of one of them, and a `|`-separated
/// closed union of those (`INTEGER | STRING`). Mirrors the property-type subset of the Cypher
/// expression type grammar (`graphus_cypher::parser::parse_type`), rejecting the non-property types
/// (`NODE`/`RELATIONSHIP`/`PATH`/`MAP`/`ANY`/`NOTHING`/`NULL`) a property can never hold.
///
/// The allowed scalars are `BOOLEAN`, `STRING`, `INTEGER`, `FLOAT`, `DATE`, `LOCAL TIME`, `ZONED TIME`,
/// `LOCAL DATETIME`, `ZONED DATETIME`, `DURATION`, `POINT` (with the openCypher synonyms `BOOL`,
/// `VARCHAR`, `INT`, `SIGNED INTEGER`). The `LIST<…>` angle brackets are the single `<` / `>` symbols
/// of the lexer; a bare `LIST` (no element) is rejected.
fn parse_constraint_type(
    lex: &mut Lexer<'_>,
) -> Result<graphus_storage::ConstraintTypeDescriptor, String> {
    use graphus_storage::ConstraintTypeDescriptor as T;
    // A `|`-separated closed union: parse one member, then greedily fold `| member` while a bare pipe
    // follows. A lone member collapses to itself (no `Union`), matching the expression type grammar.
    // The member count is capped at `MAX_UNION_MEMBERS` so the write path never produces a descriptor
    // the durable decoder rejects (`rmp` #652 — an over-wide union would truncate on the `u8` wire
    // count and mis-frame the meta image on reopen).
    let mut members = vec![parse_constraint_type_member(lex, 0)?];
    while peek_symbol(lex, '|')? {
        expect_symbol(lex, '|', "CONSTRAINT")?;
        if members.len() >= T::MAX_UNION_MEMBERS {
            return Err(format!(
                "a constraint type union may not exceed {} members",
                T::MAX_UNION_MEMBERS
            ));
        }
        members.push(parse_constraint_type_member(lex, 0)?);
    }
    let descriptor = if members.len() == 1 {
        members.pop().expect("exactly one member")
    } else {
        T::Union(members)
    };
    // Reject a descriptor the durable decoder would reject on reopen (`rmp` #652). A union adds a
    // nesting level over its members, so a union of an already-deep `LIST` can exceed the bound even
    // though each member parsed within it. Enforcing the exact storage-decode depth on the write path
    // guarantees a committed `CREATE CONSTRAINT` never persists an image that bricks the store.
    if descriptor.storage_depth() > T::MAX_TYPE_DEPTH {
        return Err(format!(
            "a constraint type may not nest deeper than {} levels",
            T::MAX_TYPE_DEPTH
        ));
    }
    Ok(descriptor)
}

/// Parses a single union member of a constraint type: a scalar, or `LIST<inner [NOT NULL]>`. `depth`
/// is the member's storage-decode nesting level (`0` at the top); it bounds `LIST` recursion at
/// [`MAX_TYPE_DEPTH`](graphus_storage::ConstraintTypeDescriptor::MAX_TYPE_DEPTH) so a crafted
/// `LIST<LIST<…>>` cannot overflow the parser stack (a DoS) nor build an image the decoder rejects.
fn parse_constraint_type_member(
    lex: &mut Lexer<'_>,
    depth: usize,
) -> Result<graphus_storage::ConstraintTypeDescriptor, String> {
    use graphus_storage::ConstraintTypeDescriptor as T;
    const VERB: &str = "CONSTRAINT";
    if depth > T::MAX_TYPE_DEPTH {
        return Err(format!(
            "a constraint type may not nest deeper than {} levels",
            T::MAX_TYPE_DEPTH
        ));
    }
    let tok = lex
        .next_tok()?
        .ok_or_else(|| "expected a type after IS :: in CONSTRAINT".to_owned())?;
    let Tok::Word(word) = &tok else {
        return Err(unexpected_generic(
            &tok,
            "a type name after IS :: in CONSTRAINT",
        ));
    };
    let upper = word.to_ascii_uppercase();
    match upper.as_str() {
        "INTEGER" | "INT" => Ok(T::Integer),
        "SIGNED" => {
            // `SIGNED INTEGER` — the openCypher synonym for `INTEGER`.
            expect_keyword(lex, "INTEGER", VERB)?;
            Ok(T::Integer)
        }
        "FLOAT" => Ok(T::Float),
        "STRING" | "VARCHAR" => Ok(T::String),
        "BOOLEAN" | "BOOL" => Ok(T::Boolean),
        "DATE" => Ok(T::Date),
        "DURATION" => Ok(T::Duration),
        "POINT" => Ok(T::Point),
        // The two-word temporal types (`LOCAL TIME` / `ZONED DATETIME`, …).
        "LOCAL" => match expect_type_word(lex)?.as_str() {
            "TIME" => Ok(T::LocalTime),
            "DATETIME" => Ok(T::LocalDateTime),
            other => Err(format!(
                "expected TIME or DATETIME after LOCAL, got `{other}`"
            )),
        },
        "ZONED" => match expect_type_word(lex)?.as_str() {
            "TIME" => Ok(T::ZonedTime),
            "DATETIME" => Ok(T::ZonedDateTime),
            other => Err(format!(
                "expected TIME or DATETIME after ZONED, got `{other}`"
            )),
        },
        "LIST" | "ARRAY" => {
            // LIST < <element type> [NOT NULL] >
            expect_symbol(lex, '<', VERB)?;
            let inner = parse_constraint_type_member(lex, depth + 1)?;
            // A Neo4j constraint list element is `NOT NULL`; accept (and require nothing more than) the
            // optional qualifier — the value model already rejects a null element against a scalar.
            if peek_word_ci(lex, "NOT") {
                expect_keyword(lex, "NOT", VERB)?;
                expect_keyword(lex, "NULL", VERB)?;
            }
            expect_symbol(lex, '>', VERB)?;
            Ok(T::List(Box::new(inner)))
        }
        // `VECTOR<…>` property-type constraints are a Cypher-25 feature tracked separately (`rmp` #647).
        "VECTOR" => Err(
            "VECTOR property-type constraints are not yet supported (tracked by rmp #647)"
                .to_owned(),
        ),
        // The structural / wildcard types a stored property value can never hold.
        "NODE" | "RELATIONSHIP" | "PATH" | "MAP" | "ANY" | "NOTHING" | "NULL" => Err(format!(
            "`{upper}` is not a valid property type for a constraint \
             (allowed: BOOLEAN, STRING, INTEGER, FLOAT, DATE, LOCAL/ZONED TIME, \
             LOCAL/ZONED DATETIME, DURATION, POINT, LIST<… NOT NULL>, or a union of these)"
        )),
        other => Err(format!(
            "unsupported constraint type `{other}` (allowed: BOOLEAN, STRING, INTEGER, FLOAT, DATE, \
             LOCAL/ZONED TIME, LOCAL/ZONED DATETIME, DURATION, POINT, LIST<… NOT NULL>, or a union)"
        )),
    }
}

/// Consumes the next token, requiring it to be a bare [`Tok::Word`], and returns its ASCII-uppercased
/// text (for the multi-word temporal type names). Errors if the next token is absent or a symbol.
fn expect_type_word(lex: &mut Lexer<'_>) -> Result<String, String> {
    match lex.next_tok()? {
        Some(Tok::Word(w)) => Ok(w.to_ascii_uppercase()),
        Some(other) => Err(unexpected_generic(&other, "a type name word in CONSTRAINT")),
        None => Err("expected a type name word in CONSTRAINT".to_owned()),
    }
}

/// Peeks whether the next token is the bare word `kw` (ASCII case-insensitive), without consuming it.
fn peek_word_ci(lex: &mut Lexer<'_>, kw: &str) -> bool {
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    matches!(peek.next_tok(), Ok(Some(Tok::Word(w))) if w.eq_ignore_ascii_case(kw))
}

/// Peeks whether the next token is the single symbol `sym`, without consuming it.
fn peek_symbol(lex: &mut Lexer<'_>, sym: char) -> Result<bool, String> {
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    Ok(matches!(peek.next_tok()?, Some(Tok::Symbol(c)) if c == sym))
}

/// Parses the legacy `ON :<Label>(<property>)` (node-only) tail (the `ON` already consumed). There is
/// no legacy relationship form, so this always yields an [`IndexTarget::Node`].
fn parse_index_legacy_on(verb: &str, lex: &mut Lexer<'_>) -> Result<IndexTarget, String> {
    expect_symbol(lex, ':', verb)?;
    let label = expect_name(lex, "a label", verb)?;
    expect_symbol(lex, '(', verb)?;
    let property = expect_name(lex, "a property", verb)?;
    expect_symbol(lex, ')', verb)?;
    // The optional trailing `OPTIONS { … }` and end-of-statement are validated by the caller.
    // The legacy `ON :Label(prop)` form is single-property only (`rmp` task #657): a composite must use
    // the openCypher `FOR (n:L) ON (n.a, n.b)` shape.
    Ok(IndexTarget::Node {
        label,
        properties: vec![property],
    })
}

// ------------------------------------------------------------------------------------------------
// Security surface (rmp #92): users, roles, grants
// ------------------------------------------------------------------------------------------------

/// Parses the remainder of a claimed **security** statement whose first two tokens are
/// `verb` (`CREATE`/`DROP`/`SHOW`) + the surface keyword `second`
/// (`USER`/`USERS`/`ROLE`/`ROLES`/`PRIVILEGES`):
///
/// ```text
/// CREATE USER <name> [SET PASSWORD '<pw>'] [IF NOT EXISTS]
/// DROP   USER <name> [IF EXISTS]
/// CREATE ROLE <name> [IF NOT EXISTS]
/// DROP   ROLE <name> [IF EXISTS]
/// SHOW   USERS
/// SHOW   ROLES
/// SHOW   PRIVILEGES
/// ```
///
/// A `<name>` is a bare word or a `` `backtick-quoted` `` name (the same rule as the database
/// surface); a password is a `'single'`- or `"double"`-quoted string literal.
fn parse_claimed_security(
    verb: &str,
    second: &Tok,
    lex: &mut Lexer<'_>,
) -> Result<AdminCommand, String> {
    // The SHOW plurals are nullary.
    if is_keyword(second, "USERS")
        || is_keyword(second, "ROLES")
        || is_keyword(second, "PRIVILEGES")
    {
        if verb != "SHOW" {
            let kw = keyword_text(second);
            return Err(format!(
                "expected the singular form after {verb} ({kw} is only valid in SHOW {kw})"
            ));
        }
        let what = format!("SHOW {}", keyword_text(second));
        expect_end(lex, &what)?;
        return Ok(if is_keyword(second, "USERS") {
            AdminCommand::ShowUsers
        } else if is_keyword(second, "ROLES") {
            AdminCommand::ShowRoles
        } else {
            AdminCommand::ShowPrivileges
        });
    }

    // Singular USER / ROLE: only CREATE and DROP (SHOW USER/ROLE singular is not a form).
    let is_user = is_keyword(second, "USER");
    let entity = if is_user { "USER" } else { "ROLE" };
    if verb == "SHOW" {
        return Err(format!(
            "expected SHOW {entity}S (the singular SHOW {entity} is not supported)"
        ));
    }

    // <name> next (bare word or backtick-quoted).
    let name = expect_security_name(
        lex,
        &format!(
            "a {} name after {verb} {entity}",
            entity.to_ascii_lowercase()
        ),
    )?;

    match (verb, is_user) {
        ("CREATE", true) => {
            // Optional SET PASSWORD '<pw>' then optional IF NOT EXISTS.
            let password = parse_optional_set_password(lex)?;
            let if_not_exists = parse_optional_if(lex, /* with_not */ true)?;
            expect_end(lex, "CREATE USER")?;
            Ok(AdminCommand::CreateUser {
                name,
                password,
                if_not_exists,
            })
        }
        ("DROP", true) => {
            let if_exists = parse_optional_if(lex, /* with_not */ false)?;
            expect_end(lex, "DROP USER")?;
            Ok(AdminCommand::DropUser { name, if_exists })
        }
        ("CREATE", false) => {
            let if_not_exists = parse_optional_if(lex, /* with_not */ true)?;
            expect_end(lex, "CREATE ROLE")?;
            Ok(AdminCommand::CreateRole {
                name,
                if_not_exists,
            })
        }
        ("DROP", false) => {
            let if_exists = parse_optional_if(lex, /* with_not */ false)?;
            expect_end(lex, "DROP ROLE")?;
            Ok(AdminCommand::DropRole { name, if_exists })
        }
        // `parse_admin_statement` only routes CREATE/DROP/SHOW here.
        (other, _) => Err(format!("unsupported security verb {other}")),
    }
}

/// Parses a claimed DBMS-introspection listing (`rmp` #637): `SHOW FUNCTIONS`, `SHOW PROCEDURES`,
/// `SHOW SETTINGS`, or `SHOW TRANSACTIONS`. Each is `SHOW`-only and nullary (the verb + keyword are
/// already read).
fn parse_claimed_introspection(
    verb: &str,
    second: &Tok,
    lex: &mut Lexer<'_>,
) -> Result<AdminCommand, String> {
    if verb != "SHOW" {
        let kw = keyword_text(second);
        return Err(format!(
            "expected the singular form after {verb} ({kw} is only valid in SHOW {kw})"
        ));
    }
    let what = format!("SHOW {}", keyword_text(second));
    expect_end(lex, &what)?;
    Ok(if is_keyword(second, "FUNCTIONS") {
        AdminCommand::ShowFunctions
    } else if is_keyword(second, "PROCEDURES") {
        AdminCommand::ShowProcedures
    } else if is_keyword(second, "SETTINGS") {
        AdminCommand::ShowSettings
    } else {
        AdminCommand::ShowTransactions
    })
}

/// Parses `TERMINATE TRANSACTIONS '<id>' [, '<id>' ...]` (`rmp` #637); the `TERMINATE` verb is
/// already read and the statement is CLAIMED (`TERMINATE` is never valid Cypher). Requires the
/// `TRANSACTIONS` keyword and at least one single-/double-quoted id, comma-separated.
fn parse_terminate(verb: &str, lex: &mut Lexer<'_>) -> Result<AdminCommand, String> {
    // TRANSACTIONS (accept the singular TRANSACTION too, mirroring Neo4j's lenient keyword).
    match lex.next_tok()? {
        Some(t) if is_keyword(&t, "TRANSACTIONS") || is_keyword(&t, "TRANSACTION") => {}
        Some(other) => {
            return Err(unexpected_generic(
                &other,
                &format!("TRANSACTIONS after {verb}"),
            ));
        }
        None => return Err(format!("expected TRANSACTIONS after {verb}")),
    }
    // One or more quoted ids, comma-separated.
    let mut ids = Vec::new();
    loop {
        match lex.next_tok()? {
            Some(Tok::Str(id)) => ids.push(id),
            Some(other) => {
                return Err(unexpected_generic(
                    &other,
                    "a quoted transaction id in TERMINATE TRANSACTIONS",
                ));
            }
            None => {
                return Err("expected a quoted transaction id in TERMINATE TRANSACTIONS".to_owned());
            }
        }
        // Optional trailing comma → another id.
        let mut peek = Lexer {
            rest: lex.rest.clone(),
        };
        match peek.next_tok()? {
            Some(Tok::Symbol(',')) => {
                lex.rest = peek.rest.clone();
            }
            _ => break,
        }
    }
    expect_end(lex, "TERMINATE TRANSACTIONS")?;
    Ok(AdminCommand::TerminateTransactions { ids })
}

/// Parses `ALTER USER <name> SET {PASSWORD '<pw>' | STATUS {ACTIVE|SUSPENDED}}` (`rmp` #641); the
/// `ALTER` verb is already read and the statement is CLAIMED (`ALTER` is never valid Cypher). Exactly
/// one `SET` clause is required. The other Neo4j clauses (`SET HOME DATABASE`, `CHANGE [NOT]
/// REQUIRED`) are a named follow-up and are rejected here.
fn parse_alter_user(verb: &str, lex: &mut Lexer<'_>) -> Result<AdminCommand, String> {
    // USER
    match lex.next_tok()? {
        Some(t) if is_keyword(&t, "USER") => {}
        Some(other) => return Err(unexpected_generic(&other, &format!("USER after {verb}"))),
        None => return Err(format!("expected USER after {verb}")),
    }
    // <name>
    let name = expect_security_name(lex, &format!("a user name after {verb} USER"))?;
    // SET
    match lex.next_tok()? {
        Some(t) if is_keyword(&t, "SET") => {}
        Some(other) => {
            return Err(unexpected_generic(
                &other,
                "SET PASSWORD '<password>' or SET STATUS {ACTIVE|SUSPENDED} in ALTER USER",
            ));
        }
        None => {
            return Err(format!(
                "expected SET PASSWORD '<password>' or SET STATUS after {verb} USER {name}"
            ));
        }
    }
    // Dispatch on the clause keyword.
    let clause = lex
        .next_tok()?
        .ok_or_else(|| "expected PASSWORD or STATUS after SET in ALTER USER".to_owned())?;
    if is_keyword(&clause, "PASSWORD") {
        let password = match lex.next_tok()? {
            Some(Tok::Str(pw)) => pw,
            Some(other) => {
                return Err(unexpected_generic(
                    &other,
                    "a quoted password after SET PASSWORD",
                ));
            }
            None => return Err("expected a quoted password after SET PASSWORD".to_owned()),
        };
        expect_end(lex, "ALTER USER")?;
        Ok(AdminCommand::AlterUserPassword { name, password })
    } else if is_keyword(&clause, "STATUS") {
        let status = lex
            .next_tok()?
            .ok_or_else(|| "expected ACTIVE or SUSPENDED after SET STATUS".to_owned())?;
        let suspended = if is_keyword(&status, "SUSPENDED") {
            true
        } else if is_keyword(&status, "ACTIVE") {
            false
        } else {
            return Err(unexpected_generic(
                &status,
                "ACTIVE or SUSPENDED after SET STATUS",
            ));
        };
        expect_end(lex, "ALTER USER")?;
        Ok(AdminCommand::AlterUserStatus { name, suspended })
    } else {
        Err(unexpected_generic(
            &clause,
            "PASSWORD or STATUS after SET (SET HOME DATABASE / CHANGE REQUIRED are not yet supported)",
        ))
    }
}

/// Parses `RENAME USER <from> TO <to>` / `RENAME ROLE <from> TO <to>` (`rmp` #641); the `RENAME`
/// verb is already read and the statement is CLAIMED (`RENAME` is never valid Cypher).
fn parse_rename(verb: &str, lex: &mut Lexer<'_>) -> Result<AdminCommand, String> {
    let kind = lex
        .next_tok()?
        .ok_or_else(|| format!("expected USER or ROLE after {verb}"))?;
    let is_user = is_keyword(&kind, "USER");
    if !is_user && !is_keyword(&kind, "ROLE") {
        return Err(unexpected_generic(
            &kind,
            &format!("USER or ROLE after {verb}"),
        ));
    }
    let entity = if is_user { "USER" } else { "ROLE" };
    let from = expect_security_name(lex, &format!("a name after {verb} {entity}"))?;
    expect_security_keyword(lex, "TO", &format!("{verb} {entity}"))?;
    let to = expect_security_name(lex, &format!("a new name after {verb} {entity} {from} TO"))?;
    expect_end(lex, &format!("RENAME {entity}"))?;
    Ok(if is_user {
        AdminCommand::RenameUser { from, to }
    } else {
        AdminCommand::RenameRole { from, to }
    })
}

/// Parses an optional `SET PASSWORD '<pw>'` clause (only consumed when the next token is `SET`).
/// Returns the plaintext password if the clause was present. A partial clause is a syntax error.
fn parse_optional_set_password(lex: &mut Lexer<'_>) -> Result<Option<String>, String> {
    // Peek: only consume if the next token is SET.
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    match peek.next_tok()? {
        Some(t) if is_keyword(&t, "SET") => {
            lex.rest = peek.rest.clone();
        }
        _ => return Ok(None),
    }
    // PASSWORD '<pw>'
    match lex.next_tok()? {
        Some(t) if is_keyword(&t, "PASSWORD") => {}
        _ => return Err("expected PASSWORD after SET".to_owned()),
    }
    match lex.next_tok()? {
        Some(Tok::Str(pw)) => Ok(Some(pw)),
        Some(other) => Err(unexpected_generic(
            &other,
            "a quoted password after SET PASSWORD",
        )),
        None => Err("expected a quoted password after SET PASSWORD".to_owned()),
    }
}

/// Parses `GRANT`/`REVOKE`/`DENY` (the verb already read, the statement already CLAIMED — none is
/// ever valid Cypher). Shapes (`rmp` #92 / #645):
///
/// ```text
/// GRANT  ROLE <role> TO   <user>            REVOKE ROLE <role> FROM <user>
/// GRANT               <action> ON <scope> TO   <role>
/// DENY                <action> ON <scope> TO   <role>
/// REVOKE [GRANT|DENY] <action> ON <scope> FROM <role>
/// ```
///
/// `<action>` is `TRAVERSE`/`READ`/`WRITE`/`SCHEMA`/`ADMIN`; `<scope>` is parsed by
/// [`parse_priv_scope`]. The trailing keyword is `TO` for `GRANT`/`DENY`, `FROM` for `REVOKE`. A
/// leading `GRANT`/`DENY` after `REVOKE` selects [`RevokeMode::GrantOnly`]/[`RevokeMode::DenyOnly`];
/// plain `REVOKE` is [`RevokeMode::Both`]. `DENY` applies only to privileges (there is no
/// `DENY ROLE`).
fn parse_grant_revoke(verb: &str, lex: &mut Lexer<'_>) -> Result<AdminCommand, String> {
    let denying = verb == "DENY";
    let revoking = verb == "REVOKE";
    // The trailing connective: FROM for REVOKE, TO for GRANT/DENY.
    let connective = if revoking { "FROM" } else { "TO" };

    let second = lex
        .next_tok()?
        .ok_or_else(|| format!("expected ROLE or an action after {verb}"))?;

    // GRANT/REVOKE ROLE <role> TO/FROM <user>. (There is no `DENY ROLE`: a role assignment is not a
    // privilege, so it cannot be denied.)
    if is_keyword(&second, "ROLE") {
        if denying {
            return Err(
                "DENY does not apply to role assignment (use REVOKE ROLE to unassign a role)"
                    .to_owned(),
            );
        }
        let role = expect_security_name(lex, &format!("a role name after {verb} ROLE"))?;
        expect_security_keyword(lex, connective, verb)?;
        let user = expect_security_name(lex, &format!("a user name after {connective}"))?;
        expect_end(lex, &format!("{verb} ROLE"))?;
        return Ok(if revoking {
            AdminCommand::RevokeRole { role, user }
        } else {
            AdminCommand::GrantRole { role, user }
        });
    }

    // REVOKE GRANT / REVOKE DENY prefix: select the access sense to remove, then read the real action.
    let mut mode = RevokeMode::Both;
    let action_tok = if revoking && is_keyword(&second, "GRANT") {
        mode = RevokeMode::GrantOnly;
        lex.next_tok()?
            .ok_or_else(|| "expected an action after REVOKE GRANT".to_owned())?
    } else if revoking && is_keyword(&second, "DENY") {
        mode = RevokeMode::DenyOnly;
        lex.next_tok()?
            .ok_or_else(|| "expected an action after REVOKE DENY".to_owned())?
    } else {
        second
    };

    // <action> ON <scope> TO/FROM <role>
    let action = match &action_tok {
        Tok::Word(w) => PrivAction::from_keyword(w).ok_or_else(|| {
            format!("unknown privilege action `{w}`; expected ROLE, TRAVERSE, READ, WRITE, SCHEMA or ADMIN")
        })?,
        other => {
            return Err(unexpected_generic(
                other,
                &format!("ROLE or an action after {verb}"),
            ));
        }
    };
    expect_security_keyword(lex, "ON", verb)?;
    let scope = parse_priv_scope(lex)?;
    expect_security_keyword(lex, connective, verb)?;
    let role = expect_security_name(lex, &format!("a role name after {connective}"))?;
    expect_end(lex, verb)?;
    Ok(if denying {
        AdminCommand::DenyPrivilege {
            action,
            scope,
            role,
        }
    } else if revoking {
        AdminCommand::RevokePrivilege {
            action,
            scope,
            role,
            mode,
        }
    } else {
        AdminCommand::GrantPrivilege {
            action,
            scope,
            role,
        }
    })
}

/// Parses `BACKUP`/`RESTORE` (the verb already read, the statement already CLAIMED — neither is
/// valid Cypher). Two shapes (`rmp` task #149):
///
/// ```text
/// BACKUP  DATABASE <name> TO   '<path>'
/// RESTORE DATABASE <name> FROM '<path>' [AT LSN <n> | AT TIMESTAMP <n>]
/// ```
///
/// `<name>` is a bare word or a `` `backtick-quoted` `` name (the database-surface rule); `<path>` is
/// a `'single'`- or `"double"`-quoted string literal. The optional `AT LSN`/`AT TIMESTAMP` clause
/// (RESTORE only) selects the point-in-time recovery target; absent, it restores the whole chain.
fn parse_backup_restore(verb: &str, lex: &mut Lexer<'_>) -> Result<AdminCommand, String> {
    let backing_up = verb == "BACKUP";
    // DATABASE
    let kw = lex
        .next_tok()?
        .ok_or_else(|| format!("expected DATABASE after {verb}"))?;
    if !is_keyword(&kw, "DATABASE") {
        return Err(unexpected_generic(&kw, &format!("DATABASE after {verb}")));
    }
    // <name>
    let name = expect_security_name(lex, &format!("a database name after {verb} DATABASE"))?;
    // TO (backup) / FROM (restore)
    let connective = if backing_up { "TO" } else { "FROM" };
    expect_security_keyword(lex, connective, verb)?;
    // '<path>'
    let path = match lex.next_tok()? {
        Some(Tok::Str(p)) => p,
        Some(other) => {
            return Err(unexpected_generic(
                &other,
                &format!("a quoted file path after {connective}"),
            ));
        }
        None => return Err(format!("expected a quoted file path after {connective}")),
    };
    if path.trim().is_empty() {
        return Err(format!("the {connective} file path must not be empty"));
    }

    if backing_up {
        expect_end(lex, "BACKUP DATABASE")?;
        return Ok(AdminCommand::BackupDatabase { name, path });
    }

    // RESTORE: optional `AT LSN <n>` / `AT TIMESTAMP <n>`.
    let point = parse_optional_restore_point(lex)?;
    expect_end(lex, "RESTORE DATABASE")?;
    Ok(AdminCommand::RestoreDatabase { name, path, point })
}

/// Parses `CHECKPOINT DATABASE <name>` (`rmp` #305), the operator maintenance trigger. Mirrors the
/// `BACKUP DATABASE <name>` head: the `CHECKPOINT` verb is already consumed.
fn parse_checkpoint(verb: &str, lex: &mut Lexer<'_>) -> Result<AdminCommand, String> {
    // DATABASE
    let kw = lex
        .next_tok()?
        .ok_or_else(|| format!("expected DATABASE after {verb}"))?;
    if !is_keyword(&kw, "DATABASE") {
        return Err(unexpected_generic(&kw, &format!("DATABASE after {verb}")));
    }
    // <name>
    let name = expect_security_name(lex, &format!("a database name after {verb} DATABASE"))?;
    expect_end(lex, "CHECKPOINT DATABASE")?;
    Ok(AdminCommand::CheckpointDatabase { name })
}

/// Parses an optional `AT (LSN | TIMESTAMP) <n>` clause for `RESTORE DATABASE` (`rmp` task #149).
/// Absent ⇒ [`RestorePoint::Latest`]. `<n>` is a non-negative decimal integer.
fn parse_optional_restore_point(lex: &mut Lexer<'_>) -> Result<RestorePoint, String> {
    // Peek: only consume if the next token is AT.
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    match peek.next_tok()? {
        Some(t) if is_keyword(&t, "AT") => {
            lex.rest = peek.rest.clone();
        }
        _ => return Ok(RestorePoint::Latest),
    }
    let kind = lex
        .next_tok()?
        .ok_or_else(|| "expected LSN or TIMESTAMP after AT".to_owned())?;
    let is_lsn = is_keyword(&kind, "LSN");
    if !is_lsn && !is_keyword(&kind, "TIMESTAMP") {
        return Err(unexpected_generic(&kind, "LSN or TIMESTAMP after AT"));
    }
    let n = match lex.next_tok()? {
        Some(Tok::Word(w)) => w.parse::<u64>().map_err(|_| {
            format!(
                "expected a non-negative integer after AT {}, got `{w}`",
                keyword_text(&kind)
            )
        })?,
        Some(other) => {
            return Err(unexpected_generic(
                &other,
                &format!("a non-negative integer after AT {}", keyword_text(&kind)),
            ));
        }
        None => {
            return Err(format!(
                "expected a non-negative integer after AT {}",
                keyword_text(&kind)
            ));
        }
    };
    Ok(if is_lsn {
        RestorePoint::Lsn(n)
    } else {
        RestorePoint::Timestamp(n)
    })
}

/// Parses a privilege `<scope>` in `GRANT`/`REVOKE`. The accepted forms map 1:1 onto the
/// [`graphus_auth::Resource`] containment tree:
///
/// ```text
/// DATABASE                                  -> Resource::Database  (server-wide)
/// GRAPH <db>                                -> Resource::Graph
/// LABEL <db>.<label>                        -> Resource::Label
/// RELATIONSHIP <db>.<rel_type>              -> Resource::RelType
/// PROPERTY <db>.<label>.<property>          -> Resource::Property
/// ```
///
/// Each dotted form is read as the matching number of `.`-separated name segments. A segment is a
/// bare word (no `.` — `.` is the segment separator) or a `` `backtick-quoted` `` name (which may
/// contain a `.`). The grammar is deliberately small and unambiguous; it does not attempt to mirror
/// Neo4j's full `GRANT … ON GRAPH … NODES …` surface, only the scopes the model represents.
fn parse_priv_scope(lex: &mut Lexer<'_>) -> Result<PrivScope, String> {
    let kw = lex.next_tok()?.ok_or_else(|| {
        "expected a scope (DATABASE, GRAPH, LABEL, RELATIONSHIP or PROPERTY)".to_owned()
    })?;
    let kw_word = match &kw {
        Tok::Word(w) => w.to_ascii_uppercase(),
        other => {
            return Err(unexpected_generic(
                other,
                "a scope (DATABASE, GRAPH, LABEL, RELATIONSHIP or PROPERTY)",
            ));
        }
    };
    match kw_word.as_str() {
        "DATABASE" => Ok(PrivScope::Database),
        "GRAPH" => {
            let segments = parse_dotted_segments(lex, "GRAPH <db>")?;
            let [db] = exactly(segments, 1, "GRAPH <db>")?;
            Ok(PrivScope::Graph { db })
        }
        "LABEL" => {
            let segments = parse_dotted_segments(lex, "LABEL <db>.<label>")?;
            let [db, label] = exactly(segments, 2, "LABEL <db>.<label>")?;
            Ok(PrivScope::Label { db, label })
        }
        "RELATIONSHIP" => {
            let segments = parse_dotted_segments(lex, "RELATIONSHIP <db>.<rel_type>")?;
            let [db, rel_type] = exactly(segments, 2, "RELATIONSHIP <db>.<rel_type>")?;
            Ok(PrivScope::RelType { db, rel_type })
        }
        "PROPERTY" => {
            let segments = parse_dotted_segments(lex, "PROPERTY <db>.<label>.<property>")?;
            let [db, label, property] = exactly(segments, 3, "PROPERTY <db>.<label>.<property>")?;
            Ok(PrivScope::Property {
                db,
                label,
                property,
            })
        }
        other => Err(format!(
            "unknown scope `{other}`; expected DATABASE, GRAPH, LABEL, RELATIONSHIP or PROPERTY"
        )),
    }
}

/// Reads a dotted name path (`a.b.c`) as its `.`-separated segments. A bare word containing `.`
/// (the lexer treats `.` as a word char) is split on `.`; a `` `backtick-quoted` `` segment keeps a
/// literal `.` (it is one segment). Mixed forms are not supported — the whole path must be a single
/// bare word OR a single backtick-quoted name; anything else is a syntax error naming `what`.
///
/// (This keeps the surface unambiguous: the common case `sales.Person.name` is one bare word the
/// lexer hands back whole, and a name containing a literal dot must be fully backtick-quoted.)
fn parse_dotted_segments(lex: &mut Lexer<'_>, what: &str) -> Result<Vec<String>, String> {
    match lex.next_tok()? {
        Some(Tok::Word(w)) => {
            if w.is_empty() {
                return Err(format!("expected {what}"));
            }
            Ok(w.split('.').map(str::to_owned).collect())
        }
        Some(Tok::Quoted(q)) => Ok(vec![q]),
        Some(other) => Err(unexpected_generic(&other, what)),
        None => Err(format!("expected {what}")),
    }
}

/// Asserts a segment vector has exactly `n` non-empty segments, returning them as a fixed array.
fn exactly<const N: usize>(
    segments: Vec<String>,
    n: usize,
    what: &str,
) -> Result<[String; N], String> {
    if segments.len() != n || segments.iter().any(String::is_empty) {
        return Err(format!("expected {what}"));
    }
    <[String; N]>::try_from(segments).map_err(|_| format!("expected {what}"))
}

/// Consumes a `<name>` for the security surface: a bare word or a `` `backtick-quoted` `` name.
fn expect_security_name(lex: &mut Lexer<'_>, what: &str) -> Result<String, String> {
    match lex.next_tok()? {
        Some(Tok::Word(w)) => Ok(w),
        Some(Tok::Quoted(q)) => Ok(q),
        Some(other) => Err(unexpected_generic(&other, what)),
        None => Err(format!("expected {what}")),
    }
}

/// Consumes the (case-insensitive) keyword `kw`, with a generic (non-INDEX) error message.
fn expect_security_keyword(lex: &mut Lexer<'_>, kw: &str, verb: &str) -> Result<(), String> {
    match lex.next_tok()? {
        Some(t) if is_keyword(&t, kw) => Ok(()),
        Some(t) => Err(unexpected_generic(&t, &format!("`{kw}` in {verb}"))),
        None => Err(format!("expected `{kw}` in {verb}")),
    }
}

/// The display text of a keyword token (for error messages); upper-cased for keywords.
fn keyword_text(tok: &Tok) -> String {
    match tok {
        Tok::Word(w) => w.to_ascii_uppercase(),
        Tok::Quoted(q) => q.clone(),
        Tok::Str(s) => format!("'{s}'"),
        Tok::Symbol(c) => c.to_string(),
    }
}

/// Renders an "unexpected token" error without the INDEX-specific framing of [`unexpected`].
fn unexpected_generic(tok: &Tok, expected: &str) -> String {
    let got = match tok {
        Tok::Word(w) => format!("`{w}`"),
        Tok::Quoted(q) => format!("`{q}`"),
        Tok::Str(s) => format!("'{s}'"),
        Tok::Symbol(c) => format!("`{c}`"),
    };
    format!("unexpected {got}; expected {expected}")
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

/// Consumes the next token, requiring it to be the single symbol `sym`.
fn expect_symbol(lex: &mut Lexer<'_>, sym: char, verb: &str) -> Result<(), String> {
    match lex.next_tok()? {
        Some(Tok::Symbol(c)) if c == sym => Ok(()),
        Some(t) => Err(unexpected(&t, &format!("`{sym}` in {verb} INDEX"))),
        None => Err(format!("expected `{sym}` in {verb} INDEX")),
    }
}

/// Consumes the next token, requiring it to be the (case-insensitive) keyword `kw`.
fn expect_keyword(lex: &mut Lexer<'_>, kw: &str, verb: &str) -> Result<(), String> {
    match lex.next_tok()? {
        Some(t) if is_keyword(&t, kw) => Ok(()),
        Some(t) => Err(unexpected(&t, &format!("`{kw}` in {verb} INDEX"))),
        None => Err(format!("expected `{kw}` in {verb} INDEX")),
    }
}

/// Consumes the next token, requiring it to be a bare [`Tok::Word`] (e.g. a variable). A quoted name
/// or a symbol here is a syntax error.
fn expect_word(lex: &mut Lexer<'_>, what: &str, verb: &str) -> Result<String, String> {
    match lex.next_tok()? {
        Some(Tok::Word(w)) => Ok(w),
        Some(t) => Err(unexpected(&t, &format!("{what} in {verb} INDEX"))),
        None => Err(format!("expected {what} in {verb} INDEX")),
    }
}

/// Consumes the next token, requiring it to be a **name**: a bare word or a `` `backtick-quoted` ``
/// name (so a label/property colliding with a keyword still works, mirroring the database surface).
fn expect_name(lex: &mut Lexer<'_>, what: &str, verb: &str) -> Result<String, String> {
    match lex.next_tok()? {
        Some(Tok::Word(w)) => Ok(w),
        Some(Tok::Quoted(q)) => Ok(q),
        Some(t) => Err(unexpected(&t, &format!("{what} in {verb} INDEX"))),
        None => Err(format!("expected {what} in {verb} INDEX")),
    }
}

/// Renders an "unexpected token" syntax error (the index/database surface's framing; identical to
/// [`unexpected_generic`], kept as the name those call sites read).
fn unexpected(tok: &Tok, expected: &str) -> String {
    unexpected_generic(tok, expected)
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
    /// The result summary — query type + schema/system counters — for this administrative statement
    /// (`rmp` #513). Empty (a default [`RunSummary`]) for the rows-only constructors; the
    /// [`AdminContext::execute`] funnel fills it for a system command (`type s` + `system-updates`),
    /// and the connectivity seams fill it for index / constraint DDL via
    /// [`crate::engine::command::index_ddl_summary`] /
    /// [`crate::engine::command::constraint_ddl_summary`].
    pub summary: RunSummary,
}

impl AdminResult {
    /// The empty result the lifecycle commands return (the [`AdminContext::execute`] funnel sets the
    /// `summary` afterwards — `rmp` #513).
    fn empty() -> Self {
        Self {
            fields: Vec::new(),
            rows: Vec::new(),
            summary: RunSummary::default(),
        }
    }
}

/// The shared multi-database context of one server: **database targeting** (session `db` →
/// [`EngineHandle`]) plus **administrative-statement execution** against the database and security
/// catalogs, used by both connectivity seams. Cheap to clone (`Arc`-shaped fields + a runtime
/// handle).
#[derive(Clone)]
pub struct AdminContext {
    /// The database catalog (naming + lifecycle + the running-engine registry).
    catalog: Arc<DatabaseCatalog>,
    /// The live, durable security catalog: admin statements are authorized against the same RBAC
    /// model as every other operation (`04 §8.4`), and the security commands (rmp #92) mutate it.
    security: Arc<SecurityCatalog>,
    /// The shared security audit log (rmp #70): admin/schema/security changes and their
    /// authorization denials are recorded at this single funnel. Disabled-by-config ⇒ a no-op sink.
    audit: Arc<AuditLog>,
    /// The server runtime, for bridging the catalogs' async APIs from the synchronous seams (module
    /// docs: why spawn + `std` channel, not `block_on`).
    runtime: Handle,
    /// The default database's engine handle — the fast path for sessions that never name a
    /// database, guaranteeing the single-db experience is byte-for-byte today's behaviour.
    default_handle: EngineHandle,
    /// The server's effective (post-hardware-auto-tune, validated) configuration, for the read-only
    /// `SHOW SETTINGS` introspection (`rmp` #637). `Arc`-shared so the per-connection clone of
    /// [`AdminContext`] stays cheap.
    config: Arc<ServerConfig>,
    /// The live registry of explicit (managed) transactions across every connectivity seam, for
    /// `SHOW TRANSACTIONS` / `TERMINATE TRANSACTIONS` (`rmp` #637).
    txns: Arc<crate::txn_registry::TransactionRegistry>,
}

impl AdminContext {
    /// Builds the context. `default_handle` must be the default database's admission-limited
    /// handle (the one [`crate::dbcatalog::DatabaseCatalog::start_default`] returned); `audit` is
    /// the shared audit log (rmp #70) the admin surface records change/denial events to.
    #[must_use]
    pub fn new(
        catalog: Arc<DatabaseCatalog>,
        security: Arc<SecurityCatalog>,
        audit: Arc<AuditLog>,
        runtime: Handle,
        default_handle: EngineHandle,
        config: Arc<ServerConfig>,
        txns: Arc<crate::txn_registry::TransactionRegistry>,
    ) -> Self {
        Self {
            catalog,
            security,
            audit,
            runtime,
            default_handle,
            config,
            txns,
        }
    }

    /// Shared access to the live security catalog (the listeners' authentication path resolves
    /// through it so a `DROP USER` immediately invalidates that user's sessions).
    #[must_use]
    pub fn security(&self) -> &Arc<SecurityCatalog> {
        &self.security
    }

    /// Shared access to the live explicit-transaction registry (`rmp` #637), so each connectivity
    /// seam registers its managed transactions into the one server-wide view that `SHOW
    /// TRANSACTIONS` / `TERMINATE TRANSACTIONS` read.
    #[must_use]
    pub fn transactions(&self) -> &Arc<crate::txn_registry::TransactionRegistry> {
        &self.txns
    }

    /// Shared access to the security audit log (rmp #70) so the seams can record their own events
    /// (e.g. index-DDL schema changes + their authz denials, and data-change events), at the same
    /// single sink the admin surface uses.
    #[must_use]
    pub fn audit(&self) -> &Arc<AuditLog> {
        &self.audit
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

    /// Authorizes `principal` for the administrative surface: it must be authenticated and hold the
    /// global `Admin` privilege — the same gate as the `/admin/*` REST endpoints (`04 §8.4`).
    ///
    /// This is the **single** admin-privilege gate, shared by the database surface
    /// ([`execute`](Self::execute)) and the index surface (`rmp` task #91; the seams call this before
    /// routing an index command to the engine). Authorization happens before any side effect, so a
    /// denied command leaves the system untouched. Audit of a denial is the **caller's**
    /// responsibility (rmp #70): [`execute`](Self::execute) audits database/security denials, and the
    /// seams audit index-DDL denials via [`audit`](Self::audit) — so the event carries the right
    /// class and detail.
    ///
    /// # Errors
    /// [`GraphusError::Security`] when the principal is absent (unauthenticated) or lacks the admin
    /// privilege — with the same messages the database surface uses, so the wire renderers classify
    /// both surfaces identically (`Neo.ClientError.Security.Forbidden` / HTTP 403).
    pub fn authorize_admin(&self, principal: Option<&str>) -> Result<(), GraphusError> {
        let principal = principal.ok_or_else(|| {
            GraphusError::Security(
                "administrative commands require an authenticated principal".to_owned(),
            )
        })?;
        // Read through the live security catalog (a brief read lock), so a just-revoked admin is
        // denied immediately rather than against a stale snapshot.
        let authorized = self
            .security
            .with_auth(|auth| auth.authorize(principal, &Privilege::admin_database()));
        if authorized {
            Ok(())
        } else {
            Err(GraphusError::Security(format!(
                "permission denied: administrative commands require the admin privilege \
                 (user {principal:?} does not hold it)"
            )))
        }
    }

    /// Authorizes `principal` for **schema/DDL** on the database `db` — index and constraint DDL
    /// (`CREATE`/`DROP INDEX`, `CREATE`/`DROP CONSTRAINT`; rmp #457). The principal must be
    /// authenticated and hold [`Action::Schema`](graphus_auth::Action::Schema) **scoped to that
    /// database's graph** ([`Privilege::on_graph`]). This is the gate that makes
    /// `GRANT SCHEMA ON GRAPH x` meaningful: an operator can delegate index/constraint management on
    /// one database without granting the global `Admin` super-privilege (which would also grant all
    /// data read/write and all security administration).
    ///
    /// **Fail-closed and never an escalation.** `Schema` does *not* imply any data action, and a
    /// graph-scoped grant never crosses database boundaries, so `SCHEMA ON GRAPH x` authorizes DDL on
    /// `x` and *nothing* on `y` (RBAC scope containment) and no data writes (RBAC action containment).
    /// Holders of `Admin` are unaffected: by the RBAC containment rules `Admin` over `Graph(x)`
    /// implies `Schema` over `Graph(x)`, and global `Admin` over [`Resource::Database`] covers every
    /// graph, so every existing admin still passes this gate. The check reads the **live** security
    /// catalog (a brief read lock), so a just-granted/revoked `SCHEMA` privilege takes effect on the
    /// very next DDL statement.
    ///
    /// Authorization happens before any side effect, so a denied command leaves the system untouched.
    /// Audit of a denial is the **caller's** responsibility (rmp #70): the seams audit the schema-DDL
    /// denial as `authz_denied` via [`audit`](Self::audit) so the event carries the right detail.
    ///
    /// # Errors
    /// [`GraphusError::Security`] when the principal is absent (unauthenticated) or holds neither
    /// `Schema` on `db` nor a privilege that implies it (e.g. `Admin`) — with a message the wire
    /// renderers classify as `Neo.ClientError.Security.Forbidden` / HTTP 403.
    pub fn authorize_schema(&self, principal: Option<&str>, db: &str) -> Result<(), GraphusError> {
        let principal = principal.ok_or_else(|| {
            GraphusError::Security(
                "schema (DDL) commands require an authenticated principal".to_owned(),
            )
        })?;
        // Read through the live security catalog (a brief read lock): a runtime grant/revoke of
        // `SCHEMA ON GRAPH db` is in effect immediately. `Admin` (graph- or server-scoped) satisfies
        // this through the RBAC containment rules, so admins are never blocked by the new gate.
        let wanted = Privilege::on_graph(graphus_auth::Action::Schema, db);
        let authorized = self
            .security
            .with_auth(|auth| auth.authorize(principal, &wanted));
        if authorized {
            Ok(())
        } else {
            Err(GraphusError::Security(format!(
                "permission denied: schema (index/constraint DDL) on database {db:?} requires the \
                 SCHEMA privilege on that database (user {principal:?} holds neither SCHEMA nor a \
                 privilege that implies it, such as ADMIN)"
            )))
        }
    }

    /// Executes an administrative command on behalf of `principal`, recording the audit trail
    /// (rmp #70): an authorization denial is always audited as `authz_denied` (with no side
    /// effects), and a *mutating* command's outcome is audited as `admin_change`/`security_change`
    /// (per [`classify_admin`]). Read-only `SHOW *` commands emit no change event. `source` is the
    /// connection the command arrived on (UDS/TCP Bolt or REST).
    ///
    /// # Errors
    /// As before: [`GraphusError::Security`] when unauthenticated/unauthorized; a client- or
    /// server-fault error from the catalog/security mutation.
    pub fn execute(
        &self,
        principal: Option<&str>,
        source: AuditSource,
        cmd: &AdminCommand,
    ) -> Result<AdminResult, GraphusError> {
        // Authorization first: a denial is ALWAYS audited (rmp #70) with no side effects.
        if let Err(e) = self.authorize_admin(principal) {
            self.audit.record(
                AuditEvent::new(AuditClass::AuthzDenied, AuditOutcome::Failure, source)
                    .actor(principal)
                    .database(admin_target_database(cmd).as_deref())
                    .detail(redact_admin_detail(cmd)),
            );
            return Err(e);
        }

        // Only mutating commands emit a change event; SHOW* are read-only (audited only on denial).
        let mutating = is_mutating_admin(cmd);
        let result = self.execute_authorized(cmd);
        if mutating {
            let outcome = if result.is_ok() {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failure
            };
            self.audit.record(
                AuditEvent::new(classify_admin(cmd), outcome, source)
                    .actor(principal)
                    .database(admin_target_database(cmd).as_deref())
                    .detail(redact_admin_detail(cmd)),
            );
        }
        // Populate the result summary on success (`rmp` #513): a system/catalog mutation reports query
        // type `s` + `system-updates`, a read-only `SHOW *` reports type `r` with no counters. A
        // failure returns `Err` here and carries no summary. This is the single funnel for **all**
        // database/security/operator commands, so neither connectivity seam duplicates the logic.
        result.map(|mut admin_result| {
            admin_result.summary = admin_command_summary(cmd);
            admin_result
        })
    }

    /// Executes an already-authorized administrative command (the mutation itself), without any
    /// audit side effects. Split out of [`execute`](Self::execute) so the audit funnel wraps it
    /// once, around both the success and failure paths.
    fn execute_authorized(&self, cmd: &AdminCommand) -> Result<AdminResult, GraphusError> {
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

            // ---- Security surface (rmp #92) ----
            AdminCommand::CreateUser {
                name,
                password,
                if_not_exists,
            } => self.run_security(*if_not_exists, false, {
                let security = Arc::clone(&self.security);
                let name = name.clone();
                let password = password.clone();
                move || async move { security.create_user(&name, password.as_deref()).await }
            }),
            AdminCommand::DropUser { name, if_exists } => self.run_security(false, *if_exists, {
                let security = Arc::clone(&self.security);
                let name = name.clone();
                move || async move { security.drop_user(&name).await }
            }),
            AdminCommand::CreateRole {
                name,
                if_not_exists,
            } => self.run_security(*if_not_exists, false, {
                let security = Arc::clone(&self.security);
                let name = name.clone();
                move || async move { security.create_role(&name).await }
            }),
            AdminCommand::DropRole { name, if_exists } => self.run_security(false, *if_exists, {
                let security = Arc::clone(&self.security);
                let name = name.clone();
                move || async move { security.drop_role(&name).await }
            }),
            AdminCommand::GrantRole { role, user } => self.run_security(false, false, {
                let security = Arc::clone(&self.security);
                let (role, user) = (role.clone(), user.clone());
                move || async move { security.grant_role(&user, &role).await }
            }),
            AdminCommand::RevokeRole { role, user } => self.run_security(false, false, {
                let security = Arc::clone(&self.security);
                let (role, user) = (role.clone(), user.clone());
                move || async move { security.revoke_role(&user, &role).await }
            }),
            AdminCommand::GrantPrivilege {
                action,
                scope,
                role,
            } => self.run_security(false, false, {
                let security = Arc::clone(&self.security);
                let role = role.clone();
                let privilege = Privilege::new(action.to_action(), scope.to_resource());
                move || async move { security.grant_privilege(&role, privilege).await }
            }),
            AdminCommand::DenyPrivilege {
                action,
                scope,
                role,
            } => self.run_security(false, false, {
                let security = Arc::clone(&self.security);
                let role = role.clone();
                let privilege = Privilege::new(action.to_action(), scope.to_resource());
                move || async move { security.deny_privilege(&role, privilege).await }
            }),
            AdminCommand::RevokePrivilege {
                action,
                scope,
                role,
                mode,
            } => self.run_security(false, false, {
                let security = Arc::clone(&self.security);
                let role = role.clone();
                let privilege = Privilege::new(action.to_action(), scope.to_resource());
                let mode = *mode;
                move || async move {
                    match mode {
                        // Plain REVOKE: remove whichever of grant/deny exists.
                        RevokeMode::Both => security.revoke_privilege(&role, privilege).await,
                        // REVOKE GRANT: the grant only.
                        RevokeMode::GrantOnly => {
                            security.revoke_granted_privilege(&role, privilege).await
                        }
                        // REVOKE DENY: the deny only.
                        RevokeMode::DenyOnly => {
                            security.revoke_deny_privilege(&role, privilege).await
                        }
                    }
                }
            }),
            AdminCommand::ShowUsers => Ok(show_users(&self.security.list_users())),
            AdminCommand::ShowRoles => Ok(show_roles(&self.security.list_roles())),
            AdminCommand::ShowPrivileges => Ok(show_privileges(&self.security.list_privileges())),
            AdminCommand::AlterUserPassword { name, password } => {
                self.run_security(false, false, {
                    let security = Arc::clone(&self.security);
                    let (name, password) = (name.clone(), password.clone());
                    move || async move { security.set_password(&name, &password).await }
                })
            }
            AdminCommand::AlterUserStatus { name, suspended } => self.run_security(false, false, {
                let security = Arc::clone(&self.security);
                let (name, suspended) = (name.clone(), *suspended);
                move || async move { security.set_user_status(&name, suspended).await }
            }),
            AdminCommand::RenameUser { from, to } => self.run_security(false, false, {
                let security = Arc::clone(&self.security);
                let (from, to) = (from.clone(), to.clone());
                move || async move { security.rename_user(&from, &to).await }
            }),
            AdminCommand::RenameRole { from, to } => self.run_security(false, false, {
                let security = Arc::clone(&self.security);
                let (from, to) = (from.clone(), to.clone());
                move || async move { security.rename_role(&from, &to).await }
            }),

            // ---- DBMS introspection surface (rmp #637) ----
            AdminCommand::ShowFunctions => Ok(show_functions()),
            AdminCommand::ShowProcedures => Ok(show_procedures()),
            AdminCommand::ShowSettings => Ok(settings_result(&self.config)),
            AdminCommand::ShowTransactions => Ok(show_transactions(&self.txns.snapshot())),
            AdminCommand::TerminateTransactions { ids } => {
                Ok(terminate_transactions(&self.txns.terminate(ids)))
            }

            // ---- Operator backup / restore surface (rmp #149) ----
            AdminCommand::BackupDatabase { name, path } => {
                let outcome = {
                    let catalog = Arc::clone(&self.catalog);
                    let (name, path) = (name.clone(), std::path::PathBuf::from(path));
                    self.run_on_runtime(async move { catalog.backup(&name, &path).await })?
                };
                outcome
                    .map(|()| AdminResult::empty())
                    .map_err(|e| graphus_error_from_catalog(&e))
            }
            AdminCommand::RestoreDatabase { name, path, point } => {
                let outcome = {
                    let catalog = Arc::clone(&self.catalog);
                    let (name, path) = (name.clone(), std::path::PathBuf::from(path));
                    let target = point.to_target();
                    self.run_on_runtime(async move { catalog.restore(&name, &path, target).await })?
                };
                outcome
                    .map(|()| AdminResult::empty())
                    .map_err(|e| graphus_error_from_catalog(&e))
            }

            // ---- Operator maintenance surface (rmp #305) ----
            AdminCommand::CheckpointDatabase { name } => {
                let outcome = {
                    let catalog = Arc::clone(&self.catalog);
                    let name = name.clone();
                    self.run_on_runtime(async move { catalog.checkpoint(&name).await })?
                };
                outcome
                    .map(|_report| AdminResult::empty())
                    .map_err(|e| graphus_error_from_catalog(&e))
            }
        }
    }

    /// Runs a security-catalog mutation on the runtime, applying the `IF [NOT] EXISTS` idempotency
    /// rules: an `AlreadyExists` becomes a no-op success under `if_not_exists`, a `NotFound` becomes
    /// a no-op success under `if_exists`. Every other [`SecurityError`] is mapped onto the engine
    /// error model (client vs. server fault) by [`graphus_error_from_security`].
    fn run_security<F, Fut>(
        &self,
        if_not_exists: bool,
        if_exists: bool,
        op: F,
    ) -> Result<AdminResult, GraphusError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = std::result::Result<(), SecurityError>> + Send + 'static,
    {
        let outcome = self.run_on_runtime(op())?;
        match outcome {
            Ok(()) => Ok(AdminResult::empty()),
            Err(SecurityError::Rbac(AuthError::AlreadyExists { .. })) if if_not_exists => {
                Ok(AdminResult::empty())
            }
            Err(SecurityError::Rbac(AuthError::NotFound { .. })) if if_exists => {
                Ok(AdminResult::empty())
            }
            Err(e) => Err(graphus_error_from_security(&e)),
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

/// The result summary for a **successful** administrative command (`rmp` #513), following the Neo4j
/// `SummaryCounters` contract:
///
/// - the system / catalog and security **mutations** (CREATE/DROP/START/STOP DATABASE,
///   CREATE/DROP USER/ROLE, GRANT/REVOKE ROLE/PRIVILEGE) report query type `"s"` (SCHEMA_WRITE) with
///   `system-updates` and the `contains-system-updates` flag — administration commands feed
///   `containsSystemUpdates`, **not** `containsUpdates`, so this is the system-side analogue of the
///   data path's `contains-updates`;
/// - the read-only `SHOW *` listings report query type `"r"` with no counters;
/// - the operator commands (`BACKUP`/`RESTORE`/`CHECKPOINT DATABASE`, which have no Neo4j-Cypher
///   equivalent) are administrative operations with no countable system-catalog change, so they report
///   `"s"` with no counters.
///
/// `system-updates` is reported as `1` for every successful mutation: the exact affected count is not
/// distinguishable at this funnel (an `IF [NOT] EXISTS` / `IF EXISTS` no-op also returns a successful
/// empty result), and `execute_authorized` returns a uniform empty [`AdminResult`] for both the real
/// change and the no-op. The acceptance contract (`rmp` #513) is `system-updates >= 1`.
fn admin_command_summary(cmd: &AdminCommand) -> RunSummary {
    use AdminCommand as A;
    match cmd {
        // Read-only listings → query type "r", no counters.
        A::ShowDatabases
        | A::ShowDatabase { .. }
        | A::ShowUsers
        | A::ShowRoles
        | A::ShowPrivileges
        | A::ShowFunctions
        | A::ShowProcedures
        | A::ShowSettings
        | A::ShowTransactions => RunSummary {
            query_type: Some("r".to_owned()),
            stats: Vec::new(),
            // An administrative command never goes through the Cypher planner: no plan (`rmp` #752).
            plan: None,
            // An administrative command is not a data-write transaction: no causal bookmark (`rmp` #807).
            bookmark: None,
        },
        // Catalog + security mutations → query type "s" + system-updates + contains-system-updates.
        A::CreateDatabase { .. }
        | A::DropDatabase { .. }
        | A::StartDatabase { .. }
        | A::StopDatabase { .. }
        | A::CreateUser { .. }
        | A::DropUser { .. }
        | A::CreateRole { .. }
        | A::DropRole { .. }
        | A::GrantRole { .. }
        | A::RevokeRole { .. }
        | A::GrantPrivilege { .. }
        | A::DenyPrivilege { .. }
        | A::RevokePrivilege { .. }
        | A::AlterUserPassword { .. }
        | A::AlterUserStatus { .. }
        | A::RenameUser { .. }
        | A::RenameRole { .. } => RunSummary {
            plan: None,
            query_type: Some("s".to_owned()),
            stats: vec![
                ("system-updates".to_owned(), Value::Integer(1)),
                ("contains-system-updates".to_owned(), Value::Boolean(true)),
            ],
            // A system-catalog update is not a graph data-write transaction: no causal bookmark
            // (`rmp` #807; bookmarks are per-database data-commit tokens, not system-database updates).
            bookmark: None,
        },
        // Operator commands: administrative operations, not countable system-catalog updates.
        A::BackupDatabase { .. }
        | A::RestoreDatabase { .. }
        | A::CheckpointDatabase { .. }
        | A::TerminateTransactions { .. } => RunSummary {
            query_type: Some("s".to_owned()),
            stats: Vec::new(),
            plan: None,
            // An operator command is not a data-write transaction: no causal bookmark (`rmp` #807).
            bookmark: None,
        },
    }
}

/// Builds the `SHOW DATABASE(S)` result from catalog listings: `name`, `state`
/// (`"online"`/`"offline"`/`"loading"`, the actual state — `"loading"` is a Mode A network
/// bulk-import session in progress, `rmp` #519), `default` (bool), `error` (string/null).
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
                        DbState::Loading => "loading",
                    }
                    .to_owned(),
                ),
                Value::Boolean(info.is_default),
                info.error.map_or(Value::Null, Value::String),
            ]
        })
        .collect();
    AdminResult {
        fields,
        rows,
        summary: RunSummary::default(),
    }
}

/// Builds the `SHOW USERS` result: `user` (string), `roles` (comma-joined string), `passwordSet`
/// (bool), `suspended` (bool, `rmp` #641).
fn show_users(users: &[crate::security::UserListing]) -> AdminResult {
    let fields = vec![
        "user".to_owned(),
        "roles".to_owned(),
        "passwordSet".to_owned(),
        "suspended".to_owned(),
    ];
    let rows = users
        .iter()
        .map(|u| {
            vec![
                Value::String(u.name.clone()),
                Value::String(u.roles.join(", ")),
                Value::Boolean(u.has_password),
                Value::Boolean(u.suspended),
            ]
        })
        .collect();
    AdminResult {
        fields,
        rows,
        summary: RunSummary::default(),
    }
}

/// Builds the `SHOW ROLES` result: `role` (string), `privilegeCount` (integer).
fn show_roles(roles: &[crate::security::RoleListing]) -> AdminResult {
    let fields = vec!["role".to_owned(), "privilegeCount".to_owned()];
    let rows = roles
        .iter()
        .map(|r| {
            vec![
                Value::String(r.name.clone()),
                Value::Integer(i64::try_from(r.privilege_count).unwrap_or(i64::MAX)),
            ]
        })
        .collect();
    AdminResult {
        fields,
        rows,
        summary: RunSummary::default(),
    }
}

/// Builds the `SHOW PRIVILEGES` result: `role` (string), `access` (`"GRANTED"`/`"DENIED"`),
/// `action` (string), `scope` (string). The `access` column distinguishes a granted privilege from
/// an explicitly denied one (`rmp` #645).
fn show_privileges(privs: &[crate::security::PrivilegeListing]) -> AdminResult {
    let fields = vec![
        "role".to_owned(),
        "access".to_owned(),
        "action".to_owned(),
        "scope".to_owned(),
    ];
    let rows = privs
        .iter()
        .map(|p| {
            vec![
                Value::String(p.role.clone()),
                Value::String(p.access.as_word().to_owned()),
                Value::String(p.action.clone()),
                Value::String(p.scope.clone()),
            ]
        })
        .collect();
    AdminResult {
        fields,
        rows,
        summary: RunSummary::default(),
    }
}

/// Builds the `SHOW FUNCTIONS` result (`rmp` #637) from the built-in function library
/// ([`graphus_cypher::function_registry::builtins`]): `name`, `category`, `description`,
/// `signature`, `isBuiltIn`, `aggregating`.
///
/// Only the built-in library is listed (every row has `isBuiltIn = true`). Argument *types* are not
/// modelled by the registry (its documented v1 scope), so `signature` renders positional argument
/// names from the accepted arity rather than typed parameters, and `category` is a coarse
/// classification derived from the function's name/aggregate flag using Neo4j's own category names.
fn show_functions() -> AdminResult {
    use graphus_cypher::function_registry as fr;
    let fields = vec![
        "name".to_owned(),
        "category".to_owned(),
        "description".to_owned(),
        "signature".to_owned(),
        "isBuiltIn".to_owned(),
        "aggregating".to_owned(),
    ];
    let rows = fr::builtins()
        .iter()
        .map(|sig| {
            let category = function_category(sig.name, sig.aggregate);
            vec![
                Value::String(sig.name.to_owned()),
                Value::String(category.to_owned()),
                Value::String(format!("The `{}` built-in function.", sig.name)),
                Value::String(function_signature_string(sig.name, sig.arity)),
                Value::Boolean(true),
                Value::Boolean(sig.aggregate),
            ]
        })
        .collect();
    AdminResult {
        fields,
        rows,
        summary: RunSummary::default(),
    }
}

/// A coarse category (using Neo4j's own category names) for a built-in function, derived from its
/// name and aggregate flag. Exact per-function categorisation is not modelled in the registry, so
/// this is a best-effort, documented classification: aggregating functions → `Aggregating`,
/// temporal/spatial names → `Temporal`/`Spatial`, everything else → `Scalar`.
fn function_category(name: &str, aggregate: bool) -> &'static str {
    if aggregate {
        return "Aggregating";
    }
    if name.starts_with("point") {
        return "Spatial";
    }
    if name.starts_with("date")
        || name.starts_with("datetime")
        || name.starts_with("time")
        || name.starts_with("localtime")
        || name.starts_with("localdatetime")
        || name.starts_with("duration")
    {
        return "Temporal";
    }
    "Scalar"
}

/// Renders a function `signature` string from its name and accepted [`graphus_cypher::function_registry::Arity`].
/// Argument *types* are not modelled, so arguments are positional placeholders (`argN`, a trailing
/// `?` for an optional one, `...` for variadic).
fn function_signature_string(
    name: &str,
    arity: graphus_cypher::function_registry::Arity,
) -> String {
    use graphus_cypher::function_registry::Arity;
    let args = match arity {
        Arity::Exact(n) => (0..n)
            .map(|i| format!("arg{i}"))
            .collect::<Vec<_>>()
            .join(", "),
        Arity::Range(lo, hi) => (0..hi)
            .map(|i| {
                if i < lo {
                    format!("arg{i}")
                } else {
                    format!("arg{i}?")
                }
            })
            .collect::<Vec<_>>()
            .join(", "),
        Arity::Variadic => "args...".to_owned(),
    };
    format!("{name}({args})")
}

/// Builds the `SHOW PROCEDURES` result (`rmp` #637): `name`, `description`, `signature`, `mode`,
/// `worksOnSystem`.
///
/// Lists the built-in procedures (`db.*`) and the full Graph Data Science surface (`gds.*`), rebuilt
/// from the same constructors the engine uses ([`graphus_cypher::ProcedureSet::with_builtins`] +
/// [`graphus_cypher::register_gds_procedures`]). `mode` is `READ` for a reader-safe procedure
/// (every built-in and GDS procedure is), else `WRITE`. `worksOnSystem` is `false` (these are
/// graph-level procedures). Deployment-registered sample UDPs are not part of the built-in surface
/// and are not listed.
fn show_procedures() -> AdminResult {
    let fields = vec![
        "name".to_owned(),
        "description".to_owned(),
        "signature".to_owned(),
        "mode".to_owned(),
        "worksOnSystem".to_owned(),
    ];
    let rows = builtin_procedure_listings()
        .iter()
        .map(|p| {
            vec![
                Value::String(p.name.clone()),
                Value::String(format!("The `{}` procedure.", p.name)),
                Value::String(procedure_signature_string(p)),
                Value::String(procedure_mode(&p.name, p.reader_safe).to_owned()),
                Value::Boolean(false),
            ]
        })
        .collect();
    AdminResult {
        fields,
        rows,
        summary: RunSummary::default(),
    }
}

/// The `SHOW PROCEDURES` `mode` column: `WRITE` only for a procedure that actually **mutates** the
/// graph (the GDS `.write` / `.mutate` surface, `rmp` #643), else `READ`.
///
/// `reader_safe` is a **threading** property (off-thread-reader-pool eligibility = no writes AND
/// thread-safe), NOT the access mode: `db.awaitIndex` and the `db.index.vector.query*` procedures
/// (`rmp` #671) are read procedures that run **inline** (the live HNSW / durable catalog is `!Send`),
/// so keying `mode` on `reader_safe` alone would mislabel them `WRITE`. Every reader-safe procedure is
/// unambiguously `READ`; among the non-reader-safe ones only the mutating GDS surface writes.
fn procedure_mode(name: &str, reader_safe: bool) -> &'static str {
    if reader_safe || !(name.ends_with(".write") || name.ends_with(".mutate")) {
        "READ"
    } else {
        "WRITE"
    }
}

/// The built-in + GDS procedure listings, rebuilt from the engine's own constructors. Cached: the
/// set is process-invariant (the GDS catalog handle affects execution, never the listed signatures),
/// so it is built once on first `SHOW PROCEDURES`.
fn builtin_procedure_listings() -> &'static [graphus_cypher::ProcedureListing] {
    static LISTINGS: std::sync::LazyLock<Vec<graphus_cypher::ProcedureListing>> =
        std::sync::LazyLock::new(|| {
            let mut set = graphus_cypher::ProcedureSet::with_builtins();
            graphus_cypher::register_gds_procedures(&mut set, graphus_cypher::new_gds_catalog());
            set.list()
        });
    &LISTINGS
}

/// Renders a procedure `signature` string from its declared, typed input/output fields (which the
/// procedure registry *does* model, unlike the function registry): `name(in :: TYPE, …) :: (out ::
/// TYPE, …)`.
fn procedure_signature_string(p: &graphus_cypher::ProcedureListing) -> String {
    let render = |fields: &[graphus_cypher::FieldSpec]| {
        fields
            .iter()
            .map(|f| match &f.default {
                // An optional input renders Neo4j's `name = default :: TYPE` (`rmp` task #667).
                Some(default) => {
                    format!(
                        "{} = {} :: {}",
                        f.name,
                        render_default_literal(default),
                        f.ty
                    )
                }
                None => format!("{} :: {}", f.name, f.ty),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "{}({}) :: ({})",
        p.name,
        render(&p.inputs),
        render(&p.outputs)
    )
}

/// Renders a procedure input's default value as a compact Cypher literal for the `SHOW PROCEDURES`
/// signature string (`rmp` task #667). Only the value kinds that appear as declared defaults are
/// handled precisely (an integer such as `300`, an empty map `{}`); anything else falls back to a
/// `?` placeholder rather than a wrong rendering.
fn render_default_literal(v: &Value) -> String {
    match v {
        Value::Null => "null".to_owned(),
        Value::Boolean(b) => b.to_string(),
        Value::Integer(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::String(s) => format!("'{s}'"),
        Value::List(l) if l.is_empty() => "[]".to_owned(),
        Value::Map(m) if m.is_empty() => "{}".to_owned(),
        _ => "?".to_owned(),
    }
}

/// Builds the `SHOW SETTINGS` result (`rmp` #637) from the effective configuration: `name`,
/// `value`, `isDynamic`, `isExplicitlySet`. `isDynamic` is `false` for every setting (Graphus
/// applies configuration at startup; none is live-reconfigurable). Secrets are already redacted by
/// [`ServerConfig::effective_settings`].
fn settings_result(config: &ServerConfig) -> AdminResult {
    let fields = vec![
        "name".to_owned(),
        "value".to_owned(),
        "isDynamic".to_owned(),
        "isExplicitlySet".to_owned(),
    ];
    let rows = config
        .effective_settings()
        .into_iter()
        .map(|row| {
            let is_set = row.value.is_some();
            vec![
                Value::String(row.name.to_owned()),
                row.value.map_or(Value::Null, Value::String),
                Value::Boolean(false),
                Value::Boolean(is_set),
            ]
        })
        .collect();
    AdminResult {
        fields,
        rows,
        summary: RunSummary::default(),
    }
}

/// Builds the `SHOW TRANSACTIONS` result (`rmp` #637) from the live explicit-transaction registry:
/// `transactionId`, `database`, `currentQuery`, `username`, `mode`, `status`, `startTime`,
/// `elapsedTimeMillis`, `protocol`, `clientAddress`. Only explicit (managed) transactions are
/// tracked; `clientAddress` is `null` when the seam did not record a peer address.
fn show_transactions(snapshots: &[crate::txn_registry::TxnSnapshot]) -> AdminResult {
    let fields = vec![
        "transactionId".to_owned(),
        "database".to_owned(),
        "currentQuery".to_owned(),
        "username".to_owned(),
        "mode".to_owned(),
        "status".to_owned(),
        "startTime".to_owned(),
        "elapsedTimeMillis".to_owned(),
        "protocol".to_owned(),
        "clientAddress".to_owned(),
    ];
    let rows = snapshots
        .iter()
        .map(|s| {
            vec![
                Value::String(s.id.clone()),
                Value::String(s.database.clone()),
                s.current_query.clone().map_or(Value::Null, Value::String),
                s.username.clone().map_or(Value::Null, Value::String),
                Value::String(s.mode.to_owned()),
                Value::String(s.status.to_owned()),
                system_time_to_value(s.started_wall),
                Value::Integer(i64::try_from(s.elapsed.as_millis()).unwrap_or(i64::MAX)),
                Value::String(s.protocol.to_owned()),
                s.client_address.clone().map_or(Value::Null, Value::String),
            ]
        })
        .collect();
    AdminResult {
        fields,
        rows,
        summary: RunSummary::default(),
    }
}

/// Renders a [`SystemTime`](std::time::SystemTime) as a UTC [`Value::LocalDateTime`] (seconds +
/// nanoseconds since the Unix epoch); a pre-epoch or unrepresentable time falls back to
/// [`Value::Null`].
fn system_time_to_value(t: std::time::SystemTime) -> Value {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => Value::LocalDateTime(graphus_core::LocalDateTime {
            epoch_seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            nanos: d.subsec_nanos(),
        }),
        Err(_) => Value::Null,
    }
}

/// Builds the `TERMINATE TRANSACTIONS` result (`rmp` #637): one row per requested id —
/// `transactionId`, `database`, `username`, `message` (`"Terminated"` / `"Transaction not found"`).
fn terminate_transactions(outcomes: &[crate::txn_registry::TerminateOutcome]) -> AdminResult {
    let fields = vec![
        "transactionId".to_owned(),
        "database".to_owned(),
        "username".to_owned(),
        "message".to_owned(),
    ];
    let rows = outcomes
        .iter()
        .map(|o| {
            vec![
                Value::String(o.id.clone()),
                o.database.clone().map_or(Value::Null, Value::String),
                o.username.clone().map_or(Value::Null, Value::String),
                Value::String(o.message.to_owned()),
            ]
        })
        .collect();
    AdminResult {
        fields,
        rows,
        summary: RunSummary::default(),
    }
}

/// Maps a [`SecurityError`] onto the engine error model with the same client/server fault split as
/// [`graphus_error_from_catalog`]: a client-fault RBAC rejection (unknown/duplicate user or role)
/// and a lock-out refusal are [`GraphusError::Runtime`] (Bolt `Neo.ClientError.*`, HTTP 400); an
/// I/O / corruption / encode fault is [`GraphusError::Storage`] (`Neo.DatabaseError.*`, HTTP 500).
fn graphus_error_from_security(e: &SecurityError) -> GraphusError {
    match e {
        SecurityError::Rbac(_) | SecurityError::WouldLockOutAdmin { .. } => {
            GraphusError::Runtime(e.to_string())
        }
        SecurityError::Io { .. } | SecurityError::Corrupt { .. } | SecurityError::Encode(_) => {
            GraphusError::Storage(e.to_string())
        }
    }
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
        | CatalogError::NotLoadable(_)
        | CatalogError::Backup(_)
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

    fn index_cmd(query: &str) -> IndexCommand {
        match parse_admin_statement(query) {
            AdminParse::Index(c) => c,
            other => panic!("expected an index command for {query:?}, got {other:?}"),
        }
    }

    fn constraint_cmd(query: &str) -> ConstraintCommand {
        match parse_admin_statement(query) {
            AdminParse::Constraint(c) => c,
            other => panic!("expected a constraint command for {query:?}, got {other:?}"),
        }
    }

    /// Builds the expected `CREATE CONSTRAINT` command for a **node** constraint (`rmp` #638 test
    /// helper), with the idempotency flags off by default.
    fn node_constraint(
        name: &str,
        label: &str,
        properties: &[&str],
        kind: ConstraintCreateKind,
    ) -> ConstraintCommand {
        ConstraintCommand::Create(CreateConstraint {
            name: name.to_owned(),
            entity: ConstraintEntity::Node {
                label: label.to_owned(),
            },
            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
            kind,
            if_not_exists: false,
            or_replace: false,
        })
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

    // ---- DBMS introspection surface (rmp #637) --------------------------------------------------

    #[test]
    fn introspection_show_listings_parse() {
        assert_eq!(cmd("SHOW FUNCTIONS"), AdminCommand::ShowFunctions);
        assert_eq!(cmd("SHOW PROCEDURES"), AdminCommand::ShowProcedures);
        assert_eq!(cmd("SHOW SETTINGS"), AdminCommand::ShowSettings);
        assert_eq!(cmd("SHOW TRANSACTIONS"), AdminCommand::ShowTransactions);
        // Case-insensitive keywords + a tolerated trailing `;`.
        assert_eq!(cmd("show functions"), AdminCommand::ShowFunctions);
        assert_eq!(cmd("SHOW   Transactions ;"), AdminCommand::ShowTransactions);
    }

    #[test]
    fn introspection_rejects_non_show_verb_and_trailing_tokens() {
        // Only SHOW takes these plurals.
        assert!(invalid("CREATE FUNCTIONS").contains("SHOW"));
        assert!(invalid("DROP PROCEDURES").contains("SHOW"));
        // No trailing tokens.
        assert!(!invalid("SHOW FUNCTIONS extra").is_empty());
        // The singular is not a claimed form; it passes through to Cypher untouched.
        not_admin("SHOW FUNCTION");
    }

    #[test]
    fn terminate_transactions_parse() {
        assert_eq!(
            cmd("TERMINATE TRANSACTIONS 'graphus-transaction-1'"),
            AdminCommand::TerminateTransactions {
                ids: vec!["graphus-transaction-1".to_owned()],
            }
        );
        // Multiple comma-separated ids.
        assert_eq!(
            cmd("TERMINATE TRANSACTIONS 'a-transaction-1', 'b-transaction-2'"),
            AdminCommand::TerminateTransactions {
                ids: vec!["a-transaction-1".to_owned(), "b-transaction-2".to_owned()],
            }
        );
        // The singular keyword is tolerated (Neo4j-lenient).
        assert_eq!(
            cmd("TERMINATE TRANSACTION 'x-transaction-9'"),
            AdminCommand::TerminateTransactions {
                ids: vec!["x-transaction-9".to_owned()],
            }
        );
    }

    #[test]
    fn terminate_transactions_rejects_malformed() {
        assert!(invalid("TERMINATE TRANSACTIONS").contains("transaction id"));
        assert!(invalid("TERMINATE").contains("TRANSACTIONS"));
        // A bare (unquoted) id is not accepted — ids are quoted string literals.
        assert!(!invalid("TERMINATE TRANSACTIONS foo").is_empty());
        // A dangling comma with no following id.
        assert!(!invalid("TERMINATE TRANSACTIONS 'a', ").is_empty());
    }

    #[test]
    fn show_functions_result_shape() {
        let r = show_functions();
        assert_eq!(
            r.fields,
            vec![
                "name",
                "category",
                "description",
                "signature",
                "isBuiltIn",
                "aggregating"
            ]
        );
        // Every built-in is reported (non-empty) and marked isBuiltIn = true.
        assert!(!r.rows.is_empty());
        assert_eq!(
            r.rows.len(),
            graphus_cypher::function_registry::builtins().len()
        );
        for row in &r.rows {
            assert_eq!(row.len(), 6);
            assert_eq!(row[4], Value::Boolean(true), "isBuiltIn must be true");
        }
        // An aggregating function is categorised + flagged as such.
        let count_row = r
            .rows
            .iter()
            .find(|row| row[0] == Value::String("count".to_owned()))
            .expect("count is a built-in");
        assert_eq!(count_row[1], Value::String("Aggregating".to_owned()));
        assert_eq!(count_row[5], Value::Boolean(true));
    }

    #[test]
    fn show_procedures_result_includes_builtins_and_gds() {
        let r = show_procedures();
        assert_eq!(
            r.fields,
            vec!["name", "description", "signature", "mode", "worksOnSystem"]
        );
        let names: Vec<&Value> = r.rows.iter().map(|row| &row[0]).collect();
        assert!(names.contains(&&Value::String("db.labels".to_owned())));
        // The GDS surface is listed (rebuilt from the engine's own constructors).
        assert!(
            r.rows
                .iter()
                .any(|row| matches!(&row[0], Value::String(n) if n.starts_with("gds."))),
            "SHOW PROCEDURES must include the gds.* surface"
        );
        for row in &r.rows {
            assert_eq!(row.len(), 5);
            // Every procedure reports a valid mode (`READ` for reader-safe procedures, `WRITE` for
            // the mutating `gds.*.write` / `gds.*.mutate` surface landed in rmp #643) and none works
            // on the system database.
            assert!(
                matches!(&row[3], Value::String(m) if m == "READ" || m == "WRITE"),
                "procedure mode must be READ or WRITE: {row:?}"
            );
            assert_eq!(row[4], Value::Boolean(false));
        }
        // The read-only `db.*` built-ins are reader-safe (mode READ)...
        let db_labels = r
            .rows
            .iter()
            .find(|row| row[0] == Value::String("db.labels".to_owned()))
            .expect("db.labels is a built-in");
        assert_eq!(db_labels[3], Value::String("READ".to_owned()));
        // ...while a `gds.*.write` procedure, if present, reports mode WRITE (rmp #643).
        if let Some(gds_write) = r
            .rows
            .iter()
            .find(|row| matches!(&row[0], Value::String(n) if n.ends_with(".write")))
        {
            assert_eq!(
                gds_write[3],
                Value::String("WRITE".to_owned()),
                "a gds.*.write procedure must report mode WRITE: {gds_write:?}"
            );
        }
    }

    #[test]
    fn show_procedures_lists_new_index_procedures_with_signatures() {
        // `rmp` task #667: the new index procedures are listed, and the optional-argument default
        // renders in the signature string (`timeOutSeconds = 300 :: INTEGER`).
        let r = show_procedures();
        let row_for = |name: &str| {
            r.rows
                .iter()
                .find(|row| row[0] == Value::String(name.to_owned()))
                .unwrap_or_else(|| panic!("SHOW PROCEDURES must list `{name}`"))
                .clone()
        };
        // Procedure names are stored canonically lower-cased (case-insensitive lookup), so the listed
        // `name` column is lower-cased; the argument names keep their casing (`indexName`, …).
        for name in [
            "db.awaitindex",
            "db.index.fulltext.awaiteventuallyconsistentindexrefresh",
            "db.index.fulltext.listavailableanalyzers",
        ] {
            let _ = row_for(name);
        }
        // The optional-argument default is rendered Neo4j-style in the signature string.
        let await_index = row_for("db.awaitindex");
        let Value::String(sig) = &await_index[2] else {
            panic!("signature column must be a string");
        };
        assert!(
            sig.contains("timeOutSeconds = 300 :: INTEGER"),
            "db.awaitIndex signature must render the optional default: {sig}"
        );
        assert!(sig.contains("indexName :: STRING"), "signature: {sig}");
        // listAvailableAnalyzers renders its three output columns.
        let analyzers = row_for("db.index.fulltext.listavailableanalyzers");
        let Value::String(asig) = &analyzers[2] else {
            panic!("signature column must be a string");
        };
        assert!(asig.contains("analyzer :: STRING"), "signature: {asig}");
        assert!(asig.contains("stopwords :: ANY"), "signature: {asig}");
        // queryNodes renders the optional options MAP default `{}`.
        let query_nodes = row_for("db.index.fulltext.querynodes");
        let Value::String(qsig) = &query_nodes[2] else {
            panic!("signature column must be a string");
        };
        assert!(
            qsig.contains("options = {} :: ANY"),
            "queryNodes must render the optional options default: {qsig}"
        );
    }

    #[test]
    fn show_procedures_lists_vector_query_procedures_as_read() {
        // `rmp` task #671: the vector query procedures are listed with their typed signatures and — key
        // — mode READ (they read the graph; `reader_safe = false` is only a threading property).
        let r = show_procedures();
        let row_for = |name: &str| {
            r.rows
                .iter()
                .find(|row| row[0] == Value::String(name.to_owned()))
                .unwrap_or_else(|| panic!("SHOW PROCEDURES must list `{name}`"))
                .clone()
        };
        for name in [
            "db.index.vector.querynodes",
            "db.index.vector.queryrelationships",
        ] {
            let row = row_for(name);
            assert_eq!(row[3], Value::String("READ".to_owned()), "mode: {row:?}");
        }
        let Value::String(nodes_sig) = &row_for("db.index.vector.querynodes")[2] else {
            panic!("signature column must be a string");
        };
        assert!(
            nodes_sig.contains("indexName :: STRING")
                && nodes_sig.contains("numberOfNearestNeighbours :: INTEGER")
                && nodes_sig.contains("query :: ANY")
                && nodes_sig.contains("node :: NODE")
                && nodes_sig.contains("score :: FLOAT"),
            "queryNodes signature: {nodes_sig}"
        );
        let Value::String(rels_sig) = &row_for("db.index.vector.queryrelationships")[2] else {
            panic!("signature column must be a string");
        };
        assert!(
            rels_sig.contains("relationship :: RELATIONSHIP")
                && rels_sig.contains("score :: FLOAT"),
            "queryRelationships signature: {rels_sig}"
        );
    }

    #[test]
    fn show_functions_lists_vector_similarity_functions() {
        // `rmp` task #671: the two vector similarity functions appear in the built-in library.
        let r = show_functions();
        for name in ["vector.similarity.cosine", "vector.similarity.euclidean"] {
            let row = r
                .rows
                .iter()
                .find(|row| row[0] == Value::String(name.to_owned()))
                .unwrap_or_else(|| panic!("SHOW FUNCTIONS must list `{name}`"));
            assert_eq!(
                row[1],
                Value::String("Scalar".to_owned()),
                "category: {row:?}"
            );
            assert_eq!(row[5], Value::Boolean(false), "not aggregating: {row:?}");
        }
    }

    #[test]
    fn show_settings_redacts_secrets_and_uses_dotted_names() {
        let cfg = ServerConfig::default();
        let r = settings_result(&cfg);
        assert_eq!(
            r.fields,
            vec!["name", "value", "isDynamic", "isExplicitlySet"]
        );
        // Dotted, canonical names are present.
        let names: Vec<String> = r
            .rows
            .iter()
            .map(|row| match &row[0] {
                Value::String(s) => s.clone(),
                other => panic!("name must be a string, got {other:?}"),
            })
            .collect();
        assert!(names.iter().any(|n| n == "admission.reader_threads"));
        assert!(names.iter().any(|n| n == "timing.statement_timeout_ms"));
        // jwt_secret is present but redacted (never its value).
        let jwt = r
            .rows
            .iter()
            .find(|row| row[0] == Value::String("jwt_secret".to_owned()))
            .expect("jwt_secret is listed");
        assert_eq!(jwt[1], Value::String("<redacted>".to_owned()));
        // Every setting is startup-only (isDynamic = false).
        for row in &r.rows {
            assert_eq!(row[2], Value::Boolean(false));
        }
    }

    #[test]
    fn introspection_summaries_are_read_only_and_terminate_is_system() {
        use crate::audit::is_mutating_admin;
        for c in [
            AdminCommand::ShowFunctions,
            AdminCommand::ShowProcedures,
            AdminCommand::ShowSettings,
            AdminCommand::ShowTransactions,
        ] {
            assert_eq!(admin_command_summary(&c).query_type.as_deref(), Some("r"));
            assert!(!is_mutating_admin(&c), "SHOW * is read-only");
        }
        let term = AdminCommand::TerminateTransactions { ids: vec![] };
        assert_eq!(
            admin_command_summary(&term).query_type.as_deref(),
            Some("s")
        );
        assert!(
            is_mutating_admin(&term),
            "TERMINATE mutates transaction state"
        );
    }

    // ---- Security DDL: ALTER USER + RENAME (rmp #641) -------------------------------------------

    #[test]
    fn alter_user_set_password_parses() {
        assert_eq!(
            cmd("ALTER USER alice SET PASSWORD 'secret'"),
            AdminCommand::AlterUserPassword {
                name: "alice".to_owned(),
                password: "secret".to_owned(),
            }
        );
        // A backtick-quoted name + a password containing spaces.
        assert_eq!(
            cmd("ALTER USER `weird name` SET PASSWORD 'p a s s'"),
            AdminCommand::AlterUserPassword {
                name: "weird name".to_owned(),
                password: "p a s s".to_owned(),
            }
        );
    }

    #[test]
    fn alter_user_set_status_parses() {
        assert_eq!(
            cmd("ALTER USER alice SET STATUS SUSPENDED"),
            AdminCommand::AlterUserStatus {
                name: "alice".to_owned(),
                suspended: true,
            }
        );
        assert_eq!(
            cmd("ALTER USER alice SET STATUS ACTIVE"),
            AdminCommand::AlterUserStatus {
                name: "alice".to_owned(),
                suspended: false,
            }
        );
    }

    #[test]
    fn alter_user_requires_a_supported_set_clause() {
        // A SET clause is mandatory; `ALTER USER x` alone is a syntax error.
        assert!(invalid("ALTER USER alice").contains("SET"));
        // An unsupported clause is rejected clearly (not silently ignored).
        assert!(invalid("ALTER USER alice SET HOME DATABASE db").contains("PASSWORD or STATUS"));
        assert!(invalid("ALTER USER alice SET STATUS BOGUS").contains("ACTIVE or SUSPENDED"));
        assert!(!invalid("ALTER DATABASE x").is_empty());
    }

    #[test]
    fn rename_user_and_role_parse() {
        assert_eq!(
            cmd("RENAME USER alice TO alicia"),
            AdminCommand::RenameUser {
                from: "alice".to_owned(),
                to: "alicia".to_owned(),
            }
        );
        assert_eq!(
            cmd("RENAME ROLE reader TO viewer"),
            AdminCommand::RenameRole {
                from: "reader".to_owned(),
                to: "viewer".to_owned(),
            }
        );
    }

    #[test]
    fn rename_rejects_malformed() {
        assert!(invalid("RENAME USER alice").contains("TO"));
        assert!(invalid("RENAME alice TO bob").contains("USER or ROLE"));
        assert!(!invalid("RENAME USER alice TO bob extra").is_empty());
    }

    #[test]
    fn alter_rename_never_swallow_cypher() {
        // These verbs are claimed only as security DDL; a MATCH/RETURN using them as identifiers is
        // not affected because ALTER/RENAME are never valid Cypher statement starts.
        not_admin("MATCH (n) RETURN n");
    }

    #[test]
    fn alter_password_redaction_never_leaks() {
        use crate::audit::redact_admin_detail;
        let c = AdminCommand::AlterUserPassword {
            name: "alice".to_owned(),
            password: "topsecret".to_owned(),
        };
        let detail = redact_admin_detail(&c);
        assert!(detail.contains("<redacted>"));
        assert!(
            !detail.contains("topsecret"),
            "the password must never be logged"
        );
    }

    /// `rmp` #513 GATE: the admin-command result summary classification. A system / catalog or security
    /// mutation reports query type `s` with `system-updates: 1` + `contains-system-updates`; the
    /// read-only `SHOW *` listings report type `r` with no counters; the operator commands
    /// (`BACKUP`/`RESTORE`/`CHECKPOINT DATABASE`) report `s` with no countable system-catalog change.
    #[test]
    fn admin_command_summary_classifies_type_and_system_updates() {
        let system_mutations = [
            cmd("CREATE DATABASE sales"),
            cmd("DROP DATABASE sales"),
            cmd("CREATE USER carol SET PASSWORD 'carol-pw8'"),
            // Constructed directly: covers the security GRANT-role and GRANT-privilege arms without a
            // dependency on the grant grammar's parse path (tested elsewhere).
            AdminCommand::GrantRole {
                role: "reader".to_owned(),
                user: "carol".to_owned(),
            },
            AdminCommand::GrantPrivilege {
                action: PrivAction::Read,
                scope: PrivScope::Database,
                role: "reader".to_owned(),
            },
        ];
        for c in &system_mutations {
            let s = admin_command_summary(c);
            assert_eq!(
                s.query_type.as_deref(),
                Some("s"),
                "{c:?} is a schema/system write"
            );
            assert_eq!(
                s.stats,
                vec![
                    ("system-updates".to_owned(), Value::Integer(1)),
                    ("contains-system-updates".to_owned(), Value::Boolean(true)),
                ],
                "{c:?}: type s, system-updates 1, contains-system-updates flag"
            );
        }

        for q in [
            "SHOW DATABASES",
            "SHOW USERS",
            "SHOW ROLES",
            "SHOW PRIVILEGES",
        ] {
            let s = admin_command_summary(&cmd(q));
            assert_eq!(s.query_type.as_deref(), Some("r"), "{q} is a read");
            assert!(s.stats.is_empty(), "{q} reports no counters");
        }

        // An operator command: administrative, but no countable system-catalog change.
        let s = admin_command_summary(&AdminCommand::CheckpointDatabase {
            name: "sales".to_owned(),
        });
        assert_eq!(s.query_type.as_deref(), Some("s"));
        assert!(
            s.stats.is_empty(),
            "CHECKPOINT reports no system-updates counter"
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
        not_admin(""); // empty input
        not_admin("   "); // blank input
        not_admin("`create` database x"); // a quoted first token is not a keyword

        // The index surface (rmp #91) must likewise never swallow regular Cypher: a node labelled
        // `Index`, a query merely mentioning the words, a prefixed identifier, and `SHOW` of
        // something unrelated all pass through. `SHOW INDEXES` itself is now ours (tested below).
        not_admin("CREATE (n:Index)");
        not_admin("CREATE (n:Index {name: 'x'}) RETURN n");
        not_admin("RETURN 'CREATE INDEX ON :Person(age)'");
        not_admin("CREATE INDEX_X");
        not_admin("MATCH (n:Index) RETURN n");
        not_admin("showindexes"); // single token, not the two-token prefix
        // `SHOW CONSTRAINTS` is now claimed by the constraint surface (`rmp` task #99), tested in the
        // constraint-grammar tests below. A node labelled `Constraint`, a query merely mentioning the
        // word, and a prefixed identifier still pass through untouched.
        not_admin("CREATE (n:Constraint)");
        not_admin("CREATE CONSTRAINT_X");
        not_admin("MATCH (n:Constraint) RETURN n");
        not_admin("showconstraints"); // single token, not the two-token prefix
    }

    /// A `CreateNodePropertyIndex` with the anonymous / no-`IF` defaults, for the terse assertions.
    fn create_np(label: &str, property: &str) -> IndexCommand {
        IndexCommand::CreateNodePropertyIndex {
            name: None,
            label: label.to_owned(),
            properties: vec![property.to_owned()],
            if_not_exists: false,
        }
    }

    /// A composite `CreateNodePropertyIndex` with the anonymous / no-`IF` defaults (`rmp` task #657).
    fn create_np_composite(label: &str, properties: &[&str]) -> IndexCommand {
        IndexCommand::CreateNodePropertyIndex {
            name: None,
            label: label.to_owned(),
            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
            if_not_exists: false,
        }
    }

    #[test]
    fn create_index_both_shapes() {
        // openCypher 9 form.
        assert_eq!(
            index_cmd("CREATE INDEX FOR (n:Person) ON (n.age)"),
            create_np("Person", "age")
        );
        // Legacy form.
        assert_eq!(
            index_cmd("CREATE INDEX ON :Person(age)"),
            create_np("Person", "age")
        );
        // Case-insensitive keywords, surrounding whitespace, trailing `;`, backtick-quoted names.
        assert_eq!(
            index_cmd("  create   index   for ( p : `Sales-Rep` )  on ( p.`first.name` ) ;"),
            create_np("Sales-Rep", "first.name")
        );
        // A different variable letter in the ON clause is fine (the variable text is irrelevant).
        assert_eq!(
            index_cmd("CREATE INDEX FOR (a:Tag) ON (a.name)"),
            create_np("Tag", "name")
        );
    }

    #[test]
    fn create_index_named_and_if_not_exists() {
        // Named openCypher form (`rmp` task #624).
        assert_eq!(
            index_cmd("CREATE INDEX ix_person FOR (p:Person) ON (p.name)"),
            IndexCommand::CreateNodePropertyIndex {
                name: Some("ix_person".to_owned()),
                label: "Person".to_owned(),
                properties: vec!["name".to_owned()],
                if_not_exists: false,
            }
        );
        // Named + IF NOT EXISTS.
        assert_eq!(
            index_cmd("CREATE INDEX ix_person IF NOT EXISTS FOR (p:PERSON) ON (p.name)"),
            IndexCommand::CreateNodePropertyIndex {
                name: Some("ix_person".to_owned()),
                label: "PERSON".to_owned(),
                properties: vec!["name".to_owned()],
                if_not_exists: true,
            }
        );
        // Anonymous + IF NOT EXISTS (no name, still idempotent).
        assert_eq!(
            index_cmd("CREATE INDEX IF NOT EXISTS FOR (p:Person) ON (p.age)"),
            IndexCommand::CreateNodePropertyIndex {
                name: None,
                label: "Person".to_owned(),
                properties: vec!["age".to_owned()],
                if_not_exists: true,
            }
        );
        // A back-ticked name colliding with a keyword still works.
        assert_eq!(
            index_cmd("CREATE INDEX `for` FOR (p:Person) ON (p.age)"),
            IndexCommand::CreateNodePropertyIndex {
                name: Some("for".to_owned()),
                label: "Person".to_owned(),
                properties: vec!["age".to_owned()],
                if_not_exists: false,
            }
        );
    }

    #[test]
    fn create_composite_index_parses_property_tuple() {
        // Composite (multi-property) node index (`rmp` task #657): the `ON (n.a, n.b)` tuple parses to a
        // multi-element `properties` list in declared order.
        assert_eq!(
            index_cmd("CREATE INDEX FOR (n:Person) ON (n.first, n.last)"),
            create_np_composite("Person", &["first", "last"])
        );
        // Three keys, whitespace + trailing `;` + backtick-quoted names + a different variable letter.
        assert_eq!(
            index_cmd("  create index  for ( p : `Sales-Rep` ) on ( p.a , p.`b.c` , p.d ) ;"),
            create_np_composite("Sales-Rep", &["a", "b.c", "d"])
        );
        // Named + IF NOT EXISTS composite, and the RANGE synonym over a tuple.
        assert_eq!(
            index_cmd("CREATE INDEX ix IF NOT EXISTS FOR (n:Person) ON (n.a, n.b)"),
            IndexCommand::CreateNodePropertyIndex {
                name: Some("ix".to_owned()),
                label: "Person".to_owned(),
                properties: vec!["a".to_owned(), "b".to_owned()],
                if_not_exists: true,
            }
        );
        assert_eq!(
            index_cmd("CREATE RANGE INDEX r FOR (n:Person) ON (n.a, n.b)"),
            IndexCommand::CreateNodePropertyIndex {
                name: Some("r".to_owned()),
                label: "Person".to_owned(),
                properties: vec!["a".to_owned(), "b".to_owned()],
                if_not_exists: false,
            }
        );
        // Order is significant: (a, b) parses distinctly from (b, a).
        assert_ne!(
            index_cmd("CREATE INDEX FOR (n:Person) ON (n.a, n.b)"),
            index_cmd("CREATE INDEX FOR (n:Person) ON (n.b, n.a)")
        );
    }

    #[test]
    fn single_property_index_stays_one_element_list() {
        // A single-property `ON (n.p)` and the legacy `ON :L(p)` both yield a 1-element list — identical
        // to the pre-composite behaviour (`rmp` task #657).
        assert_eq!(
            index_cmd("CREATE INDEX FOR (n:Person) ON (n.age)"),
            IndexCommand::CreateNodePropertyIndex {
                name: None,
                label: "Person".to_owned(),
                properties: vec!["age".to_owned()],
                if_not_exists: false,
            }
        );
        assert_eq!(
            index_cmd("CREATE INDEX ON :Person(age)"),
            IndexCommand::CreateNodePropertyIndex {
                name: None,
                label: "Person".to_owned(),
                properties: vec!["age".to_owned()],
                if_not_exists: false,
            }
        );
    }

    #[test]
    fn composite_index_rejects_empty_and_duplicate_property_lists() {
        // An empty property list `ON ()` is a syntax error (no property to index).
        assert!(!invalid("CREATE INDEX FOR (n:Person) ON ()").is_empty());
        // A duplicate property in the tuple is rejected with a clear message.
        let dup = invalid("CREATE INDEX FOR (n:Person) ON (n.a, n.a)");
        assert!(dup.contains("duplicate property"), "{dup}");
        let dup3 = invalid("CREATE INDEX FOR (n:Person) ON (n.a, n.b, n.a)");
        assert!(dup3.contains("duplicate property"), "{dup3}");
    }

    #[test]
    fn drop_composite_index_by_target_parses_property_tuple() {
        // The by-target drop of a composite index carries the ordered property tuple (`rmp` task #657).
        assert_eq!(
            index_cmd("DROP INDEX FOR (n:Person) ON (n.a, n.b)"),
            IndexCommand::DropNodePropertyIndex {
                index: NodePropertyIndexRef::Target {
                    label: "Person".to_owned(),
                    properties: vec!["a".to_owned(), "b".to_owned()],
                },
                if_exists: false,
            }
        );
    }

    #[test]
    fn composite_relationship_index_parses_property_tuple() {
        // A relationship composite `ON (r.a, r.b)` now parses to a multi-element `properties` list in
        // declared order (`rmp` task #666); the durable relationship-composite backing store exists.
        assert_eq!(
            index_cmd("CREATE INDEX FOR ()-[r:KNOWS]-() ON (r.a, r.b)"),
            IndexCommand::CreateRelPropertyIndex {
                name: None,
                rel_type: "KNOWS".to_owned(),
                properties: vec!["a".to_owned(), "b".to_owned()],
                if_not_exists: false,
            }
        );
        // Named + IF NOT EXISTS composite, three keys, backtick-quoted names, RANGE synonym.
        assert_eq!(
            index_cmd(
                "CREATE RANGE INDEX ix IF NOT EXISTS FOR ()-[r:`R-T`]-() ON (r.a, r.`b.c`, r.d)"
            ),
            IndexCommand::CreateRelPropertyIndex {
                name: Some("ix".to_owned()),
                rel_type: "R-T".to_owned(),
                properties: vec!["a".to_owned(), "b.c".to_owned(), "d".to_owned()],
                if_not_exists: true,
            }
        );
        // Order is significant: (a, b) parses distinctly from (b, a).
        assert_ne!(
            index_cmd("CREATE INDEX FOR ()-[r:KNOWS]-() ON (r.a, r.b)"),
            index_cmd("CREATE INDEX FOR ()-[r:KNOWS]-() ON (r.b, r.a)")
        );
        // A duplicate property in the tuple is rejected with a clear message.
        let dup = invalid("CREATE INDEX FOR ()-[r:KNOWS]-() ON (r.a, r.a)");
        assert!(dup.contains("duplicate property"), "{dup}");
        // A single-property relationship index still parses to a 1-element list (unchanged).
        assert_eq!(
            index_cmd("CREATE INDEX FOR ()-[r:KNOWS]-() ON (r.since)"),
            IndexCommand::CreateRelPropertyIndex {
                name: None,
                rel_type: "KNOWS".to_owned(),
                properties: vec!["since".to_owned()],
                if_not_exists: false,
            }
        );
        // The by-target DROP of a composite relationship index carries the ordered property tuple.
        assert_eq!(
            index_cmd("DROP INDEX FOR ()-[r:KNOWS]-() ON (r.a, r.b)"),
            IndexCommand::DropRelPropertyIndex {
                index: RelPropertyIndexRef::Target {
                    rel_type: "KNOWS".to_owned(),
                    properties: vec!["a".to_owned(), "b".to_owned()],
                },
                if_exists: false,
            }
        );
    }

    #[test]
    fn typed_range_is_a_node_property_synonym_and_text_is_a_distinct_kind() {
        // RANGE is a full synonym of the node-property index (`rmp` #638).
        assert_eq!(
            index_cmd("CREATE RANGE INDEX ix FOR (n:Person) ON (n.name)"),
            IndexCommand::CreateNodePropertyIndex {
                name: Some("ix".to_owned()),
                label: "Person".to_owned(),
                properties: vec!["name".to_owned()],
                if_not_exists: false,
            }
        );
        // TEXT is a DISTINCT native trigram string index, NOT a RANGE synonym (`rmp` task #662): it
        // produces its own `CreateTextIndex` command.
        assert_eq!(
            index_cmd("CREATE TEXT INDEX t IF NOT EXISTS FOR (n:Person) ON (n.nick)"),
            IndexCommand::CreateTextIndex {
                name: "t".to_owned(),
                label: "Person".to_owned(),
                property: "nick".to_owned(),
                if_not_exists: true,
            }
        );
        // An anonymous TEXT create gets a deterministic auto-name; a trailing OPTIONS clause parses.
        assert_eq!(
            index_cmd("CREATE TEXT INDEX FOR (n:Person) ON (n.bio) OPTIONS {}"),
            IndexCommand::CreateTextIndex {
                name: "text_index_Person_bio".to_owned(),
                label: "Person".to_owned(),
                property: "bio".to_owned(),
                if_not_exists: false,
            }
        );
        // DROP TEXT produces its own command; DROP RANGE delegates to the node-property form.
        assert_eq!(
            index_cmd("DROP TEXT INDEX t IF EXISTS"),
            IndexCommand::DropTextIndex {
                name: "t".to_owned(),
                if_exists: true,
            }
        );
        assert_eq!(
            index_cmd("DROP RANGE INDEX ix"),
            IndexCommand::DropNodePropertyIndex {
                index: NodePropertyIndexRef::Named("ix".to_owned()),
                if_exists: false,
            }
        );
        // The `SHOW <filter> INDEXES` forms map to the unified listing filtered by type (`rmp` #660).
        assert_eq!(
            index_cmd("SHOW RANGE INDEXES"),
            IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::Range,
                tail: None,
            }
        );
        assert_eq!(
            index_cmd("SHOW TEXT INDEXES"),
            IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::Text,
                tail: None,
            }
        );
    }

    /// `rmp` #660: every `SHOW <filter> INDEXES` form parses to the ONE unified `ShowIndexes`, filtered
    /// by index type — including `LOOKUP` (now a listing, not a decline), `VECTOR` (an empty listing,
    /// not a syntax error) and the shared `ALL` lead. A `YIELD`/`WHERE` tail is captured verbatim.
    #[test]
    fn show_indexes_filter_forms_and_tail() {
        let show = |filter, tail: Option<&str>| IndexCommand::ShowIndexes {
            filter,
            tail: tail.map(str::to_owned),
        };
        assert_eq!(
            index_cmd("SHOW ALL INDEXES"),
            show(IndexTypeFilter::All, None)
        );
        assert_eq!(
            index_cmd("SHOW POINT INDEXES"),
            show(IndexTypeFilter::Point, None)
        );
        assert_eq!(
            index_cmd("SHOW LOOKUP INDEXES"),
            show(IndexTypeFilter::Lookup, None)
        );
        assert_eq!(
            index_cmd("SHOW FULLTEXT INDEXES"),
            show(IndexTypeFilter::Fulltext, None)
        );
        assert_eq!(
            index_cmd("SHOW VECTOR INDEXES"),
            show(IndexTypeFilter::Vector, None),
            "SHOW VECTOR INDEXES is an empty listing, not a syntax error"
        );
        // A YIELD tail is captured verbatim (translated by the seam).
        assert_eq!(
            index_cmd("SHOW INDEXES YIELD name, type WHERE type = 'POINT' RETURN name"),
            show(
                IndexTypeFilter::All,
                Some("YIELD name, type WHERE type = 'POINT' RETURN name")
            )
        );
        // A terse WHERE tail after a filter is captured too.
        assert_eq!(
            index_cmd("SHOW RANGE INDEXES WHERE entityType = 'NODE'"),
            show(IndexTypeFilter::Range, Some("WHERE entityType = 'NODE'"))
        );
        // `SHOW ALL CONSTRAINTS` still routes to the constraint surface (the ALL lead is disambiguated
        // by the terminal keyword), not the index surface.
        assert_eq!(
            parse_admin_statement("SHOW ALL CONSTRAINTS"),
            AdminParse::Constraint(ConstraintCommand::Show {
                filter: ConstraintTypeFilter::All,
                tail: None,
            })
        );
    }

    #[test]
    fn lookup_index_ddl_is_declined_but_show_is_a_listing() {
        // CREATE/DROP LOOKUP is implicit / always-on in Graphus and declined.
        let msg = invalid("CREATE LOOKUP INDEX ix FOR (n) ON EACH labels(n)");
        assert!(msg.contains("LOOKUP index DDL is not supported"), "{msg}");
        // But `SHOW LOOKUP INDEXES` is a valid listing (`rmp` #660).
        assert_eq!(
            index_cmd("SHOW LOOKUP INDEXES"),
            IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::Lookup,
                tail: None,
            }
        );
    }

    #[test]
    fn create_relationship_property_index_plain_named_and_if_not_exists() {
        // Plain, anonymous relationship-property index (`rmp` task #646).
        assert_eq!(
            index_cmd("CREATE INDEX FOR ()-[r:KNOWS]-() ON (r.since)"),
            IndexCommand::CreateRelPropertyIndex {
                name: None,
                rel_type: "KNOWS".to_owned(),
                properties: vec!["since".to_owned()],
                if_not_exists: false,
            }
        );
        // Named + IF NOT EXISTS, mixed case around the pattern.
        assert_eq!(
            index_cmd("CREATE INDEX rel_ix IF NOT EXISTS FOR ()-[e:RATED]-() ON (e.stars)"),
            IndexCommand::CreateRelPropertyIndex {
                name: Some("rel_ix".to_owned()),
                rel_type: "RATED".to_owned(),
                properties: vec!["stars".to_owned()],
                if_not_exists: true,
            }
        );
        // The typed RANGE / TEXT surfaces accept the relationship form too (served by the same B-tree).
        assert_eq!(
            index_cmd("CREATE RANGE INDEX ix FOR ()-[r:KNOWS]-() ON (r.since)"),
            IndexCommand::CreateRelPropertyIndex {
                name: Some("ix".to_owned()),
                rel_type: "KNOWS".to_owned(),
                properties: vec!["since".to_owned()],
                if_not_exists: false,
            }
        );
    }

    #[test]
    fn drop_relationship_property_index_by_target_and_directed_is_rejected() {
        assert_eq!(
            index_cmd("DROP INDEX FOR ()-[r:KNOWS]-() ON (r.since)"),
            IndexCommand::DropRelPropertyIndex {
                index: RelPropertyIndexRef::Target {
                    rel_type: "KNOWS".to_owned(),
                    properties: vec!["since".to_owned()],
                },
                if_exists: false,
            }
        );
        // A directed relationship pattern is a syntax error (only the undirected form is accepted).
        assert!(
            !invalid("CREATE INDEX FOR ()-[r:KNOWS]->() ON (r.since)").is_empty(),
            "a directed rel pattern must be rejected"
        );
    }

    #[test]
    fn drop_index_by_target_and_show_indexes() {
        assert_eq!(
            index_cmd("DROP INDEX ON :Person(age)"),
            IndexCommand::DropNodePropertyIndex {
                index: NodePropertyIndexRef::Target {
                    label: "Person".to_owned(),
                    properties: vec!["age".to_owned()],
                },
                if_exists: false,
            }
        );
        assert_eq!(
            index_cmd("drop index for (n:Person) on (n.age)"),
            IndexCommand::DropNodePropertyIndex {
                index: NodePropertyIndexRef::Target {
                    label: "Person".to_owned(),
                    properties: vec!["age".to_owned()],
                },
                if_exists: false,
            }
        );
        // Bare `SHOW INDEXES` is the unified listing with no filter and no tail (`rmp` #660).
        assert_eq!(
            index_cmd("SHOW INDEXES"),
            IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::All,
                tail: None,
            }
        );
        assert_eq!(
            index_cmd("show indexes ;"),
            IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::All,
                tail: None,
            }
        );
    }

    #[test]
    fn drop_index_by_name_and_if_exists() {
        assert_eq!(
            index_cmd("DROP INDEX ix_person"),
            IndexCommand::DropNodePropertyIndex {
                index: NodePropertyIndexRef::Named("ix_person".to_owned()),
                if_exists: false,
            }
        );
        assert_eq!(
            index_cmd("DROP INDEX ix_person IF EXISTS"),
            IndexCommand::DropNodePropertyIndex {
                index: NodePropertyIndexRef::Named("ix_person".to_owned()),
                if_exists: true,
            }
        );
        // A back-ticked name colliding with a keyword still works.
        assert_eq!(
            index_cmd("DROP INDEX `on` IF EXISTS"),
            IndexCommand::DropNodePropertyIndex {
                index: NodePropertyIndexRef::Named("on".to_owned()),
                if_exists: true,
            }
        );
    }

    #[test]
    fn claimed_but_malformed_index_is_a_syntax_error() {
        // Claimed by the two-token `<verb> INDEX[ES]` prefix; the remainder must parse exactly.
        invalid("CREATE INDEX"); // missing target
        invalid("CREATE INDEX FOR (n:Person)"); // missing ON clause
        invalid("CREATE INDEX FOR (n:Person) ON (n.age) extra");
        invalid("CREATE INDEX ix FOR (n:Person) ON (n.age) extra"); // named + trailing junk
        invalid("CREATE INDEX ON Person(age)"); // legacy needs the leading `:`
        invalid("CREATE INDEX ON :Person"); // missing (property)
        invalid("CREATE INDEX FOR (n:Person) ON (age)"); // ON ref must be `var.property`
        invalid("CREATE INDEX ix_person"); // a name with no target
        invalid("CREATE INDEX ix IF NOT EXISTS"); // IF NOT EXISTS with no target
        invalid("CREATE INDEXES FOR (n:Person) ON (n.age)"); // plural only for SHOW
        invalid("SHOW INDEXES extra");
        invalid("SHOW INDEX extra"); // the singular still rejects trailing junk (`rmp` #661)
        invalid("DROP INDEX"); // missing name/target
        invalid("DROP INDEX ix_person extra"); // by-name + trailing junk
        invalid("DROP INDEX ix_person IF NOT EXISTS"); // DROP takes IF EXISTS, not IF NOT EXISTS
        invalid("DROP INDEX ON :Person(age) trailing");
        invalid("CREATE INDEX ON :`unterminated(age)"); // unterminated backtick name
    }

    #[test]
    fn create_fulltext_index_default_and_with_options() {
        // Single property, default analyzer (standard).
        assert_eq!(
            index_cmd("CREATE FULLTEXT INDEX articles FOR (n:Article) ON EACH [n.title]"),
            IndexCommand::CreateFulltextIndex {
                name: "articles".to_owned(),
                entity: FulltextEntity::Node,
                labels_or_types: vec!["Article".to_owned()],
                properties: vec!["title".to_owned()],
                analyzer: "standard".to_owned(),
                if_not_exists: false,
            }
        );
        // Multiple properties + explicit analyzer, case-insensitive keywords + whitespace + `;`.
        assert_eq!(
            index_cmd(
                "  create   fulltext index  books  for ( b : Book ) on each [ b.title , b.summary ] \
                 options { analyzer: 'keyword' } ;"
            ),
            IndexCommand::CreateFulltextIndex {
                name: "books".to_owned(),
                entity: FulltextEntity::Node,
                labels_or_types: vec!["Book".to_owned()],
                properties: vec!["title".to_owned(), "summary".to_owned()],
                analyzer: "keyword".to_owned(),
                if_not_exists: false,
            }
        );
        // Backtick-quoted name/label/property colliding with keywords still parse.
        assert_eq!(
            index_cmd("CREATE FULLTEXT INDEX `INDEX` FOR (n:`Order`) ON EACH [n.`from`]"),
            IndexCommand::CreateFulltextIndex {
                name: "INDEX".to_owned(),
                entity: FulltextEntity::Node,
                labels_or_types: vec!["Order".to_owned()],
                properties: vec!["from".to_owned()],
                analyzer: "standard".to_owned(),
                if_not_exists: false,
            }
        );
    }

    #[test]
    fn create_fulltext_multi_label_node_and_relationship() {
        // `rmp` task #663: multi-label node index (`A|B`).
        assert_eq!(
            index_cmd("CREATE FULLTEXT INDEX ml FOR (n:Article|Blog) ON EACH [n.title]"),
            IndexCommand::CreateFulltextIndex {
                name: "ml".to_owned(),
                entity: FulltextEntity::Node,
                labels_or_types: vec!["Article".to_owned(), "Blog".to_owned()],
                properties: vec!["title".to_owned()],
                analyzer: "standard".to_owned(),
                if_not_exists: false,
            }
        );
        // Relationship index, single type (undirected `()-[r:T]-()`).
        assert_eq!(
            index_cmd("CREATE FULLTEXT INDEX rf FOR ()-[r:KNOWS]-() ON EACH [r.note]"),
            IndexCommand::CreateFulltextIndex {
                name: "rf".to_owned(),
                entity: FulltextEntity::Relationship,
                labels_or_types: vec!["KNOWS".to_owned()],
                properties: vec!["note".to_owned()],
                analyzer: "standard".to_owned(),
                if_not_exists: false,
            }
        );
        // Relationship index, multi-type + explicit analyzer, whitespace/case-insensitive.
        assert_eq!(
            index_cmd(
                "create fulltext index rm for ()-[ e : RATED | REVIEWED ]-() on each \
                 [ e.body , e.title ] options { analyzer: 'keyword' }"
            ),
            IndexCommand::CreateFulltextIndex {
                name: "rm".to_owned(),
                entity: FulltextEntity::Relationship,
                labels_or_types: vec!["RATED".to_owned(), "REVIEWED".to_owned()],
                properties: vec!["body".to_owned(), "title".to_owned()],
                analyzer: "keyword".to_owned(),
                if_not_exists: false,
            }
        );
        // A directed relationship arrow is rejected (only the undirected form is accepted).
        assert!(
            !invalid("CREATE FULLTEXT INDEX rf FOR ()-[r:KNOWS]->() ON EACH [r.note]").is_empty()
        );
    }

    #[test]
    fn drop_and_show_fulltext() {
        assert_eq!(
            index_cmd("DROP FULLTEXT INDEX articles"),
            IndexCommand::DropFulltextIndex {
                name: "articles".to_owned(),
                if_exists: false,
            }
        );
        assert_eq!(
            index_cmd("drop fulltext index `My Index` ;"),
            IndexCommand::DropFulltextIndex {
                name: "My Index".to_owned(),
                if_exists: false,
            }
        );
        // `SHOW FULLTEXT INDEXES` folds into the unified listing filtered to FULLTEXT (`rmp` #660).
        assert_eq!(
            index_cmd("SHOW FULLTEXT INDEXES"),
            IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::Fulltext,
                tail: None,
            }
        );
        assert_eq!(
            index_cmd("show fulltext indexes ;"),
            IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::Fulltext,
                tail: None,
            }
        );
    }

    #[test]
    fn claimed_but_malformed_fulltext_is_a_syntax_error() {
        invalid("CREATE FULLTEXT"); // missing INDEX
        invalid("CREATE FULLTEXT INDEX"); // missing name
        invalid("CREATE FULLTEXT INDEX ft"); // missing FOR clause
        invalid("CREATE FULLTEXT INDEX ft FOR (n:Article)"); // missing ON EACH
        invalid("CREATE FULLTEXT INDEX ft FOR (n:Article) ON [n.title]"); // ON must be ON EACH
        invalid("CREATE FULLTEXT INDEX ft FOR (n:Article) ON EACH []"); // at least one property
        invalid("CREATE FULLTEXT INDEX ft FOR (n:Article) ON EACH [title]"); // ref must be var.prop
        invalid("CREATE FULLTEXT INDEX ft FOR (n:Article) ON EACH [n.title] extra");
        invalid("CREATE FULLTEXT INDEX ft FOR (n:Article) ON EACH [n.title] OPTIONS { bad: 'x' }");
        invalid(
            "CREATE FULLTEXT INDEX ft FOR (n:Article) ON EACH [n.title] OPTIONS { analyzer: x }",
        ); // unquoted
        invalid("SHOW FULLTEXT INDEXES extra");
        invalid("SHOW FULLTEXT INDEX extra"); // the singular still rejects trailing junk
        invalid("DROP FULLTEXT INDEX"); // missing name
        invalid("DROP FULLTEXT INDEX ft trailing");
        invalid("CREATE FULLTEXT INDEXES ..."); // plural only for SHOW
    }

    #[test]
    fn create_point_index_form() {
        // The Neo4j-compatible single-property shape (`rmp` task #98).
        assert_eq!(
            index_cmd("CREATE POINT INDEX by_loc FOR (n:City) ON (n.location)"),
            IndexCommand::CreatePointIndex {
                name: "by_loc".to_owned(),
                entity: SpatialEntity::Node,
                label: "City".to_owned(),
                property: "location".to_owned(),
                if_not_exists: false,
            }
        );
        // Case-insensitive keywords + whitespace + trailing `;`.
        assert_eq!(
            index_cmd("  create   point index  near  for ( p : Place ) on ( p.geo ) ;"),
            IndexCommand::CreatePointIndex {
                name: "near".to_owned(),
                entity: SpatialEntity::Node,
                label: "Place".to_owned(),
                property: "geo".to_owned(),
                if_not_exists: false,
            }
        );
        // Backtick-quoted name/label/property colliding with keywords still parse.
        assert_eq!(
            index_cmd("CREATE POINT INDEX `INDEX` FOR (n:`Order`) ON (n.`from`)"),
            IndexCommand::CreatePointIndex {
                name: "INDEX".to_owned(),
                entity: SpatialEntity::Node,
                label: "Order".to_owned(),
                property: "from".to_owned(),
                if_not_exists: false,
            }
        );
    }

    #[test]
    fn create_point_index_relationship_form() {
        // `rmp` task #664: the undirected relationship pattern `FOR ()-[r:T]-() ON (r.p)` yields a
        // relationship point index (entity Relationship, the covered token is a rel type).
        assert_eq!(
            index_cmd("CREATE POINT INDEX rel_at FOR ()-[r:VISITED]-() ON (r.at)"),
            IndexCommand::CreatePointIndex {
                name: "rel_at".to_owned(),
                entity: SpatialEntity::Relationship,
                label: "VISITED".to_owned(),
                property: "at".to_owned(),
                if_not_exists: false,
            }
        );
        // An anonymous relationship point index auto-names with the `rel_` infix, keeping it distinct
        // from a node index over the same-named token.
        assert_eq!(
            index_cmd("CREATE POINT INDEX FOR ()-[r:VISITED]-() ON (r.at)"),
            IndexCommand::CreatePointIndex {
                name: "point_index_rel_VISITED_at".to_owned(),
                entity: SpatialEntity::Relationship,
                label: "VISITED".to_owned(),
                property: "at".to_owned(),
                if_not_exists: false,
            }
        );
        // A directed arrow is a syntax error (only the undirected form is accepted, like FULLTEXT).
        invalid("CREATE POINT INDEX rel_at FOR ()-[r:VISITED]->() ON (r.at)");
    }

    #[test]
    fn drop_and_show_point() {
        assert_eq!(
            index_cmd("DROP POINT INDEX by_loc"),
            IndexCommand::DropPointIndex {
                name: "by_loc".to_owned(),
                if_exists: false,
            }
        );
        assert_eq!(
            index_cmd("drop point index `My Index` ;"),
            IndexCommand::DropPointIndex {
                name: "My Index".to_owned(),
                if_exists: false,
            }
        );
        // `SHOW POINT INDEXES` folds into the unified listing filtered to POINT (`rmp` #660).
        assert_eq!(
            index_cmd("SHOW POINT INDEXES"),
            IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::Point,
                tail: None,
            }
        );
        assert_eq!(
            index_cmd("show point indexes ;"),
            IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::Point,
                tail: None,
            }
        );
    }

    #[test]
    fn claimed_but_malformed_point_is_a_syntax_error() {
        invalid("CREATE POINT"); // missing INDEX
        invalid("CREATE POINT INDEX"); // missing FOR clause (the name is optional since `rmp` #661)
        invalid("CREATE POINT INDEX p"); // missing FOR clause
        invalid("CREATE POINT INDEX p FOR (n:City)"); // missing ON
        invalid("CREATE POINT INDEX p FOR (n:City) ON EACH [n.loc]"); // point uses single ON (...)
        invalid("CREATE POINT INDEX p FOR (n:City) ON (loc)"); // ref must be var.prop
        invalid("CREATE POINT INDEX p FOR (n:City) ON (n.loc) extra");
        invalid("SHOW POINT INDEXES extra");
        invalid("SHOW POINT INDEX extra"); // the singular still rejects trailing junk
        invalid("DROP POINT INDEX"); // missing name
        invalid("DROP POINT INDEX p trailing");
        invalid("CREATE POINT INDEXES ..."); // plural only for SHOW
    }

    // --- `rmp` #671: CREATE/DROP VECTOR INDEX + OPTIONS { indexConfig { … } } ----------------------

    /// Builds the expected `CREATE VECTOR INDEX` command for a **node** index (`rmp` #671 test helper).
    #[allow(clippy::too_many_arguments)]
    fn vector_node_cmd(
        name: Option<&str>,
        label: &str,
        property: &str,
        dimensions: usize,
        similarity: VectorSimilarity,
        m: usize,
        ef_construction: usize,
        if_not_exists: bool,
    ) -> IndexCommand {
        IndexCommand::CreateVectorIndex {
            name: name.map(str::to_owned),
            entity: VectorEntity::Node,
            label_or_type: label.to_owned(),
            property: property.to_owned(),
            dimensions,
            similarity,
            m,
            ef_construction,
            if_not_exists,
        }
    }

    #[test]
    fn create_vector_index_node_form() {
        // The Neo4j-compatible node shape with a full indexConfig (backtick-quoted config keys).
        assert_eq!(
            index_cmd(
                "CREATE VECTOR INDEX emb FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { indexConfig: { `vector.dimensions`: 1536, \
                 `vector.similarity_function`: 'cosine', `vector.hnsw.m`: 16, \
                 `vector.hnsw.ef_construction`: 100 } }"
            ),
            vector_node_cmd(
                Some("emb"),
                "Doc",
                "embedding",
                1536,
                VectorSimilarity::Cosine,
                16,
                100,
                false,
            )
        );
        // Case-insensitive keywords + similarity, bare (un-backticked) dotted config keys, `indexProvider`
        // accepted-and-ignored, whitespace + trailing `;`.
        assert_eq!(
            index_cmd(
                "  create vector index near for ( p : Place ) on ( p.vec ) \
                 options { indexProvider: 'vector-2.0', indexConfig: { vector.dimensions: 3, \
                 vector.similarity_function: 'EUCLIDEAN' } } ;"
            ),
            vector_node_cmd(
                Some("near"),
                "Place",
                "vec",
                3,
                VectorSimilarity::Euclidean,
                16,  // default m
                100, // default ef_construction
                false,
            )
        );
        // Backtick-quoted name/label/property colliding with keywords still parse.
        assert_eq!(
            index_cmd(
                "CREATE VECTOR INDEX `INDEX` FOR (n:`Order`) ON (n.`from`) \
                 OPTIONS { indexConfig: { `vector.dimensions`: 8, \
                 `vector.similarity_function`: 'cosine' } }"
            ),
            vector_node_cmd(
                Some("INDEX"),
                "Order",
                "from",
                8,
                VectorSimilarity::Cosine,
                16,
                100,
                false,
            )
        );
    }

    #[test]
    fn create_vector_index_relationship_form() {
        // The undirected relationship pattern `FOR ()-[r:T]-() ON (r.p)` yields a relationship vector
        // index (entity Relationship, the covered token is a rel type).
        assert_eq!(
            index_cmd(
                "CREATE VECTOR INDEX rel_emb FOR ()-[r:SIMILAR]-() ON (r.vec) \
                 OPTIONS { indexConfig: { `vector.dimensions`: 3, \
                 `vector.similarity_function`: 'euclidean', `vector.hnsw.m`: 24, \
                 `vector.hnsw.ef_construction`: 200 } }"
            ),
            IndexCommand::CreateVectorIndex {
                name: Some("rel_emb".to_owned()),
                entity: VectorEntity::Relationship,
                label_or_type: "SIMILAR".to_owned(),
                property: "vec".to_owned(),
                dimensions: 3,
                similarity: VectorSimilarity::Euclidean,
                m: 24,
                ef_construction: 200,
                if_not_exists: false,
            }
        );
        // A directed arrow is a syntax error (only the undirected form is accepted, like POINT/FULLTEXT).
        invalid(
            "CREATE VECTOR INDEX rel_emb FOR ()-[r:SIMILAR]->() ON (r.vec) \
             OPTIONS { indexConfig: { `vector.dimensions`: 3, `vector.similarity_function`: 'cosine' } }",
        );
    }

    #[test]
    fn create_vector_index_optional_name_and_if_not_exists() {
        // An anonymous vector index → name None (the coordinator auto-names).
        assert_eq!(
            index_cmd(
                "CREATE VECTOR INDEX FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { indexConfig: { `vector.dimensions`: 4, \
                 `vector.similarity_function`: 'cosine' } }"
            ),
            vector_node_cmd(
                None,
                "Doc",
                "embedding",
                4,
                VectorSimilarity::Cosine,
                16,
                100,
                false
            )
        );
        // `IF NOT EXISTS` after the (omitted) name.
        assert_eq!(
            index_cmd(
                "CREATE VECTOR INDEX IF NOT EXISTS FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { indexConfig: { `vector.dimensions`: 4, \
                 `vector.similarity_function`: 'cosine' } }"
            ),
            vector_node_cmd(
                None,
                "Doc",
                "embedding",
                4,
                VectorSimilarity::Cosine,
                16,
                100,
                true
            )
        );
        // `IF NOT EXISTS` after an explicit name.
        assert_eq!(
            index_cmd(
                "CREATE VECTOR INDEX emb IF NOT EXISTS FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { indexConfig: { `vector.dimensions`: 4, \
                 `vector.similarity_function`: 'cosine' } }"
            ),
            vector_node_cmd(
                Some("emb"),
                "Doc",
                "embedding",
                4,
                VectorSimilarity::Cosine,
                16,
                100,
                true
            )
        );
    }

    #[test]
    fn create_vector_index_accepts_unknown_indexconfig_key() {
        // An unknown `indexConfig` key is accepted and ignored (Neo4j leniency, matching `rmp` #661).
        assert_eq!(
            index_cmd(
                "CREATE VECTOR INDEX emb FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { indexConfig: { `vector.dimensions`: 4, \
                 `vector.similarity_function`: 'cosine', `vector.quantization.enabled`: true } }"
            ),
            vector_node_cmd(
                Some("emb"),
                "Doc",
                "embedding",
                4,
                VectorSimilarity::Cosine,
                16,
                100,
                false
            )
        );
    }

    #[test]
    fn create_vector_index_option_validation() {
        // Missing OPTIONS entirely.
        assert!(
            invalid("CREATE VECTOR INDEX emb FOR (n:Doc) ON (n.embedding)")
                .contains("requires an OPTIONS")
        );
        // Missing indexConfig map.
        assert!(
            invalid(
                "CREATE VECTOR INDEX emb FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { indexProvider: 'vector-2.0' }"
            )
            .contains("requires an `indexConfig`")
        );
        // Missing required `vector.dimensions`.
        assert!(
            invalid(
                "CREATE VECTOR INDEX emb FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { indexConfig: { `vector.similarity_function`: 'cosine' } }"
            )
            .contains("requires `vector.dimensions`")
        );
        // Missing required `vector.similarity_function`.
        assert!(
            invalid(
                "CREATE VECTOR INDEX emb FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { indexConfig: { `vector.dimensions`: 4 } }"
            )
            .contains("requires `vector.similarity_function`")
        );
        // Dimension out of range (0 and > 4096).
        assert!(
            invalid(
                "CREATE VECTOR INDEX emb FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { indexConfig: { `vector.dimensions`: 0, \
                 `vector.similarity_function`: 'cosine' } }"
            )
            .contains("between 1 and 4096")
        );
        assert!(
            invalid(
                "CREATE VECTOR INDEX emb FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { indexConfig: { `vector.dimensions`: 4097, \
                 `vector.similarity_function`: 'cosine' } }"
            )
            .contains("between 1 and 4096")
        );
        // Non-integer dimensions.
        assert!(
            invalid(
                "CREATE VECTOR INDEX emb FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { indexConfig: { `vector.dimensions`: 'lots', \
                 `vector.similarity_function`: 'cosine' } }"
            )
            .contains("integer")
        );
        // Unknown similarity.
        assert!(
            invalid(
                "CREATE VECTOR INDEX emb FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { indexConfig: { `vector.dimensions`: 4, \
                 `vector.similarity_function`: 'jaccard' } }"
            )
            .contains("similarity_function")
        );
        // Non-positive HNSW parameter.
        assert!(
            invalid(
                "CREATE VECTOR INDEX emb FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { indexConfig: { `vector.dimensions`: 4, \
                 `vector.similarity_function`: 'cosine', `vector.hnsw.m`: 0 } }"
            )
            .contains("positive integer")
        );
        // Unknown TOP-LEVEL OPTIONS key is a clear error (unlike a lenient indexConfig key).
        assert!(
            invalid(
                "CREATE VECTOR INDEX emb FOR (n:Doc) ON (n.embedding) \
                 OPTIONS { bogus: 1, indexConfig: { `vector.dimensions`: 4, \
                 `vector.similarity_function`: 'cosine' } }"
            )
            .contains("unknown vector index OPTIONS key")
        );
    }

    #[test]
    fn drop_and_show_vector() {
        assert_eq!(
            index_cmd("DROP VECTOR INDEX emb"),
            IndexCommand::DropVectorIndex {
                name: "emb".to_owned(),
                if_exists: false,
            }
        );
        assert_eq!(
            index_cmd("drop vector index `My Index` if exists ;"),
            IndexCommand::DropVectorIndex {
                name: "My Index".to_owned(),
                if_exists: true,
            }
        );
        // `SHOW VECTOR INDEXES` folds into the unified listing filtered to VECTOR (`rmp` #660).
        assert_eq!(
            index_cmd("SHOW VECTOR INDEXES"),
            IndexCommand::ShowIndexes {
                filter: IndexTypeFilter::Vector,
                tail: None,
            }
        );
    }

    #[test]
    fn claimed_but_malformed_vector_is_a_syntax_error() {
        invalid("CREATE VECTOR"); // missing INDEX
        invalid("CREATE VECTOR INDEX"); // missing FOR clause (the name is optional)
        invalid("CREATE VECTOR INDEX v"); // missing FOR clause
        invalid("CREATE VECTOR INDEX v FOR (n:Doc)"); // missing ON
        invalid("CREATE VECTOR INDEX v FOR (n:Doc) ON EACH [n.e]"); // vector uses single ON (...)
        invalid("CREATE VECTOR INDEX v FOR (n:Doc) ON (e)"); // ref must be var.prop
        // Well-formed pattern but trailing junk after a complete OPTIONS clause.
        invalid(
            "CREATE VECTOR INDEX v FOR (n:Doc) ON (n.e) \
             OPTIONS { indexConfig: { `vector.dimensions`: 4, `vector.similarity_function`: 'cosine' } } extra",
        );
        invalid("DROP VECTOR INDEX"); // missing name
        invalid("DROP VECTOR INDEX v trailing");
        invalid("CREATE VECTOR INDEXES ..."); // plural only for SHOW
    }

    // --- `rmp` #661: OPTIONS clause + IF (NOT) EXISTS + optional POINT name + singular SHOW ---------

    /// `OPTIONS { indexProvider, indexConfig { … } }` parses on RANGE/TEXT (the node-property synonym);
    /// the clause is accepted and ignored (single built-in provider), so the parsed command is the same
    /// as without it (`rmp` #661).
    #[test]
    fn options_clause_parses_on_range_text_indexes() {
        let bare = index_cmd("CREATE INDEX ix FOR (n:Person) ON (n.age)");
        assert_eq!(
            index_cmd(
                "CREATE INDEX ix FOR (n:Person) ON (n.age) \
                 OPTIONS { indexProvider: 'range-1.0', indexConfig: { `spatial.cartesian.min`: [-100.0, -100.0] } }"
            ),
            bare,
            "OPTIONS is accepted and ignored on a RANGE/plain index"
        );
        // RANGE + TEXT synonyms accept OPTIONS too.
        assert_eq!(
            index_cmd(
                "CREATE RANGE INDEX r FOR (n:P) ON (n.a) OPTIONS { indexProvider: 'range-1.0' }"
            ),
            index_cmd("CREATE RANGE INDEX r FOR (n:P) ON (n.a)")
        );
        assert_eq!(
            index_cmd("CREATE TEXT INDEX t FOR (n:P) ON (n.a) OPTIONS { indexConfig: {} }"),
            index_cmd("CREATE TEXT INDEX t FOR (n:P) ON (n.a)")
        );
        // A malformed / unknown-top-level-key OPTIONS clause is a clear syntax error.
        invalid("CREATE INDEX ix FOR (n:Person) ON (n.age) OPTIONS { bogus: 'x' }");
        invalid("CREATE INDEX ix FOR (n:Person) ON (n.age) OPTIONS { indexProvider: 7 }"); // not a string
        invalid("CREATE INDEX ix FOR (n:Person) ON (n.age) OPTIONS { indexConfig: 'x' }"); // not a map
        invalid("CREATE INDEX ix FOR (n:Person) ON (n.age) OPTIONS {"); // unterminated
    }

    /// `OPTIONS { indexConfig: { 'spatial.…': [ … ] } }` parses structurally on a POINT index; the
    /// spatial config is accepted and not applied, so the parsed command is unchanged (`rmp` #661).
    #[test]
    fn options_clause_parses_on_point_index() {
        assert_eq!(
            index_cmd(
                "CREATE POINT INDEX by_loc FOR (n:City) ON (n.loc) \
                 OPTIONS { indexConfig: { `spatial.cartesian.min`: [-100.0, -100.0], \
                                          `spatial.cartesian.max`: [100.0, 100.0] } }"
            ),
            IndexCommand::CreatePointIndex {
                name: "by_loc".to_owned(),
                entity: SpatialEntity::Node,
                label: "City".to_owned(),
                property: "loc".to_owned(),
                if_not_exists: false,
            }
        );
        invalid("CREATE POINT INDEX p FOR (n:City) ON (n.loc) OPTIONS { analyzer: 'x' }"); // unknown key
    }

    /// FULLTEXT accepts both the bare `analyzer:` form and the Neo4j `indexConfig { … }` form
    /// (backtick-quoted keys), mapping `fulltext.analyzer` to the analyzer and accepting
    /// `fulltext.eventually_consistent` (`rmp` #661).
    #[test]
    fn options_clause_parses_on_fulltext_index_configform() {
        assert_eq!(
            index_cmd(
                "CREATE FULLTEXT INDEX ft FOR (n:Doc) ON EACH [n.body] \
                 OPTIONS { indexConfig: { `fulltext.analyzer`: 'keyword', \
                                          `fulltext.eventually_consistent`: true } }"
            ),
            IndexCommand::CreateFulltextIndex {
                name: "ft".to_owned(),
                entity: FulltextEntity::Node,
                labels_or_types: vec!["Doc".to_owned()],
                properties: vec!["body".to_owned()],
                analyzer: "keyword".to_owned(),
                if_not_exists: false,
            }
        );
        // `indexProvider` is accepted and ignored; the default analyzer stays `standard`.
        assert_eq!(
            index_cmd(
                "CREATE FULLTEXT INDEX ft FOR (n:Doc) ON EACH [n.body] \
                 OPTIONS { indexProvider: 'fulltext-1.0' }"
            ),
            IndexCommand::CreateFulltextIndex {
                name: "ft".to_owned(),
                entity: FulltextEntity::Node,
                labels_or_types: vec!["Doc".to_owned()],
                properties: vec!["body".to_owned()],
                analyzer: "standard".to_owned(),
                if_not_exists: false,
            }
        );
        // A bad analyzer value type inside indexConfig is a clear error.
        invalid(
            "CREATE FULLTEXT INDEX ft FOR (n:Doc) ON EACH [n.body] \
             OPTIONS { indexConfig: { `fulltext.analyzer`: 7 } }",
        );
    }

    /// `IF NOT EXISTS` on CREATE POINT/FULLTEXT and `IF EXISTS` on DROP POINT/FULLTEXT set the
    /// idempotency flags (`rmp` #661).
    #[test]
    fn if_not_exists_and_if_exists_on_point_and_fulltext() {
        assert_eq!(
            index_cmd("CREATE POINT INDEX p IF NOT EXISTS FOR (n:City) ON (n.loc)"),
            IndexCommand::CreatePointIndex {
                name: "p".to_owned(),
                entity: SpatialEntity::Node,
                label: "City".to_owned(),
                property: "loc".to_owned(),
                if_not_exists: true,
            }
        );
        assert_eq!(
            index_cmd("CREATE FULLTEXT INDEX ft IF NOT EXISTS FOR (n:Doc) ON EACH [n.body]"),
            IndexCommand::CreateFulltextIndex {
                name: "ft".to_owned(),
                entity: FulltextEntity::Node,
                labels_or_types: vec!["Doc".to_owned()],
                properties: vec!["body".to_owned()],
                analyzer: "standard".to_owned(),
                if_not_exists: true,
            }
        );
        assert_eq!(
            index_cmd("DROP POINT INDEX p IF EXISTS"),
            IndexCommand::DropPointIndex {
                name: "p".to_owned(),
                if_exists: true,
            }
        );
        assert_eq!(
            index_cmd("DROP FULLTEXT INDEX ft IF EXISTS"),
            IndexCommand::DropFulltextIndex {
                name: "ft".to_owned(),
                if_exists: true,
            }
        );
    }

    /// An anonymous POINT index gets a deterministic auto-name `point_index_<label>_<property>`
    /// (`rmp` #661), and the anonymous + `IF NOT EXISTS` combination parses.
    #[test]
    fn anonymous_point_index_auto_name() {
        assert_eq!(
            index_cmd("CREATE POINT INDEX FOR (n:City) ON (n.loc)"),
            IndexCommand::CreatePointIndex {
                name: "point_index_City_loc".to_owned(),
                entity: SpatialEntity::Node,
                label: "City".to_owned(),
                property: "loc".to_owned(),
                if_not_exists: false,
            }
        );
        assert_eq!(
            index_cmd("CREATE POINT INDEX IF NOT EXISTS FOR (n:City) ON (n.loc)"),
            IndexCommand::CreatePointIndex {
                name: "point_index_City_loc".to_owned(),
                entity: SpatialEntity::Node,
                label: "City".to_owned(),
                property: "loc".to_owned(),
                if_not_exists: true,
            }
        );
    }

    /// The singular `SHOW INDEX` / `SHOW <filter> INDEX` behaves identically to the plural
    /// `SHOW INDEXES` (Neo4j accepts `INDEX[ES]`) (`rmp` #661).
    #[test]
    fn singular_show_index_matches_plural() {
        assert_eq!(index_cmd("SHOW INDEX"), index_cmd("SHOW INDEXES"));
        assert_eq!(
            index_cmd("SHOW POINT INDEX"),
            index_cmd("SHOW POINT INDEXES")
        );
        assert_eq!(
            index_cmd("SHOW FULLTEXT INDEX"),
            index_cmd("SHOW FULLTEXT INDEXES")
        );
        assert_eq!(
            index_cmd("SHOW RANGE INDEX"),
            index_cmd("SHOW RANGE INDEXES")
        );
        assert_eq!(index_cmd("SHOW ALL INDEX"), index_cmd("SHOW ALL INDEXES"));
        // The singular is a full synonym, including the YIELD/WHERE tail.
        assert_eq!(
            index_cmd("SHOW INDEX YIELD name"),
            index_cmd("SHOW INDEXES YIELD name")
        );
    }

    #[test]
    fn create_constraint_unique_and_not_null() {
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c1 FOR (n:Person) REQUIRE n.email IS UNIQUE"),
            node_constraint("c1", "Person", &["email"], ConstraintCreateKind::Unique),
        );
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c2 FOR (n:Person) REQUIRE n.name IS NOT NULL"),
            node_constraint("c2", "Person", &["name"], ConstraintCreateKind::Existence),
        );
        // Case-insensitive keywords, the legacy `ASSERT` spelling, and a parenthesised property all
        // parse to the same command.
        assert_eq!(
            constraint_cmd("create constraint c3 for (x:Account) assert (x.iban) is unique"),
            node_constraint("c3", "Account", &["iban"], ConstraintCreateKind::Unique),
        );
        // The optional `NODE` qualifier (`IS NODE UNIQUE`, `rmp` #638) parses identically.
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c4 FOR (n:Person) REQUIRE n.email IS NODE UNIQUE"),
            node_constraint("c4", "Person", &["email"], ConstraintCreateKind::Unique),
        );
    }

    #[test]
    fn create_constraint_node_key() {
        // A composite node key over a parenthesised property tuple.
        assert_eq!(
            constraint_cmd(
                "CREATE CONSTRAINT pk FOR (n:Person) REQUIRE (n.first, n.last) IS NODE KEY"
            ),
            node_constraint(
                "pk",
                "Person",
                &["first", "last"],
                ConstraintCreateKind::Key
            ),
        );
        // A single-property node key is also valid (the degenerate composite); case-insensitive.
        assert_eq!(
            constraint_cmd("create constraint k for (a:Account) require (a.iban) is node key"),
            node_constraint("k", "Account", &["iban"], ConstraintCreateKind::Key),
        );
        // The bare `IS KEY` form (optional `NODE`, `rmp` #638) parses identically.
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT k2 FOR (n:Person) REQUIRE (n.a, n.b) IS KEY"),
            node_constraint("k2", "Person", &["a", "b"], ConstraintCreateKind::Key),
        );
    }

    #[test]
    fn create_constraint_property_type() {
        use graphus_storage::ConstraintTypeDescriptor as T;
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT t FOR (n:Person) REQUIRE n.age IS :: INTEGER"),
            node_constraint(
                "t",
                "Person",
                &["age"],
                ConstraintCreateKind::PropertyType {
                    declared_type: T::Integer,
                },
            ),
        );
        // Each scalar type, case-insensitive, a parenthesised property, and the `IS TYPED` spelling.
        for (src, expected) in [
            ("REQUIRE n.x IS :: FLOAT", T::Float),
            ("REQUIRE n.x IS :: STRING", T::String),
            ("require n.x is :: boolean", T::Boolean),
            ("REQUIRE (n.x) IS :: STRING", T::String),
            ("REQUIRE n.x IS TYPED INTEGER", T::Integer),
        ] {
            let q = format!("CREATE CONSTRAINT t FOR (n:Person) {src}");
            assert_eq!(
                constraint_cmd(&q),
                node_constraint(
                    "t",
                    "Person",
                    &["x"],
                    ConstraintCreateKind::PropertyType {
                        declared_type: expected,
                    },
                ),
                "{q}"
            );
        }
        // A LIST<…> type, including a nested list.
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT t FOR (n:Person) REQUIRE n.tags IS :: LIST<STRING>"),
            node_constraint(
                "t",
                "Person",
                &["tags"],
                ConstraintCreateKind::PropertyType {
                    declared_type: T::List(Box::new(T::String)),
                },
            ),
        );
        assert_eq!(
            constraint_cmd(
                "CREATE CONSTRAINT t FOR (n:Person) REQUIRE n.matrix IS :: LIST<LIST<INTEGER>>"
            ),
            node_constraint(
                "t",
                "Person",
                &["matrix"],
                ConstraintCreateKind::PropertyType {
                    declared_type: T::List(Box::new(T::List(Box::new(T::Integer)))),
                },
            ),
        );
    }

    #[test]
    fn create_constraint_if_not_exists_and_or_replace() {
        // `IF NOT EXISTS` after the name (`rmp` #638).
        assert_eq!(
            constraint_cmd(
                "CREATE CONSTRAINT c IF NOT EXISTS FOR (n:Person) REQUIRE n.email IS UNIQUE"
            ),
            ConstraintCommand::Create(CreateConstraint {
                name: "c".to_owned(),
                entity: ConstraintEntity::Node {
                    label: "Person".to_owned(),
                },
                properties: vec!["email".to_owned()],
                kind: ConstraintCreateKind::Unique,
                if_not_exists: true,
                or_replace: false,
            }),
        );
        // `CREATE OR REPLACE CONSTRAINT` (a Graphus superset).
        assert_eq!(
            constraint_cmd(
                "CREATE OR REPLACE CONSTRAINT c FOR (n:Person) REQUIRE n.email IS UNIQUE"
            ),
            ConstraintCommand::Create(CreateConstraint {
                name: "c".to_owned(),
                entity: ConstraintEntity::Node {
                    label: "Person".to_owned(),
                },
                properties: vec!["email".to_owned()],
                kind: ConstraintCreateKind::Unique,
                if_not_exists: false,
                or_replace: true,
            }),
        );
        // Combining the two is rejected; OR REPLACE on a non-constraint surface is rejected.
        invalid(
            "CREATE OR REPLACE CONSTRAINT c IF NOT EXISTS FOR (n:Person) REQUIRE n.x IS UNIQUE",
        );
        invalid("CREATE OR REPLACE INDEX ix FOR (n:Person) ON (n.email)");
        invalid("CREATE OR WEIRD CONSTRAINT c FOR (n:Person) REQUIRE n.x IS UNIQUE");
    }

    #[test]
    fn relationship_constraint_patterns_parse() {
        // Relationship existence (`rmp` #638): FOR ()-[r:TYPE]-() REQUIRE r.p IS NOT NULL.
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c FOR ()-[r:KNOWS]-() REQUIRE r.since IS NOT NULL"),
            ConstraintCommand::Create(CreateConstraint {
                name: "c".to_owned(),
                entity: ConstraintEntity::Relationship {
                    rel_type: "KNOWS".to_owned(),
                },
                properties: vec!["since".to_owned()],
                kind: ConstraintCreateKind::Existence,
                if_not_exists: false,
                or_replace: false,
            }),
        );
        // RELATIONSHIP KEY over a composite tuple (both `REL KEY` and `RELATIONSHIP KEY` qualifiers).
        assert_eq!(
            constraint_cmd(
                "CREATE CONSTRAINT rk FOR ()-[r:RATED]-() REQUIRE (r.user, r.movie) IS RELATIONSHIP KEY"
            ),
            ConstraintCommand::Create(CreateConstraint {
                name: "rk".to_owned(),
                entity: ConstraintEntity::Relationship {
                    rel_type: "RATED".to_owned(),
                },
                properties: vec!["user".to_owned(), "movie".to_owned()],
                kind: ConstraintCreateKind::Key,
                if_not_exists: false,
                or_replace: false,
            }),
        );
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT rk2 FOR ()-[r:R]-() REQUIRE r.k IS REL KEY"),
            ConstraintCommand::Create(CreateConstraint {
                name: "rk2".to_owned(),
                entity: ConstraintEntity::Relationship {
                    rel_type: "R".to_owned(),
                },
                properties: vec!["k".to_owned()],
                kind: ConstraintCreateKind::Key,
                if_not_exists: false,
                or_replace: false,
            }),
        );
        // A NODE/RELATIONSHIP qualifier mismatched with the pattern is a clear error, in both directions.
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE n.email IS RELATIONSHIP UNIQUE");
        invalid("CREATE CONSTRAINT c FOR ()-[r:KNOWS]-() REQUIRE r.since IS NODE UNIQUE");
        // A directed relationship pattern is rejected (constraints are undirected).
        invalid("CREATE CONSTRAINT c FOR ()-[r:KNOWS]->() REQUIRE r.since IS NOT NULL");
    }

    #[test]
    fn malformed_node_key_and_property_type_are_syntax_errors() {
        // A composite tuple is valid for KEY and UNIQUE (`rmp` #651), but not for existence/type.
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE (n.a, n.b) IS NOT NULL");
        // NODE without KEY.
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE (n.a) IS NODE");
        // An unterminated tuple.
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE (n.a, IS NODE KEY");
        // Property-type with an unknown / missing type.
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE n.x IS :: WEIRD");
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE n.x IS ::");
        // A LIST without an element type or an unbalanced angle bracket.
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE n.x IS :: LIST");
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE n.x IS :: LIST<STRING");
        // A property-type clause must cover exactly one property.
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE (n.a, n.b) IS :: INTEGER");
    }

    #[test]
    fn property_type_constraint_full_type_set_parses() {
        use graphus_storage::ConstraintTypeDescriptor as T;
        let pt = |t: T| ConstraintCreateKind::PropertyType { declared_type: t };
        // Scalars, including the temporal + spatial types (`rmp` #652).
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: DATE"),
            node_constraint("c", "E", &["p"], pt(T::Date))
        );
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: LOCAL DATETIME"),
            node_constraint("c", "E", &["p"], pt(T::LocalDateTime))
        );
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: ZONED TIME"),
            node_constraint("c", "E", &["p"], pt(T::ZonedTime))
        );
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: POINT"),
            node_constraint("c", "E", &["p"], pt(T::Point))
        );
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: DURATION"),
            node_constraint("c", "E", &["p"], pt(T::Duration))
        );
        // `LIST<X NOT NULL>` and the lenient `LIST<X>` both fold to the same element type.
        assert_eq!(
            constraint_cmd(
                "CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: LIST<INTEGER NOT NULL>"
            ),
            node_constraint("c", "E", &["p"], pt(T::List(Box::new(T::Integer))))
        );
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: LIST<POINT>"),
            node_constraint("c", "E", &["p"], pt(T::List(Box::new(T::Point))))
        );
        // Closed unions (`INTEGER | STRING`), including the `IS TYPED` synonym and a list member.
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: INTEGER | STRING"),
            node_constraint("c", "E", &["p"], pt(T::Union(vec![T::Integer, T::String])))
        );
        assert_eq!(
            constraint_cmd(
                "CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS TYPED STRING | LIST<STRING NOT NULL>"
            ),
            node_constraint(
                "c",
                "E",
                &["p"],
                pt(T::Union(vec![T::String, T::List(Box::new(T::String))]))
            )
        );
        // Synonyms: SIGNED INTEGER, BOOL, VARCHAR, INT.
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: SIGNED INTEGER"),
            node_constraint("c", "E", &["p"], pt(T::Integer))
        );
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: VARCHAR"),
            node_constraint("c", "E", &["p"], pt(T::String))
        );
        // A relationship property-type constraint accepts the same set.
        assert!(matches!(
            constraint_cmd("CREATE CONSTRAINT c FOR ()-[r:R]-() REQUIRE r.p IS :: ZONED DATETIME"),
            ConstraintCommand::Create(_)
        ));
        // The non-property (structural / wildcard) types are clear errors.
        invalid("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: NODE");
        invalid("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: RELATIONSHIP");
        invalid("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: PATH");
        invalid("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: MAP");
        invalid("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: ANY");
        invalid("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: NULL");
        invalid("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: NOTHING");
        invalid("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: LOCAL WEIRD");
        // VECTOR property-type constraints are deferred (`rmp` #647).
        invalid("CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: VECTOR<FLOAT>(3)");
    }

    #[test]
    fn property_type_constraint_rejects_undecodable_depth_and_union_width() {
        use graphus_storage::ConstraintTypeDescriptor as T;
        // `rmp` #652 write-path guard: a descriptor the durable decoder would reject on reopen must be
        // rejected at parse time, so a committed CREATE CONSTRAINT can never leave the store unopenable.

        // A LIST nested exactly MAX_TYPE_DEPTH deep is the boundary and is accepted...
        let ok = format!(
            "CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: {}INTEGER{}",
            "LIST<".repeat(T::MAX_TYPE_DEPTH),
            ">".repeat(T::MAX_TYPE_DEPTH),
        );
        assert!(
            matches!(constraint_cmd(&ok), ConstraintCommand::Create(_)),
            "a LIST nested MAX_TYPE_DEPTH deep must parse"
        );
        // ...one level deeper is rejected (would fail to decode on reopen / overflow the parser).
        let too_deep = format!(
            "CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: {}INTEGER{}",
            "LIST<".repeat(T::MAX_TYPE_DEPTH + 1),
            ">".repeat(T::MAX_TYPE_DEPTH + 1),
        );
        invalid(&too_deep);
        // A pathological deep nesting must not overflow the parser stack — it is a clean error.
        let pathological = format!(
            "CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: {}INTEGER{}",
            "LIST<".repeat(5000),
            ">".repeat(5000),
        );
        invalid(&pathological);
        // A union adds a nesting level: a union of a MAX_TYPE_DEPTH-deep LIST exceeds the bound.
        let union_over_depth = format!(
            "CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: INTEGER | {}INTEGER{}",
            "LIST<".repeat(T::MAX_TYPE_DEPTH),
            ">".repeat(T::MAX_TYPE_DEPTH),
        );
        invalid(&union_over_depth);
        // A union wider than MAX_UNION_MEMBERS is rejected (the durable count is a single byte).
        let wide_union = format!(
            "CREATE CONSTRAINT c FOR (n:E) REQUIRE n.p IS :: {}",
            vec!["INTEGER"; T::MAX_UNION_MEMBERS + 1].join(" | "),
        );
        invalid(&wide_union);
    }

    #[test]
    fn composite_uniqueness_constraint_parses() {
        // `rmp` #651: a composite tuple `IS UNIQUE` is valid for both nodes and relationships.
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c FOR (n:Person) REQUIRE (n.a, n.b) IS UNIQUE"),
            node_constraint("c", "Person", &["a", "b"], ConstraintCreateKind::Unique)
        );
        // The NODE qualifier is accepted on the composite form too.
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c FOR (n:Person) REQUIRE (n.a, n.b) IS NODE UNIQUE"),
            node_constraint("c", "Person", &["a", "b"], ConstraintCreateKind::Unique)
        );
        // Relationship composite uniqueness.
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT rc FOR ()-[r:PAID]-() REQUIRE (r.a, r.b) IS UNIQUE"),
            ConstraintCommand::Create(CreateConstraint {
                name: "rc".to_owned(),
                entity: ConstraintEntity::Relationship {
                    rel_type: "PAID".to_owned(),
                },
                properties: vec!["a".to_owned(), "b".to_owned()],
                kind: ConstraintCreateKind::Unique,
                if_not_exists: false,
                or_replace: false,
            })
        );
        // A single-property `IS UNIQUE` still parses (regression).
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c FOR (n:Person) REQUIRE n.email IS UNIQUE"),
            node_constraint("c", "Person", &["email"], ConstraintCreateKind::Unique)
        );
    }

    #[test]
    fn unnamed_constraint_gets_a_deterministic_auto_name() {
        // `rmp` #654: an omitted name is auto-generated deterministically from the schema.
        let name_of = |q: &str| match constraint_cmd(q) {
            ConstraintCommand::Create(c) => c,
            other => panic!("expected a create, got {other:?}"),
        };
        let c = name_of("CREATE CONSTRAINT FOR (n:Person) REQUIRE n.email IS UNIQUE");
        assert!(
            c.name.starts_with("constraint_"),
            "auto name should be Neo4j-style: {}",
            c.name
        );
        // Deterministic: the same schema yields the same name.
        let c2 = name_of("CREATE CONSTRAINT FOR (n:Person) REQUIRE n.email IS UNIQUE");
        assert_eq!(c.name, c2.name);
        // A different schema yields a different name.
        let c3 = name_of("CREATE CONSTRAINT FOR (n:Person) REQUIRE n.other IS UNIQUE");
        assert_ne!(c.name, c3.name);
        // Unnamed + IF NOT EXISTS derives the same name (so idempotency holds).
        let c4 =
            name_of("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Person) REQUIRE n.email IS UNIQUE");
        assert!(c4.if_not_exists);
        assert_eq!(c4.name, c.name);
        // A backtick-quoted `for` / `if` is still an explicit name, not the "unnamed" keyword.
        let c5 = name_of("CREATE CONSTRAINT `for` FOR (n:Person) REQUIRE n.email IS UNIQUE");
        assert_eq!(c5.name, "for");
    }

    #[test]
    fn constraint_options_clause_is_accepted() {
        // `rmp` #654: an OPTIONS { … } map (any well-formed content, nested maps included) is accepted
        // for Neo4j-DDL compatibility.
        assert!(matches!(
            constraint_cmd(
                "CREATE CONSTRAINT uq FOR (n:Person) REQUIRE n.email IS UNIQUE OPTIONS {}"
            ),
            ConstraintCommand::Create(_)
        ));
        assert!(matches!(
            constraint_cmd(
                "CREATE CONSTRAINT uq FOR (n:Person) REQUIRE n.email IS UNIQUE \
                 OPTIONS { indexProvider: 'range-1.0', indexConfig: { `k`: [0, 0] } }"
            ),
            ConstraintCommand::Create(_)
        ));
        // Unnamed + OPTIONS combine.
        assert!(matches!(
            constraint_cmd(
                "CREATE CONSTRAINT FOR (n:Person) REQUIRE n.email IS UNIQUE \
                 OPTIONS { indexProvider: 'range-1.0' }"
            ),
            ConstraintCommand::Create(_)
        ));
        // An unterminated OPTIONS map is a syntax error, not a silent accept.
        invalid("CREATE CONSTRAINT uq FOR (n:Person) REQUIRE n.email IS UNIQUE OPTIONS { a: 1");
    }

    #[test]
    fn drop_and_show_constraints() {
        assert_eq!(
            constraint_cmd("DROP CONSTRAINT c1"),
            ConstraintCommand::Drop {
                name: "c1".to_owned(),
                if_exists: false,
            }
        );
        // `DROP CONSTRAINT <name> IF EXISTS` (`rmp` #638).
        assert_eq!(
            constraint_cmd("DROP CONSTRAINT c1 IF EXISTS"),
            ConstraintCommand::Drop {
                name: "c1".to_owned(),
                if_exists: true,
            }
        );
        assert_eq!(
            constraint_cmd("SHOW CONSTRAINTS"),
            ConstraintCommand::Show {
                filter: ConstraintTypeFilter::All,
                tail: None,
            }
        );
    }

    /// Every `SHOW <filter> CONSTRAINT[S]` form parses to its [`ConstraintTypeFilter`] (`rmp` #653),
    /// case-insensitively, with the optional bracketed words optional and both `CONSTRAINT`/`CONSTRAINTS`
    /// accepted for the filtered forms.
    #[test]
    fn show_constraints_type_filters() {
        use ConstraintTypeFilter as F;
        let filter = |q: &str| match constraint_cmd(q) {
            ConstraintCommand::Show { filter, tail: None } => filter,
            other => panic!("expected an unfiltered SHOW for {q:?}, got {other:?}"),
        };
        assert_eq!(filter("SHOW ALL CONSTRAINTS"), F::All);
        assert_eq!(filter("SHOW CONSTRAINTS"), F::All);
        // Uniqueness (node / rel / both), with optional PROPERTY and REL/RELATIONSHIP synonyms.
        assert_eq!(filter("SHOW NODE UNIQUENESS CONSTRAINTS"), F::NodeUnique);
        assert_eq!(
            filter("SHOW NODE PROPERTY UNIQUENESS CONSTRAINTS"),
            F::NodeUnique
        );
        assert_eq!(filter("SHOW REL UNIQUE CONSTRAINTS"), F::RelUnique);
        assert_eq!(
            filter("SHOW RELATIONSHIP UNIQUENESS CONSTRAINTS"),
            F::RelUnique
        );
        assert_eq!(filter("SHOW UNIQUENESS CONSTRAINTS"), F::Unique);
        assert_eq!(filter("SHOW PROPERTY UNIQUENESS CONSTRAINT"), F::Unique);
        // Existence.
        assert_eq!(filter("SHOW NODE EXISTENCE CONSTRAINTS"), F::NodeExistence);
        assert_eq!(
            filter("SHOW REL PROPERTY EXIST CONSTRAINTS"),
            F::RelExistence
        );
        assert_eq!(filter("SHOW EXISTENCE CONSTRAINTS"), F::Existence);
        // Key (no PROPERTY).
        assert_eq!(filter("SHOW NODE KEY CONSTRAINTS"), F::NodeKey);
        assert_eq!(filter("SHOW RELATIONSHIP KEY CONSTRAINTS"), F::RelKey);
        assert_eq!(filter("SHOW KEY CONSTRAINTS"), F::Key);
        // Property type (PROPERTY required).
        assert_eq!(
            filter("SHOW NODE PROPERTY TYPE CONSTRAINTS"),
            F::NodePropertyType
        );
        assert_eq!(
            filter("SHOW REL PROPERTY TYPE CONSTRAINTS"),
            F::RelPropertyType
        );
        assert_eq!(filter("SHOW PROPERTY TYPE CONSTRAINTS"), F::PropertyType);
        // Case-insensitive.
        assert_eq!(filter("show node key constraints"), F::NodeKey);
    }

    /// The optional `YIELD`/`WHERE` tail of `SHOW CONSTRAINTS` is captured verbatim (`rmp` #653), for
    /// both the unfiltered and filtered forms; a bare listing captures no tail.
    #[test]
    fn show_constraints_captures_yield_and_where_tail() {
        let tail = |q: &str| match constraint_cmd(q) {
            ConstraintCommand::Show { tail, .. } => tail,
            other => panic!("expected a SHOW for {q:?}, got {other:?}"),
        };
        assert_eq!(tail("SHOW CONSTRAINTS"), None);
        assert_eq!(tail("SHOW CONSTRAINTS;"), None);
        assert_eq!(
            tail("SHOW CONSTRAINTS YIELD name, type"),
            Some("YIELD name, type".to_owned())
        );
        assert_eq!(
            tail("SHOW CONSTRAINTS WHERE entityType = 'NODE'"),
            Some("WHERE entityType = 'NODE'".to_owned())
        );
        // A trailing `;` is stripped from the captured tail.
        assert_eq!(
            tail("SHOW CONSTRAINTS YIELD name RETURN name;"),
            Some("YIELD name RETURN name".to_owned())
        );
        // The tail is captured for filtered forms too.
        assert_eq!(
            tail("SHOW NODE KEY CONSTRAINTS YIELD *"),
            Some("YIELD *".to_owned())
        );
    }

    /// Malformed `SHOW … CONSTRAINTS` filters / tails are syntax errors, not silent passes (`rmp` #653).
    #[test]
    fn show_constraints_malformed_filter_or_tail_is_a_syntax_error() {
        invalid("SHOW CONSTRAINT"); // singular unfiltered still rejected
        invalid("SHOW CONSTRAINTS extra"); // garbage tail
        invalid("SHOW NODE CONSTRAINTS"); // entity without a category
        invalid("SHOW PROPERTY CONSTRAINTS"); // PROPERTY without a category
        invalid("SHOW TYPE CONSTRAINTS"); // TYPE requires PROPERTY
        invalid("SHOW PROPERTY KEY CONSTRAINTS"); // KEY is not a property constraint
        invalid("SHOW NODE REL KEY CONSTRAINTS"); // two entity qualifiers
        invalid("SHOW ALL NODE CONSTRAINTS"); // ALL takes no further filter words
        invalid("SHOW NODE KEY CONSTRAINTS garbage"); // garbage after the filter
    }

    #[test]
    fn claimed_but_malformed_constraint_is_a_syntax_error() {
        invalid("CREATE CONSTRAINT"); // missing name
        invalid("CREATE CONSTRAINT c"); // missing FOR clause
        invalid("CREATE CONSTRAINT c FOR (n:Person)"); // missing REQUIRE
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE n.email"); // missing IS …
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE n.email IS"); // missing UNIQUE/NOT NULL
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE n.email IS NOT"); // partial NOT NULL
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE n.email IS WEIRD"); // unknown rule
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE email IS UNIQUE"); // ref must be var.prop
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE n.email IS UNIQUE extra");
        invalid("SHOW CONSTRAINT"); // singular not a form
        invalid("SHOW CONSTRAINTS extra");
        invalid("DROP CONSTRAINT"); // missing name
        invalid("DROP CONSTRAINT c trailing");
        invalid("CREATE CONSTRAINTS ..."); // plural only for SHOW
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

    // ---- security surface (rmp #92) -----------------------------------------------------------

    #[test]
    fn create_drop_user_forms() {
        assert_eq!(
            cmd("CREATE USER alice"),
            AdminCommand::CreateUser {
                name: "alice".to_owned(),
                password: None,
                if_not_exists: false,
            }
        );
        assert_eq!(
            cmd("CREATE USER alice SET PASSWORD 'hunter2'"),
            AdminCommand::CreateUser {
                name: "alice".to_owned(),
                password: Some("hunter2".to_owned()),
                if_not_exists: false,
            }
        );
        // Double-quoted password, IF NOT EXISTS, trailing `;`, case-insensitive keywords.
        assert_eq!(
            cmd("  create user `Alice-2`  set password \"p w\"  if not exists ; "),
            AdminCommand::CreateUser {
                name: "Alice-2".to_owned(),
                password: Some("p w".to_owned()),
                if_not_exists: true,
            }
        );
        // An escaped quote inside the password is taken literally.
        assert_eq!(
            cmd(r"CREATE USER bob SET PASSWORD 'a\'b'"),
            AdminCommand::CreateUser {
                name: "bob".to_owned(),
                password: Some("a'b".to_owned()),
                if_not_exists: false,
            }
        );
        assert_eq!(
            cmd("DROP USER alice"),
            AdminCommand::DropUser {
                name: "alice".to_owned(),
                if_exists: false,
            }
        );
        assert_eq!(
            cmd("drop user alice if exists"),
            AdminCommand::DropUser {
                name: "alice".to_owned(),
                if_exists: true,
            }
        );
    }

    #[test]
    fn create_drop_role_forms() {
        assert_eq!(
            cmd("CREATE ROLE reader"),
            AdminCommand::CreateRole {
                name: "reader".to_owned(),
                if_not_exists: false,
            }
        );
        assert_eq!(
            cmd("create role reader if not exists"),
            AdminCommand::CreateRole {
                name: "reader".to_owned(),
                if_not_exists: true,
            }
        );
        assert_eq!(
            cmd("DROP ROLE reader IF EXISTS"),
            AdminCommand::DropRole {
                name: "reader".to_owned(),
                if_exists: true,
            }
        );
    }

    #[test]
    fn grant_revoke_role_forms() {
        assert_eq!(
            cmd("GRANT ROLE reader TO alice"),
            AdminCommand::GrantRole {
                role: "reader".to_owned(),
                user: "alice".to_owned(),
            }
        );
        assert_eq!(
            cmd("revoke role reader from alice"),
            AdminCommand::RevokeRole {
                role: "reader".to_owned(),
                user: "alice".to_owned(),
            }
        );
    }

    #[test]
    fn grant_revoke_privilege_all_scopes() {
        assert_eq!(
            cmd("GRANT READ ON DATABASE TO reader"),
            AdminCommand::GrantPrivilege {
                action: PrivAction::Read,
                scope: PrivScope::Database,
                role: "reader".to_owned(),
            }
        );
        assert_eq!(
            cmd("GRANT WRITE ON GRAPH sales TO writer"),
            AdminCommand::GrantPrivilege {
                action: PrivAction::Write,
                scope: PrivScope::Graph {
                    db: "sales".to_owned()
                },
                role: "writer".to_owned(),
            }
        );
        assert_eq!(
            cmd("GRANT TRAVERSE ON LABEL sales.Person TO reader"),
            AdminCommand::GrantPrivilege {
                action: PrivAction::Traverse,
                scope: PrivScope::Label {
                    db: "sales".to_owned(),
                    label: "Person".to_owned()
                },
                role: "reader".to_owned(),
            }
        );
        assert_eq!(
            cmd("GRANT READ ON RELATIONSHIP sales.KNOWS TO reader"),
            AdminCommand::GrantPrivilege {
                action: PrivAction::Read,
                scope: PrivScope::RelType {
                    db: "sales".to_owned(),
                    rel_type: "KNOWS".to_owned()
                },
                role: "reader".to_owned(),
            }
        );
        assert_eq!(
            cmd("REVOKE READ ON PROPERTY sales.Person.ssn FROM reader"),
            AdminCommand::RevokePrivilege {
                action: PrivAction::Read,
                scope: PrivScope::Property {
                    db: "sales".to_owned(),
                    label: "Person".to_owned(),
                    property: "ssn".to_owned(),
                },
                role: "reader".to_owned(),
                mode: RevokeMode::Both,
            }
        );
        // Schema + Admin actions.
        assert_eq!(
            cmd("GRANT SCHEMA ON DATABASE TO dba"),
            AdminCommand::GrantPrivilege {
                action: PrivAction::Schema,
                scope: PrivScope::Database,
                role: "dba".to_owned(),
            }
        );
        assert_eq!(
            cmd("GRANT ADMIN ON DATABASE TO dba"),
            AdminCommand::GrantPrivilege {
                action: PrivAction::Admin,
                scope: PrivScope::Database,
                role: "dba".to_owned(),
            }
        );
    }

    #[test]
    fn deny_and_revoke_mode_forms() {
        // DENY <action> ON <scope> TO <role> (rmp #645).
        assert_eq!(
            cmd("DENY READ ON LABEL sales.Secret TO reader"),
            AdminCommand::DenyPrivilege {
                action: PrivAction::Read,
                scope: PrivScope::Label {
                    db: "sales".to_owned(),
                    label: "Secret".to_owned(),
                },
                role: "reader".to_owned(),
            }
        );
        // REVOKE GRANT / REVOKE DENY select the access sense; plain REVOKE removes both.
        assert_eq!(
            cmd("REVOKE GRANT WRITE ON GRAPH sales FROM writer"),
            AdminCommand::RevokePrivilege {
                action: PrivAction::Write,
                scope: PrivScope::Graph {
                    db: "sales".to_owned()
                },
                role: "writer".to_owned(),
                mode: RevokeMode::GrantOnly,
            }
        );
        assert_eq!(
            cmd("revoke deny read on label sales.Secret from reader"),
            AdminCommand::RevokePrivilege {
                action: PrivAction::Read,
                scope: PrivScope::Label {
                    db: "sales".to_owned(),
                    label: "Secret".to_owned(),
                },
                role: "reader".to_owned(),
                mode: RevokeMode::DenyOnly,
            }
        );
        // DENY ROLE is rejected (a role assignment is not a deniable privilege).
        let _ = invalid("DENY ROLE reader TO alice");
    }

    #[test]
    fn priv_action_and_scope_map_onto_the_auth_model() {
        // The grammar types lower exactly onto the auth crate's model.
        assert_eq!(PrivAction::Read.to_action(), graphus_auth::Action::Read);
        assert_eq!(PrivAction::Schema.to_action(), graphus_auth::Action::Schema);
        assert_eq!(
            PrivScope::Label {
                db: "db".to_owned(),
                label: "L".to_owned()
            }
            .to_resource(),
            graphus_auth::Resource::Label {
                db: "db".to_owned(),
                label: "L".to_owned()
            }
        );
    }

    #[test]
    fn show_users_roles_privileges() {
        assert_eq!(cmd("SHOW USERS"), AdminCommand::ShowUsers);
        assert_eq!(cmd("show users ;"), AdminCommand::ShowUsers);
        assert_eq!(cmd("SHOW ROLES"), AdminCommand::ShowRoles);
        assert_eq!(cmd("SHOW PRIVILEGES"), AdminCommand::ShowPrivileges);
    }

    #[test]
    fn security_grammar_never_swallows_cypher() {
        // A node labelled User/Role, queries merely mentioning the words, prefixed identifiers.
        not_admin("CREATE (n:User)");
        not_admin("CREATE (n:User {name: 'x'}) RETURN n");
        not_admin("MATCH (n:Role) RETURN n");
        not_admin("RETURN 'CREATE USER alice'");
        not_admin("CREATE USER_X"); // second token is not the keyword
        not_admin("CREATE ROLE_X");
        not_admin("showusers");
        // GRANT/REVOKE are claimed by the first token (never valid Cypher), so a bare/garbled one
        // is an Invalid admin syntax error, not passed through — verified below.
    }

    #[test]
    fn claimed_but_malformed_security_is_a_syntax_error() {
        invalid("CREATE USER"); // missing name
        invalid("CREATE USER alice SET"); // partial SET PASSWORD
        invalid("CREATE USER alice SET PASSWORD"); // missing the quoted password
        invalid("CREATE USER alice SET PASSWORD secret"); // password must be quoted
        invalid("CREATE USER alice IF EXISTS"); // CREATE takes IF NOT EXISTS
        invalid("DROP USER alice IF NOT EXISTS"); // DROP takes IF EXISTS
        invalid("DROP USER"); // missing name
        invalid("SHOW USER"); // singular is not a form
        invalid("SHOW ROLE");
        invalid("SHOW USERS extra");
        invalid("CREATE USERS alice"); // plural only valid for SHOW
        invalid("CREATE USER alice SET PASSWORD 'unterminated"); // unterminated string literal

        invalid("GRANT"); // missing everything
        invalid("GRANT ROLE reader"); // missing TO <user>
        invalid("GRANT ROLE reader FROM alice"); // GRANT uses TO, not FROM
        invalid("REVOKE ROLE reader TO alice"); // REVOKE uses FROM, not TO
        invalid("GRANT BOGUS ON DATABASE TO reader"); // unknown action
        invalid("GRANT READ DATABASE TO reader"); // missing ON
        invalid("GRANT READ ON BOGUS TO reader"); // unknown scope
        invalid("GRANT READ ON GRAPH TO reader"); // GRAPH needs a db
        invalid("GRANT READ ON LABEL sales TO reader"); // LABEL needs db.label
        invalid("GRANT READ ON PROPERTY sales.Person TO reader"); // PROPERTY needs db.label.prop
        invalid("GRANT READ ON LABEL sales.Person.extra TO reader"); // too many segments
        invalid("GRANT READ ON DATABASE reader"); // missing TO
        invalid("GRANT READ ON DATABASE TO reader extra"); // trailing
    }

    #[test]
    fn checkpoint_database_parses_over_the_wire() {
        // The `rmp` #305 over-the-wire maintenance trigger. `CHECKPOINT` is claimed on the first token
        // (never valid Cypher), case-insensitive, and carries the target database name.
        assert_eq!(
            cmd("CHECKPOINT DATABASE sales"),
            AdminCommand::CheckpointDatabase {
                name: "sales".to_owned()
            }
        );
        assert_eq!(
            cmd("  checkpoint   database   Telemetry  "),
            AdminCommand::CheckpointDatabase {
                name: "Telemetry".to_owned() // normalization is the catalog's job
            }
        );

        // It is audited as an admin change targeting the named database, with a secret-free detail.
        let c = AdminCommand::CheckpointDatabase {
            name: "sales".to_owned(),
        };
        assert!(crate::audit::is_mutating_admin(&c));
        assert_eq!(
            crate::audit::admin_target_database(&c),
            Some("sales".to_owned())
        );
        assert_eq!(
            crate::audit::redact_admin_detail(&c),
            "CHECKPOINT DATABASE sales"
        );

        // Grammar errors are rejected (claimed, then must parse exactly) — never passed to Cypher.
        invalid("CHECKPOINT sales"); // missing DATABASE
        invalid("CHECKPOINT DATABASE"); // missing name
        invalid("CHECKPOINT DATABASE sales extra"); // trailing tokens
    }
}
