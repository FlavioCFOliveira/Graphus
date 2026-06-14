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
//! CREATE INDEX FOR (<var>:<Label>) ON (<var>.<property>)   -- openCypher 9 form
//! CREATE INDEX ON :<Label>(<property>)                     -- legacy form
//! DROP   INDEX ON :<Label>(<property>)                     -- (and the FOR … ON … form)
//! DROP   INDEX FOR (<var>:<Label>) ON (<var>.<property>)
//! SHOW   INDEXES
//!
//! CREATE POINT INDEX <name> FOR (<var>:<Label>) ON (<var>.<prop>)
//! DROP   POINT INDEX <name>
//! SHOW   POINT INDEXES
//!
//! CREATE FULLTEXT INDEX <name> FOR (<var>:<Label>) ON EACH [<var>.<prop>, …]
//!                                                  [OPTIONS { analyzer: '<analyzer>' }]   -- rmp #72
//! DROP   FULLTEXT INDEX <name>
//! SHOW   FULLTEXT INDEXES
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

use graphus_auth::{AuthError, Privilege};
use graphus_core::{GraphusError, Value};
use tokio::runtime::Handle;

use crate::audit::{
    AuditClass, AuditEvent, AuditLog, AuditOutcome, AuditSource, admin_target_database,
    classify_admin, is_mutating_admin, redact_admin_detail,
};
use crate::dbcatalog::{CatalogError, DatabaseCatalog, DbState, normalize_db_name};
use crate::engine::{ConstraintCommand, EngineHandle, IndexCommand};
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
    /// `REVOKE <action> ON <scope> FROM <role>`.
    RevokePrivilege {
        /// The parsed action.
        action: PrivAction,
        /// The parsed scope.
        scope: PrivScope,
        /// The role to revoke from.
        role: String,
    },
    /// `SHOW USERS`.
    ShowUsers,
    /// `SHOW ROLES`.
    ShowRoles,
    /// `SHOW PRIVILEGES`.
    ShowPrivileges,

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

/// A grantable action in the `GRANT`/`REVOKE` grammar (mirrors [`graphus_auth::Action`] but kept
/// separate so the grammar is decoupled from the auth crate's `#[non_exhaustive]` enum).
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

    // GRANT / REVOKE are never valid Cypher statement starts, so they are CLAIMED on the first token
    // alone (the security surface, rmp #92). Their remainder must then parse exactly.
    if verb == "GRANT" || verb == "REVOKE" {
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

    if !matches!(verb.as_str(), "CREATE" | "DROP" | "START" | "STOP" | "SHOW") {
        return AdminParse::NotAdmin;
    }

    // Token 2: the surface keyword — DATABASE(S) (database surface), INDEX(ES) (index surface), or
    // USER(S)/ROLE(S)/PRIVILEGES (security surface). (Reading it cannot legitimately fail for real
    // Cypher here — a backtick directly after these verbs is not valid Cypher either — but an
    // unterminated quote is still just "not ours" at this point.)
    let second = match lex.next_tok() {
        Ok(Some(t)) => t,
        _ => return AdminParse::NotAdmin,
    };

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
        return match parse_claimed_constraint(&verb, plural, &mut lex) {
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
        // CLAIMED by the index surface: parse strictly.
        return match parse_claimed_index(&verb, plural, &mut lex) {
            Ok(cmd) => AdminParse::Index(cmd),
            Err(msg) => AdminParse::Invalid(msg),
        };
    }

    AdminParse::NotAdmin
}

/// Parses the remainder of a claimed **index** statement (`verb` + `INDEX`/`INDEXES` already read),
/// for the two `CREATE`/`DROP` shapes and `SHOW INDEXES` (`rmp` task #91):
///
/// ```text
/// CREATE INDEX FOR (n:Label) ON (n.property)   -- openCypher 9
/// CREATE INDEX ON :Label(property)             -- legacy
/// DROP   INDEX FOR (n:Label) ON (n.property)
/// DROP   INDEX ON :Label(property)
/// SHOW   INDEXES
/// ```
///
/// A label/property name is a bare word or a `` `backtick-quoted` `` name (so a name colliding with a
/// keyword still works); a variable is any bare word (its actual text is irrelevant — both shapes are
/// single-variable). `CREATE/DROP INDEX` without a name (openCypher's named-index `DROP INDEX name`)
/// is **not** supported here: Graphus identifies a node-property index by `(label, property)`, not by
/// a server-assigned name, so the label/property shapes are the canonical surface.
fn parse_claimed_index(
    verb: &str,
    plural: bool,
    lex: &mut Lexer<'_>,
) -> Result<IndexCommand, String> {
    if plural {
        // SHOW INDEXES — nothing else allowed.
        expect_end(lex, "SHOW INDEXES")?;
        return Ok(IndexCommand::ShowIndexes);
    }
    if verb == "SHOW" {
        // `SHOW INDEX` (singular) is not a recognised form; only the plural `SHOW INDEXES`.
        return Err("expected SHOW INDEXES (the singular SHOW INDEX is not supported)".to_owned());
    }

    // CREATE / DROP INDEX: parse the `(label, property)` from either the `FOR … ON …` or the
    // `ON :Label(property)` shape.
    let (label, property) = parse_index_target(verb, lex)?;
    match verb {
        "CREATE" => Ok(IndexCommand::CreateNodePropertyIndex { label, property }),
        "DROP" => Ok(IndexCommand::DropNodePropertyIndex { label, property }),
        // `parse_admin_statement` only routes CREATE/DROP/SHOW here; START/STOP never reach this.
        other => Err(format!("unsupported index verb {other}")),
    }
}

/// Parses an index target `(label, property)` from either supported shape after `verb INDEX`:
///
/// - **openCypher 9:** `FOR (<var>:<Label>) ON (<var>.<property>)`
/// - **legacy:** `ON :<Label>(<property>)`
///
/// The leading keyword (`FOR` vs `ON`) disambiguates; anything else is a syntax error naming both
/// accepted shapes.
fn parse_index_target(verb: &str, lex: &mut Lexer<'_>) -> Result<(String, String), String> {
    match lex.next_tok()? {
        Some(t) if is_keyword(&t, "FOR") => parse_index_for_on(verb, lex),
        Some(t) if is_keyword(&t, "ON") => parse_index_legacy_on(verb, lex),
        Some(other) => Err(unexpected(
            &other,
            &format!("FOR (n:Label) ON (n.property) or ON :Label(property) after {verb} INDEX"),
        )),
        None => Err(format!(
            "expected FOR (n:Label) ON (n.property) or ON :Label(property) after {verb} INDEX"
        )),
    }
}

/// Parses the openCypher-9 `FOR (<var>:<Label>) ON (<var>.<property>)` tail (the `FOR` already
/// consumed).
///
/// # Tokenization note
///
/// The lexer treats `.` and `-` as word characters (so a hyphenated/dotted name is one token), so
/// `n.property` lexes as a **single** [`Tok::Word`] (`"n.property"`), not `n` `.` `property`. We
/// therefore read that one word and split it on the first `.` into `(variable, property)`. The
/// `(n:Label)` part, by contrast, splits naturally because `:` is a symbol.
fn parse_index_for_on(verb: &str, lex: &mut Lexer<'_>) -> Result<(String, String), String> {
    // FOR ( <var> : <Label> )
    expect_symbol(lex, '(', verb)?;
    let _var = expect_word(lex, "a variable", verb)?;
    expect_symbol(lex, ':', verb)?;
    let label = expect_name(lex, "a label", verb)?;
    expect_symbol(lex, ')', verb)?;
    // ON ( <var>.<property> )
    expect_keyword(lex, "ON", verb)?;
    expect_symbol(lex, '(', verb)?;
    let property = parse_property_ref(verb, lex)?;
    expect_symbol(lex, ')', verb)?;
    expect_end(lex, &format!("{verb} INDEX"))?;
    Ok((label, property))
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

    if plural {
        // SHOW FULLTEXT INDEXES — nothing else allowed.
        if verb != "SHOW" {
            return Err(format!(
                "expected INDEX after {verb} FULLTEXT (INDEXES is only valid in SHOW FULLTEXT INDEXES)"
            ));
        }
        expect_end(lex, "SHOW FULLTEXT INDEXES")?;
        return Ok(IndexCommand::ShowFulltextIndexes);
    }
    if verb == "SHOW" {
        return Err(
            "expected SHOW FULLTEXT INDEXES (the singular SHOW FULLTEXT INDEX is not supported)"
                .to_owned(),
        );
    }

    // Both CREATE and DROP take a name next.
    let name = expect_name(lex, "a full-text index name", "FULLTEXT")?;

    match verb {
        "DROP" => {
            expect_end(lex, "DROP FULLTEXT INDEX")?;
            Ok(IndexCommand::DropFulltextIndex { name })
        }
        "CREATE" => {
            let (label, properties, analyzer) = parse_fulltext_create_tail(lex)?;
            Ok(IndexCommand::CreateFulltextIndex {
                name,
                label,
                properties,
                analyzer,
            })
        }
        // `parse_admin_statement` only routes CREATE/DROP/SHOW here; START/STOP never reach this.
        other => Err(format!("unsupported full-text index verb {other}")),
    }
}

/// Parses the `FOR (<var>:<Label>) ON EACH [<var>.<prop>, …] [OPTIONS { analyzer: '<name>' }]` tail
/// of a `CREATE FULLTEXT INDEX <name>` statement (`rmp` task #72). Returns
/// `(label, properties, analyzer_name)`; the analyzer defaults to `"standard"` when no `OPTIONS`
/// clause is present.
fn parse_fulltext_create_tail(
    lex: &mut Lexer<'_>,
) -> Result<(String, Vec<String>, String), String> {
    const VERB: &str = "FULLTEXT";
    // FOR ( <var> : <Label> )
    expect_keyword(lex, "FOR", VERB)?;
    expect_symbol(lex, '(', VERB)?;
    let _var = expect_word(lex, "a variable", VERB)?;
    expect_symbol(lex, ':', VERB)?;
    let label = expect_name(lex, "a label", VERB)?;
    expect_symbol(lex, ')', VERB)?;
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
    Ok((label, properties, analyzer))
}

/// Parses an optional `OPTIONS { analyzer: '<name>' }` clause (only consumed when the next token is
/// `OPTIONS`). Returns the analyzer name if the clause was present. Any other recognised option key
/// is rejected (only `analyzer` is supported in v1); a malformed clause is a syntax error.
fn parse_optional_fulltext_options(lex: &mut Lexer<'_>) -> Result<Option<String>, String> {
    // Peek: only consume if the next token is OPTIONS.
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    match peek.next_tok()? {
        Some(t) if is_keyword(&t, "OPTIONS") => {
            lex.rest = peek.rest.clone();
        }
        _ => return Ok(None),
    }
    expect_symbol(lex, '{', "FULLTEXT")?;
    // key : 'value'  (only `analyzer` is supported).
    let key = expect_name(lex, "an option key (analyzer)", "FULLTEXT")?;
    if !key.eq_ignore_ascii_case("analyzer") {
        return Err(format!(
            "unsupported full-text index option {key:?}; only 'analyzer' is supported"
        ));
    }
    expect_symbol(lex, ':', "FULLTEXT")?;
    let analyzer = match lex.next_tok()? {
        Some(Tok::Str(s)) => s,
        Some(other) => {
            return Err(unexpected_generic(
                &other,
                "a quoted analyzer name after OPTIONS { analyzer:",
            ));
        }
        None => return Err("expected a quoted analyzer name after OPTIONS { analyzer:".to_owned()),
    };
    expect_symbol(lex, '}', "FULLTEXT")?;
    Ok(Some(analyzer))
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

    if plural {
        // SHOW POINT INDEXES — nothing else allowed.
        if verb != "SHOW" {
            return Err(format!(
                "expected INDEX after {verb} POINT (INDEXES is only valid in SHOW POINT INDEXES)"
            ));
        }
        expect_end(lex, "SHOW POINT INDEXES")?;
        return Ok(IndexCommand::ShowPointIndexes);
    }
    if verb == "SHOW" {
        return Err(
            "expected SHOW POINT INDEXES (the singular SHOW POINT INDEX is not supported)"
                .to_owned(),
        );
    }

    // Both CREATE and DROP take a name next.
    let name = expect_name(lex, "a point index name", "POINT")?;

    match verb {
        "DROP" => {
            expect_end(lex, "DROP POINT INDEX")?;
            Ok(IndexCommand::DropPointIndex { name })
        }
        "CREATE" => {
            let (label, property) = parse_point_create_tail(lex)?;
            Ok(IndexCommand::CreatePointIndex {
                name,
                label,
                property,
            })
        }
        // `parse_admin_statement` only routes CREATE/DROP/SHOW here; START/STOP never reach this.
        other => Err(format!("unsupported point index verb {other}")),
    }
}

/// Parses the `FOR (<var>:<Label>) ON (<var>.<property>)` tail of a `CREATE POINT INDEX <name>`
/// statement (`rmp` task #98). Returns `(label, property)`. Mirrors the openCypher-9 node-property
/// `FOR … ON …` shape (a single property), reusing [`parse_property_ref`] for the property reference.
fn parse_point_create_tail(lex: &mut Lexer<'_>) -> Result<(String, String), String> {
    const VERB: &str = "POINT";
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
    expect_end(lex, "CREATE POINT INDEX")?;
    Ok((label, property))
}

/// Parses the remainder of a claimed **constraint** statement (`verb` + `CONSTRAINT`/`CONSTRAINTS`
/// already read), for the six shapes (`rmp` tasks #99, #100):
///
/// ```text
/// CREATE CONSTRAINT <name> FOR (<var>:<Label>) REQUIRE <var>.<prop> IS UNIQUE
/// CREATE CONSTRAINT <name> FOR (<var>:<Label>) REQUIRE <var>.<prop> IS NOT NULL
/// CREATE CONSTRAINT <name> FOR (<var>:<Label>) REQUIRE (<var>.a, <var>.b, …) IS NODE KEY
/// CREATE CONSTRAINT <name> FOR (<var>:<Label>) REQUIRE <var>.<prop> IS :: <TYPE>
/// DROP   CONSTRAINT <name>
/// SHOW   CONSTRAINTS
/// ```
///
/// A constraint is identified by **name** (Neo4j-compatible), like a full-text / point index. The
/// `REQUIRE … IS …` tail distinguishes the kind; the `<var>` text is irrelevant (single-variable
/// shape, reusing [`parse_property_ref`]). `<TYPE>` is an openCypher type name — `INTEGER`, `FLOAT`,
/// `STRING`, `BOOLEAN`, or `LIST<…>` — parsed by [`parse_constraint_type`].
fn parse_claimed_constraint(
    verb: &str,
    plural: bool,
    lex: &mut Lexer<'_>,
) -> Result<ConstraintCommand, String> {
    if plural {
        // SHOW CONSTRAINTS — nothing else allowed.
        expect_end(lex, "SHOW CONSTRAINTS")?;
        return Ok(ConstraintCommand::Show);
    }
    if verb == "SHOW" {
        // `SHOW CONSTRAINT` (singular) is not a recognised form; only the plural `SHOW CONSTRAINTS`.
        return Err(
            "expected SHOW CONSTRAINTS (the singular SHOW CONSTRAINT is not supported)".to_owned(),
        );
    }

    // Both CREATE and DROP take a name next.
    let name = expect_name(lex, "a constraint name", "CONSTRAINT")?;

    match verb {
        "DROP" => {
            expect_end(lex, "DROP CONSTRAINT")?;
            Ok(ConstraintCommand::Drop { name })
        }
        "CREATE" => {
            let (label, tail) = parse_constraint_create_tail(lex)?;
            Ok(match tail {
                ConstraintTail::Unique { property } => ConstraintCommand::CreateUnique {
                    name,
                    label,
                    property,
                },
                ConstraintTail::Existence { property } => ConstraintCommand::CreateExistence {
                    name,
                    label,
                    property,
                },
                ConstraintTail::NodeKey { properties } => ConstraintCommand::CreateNodeKey {
                    name,
                    label,
                    properties,
                },
                ConstraintTail::PropertyType {
                    property,
                    declared_type,
                } => ConstraintCommand::CreatePropertyType {
                    name,
                    label,
                    property,
                    declared_type,
                },
            })
        }
        // `parse_admin_statement` only routes CREATE/DROP/SHOW here; START/STOP never reach this.
        other => Err(format!("unsupported constraint verb {other}")),
    }
}

/// The parsed `REQUIRE … IS …` body of a `CREATE CONSTRAINT` statement (`rmp` tasks #99, #100), one per
/// constraint kind. The label is returned separately by [`parse_constraint_create_tail`].
enum ConstraintTail {
    /// `IS UNIQUE` over a single property.
    Unique { property: String },
    /// `IS NOT NULL` over a single property.
    Existence { property: String },
    /// `IS NODE KEY` over a composite property tuple (one or more, in declared order).
    NodeKey { properties: Vec<String> },
    /// `IS :: <TYPE>` over a single property, with the declared value type.
    PropertyType {
        property: String,
        declared_type: graphus_storage::ConstraintTypeDescriptor,
    },
}

/// Parses the `FOR (<var>:<Label>) REQUIRE … IS …` tail of a `CREATE CONSTRAINT <name>` statement
/// (`rmp` tasks #99, #100). Returns `(label, tail)`. Mirrors the openCypher `FOR (n:Label) … (n.prop)`
/// node-property shape, reusing [`parse_property_ref`].
///
/// The `REQUIRE` target is a single bare/parenthesised property (`UNIQUE` / `NOT NULL` / `:: TYPE`) or
/// a parenthesised composite tuple `(n.a, n.b, …)` (only valid with `NODE KEY`). The closing keyword
/// after `IS` selects the kind. A multi-property tuple with any kind other than `NODE KEY` is rejected.
fn parse_constraint_create_tail(lex: &mut Lexer<'_>) -> Result<(String, ConstraintTail), String> {
    const VERB: &str = "CONSTRAINT";
    // FOR ( <var> : <Label> )
    expect_keyword(lex, "FOR", VERB)?;
    expect_symbol(lex, '(', VERB)?;
    let _var = expect_word(lex, "a variable", VERB)?;
    expect_symbol(lex, ':', VERB)?;
    let label = expect_name(lex, "a label", VERB)?;
    expect_symbol(lex, ')', VERB)?;
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
    // IS (UNIQUE | NOT NULL | NODE KEY | :: <TYPE>)
    expect_keyword(lex, "IS", VERB)?;

    // `::` opens a property-type clause (`IS :: <TYPE>`); it is two adjacent `:` symbols.
    if peek_symbol(lex, ':')? {
        expect_symbol(lex, ':', VERB)?;
        expect_symbol(lex, ':', VERB)?;
        let declared_type = parse_constraint_type(lex)?;
        expect_end(lex, "CREATE CONSTRAINT")?;
        let [property] = properties.as_slice() else {
            return Err(
                "a property-type constraint (IS :: <TYPE>) covers exactly one property".to_owned(),
            );
        };
        return Ok((
            label,
            ConstraintTail::PropertyType {
                property: property.clone(),
                declared_type,
            },
        ));
    }

    let next = lex
        .next_tok()?
        .ok_or_else(|| "expected UNIQUE, NOT NULL, NODE KEY or :: <TYPE> after IS".to_owned())?;
    let tail = if is_keyword(&next, "UNIQUE") {
        let [property] = properties.as_slice() else {
            return Err(
                "a uniqueness constraint (IS UNIQUE) covers exactly one property".to_owned(),
            );
        };
        ConstraintTail::Unique {
            property: property.clone(),
        }
    } else if is_keyword(&next, "NOT") {
        // NOT NULL
        let null = lex
            .next_tok()?
            .ok_or_else(|| "expected NULL after NOT in CONSTRAINT".to_owned())?;
        if !is_keyword(&null, "NULL") {
            return Err(unexpected_generic(&null, "NULL after NOT in CONSTRAINT"));
        }
        let [property] = properties.as_slice() else {
            return Err(
                "an existence constraint (IS NOT NULL) covers exactly one property".to_owned(),
            );
        };
        ConstraintTail::Existence {
            property: property.clone(),
        }
    } else if is_keyword(&next, "NODE") {
        // NODE KEY
        let key = lex
            .next_tok()?
            .ok_or_else(|| "expected KEY after NODE in CONSTRAINT".to_owned())?;
        if !is_keyword(&key, "KEY") {
            return Err(unexpected_generic(&key, "KEY after NODE in CONSTRAINT"));
        }
        ConstraintTail::NodeKey {
            properties: properties.clone(),
        }
    } else {
        return Err(unexpected_generic(
            &next,
            "UNIQUE, NOT NULL, NODE KEY or :: <TYPE> after IS in CONSTRAINT",
        ));
    };
    expect_end(lex, "CREATE CONSTRAINT")?;
    Ok((label, tail))
}

/// Parses an openCypher constraint **type name** for a `IS :: <TYPE>` clause (`rmp` task #100):
/// `INTEGER`, `FLOAT`, `STRING`, `BOOLEAN`, or `LIST<<TYPE>>` (recursively). The `LIST<…>` angle
/// brackets are the single `<` / `>` symbols of the lexer. A bare `LIST` (no element type) is rejected
/// — the openCypher surface for a property-type constraint always names the element type.
fn parse_constraint_type(
    lex: &mut Lexer<'_>,
) -> Result<graphus_storage::ConstraintTypeDescriptor, String> {
    use graphus_storage::ConstraintTypeDescriptor as T;
    const VERB: &str = "CONSTRAINT";
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
        "FLOAT" => Ok(T::Float),
        "STRING" => Ok(T::String),
        "BOOLEAN" | "BOOL" => Ok(T::Boolean),
        "LIST" => {
            // LIST < <element type> >
            expect_symbol(lex, '<', VERB)?;
            let inner = parse_constraint_type(lex)?;
            expect_symbol(lex, '>', VERB)?;
            Ok(T::List(Box::new(inner)))
        }
        other => Err(format!(
            "unsupported constraint type `{other}` (expected INTEGER, FLOAT, STRING, BOOLEAN or LIST<…>)"
        )),
    }
}

/// Peeks whether the next token is the single symbol `sym`, without consuming it.
fn peek_symbol(lex: &mut Lexer<'_>, sym: char) -> Result<bool, String> {
    let mut peek = Lexer {
        rest: lex.rest.clone(),
    };
    Ok(matches!(peek.next_tok()?, Some(Tok::Symbol(c)) if c == sym))
}

/// Parses the legacy `ON :<Label>(<property>)` tail (the `ON` already consumed).
fn parse_index_legacy_on(verb: &str, lex: &mut Lexer<'_>) -> Result<(String, String), String> {
    expect_symbol(lex, ':', verb)?;
    let label = expect_name(lex, "a label", verb)?;
    expect_symbol(lex, '(', verb)?;
    let property = expect_name(lex, "a property", verb)?;
    expect_symbol(lex, ')', verb)?;
    expect_end(lex, &format!("{verb} INDEX"))?;
    Ok((label, property))
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

/// Parses `GRANT`/`REVOKE` (the verb already read, the statement already CLAIMED — GRANT/REVOKE are
/// never valid Cypher). Two shapes:
///
/// ```text
/// GRANT  ROLE <role> TO   <user>      REVOKE ROLE <role> FROM <user>
/// GRANT  <action> ON <scope> TO <role>
/// REVOKE <action> ON <scope> FROM <role>
/// ```
///
/// `<action>` is `TRAVERSE`/`READ`/`WRITE`/`SCHEMA`/`ADMIN`; `<scope>` is parsed by
/// [`parse_priv_scope`]. The trailing keyword is `TO` for `GRANT`, `FROM` for `REVOKE`.
fn parse_grant_revoke(verb: &str, lex: &mut Lexer<'_>) -> Result<AdminCommand, String> {
    let granting = verb == "GRANT";
    let connective = if granting { "TO" } else { "FROM" };

    let second = lex
        .next_tok()?
        .ok_or_else(|| format!("expected ROLE or an action after {verb}"))?;

    // GRANT/REVOKE ROLE <role> TO/FROM <user>
    if is_keyword(&second, "ROLE") {
        let role = expect_security_name(lex, &format!("a role name after {verb} ROLE"))?;
        expect_security_keyword(lex, connective, verb)?;
        let user = expect_security_name(lex, &format!("a user name after {connective}"))?;
        expect_end(lex, &format!("{verb} ROLE"))?;
        return Ok(if granting {
            AdminCommand::GrantRole { role, user }
        } else {
            AdminCommand::RevokeRole { role, user }
        });
    }

    // GRANT/REVOKE <action> ON <scope> TO/FROM <role>
    let action = match &second {
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
    Ok(if granting {
        AdminCommand::GrantPrivilege {
            action,
            scope,
            role,
        }
    } else {
        AdminCommand::RevokePrivilege {
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
    ) -> Self {
        Self {
            catalog,
            security,
            audit,
            runtime,
            default_handle,
        }
    }

    /// Shared access to the live security catalog (the listeners' authentication path resolves
    /// through it so a `DROP USER` immediately invalidates that user's sessions).
    #[must_use]
    pub fn security(&self) -> &Arc<SecurityCatalog> {
        &self.security
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
        result
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
            AdminCommand::RevokePrivilege {
                action,
                scope,
                role,
            } => self.run_security(false, false, {
                let security = Arc::clone(&self.security);
                let role = role.clone();
                let privilege = Privilege::new(action.to_action(), scope.to_resource());
                move || async move { security.revoke_privilege(&role, privilege).await }
            }),
            AdminCommand::ShowUsers => Ok(show_users(&self.security.list_users())),
            AdminCommand::ShowRoles => Ok(show_roles(&self.security.list_roles())),
            AdminCommand::ShowPrivileges => Ok(show_privileges(&self.security.list_privileges())),

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

/// Builds the `SHOW USERS` result: `user` (string), `roles` (comma-joined string), `passwordSet`
/// (bool).
fn show_users(users: &[crate::security::UserListing]) -> AdminResult {
    let fields = vec![
        "user".to_owned(),
        "roles".to_owned(),
        "passwordSet".to_owned(),
    ];
    let rows = users
        .iter()
        .map(|u| {
            vec![
                Value::String(u.name.clone()),
                Value::String(u.roles.join(", ")),
                Value::Boolean(u.has_password),
            ]
        })
        .collect();
    AdminResult { fields, rows }
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
    AdminResult { fields, rows }
}

/// Builds the `SHOW PRIVILEGES` result: `role` (string), `action` (string), `scope` (string).
fn show_privileges(privs: &[crate::security::PrivilegeListing]) -> AdminResult {
    let fields = vec!["role".to_owned(), "action".to_owned(), "scope".to_owned()];
    let rows = privs
        .iter()
        .map(|p| {
            vec![
                Value::String(p.role.clone()),
                Value::String(p.action.clone()),
                Value::String(p.scope.clone()),
            ]
        })
        .collect();
    AdminResult { fields, rows }
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

    #[test]
    fn create_index_both_shapes() {
        // openCypher 9 form.
        assert_eq!(
            index_cmd("CREATE INDEX FOR (n:Person) ON (n.age)"),
            IndexCommand::CreateNodePropertyIndex {
                label: "Person".to_owned(),
                property: "age".to_owned(),
            }
        );
        // Legacy form.
        assert_eq!(
            index_cmd("CREATE INDEX ON :Person(age)"),
            IndexCommand::CreateNodePropertyIndex {
                label: "Person".to_owned(),
                property: "age".to_owned(),
            }
        );
        // Case-insensitive keywords, surrounding whitespace, trailing `;`, backtick-quoted names.
        assert_eq!(
            index_cmd("  create   index   for ( p : `Sales-Rep` )  on ( p.`first.name` ) ;"),
            IndexCommand::CreateNodePropertyIndex {
                label: "Sales-Rep".to_owned(),
                property: "first.name".to_owned(),
            }
        );
        // A different variable letter in the ON clause is fine (the variable text is irrelevant).
        assert_eq!(
            index_cmd("CREATE INDEX FOR (a:Tag) ON (a.name)"),
            IndexCommand::CreateNodePropertyIndex {
                label: "Tag".to_owned(),
                property: "name".to_owned(),
            }
        );
    }

    #[test]
    fn drop_index_both_shapes_and_show_indexes() {
        assert_eq!(
            index_cmd("DROP INDEX ON :Person(age)"),
            IndexCommand::DropNodePropertyIndex {
                label: "Person".to_owned(),
                property: "age".to_owned(),
            }
        );
        assert_eq!(
            index_cmd("drop index for (n:Person) on (n.age)"),
            IndexCommand::DropNodePropertyIndex {
                label: "Person".to_owned(),
                property: "age".to_owned(),
            }
        );
        assert_eq!(index_cmd("SHOW INDEXES"), IndexCommand::ShowIndexes);
        assert_eq!(index_cmd("show indexes ;"), IndexCommand::ShowIndexes);
    }

    #[test]
    fn claimed_but_malformed_index_is_a_syntax_error() {
        // Claimed by the two-token `<verb> INDEX[ES]` prefix; the remainder must parse exactly.
        invalid("CREATE INDEX"); // missing target
        invalid("CREATE INDEX FOR (n:Person)"); // missing ON clause
        invalid("CREATE INDEX FOR (n:Person) ON (n.age) extra");
        invalid("CREATE INDEX ON Person(age)"); // legacy needs the leading `:`
        invalid("CREATE INDEX ON :Person"); // missing (property)
        invalid("CREATE INDEX FOR (n:Person) ON (age)"); // ON ref must be `var.property`
        invalid("CREATE INDEXES FOR (n:Person) ON (n.age)"); // plural only for SHOW
        invalid("SHOW INDEX"); // the singular is not a form
        invalid("SHOW INDEXES extra");
        invalid("DROP INDEX"); // missing target
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
                label: "Article".to_owned(),
                properties: vec!["title".to_owned()],
                analyzer: "standard".to_owned(),
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
                label: "Book".to_owned(),
                properties: vec!["title".to_owned(), "summary".to_owned()],
                analyzer: "keyword".to_owned(),
            }
        );
        // Backtick-quoted name/label/property colliding with keywords still parse.
        assert_eq!(
            index_cmd("CREATE FULLTEXT INDEX `INDEX` FOR (n:`Order`) ON EACH [n.`from`]"),
            IndexCommand::CreateFulltextIndex {
                name: "INDEX".to_owned(),
                label: "Order".to_owned(),
                properties: vec!["from".to_owned()],
                analyzer: "standard".to_owned(),
            }
        );
    }

    #[test]
    fn drop_and_show_fulltext() {
        assert_eq!(
            index_cmd("DROP FULLTEXT INDEX articles"),
            IndexCommand::DropFulltextIndex {
                name: "articles".to_owned()
            }
        );
        assert_eq!(
            index_cmd("drop fulltext index `My Index` ;"),
            IndexCommand::DropFulltextIndex {
                name: "My Index".to_owned()
            }
        );
        assert_eq!(
            index_cmd("SHOW FULLTEXT INDEXES"),
            IndexCommand::ShowFulltextIndexes
        );
        assert_eq!(
            index_cmd("show fulltext indexes ;"),
            IndexCommand::ShowFulltextIndexes
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
        invalid("SHOW FULLTEXT INDEX"); // singular not a form
        invalid("SHOW FULLTEXT INDEXES extra");
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
                label: "City".to_owned(),
                property: "location".to_owned(),
            }
        );
        // Case-insensitive keywords + whitespace + trailing `;`.
        assert_eq!(
            index_cmd("  create   point index  near  for ( p : Place ) on ( p.geo ) ;"),
            IndexCommand::CreatePointIndex {
                name: "near".to_owned(),
                label: "Place".to_owned(),
                property: "geo".to_owned(),
            }
        );
        // Backtick-quoted name/label/property colliding with keywords still parse.
        assert_eq!(
            index_cmd("CREATE POINT INDEX `INDEX` FOR (n:`Order`) ON (n.`from`)"),
            IndexCommand::CreatePointIndex {
                name: "INDEX".to_owned(),
                label: "Order".to_owned(),
                property: "from".to_owned(),
            }
        );
    }

    #[test]
    fn drop_and_show_point() {
        assert_eq!(
            index_cmd("DROP POINT INDEX by_loc"),
            IndexCommand::DropPointIndex {
                name: "by_loc".to_owned()
            }
        );
        assert_eq!(
            index_cmd("drop point index `My Index` ;"),
            IndexCommand::DropPointIndex {
                name: "My Index".to_owned()
            }
        );
        assert_eq!(
            index_cmd("SHOW POINT INDEXES"),
            IndexCommand::ShowPointIndexes
        );
        assert_eq!(
            index_cmd("show point indexes ;"),
            IndexCommand::ShowPointIndexes
        );
    }

    #[test]
    fn claimed_but_malformed_point_is_a_syntax_error() {
        invalid("CREATE POINT"); // missing INDEX
        invalid("CREATE POINT INDEX"); // missing name
        invalid("CREATE POINT INDEX p"); // missing FOR clause
        invalid("CREATE POINT INDEX p FOR (n:City)"); // missing ON
        invalid("CREATE POINT INDEX p FOR (n:City) ON EACH [n.loc]"); // point uses single ON (...)
        invalid("CREATE POINT INDEX p FOR (n:City) ON (loc)"); // ref must be var.prop
        invalid("CREATE POINT INDEX p FOR (n:City) ON (n.loc) extra");
        invalid("SHOW POINT INDEX"); // singular not a form
        invalid("SHOW POINT INDEXES extra");
        invalid("DROP POINT INDEX"); // missing name
        invalid("DROP POINT INDEX p trailing");
        invalid("CREATE POINT INDEXES ..."); // plural only for SHOW
    }

    #[test]
    fn create_constraint_unique_and_not_null() {
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c1 FOR (n:Person) REQUIRE n.email IS UNIQUE"),
            ConstraintCommand::CreateUnique {
                name: "c1".to_owned(),
                label: "Person".to_owned(),
                property: "email".to_owned(),
            }
        );
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT c2 FOR (n:Person) REQUIRE n.name IS NOT NULL"),
            ConstraintCommand::CreateExistence {
                name: "c2".to_owned(),
                label: "Person".to_owned(),
                property: "name".to_owned(),
            }
        );
        // Case-insensitive keywords, the legacy `ASSERT` spelling, and a parenthesised property all
        // parse to the same command.
        assert_eq!(
            constraint_cmd("create constraint c3 for (x:Account) assert (x.iban) is unique"),
            ConstraintCommand::CreateUnique {
                name: "c3".to_owned(),
                label: "Account".to_owned(),
                property: "iban".to_owned(),
            }
        );
    }

    #[test]
    fn create_constraint_node_key() {
        // A composite node key over a parenthesised property tuple.
        assert_eq!(
            constraint_cmd(
                "CREATE CONSTRAINT pk FOR (n:Person) REQUIRE (n.first, n.last) IS NODE KEY"
            ),
            ConstraintCommand::CreateNodeKey {
                name: "pk".to_owned(),
                label: "Person".to_owned(),
                properties: vec!["first".to_owned(), "last".to_owned()],
            }
        );
        // A single-property node key is also valid (the degenerate composite); case-insensitive.
        assert_eq!(
            constraint_cmd("create constraint k for (a:Account) require (a.iban) is node key"),
            ConstraintCommand::CreateNodeKey {
                name: "k".to_owned(),
                label: "Account".to_owned(),
                properties: vec!["iban".to_owned()],
            }
        );
    }

    #[test]
    fn create_constraint_property_type() {
        use graphus_storage::ConstraintTypeDescriptor as T;
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT t FOR (n:Person) REQUIRE n.age IS :: INTEGER"),
            ConstraintCommand::CreatePropertyType {
                name: "t".to_owned(),
                label: "Person".to_owned(),
                property: "age".to_owned(),
                declared_type: T::Integer,
            }
        );
        // Each scalar type, case-insensitive, and a parenthesised property.
        for (src, expected) in [
            ("REQUIRE n.x IS :: FLOAT", T::Float),
            ("REQUIRE n.x IS :: STRING", T::String),
            ("require n.x is :: boolean", T::Boolean),
            ("REQUIRE (n.x) IS :: STRING", T::String),
        ] {
            let q = format!("CREATE CONSTRAINT t FOR (n:Person) {src}");
            assert_eq!(
                constraint_cmd(&q),
                ConstraintCommand::CreatePropertyType {
                    name: "t".to_owned(),
                    label: "Person".to_owned(),
                    property: "x".to_owned(),
                    declared_type: expected,
                },
                "{q}"
            );
        }
        // A LIST<…> type, including a nested list.
        assert_eq!(
            constraint_cmd("CREATE CONSTRAINT t FOR (n:Person) REQUIRE n.tags IS :: LIST<STRING>"),
            ConstraintCommand::CreatePropertyType {
                name: "t".to_owned(),
                label: "Person".to_owned(),
                property: "tags".to_owned(),
                declared_type: T::List(Box::new(T::String)),
            }
        );
        assert_eq!(
            constraint_cmd(
                "CREATE CONSTRAINT t FOR (n:Person) REQUIRE n.matrix IS :: LIST<LIST<INTEGER>>"
            ),
            ConstraintCommand::CreatePropertyType {
                name: "t".to_owned(),
                label: "Person".to_owned(),
                property: "matrix".to_owned(),
                declared_type: T::List(Box::new(T::List(Box::new(T::Integer)))),
            }
        );
    }

    #[test]
    fn malformed_node_key_and_property_type_are_syntax_errors() {
        // A composite tuple is only valid with NODE KEY.
        invalid("CREATE CONSTRAINT c FOR (n:Person) REQUIRE (n.a, n.b) IS UNIQUE");
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
    fn drop_and_show_constraints() {
        assert_eq!(
            constraint_cmd("DROP CONSTRAINT c1"),
            ConstraintCommand::Drop {
                name: "c1".to_owned()
            }
        );
        assert_eq!(constraint_cmd("SHOW CONSTRAINTS"), ConstraintCommand::Show);
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
}
