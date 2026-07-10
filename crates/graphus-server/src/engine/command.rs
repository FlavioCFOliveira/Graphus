//! The command protocol between the connection tasks (Bolt/REST) and the single engine task
//! (`04-technical-design.md` §9.1: the sharded write/ACID path; v1 = one shard).
//!
//! The cypher engine is single-threaded (`!Sync`, `Rc<RefCell<…>>`-backed — see the crate docs and
//! [`graphus_cypher::TxnCoordinator`]), but the server is a multi-threaded Tokio runtime. We bridge
//! the two by funnelling **all** query execution through one engine thread that owns the
//! [`graphus_storage::RecordStore`] + `TxnCoordinator`, and serving [`EngineCommand`]s over a
//! **bounded** channel. Each connection submits a command carrying its authenticated identity +
//! access mode and a [`tokio::sync::oneshot`] reply sender, then awaits the reply.
//!
//! Writes serialize through the engine thread (the single-writer ACID path). **Reads do not:** a
//! structurally read-only auto-commit statement is captured on the engine thread and then executed
//! **off-thread** on the reader pool against a cloned MVCC read view, concurrently with the writer and
//! with other readers (`rmp` tasks #336 + #543, `super::read_pool`). Reads take no locks and never
//! block a writer (`graphus_txn` — `note_read` never touches the `LockTable`).

use graphus_core::{GraphusError, Value};

use super::bulk_load::{BulkImportBatchInput, BulkImportBatchOutcome};
use super::bulk_load_b::{BulkImportModeBChunkInput, BulkImportModeBChunkOutcome};
use super::privileges::EffectivePrivileges;
use super::stream::{RowReceiver, SummarySink};
use crate::engine::TxTicket;

/// The engine's end of a command reply: a one-shot, capacity-1 [`std::sync::mpsc::SyncSender`].
///
/// Replies use a **std** channel (not `tokio::sync::oneshot`) deliberately. The blocking seams (Bolt,
/// and REST whose synchronous handlers run inside a `Handle::block_on` on a blocking thread) must be
/// able to receive a reply **synchronously**; `oneshot::blocking_recv` panics when called inside a
/// runtime context (which `Handle::block_on` establishes), whereas a std `recv` has no such guard and
/// works on any thread. The async [`crate::engine::EngineHandle`] methods (admin/shutdown) await the
/// std receive via `spawn_blocking`.
pub struct Reply<T>(std::sync::mpsc::SyncSender<T>);

impl<T> Reply<T> {
    /// Sends the reply, returning `Err(value)` if the receiver was already dropped (e.g. a
    /// disconnected client). The engine uses the error to detect a gone consumer and clean up an
    /// orphaned auto-commit transaction.
    pub fn send(self, value: T) -> Result<(), T> {
        self.0.send(value).map_err(|e| e.0)
    }

    /// Returns a second [`Reply`] handle sharing the same one-shot channel, for use as a **panic
    /// fallback** (`rmp` task #386).
    ///
    /// The engine's per-statement dispatch moves the original `Reply` into the executor; if that
    /// execution **panics** before it delivered its reply, the unwind boundary still needs a way to
    /// hand the waiting consumer a clean terminal error instead of letting the connection hang on
    /// `engine_gone` forever. This clone provides exactly that: it points at the same capacity-1
    /// channel, so a [`Self::try_send_fallback`] on it is delivered iff the original never sent (the
    /// buffer is empty). If the original *did* send first, the buffer is full and the fallback is a
    /// harmless no-op — the consumer already has its (possibly partial) reply and the stream is
    /// terminated by the dropped row channel.
    #[must_use]
    pub fn fallback(&self) -> Self {
        Reply(self.0.clone())
    }

    /// Best-effort, **non-blocking** terminal send used only by the panic fallback (`rmp` task #386).
    ///
    /// Never blocks the engine thread: a full buffer (the original reply already landed) or a gone
    /// receiver (consumer disconnected) both resolve to `Err(value)` and are ignored by the caller.
    /// This is the only send that may legitimately fail-and-be-dropped, because by construction the
    /// real reply has already reached the consumer in those cases.
    pub fn try_send_fallback(&self, value: T) -> Result<(), T> {
        use std::sync::mpsc::TrySendError;
        self.0.try_send(value).map_err(|e| match e {
            TrySendError::Full(v) | TrySendError::Disconnected(v) => v,
        })
    }
}

/// The submitter's end of a command reply.
pub struct ReplyReceiver<T>(std::sync::mpsc::Receiver<T>);

impl<T> ReplyReceiver<T> {
    /// Blocking receive — usable on any thread (no runtime-context guard).
    ///
    /// # Errors
    /// Returns `Err` if the engine dropped the sender (engine gone).
    pub fn recv(self) -> Result<T, std::sync::mpsc::RecvError> {
        self.0.recv()
    }
}

/// Creates a one-shot reply channel (capacity 1).
#[must_use]
pub fn reply_channel<T>() -> (Reply<T>, ReplyReceiver<T>) {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    (Reply(tx), ReplyReceiver(rx))
}

/// The access mode of a transaction, unified across both connectivity seams.
///
/// `graphus_bolt::AccessMode` and `graphus_rest::AccessMode` are distinct types (each crate owns
/// its own), so the engine carries this neutral copy and the adapters convert at their boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessMode {
    /// Read-only: write statements are rejected.
    Read,
    /// Read-write (the default).
    #[default]
    Write,
}

/// The reply to a [`EngineCommand::Run`]: the result column names and a bounded receiver the caller
/// pulls rows from, or the engine's error if the query failed before producing any row.
#[derive(Debug)]
pub struct RunReply {
    /// The result column names, in projection order (the `fields` metadata).
    pub fields: Vec<String>,
    /// The bounded row stream; pull rows until it yields `None` (exhausted) or a row `Err`.
    pub rows: RowReceiver,
    /// The side channel the engine fills with this statement's result summary (`metadata.type` +
    /// `metadata.stats`) once its rows are produced (`rmp` task #512). The consumer seam reads it via
    /// [`SummarySink::get`] **after** draining `rows` (the happens-before the sink documents); it is
    /// empty (a default [`RunSummary`]) until the engine fills it.
    pub summary: SummarySink,
}

/// How a `DROP INDEX` identifies the node-property index to drop (`rmp` task #624): by its
/// server-unique **name** (`DROP INDEX <name>`) or by its covered `(label, property)` **target**
/// (the openCypher `DROP INDEX FOR (n:L) ON (n.p)` / legacy `DROP INDEX ON :L(p)` shapes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodePropertyIndexRef {
    /// `DROP INDEX <name>` — identify the index by its server-unique name.
    Named(String),
    /// `DROP INDEX FOR (n:L) ON (n.p)` / `DROP INDEX ON :L(p)` — identify by covered label + covered
    /// property tuple. A single-element list targets a single-property node index; a multi-element list
    /// targets the composite (multi-property) index over that exact ordered tuple (`rmp` task #657).
    Target {
        /// The covered node label.
        label: String,
        /// The covered property keys, in declared order (one for a single-property index, two or more
        /// for a composite index).
        properties: Vec<String>,
    },
}

/// An **index-DDL** statement routed to the engine thread (`rmp` task #91), where the
/// node-property index catalog lives (on the single-threaded coordinator). Unlike the DATABASE
/// admin commands — which act on the off-engine async [`crate::dbcatalog::DatabaseCatalog`] — index
/// DDL must reach the [`graphus_cypher::TxnCoordinator`], so it travels as its own engine command.
///
/// The names are validated/normalized by the admin matcher before this is built; the engine looks
/// them up / interns them through the coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexCommand {
    /// `CREATE INDEX [<name>] [IF NOT EXISTS] FOR (n:<Label>) ON (n.<a>[, n.<b>, …])` on
    /// `(label, properties)`: starts a **non-blocking** build (the index is `Populating` and built in
    /// the background; the command returns promptly). A single-element `properties` is a single-property
    /// RANGE index; a two-or-more-element list is a **composite** (multi-property) RANGE index over the
    /// ordered property tuple (`rmp` task #657). `name` is the requested server-unique name, or [`None`]
    /// to auto-generate a deterministic one (`rmp` task #624); `if_not_exists` makes an already-existing
    /// index (by name or equivalent schema) a no-op success rather than an error.
    CreateNodePropertyIndex {
        /// The requested server-unique name, or [`None`] to auto-generate one.
        name: Option<String>,
        /// The node label the index is declared on.
        label: String,
        /// The property keys the index is declared on, in declared order (one for a single-property
        /// index, two or more for a composite index; the order is significant for a composite).
        properties: Vec<String>,
        /// Whether `IF NOT EXISTS` was given (a duplicate becomes a no-op success).
        if_not_exists: bool,
    },
    /// `DROP INDEX <name> [IF EXISTS]` (by name) or `DROP INDEX FOR (n:<Label>) ON (n.<property>)` /
    /// `DROP INDEX ON :<Label>(<property>)` (by target): removes the index (durable + in-memory),
    /// cancelling any in-progress build. `if_exists` (by-name form only) makes a missing index a no-op
    /// success rather than an error (`rmp` task #624).
    DropNodePropertyIndex {
        /// Which index to drop — by name or by covered `(label, property)`.
        index: NodePropertyIndexRef,
        /// Whether `IF EXISTS` was given (a missing index becomes a no-op success).
        if_exists: bool,
    },
    /// `SHOW [<filter>] INDEX[ES] [YIELD … | WHERE …]` (`rmp` tasks #91, #660): the **unified**
    /// Neo4j-conformant listing of *every* index kind — node-property and relationship-property
    /// `RANGE`, composite `RANGE`, `FULLTEXT`, `POINT`, and the two always-on token `LOOKUP` indexes —
    /// restricted to `filter`'s kinds, with an optional `YIELD`/`WHERE`/`RETURN` tail.
    ///
    /// The engine renders the **full column** row set (`crate::engine::index_show::COLUMNS_FULL`,
    /// filtered by `filter`); the seams then, when `tail` is `Some`, re-run a **translated read query**
    /// over those rows through the Cypher engine (`crate::engine::index_show::finish`), and otherwise
    /// project to the default columns. `tail` is the raw post-`INDEX[ES]` text (beginning `YIELD` or
    /// `WHERE`) captured verbatim by the admin parser. This folds the legacy bespoke-column
    /// `SHOW FULLTEXT INDEXES` / `SHOW POINT INDEXES` surfaces into one Neo4j-shaped listing.
    ShowIndexes {
        /// The index-kind filter (`ALL` / a specific-kind selector).
        filter: IndexTypeFilter,
        /// The raw `YIELD …` / `WHERE …` tail, or [`None`] for a bare listing.
        tail: Option<String>,
    },
    /// `CREATE FULLTEXT INDEX <name> [IF NOT EXISTS] FOR (n:<Label>[|<Label>…]) ON EACH [n.<prop>, …]`
    /// (node) or `… FOR ()-[r:<Type>[|<Type>…]]-() ON EACH [r.<prop>, …]` (relationship)
    /// (`rmp` tasks #72, #661, #663): starts an online build of a full-text index over
    /// `(entity, labels_or_types, properties)` analyzed with `analyzer` (a lower-cased analyzer name;
    /// `standard` by default). `if_not_exists` makes an already-existing equivalent index (same name or
    /// same covered schema) a no-op success rather than a replace.
    CreateFulltextIndex {
        /// The server-unique index name.
        name: String,
        /// Whether the index covers node labels or relationship types (`rmp` task #663).
        entity: graphus_cypher::FulltextEntity,
        /// The node labels (node index) or relationship types (relationship index) the index covers,
        /// in declared order (one or more, `rmp` task #663).
        labels_or_types: Vec<String>,
        /// The property keys the index covers, in declared order (one or more).
        properties: Vec<String>,
        /// The analyzer name (`standard` / `keyword`); validated by the engine against the supported
        /// set so an unknown analyzer is a clear error.
        analyzer: String,
        /// Whether `IF NOT EXISTS` was given (a duplicate becomes a no-op success) (`rmp` task #661).
        if_not_exists: bool,
    },
    /// `DROP [FULLTEXT] INDEX <name> [IF EXISTS]` of a full-text index (`rmp` tasks #72, #661): removes
    /// it (durable + in-memory), cancelling any in-progress build. `if_exists` makes a missing index a
    /// no-op success rather than an error.
    DropFulltextIndex {
        /// The full-text index name to drop.
        name: String,
        /// Whether `IF EXISTS` was given (a missing index becomes a no-op success) (`rmp` task #661).
        if_exists: bool,
    },
    /// `CREATE POINT INDEX [<name>] [IF NOT EXISTS] FOR (n:<Label>) ON (n.<prop>)` (node) or
    /// `… FOR ()-[r:<Type>]-() ON (r.<prop>)` (relationship) (`rmp` tasks #98, #661, #664): starts a
    /// build of a grid spatial (point) index over `(entity, label_or_type, property)` — non-blocking for
    /// a node index, synchronous-`Online` for a relationship index. `name` is the requested server-unique
    /// name (auto-generated deterministically by the admin matcher when omitted); `if_not_exists` makes an
    /// already-existing equivalent index (same name or same covered schema) a no-op success.
    CreatePointIndex {
        /// The server-unique index name.
        name: String,
        /// Whether the index covers a node label or a relationship type (`rmp` task #664).
        entity: graphus_cypher::SpatialEntity,
        /// The node label (node index) or relationship type (relationship index) the index covers.
        label: String,
        /// The point property the index covers (exactly one).
        property: String,
        /// Whether `IF NOT EXISTS` was given (a duplicate becomes a no-op success) (`rmp` task #661).
        if_not_exists: bool,
    },
    /// `DROP [POINT] INDEX <name> [IF EXISTS]` (`rmp` tasks #98, #661): removes the spatial index
    /// (durable + in-memory), cancelling any in-progress build. `if_exists` makes a missing index a
    /// no-op success rather than an error.
    DropPointIndex {
        /// The spatial index name to drop.
        name: String,
        /// Whether `IF EXISTS` was given (a missing index becomes a no-op success) (`rmp` task #661).
        if_exists: bool,
    },
    /// `CREATE TEXT INDEX [<name>] [IF NOT EXISTS] FOR (n:<Label>) ON (n.<prop>)` (`rmp` task #662):
    /// declares a **text (trigram) index** — a distinct native string index, NOT a synonym of `RANGE` —
    /// that accelerates `CONTAINS` / `ENDS WITH` / `STARTS WITH` over `(label, property)`. Built
    /// synchronously (ending `Online`), like a relationship / composite index. `name` is the requested
    /// server-unique name (auto-generated deterministically by the admin matcher when omitted);
    /// `if_not_exists` makes an already-existing equivalent index (same name or same covered schema) a
    /// no-op success rather than an error.
    CreateTextIndex {
        /// The server-unique index name.
        name: String,
        /// The node label the index covers.
        label: String,
        /// The string property the index covers (exactly one).
        property: String,
        /// Whether `IF NOT EXISTS` was given (a duplicate becomes a no-op success) (`rmp` task #662).
        if_not_exists: bool,
    },
    /// `DROP [TEXT] INDEX <name> [IF EXISTS]` (`rmp` task #662): removes the text (trigram) index
    /// (durable + in-memory). `if_exists` makes a missing index a no-op success rather than an error.
    DropTextIndex {
        /// The text index name to drop.
        name: String,
        /// Whether `IF EXISTS` was given (a missing index becomes a no-op success) (`rmp` task #662).
        if_exists: bool,
    },
    /// `CREATE INDEX [<name>] [IF NOT EXISTS] FOR ()-[r:<TYPE>]-() ON (r.<a>[, r.<b>, …])` on
    /// `(rel_type, properties)` (`rmp` tasks #646 / #666): the relationship analogue of
    /// [`CreateNodePropertyIndex`](Self::CreateNodePropertyIndex). A single-element `properties` is a
    /// single-property RANGE index; a two-or-more-element list is a **composite** (multi-property) RANGE
    /// index over the ordered property tuple (`rmp` task #666). Synchronously builds the index from the
    /// existing relationships (ending `Online`). `name` is the requested server-unique name, or [`None`]
    /// to auto-generate a deterministic one; `if_not_exists` makes a duplicate a no-op success.
    CreateRelPropertyIndex {
        /// The requested server-unique name, or [`None`] to auto-generate one.
        name: Option<String>,
        /// The relationship type the index is declared on.
        rel_type: String,
        /// The property keys the index is declared on, in declared order (one for a single-property
        /// index, two or more for a composite index; the order is significant for a composite).
        properties: Vec<String>,
        /// Whether `IF NOT EXISTS` was given (a duplicate becomes a no-op success).
        if_not_exists: bool,
    },
    /// `DROP INDEX <name> [IF EXISTS]` (by name) or `DROP INDEX FOR ()-[r:<TYPE>]-() ON (r.<property>)`
    /// (by target) for a relationship-property index (`rmp` task #646). `if_exists` (by-name form only)
    /// makes a missing index a no-op success.
    DropRelPropertyIndex {
        /// Which index to drop — by name or by covered `(rel_type, property)`.
        index: RelPropertyIndexRef,
        /// Whether `IF EXISTS` was given (a missing index becomes a no-op success).
        if_exists: bool,
    },
}

/// How a `DROP INDEX` identifies the relationship-property index to drop (`rmp` task #646): by its
/// server-unique **name** (`DROP INDEX <name>`) or by its covered `(rel_type, property)` **target**
/// (`DROP INDEX FOR ()-[r:T]-() ON (r.p)`). The relationship analogue of [`NodePropertyIndexRef`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelPropertyIndexRef {
    /// `DROP INDEX <name>` — identify the index by its server-unique name.
    Named(String),
    /// `DROP INDEX FOR ()-[r:T]-() ON (r.p[, r.q, …])` — identify by covered relationship type + covered
    /// property tuple. A single-element list targets a single-property relationship index; a
    /// multi-element list targets the composite (multi-property) index over that exact ordered tuple
    /// (`rmp` task #666).
    Target {
        /// The covered relationship type.
        rel_type: String,
        /// The covered property keys, in declared order (one for a single-property index, two or more
        /// for a composite index).
        properties: Vec<String>,
    },
}

/// The entity a constraint covers (`rmp` #638): a node label (the `FOR (n:Label)` pattern) or a
/// relationship type (the `FOR ()-[r:TYPE]-()` pattern). The entity selects the token namespace the
/// covering name interns into and the store domain — nodes vs relationships — that a `CREATE`
/// validates against and the write path enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintEntity {
    /// A node constraint over `label` (the `FOR (n:Label)` pattern, `rmp` tasks #99/#100).
    Node {
        /// The node label the constraint covers.
        label: String,
    },
    /// A relationship constraint over `rel_type` (the `FOR ()-[r:TYPE]-()` pattern, `rmp` #638).
    Relationship {
        /// The relationship type the constraint covers.
        rel_type: String,
    },
}

impl ConstraintEntity {
    /// The covering schema name — the label for a node entity, the relationship type for a
    /// relationship entity — used for interning and diagnostic messages.
    #[must_use]
    pub fn covering_name(&self) -> &str {
        match self {
            Self::Node { label } => label,
            Self::Relationship { rel_type } => rel_type,
        }
    }

    /// Whether this is a relationship entity (`rmp` #638).
    #[must_use]
    pub fn is_relationship(&self) -> bool {
        matches!(self, Self::Relationship { .. })
    }
}

/// The kind of a `CREATE CONSTRAINT` rule, entity-agnostic (`rmp` #638): the same four kinds apply to
/// either a node or a relationship entity, and [`CreateConstraint`] pairs one with a
/// [`ConstraintEntity`]. The engine maps the `(entity, kind)` pair onto the durable
/// [`graphus_storage::ConstraintKind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintCreateKind {
    /// `IS [NODE|REL[ATIONSHIP]] UNIQUE` — the covered single property is unique across the domain.
    Unique,
    /// `IS NOT NULL` — the covered single property must be present + non-null (existence).
    Existence,
    /// `IS [NODE|REL[ATIONSHIP]] KEY` — the covered property tuple (one or more) is present + unique.
    Key,
    /// `IS :: <TYPE>` — the covered single property, when present, matches `declared_type`.
    PropertyType {
        /// The declared value type the property must match.
        declared_type: graphus_storage::ConstraintTypeDescriptor,
    },
}

/// The parsed body of a `CREATE CONSTRAINT` statement (`rmp` tasks #99, #100, #638). The admin matcher
/// validates/normalizes the identifiers before this is built; the engine interns them through the
/// coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateConstraint {
    /// The server-unique constraint name.
    pub name: String,
    /// The entity (node label / relationship type) the constraint covers.
    pub entity: ConstraintEntity,
    /// The covered properties in declared order (one for `Unique`/`Existence`/`PropertyType`,
    /// one-or-more for a composite `Key`).
    pub properties: Vec<String>,
    /// The constraint kind.
    pub kind: ConstraintCreateKind,
    /// `IF NOT EXISTS` (`rmp` #638): an equivalent existing constraint — same name, or same
    /// schema — makes creation an idempotent no-op success (`0` counters) rather than an error.
    /// Mutually exclusive with `or_replace` (the parser rejects both at once).
    pub if_not_exists: bool,
    /// `OR REPLACE` (`rmp` #638): drop any same-named constraint first, then create. A **Graphus
    /// superset** of the Neo4j surface (which offers only `IF NOT EXISTS` for constraints). Mutually
    /// exclusive with `if_not_exists`.
    pub or_replace: bool,
}

/// A type filter for `SHOW CONSTRAINTS` (`rmp` task #653): `SHOW <filter> CONSTRAINT[S]` restricts the
/// listing to the constraint kinds the filter selects, matching Neo4j-5.x's filtered forms
/// (`SHOW NODE KEY CONSTRAINTS`, `SHOW UNIQUENESS CONSTRAINTS`, `SHOW REL PROPERTY EXISTENCE
/// CONSTRAINTS`, …). [`All`](Self::All) — and the absent filter of a bare `SHOW CONSTRAINTS` — selects
/// every kind. The entity-qualified variants (`Node*`/`Rel*`) select one entity dimension; the
/// unqualified ones (`Unique`/`Existence`/`Key`/`PropertyType`) select both node and relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintTypeFilter {
    /// `ALL` / no filter — every constraint kind.
    All,
    /// `NODE [PROPERTY] UNIQUE[NESS]` — node uniqueness only.
    NodeUnique,
    /// `REL[ATIONSHIP] [PROPERTY] UNIQUE[NESS]` — relationship uniqueness only.
    RelUnique,
    /// `[PROPERTY] UNIQUE[NESS]` — node **and** relationship uniqueness.
    Unique,
    /// `NODE [PROPERTY] EXIST[ENCE]` — node existence only.
    NodeExistence,
    /// `REL[ATIONSHIP] [PROPERTY] EXIST[ENCE]` — relationship existence only.
    RelExistence,
    /// `[PROPERTY] EXIST[ENCE]` — node **and** relationship existence.
    Existence,
    /// `NODE KEY` — node key only.
    NodeKey,
    /// `REL[ATIONSHIP] KEY` — relationship key only.
    RelKey,
    /// `KEY` — node **and** relationship key.
    Key,
    /// `NODE PROPERTY TYPE` — node property-type only.
    NodePropertyType,
    /// `REL[ATIONSHIP] PROPERTY TYPE` — relationship property-type only.
    RelPropertyType,
    /// `PROPERTY TYPE` — node **and** relationship property-type.
    PropertyType,
}

impl ConstraintTypeFilter {
    /// Whether a constraint of durable `kind` is selected by this filter (`rmp` task #653).
    #[must_use]
    pub fn matches(self, kind: graphus_storage::ConstraintKind) -> bool {
        use graphus_storage::ConstraintKind as K;
        match self {
            Self::All => true,
            Self::NodeUnique => kind == K::Unique,
            Self::RelUnique => kind == K::RelUnique,
            Self::Unique => matches!(kind, K::Unique | K::RelUnique),
            Self::NodeExistence => kind == K::Existence,
            Self::RelExistence => kind == K::RelExistence,
            Self::Existence => matches!(kind, K::Existence | K::RelExistence),
            Self::NodeKey => kind == K::NodeKey,
            Self::RelKey => kind == K::RelKey,
            Self::Key => matches!(kind, K::NodeKey | K::RelKey),
            Self::NodePropertyType => kind == K::PropertyType,
            Self::RelPropertyType => kind == K::RelPropertyType,
            Self::PropertyType => matches!(kind, K::PropertyType | K::RelPropertyType),
        }
    }
}

/// A type filter for `SHOW INDEXES` (`rmp` task #660): `SHOW <filter> INDEX[ES]` restricts the unified
/// listing to the index kinds the filter selects, matching Neo4j-5.x's filtered forms
/// (`SHOW RANGE INDEXES`, `SHOW FULLTEXT INDEXES`, `SHOW POINT INDEXES`, `SHOW LOOKUP INDEXES`, …).
/// [`All`](Self::All) — and the absent filter of a bare `SHOW INDEXES` — selects every kind. The filter
/// matches the Neo4j `type` string a row renders (`RANGE` / `FULLTEXT` / `POINT` / `LOOKUP`).
///
/// Graphus has no distinct `TEXT` or `VECTOR` index kind: a `TEXT` index is a create-time synonym of a
/// `RANGE` B-tree (it renders `type = RANGE`), and vector indexes arrive in a later sprint. So
/// [`Text`](Self::Text) and [`Vector`](Self::Vector) select the (currently empty) set of rows whose
/// `type` is exactly `TEXT` / `VECTOR` — an empty listing rather than a syntax error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexTypeFilter {
    /// `ALL` / no filter — every index kind.
    All,
    /// `RANGE` — node-property, relationship-property and composite range indexes.
    Range,
    /// `TEXT` — text indexes (none in Graphus; a `TEXT` create is a synonym of `RANGE`).
    Text,
    /// `POINT` — spatial (point) indexes.
    Point,
    /// `LOOKUP` — the two always-on token lookup indexes.
    Lookup,
    /// `FULLTEXT` — full-text indexes.
    Fulltext,
    /// `VECTOR` — vector indexes (none in Graphus yet; a later sprint).
    Vector,
}

impl IndexTypeFilter {
    /// Whether an index whose Neo4j `type` string is `type_str` is selected by this filter (`rmp` #660).
    #[must_use]
    pub fn matches(self, type_str: &str) -> bool {
        match self {
            Self::All => true,
            Self::Range => type_str == "RANGE",
            Self::Text => type_str == "TEXT",
            Self::Point => type_str == "POINT",
            Self::Lookup => type_str == "LOOKUP",
            Self::Fulltext => type_str == "FULLTEXT",
            Self::Vector => type_str == "VECTOR",
        }
    }
}

/// A **constraint-DDL** statement routed to the engine thread (`rmp` task #99), where the constraint
/// catalog lives (on the single-threaded coordinator). Like [`IndexCommand`] — and unlike the
/// DATABASE admin commands, which act on the off-engine async catalog — constraint DDL must reach the
/// [`graphus_cypher::TxnCoordinator`], so it travels as its own engine command.
///
/// Unlike an index, a constraint `CREATE` is **synchronous and validated** (it scans existing data and
/// may fail) — there is no non-blocking build phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintCommand {
    /// `CREATE [OR REPLACE] CONSTRAINT <name> [IF NOT EXISTS] FOR … REQUIRE … IS …` (`rmp` tasks #99,
    /// #100, #638): declares a constraint after validating existing data conforms. See
    /// [`CreateConstraint`].
    Create(CreateConstraint),
    /// `DROP CONSTRAINT <name> [IF EXISTS]` (`rmp` tasks #99, #638): removes the constraint (durable +
    /// in-memory), so the write path stops enforcing it. With `if_exists`, a missing constraint is an
    /// idempotent no-op success (`0` removed) rather than an error.
    Drop {
        /// The constraint name to drop.
        name: String,
        /// Whether `IF EXISTS` was given (a missing constraint becomes a no-op success).
        if_exists: bool,
    },
    /// `SHOW [<filter>] CONSTRAINT[S] [YIELD … | WHERE …]` (`rmp` tasks #99, #653): lists declared
    /// constraints, restricted to `filter`'s kinds, with an optional `YIELD`/`WHERE`/`RETURN` tail.
    ///
    /// The engine renders the **full 10-column** row set (`crate::engine::constraint_show::COLUMNS_FULL`,
    /// filtered by `filter`); the seams then, when `tail` is `Some`, re-run a **translated read query**
    /// over those rows through the Cypher engine (`crate::engine::constraint_show::finish`), and
    /// otherwise project to the 8 default columns. `tail` is the raw post-`CONSTRAINT[S]` text (beginning
    /// `YIELD` or `WHERE`) captured verbatim by the admin parser.
    Show {
        /// The constraint-kind filter (`ALL` / a specific-kind selector).
        filter: ConstraintTypeFilter,
        /// The raw `YIELD …` / `WHERE …` tail, or [`None`] for a bare listing.
        tail: Option<String>,
    },
}

/// The buffered result of an [`EngineCommand::IndexDdl`]: column names + rows, streamed back through
/// each seam's normal admin-result mechanism. `CREATE`/`DROP` return no rows; `SHOW INDEXES` returns
/// one row per index.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IndexDdlReply {
    /// The result column names (empty for `CREATE`/`DROP`).
    pub fields: Vec<String>,
    /// The result rows (one per index for `SHOW INDEXES`).
    pub rows: Vec<Vec<Value>>,
    /// Whether the DDL **actually mutated** the schema (`rmp` task #626 follow-up). A
    /// `CREATE … IF NOT EXISTS` on an existing rule and a `DROP … IF EXISTS` (or a by-target drop) of a
    /// missing rule are **no-ops** (`mutated == false`): the seam then reports `indexes-added` /
    /// `indexes-removed` / `constraints-*` of `0` (empty counters, no `contains-updates`), matching
    /// Neo4j's idempotent-DDL summary. A real mutation is `true`. Irrelevant for a `SHOW` (always
    /// `false`; the read summary ignores it).
    pub mutated: bool,
}

impl IndexDdlReply {
    /// A rows-less reply for a `CREATE`/`DROP` DDL, recording whether it actually mutated the schema
    /// (`rmp` task #626 follow-up). `mutated == false` is an idempotent no-op (`IF NOT EXISTS` /
    /// `IF EXISTS` / by-target drop of a missing rule) and the seam reports a `0` counter for it.
    #[must_use]
    pub fn mutation(mutated: bool) -> Self {
        Self {
            fields: Vec::new(),
            rows: Vec::new(),
            mutated,
        }
    }
}

/// One request to the engine task. Every variant carries a `oneshot` sender for its reply, so the
/// submitting (async) task awaits the engine's serial execution without blocking a runtime worker.
pub enum EngineCommand {
    /// Open an explicit transaction in `mode`, replying with its [`TxTicket`].
    Begin {
        /// Read/write access mode for the transaction.
        mode: AccessMode,
        /// Reply channel: the new transaction's ticket, or a transaction error.
        reply: Reply<Result<TxTicket, GraphusError>>,
    },
    /// Run `query` with `params` inside the transaction identified by `ticket`, replying with the
    /// result stream (or the engine error if it failed before the first row).
    ///
    /// `auto_commit` requests the auto-commit shape: the engine commits the (internally-opened)
    /// transaction once the result stream is fully consumed. For an explicit transaction the caller
    /// drives `Commit`/`Rollback` itself.
    Run {
        /// The transaction to run within.
        ticket: TxTicket,
        /// The Cypher query text.
        query: String,
        /// Bound parameters as `(name, value)` pairs.
        params: Vec<(String, Value)>,
        /// Whether this is an auto-commit statement (commit on stream exhaustion).
        auto_commit: bool,
        /// The principal's resolved fine-grained privileges for this statement, scoped to the
        /// session database (rmp #93). `None` means **no RBAC enforcement** for this statement — the
        /// internal / TCK / direct-test path, which behaves byte-identically to a server without
        /// access control. `Some(_)` whose
        /// [`is_unrestricted`](graphus_cypher::PrivilegeOracle::is_unrestricted) is `true` (an
        /// admin) is likewise a pass-through; only a restricted principal triggers filtering. Built
        /// once per statement in the connection seam (where the principal + database are known), the
        /// engine wraps its [`graphus_cypher::GraphAccess`] seam in a
        /// [`graphus_cypher::AuthorizedGraph`] when this is `Some`.
        ///
        /// Boxed so this (the only large) field does not inflate every `EngineCommand` variant on the
        /// command channel (it is `None` on the common unrestricted path; one heap allocation per
        /// restricted statement is negligible against compiling and executing the query).
        privileges: Option<Box<EffectivePrivileges>>,
        /// Reply channel: the result stream, or a compile/runtime/transaction error.
        reply: Reply<Result<RunReply, GraphusError>>,
    },
    /// Begin an auto-commit transaction, returning its ticket. Used by the seams to open the
    /// implicit transaction a bare `RUN` / `POST …/tx/commit` runs in (the engine commits it when
    /// the resulting [`EngineCommand::Run`]'s stream is drained, when `auto_commit` is set).
    BeginAutoCommit {
        /// Read/write access mode.
        mode: AccessMode,
        /// Reply channel: the implicit transaction's ticket.
        reply: Reply<Result<TxTicket, GraphusError>>,
    },
    /// Commit the explicit transaction identified by `ticket`, replying with its summary.
    Commit {
        /// The transaction to commit.
        ticket: TxTicket,
        /// Reply channel: the commit summary, or a (possibly retriable) transaction error.
        reply: Reply<Result<RunSummary, GraphusError>>,
    },
    /// Roll back the transaction identified by `ticket`. Idempotent: rolling back an unknown ticket
    /// is `Ok(())` so the REST inactivity sweep and an explicit `DELETE` cannot race into a spurious
    /// failure (mirrors `graphus_rest::RestEngine::rollback`).
    Rollback {
        /// The transaction to roll back.
        ticket: TxTicket,
        /// Reply channel: `Ok(())` on success or idempotent no-op, else a genuine engine fault.
        reply: Reply<Result<(), GraphusError>>,
    },
    /// Drain in-flight transactions for graceful shutdown (`04 §9.4`): roll back every still-open
    /// transaction, flush + sync the store, and reply once the store is durable and clean. After
    /// this the engine task exits its loop.
    Shutdown {
        /// Reply channel: `Ok(())` once drained + durable, else the flush/sync error.
        reply: Reply<Result<(), GraphusError>>,
    },
    /// Publish the current open-transaction count to the metrics gauge (cheap status probe). Used by
    /// the admin status endpoint and periodic observability.
    Status {
        /// Reply channel: the number of currently-open transactions.
        reply: Reply<usize>,
    },
    /// Execute an **index-DDL** statement (`CREATE/DROP INDEX`, `SHOW INDEXES`) against the
    /// coordinator's node-property index catalog (`rmp` task #91). Routed to the engine — not the
    /// async database catalog — because the index catalog lives on the single-threaded coordinator.
    /// `CREATE` starts a non-blocking background build and returns promptly; the engine loop then
    /// drives that build between commands so concurrent reads/writes are never blocked.
    IndexDdl {
        /// The index-DDL statement to execute.
        command: IndexCommand,
        /// Reply channel: the buffered fields + rows, or an engine error.
        reply: Reply<Result<IndexDdlReply, GraphusError>>,
    },
    /// Execute a **constraint-DDL** statement (`CREATE/DROP CONSTRAINT`, `SHOW CONSTRAINTS`) against
    /// the coordinator's constraint catalog (`rmp` task #99). Routed to the engine — not the async
    /// database catalog — because the constraint catalog lives on the single-threaded coordinator.
    /// Unlike index DDL, `CREATE` is **synchronous and validated**: it scans existing data and fails
    /// (without side effects) if any node violates the new constraint, otherwise it persists the
    /// declaration and the rule is enforced from then on.
    ConstraintDdl {
        /// The constraint-DDL statement to execute.
        command: ConstraintCommand,
        /// Reply channel: the buffered fields + rows (reusing [`IndexDdlReply`]), or an engine error.
        reply: Reply<Result<IndexDdlReply, GraphusError>>,
    },
    /// Capture an **online backup chain artifact** of the live store (`rmp` task #149): on the engine
    /// thread the store is borrowed mutably, quiesced (flush + checkpoint) and framed as a base full
    /// artifact plus the WAL tail — a [`graphus_storage::ChainArtifact`] encoded to bytes with the
    /// identity codec. The reply carries the **plaintext** encoded artifact; the catalog seals it
    /// (when the database is encrypted) and writes it to the operator's path. Like the DDL commands
    /// this takes no admission permit (it is a control operation the engine serialises itself), and
    /// the caller is responsible for the admin-privilege gate beforehand.
    Backup {
        /// Reply channel: the encoded plaintext `ChainArtifact` bytes, or a storage error (which also
        /// signals a corrupt source store — `backup_store` refuses to back up corruption).
        reply: Reply<Result<Vec<u8>, GraphusError>>,
    },
    /// Drive a **maintenance checkpoint** of the live store (`rmp` #305): a reader-safe GC pass (which
    /// reclaims dead versions and freezes committed MVCC stamps, lowering the WAL reclaim floor)
    /// followed by a sharp checkpoint that flushes dirty pages home and physically reclaims the WAL
    /// prefix below the floor — releasing RAM (`rmp` #313), disk (`rmp` #315) and version slots. Like
    /// the DDL/backup commands this takes no admission permit (the engine serialises it itself) and
    /// the caller is responsible for the admin-privilege gate beforehand. Driven by the over-the-wire
    /// `CHECKPOINT DATABASE` admin statement **and** the engine's background maintenance cadence.
    Checkpoint {
        /// Reply channel: a [`CheckpointReply`] summary, or a storage error from the GC pass / flush /
        /// reclaim.
        reply: Reply<Result<CheckpointReply, GraphusError>>,
    },
    /// Ingests one batch of a **network bulk-import Mode A session** (`08-network-bulk-import.md`
    /// §5.1/§7.1, `rmp` #519): creates/updates rows directly through the low-level store API
    /// (mirroring the offline `graphus-bulk` importer), committing through the coordinator's own
    /// transaction id source ([`graphus_cypher::TxnCoordinator::raw_txn`]) so it recovers identically
    /// to any other transaction. Session-local state (the external-id map, per-file token caches,
    /// cumulative stats, the durable checkpoint sentinel node) lives on the engine thread across many
    /// dispatches of this command — see `crate::engine::bulk_load`. Like the DDL/backup/checkpoint
    /// commands this takes **no admission permit**; the caller (the REST bulk-import handler) is
    /// responsible for the `Loading`-state precondition and the admin-privilege gate beforehand.
    BulkImportBatch {
        /// The batch to ingest, or the session-ending sentinel cleanup.
        batch: BulkImportBatchInput,
        /// Reply channel: the session's cumulative stats after this batch, or a storage/value-parse
        /// error (the batch's transaction is rolled back on any error — no partial batch is ever
        /// visible).
        reply: Reply<Result<BulkImportBatchOutcome, GraphusError>>,
    },
    /// Ingests one chunk of a **network bulk-import Mode B batch** (`08-network-bulk-import.md`
    /// §5.3/§7.2, `rmp` #520): loading into an already-**live** database, concurrent with ordinary
    /// traffic. Unlike [`EngineCommand::BulkImportBatch`] (Mode A's raw, no-SSI store write), every
    /// row is applied through the ordinary [`graphus_cypher::GraphAccess`] write seam
    /// (`create_node`/`create_rel`) inside the **already-open** transaction `ticket` (opened via the
    /// ordinary [`EngineCommand::Begin`]) — full SIREAD/predicate-marker registration and
    /// write-locking, so it participates in MVCC/SSI exactly like a concurrent Cypher `CREATE`. Does
    /// **not** commit: the caller (`crate::bulk_import_mode_b`'s batch driver) commits/rolls back the
    /// whole batch itself via the ordinary [`EngineCommand::Commit`]/[`EngineCommand::Rollback`].
    /// Takes **no admission permit** (mirrors [`EngineCommand::BulkImportBatch`]) — Mode B's own
    /// server-wide concurrent-session cap (`08` §8) is the resource-bounding mechanism instead.
    BulkImportModeBChunk {
        /// The already-open transaction (opened via `Begin`) this chunk's rows are applied into.
        ticket: TxTicket,
        /// The rows to ingest.
        chunk: BulkImportModeBChunkInput,
        /// Reply channel: this chunk's outcome (new external-id bindings + row-count deltas), or the
        /// captured/parse/commit-adjacent error. [`GraphusError::Transaction`] is the retriable case
        /// (a write-write lock conflict or an SSI predicate conflict registered mid-statement);
        /// every other variant is terminal (a malformed row, an unknown transaction ticket, an
        /// unknown relationship endpoint).
        reply: Reply<Result<BulkImportModeBChunkOutcome, GraphusError>>,
    },
    /// **Test-only** (`rmp` #435, opt-in `internal-test-udf`): deterministically drives this engine's
    /// **background maintenance escalation** path so the per-engine reclamation-degraded flag is set
    /// (after `K` simulated consecutive failures) or cleared (a simulated success) WITHOUT having to
    /// grow the WAL past `MAINTENANCE_CHECKPOINT_INTERVAL_BYTES`. Exercises the real
    /// `record_maintenance_failure` / [`crate::engine::MaintenanceDegraded`] code on the targeted
    /// engine only, so the multi-tenant isolation gate can prove a secondary database's stall does not
    /// touch another engine's flag. Off in production (the variant compiles away).
    #[cfg(feature = "internal-test-udf")]
    SimulateMaintenance {
        /// `true` to simulate one maintenance-checkpoint **failure** (escalating the streak), `false`
        /// to simulate a **success** (which clears this engine's flag and resets the streak).
        fail: bool,
        /// Reply channel: whether this engine is degraded **after** applying the simulated outcome.
        reply: Reply<Result<bool, GraphusError>>,
    },
}

/// The summary of a [`EngineCommand::Checkpoint`] maintenance pass — what the GC sweep reclaimed/froze,
/// surfaced to the operator (over the wire) and to observability (the background cadence logs it).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckpointReply {
    /// MVCC version slots reclaimed (returned to the free list) by the GC pass.
    pub reclaimed: usize,
    /// Committed in-flight MVCC stamps settled to their durable `Committed(ts)` form by the freeze sweep.
    pub frozen: usize,
}

/// The summary metadata for a finished result / committed transaction, unified across both seams.
///
/// Mirrors `graphus_bolt::QuerySummary` / `graphus_rest::RunSummary`; the adapters convert at their
/// boundary so the engine carries one neutral type.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunSummary {
    /// The query type code (`"r"`/`"rw"`/`"w"`/`"s"`), if known.
    pub query_type: Option<String>,
    /// Side-effect counters (e.g. `nodes-created`), in order.
    pub stats: Vec<(String, Value)>,
}

/// Builds a **schema-mutation** result summary for DDL (`rmp` #513): query type `"s"` (SCHEMA_WRITE)
/// plus, **when the DDL actually mutated the schema**, the single fired counter `key: 1` and the Neo4j
/// `contains-updates` flag — index and constraint counters both feed
/// `SummaryCounters.containsUpdates()`, mirroring how the data path appends `contains-updates` (see
/// `exec::counters_to_stats`).
///
/// An **idempotent no-op** (`mutated == false`) — a `CREATE … IF NOT EXISTS` on an existing rule, or a
/// `DROP … IF EXISTS` (or by-target drop) of a missing rule — carries the `"s"` type with **no
/// counters** (`rmp` task #626 follow-up): the driver then sees `key = 0` and
/// `containsUpdates() == false`, exactly as Neo4j reports an idempotent DDL that changed nothing. A
/// failed mutation likewise reaches this with no counters, but in practice the seam returns the engine
/// error before it ever builds a result stream, so only the success (mutated / no-op) shapes reach the
/// wire.
fn schema_mutation_summary(key: &str, mutated: bool) -> RunSummary {
    let stats = if mutated {
        vec![
            (key.to_owned(), Value::Integer(1)),
            ("contains-updates".to_owned(), Value::Boolean(true)),
        ]
    } else {
        Vec::new()
    };
    RunSummary {
        query_type: Some("s".to_owned()),
        stats,
    }
}

/// The result summary for an [`IndexCommand`] (`rmp` #513), following the Neo4j `SummaryCounters`
/// wire contract: a `CREATE … INDEX` reports query type `"s"` with `indexes-added: 1`; a `DROP …
/// INDEX` reports `indexes-removed: 1`; the read-only `SHOW … INDEXES` listings report query type
/// `"r"` with no counters. `mutated` is whether the DDL actually changed the schema — an idempotent
/// no-op (`IF NOT EXISTS` / `IF EXISTS` / a by-target drop of a missing index) reports the `0` counter
/// shape (empty counters, no `contains-updates`), matching Neo4j (see [`schema_mutation_summary`]).
///
/// Shared by both connectivity seams ([`crate::engine::BoltEngineExecutor`] /
/// [`crate::engine::RestEngineAdapter`]) so Bolt and REST spell every key identically: the wire-key
/// naming lives here in the server layer while the engine's [`IndexCommand`] stays protocol-agnostic.
#[must_use]
pub fn index_ddl_summary(command: &IndexCommand, mutated: bool) -> RunSummary {
    match command {
        IndexCommand::ShowIndexes { .. } => RunSummary {
            query_type: Some("r".to_owned()),
            stats: Vec::new(),
        },
        IndexCommand::CreateNodePropertyIndex { .. }
        | IndexCommand::CreateRelPropertyIndex { .. }
        | IndexCommand::CreateFulltextIndex { .. }
        | IndexCommand::CreatePointIndex { .. }
        | IndexCommand::CreateTextIndex { .. } => schema_mutation_summary("indexes-added", mutated),
        IndexCommand::DropNodePropertyIndex { .. }
        | IndexCommand::DropRelPropertyIndex { .. }
        | IndexCommand::DropFulltextIndex { .. }
        | IndexCommand::DropPointIndex { .. }
        | IndexCommand::DropTextIndex { .. } => schema_mutation_summary("indexes-removed", mutated),
    }
}

/// The result summary for a [`ConstraintCommand`] (`rmp` #513), following the Neo4j `SummaryCounters`
/// wire contract: a `CREATE CONSTRAINT` reports query type `"s"` with `constraints-added: 1`; a `DROP
/// CONSTRAINT` reports `constraints-removed: 1`; the read-only `SHOW CONSTRAINTS` reports query type
/// `"r"` with no counters. `mutated` is whether the DDL actually changed the schema — a `DROP
/// CONSTRAINT` of a missing constraint is an idempotent no-op that reports the `0` counter shape
/// (empty counters, no `contains-updates`), matching Neo4j (see [`schema_mutation_summary`]).
///
/// A uniqueness / node-key constraint is enforced by an implicit backing index, but — matching Neo4j,
/// whose `CREATE CONSTRAINT` result summary reports `constraintsAdded` **without** an accompanying
/// `indexesAdded` for that backing index — only `constraints-added` is reported here (`rmp` #513's
/// empirical decision). Shared by both seams for identical wire keys.
#[must_use]
pub fn constraint_ddl_summary(command: &ConstraintCommand, mutated: bool) -> RunSummary {
    match command {
        ConstraintCommand::Show { .. } => RunSummary {
            query_type: Some("r".to_owned()),
            stats: Vec::new(),
        },
        ConstraintCommand::Create(_) => schema_mutation_summary("constraints-added", mutated),
        ConstraintCommand::Drop { .. } => schema_mutation_summary("constraints-removed", mutated),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rmp` #513 GATE: an index `CREATE` reports query type `s` with `indexes-added: 1` +
    /// `contains-updates`; a `DROP` reports `indexes-removed: 1`; the full-text / point CREATE/DROP
    /// share that shape; every `SHOW … INDEXES` is a read (`r`, no counters).
    #[test]
    fn index_ddl_summary_create_drop_show() {
        let create = index_ddl_summary(
            &IndexCommand::CreateNodePropertyIndex {
                name: None,
                label: "Person".to_owned(),
                properties: vec!["name".to_owned()],
                if_not_exists: false,
            },
            true,
        );
        assert_eq!(create.query_type.as_deref(), Some("s"));
        assert_eq!(
            create.stats,
            vec![
                ("indexes-added".to_owned(), Value::Integer(1)),
                ("contains-updates".to_owned(), Value::Boolean(true)),
            ],
            "CREATE INDEX: type s, indexes-added 1, contains-updates flag last"
        );

        let drop = index_ddl_summary(
            &IndexCommand::DropNodePropertyIndex {
                index: NodePropertyIndexRef::Named("ix".to_owned()),
                if_exists: false,
            },
            true,
        );
        assert_eq!(drop.query_type.as_deref(), Some("s"));
        assert_eq!(
            drop.stats[0],
            ("indexes-removed".to_owned(), Value::Integer(1))
        );

        // Full-text and point CREATE/DROP follow the same indexes-added/removed shape.
        assert_eq!(
            index_ddl_summary(
                &IndexCommand::CreateFulltextIndex {
                    name: "ft".to_owned(),
                    entity: graphus_cypher::FulltextEntity::Node,
                    labels_or_types: vec!["Doc".to_owned()],
                    properties: vec!["body".to_owned()],
                    analyzer: "standard".to_owned(),
                    if_not_exists: false,
                },
                true,
            )
            .stats[0],
            ("indexes-added".to_owned(), Value::Integer(1)),
        );
        assert_eq!(
            index_ddl_summary(
                &IndexCommand::DropPointIndex {
                    name: "p".to_owned(),
                    if_exists: false,
                },
                true
            )
            .stats[0],
            ("indexes-removed".to_owned(), Value::Integer(1)),
        );

        // Every `SHOW … INDEXES` filtered form is now the one unified `ShowIndexes` (`rmp` #660).
        for filter in [
            IndexTypeFilter::All,
            IndexTypeFilter::Range,
            IndexTypeFilter::Fulltext,
            IndexTypeFilter::Point,
            IndexTypeFilter::Lookup,
        ] {
            let show = IndexCommand::ShowIndexes { filter, tail: None };
            let s = index_ddl_summary(&show, true);
            assert_eq!(s.query_type.as_deref(), Some("r"), "{show:?} is a read");
            assert!(s.stats.is_empty(), "a SHOW reports no counters: {show:?}");
        }
    }

    /// `rmp` #626 follow-up: an **idempotent no-op** DDL (`mutated == false`) keeps the `s` type but
    /// reports **no counters** — so a `CREATE … IF NOT EXISTS` on an existing index and a `DROP …
    /// IF EXISTS` of a missing one surface `indexes-added`/`indexes-removed` of `0` and no
    /// `contains-updates`, matching Neo4j. (A genuine failure reaches the same shape, but the seam
    /// returns the engine error before building a stream, so only the mutated / no-op shapes are wired.)
    #[test]
    fn index_ddl_summary_noop_has_no_counters() {
        let create_noop = index_ddl_summary(
            &IndexCommand::CreateNodePropertyIndex {
                name: None,
                label: "Person".to_owned(),
                properties: vec!["name".to_owned()],
                if_not_exists: true,
            },
            false, // mutated == false: an IF NOT EXISTS that changed nothing.
        );
        assert_eq!(create_noop.query_type.as_deref(), Some("s"));
        assert!(
            create_noop.stats.is_empty(),
            "a no-op CREATE reports 0 (empty counters, no contains-updates): {:?}",
            create_noop.stats
        );

        let drop_noop = index_ddl_summary(
            &IndexCommand::DropNodePropertyIndex {
                index: NodePropertyIndexRef::Named("missing".to_owned()),
                if_exists: true,
            },
            false, // mutated == false: an IF EXISTS drop of a missing index.
        );
        assert_eq!(drop_noop.query_type.as_deref(), Some("s"));
        assert!(drop_noop.stats.is_empty(), "a no-op DROP reports 0");
    }

    /// `rmp` #513 GATE: a constraint `CREATE` reports query type `s` with `constraints-added: 1` +
    /// `contains-updates` (and **no** `indexes-added` for the implicit backing index, matching Neo4j);
    /// a `DROP` reports `constraints-removed: 1`; `SHOW CONSTRAINTS` is a read (`r`, no counters).
    #[test]
    fn constraint_ddl_summary_create_drop_show() {
        let create = constraint_ddl_summary(
            &ConstraintCommand::Create(CreateConstraint {
                name: "u".to_owned(),
                entity: ConstraintEntity::Node {
                    label: "Person".to_owned(),
                },
                properties: vec!["email".to_owned()],
                kind: ConstraintCreateKind::Unique,
                if_not_exists: false,
                or_replace: false,
            }),
            true,
        );
        assert_eq!(create.query_type.as_deref(), Some("s"));
        assert_eq!(
            create.stats,
            vec![
                ("constraints-added".to_owned(), Value::Integer(1)),
                ("contains-updates".to_owned(), Value::Boolean(true)),
            ]
        );
        assert!(
            !create.stats.iter().any(|(k, _)| k == "indexes-added"),
            "a uniqueness constraint reports constraints-added only, not a backing-index counter"
        );

        let drop = constraint_ddl_summary(
            &ConstraintCommand::Drop {
                name: "u".to_owned(),
                if_exists: false,
            },
            true,
        );
        assert_eq!(drop.query_type.as_deref(), Some("s"));
        assert_eq!(
            drop.stats[0],
            ("constraints-removed".to_owned(), Value::Integer(1))
        );

        let show = constraint_ddl_summary(
            &ConstraintCommand::Show {
                filter: ConstraintTypeFilter::All,
                tail: None,
            },
            true,
        );
        assert_eq!(show.query_type.as_deref(), Some("r"));
        assert!(show.stats.is_empty());
    }
}
