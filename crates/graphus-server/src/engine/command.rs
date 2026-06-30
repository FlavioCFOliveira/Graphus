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
//! Reads serialize through the engine too in v1; lock-free concurrent reads against committed
//! versions are the documented follow-up (`04 §9.1`).

use graphus_core::{GraphusError, Value};

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

/// An **index-DDL** statement routed to the engine thread (`rmp` task #91), where the
/// node-property index catalog lives (on the single-threaded coordinator). Unlike the DATABASE
/// admin commands — which act on the off-engine async [`crate::dbcatalog::DatabaseCatalog`] — index
/// DDL must reach the [`graphus_cypher::TxnCoordinator`], so it travels as its own engine command.
///
/// The names are validated/normalized by the admin matcher before this is built; the engine looks
/// them up / interns them through the coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexCommand {
    /// `CREATE INDEX …` on `(label, property)`: starts a **non-blocking** build (the index is
    /// `Populating` and built in the background; the command returns promptly).
    CreateNodePropertyIndex {
        /// The node label the index is declared on.
        label: String,
        /// The property key the index is declared on.
        property: String,
    },
    /// `DROP INDEX …` on `(label, property)`: removes the index (durable + in-memory), cancelling
    /// any in-progress build.
    DropNodePropertyIndex {
        /// The node label of the index to drop.
        label: String,
        /// The property key of the index to drop.
        property: String,
    },
    /// `SHOW INDEXES`: lists every declared node-property index with its build state.
    ShowIndexes,
    /// `CREATE FULLTEXT INDEX <name> FOR (n:<Label>) ON EACH [n.<prop>, …]` (`rmp` task #72): starts
    /// a **non-blocking** online build of a full-text index over `(label, properties)` analyzed with
    /// `analyzer` (a lower-cased analyzer name; `standard` by default).
    CreateFulltextIndex {
        /// The server-unique index name.
        name: String,
        /// The node label the index covers.
        label: String,
        /// The property keys the index covers, in declared order (one or more).
        properties: Vec<String>,
        /// The analyzer name (`standard` / `keyword`); validated by the engine against the supported
        /// set so an unknown analyzer is a clear error.
        analyzer: String,
    },
    /// `DROP INDEX <name>` of a full-text index (`rmp` task #72): removes it (durable + in-memory),
    /// cancelling any in-progress build.
    DropFulltextIndex {
        /// The full-text index name to drop.
        name: String,
    },
    /// `SHOW FULLTEXT INDEXES` (`rmp` task #72): lists every declared full-text index.
    ShowFulltextIndexes,
    /// `CREATE POINT INDEX <name> FOR (n:<Label>) ON (n.<prop>)` (`rmp` task #98): starts a
    /// **non-blocking** online build of a grid spatial (point) index over `(label, property)`.
    CreatePointIndex {
        /// The server-unique index name.
        name: String,
        /// The node label the index covers.
        label: String,
        /// The point property the index covers (exactly one).
        property: String,
    },
    /// `DROP POINT INDEX <name>` (`rmp` task #98): removes the spatial index (durable + in-memory),
    /// cancelling any in-progress build.
    DropPointIndex {
        /// The spatial index name to drop.
        name: String,
    },
    /// `SHOW POINT INDEXES` (`rmp` task #98): lists every declared spatial index.
    ShowPointIndexes,
}

/// A **constraint-DDL** statement routed to the engine thread (`rmp` task #99), where the constraint
/// catalog lives (on the single-threaded coordinator). Like [`IndexCommand`] — and unlike the
/// DATABASE admin commands, which act on the off-engine async catalog — constraint DDL must reach the
/// [`graphus_cypher::TxnCoordinator`], so it travels as its own engine command.
///
/// The name/label/property are validated/normalized by the admin matcher before this is built; the
/// engine looks them up / interns them through the coordinator. Unlike an index, a constraint
/// `CREATE` is **synchronous and validated** (it scans existing data and may fail) — there is no
/// non-blocking build phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintCommand {
    /// `CREATE CONSTRAINT <name> FOR (n:<Label>) REQUIRE n.<prop> IS UNIQUE` (`rmp` task #99):
    /// declares a **uniqueness** constraint after validating existing data conforms.
    CreateUnique {
        /// The server-unique constraint name.
        name: String,
        /// The node label the constraint covers.
        label: String,
        /// The property the constraint covers (exactly one in v1).
        property: String,
    },
    /// `CREATE CONSTRAINT <name> FOR (n:<Label>) REQUIRE n.<prop> IS NOT NULL` (`rmp` task #99):
    /// declares an **existence** (`NOT NULL`) constraint after validating existing data conforms.
    CreateExistence {
        /// The server-unique constraint name.
        name: String,
        /// The node label the constraint covers.
        label: String,
        /// The property the constraint covers (exactly one).
        property: String,
    },
    /// `CREATE CONSTRAINT <name> FOR (n:<Label>) REQUIRE (n.a, n.b, …) IS NODE KEY` (`rmp` task #100):
    /// declares a **node-key** constraint over a composite property tuple (present + unique) after
    /// validating existing data conforms.
    CreateNodeKey {
        /// The server-unique constraint name.
        name: String,
        /// The node label the constraint covers.
        label: String,
        /// The properties forming the key, in declared order (one or more).
        properties: Vec<String>,
    },
    /// `CREATE CONSTRAINT <name> FOR (n:<Label>) REQUIRE n.<prop> IS :: <TYPE>` (`rmp` task #100):
    /// declares a **property-type** constraint requiring the covered property — when present — to hold
    /// a value of `declared_type`, after validating existing data conforms.
    CreatePropertyType {
        /// The server-unique constraint name.
        name: String,
        /// The node label the constraint covers.
        label: String,
        /// The property the constraint covers (exactly one).
        property: String,
        /// The declared value type the property must match.
        declared_type: graphus_storage::ConstraintTypeDescriptor,
    },
    /// `DROP CONSTRAINT <name>` (`rmp` task #99): removes the constraint (durable + in-memory), so the
    /// write path stops enforcing it.
    Drop {
        /// The constraint name to drop.
        name: String,
    },
    /// `SHOW CONSTRAINTS` (`rmp` task #99): lists every declared constraint.
    Show,
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
/// plus, on success, the single fired counter `key: 1` and the Neo4j `contains-updates` flag — index
/// and constraint counters both feed `SummaryCounters.containsUpdates()`, mirroring how the data path
/// appends `contains-updates` (see `exec::counters_to_stats`). A failed mutation (`ok == false`)
/// carries the `"s"` type with no counters; in practice the seam returns the engine error before it
/// ever builds a result stream, so only the success shape reaches the wire.
fn schema_mutation_summary(key: &str, ok: bool) -> RunSummary {
    let stats = if ok {
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
/// `"r"` with no counters. `ok` is whether the DDL succeeded (a failure carries no counters — see
/// [`schema_mutation_summary`]).
///
/// Shared by both connectivity seams ([`crate::engine::BoltEngineExecutor`] /
/// [`crate::engine::RestEngineAdapter`]) so Bolt and REST spell every key identically: the wire-key
/// naming lives here in the server layer while the engine's [`IndexCommand`] stays protocol-agnostic.
#[must_use]
pub fn index_ddl_summary(command: &IndexCommand, ok: bool) -> RunSummary {
    match command {
        IndexCommand::ShowIndexes
        | IndexCommand::ShowFulltextIndexes
        | IndexCommand::ShowPointIndexes => RunSummary {
            query_type: Some("r".to_owned()),
            stats: Vec::new(),
        },
        IndexCommand::CreateNodePropertyIndex { .. }
        | IndexCommand::CreateFulltextIndex { .. }
        | IndexCommand::CreatePointIndex { .. } => schema_mutation_summary("indexes-added", ok),
        IndexCommand::DropNodePropertyIndex { .. }
        | IndexCommand::DropFulltextIndex { .. }
        | IndexCommand::DropPointIndex { .. } => schema_mutation_summary("indexes-removed", ok),
    }
}

/// The result summary for a [`ConstraintCommand`] (`rmp` #513), following the Neo4j `SummaryCounters`
/// wire contract: a `CREATE CONSTRAINT` reports query type `"s"` with `constraints-added: 1`; a `DROP
/// CONSTRAINT` reports `constraints-removed: 1`; the read-only `SHOW CONSTRAINTS` reports query type
/// `"r"` with no counters. `ok` is whether the DDL succeeded (see [`schema_mutation_summary`]).
///
/// A uniqueness / node-key constraint is enforced by an implicit backing index, but — matching Neo4j,
/// whose `CREATE CONSTRAINT` result summary reports `constraintsAdded` **without** an accompanying
/// `indexesAdded` for that backing index — only `constraints-added` is reported here (`rmp` #513's
/// empirical decision). Shared by both seams for identical wire keys.
#[must_use]
pub fn constraint_ddl_summary(command: &ConstraintCommand, ok: bool) -> RunSummary {
    match command {
        ConstraintCommand::Show => RunSummary {
            query_type: Some("r".to_owned()),
            stats: Vec::new(),
        },
        ConstraintCommand::CreateUnique { .. }
        | ConstraintCommand::CreateExistence { .. }
        | ConstraintCommand::CreateNodeKey { .. }
        | ConstraintCommand::CreatePropertyType { .. } => {
            schema_mutation_summary("constraints-added", ok)
        }
        ConstraintCommand::Drop { .. } => schema_mutation_summary("constraints-removed", ok),
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
                label: "Person".to_owned(),
                property: "name".to_owned(),
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
                label: "Person".to_owned(),
                property: "name".to_owned(),
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
                    label: "Doc".to_owned(),
                    properties: vec!["body".to_owned()],
                    analyzer: "standard".to_owned(),
                },
                true,
            )
            .stats[0],
            ("indexes-added".to_owned(), Value::Integer(1)),
        );
        assert_eq!(
            index_ddl_summary(
                &IndexCommand::DropPointIndex {
                    name: "p".to_owned()
                },
                true
            )
            .stats[0],
            ("indexes-removed".to_owned(), Value::Integer(1)),
        );

        for show in [
            IndexCommand::ShowIndexes,
            IndexCommand::ShowFulltextIndexes,
            IndexCommand::ShowPointIndexes,
        ] {
            let s = index_ddl_summary(&show, true);
            assert_eq!(s.query_type.as_deref(), Some("r"), "{show:?} is a read");
            assert!(s.stats.is_empty(), "a SHOW reports no counters: {show:?}");
        }
    }

    /// `rmp` #513: a failed schema mutation keeps the `s` type but reports no counters (in practice the
    /// seam returns the engine error before building a stream, so only the success shape is wired).
    #[test]
    fn index_ddl_summary_failure_has_no_counters() {
        let s = index_ddl_summary(
            &IndexCommand::CreateNodePropertyIndex {
                label: "Person".to_owned(),
                property: "name".to_owned(),
            },
            false,
        );
        assert_eq!(s.query_type.as_deref(), Some("s"));
        assert!(s.stats.is_empty());
    }

    /// `rmp` #513 GATE: a constraint `CREATE` reports query type `s` with `constraints-added: 1` +
    /// `contains-updates` (and **no** `indexes-added` for the implicit backing index, matching Neo4j);
    /// a `DROP` reports `constraints-removed: 1`; `SHOW CONSTRAINTS` is a read (`r`, no counters).
    #[test]
    fn constraint_ddl_summary_create_drop_show() {
        let create = constraint_ddl_summary(
            &ConstraintCommand::CreateUnique {
                name: "u".to_owned(),
                label: "Person".to_owned(),
                property: "email".to_owned(),
            },
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
            },
            true,
        );
        assert_eq!(drop.query_type.as_deref(), Some("s"));
        assert_eq!(
            drop.stats[0],
            ("constraints-removed".to_owned(), Value::Integer(1))
        );

        let show = constraint_ddl_summary(&ConstraintCommand::Show, true);
        assert_eq!(show.query_type.as_deref(), Some("r"));
        assert!(show.stats.is_empty());
    }
}
