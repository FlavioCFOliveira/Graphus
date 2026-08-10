//! Per-`Run` execution on the engine thread: compile → bind → execute the Cypher pipeline against a
//! coordinator statement seam, stream rows over the bounded egress channel, and (for auto-commit)
//! commit when the stream is drained (`04-technical-design.md` §1.3 request lifecycle, §7.1 pipeline,
//! §7.7 streaming).
//!
//! All of this runs on the **single engine thread** (see [`super`]), so it may block freely (storage
//! I/O, the WAL group-commit `fdatasync`) without touching a Tokio runtime worker (`04 §9.1`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_core::error::GraphusError;
use graphus_cypher::extension::ExtensionRegistry;
use graphus_cypher::function_registry::{Arity, FunctionFailure};
use graphus_cypher::procedure_registry::{FieldSpec, FieldType, ProcedureFailure, ValueClass};
use graphus_cypher::{
    AuthorizedGraph, FeatureFlags, GraphAccess, IndexCatalog, Parameters, PhysicalPlan, PlanCache,
    PlanCacheKey, PlanDescription, PrivilegeOracle, ProcedureSignature, ProfileRecorder,
    SchemaVersion, Statistics, TxnCoordinator, analyze_with_extensions, bind_parameters,
    execute_with_extensions_cancellable, lower, parse_tokens, plan_physical_hinted, tokenize,
};
use graphus_io::BlockDevice;
use graphus_wal::LogSink;

use super::command::{AccessMode, QueryPlan, Reply};
use super::latch::EngineLatch;
use super::privileges::EffectivePrivileges;
use super::read_pool::{ReadDispatch, ReadTask};
use super::stream::{RowReceiver, RowSender, SummarySink};
use super::{OpenTxTable, RunReply, RunSummary, TxTicket};
use crate::metrics::Metrics;

/// The default capacity of the engine's compiled-plan cache (`rmp` task #322). A few hundred distinct
/// query texts comfortably covers the working set of a typical application (its handful of statement
/// templates) while bounding the memory a pathological churn of unique queries can pin; the LRU evicts
/// the least-recently-used plan past this.
const PLAN_CACHE_CAPACITY: usize = 512;

/// The engine's per-thread compiled-plan cache plus the **schema version** the cache is keyed against
/// (`rmp` task #322; `04 §7.5`).
///
/// The server's RUN path used to re-run the *entire* compile pipeline
/// (tokenize→parse→analyze→lower→physical-plan) on **every** `Run` — a measured ~2.4–8.6 µs of pure CPU
/// per statement that a looped concurrency workload pays on every iteration. This cache reuses the
/// compiled [`PhysicalPlan`] for an identical query text, turning a repeated `Run` into a ~50 ns hash
/// lookup + an `Arc::clone` (an atomic refcount bump) of the shared plan.
///
/// **Shared plans (`rmp` task #531).** The cache value is an `Arc<PhysicalPlan>`, not an owned plan, so
/// a cache hit hands out an `Arc::clone` (a few nanoseconds) instead of the ~0.2–0.7 µs deep clone of
/// the operator tree the engine used to pay per statement. The same shared `Arc` is threaded all the
/// way into [`graphus_cypher::execute_with_extensions_cancellable`], so the executor no longer deep
/// clones the plan into itself either — a cache-hit statement performs **zero** deep plan clones on the
/// engine thread. The `Arc<PhysicalPlan>` is `Send + Sync` (the plan is pure data), so the off-thread
/// reader (`rmp` #336/#527) still receives a correct `Send` plan.
///
/// **Keying & correctness.** The key is the **verbatim query text** paired with the current
/// [`SchemaVersion`] (and an empty [`FeatureFlags`] set — the engine compiles one feature line).
/// Exact-text keying makes reuse trivially sound: identical text compiled under the same schema
/// yields an identical plan, and any literal difference changes the text (so it never reuses a plan
/// compiled for a different literal). Auto-parameterised normalisation (collapsing literal-only
/// variants onto one plan, `plan_cache::normalize_query`) is deliberately **not** used here — it would
/// need an AST-level literal→parameter rewrite the planner consumes, a larger and higher-risk change
/// promoted as its own task.
///
/// **Invalidation.** [`bump_schema`](Self::bump_schema) advances the [`SchemaVersion`], which is part
/// of every key, so all previously-cached plans become unreachable in one step (with eager eviction
/// of the now-dead entries). The engine bumps it whenever the planner-visible catalog changes: any
/// mutating index/constraint DDL, and the asynchronous promotion of an online index build
/// (`Populating`→`Online`, which is when [`TxnCoordinator::catalog`] starts exposing the new index).
///
/// **Statistics freshness.** A cached plan was cost-optimised against the statistics at its
/// compilation; reusing it under newer statistics is acceptable because every cost-based rewrite is
/// bag-preserving (`04 §7.5`) — statistics steer *which* equivalent plan is chosen, never the rows it
/// produces. A schema change (the thing that *can* change results, e.g. a new unique constraint or a
/// usable index) bumps the version and invalidates.
///
/// This lives on the **single engine thread** and is borrowed `&mut` per `Run`, so the underlying
/// [`PlanCache`]'s documented single-threaded contract holds with no synchronisation.
pub(super) struct EnginePlanCache {
    cache: PlanCache<Arc<PhysicalPlan>>,
    schema_version: SchemaVersion,
    feature_flags: FeatureFlags,
}

impl EnginePlanCache {
    /// Creates the engine's plan cache at the default capacity, keyed against the initial schema.
    pub(super) fn new() -> Self {
        Self {
            cache: PlanCache::new(PLAN_CACHE_CAPACITY),
            schema_version: SchemaVersion::INITIAL,
            feature_flags: FeatureFlags::empty(),
        }
    }

    /// Advances the schema version, invalidating every cached plan (their keys all change) and eagerly
    /// reclaiming the now-dead entries. Called when the planner-visible catalog changes (DDL / online
    /// index promotion).
    pub(super) fn bump_schema(&mut self) {
        self.schema_version = self.schema_version.next();
        self.cache.invalidate_schema_change(self.schema_version);
    }

    /// Builds the exact-text key for `query` under the current schema/flags.
    fn key(&self, query: &str) -> PlanCacheKey {
        PlanCacheKey {
            normalized_query_text: query.to_owned(),
            schema_version: self.schema_version,
            feature_flags: self.feature_flags.clone(),
        }
    }

    /// Cumulative cache statistics (observability / tests).
    pub(super) fn stats(&self) -> graphus_cypher::CacheStats {
        self.cache.stats()
    }
}

/// Builds the engine's [`ExtensionRegistry`] — the **v1 compiled-in registration hook** for
/// user-defined functions/procedures (`rmp` task #75).
///
/// This is the single place a deployment adds its own UDFs/UDPs: register them here (a safe Rust
/// API, type-checked at registration, no dynamic code loading — see the
/// [`graphus_cypher::extension`] module docs for why dynamic native loading is out of scope and WASM
/// is the recommended future direction). The registry is built **once per engine**, on the engine
/// thread, and lives for the engine's lifetime; the engine handles commands serially, so it is
/// borrowed immutably for the duration of each `Run`.
///
/// The registry ships two sample extensions so the feature is reachable and testable end-to-end:
///
/// - `ext.double(n)` — a scalar UDF returning `2 * n` (integer or float; `null` passes through; a
///   non-number is a runtime [`FunctionFailure`]).
/// - `ext.range(a, b) YIELD value` — a UDP yielding the inclusive integer range `a..=b` as one
///   `value` column per row.
///
/// [`FunctionFailure`]: graphus_cypher::function_registry::FunctionFailure
pub(super) fn install_extensions() -> ExtensionRegistry {
    let mut reg = ExtensionRegistry::new();
    register_builtin_extensions(&mut reg);
    register_gds(&mut reg);
    reg
}

/// Registers the Graph Data Science (`gds.*`) procedure surface into `reg` (`rmp` task #133).
///
/// The `gds.*` procedures (graph projection lifecycle + the streaming algorithms) share **one**
/// named-graph catalog, built here and captured by every procedure closure. The catalog lives for the
/// engine's lifetime (the registry is built once per engine), so a `gds.graph.project(...)` in one
/// statement is visible to a `gds.pageRank.stream(...)` in the next, exactly as Neo4j's GDS catalog
/// behaves. Each projection is taken under the calling statement's MVCC-consistent, RBAC-filtered
/// `GraphAccess` seam, so it is a consistent committed snapshot of the live store.
fn register_gds(reg: &mut ExtensionRegistry) {
    let catalog = graphus_cypher::new_gds_catalog();
    // `register_gds_procedures` registers into a `ProcedureSet`; the `ExtensionRegistry` exposes its
    // procedure registration through `register_procedure`, so we route through the registry's own set
    // by registering each procedure there. The shared catalog handle is cloned into every closure.
    reg.register_gds_procedures(catalog);
}

/// Registers the engine's compiled-in sample extensions into `reg` (`rmp` task #75). Split from
/// [`install_extensions`] so a future deployment build can call it on its own registry, or extend it
/// with its own registrations, in one obvious place.
fn register_builtin_extensions(reg: &mut ExtensionRegistry) {
    // Scalar UDF: `ext.double(n)`.
    reg.register_function(
        "ext.double",
        Arity::Exact(1),
        false,
        Box::new(|args: &[Value]| match args.first() {
            Some(Value::Integer(i)) => Ok(Value::Integer(i.wrapping_mul(2))),
            Some(Value::Float(f)) => Ok(Value::Float(f * 2.0)),
            Some(Value::Null) | None => Ok(Value::Null),
            Some(other) => Err(FunctionFailure::new(
                "ext.double",
                format!("expected a number, got {other:?}"),
            )),
        }),
    )
    // An INVARIANT: `ext.double` is a fixed name registered once into a fresh registry, so it can
    // never collide. A failure here is a programming error in this hook, surfaced loudly.
    .expect("INVARIANT: sample UDF `ext.double` registers into a fresh registry");

    // UDP: `ext.range(a, b) YIELD value` — yields the inclusive integer range as rows.
    reg.register_procedure(
        ProcedureSignature::new(
            "ext.range",
            vec![
                FieldSpec::new(
                    "a",
                    FieldType {
                        class: ValueClass::Integer,
                        nullable: false,
                    },
                ),
                FieldSpec::new(
                    "b",
                    FieldType {
                        class: ValueClass::Integer,
                        nullable: false,
                    },
                ),
            ],
            vec![FieldSpec::new(
                "value",
                FieldType {
                    class: ValueClass::Integer,
                    nullable: false,
                },
            )],
        ),
        Box::new(|args: &[Value], _graph: &mut dyn GraphAccess| {
            let (Some(Value::Integer(a)), Some(Value::Integer(b))) = (args.first(), args.get(1))
            else {
                return Err(ProcedureFailure::new(
                    "ext.range",
                    "expected two integer arguments",
                ));
            };
            Ok((*a..=*b).map(|n| vec![Value::Integer(n)]).collect())
        }),
    );

    // Test-only scalar UDF: `ext.panic(n)` **panics** when `n` is non-null (returns `n` unchanged when
    // null). Compiled in only under the opt-in `internal-test-udf` feature (OFF in production), it is
    // the deliberately-panicking statement the `rmp` #386 regression gates drive through the real
    // engine — a panic reachable on the production execution path (compile → bind → execute), proving
    // the engine's per-statement panic boundary converts it to a clean statement error and survives.
    // Used per-row inside a morsel-eligible aggregate to also prove a `rayon`-propagated worker panic
    // is caught by the same engine boundary. (A Cargo *feature*, not `cfg(test)`, because integration
    // tests link the non-test build of this lib, where `cfg(test)` is inactive.)
    #[cfg(feature = "internal-test-udf")]
    reg.register_function(
        "ext.panic",
        Arity::Exact(1),
        false,
        Box::new(|args: &[Value]| match args.first() {
            Some(Value::Null) | None => Ok(Value::Null),
            Some(_) => panic!("ext.panic: deliberate test panic (rmp #386)"),
        }),
    )
    .expect("INVARIANT: test UDF `ext.panic` registers into a fresh registry");

    // Test-only dispatch oracle (`rmp` task #546): `ext.readerPoolWorker() YIELD onPool` yields a
    // single Boolean row = whether the procedure BODY is executing on an off-thread reader-pool worker
    // ([`graphus_cypher::morsel::is_reader_pool_worker`], the thread-local a `ReaderPoolWorkerGuard`
    // sets). Registered **reader-safe**, so a `CALL ext.readerPoolWorker()` auto-commit read is
    // dispatched to the reader pool and yields `true`; the same call in an explicit transaction (or via
    // the inline DST driver) runs on the engine thread and yields `false`. The `…Inline` sibling is
    // registered **not** reader-safe, so it stays inline even in an auto-commit read (yielding
    // `false`) — the deterministic negative gate for the reader-safe classification. Gated on the
    // opt-in `internal-test-udf` feature (OFF in production) exactly like `ext.panic`.
    #[cfg(feature = "internal-test-udf")]
    {
        fn reader_pool_probe_signature(name: &str) -> ProcedureSignature {
            ProcedureSignature::new(
                name,
                Vec::new(),
                vec![FieldSpec::new(
                    "onPool",
                    FieldType {
                        class: ValueClass::Boolean,
                        nullable: false,
                    },
                )],
            )
        }
        reg.register_procedure_reader_safe(
            reader_pool_probe_signature("ext.readerPoolWorker"),
            Box::new(|_args: &[Value], _graph: &mut dyn GraphAccess| {
                Ok(vec![vec![Value::Boolean(
                    graphus_cypher::morsel::is_reader_pool_worker(),
                )]])
            }),
        );
        reg.register_procedure(
            reader_pool_probe_signature("ext.readerPoolWorkerInline"),
            Box::new(|_args: &[Value], _graph: &mut dyn GraphAccess| {
                Ok(vec![vec![Value::Boolean(
                    graphus_cypher::morsel::is_reader_pool_worker(),
                )]])
            }),
        );
    }
}

/// Combines the operator's configured per-statement timeout with a caller-supplied one, **clamping
/// downward only** (`rmp` #909).
///
/// `configured` is [`crate::config::TimingConfig::statement_timeout`] (`None` = the operator disabled
/// the per-statement budget). `client` is the budget the caller asked for — on Bolt, the normalised
/// `tx_timeout` of `BEGIN` / an auto-commit `RUN` (`None` = the client asked for no bound of its own).
///
/// The result is the **smaller** of whichever are present:
///
/// | configured | client | effective | meaning |
/// |---|---|---|---|
/// | `None` | `None` | `None` | unbounded, as before |
/// | `Some(s)` | `None` | `Some(s)` | the operator's bound, as before |
/// | `None` | `Some(c)` | `Some(c)` | the client self-limits where the operator set no bound |
/// | `Some(s)` | `Some(c)` | `Some(min(s, c))` | the client may tighten, never relax |
///
/// The last row is the security-relevant one: a client asking for **more** time than the operator
/// allows gets the operator's bound, so `tx_timeout` can never be used to escape the CPU-exhaustion
/// defence (`rmp` #476) it rides on. This mirrors the Neo4j 4.2–5.2 contract the official drivers
/// document for the same field ("values higher than the server's configured transaction timeout are
/// ignored and fall back to the default"); Graphus applies the rule at every version rather than
/// letting a client raise its ceiling.
///
/// A client asking for *no* bound (`tx_timeout: 0`, which Neo4j documents as "transaction does not
/// have a timeout") reaches here as `None`, so it likewise cannot lift the operator's bound.
pub(super) fn effective_statement_timeout(
    configured: Option<Duration>,
    client: Option<Duration>,
) -> Option<Duration> {
    match (configured, client) {
        (Some(configured), Some(client)) => Some(configured.min(client)),
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    }
}

/// Handles a [`super::EngineCommand::Run`]: resolves the transaction, compiles + binds the query,
/// then streams its rows.
///
/// Sends the [`RunReply`] (fields + the row receiver) over `reply` **before** streaming any row, so
/// the consumer can start draining the bounded egress channel concurrently (otherwise the engine
/// thread would block on a full channel with no consumer). A compile/bind/transaction error that
/// occurs before the first row is delivered through `reply` as an `Err` instead.
#[allow(clippy::too_many_arguments)] // The engine loop threads all execution context through here.
pub(super) fn handle_run<
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
>(
    coordinator: &TxnCoordinator<D, S>,
    // The LATCHES, never guards (`rmp` #1038): each is taken where it is used and released before the
    // next thing happens. See the acquisition sites below for what "where it is used" means here —
    // three `O(1)` table operations and two cache operations, in a function that runs a whole query.
    open: &EngineLatch<OpenTxTable>,
    plan_cache: &EngineLatch<EnginePlanCache>,
    ticket: TxTicket,
    query: &str,
    params: Vec<(String, graphus_core::Value)>,
    auto_commit: bool,
    privileges: Option<EffectivePrivileges>,
    extensions: &Arc<ExtensionRegistry>,
    dispatch: &ReadDispatch<D, S>,
    // How many off-thread reads are already in flight on the engine (`rmp` task #575-g.1). Read-only, a
    // snapshot taken on the engine thread just before this statement: the dispatch site derives this read's
    // **adaptive morsel width** from it (`floor(analytics_pool_threads / (readers_inflight + 1))`) so a
    // lone heavy read fans out across the whole analytics pool while `K` concurrent reads share it without
    // over-subscription. Unused on every non-dispatch path.
    readers_inflight: u64,
    result_buffer_capacity: usize,
    metrics: &Arc<Metrics>,
    db: &str,
    // `rmp` #955: a commit that fails at the STORE level leaves its transaction open, and this path has
    // already surrendered the ticket — so the auto-commit finaliser rolls it back, and flags the engine
    // degraded if that rollback is itself left incomplete.
    degraded: &super::EngineDegraded,
    clock: &Arc<dyn Clock + Send + Sync>,
    statement_timeout: Option<Duration>,
    // The caller's own budget for THIS statement (`rmp` #909): the Bolt `tx_timeout` a client set on its
    // `BEGIN` / auto-commit `RUN`, already normalised and — for a statement inside an explicit
    // transaction — already reduced to the transaction's *remaining* budget by the connection seam.
    // Combined with `statement_timeout` by [`effective_statement_timeout`], which takes the smaller.
    client_timeout: Option<Duration>,
    // Group commit (`rmp` #566): when this statement finishes within its visit as a durable auto-commit
    // WRITE, [`finalize_inflight`] PREPAREs it and defers its ack into this batch (a clone of its egress
    // sender held open until the batch harden), instead of an inline `fdatasync` per statement — so
    // concurrent auto-commit writers coalesce onto one sync. Unused on the off-thread-read / early-error
    // paths (which never commit here); the DST `LocalEngine` passes a batch it hardens inline (batch-of-one).
    commit_batch: &mut Vec<super::PendingCommit>,
    reply: Reply<Result<RunReply, GraphusError>>,
) -> RunOutcome {
    // The per-statement wall-clock **deadline** (`rmp` #476): the start of this statement's CPU budget.
    // Captured up front so it covers compile + bind + execute (all of which run on this engine thread),
    // and on the **monotonic** `Instant` clock so an NTP step cannot perturb it. `None` (the
    // statement-timeout-disabled config, and the deterministic `LocalEngine`, which never sets a timeout)
    // leaves the executor wall-clock-free — byte-identical to before. Carried into both the inline cursor
    // and the off-thread reader's `ReadTask`, and it survives suspend/resume (the token lives on the
    // cursor), so the same budget governs every batch of the statement.
    //
    // `rmp` #909: the budget is the *smaller* of the operator's configured timeout and the client's own
    // (`tx_timeout`) — see [`effective_statement_timeout`].
    //
    // `checked_add`, never `+`: `Instant + Duration` PANICS on overflow, and the client half of that sum
    // is attacker-chosen (a `tx_timeout` of `i64::MAX` milliseconds is ~292 million years, and whether
    // that overflows depends on the platform's `Instant` representation). An absurd budget degrades to
    // "no deadline", which is safe — it is exactly the operator's own `statement_timeout_ms = 0`
    // behaviour, so no ceiling is raised — instead of a panic on the engine thread.
    let deadline: Option<Instant> = effective_statement_timeout(statement_timeout, client_timeout)
        .and_then(|d| Instant::now().checked_add(d));

    // Resolve the open transaction. Both fields are `Copy`, so the whole of what execution needs from
    // the table is two words, lifted out here and the latch released — the shape the struct docs on
    // `EngineShared` always claimed and, until `rmp` #1038, only the *borrow* obeyed while the *guard*
    // stayed alive for the entire query. The failed lookup and its diagnosis share the critical
    // section: `unknown_ticket_error` consumes the reap record, so reading it must be part of the same
    // step that observed the ticket missing.
    let resolved = {
        let mut open = open.lock();
        match open.get(&ticket.0).map(|tx| (tx.txn, tx.mode)) {
            Some(found) => Ok(found),
            None => Err(open.unknown_ticket_error(ticket.0, "RUN in transaction")),
        }
    };
    let (txn, mode) = match resolved {
        Ok(found) => found,
        // A permanent, NON-retryable client fault (`rmp` #988): the ticket names a transaction the
        // engine does not have. Replaying this RUN against this ticket can never find it, so it must
        // NOT be announced as the retryable serialization-abort class, which used to send the driver's
        // managed-transaction loop round for its full 30 s budget. `unknown_ticket_error` separates
        // "the age sweep stopped it" (`TransactionTimedOut`) from "it never existed / is spent"
        // (`TransactionNotFound`) — same class either way, but only one of them tells an operator why.
        Err(unknown) => {
            let _ = reply.send(Err(unknown));
            return RunOutcome::Done;
        }
    };

    // Compile + bind off any store borrow (pure pipeline). A compile error is raised before any side
    // effect, exactly as the TCK requires (`04 §7.3`). The catalog reflects the coordinator's current
    // indexes so the physical planner can pick index-accelerated strategies (`04 §6.6`), and the
    // coordinator's statistics seam activates the cost-based optimiser (`rmp` tasks #65/#82; each
    // statistics call borrows the store briefly, never across the compile).
    //
    // Plan-reuse policy (`rmp` tasks #322/#531): the server consults the engine's [`EnginePlanCache`]
    // keyed on `(query text, schema_version)`. A hit reuses the compiled plan as a shared
    // `Arc<PhysicalPlan>` (a ~50 ns lookup + an `Arc::clone` refcount bump — no operator-tree deep
    // clone) instead of re-running the ~2.4–8.6 µs compile pipeline; a miss compiles and inserts. The
    // same `Arc` is threaded into the executor, so a cache-hit statement performs zero deep plan clones
    // on the engine thread. A cached plan keeps the statistics it was compiled against — acceptable
    // because every cost-based rewrite is bag-preserving (`04 §7.5`), and any schema change that
    // *could* alter results bumps the version (invalidating the cache) via
    // [`EnginePlanCache::bump_schema`].
    let plan = match compile_cached(plan_cache, query, coordinator, extensions.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics, db);
            let _ = reply.send(Err(e));
            return RunOutcome::Done;
        }
    };
    let bound = match bind_parameters(&plan, &to_parameters(params)) {
        Ok(b) => b,
        Err(e) => {
            finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics, db);
            let _ = reply.send(Err(GraphusError::Runtime(e.to_string())));
            return RunOutcome::Done;
        }
    };

    // The Bolt/REST result-summary query type (`rmp` task #512): classified structurally from the plan
    // (`r` / `w` / `rw`) by the exhaustive `contains_write` walk. Computed here — before the plan is
    // moved into either dispatch path — so it is available to the inline statement's summary regardless
    // of the suspend/resume path. The off-thread reader path is always read-only (`"r"`), set in
    // `read_pool::run_read_task`. The enum is also the authoritative **structural** read-only signal for
    // off-thread dispatch (`rmp` task #543) AND the write-in-READ-transaction rejection below.
    let plan_query_type = plan.query_type();
    let query_type = query_type_code(plan_query_type);

    // Reject a write in a read-only transaction (`06 §4`). Detected structurally via the plan's query
    // type — a write operator anywhere makes it `Write`/`ReadWrite`, never `Read` (`rmp` #548: reuse the
    // single exhaustive `query_type()` classifier instead of a hand-maintained operator list that could
    // miss a child-bearing operator and let a nested write escape the READ-mode gate).
    if mode == AccessMode::Read && plan_query_type != graphus_cypher::QueryType::Read {
        finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics, db);
        // A permanent, NON-retryable client fault (`rmp` #988): the reference server's
        // `Neo.ClientError.Statement.AccessMode`. This is the headline case — a client that calls
        // `session.executeRead` and runs a `CREATE` used to be told the retryable
        // `Neo.TransientError.Transaction.Outdated`, so the driver replayed the doomed unit of work
        // until `maxTransactionRetryTime` (30 s) expired and then reported a timeout instead of the
        // real cause. No replay makes a write legal in a READ transaction.
        let _ = reply.send(Err(graphus_core::status::write_in_read_access_mode()));
        return RunOutcome::Done;
    }

    // Snapshot-Isolation demotion for a standalone read (`rmp` task #545): a read-only **auto-commit**
    // statement is not a serializable transaction — it is a MySQL / MariaDB / SQL-Server style SI
    // snapshot read. Demote it BEFORE it runs (and before either dispatch path), so its SIREAD markers
    // are dropped unmerged and its commit skips `detect_pivot_abort`: a read takes no serializability
    // overhead and can never cause a writer to abort. Applied uniformly to the off-thread and inline
    // paths, so the isolation is identical however the read is dispatched. Writes and explicit
    // (`BEGIN … COMMIT`) transactions are untouched — they keep full Serializable SSI. The transaction
    // keeps its snapshot reservation (GC-watermark pin), so the read still sees a consistent MVCC
    // snapshot with no premature reclamation.
    //
    // A procedure-calling plan is EXCLUDED from the demotion (`rmp` #548, symmetric with the off-thread
    // gate below): `query_type()` classifies a `ProcedureCall` as read-only unless its *input* subtree
    // writes — it cannot see a mutation inside a procedure's Rust body. Keeping a procedure-calling read
    // at full Serializable SSI closes the latent trap where a future write-capable procedure would be
    // classified `Read`, demoted to Snapshot, and silently skip pivot detection. Read-only procedures are
    // unaffected in practice (SI vs Serializable is indistinguishable for a pure read).
    if auto_commit && plan_query_type == graphus_cypher::QueryType::Read && !plan.calls_procedure()
    {
        coordinator.demote_read_to_snapshot(txn);
    }

    // The egress channel: bounded for backpressure (`04 §9.3`), or unbounded for the inline
    // single-threaded driver (`super::stream::UNBOUNDED`, used by `super::LocalEngine`).
    let (row_tx, row_rx) = super::stream::egress(result_buffer_capacity);

    // Off-thread read dispatch (`rmp` task #336, Slice 3b-ii; widened by `rmp` task #543): a
    // **structurally read-only auto-commit** statement is a candidate to run on a reader thread
    // concurrently with this engine thread. We capture the owned `Send` read inputs **here on the engine
    // thread** (so the reader never touches the live store's `Rc`/`RefCell` state), package a `ReadTask`,
    // and submit it to the reader pool. The reader streams its rows and retires via the command channel —
    // the engine then merges its SIREAD buffer (M1) and auto-commits. `begin` (TxnId mint +
    // `ssi.register` + `active.insert`) already ran on this thread (the seam opened the auto-commit txn
    // before this `Run`), so the reader's txn is in the conflict graph + active set *before* dispatch —
    // the no-lost-edge + GC-watermark invariants.
    //
    // Eligibility (`rmp` task #543): the gate keys on the **structural** query type (`plan_query_type ==
    // QueryType::Read`, i.e. no write operator anywhere in the plan) — NOT the client-declared Bolt/REST
    // access mode. The declared mode defaults to Write (a bare `MATCH` sent without a read/routing hint
    // arrives as `AccessMode::Write`), so keying on it left the overwhelmingly common read — a plain
    // auto-commit `MATCH` — pinned to the single engine thread (the measured ~1-core read ceiling). A
    // structurally read-only graph read runs identically off-thread: `ReadOnlyGraph` implements the full
    // `GraphAccess` trait, degrades any (impossible-for-a-read-plan) write attempt to a captured error +
    // rollback, and gracefully degrades a *declined* accelerator seam (index / full-text / spatial /
    // columnar) to a correct full scan — so routing it to a reader is fail-safe. Writes still run inline;
    // a write submitted in a declared READ transaction is already rejected above (via `query_type()`).
    //
    // Procedures (`rmp` task #546, re-enabling the #543 deferral): a plan may now dispatch off-thread
    // when **every** procedure it calls is reader-safe
    // (`plan.calls_only_reader_safe_procedures(...)` — the exhaustive structural walk of `rmp` #548,
    // now consulting the registry's `is_reader_safe` capability). Reader-safe = the body performs no
    // graph-store write and no non-thread-safe side effect: GDS algorithms (which additionally nest
    // their own `rmp` #342 rayon parallelism on the reader thread), `db.*` introspection, and
    // `db.index.fulltext.queryNodes` — the last served off-thread from the full-text catalogue captured
    // into `inputs.fulltext`, recomputing its matches from this reader's snapshot (a snapshot-correct
    // scan whose results + SIREAD markers are byte-identical to inline). A plan calling even one
    // non-reader-safe procedure (a UDP that may write, or one whose side effects are not thread-safe)
    // still stays inline — as does every write. NOTE: the Snapshot-Isolation demotion above deliberately
    // still excludes *all* procedure-calling reads (`!plan.calls_procedure()`), so a reader-safe
    // procedure read keeps full Serializable SSI; its markers are merged at retirement and are proven
    // byte-identical to the inline path, so isolation is unchanged — only the thread it runs on differs.
    //
    // Only **auto-commit** reads dispatch off-thread (explicit `BEGIN…MATCH…COMMIT` reads stay inline —
    // they carry ongoing transaction state on the engine thread). A non-threaded dispatcher (DST
    // `LocalEngine`) or a full reader queue falls through to the inline path below — always correct,
    // just serial.
    // Captured here so the queue-full fallback (below) can re-bind the locals the `ReadTask` consumes;
    // `Some(..)` only on the off-thread path, reduced back to the inline locals if submission fails.
    let mut plan = plan;
    let mut bound = bound;
    let mut row_tx = row_tx;
    let mut row_rx = Some(row_rx);
    let mut reply = Some(reply);
    let mut privileges = privileges;
    if plan_query_type == graphus_cypher::QueryType::Read
        && plan.calls_only_reader_safe_procedures(extensions.procedures_dyn())
        && auto_commit
        && dispatch.is_threaded()
    {
        match coordinator.read_task_inputs(txn) {
            Ok(mut inputs) => {
                // `rmp` #755, Slice S2: pre-run this plan's statically-knowable node-property equality
                // seeks HERE, on the engine thread that owns the index, and send the results with the
                // task. Filled at this site (rather than inside `read_task_inputs`) because it is the
                // plan + bound parameters that decide which seeks to run, and only this site has them.
                // Without it the reader declines every seek and full-scans a planned index.
                inputs.index_candidates = coordinator.index_candidates_for(txn, &plan, &bound);
                // `rmp` #866: capture this plan's count-store answers HERE, for the same reason — only
                // this site has the plan, and only this thread may read the counters or evaluate their
                // equivalence predicate. The verdict and the values are frozen together, so the reader
                // reports a number that was provably equal to its own snapshot's count at capture time.
                // An empty capture (predicate failed, or no count-store operator) declines to the scan.
                //
                // Not captured at all for a RESTRICTED principal. The counters are global and
                // unfiltered, so a denied count must never be answered from them —
                // `AuthorizedGraph::count_store_nodes` already declines before the memo is ever
                // consulted (the reader wraps `ReadOnlyGraph` in an `AuthorizedGraph` exactly as the
                // inline path does), and that decline is the load-bearing control. Skipping the capture
                // is defence in depth on top of it: the number is then never computed, so it cannot be
                // disclosed by some future path that reaches the memo without passing the decorator.
                // It also saves the work, which for a restricted principal could never have been used.
                if privileges
                    .as_ref()
                    .is_none_or(EffectivePrivileges::is_unrestricted)
                {
                    inputs.count_store = coordinator.count_store_for(txn, &plan);
                }
                // `rmp` #813: mint this auto-commit read's Bolt causal bookmark HERE, on the engine thread,
                // from the DB's durable-write high-water — the latest already-durable write this read
                // observes (it is dispatched only from a `RUN`, i.e. after any pending commit batch was
                // flushed, so the high-water is already hardened). Captured into the `Send` task so the
                // reader thread places it in the terminal `PULL` `SUCCESS` without touching the live store.
                let read_bookmark = Some(bookmark_token(db, coordinator.durable_write_commit_ts()));
                let task = ReadTask {
                    txn,
                    ticket,
                    plan,
                    bound,
                    inputs,
                    read_bookmark,
                    extensions: Arc::clone(extensions),
                    privileges,
                    // The per-statement deadline (`rmp` #476) rides the `Send` task to the reader thread,
                    // so an off-thread read is bounded by the same budget as an inline one.
                    deadline,
                    // The adaptive intra-query morsel width (`rmp` task #575-g.1): derived HERE on the
                    // engine thread from `readers_inflight` (the reader knows only that it is *a* worker,
                    // not how many peers are in flight), and carried to the worker's `ReaderPoolWorkerGuard`.
                    // A lone read (`readers_inflight == 0`) fans across the whole analytics pool; `K`
                    // concurrent reads get `<= P/K` each (sum `<= P`, no over-subscription; `1` at `K >= P`).
                    morsel_width: graphus_cypher::morsel::reader_pool_morsel_width(
                        readers_inflight,
                    ),
                    row_tx,
                    row_rx: row_rx
                        .take()
                        .expect("egress receiver present before dispatch"),
                    reply: reply.take().expect("reply present before dispatch"),
                };
                match dispatch.try_submit(task) {
                    Ok(()) => {
                        // Dispatched: the reader owns the statement now. The engine does **not** commit
                        // here — it commits when it processes the reader's retirement. The open-tx entry
                        // stays in `open` (finalised at retirement); `active` keeps the reader's snapshot
                        // pinning the GC watermark until then. Return `OffThreadReader` so the loop
                        // tracks it as an in-flight reader (polls the retirement channel until it returns).
                        return RunOutcome::OffThreadReader;
                    }
                    Err(returned) => {
                        // The reader queue is full: rather than block the engine, fall through to the
                        // inline `stream_rows` path below (correct, just serial). Re-bind the locals the
                        // task consumed. (We could fast-reject with `ServerBusy`, but running inline
                        // keeps the statement serving — the admission limiter upstream bounds load.)
                        plan = returned.plan;
                        bound = returned.bound;
                        row_tx = returned.row_tx;
                        row_rx = Some(returned.row_rx);
                        reply = Some(returned.reply);
                        privileges = returned.privileges;
                    }
                }
            }
            Err(e) => {
                // The txn vanished between `begin` and here (should not happen on the serial engine
                // thread); surface it and finalise the auto-commit.
                finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics, db);
                let _ = reply.take().expect("reply present").send(Err(e));
                return RunOutcome::Done;
            }
        }
    }
    // The inline locals (either we never dispatched off-thread, or the queue was full).
    let row_rx = row_rx.expect("egress receiver present on the inline path");
    let reply = reply.expect("reply present on the inline path");

    // Timing is taken from the **injected [`Clock`]** rather than `Instant::now()` so the whole
    // execution path is wall-clock-free and deterministically testable (`04 §11`): production passes a
    // [`crate::server::SystemClock`]-backed clock, while the deterministic [`super::LocalEngine`]
    // passes a `SimClock` so the measured latency replays identically.
    let started = clock.now_nanos();

    // First visit: open the seam + cursor, send the `RunReply` (fields + receiver) over `reply`
    // **before** the first row (so the consumer drains concurrently), then push the first batch. A
    // compile/runtime/transaction error before the first row is delivered through `reply` instead. If
    // the bounded egress channel fills while a slow consumer drains, the cursor is **suspended** off
    // the coordinator borrow (`rmp` task #372) and returned to the engine loop, which resumes it one
    // batch per tick — so the engine thread never head-of-line-blocks on a full channel.
    let mut inflight = InFlightInline {
        cursor: None,
        txn,
        ticket,
        auto_commit,
        privileges,
        row_tx,
        row_rx: Some(row_rx),
        pending_row: None,
        pending_error: None,
        seam_error: None,
        serialization_failure: false,
        started_nanos: started,
        query: query.to_owned(),
        deadline,
        counters: graphus_cypher::QueryCounters::default(),
        query_type: Some(query_type),
        summary_sink: SummarySink::new(),
        plan: Arc::clone(&plan),
        profile: None,
    };
    match start_inline(
        &mut inflight,
        coordinator,
        &plan,
        &bound,
        extensions.as_ref(),
        reply,
    ) {
        BatchStep::Suspended => {
            // The channel filled on the first visit: park the statement; the loop resumes it.
            RunOutcome::Suspended(Box::new(inflight))
        }
        BatchStep::Done { produced_ok } => {
            // The seam's captured deferral error is this statement's terminal item, and handing it
            // over must never block the engine thread on a full egress channel (`rmp` #907): if the
            // channel refuses it, park the statement and let the resume path deliver it.
            let Some(produced_ok) = settle_seam_error(&mut inflight, produced_ok) else {
                return RunOutcome::Suspended(Box::new(inflight));
            };
            finalize_inflight(
                &mut inflight,
                coordinator,
                open,
                produced_ok,
                metrics,
                db,
                degraded,
                clock,
                // Defer a durable auto-commit WRITE's ack into the group-commit batch (`rmp` #566): a
                // clone of `row_tx` is held open in the batch until the batch harden makes it durable.
                Some(commit_batch),
            );
            // For a NON-deferred outcome (read / rollback / read-only / SSI-abort) the egress channel
            // closes when `inflight` (owning `row_tx`) drops at end of scope. For a DEFERRED auto-commit
            // write, `inflight`'s sender drops here but the batch holds a live clone, so the channel stays
            // open until [`super::ack_prepared_commits`] drops it after the `fdatasync` (ack-after-fsync).
            RunOutcome::Done
        }
    }
}

/// Runs the **first** visit of an inline statement (`rmp` task #372): opens the per-statement seam +
/// cursor, sends the [`RunReply`] (fields + receiver) over `reply` before the first row, then pushes
/// the first batch into the bounded egress channel. Returns [`BatchStep::Suspended`] (channel filled —
/// the caller parks the statement) or [`BatchStep::Done`] (cursor exhausted / runtime error /
/// disconnect / a compile-or-seam error delivered through `reply`). On suspension the cursor state is
/// stored into `inflight.cursor` before the seam borrow drops.
fn start_inline<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    inflight: &mut InFlightInline,
    coordinator: &TxnCoordinator<D, S>,
    plan: &Arc<graphus_cypher::PhysicalPlan>,
    bound: &graphus_cypher::BoundParameters,
    extensions: &ExtensionRegistry,
    reply: Reply<Result<RunReply, GraphusError>>,
) -> BatchStep {
    // Borrow the per-statement seam (dropped at end of scope — the transaction stays open across
    // statements; on suspension a fresh seam is taken each resume).
    let mut graph = match coordinator.statement(inflight.txn) {
        Ok(g) => g,
        Err(e) => {
            let _ = reply.send(Err(e));
            return BatchStep::Done { produced_ok: false };
        }
    };

    // RBAC (rmp #93): wrap a restricted principal's seam in `AuthorizedGraph` so reads are filtered and
    // denied writes rejected at the boundary. Unrestricted/internal/TCK → the bare seam (zero overhead,
    // byte-identical to before). The decorator's write-denial is harvested before it drops.
    let (step, auth_error) = match inflight.privileges.clone() {
        Some(privileges) if !privileges.is_unrestricted() => {
            let mut authz = AuthorizedGraph::new(&mut graph, privileges);
            // `open_and_drive_first` detaches the cursor into `inflight.cursor` on suspension, before
            // the `authz`/`graph` borrows drop at end of this arm.
            let step = open_and_drive_first(inflight, plan, bound, &mut authz, extensions, reply);
            (step, authz.take_auth_error())
        }
        _ => {
            let step = open_and_drive_first(inflight, plan, bound, &mut graph, extensions, reply);
            (step, None)
        }
    };

    // Harvest the seam's captured deferral error for this first visit (first one wins across visits).
    if inflight.seam_error.is_none() {
        if let Some(err) = auth_error.or_else(|| graph.take_error()) {
            inflight.seam_error = Some(err);
        }
    }

    // Accumulate THIS visit's side-effect counters (`rmp` task #512). Each per-visit seam from
    // `coordinator.statement()` starts at zero, so summing every visit's slice yields the statement's
    // cumulative total across suspend/resume. The `AuthorizedGraph` decorator delegated its writes to
    // this inner seam, so its counters are already included (a denied write never reached the seam).
    inflight.counters.add(&graph.write_counters());

    step
}

/// Opens the cursor over `graph`, sends the [`RunReply`] before the first row, and pushes the first
/// batch (`rmp` task #372). On a [`BatchStep::Suspended`] the cursor is detached into `inflight.cursor`
/// before returning (so the `graph` borrow is released by the caller's scope). A compile error opening
/// the cursor, or a consumer that disconnected before receiving the reply, is handled here.
fn open_and_drive_first(
    inflight: &mut InFlightInline,
    plan: &Arc<graphus_cypher::PhysicalPlan>,
    bound: &graphus_cypher::BoundParameters,
    graph: &mut dyn GraphAccess,
    extensions: &ExtensionRegistry,
    reply: Reply<Result<RunReply, GraphusError>>,
) -> BatchStep {
    // Open the cursor and hand the consumer its receiver up front (with the column names), so it can
    // drain the bounded channel concurrently with production. The cursor carries a deadline-bearing
    // cancellation token (`rmp` #476): the per-statement CPU budget the executor's safe points enforce.
    // The token lives on the cursor (and survives suspend/resume), so the budget spans every batch.
    let mut cursor = match execute_with_extensions_cancellable(
        // `Arc::clone` (a refcount bump) — the executor holds the shared plan, no deep clone (`rmp` #531).
        Arc::clone(plan),
        bound,
        graph,
        extensions.functions_dyn(),
        extensions.procedures_dyn(),
        graphus_cypher::CancellationToken::with_deadline(inflight.deadline),
    ) {
        Ok(c) => c,
        Err(e) => {
            let _ = reply.send(Err(GraphusError::Runtime(e.to_string())));
            return BatchStep::Done { produced_ok: false };
        }
    };
    let fields: Vec<String> = cursor.columns().to_vec();
    // Capture the `PROFILE` counter sink (`rmp` #752) — it is shared (`Arc`) with the cursor, so the
    // counters keep accruing as the statement streams (including across a suspend/resume) and are read at
    // finalization, long after the cursor itself is gone. `None` for every other statement.
    inflight.profile = cursor.profile().map(Arc::clone);

    // Send the reply (fields + the consumer's receiver + the result-summary sink) before the first
    // row. The sink is shared (`rmp` #512): the consumer keeps a clone and reads it after draining,
    // while `finalize_inflight` fills `inflight.summary_sink` (the same cell) before `row_tx` drops.
    let rows = RowReceiver::new(
        inflight
            .row_rx
            .take()
            .expect("INVARIANT: the first visit owns the egress receiver"),
    );
    if reply
        .send(Ok(RunReply {
            fields,
            rows,
            summary: inflight.summary_sink.clone(),
        }))
        .is_err()
    {
        // The consumer disconnected between submit and reply: nothing to stream; finalization handles
        // the orphaned auto-commit as a (drained) success, exactly as `run_cursor` does.
        return BatchStep::Done { produced_ok: true };
    }

    // Push the first batch.
    let step = drive_batch(inflight, &mut cursor);
    if matches!(step, BatchStep::Suspended) {
        inflight.cursor = Some(cursor.suspend());
    }
    step
}

/// Compiles a query string into a physical plan via the full front-end pipeline (lex → parse →
/// analyze → lower → physical-plan), consulting `catalog` for index-aware strategy choices and
/// `stats` (the coordinator's statistics seam, `rmp` task #82) for cost-based plan refinement.
/// Returns the compiled [`PhysicalPlan`] for `query`, consulting the engine's [`EnginePlanCache`]
/// (`rmp` task #322).
///
/// On a **hit** the cached [`Arc<PhysicalPlan>`](std::sync::Arc) is `Arc::clone`d (an atomic refcount
/// bump — no operator-tree deep clone) and returned without touching the store — no parse, no analyse,
/// no planning, and crucially no `catalog()`/`statistics()` borrow (those are taken only to *compile* a
/// fresh plan). On a **miss** the full [`compile`] pipeline runs against the coordinator's current
/// catalog + statistics, the fresh plan is wrapped in an `Arc` inserted under the exact-text key, and a
/// clone of that `Arc` is returned (again no deep clone). Reuse is sound because the key pairs the
/// verbatim text with the current schema version (see [`EnginePlanCache`]); a compile error is never
/// cached (only a successful plan is inserted).
/// ## Consult, release, compile, re-take (`rmp` #1038)
///
/// The compile pipeline — tokenize, parse, analyse, plan, cost — is the most expensive thing that
/// happens on a cache miss, and it needs nothing from the cache. It therefore runs with the latch
/// released, between a lookup that takes it and an insert that re-takes it. Two workers that miss on
/// the same text at the same moment will both compile, and the second insert simply replaces an
/// identical plan: compilation is a pure function of `(text, catalog, statistics, extensions)`, so a
/// duplicated compile costs work and changes nothing. Holding the latch to avoid that would trade a
/// rare few microseconds of duplicated work for every worker in the engine waiting on every compile.
///
/// The key is re-derived under the second acquisition and the insert is **skipped if it changed**. A
/// key carries the schema version, so a DDL that lands during the compile means this plan was built
/// against a catalog that is no longer current — inserting it would publish a plan under a version it
/// was not compiled for, which is precisely what `bump_schema` exists to prevent. Dropping it is
/// correct and costs one recompile.
fn compile_cached<D: BlockDevice, S: LogSink>(
    plan_cache: &EngineLatch<EnginePlanCache>,
    query: &str,
    coordinator: &TxnCoordinator<D, S>,
    extensions: &ExtensionRegistry,
) -> Result<Arc<PhysicalPlan>, GraphusError> {
    let key = {
        let mut cache = plan_cache.lock();
        let key = cache.key(query);
        if let Some(plan) = cache.cache.get(&key) {
            return Ok(Arc::clone(plan));
        }
        key
    };
    // Miss: compile against the current catalog + statistics, wrap in an `Arc`, then cache. Inserting a
    // clone of the `Arc` (not a deep clone of the plan) keeps the insert-and-return path clone-free too.
    let catalog = coordinator.catalog();
    let stats = coordinator.statistics();
    let plan = Arc::new(compile(query, &catalog, Some(&stats), extensions)?);
    {
        let mut cache = plan_cache.lock();
        if cache.key(query) == key {
            cache.cache.insert(key, Arc::clone(&plan));
        }
    }
    Ok(plan)
}

fn compile(
    query: &str,
    catalog: &IndexCatalog,
    stats: Option<&dyn Statistics>,
    extensions: &ExtensionRegistry,
) -> Result<graphus_cypher::PhysicalPlan, GraphusError> {
    let tokens = tokenize(query).map_err(|e| GraphusError::Compile(e.to_string()))?;
    let ast = parse_tokens(&tokens, query).map_err(|e| GraphusError::Compile(e.to_string()))?;
    // Resolve callables (extension functions + procedures) against the engine's registry so a
    // registered UDF/UDP is found at compile time (`rmp` task #75); the **same** registry backs
    // execution (`run_cursor`), or the compile-time guarantees would be void.
    let validated = analyze_with_extensions(
        &ast,
        extensions.functions_dyn(),
        extensions.procedures_dyn(),
    )
    .map_err(|e| GraphusError::Compile(e.to_string()))?;
    let logical = lower(&validated);
    // The statement's `EXPLAIN` / `PROFILE` prefix (`rmp` #752) rides on the compiled plan, so the ONE
    // parse the pipeline already performs is also the one that decides how the statement runs — no second
    // scan of the text, and the plan cache keys the prefixed and unprefixed forms apart naturally (they
    // are different statements).
    // Planner hints (`rmp` task #855) are read from the validated AST rather than the logical plan: they
    // direct HOW to plan, not what the query means, so the lowering does not carry them. An
    // unsatisfiable hint is an error here, following Neo4j — silently ignoring one would leave the
    // operator believing they had overridden the planner when they had not.
    let hints = validated.planner_hints();
    Ok(plan_physical_hinted(&logical, catalog, stats, &hints)?.with_prefix(ast.prefix()))
}

/// Builds the result-summary [`QueryPlan`] for a statement that carried an `EXPLAIN` / `PROFILE` prefix
/// (`rmp` task #752); `None` for an ordinary statement, which then reports no plan key at all.
///
/// `recorder` is the executor's [`ProfileRecorder`](graphus_cypher::ProfileRecorder) for a profiled run —
/// `None` when the statement never opened a cursor (it failed at compile/bind/seam), in which case a
/// `PROFILE` reports **no** plan rather than a plan of zeroes: nothing ran, so there is nothing measured to
/// report, and Graphus never emits a counter it did not measure.
fn plan_summary(plan: &PhysicalPlan, recorder: Option<&Arc<ProfileRecorder>>) -> Option<QueryPlan> {
    match plan.prefix()? {
        graphus_cypher::QueryPrefix::Explain => Some(QueryPlan {
            profiled: false,
            description: PlanDescription::explain(plan).to_value(),
        }),
        graphus_cypher::QueryPrefix::Profile => recorder.map(|rec| QueryPlan {
            profiled: true,
            description: PlanDescription::profile(rec).to_value(),
        }),
    }
}

/// The outcome of streaming one row through the deadline-aware egress send ([`send_row_with_backpressure`]).
enum EgressStep {
    /// The row was delivered to the bounded egress channel.
    Sent,
    /// The consumer dropped its receiver (client disconnect / session end): stop streaming, not an error.
    ConsumerGone,
    /// The per-statement deadline (or an explicit cancel) tripped while the channel was full: abort the read.
    Cancelled,
    /// The **egress-stall ceiling** (`rmp` #591, C-F1) tripped: the consumer accepted no row for longer
    /// than `egress_stall_timeout`, so the reader is released even when no per-statement deadline is set.
    Stalled,
}

/// Backoff escalation for the off-thread reader's egress-backpressure wait (`rmp` #551): a short
/// `spin_loop` burst (near-zero latency when a fast consumer momentarily fills the bounded channel),
/// then `yield_now`, then brief sleeps (no CPU spin while a genuinely stalled consumer is not draining).
/// The step counts are small so the statement deadline is re-checked promptly (sub-millisecond) once the
/// wait escalates to sleeping.
const EGRESS_PARK_SPINS: u32 = 8;
const EGRESS_PARK_YIELDS: u32 = 16;
const EGRESS_PARK_SLEEP: Duration = Duration::from_micros(200);

/// Delivers one `item` to the bounded egress channel, honouring the reader's per-statement deadline
/// AND an always-on egress-stall ceiling while the channel is full (`rmp` #551 / #591).
///
/// The off-thread reader (`run_cursor`, called only from the reader pool) runs on its own worker
/// thread — it cannot "suspend and yield the engine thread" the way the inline path does. A bare
/// blocking [`RowSender::send`] would therefore park this reader **forever** if the consumer stops
/// draining (TCP zero-window / a slow-loris on the result stream), which pins this read's MVCC snapshot
/// (the GC watermark, so nothing it read is ever reclaimed → unbounded RAM + disk growth) and wedges a
/// finite reader-pool slot (a few such reads exhaust the pool = read-service DoS). Instead we
/// [`RowSender::try_send`] and, while the channel is full, back off and re-check two independent bounds:
///
/// 1. the reader's [`CancellationToken`](graphus_cypher::CancellationToken) — the SAME per-statement
///    deadline the CPU path enforces (`rmp` #476). This closes the gap the aged-transaction reaper's
///    auto-commit exclusion (`engine::maybe_reap_aged`) ASSUMES is closed — that an auto-commit read is
///    "bounded by the per-statement timeout" — which held on the CPU path but not while blocked on egress.
///
/// 2. an **egress-stall ceiling** (`egress_stall_timeout`, `rmp` #591 C-F1): the maximum wall-clock the
///    channel may stay full with **no progress** (no row accepted). This is measured from the moment this
///    send first finds the channel full, so it is a *time-since-last-progress* bound — every accepted row
///    starts a fresh call, resetting it — that never false-aborts a consumer which keeps draining (even
///    slowly). It exists because bound (1) is `None` when `statement_timeout_ms = 0` (a legitimate choice
///    for long analytics): without it a zero-window consumer would pin the reader forever. A full
///    consumer *disconnect* already returns [`EgressStep::ConsumerGone`]; a zero-window *stall* never
///    disconnects, which is exactly what this ceiling bounds. `None` disables it (opt-out).
fn send_row_with_backpressure(
    row_tx: &RowSender,
    cancel: &graphus_cypher::CancellationToken,
    egress_stall_timeout: Option<Duration>,
    item: super::stream::RowItem,
) -> EgressStep {
    let mut item = item;
    let mut waited: u32 = 0;
    // The stall deadline is armed lazily on the FIRST full-channel observation (not before the loop), so
    // it measures time spent with no progress on *this* row — and because a delivered row returns and the
    // next row starts a fresh call, it resets on every accepted row. A consumer draining at any finite
    // rate under the ceiling therefore never trips it; only a genuine stall (no row accepted for the whole
    // window) does. `None` (ceiling disabled) leaves it unarmed forever — the pre-`rmp`-#591 behaviour.
    let mut stall_deadline: Option<Instant> = None;
    loop {
        match row_tx.try_send(item) {
            super::stream::TrySend::Sent => return EgressStep::Sent,
            super::stream::TrySend::Disconnected(_) => return EgressStep::ConsumerGone,
            super::stream::TrySend::Full(returned) => {
                // Re-check the deadline/cancel BEFORE backing off, so a stalled consumer releases this
                // reader (and its snapshot + slot) within the statement budget.
                if cancel.is_cancelled() {
                    return EgressStep::Cancelled;
                }
                // Arm the egress-stall ceiling on first contention, then trip it once the channel has
                // stayed full with no accepted row for the whole window — bounding a stalled consumer
                // INDEPENDENTLY of the per-statement deadline (`rmp` #591 C-F1).
                match stall_deadline {
                    None => {
                        stall_deadline = egress_stall_timeout.map(|t| Instant::now() + t);
                    }
                    Some(deadline) if Instant::now() >= deadline => {
                        return EgressStep::Stalled;
                    }
                    Some(_) => {}
                }
                item = returned;
                if waited < EGRESS_PARK_SPINS {
                    std::hint::spin_loop();
                } else if waited < EGRESS_PARK_SPINS + EGRESS_PARK_YIELDS {
                    std::thread::yield_now();
                } else {
                    std::thread::sleep(EGRESS_PARK_SLEEP);
                }
                waited = waited.saturating_add(1);
            }
        }
    }
}

/// Opens the cursor for `plan` over `graph` (the bare seam or an [`AuthorizedGraph`] wrapper), sends
/// the [`RunReply`] before the first row, then streams each row into `row_tx`.
///
/// Returns `true` if streaming completed with no **runtime** error (a consumer disconnect counts as
/// success — the caller handles the orphaned transaction). A compile/runtime error before the first
/// row goes through `reply`; a runtime error mid-stream goes through `row_tx`. Authorization denials
/// and seam-captured deferral errors are surfaced by the caller after this returns (they live on the
/// `graph`/wrapper, not in the runtime error channel).
#[allow(clippy::too_many_arguments)] // Threads the seam + extension registry + egress channel + bounds.
pub(super) fn run_cursor(
    plan: &Arc<graphus_cypher::PhysicalPlan>,
    bound: &graphus_cypher::BoundParameters,
    graph: &mut dyn GraphAccess,
    extensions: &ExtensionRegistry,
    deadline: Option<Instant>,
    // The always-on egress-stall ceiling (`rmp` #591 C-F1): bounds a full-channel no-progress wait
    // independently of `deadline`, so a stalled consumer releases this reader even when the per-statement
    // timeout is disabled. `None` disables it. Pool-wide (captured at `ReadPool::spawn`), not per-task.
    egress_stall_timeout: Option<Duration>,
    // For the `graphus_egress_stall_aborts_total` observability counter, recorded on the stall exit path.
    metrics: &Metrics,
    row_tx: &RowSender,
    row_rx: std::sync::mpsc::Receiver<super::stream::RowItem>,
    summary: SummarySink,
    // The auto-commit read's Bolt causal bookmark (`rmp` #813), minted on the engine thread at dispatch
    // from the DB's durable-write high-water and carried here so it reaches the terminal `PULL` `SUCCESS`.
    // `None` on the (non-reader-pool) callers that do not carry one.
    read_bookmark: Option<String>,
    reply: Reply<Result<RunReply, GraphusError>>,
) -> bool {
    // The **same** registry that backed `compile` must back execution (`rmp` task #75), or the
    // compile-time function/procedure guarantees are void. The cursor carries a deadline-bearing
    // cancellation token (`rmp` #476): the same per-statement CPU budget the inline path enforces, so an
    // off-thread reader is bounded identically. Built ONCE and cloned (`rmp` #551): the executor enforces
    // the deadline on the CPU/compute path, and the SAME token bounds the egress-backpressure wait in the
    // streaming loop below, so a stalled consumer cannot pin this reader (its MVCC snapshot / the GC
    // watermark) or its pool slot past the statement deadline.
    let cancel = graphus_cypher::CancellationToken::with_deadline(deadline);
    let mut cursor = match execute_with_extensions_cancellable(
        // `Arc::clone` (a refcount bump) — the executor holds the shared plan, no deep clone (`rmp` #531).
        Arc::clone(plan),
        bound,
        graph,
        extensions.functions_dyn(),
        extensions.procedures_dyn(),
        cancel.clone(),
    ) {
        Ok(c) => c,
        Err(e) => {
            let _ = reply.send(Err(GraphusError::Runtime(e.to_string())));
            return false;
        }
    };

    // The `PROFILE` counter sink for this read (`rmp` #752): shared with the cursor, read after the last
    // row so its counters are final. `None` for every other statement.
    let profile = cursor.profile().map(Arc::clone);

    // The plan compiled and the cursor opened: hand the consumer its stream now, with the result
    // column names known up front (`04 §7.7`).
    let fields: Vec<String> = cursor.columns().to_vec();
    if reply
        .send(Ok(RunReply {
            fields,
            rows: RowReceiver::new(row_rx),
            summary: summary.clone(),
        }))
        .is_err()
    {
        // The consumer disconnected between submit and reply; nothing to stream (the caller handles
        // an auto-commit rollback for the now-orphaned transaction).
        return true;
    }

    loop {
        // Materialize the executor's `RowValue` row at the egress boundary (`04 §8.3`): each entity
        // is resolved (labels/type/endpoints/properties) through the cursor's graph seam, so the wire
        // form carries full structural values, not flattened ids (rmp #76/#96). Because resolution
        // reads through the *same* `&mut dyn GraphAccess` the cursor holds — including the
        // `AuthorizedGraph` decorator (rmp #93) — RBAC filtering and MVCC visibility compose
        // automatically: a hidden property is already `None`, an invisible entity already filtered.
        match cursor.next_materialized() {
            Ok(Some(cells)) => {
                match send_row_with_backpressure(row_tx, &cancel, egress_stall_timeout, Ok(cells)) {
                    EgressStep::Sent => {}
                    // A closed channel (consumer gone) ends streaming early; not an error.
                    EgressStep::ConsumerGone => return true,
                    EgressStep::Cancelled => {
                        // The per-statement deadline (`rmp` #476) tripped (or an explicit cancel) WHILE
                        // this reader was backpressured by a consumer that stopped draining (`rmp` #551).
                        // End the read so it retires and releases its MVCC snapshot (advancing the GC
                        // watermark) and its reader-pool slot. Best-effort deliver a clear timeout error;
                        // if the channel is still full it is dropped and the consumer observes the
                        // disconnect at retirement.
                        let _ = row_tx.try_send(Err(GraphusError::Runtime(
                            "statement timed out while streaming results to a slow or stalled consumer"
                                .to_owned(),
                        )));
                        return false;
                    }
                    EgressStep::Stalled => {
                        // The egress-stall ceiling (`rmp` #591 C-F1) tripped: the consumer accepted no row
                        // for the whole `egress_stall_timeout` window (a zero-window / non-draining
                        // consumer). Terminate the read so it retires and releases its MVCC snapshot
                        // (advancing the GC watermark) and its reader-pool slot — the SAME terminal-error
                        // contract as the deadline path, but bounded INDEPENDENTLY of `statement_timeout`
                        // (so a stalled consumer cannot pin the reader forever when the timeout is `0`).
                        metrics.record_egress_stall_abort();
                        let _ = row_tx.try_send(Err(GraphusError::Runtime(
                            "read aborted: the result stream stalled (the client stopped draining rows) \
                             past the egress-stall ceiling"
                                .to_owned(),
                        )));
                        return false;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                let _ = row_tx.send(Err(GraphusError::Runtime(e.to_string())));
                return false;
            }
        }
    }

    // The off-thread reader path is read-only (`rmp` #336): publish an `r` summary into the sink
    // BEFORE the caller drops `row_tx`, so the consumer's post-drain `summary()` reports the query
    // type for reads exactly as the inline path does for writes (`rmp` #512). A read applies no
    // mutations, so `write_counters()` is empty and `counters_to_stats` omits the `stats` block.
    summary.set(RunSummary {
        query_type: Some("r".to_owned()),
        stats: counters_to_stats(&graph.write_counters()),
        // An `EXPLAIN` / `PROFILE` read dispatched to the reader pool reports its plan exactly as the
        // inline path does (`rmp` #752): same renderer, same keys — the thread a read runs on is not
        // observable to the client. Read after the last row, so a PROFILE's counters are final.
        plan: plan_summary(plan, profile.as_ref()),
        // The auto-commit read's causal bookmark (`rmp` #813): the DB's monotonic durable-write
        // high-water, minted on the engine thread at dispatch and carried in with the task. It names an
        // already-durable commit and is identical for two reads with no write between them — matching a
        // real Neo4j server, which emits a bookmark for read transactions too. A reader-pool read is
        // always an auto-commit statement whose terminal (`has_more == false`) `PULL` `SUCCESS` this
        // summary backs, so this is exactly the spec-named message that carries the bookmark.
        bookmark: read_bookmark,
    });
    true
}

/// The disposition of a [`handle_run`] inline statement (`rmp` task #372).
///
/// A statement either finishes within its first engine visit ([`Done`](RunOutcome::Done)), is handed
/// to an off-thread reader ([`OffThreadReader`](RunOutcome::OffThreadReader), the `rmp` #336 path), or
/// — when a slow consumer fills the bounded egress channel — is **suspended**
/// ([`Suspended`](RunOutcome::Suspended)) so the engine thread returns to its command loop and
/// services other commands/writes on the same database. A suspended statement is resumed one batch
/// per loop tick by [`resume_inflight`].
pub(super) enum RunOutcome {
    /// The statement completed (committed/rolled back) within this visit; nothing to track.
    Done,
    /// The statement was dispatched to the off-thread reader pool; it retires later (`rmp` #336).
    OffThreadReader,
    /// The egress channel filled with a slow consumer draining; the statement's cursor was suspended
    /// off the coordinator borrow and must be resumed batch-by-batch.
    Suspended(Box<InFlightInline>),
}

/// A suspended inline statement parked between batches because the bounded egress channel filled
/// (`rmp` task #372). Owns everything needed to resume on a later loop tick **without** holding the
/// coordinator's `&mut` borrow, so the engine thread is free to serve concurrent commands/writes on
/// the same database while a slow (even zero-draining) consumer catches up.
///
/// Re-binding to a fresh per-visit seam for the **same** transaction (same MVCC snapshot + the same
/// uncommitted write buffer) keeps the continuation coherent; suspend/resume changes neither commit
/// timing nor durability (writes apply incrementally per `next()`; durability is at commit, which
/// still happens once the stream is exhausted — see [`SuspendedCursor`](graphus_cypher::SuspendedCursor)).
pub(super) struct InFlightInline {
    /// The detached cursor execution state (`None` only transiently while a batch runs).
    cursor: Option<graphus_cypher::SuspendedCursor>,
    /// The transaction this statement runs in (resolved to a fresh seam each resume).
    txn: graphus_core::TxnId,
    /// The open-tx ticket, finalised at exhaustion.
    ticket: TxTicket,
    /// Whether this is an auto-commit statement (commit/rollback at finalization).
    auto_commit: bool,
    /// The restricted principal's privileges, re-wrapping a fresh [`AuthorizedGraph`] each visit; the
    /// unrestricted/internal path is `None`.
    privileges: Option<EffectivePrivileges>,
    /// The engine end of the egress channel, kept open across visits so the consumer keeps pulling
    /// and the terminal auto-commit/runtime error still reaches it in position.
    row_tx: RowSender,
    /// The consumer end of the egress channel, owned only until the first visit sends the `RunReply`
    /// (which hands it to the consumer); `None` thereafter.
    row_rx: Option<std::sync::mpsc::Receiver<super::stream::RowItem>>,
    /// One materialized row produced but not yet sent (the channel was full at try_send time). Held
    /// here so no row is lost or re-pulled; sent first on the next resume.
    pending_row: Option<Vec<graphus_cypher::MaterializedValue>>,
    /// The statement's **terminal error**, produced but not yet accepted by a full bounded egress
    /// channel (`rmp` #907).
    ///
    /// Every terminal item used to be handed over with the *blocking* [`RowSender::send`], on the
    /// documented assumption that "the engine only ever reaches a resumed batch while the consumer is
    /// actively draining". That assumption does not hold: the engine reaches a resumed batch whenever
    /// the channel has room, and a consumer that stopped draining after its last page leaves the
    /// channel exactly full at the moment the cursor's next call errors. The blocking `send` then
    /// parks the **engine thread** — the single thread serving the whole database — until somebody
    /// drains that one channel, which is precisely what a paused consumer will not do. A Bolt client
    /// with several results open in one transaction can reach it inside a single connection: it
    /// blocks in its next `RUN` while the earlier result is parked, so it cannot drain and cannot be
    /// unblocked.
    ///
    /// While this is `Some` the statement's cursor is finished — no further row is ever pulled. The
    /// statement simply stays parked and the engine re-offers the error, without blocking, on each
    /// resume until the consumer makes room. The error is never dropped (that would be a silent
    /// truncation of a failed result) and never re-ordered (it is still the last item on the stream).
    pending_error: Option<GraphusError>,
    /// The first seam-captured deferral error seen across visits (the load-bearing `RecordStoreGraph`
    /// invariant), surfaced as the terminal item at finalization — rows precede it, byte-identically
    /// to the single-visit ordering.
    seam_error: Option<GraphusError>,
    /// Whether this statement's terminal item was a **retriable serialization failure**
    /// ([`GraphusError::Transaction`]) captured by the write seam (`rmp` #967).
    ///
    /// A write-write conflict is refused in two places that agree on the victim — the coordinator's
    /// first-updater-wins [`LockTable`](graphus_txn::LockTable) and, since `rmp` #967, the store's
    /// `ensure_no_conflicting_writer` (`D-property-write-conflict`) — and both document the same
    /// contract: the error is captured "so the caller rolls this transaction back". For an
    /// auto-commit statement the caller is [`finish_autocommit`], which already does. For an
    /// EXPLICIT transaction there was no caller at all, so the refused writer stayed open and
    /// committable; [`finalize_inflight`] now closes that half. See the comment there for the
    /// committed-data-loss this prevents.
    serialization_failure: bool,
    /// `clock.now_nanos()` at statement start, for an accurate latency/slow-query log at finish.
    started_nanos: u64,
    /// The query string, kept for the slow-query log at finish.
    query: String,
    /// The per-statement wall-clock deadline (`rmp` #476), or `None` when no statement timeout is
    /// configured. Read once by [`open_and_drive_first`] to build the cursor's deadline-bearing
    /// [`CancellationToken`](graphus_cypher::CancellationToken); the token then lives on the cursor (and
    /// its [`SuspendedCursor`](graphus_cypher::SuspendedCursor)), so the same budget governs every resume
    /// batch without re-reading this.
    deadline: Option<Instant>,
    /// Cumulative side-effect counters tallied across every (re)visit of this statement (`rmp` #512).
    /// Each per-visit seam from `coordinator.statement()` starts at zero; `start_inline`/`run_batch`
    /// add its slice here, so the running total is correct across suspend/resume. Published into
    /// `summary_sink` at finalization.
    counters: graphus_cypher::QueryCounters,
    /// The Bolt/REST result-summary query-type code (`r`/`w`/`rw`), classified once from the plan in
    /// [`handle_run`] (`rmp` #512) and carried unchanged across resumes.
    query_type: Option<String>,
    /// The side channel the consumer reads its result summary from; filled by [`finalize_inflight`]
    /// (query type + counters +, for a prefixed statement, the plan) BEFORE `row_tx` drops (`rmp` #512 —
    /// see [`SummarySink`]'s happens-before contract).
    summary_sink: SummarySink,
    /// The compiled plan, kept so the result summary of an `EXPLAIN` / `PROFILE` statement can be rendered
    /// at finalization (`rmp` #752). An `Arc::clone` — a refcount bump, no plan deep-clone.
    plan: Arc<PhysicalPlan>,
    /// The executor's `PROFILE` counter sink for this statement (`rmp` #752), captured when the cursor
    /// opened and read once the statement finishes. `None` for every non-profiled statement — and for a
    /// profiled one that never opened a cursor, which then reports no plan rather than a plan of zeroes.
    profile: Option<Arc<ProfileRecorder>>,
}

impl InFlightInline {
    /// The transaction this suspended inline statement runs in. The engine loop reads it so the
    /// maximum-transaction-age sweep (`rmp` #477) never reaps a transaction whose statement is currently
    /// executing inline (a reap mid-statement would pull the seam out from under the live cursor).
    pub(super) fn txn(&self) -> graphus_core::TxnId {
        self.txn
    }

    /// Delivers a **terminal error** to the consumer through the still-open egress channel (`rmp` #485
    /// B2). When the engine loop abandons a parked statement — it panicked on a resumed batch, or was
    /// rejected at the parked-queue capacity bound — the consumer has received rows but no terminal
    /// item; without this it would observe a clean end-of-stream (`Ok(None)`) and report a **partial
    /// result as success** (the CWE-393 silent-truncation class). This sends the failure in the same
    /// terminal position [`drive_batch`] uses for a mid-stream runtime error, [`finalize_inflight`] for
    /// a commit failure, and the off-thread `finish_reader` for an auto-commit abort — so an
    /// abandoned-on-the-resume-path statement is reported to the client exactly as those are: a FAILURE.
    ///
    /// Uses the **blocking** [`RowSender::send`] like those existing terminal-error sites: the engine
    /// only ever reaches a *resumed* batch while the consumer is actively draining (a stalled consumer
    /// leaves the egress full, so the statement stays suspended and is never pulled — hence never
    /// panics here), so this does not stall the engine any more than the runtime-error terminal in
    /// `drive_batch` already can. A dropped receiver (early disconnect) makes the send a harmless no-op.
    pub(super) fn deliver_terminal_error(&self, e: GraphusError) {
        let _ = self.row_tx.send(Err(e));
    }

    /// Offers `error` to the consumer as this stream's **terminal item without blocking the engine
    /// thread** (`rmp` #907). Returns `true` once it has been handed over (or the consumer is gone,
    /// in which case there is nobody left to tell); `false` when the bounded egress channel is full,
    /// in which case the error is retained in [`pending_error`](Self::pending_error) and the caller
    /// must keep the statement parked so [`retry_pending_error`](Self::retry_pending_error) can
    /// re-offer it on a later tick.
    fn offer_terminal_error(&mut self, error: GraphusError) -> bool {
        use super::stream::TrySend;
        match self.row_tx.try_send(Err(error)) {
            TrySend::Sent | TrySend::Disconnected(_) => true,
            TrySend::Full(item) => {
                // `try_send` hands back exactly the item it refused, so this is the same error.
                self.pending_error = item.err();
                debug_assert!(
                    self.pending_error.is_some(),
                    "INVARIANT: a refused terminal item is the error we passed in"
                );
                false
            }
        }
    }

    /// Re-offers the terminal error held back by a full egress channel (`rmp` #907). Returns `true`
    /// once it lands (the statement can then be finalised), `false` while the channel is still full
    /// (the statement stays parked). A no-op returning `true` when nothing is held.
    fn retry_pending_error(&mut self) -> bool {
        match self.pending_error.take() {
            None => true,
            Some(error) => self.offer_terminal_error(error),
        }
    }
}

/// Hands the seam's captured deferral error to the consumer as the statement's terminal item, without
/// blocking the engine thread (`rmp` #907).
///
/// Returns the `produced_ok` verdict to finalise with — `Some(false)` once an error has been
/// delivered, `Some(produced_ok)` when there is none — or `None` when the bounded egress channel
/// refused it, in which case the caller must keep the statement **parked**: the error is held in
/// [`InFlightInline::pending_error`] and the resume path delivers it and finalises later.
///
/// A statement that already failed (`produced_ok == false`) has delivered its terminal item elsewhere,
/// so the seam error is not sent a second time — the pre-existing behaviour, preserved exactly.
fn settle_seam_error(inflight: &mut InFlightInline, produced_ok: bool) -> Option<bool> {
    if !produced_ok {
        return Some(false);
    }
    match inflight.seam_error.take() {
        None => Some(true),
        Some(error) => {
            // `rmp` #967: remember that this statement died of a RETRIABLE serialization failure, so
            // `finalize_inflight` can roll an explicit transaction back. Recorded here — the single
            // point where a seam error becomes the terminal item — so both delivery routes (accepted
            // now, or parked in `pending_error` and re-offered on a later tick) are covered.
            inflight.serialization_failure = matches!(error, GraphusError::Transaction(_));
            if inflight.offer_terminal_error(error) {
                Some(false)
            } else {
                None
            }
        }
    }
}

/// How a single resume visit ended (`rmp` task #372): either the statement is fully done (the caller
/// finalises it), or it filled the channel again and stays suspended for a later tick.
enum BatchStep {
    /// The cursor exhausted (or the consumer disconnected, or a runtime/deferral error terminated the
    /// stream): `produced_ok` is `true` iff no runtime/deferral/auth error occurred, so the caller
    /// runs the auto-commit accordingly.
    Done { produced_ok: bool },
    /// The egress channel filled again; the statement stays suspended (state already stored back).
    ///
    /// It is also how a **terminal error that the full channel refused** is reported (`rmp` #907):
    /// the error is held in [`InFlightInline::pending_error`], the cursor is finished and will never
    /// be resumed (the resume path delivers the error first and finalises), so the statement is
    /// simply parked like any other suspension.
    Suspended,
}

/// Drives **one** resume batch of a suspended inline statement on the engine thread (`rmp` task
/// #372): opens a fresh seam for the same txn, re-binds the cursor, sends as many rows as the bounded
/// channel accepts (starting with any `pending_row`), and either re-suspends (channel full) or runs
/// to a terminal condition. On a terminal condition it finalises (auto-commit + latency/slow-log) and
/// returns; on re-suspension it stores the cursor state back into `inflight`.
///
/// Returns `true` while the statement is still in flight (stay subscribed), `false` once finalised.
#[allow(clippy::too_many_arguments)] // the resume path threads its execution context here
pub(super) fn resume_inflight<
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
>(
    inflight: &mut InFlightInline,
    coordinator: &TxnCoordinator<D, S>,
    open: &EngineLatch<OpenTxTable>,
    extensions: &ExtensionRegistry,
    metrics: &Metrics,
    db: &str,
    degraded: &super::EngineDegraded,
    clock: &Arc<dyn Clock + Send + Sync>,
) -> bool {
    // A terminal error a full egress channel refused on an earlier visit (`rmp` #907). The cursor is
    // already finished, so nothing may be pulled from it: all that remains is to hand the error over.
    // Re-offer it WITHOUT blocking — while the consumer still has not made room the statement simply
    // stays parked, which costs the engine thread nothing and keeps every other database client
    // moving. Blocking here (the old behaviour) stalled the engine thread for the whole database.
    if inflight.pending_error.is_some() {
        if !inflight.retry_pending_error() {
            return true; // still full; try again on a later tick
        }
        finalize_inflight(
            inflight,
            coordinator,
            open,
            /* produced_ok */ false,
            metrics,
            db,
            degraded,
            clock,
            None,
        );
        return false;
    }

    let step = run_batch(inflight, coordinator, extensions);
    match step {
        BatchStep::Suspended => true,
        BatchStep::Done { produced_ok } => {
            // The seam's captured deferral error is the terminal item and must not block the engine
            // thread either (`rmp` #907): when the channel refuses it the statement stays parked and
            // the branch above finalises it once it lands.
            let Some(produced_ok) = settle_seam_error(inflight, produced_ok) else {
                return true;
            };
            // The parked-statement resume path runs OUTSIDE a group-commit batch drain, so a durable
            // auto-commit write finalised here commits INLINE (`None`, its own `fdatasync`), unchanged by
            // #566 — the (rare) slow-consumer statement pays one sync, never coalesced. The common
            // single-visit write coalesces via the `Some(batch)` path in [`handle_run`].
            finalize_inflight(
                inflight,
                coordinator,
                open,
                produced_ok,
                metrics,
                db,
                degraded,
                clock,
                None,
            );
            false
        }
    }
}

/// Runs one batch of a suspended statement: a fresh seam + (optional) [`AuthorizedGraph`] wrapper, the
/// cursor resumed over it, rows `try_send`-ed until the channel is `Full` (re-suspend) or the cursor
/// reaches a terminal condition. Pure batch mechanics; finalization (commit/log) is the caller's.
fn run_batch<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    inflight: &mut InFlightInline,
    coordinator: &TxnCoordinator<D, S>,
    extensions: &ExtensionRegistry,
) -> BatchStep {
    // A fresh per-visit seam for the SAME txn: same MVCC snapshot, same uncommitted write buffer (the
    // writes a prior visit applied are owner-visible), so the cursor continues coherently. A seam
    // error here is terminal — surface it like a deferral error.
    let mut graph = match coordinator.statement(inflight.txn) {
        Ok(g) => g,
        Err(e) => {
            // Terminal, and handed over WITHOUT blocking the engine thread (`rmp` #907): a full
            // channel parks the statement holding the error instead of stalling the whole database.
            return if inflight.offer_terminal_error(e) {
                BatchStep::Done { produced_ok: false }
            } else {
                BatchStep::Suspended
            };
        }
    };

    // Take the suspended state out; it is restored (re-suspended) or consumed (done) below.
    let suspended = inflight
        .cursor
        .take()
        .expect("INVARIANT: a suspended inflight always holds its cursor between batches");

    // Re-wrap in `AuthorizedGraph` for a restricted principal (rmp #93), exactly as the first visit
    // did, so RBAC filtering/denial compose every visit. The wrapper borrows the seam, so its
    // auth-error is harvested before it drops at the end of this scope.
    let (step, auth_error) = match inflight.privileges.clone() {
        Some(privileges) if !privileges.is_unrestricted() => {
            let mut authz = AuthorizedGraph::new(&mut graph, privileges);
            let mut cursor = suspended.resume(
                &mut authz,
                extensions.functions_dyn(),
                extensions.procedures_dyn(),
            );
            let step = drive_batch(inflight, &mut cursor);
            // On a re-suspension, detach the cursor state back into `inflight` BEFORE the wrapper +
            // seam borrows drop at end of scope (so the borrow is truly released).
            if matches!(step, BatchStep::Suspended) {
                inflight.cursor = Some(cursor.suspend());
            }
            (step, authz.take_auth_error())
        }
        _ => {
            let mut cursor = suspended.resume(
                &mut graph,
                extensions.functions_dyn(),
                extensions.procedures_dyn(),
            );
            let step = drive_batch(inflight, &mut cursor);
            if matches!(step, BatchStep::Suspended) {
                inflight.cursor = Some(cursor.suspend());
            }
            (step, None)
        }
    };

    // Harvest the seam's captured deferral error for THIS visit (a fresh error cell per `statement()`,
    // record_graph.rs ~308): accumulate the FIRST one across visits. The seam drops at the end of this
    // function, merging its read buffer into the shared SSI tracker (the M1 barrier) — correct, and
    // idempotent across visits (markers are sorted/deduped).
    if inflight.seam_error.is_none() {
        if let Some(err) = auth_error.or_else(|| graph.take_error()) {
            inflight.seam_error = Some(err);
        }
    }

    // Accumulate THIS resume visit's counters (`rmp` task #512), exactly as the first visit in
    // `start_inline`: the fresh per-visit seam contributes only the writes applied during this batch,
    // so the running total in `inflight.counters` stays correct across every suspend/resume.
    inflight.counters.add(&graph.write_counters());

    step
}

/// Sends rows from a resumed `cursor` into the egress channel until it is `Full` (re-suspend) or the
/// cursor reaches a terminal condition. The first thing sent is any `pending_row` held from the
/// previous visit's `Full` (so no row is lost or re-pulled).
fn drive_batch(
    inflight: &mut InFlightInline,
    cursor: &mut graphus_cypher::Cursor<'_>,
) -> BatchStep {
    use super::stream::TrySend;

    // 1) Flush the held row first, if any. A `Full` here means we still cannot make progress: stay
    //    suspended, still HOLDING the row (no `next()` is pulled, so nothing is lost or re-pulled).
    if let Some(row) = inflight.pending_row.take() {
        match inflight.row_tx.try_send(Ok(row)) {
            TrySend::Sent => {}
            TrySend::Full(item) => {
                inflight.pending_row = Some(unwrap_row(item));
                return BatchStep::Suspended;
            }
            TrySend::Disconnected(_) => {
                // Consumer gone: finish as a (drained) success — the orphaned auto-commit is handled
                // by finalization exactly as a normal completion (a disconnect counts as success, as
                // in `run_cursor`).
                return BatchStep::Done { produced_ok: true };
            }
        }
    }

    // 2) Pull-and-send the rest of this batch.
    loop {
        match cursor.next_materialized() {
            Ok(Some(cells)) => match inflight.row_tx.try_send(Ok(cells)) {
                TrySend::Sent => {}
                TrySend::Full(item) => {
                    // Channel full: park the unsent row, suspend, and yield the engine thread.
                    inflight.pending_row = Some(unwrap_row(item));
                    return BatchStep::Suspended;
                }
                TrySend::Disconnected(_) => return BatchStep::Done { produced_ok: true },
            },
            Ok(None) => {
                // Cursor exhausted. A seam deferral / auth error (harvested by the caller after the
                // seam drops) still flips this to a failure at finalization; here we report the row
                // production itself succeeded.
                return BatchStep::Done { produced_ok: true };
            }
            Err(e) => {
                // A runtime error mid-stream is the terminal item, in the SAME position it would have
                // in a single visit (after the rows already sent). Handed over WITHOUT blocking the
                // engine thread (`rmp` #907): the row that filled the channel may have been the last
                // one this batch could send, and a consumer that has paused between pages would then
                // park the single engine thread here for the whole database. On a refusal the error
                // is held and the statement is parked; the resume path re-offers it.
                return if inflight.offer_terminal_error(GraphusError::Runtime(e.to_string())) {
                    BatchStep::Done { produced_ok: false }
                } else {
                    BatchStep::Suspended
                };
            }
        }
    }
}

/// Recovers the row out of the `Ok(row)` item a [`super::stream::TrySend::Full`] handed back (it is
/// always the exact item we passed to `try_send`, so this never hits the `Err` arm in practice).
fn unwrap_row(item: super::stream::RowItem) -> Vec<graphus_cypher::MaterializedValue> {
    // try_send only ever returns the exact `Ok(row)` item we passed in, so the `Err` arm is
    // unreachable; default to an empty row defensively rather than panic on a corrupt invariant.
    item.unwrap_or_default()
}

/// Finalises a suspended inline statement once its stream is exhausted (`rmp` task #372): surfaces any
/// accumulated seam deferral error as the terminal item (rows precede it — byte-identical ordering to
/// the single-visit path, where `stream_rows` sent `take_error` before `handle_run`'s commit), runs
/// the auto-commit (or rolls back on failure), closes the egress channel, and emits the latency /
/// slow-query log from the stored `started_nanos`.
///
/// The auto-commit semantics are **identical** to the single-visit path: [`finish_autocommit`] is
/// called at the same point relative to the still-open `row_tx`, so the terminal-error / auto-commit /
/// explicit-txn contracts are preserved. An explicit (non-auto-commit) statement is not committed here
/// — its `BEGIN…COMMIT` does that — exactly as before.
#[allow(clippy::too_many_arguments)] // execution context + the #566 group-commit batch, all positional
fn finalize_inflight<D: BlockDevice, S: LogSink>(
    inflight: &mut InFlightInline,
    coordinator: &TxnCoordinator<D, S>,
    open: &EngineLatch<OpenTxTable>,
    produced_ok: bool,
    metrics: &Metrics,
    db: &str,
    degraded: &super::EngineDegraded,
    clock: &Arc<dyn Clock + Send + Sync>,
    // Group commit (`rmp` #566): `Some(batch)` (the single-visit / `dispatch_command` path) DEFERS a
    // durable auto-commit WRITE's ack into `batch` — coalescing its `fdatasync` with the rest of the
    // batch. `None` (the parked-statement resume path) commits INLINE (its own `fdatasync`), unchanged.
    commit_batch: Option<&mut Vec<super::PendingCommit>>,
) {
    // A seam-captured deferral error (the load-bearing `RecordStoreGraph` invariant) is the terminal
    // item, sent after every row — and it flips the statement to a failure so the auto-commit rolls
    // back rather than commits silently-wrong rows. It is delivered by [`settle_seam_error`] in the
    // caller, immediately before this call and in exactly the same position on the stream, because
    // delivery may have to be *deferred* when the bounded egress channel is full: blocking here would
    // stall the engine thread for the whole database (`rmp` #907). By the time we get here the error
    // is gone and `produced_ok` already reflects it.
    debug_assert!(
        inflight.seam_error.is_none() && inflight.pending_error.is_none(),
        "INVARIANT: the terminal error is settled before finalization (rmp #907)"
    );

    // Auto-commit: commit on success, roll back on a runtime/deferral error — while `row_tx` is still
    // open so a commit failure (e.g. an SSI serialization abort) reaches the consumer as a terminal
    // error, never swallowed into a false success (`04 §1.3` step 6; the rmp #238 atomicity divergence).
    //
    // A durable auto-commit **write** yields the transaction's bookmark (`rmp` #807): the monotonic
    // per-database `"<db>:<commit_ts>"` token the client receives in the terminal `PULL` `SUCCESS`. A
    // read / no-op auto-commit, and every explicit-transaction `RUN` (which does not auto-commit —
    // `inflight.auto_commit == false`, so `finish_autocommit` is not called and this stays `None`),
    // mints none; the bookmark for an explicit transaction is minted by its `COMMIT` instead. This is
    // the structural gate that keeps the bookmark off a `RUN` `SUCCESS` and off an explicit-tx `PULL`.
    let bookmark = if inflight.auto_commit {
        finish_autocommit(
            coordinator,
            open,
            inflight.ticket,
            produced_ok,
            &inflight.row_tx,
            metrics,
            db,
            degraded,
            commit_batch,
        )
    } else {
        // An EXPLICIT transaction whose statement died of a retriable serialization failure is rolled
        // back HERE, at statement end (`rmp` #967). Committed-data-loss, measured on
        // `graphus-dst`'s `isolation::tests::write_write_conflict_is_detected`:
        //
        // T1 and T2 both run `MATCH (c:Counter) SET c.v = c.v + 1`. T1 wins the entity — the
        // coordinator's first-updater-wins `LockTable` grants it the write lock, and (since #967) the
        // store's `ensure_no_conflicting_writer` names it the holder of the undo chain — so T2's write
        // is REFUSED with a retriable `GraphusError::Transaction`. But T2's SSI footprint was already
        // announced (`note_write` records the write marker BEFORE it acquires the lock, and the
        // predicate pre-image is announced before the store call), so the tracker still believes T2
        // wrote the node. That phantom write gives T1 an outbound rw-edge, makes T1 a Case-A pivot,
        // and SSI aborts T1 — the writer that actually succeeded — while T2, whose write never
        // happened, went on to COMMIT as if it had. Net: neither increment survives and the committed
        // value silently stays at the pre-image.
        //
        // Rolling T2 back at statement end retires its phantom footprint (`TxnCoordinator::abort` →
        // `SsiTracker::forget` + `LockTable::release_all`), so T1 is no longer a pivot and commits its
        // increment, and T2's later `COMMIT` correctly fails instead of silently succeeding over a
        // write the engine refused. That is exactly the contract both refusal sites already document —
        // `RecordGraph::note_write`: "captures a retriable serialization error **so the caller rolls
        // this transaction back**" — which had a caller for auto-commit statements
        // (`finish_autocommit`'s `!produced_ok` arm) and none at all for explicit ones.
        //
        // Deliberately narrow: ONLY a retriable `GraphusError::Transaction` from the write seam. Those
        // are exactly two sites — `RecordGraph::note_write`'s first-updater-wins refusal and
        // `RecordStore::ensure_no_conflicting_writer` — and no other error the seam can capture carries
        // that variant (an authorization denial is `Security`, a constraint violation is its own kind,
        // everything else from the store is `Storage`). Every other statement failure keeps the existing
        // behaviour: the error is the terminal item and the transaction stays open for the client to
        // roll back itself.
        //
        // Routed through `rollback_tx` rather than a bare `coordinator.rollback`, so this abort keeps
        // the guarantees a client `ROLLBACK` has: the `catch_recovery` boundary that stops an fsyncgate
        // panic unwinding the single engine thread (`rmp` #386/#955) and the `degrade_on_incomplete_undo`
        // flag when the undo does not complete (`rmp` #955).
        if !produced_ok && inflight.serialization_failure {
            let _ = super::rollback_tx(coordinator, open, inflight.ticket, metrics, db, degraded);
        }
        None
    };

    // Publish the finished statement's result summary (`rmp` task #512) into the side sink BEFORE
    // `row_tx` drops. THIS ORDERING IS CRITICAL: the channel-close that follows — when `inflight`
    // (which owns `row_tx`) drops at the caller's scope end — is the happens-before edge the consumer
    // relies on. The consumer reads `summary()` only after its row stream returns `None` (the closed
    // channel), and `std::sync::mpsc` orders that observation happens-after this `set`. Filling the
    // sink AFTER the drop would race the consumer's post-drain read and surface an empty summary. The
    // counters reflect operations *applied* during execution (Neo4j operation-count model); on a
    // rollback the consumer sees the terminal error and never reads the summary, so it is harmless.
    inflight.summary_sink.set(RunSummary {
        query_type: inflight.query_type.clone(),
        stats: counters_to_stats(&inflight.counters),
        // The plan of an `EXPLAIN` / `PROFILE` statement (`rmp` #752). For a PROFILE this reads the
        // executor's recorder AFTER the last row was produced, so every operator's measured counters are
        // final; for an EXPLAIN nothing ran and the plan carries estimates only.
        plan: plan_summary(&inflight.plan, inflight.profile.as_ref()),
        // The auto-commit write bookmark computed just above (`rmp` #807); `None` for a read / no-op or
        // an explicit-transaction statement. The consumer reads this summary only AFTER the egress
        // channel closes — which for a deferred (group-commit) durable write is the post-`fdatasync`
        // batch ack — so a bookmark the client observes always names an already-durable commit.
        bookmark,
    });

    // Latency + slow-query log, measured from statement start (`04 §9` / NFR-10). Emitted at finish so
    // the latency spans the whole — possibly suspended — stream, exactly as the single-visit path.
    //
    // Measured on the **monotonic** clock timeline (rmp #395): production's `SystemClock::now_nanos`
    // reads `CLOCK_MONOTONIC`, so the end never precedes the start and a wall-clock NTP step cannot
    // corrupt the duration. We still clamp defensively here — the `Clock` is injectable (tests / a
    // future faulty source can hand back a non-monotonic value), and an observability path must never
    // emit a wrapped-to-instant or spurious multi-decade latency. `saturating_sub` floors a backward
    // reading at 0; `monotonic_elapsed` additionally caps an absurd forward jump at a sane ceiling so a
    // hostile clock cannot poison the histogram or fire a bogus slow-query alert.
    let elapsed = monotonic_elapsed(inflight.started_nanos, clock.now_nanos());
    metrics.observe_query_latency_for(db, elapsed);
    if elapsed >= slow_threshold() {
        metrics.record_slow_query_for(db);
        tracing::warn!(
            target: "graphus::slow_query",
            duration_ms = elapsed.as_millis() as u64,
            query = %truncate_for_log(&inflight.query),
            "slow query",
        );
    }
}

/// The largest elapsed duration the latency path will report (rmp #395): 24 hours. Any apparent span
/// beyond this is treated as a clock anomaly (a forward NTP step between the start and end readings on
/// a non-monotonic source) rather than a real query latency, and is clamped to this ceiling so it can
/// neither poison the latency histogram's `_sum` nor fire a spurious slow-query alert claiming a
/// multi-decade duration. No legitimate single statement runs for a day; the engine's own statement
/// timeouts cut long queries off far sooner.
const MAX_PLAUSIBLE_ELAPSED: Duration = Duration::from_secs(24 * 60 * 60);

/// Computes a **sane** elapsed duration between a start and end reading of the monotonic clock,
/// clamping both pathological directions a non-monotonic clock could produce (rmp #395).
///
/// On the production [`crate::server::SystemClock`] this is exact (`now_nanos` is `CLOCK_MONOTONIC`,
/// so `end >= start` always and neither clamp ever engages). The clamps exist because the [`Clock`] is
/// **injectable**: a test or a future faulty source can return a value that went backwards (NTP step)
/// or jumped implausibly far forward. A backward reading floors at `0` (logged as instant, never an
/// underflow wrap to ~584 years); a forward jump past [`MAX_PLAUSIBLE_ELAPSED`] caps at the ceiling.
fn monotonic_elapsed(started_nanos: u64, now_nanos: u64) -> Duration {
    let raw = Duration::from_nanos(now_nanos.saturating_sub(started_nanos));
    raw.min(MAX_PLAUSIBLE_ELAPSED)
}

/// Builds a [`Parameters`] set from the `(name, value)` pairs the seam passed in.
fn to_parameters(params: Vec<(String, graphus_core::Value)>) -> Parameters {
    let mut p = Parameters::new();
    for (name, value) in params {
        p.insert(name, value);
    }
    p
}

/// Finalises an auto-commit transaction after its single statement streamed: commit on success,
/// roll back on a runtime error (`04 §1.3` step 6). Removes the ticket from the open set either way.
///
/// A commit failure (an SSI serialization abort, or any commit error) is **not** swallowed: it is sent
/// as a **terminal error** through the still-open egress channel `row_tx`, so the consumer observes the
/// auto-commit statement as failed and retriable. Reporting success for a transaction the engine rolled
/// back would be an atomicity/durability violation — the client would believe a write is committed (and
/// durable) when it was undone (`04 §1.3` step 6, ACID mandate). This was the seed-4 VOPR
/// `EdgeMultisetMismatch` divergence (rmp #238): an auto-commit `CREATE (a)-[:KNOWS]->(b)` whose
/// post-stream COMMIT lost the SSI dangerous-structure check was acknowledged as committed, so the
/// model recorded the edge the engine had rolled back.
///
/// # Group commit (`rmp` #566)
/// A durable auto-commit **write** takes one of two commit shapes, chosen by `commit_batch`:
/// * `Some(batch)` — the common single-visit path: PREPARE the commit ([`TxnCoordinator::commit_prepare`]
///   — SSI validation + `COMMIT` record appended, **no `fdatasync`**) and DEFER the ack by pushing a
///   [`super::PendingCommit::Autocommit`] holding a *clone* of `row_tx` onto the batch. The batch harden
///   issues ONE `fdatasync` covering every batched committer, and only then drops the held-open clone —
///   closing the egress channel, the client's ack-after-fsync end-of-stream. This coalesces concurrent
///   auto-commit writers onto one sync (the T1 win); it no longer does an inline per-statement sync on
///   the engine thread. `record_commit` is deferred to the batch ack.
/// * `None` — the parked-statement resume path: commit INLINE ([`TxnCoordinator::commit`], its own
///   `fdatasync`), exactly as before #566. Rare (a slow-consumer statement), so left un-coalesced.
///
/// In BOTH shapes the SSI validation runs at commit time in channel order, so serializability and the
/// abort victim are byte-identical to the pre-#566 inline commit — only the `fdatasync` is coalesced.
/// Returns the auto-commit **write** bookmark (`rmp` #807) — `Some("<db>:<commit_ts>")` when this
/// transaction committed a durable write, `None` for a read / no-op commit or an abort. The token is
/// opaque and monotonic per database (the commit-timestamp oracle issues strictly increasing values),
/// and the caller publishes it into the statement's summary sink so the client receives it in the
/// terminal `PULL` `SUCCESS`.
#[allow(clippy::too_many_arguments)] // commit bookkeeping + the #566 group-commit batch, all positional
fn finish_autocommit<D: BlockDevice, S: LogSink>(
    coordinator: &TxnCoordinator<D, S>,
    open: &EngineLatch<OpenTxTable>,
    ticket: TxTicket,
    produced_ok: bool,
    row_tx: &RowSender,
    metrics: &Metrics,
    db: &str,
    degraded: &super::EngineDegraded,
    commit_batch: Option<&mut Vec<super::PendingCommit>>,
) -> Option<String> {
    // The removal claims this auto-commit: whoever takes the ticket out owns the commit or rollback
    // that follows, and everything that follows — SSI validation, a WAL append, possibly an
    // `fdatasync` — runs with the latch released (`rmp` #1038).
    let tx = open.lock().remove(&ticket.0)?;
    if !produced_ok {
        // A runtime/deferral error terminated the stream: roll back (no commit, nothing durable).
        let _ = coordinator.rollback(tx.txn);
        metrics.record_abort_for(db);
        return None;
    }
    match commit_batch {
        // Group-commit batch available (`rmp` #566): PREPARE the write and DEFER its durability ack.
        Some(batch) => match coordinator.commit_prepare(tx.txn) {
            // A durable write commit: hold a clone of the egress sender open in the batch so the channel
            // stays open until the shared batch `fdatasync` covers `commit_lsn`; the client is acked
            // (channel close) only then — the ack-after-fsync rule, coalesced across the batch. The
            // statement's own `row_tx` drops when its `handle_run` returns, leaving this clone the last
            // sender, so the close happens precisely at the batch ack. `record_commit` is deferred there.
            // The commit timestamp (strictly monotonic per database) is this write's bookmark (`rmp` #807).
            Ok((commit_ts, Some(commit_lsn))) => {
                batch.push(super::PendingCommit::Autocommit {
                    row_tx: row_tx.clone(),
                    commit_lsn,
                });
                Some(bookmark_token(db, commit_ts))
            }
            // Wrote nothing durable (`rmp` #529): nothing to harden, so no deferral — ack now. The
            // statement's `row_tx` drop (at `handle_run` scope end) closes the channel with no sync. A
            // read / no-op auto-commit mints the DB's **durable-write** bookmark (`rmp` #813): the
            // monotonic `"<db>:<durable_write_commit_ts>"` high-water — the latest already-durable write
            // this commit could have observed. It is deliberately NOT this transaction's own
            // (phantom-ticked, `rmp` #529) `commit_ts`, so it always names a durable commit and two reads
            // with no write between them return the SAME token (Neo4j read-bookmark semantics).
            Ok((_commit_ts, None)) => {
                metrics.record_commit_for(db);
                Some(bookmark_token(db, coordinator.durable_write_commit_ts()))
            }
            // An SSI serialization abort (or an inactive txn) has already been rolled back; a STORE-level
            // prepare failure has NOT, and this ticket is already out of `open`, so `resolve_failed_commit`
            // is the only thing that ever will (`rmp` #955). Either way the retriable failure is surfaced
            // as a terminal stream error, never a silent success over rolled-back writes (`04 §1.3` step 6;
            // the rmp #238 seed-4 atomicity divergence). A rolled-back txn mints no bookmark, and the
            // consumer sees the terminal error and never reads the summary anyway.
            Err(e) => {
                super::resolve_failed_commit(
                    coordinator,
                    tx.txn,
                    degraded,
                    "failed-autocommit rollback",
                );
                let _ = row_tx.send(Err(e));
                metrics.record_abort_for(db);
                None
            }
        },
        // No batch (the parked-statement resume path): commit INLINE with its own `fdatasync`, exactly
        // as before #566. This path is reached only by a suspended (slow-consumer) auto-commit **write**
        // — auto-commit reads run off the reader pool and never park here — so a successful inline
        // commit yields the write's bookmark from its commit timestamp (`rmp` #807).
        None => match coordinator.commit(tx.txn) {
            Ok(commit_ts) => {
                metrics.record_commit_for(db);
                Some(bookmark_token(db, commit_ts))
            }
            Err(e) => {
                super::resolve_failed_commit(
                    coordinator,
                    tx.txn,
                    degraded,
                    "failed-autocommit rollback",
                );
                let _ = row_tx.send(Err(e));
                metrics.record_abort_for(db);
                None
            }
        },
    }
}

/// Formats a Bolt transaction **bookmark** (`rmp` #807): the opaque, monotonic-per-database token
/// `"<db>:<commit_ts>"`, from the database name and the transaction's commit timestamp. The
/// commit-timestamp oracle issues strictly increasing values per database (see
/// `graphus_txn::TimestampOracle::commit`), so successive commits on a database yield strictly
/// increasing tokens — the monotonicity a driver's causal chaining (`session.last_bookmarks()`) and
/// the `rmp` #807 regression rely on. Drivers treat the whole string as opaque; the format is an
/// internal convention, not wire-fixed.
pub(super) fn bookmark_token(db: &str, commit_ts: graphus_core::Timestamp) -> String {
    format!("{db}:{}", commit_ts.0)
}

/// Rolls back an auto-commit transaction that failed to compile/bind (so it never leaks). A no-op
/// for an explicit transaction (the caller still owns it).
fn finish_failed_autocommit<D: BlockDevice, S: LogSink>(
    coordinator: &TxnCoordinator<D, S>,
    open: &EngineLatch<OpenTxTable>,
    ticket: TxTicket,
    auto_commit: bool,
    metrics: &Metrics,
    db: &str,
) {
    if !auto_commit {
        return;
    }
    // The removal claims the rollback; the undo runs with the latch released (`rmp` #1038).
    let claimed = open.lock().remove(&ticket.0);
    if let Some(tx) = claimed {
        let _ = coordinator.rollback(tx.txn);
        metrics.record_abort_for(db);
    }
}

/// Maps the cypher [`QueryType`](graphus_cypher::QueryType) to its Bolt/REST wire code (`rmp` task
/// #512): `r` (read), `w` (pure write — no result rows), `rw` (read-write — returns rows). The schema
/// class `s` is not produced here: DDL is intercepted before the Cypher pipeline, so admin summaries
/// are a separate task (#513).
fn query_type_code(query_type: graphus_cypher::QueryType) -> String {
    use graphus_cypher::QueryType;
    match query_type {
        QueryType::Read => "r",
        QueryType::Write => "w",
        QueryType::ReadWrite => "rw",
    }
    .to_owned()
}

/// Builds the Bolt/REST `stats` key/value pairs from the cypher
/// [`QueryCounters`](graphus_cypher::QueryCounters) (`rmp` task #512), following the Neo4j
/// `SummaryCounters` wire contract.
///
/// Only **non-zero** data counters are emitted (a counter that did not change is omitted), keyed in the
/// kebab-case the official driver ecosystem expects. When any data counter is non-zero a
/// `contains-updates = true` flag is appended (mirroring `SummaryCounters.containsUpdates()`). A
/// fully-empty set (a read) yields an empty vec, so the wire layer emits no `stats` block at all.
///
/// The wire-key naming lives here in the server layer — the cypher counters stay protocol-agnostic —
/// and **both** seams convert through this one helper, so Bolt and REST spell every key identically.
fn counters_to_stats(counters: &graphus_cypher::QueryCounters) -> Vec<(String, Value)> {
    let entries = [
        ("nodes-created", counters.nodes_created),
        ("nodes-deleted", counters.nodes_deleted),
        ("relationships-created", counters.relationships_created),
        ("relationships-deleted", counters.relationships_deleted),
        ("properties-set", counters.properties_set),
        ("labels-added", counters.labels_added),
        ("labels-removed", counters.labels_removed),
    ];
    let mut stats: Vec<(String, Value)> = entries
        .into_iter()
        .filter(|&(_, n)| n > 0)
        // Operation counts never approach `i64::MAX`; clamp defensively rather than wrap.
        .map(|(key, n)| {
            (
                key.to_owned(),
                Value::Integer(i64::try_from(n).unwrap_or(i64::MAX)),
            )
        })
        .collect();
    if counters.contains_updates() {
        stats.push(("contains-updates".to_owned(), Value::Boolean(true)));
    }
    stats
}

/// The slow-query threshold, read from the process-wide cell the server sets at startup. Falls back
/// to a conservative default if unset (e.g. in a unit test that does not configure it).
fn slow_threshold() -> std::time::Duration {
    crate::observability::slow_query_threshold()
}

/// Truncates a query string for the slow-query log so a giant statement does not bloat a log line.
fn truncate_for_log(query: &str) -> String {
    const MAX: usize = 200;
    if query.len() <= MAX {
        query.to_owned()
    } else {
        // Truncate on a char boundary at or before MAX.
        let mut end = MAX;
        while !query.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &query[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// rmp #395 GATE: the latency elapsed computation is fed a **non-monotonic** clock (the end
    /// reading precedes the start, as a backward NTP step would produce) and must clamp to instant
    /// rather than underflow-wrap to a ~584-year duration. This is the defense `finalize_inflight`
    /// relies on so a clock anomaly can never log a slow query as instant *or* as a bogus multi-decade
    /// duration.
    #[test]
    fn monotonic_elapsed_clamps_a_backward_clock_step_to_instant() {
        // started at t=1_000_000_000, "now" jumped *backwards* to t=0 (NTP step / hostile clock).
        let elapsed = monotonic_elapsed(1_000_000_000, 0);
        assert_eq!(
            elapsed,
            Duration::ZERO,
            "a backward clock reading must floor at 0, never underflow-wrap"
        );
        // And it is nowhere near the wrap value a naive `now - started` would yield.
        assert!(elapsed < Duration::from_secs(1));
    }

    /// rmp #395 GATE: an implausible **forward** jump (a forward NTP step between the start and end
    /// readings) is capped at the 24h ceiling, so it cannot poison the latency histogram's `_sum` or
    /// fire a slow-query alert claiming a multi-decade duration.
    #[test]
    fn monotonic_elapsed_caps_an_implausible_forward_jump() {
        // started at t=0, "now" jumped forward by ~584 years (near u64::MAX nanos).
        let elapsed = monotonic_elapsed(0, u64::MAX);
        assert_eq!(
            elapsed, MAX_PLAUSIBLE_ELAPSED,
            "an absurd forward jump must cap at the plausibility ceiling"
        );
    }

    /// A normal, monotone interval is reported exactly (no clamp engages on the production path).
    #[test]
    fn monotonic_elapsed_reports_a_normal_interval_exactly() {
        // 2.5 ms in nanoseconds.
        let elapsed = monotonic_elapsed(1_000_000_000, 1_002_500_000);
        assert_eq!(elapsed, Duration::from_micros(2_500));
    }

    /// `rmp` #512 GATE: the wire `stats` builder emits ONLY non-zero counters, in the fixed wire
    /// order, kebab-case, and appends `contains-updates` whenever any counter fired. A read (all
    /// zero) yields an empty vec, so the seam omits the `stats` block entirely. This locks the wire
    /// key spelling + ordering both seams depend on (byte-determinism for the DST clients).
    #[test]
    fn counters_to_stats_omits_zeros_and_flags_updates() {
        use graphus_cypher::QueryCounters;
        assert!(
            counters_to_stats(&QueryCounters::default()).is_empty(),
            "a read records no counters, so no stats block is emitted"
        );
        let c = QueryCounters {
            nodes_created: 2,
            properties_set: 3,
            labels_added: 1,
            ..Default::default()
        };
        assert_eq!(
            counters_to_stats(&c),
            vec![
                ("nodes-created".to_owned(), Value::Integer(2)),
                ("properties-set".to_owned(), Value::Integer(3)),
                ("labels-added".to_owned(), Value::Integer(1)),
                ("contains-updates".to_owned(), Value::Boolean(true)),
            ],
            "only the non-zero counters, kebab-case, fixed order, contains-updates flag last"
        );
    }

    /// `rmp` #512 GATE: the query-type classification maps onto the Bolt/REST wire codes.
    #[test]
    fn query_type_code_maps_read_write_readwrite() {
        use graphus_cypher::QueryType;
        assert_eq!(query_type_code(QueryType::Read), "r");
        assert_eq!(query_type_code(QueryType::Write), "w");
        assert_eq!(query_type_code(QueryType::ReadWrite), "rw");
    }

    // ---- rmp #909: the client's `tx_timeout` clamps DOWNWARD only ------------------------------

    #[test]
    fn a_client_budget_can_only_shorten_the_configured_one() {
        let s = Duration::from_secs(120); // the shipped `statement_timeout_ms` default
        let short = Duration::from_secs(1);
        let long = Duration::from_secs(3_600);

        // Neither side set a bound: unbounded, exactly as before the field existed.
        assert_eq!(effective_statement_timeout(None, None), None);
        // Only the operator: their bound, untouched.
        assert_eq!(effective_statement_timeout(Some(s), None), Some(s));
        // Only the client (the operator disabled the per-statement budget): the client self-limits.
        assert_eq!(effective_statement_timeout(None, Some(short)), Some(short));

        // THE CONTRACT. Below the server bound the client's figure is honoured...
        assert_eq!(
            effective_statement_timeout(Some(s), Some(short)),
            Some(short)
        );
        // ...and above it the SERVER's bound wins. This is the security-relevant direction: were it
        // the other way round, `tx_timeout` would be a one-field escape from the CPU-exhaustion
        // defence the per-statement deadline exists to provide (`rmp` #476).
        assert_eq!(effective_statement_timeout(Some(s), Some(long)), Some(s));
        // Equal values are a no-op either way.
        assert_eq!(effective_statement_timeout(Some(s), Some(s)), Some(s));
    }

    #[test]
    fn an_absurd_client_budget_degrades_instead_of_panicking() {
        // A hand-rolled client can put `i64::MAX` in `tx_timeout`; the server normalises that to a
        // ~292-million-year `Duration`. `Instant + Duration` PANICS on overflow, and whether this
        // particular sum overflows depends on the platform's `Instant` representation — so the
        // deadline is built with `checked_add` and an unrepresentable one simply means "no deadline".
        let absurd = Duration::from_millis(i64::MAX.unsigned_abs());
        // The clamp still prefers the operator's bound, which is the only outcome that matters here.
        assert_eq!(
            effective_statement_timeout(Some(Duration::from_secs(120)), Some(absurd)),
            Some(Duration::from_secs(120)),
            "an absurd client budget is clamped to the operator's, so it never reaches the addition"
        );
        // And if the operator disabled their own budget, the addition is still panic-free.
        let effective =
            effective_statement_timeout(None, Some(absurd)).expect("client-only budget");
        let _: Option<Instant> = Instant::now().checked_add(effective);
    }
}
