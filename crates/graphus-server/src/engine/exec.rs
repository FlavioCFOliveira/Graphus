//! Per-`Run` execution on the engine thread: compile → bind → execute the Cypher pipeline against a
//! coordinator statement seam, stream rows over the bounded egress channel, and (for auto-commit)
//! commit when the stream is drained (`04-technical-design.md` §1.3 request lifecycle, §7.1 pipeline,
//! §7.7 streaming).
//!
//! All of this runs on the **single engine thread** (see [`super`]), so it may block freely (storage
//! I/O, the WAL group-commit `fdatasync`) without touching a Tokio runtime worker (`04 §9.1`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_core::error::GraphusError;
use graphus_cypher::extension::ExtensionRegistry;
use graphus_cypher::function_registry::{Arity, FunctionFailure};
use graphus_cypher::procedure_registry::{FieldSpec, FieldType, ProcedureFailure, ValueClass};
use graphus_cypher::{
    AuthorizedGraph, FeatureFlags, GraphAccess, IndexCatalog, Parameters, PhysicalPlan, PlanCache,
    PlanCacheKey, PrivilegeOracle, ProcedureSignature, SchemaVersion, Statistics, TxnCoordinator,
    analyze_with_extensions, bind_parameters, execute_with_extensions, lower, parse_tokens,
    plan_physical_with_stats, tokenize,
};
use graphus_io::BlockDevice;
use graphus_wal::LogSink;

use super::command::{AccessMode, Reply};
use super::privileges::EffectivePrivileges;
use super::read_pool::{ReadDispatch, ReadTask};
use super::stream::{RowReceiver, RowSender};
use super::{OpenTx, RunReply, TxTicket};
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
/// (tokenize→parse→analyze→lower→physical-plan) on **every** `Run` — a measured ~7–9 µs of pure CPU
/// per statement that a looped concurrency workload pays on every iteration. This cache reuses the
/// compiled [`PhysicalPlan`] for an identical query text, turning a repeated `Run` into a ~0.1 µs
/// hash lookup + a cheap plan clone.
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
    cache: PlanCache<PhysicalPlan>,
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
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    plan_cache: &mut EnginePlanCache,
    ticket: TxTicket,
    query: &str,
    params: Vec<(String, graphus_core::Value)>,
    auto_commit: bool,
    privileges: Option<EffectivePrivileges>,
    extensions: &Arc<ExtensionRegistry>,
    dispatch: &ReadDispatch<D, S>,
    result_buffer_capacity: usize,
    metrics: &Arc<Metrics>,
    clock: &Arc<dyn Clock + Send + Sync>,
    reply: Reply<Result<RunReply, GraphusError>>,
) -> RunOutcome {
    // Resolve the open transaction.
    let Some(tx) = open.get(&ticket.0) else {
        let _ = reply.send(Err(GraphusError::Transaction(format!(
            "run in unknown transaction {}",
            ticket.0
        ))));
        return RunOutcome::Done;
    };
    let txn = tx.txn;
    let mode = tx.mode;

    // Compile + bind off any store borrow (pure pipeline). A compile error is raised before any side
    // effect, exactly as the TCK requires (`04 §7.3`). The catalog reflects the coordinator's current
    // indexes so the physical planner can pick index-accelerated strategies (`04 §6.6`), and the
    // coordinator's statistics seam activates the cost-based optimiser (`rmp` tasks #65/#82; each
    // statistics call borrows the store briefly, never across the compile).
    //
    // Plan-reuse policy (`rmp` task #322): the server consults the engine's [`EnginePlanCache`] keyed
    // on `(query text, schema_version)`. A hit reuses the compiled [`PhysicalPlan`] (a ~0.1 µs lookup
    // + a cheap plan clone) instead of re-running the ~7–9 µs compile pipeline; a miss compiles and
    // inserts. A cached plan keeps the statistics it was compiled against — acceptable because every
    // cost-based rewrite is bag-preserving (`04 §7.5`), and any schema change that *could* alter
    // results bumps the version (invalidating the cache) via [`EnginePlanCache::bump_schema`].
    let plan = match compile_cached(plan_cache, query, coordinator, extensions.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics);
            let _ = reply.send(Err(e));
            return RunOutcome::Done;
        }
    };
    let bound = match bind_parameters(&plan, &to_parameters(params)) {
        Ok(b) => b,
        Err(e) => {
            finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics);
            let _ = reply.send(Err(GraphusError::Runtime(e.to_string())));
            return RunOutcome::Done;
        }
    };

    // Reject a write in a read-only transaction (`06 §4`). The physical plan carries whether it
    // mutates; we detect it structurally via the plan's writes flag.
    if mode == AccessMode::Read && plan_writes(&plan) {
        finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics);
        let _ = reply.send(Err(GraphusError::Transaction(
            "write statement attempted in a READ transaction".to_owned(),
        )));
        return RunOutcome::Done;
    }

    // The egress channel: bounded for backpressure (`04 §9.3`), or unbounded for the inline
    // single-threaded driver (`super::stream::UNBOUNDED`, used by `super::LocalEngine`).
    let (row_tx, row_rx) = super::stream::egress(result_buffer_capacity);

    // Off-thread read dispatch (`rmp` task #336, Slice 3b-ii): a **read-only auto-commit** statement is
    // a candidate to run on a reader thread concurrently with this engine thread. We capture the owned
    // `Send` read inputs **here on the engine thread** (so the reader never touches the live store's
    // `Rc`/`RefCell` state), package a `ReadTask`, and submit it to the reader pool. The reader streams
    // its rows and retires via the command channel — the engine then merges its SIREAD buffer (M1) and
    // auto-commits. `begin` (TxnId mint + `ssi.register` + `active.insert`) already ran on this thread
    // (the seam opened the auto-commit txn before this `Run`), so the reader's txn is in the conflict
    // graph + active set *before* dispatch — the no-lost-edge + GC-watermark invariants.
    //
    // Only auto-commit Reads dispatch off-thread in this slice (explicit `BEGIN…MATCH…COMMIT` reads
    // stay inline). A non-threaded dispatcher (DST `LocalEngine`) or a full reader queue falls through
    // to the inline path below — always correct, just serial.
    // Captured here so the queue-full fallback (below) can re-bind the locals the `ReadTask` consumes;
    // `Some(..)` only on the off-thread path, reduced back to the inline locals if submission fails.
    let mut plan = plan;
    let mut bound = bound;
    let mut row_tx = row_tx;
    let mut row_rx = Some(row_rx);
    let mut reply = Some(reply);
    let mut privileges = privileges;
    if mode == AccessMode::Read && auto_commit && dispatch.is_threaded() {
        match coordinator.read_task_inputs(txn) {
            Ok(inputs) => {
                let task = ReadTask {
                    txn,
                    ticket,
                    plan,
                    bound,
                    inputs,
                    extensions: Arc::clone(extensions),
                    privileges,
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
                finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics);
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
        seam_error: None,
        started_nanos: started,
        query: query.to_owned(),
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
            finalize_inflight(
                &mut inflight,
                coordinator,
                open,
                produced_ok,
                metrics,
                clock,
            );
            // The egress channel closes when `inflight` (owning `row_tx`) drops at end of scope.
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
    coordinator: &mut TxnCoordinator<D, S>,
    plan: &graphus_cypher::PhysicalPlan,
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

    step
}

/// Opens the cursor over `graph`, sends the [`RunReply`] before the first row, and pushes the first
/// batch (`rmp` task #372). On a [`BatchStep::Suspended`] the cursor is detached into `inflight.cursor`
/// before returning (so the `graph` borrow is released by the caller's scope). A compile error opening
/// the cursor, or a consumer that disconnected before receiving the reply, is handled here.
fn open_and_drive_first(
    inflight: &mut InFlightInline,
    plan: &graphus_cypher::PhysicalPlan,
    bound: &graphus_cypher::BoundParameters,
    graph: &mut dyn GraphAccess,
    extensions: &ExtensionRegistry,
    reply: Reply<Result<RunReply, GraphusError>>,
) -> BatchStep {
    // Open the cursor and hand the consumer its receiver up front (with the column names), so it can
    // drain the bounded channel concurrently with production.
    let mut cursor = match execute_with_extensions(
        plan,
        bound,
        graph,
        extensions.functions_dyn(),
        extensions.procedures_dyn(),
    ) {
        Ok(c) => c,
        Err(e) => {
            let _ = reply.send(Err(GraphusError::Runtime(e.to_string())));
            return BatchStep::Done { produced_ok: false };
        }
    };
    let fields: Vec<String> = cursor.columns().to_vec();

    // Send the reply (fields + the consumer's receiver) before the first row.
    let rows = RowReceiver::new(
        inflight
            .row_rx
            .take()
            .expect("INVARIANT: the first visit owns the egress receiver"),
    );
    if reply.send(Ok(RunReply { fields, rows })).is_err() {
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
/// On a **hit** the cached plan is cloned and returned without touching the store — no parse, no
/// analyse, no planning, and crucially no `catalog()`/`statistics()` borrow (those are taken only to
/// *compile* a fresh plan). On a **miss** the full [`compile`] pipeline runs against the coordinator's
/// current catalog + statistics, and the result is inserted under the exact-text key before being
/// returned. Reuse is sound because the key pairs the verbatim text with the current schema version
/// (see [`EnginePlanCache`]); a compile error is never cached (only a successful plan is inserted).
fn compile_cached<D: BlockDevice, S: LogSink>(
    plan_cache: &mut EnginePlanCache,
    query: &str,
    coordinator: &TxnCoordinator<D, S>,
    extensions: &ExtensionRegistry,
) -> Result<PhysicalPlan, GraphusError> {
    let key = plan_cache.key(query);
    if let Some(plan) = plan_cache.cache.get(&key) {
        return Ok(plan.clone());
    }
    // Miss: compile against the current catalog + statistics, then cache.
    let catalog = coordinator.catalog();
    let stats = coordinator.statistics();
    let plan = compile(query, &catalog, Some(&stats), extensions)?;
    plan_cache.cache.insert(key, plan.clone());
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
    Ok(plan_physical_with_stats(&logical, catalog, stats))
}

/// Opens the cursor for `plan` over `graph` (the bare seam or an [`AuthorizedGraph`] wrapper), sends
/// the [`RunReply`] before the first row, then streams each row into `row_tx`.
///
/// Returns `true` if streaming completed with no **runtime** error (a consumer disconnect counts as
/// success — the caller handles the orphaned transaction). A compile/runtime error before the first
/// row goes through `reply`; a runtime error mid-stream goes through `row_tx`. Authorization denials
/// and seam-captured deferral errors are surfaced by the caller after this returns (they live on the
/// `graph`/wrapper, not in the runtime error channel).
#[allow(clippy::too_many_arguments)] // Threads the seam + extension registry + egress channel.
pub(super) fn run_cursor(
    plan: &graphus_cypher::PhysicalPlan,
    bound: &graphus_cypher::BoundParameters,
    graph: &mut dyn GraphAccess,
    extensions: &ExtensionRegistry,
    row_tx: &RowSender,
    row_rx: std::sync::mpsc::Receiver<super::stream::RowItem>,
    reply: Reply<Result<RunReply, GraphusError>>,
) -> bool {
    // The **same** registry that backed `compile` must back execution (`rmp` task #75), or the
    // compile-time function/procedure guarantees are void.
    let mut cursor = match execute_with_extensions(
        plan,
        bound,
        graph,
        extensions.functions_dyn(),
        extensions.procedures_dyn(),
    ) {
        Ok(c) => c,
        Err(e) => {
            let _ = reply.send(Err(GraphusError::Runtime(e.to_string())));
            return false;
        }
    };

    // The plan compiled and the cursor opened: hand the consumer its stream now, with the result
    // column names known up front (`04 §7.7`).
    let fields: Vec<String> = cursor.columns().to_vec();
    if reply
        .send(Ok(RunReply {
            fields,
            rows: RowReceiver::new(row_rx),
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
                // A closed channel (consumer gone) ends streaming early; not an error.
                if row_tx.send(Ok(cells)).is_err() {
                    return true;
                }
            }
            Ok(None) => break,
            Err(e) => {
                let _ = row_tx.send(Err(GraphusError::Runtime(e.to_string())));
                return false;
            }
        }
    }
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
    /// The first seam-captured deferral error seen across visits (the load-bearing `RecordStoreGraph`
    /// invariant), surfaced as the terminal item at finalization — rows precede it, byte-identically
    /// to the single-visit ordering.
    seam_error: Option<GraphusError>,
    /// `clock.now_nanos()` at statement start, for an accurate latency/slow-query log at finish.
    started_nanos: u64,
    /// The query string, kept for the slow-query log at finish.
    query: String,
}

/// How a single resume visit ended (`rmp` task #372): either the statement is fully done (the caller
/// finalises it), or it filled the channel again and stays suspended for a later tick.
enum BatchStep {
    /// The cursor exhausted (or the consumer disconnected, or a runtime/deferral error terminated the
    /// stream): `produced_ok` is `true` iff no runtime/deferral/auth error occurred, so the caller
    /// runs the auto-commit accordingly.
    Done { produced_ok: bool },
    /// The egress channel filled again; the statement stays suspended (state already stored back).
    Suspended,
}

/// Drives **one** resume batch of a suspended inline statement on the engine thread (`rmp` task
/// #372): opens a fresh seam for the same txn, re-binds the cursor, sends as many rows as the bounded
/// channel accepts (starting with any `pending_row`), and either re-suspends (channel full) or runs
/// to a terminal condition. On a terminal condition it finalises (auto-commit + latency/slow-log) and
/// returns; on re-suspension it stores the cursor state back into `inflight`.
///
/// Returns `true` while the statement is still in flight (stay subscribed), `false` once finalised.
pub(super) fn resume_inflight<
    D: BlockDevice + Send + Sync + 'static,
    S: LogSink + Send + Sync + 'static,
>(
    inflight: &mut InFlightInline,
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    extensions: &ExtensionRegistry,
    metrics: &Metrics,
    clock: &Arc<dyn Clock + Send + Sync>,
) -> bool {
    let step = run_batch(inflight, coordinator, extensions);
    match step {
        BatchStep::Suspended => true,
        BatchStep::Done { produced_ok } => {
            finalize_inflight(inflight, coordinator, open, produced_ok, metrics, clock);
            false
        }
    }
}

/// Runs one batch of a suspended statement: a fresh seam + (optional) [`AuthorizedGraph`] wrapper, the
/// cursor resumed over it, rows `try_send`-ed until the channel is `Full` (re-suspend) or the cursor
/// reaches a terminal condition. Pure batch mechanics; finalization (commit/log) is the caller's.
fn run_batch<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>(
    inflight: &mut InFlightInline,
    coordinator: &mut TxnCoordinator<D, S>,
    extensions: &ExtensionRegistry,
) -> BatchStep {
    // A fresh per-visit seam for the SAME txn: same MVCC snapshot, same uncommitted write buffer (the
    // writes a prior visit applied are owner-visible), so the cursor continues coherently. A seam
    // error here is terminal — surface it like a deferral error.
    let mut graph = match coordinator.statement(inflight.txn) {
        Ok(g) => g,
        Err(e) => {
            let _ = inflight.row_tx.send(Err(e));
            return BatchStep::Done { produced_ok: false };
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
                // in a single visit (after the rows already sent).
                let _ = inflight
                    .row_tx
                    .send(Err(GraphusError::Runtime(e.to_string())));
                return BatchStep::Done { produced_ok: false };
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
fn finalize_inflight<D: BlockDevice, S: LogSink>(
    inflight: &mut InFlightInline,
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    produced_ok: bool,
    metrics: &Metrics,
    clock: &Arc<dyn Clock + Send + Sync>,
) {
    // A seam-captured deferral error (the load-bearing `RecordStoreGraph` invariant) is the terminal
    // item, sent after every row — and it flips the statement to a failure so the auto-commit rolls
    // back rather than commits silently-wrong rows.
    let mut produced_ok = produced_ok;
    if produced_ok {
        if let Some(err) = inflight.seam_error.take() {
            let _ = inflight.row_tx.send(Err(err));
            produced_ok = false;
        }
    }

    // Auto-commit: commit on success, roll back on a runtime/deferral error — while `row_tx` is still
    // open so a commit failure (e.g. an SSI serialization abort) reaches the consumer as a terminal
    // error, never swallowed into a false success (`04 §1.3` step 6; the rmp #238 atomicity divergence).
    if inflight.auto_commit {
        finish_autocommit(
            coordinator,
            open,
            inflight.ticket,
            produced_ok,
            &inflight.row_tx,
            metrics,
        );
    }

    // Latency + slow-query log, measured from statement start (`04 §9` / NFR-10). Emitted at finish so
    // the latency spans the whole — possibly suspended — stream, exactly as the single-visit path.
    let elapsed = Duration::from_nanos(clock.now_nanos().saturating_sub(inflight.started_nanos));
    metrics.observe_query_latency(elapsed);
    if elapsed >= slow_threshold() {
        metrics.record_slow_query();
        tracing::warn!(
            target: "graphus::slow_query",
            duration_ms = elapsed.as_millis() as u64,
            query = %truncate_for_log(&inflight.query),
            "slow query",
        );
    }
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
/// A commit failure (an SSI serialization abort, or any [`TxnCoordinator::commit`] error) is **not**
/// swallowed: it is sent as a **terminal error** through the still-open egress channel `row_tx`, so
/// the consumer observes the auto-commit statement as failed and retriable. Reporting success for a
/// transaction the engine rolled back would be an atomicity/durability violation — the client would
/// believe a write is committed (and durable) when it was undone (`04 §1.3` step 6, ACID mandate).
/// This was the seed-4 VOPR `EdgeMultisetMismatch` divergence (rmp #238): an auto-commit
/// `CREATE (a)-[:KNOWS]->(b)` whose post-stream COMMIT lost the SSI dangerous-structure check was
/// acknowledged as committed, so the model recorded the edge the engine had rolled back.
fn finish_autocommit<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    ticket: TxTicket,
    produced_ok: bool,
    row_tx: &RowSender,
    metrics: &Metrics,
) {
    let Some(tx) = open.remove(&ticket.0) else {
        return;
    };
    if produced_ok {
        match coordinator.commit(tx.txn) {
            Ok(_) => metrics.record_commit(),
            Err(e) => {
                // The COMMIT failed (e.g. SSI serialization abort): the transaction has been rolled
                // back. Surface the failure to the consumer as a terminal stream error so the
                // statement is reported as failed/retriable — never a silent success over rolled-back
                // writes (`04 §1.3` step 6; the rmp #238 seed-4 atomicity divergence).
                let _ = row_tx.send(Err(e));
                metrics.record_abort();
            }
        }
    } else {
        let _ = coordinator.rollback(tx.txn);
        metrics.record_abort();
    }
}

/// Rolls back an auto-commit transaction that failed to compile/bind (so it never leaks). A no-op
/// for an explicit transaction (the caller still owns it).
fn finish_failed_autocommit<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    ticket: TxTicket,
    auto_commit: bool,
    metrics: &Metrics,
) {
    if !auto_commit {
        return;
    }
    if let Some(tx) = open.remove(&ticket.0) {
        let _ = coordinator.rollback(tx.txn);
        metrics.record_abort();
    }
}

/// Whether a physical plan performs writes (so a `READ` transaction can reject it — `06 §4`). A
/// write plan's root (or a nested write op) is one of the mutating operators.
fn plan_writes(plan: &graphus_cypher::PhysicalPlan) -> bool {
    op_writes(&plan.root)
}

/// Recursively checks whether `op` (or any input) is a mutating operator.
fn op_writes(op: &graphus_cypher::PhysicalOp) -> bool {
    use graphus_cypher::PhysicalOp as P;
    match op {
        P::Create { .. }
        | P::Merge { .. }
        | P::SetClause { .. }
        | P::Delete { .. }
        | P::Remove { .. } => true,
        // Recurse through the single-input operators.
        P::Filter { input, .. }
        | P::Projection { input, .. }
        | P::Skip { input, .. }
        | P::Limit { input, .. }
        | P::Sort { input, .. }
        | P::TopN { input, .. }
        | P::Optional { input, .. }
        | P::Unwind { input, .. }
        | P::Aggregation { input, .. } => op_writes(input),
        // The procedure-call operator may have an optional input.
        P::ProcedureCall { input, .. } => input.as_deref().is_some_and(op_writes),
        // Binary operators.
        P::NestedLoopJoin { left, right, .. }
        | P::HashJoin { left, right, .. }
        | P::Union { left, right, .. } => op_writes(left) || op_writes(right),
        // Leaves never write.
        _ => false,
    }
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
