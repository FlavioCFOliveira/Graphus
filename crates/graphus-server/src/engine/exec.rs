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
    AuthorizedGraph, GraphAccess, IndexCatalog, Parameters, PrivilegeOracle, ProcedureSignature,
    Statistics, TxnCoordinator, analyze_with_extensions, bind_parameters, execute_with_extensions,
    lower, parse_tokens, plan_physical_with_stats, tokenize,
};
use graphus_io::BlockDevice;
use graphus_wal::LogSink;

use super::command::{AccessMode, Reply};
use super::privileges::EffectivePrivileges;
use super::read_pool::{ReadDispatch, ReadTask};
use super::stream::{RowReceiver, RowSender};
use super::{OpenTx, RunReply, TxTicket};
use crate::metrics::Metrics;

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
) -> bool {
    // Resolve the open transaction.
    let Some(tx) = open.get(&ticket.0) else {
        let _ = reply.send(Err(GraphusError::Transaction(format!(
            "run in unknown transaction {}",
            ticket.0
        ))));
        return false;
    };
    let txn = tx.txn;
    let mode = tx.mode;

    // Compile + bind off any store borrow (pure pipeline). A compile error is raised before any side
    // effect, exactly as the TCK requires (`04 §7.3`). The catalog reflects the coordinator's current
    // indexes so the physical planner can pick index-accelerated strategies (`04 §6.6`), and the
    // coordinator's statistics seam activates the cost-based optimiser (`rmp` tasks #65/#82; each
    // statistics call borrows the store briefly, never across the compile).
    //
    // Plan-reuse policy: the server compiles per-`Run` today (no plan cache in this path), so the
    // statistics are as fresh as this compilation. If/when the plan cache is wired here, plans key
    // on the schema version and a stale-stats plan stays acceptable until invalidation — statistics
    // are advisory cost inputs only; every cost-based rewrite is bag-preserving.
    let catalog = coordinator.catalog();
    let stats = coordinator.statistics();
    let plan = match compile(query, &catalog, Some(&stats), extensions.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics);
            let _ = reply.send(Err(e));
            return false;
        }
    };
    let bound = match bind_parameters(&plan, &to_parameters(params)) {
        Ok(b) => b,
        Err(e) => {
            finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics);
            let _ = reply.send(Err(GraphusError::Runtime(e.to_string())));
            return false;
        }
    };

    // Reject a write in a read-only transaction (`06 §4`). The physical plan carries whether it
    // mutates; we detect it structurally via the plan's writes flag.
    if mode == AccessMode::Read && plan_writes(&plan) {
        finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics);
        let _ = reply.send(Err(GraphusError::Transaction(
            "write statement attempted in a READ transaction".to_owned(),
        )));
        return false;
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
                        // pinning the GC watermark until then. Return `true` so the loop tracks it as an
                        // in-flight reader (polls the retirement channel until it returns).
                        return true;
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
                return false;
            }
        }
    }
    // The inline locals (either we never dispatched off-thread, or the queue was full).
    let row_rx = row_rx.expect("egress receiver present on the inline path");
    let reply = reply.expect("reply present on the inline path");

    // Execute and stream. `produced_ok` is true iff streaming completed without a runtime error.
    // `stream_rows` opens the cursor, sends the `RunReply` (fields + receiver) over `reply` *before*
    // the first row (so the consumer can drain concurrently), then streams. A compile/runtime error
    // before the first row is delivered through `reply` instead.
    // Timing is taken from the **injected [`Clock`]** rather than `Instant::now()` so the whole
    // execution path is wall-clock-free and deterministically testable (`04 §11`): production passes a
    // [`crate::server::SystemClock`]-backed clock (latency is wall-nanos, equivalent to the previous
    // `Instant` source for metrics), while the deterministic [`super::LocalEngine`] passes a
    // `SimClock` so the measured latency — and therefore every observation — replays identically.
    let started = clock.now_nanos();
    let produced_ok = stream_rows(
        coordinator,
        txn,
        &plan,
        &bound,
        privileges,
        extensions.as_ref(),
        &row_tx,
        row_rx,
        reply,
    );

    let elapsed = Duration::from_nanos(clock.now_nanos().saturating_sub(started));
    metrics.observe_query_latency(elapsed);

    // Auto-commit: commit on success, roll back on a runtime error (`04 §1.3` step 6). The commit
    // runs while `row_tx` is still open so a commit failure (e.g. an SSI serialization abort) is
    // delivered to the consumer as a terminal stream error — never swallowed into a false success.
    if auto_commit {
        finish_autocommit(coordinator, open, ticket, produced_ok, &row_tx, metrics);
    }
    // Closing the egress channel: every row (and any terminal auto-commit error) has been sent.
    drop(row_tx);

    // Slow-query log (`04 §9` / NFR-10): emitted after the fact so the latency is accurate.
    if elapsed >= slow_threshold() {
        metrics.record_slow_query();
        tracing::warn!(
            target: "graphus::slow_query",
            duration_ms = elapsed.as_millis() as u64,
            query = %truncate_for_log(query),
            "slow query",
        );
    }
    // The statement ran inline on this engine thread (it was already committed/rolled back above), so
    // there is no off-thread reader to track.
    false
}

/// Compiles a query string into a physical plan via the full front-end pipeline (lex → parse →
/// analyze → lower → physical-plan), consulting `catalog` for index-aware strategy choices and
/// `stats` (the coordinator's statistics seam, `rmp` task #82) for cost-based plan refinement.
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

/// Opens the cursor for `plan` over a per-statement seam for `txn`, sends the [`RunReply`] (fields +
/// receiver) over `reply`, then streams each row into `row_tx`.
///
/// Sending the reply (with `cursor.columns()` as the fields) **before** the first row is what lets
/// the consumer drain the bounded egress channel concurrently with production (otherwise a full
/// channel would deadlock the engine thread against a consumer that never received its receiver). A
/// compile/runtime/transaction error that occurs before the first row is delivered through `reply` as
/// an `Err` (and `row_tx`/`row_rx` are dropped unused).
///
/// Returns `true` if execution completed with no runtime error (including the seam's captured-error
/// channel being clean), `false` otherwise. A full bounded `row_tx` blocks here — the intended egress
/// backpressure (`04 §9.3`).
#[allow(clippy::too_many_arguments)] // Threads the per-statement seam + privileges + egress channel.
fn stream_rows<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    txn: graphus_core::TxnId,
    plan: &graphus_cypher::PhysicalPlan,
    bound: &graphus_cypher::BoundParameters,
    privileges: Option<EffectivePrivileges>,
    extensions: &ExtensionRegistry,
    row_tx: &RowSender,
    row_rx: std::sync::mpsc::Receiver<super::stream::RowItem>,
    reply: Reply<Result<RunReply, GraphusError>>,
) -> bool {
    // Borrow the per-statement seam; it is dropped at the end of this scope (the transaction stays
    // open across statements — `coordinator.statement` doc).
    let mut graph = match coordinator.statement(txn) {
        Ok(g) => g,
        Err(e) => {
            let _ = reply.send(Err(e));
            return false;
        }
    };

    // RBAC enforcement (rmp #93): when a restricted principal's privileges are present, wrap the seam
    // in an `AuthorizedGraph` so every read/traversal is filtered and every denied write rejected at
    // the `GraphAccess` boundary — uniformly for all connection types. When `privileges` is `None`
    // (the internal/TCK/direct path) or the principal is unrestricted (an admin), no wrapper is
    // installed and the seam runs verbatim (zero overhead). The decorator's own write-denial error is
    // surfaced **in addition** to the seam's captured deferral error.
    //
    // The cursor borrows the graph (bare or wrapped) for the whole stream, so the streaming loop runs
    // inside a scope that drops the cursor (and the wrapper) before we inspect the seam's
    // `take_error`. `auth_error` carries any write denial back out of that scope.
    let mut auth_error: Option<GraphusError> = None;
    let produced_ok = match privileges {
        Some(privileges) if !privileges.is_unrestricted() => {
            let mut authz = AuthorizedGraph::new(&mut graph, privileges);
            let ok = run_cursor(plan, bound, &mut authz, extensions, row_tx, row_rx, reply);
            // Capture the decorator's write-denial (if any) before it is dropped at end of scope.
            auth_error = authz.take_auth_error();
            ok
        }
        // No restriction (no principal, or an admin): run the bare seam, byte-identically to today.
        _ => run_cursor(plan, bound, &mut graph, extensions, row_tx, row_rx, reply),
    };

    if !produced_ok {
        // A runtime error (or a disconnected consumer signalled as success) was already handled inside
        // `run_cursor`; nothing more to surface.
        return produced_ok;
    }

    // A denied write is a hard authorization failure: surface it as a terminal error item so the
    // statement is rolled back (never committed with a half-applied or skipped write). Checked before
    // the seam's deferral error because an authz denial is the more specific cause.
    if let Some(err) = auth_error {
        let _ = row_tx.send(Err(err));
        return false;
    }

    // The seam captures deferral errors rather than emitting silently-wrong rows (the load-bearing
    // `RecordStoreGraph` invariant); surface any as a runtime error terminal item.
    if let Some(err) = graph.take_error() {
        let _ = row_tx.send(Err(err));
        return false;
    }
    // The caller owns `row_tx`: for an auto-commit statement it runs the COMMIT next and, on a commit
    // failure (e.g. an SSI serialization abort), sends a terminal error through `row_tx` BEFORE
    // dropping it — so a rolled-back auto-commit is reported to the client as a failed statement, never
    // a silent success. When the caller drops `row_tx` the channel closes and the consumer's `recv`
    // ends.
    true
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
