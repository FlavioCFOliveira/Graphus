//! Per-`Run` execution on the engine thread: compile → bind → execute the Cypher pipeline against a
//! coordinator statement seam, stream rows over the bounded egress channel, and (for auto-commit)
//! commit when the stream is drained (`04-technical-design.md` §1.3 request lifecycle, §7.1 pipeline,
//! §7.7 streaming).
//!
//! All of this runs on the **single engine thread** (see [`super`]), so it may block freely (storage
//! I/O, the WAL group-commit `fdatasync`) without touching a Tokio runtime worker (`04 §9.1`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use graphus_core::error::GraphusError;
use graphus_cypher::{
    IndexCatalog, Parameters, Statistics, TxnCoordinator, analyze, bind_parameters, execute, lower,
    parse_tokens, plan_physical_with_stats, tokenize,
};
use graphus_io::BlockDevice;
use graphus_wal::LogSink;

use super::command::{AccessMode, Reply};
use super::stream::{RowReceiver, RowSender};
use super::{OpenTx, RunReply, TxTicket};
use crate::metrics::Metrics;

/// Handles a [`super::EngineCommand::Run`]: resolves the transaction, compiles + binds the query,
/// then streams its rows.
///
/// Sends the [`RunReply`] (fields + the row receiver) over `reply` **before** streaming any row, so
/// the consumer can start draining the bounded egress channel concurrently (otherwise the engine
/// thread would block on a full channel with no consumer). A compile/bind/transaction error that
/// occurs before the first row is delivered through `reply` as an `Err` instead.
#[allow(clippy::too_many_arguments)] // The engine loop threads all execution context through here.
pub(super) fn handle_run<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    ticket: TxTicket,
    query: &str,
    params: Vec<(String, graphus_core::Value)>,
    auto_commit: bool,
    result_buffer_capacity: usize,
    metrics: &Arc<Metrics>,
    reply: Reply<Result<RunReply, GraphusError>>,
) {
    // Resolve the open transaction.
    let Some(tx) = open.get(&ticket.0) else {
        let _ = reply.send(Err(GraphusError::Transaction(format!(
            "run in unknown transaction {}",
            ticket.0
        ))));
        return;
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
    let plan = match compile(query, &catalog, Some(&stats)) {
        Ok(p) => p,
        Err(e) => {
            finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics);
            let _ = reply.send(Err(e));
            return;
        }
    };
    let bound = match bind_parameters(&plan, &to_parameters(params)) {
        Ok(b) => b,
        Err(e) => {
            finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics);
            let _ = reply.send(Err(GraphusError::Runtime(e.to_string())));
            return;
        }
    };

    // Reject a write in a read-only transaction (`06 §4`). The physical plan carries whether it
    // mutates; we detect it structurally via the plan's writes flag.
    if mode == AccessMode::Read && plan_writes(&plan) {
        finish_failed_autocommit(coordinator, open, ticket, auto_commit, metrics);
        let _ = reply.send(Err(GraphusError::Transaction(
            "write statement attempted in a READ transaction".to_owned(),
        )));
        return;
    }

    // The egress channel: bounded for backpressure (`04 §9.3`).
    let (row_tx, row_rx) = std::sync::mpsc::sync_channel(result_buffer_capacity);

    // Execute and stream. `produced_ok` is true iff streaming completed without a runtime error.
    // `stream_rows` opens the cursor, sends the `RunReply` (fields + receiver) over `reply` *before*
    // the first row (so the consumer can drain concurrently), then streams. A compile/runtime error
    // before the first row is delivered through `reply` instead.
    let started = Instant::now();
    let produced_ok = stream_rows(coordinator, txn, &plan, &bound, row_tx, row_rx, reply);

    let elapsed = started.elapsed();
    metrics.observe_query_latency(elapsed);

    // Auto-commit: commit on success, roll back on a runtime error (`04 §1.3` step 6).
    if auto_commit {
        finish_autocommit(coordinator, open, ticket, produced_ok, metrics);
    }

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
}

/// Compiles a query string into a physical plan via the full front-end pipeline (lex → parse →
/// analyze → lower → physical-plan), consulting `catalog` for index-aware strategy choices and
/// `stats` (the coordinator's statistics seam, `rmp` task #82) for cost-based plan refinement.
fn compile(
    query: &str,
    catalog: &IndexCatalog,
    stats: Option<&dyn Statistics>,
) -> Result<graphus_cypher::PhysicalPlan, GraphusError> {
    let tokens = tokenize(query).map_err(|e| GraphusError::Compile(e.to_string()))?;
    let ast = parse_tokens(&tokens, query).map_err(|e| GraphusError::Compile(e.to_string()))?;
    let validated = analyze(&ast).map_err(|e| GraphusError::Compile(e.to_string()))?;
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
fn stream_rows<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    txn: graphus_core::TxnId,
    plan: &graphus_cypher::PhysicalPlan,
    bound: &graphus_cypher::BoundParameters,
    row_tx: RowSender,
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
    let mut cursor = match execute(plan, bound, &mut graph) {
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
        match cursor.next() {
            Ok(Some(row)) => {
                // Project the executor's `RowValue` row down to the public `Value` model (`04 §8.3`).
                let cells = project_row(&row);
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

    // The seam captures deferral errors rather than emitting silently-wrong rows (the load-bearing
    // `RecordStoreGraph` invariant); surface any as a runtime error terminal item.
    if let Some(err) = graph.take_error() {
        let _ = row_tx.send(Err(err));
        return false;
    }
    // `row_tx` drops here, closing the channel so the consumer's `recv` ends.
    true
}

/// Projects one executor [`graphus_cypher::Row`] (a `RowValue` superset) down to the public
/// `Vec<Value>` the wire seams carry (`04 §8.3`).
///
/// The structural `RowValue` variants (`Node`/`Rel`/`Path`/structural `List`) are **deferred in
/// `graphus_core::Value`** (`04 §7.2`); until the variants land, an entity is exposed as its id as a
/// `Value::Integer`, a structural list projects element-wise into a `Value::List`, and a path
/// projects into the `Value::List` of its element ids in traversal order (start node, then each
/// hop's relationship and arrival node) — matching how the Bolt/REST seams document the deferral. A
/// plain `Value` cell passes through.
fn project_row(row: &graphus_cypher::Row) -> Vec<graphus_core::Value> {
    row.values().iter().map(project_value).collect()
}

/// Projects one [`graphus_cypher::RowValue`] to a wire [`graphus_core::Value`] (see
/// [`project_row`]).
fn project_value(rv: &graphus_cypher::RowValue) -> graphus_core::Value {
    use graphus_core::Value;
    use graphus_cypher::RowValue;
    match rv {
        RowValue::Value(v) => v.clone(),
        // `NodeId`/`RelId` are `pub` newtypes over `u64`; expose the id until the structural
        // `Value` variants land (`04 §7.2`).
        RowValue::Node(n) => Value::Integer(n.id.0 as i64),
        RowValue::Rel(r) => Value::Integer(r.id.0 as i64),
        // A structural list projects element-wise; a path flattens to its element ids in traversal
        // order (start node, then each hop's relationship + arrival node).
        RowValue::List(items) => Value::List(items.iter().map(project_value).collect()),
        RowValue::Path(p) => {
            let mut ids = Vec::with_capacity(p.steps.len() * 2 + 1);
            ids.push(Value::Integer(p.start.0 as i64));
            for s in &p.steps {
                ids.push(Value::Integer(s.rel.0 as i64));
                ids.push(Value::Integer(s.node.0 as i64));
            }
            Value::List(ids)
        }
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
fn finish_autocommit<D: BlockDevice, S: LogSink>(
    coordinator: &mut TxnCoordinator<D, S>,
    open: &mut HashMap<u64, OpenTx>,
    ticket: TxTicket,
    produced_ok: bool,
    metrics: &Metrics,
) {
    let Some(tx) = open.remove(&ticket.0) else {
        return;
    };
    if produced_ok {
        match coordinator.commit(tx.txn) {
            Ok(_) => metrics.record_commit(),
            Err(_) => metrics.record_abort(),
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
