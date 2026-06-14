//! The Cypher **Volcano executor** (`04-technical-design.md` §7.4, §7.7).
//!
//! This is where queries actually run. [`execute`] turns a compiled [`PhysicalPlan`] plus its
//! [`BoundParameters`] into a [`Cursor`]
//! the caller pulls rows from on demand. Each [`PhysicalOp`] becomes an operator implementing the
//! iterator (Volcano) model — a `next()`-style cursor that produces one [`Row`] at a time
//! (`04 §7.4`):
//!
//! > *"Volcano (iterator) model for the operator tree: each operator is a `next()`-style cursor …
//! > it streams results lazily (essential for `PULL n` flow control …) and keeps memory bounded
//! > under large result sets."*
//!
//! # Streaming vs materialising operators
//!
//! Most operators are **streaming**: scans, `Filter`, `Projection` (non-distinct), `ExpandAll`,
//! `Unwind`, `Skip`, `Limit`, `Optional`, joins — they pull from their input and emit lazily, so a
//! `LIMIT 3` stops the whole pipeline after three rows (proven by the cancellation/limit tests).
//! A few operators are inherently **materialising** by their semantics: `Sort`/`TopN` must see all
//! input to order it, `Aggregation` must see a whole group, `DISTINCT` must remember what it has
//! emitted, and `HashJoin` must build its hash side. Those buffer exactly what their semantics
//! demand and no more (`04 §7.4`'s "stay tuple-at-a-time where semantics demand it").
//!
//! # Vectorised leaves (deferred, named)
//!
//! `04 §7.4` allows *"tuple-at-a-time first"* and flags vectorised leaf scans as the optimisation.
//! v1 is tuple-at-a-time throughout; batching of scans/visibility is a named follow-up that does not
//! change the result-set shape.
//!
//! # Result streaming, timeout & cancellation (`04 §7.7`)
//!
//! A [`Cursor`] is consumed at the client's demand rate via [`Cursor::pull`] (PULL `n`) /
//! [`Cursor::next`]. Every operator polls a [`CancellationToken`] at a **safe point** (between
//! rows); on a trip, `next` returns [`ExecError::Cancelled`] and the pipeline unwinds cleanly with
//! no panic. **Atomic rollback** of a half-applied write on cancellation is the *real* transaction
//! layer's job (`04 §7.7`: "the WAL undo guarantees atomic rollback"); the in-memory
//! [`MemGraph`](crate::graph_access::MemGraph) has no rollback, so a write cancelled mid-flight
//! leaves it as-is — this is **documented** and is exactly the seam sub-task #38 replaces.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use graphus_core::Value;

use crate::ast::{Expr, ExprKind, Label, RelDirection, RelType, SortDirection, VarLengthRange};
use crate::binding::BoundParameters;
use crate::eval::{EvalError, eval, eval_value};
use crate::function_registry::{self, FunctionRegistry};
use crate::graph_access::{ExpandDirection, GraphAccess, NodeId, RelId};
use crate::loadcsv::LoadCsvState;
use crate::logical::{CreatePart, ProjectionColumn, RemoveOp, SetOp, SortKey, Var, YieldColumn};
use crate::ordering::cmp_values;
use crate::physical::{PhysicalOp, PhysicalPlan, RangeBound};
use crate::procedure_registry::{self, ProcedureFailure, ProcedureRegistry};
use crate::runtime::{
    NodeRef, PathStep, PathValue, RelRef, Row, RowValue, cmp_row_values, row_values_equivalent,
};
use crate::ternary::Ternary;

/// A cooperative **cancellation token** shared between a caller and a running query (`04 §7.7`).
///
/// The caller holds a clone and trips it (e.g. on deadline / client disconnect / `RESET`); operators
/// poll [`is_cancelled`](Self::is_cancelled) at safe points (between rows). Cloning shares the same
/// underlying flag (an [`Arc<AtomicBool>`]), so a trip on any clone is observed by all. It is
/// `Send + Sync`, ready for the connectivity layer's `tokio::select!` timeout/abort branches.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
}

impl CancellationToken {
    /// A fresh, untripped token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Trips the token: every clone now observes [`is_cancelled`](Self::is_cancelled) as `true`.
    ///
    /// `Release` ordering pairs with the `Acquire` load in [`is_cancelled`](Self::is_cancelled) so a
    /// cancelling thread's prior writes are visible to the observing executor thread.
    pub fn cancel(&self) {
        self.flag.store(true, AtomicOrdering::Release);
    }

    /// Whether the token has been tripped.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(AtomicOrdering::Acquire)
    }
}

/// A **runtime** execution error (`04 §7.3` runtime phase; never a compile-time class).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExecError {
    /// An expression-evaluation runtime error ([`EvalError`]).
    Eval(EvalError),
    /// The query was cancelled (deadline / client abort / `RESET`); the pipeline unwound cleanly
    /// (`04 §7.7`).
    Cancelled,
    /// A `DELETE` of a node that still has incident relationships, without `DETACH` (`04 §7.3`).
    DeleteConnectedNode,
    /// A write expected a bound entity reference but the column held a non-entity value.
    NotAnEntity {
        /// A human description of the offending position.
        context: String,
    },
    /// A `CREATE`/`MERGE` inline property map was not a map value at runtime.
    PropertiesNotAMap,
    /// A `MERGE` pattern's inline property map evaluated to a **null** value for some key
    /// (`MERGE ({num: null})`, `MERGE (a)-[r:X {num: null}]->(b)`). `MERGE` cannot match-or-create on
    /// a null property predicate, so this is the runtime TCK `SemanticError: MergeReadOwnWrites`
    /// (`clauses/merge/Merge1` [17], `clauses/merge/Merge5` [29]). The value is only known once the
    /// map is evaluated, so the fault is necessarily runtime, not compile-time.
    MergeNullProperty,
    /// A `LOAD CSV` source could not be read: the URL was not a string, named a non-`file` scheme
    /// (rejected by the Neo4j `LOAD CSV` security model), the file was missing/unreadable, or a
    /// record failed to parse.
    LoadCsv {
        /// A human description of the failure (path / scheme / I/O / parse detail).
        reason: String,
    },
    /// A procedure invocation failed at runtime (`CALL …`; rmp #57): the registry rejected it
    /// (compile/execute registry mismatch — semantic analysis resolves names at compile time), a
    /// `YIELD` named a result field the signature does not declare, or the procedure body failed.
    Procedure(ProcedureFailure),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eval(e) => write!(f, "{e}"),
            Self::Cancelled => write!(f, "query cancelled"),
            Self::DeleteConnectedNode => write!(
                f,
                "cannot delete a node that still has relationships (use DETACH DELETE)"
            ),
            Self::NotAnEntity { context } => {
                write!(f, "expected a node or relationship: {context}")
            }
            Self::PropertiesNotAMap => write!(f, "inline properties must be a map"),
            Self::MergeNullProperty => write!(
                f,
                "MERGE cannot use a null property value as a match predicate (MergeReadOwnWrites)"
            ),
            Self::LoadCsv { reason } => write!(f, "LOAD CSV failed: {reason}"),
            Self::Procedure(failure) => write!(f, "{failure}"),
        }
    }
}

impl std::error::Error for ExecError {}

impl From<EvalError> for ExecError {
    fn from(e: EvalError) -> Self {
        ExecError::Eval(e)
    }
}

impl From<ExecError> for graphus_core::GraphusError {
    /// Every [`ExecError`] is a Cypher **runtime** error (`04 §7.3`).
    fn from(e: ExecError) -> Self {
        graphus_core::GraphusError::Runtime(e.to_string())
    }
}

/// The shared, per-execution context every operator threads through `next`: the bound parameters,
/// the cancellation token, the live graph seam, the extension-function registry, and the procedure
/// registry.
///
/// The graph is a `&mut dyn GraphAccess` so write operators can mutate it; read operators take it
/// by shared reborrow. Bundling it keeps the operator `next` signature small.
struct Ctx<'a> {
    params: &'a BoundParameters,
    token: &'a CancellationToken,
    graph: &'a mut dyn GraphAccess,
    /// The extension-function registry (`rmp` task #75): consulted by [`crate::eval`] for a
    /// user-defined scalar function call (after the built-ins, which take precedence).
    functions: &'a dyn FunctionRegistry,
    procedures: &'a dyn ProcedureRegistry,
}

impl Ctx<'_> {
    /// Polls the cancellation token at a safe point; `Err(Cancelled)` unwinds the pipeline.
    fn check_cancelled(&self) -> Result<(), ExecError> {
        if self.token.is_cancelled() {
            Err(ExecError::Cancelled)
        } else {
            Ok(())
        }
    }
}

// =================================================================================================
// Operator state machine (the Volcano cursors)
// =================================================================================================

/// One operator's runtime state. Each variant is a `next()`-style cursor (`04 §7.4`); streaming
/// variants hold their child operator(s) boxed and pull lazily, materialising variants buffer the
/// minimum their semantics require.
enum Operator {
    /// A pre-computed queue of rows (used for leaf scans, and for materialised results of
    /// `Sort`/`TopN`/`Aggregation`/`DISTINCT`/`HashJoin`/`Union`-distinct). Lazily *drained*.
    Buffered { rows: VecDeque<Row> },

    /// The single empty row, emitted once.
    SingleRow { emitted: bool, row: Row },

    /// `Filter`: pull from `input`, keep rows whose predicate is `TRUE` (3VL).
    Filter {
        input: Box<Operator>,
        predicate: Expr,
    },

    /// Streaming `Projection` (non-distinct): map each input row to the projected columns.
    Project {
        input: Box<Operator>,
        items: Vec<ProjectionColumn>,
    },

    /// `Skip`: drop the first `count` input rows, then stream the rest.
    Skip {
        input: Box<Operator>,
        remaining: i64,
        primed: bool,
        count_expr: Expr,
    },

    /// `Limit`: stream at most `count` rows, then stop (early termination).
    Limit {
        input: Box<Operator>,
        remaining: i64,
        primed: bool,
        count_expr: Expr,
    },

    /// `Unwind`: for each input row, expand `list` into one row per element.
    Unwind {
        input: Box<Operator>,
        list: Expr,
        variable: Var,
        current: Option<(Row, VecDeque<RowValue>)>,
    },

    /// `LoadCsv`: for each input row, resolve the URL to a local file and stream it, emitting one
    /// output row per CSV record bound to `variable` (a `List` of fields, or a `Map{header -> field}`
    /// when `with_headers`). The reader streams record-by-record (never slurps), so a large file does
    /// not blow memory; `current` holds the driving row plus the open reader + decoded headers.
    LoadCsv {
        input: Box<Operator>,
        with_headers: bool,
        url: Expr,
        variable: Var,
        field_terminator: u8,
        current: Option<LoadCsvState>,
    },

    /// `ExpandAll`/`ExpandInto`: for each input row, enumerate incident relationships. A
    /// variable-length `range` (`-[*m..n]->`) enumerates **trails** (relationship-unique paths)
    /// instead, binding the relationship variable to the list of traversed relationships.
    Expand {
        input: Box<Operator>,
        from: Var,
        relationship: Var,
        to: Var,
        direction: RelDirection,
        types: Vec<RelType>,
        into: bool,
        range: Option<VarLengthRange>,
        /// Relationship variables bound by earlier links of the same MATCH pattern. A candidate
        /// relationship already bound to one of these on the driving row is skipped (relationship
        /// isomorphism — a relationship may be traversed at most once per pattern).
        prior_rels: Vec<Var>,
        /// A var-length hop's inline relationship-property map, applied to **each** relationship of
        /// the path during expansion (`None` for a fixed-length hop).
        rel_props: Option<Expr>,
        pending: VecDeque<Row>,
    },

    /// `ShortestPath`/`allShortestPaths`: for each input row (both endpoints already bound), run a
    /// breadth-first search from `from` to `to` honouring `direction`, `types` and the `range` length
    /// bounds, with node-uniqueness within a path (openCypher `shortestPath` semantics). For
    /// `all = false` it emits a single minimal-length path; for `all = true` it emits every path of
    /// that minimal length (one row each). Each produced row binds `relationship` to the path's
    /// relationship list and, when present, `path` to the reconstructed path value. No path within the
    /// bounds emits no row (a plain `MATCH` filters it out; an `OPTIONAL MATCH` null-fills it through
    /// the usual optional machinery).
    ShortestPath {
        input: Box<Operator>,
        from: Var,
        to: Var,
        relationship: Var,
        path: Option<Var>,
        direction: RelDirection,
        types: Vec<RelType>,
        range: VarLengthRange,
        all: bool,
        pending: VecDeque<Row>,
    },

    /// `NamedPath`: for each input row, reconstruct the path value bound by `MATCH p = …` from the
    /// pattern part's `start` node and `steps` relationship bindings, binding `variable` to it.
    NamedPath {
        input: Box<Operator>,
        variable: Var,
        start: Var,
        steps: Vec<Var>,
    },

    /// `Optional` (left-outer guarantee): emit the input's rows, or one null-filled row if empty.
    Optional {
        input: Box<Operator>,
        null_variables: Vec<Var>,
        produced_any: bool,
        exhausted: bool,
    },

    /// `NestedLoopJoin`: for each left row, run the right branch with the left bindings available.
    NestedLoop {
        left: Box<Operator>,
        right_template: Box<PhysicalOp>,
        current_left: Option<Row>,
        current_right: Option<Box<Operator>>,
    },

    /// A write operator (`Create`/`Merge`/`SetClause`/`Delete`/`Remove`), applied once per input row.
    ///
    /// A `MERGE` can emit **more than one** row for a single input row: when its pattern matches
    /// several existing entities (e.g. two relationships satisfy `MERGE (a)-[r:T]->(b)`), it binds
    /// **all** matches, one output row each (`clauses/merge/Merge5` [3]). The `pending` queue holds the
    /// not-yet-emitted rows of the current input row; every other write kind produces exactly one row
    /// and leaves the queue empty.
    Write {
        input: Box<Operator>,
        kind: WriteKind,
        pending: VecDeque<Row>,
    },

    /// `CALL proc(args) [YIELD …]` (rmp #57): for each driving row, evaluate the arguments, invoke
    /// the procedure through the registry, and stream one output row per procedure result row —
    /// the driving row extended with the `bindings` columns. A **void** procedure (no declared
    /// outputs) is invoked for its effect and passes the driving row through once (openCypher
    /// `test.doNothing()` semantics). A leading/standalone call's `input` is a [`Self::SingleRow`].
    ProcedureCall {
        input: Box<Operator>,
        /// The dotted procedure name.
        name: String,
        /// The argument expressions, evaluated per driving row (semantic analysis already resolved
        /// the implicit form to parameter expressions).
        args: Vec<Expr>,
        /// The output bindings, resolved at build time: `(variable name, index into the procedure's
        /// result row, is_node)`. `is_node` is `true` when the bound output column's declared class is
        /// [`ValueClass::Node`](crate::procedure_registry::ValueClass::Node) (`rmp` task #72): the
        /// yielded id [`Value`] is then bound as a structural [`RowValue::Node`] (so result egress
        /// materializes it, composing MVCC + RBAC), instead of a plain [`RowValue::Value`].
        bindings: Vec<(String, usize, bool)>,
        /// `true` when the signature declares no outputs (the void pass-through case).
        void: bool,
        /// The driving row plus its pending procedure result rows.
        current: Option<(Row, VecDeque<Vec<Value>>)>,
    },
}

/// The kind of write a [`Operator::Write`] performs (mirrors the write [`PhysicalOp`]s).
#[derive(Clone)]
enum WriteKind {
    Create {
        pattern: Vec<CreatePart>,
    },
    Merge {
        pattern: Vec<CreatePart>,
        on_create: Vec<SetOp>,
        on_match: Vec<SetOp>,
    },
    Set {
        ops: Vec<SetOp>,
    },
    Delete {
        detach: bool,
        exprs: Vec<Expr>,
    },
    Remove {
        ops: Vec<RemoveOp>,
    },
}

impl Operator {
    /// Pulls the next row, or `None` at end of stream. Polls cancellation at every safe point.
    fn next(&mut self, ctx: &mut Ctx<'_>) -> Result<Option<Row>, ExecError> {
        ctx.check_cancelled()?;
        match self {
            Operator::Buffered { rows } => Ok(rows.pop_front()),

            Operator::SingleRow { emitted, row } => {
                if *emitted {
                    Ok(None)
                } else {
                    *emitted = true;
                    Ok(Some(row.clone()))
                }
            }

            Operator::Filter { input, predicate } => {
                while let Some(row) = input.next(ctx)? {
                    ctx.check_cancelled()?;
                    let t = predicate_truth(predicate, &row, ctx)?;
                    if t.is_true() {
                        return Ok(Some(row));
                    }
                }
                Ok(None)
            }

            Operator::Project { input, items } => {
                if let Some(row) = input.next(ctx)? {
                    Ok(Some(project_row(&row, items, ctx)?))
                } else {
                    Ok(None)
                }
            }

            Operator::NamedPath {
                input,
                variable,
                start,
                steps,
            } => {
                if let Some(mut row) = input.next(ctx)? {
                    let path = reconstruct_named_path(&row, start, steps, &*ctx.graph);
                    row.set(variable.name.clone(), path);
                    Ok(Some(row))
                } else {
                    Ok(None)
                }
            }

            Operator::Skip {
                input,
                remaining,
                primed,
                count_expr,
            } => {
                if !*primed {
                    *remaining = eval_count(count_expr, ctx)?;
                    *primed = true;
                }
                while *remaining > 0 {
                    if input.next(ctx)?.is_none() {
                        return Ok(None);
                    }
                    *remaining -= 1;
                }
                input.next(ctx)
            }

            Operator::Limit {
                input,
                remaining,
                primed,
                count_expr,
            } => {
                if !*primed {
                    *remaining = eval_count(count_expr, ctx)?;
                    *primed = true;
                }
                if *remaining <= 0 {
                    return Ok(None);
                }
                match input.next(ctx)? {
                    Some(row) => {
                        *remaining -= 1;
                        Ok(Some(row))
                    }
                    None => Ok(None),
                }
            }

            Operator::Unwind {
                input,
                list,
                variable,
                current,
            } => loop {
                if let Some((base, queue)) = current {
                    if let Some(v) = queue.pop_front() {
                        return Ok(Some(base.with(variable.name.clone(), v)));
                    }
                    *current = None;
                }
                let Some(base) = input.next(ctx)? else {
                    return Ok(None);
                };
                // Evaluate the list **structurally** (`eval`, not `eval_value`) so a list of nodes /
                // relationships / paths is preserved — collapsing through a property `Value` would
                // turn each entity into `Null` (regression guard: `UNWIND collect(node) AS x`).
                let listv = eval(list, &base, ctx.params, ctx.graph, ctx.functions)?;
                let elems = match listv.as_list_elems() {
                    Some(items) => VecDeque::from(items),
                    // UNWIND null produces no rows for that input row (Cypher).
                    None if matches!(listv, RowValue::Value(Value::Null)) => VecDeque::new(),
                    // UNWIND of a scalar yields a single row (Cypher treats it as a one-element list).
                    None => VecDeque::from(vec![listv]),
                };
                if !elems.is_empty() {
                    *current = Some((base, elems));
                }
            },

            Operator::LoadCsv {
                input,
                with_headers,
                url,
                variable,
                field_terminator,
                current,
            } => loop {
                // Drain the open CSV stream first, fanning each record across the driving row.
                if let Some(state) = current {
                    if let Some(rv) = state.next_record()? {
                        return Ok(Some(state.base.with(variable.name.clone(), rv)));
                    }
                    // Stream exhausted: close it and advance to the next driving row.
                    *current = None;
                }
                let Some(base) = input.next(ctx)? else {
                    return Ok(None);
                };
                // The URL is evaluated per driving row (it may reference the row's bindings), then the
                // file is resolved and opened — transactionally, inside the statement's graph seam.
                let url_value = eval_value(url, &base, ctx.params, ctx.graph, ctx.functions)?;
                let state = LoadCsvState::open(base, &url_value, *field_terminator, *with_headers)?;
                *current = Some(state);
            },

            Operator::Expand {
                input,
                from,
                relationship,
                to,
                direction,
                types,
                into,
                range,
                prior_rels,
                rel_props,
                pending,
            } => loop {
                if let Some(row) = pending.pop_front() {
                    return Ok(Some(row));
                }
                let Some(base) = input.next(ctx)? else {
                    return Ok(None);
                };
                // A relationship variable **already bound on the input** (reused from a prior clause,
                // e.g. `MATCH ()-[r]-() MATCH (a)-[r]-(b)`, or a list `MATCH (a)-[rs*]->(b)` with
                // `rs` bound to a relationship list) constrains the traversal to exactly that
                // relationship / list rather than enumerating fresh ones (TCK `Match4` [7]/[8]).
                if base.get(&relationship.name).is_some() {
                    bound_rel_expand(
                        &base,
                        from,
                        relationship,
                        to,
                        *direction,
                        types,
                        *into,
                        range.is_some(),
                        prior_rels,
                        ctx,
                        pending,
                    )?;
                } else if let Some(range) = range {
                    var_expand_into_pending(
                        &base,
                        from,
                        relationship,
                        to,
                        *direction,
                        types,
                        *into,
                        *range,
                        prior_rels,
                        rel_props.as_ref(),
                        ctx,
                        pending,
                    )?;
                } else {
                    expand_into_pending(
                        &base,
                        from,
                        relationship,
                        to,
                        *direction,
                        types,
                        *into,
                        prior_rels,
                        ctx,
                        pending,
                    )?;
                }
            },

            Operator::ShortestPath {
                input,
                from,
                to,
                relationship,
                path,
                direction,
                types,
                range,
                all,
                pending,
            } => loop {
                if let Some(row) = pending.pop_front() {
                    return Ok(Some(row));
                }
                let Some(base) = input.next(ctx)? else {
                    return Ok(None);
                };
                shortest_paths_into_pending(
                    &base,
                    from,
                    to,
                    relationship,
                    path,
                    *direction,
                    types,
                    *range,
                    *all,
                    ctx,
                    pending,
                )?;
            },

            Operator::Optional {
                input,
                null_variables,
                produced_any,
                exhausted,
            } => {
                if *exhausted {
                    return Ok(None);
                }
                match input.next(ctx)? {
                    Some(row) => {
                        *produced_any = true;
                        Ok(Some(row))
                    }
                    None => {
                        *exhausted = true;
                        if *produced_any {
                            Ok(None)
                        } else {
                            // Left-outer guarantee: one null-filled row when the input produced none.
                            let mut row = Row::empty();
                            for v in null_variables.iter() {
                                row.set(v.name.clone(), RowValue::NULL);
                            }
                            Ok(Some(row))
                        }
                    }
                }
            }

            Operator::NestedLoop {
                left,
                right_template,
                current_left,
                current_right,
            } => loop {
                if let (Some(left_row), Some(right_op)) =
                    (current_left.as_ref(), current_right.as_mut())
                {
                    if let Some(right_row) = right_op.next(ctx)? {
                        return Ok(Some(merge_rows(left_row, &right_row)));
                    }
                    // This left row's right branch is exhausted; advance the left.
                    *current_right = None;
                }
                let Some(left_row) = left.next(ctx)? else {
                    return Ok(None);
                };
                // Re-instantiate the right branch seeded with the left row's bindings (correlation
                // via the Argument leaf), then loop to drain it.
                let right_op = build_operator_with_arg(right_template, &left_row, ctx)?;
                *current_left = Some(left_row);
                *current_right = Some(Box::new(right_op));
            },

            Operator::Write {
                input,
                kind,
                pending,
            } => {
                loop {
                    // Drain any rows the previous input row fanned out (a multi-match MERGE) first.
                    if let Some(row) = pending.pop_front() {
                        return Ok(Some(row));
                    }
                    let Some(row) = input.next(ctx)? else {
                        return Ok(None);
                    };
                    let mut out = apply_write(kind, row, ctx)?;
                    // The common case is a single output row; fan-out (multi-match MERGE) queues the
                    // rest. An empty `out` (no row produced) loops to the next input row.
                    if out.is_empty() {
                        continue;
                    }
                    let first = out.remove(0);
                    pending.extend(out);
                    return Ok(Some(first));
                }
            }

            Operator::ProcedureCall {
                input,
                name,
                args,
                bindings,
                void,
                current,
            } => loop {
                // Drain the pending result rows of the current driving row first.
                if let Some((base, queue)) = current {
                    if let Some(out) = queue.pop_front() {
                        let mut row = base.clone();
                        for (variable, idx, is_node) in bindings.iter() {
                            // `idx` was resolved against the signature's outputs at build time and
                            // the registry contract aligns each result row with them, so a short
                            // row is a registry bug — surface `null` rather than panic.
                            let value = out.get(*idx).cloned().unwrap_or(Value::Null);
                            // A `NODE`-classed output (`rmp` task #72) carries the node id as a
                            // `Value::Integer`; bind it as a structural `RowValue::Node` so result
                            // egress materializes it (labels/properties through the same seam,
                            // composing MVCC + RBAC). A `null` id (no node) stays a null cell.
                            let cell = match (is_node, &value) {
                                (true, Value::Integer(id)) => RowValue::Node(NodeRef {
                                    id: NodeId(*id as u64),
                                }),
                                _ => RowValue::Value(value),
                            };
                            row.set(variable.clone(), cell);
                        }
                        return Ok(Some(row));
                    }
                    *current = None;
                }
                let Some(base) = input.next(ctx)? else {
                    return Ok(None);
                };
                // Arguments are evaluated per driving row (they may reference its bindings), then
                // collapsed to property values — the v1 procedure argument domain.
                let mut arg_values = Vec::with_capacity(args.len());
                for a in args.iter() {
                    arg_values.push(eval_value(a, &base, ctx.params, ctx.graph, ctx.functions)?);
                }
                let rows = ctx
                    .procedures
                    .invoke(name, &arg_values, &mut *ctx.graph)
                    .map_err(ExecError::Procedure)?;
                if *void {
                    // VOID procedure: invoked for its effect; the driving row passes through once
                    // (openCypher `test.doNothing()` semantics — cardinality is preserved).
                    return Ok(Some(base));
                }
                if !rows.is_empty() {
                    *current = Some((base, VecDeque::from(rows)));
                }
            },
        }
    }
}

/// Evaluates a `SKIP`/`LIMIT`/`TopN` count expression to a non-negative `i64` (binding validated it).
fn eval_count(expr: &Expr, ctx: &mut Ctx<'_>) -> Result<i64, ExecError> {
    match eval_value(expr, &Row::empty(), ctx.params, ctx.graph, ctx.functions)? {
        Value::Integer(n) if n >= 0 => Ok(n),
        // A negative or non-integer count is a runtime type error (binding catches the param case;
        // a literal/expression case is caught here).
        _ => Err(ExecError::Eval(EvalError::TypeError {
            context: "SKIP/LIMIT count must be a non-negative integer".to_owned(),
        })),
    }
}

/// Evaluates a predicate to a [`Ternary`] (3VL): non-boolean non-null is a runtime type error.
fn predicate_truth(expr: &Expr, row: &Row, ctx: &mut Ctx<'_>) -> Result<Ternary, ExecError> {
    match eval(expr, row, ctx.params, ctx.graph, ctx.functions)? {
        RowValue::Value(Value::Boolean(b)) => Ok(Ternary::from_bool(b)),
        RowValue::Value(Value::Null) => Ok(Ternary::Null),
        _ => Err(ExecError::Eval(EvalError::TypeError {
            context: "WHERE/predicate must be a boolean".to_owned(),
        })),
    }
}

/// Projects a row to the output columns, evaluating each item against the input row.
fn project_row(row: &Row, items: &[ProjectionColumn], ctx: &mut Ctx<'_>) -> Result<Row, ExecError> {
    let mut out = Row::empty();
    for col in items {
        let v = eval(&col.expr, row, ctx.params, ctx.graph, ctx.functions)?;
        out.set(col.alias.clone(), v);
    }
    Ok(out)
}

/// Merges two rows (left then right); right bindings win on a name clash (the right branch's view).
fn merge_rows(left: &Row, right: &Row) -> Row {
    let mut out = left.clone();
    for (name, value) in right.columns().iter().zip(right.values().iter()) {
        out.set(name.clone(), value.clone());
    }
    out
}

/// Expands one base row's incident relationships into `pending`. For `ExpandInto`, only edges whose
/// far endpoint equals the already-bound `to` are kept (a connection check).
/// Collects the relationship ids already bound to `prior_rels` on `base` — the relationships earlier
/// links of the same MATCH pattern have traversed. A variable bound to a single relationship
/// contributes its id; one bound to a variable-length relationship list contributes every id in the
/// list. Used to enforce relationship isomorphism: a hop must not re-traverse any of these.
fn used_relationships(base: &Row, prior_rels: &[Var]) -> std::collections::BTreeSet<RelId> {
    fn collect(v: &RowValue, out: &mut std::collections::BTreeSet<RelId>) {
        match v {
            RowValue::Rel(r) => {
                out.insert(r.id);
            }
            RowValue::List(items) => items.iter().for_each(|item| collect(item, out)),
            _ => {}
        }
    }
    let mut out = std::collections::BTreeSet::new();
    for var in prior_rels {
        if let Some(v) = base.get(&var.name) {
            collect(v, &mut out);
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn expand_into_pending(
    base: &Row,
    from: &Var,
    relationship: &Var,
    to: &Var,
    direction: RelDirection,
    types: &[RelType],
    into: bool,
    prior_rels: &[Var],
    ctx: &mut Ctx<'_>,
    pending: &mut VecDeque<Row>,
) -> Result<(), ExecError> {
    let Some(anchor) = base.get(&from.name).and_then(RowValue::as_node) else {
        // The anchor is unbound / not a node (e.g. null from an OPTIONAL); emit nothing.
        return Ok(());
    };
    let target = if into {
        base.get(&to.name).and_then(RowValue::as_node)
    } else {
        None
    };
    // Relationships already traversed by earlier links of the same pattern — none of which this hop
    // may re-use (relationship isomorphism, `04 §2.4`).
    let used = used_relationships(base, prior_rels);
    let type_names: Vec<String> = types.iter().map(|t| t.name.clone()).collect();
    let dir = ExpandDirection::from_pattern(direction);
    let incidents = ctx.graph.expand(anchor, dir, &type_names);
    // Deduplicate self-loops reported once per side (`04 §2.4`): a relationship id appears at most
    // once per produced row set for this anchor.
    let mut seen_rel = std::collections::BTreeSet::new();
    for inc in incidents {
        if !seen_rel.insert(inc.rel) {
            continue;
        }
        if used.contains(&inc.rel) {
            continue;
        }
        if into && Some(inc.neighbour) != target {
            continue;
        }
        let mut row = base.clone();
        row.set(
            relationship.name.clone(),
            RowValue::Rel(RelRef { id: inc.rel }),
        );
        if !into {
            row.set(
                to.name.clone(),
                RowValue::Node(NodeRef { id: inc.neighbour }),
            );
        }
        pending.push_back(row);
    }
    Ok(())
}

/// Expands one base row's **variable-length** pattern (`-[r:T*m..n]->`) into `pending`: a
/// depth-first enumeration of the trails (relationship-unique walks, openCypher uniqueness) from
/// the anchor whose hop count lies in `[min, max]`. Each produced row binds the relationship
/// variable to the **list** of traversed relationships (in order) and — for expand-all — the far
/// endpoint to `to`; for expand-into only trails ending at the already-bound `to` are kept. A
/// `min` of 0 admits the zero-length trail (the anchor itself, an empty relationship list).
///
/// Trail semantics bound the search depth by the relationship count, so an unbounded `*`
/// terminates on any graph (cycles included).
#[allow(clippy::too_many_arguments)]
fn var_expand_into_pending(
    base: &Row,
    from: &Var,
    relationship: &Var,
    to: &Var,
    direction: RelDirection,
    types: &[RelType],
    into: bool,
    range: VarLengthRange,
    prior_rels: &[Var],
    rel_props: Option<&Expr>,
    ctx: &mut Ctx<'_>,
    pending: &mut VecDeque<Row>,
) -> Result<(), ExecError> {
    let Some(anchor) = base.get(&from.name).and_then(RowValue::as_node) else {
        // The anchor is unbound / not a node (e.g. null from an OPTIONAL); emit nothing.
        return Ok(());
    };
    let target = if into {
        base.get(&to.name).and_then(RowValue::as_node)
    } else {
        None
    };
    // Relationships earlier links of the same pattern already traversed — forbidden in this walk
    // (relationship isomorphism spans the whole pattern, not just this variable-length segment).
    let forbidden = used_relationships(base, prior_rels);
    let type_names: Vec<String> = types.iter().map(|t| t.name.clone()).collect();
    let dir = ExpandDirection::from_pattern(direction);
    let min = range.min.unwrap_or(1);

    // The DFS worker: `trail` is the relationship stack (ids, traversal order).
    #[allow(clippy::too_many_arguments)]
    fn dfs(
        depth: u64,
        current: NodeId,
        trail: &mut Vec<crate::graph_access::RelId>,
        min: u64,
        max: Option<u64>,
        target: Option<NodeId>,
        dir: ExpandDirection,
        type_names: &[String],
        forbidden: &std::collections::BTreeSet<RelId>,
        rel_props: Option<&Expr>,
        base: &Row,
        relationship: &Var,
        to: &Var,
        into: bool,
        ctx: &mut Ctx<'_>,
        pending: &mut VecDeque<Row>,
    ) -> Result<(), ExecError> {
        ctx.check_cancelled()?;
        if depth >= min && (!into || Some(current) == target) {
            let mut row = base.clone();
            row.set(
                relationship.name.clone(),
                RowValue::list(
                    trail
                        .iter()
                        .map(|&id| RowValue::Rel(RelRef { id }))
                        .collect(),
                ),
            );
            if !into {
                row.set(to.name.clone(), RowValue::Node(NodeRef { id: current }));
            }
            pending.push_back(row);
        }
        if max.is_some_and(|m| depth >= m) {
            return Ok(());
        }
        // Deduplicate self-loops reported once per side (`04 §2.4`); the trail check enforces
        // relationship uniqueness across the whole walk.
        let mut seen_rel = std::collections::BTreeSet::new();
        let incidents = ctx.graph.expand(current, dir, type_names);
        for inc in incidents {
            if !seen_rel.insert(inc.rel) || trail.contains(&inc.rel) || forbidden.contains(&inc.rel)
            {
                continue;
            }
            // A var-length hop's inline property map must hold for **every** relationship of the
            // path: skip a relationship that does not satisfy it (`Match4` [5]).
            if let Some(props) = rel_props {
                if !rel_satisfies_props(inc.rel, props, base, relationship, ctx)? {
                    continue;
                }
            }
            trail.push(inc.rel);
            dfs(
                depth + 1,
                inc.neighbour,
                trail,
                min,
                max,
                target,
                dir,
                type_names,
                forbidden,
                rel_props,
                base,
                relationship,
                to,
                into,
                ctx,
                pending,
            )?;
            trail.pop();
        }
        Ok(())
    }

    dfs(
        0,
        anchor,
        &mut Vec::new(),
        min,
        range.max,
        target,
        dir,
        &type_names,
        &forbidden,
        rel_props,
        base,
        relationship,
        to,
        into,
        ctx,
        pending,
    )
}

/// Expands a hop whose relationship variable is **already bound on the input row** — a relationship
/// reused from a prior clause (`MATCH ()-[r]-() MATCH (a)-[r]-(b)`) or a bound relationship **list**
/// driving a variable-length hop (`WITH [r1, r2] AS rs MATCH (a)-[rs*]->(b)`). Rather than
/// enumerating fresh relationships, the traversal walks exactly the bound relationship(s) in order
/// from `from`, honouring the pattern `direction` and `types`, and emits one row binding `to` to the
/// final endpoint (and, for `into`, only when that endpoint equals the already-bound `to`). Any
/// mismatch (a relationship not incident in the required direction, a type filter failure, an
/// already-used relationship, or — for the list form — a list element that is not a relationship)
/// yields no row.
#[allow(clippy::too_many_arguments)]
fn bound_rel_expand(
    base: &Row,
    from: &Var,
    relationship: &Var,
    to: &Var,
    direction: RelDirection,
    types: &[RelType],
    into: bool,
    var_length: bool,
    prior_rels: &[Var],
    ctx: &mut Ctx<'_>,
    pending: &mut VecDeque<Row>,
) -> Result<(), ExecError> {
    let Some(mut current) = base.get(&from.name).and_then(RowValue::as_node) else {
        return Ok(());
    };
    // The bound relationship(s), in traversal order.
    let bound = base.get(&relationship.name);
    let rel_ids: Vec<RelId> = match bound {
        Some(RowValue::Rel(r)) => vec![r.id],
        Some(other) => match other.as_list_elems() {
            Some(elems) => {
                let mut ids = Vec::with_capacity(elems.len());
                for e in &elems {
                    let Some(id) = e.as_rel() else {
                        return Ok(()); // a non-relationship element cannot drive a relationship hop
                    };
                    ids.push(id);
                }
                ids
            }
            None => return Ok(()),
        },
        None => return Ok(()),
    };
    // Relationship isomorphism still applies against earlier links of the same pattern.
    let used = used_relationships(base, prior_rels);
    let type_ok = |t: &str| types.is_empty() || types.iter().any(|rt| rt.name == t);

    // Walk each bound relationship, advancing `current` through its endpoints.
    for rel in &rel_ids {
        if used.contains(rel) {
            return Ok(());
        }
        let Some(data) = ctx.graph.rel_data(*rel) else {
            return Ok(());
        };
        if !type_ok(&data.rel_type) {
            return Ok(());
        }
        let next = match direction {
            RelDirection::LeftToRight if data.start == current => data.end,
            RelDirection::RightToLeft if data.end == current => data.start,
            RelDirection::Undirected if data.start == current => data.end,
            RelDirection::Undirected if data.end == current => data.start,
            _ => return Ok(()), // not incident from `current` in the required direction
        };
        current = next;
    }

    // For a zero-length bound list the endpoint is the anchor itself; var-length keeps a list
    // binding, a single bound relationship keeps its scalar binding (already present on the row).
    if into {
        let target = base.get(&to.name).and_then(RowValue::as_node);
        if Some(current) != target {
            return Ok(());
        }
    }
    let mut row = base.clone();
    if !into {
        row.set(to.name.clone(), RowValue::Node(NodeRef { id: current }));
    }
    // Normalise the relationship binding: a var-length hop binds the **list** (even of length one),
    // a fixed hop keeps the scalar. The bound value is already on the row, so only the var-length
    // case needs a (re)materialised list to guarantee the structural list representation.
    if var_length {
        row.set(
            relationship.name.clone(),
            RowValue::list(
                rel_ids
                    .iter()
                    .map(|&id| RowValue::Rel(RelRef { id }))
                    .collect(),
            ),
        );
    }
    pending.push_back(row);
    Ok(())
}

/// Whether the single relationship `rel` satisfies a var-length hop's inline property map `props`
/// (`-[:T* {k: v}]->`). Evaluates the property-map predicate against a row binding `rel_var` to this
/// one relationship, reusing the ordinary inline-property semantics: each `k: v` becomes
/// `rel_var.k = v`, and a non-matching or null comparison drops the relationship (Cypher 3VL —
/// `Match4` [5]). `props` is the AST map literal (or `$param`) the lowering carried through.
fn rel_satisfies_props(
    rel: RelId,
    props: &Expr,
    base: &Row,
    rel_var: &Var,
    ctx: &mut Ctx<'_>,
) -> Result<bool, ExecError> {
    // Bind the relationship variable to this one relationship, then test each property equality.
    let mut probe = base.clone();
    probe.set(rel_var.name.clone(), RowValue::Rel(RelRef { id: rel }));
    let entries = match &props.kind {
        ExprKind::Map(entries) => entries,
        // Only inline map literals reach a var-length hop's `rel_props` (the parser/semantics
        // restrict pattern properties to map literals or parameters); a parameter map is rare here
        // and unmeasured, so treat a non-map form as "no constraint" rather than failing.
        _ => return Ok(true),
    };
    let span = crate::lexer::Span::new(0, 0);
    for (key, value_expr) in entries {
        // Build and evaluate `rel_var.key = value`, matching the fixed-length inline-property
        // semantics (`filter_inline_props`): a false or null (3VL) result rejects the relationship.
        let lhs = Expr::new(
            ExprKind::Property {
                base: Box::new(Expr::new(ExprKind::Variable(rel_var.name.clone()), span)),
                key: key.name.clone(),
            },
            span,
        );
        let predicate = Expr::new(
            ExprKind::Binary {
                op: crate::ast::BinaryOp::Eq,
                lhs: Box::new(lhs),
                rhs: Box::new(value_expr.clone()),
            },
            span,
        );
        let result = eval(&predicate, &probe, ctx.params, ctx.graph, ctx.functions)?;
        if !matches!(result, RowValue::Value(Value::Boolean(true))) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Runs a breadth-first search for `shortestPath`/`allShortestPaths` between the already-bound
/// `from` and `to` endpoints of `base`, pushing one row per shortest path into `pending` (or none
/// when no path of a length within `range` connects them). `all` selects between a single minimal
/// path and every minimal-length path.
///
/// The forward BFS records, for every node reached at its shortest distance, the set of
/// `(predecessor, relationship)` pairs lying on a shortest path (the shortest-path predecessor DAG),
/// then enumerates paths by backtracking from `to` to `from` over that DAG. Because each step
/// strictly decreases the distance, every enumerated path is node-unique (openCypher `shortestPath`
/// semantics) and the enumeration always terminates. The multigraph is honoured — parallel
/// relationships between two consecutive-distance nodes are distinct shortest paths.
///
/// Boundary: both endpoints must be bound (the supported form). A lower bound greater than the
/// actual shortest distance (e.g. `shortestPath((a)-[*3..]-(b))` with `a`, `b` two hops apart) is
/// not satisfied — no row is produced — since the BFS reports the unconstrained shortest distance.
#[allow(clippy::too_many_arguments)]
fn shortest_paths_into_pending(
    base: &Row,
    from: &Var,
    to: &Var,
    relationship: &Var,
    path: &Option<Var>,
    direction: RelDirection,
    types: &[RelType],
    range: VarLengthRange,
    all: bool,
    ctx: &mut Ctx<'_>,
    pending: &mut VecDeque<Row>,
) -> Result<(), ExecError> {
    let Some(anchor) = base.get(&from.name).and_then(RowValue::as_node) else {
        return Ok(());
    };
    let Some(target) = base.get(&to.name).and_then(RowValue::as_node) else {
        return Ok(());
    };
    let type_names: Vec<String> = types.iter().map(|t| t.name.clone()).collect();
    let dir = ExpandDirection::from_pattern(direction);
    let min = range.min.unwrap_or(1);
    let max = range.max;

    // Forward BFS: shortest distance to each node + the shortest-path predecessor DAG.
    let mut dist: std::collections::HashMap<NodeId, u64> = std::collections::HashMap::new();
    let mut preds: std::collections::HashMap<NodeId, Vec<(NodeId, crate::graph_access::RelId)>> =
        std::collections::HashMap::new();
    dist.insert(anchor, 0);
    let mut frontier = vec![anchor];
    let mut depth = 0u64;
    // The zero-length path (the anchor itself) is a valid shortest path only when the lower bound
    // admits length 0 and the endpoints coincide.
    let mut reached: Option<u64> = (anchor == target && min == 0).then_some(0);

    while !frontier.is_empty() {
        if max.is_some_and(|m| depth >= m) {
            break;
        }
        if reached.is_some_and(|d| depth >= d) {
            break; // every shortest path is discovered by the level the target is first reached
        }
        ctx.check_cancelled()?;
        let mut next = Vec::new();
        for &node in &frontier {
            for inc in ctx.graph.expand(node, dir, &type_names) {
                let nb = inc.neighbour;
                match dist.get(&nb).copied() {
                    None => {
                        dist.insert(nb, depth + 1);
                        preds.entry(nb).or_default().push((node, inc.rel));
                        next.push(nb);
                        if nb == target && reached.is_none() {
                            reached = Some(depth + 1);
                        }
                    }
                    // Another shortest-path predecessor reaching `nb` at the same minimal distance.
                    Some(d) if d == depth + 1 => {
                        preds.entry(nb).or_default().push((node, inc.rel));
                    }
                    _ => {} // already reached via a strictly shorter path
                }
            }
        }
        depth += 1;
        frontier = next;
    }

    let Some(d) = reached else {
        return Ok(()); // disconnected within the bounds
    };
    if d < min {
        return Ok(()); // the shortest path is below the requested lower bound
    }

    // Enumerate the relationship trails (anchor -> target order) of the shortest path(s).
    let mut trails: Vec<Vec<crate::graph_access::RelId>> = Vec::new();
    if d == 0 {
        trails.push(Vec::new());
    } else {
        let mut rev_trail = Vec::new();
        collect_shortest(target, anchor, &preds, &mut rev_trail, &mut trails, all);
    }

    for trail in trails {
        let mut row = base.clone();
        row.set(
            relationship.name.clone(),
            RowValue::list(
                trail
                    .iter()
                    .map(|&id| RowValue::Rel(RelRef { id }))
                    .collect(),
            ),
        );
        if let Some(pvar) = path {
            let mut current = anchor;
            let mut steps = Vec::with_capacity(trail.len());
            for &rel in &trail {
                let hop = hop_step_from(rel, current, &*ctx.graph);
                current = hop.node;
                steps.push(hop);
            }
            row.set(
                pvar.name.clone(),
                RowValue::Path(PathValue {
                    start: anchor,
                    steps,
                }),
            );
        }
        pending.push_back(row);
    }
    Ok(())
}

/// Backtracks the shortest-path predecessor DAG from `node` to `anchor`, collecting each path's
/// relationship trail (pushed reversed on the way down, emitted in anchor->target order). With
/// `all = false` it stops after the first complete path (a single shortest path).
fn collect_shortest(
    node: NodeId,
    anchor: NodeId,
    preds: &std::collections::HashMap<NodeId, Vec<(NodeId, crate::graph_access::RelId)>>,
    rev_trail: &mut Vec<crate::graph_access::RelId>,
    out: &mut Vec<Vec<crate::graph_access::RelId>>,
    all: bool,
) {
    if node == anchor {
        out.push(rev_trail.iter().rev().copied().collect());
        return;
    }
    let Some(parents) = preds.get(&node) else {
        return;
    };
    for &(parent, rel) in parents {
        rev_trail.push(rel);
        collect_shortest(parent, anchor, preds, rev_trail, out, all);
        rev_trail.pop();
        if !all && !out.is_empty() {
            return;
        }
    }
}

/// Reconstructs the [`PathValue`] a `NamedPath` operator binds (`MATCH p = …`) from the pattern
/// part's `start` node binding and its per-link `steps` relationship bindings.
///
/// Each step variable binds either a single relationship (a fixed hop) or the list of traversed
/// relationships (a variable-length hop), in pattern order. The walk recovers each hop's
/// orientation from the relationship's stored endpoints relative to the node it leaves, mirroring
/// the expression-side reconstruction in [`crate::eval`] so the two produce equal path values. A
/// null / unbound `start` or step — the `OPTIONAL MATCH` no-match row — binds the path to null.
fn reconstruct_named_path(
    row: &Row,
    start: &Var,
    steps: &[Var],
    graph: &dyn GraphAccess,
) -> RowValue {
    let Some(start_id) = row.get(&start.name).and_then(RowValue::as_node) else {
        return RowValue::NULL;
    };
    let mut current = start_id;
    let mut path_steps = Vec::new();
    for step in steps {
        // The relationships of this link, in traversal order: a single bound relationship, or the
        // list bound by a variable-length hop. Anything else (null / non-relationship element) is
        // the OPTIONAL no-match case and collapses the whole path to null.
        let rels: Vec<RelId> = match row.get(&step.name) {
            Some(RowValue::Rel(r)) => vec![r.id],
            Some(other) => {
                let Some(elems) = other.as_list_elems() else {
                    return RowValue::NULL;
                };
                let mut ids = Vec::with_capacity(elems.len());
                for e in &elems {
                    let Some(id) = e.as_rel() else {
                        return RowValue::NULL;
                    };
                    ids.push(id);
                }
                ids
            }
            None => return RowValue::NULL,
        };
        for rel in rels {
            let hop = hop_step_from(rel, current, graph);
            current = hop.node;
            path_steps.push(hop);
        }
    }
    RowValue::Path(PathValue {
        start: start_id,
        steps: path_steps,
    })
}

/// The [`PathStep`] for traversing `rel` leaving `from`: forward iff the relationship's stored start
/// is `from` (a self-loop and a missing relationship record as forward), arriving at the opposite
/// endpoint. Mirrors `eval::hop_step` so the executor and the expression evaluator agree on path
/// orientation.
fn hop_step_from(rel: RelId, from: NodeId, graph: &dyn GraphAccess) -> PathStep {
    match graph.rel_data(rel) {
        Some(d) => {
            let forward = d.start == from;
            PathStep {
                forward,
                rel,
                node: if forward { d.end } else { d.start },
            }
        }
        None => PathStep {
            forward: true,
            rel,
            node: from,
        },
    }
}

// =================================================================================================
// Operator construction (compile a PhysicalOp tree into an Operator tree)
// =================================================================================================

/// Builds the operator tree for `op`, eagerly computing any materialising operator's buffer.
///
/// `arg` is the correlation row for an [`Argument`](PhysicalOp::Argument) leaf (the left row of an
/// enclosing nested-loop join); `None` at the top level.
fn build_operator(
    op: &PhysicalOp,
    arg: Option<&Row>,
    ctx: &mut Ctx<'_>,
) -> Result<Operator, ExecError> {
    match op {
        // ---- leaves ---------------------------------------------------------------------------
        PhysicalOp::AllNodesScan { variable } => {
            let rows = ctx
                .graph
                .scan_nodes()
                .into_iter()
                .map(|id| {
                    Row::from_pairs([(variable.name.clone(), RowValue::Node(NodeRef { id }))])
                })
                .collect();
            Ok(Operator::Buffered { rows })
        }
        PhysicalOp::NodeByLabelScan { variable, label } => Ok(Operator::Buffered {
            rows: label_scan_rows(variable, label, ctx),
        }),
        PhysicalOp::TokenLookupScan {
            variable, label, ..
        } => {
            // The token-lookup index is the label scan store; the in-memory seam serves it as a
            // label scan (no separate index structure). Result-equivalent (`04 §6.2`).
            Ok(Operator::Buffered {
                rows: label_scan_rows(variable, label, ctx),
            })
        }
        PhysicalOp::NodeIndexSeek {
            variable,
            label,
            property,
            value,
            ..
        } => {
            let seek = eval_value(value, &Row::empty(), ctx.params, ctx.graph, ctx.functions)?;
            let ids = match ctx.graph.index_seek_eq(&label.name, property, &seek) {
                Some(ids) => ids,
                // No index in the seam: fall back to a label scan + equality residual.
                None => scan_filter_eq(label, property, &seek, ctx),
            };
            Ok(Operator::Buffered {
                rows: nodes_to_rows(variable, ids),
            })
        }
        PhysicalOp::NodeIndexRangeSeek {
            variable,
            label,
            property,
            bound,
            value,
            ..
        } => {
            let bound_val = eval_value(value, &Row::empty(), ctx.params, ctx.graph, ctx.functions)?;
            let (lower, upper) = range_bounds(*bound, &bound_val);
            let ids = match ctx
                .graph
                .index_seek_range(&label.name, property, lower, upper)
            {
                Some(ids) => ids,
                None => scan_filter_range(label, property, *bound, &bound_val, ctx),
            };
            Ok(Operator::Buffered {
                rows: nodes_to_rows(variable, ids),
            })
        }
        PhysicalOp::SpatialIndexSeek {
            variable,
            label,
            property,
            center_x,
            center_y,
            radius,
            ..
        } => {
            // Ask the spatial index for the candidate superset within the radius; if the seam has no
            // such index at run time, fall back to a label scan so the result is still correct (the
            // residual `distance(...) <op> r` filter above this operator does the exact trimming, and
            // MVCC visibility / current-value / current-label re-checks, in BOTH paths — so the
            // index-accelerated and scan paths return the identical node set, `rmp` task #73).
            let ids = ctx
                .graph
                .index_seek_spatial(&label.name, property, *center_x, *center_y, *radius)
                .unwrap_or_else(|| ctx.graph.scan_nodes_by_label(&label.name));
            Ok(Operator::Buffered {
                rows: nodes_to_rows(variable, ids),
            })
        }
        PhysicalOp::AllRelationshipsScan {
            relationship,
            from,
            to,
            direction,
            types,
        } => Ok(Operator::Buffered {
            rows: all_rels_rows(relationship, from, to, *direction, types, ctx),
        }),
        PhysicalOp::Argument { arguments } => {
            // The single correlation row, projected to the declared argument variables.
            let mut row = Row::empty();
            if let Some(arg) = arg {
                for v in arguments {
                    if let Some(value) = arg.get(&v.name) {
                        row.set(v.name.clone(), value.clone());
                    }
                }
            }
            Ok(Operator::SingleRow {
                emitted: false,
                row,
            })
        }
        PhysicalOp::Empty => Ok(Operator::SingleRow {
            emitted: false,
            row: arg.cloned().unwrap_or_else(Row::empty),
        }),

        // ---- graph ----------------------------------------------------------------------------
        PhysicalOp::ExpandAll {
            input,
            from,
            relationship,
            to,
            direction,
            types,
            range,
            prior_rels,
            rel_props,
        } => Ok(Operator::Expand {
            input: Box::new(build_operator(input, arg, ctx)?),
            from: from.clone(),
            relationship: relationship.clone(),
            to: to.clone(),
            direction: *direction,
            types: types.clone(),
            into: false,
            range: *range,
            prior_rels: prior_rels.clone(),
            rel_props: rel_props.clone(),
            pending: VecDeque::new(),
        }),
        PhysicalOp::ExpandInto {
            input,
            from,
            relationship,
            to,
            direction,
            types,
            range,
            prior_rels,
            rel_props,
        } => Ok(Operator::Expand {
            input: Box::new(build_operator(input, arg, ctx)?),
            from: from.clone(),
            relationship: relationship.clone(),
            to: to.clone(),
            direction: *direction,
            types: types.clone(),
            into: true,
            range: *range,
            prior_rels: prior_rels.clone(),
            rel_props: rel_props.clone(),
            pending: VecDeque::new(),
        }),
        PhysicalOp::ShortestPath {
            input,
            from,
            to,
            relationship,
            path,
            direction,
            types,
            range,
            all,
        } => Ok(Operator::ShortestPath {
            input: Box::new(build_operator(input, arg, ctx)?),
            from: from.clone(),
            to: to.clone(),
            relationship: relationship.clone(),
            path: path.clone(),
            direction: *direction,
            types: types.clone(),
            range: *range,
            all: *all,
            pending: VecDeque::new(),
        }),
        PhysicalOp::NamedPath {
            input,
            variable,
            start,
            steps,
        } => Ok(Operator::NamedPath {
            input: Box::new(build_operator(input, arg, ctx)?),
            variable: variable.clone(),
            start: start.clone(),
            steps: steps.clone(),
        }),

        // ---- relational -----------------------------------------------------------------------
        PhysicalOp::Filter { input, predicate } => Ok(Operator::Filter {
            input: Box::new(build_operator(input, arg, ctx)?),
            predicate: predicate.clone(),
        }),
        PhysicalOp::Projection {
            input,
            items,
            distinct,
        } => {
            let inner = build_operator(input, arg, ctx)?;
            if *distinct {
                Ok(Operator::Buffered {
                    rows: distinct_rows(inner, items, ctx)?,
                })
            } else {
                Ok(Operator::Project {
                    input: Box::new(inner),
                    items: items.clone(),
                })
            }
        }
        PhysicalOp::Aggregation {
            input,
            group_keys,
            aggregates,
        } => {
            let inner = build_operator(input, arg, ctx)?;
            Ok(Operator::Buffered {
                rows: aggregate_rows(inner, group_keys, aggregates, ctx)?,
            })
        }
        PhysicalOp::Sort { input, keys } => {
            let inner = build_operator(input, arg, ctx)?;
            Ok(Operator::Buffered {
                rows: sort_rows(inner, keys, None, ctx)?,
            })
        }
        PhysicalOp::TopN { input, keys, limit } => {
            let n = eval_count(limit, ctx)?;
            let inner = build_operator(input, arg, ctx)?;
            Ok(Operator::Buffered {
                rows: sort_rows(inner, keys, Some(n as usize), ctx)?,
            })
        }
        PhysicalOp::Skip { input, count } => Ok(Operator::Skip {
            input: Box::new(build_operator(input, arg, ctx)?),
            remaining: 0,
            primed: false,
            count_expr: count.clone(),
        }),
        PhysicalOp::Limit { input, count } => Ok(Operator::Limit {
            input: Box::new(build_operator(input, arg, ctx)?),
            remaining: 0,
            primed: false,
            count_expr: count.clone(),
        }),
        PhysicalOp::Eager { input } => {
            // The eager-write barrier (planner-inserted under a Limit over writes): drain the
            // input in full at build time so every write side effect runs, then serve the buffer.
            // Cancellation is still polled row-by-row through the inner operator's `next`.
            let mut inner = build_operator(input, arg, ctx)?;
            let mut rows = VecDeque::new();
            while let Some(row) = inner.next(ctx)? {
                rows.push_back(row);
            }
            Ok(Operator::Buffered { rows })
        }
        PhysicalOp::Unwind {
            input,
            list,
            variable,
        } => Ok(Operator::Unwind {
            input: Box::new(build_operator(input, arg, ctx)?),
            list: list.clone(),
            variable: variable.clone(),
            current: None,
        }),
        PhysicalOp::LoadCsv {
            input,
            with_headers,
            url,
            variable,
            field_terminator,
        } => {
            // The CSV delimiter is a single byte. The parser already constrains FIELDTERMINATOR to a
            // single character; a non-ASCII one would be multiple UTF-8 bytes and cannot be a CSV
            // delimiter, so reject it as a build-time configuration error (a runtime `LoadCsv` class).
            let delimiter = match field_terminator {
                Some(c) => u8::try_from(u32::from(*c)).map_err(|_| ExecError::LoadCsv {
                    reason: format!("FIELDTERMINATOR must be a single-byte character, got {c:?}"),
                })?,
                None => b',',
            };
            Ok(Operator::LoadCsv {
                input: Box::new(build_operator(input, arg, ctx)?),
                with_headers: *with_headers,
                url: url.clone(),
                variable: variable.clone(),
                field_terminator: delimiter,
                current: None,
            })
        }

        // ---- joins ----------------------------------------------------------------------------
        PhysicalOp::NestedLoopJoin { left, right } => Ok(Operator::NestedLoop {
            left: Box::new(build_operator(left, arg, ctx)?),
            right_template: right.clone(),
            current_left: None,
            current_right: None,
        }),
        PhysicalOp::HashJoin {
            left,
            right,
            join_keys,
        } => {
            // Both sides are independent (no correlation); materialise the join.
            let rows = hash_join_rows(left, right, join_keys, arg, ctx)?;
            Ok(Operator::Buffered { rows })
        }
        PhysicalOp::Union { left, right, all } => {
            let rows = union_rows(left, right, *all, arg, ctx)?;
            Ok(Operator::Buffered { rows })
        }
        PhysicalOp::Optional {
            input,
            null_variables,
        } => Ok(Operator::Optional {
            input: Box::new(build_operator(input, arg, ctx)?),
            null_variables: null_variables.clone(),
            produced_any: false,
            exhausted: false,
        }),

        // ---- write ----------------------------------------------------------------------------
        PhysicalOp::Create { input, pattern } => Ok(Operator::Write {
            input: Box::new(build_operator(input, arg, ctx)?),
            kind: WriteKind::Create {
                pattern: pattern.clone(),
            },
            pending: VecDeque::new(),
        }),
        PhysicalOp::Merge {
            input,
            pattern,
            on_create,
            on_match,
        } => Ok(Operator::Write {
            input: Box::new(build_operator(input, arg, ctx)?),
            kind: WriteKind::Merge {
                pattern: pattern.clone(),
                on_create: on_create.clone(),
                on_match: on_match.clone(),
            },
            pending: VecDeque::new(),
        }),
        PhysicalOp::SetClause { input, ops } => Ok(Operator::Write {
            input: Box::new(build_operator(input, arg, ctx)?),
            kind: WriteKind::Set { ops: ops.clone() },
            pending: VecDeque::new(),
        }),
        PhysicalOp::Delete {
            input,
            detach,
            exprs,
        } => Ok(Operator::Write {
            input: Box::new(build_operator(input, arg, ctx)?),
            kind: WriteKind::Delete {
                detach: *detach,
                exprs: exprs.clone(),
            },
            pending: VecDeque::new(),
        }),
        PhysicalOp::Remove { input, ops } => Ok(Operator::Write {
            input: Box::new(build_operator(input, arg, ctx)?),
            kind: WriteKind::Remove { ops: ops.clone() },
            pending: VecDeque::new(),
        }),

        // ---- procedure ------------------------------------------------------------------------
        PhysicalOp::ProcedureCall {
            input,
            name,
            args,
            yields,
        } => {
            let dotted = name.join(".");
            // Semantic analysis resolved the name at compile time over the *same* registry, so a
            // miss here means the compile-time and execution-time registries diverged.
            let Some(sig) = ctx.procedures.signature(&dotted) else {
                return Err(ExecError::Procedure(ProcedureFailure::new(
                    &dotted,
                    "procedure is not registered (compile/execute registry mismatch)",
                )));
            };
            // Resolve the output bindings once: `YIELD [field AS] var` columns by declared result
            // field, or — for the standalone / `YIELD *` form (`yields: None`) — every declared
            // output verbatim.
            let is_node_output = |idx: usize| {
                sig.outputs[idx].ty.class == crate::procedure_registry::ValueClass::Node
            };
            let bindings: Vec<(String, usize, bool)> = match yields {
                Some(items) => {
                    let mut out = Vec::with_capacity(items.len());
                    for y in items {
                        let field = y.field.as_deref().unwrap_or(&y.variable.name);
                        let Some(idx) = sig.outputs.iter().position(|o| o.name == field) else {
                            return Err(ExecError::Procedure(ProcedureFailure::new(
                                &dotted,
                                format!("YIELD names unknown result field `{field}`"),
                            )));
                        };
                        out.push((y.variable.name.clone(), idx, is_node_output(idx)));
                    }
                    out
                }
                None => sig
                    .outputs
                    .iter()
                    .enumerate()
                    .map(|(i, o)| (o.name.clone(), i, is_node_output(i)))
                    .collect(),
            };
            // The implicit form was resolved to parameter expressions by semantic analysis; a
            // zero-input procedure's implicit form is equivalent to `()`.
            let args = match args {
                Some(a) => a.clone(),
                None if sig.inputs.is_empty() => Vec::new(),
                None => {
                    return Err(ExecError::Procedure(ProcedureFailure::new(
                        &dotted,
                        "implicit argument passing reached the executor unresolved",
                    )));
                }
            };
            let void = sig.outputs.is_empty();
            let input = match input {
                Some(op) => build_operator(op, arg, ctx)?,
                // A leading/standalone call is driven by the single empty row.
                None => Operator::SingleRow {
                    emitted: false,
                    row: Row::empty(),
                },
            };
            Ok(Operator::ProcedureCall {
                input: Box::new(input),
                name: dotted,
                args,
                bindings,
                void,
                current: None,
            })
        }
    }
}

/// Builds the right branch of a nested-loop join seeded with the left row as the correlation arg.
fn build_operator_with_arg(
    op: &PhysicalOp,
    left_row: &Row,
    ctx: &mut Ctx<'_>,
) -> Result<Operator, ExecError> {
    build_operator(op, Some(left_row), ctx)
}

/// Rows for a label scan (each matching node bound to `variable`).
fn label_scan_rows(variable: &Var, label: &Label, ctx: &Ctx<'_>) -> VecDeque<Row> {
    nodes_to_rows(variable, ctx.graph.scan_nodes_by_label(&label.name))
}

/// Wraps node ids into single-binding rows for `variable`.
fn nodes_to_rows(variable: &Var, ids: Vec<NodeId>) -> VecDeque<Row> {
    ids.into_iter()
        .map(|id| Row::from_pairs([(variable.name.clone(), RowValue::Node(NodeRef { id }))]))
        .collect()
}

/// All-relationships scan rows: bind relationship + both endpoints, honouring the pattern direction
/// (an undirected/`<-` pattern still binds `from`/`to` per the AST arrow).
fn all_rels_rows(
    relationship: &Var,
    from: &Var,
    to: &Var,
    direction: RelDirection,
    types: &[RelType],
    ctx: &Ctx<'_>,
) -> VecDeque<Row> {
    let type_names: Vec<String> = types.iter().map(|t| t.name.clone()).collect();
    let mut out = VecDeque::new();
    // Enumerate every node's outgoing edges once to list all relationships deterministically.
    for node in ctx.graph.scan_nodes() {
        for inc in ctx
            .graph
            .expand(node, ExpandDirection::Outgoing, &type_names)
        {
            let Some(data) = ctx.graph.rel_data(inc.rel) else {
                continue;
            };
            // Bind from/to per the pattern arrow: LeftToRight uses (start, end); RightToLeft swaps;
            // Undirected keeps (start, end) for the canonical orientation.
            let (f, t) = match direction {
                RelDirection::RightToLeft => (data.end, data.start),
                RelDirection::LeftToRight | RelDirection::Undirected => (data.start, data.end),
            };
            let mut row = Row::empty();
            row.set(from.name.clone(), RowValue::Node(NodeRef { id: f }));
            row.set(
                relationship.name.clone(),
                RowValue::Rel(RelRef { id: inc.rel }),
            );
            row.set(to.name.clone(), RowValue::Node(NodeRef { id: t }));
            out.push_back(row);
        }
    }
    out
}

/// Fallback equality access: scan the label and keep nodes whose property equals `seek`.
fn scan_filter_eq(label: &Label, property: &str, seek: &Value, ctx: &Ctx<'_>) -> Vec<NodeId> {
    ctx.graph
        .scan_nodes_by_label(&label.name)
        .into_iter()
        .filter(|id| {
            ctx.graph
                .node_property(*id, property)
                .is_some_and(|v| crate::equality::equals(&v, seek).is_true())
        })
        .collect()
}

/// Fallback range access: scan the label and keep nodes whose property satisfies the range bound.
fn scan_filter_range(
    label: &Label,
    property: &str,
    bound: RangeBound,
    value: &Value,
    ctx: &Ctx<'_>,
) -> Vec<NodeId> {
    use std::cmp::Ordering;
    ctx.graph
        .scan_nodes_by_label(&label.name)
        .into_iter()
        .filter(|id| {
            let Some(v) = ctx.graph.node_property(*id, property) else {
                return false;
            };
            if v.is_null() || value.is_null() {
                return false;
            }
            let ord = cmp_values(&v, value);
            match bound {
                RangeBound::GreaterThan => ord == Ordering::Greater,
                RangeBound::GreaterOrEqual => ord != Ordering::Less,
                RangeBound::LessThan => ord == Ordering::Less,
                RangeBound::LessOrEqual => ord != Ordering::Greater,
            }
        })
        .collect()
}

/// One side of an index range bound: `(value, inclusive)`. `None` means the side is open.
type RangeSide<'v> = Option<(&'v Value, bool)>;

/// Converts a [`RangeBound`] + value into `(lower, upper)` [`RangeSide`]s for the seam.
fn range_bounds<'v>(bound: RangeBound, value: &'v Value) -> (RangeSide<'v>, RangeSide<'v>) {
    match bound {
        RangeBound::GreaterThan => (Some((value, false)), None),
        RangeBound::GreaterOrEqual => (Some((value, true)), None),
        RangeBound::LessThan => (None, Some((value, false))),
        RangeBound::LessOrEqual => (None, Some((value, true))),
    }
}

// =================================================================================================
// Materialising helpers (DISTINCT, Sort/TopN, Aggregation, joins)
// =================================================================================================

/// Drains `inner`, projects each row, and de-duplicates by Cypher equivalence (`04 §7.6`).
fn distinct_rows(
    mut inner: Operator,
    items: &[ProjectionColumn],
    ctx: &mut Ctx<'_>,
) -> Result<VecDeque<Row>, ExecError> {
    let mut seen: Vec<Row> = Vec::new();
    let mut out = VecDeque::new();
    while let Some(row) = inner.next(ctx)? {
        let projected = project_row(&row, items, ctx)?;
        if !seen.iter().any(|s| rows_equivalent(s, &projected)) {
            seen.push(projected.clone());
            out.push_back(projected);
        }
    }
    Ok(out)
}

/// Whether two rows are equivalent column-by-column under grouping equivalence.
fn rows_equivalent(a: &Row, b: &Row) -> bool {
    a.columns() == b.columns()
        && a.values()
            .iter()
            .zip(b.values())
            .all(|(x, y)| row_values_equivalent(x, y))
}

/// Drains `inner` and sorts it by `keys`; `top_n` keeps only the first `n` rows (the `TopN` fusion).
fn sort_rows(
    mut inner: Operator,
    keys: &[SortKey],
    top_n: Option<usize>,
    ctx: &mut Ctx<'_>,
) -> Result<VecDeque<Row>, ExecError> {
    let mut rows: Vec<Row> = Vec::new();
    while let Some(row) = inner.next(ctx)? {
        rows.push(row);
    }
    // Pre-compute each row's sort key values so the comparison is pure (no graph access mid-sort).
    let mut keyed: Vec<(Vec<RowValue>, Row)> = Vec::with_capacity(rows.len());
    for row in rows {
        let mut kvs = Vec::with_capacity(keys.len());
        for k in keys {
            kvs.push(eval(&k.expr, &row, ctx.params, ctx.graph, ctx.functions)?);
        }
        keyed.push((kvs, row));
    }
    keyed.sort_by(|a, b| compare_sort_keys(&a.0, &b.0, keys));
    let mut out: VecDeque<Row> = keyed.into_iter().map(|(_, r)| r).collect();
    if let Some(n) = top_n {
        out.truncate(n);
    }
    Ok(out)
}

/// Compares two rows' pre-computed sort-key vectors, honouring each key's direction and Cypher's
/// `NULL`-largest ordering (`04 §7.6`: ascending puts `NULL` last; descending reverses).
fn compare_sort_keys(a: &[RowValue], b: &[RowValue], keys: &[SortKey]) -> std::cmp::Ordering {
    for ((av, bv), key) in a.iter().zip(b.iter()).zip(keys.iter()) {
        let ord = cmp_row_values(av, bv);
        let ord = match key.direction {
            SortDirection::Ascending => ord,
            SortDirection::Descending => ord.reverse(),
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    std::cmp::Ordering::Equal
}

/// Drains `inner` and folds aggregates per group (`04 §7.6` grouping by equivalence).
///
/// An aggregate column may be a **composite** expression around its aggregate call(s) —
/// `size(collect(n))`, `head(collect(m))`, `ALL(x IN collect(y) WHERE …)` (TCK `Return6` \[5\],
/// `Return4` \[11\], `List11` \[3\]). Each column is therefore pre-compiled into an [`AggPlan`]:
/// the aggregate sub-calls are extracted into per-group [`Accumulator`]s and replaced by synthetic
/// variables in the outer expression, which is then evaluated once per finished group against a
/// representative row of that group (every grouped expression agrees across the group's rows, and
/// the semantic pass guarantees the outer composition only uses constants, grouped keys and
/// locally-bound variables).
fn aggregate_rows(
    mut inner: Operator,
    group_keys: &[ProjectionColumn],
    aggregates: &[ProjectionColumn],
    ctx: &mut Ctx<'_>,
) -> Result<VecDeque<Row>, ExecError> {
    // Compile each aggregate column independently; the column index disambiguates the synthetic
    // names so two columns' extracted aggregates never collide in the shared evaluation row.
    let plans: Vec<AggPlan> = aggregates
        .iter()
        .enumerate()
        .map(|(col, c)| AggPlan::compile(&c.expr, col))
        .collect();

    // Each group: its key row-values (in group_keys order), one accumulator per extracted
    // aggregate sub-call of every column, and a representative input row.
    struct Group {
        keys: Vec<RowValue>,
        accs: Vec<Vec<Accumulator>>,
        representative: Row,
    }
    let new_accs = |plans: &[AggPlan]| -> Vec<Vec<Accumulator>> {
        plans
            .iter()
            .map(|p| p.subs.iter().map(|(_, e)| Accumulator::new(e)).collect())
            .collect()
    };
    let mut groups: Vec<Group> = Vec::new();

    while let Some(row) = inner.next(ctx)? {
        ctx.check_cancelled()?;
        // Compute the group key.
        let mut key_vals = Vec::with_capacity(group_keys.len());
        for col in group_keys {
            key_vals.push(eval(&col.expr, &row, ctx.params, ctx.graph, ctx.functions)?);
        }
        let idx = match groups.iter().position(|g| {
            g.keys.len() == key_vals.len()
                && g.keys
                    .iter()
                    .zip(&key_vals)
                    .all(|(x, y)| row_values_equivalent(x, y))
        }) {
            Some(i) => i,
            None => {
                groups.push(Group {
                    keys: key_vals.clone(),
                    accs: new_accs(&plans),
                    representative: row.clone(),
                });
                groups.len() - 1
            }
        };
        // Update each accumulator from this row.
        for (plan, accs) in plans.iter().zip(groups[idx].accs.iter_mut()) {
            for ((_, sub), acc) in plan.subs.iter().zip(accs.iter_mut()) {
                acc.update(sub, &row, ctx)?;
            }
        }
    }

    // With no input rows and no grouping keys, Cypher still emits one row (the empty group) — e.g.
    // `count(*)` over an empty match is 0. Materialise that single empty group.
    if groups.is_empty() && group_keys.is_empty() {
        groups.push(Group {
            keys: Vec::new(),
            accs: new_accs(&plans),
            representative: Row::empty(),
        });
    }

    let mut out = VecDeque::new();
    for g in groups {
        let mut row = Row::empty();
        // The evaluation row for the outer expressions: the group's representative input row,
        // the projected key aliases, and the synthetic aggregate-result bindings.
        let mut eval_row = g.representative;
        for (col, kv) in group_keys.iter().zip(g.keys) {
            eval_row.set(col.alias.clone(), kv.clone());
            row.set(col.alias.clone(), kv);
        }
        for (plan, accs) in plans.iter().zip(g.accs) {
            for ((name, _), acc) in plan.subs.iter().zip(accs) {
                eval_row.set(name.clone(), acc.finish());
            }
        }
        for (col, plan) in aggregates.iter().zip(&plans) {
            let value = eval(&plan.outer, &eval_row, ctx.params, ctx.graph, ctx.functions)?;
            row.set(col.alias.clone(), value);
        }
        out.push_back(row);
    }
    Ok(out)
}

/// One aggregate column, compiled for [`aggregate_rows`]: the outer expression with each aggregate
/// sub-call replaced by a synthetic variable, plus the extracted `(synthetic name, aggregate
/// call)` pairs in extraction order.
struct AggPlan {
    outer: Expr,
    subs: Vec<(String, Expr)>,
}

impl AggPlan {
    /// Extracts the aggregate sub-calls of `expr` (aggregates never nest — the semantic pass
    /// rejects that), substituting synthetic variables the parser can never produce. `col` is the
    /// column's index among the aggregate columns, woven into the synthetic names so they are
    /// unique across the whole projection (not just within one column).
    fn compile(expr: &Expr, col: usize) -> AggPlan {
        let mut subs = Vec::new();
        let outer = extract_aggregates(expr, &mut subs, col);
        AggPlan { outer, subs }
    }
}

/// Whether `expr` is itself an aggregate call (`count(*)` or an aggregating function).
fn is_aggregate_call(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::CountStar => true,
        ExprKind::FunctionCall { name, .. } => {
            crate::function_registry::is_aggregate(&name.join("."))
        }
        _ => false,
    }
}

/// Rewrites `expr`, replacing every aggregate call by a fresh synthetic variable recorded in
/// `subs`. Sub-scopes (comprehension/quantifier bodies) are traversed too — an aggregate is only
/// legal there in the **source list**, which evaluates in the outer scope, and the semantic pass
/// has already rejected the illegal positions.
fn extract_aggregates(expr: &Expr, subs: &mut Vec<(String, Expr)>, col: usize) -> Expr {
    if is_aggregate_call(expr) {
        let name = format!("#agg{col}_{}", subs.len());
        subs.push((name.clone(), expr.clone()));
        return Expr::new(ExprKind::Variable(name), expr.span);
    }
    let rewrite =
        |e: &Expr, subs: &mut Vec<(String, Expr)>| Box::new(extract_aggregates(e, subs, col));
    let kind = match &expr.kind {
        k @ (ExprKind::Literal(_)
        | ExprKind::Parameter(_)
        | ExprKind::Variable(_)
        | ExprKind::CountStar) => k.clone(),
        ExprKind::Binary { op, lhs, rhs } => ExprKind::Binary {
            op: *op,
            lhs: rewrite(lhs, subs),
            rhs: rewrite(rhs, subs),
        },
        ExprKind::Unary { op, operand } => ExprKind::Unary {
            op: *op,
            operand: rewrite(operand, subs),
        },
        ExprKind::Predicate { op, operand, rhs } => ExprKind::Predicate {
            op: *op,
            operand: rewrite(operand, subs),
            rhs: rhs.as_deref().map(|e| rewrite(e, subs)),
        },
        ExprKind::HasLabels { operand, labels } => ExprKind::HasLabels {
            operand: rewrite(operand, subs),
            labels: labels.clone(),
        },
        ExprKind::Property { base, key } => ExprKind::Property {
            base: rewrite(base, subs),
            key: key.clone(),
        },
        ExprKind::Index { base, index } => ExprKind::Index {
            base: rewrite(base, subs),
            index: rewrite(index, subs),
        },
        ExprKind::Slice { base, low, high } => ExprKind::Slice {
            base: rewrite(base, subs),
            low: low.as_deref().map(|e| rewrite(e, subs)),
            high: high.as_deref().map(|e| rewrite(e, subs)),
        },
        ExprKind::FunctionCall {
            name,
            distinct,
            args,
        } => ExprKind::FunctionCall {
            name: name.clone(),
            distinct: *distinct,
            args: args
                .iter()
                .map(|a| extract_aggregates(a, subs, col))
                .collect(),
        },
        ExprKind::List(items) => ExprKind::List(
            items
                .iter()
                .map(|it| extract_aggregates(it, subs, col))
                .collect(),
        ),
        ExprKind::Map(entries) => ExprKind::Map(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), extract_aggregates(v, subs, col)))
                .collect(),
        ),
        ExprKind::Case(case) => {
            let mut case = case.clone();
            case.subject = case.subject.take().map(|s| rewrite(&s, subs));
            for alt in &mut case.alternatives {
                alt.when = extract_aggregates(&alt.when, subs, col);
                alt.then = extract_aggregates(&alt.then, subs, col);
            }
            case.else_expr = case.else_expr.take().map(|e| rewrite(&e, subs));
            ExprKind::Case(case)
        }
        ExprKind::ListComprehension(lc) => {
            let mut lc = lc.clone();
            lc.list = rewrite(&lc.list, subs);
            lc.predicate = lc.predicate.take().map(|p| rewrite(&p, subs));
            lc.projection = lc.projection.take().map(|p| rewrite(&p, subs));
            ExprKind::ListComprehension(lc)
        }
        ExprKind::Quantifier(q) => {
            let mut q = q.clone();
            q.list = rewrite(&q.list, subs);
            q.predicate = rewrite(&q.predicate, subs);
            ExprKind::Quantifier(q)
        }
        // Pattern comprehensions / EXISTS subqueries cannot contain aggregates (their scopes are
        // pattern-bound; the semantic pass rejects aggregation inside them), so pass them through.
        k @ (ExprKind::PatternComprehension(_) | ExprKind::ExistsSubquery(_)) => k.clone(),
    };
    Expr::new(kind, expr.span)
}

/// One aggregate accumulator: identifies the function from the aggregate column's expression and
/// folds values for one group.
struct Accumulator {
    kind: AggKind,
    distinct: bool,
    count: i64,
    seen: Vec<RowValue>, // distinct-set: RowValue-typed so entity references dedupe by identity
    sum: f64,
    sum_is_int: bool,
    int_sum: i64,
    extreme: Option<Value>,
    // RowValue-typed so `collect(n)` / `collect(nodes(p))` keep their structural elements.
    collected: Vec<RowValue>,
    // `percentileCont`/`percentileDisc`: every numeric input value, kept as `(sort_key, original)`
    // so the result can preserve the source numeric subtype (`percentileDisc` returns a real value
    // of the set) while sorting on the `f64` key. The percentile (`args[1]`) is captured and
    // range-validated on the first contributing row, matching Neo4j's `onFirstRow` semantics.
    numeric: Vec<(f64, Value)>,
    percentile: Option<f64>,
}

/// The aggregate function an [`Accumulator`] computes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AggKind {
    CountStar,
    Count,
    Sum,
    Avg,
    Min,
    Max,
    Collect,
    /// `percentileCont(expr, p)` — continuous percentile via linear interpolation over the sorted
    /// numeric values; `p ∈ [0.0, 1.0]`.
    PercentileCont,
    /// `percentileDisc(expr, p)` — discrete percentile (nearest-rank) returning a real value of the
    /// set; `p ∈ [0.0, 1.0]`.
    PercentileDisc,
    /// A non-aggregating expression placed in the aggregate slot (defensive; treated as last value).
    Other,
}

impl Accumulator {
    /// Identifies the aggregate from `expr` (a `count(*)`, an aggregating `FunctionCall`, or other).
    fn new(expr: &Expr) -> Self {
        let (kind, distinct) = match &expr.kind {
            ExprKind::CountStar => (AggKind::CountStar, false),
            ExprKind::FunctionCall { name, distinct, .. } => {
                let kind = match name.join(".").to_ascii_lowercase().as_str() {
                    "count" => AggKind::Count,
                    "sum" => AggKind::Sum,
                    "avg" => AggKind::Avg,
                    "min" => AggKind::Min,
                    "max" => AggKind::Max,
                    "collect" => AggKind::Collect,
                    "percentilecont" => AggKind::PercentileCont,
                    "percentiledisc" => AggKind::PercentileDisc,
                    _ => AggKind::Other,
                };
                (kind, *distinct)
            }
            _ => (AggKind::Other, false),
        };
        Self {
            kind,
            distinct,
            count: 0,
            seen: Vec::new(),
            sum: 0.0,
            sum_is_int: true,
            int_sum: 0,
            extreme: None,
            collected: Vec::new(),
            numeric: Vec::new(),
            percentile: None,
        }
    }

    /// Folds one input row into the accumulator.
    fn update(&mut self, expr: &Expr, row: &Row, ctx: &mut Ctx<'_>) -> Result<(), ExecError> {
        if self.kind == AggKind::CountStar {
            self.count += 1;
            return Ok(());
        }
        // The aggregate's single argument (count/sum/.../collect take one arg). Evaluate it as a
        // `RowValue` so a bound **node/relationship** is recognised as a non-null value: `count(n)`
        // over node bindings must count them. (`eval_value` would collapse an entity to `Value::Null`
        // — the value-context rule — which made `count(<entity>)` wrongly return 0.)
        let rv = match &expr.kind {
            ExprKind::FunctionCall { args, .. } if !args.is_empty() => {
                eval(&args[0], row, ctx.params, ctx.graph, ctx.functions)?
            }
            _ => RowValue::NULL,
        };
        // count(x), sum, avg, min, max ignore nulls (Cypher); collect drops nulls too. An entity
        // reference is non-null.
        if rv.is_null() {
            return Ok(());
        }
        if self.distinct && self.seen.iter().any(|s| row_values_equivalent(s, &rv)) {
            return Ok(());
        }
        if self.distinct {
            self.seen.push(rv.clone());
        }
        // `collect` keeps the full RowValue (structural elements survive into the list).
        if self.kind == AggKind::Collect {
            self.collected.push(rv);
            return Ok(());
        }
        // `percentileCont`/`percentileDisc(value, p)`: gather every numeric `value`, keyed by its
        // `f64` for sorting but keeping the original `Value` so `percentileDisc` returns a real set
        // member with its source subtype. The percentile is captured and range-validated on the
        // first contributing (numeric, non-null) row — mirroring Neo4j's `onFirstRow`, which runs
        // inside the per-number callback, so a leading null `value` contributes no validation.
        if matches!(self.kind, AggKind::PercentileCont | AggKind::PercentileDisc) {
            let argv = collapse_rv(&rv);
            let key = match &argv {
                Value::Integer(i) => *i as f64,
                Value::Float(f) => *f,
                // A non-numeric `value` is a runtime type error (the aggregate operates on numbers).
                _ => {
                    return Err(ExecError::Eval(EvalError::TypeError {
                        context: "percentileCont/percentileDisc require numeric input".to_owned(),
                    }));
                }
            };
            if self.percentile.is_none() {
                let p = self.eval_percentile(expr, row, ctx)?;
                self.percentile = Some(p);
            }
            self.numeric.push((key, argv));
            return Ok(());
        }
        // The collapsed property value for the numeric / extreme arms. An entity/path collapses to
        // `Value::Null` here (it is not a property value) and a structural list collapses
        // elementwise: `count` and `collect` keep the RowValue-aware semantics above, while
        // `sum`/`avg`/`min`/`max` over an entity argument are a type error / no-op exactly as
        // before this fix.
        let argv = collapse_rv(&rv);
        match self.kind {
            AggKind::Count => self.count += 1,
            AggKind::Sum | AggKind::Avg => {
                self.count += 1;
                match &argv {
                    Value::Integer(i) => {
                        self.int_sum = self.int_sum.saturating_add(*i);
                        self.sum += *i as f64;
                    }
                    Value::Float(f) => {
                        self.sum_is_int = false;
                        self.sum += *f;
                    }
                    _ => {
                        return Err(ExecError::Eval(EvalError::TypeError {
                            context: "sum/avg require numeric input".to_owned(),
                        }));
                    }
                }
            }
            AggKind::Min => {
                if self
                    .extreme
                    .as_ref()
                    .is_none_or(|e| cmp_values(&argv, e).is_lt())
                {
                    self.extreme = Some(argv);
                }
            }
            AggKind::Max => {
                if self
                    .extreme
                    .as_ref()
                    .is_none_or(|e| cmp_values(&argv, e).is_gt())
                {
                    self.extreme = Some(argv);
                }
            }
            AggKind::Other => self.extreme = Some(argv),
            // Handled by the early returns above.
            AggKind::Collect
            | AggKind::CountStar
            | AggKind::PercentileCont
            | AggKind::PercentileDisc => unreachable!(),
        }
        Ok(())
    }

    /// Evaluates and range-validates the percentile argument (`args[1]`) of a
    /// `percentileCont`/`percentileDisc` call. The percentile is a per-group constant; the semantic
    /// pass guarantees it does not reference the aggregated value, so any contributing row yields
    /// the same result.
    ///
    /// # Errors
    ///
    /// - [`EvalError::TypeError`] if the percentile is not a number (or is null);
    /// - [`EvalError::NumberOutOfRange`] if it lies outside `[0.0, 1.0]`.
    fn eval_percentile(&self, expr: &Expr, row: &Row, ctx: &mut Ctx<'_>) -> Result<f64, ExecError> {
        let arg = match &expr.kind {
            ExprKind::FunctionCall { args, .. } if args.len() >= 2 => &args[1],
            // Arity is checked at compile time; a malformed call reaching here is a type error.
            _ => {
                return Err(ExecError::Eval(EvalError::TypeError {
                    context: "percentileCont/percentileDisc expect (value, percentile)".to_owned(),
                }));
            }
        };
        let p = match collapse_rv(&eval(arg, row, ctx.params, ctx.graph, ctx.functions)?) {
            Value::Integer(i) => i as f64,
            Value::Float(f) => f,
            _ => {
                return Err(ExecError::Eval(EvalError::TypeError {
                    context: "percentile must be a number".to_owned(),
                }));
            }
        };
        if !(0.0..=1.0).contains(&p) {
            return Err(ExecError::Eval(EvalError::NumberOutOfRange {
                value: p.to_string(),
            }));
        }
        Ok(p)
    }

    /// Produces the group's aggregate value.
    fn finish(self) -> RowValue {
        let value = match self.kind {
            AggKind::CountStar | AggKind::Count => Value::Integer(self.count),
            AggKind::Sum => {
                if self.sum_is_int {
                    Value::Integer(self.int_sum)
                } else {
                    Value::Float(self.sum)
                }
            }
            AggKind::Avg => {
                if self.count == 0 {
                    Value::Null
                } else {
                    Value::Float(self.sum / self.count as f64)
                }
            }
            AggKind::Min | AggKind::Max | AggKind::Other => self.extreme.unwrap_or(Value::Null),
            // `collect` builds the canonical list (structural iff any element is).
            AggKind::Collect => return RowValue::list(self.collected),
            AggKind::PercentileCont | AggKind::PercentileDisc => self.finish_percentile(),
        };
        RowValue::Value(value)
    }

    /// Computes the group's percentile (`percentileCont`/`percentileDisc`) over the gathered numeric
    /// values, following Neo4j's algorithm exactly. With no contributing values the result is
    /// `null`. The percentile was already range-validated in [`Accumulator::update`].
    fn finish_percentile(mut self) -> Value {
        let count = self.numeric.len();
        if count == 0 {
            return Value::Null;
        }
        // Sort ascending by the numeric key (NaN cannot occur: inputs are real `Integer`/`Float`).
        self.numeric
            .sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        // `percentile` is `Some` whenever `numeric` is non-empty (both are set together in `update`).
        let perc = self.percentile.unwrap_or(0.0);

        match self.kind {
            AggKind::PercentileDisc => {
                // Nearest-rank: returns a real value of the set (original subtype preserved).
                let idx = if perc == 1.0 || count == 1 {
                    count - 1
                } else {
                    let float_idx = perc * count as f64;
                    let to_int = float_idx as usize; // truncation toward zero (perc, count ≥ 0)
                    if float_idx != to_int as f64 || to_int == 0 {
                        to_int
                    } else {
                        to_int - 1
                    }
                };
                self.numeric[idx].1.clone()
            }
            AggKind::PercentileCont => {
                // Linear interpolation; always yields a `Float`.
                if perc == 1.0 || count == 1 {
                    return Value::Float(self.numeric[count - 1].0);
                }
                let float_idx = perc * (count - 1) as f64;
                let floor = float_idx as usize; // truncation toward zero
                let ceil = float_idx.ceil() as usize;
                let value = if ceil == floor || floor == count - 1 {
                    self.numeric[floor].0
                } else {
                    self.numeric[floor].0 * (ceil as f64 - float_idx)
                        + self.numeric[ceil].0 * (float_idx - floor as f64)
                };
                Value::Float(value)
            }
            _ => unreachable!("finish_percentile is only reached for percentile kinds"),
        }
    }
}

/// Collapses a [`RowValue`] to its property-value projection for the numeric/extreme aggregate
/// arms: entities/paths become null, lists collapse elementwise (mirrors `eval`'s value-context
/// rule).
fn collapse_rv(rv: &RowValue) -> Value {
    match rv {
        RowValue::Value(v) => v.clone(),
        RowValue::Node(_) | RowValue::Rel(_) | RowValue::Path(_) => Value::Null,
        RowValue::List(items) => Value::List(items.iter().map(collapse_rv).collect()),
        RowValue::Map(entries) => Value::Map(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), collapse_rv(v)))
                .collect(),
        ),
    }
}

/// Materialises a hash join: build a map from join-key tuple to left rows, then probe with the right.
fn hash_join_rows(
    left: &PhysicalOp,
    right: &PhysicalOp,
    join_keys: &[String],
    arg: Option<&Row>,
    ctx: &mut Ctx<'_>,
) -> Result<VecDeque<Row>, ExecError> {
    let mut left_op = build_operator(left, arg, ctx)?;
    let mut build: Vec<(Vec<RowValue>, Row)> = Vec::new();
    while let Some(row) = left_op.next(ctx)? {
        let key = key_of(&row, join_keys);
        build.push((key, row));
    }
    let mut right_op = build_operator(right, arg, ctx)?;
    let mut out = VecDeque::new();
    while let Some(row) = right_op.next(ctx)? {
        let key = key_of(&row, join_keys);
        for (lkey, lrow) in &build {
            if keys_match(lkey, &key) {
                out.push_back(merge_rows(lrow, &row));
            }
        }
    }
    Ok(out)
}

/// The join-key tuple of a row (the values bound to the named keys; absent → null).
fn key_of(row: &Row, keys: &[String]) -> Vec<RowValue> {
    keys.iter()
        .map(|k| row.get(k).cloned().unwrap_or(RowValue::NULL))
        .collect()
}

/// Whether two join keys match under grouping equivalence (so `null`/`NaN` join consistently).
fn keys_match(a: &[RowValue], b: &[RowValue]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| row_values_equivalent(x, y))
}

/// Materialises a `UNION`/`UNION ALL`: concatenate both branches; for plain `UNION`, de-duplicate by
/// equivalence (`04 §7.6`).
fn union_rows(
    left: &PhysicalOp,
    right: &PhysicalOp,
    all: bool,
    arg: Option<&Row>,
    ctx: &mut Ctx<'_>,
) -> Result<VecDeque<Row>, ExecError> {
    let mut out: Vec<Row> = Vec::new();
    let push = |row: Row, out: &mut Vec<Row>| {
        if all || !out.iter().any(|r| rows_equivalent(r, &row)) {
            out.push(row);
        }
    };
    let mut lop = build_operator(left, arg, ctx)?;
    while let Some(row) = lop.next(ctx)? {
        push(row, &mut out);
    }
    let mut rop = build_operator(right, arg, ctx)?;
    while let Some(row) = rop.next(ctx)? {
        push(row, &mut out);
    }
    Ok(out.into())
}

// =================================================================================================
// Write application
// =================================================================================================

/// Applies a write to the graph for one driving row, returning the output rows.
///
/// Every write kind produces exactly one row — the input row extended with any new bindings —
/// **except** `MERGE`, which fans out **one row per match** when its pattern matches several existing
/// entities (`clauses/merge/Merge5` [3]).
fn apply_write(kind: &WriteKind, row: Row, ctx: &mut Ctx<'_>) -> Result<Vec<Row>, ExecError> {
    match kind {
        WriteKind::Create { pattern } => Ok(vec![create_pattern(pattern, row, ctx)?]),
        WriteKind::Merge {
            pattern,
            on_create,
            on_match,
        } => merge_pattern(pattern, on_create, on_match, row, ctx),
        WriteKind::Set { ops } => {
            apply_set_ops(ops, &row, ctx)?;
            Ok(vec![row])
        }
        WriteKind::Delete { detach, exprs } => {
            apply_delete(*detach, exprs, &row, ctx)?;
            Ok(vec![row])
        }
        WriteKind::Remove { ops } => {
            apply_remove_ops(ops, &row, ctx)?;
            Ok(vec![row])
        }
    }
}

/// Creates each part of a CREATE pattern, binding new entities into `row`.
fn create_pattern(
    pattern: &[CreatePart],
    mut row: Row,
    ctx: &mut Ctx<'_>,
) -> Result<Row, ExecError> {
    for part in pattern {
        match part {
            CreatePart::Node {
                variable,
                labels,
                properties,
            } => {
                // A variable already bound — by an earlier comma-separated pattern part or a prior
                // clause (e.g. `CREATE (a {..}), (a)-[:R]->(b)` or `MATCH (a) CREATE (a)-[:R]->(b)`)
                // — REFERENCES the existing node; it must not create a second one (`rmp` task #41).
                // Anonymous nodes get unique generated variable names, so they never collide here and
                // are always created.
                if row
                    .get(&variable.name)
                    .and_then(RowValue::as_node)
                    .is_some()
                {
                    continue;
                }
                let props = eval_properties(properties.as_ref(), &row, ctx)?;
                let label_names: Vec<String> = labels.iter().map(|l| l.name.clone()).collect();
                let id = ctx.graph.create_node(&label_names, &props);
                row.set(variable.name.clone(), RowValue::Node(NodeRef { id }));
            }
            CreatePart::Relationship {
                variable,
                from,
                to,
                rel_type,
                direction,
                properties,
            } => {
                let props = eval_properties(properties.as_ref(), &row, ctx)?;
                let (start, end) = rel_endpoints(from, to, *direction, &row)?;
                let id = ctx.graph.create_rel(&rel_type.name, start, end, &props);
                row.set(variable.name.clone(), RowValue::Rel(RelRef { id }));
            }
        }
    }
    Ok(row)
}

/// Resolves a relationship's `(start, end)` node ids from the bound endpoint variables, honouring
/// the pattern arrow direction.
fn rel_endpoints(
    from: &Var,
    to: &Var,
    direction: RelDirection,
    row: &Row,
) -> Result<(NodeId, NodeId), ExecError> {
    let f = row
        .get(&from.name)
        .and_then(RowValue::as_node)
        .ok_or_else(|| ExecError::NotAnEntity {
            context: format!("relationship start `{}`", from.name),
        })?;
    let t = row
        .get(&to.name)
        .and_then(RowValue::as_node)
        .ok_or_else(|| ExecError::NotAnEntity {
            context: format!("relationship end `{}`", to.name),
        })?;
    match direction {
        RelDirection::RightToLeft => Ok((t, f)),
        RelDirection::LeftToRight | RelDirection::Undirected => Ok((f, t)),
    }
}

/// `MERGE`: try to match the pattern against the current row; create it if no match exists. Runs the
/// `ON MATCH` / `ON CREATE` side-effects accordingly.
///
/// openCypher `MERGE` semantics: if the pattern matches **at least one** existing binding, bind
/// **all** matches (one output row each) and run `ON MATCH`; otherwise create **exactly one**
/// instance and run `ON CREATE` (`clauses/merge/Merge5` [3] requires the multi-match fan-out).
fn merge_pattern(
    pattern: &[CreatePart],
    on_create: &[SetOp],
    on_match: &[SetOp],
    row: Row,
    ctx: &mut Ctx<'_>,
) -> Result<Vec<Row>, ExecError> {
    let matched = try_match_pattern(pattern, &row, ctx)?;
    if !matched.is_empty() {
        for m in &matched {
            apply_set_ops(on_match, m, ctx)?;
        }
        Ok(matched)
    } else {
        let created = create_pattern(pattern, row, ctx)?;
        apply_set_ops(on_create, &created, ctx)?;
        Ok(vec![created])
    }
}

/// Finds **every** existing binding satisfying the MERGE pattern, given the already-bound row.
///
/// Supports the shapes MERGE admits: a single node `MERGE (n:Label {props})`, and a relationship
/// `MERGE (a)-[r:T {props}]->(b)` (directed or undirected) whose endpoints are already bound or
/// matched earlier in the pattern. Returns one row per match (extended with the matched bindings),
/// or an empty vector when no match exists. Each part fans the working rows out over its candidates,
/// so several matches multiply (`clauses/merge/Merge5` [3]).
fn try_match_pattern(
    pattern: &[CreatePart],
    row: &Row,
    ctx: &mut Ctx<'_>,
) -> Result<Vec<Row>, ExecError> {
    // Start from the single driving row; each part either keeps a working row (a reused/bound entity),
    // matches it against zero or more candidates (fanning out), or eliminates it (no match). An empty
    // working set at any point means "no match" — `MERGE` then creates.
    let mut working = vec![row.clone()];
    for part in pattern {
        let mut next = Vec::new();
        for w in working {
            match part {
                CreatePart::Node {
                    variable,
                    labels,
                    properties,
                } => {
                    // A variable already bound to a node (prior MATCH/MERGE) is reused as-is.
                    if w.get(&variable.name).and_then(RowValue::as_node).is_some() {
                        next.push(w);
                        continue;
                    }
                    let props = eval_merge_properties(properties.as_ref(), &w, ctx)?;
                    let label_names: Vec<String> = labels.iter().map(|l| l.name.clone()).collect();
                    let candidates = match label_names.first() {
                        Some(first) => ctx.graph.scan_nodes_by_label(first),
                        None => ctx.graph.scan_nodes(),
                    };
                    for id in candidates {
                        if node_has_labels(id, &label_names, ctx) && node_has_props(id, &props, ctx)
                        {
                            let mut row = w.clone();
                            row.set(variable.name.clone(), RowValue::Node(NodeRef { id }));
                            next.push(row);
                        }
                    }
                }
                CreatePart::Relationship {
                    variable,
                    from,
                    to,
                    rel_type,
                    direction,
                    properties,
                } => {
                    let props = eval_merge_properties(properties.as_ref(), &w, ctx)?;
                    // Endpoints are resolved in pattern order (left node, right node). A directed
                    // pattern fixes the orientation; an undirected one matches a relationship in either
                    // orientation between the two endpoints.
                    let (left, right) = rel_endpoints(from, to, RelDirection::LeftToRight, &w)?;
                    let type_names = [rel_type.name.clone()];
                    // `expand(..Both..)` reports each incident relationship once per side it touches, so
                    // a self-loop (or an `a`/`b` alias of the same node) appears twice; dedup by
                    // relationship id so one relationship yields at most one match per working row
                    // (`clauses/merge/Merge5` [18][19]).
                    let mut seen = std::collections::HashSet::new();
                    for inc in ctx.graph.expand(left, ExpandDirection::Both, &type_names) {
                        // Keep only the side whose neighbour is the other endpoint.
                        if inc.neighbour != right {
                            continue;
                        }
                        // Orientation gate: a left-to-right pattern accepts only `left -> right`; a
                        // right-to-left pattern accepts only `right -> left`; an undirected pattern
                        // accepts either.
                        let is_outgoing = rel_starts_at(inc.rel, left, ctx);
                        let accept = match direction {
                            RelDirection::LeftToRight => is_outgoing,
                            RelDirection::RightToLeft => !is_outgoing,
                            RelDirection::Undirected => true,
                        };
                        if accept && seen.insert(inc.rel) && rel_has_props(inc.rel, &props, ctx) {
                            let mut row = w.clone();
                            row.set(variable.name.clone(), RowValue::Rel(RelRef { id: inc.rel }));
                            next.push(row);
                        }
                    }
                }
            }
        }
        working = next;
        if working.is_empty() {
            return Ok(Vec::new());
        }
    }
    Ok(working)
}

/// Whether relationship `rel` has `node` as its start node (used to orient an undirected MERGE match
/// reported through a `Both` expansion).
fn rel_starts_at(rel: crate::graph_access::RelId, node: NodeId, ctx: &Ctx<'_>) -> bool {
    ctx.graph.rel_data(rel).is_some_and(|d| d.start == node)
}

/// Whether a node carries all of `labels`.
fn node_has_labels(id: NodeId, labels: &[String], ctx: &Ctx<'_>) -> bool {
    match ctx.graph.node_labels(id) {
        Some(nl) => labels.iter().all(|l| nl.iter().any(|x| x == l)),
        None => false,
    }
}

/// Whether a node has every `(key, value)` of `props` (the MERGE match predicate).
fn node_has_props(id: NodeId, props: &[(String, Value)], ctx: &Ctx<'_>) -> bool {
    props.iter().all(|(k, v)| {
        ctx.graph
            .node_property(id, k)
            .is_some_and(|nv| crate::equality::equals(&nv, v).is_true())
    })
}

/// Whether a relationship has every `(key, value)` of `props`.
fn rel_has_props(id: crate::graph_access::RelId, props: &[(String, Value)], ctx: &Ctx<'_>) -> bool {
    props.iter().all(|(k, v)| {
        ctx.graph
            .rel_property(id, k)
            .is_some_and(|rv| crate::equality::equals(&rv, v).is_true())
    })
}

/// Evaluates an inline property-map expression into `(key, value)` pairs (empty when absent).
fn eval_properties(
    props: Option<&Expr>,
    row: &Row,
    ctx: &mut Ctx<'_>,
) -> Result<Vec<(String, Value)>, ExecError> {
    let Some(expr) = props else {
        return Ok(Vec::new());
    };
    match eval_value(expr, row, ctx.params, ctx.graph, ctx.functions)? {
        Value::Map(entries) => Ok(entries),
        Value::Null => Ok(Vec::new()),
        _ => Err(ExecError::PropertiesNotAMap),
    }
}

/// Evaluates a `MERGE` pattern element's inline property map, rejecting any **null** value.
///
/// `MERGE` cannot match-or-create on a null property predicate, so a map carrying a null value
/// (`MERGE ({num: null})`) is the runtime TCK `SemanticError: MergeReadOwnWrites`
/// (`clauses/merge/Merge1` [17], `Merge5` [29]). The null is only observable once the map is
/// evaluated, hence this is necessarily a runtime check.
fn eval_merge_properties(
    props: Option<&Expr>,
    row: &Row,
    ctx: &mut Ctx<'_>,
) -> Result<Vec<(String, Value)>, ExecError> {
    let entries = eval_properties(props, row, ctx)?;
    if entries.iter().any(|(_, v)| v.is_null()) {
        return Err(ExecError::MergeNullProperty);
    }
    Ok(entries)
}

/// Evaluates the right-hand side of `SET x = src` / `SET x += src` into the property `(key, value)`
/// pairs to apply.
///
/// The source may be a **map literal** (`SET r += {a: 1}`) **or another graph entity** (`SET r = a`,
/// `SET r += b`): copying an entity's properties is openCypher `SET … = node`/`= relationship`
/// (`clauses/merge/Merge6` [6], `Merge7` [4]). A `null` source clears (replace) or is a no-op overlay
/// (merge); anything else is a runtime type error.
fn eval_property_source(
    value: &Expr,
    row: &Row,
    ctx: &mut Ctx<'_>,
) -> Result<Vec<(String, Value)>, ExecError> {
    match eval(value, row, ctx.params, ctx.graph, ctx.functions)? {
        // A graph entity contributes its own property set (the `SET x = entity` copy form).
        RowValue::Node(n) => Ok(ctx.graph.node_properties(n.id).unwrap_or_default()),
        RowValue::Rel(r) => Ok(ctx.graph.rel_properties(r.id).unwrap_or_default()),
        // A map literal/value contributes its entries directly.
        RowValue::Value(Value::Map(entries)) => Ok(entries),
        RowValue::Map(entries) => Ok(entries
            .into_iter()
            .map(|(k, v)| (k, crate::eval::to_value(v)))
            .collect()),
        RowValue::Value(Value::Null) => Ok(Vec::new()),
        _ => Err(ExecError::PropertiesNotAMap),
    }
}

/// Applies a list of `SET` ops to the current row's bound entities.
fn apply_set_ops(ops: &[SetOp], row: &Row, ctx: &mut Ctx<'_>) -> Result<(), ExecError> {
    for op in ops {
        match op {
            SetOp::Property { target, value } => {
                let (entity, key) = resolve_property_target(target, row)?;
                let v = eval_value(value, row, ctx.params, ctx.graph, ctx.functions)?;
                set_entity_property(entity, &key, v, ctx);
            }
            SetOp::ReplaceProperties { target, value } => {
                let entity = entity_ref(target, row)?;
                let props = eval_property_source(value, row, ctx)?;
                match entity {
                    EntityRef::Node(id) => ctx.graph.replace_node_properties(id, &props),
                    EntityRef::Rel(id) => ctx.graph.replace_rel_properties(id, &props),
                }
            }
            SetOp::MergeProperties { target, value } => {
                let entity = entity_ref(target, row)?;
                let props = eval_property_source(value, row, ctx)?;
                match entity {
                    EntityRef::Node(id) => ctx.graph.merge_node_properties(id, &props),
                    EntityRef::Rel(id) => ctx.graph.merge_rel_properties(id, &props),
                }
            }
            SetOp::AddLabels { target, labels } => {
                let id = entity_node(target, row)?;
                let names: Vec<String> = labels.iter().map(|l| l.name.clone()).collect();
                ctx.graph.add_labels(id, &names);
            }
        }
    }
    Ok(())
}

/// The entity + property key referenced by a `SET a.b = …` target (`a.b`).
fn resolve_property_target(target: &Expr, row: &Row) -> Result<(EntityRef, String), ExecError> {
    let ExprKind::Property { base, key } = &target.kind else {
        return Err(ExecError::NotAnEntity {
            context: "SET target must be a property access".to_owned(),
        });
    };
    let ExprKind::Variable(name) = &base.kind else {
        return Err(ExecError::NotAnEntity {
            context: "SET target base must be a variable".to_owned(),
        });
    };
    let entity = match row.get(name) {
        Some(RowValue::Node(n)) => EntityRef::Node(n.id),
        Some(RowValue::Rel(r)) => EntityRef::Rel(r.id),
        _ => {
            return Err(ExecError::NotAnEntity {
                context: format!("`{name}` is not a bound node or relationship"),
            });
        }
    };
    Ok((entity, key.clone()))
}

/// A node-or-relationship reference resolved from a row binding.
#[derive(Clone, Copy)]
enum EntityRef {
    Node(NodeId),
    Rel(crate::graph_access::RelId),
}

/// Sets a property on a node or relationship.
fn set_entity_property(entity: EntityRef, key: &str, value: Value, ctx: &mut Ctx<'_>) {
    match entity {
        EntityRef::Node(id) => ctx.graph.set_node_property(id, key, value),
        EntityRef::Rel(id) => ctx.graph.set_rel_property(id, key, value),
    }
}

/// Resolves a variable expression to a bound node id (for label ops, which apply only to nodes).
fn entity_node(target: &Var, row: &Row) -> Result<NodeId, ExecError> {
    row.get(&target.name)
        .and_then(RowValue::as_node)
        .ok_or_else(|| ExecError::NotAnEntity {
            context: format!("`{}` is not a bound node", target.name),
        })
}

/// Resolves a variable to the node **or relationship** it is bound to (for `SET x = map` / `SET x +=
/// map`, which apply to either; `clauses/merge/Merge6` [6][7], `Merge7` [4][5]).
fn entity_ref(target: &Var, row: &Row) -> Result<EntityRef, ExecError> {
    match row.get(&target.name) {
        Some(RowValue::Node(n)) => Ok(EntityRef::Node(n.id)),
        Some(RowValue::Rel(r)) => Ok(EntityRef::Rel(r.id)),
        _ => Err(ExecError::NotAnEntity {
            context: format!("`{}` is not a bound node or relationship", target.name),
        }),
    }
}

/// Applies a `[DETACH] DELETE` to the entities the expressions resolve to.
///
/// A single `DELETE` clause is **two-phase**: it first collects every distinct relationship and
/// node its expressions resolve to (recursing through lists, maps and paths), then deletes **all
/// relationships before any node**. This is what lets a plain (non-`DETACH`) `DELETE` of two
/// overlapping paths succeed — once every targeted relationship is gone, each targeted node is
/// isolated and the connectedness rule is satisfied (openCypher `DELETE pathColls.key[0],
/// pathColls.key[1]`; `clauses/delete/Delete5.feature` [7]). Deduplicating by id makes the delete
/// idempotent across overlapping targets and keeps the side-effect counts exact (each element
/// counted once).
fn apply_delete(
    detach: bool,
    exprs: &[Expr],
    row: &Row,
    ctx: &mut Ctx<'_>,
) -> Result<(), ExecError> {
    // Preserve first-seen order while deduping, so deletion order is deterministic.
    let mut rel_ids: Vec<RelId> = Vec::new();
    let mut node_ids: Vec<NodeId> = Vec::new();
    let mut seen_rels = std::collections::BTreeSet::new();
    let mut seen_nodes = std::collections::BTreeSet::new();
    for expr in exprs {
        let value = eval(expr, row, ctx.params, ctx.graph, ctx.functions)?;
        collect_delete_targets(
            value,
            &mut rel_ids,
            &mut node_ids,
            &mut seen_rels,
            &mut seen_nodes,
        );
    }

    // Phase 1: every targeted relationship (idempotent on an already-gone relationship).
    for rid in rel_ids {
        ctx.graph.delete_rel(rid);
    }
    // Phase 2: every targeted node, now under the connectedness rule against the *remaining*
    // relationships (those not in this clause's target set).
    for nid in node_ids {
        delete_node(detach, nid, ctx)?;
    }
    Ok(())
}

/// Recursively gathers the graph elements a `DELETE` target resolves to into the dedup'd
/// relationship / node id sets. A relationship contributes its id; a node its id; a path all its
/// relationship ids then all its node ids; a list/structural-map recurses into its elements/values.
/// Null and any other non-entity value is a no-op (Cypher ignores null/non-entity `DELETE`).
fn collect_delete_targets(
    target: RowValue,
    rel_ids: &mut Vec<RelId>,
    node_ids: &mut Vec<NodeId>,
    seen_rels: &mut std::collections::BTreeSet<RelId>,
    seen_nodes: &mut std::collections::BTreeSet<NodeId>,
) {
    match target {
        RowValue::Rel(r) => {
            if seen_rels.insert(r.id) {
                rel_ids.push(r.id);
            }
        }
        RowValue::Node(n) => {
            if seen_nodes.insert(n.id) {
                node_ids.push(n.id);
            }
        }
        RowValue::Path(p) => {
            for rel in p.rels() {
                if seen_rels.insert(rel) {
                    rel_ids.push(rel);
                }
            }
            for node in p.nodes() {
                if seen_nodes.insert(node) {
                    node_ids.push(node);
                }
            }
        }
        RowValue::List(items) => {
            for item in items {
                collect_delete_targets(item, rel_ids, node_ids, seen_rels, seen_nodes);
            }
        }
        // A map is not itself a deletable entity; deleting its graph elements is done by accessing
        // them (`DELETE m.key`), which unwraps to the inner node/rel/path before reaching here. A
        // bare map (like any non-entity value) is a no-op, matching Cypher's null/non-entity rule.
        RowValue::Map(_) | RowValue::Value(_) => {}
    }
}

/// Deletes one node under the connectedness rule: remaining incident relationships fail the delete
/// unless `DETACH` removes them first. By the time this runs in [`apply_delete`], every
/// relationship the same clause targets is already gone, so only relationships *outside* the
/// delete set can trip the rule.
fn delete_node(detach: bool, id: NodeId, ctx: &mut Ctx<'_>) -> Result<(), ExecError> {
    let incident = ctx.graph.incident_rels(id);
    if !incident.is_empty() {
        if detach {
            for r in incident {
                ctx.graph.delete_rel(r);
            }
        } else {
            return Err(ExecError::DeleteConnectedNode);
        }
    }
    ctx.graph.delete_node(id);
    Ok(())
}

/// Applies a list of `REMOVE` ops.
fn apply_remove_ops(ops: &[RemoveOp], row: &Row, ctx: &mut Ctx<'_>) -> Result<(), ExecError> {
    for op in ops {
        match op {
            RemoveOp::Labels { target, labels } => {
                let id = entity_node(target, row)?;
                let names: Vec<String> = labels.iter().map(|l| l.name.clone()).collect();
                ctx.graph.remove_labels(id, &names);
            }
            RemoveOp::Property { target } => {
                let (entity, key) = resolve_property_target(target, row)?;
                match entity {
                    EntityRef::Node(id) => ctx.graph.remove_node_property(id, &key),
                    EntityRef::Rel(id) => ctx.graph.remove_rel_property(id, &key),
                }
            }
        }
    }
    Ok(())
}

// =================================================================================================
// Public execution API: Executor, Cursor, execute
// =================================================================================================

/// A lazy **result cursor** over an executing query (`04 §7.7`).
///
/// The caller pulls rows on demand with [`pull`](Self::pull) (PULL `n`) or [`next`](Self::next),
/// so results are produced lazily and memory stays bounded. The cursor borrows the graph mutably for
/// its lifetime (the executor may write); when it is dropped the borrow is released. Each pull polls
/// the [`CancellationToken`]; a tripped token surfaces as [`ExecError::Cancelled`].
#[must_use = "a cursor yields no rows unless pulled"]
pub struct Cursor<'a> {
    root: Operator,
    params: BoundParameters,
    token: CancellationToken,
    graph: &'a mut dyn GraphAccess,
    functions: &'a dyn FunctionRegistry,
    procedures: &'a dyn ProcedureRegistry,
    columns: Vec<String>,
    finished: bool,
    /// `false` for a write statement with no `RETURN`: the cursor drains its operator tree to apply
    /// the side effects but presents an empty result (openCypher write cardinality).
    emits_rows: bool,
}

impl<'a> Cursor<'a> {
    /// The result column names, in order — the schema the rows carry (`04 §7.7`).
    #[must_use]
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// Pulls the next row, `None` at end of stream.
    ///
    /// Deliberately **not** [`Iterator::next`]: it returns a `Result` (a pull can fail with a
    /// runtime error or cancellation, `04 §7.7`) and the cursor borrows the graph mutably for its
    /// lifetime, neither of which `Iterator` can express. The name matches the Volcano-cursor
    /// vocabulary of `04 §7.4`.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Cancelled`] if the cancellation token tripped, or another [`ExecError`]
    /// for a runtime failure during row production.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Row>, ExecError> {
        if self.finished {
            return Ok(None);
        }
        let mut ctx = Ctx {
            params: &self.params,
            token: &self.token,
            graph: self.graph,
            functions: self.functions,
            procedures: self.procedures,
        };
        // A write statement with no `RETURN` yields zero rows (openCypher write cardinality), but
        // its side effects must still happen: drain the operator tree once so every write `next()`
        // fires (e.g. `MATCH (n) SET n.x = 1` applies all N updates), then present an empty result.
        if !self.emits_rows {
            self.finished = true;
            loop {
                match self.root.next(&mut ctx) {
                    Ok(Some(_)) => {}
                    Ok(None) => return Ok(None),
                    Err(e) => return Err(e),
                }
            }
        }
        match self.root.next(&mut ctx) {
            Ok(Some(row)) => Ok(Some(row)),
            Ok(None) => {
                self.finished = true;
                Ok(None)
            }
            Err(e) => {
                // On any error (including cancellation) the cursor is spent — do not keep pulling.
                self.finished = true;
                Err(e)
            }
        }
    }

    /// Pulls up to `n` rows (PULL `n` flow control, `04 §7.7`). Fewer than `n` rows means the stream
    /// ended; `n == 0` returns no rows.
    ///
    /// # Errors
    ///
    /// Propagates the first [`ExecError`] encountered while producing the batch.
    pub fn pull(&mut self, n: usize) -> Result<Vec<Row>, ExecError> {
        let mut out = Vec::new();
        for _ in 0..n {
            match self.next()? {
                Some(row) => out.push(row),
                None => break,
            }
        }
        Ok(out)
    }

    /// Drains every remaining row (PULL all). Convenience over [`pull`](Self::pull).
    ///
    /// # Errors
    ///
    /// Propagates the first [`ExecError`] encountered.
    pub fn collect_all(&mut self) -> Result<Vec<Row>, ExecError> {
        let mut out = Vec::new();
        while let Some(row) = self.next()? {
            out.push(row);
        }
        Ok(out)
    }

    /// Pulls the next row and **materializes** it for the wire (`04 §8.3`): each cell becomes a
    /// [`MaterializedValue`](crate::result::MaterializedValue) with every entity's labels / type /
    /// endpoints / properties resolved through the cursor's graph seam. `None` at end of stream.
    ///
    /// This is the egress counterpart to [`next`](Self::next): the lazy [`RowValue`] ids are kept
    /// inside the engine (operators, equality/ordering, the TCK comparison path all run on
    /// [`Row`]/[`RowValue`] unchanged), and resolution to a full structural value happens **only**
    /// here, at the boundary, reading through the same `&mut dyn GraphAccess` the cursor holds. RBAC
    /// (rmp #93) and MVCC visibility therefore compose for free — a hidden property is already
    /// `None` and an invisible entity already filtered before this resolves anything.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Cancelled`] if the cancellation token tripped, or another [`ExecError`]
    /// for a runtime failure during row production (materialization itself is infallible — an absent
    /// entity resolves to an empty stub, never an error).
    pub fn next_materialized(
        &mut self,
    ) -> Result<Option<Vec<crate::result::MaterializedValue>>, ExecError> {
        match self.next()? {
            Some(row) => Ok(Some(crate::result::materialize_row(self.graph, &row))),
            None => Ok(None),
        }
    }

    /// Materializes an already-pulled [`Row`] through the cursor's graph seam (`04 §8.3`).
    ///
    /// The row-at-a-time counterpart to [`next_materialized`](Self::next_materialized) for callers
    /// that hold a [`Row`] (e.g. a `pull(n)` batch) and want its wire form. Resolution reads through
    /// the cursor's `&mut dyn GraphAccess`, so RBAC/MVCC apply exactly as for `next_materialized`.
    #[must_use]
    pub fn materialize_row(&mut self, row: &Row) -> Vec<crate::result::MaterializedValue> {
        crate::result::materialize_row(self.graph, row)
    }
}

/// The compiled executor for one plan: holds the plan + parameters and opens [`Cursor`]s over a
/// graph (`04 §7.4`).
///
/// Separating the [`Executor`] (plan + params) from the [`Cursor`] (a live run over a graph) lets
/// the same compiled execution be re-run against different graph states, and keeps the mutable graph
/// borrow scoped to the cursor.
#[must_use]
pub struct Executor {
    plan: PhysicalPlan,
    params: BoundParameters,
}

impl Executor {
    /// Builds an executor for `plan` bound with `params`.
    pub fn new(plan: PhysicalPlan, params: BoundParameters) -> Self {
        Self { plan, params }
    }

    /// The result column names this plan produces (the root projection's output schema), resolved
    /// against the engine's [built-in procedures](crate::procedure_registry::builtins). When
    /// running against a caller-supplied registry, use the columns of the cursor returned by
    /// [`open_with_procedures`](Self::open_with_procedures) instead.
    #[must_use]
    pub fn columns(&self) -> Vec<String> {
        result_columns(&self.plan.root, procedure_registry::builtins())
    }

    /// Opens a [`Cursor`] over `graph` with cancellation token `token` (`04 §7.7`), resolving any
    /// procedure call against the engine [built-ins](crate::procedure_registry::builtins).
    ///
    /// Leaf scans and materialising operators are computed during this call (they need the graph);
    /// streaming operators stay lazy and are driven by [`Cursor::next`] / [`Cursor::pull`].
    ///
    /// # Errors
    ///
    /// Returns an [`ExecError`] if building a materialising operator (e.g. evaluating a `TopN`
    /// limit, or folding an aggregate) hits a runtime error, or if the token was already cancelled.
    pub fn open<'a>(
        &self,
        graph: &'a mut dyn GraphAccess,
        token: CancellationToken,
    ) -> Result<Cursor<'a>, ExecError> {
        self.open_with_procedures(graph, token, procedure_registry::builtins())
    }

    /// [`open`](Self::open) against a caller-supplied [`ProcedureRegistry`] (rmp #57).
    ///
    /// The registry must be the **same** one the statement was compiled against
    /// ([`crate::semantics::analyze_with_procedures`]); a swap between the phases voids the
    /// compile-time procedure guarantees.
    ///
    /// # Errors
    ///
    /// As [`open`](Self::open), plus [`ExecError::Procedure`] if the plan calls a procedure the
    /// registry does not provide (a compile/execute registry mismatch) or a `YIELD` names a result
    /// field the signature does not declare.
    pub fn open_with_procedures<'a>(
        &self,
        graph: &'a mut dyn GraphAccess,
        token: CancellationToken,
        procedures: &'a dyn ProcedureRegistry,
    ) -> Result<Cursor<'a>, ExecError> {
        // A pure pass-through to the extensions form with an empty function registry: the
        // function-less callers (this one, used by the TCK harness, and `open`) see only the
        // built-in functions, so their behaviour is byte-identical to before the extension
        // mechanism (`rmp` task #75).
        self.open_with_extensions(graph, token, function_registry::no_functions(), procedures)
    }

    /// [`open`](Self::open) against caller-supplied **function** and **procedure** registries (`rmp`
    /// task #75).
    ///
    /// Both registries must be the **same** ones the statement was compiled against
    /// ([`crate::semantics::analyze_with_extensions`]); a swap between the phases voids the
    /// compile-time guarantees. [`open`](Self::open) and [`open_with_procedures`](Self::open_with_procedures)
    /// are thin wrappers over this with an empty
    /// [`FunctionRegistry`](crate::function_registry::no_functions).
    ///
    /// # Errors
    ///
    /// As [`open_with_procedures`](Self::open_with_procedures); additionally, a user-defined-function
    /// body failure surfaces (during streaming) as
    /// [`ExecError::Eval`]`(`[`EvalError::ExtensionFunction`]`)`.
    pub fn open_with_extensions<'a>(
        &self,
        graph: &'a mut dyn GraphAccess,
        token: CancellationToken,
        functions: &'a dyn FunctionRegistry,
        procedures: &'a dyn ProcedureRegistry,
    ) -> Result<Cursor<'a>, ExecError> {
        let columns = result_columns(&self.plan.root, procedures);
        let root = {
            let mut ctx = Ctx {
                params: &self.params,
                token: &token,
                graph,
                functions,
                procedures,
            };
            build_operator(&self.plan.root, None, &mut ctx)?
        };
        Ok(Cursor {
            root,
            params: self.params.clone(),
            token,
            graph,
            functions,
            procedures,
            columns,
            finished: false,
            emits_rows: !root_is_write(&self.plan.root),
        })
    }

    /// [`open_with_extensions`](Self::open_with_extensions) **seeded** with a correlation row.
    ///
    /// The plan's [`Argument`](crate::physical::PhysicalOp::Argument) leaf reads its declared columns
    /// from `seed`; every other leaf ignores it. This drives a **correlated subplan** — the inner
    /// plan of the full-query form of an `EXISTS { ... }` subquery (`rmp` #123), whose root chain
    /// bottoms out at an `Argument` seeded with the outer row, so a correlated `MATCH (n)` reuses the
    /// outer `n` rather than re-scanning the graph.
    ///
    /// # Errors
    ///
    /// As [`open_with_extensions`](Self::open_with_extensions).
    pub fn open_seeded<'a>(
        &self,
        graph: &'a mut dyn GraphAccess,
        token: CancellationToken,
        functions: &'a dyn FunctionRegistry,
        procedures: &'a dyn ProcedureRegistry,
        seed: &Row,
    ) -> Result<Cursor<'a>, ExecError> {
        let columns = result_columns(&self.plan.root, procedures);
        let root = {
            let mut ctx = Ctx {
                params: &self.params,
                token: &token,
                graph,
                functions,
                procedures,
            };
            build_operator(&self.plan.root, Some(seed), &mut ctx)?
        };
        Ok(Cursor {
            root,
            params: self.params.clone(),
            token,
            graph,
            functions,
            procedures,
            columns,
            finished: false,
            emits_rows: !root_is_write(&self.plan.root),
        })
    }
}

/// Executes `plan` (bound with `params`) over `graph`, returning a [`Cursor`] (`04 §7.4`, §7.7).
///
/// A convenience wrapping [`Executor::open`] with a fresh, untripped [`CancellationToken`] when the
/// caller does not need to cancel. For cancellable execution, construct an [`Executor`] and call
/// [`open`](Executor::open) with a token you retain.
///
/// # Errors
///
/// Returns an [`ExecError`] if opening the cursor (computing leaf/materialising operators) fails.
///
/// # Examples
///
/// ```
/// use graphus_core::Value;
/// use graphus_cypher::{
///     binding::{bind_parameters, Parameters},
///     catalog::IndexCatalog, executor::execute, graph_access::MemGraph,
///     lexer::tokenize, lower::lower, parser::parse_tokens, physical::plan_physical,
///     semantics::analyze,
/// };
///
/// let src = "MATCH (n:Person) RETURN n.name AS name";
/// let toks = tokenize(src).unwrap();
/// let ast = parse_tokens(&toks, src).unwrap();
/// let plan = plan_physical(&lower(&analyze(&ast).unwrap()), &IndexCatalog::empty());
/// let params = bind_parameters(&plan, &Parameters::new()).unwrap();
///
/// let mut graph = MemGraph::new();
/// graph.add_node(["Person"], [("name", Value::String("Ada".into()))]);
///
/// let mut cursor = execute(&plan, &params, &mut graph).unwrap();
/// let rows = cursor.collect_all().unwrap();
/// assert_eq!(rows.len(), 1);
/// assert_eq!(rows[0].value("name"), Value::String("Ada".into()));
/// ```
pub fn execute<'a>(
    plan: &PhysicalPlan,
    params: &BoundParameters,
    graph: &'a mut dyn GraphAccess,
) -> Result<Cursor<'a>, ExecError> {
    Executor::new(plan.clone(), params.clone()).open(graph, CancellationToken::new())
}

/// [`execute`] against a caller-supplied [`ProcedureRegistry`] (rmp #57): a convenience wrapping
/// [`Executor::open_with_procedures`] with a fresh [`CancellationToken`].
///
/// The registry must be the **same** one the statement was compiled against
/// ([`crate::semantics::analyze_with_procedures`]).
///
/// # Errors
///
/// As [`execute`], plus [`ExecError::Procedure`] for a compile/execute registry mismatch.
pub fn execute_with_procedures<'a>(
    plan: &PhysicalPlan,
    params: &BoundParameters,
    graph: &'a mut dyn GraphAccess,
    procedures: &'a dyn ProcedureRegistry,
) -> Result<Cursor<'a>, ExecError> {
    Executor::new(plan.clone(), params.clone()).open_with_procedures(
        graph,
        CancellationToken::new(),
        procedures,
    )
}

/// [`execute`] against caller-supplied **function** and **procedure** registries (`rmp` task #75): a
/// convenience wrapping [`Executor::open_with_extensions`] with a fresh [`CancellationToken`].
///
/// Both registries must be the **same** ones the statement was compiled against
/// ([`crate::semantics::analyze_with_extensions`]).
///
/// # Errors
///
/// As [`execute_with_procedures`]; additionally a user-defined-function body failure surfaces during
/// streaming as [`ExecError::Eval`]`(`[`EvalError::ExtensionFunction`]`)`.
pub fn execute_with_extensions<'a>(
    plan: &PhysicalPlan,
    params: &BoundParameters,
    graph: &'a mut dyn GraphAccess,
    functions: &'a dyn FunctionRegistry,
    procedures: &'a dyn ProcedureRegistry,
) -> Result<Cursor<'a>, ExecError> {
    Executor::new(plan.clone(), params.clone()).open_with_extensions(
        graph,
        CancellationToken::new(),
        functions,
        procedures,
    )
}

/// Whether `op` is a top-level write operator (`Create`/`Merge`/`SetClause`/`Delete`/`Remove`).
/// A query whose physical-plan **root** is such an operator has no `RETURN` and therefore yields
/// zero result rows (openCypher: a write's effect is a summary-only side effect). When a `RETURN`
/// follows the write, the plan root is the projection above it, not the write, so this is false.
fn root_is_write(op: &PhysicalOp) -> bool {
    matches!(
        op,
        PhysicalOp::Create { .. }
            | PhysicalOp::Merge { .. }
            | PhysicalOp::SetClause { .. }
            | PhysicalOp::Delete { .. }
            | PhysicalOp::Remove { .. }
    )
}

/// The result column names a plan produces, derived from its root operator's output schema.
///
/// A `Projection`/`Aggregation` root names its columns explicitly; an `Optional`/`Skip`/`Limit`/
/// `Sort`/`Eager`/`Filter` root delegates to its input's columns. A write root (`Create`/`Merge`/
/// `SetClause`/`Delete`/`Remove`) declares **no** result columns: it has no `RETURN` (a `RETURN`
/// would put a projection above it), so the query yields zero rows. Leaves name their introduced
/// variable(s). A `ProcedureCall` without `YIELD` (the standalone / `YIELD *` form) names the
/// procedure's declared outputs, resolved through `procedures`.
fn result_columns(op: &PhysicalOp, procedures: &dyn ProcedureRegistry) -> Vec<String> {
    match op {
        PhysicalOp::Projection { items, .. } => items.iter().map(|c| c.alias.clone()).collect(),
        PhysicalOp::Aggregation {
            group_keys,
            aggregates,
            ..
        } => group_keys
            .iter()
            .chain(aggregates)
            .map(|c| c.alias.clone())
            .collect(),
        PhysicalOp::Filter { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Eager { input }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::Optional { input, .. } => result_columns(input, procedures),
        // A write root has no `RETURN` (a `RETURN` would put a projection above it), so it declares
        // no result columns — the query yields zero rows (openCypher write cardinality).
        PhysicalOp::Create { .. }
        | PhysicalOp::Merge { .. }
        | PhysicalOp::SetClause { .. }
        | PhysicalOp::Delete { .. }
        | PhysicalOp::Remove { .. } => Vec::new(),
        PhysicalOp::TopN { input, .. } => result_columns(input, procedures),
        PhysicalOp::Unwind {
            input, variable, ..
        }
        | PhysicalOp::LoadCsv {
            input, variable, ..
        }
        | PhysicalOp::NamedPath {
            input, variable, ..
        } => {
            let mut cols = result_columns(input, procedures);
            if !cols.contains(&variable.name) {
                cols.push(variable.name.clone());
            }
            cols
        }
        PhysicalOp::ExpandAll {
            input,
            relationship,
            to,
            ..
        }
        | PhysicalOp::ExpandInto {
            input,
            relationship,
            to,
            ..
        } => {
            let mut cols = result_columns(input, procedures);
            for v in [relationship, to] {
                if !cols.contains(&v.name) {
                    cols.push(v.name.clone());
                }
            }
            cols
        }
        PhysicalOp::ShortestPath {
            input,
            relationship,
            path,
            ..
        } => {
            // Both endpoints are bound by `input`; this operator introduces the relationship list and,
            // when named (`p = shortestPath(...)`), the path variable.
            let mut cols = result_columns(input, procedures);
            if !cols.contains(&relationship.name) {
                cols.push(relationship.name.clone());
            }
            if let Some(p) = path {
                if !cols.contains(&p.name) {
                    cols.push(p.name.clone());
                }
            }
            cols
        }
        PhysicalOp::NestedLoopJoin { left, right } | PhysicalOp::HashJoin { left, right, .. } => {
            let mut cols = result_columns(left, procedures);
            for c in result_columns(right, procedures) {
                if !cols.contains(&c) {
                    cols.push(c);
                }
            }
            cols
        }
        PhysicalOp::Union { left, .. } => result_columns(left, procedures),
        PhysicalOp::AllNodesScan { variable }
        | PhysicalOp::NodeByLabelScan { variable, .. }
        | PhysicalOp::TokenLookupScan { variable, .. }
        | PhysicalOp::NodeIndexSeek { variable, .. }
        | PhysicalOp::NodeIndexRangeSeek { variable, .. }
        | PhysicalOp::SpatialIndexSeek { variable, .. } => vec![variable.name.clone()],
        PhysicalOp::AllRelationshipsScan {
            relationship,
            from,
            to,
            ..
        } => {
            vec![
                from.name.clone(),
                relationship.name.clone(),
                to.name.clone(),
            ]
        }
        PhysicalOp::Argument { arguments } => arguments.iter().map(|v| v.name.clone()).collect(),
        PhysicalOp::Empty => Vec::new(),
        PhysicalOp::ProcedureCall {
            input,
            name,
            yields,
            ..
        } => {
            let mut cols = input
                .as_deref()
                .map(|i| result_columns(i, procedures))
                .unwrap_or_default();
            match yields {
                Some(ys) => {
                    for y in ys.iter().map(|y: &YieldColumn| &y.variable.name) {
                        if !cols.contains(y) {
                            cols.push(y.clone());
                        }
                    }
                }
                // The standalone / `YIELD *` form binds every declared output verbatim. An
                // unknown procedure yields no columns here; opening the cursor then raises the
                // registry-mismatch error.
                None => {
                    if let Some(sig) = procedures.signature(&name.join(".")) {
                        for o in &sig.outputs {
                            if !cols.contains(&o.name) {
                                cols.push(o.name.clone());
                            }
                        }
                    }
                }
            }
            cols
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::IndexCatalog;
    use crate::graph_access::MemGraph;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::plan_physical;
    use crate::semantics::analyze;

    fn run(src: &str, graph: &mut MemGraph) -> Vec<Row> {
        run_with_catalog(src, graph, &IndexCatalog::empty())
    }

    fn run_with_catalog(src: &str, graph: &mut MemGraph, catalog: &IndexCatalog) -> Vec<Row> {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let plan = plan_physical(&lower(&analyze(&ast).expect("analyze")), catalog);
        let params = crate::binding::bind_parameters(&plan, &crate::binding::Parameters::new())
            .expect("bind");
        execute(&plan, &params, graph)
            .expect("open")
            .collect_all()
            .expect("rows")
    }

    const NO_PROPS: [(&str, Value); 0] = [];

    #[test]
    fn match_all_nodes() {
        let mut g = MemGraph::new();
        let _ = g.add_node(["A"], NO_PROPS);
        let _ = g.add_node(["B"], NO_PROPS);
        let rows = run("MATCH (n) RETURN n", &mut g);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.get("n").unwrap().as_node().is_some()));
    }

    #[test]
    fn create_reuses_a_rementioned_variable_across_comma_parts() {
        // `rmp` task #41: `CREATE (a {..}), (a)-[:R]->(b)` must REUSE the bound `a`, creating exactly
        // one `a` (plus one `b` and one relationship), not a second anonymous node.
        let mut g = MemGraph::new();
        let _ = run("CREATE (a {n: 1}), (a)-[:R]->(b {n: 2})", &mut g);

        let mut vs: Vec<i64> = run("MATCH (x) RETURN x.n AS v", &mut g)
            .iter()
            .filter_map(|r| match r.value("v") {
                Value::Integer(k) => Some(k),
                _ => None,
            })
            .collect();
        vs.sort_unstable();
        assert_eq!(
            vs,
            vec![1, 2],
            "exactly one a (n=1) and one b (n=2); no duplicate a"
        );

        let rels = run("MATCH (x)-[:R]->(y) RETURN x.n AS xn, y.n AS yn", &mut g);
        assert_eq!(rels.len(), 1, "exactly one relationship, from the reused a");
        assert_eq!(rels[0].value("xn"), Value::Integer(1));
        assert_eq!(rels[0].value("yn"), Value::Integer(2));
    }

    #[test]
    fn count_star_over_empty_match_is_zero() {
        let mut g = MemGraph::new();
        let rows = run("MATCH (n:Missing) RETURN count(*) AS c", &mut g);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value("c"), Value::Integer(0));
    }

    #[test]
    fn limit_stops_early() {
        let mut g = MemGraph::new();
        for _ in 0..100 {
            let _ = g.add_node(["N"], NO_PROPS);
        }
        let rows = run("MATCH (n) RETURN n LIMIT 3", &mut g);
        assert_eq!(rows.len(), 3);
    }

    /// The result column names this plan declares (the executor's wire schema); for a write without
    /// `RETURN` this is empty — a sibling of [`run`] used by the rmp #97 cardinality regressions.
    /// Needs no graph: [`Executor::columns`] resolves the schema against the built-in procedures.
    fn columns_of(src: &str) -> Vec<String> {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let plan = plan_physical(
            &lower(&analyze(&ast).expect("analyze")),
            &IndexCatalog::empty(),
        );
        let params = crate::binding::bind_parameters(&plan, &crate::binding::Parameters::new())
            .expect("bind");
        Executor::new(plan, params).columns()
    }

    // ---- rmp #97: a write with no `RETURN` yields zero rows but still applies its side effect -----

    #[test]
    fn create_without_return_yields_no_rows_but_persists() {
        let mut g = MemGraph::new();
        let rows = run(
            "CREATE (a:Person {name: 'Ada'})-[:KNOWS]->(b:Person)",
            &mut g,
        );
        assert!(rows.is_empty(), "a write without RETURN echoes no rows");
        assert!(
            columns_of("CREATE (a:Person {name: 'Ada'})-[:KNOWS]->(b:Person)").is_empty(),
            "a write root declares no result columns",
        );

        // The side effect happened: two Person nodes and one KNOWS relationship.
        let names = run("MATCH (n:Person) RETURN n.name AS name", &mut g);
        assert_eq!(names.len(), 2, "both nodes were created");
        let rels = run("MATCH (:Person)-[r:KNOWS]->(:Person) RETURN r", &mut g);
        assert_eq!(rels.len(), 1, "the relationship was created");
    }

    #[test]
    fn set_without_return_yields_no_rows_but_applies_to_every_match() {
        let mut g = MemGraph::new();
        for _ in 0..3 {
            let _ = g.add_node(["N"], NO_PROPS);
        }
        let rows = run("MATCH (n:N) SET n.x = 1", &mut g);
        assert!(rows.is_empty(), "a write without RETURN echoes no rows");

        // The drain applied the write to all three matched nodes.
        let xs = run("MATCH (n:N) RETURN n.x AS x", &mut g);
        assert_eq!(xs.len(), 3);
        assert!(
            xs.iter().all(|r| r.value("x") == Value::Integer(1)),
            "every matched node received x = 1",
        );
    }

    #[test]
    fn delete_without_return_yields_no_rows_but_removes() {
        let mut g = MemGraph::new();
        let _ = g.add_node(["Doomed"], NO_PROPS);
        let _ = g.add_node(["Doomed"], NO_PROPS);
        let rows = run("MATCH (n:Doomed) DELETE n", &mut g);
        assert!(rows.is_empty(), "a write without RETURN echoes no rows");

        let survivors = run("MATCH (n:Doomed) RETURN n", &mut g);
        assert!(survivors.is_empty(), "both nodes were deleted");
    }

    #[test]
    fn delete_node_referenced_through_a_list() {
        // `DELETE friends[0]` must reach the node the list holds (openCypher
        // `clauses/delete/Delete5.feature` [1]). DETACH so the incident relationship is removed too.
        let mut g = MemGraph::new();
        let u = g.add_node(["User"], NO_PROPS);
        let f = g.add_node::<[&str; 0], _, _, _>([], NO_PROPS);
        let _ = g.add_rel("FRIEND", u, f, NO_PROPS);
        let rows = run(
            "MATCH (:User)-[:FRIEND]->(n) WITH collect(n) AS friends DETACH DELETE friends[0]",
            &mut g,
        );
        assert!(rows.is_empty());
        assert_eq!(g.node_count(), 1, "only the friend node was deleted");
        assert_eq!(g.rel_count(), 0, "DETACH removed the incident relationship");
    }

    #[test]
    fn delete_node_referenced_through_a_map() {
        // `DELETE nodes.key` where `nodes` is `{key: u}` must recover the node from the structural
        // map (`clauses/delete/Delete5.feature` [3]).
        let mut g = MemGraph::new();
        let _ = g.add_node(["User"], NO_PROPS);
        let _ = g.add_node(["User"], NO_PROPS);
        let rows = run(
            "MATCH (u:User) WITH {key: u} AS nodes DELETE nodes.key",
            &mut g,
        );
        assert!(rows.is_empty());
        assert_eq!(
            g.node_count(),
            0,
            "both User nodes were deleted via the map"
        );
    }

    #[test]
    fn delete_relationship_referenced_through_a_nested_map() {
        // `DELETE rels.key.key[0]` reaches the relationship a nested map-of-list holds
        // (`clauses/delete/Delete5.feature` [6]).
        let mut g = MemGraph::new();
        let a = g.add_node(["User"], NO_PROPS);
        let b = g.add_node(["User"], NO_PROPS);
        let _ = g.add_rel("R", a, b, NO_PROPS);
        let _ = g.add_rel("R", b, a, NO_PROPS);
        let rows = run(
            "MATCH (:User)-[r]->(:User) WITH {key: {key: collect(r)}} AS rels DELETE rels.key.key[0]",
            &mut g,
        );
        assert!(rows.is_empty());
        assert_eq!(g.node_count(), 2, "no node was deleted");
        assert_eq!(
            g.rel_count(),
            1,
            "exactly one of the two relationships was deleted"
        );
    }

    #[test]
    fn delete_two_overlapping_paths_without_detach() {
        // Two paths over a bidirectional pair: `DELETE p0, p1` must delete every relationship before
        // any node, so the connectedness rule never trips without DETACH
        // (`clauses/delete/Delete5.feature` [7]).
        let mut g = MemGraph::new();
        let a = g.add_node(["User"], NO_PROPS);
        let b = g.add_node(["User"], NO_PROPS);
        let _ = g.add_rel("R", a, b, NO_PROPS);
        let _ = g.add_rel("R", b, a, NO_PROPS);
        let rows = run(
            "MATCH p = (:User)-[r]->(:User) WITH collect(p) AS ps DELETE ps[0], ps[1]",
            &mut g,
        );
        assert!(rows.is_empty());
        assert_eq!(g.node_count(), 0, "both nodes deleted");
        assert_eq!(g.rel_count(), 0, "both relationships deleted");
    }

    #[test]
    fn delete_dedups_repeated_targets() {
        // The same node named twice in one DELETE is deleted exactly once (idempotent), and a node
        // listed alongside its relationship deletes cleanly without DETACH (rels go first).
        let mut g = MemGraph::new();
        let a = g.add_node::<[&str; 0], _, _, _>([], NO_PROPS);
        let b = g.add_node::<[&str; 0], _, _, _>([], NO_PROPS);
        let _ = g.add_rel("R", a, b, NO_PROPS);
        let rows = run("MATCH (a)-[r]->(b) DELETE r, a, b, a", &mut g);
        assert!(rows.is_empty());
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.rel_count(), 0);
    }

    #[test]
    fn delete_of_an_integer_expression_is_a_compile_time_type_error() {
        // `DELETE 1 + 1` is `InvalidArgumentType` (arithmetic), not `InvalidDelete`
        // (`clauses/delete/Delete5.feature` [9]).
        let src = "MATCH () DELETE 1 + 1";
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let err = analyze(&ast).expect_err("DELETE of arithmetic must fail semantic analysis");
        assert_eq!(
            err.classification().detail.as_tck_str(),
            "InvalidArgumentType"
        );
    }

    #[test]
    fn delete_of_a_label_predicate_is_invalid_delete() {
        // `DELETE n:Person` is the syntactic `InvalidDelete` family, distinct from the arithmetic
        // type error above (`clauses/delete/Delete1.feature`).
        let src = "MATCH (n) DELETE n:Person";
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let err = analyze(&ast).expect_err("DELETE of a label predicate must fail");
        assert_eq!(err.classification().detail.as_tck_str(), "InvalidDelete");
    }

    #[test]
    fn merge_without_return_yields_no_rows_but_creates() {
        let mut g = MemGraph::new();
        let rows = run("MERGE (n:Account {id: 7})", &mut g);
        assert!(rows.is_empty(), "a write without RETURN echoes no rows");

        let accts = run("MATCH (n:Account) RETURN n.id AS id", &mut g);
        assert_eq!(accts.len(), 1, "MERGE created the missing node");
        assert_eq!(accts[0].value("id"), Value::Integer(7));
    }

    #[test]
    fn merge_binds_a_node_path() {
        // `clauses/merge/Merge1` [13]: `MERGE p = (a {num: 1}) RETURN p` binds a zero-length path
        // over the merged node.
        let mut g = MemGraph::new();
        let rows = run("MERGE p = (a {num: 1}) RETURN p", &mut g);
        assert_eq!(rows.len(), 1);
        let path = rows[0].get("p").and_then(RowValue::as_path).expect("path");
        assert!(path.is_empty(), "a single-node path has no steps");
        assert_eq!(path.nodes().len(), 1);
    }

    #[test]
    fn merge_binds_a_relationship_path() {
        // `clauses/merge/Merge5` [10]: `MERGE p = (a)-[:R]->(b)` binds a one-hop path over the merged
        // relationship and its endpoints.
        let mut g = MemGraph::new();
        let rows = run(
            "MERGE (a {num: 1}) MERGE (b {num: 2}) MERGE p = (a)-[:R]->(b) RETURN p",
            &mut g,
        );
        assert_eq!(rows.len(), 1);
        let path = rows[0].get("p").and_then(RowValue::as_path).expect("path");
        assert_eq!(path.len(), 1, "one relationship hop");
        assert!(
            path.steps[0].forward,
            "created left-to-right, traversed forward"
        );
    }

    #[test]
    fn merge_does_not_match_a_deleted_node_and_creates_fresh() {
        // `clauses/merge/Merge1` [14]: after `MATCH (a:A) DELETE a`, the MERGE scan must not see the
        // just-deleted nodes, so every row creates a fresh, property-less node (`a2.num` is null).
        let mut g = MemGraph::new();
        let _ = g.add_node(["A"], [("num", Value::Integer(1))]);
        let _ = g.add_node(["A"], [("num", Value::Integer(2))]);
        let rows = run(
            "MATCH (a:A) DELETE a MERGE (a2:A) RETURN a2.num AS num",
            &mut g,
        );
        assert_eq!(rows.len(), 2, "one row per pre-delete A node");
        assert!(
            rows.iter().all(|r| r.value("num") == Value::Null),
            "each MERGE created a fresh property-less node, never matched a deleted one"
        );
        // Net: the two originals are gone, one fresh node remains.
        let live = run("MATCH (n:A) RETURN count(*) AS c", &mut g);
        assert_eq!(live[0].value("c"), Value::Integer(1));
    }

    #[test]
    fn undirected_merge_creates_left_to_right() {
        // `clauses/merge/Merge5` [11]: an undirected MERGE with no match creates the relationship in
        // the canonical left-to-right direction (start = left endpoint).
        let mut g = MemGraph::new();
        let rows = run(
            "CREATE (a {id: 2}), (b {id: 1}) \
             MERGE (a)-[r:KNOWS]-(b) \
             RETURN startNode(r).id AS s, endNode(r).id AS e",
            &mut g,
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value("s"), Value::Integer(2), "start = left node");
        assert_eq!(rows[0].value("e"), Value::Integer(1), "end = right node");
    }

    #[test]
    fn undirected_merge_matches_existing_reversed_relationship() {
        // `clauses/merge/Merge5` [12]: an undirected MERGE matches an existing relationship even when
        // it was stored in the opposite orientation — no new relationship is created.
        let mut g = MemGraph::new();
        let a = g.add_node([] as [&str; 0], [("id", Value::Integer(1))]);
        let b = g.add_node([] as [&str; 0], [("id", Value::Integer(2))]);
        let _ = g.add_rel("KNOWS", a, b, NO_PROPS);
        // Query matches with the endpoints swapped relative to the stored direction.
        let rows = run(
            "MATCH (x {id: 2}), (y {id: 1}) MERGE (x)-[r:KNOWS]-(y) RETURN r",
            &mut g,
        );
        assert_eq!(rows.len(), 1);
        let rels = run("MATCH ()-[r:KNOWS]->() RETURN count(*) AS c", &mut g);
        assert_eq!(rels[0].value("c"), Value::Integer(1), "no new relationship");
    }

    #[test]
    fn merge_matching_two_relationships_yields_two_rows() {
        // `clauses/merge/Merge5` [3]: when the pattern matches two relationships, MERGE binds BOTH
        // (one row each) and creates nothing.
        let mut g = MemGraph::new();
        let a = g.add_node(["A"], NO_PROPS);
        let b = g.add_node(["B"], NO_PROPS);
        let _ = g.add_rel("TYPE", a, b, NO_PROPS);
        let _ = g.add_rel("TYPE", a, b, NO_PROPS);
        let rows = run(
            "MATCH (a:A), (b:B) MERGE (a)-[r:TYPE]->(b) RETURN r",
            &mut g,
        );
        assert_eq!(rows.len(), 2, "both matching relationships are bound");
        let total = run("MATCH ()-[r:TYPE]->() RETURN count(*) AS c", &mut g);
        assert_eq!(total[0].value("c"), Value::Integer(2), "nothing created");
    }

    #[test]
    fn merge_with_null_property_raises_runtime_semantic_error() {
        // `clauses/merge/Merge1` [17]: a null inline property value is a runtime
        // `SemanticError: MergeReadOwnWrites`.
        let mut g = MemGraph::new();
        let err = run_err("MERGE ({num: null})", &mut g);
        assert!(
            matches!(err, ExecError::MergeNullProperty),
            "expected MergeNullProperty, got {err:?}"
        );
    }

    #[test]
    fn merge_copies_relationship_properties_from_a_node() {
        // `clauses/merge/Merge6` [6]: `ON CREATE SET r = a` copies the node `a`'s properties onto the
        // freshly-created relationship.
        let mut g = MemGraph::new();
        let _ = g.add_node(["A"], [("name", Value::String("A".to_owned()))]);
        let _ = g.add_node(["B"], [("name", Value::String("B".to_owned()))]);
        let _ = run(
            "MATCH (a {name: 'A'}), (b {name: 'B'}) \
             MERGE (a)-[r:TYPE]->(b) ON CREATE SET r = a",
            &mut g,
        );
        let rows = run("MATCH ()-[r:TYPE]->() RETURN r.name AS name", &mut g);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value("name"), Value::String("A".to_owned()));
    }

    #[test]
    fn merge_parameter_predicate_is_rejected_at_compile_time() {
        // `clauses/merge/Merge1` [16]: a parameter as a MERGE node predicate is the compile-time
        // SyntaxError `InvalidParameterUse` — raised by semantic analysis, before execution.
        use crate::errors::SemanticErrorKind;
        let src = "MERGE (n $param) RETURN n";
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let err = analyze(&ast).expect_err("must be rejected");
        assert!(
            matches!(err.kind, SemanticErrorKind::InvalidParameterUse),
            "expected InvalidParameterUse, got {:?}",
            err.kind
        );
    }

    #[test]
    fn remove_without_return_yields_no_rows_but_strips_property() {
        let mut g = MemGraph::new();
        let _ = g.add_node(["P"], [("doomed", Value::Integer(1))]);
        let rows = run("MATCH (n:P) REMOVE n.doomed", &mut g);
        assert!(rows.is_empty(), "a write without RETURN echoes no rows");

        let after = run("MATCH (n:P) RETURN n.doomed AS d", &mut g);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].value("d"), Value::Null, "the property was removed");
    }

    #[test]
    fn returning_write_still_yields_its_row() {
        // A write *followed by* `RETURN` has a projection root, not a write root, so it returns rows.
        let mut g = MemGraph::new();
        let rows = run("CREATE (a:Person {name: 'Ada'}) RETURN a", &mut g);
        assert_eq!(rows.len(), 1, "a returning write yields exactly one row");
        assert_eq!(rows[0].len(), 1, "with a single column");
        assert!(rows[0].get("a").and_then(RowValue::as_node).is_some());
        assert_eq!(
            columns_of("CREATE (a:Person {name: 'Ada'}) RETURN a"),
            vec!["a".to_owned()],
            "the projection above the write declares the result column",
        );
    }

    #[test]
    fn spatial_index_seek_returns_exactly_the_scan_result() {
        // `rmp` task #73: the spatial index must NEVER change results — only speed. Seed Cartesian
        // points whose Euclidean distances from the origin are exact (0, 3, 4, 5), then assert the
        // proximity query returns the IDENTICAL node set whether or not a spatial index is present.
        use crate::catalog::IndexCatalog;
        use graphus_core::value::spatial::{Crs, Point};

        let point = |x: f64, y: f64| Value::Point(Point::new_2d(Crs::Cartesian, x, y));

        // The sorted node-id set a proximity query returns over `graph` with `catalog`.
        fn ids(src: &str, graph: &mut MemGraph, catalog: &IndexCatalog) -> Vec<u64> {
            let mut out: Vec<u64> = run_with_catalog(src, graph, catalog)
                .iter()
                .filter_map(|r| r.get("n").and_then(RowValue::as_node))
                .map(|id| id.0)
                .collect();
            out.sort_unstable();
            out
        }

        // Two identically-seeded graphs: one indexed, one not. (A graph carries its own declared
        // spatial index; the catalog is what routes the planner to the seek — both must agree.)
        let seed = |g: &mut MemGraph| {
            g.add_node(["City"], [("loc", point(0.0, 0.0))]); // d = 0
            g.add_node(["City"], [("loc", point(3.0, 0.0))]); // d = 3
            g.add_node(["City"], [("loc", point(0.0, 4.0))]); // d = 4 (boundary)
            g.add_node(["City"], [("loc", point(3.0, 4.0))]); // d = 5 (inside the bbox, outside r=4)
        };
        let mut indexed = MemGraph::new();
        seed(&mut indexed);
        indexed.create_spatial_index("City", "loc");
        let mut plain = MemGraph::new();
        seed(&mut plain);

        let with_index = IndexCatalog::builder()
            .with_label_spatial("City", "loc")
            .build();
        let no_index = IndexCatalog::empty();

        // `< 4`: nodes at d = 0 and d = 3 only (the hit set). The d = 4 node is excluded (strict), and
        // the d = 5 node — a grid bbox false positive — is excluded by the residual `distance` filter.
        let q_lt = "MATCH (n:City) WHERE distance(n.loc, point({x:0, y:0})) < 4 RETURN n";
        let seek_lt = ids(q_lt, &mut indexed, &with_index);
        let scan_lt = ids(q_lt, &mut plain, &no_index);
        assert_eq!(seek_lt, scan_lt, "index must not change results (< r)");
        assert_eq!(seek_lt.len(), 2, "only d=0 and d=3 are within r=4 (strict)");

        // `<= 4.0`: the boundary node at d = 4 is now included (a float radius so `distance` — always
        // a `Value::Float` — compares numerically against it). The d = 5 bbox false positive stays out.
        let q_le = "MATCH (n:City) WHERE distance(n.loc, point({x:0, y:0})) <= 4.0 RETURN n";
        let seek_le = ids(q_le, &mut indexed, &with_index);
        let scan_le = ids(q_le, &mut plain, &no_index);
        assert_eq!(seek_le, scan_le, "index must not change results (<= r)");
        assert_eq!(
            seek_le.len(),
            3,
            "d=0, d=3 and the boundary d=4 are within r=4 inclusive"
        );

        // The grid bbox false positive (d = 5, node id 3) is never returned by either path.
        assert!(
            !seek_le.contains(&3),
            "the d=5 node (same bbox, outside the radius) must be excluded by the residual re-check"
        );

        // Sanity: the indexed plan really does use the seek (else the test proves nothing about it).
        let plan = {
            let toks = tokenize(q_lt).expect("lex");
            let ast = parse_tokens(&toks, q_lt).expect("parse");
            plan_physical(&lower(&analyze(&ast).expect("analyze")), &with_index)
        };
        assert!(
            plan.to_string().contains("SpatialIndexSeek"),
            "the indexed plan must route through the spatial seek:\n{plan}"
        );
    }

    // ---- rmp #131: percentileDisc / percentileCont aggregations -------------------------------

    /// Runs `src`, returning the runtime error (panics if the query succeeds). Sibling of [`run`].
    fn run_err(src: &str, graph: &mut MemGraph) -> ExecError {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let plan = plan_physical(
            &lower(&analyze(&ast).expect("analyze")),
            &IndexCatalog::empty(),
        );
        let params = crate::binding::bind_parameters(&plan, &crate::binding::Parameters::new())
            .expect("bind");
        // The error may surface either while opening the cursor (aggregation is eager) or while
        // draining it; capture it from whichever stage produces it.
        match execute(&plan, &params, graph) {
            Err(e) => e,
            Ok(mut cursor) => cursor
                .collect_all()
                .expect_err("query was expected to fail at runtime"),
        }
    }

    /// Builds a graph of one node per element of `prices` (property `price`), so an aggregation over
    /// `MATCH (n) RETURN agg(n.price, ...)` sees exactly those values.
    fn prices_graph(prices: &[f64]) -> MemGraph {
        let mut g = MemGraph::new();
        for &p in prices {
            let _ = g.add_node(["P"], [("price", Value::Float(p))]);
        }
        g
    }

    fn percentile(agg: &str, prices: &[f64], p: f64) -> Value {
        let mut g = prices_graph(prices);
        let src = format!("MATCH (n) RETURN {agg}(n.price, {p}) AS r");
        let rows = run(&src, &mut g);
        assert_eq!(
            rows.len(),
            1,
            "an aggregation over a non-empty match is one row"
        );
        rows[0].value("r")
    }

    #[test]
    fn percentile_disc_nearest_rank_over_known_set() {
        // Sorted set [1,2,3,4]; nearest-rank `idx`:
        //   p=0   -> floatIdx=0,  idx=0 -> 1
        //   p=0.5 -> floatIdx=2,  idx=1 (exact, non-zero -> idx-1) -> 2
        //   p=1.0 -> last -> 4
        let xs = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(percentile("percentileDisc", &xs, 0.0), Value::Float(1.0));
        assert_eq!(percentile("percentileDisc", &xs, 0.5), Value::Float(2.0));
        assert_eq!(percentile("percentileDisc", &xs, 1.0), Value::Float(4.0));
    }

    #[test]
    fn percentile_cont_linear_interpolation_over_known_set() {
        // Sorted set [1,2,3,4]; floatIdx = p*(n-1) = p*3:
        //   p=0   -> idx 0 -> 1.0
        //   p=0.5 -> floatIdx=1.5, floor=1,ceil=2 -> 2*(0.5)+3*(0.5) = 2.5
        //   p=1.0 -> last -> 4.0
        let xs = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(percentile("percentileCont", &xs, 0.0), Value::Float(1.0));
        assert_eq!(percentile("percentileCont", &xs, 0.5), Value::Float(2.5));
        assert_eq!(percentile("percentileCont", &xs, 1.0), Value::Float(4.0));
    }

    #[test]
    fn percentile_three_value_set_matches_tck_examples() {
        // TCK Aggregation6 [1]/[2]: prices 10/20/30, p=0/0.5/1 -> 10/20/30 for both functions.
        let xs = [10.0, 20.0, 30.0];
        for agg in ["percentileDisc", "percentileCont"] {
            assert_eq!(percentile(agg, &xs, 0.0), Value::Float(10.0));
            assert_eq!(percentile(agg, &xs, 0.5), Value::Float(20.0));
            assert_eq!(percentile(agg, &xs, 1.0), Value::Float(30.0));
        }
    }

    #[test]
    fn percentile_disc_preserves_integer_subtype() {
        // `percentileDisc` returns a real member of the set, so an integer property stays an integer.
        let mut g = MemGraph::new();
        for v in [1_i64, 2, 3, 4] {
            let _ = g.add_node(["P"], [("price", Value::Integer(v))]);
        }
        let rows = run("MATCH (n) RETURN percentileDisc(n.price, 0.5) AS r", &mut g);
        assert_eq!(rows[0].value("r"), Value::Integer(2));
    }

    #[test]
    fn percentile_ignores_null_values() {
        // A null `value` contributes nothing (like every other aggregate), so [null,1,2,3,4] behaves
        // exactly like [1,2,3,4].
        let mut g = MemGraph::new();
        let _ = g.add_node(["P"], NO_PROPS); // no `price` -> n.price is null
        for v in [1.0, 2.0, 3.0, 4.0] {
            let _ = g.add_node(["P"], [("price", Value::Float(v))]);
        }
        let rows = run("MATCH (n) RETURN percentileCont(n.price, 0.5) AS r", &mut g);
        assert_eq!(rows[0].value("r"), Value::Float(2.5));
    }

    #[test]
    fn percentile_over_empty_set_is_null() {
        let mut g = MemGraph::new();
        let rows = run(
            "MATCH (n:Missing) RETURN percentileDisc(n.price, 0.5) AS r",
            &mut g,
        );
        assert_eq!(rows.len(), 1, "the empty group still emits one row");
        assert_eq!(rows[0].value("r"), Value::Null);
        let rows = run(
            "MATCH (n:Missing) RETURN percentileCont(n.price, 0.5) AS r",
            &mut g,
        );
        assert_eq!(rows[0].value("r"), Value::Null);
    }

    #[test]
    fn percentile_out_of_range_is_number_out_of_range() {
        // The percentile must lie in [0,1]; outside it raises NumberOutOfRange (TCK ArgumentError).
        for p in ["1.5", "-0.1", "1000", "-1"] {
            for agg in ["percentileDisc", "percentileCont"] {
                let mut g = prices_graph(&[10.0]);
                let src = format!("MATCH (n) RETURN {agg}(n.price, {p}) AS r");
                match run_err(&src, &mut g) {
                    ExecError::Eval(EvalError::NumberOutOfRange { .. }) => {}
                    other => panic!("expected NumberOutOfRange for {agg}(.., {p}), got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn percentile_non_numeric_argument_is_type_error() {
        // A non-numeric percentile is a runtime type error, not NumberOutOfRange.
        let mut g = prices_graph(&[10.0]);
        match run_err("MATCH (n) RETURN percentileCont(n.price, 'x') AS r", &mut g) {
            ExecError::Eval(EvalError::TypeError { .. }) => {}
            other => panic!("expected TypeError for a string percentile, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Full-query EXISTS subquery (rmp #123)
    // ---------------------------------------------------------------------------------------------

    /// The TCK `ExistentialSubquery2`/`3` graph: `(:A{prop:1})` with three outgoing `:R` to
    /// `(:B{prop:1})`, `(:C{prop:2})`, `(:D{prop:3})`. Only `A` has any outgoing relationship.
    fn exists_tck_graph() -> MemGraph {
        let mut g = MemGraph::new();
        let a = g.add_node(["A"], [("prop", Value::Integer(1))]);
        let b = g.add_node(["B"], [("prop", Value::Integer(1))]);
        let c = g.add_node(["C"], [("prop", Value::Integer(2))]);
        let d = g.add_node(["D"], [("prop", Value::Integer(3))]);
        let _ = g.add_rel("R", a, b, NO_PROPS);
        let _ = g.add_rel("R", a, c, NO_PROPS);
        let _ = g.add_rel("R", a, d, NO_PROPS);
        g
    }

    /// The `prop` values of the returned `n` nodes (sorted), via a wrapping projection so we read a
    /// scalar rather than inspecting node identity.
    fn qualifying_props(src: &str, g: &mut MemGraph) -> Vec<i64> {
        // Wrap the query so it returns n.prop. The supplied `src` ends in `RETURN n`.
        let wrapped = src.replace("RETURN n", "RETURN n.prop AS p");
        let mut props: Vec<i64> = run(&wrapped, g)
            .iter()
            .filter_map(|r| match r.value("p") {
                Value::Integer(k) => Some(k),
                _ => None,
            })
            .collect();
        props.sort_unstable();
        props
    }

    #[test]
    fn exists_full_query_simple() {
        // TCK ExistentialSubquery2 [1]: only the node with an outgoing relationship (A, prop 1).
        let mut g = exists_tck_graph();
        let props = qualifying_props(
            "MATCH (n) WHERE exists { MATCH (n)-->() RETURN true } RETURN n",
            &mut g,
        );
        assert_eq!(
            props,
            vec![1],
            "only A (prop 1) has an outgoing relationship"
        );
    }

    #[test]
    fn exists_full_query_aggregation() {
        // TCK ExistentialSubquery2 [2]: A has exactly 3 outgoing rels; with the extra (b)-[:R]->(d)
        // edge, B has 1. Only A satisfies `count(*) = 3`.
        let mut g = MemGraph::new();
        let a = g.add_node(["A"], [("prop", Value::Integer(1))]);
        let b = g.add_node(["B"], [("prop", Value::Integer(1))]);
        let c = g.add_node(["C"], [("prop", Value::Integer(2))]);
        let d = g.add_node(["D"], [("prop", Value::Integer(3))]);
        let _ = g.add_rel("R", a, b, NO_PROPS);
        let _ = g.add_rel("R", a, c, NO_PROPS);
        let _ = g.add_rel("R", a, d, NO_PROPS);
        let _ = g.add_rel("R", b, d, NO_PROPS);
        let props = qualifying_props(
            "MATCH (n) WHERE exists { MATCH (n)-->(m) WITH n, count(*) AS numConnections WHERE numConnections = 3 RETURN true } RETURN n",
            &mut g,
        );
        assert_eq!(
            props,
            vec![1],
            "only A has exactly 3 outgoing relationships"
        );
    }

    #[test]
    fn exists_correlated_outer_var_constrains() {
        // The crux: the subquery is correlated by the outer `n`. A node with no outgoing rel must be
        // EXCLUDED, one with an outgoing rel INCLUDED. (If correlation were broken — the inner MATCH
        // re-scanning every node — every outer node would pass and all four props would appear.)
        let mut g = exists_tck_graph();
        let props = qualifying_props(
            "MATCH (n) WHERE exists { MATCH (n)-->() RETURN true } RETURN n",
            &mut g,
        );
        assert_eq!(
            props,
            vec![1],
            "correlation must restrict to A; a broken seed would yield [1, 1, 2, 3]"
        );
    }

    #[test]
    fn exists_nested_simple() {
        // TCK ExistentialSubquery3 [1]: nested EXISTS with a pattern predicate `n.prop = m.prop`.
        // A(prop 1) -> B(prop 1): the prop match holds only for A.
        let mut g = exists_tck_graph();
        let props = qualifying_props(
            "MATCH (n) WHERE exists { MATCH (m) WHERE exists { (n)-[]->(m) WHERE n.prop = m.prop } RETURN true } RETURN n",
            &mut g,
        );
        assert_eq!(
            props,
            vec![1],
            "only A matches a prop-equal outgoing neighbour"
        );
    }

    #[test]
    fn exists_nested_full_query() {
        // TCK ExistentialSubquery3 [2]: nested full-query EXISTS with `(l)<-[:R]-(n)-[:R]->(m)` —
        // n needs at least two outgoing :R relationships. A has three; nobody else has any.
        let mut g = exists_tck_graph();
        let props = qualifying_props(
            "MATCH (n) WHERE exists { MATCH (m) WHERE exists { MATCH (l)<-[:R]-(n)-[:R]->(m) RETURN true } RETURN true } RETURN n",
            &mut g,
        );
        assert_eq!(props, vec![1], "only A has two+ outgoing :R relationships");
    }

    #[test]
    fn exists_nested_full_query_with_pattern_predicate() {
        // TCK ExistentialSubquery3 [3]: the innermost predicate is a pattern predicate inside WHERE.
        let mut g = exists_tck_graph();
        let props = qualifying_props(
            "MATCH (n) WHERE exists { MATCH (m) WHERE exists { MATCH (l) WHERE (l)<-[:R]-(n)-[:R]->(m) RETURN true } RETURN true } RETURN n",
            &mut g,
        );
        assert_eq!(
            props,
            vec![1],
            "only A satisfies the nested pattern predicate"
        );
    }

    #[test]
    fn exists_pattern_only_unbroken() {
        // The pre-existing pattern-only form must still work unchanged.
        let mut g = exists_tck_graph();
        let props = qualifying_props("MATCH (n) WHERE exists { (n)-->() } RETURN n", &mut g);
        assert_eq!(props, vec![1], "pattern-only EXISTS still selects A");
    }

    #[test]
    fn exists_pattern_predicate_unbroken() {
        // The pre-existing bare pattern-predicate form must still work unchanged.
        let mut g = exists_tck_graph();
        let props = qualifying_props("MATCH (n) WHERE (n)-->() RETURN n", &mut g);
        assert_eq!(props, vec![1], "bare pattern predicate still selects A");
    }
}
