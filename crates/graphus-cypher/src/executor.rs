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
use std::time::Instant;

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
    NodeRef, PathStep, PathValue, RelRef, Row, RowValue, cmp_row_values, hash_row_value,
    row_values_equivalent,
};
use crate::statement_clock::StatementClock;
use crate::ternary::Ternary;

/// A cooperative **cancellation token** shared between a caller and a running query (`04 §7.7`).
///
/// The caller holds a clone and trips it (e.g. on client disconnect / `RESET`); operators poll
/// [`is_cancelled`](Self::is_cancelled) at safe points (between rows). Cloning shares the same
/// underlying flag (an [`Arc<AtomicBool>`]), so a trip on any clone is observed by all. It is
/// `Send + Sync`, ready for the connectivity layer's `tokio::select!` timeout/abort branches.
///
/// A token may additionally carry a **wall-clock deadline** ([`with_deadline`](Self::with_deadline),
/// `rmp` #476): a per-statement CPU budget the executor's existing safe points enforce cooperatively,
/// so a runaway query (a cartesian / variable-length-expansion bomb) aborts with
/// [`ExecError::Cancelled`] even with no external canceller — bounding per-database-thread CPU
/// exhaustion. The deadline is a plain `Copy` [`Instant`] fixed at construction (not shared through the
/// `Arc`): every clone observes the same instant, so no atomic is needed. A `None` deadline (the
/// default — and what every test / TCK / deterministic-engine path uses) preserves the prior flag-only
/// behaviour exactly.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
    deadline: Option<Instant>,
}

impl CancellationToken {
    /// A fresh, untripped token with no deadline.
    pub fn new() -> Self {
        Self::default()
    }

    /// A token that trips automatically once the monotonic clock reaches `deadline`, in addition to an
    /// explicit [`cancel`](Self::cancel) (`rmp` #476). `None` yields a never-expiring token, identical
    /// to [`new`](Self::new) — used by the deterministic engine and the test/TCK paths so they never
    /// observe wall-clock-dependent behaviour.
    pub fn with_deadline(deadline: Option<Instant>) -> Self {
        Self {
            flag: Arc::default(),
            deadline,
        }
    }

    /// The wall-clock deadline this token enforces, if any (`rmp` #476). The morsel tier reads it to
    /// install the same cooperative budget on its off-thread workers.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Trips the explicit cancel flag: every clone now observes [`is_cancelled`](Self::is_cancelled) as
    /// `true`.
    ///
    /// `Release` ordering pairs with the `Acquire` load in [`is_flagged`](Self::is_flagged) so a
    /// cancelling thread's prior writes are visible to the observing executor thread.
    pub fn cancel(&self) {
        self.flag.store(true, AtomicOrdering::Release);
    }

    /// Whether the explicit cancel flag has been tripped (client disconnect / `RESET` / external
    /// abort). A single cheap atomic load — it does **not** consult the wall-clock deadline, so the
    /// hot per-row safe point can check it on every call without reading the clock.
    #[must_use]
    pub fn is_flagged(&self) -> bool {
        self.flag.load(AtomicOrdering::Acquire)
    }

    /// Whether the wall-clock deadline (if any) has elapsed (`rmp` #476). Reads `Instant::now()`, so
    /// callers on a hot path should gate how often they poll it (the executor's
    /// [`Ctx::check_cancelled`] polls it at a strided cadence; the morsel workers poll it per chunk).
    #[must_use]
    pub fn deadline_exceeded(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }

    /// Whether the token is cancelled by **either** the explicit flag or an elapsed deadline.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.is_flagged() || self.deadline_exceeded()
    }
}

/// How many [`Ctx::check_cancelled`] safe points pass between two wall-clock deadline polls (`rmp`
/// #476). The explicit cancel flag is an atomic load checked on **every** safe point; the deadline,
/// which needs an `Instant::now()`, is consulted only once per this many calls so a legitimate large
/// result keeps its prior atomic-only hot-path cost (production always configures a finite default, so
/// an un-gated per-row `Instant::now()` would tax every big read). A runaway query still aborts within
/// this many safe points of the deadline — microseconds for a tight loop — so cancellation stays
/// prompt. A power of two so the gate is a mask, not a division.
const DEADLINE_POLL_STRIDE: u32 = 1024;

thread_local! {
    /// A per-thread, monotonic counter that strides the wall-clock deadline poll in
    /// [`Ctx::check_cancelled`] (`rmp` #476). It is a **benign performance gate**, not semantic state:
    /// it only decides *when* to read `Instant::now()`, never *whether* the query is cancelled, so its
    /// value carrying across statements (the engine thread is long-lived) is harmless — it merely
    /// phases the gate. Lives at thread scope (not on [`Ctx`]) so it persists across `Cursor::next`
    /// calls: a streaming cartesian bomb emits one row per `next()` with only a few safe points each,
    /// and the deadline must still be polled across that stream.
    static DEADLINE_POLL_COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
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
    /// The fixed per-statement "current instant" (`rmp` task #140): captured once when the cursor
    /// opened and threaded into [`crate::eval`] so that every zero-argument temporal constructor
    /// (`date()`, `datetime()`, …) in one statement observes the same instant.
    clock: StatementClock,
    /// The effective morsel-thread count for this statement (`rmp` task #339): populated from the
    /// process-global [`crate::morsel::morsel_threads`] at cursor-open. `<= 1` means the morsel tier
    /// early-returns (fully serial — the RPi / determinism / library / `MemGraph` default); `>= 2`
    /// enables morsel-driven intra-query parallelism for the bare-aggregate shape.
    morsel_threads: usize,
}

impl Ctx<'_> {
    /// Polls the cancellation token at a safe point; `Err(Cancelled)` unwinds the pipeline.
    ///
    /// The explicit cancel flag (client disconnect / `RESET` / external abort) is a cheap atomic load
    /// checked on every call. The per-statement wall-clock deadline (`rmp` #476) needs an
    /// `Instant::now()`, so it is polled at a strided cadence ([`DEADLINE_POLL_STRIDE`]) — bounding a
    /// runaway query within that many safe points of its deadline while keeping a legitimate large
    /// result on the prior atomic-only hot path. When the token has no deadline (every test / TCK /
    /// deterministic-engine path) the clock is never read, so behaviour is byte-identical to before.
    fn check_cancelled(&self) -> Result<(), ExecError> {
        if self.token.is_flagged() {
            return Err(ExecError::Cancelled);
        }
        if self.token.deadline().is_some() {
            let fire = DEADLINE_POLL_COUNTER.with(|c| {
                let n = c.get().wrapping_add(1);
                c.set(n);
                n & (DEADLINE_POLL_STRIDE - 1) == 0
            });
            if fire && self.token.deadline_exceeded() {
                return Err(ExecError::Cancelled);
            }
        }
        Ok(())
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
        /// `rmp` #371: the relationship-type names of `types`, resolved to owned `String`s **once** at
        /// operator construction instead of once per driving (base) row. `GraphAccess::expand` takes
        /// `&[String]`, and every base row of this operator expands over the same `types`, so this is
        /// hoisted out of the per-row hot loop.
        type_names: Vec<String>,
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

    /// `FOREACH ( var IN list | …+ )`: a per-row side-effect. For each input row, `list` is evaluated
    /// once; for each element the loop `variable` is bound on a correlation row and the inner update
    /// sub-plan (`body_template`, rebuilt per element via [`build_operator_with_arg`]) is driven to
    /// completion for its side effects. The input row is passed through **unchanged** (the loop
    /// variable is local and never escapes), so cardinality is preserved.
    Foreach {
        input: Box<Operator>,
        variable: Var,
        list: Expr,
        /// The correlated body sub-plan, rebuilt per `(row, element)` over its Argument leaf.
        body_template: Box<PhysicalOp>,
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
                let listv = eval(
                    list,
                    &base,
                    ctx.params,
                    ctx.graph,
                    ctx.functions,
                    &ctx.clock,
                )?;
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
                let url_value =
                    eval_value(url, &base, ctx.params, ctx.graph, ctx.functions, &ctx.clock)?;
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
                type_names,
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
                        type_names,
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
                        type_names,
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

            Operator::Foreach {
                input,
                variable,
                list,
                body_template,
            } => {
                // FOREACH is a per-row side-effect; it passes each input row through UNCHANGED.
                let Some(row) = input.next(ctx)? else {
                    return Ok(None);
                };
                // Evaluate the list **structurally** (`eval`, not `eval_value`) so a list of
                // nodes / relationships / paths is preserved — the same rationale as UNWIND.
                let listv = eval(list, &row, ctx.params, ctx.graph, ctx.functions, &ctx.clock)?;
                let elems = match listv.as_list_elems() {
                    Some(items) => items,
                    // FOREACH over null is a no-op for that row (zero iterations).
                    None if matches!(listv, RowValue::Value(Value::Null)) => Vec::new(),
                    // A non-list, non-null value is a runtime TypeError: unlike UNWIND, FOREACH does
                    // NOT treat a scalar as a one-element list — openCypher requires a list here.
                    None => {
                        return Err(ExecError::Eval(EvalError::TypeError {
                            context: "FOREACH expects a list".to_owned(),
                        }));
                    }
                };
                for elem in elems {
                    ctx.check_cancelled()?;
                    // Bind the loop variable for this element onto a correlation row and run the inner
                    // update sub-plan to completion, draining every row for its side effects. The
                    // loop variable lives only on this correlation row, so it never escapes into the
                    // emitted `row`.
                    let arg_row = row.with(variable.name.clone(), elem);
                    let mut sub = build_operator_with_arg(body_template, &arg_row, ctx)?;
                    while sub.next(ctx)?.is_some() {}
                }
                Ok(Some(row))
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
                    arg_values.push(eval_value(
                        a,
                        &base,
                        ctx.params,
                        ctx.graph,
                        ctx.functions,
                        &ctx.clock,
                    )?);
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
    match eval_value(
        expr,
        &Row::empty(),
        ctx.params,
        ctx.graph,
        ctx.functions,
        &ctx.clock,
    )? {
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
    match eval(expr, row, ctx.params, ctx.graph, ctx.functions, &ctx.clock)? {
        RowValue::Value(Value::Boolean(b)) => Ok(Ternary::from_bool(b)),
        RowValue::Value(Value::Null) => Ok(Ternary::Null),
        _ => Err(ExecError::Eval(EvalError::TypeError {
            context: "WHERE/predicate must be a boolean".to_owned(),
        })),
    }
}

thread_local! {
    /// Memoises the output [`RowSchema`] of a projection by its **ordered alias list** (`rmp` task
    /// #364). A projection's output column names are identical for every row it emits, so the schema
    /// is built once and shared (an `Arc` bump) across all produced rows instead of re-allocating the
    /// alias `String`s per row. Keyed by the alias vector (not by slice pointer, which a planner is
    /// free to reuse for a different projection) so the memo is always correct.
    static PROJECTION_SCHEMA_CACHE: std::cell::RefCell<
        std::collections::HashMap<Vec<String>, std::sync::Arc<crate::runtime::RowSchema>>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// The shared output schema for a projection's `items`, built once per distinct alias list and reused
/// for every row the projection emits (`rmp` task #364 — kills the per-row alias `String` alloc).
fn projection_schema(items: &[ProjectionColumn]) -> std::sync::Arc<crate::runtime::RowSchema> {
    PROJECTION_SCHEMA_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        // The alias list is the identity of the output shape. A `Vec<String>` clone here happens once
        // per distinct projection shape (a handful of times per query), never per row.
        let key: Vec<String> = items.iter().map(|c| c.alias.clone()).collect();
        if let Some(schema) = cache.get(&key) {
            return std::sync::Arc::clone(schema);
        }
        let schema =
            std::sync::Arc::new(crate::runtime::RowSchema::from_names(key.iter().cloned()));
        cache.insert(key, std::sync::Arc::clone(&schema));
        schema
    })
}

/// Projects a row to the output columns, evaluating each item against the input row.
///
/// The output **schema** (the alias list) is identical for every emitted row, so when the aliases are
/// distinct it is built once and shared via [`projection_schema`]; only the evaluated `values` are
/// produced per row, with **no** per-row column-name allocation (`rmp` task #364). On the rare case
/// of a duplicate alias the previous `set`-based collapse semantics (last write wins, original
/// position kept) are preserved exactly.
fn project_row(row: &Row, items: &[ProjectionColumn], ctx: &mut Ctx<'_>) -> Result<Row, ExecError> {
    let schema = projection_schema(items);
    if schema.len() == items.len() {
        // Distinct aliases (the steady state): one value per item, shared schema, zero name alloc.
        let mut values = Vec::with_capacity(items.len());
        for col in items {
            let v = eval(
                &col.expr,
                row,
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?;
            values.push(v);
        }
        return Ok(crate::runtime::Row::from_schema_values(schema, values));
    }
    // Duplicate alias present: fall back to the collapse-on-rebind path for byte-identical output.
    let mut out = Row::empty();
    for col in items {
        let v = eval(
            &col.expr,
            row,
            ctx.params,
            ctx.graph,
            ctx.functions,
            &ctx.clock,
        )?;
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
/// `rmp` #371: the set is used only for membership (`.contains`) — never iterated for output — so an
/// unordered `FxHashSet` is byte-identical to the former `BTreeSet` and avoids the per-insert tree
/// balancing.
fn used_relationships(base: &Row, prior_rels: &[Var]) -> rustc_hash::FxHashSet<RelId> {
    fn collect(v: &RowValue, out: &mut rustc_hash::FxHashSet<RelId>) {
        match v {
            RowValue::Rel(r) => {
                out.insert(r.id);
            }
            RowValue::List(items) => items.iter().for_each(|item| collect(item, out)),
            _ => {}
        }
    }
    let mut out = rustc_hash::FxHashSet::default();
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
    type_names: &[String],
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
    // may re-use (relationship isomorphism, `04 §2.4`). `rmp` #371: when there are no prior pattern
    // relationships there is nothing to forbid (`used_relationships` would return ∅, so
    // `used.contains(..)` is always false) — skip building/consulting it entirely. The per-anchor
    // `seen_rel` self-loop dedup below stays active regardless.
    let used = if prior_rels.is_empty() {
        None
    } else {
        Some(used_relationships(base, prior_rels))
    };
    let dir = ExpandDirection::from_pattern(direction);
    let incidents = ctx.graph.expand(anchor, dir, type_names);
    // `rmp` #364: derive the produced-row shape ONCE before the loop instead of once per produced
    // edge. Build a template row by applying the same `set`s to the base; every produced row then
    // shares that template's schema (an `Arc` bump) and overwrites only the two bound columns by
    // index — no per-edge schema allocation and no per-edge column-name clone.
    let mut template = base.clone();
    template.set(
        relationship.name.clone(),
        RowValue::Rel(RelRef { id: RelId(0) }),
    );
    if !into {
        template.set(to.name.clone(), RowValue::Node(NodeRef { id: anchor }));
    }
    let rel_idx = template
        .schema()
        .index_of_pub(&relationship.name)
        .expect("INVARIANT: relationship column was just set on the template");
    let to_idx = if into {
        None
    } else {
        Some(
            template
                .schema()
                .index_of_pub(&to.name)
                .expect("INVARIANT: to column was just set on the template"),
        )
    };
    // Deduplicate self-loops reported once per side (`04 §2.4`): a relationship id appears at most
    // once per produced row set for this anchor.
    let mut seen_rel = rustc_hash::FxHashSet::default();
    for inc in incidents {
        if !seen_rel.insert(inc.rel) {
            continue;
        }
        if used.as_ref().is_some_and(|u| u.contains(&inc.rel)) {
            continue;
        }
        if into && Some(inc.neighbour) != target {
            continue;
        }
        let mut row = template.clone();
        row.set_at(rel_idx, RowValue::Rel(RelRef { id: inc.rel }));
        if let Some(to_idx) = to_idx {
            row.set_at(to_idx, RowValue::Node(NodeRef { id: inc.neighbour }));
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
    type_names: &[String],
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
    // `rmp` #371: an empty `FxHashSet` (the no-prior-rels case) allocates nothing until first insert,
    // so this is already near-free; the dfs threads `&forbidden` at every depth.
    let forbidden = used_relationships(base, prior_rels);
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
        forbidden: &rustc_hash::FxHashSet<RelId>,
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
        let mut seen_rel = rustc_hash::FxHashSet::default();
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
        type_names,
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
        let result = eval(
            &predicate,
            &probe,
            ctx.params,
            ctx.graph,
            ctx.functions,
            &ctx.clock,
        )?;
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
            let seek = eval_value(
                value,
                &Row::empty(),
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?;
            let ids = match ctx.graph.index_seek_eq(&label.name, property, &seek) {
                Some(ids) => ids,
                // No index in the seam: fall back to a label scan + equality residual.
                None => scan_filter_eq(label, property, &seek, ctx),
            };
            Ok(Operator::Buffered {
                rows: nodes_to_rows(variable, ids),
            })
        }
        PhysicalOp::NodeLabelScanEq {
            variable,
            label,
            property,
            value,
        } => {
            // The precise equality-filtered label scan (`rmp` task #325): evaluate the seek value, then
            // route to the `scan_filter_eq` seam, which reads every node but builds an SSI dependency on
            // only the matching rows (+ the precise `Equality` predicate marker) — the scan-path twin of
            // `NodeIndexSeek`'s footprint, without the bare label scan's blanket "mark every node".
            let seek = eval_value(
                value,
                &Row::empty(),
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?;
            Ok(Operator::Buffered {
                rows: nodes_to_rows(variable, scan_filter_eq(label, property, &seek, ctx)),
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
            let bound_val = eval_value(
                value,
                &Row::empty(),
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?;
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
            type_names: types.iter().map(|t| t.name.clone()).collect(),
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
            type_names: types.iter().map(|t| t.name.clone()).collect(),
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
            // Morsel-driven parallel scan→filter→project (`rmp` #339, Slice 3b): for a *large* bare
            // `MATCH (n:Label) [WHERE <pure>] RETURN <per-row projection>` with the morsel knob enabled,
            // read the candidates across contiguous morsels concurrently (each filtering + projecting on a
            // `Send` `ReadOnlyGraph`), converging via a CONTIGUOUS CONCAT in ascending candidate order —
            // row-order-identical to (and deterministic regardless of worker count, unlike) the serial
            // pipeline. Declines (falls through) for any non-conforming / impure / below-threshold shape,
            // knob<=1, RBAC restriction, standalone / historical read, or a morsel error. NB: a
            // `Projection` directly under a `Sort` / `TopN` is handled by *those* sites (with the stable
            // ORDER BY merge) before this builds the inner; if a Sort's tier declined, this concat path is
            // still correct (the serial Sort above re-sorts the concat).
            if !*distinct {
                // Morsel-driven parallel scan→expand→project (`rmp` #339, Slice 3c): for a *large* bare
                // `MATCH (a:Label)-[r]->(b) RETURN <pure projection of a/r/b>`, partition the ANCHORS into
                // contiguous morsels, expand + project each anchor's single hop concurrently (each over a
                // `Send` `ReadOnlyGraph`), converging via a CONTIGUOUS CONCAT in ascending anchor order —
                // row-order-identical to (and worker-count-deterministic, unlike) serial. Tried before the
                // scan→filter→project tier: an `ExpandAll` input is the 3c case, a bare label-scan input is
                // the 3b case. Declines (falls through) for any non-conforming shape.
                if let Some(rows) = try_morsel_expand_project(op, ctx)? {
                    return Ok(Operator::Buffered { rows });
                }
                if let Some(rows) = try_morsel_scan_filter_project(op, &[], None, ctx)? {
                    return Ok(Operator::Buffered { rows });
                }
            }
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
            // Morsel-driven parallel READ path (`rmp` #339, Slice 3a — the first slice that makes a
            // single heavy analytical query use >1 core): for a *large* bare
            // `MATCH (n:Label) RETURN <exact-agg>(n.p)` over an integer column, with the morsel knob
            // enabled, split the candidate-id vector into contiguous morsels and read each
            // **concurrently** on a dedicated worker pool (parallelizing the per-candidate
            // MVCC-revalidating read itself — the measured bottleneck the `rmp` #352 fold-parallel tier
            // could not touch), then fold the survivors' values + converge the per-morsel SSI buffers.
            // Bit-identical to serial (exact/associative aggregates only). Declines (falls through) for
            // any non-conforming shape, float/avg, below-threshold, knob<=1, RBAC restriction, standalone
            // / historical read, or a morsel read error — in which case the tiers below run verbatim.
            // Morsel-driven parallel DEGREE / count-over-expand path (`rmp` #339, Slice 3c — the final
            // slice, parallelizing the traversal): for a *large* bare
            // `MATCH (a:Label)-[r]->(b) RETURN count(b) | count(*)`, partition the ANCHORS into contiguous
            // morsels, expand each anchor's single hop concurrently (each over a `Send` `ReadOnlyGraph`),
            // and SUM the per-anchor matching degrees (an order-independent combine). Bit-identical to
            // serial. Declines (falls through) for any non-conforming shape, below-threshold, knob<=1, RBAC
            // restriction, standalone / historical read, or a morsel error.
            if let Some(rows) = try_morsel_expand_aggregate(input, group_keys, aggregates, ctx)? {
                return Ok(Operator::Buffered { rows });
            }
            // Morsel-driven parallel GROUPED aggregation (`rmp` #360 — the actual LDBC-BI bottleneck): for
            // a *large* bare `MATCH (n:Label) RETURN <bare group keys>, <bare mergeable aggregates>`, split
            // the candidate-id vector into contiguous morsels, build a LOCAL group table per morsel
            // **concurrently** on the dedicated pool, then merge the partials deterministically (serial
            // first-seen order) on the engine thread. Byte-identical to serial (mergeable aggregates only:
            // count/sum-no-overflow-int/min/max/collect; avg/percentile/composite/filtered shapes decline).
            // This is the non-empty-GROUP-BY counterpart of the keyless Slice-3a tier below.
            if let Some(rows) = try_morsel_group_aggregate(input, group_keys, aggregates, ctx)? {
                return Ok(Operator::Buffered { rows });
            }
            if let Some(rows) = try_morsel_label_aggregate(input, group_keys, aggregates, ctx)? {
                return Ok(Operator::Buffered { rows });
            }
            // Parallel FOLD fast path (`rmp` #352, phase 1 of #336): the prior tier, kept as the base for
            // when the morsel knob is off (the global `rayon` pool's fold over a serially-projected
            // column). Bit-identical to serial; declines for any non-conforming shape, float/avg,
            // below-threshold, single-thread, RBAC restriction, or historical read.
            if let Some(rows) =
                try_parallel_label_property_aggregate(input, group_keys, aggregates, ctx)?
            {
                return Ok(Operator::Buffered { rows });
            }
            // Vectorized fast path (`rmp` #330): an analytical `MATCH (n:Label) RETURN agg(n.p)` over
            // a columnar-cached column folds the contiguous column in batches instead of pulling rows
            // one at a time. It produces the IDENTICAL result (shared accumulator arithmetic over the
            // MVCC-re-validated columnar scan) and declines to `None` for any shape it does not cover,
            // any uncached column, or under RBAC restriction — in which case the row-at-a-time Volcano
            // path below runs verbatim (the default + fallback).
            if let Some(rows) =
                try_vectorized_label_property_aggregate(input, group_keys, aggregates, ctx)?
            {
                return Ok(Operator::Buffered { rows });
            }
            let inner = build_operator(input, arg, ctx)?;
            Ok(Operator::Buffered {
                rows: aggregate_rows(inner, group_keys, aggregates, ctx)?,
            })
        }
        PhysicalOp::Sort { input, keys } => {
            // Morsel-driven parallel scan→filter→project + STABLE ORDER BY (`rmp` #339, Slice 3b): when a
            // `Sort` sits directly above the eligible projection shape, read+filter+project the candidates
            // across contiguous morsels, each pre-sorting its rows stably by `keys`, then converge via a
            // STABLE k-way merge (ties broken by ascending candidate order) — byte-identical to the serial
            // `sort_rows` stable `sort_by`. Declines (falls through to serial) for any non-conforming /
            // impure / below-threshold shape, knob<=1, RBAC restriction, or a morsel error.
            if let Some(rows) = try_morsel_scan_filter_project(input, keys, None, ctx)? {
                return Ok(Operator::Buffered { rows });
            }
            let inner = build_operator(input, arg, ctx)?;
            Ok(Operator::Buffered {
                rows: sort_rows(inner, keys, None, ctx)?,
            })
        }
        PhysicalOp::TopN { input, keys, limit } => {
            let n = eval_count(limit, ctx)?;
            // Morsel-driven parallel scan→filter→project + STABLE top-k (`rmp` #339, Slice 3b): as the
            // `Sort` case, but each morsel keeps its rows pre-sorted and the stable k-way merge bounds its
            // output to the first `n` rows — byte-identical to serial `sort_rows`' stable sort + `truncate(n)`.
            if let Some(rows) = try_morsel_scan_filter_project(input, keys, Some(n as usize), ctx)?
            {
                return Ok(Operator::Buffered { rows });
            }
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
        PhysicalOp::Foreach {
            input,
            variable,
            list,
            body,
        } => Ok(Operator::Foreach {
            input: Box::new(build_operator(input, arg, ctx)?),
            variable: variable.clone(),
            list: list.clone(),
            body_template: body.clone(),
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

/// Precise equality access (`rmp` task #325): the seam's `scan_filter_eq` reads every node to evaluate
/// the predicate but registers an SSI read dependency on **only the matching nodes** plus the precise
/// `Equality` predicate marker — the scan-path twin of `index_seek_eq`'s footprint. This replaces the
/// old fallback that ran `scan_nodes_by_label` (marking every live node) + a residual filter, whose
/// blanket marker produced reciprocal false aborts between transactions matching disjoint keys.
fn scan_filter_eq(label: &Label, property: &str, seek: &Value, ctx: &Ctx<'_>) -> Vec<NodeId> {
    ctx.graph.scan_filter_eq(&label.name, property, seek)
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
            kvs.push(eval(
                &k.expr,
                &row,
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?);
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
///
/// `pub(crate)` so the `rmp` #339 Slice-3b morsel converge ([`crate::morsel`]) uses the **same** total
/// order — per-morsel stable sort + the engine-thread stable k-way merge — that serial `sort_rows`'
/// stable `sort_by` uses, guaranteeing the parallel ORDER BY is row-order-identical to serial.
pub(crate) fn compare_sort_keys(
    a: &[RowValue],
    b: &[RowValue],
    keys: &[SortKey],
) -> std::cmp::Ordering {
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
///
/// The batch size for the vectorized aggregation fold (`rmp` #330) — the column-store convention
/// (MonetDB/X100, DuckDB): fold the columnar scan a cache-friendly chunk at a time, amortising the
/// per-tuple interpreter overhead the Volcano path pays. The whole columnar scan is materialized by
/// the seam, so this only governs the **fold** granularity (and the cancellation poll cadence).
const VECTOR_BATCH: usize = 1024;

/// One recognized **bare** aggregate of the vectorized fast path (`rmp` #330): the outer expression
/// of an aggregate column is exactly one of these (no surrounding arithmetic, no `DISTINCT`).
enum VecAgg {
    /// `count(*)` — the matched-node count (every label-matching node, property present or not).
    CountStar,
    /// `count(n.p)` — the count of nodes whose property `p` is present (a columnar row each).
    CountProp,
    /// `sum(n.p)` / `avg(n.p)` / `min(n.p)` / `max(n.p)` — a fold over the present property values.
    /// Carries the [`AggKind`] so the shared [`Accumulator`] computes it identically to Volcano.
    Fold(AggKind),
}

/// Recognizes whether `expr` (an aggregate **column's** outer expression) is a bare aggregate the
/// vectorized path supports over the single scan variable `scan_var` and property `property`
/// (`rmp` #330). Returns the [`VecAgg`] kind, or `None` to decline (the column then forces the whole
/// aggregation onto the Volcano path — always correct).
///
/// Strict by design: the column must be *exactly* the aggregate call (so the result equals the
/// aggregate value with no outer evaluation), no `DISTINCT`, and any property argument must be
/// `scan_var.property` for the single column the scan covers. `count(*)` needs no property.
fn recognize_vec_agg(expr: &Expr, scan_var: &str, property: &str) -> Option<VecAgg> {
    match &expr.kind {
        ExprKind::CountStar => Some(VecAgg::CountStar),
        ExprKind::FunctionCall {
            name,
            distinct,
            args,
        } => {
            if *distinct {
                return None; // DISTINCT folds need the distinct-set; not the vectorized fast path.
            }
            let kind = match name.join(".").to_ascii_lowercase().as_str() {
                "count" => Some(AggKind::Count),
                "sum" => Some(AggKind::Sum),
                "avg" => Some(AggKind::Avg),
                "min" => Some(AggKind::Min),
                "max" => Some(AggKind::Max),
                _ => None,
            }?;
            // Exactly one argument, and it must be `scan_var.property` (the column the scan covers).
            let [arg] = args.as_slice() else {
                return None;
            };
            if !is_scan_var_property(arg, scan_var, property) {
                return None;
            }
            Some(match kind {
                AggKind::Count => VecAgg::CountProp,
                other => VecAgg::Fold(other),
            })
        }
        _ => None,
    }
}

/// Whether `expr` is exactly the property access `scan_var.property` (`rmp` #330 recognizer helper).
fn is_scan_var_property(expr: &Expr, scan_var: &str, property: &str) -> bool {
    match &expr.kind {
        ExprKind::Property { base, key } => {
            key == property && matches!(&base.kind, ExprKind::Variable(v) if v == scan_var)
        }
        _ => false,
    }
}

/// The minimum estimated cardinality at which the parallel label-property aggregation tier is even
/// attempted (`rmp` task #352, phase 1 of #336). Below this, the snapshot-projection + rayon fan-out
/// cannot recover its fixed cost (projecting an owned column, spinning up the rayon reduction), so the
/// serial vectorized / Volcano tiers — which have effectively zero setup — win. Conservative on
/// purpose: a too-low threshold would slow small queries; the win is on the *large* analytical scans
/// (#336's motivation), where this is dwarfed by the column size. Tunable — raise it if profiling
/// shows the crossover is higher on a given deployment, lower it if parallelism pays off sooner.
const PARALLEL_AGG_MIN_ROWS: f64 = 50_000.0;

/// Whether `kind` is an **exact, associative-and-commutative** aggregate whose rayon partition-reduce
/// is provably bit-identical to the serial fold (`rmp` task #352): `count(*)`/`count(n.p)` (integer
/// increment) and integer `sum`/`min`/`max`. `avg` is excluded (float division is order-sensitive and
/// is the deferred slice), and so is any other kind. Float `sum`/`min`/`max` is excluded at the
/// *value* level (see [`try_parallel_label_property_aggregate`]), because float addition is **not**
/// associative — a parallel reduction tree could round differently from the serial left fold.
fn is_exact_parallel_agg(spec: &VecAgg) -> bool {
    match spec {
        VecAgg::CountStar | VecAgg::CountProp => true,
        VecAgg::Fold(kind) => matches!(kind, AggKind::Sum | AggKind::Min | AggKind::Max),
    }
}

/// If `(plan, input, group_keys, aggregates)` is the **parallel-eligible** analytical shape — a large
/// `MATCH (n:Label) RETURN <exact-agg>(n.p)[, …]` over an **integer** column, with more than one rayon
/// worker available — projects a frozen `Send + Sync` [`GraphSnapshot`] off the seam and folds it
/// across all cores, returning the single result row. Otherwise returns `None` so the caller falls
/// through to [`try_vectorized_label_property_aggregate`] and then the serial [`aggregate_rows`], both
/// of which run **verbatim** (`rmp` task #352, phase 1 of #336).
///
/// # Bit-identical to serial, by construction
///
/// * **Same values, same visibility, same SSI markers** — the snapshot is projected through
///   [`GraphAccess::project_snapshot`], which (on [`RecordStoreGraph`](crate::record_graph::RecordStoreGraph))
///   reuses the *identical* internal candidate pass the serial columnar scan uses: the same
///   `PredicateRead`/per-node SIREAD markers are registered on the engine thread **before** the owned
///   snapshot is handed to rayon, and every value is the node's snapshot-visible current value. So the
///   `(node, value)` set folded here is exactly the serial path's, and serializability is unchanged.
/// * **Same arithmetic** — the fold reuses the shared [`Accumulator`] (`set_count_star` / `fold_value`),
///   the very methods the serial vectorized path uses, so the per-partition results combine into the
///   identical total. Integer `+`/`min`/`max` are associative **and** commutative, so any rayon split
///   yields the identical value regardless of partition count or order — asserted by the equivalence
///   tests.
///
/// # Eligibility (ALL required, else `None`)
///
/// - no grouping keys (a single `RETURN <agg>(...)` over a whole label), input a bare label scan, and
///   every aggregate a bare recognized aggregate over the **same** single property — i.e. exactly the
///   shape [`try_vectorized_label_property_aggregate`] recognizes;
/// - every aggregate is **exact/associative** ([`is_exact_parallel_agg`]): `count(*)`, `count(n.p)`,
///   or integer `sum`/`min`/`max` (NOT `avg`, NOT a float fold);
/// - the projected column is **all integers** (a float/mixed column forces the serial path, which
///   handles float semantics and order-sensitive rounding);
/// - the **estimated input size** — the label scan's cardinality — is at least
///   [`PARALLEL_AGG_MIN_ROWS`] (below which the serial tiers win, as their setup is ~free);
/// - [`rayon::current_num_threads`] `> 1` (no point fanning out onto a single worker).
///
/// # Why the gate is the *input scan* estimate, not the plan-root estimate
///
/// The work this tier parallelizes is the **scan + fold** over the label's nodes, whose size is the
/// label scan's cardinality. The plan **root** here is the [`Aggregation`](PhysicalOp::Aggregation),
/// which collapses an ungrouped aggregation to exactly one output row
/// ([`PhysicalPlan::estimated_rows`](crate::physical::PhysicalPlan::estimated_rows) is `1.0`) — the
/// wrong quantity for this decision. So the gate is the input
/// [`NodeByLabelScan`](PhysicalOp::NodeByLabelScan) estimate, read via the seam's
/// [`Statistics`](crate::statistics::Statistics) (`nodes_with_label`) — the **same** source and formula
/// the cardinality estimator applies to a `NodeByLabelScan` leaf
/// ([`estimate_rows`](crate::cardinality::estimate_rows)). When the seam exposes no statistics, the
/// estimate is unavailable and the tier conservatively declines (serial path), so a backend without
/// counts is never forced onto the parallel path on a guess.
/// If `(input, group_keys, aggregates)` is the **morsel-parallel-eligible** analytical shape — a large
/// bare `MATCH (n:Label) RETURN <exact-agg>(n.p)[, …]` over an **integer** column, with the morsel knob
/// enabled and the seam able to hand off an off-thread read bundle — reads the label scan across
/// **contiguous morsels concurrently** on the dedicated morsel pool (parallelizing the
/// MVCC-revalidating read itself, `rmp` task #339, Slice 3a), folds the survivors' values across the
/// morsels, and returns the single result row. Otherwise returns `None` so the caller falls through to
/// [`try_parallel_label_property_aggregate`] / [`try_vectorized_label_property_aggregate`] / the serial
/// [`aggregate_rows`], all of which run **verbatim**.
///
/// # Why this beats the `rmp` #352 tier (and is still bit-identical to serial)
///
/// [`try_parallel_label_property_aggregate`] parallelizes only the **fold** over a *serially-projected*
/// column, which measured **zero** end-to-end gain — the cost is the per-candidate MVCC-revalidating
/// **read**, not the fold. This tier splits the candidate-id vector into contiguous morsels and reads
/// each morsel **concurrently** (each morsel cheap-clones a `StoreReadView` and runs the same
/// source-generic `filter_label_candidates` + `node_property` the serial path runs), so it parallelizes
/// the read.
///
/// It is bit-identical to serial by the same construction the #352 tier uses, plus the morsel-specific
/// invariants:
/// * **Same values, same visibility** — every morsel reads through the identical lifted read body over
///   an MVCC-superset-safe `StoreReadView`, so the `(node, value)` set is exactly the serial path's.
/// * **Same SSI markers** — the coarse `PredicateRead::Label` + all-live-nodes footprint is registered
///   on the engine thread by the seam (`morsel_label_scan`); each morsel records its per-candidate
///   SIREAD markers into its own buffer, folded back via `merge_morsel_buffer`
///   ([`SsiTracker::merge_read_buffer`] sorts + dedups + replays — commutative + idempotent), so the
///   merged conflict graph is the union = the serial scan's marker set.
/// * **Same arithmetic** — the morsels read values; the engine thread folds them with the shared
///   [`Accumulator`] (`fold_value` / `set_count_star`), integer `+`/`min`/`max` being associative +
///   commutative, so any morsel split yields the identical total. `count(*)` is the summed
///   visible-label-carrying count across morsels.
///
/// # Eligibility (ALL required, else `None`)
///
/// - the morsel knob is enabled: [`Ctx::morsel_threads`] `> 1` (the cheap first gate; `<= 1` is the
///   fully-serial RPi / determinism / library default);
/// - no grouping keys, input a bare label scan, every aggregate a bare recognized **exact/associative**
///   aggregate over the **same** single property (the [`try_vectorized_label_property_aggregate`] shape
///   restricted to [`is_exact_parallel_agg`] — `avg` / a float fold force the serial path);
/// - the estimated label cardinality is at least [`MORSEL_MIN_ROWS`](crate::morsel::MORSEL_MIN_ROWS)
///   (via `statistics().nodes_with_label`; no statistics ⇒ decline);
/// - the seam returns `Some` from [`GraphAccess::morsel_label_scan`] (it declines for a restricted
///   principal, a standalone / historical read, and `MemGraph`).
///
/// After reading, if any property fold is requested and any morsel observed a **non-integer** value, the
/// tier discards the morsel results **without folding their buffers** and returns `None` (the serial
/// path then handles the float column and re-registers the per-candidate markers identically — the
/// coarse footprint already registered by the seam is harmlessly idempotent under the merge).
/// Whether `expr` is a **bare, mergeable** aggregate column the `rmp` #360 grouped morsel tier admits:
/// exactly one aggregate call (no surrounding arithmetic) of a kind whose parallel partition-merge is
/// provably **bit-identical** to the serial fold. Returns `Some(needs_integer_gate)` for an admitted
/// column (`needs_integer_gate == true` for `sum`, which must additionally be gated to a no-overflow
/// integer column — see [`try_morsel_group_aggregate`]); `None` to decline the whole tier.
///
/// # Admitted (mergeable)
/// - `count(*)` / `count(x)` / `count(DISTINCT x)` — pure i64 increment / order-preserving DISTINCT set
///   (associative; DISTINCT re-deduped across partitions by [`Accumulator::combine`]);
/// - `min(x)` / `max(x)` — idempotent selection via [`cmp_values`] (associative + commutative);
/// - `sum(x)` — i64 add, **but only over a no-overflow integer column** (`needs_integer_gate`); float
///   `sum` and an overflowing integer `sum` are NOT associative (`saturating_add` clamps order-
///   dependently once any partition subtree saturates — empirically verified), so they decline to serial;
/// - `collect(x)` / `collect(DISTINCT x)` — list-concat / order-preserving set-union in ascending-`lo`
///   order = serial encounter order.
///
/// # Rejected (⇒ serial, never parallelized)
/// - `avg(x)` — serial divides a scan-order f64 running sum; above 2^53 a parallel reduction in a
///   different order diverges by ≥1 ULP (empirically verified), so it is never bit-identical;
/// - `percentileCont`/`percentileDisc` — order-sensitive gather + a second argument the bare-fold path
///   does not evaluate;
/// - any composite column (`sum(x) + 1`, `size(collect(x))`), a non-aggregate column, or a second
///   argument — the serial `aggregate_rows` `AggPlan` covers all of those correctly.
fn recognize_mergeable_bare_agg(expr: &Expr, scan_var: &str) -> Option<bool> {
    match &expr.kind {
        // `count(*)`: pure i64 increment, always mergeable, no integer gate.
        ExprKind::CountStar => Some(false),
        ExprKind::FunctionCall {
            name,
            distinct,
            args,
        } => {
            let fname = name.join(".").to_ascii_lowercase();
            // Exactly one argument referencing the scan var (`count`/`sum`/`min`/`max`/`collect` are
            // single-argument); the argument must be pure per-row so the off-thread eval is deterministic
            // and cross-row-free, AND must reference the scan var (a constant-/param-only aggregate
            // argument is unusual and left to serial).
            let [arg] = args.as_slice() else {
                return None;
            };
            if !crate::morsel::is_pure_per_row_expr(arg) || !expr_references_var(arg, scan_var) {
                return None;
            }
            match fname.as_str() {
                // DISTINCT is mergeable only for count/collect (re-deduped across partitions); a DISTINCT
                // sum/min/max is left to serial (min/max DISTINCT == min/max, but we keep the gate tight).
                "count" | "collect" => Some(false),
                "min" | "max" if !*distinct => Some(false),
                // `sum` needs the no-overflow integer gate (the caller checks the column).
                "sum" if !*distinct => Some(true),
                // avg / percentile / any other kind, or a DISTINCT sum/min/max: decline.
                _ => None,
            }
        }
        _ => None,
    }
}

/// Whether `expr` syntactically references the variable `var` (its property, or the bare variable) —
/// a cheap structural walk used by the `rmp` #360 grouped recognizer to confirm an aggregate argument /
/// group key is anchored on the scanned node (so the off-thread per-row eval is meaningful). Conservative:
/// any reference anywhere in the expression counts.
fn expr_references_var(expr: &Expr, var: &str) -> bool {
    match &expr.kind {
        ExprKind::Variable(v) => v == var,
        ExprKind::Literal(_) | ExprKind::Parameter(_) | ExprKind::CountStar => false,
        ExprKind::Binary { lhs, rhs, .. } => {
            expr_references_var(lhs, var) || expr_references_var(rhs, var)
        }
        ExprKind::Unary { operand, .. } => expr_references_var(operand, var),
        ExprKind::Predicate { operand, rhs, .. } => {
            expr_references_var(operand, var)
                || rhs.as_deref().is_some_and(|e| expr_references_var(e, var))
        }
        ExprKind::Property { base, .. } => expr_references_var(base, var),
        ExprKind::Index { base, index } => {
            expr_references_var(base, var) || expr_references_var(index, var)
        }
        ExprKind::Slice { base, low, high } => {
            expr_references_var(base, var)
                || low.as_deref().is_some_and(|e| expr_references_var(e, var))
                || high.as_deref().is_some_and(|e| expr_references_var(e, var))
        }
        ExprKind::HasLabels { operand, .. } => expr_references_var(operand, var),
        ExprKind::FunctionCall { args, .. } => args.iter().any(|a| expr_references_var(a, var)),
        ExprKind::List(items) => items.iter().any(|e| expr_references_var(e, var)),
        ExprKind::Map(entries) => entries.iter().any(|(_, v)| expr_references_var(v, var)),
        ExprKind::Case(case) => {
            case.subject
                .as_deref()
                .is_some_and(|e| expr_references_var(e, var))
                || case.alternatives.iter().any(|alt| {
                    expr_references_var(&alt.when, var) || expr_references_var(&alt.then, var)
                })
                || case
                    .else_expr
                    .as_deref()
                    .is_some_and(|e| expr_references_var(e, var))
        }
        // Comprehensions / quantifiers / subqueries are rejected by the purity gate before this is
        // reached, so a conservative `false` is fine (the column already declined).
        ExprKind::ListComprehension(_)
        | ExprKind::PatternComprehension(_)
        | ExprKind::Quantifier(_)
        | ExprKind::ExistsSubquery(_) => false,
    }
}

/// If `(input, group_keys, aggregates)` is the **morsel-parallel-eligible GROUPED aggregation shape** —
/// a large bare `MATCH (n:Label) RETURN <bare pure group keys>, <bare mergeable aggregates>` (`rmp` task
/// #360, the grouped tier extending Slice 3a to the non-empty-GROUP-BY case, the actual LDBC-BI
/// bottleneck) — partitions the candidate-id vector into contiguous morsels, builds a LOCAL group table
/// per morsel **concurrently** on the dedicated pool, merges the partials deterministically on the engine
/// thread, and returns the grouped rows. Otherwise returns `None` so the caller falls through to the
/// keyless tiers and then the serial [`aggregate_rows`], all of which run **verbatim**.
///
/// # Byte-identical to serial, by construction
///
/// * **Same grouping** — each morsel keys its local table on the SAME SipHash digest
///   ([`group_key_hash`]) + [`row_values_equivalent`] resolution the serial `aggregate_rows` uses (and
///   the engine-thread merge re-keys identically), so the partition of rows into groups is identical;
/// * **Same values / visibility / SSI markers** — each morsel reads through the identical lifted read
///   body over an MVCC-superset-safe `StoreReadView` and evaluates keys + aggregate arguments with the
///   identical [`eval`]; the coarse `PredicateRead::Label` + all-live-nodes footprint is registered on
///   the engine thread by the seam, and each morsel's markers fold back via `merge_morsel_buffer` (union
///   = the serial set);
/// * **Same arithmetic** — every morsel folds into the SAME [`Accumulator`] type the serial path uses
///   (via [`Accumulator::fold_bare`]); the merge combines via [`Accumulator::combine`], which is
///   associative for `count`/`sum`/`min`/`max` and order-preserving (ascending-`lo`) for
///   `collect`/`DISTINCT`; `sum` is gated to a **no-overflow integer** column (a `saturating_add` that
///   never clamps is pure associative i64 add); `avg` / percentile decline (their parallel merge is not
///   bit-identical);
/// * **Same output order** — the merge emits groups sorted by global first-seen rank (the unique global
///   survivor index that first created each group), which is order-isomorphic to serial first-seen order,
///   **independent of the worker count** (the AC's determinism).
///
/// # Eligibility (ALL required, else `None`)
/// - the morsel knob is enabled: [`Ctx::morsel_threads`] `> 1`;
/// - `input` is a bare label scan (`NodeByLabelScan` / `TokenLookupScan`) — NO interposed `Filter` /
///   `Expand` (those change which rows / the candidate order; the planner shapes
///   `MATCH (n:Label) RETURN n.k, agg(n.p)` with the bare scan directly under the `Aggregation`, and a
///   `WHERE` interposes a `Filter` ⇒ declines);
/// - there is **at least one** group key (the keyless case is the existing Slice-3a tier), every group
///   key is **pure per-row** ([`crate::morsel::is_pure_per_row_expr`]) and references the scan var;
/// - every aggregate column is a **bare mergeable** aggregate ([`recognize_mergeable_bare_agg`]);
/// - the estimated label cardinality is at least [`MORSEL_MIN_ROWS`](crate::morsel::MORSEL_MIN_ROWS)
///   (via `statistics().nodes_with_label`; no statistics ⇒ decline);
/// - if any `sum` is requested, the column is provably **no-overflow integer** (every read value an
///   `Integer`, and the running per-morsel sub-sum cannot saturate — checked after the read);
/// - the seam returns `Some` from [`GraphAccess::morsel_label_scan`] (it declines for a restricted
///   principal, a standalone / historical read, and `MemGraph`).
///
/// On any per-morsel error the tier discards every morsel's groups + buffers and returns `None`; the
/// serial fallback re-runs the pipeline, re-registering the markers and re-raising the identical error.
fn try_morsel_group_aggregate(
    input: &PhysicalOp,
    group_keys: &[ProjectionColumn],
    aggregates: &[ProjectionColumn],
    ctx: &mut Ctx<'_>,
) -> Result<Option<VecDeque<Row>>, ExecError> {
    // --- cheap gate first (no seam work): the morsel knob must be enabled (>= 2 workers) ---
    if ctx.morsel_threads <= 1 {
        return Ok(None);
    }

    // --- recognize the GROUPED bare-aggregate shape: >= 1 group key, >= 1 aggregate, bare label scan ---
    if group_keys.is_empty() || aggregates.is_empty() {
        return Ok(None);
    }
    let (scan_var, label) = match input {
        PhysicalOp::NodeByLabelScan { variable, label }
        | PhysicalOp::TokenLookupScan {
            variable, label, ..
        } => (&variable.name, &label.name),
        _ => return Ok(None),
    };

    // Every group key must be PURE per-row (so the off-thread eval is deterministic + cross-row-free) and
    // reference the scanned node (a constant group key is degenerate and left to serial).
    for col in group_keys {
        if !crate::morsel::is_pure_per_row_expr(&col.expr)
            || !expr_references_var(&col.expr, scan_var)
        {
            return Ok(None);
        }
    }

    // Every aggregate column must be a BARE MERGEABLE aggregate; collect whether any requires the
    // no-overflow integer gate (i.e. is a `sum`).
    let mut any_sum = false;
    for col in aggregates {
        match recognize_mergeable_bare_agg(&col.expr, scan_var) {
            Some(needs_integer_gate) => any_sum |= needs_integer_gate,
            None => return Ok(None),
        }
    }

    // --- the size gate: the label scan's estimated cardinality (the work being parallelized) ---
    let estimated_input = match ctx
        .graph
        .statistics()
        .and_then(|s| s.nodes_with_label(label))
    {
        Some(count) => count as f64,
        None => return Ok(None),
    };
    if !estimated_input.is_finite() || estimated_input < crate::morsel::morsel_min_rows() {
        return Ok(None);
    }

    // --- the engine-thread seam: capture the candidate vector + off-thread read surface (registers the
    // identical coarse SSI markers). `None` ⇒ standalone / historical / restricted-RBAC / MemGraph ⇒
    // serial pipeline runs verbatim. ---
    let Some(mut scan) = ctx.graph.morsel_label_scan(label) else {
        return Ok(None);
    };
    // Install the per-statement wall-clock budget (`rmp` #476) on the parallel workers, so a runaway
    // grouped morsel scan abandons rather than pinning every core; on elapse a worker records a timeout
    // error and the serial fallback below surfaces a clean `Cancelled`.
    scan.deadline = ctx.token.deadline();

    // Cancellation (flag and an already-elapsed deadline) is polled once up front; each worker then polls
    // the deadline again at a strided cadence while it runs (`rmp` #476).
    ctx.check_cancelled()?;

    let spec = crate::morsel::MorselGroupSpec {
        scan_var,
        group_keys,
        aggregates,
    };

    // --- group + aggregate the morsels concurrently, merging deterministically (serial first-seen order) ---
    let converged =
        crate::morsel::run_group_aggregate_morsels(&scan, &spec, ctx.params, ctx.morsel_threads);

    // If any morsel hit a storage / evaluation error, the parallel result is untrustworthy: decline
    // WITHOUT folding the buffers (dropped here). The serial fallback re-reads + re-evaluates through the
    // live seam, re-registering the identical markers AND re-raising the identical error.
    if converged.error.is_some() {
        return Ok(None);
    }

    // --- the no-overflow integer gate for `sum` (`rmp` #360, finding C): `saturating_add` is NOT
    // associative once any partition subtree clamps to the i64 rail (empirically verified:
    // `[i64::MAX, i64::MAX, -i64::MAX, -i64::MAX]` folds to MIN+1 serially but -1 under a 2+2 split), so a
    // parallel `sum` is bit-identical to serial ONLY when no sub-sum saturates. We cannot know the column
    // a priori, so the merged accumulators are checked here: if any `sum` accumulator's combined witnesses
    // indicate a float was seen (non-integer column) OR a saturation occurred anywhere, discard the
    // parallel result and fall back to serial (which folds the column exactly). This is the conservative,
    // provably-correct gate — the parallel win is preserved for the overwhelmingly common small-magnitude
    // analytical columns #360 targets, and a pathological near-rail column is handled correctly by serial.
    if any_sum
        && converged
            .groups
            .iter()
            .any(|g| g.accs.iter().any(Accumulator::sum_is_parallel_unsafe))
    {
        return Ok(None);
    }

    // Every gate passed and the read succeeded: record the engagement (observability), then converge the
    // per-morsel SSI buffers. From here we are committed to the parallel result.
    ctx.graph.note_parallel_aggregate();
    for buffer in converged.buffers {
        ctx.graph.merge_morsel_buffer(buffer);
    }

    // Finish each merged group into its output row, in serial first-seen order. For the BARE shape the
    // group key value IS the column value and each aggregate value IS `acc.finish()` — there is no outer
    // expression to evaluate (the recognizer guaranteed bare columns), exactly as the keyless morsel tier
    // builds its single row.
    let mut out = VecDeque::with_capacity(converged.groups.len());
    for group in converged.groups {
        let mut row = Row::empty();
        for (col, kv) in group_keys.iter().zip(group.key) {
            row.set(col.alias.clone(), kv);
        }
        for (col, acc) in aggregates.iter().zip(group.accs) {
            row.set(col.alias.clone(), acc.finish());
        }
        out.push_back(row);
    }
    Ok(Some(out))
}

fn try_morsel_label_aggregate(
    input: &PhysicalOp,
    group_keys: &[ProjectionColumn],
    aggregates: &[ProjectionColumn],
    ctx: &mut Ctx<'_>,
) -> Result<Option<VecDeque<Row>>, ExecError> {
    // --- cheap gate first (no seam work): the morsel knob must be enabled (>= 2 workers) ---
    if ctx.morsel_threads <= 1 {
        return Ok(None);
    }

    // --- recognize exactly the bare-aggregate analytical shape (single group, bare label scan) ---
    if !group_keys.is_empty() || aggregates.is_empty() {
        return Ok(None);
    }
    let (scan_var, label) = match input {
        PhysicalOp::NodeByLabelScan { variable, label }
        | PhysicalOp::TokenLookupScan {
            variable, label, ..
        } => (&variable.name, &label.name),
        _ => return Ok(None),
    };

    // --- the size gate: the label scan's estimated cardinality (the work being parallelized) ---
    // The same source + formula the cardinality estimator uses for a `NodeByLabelScan` leaf; no
    // statistics ⇒ no estimate ⇒ conservatively decline (serial path).
    let estimated_input = match ctx
        .graph
        .statistics()
        .and_then(|s| s.nodes_with_label(label))
    {
        Some(count) => count as f64,
        None => return Ok(None),
    };
    if !estimated_input.is_finite() || estimated_input < crate::morsel::morsel_min_rows() {
        return Ok(None);
    }

    // Resolve the single covered property (the first property-bearing aggregate fixes it; the rest must
    // agree). A pure `count(*)`-only aggregation has no column to read — let the serial path handle it
    // (it is trivially cheap and the morsel read keys on a property column).
    let mut property: Option<String> = None;
    for col in aggregates {
        if let Some(p) = sole_aggregate_property(&col.expr, scan_var) {
            match &property {
                Some(existing) if existing != &p => return Ok(None),
                _ => property = Some(p),
            }
        }
    }
    let Some(property) = property else {
        return Ok(None);
    };

    // Recognize every column as a bare aggregate over `(scan_var, property)`, and require each to be an
    // EXACT/associative aggregate (decline `avg`, any non-bare column, a `DISTINCT`, or a second
    // property — the serial path covers all of those correctly).
    let mut specs: Vec<VecAgg> = Vec::with_capacity(aggregates.len());
    for col in aggregates {
        match recognize_vec_agg(&col.expr, scan_var, &property) {
            Some(spec) if is_exact_parallel_agg(&spec) => specs.push(spec),
            _ => return Ok(None),
        }
    }

    // --- the engine-thread seam: capture the candidate vector + off-thread read surface (registers the
    // identical coarse SSI markers). `None` ⇒ standalone / historical / restricted-RBAC / MemGraph ⇒
    // fall through to the serial tiers, which run verbatim. ---
    let Some(mut scan) = ctx.graph.morsel_label_scan(label) else {
        return Ok(None);
    };
    // Install the per-statement wall-clock budget (`rmp` #476): the bare-aggregate fan-out gates each
    // morsel on the deadline, so a runaway scan abandons rather than pinning every core; the serial
    // fallback below then surfaces a clean `Cancelled`.
    scan.deadline = ctx.token.deadline();

    // Cancellation (flag and an already-elapsed deadline) is polled once up front; the fan-out then gates
    // each morsel on the deadline as it runs (`rmp` #476).
    ctx.check_cancelled()?;

    // --- read the morsels concurrently on the dedicated pool (the parallelized MVCC-revalidating read) ---
    let outcomes = crate::morsel::run_morsels(&scan, &property, ctx.morsel_threads);

    // If any morsel hit a storage / deferred-feature error, the parallel result is untrustworthy:
    // decline (the morsel buffers are dropped — markers NOT folded). The serial fallback re-reads the
    // same nodes through the live seam, which re-registers the identical per-candidate markers AND
    // re-hits the same storage fault, capturing it through the normal `ReadSink::capture` channel so the
    // statement rolls back — exactly as if the morsel path had never run.
    if outcomes.iter().any(|o| o.error.is_some()) {
        return Ok(None);
    }

    // The all-integer constraint (the exactness guarantee): if any property fold is requested and ANY
    // morsel observed a non-integer value, a parallel reduction could round differently than the serial
    // left fold (float `+` is non-associative). Discard the morsel results WITHOUT folding their buffers
    // and decline — the serial path handles the float column exactly and re-registers the markers.
    let any_fold = specs.iter().any(|s| matches!(s, VecAgg::Fold(_)));
    if any_fold
        && outcomes
            .iter()
            .any(|o| o.values.iter().any(|v| !matches!(v, Value::Integer(_))))
    {
        return Ok(None);
    }

    // --- fold the survivors' values into one accumulator per column (NOT yet committed) ---
    let mut accs: Vec<Accumulator> = specs.iter().map(new_parallel_acc).collect();
    let mut label_matches: usize = 0;
    for outcome in &outcomes {
        label_matches = label_matches.saturating_add(outcome.label_matches);
        for value in &outcome.values {
            for (spec, acc) in specs.iter().zip(accs.iter_mut()) {
                match spec {
                    // `count(*)` is assigned from `label_matches` after the fold, not folded per value.
                    VecAgg::CountStar => {}
                    VecAgg::CountProp | VecAgg::Fold(_) => acc.fold_value(value)?,
                }
            }
        }
    }

    // --- the no-overflow gate for `sum` (`rmp` #360, finding C — closing a latent bug in this pre-existing
    // keyless tier): `saturating_add` is NOT associative once any partition subtree clamps to the i64 rail,
    // so a parallel `sum` matches the serial left fold ONLY when no fold saturated. The all-integer gate
    // above is necessary but NOT sufficient (an integer column can still overflow). If any `sum`
    // accumulator's saturation witness is set, decline (WITHOUT noting / merging buffers) so the serial
    // path folds the column exactly. The common small-magnitude analytical column never saturates and stays
    // parallel. ---
    if accs.iter().any(Accumulator::sum_is_parallel_unsafe) {
        return Ok(None);
    }

    // Every gate passed and the read succeeded: record the engagement (observability), then converge the
    // morsels' SSI buffers. From here we are committed to the parallel result.
    ctx.graph.note_parallel_aggregate();

    // `count(*)` is the matched-node count (every visible label-carrying node, property or not) —
    // identical to the serial vectorized path's `set_count_star`.
    let count_star = i64::try_from(label_matches).unwrap_or(i64::MAX);
    for (spec, acc) in specs.iter().zip(accs.iter_mut()) {
        if matches!(spec, VecAgg::CountStar) {
            acc.set_count_star(count_star);
        }
    }

    // --- converge the per-morsel SIREAD buffers into the statement's shared SSI tracker (engine thread,
    // before commit — rule M1). The merge sorts + dedups + replays, so the conflict graph is the union =
    // the serial scan's marker set. ---
    for outcome in outcomes {
        ctx.graph.merge_morsel_buffer(outcome.buffer);
    }

    // Finish each column into the single output row (every column is a bare aggregate, so the aggregate
    // value IS the column value — no outer expression to evaluate).
    let mut row = Row::empty();
    for (col, acc) in aggregates.iter().zip(accs) {
        row.set(col.alias.clone(), acc.finish());
    }
    Ok(Some(VecDeque::from(vec![row])))
}

fn try_parallel_label_property_aggregate(
    input: &PhysicalOp,
    group_keys: &[ProjectionColumn],
    aggregates: &[ProjectionColumn],
    ctx: &mut Ctx<'_>,
) -> Result<Option<VecDeque<Row>>, ExecError> {
    use rayon::prelude::*;

    // --- cheap gate first (no seam work): require more than one rayon worker ---
    if rayon::current_num_threads() <= 1 {
        return Ok(None);
    }

    // --- recognize exactly the vectorized analytical shape (single group, bare label scan) ---
    if !group_keys.is_empty() || aggregates.is_empty() {
        return Ok(None);
    }
    let (scan_var, label) = match input {
        PhysicalOp::NodeByLabelScan { variable, label }
        | PhysicalOp::TokenLookupScan {
            variable, label, ..
        } => (&variable.name, &label.name),
        _ => return Ok(None),
    };

    // --- the size gate: the label scan's estimated cardinality (the work being parallelized) ---
    // Read from the seam's statistics — the same source + formula the cardinality estimator uses for a
    // `NodeByLabelScan` leaf. No statistics ⇒ no estimate ⇒ conservatively decline (serial path).
    let estimated_input = match ctx
        .graph
        .statistics()
        .and_then(|s| s.nodes_with_label(label))
    {
        Some(count) => count as f64,
        None => return Ok(None),
    };
    if !estimated_input.is_finite() || estimated_input < PARALLEL_AGG_MIN_ROWS {
        return Ok(None);
    }

    // Resolve the single covered property (the first property-bearing aggregate fixes it; the rest
    // must agree). A pure `count(*)`-only aggregation has no column to project — let the serial path
    // handle it (it is already trivially cheap and the seam keys a snapshot on a property column).
    let mut property: Option<String> = None;
    for col in aggregates {
        if let Some(p) = sole_aggregate_property(&col.expr, scan_var) {
            match &property {
                Some(existing) if existing != &p => return Ok(None),
                _ => property = Some(p),
            }
        }
    }
    let Some(property) = property else {
        return Ok(None);
    };

    // Recognize every column as a bare aggregate over `(scan_var, property)`, and require each to be
    // an EXACT/associative aggregate (decline `avg`, any non-bare column, a `DISTINCT`, or a second
    // property — the serial path covers all of those correctly).
    let mut specs: Vec<VecAgg> = Vec::with_capacity(aggregates.len());
    for col in aggregates {
        match recognize_vec_agg(&col.expr, scan_var, &property) {
            Some(spec) if is_exact_parallel_agg(&spec) => specs.push(spec),
            _ => return Ok(None),
        }
    }

    // --- read the SAME owned candidate column the serial vectorized tier reads ---
    // One MVCC-revalidating pass through the seam that registers the identical SSI/predicate markers
    // (RBAC-restricted principals decline one layer up); `None` ⇒ no columnar cache / historical read
    // ⇒ fall through to the serial tiers, which run verbatim. We then fold these owned `(node, value)`
    // rows in parallel directly. NB (rmp #352 measurement): building a full `GraphSnapshot` here
    // (topology + label index + a reconstructed column) measured ~1.8x SLOWER than serial — the fold
    // never touches that structure and the dominant cost is this read, which is identical on both
    // paths. The materialized-snapshot enabler is for compute-heavy operators (traversals/GDS), not a
    // trivial associative fold whose bottleneck is the read.
    let Some(scan) = ctx.graph.columnar_label_property_scan(label, &property) else {
        return Ok(None);
    };
    let rows = scan.rows;
    let label_matches = scan.label_matches;

    // If any property fold (`sum`/`min`/`max`) is requested, require an ALL-INTEGER column: a
    // float/mixed column is the deferred slice (float `+` is non-associative, so a parallel reduction
    // could round differently than the serial left fold), so decline and let the serial path handle it
    // exactly. A `count`/`count(*)`-only set imposes no such constraint (it never inspects the value).
    let any_fold = specs.iter().any(|s| matches!(s, VecAgg::Fold(_)));
    if any_fold && rows.iter().any(|(_, v)| !matches!(v, Value::Integer(_))) {
        return Ok(None);
    }

    // Every gate passed and we are about to fold in parallel: record the engagement (observability).
    ctx.graph.note_parallel_aggregate();

    // --- the parallel reduction: one accumulator per column, folded over a FIXED partition order ---
    // rayon's `fold` produces per-thread partial accumulators; `reduce` combines them. Integer
    // `+`/`min`/`max` are associative + commutative, so the combine is order-independent and the total
    // equals the serial left fold bit-for-bit (asserted by the equivalence tests). Cancellation is
    // polled once up front (the fold itself is a tight CPU loop over owned integers — no seam access).
    ctx.check_cancelled()?;

    // The empty-input fast path keeps the reduce identity trivial and avoids a needless fan-out.
    let folded: Result<Vec<Accumulator>, ExecError> = if rows.is_empty() {
        Ok(specs.iter().map(new_parallel_acc).collect())
    } else {
        rows.par_iter()
            .try_fold(
                || specs.iter().map(new_parallel_acc).collect::<Vec<_>>(),
                |mut accs, (_node, value)| {
                    for (spec, acc) in specs.iter().zip(accs.iter_mut()) {
                        match spec {
                            // `count(*)` is assigned from `label_matches` after the reduce, not folded.
                            VecAgg::CountStar => {}
                            VecAgg::CountProp | VecAgg::Fold(_) => acc.fold_value(value)?,
                        }
                    }
                    Ok(accs)
                },
            )
            .try_reduce(
                || specs.iter().map(new_parallel_acc).collect::<Vec<_>>(),
                |mut a, b| {
                    for (acc_a, acc_b) in a.iter_mut().zip(b) {
                        acc_a.combine(acc_b);
                    }
                    Ok(a)
                },
            )
    };
    let mut accs = folded?;

    // --- the no-overflow gate for `sum` (`rmp` #360, finding C — closing a latent bug in this pre-existing
    // #352 tier): `saturating_add` is non-associative once any partition subtree clamps to the i64 rail, so
    // a parallel `sum` matches the serial left fold ONLY when no fold saturated. The all-integer gate above
    // is necessary but NOT sufficient (an integer column can still overflow). If any `sum` accumulator's
    // saturation witness is set, decline so the serial path folds the column exactly (the markers were
    // registered by the seam on the engine thread, so the serial re-registration is idempotent). ---
    if accs.iter().any(Accumulator::sum_is_parallel_unsafe) {
        return Ok(None);
    }

    // `count(*)` is the matched-node count, assigned directly (every matched node, property or not) —
    // identical to the serial vectorized path's `set_count_star`.
    let label_matches = i64::try_from(label_matches).unwrap_or(i64::MAX);
    for (spec, acc) in specs.iter().zip(accs.iter_mut()) {
        if matches!(spec, VecAgg::CountStar) {
            acc.set_count_star(label_matches);
        }
    }

    // Finish each column into the single output row (every column is a bare aggregate, so the
    // aggregate value IS the column value — no outer expression to evaluate).
    let mut row = Row::empty();
    for (col, acc) in aggregates.iter().zip(accs) {
        row.set(col.alias.clone(), acc.finish());
    }
    Ok(Some(VecDeque::from(vec![row])))
}

/// A fresh, zeroed [`Accumulator`] for a parallel partition of `spec` (`rmp` task #352) — the same
/// zero state the serial vectorized path builds, so a partial fold here combines exactly with one
/// from any other partition.
fn new_parallel_acc(spec: &VecAgg) -> Accumulator {
    match spec {
        VecAgg::CountStar => Accumulator::for_kind(AggKind::CountStar),
        VecAgg::CountProp => Accumulator::for_kind(AggKind::Count),
        VecAgg::Fold(kind) => Accumulator::for_kind(*kind),
    }
}

/// If `(input, group_keys, aggregates)` is the **vectorized-eligible** analytical shape
/// `MATCH (n:Label) RETURN agg(n.p)[, …]` over a columnar-cached `(Label, p)`, runs the batched fold
/// over the columnar scan and returns the single result row; otherwise returns `None` so the caller
/// uses the row-at-a-time [`aggregate_rows`] (the default + fallback for everything else) — `rmp` #330.
///
/// # Identical results, by construction
///
/// The fold reuses the **same** [`Accumulator`] arithmetic the Volcano path uses (`fold_value` /
/// `set_count_star`), and the columnar scan returns **exactly** the row-path `(node, value)` set plus
/// the exact `count(*)` denominator (every cached value is MVCC-re-validated, with a row-read
/// fallback) — so the produced row is byte-identical to `aggregate_rows`. The vectorization is
/// **compute-only**: it changes how fast the values are folded, never which values, and result egress
/// (Bolt/PackStream) is unchanged. Any shape this does not recognize, any column not cached, or any
/// captured seam error makes it decline and the Volcano path runs verbatim.
///
/// # Eligibility (all required)
/// - no grouping keys (a single group — the `RETURN agg(...)` over a whole label);
/// - the input is a bare label scan (`NodeByLabelScan` / `TokenLookupScan`), no interposed filter;
/// - every aggregate column is a bare recognized aggregate ([`recognize_vec_agg`]) and all
///   property-bearing ones reference the **same** property (the one column the scan covers);
/// - the seam offers a columnar scan for `(label, property)` (else `None`).
fn try_vectorized_label_property_aggregate(
    input: &PhysicalOp,
    group_keys: &[ProjectionColumn],
    aggregates: &[ProjectionColumn],
    ctx: &mut Ctx<'_>,
) -> Result<Option<VecDeque<Row>>, ExecError> {
    // Only the single-group `RETURN agg(...)` shape (no GROUP BY) is vectorized in this task.
    if !group_keys.is_empty() || aggregates.is_empty() {
        return Ok(None);
    }
    // The input must be a bare label scan binding one variable (no Filter/Expand between it and the
    // aggregation — those change which rows or values feed the fold).
    let (scan_var, label) = match input {
        PhysicalOp::NodeByLabelScan { variable, label }
        | PhysicalOp::TokenLookupScan {
            variable, label, ..
        } => (&variable.name, &label.name),
        _ => return Ok(None),
    };

    // Resolve the single covered property: the first property-bearing aggregate fixes it; every other
    // property-bearing aggregate must agree (the scan covers exactly one column). `count(*)` is
    // property-free and imposes no constraint.
    let mut property: Option<String> = None;
    for col in aggregates {
        if let Some(p) = sole_aggregate_property(&col.expr, scan_var) {
            match &property {
                Some(existing) if existing != &p => return Ok(None), // two different columns
                _ => property = Some(p),
            }
        }
    }
    // A pure `count(*)`-only aggregation has no property column to scan; let the Volcano path handle
    // it (it is already trivially cheap, and the columnar seam keys on a property).
    let Some(property) = property else {
        return Ok(None);
    };

    // Recognize every column as a bare aggregate over `(scan_var, property)`; decline on the first
    // non-conforming column (e.g. `sum(n.p) + 1`, a `DISTINCT`, or a second property).
    let mut specs: Vec<VecAgg> = Vec::with_capacity(aggregates.len());
    for col in aggregates {
        match recognize_vec_agg(&col.expr, scan_var, &property) {
            Some(spec) => specs.push(spec),
            None => return Ok(None),
        }
    }

    // Ask the seam for the columnar scan. `None` ⇒ no columnar cache for this column ⇒ decline (the
    // Volcano path runs). This call registers the identical SSI/predicate read markers the row scan
    // would (inside the seam), so serializability is unchanged whether or not we take this path.
    let Some(scan) = ctx.graph.columnar_label_property_scan(label, &property) else {
        return Ok(None);
    };

    // Fold the values into one accumulator per column, in cache-friendly batches (`rmp` #330).
    let mut accs: Vec<Accumulator> = specs
        .iter()
        .map(|spec| match spec {
            VecAgg::CountStar => Accumulator::for_kind(AggKind::CountStar),
            VecAgg::CountProp => Accumulator::for_kind(AggKind::Count),
            VecAgg::Fold(kind) => Accumulator::for_kind(*kind),
        })
        .collect();

    // `count(*)` is the matched-node count, assigned directly (every matched node, property or not).
    let label_matches = i64::try_from(scan.label_matches).unwrap_or(i64::MAX);
    for (spec, acc) in specs.iter().zip(accs.iter_mut()) {
        if matches!(spec, VecAgg::CountStar) {
            acc.set_count_star(label_matches);
        }
    }

    // The property folds (`count(n.p)`/`sum`/`avg`/`min`/`max`) run over the present values, batched.
    for batch in scan.rows.chunks(VECTOR_BATCH) {
        ctx.check_cancelled()?;
        for (_node, value) in batch {
            for (spec, acc) in specs.iter().zip(accs.iter_mut()) {
                match spec {
                    // `count(*)` was assigned up front; it does not fold per value.
                    VecAgg::CountStar => {}
                    // `count(n.p)` and the numeric/extreme folds fold each present value identically
                    // to the Volcano `Accumulator` (shared arithmetic ⇒ identical result).
                    VecAgg::CountProp | VecAgg::Fold(_) => acc.fold_value(value)?,
                }
            }
        }
    }

    // Finish each column into the single output row (the aggregate value is the column value, since
    // every column is a bare aggregate — no outer expression to evaluate).
    let mut row = Row::empty();
    for (col, acc) in aggregates.iter().zip(accs) {
        row.set(col.alias.clone(), acc.finish());
    }
    Ok(Some(VecDeque::from(vec![row])))
}

/// The bare label-scan leaf at the bottom of a 3b shape, resolved to `(scan_var, label)` — the same two
/// scan leaves the Slice-3a aggregate tier accepts. Returns `None` for any other op (⇒ the tier
/// declines, serial path).
fn morsel_label_scan_leaf(op: &PhysicalOp) -> Option<(&str, &str)> {
    match op {
        PhysicalOp::NodeByLabelScan { variable, label }
        | PhysicalOp::TokenLookupScan {
            variable, label, ..
        } => Some((&variable.name, &label.name)),
        _ => None,
    }
}

/// The recognized Slice-3b shape (`rmp` task #339): a bare `MATCH (n:Label) [WHERE <pure>] RETURN
/// <per-row projection> [ORDER BY <pure keys> [LIMIT n]]`, decomposed into the pieces the morsel tier
/// drives. Lifetimes borrow the plan (no clone of the AST).
struct MorselScanFilterShape<'p> {
    /// The scanned node variable.
    scan_var: &'p str,
    /// The scanned label name.
    label: &'p str,
    /// The residual `WHERE` predicate (pure per-row), or `None` for an unfiltered scan.
    filter: Option<&'p Expr>,
    /// The per-row projection columns.
    projection: &'p [ProjectionColumn],
    /// The `ORDER BY` keys (pure per-row, computed against the projected row), or empty (no sort).
    sort_keys: &'p [SortKey],
    /// The `TopN` row cap (a fused `ORDER BY … LIMIT n`), already evaluated, or `None`.
    top_n: Option<usize>,
}

/// Recognizes the Slice-3b morsel scan→filter→project shape over `op` (`rmp` task #339), with optional
/// `sort_keys` / `top_n` supplied by a `Sort` / `TopN` parent. Returns the decomposed shape, or `None`
/// to decline (⇒ the caller runs the serial pipeline verbatim).
///
/// The accepted op is `Projection { items, distinct: false, input: <Filter? over a bare label scan> }`.
/// Every recognized expression — the residual filter, every projection column, and every sort key — must
/// be **pure per-row** ([`crate::morsel::is_pure_per_row_expr`]): no aggregates, subqueries,
/// comprehensions, quantifiers, or function calls. That purity is what makes the contiguous concat (no
/// sort) / stable k-way merge (sort) provably byte-identical to the serial pipeline. A `DISTINCT`
/// projection is declined (it collapses rows cross-row; the contiguous concat cannot prove the dedup
/// identical).
fn recognize_morsel_scan_filter<'p>(
    op: &'p PhysicalOp,
    sort_keys: &'p [SortKey],
    top_n: Option<usize>,
) -> Option<MorselScanFilterShape<'p>> {
    // The op must be a non-DISTINCT projection (DISTINCT is a cross-row collapse — decline).
    let PhysicalOp::Projection {
        input,
        items,
        distinct: false,
    } = op
    else {
        return None;
    };

    // The projection's input is either a residual Filter over a bare label scan, or a bare label scan.
    let (filter, scan_op): (Option<&Expr>, &PhysicalOp) = match input.as_ref() {
        PhysicalOp::Filter {
            input: scan,
            predicate,
        } => (Some(predicate), scan.as_ref()),
        other => (None, other),
    };
    let (scan_var, label) = morsel_label_scan_leaf(scan_op)?;

    // Every projection column, the residual filter, and every sort key must be PURE per-row (no
    // aggregates / subqueries / comprehensions / quantifiers / function calls) — else the contiguous
    // concat / stable merge cannot be proven order-identical to serial, so decline.
    if !items
        .iter()
        .all(|c| crate::morsel::is_pure_per_row_expr(&c.expr))
    {
        return None;
    }
    if let Some(pred) = filter {
        if !crate::morsel::is_pure_per_row_expr(pred) {
            return None;
        }
    }
    if !sort_keys
        .iter()
        .all(|k| crate::morsel::is_pure_per_row_expr(&k.expr))
    {
        return None;
    }

    Some(MorselScanFilterShape {
        scan_var,
        label,
        filter,
        projection: items,
        sort_keys,
        top_n,
    })
}

/// If `op` (a `Projection`, or the `Projection` directly under a `Sort` / `TopN`) is the
/// **morsel-parallel-eligible** scan→filter→project shape — a large bare `MATCH (n:Label) [WHERE <pure>]
/// RETURN <per-row projection> [ORDER BY <pure keys> [LIMIT n]]`, with the morsel knob enabled and the
/// seam able to hand off an off-thread read bundle — reads the label scan across **contiguous morsels
/// concurrently** on the dedicated morsel pool (each morsel filtering + projecting on a `Send`
/// [`ReadOnlyGraph`](crate::read_only_graph::ReadOnlyGraph) over a cheap-cloned read view, `rmp` task
/// #339, Slice 3b), converges the rows **row-order-identically to serial**, and returns them. Otherwise
/// returns `None` so the caller runs the serial pipeline verbatim.
///
/// # Row-order-identical to serial, by construction
///
/// * **No ORDER BY (contiguous concat)** — each morsel reads a *contiguous* candidate slice and
///   `filter_label_candidates` preserves input order, so concatenating the morsels' projected rows in
///   ascending source-index (`lo`) order reproduces the serial scan→filter→project candidate order
///   exactly, **independent of the worker count** (the AC's determinism).
/// * **ORDER BY / TopN (stable k-way merge)** — each morsel stably sorts its rows by the keys (ties
///   keeping candidate order); a stable k-way merge over the per-morsel runs (same total order as serial
///   `sort_rows`' `compare_sort_keys`, ties broken by ascending-`lo` = the serial candidate order)
///   reproduces the serial stable `sort_by` byte-for-byte, and `top_n` truncates to the first `n` rows
///   identically to serial's `truncate(n)`.
/// * **Same values, visibility, SSI markers** — every morsel reads through the identical lifted read body
///   over an MVCC-superset-safe `StoreReadView` and evaluates the filter / projection / sort keys with
///   the identical [`eval`], so the `(node → row)` mapping and three-valued filter decisions match the
///   serial path; the coarse `PredicateRead::Label` + all-live-nodes footprint is registered on the
///   engine thread by the seam, and each morsel's per-candidate + per-row-read markers are folded back
///   via `merge_morsel_buffer` (sort + dedup ⇒ union = the serial marker set).
///
/// # Eligibility (ALL required, else `None`)
///
/// - the morsel knob is enabled: [`Ctx::morsel_threads`] `> 1`;
/// - the shape is [`recognize_morsel_scan_filter`]: a non-DISTINCT projection over a (filtered) bare
///   label scan, every filter / projection / sort-key expression **pure per-row**;
/// - the estimated label cardinality is at least [`MORSEL_MIN_ROWS`](crate::morsel::MORSEL_MIN_ROWS)
///   (via `statistics().nodes_with_label`; no statistics ⇒ decline);
/// - the seam returns `Some` from [`GraphAccess::morsel_label_scan`] (it declines for a restricted
///   principal, a standalone / historical read, and `MemGraph`).
///
/// On any per-morsel error the tier discards every morsel's rows **and** buffers and returns `None`; the
/// serial fallback re-runs the pipeline, re-registering the markers and re-raising the identical error.
fn try_morsel_scan_filter_project(
    op: &PhysicalOp,
    sort_keys: &[SortKey],
    top_n: Option<usize>,
    ctx: &mut Ctx<'_>,
) -> Result<Option<VecDeque<Row>>, ExecError> {
    // --- cheap gate first (no seam work): the morsel knob must be enabled (>= 2 workers) ---
    if ctx.morsel_threads <= 1 {
        return Ok(None);
    }

    // --- recognize exactly the scan→filter→project (+ optional ORDER BY / TopN) shape ---
    let shape = match recognize_morsel_scan_filter(op, sort_keys, top_n) {
        Some(s) => s,
        None => return Ok(None),
    };

    // --- the size gate: the label scan's estimated cardinality (the work being parallelized) ---
    let estimated_input = match ctx
        .graph
        .statistics()
        .and_then(|s| s.nodes_with_label(shape.label))
    {
        Some(count) => count as f64,
        None => return Ok(None),
    };
    if !estimated_input.is_finite() || estimated_input < crate::morsel::morsel_min_rows() {
        return Ok(None);
    }

    // --- the engine-thread seam: capture the candidate vector + off-thread read surface (registers the
    // identical coarse SSI markers). `None` ⇒ standalone / historical / restricted-RBAC / MemGraph ⇒
    // fall through to the serial pipeline, which runs verbatim. ---
    let Some(mut scan) = ctx.graph.morsel_label_scan(shape.label) else {
        return Ok(None);
    };
    // Install the per-statement wall-clock budget (`rmp` #476) on the parallel workers, so a runaway
    // scan→filter→project abandons rather than pinning every core; the serial fallback surfaces `Cancelled`.
    scan.deadline = ctx.token.deadline();

    // Cancellation (flag and an already-elapsed deadline) is polled once up front; each worker then polls
    // the deadline again at a strided cadence while it runs (`rmp` #476).
    ctx.check_cancelled()?;

    // --- read + filter + project the morsels concurrently, converging row-order-identically to serial ---
    let converged = crate::morsel::run_scan_filter_morsels(
        &scan,
        shape.scan_var,
        shape.filter,
        shape.projection,
        shape.sort_keys,
        shape.top_n,
        ctx.params,
        ctx.morsel_threads,
    );

    // If any morsel hit a storage / evaluation error, the parallel result is untrustworthy: decline
    // WITHOUT folding the buffers (`converged.buffers` are dropped here). The serial fallback re-reads +
    // re-evaluates through the live seam, re-registering the identical markers AND re-raising the
    // identical error so the statement behaves exactly as if the morsel path had never run.
    if converged.error.is_some() {
        return Ok(None);
    }

    // Every gate passed and the read succeeded: record the engagement (observability), then converge the
    // per-morsel SSI buffers. From here we are committed to the parallel result.
    ctx.graph.note_parallel_aggregate();

    // --- converge the per-morsel SIREAD buffers into the statement's shared SSI tracker (engine thread,
    // before commit — rule M1). The merge sorts + dedups + replays, so the conflict graph is the union =
    // the serial pipeline's marker set. ---
    for buffer in converged.buffers {
        ctx.graph.merge_morsel_buffer(buffer);
    }

    Ok(Some(VecDeque::from(converged.rows)))
}

/// The recognized Slice-3c **traversal** shape (`rmp` task #339, the final slice): a bare
/// `MATCH (a:Label)-[r(:T…)?]->(b)` whose heavy work is the per-anchor single-hop `ExpandAll`, with one
/// of two post-works above — `RETURN count(b) | count(*)` (the degree shape) or
/// `RETURN <pure per-row projection of a/r/b>` (the neighbour-collect shape). Borrows the plan (no AST
/// clone) so it can hand the borrowed expand pieces straight into a `MorselExpandPlan`.
struct MorselExpandShape<'p> {
    /// The scanned anchor label name.
    label: &'p str,
    /// The expand pattern pieces (mirrors the serial `Operator::Expand` plan).
    from: &'p Var,
    relationship: &'p Var,
    to: &'p Var,
    direction: RelDirection,
    types: &'p [RelType],
}

/// Recognizes a Slice-3c **fixed-length, fresh single-hop** `ExpandAll` over a bare label scan, the
/// substrate both the degree and rows-over-expand tiers stand on (`rmp` task #339). Returns the expand
/// pieces (the anchor's label, the `from`/`relationship`/`to` vars, direction, rel-types), or `None`
/// to decline (⇒ the caller runs the serial pipeline verbatim).
///
/// The accepted op is `ExpandAll { input: <bare label scan>, range: None, prior_rels: [], rel_props:
/// None, .. }` whose `from` IS the scanned variable — i.e. exactly the
/// [`expand_into_pending`](crate::executor) shape with the anchor produced by the scan. **Declines**
/// (so serial handles them correctly):
///
/// * `ExpandInto` (both endpoints bound — a connection check, not an anchor fan-out): not matched here
///   (only `ExpandAll`);
/// * a **variable-length** hop (`range: Some`) — the trail-DFS order / `collect` semantics the
///   contiguous concat cannot prove identical;
/// * a hop with **prior-pattern** relationships (`prior_rels` non-empty) or an **already-bound**
///   relationship variable on the input — only a bare label-scan input is the recognized anchor source,
///   so neither can arise here, but they are excluded defensively;
/// * an **inline relationship-property map** (`rel_props: Some`) — only a var-length hop carries one;
///   excluded defensively.
fn recognize_morsel_expand(op: &PhysicalOp) -> Option<MorselExpandShape<'_>> {
    let PhysicalOp::ExpandAll {
        input,
        from,
        relationship,
        to,
        direction,
        types,
        range,
        prior_rels,
        rel_props,
    } = op
    else {
        return None;
    };
    // Fixed-length, fresh single hop only (the `expand_into_pending` shape). Anything else → serial.
    if range.is_some() || !prior_rels.is_empty() || rel_props.is_some() {
        return None;
    }
    // The input must be a bare label scan, and its scanned variable must be this expand's anchor (`from`).
    let (scan_var, label) = morsel_label_scan_leaf(input.as_ref())?;
    if scan_var != from.name {
        return None;
    }
    Some(MorselExpandShape {
        label,
        from,
        relationship,
        to,
        direction: *direction,
        types,
    })
}

/// Whether the aggregate column `expr` is exactly `count(*)` or `count(<to_var>)` — the **degree**
/// over an `ExpandAll`'s far-endpoint variable (`rmp` task #339, Slice 3c). Both count one row per
/// produced expansion side; since a single-hop `ExpandAll` binds `to` to a real node on **every**
/// produced row, `count(to)` (non-null count) equals `count(*)` (row count) equals the matching degree,
/// so both map to the morsel's `partial_count` identically. Any `DISTINCT`, surrounding arithmetic, a
/// different argument, or a non-`count` aggregate yields `false` (⇒ decline, serial handles it).
fn is_expand_degree_count(expr: &Expr, to_var: &str) -> bool {
    match &expr.kind {
        ExprKind::CountStar => true,
        ExprKind::FunctionCall {
            name,
            distinct: false,
            args,
        } => {
            // `rmp` #371: avoid the `String` join for the single-segment fast path (`count(..)`).
            let is_count = match name.as_slice() {
                [single] => single.eq_ignore_ascii_case("count"),
                _ => name.join(".").eq_ignore_ascii_case("count"),
            };
            if !is_count {
                return false;
            }
            let [arg] = args.as_slice() else {
                return false;
            };
            matches!(&arg.kind, ExprKind::Variable(v) if v == to_var)
        }
        _ => false,
    }
}

/// If `input` (the input of an `Aggregation`) is the **morsel-parallel-eligible degree shape** — a large
/// bare `MATCH (a:Label)-[r(:T…)?]->(b) RETURN count(b) | count(*)`, single group, with the morsel knob
/// enabled and the seam able to hand off an off-thread read bundle — partitions the **anchors** into
/// contiguous morsels, expands each anchor's single hop **concurrently** on the dedicated morsel pool
/// (each over a `Send` [`ReadOnlyGraph`], `rmp` task #339, Slice 3c — the final slice), **sums** the
/// per-anchor matching degrees (an order-independent combine), and returns the single count row.
/// Otherwise returns `None` so the caller runs the serial pipeline verbatim.
///
/// # Identical to serial, by construction
///
/// * Each morsel expands a *contiguous* anchor slice through the **same** lifted `read_source::expand`
///   body the serial `Operator::Expand` runs (over a `ReadOnlyGraph`), reproducing the serial
///   self-loop-dedup (per anchor, by relationship id) + direction + type filtering EXACTLY, so the
///   per-anchor degree is the serial degree; summing the morsels' degrees is associative ⇒ the total
///   equals serial `count(*)` / `count(b)` regardless of the worker count.
/// * The coarse `PredicateRead::Label` + all-live-nodes footprint is registered on the engine thread by
///   the seam; each morsel's per-anchor label-scan markers AND the per-anchor expand's
///   relationship-pattern predicate + per-edge markers are folded back via `merge_morsel_buffer` (sort
///   + dedup ⇒ union = the serial scan→expand marker set).
///
/// # Eligibility (ALL required, else `None`)
///
/// - the morsel knob is enabled: [`Ctx::morsel_threads`] `> 1`;
/// - single group (`group_keys` empty), exactly one aggregate column, and it is
///   [`is_expand_degree_count`] (`count(*)` / `count(to)`);
/// - the input is [`recognize_morsel_expand`]: a fixed-length, fresh single-hop `ExpandAll` over a bare
///   label scan;
/// - the estimated anchor-label cardinality is at least
///   [`MORSEL_MIN_ROWS`](crate::morsel::MORSEL_MIN_ROWS) (via `statistics().nodes_with_label`; no
///   statistics ⇒ decline);
/// - the seam returns `Some` from [`GraphAccess::morsel_label_scan`] (it declines for a restricted
///   principal — so per-relationship/endpoint RBAC is never bypassed by the off-thread expand — a
///   standalone / historical read, and `MemGraph`).
///
/// On any per-morsel error the tier discards every morsel's count + buffers and returns `None`; the
/// serial fallback re-runs the pipeline, re-registering the markers and re-raising the identical error.
fn try_morsel_expand_aggregate(
    input: &PhysicalOp,
    group_keys: &[ProjectionColumn],
    aggregates: &[ProjectionColumn],
    ctx: &mut Ctx<'_>,
) -> Result<Option<VecDeque<Row>>, ExecError> {
    // --- cheap gate first (no seam work): the morsel knob must be enabled (>= 2 workers) ---
    if ctx.morsel_threads <= 1 {
        return Ok(None);
    }

    // --- recognize the degree shape: single group, exactly one `count(*)`/`count(to)` over a fresh
    // single-hop `ExpandAll` ---
    if !group_keys.is_empty() {
        return Ok(None);
    }
    let [agg] = aggregates else {
        return Ok(None);
    };
    let Some(shape) = recognize_morsel_expand(input) else {
        return Ok(None);
    };
    if !is_expand_degree_count(&agg.expr, &shape.to.name) {
        return Ok(None);
    }

    // --- the size gate: the anchor label scan's estimated cardinality (the fan-out being parallelized) ---
    let estimated_input = match ctx
        .graph
        .statistics()
        .and_then(|s| s.nodes_with_label(shape.label))
    {
        Some(count) => count as f64,
        None => return Ok(None),
    };
    if !estimated_input.is_finite() || estimated_input < crate::morsel::morsel_min_rows() {
        return Ok(None);
    }

    // --- the engine-thread seam: capture the anchor candidate vector + off-thread read surface (registers
    // the identical coarse SSI markers). `None` ⇒ standalone / historical / restricted-RBAC / MemGraph ⇒
    // serial pipeline runs verbatim (and RBAC-composes per relationship/endpoint). ---
    let Some(mut scan) = ctx.graph.morsel_label_scan(shape.label) else {
        return Ok(None);
    };
    // Install the per-statement wall-clock budget (`rmp` #476) on the parallel workers, so a runaway
    // scan→expand (incl. a supernode's fan-out) abandons rather than pinning every core; the serial
    // fallback surfaces a clean `Cancelled`.
    scan.deadline = ctx.token.deadline();

    // Cancellation (flag and an already-elapsed deadline) is polled once up front; each worker then polls
    // the deadline again — per anchor and within a high-degree anchor's expansion — while it runs (`rmp` #476).
    ctx.check_cancelled()?;

    let plan = crate::morsel::MorselExpandPlan {
        from: shape.from,
        relationship: shape.relationship,
        to: shape.to,
        direction: shape.direction,
        types: shape.types,
        post: crate::morsel::MorselExpandPostWork::Count,
    };

    // --- expand the anchors concurrently, summing the per-anchor degrees (order-independent combine) ---
    let converged = crate::morsel::run_expand_morsels(&scan, &plan, ctx.params, ctx.morsel_threads);

    // If any morsel hit a storage error, the parallel count is untrustworthy: decline WITHOUT folding the
    // buffers (dropped here). The serial fallback re-reads + re-expands through the live seam, re-registering
    // the identical markers AND re-raising the identical error.
    if converged.error.is_some() {
        return Ok(None);
    }

    // Every gate passed and the read succeeded: record the engagement (observability), then converge the
    // per-morsel SSI buffers. From here we are committed to the parallel result.
    ctx.graph.note_parallel_aggregate();
    for buffer in converged.buffers {
        ctx.graph.merge_morsel_buffer(buffer);
    }

    // The single count row: bind the summed degree to the aggregate column's alias.
    let mut row = Row::empty();
    row.set(
        agg.alias.clone(),
        RowValue::Value(Value::Integer(converged.count)),
    );
    Ok(Some(VecDeque::from(vec![row])))
}

/// If `op` (a `Projection`) is the **morsel-parallel-eligible neighbour-collect shape** — a large bare
/// `MATCH (a:Label)-[r(:T…)?]->(b) RETURN <pure per-row projection of a/r/b>` (non-DISTINCT), with the
/// morsel knob enabled and the seam able to hand off an off-thread read bundle — partitions the
/// **anchors** into contiguous morsels, expands + projects each anchor's single hop **concurrently** on
/// the dedicated morsel pool (each over a `Send` [`ReadOnlyGraph`], `rmp` task #339, Slice 3c),
/// converges the rows **row-order-identically to serial** (contiguous concat in ascending anchor →
/// per-anchor expansion order), and returns them. Otherwise returns `None` so the caller runs serial
/// verbatim.
///
/// # Row-order-identical to serial, by construction
///
/// Each morsel expands a *contiguous* anchor slice in serial anchor order, and per anchor produces the
/// expansion rows in the serial `Operator::Expand` order (incidence-chain order, self-loops deduplicated
/// per anchor by relationship id), so concatenating the morsels' rows in ascending source-index (`lo`)
/// order reproduces the serial scan→expand→project row sequence exactly — **independent of the worker
/// count** (the AC's determinism). Values + visibility + SSI markers match because the morsel reads
/// through the identical lifted `read_source::expand` / property-read body and evaluates the projection
/// with the identical [`eval`]; the coarse predicate footprint is registered on the engine thread by the
/// seam, and each morsel's markers are folded back via `merge_morsel_buffer` (union = the serial set).
///
/// # Eligibility (ALL required, else `None`)
///
/// - the morsel knob is enabled: [`Ctx::morsel_threads`] `> 1`;
/// - `op` is a non-DISTINCT `Projection` whose every column is **pure per-row**
///   ([`crate::morsel::is_pure_per_row_expr`]) over an [`recognize_morsel_expand`] fixed-length fresh
///   single-hop `ExpandAll` over a bare label scan;
/// - the estimated anchor-label cardinality is at least
///   [`MORSEL_MIN_ROWS`](crate::morsel::MORSEL_MIN_ROWS) (no statistics ⇒ decline);
/// - the seam returns `Some` from [`GraphAccess::morsel_label_scan`] (declines for a restricted principal,
///   a standalone / historical read, and `MemGraph`).
///
/// On any per-morsel error the tier discards every morsel's rows + buffers and returns `None`; the serial
/// fallback re-runs the pipeline, re-registering the markers and re-raising the identical error.
fn try_morsel_expand_project(
    op: &PhysicalOp,
    ctx: &mut Ctx<'_>,
) -> Result<Option<VecDeque<Row>>, ExecError> {
    // --- cheap gate first (no seam work): the morsel knob must be enabled (>= 2 workers) ---
    if ctx.morsel_threads <= 1 {
        return Ok(None);
    }

    // --- recognize: a non-DISTINCT projection (pure per-row columns) directly over a fresh single-hop
    // `ExpandAll` over a bare label scan ---
    let PhysicalOp::Projection {
        input,
        items,
        distinct: false,
    } = op
    else {
        return Ok(None);
    };
    let Some(shape) = recognize_morsel_expand(input.as_ref()) else {
        return Ok(None);
    };
    // Every projection column must be PURE per-row (no aggregates / subqueries / comprehensions /
    // quantifiers / function calls) — else the contiguous concat cannot be proven order-identical to
    // serial, so decline.
    if !items
        .iter()
        .all(|c| crate::morsel::is_pure_per_row_expr(&c.expr))
    {
        return Ok(None);
    }

    // --- the size gate: the anchor label scan's estimated cardinality (the fan-out being parallelized) ---
    let estimated_input = match ctx
        .graph
        .statistics()
        .and_then(|s| s.nodes_with_label(shape.label))
    {
        Some(count) => count as f64,
        None => return Ok(None),
    };
    if !estimated_input.is_finite() || estimated_input < crate::morsel::morsel_min_rows() {
        return Ok(None);
    }

    // --- the engine-thread seam: capture the anchor candidate vector + off-thread read surface ---
    let Some(mut scan) = ctx.graph.morsel_label_scan(shape.label) else {
        return Ok(None);
    };
    // Install the per-statement wall-clock budget (`rmp` #476) on the parallel workers, so a runaway
    // scan→expand→project abandons rather than pinning every core; the serial fallback surfaces `Cancelled`.
    scan.deadline = ctx.token.deadline();

    ctx.check_cancelled()?;

    let plan = crate::morsel::MorselExpandPlan {
        from: shape.from,
        relationship: shape.relationship,
        to: shape.to,
        direction: shape.direction,
        types: shape.types,
        post: crate::morsel::MorselExpandPostWork::Project(items),
    };

    // --- expand + project the anchors concurrently, converging row-order-identically to serial ---
    let converged = crate::morsel::run_expand_morsels(&scan, &plan, ctx.params, ctx.morsel_threads);

    if converged.error.is_some() {
        return Ok(None);
    }

    ctx.graph.note_parallel_aggregate();
    for buffer in converged.buffers {
        ctx.graph.merge_morsel_buffer(buffer);
    }

    Ok(Some(VecDeque::from(converged.rows)))
}

/// The sole property name an aggregate column references on `scan_var`, if the column is a bare
/// single-argument aggregate over `scan_var.<property>` (`rmp` #330). `count(*)` and any non-bare /
/// multi-property column yield `None` (no single property constraint from this column).
fn sole_aggregate_property(expr: &Expr, scan_var: &str) -> Option<String> {
    let ExprKind::FunctionCall { args, .. } = &expr.kind else {
        return None;
    };
    let [arg] = args.as_slice() else {
        return None;
    };
    match &arg.kind {
        ExprKind::Property { base, key } if matches!(&base.kind, ExprKind::Variable(v) if v == scan_var) => {
            Some(key.clone())
        }
        _ => None,
    }
}

/// The SipHash digest of a group-key tuple (`rmp` #314 grouping index, shared with the `rmp` #360 grouped
/// morsel tier). `std`'s `DefaultHasher` is SipHash-1-3 with a per-process random seed, which is
/// **DoS-resistant** over the client-derived property values that make up a group key (SEC-210 /
/// CWE-407): the grouped morsel tier MUST use this exact digest — never a fixed-seed `FxHasher` over the
/// raw key values — both to stay byte-identical to the serial group index AND to keep the hash-flooding
/// resistance. The length is mixed in first (so `[a]` and `[a, b]` cannot collide trivially), then each
/// element via [`hash_row_value`] (consistent with [`row_values_equivalent`]); a bucket collision still
/// falls back to the exact equivalence check, so grouping semantics are unchanged.
pub(crate) fn group_key_hash(key_vals: &[RowValue]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key_vals.len().hash(&mut h);
    for kv in key_vals {
        hash_row_value(kv, &mut h);
    }
    h.finish()
}

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
    // Hash index over `groups`: key-tuple hash → indices of groups whose key hashes there. Replaces
    // the former O(groups) linear `position` scan per input row, which made grouping O(rows×groups)
    // — e.g. 996k LIKE rows × 30k article groups ≈ 10^10 comparisons on the audited `top_liked`
    // (`rmp` #314). The hash is `hash_row_value` (consistent with `row_values_equivalent`); a bucket
    // collision still falls back to the exact equivalence check, so grouping semantics are
    // unchanged. Groups stay in first-seen order (output order is preserved).
    //
    // `rmp` #371: the index is keyed on the `group_key_hash` `u64` digest, which is ALREADY a
    // DoS-resistant SipHash output (SEC-210 / CWE-407) — re-hashing it under `std`'s SipHash is pure
    // waste, so the outer map uses `FxHasher` (`FxHashMap`). Only the digest computation stays SipHash;
    // bucketing the digest with a fast fixed-seed hasher is safe and faster.
    let mut index: rustc_hash::FxHashMap<u64, Vec<usize>> = rustc_hash::FxHashMap::default();

    while let Some(row) = inner.next(ctx)? {
        ctx.check_cancelled()?;
        // Compute the group key.
        let mut key_vals = Vec::with_capacity(group_keys.len());
        for col in group_keys {
            key_vals.push(eval(
                &col.expr,
                &row,
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?);
        }
        // Hash the whole key tuple, then resolve within the (normally singleton) bucket by exact
        // equivalence. The hash is the shared [`group_key_hash`] — the SAME digest the `rmp` #360 grouped
        // morsel tier keys its local tables on, so serial and parallel group identically.
        let key_hash = group_key_hash(&key_vals);
        let bucket = index.entry(key_hash).or_default();
        let found = bucket.iter().copied().find(|&gi| {
            let g = &groups[gi];
            g.keys.len() == key_vals.len()
                && g.keys
                    .iter()
                    .zip(&key_vals)
                    .all(|(x, y)| row_values_equivalent(x, y))
        });
        let idx = match found {
            Some(i) => i,
            None => {
                let gi = groups.len();
                groups.push(Group {
                    keys: key_vals.clone(),
                    accs: new_accs(&plans),
                    representative: row.clone(),
                });
                bucket.push(gi);
                gi
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
        //
        // `rmp` #371: the representative input row is NOT dead and MUST stay. An aggregate-containing
        // projection item may, outside its aggregate calls, reference the projection's *simple grouping
        // keys*, which `semantics.rs` (`GroupingKeys::simple`, the `check_aggregate_item_references`
        // rule at `semantics.rs` ~1318) defines as a bare variable OR a **variable-rooted property
        // path** — e.g. `RETURN n.name, n.name + count(*)` is valid, and the outer expression
        // `n.name + <agg>` reads the raw input variable `n` (rooting `n.name`), not the key *alias*.
        // Those raw input bindings come only from the representative row; building `eval_row` fresh
        // would make such property paths evaluate to null and diverge from the TCK. (Materializing only
        // the key *columns* would not help — the outer expr reads the raw variable, not the alias.)
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
            let value = eval(
                &plan.outer,
                &eval_row,
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?;
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
///
/// The `rmp` #360 morsel-parallel grouped-aggregation tier ([`crate::morsel`]) builds per-morsel local
/// group tables of the **same** accumulator type the serial `aggregate_rows` uses, then merges them via
/// `combine` — so the parallel result is byte-identical to serial by construction (same fold arithmetic,
/// same associative combine). The type is `pub` only so it can appear in the `pub`
/// grouped-morsel result types ([`crate::morsel::MorselGroupOutcome`] / [`crate::morsel::MergedGroup`])
/// that the crate's integration tests drive; its fields are private and every method is `pub(crate)`, so
/// it cannot be constructed or used outside the crate (no usable public surface beyond the name).
pub struct Accumulator {
    kind: AggKind,
    distinct: bool,
    count: i64,
    seen: Vec<RowValue>, // distinct-set: RowValue-typed so entity references dedupe by identity
    sum: f64,
    sum_is_int: bool,
    int_sum: i64,
    /// `true` once any integer `sum` step (a fold or a [`combine`](Self::combine)) clamped `int_sum` to
    /// the `i64` rail (`rmp` #360, finding C). `saturating_add` is **non-associative** once it clamps, so a
    /// parallel `sum` whose witness is set here is NOT bit-identical to the serial left fold — the grouped
    /// morsel tier ([`sum_is_parallel_unsafe`](Self::sum_is_parallel_unsafe)) detects this and falls back
    /// to serial. The serial path never reads this flag (its single left fold is the source of truth).
    int_sum_saturated: bool,
    extreme: Option<Value>,
    // RowValue-typed so `collect(n)` / `collect(nodes(p))` keep their structural elements.
    collected: Vec<RowValue>,
    /// The running estimated in-memory byte size of [`collected`](Self::collected) (`SEC-191`,
    /// CWE-770 / CWE-789). Maintained incrementally — each push adds only the appended element's
    /// estimate, so it is amortised `O(1)` and never re-walks the accumulated list. The serial fold
    /// rejects with [`EvalError::ResourceLimit`] the instant this crosses
    /// [`MAX_VALUE_BYTES`](crate::value_size::MAX_VALUE_BYTES); the parallel grouped tier
    /// ([`combine`](Self::combine)) keeps it summed across merged partitions so the engine thread can
    /// detect a merged `collect` that crossed the budget and decline to the serial path (which raises
    /// the identical error). Non-`collect` kinds leave it at `0`.
    collected_bytes: usize,
    // `percentileCont`/`percentileDisc`: every numeric input value, kept as `(sort_key, original)`
    // so the result can preserve the source numeric subtype (`percentileDisc` returns a real value
    // of the set) while sorting on the `f64` key. The percentile (`args[1]`) is captured and
    // range-validated on the first contributing row, matching Neo4j's `onFirstRow` semantics.
    numeric: Vec<(f64, Value)>,
    percentile: Option<f64>,
}

/// The aggregate function an [`Accumulator`] computes. `pub` (matching [`Accumulator`]) only so it can
/// appear transitively in the `pub` grouped-morsel result types; its variants are `pub(crate)`-relevant
/// only (the recognizer + local fold in [`crate::morsel`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AggKind {
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
    /// `pub(crate)` so the `rmp` #360 grouped morsel tier builds a per-column local accumulator from the
    /// **same** column expression the serial path compiles, guaranteeing identical kind/`distinct`.
    pub(crate) fn new(expr: &Expr) -> Self {
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
        Self::zeroed(kind, distinct)
    }

    /// Builds a fresh, zeroed accumulator of `kind` (non-distinct) — the vectorized fast path's
    /// constructor (`rmp` #330), which already knows the [`AggKind`] from the recognizer and so needs
    /// no `Expr` to classify. Shares the exact zero-init [`new`](Self::new) uses, so a vectorized
    /// accumulator and a Volcano one of the same kind are identical state.
    fn for_kind(kind: AggKind) -> Self {
        Self::zeroed(kind, false)
    }

    /// The shared zero-initialised accumulator state for `kind` / `distinct`.
    fn zeroed(kind: AggKind, distinct: bool) -> Self {
        Self {
            kind,
            distinct,
            count: 0,
            seen: Vec::new(),
            sum: 0.0,
            sum_is_int: true,
            int_sum: 0,
            int_sum_saturated: false,
            extreme: None,
            collected: Vec::new(),
            collected_bytes: 0,
            numeric: Vec::new(),
            percentile: None,
        }
    }

    /// Appends `rv` to the `collect` buffer, growing the running byte estimate
    /// ([`collected_bytes`](Self::collected_bytes)) and **rejecting before the push** if the
    /// accumulated list would exceed the per-value budget
    /// ([`MAX_VALUE_BYTES`](crate::value_size::MAX_VALUE_BYTES)) — the `collect`-side memory-DoS guard
    /// (`SEC-191`, CWE-770 / CWE-789). Walks only the appended element (amortised `O(1)`).
    ///
    /// # Errors
    /// [`EvalError::ResourceLimit`] (as [`ExecError::Eval`]) once the buffer would cross the budget.
    fn push_collected(&mut self, rv: RowValue) -> Result<(), ExecError> {
        let next = self
            .collected_bytes
            .saturating_add(crate::value_size::estimate_rowvalue_bytes(&rv));
        let limit = crate::value_size::max_value_bytes();
        if next > limit {
            return Err(ExecError::Eval(EvalError::ResourceLimit {
                detail: format!("collected list exceeds the {limit}-byte value limit"),
            }));
        }
        self.collected_bytes = next;
        self.collected.push(rv);
        Ok(())
    }

    /// The running estimated byte size of the `collect` buffer (`SEC-191`). The `rmp` #360 grouped
    /// morsel tier reads this on the engine thread after merging a group's partitions: a merged
    /// `collect` whose estimate crosses [`MAX_VALUE_BYTES`](crate::value_size::MAX_VALUE_BYTES) makes
    /// the tier decline to the serial path, which re-folds and raises the identical
    /// [`EvalError::ResourceLimit`].
    #[must_use]
    pub(crate) fn collected_bytes(&self) -> usize {
        self.collected_bytes
    }

    /// Saturating-adds `delta` into `int_sum`, recording in [`int_sum_saturated`](Self::int_sum_saturated)
    /// whether the add clamped to the `i64` rail (`rmp` #360, finding C) — the witness the grouped morsel
    /// tier consults to reject a non-associative parallel `sum`. Used by every integer-`sum` fold/combine
    /// site so the witness is complete.
    #[inline]
    fn add_int_sum(&mut self, delta: i64) {
        if self.int_sum.checked_add(delta).is_none() {
            self.int_sum_saturated = true;
        }
        self.int_sum = self.int_sum.saturating_add(delta);
    }

    /// Whether this is a `sum` accumulator whose value was computed in a way that a parallel
    /// partition-merge could NOT reproduce bit-identically to the serial left fold (`rmp` #360, finding C):
    /// a **float** was seen (`!sum_is_int` — float `+` is non-associative) OR an integer step **saturated**
    /// (`saturating_add` clamps order-dependently once any subtree hits the rail). The grouped morsel tier
    /// checks every merged accumulator; if any returns `true` it discards the parallel result and folds the
    /// column serially. Non-`sum` kinds always return `false` (they are associative / order-preserving).
    pub(crate) fn sum_is_parallel_unsafe(&self) -> bool {
        self.kind == AggKind::Sum && (!self.sum_is_int || self.int_sum_saturated)
    }

    /// Folds one **bare property value** directly into the accumulator — the vectorized fast path's
    /// per-value step (`rmp` #330), used by [`try_vectorized_label_property_aggregate`] when the value
    /// comes straight from the columnar scan rather than from evaluating an expression over a row.
    ///
    /// This is **arithmetically identical** to the relevant arms of [`update`](Self::update): a null
    /// value is ignored (Cypher `count`/`sum`/`avg`/`min`/`max` skip nulls), and the numeric / extreme
    /// folds use the very same `int_sum`/`sum`/`sum_is_int`/`extreme` updates, so a finish produces
    /// byte-identical results to the Volcano path. It only handles the kinds the vectorized recognizer
    /// admits (`Count`/`Sum`/`Avg`/`Min`/`Max`); any other kind is a recognizer bug and is a no-op.
    ///
    /// # Errors
    /// [`EvalError::TypeError`] if a `sum`/`avg` value is non-numeric — the same error `update` raises.
    fn fold_value(&mut self, value: &Value) -> Result<(), ExecError> {
        // Nulls are ignored by every aggregate here (the columnar scan never yields a null value, but
        // this keeps the contract identical to `update` defensively).
        if value.is_null() {
            return Ok(());
        }
        match self.kind {
            AggKind::Count => self.count += 1,
            AggKind::Sum | AggKind::Avg => {
                self.count += 1;
                match value {
                    Value::Integer(i) => {
                        self.add_int_sum(*i);
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
            AggKind::Min | AggKind::Max => {
                let want_min = self.kind == AggKind::Min;
                let replace = self.extreme.as_ref().is_none_or(|e| {
                    let ord = cmp_values(value, e);
                    if want_min { ord.is_lt() } else { ord.is_gt() }
                });
                if replace {
                    self.extreme = Some(value.clone());
                }
            }
            // The vectorized recognizer never builds an accumulator of another kind for a value fold.
            _ => {}
        }
        Ok(())
    }

    /// Sets the `count(*)` total directly (`rmp` #330): the vectorized path knows the matched-node
    /// count up front (from [`ColumnarScan::label_matches`](crate::graph_access::ColumnarScan)), so it
    /// assigns it rather than incrementing per row. Identical to `count += 1` per matched node.
    fn set_count_star(&mut self, total: i64) {
        self.count = total;
    }

    /// Merges another partial accumulator `other` of the **same exact aggregate kind** into `self`
    /// (`rmp` task #352): the associative-and-commutative combine step of the parallel label-property
    /// fold. `self` and `other` must both come from [`Accumulator::for_kind`] over the same
    /// [`AggKind`], folded over disjoint partitions of the same column; the merged accumulator is then
    /// identical to one folded serially over the concatenation, regardless of how the partitions were
    /// split or ordered.
    ///
    /// Only the kinds the parallel tier admits are merged precisely — `Count` (and `CountStar`, whose
    /// count is assigned after the reduce), integer `Sum`, `Min`, `Max`, and `Collect` (`rmp` #360
    /// extends the merge to `collect`/`collect(DISTINCT)` by list-concat / order-preserving set-union).
    /// Every field those kinds touch in [`fold_value`](Self::fold_value) / [`fold_rowvalue`](Self::fold_rowvalue)
    /// is combined here: the row `count`, the integer/float sum witnesses, the running extreme (via the
    /// same [`cmp_values`] ordering the folds use, so the tie-break is identical), and — for `rmp` #360 —
    /// the `collect` buffer and the `DISTINCT` set.
    ///
    /// `pub(crate)` so the `rmp` #360 grouped morsel tier merges per-morsel partial groups on the engine
    /// thread. **Ordering contract (for the `rmp` #360 grouped tier):** for the order-sensitive kinds
    /// (`Collect`, and the `DISTINCT` first-encounter set) the combine appends `other` AFTER `self`, so
    /// the engine thread MUST call `self.combine(other)` with the morsels in **ascending source order**
    /// (`self` = the lower-`lo` partition) to reproduce the serial scan-order encounter sequence. The
    /// associative-and-commutative kinds (`Count`/`Sum`/`Min`/`Max`) are order-independent.
    pub(crate) fn combine(&mut self, other: Accumulator) {
        // --- DISTINCT kinds (`rmp` #360): a value seen in BOTH partitions must be counted/collected
        // ONCE, so re-apply `self`'s cross-partition dedup over `other`'s kept-distinct elements rather
        // than blindly adding counts. `other`'s distinct elements, in `other`'s first-encounter order,
        // are exactly `other.seen` (every push to `seen`/`collected` for a distinct accumulator is gated
        // by the same dedup, so `seen` IS the kept set in encounter order). Replaying them through the
        // same `seen`-membership + `count`/`collected` updates the per-row fold uses makes the merged
        // accumulator identical to a single serial fold over the concatenation. The caller drives
        // `self.combine(other)` in ascending-source order, so `other` (the later partition) appends after
        // `self` — reproducing the serial scan-order first-encounter sequence. ---
        if self.distinct {
            for v in &other.seen {
                if self.seen.iter().any(|s| row_values_equivalent(s, v)) {
                    continue; // already counted in an earlier (lower-`lo`) partition
                }
                self.seen.push(v.clone());
                match self.kind {
                    AggKind::Count => self.count += 1,
                    AggKind::Collect => {
                        // Track the running byte estimate (`SEC-191`) so the engine thread can detect a
                        // merged DISTINCT `collect` that crossed the budget; `combine` is infallible, so
                        // it accounts the bytes here and the merge site enforces the cap (declining to
                        // serial, which re-raises the typed error).
                        self.collected_bytes = self
                            .collected_bytes
                            .saturating_add(crate::value_size::estimate_rowvalue_bytes(v));
                        self.collected.push(v.clone());
                    }
                    // The `rmp` #360 grouped recognizer admits DISTINCT only on `count` / `collect`, so a
                    // DISTINCT merge of any other kind (sum/min/max/avg DISTINCT) never reaches here. A
                    // no-op keeps the merge total; the `debug_assert` flags a gate-widening that forgot to
                    // extend this branch.
                    other => {
                        debug_assert!(
                            matches!(other, AggKind::Count | AggKind::Collect),
                            "combine: DISTINCT merge only supports count/collect (gate is tighter)"
                        );
                    }
                }
            }
            return;
        }

        // --- non-DISTINCT kinds ---
        // Row count: additive for every kind (CountStar's is overwritten by `set_count_star` later).
        self.count += other.count;
        // Sum witnesses: additive, and the column is non-integer if *either* partition saw a float
        // (the parallel tier gates folds to all-integer columns, so `sum_is_int` stays true in
        // practice; combining it faithfully keeps the method correct if that gate ever widens). The
        // saturation witness (`rmp` #360, finding C) propagates: a clamp in EITHER partition — or one
        // introduced by combining the two sub-sums here (`add_int_sum`) — marks the result
        // parallel-unsafe, so the grouped tier falls back to serial for that column.
        self.int_sum_saturated |= other.int_sum_saturated;
        self.add_int_sum(other.int_sum);
        self.sum += other.sum;
        self.sum_is_int = self.sum_is_int && other.sum_is_int;
        // Extreme: keep the min/max across partitions, using the same comparator `fold_value` uses.
        if let Some(other_extreme) = other.extreme {
            let take_other = match (&self.extreme, self.kind) {
                (None, _) => true,
                (Some(cur), AggKind::Min) => cmp_values(&other_extreme, cur).is_lt(),
                (Some(cur), AggKind::Max) => cmp_values(&other_extreme, cur).is_gt(),
                // Any non-extreme kind never has an `extreme`; keep `self` (defensive, unreachable
                // for the admitted kinds).
                (Some(_), _) => false,
            };
            if take_other {
                self.extreme = Some(other_extreme);
            }
        }
        // `collect` (non-DISTINCT): concatenate `other`'s buffer AFTER `self`'s (`rmp` #360). The caller
        // drives the combine in ascending-source order, so the concatenation reproduces the serial
        // scan-order encounter sequence. Structural elements are preserved (RowValue-typed). The running
        // byte estimate is summed too (`SEC-191`) so the engine thread can detect a merged `collect` that
        // crossed [`MAX_VALUE_BYTES`](crate::value_size::MAX_VALUE_BYTES) and decline to the serial path.
        if self.kind == AggKind::Collect {
            self.collected_bytes = self.collected_bytes.saturating_add(other.collected_bytes);
            self.collected.extend(other.collected);
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
            ExprKind::FunctionCall { args, .. } if !args.is_empty() => eval(
                &args[0],
                row,
                ctx.params,
                ctx.graph,
                ctx.functions,
                &ctx.clock,
            )?,
            _ => RowValue::NULL,
        };
        // `percentileCont`/`percentileDisc(value, p)` is the one kind whose fold needs the second
        // argument (`args[1]`) evaluated against the input row, so it stays inline here (where `expr`
        // / `row` / `ctx` are in scope). Every other kind folds purely from the already-evaluated
        // first-argument `rv`, via the shared [`fold_rowvalue`](Self::fold_rowvalue) — the SAME
        // post-evaluation body the `rmp` #360 morsel-parallel grouped tier folds with off-thread, so
        // serial and parallel are byte-identical by construction.
        if matches!(self.kind, AggKind::PercentileCont | AggKind::PercentileDisc) {
            // count(x), sum, avg, min, max ignore nulls (Cypher); percentile drops nulls too.
            if rv.is_null() {
                return Ok(());
            }
            if self.distinct && self.seen.iter().any(|s| row_values_equivalent(s, &rv)) {
                return Ok(());
            }
            if self.distinct {
                self.seen.push(rv.clone());
            }
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
        self.fold_rowvalue(&rv)
    }

    /// Folds one input `row` into the accumulator for a **bare aggregate column** `expr`, evaluating the
    /// aggregate's single argument against an arbitrary `graph` / `functions` (`rmp` task #360) — the
    /// off-thread analogue of [`update`](Self::update) the morsel-parallel grouped tier drives over its
    /// per-morsel [`ReadOnlyGraph`](crate::read_only_graph). It is byte-identical to `update` for the
    /// kinds the grouped recognizer admits (`count(*)` / `count` / `sum` / `min` / `max` / `collect`,
    /// `DISTINCT` only on `count`/`collect`): `count(*)` increments the row count; every other kind
    /// evaluates `args[0]` as a [`RowValue`] (so a bound node/relationship counts as non-null) and folds
    /// it via the shared [`fold_rowvalue`](Self::fold_rowvalue). The percentiles are NOT admitted by the
    /// grouped recognizer (their fold needs `args[1]`), so this method does not handle them.
    ///
    /// # Errors
    /// Propagates the [`EvalError`] of the argument evaluation, or [`EvalError::TypeError`] for a
    /// non-numeric `sum` value — the identical errors `update` raises.
    pub(crate) fn fold_bare(
        &mut self,
        expr: &Expr,
        row: &Row,
        params: &BoundParameters,
        graph: &dyn GraphAccess,
        functions: &dyn FunctionRegistry,
        clock: &StatementClock,
    ) -> Result<(), ExecError> {
        // `count(*)` counts every matched row (no argument to evaluate) — exactly serial `update`'s
        // first branch.
        if self.kind == AggKind::CountStar {
            self.count += 1;
            return Ok(());
        }
        // Evaluate the aggregate's single argument as a `RowValue` (so `count(n)` over a node binding
        // sees a non-null entity), identical to serial `update`.
        let rv = match &expr.kind {
            ExprKind::FunctionCall { args, .. } if !args.is_empty() => {
                eval(&args[0], row, params, graph, functions, clock)?
            }
            _ => RowValue::NULL,
        };
        self.fold_rowvalue(&rv)
    }

    /// Folds one **already-evaluated** aggregate-argument [`RowValue`] into the accumulator (`rmp` task
    /// #360) — the post-argument-evaluation body of [`update`](Self::update), shared verbatim by the
    /// serial row-at-a-time path and the morsel-parallel grouped tier, so the two produce byte-identical
    /// group state. Handles every kind **except** the percentiles (whose fold needs the second argument
    /// evaluated against the input row; `update` keeps that inline). Applies the identical null-skip,
    /// `DISTINCT` dedup (via [`row_values_equivalent`]), `collect` push (structural elements preserved),
    /// and numeric / extreme arithmetic.
    ///
    /// # Errors
    /// [`EvalError::TypeError`] if a `sum`/`avg` argument is non-numeric — the same error `update` raises.
    pub(crate) fn fold_rowvalue(&mut self, rv: &RowValue) -> Result<(), ExecError> {
        // count(x), sum, avg, min, max ignore nulls (Cypher); collect drops nulls too. An entity
        // reference is non-null.
        if rv.is_null() {
            return Ok(());
        }
        if self.distinct && self.seen.iter().any(|s| row_values_equivalent(s, rv)) {
            return Ok(());
        }
        if self.distinct {
            self.seen.push(rv.clone());
        }
        // `collect` keeps the full RowValue (structural elements survive into the list), bounded by
        // the per-value memory budget (`SEC-191`): `push_collected` rejects before the buffer crosses
        // [`MAX_VALUE_BYTES`](crate::value_size::MAX_VALUE_BYTES).
        if self.kind == AggKind::Collect {
            return self.push_collected(rv.clone());
        }
        // A percentile accumulator must never reach here (its fold needs `args[1]`; `update` keeps it
        // inline). The grouped-tier recognizer excludes percentiles, so this is defensive only.
        debug_assert!(
            !matches!(self.kind, AggKind::PercentileCont | AggKind::PercentileDisc),
            "fold_rowvalue does not handle percentiles (their fold needs the second argument)"
        );
        // The collapsed property value for the numeric / extreme arms. An entity/path collapses to
        // `Value::Null` here (it is not a property value) and a structural list collapses
        // elementwise: `count` and `collect` keep the RowValue-aware semantics above, while
        // `sum`/`avg`/`min`/`max` over an entity argument are a type error / no-op exactly as
        // before this fix.
        let argv = collapse_rv(rv);
        match self.kind {
            AggKind::Count => self.count += 1,
            AggKind::Sum | AggKind::Avg => {
                self.count += 1;
                match &argv {
                    Value::Integer(i) => {
                        self.add_int_sum(*i);
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
            // `Collect` returned early above; `CountStar` counts rows (not values) and is driven by the
            // caller's per-row increment, not a value fold; the percentiles are kept inline in `update`.
            // None of these fold a value here — a no-op keeps `fold_rowvalue` total and panic-free
            // (the `debug_assert` above flags a percentile reaching this body in a debug build).
            AggKind::Collect
            | AggKind::CountStar
            | AggKind::PercentileCont
            | AggKind::PercentileDisc => {}
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
        let p = match collapse_rv(&eval(
            arg,
            row,
            ctx.params,
            ctx.graph,
            ctx.functions,
            &ctx.clock,
        )?) {
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
                value: format!("{p} is not in [0.0, 1.0]"),
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

        // Consumer-side bound (`rmp` #400, defense in depth): every index below is derived from
        // `perc * count` and is in-range for the `perc ∈ [0.0, 1.0]` invariant `Accumulator::update`
        // enforces at intake — no OOB is reachable on the current single-threaded fold. But the raw
        // slice index lives one function away from its guard, and a future parallel-percentile path
        // could feed an unvalidated `perc`. `clamp_idx` collapses any rogue index to the last in-set
        // element rather than panicking, so an out-of-range value degrades to a defined in-set result
        // instead of an OOB index. `count >= 1` here (the `count == 0` early-return above), so
        // `count - 1` is the well-defined upper bound.
        let clamp_idx = |idx: usize| idx.min(count - 1);

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
                self.numeric[clamp_idx(idx)].1.clone()
            }
            AggKind::PercentileCont => {
                // Linear interpolation; always yields a `Float`.
                if perc == 1.0 || count == 1 {
                    return Value::Float(self.numeric[count - 1].0);
                }
                let float_idx = perc * (count - 1) as f64;
                let floor = clamp_idx(float_idx as usize); // truncation toward zero
                let ceil = clamp_idx(float_idx.ceil() as usize);
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
    match eval_value(expr, row, ctx.params, ctx.graph, ctx.functions, &ctx.clock)? {
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
    match eval(value, row, ctx.params, ctx.graph, ctx.functions, &ctx.clock)? {
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
///
/// A `SET` whose target is `null` (e.g. a variable left unbound by `OPTIONAL MATCH`) is a silent
/// no-op with **no side effects**: openCypher `SET a.num = 42` / `SET a = {…}` / `SET a += {…}` over a
/// null `a` (`clauses/set/Set1` [8], `Set4` [5], `Set5` [1]). The resolver helpers return `None` for a
/// null target, which short-circuits the op without evaluating its right-hand side.
fn apply_set_ops(ops: &[SetOp], row: &Row, ctx: &mut Ctx<'_>) -> Result<(), ExecError> {
    for op in ops {
        match op {
            SetOp::Property { target, value } => {
                let Some((entity, key)) = resolve_property_target(target, row)? else {
                    continue;
                };
                let v = eval_value(value, row, ctx.params, ctx.graph, ctx.functions, &ctx.clock)?;
                set_entity_property(entity, &key, v, ctx);
            }
            SetOp::ReplaceProperties { target, value } => {
                let Some(entity) = entity_ref(target, row)? else {
                    continue;
                };
                let props = eval_property_source(value, row, ctx)?;
                match entity {
                    EntityRef::Node(id) => ctx.graph.replace_node_properties(id, &props),
                    EntityRef::Rel(id) => ctx.graph.replace_rel_properties(id, &props),
                }
            }
            SetOp::MergeProperties { target, value } => {
                let Some(entity) = entity_ref(target, row)? else {
                    continue;
                };
                let props = eval_property_source(value, row, ctx)?;
                match entity {
                    EntityRef::Node(id) => ctx.graph.merge_node_properties(id, &props),
                    EntityRef::Rel(id) => ctx.graph.merge_rel_properties(id, &props),
                }
            }
            SetOp::AddLabels { target, labels } => {
                let Some(id) = entity_node(target, row)? else {
                    continue;
                };
                let names: Vec<String> = labels.iter().map(|l| l.name.clone()).collect();
                ctx.graph.add_labels(id, &names);
            }
        }
    }
    Ok(())
}

/// The entity + property key referenced by a `SET a.b = …` / `REMOVE a.b` target (`a.b`).
///
/// Returns `Ok(None)` when the base variable is bound to `null` (or left unbound), so the caller
/// treats the whole op as a no-op with no side effects — openCypher ignores `SET`/`REMOVE` of a
/// property on a null entity (`clauses/set/Set1` [8], `clauses/remove/Remove1` [5][6]). A base bound
/// to a non-null, non-entity value is still a `NotAnEntity` error.
fn resolve_property_target(
    target: &Expr,
    row: &Row,
) -> Result<Option<(EntityRef, String)>, ExecError> {
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
        // A null / unbound target is a silent no-op (Cypher's null-target rule).
        None | Some(RowValue::Value(Value::Null)) => return Ok(None),
        _ => {
            return Err(ExecError::NotAnEntity {
                context: format!("`{name}` is not a bound node or relationship"),
            });
        }
    };
    Ok(Some((entity, key.clone())))
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
///
/// Returns `Ok(None)` when the target is bound to `null` (or left unbound), so label `SET`/`REMOVE`
/// over a null node is a silent no-op (`clauses/remove/Remove2` [5]). A non-null, non-node value is
/// still a `NotAnEntity` error.
fn entity_node(target: &Var, row: &Row) -> Result<Option<NodeId>, ExecError> {
    match row.get(&target.name) {
        Some(RowValue::Node(n)) => Ok(Some(n.id)),
        None | Some(RowValue::Value(Value::Null)) => Ok(None),
        _ => Err(ExecError::NotAnEntity {
            context: format!("`{}` is not a bound node", target.name),
        }),
    }
}

/// Resolves a variable to the node **or relationship** it is bound to (for `SET x = map` / `SET x +=
/// map`, which apply to either; `clauses/merge/Merge6` [6][7], `Merge7` [4][5]).
///
/// Returns `Ok(None)` when the target is bound to `null` (or left unbound), so `SET a = {…}` /
/// `SET a += {…}` over a null `a` is a silent no-op (`clauses/set/Set4` [5], `Set5` [1]). A non-null,
/// non-entity value is still a `NotAnEntity` error.
fn entity_ref(target: &Var, row: &Row) -> Result<Option<EntityRef>, ExecError> {
    match row.get(&target.name) {
        Some(RowValue::Node(n)) => Ok(Some(EntityRef::Node(n.id))),
        Some(RowValue::Rel(r)) => Ok(Some(EntityRef::Rel(r.id))),
        None | Some(RowValue::Value(Value::Null)) => Ok(None),
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
        let value = eval(expr, row, ctx.params, ctx.graph, ctx.functions, &ctx.clock)?;
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
///
/// A `REMOVE` whose target is `null` (e.g. a variable left unbound by `OPTIONAL MATCH`) is a silent
/// no-op with no side effects (`clauses/remove/Remove1` [5][6], `Remove2` [5]); the resolver helpers
/// return `None` for a null target.
fn apply_remove_ops(ops: &[RemoveOp], row: &Row, ctx: &mut Ctx<'_>) -> Result<(), ExecError> {
    for op in ops {
        match op {
            RemoveOp::Labels { target, labels } => {
                let Some(id) = entity_node(target, row)? else {
                    continue;
                };
                let names: Vec<String> = labels.iter().map(|l| l.name.clone()).collect();
                ctx.graph.remove_labels(id, &names);
            }
            RemoveOp::Property { target } => {
                let Some((entity, key)) = resolve_property_target(target, row)? else {
                    continue;
                };
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
    /// The fixed per-statement "current instant" (`rmp` task #140), captured once at `open()` and
    /// reused for every `next()`/`pull` so the whole statement observes one instant.
    clock: StatementClock,
    /// The effective morsel-thread count (`rmp` task #339), captured once at `open()` from the
    /// process-global [`crate::morsel::morsel_threads`] and reused for every `next()` so the morsel
    /// tier decision is stable across the statement's lifetime.
    morsel_threads: usize,
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
            clock: self.clock,
            morsel_threads: self.morsel_threads,
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

    /// Detaches this cursor's **owned execution state** from the borrowed graph seam, releasing the
    /// `&mut dyn GraphAccess` / registry borrows so another command can take the coordinator's
    /// `&mut` (`rmp` task #372 — resumable cursor for egress backpressure without head-of-line
    /// blocking the engine thread).
    ///
    /// The returned [`SuspendedCursor`] carries no lifetime: it owns the [`Operator`] state machine
    /// (which touches the graph only transiently through a per-`next()` [`Ctx`]), the bound
    /// parameters, the cancellation token, the per-statement clock, the morsel-thread count, the
    /// result columns, and the `finished`/`emits_rows` flags. [`SuspendedCursor::resume`] re-binds it
    /// to a **fresh per-visit seam for the same transaction** (the same MVCC snapshot + the same
    /// uncommitted write buffer, so continuation is coherent) and yields an equivalent [`Cursor`].
    ///
    /// Suspend/resume changes neither commit timing nor durability: write side effects already apply
    /// incrementally per `next()` into the shared store, and durability happens only at commit (after
    /// the stream is exhausted). Resuming over a different graph state is **not** supported and would
    /// be a logic error — the contract is "same txn, fresh seam".
    pub fn suspend(self) -> SuspendedCursor {
        SuspendedCursor {
            root: self.root,
            params: self.params,
            token: self.token,
            clock: self.clock,
            morsel_threads: self.morsel_threads,
            columns: self.columns,
            finished: self.finished,
            emits_rows: self.emits_rows,
        }
    }
}

/// A [`Cursor`]'s owned execution state, detached from any graph borrow (`rmp` task #372).
///
/// Produced by [`Cursor::suspend`] and turned back into a live [`Cursor`] by
/// [`resume`](Self::resume). Holding one of these lets the engine thread park a slow consumer's
/// stream *without* keeping the coordinator's `&mut` borrow, so it returns to its command loop and
/// services concurrent writes/commands on the same database between batches.
#[must_use = "a suspended cursor yields no rows unless resumed"]
pub struct SuspendedCursor {
    root: Operator,
    params: BoundParameters,
    token: CancellationToken,
    clock: StatementClock,
    morsel_threads: usize,
    columns: Vec<String>,
    finished: bool,
    emits_rows: bool,
}

impl SuspendedCursor {
    /// The result column names, in order — unchanged across suspend/resume.
    #[must_use]
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// `true` once the operator tree is exhausted (no more rows will ever be produced). When this is
    /// set the engine can finalize immediately without a further [`resume`](Self::resume).
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Re-binds the suspended execution state to `graph` + the function/procedure registries, for the
    /// **same transaction** the cursor originally ran against (`rmp` task #372).
    ///
    /// The caller MUST pass a fresh seam for the same txn (same MVCC snapshot + the same uncommitted
    /// write buffer); the operator state continues coherently because it reads only through the
    /// per-`next()` [`Ctx`] built from these borrows.
    pub fn resume<'a>(
        self,
        graph: &'a mut dyn GraphAccess,
        functions: &'a dyn FunctionRegistry,
        procedures: &'a dyn ProcedureRegistry,
    ) -> Cursor<'a> {
        Cursor {
            root: self.root,
            params: self.params,
            token: self.token,
            graph,
            functions,
            procedures,
            clock: self.clock,
            morsel_threads: self.morsel_threads,
            columns: self.columns,
            finished: self.finished,
            emits_rows: self.emits_rows,
        }
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
        // Capture the statement clock once per open() — this is the fixed per-statement instant
        // every zero-argument temporal constructor in the statement reads (`rmp` task #140).
        let clock = StatementClock::capture();
        // The effective morsel-thread count for this statement (`rmp` task #339), read once from the
        // process-global knob at open and frozen for the cursor's lifetime.
        let morsel_threads = crate::morsel::morsel_threads();
        let root = {
            let mut ctx = Ctx {
                params: &self.params,
                token: &token,
                graph,
                functions,
                procedures,
                clock,
                morsel_threads,
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
            clock,
            morsel_threads,
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
        // Capture the statement clock once per open() — see `open_with_extensions` (`rmp` task #140).
        let clock = StatementClock::capture();
        // The effective morsel-thread count for this statement (`rmp` task #339), frozen at open.
        let morsel_threads = crate::morsel::morsel_threads();
        let root = {
            let mut ctx = Ctx {
                params: &self.params,
                token: &token,
                graph,
                functions,
                procedures,
                clock,
                morsel_threads,
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
            clock,
            morsel_threads,
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

/// [`execute_with_extensions`] driven by a **caller-supplied** [`CancellationToken`] (`rmp` #476)
/// instead of a fresh throwaway one — so the engine can install a per-statement wall-clock deadline
/// (and/or trip the token on client disconnect / `RESET`) and have the executor's existing safe points
/// abort a runaway query cooperatively.
///
/// Build the token with [`CancellationToken::with_deadline`] for a finite per-statement budget, or with
/// [`CancellationToken::new`] for an unbounded one. The token is moved into the returned [`Cursor`] (and
/// survives [`Cursor::suspend`]/[`SuspendedCursor::resume`]), so the same budget governs every batch of
/// the statement.
///
/// # Errors
///
/// As [`execute_with_extensions`]; additionally an already-elapsed deadline (or an already-tripped flag)
/// surfaces as [`ExecError::Cancelled`] at the first safe point.
pub fn execute_with_extensions_cancellable<'a>(
    plan: &PhysicalPlan,
    params: &BoundParameters,
    graph: &'a mut dyn GraphAccess,
    functions: &'a dyn FunctionRegistry,
    procedures: &'a dyn ProcedureRegistry,
    token: CancellationToken,
) -> Result<Cursor<'a>, ExecError> {
    Executor::new(plan.clone(), params.clone())
        .open_with_extensions(graph, token, functions, procedures)
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
            | PhysicalOp::Foreach { .. }
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
        | PhysicalOp::Remove { .. }
        // FOREACH is a write root: no `RETURN` sits above it, so it declares no result columns.
        | PhysicalOp::Foreach { .. } => Vec::new(),
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
        | PhysicalOp::NodeLabelScanEq { variable, .. }
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

    // ---- parallel label-property aggregation gates (`rmp` task #352) ---------------------------

    /// A `Send` seam (so it can be driven inside a `rayon` `pool.install`) that delegates every
    /// `GraphAccess` read/write to an inner [`MemGraph`] but (a) reports a configurable
    /// `nodes_with_label` count (to drive the size gate over/under the threshold) and (b) returns a
    /// non-`None` `project_snapshot` (so a `Some` here is observable). Used to isolate the
    /// thread-count and size gates of [`try_parallel_label_property_aggregate`], which the integration
    /// tests cannot exercise deterministically (the real `!Send` coordinator cannot enter `install`).
    struct ParallelGateStub {
        inner: MemGraph,
        label_count: u64,
    }

    impl crate::statistics::Statistics for ParallelGateStub {
        fn total_nodes(&self) -> u64 {
            self.label_count
        }
        fn nodes_with_label(&self, _label: &str) -> Option<u64> {
            Some(self.label_count)
        }
        fn total_relationships(&self) -> u64 {
            0
        }
        fn relationships_with_type(&self, _rel_type: &str) -> Option<u64> {
            Some(0)
        }
    }

    impl GraphAccess for ParallelGateStub {
        fn project_snapshot(
            &self,
            spec: &crate::snapshot::SnapshotSpec,
        ) -> Option<crate::snapshot::GraphSnapshot> {
            let (label, property) = spec.columns().first()?;
            let members = self.inner.scan_nodes_by_label(label);
            let rows = members
                .iter()
                .filter_map(|&n| self.inner.node_property(n, property).map(|v| (n, v)))
                .collect();
            Some(crate::snapshot::GraphSnapshot::from_label_column(
                label, property, members, rows,
            ))
        }
        fn columnar_label_property_scan(
            &self,
            label: &str,
            property: &str,
        ) -> Option<crate::graph_access::ColumnarScan> {
            // The parallel aggregation tier reads its owned column from this seam (the same one the
            // serial vectorized tier uses); supply it from the inner graph so the gate tests exercise
            // the real engage/decline path. The size gate is still driven by the faked `statistics`.
            let members = self.inner.scan_nodes_by_label(label);
            let rows = members
                .iter()
                .filter_map(|&n| self.inner.node_property(n, property).map(|v| (n, v)))
                .collect();
            Some(crate::graph_access::ColumnarScan {
                label_matches: members.len(),
                rows,
            })
        }
        fn statistics(&self) -> Option<&dyn crate::statistics::Statistics> {
            Some(self)
        }
        fn scan_nodes(&self) -> Vec<NodeId> {
            self.inner.scan_nodes()
        }
        fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
            self.inner.scan_nodes_by_label(label)
        }
        fn expand(
            &self,
            node: NodeId,
            direction: ExpandDirection,
            types: &[String],
        ) -> Vec<crate::graph_access::Incident> {
            self.inner.expand(node, direction, types)
        }
        fn node_exists(&self, node: NodeId) -> bool {
            self.inner.node_exists(node)
        }
        fn rel_exists(&self, rel: RelId) -> bool {
            self.inner.rel_exists(rel)
        }
        fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
            self.inner.node_labels(node)
        }
        fn rel_data(&self, rel: RelId) -> Option<crate::graph_access::RelData> {
            self.inner.rel_data(rel)
        }
        fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
            self.inner.node_property(node, key)
        }
        fn rel_property(&self, rel: RelId, key: &str) -> Option<Value> {
            self.inner.rel_property(rel, key)
        }
        fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
            self.inner.node_properties(node)
        }
        fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
            self.inner.rel_properties(rel)
        }
        fn create_node(&mut self, labels: &[String], properties: &[(String, Value)]) -> NodeId {
            self.inner.create_node(labels, properties)
        }
        fn create_rel(
            &mut self,
            rel_type: &str,
            start: NodeId,
            end: NodeId,
            properties: &[(String, Value)],
        ) -> RelId {
            self.inner.create_rel(rel_type, start, end, properties)
        }
        fn set_node_property(&mut self, node: NodeId, key: &str, value: Value) {
            self.inner.set_node_property(node, key, value);
        }
        fn set_rel_property(&mut self, rel: RelId, key: &str, value: Value) {
            self.inner.set_rel_property(rel, key, value);
        }
        fn add_labels(&mut self, node: NodeId, labels: &[String]) {
            self.inner.add_labels(node, labels);
        }
        fn remove_labels(&mut self, node: NodeId, labels: &[String]) {
            self.inner.remove_labels(node, labels);
        }
        fn remove_node_property(&mut self, node: NodeId, key: &str) {
            self.inner.remove_node_property(node, key);
        }
        fn remove_rel_property(&mut self, rel: RelId, key: &str) {
            self.inner.remove_rel_property(rel, key);
        }
        fn replace_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
            self.inner.replace_node_properties(node, properties);
        }
        fn merge_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
            self.inner.merge_node_properties(node, properties);
        }
        fn replace_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
            self.inner.replace_rel_properties(rel, properties);
        }
        fn merge_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
            self.inner.merge_rel_properties(rel, properties);
        }
        fn incident_rels(&self, node: NodeId) -> Vec<RelId> {
            self.inner.incident_rels(node)
        }
        fn delete_rel(&mut self, rel: RelId) {
            self.inner.delete_rel(rel);
        }
        fn delete_node(&mut self, node: NodeId) {
            self.inner.delete_node(node);
        }
    }

    /// Compiles `src` and returns its root [`PhysicalOp`] (the [`PhysicalOp::Aggregation`] the gate
    /// tests poke at directly).
    fn aggregation_parts(src: &str) -> PhysicalOp {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        plan_physical(
            &lower(&analyze(&ast).expect("analyze")),
            &IndexCatalog::empty(),
        )
        .root
    }

    /// Drives [`try_parallel_label_property_aggregate`] once over `graph` for the aggregation `op`,
    /// returning whether it engaged (`Some`) — a tiny harness that builds the minimal [`Ctx`].
    fn parallel_engaged(op: &PhysicalOp, graph: &mut dyn GraphAccess) -> bool {
        let PhysicalOp::Aggregation {
            input,
            group_keys,
            aggregates,
        } = op
        else {
            panic!("expected an Aggregation root");
        };
        let params = BoundParameters::empty();
        let token = CancellationToken::new();
        let functions = crate::function_registry::no_functions();
        let procedures = crate::procedure_registry::builtins();
        let mut ctx = Ctx {
            params: &params,
            token: &token,
            graph,
            functions,
            procedures,
            clock: StatementClock::capture(),
            morsel_threads: crate::morsel::morsel_threads(),
        };
        try_parallel_label_property_aggregate(input, group_keys, aggregates, &mut ctx)
            .expect("no error")
            .is_some()
    }

    /// The **single-thread** gate (`rmp` task #352): inside a one-worker `rayon` pool the parallel tier
    /// declines (returns `None`) **even though** every other gate (huge label count, integer column,
    /// exact aggregate, available snapshot) passes — proving the thread gate fires first. Outside the
    /// one-thread pool (the multi-worker default global pool) the same setup engages.
    #[test]
    fn parallel_thread_gate_declines_single_worker() {
        let op = aggregation_parts("MATCH (n:Person) RETURN sum(n.age) AS r");

        let mut g = MemGraph::new();
        for i in 0..10 {
            g.add_node(["Person"], [("age", Value::Integer(i))]);
        }
        // A label count far above the size gate, so only the thread gate can decline.
        let mut stub = ParallelGateStub {
            inner: g,
            label_count: 1_000_000,
        };

        // One worker → declines (the thread gate fires before any seam access).
        let pool1 = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("1-thread pool");
        let engaged_single = pool1.install(|| parallel_engaged(&op, &mut stub));
        assert!(
            !engaged_single,
            "a single rayon worker must DECLINE the parallel tier"
        );

        // Multiple workers → engages (all gates pass: count, integer column, exact aggregate).
        let pool4 = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .expect("4-thread pool");
        let engaged_multi = pool4.install(|| parallel_engaged(&op, &mut stub));
        assert!(
            engaged_multi,
            "with multiple workers and all gates passing, the parallel tier must engage"
        );
    }

    /// The **size** gate (`rmp` task #352): a label count below the threshold declines; at/above it
    /// engages. Run under a multi-worker pool so the thread gate is satisfied and only the size gate
    /// varies.
    #[test]
    fn parallel_size_gate_threshold() {
        let op = aggregation_parts("MATCH (n:Person) RETURN sum(n.age) AS r");
        let mut g = MemGraph::new();
        for i in 0..10 {
            g.add_node(["Person"], [("age", Value::Integer(i))]);
        }
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .expect("4-thread pool");

        // Below the threshold → declines.
        let mut below = ParallelGateStub {
            inner: g.clone(),
            label_count: (PARALLEL_AGG_MIN_ROWS as u64) - 1,
        };
        assert!(
            !pool.install(|| parallel_engaged(&op, &mut below)),
            "below the size threshold the parallel tier must decline"
        );

        // At the threshold → engages.
        let mut at = ParallelGateStub {
            inner: g,
            label_count: PARALLEL_AGG_MIN_ROWS as u64,
        };
        assert!(
            pool.install(|| parallel_engaged(&op, &mut at)),
            "at the size threshold the parallel tier must engage"
        );
    }

    /// `avg` and a non-aggregate-shaped column decline regardless of size/threads (`rmp` task #352):
    /// the shape/exactness gates. Proven with all other gates satisfied (huge count, multi-worker).
    #[test]
    fn parallel_shape_gate_declines_avg_and_non_bare() {
        let mut g = MemGraph::new();
        for i in 0..10 {
            g.add_node(["Person"], [("age", Value::Integer(i))]);
        }
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .expect("4-thread pool");

        for src in [
            "MATCH (n:Person) RETURN avg(n.age) AS r", // deferred aggregate
            "MATCH (n:Person) RETURN sum(n.age) + 1 AS r", // not a bare aggregate
            "MATCH (n:Person) RETURN count(DISTINCT n.age) AS r", // DISTINCT
            "MATCH (n:Person) RETURN n.age AS k, sum(n.age) AS r", // grouping key present
        ] {
            let op = aggregation_parts(src);
            let mut stub = ParallelGateStub {
                inner: g.clone(),
                label_count: 1_000_000,
            };
            assert!(
                !pool.install(|| parallel_engaged(&op, &mut stub)),
                "`{src}` must DECLINE the parallel tier (shape/exactness gate)"
            );
        }
    }

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

    // ---- rmp #360: the Accumulator merge mechanics the grouped morsel tier relies on -------------

    /// Folds a slice of integer values into a fresh `Sum` accumulator (`fold_rowvalue` — the shared
    /// serial/parallel body).
    fn sum_fold(values: &[i64]) -> Accumulator {
        let mut acc = Accumulator::for_kind(AggKind::Sum);
        for &v in values {
            acc.fold_rowvalue(&RowValue::Value(Value::Integer(v)))
                .expect("integer sum fold never errors");
        }
        acc
    }

    /// The saturation witness (`rmp` #360, finding C): a `sum` whose integer fold clamps to the i64 rail
    /// is flagged `sum_is_parallel_unsafe` (so the grouped tier declines), and `combine` propagates the
    /// flag — proving the GATE FIRES (the part the end-to-end test cannot isolate, since a small fixture
    /// may keep all rail values in one morsel). Mirrors the empirically-verified divergence input.
    #[test]
    fn sum_saturation_is_flagged_parallel_unsafe() {
        // A single left fold that saturates (MAX + MAX clamps).
        let acc = sum_fold(&[i64::MAX, i64::MAX, -i64::MAX, -i64::MAX]);
        assert!(
            acc.sum_is_parallel_unsafe(),
            "an integer sum that saturated must be flagged parallel-unsafe"
        );
        // The serial result is the incremental-saturation value (MIN+1), NOT the true total (0).
        assert_eq!(acc.finish(), RowValue::Value(Value::Integer(i64::MIN + 1)));

        // A 2+2 partition: each sub-sum saturates, so BOTH halves are flagged, and combining them keeps the
        // flag set — the tier would see `sum_is_parallel_unsafe` on the merged accumulator and decline.
        let mut lo = sum_fold(&[i64::MAX, i64::MAX]);
        let hi = sum_fold(&[-i64::MAX, -i64::MAX]);
        assert!(lo.sum_is_parallel_unsafe() && hi.sum_is_parallel_unsafe());
        lo.combine(hi);
        assert!(
            lo.sum_is_parallel_unsafe(),
            "combine must propagate the saturation witness so the merged sum is flagged"
        );
    }

    /// A no-overflow integer `sum` is NOT flagged, and its parallel partition-merge is **bit-identical**
    /// to the serial left fold (`rmp` #360): `saturating_add` that never clamps is pure associative i64
    /// add. This is the common analytical case the tier keeps parallel.
    #[test]
    fn sum_no_overflow_is_safe_and_combine_equals_serial() {
        let column = [1_000_000_000i64, -3, 42, -1_000_000_000, 7, 999];
        let serial_acc = sum_fold(&column);
        assert!(
            !serial_acc.sum_is_parallel_unsafe(),
            "a no-overflow integer sum must stay on the parallel path"
        );
        let serial_result = serial_acc.finish();
        // Every 2-way split combines to the identical total.
        for split in 1..column.len() {
            let mut a = sum_fold(&column[..split]);
            let b = sum_fold(&column[split..]);
            a.combine(b);
            assert!(
                !a.sum_is_parallel_unsafe(),
                "split at {split}: a no-overflow column must stay parallel-safe after combine"
            );
            assert_eq!(
                a.finish(),
                serial_result,
                "split at {split}: combine must equal the serial left fold"
            );
        }
    }

    /// A FLOAT `sum` is flagged parallel-unsafe (`rmp` #360): float `+` is non-associative, so the tier
    /// declines and serial folds it exactly.
    #[test]
    fn float_sum_is_flagged_parallel_unsafe() {
        let mut acc = Accumulator::for_kind(AggKind::Sum);
        acc.fold_rowvalue(&RowValue::Value(Value::Float(1.5)))
            .unwrap();
        acc.fold_rowvalue(&RowValue::Value(Value::Integer(2)))
            .unwrap();
        assert!(
            acc.sum_is_parallel_unsafe(),
            "a sum that saw a float must be flagged parallel-unsafe (decline to serial)"
        );
    }

    /// `count(DISTINCT)` merge (`rmp` #360): a value seen in BOTH partitions is counted ONCE. The merge
    /// re-applies the cross-partition dedup, so the combined count equals a single serial fold over the
    /// concatenation.
    #[test]
    fn distinct_count_combine_dedups_across_partitions() {
        let distinct_count = |vals: &[i64]| -> Accumulator {
            let mut acc = Accumulator::zeroed(AggKind::Count, true);
            for &v in vals {
                acc.fold_rowvalue(&RowValue::Value(Value::Integer(v)))
                    .unwrap();
            }
            acc
        };
        // Partition A: {1,2,3}; Partition B: {2,3,4}. Union distinct = {1,2,3,4} ⇒ count 4.
        let mut a = distinct_count(&[1, 2, 3, 2]);
        let b = distinct_count(&[2, 3, 4, 4]);
        a.combine(b);
        let merged = a.finish();
        assert_eq!(
            merged,
            RowValue::Value(Value::Integer(4)),
            "DISTINCT count across partitions must dedup the overlap (1,2,3,4 ⇒ 4)"
        );
        // Equals a single serial fold over the concatenation.
        let serial = distinct_count(&[1, 2, 3, 2, 2, 3, 4, 4]);
        assert_eq!(merged, serial.finish());
    }

    /// `collect` (non-DISTINCT) merge (`rmp` #360): the combine concatenates `other` AFTER `self`, so the
    /// ascending-`lo` merge order reproduces the serial scan-encounter order.
    #[test]
    fn collect_combine_concatenates_in_order() {
        let collect = |vals: &[i64]| -> Accumulator {
            let mut acc = Accumulator::for_kind(AggKind::Collect);
            for &v in vals {
                acc.fold_rowvalue(&RowValue::Value(Value::Integer(v)))
                    .unwrap();
            }
            acc
        };
        let mut a = collect(&[1, 2, 3]);
        let b = collect(&[4, 5]);
        a.combine(b); // a is the lower-`lo` partition ⇒ its elements come first
        let serial = collect(&[1, 2, 3, 4, 5]);
        assert_eq!(
            a.finish(),
            serial.finish(),
            "collect merge in ascending-lo order must equal the serial encounter order"
        );
    }

    /// `rmp` #481: the `collect` byte-accounting the per-value budget rejects on. The running estimate must
    /// be additive across folds AND across a `combine` (the input the `rmp` #360 grouped-morsel merge-site
    /// detector reads), so a merged `collect` that crosses the budget is detected exactly as a serial fold
    /// of the same elements would be — even when no single partition crossed it alone.
    #[test]
    fn collect_byte_estimate_is_additive_over_fold_and_combine() {
        let per = crate::value_size::estimate_rowvalue_bytes(&RowValue::Value(Value::Integer(0)));

        let collect = |vals: &[i64]| -> Accumulator {
            let mut acc = Accumulator::for_kind(AggKind::Collect);
            for &v in vals {
                acc.fold_rowvalue(&RowValue::Value(Value::Integer(v)))
                    .unwrap();
            }
            acc
        };

        // Per-fold: N integers ⇒ N * per bytes.
        let a = collect(&[1, 2, 3]);
        assert_eq!(
            a.collected_bytes(),
            3 * per,
            "fold estimate must be additive"
        );

        // Per-combine: the merged estimate is the sum of the partitions' — exactly what a single serial fold
        // over the concatenation reports.
        let mut left = collect(&[1, 2, 3]);
        let right = collect(&[4, 5]);
        left.combine(right);
        assert_eq!(
            left.collected_bytes(),
            5 * per,
            "combine must sum the partitions' byte estimates (the merge-site cap input)"
        );
        assert_eq!(
            left.collected_bytes(),
            collect(&[1, 2, 3, 4, 5]).collected_bytes(),
            "merged estimate must equal the serial fold over the concatenation"
        );
    }

    /// `collect(DISTINCT)` merge (`rmp` #360): order-preserving set-union — first-encounter order across
    /// partitions, overlap dropped.
    #[test]
    fn distinct_collect_combine_is_order_preserving_union() {
        let dcollect = |vals: &[i64]| -> Accumulator {
            let mut acc = Accumulator::zeroed(AggKind::Collect, true);
            for &v in vals {
                acc.fold_rowvalue(&RowValue::Value(Value::Integer(v)))
                    .unwrap();
            }
            acc
        };
        // A: {1,2}; B: {2,3,1}. First-encounter union in ascending-lo = [1,2,3] (B's 2 and 1 are dups).
        let mut a = dcollect(&[1, 2, 2]);
        let b = dcollect(&[2, 3, 1]);
        a.combine(b);
        let serial = dcollect(&[1, 2, 2, 2, 3, 1]);
        assert_eq!(
            a.finish(),
            serial.finish(),
            "collect(DISTINCT) merge must be the order-preserving first-encounter union"
        );
    }
}
